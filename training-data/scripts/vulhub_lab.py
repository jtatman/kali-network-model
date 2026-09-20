#!/usr/bin/env python3
"""On-demand launcher for vulhub's per-CVE docker-compose environments --
the "known baseline" alternative to the always-on infosecwarrior/wordpress
lab stack in ~/Offensive-Pentesting-Lab/docker-compose.yml. Rather than
running dozens of containers simultaneously (a real resource problem,
confirmed: 108GB of images / 47.9GB reclaimable build cache before this
tool existed), this starts exactly one (or a few, deliberately) vulhub
CVE environment at a time, reports the real container IP(s) to point a
recipe at, and tears it down when done.

vulhub itself (a git clone, not part of this repo) has one docker-
compose.yml PER CVE, e.g. vulhub/drupal/CVE-2018-7600/docker-compose.yml
-- each with its own README.md documenting the exact CVE, the expected
vulnerable behavior, and (usually) a reproduction snippet. That README
is the "strong baseline for what results we should be seeing" this tool
exists to make usable: `info` prints it, `up` runs the real compose file
unmodified from vulhub's own directory.

THE REAL GOTCHA THIS TOOL HANDLES: kali-agent-box is explicitly attached
to several existing lab networks (offensive-pentesting-lab_default,
offensive-pentesting-lab_labnet, ...) via individual `docker network
connect` calls made by hand at some point -- it is NOT simply "on the
default bridge and can reach everything." Every vulhub CVE directory's
`docker compose up` creates a NEW, isolated project network the exec
target has zero route to until explicitly connected. `up` discovers the
real network(s) the started container(s) landed on (via `docker inspect`,
not by guessing compose's project-name-mangling scheme) and connects
DOCKER_CONTAINER (from .env) to each one automatically -- skip this and
every new environment is silently unreachable from the Kali exec box.

State (which environments THIS tool has started, their directories,
their networks) is tracked in .vulhub_lab_state.json (gitignored,
sibling to this script) so `down --all` tears down exactly what it
started, never someone else's unrelated docker state.

Usage:
  vulhub_lab.py list [FILTER]        List available app/CVE dirs (has a
                                      docker-compose.yml), optionally
                                      substring-filtered.
  vulhub_lab.py info APP/CVE         Print that CVE's real README summary.
  vulhub_lab.py up APP/CVE           Start it, connect DOCKER_CONTAINER to
                                      its network(s), print container IPs.
  vulhub_lab.py down APP/CVE         Tear it down (docker compose down -v
                                      --remove-orphans -- disposable test
                                      targets, no reason to accumulate
                                      orphaned volumes).
  vulhub_lab.py down --all           Tear down everything this tool has
                                      started.
  vulhub_lab.py status               What's currently up, per this tool's
                                      own state (cross-checked against
                                      real `docker compose ps`, in case
                                      something was torn down out-of-band).
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))
except ImportError:
    pass

VULHUB_ROOT = os.environ.get(
    "VULHUB_ROOT", os.path.expanduser("~/Offensive-Pentesting-Lab/vulhub")
)
DOCKER_CONTAINER = os.environ.get("DOCKER_CONTAINER", "kali-agent-box")
STATE_FILE = os.path.join(os.path.dirname(__file__), ".vulhub_lab_state.json")


def _load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE) as f:
        return json.load(f)


def _save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def _cve_dir(app_cve):
    """app_cve is "app/CVE-XXXX-XXXX" (or any subdir name vulhub uses --
    not every entry is a CVE id, e.g. flask/ssti, tomcat/tomcat8)."""
    path = os.path.join(VULHUB_ROOT, app_cve)
    compose_path = os.path.join(path, "docker-compose.yml")
    if not os.path.exists(compose_path):
        return None
    return path


def cmd_list(args):
    if not os.path.isdir(VULHUB_ROOT):
        print(f"VULHUB_ROOT not found: {VULHUB_ROOT}")
        print("Set VULHUB_ROOT env var if vulhub is cloned somewhere else.")
        sys.exit(1)
    matches = []
    for app in sorted(os.listdir(VULHUB_ROOT)):
        app_path = os.path.join(VULHUB_ROOT, app)
        if not os.path.isdir(app_path):
            continue
        for entry in sorted(os.listdir(app_path)):
            candidate = f"{app}/{entry}"
            if _cve_dir(candidate):
                if args.filter and args.filter.lower() not in candidate.lower():
                    continue
                matches.append(candidate)
    print(f"{len(matches)} matching environment(s):")
    for m in matches:
        print(f"  {m}")


def cmd_info(args):
    d = _cve_dir(args.target)
    if not d:
        print(f"No docker-compose.yml found for '{args.target}' under {VULHUB_ROOT}")
        sys.exit(1)
    readme = os.path.join(d, "README.md")
    if not os.path.exists(readme):
        print(f"(no README.md in {d})")
        return
    with open(readme) as f:
        lines = f.readlines()
    # Skip the "[中文版本...]" link line vulhub's READMEs all open with --
    # noise for this purpose, not part of the actual CVE description.
    printed = 0
    for line in lines:
        if "中文版本" in line:
            continue
        print(line.rstrip())
        printed += 1
        if printed >= 25:
            print("...")
            break


def _run(cmd, cwd=None, capture=False):
    # flush=True: this print's stdout is buffered independently of the
    # subprocess's own inherited stdout, which writes directly to the fd --
    # without flushing first, the "$ ..." line can print AFTER the
    # command's own real-time output despite being called first (confirmed
    # visually during live testing).
    print(f"$ {' '.join(cmd)}" + (f"  (cwd={cwd})" if cwd else ""), flush=True)
    if capture:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return subprocess.run(cmd, cwd=cwd)


def _container_networks(container_id):
    """Real network membership + IP, from docker inspect -- never guessed
    from compose's project-name-mangling rules (hyphens/underscores
    stripped differently across compose versions; inspecting the actual
    running container sidesteps needing to replicate that logic)."""
    result = subprocess.run(
        ["docker", "inspect", container_id, "--format", "{{json .NetworkSettings.Networks}}"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return {}
    return json.loads(result.stdout)


def cmd_up(args):
    d = _cve_dir(args.target)
    if not d:
        print(f"No docker-compose.yml found for '{args.target}' under {VULHUB_ROOT}")
        sys.exit(1)

    up_result = _run(["docker", "compose", "up", "-d"], cwd=d)
    if up_result.returncode != 0:
        print("docker compose up failed -- see output above.")
        sys.exit(1)

    ps_result = _run(["docker", "compose", "ps", "-q"], cwd=d, capture=True)
    container_ids = [c for c in ps_result.stdout.strip().splitlines() if c]
    if not container_ids:
        print("WARNING: compose up succeeded but no containers found via `compose ps -q`.")
        sys.exit(1)

    all_networks = set()
    containers_info = {}
    for cid in container_ids:
        name_result = subprocess.run(
            ["docker", "inspect", cid, "--format", "{{.Name}}"], capture_output=True, text=True
        )
        cname = name_result.stdout.strip().lstrip("/")
        networks = _container_networks(cid)
        containers_info[cname] = {
            net: info.get("IPAddress") for net, info in networks.items()
        }
        all_networks.update(networks.keys())

    print(f"\nConnecting {DOCKER_CONTAINER} to {len(all_networks)} network(s)...")
    for net in sorted(all_networks):
        result = subprocess.run(
            ["docker", "network", "connect", net, DOCKER_CONTAINER],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            print(f"  connected: {net}")
        elif "already exists" in result.stderr or "already connected" in result.stderr:
            print(f"  already connected: {net}")
        else:
            print(f"  FAILED to connect {net}: {result.stderr.strip()}")

    state = _load_state()
    state[args.target] = {
        "dir": d,
        "networks": sorted(all_networks),
        "containers": containers_info,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_state(state)

    print(f"\n{args.target} is up. Container IP(s) reachable from {DOCKER_CONTAINER}:")
    for cname, nets in containers_info.items():
        for net, ip in nets.items():
            print(f"  {cname}  ({net})  {ip}")

    if args.for_pathway:
        _write_pipeline_targets(args.for_pathway, args.container, containers_info)
    else:
        print(
            f"\nUse one of the IPs above as a recipe target -- run "
            f"`{sys.argv[0]} info {args.target}` for the documented CVE/expected behavior, "
            f"or re-run with --for-pathway PATHWAY[,PATHWAY...] to write it straight into "
            f"pipeline_targets.json."
        )


def _write_pipeline_targets(pathways, container_name, containers_info):
    """Writes {pathway: {"target": ip}} into pipeline_targets.json (NOT
    pipeline_recipes.py's own baked-in defaults) for each given pathway --
    this is the bridge between vulhub_lab's dynamic per-launch IPs and
    pipeline_chain_builder.py's target-override mechanism (see
    pipeline_targets.example.json's own docstring: overrides apply BEFORE
    template substitution, same file per-machine deployment already uses).
    Vulhub IPs are NOT stable across relaunches the way this repo's old
    always-on docker-compose.yml IPs were -- re-run this every time you
    bring an environment back up, don't assume yesterday's IP still
    applies."""
    def _first_ip(nets):
        # Real failure mode, hit live: a container left over from an
        # earlier FAILED `up` (e.g. a host-port conflict from another
        # environment still running) can come back "Up" per `docker ps`
        # but with a genuinely empty NetworkSettings.Networks -- silently
        # never actually attached. Surface that clearly instead of an
        # opaque StopIteration.
        if not nets:
            return None
        return next(iter(nets.values()))

    if len(containers_info) == 1:
        ip = _first_ip(next(iter(containers_info.values())))
    elif container_name and container_name in containers_info:
        ip = _first_ip(containers_info[container_name])
    else:
        print(
            f"\nMultiple containers ({', '.join(containers_info)}) -- pass "
            f"--container NAME to pick which one --for-pathway should point at. "
            f"Not writing pipeline_targets.json."
        )
        return

    if ip is None:
        print(
            "\nWARNING: the target container has no network attached (empty "
            "NetworkSettings.Networks) -- likely a broken leftover from an "
            "earlier failed `up` (e.g. a host-port conflict with another "
            "environment still running). Run `down` on this target and `up` "
            "again once the port conflict is resolved. Not writing "
            "pipeline_targets.json."
        )
        return

    targets_path = os.path.join(os.path.dirname(__file__), "pipeline_targets.json")
    targets = {}
    if os.path.exists(targets_path):
        with open(targets_path) as f:
            targets = json.load(f)
    for pathway in pathways.split(","):
        pathway = pathway.strip()
        targets.setdefault(pathway, {})["target"] = ip
    with open(targets_path, "w") as f:
        json.dump(targets, f, indent=2)
    print(f"\nWrote target={ip} for {pathways} into {targets_path}")


def cmd_down(args):
    state = _load_state()
    targets = list(state.keys()) if args.all else [args.target]
    if not targets:
        print("Nothing tracked as up (state file empty).")
        return
    for target in targets:
        entry = state.get(target)
        d = entry["dir"] if entry else _cve_dir(target)
        if not d or not os.path.isdir(d):
            print(f"Skipping {target}: directory not found ({d}).")
            state.pop(target, None)
            continue
        # MUST disconnect DOCKER_CONTAINER from this environment's network(s)
        # BEFORE `compose down` -- confirmed live: compose's own network
        # removal step fails silently with "Resource is still in use"
        # whenever an endpoint from OUTSIDE that compose project (i.e.
        # exactly the connection `up` made) is still attached, leaving an
        # orphaned network behind forever otherwise. Best-effort: an
        # already-disconnected network (e.g. torn down out-of-band) just
        # errors harmlessly here.
        for net in (entry or {}).get("networks", []):
            subprocess.run(
                ["docker", "network", "disconnect", net, DOCKER_CONTAINER],
                capture_output=True, text=True,
            )
        _run(["docker", "compose", "down", "-v", "--remove-orphans"], cwd=d)
        state.pop(target, None)
    _save_state(state)
    print(f"\nTorn down: {', '.join(targets)}")


def cmd_status(args):
    state = _load_state()
    if not state:
        print("Nothing tracked as up.")
        return
    for target, entry in state.items():
        print(f"\n{target}  (started {entry['started_at']})")
        ps_result = subprocess.run(
            ["docker", "compose", "ps", "--format", "{{.Name}}\t{{.Status}}"],
            cwd=entry["dir"], capture_output=True, text=True,
        )
        real_status = ps_result.stdout.strip() or "(no containers found -- may have been torn down out-of-band)"
        print(f"  {real_status}")
        for cname, nets in entry["containers"].items():
            for net, ip in nets.items():
                print(f"  {cname}  ({net})  {ip}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="List available vulhub CVE environments")
    p_list.add_argument("filter", nargs="?", default=None)
    p_list.set_defaults(func=cmd_list)

    p_info = sub.add_parser("info", help="Print a CVE environment's README summary")
    p_info.add_argument("target", help="e.g. drupal/CVE-2018-7600")
    p_info.set_defaults(func=cmd_info)

    p_up = sub.add_parser("up", help="Start one CVE environment, connect the exec target to it")
    p_up.add_argument("target", help="e.g. drupal/CVE-2018-7600")
    p_up.add_argument(
        "--for-pathway", default=None,
        help="Comma-separated pipeline_recipes.py pathway name(s) to write this "
             "environment's IP into pipeline_targets.json for (e.g. "
             "ffuf_wordpress_fuzz__v0,katana_crawl_wordpress__v0)",
    )
    p_up.add_argument(
        "--container", default=None,
        help="Which container's IP to use with --for-pathway, when the "
             "environment has more than one (e.g. nginx, not the php-fpm backend)",
    )
    p_up.set_defaults(func=cmd_up)

    p_down = sub.add_parser("down", help="Tear down one (or all) CVE environments this tool started")
    p_down.add_argument("target", nargs="?", default=None)
    p_down.add_argument("--all", action="store_true")
    p_down.set_defaults(func=cmd_down)

    p_status = sub.add_parser("status", help="Show what's currently up per this tool's state")
    p_status.set_defaults(func=cmd_status)

    args = p.parse_args()
    if args.command == "down" and not args.all and not args.target:
        p_down.error("target is required unless --all is given")
    args.func(args)


if __name__ == "__main__":
    main()
