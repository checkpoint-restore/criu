#!/usr/bin/env python3
"""Test fallback-link plugin dispatch using real network-namespace dumps.

Run as root after loading sit, ipip and ip_gre. All link changes are made
in child network namespaces. With --restore, also check default and configured
fallback devices, which the loaded modules create in the restored namespace.
"""

import argparse
import base64
import errno
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "lib"))

FALLBACKS = {"sit0": "sit", "tunl0": "ipip", "gre0": "gre", "gretap0": "gretap"}


def fail(message, directory):
    for name in ("dump.log", "restore.log"):
        path = directory / name
        if path.exists():
            print(f"=== {path} ===", file=sys.stderr)
            print(path.read_text(errors="replace"), file=sys.stderr, flush=True)
    raise RuntimeError(f"{message}; see {directory}")


def in_net(pid, *args):
    return subprocess.check_output(
        ["nsenter", "-t", str(pid), "-n", "--", *args], text=True)


def wait_for_netns(worker):
    parent_ns = os.readlink("/proc/self/ns/net")
    deadline = time.monotonic() + 10
    while worker.poll() is None and time.monotonic() < deadline:
        if (os.readlink(f"/proc/{worker.pid}/ns/net") != parent_ns
                and Path(f"/proc/{worker.pid}/comm").read_text().strip() == "sleep"):
            return
        time.sleep(0.01)
    raise RuntimeError("Worker failed to start in a separate network namespace")


def dump(criu, pid, directory, plugins, name, mode):
    directory.mkdir()
    env = dict(os.environ, CRIU_FALLBACK_NAME=name, CRIU_FALLBACK_MODE=mode)
    result = subprocess.run(
        [str(criu), "dump", "--no-default-config", "-t", str(pid),
         "-D", str(directory), "-o", "dump.log", "-v4", "--leave-running",
         "--shell-job", "--manage-cgroups=ignore", "--network-lock", "skip",
         "--libdir", str(plugins)], env=env, check=False, timeout=60)
    log = (directory / "dump.log").read_text()
    return result.returncode, log


def read_links(directory):
    from pycriu import images

    entries = {}
    for path in directory.glob("netdev-*.img"):
        with path.open("rb") as image:
            for entry in images.load(image)["entries"]:
                entries[entry["name"]] = entry
    if "lo" not in entries:
        fail("Dump did not capture the worker's network namespace", directory)
    return entries


def check_case(criu, pid, work, plugins, name, kind, mode, fallback=True):
    directory = work / f"{name}-{mode}"
    status, log = dump(criu, pid, directory, plugins, name, mode)
    marker = f"fallback-test: {name} {kind} {mode}\n"
    if log.count(marker) != 1:
        fail(f"{name}/{mode}: expected exactly one plugin callback", directory)

    expected_failure = mode == "error" or (mode == "decline" and not fallback)
    if bool(status) != expected_failure:
        fail(f"{name}/{mode}: unexpected dump status {status}", directory)
    if not expected_failure:
        links = read_links(directory)
        if mode == "decline":
            if name in links:
                fail(f"Declined fallback {name} was not skipped", directory)
        else:
            live = json.loads(in_net(pid, "ip", "-j", "link", "show", "dev", name))[0]
            entry = links.get(name, {})
            flags = int(str(entry.get("flags", "0")), 0)
            if (entry.get("type") != "EXTLINK" or entry.get("ifindex") != live["ifindex"]
                    or entry.get("mtu") != 1400 or not flags & 1):
                fail(f"Missing external-link state for {name}: {entry}", directory)
        if links.get("criu-sit", {}).get("type") != "SIT":
            fail("Ordinary SIT device lost native dump handling", directory)
    print(f"PASS: {name} {mode}", flush=True)


def link_state(pid):
    links = json.loads(in_net(pid, "ip", "-j", "link", "show"))
    state = {}
    for link in links:
        name = link["ifname"]
        if name not in FALLBACKS and name not in ("criu-sit", "erspan0"):
            continue
        state[name] = {key: link.get(key) for key in ("ifindex", "mtu", "flags", "address")}
        for option in ("mtu", "disable_ipv6"):
            value = in_net(pid, "sysctl", "-e", "-n", f"net.ipv6.conf.{name}.{option}").strip()
            state[name][f"ipv6_{option}"] = int(value) if value else None
    return state


def check_restored_links(criu, pid, directory, plugins, before, expected_error=None):
    pidfile = directory / "restored.pid"
    try:
        result = subprocess.run(
            [str(criu), "restore", "--no-default-config", "-D", str(directory),
             "-o", "restore.log", "-v4", "--shell-job", "--manage-cgroups=ignore",
             "--network-lock", "skip", "--libdir", str(plugins),
             "--restore-detached", "--restore-sibling", "--pidfile", str(pidfile)],
            stdin=subprocess.DEVNULL, check=False, timeout=60)
        log = (directory / "restore.log").read_text()
        if expected_error:
            if not result.returncode or expected_error not in log:
                fail(f"Expected restore failure {expected_error!r}", directory)
        else:
            if result.returncode:
                fail("Restore failed", directory)
            restored = int(pidfile.read_text())
            after = link_state(restored)
            if after != before:
                fail(f"Restored links differ: before={before}, after={after}", directory)
    finally:
        # --restore-sibling makes the restored task our child, including on failure.
        if pidfile.exists():
            pid = int(pidfile.read_text())
        try:
            if os.waitpid(pid, os.WNOHANG)[0] == 0:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
        except ChildProcessError:
            # Restore may fail before creating a child, or the child may
            # already have been reaped.
            pass


def check_restore(criu, worker, work, plugins):
    from pycriu import images

    pid = worker.pid
    # The ordinary IPIP device only exercises dump dispatch; it needs an external
    # setup script on restore. Fallback devices are created by the kernel.
    in_net(pid, "ip", "link", "del", "criu-ipip")
    live = json.loads(in_net(pid, "ip", "-j", "link", "show"))
    names = list(FALLBACKS)
    if any(link["ifname"] == "erspan0" for link in live):
        names.append("erspan0")
    for name in names:
        if name in ("gretap0", "erspan0"):
            in_net(pid, "ip", "link", "set", "dev", name, "address", "02:00:00:00:00:01")
        in_net(pid, "ip", "link", "set", "dev", name, "mtu", "1400", "up")
    before = link_state(pid)
    directory = work / "restore"
    status, _ = dump(criu, pid, directory, plugins, "sit0", "accept")
    if status:
        fail("Dump for restore failed", directory)

    worker.kill()
    worker.wait()
    check_restored_links(criu, pid, directory, plugins, before)
    print("PASS: configured fallback restore", flush=True)

    # A different tunnel address must still reach the setter and fail, rather
    # than being silently discarded along with unchanged addresses.
    mismatch = work / "restore-address-mismatch"
    shutil.copytree(directory, mismatch)
    (mismatch / "restored.pid").unlink()
    changed = False
    for path in mismatch.glob("netdev-*.img"):
        with path.open("rb") as stream:
            image = images.load(stream)
        for entry in image["entries"]:
            if entry["name"] == "sit0":
                entry["address"] = base64.b64encode(bytes([192, 0, 2, 1])).decode()
                changed = True
        with path.open("wb") as stream:
            images.dump(image, stream)
    if not changed:
        fail("Missing sit0 image for the address mismatch test", mismatch)
    check_restored_links(criu, pid, mismatch, plugins, before,
                         expected_error=f"-{errno.EOPNOTSUPP} reported by netlink:")
    print("PASS: unsupported fallback address mismatch", flush=True)


def check_ipv6_mtu_restore(criu, work, plugins, mode):
    from pycriu import images

    worker = subprocess.Popen(
        ["unshare", "--net", "--", "sleep", "infinity"], start_new_session=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        wait_for_netns(worker)
        pid = worker.pid
        initial = link_state(pid)
        if initial.get("gretap0", {}).get("ipv6_mtu") is None:
            raise RuntimeError("The IPv6 MTU restore test requires gretap0 with IPv6 support")

        if mode == "enable-ipv6":
            # Restore must re-enable IPv6 on gretap0 after restoring the
            # namespace defaults, and then restore its smaller IPv6 MTU.
            in_net(pid, "sysctl", "-q", "-w", "net.ipv6.conf.all.disable_ipv6=1")
            in_net(pid, "ip", "link", "set", "dev", "gretap0",
                   "address", "02:00:00:00:00:01", "up")
            in_net(pid, "sysctl", "-q", "-w", "net.ipv6.conf.gretap0.disable_ipv6=0")
        if mode != "default":
            # Matching the saved namespace default must not suppress a
            # necessary write of the device's IPv6 MTU.
            in_net(pid, "sysctl", "-q", "-w", "net.ipv6.conf.default.mtu=1280",
                   "net.ipv6.conf.gretap0.mtu=1280")

        before = link_state(pid)
        directory = work / f"restore-ipv6-mtu-{mode}"
        status, _ = dump(criu, pid, directory, plugins, "gretap0", "accept")
        if status:
            fail("Dump for IPv6 MTU restore failed", directory)
        worker.kill()
        worker.wait()
        check_restored_links(criu, pid, directory, plugins, before)
        print(f"PASS: {mode} fallback IPv6 MTU restore", flush=True)

        if mode == "default":
            # Force a real mismatch: the lower link MTU changes the live IPv6
            # MTU, and the saved larger IPv6 MTU must still be rejected.
            mismatch = work / "restore-ipv6-mtu-mismatch"
            shutil.copytree(directory, mismatch)
            (mismatch / "restored.pid").unlink()
            changed = False
            for path in mismatch.glob("netdev-*.img"):
                with path.open("rb") as stream:
                    image = images.load(stream)
                for entry in image["entries"]:
                    if entry["name"] == "gretap0":
                        entry["mtu"] = 1280
                        changed = True
                with path.open("wb") as stream:
                    images.dump(image, stream)
            if not changed:
                fail("Missing gretap0 image for the IPv6 MTU mismatch test", mismatch)
            check_restored_links(
                criu, pid, mismatch, plugins, before,
                expected_error="Can't write net/ipv6/conf/gretap0/mtu: Invalid argument")
            print("PASS: unsupported fallback IPv6 MTU mismatch", flush=True)
    finally:
        if worker.poll() is None:
            worker.kill()
            worker.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--criu", type=Path, default=ROOT / "criu/criu")
    parser.add_argument("--devices", nargs="+", choices=FALLBACKS, default=list(FALLBACKS))
    parser.add_argument("--restore", action="store_true", help="also check fallback restore")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run as root")

    work = Path(tempfile.mkdtemp(prefix="criu-fallback-"))
    print(f"Logs and images: {work}", flush=True)
    plugins = work / "plugins"
    plugins.mkdir()
    shutil.copy2(HERE / "fallback.so", plugins)
    worker = subprocess.Popen(
        ["unshare", "--net", "--", "sleep", "infinity"], start_new_session=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        wait_for_netns(worker)
        live = {link["ifname"]: link for link in
                json.loads(in_net(worker.pid, "ip", "-j", "-d", "link", "show"))}
        for name in args.devices:
            if live.get(name, {}).get("linkinfo", {}).get("info_kind") != FALLBACKS[name]:
                raise RuntimeError(f"Missing {name}; load its tunnel module before running this test")
            if name == "gretap0":
                in_net(worker.pid, "ip", "link", "set", "dev", name,
                       "address", "02:00:00:00:00:01")
            in_net(worker.pid, "ip", "link", "set", "dev", name, "mtu", "1400", "up")

        in_net(worker.pid, "ip", "link", "add", "criu-sit", "type", "sit",
               "local", "192.0.2.1", "remote", "192.0.2.2")
        in_net(worker.pid, "ip", "link", "add", "criu-ipip", "type", "ipip",
               "local", "192.0.2.1", "remote", "192.0.2.2")
        in_net(worker.pid, "ip", "link", "set", "dev", "criu-ipip", "mtu", "1400", "up")
        for name in args.devices:
            for mode in ("accept", "decline", "error"):
                check_case(args.criu.resolve(), worker.pid, work, plugins,
                           name, FALLBACKS[name], mode)
        for mode in ("accept", "decline", "error"):
            check_case(args.criu.resolve(), worker.pid, work, plugins,
                       "criu-ipip", "ipip", mode, fallback=False)
        if args.restore:
            check_restore(args.criu.resolve(), worker, work, plugins)
            for mode in ("default", "changed", "enable-ipv6"):
                check_ipv6_mtu_restore(args.criu.resolve(), work, plugins, mode)
    finally:
        if worker.poll() is None:
            worker.kill()
            worker.wait()


if __name__ == "__main__":
    main()
