#!/usr/bin/env python3

"""A failed pre-dump script must return an error before plugins are initialized."""

from pathlib import Path
import resource
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[3]


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    with tempfile.TemporaryDirectory(prefix="criu-action-script-failure-") as work:
        directory = Path(work)
        plugins = directory / "plugins"
        plugins.mkdir()
        target = subprocess.Popen(["sleep", "300"], stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            result = subprocess.run([
                str(ROOT / "criu/criu"), "dump", "--no-default-config",
                "--tree", str(target.pid), "--images-dir", str(directory),
                "--log-file", "dump.log", "--verbosity=4", "--shell-job",
                "--libdir", str(plugins), "--action-script", "/bin/false",
            ], timeout=30)
            log = (directory / "dump.log").read_text()
            assert result.returncode == 1, f"CRIU exited with {result.returncode}\n{log}"
            assert "Pre dump script failed" in log, log
            assert "Dumping FAILED" in log, log
            assert target.poll() is None, "pre-dump failure killed the target"
            status = Path(f"/proc/{target.pid}/status").read_text()
            assert "TracerPid:\t0\n" in status, status
        finally:
            target.kill()
            target.wait(timeout=5)
    print("Pre-dump script failure PASS")


if __name__ == "__main__":
    main()
