#!/usr/bin/env python3
"""Shared Podman serving checkpoint/restore benchmark implementation."""

import argparse
import base64
import contextlib
import errno
import fcntl
import hashlib
import json
import os
import platform
import posixpath
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

# Sentinel distinguishing "runc.conf never touched" from "stashed, but the
# file did not exist" (which stashes None).
_RUNC_CONF_UNSET = object()


class RuntimeState:
    """Mutable resources owned by this benchmark process."""

    def __init__(self):
        self.tempdirs = set()
        self.started_containers = set()
        self.cleanup_containers = True
        self.original_runc_conf = _RUNC_CONF_UNSET
        self.runc_conf_lock_fd = None
        self.runc_conf_path = None
        self.runc_conf_state_path = None
        self.runc_conf_state = None
        self.criu_wrapper_dir = None
        self.cleanup_started = False
        self.received_signal = None


PODMAN = "podman"
RUNC_CONF_BEGIN = "# BEGIN criu-compression-benchmark"
RUNC_CONF_END = "# END criu-compression-benchmark"
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
MAX_REGION_SIZE = 4 * 1024 * 1024
MAX_COMPRESSION_ACCELERATION = 65537
MAX_DECOMPRESSION_THREADS = 1024
COMPRESSION_OPTIONS = {
    "compress", "compress-region", "compress-acceleration",
    "decompress-threads",
}
HF_TOKEN_ENV_VARS = ("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN")
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SIGNALS = (signal.SIGINT, signal.SIGHUP, signal.SIGTERM)


class ServingBenchmark:
    """One framework driver with process-local mutable resource state."""

    def __init__(self, adapter, description):
        self.adapter = adapter
        self.description = description
        self.state = RuntimeState()

    def cleanup(self):
        return cleanup(self)

    def signal_handler(self, signum, frame):
        return signal_handler(self, signum, frame)

    def podman_env(self, args):
        return podman_env(self, args)

    def ensure_no_default_config_wrapper(self):
        return ensure_no_default_config_wrapper(self)

    def release_runc_conf_lock(self):
        return release_runc_conf_lock(self)

    def set_runc_conf_for_cfg(self, path, cfg, acceleration,
                              decompress_threads=None):
        return set_runc_conf_for_cfg(
            self, path, cfg, acceleration, decompress_threads
        )

    def restore_runc_conf(self):
        return restore_runc_conf(self)

    def build_container_cmd(self, name, args):
        return build_container_cmd(self, name, args)

    def start_container(self, name, args):
        return start_container(self, name, args)

    def checkpoint_container(self, name, archive, cfg, args):
        return checkpoint_container(self, name, archive, cfg, args)

    def restore_container(self, name, archive, args):
        return restore_container(self, name, archive, args)

    def chat_once(self, base_url, model, prompt, max_tokens, temperature,
                  seed, timeout, extra_body=None):
        return chat_once(
            base_url, model, prompt, max_tokens, temperature, seed, timeout,
            extra_body, self.adapter.display_name
        )

    def run_trial(self, cfg, workdir, args, trial_id, keep_running=False):
        return run_trial(self, cfg, workdir, args, trial_id, keep_running)

    def report(self, results_by_cfg, order):
        return report(self, results_by_cfg, order)

    def main(self, argv=None):
        return run_main(self, argv, self.description)


@contextlib.contextmanager
def _blocked_termination_signals():
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def cleanup(benchmark):
    runtime = benchmark.state
    if runtime.cleanup_started:
        return
    with _blocked_termination_signals():
        runtime.cleanup_started = True
        try:
            restore_runc_conf(benchmark)
        except (OSError, RuntimeError, ValueError) as e:
            print(f"cleanup: failed to restore runc.conf: {e}", file=sys.stderr)
        if runtime.cleanup_containers:
            for name in list(runtime.started_containers):
                try:
                    result = subprocess.run([PODMAN, "rm", "-f", name],
                                            capture_output=True, text=True)
                except OSError as e:
                    print(f"cleanup: failed to execute Podman for {name}: {e}",
                          file=sys.stderr)
                    continue
                if result.returncode:
                    detail = (result.stderr or result.stdout).strip()
                    print(f"cleanup: failed to remove {name}: {detail[-1000:]}",
                          file=sys.stderr)
            runtime.started_containers.clear()
        for path in list(runtime.tempdirs):
            shutil.rmtree(path, ignore_errors=True)
            if os.path.exists(path):
                print(f"cleanup: failed to remove temporary directory {path}",
                      file=sys.stderr)
        runtime.tempdirs.clear()


def signal_handler(benchmark, signum, frame):
    runtime = benchmark.state
    if runtime.received_signal is not None:
        return
    runtime.received_signal = signum
    # Defer cleanup until subprocess.run() has killed and waited for its
    # active child and Python starts unwinding through atexit handlers.
    for handled in SIGNALS:
        signal.signal(handled, signal.SIG_IGN)
    raise SystemExit(128 + signum)


def median(v):
    s = sorted(v)
    n = len(s)
    if n == 0:
        return 0
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def format_bytes(byte_count):
    if byte_count >= 1073741824:
        return f"{byte_count / 1073741824:.2f} GB"
    return f"{byte_count / 1048576:.1f} MB"


def format_duration(microseconds):
    if microseconds >= 1e6:
        return f"{microseconds / 1e6:.3f} s"
    return f"{microseconds / 1000:.1f} ms"


def cfg_label(cfg):
    if cfg["mode"] == "uncompressed":
        return "Uncompressed"
    if cfg["mode"] == "lz4-page":
        return f"LZ4 per page ({PAGE_SIZE // 1024} KiB blocks)"
    return f"LZ4 regions ({cfg['region_size'] // 1024} KiB blocks)"


def decompress_threads_label(threads):
    """None uses CRIU's serial default; 0 is auto; positive values are explicit."""
    if threads is None:
        return "default (serial)"
    if threads == 0:
        return "auto"
    return str(threads)


def server_base_url(port, base_url):
    if base_url is not None:
        return base_url
    return f"http://127.0.0.1:{port}"


def json_object(value):
    try:
        obj = json.loads(value)
    except json.JSONDecodeError as e:
        raise argparse.ArgumentTypeError(str(e))
    if not isinstance(obj, dict):
        raise argparse.ArgumentTypeError("expected a JSON object")
    return obj


def collect_system_info():
    info = {"kernel": platform.release(), "arch": platform.machine(),
            "cpus": os.cpu_count()}
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    info["cpu"] = line.split(":", 1)[1].strip()
                    break
    except OSError:
        info["cpu"] = "unknown"
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal"):
                    info["memory_mb"] = int(line.split()[1]) // 1024
                    break
    except OSError:
        info["memory_mb"] = 0
    for cmd, key in (([PODMAN, "--version"], "podman"),
                     (["criu", "--version"], "criu")):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode == 0:
                info[key] = r.stdout.strip()
        except OSError:
            info[key] = "unknown"
    try:
        r = subprocess.run(["nvidia-smi", "--query-gpu=name",
                            "--format=csv,noheader"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            info["gpus"] = [line.strip() for line in r.stdout.splitlines()
                            if line.strip()]
    except OSError:
        info["gpus"] = []
    return info


def http_json(method, url, payload=None, timeout=120):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
        headers["Authorization"] = "Bearer EMPTY"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
    return json.loads(body.decode()) if body else {}


def podman_text(args):
    try:
        r = subprocess.run([PODMAN, *args], capture_output=True, text=True)
    except OSError as e:
        return f"unable to execute Podman: {e}"
    return (r.stdout + r.stderr).strip()


def container_diagnostics(name):
    parts = [f"container={name}"]
    ps = podman_text(["ps", "-a", "--filter", f"name=^{name}$",
                      "--format", "{{.Names}} {{.Status}} {{.Ports}}"])
    if ps:
        parts.append(f"podman ps:\n{ps}")
    logs = podman_text(["logs", "--tail", "80", name])
    if logs:
        parts.append(f"last logs:\n{logs[-6000:]}")
    return "\n\n".join(parts)


def container_exit_code(name):
    """Return an exit code for a stopped container, or None otherwise."""
    try:
        result = subprocess.run(
            [PODMAN, "inspect", "--format",
             "{{.State.Running}} {{.State.ExitCode}}", name],
            capture_output=True, text=True,
        )
    except OSError:
        return None
    if result.returncode:
        return None
    fields = result.stdout.strip().split()
    if len(fields) != 2 or fields[0].lower() != "false":
        return None
    try:
        return int(fields[1])
    except ValueError:
        return None


def wait_health(base_url, health_path, timeout, container_name=None,
                framework_name="serving"):
    deadline = time.monotonic() + timeout
    next_state_check = 0
    last = None
    url = f"{base_url.rstrip('/')}/{health_path.lstrip('/')}"
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(url, timeout=5).read()
            return
        except (OSError, urllib.error.URLError) as e:
            last = e
            now = time.monotonic()
            if container_name and now >= next_state_check:
                next_state_check = now + 5
                exit_code = container_exit_code(container_name)
                if exit_code is not None:
                    raise RuntimeError(
                        f"{framework_name} container exited with status {exit_code} "
                        f"before becoming healthy\n\n"
                        f"{container_diagnostics(container_name)}"
                    ) from e
            time.sleep(1)
    detail = ""
    if container_name:
        detail = "\n\n" + container_diagnostics(container_name)
    raise RuntimeError(
        f"{framework_name} health check timed out after {timeout}s: {last}{detail}"
    )


def chat_once(base_url, model, prompt, max_tokens, temperature, seed, timeout,
              extra_body=None, framework_name="serving"):
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
        "seed": seed,
    }
    if extra_body:
        payload.update(extra_body)
    t0 = time.monotonic()
    data = http_json("POST", f"{base_url.rstrip('/')}/v1/chat/completions",
                     payload, timeout)
    latency_us = int((time.monotonic() - t0) * 1e6)
    content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
    if not content.strip():
        raise RuntimeError(f"{framework_name} validation returned an empty response")
    return latency_us, content


def format_cmd(cmd):
    """Format a command without printing values passed through --env."""
    out = []
    redact_next = False
    for item in cmd:
        if redact_next:
            name = item.split("=", 1)[0]
            out.append(f"{name}=<redacted>" if "=" in item else item)
            redact_next = False
            continue
        if item.startswith("--env=") or (item.startswith("-e") and
                                           not item.startswith("--")):
            if item.startswith("--env="):
                option, value = item.split("=", 1)
            else:
                option, value = "-e", item[2:].lstrip("=")
            name = value.split("=", 1)[0]
            out.append(f"{option}{'=' if option == '--env' else ''}"
                       f"{name}=<redacted>" if "=" in value
                       else item)
            continue
        out.append(item)
        redact_next = item in ("--env", "-e")
    return " ".join(out)


def run_arg_sets_environment(item):
    """Return whether a raw Podman argument can carry an environment value."""
    return (item == "--env" or item.startswith("--env=") or
            (item.startswith("-e") and not item.startswith("--")))


def redact_run_arg(item):
    if item.startswith("--env=") or (item.startswith("-e") and
                                       not item.startswith("--")):
        if item.startswith("--env="):
            option, value = item.split("=", 1)
        else:
            option, value = "-e", item[2:].lstrip("=")
        name = value.split("=", 1)[0]
        separator = "=" if option == "--env" else ""
        return f"{option}{separator}{name}=<redacted>" if "=" in value else item
    return item


def redact_run_args(items):
    out = []
    redact_next = False
    for item in items:
        if redact_next:
            name = item.split("=", 1)[0]
            out.append(f"{name}=<redacted>" if "=" in item else item)
            redact_next = False
            continue
        out.append(redact_run_arg(item))
        redact_next = item in ("--env", "-e")
    return out


def run_cmd(cmd, env=None, check=True):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, env=env)
    except OSError as e:
        raise RuntimeError(f"unable to execute {format_cmd(cmd)}: {e}") from e
    if check and r.returncode:
        msg = (r.stderr or r.stdout).strip()
        raise RuntimeError(f"{format_cmd(cmd)} failed: {msg[-6000:]}")
    return r


def podman_env(benchmark, args):
    env = os.environ.copy()
    # Start CRIU without global, user, or inherited configuration. runc still
    # supplies the benchmark-owned runc.conf through the RPC request.
    env.pop("CRIU_CONFIG_FILE", None)
    wrapper_dir = benchmark.ensure_no_default_config_wrapper()
    env["PATH"] = wrapper_dir + os.pathsep + env.get("PATH", os.defpath)
    if args.criu_libdir:
        env["CRIU_LIBS_DIR"] = args.criu_libdir
    return env


def ensure_no_default_config_wrapper(benchmark):
    runtime = benchmark.state
    if runtime.criu_wrapper_dir is not None:
        return runtime.criu_wrapper_dir
    criu = shutil.which("criu")
    if criu is None:
        raise RuntimeError("criu was not found in PATH")
    wrapper_dir = tempfile.mkdtemp(prefix="criu-no-default-config-")
    runtime.tempdirs.add(wrapper_dir)
    wrapper = os.path.join(wrapper_dir, "criu")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(wrapper, flags, 0o700)
    try:
        with os.fdopen(fd, "w") as output:
            fd = -1
            output.write("#!/bin/sh\n")
            output.write(f"exec {shlex.quote(criu)} --no-default-config \"$@\"\n")
    finally:
        if fd >= 0:
            os.close(fd)
    runtime.criu_wrapper_dir = wrapper_dir
    return wrapper_dir


def read_file(path):
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return None


def _sync_directory(path):
    directory = os.path.dirname(path) or "."
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_xattrs(path):
    if not hasattr(os, "listxattr"):
        return None
    try:
        names = os.listxattr(path)
    except OSError as e:
        if e.errno in (errno.ENOTSUP, errno.ENOSYS):
            return None
        raise
    return {
        name: base64.b64encode(os.getxattr(path, name)).decode("ascii")
        for name in names
    }


def _apply_xattrs(path, encoded):
    if encoded is None:
        return
    current = _read_xattrs(path)
    if current is None:
        if encoded:
            raise OSError(errno.ENOTSUP, "extended attributes are unsupported",
                          path)
        return
    for name in current.keys() - encoded.keys():
        os.removexattr(path, name)
    for name, value in encoded.items():
        decoded = base64.b64decode(value, validate=True)
        if current.get(name) != value:
            os.setxattr(path, name, decoded)


def _apply_metadata(path, metadata):
    current = os.stat(path)
    if current.st_uid != metadata["uid"] or current.st_gid != metadata["gid"]:
        os.chown(path, metadata["uid"], metadata["gid"])
    os.chmod(path, metadata["mode"])
    _apply_xattrs(path, metadata.get("xattrs"))
    os.utime(path, ns=(metadata["atime_ns"], metadata["mtime_ns"]))


def write_file(path, data, metadata=None):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}.{time.monotonic_ns()}"
    if metadata is None:
        metadata = _runc_conf_metadata(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            fd = -1
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
            if metadata is not None:
                _apply_metadata(tmp, metadata)
                os.fsync(f.fileno())
        os.replace(tmp, path)
        _sync_directory(path)
    finally:
        if fd >= 0:
            os.close(fd)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)


def _runc_conf_metadata(path):
    try:
        metadata = os.stat(path)
    except FileNotFoundError:
        return None
    return {
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "atime_ns": metadata.st_atime_ns,
        "mtime_ns": metadata.st_mtime_ns,
        "xattrs": _read_xattrs(path),
    }


def _file_state(path):
    # Capture timestamps before opening the file: reading an old file can
    # update its atime under relatime.
    metadata = _runc_conf_metadata(path)
    content = read_file(path) if metadata is not None else None
    return {
        "existed": content is not None,
        "content": content,
        "metadata": metadata,
    }


def _metadata_identity(metadata):
    if metadata is None:
        return None
    return {key: metadata.get(key) for key in
            ("mode", "uid", "gid", "mtime_ns", "xattrs")}


def _same_file_state(actual, expected):
    if actual["existed"] != expected["existed"]:
        return False
    if not actual["existed"]:
        return True
    if actual["content"] != expected["content"]:
        return False
    # Metadata for a newly created pending file is not known until after its
    # atomic rename. Content still makes that narrow recovery window safe.
    if expected.get("metadata") is None:
        return True
    return (_metadata_identity(actual["metadata"]) ==
            _metadata_identity(expected["metadata"]))


def _owned_runc_conf_state(state):
    current = _file_state(state["path"])
    owned = [state["active"]]
    if state.get("pending") is not None:
        owned.append(state["pending"])
    if not any(_same_file_state(current, item) for item in owned):
        raise RuntimeError(
            f"{state['path']} changed outside the compression benchmark; "
            "refusing to overwrite it (recovery state was preserved)"
        )
    return current


def _restore_runc_conf_state(state, state_path):
    _owned_runc_conf_state(state)
    path = state["path"]
    original = state["original"]
    # Journal the restore before changing the target. If the process dies
    # after the rename/unlink but before removing the journal, the next run
    # can recognize the original file as benchmark-owned recovery work.
    state["pending"] = original
    _write_recovery_state(state_path, state)
    if original["existed"]:
        write_file(path, original["content"], original["metadata"])
    else:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
        _sync_directory(path)


def _write_recovery_state(path, state):
    tmp = f"{path}.tmp.{os.getpid()}.{time.monotonic_ns()}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "w") as output:
            fd = -1
            json.dump(state, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(tmp, path)
        _sync_directory(path)
    finally:
        if fd >= 0:
            os.close(fd)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)


def _read_recovery_state(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd) as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"invalid runc.conf recovery file: {path}")
        state = json.load(source)
    if (not isinstance(state, dict) or
            not all(key in state for key in ("path", "original", "active"))):
        raise RuntimeError(f"invalid runc.conf recovery file: {path}")
    return state


def acquire_runc_conf(benchmark, path):
    runtime = benchmark.state
    # Every spelling of the same target, including symlink aliases, must use
    # one lock and one recovery journal.
    target = os.path.realpath(path)
    lock_path = target + ".compression-benchmark.lock"
    directory = os.path.dirname(lock_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    lock_fd = os.open(lock_path, flags, 0o600)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError(
                f"another compression benchmark is using {path}"
            ) from exc

        state_path = lock_path + ".state"
        if os.path.exists(state_path):
            state = _read_recovery_state(state_path)
            if state.get("path") != target:
                raise RuntimeError(
                    f"runc.conf recovery state refers to {state.get('path')}, "
                    f"not {target}"
                )
            _restore_runc_conf_state(state, state_path)
            os.unlink(state_path)
            _sync_directory(state_path)

        original = _file_state(target)
        state = {
            "path": target,
            "original": original,
            "active": original,
            "pending": None,
        }
        _write_recovery_state(state_path, state)
        runtime.runc_conf_lock_fd = lock_fd
        runtime.runc_conf_path = target
        runtime.runc_conf_state_path = state_path
        runtime.runc_conf_state = state
        return target, original["content"]
    except BaseException:
        os.close(lock_fd)
        raise


def release_runc_conf_lock(benchmark):
    runtime = benchmark.state
    if runtime.runc_conf_lock_fd is not None:
        fcntl.flock(runtime.runc_conf_lock_fd, fcntl.LOCK_UN)
        os.close(runtime.runc_conf_lock_fd)
    runtime.runc_conf_lock_fd = None
    runtime.runc_conf_path = None
    runtime.runc_conf_state_path = None
    runtime.runc_conf_state = None


def strip_compression_runc_options(text):
    """Remove prior benchmark blocks and any ambient compression options."""
    if not text:
        return ""
    lines = text.splitlines()
    out = []
    skipping = False
    for line in lines:
        if line.strip() == RUNC_CONF_BEGIN:
            skipping = True
            continue
        if line.strip() == RUNC_CONF_END:
            skipping = False
            continue
        if skipping:
            continue
        statement = line.strip()
        if not statement or statement.startswith("#"):
            out.append(line)
            continue
        option = statement.split(None, 1)[0].split("=", 1)[0]
        option = option.lstrip("-").replace("_", "-")
        if option not in COMPRESSION_OPTIONS:
            out.append(line)
    return "\n".join(out).rstrip()


def compression_config_lines(cfg, acceleration, decompress_threads=None):
    if cfg["mode"] == "uncompressed":
        return []
    if cfg["mode"] == "lz4-page":
        lines = ["compress"]
    else:
        lines = [f"compress-region {cfg['region_size']}"]
    if acceleration != 1:
        lines.append(f"compress-acceleration {acceleration}")
    if decompress_threads is not None:
        lines.append(f"decompress-threads {decompress_threads}")
    return lines


def set_runc_conf_for_cfg(benchmark, path, cfg, acceleration,
                          decompress_threads=None):
    runtime = benchmark.state
    if runtime.original_runc_conf is _RUNC_CONF_UNSET:
        path, original = acquire_runc_conf(benchmark, path)
        runtime.original_runc_conf = original
    else:
        path = runtime.runc_conf_path

    base = strip_compression_runc_options(runtime.original_runc_conf)
    lines = compression_config_lines(cfg, acceleration, decompress_threads)
    if lines:
        block = "\n".join([RUNC_CONF_BEGIN, *lines, RUNC_CONF_END])
        text = f"{base}\n\n{block}\n" if base else f"{block}\n"
    else:
        text = f"{base}\n" if base else ""
    current = _owned_runc_conf_state(runtime.runc_conf_state)
    runtime.runc_conf_state["pending"] = {
        "existed": True,
        "content": text,
        "metadata": current["metadata"],
    }
    _write_recovery_state(runtime.runc_conf_state_path,
                          runtime.runc_conf_state)
    write_file(path, text, current["metadata"])
    runtime.runc_conf_state["active"] = _file_state(path)
    runtime.runc_conf_state["pending"] = None
    _write_recovery_state(runtime.runc_conf_state_path,
                          runtime.runc_conf_state)


def restore_runc_conf(benchmark):
    runtime = benchmark.state
    if runtime.original_runc_conf is _RUNC_CONF_UNSET:
        return
    path = runtime.runc_conf_path
    if not path:
        return
    with _blocked_termination_signals():
        try:
            _restore_runc_conf_state(runtime.runc_conf_state,
                                     runtime.runc_conf_state_path)
            if runtime.runc_conf_state_path is not None:
                os.unlink(runtime.runc_conf_state_path)
                _sync_directory(runtime.runc_conf_state_path)
        finally:
            runtime.original_runc_conf = _RUNC_CONF_UNSET
            release_runc_conf_lock(benchmark)


def build_container_cmd(benchmark, name, args):
    cmd = [
        PODMAN, "run", "-d",
        "--name", name,
        "--security-opt", args.security_opt,
        "--network", "host",
        "--shm-size", args.shm_size,
        "-v", f"{args.hf_cache}:/root/.cache/huggingface",
    ]
    for name in HF_TOKEN_ENV_VARS:
        # Podman copies the value from its environment. It never appears in
        # this process's command line or in an error message.
        if name in os.environ:
            cmd += ["--env", name]
    if args.accelerator == "gpu":
        cmd += [
            "--device", args.gpu_device,
            "--env", f"CUDA_VISIBLE_DEVICES={args.cuda_visible_devices}",
            "--env", "NCCL_P2P_DISABLE=1",
            "--env", "NCCL_SHM_DISABLE=1",
            "--env", "NCCL_IB_DISABLE=1",
            "--env", "NCCL_CUMEM_ENABLE=0",
        ]
    else:
        cmd += benchmark.adapter.cpu_podman_args(args)
    for item in args.env:
        cmd += ["--env", item]
    for item in args.volume:
        cmd += ["-v", item]
    for item in args.run_arg:
        cmd.append(item)
    for item in args.ulimit:
        cmd += ["--ulimit", item]

    cmd += benchmark.adapter.server_argv(args)

    return cmd


def start_container(benchmark, name, args):
    os.makedirs(args.hf_cache, exist_ok=True)
    cmd = build_container_cmd(benchmark, name, args)

    run_cmd([PODMAN, "rm", "-f", name], check=False)
    benchmark.state.started_containers.add(name)
    run_cmd(cmd, env=podman_env(benchmark, args))
    print(f"  waiting for {name} health on {args.base_url}", flush=True)
    wait_health(args.base_url, args.health_path, args.wait_seconds, name,
                benchmark.adapter.display_name)


def checkpoint_container(benchmark, name, archive, cfg, args):
    set_runc_conf_for_cfg(benchmark, args.runc_conf, cfg,
                          args.compress_acceleration,
                          args.decompress_threads)
    cmd = [
        PODMAN, "container", "checkpoint",
        "--export", archive,
        "--compress", args.archive_compression,
        "--ignore-volumes",
        "--tcp-established",
    ]
    if args.print_stats:
        cmd.append("--print-stats")
    if args.keep_checkpoint_files:
        cmd.append("--keep")
    cmd.append(name)

    t0 = time.monotonic()
    r = run_cmd(cmd, env=podman_env(benchmark, args))
    checkpoint_us = int((time.monotonic() - t0) * 1e6)
    return checkpoint_us, r.stdout.strip()


def _tar_command(cmd, binary=False):
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=not binary)
    except OSError as exc:
        raise RuntimeError(f"unable to inspect checkpoint archive: {exc}") from exc
    if result.returncode:
        stderr = result.stderr
        if binary:
            stderr = stderr.decode(errors="replace")
        raise RuntimeError(
            "unable to inspect checkpoint archive: " + stderr.strip()[-2000:]
        )
    return result.stdout


def inventory_bytes_from_archive(archive):
    listing = _tar_command(["tar", "--list", "--file", archive])
    inventories = [
        member for member in listing.splitlines()
        if posixpath.basename(member.rstrip("/")) == "inventory.img"
    ]
    if len(inventories) != 1:
        raise RuntimeError(
            "checkpoint archive must contain exactly one inventory.img; "
            f"found {len(inventories)}"
        )
    return _tar_command([
        "tar", "--extract", "--to-stdout", "--file", archive,
        "--", inventories[0],
    ], binary=True)


def inventory_entry_from_archive(archive):
    if os.path.join(REPO_ROOT, "lib") not in sys.path:
        sys.path.insert(0, os.path.join(REPO_ROOT, "lib"))
    try:
        from pycriu import images as pimg
        inventory = pimg.loads(inventory_bytes_from_archive(archive))
    except Exception as exc:
        raise RuntimeError(
            "unable to decode checkpoint inventory; build the CRIU Python "
            f"bindings with 'make -C {REPO_ROOT} lib': {exc}"
        ) from exc
    if inventory.get("magic") != "INVENTORY":
        raise RuntimeError("checkpoint inventory has the wrong image magic")
    entries = inventory.get("entries", [])
    if len(entries) != 1:
        raise RuntimeError(
            f"checkpoint inventory must contain one entry; found {len(entries)}"
        )
    return entries[0]


def verify_archive_compression(archive, cfg):
    entry = inventory_entry_from_archive(archive)
    expected = {"uncompressed": 0, "lz4-page": 1, "lz4-region": 2}[cfg["mode"]]
    try:
        actual = int(entry.get("compress", 0))
    except (TypeError, ValueError) as exc:
        raise RuntimeError("checkpoint inventory has an invalid compression mode") from exc
    if actual != expected:
        raise RuntimeError(
            "checkpoint compression mode does not match the benchmark "
            f"configuration: expected {expected}, found {actual}"
        )
    if expected == 2:
        try:
            region_size = int(entry.get("compress_region_size", 0))
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                "checkpoint inventory has an invalid compression region size"
            ) from exc
        if region_size != cfg["region_size"]:
            raise RuntimeError(
                "checkpoint compression region does not match the benchmark "
                f"configuration: expected {cfg['region_size']}, found {region_size}"
            )
    return actual


def restore_container(benchmark, name, archive, args):
    cmd = [
        PODMAN, "container", "restore",
        "--import", archive,
        "--ignore-volumes",
        "--tcp-established",
    ]
    if args.print_stats:
        cmd.append("--print-stats")

    t0 = time.monotonic()
    benchmark.state.started_containers.add(name)
    r = run_cmd(cmd, env=podman_env(benchmark, args))
    restore_us = int((time.monotonic() - t0) * 1e6)
    print(f"  waiting for restored {name} health on {args.base_url}", flush=True)
    wait_health(args.base_url, args.health_path, args.wait_seconds, name,
                benchmark.adapter.display_name)
    return restore_us, r.stdout.strip()


def run_trial(benchmark, cfg, workdir, args, trial_id, keep_running=False):
    name = f"{args.container_name}-{os.getpid()}-{trial_id}"
    archive = os.path.join(workdir, f"{name}.tar")
    if args.archive_compression == "gzip":
        archive += ".gz"
    elif args.archive_compression == "zstd":
        archive += ".zst"

    benchmark.start_container(name, args)
    request_model = args.served_model_name or args.model
    for _ in range(args.warmup_requests):
        benchmark.chat_once(args.base_url, request_model, args.prompt,
                            args.max_tokens, args.temperature, args.seed,
                            args.request_timeout, args.chat_extra_json)
    pre_us, pre_content = benchmark.chat_once(
        args.base_url, request_model, args.prompt, args.max_tokens,
        args.temperature, args.seed, args.request_timeout,
        args.chat_extra_json,
    )
    checkpoint_us, checkpoint_stats = benchmark.checkpoint_container(
        name, archive, cfg, args
    )
    inventory_compress_mode = verify_archive_compression(archive, cfg)
    run_cmd([PODMAN, "rm", "-f", name])
    benchmark.state.started_containers.discard(name)
    restore_us, restore_stats = benchmark.restore_container(name, archive, args)
    post_us, post_content = benchmark.chat_once(
        args.base_url, request_model, args.prompt, args.max_tokens,
        args.temperature, args.seed, args.request_timeout,
        args.chat_extra_json,
    )
    pre_digest = hashlib.sha256(pre_content.encode()).hexdigest()
    post_digest = hashlib.sha256(post_content.encode()).hexdigest()
    valid = pre_digest == post_digest
    if not valid:
        raise RuntimeError(
            "deterministic validation response changed after restore: "
            f"before_sha256={pre_digest}, after_sha256={post_digest}"
        )
    if keep_running:
        # Exempt only the explicitly retained final container from atexit
        # cleanup. Earlier trials must release the shared host-network port.
        benchmark.state.started_containers.discard(name)
    else:
        run_cmd([PODMAN, "rm", "-f", name])
        benchmark.state.started_containers.discard(name)

    return {
        "archive_size": os.path.getsize(archive),
        "inventory_compress_mode": inventory_compress_mode,
        "checkpoint_wall_us": checkpoint_us,
        "restore_wall_us": restore_us,
        "pre_request_us": pre_us,
        "post_request_us": post_us,
        "checkpoint_stats": checkpoint_stats,
        "restore_stats": restore_stats,
        "validation_response_sha256": post_digest,
        "valid": valid,
        "framework": benchmark.adapter.key,
        "container_name": name if keep_running else None,
    }


def json_config(args):
    result = vars(args).copy()
    result["env"] = [
        f"{item.split('=', 1)[0]}=<redacted>" if "=" in item else item
        for item in args.env
    ]
    result["run_arg"] = redact_run_args(getattr(args, "run_arg", []))
    return result


def report(benchmark, results_by_cfg, order):
    label_width = max(20, max(len(label) for label in order))
    value_width = 14
    width = max(88, label_width + value_width * 3 + 12)
    print()
    print("=" * width)
    print(
        f"  PODMAN {benchmark.adapter.heading} "
        f"(n={len(next(iter(results_by_cfg.values())))})"
    )
    print("=" * width)
    ok = all(r["valid"] for trials in results_by_cfg.values() for r in trials)
    print(f"  Inference validation: {'PASS' if ok else 'FAIL'}")
    print()

    baseline = "Uncompressed" if "Uncompressed" in results_by_cfg else order[0]
    base = median([r["archive_size"] for r in results_by_cfg[baseline]])
    baseline_note = (
        "CRIU page-image compression disabled"
        if baseline == "Uncompressed"
        else "first selected configuration"
    )
    print(f"  Baseline: {baseline} ({baseline_note})")
    storage_header = (f"  {'configuration':<{label_width}} | "
                      f"{'archive':>{value_width}} | "
                      f"{'ratio':>{value_width}} | "
                      f"{'saved':>{value_width}}")
    print("  STORAGE (relative to baseline)")
    print(storage_header)
    print("  " + "-" * (len(storage_header) - 2))
    for label in order:
        size = median([r["archive_size"] for r in results_by_cfg[label]])
        ratio = size / base if base else 0
        print(f"  {label:<{label_width}} | {format_bytes(size):>{value_width}} | "
              f"{ratio:>{value_width - 1}.3f}x | "
              f"{(1-ratio):>{value_width}.0%}")
    print()

    print("  LATENCY (median)")
    latency_header = (f"  {'configuration':<{label_width}} | "
                      f"{'checkpoint':>{value_width}} | "
                      f"{'restore':>{value_width}} | "
                      f"{'request after':>{value_width}}")
    print(latency_header)
    print("  " + "-" * (len(latency_header) - 2))
    for label in order:
        trials = results_by_cfg[label]
        values = [
            format_duration(median([r[key] for r in trials]))
            for key in ("checkpoint_wall_us", "restore_wall_us",
                        "post_request_us")
        ]
        print(f"  {label:<{label_width}} | " + " | ".join(
            f"{value:>{value_width}}" for value in values))


def run_main(benchmark, argv=None, description=None):
    adapter = benchmark.adapter
    runtime = benchmark.state
    ap = argparse.ArgumentParser(description=description,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--accelerator", choices=["gpu", "cpu"], default="gpu",
                    help="Inference accelerator (default: gpu)")
    adapter.add_image_arguments(ap)
    ap.add_argument("--model", default="Qwen/Qwen3-0.6B")
    ap.add_argument("--served-model-name",
                    help="Model name to use in OpenAI API requests; defaults "
                         "to --model")
    adapter.add_model_arguments(ap)
    ap.add_argument("--port", type=int, default=30000)
    ap.add_argument("--base-url",
                    help="Server URL (default: http://127.0.0.1:PORT)")
    ap.add_argument("--health-path", default="/health")
    ap.add_argument("--container-name", default=adapter.default_container_name)
    ap.add_argument("-n", "--iterations", type=int, default=3)
    ap.add_argument("--modes", nargs="+",
                    default=["uncompressed", "lz4-page", "lz4-region"],
                    choices=["uncompressed", "lz4-page", "lz4-region"],
                    help="CRIU memory page compression modes to compare")
    ap.add_argument("--region-sizes", nargs="+", type=int,
                    default=[65536, 262144, 1048576],
                    help="Region sizes in bytes when --modes contains "
                         "lz4-region")
    ap.add_argument("--compress-acceleration", type=int, default=1,
                    help="CRIU LZ4 acceleration level")
    ap.add_argument("--decompress-threads", type=int, default=None,
                    help="CRIU LZ4/zero-fill worker concurrency "
                         "(default: unset = CRIU default; 0 = auto; "
                         "1 = serial per request; N > 1 = aggregate worker limit); "
                         "written to runc.conf")
    ap.add_argument("--runc-conf", default="/etc/criu/runc.conf",
                    help="CRIU config file read by runc during Podman checkpoint")
    ap.add_argument("--archive-compression", default="none",
                    choices=["none", "gzip", "zstd"],
                    help="Podman checkpoint archive compression")
    ap.add_argument("--criu-libdir", default=os.environ.get("CRIU_LIBS_DIR"),
                    help="Directory containing CRIU plugin .so files")
    ap.add_argument("--hf-cache", default=os.path.expanduser("~/.cache/huggingface"))
    ap.add_argument("--gpu-device", default="nvidia.com/gpu=all",
                    help="GPU device selector passed to podman --device")
    ap.add_argument("--security-opt", default="label=disable",
                    help="Security option passed to podman --security-opt")
    ap.add_argument("--cuda-visible-devices", default="0")
    ap.add_argument("--shm-size", default="32g")
    adapter.add_resource_arguments(ap)
    ap.add_argument("--prompt", default="Say hello in one short sentence.")
    ap.add_argument("--prompt-file",
                    help="Read the validation/warmup prompt from a text file")
    ap.add_argument("--max-tokens", type=int, default=32)
    ap.add_argument("--temperature", type=float, default=0,
                    help="Chat completion temperature for validation requests")
    ap.add_argument("--seed", type=int, default=42,
                    help="Chat completion seed used before and after restore")
    ap.add_argument("--chat-extra-json", type=json_object,
                    help="JSON object merged into every chat completion request")
    adapter.add_request_arguments(ap)
    ap.add_argument("--warmup-requests", type=int, default=0,
                    help="Extra successful chat requests to issue before the "
                         "measured pre-checkpoint request")
    ap.add_argument("--wait-seconds", type=int, default=900)
    ap.add_argument("--request-timeout", type=int, default=180)
    ap.add_argument("--env", action="append", default=[],
                    help="Extra container environment entry, e.g. KEY=VALUE")
    ap.add_argument("--volume", action="append", default=[],
                    help="Extra container volume, e.g. /host:/container")
    ap.add_argument("--run-arg", action="append", default=[],
                    help="Extra raw argument for podman run before the image")
    ap.add_argument("--ulimit", action="append", default=[],
                    help="Extra Podman ulimit, e.g. nofile=65535:524288")
    adapter.add_server_arguments(ap)
    ap.add_argument("--print-stats", action="store_true",
                    help="Ask Podman to print checkpoint/restore stats")
    ap.add_argument("--keep-checkpoint-files", action="store_true",
                    help="Pass --keep to podman checkpoint")
    ap.add_argument("--keep-running", action="store_true",
                    help="Leave only the final measured restored container "
                         "running")
    ap.add_argument("--json", metavar="FILE", help="Write raw results to JSON")
    args = ap.parse_args(argv)
    args.base_url = server_base_url(args.port, args.base_url)

    if args.iterations <= 0:
        ap.error("--iterations must be greater than zero")
    if not 1 <= args.compress_acceleration <= MAX_COMPRESSION_ACCELERATION:
        ap.error("--compress-acceleration must be between 1 and "
                 f"{MAX_COMPRESSION_ACCELERATION}")
    if args.decompress_threads is not None and \
            not 0 <= args.decompress_threads <= MAX_DECOMPRESSION_THREADS:
        ap.error("--decompress-threads must be between 0 and "
                 f"{MAX_DECOMPRESSION_THREADS}")
    if any(size <= 0 or size > MAX_REGION_SIZE or size % PAGE_SIZE
           for size in args.region_sizes):
        ap.error(f"--region-sizes must be positive multiples of {PAGE_SIZE} "
                 f"not exceeding {MAX_REGION_SIZE}")
    if len(args.modes) != len(set(args.modes)):
        ap.error("--modes must not contain duplicate values")
    if len(args.region_sizes) != len(set(args.region_sizes)):
        ap.error("--region-sizes must not contain duplicate values")
    if any(item.split("=", 1)[0] in HF_TOKEN_ENV_VARS for item in args.env):
        ap.error("set Hugging Face tokens in the host environment instead of "
                 "passing their values through --env")
    if any(run_arg_sets_environment(item) for item in args.run_arg):
        ap.error("pass environment entries through --env, not --run-arg")
    adapter.normalize_args(ap, args)
    if os.getuid() != 0:
        sys.exit("Error: run as root so Podman/CRIU can checkpoint the container")
    runtime.cleanup_containers = True

    import atexit
    for handled in SIGNALS:
        signal.signal(
            handled,
            lambda signum, frame: signal_handler(benchmark, signum, frame),
        )
    atexit.register(cleanup, benchmark)

    info = collect_system_info()
    print()
    adapter.prepare_args(args)
    if args.prompt_file:
        prompt = read_file(args.prompt_file)
        if prompt is None:
            sys.exit(f"Error: prompt file not found: {args.prompt_file}")
        args.prompt = prompt.rstrip("\n")

    print(f"Podman {adapter.display_name} Checkpoint/Restore Benchmark")
    print(f"  Kernel : {info.get('kernel', '?')}")
    print(f"  CPU    : {info.get('cpu', '?')}")
    print(f"  Memory : {info.get('memory_mb', '?')} MB")
    print(f"  GPU    : {', '.join(info.get('gpus', ['?']))}")
    print(f"  Accelerator: {args.accelerator}")
    print(f"  Podman : {info.get('podman', '?')}")
    print(f"  CRIU   : {info.get('criu', '?')}")
    print(f"  Plugin : {args.criu_libdir or 'default CRIU plugin path'}")
    print(f"  Runc conf: {args.runc_conf}")
    print(f"  Archive: podman --compress={args.archive_compression}")

    cfgs = []
    for mode in args.modes:
        if mode == "lz4-region":
            for rs in args.region_sizes:
                cfgs.append({"mode": "lz4-region", "region_size": rs})
        else:
            cfgs.append({"mode": mode, "region_size": 0})
    labels = [cfg_label(cfg) for cfg in cfgs]

    print(f"  Config : {args.iterations}+1 iterations, "
          f"modes={','.join(labels)}")
    print("  Restore: decompress-threads="
          f"{decompress_threads_label(args.decompress_threads)}")
    print(f"  Server : {args.base_url}, model={args.model}, "
          f"{adapter.server_summary(args)}")
    print(f"  Request: max_tokens={args.max_tokens}, "
          f"temperature={args.temperature:g}, "
          f"warmup_requests={args.warmup_requests}")
    if args.prompt_file:
        print(f"  Prompt : {args.prompt_file}")
    if args.ulimit:
        print(f"  Ulimit : {','.join(args.ulimit)}")

    results = {label: [] for label in labels}
    total = args.iterations + 1
    trial = 0
    for i in range(total):
        warmup = (i == 0)
        configurations = list(zip(cfgs, labels))
        offset = i % len(configurations)
        configurations = configurations[offset:] + configurations[:offset]
        for config_index, (cfg, label) in enumerate(configurations):
            trial += 1
            workdir = tempfile.mkdtemp(prefix=adapter.temp_prefix)
            runtime.tempdirs.add(workdir)
            try:
                retain = (args.keep_running and not warmup and
                          i == total - 1 and
                          config_index == len(configurations) - 1)
                result = benchmark.run_trial(cfg, workdir, args, trial, retain)
                if not warmup:
                    results[label].append(result)
            except Exception as e:
                runtime.tempdirs.discard(workdir)
                print(f"\n  ERROR: {label}: {e}", file=sys.stderr)
                print(f"  Artifacts preserved in {workdir}", file=sys.stderr)
                print(container_diagnostics(
                    f"{args.container_name}-{os.getpid()}-{trial}"),
                      file=sys.stderr)
                raise
            else:
                shutil.rmtree(workdir)
                runtime.tempdirs.discard(workdir)
        print(f"  completed {'warmup' if warmup else f'{i}/{args.iterations}'}")

    benchmark.report(results, labels)

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"system": info,
                       "framework": adapter.key,
                       "config": json_config(args),
                       "results": results}, f, indent=2)
        print(f"\nResults written to {args.json}")

    # A successful benchmark must not report success until the host-wide
    # CRIU configuration is restored. atexit remains a fallback for errors
    # and signals, where cleanup diagnostics cannot change an existing status.
    benchmark.restore_runc_conf()
    print()
