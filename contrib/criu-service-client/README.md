# CRIU service client

An example CRIU service client that uses `libcriu` to checkpoint and restore
processes. It demonstrates how to use the libcriu C API as an alternative to
invoking the `criu` command-line tool directly.

The option names mirror those of the `criu` CLI so that switching between the
two is straightforward.

## Building

By default, `make` builds `libcriu` from the source tree so there is
no need to install anything first:

```
make
```

If you already have `libcriu` installed on your system (via the
`criu-devel` RPM or `libcriu-dev` DEB package), you can skip the
source build:

```
make LOCAL=0
```

## Usage

```
criu-service-client <dump|pre-dump|restore> [OPTIONS]
```

### Dump

Checkpoint a running process into an image directory:

```
sudo criu-service-client dump -t <PID> -D /tmp/imgs -j -v4
```

### Pre-dump

Pre-dump captures only the modified memory pages while the process keeps
running. This reduces final dump downtime by transferring most memory ahead
of time. Use `--prev-images-dir` on subsequent pre-dumps or the final dump
to point to the previous image directory (relative to `-D`):

```
mkdir -p /tmp/imgs/1 /tmp/imgs/2 /tmp/imgs/3

sudo criu-service-client pre-dump -t <PID> -D /tmp/imgs/1 --track-mem -v4
sudo criu-service-client pre-dump -t <PID> -D /tmp/imgs/2 --prev-images-dir ../1 --track-mem -v4
sudo criu-service-client dump    -t <PID> -D /tmp/imgs/3 --prev-images-dir ../2 --track-mem -j -v4
```

### Restore

Restore a process from a previously created checkpoint:

```
sudo criu-service-client restore -D /tmp/imgs -j -v4
```

### Connecting to a CRIU service

By default the client launches `criu` internally via libcriu. To talk to an
already-running `criu service` daemon, start the service first and then pass
`--service-address`:

```
sudo make start-service
sudo criu-service-client dump -t <PID> -D /tmp/imgs --service-address ./criu-service.socket
```

The `start-service` target daemonizes `criu service` with a pidfile. Stop
it with `make stop-service`. The socket, log, and pidfile paths are
configurable:

```
sudo make start-service CRIU_SERVICE_SOCKET=/var/run/criu.socket CRIU_SERVICE_LOG=/var/log/criu.log
sudo make stop-service
```

## Testing

Run the test suite (requires root for dump/restore operations):

```
sudo make test
```

This runs three tests:

- **run.sh** - iterative pre-dump, dump, and restore using a loop workload
- **run-shell-job.py** - dump and restore of a process with a controlling
  terminal (`--shell-job`)
- **run-service.sh** - pre-dump, dump, and restore through a `criu service`
  daemon (`--service-address`)

To test against the system-installed CRIU instead of building from source:

```
sudo make LOCAL=0 test
```
