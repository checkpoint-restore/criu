# CRIU - Checkpoint and Restore in Userspace

CRIU is a utility for checkpoint/restore functionality on Linux that can freeze running applications and restore them from saved state. This is a system-level tool primarily written in C with Python testing infrastructure.

## Repository Structure

- `criu/` - Main CRIU executable source code (C)
- `lib/` - Libraries including libcriu, libcompel (parasite injection), libsoccr (TCP socket C/R)
- `compel/` - Parasite code injection toolkit
- `test/zdtm/` - ZDTM (Zero Down Time Migration) test suite
- `scripts/` - Build and CI scripts (Shell, Python)
- `images/` - Protocol buffer definitions for checkpoint images
- `Documentation/` - User and developer documentation
- `contrib/` - Additional tools and integrations

## Build System

**Primary build system**: GNU Make (Makefile-based)
- `make` - Build CRIU executable and libraries
- `make zdtm` - Build test suite
- `make install` - Install system-wide
- `make clean` / `make mrproper` - Clean build artifacts

**Key variables**:
- `DESTDIR`, `PREFIX` - Installation paths
- `NETWORK_LOCK_DEFAULT` - Network locking backend (IPTABLES/NFTABLES/SKIP)
- Architecture support: x86, arm, aarch64, ppc64, s390, mips, loongarch64, riscv64

## Dependencies

**Build dependencies** (install via `scripts/install-debian-pkgs.sh`):
- libbsd-dev, libcap-dev, libnet1-dev, libnl-3-dev, pkg-config
- protobuf-c-compiler, python3-protobuf, libprotobuf-c-dev
- libaio-dev, libgnutls28-dev, python3-pip

**Runtime dependencies**: 
- Linux kernel 3.11+ with specific CONFIG options
- Root privileges for most operations (checkpoint/restore requires CAP_SYS_ADMIN)

## Code Style and Quality

**Language standards**:
- C code: Linux kernel coding style, 80-character lines, 8-character tabs
- Python: PEP 8 compliant
- Shell: Follows common conventions

**Quality tools**:
- `make lint` - Run all linters (ruff for Python, shellcheck, codespell, CRIU-specific checks)
- `make indent` - Check C code formatting with clang-format
- Code coverage with `make gcov`

## Testing

**Test framework**: ZDTM (Zero Down Time Migration)
- `make test` - Run full ZDTM test suite (30+ minutes, requires root)
- `make unittest` - Quick unit tests
- Tests located in `test/zdtm/` with groups in `test/zdtm.desc`

**CI Testing**:
- X86_64 GCC/Clang testing
- Cross-compilation for multiple architectures
- Container testing (Docker, Podman)
- ASAN (AddressSanitizer) builds
- Java integration tests
- Stream testing for live migration

## Development Workflow

**Branches**:
- `criu-dev` - Main development branch (NOT master)
- Feature development in topic branches

**Build workflow**:
1. Install dependencies: `sudo scripts/install-debian-pkgs.sh`  
2. Build: `make` (5-15 minutes)
3. Test: `sudo make test` (30-60 minutes, requires root)
4. Lint: `make lint && make indent`

**Key commands for development**:
- `make tags` / `make cscope` - Generate code navigation
- `make dist` - Create source tarball
- `sudo make install DESTDIR=/path` - Test installation

## Architecture

**Core components**:
- **criu** - Main checkpoint/restore tool
- **libcriu** - C API for checkpoint/restore
- **libcompel** - Parasite code injection library  
- **libsoccr** - TCP socket checkpoint/restore
- **crit** - Tool for manipulating checkpoint images

**Key concepts**:
- Parasite code injection for process introspection
- Protocol buffers for checkpoint image format
- Support for containers (Docker, LXC, OpenVZ)
- Live migration capabilities via P.Haul

## Performance Considerations

- **Build time**: 5-15 minutes on modern hardware
- **Test time**: 30-90 minutes for full ZDTM suite
- **Memory usage**: Moderate during build, varies greatly during checkpoint/restore
- **Privileges**: Most operations require root or specific capabilities

## Integration Points

- **Container runtimes**: Docker, Podman, LXC/LXD, OpenVZ
- **Languages**: Go bindings available in go-criu repository
- **Network**: Integration with iptables/nftables for network locking
- **Storage**: Checkpoint images stored as protobuf files

## Security Notes

- Requires privileged access for checkpoint/restore
- Parasite injection uses ptrace and process memory manipulation
- Network locking may require firewall rule manipulation
- Checkpoint images contain full process state (potential secrets)

## Common Issues

- Kernel version compatibility (3.11+ required)
- Missing kernel CONFIG options for specific features
- Permission issues (most operations need root)
- Architecture-specific compilation issues
- Container runtime integration complexities

## Documentation

- Primary documentation at https://criu.org
- Installation guide: https://criu.org/Installation
- API documentation in `Documentation/`
- Example usage: https://criu.org/Simple_loop
- Troubleshooting: https://criu.org/When_C/R_fails