## Building CRIU from source code

First, you need to install compile-time dependencies. Check [Installation dependencies](https://criu.org/Installation#Dependencies) for more info.

To compile CRIU, run:
```
make
```
This should create the `./criu/criu` executable.

To change the default behaviour of CRIU, the following variables can be passed
to the make command:

 * **NETWORK_LOCK_DEFAULT**, can be set to one of the following
   values: `NETWORK_LOCK_IPTABLES`, `NETWORK_LOCK_NFTABLES`,
   `NETWORK_LOCK_SKIP`. CRIU defaults to `NETWORK_LOCK_IPTABLES`
   if nothing is specified. If another network locking backend is
   needed, `make` can be called like this:
   `make NETWORK_LOCK_DEFAULT=NETWORK_LOCK_NFTABLES`

 * **NO_LIBBSD=1** builds without libbsd and skips its compiler probe, even
   when libbsd development files are installed.

### Static builds

`make static` downloads checksum-verified dependencies, builds them as static
archives, and produces a fully static `criu/criu`: it has no shared-library
dependencies or dynamic loader. It requires a Linux host with the matching
architecture and the kernel features needed by the workload. Such a binary
cannot load `.so` plugins, so `--libdir` and `CRIU_LIBS_DIR` are rejected,
as are restore images that require a plugin.

The build requires a musl toolchain, such as the native compiler on Alpine
Linux, with curl, pkg-config, autoconf, automake, libtool, m4, flex, and
bison, plus the protobuf code generators CRIU always needs (`protoc`,
`protoc-gen-c`, and the protobuf development files that provide
`descriptor.proto`). glibc is rejected, because a statically linked glibc
still loads NSS modules from the host at run time. On other hosts, build in
the provided Alpine image with Docker or Podman:

```
docker build -f scripts/build/Dockerfile.static -o build/static .
```

This exports `build/static/criu`.

The static target cleans existing CRIU build products before rebuilding,
and omits optional GnuTLS, libbsd, and BPF features. LZ4 compression,
nftables, and SELinux support are included, and the resulting binary is
checked by `scripts/build/static/check-binary.sh`. `STATIC_DEP_DIR` selects
the dependency cache (default `build/static-deps/<target>`, where `<target>`
is the output of `$CC -dumpmachine`); a cache populated by a different
compiler is rejected. `PREFIX` and `V` are passed to the CRIU build;
`make -jN` limits parallel builds.

The dependency versions and checksums are pinned in
`scripts/build/static/versions.mk`.
`make -C scripts/build/static check-updates` lists newer upstream releases,
and `scripts/build/static/update.sh NAME VERSION` updates one of them.
Changing the selected version, URL, or checksum invalidates the dependency's
cached build. Cached tarballs are checked again before extraction.

## Installing CRIU from source code

Once CRIU is built one can easily setup the complete CRIU package
(which includes executable itself, CRIT tool, libraries, manual
and etc) simply typing
```
make install
```
this command accepts the following variables:

 * **DESTDIR**, to specify global root where all components will be placed under (empty by default);
 * **PREFIX**, to specify additional prefix for path of every component installed (`/usr/local` by default);
 * **BINDIR**, to specify where to put CRIT tool (`$(PREFIX)/bin` by default);
 * **SBINDIR**, to specify where to put CRIU executable (`$(PREFIX)/sbin` by default);
 * **MANDIR**, to specify directory for manual pages (`$(PREFIX)/share/man` by default);
 * **LIBDIR**, to specify directory where to put libraries (guess the correct path  by default).

Thus one can type
```
make DESTDIR=/some/new/place install
```
and get everything installed under `/some/new/place`.

## Uninstalling CRIU

To clean up previously installed CRIU instance one can type
```
make uninstall
```
and everything should be removed. Note though that if some variable (**DESTDIR**, **BINDIR**
and such) has been used during installation procedure, the same *must* be passed with
uninstall action.
