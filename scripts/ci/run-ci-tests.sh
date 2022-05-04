#!/bin/bash
set -x -e

CI_PKGS="protobuf-c-compiler libprotobuf-c-dev libaio-dev libgnutls28-dev
		libgnutls30 libprotobuf-dev protobuf-compiler libcap-dev
		libnl-3-dev gdb bash libnet-dev util-linux asciidoctor
		libnl-route-3-dev time flake8 libbsd-dev python3-yaml
		libperl-dev pkg-config python3-future python3-protobuf
		python3-junit.xml"

X86_64_PKGS="gcc-multilib"

UNAME_M=$(uname -m)

if [ "$UNAME_M" != "x86_64" ]; then
	# For Travis only x86_64 seems to be baremetal. Other
	# architectures are running in unprivileged LXD containers.
	# That seems to block most of CRIU's interfaces.

	# But with the introduction of baremetal aarch64 systems in
	# Travis (arch: arm64-graviton2) we can override this using
	# an environment variable
	[ -n "$RUN_TESTS" ] || SKIP_CI_TEST=1
fi

ci_prep () {
	[ -n "$SKIP_CI_PREP" ] && return

	cd ../../

	# At least one of the test cases run by this script (others/rpc)
	# expects a user with the ID 1000. sudo from 20.04 (focal) does
	# not run anymore with 'sudo -u \#1000' if the UID does not exist.
	adduser -u 1000 --disabled-password --gecos "criutest" criutest || :

	# This can fail on aarch64 travis
	service apport stop || :

	if [ "$CLANG" = "1" ]; then
		# clang support
		CC=clang
		# If this is running in an environment without gcc installed
		# compel-host-bin will fail as it is using HOSTCC. Also
		# set HOSTCC to clang to build compel-host-bin with it.
		export HOSTCC=clang
	else
		CC=gcc
	fi
	CI_PKGS="$CI_PKGS $CC"

	# Do not install x86_64 specific packages on other architectures
	if [ "$UNAME_M" = "x86_64" ]; then
		CI_PKGS="$CI_PKGS $X86_64_PKGS"
	fi

	scripts/ci/apt-install "$CI_PKGS"
	chmod a+x "$HOME"

	# zdtm uses an unversioned python binary to run the tests.
	# let's point python to python3
	ln -sf /usr/bin/python3 /usr/bin/python
}

test_stream() {
	# Testing CRIU streaming to criu-image-streamer

	# FIXME: Currently, hugetlb mappings is not premapped, so in the restore content
	# phase, we skip page read these pages, enqueue the iovec for later reading in
	# restorer and eventually close the page read. However, image-streamer expects the
	# whole image to be read and the image is not reopened, sent twice. These MAP_HUGETLB
	# test cases will result in EPIPE error at the moment.
	STREAM_TEST_EXCLUDE="-x maps09 -x maps10"
	# shellcheck disable=SC2086
	./test/zdtm.py run --stream -p 2 --keep-going -a $STREAM_TEST_EXCLUDE $ZDTM_OPTS
}

print_header() {
	echo "############### $1 ###############"
}

print_env() {
	set +x
	# As this script can run on multiple different CI systems
	# the following lines should give some context to the
	# evnvironment of this CI run.
	print_header "Environment variables"
	printenv
	print_header "uname -a"
	uname -a || :
	print_header "Mounted file systems"
	cat /proc/self/mountinfo || :
	print_header "Kernel command line"
	cat /proc/cmdline || :
	print_header "Kernel modules"
	lsmod || :
	print_header "Distribution information"
	[ -e /etc/lsb-release ] && cat /etc/lsb-release
	[ -e /etc/redhat-release ] && cat /etc/redhat-release
	[ -e /etc/alpine-release ] && cat /etc/alpine-release
	print_header "ulimit -a"
	ulimit -a
	print_header "Available memory"
	if [ -e /etc/alpine-release ]; then
		# Alpine's busybox based free does not understand -h
		free
	else
		free -h
	fi
	print_header "Available CPUs"
	lscpu || :
	set -x
}

# FIXME: workaround for the issue https://github.com/checkpoint-restore/criu/issues/1866
modprobe -v sit || :

print_env

ci_prep

if [ "${CD_TO_TOP}" = "1" ]; then
	cd ../../
fi

export GCOV CC
$CC --version
time make CC="$CC" -j4 V=1

./criu/criu -v4 cpuinfo dump || :
./criu/criu -v4 cpuinfo check || :

# Check that help output fits into 80 columns
WIDTH=$(./criu/criu --help | wc --max-line-length)
if [ "$WIDTH" -gt 80 ]; then
	echo "criu --help output does not obey 80 characters line width!"
	exit 1
fi

# Unit tests at this point do not require any kernel or hardware capabilities.
# Just try to run it everywhere for now.
time make unittest

[ -n "$SKIP_CI_TEST" ] && exit 0

ulimit -c unlimited

cgid=$$
cleanup_cgroup() {
	./test/zdtm_umount_cgroups $cgid
}
trap cleanup_cgroup EXIT
./test/zdtm_mount_cgroups $cgid

echo "|$(pwd)/test/abrt.sh %P %p %s %e" > /proc/sys/kernel/core_pattern

if [ "${COMPAT_TEST}x" = "yx" ] ; then
	# Dirty hack to keep both ia32 & x86_64 shared libs on a machine:
	# headers are probably not compatible, so apt-get doesn't allow
	# installing both versions, while we need one for CRIU and one
	# for 32-bit tests. A better way would involve launching docker..
	# But it would require making zdtm.py aware of docker and launching
	# tests inside the CT.
	INCOMPATIBLE_LIBS="libaio-dev libcap-dev libnl-3-dev libnl-route-3-dev"
	IA32_PKGS=""
	REFUGE=64-refuge

	mkdir "$REFUGE"
	for i in $INCOMPATIBLE_LIBS ; do
		for j in $(dpkg --listfiles "$i" | grep '\.so$') ; do
			cp "$j" "$REFUGE/"
		done
		IA32_PKGS="$IA32_PKGS $i:i386"
	done
	# shellcheck disable=SC2086
	apt-get remove $INCOMPATIBLE_LIBS
	dpkg --add-architecture i386
	scripts/ci/apt-install "$IA32_PKGS"
	mkdir -p /usr/lib/x86_64-linux-gnu/
	mv "$REFUGE"/* /usr/lib/x86_64-linux-gnu/
fi

time make CC="$CC" -j4 -C test/zdtm V=1

if [ "${COMPAT_TEST}x" = "yx" ] ; then
	# Cross-verify that zdtm tests are 32-bit
	file test/zdtm/static/env00 | grep 'ELF 32-bit' -q
fi

# umask has to be called before a first criu run, so that .gcda (coverage data)
# files are created with read-write permissions for all.
umask 0000
./criu/criu check
./criu/criu check --all || echo $?
if [ "$UNAME_M" == "x86_64" ]; then
	# This fails on aarch64 (aws-graviton2)
	./criu/criu cpuinfo dump
	./criu/criu cpuinfo check
fi

export SKIP_PREP=1

chmod 0777 test/
chmod 0777 test/zdtm/static
chmod 0777 test/zdtm/transition

# We run streaming tests separately to improve test completion times,
# hence the exit 0.
if [ "${STREAM_TEST}" = "1" ]; then
	./scripts/install-criu-image-streamer.sh
	test_stream
	exit 0
fi

# shellcheck disable=SC2086
./test/zdtm.py run -a -p 2 --keep-going $ZDTM_OPTS
if criu/criu check --feature move_mount_set_group; then
	# shellcheck disable=SC2086
	./test/zdtm.py run -a -p 2 --mntns-compat-mode --keep-going $ZDTM_OPTS
fi

# shellcheck disable=SC2086
./test/zdtm.py run -a -p 2 --keep-going --criu-config $ZDTM_OPTS

# Newer kernels are blocking access to userfaultfd:
# uffd: Set unprivileged_userfaultfd sysctl knob to 1 if kernel faults must be handled without obtaining CAP_SYS_PTRACE capability
if [ -e /proc/sys/vm/unprivileged_userfaultfd ]; then
	echo 1 > /proc/sys/vm/unprivileged_userfaultfd
fi

LAZY_EXCLUDE="-x maps04 -x cmdlinenv00 -x maps007"

LAZY_TESTS='.*(maps0|uffd-events|lazy-thp|futex|fork).*'
LAZY_OPTS="-p 2 -T $LAZY_TESTS $LAZY_EXCLUDE $ZDTM_OPTS"

# shellcheck disable=SC2086
./test/zdtm.py run $LAZY_OPTS --lazy-pages
# shellcheck disable=SC2086
./test/zdtm.py run $LAZY_OPTS --remote-lazy-pages
# shellcheck disable=SC2086
./test/zdtm.py run $LAZY_OPTS --remote-lazy-pages --tls

bash -x ./test/jenkins/criu-fault.sh
if [ "$UNAME_M" == "x86_64" ]; then
	# This fails on aarch64 (aws-graviton2) with:
	# 33: ERR: thread-bomb.c:49: pthread_attr_setstacksize(): 22
	bash -x ./test/jenkins/criu-fcg.sh
fi
bash -x ./test/jenkins/criu-inhfd.sh

if [ -z "$SKIP_EXT_DEV_TEST" ]; then
	make -C test/others/mnt-ext-dev/ run
	if criu/criu check --feature move_mount_set_group; then
		EXTRA_OPTS=--mntns-compat-mode make -C test/others/mnt-ext-dev/ run
	fi
fi

make -C test/others/make/ run CC="$CC"
if [ -n "$TRAVIS" ] || [ -n "$CIRCLECI" ]; then
       # GitHub Actions (and Cirrus CI) does not provide a real TTY and CRIU will fail with:
       # Error (criu/tty.c:1014): tty: Don't have tty to inherit session from, aborting
       make -C test/others/shell-job/ run
fi
make -C test/others/rpc/ run

./test/zdtm.py run -t zdtm/static/env00 --sibling

./test/zdtm.py run -t zdtm/transition/maps007 --pre 2 --dedup
./test/zdtm.py run -t zdtm/transition/maps007 --pre 2 --noauto-dedup
./test/zdtm.py run -t zdtm/transition/maps007 --pre 2 --page-server
./test/zdtm.py run -t zdtm/transition/maps007 --pre 2 --page-server --dedup

./test/zdtm.py run -t zdtm/transition/pid_reuse --pre 2 # start time based pid reuse detection
./test/zdtm.py run -t zdtm/transition/pidfd_store_sk --rpc --pre 2 # pidfd based pid reuse detection

./test/zdtm.py run -t zdtm/static/socket-tcp-local --norst

ip net add test
./test/zdtm.py run -t zdtm/static/env00 -f h --join-ns

# RPC testing
./test/zdtm.py run -t zdtm/static/env00 --rpc		# Basic
./test/zdtm.py run -t zdtm/static/env00 --rpc --pre 2 --page-server
./test/zdtm.py run -t zdtm/static/ptrace_sig -f h --rpc # Error handling (crfail test)

./test/zdtm.py run --empty-ns -T zdtm/static/socket-tcp*-local --iter 2

./test/zdtm.py run -t zdtm/static/env00 -t zdtm/transition/fork -t zdtm/static/ghost_holes00 -t zdtm/static/socket-tcp -t zdtm/static/msgque -k always
./test/crit-recode.py

# more crit testing
make -C test/others/crit run

# coredump testing
make -C test/others/criu-coredump run

# libcriu testing
make -C test/others/libcriu run

# external namespace testing
make -C test/others/ns_ext run

# config file parser and parameter testing
make -C test/others/config-file run

# Skip all further tests when running with GCOV=1
# The one test which currently cannot handle GCOV testing is compel/test
# Probably because the GCOV Makefile infrastructure does not exist in compel
[ -n "$GCOV" ] && exit 0

# compel testing
make -C compel/test
