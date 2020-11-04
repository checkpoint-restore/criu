#!/bin/bash
set -x -e

CI_PKGS="protobuf-c-compiler libprotobuf-c-dev libaio-dev libgnutls28-dev
		libgnutls30 libprotobuf-dev protobuf-compiler libcap-dev
		libnl-3-dev gdb bash libnet-dev util-linux asciidoctor
		libnl-route-3-dev time ccache flake8 libbsd-dev"


if [ -e /etc/lsb-release ]; then
	# This file does not exist on non Ubuntu
	# shellcheck disable=SC1091
	. /etc/lsb-release
	if [ "$DISTRIB_RELEASE" = "16.04" ]; then
		# There is one last test running on 16.04 because of the broken
		# overlayfs in 18.04. Once that is fixed we can remove the last
		# 16.04 based test and this if clause.
		CI_PKGS="$CI_PKGS python-future python-protobuf python-yaml
			python-junit.xml python-ipaddress"
	else
		CI_PKGS="$CI_PKGS python3-future python3-protobuf python3-yaml
			python3-junit.xml"
	fi
fi

X86_64_PKGS="gcc-multilib"

UNAME_M=$(uname -m)

if [ "$UNAME_M" != "x86_64" ]; then
	# For Travis only x86_64 seems to be baremetal. Other
	# architectures are running in unprivileged LXD containers.
	# That seems to block most of CRIU's interfaces.

	# But with the introduction of baremetal aarch64 systems in
	# Travis (arch: arm64-graviton2) we can override this using
	# an evironment variable
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

	CC=gcc
	# clang support
	if [ "$CLANG" = "1" ]; then
		CI_PKGS="$CI_PKGS clang"
		CC=clang
	fi

	[ -n "$GCOV" ] && {
		apt-add-repository -y "ppa:ubuntu-toolchain-r/test"
		scripts/ci/apt-install --no-install-suggests g++-7
		CC=gcc-7
	}

	# ccache support, only enable for non-GCOV case
	if [ "$CCACHE" = "1" ] && [ -z "$GCOV" ]; then
		# ccache is installed by default, need to set it up
		export CCACHE_DIR=$HOME/.ccache
		[ "$CC" = "clang" ] && export CCACHE_CPP2=yes
		# uncomment the following to get detailed ccache logs
		#export CCACHE_LOGFILE=$HOME/ccache.log
		CC="ccache $CC"
	fi

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
	# We must test CRIU features that dump content into an image file to ensure
	# streaming compatibility.
	STREAM_TEST_PATTERN='.*(ghost|fifo|unlink|memfd|shmem|socket_queue).*'
	# shellcheck disable=SC2086
	./test/zdtm.py run --stream -p 2 --keep-going -T "$STREAM_TEST_PATTERN" $ZDTM_OPTS
}

ci_prep

export GCOV
$CC --version
time make CC="$CC" -j4

./criu/criu -v4 cpuinfo dump || :
./criu/criu -v4 cpuinfo check || :

# Check that help output fits into 80 columns
WIDTH=$(./criu/criu --help | wc --max-line-length)
if [ "$WIDTH" -gt 80 ]; then
	echo "criu --help output does not obey 80 characters line width!"
	exit 1
fi

[ -n "$SKIP_CI_TEST" ] && exit 0

ulimit -c unlimited

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
	scripts/ci/apt-install "$IA32_PKGS"
	mkdir -p /usr/lib/x86_64-linux-gnu/
	mv "$REFUGE"/* /usr/lib/x86_64-linux-gnu/
fi

time make CC="$CC" -j4 -C test/zdtm

[ -f "$CCACHE_LOGFILE" ] && cat "$CCACHE_LOGFILE"

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
# The 3.19 kernel (from Ubuntu 14.04) has a bug. When /proc/PID/pagemap
# is read for a few VMAs in one read call, incorrect data is returned.
# See https://github.com/checkpoint-restore/criu/issues/207
# Kernel 4.4 (from Ubuntu 14.04.5 update) fixes this.
uname -r | grep -q ^3\.19 && export CRIU_PMC_OFF=1

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
fi
#make -C test/others/exec/ run
make -C test/others/make/ run CC="$CC"
if [ -n "$TRAVIS" ]; then
       # GitHub Actions does not provide a real TTY and CRIU will fail with:
       # Error (criu/tty.c:1014): tty: Don't have tty to inherit session from, aborting
       make -C test/others/shell-job/ run
fi
make -C test/others/rpc/ run

./test/zdtm.py run -t zdtm/static/env00 --sibling

./test/zdtm.py run -t zdtm/transition/maps007 --pre 2 --dedup
./test/zdtm.py run -t zdtm/transition/maps007 --pre 2 --noauto-dedup
./test/zdtm.py run -t zdtm/transition/maps007 --pre 2 --page-server
./test/zdtm.py run -t zdtm/transition/maps007 --pre 2 --page-server --dedup

./test/zdtm.py run -t zdtm/static/socket-tcp-local --norst

ip net add test
./test/zdtm.py run -t zdtm/static/env00 -f h --join-ns

# RPC testing
./test/zdtm.py run -t zdtm/static/env00 --rpc		# Basic
./test/zdtm.py run -t zdtm/static/env00 --rpc --pre 2 --page-server
./test/zdtm.py run -t zdtm/static/ptrace_sig -f h --rpc # Error handling (crfail test)

./test/zdtm.py run --empty-ns -T zdtm/static/socket-tcp*-local --iter 2

./test/zdtm.py run -t zdtm/static/env00 -k always
./test/crit-recode.py

# libcriu testing
make -C test/others/libcriu run

# external namespace testing
make -C test/others/ns_ext run
