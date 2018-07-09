ARG CC=gcc
ARG ENV1=FOOBAR

RUN dnf install -y \
	ccache \
	findutils \
	gcc \
	git \
	iproute \
	iptables \
	libaio-devel \
	libasan \
	libcap-devel \
	libnet-devel \
	libnl3-devel \
	make \
	procps-ng \
	protobuf-c-devel \
	protobuf-devel \
	python2-protobuf \
	python2 \
	# Starting with Fedora 28 this is python2-ipaddress
	python-ipaddress \
	# Starting with Fedora 28 this is python2-pyyaml
	python-yaml \
	python3-pip \
	python2-future \
	python3-PyYAML \
	python3-future \
	python3-protobuf \
	python3-junit_xml \
	sudo \
	tar \
	which \
	e2fsprogs \
	asciidoc xmlto

# Replace coreutils-single with "traditional" coreutils
# to fix the following error on Fedora 28/rawhide while
# running under QEMU:
# > sh: /usr/bin/sort: /usr/bin/coreutils: bad interpreter: No such file or directory
RUN dnf install -y --allowerasing coreutils

RUN ln -sf python3 /usr/bin/python

COPY . /criu
WORKDIR /criu

ENV CCACHE_DIR=/tmp/.ccache CCACHE_NOCOMPRESS=1 $ENV1=yes
RUN mv .ccache /tmp && make mrproper && ccache -sz  && \
	date && make -j $(nproc) CC="$CC" && date && ccache -s

# The rpc test cases are running as user #1000, let's add the user
RUN adduser -u 1000 test

RUN make -C test/zdtm -j $(nproc)

