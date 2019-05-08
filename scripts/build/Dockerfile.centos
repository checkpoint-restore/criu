FROM centos:7

ARG CC=gcc
ARG ENV1=FOOBAR

RUN yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
RUN yum install -y \
	ccache \
	findutils \
	gcc \
	git \
	gnutls-devel \
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
	protobuf-python \
	python \
	python-ipaddress \
	python2-future \
	python2-junit_xml \
	python-yaml \
	python-six \
	sudo \
	tar \
	which \
	e2fsprogs \
	python2-pip \
	rubygem-asciidoctor

COPY . /criu
WORKDIR /criu

ENV CCACHE_DIR=/tmp/.ccache CCACHE_NOCOMPRESS=1 $ENV1=yes
RUN mv .ccache /tmp && make mrproper && ccache -sz  && \
	date && make -j $(nproc) CC="$CC" && date && ccache -s

# The rpc test cases are running as user #1000, let's add the user
RUN adduser -u 1000 test

RUN make -C test/zdtm -j $(nproc)
