FROM alpine
ARG CC=gcc
ARG ENV1=FOOBAR

RUN apk update && apk add \
	$CC \
	bash \
	build-base \
	ccache \
	coreutils \
	git \
	libaio-dev \
	libcap-dev \
	libnet-dev \
	libnl3-dev \
	pkgconfig \
	protobuf-c-dev \
	protobuf-dev \
	python \
	sudo

COPY . /criu
WORKDIR /criu
ENV CC="ccache $CC" CCACHE_DIR=/tmp/.ccache CCACHE_NOCOMPRESS=1 $ENV1=yes
RUN mv .ccache /tmp && make mrproper && ccache -sz && \
	date && make -j $(nproc) CC="$CC" && date && ccache -s

RUN apk add \
	py-yaml \
	py-pip	\
	py2-future \
	ip6tables \
	iptables \
	iproute2 \
	tar \
	bash \
	go \
	e2fsprogs \
	asciidoc xmlto

# The rpc test cases are running as user #1000, let's add the user
RUN adduser -u 1000 -D test

RUN pip install protobuf ipaddress junit_xml
RUN make -C test/zdtm
