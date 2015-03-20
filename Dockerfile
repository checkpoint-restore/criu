FROM ubuntu:utopic

RUN apt-get update && apt-get install -y \
		build-essential	\
		protobuf-c-compiler \
		libprotobuf-c0-dev \
		libprotobuf-dev	\
		bsdmainutils \
		protobuf-compiler \
		python-minimal \
		libaio-dev \
		iptables

COPY . /criu
WORKDIR /criu

RUN make clean && make -j $(nproc)
RUN make -j $(nproc) -C test ZDTM_ARGS="-C -x static/rtc -x mountpoint -x static/cgroup02 -x tcp6 -x tcpbuf6"
