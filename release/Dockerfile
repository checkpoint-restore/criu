ARG IMAGE=kindest/node
ARG VERSION=1.32
ARG MINOR=2

FROM ${IMAGE}:v${VERSION}.${MINOR} AS build
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y \
    gnupg \
    tzdata \
    net-tools \
    libgpgme-dev \
    libdevmapper-dev \
    ca-certificates \
    pkg-config \
    patchelf \
    git \
    libprotobuf-dev libprotobuf-c-dev protobuf-c-compiler protobuf-compiler python3-protobuf \
    build-essential libmnl-dev \
    libcap-dev libnftables-dev libnet1-dev python3-yaml libaio-dev libaio-dev libnl-3-dev libcap-dev

WORKDIR /tmp/work
COPY ./release/criu.sh .
COPY ./release/install.sh .
RUN ./criu.sh

FROM scratch
COPY --from=build /tmp/criu-bundle .
