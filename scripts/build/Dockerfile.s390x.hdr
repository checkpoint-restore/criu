FROM s390x/debian:latest

ENV QEMU_CPU z900
COPY scripts/build/qemu-user-static/usr/bin/qemu-s390x-static /usr/bin/qemu-s390x-static
# The security repository does not seem to exist anymore
RUN sed -i '/security/ d' /etc/apt/sources.list
