all: armv7hf aarch64 ppc64le

AARCH64_IMG ?= aarch64/ubuntu:trusty
ARMV7HF_IMG ?= armv7/armhf-ubuntu
PPC64LE_IMG ?= ppc64le/ubuntu

.FORCE:

Dockerfile.aarch64: Dockerfile.aarch64.hdr Dockerfile.tmpl
	cat Dockerfile.aarch64.hdr > Dockerfile.aarch64
	cat Dockerfile.tmpl >> Dockerfile.aarch64

Dockerfile.armv7hf: Dockerfile.armv7hf.hdr Dockerfile.tmpl
	cat Dockerfile.armv7hf.hdr > Dockerfile.armv7hf
	cat Dockerfile.tmpl >> Dockerfile.armv7hf

Dockerfile.ppc64le: Dockerfile.ppc64le.hdr Dockerfile.tmpl
	cat Dockerfile.ppc64le.hdr > Dockerfile.ppc64le
	cat Dockerfile.tmpl >> Dockerfile.ppc64le

Dockerfile.x86_64: Dockerfile.x86_64.hdr Dockerfile.tmpl
	cat Dockerfile.x86_64.hdr > Dockerfile.x86_64
	cat Dockerfile.tmpl >> Dockerfile.x86_64

qemu-user-static:
	./extract-deb-pkg qemu-user-static

binfmt_misc: .FORCE
	./binfmt_misc

armv7hf: qemu-user-static binfmt_misc Dockerfile.armv7hf
	docker build  -t criu-armv7hf -f Dockerfile.armv7hf ../..

aarch64: qemu-user-static binfmt_misc Dockerfile.aarch64
	docker build  -t criu-aarch64 -f Dockerfile.aarch64 ../..

ppc64le: qemu-user-static binfmt_misc Dockerfile.ppc64le
	docker build  -t criu-ppc64le -f Dockerfile.ppc64le ../..

x86_64: Dockerfile.x86_64
	docker build  -t criu-x86_64 -f Dockerfile.x86_64 ../..

clean:
	[ ! -f /proc/sys/fs/binfmt_misc/ppc64le ] || echo -1 > /proc/sys/fs/binfmt_misc/ppc64le
	[ ! -f /proc/sys/fs/binfmt_misc/armv7hf ] || echo -1 > /proc/sys/fs/binfmt_misc/armv7hf
	[ ! -f /proc/sys/fs/binfmt_misc/aarch64 ] || echo -1 > /proc/sys/fs/binfmt_misc/aarch64
	rm -rf qemu-user-static Dockerfile.aarch64 Dockerfile.armv7hf Dockerfile.ppc64le Dockerfile.x86_64
