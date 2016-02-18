all: armv7hf aarch64 ppc64le

.FORCE:

qemu-user-static:
	./extract-deb-pkg qemu-user-static

binfmt_misc: .FORCE
	./binfmt_misc

armv7hf: qemu-user-static binfmt_misc
	docker build  -t criu-armv7hf -f Dockerfile.armv7hf ../..

aarch64: qemu-user-static binfmt_misc
	docker build  -t criu-aarch64 -f Dockerfile.aarch64 ../..

ppc64le: qemu-user-static binfmt_misc
	docker build  -t criu-aarch64 -f Dockerfile.ppc64le ../..

clean:
	echo -1 > /proc/sys/fs/binfmt_misc/ppc64le
	echo -1 > /proc/sys/fs/binfmt_misc/armv7hf
	echo -1 > /proc/sys/fs/binfmt_misc/aarch64
	rm -rf qemu-user-static
