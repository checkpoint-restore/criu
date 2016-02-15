all: armv7hf aarch64 ppc64le

qemu-user-static:
	./extract-deb-pkg qemu-user-static

binfmt_misc:
	echo ':armv7hf:M::\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00:\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/qemu-arm-static:' > /proc/sys/fs/binfmt_misc/register;
	echo ':aarch64:M::\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xb7:\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff:/usr/bin/qemu-aarch64-static:' > /proc/sys/fs/binfmt_misc/register
	echo ':ppc64le:M::\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x15\x00:\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\x00:/usr/bin/qemu-ppc64le-static:' > /proc/sys/fs/binfmt_misc/register

armv7hf: qemu-user-static
	docker build  -t criu-armv7hf -f Dockerfile.armv7hf ../..

aarch64: qemu-user-static
	docker build  -t criu-aarch64 -f Dockerfile.aarch64 ../..

ppc64le: qemu-user-static
	docker build  -t criu-aarch64 -f Dockerfile.ppc64le ../..

clean:
	echo -1 > /proc/sys/fs/binfmt_misc/ppc64le
	echo -1 > /proc/sys/fs/binfmt_misc/armv7hf
	echo -1 > /proc/sys/fs/binfmt_misc/aarch64
	rm -rf qemu-user-static
