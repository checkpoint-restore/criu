ARCHES ?= armv7hf aarch64 ppc64le # x86_64
all: $(ARCHES)

Dockerfile.%: Dockerfile.%.hdr Dockerfile.tmpl
	cat $^ > $@

qemu-user-static:
	./extract-deb-pkg qemu-user-static

binfmt_misc:
	./binfmt_misc
.PHONY: binfmt_misc

alpine:
	docker build  -t criu-$@ -f Dockerfile.alpine ../..

%: Dockerfile.% qemu-user-static binfmt_misc
	docker build  -t criu-$@ -f $< ../..

clean:
	rm -rf qemu-user-static
	for ARCH in $(ARCHES); do \
		FILE=/proc/sys/fs/binfmt_misc/$$ARCH; \
		test -f $$FILE && echo -1 > $$FILE; \
		rm -f Dockerfile.$$ARCH; \
	done
