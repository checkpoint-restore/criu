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
	docker build  -t criu-$@ -f Dockerfile.alpine $(DB_ARGS) ../..

%: Dockerfile.% qemu-user-static binfmt_misc
	docker build  -t criu-$@ -f $< $(DB_ARGS) ../..

%-clang: DB_ARGS=--build-arg CC=clang-3.8
alpine-clang: DB_ARGS=--build-arg CC=clang
alpine-clang: alpine
armv7hf-clang: armv7hf
aarch64-clang: DB_ARGS=--build-arg CC=clang-3.6
aarch64-clang: aarch64
ppc64le-clang: ppc64le
x86_64-clang: x86_64
.PHONY: alpine-clang armv7hf-clang aarch64-clang ppc64le-clang x86_64-clang

clean:
	rm -rf qemu-user-static
	for ARCH in $(ARCHES); do \
		FILE=/proc/sys/fs/binfmt_misc/$$ARCH; \
		test -f $$FILE && echo -1 > $$FILE; \
		rm -f Dockerfile.$$ARCH; \
	done
