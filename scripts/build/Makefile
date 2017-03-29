QEMU_ARCHES := armv7hf aarch64 ppc64le # require qemu
ARCHES := $(QEMU_ARCHES) x86_64
TARGETS := $(ARCHES) alpine fedora-asan
TARGETS_CLANG := $(addsuffix $(TARGETS),-clang)

all: $(TARGETS) $(TARGETS_CLANG)
.PHONY: all

# A build for each architecture requires appropriate Dockerfile
define ARCH_DEP
$(1): Dockerfile.$(1)
endef
$(foreach arch,$(ARCHES),$(eval $(call ARCH_DEP,$(arch))))

Dockerfile.%: Dockerfile.%.hdr Dockerfile.tmpl
	cat $^ > $@

qemu-user-static:
	./extract-deb-pkg qemu-user-static

binfmt_misc:
	./binfmt_misc
.PHONY: binfmt_misc

$(QEMU_ARCHES): qemu-user-static binfmt_misc

$(TARGETS):
	mkdir -p $(HOME)/.ccache
	mv $(HOME)/.ccache ../../
	docker build  -t criu-$@ -f Dockerfile.$@ $(DB_CC) $(DB_ENV) ../..
	docker run criu-$@ tar c -C /tmp .ccache | tar x -C $(HOME)
.PHONY: $(TARGETS)

# Clang builds add some Docker build env
define CLANG_DEP
$(1)-clang: $(1)
endef
$(foreach t,$(TARGETS),$(eval $(call CLANG_DEP,$(t))))

%-clang:	DB_CC=--build-arg CC=clang-3.8
%-clang:	DB_ENV=--build-arg ENV1=CCACHE_CPP2
alpine-clang:	DB_CC=--build-arg CC=clang
aarch64-clang:	DB_CC=--build-arg CC=clang-3.6
.PHONY: $(TARGETS_CLANG)

clean:
	rm -rf qemu-user-static
	for ARCH in $(ARCHES); do \
		FILE=/proc/sys/fs/binfmt_misc/$$ARCH; \
		test -f $$FILE && echo -1 > $$FILE; \
		rm -f Dockerfile.$$ARCH; \
	done
.PHONY: clean
