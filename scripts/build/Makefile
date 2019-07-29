QEMU_ARCHES := armv7hf aarch64 ppc64le s390x fedora-rawhide-aarch64 # require qemu
ARCHES := $(QEMU_ARCHES) x86_64 fedora-asan fedora-rawhide centos
TARGETS := $(ARCHES) alpine
TARGETS_CLANG := $(addsuffix $(TARGETS),-clang)
CONTAINER_RUNTIME := docker

all: $(TARGETS) $(TARGETS_CLANG)
.PHONY: all

# A build for each architecture requires appropriate Dockerfile
define ARCH_DEP
$(1): Dockerfile.$(1)
endef
$(foreach arch,$(ARCHES),$(eval $(call ARCH_DEP,$(arch))))

Dockerfile.%: Dockerfile.%.hdr Dockerfile.%.tmpl
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
	$(CONTAINER_RUNTIME) build  -t criu-$@ -f Dockerfile.$@ $(DB_CC) $(DB_ENV) ../..
	$(CONTAINER_RUNTIME) run criu-$@ tar c -C /tmp .ccache | tar x -C $(HOME)
.PHONY: $(TARGETS)

# Clang builds add some Docker build env
define CLANG_DEP
$(1)-clang: $(1)
endef
$(foreach t,$(TARGETS),$(eval $(call CLANG_DEP,$(t))))

%-clang:	DB_CC=--build-arg CC=clang
%-clang:	DB_ENV=--build-arg ENV1=CCACHE_CPP2
s390x-clang:	DB_CC=--build-arg CC=clang-3.8
.PHONY: $(TARGETS_CLANG)

clean:
	rm -rf qemu-user-static
	for ARCH in $(ARCHES); do \
		FILE=/proc/sys/fs/binfmt_misc/$$ARCH; \
		test -f $$FILE && echo -1 > $$FILE; \
		rm -f Dockerfile.$$ARCH; \
	done
.PHONY: clean
