ARCHES := x86_64 fedora-asan fedora-rawhide armv7hf centos8
STABLE_CROSS_ARCHES := armv7-stable-cross aarch64-stable-cross ppc64-stable-cross mips64el-stable-cross riscv64-stable-cross
UNSTABLE_CROSS_ARCHES := armv7-unstable-cross aarch64-unstable-cross ppc64-unstable-cross mips64el-unstable-cross
NON_CLANG := $(UNSTABLE_CROSS_ARCHES) $(STABLE_CROSS_ARCHES)
CREATE_DOCKERFILES := $(ARCHES) $(NON_CLANG)
TARGETS := $(ARCHES) alpine archlinux
TARGETS_CLANG := $(addsuffix $(TARGETS),-clang)
CONTAINER_RUNTIME := docker
CONTAINER_TARGETS := $(TARGETS) $(NON_CLANG)

all: $(CONTAINER_TARGETS) $(TARGETS_CLANG)
.PHONY: all

# A build for each architecture requires appropriate Dockerfile
define FILE_DEP
$(1): Dockerfile.$(1)
endef
$(foreach file,$(CREATE_DOCKERFILES),$(eval $(call FILE_DEP,$(file))))

Dockerfile.%: Dockerfile.%.hdr Dockerfile.%.tmpl
	cat $^ > $@

$(CONTAINER_TARGETS):
	$(CONTAINER_RUNTIME) build $(BUILD_OPTIONS) -t criu-$@ -f Dockerfile.$@ $(DB_CC) ../..
.PHONY: $(CONTAINER_TARGETS)

# Clang builds add some Docker build env
define CLANG_DEP
$(1)-clang: $(1)
endef
$(foreach t,$(TARGETS),$(eval $(call CLANG_DEP,$(t))))

%-clang:	DB_CC=--build-arg CC=clang
s390x-clang:	DB_CC=--build-arg CC=clang-3.8
.PHONY: $(TARGETS_CLANG)
