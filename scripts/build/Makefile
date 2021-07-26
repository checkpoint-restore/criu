ARCHES := x86_64 fedora-asan fedora-rawhide centos7 armv7hf centos8
NON_CLANG := armv7-cross aarch64-cross ppc64-cross mips64el-cross
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
