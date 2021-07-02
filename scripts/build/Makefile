ARCHES := x86_64 fedora-asan fedora-rawhide centos7 armv7hf centos8
TARGETS := $(ARCHES) alpine
TARGETS_CLANG := $(addsuffix $(TARGETS),-clang)
CONTAINER_RUNTIME := docker

TARGETS += armv7-cross aarch64-cross ppc64-cross mips64el-cross


all: $(TARGETS) $(TARGETS_CLANG)
.PHONY: all

# A build for each architecture requires appropriate Dockerfile
define ARCH_DEP
$(1): Dockerfile.$(1)
endef
$(foreach arch,$(ARCHES),$(eval $(call ARCH_DEP,$(arch))))

Dockerfile.%: Dockerfile.%.hdr Dockerfile.%.tmpl
	cat $^ > $@

$(TARGETS):
	$(CONTAINER_RUNTIME) build  -t criu-$@ -f Dockerfile.$@ $(DB_CC) ../..
.PHONY: $(TARGETS)

# Clang builds add some Docker build env
define CLANG_DEP
$(1)-clang: $(1)
endef
$(foreach t,$(TARGETS),$(eval $(call CLANG_DEP,$(t))))

%-clang:	DB_CC=--build-arg CC=clang
s390x-clang:	DB_CC=--build-arg CC=clang-3.8
.PHONY: $(TARGETS_CLANG)
