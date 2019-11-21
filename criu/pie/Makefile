# Recipes to compile PIEs: parastie and restorer
# Compel will deal with converting the result binaries
# to a C array to be used in CRIU.

target		:= parasite restorer

CFLAGS		:= $(filter-out -pg $(CFLAGS-GCOV) $(CFLAGS-ASAN),$(CFLAGS))
CFLAGS		+= $(CFLAGS_PIE)
ccflags-y	+= -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
ccflags-y	+= -Wp,-U_FORTIFY_SOURCE -Wp,-D_FORTIFY_SOURCE=0

ifneq ($(filter-out clean mrproper,$(MAKECMDGOALS)),)
        LDFLAGS		+= $(shell $(COMPEL_BIN) ldflags)
        compel_plugins	:= $(shell $(COMPEL_BIN) plugins)
endif

LDS		:= compel/arch/$(ARCH)/scripts/compel-pack.lds.S

restorer-obj-y	+= parasite-vdso.o ./$(ARCH_DIR)/vdso-pie.o
restorer-obj-y	+= ./$(ARCH_DIR)/restorer.o

ifeq ($(ARCH),x86)
        ifeq ($(CONFIG_COMPAT),y)
                restorer-obj-y	+= ./$(ARCH_DIR)/restorer_unmap.o
                restorer-obj-y	+= ./$(ARCH_DIR)/sigaction_compat_pie.o
        endif
endif

ifeq ($(ARCH),aarch64)
        restorer-obj-y	+= ./$(ARCH_DIR)/intraprocedure.o
endif

ifeq ($(ARCH),ppc64)
        restorer-obj-y	+= ./$(ARCH_DIR)/vdso-trampoline.o
endif

define gen-pie-rules
$(1)-obj-y	+= $(1).o
$(1)-obj-e	+= pie.lib.a
$(1)-obj-e	+= $$(compel_plugins)

# Dependency on compel linker script, to relink if it has changed
$$(obj)/$(1).built-in.o: $$(LDS) $$(compel_plugins)

$$(obj)/$(1)-blob.h: $$(obj)/$(1).built-in.o
	$$(call msg-gen, $$@)
	$$(Q) $$(COMPEL_BIN) hgen -f $$< -o $$@

all-y		+= $$(obj)/$(1)-blob.h
cleanup-y	+= $$(obj)/$(1)-blob.h
endef

$(foreach t,$(target),$(eval $(call gen-pie-rules,$(t))))
