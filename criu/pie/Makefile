target		:= parasite restorer

CFLAGS		:= $(filter-out -pg $(CFLAGS-GCOV) $(CFLAGS-ASAN),$(CFLAGS))
ccflags-y	+= $(COMPEL_UAPI_INCLUDES)
ccflags-y	+= -DCR_NOGLIBC
ccflags-y	+= -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
ccflags-y	+= -Wp,-U_FORTIFY_SOURCE -Wp,-D_FORTIFY_SOURCE=0

ifneq ($(filter-out clean mrproper,$(MAKECMDGOALS)),)
	CFLAGS		+= $(shell $(COMPEL_BIN) cflags)
	LDFLAGS		+= $(shell $(COMPEL_BIN) ldflags)
	compel_plugins	:= $(shell $(COMPEL_BIN) plugins)
endif

ifeq ($(SRCARCH),arm)
	ccflags-y	+= -marm
endif

asflags-y	+= -D__ASSEMBLY__

LDS		:= compel/arch/$(SRCARCH)/scripts/compel-pack.lds.S

restorer-obj-y	+= ./$(ARCH_DIR)/restorer.o

ifeq ($(ARCH),x86)
        ifeq ($(CONFIG_COMPAT),y)
                restorer-obj-y	+= ./$(ARCH_DIR)/call32.o
                restorer-obj-y	+= ./$(ARCH_DIR)/restorer_unmap.o
                restorer-obj-y	+= ./$(ARCH_DIR)/sigaction_compat_pie.o
        endif
endif

define gen-pie-rules
$(1)-obj-y	+= $(1).o
$(1)-obj-e	+= pie.lib.a
$(1)-obj-e	+= $$(compel_plugins)

# Dependency on compel linker script, to relink if it has changed
$$(obj)/$(1).built-in.o: $$(LDS)

$$(obj)/$(1)-blob.h: $$(obj)/$(1).built-in.o
	$$(call msg-gen, $$@)
	$$(Q) $$(COMPEL_BIN) hgen -f $$< -o $$@

all-y		+= $$(obj)/$(1)-blob.h
cleanup-y	+= $$(obj)/$(1)-blob.h
endef

$(foreach t,$(target),$(eval $(call gen-pie-rules,$(t))))
