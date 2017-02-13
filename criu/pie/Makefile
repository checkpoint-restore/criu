target		+= parasite restorer

parasite-obj-e	+= ./compel/plugins/std.built-in.o
restorer-obj-e	+= ./compel/plugins/std.built-in.o

parasite-obj-y	+= parasite.o
restorer-obj-y	+= restorer.o
restorer-obj-y	+= ./$(ARCH_DIR)/restorer.o

ifeq ($(ARCH),x86)
        ifeq ($(CONFIG_COMPAT),y)
                restorer-obj-y	+= ./$(ARCH_DIR)/call32.o
                restorer-obj-y	+= ./$(ARCH_DIR)/sigaction_compat_pie.o
        endif
endif

#
# We can't provide proper mount implementation
# in parasite code -- it requires run-time rellocation
# applications, which is not the target of the
# project.
#
CFLAGS		:= $(filter-out -pg $(CFLAGS-GCOV),$(CFLAGS))
CFLAGS		:= $(filter-out $(CFLAGS-ASAN),$(CFLAGS))
CFLAGS		+= -iquote $(SRC_DIR)/criu/arch/$(ARCH)/include
CFLAGS		+= -iquote $(SRC_DIR)/criu/include
CFLAGS		+= -iquote $(SRC_DIR)/include
CFLAGS		+= -iquote $(SRC_DIR)

ccflags-y	+= $(COMPEL_UAPI_INCLUDES)
ccflags-y	+= -DCR_NOGLIBC
ccflags-y	+= -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
ccflags-y	+= -Wp,-U_FORTIFY_SOURCE -Wp,-D_FORTIFY_SOURCE=0

ifneq ($(filter-out clean mrproper,$(MAKECMDGOALS)),)
        CFLAGS	+= $(shell $(COMPEL_BIN) cflags)
	compel_std	:= $(shell $(COMPEL_BIN) plugins)
endif

ifeq ($(SRCARCH),arm)
        ccflags-y	+= -marm
endif

asflags-y	+= -D__ASSEMBLY__

BLOBS		+= $(obj)/restorer-blob.h $(obj)/parasite-blob.h
LDS		:= $(SRC_DIR)/compel/arch/$(SRCARCH)/scripts/compel-pack.lds.S

.SECONDARY:

target-name = $(patsubst criu/pie/%-blob.h,%,$(1))

$(obj)/restorer.built-in.o: $(compel_std)
$(obj)/parasite.built-in.o: $(compel_std)
$(obj)/%.built-in.bin.o: $(obj)/%.built-in.o $(obj)/pie.lib.a $(LDS)
	$(call msg-gen, $@)
	$(Q) $(LD) $(shell $(COMPEL_BIN) ldflags) -o $@ $^

$(obj)/%-blob.h: $(obj)/%.built-in.bin.o $(SRC_DIR)/compel/compel-host-bin
	$(call msg-gen, $@)
	$(Q) $(COMPEL_BIN) hgen -f $< -o $@

all-y += $(BLOBS)
# blobs and pields are in cleanup, rather than in mrproper because
# we want them to be re-generated after `make clean && make`
cleanup-y += $(BLOBS)
cleanup-y += $(obj)/*.bin
cleanup-y += $(obj)/*.built-in.bin.o
cleanup-y += $(obj)/*.built-in.bin
