ifndef ____nmk_defined__build

#
# General helpers for simplified Makefiles.
#
src		:= $(obj)
src-makefile	:= $(call objectify,$(makefile))
obj-y		:=
obj-e		:=
builtin-name	:=
builtin-target	:=
lib-y		:=
lib-e		:=
lib-name	:=
lib-target	:=
hostprogs-y	:=
libso-y		:=
ld_flags	:=
ldflags-so	:=
arflags-y	:=
target          :=
deps-y		:=
all-y		:=
cleanup-y	:=
mrproper-y	:=
target		:=
objdirs		:=

MAKECMDGOALS := $(call uniq,$(MAKECMDGOALS))

ifndef obj
        $(error obj is undefined)
endif

ifndef __nmk-makefile-deps
        # Add top-make - it isn't included into this build.mk
        __nmk-makefile-deps := Makefile
endif
__nmk-makefile-deps += $(src-makefile)
export __nmk-makefile-deps

#
# Filter out any -Wl,XXX option: some of build farms
# assumes that we're using $(CC) for building built-in
# targets (and they have all rights to). But we're
# using $(LD) directly instead so filter out -Wl
# flags to make maintainer's life easier.
LDFLAGS-MASK	:= -Wl,%
LDFLAGS		:= $(filter-out $(LDFLAGS-MASK),$(LDFLAGS))

#
# Accumulate common flags.
define nmk-ccflags
        $(filter-out $(CFLAGS_REMOVE_$(@F)), $(CFLAGS) $(ccflags-y) $(CFLAGS_$(@F)))
endef

define nmk-asflags
        $(CFLAGS) $(AFLAGS) $(asflags-y) $(AFLAGS_$(@F))
endef

define nmk-host-ccflags
        $(HOSTCFLAGS) $(host-ccflags-y) $(HOSTCFLAGS_$(@F))
endef

#
# General rules.
define gen-cc-rules
$(1).o: $(2).c $(__nmk-makefile-deps)
	$$(call msg-cc, $$@)
	$$(Q) $$(CC) -c $$(strip $$(nmk-ccflags)) $$< -o $$@
$(1).i: $(2).c $(__nmk-makefile-deps)
	$$(call msg-cc, $$@)
	$$(Q) $$(CC) -E $$(strip $$(nmk-ccflags)) $$< -o $$@
$(1).s: $(2).c $(__nmk-makefile-deps)
	$$(call msg-cc, $$@)
	$$(Q) $$(CC) -S -fverbose-asm $$(strip $$(nmk-ccflags)) $$< -o $$@
$(1).d: $(2).c $(__nmk-makefile-deps)
	$$(call msg-dep, $$@)
	$$(Q) $$(CC) -M -MT $$@ -MT $$(patsubst %.d,%.o,$$@) $$(strip $$(nmk-ccflags)) $$< -o $$@
$(1).o: $(2).S $(__nmk-makefile-deps)
	$$(call msg-cc, $$@)
	$$(Q) $$(CC) -c $$(strip $$(nmk-asflags)) $$< -o $$@
$(1).i: $(2).S $(__nmk-makefile-deps)
	$$(call msg-cc, $$@)
	$$(Q) $$(CC) -E $$(strip $$(nmk-asflags)) $$< -o $$@
$(1).d: $(2).S $(__nmk-makefile-deps)
	$$(call msg-dep, $$@)
	$$(Q) $$(CC) -M -MT $$@ -MT $$(patsubst %.d,%.o,$$@) $$(strip $$(nmk-asflags)) $$< -o $$@
endef

include $(src-makefile)

ifneq ($(strip $(target)),)
	target := $(sort $(call uniq,$(target)))
endif

#
# Prepare the unique entries.
obj-y           := $(sort $(call uniq,$(obj-y)))
lib-y           := $(filter-out $(obj-y),$(lib-y))

#
# Add subdir path
obj-y           := $(call objectify,$(obj-y))
lib-y           := $(call objectify,$(lib-y))

#
# Strip custom names.
lib-name	:= $(strip $(lib-name))
builtin-name	:= $(strip $(builtin-name))

#
# Link flags.
ldflags-y	:= $(strip $(LDFLAGS) $(ldflags-y))

#
# $(obj) related rules.
$(eval $(call gen-cc-rules,$(obj)/%,$(obj)/%))

#
# Prepare targets.
ifneq ($(lib-y),)
        ifneq ($(lib-name),)
                lib-target := $(obj)/$(lib-name)
        else
                lib-target := $(obj)/lib.a
        endif
        cleanup-y += $(call cleanify,$(lib-y))
        cleanup-y += $(lib-target)
        all-y += $(lib-target)
        objdirs += $(dir $(lib-y))
endif

ifneq ($(obj-y),)
        ifneq ($(builtin-name),)
                builtin-target := $(obj)/$(builtin-name)
        else
                builtin-target := $(obj)/built-in.o
        endif
        cleanup-y += $(call cleanify,$(obj-y))
        cleanup-y += $(builtin-target)
        all-y += $(builtin-target)
        objdirs += $(dir $(obj-y))
endif

#
# Helpers for targets.
define gen-ld-target-rule
$(1): $(3)
	$$(call msg-link, $$@)
	$$(Q) $$(LD) $(2) -o $$@ $(4)
endef

define gen-ar-target-rule
$(1): $(3)
	$$(call msg-ar, $$@)
	$$(Q) $$(AR) -rcs$(2) $$@ $(4)
endef

#
# Predefined (builtins) targets rules.
ifdef builtin-target
        $(eval $(call gen-ld-target-rule,                               \
                        $(builtin-target),                              \
                        $(ldflags-y),                                   \
                        $(obj-y) $(__nmk-makefile-deps),                \
                        $(obj-y) $(call objectify,$(obj-e))))
endif

ifdef lib-target
        $(eval $(call gen-ar-target-rule,                               \
                        $(lib-target),                                  \
                        $(ARFLAGS) $(arflags-y),                        \
                        $(lib-y) $(__nmk-makefile-deps),                \
                        $(lib-y) $(call objectify,$(lib-e))))
endif

#
# Custom targets rules.
define gen-custom-target-rule
        ifneq ($($(1)-obj-y),)
                $(eval $(call gen-ld-target-rule,                       \
                                $(obj)/$(1).built-in.o,                 \
                                $(ldflags-y) $(LDFLAGS_$(1)),           \
                                $(call objectify,$($(1)-obj-y))         \
                                $(__nmk-makefile-deps),                 \
                                $(call objectify,$($(1)-obj-y))         \
                                $(call objectify,$($(1)-obj-e))))
                all-y += $(obj)/$(1).built-in.o
                cleanup-y += $(call cleanify,$(call objectify,$($(1)-obj-y)))
                cleanup-y += $(obj)/$(1).built-in.o
                objdirs += $(dir $(call objectify,$($(1)-obj-y)))
        endif
        ifneq ($($(1)-lib-y),)
                $(eval $(call gen-ar-target-rule,                       \
                                $(obj)/$(1).lib.a,                      \
                                $(ARFLAGS) $($(1)-arflags-y),           \
                                $(call objectify,$($(1)-lib-y))         \
                                $(__nmk-makefile-deps),                 \
                                $(call objectify,$($(1)-lib-y)))        \
                                $(call objectify,$($(1)-lib-e)))
                all-y += $(obj)/$(1).lib.a
                cleanup-y += $(call cleanify,$(call objectify,$($(1)-lib-y)))
                cleanup-y += $(obj)/$(1).lib.a
                objdirs += $(dir $(call objectify,$($(1)-lib-y)))
        endif
endef

$(foreach t,$(target),$(eval $(call gen-custom-target-rule,$(t))))

#
# Prepare rules for dirs other than (obj)/.
objdirs := $(patsubst %/,%,$(filter-out $(obj)/,$(call uniq,$(objdirs))))
$(foreach t,$(objdirs),$(eval $(call gen-cc-rules,$(t)/%,$(t)/%)))

#
# Host programs.
define gen-host-cc-rules
$(addprefix $(obj)/,$(1)): $(obj)/%.o: $(obj)/%.c $(__nmk-makefile-deps)
	$$(call msg-host-cc, $$@)
	$$(Q) $$(HOSTCC) -c $$(strip $$(nmk-host-ccflags)) $$< -o $$@
$(patsubst %.o,%.i,$(addprefix $(obj)/,$(1))): $(obj)/%.i: $(obj)/%.c $(__nmk-makefile-deps)
	$$(call msg-host-cc, $$@)
	$$(Q) $$(HOSTCC) -E $$(strip $$(nmk-host-ccflags)) $$< -o $$@
$(patsubst %.o,%.s,$(addprefix $(obj)/,$(1))): $(obj)/%.s: $(obj)/%.c $(__nmk-makefile-deps)
	$$(call msg-host-cc, $$@)
	$$(Q) $$(HOSTCC) -S -fverbose-asm $$(strip $$(nmk-host-ccflags)) $$< -o $$@
$(patsubst %.o,%.d,$(addprefix $(obj)/,$(1))): $(obj)/%.d: $(obj)/%.c $(__nmk-makefile-deps)
	$$(call msg-host-dep, $$@)
	$$(Q) $$(HOSTCC) -M -MT $$@ -MT $$(patsubst %.d,%.o,$$@) $$(strip $$(nmk-host-ccflags)) $$< -o $$@
endef

define gen-host-rules
        $(eval $(call gen-host-cc-rules,$($(1)-objs)))
        all-y += $(addprefix $(obj)/,$($(1)-objs))
        cleanup-y += $(call cleanify,$(addprefix $(obj)/,$($(1)-objs)))
$(obj)/$(1): $(addprefix $(obj)/,$($(1)-objs)) $(__nmk-makefile-deps)
	$$(call msg-host-link, $$@)
	$$(Q) $$(HOSTCC) $$(HOSTCFLAGS) $(addprefix $(obj)/,$($(1)-objs)) $$(HOSTLDFLAGS) $$(HOSTLDFLAGS_$$(@F)) -o $$@
all-y += $(obj)/$(1)
cleanup-y += $(obj)/$(1)
endef
$(foreach t,$(hostprogs-y),$(eval $(call gen-host-rules,$(t))))

#
# Dynamic library linking.
define gen-so-link-rules
$(call objectify,$(1)).so:  $(call objectify,$($(1)-objs)) $(__nmk-makefile-deps)
	$$(call msg-link, $$@)
	$$(Q) $$(CC) -shared $$(ldflags-so) $$(LDFLAGS) $$(LDFLAGS_$$(@F)) -o $$@ $(call objectify,$($(1)-objs))
all-y += $(call objectify,$(1)).so
cleanup-y += $(call objectify,$(1)).so
endef
$(foreach t,$(libso-y),$(eval $(call gen-so-link-rules,$(t))))

#
# Figure out if the target we're building needs deps to include.
define collect-builtin-deps
        ifeq ($(1),$(2))
                deps-y += $(obj-y:.o=.d)
        endif
endef
define collect-lib-deps
        ifeq ($(1),$(2))
                deps-y += $(lib-y:.o=.d)
        endif
endef
define collect-hostprogs-deps
        ifeq ($(1),$(2))
                deps-y += $(addprefix $(obj)/,$($(1)-objs:.o=.d))
        endif
endef
define collect-target-deps
        ifeq ($(1),$(2))
                deps-y += $(call objectify,$($(t)-lib-y:.o=.d))
                deps-y += $(call objectify,$($(t)-obj-y:.o=.d))
        endif
endef
define collect-deps
        ifneq ($(filter all,$(1)),)
                $(eval $(call collect-builtin-deps,$(builtin-target),$(builtin-target)))
                $(eval $(call collect-lib-deps,$(lib-target),$(lib-target)))
                $(foreach t,$(hostprogs-y),$(eval $(call collect-hostprogs-deps,$(t),$(t))))
                $(foreach t,$(target),$(eval $(call collect-target-deps,$(t),$(t))))
        else
                ifneq ($(filter-out %.d $(builtin-target) $(lib-target) $(hostprogs-y) $(target),$(1)),)
                        ifneq ($(filter %.o %.i %.s,$(1)),)
                                deps-y += $(addsuffix .d,$(basename $(1)))
                        endif
                else
                        $(eval $(call collect-builtin-deps,$(builtin-target),$(1)))
                        $(eval $(call collect-lib-deps,$(lib-target),$(1)))
                        $(foreach t,$(hostprogs-y),$(eval $(call collect-hostprogs-deps,$(t),$(1))))
                        $(foreach t,$(target),$(eval $(call collect-target-deps,$(t),$(1))))
                endif
        endif
endef

ifneq ($(MAKECMDGOALS),)
        ifneq ($(filter-out clean mrproper,$(MAKECMDGOALS)),)
                $(foreach goal,$(MAKECMDGOALS),$(eval $(call collect-deps,$(goal))))
                deps-y := $(call uniq,$(deps-y))
                ifneq ($(deps-y),)
                        $(eval -include $(deps-y))
                endif
        endif
endif

#
# Main phony rule.
all: $(all-y) ;
.PHONY: all

#
# Clean most files, but leave enough to navigate with tags (generated files)
clean:
	$(call msg-clean, $(obj))
	$(Q) $(RM) $(cleanup-y)
.PHONY: clean

#
# Delete all generated files
mrproper: clean
	$(Q) $(RM) $(mrproper-y)
.PHONY: mrproper

#
# Footer.
____nmk_defined__build = y
endif
