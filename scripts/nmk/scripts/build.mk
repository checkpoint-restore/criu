ifndef ____nmk_defined__build

#
# General helpers for simplified Makefiles.
#
src		:= $(obj)
obj-y		:=
lib-y		:=
target          :=
deps-y		:=
all-y		:=
builtin-name	:=
lib-name	:=
ld_flags	:=
cleanup-y	:=
mrproper-y	:=

MAKECMDGOALS := $(call uniq,$(MAKECMDGOALS))

ifndef obj
        $(error obj is undefined)
endif

#
# Accumulate common flags.
define nmk-ccflags
        $(CFLAGS) $(ccflags-y) $(CFLAGS_$(@F))
endef

define nmk-asflags
        $(CFLAGS) $(AFLAGS) $(asflags-y) $(AFLAGS_$(@F))
endef

#
# General rules.
define gen-cc-rules
$(1).o: $(2).c $(3)
	$$(call msg-cc, $$@)
	$$(Q) $$(CC) -c $$(strip $$(nmk-ccflags)) $(4) $$< -o $$@
$(1).i: $(2).c $(3)
	$$(call msg-cc, $$@)
	$$(Q) $$(CC) -E $$(strip $$(nmk-ccflags)) $(4) $$< -o $$@
$(1).s: $(2).c $(3)
	$$(call msg-cc, $$@)
	$$(Q) $$(CC) -S -fverbose-asm $$(strip $$(nmk-ccflags)) $(4) $$< -o $$@
$(1).d: $(2).c $(3)
	$$(call msg-dep, $$@)
	$$(Q) $$(CC) -M -MT $$@ -MT $$(patsubst %.d,%.o,$$@) $$(strip $$(nmk-ccflags)) $(4) $$< -o $$@
$(1).o: $(2).S $(3)
	$$(call msg-cc, $$@)
	$$(Q) $$(CC) -c $$(strip $$(nmk-asflags)) $(5) $$< -o $$@
$(1).i: $(2).S $(3)
	$$(call msg-cc, $$@)
	$$(Q) $$(CC) -E $$(strip $$(nmk-asflags)) $(5) $$< -o $$@
$(1).d: $(2).S $(3)
	$$(call msg-dep, $$@)
	$$(Q) $$(CC) -M -MT $$@ -MT $$(patsubst %.d,%.o,$$@) $$(strip $$(nmk-asflags)) $(5) $$< -o $$@
endef

#
# Expand early which matched all implicits.
$(eval $(call gen-cc-rules,%,%))

src-makefile	:= $(call objectify,$(makefile))
include $(src-makefile)

ifneq ($(strip $(target)),)
	target := $(sort $(call uniq,$(target)))
endif

#
# Prepare the unique entries.
obj-y           := $(sort $(call uniq,$(obj-y)))
lib-y           := $(filter-out $(obj-y),$(sort $(call uniq,$(lib-y))))

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
ld_flags	:= $(strip $(LDFLAGS) $(ldflags-y))

#
# $(obj) related rules.
$(eval $(call gen-cc-rules,$(obj)/%,$(obj)/%,$(src-makefile)))

#
# Prepare targets.
ifneq ($(lib-y),)
        lib-target :=
        ifneq ($(lib-name),)
                lib-target := $(obj)/$(lib-name)
        else
                lib-target := $(obj)/lib.a
        endif
        cleanup-y += $(call cleanify,$(lib-y))
        cleanup-y += $(lib-target)
        all-y += $(lib-target)
endif

ifneq ($(obj-y),)
        builtin-target :=
        ifneq ($(builtin-name),)
                builtin-target := $(obj)/$(builtin-name)
        else
                builtin-target := $(obj)/built-in.o
        endif
        cleanup-y += $(call cleanify,$(obj-y))
        cleanup-y += $(builtin-target)
        all-y += $(builtin-target)
endif

#
# Helpers for targets.
define gen-ld-target-rule
$(1): $(3)
	$$(call msg-link, $$@)
	$$(Q) $$(LD) $(2) -r -o $$@ $(4)
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
                        $(ld_flags),                                    \
                        $(obj-y) $(src-makefile),                       \
                        $(obj-y) $(call objectify,$(obj-e))))
endif

ifdef lib-target
        $(eval $(call gen-ar-target-rule,                               \
                        $(lib-target),                                  \
                        $(ARFLAGS) $(arflags-y),                        \
                        $(lib-y) $(src-makefile),                       \
                        $(lib-y) $(call objectify,$(lib-e))))
endif

#
# Custom targets rules.
define gen-custom-target-rule
        ifneq ($($(1)-obj-y),)
                $(eval $(call gen-ld-target-rule,                       \
                                $(obj)/$(1).built-in.o,                 \
                                $(ld_flags) $(LDFLAGS_$(1)),            \
                                $(call objectify,$($(1)-obj-y))         \
                                $(src-makefile),                        \
                                $(call objectify,$($(1)-obj-y))         \
                                $(call objectify,$($(1)-obj-e))))
                all-y += $(obj)/$(1).built-in.o
                cleanup-y += $(call cleanify,$(call objectify,$($(1)-obj-y)))
                cleanup-y += $(obj)/$(1).built-in.o
        endif
        ifneq ($($(1)-lib-y),)
                $(eval $(call gen-ar-target-rule,                       \
                                $(obj)/$(1).lib.a,                      \
                                $(ARFLAGS) $($(1)-arflags-y),           \
                                $(call objectify,$($(1)-lib-y))         \
                                $(src-makefile),                        \
                                $(call objectify,$($(1)-lib-y)))        \
                                $(call objectify,$($(1)-lib-e)))
                all-y += $(obj)/$(1).lib.a
                cleanup-y += $(call cleanify,$(call objectify,$($(1)-lib-y)))
                cleanup-y += $(obj)/$(1).lib.a
        endif
endef

$(foreach t,$(target),$(eval $(call gen-custom-target-rule,$(t))))

#
# Figure out if the target we're building needs deps to include.
define collect-deps
        ifneq ($(filter-out %.d,$(1)),)
                ifneq ($(filter %.o %.i %.s,$(1)),)
                        deps-y += $(addsuffix .d,$(basename $(1)))
                endif
        endif
        ifeq ($(builtin-target),$(1))
                deps-y += $(obj-y:.o=.d)
        endif
        ifeq ($(lib-target),$(1))
                deps-y += $(lib-y:.o=.d)
        endif
        ifneq ($(filter all $(all-y) $(target),$(1)),)
                deps-y += $(obj-y:.o=.d)
                deps-y += $(lib-y:.o=.d)
                deps-y += $(foreach t,$(target),$($(t)-lib-y:.o=.d) $($(t)-obj-y:.o=.d))
        endif
endef

ifneq ($(MAKECMDGOALS),)
        ifneq ($(MAKECMDGOALS),clean)
                $(foreach goal,$(MAKECMDGOALS),$(eval $(call collect-deps,$(goal))))
                deps-y := $(call uniq,$(deps-y))
                ifneq ($(deps-y),)
                        $(eval -include $(deps-y))
                endif
        endif
endif

#
# Main phony rule.
all: $(all-y)
	@true
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
$(__nmk_dir)scripts/build.mk:
	@true
____nmk_defined__build = y
endif
