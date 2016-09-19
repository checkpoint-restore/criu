ifndef ____nmk_defined__macro

#
# Helper to include makefile only once.
#
define include-once
        ifndef $(join ____nmk_defined__,$(1:.mk=))
                include $(__nmk_dir)$(1)
        endif
endef

# Helper to build built-in target in directory.
# $(eval $(call gen-built-in,<dir>,<prerequsite>,<phony>))
define gen-built-in
$(1)/%: $(2)
	$$(Q) $$(MAKE) $$(build)=$(1) $$@
ifneq ($(3),)
$(3): $(2)
	$$(Q) $$(MAKE) $$(build)=$(1) all
.PHONY: $(3)
$(1)/built-in.o: $(3)
else
$(1): $(2)
	$$(Q) $$(MAKE) $$(build)=$(1) all
.PHONY: $(1)
$(1)/built-in.o: $(1)
endif
endef

#
# Footer.
____nmk_defined__macro = y
endif
