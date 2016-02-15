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
# $(eval $(call gen-built-in,<dir>))
define gen-built-in
$(1)/%:
	$$(Q) $$(MAKE) $$(build)=$(1) $$@
$(1):
	$$(Q) $$(MAKE) $$(build)=$(1) all
$(1)/built-in.o: $(1)
endef

#
# Footer.
$(__nmk_dir)scripts/macro.mk:
	@true
____nmk_defined__macro = y
endif
