ifndef ____nmk_defined__utils

#
# Usage: option := $(call try-compile,language,source-to-build,cc-options,cc-defines)
try-compile = $(shell sh -c 'echo "$(2)" |					\
        $(CC) $(CFLAGS) $(LDFLAGS) $(4) -x $(1) - $(3) -o /dev/null > /dev/null 2>&1 &&		\
        echo true || echo false')

#
# Usage: option := $(call try-cc,source-to-build,cc-options,cc-defines)
try-cc = $(call try-compile,c,$(1),$(2),$(3))

#
# Usage: option := $(call try-cc,source-to-build,cc-options,cc-defines)
try-asm = $(call try-compile,assembler-with-cpp,$(1),$(2),$(3))

# pkg-config-check
# Usage: ifeq ($(call pkg-config-check, library),y)
pkg-config-check = $(shell sh -c '$(PKG_CONFIG) $(1) && echo y')

#
# Remove duplicates.
uniq = $(strip $(if $1,$(firstword $1) $(call uniq,$(filter-out $(firstword $1),$1))))

#
# Add $(obj)/ for paths that are not relative
objectify = $(foreach o,$(1),$(if $(filter /% ./% ../%,$(o)),$(o),$(obj)/$(o)))

# To cleanup entries.
cleanify = $(foreach o,$(sort $(call uniq,$(1))),$(o) $(o:.o=.d) $(o:.o=.i) $(o:.o=.s) $(o:.o=.gcda) $(o:.o=.gcno))

#
# Footer.
____nmk_defined__utils = y
endif
