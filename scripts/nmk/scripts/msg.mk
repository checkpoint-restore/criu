ifndef ____nmk_defined__msg

#
# Silent make rules.
ifeq ($(strip $(V)),)
        E := @echo
        Q := @
else
        E := @\#
        Q :=
endif

export E Q

#
# Message helpers.
define msg-gen
        $(E) "  GEN     " $(1)
endef

define msg-clean
        $(E) "  CLEAN   " $(1)
endef

define msg-cc
        $(E) "  CC      " $(1)
endef

define msg-dep
        $(E) "  DEP     " $(1)
endef

define msg-link
        $(E) "  LINK    " $(1)
endef

define msg-ar
        $(E) "  AR      " $(1)
endef

define msg-build
        $(E) "  BUILD   " $(1)
endef

define msg-host-cc
        $(E) "  HOSTCC  " $(1)
endef

define msg-host-dep
        $(E) "  HOSTDEP " $(1)
endef

define msg-host-link
        $(E) "  HOSTLINK" $(1)
endef

define newline


endef

# map function:
# $1 - func to call
# $2 - list over which map the $1 func
# result is divided with newlines
map = $(foreach x,$2,$(call $1,$x)$(newline))

#
# Footer.
____nmk_defined__msg = y
endif #____nmk_defined__msg
