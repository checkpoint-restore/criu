# Check libbsd detection without depending on the host's compiler or libraries.
.DEFAULT_GOAL := check

__nmk_dir := scripts/nmk/scripts/
include $(__nmk_dir)utils.mk

try-cc = $(strip $(if $(filter -lbsd,$(2)),\
	$(if $(NO_LIBBSD),$(error libbsd probe ran with NO_LIBBSD set),\
	$(eval LIBBSD_PROBED := y)$(LIBBSD_RESULT)),false))
pkg-config-check =
ARCH :=
CONFIG_HEADER := unused-config.h

include Makefile.config

ifeq ($(NO_LIBBSD),)
ifneq ($(LIBBSD_PROBED),y)
$(error libbsd was not probed)
endif
endif

expected := $(if $(NO_LIBBSD),,$(filter true,$(LIBBSD_RESULT)))
ifneq ($(filter -lbsd,$(LIBS_FEATURES)),$(if $(expected),-lbsd))
$(error unexpected libbsd link flags: $(LIBS_FEATURES))
endif
ifneq ($(filter -DCONFIG_HAS_LIBBSD,$(FEATURE_DEFINES)),$(if $(expected),-DCONFIG_HAS_LIBBSD))
$(error unexpected libbsd feature definition: $(FEATURE_DEFINES))
endif

check:
	@echo 'libbsd detection checks PASS'
.PHONY: check
