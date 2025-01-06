VERSION_FILE := $(if $(obj),$(addprefix $(obj)/,crit/version.py),crit/version.py)

all-y	+= ${VERSION_FILE}
cleanup-y	+= ${VERSION_FILE}

${VERSION_FILE}:
	$(Q) echo "__version__ = '${CRIU_VERSION}'" > $@

install: ${VERSION_FILE}
ifeq ($(SKIP_PIP_INSTALL),0)
	$(E) "  INSTALL " crit
	$(Q) $(PYTHON) -m pip install $(PIPFLAGS) --prefix=$(DESTDIR)$(PREFIX) ./crit
else
	$(E) " SKIP INSTALL crit"
endif
.PHONY: install

uninstall:
ifeq ($(SKIP_PIP_INSTALL),0)
	$(E) " UNINSTALL" crit
	$(Q) $(PYTHON) ./scripts/uninstall_module.py --prefix=$(DESTDIR)$(PREFIX) crit
else
	$(E) " SKIP UNINSTALL crit"
endif
.PHONY: uninstall
