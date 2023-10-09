PYTHON_EXTERNALLY_MANAGED := $(shell $(PYTHON) -c 'import os, sysconfig; print(int(os.path.isfile(os.path.join(sysconfig.get_path("stdlib"), "EXTERNALLY-MANAGED"))))')
PIP_BREAK_SYSTEM_PACKAGES := 0

VERSION_FILE := $(if $(obj),$(addprefix $(obj)/,crit/version.py),crit/version.py)

all-y	+= ${VERSION_FILE}
cleanup-y	+= ${VERSION_FILE}

${VERSION_FILE}:
	$(Q) echo "__version__ = '${CRIU_VERSION}'" > $@

install: ${VERSION_FILE}
ifeq ($(PYTHON_EXTERNALLY_MANAGED),1)
ifeq ($(PIP_BREAK_SYSTEM_PACKAGES),0)
	$(E) "  SKIP INSTALL crit: Externally managed python environment (See PEP 668 for more information)"
	$(E) "  Consider using PIP_BREAK_SYSTEM_PACKAGES=1 make install"
else
	$(E) "  INSTALL " crit
	$(Q) $(PYTHON) -m pip install --upgrade --ignore-installed --prefix=$(DESTDIR)$(PREFIX) ./crit
endif
else
	$(E) "  INSTALL " crit
	$(Q) $(PYTHON) -m pip install --upgrade --ignore-installed --prefix=$(DESTDIR)$(PREFIX) ./crit
endif
.PHONY: install

uninstall:
ifeq ($(PYTHON_EXTERNALLY_MANAGED),1)
ifeq ($(PIP_BREAK_SYSTEM_PACKAGES),0)
	$(E) " SKIP UNINSTALL crit: Externally managed python environment (See PEP 668 for more information)"
	$(E) " Consider using PIP_BREAK_SYSTEM_PACKAGES=1 make uninstall"
else
	$(E) " UNINSTALL" crit
	$(Q) $(PYTHON) ./scripts/uninstall_module.py --prefix=$(DESTDIR)$(PREFIX) crit
endif
else
	$(E) " UNINSTALL" crit
	$(Q) $(PYTHON) ./scripts/uninstall_module.py --prefix=$(DESTDIR)$(PREFIX) crit
endif
.PHONY: uninstall
