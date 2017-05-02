CRIU_SO			:= libcriu.so
UAPI_HEADERS		:= lib/c/criu.h images/rpc.proto
PYTHON_BIN ?= python2

.PHONY: .FORCE

#
# File to keep track of files installed by setup.py
CRIT_SETUP_FILES	:= lib/.crit-setup.files

all-y	+= lib-c lib-py

#
# C language bindings.
lib/c/Makefile: ;
lib/c/%: .FORCE
	$(Q) $(MAKE) $(build)=lib/c $@

cflags-so		+= $(CFLAGS) -rdynamic -Wl,-soname,$(CRIU_SO).$(CRIU_SO_VERSION_MAJOR)
ldflags-so		+= -lprotobuf-c

lib/c/$(CRIU_SO): lib/c/built-in.o
	$(call msg-link, $@)
	$(Q) $(CC) -shared $(cflags-so) -o $@ $^ $(ldflags-so) $(LDFLAGS)
lib-c: lib/c/$(CRIU_SO)
.PHONY: lib-c

#
# Python bindings.
lib/py/Makefile: ;
lib/py/%: .FORCE
	$(call msg-gen, $@)
	$(Q) $(MAKE) $(build)=lib/py $@
lib-py:
	$(Q) $(MAKE) $(build)=lib/py all
.PHONY: lib-py

clean-lib:
	$(Q) $(MAKE) $(build)=lib/c clean
	$(Q) $(MAKE) $(build)=lib/py clean
.PHONY: clean-lib
clean: clean-lib
cleanup-y	+= lib/c/$(CRIU_SO) lib/c/criu.pc
mrproper: clean

install: lib-c lib-py crit/crit lib/c/criu.pc.in
	$(E) "  INSTALL " lib
	$(Q) mkdir -p $(DESTDIR)$(LIBDIR)
	$(Q) install -m 755 lib/c/$(CRIU_SO) $(DESTDIR)$(LIBDIR)/$(CRIU_SO).$(CRIU_SO_VERSION_MAJOR).$(CRIU_SO_VERSION_MINOR)
	$(Q) ln -fns $(CRIU_SO).$(CRIU_SO_VERSION_MAJOR).$(CRIU_SO_VERSION_MINOR) $(DESTDIR)$(LIBDIR)/$(CRIU_SO).$(CRIU_SO_VERSION_MAJOR)
	$(Q) ln -fns $(CRIU_SO).$(CRIU_SO_VERSION_MAJOR).$(CRIU_SO_VERSION_MINOR) $(DESTDIR)$(LIBDIR)/$(CRIU_SO)
	$(Q) mkdir -p $(DESTDIR)$(INCLUDEDIR)/criu/
	$(Q) install -m 644 $(UAPI_HEADERS) $(DESTDIR)$(INCLUDEDIR)/criu/
	$(E) "  INSTALL " pkgconfig/criu.pc
	$(Q) mkdir -p $(DESTDIR)$(LIBDIR)/pkgconfig
	$(Q) sed -e 's,@version@,$(CRIU_VERSION),' -e 's,@libdir@,$(LIBDIR),' -e 's,@includedir@,$(dir $(INCLUDEDIR)/criu/),' lib/c/criu.pc.in > lib/c/criu.pc
	$(Q) install -m 644 lib/c/criu.pc $(DESTDIR)$(LIBDIR)/pkgconfig
	$(E) "  INSTALL " crit
	$(Q) $(PYTHON_BIN) scripts/crit-setup.py install --prefix=$(DESTDIR)$(PREFIX) --record $(CRIT_SETUP_FILES)
.PHONY: install

uninstall:
	$(E) " UNINSTALL" $(CRIU_SO)
	$(Q) $(RM) $(addprefix $(DESTDIR)$(LIBDIR)/,$(CRIU_SO).$(CRIU_SO_VERSION_MAJOR))
	$(Q) $(RM) $(addprefix $(DESTDIR)$(LIBDIR)/,$(CRIU_SO))
	$(Q) $(RM) $(addprefix $(DESTDIR)$(LIBDIR)/,$(CRIU_SO).$(CRIU_SO_VERSION_MAJOR).$(CRIU_SO_VERSION_MINOR))
	$(Q) $(RM) $(addprefix $(DESTDIR)$(INCLUDEDIR)/criu/,$(notdir $(UAPI_HEADERS)))
	$(E) " UNINSTALL" pkgconfig/criu.pc
	$(Q) $(RM) $(addprefix $(DESTDIR)$(LIBDIR)/pkgconfig/,criu.pc)
	$(E) " UNINSTALL" crit
	$(Q) while read -r file; do $(RM) "$$file"; done < $(CRIT_SETUP_FILES)
.PHONY: uninstall
