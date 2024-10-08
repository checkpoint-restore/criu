CRIU_SO			:= libcriu.so
CRIU_A			:= libcriu.a
UAPI_HEADERS		:= lib/c/criu.h images/rpc.proto images/rpc.pb-c.h criu/include/version.h

all-y	+= lib-c lib-a lib-py

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
lib/c/$(CRIU_A): lib/c/built-in.o
	$(call msg-link, $@)
	$(Q) $(AR) rcs $@ $^
lib-c: lib/c/$(CRIU_SO)
lib-a: lib/c/$(CRIU_A)
.PHONY: lib-c lib-a

#
# Python bindings.
lib/pycriu/Makefile: ;
lib/pycriu/%: .FORCE
	$(call msg-gen, $@)
	$(Q) $(MAKE) $(build)=lib/pycriu $@
lib-py:
	$(Q) $(MAKE) $(build)=lib/pycriu all
.PHONY: lib-py

clean-lib:
	$(Q) $(MAKE) $(build)=lib/c clean
	$(Q) $(MAKE) $(build)=lib/pycriu clean
.PHONY: clean-lib
clean: clean-lib
cleanup-y	+= lib/c/$(CRIU_SO) lib/c/$(CRIU_A) lib/c/criu.pc
mrproper: clean

install: lib-c lib-a lib-py lib/c/criu.pc.in
	$(E) "  INSTALL " lib
	$(Q) mkdir -p $(DESTDIR)$(LIBDIR)
	$(Q) install -m 755 lib/c/$(CRIU_SO) $(DESTDIR)$(LIBDIR)/$(CRIU_SO).$(CRIU_SO_VERSION_MAJOR).$(CRIU_SO_VERSION_MINOR)
	$(Q) ln -fns $(CRIU_SO).$(CRIU_SO_VERSION_MAJOR).$(CRIU_SO_VERSION_MINOR) $(DESTDIR)$(LIBDIR)/$(CRIU_SO).$(CRIU_SO_VERSION_MAJOR)
	$(Q) ln -fns $(CRIU_SO).$(CRIU_SO_VERSION_MAJOR).$(CRIU_SO_VERSION_MINOR) $(DESTDIR)$(LIBDIR)/$(CRIU_SO)
	$(Q) install -m 755 lib/c/$(CRIU_A) $(DESTDIR)$(LIBDIR)/$(CRIU_A)
	$(Q) mkdir -p $(DESTDIR)$(INCLUDEDIR)/criu/
	$(Q) install -m 644 $(UAPI_HEADERS) $(DESTDIR)$(INCLUDEDIR)/criu/
	$(E) "  INSTALL " pkgconfig/criu.pc
	$(Q) mkdir -p $(DESTDIR)$(LIBDIR)/pkgconfig
	$(Q) sed -e 's,@version@,$(CRIU_VERSION),' -e 's,@libdir@,$(LIBDIR),' -e 's,@includedir@,$(dir $(INCLUDEDIR)/criu/),' lib/c/criu.pc.in > lib/c/criu.pc
	$(Q) install -m 644 lib/c/criu.pc $(DESTDIR)$(LIBDIR)/pkgconfig
ifeq ($(SKIP_PIP_INSTALL),0)
	$(E) "  INSTALL " pycriu
	$(Q) $(PYTHON) -m pip install $(PIPFLAGS) --prefix=$(DESTDIR)$(PREFIX) ./lib
else
	$(E) " SKIP INSTALL pycriu"
endif
.PHONY: install

uninstall:
	$(E) " UNINSTALL" $(CRIU_SO)
	$(Q) $(RM) $(addprefix $(DESTDIR)$(LIBDIR)/,$(CRIU_SO).$(CRIU_SO_VERSION_MAJOR))
	$(Q) $(RM) $(addprefix $(DESTDIR)$(LIBDIR)/,$(CRIU_SO))
	$(Q) $(RM) $(addprefix $(DESTDIR)$(LIBDIR)/,$(CRIU_A))
	$(Q) $(RM) $(addprefix $(DESTDIR)$(LIBDIR)/,$(CRIU_SO).$(CRIU_SO_VERSION_MAJOR).$(CRIU_SO_VERSION_MINOR))
	$(Q) $(RM) $(addprefix $(DESTDIR)$(INCLUDEDIR)/criu/,$(notdir $(UAPI_HEADERS)))
	$(E) " UNINSTALL" pkgconfig/criu.pc
	$(Q) $(RM) $(addprefix $(DESTDIR)$(LIBDIR)/pkgconfig/,criu.pc)
ifeq ($(SKIP_PIP_INSTALL),0)
	$(E) " UNINSTALL" pycriu
	$(Q) $(PYTHON) ./scripts/uninstall_module.py --prefix=$(DESTDIR)$(PREFIX) pycriu
else
	$(E) " SKIP UNINSTALL pycriu"
endif
.PHONY: uninstall
