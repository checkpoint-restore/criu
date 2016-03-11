include $(__nmk_dir)/include.mk
include $(__nmk_dir)/macro.mk

CRIU_SO			:= libcriu.so
UAPI_HEADERS		:= c/criu.h ../images/rpc.proto

#
# C language bindings.
c/%: ../Makefile.versions
	$(call msg-gen, $@)
	$(Q) $(MAKE) $(build)=c $@

cflags-so		+= $(CFLAGS) -rdynamic -Wl,-soname,$(CRIU_SO).$(CRIU_SO_VERSION_MAJOR)
ldflags-so		+= -lprotobuf-c
c/$(CRIU_SO): c/built-in.o
	$(call msg-link, $@)
	$(Q) $(CC) -shared $(cflags-so) -o $@ $^ $(ldflags-so) $(LDFLAGS)
lib-c: c/$(CRIU_SO)
.PHONY: lib-c

#
# Python bindings.
lib-py:
	$(call msg-gen, $@)
	$(Q) $(MAKE) -C py all
.PHONY: lib-py

all: lib-c lib-py
	@true
.PHONY: all

clean:
	$(call msg-clean, lib-c)
	$(Q) $(MAKE) $(build)=c $@
	$(Q) $(RM) c/$(CRIU_SO)
	$(Q) $(RM) c/criu.pc
	$(call msg-clean, lib-py)
	$(Q) $(MAKE) -C py $@
	$(Q) $(RM) -r build usr
.PHONY: clean

install: lib-c lib-py ../crit/crit c/criu.pc.in
	$(E) "  INSTALL " $(CRIU_SO)
	$(Q) mkdir -p $(DESTDIR)$(LIBDIR)
	$(Q) install -m 755 c/$(CRIU_SO) $(DESTDIR)$(LIBDIR)/$(CRIU_SO).$(CRIU_SO_VERSION_MAJOR).$(CRIU_SO_VERSION_MINOR)
	$(Q) ln -fns $(CRIU_SO).$(CRIU_SO_VERSION_MAJOR).$(CRIU_SO_VERSION_MINOR) $(DESTDIR)$(LIBDIR)/$(CRIU_SO).$(CRIU_SO_VERSION_MAJOR)
	$(Q) ln -fns $(CRIU_SO).$(CRIU_SO_VERSION_MAJOR).$(CRIU_SO_VERSION_MINOR) $(DESTDIR)$(LIBDIR)/$(CRIU_SO)
	$(Q) mkdir -p $(DESTDIR)$(INCLUDEDIR)
	$(Q) install -m 644 $(UAPI_HEADERS) $(DESTDIR)$(INCLUDEDIR)
	$(E) "  INSTALL " pkgconfig/criu.pc
	$(Q) mkdir -p $(DESTDIR)$(LIBDIR)/pkgconfig
	$(Q) sed -e 's,@version@,$(CRIU_VERSION),' -e 's,@libdir@,$(LIBDIR),' -e 's,@includedir@,$(dir $(INCLUDEDIR)),' c/criu.pc.in > c/criu.pc
	$(Q) install -m 644 c/criu.pc $(DESTDIR)$(LIBDIR)/pkgconfig
	$(E) "  INSTALL " crit
	$(Q) python ../scripts/crit-setup.py install --root=$(DESTDIR) --prefix=$(PREFIX)
.PHONY: install
