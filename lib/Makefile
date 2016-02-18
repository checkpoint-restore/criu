include $(__nmk_dir)/include.mk
include $(__nmk_dir)/macro.mk

CRIU_SO			:= libcriu.so

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
PHONY += lib-c

#
# Python bindings.
lib-py:
	$(call msg-gen, $@)
	$(Q) $(MAKE) -C pycriu/images all
PHONY += lib-py

clean:
	$(call msg-clean, lib-c)
	$(Q) $(MAKE) $(build)=c $@
	$(Q) $(RM) c/$(CRIU_SO)
	$(call msg-clean, lib-py)
	$(Q) $(MAKE) -C pycriu/images $@

all: $(PHONY)
	@true
PHONY += all

.PHONY: $(PHONY) clean
