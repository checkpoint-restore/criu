include $(__nmk_dir)/include.mk
include $(__nmk_dir)/macro.mk

VERSION_SO_MAJOR	:= 1
VERSION_SO_MINOR	:= 0

CRIU_SO			:= libcriu.so

#
# C language bindings.
c/%:
	$(call msg-gen, $@)
	$(Q) $(MAKE) $(build)=c $@
c/built-in.o:
	$(call msg-gen, $@)
	$(Q) $(MAKE) $(build)=c all

ccflags-so		+= $(CFLAGS) -rdynamic -Wl,-soname,$(lib-so).so.$(VERSION_SO_MAJOR)
ldflags-so		+= -lprotobuf-c
c/$(CRIU_SO): c/built-in.o
	$(call msg-link, $@)
	$(Q) $(CC) -shared $(ccflags-so) -o $@ $^ $(ldflags-so) $(LDFLAGS)
lib-c: c/$(CRIU_SO)
PHONY += lib-c

#
# Python bindings.
lib-py:
	$(call msg-gen, $@)
	$(Q) $(MAKE) -C py/images all
PHONY += lib-py

clean:
	$(call msg-clean, lib-c)
	$(Q) $(MAKE) $(build)=c $@
	$(Q) $(RM) c/$(CRIU_SO)
	$(call msg-clean, lib-py)
	$(Q) $(MAKE) -C py/images $@

all: $(PHONY)
	@true
PHONY += all
