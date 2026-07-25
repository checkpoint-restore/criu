PLUGIN_NAME := cuda_plugin
PLUGIN_SOBJS := cuda_plugin_v1.so cuda_plugin_v2.so

DEPS_CUDA := $(PLUGIN_SOBJS)

PLUGIN_INCLUDE  	:= -iquote../../include
PLUGIN_INCLUDE  	+= -iquote../../criu/include
PLUGIN_INCLUDE  	+= -iquote../../criu/arch/$(ARCH)/include/
PLUGIN_INCLUDE  	+= -iquote../../

COMPEL := ../../compel/compel-host

PLUGIN_CFLAGS := -g -Wall -Werror -shared -nostartfiles -fPIC

__nmk_dir ?= ../../scripts/nmk/scripts/
include $(__nmk_dir)msg.mk

all: $(DEPS_CUDA)

cuda.pb-c.c: cuda.proto
	protoc --proto_path=. --c_out=. cuda.proto

cuda_plugin_v1.so: cuda_plugin_v1.c
	$(call msg-gen, $@)
	$(Q) $(CC) $(PLUGIN_CFLAGS) $(DEFINES) $(shell $(COMPEL) includes) $^ -o $@ $(PLUGIN_INCLUDE) $(PLUGIN_LDFLAGS)

cuda_plugin_v2.so: cuda_plugin_v2.c cuda_device_map.c cuda.pb-c.c
	$(call msg-gen, $@)
	$(Q) $(CC) $(PLUGIN_CFLAGS) $(DEFINES) $(shell $(COMPEL) includes) $^ -o $@ $(PLUGIN_INCLUDE) $(PLUGIN_LDFLAGS) -ldl

clean:
	$(call msg-clean, $@)
	$(Q) $(RM) $(PLUGIN_SOBJS) cuda.pb-c.c cuda.pb-c.h
.PHONY: clean

mrproper: clean

install:
	$(Q) mkdir -p $(DESTDIR)$(PLUGINDIR)
	$(E) "  INSTALL " $(PLUGIN_NAME)
	$(Q) install -m 755 $(PLUGIN_SOBJS) $(DESTDIR)$(PLUGINDIR)
.PHONY: install

uninstall:
	$(E) " UNINSTALL" $(PLUGIN_NAME)
	$(Q) $(RM) $(addprefix $(DESTDIR)$(PLUGINDIR)/,$(PLUGIN_SOBJS))
.PHONY: uninstall
