PLUGIN_NAME := cuda_plugin
PLUGIN_SOBJ := cuda_plugin.so
PLUGIN_SRCS := cuda_plugin.c cuda_plugin_driver.c cuda_plugin_cli.c cuda_device_map.c cuda.pb-c.c
PLUGIN_HEADERS := cuda_plugin.h cuda_checkpoint.h cuda_device_map.h

DEPS_CUDA := $(PLUGIN_SOBJ)

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
	$(Q) protoc --proto_path=. --c_out=. cuda.proto

cuda_plugin.so: $(PLUGIN_SRCS) $(PLUGIN_HEADERS)
	$(call msg-gen, $@)
	$(Q) $(CC) $(PLUGIN_CFLAGS) $(DEFINES) $(shell $(COMPEL) includes) $(PLUGIN_SRCS) -o $@ $(PLUGIN_INCLUDE) $(PLUGIN_LDFLAGS) -ldl

clean:
	$(call msg-clean, $@)
	$(Q) $(RM) $(PLUGIN_SOBJ) cuda.pb-c.c cuda.pb-c.h
.PHONY: clean

mrproper: clean

install:
	$(Q) mkdir -p $(DESTDIR)$(PLUGINDIR)
	$(E) "  INSTALL " $(PLUGIN_NAME)
	$(Q) install -m 755 $(PLUGIN_SOBJ) $(DESTDIR)$(PLUGINDIR)
.PHONY: install

uninstall:
	$(E) " UNINSTALL" $(PLUGIN_NAME)
	$(Q) $(RM) $(DESTDIR)$(PLUGINDIR)/$(PLUGIN_SOBJ)
.PHONY: uninstall
