PLUGIN_NAME		:= amdgpu_plugin
PLUGIN_SOBJ		:= amdgpu_plugin.so

PLUGIN_INC		:= ../../../criu/include
PLUGIN_INC_EXTRA	:= ../../criu/include
PLUGIN_INCLUDE		:= -iquote$(PLUGIN_INC) -iquote$(PLUGIN_INC_EXTRA)
LIBDRM_INC             := -I/usr/include/libdrm
DEPS_OK 		:= amdgpu_plugin.so
DEPS_NOK 		:= ;

include $(__nmk_dir)msg.mk

CC      		:= gcc
PLUGIN_CFLAGS  		:= -g -Wall -Werror -D _GNU_SOURCE -shared -nostartfiles -fPIC

ifeq ($(CONFIG_AMDGPU),y)
        all: $(DEPS_OK)
else
        all: $(DEPS_NOK)
endif

criu-amdgpu.pb-c.c: criu-amdgpu.proto
		protoc-c --proto_path=. --c_out=. criu-amdgpu.proto

amdgpu_plugin.so: amdgpu_plugin.c amdgpu_plugin_topology.c criu-amdgpu.pb-c.c
	$(CC) $(PLUGIN_CFLAGS) $^ -o $@ $(PLUGIN_INCLUDE)

amdgpu_plugin_clean:
	$(call msg-clean, $@)
	$(Q) $(RM) amdgpu_plugin.so criu-amdgpu.pb-c*
.PHONY: amdgpu_plugin_clean
clean: amdgpu_plugin_clean

mrproper: clean

install:
	$(Q) mkdir -p $(PLUGINDIR)
ifeq ($(CONFIG_AMDGPU),y)
	$(E) "  INSTALL " $(PLUGIN_NAME)
	$(Q) install -m 644 $(PLUGIN_SOBJ) $(PLUGINDIR)
endif
.PHONY: install

uninstall:
ifeq ($(CONFIG_AMDGPU),y)
	$(E) " UNINSTALL" $(PLUGIN_NAME)
	$(Q) $(RM) $(PLUGINDIR)/$(PLUGIN_SOBJ)
endif
.PHONY: uninstall
