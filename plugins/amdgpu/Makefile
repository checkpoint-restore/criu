PLUGIN_NAME		:= amdgpu_plugin
PLUGIN_SOBJ		:= amdgpu_plugin.so

PLUGIN_INC		:= ../../../criu/include
PLUGIN_INC_EXTRA	:= ../../criu/include
PLUGIN_INCLUDE		:= -iquote$(PLUGIN_INC) -iquote $(PLUGIN_INC_EXTRA)

include $(__nmk_dir)msg.mk

CC      		:= gcc
PLUGIN_CFLAGS  		:= -g -Wall -Werror -D _GNU_SOURCE -shared -nostartfiles -fPIC
PLUGIN_LDFLAGS		:= -lrt -lpthread

all: amdgpu_plugin.so amdgpu_plugin_test

criu-amdgpu.pb-c.c: criu-amdgpu.proto
		protoc-c --proto_path=. --c_out=. criu-amdgpu.proto

amdgpu_plugin.so: amdgpu_plugin.c amdgpu_plugin_topology.c criu-amdgpu.pb-c.c
	$(CC) $(PLUGIN_CFLAGS) $^ -o $@ $(PLUGIN_INCLUDE) $(PLUGIN_LDFLAGS)

amdgpu_plugin_clean:
	$(call msg-clean, $@)
	$(Q) $(RM) amdgpu_plugin.so criu-amdgpu.pb-c*
.PHONY: amdgpu_plugin_clean

test_topology_remap: amdgpu_plugin_topology.c tests/test_topology_remap.c
	$(CC) $^ -o $@ -DCOMPILE_TESTS $(PLUGIN_INCLUDE) -I .

amdgpu_plugin_test:  test_topology_remap

amdgpu_plugin_test_clean:
	$(Q) $(RM) test_topology_remap
.PHONY: amdgpu_plugin_test_clean

clean: amdgpu_plugin_clean amdgpu_plugin_test_clean

mrproper: clean

install:
	$(E) "  INSTALL " $(PLUGIN_NAME)
	$(Q) mkdir -p $(PLUGINDIR)
	$(Q) install -m 644 $(PLUGIN_SOBJ) $(PLUGINDIR)
.PHONY: install

uninstall:
	$(E) " UNINSTALL" $(PLUGIN_NAME)
	$(Q) $(RM) $(PLUGINDIR)/$(PLUGIN_SOBJ)
.PHONY: uninstall
