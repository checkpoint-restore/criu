SRC_DIR := ../../plugins
PLUGIN_TARGETS := inventory_test_enabled_plugin.so inventory_test_disabled_plugin.so amdgpu_plugin.so cuda_plugin.so

ARCH	:= x86

PLUGIN_INCLUDE	:= -iquote../../include
PLUGIN_INCLUDE	+= -iquote../../criu/include
PLUGIN_INCLUDE	+= -iquote../../criu/arch/$(ARCH)/include/
PLUGIN_INCLUDE	+= -iquote../../
PLUGIN_CFLAGS	:= -g -Wall -Werror -shared -nostartfiles -fPIC

# Silent make rules.
Q := @

all: $(PLUGIN_TARGETS)

amdgpu_plugin.so: $(SRC_DIR)/amdgpu/amdgpu_plugin.so
	$(Q) cp $< $@

cuda_plugin.so: $(SRC_DIR)/cuda/cuda_plugin.so
	$(Q) cp $< $@

inventory_test_enabled_plugin.so: inventory_test_enabled_plugin.c
	$(Q) $(CC) $(PLUGIN_CFLAGS) $< -o $@ $(PLUGIN_INCLUDE)

inventory_test_disabled_plugin.so: inventory_test_disabled_plugin.c
	$(Q) $(CC) $(PLUGIN_CFLAGS) $< -o $@ $(PLUGIN_INCLUDE)

clean:
	$(Q) $(RM) $(PLUGIN_TARGETS)

.PHONY: all clean
