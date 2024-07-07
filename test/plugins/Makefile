SRC_DIR := ../../plugins
PLUGIN_TARGETS := amdgpu_plugin.so cuda_plugin.so

# Silent make rules.
Q := @

all: $(PLUGIN_TARGETS)

amdgpu_plugin.so: $(SRC_DIR)/amdgpu/amdgpu_plugin.so
	$(Q) cp $< $@

cuda_plugin.so: $(SRC_DIR)/cuda/cuda_plugin.so
	$(Q) cp $< $@

clean:
	$(Q) $(RM) $(PLUGIN_TARGETS)

.PHONY: all clean
