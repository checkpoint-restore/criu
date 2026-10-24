CUDA_PLUGIN_DIR := ..
MOCK := mock
PLUGINS := cuda_plugin.so

__nmk_dir ?= ../../../scripts/nmk/scripts/
include $(__nmk_dir)msg.mk

all: $(PLUGINS) mock

mock:
	$(Q)$(MAKE) -C $(MOCK)

zdtm:
	$(Q)$(MAKE) -C zdtm

cuda_plugin.so: $(CUDA_PLUGIN_DIR)/cuda_plugin.so
	$(Q) cp $< $@

test: all

run: test zdtm
	cd ../../../test && ./zdtm.py --set cuda run -a --mocked-cuda-checkpoint

clean:
	$(Q)$(RM) $(PLUGINS)
	$(Q)$(MAKE) -C $(MOCK) clean
	$(Q)$(MAKE) -C zdtm clean

.PHONY: all mock zdtm clean test run
