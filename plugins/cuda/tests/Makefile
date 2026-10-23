CUDA_PLUGIN_DIR := ..
MOCK := mock
PLUGINS := cuda_plugin.so dump_finish_failure.so
CFLAGS += -g -Wall -Werror -D_GNU_SOURCE
CUDA_CPPFLAGS := -iquote../../../include -iquote../../../criu/include
CUDA_CPPFLAGS += -iquote../../..

__nmk_dir ?= ../../../scripts/nmk/scripts/
include $(__nmk_dir)msg.mk

all: $(PLUGINS) mock

mock:
	$(Q)$(MAKE) -C $(MOCK)

zdtm:
	$(Q)$(MAKE) -C zdtm

cuda_plugin.so: $(CUDA_PLUGIN_DIR)/cuda_plugin.so
	$(Q) cp $< $@

dump_finish_failure.so: dump_finish_failure.c mock/mock.h ../../../criu/include/criu-plugin.h
	$(E) " LINK     " $@
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) -shared -nostartfiles -fPIC $< -o $@ $(CUDA_CPPFLAGS)

test: all

run: test zdtm
	cd ../../../test && ./zdtm.py --set cuda run -a --mocked-cuda-checkpoint

clean:
	$(Q)$(RM) $(PLUGINS)
	$(Q)$(MAKE) -C $(MOCK) clean
	$(Q)$(MAKE) -C zdtm clean

.PHONY: all mock zdtm clean test run
