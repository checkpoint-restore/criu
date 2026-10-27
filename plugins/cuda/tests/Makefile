LIBDIR := ../../../test/zdtm/lib
CUDA_PLUGIN_DIR := ..
MOCK := mock
BIN := cuda-device-map-test fork-target
PLUGINS := cuda_plugin.so dump_finish_failure.so
SRC := fork-target.c
OBJ := $(SRC:%.c=%.o)
DEP := $(SRC:%.c=%.d)
PRESERVE_GITIGNORE := y
include ../../../test/zdtm/Makefile.inc

CUDA_ARCH := $(if $(filter aarch64,$(ARCH)),arm64,$(ARCH))
CUDA_CPPFLAGS := -iquote../../../include -iquote../../../criu/include
CUDA_CPPFLAGS += -iquote../../../criu/arch/$(CUDA_ARCH)/include -iquote../../..
CUDA_CPPFLAGS += -iquote$(CUDA_PLUGIN_DIR)

all: $(BIN) $(PLUGINS) mock

mock:
	$(Q)$(MAKE) -C $(MOCK)

zdtm:
	$(Q)$(MAKE) -C zdtm

cuda_plugin.so: $(CUDA_PLUGIN_DIR)/cuda_plugin.so
	$(Q) cp $< $@

dump_finish_failure.so: dump_finish_failure.c mock/mock.h ../../../criu/include/criu-plugin.h
	$(E) " LINK     " $@
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) -shared -nostartfiles -fPIC $< -o $@ $(CUDA_CPPFLAGS)

cuda-device-map-test: device-map.c $(CUDA_PLUGIN_DIR)/cuda_device_map.c $(CUDA_PLUGIN_DIR)/cuda_wait.c \
		$(CUDA_PLUGIN_DIR)/cuda_device_map.h $(CUDA_PLUGIN_DIR)/cuda_wait.h $(CUDA_PLUGIN_DIR)/cuda.proto
	$(Q)$(MAKE) -C $(CUDA_PLUGIN_DIR) cuda.pb-c.c
	$(E) " LINK     " $@
	$(Q)$(CC) $(CFLAGS) $(CUDA_CPPFLAGS) device-map.c $(CUDA_PLUGIN_DIR)/cuda_device_map.c \
		$(CUDA_PLUGIN_DIR)/cuda.pb-c.c $(CUDA_PLUGIN_DIR)/cuda_wait.c \
		-o $@ -Wl,--wrap,fork -Wl,--wrap,write -Wl,--wrap,close -ldl -lprotobuf-c

fork-target: fork-target.c
	$(E) " LINK     " $@
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

test: all
	LD_LIBRARY_PATH=$(abspath $(MOCK)) ./cuda-device-map-test

run: test zdtm
	python3 backend-errors.py
	cd ../../../test && ./zdtm.py --set cuda run -a --mocked-cuda-checkpoint

clean-more:
	$(Q)$(RM) $(BIN) $(PLUGINS)
	$(Q)$(MAKE) -C $(MOCK) clean
	$(Q)$(MAKE) -C zdtm clean

clean: clean-more

.PHONY: all mock zdtm clean-more test run
