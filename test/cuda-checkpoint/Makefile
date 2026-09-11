CFLAGS	+= $(USERCFLAGS) $(ARCHCFLAGS) -fPIC

BIN := cuda-checkpoint libcuda.so.1 unsupported/libcuda.so.1 cuda-device-map-test
SRC := cuda-checkpoint.c libcuda.c
DEP	:= $(SRC:%.c=%.d)
OBJ	:= $(SRC:%.c=%.o)
TARGETS	:= $(BIN)

CUDA_PLUGIN_DIR := ../../plugins/cuda
CUDA_TEST_ARCH := $(if $(strip $(ARCH)),$(ARCH),$(shell uname -m | sed \
	-e 's/i.86/x86/' -e 's/x86_64/x86/' -e 's/aarch64/arm64/'))
CUDA_TEST_CPPFLAGS := -iquote../../include
CUDA_TEST_CPPFLAGS += -iquote../../criu/include
CUDA_TEST_CPPFLAGS += -iquote../../criu/arch/$(CUDA_TEST_ARCH)/include/
CUDA_TEST_CPPFLAGS += -iquote../..
CUDA_TEST_CPPFLAGS += -iquote$(CUDA_PLUGIN_DIR)

include ../zdtm/Makefile.inc

all:	$(TARGETS)
	$(Q)printf '%s\n' cuda-checkpoint libcuda.so.1 cuda-device-map-test unsupported/ > .gitignore
.PHONY: all

cuda-checkpoint: cuda-checkpoint.o
	$(E) " LINK     " $@
	$(Q)$(CC) $(LDFLAGS) $^ -o $@

libcuda.so.1: libcuda.o
	$(E) " LINK     " $@
	$(Q)$(CC) $(LDFLAGS) -shared $^ -o $@

unsupported/libcuda.so.1: libcuda.c
	$(E) " LINK     " $@
	$(Q)mkdir -p $(@D)
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) -shared \
		-DMOCK_CUDA_DRIVER_VERSION=12000 $< -o $@

cuda-device-map-test: device-map.c $(CUDA_PLUGIN_DIR)/cuda_device_map.c $(CUDA_PLUGIN_DIR)/cuda.proto
	$(Q)$(MAKE) --no-print-directory -C $(CUDA_PLUGIN_DIR) cuda.pb-c.c
	$(E) " LINK     " $@
	$(Q)$(CC) $(CFLAGS) $(CUDA_TEST_CPPFLAGS) \
		device-map.c $(CUDA_PLUGIN_DIR)/cuda_device_map.c $(CUDA_PLUGIN_DIR)/cuda.pb-c.c \
		-o $@ -ldl -lprotobuf-c

test: all
	LD_LIBRARY_PATH="$(CURDIR)$${LD_LIBRARY_PATH:+:$${LD_LIBRARY_PATH}}" ./cuda-device-map-test
.PHONY: test

clean-more:
	$(RM) $(TARGETS)
	$(Q)rmdir unsupported 2>/dev/null || true
.PHONY: clean-more
clean: clean-more
