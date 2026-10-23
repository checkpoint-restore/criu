CFLAGS	+= $(USERCFLAGS) $(ARCHCFLAGS) -fPIC

BIN := cuda-device-map-test cuda-backend-guard-test untraced-clone-target dump_finish_failure.so
SRC := untraced-clone-target.c
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

PRESERVE_GITIGNORE := y
include ../zdtm/Makefile.inc

MOCK_DIR := $(abspath ../../plugins/cuda/tests/mock)

all: mocks $(TARGETS)

mocks:
	$(MAKE) -C $(MOCK_DIR)
.PHONY: mocks
.PHONY: all

cuda-device-map-test: device-map.c $(CUDA_PLUGIN_DIR)/cuda_device_map.c $(CUDA_PLUGIN_DIR)/cuda.proto \
		$(CUDA_PLUGIN_DIR)/cuda_wait.c $(CUDA_PLUGIN_DIR)/cuda_wait.h
	$(Q)$(MAKE) --no-print-directory -C $(CUDA_PLUGIN_DIR) cuda.pb-c.c
	$(E) " LINK     " $@
	$(Q)$(CC) $(CFLAGS) $(CUDA_TEST_CPPFLAGS) \
		device-map.c $(CUDA_PLUGIN_DIR)/cuda_device_map.c $(CUDA_PLUGIN_DIR)/cuda.pb-c.c \
		$(CUDA_PLUGIN_DIR)/cuda_wait.c \
		-o $@ -Wl,--wrap,fork -Wl,--wrap,write -Wl,--wrap,close -ldl -lprotobuf-c

cuda-backend-guard-test: backend-guard.c $(CUDA_PLUGIN_DIR)/cuda_plugin_driver.c \
		$(CUDA_PLUGIN_DIR)/cuda_plugin_cli.c \
		$(CUDA_PLUGIN_DIR)/cuda_wait.c $(CUDA_PLUGIN_DIR)/cuda_wait.h ../../compel/libcompel.a
	$(E) " LINK     " $@
	$(Q)$(CC) $(CFLAGS) $(CUDA_TEST_CPPFLAGS) -I../../compel/include/uapi \
		backend-guard.c $(CUDA_PLUGIN_DIR)/cuda_plugin_driver.c $(CUDA_PLUGIN_DIR)/cuda_plugin_cli.c \
		$(CUDA_PLUGIN_DIR)/cuda_wait.c \
		../../compel/libcompel.a \
		-Wl,--wrap,ptrace -ldl -pthread -o $@

untraced-clone-target: untraced-clone-target.c
	$(E) " LINK     " $@
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

dump_finish_failure.so: dump-finish-failure.c ../../criu/include/criu-plugin.h
	$(E) " LINK     " $@
	$(Q)$(CC) $(CFLAGS) $(CUDA_TEST_CPPFLAGS) $(LDFLAGS) -shared -nostartfiles $< -o $@

test: all
	LD_LIBRARY_PATH="$(MOCK_DIR)$${LD_LIBRARY_PATH:+:$${LD_LIBRARY_PATH}}" ./cuda-device-map-test
	PATH="$(MOCK_DIR):$$PATH" LD_LIBRARY_PATH="$(MOCK_DIR)$${LD_LIBRARY_PATH:+:$${LD_LIBRARY_PATH}}" ./cuda-backend-guard-test
.PHONY: test

clean-more:
	$(RM) $(TARGETS)
	$(Q)rmdir unsupported 2>/dev/null || true
.PHONY: clean-more
clean: clean-more
