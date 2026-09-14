CFLAGS	+= $(USERCFLAGS) $(ARCHCFLAGS) -fPIC

BIN := cuda-checkpoint libcuda.so.1 unsupported/libcuda.so.1 cuda-backend-guard-test
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

PRESERVE_GITIGNORE := y
include ../zdtm/Makefile.inc

all:	$(TARGETS)
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

cuda-backend-guard-test: backend-guard.c $(CUDA_PLUGIN_DIR)/cuda_plugin_driver.c \
		$(CUDA_PLUGIN_DIR)/cuda_plugin_cli.c \
		$(CUDA_PLUGIN_DIR)/cuda_driver_worker.c $(CUDA_PLUGIN_DIR)/cuda_driver_worker.h \
		$(CUDA_PLUGIN_DIR)/cuda_wait.c $(CUDA_PLUGIN_DIR)/cuda_wait.h ../../criu/clone-noasan.c
	$(E) " LINK     " $@
	$(Q)$(CC) $(CFLAGS) $(CUDA_TEST_CPPFLAGS) -I../../compel/include/uapi \
		backend-guard.c $(CUDA_PLUGIN_DIR)/cuda_plugin_driver.c $(CUDA_PLUGIN_DIR)/cuda_plugin_cli.c \
		$(CUDA_PLUGIN_DIR)/cuda_driver_worker.c $(CUDA_PLUGIN_DIR)/cuda_wait.c \
		../../criu/clone-noasan.c \
		-Wl,--wrap,ptrace -ldl -o $@

test: all
	PATH="$(CURDIR):$$PATH" LD_LIBRARY_PATH="$(CURDIR)$${LD_LIBRARY_PATH:+:$${LD_LIBRARY_PATH}}" ./cuda-backend-guard-test
.PHONY: test

clean-more:
	$(RM) $(TARGETS)
	$(Q)rmdir unsupported 2>/dev/null || true
.PHONY: clean-more
clean: clean-more
