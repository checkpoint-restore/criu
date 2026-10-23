CFLAGS	+= $(USERCFLAGS) $(ARCHCFLAGS) -fPIC

BIN := untraced-clone-target dump_finish_failure.so
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

untraced-clone-target: untraced-clone-target.c
	$(E) " LINK     " $@
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

dump_finish_failure.so: dump-finish-failure.c ../../criu/include/criu-plugin.h
	$(E) " LINK     " $@
	$(Q)$(CC) $(CFLAGS) $(CUDA_TEST_CPPFLAGS) $(LDFLAGS) -shared -nostartfiles $< -o $@

test: all
	$(Q)$(MAKE) -C ../../plugins/cuda/tests test
.PHONY: test

clean-more:
	$(RM) $(TARGETS)
	$(Q)rmdir unsupported 2>/dev/null || true
.PHONY: clean-more
clean: clean-more
