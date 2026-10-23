LIBDIR := ../../../../test/zdtm/lib
CFLAGS += -fPIC
BIN := cuda-checkpoint libcuda.so.1 unsupported/libcuda.so.1
SRC := cuda-checkpoint.c libcuda.c
OBJ := $(SRC:%.c=%.o)
DEP := $(SRC:%.c=%.d)
PRESERVE_GITIGNORE := y
include ../../../../test/zdtm/Makefile.inc

all: $(BIN)

cuda-checkpoint: cuda-checkpoint.o
	$(E) " LINK     " $@
	$(Q)$(CC) $(LDFLAGS) $^ -o $@

libcuda.so.1: libcuda.o
	$(E) " LINK     " $@
	$(Q)$(CC) $(LDFLAGS) -shared $^ -o $@

unsupported/libcuda.so.1: libcuda.c
	$(Q)mkdir -p $(@D)
	$(E) " LINK     " $@
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -shared -DMOCK_CUDA_DRIVER_VERSION=12000 $< -o $@

clean-more:
	$(Q)$(RM) $(BIN)
	$(Q)rmdir unsupported 2>/dev/null || true

clean: clean-more

.PHONY: all clean-more
