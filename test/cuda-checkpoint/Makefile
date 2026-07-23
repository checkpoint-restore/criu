CFLAGS	+= $(USERCFLAGS) $(ARCHCFLAGS) -fPIC

BIN := cuda-checkpoint libcuda.so.1 unsupported/libcuda.so.1
SRC := cuda-checkpoint.c libcuda.c
DEP	:= $(SRC:%.c=%.d)
OBJ	:= $(SRC:%.c=%.o)
TARGETS	:= $(BIN)

include ../zdtm/Makefile.inc

all:	$(TARGETS)
	$(Q)printf '%s\n' cuda-checkpoint libcuda.so.1 unsupported/ > .gitignore
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

clean-more:
	$(RM) $(TARGETS)
	$(Q)rmdir unsupported 2>/dev/null || true
.PHONY: clean-more
clean: clean-more
