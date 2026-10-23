LIBDIR := ../../../../test/zdtm/lib
CFLAGS += -fPIC
BIN := cuda-checkpoint libcuda.so.1
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

clean-more:
	$(Q)$(RM) $(BIN)

clean: clean-more

.PHONY: all clean-more
