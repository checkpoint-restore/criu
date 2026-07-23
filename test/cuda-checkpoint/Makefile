CFLAGS	+= $(USERCFLAGS) $(ARCHCFLAGS) -fPIC

BIN := libcuda.so.1
SRC := libcuda.c
DEP	:= $(SRC:%.c=%.d)
OBJ	:= $(SRC:%.c=%.o)
TARGETS	:= $(BIN)

include ../zdtm/Makefile.inc

all:	$(TARGETS)
.PHONY: all

libcuda.so.1: libcuda.o
	$(E) " LINK     " $@
	$(Q)$(CC) $(LDFLAGS) -shared $^ -o $@

clean-more:
	$(RM) $(TARGETS)
.PHONY: clean-more
clean: clean-more
