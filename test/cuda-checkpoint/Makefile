CFLAGS	+= $(USERCFLAGS) $(ARCHCFLAGS)

BIN := cuda-checkpoint
SRC := cuda-checkpoint.c
DEP	:= $(SRC:%.c=%.d)
OBJ	:= $(SRC:%.c=%.o)
TARGETS	:= $(BIN)

include ../zdtm/Makefile.inc

all:	$(TARGETS)
.PHONY: all

clean-more:
	$(RM) $(TARGETS)
.PHONY: clean-more
clean: clean-more
