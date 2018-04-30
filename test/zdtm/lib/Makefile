LIBDIR	:= .

CFLAGS	+= $(USERCFLAGS)

LIB	:= libzdtmtst.a

LIBSRC	:= datagen.c msg.c parseargs.c test.c streamutil.c lock.c ns.c tcp.c fs.c
LIBOBJ	:= $(LIBSRC:%.c=%.o)

BIN	:= groups
SRC	:= $(LIBSRC) groups.c
DEP	:= $(SRC:%.c=%.d)
OBJ	:= $(SRC:%.c=%.o)
LDLIBS	:= $(LIB)

TARGETS	:= $(LIB) $(BIN)

include ../Makefile.inc

all:	$(TARGETS)
.PHONY: all

clean-more:
	$(RM) $(TARGETS)
.PHONY: clean-more
clean: clean-more

$(LIB):	$(LIBOBJ)
	$(E) " AR       " $@
	$(Q)ar rcs $@ $^
