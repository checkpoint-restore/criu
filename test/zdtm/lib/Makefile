MAKEFLAGS	+= -r
LIBDIR	:= .
include ../Makefile.inc

CFLAGS	:= -g -O2 -Wall -Werror -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
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

all:	$(TARGETS)
.PHONY: all

DEPEND.c = $(COMPILE.c) -MM -MP
%.d:   %.c
	$(E) " DEP      " $*.d
	$(Q)$(DEPEND.c) $(OUTPUT_OPTION) $<

%.o: %.c | %.d
	$(E) " CC       " $@
	$(Q)$(COMPILE.c) $(OUTPUT_OPTION) $<

%: %.o $(LDLIBS)
	$(E) " LINK     " $@
	$(Q)$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(LIB):	$(LIBOBJ)
	$(E) " AR       " $@
	$(Q)ar rcs $@ $^

dep: $(DEP)
.PHONY: dep

clean:
	$(RM) $(OBJ) $(TARGETS)

cleandep: clean
	$(RM) $(DEP)

cleanout: clean ;

realclean:	clean cleandep

.PHONY:	clean cleandep cleanout realclean

no-deps-targets	:= clean cleandep cleanout realclean

ifeq ($(filter $(no-deps-targets), $(MAKECMDGOALS)),)
-include $(DEP)
endif
