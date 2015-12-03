include ../Makefile.inc

CFLAGS	= -g -O2 -Wall -Werror -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
CFLAGS	+= $(USERCFLAGS)

LIBDIR	= .
LIB	= libzdtmtst.a
GRPS	= groups

LIBSRC	= datagen.c msg.c parseargs.c test.c streamutil.c lock.c ns.c tcp.c fs.c
LIBOBJ	= $(LIBSRC:%.c=%.o)
LIBDEP	= $(LIBSRC:%.c=%.d)

DEPEND.c = $(COMPILE.c) -MM -MP
%.d:	%.c
	$(DEPEND.c) $(OUTPUT_OPTION) $<

all:	$(LIB)
	@true
install: all
.PHONY: all install

$(LIB):	$(LIBOBJ)
	$(Q) ar rv $@ $^

clean:
	$(RM) -f $(LIBOBJ) $(LIB) *~

cleandep:
	$(RM) -f $(LIBDEP)

cleanout:
	@true

$(GRPS): $(LIB)

$(GRPS:%=%.pid): $(GRPS)
	$(<D)/$(<F) --pidfile=$@ --outfile=$<.out

$(GRPS:%=%.out): $(GRPS:%=%.pid)
	-kill -TERM `cat $<`

$(GRPS:%=%.cleanout): $(GRPS)
	$(Q) $(RM) -f -r $<.pid $<.out* *$<.test* $<.*.test $<.state $<.init.pid

realclean:	clean cleandep

.PHONY:	clean cleandep cleanout realclean

ifeq ($(filter-out no-deps-targets, $(MAKECMDGOALS)),)
-include $(LIBDEP)
endif
