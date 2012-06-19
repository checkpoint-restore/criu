CFLAGS	= -g -O2 -Wall -Werror -Wno-unused-result

LIB	= libzdtmtst.a

LIBSRC	= datagen.c msg.c parseargs.c test.c streamutil.c lock.c
LIBOBJ	= $(LIBSRC:%.c=%.o)
LIBDEP	= $(LIBSRC:%.c=%.d)

DEPEND.c = $(COMPILE.c) -MM -MP
%.d:	%.c
	$(DEPEND.c) $(OUTPUT_OPTION) $<

all:	$(LIB) test_init
install: all

$(LIB):	$(LIB)(${LIBOBJ})

test_init: test_init.c

clean:
	$(RM) $(LIBOBJ) $(LIB) test_init *~

cleandep:
	$(RM) $(LIBDEP)

realclean:	clean cleandep

.PHONY:	force clean cleandep cleanout realclean start check_start stop wait_stop

ifeq ($(filter-out no-deps-targets, $(MAKECMDGOALS)),)
-include $(LIBDEP)
endif
