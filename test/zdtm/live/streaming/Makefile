LIBDIR	= ../../lib
LIB	= $(LIBDIR)/libzdtmtst.a
override CPPFLAGS += -I$(LIBDIR)
CFLAGS	= -g -O2 -Wall -Werror -fno-strict-aliasing

TST_NOFILE	=	\
		pipe_loop00	\
		pipe_shared00	\
		socket_loop00	\
		netlink00	\
		file_aio	\

TST_FILE	=	\
		unix_sock	\
		fifo_dyn	\
		fifo_loop	\

TST	= $(TST_NOFILE) $(TST_FILE)
SRC	= $(TST:%=%.c)
OBJ	= $(SRC:%.c=%.o)
DEP	= $(SRC:%.c=%.d)
PID	= $(TST:%=%.pid)
OUT	= $(TST:%=%.out)

DEPEND.c = $(COMPILE.c) -MM -MP
%.d:	%.c
	$(DEPEND.c) $(OUTPUT_OPTION) $<

all:	$(TST)
install: all

$(TST_NOFILE:%=%.pid):	%.pid:	%
	$(<D)/$(<F) --pidfile=$@ --outfile=$<.out

$(TST_FILE:%=%.pid):	%.pid:	%
	$(<D)/$(<F) --pidfile=$@ --outfile=$<.out --filename=$<.test

%.out:	%.pid %
	-kill -TERM `< $<`

start:	$(PID)

%.is_running:	%.pid
	kill -0 `< $<`

check_start:	$(PID:%.pid=%.is_running)

stop:
	-kill -TERM `cat *.pid`

WAIT_TIME=10
wait_stop:
	-for ((i = 0; i < $(WAIT_TIME); i++)); do \
		kill -0 `cat *.pid 2>/dev/null` 2>/dev/null || break; \
		sleep 1; \
	done

$(TST):	$(LIB)

file_aio: override LDLIBS += -lrt

$(LIB):	force
	$(MAKE) -C $(LIBDIR)

clean:
	$(RM) $(OBJ) $(TST) *~

cleandep:	clean
	$(RM) $(DEP)

cleanout:
	$(RM) *.pid *.out* *.test*

realclean:	cleandep cleanout

.PHONY:	force clean cleandep cleanout realclean start check_start stop wait_stop

ifeq ($(filter-out no-deps-targets, $(MAKECMDGOALS)),)
-include $(DEP)
endif
