include ../../Makefile.inc

LIBDIR	= ../../lib
LIB	= $(LIBDIR)/libzdtmtst.a
override CPPFLAGS += -I$(LIBDIR)
CFLAGS	= -g -O2 -Wall -Werror
CFLAGS	+= $(USERCFLAGS)

TST_NOFILE	=	\
		ipc		\
		ptrace		\
		epoll		\
		fork		\
		fork2		\
		thread-bomb	\
		maps007		\

TST_FILE	=	\
		file_read	\

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
.PHONY: all install

$(TST_NOFILE:%=%.pid):	%.pid:	%
	$(<D)/$(<F) --pidfile=$@ --outfile=$<.out

$(TST_FILE:%=%.pid):	%.pid:	%
	$(<D)/$(<F) --pidfile=$@ --outfile=$<.out --filename=$<.test

%.out:	%.pid %
	-kill -TERM `cat $<`

start:	$(PID)

%.is_running:	%.pid
	kill -0 `cat $<`

check_start:	$(PID:%.pid=%.is_running)

stop:
	-kill -TERM `cat *.pid`

WAIT_TIME=10
wait_stop:
	-for i in `seq 1 $(WAIT_TIME)`; do \
		kill -0 `cat *.pid 2>/dev/null` 2>/dev/null || break; \
		sleep 1; \
	done

$(TST):	$(LIB)

ptrace.o:	override CFLAGS += -pthread
ptrace:		override LDFLAGS += -pthread
ipc:		override CFLAGS += -DNEW_IPC_NS
fork2:		override CFLAGS += -D FORK2
thread-bomb.o:		override CFLAGS += -pthread
thread-bomb:		override LDFLAGS += -pthread

%: %.sh
	cp $< $@
	chmod +x $@

$(LIB):	force
	$(Q) $(MAKE) -C $(LIBDIR)

clean:
	$(RM) -f $(OBJ) $(TST) *~

cleandep:	clean
	$(RM) -f $(DEP)

%.cleanout: %
	$(Q) $(RM) -f -r $<.pid $<.out* $<.test chew_$<.test*

cleanout:
	$(RM) -f *.pid *.out* *.test chew*

realclean:	cleandep cleanout

.PHONY:	force clean cleandep cleanout realclean start check_start stop wait_stop

ifeq ($(filter-out no-deps-targets, $(MAKECMDGOALS)),)
-include $(DEP)
endif
