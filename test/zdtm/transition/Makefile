include ../Makefile.inc

LIBDIR	= ../lib
LIB	= $(LIBDIR)/libzdtmtst.a
LDLIBS	+= $(LIBDIR)/libzdtmtst.a
override CPPFLAGS += -I$(LIBDIR)
CFLAGS	= -g -O2 -Wall -Werror -fno-strict-aliasing
CFLAGS	+= $(USERCFLAGS)

TST_NOFILE	=	\
		ipc		\
		ptrace		\
		epoll		\
		fork		\
		fork2		\
		thread-bomb	\
		maps007		\
		pipe_loop00     \
		pipe_shared00   \
		socket_loop00   \
		netlink00       \
		file_aio        \
		socket-tcp      \
		socket-tcp6     \


TST_FILE	=	\
		file_read	\
		unix_sock       \
		fifo_dyn        \
		fifo_loop       \


TST	= $(TST_NOFILE) $(TST_FILE)
SRC	= $(TST:%=%.c)
OBJ	= $(SRC:%.c=%.o)
DEP	= $(SRC:%.c=%.d)
PID	= $(TST:%=%.pid)
OUT	= $(TST:%=%.out)

%: %.c
	$(Q)echo $@ >> .gitignore
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(LOADLIBES) $^ $(LDLIBS) -o $@

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

file_aio:	override LDLIBS += -lrt -pthread
socket-tcp:	override CFLAGS += -D STREAM
socket-tcp6:	override CFLAGS += -D ZDTM_IPV6 -D STREAM
ptrace.o:	override CFLAGS += -pthread
ptrace:		override LDFLAGS += -pthread
fork2:		override CFLAGS += -D FORK2
thread-bomb.o:	override CFLAGS += -pthread
thread-bomb:	override LDFLAGS += -pthread

%: %.sh
	cp $< $@
	chmod +x $@

$(LIB):	force
	$(Q) $(MAKE) -C $(LIBDIR)

gitignore-clean:
	$(RM) -f .gitignore

clean:	gitignore-clean
	$(RM) -f $(OBJ) $(TST) *~

cleandep:	clean
	$(RM) -f $(DEP)

%.cleanout: %
	$(Q) $(RM) -f -r $<.pid* $<.out* $<.test chew_$<.test*

cleanout:
	$(RM) -f *.pid *.out* *.test chew*

realclean:	cleandep cleanout

.PHONY:	force clean cleandep cleanout realclean start check_start stop wait_stop
