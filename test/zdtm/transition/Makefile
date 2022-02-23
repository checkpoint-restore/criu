LIBDIR	:= ../lib
LIB	:= $(LIBDIR)/libzdtmtst.a
LDLIBS	+= $(LIB)
CPPFLAGS += -I$(LIBDIR)

TST_NOFILE	=	\
		ipc		\
		ptrace		\
		epoll		\
		fork		\
		fork2		\
		thread-bomb	\
		maps007		\
		maps008		\
		pipe_loop00     \
		pipe_shared00   \
		socket_loop00   \
		netlink00       \
		file_aio        \
		socket-tcp      \
		socket-tcp6     \
		shmem		\
		lazy-thp	\
		pid_reuse	\
		pidfd_store_sk \
		rseq01		\
		rseq02		\


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

include ../Makefile.inc

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
	-kill -TERM `awk '{print}' *.pid`

WAIT_TIME=10
wait_stop:
	-for i in `seq 1 $(WAIT_TIME)`; do \
		kill -0 `awk '{print}' *.pid 2>/dev/null` 2>/dev/null || break; \
		sleep 1; \
	done

$(TST):	| $(LIB)

file_aio:	LDLIBS += -lrt -pthread
socket-tcp:	CFLAGS += -D STREAM
socket-tcp6:	CFLAGS += -D ZDTM_IPV6 -D STREAM
ptrace.o:	CFLAGS += -pthread
ptrace:		LDFLAGS += -pthread
fork2:		CFLAGS += -D FORK2
thread-bomb.o:	CFLAGS += -pthread
thread-bomb:	LDFLAGS += -pthread
rseq02:		CFLAGS += -D NORESTART

%: %.sh
	cp $< $@
	chmod +x $@

$(LIB):	force
	$(Q) $(MAKE) -C $(LIBDIR)

.PHONY:	force start check_start stop wait_stop
