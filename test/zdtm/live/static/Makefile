LIBDIR	= ../../lib
LIB	= $(LIBDIR)/libzdtmtst.a
override CPPFLAGS += -I$(LIBDIR)
CFLAGS	= -g -O2 -Wall -Werror -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0

TST_NOFILE	=				\
		busyloop00			\
		sleeping00			\
		pid00				\
		caps00				\
		wait00				\
		zombie00			\
		fpu00				\
		futex				\
		futex-rl			\
		mmx00				\
		sse00				\
		sse20				\
		mprotect00			\
		timers				\
		unbound_sock			\
		socket_listen			\
		socket_udp			\
		socket6_udp			\
		socket_udplite			\
		socket_aio			\
		packet_sock			\
		msgque				\
		inotify_system			\
		inotify_system_nodel		\
		shm				\
		ptrace_sig			\
		pipe00				\
		pipe01				\
		pthread00			\
		vdso00				\
		utsname				\
		pstree				\
		sockets00			\
		sockets_spair			\
		sockets_dgram			\
		socket_queues			\
		socket-tcp			\
		ipc_namespace			\
		selfexe00			\
		sem				\
		maps01				\
		xids00				\
		file_fown			\
		eventfs00			\
		signalfd00			\
		inotify00			\
		uptime_grow			\
		session00			\
		pty00				\
		pty01				\
		pty02				\
		pty03				\
		pty04				\
		tty00				\
		mountpoints			\
		netns				\
		session01			\
		socket-ext			\
		unhashed_proc			\
#		jobctl00			\

TST_FILE	=				\
		write_read00			\
		write_read01			\
		write_read02			\
		write_read10			\
		maps00				\
		link10				\
		file_attr			\
		deleted_unix_sock		\
		deleted_dev			\
		unlink_fstat00			\
		unlink_fstat01			\
		unlink_fstat02			\
		unlink_largefile		\
		mtime_mmap			\
		fifo				\
		fifo-ghost			\
		fifo_ro				\
		fifo_wronly			\
		unlink_fifo			\
		unlink_fifo_wronly		\
		file_shared			\

TST_DIR		=				\
		cwd00				\
		overmount_dev			\
		overmount_file			\
		overmount_fifo			\
		overmount_sock			\

TST		=				\
		$(TST_NOFILE)			\
		$(TST_FILE)			\
		$(TST_DIR)			\
		env00				\
		fifo-rowo-pair			\
		umask00				\
		cmdlinenv00			\

TST_STATE	=				\
		conntracks			\
		route_rules			\


SRC	= $(TST:%=%.c)
OBJ	= $(SRC:%.c=%.o)
DEP	= $(SRC:%.c=%.d)
PID	= $(TST:%=%.pid)
OUT	= $(TST:%=%.out)
STATE	= $(TST_STATE:%=%.state)
STATE_OUT	= $(TST_STATE:%=%.out)

DEPEND.c = $(COMPILE.c) -MM -MP
%.d:	%.c
	$(DEPEND.c) $(OUTPUT_OPTION) $<

all:	$(TST)
install: all

inotify_system_nodel.c: inotify_system.c
	ln -s inotify_system.c inotify_system_nodel.c

$(TST_NOFILE:%=%.pid):	%.pid:	%
	$(<D)/$(<F) --pidfile=$@ --outfile=$<.out

$(TST_FILE:%=%.pid):	%.pid:	%
	$(<D)/$(<F) --pidfile=$@ --outfile=$<.out --filename=$<.test

$(TST_DIR:%=%.pid):	%.pid:	%
	$(<D)/$(<F) --pidfile=$@ --outfile=$<.out --dirname=$<.test

cmdlinenv00.pid: cmdlinenv00
	$(<D)/$(<F) --pidfile=$@ --outfile=$<.out --arg1=arg1 --arg2=arg2 --arg3=arg3

env00.pid:	env00
	$(<D)/$(<F) --pidfile=$@ --outfile=$<.out --envname=ENV_00_TEST
umask00.pid:	umask00
	$(<D)/$(<F) --pidfile=$@ --outfile=$<.out --mask=0345

fifo-rowo-pair.pid: fifo-rowo-pair
	$(<D)/$(<F) --pidfile=$@ --outfile=$<.out --name_master=$<.master.test --name_slave=$<.slave.test

%.out:	%.pid %
	-kill -TERM `cat $<`

$(TST_STATE:%=%.state):	%.state: %
	$(<D)/$(<F) --statefile=$@ --outfile=$<.out start

$(TST_STATE:%=%.out): %.out: %
	-$(<D)/$(<F) --statefile=$<.state --outfile=$@ stop

start:	$(PID) $(STATE)

%.is_running:	%.pid
	kill -0 `cat $<`

check_start:	$(PID:%.pid=%.is_running)

stop:	$(STATE_OUT)
	-kill -TERM `cat *.pid`

WAIT_TIME=10
wait_stop:
	-for ((i = 0; i < $(WAIT_TIME); i++)); do \
		kill -0 `cat *.pid 2>/dev/null` 2>/dev/null || break; \
		sleep 1; \
	done

$(TST):	$(LIB)

futex.o:		override CFLAGS += -pthread
futex:			override LDFLAGS += -pthread
futex-rl.o:		override CFLAGS += -pthread
futex-rl:		override LDFLAGS += -pthread
jobctl00:		override LDLIBS += -lutil
socket_listen:		override LDLIBS += -lrt -pthread
socket_aio:		override LDLIBS += -lrt -pthread
uptime_grow:	override LDLIBS += -lrt -pthread
unlink_largefile:	override CFLAGS += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE
inotify_system_nodel:	override CFLAGS += -DNODEL
pthread00:		override LDLIBS += -pthread
shm:			override CFLAGS += -DNEW_IPC_NS
msgque:			override CFLAGS += -DNEW_IPC_NS
sem:			override CFLAGS += -DNEW_IPC_NS

$(LIB):	force
	$(MAKE) -C $(LIBDIR)

clean:
	$(RM) $(OBJ) $(TST) *~

cleandep:	clean
	$(RM) $(DEP)

cleanout:
	$(RM) -r *.pid *.out* *.test* *.state

realclean:	cleandep cleanout

.PHONY:	force clean cleandep cleanout realclean start check_start stop wait_stop

ifeq ($(filter-out no-deps-targets, $(MAKECMDGOALS)),)
-include $(DEP)
endif
