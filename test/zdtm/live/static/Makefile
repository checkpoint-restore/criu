include ../../Makefile.inc

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
		fpu01				\
		arm-neon00			\
		futex				\
		futex-rl			\
		mmx00				\
		sse00				\
		sse20				\
		mprotect00			\
		timers				\
		unbound_sock			\
		sched_prio00			\
		sched_policy00			\
		socket_listen			\
		socket_listen6			\
		socket_udp			\
		socket6_udp			\
		socket_udplite			\
		socket_aio			\
		packet_sock			\
		sock_filter			\
		msgque				\
		inotify_system			\
		inotify_system_nodel		\
		shm				\
		ptrace_sig			\
		pipe00				\
		pipe01				\
		pipe02				\
		pthread00			\
		pthread01			\
		vdso00				\
		utsname				\
		pstree				\
		sockets01			\
		sockets02			\
		sockets_spair			\
		socket_queues			\
		socket_queues02			\
		socket-tcp			\
		socket-tcp6			\
		socket-tcpbuf			\
		socket-tcpbuf-local		\
		socket-tcpbuf6			\
		sock_opts00			\
		sock_opts01			\
		sk-unix-unconn			\
		ipc_namespace			\
		selfexe00			\
		sem				\
		maps01				\
		maps02				\
		maps03				\
		maps04				\
		xids00				\
		groups				\
		file_fown			\
		proc-self			\
		eventfs00			\
		signalfd00			\
		inotify00			\
		fanotify00			\
		uptime_grow			\
		session00			\
		rlimits00			\
		pty00				\
		pty01				\
		pty02				\
		pty03				\
		pty04				\
		tty00				\
		tty02				\
		tty03				\
		mountpoints			\
		netns				\
		session01			\
		session02			\
		session03			\
		socket-ext			\
		unhashed_proc			\
		cow00				\
		child_opened_proc		\
		posix_timers			\
		sigpending			\
		sigaltstack			\
		sk-netlink			\
		mem-touch			\
		grow_map			\
		grow_map02			\
		tun				\
		stopped				\
		rtc				\
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
		unlink_fstat03			\
		unlink_largefile		\
		mtime_mmap			\
		fifo				\
		fifo-ghost			\
		fifo_ro				\
		fifo_wronly			\
		unlink_fifo			\
		unlink_fifo_wronly		\
		file_shared			\
		file_append			\
		cow01				\
		fdt_shared			\
		sockets00			\
		sockets_dgram			\
		file_locks00			\
		file_locks01			\
		netns-nf			\

TST_DIR		=				\
		cwd00				\
		overmount_dev			\
		overmount_file			\
		overmount_fifo			\
		overmount_sock			\

TST_DIR_FILE	=				\
		chroot				\
		chroot-file

TST		=				\
		$(TST_NOFILE)			\
		$(TST_FILE)			\
		$(TST_DIR)			\
		$(TST_DIR_FILE)			\
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

all:	$(TST) criu-rtc.so
install: all

inotify_system_nodel.c: inotify_system.c
	ln -s inotify_system.c inotify_system_nodel.c

$(TST_NOFILE:%=%.pid):	%.pid:	%
	$(<D)/$(<F) --pidfile=$@ --outfile=$<.out

$(TST_FILE:%=%.pid):	%.pid:	%
	$(<D)/$(<F) --pidfile=$@ --outfile=$<.out --filename=$<.test

$(TST_DIR:%=%.pid):	%.pid:	%
	$(<D)/$(<F) --pidfile=$@ --outfile=$<.out --dirname=$<.test

$(TST_DIR_FILE:%=%.pid):	%.pid:	%
	$(<D)/$(<F) --pidfile=$@ --outfile=$<.out --dirname=$<.dir.test --filename=$<.test

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
pthread01:		override LDLIBS += -pthread
sigpending:		override LDLIBS += -pthread
sigaltstack:		override LDLIBS += -pthread
shm:			override CFLAGS += -DNEW_IPC_NS
msgque:			override CFLAGS += -DNEW_IPC_NS
sem:			override CFLAGS += -DNEW_IPC_NS
posix_timers:		override LDLIBS += -lrt
socket-tcp6: override CFLAGS += -D ZDTM_IPV6
socket-tcpbuf6: override CFLAGS += -D ZDTM_IPV6
socket-tcpbuf-local: override CFLAGS += -D ZDTM_TCP_LOCAL
socket_listen6: override CFLAGS += -D ZDTM_IPV6
sigpending:		override LDLIBS += -lrt

$(LIB):	force
	$(Q) $(MAKE) -C $(LIBDIR)

clean:
	$(RM) -f $(OBJ) $(TST) *~ criu-rtc.so criu-rtc.pb-c.c criu-rtc.pb-c.h

cleandep:	clean
	$(RM) -f $(DEP)

cleanout:
	$(RM) -f -r *.pid *.out* *.test* *.state

%.cleanout: %
	$(Q) $(RM) -f -r $<.pid $<.out* *$<.test* $<.*.test $<.state

realclean:	cleandep cleanout

rtc.c: criu-rtc.so

criu-rtc.pb-c.c: criu-rtc.proto
	protoc-c --proto_path=. --c_out=. criu-rtc.proto

criu-rtc.so: criu-rtc.c criu-rtc.pb-c.c
	gcc -g -Wall -shared -nostartfiles criu-rtc.c criu-rtc.pb-c.c -o criu-rtc.so -iquote ../../../../include -fPIC

.PHONY:	force clean cleandep cleanout realclean start check_start stop wait_stop

ifeq ($(filter-out no-deps-targets, $(MAKECMDGOALS)),)
-include $(DEP)
endif
