include ../Makefile.inc

LIBDIR	= ../lib
LIB	= $(LIBDIR)/libzdtmtst.a
LDLIBS	+= $(LIBDIR)/libzdtmtst.a
override CPPFLAGS += -I$(LIBDIR)
CFLAGS	= -g -O2 -Wall -Werror -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
CFLAGS	+= $(USERCFLAGS)

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
		timerfd				\
		unbound_sock			\
		sched_prio00			\
		sched_policy00			\
		socket_listen			\
		socket_listen6			\
		socket_udp			\
		socket6_udp			\
		sk-freebind			\
		sk-freebind-false		\
		socket_udplite			\
		socket_aio			\
		socket_close_data		\
		socket_snd_addr			\
		socket_dgram_data		\
		packet_sock			\
		packet_sock_mmap		\
		sock_filter			\
		msgque				\
		inotify_system			\
		inotify_system_nodel		\
		shm				\
		shm-mp				\
		ptrace_sig			\
		pipe00				\
		pipe01				\
		pipe02				\
		pthread00			\
		pthread01			\
		pthread02			\
		vdso00				\
		vdso01				\
		utsname				\
		pstree				\
		sockets01			\
		sockets02			\
		sockets_spair			\
		socket_queues			\
		socket_queues02			\
		socket-tcp			\
		socket-tcp6			\
		socket-tcp-local		\
		socket-tcp-nfconntrack		\
		socket-tcp6-local		\
		socket-tcpbuf			\
		socket-tcpbuf-local		\
		socket-tcpbuf6-local		\
		socket-tcpbuf6			\
		socket-closed-tcp		\
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
		maps05				\
		mlock_setuid			\
		xids00				\
		groups				\
		pdeath_sig			\
		file_fown			\
		proc-self			\
		eventfs00			\
		signalfd00			\
		inotify_irmap			\
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
		poll				\
		mountpoints			\
		netns				\
		netns-dev			\
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
		grow_map03			\
		tun				\
		stopped				\
		stopped01			\
		stopped02			\
		stopped12			\
		rtc				\
		clean_mntns			\
		mntns_rw_ro_rw			\
		dumpable01			\
		dumpable02			\
		remap_dead_pid			\
		remap_dead_pid_root			\
		aio00				\
		aio01				\
		fd				\
		apparmor				\
		seccomp_strict			\
		seccomp_filter			\
		seccomp_filter_tsync			\
		seccomp_filter_inheritance		\
		different_creds			\
		vsx				\
		bridge				\
		vfork00				\
		oom_score_adj			\
		loginuid			\
		cgroupns			\
		helper_zombie_child		\
#		jobctl00			\

TST_FILE	=				\
		maps06				\
		write_read00			\
		write_read01			\
		write_read02			\
		write_read10			\
		maps00				\
		link10				\
		file_attr			\
		deleted_unix_sock		\
		sk-unix-rel			\
		deleted_dev			\
		unlink_fstat00			\
		unlink_fstat01			\
		unlink_fstat01+			\
		unlink_fstat02			\
		unlink_fstat03			\
		unlink_largefile		\
		mtime_mmap			\
		fifo				\
		fifo-ghost			\
		fifo_ro				\
		fifo_wronly			\
		console				\
		vt				\
		unlink_fifo			\
		unlink_fifo_wronly		\
		unlink_mmap00			\
		unlink_mmap01			\
		unlink_mmap02			\
		file_shared			\
		file_append			\
		cow01				\
		fdt_shared			\
		sockets00			\
		sockets03			\
		sockets_dgram			\
		file_locks00			\
		file_locks01			\
		file_locks02			\
		file_locks03			\
		file_locks04			\
		file_locks05			\
		netns-nf			\
		maps_file_prot			\
		socket_close_data01		\

TST_DIR		=				\
		cwd00				\
		cwd01				\
		cwd02				\
		overmount_dev			\
		overmount_file			\
		overmount_fifo			\
		overmount_sock			\
		tempfs				\
		tempfs_overmounted		\
		tempfs_overmounted01		\
		tempfs_ro			\
		tempfs_subns			\
		mnt_ro_bind			\
		mount_paths			\
		bind-mount			\
		inotify00			\
		inotify01			\
		inotify02			\
		cgroup00			\
		rmdir_open			\
		cgroup01			\
		cgroup02			\
		cgroup03			\
		cgroup04			\
		cgroup_stray		\
		unlink_fstat04			\
		mntns_open			\
		mntns_link_remap		\
		mntns_ghost			\
		mntns_link_ghost		\
		mntns_shared_bind		\
		mntns_shared_bind02		\
		mntns_root_bind			\
		mntns_root_bind02		\
		mntns_overmount			\
		mntns_shared_vs_private		\
		mnt_ext_auto			\
		mnt_ext_master			\
		mnt_ext_dev			\
		mnt_tracefs			\
		mntns_deleted			\
		unlink_regular00		\
		mnt_enablefs			\
		autofs				\
		del_standalone_un		\

TST_DIR_FILE	=				\
		chroot				\
		chroot-file			\
		binfmt_misc			\

TST		=				\
		$(TST_NOFILE)			\
		$(TST_FILE)			\
		$(TST_DIR)			\
		$(TST_DIR_FILE)			\
		env00				\
		fifo-rowo-pair			\
		umask00				\
		cmdlinenv00			\
		shm-unaligned			\

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

%: %.c
	$(Q)echo $@ >> .gitignore
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(LOADLIBES) $^ $(LDLIBS) -o $@

all:	$(TST) criu-rtc.so
install: all
.PHONY: all install

inotify_system_nodel.c: inotify_system.c
	ln -sf inotify_system.c inotify_system_nodel.c

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

shm-unaligned.pid: shm-unaligned
	$(<D)/$(<F) --pidfile=$@ --outfile=$<.out --shmem_size=5000

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

WAIT_TIME=240
%.stop:	%.pid %
	kill -TERM `cat $<`; \
	i=0; \
	while [ $$i -lt $(WAIT_TIME) ] ; do \
		kill -0 `cat $< 2>/dev/null` 2>/dev/null || break; \
		sleep 1; \
		echo -n .; \
		i=`expr $$i + 1`; \
	done; \
	echo; \
	[ $$i -lt $(WAIT_TIME) ]

wait_stop:
		i=0; \
		while [ $$i -lt $(WAIT_TIME) ] ; do \
		kill -0 `cat *.pid 2>/dev/null` 2>/dev/null || break; \
		sleep 1; \
		i=`expr $$i + 1`; \
	done

$(TST):	$(LIB)

aio00:			override LDLIBS += -laio
different_creds:	override LDLIBS += -lcap
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
pthread02:		override LDLIBS += -pthread
different_creds:	override LDLIBS += -pthread
sigpending:		override LDLIBS += -pthread
sigaltstack:		override LDLIBS += -pthread
seccomp_filter_tsync:		override LDLIBS += -pthread
shm:			override CFLAGS += -DNEW_IPC_NS
msgque:			override CFLAGS += -DNEW_IPC_NS
sem:			override CFLAGS += -DNEW_IPC_NS
posix_timers:		override LDLIBS += -lrt -pthread
socket-tcp6: override CFLAGS += -D ZDTM_IPV6
socket-tcpbuf6: override CFLAGS += -D ZDTM_IPV6
socket-tcpbuf-local: override CFLAGS += -D ZDTM_TCP_LOCAL
socket-tcpbuf6-local: override CFLAGS += -D ZDTM_TCP_LOCAL -D ZDTM_IPV6
socket-tcp6-local: override CFLAGS += -D ZDTM_TCP_LOCAL -D ZDTM_IPV6
socket-tcp-local: override CFLAGS += -D ZDTM_TCP_LOCAL
socket-tcp-nfconntrack: override CFLAGS += -D ZDTM_TCP_LOCAL -DZDTM_CONNTRACK
socket_listen6: override CFLAGS += -D ZDTM_IPV6
sigpending:		override LDLIBS += -lrt
vdso01:			override LDLIBS += -lrt
mntns_link_remap:	override CFLAGS += -DZDTM_LINK_REMAP
mntns_shared_bind02:		override CFLAGS += -DSHARED_BIND02
mntns_root_bind02:	override CFLAGS += -DROOT_BIND02
maps02:		get_smaps_bits.o
mlock_setuid:		get_smaps_bits.o
inotify01:		override CFLAGS += -DINOTIFY01
unlink_fstat01+:	override CFLAGS += -DUNLINK_OVER
unlink_fstat04:		override CFLAGS += -DUNLINK_FSTAT04
sk-freebind-false:	override CFLAGS += -DZDTM_FREEBIND_FALSE
stopped01:	override CFLAGS += -DZDTM_STOPPED_KILL
stopped02:	override CFLAGS += -DZDTM_STOPPED_TKILL
stopped12:	override CFLAGS += -DZDTM_STOPPED_KILL -DZDTM_STOPPED_TKILL

$(LIB):	force
	$(Q) $(MAKE) -C $(LIBDIR)

gitignore-clean:
	$(RM) -f .gitignore

clean:	gitignore-clean
	$(RM) -f $(OBJ) $(TST) *~ criu-rtc.so criu-rtc.pb-c.c criu-rtc.pb-c.h get_smaps_bits.o

cleandep:	clean
	$(RM) -f $(DEP)

cleanout:
	$(RM) -f -r *.pid *.out* *.test* *.state

%.cleanout: %
	$(Q) $(RM) -f -r $<.pid* $<.out* *$<.test* $<.*.test $<.state

realclean:	cleandep cleanout

rtc.c: criu-rtc.so

criu-rtc.pb-c.c: criu-rtc.proto
	$(Q)echo $@ >> .gitignore
	$(Q)echo $(@:%.c=%.h) >> .gitignore
	protoc-c --proto_path=. --c_out=. criu-rtc.proto

criu-rtc.so: criu-rtc.c criu-rtc.pb-c.c
	$(CC) -g -Wall -shared -nostartfiles criu-rtc.c criu-rtc.pb-c.c -o criu-rtc.so -iquote ../../../criu/include -fPIC $(USERCFLAGS)

.PHONY:	force clean cleandep cleanout realclean start check_start stop wait_stop
