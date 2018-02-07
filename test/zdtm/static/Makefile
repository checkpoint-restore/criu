LIBDIR	:= ../lib
LIB	:= $(LIBDIR)/libzdtmtst.a
LDLIBS	+= $(LIB)
CPPFLAGS += -I$(LIBDIR)

TST_NOFILE	:=				\
		busyloop00			\
		sleeping00			\
		pid00				\
		caps00				\
		wait00				\
		zombie00			\
		zombie01			\
		fpu00				\
		fpu01				\
		fpu02				\
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
		socket_listen4v6		\
		socket_udp			\
		socket_udp-corked		\
		socket6_udp			\
		socket_udp_shutdown		\
		sk-freebind			\
		sk-freebind-false		\
		socket_udplite			\
		socket_aio			\
		socket_close_data		\
		socket_snd_addr			\
		socket_dgram_data		\
		packet_sock			\
		packet_sock_mmap		\
		packet_sock_spkt		\
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
		vdso02				\
		vdso-proxy			\
		utsname				\
		pstree				\
		sockets01			\
		sockets02			\
		sockets_spair			\
		socket_queues			\
		socket-tcp			\
		socket-tcp-reseted		\
		socket-tcp6			\
		socket-tcp4v6			\
		socket-tcp-local		\
		socket-tcp-reuseport		\
		socket-tcp-nfconntrack		\
		socket-tcp6-local		\
		socket-tcp4v6-local		\
		socket-tcpbuf			\
		socket-tcpbuf-local		\
		socket-tcpbuf6-local		\
		socket-tcpbuf6			\
		socket-tcp-fin-wait1		\
		socket-tcp6-fin-wait1		\
		socket-tcp4v6-fin-wait1		\
		socket-tcp-fin-wait2		\
		socket-tcp6-fin-wait2		\
		socket-tcp4v6-fin-wait2		\
		socket-tcp-close-wait		\
		socket-tcp6-close-wait		\
		socket-tcp4v6-close-wait		\
		socket-tcp-last-ack		\
		socket-tcp6-last-ack		\
		socket-tcp4v6-last-ack		\
		socket-tcp-closing		\
		socket-tcp6-closing		\
		socket-tcp4v6-closing		\
		socket-tcp-closed		\
		socket-tcp-closed-last-ack	\
		socket-tcp6-closed		\
		socket-tcp4v6-closed		\
		socket-tcp-close0 		\
		socket-tcp-close1 		\
		socket-tcp-unconn		\
		socket-tcp6-unconn		\
		socket-tcp-syn-sent		\
		sock_opts00			\
		sock_opts01			\
		sk-unix-unconn			\
		ipc_namespace			\
		selfexe00			\
		sem				\
		maps01				\
		maps02				\
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
		pty-console			\
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
		scm00				\
		scm01				\
		scm02				\
		scm03				\
		scm04				\
		scm05				\
		scm06				\
		aio00				\
		aio01				\
		fd				\
		fd01				\
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
		clone_fs			\
		macvlan			\
		sit				\
		cr_veth				\
		sock_peercred			\
		s390x_mmap_high			\
		uffd-events			\
		thread_different_uid_gid	\
		pipe03				\
		netns_sub			\
		netns_sub_veth			\
#		jobctl00			\

include ../Makefile.inc

ifneq ($(SRCARCH),arm)
ifneq ($(COMPAT_TEST),y)
        TST_NOFILE += maps03
endif
endif

ifeq ($(SRCARCH),s390)
        TST_NOFILE +=	s390x_regs_check	\
			s390x_gs_threads	\
			s390x_runtime_instr
endif

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
		ghost_holes00			\
		ghost_holes01			\
		ghost_holes02			\
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
		file_lease00			\
		file_lease01			\
		file_lease02			\
		file_lease03			\
		file_lease04			\
		file_locks00			\
		file_locks01			\
		file_locks02			\
		file_locks03			\
		file_locks04			\
		file_locks05			\
		file_locks06			\
		file_locks07			\
		file_locks08			\
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
		tempfs_ro02			\
		tempfs_subns			\
		mnt_ro_bind			\
		mount_paths			\
		bind-mount			\
		shared_mount_propagation	\
		overmount_with_shared_parent	\
		inotify00			\
		inotify01			\
		inotify02			\
		cgroup00			\
		rmdir_open			\
		cgroup01			\
		cgroup02			\
		cgroup03			\
		cgroup04			\
		cgroup_ifpriomap		\
		cgroup_stray		\
		unlink_fstat04			\
		mntns_remap			\
		mntns_open			\
		mntns_link_remap		\
		mntns_ghost			\
		mntns_ghost01			\
		mntns_ro_root			\
		mntns_link_ghost		\
		mntns_shared_bind		\
		mntns_shared_bind02		\
		mntns_shared_bind03		\
		mntns_root_bind			\
		mntns_root_bind02		\
		mntns_overmount			\
		mntns_shared_vs_private		\
		mnt_ext_manual			\
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

AUX_SRC	= get_smaps_bits.c ofd_file_locks.c

SRC	= $(TST:%=%.c) $(AUX_SRC)
OBJ	= $(SRC:%.c=%.o)
DEP	= $(SRC:%.c=%.d)
PID	= $(TST:%=%.pid)
OUT	= $(TST:%=%.out)
STATE	= $(TST_STATE:%=%.state)
STATE_OUT	= $(TST_STATE:%=%.out)

all:	$(TST) criu-rtc.so
install: all
.PHONY: all install

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
	-kill -TERM `awk '{print}' *.pid`

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
		kill -0 `awk '{print}' *.pid 2>/dev/null` 2>/dev/null || break; \
		sleep 1; \
		i=`expr $$i + 1`; \
	done

$(TST):	| $(LIB)

aio00:			LDLIBS += -laio
different_creds:	LDLIBS += -lcap
file_locks06 file_locks07 file_locks08:	ofd_file_locks.o
futex:			CFLAGS += -pthread
futex:			LDFLAGS += -pthread
futex-rl:		CFLAGS += -pthread
futex-rl:		LDFLAGS += -pthread
jobctl00:		LDLIBS += -lutil
socket_listen:		LDLIBS += -lrt -pthread
socket_aio:		LDLIBS += -lrt -pthread
uptime_grow:		LDLIBS += -lrt -pthread
unlink_largefile:	CFLAGS += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE
inotify_system_nodel:	CFLAGS += -DNODEL
pthread00:		LDLIBS += -pthread
pthread01:		LDLIBS += -pthread
pthread02:		LDLIBS += -pthread
different_creds:	LDLIBS += -pthread
sigpending:		LDLIBS += -pthread
sigaltstack:		LDLIBS += -pthread
seccomp_filter_tsync:	LDLIBS += -pthread
shm:			CFLAGS += -DNEW_IPC_NS
msgque:			CFLAGS += -DNEW_IPC_NS
sem:			CFLAGS += -DNEW_IPC_NS
posix_timers:		LDLIBS += -lrt -pthread
remap_dead_pid_root:	CFLAGS += -DREMAP_PID_ROOT
socket-tcp6:		CFLAGS += -D ZDTM_IPV6
socket-tcp4v6:		CFLAGS += -D ZDTM_IPV4V6
socket-tcpbuf6:		CFLAGS += -D ZDTM_IPV6
socket-tcpbuf-local:	CFLAGS += -D ZDTM_TCP_LOCAL
socket-tcpbuf6-local:	CFLAGS += -D ZDTM_TCP_LOCAL -D ZDTM_IPV6
socket-tcp6-local:	CFLAGS += -D ZDTM_TCP_LOCAL -D ZDTM_IPV6
socket-tcp4v6-local:	CFLAGS += -D ZDTM_TCP_LOCAL -D ZDTM_IPV4V6
socket-tcp-local:	CFLAGS += -D ZDTM_TCP_LOCAL
socket-tcp-nfconntrack: CFLAGS += -D ZDTM_TCP_LOCAL -DZDTM_CONNTRACK
socket_listen6:		CFLAGS += -D ZDTM_IPV6
socket_listen4v6:	CFLAGS += -D ZDTM_IPV4V6
socket-tcp6-closed:	CFLAGS += -D ZDTM_IPV6
socket-tcp6-closed:	CFLAGS += -D ZDTM_IPV4V6
socket-tcp-closed-last-ack:	CFLAGS += -D ZDTM_TCP_LAST_ACK
mnt_ext_manual:		CFLAGS += -D ZDTM_EXTMAP_MANUAL
sigpending:		LDLIBS += -lrt
vdso01:			LDLIBS += -lrt
scm01:			CFLAGS += -DKEEP_SENT_FD
scm02:			CFLAGS += -DSEND_BOTH
scm04:			CFLAGS += -DSEPARATE
mntns_link_remap:	CFLAGS += -DZDTM_LINK_REMAP
mntns_shared_bind02:	CFLAGS += -DSHARED_BIND02
mntns_root_bind02:	CFLAGS += -DROOT_BIND02
maps02: get_smaps_bits.o
mlock_setuid: get_smaps_bits.o
inotify01:		CFLAGS += -DINOTIFY01
unlink_fstat01+:	CFLAGS += -DUNLINK_OVER
unlink_fstat04:		CFLAGS += -DUNLINK_FSTAT04
ghost_holes01:		CFLAGS += -DTAIL_HOLE
ghost_holes02:		CFLAGS += -DHEAD_HOLE
sk-freebind-false:	CFLAGS += -DZDTM_FREEBIND_FALSE
stopped01:		CFLAGS += -DZDTM_STOPPED_KILL
stopped02:		CFLAGS += -DZDTM_STOPPED_TKILL
stopped12:		CFLAGS += -DZDTM_STOPPED_KILL -DZDTM_STOPPED_TKILL
clone_fs:		LDLIBS += -pthread
# As generating dependencies won't work without proper includes,
# we have to explicitly specify both .o and .d for this case:
netns_sub_veth.o netns_sub_veth.d:	CPPFLAGS += -I/usr/include/libnl3
netns_sub_veth:		LDLIBS += -lnl-3 -l nl-route-3

socket-tcp-fin-wait1:	CFLAGS += -D ZDTM_TCP_FIN_WAIT1
socket-tcp-fin-wait2:	CFLAGS += -D ZDTM_TCP_FIN_WAIT2
socket-tcp6-fin-wait1:	CFLAGS += -D ZDTM_TCP_FIN_WAIT1 -D ZDTM_IPV6
socket-tcp6-fin-wait2:	CFLAGS += -D ZDTM_TCP_FIN_WAIT2 -D ZDTM_IPV6
socket-tcp4v6-fin-wait1:	CFLAGS += -D ZDTM_TCP_FIN_WAIT1 -D ZDTM_IPV4V6
socket-tcp4v6-fin-wait2:	CFLAGS += -D ZDTM_TCP_FIN_WAIT2 -D ZDTM_IPV4V6
socket-tcp-close-wait:	CFLAGS += -D ZDTM_TCP_CLOSE_WAIT
socket-tcp6-close-wait:	CFLAGS += -D ZDTM_TCP_CLOSE_WAIT -D ZDTM_IPV6
socket-tcp4v6-close-wait:	CFLAGS += -D ZDTM_TCP_CLOSE_WAIT -D ZDTM_IPV4V6
socket-tcp-last-ack:	CFLAGS += -D ZDTM_TCP_LAST_ACK
socket-tcp6-last-ack:	CFLAGS += -D ZDTM_TCP_LAST_ACK -D ZDTM_IPV6
socket-tcp6-closing:	CFLAGS += -D ZDTM_IPV6
socket-tcp6-unconn:	CFLAGS += -D ZDTM_IPV6
socket-tcp4v6-last-ack:	CFLAGS += -D ZDTM_TCP_LAST_ACK -D ZDTM_IPV4V6
socket-tcp4v6-closing:	CFLAGS += -D ZDTM_IPV4V6

pty-console:		CFLAGS += -D ZDTM_DEV_CONSOLE

shm-unaligned:		CFLAGS += -DZDTM_SHM_UNALIGNED

s390x_regs_check:	LDFLAGS += -pthread
s390x_gs_threads:	LDFLAGS += -pthread

thread_different_uid_gid:	LDLIBS += -pthread -lcap

$(LIB):	force
	$(Q) $(MAKE) -C $(LIBDIR)

clean-more:
	$(RM) criu-rtc.so criu-rtc.pb-c.c criu-rtc.pb-c.h
.PHONY: clean-more
clean: clean-more

rtc.c: criu-rtc.so

criu-rtc.pb-c.c: criu-rtc.proto
	$(Q)echo $@ >> .gitignore
	$(Q)echo $(@:%.c=%.h) >> .gitignore
	$(E) " PBCC     " $@
	$(Q)protoc-c --proto_path=. --c_out=. criu-rtc.proto

criu-rtc.so: criu-rtc.c criu-rtc.pb-c.c
	$(E) " LD       " $@
	$(Q)$(CC) -g -Wall -shared -nostartfiles criu-rtc.c criu-rtc.pb-c.c -o criu-rtc.so -iquote ../../../criu/include -fPIC $(filter-out -m32,$(USERCFLAGS))

.PHONY:	force start check_start stop wait_stop
