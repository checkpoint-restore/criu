LIBDIR	:= ../lib
LIB	:= $(LIBDIR)/libzdtmtst.a
LDLIBS	+= $(LIB)
CPPFLAGS += -I$(LIBDIR)

TST_NOFILE	:=				\
		busyloop00			\
		sleeping00			\
		pid00				\
		caps00				\
		caps01				\
		wait00				\
		zombie00			\
		zombie01			\
		fpu00				\
		fpu01				\
		fpu02				\
		fpu03				\
		arm-neon00			\
		futex				\
		futex-rl			\
		mmx00				\
		sse00				\
		sse20				\
		mprotect00			\
		timers				\
		timers01			\
		timerfd				\
		unbound_sock			\
		sched_prio00			\
		sched_policy00			\
		socket_listen			\
		socket_listen6			\
		socket_listen4v6		\
		socket_udp			\
		socket_udp-broadcast		\
		socket_udp-corked		\
		socket6_udp			\
		socket_udp_shutdown		\
		socket_icmp			\
		socket6_icmp			\
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
		sock_filter00			\
		sock_filter01			\
		msgque				\
		inotify_system			\
		inotify_system_nodel		\
		shm				\
		shm-mp				\
		ptrace_sig			\
		pidfd_self			\
		pidfd_of_thread			\
		pidfd_dead			\
		pidfd_diffdead			\
		pidfd_child			\
		pidfd_kill			\
		fd_from_pidfd			\
		pipe00				\
		pipe01				\
		pipe02				\
		pthread00			\
		pthread00-pac			\
		pthread01			\
		pthread02			\
		pthread_timers			\
		pthread_timers_h		\
		rseq00				\
		membarrier			\
		vdso00				\
		vdso01				\
		vdso02				\
		vdso-proxy			\
		utsname				\
		pstree				\
		sockets01			\
		sockets01-seqpacket		\
		sockets02			\
		sockets02-seqpacket		\
		sockets_spair			\
		sockets_spair_seqpacket		\
		socket_queues			\
		socket_queues_seqpacket		\
		socket-raw			\
		socket-tcp			\
		socket-tcp-listen		\
		socket-tcp-reseted		\
		socket-tcp6			\
		socket-tcp4v6			\
		socket-tcp-local		\
		socket-tcp-reuseport		\
		socket-tcp-ipt-nfconntrack	\
		socket-tcp-nft-nfconntrack	\
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
		socket-tcp-close2		\
		socket-dump-tcp-close 		\
		socket-tcp-unconn		\
		socket-tcp6-unconn		\
		socket-tcp-syn-sent		\
		socket-tcp-skip-in-flight	\
		socket-tcp-keepalive		\
		socket-linger			\
		sock_opts00			\
		sock_opts01			\
		sock_opts02			\
		sock_ip_opts00			\
		sock_ip_opts01			\
		sock_tcp_opts00			\
		sock_tcp_opts01			\
		sk-unix-unconn			\
		sk-unix-unconn-seqpacket	\
		ipc_namespace			\
		selfexe00			\
		sem				\
		maps01				\
		maps02				\
		maps04				\
		maps05				\
		maps09				\
		maps10				\
		maps11				\
		mlock_setuid			\
		xids00				\
		groups				\
		pdeath_sig			\
		file_fown			\
		file_cloexec			\
		proc-self			\
		eventfs00			\
		epoll				\
		epoll01				\
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
		tun_ns				\
		stopped				\
		stopped01			\
		stopped02			\
		stopped12			\
		stopped03			\
		stopped04			\
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
		scm03-seqpacket			\
		scm04				\
		scm05				\
		scm06				\
		scm09				\
		aio00				\
		aio01				\
		fd				\
		fd01				\
		apparmor				\
		apparmor_stacking				\
		seccomp_strict			\
		seccomp_filter			\
		seccomp_filter_tsync			\
		seccomp_filter_threads			\
		seccomp_filter_inheritance		\
		seccomp_no_new_privs		\
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
		cr_veth02			\
		sock_peercred			\
		s390x_mmap_high			\
		uffd-events			\
		thread_different_uid_gid	\
		pipe03				\
		netns_lock_iptables			\
		netns_lock_nftables			\
		net_lock_socket_iptables		\
		net_lock_socket_iptables6		\
		net_lock_socket_nftables		\
		net_lock_socket_nftables6		\
		netns_sub			\
		netns_sub_veth			\
		netns_sub_sysctl	\
		unlink_multiple_largefiles	\
		thp_disable			\
		pid_file			\
		selinux00			\
		selinux01			\
		selinux02			\
		child_subreaper			\
		child_subreaper_existing_child	\
		child_subreaper_and_reparent	\
		memfd00				\
		memfd01				\
		memfd02				\
		memfd02-hugetlb			\
		memfd03				\
		memfd04				\
		memfd05				\
		shmemfd				\
		shmemfd-priv			\
		time				\
		timens_nested			\
		timens_for_kids			\
		zombie_leader			\
		sigtrap				\
		sigtrap01			\
		change_mnt_context		\
		fd_offset			\
#		jobctl00			\

PKG_CONFIG ?= pkg-config
pkg-config-check = $(shell sh -c '$(PKG_CONFIG) $(1) && echo y')
ifeq ($(call pkg-config-check,libbpf),y)
TST_NOFILE	+=				\
		bpf_hash			\
		bpf_array
endif

ifneq ($(ARCH),arm)
ifneq ($(COMPAT_TEST),y)
        TST_NOFILE += maps03
endif
endif

ifeq ($(ARCH),s390)
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
		sk-unix-rel-seqpacket		\
		deleted_dev			\
		unlink_fstat00			\
		unlink_fstat01			\
		unlink_fstat01+			\
		unlink_fstat02			\
		unlink_fstat03			\
		ghost_holes00			\
		ghost_holes01			\
		ghost_holes02			\
		ghost_holes_large00     \
		ghost_holes_large01     \
		ghost_multi_hole00      \
		ghost_multi_hole01      \
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
		sockets00-seqpacket		\
		sockets03			\
		sockets03-seqpacket		\
		sockets_dgram			\
		file_lease00			\
		file_lease01			\
		file_lease02			\
		file_lease03			\
		file_lease04			\
		file_locks00			\
		file_locks00_fail		\
		file_locks01			\
		file_locks02			\
		file_locks03			\
		file_locks04			\
		file_locks05			\
		file_locks06			\
		file_locks07			\
		file_locks08			\
		netns-nf			\
		netns-nft			\
		netns-nft-ipt			\
		maps_file_prot			\
		socket_close_data01		\
		fifo_upon_unix_socket00		\
		fifo_upon_unix_socket01		\
		sk-unix-listen01		\
		sk-unix-listen02		\
		sk-unix-listen03		\
		sk-unix-listen04		\
		mnt_ext_file_bind_auto		\

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
		inotify04			\
		cgroup00			\
		rmdir_open			\
		cgroup01			\
		cgroup02			\
		cgroup03			\
		cgroup04			\
		cgroupv2_00			\
		cgroupv2_01			\
		cgroup_ifpriomap		\
		cgroup_ignore			\
		cgroup_stray			\
		cgroup_yard			\
		cgroup_threads			\
		unlink_fstat04			\
		unlink_fstat041			\
		mntns_remap			\
		mntns_open			\
		mntns_link_remap		\
		mntns_ghost			\
		mntns_ghost01			\
		mntns_ro_root			\
		mnt_ro_root			\
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
		mnt_ext_root			\
		mnt_root_ext			\
		mnt_ext_collision		\
		mntns_pivot_root		\
		mntns_pivot_root_ro		\
		mnt_ext_sharing			\
		mnt_ext_multiple		\
		mount_complex_sharing		\
		mnt_tracefs			\
		mntns_deleted			\
		unlink_regular00		\
		mnt_enablefs			\
		autofs				\
		del_standalone_un		\
		del_standalone_un_seqpacket	\
		sk-unix-mntns			\
		sk-unix01			\
		sk-unix01-seqpacket		\
		sk-unix-dgram-ghost		\
		unsupported_children_collision  \
		shared_slave_mount_children	\
		non_uniform_share_propagation	\
		private_bind_propagation	\
		ghost_on_rofs			\
		overmounted_file		\
		opath_file			\
		symlink				\
		symlink01			\
		unbindable			\

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
		shm-hugetlb			\

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

include ../Makefile.inc

ifeq ($(ARCH),aarch64)
	PAC_CFLAGS := -mbranch-protection=standard
else
	PAC_CFLAGS :=
endif

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

shm-hugetlb.pid: shm-hugetlb
	$(<D)/$(<F) --pidfile=$@ --outfile=$<.out --shmem_size=4194304

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
fpu03:			CFLAGS += -pthread -D ZDTM_FPU00_RUN_IN_THREAD
fpu03:			LDFLAGS += -pthread
futex:			CFLAGS += -pthread
futex:			LDFLAGS += -pthread
futex-rl:		CFLAGS += -pthread
futex-rl:		LDFLAGS += -pthread
jobctl00:		LDLIBS += -lutil
socket_listen:		LDLIBS += -lrt -pthread
socket_aio:		LDLIBS += -lrt -pthread
uptime_grow:		LDLIBS += -lrt -pthread
unlink_largefile:	CFLAGS += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE
inotify_system_nodel:	CFLAGS += -DNO_DEL
pthread00:		LDLIBS += -pthread
pthread00-pac:		CFLAGS += ${PAC_CFLAGS}
pthread00-pac:		LDLIBS += -pthread
pthread01:		LDLIBS += -pthread
pthread02:		LDLIBS += -pthread
pthread_timers:		LDLIBS += -lrt -pthread
pthread_timers_h:	LDLIBS += -lrt -pthread
different_creds:	LDLIBS += -pthread
sigpending:		LDLIBS += -pthread
sigaltstack:		LDLIBS += -pthread
seccomp_filter_tsync:	LDLIBS += -pthread
seccomp_filter_threads:	LDLIBS += -pthread
shm:			CFLAGS += -DNEW_IPC_NS
msgque:			CFLAGS += -DNEW_IPC_NS
sem:			CFLAGS += -DNEW_IPC_NS
posix_timers:		LDLIBS += -lrt -pthread
remap_dead_pid_root:	CFLAGS += -DREMAP_PID_ROOT
sock_filter01:		CFLAGS += -DSOCK_FILTER01
socket-tcp6:		CFLAGS += -D ZDTM_IPV6
socket-tcp4v6:		CFLAGS += -D ZDTM_IPV4V6
socket-tcpbuf6:		CFLAGS += -D ZDTM_IPV6
socket-tcpbuf-local:	CFLAGS += -D ZDTM_TCP_LOCAL
socket-tcpbuf6-local:	CFLAGS += -D ZDTM_TCP_LOCAL -D ZDTM_IPV6
socket-tcp6-local:	CFLAGS += -D ZDTM_TCP_LOCAL -D ZDTM_IPV6
socket-tcp4v6-local:	CFLAGS += -D ZDTM_TCP_LOCAL -D ZDTM_IPV4V6
socket-tcp-local:	CFLAGS += -D ZDTM_TCP_LOCAL
socket-tcp-ipt-nfconntrack: CFLAGS += -D ZDTM_TCP_LOCAL -DZDTM_IPT_CONNTRACK
socket-tcp-nft-nfconntrack: CFLAGS += -D ZDTM_TCP_LOCAL -DZDTM_NFT_CONNTRACK
socket_listen6:		CFLAGS += -D ZDTM_IPV6
socket_listen4v6:	CFLAGS += -D ZDTM_IPV4V6
socket-tcp6-closed:	CFLAGS += -D ZDTM_IPV6
socket-tcp6-closed:	CFLAGS += -D ZDTM_IPV4V6
socket-tcp-closed-last-ack:	CFLAGS += -D ZDTM_TCP_LAST_ACK
socket-tcp-skip-in-flight:	CFLAGS += -D ZDTM_IPV4V6
socket6-icmp:		CFLAGS += -DZDTM_IPV6
sock_ip_opts01:		CFLAGS += -DZDTM_VAL_ZERO
sock_tcp_opts01:	CFLAGS += -DZDTM_VAL_ZERO
tun_ns:			CFLAGS += -DTUN_NS
mnt_ext_manual:		CFLAGS += -D ZDTM_EXTMAP_MANUAL
mntns_pivot_root_ro:	CFLAGS += -DMNTNS_PIVOT_ROOT_RO
sigpending:		LDLIBS += -lrt
vdso01:			LDLIBS += -lrt
scm01:			CFLAGS += -DKEEP_SENT_FD
scm02:			CFLAGS += -DSEND_BOTH
scm04:			CFLAGS += -DSEPARATE
scm09:			CFLAGS += -DCLOSE_SENDER_FD
mntns_link_remap:	CFLAGS += -DZDTM_LINK_REMAP
mntns_shared_bind02:	CFLAGS += -DSHARED_BIND02
mntns_root_bind02:	CFLAGS += -DROOT_BIND02
maps02: get_smaps_bits.o
mlock_setuid: get_smaps_bits.o
thp_disable: get_smaps_bits.o
inotify01:		CFLAGS += -DINOTIFY01
unlink_fstat01+:	CFLAGS += -DUNLINK_OVER
unlink_fstat04:		CFLAGS += -DUNLINK_FSTAT04
unlink_fstat041:		CFLAGS += -DUNLINK_FSTAT041 -DUNLINK_FSTAT04
ghost_holes01:		CFLAGS += -DTAIL_HOLE
ghost_holes02:		CFLAGS += -DHEAD_HOLE
ghost_holes_large01:		CFLAGS += -DLIMIT
sk-freebind-false:	CFLAGS += -DZDTM_FREEBIND_FALSE
selinux02:		CFLAGS += -DUSING_SOCKCREATE
stopped01:		CFLAGS += -DZDTM_STOPPED_KILL
stopped02:		CFLAGS += -DZDTM_STOPPED_TKILL
stopped12:		CFLAGS += -DZDTM_STOPPED_KILL -DZDTM_STOPPED_TKILL
clone_fs:		LDLIBS += -pthread
# As generating dependencies won't work without proper includes,
# we have to explicitly specify both .o and .d for this case:
netns_sub_veth.o netns_sub_veth.d: CPPFLAGS += $(call pkg-cflags, libnl-3.0)
netns_sub_veth:		LDLIBS += $(call pkg-libs, libnl-route-3.0 libnl-3.0)
net_lock_socket_iptables6:	CFLAGS += -D ZDTM_IPV6
net_lock_socket_nftables6:	CFLAGS += -D ZDTM_IPV6
symlink01:		CFLAGS += -DZDTM_UNLINK_SYMLINK

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
memfd02-hugetlb:	CFLAGS += -D ZDTM_HUGETLB
memfd05:		CFLAGS += -D ZDTM_MEMFD05

sockets00-seqpacket:	CFLAGS += -D ZDTM_UNIX_SEQPACKET
sockets01-seqpacket:	CFLAGS += -D ZDTM_UNIX_SEQPACKET
sockets02-seqpacket:	CFLAGS += -D ZDTM_UNIX_SEQPACKET
sockets03-seqpacket:	CFLAGS += -D ZDTM_UNIX_SEQPACKET
sk-unix01-seqpacket:	CFLAGS += -D ZDTM_UNIX_SEQPACKET
sk-unix-rel-seqpacket:	CFLAGS += -D ZDTM_UNIX_SEQPACKET
sockets_spair_seqpacket:	CFLAGS += -D ZDTM_UNIX_SEQPACKET
socket_queues_seqpacket:	CFLAGS += -D ZDTM_UNIX_SEQPACKET
del_standalone_un_seqpacket:	CFLAGS += -D ZDTM_UNIX_SEQPACKET
sk-unix-unconn-seqpacket:	CFLAGS += -D ZDTM_UNIX_SEQPACKET
scm03-seqpacket:	CFLAGS += -D ZDTM_UNIX_SEQPACKET

pty-console:		CFLAGS += -D ZDTM_DEV_CONSOLE

shm-unaligned:		CFLAGS += -DZDTM_SHM_UNALIGNED
shm-hugetlb:		CFLAGS += -DZDTM_HUGETLB

s390x_regs_check:	LDFLAGS += -pthread
s390x_gs_threads:	LDFLAGS += -pthread

thread_different_uid_gid:	LDLIBS += -pthread -lcap

cgroup_threads:		LDFLAGS += -pthread

bpf_hash:		LDLIBS += -lbpf
bpf_array:		LDLIBS += -lbpf

fifo_upon_unix_socket01:	CFLAGS += -DFIFO_UPON_UNIX01

sk-unix-listen02: CFLAGS += -DSK_UNIX_LISTEN02
sk-unix-listen03: CFLAGS += -DSK_UNIX_LISTEN03
sk-unix-listen04: CFLAGS += -DSK_UNIX_LISTEN02 -DSK_UNIX_LISTEN03

cgroupv2_01:		LDLIBS += -pthread

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
	$(Q)protoc --proto_path=. --c_out=. criu-rtc.proto

criu-rtc.so: criu-rtc.c criu-rtc.pb-c.c
	$(E) " LD       " $@
	$(Q)$(CC) -g -Wall -shared -nostartfiles criu-rtc.c criu-rtc.pb-c.c -o criu-rtc.so -iquote ../../../criu/include -fPIC $(filter-out -m32,$(USERCFLAGS))

.PHONY:	force start check_start stop wait_stop
