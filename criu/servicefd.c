#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>

#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/resource.h>

#include "common/compiler.h"
#include "common/list.h"

#include "util.h"
#include "bitops.h"
#include "pstree.h"
#include "files.h"
#include "rst_info.h"
#include "servicefd.h"

#undef LOG_PREFIX
#define LOG_PREFIX "sfd: "

/* Max potentially possible fd to be open by criu process */
int service_fd_rlim_cur;

/* Base of current process service fds set */
static int service_fd_base;

/* Id of current process in shared fdt */
static int service_fd_id = 0;

static DECLARE_BITMAP(sfd_map, SERVICE_FD_MAX);
static int sfd_arr[SERVICE_FD_MAX];
/*
 * Variable for marking areas of code, where service fds modifications
 * are prohibited. It's used to safe them from reusing their numbers
 * by ordinary files. See install_service_fd() and close_service_fd().
 */
bool sfds_protected = false;

const char *sfd_type_name(enum sfd_type type)
{
	static const char *names[] = {
		[SERVICE_FD_MIN] = __stringify_1(SERVICE_FD_MIN),
		[LOG_FD_OFF] = __stringify_1(LOG_FD_OFF),
		[IMG_FD_OFF] = __stringify_1(IMG_FD_OFF),
		[PROC_FD_OFF] = __stringify_1(PROC_FD_OFF),
		[PROC_PID_FD_OFF] = __stringify_1(PROC_PID_FD_OFF),
		[PROC_SELF_FD_OFF] = __stringify_1(PROC_SELF_FD_OFF),
		[CR_PROC_FD_OFF] = __stringify_1(CR_PROC_FD_OFF),
		[ROOT_FD_OFF] = __stringify_1(ROOT_FD_OFF),
		[CGROUP_YARD] = __stringify_1(CGROUP_YARD),
		[USERNSD_SK] = __stringify_1(USERNSD_SK),
		[NS_FD_OFF] = __stringify_1(NS_FD_OFF),
		[TRANSPORT_FD_OFF] = __stringify_1(TRANSPORT_FD_OFF),
		[RPC_SK_OFF] = __stringify_1(RPC_SK_OFF),
		[FDSTORE_SK_OFF] = __stringify_1(FDSTORE_SK_OFF),
		[SERVICE_FD_MAX] = __stringify_1(SERVICE_FD_MAX),
	};

	if (type < ARRAY_SIZE(names))
		return names[type];

	return "UNKNOWN";
}

int init_service_fd(void)
{
	struct rlimit64 rlimit;

	/*
	 * Service fd engine implies that file descriptors used won't be
	 * borrowed by the rest of the code and default 1024 limit is not
	 * enough for high loaded test/containers. Thus use kdat engine to
	 * fetch current system level limit for numbers of files allowed to
	 * open up and lift up own limits.
	 *
	 * Note we have to do it before the service fd get initialized and we
	 * don't exit with errors here because in worst scenario where clash of
	 * fd happen we simply exit with explicit error during real action
	 * stage.
	 */
	rlimit_unlimit_nofile();

	/*
	 * Service FDs are those that most likely won't
	 * conflict with any 'real-life' ones
	 */

	if (syscall(__NR_prlimit64, getpid(), RLIMIT_NOFILE, NULL, &rlimit)) {
		pr_perror("Can't get rlimit");
		return -1;
	}

	service_fd_rlim_cur = (int)rlimit.rlim_cur;
	return 0;
}

static int __get_service_fd(enum sfd_type type, int service_fd_id)
{
	return service_fd_base - type - SERVICE_FD_MAX * service_fd_id;
}

int get_service_fd(enum sfd_type type)
{
	BUG_ON((int)type <= SERVICE_FD_MIN || (int)type >= SERVICE_FD_MAX);

	if (!test_bit(type, sfd_map))
		return -1;

	if (service_fd_base == 0)
		return sfd_arr[type];

	return __get_service_fd(type, service_fd_id);
}

bool is_any_service_fd(int fd)
{
	int sfd_min_fd = __get_service_fd(SERVICE_FD_MAX, service_fd_id);
	int sfd_max_fd = __get_service_fd(SERVICE_FD_MIN, service_fd_id);

	if (fd > sfd_min_fd && fd < sfd_max_fd) {
		int type = SERVICE_FD_MAX - (fd - sfd_min_fd);
		if (type > SERVICE_FD_MIN && type < SERVICE_FD_MAX)
			return !!test_bit(type, sfd_map);
	}

	return false;
}

bool is_service_fd(int fd, enum sfd_type type)
{
	return fd == get_service_fd(type);
}

int service_fd_min_fd(struct pstree_item *item)
{
	struct fdt *fdt = rsti(item)->fdt;
	int id = 0;

	if (fdt)
		id = fdt->nr - 1;
	return service_fd_rlim_cur - (SERVICE_FD_MAX - 1) - SERVICE_FD_MAX * id;
}

static void sfds_protection_bug(enum sfd_type type)
{
	pr_err("Service fd %s is being modified in protected context\n", sfd_type_name(type));
	print_stack_trace(current ? vpid(current) : 0);
	BUG();
}

int install_service_fd(enum sfd_type type, int fd)
{
	int sfd = __get_service_fd(type, service_fd_id);
	int tmp;

	BUG_ON((int)type <= SERVICE_FD_MIN || (int)type >= SERVICE_FD_MAX);
	if (sfds_protected && !test_bit(type, sfd_map))
		sfds_protection_bug(type);

	if (service_fd_base == 0) {
		if (test_bit(type, sfd_map))
			close(sfd_arr[type]);
		sfd_arr[type] = fd;
		set_bit(type, sfd_map);
		return fd;
	}

	if (!test_bit(type, sfd_map))
		tmp = fcntl(fd, F_DUPFD, sfd);
	else
		tmp = dup3(fd, sfd, O_CLOEXEC);
	if (tmp < 0) {
		pr_perror("%s dup %d -> %d failed", sfd_type_name(type), fd, sfd);
		close(fd);
		return -1;
	} else if (tmp != sfd) {
		pr_err("%s busy target %d -> %d\n", sfd_type_name(type), fd, sfd);
		close(tmp);
		close(fd);
		return -1;
	}

	set_bit(type, sfd_map);
	close(fd);
	return sfd;
}

int close_service_fd(enum sfd_type type)
{
	int fd;

	if (sfds_protected)
		sfds_protection_bug(type);

	fd = get_service_fd(type);
	if (fd < 0)
		return 0;

	if (close_safe(&fd))
		return -1;

	clear_bit(type, sfd_map);
	return 0;
}

void __close_service_fd(enum sfd_type type)
{
	int fd;

	fd = __get_service_fd(type, service_fd_id);
	close(fd);
	clear_bit(type, sfd_map);
}

static int move_service_fd(struct pstree_item *me, int type, int new_id, int new_base)
{
	int old = get_service_fd(type);
	int new = new_base - type - SERVICE_FD_MAX *new_id;
	int ret;

	if (old < 0)
		return 0;

	if (!test_bit(type, sfd_map))
		ret = fcntl(old, F_DUPFD, new);
	else
		ret = dup2(old, new);
	if (ret == -1) {
		pr_perror("%s unable to clone %d->%d", sfd_type_name(type), old, new);
		return -1;
	} else if (ret != new) {
		pr_err("%s busy target %d -> %d\n", sfd_type_name(type), old, new);
		return -1;
	} else if (!(rsti(me)->clone_flags & CLONE_FILES))
		close(old);

	return 0;
}

static int choose_service_fd_base(struct pstree_item *me)
{
	int nr, real_nr, fdt_nr = 1, id = rsti(me)->service_fd_id;

	if (rsti(me)->fdt) {
		/* The base is set by owner of fdt (id 0) */
		if (id != 0)
			return service_fd_base;
		fdt_nr = rsti(me)->fdt->nr;
	}
	/* Now find process's max used fd number */
	if (!list_empty(&rsti(me)->fds))
		nr = list_entry(rsti(me)->fds.prev, struct fdinfo_list_entry, ps_list)->fe->fd;
	else
		nr = -1;

	nr = max(nr, inh_fd_max);
	/*
	 * Service fds go after max fd near right border of alignment:
	 *
	 * ...|max_fd|max_fd+1|...|sfd first|...|sfd last (aligned)|
	 *
	 * So, they take maximum numbers of area allocated by kernel.
	 * See linux alloc_fdtable() for details.
	 */
	nr += (SERVICE_FD_MAX - SERVICE_FD_MIN) * fdt_nr;
	nr += 16; /* Safety pad */
	real_nr = nr;

	nr /= (1024 / sizeof(void *));
	if (nr)
		nr = 1 << (32 - __builtin_clz(nr));
	else
		nr = 1;
	nr *= (1024 / sizeof(void *));

	if (nr > service_fd_rlim_cur) {
		/* Right border is bigger, than rlim. OK, then just aligned value is enough */
		nr = round_down(service_fd_rlim_cur, (1024 / sizeof(void *)));
		if (nr < real_nr) {
			pr_err("Can't chose service_fd_base: %d %d\n", nr, real_nr);
			return -1;
		}
	}

	return nr;
}

int clone_service_fd(struct pstree_item *me)
{
	int id, new_base, i, ret = -1;

	new_base = choose_service_fd_base(me);
	id = rsti(me)->service_fd_id;

	if (new_base == -1)
		return -1;

	if (get_service_fd(LOG_FD_OFF) == new_base - LOG_FD_OFF - SERVICE_FD_MAX * id)
		return 0;

	/* Dup sfds in memmove() style: they may overlap */
	if (get_service_fd(LOG_FD_OFF) < new_base - LOG_FD_OFF - SERVICE_FD_MAX * id)
		for (i = SERVICE_FD_MIN + 1; i < SERVICE_FD_MAX; i++)
			move_service_fd(me, i, id, new_base);
	else
		for (i = SERVICE_FD_MAX - 1; i > SERVICE_FD_MIN; i--)
			move_service_fd(me, i, id, new_base);

	service_fd_base = new_base;
	service_fd_id = id;
	ret = 0;

	return ret;
}
