#ifndef _VIMITESU_H_
#define _VIMITESU_H_

#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>

#define INPROGRESS ".inprogress"

#ifndef PAGE_SIZE
# define PAGE_SIZE (unsigned int)(sysconf(_SC_PAGESIZE))
#endif

#ifndef PR_SET_CHILD_SUBREAPER
# define PR_SET_CHILD_SUBREAPER 36
#endif

/* set up test */
extern void test_ext_init(int argc, char **argv);
extern void test_init(int argc, char **argv);

#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS 0x04000000
#endif

#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0x08000000
#endif

#define TEST_MSG_BUFFER_SIZE	2048
/*wrapper for fork: init log offset*/
#define test_fork() test_fork_id(-1)
extern int test_fork_id(int id);
/* finish setting up the test, write out pid file, and go to background */
extern void test_daemon(void);
/* store a message to a static buffer */
extern void test_msg(const char *format, ...)
	__attribute__ ((__format__ (__printf__, 1, 2)));
/* tell if SIGTERM hasn't been received yet */
extern int test_go(void);
/* sleep until SIGTERM is delivered */
extern void test_waitsig(void);

#include <stdint.h>

/* generate data with crc32 at the end of the buffer */
extern void datagen(uint8_t *buffer, unsigned length, uint32_t *crc);
/* generate data without crc32 at the end of the buffer */
extern void datagen2(uint8_t *buffer, unsigned length, uint32_t *crc);
/* check the data buffer against its crc32 */
extern int datachk(const uint8_t *buffer, unsigned length, uint32_t *crc);
/* calculate crc for the data buffer*/
extern int datasum(const uint8_t *buffer, unsigned length, uint32_t *crc);

/* streaming helpers */
extern int set_nonblock(int fd, int on);
extern int pipe_in2out(int infd, int outfd, uint8_t *buffer, int length);
extern int read_data(int fd, unsigned char *buf, int len);
extern int write_data(int fd, const unsigned char *buf, int len);

/* command line args */
struct long_opt {
	const char *name;
	const char *type;
	const char *doc;
	int is_required;

	int (*parse_opt)(char *arg, void *value);
	void *value;
	struct long_opt *next;
};

extern void __push_opt(struct long_opt *opt);

#define TEST_OPTION(name, type, doc, is_required)				\
	param_check_##type(name, &(name));					\
	static struct long_opt __long_opt_##name = {				\
		#name, #type, doc, is_required, parse_opt_##type, &name };	\
	static void __init_opt_##name(void) __attribute__ ((constructor));	\
	static void __init_opt_##name(void) \
	{ (void)__check_##name; __push_opt(&__long_opt_##name); }

#define __param_check(name, p, type) \
	static inline type *__check_##name(void) { return(p); }

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

extern void parseargs(int, char **);
extern int parse_opt_bool(char *param, void *arg);
#define param_check_bool(name, p) __param_check(name, p, int)
extern int parse_opt_int(char *param, void *arg);
#define param_check_int(name, p) __param_check(name, p, int)
extern int parse_opt_uint(char *param, void *arg);
#define param_check_uint(name, p) __param_check(name, p, unsigned int)
extern int parse_opt_long(char *param, void *arg);
#define param_check_long(name, p) __param_check(name, p, long)
extern int parse_opt_ulong(char *param, void *arg);
#define param_check_ulong(name, p) __param_check(name, p, unsigned long)
extern int parse_opt_string(char *param, void *arg);
#define param_check_string(name, p) __param_check(name, p, char *)

extern int write_pidfile(int pid);

#include <stdio.h>
#include <errno.h>
#include <string.h>

#define __stringify_1(x)        #x
#define __stringify(x)          __stringify_1(x)

/*
 * Macro to define stack alignment. 
 * aarch64 requires stack to be aligned to 16 bytes.
 */
#define __stack_aligned__	__attribute__((aligned(16)))

/* message helpers */
extern int test_log_init(const char *outfile, const char *suffix);
extern int zdtm_seccomp;
#define pr_err(format, arg...) \
	test_msg("ERR: %s:%d: " format, __FILE__, __LINE__, ## arg)
#define pr_perror(format, arg...)	\
	test_msg("ERR: %s:%d: " format " (errno = %d (%s))\n", \
		__FILE__, __LINE__, ## arg, errno, strerror(errno))
#define fail(format, arg...)	\
	test_msg("FAIL: %s:%d: " format " (errno = %d (%s))\n", \
		 __FILE__, __LINE__, ## arg, errno, strerror(errno))
#define skip(format, arg...)	\
	test_msg("SKIP: %s:%d: " format "\n", \
		 __FILE__, __LINE__, ## arg)
#define pass()	test_msg("PASS\n")

typedef struct {
	unsigned long	seed;
	int		pipes[2];
} task_waiter_t;

extern void task_waiter_init(task_waiter_t *t);
extern void task_waiter_fini(task_waiter_t *t);
extern void task_waiter_wait4(task_waiter_t *t, unsigned int lockid);
extern void task_waiter_complete(task_waiter_t *t, unsigned int lockid);
extern void task_waiter_complete_current(task_waiter_t *t);
extern int tcp_init_server(int family, int *port);
extern int tcp_accept_server(int sock);
extern int tcp_init_client(int family, char *servIP, unsigned short servPort);

struct zdtm_tcp_opts {
	bool reuseaddr;
	bool reuseport;
	int flags;
};

extern int tcp_init_server_with_opts(int family, int *port, struct zdtm_tcp_opts *opts);
extern pid_t sys_clone_unified(unsigned long flags, void *child_stack, void *parent_tid,
			       void *child_tid, unsigned long newtls);

#define ssprintf(s, fmt, ...) ({ 						\
	int ___ret;								\
										\
	___ret = snprintf(s, sizeof(s), fmt, ##__VA_ARGS__);			\
	if (___ret >= sizeof(s))						\
		abort();								\
	___ret;									\
})

#endif /* _VIMITESU_H_ */
