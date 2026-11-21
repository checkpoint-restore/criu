#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#ifdef AMBIENT_SECUREBITS
#include <linux/securebits.h>
#endif

#include "zdtmtst.h"

#ifdef AMBIENT_SECUREBITS
const char *test_doc = "Preserve ambient capabilities with NO_CAP_AMBIENT_RAISE";
#else
const char *test_doc = "Check that CapAmb are preserved";
#endif
const char *test_author = "Liu Chao <liuchao173@huawei.com>";

struct cap_hdr {
	unsigned int version;
	int pid;
};

struct cap_data {
	unsigned int eff;
	unsigned int prm;
	unsigned int inh;
};

#define _LINUX_CAPABILITY_VERSION_3 0x20080522
#define _LINUX_CAPABILITY_U32S_3    2
#define CAP_DAC_OVERRIDE	    1
#define PR_CAP_AMBIENT		    47
#define PR_CAP_AMBIENT_IS_SET	    1
#define PR_CAP_AMBIENT_RAISE	    2
#define PR_CAP_AMBIENT_LOWER	    3

int capget(struct cap_hdr *hdrp, struct cap_data *datap);
int capset(struct cap_hdr *hdrp, const struct cap_data *datap);

static int cap_last_cap = 63;

int main(int argc, char **argv)
{
	task_waiter_t t;
	int pid, result_pipe[2];
	unsigned int amb[_LINUX_CAPABILITY_U32S_3];
	unsigned int amb_2[_LINUX_CAPABILITY_U32S_3] = { 0 };
	char res = 'x';
	FILE *f;

	test_init(argc, argv);
	task_waiter_init(&t);

	f = fopen("/proc/sys/kernel/cap_last_cap", "r");
	if (f) {
		if (fscanf(f, "%d", &cap_last_cap) != 1) {
			pr_perror("Unable to read cal_last_cap");
			fclose(f);
			return 1;
		}
		fclose(f);
	} else
		test_msg("/proc/sys/kernel/cap_last_cap is not available\n");

	if (pipe(result_pipe)) {
		pr_perror("Can't create pipe");
		return 1;
	}

	pid = test_fork();
	if (pid == 0) {
		int b, i, ret;
#ifdef AMBIENT_SECUREBITS
		int securebits;
		unsigned int bnd[_LINUX_CAPABILITY_U32S_3] = { 0 };
		struct cap_data saved[_LINUX_CAPABILITY_U32S_3], restored[_LINUX_CAPABILITY_U32S_3];
#endif
		struct cap_hdr hdr;
		struct cap_data data[_LINUX_CAPABILITY_U32S_3];

		hdr.version = _LINUX_CAPABILITY_VERSION_3;
		hdr.pid = 0;

		if (capget(&hdr, data) < 0) {
			pr_perror("capget");
			return -1;
		}

		hdr.version = _LINUX_CAPABILITY_VERSION_3;
		hdr.pid = 0;

		data[0].eff &= ~((1 << CAP_CHOWN) | (1 << CAP_DAC_OVERRIDE));
		data[0].prm &= ~(1 << CAP_DAC_OVERRIDE);
		data[0].inh = data[0].prm;
		data[1].inh = data[1].prm;

		if (capset(&hdr, data) < 0) {
			pr_perror("capset");
			return -1;
		}

		for (b = 0; b < _LINUX_CAPABILITY_U32S_3; b++) {
			amb[b] = data[b].prm;
			for (i = 0; i < 32; i++) {
				if (b * 32 + i > cap_last_cap)
					break;
				if ((amb[b] & (1 << i)) > 0)
					ret = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, i + b * 32, 0, 0);
				else
					ret = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, i + b * 32, 0, 0);
				if (ret) {
					pr_perror("Unable to set ambient capability %d to %d: %d", i + b * 32, amb[b] & (1 << i), ret);
					return -1;
				}
			}
		}

#ifdef AMBIENT_SECUREBITS
		securebits = prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
		if (securebits < 0) {
			pr_perror("Unable to read securebits");
			return -1;
		}
		securebits |= AMBIENT_SECUREBITS;
		if (prctl(PR_SET_SECUREBITS, securebits, 0, 0, 0)) {
			pr_perror("Unable to forbid ambient raises");
			return -1;
		}
#endif

#ifdef AMBIENT_SECUREBITS
		for (b = 0; b < _LINUX_CAPABILITY_U32S_3; b++) {
			saved[b] = data[b];
			for (i = 0; i < 32 && b * 32 + i <= cap_last_cap; i++) {
				ret = prctl(PR_CAPBSET_READ, b * 32 + i, 0, 0, 0);
				if (ret < 0) {
					pr_perror("Unable to read bounding set");
					return -1;
				}
				bnd[b] |= (unsigned int)ret << i;
			}
		}
#endif

		task_waiter_complete_current(&t);
		task_waiter_wait4(&t, getppid());

#ifdef AMBIENT_SECUREBITS
		if (capget(&hdr, restored) < 0) {
			pr_perror("Unable to read restored capabilities");
			goto bad;
		}
		for (b = 0; b < _LINUX_CAPABILITY_U32S_3; b++) {
			if (restored[b].prm != saved[b].prm || restored[b].eff != saved[b].eff ||
			    restored[b].inh != saved[b].inh) {
				fail("P/E/I capabilities changed after restore");
				goto bad;
			}
			for (i = 0; i < 32 && b * 32 + i <= cap_last_cap; i++) {
				ret = prctl(PR_CAPBSET_READ, b * 32 + i, 0, 0, 0);
				if (ret < 0 || (unsigned int)ret != ((bnd[b] >> i) & 1U)) {
					fail("Bounding set changed after restore");
					goto bad;
				}
			}
		}
		if (prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) != securebits) {
			fail("Securebits changed after restore");
			goto bad;
		}
		errno = 0;
		if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_CHOWN, 0, 0) != -1 || errno != EPERM) {
			fail("Ambient raises are not forbidden after restore");
			goto bad;
		}
#if AMBIENT_SECUREBITS & SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED
		errno = 0;
		if (prctl(PR_SET_SECUREBITS, securebits & ~SECBIT_NO_CAP_AMBIENT_RAISE, 0, 0, 0) != -1 ||
		    errno != EPERM) {
			fail("Ambient securebit lock was not preserved");
			goto bad;
		}
#else
		if (prctl(PR_SET_SECUREBITS, securebits & ~SECBIT_NO_CAP_AMBIENT_RAISE, 0, 0, 0)) {
			fail("Unlocked ambient securebit cannot be cleared");
			goto bad;
		}
#endif
#endif

		for (b = 0; b < _LINUX_CAPABILITY_U32S_3; b++) {
			amb_2[b] = 0;
			for (i = 0; i < 32; i++) {
				if (b * 32 + i > cap_last_cap)
					break;
				ret = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, i + b * 32, 0, 0);
				if (ret < 0) {
					pr_perror("Unable to read ambient capability %d: %d", i + b * 32, ret);
					goto bad;
				}

				amb_2[b] |= (ret << i);
			}
		}

		for (b = 0; b < _LINUX_CAPABILITY_U32S_3; b++) {
			if (amb[b] != amb_2[b]) {
				res = '1';
				goto bad;
			}
		}

		res = '0';
	bad:
		write(result_pipe[1], &res, 1);

		if (res != '0') {
			write(result_pipe[1], amb, sizeof(amb));
			write(result_pipe[1], amb_2, sizeof(amb_2));
		}

		close(result_pipe[0]);
		close(result_pipe[1]);
		_exit(0);
	}

	task_waiter_wait4(&t, pid);

	test_daemon();
	test_waitsig();

	task_waiter_complete_current(&t);

	read(result_pipe[0], &res, 1);

	if (res == '0')
		pass();
	else {
		read(result_pipe[0], amb, sizeof(amb));
		read(result_pipe[0], amb_2, sizeof(amb_2));
		test_msg("amb[]=%08x, %08x\n", amb[0], amb[1]);
		test_msg("amb[]=%08x, %08x\n", amb_2[0], amb_2[1]);
		fail("Fail: %c", res);
	}
	close(result_pipe[0]);
	close(result_pipe[1]);

	return 0;
}
