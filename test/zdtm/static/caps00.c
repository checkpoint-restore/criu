#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <linux/capability.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that aps are preserved";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

struct cap_hdr {
	unsigned int version;
	int pid;
};

struct cap_data {
	unsigned int	eff;
	unsigned int	prm;
	unsigned int	inh;
};

#define _LINUX_CAPABILITY_VERSION_3     0x20080522
#define _LINUX_CAPABILITY_U32S_3        2
#define CAP_CHOWN            0
#define CAP_DAC_OVERRIDE     1

int capget(struct cap_hdr *hdrp, struct cap_data *datap);
int capset(struct cap_hdr *hdrp, const struct cap_data *datap);

static int cap_last_cap = 63;
#define NORM_CAPS(v, cap) v[1].cap &= (1LL << (cap_last_cap + 1 - 32)) - 1;

int main(int argc, char **argv)
{
	task_waiter_t t;
	int pid, result_pipe[2];
	struct cap_data data[_LINUX_CAPABILITY_U32S_3];
	struct cap_data data_2[_LINUX_CAPABILITY_U32S_3];
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
		struct cap_hdr hdr;
		if (prctl(PR_CAPBSET_DROP, CAP_SETPCAP, 0, 0, 0)) {
			res = 'x';
			task_waiter_complete_current(&t);
			goto bad;
		}

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

		if (capset(&hdr, data) < 0) {
			pr_perror("capset");
			return -1;
		}

		task_waiter_complete_current(&t);
		task_waiter_wait4(&t, getppid());

		hdr.version = _LINUX_CAPABILITY_VERSION_3;
		hdr.pid = 0;

		if (capget(&hdr, data_2) < 0) {
			pr_perror("second capget");
			return -1;
		}

		NORM_CAPS(data, eff);
		NORM_CAPS(data, prm);
		NORM_CAPS(data, inh);
		NORM_CAPS(data_2, eff);
		NORM_CAPS(data_2, prm);
		NORM_CAPS(data_2, inh);

		if (data[0].eff != data_2[0].eff) {
			res = '1';
			goto bad;
		}
		if (data[1].eff != data_2[1].eff) {
			res = '2';
			goto bad;
		}
		if (data[0].prm != data_2[0].prm) {
			res = '3';
			goto bad;
		}
		if (data[1].prm != data_2[1].prm) {
			res = '4';
			goto bad;
		}
		if (data[0].inh != data_2[0].inh) {
			res = '3';
			goto bad;
		}
		if (data[1].inh != data_2[1].inh) {
			res = '4';
			goto bad;
		}

		if (prctl(PR_CAPBSET_READ, CAP_SETPCAP, 0, 0, 0) != 0) {
			res='5';
			goto bad;
		}

		res = '0';
bad:
		write(result_pipe[1], &res, 1);

		if (res != '0') {
			write(result_pipe[1], data, sizeof(data));
			write(result_pipe[1], data_2, sizeof(data_2));
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
		read(result_pipe[0], data, sizeof(data));
		read(result_pipe[0], data_2, sizeof(data_2));
		test_msg("{eff,prm,inh}[]={%08x,%08x,%08x}, {%08x,%08x,%08x}\n",
			  data[0].eff, data[0].prm, data[0].inh,
			  data[1].eff, data[1].prm, data[1].inh);
		test_msg("{eff,prm,inh}[]={%08x,%08x,%08x}, {%08x,%08x,%08x}\n",
			  data_2[0].eff, data_2[0].prm, data_2[0].inh,
			  data_2[1].eff, data_2[1].prm, data_2[1].inh);
		fail("Fail: %c", res);
	}
	close(result_pipe[0]);
	close(result_pipe[1]);

	return 0;
}
