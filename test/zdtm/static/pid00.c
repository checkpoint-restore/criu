#define _GNU_SOURCE
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that p?pid and e?[ug]id didn't change";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

int setfsuid(uid_t fsuid);
int setfsgid(uid_t fsgid);

int main(int argc, char **argv)
{
	int pid, s_p[2], f_p[2], r_p[3];
	const __uid_t w_ruid = 1, w_euid = 2, w_suid = 3, w_fsuid = w_euid;
	const __uid_t w_rgid = 5, w_egid = 6, w_sgid = 7, w_fsgid = 8;
	__uid_t rid, eid, sid, fsid;
	char res = 'x';

	test_init(argc, argv);

	pipe(s_p);
	pipe(f_p);
	pipe(r_p);

	pid = fork();
	if (pid == 0) {
		close(s_p[0]);
		close(f_p[1]);
		close(r_p[0]);

		setresgid(w_rgid, w_egid, w_sgid);
		setfsgid(w_fsgid);
		setresuid(w_ruid, w_euid, w_suid);
		/* fsuid change is impossible after above */

		close(s_p[1]);

		read(f_p[0], &res, 1);
		close(f_p[0]);

#define CHECK_ID(__t, __w, __e)	do {			\
		if (__t##id != w_##__t##__w##id) {	\
			res = __e;			\
			goto bad;			\
		}					\
	} while (0)

		rid = eid = sid = fsid = 0;
		getresuid(&rid, &eid, &sid);
		fsid = setfsuid(w_euid);
		CHECK_ID(r, u, '1');
		CHECK_ID(e, u, '2');
		CHECK_ID(s, u, '3');
		CHECK_ID(s, u, '3');
		CHECK_ID(fs, u, '4');

		rid = eid = sid = fsid = 0;
		getresgid(&rid, &eid, &sid);
		fsid = setfsgid(w_fsgid);
		CHECK_ID(r, g, '5');
		CHECK_ID(e, g, '6');
		CHECK_ID(s, g, '7');
		CHECK_ID(fs, g, '8');

		res = '0';
bad:
		write(r_p[1], &res, 1);
		close(r_p[1]);
		_exit(0);
	}

	close(f_p[0]);
	close(s_p[1]);
	close(r_p[1]);

	read(s_p[0], &res, 1);
	close(s_p[0]);

	test_daemon();
	test_waitsig();

	close(f_p[1]);

	read(r_p[0], &res, 1);
	if (res == '0')
		pass();
	else
		fail("Fail: %c", res);

	return 0;
}
