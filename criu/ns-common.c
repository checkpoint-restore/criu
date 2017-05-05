#include <sys/socket.h>
#include <sys/un.h>

void pid_ns_helper_socket_name(struct sockaddr_un *addr, socklen_t *len, unsigned int id)
{
	const char prefix[] = "0/criu-pid-ns-";
	const char int_max[] = "2147483647";

	*len = sizeof(*addr) - sizeof(addr->sun_path) +
	       sizeof(prefix) - 1 + sizeof(int_max) - 1;

	addr->sun_family = AF_UNIX;

	memset(addr->sun_path + sizeof(prefix) - 1, '\0', sizeof(int_max) - 1);
#ifdef CR_NOGLIBC
	std_sprintf(addr->sun_path, "%s%d", prefix, id);
#else
	sprintf(addr->sun_path, "%s%d", prefix, id);
#endif
	addr->sun_path[0] = '\0';
}

/* Send helper a request to set next pid and receive success */
int request_set_next_pid(int pid_ns_id, pid_t pid, int sk)
{
	struct sockaddr_un addr;
	int answer, ret;
	socklen_t len;

	BUG_ON(pid == -1);

	pid_ns_helper_socket_name(&addr, &len, pid_ns_id);
	ret = __sys(sendto)(sk, &pid, sizeof(pid), 0, (struct sockaddr *)&addr, len);
	if (ret	< 0) {
		pr_err("Can't send request: err=%d\n", __sys_err(ret));
		return -1;
	}

	ret = __sys(recvfrom)(sk, &answer, sizeof(answer), 0, NULL, NULL);
	if (ret < 0) {
		pr_err("Can't recv answer: err=%d\n", __sys_err(ret));
		return -1;
	}

	if (answer != 0) {
		pr_err("Error answer\n");
		return -1;
	}

	return 0;
}
