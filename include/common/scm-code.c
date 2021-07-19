#ifndef __sys
#error "The __sys macro is required"
#endif

static void scm_fdset_init_chunk(struct scm_fdset *fdset, int nr_fds, void *data, unsigned ch_size)
{
	struct cmsghdr *cmsg;
	static char dummy;

	fdset->hdr.msg_controllen = CMSG_LEN(sizeof(int) * nr_fds);

	cmsg = CMSG_FIRSTHDR(&fdset->hdr);
	cmsg->cmsg_len = fdset->hdr.msg_controllen;

	if (data) {
		fdset->iov.iov_base = data;
		fdset->iov.iov_len = nr_fds * ch_size;
	} else {
		fdset->iov.iov_base = &dummy;
		fdset->iov.iov_len = 1;
	}
}

static int *scm_fdset_init(struct scm_fdset *fdset, struct sockaddr_un *saddr, int saddr_len)
{
	struct cmsghdr *cmsg;

	BUILD_BUG_ON(sizeof(fdset->msg_buf) < (CMSG_SPACE(sizeof(int) * CR_SCM_MAX_FD)));

	fdset->iov.iov_base = (void *)0xdeadbeef;

	fdset->hdr.msg_iov = &fdset->iov;
	fdset->hdr.msg_iovlen = 1;
	fdset->hdr.msg_name = (struct sockaddr *)saddr;
	fdset->hdr.msg_namelen = saddr_len;

	fdset->hdr.msg_control = &fdset->msg_buf;
	fdset->hdr.msg_controllen = CMSG_LEN(sizeof(int) * CR_SCM_MAX_FD);

	cmsg = CMSG_FIRSTHDR(&fdset->hdr);
	cmsg->cmsg_len = fdset->hdr.msg_controllen;
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;

	return (int *)CMSG_DATA(cmsg);
}

int send_fds(int sock, struct sockaddr_un *saddr, int len, int *fds, int nr_fds, void *data, unsigned ch_size)
{
	/* In musl_libc the msghdr structure has pads which has to be zeroed */
	struct scm_fdset fdset = {};
	int *cmsg_data;
	int i, min_fd, ret;

	cmsg_data = scm_fdset_init(&fdset, saddr, len);
	for (i = 0; i < nr_fds; i += min_fd) {
		min_fd = min(CR_SCM_MAX_FD, nr_fds - i);
		scm_fdset_init_chunk(&fdset, min_fd, data, ch_size);
		memcpy(cmsg_data, &fds[i], sizeof(int) * min_fd);

		ret = __sys(sendmsg)(sock, &fdset.hdr, 0);
		if (ret <= 0)
			return ret ?: -1;

		if (data)
			data += min_fd * ch_size;
	}

	return 0;
}

int __recv_fds(int sock, int *fds, int nr_fds, void *data, unsigned ch_size, int flags)
{
	/* In musl_libc the msghdr structure has pads which has to be zeroed */
	struct scm_fdset fdset = {};
	struct cmsghdr *cmsg;
	int *cmsg_data;
	int ret;
	int i, min_fd;

	cmsg_data = scm_fdset_init(&fdset, NULL, 0);
	for (i = 0; i < nr_fds; i += min_fd) {
		min_fd = min(CR_SCM_MAX_FD, nr_fds - i);
		scm_fdset_init_chunk(&fdset, min_fd, data, ch_size);

		ret = __sys(recvmsg)(sock, &fdset.hdr, flags);
		if (ret <= 0)
			return ret ? __sys_err(ret) : -ENOMSG;

		cmsg = CMSG_FIRSTHDR(&fdset.hdr);
		if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS)
			return -EINVAL;
		if (fdset.hdr.msg_flags & MSG_CTRUNC)
			return -ENFILE;

		min_fd = (cmsg->cmsg_len - sizeof(struct cmsghdr)) / sizeof(int);
		/*
		 * In case if kernel screwed the recipient, most probably
		 * the caller stack frame will be overwriten, just scream
		 * and exit.
		 *
		 * FIXME Need to sanitize util.h to be able to include it
		 * into files which do not have glibc and a couple of
		 * sys_write_ helpers. Meawhile opencoded BUG_ON here.
		 */
		BUG_ON(min_fd > CR_SCM_MAX_FD);

		if (unlikely(min_fd <= 0))
			return -EBADFD;

		memcpy(&fds[i], cmsg_data, sizeof(int) * min_fd);
		if (data)
			data += ch_size * min_fd;
	}

	return 0;
}
