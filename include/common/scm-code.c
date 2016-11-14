#ifndef __sys
#error "The __sys macro is required"
#endif

#ifndef __memcpy
#error "The __memcpy macro is required"
#endif

#ifdef SCM_FDSET_HAS_OPTS
#define OPTS_LEN(_flags, _nr)	(_flags ? sizeof(struct fd_opts) * (_nr) : 1)
#define OPTS_BUF(_fdset)	((_fdset)->opts)
#else
#define OPTS_LEN(_flags, _nr)	(1)
#define OPTS_BUF(_fdset)	(&(_fdset)->dummy)
#endif

static void scm_fdset_init_chunk(struct scm_fdset *fdset, int nr_fds, bool with_flags)
{
	struct cmsghdr *cmsg;

	fdset->hdr.msg_controllen = CMSG_LEN(sizeof(int) * nr_fds);

	cmsg		= CMSG_FIRSTHDR(&fdset->hdr);
	cmsg->cmsg_len	= fdset->hdr.msg_controllen;

	fdset->iov.iov_len = OPTS_LEN(with_flags, nr_fds);
}

static int *scm_fdset_init(struct scm_fdset *fdset, struct sockaddr_un *saddr,
		int saddr_len)
{
	struct cmsghdr *cmsg;

	BUILD_BUG_ON(sizeof(fdset->msg_buf) < (CMSG_SPACE(sizeof(int) * CR_SCM_MAX_FD)));

	fdset->iov.iov_base		= OPTS_BUF(fdset);

	fdset->hdr.msg_iov		= &fdset->iov;
	fdset->hdr.msg_iovlen		= 1;
	fdset->hdr.msg_name		= (struct sockaddr *)saddr;
	fdset->hdr.msg_namelen		= saddr_len;

	fdset->hdr.msg_control		= &fdset->msg_buf;
	fdset->hdr.msg_controllen	= CMSG_LEN(sizeof(int) * CR_SCM_MAX_FD);

	cmsg				= CMSG_FIRSTHDR(&fdset->hdr);
	cmsg->cmsg_len			= fdset->hdr.msg_controllen;
	cmsg->cmsg_level		= SOL_SOCKET;
	cmsg->cmsg_type			= SCM_RIGHTS;

	return (int *)CMSG_DATA(cmsg);
}

int send_fds(int sock, struct sockaddr_un *saddr, int len,
		int *fds, int nr_fds, bool with_flags)
{
	struct scm_fdset fdset;
	int *cmsg_data;
	int i, min_fd, ret;

	cmsg_data = scm_fdset_init(&fdset, saddr, len);
	for (i = 0; i < nr_fds; i += min_fd) {
		min_fd = min(CR_SCM_MAX_FD, nr_fds - i);
		scm_fdset_init_chunk(&fdset, min_fd, with_flags);
		__memcpy(cmsg_data, &fds[i], sizeof(int) * min_fd);

#ifdef SCM_FDSET_HAS_OPTS
		if (with_flags) {
			int j;

			for (j = 0; j < min_fd; j++) {
				int flags, fd = fds[i + j];
				struct fd_opts *p = fdset.opts + j;
				struct f_owner_ex owner_ex;
				uint32_t v[2];

				flags = __sys(fcntl)(fd, F_GETFD, 0);
				if (flags < 0) {
					pr_err("fcntl(%d, F_GETFD) -> %d\n", fd, flags);
					return -1;
				}

				p->flags = (char)flags;

				ret = __sys(fcntl)(fd, F_GETOWN_EX, (long)&owner_ex);
				if (ret) {
					pr_err("fcntl(%d, F_GETOWN_EX) -> %d\n", fd, ret);
					return -1;
				}

				/*
				 * Simple case -- nothing is changed.
				 */
				if (owner_ex.pid == 0) {
					p->fown.pid = 0;
					continue;
				}

				ret = __sys(fcntl)(fd, F_GETOWNER_UIDS, (long)&v);
				if (ret) {
					pr_err("fcntl(%d, F_GETOWNER_UIDS) -> %d\n", fd, ret);
					return -1;
				}

				p->fown.uid	 = v[0];
				p->fown.euid	 = v[1];
				p->fown.pid_type = owner_ex.type;
				p->fown.pid	 = owner_ex.pid;
			}
		}
#endif

		ret = __sys(sendmsg)(sock, &fdset.hdr, 0);
		if (ret <= 0)
			return ret ? : -1;
	}

	return 0;
}

int recv_fds(int sock, int *fds, int nr_fds, struct fd_opts *opts)
{
	struct scm_fdset fdset;
	struct cmsghdr *cmsg;
	int *cmsg_data;
	int ret;
	int i, min_fd;

	cmsg_data = scm_fdset_init(&fdset, NULL, 0);
	for (i = 0; i < nr_fds; i += min_fd) {
		min_fd = min(CR_SCM_MAX_FD, nr_fds - i);
		scm_fdset_init_chunk(&fdset, min_fd, opts != NULL);

		ret = __sys(recvmsg)(sock, &fdset.hdr, 0);
		if (ret <= 0)
			return ret ? : -1;

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
			return -1;
		__memcpy(&fds[i], cmsg_data, sizeof(int) * min_fd);
#ifdef SCM_FDSET_HAS_OPTS
		if (opts)
			__memcpy(opts + i, fdset.opts, sizeof(struct fd_opts) * min_fd);
#endif
	}

	return 0;
}

