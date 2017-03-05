#include <sys/types.h>

#include <compel/plugins.h>
#include <compel/plugins/std.h>

#include "asm/prologue.h"

static struct prologue_init_args *init_args;
static int ctl_socket = -1;

int std_ctl_sock(void)
{
	return ctl_socket;
}

static int init_socket(struct prologue_init_args *args)
{
	int ret;

	ctl_socket = sys_socket(PF_UNIX, SOCK_SEQPACKET, 0);
	if (ctl_socket < 0)
		return ctl_socket;

	ret = sys_connect(ctl_socket, (struct sockaddr *)&args->ctl_sock_addr, args->ctl_sock_addr_len);
	if (ret < 0)
		return ret;

	return 0;
}

static int fini_socket(void)
{
	char buf[32];
	int ret = 0;

	ret = sys_shutdown(ctl_socket, SHUT_WR);
	if (ret)
		goto err;

	ret = sys_recv(ctl_socket, buf, sizeof(buf), MSG_WAITALL);
	if (ret)
		goto err;
err:
	sys_close(ctl_socket);
	ctl_socket = -1;
	return ret;
}

#define plugin_init_count(size)	((size) / (sizeof(plugin_init_t *)))

int __export_std_compel_start(struct prologue_init_args *args,
			      const plugin_init_t * const *init_array,
			      size_t init_size)
{
	unsigned int i;
	int ret = 0;

	init_args = args;

	ret = init_socket(args);
	if (ret)
		return ret;

	for (i = 0; i < plugin_init_count(init_size); i++) {
		const plugin_init_t *d = init_array[i];

		if (d && d->init) {
			ret = d->init();
			if (ret)
				break;
		}
	}

	for (; i > 0; i--) {
		const plugin_init_t *d = init_array[i - 1];

		if (d && d->exit)
			d->exit();
	}

	fini_socket();
	return ret;
}

PLUGIN_REGISTER_DUMMY(std)
