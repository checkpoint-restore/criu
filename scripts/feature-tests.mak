define TCP_REPAIR_TEST

#include <netinet/tcp.h>

int main(void)
{
	struct tcp_repair_opt opts;
	opts.opt_code = TCP_NO_QUEUE;
	opts.opt_val = 0;

	return opts.opt_val;
}
endef
