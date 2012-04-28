#include <netinet/tcp.h>
#include "types.h"
#include "sockets.h"
#include "files.h"
#include "sk-inet.h"

void show_tcp_stream(int fd, struct cr_options *opt)
{
	struct tcp_stream_entry tse;
	pr_img_head(CR_FD_TCP_STREAM);

	if (read_img(fd, &tse) > 0) {
		pr_msg("IN:   seq %10u len %10u\n", tse.inq_seq, tse.inq_len);
		pr_msg("OUT:  seq %10u len %10u\n", tse.outq_seq, tse.outq_len);
		pr_msg("OPTS: %#x\n", (int)tse.opt_mask);
		pr_msg("\tmss_clamp %u\n", (int)tse.mss_clamp);
		if (tse.opt_mask & TCPI_OPT_WSCALE)
			pr_msg("\twscale %u\n", (int)tse.snd_wscale);
		if (tse.opt_mask & TCPI_OPT_TIMESTAMPS)
			pr_msg("\ttimestamps\n");
		if (tse.opt_mask & TCPI_OPT_SACK)
			pr_msg("\tsack\n");
	}

	pr_img_tail(CR_FD_TCP_STREAM);
}
