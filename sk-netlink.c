#include <unistd.h>

#include "crtools.h"

#include "protobuf.h"
#include "protobuf/sk-netlink.pb-c.h"

void show_netlinksk(int fd, struct cr_options *o)
{
	pb_show_plain(fd, PB_NETLINKSK);
}
