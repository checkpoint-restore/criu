#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#include "crtools.h"
#include "protobuf.h"
#include "cr-show.h"
#include "files.h"
#include "files-reg.h"
#include "tun.h"
#include "net.h"

#include "protobuf/tun.pb-c.h"

#ifndef IFF_PERSIST
#define IFF_PERSIST 0x0800
#endif

#ifndef IFF_NOFILTER
#define IFF_NOFILTER 0x1000
#endif

#ifndef TUNSETQUEUE
#define TUNSETQUEUE  _IOW('T', 217, int)
#define IFF_ATTACH_QUEUE 0x0200
#define IFF_DETACH_QUEUE 0x0400
#endif

/*
 * Absense of the 1st ioctl means we cannot restore tun link. But
 * since the 2nd one appeared at the same time, we'll "check" this
 * by trying to dump filter and abort dump if it's not there.
 */

#ifndef TUNSETIFINDEX
#define TUNSETIFINDEX _IOW('T', 218, unsigned int)
#endif

#ifndef TUNGETFILTER
#define TUNGETFILTER _IOR('T', 219, struct sock_fprog)
#endif

#define TUN_DEV_GEN_PATH	"/dev/net/tun"

void show_tunfile(int fd)
{
	pb_show_plain(fd, PB_TUNFILE);
}
