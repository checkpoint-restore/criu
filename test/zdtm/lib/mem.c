#include <sys/sysmacros.h>
#include <string.h>
#include <stdint.h>

#include "zdtmtst.h"

dev_t get_mapping_dev(void *addr)
{
	char buf[1024];
	FILE *f;
	unsigned int major, minor;
	int ret;

	f = fopen("/proc/self/maps", "r");
	if (f == NULL) {
		pr_perror("Failed to open maps file");
		return (dev_t)-1;
	}

	while (fgets(buf, sizeof(buf), f)) {
		if ((unsigned long)addr == strtoul(buf, NULL, 16)) {
			ret = sscanf(buf, "%*x-%*x %*c%*c%*c%*c %*x %x:%x", &major, &minor);
			if (ret != 2) {
				pr_err("Can't parse /proc/self/maps\n");
				return (dev_t)-1;
			}
			return makedev(major, minor);
		}
	}

	return (dev_t)-1;
}
