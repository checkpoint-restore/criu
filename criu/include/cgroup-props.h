#ifndef __CR_CGROUP_PROPS_H__
#define __CR_CGROUP_PROPS_H__

#include <stdbool.h>

typedef struct {
	const char	*name;
	size_t		nr_props;
	const char	**props;
} cgp_t;

extern cgp_t cgp_global;
extern const cgp_t *cgp_get_props(const char *name);
extern bool cgp_should_skip_controller(const char *name);
extern bool cgp_add_dump_controller(const char *name);

extern int cgp_init(char *stream, size_t len, char *path);
extern void cgp_fini(void);

#endif /* __CR_CGROUP_PROPS_H__ */
