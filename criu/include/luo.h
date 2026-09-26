#ifndef __CR_LUO_H__
#define __CR_LUO_H__

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "int.h"
#include "common/config.h"
#include "common/list.h"

#ifdef CONFIG_HAS_LIVEUPDATE
/* Include the liveupdate header from the kernel source */
#include <linux/liveupdate.h>
#endif

struct luo_fd_mapping {
	char *path;
	uint64_t token;
	struct list_head list;
};

#ifdef CONFIG_HAS_LIVEUPDATE
/* LUO session management - core functions */
extern int luo_init_session(const char *session_name);
extern int luo_preserve_fd(int fd, uint64_t *token, const char *path);
extern int luo_retrieve_fd_by_path(const char *path, int *fd);
extern int luo_retrieve_session(const char *session_name);
extern int luo_retrieve_fd(uint64_t token, int *fd);
extern int luo_finish_session(void);
extern void luo_cleanup(bool finish_session);
/* Fork a daemon to hold the session fd for kexec reboot */
extern void luo_daemonize_and_wait(void);

/* LUO metadata serialization */
extern int luo_save_image_metadata(void);
extern int luo_load_image_metadata(void);

#else /* !CONFIG_HAS_LIVEUPDATE */

/* Stub implementations when LUO is not available */
static inline int luo_init_session(const char *session_name) { return -ENOTSUP; }
static inline int luo_preserve_fd(int fd, uint64_t *token, const char *path) { return -ENOTSUP; }
static inline int luo_retrieve_fd_by_path(const char *path, int *fd) { return -ENOTSUP; }
static inline int luo_retrieve_session(const char *session_name) { return -ENOTSUP; }
static inline int luo_retrieve_fd(uint64_t token, int *fd) { return -ENOTSUP; }
static inline int luo_finish_session(void) { return -ENOTSUP; }
static inline void luo_cleanup(bool finish_session) {}
static inline void luo_daemonize_and_wait(void) {}
static inline int luo_save_image_metadata(void) { return -ENOTSUP; }
static inline int luo_load_image_metadata(void) { return -ENOTSUP; }

#endif /* CONFIG_HAS_LIVEUPDATE */

#endif /* __CR_LUO_H__ */
