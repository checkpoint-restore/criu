#ifndef __CR_KCMP_H__
#define __CR_KCMP_H__

#include <stdint.h>

enum kcmp_type {
	KCMP_FILE,
	KCMP_VM,
	KCMP_FILES,
	KCMP_FS,
	KCMP_SIGHAND,
	KCMP_IO,
	KCMP_SYSVSEM,
	KCMP_EPOLL_TFD,

	KCMP_TYPES,
};

/* Slot for KCMP_EPOLL_TFD */
typedef struct {
	uint32_t	efd;	/* epoll file descriptor */
	uint32_t	tfd;	/* target file number */
	uint32_t	toff;	/* target offset within same numbered sequence */
} kcmp_epoll_slot_t;

#endif /* __CR_KCMP_H__ */
