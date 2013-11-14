#ifndef __CR_KCMP_H__
#define __CR_KCMP_H__

enum kcmp_type {
	KCMP_FILE,
	KCMP_VM,
	KCMP_FILES,
	KCMP_FS,
	KCMP_SIGHAND,
	KCMP_IO,
	KCMP_SYSVSEM,

	KCMP_TYPES,
};

#endif /* __CR_KCMP_H__ */
