#ifndef __CR_SYSCTL_H__
#define __CR_SYSCTL_H__

struct sysctl_req {
	char	*name;
	void	*arg;
	int	type;
	int	flags;
};

extern int sysctl_op(struct sysctl_req *req, size_t nr_req, int op, unsigned int ns);

enum {
	CTL_READ,
	CTL_WRITE,
};

#define CTL_SHIFT	4	/* Up to 16 types */

#define CTL_U32		1	/* Single u32 */
#define CTL_U64		2	/* Single u64 */
#define __CTL_U32A	3	/* Array of u32 */
#define __CTL_U64A	4	/* Array of u64 */
#define __CTL_STR	5	/* String */
#define CTL_32		6	/* Single s32 */

#define CTL_U32A(n)	(__CTL_U32A | ((n)   << CTL_SHIFT))
#define CTL_U64A(n)	(__CTL_U64A | ((n)   << CTL_SHIFT))
#define CTL_STR(len)	(__CTL_STR  | ((len) << CTL_SHIFT))

#define CTL_LEN(t)	((t) >> CTL_SHIFT)
#define CTL_TYPE(t)	((t) & ((1 << CTL_SHIFT) - 1))

/*
 * Some entries might be missing mark them as optional.
 */
#define CTL_FLAGS_OPTIONAL	1
#define CTL_FLAGS_HAS		2
#define CTL_FLAGS_READ_EIO_SKIP	4

#endif /* __CR_SYSCTL_H__ */
