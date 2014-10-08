#ifndef __CR_SYSCTL_H__
#define __CR_SYSCTL_H__

struct sysctl_req {
	char	*name;
	void	*arg;
	int	type;
};

extern int sysctl_op(struct sysctl_req *req, int op);

enum {
	CTL_READ,
	CTL_WRITE,
	CTL_PRINT,
	CTL_SHOW,
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

#endif /* __CR_SYSCTL_H__ */
