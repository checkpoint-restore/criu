#ifndef __UAPI_FLOG_H__
#define __UAPI_FLOG_H__

#include <stdbool.h>
#include <string.h>
#include <errno.h>

/*
 * We work with up to 32 arguments in macros here.
 * If more provided -- behaviour is undefined.
 */

/*
 * By Laurent Deniau at https://groups.google.com/forum/#!topic/comp.std.c/d-6Mj5Lko_s
 */
#define FLOG_PP_NARG_(...)			FLOG_PP_ARG_N(__VA_ARGS__)
#define FLOG_PP_NARG(...)			FLOG_PP_NARG_(1, ##__VA_ARGS__, FLOG_PP_RSEQ_N())

#define FLOG_PP_ARG_N( _0, _1, _2, _3, _4,	\
		       _5, _6, _7, _8, _9,	\
		      _10,_11,_12,_13,_14,	\
		      _15,_16,_17,_18,_19,	\
		      _20,_21,_22,_23,_24,	\
		      _25,_26,_27,_28,_29,	\
		      _30,_31,  N, ...)		N

#define FLOG_PP_RSEQ_N()			\
		       31, 30, 29, 28, 27,	\
		       26, 25, 24, 23, 22,	\
		       21, 20, 19, 18, 17,	\
		       16, 15, 14, 13, 12,	\
		       11, 10,  9,  8,  7,	\
		        6,  5,  4,  3,  2,	\
		        1,  0

#define FLOG_GENMASK_0(N, x)		0
#define FLOG_GENMASK_1(N,  op, x, ...)	 (op(N,  0, x))
#define FLOG_GENMASK_2(N,  op, x, ...)	((op(N,  1, x)) | FLOG_GENMASK_1(N,  op,  __VA_ARGS__))
#define FLOG_GENMASK_3(N,  op, x, ...)	((op(N,  2, x)) | FLOG_GENMASK_2(N,  op,  __VA_ARGS__))
#define FLOG_GENMASK_4(N,  op, x, ...)	((op(N,  3, x)) | FLOG_GENMASK_3(N,  op,  __VA_ARGS__))
#define FLOG_GENMASK_5(N,  op, x, ...)	((op(N,  4, x)) | FLOG_GENMASK_4(N,  op,  __VA_ARGS__))
#define FLOG_GENMASK_6(N,  op, x, ...)	((op(N,  5, x)) | FLOG_GENMASK_5(N,  op,  __VA_ARGS__))
#define FLOG_GENMASK_7(N,  op, x, ...)	((op(N,  6, x)) | FLOG_GENMASK_6(N,  op,  __VA_ARGS__))
#define FLOG_GENMASK_8(N,  op, x, ...)	((op(N,  7, x)) | FLOG_GENMASK_7(N,  op,  __VA_ARGS__))
#define FLOG_GENMASK_9(N,  op, x, ...)	((op(N,  8, x)) | FLOG_GENMASK_8(N,  op,  __VA_ARGS__))
#define FLOG_GENMASK_10(N, op, x, ...)	((op(N,  9, x)) | FLOG_GENMASK_9(N,  op,  __VA_ARGS__))
#define FLOG_GENMASK_11(N, op, x, ...)	((op(N, 10, x)) | FLOG_GENMASK_10(N, op,  __VA_ARGS__))
#define FLOG_GENMASK_12(N, op, x, ...)	((op(N, 11, x)) | FLOG_GENMASK_11(N, op,  __VA_ARGS__))
#define FLOG_GENMASK_13(N, op, x, ...)	((op(N, 12, x)) | FLOG_GENMASK_12(N, op,  __VA_ARGS__))
#define FLOG_GENMASK_14(N, op, x, ...)	((op(N, 13, x)) | FLOG_GENMASK_13(N, op,  __VA_ARGS__))
#define FLOG_GENMASK_15(N, op, x, ...)	((op(N, 14, x)) | FLOG_GENMASK_14(N, op,  __VA_ARGS__))
#define FLOG_GENMASK_16(N, op, x, ...)	((op(N, 15, x)) | FLOG_GENMASK_15(N, op,  __VA_ARGS__))
#define FLOG_GENMASK_17(N, op, x, ...)	((op(N, 16, x)) | FLOG_GENMASK_16(N, op,  __VA_ARGS__))
#define FLOG_GENMASK_18(N, op, x, ...)	((op(N, 17, x)) | FLOG_GENMASK_17(N, op,  __VA_ARGS__))
#define FLOG_GENMASK_19(N, op, x, ...)	((op(N, 18, x)) | FLOG_GENMASK_18(N, op,  __VA_ARGS__))
#define FLOG_GENMASK_20(N, op, x, ...)	((op(N, 19, x)) | FLOG_GENMASK_19(N, op,  __VA_ARGS__))
#define FLOG_GENMASK_21(N, op, x, ...)	((op(N, 20, x)) | FLOG_GENMASK_20(N, op,  __VA_ARGS__))
#define FLOG_GENMASK_22(N, op, x, ...)	((op(N, 21, x)) | FLOG_GENMASK_21(N, op,  __VA_ARGS__))
#define FLOG_GENMASK_23(N, op, x, ...)	((op(N, 22, x)) | FLOG_GENMASK_22(N, op,  __VA_ARGS__))
#define FLOG_GENMASK_24(N, op, x, ...)	((op(N, 23, x)) | FLOG_GENMASK_23(N, op,  __VA_ARGS__))
#define FLOG_GENMASK_25(N, op, x, ...)	((op(N, 24, x)) | FLOG_GENMASK_24(N, op,  __VA_ARGS__))
#define FLOG_GENMASK_26(N, op, x, ...)	((op(N, 25, x)) | FLOG_GENMASK_25(N, op,  __VA_ARGS__))
#define FLOG_GENMASK_27(N, op, x, ...)	((op(N, 26, x)) | FLOG_GENMASK_26(N, op,  __VA_ARGS__))
#define FLOG_GENMASK_28(N, op, x, ...)	((op(N, 27, x)) | FLOG_GENMASK_27(N, op,  __VA_ARGS__))
#define FLOG_GENMASK_29(N, op, x, ...)	((op(N, 28, x)) | FLOG_GENMASK_28(N, op,  __VA_ARGS__))
#define FLOG_GENMASK_30(N, op, x, ...)	((op(N, 29, x)) | FLOG_GENMASK_29(N, op,  __VA_ARGS__))
#define FLOG_GENMASK_31(N, op, x, ...)	((op(N, 30, x)) | FLOG_GENMASK_30(N, op,  __VA_ARGS__))
#define FLOG_GENMASK_32(N, op, x, ...)	((op(N, 31, x)) | FLOG_GENMASK_31(N, op,  __VA_ARGS__))

#define FLOG_CONCAT(arg1, arg2)		FLOG_CONCAT1(arg1, arg2)
#define FLOG_CONCAT1(arg1, arg2)	FLOG_CONCAT2(arg1, arg2)
#define FLOG_CONCAT2(arg1, arg2)	arg1##arg2

#define FLOG_GENMASK_(N, op, ...)	FLOG_CONCAT(FLOG_GENMASK_, N)(N, op, ##__VA_ARGS__)
#define FLOG_GENMASK(op, ...)		FLOG_GENMASK_(FLOG_PP_NARG(__VA_ARGS__), op, ##__VA_ARGS__)

#define flog_genbit(ord, n, v, ...)					\
	_Generic((v),							\
									\
		 /* Basic types */					\
		 char:				0,			\
		 signed char:			0,			\
		 unsigned char:			0,			\
		 signed short int:		0,			\
		 unsigned short int:		0,			\
		 signed int:			0,			\
		 unsigned int:			0,			\
		 signed long:			0,			\
		 unsigned long:			0,			\
		 signed long long:		0,			\
		 unsigned long long:		0,			\
									\
		 /* Not used for a while */				\
		 /* float:			12, */			\
		 /* double:			13, */			\
		 /* long double:		14, */			\
									\
		 /* Basic poniters */					\
		 char *:			(1u << (ord - n - 1)),	\
		 signed char *:			(1u << (ord - n - 1)),	\
		 unsigned char *:		(1u << (ord - n - 1)),	\
		 signed short int *:		0,			\
		 unsigned short int *:		0,			\
		 signed int *:			0,			\
		 unsigned int *:		0,			\
		 signed long *:			0,			\
		 unsigned long *:		0,			\
		 signed long long *:		0,			\
		 unsigned long long *:		0,			\
		 void *:			0,			\
									\
		 /* Const basic pointers */				\
		 const char *:			(1u << (ord - n - 1)),	\
		 const signed char *:		(1u << (ord - n - 1)),	\
		 const unsigned char *:		(1u << (ord - n - 1)),	\
		 const signed short int *:	0,			\
		 const unsigned short int *:	0,			\
		 const signed int *:		0,			\
		 const unsigned int *:		0,			\
		 const signed long *:		0,			\
		 const unsigned long *:		0,			\
		 const signed long long *:	0,			\
		 const unsigned long long *:	0,			\
		 const void *:			0,			\
									\
		 /* Systypes and pointers */				\
		 default:			-1)

typedef struct {
	unsigned int	magic;
	unsigned int	size;
	unsigned int	nargs;
	unsigned int	mask;
	long		fmt;
	long		args[0];
} flog_msg_t;

extern int flog_encode_msg(int fdout, unsigned int nargs, unsigned int mask, const char *format, ...);
void flog_decode_msg(int fdout, const char *format, ...);
extern int flog_decode_all(int fdin, int fdout);

#define flog_encode(fdout, fmt, ...)							\
	flog_encode_msg(fdout, FLOG_PP_NARG(__VA_ARGS__),				\
			FLOG_GENMASK(flog_genbit, ##__VA_ARGS__), fmt, ##__VA_ARGS__)

int flog_map_buf(int fdout);
int flog_close(int fdout);

#endif /* __UAPI_FLOG_H__ */
