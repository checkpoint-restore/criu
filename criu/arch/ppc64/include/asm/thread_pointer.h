/* __thread_pointer definition.  powerpc version.
   Copyright (C) 2021 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library.  If not, see
   <https://www.gnu.org/licenses/>.  */

#ifndef _SYS_THREAD_POINTER_H
#define _SYS_THREAD_POINTER_H

#ifdef __powerpc64__
register void *__thread_register asm("r13");
#else
register void *__thread_register asm("r2");
#endif

static inline void *__criu_thread_pointer(void)
{
	return __thread_register;
}

#endif /* _SYS_THREAD_POINTER_H */