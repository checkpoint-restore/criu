/* __thread_pointer definition.  x86 version.
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

static inline void *__criu_thread_pointer(void)
{
#if __GNUC_PREREQ(11, 1)
	return __builtin_thread_pointer();
#else
	void *__result;
#ifdef __x86_64__
	__asm__("mov %%fs:0, %0" : "=r"(__result));
#else
	__asm__("mov %%gs:0, %0" : "=r"(__result));
#endif
	return __result;
#endif /* !GCC 11 */
}

#endif /* _SYS_THREAD_POINTER_H */