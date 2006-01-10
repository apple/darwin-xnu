/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*-
 * Copyright (c) 1999 John D. Polstra
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef _SYS_LINKER_SET_H_
#define _SYS_LINKER_SET_H_

#include <sys/appleapiopts.h>

#if !defined(KERNEL) || defined(__APPLE_API_PRIVATE)
/*
 * The following macros are used to declare global sets of objects, which
 * are collected by the linker into a `struct linker_set' as defined below.
 * For ELF, this is done by constructing a separate segment for each set.
 * For a.out, it is done automatically by the linker.
 */

#define __ELF__
#ifdef __ELF__

#define MAKE_SET(seg, set, sym)						\
	static void const * const __set_##set##_sym_##sym = &sym;	\
	__asm(".section  seg, " #set ""); 	\
	__asm(".long " #sym);						

/*	__asm(".previous") */


#define TEXT_SET(set, sym) MAKE_SET(__TEXT, set, sym)
#define DATA_SET(set, sym) MAKE_SET(__DATA, set, sym)
#define BSS_SET(set, sym)  MAKE_SET(__BSS,  set, sym)
#define ABS_SET(set, sym)  MAKE_SET(__ABS,  set, sym)

#else

/*
 * NB: the constants defined below must match those defined in
 * nlist.h.  Since their calculation requires arithmetic, we
 * can't name them symbolically (e.g., 7 is N_DATA | N_EXT).
 */
#define MAKE_SET(set, sym, type) \
	static void const * const __set_##set##_sym_##sym = &sym; \
	__asm(".stabs \"_" #set "\", " #type ", 0, 0, _" #sym)

#define TEXT_SET(set, sym) MAKE_SET(set, sym, 5)
#define DATA_SET(set, sym) MAKE_SET(set, sym, 7)
#define BSS_SET(set, sym)  MAKE_SET(set, sym, 9)
#define ABS_SET(set, sym)  MAKE_SET(set, sym, 3)

#endif

struct linker_set {
	int		ls_length;
	const void	*ls_items[1];		/* really ls_length of them,
						 * trailing NULL */
};
#endif /* !KERNEL || __APPLE_API_PRIVATE */

#endif /* _SYS_LINKER_SET_H_ */

