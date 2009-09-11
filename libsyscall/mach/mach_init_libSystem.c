/*
 * Copyright (c) 2007, 2008 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
#ifdef __DYNAMIC__
struct ProgramVars; /* forward reference */

extern void pthread_init(void);				// from libc.a
extern void __libc_init(const struct ProgramVars* vars);	// from libc.a
extern void __keymgr_initializer(void);		// from libkeymgr.a
extern void _dyld_initializer(void);		// from libdyld.a
extern void libdispatch_init(void);		// from libdispatch.a

/*
 * libsyscall_initializer() initializes all of libSystem.dylib <rdar://problem/4892197>
 */
static __attribute__((constructor)) 
void libSystem_initializer(int argc, const char* argv[], const char* envp[], const char* apple[], const struct ProgramVars* vars)
{
	mach_init();
	pthread_init();
	__libc_init(vars);
	__keymgr_initializer();
	_dyld_initializer();
	libdispatch_init();
}

/*  
 *  Old crt1.o glue used to call through mach_init_routine which was used to initialize libSystem.
 *  LibSystem now auto-initializes but mach_init_routine is left for binary compatibility.
 */
static void mach_init_old() {}
void (*mach_init_routine)(void) = &mach_init_old;

#endif /* __DYNAMIC__ */
