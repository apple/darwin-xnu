/*
 * Copyright (c) 2011-2013 Apple Inc. All rights reserved.
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

#ifdef __arm64__

#include "../custom/SYS.h"
#include <mach/arm64/asm.h>

/* 
 * Stubs are to handle the ARM64 ABI for variadic functions' 
 * not matching the ABI used by the system call handler.
 */

/*
 *	sem_t* sem_open(const char *name, int oflag, ...);
 *	sem_t* __sem_open(const char *name, int oflag, int mode, int value);
 */
MI_ENTRY_POINT(_sem_open) 
	PUSH_FRAME
	ldp	x2, x3, [fp, #16]
	MI_CALL_EXTERNAL(___sem_open)
	POP_FRAME
	ret

/*
 *	int open(const char *name, int oflag, ...);
 *	int __open(const char *name, int oflag, int mode, int value);
 */
MI_ENTRY_POINT(_open) 
	PUSH_FRAME
	ldr	x2, [fp, #16]
	MI_CALL_EXTERNAL(___open)
	POP_FRAME
	ret

/*
 *	int open_nocancel(const char *name, int oflag, ...);
 *	int __open_nocancel(const char *name, int oflag, int mode);
 */
MI_ENTRY_POINT(_open$NOCANCEL) 
	PUSH_FRAME
	ldr	x2, [fp, #16]
	MI_CALL_EXTERNAL(___open_nocancel)
	POP_FRAME
	ret

/*
 *	int openat(int fd,const char *name, int oflag, ...);
 *	int __openat(int fd, const char *name, int oflag, int mode, int value);
 */
MI_ENTRY_POINT(_openat)
	PUSH_FRAME
	ldr	x3, [fp, #16]
	MI_CALL_EXTERNAL(___openat)
	POP_FRAME
	ret

/*
 *	int openat_nocancel(int fd, const char *name, int oflag, ...);
 *	int __openat_nocancel(int fd, const char *name, int oflag, int mode);
 */
MI_ENTRY_POINT(_openat$NOCANCEL)
	PUSH_FRAME
	ldr	x3, [fp, #16]
	MI_CALL_EXTERNAL(___openat_nocancel)
	POP_FRAME
	ret

/* 
 * int shm_open(const char *, int, ...);
 * int __shm_open(const char*, int oflag, int mode);
 */
MI_ENTRY_POINT(_shm_open)
	PUSH_FRAME
	ldr x2, [fp, #16]
	MI_CALL_EXTERNAL(___shm_open)
	POP_FRAME
	ret

/*
 * int msgsys(int, ...);
 * int __msgsys(int which, int a2, int a3, int a4, int a5);
 */
MI_ENTRY_POINT(_msgsys)
	PUSH_FRAME
 	ldp x1, x2, [fp, #16]
 	ldp x3, x4, [fp, #32]
	MI_CALL_EXTERNAL(___msgsys)
	POP_FRAME
	ret

/*
 * int semsys(int, ...);
 * int __semsys(int which, int a2, int a3, int a4, int a5);
 */
MI_ENTRY_POINT(_semsys)
	PUSH_FRAME
 	ldp x1, x2, [fp, #16]
 	ldp x3, x4, [fp, #32]
	MI_CALL_EXTERNAL(___semsys)
	POP_FRAME
	ret

/* 
 * int	semctl(int, int, int, ...);
 * int __semctl(int semid, int semnum, int cmd, semun_t arg);
 */
 MI_ENTRY_POINT(_semctl)
	PUSH_FRAME
 	ldr x3, [fp, #16]
	MI_CALL_EXTERNAL(___semctl)
	POP_FRAME
	ret

/* 
 * int	shmsys(int, ...);
 * int __shmsys(int which, int a2, int a3, int a4);
 */
 MI_ENTRY_POINT(_shmsys)
	PUSH_FRAME
 	ldp x1, x2, [fp, #16]
 	ldr x3, [fp, #32]
	MI_CALL_EXTERNAL(___shmsys)
	POP_FRAME
	ret

#endif /* defined(__arm64__) */
