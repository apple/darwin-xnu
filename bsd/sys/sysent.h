/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#ifndef _SYS_SYSENT_H_
#define	_SYS_SYSENT_H_

#include <sys/appleapiopts.h>
#include <sys/cdefs.h>
#ifdef __ppc__
#include <sys/types.h>
#endif

#ifdef KERNEL_PRIVATE
#ifdef __APPLE_API_PRIVATE

typedef	int32_t	sy_call_t(struct proc *, void *, int *);
typedef	void	sy_munge_t(const void *, void *);

extern struct sysent {		/* system call table */
	int16_t		sy_narg;	/* number of args */
	int8_t		sy_cancel;	/* funnel type */
	int8_t		sy_funnel;	/* funnel type */
	sy_call_t	*sy_call;	/* implementing function */
	sy_munge_t	*sy_arg_munge32; /* system call aguments munger for 32-bit process */
	sy_munge_t	*sy_arg_munge64; /* system call aguments munger for 64-bit process */
	int32_t		sy_return_type; /* system call return types */
} sysent[];

/* sy_funnel flags bits */
#define FUNNEL_MASK	0x00ff
#define	UNSAFE_64BIT	0x0100

/* 
 * Valid values for sy_cancel
 */
#define _SYSCALL_CANCEL_NONE	0		/* Not a cancellation point */
#define _SYSCALL_CANCEL_PRE		1		/* Canbe cancelled on entry itself */
#define _SYSCALL_CANCEL_POST	2		/* Can only be cancelled after syscall is run */

/*
 * Valid values for sy_return_type
 */
#define _SYSCALL_RET_NONE		0
#define _SYSCALL_RET_INT_T		1	
#define _SYSCALL_RET_UINT_T		2	
#define _SYSCALL_RET_OFF_T		3	
#define _SYSCALL_RET_ADDR_T		4	
#define _SYSCALL_RET_SIZE_T		5	
#define _SYSCALL_RET_SSIZE_T	6	

extern int nsysent;

#endif /* __APPLE_API_PRIVATE */
#endif /* KERNEL_PRIVATE */

#endif /* !_SYS_SYSENT_H_ */
