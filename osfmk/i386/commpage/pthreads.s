/*
 * Copyright (c) 2003-2006 Apple Computer, Inc. All rights reserved.
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

#include <sys/appleapiopts.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>

#define _PTHREAD_TSD_OFFSET32 0x48
#define _PTHREAD_TSD_OFFSET64 0x60


/* These routines do not need to be on the copmmpage on Intel.  They are for now
 * to avoid revlock, but the code should move to Libc, and we should eventually remove
 * these.
 */
        .text
        .align  2, 0x90

Lpthread_getspecific:
	movl	4(%esp), %eax
	movl	%gs:_PTHREAD_TSD_OFFSET32(,%eax,4), %eax
	ret

	COMMPAGE_DESCRIPTOR(pthread_getspecific,_COMM_PAGE_PTHREAD_GETSPECIFIC,0,0)

Lpthread_self:
	movl	%gs:_PTHREAD_TSD_OFFSET32, %eax
	ret

	COMMPAGE_DESCRIPTOR(pthread_self,_COMM_PAGE_PTHREAD_SELF,0,0)

/* the 64-bit versions: */
	
	.code64
Lpthread_getspecific_64:
	movq	%gs:_PTHREAD_TSD_OFFSET64(,%rdi,8), %rax
	ret

	COMMPAGE_DESCRIPTOR(pthread_getspecific_64,_COMM_PAGE_PTHREAD_GETSPECIFIC,0,0)

Lpthread_self_64:
	movq	%gs:_PTHREAD_TSD_OFFSET64, %rax
	ret

	COMMPAGE_DESCRIPTOR(pthread_self_64,_COMM_PAGE_PTHREAD_SELF,0,0)
