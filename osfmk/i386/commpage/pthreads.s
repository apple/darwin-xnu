/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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

#define _PTHREAD_TSD_OFFSET 0x48

        .text
        .align  2, 0x90

Lpthread_getspecific:
	movl	4(%esp), %eax
	movl	%gs:_PTHREAD_TSD_OFFSET(,%eax,4), %eax
	ret

	COMMPAGE_DESCRIPTOR(pthread_getspecific,_COMM_PAGE_PTHREAD_GETSPECIFIC,0,0)

Lpthread_self:
	movl	4(%esp), %eax
	movl	%gs:_PTHREAD_TSD_OFFSET, %eax
	ret

	COMMPAGE_DESCRIPTOR(pthread_self,_COMM_PAGE_PTHREAD_SELF,0,0)
