/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
/*
 * Copyright 1993, NeXT Computer, Inc.
 */

#ifndef _BSD_PPC_REG_H_
#define _BSD_PPC_REG_H_

#include <sys/appleapiopts.h>

#ifdef	KERNEL_PRIVATE
#ifdef __APPLE_API_PRIVATE

/* Index into the thread_state */
#define SP	3
#define PC 	0

#endif /* __APPLE_API_PRIVATE */

#endif /* KERNEL_PRIVATE */

#endif /* _BSD_PPC_REG_H_ */

