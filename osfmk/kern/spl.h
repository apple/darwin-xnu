/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
#ifndef	_KERN_SPL_H_
#define	_KERN_SPL_H_

typedef unsigned spl_t;

#define	splhigh()	(spl_t) ml_set_interrupts_enabled(FALSE)
#define	splsched()	(spl_t) ml_set_interrupts_enabled(FALSE)
#define	splclock()	(spl_t) ml_set_interrupts_enabled(FALSE)
#define	splx(x)		(void) ml_set_interrupts_enabled(x)
#define	spllo()		(void) ml_set_interrupts_enabled(TRUE)

#endif	/* _KERN_SPL_H_ */
