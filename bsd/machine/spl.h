/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
#ifndef _BSD_MACHINE_SPL_H_
#define _BSD_MACHINE_SPL_H_

#ifdef KERNEL
#ifndef __ASSEMBLER__
/*
 *	Machine-dependent SPL definitions.
 *
 */
typedef unsigned	spl_t;

extern unsigned	int sploff(void);
extern unsigned	int splhigh(void);
extern unsigned	int splsched(void);
extern unsigned	int splclock(void);
extern unsigned	int splpower(void);
extern unsigned	int splvm(void);
extern unsigned	int splbio(void);
extern unsigned	int splimp(void);
extern unsigned	int spltty(void);
extern unsigned	int splnet(void);
extern unsigned	int splsoftclock(void);

extern void	spllo(void);
extern void	splon(unsigned int level);
extern void	splx(unsigned int level);
extern void	spln(unsigned int level);
#define splstatclock()	splhigh()

#endif /* __ASSEMBLER__ */

#endif /* KERNEL */


#endif /* _BSD_MACHINE_SPL_H_ */
