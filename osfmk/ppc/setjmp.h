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
/*
 * @OSF_COPYRIGHT@
 */

#ifndef	_PPC_SETJMP_H_
#define	_PPC_SETJMP_H_

/*
 * We save the following registers (marked as non-volatile in the ELF spec)
 *
 * r1      - stack pointer
 * r13     - small data area pointer
 * r14-r30 - local variables
 * r31     - local variable/environment pointer
 * 
 * cr      - condition register
 * lr      - link register (to know where to jump back to)
 * xer     - fixed point exception register
 *
 * fpscr   - floating point status and control
 * f14-f31 - local variables
 *
 * which comes to 57 words. We round up to 64 for good measure.
 */

typedef	struct jmp_buf {
	int	jmp_buf[64];
} jmp_buf_t;

#endif	/* _PPC_SETJMP_H_ */
