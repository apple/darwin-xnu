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
 * Copyright (c) 1992 NeXT Computer, Inc.
 *
 * Intel386 Family:	Definition of eflags register.
 *
 * HISTORY
 *
 * 7 April 1992 ? at NeXT
 *	Created.
 */
 
#if	KERNEL_PRIVATE

#ifndef _BSD_I386_PSL_H_
#define _BSD_I386_PSL_H_
 
#define EFL_ALLCC	(		\
			    EFL_CF |	\
			    EFL_PF |	\
			    EFL_AF |	\
			    EFL_ZF |	\
			    EFL_SF |	\
			    EFL_OF	\
			)
#define EFL_USERSET	( EFL_IF | EFL_SET )
#define EFL_USERCLR	( EFL_VM | EFL_NT | EFL_IOPL | EFL_CLR )

#define PSL_ALLCC	EFL_ALLCC
#define PSL_T		EFL_TF

#endif	/* _BSD_I386_PSL_H_ */

#endif	/* KERNEL_PRIVATE */
