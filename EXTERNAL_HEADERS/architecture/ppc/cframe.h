/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
/* Copyright (c) 1991 NeXT Software, Inc.  All rights reserved.
 *
 *	File:	architecture/ppc/cframe.h
 *	Author:	Mike DeMoney, NeXT Software, Inc.
 *
 *	This include file defines C calling sequence defines
 *	for ppc port.
 *
 * HISTORY
 * 20-May-97  Umesh Vaishampayan  (umeshv@apple.com)
 *	Added C_RED_ZONE.
 * 29-Dec-96  Umesh Vaishampayan  (umeshv@NeXT.com)
 *	Ported from m98k.
 * 11-June-91  Mike DeMoney (mike@next.com)
 *	Created.
 */

#ifndef	_ARCH_PPC_CFRAME_H_
#define	_ARCH_PPC_CFRAME_H_

#define	C_ARGSAVE_LEN	32	/* at least 32 bytes of arg save */
#define	C_STACK_ALIGN	16	/* stack must be 16 byte aligned */
#define	C_RED_ZONE	244	/* 224 bytes to skip over saved registers */

#endif	/* _ARCH_PPC_CFRAME_H_ */
