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
/*
 * Copyright 1997 Apple Computer, Inc. All rights reserved.
 *
 * History :
 *	29-Sep-1997  Umesh Vaishampayan
 *		Created.
 */
#ifndef _BSD_MACHINE_PROFILE_H_
#define _BSD_MACHINE_PROFILE_H_


#if defined (__ppc__) || defined (__ppc64__)
#include "ppc/profile.h"
#elif defined (__i386__)
#include "i386/profile.h"
#else
#error architecture not supported
#endif


#endif /* _BSD_MACHINE_PROFILE_H_ */
