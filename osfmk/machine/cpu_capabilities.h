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

#ifndef _MACHINE_CPU_CAPABILITIES_H
#define _MACHINE_CPU_CAPABILITIES_H

#ifdef __APPLE_API_PRIVATE

#if defined (__ppc__)
#include "ppc/cpu_capabilities.h"
#elif defined (__i386__)
#include "i386/cpu_capabilities.h"
#else
#error architecture not supported
#endif

#endif /* __APPLE_API_PRIVATE */
#endif /* _MACHINE_CPU_CAPABILITIES_H */
