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
 * 
 */

#ifndef	PPC_CPU_DATA
#define PPC_CPU_DATA

#if	defined(__GNUC__)

#define disable_preemption			_disable_preemption
#define enable_preemption			_enable_preemption
#define enable_preemption_no_check		_enable_preemption_no_check
#define mp_disable_preemption			_disable_preemption
#define mp_enable_preemption			_enable_preemption
#define mp_enable_preemption_no_check		_enable_preemption_no_check

extern thread_t					current_thread(void);
extern int 					get_preemption_level(void);
extern void 					disable_preemption(void);
extern void 					enable_preemption(void);
extern void 					enable_preemption_no_check(void);
extern void 					mp_disable_preemption(void);
extern void 					mp_enable_preemption(void);
extern void 					mp_enable_preemption_no_check(void);
extern int 					get_simple_lock_count(void);
#endif	/* defined(__GNUC__) */

#endif	/* PPC_CPU_DATA */
