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
/*
 * @OSF_COPYRIGHT@
 * 
 */

#ifndef	PPC_CPU_DATA
#define PPC_CPU_DATA

typedef struct
{
	int		preemption_level;
	int		simple_lock_count;
	int		interrupt_level;
} cpu_data_t;

#define disable_preemption			_disable_preemption
#define enable_preemption			_enable_preemption
#define enable_preemption_no_check		_enable_preemption_no_check
#define mp_disable_preemption			_disable_preemption
#define mp_enable_preemption			_enable_preemption
#define mp_enable_preemption_no_check		_enable_preemption_no_check

extern __inline__ thread_act_t current_act(void) 
{
	thread_act_t act;
	__asm__ volatile("mfsprg %0,1" : "=r" (act));  
	return act;
};

/*
 *	Note that the following function is ONLY guaranteed when preemption or interrupts are disabled
 */
extern __inline__ struct per_proc_info *getPerProc(void) 
{
	struct per_proc_info *perproc;
	__asm__ volatile("mfsprg %0,0" : "=r" (perproc));  
	return perproc;
};

#define	current_thread()	current_act()->thread

extern void					set_machine_current_act(thread_act_t);

extern int 					get_preemption_level(void);
extern void 					disable_preemption(void);
extern void 					enable_preemption(void);
extern void 					enable_preemption_no_check(void);
extern void 					mp_disable_preemption(void);
extern void 					mp_enable_preemption(void);
extern void 					mp_enable_preemption_no_check(void);
extern int 					get_simple_lock_count(void);

#endif	/* PPC_CPU_DATA */
