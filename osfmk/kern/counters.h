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
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:35  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:54  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.13.7  1995/02/24  15:19:14  alanl
 * 	Merge with DIPC2_SHARED.
 * 	[1995/02/22  20:19:55  alanl]
 *
 * Revision 1.1.19.4  1994/11/04  10:16:23  dwm
 * 	mk6 CR668 - 1.3b26 merge
 * 	add counters, then remove unused items
 * 	[1994/11/04  09:45:39  dwm]
 * 
 * Revision 1.1.13.5  1994/09/23  02:16:08  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:32:13  ezf]
 * 
 * Revision 1.1.13.4  1994/09/16  06:29:25  dwm
 * 	mk6 CR551 - remove unused SAFE_VM_FAULT pseudo-continuation,
 * 	remove unused args from vm_page_wait, vm_fault(_page).
 * 	Fix vm_page_wait counters, and rm thread_handoff counter.
 * 	[1994/09/16  06:23:26  dwm]
 * 
 * Revision 1.1.13.3  1994/09/10  21:45:55  bolinger
 * 	Merge up to NMK17.3
 * 	[1994/09/08  19:57:29  bolinger]
 * 
 * Revision 1.1.13.2  1994/06/21  17:28:43  dlb
 * 	Add two vm_fault counters from NMK17.
 * 	[94/06/17            dlb]
 * 
 * Revision 1.1.10.3  1994/06/15  09:12:05  paire
 * 	Corrected spelling of c_vm_fault_wait_on_unlock variable.
 * 	[94/06/15            paire]
 * 
 * Revision 1.1.13.1  1994/06/14  17:00:01  bolinger
 * 	Merge up to NMK17.2.
 * 	[1994/06/14  16:53:41  bolinger]
 * 
 * Revision 1.1.10.2  1994/05/30  07:37:03  bernadat
 * 	Added new c_vm_fault_retry_on_unlock and c_vm_fault_retry_on_w_prot.
 * 	Sorted the whole list of counters.
 * 	[paire@gr.osf.org]
 * 	[94/05/26            bernadat]
 * 
 * Revision 1.1.10.1  1994/02/11  14:25:21  paire
 * 	Added missing c_exception_raise_state_block and
 * 	c_exception_raise_state_identity_block counters.
 * 	Change from NMK16.1 [93/08/09            paire]
 * 	[94/02/04            paire]
 * 
 * Revision 1.1.2.3  1993/06/07  22:12:36  jeffc
 * 	CR9176 - ANSI C violations: trailing tokens on CPP
 * 	directives, extra semicolons after decl_ ..., asm keywords
 * 	[1993/06/07  19:04:11  jeffc]
 * 
 * Revision 1.1.2.2  1993/06/02  23:35:54  jeffc
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:12:09  jeffc]
 * 
 * Revision 1.1  1992/09/30  02:29:32  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.3  91/05/14  16:40:30  mrt
 * 	Correcting copyright
 * 
 * Revision 2.2  91/03/16  15:16:06  rpd
 * 	Created.
 * 	[91/03/13            rpd]
 * 
 */
/* CMU_ENDHIST */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */

#ifndef	_KERN_COUNTERS_
#define	_KERN_COUNTERS_

#include <mach_counters.h>

/*
 *	We can count various interesting events and paths.
 *
 *	Use counter() to change the counters, eg:
 *		counter(c_idle_thread_block++);
 *	Use counter_always() for non-conditional counters.
 */

#define counter_always(code)	code

#if	MACH_COUNTERS

#define counter(code)		counter_always(code)

#else	/* MACH_COUNTERS */

#define counter(code)

#endif	/* MACH_COUNTERS */

/*
 *	We define the counters with individual integers,
 *	instead of a big structure, so that ddb
 *	will know the addresses of the counters.
 */

typedef unsigned int mach_counter_t;

extern mach_counter_t c_thread_invoke_csw;
extern mach_counter_t c_thread_invoke_same;
extern mach_counter_t c_thread_invoke_same_cont;
extern mach_counter_t c_thread_invoke_misses;
extern mach_counter_t c_thread_invoke_hits;
extern mach_counter_t c_incoming_interrupts;
extern mach_counter_t c_syscalls_unix;
extern mach_counter_t c_syscalls_mach;

#if	MACH_COUNTERS
extern mach_counter_t c_action_thread_block;
extern mach_counter_t c_ast_taken_block;
extern mach_counter_t c_clock_ticks;
extern mach_counter_t c_dev_io_blocks;
extern mach_counter_t c_dev_io_tries;
extern mach_counter_t c_idle_thread_block;
extern mach_counter_t c_idle_thread_handoff;
extern mach_counter_t c_io_done_thread_block;
extern mach_counter_t c_ipc_mqueue_receive_block_kernel;
extern mach_counter_t c_ipc_mqueue_receive_block_user;
extern mach_counter_t c_ipc_mqueue_send_block;
extern mach_counter_t c_net_thread_block;
extern mach_counter_t c_reaper_thread_block;
extern mach_counter_t c_sched_thread_block;
extern mach_counter_t c_stacks_current;
extern mach_counter_t c_stacks_max;
extern mach_counter_t c_stacks_min;
extern mach_counter_t c_swtch_block;
extern mach_counter_t c_swtch_pri_block;
extern mach_counter_t c_thread_switch_block;
extern mach_counter_t c_thread_switch_handoff;
extern mach_counter_t c_vm_fault_page_block_backoff_kernel;
extern mach_counter_t c_vm_fault_page_block_busy_kernel;
extern mach_counter_t c_vm_fault_retry_on_w_prot;
extern mach_counter_t c_vm_fault_wait_on_unlock;
extern mach_counter_t c_vm_map_simplified_lower;
extern mach_counter_t c_vm_map_simplified_upper;
extern mach_counter_t c_vm_map_simplify_called;
extern mach_counter_t c_vm_page_wait_block;
extern mach_counter_t c_vm_pageout_block;
extern mach_counter_t c_vm_pageout_scan_block;
extern mach_counter_t c_vm_fault_retry_on_w_prot;
extern mach_counter_t c_vm_fault_wait_on_unlock;
#endif	/* MACH_COUNTERS */

#endif	/* _KERN_COUNTERS_ */

