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
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:35  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:54  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.13.7  1995/02/24  15:19:11  alanl
 * 	Merge with DIPC2_SHARED.
 * 	[1995/02/22  20:31:50  alanl]
 *
 * Revision 1.1.21.1  1994/11/04  10:06:28  dwm
 * 	mk6 CR668 - 1.3b26 merge
 * 	remove unused counters
 * 	* Revision 1.1.2.4  1994/01/06  17:53:55  jeffc
 * 	CR9854 -- Missing exception_raise_state counters
 * 	CR10394 -- instrument vm_map_simplify
 * 	* End1.3merge
 * 	[1994/11/04  09:20:23  dwm]
 * 
 * Revision 1.1.13.5  1994/09/23  02:15:57  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:32:09  ezf]
 * 
 * Revision 1.1.13.4  1994/09/16  06:29:22  dwm
 * 	mk6 CR551 - remove unused SAFE_VM_FAULT pseudo-continuation,
 * 	remove unused args from vm_page_wait, vm_fault(_page).
 * 	Also, fix vm_page_wait counters.
 * 	[1994/09/16  06:23:24  dwm]
 * 
 * Revision 1.1.13.3  1994/09/10  21:45:51  bolinger
 * 	Merge up to NMK17.3
 * 	[1994/09/08  19:57:27  bolinger]
 * 
 * Revision 1.1.13.2  1994/06/21  17:28:40  dlb
 * 	Add two vm_fault counters from latest NMK17 version.
 * 	[94/06/17            dlb]
 * 
 * Revision 1.1.13.1  1994/06/14  16:59:58  bolinger
 * 	Merge up to NMK17.2.
 * 	[1994/06/14  16:53:39  bolinger]
 * 
 * Revision 1.1.8.2  1994/03/17  22:40:02  dwm
 * 	dead code removal:  thread swapping.
 * 	[1994/03/17  21:29:18  dwm]
 * 
 * Revision 1.1.8.1  1993/11/18  18:14:54  dwm
 * 	Coloc: remove continuations entirely;
 * 	[1993/11/18  18:09:54  dwm]
 * 
 * Revision 1.1.2.3  1993/06/07  22:12:34  jeffc
 * 	CR9176 - ANSI C violations: trailing tokens on CPP
 * 	directives, extra semicolons after decl_ ..., asm keywords
 * 	[1993/06/07  19:04:06  jeffc]
 * 
 * Revision 1.1.2.2  1993/06/02  23:35:48  jeffc
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:12:06  jeffc]
 * 
 * Revision 1.1  1992/09/30  02:08:53  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.3  91/05/14  16:40:19  mrt
 * 	Correcting copyright
 * 
 * Revision 2.2  91/03/16  15:15:51  rpd
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

#include <mach_counters.h>

#include <kern/counters.h>

/*
 *	We explicitly initialize the counters to make
 *	them contiguous in the kernel's data space.
 *	This makes them easier to examine with ddb.
 */

mach_counter_t c_thread_invoke_csw = 0;
mach_counter_t c_thread_invoke_hits = 0;
mach_counter_t c_thread_invoke_misses = 0;
mach_counter_t c_thread_invoke_same = 0;
mach_counter_t c_thread_invoke_same_cont = 0;
mach_counter_t c_incoming_interrupts = 0;
mach_counter_t c_syscalls_unix = 0;
mach_counter_t c_syscalls_mach = 0;

#if	MACH_COUNTERS
mach_counter_t c_action_thread_block = 0;
mach_counter_t c_ast_taken_block = 0;
mach_counter_t c_clock_ticks = 0;
mach_counter_t c_dev_io_blocks = 0;
mach_counter_t c_dev_io_tries = 0;
mach_counter_t c_idle_thread_block = 0;
mach_counter_t c_idle_thread_handoff = 0;
mach_counter_t c_io_done_thread_block = 0;
mach_counter_t c_ipc_mqueue_receive_block_kernel = 0;
mach_counter_t c_ipc_mqueue_receive_block_user = 0;
mach_counter_t c_ipc_mqueue_send_block = 0;
mach_counter_t c_net_thread_block = 0;
mach_counter_t c_reaper_thread_block = 0;
mach_counter_t c_sched_thread_block = 0;
mach_counter_t c_stacks_current = 0;
mach_counter_t c_stacks_max = 0;
mach_counter_t c_stacks_min = 0;
mach_counter_t c_swtch_block = 0;
mach_counter_t c_swtch_pri_block = 0;
mach_counter_t c_thread_switch_block = 0;
mach_counter_t c_thread_switch_handoff = 0;
mach_counter_t c_vm_fault_page_block_backoff_kernel = 0;
mach_counter_t c_vm_fault_page_block_busy_kernel = 0;
mach_counter_t c_vm_fault_retry_on_w_prot;
mach_counter_t c_vm_fault_wait_on_unlock;
mach_counter_t c_vm_map_simplified_lower = 0;
mach_counter_t c_vm_map_simplified_upper = 0;
mach_counter_t c_vm_map_simplify_called = 0;
mach_counter_t c_vm_page_wait_block = 0;
mach_counter_t c_vm_pageout_block = 0;
mach_counter_t c_vm_pageout_scan_block = 0;
mach_counter_t c_vm_fault_retry_on_w_prot = 0;
mach_counter_t c_vm_fault_wait_on_unlock = 0;
#endif	/* MACH_COUNTERS */
