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
 * $Log: default_pager.c,v $
 * Revision 1.7  2001/01/15 20:03:32  lindak
 * Merged PR-2523198-116-3 into Cheetah from magee which fixes all of the
 * following:
 * 2430517 2445360 2511207 2513779 2523198 2581705 2585290 2595323 2596060
 * 2597427 2601360
 *
 * Revision 1.6.260.1  2001/01/14 10:02:17  jmagee
 * A conglomeration of fixes related to races in the termination of processes
 *
 * Bug #2430517 - Race condition between port death and BSD causes wait4() to fail
 * Bug #2445360 - Process hung in sigsuspend waiting for SIGCHLD
 * Bug #2511207 - IPC thread_act disable too "loose"
 * Bug #2513779 - thread_continue is NOT a continuation routine
 * Bug #2523198 - shuttleless activation during thread creation
 * Bug #2581705 - 4F8: panic in task_info
 * Bug #2585290 - PANIC: thread_deallocate: released last reference on map
 * Bug #2595323 - Cheetah4K9: Lost user context
 * Bug #2596060 - can't get mutex interlock in vm_map_deallocate / load_machfile
 * Bug #2601360 - killing CrashReporter causes process hangs
 * Submitted by: jmagee
 * Reviewed by: Youngworth Umesh Ramesh
 *
 * Revision 1.6  2000/10/13 06:21:06  lindak
 * Merged PR-2425995-2 into Cheetah (youngworth Need Pager and VM support for
 * 64 bit address space)
 *
 * Revision 1.5.804.1  2000/10/12 17:29:25  youngwor
 * Changes for base 64 bit data path support
 *
 * Revision 1.5.782.1  2000/10/12 14:02:32  youngwor
 * Changes to support 64 bit data path throughout the kernel.
 * Bug #: 2425995
 * Submitted by: Chris Youngworth
 * Reviewed by:
 *
 * Revision 1.5  2000/01/26 05:56:22  wsanchez
 * Add APSL
 *
 * Revision 1.4  1999/07/20 02:55:34  lindak
 * Merged PR-2291281-1 into Beaker (magee Kernel Components kobject groupings)
 *
 * Revision 1.3.674.1  1999/07/20 00:33:02  jmagee
 * Workaround for partial EMMI components work
 *
 * Revision 1.3  1999/02/24 16:55:12  wsanchez
 * PR-2308031
 *
 * Revision 1.2.168.1  1999/02/23 20:43:52  semeria
 * Component Header files phase 1
 *
 * Revision 1.2  1998/12/01 00:24:41  wsanchez
 * Merged in CDY_DP1 (chris: default pager)
 *
 * Revision 1.1.2.2  1998/11/25 21:32:17  youngwor
 * fix errant comment format
 *
 * Revision 1.1.2.1  1998/11/24 22:39:57  youngwor
 * Check-in of support for the in-kernel default pager
 *
 * Revision 1.1.1.1  1998/03/07 02:26:31  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.2.84.2  1997/03/27  18:45:15  barbou
 * 	submit adidtional picco changes
 * 	[1996/09/12  22:09:29  robert]
 * 	AXP pool merge.
 * 	[97/02/25            barbou]
 *
 * Revision 1.2.84.1  1996/11/29  16:54:38  stephen
 * 	nmklinux_1.0b3_shared into pmk1.1
 * 	Added -v option (verbose flag) and tests before warning printfs
 * 	[1996/07/29  12:25:54  stephen]
 * 
 * Revision 1.2.34.16  1996/07/31  06:41:45  paire
 * 	Merged with nmk20b7_shared (1.2.77.1)
 * 	[96/05/30            paire]
 * 
 * Revision 1.2.77.1  1996/04/12  06:30:58  paire
 * 	Changed signature of default_pager_thread to (void ()(void *)).
 * 	Replaced bzero() by memset().
 * 	[96/01/30            paire]
 * 
 * Revision 1.2.34.15  1995/08/21  20:52:09  devrcs
 * 	Initialize dpt_initialized_p element of
 * 	default_pager_thread_tb and set it to true after thread starts
 * 	up.  Wait until all threads have signalled ready before
 * 	telling the bootstrap process that it's ok to go ahead.
 * 	[95/07/10            randys]
 * 
 * Revision 1.2.34.14  1995/06/12  18:44:00  dwm
 * 	ri-osc CR1394 - allow argument from bootstrap to set cluster size,
 * 	Usage: default_pager clsize=4 sd0b, for example
 * 	[1995/06/12  18:40:21  dwm]
 * 
 * Revision 1.2.34.13  1995/05/31  07:55:10  emcmanus
 * 	Use mach_msg instead of mach_msg_overwrite_trap so that message
 * 	operations can be interrupted without provoking a default-pager
 * 	panic.  Remote gdb does this.
 * 	[1995/05/31  07:54:21  emcmanus]
 * 
 * Revision 1.2.34.12  1995/05/25  20:36:39  mmp
 * 	Removed TEMPORARILY_USE_OLD_INIT and the !TEMPORARILY_USE_OLD_INIT
 * 	code.  The change to use m_o_init was not temporary.
 * 	[1995/05/25  19:59:17  mmp]
 * 
 * Revision 1.2.34.11  1995/04/07  18:50:57  barbou
 * 	Merged into mainline:
 * 	Revision 1.2.34.10  1995/02/27  18:24:08  mmp
 * 	   Replaced m_o_notify with m_o_init; used m_o_change_attributes
 * 	   instead of m_o_establish; removed m_o_rejected.
 * 	   [1995/02/27  18:22:40  mmp]
 * 	Revision 1.2.34.9  1995/02/23  21:15:48  alanl
 * 	   Use system_priority instead of server_priority.  Fix locking
 * 	   with regards to pager_extend!
 * 	   Merged with DIPC2_SHARED.
 * 	   [1995/02/23  21:14:55  alanl]
 * 	[95/03/08            barbou]
 * 
 * 	VM-MK6 Merge.
 * 	Started from the modified b26 file.
 * 	Integrated the following MK6 changes:
 * 
 * 	Fix ri-osc CR846:  Avoid use of fixed BASEPRI_SYSTEM; use new
 * 	host_info() interface to determine priority dynamically.
 * 	[1994/12/23  15:39:32  bolinger]
 * 	mk6 CR668 - 1.3b26 merge
 * 	Correct local btodb() def; change port_to_ds() et al. to work
 * 	with port names returned by current merged kernel.
 * 	[1994/12/03  02:10:30  bolinger]
 * 	mk6 CR668 - 1.3b26 merge
 * 	Did not bring forward PAGING_MEMORY support.  Did bring forward
 * 	NORMA support -- can be deleted when proven no longer needed.
 * 	[1994/11/10  15:32:12  bolinger]
 * 	[95/01/10            barbou]
 * 	[95/03/08            barbou]
 * 
 * Revision 1.2.56.2  1995/02/13  14:40:41  barbou
 * 	VM-MK6 Merge.
 * 	Started from the modified b26 file.
 * 	Integrated the following MK6 changes:
 * 
 * 	Fix ri-osc CR846:  Avoid use of fixed BASEPRI_SYSTEM; use new
 * 	host_info() interface to determine priority dynamically.
 * 	[1994/12/23  15:39:32  bolinger]
 * 	mk6 CR668 - 1.3b26 merge
 * 	Correct local btodb() def; change port_to_ds() et al. to work
 * 	with port names returned by current merged kernel.
 * 	[1994/12/03  02:10:30  bolinger]
 * 	mk6 CR668 - 1.3b26 merge
 * 	Did not bring forward PAGING_MEMORY support.  Did bring forward
 * 	NORMA support -- can be deleted when proven no longer needed.
 * 	[1994/11/10  15:32:12  bolinger]
 * 	[95/01/10            barbou]
 * 
 * Revision 1.2.46.3  1994/11/02  14:57:23  barbou
 * 	Use new task_swappable() interface to make our task unswappable.
 * 	[94/11/02            barbou]
 * 
 * Revision 1.2.46.2  1994/10/10  15:28:48  barbou
 * 	VM Merge - Default Pager Clustering.
 * 
 * 	Also split this file in three:
 * 		default_pager.c contains code that deals with threads and
 * 			incoming messages.
 * 		dp_memory_object.c contains memory object management code.
 * 		dp_backing_store.c contains backing store management code.
 * 	[94/10/10            barbou]
 * 
 * Revision 1.2.6.23  1994/05/16  16:43:50  jph
 * 	CR8809 -- Fix messages when paging space is exhausted.
 * 	CR10905 -- Disallow overlapped paging areas.
 * 	[1994/05/16  16:43:04  jph]
 * 
 * Revision 1.2.6.22  1994/04/01  18:42:34  jph
 * 	CR10550 -- Add backing store info interfaces.
 * 	CR10718 -- Fix pagein error path.
 * 	[1994/04/01  18:40:13  jph]
 * 
 * Revision 1.2.6.21  1994/03/04  18:34:49  jeffc
 * 	CR10636 -- delete all NMK15_COMPAT support.
 * 	[1994/03/04  14:50:44  jeffc]
 * 
 * Revision 1.2.6.20  1994/02/16  14:22:24  jph
 * 	CR10554 -- Multi-page requests now handled, albeit crudely.
 * 	Fixed leak in data_request for partial page reads.
 * 	Tidied up code to be at least consistent.
 * 	Fixed ASSERTIONS option and bad assert (name_refs in terminate).
 * 	[1994/02/16  14:20:47  jph]
 * 
 * Revision 1.2.6.19  1994/02/07  22:41:25  jph
 * 	Merged with changes from 1.2.6.18
 * 	[1994/02/07  22:40:25  jph]
 * 
 * 	CR10433 -- Upgrade default pager.
 * 	Add device argument capability.
 * 	Removed defunct file_io.h reference.
 * 	Replaced pager_{lock_init,lock,unlock,lock_try} macros.
 * 	Moved cthreads globals to top of file from middle.
 * 	Removed "id" field of "partition_t" - not needed.
 * 	Added "device", "offset", "count" and "record_shift" fields
 * 	 to "partition_t" to record backing store device info.
 * 	Removed "p_read", "p_write" and "p_private" fields from
 * 	 "partition_t" - Unneeded filesystem abstraction.
 * 	Merge "struct dstruct" fields into the "struct dpager",
 * 	 delete "struct dstruct" and "default_pager_t".
 * 	Added "struct bstruct" and "all_backing_store" to hold list
 * 	 of all backing store ports.
 * 	Simplify arguments to create_paging_partition().
 * 	Delete part_id(), add_paging_file() and default_pager_setup() routines.
 * 	Added backing_store_port_alloc(), log2() routine.
 * 	Added vm_page_mask and vm_page_shift to augment vm_page_size.
 * 	[1994/02/07  22:28:15  jph]
 * 
 * Revision 1.2.6.18  1994/02/01  19:44:38  collins
 * 	CR9926: Set the default pager scheduling policy to round-robin with
 * 	a priority of BASEPRI_SYSTEM.
 * 	[1994/02/01  14:56:05  collins]
 * 
 * Revision 1.2.6.17  1994/01/27  17:04:21  chasb
 * 	Expand Copyright markers
 * 	[1994/01/27  16:32:40  chasb]
 * 
 * Revision 1.2.6.16  1994/01/26  18:42:03  collins
 * 	CR10474: Change any_t to void *.
 * 	[1994/01/26  18:39:47  collins]
 * 
 * Revision 1.2.6.15  1994/01/25  17:02:40  jeffc
 * 	CR10107 -- Mach spec compliance - eliminate copy_call
 * 	[1994/01/24  21:23:43  jeffc]
 * 
 * Revision 1.2.6.14  1994/01/20  16:58:18  meissner
 * 	CR 10468 - Make initialization have proper number of {}'s.
 * 	[1994/01/19  19:02:57  meissner]
 * 
 * Revision 1.2.6.13  1993/12/03  20:53:51  jvs
 * 	Trusted pager throttling changes.  CR 10108
 * 	[1993/12/03  20:53:09  jvs]
 * 
 * Revision 1.2.6.12  1993/12/02  17:22:34  jph
 * 	CR10254 -- Fix warning about unused ledger/ security ports.
 * 	[1993/12/02  15:59:30  jph]
 * 
 * Revision 1.2.6.11  1993/11/24  20:30:31  jph
 * 	CR9801 brezak merge, ledgers, security and NMK15_COMPAT
 * 	[1993/11/23  22:52:33  jph]
 * 
 * 	New bootstrap_ports() signature.
 * 	[1993/11/23  20:58:25  jph]
 * 
 * Revision 1.2.6.10  1993/11/23  18:05:47  watkins
 * 	Increment send right for object in mo_notify.
 * 	[1993/11/23  18:04:35  watkins]
 * 
 * Revision 1.2.6.9  1993/11/16  21:49:42  watkins
 * 	Remove pager_name argument from memory_object_terminate
 * 	and memory_object_create, as per spec.  Remove mo_init
 * 	and flesh out mo_notify. Extend maps for reads beyond the
 * 	end. Add xpr traces.
 * 	[1993/11/16  21:29:43  watkins]
 * 
 * Revision 1.2.6.8  1993/10/20  18:50:13  gm
 * 	CR9928: Remove bootstrap_port lookup.
 * 	CR9990: Remove code that deletes initial stack.
 * 	[1993/10/20  12:34:40  gm]
 * 
 * Revision 1.2.6.7  1993/10/08  17:32:08  jeffc
 * 	CR9508 - Delete typed IPC code
 * 	[1993/09/28  17:27:02  jeffc]
 * 
 * Revision 1.2.6.6  1993/10/08  16:08:14  jeffc
 * 	CR9792 - delete obsolete memory_object_data_write message.
 * 	[1993/10/08  15:59:49  jeffc]
 * 
 * Revision 1.2.6.5  1993/10/05  21:57:08  watkins
 * 	New memory object attribute interfaces comply with spec.
 * 	[1993/10/05  21:53:27  watkins]
 * 
 * Revision 1.2.6.4  1993/09/16  18:38:39  jeffc
 * 	CR9792 - delete defunct EMMI interfaces
 * 	[1993/09/15  20:02:07  jeffc]
 * 
 * Revision 1.2.6.3  1993/08/05  17:57:08  gm
 * 	CR9627: Moved def_pager_setup and bootstrap code here.  Removed
 * 	EXT_PAGER code.  Fixed up code problems with more agressive warning
 * 	in gcc.  Added full prototype support.  Changed internal interfaces
 * 	that had unions as return values to take pointer arguments instead.
 * 	Delete bootstrap code since their is now a separate bootstrap task.
 * 	Removed set_ras_address() since it should be provided by a machine
 * 	dependent file on machines that need it.  Changed to get priv
 * 	ports using mach interfaces instead of argv.
 * 	[1993/07/09  19:11:36  gm]
 * 
 * Revision 1.2.6.2  1993/06/09  02:08:56  gm
 * 	Conditionalize no_senders_check for untyped IPC.  CR #9058.
 * 	[1993/05/11  18:19:30  rod]
 * 
 * 	Add header files to pick up definitions of Mach traps and
 * 	wiring interfaces.
 * 	[1993/05/14  15:37:15  jeffc]
 * 
 * 	Fix ANSI C violations and warnings.
 * 	[1993/05/13  21:05:22  jeffc]
 * 
 * 	Remove dependency on own pathname.
 * 	[1993/05/12  17:53:18  jeffc]
 * 
 * Revision 1.2  1993/04/19  15:07:02  devrcs
 * 	Added trailer support to untyped ipc.	[travos@osf.org, fdr@osf.org]
 * 	[1993/04/06  18:14:54  travos]
 * 
 * 	Merge untyped ipc:
 * 	Added untyped support to bootstrap_compat().
 * 	[1993/04/02  17:37:59  rod]
 * 
 * 	Share more code when building the in kernel version
 * 	of the pager.
 * 	[93/03/19            bernadat]
 * 
 * 	Fix memory_object_synchronize hang.
 * 	[1993/03/15  13:21:59  david]
 * 
 * 	memory_object_synchronize define twice
 * 	[1993/03/03  15:09:30  david]
 * 
 * 	remerge with 1.1.2.3
 * 	[1993/03/03  14:26:14  david]
 * 
 * 	Add memory_object_synchronize stub
 * 	[1993/03/03  11:04:05  david]
 * 
 * 	Fixed a deadlock bug in internal pager configuration.
 * 	[93/02/25            bernadat]
 * 
 * 	moved out of mach_kernel directory
 * 	[1993/02/27  13:56:35  david]
 * 
 * 	Modified to use the same new interface (default_pager_object.defs) for both
 * 	configurations.
 * 	[1993/02/17  13:40:18  bruel]
 * 
 * 	Added stubs for new exception interface.
 * 	[93/02/11            bruel]
 * 
 * 	Modified from mk78.
 * 	Added the ufs_pager_option.
 * 	[93/01/29            bruel]
 * 
 * 	Yup, it works. Undefine CHECKSUM, debug and
 * 	DEBUG_READER_CONFLICTS again.
 * 	[92/12/03            ian]
 * 
 * 	Update CHECKSUM to work with current dp_map union.
 * 	[92/12/03            ian]
 * 
 * 	Define debug CHECKSUM and DEBUG_READER_CONFLICTS.
 * 	[92/11/28            ian]
 * 
 * 	Eliminated use of old memory object calls (set_attributes, data_write, data_provided).
 * 	[92/09/25            jsb]
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.12  92/07/20  13:32:18  cmaeda
 * 	Added private version of set_ras_address for fast_tas support.
 * 	[92/05/11  14:31:52  cmaeda]
 * 
 * Revision 2.11  92/05/05  10:03:46  danner
 * 	For merge purposes, backed-out the unstable stuff.
 * 	[92/05/04  11:12:01  af]
 * 
 * 	Now we can page an object across partitions.
 * 	Initial rough ideas about automatically extending
 * 	paging space.
 * 	[92/03/11  02:23:58  af]
 * 
 * Revision 2.10  92/03/06  13:58:48  rpd
 * 	Fixed pager_dealloc_page calls in pager_dealloc (from af).
 * 	Removed chatty printfs.
 * 	[92/03/06            rpd]
 * 
 * Revision 2.9  92/03/05  15:58:35  rpd
 * 	Changed PAGEMAP_ENTRIES from 128 to 64.  From af.
 * 	[92/03/05            rpd]
 * 
 * Revision 2.8  92/03/03  12:12:04  rpd
 * 	Changed to catch exception messages and handle bootstrap requests.
 * 	Added partition_init.
 * 	[92/03/03            rpd]
 * 
 * Revision 2.7  92/02/25  11:22:38  elf
 * 	Accept creation of objects bigger than any one partition, in
 * 	anticipation of the code that will page across partitions.
 * 	Since we are at it, also proceed with no paging partitions:
 * 	rely on killing unlucky objects on pageouts.
 * 	[92/02/25            af]
 * 
 * Revision 2.6  92/02/23  23:00:31  elf
 * 	Copyright updated, corrected history.
 * 	[92/02/23            elf]
 * 
 * Revision 2.5  92/02/23  22:25:35  elf
 * 	Improved handling of big objects, fixed a deadlock in
 * 	object relocation, improved printouts.
 * 	Now only crash if out of memory, otherwise use the old
 * 	code that just marked the object as in-error.
 * 	[92/02/23  13:25:49  af]
 * 
 * 	As per jsb instructions, removed all NORMA conditionals.
 * 	Rename port names to odd values, a trivial heuristic that
 * 	makes name conflicts even more unlikely.
 * 	[92/02/22            af]
 * 
 * 	Refined the port name conflict problem.  Instead of renaming
 * 	ports that we send to, just set aside the memory that we cannot
 * 	use.  When objects get deleted put back the memory in the system.
 * 	[92/02/21            af]
 * 
 * 	Added renaming of request and name ports (from af).
 * 	[92/02/21            danner]
 * 
 * 	Many changes. Now supports adding/removing paging files, it does
 * 	not immediately panic if a paging file fills up but relocates the
 * 	object elsewhere, it uses the precious attribute in data_supply
 * 	to reduce paging space usage (under USE_PRECIOUS conditional,
 * 	enabled).
 * 	[92/02/19  17:29:54  af]
 * 
 * 	Two mods: changed bitmap ops to work one int at a time rather
 * 	than one byte at a time.  This helps under load, e.g. when the
 * 	paging file is large and busy. Second mod to use port-to-pointer
 * 	casting in lookups, rather than hash+list searching.  This not
 * 	only helps under load (I see >600 objects on my pmax) but also
 * 	increases parallelism a little.
 * 	Shrunk the code size by one page in the process.
 * 	[92/02/14  01:44:23  af]
 * 
 * Revision 2.4  92/01/23  15:19:41  rpd
 * 	Changed to not include mig server interfaces.
 * 	[92/01/23            rpd]
 * 
 * Revision 2.3  92/01/14  16:43:14  rpd
 * 	Moved mach/default_pager_object.defs to mach/default_pager.defs.
 * 	Revised default_pager_info etc. for their new definitions.
 * 	Removed (now) unnecessary #define's to rename kernel functions.
 * 	[92/01/13            rpd]
 * 	Added page_size to default_pager_info.
 * 	Added default_pager_object_pages.
 * 	[92/01/03            rpd]
 * 
 * 	Updated to handle name ports from memory_object_create.
 * 	Changed to remember the name ports associated with objects.
 * 	Changed default_pager_objects to return the name ports.
 * 	[91/12/28            rpd]
 * 
 * 	Added default_pager_objects.
 * 	[91/12/15            rpd]
 * 
 * Revision 2.2  92/01/03  19:56:21  dbg
 * 	Simplify locking.
 * 	[91/10/02            dbg]
 * 
 * 	Convert to run outside of kernel.
 * 	[91/09/04            dbg]
 * 
 * Revision 2.17  91/08/29  13:44:27  jsb
 * 	A couple quick changes for NORMA_VM. Will be fixed later.
 * 
 * Revision 2.16  91/08/28  16:59:29  jsb
 * 	Fixed the default values of default_pager_internal_count and
 * 	default_pager_external_count.
 * 	[91/08/28            rpd]
 * 
 * Revision 2.15  91/08/28  11:09:32  jsb
 * 	Added seqnos_memory_object_change_completed.
 * 	From dlb: use memory_object_data_supply for pagein when buffer is
 * 	going to be deallocated.
 * 	From me: don't use data_supply under NORMA_VM (will be fixed).
 * 	[91/08/26  14:30:07  jsb]
 * 
 * 	Changed to process requests in parallel when possible.
 * 
 * 	Don't bother keeping track of mscount.
 * 	[91/08/16            rpd]
 * 	Added default_pager_info.
 * 	[91/08/15            rpd]
 * 
 * 	Added sequence numbers to the memory object interface.
 * 	Changed to use no-senders notifications.
 * 	Changed to keep track of port rights and not use mach_port_destroy.
 * 	Added dummy supply-completed and data-return stubs.
 * 	[91/08/13            rpd]
 * 
 * Revision 2.14  91/05/18  14:28:32  rpd
 * 	Don't give privileges to threads handling external objects.
 * 	[91/04/06            rpd]
 * 	Enhanced to use multiple threads, for performance and to avoid
 * 	a deadlock caused by default_pager_object_create.
 * 	Added locking to partitions.
 * 	Added locking to pager_port_hashtable.
 * 	Changed pager_port_hash to something reasonable.
 * 	[91/04/03            rpd]
 * 
 * Revision 2.13  91/05/14  15:21:41  mrt
 * 	Correcting copyright
 * 
 * Revision 2.12  91/03/16  14:41:26  rpd
 * 	Updated for new kmem_alloc interface.
 * 	Fixed memory_object_create to zero the new pager structure.
 * 	[91/03/03            rpd]
 * 	Removed thread_swappable.
 * 	[91/01/18            rpd]
 * 
 * Revision 2.11  91/02/05  17:00:49  mrt
 * 	Changed to new copyright
 * 	[91/01/28  14:54:31  mrt]
 * 
 * Revision 2.10  90/09/09  14:31:01  rpd
 * 	Use decl_simple_lock_data.
 * 	[90/08/30            rpd]
 * 
 * Revision 2.9  90/08/27  21:44:51  dbg
 * 	Add definitions of NBBY, howmany.
 * 	[90/07/16            dbg]
 * 
 * Revision 2.8  90/06/02  14:45:22  rpd
 * 	Changed default_pager_object_create so the out argument
 * 	is a poly send right.
 * 	[90/05/03            rpd]
 * 	Removed references to keep_wired_memory.
 * 	[90/04/29            rpd]
 * 	Converted to new IPC.
 * 	Removed data-request queue.
 * 	[90/03/26  21:30:57  rpd]
 * 
 * Revision 2.7  90/03/14  21:09:58  rwd
 * 	Call default_pager_object_server and add
 * 	default_pager_object_create
 * 	[90/01/22            rwd]
 * 
 * Revision 2.6  90/01/11  11:41:08  dbg
 * 	Use bootstrap-task print routines.
 * 	[89/12/20            dbg]
 * 
 * 	De-lint.
 * 	[89/12/06            dbg]
 * 
 * Revision 2.5  89/12/08  19:52:03  rwd
 * 	Turn off CHECKSUM
 * 	[89/12/06            rwd]
 * 
 * Revision 2.4  89/10/23  12:01:54  dbg
 * 	Change pager_read_offset and pager_write_offset to return block
 * 	number as function result.  default_read()'s caller must now
 * 	deallocate data if not the same as the data buffer passed in.
 * 	Add register declarations and clean up loops a bit.
 * 	[89/10/19            dbg]
 * 
 * 	Oops - nothing like having your debugging code introduce bugs...
 * 	[89/10/17            dbg]
 * 
 * Revision 2.3  89/10/16  15:21:59  rwd
 * 	debugging: checksum pages in each object.
 * 	[89/10/04            dbg]
 * 
 * Revision 2.2  89/09/08  11:22:06  dbg
 * 	Wait for default_partition to be set.
 * 	[89/09/01            dbg]
 * 
 * 	Modified to call outside routines for read and write.
 * 	Removed disk structure.  Added part_create.
 * 	Reorganized code.
 * 	[89/07/11            dbg]
 * 
 */
/* CMU_ENDHIST */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
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
 * 	Default pager.
 * 		Threads management.
 *		Requests handling.
 */

#include "default_pager_internal.h"
#include <kern/host.h>
#include <kern/ledger.h>
#include <mach/host_info.h>
#include <ipc/ipc_space.h>
#include <vm/vm_kern.h>

char	my_name[] = "(default pager): ";

#if	DEFAULT_PAGER_DEBUG
int	debug_mask = 0;
#endif	/* DEFAULT_PAGER_DEBUG */

/*
 * Use 16 Kbyte stacks instead of the default 64K.
 * Use 4 Kbyte waiting stacks instead of the default 8K.
 */

vm_size_t	cthread_stack_size = 16 *1024;
extern vm_size_t cthread_wait_stack_size;

unsigned long long	vm_page_mask;
int		vm_page_shift;

int 		norma_mk;

boolean_t	verbose;

/* task_t default_pager_self; */	/* Our task port. */
mutex_t			dpt_lock;       /* lock for the dpt array struct */
default_pager_thread_t	**dpt_array;

MACH_PORT_FACE default_pager_default_set; /* Port set for "default" thread. */
MACH_PORT_FACE default_pager_default_port;/* Port for memory_object_create. */
MACH_PORT_FACE default_pager_internal_set; /* Port set for internal objects. */
MACH_PORT_FACE default_pager_external_set; /* Port set for external objects. */

#define DEFAULT_PAGER_INTERNAL_COUNT	(4)


/* Memory created by default_pager_object_create should mostly be resident. */
#define DEFAULT_PAGER_EXTERNAL_COUNT	(2)

unsigned int	default_pager_internal_count = DEFAULT_PAGER_INTERNAL_COUNT;
/* Number of "internal" threads. */
unsigned int	default_pager_external_count = DEFAULT_PAGER_EXTERNAL_COUNT;
/* Number of "external" threads. */

/*
 * Forward declarations.
 */
boolean_t default_pager_notify_server(mach_msg_header_t *,
				      mach_msg_header_t *);
boolean_t default_pager_demux_object(mach_msg_header_t *,
				     mach_msg_header_t *);
boolean_t default_pager_demux_default(mach_msg_header_t *,
				      mach_msg_header_t *);
default_pager_thread_t *start_default_pager_thread(int, boolean_t);
void	default_pager(void);
void	default_pager_thread(void *);
void	default_pager_initialize(void);
void	default_pager_set_policy(MACH_PORT_FACE);
boolean_t	dp_parse_argument(char *);	/* forward; */
unsigned int	d_to_i(char *);			/* forward; */


extern int vstruct_def_clshift;


/*
 * Initialize and Run the default pager
 */
void
default_pager(void)
{
	int			i, id;
	static char		here[] = "default_pager";
	mach_msg_options_t 	server_options;
	default_pager_thread_t	dpt;
	kern_return_t kr;



	/*
	 * Give me space for the thread array and zero it.
	 */
	i = default_pager_internal_count + default_pager_external_count + 1;
	dpt_array = (default_pager_thread_t **)
	    kalloc(i * sizeof(default_pager_thread_t *));
	memset(dpt_array, 0, i * sizeof(default_pager_thread_t *));

	/* Setup my thread structure.  */
	id = 0;
	dpt.dpt_buffer = 0;
	dpt.dpt_internal = FALSE;
	dpt.dpt_initialized_p = TRUE;
	dpt_array[0] = &dpt;

	/*
	 * Now we create the threads that will actually
	 * manage objects.
	 */

	for (i = 0; i < default_pager_internal_count; i++) {
		dpt_array[id] = (default_pager_thread_t *)
				kalloc(sizeof (default_pager_thread_t));
		if (dpt_array[id] == NULL)
	 		Panic("alloc pager thread");
		kr = vm_allocate(kernel_map, &((dpt_array[id])->dpt_buffer),
				 vm_page_size << vstruct_def_clshift, TRUE);
		if (kr != KERN_SUCCESS)
			Panic("alloc thread buffer");
		kr = vm_map_wire(kernel_map, (dpt_array[id])->dpt_buffer, 
			((dpt_array[id])->dpt_buffer)
					+(vm_page_size << vstruct_def_clshift), 
			VM_PROT_DEFAULT,
			FALSE);
		if (kr != KERN_SUCCESS)
			Panic("wire thread buffer");
		(dpt_array[id])->dpt_internal = TRUE;
		(dpt_array[id])->dpt_initialized_p = TRUE;
		(dpt_array[id])->checked_out = FALSE;
		id++;
	}
	DPT_LOCK_INIT(dpt_lock);
}






/* simple utility: only works for 2^n */
int
local_log2(
	unsigned int n)
{
	register int	i = 0;

	if(n == 0) return 0;

	while ((n & 1) == 0) {
		i++;
		n >>= 1;
	}
	return i;
}




/* another simple utility, d_to_i(char*) supporting only decimal
 * and devoid of range checking; obscure name chosen deliberately
 * to avoid confusion with semantic-rich POSIX routines */
unsigned int
d_to_i(char * arg)
{
    unsigned int rval = 0;
    char ch;

    while ((ch = *arg++) && ch >= '0' && ch <= '9') {
	rval *= 10;
	rval += ch - '0';
    }
    return(rval);
}




/*
 * Check for non-disk-partition arguments of the form
 *	attribute=argument
 * returning TRUE if one if found
 */
boolean_t dp_parse_argument(char *av)
{
	char *rhs = av;
	static char	here[] = "dp_parse_argument";

	/* Check for '-v' flag */

	if (av[0] == '-' && av[1] == 'v' && av[2] == 0) {
		verbose = TRUE ;
		return TRUE;
	}

	/*
	 * If we find a '=' followed by an argument in the string,
	 * check for known arguments
	 */
	while (*rhs && *rhs != '=')
		rhs++;
	if (*rhs && *++rhs) {
		/* clsize=N pages */
		if (strprefix(av,"cl")) {
			if (!bs_set_default_clsize(d_to_i(rhs)))
				dprintf(("Bad argument (%s) - ignored\n", av));
			return(TRUE);
		}
		/* else if strprefix(av,"another_argument")) {
			handle_another_argument(av);
			return(TRUE);
		} */
	}
	return(FALSE);
}

int
start_def_pager(char *bs_device)
{
	int			my_node;
/*
	MACH_PORT_FACE		master_device_port;
*/
	MACH_PORT_FACE		security_port;
/*
	MACH_PORT_FACE		root_ledger_wired;
	MACH_PORT_FACE		root_ledger_paged;
*/
	static char		here[] = "main";
	int			need_dp_init = 1;



/*
	default_pager_host_port = ipc_port_make_send(realhost.host_priv_self);
	master_device_port = ipc_port_make_send(master_device_port);
	root_ledger_wired = ipc_port_make_send(root_wired_ledger_port);
	root_ledger_paged = ipc_port_make_send(root_paged_ledger_port);
*/
	security_port = ipc_port_make_send(realhost.host_security_self);


#if NORMA_VM
	norma_mk = 1;
#else
	norma_mk = 0;
#endif


	/* setup read buffers, etc */
	default_pager_initialize();
	default_pager();
}

/*
 * Return TRUE if string 2 is a prefix of string 1.
 */     
boolean_t       
strprefix(register const char *s1, register const char *s2)
{               
        register int    c;
                
        while ((c = *s2++) != '\0') {
            if (c != *s1++) 
                return (FALSE);
        }       
        return (TRUE);
}


kern_return_t
default_pager_info(
	MACH_PORT_FACE		pager,
	default_pager_info_t	*infop)
{
	vm_size_t	pages_total, pages_free;

	if (pager != default_pager_default_port)
		return KERN_INVALID_ARGUMENT; 

	bs_global_info(&pages_total, &pages_free);

	infop->dpi_total_space = ptoa(pages_total);
	infop->dpi_free_space = ptoa(pages_free);
	infop->dpi_page_size = vm_page_size;

	return KERN_SUCCESS;
}


void
default_pager_initialize()
{
	kern_return_t		kr;
	static char		here[] = "default_pager_initialize";


	/*
	 * Exported DMM port.
	 */
	default_pager_default_port = ipc_port_alloc_kernel();


	/*
	 * Export pager interfaces.
	 */
#ifdef	USER_PAGER
	if ((kr = netname_check_in(name_server_port, "UserPager",
				   default_pager_self,
				   default_pager_default_port))
	    != KERN_SUCCESS) {
		dprintf(("netname_check_in returned 0x%x\n", kr));
		exit(1);
	}
#else	/* USER_PAGER */
	{
		int clsize;
		ipc_port_t DMM;

		DMM = ipc_port_make_send(default_pager_default_port);
		clsize = (vm_page_size << vstruct_def_clshift);
		kr = host_default_memory_manager(host_priv_self(), &DMM, clsize);
		if ((kr != KERN_SUCCESS) || (DMM != MACH_PORT_NULL))
			Panic("default memory manager");

	}
#endif	/* USER_PAGER */


	/*
	 * Vm variables.
	 */
	vm_page_mask = vm_page_size - 1;
	vm_page_shift = local_log2(vm_page_size);

	/*
	 * List of all vstructs.
	 */
	VSL_LOCK_INIT();
	queue_init(&vstruct_list.vsl_queue);
	queue_init(&vstruct_list.vsl_leak_queue);
	vstruct_list.vsl_count = 0;

	VSTATS_LOCK_INIT(&global_stats.gs_lock);

	bs_initialize();
}

