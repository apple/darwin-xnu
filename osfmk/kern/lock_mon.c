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
 * Revision 1.1.1.1  1998/09/22 21:05:34  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:55  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.3.19.1  1997/09/22  17:39:46  barbou
 * 	MP+RT: protect cpu_number() usage against preemption.
 * 	[97/09/16            barbou]
 *
 * Revision 1.3.15.4  1995/02/24  15:20:58  alanl
 * 	DIPC: Merge from nmk17b2 to nmk18b8.
 * 	Notes:  major lock cleanup.  Change kdb_lock and printf_lock
 * 	references to conform with simple_lock declaration rules.
 * 	This code is broken and non-portable; its functionality
 * 	should be subsumed in the regular lock package.
 * 	[95/01/16            alanl]
 * 
 * Revision 1.3.17.2  1994/11/10  06:13:19  dwm
 * 	mk6 CR764 - s/spinlock/simple_lock/ (name change only)
 * 	[1994/11/10  05:28:52  dwm]
 * 
 * Revision 1.3.17.1  1994/11/04  10:07:54  dwm
 * 	mk6 CR668 - 1.3b26 merge
 * 	This file is obviously UNUSED - hence broken; merged anyway
 * 	* Revision 1.3.4.4  1994/05/06  18:50:11  tmt
 * 	Merge in DEC Alpha changes to osc1.3b19.
 * 	Merge Alpha changes into osc1.312b source code.
 * 	64bit cleanup.
 * 	* End1.3merge
 * 	[1994/11/04  09:25:58  dwm]
 * 
 * Revision 1.3.15.1  1994/09/23  02:21:48  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:34:22  ezf]
 * 
 * Revision 1.3.13.1  1994/06/09  14:11:30  dswartz
 * 	Preemption merge.
 * 	[1994/06/09  14:07:06  dswartz]
 * 
 * Revision 1.3.4.2  1993/06/09  02:36:12  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:13:15  jeffc]
 * 
 * Revision 1.3  1993/04/19  16:26:56  devrcs
 * 	Fix for TIME_STAMP configuration.
 * 	[Patrick Petit <petit@gr.osf.org>]
 * 	[93/02/11            bernadat]
 * 
 * Revision 1.2  1992/11/25  01:11:05  robert
 * 	integrate changes below for norma_14
 * 
 * 	Philippe Bernadat (bernadat) at gr.osf.org
 * 	Moved MACH_MP_DEBUG code to kern/lock.c
 * 	[1992/11/13  19:33:47  robert]
 * 
 * Revision 1.1  1992/09/30  02:09:28  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.1.2.1.3.1  92/02/18  19:08:45  jeffreyh
 * 	Created. Might need some work if used on anything but a 386.
 * 	[92/02/11  07:56:50  bernadat]
 */
/* CMU_ENDHIST */

/* 
 * Mach Operating System
 * Copyright (c) 1990 Carnegie-Mellon University
 * Copyright (c) 1989 Carnegie-Mellon University
 * All rights reserved.  The CMU software License Agreement specifies
 * the terms and conditions for use and redistribution.
 */

/*
 */

/*
 * 	Support For MP Debugging
 *		if MACH_MP_DEBUG is on, we use alternate locking
 *		routines do detect dealocks
 *	Support for MP lock monitoring (MACH_LOCK_MON).
 *		Registers use of locks, contention.
 *		Depending on hardware also records time spent with locks held
 */

#include <cpus.h>
#include <mach_mp_debug.h>
#include <mach_lock_mon.h>
#include <time_stamp.h>

#include <sys/types.h>
#include <mach/machine/vm_types.h>
#include <mach/boolean.h>
#include <kern/thread.h>
#include <kern/lock.h>


decl_simple_lock_data(extern, kdb_lock)
decl_simple_lock_data(extern, printf_lock)

#if	NCPUS > 1 && MACH_LOCK_MON

#if	TIME_STAMP
extern	time_stamp_t time_stamp;
#else	TIME_STAMP
typedef unsigned int time_stamp_t;
#define	time_stamp 0
#endif	TIME_STAMP

#define LOCK_INFO_MAX	     (1024*32)
#define LOCK_INFO_HASH_COUNT 1024
#define LOCK_INFO_PER_BUCKET	(LOCK_INFO_MAX/LOCK_INFO_HASH_COUNT)


#define HASH_LOCK(lock)	((long)lock>>5 & (LOCK_INFO_HASH_COUNT-1))

struct lock_info {
	unsigned int	success;
	unsigned int	fail;
	unsigned int	masked;
	unsigned int	stack; 
	unsigned int	time;
#if	MACH_SLOCKS
	simple_lock_data_t	* lock;
#endif
	vm_offset_t	caller;
};

struct lock_info_bucket {
	struct lock_info info[LOCK_INFO_PER_BUCKET];
};

struct lock_info_bucket lock_info[LOCK_INFO_HASH_COUNT];
struct lock_info default_lock_info;
unsigned default_lock_stack = 0;

extern int curr_ipl[];



struct lock_info *
locate_lock_info(lock)
simple_lock_data_t	** lock;
{
	struct lock_info *li =  &(lock_info[HASH_LOCK(*lock)].info[0]);
	register i;

	for (i=0; i < LOCK_INFO_PER_BUCKET; i++, li++)
		if (li->lock) {
			if (li->lock == *lock)
				return(li);
		} else {
			li->lock = *lock;
			li->caller = *((vm_offset_t *)lock - 1);
			return(li);
		}
	db_printf("out of lock_info slots\n");
	li = &default_lock_info;
	return(li);
}
		

simple_lock(lock)
decl_simple_lock_data(, *lock)
{
	register struct lock_info *li = locate_lock_info(&lock);

	if (current_thread()) 
		li->stack = current_thread()->lock_stack++;
	mp_disable_preemption();
	if (curr_ipl[cpu_number()])
		li->masked++;
	mp_enable_preemption();
	if (_simple_lock_try(lock))
		li->success++;
	else {
		_simple_lock(lock);
		li->fail++;
	}
	li->time = time_stamp - li->time;
}

simple_lock_try(lock)
decl_simple_lock_data(, *lock)
{
	register struct lock_info *li = locate_lock_info(&lock);

	mp_disable_preemption();
	if (curr_ipl[cpu_number()])
		li->masked++;
	mp_enable_preemption();
	if (_simple_lock_try(lock)) {
		li->success++;
		li->time = time_stamp - li->time;
		if (current_thread())
			li->stack = current_thread()->lock_stack++;
		return(1);
	} else {
		li->fail++;
		return(0);
	}
}

simple_unlock(lock)
decl_simple_lock_data(, *lock)
{
	register time_stamp_t stamp = time_stamp;
	register time_stamp_t *time = &locate_lock_info(&lock)->time;
	register unsigned *lock_stack;

	*time = stamp - *time;
	_simple_unlock(lock);
	if (current_thread()) {
		lock_stack = &current_thread()->lock_stack;
		if (*lock_stack)
			(*lock_stack)--;
	}
}

lip() {
	lis(4, 1, 0);
}

#define lock_info_sort lis

unsigned scurval, ssum;
struct lock_info *sli;

lock_info_sort(arg, abs, count)
{
	struct lock_info *li, mean;
	int bucket = 0;
	int i;
	unsigned max_val;
	unsigned old_val = (unsigned)-1;
	struct lock_info *target_li = &lock_info[0].info[0];
	unsigned sum;
	unsigned empty, total;
	unsigned curval;

	printf("\nSUCCESS	FAIL	MASKED	STACK	TIME	LOCK/CALLER\n");
	if (!count)
		count = 8 ;
	while (count && target_li) {
		empty = LOCK_INFO_HASH_COUNT;
		target_li = 0;
		total = 0;
		max_val = 0;
		mean.success = 0;
		mean.fail = 0;
		mean.masked = 0;
		mean.stack = 0;
		mean.time = 0;
		mean.lock = (simple_lock_data_t *) &lock_info;
		mean.caller = (vm_offset_t) &lock_info;
		for (bucket = 0; bucket < LOCK_INFO_HASH_COUNT; bucket++) {
			li = &lock_info[bucket].info[0];
			if (li->lock)
				empty--;
			for (i= 0; i< LOCK_INFO_PER_BUCKET && li->lock; i++, li++) {
				if (li->lock == &kdb_lock || li->lock == &printf_lock)
					continue;
				total++;
				curval = *((int *)li + arg);
				sum = li->success + li->fail;
				if(!sum && !abs)
					continue;
				scurval = curval;
				ssum = sum;
				sli = li;
				if (!abs) switch(arg) {
				case 0:
					break;
				case 1:
				case 2:
					curval = (curval*100) / sum;
					break;
				case 3:
				case 4:
					curval = curval / sum;
					break;
				}
				if (curval > max_val && curval < old_val) {
					max_val = curval;
					target_li = li;
				}
				if (curval == old_val && count != 0) {
					print_lock_info(li);
					count--;
				}
				mean.success += li->success;
				mean.fail += li->fail;
				mean.masked += li->masked;
				mean.stack += li->stack;
				mean.time += li->time;
			}
		}
		if (target_li)
		        old_val = max_val;
	}
	db_printf("\n%d total locks, %d empty buckets", total, empty );
	if (default_lock_info.success) 
		db_printf(", default: %d", default_lock_info.success + default_lock_info.fail); 
	db_printf("\n");
	print_lock_info(&mean);
}

#define lock_info_clear lic

lock_info_clear()
{
	struct lock_info *li;
	int bucket = 0;
	int i;
	for (bucket = 0; bucket < LOCK_INFO_HASH_COUNT; bucket++) {
		li = &lock_info[bucket].info[0];
		for (i= 0; i< LOCK_INFO_PER_BUCKET; i++, li++) {
			bzero(li, sizeof(struct lock_info));
		}
	}
	bzero(&default_lock_info, sizeof(struct lock_info)); 
}

print_lock_info(li)
struct lock_info *li;
{
	int off;
	int sum = li->success + li->fail;
	db_printf("%d	%d/%d	%d/%d	%d/%d	%d/%d	", li->success,
		   li->fail, (li->fail*100)/sum,
		   li->masked, (li->masked*100)/sum,
		   li->stack, li->stack/sum,
		   li->time, li->time/sum);
	db_search_symbol(li->lock, 0, &off);
	if (off < 1024)
		db_printsym(li->lock, 0);
	else {
		db_printsym(li->caller, 0);
		db_printf("(%X)", li->lock);
	}
	db_printf("\n");
}

#endif	NCPUS > 1 && MACH_LOCK_MON

#if	TIME_STAMP

/*
 *	Measure lock/unlock operations
 */

time_lock(loops)
{
	decl_simple_lock_data(, lock)
	register time_stamp_t stamp;
	register int i;


	if (!loops)
		loops = 1000;
	simple_lock_init(&lock);
	stamp = time_stamp;
	for (i = 0; i < loops; i++) {
		simple_lock(&lock);
		simple_unlock(&lock);
	}
	stamp = time_stamp - stamp;
	db_printf("%d stamps for simple_locks\n", stamp/loops);
#if	MACH_LOCK_MON
	stamp = time_stamp;
	for (i = 0; i < loops; i++) {
		_simple_lock(&lock);
		_simple_unlock(&lock);
        }
	stamp = time_stamp - stamp;
	db_printf("%d stamps for _simple_locks\n", stamp/loops);
#endif	MACH_LOCK_MON
}
#endif	TIME_STAMP





