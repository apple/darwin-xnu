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
 * Revision 1.1.1.1  1998/09/22 21:05:34  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:55  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.2.19.5  1995/02/24  15:20:29  alanl
 * 	Lock package cleanup.
 * 	[95/02/15            alanl]
 *
 * 	Merge with DIPC2_SHARED.
 * 	[1995/01/05  15:11:02  alanl]
 *
 * Revision 1.2.28.2  1994/11/10  06:12:50  dwm
 * 	mk6 CR764 - s/spinlock/simple_lock/ (name change only)
 * 	[1994/11/10  05:28:35  dwm]
 * 
 * Revision 1.2.28.1  1994/11/04  10:07:40  dwm
 * 	mk6 CR668 - 1.3b26 merge
 * 	* Revision 1.2.2.4  1993/11/08  15:04:18  gm
 * 	CR9710: Updated to new zinit() and zone_change() interfaces.
 * 	* End1.3merge
 * 	[1994/11/04  09:25:48  dwm]
 * 
 * Revision 1.2.19.3  1994/09/23  02:20:52  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:33:57  ezf]
 * 
 * Revision 1.2.19.2  1994/06/14  18:36:36  bolinger
 * 	NMK17.2 merge:  Replace simple_lock ops.
 * 	[1994/06/14  18:35:17  bolinger]
 * 
 * Revision 1.2.19.1  1994/06/14  17:04:23  bolinger
 * 	Merge up to NMK17.2.
 * 	[1994/06/14  16:54:19  bolinger]
 * 
 * Revision 1.2.23.3  1994/10/14  12:24:33  sjs
 * 	Removed krealloc_spinl routine: the newer locking scheme makes it
 * 	obsolete.
 * 	[94/10/13            sjs]
 * 
 * Revision 1.2.23.2  1994/08/11  14:42:46  rwd
 * 	Post merge cleanup
 * 	[94/08/09            rwd]
 * 
 * 	Changed zcollectable to use zchange.
 * 	[94/08/04            rwd]
 * 
 * Revision 1.2.17.2  1994/07/08  01:58:45  alanl
 * 	Change comment to match function name.
 * 	[1994/07/08  01:47:59  alanl]
 * 
 * Revision 1.2.17.1  1994/05/26  16:20:38  sjs
 * 	Added krealloc_spinl: same as krealloc but uses spin locks.
 * 	[94/05/25            sjs]
 * 
 * Revision 1.2.23.1  1994/08/04  02:24:55  mmp
 * 	Added krealloc_spinl: same as krealloc but uses spin locks.
 * 	[94/05/25            sjs]
 * 
 * Revision 1.2.13.1  1994/02/11  14:27:12  paire
 * 	Changed krealloc() to make it work on a MP system. Added a new parameter
 * 	which is the simple lock that should be held while modifying the memory
 * 	area already initialized.
 * 	Change from NMK16.1 [93/09/02            paire]
 * 
 * 	Do not set debug for kalloc zones as default. It wastes
 * 	to much space.
 * 	Change from NMK16.1 [93/08/16            bernadat]
 * 	[94/02/07            paire]
 * 
 * Revision 1.2.2.3  1993/07/28  17:15:44  bernard
 * 	CR9523 -- Prototypes.
 * 	[1993/07/27  20:14:12  bernard]
 * 
 * Revision 1.2.2.2  1993/06/02  23:37:46  jeffc
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:12:59  jeffc]
 * 
 * Revision 1.2  1992/12/07  21:28:42  robert
 * 	integrate any changes below for 14.0 (branch from 13.16 base)
 * 
 * 	Joseph Barrera (jsb) at Carnegie-Mellon University 11-Sep-92
 * 	Added krealloc. Added kalloc_max_prerounded for quicker choice between
 * 	zalloc and kmem_alloc. Renamed MINSIZE to KALLOC_MINSIZE.
 * 	[1992/12/06  19:47:16  robert]
 * 
 * Revision 1.1  1992/09/30  02:09:23  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.9  91/05/14  16:43:17  mrt
 * 	Correcting copyright
 * 
 * Revision 2.8  91/03/16  14:50:37  rpd
 * 	Updated for new kmem_alloc interface.
 * 	[91/03/03            rpd]
 * 
 * Revision 2.7  91/02/05  17:27:22  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  16:14:12  mrt]
 * 
 * Revision 2.6  90/06/19  22:59:06  rpd
 * 	Made the big kalloc zones collectable.
 * 	[90/06/05            rpd]
 * 
 * Revision 2.5  90/06/02  14:54:47  rpd
 * 	Added kalloc_max, kalloc_map_size.
 * 	[90/03/26  22:06:39  rpd]
 * 
 * Revision 2.4  90/01/11  11:43:13  dbg
 * 	De-lint.
 * 	[89/12/06            dbg]
 * 
 * Revision 2.3  89/09/08  11:25:51  dbg
 * 	MACH_KERNEL: remove non-MACH data types.
 * 	[89/07/11            dbg]
 * 
 * Revision 2.2  89/08/31  16:18:59  rwd
 * 	First Checkin
 * 	[89/08/23  15:41:37  rwd]
 * 
 * Revision 2.6  89/08/02  08:03:28  jsb
 * 	Make all kalloc zones 8 MB big. (No more kalloc panics!)
 * 	[89/08/01  14:10:17  jsb]
 * 
 * Revision 2.4  89/04/05  13:03:10  rvb
 * 	Guarantee a zone max of at least 100 elements or 10 pages
 * 	which ever is greater.  Afs (AllocDouble()) puts a great demand
 * 	on the 2048 zone and used to blow away.
 * 	[89/03/09            rvb]
 * 
 * Revision 2.3  89/02/25  18:04:39  gm0w
 * 	Changes for cleanup.
 * 
 * Revision 2.2  89/01/18  02:07:04  jsb
 * 	Give each kalloc zone a meaningful name (for panics);
 * 	create a zone for each power of 2 between MINSIZE
 * 	and PAGE_SIZE, instead of using (obsoleted) NQUEUES.
 * 	[89/01/17  10:16:33  jsb]
 * 
 *
 * 13-Feb-88  John Seamons (jks) at NeXT
 *	Updated to use kmem routines instead of vmem routines.
 *
 * 21-Jun-85  Avadis Tevanian (avie) at Carnegie-Mellon University
 *	Created.
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
/*
 *	File:	kern/kalloc.c
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1985
 *
 *	General kernel memory allocator.  This allocator is designed
 *	to be used by the kernel to manage dynamic memory fast.
 */

#include <zone_debug.h>

#include <mach/boolean.h>
#include <mach/machine/vm_types.h>
#include <mach/vm_param.h>
#include <kern/misc_protos.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <kern/lock.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_map.h>

#ifdef MACH_BSD
zone_t kalloc_zone(vm_size_t);
#endif

vm_map_t kalloc_map;
vm_size_t kalloc_map_size = 16 * 1024 * 1024;
vm_size_t kalloc_max;
vm_size_t kalloc_max_prerounded;

unsigned int kalloc_large_inuse;
vm_size_t    kalloc_large_total;
vm_size_t    kalloc_large_max;

/*
 *	All allocations of size less than kalloc_max are rounded to the
 *	next highest power of 2.  This allocator is built on top of
 *	the zone allocator.  A zone is created for each potential size
 *	that we are willing to get in small blocks.
 *
 *	We assume that kalloc_max is not greater than 64K;
 *	thus 16 is a safe array size for k_zone and k_zone_name.
 *
 *	Note that kalloc_max is somewhat confusingly named.
 *	It represents the first power of two for which no zone exists.
 *	kalloc_max_prerounded is the smallest allocation size, before
 *	rounding, for which no zone exists.
 */

int first_k_zone = -1;
struct zone *k_zone[16];
static char *k_zone_name[16] = {
	"kalloc.1",		"kalloc.2",
	"kalloc.4",		"kalloc.8",
	"kalloc.16",		"kalloc.32",
	"kalloc.64",		"kalloc.128",
	"kalloc.256",		"kalloc.512",
	"kalloc.1024",		"kalloc.2048",
	"kalloc.4096",		"kalloc.8192",
	"kalloc.16384",		"kalloc.32768"
};

/*
 *  Max number of elements per zone.  zinit rounds things up correctly
 *  Doing things this way permits each zone to have a different maximum size
 *  based on need, rather than just guessing; it also
 *  means its patchable in case you're wrong!
 */
unsigned long k_zone_max[16] = {
      1024,		/*      1 Byte  */
      1024,		/*      2 Byte  */
      1024,		/*      4 Byte  */
      1024,		/*      8 Byte  */
      1024,		/*     16 Byte  */
      4096,		/*     32 Byte  */
      4096,		/*     64 Byte  */
      4096,		/*    128 Byte  */
      4096,		/*    256 Byte  */
      1024,		/*    512 Byte  */
      1024,		/*   1024 Byte  */
      1024,		/*   2048 Byte  */
      1024,		/*   4096 Byte  */
      4096,		/*   8192 Byte  */
      64,		/*  16384 Byte  */
      64,		/*  32768 Byte  */
};

/*
 *	Initialize the memory allocator.  This should be called only
 *	once on a system wide basis (i.e. first processor to get here
 *	does the initialization).
 *
 *	This initializes all of the zones.
 */

void
kalloc_init(
	void)
{
	kern_return_t retval;
	vm_offset_t min;
	vm_size_t size;
	register int i;

	retval = kmem_suballoc(kernel_map, &min, kalloc_map_size,
			       FALSE, TRUE, &kalloc_map);
	if (retval != KERN_SUCCESS)
		panic("kalloc_init: kmem_suballoc failed");

	/*
	 *	Ensure that zones up to size 8192 bytes exist.
	 *	This is desirable because messages are allocated
	 *	with kalloc, and messages up through size 8192 are common.
	 */

	if (PAGE_SIZE < 16*1024)
		kalloc_max = 16*1024;
	else
		kalloc_max = PAGE_SIZE;
	kalloc_max_prerounded = kalloc_max / 2 + 1;

	/*
	 *	Allocate a zone for each size we are going to handle.
	 *	We specify non-paged memory.
	 */
	for (i = 0, size = 1; size < kalloc_max; i++, size <<= 1) {
		if (size < KALLOC_MINSIZE) {
			k_zone[i] = 0;
			continue;
		}
		if (size == KALLOC_MINSIZE) {
			first_k_zone = i;
		}
		k_zone[i] = zinit(size, k_zone_max[i] * size, size,
				  k_zone_name[i]);
	}
}

vm_offset_t
kalloc_canblock(
		vm_size_t	size,
		boolean_t       canblock)
{
	register int zindex;
	register vm_size_t allocsize;

	/*
	 * If size is too large for a zone, then use kmem_alloc.
	 * (We use kmem_alloc instead of kmem_alloc_wired so that
	 * krealloc can use kmem_realloc.)
	 */

	if (size >= kalloc_max_prerounded) {
		vm_offset_t addr;

		/* kmem_alloc could block so we return if noblock */
		if (!canblock) {
		  return(0);
		}
		if (kmem_alloc(kalloc_map, &addr, size) != KERN_SUCCESS)
			addr = 0;

		if (addr) {
		        kalloc_large_inuse++;
		        kalloc_large_total += size;

			if (kalloc_large_total > kalloc_large_max)
			        kalloc_large_max = kalloc_large_total;
		}
		return(addr);
	}

	/* compute the size of the block that we will actually allocate */

	allocsize = KALLOC_MINSIZE;
	zindex = first_k_zone;
	while (allocsize < size) {
		allocsize <<= 1;
		zindex++;
	}

	/* allocate from the appropriate zone */

	assert(allocsize < kalloc_max);
	return(zalloc_canblock(k_zone[zindex], canblock));
}

vm_offset_t
kalloc(
       vm_size_t size)
{
  return( kalloc_canblock(size, TRUE) );
}

vm_offset_t
kalloc_noblock(
	       vm_size_t size)
{
  return( kalloc_canblock(size, FALSE) );
}


void
krealloc(
	vm_offset_t	*addrp,
	vm_size_t	old_size,
	vm_size_t	new_size,
	simple_lock_t	lock)
{
	register int zindex;
	register vm_size_t allocsize;
	vm_offset_t naddr;

	/* can only be used for increasing allocation size */

	assert(new_size > old_size);

	/* if old_size is zero, then we are simply allocating */

	if (old_size == 0) {
		simple_unlock(lock);
		naddr = kalloc(new_size);
		simple_lock(lock);
		*addrp = naddr;
		return;
	}

	/* if old block was kmem_alloc'd, then use kmem_realloc if necessary */

	if (old_size >= kalloc_max_prerounded) {
		old_size = round_page(old_size);
		new_size = round_page(new_size);
		if (new_size > old_size) {

			if (kmem_realloc(kalloc_map, *addrp, old_size, &naddr,
					 new_size) != KERN_SUCCESS) {
				panic("krealloc: kmem_realloc");
				naddr = 0;
			}

			simple_lock(lock);
			*addrp = naddr;

			/* kmem_realloc() doesn't free old page range. */
			kmem_free(kalloc_map, *addrp, old_size);

			kalloc_large_total += (new_size - old_size);

			if (kalloc_large_total > kalloc_large_max)
			        kalloc_large_max = kalloc_large_total;
		}
		return;
	}

	/* compute the size of the block that we actually allocated */

	allocsize = KALLOC_MINSIZE;
	zindex = first_k_zone;
	while (allocsize < old_size) {
		allocsize <<= 1;
		zindex++;
	}

	/* if new size fits in old block, then return */

	if (new_size <= allocsize) {
		return;
	}

	/* if new size does not fit in zone, kmem_alloc it, else zalloc it */

	simple_unlock(lock);
	if (new_size >= kalloc_max_prerounded) {
		if (kmem_alloc(kalloc_map, &naddr, new_size) != KERN_SUCCESS) {
			panic("krealloc: kmem_alloc");
			simple_lock(lock);
			*addrp = 0;
			return;
		}
		kalloc_large_inuse++;
		kalloc_large_total += new_size;

		if (kalloc_large_total > kalloc_large_max)
		        kalloc_large_max = kalloc_large_total;
	} else {
		register int new_zindex;

		allocsize <<= 1;
		new_zindex = zindex + 1;
		while (allocsize < new_size) {
			allocsize <<= 1;
			new_zindex++;
		}
		naddr = zalloc(k_zone[new_zindex]);
	}
	simple_lock(lock);

	/* copy existing data */

	bcopy((const char *)*addrp, (char *)naddr, old_size);

	/* free old block, and return */

	zfree(k_zone[zindex], *addrp);

	/* set up new address */

	*addrp = naddr;
}


vm_offset_t
kget(
	vm_size_t	size)
{
	register int zindex;
	register vm_size_t allocsize;

	/* size must not be too large for a zone */

	if (size >= kalloc_max_prerounded) {
		/* This will never work, so we might as well panic */
		panic("kget");
	}

	/* compute the size of the block that we will actually allocate */

	allocsize = KALLOC_MINSIZE;
	zindex = first_k_zone;
	while (allocsize < size) {
		allocsize <<= 1;
		zindex++;
	}

	/* allocate from the appropriate zone */

	assert(allocsize < kalloc_max);
	return(zget(k_zone[zindex]));
}

void
kfree(
	vm_offset_t	data,
	vm_size_t	size)
{
	register int zindex;
	register vm_size_t freesize;

	/* if size was too large for a zone, then use kmem_free */

	if (size >= kalloc_max_prerounded) {
		kmem_free(kalloc_map, data, size);

		kalloc_large_total -= size;
		kalloc_large_inuse--;

		return;
	}

	/* compute the size of the block that we actually allocated from */

	freesize = KALLOC_MINSIZE;
	zindex = first_k_zone;
	while (freesize < size) {
		freesize <<= 1;
		zindex++;
	}

	/* free to the appropriate zone */

	assert(freesize < kalloc_max);
	zfree(k_zone[zindex], data);
}

#ifdef MACH_BSD
zone_t
kalloc_zone(
	vm_size_t       size)
{
	register int zindex = 0;
	register vm_size_t allocsize;

	/* compute the size of the block that we will actually allocate */

	allocsize = size;
	if (size <= kalloc_max) {
		allocsize = KALLOC_MINSIZE;
		zindex = first_k_zone;
		while (allocsize < size) {
			allocsize <<= 1;
			zindex++;
		}
		return (k_zone[zindex]);
	}
	return (ZONE_NULL);
}
#endif



kalloc_fake_zone_info(int *count, vm_size_t *cur_size, vm_size_t *max_size, vm_size_t *elem_size,
		     vm_size_t *alloc_size, int *collectable, int *exhaustable)
{
        *count      = kalloc_large_inuse;
	*cur_size   = kalloc_large_total;
	*max_size   = kalloc_large_max;
	*elem_size  = kalloc_large_total / kalloc_large_inuse;
	*alloc_size = kalloc_large_total / kalloc_large_inuse;
	*collectable = 0;
	*exhaustable = 0;
}

