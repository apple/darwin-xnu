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
 * Revision 1.1.1.1  1998/03/07 02:25:54  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.12.1  1996/09/17  16:27:00  bruel
 * 	fixed bzero prototype.
 * 	[96/09/17            bruel]
 *
 * Revision 1.1.2.4  1995/10/09  17:13:51  devrcs
 * 	Merged in RT3_SHARED ETAP code.
 * 	[1995/09/13  18:34:15  joe]
 * 
 * Revision 1.1.2.3  1995/09/18  19:13:37  devrcs
 * 	Merged in RT3_SHARED ETAP code.
 * 	[1995/09/13  18:34:15  joe]
 * 
 * Revision 1.1.2.2  1995/01/10  05:11:15  devrcs
 * 	mk6 CR801 - merge up from nmk18b4 to nmk18b7
 * 	patch up spinlock references ==> simplelock
 * 	[1994/12/09  20:54:30  dwm]
 * 
 * 	mk6 CR801 - new file for mk6_shared from cnmk_shared.
 * 	[1994/12/01  21:11:49  dwm]
 * 
 * Revision 1.1.2.1  1994/10/21  18:28:50  joe
 * 	Initial ETAP submission
 * 	[1994/10/20  19:31:33  joe]
 * 
 * $EndLog$
 */
/*
 * File:       etap_pool.c
 *
 *             etap_pool.c contains the functions for maintenance
 *             of the start_data_pool.   The start_data_pool is
 *             used by the ETAP package.  Its primary
 *             objective is to provide start_data_nodes to complex
 *             locks so they can hold start information for read
 *             locks  (since multiple readers can acquire a read
 *             lock).   Each complex lock will maintain a linked
 *             list of these nodes.
 *
 * NOTES:      The start_data_pool is used instead of zalloc to
 *             eliminate complex lock dependancies.  If zalloc was used,
 *             then no complex locks could be used in zalloc code paths.
 *             This is both difficult and unrealistic, since zalloc
 *             allocates memory dynamically. Hence, this dependancy is
 *             eliminated with the use of the statically allocated
 *             start_data_pool.
 *
 */

#include <kern/lock.h>
#include <kern/spl.h>
#include <kern/etap_pool.h>
#include <kern/sched_prim.h>
#include <kern/macro_help.h>

#if	ETAP_LOCK_TRACE

/*
 *  Statically allocate the start data pool,
 *  header and lock.
 */

struct start_data_node  sd_pool [SD_POOL_ENTRIES];  /* static buffer */
start_data_node_t       sd_free_list;   /* pointer to free node list */
int                     sd_sleepers;    /* number of blocked threads */

simple_lock_data_t		sd_pool_lock;


/*
 *  Interrupts must be disabled while the 
 *  sd_pool_lock is taken.
 */

#define pool_lock(s)			\
MACRO_BEGIN				\
	s = splhigh();			\
	simple_lock(&sd_pool_lock);	\
MACRO_END

#define pool_unlock(s)			\
MACRO_BEGIN				\
	simple_unlock(&sd_pool_lock);	\
	splx(s);			\
MACRO_END


/*
 *  ROUTINE:    init_start_data_pool
 *
 *  FUNCTION:   Initialize the start_data_pool:
 *              - create the free list chain for the max 
 *                number of entries.
 *              - initialize the sd_pool_lock
 */

void
init_start_data_pool(void)
{
	int x;

	simple_lock_init(&sd_pool_lock, ETAP_MISC_SD_POOL);
    
	/*
	 *  Establish free list pointer chain
	 */

	for (x=0; x < SD_POOL_ENTRIES-1; x++)
		sd_pool[x].next = &sd_pool[x+1];

	sd_pool[SD_POOL_ENTRIES-1].next = SD_ENTRY_NULL;
	sd_free_list  = &sd_pool[0];
	sd_sleepers   = 0;
}

/*
 *  ROUTINE:    get_start_data_node
 *
 *  FUNCTION:   Returns a free node from the start data pool
 *              to the caller.  If none are available, the
 *              call will block, then try again.
 */

start_data_node_t
get_start_data_node(void)
{
	start_data_node_t avail_node;
	spl_t		  s;

	pool_lock(s);

	/*
	 *  If the pool does not have any nodes available,
	 *  block until one becomes free.
	 */

	while (sd_free_list == SD_ENTRY_NULL) {

		sd_sleepers++;
		assert_wait((event_t) &sd_pool[0], THREAD_UNINT);
		pool_unlock(s);

		printf ("DEBUG-KERNEL: empty start_data_pool\n");
		thread_block(THREAD_CONTINUE_NULL);

		pool_lock(s);
		sd_sleepers--;
	}

	avail_node   = sd_free_list;
	sd_free_list = sd_free_list->next;

	pool_unlock(s);

	bzero ((char *) avail_node, sizeof(struct start_data_node)); 
	avail_node->next = SD_ENTRY_NULL;

	return (avail_node);
}

/*
 *  ROUTINE:    free_start_data_node
 *
 *  FUNCTION:   Releases start data node back to the sd_pool,
 *              so that it can be used again.
 */

void
free_start_data_node (
	start_data_node_t   node)
{
	boolean_t   wakeup = FALSE;
	spl_t	    s;

	if (node == SD_ENTRY_NULL)
		return;

	pool_lock(s);

	node->next   = sd_free_list;
	sd_free_list = node;

	if (sd_sleepers)
		wakeup = TRUE;

	pool_unlock(s);

	if (wakeup)
		thread_wakeup((event_t) &sd_pool[0]);
}

#endif	/* ETAP_LOCK_TRACE */
