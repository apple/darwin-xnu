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
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:34  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:54  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.2.4  1995/10/09  17:13:55  devrcs
 * 	Merged RT3_SHARED version into `mainline.'
 * 	[1995/09/13  16:17:31  joe]
 *
 * Revision 1.1.2.3  1995/09/18  19:13:40  devrcs
 * 	Merged RT3_SHARED version into `mainline.'
 * 	[1995/09/13  16:17:31  joe]
 * 
 * Revision 1.1.2.2  1995/01/10  05:11:19  devrcs
 * 	mk6 CR801 - new file for mk6_shared from cnmk_shared.
 * 	[1994/12/01  21:11:51  dwm]
 * 
 * Revision 1.1.2.1  1994/10/21  18:28:53  joe
 * 	Initial ETAP submission
 * 	[1994/10/20  19:31:35  joe]
 * 
 * $EndLog$
 */
/* 
 * File : etap_pool.h
 *
 *	  The start_data_node structure is primarily needed to hold
 *	  start information for read locks (since multiple readers
 * 	  can acquire a read lock).  For consistency, however, the
 * 	  structure is used for write locks as well.  Each complex
 *	  lock will maintain a linked list of these structures.
 */

#ifndef _KERN_ETAP_POOL_H_
#define _KERN_ETAP_POOL_H_

#include <kern/etap_options.h>
#include <mach/etap.h>
#include <mach/boolean.h>

#if	ETAP_LOCK_TRACE

#include <cpus.h>
#include <mach/clock_types.h>
#include <mach/kern_return.h>
#include <kern/misc_protos.h>

struct start_data_node {
	unsigned int	thread_id;           /* thread id                    */
	etap_time_t	start_hold_time;     /* time of last acquisition     */
	etap_time_t	start_wait_time;     /* time of first miss           */
	unsigned int	start_pc;            /* pc of acquiring function     */
	unsigned int	end_pc;              /* pc of relinquishing function */
	struct start_data_node *next;	     /* pointer to next list entry   */
};

typedef struct start_data_node* start_data_node_t;

/*
 *  The start_data_node pool is statically
 *  allocated and privatly maintained
 */
 
#define SD_POOL_ENTRIES     (NCPUS * 256)

extern  void			init_start_data_pool(void);
extern  start_data_node_t	get_start_data_node(void);
extern  void			free_start_data_node(start_data_node_t);

#else	/* ETAP_LOCK_TRACE */
typedef boolean_t start_data_node_t;
#define get_start_data_node()
#define free_start_start_data_node(node)
#endif	/* ETAP_LOCK_TRACE  */

#define SD_ENTRY_NULL	((start_data_node_t) 0)

#endif  /* _KERN_ETAP_POOL_H_ */
