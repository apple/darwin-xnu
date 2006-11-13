/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */
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
 *	Default pager.
 *		General definitions.
 */

#ifndef	_DEFAULT_PAGER_INTERNAL_H_
#define _DEFAULT_PAGER_INTERNAL_H_

#include <default_pager/diag.h>
#include <default_pager/default_pager_types.h>
#include <mach/mach_types.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_types.h>
#include <ipc/ipc_space.h>
#include <kern/lock.h>
#include <kern/kalloc.h>
#include <kern/thread.h>
#include <vm/vm_kern.h>
#include <device/device_types.h>

/*
 * Default option settings.
 */
#ifndef	PARALLEL
#define	PARALLEL	1
#endif

#ifndef	CHECKSUM
#define	CHECKSUM	0
#endif

#define MACH_PORT_FACE mach_port_t

#if 0
#ifndef	USE_PRECIOUS
#define	USE_PRECIOUS	TRUE
#endif
#endif

#ifdef	USER_PAGER
#define UP(stuff)	stuff
#else	/* USER_PAGER */
#define UP(stuff)
#endif	/* USER_PAGER */

#ifndef MACH_KERNEL
extern struct mutex dprintf_lock;
#define PRINTF_LOCK_INIT()	mutex_init(&dprintf_lock)
#define PRINTF_LOCK()		mutex_lock(&dprintf_lock)
#define PRINTF_UNLOCK()		mutex_unlock(&dprintf_lock)
#endif

#ifndef MACH_KERNEL
#define dprintf(args)							\
	do {								\
		PRINTF_LOCK();						\
		printf("%s[%d]: ", my_name, dp_thread_id());		\
		printf args;						\
		PRINTF_UNLOCK();					\
	} while (0)
#else
#define dprintf(args)						\
	do {							\
		printf("%s[KERNEL]: ", my_name);		\
		printf args;					\
	} while (0)
#endif

/*
 * Debug.
 */
__private_extern__ char	my_name[];

#define DEFAULT_PAGER_DEBUG	0

#if	DEFAULT_PAGER_DEBUG

extern int	debug_mask;
#define	DEBUG_MSG_EXTERNAL	0x00000001
#define DEBUG_MSG_INTERNAL	0x00000002
#define DEBUG_MO_EXTERNAL	0x00000100
#define DEBUG_MO_INTERNAL	0x00000200
#define DEBUG_VS_EXTERNAL	0x00010000
#define DEBUG_VS_INTERNAL	0x00020000
#define DEBUG_BS_EXTERNAL	0x01000000
#define DEBUG_BS_INTERNAL	0x02000000

#define DP_DEBUG(level, args)						\
	do {								\
		if (debug_mask & (level)) 				\
			dprintf(args); 					\
	} while (0)

#define ASSERT(expr)							\
	do {								\
		if (!(expr))						\
#ifndef MACH_KERNEL
			panic("%s[%d]%s: assertion failed in %s line %d: %s",\
			      my_name, dp_thread_id(), here,		\
			      __FILE__, __LINE__, # expr);		\
#else
		  panic("%s[KERNEL]: assertion failed in %s line %d: %s",\
			      my_name, __FILE__, __LINE__, # expr); \
#endif
	} while (0)

#else	/* DEFAULT_PAGER_DEBUG */

#define DP_DEBUG(level, args)
#define ASSERT(clause)

#endif	/* DEFAULT_PAGER_DEBUG */

#ifndef MACH_KERNEL
extern char *mach_error_string(kern_return_t);
#endif

#define MIN(a,b)	(((a) < (b)) ? (a) : (b))

#define	PAGER_SUCCESS	0
#define	PAGER_FULL	1
#define	PAGER_ERROR	2

/*
 * VM and IPC globals.
 */
#ifdef MACH_KERNEL
#define vm_page_size page_size
#else
extern vm_object_size_t	vm_page_size;
#endif
extern unsigned long long	vm_page_mask;
extern int		vm_page_shift;

#ifndef MACH_KERNEL
#define	ptoa(p)	((p)*vm_page_size)
#define	atop(a)	((a)/vm_page_size)
#endif
#define	howmany(a,b)	(((a) + (b) - 1)/(b))

extern memory_object_default_t	default_pager_object;

#ifdef MACH_KERNEL
extern mutex_t		dpt_lock;	/* Lock for the dpt array */
extern int	default_pager_internal_count;
extern MACH_PORT_FACE	default_pager_host_port;
/* extern task_t		default_pager_self; */  /* dont need or want */
extern MACH_PORT_FACE	default_pager_internal_set;
extern MACH_PORT_FACE	default_pager_external_set;
extern MACH_PORT_FACE	default_pager_default_set;
#else
extern mach_port_t	default_pager_host_port;
extern task_port_t	default_pager_self;
extern mach_port_t	default_pager_internal_set;
extern mach_port_t	default_pager_external_set;
extern mach_port_t	default_pager_default_set;
#endif

typedef struct default_pager_thread {
#ifndef MACH_KERNEL
	cthread_t	dpt_thread;	/* Server thread. */
#endif
	vm_offset_t	dpt_buffer;	/* Read buffer. */
	boolean_t	dpt_internal;	/* Do we handle internal objects? */
#ifndef MACH_KERNEL
	int		dpt_id;		/* thread id for printf */
#else
	int		checked_out;	
#endif
	boolean_t	dpt_initialized_p; /* Thread is ready for requests.  */
} default_pager_thread_t;

#ifdef MACH_KERNEL
extern default_pager_thread_t	**dpt_array;
#endif

/*
 * Global statistics.
 */
struct {
	unsigned int	gs_pageout_calls;	/* # pageout calls */
	unsigned int	gs_pagein_calls;	/* # pagein calls */
	unsigned int	gs_pages_in;		/* # pages paged in (total) */
	unsigned int	gs_pages_out;		/* # pages paged out (total) */
	unsigned int	gs_pages_unavail;	/* # zero-fill pages */
	unsigned int	gs_pages_init;		/* # page init requests */
	unsigned int	gs_pages_init_writes;	/* # page init writes */
	VSTATS_LOCK_DECL(gs_lock)
} global_stats;
#define GSTAT(clause)	VSTATS_ACTION(&global_stats.gs_lock, (clause))

/*
 * Cluster related definitions.
 * Clusters are sized in number of pages per cluster.
 * Cluster sizes must be powers of two.
 *
 * These numbers are related to the struct vs_map,
 * defined below.
 */
#define MAX_CLUSTER_SIZE 8
#define MAX_CLUSTER_SHIFT 3
#define NO_CLSIZE 0

/*
 * bit map related macros
 */
#define	NBBY		8	/* bits per byte XXX */
#define BYTEMASK	0xff
#define setbit(a,i)	(*(((char *)(a)) + ((i)/NBBY)) |= 1<<((i)%NBBY))
#define clrbit(a,i)	(*(((char *)(a)) + ((i)/NBBY)) &= ~(1<<((i)%NBBY)))
#define isset(a,i)	(*(((char *)(a)) + ((i)/NBBY)) & (1<<((i)%NBBY)))
#define isclr(a,i)	((*(((char *)(a)) + ((i)/NBBY)) & (1<<((i)%NBBY))) == 0)

/*
 *	Default Pager.
 *		Backing Store Management.
 */

#define BS_MAXPRI	4
#define BS_MINPRI	0
#define BS_NOPRI	-1
#define BS_FULLPRI	-2

/*
 * Mapping between backing store port and backing store object.
 */
struct backing_store {
	queue_chain_t	bs_links;	/* link in backing_store_list */
#ifdef MACH_KERNEL
	mutex_t		bs_lock;	/* lock for the structure */
#else
	struct mutex	bs_lock;	/* lock for the structure */
#endif
	MACH_PORT_FACE	bs_port;	/* backing store port */
	int		bs_priority;
	int		bs_clsize;	/* cluster size in pages */

	/* statistics */
	unsigned int	bs_pages_free;		/* # unallocated pages */
	unsigned int	bs_pages_total;		/* # pages (total) */
	unsigned int	bs_pages_in;		/* # page read requests */
	unsigned int	bs_pages_in_fail;	/* # page read errors */
	unsigned int	bs_pages_out;		/* # page write requests */
	unsigned int	bs_pages_out_fail;	/* # page write errors */
};
typedef struct backing_store 	*backing_store_t;
#define	BACKING_STORE_NULL	((backing_store_t) 0)
#define BS_STAT(bs, clause)	VSTATS_ACTION(&(bs)->bs_lock, (clause))

#ifdef MACH_KERNEL
#define BS_LOCK_INIT(bs)	mutex_init(&(bs)->bs_lock, 0)
#else
#define BS_LOCK_INIT(bs)	mutex_init(&(bs)->bs_lock)
#endif
#define BS_LOCK(bs)		mutex_lock(&(bs)->bs_lock)
#define BS_UNLOCK(bs)		mutex_unlock(&(bs)->bs_lock)

struct backing_store_list_head {
	queue_head_t	bsl_queue;
#ifdef MACH_KERNEL
	mutex_t 	bsl_lock;
#else
	struct mutex 	bsl_lock;
#endif
};
extern struct backing_store_list_head	backing_store_list;
extern int	backing_store_release_trigger_disable;

#ifdef MACH_KERNEL
#define	BSL_LOCK_INIT()	mutex_init(&backing_store_list.bsl_lock, 0)
#else
#define	BSL_LOCK_INIT()	mutex_init(&backing_store_list.bsl_lock)
#endif
#define BSL_LOCK()	mutex_lock(&backing_store_list.bsl_lock)
#define BSL_UNLOCK()	mutex_unlock(&backing_store_list.bsl_lock)

/*
 * 	Paging segment management.
 * 	Controls allocation of blocks within paging area.
 */
struct paging_segment {
	/* device management */
	union {
		MACH_PORT_FACE	dev;		/* Port to device */
	 	struct vnode	*vnode;		/* vnode for bs file */
	} storage_type;
	unsigned int	ps_segtype;	/* file type or partition */
	MACH_PORT_FACE	ps_device;	/* Port to device */
	vm_offset_t	ps_offset;	/* Offset of segment within device */
	vm_offset_t	ps_recnum;	/* Number of device records in segment*/
	unsigned int	ps_pgnum;	/* Number of pages in segment */
	unsigned int	ps_record_shift;/* Bit shift: pages to device records */

	/* clusters and pages */
	unsigned int	ps_clshift;	/* Bit shift: clusters to pages */
	unsigned int	ps_ncls;	/* Number of clusters in segment */
	unsigned int	ps_clcount;	/* Number of free clusters */
	unsigned int	ps_pgcount;	/* Number of free pages */
	unsigned long	ps_hint;	/* Hint of where to look next. */

	/* bitmap */
#ifdef MACH_KERNEL
	mutex_t		ps_lock;	/* Lock for contents of struct */
#else
	struct mutex	ps_lock;	/* Lock for contents of struct */
#endif
	unsigned char	*ps_bmap;	/* Map of used clusters */
	
	/* backing store */
	backing_store_t	ps_bs;		/* Backing store segment belongs to */

	boolean_t	ps_going_away;	/* Destroy attempt in progress */
};

#define ps_vnode	storage_type.vnode
#define ps_device	storage_type.dev
#define PS_PARTITION 1
#define PS_FILE	2

typedef struct paging_segment *paging_segment_t;

#define PAGING_SEGMENT_NULL	((paging_segment_t) 0)

#ifdef MACH_KERNEL
#define PS_LOCK_INIT(ps)	mutex_init(&(ps)->ps_lock, 0)
#else
#define PS_LOCK_INIT(ps)	mutex_init(&(ps)->ps_lock)
#endif
#define PS_LOCK(ps)		mutex_lock(&(ps)->ps_lock)
#define PS_UNLOCK(ps)		mutex_unlock(&(ps)->ps_lock)

typedef unsigned int	pseg_index_t;

#define	INVALID_PSEG_INDEX	((pseg_index_t)-1)
#define NULL_PSEG_INDEX		((pseg_index_t) 0)
/*
 * MAX_PSEG_INDEX value is related to struct vs_map below.
 * "0" is reserved for empty map entries (no segment).
 */
#define MAX_PSEG_INDEX	63	/* 0 is reserved for empty map */
#define MAX_NUM_PAGING_SEGMENTS MAX_PSEG_INDEX

/* paging segments array */
extern paging_segment_t	paging_segments[MAX_NUM_PAGING_SEGMENTS];
#ifdef MACH_KERNEL
extern mutex_t paging_segments_lock;
#else
extern struct mutex paging_segments_lock;
#endif
extern int	paging_segment_count;	/* number of active paging segments */
extern int	paging_segment_max;	/* highest used paging segment index */
extern int ps_select_array[DEFAULT_PAGER_BACKING_STORE_MAXPRI+1];

#ifdef MACH_KERNEL
#define	PSL_LOCK_INIT()	mutex_init(&paging_segments_lock, 0)
#else
#define	PSL_LOCK_INIT()	mutex_init(&paging_segments_lock)
#endif
#define PSL_LOCK()	mutex_lock(&paging_segments_lock)
#define PSL_UNLOCK()	mutex_unlock(&paging_segments_lock)

/*
 * Vstruct manipulation.  The vstruct is the pager's internal
 * representation of vm objects it manages.  There is one vstruct allocated
 * per vm object.
 *
 * The following data structures are defined for vstruct and vm object
 * management.
 */

/*
 * vs_map
 * A structure used only for temporary objects.  It is the element
 * contained in the vs_clmap structure, which contains information
 * about which clusters and pages in an object are present on backing
 * store (a paging file).
 * Note that this structure and its associated constants may change
 * with minimal impact on code.  The only function which knows the
 * internals of this structure is ps_clmap().
 *
 * If it is necessary to change the maximum number of paging segments
 * or pages in a cluster, then this structure is the one most
 * affected.   The constants and structures which *may* change are:
 *	MAX_CLUSTER_SIZE
 *	MAX_CLUSTER_SHIFT
 *	MAX_NUM_PAGING_SEGMENTS
 *	VSTRUCT_DEF_CLSHIFT
 *	struct vs_map and associated macros and constants (VSM_*)
 *	  (only the macro definitions need change, the exported (inside the
 *	   pager only) interfaces remain the same; the constants are for
 *	   internal vs_map manipulation only).
 *	struct clbmap (below).
 */
struct vs_map {
	unsigned int	vsmap_entry:23,		/* offset in paging segment */
			vsmap_psindex:8,	/* paging segment */
			vsmap_error:1,
			vsmap_bmap:16,
			vsmap_alloc:16;
};

typedef struct vs_map *vs_map_t;


#define	VSM_ENTRY_NULL	0x7fffff

/*
 * Exported macros for manipulating the vs_map structure --
 * checking status, getting and setting bits.
 */
#define	VSCLSIZE(vs)		(1UL << (vs)->vs_clshift)
#define	VSM_ISCLR(vsm)		(((vsm).vsmap_entry == VSM_ENTRY_NULL) &&   \
					((vsm).vsmap_error == 0))
#define	VSM_ISERR(vsm)		((vsm).vsmap_error)
#define	VSM_SETCLOFF(vsm, val)	((vsm).vsmap_entry = (val))
#define	VSM_SETERR(vsm, err)	((vsm).vsmap_error = 1,   \
					(vsm).vsmap_entry = (err))
#define	VSM_GETERR(vsm)		((vsm).vsmap_entry)
#define	VSM_SETPG(vsm, page)	((vsm).vsmap_bmap |= (1 << (page)))
#define	VSM_CLRPG(vsm, page)	((vsm).vsmap_bmap &= ~(1 << (page)))
#define	VSM_SETPS(vsm, psindx)	((vsm).vsmap_psindex = (psindx))
#define	VSM_PSINDEX(vsm)	((vsm).vsmap_psindex)
#define	VSM_PS(vsm)		paging_segments[(vsm).vsmap_psindex]
#define	VSM_BMAP(vsm)		((vsm).vsmap_bmap)
#define	VSM_CLOFF(vsm)		((vsm).vsmap_entry)
#define	VSM_CLR(vsm)		((vsm).vsmap_entry = VSM_ENTRY_NULL,   \
					(vsm).vsmap_psindex = 0,   \
					(vsm).vsmap_error = 0,	   \
					(vsm).vsmap_bmap = 0,	   \
					(vsm).vsmap_alloc = 0)
#define	VSM_ALLOC(vsm)		((vsm).vsmap_alloc)
#define	VSM_SETALLOC(vsm, page)	((vsm).vsmap_alloc |= (1 << (page)))
#define	VSM_CLRALLOC(vsm, page)	((vsm).vsmap_alloc &= ~(1 << (page)))

/*
 * Constants and macros for dealing with vstruct maps,
 * which comprise vs_map structures, which
 * map vm objects to backing storage (paging files and clusters).
 */
#define CLMAP_THRESHOLD	512 	/* bytes */
#define	CLMAP_ENTRIES		(CLMAP_THRESHOLD/sizeof(struct vs_map))
#define	CLMAP_SIZE(ncls)	(ncls*sizeof(struct vs_map))

#define	INDIRECT_CLMAP_ENTRIES(ncls) (((ncls-1)/CLMAP_ENTRIES) + 1)
#define INDIRECT_CLMAP_SIZE(ncls) (INDIRECT_CLMAP_ENTRIES(ncls) * sizeof(struct vs_map *))
#define INDIRECT_CLMAP(size)	(CLMAP_SIZE(size) > CLMAP_THRESHOLD)

#define RMAPSIZE(blocks) 	(howmany(blocks,NBBY))

#define CL_FIND 1
#define CL_ALLOC 2

/*
 * clmap
 *
 * A cluster map returned by ps_clmap.  It is an abstracted cluster of
 * pages.  It gives the caller information about the cluster
 * desired.  On read it tells the caller if a cluster is mapped, and if so,
 * which of its pages are valid.  It should not be referenced directly,
 * except by  ps_clmap; macros should be used.  If the number of pages
 * in a cluster needs to be more than 32, then the struct clbmap must
 * become larger.
 */
struct clbmap {
	unsigned int	clb_map;
};

struct clmap {
	paging_segment_t cl_ps;		/* paging segment backing cluster */
	int		cl_numpages;	/* number of valid pages */
	struct clbmap	cl_bmap;	/* map of pages in cluster */
	int		cl_error;	/* cluster error value */
	struct clbmap	cl_alloc;	/* map of allocated pages in cluster */
};

#define  CLMAP_ERROR(clm)	(clm).cl_error
#define  CLMAP_PS(clm)		(clm).cl_ps
#define  CLMAP_NPGS(clm)	(clm).cl_numpages
#define	 CLMAP_ISSET(clm,i)	((1<<(i))&((clm).cl_bmap.clb_map))
#define  CLMAP_ALLOC(clm)	(clm).cl_alloc.clb_map
/*
 * Shift off unused bits in a partial cluster
 */
#define  CLMAP_SHIFT(clm,vs)	\
	(clm)->cl_bmap.clb_map >>= (VSCLSIZE(vs) - (clm)->cl_numpages)
#define  CLMAP_SHIFTALLOC(clm,vs)	\
	(clm)->cl_alloc.clb_map >>= (VSCLSIZE(vs) - (clm)->cl_numpages)

typedef struct vstruct_alias {
	int *name;
	struct vstruct *vs;
} vstruct_alias_t;

#ifdef MACH_KERNEL
#define DPT_LOCK_INIT(lock)	mutex_init(&(lock), 0)
#define DPT_LOCK(lock)		mutex_lock(&(lock))
#define DPT_UNLOCK(lock)	mutex_unlock(&(lock))
#define DPT_SLEEP(lock, e, i)	thread_sleep_mutex(&(lock), (event_t)(e), i)
#define VS_LOCK_TYPE		hw_lock_data_t
#define VS_LOCK_INIT(vs)	hw_lock_init(&(vs)->vs_lock)
#define VS_TRY_LOCK(vs)		(VS_LOCK(vs),TRUE)
#define VS_LOCK(vs)		hw_lock_lock(&(vs)->vs_lock)
#define VS_UNLOCK(vs)		hw_lock_unlock(&(vs)->vs_lock)
#define VS_MAP_LOCK_TYPE	mutex_t
#define VS_MAP_LOCK_INIT(vs)	mutex_init(&(vs)->vs_map_lock, 0)
#define VS_MAP_LOCK(vs)		mutex_lock(&(vs)->vs_map_lock)
#define VS_MAP_TRY_LOCK(vs)	mutex_try(&(vs)->vs_map_lock)
#define VS_MAP_UNLOCK(vs)	mutex_unlock(&(vs)->vs_map_lock)
#else
#define VS_LOCK_TYPE		struct mutex
#define VS_LOCK_INIT(vs)	mutex_init(&(vs)->vs_lock, 0)
#define VS_TRY_LOCK(vs)		mutex_try(&(vs)->vs_lock)
#define VS_LOCK(vs)		mutex_lock(&(vs)->vs_lock)
#define VS_UNLOCK(vs)		mutex_unlock(&(vs)->vs_lock)
#define VS_MAP_LOCK_TYPE	struct mutex
#define VS_MAP_LOCK_INIT(vs)	mutex_init(&(vs)->vs_map_lock)
#define VS_MAP_LOCK(vs)		mutex_lock(&(vs)->vs_map_lock)
#define VS_MAP_TRY_LOCK(vs)	mutex_try(&(vs)->vs_map_lock)
#define VS_MAP_UNLOCK(vs)	mutex_unlock(&(vs)->vs_map_lock)
#endif


/*
 * VM Object Structure:  This is the structure used to manage
 * default pager object associations with their control counter-
 * parts (VM objects).
 */
typedef struct vstruct {
	int		 	*vs_mem_obj;	/* our memory obj - temp */
	int			vs_mem_obj_ikot;/* JMM:fake ip_kotype() */
	memory_object_control_t vs_control;	/* our mem obj control ref */
	VS_LOCK_TYPE		vs_lock;	/* data for the lock */

	/* JMM - Could combine these first two in a single pending count now */
	unsigned int		vs_next_seqno;	/* next sequence num to issue */
	unsigned int		vs_seqno;	/* Pager port sequence number */
	unsigned int		vs_readers;	/* Reads in progress */
	unsigned int		vs_writers;	/* Writes in progress */

#ifdef MACH_KERNEL
	int
	/* boolean_t */		vs_waiting_seqno:1,	/* to wait on seqno */
	/* boolean_t */		vs_waiting_read:1, 	/* waiting on reader? */
	/* boolean_t */		vs_waiting_write:1,	/* waiting on writer? */
	/* boolean_t */		vs_waiting_async:1,	/* waiting on async? */
	/* boolean_t */		vs_indirect:1,		/* map indirect? */
	/* boolean_t */		vs_xfer_pending:1;	/* xfer out of seg? */
#else
	event_t			vs_waiting_seqno;/* to wait on seqno */
	event_t			vs_waiting_read; /* to wait on readers */
	event_t			vs_waiting_write;/* to wait on writers */
	event_t			vs_waiting_async;/* to wait on async_pending */
	int			vs_indirect:1,	/* Is the map indirect ? */
				vs_xfer_pending:1; /* xfering out of a seg ? */
#endif

	unsigned int		vs_async_pending;/* pending async write count */
	unsigned int		vs_errors;	/* Pageout error count */
	unsigned int		vs_references;	/* references */

	queue_chain_t		vs_links;	/* Link in pager-wide list */

	unsigned int		vs_clshift;	/* Bit shift: clusters->pages */
	unsigned int		vs_size;	/* Object size in clusters */
#ifdef MACH_KERNEL
	mutex_t		vs_map_lock;	/* to protect map below */
#else
	struct mutex	vs_map_lock;	/* to protect map below */
#endif
	union {
		struct vs_map	*vsu_dmap;	/* Direct map of clusters */
		struct vs_map	**vsu_imap;	/* Indirect map of clusters */
	} vs_un;
} *vstruct_t;

#define vs_dmap vs_un.vsu_dmap
#define vs_imap vs_un.vsu_imap

#define VSTRUCT_NULL	((vstruct_t) 0)

__private_extern__ void vs_async_wait(vstruct_t);

#if PARALLEL
__private_extern__ void vs_lock(vstruct_t);
__private_extern__ void vs_unlock(vstruct_t);
__private_extern__ void vs_start_read(vstruct_t);
__private_extern__ void vs_finish_read(vstruct_t);
__private_extern__ void vs_wait_for_readers(vstruct_t);
__private_extern__ void vs_start_write(vstruct_t);
__private_extern__ void vs_finish_write(vstruct_t);
__private_extern__ void vs_wait_for_writers(vstruct_t);
__private_extern__ void vs_wait_for_sync_writers(vstruct_t);
#else	/* PARALLEL */
#define	vs_lock(vs)
#define	vs_unlock(vs)
#define	vs_start_read(vs)
#define	vs_wait_for_readers(vs)
#define	vs_finish_read(vs)
#define	vs_start_write(vs)
#define	vs_wait_for_writers(vs)
#define	vs_wait_for_sync_writers(vs)
#define	vs_finish_write(vs)
#endif /* PARALLEL */

/*
 * Data structures and variables dealing with asynchronous
 * completion of paging operations.
 */
/*
 * vs_async
 * 	A structure passed to ps_write_device for asynchronous completions.
 * 	It contains enough information to complete the write and
 *	inform the VM of its completion.
 */
struct vs_async {
	struct vs_async	*vsa_next;	/* pointer to next structure */
	vstruct_t	vsa_vs;		/* the vstruct for the object */
	vm_offset_t	vsa_addr;	/* the vaddr of the data moved */
	vm_offset_t	vsa_offset;	/* the object offset of the data */
	vm_size_t	vsa_size;	/* the number of bytes moved */
	paging_segment_t vsa_ps;	/* the paging segment used */
	int		vsa_flags;	/* flags */
	int		vsa_error;	/* error, if there is one */
	mutex_t		vsa_lock;
	MACH_PORT_FACE	reply_port;	/* associated reply port */
};

/*
 * flags values.
 */
#define VSA_READ	0x0001
#define VSA_WRITE	0x0002
#define VSA_TRANSFER	0x0004

/*
 * List of all vstructs.  A specific vstruct is
 * found directly via its port, this list is
 * only used for monitoring purposes by the
 * default_pager_object* calls
 */
struct vstruct_list_head {
	queue_head_t	vsl_queue;
#ifdef MACH_KERNEL
	mutex_t		vsl_lock;
#else
	struct mutex	vsl_lock;
#endif
	int		vsl_count;	/* saves code */
};

__private_extern__ struct vstruct_list_head	vstruct_list;

__private_extern__ void vstruct_list_insert(vstruct_t vs);
__private_extern__ void vstruct_list_delete(vstruct_t vs);


#ifdef MACH_KERNEL
#define VSL_LOCK_INIT()	mutex_init(&vstruct_list.vsl_lock, 0)
#else
#define VSL_LOCK_INIT()	mutex_init(&vstruct_list.vsl_lock)
#endif
#define VSL_LOCK()	mutex_lock(&vstruct_list.vsl_lock)
#define VSL_LOCK_TRY()	mutex_try(&vstruct_list.vsl_lock)
#define VSL_UNLOCK()	mutex_unlock(&vstruct_list.vsl_lock)
#define VSL_SLEEP(e,i)	thread_sleep_mutex((e), &vstruct_list.vsl_lock, (i))

#ifdef MACH_KERNEL
__private_extern__ zone_t	vstruct_zone;
#endif

/*
 * Create port alias for vstruct address.
 *
 * We assume that the last two bits of a vstruct address will be zero due to
 * memory allocation restrictions, hence are available for use as a sanity
 * check.
 */
#ifdef MACH_KERNEL

#define ISVS ((int *)123456)
#define mem_obj_is_vs(_mem_obj_)					\
	(((_mem_obj_) != NULL) && ((_mem_obj_)->pager == ISVS))
#define mem_obj_to_vs(_mem_obj_)					\
	((vstruct_t)(_mem_obj_))
#define vs_to_mem_obj(_vs_) ((memory_object_t)(_vs_))
#define vs_lookup(_mem_obj_, _vs_)					\
	do {								\
	if (!mem_obj_is_vs(_mem_obj_))					\
		panic("bad dp memory object");				\
	_vs_ = mem_obj_to_vs(_mem_obj_);				\
	} while (0)
#define vs_lookup_safe(_mem_obj_, _vs_)					\
	do {								\
	if (!mem_obj_is_vs(_mem_obj_))					\
		_vs_ = VSTRUCT_NULL;					\
	else								\
		_vs_ = mem_obj_to_vs(_mem_obj_);			\
	} while (0)
#else

#define	vs_to_port(_vs_)	(((vm_offset_t)(_vs_))+1)
#define	port_to_vs(_port_)	((vstruct_t)(((vm_offset_t)(_port_))&~3))
#define port_is_vs(_port_)	((((vm_offset_t)(_port_))&3) == 1)

#define vs_lookup(_port_, _vs_)						\
	do {								\
		if (!MACH_PORT_VALID(_port_) || !port_is_vs(_port_)	\
		    || port_to_vs(_port_)->vs_mem_obj != (_port_))	\
			Panic("bad pager port");			\
		_vs_ = port_to_vs(_port_);				\
	} while (0)
#endif

/*
 * Cross-module routines declaration.
 */
#ifndef MACH_KERNEL
extern int		dp_thread_id(void);
#endif
extern boolean_t	device_reply_server(mach_msg_header_t *,
					    mach_msg_header_t *);
#ifdef MACH_KERNEL
extern boolean_t	default_pager_no_senders(memory_object_t,
						 mach_port_mscount_t);
#else
extern void		default_pager_no_senders(memory_object_t,
						 mach_port_seqno_t,
						 mach_port_mscount_t);
#endif

extern int		local_log2(unsigned int);
extern void		bs_initialize(void);
extern void		bs_global_info(vm_size_t *,
				       vm_size_t *);
extern boolean_t	bs_add_device(char *,
				      MACH_PORT_FACE);
extern vstruct_t	ps_vstruct_create(vm_size_t);
extern void		ps_vstruct_dealloc(vstruct_t);
extern kern_return_t	pvs_cluster_read(vstruct_t,
					vm_offset_t,
					vm_size_t);
extern kern_return_t	vs_cluster_write(vstruct_t,
					 upl_t,
					 upl_offset_t,
					 upl_size_t,
					 boolean_t,
					 int);
extern vm_offset_t	ps_clmap(vstruct_t,
				 vm_offset_t,
				 struct clmap *,
				 int,
				 vm_size_t,
				 int);
extern vm_size_t	ps_vstruct_allocated_size(vstruct_t);
extern size_t		ps_vstruct_allocated_pages(vstruct_t,
						   default_pager_page_t *,
						   size_t);
extern boolean_t	bs_set_default_clsize(unsigned int);

extern boolean_t	verbose;

extern thread_call_t	default_pager_backing_store_monitor_callout;
extern void		default_pager_backing_store_monitor(thread_call_param_t, thread_call_param_t);

extern ipc_port_t	max_pages_trigger_port;
extern unsigned int	dp_pages_free;
extern unsigned int	maximum_pages_free;

/* Do we know yet if swap files need to be encrypted ? */
extern boolean_t	dp_encryption_inited;
/* Should we encrypt data before writing to swap ? */
extern boolean_t	dp_encryption;

#endif	/* _DEFAULT_PAGER_INTERNAL_H_ */
