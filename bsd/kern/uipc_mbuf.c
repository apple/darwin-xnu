/*
 * Copyright (c) 1998-2011 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1988, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)uipc_mbuf.c	8.2 (Berkeley) 1/4/94
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/queue.h>
#include <sys/proc.h>

#include <kern/kern_types.h>
#include <kern/simple_lock.h>
#include <kern/queue.h>
#include <kern/sched_prim.h>
#include <kern/cpu_number.h>
#include <kern/zalloc.h>

#include <libkern/OSAtomic.h>
#include <libkern/libkern.h>

#include <IOKit/IOMapper.h>

#include <machine/limits.h>
#include <machine/machine_routines.h>

#if CONFIG_MACF_NET
#include <security/mac_framework.h>
#endif /* MAC_NET */

#include <sys/mcache.h>

/*
 * MBUF IMPLEMENTATION NOTES.
 *
 * There is a total of 5 per-CPU caches:
 *
 * MC_MBUF:
 *	This is a cache of rudimentary objects of MSIZE in size; each
 *	object represents an mbuf structure.  This cache preserves only
 *	the m_type field of the mbuf during its transactions.
 *
 * MC_CL:
 *	This is a cache of rudimentary objects of MCLBYTES in size; each
 *	object represents a mcluster structure.  This cache does not
 *	preserve the contents of the objects during its transactions.
 *
 * MC_BIGCL:
 *	This is a cache of rudimentary objects of MBIGCLBYTES in size; each
 *	object represents a mbigcluster structure.  This cache does not
 *	preserve the contents of the objects during its transaction.
 *
 * MC_MBUF_CL:
 *	This is a cache of mbufs each having a cluster attached to it.
 *	It is backed by MC_MBUF and MC_CL rudimentary caches.  Several
 *	fields of the mbuf related to the external cluster are preserved
 *	during transactions.
 *
 * MC_MBUF_BIGCL:
 *	This is a cache of mbufs each having a big cluster attached to it.
 *	It is backed by MC_MBUF and MC_BIGCL rudimentary caches.  Several
 *	fields of the mbuf related to the external cluster are preserved
 *	during transactions.
 *
 * OBJECT ALLOCATION:
 *
 * Allocation requests are handled first at the per-CPU (mcache) layer
 * before falling back to the slab layer.  Performance is optimal when
 * the request is satisfied at the CPU layer because global data/lock
 * never gets accessed.  When the slab layer is entered for allocation,
 * the slab freelist will be checked first for available objects before
 * the VM backing store is invoked.  Slab layer operations are serialized
 * for all of the caches as the mbuf global lock is held most of the time.
 * Allocation paths are different depending on the class of objects:
 *
 * a. Rudimentary object:
 *
 *	{ m_get_common(), m_clattach(), m_mclget(),
 *	  m_mclalloc(), m_bigalloc(), m_copym_with_hdrs(),
 *	  composite object allocation }
 *			|	^
 *			|	|
 *			|	+-----------------------+
 *			v				|
 *	   mcache_alloc/mcache_alloc_ext()	mbuf_slab_audit()
 *			|				^
 *			v				|
 *		   [CPU cache] ------->	(found?) -------+
 *			|				|
 *			v				|
 *		 mbuf_slab_alloc()			|
 *			|				|
 *			v				|
 *	+---------> [freelist] ------->	(found?) -------+
 *	|		|
 *	|		v
 *	|	    m_clalloc()
 *	|		|
 *	|		v
 *	+---<<---- kmem_mb_alloc()
 *
 * b. Composite object:
 *
 *	{ m_getpackets_internal(), m_allocpacket_internal() }
 *			|	^
 *			|	|
 *			|	+------	(done) ---------+
 *			v				|
 *	   mcache_alloc/mcache_alloc_ext()	mbuf_cslab_audit()
 *			|				^
 *			v				|
 *		   [CPU cache] ------->	(found?) -------+
 *			|				|
 *			v				|
 *		 mbuf_cslab_alloc()			|
 *			|				|
 *			v				|
 *		    [freelist] ------->	(found?) -------+
 *			|				|
 *			v				|
 *		(rudimentary object)			|
 *	   mcache_alloc/mcache_alloc_ext() ------>>-----+
 *
 * Auditing notes: If auditing is enabled, buffers will be subjected to
 * integrity checks by the audit routine.  This is done by verifying their
 * contents against DEADBEEF (free) pattern before returning them to caller.
 * As part of this step, the routine will also record the transaction and
 * pattern-fill the buffers with BADDCAFE (uninitialized) pattern.  It will
 * also restore any constructed data structure fields if necessary.
 *
 * OBJECT DEALLOCATION:
 *
 * Freeing an object simply involves placing it into the CPU cache; this
 * pollutes the cache to benefit subsequent allocations.  The slab layer
 * will only be entered if the object is to be purged out of the cache.
 * During normal operations, this happens only when the CPU layer resizes
 * its bucket while it's adjusting to the allocation load.  Deallocation
 * paths are different depending on the class of objects:
 *
 * a. Rudimentary object:
 *
 *	{ m_free(), m_freem_list(), composite object deallocation }
 *			|	^
 *			|	|
 *			|	+------	(done) ---------+
 *			v				|
 *	   mcache_free/mcache_free_ext()		|
 *			|				|
 *			v				|
 *		mbuf_slab_audit()			|
 *			|				|
 *			v				|
 *		   [CPU cache] ---> (not purging?) -----+
 *			|				|
 *			v				|
 *		 mbuf_slab_free()			|
 *			|				|
 *			v				|
 *		    [freelist] ----------->>------------+
 *	 (objects never get purged to VM)
 *
 * b. Composite object:
 *
 *	{ m_free(), m_freem_list() }
 *			|	^
 *			|	|
 *			|	+------	(done) ---------+
 *			v				|
 *	   mcache_free/mcache_free_ext()		|
 *			|				|
 *			v				|
 *		mbuf_cslab_audit()			|
 *			|				|
 *			v				|
 *		   [CPU cache] ---> (not purging?) -----+
 *			|				|
 *			v				|
 *		 mbuf_cslab_free()			|
 *			|				|
 *			v				|
 *		    [freelist] ---> (not purging?) -----+
 *			|				|
 *			v				|
 *		(rudimentary object)			|
 *	   mcache_free/mcache_free_ext() ------->>------+
 *
 * Auditing notes: If auditing is enabled, the audit routine will save
 * any constructed data structure fields (if necessary) before filling the
 * contents of the buffers with DEADBEEF (free) pattern and recording the
 * transaction.  Buffers that are freed (whether at CPU or slab layer) are
 * expected to contain the free pattern.
 *
 * DEBUGGING:
 *
 * Debugging can be enabled by adding "mbuf_debug=0x3" to boot-args; this
 * translates to the mcache flags (MCF_VERIFY | MCF_AUDIT).  Additionally,
 * the CPU layer cache can be disabled by setting the MCF_NOCPUCACHE flag,
 * i.e. modify the boot argument parameter to "mbuf_debug=0x13".  Leak
 * detection may also be disabled by setting the MCF_NOLEAKLOG flag, e.g.
 * "mbuf_debug=0x113".  Note that debugging consumes more CPU and memory.
 *
 * Each object is associated with exactly one mcache_audit_t structure that
 * contains the information related to its last buffer transaction.  Given
 * an address of an object, the audit structure can be retrieved by finding
 * the position of the object relevant to the base address of the cluster:
 *
 *	+------------+			+=============+
 *	| mbuf addr  |			| mclaudit[i] |
 *	+------------+			+=============+
 *	      |				| cl_audit[0] |
 *	i = MTOBG(addr)			+-------------+
 *	      |			+----->	| cl_audit[1] | -----> mcache_audit_t
 *	b = BGTOM(i)		|	+-------------+
 *	      |			|	|     ...     |
 *	x = MCLIDX(b, addr)	|	+-------------+
 *	      |			|	| cl_audit[7] |
 *	      +-----------------+	+-------------+
 *		 (e.g. x == 1)
 *
 * The mclaudit[] array is allocated at initialization time, but its contents
 * get populated when the corresponding cluster is created.  Because a page
 * can be turned into NMBPBG number of mbufs, we preserve enough space for the
 * mbufs so that there is a 1-to-1 mapping between them.  A page that never
 * gets (or has not yet) turned into mbufs will use only cl_audit[0] with the
 * remaining entries unused.  For 16KB cluster, only one entry from the first
 * page is allocated and used for the entire object.
 */

/* TODO: should be in header file */
/* kernel translater */
extern vm_offset_t kmem_mb_alloc(vm_map_t, int, int);
extern ppnum_t pmap_find_phys(pmap_t pmap, addr64_t va);
extern vm_map_t mb_map;		/* special map */

/* Global lock */
static lck_mtx_t *mbuf_mlock;
static lck_attr_t *mbuf_mlock_attr;
static lck_grp_t *mbuf_mlock_grp;
static lck_grp_attr_t *mbuf_mlock_grp_attr;

/* Back-end (common) layer */
static void *mbuf_worker_run;	/* wait channel for worker thread */
static int mbuf_worker_ready;	/* worker thread is runnable */
static int mbuf_expand_mcl;	/* number of cluster creation requets */
static int mbuf_expand_big;	/* number of big cluster creation requests */
static int mbuf_expand_16k;	/* number of 16KB cluster creation requests */
static int ncpu;		/* number of CPUs */
static ppnum_t *mcl_paddr;	/* Array of cluster physical addresses */
static ppnum_t mcl_pages;	/* Size of array (# physical pages) */
static ppnum_t mcl_paddr_base;	/* Handle returned by IOMapper::iovmAlloc() */
static mcache_t *ref_cache;	/* Cache of cluster reference & flags */
static mcache_t *mcl_audit_con_cache; /* Audit contents cache */
static unsigned int mbuf_debug;	/* patchable mbuf mcache flags */
static unsigned int mb_normalized; /* number of packets "normalized" */

#define	MB_GROWTH_AGGRESSIVE	1	/* Threshold: 1/2 of total */
#define	MB_GROWTH_NORMAL	2	/* Threshold: 3/4 of total */

typedef enum {
	MC_MBUF = 0,	/* Regular mbuf */
	MC_CL,		/* Cluster */
	MC_BIGCL,	/* Large (4KB) cluster */
	MC_16KCL,	/* Jumbo (16KB) cluster */
	MC_MBUF_CL,	/* mbuf + cluster */
	MC_MBUF_BIGCL,	/* mbuf + large (4KB) cluster */
	MC_MBUF_16KCL	/* mbuf + jumbo (16KB) cluster */
} mbuf_class_t;

#define	MBUF_CLASS_MIN		MC_MBUF
#define	MBUF_CLASS_MAX		MC_MBUF_16KCL
#define	MBUF_CLASS_LAST		MC_16KCL
#define	MBUF_CLASS_VALID(c) \
	((int)(c) >= MBUF_CLASS_MIN && (int)(c) <= MBUF_CLASS_MAX)
#define	MBUF_CLASS_COMPOSITE(c) \
	((int)(c) > MBUF_CLASS_LAST)


/*
 * mbuf specific mcache allocation request flags.
 */
#define	MCR_COMP	MCR_USR1 /* for MC_MBUF_{CL,BIGCL,16KCL} caches */

/*
 * Per-cluster slab structure.
 *
 * A slab is a cluster control structure that contains one or more object
 * chunks; the available chunks are chained in the slab's freelist (sl_head).
 * Each time a chunk is taken out of the slab, the slab's reference count
 * gets incremented.  When all chunks have been taken out, the empty slab
 * gets removed (SLF_DETACHED) from the class's slab list.  A chunk that is
 * returned to a slab causes the slab's reference count to be decremented;
 * it also causes the slab to be reinserted back to class's slab list, if
 * it's not already done.
 *
 * Compartmentalizing of the object chunks into slabs allows us to easily
 * merge one or more slabs together when the adjacent slabs are idle, as
 * well as to convert or move a slab from one class to another; e.g. the
 * mbuf cluster slab can be converted to a regular cluster slab when all
 * mbufs in the slab have been freed.
 *
 * A slab may also span across multiple clusters for chunks larger than
 * a cluster's size.  In this case, only the slab of the first cluster is
 * used.  The rest of the slabs are marked with SLF_PARTIAL to indicate
 * that they are part of the larger slab.
 *
 * Each slab controls a page of memory.
 */
typedef struct mcl_slab {
	struct mcl_slab	*sl_next;	/* neighboring slab */
	u_int8_t	sl_class;	/* controlling mbuf class */
	int8_t		sl_refcnt;	/* outstanding allocations */
	int8_t		sl_chunks;	/* chunks (bufs) in this slab */
	u_int16_t	sl_flags;	/* slab flags (see below) */
	u_int16_t	sl_len;		/* slab length */
	void		*sl_base;	/* base of allocated memory */
	void		*sl_head;	/* first free buffer */
	TAILQ_ENTRY(mcl_slab) sl_link;	/* next/prev slab on freelist */
} mcl_slab_t;

#define	SLF_MAPPED	0x0001		/* backed by a mapped page */
#define	SLF_PARTIAL	0x0002		/* part of another slab */
#define	SLF_DETACHED	0x0004		/* not in slab freelist */

/*
 * The array of slabs are broken into groups of arrays per 1MB of kernel
 * memory to reduce the footprint.  Each group is allocated on demand
 * whenever a new piece of memory mapped in from the VM crosses the 1MB
 * boundary.
 */
#define	NSLABSPMB	((1 << MBSHIFT) >> PGSHIFT)	/* 256 slabs/grp */

typedef struct mcl_slabg {
	mcl_slab_t	slg_slab[NSLABSPMB];	/* group of slabs */
} mcl_slabg_t;

/*
 * Number of slabs needed to control a 16KB cluster object.
 */
#define	NSLABSP16KB	(M16KCLBYTES >> PGSHIFT)

/*
 * Per-cluster audit structure.
 */
typedef struct {
	mcache_audit_t	*cl_audit[NMBPBG];	/* array of audits */
} mcl_audit_t;

/*
 * Size of data from the beginning of an mbuf that covers m_hdr, pkthdr
 * and m_ext structures.  If auditing is enabled, we allocate a shadow
 * mbuf structure of this size inside each audit structure, and the
 * contents of the real mbuf gets copied into it when the mbuf is freed.
 * This allows us to pattern-fill the mbuf for integrity check, and to
 * preserve any constructed mbuf fields (e.g. mbuf + cluster cache case).
 * Note that we don't save the contents of clusters when they are freed;
 * we simply pattern-fill them.
 */
#define	AUDIT_CONTENTS_SIZE	((MSIZE - MHLEN) + sizeof (_m_ext_t))

/*
 * mbuf specific mcache audit flags
 */
#define	MB_INUSE	0x01	/* object has not been returned to slab */
#define	MB_COMP_INUSE	0x02	/* object has not been returned to cslab */
#define	MB_SCVALID	0x04	/* object has valid saved contents */

/*
 * Each of the following two arrays hold up to nmbclusters elements.
 */
static mcl_audit_t *mclaudit;	/* array of cluster audit information */
static unsigned int maxclaudit;	/* max # of entries in audit table */
static mcl_slabg_t **slabstbl;	/* cluster slabs table */
static unsigned int maxslabgrp;	/* max # of entries in slabs table */
static unsigned int slabgrp;	/* # of entries in slabs table */

/* Globals */
int nclusters;			/* # of clusters for non-jumbo (legacy) sizes */
int njcl;			/* # of clusters for jumbo sizes */
int njclbytes;			/* size of a jumbo cluster */
union mbigcluster *mbutl;	/* first mapped cluster address */
union mbigcluster *embutl;	/* ending virtual address of mclusters */
int max_linkhdr;		/* largest link-level header */
int max_protohdr;		/* largest protocol header */
int max_hdr;			/* largest link+protocol header */
int max_datalen;		/* MHLEN - max_hdr */

static boolean_t mclverify;	/* debug: pattern-checking */
static boolean_t mcltrace;	/* debug: stack tracing */
static boolean_t mclfindleak;	/* debug: leak detection */

/* mbuf leak detection variables */
static struct mleak_table mleak_table;
static mleak_stat_t *mleak_stat;

#define	MLEAK_STAT_SIZE(n) \
	((size_t)(&((mleak_stat_t *)0)->ml_trace[n]))

struct mallocation {
	mcache_obj_t *element;	/* the alloc'ed element, NULL if unused */
	u_int32_t trace_index;	/* mtrace index for corresponding backtrace */
	u_int32_t count;	/* How many objects were requested */
	u_int64_t hitcount;	/* for determining hash effectiveness */
};

struct mtrace {
	u_int64_t	collisions;
	u_int64_t	hitcount;
	u_int64_t	allocs;
	u_int64_t	depth;
	uintptr_t	addr[MLEAK_STACK_DEPTH];
};

/* Size must be a power of two for the zhash to be able to just mask off bits */
#define	MLEAK_ALLOCATION_MAP_NUM	512
#define	MLEAK_TRACE_MAP_NUM		256

/*
 * Sample factor for how often to record a trace.  This is overwritable
 * by the boot-arg mleak_sample_factor.
 */
#define	MLEAK_SAMPLE_FACTOR		500

/*
 * Number of top leakers recorded.
 */
#define	MLEAK_NUM_TRACES		5

static uint32_t mleak_alloc_buckets = MLEAK_ALLOCATION_MAP_NUM;
static uint32_t mleak_trace_buckets = MLEAK_TRACE_MAP_NUM;

/* Hashmaps of allocations and their corresponding traces */
static struct mallocation *mleak_allocations;
static struct mtrace *mleak_traces;
static struct mtrace *mleak_top_trace[MLEAK_NUM_TRACES];

/* Lock to protect mleak tables from concurrent modification */
static lck_mtx_t *mleak_lock;
static lck_attr_t *mleak_lock_attr;
static lck_grp_t *mleak_lock_grp;
static lck_grp_attr_t *mleak_lock_grp_attr;

extern u_int32_t high_sb_max;

/* TODO: should be in header file */
int do_reclaim = 0;

/* The minimum number of objects that are allocated, to start. */
#define	MINCL		32
#define	MINBIGCL	(MINCL >> 1)
#define	MIN16KCL	(MINCL >> 2)

/* Low watermarks (only map in pages once free counts go below) */
#define	MBIGCL_LOWAT	MINBIGCL
#define	M16KCL_LOWAT	MIN16KCL

typedef struct {
	mbuf_class_t	mtbl_class;	/* class type */
	mcache_t	*mtbl_cache;	/* mcache for this buffer class */
	TAILQ_HEAD(mcl_slhead, mcl_slab) mtbl_slablist; /* slab list */
	mcache_obj_t	*mtbl_cobjlist;	/* composite objects freelist */
	mb_class_stat_t	*mtbl_stats;	/* statistics fetchable via sysctl */
	u_int32_t	mtbl_maxsize;	/* maximum buffer size */
	int		mtbl_minlimit;	/* minimum allowed */
	int		mtbl_maxlimit;	/* maximum allowed */
	u_int32_t	mtbl_wantpurge;	/* purge during next reclaim */
} mbuf_table_t;

#define	m_class(c)	mbuf_table[c].mtbl_class
#define	m_cache(c)	mbuf_table[c].mtbl_cache
#define	m_slablist(c)	mbuf_table[c].mtbl_slablist
#define	m_cobjlist(c)	mbuf_table[c].mtbl_cobjlist
#define	m_maxsize(c)	mbuf_table[c].mtbl_maxsize
#define	m_minlimit(c)	mbuf_table[c].mtbl_minlimit
#define	m_maxlimit(c)	mbuf_table[c].mtbl_maxlimit
#define	m_wantpurge(c)	mbuf_table[c].mtbl_wantpurge
#define	m_cname(c)	mbuf_table[c].mtbl_stats->mbcl_cname
#define	m_size(c)	mbuf_table[c].mtbl_stats->mbcl_size
#define	m_total(c)	mbuf_table[c].mtbl_stats->mbcl_total
#define	m_active(c)	mbuf_table[c].mtbl_stats->mbcl_active
#define	m_infree(c)	mbuf_table[c].mtbl_stats->mbcl_infree
#define	m_slab_cnt(c)	mbuf_table[c].mtbl_stats->mbcl_slab_cnt
#define	m_alloc_cnt(c)	mbuf_table[c].mtbl_stats->mbcl_alloc_cnt
#define	m_free_cnt(c)	mbuf_table[c].mtbl_stats->mbcl_free_cnt
#define	m_notified(c)	mbuf_table[c].mtbl_stats->mbcl_notified
#define	m_purge_cnt(c)	mbuf_table[c].mtbl_stats->mbcl_purge_cnt
#define	m_fail_cnt(c)	mbuf_table[c].mtbl_stats->mbcl_fail_cnt
#define	m_ctotal(c)	mbuf_table[c].mtbl_stats->mbcl_ctotal

static mbuf_table_t mbuf_table[] = {
	/*
	 * The caches for mbufs, regular clusters and big clusters.
	 */
	{ MC_MBUF, NULL, TAILQ_HEAD_INITIALIZER(m_slablist(MC_MBUF)),
	    NULL, NULL, 0, 0, 0, 0 },
	{ MC_CL, NULL, TAILQ_HEAD_INITIALIZER(m_slablist(MC_CL)),
	    NULL, NULL, 0, 0, 0, 0 },
	{ MC_BIGCL, NULL, TAILQ_HEAD_INITIALIZER(m_slablist(MC_BIGCL)),
	    NULL, NULL, 0, 0, 0, 0 },
	{ MC_16KCL, NULL, TAILQ_HEAD_INITIALIZER(m_slablist(MC_16KCL)),
	    NULL, NULL, 0, 0, 0, 0 },
	/*
	 * The following are special caches; they serve as intermediate
	 * caches backed by the above rudimentary caches.  Each object
	 * in the cache is an mbuf with a cluster attached to it.  Unlike
	 * the above caches, these intermediate caches do not directly
	 * deal with the slab structures; instead, the constructed
	 * cached elements are simply stored in the freelists.
	 */
	{ MC_MBUF_CL, NULL, { NULL, NULL }, NULL, NULL, 0, 0, 0, 0 },
	{ MC_MBUF_BIGCL, NULL, { NULL, NULL }, NULL, NULL, 0, 0, 0, 0 },
	{ MC_MBUF_16KCL, NULL, { NULL, NULL }, NULL, NULL, 0, 0, 0, 0 },
};

#define	NELEM(a)	(sizeof (a) / sizeof ((a)[0]))

static void *mb_waitchan = &mbuf_table;	/* wait channel for all caches */
static int mb_waiters;			/* number of waiters */

#define	MB_WDT_MAXTIME	10		/* # of secs before watchdog panic */
static struct timeval mb_wdtstart;	/* watchdog start timestamp */
static char mbuf_dump_buf[256];

/*
 * mbuf watchdog is enabled by default on embedded platforms.  It is
 * also toggeable via the kern.ipc.mb_watchdog sysctl.
 */
#if CONFIG_EMBEDDED
static unsigned int mb_watchdog = 1;
#else
static unsigned int mb_watchdog = 0;
#endif /* CONFIG_EMBEDDED */

/* The following are used to serialize m_clalloc() */
static boolean_t mb_clalloc_busy;
static void *mb_clalloc_waitchan = &mb_clalloc_busy;
static int mb_clalloc_waiters;

static void mbuf_mtypes_sync(boolean_t);
static int mbstat_sysctl SYSCTL_HANDLER_ARGS;
static void mbuf_stat_sync(void);
static int mb_stat_sysctl SYSCTL_HANDLER_ARGS;
static int mleak_top_trace_sysctl SYSCTL_HANDLER_ARGS;
static int mleak_table_sysctl SYSCTL_HANDLER_ARGS;
static char *mbuf_dump(void);
static void mbuf_table_init(void);
static inline void m_incref(struct mbuf *);
static inline u_int32_t m_decref(struct mbuf *);
static int m_clalloc(const u_int32_t, const int, const u_int32_t);
static void mbuf_worker_thread_init(void);
static mcache_obj_t *slab_alloc(mbuf_class_t, int);
static void slab_free(mbuf_class_t, mcache_obj_t *);
static unsigned int mbuf_slab_alloc(void *, mcache_obj_t ***,
    unsigned int, int);
static void mbuf_slab_free(void *, mcache_obj_t *, int);
static void mbuf_slab_audit(void *, mcache_obj_t *, boolean_t);
static void mbuf_slab_notify(void *, u_int32_t);
static unsigned int cslab_alloc(mbuf_class_t, mcache_obj_t ***,
    unsigned int);
static unsigned int cslab_free(mbuf_class_t, mcache_obj_t *, int);
static unsigned int mbuf_cslab_alloc(void *, mcache_obj_t ***,
    unsigned int, int);
static void mbuf_cslab_free(void *, mcache_obj_t *, int);
static void mbuf_cslab_audit(void *, mcache_obj_t *, boolean_t);
static int freelist_populate(mbuf_class_t, unsigned int, int);
static void freelist_init(mbuf_class_t);
static boolean_t mbuf_cached_above(mbuf_class_t, int);
static boolean_t mbuf_steal(mbuf_class_t, unsigned int);
static void m_reclaim(mbuf_class_t, unsigned int, boolean_t);
static int m_howmany(int, size_t);
static void mbuf_worker_thread(void);
static void mbuf_watchdog(void);
static boolean_t mbuf_sleep(mbuf_class_t, unsigned int, int);

static void mcl_audit_init(void *, mcache_audit_t **, mcache_obj_t **,
    size_t, unsigned int);
static mcache_audit_t *mcl_audit_buf2mca(mbuf_class_t, mcache_obj_t *);
static void mcl_audit_mbuf(mcache_audit_t *, void *, boolean_t, boolean_t);
static void mcl_audit_cluster(mcache_audit_t *, void *, size_t, boolean_t,
    boolean_t);
static void mcl_audit_restore_mbuf(struct mbuf *, mcache_audit_t *, boolean_t);
static void mcl_audit_save_mbuf(struct mbuf *, mcache_audit_t *);
static void mcl_audit_mcheck_panic(struct mbuf *);
static void mcl_audit_verify_nextptr(void *, mcache_audit_t *);

static void mleak_activate(void);
static void mleak_logger(u_int32_t, mcache_obj_t *, boolean_t);
static boolean_t mleak_log(uintptr_t *, mcache_obj_t *, uint32_t, int);
static void mleak_free(mcache_obj_t *);

static mcl_slab_t *slab_get(void *);
static void slab_init(mcl_slab_t *, mbuf_class_t, u_int32_t,
    void *, void *, unsigned int, int, int);
static void slab_insert(mcl_slab_t *, mbuf_class_t);
static void slab_remove(mcl_slab_t *, mbuf_class_t);
static boolean_t slab_inrange(mcl_slab_t *, void *);
static void slab_nextptr_panic(mcl_slab_t *, void *);
static void slab_detach(mcl_slab_t *);
static boolean_t slab_is_detached(mcl_slab_t *);

static int m_copyback0(struct mbuf **, int, int, const void *, int, int);
static struct mbuf *m_split0(struct mbuf *, int, int, int);

/* flags for m_copyback0 */
#define	M_COPYBACK0_COPYBACK	0x0001	/* copyback from cp */
#define	M_COPYBACK0_PRESERVE	0x0002	/* preserve original data */
#define	M_COPYBACK0_COW		0x0004	/* do copy-on-write */
#define	M_COPYBACK0_EXTEND	0x0008	/* extend chain */

/*
 * This flag is set for all mbufs that come out of and into the composite
 * mbuf + cluster caches, i.e. MC_MBUF_CL and MC_MBUF_BIGCL.  mbufs that
 * are marked with such a flag have clusters attached to them, and will be
 * treated differently when they are freed; instead of being placed back
 * into the mbuf and cluster freelists, the composite mbuf + cluster objects
 * are placed back into the appropriate composite cache's freelist, and the
 * actual freeing is deferred until the composite objects are purged.  At
 * such a time, this flag will be cleared from the mbufs and the objects
 * will be freed into their own separate freelists.
 */
#define	EXTF_COMPOSITE	0x1

/*
 * This flag indicates that the external cluster is read-only, i.e. it is
 * or was referred to by more than one mbufs.  Once set, this flag is never
 * cleared.
 */
#define	EXTF_READONLY	0x2
#define	EXTF_MASK	(EXTF_COMPOSITE | EXTF_READONLY)

#define	MEXT_RFA(m)		((m)->m_ext.ext_refflags)
#define	MEXT_REF(m)		(MEXT_RFA(m)->refcnt)
#define	MEXT_FLAGS(m)		(MEXT_RFA(m)->flags)
#define	MBUF_IS_COMPOSITE(m)	\
	(MEXT_REF(m) == 0 && (MEXT_FLAGS(m) & EXTF_MASK) == EXTF_COMPOSITE)

/*
 * Macros used to verify the integrity of the mbuf.
 */
#define	_MCHECK(m) {							\
	if ((m)->m_type != MT_FREE) {					\
		if (mclaudit == NULL)					\
			panic("MCHECK: m_type=%d m=%p",			\
			    (u_int16_t)(m)->m_type, m);			\
		else							\
			mcl_audit_mcheck_panic(m);			\
	}								\
}

#define	MBUF_IN_MAP(addr)						\
	((void *)(addr) >= (void *)mbutl && (void *)(addr) < (void *)embutl)

#define	MRANGE(addr) {							\
	if (!MBUF_IN_MAP(addr))						\
		panic("MRANGE: address out of range 0x%p", addr);	\
}

/*
 * Macro version of mtod.
 */
#define	MTOD(m, t)	((t)((m)->m_data))

/*
 * Macros to obtain (4KB) cluster index and base cluster address.
 */

#define	MTOBG(x)	(((char *)(x) - (char *)mbutl) >> MBIGCLSHIFT)
#define	BGTOM(x)	((union mbigcluster *)(mbutl + (x)))

/*
 * Macro to find the mbuf index relative to a base.
 */
#define	MCLIDX(c, m)	(((char *)(m) - (char *)(c)) >> MSIZESHIFT)

/*
 * Same thing for 2KB cluster index.
 */
#define	CLBGIDX(c, m)	(((char *)(m) - (char *)(c)) >> MCLSHIFT)

/*
 * Macros used during mbuf and cluster initialization.
 */
#define	MBUF_INIT(m, pkthdr, type) {					\
	_MCHECK(m);							\
	(m)->m_next = (m)->m_nextpkt = NULL;				\
	(m)->m_len = 0;							\
	(m)->m_type = type;						\
	if ((pkthdr) == 0) {						\
		(m)->m_data = (m)->m_dat;				\
		(m)->m_flags = 0;					\
	} else {							\
		(m)->m_data = (m)->m_pktdat;				\
		(m)->m_flags = M_PKTHDR;				\
		(m)->m_pkthdr.rcvif = NULL;				\
		(m)->m_pkthdr.len = 0;					\
		(m)->m_pkthdr.header = NULL;				\
		(m)->m_pkthdr.csum_flags = 0;				\
		(m)->m_pkthdr.csum_data = 0;				\
		(m)->m_pkthdr.tso_segsz = 0;				\
		(m)->m_pkthdr.vlan_tag = 0;				\
		(m)->m_pkthdr.socket_id = 0;				\
		(m)->m_pkthdr.vt_nrecs = 0;				\
		m_tag_init(m);						\
		m_prio_init(m);						\
	}								\
}

#define	MEXT_INIT(m, buf, size, free, arg, rfa, ref, flag) {		\
	(m)->m_data = (m)->m_ext.ext_buf = (buf);			\
	(m)->m_flags |= M_EXT;						\
	(m)->m_ext.ext_size = (size);					\
	(m)->m_ext.ext_free = (free);					\
	(m)->m_ext.ext_arg = (arg);					\
	(m)->m_ext.ext_refs.forward = (m)->m_ext.ext_refs.backward =	\
	    &(m)->m_ext.ext_refs;					\
	MEXT_RFA(m) = (rfa);						\
	MEXT_REF(m) = (ref);						\
	MEXT_FLAGS(m) = (flag);						\
}

#define	MBUF_CL_INIT(m, buf, rfa, ref, flag)	\
	MEXT_INIT(m, buf, m_maxsize(MC_CL), NULL, NULL, rfa, ref, flag)

#define	MBUF_BIGCL_INIT(m, buf, rfa, ref, flag)	\
	MEXT_INIT(m, buf, m_maxsize(MC_BIGCL), m_bigfree, NULL, rfa, ref, flag)

#define	MBUF_16KCL_INIT(m, buf, rfa, ref, flag)	\
	MEXT_INIT(m, buf, m_maxsize(MC_16KCL), m_16kfree, NULL, rfa, ref, flag)

/*
 * Macro to convert BSD malloc sleep flag to mcache's
 */
#define	MSLEEPF(f)	((!((f) & M_DONTWAIT)) ? MCR_SLEEP : MCR_NOSLEEP)

/*
 * The structure that holds all mbuf class statistics exportable via sysctl.
 * Similar to mbstat structure, the mb_stat structure is protected by the
 * global mbuf lock.  It contains additional information about the classes
 * that allows for a more accurate view of the state of the allocator.
 */
struct mb_stat *mb_stat;
struct omb_stat *omb_stat;	/* For backwards compatibility */

#define	MB_STAT_SIZE(n) \
	((size_t)(&((mb_stat_t *)0)->mbs_class[n]))
#define	OMB_STAT_SIZE(n) \
	((size_t)(&((struct omb_stat *)0)->mbs_class[n]))

/*
 * The legacy structure holding all of the mbuf allocation statistics.
 * The actual statistics used by the kernel are stored in the mbuf_table
 * instead, and are updated atomically while the global mbuf lock is held.
 * They are mirrored in mbstat to support legacy applications (e.g. netstat).
 * Unlike before, the kernel no longer relies on the contents of mbstat for
 * its operations (e.g. cluster expansion) because the structure is exposed
 * to outside and could possibly be modified, therefore making it unsafe.
 * With the exception of the mbstat.m_mtypes array (see below), all of the
 * statistics are updated as they change.
 */
struct mbstat mbstat;

#define	MBSTAT_MTYPES_MAX \
	(sizeof (mbstat.m_mtypes) / sizeof (mbstat.m_mtypes[0]))

/*
 * Allocation statistics related to mbuf types (up to MT_MAX-1) are updated
 * atomically and stored in a per-CPU structure which is lock-free; this is
 * done in order to avoid writing to the global mbstat data structure which
 * would cause false sharing.  During sysctl request for kern.ipc.mbstat,
 * the statistics across all CPUs will be converged into the mbstat.m_mtypes
 * array and returned to the application.  Any updates for types greater or
 * equal than MT_MAX would be done atomically to the mbstat; this slows down
 * performance but is okay since the kernel uses only up to MT_MAX-1 while
 * anything beyond that (up to type 255) is considered a corner case.
 */
typedef struct {
	unsigned int	cpu_mtypes[MT_MAX];
} __attribute__((aligned(CPU_CACHE_SIZE), packed)) mtypes_cpu_t;

typedef struct {
	mtypes_cpu_t	mbs_cpu[1];
} mbuf_mtypes_t;

static mbuf_mtypes_t *mbuf_mtypes;	/* per-CPU statistics */

#define	MBUF_MTYPES_SIZE(n) \
	((size_t)(&((mbuf_mtypes_t *)0)->mbs_cpu[n]))

#define	MTYPES_CPU(p) \
	((mtypes_cpu_t *)((char *)(p) + MBUF_MTYPES_SIZE(cpu_number())))

#define	mtype_stat_add(type, n) {					\
	if ((unsigned)(type) < MT_MAX) {				\
		mtypes_cpu_t *mbs = MTYPES_CPU(mbuf_mtypes);		\
		atomic_add_32(&mbs->cpu_mtypes[type], n);		\
	} else if ((unsigned)(type) < (unsigned)MBSTAT_MTYPES_MAX) {	\
		atomic_add_16((int16_t *)&mbstat.m_mtypes[type], n);	\
	}								\
}

#define	mtype_stat_sub(t, n)	mtype_stat_add(t, -(n))
#define	mtype_stat_inc(t)	mtype_stat_add(t, 1)
#define	mtype_stat_dec(t)	mtype_stat_sub(t, 1)

static void
mbuf_mtypes_sync(boolean_t locked)
{
	int m, n;
	mtypes_cpu_t mtc;

	if (locked)
		lck_mtx_assert(mbuf_mlock, LCK_MTX_ASSERT_OWNED);

	bzero(&mtc, sizeof (mtc));
	for (m = 0; m < ncpu; m++) {
		mtypes_cpu_t *scp = &mbuf_mtypes->mbs_cpu[m];
		mtypes_cpu_t temp;

		bcopy(&scp->cpu_mtypes, &temp.cpu_mtypes,
		    sizeof (temp.cpu_mtypes));

		for (n = 0; n < MT_MAX; n++)
			mtc.cpu_mtypes[n] += temp.cpu_mtypes[n];
	}
	if (!locked)
		lck_mtx_lock(mbuf_mlock);
	for (n = 0; n < MT_MAX; n++)
		mbstat.m_mtypes[n] = mtc.cpu_mtypes[n];
	if (!locked)
		lck_mtx_unlock(mbuf_mlock);
}

static int
mbstat_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	mbuf_mtypes_sync(FALSE);

	return (SYSCTL_OUT(req, &mbstat, sizeof (mbstat)));
}

static void
mbuf_stat_sync(void)
{
	mb_class_stat_t *sp;
	mcache_cpu_t *ccp;
	mcache_t *cp;
	int k, m, bktsize;

	lck_mtx_assert(mbuf_mlock, LCK_MTX_ASSERT_OWNED);

	for (k = 0; k < NELEM(mbuf_table); k++) {
		cp = m_cache(k);
		ccp = &cp->mc_cpu[0];
		bktsize = ccp->cc_bktsize;
		sp = mbuf_table[k].mtbl_stats;

		if (cp->mc_flags & MCF_NOCPUCACHE)
			sp->mbcl_mc_state = MCS_DISABLED;
		else if (cp->mc_purge_cnt > 0)
			sp->mbcl_mc_state = MCS_PURGING;
		else if (bktsize == 0)
			sp->mbcl_mc_state = MCS_OFFLINE;
		else
			sp->mbcl_mc_state = MCS_ONLINE;

		sp->mbcl_mc_cached = 0;
		for (m = 0; m < ncpu; m++) {
			ccp = &cp->mc_cpu[m];
			if (ccp->cc_objs > 0)
				sp->mbcl_mc_cached += ccp->cc_objs;
			if (ccp->cc_pobjs > 0)
				sp->mbcl_mc_cached += ccp->cc_pobjs;
		}
		sp->mbcl_mc_cached += (cp->mc_full.bl_total * bktsize);
		sp->mbcl_active = sp->mbcl_total - sp->mbcl_mc_cached -
		    sp->mbcl_infree;

		sp->mbcl_mc_waiter_cnt = cp->mc_waiter_cnt;
		sp->mbcl_mc_wretry_cnt = cp->mc_wretry_cnt;
		sp->mbcl_mc_nwretry_cnt = cp->mc_nwretry_cnt;

		/* Calculate total count specific to each class */
		sp->mbcl_ctotal = sp->mbcl_total;
		switch (m_class(k)) {
		case MC_MBUF:
			/* Deduct mbufs used in composite caches */
			sp->mbcl_ctotal -= (m_total(MC_MBUF_CL) +
			    m_total(MC_MBUF_BIGCL));
			break;

		case MC_CL:
			/* Deduct clusters used in composite cache */
			sp->mbcl_ctotal -= m_total(MC_MBUF_CL);
			break;

		case MC_BIGCL:
			/* Deduct clusters used in composite cache */
			sp->mbcl_ctotal -= m_total(MC_MBUF_BIGCL);
			break;

		case MC_16KCL:
			/* Deduct clusters used in composite cache */
			sp->mbcl_ctotal -= m_total(MC_MBUF_16KCL);
			break;

		default:
			break;
		}
	}
}

static int
mb_stat_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	void *statp;
	int k, statsz, proc64 = proc_is64bit(req->p);

	lck_mtx_lock(mbuf_mlock);
	mbuf_stat_sync();

	if (!proc64) {
		struct omb_class_stat *oc;
		struct mb_class_stat *c;

		omb_stat->mbs_cnt = mb_stat->mbs_cnt;
		oc = &omb_stat->mbs_class[0];
		c = &mb_stat->mbs_class[0];
		for (k = 0; k < omb_stat->mbs_cnt; k++, oc++, c++) {
			(void) snprintf(oc->mbcl_cname, sizeof (oc->mbcl_cname),
			    "%s", c->mbcl_cname);
			oc->mbcl_size = c->mbcl_size;
			oc->mbcl_total = c->mbcl_total;
			oc->mbcl_active = c->mbcl_active;
			oc->mbcl_infree = c->mbcl_infree;
			oc->mbcl_slab_cnt = c->mbcl_slab_cnt;
			oc->mbcl_alloc_cnt = c->mbcl_alloc_cnt;
			oc->mbcl_free_cnt = c->mbcl_free_cnt;
			oc->mbcl_notified = c->mbcl_notified;
			oc->mbcl_purge_cnt = c->mbcl_purge_cnt;
			oc->mbcl_fail_cnt = c->mbcl_fail_cnt;
			oc->mbcl_ctotal = c->mbcl_ctotal;
			oc->mbcl_mc_state = c->mbcl_mc_state;
			oc->mbcl_mc_cached = c->mbcl_mc_cached;
			oc->mbcl_mc_waiter_cnt = c->mbcl_mc_waiter_cnt;
			oc->mbcl_mc_wretry_cnt = c->mbcl_mc_wretry_cnt;
			oc->mbcl_mc_nwretry_cnt = c->mbcl_mc_nwretry_cnt;
		}
		statp = omb_stat;
		statsz = OMB_STAT_SIZE(NELEM(mbuf_table));
	} else {
		statp = mb_stat;
		statsz = MB_STAT_SIZE(NELEM(mbuf_table));
	}

	lck_mtx_unlock(mbuf_mlock);

	return (SYSCTL_OUT(req, statp, statsz));
}

static int
mleak_top_trace_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	mleak_trace_stat_t *mltr;
	int i;

	/* Ensure leak tracing turned on */
	if (!mclfindleak)
		return (ENXIO);

	VERIFY(mleak_stat != NULL);
#ifdef __LP64__
	VERIFY(mleak_stat->ml_isaddr64);
#else
	VERIFY(!mleak_stat->ml_isaddr64);
#endif /* !__LP64__ */
	VERIFY(mleak_stat->ml_cnt == MLEAK_NUM_TRACES);

	lck_mtx_lock(mleak_lock);
	mltr = &mleak_stat->ml_trace[0];
	bzero(mltr, sizeof (*mltr) * MLEAK_NUM_TRACES);
	for (i = 0; i < MLEAK_NUM_TRACES; i++) {
		int j;

		if (mleak_top_trace[i] == NULL ||
		    mleak_top_trace[i]->allocs == 0)
			continue;

		mltr->mltr_collisions	= mleak_top_trace[i]->collisions;
		mltr->mltr_hitcount	= mleak_top_trace[i]->hitcount;
		mltr->mltr_allocs	= mleak_top_trace[i]->allocs;
		mltr->mltr_depth	= mleak_top_trace[i]->depth;

		VERIFY(mltr->mltr_depth <= MLEAK_STACK_DEPTH);
		for (j = 0; j < mltr->mltr_depth; j++)
			mltr->mltr_addr[j] = mleak_top_trace[i]->addr[j];

		mltr++;
	}
	i = SYSCTL_OUT(req, mleak_stat, MLEAK_STAT_SIZE(MLEAK_NUM_TRACES));
	lck_mtx_unlock(mleak_lock);

	return (i);
}

static int
mleak_table_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int i = 0;

	/* Ensure leak tracing turned on */
	if (!mclfindleak)
		return (ENXIO);

	lck_mtx_lock(mleak_lock);
	i = SYSCTL_OUT(req, &mleak_table, sizeof (mleak_table));
	lck_mtx_unlock(mleak_lock);

	return (i);
}

static inline void
m_incref(struct mbuf *m)
{
	UInt32 old, new;
	volatile UInt32 *addr = (volatile UInt32 *)&MEXT_REF(m);

	do {
		old = *addr;
		new = old + 1;
		ASSERT(new != 0);
	} while (!OSCompareAndSwap(old, new, addr));

	/*
	 * If cluster is shared, mark it with (sticky) EXTF_READONLY;
	 * we don't clear the flag when the refcount goes back to 1
	 * to simplify code calling m_mclhasreference().
	 */
	if (new > 1 && !(MEXT_FLAGS(m) & EXTF_READONLY))
		(void) OSBitOrAtomic(EXTF_READONLY, &MEXT_FLAGS(m));
}

static inline u_int32_t
m_decref(struct mbuf *m)
{
	UInt32 old, new;
	volatile UInt32 *addr = (volatile UInt32 *)&MEXT_REF(m);

	do {
		old = *addr;
		new = old - 1;
		ASSERT(old != 0);
	} while (!OSCompareAndSwap(old, new, addr));

	return (new);
}

static void
mbuf_table_init(void)
{
	unsigned int b, c, s;
	int m;

	MALLOC(omb_stat, struct omb_stat *, OMB_STAT_SIZE(NELEM(mbuf_table)),
	    M_TEMP, M_WAITOK | M_ZERO);
	VERIFY(omb_stat != NULL);

	MALLOC(mb_stat, mb_stat_t *, MB_STAT_SIZE(NELEM(mbuf_table)),
	    M_TEMP, M_WAITOK | M_ZERO);
	VERIFY(mb_stat != NULL);

	mb_stat->mbs_cnt = NELEM(mbuf_table);
	for (m = 0; m < NELEM(mbuf_table); m++)
		mbuf_table[m].mtbl_stats = &mb_stat->mbs_class[m];

#if CONFIG_MBUF_JUMBO
	/*
	 * Set aside 1/3 of the mbuf cluster map for jumbo clusters; we do
	 * this only on platforms where jumbo cluster pool is enabled.
	 */
	njcl = nmbclusters / 3;
	njclbytes = M16KCLBYTES;
#endif /* CONFIG_MBUF_JUMBO */

	/*
	 * nclusters holds both the 2KB and 4KB pools, so ensure it's
	 * a multiple of 4KB clusters.
	 */
	nclusters = P2ROUNDDOWN(nmbclusters - njcl, NCLPBG);
	if (njcl > 0) {
		/*
		 * Each jumbo cluster takes 8 2KB clusters, so make
		 * sure that the pool size is evenly divisible by 8;
		 * njcl is in 2KB unit, hence treated as such.
		 */
		njcl = P2ROUNDDOWN(nmbclusters - nclusters, 8);

		/* Update nclusters with rounded down value of njcl */
		nclusters = P2ROUNDDOWN(nmbclusters - njcl, NCLPBG);
	}

	/*
	 * njcl is valid only on platforms with 16KB jumbo clusters, where
	 * it is configured to 1/3 of the pool size.  On these platforms,
	 * the remaining is used for 2KB and 4KB clusters.  On platforms
	 * without 16KB jumbo clusters, the entire pool is used for both
	 * 2KB and 4KB clusters.  A 4KB cluster can either be splitted into
	 * 16 mbufs, or into 2 2KB clusters.
	 *
	 *  +---+---+------------ ... -----------+------- ... -------+
	 *  | c | b |              s             |        njcl       |
	 *  +---+---+------------ ... -----------+------- ... -------+
	 *
	 * 1/32th of the shared region is reserved for pure 2KB and 4KB
	 * clusters (1/64th each.)
	 */
	c = P2ROUNDDOWN((nclusters >> 6), 2);		/* in 2KB unit */
	b = P2ROUNDDOWN((nclusters >> (6 + NCLPBGSHIFT)), 2); /* in 4KB unit */
	s = nclusters - (c + (b << NCLPBGSHIFT));	/* in 2KB unit */

	/*
	 * 1/64th (c) is reserved for 2KB clusters.
	 */
	m_minlimit(MC_CL) = c;
	m_maxlimit(MC_CL) = s + c;			/* in 2KB unit */
	m_maxsize(MC_CL) = m_size(MC_CL) = MCLBYTES;
	(void) snprintf(m_cname(MC_CL), MAX_MBUF_CNAME, "cl");

	/*
	 * Another 1/64th (b) of the map is reserved for 4KB clusters.
	 * It cannot be turned into 2KB clusters or mbufs.
	 */
	m_minlimit(MC_BIGCL) = b;
	m_maxlimit(MC_BIGCL) = (s >> NCLPBGSHIFT) + b;	/* in 4KB unit */
	m_maxsize(MC_BIGCL) = m_size(MC_BIGCL) = MBIGCLBYTES;
	(void) snprintf(m_cname(MC_BIGCL), MAX_MBUF_CNAME, "bigcl");

	/*
	 * The remaining 31/32ths (s) are all-purpose (mbufs, 2KB, or 4KB)
	 */
	m_minlimit(MC_MBUF) = 0;
	m_maxlimit(MC_MBUF) = (s << NMBPCLSHIFT);	/* in mbuf unit */
	m_maxsize(MC_MBUF) = m_size(MC_MBUF) = MSIZE;
	(void) snprintf(m_cname(MC_MBUF), MAX_MBUF_CNAME, "mbuf");

	/*
	 * Set limits for the composite classes.
	 */
	m_minlimit(MC_MBUF_CL) = 0;
	m_maxlimit(MC_MBUF_CL) = m_maxlimit(MC_CL);
	m_maxsize(MC_MBUF_CL) = MCLBYTES;
	m_size(MC_MBUF_CL) = m_size(MC_MBUF) + m_size(MC_CL);
	(void) snprintf(m_cname(MC_MBUF_CL), MAX_MBUF_CNAME, "mbuf_cl");

	m_minlimit(MC_MBUF_BIGCL) = 0;
	m_maxlimit(MC_MBUF_BIGCL) = m_maxlimit(MC_BIGCL);
	m_maxsize(MC_MBUF_BIGCL) = MBIGCLBYTES;
	m_size(MC_MBUF_BIGCL) = m_size(MC_MBUF) + m_size(MC_BIGCL);
	(void) snprintf(m_cname(MC_MBUF_BIGCL), MAX_MBUF_CNAME, "mbuf_bigcl");

	/*
	 * And for jumbo classes.
	 */
	m_minlimit(MC_16KCL) = 0;
	m_maxlimit(MC_16KCL) = (njcl >> NCLPJCLSHIFT);	/* in 16KB unit */
	m_maxsize(MC_16KCL) = m_size(MC_16KCL) = M16KCLBYTES;
	(void) snprintf(m_cname(MC_16KCL), MAX_MBUF_CNAME, "16kcl");

	m_minlimit(MC_MBUF_16KCL) = 0;
	m_maxlimit(MC_MBUF_16KCL) = m_maxlimit(MC_16KCL);
	m_maxsize(MC_MBUF_16KCL) = M16KCLBYTES;
	m_size(MC_MBUF_16KCL) = m_size(MC_MBUF) + m_size(MC_16KCL);
	(void) snprintf(m_cname(MC_MBUF_16KCL), MAX_MBUF_CNAME, "mbuf_16kcl");

	/*
	 * Initialize the legacy mbstat structure.
	 */
	bzero(&mbstat, sizeof (mbstat));
	mbstat.m_msize = m_maxsize(MC_MBUF);
	mbstat.m_mclbytes = m_maxsize(MC_CL);
	mbstat.m_minclsize = MINCLSIZE;
	mbstat.m_mlen = MLEN;
	mbstat.m_mhlen = MHLEN;
	mbstat.m_bigmclbytes = m_maxsize(MC_BIGCL);
}

#if defined(__LP64__)
typedef struct ncl_tbl {
	uint64_t nt_maxmem;	/* memory (sane) size */
	uint32_t nt_mbpool;	/* mbuf pool size */
} ncl_tbl_t;

/* Non-server */
static ncl_tbl_t ncl_table[] = {
	{ (1ULL << GBSHIFT)       /*  1 GB */,	(64 << MBSHIFT)	 /*  64 MB */ },
	{ (1ULL << (GBSHIFT + 3)) /*  8 GB */,	(96 << MBSHIFT)	 /*  96 MB */ },
	{ (1ULL << (GBSHIFT + 4)) /* 16 GB */,	(128 << MBSHIFT) /* 128 MB */ },
	{ 0, 0 }
};

/* Server */
static ncl_tbl_t ncl_table_srv[] = {
	{ (1ULL << GBSHIFT)       /*  1 GB */,	(96 << MBSHIFT)  /*  96 MB */ },
	{ (1ULL << (GBSHIFT + 2)) /*  4 GB */,	(128 << MBSHIFT) /* 128 MB */ },
	{ (1ULL << (GBSHIFT + 3)) /*  8 GB */,	(160 << MBSHIFT) /* 160 MB */ },
	{ (1ULL << (GBSHIFT + 4)) /* 16 GB */,	(192 << MBSHIFT) /* 192 MB */ },
	{ (1ULL << (GBSHIFT + 5)) /* 32 GB */,	(256 << MBSHIFT) /* 256 MB */ },
	{ (1ULL << (GBSHIFT + 6)) /* 64 GB */,	(384 << MBSHIFT) /* 384 MB */ },
	{ 0, 0 }
};
#endif /* __LP64__ */

__private_extern__ unsigned int
mbuf_default_ncl(int server, uint64_t mem)
{
#if !defined(__LP64__)
#pragma unused(server)
	unsigned int n;
	/*
	 * 32-bit kernel (default to 64MB of mbuf pool for >= 1GB RAM).
	 */
	if ((n = ((mem / 16) / MCLBYTES)) > 32768)
		n = 32768;
#else
	unsigned int n, i;
	ncl_tbl_t *tbl = (server ? ncl_table_srv : ncl_table);
	/*
	 * 64-bit kernel (mbuf pool size based on table).
	 */
	n = tbl[0].nt_mbpool;
	for (i = 0; tbl[i].nt_mbpool != 0; i++) {
		if (mem < tbl[i].nt_maxmem)
			break;
		n = tbl[i].nt_mbpool;
	}
	n >>= MCLSHIFT;
#endif /* !__LP64__ */
	return (n);
}

__private_extern__ void
mbinit(void)
{
	unsigned int m;
	unsigned int initmcl = 0;
	void *buf;
	thread_t thread = THREAD_NULL;

	if (nmbclusters == 0)
		nmbclusters = NMBCLUSTERS;

	/* This should be a sane (at least even) value by now */
	VERIFY(nmbclusters != 0 && !(nmbclusters & 0x1));

	/* Setup the mbuf table */
	mbuf_table_init();

	/* Global lock for common layer */
	mbuf_mlock_grp_attr = lck_grp_attr_alloc_init();
	mbuf_mlock_grp = lck_grp_alloc_init("mbuf", mbuf_mlock_grp_attr);
	mbuf_mlock_attr = lck_attr_alloc_init();
	mbuf_mlock = lck_mtx_alloc_init(mbuf_mlock_grp, mbuf_mlock_attr);

	/*
	 * Allocate cluster slabs table:
	 *
	 *	maxslabgrp = (N * 2048) / (1024 * 1024)
	 *
	 * Where N is nmbclusters rounded up to the nearest 512.  This yields
	 * mcl_slab_g_t units, each one representing a MB of memory.
	 */
	maxslabgrp =
	    (P2ROUNDUP(nmbclusters, (MBSIZE >> 11)) << MCLSHIFT) >> MBSHIFT;
	MALLOC(slabstbl, mcl_slabg_t **, maxslabgrp * sizeof (mcl_slabg_t *),
	    M_TEMP, M_WAITOK | M_ZERO);
	VERIFY(slabstbl != NULL);

	/*
	 * Allocate audit structures, if needed:
	 *
	 *	maxclaudit = (maxslabgrp * 1024 * 1024) / 4096
	 *
	 * This yields mcl_audit_t units, each one representing a page.
	 */
	PE_parse_boot_argn("mbuf_debug", &mbuf_debug, sizeof (mbuf_debug));
	mbuf_debug |= mcache_getflags();
	if (mbuf_debug & MCF_DEBUG) {
		maxclaudit = ((maxslabgrp << MBSHIFT) >> PGSHIFT);
		MALLOC(mclaudit, mcl_audit_t *, maxclaudit * sizeof (*mclaudit),
		    M_TEMP, M_WAITOK | M_ZERO);
		VERIFY(mclaudit != NULL);

		mcl_audit_con_cache = mcache_create("mcl_audit_contents",
		    AUDIT_CONTENTS_SIZE, 0, 0, MCR_SLEEP);
		VERIFY(mcl_audit_con_cache != NULL);
	}
	mclverify = (mbuf_debug & MCF_VERIFY);
	mcltrace = (mbuf_debug & MCF_TRACE);
	mclfindleak = !(mbuf_debug & MCF_NOLEAKLOG);

	/* Enable mbuf leak logging, with a lock to protect the tables */

	mleak_lock_grp_attr = lck_grp_attr_alloc_init();
	mleak_lock_grp = lck_grp_alloc_init("mleak_lock", mleak_lock_grp_attr);
	mleak_lock_attr = lck_attr_alloc_init();
	mleak_lock = lck_mtx_alloc_init(mleak_lock_grp, mleak_lock_attr);

	mleak_activate();

	/* Calculate the number of pages assigned to the cluster pool */
	mcl_pages = (nmbclusters * MCLBYTES) / CLBYTES;
	MALLOC(mcl_paddr, ppnum_t *, mcl_pages * sizeof (ppnum_t),
	    M_TEMP, M_WAITOK);
	VERIFY(mcl_paddr != NULL);

	/* Register with the I/O Bus mapper */
	mcl_paddr_base = IOMapperIOVMAlloc(mcl_pages);
	bzero((char *)mcl_paddr, mcl_pages * sizeof (ppnum_t));

	embutl = (union mbigcluster *)
	    ((unsigned char *)mbutl + (nmbclusters * MCLBYTES));
	VERIFY((((char *)embutl - (char *)mbutl) % MBIGCLBYTES) == 0);

	/* Prime up the freelist */
	PE_parse_boot_argn("initmcl", &initmcl, sizeof (initmcl));
	if (initmcl != 0) {
		initmcl >>= NCLPBGSHIFT;	/* become a 4K unit */
		if (initmcl > m_maxlimit(MC_BIGCL))
			initmcl = m_maxlimit(MC_BIGCL);
	}
	if (initmcl < m_minlimit(MC_BIGCL))
		initmcl = m_minlimit(MC_BIGCL);

	lck_mtx_lock(mbuf_mlock);

	/*
	 * For classes with non-zero minimum limits, populate their freelists
	 * so that m_total(class) is at least m_minlimit(class).
	 */
	VERIFY(m_total(MC_BIGCL) == 0 && m_minlimit(MC_BIGCL) != 0);
	freelist_populate(m_class(MC_BIGCL), initmcl, M_WAIT);
	VERIFY(m_total(MC_BIGCL) >= m_minlimit(MC_BIGCL));
	freelist_init(m_class(MC_CL));

	for (m = 0; m < NELEM(mbuf_table); m++) {
		/* Make sure we didn't miss any */
		VERIFY(m_minlimit(m_class(m)) == 0 ||
		    m_total(m_class(m)) >= m_minlimit(m_class(m)));
	}

	lck_mtx_unlock(mbuf_mlock);

	(void) kernel_thread_start((thread_continue_t)mbuf_worker_thread_init,
	    NULL, &thread);
	thread_deallocate(thread);

	ref_cache = mcache_create("mext_ref", sizeof (struct ext_ref),
	    0, 0, MCR_SLEEP);

	/* Create the cache for each class */
	for (m = 0; m < NELEM(mbuf_table); m++) {
		void *allocfunc, *freefunc, *auditfunc, *logfunc;
		u_int32_t flags;

		flags = mbuf_debug;
		if (m_class(m) == MC_MBUF_CL || m_class(m) == MC_MBUF_BIGCL ||
		    m_class(m) == MC_MBUF_16KCL) {
			allocfunc = mbuf_cslab_alloc;
			freefunc = mbuf_cslab_free;
			auditfunc = mbuf_cslab_audit;
			logfunc = mleak_logger;
		} else {
			allocfunc = mbuf_slab_alloc;
			freefunc = mbuf_slab_free;
			auditfunc = mbuf_slab_audit;
			logfunc = mleak_logger;
		}

		/*
		 * Disable per-CPU caches for jumbo classes if there
		 * is no jumbo cluster pool available in the system.
		 * The cache itself is still created (but will never
		 * be populated) since it simplifies the code.
		 */
		if ((m_class(m) == MC_MBUF_16KCL || m_class(m) == MC_16KCL) &&
		    njcl == 0)
			flags |= MCF_NOCPUCACHE;

		if (!mclfindleak)
			flags |= MCF_NOLEAKLOG;

		m_cache(m) = mcache_create_ext(m_cname(m), m_maxsize(m),
		    allocfunc, freefunc, auditfunc, logfunc, mbuf_slab_notify,
		    (void *)(uintptr_t)m, flags, MCR_SLEEP);
	}

	/*
	 * Allocate structure for per-CPU statistics that's aligned
	 * on the CPU cache boundary; this code assumes that we never
	 * uninitialize this framework, since the original address
	 * before alignment is not saved.
	 */
	ncpu = ml_get_max_cpus();
	MALLOC(buf, void *, MBUF_MTYPES_SIZE(ncpu) + CPU_CACHE_SIZE,
	    M_TEMP, M_WAITOK);
	VERIFY(buf != NULL);

	mbuf_mtypes = (mbuf_mtypes_t *)P2ROUNDUP((intptr_t)buf, CPU_CACHE_SIZE);
	bzero(mbuf_mtypes, MBUF_MTYPES_SIZE(ncpu));

	/*
	 * Set the max limit on sb_max to be 1/16 th of the size of
	 * memory allocated for mbuf clusters.
	 */
	high_sb_max = (nmbclusters << (MCLSHIFT - 4));
	if (high_sb_max < sb_max) {
		/* sb_max is too large for this configuration, scale it down */
		if (high_sb_max > (1 << MBSHIFT)) {
			/* We have atleast 16 M of mbuf pool */
			sb_max = high_sb_max;
		} else if ((nmbclusters << MCLSHIFT) > (1 << MBSHIFT)) {
			/*
			 * If we have more than 1M of mbufpool, cap the size of
			 * max sock buf at 1M
			 */
			sb_max = high_sb_max = (1 << MBSHIFT);
		} else {
			sb_max = high_sb_max;
		}
	}

	printf("mbinit: done [%d MB total pool size, (%d/%d) split]\n",
	    (nmbclusters << MCLSHIFT) >> MBSHIFT,
	    (nclusters << MCLSHIFT) >> MBSHIFT,
	    (njcl << MCLSHIFT) >> MBSHIFT);
}

/*
 * Obtain a slab of object(s) from the class's freelist.
 */
static mcache_obj_t *
slab_alloc(mbuf_class_t class, int wait)
{
	mcl_slab_t *sp;
	mcache_obj_t *buf;

	lck_mtx_assert(mbuf_mlock, LCK_MTX_ASSERT_OWNED);

	VERIFY(class != MC_16KCL || njcl > 0);

	/* This should always be NULL for us */
	VERIFY(m_cobjlist(class) == NULL);

	/*
	 * Treat composite objects as having longer lifespan by using
	 * a slab from the reverse direction, in hoping that this could
	 * reduce the probability of fragmentation for slabs that hold
	 * more than one buffer chunks (e.g. mbuf slabs).  For other
	 * slabs, this probably doesn't make much of a difference.
	 */
	if ((class == MC_MBUF || class == MC_CL) && (wait & MCR_COMP))
		sp = (mcl_slab_t *)TAILQ_LAST(&m_slablist(class), mcl_slhead);
	else
		sp = (mcl_slab_t *)TAILQ_FIRST(&m_slablist(class));

	if (sp == NULL) {
		VERIFY(m_infree(class) == 0 && m_slab_cnt(class) == 0);
		/* The slab list for this class is empty */
		return (NULL);
	}

	VERIFY(m_infree(class) > 0);
	VERIFY(!slab_is_detached(sp));
	VERIFY(sp->sl_class == class &&
	    (sp->sl_flags & (SLF_MAPPED | SLF_PARTIAL)) == SLF_MAPPED);
	buf = sp->sl_head;
	VERIFY(slab_inrange(sp, buf) && sp == slab_get(buf));

	if (class == MC_MBUF) {
		sp->sl_head = buf->obj_next;
		VERIFY(sp->sl_head != NULL || sp->sl_refcnt == (NMBPBG - 1));
	} else if (class == MC_CL) {
		sp->sl_head = buf->obj_next;
		VERIFY(sp->sl_head != NULL || sp->sl_refcnt == (NCLPBG - 1));
	} else {
		sp->sl_head = NULL;
	}
	if (sp->sl_head != NULL && !slab_inrange(sp, sp->sl_head)) {
		slab_nextptr_panic(sp, sp->sl_head);
		/* In case sl_head is in the map but not in the slab */
		VERIFY(slab_inrange(sp, sp->sl_head));
		/* NOTREACHED */
	}

	/* Increment slab reference */
	sp->sl_refcnt++;

	if (mclaudit != NULL) {
		mcache_audit_t *mca = mcl_audit_buf2mca(class, buf);
		mca->mca_uflags = 0;
		/* Save contents on mbuf objects only */
		if (class == MC_MBUF)
			mca->mca_uflags |= MB_SCVALID;
	}

	if (class == MC_CL) {
		mbstat.m_clfree = (--m_infree(MC_CL)) + m_infree(MC_MBUF_CL);
		/*
		 * A 2K cluster slab can have at most NCLPBG references.
		 */
		VERIFY(sp->sl_refcnt >= 1 && sp->sl_refcnt <= NCLPBG &&
		    sp->sl_chunks == NCLPBG &&
		    sp->sl_len == m_maxsize(MC_BIGCL));
		VERIFY(sp->sl_refcnt < NCLPBG || sp->sl_head == NULL);
	} else if (class == MC_BIGCL) {
		mbstat.m_bigclfree = (--m_infree(MC_BIGCL)) +
		    m_infree(MC_MBUF_BIGCL);
		/*
		 * A 4K cluster slab can have at most 1 reference.
		 */
		VERIFY(sp->sl_refcnt == 1 && sp->sl_chunks == 1 &&
		    sp->sl_len == m_maxsize(class) && sp->sl_head == NULL);
	} else if (class == MC_16KCL) {
		mcl_slab_t *nsp;
		int k;

		--m_infree(MC_16KCL);
		VERIFY(sp->sl_refcnt == 1 && sp->sl_chunks == 1 &&
		    sp->sl_len == m_maxsize(class) && sp->sl_head == NULL);
		/*
		 * Increment 2nd-Nth slab reference, where N is NSLABSP16KB.
		 * A 16KB big cluster takes NSLABSP16KB slabs, each having at
		 * most 1 reference.
		 */
		for (nsp = sp, k = 1; k < NSLABSP16KB; k++) {
			nsp = nsp->sl_next;
			/* Next slab must already be present */
			VERIFY(nsp != NULL);
			nsp->sl_refcnt++;
			VERIFY(!slab_is_detached(nsp));
			VERIFY(nsp->sl_class == MC_16KCL &&
			    nsp->sl_flags == (SLF_MAPPED | SLF_PARTIAL) &&
			    nsp->sl_refcnt == 1 && nsp->sl_chunks == 0 &&
			    nsp->sl_len == 0 && nsp->sl_base == sp->sl_base &&
			    nsp->sl_head == NULL);
		}
	} else {
		VERIFY(class == MC_MBUF);
		--m_infree(MC_MBUF);
		/*
		 * If auditing is turned on, this check is
		 * deferred until later in mbuf_slab_audit().
		 */
		if (mclaudit == NULL)
			_MCHECK((struct mbuf *)buf);
		/*
		 * Since we have incremented the reference count above,
		 * an mbuf slab (formerly a 4KB cluster slab that was cut
		 * up into mbufs) must have a reference count between 1
		 * and NMBPBG at this point.
		 */
		VERIFY(sp->sl_refcnt >= 1 && sp->sl_refcnt <= NMBPBG &&
		    sp->sl_chunks == NMBPBG &&
		    sp->sl_len == m_maxsize(MC_BIGCL));
		VERIFY(sp->sl_refcnt < NMBPBG || sp->sl_head == NULL);
	}

	/* If empty, remove this slab from the class's freelist */
	if (sp->sl_head == NULL) {
		VERIFY(class != MC_MBUF || sp->sl_refcnt == NMBPBG);
		VERIFY(class != MC_CL || sp->sl_refcnt == NCLPBG);
		slab_remove(sp, class);
	}

	return (buf);
}

/*
 * Place a slab of object(s) back into a class's slab list.
 */
static void
slab_free(mbuf_class_t class, mcache_obj_t *buf)
{
	mcl_slab_t *sp;

	lck_mtx_assert(mbuf_mlock, LCK_MTX_ASSERT_OWNED);

	VERIFY(class != MC_16KCL || njcl > 0);
	VERIFY(buf->obj_next == NULL);
	sp = slab_get(buf);
	VERIFY(sp->sl_class == class && slab_inrange(sp, buf) &&
	    (sp->sl_flags & (SLF_MAPPED | SLF_PARTIAL)) == SLF_MAPPED);

	/* Decrement slab reference */
	sp->sl_refcnt--;

	if (class == MC_CL) {
		VERIFY(IS_P2ALIGNED(buf, MCLBYTES));
		/*
		 * A slab that has been splitted for 2KB clusters can have
		 * at most 1 outstanding reference at this point.
		 */
		VERIFY(sp->sl_refcnt >= 0 && sp->sl_refcnt <= (NCLPBG - 1) &&
		    sp->sl_chunks == NCLPBG &&
		    sp->sl_len == m_maxsize(MC_BIGCL));
		VERIFY(sp->sl_refcnt < (NCLPBG - 1) ||
		    (slab_is_detached(sp) && sp->sl_head == NULL));
	} else if (class == MC_BIGCL) {
		VERIFY(IS_P2ALIGNED(buf, MCLBYTES));
		/*
		 * A 4KB cluster slab can have at most 1 reference
		 * which must be 0 at this point.
		 */
		VERIFY(sp->sl_refcnt == 0 && sp->sl_chunks == 1 &&
		    sp->sl_len == m_maxsize(class) && sp->sl_head == NULL);
		VERIFY(slab_is_detached(sp));
	} else if (class == MC_16KCL) {
		mcl_slab_t *nsp;
		int k;
		/*
		 * A 16KB cluster takes NSLABSP16KB slabs, all must
		 * now have 0 reference.
		 */
		VERIFY(IS_P2ALIGNED(buf, MBIGCLBYTES));
		VERIFY(sp->sl_refcnt == 0 && sp->sl_chunks == 1 &&
		    sp->sl_len == m_maxsize(class) && sp->sl_head == NULL);
		VERIFY(slab_is_detached(sp));
		for (nsp = sp, k = 1; k < NSLABSP16KB; k++) {
			nsp = nsp->sl_next;
			/* Next slab must already be present */
			VERIFY(nsp != NULL);
			nsp->sl_refcnt--;
			VERIFY(slab_is_detached(nsp));
			VERIFY(nsp->sl_class == MC_16KCL &&
			    (nsp->sl_flags & (SLF_MAPPED | SLF_PARTIAL)) &&
			    nsp->sl_refcnt == 0 && nsp->sl_chunks == 0 &&
			    nsp->sl_len == 0 && nsp->sl_base == sp->sl_base &&
			    nsp->sl_head == NULL);
		}
	} else {
		/*
		 * A slab that has been splitted for mbufs has at most NMBPBG
		 * reference counts.  Since we have decremented one reference
		 * above, it must now be between 0 and NMBPBG-1.
		 */
		VERIFY(class == MC_MBUF);
		VERIFY(sp->sl_refcnt >= 0 && sp->sl_refcnt <= (NMBPBG - 1) &&
		    sp->sl_chunks == NMBPBG &&
		    sp->sl_len == m_maxsize(MC_BIGCL));
		VERIFY(sp->sl_refcnt < (NMBPBG - 1) ||
		    (slab_is_detached(sp) && sp->sl_head == NULL));
	}

	/*
	 * When auditing is enabled, ensure that the buffer still
	 * contains the free pattern.  Otherwise it got corrupted
	 * while at the CPU cache layer.
	 */
	if (mclaudit != NULL) {
		mcache_audit_t *mca = mcl_audit_buf2mca(class, buf);
		if (mclverify) {
			mcache_audit_free_verify(mca, buf, 0, m_maxsize(class));
		}
		mca->mca_uflags &= ~MB_SCVALID;
	}

	if (class == MC_CL) {
		mbstat.m_clfree = (++m_infree(MC_CL)) + m_infree(MC_MBUF_CL);
		buf->obj_next = sp->sl_head;
	} else if (class == MC_BIGCL) {
		mbstat.m_bigclfree = (++m_infree(MC_BIGCL)) +
		    m_infree(MC_MBUF_BIGCL);
	} else if (class == MC_16KCL) {
		++m_infree(MC_16KCL);
	} else {
		++m_infree(MC_MBUF);
		buf->obj_next = sp->sl_head;
	}
	sp->sl_head = buf;

	/*
	 * If a slab has been splitted to either one which holds 2KB clusters,
	 * or one which holds mbufs, turn it back to one which holds a 4KB
	 * cluster.
	 */
	if (class == MC_MBUF && sp->sl_refcnt == 0 &&
	    m_total(class) > m_minlimit(class) &&
	    m_total(MC_BIGCL) < m_maxlimit(MC_BIGCL)) {
		int i = NMBPBG;

		m_total(MC_BIGCL)++;
		mbstat.m_bigclusters = m_total(MC_BIGCL);
		m_total(MC_MBUF) -= NMBPBG;
		mbstat.m_mbufs = m_total(MC_MBUF);
		m_infree(MC_MBUF) -= NMBPBG;
		mtype_stat_add(MT_FREE, -((unsigned)NMBPBG));

		VERIFY(m_total(MC_BIGCL) <= m_maxlimit(MC_BIGCL));
		VERIFY(m_total(MC_MBUF) >= m_minlimit(MC_MBUF));

		while (i--) {
			struct mbuf *m = sp->sl_head;
			VERIFY(m != NULL);
			sp->sl_head = m->m_next;
			m->m_next = NULL;
		}
		VERIFY(sp->sl_head == NULL);

		/* Remove the slab from the mbuf class's slab list */
		slab_remove(sp, class);

		/* Reinitialize it as a 4KB cluster slab */
		slab_init(sp, MC_BIGCL, sp->sl_flags, sp->sl_base, sp->sl_base,
		    sp->sl_len, 0, 1);

		if (mclverify) {
			mcache_set_pattern(MCACHE_FREE_PATTERN,
			    (caddr_t)sp->sl_head, m_maxsize(MC_BIGCL));
		}
		mbstat.m_bigclfree = (++m_infree(MC_BIGCL)) +
		    m_infree(MC_MBUF_BIGCL);

		VERIFY(slab_is_detached(sp));
		/* And finally switch class */
		class = MC_BIGCL;
	} else if (class == MC_CL && sp->sl_refcnt == 0 &&
	    m_total(class) > m_minlimit(class) &&
	    m_total(MC_BIGCL) < m_maxlimit(MC_BIGCL)) {
		int i = NCLPBG;

		m_total(MC_BIGCL)++;
		mbstat.m_bigclusters = m_total(MC_BIGCL);
		m_total(MC_CL) -= NCLPBG;
		mbstat.m_clusters = m_total(MC_CL);
		m_infree(MC_CL) -= NCLPBG;
		VERIFY(m_total(MC_BIGCL) <= m_maxlimit(MC_BIGCL));
		VERIFY(m_total(MC_CL) >= m_minlimit(MC_CL));

		while (i--) {
			union mcluster *c = sp->sl_head;
			VERIFY(c != NULL);
			sp->sl_head = c->mcl_next;
			c->mcl_next = NULL;
		}
		VERIFY(sp->sl_head == NULL);

		/* Remove the slab from the 2KB cluster class's slab list */
		slab_remove(sp, class);

		/* Reinitialize it as a 4KB cluster slab */
		slab_init(sp, MC_BIGCL, sp->sl_flags, sp->sl_base, sp->sl_base,
		    sp->sl_len, 0, 1);

		if (mclverify) {
			mcache_set_pattern(MCACHE_FREE_PATTERN,
			    (caddr_t)sp->sl_head, m_maxsize(MC_BIGCL));
		}
		mbstat.m_bigclfree = (++m_infree(MC_BIGCL)) +
		    m_infree(MC_MBUF_BIGCL);

		VERIFY(slab_is_detached(sp));
		/* And finally switch class */
		class = MC_BIGCL;
	}

	/* Reinsert the slab to the class's slab list */
	if (slab_is_detached(sp))
		slab_insert(sp, class);
}

/*
 * Common allocator for rudimentary objects called by the CPU cache layer
 * during an allocation request whenever there is no available element in the
 * bucket layer.  It returns one or more elements from the appropriate global
 * freelist.  If the freelist is empty, it will attempt to populate it and
 * retry the allocation.
 */
static unsigned int
mbuf_slab_alloc(void *arg, mcache_obj_t ***plist, unsigned int num, int wait)
{
	mbuf_class_t class = (mbuf_class_t)arg;
	unsigned int need = num;
	mcache_obj_t **list = *plist;

	ASSERT(MBUF_CLASS_VALID(class) && !MBUF_CLASS_COMPOSITE(class));
	ASSERT(need > 0);

	lck_mtx_lock(mbuf_mlock);

	for (;;) {
		if ((*list = slab_alloc(class, wait)) != NULL) {
			(*list)->obj_next = NULL;
			list = *plist = &(*list)->obj_next;

			if (--need == 0) {
				/*
				 * If the number of elements in freelist has
				 * dropped below low watermark, asynchronously
				 * populate the freelist now rather than doing
				 * it later when we run out of elements.
				 */
				if (!mbuf_cached_above(class, wait) &&
				    m_infree(class) < m_total(class) >> 5) {
					(void) freelist_populate(class, 1,
					    M_DONTWAIT);
				}
				break;
			}
		} else {
			VERIFY(m_infree(class) == 0 || class == MC_CL);

			(void) freelist_populate(class, 1,
			    (wait & MCR_NOSLEEP) ? M_DONTWAIT : M_WAIT);

			if (m_infree(class) > 0)
				continue;

			/* Check if there's anything at the cache layer */
			if (mbuf_cached_above(class, wait))
				break;

			/* watchdog checkpoint */
			mbuf_watchdog();

			/* We have nothing and cannot block; give up */
			if (wait & MCR_NOSLEEP) {
				if (!(wait & MCR_TRYHARD)) {
					m_fail_cnt(class)++;
					mbstat.m_drops++;
					break;
				}
			}

			/*
			 * If the freelist is still empty and the caller is
			 * willing to be blocked, sleep on the wait channel
			 * until an element is available.  Otherwise, if
			 * MCR_TRYHARD is set, do our best to satisfy the
			 * request without having to go to sleep.
			 */
			if (mbuf_worker_ready &&
			    mbuf_sleep(class, need, wait))
				break;

			lck_mtx_assert(mbuf_mlock, LCK_MTX_ASSERT_OWNED);
		}
	}

	m_alloc_cnt(class) += num - need;
	lck_mtx_unlock(mbuf_mlock);

	return (num - need);
}

/*
 * Common de-allocator for rudimentary objects called by the CPU cache
 * layer when one or more elements need to be returned to the appropriate
 * global freelist.
 */
static void
mbuf_slab_free(void *arg, mcache_obj_t *list, __unused int purged)
{
	mbuf_class_t class = (mbuf_class_t)arg;
	mcache_obj_t *nlist;
	unsigned int num = 0;
	int w;

	ASSERT(MBUF_CLASS_VALID(class) && !MBUF_CLASS_COMPOSITE(class));

	lck_mtx_lock(mbuf_mlock);

	for (;;) {
		nlist = list->obj_next;
		list->obj_next = NULL;
		slab_free(class, list);
		++num;
		if ((list = nlist) == NULL)
			break;
	}
	m_free_cnt(class) += num;

	if ((w = mb_waiters) > 0)
		mb_waiters = 0;

	lck_mtx_unlock(mbuf_mlock);

	if (w != 0)
		wakeup(mb_waitchan);
}

/*
 * Common auditor for rudimentary objects called by the CPU cache layer
 * during an allocation or free request.  For the former, this is called
 * after the objects are obtained from either the bucket or slab layer
 * and before they are returned to the caller.  For the latter, this is
 * called immediately during free and before placing the objects into
 * the bucket or slab layer.
 */
static void
mbuf_slab_audit(void *arg, mcache_obj_t *list, boolean_t alloc)
{
	mbuf_class_t class = (mbuf_class_t)arg;
	mcache_audit_t *mca;

	ASSERT(MBUF_CLASS_VALID(class) && !MBUF_CLASS_COMPOSITE(class));

	while (list != NULL) {
		lck_mtx_lock(mbuf_mlock);
		mca = mcl_audit_buf2mca(class, list);

		/* Do the sanity checks */
		if (class == MC_MBUF) {
			mcl_audit_mbuf(mca, list, FALSE, alloc);
			ASSERT(mca->mca_uflags & MB_SCVALID);
		} else {
			mcl_audit_cluster(mca, list, m_maxsize(class),
			    alloc, TRUE);
			ASSERT(!(mca->mca_uflags & MB_SCVALID));
		}
		/* Record this transaction */
		if (mcltrace)
			mcache_buffer_log(mca, list, m_cache(class));

		if (alloc)
			mca->mca_uflags |= MB_INUSE;
		else
			mca->mca_uflags &= ~MB_INUSE;
		/* Unpair the object (unconditionally) */
		mca->mca_uptr = NULL;
		lck_mtx_unlock(mbuf_mlock);

		list = list->obj_next;
	}
}

/*
 * Common notify routine for all caches.  It is called by mcache when
 * one or more objects get freed.  We use this indication to trigger
 * the wakeup of any sleeping threads so that they can retry their
 * allocation requests.
 */
static void
mbuf_slab_notify(void *arg, u_int32_t reason)
{
	mbuf_class_t class = (mbuf_class_t)arg;
	int w;

	ASSERT(MBUF_CLASS_VALID(class));

	if (reason != MCN_RETRYALLOC)
		return;

	lck_mtx_lock(mbuf_mlock);
	if ((w = mb_waiters) > 0) {
		m_notified(class)++;
		mb_waiters = 0;
	}
	lck_mtx_unlock(mbuf_mlock);

	if (w != 0)
		wakeup(mb_waitchan);
}

/*
 * Obtain object(s) from the composite class's freelist.
 */
static unsigned int
cslab_alloc(mbuf_class_t class, mcache_obj_t ***plist, unsigned int num)
{
	unsigned int need = num;
	mcl_slab_t *sp, *clsp, *nsp;
	struct mbuf *m;
	mcache_obj_t **list = *plist;
	void *cl;

	VERIFY(need > 0);
	VERIFY(class != MC_MBUF_16KCL || njcl > 0);
	lck_mtx_assert(mbuf_mlock, LCK_MTX_ASSERT_OWNED);

	/* Get what we can from the freelist */
	while ((*list = m_cobjlist(class)) != NULL) {
		MRANGE(*list);

		m = (struct mbuf *)*list;
		sp = slab_get(m);
		cl = m->m_ext.ext_buf;
		clsp = slab_get(cl);
		VERIFY(m->m_flags == M_EXT && cl != NULL);
		VERIFY(MEXT_RFA(m) != NULL && MBUF_IS_COMPOSITE(m));

		if (class == MC_MBUF_CL) {
			VERIFY(clsp->sl_refcnt >= 1 &&
			    clsp->sl_refcnt <= NCLPBG);
		} else {
			VERIFY(clsp->sl_refcnt == 1);
		}

		if (class == MC_MBUF_16KCL) {
			int k;
			for (nsp = clsp, k = 1; k < NSLABSP16KB; k++) {
				nsp = nsp->sl_next;
				/* Next slab must already be present */
				VERIFY(nsp != NULL);
				VERIFY(nsp->sl_refcnt == 1);
			}
		}

		if ((m_cobjlist(class) = (*list)->obj_next) != NULL &&
		    !MBUF_IN_MAP(m_cobjlist(class))) {
			slab_nextptr_panic(sp, m_cobjlist(class));
			/* NOTREACHED */
		}
		(*list)->obj_next = NULL;
		list = *plist = &(*list)->obj_next;

		if (--need == 0)
			break;
	}
	m_infree(class) -= (num - need);

	return (num - need);
}

/*
 * Place object(s) back into a composite class's freelist.
 */
static unsigned int
cslab_free(mbuf_class_t class, mcache_obj_t *list, int purged)
{
	mcache_obj_t *o, *tail;
	unsigned int num = 0;
	struct mbuf *m, *ms;
	mcache_audit_t *mca = NULL;
	mcache_obj_t *ref_list = NULL;
	mcl_slab_t *clsp, *nsp;
	void *cl;
	mbuf_class_t cl_class;

	ASSERT(MBUF_CLASS_VALID(class) && MBUF_CLASS_COMPOSITE(class));
	VERIFY(class != MC_MBUF_16KCL || njcl > 0);
	lck_mtx_assert(mbuf_mlock, LCK_MTX_ASSERT_OWNED);

	if (class == MC_MBUF_CL) {
		cl_class = MC_CL;
	} else if (class == MC_MBUF_BIGCL) {
		cl_class = MC_BIGCL;
	} else {
		VERIFY(class == MC_MBUF_16KCL);
		cl_class = MC_16KCL;
	}

	o = tail = list;

	while ((m = ms = (struct mbuf *)o) != NULL) {
		mcache_obj_t *rfa, *nexto = o->obj_next;

		/* Do the mbuf sanity checks */
		if (mclaudit != NULL) {
			mca = mcl_audit_buf2mca(MC_MBUF, (mcache_obj_t *)m);
			if (mclverify) {
				mcache_audit_free_verify(mca, m, 0,
				    m_maxsize(MC_MBUF));
			}
			ms = (struct mbuf *)mca->mca_contents;
		}

		/* Do the cluster sanity checks */
		cl = ms->m_ext.ext_buf;
		clsp = slab_get(cl);
		if (mclverify) {
			size_t size = m_maxsize(cl_class);
			mcache_audit_free_verify(mcl_audit_buf2mca(cl_class,
			    (mcache_obj_t *)cl), cl, 0, size);
		}
		VERIFY(ms->m_type == MT_FREE);
		VERIFY(ms->m_flags == M_EXT);
		VERIFY(MEXT_RFA(ms) != NULL && MBUF_IS_COMPOSITE(ms));
		if (cl_class == MC_CL) {
			VERIFY(clsp->sl_refcnt >= 1 &&
			    clsp->sl_refcnt <= NCLPBG);
		} else {
			VERIFY(clsp->sl_refcnt == 1);
		}
		if (cl_class == MC_16KCL) {
			int k;
			for (nsp = clsp, k = 1; k < NSLABSP16KB; k++) {
				nsp = nsp->sl_next;
				/* Next slab must already be present */
				VERIFY(nsp != NULL);
				VERIFY(nsp->sl_refcnt == 1);
			}
		}

		/*
		 * If we're asked to purge, restore the actual mbuf using
		 * contents of the shadow structure (if auditing is enabled)
		 * and clear EXTF_COMPOSITE flag from the mbuf, as we are
		 * about to free it and the attached cluster into their caches.
		 */
		if (purged) {
			/* Restore constructed mbuf fields */
			if (mclaudit != NULL)
				mcl_audit_restore_mbuf(m, mca, TRUE);

			MEXT_REF(m) = 0;
			MEXT_FLAGS(m) = 0;

			rfa = (mcache_obj_t *)MEXT_RFA(m);
			rfa->obj_next = ref_list;
			ref_list = rfa;
			MEXT_RFA(m) = NULL;

			m->m_type = MT_FREE;
			m->m_flags = m->m_len = 0;
			m->m_next = m->m_nextpkt = NULL;

			/* Save mbuf fields and make auditing happy */
			if (mclaudit != NULL)
				mcl_audit_mbuf(mca, o, FALSE, FALSE);

			VERIFY(m_total(class) > 0);
			m_total(class)--;

			/* Free the mbuf */
			o->obj_next = NULL;
			slab_free(MC_MBUF, o);

			/* And free the cluster */
			((mcache_obj_t *)cl)->obj_next = NULL;
			if (class == MC_MBUF_CL)
				slab_free(MC_CL, cl);
			else if (class == MC_MBUF_BIGCL)
				slab_free(MC_BIGCL, cl);
			else
				slab_free(MC_16KCL, cl);
		}

		++num;
		tail = o;
		o = nexto;
	}

	if (!purged) {
		tail->obj_next = m_cobjlist(class);
		m_cobjlist(class) = list;
		m_infree(class) += num;
	} else if (ref_list != NULL) {
		mcache_free_ext(ref_cache, ref_list);
	}

	return (num);
}

/*
 * Common allocator for composite objects called by the CPU cache layer
 * during an allocation request whenever there is no available element in
 * the bucket layer.  It returns one or more composite elements from the
 * appropriate global freelist.  If the freelist is empty, it will attempt
 * to obtain the rudimentary objects from their caches and construct them
 * into composite mbuf + cluster objects.
 */
static unsigned int
mbuf_cslab_alloc(void *arg, mcache_obj_t ***plist, unsigned int needed,
    int wait)
{
	mbuf_class_t class = (mbuf_class_t)arg;
	mbuf_class_t cl_class = 0;
	unsigned int num = 0, cnum = 0, want = needed;
	mcache_obj_t *ref_list = NULL;
	mcache_obj_t *mp_list = NULL;
	mcache_obj_t *clp_list = NULL;
	mcache_obj_t **list;
	struct ext_ref *rfa;
	struct mbuf *m;
	void *cl;

	ASSERT(MBUF_CLASS_VALID(class) && MBUF_CLASS_COMPOSITE(class));
	ASSERT(needed > 0);

	VERIFY(class != MC_MBUF_16KCL || njcl > 0);

	/* There should not be any slab for this class */
	VERIFY(m_slab_cnt(class) == 0 &&
	    m_slablist(class).tqh_first == NULL &&
	    m_slablist(class).tqh_last == NULL);

	lck_mtx_lock(mbuf_mlock);

	/* Try using the freelist first */
	num = cslab_alloc(class, plist, needed);
	list = *plist;
	if (num == needed) {
		m_alloc_cnt(class) += num;
		lck_mtx_unlock(mbuf_mlock);
		return (needed);
	}

	lck_mtx_unlock(mbuf_mlock);

	/*
	 * We could not satisfy the request using the freelist alone;
	 * allocate from the appropriate rudimentary caches and use
	 * whatever we can get to construct the composite objects.
	 */
	needed -= num;

	/*
	 * Mark these allocation requests as coming from a composite cache.
	 * Also, if the caller is willing to be blocked, mark the request
	 * with MCR_FAILOK such that we don't end up sleeping at the mbuf
	 * slab layer waiting for the individual object when one or more
	 * of the already-constructed composite objects are available.
	 */
	wait |= MCR_COMP;
	if (!(wait & MCR_NOSLEEP))
		wait |= MCR_FAILOK;

	/* allocate mbufs */
	needed = mcache_alloc_ext(m_cache(MC_MBUF), &mp_list, needed, wait);
	if (needed == 0) {
		ASSERT(mp_list == NULL);
		goto fail;
	}

	/* allocate clusters */
	if (class == MC_MBUF_CL) {
		cl_class = MC_CL;
	} else if (class == MC_MBUF_BIGCL) {
		cl_class = MC_BIGCL;
	} else {
		VERIFY(class == MC_MBUF_16KCL);
		cl_class = MC_16KCL;
	}
	needed = mcache_alloc_ext(m_cache(cl_class), &clp_list, needed, wait);
	if (needed == 0) {
		ASSERT(clp_list == NULL);
		goto fail;
	}

	needed = mcache_alloc_ext(ref_cache, &ref_list, needed, wait);
	if (needed == 0) {
		ASSERT(ref_list == NULL);
		goto fail;
	}

	/*
	 * By this time "needed" is MIN(mbuf, cluster, ref).  Any left
	 * overs will get freed accordingly before we return to caller.
	 */
	for (cnum = 0; cnum < needed; cnum++) {
		struct mbuf *ms;

		m = ms = (struct mbuf *)mp_list;
		mp_list = mp_list->obj_next;

		cl = clp_list;
		clp_list = clp_list->obj_next;
		((mcache_obj_t *)cl)->obj_next = NULL;

		rfa = (struct ext_ref *)ref_list;
		ref_list = ref_list->obj_next;
		((mcache_obj_t *)rfa)->obj_next = NULL;

		/*
		 * If auditing is enabled, construct the shadow mbuf
		 * in the audit structure instead of in the actual one.
		 * mbuf_cslab_audit() will take care of restoring the
		 * contents after the integrity check.
		 */
		if (mclaudit != NULL) {
			mcache_audit_t *mca, *cl_mca;

			lck_mtx_lock(mbuf_mlock);
			mca = mcl_audit_buf2mca(MC_MBUF, (mcache_obj_t *)m);
			ms = ((struct mbuf *)mca->mca_contents);
			cl_mca = mcl_audit_buf2mca(MC_CL, (mcache_obj_t *)cl);

			/*
			 * Pair them up.  Note that this is done at the time
			 * the mbuf+cluster objects are constructed.  This
			 * information should be treated as "best effort"
			 * debugging hint since more than one mbufs can refer
			 * to a cluster.  In that case, the cluster might not
			 * be freed along with the mbuf it was paired with.
			 */
			mca->mca_uptr = cl_mca;
			cl_mca->mca_uptr = mca;

			ASSERT(mca->mca_uflags & MB_SCVALID);
			ASSERT(!(cl_mca->mca_uflags & MB_SCVALID));
			lck_mtx_unlock(mbuf_mlock);

			/* Technically, they are in the freelist */
			if (mclverify) {
				size_t size;

				mcache_set_pattern(MCACHE_FREE_PATTERN, m,
				    m_maxsize(MC_MBUF));

				if (class == MC_MBUF_CL)
					size = m_maxsize(MC_CL);
				else if (class == MC_MBUF_BIGCL)
					size = m_maxsize(MC_BIGCL);
				else
					size = m_maxsize(MC_16KCL);

				mcache_set_pattern(MCACHE_FREE_PATTERN, cl,
				    size);
			}
		}

		MBUF_INIT(ms, 0, MT_FREE);
		if (class == MC_MBUF_16KCL) {
			MBUF_16KCL_INIT(ms, cl, rfa, 0, EXTF_COMPOSITE);
		} else if (class == MC_MBUF_BIGCL) {
			MBUF_BIGCL_INIT(ms, cl, rfa, 0, EXTF_COMPOSITE);
		} else {
			MBUF_CL_INIT(ms, cl, rfa, 0, EXTF_COMPOSITE);
		}
		VERIFY(ms->m_flags == M_EXT);
		VERIFY(MEXT_RFA(ms) != NULL && MBUF_IS_COMPOSITE(ms));

		*list = (mcache_obj_t *)m;
		(*list)->obj_next = NULL;
		list = *plist = &(*list)->obj_next;
	}

fail:
	/*
	 * Free up what's left of the above.
	 */
	if (mp_list != NULL)
		mcache_free_ext(m_cache(MC_MBUF), mp_list);
	if (clp_list != NULL)
		mcache_free_ext(m_cache(cl_class), clp_list);
	if (ref_list != NULL)
		mcache_free_ext(ref_cache, ref_list);

	lck_mtx_lock(mbuf_mlock);
	if (num > 0 || cnum > 0) {
		m_total(class) += cnum;
		VERIFY(m_total(class) <= m_maxlimit(class));
		m_alloc_cnt(class) += num + cnum;
	}
	if ((num + cnum) < want)
		m_fail_cnt(class) += (want - (num + cnum));
	lck_mtx_unlock(mbuf_mlock);

	return (num + cnum);
}

/*
 * Common de-allocator for composite objects called by the CPU cache
 * layer when one or more elements need to be returned to the appropriate
 * global freelist.
 */
static void
mbuf_cslab_free(void *arg, mcache_obj_t *list, int purged)
{
	mbuf_class_t class = (mbuf_class_t)arg;
	unsigned int num;
	int w;

	ASSERT(MBUF_CLASS_VALID(class) && MBUF_CLASS_COMPOSITE(class));

	lck_mtx_lock(mbuf_mlock);

	num = cslab_free(class, list, purged);
	m_free_cnt(class) += num;

	if ((w = mb_waiters) > 0)
		mb_waiters = 0;

	lck_mtx_unlock(mbuf_mlock);

	if (w != 0)
		wakeup(mb_waitchan);
}

/*
 * Common auditor for composite objects called by the CPU cache layer
 * during an allocation or free request.  For the former, this is called
 * after the objects are obtained from either the bucket or slab layer
 * and before they are returned to the caller.  For the latter, this is
 * called immediately during free and before placing the objects into
 * the bucket or slab layer.
 */
static void
mbuf_cslab_audit(void *arg, mcache_obj_t *list, boolean_t alloc)
{
	mbuf_class_t class = (mbuf_class_t)arg;
	mcache_audit_t *mca;
	struct mbuf *m, *ms;
	mcl_slab_t *clsp, *nsp;
	size_t size;
	void *cl;

	ASSERT(MBUF_CLASS_VALID(class) && MBUF_CLASS_COMPOSITE(class));

	while ((m = ms = (struct mbuf *)list) != NULL) {
		lck_mtx_lock(mbuf_mlock);
		/* Do the mbuf sanity checks and record its transaction */
		mca = mcl_audit_buf2mca(MC_MBUF, (mcache_obj_t *)m);
		mcl_audit_mbuf(mca, m, TRUE, alloc);
		if (mcltrace)
			mcache_buffer_log(mca, m, m_cache(class));

		if (alloc)
			mca->mca_uflags |= MB_COMP_INUSE;
		else
			mca->mca_uflags &= ~MB_COMP_INUSE;

		/*
		 * Use the shadow mbuf in the audit structure if we are
		 * freeing, since the contents of the actual mbuf has been
		 * pattern-filled by the above call to mcl_audit_mbuf().
		 */
		if (!alloc && mclverify)
			ms = (struct mbuf *)mca->mca_contents;

		/* Do the cluster sanity checks and record its transaction */
		cl = ms->m_ext.ext_buf;
		clsp = slab_get(cl);
		VERIFY(ms->m_flags == M_EXT && cl != NULL);
		VERIFY(MEXT_RFA(ms) != NULL && MBUF_IS_COMPOSITE(ms));
		if (class == MC_MBUF_CL)
			VERIFY(clsp->sl_refcnt >= 1 &&
			    clsp->sl_refcnt <= NCLPBG);
		else
			VERIFY(clsp->sl_refcnt == 1);

		if (class == MC_MBUF_16KCL) {
			int k;
			for (nsp = clsp, k = 1; k < NSLABSP16KB; k++) {
				nsp = nsp->sl_next;
				/* Next slab must already be present */
				VERIFY(nsp != NULL);
				VERIFY(nsp->sl_refcnt == 1);
			}
		}

		mca = mcl_audit_buf2mca(MC_CL, cl);
		if (class == MC_MBUF_CL)
			size = m_maxsize(MC_CL);
		else if (class == MC_MBUF_BIGCL)
			size = m_maxsize(MC_BIGCL);
		else
			size = m_maxsize(MC_16KCL);
		mcl_audit_cluster(mca, cl, size, alloc, FALSE);
		if (mcltrace)
			mcache_buffer_log(mca, cl, m_cache(class));

		if (alloc)
			mca->mca_uflags |= MB_COMP_INUSE;
		else
			mca->mca_uflags &= ~MB_COMP_INUSE;
		lck_mtx_unlock(mbuf_mlock);

		list = list->obj_next;
	}
}

/*
 * Allocate some number of mbuf clusters and place on cluster freelist.
 */
static int
m_clalloc(const u_int32_t num, const int wait, const u_int32_t bufsize)
{
	int i;
	vm_size_t size = 0;
	int numpages = 0, large_buffer = (bufsize == m_maxsize(MC_16KCL));
	vm_offset_t page = 0;
	mcache_audit_t *mca_list = NULL;
	mcache_obj_t *con_list = NULL;
	mcl_slab_t *sp;

	VERIFY(bufsize == m_maxsize(MC_BIGCL) ||
	    bufsize == m_maxsize(MC_16KCL));

	lck_mtx_assert(mbuf_mlock, LCK_MTX_ASSERT_OWNED);

	/*
	 * Multiple threads may attempt to populate the cluster map one
	 * after another.  Since we drop the lock below prior to acquiring
	 * the physical page(s), our view of the cluster map may no longer
	 * be accurate, and we could end up over-committing the pages beyond
	 * the maximum allowed for each class.  To prevent it, this entire
	 * operation (including the page mapping) is serialized.
	 */
	while (mb_clalloc_busy) {
		mb_clalloc_waiters++;
		(void) msleep(mb_clalloc_waitchan, mbuf_mlock,
		    (PZERO-1), "m_clalloc", NULL);
		lck_mtx_assert(mbuf_mlock, LCK_MTX_ASSERT_OWNED);
	}

	/* We are busy now; tell everyone else to go away */
	mb_clalloc_busy = TRUE;

	/*
	 * Honor the caller's wish to block or not block.  We have a way
	 * to grow the pool asynchronously using the mbuf worker thread.
	 */
	i = m_howmany(num, bufsize);
	if (i == 0 || (wait & M_DONTWAIT))
		goto out;

	lck_mtx_unlock(mbuf_mlock);

	size = round_page(i * bufsize);
	page = kmem_mb_alloc(mb_map, size, large_buffer);

	/*
	 * If we did ask for "n" 16KB physically contiguous chunks
	 * and didn't get them, then please try again without this
	 * restriction.
	 */
	if (large_buffer && page == 0)
		page = kmem_mb_alloc(mb_map, size, 0);

	if (page == 0) {
		if (bufsize == m_maxsize(MC_BIGCL)) {
			/* Try for 1 page if failed, only 4KB request */
			size = NBPG;
			page = kmem_mb_alloc(mb_map, size, 0);
		}

		if (page == 0) {
			lck_mtx_lock(mbuf_mlock);
			goto out;
		}
	}

	VERIFY(IS_P2ALIGNED(page, NBPG));
	numpages = size / NBPG;

	/* If auditing is enabled, allocate the audit structures now */
	if (mclaudit != NULL) {
		int needed;

		/*
		 * Yes, I realize this is a waste of memory for clusters
		 * that never get transformed into mbufs, as we may end
		 * up with NMBPBG-1 unused audit structures per cluster.
		 * But doing so tremendously simplifies the allocation
		 * strategy, since at this point we are not holding the
		 * mbuf lock and the caller is okay to be blocked.
		 */
		if (bufsize == m_maxsize(MC_BIGCL)) {
			needed = numpages * NMBPBG;

			i = mcache_alloc_ext(mcl_audit_con_cache,
			    &con_list, needed, MCR_SLEEP);

			VERIFY(con_list != NULL && i == needed);
		} else {
			needed = numpages / NSLABSP16KB;
		}

		i = mcache_alloc_ext(mcache_audit_cache,
		    (mcache_obj_t **)&mca_list, needed, MCR_SLEEP);

		VERIFY(mca_list != NULL && i == needed);
	}

	lck_mtx_lock(mbuf_mlock);

	for (i = 0; i < numpages; i++, page += NBPG) {
		ppnum_t offset = ((char *)page - (char *)mbutl) / NBPG;
		ppnum_t new_page = pmap_find_phys(kernel_pmap,
		    (vm_offset_t)page);

		/*
		 * In the case of no mapper being available the following
		 * code noops and returns the input page; if there is a
		 * mapper the appropriate I/O page is returned.
		 */
		VERIFY(offset < mcl_pages);
		new_page = IOMapperInsertPage(mcl_paddr_base, offset, new_page);
		mcl_paddr[offset] = new_page << PGSHIFT;

		/* Pattern-fill this fresh page */
		if (mclverify) {
			mcache_set_pattern(MCACHE_FREE_PATTERN,
			    (caddr_t)page, NBPG);
		}
		if (bufsize == m_maxsize(MC_BIGCL)) {
			union mbigcluster *mbc = (union mbigcluster *)page;

			/* One for the entire page */
			sp = slab_get(mbc);
			if (mclaudit != NULL) {
				mcl_audit_init(mbc, &mca_list, &con_list,
				    AUDIT_CONTENTS_SIZE, NMBPBG);
			}
			VERIFY(sp->sl_refcnt == 0 && sp->sl_flags == 0);
			slab_init(sp, MC_BIGCL, SLF_MAPPED,
			    mbc, mbc, bufsize, 0, 1);

			/* Insert this slab */
			slab_insert(sp, MC_BIGCL);

			/* Update stats now since slab_get() drops the lock */
			mbstat.m_bigclfree = ++m_infree(MC_BIGCL) +
			    m_infree(MC_MBUF_BIGCL);
			mbstat.m_bigclusters = ++m_total(MC_BIGCL);
			VERIFY(m_total(MC_BIGCL) <= m_maxlimit(MC_BIGCL));
		} else if ((i % NSLABSP16KB) == 0) {
			union m16kcluster *m16kcl = (union m16kcluster *)page;
			mcl_slab_t *nsp;
			int k;

			VERIFY(njcl > 0);
			/* One for the entire 16KB */
			sp = slab_get(m16kcl);
			if (mclaudit != NULL)
				mcl_audit_init(m16kcl, &mca_list, NULL, 0, 1);

			VERIFY(sp->sl_refcnt == 0 && sp->sl_flags == 0);
			slab_init(sp, MC_16KCL, SLF_MAPPED,
			    m16kcl, m16kcl, bufsize, 0, 1);

			/*
			 * 2nd-Nth page's slab is part of the first one,
			 * where N is NSLABSP16KB.
			 */
			for (k = 1; k < NSLABSP16KB; k++) {
				nsp = slab_get(((union mbigcluster *)page) + k);
				VERIFY(nsp->sl_refcnt == 0 &&
				    nsp->sl_flags == 0);
				slab_init(nsp, MC_16KCL,
				    SLF_MAPPED | SLF_PARTIAL,
				    m16kcl, NULL, 0, 0, 0);
			}

			/* Insert this slab */
			slab_insert(sp, MC_16KCL);

			/* Update stats now since slab_get() drops the lock */
			m_infree(MC_16KCL)++;
			m_total(MC_16KCL)++;
			VERIFY(m_total(MC_16KCL) <= m_maxlimit(MC_16KCL));
		}
	}
	VERIFY(mca_list == NULL && con_list == NULL);

	/* We're done; let others enter */
	mb_clalloc_busy = FALSE;
	if (mb_clalloc_waiters > 0) {
		mb_clalloc_waiters = 0;
		wakeup(mb_clalloc_waitchan);
	}

	if (bufsize == m_maxsize(MC_BIGCL))
		return (numpages);

	VERIFY(bufsize == m_maxsize(MC_16KCL));
	return (numpages / NSLABSP16KB);

out:
	lck_mtx_assert(mbuf_mlock, LCK_MTX_ASSERT_OWNED);

	/* We're done; let others enter */
	mb_clalloc_busy = FALSE;
	if (mb_clalloc_waiters > 0) {
		mb_clalloc_waiters = 0;
		wakeup(mb_clalloc_waitchan);
	}

	/*
	 * When non-blocking we kick a thread if we have to grow the
	 * pool or if the number of free clusters is less than requested.
	 */
	if (bufsize == m_maxsize(MC_BIGCL)) {
		if (i > 0) {
			/*
			 * Remember total number of 4KB clusters needed
			 * at this time.
			 */
			i += m_total(MC_BIGCL);
			if (i > mbuf_expand_big) {
				mbuf_expand_big = i;
				if (mbuf_worker_ready)
					wakeup((caddr_t)&mbuf_worker_run);
			}
		}

		if (m_infree(MC_BIGCL) >= num)
			return (1);
	} else {
		if (i > 0) {
			/*
			 * Remember total number of 16KB clusters needed
			 * at this time.
			 */
			i += m_total(MC_16KCL);
			if (i > mbuf_expand_16k) {
				mbuf_expand_16k = i;
				if (mbuf_worker_ready)
					wakeup((caddr_t)&mbuf_worker_run);
			}
		}

		if (m_infree(MC_16KCL) >= num)
			return (1);
	}
	return (0);
}

/*
 * Populate the global freelist of the corresponding buffer class.
 */
static int
freelist_populate(mbuf_class_t class, unsigned int num, int wait)
{
	mcache_obj_t *o = NULL;
	int i, numpages = 0, count;

	VERIFY(class == MC_MBUF || class == MC_CL || class == MC_BIGCL ||
	    class == MC_16KCL);

	lck_mtx_assert(mbuf_mlock, LCK_MTX_ASSERT_OWNED);

	switch (class) {
	case MC_MBUF:
	case MC_CL:
	case MC_BIGCL:
		numpages = (num * m_size(class) + NBPG - 1) / NBPG;
		i = m_clalloc(numpages, wait, m_maxsize(MC_BIGCL));

		/* Respect the 4KB clusters minimum limit */
		if (m_total(MC_BIGCL) == m_maxlimit(MC_BIGCL) &&
		    m_infree(MC_BIGCL) <= m_minlimit(MC_BIGCL)) {
			if (class != MC_BIGCL || (wait & MCR_COMP))
				return (0);
		}
		if (class == MC_BIGCL)
			return (i != 0);
		break;

	case MC_16KCL:
		return (m_clalloc(num, wait, m_maxsize(class)) != 0);
		/* NOTREACHED */

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	VERIFY(class == MC_MBUF || class == MC_CL);

	/* how many objects will we cut the page into? */
	int numobj = (class == MC_MBUF ? NMBPBG : NCLPBG);

	for (count = 0; count < numpages; count++) {

		/* respect totals, minlimit, maxlimit */
		if (m_total(MC_BIGCL) <= m_minlimit(MC_BIGCL) ||
		    m_total(class) >= m_maxlimit(class))
			break;

		if ((o = slab_alloc(MC_BIGCL, wait)) == NULL)
			break;

		struct mbuf *m = (struct mbuf *)o;
		union mcluster *c = (union mcluster *)o;
		mcl_slab_t *sp = slab_get(o);
		mcache_audit_t *mca = NULL;

		VERIFY(slab_is_detached(sp) &&
		    (sp->sl_flags & (SLF_MAPPED | SLF_PARTIAL)) == SLF_MAPPED);

		/*
		 * Make sure that the cluster is unmolested
		 * while in freelist
		 */
		if (mclverify) {
			mca = mcl_audit_buf2mca(MC_BIGCL, o);
			mcache_audit_free_verify(mca, o, 0,
			    m_maxsize(MC_BIGCL));
		}

		/* Reinitialize it as an mbuf or 2K slab */
		slab_init(sp, class, sp->sl_flags,
		    sp->sl_base, NULL, sp->sl_len, 0, numobj);

		VERIFY(o == (mcache_obj_t *)sp->sl_base);
		VERIFY(sp->sl_head == NULL);

		VERIFY(m_total(MC_BIGCL) > 0);
		m_total(MC_BIGCL)--;
		mbstat.m_bigclusters = m_total(MC_BIGCL);

		m_total(class) += numobj;
		m_infree(class) += numobj;

		VERIFY(m_total(MC_BIGCL) >= m_minlimit(MC_BIGCL));
		VERIFY(m_total(class) <= m_maxlimit(class));

		i = numobj;
		if (class == MC_MBUF) {
			mbstat.m_mbufs = m_total(MC_MBUF);
			mtype_stat_add(MT_FREE, NMBPBG);
			while (i--) {
				/*
				 * If auditing is enabled, construct the
				 * shadow mbuf in the audit structure
				 * instead of the actual one.
				 * mbuf_slab_audit() will take care of
				 * restoring the contents after the
				 * integrity check.
				 */
				if (mclaudit != NULL) {
					struct mbuf *ms;
					mca = mcl_audit_buf2mca(MC_MBUF,
					    (mcache_obj_t *)m);
					ms = ((struct mbuf *)
					    mca->mca_contents);
					ms->m_type = MT_FREE;
				} else {
					m->m_type = MT_FREE;
				}
				m->m_next = sp->sl_head;
				sp->sl_head = (void *)m++;
			}
		} else { /* MC_CL */
			mbstat.m_clfree =
			    m_infree(MC_CL) + m_infree(MC_MBUF_CL);
			mbstat.m_clusters = m_total(MC_CL);
			while (i--) {
				c->mcl_next = sp->sl_head;
				sp->sl_head = (void *)c++;
			}
		}

		/* Insert into the mbuf or 2k slab list */
		slab_insert(sp, class);

		if ((i = mb_waiters) > 0)
			mb_waiters = 0;
		if (i != 0)
			wakeup(mb_waitchan);
	}
	return (count != 0);
}

/*
 * For each class, initialize the freelist to hold m_minlimit() objects.
 */
static void
freelist_init(mbuf_class_t class)
{
	lck_mtx_assert(mbuf_mlock, LCK_MTX_ASSERT_OWNED);

	VERIFY(class == MC_CL || class == MC_BIGCL);
	VERIFY(m_total(class) == 0);
	VERIFY(m_minlimit(class) > 0);

	while (m_total(class) < m_minlimit(class))
		(void) freelist_populate(class, m_minlimit(class), M_WAIT);

	VERIFY(m_total(class) >= m_minlimit(class));
}

/*
 * (Inaccurately) check if it might be worth a trip back to the
 * mcache layer due the availability of objects there.  We'll
 * end up back here if there's nothing up there.
 */
static boolean_t
mbuf_cached_above(mbuf_class_t class, int wait)
{
	switch (class) {
	case MC_MBUF:
		if (wait & MCR_COMP)
			return (!mcache_bkt_isempty(m_cache(MC_MBUF_CL)) ||
			    !mcache_bkt_isempty(m_cache(MC_MBUF_BIGCL)));
		break;

	case MC_CL:
		if (wait & MCR_COMP)
			return (!mcache_bkt_isempty(m_cache(MC_MBUF_CL)));
		break;

	case MC_BIGCL:
		if (wait & MCR_COMP)
			return (!mcache_bkt_isempty(m_cache(MC_MBUF_BIGCL)));
		break;

	case MC_16KCL:
		if (wait & MCR_COMP)
			return (!mcache_bkt_isempty(m_cache(MC_MBUF_16KCL)));
		break;

	case MC_MBUF_CL:
	case MC_MBUF_BIGCL:
	case MC_MBUF_16KCL:
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (!mcache_bkt_isempty(m_cache(class)));
}

/*
 * If possible, convert constructed objects to raw ones.
 */
static boolean_t
mbuf_steal(mbuf_class_t class, unsigned int num)
{
	mcache_obj_t *top = NULL;
	mcache_obj_t **list = &top;
	unsigned int tot = 0;

	lck_mtx_assert(mbuf_mlock, LCK_MTX_ASSERT_OWNED);

	switch (class) {
	case MC_MBUF:
	case MC_CL:
	case MC_BIGCL:
	case MC_16KCL:
		return (FALSE);

	case MC_MBUF_CL:
	case MC_MBUF_BIGCL:
	case MC_MBUF_16KCL:
		/* Get the required number of constructed objects if possible */
		if (m_infree(class) > m_minlimit(class)) {
			tot = cslab_alloc(class, &list,
			    MIN(num, m_infree(class)));
		}

		/* And destroy them to get back the raw objects */
		if (top != NULL)
			(void) cslab_free(class, top, 1);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (tot == num);
}

static void
m_reclaim(mbuf_class_t class, unsigned int num, boolean_t comp)
{
	int m, bmap = 0;

	lck_mtx_assert(mbuf_mlock, LCK_MTX_ASSERT_OWNED);

	VERIFY(m_total(MC_CL) <= m_maxlimit(MC_CL));
	VERIFY(m_total(MC_BIGCL) <= m_maxlimit(MC_BIGCL));
	VERIFY(m_total(MC_16KCL) <= m_maxlimit(MC_16KCL));

	/*
	 * This logic can be made smarter; for now, simply mark
	 * all other related classes as potential victims.
	 */
	switch (class) {
	case MC_MBUF:
		m_wantpurge(MC_CL)++;
		m_wantpurge(MC_BIGCL)++;
		m_wantpurge(MC_MBUF_CL)++;
		m_wantpurge(MC_MBUF_BIGCL)++;
		break;

	case MC_CL:
		m_wantpurge(MC_MBUF)++;
		m_wantpurge(MC_BIGCL)++;
		m_wantpurge(MC_MBUF_BIGCL)++;
		if (!comp)
			m_wantpurge(MC_MBUF_CL)++;
		break;

	case MC_BIGCL:
		m_wantpurge(MC_MBUF)++;
		m_wantpurge(MC_CL)++;
		m_wantpurge(MC_MBUF_CL)++;
		if (!comp)
			m_wantpurge(MC_MBUF_BIGCL)++;
		break;

	case MC_16KCL:
		if (!comp)
			m_wantpurge(MC_MBUF_16KCL)++;
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	/*
	 * Run through each marked class and check if we really need to
	 * purge (and therefore temporarily disable) the per-CPU caches
	 * layer used by the class.  If so, remember the classes since
	 * we are going to drop the lock below prior to purging.
	 */
	for (m = 0; m < NELEM(mbuf_table); m++) {
		if (m_wantpurge(m) > 0) {
			m_wantpurge(m) = 0;
			/*
			 * Try hard to steal the required number of objects
			 * from the freelist of other mbuf classes.  Only
			 * purge and disable the per-CPU caches layer when
			 * we don't have enough; it's the last resort.
			 */
			if (!mbuf_steal(m, num))
				bmap |= (1 << m);
		}
	}

	lck_mtx_unlock(mbuf_mlock);

	if (bmap != 0) {
		/* drain is performed in pfslowtimo(), to avoid deadlocks */
		do_reclaim = 1;

		/* Sigh; we have no other choices but to ask mcache to purge */
		for (m = 0; m < NELEM(mbuf_table); m++) {
			if ((bmap & (1 << m)) &&
			    mcache_purge_cache(m_cache(m))) {
				lck_mtx_lock(mbuf_mlock);
				m_purge_cnt(m)++;
				mbstat.m_drain++;
				lck_mtx_unlock(mbuf_mlock);
			}
		}
	} else {
		/*
		 * Request mcache to reap extra elements from all of its caches;
		 * note that all reaps are serialized and happen only at a fixed
		 * interval.
		 */
		mcache_reap();
	}
	lck_mtx_lock(mbuf_mlock);
}

static inline struct mbuf *
m_get_common(int wait, short type, int hdr)
{
	struct mbuf *m;
	int mcflags = MSLEEPF(wait);

	/* Is this due to a non-blocking retry?  If so, then try harder */
	if (mcflags & MCR_NOSLEEP)
		mcflags |= MCR_TRYHARD;

	m = mcache_alloc(m_cache(MC_MBUF), mcflags);
	if (m != NULL) {
		MBUF_INIT(m, hdr, type);
		mtype_stat_inc(type);
		mtype_stat_dec(MT_FREE);
#if CONFIG_MACF_NET
		if (hdr && mac_init_mbuf(m, wait) != 0) {
			m_free(m);
			return (NULL);
		}
#endif /* MAC_NET */
	}
	return (m);
}

/*
 * Space allocation routines; these are also available as macros
 * for critical paths.
 */
#define	_M_GET(wait, type)	m_get_common(wait, type, 0)
#define	_M_GETHDR(wait, type)	m_get_common(wait, type, 1)
#define	_M_RETRY(wait, type)	_M_GET(wait, type)
#define	_M_RETRYHDR(wait, type)	_M_GETHDR(wait, type)
#define	_MGET(m, how, type)	((m) = _M_GET(how, type))
#define	_MGETHDR(m, how, type)	((m) = _M_GETHDR(how, type))

struct mbuf *
m_get(int wait, int type)
{
	return (_M_GET(wait, type));
}

struct mbuf *
m_gethdr(int wait, int type)
{
	return (_M_GETHDR(wait, type));
}

struct mbuf *
m_retry(int wait, int type)
{
	return (_M_RETRY(wait, type));
}

struct mbuf *
m_retryhdr(int wait, int type)
{
	return (_M_RETRYHDR(wait, type));
}

struct mbuf *
m_getclr(int wait, int type)
{
	struct mbuf *m;

	_MGET(m, wait, type);
	if (m != NULL)
		bzero(MTOD(m, caddr_t), MLEN);
	return (m);
}

struct mbuf *
m_free(struct mbuf *m)
{
	struct mbuf *n = m->m_next;

	if (m->m_type == MT_FREE)
		panic("m_free: freeing an already freed mbuf");

	/* Free the aux data and tags if there is any */
	if (m->m_flags & M_PKTHDR) {
		m_tag_delete_chain(m, NULL);
	}

	if (m->m_flags & M_EXT) {
		u_int32_t refcnt;
		u_int32_t composite;

		refcnt = m_decref(m);
		composite = (MEXT_FLAGS(m) & EXTF_COMPOSITE);
		if (refcnt == 0 && !composite) {
			if (m->m_ext.ext_free == NULL) {
				mcache_free(m_cache(MC_CL), m->m_ext.ext_buf);
			} else if (m->m_ext.ext_free == m_bigfree) {
				mcache_free(m_cache(MC_BIGCL),
				    m->m_ext.ext_buf);
			} else if (m->m_ext.ext_free == m_16kfree) {
				mcache_free(m_cache(MC_16KCL),
				    m->m_ext.ext_buf);
			} else {
				(*(m->m_ext.ext_free))(m->m_ext.ext_buf,
				    m->m_ext.ext_size, m->m_ext.ext_arg);
			}
			mcache_free(ref_cache, MEXT_RFA(m));
			MEXT_RFA(m) = NULL;
		} else if (refcnt == 0 && composite) {
			VERIFY(m->m_type != MT_FREE);

			mtype_stat_dec(m->m_type);
			mtype_stat_inc(MT_FREE);

			m->m_type = MT_FREE;
			m->m_flags = M_EXT;
			m->m_len = 0;
			m->m_next = m->m_nextpkt = NULL;

			MEXT_FLAGS(m) &= ~EXTF_READONLY;

			/* "Free" into the intermediate cache */
			if (m->m_ext.ext_free == NULL) {
				mcache_free(m_cache(MC_MBUF_CL), m);
			} else if (m->m_ext.ext_free == m_bigfree) {
				mcache_free(m_cache(MC_MBUF_BIGCL), m);
			} else {
				VERIFY(m->m_ext.ext_free == m_16kfree);
				mcache_free(m_cache(MC_MBUF_16KCL), m);
			}
			return (n);
		}
	}

	if (m->m_type != MT_FREE) {
		mtype_stat_dec(m->m_type);
		mtype_stat_inc(MT_FREE);
	}

	m->m_type = MT_FREE;
	m->m_flags = m->m_len = 0;
	m->m_next = m->m_nextpkt = NULL;

	mcache_free(m_cache(MC_MBUF), m);

	return (n);
}

__private_extern__ struct mbuf *
m_clattach(struct mbuf *m, int type, caddr_t extbuf,
    void (*extfree)(caddr_t, u_int, caddr_t), u_int extsize, caddr_t extarg,
    int wait)
{
	struct ext_ref *rfa = NULL;

	if (m == NULL && (m = _M_GETHDR(wait, type)) == NULL)
		return (NULL);

	if (m->m_flags & M_EXT) {
		u_int32_t refcnt;
		u_int32_t composite;

		refcnt = m_decref(m);
		composite = (MEXT_FLAGS(m) & EXTF_COMPOSITE);
		if (refcnt == 0 && !composite) {
			if (m->m_ext.ext_free == NULL) {
				mcache_free(m_cache(MC_CL), m->m_ext.ext_buf);
			} else if (m->m_ext.ext_free == m_bigfree) {
				mcache_free(m_cache(MC_BIGCL),
				    m->m_ext.ext_buf);
			} else if (m->m_ext.ext_free == m_16kfree) {
				mcache_free(m_cache(MC_16KCL),
				    m->m_ext.ext_buf);
			} else {
				(*(m->m_ext.ext_free))(m->m_ext.ext_buf,
				    m->m_ext.ext_size, m->m_ext.ext_arg);
			}
			/* Re-use the reference structure */
			rfa = MEXT_RFA(m);
		} else if (refcnt == 0 && composite) {
			VERIFY(m->m_type != MT_FREE);

			mtype_stat_dec(m->m_type);
			mtype_stat_inc(MT_FREE);

			m->m_type = MT_FREE;
			m->m_flags = M_EXT;
			m->m_len = 0;
			m->m_next = m->m_nextpkt = NULL;

			MEXT_FLAGS(m) &= ~EXTF_READONLY;

			/* "Free" into the intermediate cache */
			if (m->m_ext.ext_free == NULL) {
				mcache_free(m_cache(MC_MBUF_CL), m);
			} else if (m->m_ext.ext_free == m_bigfree) {
				mcache_free(m_cache(MC_MBUF_BIGCL), m);
			} else {
				VERIFY(m->m_ext.ext_free == m_16kfree);
				mcache_free(m_cache(MC_MBUF_16KCL), m);
			}
			/*
			 * Allocate a new mbuf, since we didn't divorce
			 * the composite mbuf + cluster pair above.
			 */
			if ((m = _M_GETHDR(wait, type)) == NULL)
				return (NULL);
		}
	}

	if (rfa == NULL &&
	    (rfa = mcache_alloc(ref_cache, MSLEEPF(wait))) == NULL) {
		m_free(m);
		return (NULL);
	}

	MEXT_INIT(m, extbuf, extsize, extfree, extarg, rfa, 1, 0);

	return (m);
}

/*
 * Perform `fast' allocation mbuf clusters from a cache of recently-freed
 * clusters. (If the cache is empty, new clusters are allocated en-masse.)
 */
struct mbuf *
m_getcl(int wait, int type, int flags)
{
	struct mbuf *m;
	int mcflags = MSLEEPF(wait);
	int hdr = (flags & M_PKTHDR);

	/* Is this due to a non-blocking retry?  If so, then try harder */
	if (mcflags & MCR_NOSLEEP)
		mcflags |= MCR_TRYHARD;

	m = mcache_alloc(m_cache(MC_MBUF_CL), mcflags);
	if (m != NULL) {
		u_int32_t flag;
		struct ext_ref *rfa;
		void *cl;

		VERIFY(m->m_type == MT_FREE && m->m_flags == M_EXT);
		cl = m->m_ext.ext_buf;
		rfa = MEXT_RFA(m);

		ASSERT(cl != NULL && rfa != NULL);
		VERIFY(MBUF_IS_COMPOSITE(m) && m->m_ext.ext_free == NULL);

		flag = MEXT_FLAGS(m);

		MBUF_INIT(m, hdr, type);
		MBUF_CL_INIT(m, cl, rfa, 1, flag);

		mtype_stat_inc(type);
		mtype_stat_dec(MT_FREE);
#if CONFIG_MACF_NET
		if (hdr && mac_init_mbuf(m, wait) != 0) {
			m_freem(m);
			return (NULL);
		}
#endif /* MAC_NET */
	}
	return (m);
}

/* m_mclget() add an mbuf cluster to a normal mbuf */
struct mbuf *
m_mclget(struct mbuf *m, int wait)
{
	struct ext_ref *rfa;

	if ((rfa = mcache_alloc(ref_cache, MSLEEPF(wait))) == NULL)
		return (m);

	m->m_ext.ext_buf = m_mclalloc(wait);
	if (m->m_ext.ext_buf != NULL) {
		MBUF_CL_INIT(m, m->m_ext.ext_buf, rfa, 1, 0);
	} else {
		mcache_free(ref_cache, rfa);
	}
	return (m);
}

/* Allocate an mbuf cluster */
caddr_t
m_mclalloc(int wait)
{
	int mcflags = MSLEEPF(wait);

	/* Is this due to a non-blocking retry?  If so, then try harder */
	if (mcflags & MCR_NOSLEEP)
		mcflags |= MCR_TRYHARD;

	return (mcache_alloc(m_cache(MC_CL), mcflags));
}

/* Free an mbuf cluster */
void
m_mclfree(caddr_t p)
{
	mcache_free(m_cache(MC_CL), p);
}

/*
 * mcl_hasreference() checks if a cluster of an mbuf is referenced by
 * another mbuf; see comments in m_incref() regarding EXTF_READONLY.
 */
int
m_mclhasreference(struct mbuf *m)
{
	if (!(m->m_flags & M_EXT))
		return (0);

	ASSERT(MEXT_RFA(m) != NULL);

	return ((MEXT_FLAGS(m) & EXTF_READONLY) ? 1 : 0);
}

__private_extern__ caddr_t
m_bigalloc(int wait)
{
	int mcflags = MSLEEPF(wait);

	/* Is this due to a non-blocking retry?  If so, then try harder */
	if (mcflags & MCR_NOSLEEP)
		mcflags |= MCR_TRYHARD;

	return (mcache_alloc(m_cache(MC_BIGCL), mcflags));
}

__private_extern__ void
m_bigfree(caddr_t p, __unused u_int size, __unused caddr_t arg)
{
	mcache_free(m_cache(MC_BIGCL), p);
}

/* m_mbigget() add an 4KB mbuf cluster to a normal mbuf */
__private_extern__ struct mbuf *
m_mbigget(struct mbuf *m, int wait)
{
	struct ext_ref *rfa;

	if ((rfa = mcache_alloc(ref_cache, MSLEEPF(wait))) == NULL)
		return (m);

	m->m_ext.ext_buf =  m_bigalloc(wait);
	if (m->m_ext.ext_buf != NULL) {
		MBUF_BIGCL_INIT(m, m->m_ext.ext_buf, rfa, 1, 0);
	} else {
		mcache_free(ref_cache, rfa);
	}
	return (m);
}

__private_extern__ caddr_t
m_16kalloc(int wait)
{
	int mcflags = MSLEEPF(wait);

	/* Is this due to a non-blocking retry?  If so, then try harder */
	if (mcflags & MCR_NOSLEEP)
		mcflags |= MCR_TRYHARD;

	return (mcache_alloc(m_cache(MC_16KCL), mcflags));
}

__private_extern__ void
m_16kfree(caddr_t p, __unused u_int size, __unused caddr_t arg)
{
	mcache_free(m_cache(MC_16KCL), p);
}

/* m_m16kget() add a 16KB mbuf cluster to a normal mbuf */
__private_extern__ struct mbuf *
m_m16kget(struct mbuf *m, int wait)
{
	struct ext_ref *rfa;

	if ((rfa = mcache_alloc(ref_cache, MSLEEPF(wait))) == NULL)
		return (m);

	m->m_ext.ext_buf =  m_16kalloc(wait);
	if (m->m_ext.ext_buf != NULL) {
		MBUF_16KCL_INIT(m, m->m_ext.ext_buf, rfa, 1, 0);
	} else {
		mcache_free(ref_cache, rfa);
	}
	return (m);
}

/*
 * "Move" mbuf pkthdr from "from" to "to".
 * "from" must have M_PKTHDR set, and "to" must be empty.
 */
void
m_copy_pkthdr(struct mbuf *to, struct mbuf *from)
{
	/* We will be taking over the tags of 'to' */
	if (to->m_flags & M_PKTHDR)
		m_tag_delete_chain(to, NULL);
	to->m_pkthdr = from->m_pkthdr;		/* especially tags */
	m_tag_init(from);			/* purge tags from src */
	m_prio_init(from);			/* reset priority from src */
	to->m_flags = (from->m_flags & M_COPYFLAGS) | (to->m_flags & M_EXT);
	if ((to->m_flags & M_EXT) == 0)
		to->m_data = to->m_pktdat;
}

/*
 * Duplicate "from"'s mbuf pkthdr in "to".
 * "from" must have M_PKTHDR set, and "to" must be empty.
 * In particular, this does a deep copy of the packet tags.
 */
static int
m_dup_pkthdr(struct mbuf *to, struct mbuf *from, int how)
{
	if (to->m_flags & M_PKTHDR)
		m_tag_delete_chain(to, NULL);
	to->m_flags = (from->m_flags & M_COPYFLAGS) | (to->m_flags & M_EXT);
	if ((to->m_flags & M_EXT) == 0)
		to->m_data = to->m_pktdat;
	to->m_pkthdr = from->m_pkthdr;
	m_tag_init(to);
	return (m_tag_copy_chain(to, from, how));
}

/*
 * Return a list of mbuf hdrs that point to clusters.  Try for num_needed;
 * if wantall is not set, return whatever number were available.  Set up the
 * first num_with_pkthdrs with mbuf hdrs configured as packet headers; these
 * are chained on the m_nextpkt field.  Any packets requested beyond this
 * are chained onto the last packet header's m_next field.  The size of
 * the cluster is controlled by the parameter bufsize.
 */
__private_extern__ struct mbuf *
m_getpackets_internal(unsigned int *num_needed, int num_with_pkthdrs,
    int wait, int wantall, size_t bufsize)
{
	struct mbuf *m;
	struct mbuf **np, *top;
	unsigned int pnum, needed = *num_needed;
	mcache_obj_t *mp_list = NULL;
	int mcflags = MSLEEPF(wait);
	u_int32_t flag;
	struct ext_ref *rfa;
	mcache_t *cp;
	void *cl;

	ASSERT(bufsize == m_maxsize(MC_CL) ||
	    bufsize == m_maxsize(MC_BIGCL) ||
	    bufsize == m_maxsize(MC_16KCL));

	/*
	 * Caller must first check for njcl because this
	 * routine is internal and not exposed/used via KPI.
	 */
	VERIFY(bufsize != m_maxsize(MC_16KCL) || njcl > 0);

	top = NULL;
	np = &top;
	pnum = 0;

	/*
	 * The caller doesn't want all the requested buffers; only some.
	 * Try hard to get what we can, but don't block.  This effectively
	 * overrides MCR_SLEEP, since this thread will not go to sleep
	 * if we can't get all the buffers.
	 */
	if (!wantall || (mcflags & MCR_NOSLEEP))
		mcflags |= MCR_TRYHARD;

	/* Allocate the composite mbuf + cluster elements from the cache */
	if (bufsize == m_maxsize(MC_CL))
		cp = m_cache(MC_MBUF_CL);
	else if (bufsize == m_maxsize(MC_BIGCL))
		cp = m_cache(MC_MBUF_BIGCL);
	else
		cp = m_cache(MC_MBUF_16KCL);
	needed = mcache_alloc_ext(cp, &mp_list, needed, mcflags);

	for (pnum = 0; pnum < needed; pnum++) {
		m = (struct mbuf *)mp_list;
		mp_list = mp_list->obj_next;

		VERIFY(m->m_type == MT_FREE && m->m_flags == M_EXT);
		cl = m->m_ext.ext_buf;
		rfa = MEXT_RFA(m);

		ASSERT(cl != NULL && rfa != NULL);
		VERIFY(MBUF_IS_COMPOSITE(m));

		flag = MEXT_FLAGS(m);

		MBUF_INIT(m, num_with_pkthdrs, MT_DATA);
		if (bufsize == m_maxsize(MC_16KCL)) {
			MBUF_16KCL_INIT(m, cl, rfa, 1, flag);
		} else if (bufsize == m_maxsize(MC_BIGCL)) {
			MBUF_BIGCL_INIT(m, cl, rfa, 1, flag);
		} else {
			MBUF_CL_INIT(m, cl, rfa, 1, flag);
		}

		if (num_with_pkthdrs > 0) {
			--num_with_pkthdrs;
#if CONFIG_MACF_NET
			if (mac_mbuf_label_init(m, wait) != 0) {
				m_freem(m);
				break;
			}
#endif /* MAC_NET */
		}

		*np = m;
		if (num_with_pkthdrs > 0)
			np = &m->m_nextpkt;
		else
			np = &m->m_next;
	}
	ASSERT(pnum != *num_needed || mp_list == NULL);
	if (mp_list != NULL)
		mcache_free_ext(cp, mp_list);

	if (pnum > 0) {
		mtype_stat_add(MT_DATA, pnum);
		mtype_stat_sub(MT_FREE, pnum);
	}

	if (wantall && (pnum != *num_needed)) {
		if (top != NULL)
			m_freem_list(top);
		return (NULL);
	}

	*num_needed = pnum;
	return (top);
}

/*
 * Return list of mbuf linked by m_nextpkt.  Try for numlist, and if
 * wantall is not set, return whatever number were available.  The size of
 * each mbuf in the list is controlled by the parameter packetlen.  Each
 * mbuf of the list may have a chain of mbufs linked by m_next.  Each mbuf
 * in the chain is called a segment.  If maxsegments is not null and the
 * value pointed to is not null, this specify the maximum number of segments
 * for a chain of mbufs.  If maxsegments is zero or the value pointed to
 * is zero the caller does not have any restriction on the number of segments.
 * The actual  number of segments of a mbuf chain is return in the value
 * pointed to by maxsegments.
 */
__private_extern__ struct mbuf *
m_allocpacket_internal(unsigned int *numlist, size_t packetlen,
    unsigned int *maxsegments, int wait, int wantall, size_t wantsize)
{
	struct mbuf **np, *top, *first = NULL;
	size_t bufsize, r_bufsize;
	unsigned int num = 0;
	unsigned int nsegs = 0;
	unsigned int needed, resid;
	int mcflags = MSLEEPF(wait);
	mcache_obj_t *mp_list = NULL, *rmp_list = NULL;
	mcache_t *cp = NULL, *rcp = NULL;

	if (*numlist == 0)
		return (NULL);

	top = NULL;
	np = &top;

	if (wantsize == 0) {
		if (packetlen <= MINCLSIZE) {
			bufsize = packetlen;
		} else if (packetlen > m_maxsize(MC_CL)) {
			/* Use 4KB if jumbo cluster pool isn't available */
			if (packetlen <= m_maxsize(MC_BIGCL) || njcl == 0)
				bufsize = m_maxsize(MC_BIGCL);
			else
				bufsize = m_maxsize(MC_16KCL);
		} else {
			bufsize = m_maxsize(MC_CL);
		}
	} else if (wantsize == m_maxsize(MC_CL) ||
	    wantsize == m_maxsize(MC_BIGCL) ||
	    (wantsize == m_maxsize(MC_16KCL) && njcl > 0)) {
		bufsize = wantsize;
	} else {
		return (NULL);
	}

	if (bufsize <= MHLEN) {
		nsegs = 1;
	} else if (bufsize <= MINCLSIZE) {
		if (maxsegments != NULL && *maxsegments == 1) {
			bufsize = m_maxsize(MC_CL);
			nsegs = 1;
		} else {
			nsegs = 2;
		}
	} else if (bufsize == m_maxsize(MC_16KCL)) {
		VERIFY(njcl > 0);
		nsegs = ((packetlen - 1) >> (PGSHIFT + 2)) + 1;
	} else if (bufsize == m_maxsize(MC_BIGCL)) {
		nsegs = ((packetlen - 1) >> PGSHIFT) + 1;
	} else {
		nsegs = ((packetlen - 1) >> MCLSHIFT) + 1;
	}
	if (maxsegments != NULL) {
		if (*maxsegments && nsegs > *maxsegments) {
			*maxsegments = nsegs;
			return (NULL);
		}
		*maxsegments = nsegs;
	}

	/*
	 * The caller doesn't want all the requested buffers; only some.
	 * Try hard to get what we can, but don't block.  This effectively
	 * overrides MCR_SLEEP, since this thread will not go to sleep
	 * if we can't get all the buffers.
	 */
	if (!wantall || (mcflags & MCR_NOSLEEP))
		mcflags |= MCR_TRYHARD;

	/*
	 * Simple case where all elements in the lists/chains are mbufs.
	 * Unless bufsize is greater than MHLEN, each segment chain is made
	 * up of exactly 1 mbuf.  Otherwise, each segment chain is made up
	 * of 2 mbufs; the second one is used for the residual data, i.e.
	 * the remaining data that cannot fit into the first mbuf.
	 */
	if (bufsize <= MINCLSIZE) {
		/* Allocate the elements in one shot from the mbuf cache */
		ASSERT(bufsize <= MHLEN || nsegs == 2);
		cp = m_cache(MC_MBUF);
		needed = mcache_alloc_ext(cp, &mp_list,
		    (*numlist) * nsegs, mcflags);

		/*
		 * The number of elements must be even if we are to use an
		 * mbuf (instead of a cluster) to store the residual data.
		 * If we couldn't allocate the requested number of mbufs,
		 * trim the number down (if it's odd) in order to avoid
		 * creating a partial segment chain.
		 */
		if (bufsize > MHLEN && (needed & 0x1))
			needed--;

		while (num < needed) {
			struct mbuf *m;

			m = (struct mbuf *)mp_list;
			mp_list = mp_list->obj_next;
			ASSERT(m != NULL);

			MBUF_INIT(m, 1, MT_DATA);
#if CONFIG_MACF_NET
			if (mac_init_mbuf(m, wait) != 0) {
				m_free(m);
				break;
			}
#endif /* MAC_NET */
			num++;
			if (bufsize > MHLEN) {
				/* A second mbuf for this segment chain */
				m->m_next = (struct mbuf *)mp_list;
				mp_list = mp_list->obj_next;
				ASSERT(m->m_next != NULL);

				MBUF_INIT(m->m_next, 0, MT_DATA);
				num++;
			}
			*np = m;
			np = &m->m_nextpkt;
		}
		ASSERT(num != *numlist || mp_list == NULL);

		if (num > 0) {
			mtype_stat_add(MT_DATA, num);
			mtype_stat_sub(MT_FREE, num);
		}
		num /= nsegs;

		/* We've got them all; return to caller */
		if (num == *numlist)
			return (top);

		goto fail;
	}

	/*
	 * Complex cases where elements are made up of one or more composite
	 * mbufs + cluster, depending on packetlen.  Each N-segment chain can
	 * be illustrated as follows:
	 *
	 * [mbuf + cluster 1] [mbuf + cluster 2] ... [mbuf + cluster N]
	 *
	 * Every composite mbuf + cluster element comes from the intermediate
	 * cache (either MC_MBUF_CL or MC_MBUF_BIGCL).  For space efficiency,
	 * the last composite element will come from the MC_MBUF_CL cache,
	 * unless the residual data is larger than 2KB where we use the
	 * big cluster composite cache (MC_MBUF_BIGCL) instead.  Residual
	 * data is defined as extra data beyond the first element that cannot
	 * fit into the previous element, i.e. there is no residual data if
	 * the chain only has 1 segment.
	 */
	r_bufsize = bufsize;
	resid = packetlen > bufsize ? packetlen % bufsize : 0;
	if (resid > 0) {
		/* There is residual data; figure out the cluster size */
		if (wantsize == 0 && packetlen > MINCLSIZE) {
			/*
			 * Caller didn't request that all of the segments
			 * in the chain use the same cluster size; use the
			 * smaller of the cluster sizes.
			 */
			if (njcl > 0 && resid > m_maxsize(MC_BIGCL))
				r_bufsize = m_maxsize(MC_16KCL);
			else if (resid > m_maxsize(MC_CL))
				r_bufsize = m_maxsize(MC_BIGCL);
			else
				r_bufsize = m_maxsize(MC_CL);
		} else {
			/* Use the same cluster size as the other segments */
			resid = 0;
		}
	}

	needed = *numlist;
	if (resid > 0) {
		/*
		 * Attempt to allocate composite mbuf + cluster elements for
		 * the residual data in each chain; record the number of such
		 * elements that can be allocated so that we know how many
		 * segment chains we can afford to create.
		 */
		if (r_bufsize <= m_maxsize(MC_CL))
			rcp = m_cache(MC_MBUF_CL);
		else if (r_bufsize <= m_maxsize(MC_BIGCL))
			rcp = m_cache(MC_MBUF_BIGCL);
		else
			rcp = m_cache(MC_MBUF_16KCL);
		needed = mcache_alloc_ext(rcp, &rmp_list, *numlist, mcflags);

		if (needed == 0)
			goto fail;

		/* This is temporarily reduced for calculation */
		ASSERT(nsegs > 1);
		nsegs--;
	}

	/*
	 * Attempt to allocate the rest of the composite mbuf + cluster
	 * elements for the number of segment chains that we need.
	 */
	if (bufsize <= m_maxsize(MC_CL))
		cp = m_cache(MC_MBUF_CL);
	else if (bufsize <= m_maxsize(MC_BIGCL))
		cp = m_cache(MC_MBUF_BIGCL);
	else
		cp = m_cache(MC_MBUF_16KCL);
	needed = mcache_alloc_ext(cp, &mp_list, needed * nsegs, mcflags);

	/* Round it down to avoid creating a partial segment chain */
	needed = (needed / nsegs) * nsegs;
	if (needed == 0)
		goto fail;

	if (resid > 0) {
		/*
		 * We're about to construct the chain(s); take into account
		 * the number of segments we have created above to hold the
		 * residual data for each chain, as well as restore the
		 * original count of segments per chain.
		 */
		ASSERT(nsegs > 0);
		needed += needed / nsegs;
		nsegs++;
	}

	for (;;) {
		struct mbuf *m;
		u_int32_t flag;
		struct ext_ref *rfa;
		void *cl;
		int pkthdr;

		++num;
		if (nsegs == 1 || (num % nsegs) != 0 || resid == 0) {
			m = (struct mbuf *)mp_list;
			mp_list = mp_list->obj_next;
		} else {
			m = (struct mbuf *)rmp_list;
			rmp_list = rmp_list->obj_next;
		}
		ASSERT(m != NULL);
		VERIFY(m->m_type == MT_FREE && m->m_flags == M_EXT);
		VERIFY(m->m_ext.ext_free == NULL ||
		    m->m_ext.ext_free == m_bigfree ||
		    m->m_ext.ext_free == m_16kfree);

		cl = m->m_ext.ext_buf;
		rfa = MEXT_RFA(m);

		ASSERT(cl != NULL && rfa != NULL);
		VERIFY(MBUF_IS_COMPOSITE(m));

		flag = MEXT_FLAGS(m);

		pkthdr = (nsegs == 1 || (num % nsegs) == 1);
		if (pkthdr)
			first = m;
		MBUF_INIT(m, pkthdr, MT_DATA);
		if (m->m_ext.ext_free == m_16kfree) {
			MBUF_16KCL_INIT(m, cl, rfa, 1, flag);
		} else if (m->m_ext.ext_free == m_bigfree) {
			MBUF_BIGCL_INIT(m, cl, rfa, 1, flag);
		} else {
			MBUF_CL_INIT(m, cl, rfa, 1, flag);
		}
#if CONFIG_MACF_NET
		if (pkthdr && mac_init_mbuf(m, wait) != 0) {
			--num;
			m_freem(m);
			break;
		}
#endif /* MAC_NET */

		*np = m;
		if ((num % nsegs) == 0)
			np = &first->m_nextpkt;
		else
			np = &m->m_next;

		if (num == needed)
			break;
	}

	if (num > 0) {
		mtype_stat_add(MT_DATA, num);
		mtype_stat_sub(MT_FREE, num);
	}

	num /= nsegs;

	/* We've got them all; return to caller */
	if (num == *numlist) {
		ASSERT(mp_list == NULL && rmp_list == NULL);
		return (top);
	}

fail:
	/* Free up what's left of the above */
	if (mp_list != NULL)
		mcache_free_ext(cp, mp_list);
	if (rmp_list != NULL)
		mcache_free_ext(rcp, rmp_list);
	if (wantall && top != NULL) {
		m_freem(top);
		return (NULL);
	}
	*numlist = num;
	return (top);
}

/*
 * Best effort to get a mbuf cluster + pkthdr.  Used by drivers to allocated
 * packets on receive ring.
 */
__private_extern__ struct mbuf *
m_getpacket_how(int wait)
{
	unsigned int num_needed = 1;

	return (m_getpackets_internal(&num_needed, 1, wait, 1,
	    m_maxsize(MC_CL)));
}

/*
 * Best effort to get a mbuf cluster + pkthdr.  Used by drivers to allocated
 * packets on receive ring.
 */
struct mbuf *
m_getpacket(void)
{
	unsigned int num_needed = 1;

	return (m_getpackets_internal(&num_needed, 1, M_WAIT, 1,
	    m_maxsize(MC_CL)));
}

/*
 * Return a list of mbuf hdrs that point to clusters.  Try for num_needed;
 * if this can't be met, return whatever number were available.  Set up the
 * first num_with_pkthdrs with mbuf hdrs configured as packet headers.  These
 * are chained on the m_nextpkt field.  Any packets requested beyond this are
 * chained onto the last packet header's m_next field.
 */
struct mbuf *
m_getpackets(int num_needed, int num_with_pkthdrs, int how)
{
	unsigned int n = num_needed;

	return (m_getpackets_internal(&n, num_with_pkthdrs, how, 0,
	    m_maxsize(MC_CL)));
}

/*
 * Return a list of mbuf hdrs set up as packet hdrs chained together
 * on the m_nextpkt field
 */
struct mbuf *
m_getpackethdrs(int num_needed, int how)
{
	struct mbuf *m;
	struct mbuf **np, *top;

	top = NULL;
	np = &top;

	while (num_needed--) {
		m = _M_RETRYHDR(how, MT_DATA);
		if (m == NULL)
			break;

		*np = m;
		np = &m->m_nextpkt;
	}

	return (top);
}

/*
 * Free an mbuf list (m_nextpkt) while following m_next.  Returns the count
 * for mbufs packets freed.  Used by the drivers.
 */
int
m_freem_list(struct mbuf *m)
{
	struct mbuf *nextpkt;
	mcache_obj_t *mp_list = NULL;
	mcache_obj_t *mcl_list = NULL;
	mcache_obj_t *mbc_list = NULL;
	mcache_obj_t *m16k_list = NULL;
	mcache_obj_t *m_mcl_list = NULL;
	mcache_obj_t *m_mbc_list = NULL;
	mcache_obj_t *m_m16k_list = NULL;
	mcache_obj_t *ref_list = NULL;
	int pktcount = 0;
	int mt_free = 0, mt_data = 0, mt_header = 0, mt_soname = 0, mt_tag = 0;

	while (m != NULL) {
		pktcount++;

		nextpkt = m->m_nextpkt;
		m->m_nextpkt = NULL;

		while (m != NULL) {
			struct mbuf *next = m->m_next;
			mcache_obj_t *o, *rfa;
			u_int32_t refcnt, composite;

			if (m->m_type == MT_FREE)
				panic("m_free: freeing an already freed mbuf");

			if (m->m_type != MT_FREE)
				mt_free++;

			if (m->m_flags & M_PKTHDR) {
				m_tag_delete_chain(m, NULL);
			}

			if (!(m->m_flags & M_EXT))
				goto simple_free;

			o = (mcache_obj_t *)m->m_ext.ext_buf;
			refcnt = m_decref(m);
			composite = (MEXT_FLAGS(m) & EXTF_COMPOSITE);
			if (refcnt == 0 && !composite) {
				if (m->m_ext.ext_free == NULL) {
					o->obj_next = mcl_list;
					mcl_list = o;
				} else if (m->m_ext.ext_free == m_bigfree) {
					o->obj_next = mbc_list;
					mbc_list = o;
				} else if (m->m_ext.ext_free == m_16kfree) {
					o->obj_next = m16k_list;
					m16k_list = o;
				} else {
					(*(m->m_ext.ext_free))((caddr_t)o,
					    m->m_ext.ext_size,
					    m->m_ext.ext_arg);
				}
				rfa = (mcache_obj_t *)MEXT_RFA(m);
				rfa->obj_next = ref_list;
				ref_list = rfa;
				MEXT_RFA(m) = NULL;
			} else if (refcnt == 0 && composite) {
				VERIFY(m->m_type != MT_FREE);
				/*
				 * Amortize the costs of atomic operations
				 * by doing them at the end, if possible.
				 */
				if (m->m_type == MT_DATA)
					mt_data++;
				else if (m->m_type == MT_HEADER)
					mt_header++;
				else if (m->m_type == MT_SONAME)
					mt_soname++;
				else if (m->m_type == MT_TAG)
					mt_tag++;
				else
					mtype_stat_dec(m->m_type);

				m->m_type = MT_FREE;
				m->m_flags = M_EXT;
				m->m_len = 0;
				m->m_next = m->m_nextpkt = NULL;

				MEXT_FLAGS(m) &= ~EXTF_READONLY;

				/* "Free" into the intermediate cache */
				o = (mcache_obj_t *)m;
				if (m->m_ext.ext_free == NULL) {
					o->obj_next = m_mcl_list;
					m_mcl_list = o;
				} else if (m->m_ext.ext_free == m_bigfree) {
					o->obj_next = m_mbc_list;
					m_mbc_list = o;
				} else {
					VERIFY(m->m_ext.ext_free == m_16kfree);
					o->obj_next = m_m16k_list;
					m_m16k_list = o;
				}
				m = next;
				continue;
			}
simple_free:
			/*
			 * Amortize the costs of atomic operations
			 * by doing them at the end, if possible.
			 */
			if (m->m_type == MT_DATA)
				mt_data++;
			else if (m->m_type == MT_HEADER)
				mt_header++;
			else if (m->m_type == MT_SONAME)
				mt_soname++;
			else if (m->m_type == MT_TAG)
				mt_tag++;
			else if (m->m_type != MT_FREE)
				mtype_stat_dec(m->m_type);

			m->m_type = MT_FREE;
			m->m_flags = m->m_len = 0;
			m->m_next = m->m_nextpkt = NULL;

			((mcache_obj_t *)m)->obj_next = mp_list;
			mp_list = (mcache_obj_t *)m;

			m = next;
		}

		m = nextpkt;
	}

	if (mt_free > 0)
		mtype_stat_add(MT_FREE, mt_free);
	if (mt_data > 0)
		mtype_stat_sub(MT_DATA, mt_data);
	if (mt_header > 0)
		mtype_stat_sub(MT_HEADER, mt_header);
	if (mt_soname > 0)
		mtype_stat_sub(MT_SONAME, mt_soname);
	if (mt_tag > 0)
		mtype_stat_sub(MT_TAG, mt_tag);

	if (mp_list != NULL)
		mcache_free_ext(m_cache(MC_MBUF), mp_list);
	if (mcl_list != NULL)
		mcache_free_ext(m_cache(MC_CL), mcl_list);
	if (mbc_list != NULL)
		mcache_free_ext(m_cache(MC_BIGCL), mbc_list);
	if (m16k_list != NULL)
		mcache_free_ext(m_cache(MC_16KCL), m16k_list);
	if (m_mcl_list != NULL)
		mcache_free_ext(m_cache(MC_MBUF_CL), m_mcl_list);
	if (m_mbc_list != NULL)
		mcache_free_ext(m_cache(MC_MBUF_BIGCL), m_mbc_list);
	if (m_m16k_list != NULL)
		mcache_free_ext(m_cache(MC_MBUF_16KCL), m_m16k_list);
	if (ref_list != NULL)
		mcache_free_ext(ref_cache, ref_list);

	return (pktcount);
}

void
m_freem(struct mbuf *m)
{
	while (m != NULL)
		m = m_free(m);
}

/*
 * Mbuffer utility routines.
 */

/*
 * Compute the amount of space available before the current start
 * of data in an mbuf.
 */
int
m_leadingspace(struct mbuf *m)
{
	if (m->m_flags & M_EXT) {
		if (MCLHASREFERENCE(m))
			return (0);
		return (m->m_data - m->m_ext.ext_buf);
	}
	if (m->m_flags & M_PKTHDR)
		return (m->m_data - m->m_pktdat);
	return (m->m_data - m->m_dat);
}

/*
 * Compute the amount of space available after the end of data in an mbuf.
 */
int
m_trailingspace(struct mbuf *m)
{
	if (m->m_flags & M_EXT) {
		if (MCLHASREFERENCE(m))
			return (0);
		return (m->m_ext.ext_buf + m->m_ext.ext_size -
		    (m->m_data + m->m_len));
	}
	return (&m->m_dat[MLEN] - (m->m_data + m->m_len));
}

/*
 * Lesser-used path for M_PREPEND: allocate new mbuf to prepend to chain,
 * copy junk along.  Does not adjust packet header length.
 */
struct mbuf *
m_prepend(struct mbuf *m, int len, int how)
{
	struct mbuf *mn;

	_MGET(mn, how, m->m_type);
	if (mn == NULL) {
		m_freem(m);
		return (NULL);
	}
	if (m->m_flags & M_PKTHDR) {
		M_COPY_PKTHDR(mn, m);
		m->m_flags &= ~M_PKTHDR;
	}
	mn->m_next = m;
	m = mn;
	if (len < MHLEN)
		MH_ALIGN(m, len);
	m->m_len = len;
	return (m);
}

/*
 * Replacement for old M_PREPEND macro: allocate new mbuf to prepend to
 * chain, copy junk along, and adjust length.
 */
struct mbuf *
m_prepend_2(struct mbuf *m, int len, int how)
{
	if (M_LEADINGSPACE(m) >= len) {
		m->m_data -= len;
		m->m_len += len;
	} else {
		m = m_prepend(m, len, how);
	}
	if ((m) && (m->m_flags & M_PKTHDR))
		m->m_pkthdr.len += len;
	return (m);
}

/*
 * Make a copy of an mbuf chain starting "off0" bytes from the beginning,
 * continuing for "len" bytes.  If len is M_COPYALL, copy to end of mbuf.
 * The wait parameter is a choice of M_WAIT/M_DONTWAIT from caller.
 */
int MCFail;

struct mbuf *
m_copym(struct mbuf *m, int off0, int len, int wait)
{
	struct mbuf *n, *mhdr = NULL, **np;
	int off = off0;
	struct mbuf *top;
	int copyhdr = 0;

	if (off < 0 || len < 0)
		panic("m_copym: invalid offset %d or len %d", off, len);

	if (off == 0 && (m->m_flags & M_PKTHDR)) {
		mhdr = m;
		copyhdr = 1;
	}

	while (off >= m->m_len) {
		if (m->m_next == NULL)
			panic("m_copym: invalid mbuf chain");
		off -= m->m_len;
		m = m->m_next;
	}
	np = &top;
	top = NULL;

	while (len > 0) {
		if (m == NULL) {
			if (len != M_COPYALL)
				panic("m_copym: len != M_COPYALL");
			break;
		}

		n = _M_RETRY(wait, m->m_type);
		*np = n;

		if (n == NULL)
			goto nospace;

		if (copyhdr != 0) {
			M_COPY_PKTHDR(n, mhdr);
			if (len == M_COPYALL)
				n->m_pkthdr.len -= off0;
			else
				n->m_pkthdr.len = len;
			copyhdr = 0;
		}
		if (len == M_COPYALL) {
			if (MIN(len, (m->m_len - off)) == len) {
				printf("m->m_len %d - off %d = %d, %d\n",
				    m->m_len, off, m->m_len - off,
				    MIN(len, (m->m_len - off)));
			}
		}
		n->m_len = MIN(len, (m->m_len - off));
		if (n->m_len == M_COPYALL) {
			printf("n->m_len == M_COPYALL, fixing\n");
			n->m_len = MHLEN;
		}
		if (m->m_flags & M_EXT) {
			n->m_ext = m->m_ext;
			m_incref(m);
			n->m_data = m->m_data + off;
			n->m_flags |= M_EXT;
		} else {
			bcopy(MTOD(m, caddr_t)+off, MTOD(n, caddr_t),
			    (unsigned)n->m_len);
		}
		if (len != M_COPYALL)
			len -= n->m_len;
		off = 0;
		m = m->m_next;
		np = &n->m_next;
	}

	if (top == NULL)
		MCFail++;

	return (top);
nospace:

	m_freem(top);
	MCFail++;
	return (NULL);
}

/*
 * Equivalent to m_copym except that all necessary mbuf hdrs are allocated
 * within this routine also, the last mbuf and offset accessed are passed
 * out and can be passed back in to avoid having to rescan the entire mbuf
 * list (normally hung off of the socket)
 */
struct mbuf *
m_copym_with_hdrs(struct mbuf *m, int off0, int len0, int wait,
    struct mbuf **m_lastm, int *m_off)
{
	struct mbuf *n, **np = NULL;
	int off = off0, len = len0;
	struct mbuf *top = NULL;
	int mcflags = MSLEEPF(wait);
	int copyhdr = 0;
	int type = 0;
	mcache_obj_t *list = NULL;
	int needed = 0;

	if (off == 0 && (m->m_flags & M_PKTHDR))
		copyhdr = 1;

	if (*m_lastm != NULL) {
		m = *m_lastm;
		off = *m_off;
	} else {
		while (off >= m->m_len) {
			off -= m->m_len;
			m = m->m_next;
		}
	}

	n = m;
	while (len > 0) {
		needed++;
		ASSERT(n != NULL);
		len -= MIN(len, (n->m_len - ((needed == 1) ? off : 0)));
		n = n->m_next;
	}
	needed++;
	len = len0;

	/*
	 * If the caller doesn't want to be put to sleep, mark it with
	 * MCR_TRYHARD so that we may reclaim buffers from other places
	 * before giving up.
	 */
	if (mcflags & MCR_NOSLEEP)
		mcflags |= MCR_TRYHARD;

	if (mcache_alloc_ext(m_cache(MC_MBUF), &list, needed,
	    mcflags) != needed)
		goto nospace;

	needed = 0;
	while (len > 0) {
		n = (struct mbuf *)list;
		list = list->obj_next;
		ASSERT(n != NULL && m != NULL);

		type = (top == NULL) ? MT_HEADER : m->m_type;
		MBUF_INIT(n, (top == NULL), type);
#if CONFIG_MACF_NET
		if (top == NULL && mac_mbuf_label_init(n, wait) != 0) {
			mtype_stat_inc(MT_HEADER);
			mtype_stat_dec(MT_FREE);
			m_free(n);
			goto nospace;
		}
#endif /* MAC_NET */

		if (top == NULL) {
			top = n;
			np = &top->m_next;
			continue;
		} else {
			needed++;
			*np = n;
		}

		if (copyhdr) {
			M_COPY_PKTHDR(n, m);
			n->m_pkthdr.len = len;
			copyhdr = 0;
		}
		n->m_len = MIN(len, (m->m_len - off));

		if (m->m_flags & M_EXT) {
			n->m_ext = m->m_ext;
			m_incref(m);
			n->m_data = m->m_data + off;
			n->m_flags |= M_EXT;
		} else {
			bcopy(MTOD(m, caddr_t)+off, MTOD(n, caddr_t),
			    (unsigned)n->m_len);
		}
		len -= n->m_len;

		if (len == 0) {
			if ((off + n->m_len) == m->m_len) {
				*m_lastm = m->m_next;
				*m_off  = 0;
			} else {
				*m_lastm = m;
				*m_off  = off + n->m_len;
			}
			break;
		}
		off = 0;
		m = m->m_next;
		np = &n->m_next;
	}

	mtype_stat_inc(MT_HEADER);
	mtype_stat_add(type, needed);
	mtype_stat_sub(MT_FREE, needed + 1);

	ASSERT(list == NULL);
	return (top);

nospace:
	if (list != NULL)
		mcache_free_ext(m_cache(MC_MBUF), list);
	if (top != NULL)
		m_freem(top);
	MCFail++;
	return (NULL);
}

/*
 * Copy data from an mbuf chain starting "off" bytes from the beginning,
 * continuing for "len" bytes, into the indicated buffer.
 */
void
m_copydata(struct mbuf *m, int off, int len, void *vp)
{
	unsigned count;
	char *cp = vp;

	if (off < 0 || len < 0)
		panic("m_copydata: invalid offset %d or len %d", off, len);

	while (off > 0) {
		if (m == NULL)
			panic("m_copydata: invalid mbuf chain");
		if (off < m->m_len)
			break;
		off -= m->m_len;
		m = m->m_next;
	}
	while (len > 0) {
		if (m == NULL)
			panic("m_copydata: invalid mbuf chain");
		count = MIN(m->m_len - off, len);
		bcopy(MTOD(m, caddr_t) + off, cp, count);
		len -= count;
		cp += count;
		off = 0;
		m = m->m_next;
	}
}

/*
 * Concatenate mbuf chain n to m.  Both chains must be of the same type
 * (e.g. MT_DATA).  Any m_pkthdr is not updated.
 */
void
m_cat(struct mbuf *m, struct mbuf *n)
{
	while (m->m_next)
		m = m->m_next;
	while (n) {
		if ((m->m_flags & M_EXT) ||
		    m->m_data + m->m_len + n->m_len >= &m->m_dat[MLEN]) {
			/* just join the two chains */
			m->m_next = n;
			return;
		}
		/* splat the data from one into the other */
		bcopy(MTOD(n, caddr_t), MTOD(m, caddr_t) + m->m_len,
		    (u_int)n->m_len);
		m->m_len += n->m_len;
		n = m_free(n);
	}
}

void
m_adj(struct mbuf *mp, int req_len)
{
	int len = req_len;
	struct mbuf *m;
	int count;

	if ((m = mp) == NULL)
		return;
	if (len >= 0) {
		/*
		 * Trim from head.
		 */
		while (m != NULL && len > 0) {
			if (m->m_len <= len) {
				len -= m->m_len;
				m->m_len = 0;
				m = m->m_next;
			} else {
				m->m_len -= len;
				m->m_data += len;
				len = 0;
			}
		}
		m = mp;
		if (m->m_flags & M_PKTHDR)
			m->m_pkthdr.len -= (req_len - len);
	} else {
		/*
		 * Trim from tail.  Scan the mbuf chain,
		 * calculating its length and finding the last mbuf.
		 * If the adjustment only affects this mbuf, then just
		 * adjust and return.  Otherwise, rescan and truncate
		 * after the remaining size.
		 */
		len = -len;
		count = 0;
		for (;;) {
			count += m->m_len;
			if (m->m_next == (struct mbuf *)0)
				break;
			m = m->m_next;
		}
		if (m->m_len >= len) {
			m->m_len -= len;
			m = mp;
			if (m->m_flags & M_PKTHDR)
				m->m_pkthdr.len -= len;
			return;
		}
		count -= len;
		if (count < 0)
			count = 0;
		/*
		 * Correct length for chain is "count".
		 * Find the mbuf with last data, adjust its length,
		 * and toss data from remaining mbufs on chain.
		 */
		m = mp;
		if (m->m_flags & M_PKTHDR)
			m->m_pkthdr.len = count;
		for (; m; m = m->m_next) {
			if (m->m_len >= count) {
				m->m_len = count;
				break;
			}
			count -= m->m_len;
		}
		while ((m = m->m_next))
			m->m_len = 0;
	}
}

/*
 * Rearange an mbuf chain so that len bytes are contiguous
 * and in the data area of an mbuf (so that mtod and dtom
 * will work for a structure of size len).  Returns the resulting
 * mbuf chain on success, frees it and returns null on failure.
 * If there is room, it will add up to max_protohdr-len extra bytes to the
 * contiguous region in an attempt to avoid being called next time.
 */
int MPFail;

struct mbuf *
m_pullup(struct mbuf *n, int len)
{
	struct mbuf *m;
	int count;
	int space;

	/*
	 * If first mbuf has no cluster, and has room for len bytes
	 * without shifting current data, pullup into it,
	 * otherwise allocate a new mbuf to prepend to the chain.
	 */
	if ((n->m_flags & M_EXT) == 0 &&
	    n->m_data + len < &n->m_dat[MLEN] && n->m_next) {
		if (n->m_len >= len)
			return (n);
		m = n;
		n = n->m_next;
		len -= m->m_len;
	} else {
		if (len > MHLEN)
			goto bad;
		_MGET(m, M_DONTWAIT, n->m_type);
		if (m == 0)
			goto bad;
		m->m_len = 0;
		if (n->m_flags & M_PKTHDR) {
			M_COPY_PKTHDR(m, n);
			n->m_flags &= ~M_PKTHDR;
		}
	}
	space = &m->m_dat[MLEN] - (m->m_data + m->m_len);
	do {
		count = MIN(MIN(MAX(len, max_protohdr), space), n->m_len);
		bcopy(MTOD(n, caddr_t), MTOD(m, caddr_t) + m->m_len,
		    (unsigned)count);
		len -= count;
		m->m_len += count;
		n->m_len -= count;
		space -= count;
		if (n->m_len)
			n->m_data += count;
		else
			n = m_free(n);
	} while (len > 0 && n);
	if (len > 0) {
		(void) m_free(m);
		goto bad;
	}
	m->m_next = n;
	return (m);
bad:
	m_freem(n);
	MPFail++;
	return (0);
}

/*
 * Like m_pullup(), except a new mbuf is always allocated, and we allow
 * the amount of empty space before the data in the new mbuf to be specified
 * (in the event that the caller expects to prepend later).
 */
__private_extern__ int MSFail = 0;

__private_extern__ struct mbuf *
m_copyup(struct mbuf *n, int len, int dstoff)
{
	struct mbuf *m;
	int count, space;

	if (len > (MHLEN - dstoff))
		goto bad;
	MGET(m, M_DONTWAIT, n->m_type);
	if (m == NULL)
		goto bad;
	m->m_len = 0;
	if (n->m_flags & M_PKTHDR) {
		m_copy_pkthdr(m, n);
		n->m_flags &= ~M_PKTHDR;
	}
	m->m_data += dstoff;
	space = &m->m_dat[MLEN] - (m->m_data + m->m_len);
	do {
		count = min(min(max(len, max_protohdr), space), n->m_len);
		memcpy(mtod(m, caddr_t) + m->m_len, mtod(n, caddr_t),
		    (unsigned)count);
		len -= count;
		m->m_len += count;
		n->m_len -= count;
		space -= count;
		if (n->m_len)
			n->m_data += count;
		else
			n = m_free(n);
	} while (len > 0 && n);
	if (len > 0) {
		(void) m_free(m);
		goto bad;
	}
	m->m_next = n;
	return (m);
bad:
	m_freem(n);
	MSFail++;
	return (NULL);
}

/*
 * Partition an mbuf chain in two pieces, returning the tail --
 * all but the first len0 bytes.  In case of failure, it returns NULL and
 * attempts to restore the chain to its original state.
 */
struct mbuf *
m_split(struct mbuf *m0, int len0, int wait)
{
	return (m_split0(m0, len0, wait, 1));
}

static struct mbuf *
m_split0(struct mbuf *m0, int len0, int wait, int copyhdr)
{
	struct mbuf *m, *n;
	unsigned len = len0, remain;

	for (m = m0; m && len > m->m_len; m = m->m_next)
		len -= m->m_len;
	if (m == NULL)
		return (NULL);
	remain = m->m_len - len;
	if (copyhdr && (m0->m_flags & M_PKTHDR)) {
		_MGETHDR(n, wait, m0->m_type);
		if (n == NULL)
			return (NULL);
		n->m_pkthdr.rcvif = m0->m_pkthdr.rcvif;
		n->m_pkthdr.len = m0->m_pkthdr.len - len0;
		m0->m_pkthdr.len = len0;
		if (m->m_flags & M_EXT)
			goto extpacket;
		if (remain > MHLEN) {
			/* m can't be the lead packet */
			MH_ALIGN(n, 0);
			n->m_next = m_split(m, len, wait);
			if (n->m_next == NULL) {
				(void) m_free(n);
				return (NULL);
			} else
				return (n);
		} else
			MH_ALIGN(n, remain);
	} else if (remain == 0) {
		n = m->m_next;
		m->m_next = NULL;
		return (n);
	} else {
		_MGET(n, wait, m->m_type);
		if (n == NULL)
			return (NULL);
		M_ALIGN(n, remain);
	}
extpacket:
	if (m->m_flags & M_EXT) {
		n->m_flags |= M_EXT;
		n->m_ext = m->m_ext;
		m_incref(m);
		n->m_data = m->m_data + len;
	} else {
		bcopy(MTOD(m, caddr_t) + len, MTOD(n, caddr_t), remain);
	}
	n->m_len = remain;
	m->m_len = len;
	n->m_next = m->m_next;
	m->m_next = NULL;
	return (n);
}

/*
 * Routine to copy from device local memory into mbufs.
 */
struct mbuf *
m_devget(char *buf, int totlen, int off0, struct ifnet *ifp,
    void (*copy)(const void *, void *, size_t))
{
	struct mbuf *m;
	struct mbuf *top = NULL, **mp = &top;
	int off = off0, len;
	char *cp;
	char *epkt;

	cp = buf;
	epkt = cp + totlen;
	if (off) {
		/*
		 * If 'off' is non-zero, packet is trailer-encapsulated,
		 * so we have to skip the type and length fields.
		 */
		cp += off + 2 * sizeof (u_int16_t);
		totlen -= 2 * sizeof (u_int16_t);
	}
	_MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (m == NULL)
		return (NULL);
	m->m_pkthdr.rcvif = ifp;
	m->m_pkthdr.len = totlen;
	m->m_len = MHLEN;

	while (totlen > 0) {
		if (top != NULL) {
			_MGET(m, M_DONTWAIT, MT_DATA);
			if (m == NULL) {
				m_freem(top);
				return (NULL);
			}
			m->m_len = MLEN;
		}
		len = MIN(totlen, epkt - cp);
		if (len >= MINCLSIZE) {
			MCLGET(m, M_DONTWAIT);
			if (m->m_flags & M_EXT) {
				m->m_len = len = MIN(len, m_maxsize(MC_CL));
			} else {
				/* give up when it's out of cluster mbufs */
				if (top != NULL)
					m_freem(top);
				m_freem(m);
				return (NULL);
			}
		} else {
			/*
			 * Place initial small packet/header at end of mbuf.
			 */
			if (len < m->m_len) {
				if (top == NULL &&
				    len + max_linkhdr <= m->m_len)
					m->m_data += max_linkhdr;
				m->m_len = len;
			} else {
				len = m->m_len;
			}
		}
		if (copy)
			copy(cp, MTOD(m, caddr_t), (unsigned)len);
		else
			bcopy(cp, MTOD(m, caddr_t), (unsigned)len);
		cp += len;
		*mp = m;
		mp = &m->m_next;
		totlen -= len;
		if (cp == epkt)
			cp = buf;
	}
	return (top);
}

#ifndef MBUF_GROWTH_NORMAL_THRESH
#define	MBUF_GROWTH_NORMAL_THRESH 25
#endif

/*
 * Cluster freelist allocation check.
 */
static int
m_howmany(int num, size_t bufsize)
{
	int i = 0, j = 0;
	u_int32_t m_mbclusters, m_clusters, m_bigclusters, m_16kclusters;
	u_int32_t m_mbfree, m_clfree, m_bigclfree, m_16kclfree;
	u_int32_t sumclusters, freeclusters;
	u_int32_t percent_pool, percent_kmem;
	u_int32_t mb_growth, mb_growth_thresh;

	VERIFY(bufsize == m_maxsize(MC_BIGCL) ||
	    bufsize == m_maxsize(MC_16KCL));

	lck_mtx_assert(mbuf_mlock, LCK_MTX_ASSERT_OWNED);

	/* Numbers in 2K cluster units */
	m_mbclusters = m_total(MC_MBUF) >> NMBPCLSHIFT;
	m_clusters = m_total(MC_CL);
	m_bigclusters = m_total(MC_BIGCL) << NCLPBGSHIFT;
	m_16kclusters = m_total(MC_16KCL);
	sumclusters = m_mbclusters + m_clusters + m_bigclusters;

	m_mbfree = m_infree(MC_MBUF) >> NMBPCLSHIFT;
	m_clfree = m_infree(MC_CL);
	m_bigclfree = m_infree(MC_BIGCL) << NCLPBGSHIFT;
	m_16kclfree = m_infree(MC_16KCL);
	freeclusters = m_mbfree + m_clfree + m_bigclfree;

	/* Bail if we've maxed out the mbuf memory map */
	if ((bufsize == m_maxsize(MC_BIGCL) && sumclusters >= nclusters) ||
	    (njcl > 0 && bufsize == m_maxsize(MC_16KCL) &&
	    (m_16kclusters << NCLPJCLSHIFT) >= njcl)) {
		return (0);
	}

	if (bufsize == m_maxsize(MC_BIGCL)) {
		/* Under minimum */
		if (m_bigclusters < m_minlimit(MC_BIGCL))
			return (m_minlimit(MC_BIGCL) - m_bigclusters);

		percent_pool =
		    ((sumclusters - freeclusters) * 100) / sumclusters;
		percent_kmem = (sumclusters * 100) / nclusters;

		/*
		 * If a light/normal user, grow conservatively (75%)
		 * If a heavy user, grow aggressively (50%)
		 */
		if (percent_kmem < MBUF_GROWTH_NORMAL_THRESH)
			mb_growth = MB_GROWTH_NORMAL;
		else
			mb_growth = MB_GROWTH_AGGRESSIVE;

		if (percent_kmem < 5) {
			/* For initial allocations */
			i = num;
		} else {
			/* Return if >= MBIGCL_LOWAT clusters available */
			if (m_infree(MC_BIGCL) >= MBIGCL_LOWAT &&
			    m_total(MC_BIGCL) >=
			    MBIGCL_LOWAT + m_minlimit(MC_BIGCL))
				return (0);

			/* Ensure at least num clusters are accessible */
			if (num >= m_infree(MC_BIGCL))
				i = num - m_infree(MC_BIGCL);
			if (num > m_total(MC_BIGCL) - m_minlimit(MC_BIGCL))
				j = num - (m_total(MC_BIGCL) -
				    m_minlimit(MC_BIGCL));

			i = MAX(i, j);

			/*
			 * Grow pool if percent_pool > 75 (normal growth)
			 * or percent_pool > 50 (aggressive growth).
			 */
			mb_growth_thresh = 100 - (100 / (1 << mb_growth));
			if (percent_pool > mb_growth_thresh)
				j = ((sumclusters + num) >> mb_growth) -
				    freeclusters;
			i = MAX(i, j);
		}

		/* Check to ensure we didn't go over limits */
		if (i + m_bigclusters >= m_maxlimit(MC_BIGCL))
			i = m_maxlimit(MC_BIGCL) - m_bigclusters;
		if ((i << 1) + sumclusters >= nclusters)
			i = (nclusters - sumclusters) >> 1;
		VERIFY((m_total(MC_BIGCL) + i) <= m_maxlimit(MC_BIGCL));
		VERIFY(sumclusters + (i << 1) <= nclusters);

	} else { /* 16K CL */
		VERIFY(njcl > 0);
		/* Under minimum */
		if (m_16kclusters < MIN16KCL)
			return (MIN16KCL - m_16kclusters);
		if (m_16kclfree >= M16KCL_LOWAT)
			return (0);

		/* Ensure at least num clusters are available */
		if (num >= m_16kclfree)
			i = num - m_16kclfree;

		/* Always grow 16KCL pool aggressively */
		if (((m_16kclusters + num) >> 1) > m_16kclfree)
			j = ((m_16kclusters + num) >> 1) - m_16kclfree;
		i = MAX(i, j);

		/* Check to ensure we don't go over limit */
		if (i + m_16kclusters >= m_maxlimit(MC_16KCL))
			i = m_maxlimit(MC_16KCL) - m_16kclusters;
		VERIFY((m_total(MC_16KCL) + i) <= m_maxlimit(MC_16KCL));
	}
	return (i);
}
/*
 * Return the number of bytes in the mbuf chain, m.
 */
unsigned int
m_length(struct mbuf *m)
{
	struct mbuf *m0;
	unsigned int pktlen;

	if (m->m_flags & M_PKTHDR)
		return (m->m_pkthdr.len);

	pktlen = 0;
	for (m0 = m; m0 != NULL; m0 = m0->m_next)
		pktlen += m0->m_len;
	return (pktlen);
}

/*
 * Copy data from a buffer back into the indicated mbuf chain,
 * starting "off" bytes from the beginning, extending the mbuf
 * chain if necessary.
 */
void
m_copyback(struct mbuf *m0, int off, int len, const void *cp)
{
#if DEBUG
	struct mbuf *origm = m0;
	int error;
#endif /* DEBUG */

	if (m0 == NULL)
		return;

#if DEBUG
	error =
#endif /* DEBUG */
	m_copyback0(&m0, off, len, cp,
	    M_COPYBACK0_COPYBACK | M_COPYBACK0_EXTEND, M_DONTWAIT);

#if DEBUG
	if (error != 0 || (m0 != NULL && origm != m0))
		panic("m_copyback");
#endif /* DEBUG */
}

struct mbuf *
m_copyback_cow(struct mbuf *m0, int off, int len, const void *cp, int how)
{
	int error;

	/* don't support chain expansion */
	VERIFY(off + len <= m_length(m0));

	error = m_copyback0(&m0, off, len, cp,
	    M_COPYBACK0_COPYBACK | M_COPYBACK0_COW, how);
	if (error) {
		/*
		 * no way to recover from partial success.
		 * just free the chain.
		 */
		m_freem(m0);
		return (NULL);
	}
	return (m0);
}

/*
 * m_makewritable: ensure the specified range writable.
 */
int
m_makewritable(struct mbuf **mp, int off, int len, int how)
{
	int error;
#if DEBUG
	struct mbuf *n;
	int origlen, reslen;

	origlen = m_length(*mp);
#endif /* DEBUG */

#if 0 /* M_COPYALL is large enough */
	if (len == M_COPYALL)
		len = m_length(*mp) - off; /* XXX */
#endif

	error = m_copyback0(mp, off, len, NULL,
	    M_COPYBACK0_PRESERVE | M_COPYBACK0_COW, how);

#if DEBUG
	reslen = 0;
	for (n = *mp; n; n = n->m_next)
		reslen += n->m_len;
	if (origlen != reslen)
		panic("m_makewritable: length changed");
	if (((*mp)->m_flags & M_PKTHDR) && reslen != (*mp)->m_pkthdr.len)
		panic("m_makewritable: inconsist");
#endif /* DEBUG */

	return (error);
}

static int
m_copyback0(struct mbuf **mp0, int off, int len, const void *vp, int flags,
    int how)
{
	int mlen;
	struct mbuf *m, *n;
	struct mbuf **mp;
	int totlen = 0;
	const char *cp = vp;

	VERIFY(mp0 != NULL);
	VERIFY(*mp0 != NULL);
	VERIFY((flags & M_COPYBACK0_PRESERVE) == 0 || cp == NULL);
	VERIFY((flags & M_COPYBACK0_COPYBACK) == 0 || cp != NULL);

	/*
	 * we don't bother to update "totlen" in the case of M_COPYBACK0_COW,
	 * assuming that M_COPYBACK0_EXTEND and M_COPYBACK0_COW are exclusive.
	 */

	VERIFY((~flags & (M_COPYBACK0_EXTEND|M_COPYBACK0_COW)) != 0);

	mp = mp0;
	m = *mp;
	while (off > (mlen = m->m_len)) {
		off -= mlen;
		totlen += mlen;
		if (m->m_next == NULL) {
			int tspace;
extend:
			if (!(flags & M_COPYBACK0_EXTEND))
				goto out;

			/*
			 * try to make some space at the end of "m".
			 */

			mlen = m->m_len;
			if (off + len >= MINCLSIZE &&
			    !(m->m_flags & M_EXT) && m->m_len == 0) {
				MCLGET(m, how);
			}
			tspace = M_TRAILINGSPACE(m);
			if (tspace > 0) {
				tspace = MIN(tspace, off + len);
				VERIFY(tspace > 0);
				bzero(mtod(m, char *) + m->m_len,
				    MIN(off, tspace));
				m->m_len += tspace;
				off += mlen;
				totlen -= mlen;
				continue;
			}

			/*
			 * need to allocate an mbuf.
			 */

			if (off + len >= MINCLSIZE) {
				n = m_getcl(how, m->m_type, 0);
			} else {
				n = _M_GET(how, m->m_type);
			}
			if (n == NULL) {
				goto out;
			}
			n->m_len = 0;
			n->m_len = MIN(M_TRAILINGSPACE(n), off + len);
			bzero(mtod(n, char *), MIN(n->m_len, off));
			m->m_next = n;
		}
		mp = &m->m_next;
		m = m->m_next;
	}
	while (len > 0) {
		mlen = m->m_len - off;
		if (mlen != 0 && m_mclhasreference(m)) {
			char *datap;
			int eatlen;

			/*
			 * this mbuf is read-only.
			 * allocate a new writable mbuf and try again.
			 */

#if defined(DIAGNOSTIC)
			if (!(flags & M_COPYBACK0_COW))
				panic("m_copyback0: read-only");
#endif /* defined(DIAGNOSTIC) */

			/*
			 * if we're going to write into the middle of
			 * a mbuf, split it first.
			 */
			if (off > 0 && len < mlen) {
				n = m_split0(m, off, how, 0);
				if (n == NULL)
					goto enobufs;
				m->m_next = n;
				mp = &m->m_next;
				m = n;
				off = 0;
				continue;
			}

			/*
			 * XXX TODO coalesce into the trailingspace of
			 * the previous mbuf when possible.
			 */

			/*
			 * allocate a new mbuf.  copy packet header if needed.
			 */
			n = _M_GET(how, m->m_type);
			if (n == NULL)
				goto enobufs;
			if (off == 0 && (m->m_flags & M_PKTHDR)) {
				M_COPY_PKTHDR(n, m);
				n->m_len = MHLEN;
			} else {
				if (len >= MINCLSIZE)
					MCLGET(n, M_DONTWAIT);
				n->m_len =
				    (n->m_flags & M_EXT) ? MCLBYTES : MLEN;
			}
			if (n->m_len > len)
				n->m_len = len;

			/*
			 * free the region which has been overwritten.
			 * copying data from old mbufs if requested.
			 */
			if (flags & M_COPYBACK0_PRESERVE)
				datap = mtod(n, char *);
			else
				datap = NULL;
			eatlen = n->m_len;
			VERIFY(off == 0 || eatlen >= mlen);
			if (off > 0) {
				VERIFY(len >= mlen);
				m->m_len = off;
				m->m_next = n;
				if (datap) {
					m_copydata(m, off, mlen, datap);
					datap += mlen;
				}
				eatlen -= mlen;
				mp = &m->m_next;
				m = m->m_next;
			}
			while (m != NULL && m_mclhasreference(m) &&
			    n->m_type == m->m_type && eatlen > 0) {
				mlen = MIN(eatlen, m->m_len);
				if (datap) {
					m_copydata(m, 0, mlen, datap);
					datap += mlen;
				}
				m->m_data += mlen;
				m->m_len -= mlen;
				eatlen -= mlen;
				if (m->m_len == 0)
					*mp = m = m_free(m);
			}
			if (eatlen > 0)
				n->m_len -= eatlen;
			n->m_next = m;
			*mp = m = n;
			continue;
		}
		mlen = MIN(mlen, len);
		if (flags & M_COPYBACK0_COPYBACK) {
			bcopy(cp, mtod(m, caddr_t) + off, (unsigned)mlen);
			cp += mlen;
		}
		len -= mlen;
		mlen += off;
		off = 0;
		totlen += mlen;
		if (len == 0)
			break;
		if (m->m_next == NULL) {
			goto extend;
		}
		mp = &m->m_next;
		m = m->m_next;
	}
out:
	if (((m = *mp0)->m_flags & M_PKTHDR) && (m->m_pkthdr.len < totlen)) {
		VERIFY(flags & M_COPYBACK0_EXTEND);
		m->m_pkthdr.len = totlen;
	}

	return (0);

enobufs:
	return (ENOBUFS);
}

char *
mcl_to_paddr(char *addr)
{
	vm_offset_t base_phys;

	if (!MBUF_IN_MAP(addr))
		return (NULL);
	base_phys = mcl_paddr[(addr - (char *)mbutl) >> PGSHIFT];

	if (base_phys == 0)
		return (NULL);
	return ((char *)((uintptr_t)base_phys | ((uintptr_t)addr & PGOFSET)));
}

/*
 * Dup the mbuf chain passed in.  The whole thing.  No cute additional cruft.
 * And really copy the thing.  That way, we don't "precompute" checksums
 * for unsuspecting consumers.  Assumption: m->m_nextpkt == 0.  Trick: for
 * small packets, don't dup into a cluster.  That way received  packets
 * don't take up too much room in the sockbuf (cf. sbspace()).
 */
int MDFail;

struct mbuf *
m_dup(struct mbuf *m, int how)
{
	struct mbuf *n, **np;
	struct mbuf *top;
	int copyhdr = 0;

	np = &top;
	top = NULL;
	if (m->m_flags & M_PKTHDR)
		copyhdr = 1;

	/*
	 * Quick check: if we have one mbuf and its data fits in an
	 *  mbuf with packet header, just copy and go.
	 */
	if (m->m_next == NULL) {
		/* Then just move the data into an mbuf and be done... */
		if (copyhdr) {
			if (m->m_pkthdr.len <= MHLEN && m->m_len <= MHLEN) {
				if ((n = _M_GETHDR(how, m->m_type)) == NULL)
					return (NULL);
				n->m_len = m->m_len;
				m_dup_pkthdr(n, m, how);
				bcopy(m->m_data, n->m_data, m->m_len);
				return (n);
			}
		} else if (m->m_len <= MLEN) {
			if ((n = _M_GET(how, m->m_type)) == NULL)
				return (NULL);
			bcopy(m->m_data, n->m_data, m->m_len);
			n->m_len = m->m_len;
			return (n);
		}
	}
	while (m != NULL) {
#if BLUE_DEBUG
		kprintf("<%x: %x, %x, %x\n", m, m->m_flags, m->m_len,
		    m->m_data);
#endif
		if (copyhdr)
			n = _M_GETHDR(how, m->m_type);
		else
			n = _M_GET(how, m->m_type);
		if (n == NULL)
			goto nospace;
		if (m->m_flags & M_EXT) {
			if (m->m_len <= m_maxsize(MC_CL))
				MCLGET(n, how);
			else if (m->m_len <= m_maxsize(MC_BIGCL))
				n = m_mbigget(n, how);
			else if (m->m_len <= m_maxsize(MC_16KCL) && njcl > 0)
				n = m_m16kget(n, how);
			if (!(n->m_flags & M_EXT)) {
				(void) m_free(n);
				goto nospace;
			}
		}
		*np = n;
		if (copyhdr) {
			/* Don't use M_COPY_PKTHDR: preserve m_data */
			m_dup_pkthdr(n, m, how);
			copyhdr = 0;
			if (!(n->m_flags & M_EXT))
				n->m_data = n->m_pktdat;
		}
		n->m_len = m->m_len;
		/*
		 * Get the dup on the same bdry as the original
		 * Assume that the two mbufs have the same offset to data area
		 * (up to word boundaries)
		 */
		bcopy(MTOD(m, caddr_t), MTOD(n, caddr_t), (unsigned)n->m_len);
		m = m->m_next;
		np = &n->m_next;
#if BLUE_DEBUG
		kprintf(">%x: %x, %x, %x\n", n, n->m_flags, n->m_len,
		    n->m_data);
#endif
	}

	if (top == NULL)
		MDFail++;
	return (top);

nospace:
	m_freem(top);
	MDFail++;
	return (NULL);
}

#define	MBUF_MULTIPAGES(m)						\
	(((m)->m_flags & M_EXT) &&					\
	((IS_P2ALIGNED((m)->m_data, NBPG) && (m)->m_len > NBPG) ||	\
	(!IS_P2ALIGNED((m)->m_data, NBPG) &&				\
	P2ROUNDUP((m)->m_data, NBPG) < ((uintptr_t)(m)->m_data + (m)->m_len))))

static struct mbuf *
m_expand(struct mbuf *m, struct mbuf **last)
{
	struct mbuf *top = NULL;
	struct mbuf **nm = &top;
	uintptr_t data0, data;
	unsigned int len0, len;

	VERIFY(MBUF_MULTIPAGES(m));
	VERIFY(m->m_next == NULL);
	data0 = (uintptr_t)m->m_data;
	len0 = m->m_len;
	*last = top;

	for (;;) {
		struct mbuf *n;

		data = data0;
		if (IS_P2ALIGNED(data, NBPG) && len0 > NBPG)
			len = NBPG;
		else if (!IS_P2ALIGNED(data, NBPG) &&
		    P2ROUNDUP(data, NBPG) < (data + len0))
			len = P2ROUNDUP(data, NBPG) - data;
		else
			len = len0;

		VERIFY(len > 0);
		VERIFY(m->m_flags & M_EXT);
		m->m_data = (void *)data;
		m->m_len = len;

		*nm = *last = m;
		nm = &m->m_next;
		m->m_next = NULL;

		data0 += len;
		len0 -= len;
		if (len0 == 0)
			break;

		n = _M_RETRY(M_DONTWAIT, MT_DATA);
		if (n == NULL) {
			m_freem(top);
			top = *last = NULL;
			break;
		}

		n->m_ext = m->m_ext;
		m_incref(m);
		n->m_flags |= M_EXT;
		m = n;
	}
	return (top);
}

struct mbuf *
m_normalize(struct mbuf *m)
{
	struct mbuf *top = NULL;
	struct mbuf **nm = &top;
	boolean_t expanded = FALSE;

	while (m != NULL) {
		struct mbuf *n;

		n = m->m_next;
		m->m_next = NULL;

		/* Does the data cross one or more page boundaries? */
		if (MBUF_MULTIPAGES(m)) {
			struct mbuf *last;
			if ((m = m_expand(m, &last)) == NULL) {
				m_freem(n);
				m_freem(top);
				top = NULL;
				break;
			}
			*nm = m;
			nm = &last->m_next;
			expanded = TRUE;
		} else {
			*nm = m;
			nm = &m->m_next;
		}
		m = n;
	}
	if (expanded)
		atomic_add_32(&mb_normalized, 1);
	return (top);
}

/*
 * Append the specified data to the indicated mbuf chain,
 * Extend the mbuf chain if the new data does not fit in
 * existing space.
 *
 * Return 1 if able to complete the job; otherwise 0.
 */
int
m_append(struct mbuf *m0, int len, caddr_t cp)
{
	struct mbuf *m, *n;
	int remainder, space;

	for (m = m0; m->m_next != NULL; m = m->m_next)
		;
	remainder = len;
	space = M_TRAILINGSPACE(m);
	if (space > 0) {
		/*
		 * Copy into available space.
		 */
		if (space > remainder)
			space = remainder;
		bcopy(cp, mtod(m, caddr_t) + m->m_len, space);
		m->m_len += space;
		cp += space, remainder -= space;
	}
	while (remainder > 0) {
		/*
		 * Allocate a new mbuf; could check space
		 * and allocate a cluster instead.
		 */
		n = m_get(M_WAITOK, m->m_type);
		if (n == NULL)
			break;
		n->m_len = min(MLEN, remainder);
		bcopy(cp, mtod(n, caddr_t), n->m_len);
		cp += n->m_len;
		remainder -= n->m_len;
		m->m_next = n;
		m = n;
	}
	if (m0->m_flags & M_PKTHDR)
		m0->m_pkthdr.len += len - remainder;
	return (remainder == 0);
}

struct mbuf *
m_last(struct mbuf *m)
{
	while (m->m_next != NULL)
		m = m->m_next;
	return (m);
}

void
m_mchtype(struct mbuf *m, int t)
{
	mtype_stat_inc(t);
	mtype_stat_dec(m->m_type);
	(m)->m_type = t;
}

void *
m_mtod(struct mbuf *m)
{
	return (MTOD(m, void *));
}

struct mbuf *
m_dtom(void *x)
{
	return ((struct mbuf *)((uintptr_t)(x) & ~(MSIZE-1)));
}

void
m_mcheck(struct mbuf *m)
{
	_MCHECK(m);
}

/*
 * Return a pointer to mbuf/offset of location in mbuf chain.
 */
struct mbuf *
m_getptr(struct mbuf *m, int loc, int *off)
{

	while (loc >= 0) {
		/* Normal end of search. */
		if (m->m_len > loc) {
			*off = loc;
			return (m);
		} else {
			loc -= m->m_len;
			if (m->m_next == NULL) {
				if (loc == 0) {
					/* Point at the end of valid data. */
					*off = m->m_len;
					return (m);
				}
				return (NULL);
			}
			m = m->m_next;
		}
	}
	return (NULL);
}

/*
 * Inform the corresponding mcache(s) that there's a waiter below.
 */
static void
mbuf_waiter_inc(mbuf_class_t class, boolean_t comp)
{
	mcache_waiter_inc(m_cache(class));
	if (comp) {
		if (class == MC_CL) {
			mcache_waiter_inc(m_cache(MC_MBUF_CL));
		} else if (class == MC_BIGCL) {
			mcache_waiter_inc(m_cache(MC_MBUF_BIGCL));
		} else if (class == MC_16KCL) {
			mcache_waiter_inc(m_cache(MC_MBUF_16KCL));
		} else {
			mcache_waiter_inc(m_cache(MC_MBUF_CL));
			mcache_waiter_inc(m_cache(MC_MBUF_BIGCL));
		}
	}
}

/*
 * Inform the corresponding mcache(s) that there's no more waiter below.
 */
static void
mbuf_waiter_dec(mbuf_class_t class, boolean_t comp)
{
	mcache_waiter_dec(m_cache(class));
	if (comp) {
		if (class == MC_CL) {
			mcache_waiter_dec(m_cache(MC_MBUF_CL));
		} else if (class == MC_BIGCL) {
			mcache_waiter_dec(m_cache(MC_MBUF_BIGCL));
		} else if (class == MC_16KCL) {
			mcache_waiter_dec(m_cache(MC_MBUF_16KCL));
		} else {
			mcache_waiter_dec(m_cache(MC_MBUF_CL));
			mcache_waiter_dec(m_cache(MC_MBUF_BIGCL));
		}
	}
}

/*
 * Called during slab (blocking and non-blocking) allocation.  If there
 * is at least one waiter, and the time since the first waiter is blocked
 * is greater than the watchdog timeout, panic the system.
 */
static void
mbuf_watchdog(void)
{
	struct timeval now;
	unsigned int since;

	if (mb_waiters == 0 || !mb_watchdog)
		return;

	microuptime(&now);
	since = now.tv_sec - mb_wdtstart.tv_sec;
	if (since >= MB_WDT_MAXTIME) {
		panic_plain("%s: %d waiters stuck for %u secs\n%s", __func__,
		    mb_waiters, since, mbuf_dump());
		/* NOTREACHED */
	}
}

/*
 * Called during blocking allocation.  Returns TRUE if one or more objects
 * are available at the per-CPU caches layer and that allocation should be
 * retried at that level.
 */
static boolean_t
mbuf_sleep(mbuf_class_t class, unsigned int num, int wait)
{
	boolean_t mcache_retry = FALSE;

	lck_mtx_assert(mbuf_mlock, LCK_MTX_ASSERT_OWNED);

	/* Check if there's anything at the cache layer */
	if (mbuf_cached_above(class, wait)) {
		mcache_retry = TRUE;
		goto done;
	}

	/* Nothing?  Then try hard to get it from somewhere */
	m_reclaim(class, num, (wait & MCR_COMP));

	/* We tried hard and got something? */
	if (m_infree(class) > 0) {
		mbstat.m_wait++;
		goto done;
	} else if (mbuf_cached_above(class, wait)) {
		mbstat.m_wait++;
		mcache_retry = TRUE;
		goto done;
	} else if (wait & MCR_TRYHARD) {
		mcache_retry = TRUE;
		goto done;
	}

	/*
	 * There's really nothing for us right now; inform the
	 * cache(s) that there is a waiter below and go to sleep.
	 */
	mbuf_waiter_inc(class, (wait & MCR_COMP));

	VERIFY(!(wait & MCR_NOSLEEP));

	/*
	 * If this is the first waiter, arm the watchdog timer.  Otherwise
	 * check if we need to panic the system due to watchdog timeout.
	 */
	if (mb_waiters == 0)
		microuptime(&mb_wdtstart);
	else
		mbuf_watchdog();

	mb_waiters++;
	(void) msleep(mb_waitchan, mbuf_mlock, (PZERO-1), m_cname(class), NULL);

	/* We are now up; stop getting notified until next round */
	mbuf_waiter_dec(class, (wait & MCR_COMP));

	/* We waited and got something */
	if (m_infree(class) > 0) {
		mbstat.m_wait++;
		goto done;
	} else if (mbuf_cached_above(class, wait)) {
		mbstat.m_wait++;
		mcache_retry = TRUE;
	}
done:
	return (mcache_retry);
}

static void
mbuf_worker_thread(void)
{
	int mbuf_expand;

	while (1) {
		lck_mtx_lock(mbuf_mlock);

		mbuf_expand = 0;
		if (mbuf_expand_mcl) {
			int n;

			/* Adjust to current number of cluster in use */
			n = mbuf_expand_mcl -
			    (m_total(MC_CL) - m_infree(MC_CL));
			if ((n + m_total(MC_CL)) > m_maxlimit(MC_CL))
				n = m_maxlimit(MC_CL) - m_total(MC_CL);
			mbuf_expand_mcl = 0;

			if (n > 0 && freelist_populate(MC_CL, n, M_WAIT) > 0)
				mbuf_expand++;
		}
		if (mbuf_expand_big) {
			int n;

			/* Adjust to current number of 4 KB cluster in use */
			n = mbuf_expand_big -
			    (m_total(MC_BIGCL) - m_infree(MC_BIGCL));
			if ((n + m_total(MC_BIGCL)) > m_maxlimit(MC_BIGCL))
				n = m_maxlimit(MC_BIGCL) - m_total(MC_BIGCL);
			mbuf_expand_big = 0;

			if (n > 0 && freelist_populate(MC_BIGCL, n, M_WAIT) > 0)
				mbuf_expand++;
		}
		if (mbuf_expand_16k) {
			int n;

			/* Adjust to current number of 16 KB cluster in use */
			n = mbuf_expand_16k -
			    (m_total(MC_16KCL) - m_infree(MC_16KCL));
			if ((n + m_total(MC_16KCL)) > m_maxlimit(MC_16KCL))
				n = m_maxlimit(MC_16KCL) - m_total(MC_16KCL);
			mbuf_expand_16k = 0;

			if (n > 0)
				(void) freelist_populate(MC_16KCL, n, M_WAIT);
		}

		/*
		 * Because we can run out of memory before filling the mbuf
		 * map, we should not allocate more clusters than they are
		 * mbufs -- otherwise we could have a large number of useless
		 * clusters allocated.
		 */
		if (mbuf_expand) {
			while (m_total(MC_MBUF) <
			    (m_total(MC_BIGCL) + m_total(MC_CL))) {
				if (freelist_populate(MC_MBUF, 1, M_WAIT) == 0)
					break;
			}
		}

		lck_mtx_unlock(mbuf_mlock);

		assert_wait(&mbuf_worker_run, THREAD_UNINT);
		(void) thread_block((thread_continue_t)mbuf_worker_thread);
	}
}

static void
mbuf_worker_thread_init(void)
{
	mbuf_worker_ready++;
	mbuf_worker_thread();
}

static mcl_slab_t *
slab_get(void *buf)
{
	mcl_slabg_t *slg;
	unsigned int ix, k;

	lck_mtx_assert(mbuf_mlock, LCK_MTX_ASSERT_OWNED);

	VERIFY(MBUF_IN_MAP(buf));
	ix = ((char *)buf - (char *)mbutl) >> MBSHIFT;
	VERIFY(ix < maxslabgrp);

	if ((slg = slabstbl[ix]) == NULL) {
		/*
		 * In the current implementation, we never shrink the memory
		 * pool (hence the cluster map); if we attempt to reallocate
		 * a cluster group when it's already allocated, panic since
		 * this is a sign of a memory corruption (slabstbl[ix] got
		 * nullified).  This also means that there shouldn't be any
		 * hole in the kernel sub-map for the mbuf pool.
		 */
		++slabgrp;
		VERIFY(ix < slabgrp);
		/*
		 * Slabs expansion can only be done single threaded; when
		 * we get here, it must be as a result of m_clalloc() which
		 * is serialized and therefore mb_clalloc_busy must be set.
		 */
		VERIFY(mb_clalloc_busy);
		lck_mtx_unlock(mbuf_mlock);

		/* This is a new buffer; create the slabs group for it */
		MALLOC(slg, mcl_slabg_t *, sizeof (*slg), M_TEMP,
		    M_WAITOK | M_ZERO);
		VERIFY(slg != NULL);

		lck_mtx_lock(mbuf_mlock);
		/*
		 * No other thread could have gone into m_clalloc() after
		 * we dropped the lock above, so verify that it's true.
		 */
		VERIFY(mb_clalloc_busy);

		slabstbl[ix] = slg;

		/* Chain each slab in the group to its forward neighbor */
		for (k = 1; k < NSLABSPMB; k++)
			slg->slg_slab[k - 1].sl_next = &slg->slg_slab[k];
		VERIFY(slg->slg_slab[NSLABSPMB - 1].sl_next == NULL);

		/* And chain the last slab in the previous group to this */
		if (ix > 0) {
			VERIFY(slabstbl[ix - 1]->
			    slg_slab[NSLABSPMB - 1].sl_next == NULL);
			slabstbl[ix - 1]->slg_slab[NSLABSPMB - 1].sl_next =
			    &slg->slg_slab[0];
		}
	}

	ix = MTOBG(buf) % NSLABSPMB;
	VERIFY(ix < NSLABSPMB);

	return (&slg->slg_slab[ix]);
}

static void
slab_init(mcl_slab_t *sp, mbuf_class_t class, u_int32_t flags,
    void *base, void *head, unsigned int len, int refcnt, int chunks)
{
	sp->sl_class = class;
	sp->sl_flags = flags;
	sp->sl_base = base;
	sp->sl_head = head;
	sp->sl_len = len;
	sp->sl_refcnt = refcnt;
	sp->sl_chunks = chunks;
	slab_detach(sp);
}

static void
slab_insert(mcl_slab_t *sp, mbuf_class_t class)
{
	VERIFY(slab_is_detached(sp));
	m_slab_cnt(class)++;
	TAILQ_INSERT_TAIL(&m_slablist(class), sp, sl_link);
	sp->sl_flags &= ~SLF_DETACHED;
	if (class == MC_16KCL) {
		int k;
		for (k = 1; k < NSLABSP16KB; k++) {
			sp = sp->sl_next;
			/* Next slab must already be present */
			VERIFY(sp != NULL);
			VERIFY(slab_is_detached(sp));
			sp->sl_flags &= ~SLF_DETACHED;
		}
	}
}

static void
slab_remove(mcl_slab_t *sp, mbuf_class_t class)
{
	VERIFY(!slab_is_detached(sp));
	VERIFY(m_slab_cnt(class) > 0);
	m_slab_cnt(class)--;
	TAILQ_REMOVE(&m_slablist(class), sp, sl_link);
	slab_detach(sp);
	if (class == MC_16KCL) {
		int k;
		for (k = 1; k < NSLABSP16KB; k++) {
			sp = sp->sl_next;
			/* Next slab must already be present */
			VERIFY(sp != NULL);
			VERIFY(!slab_is_detached(sp));
			slab_detach(sp);
		}
	}
}

static boolean_t
slab_inrange(mcl_slab_t *sp, void *buf)
{
	return ((uintptr_t)buf >= (uintptr_t)sp->sl_base &&
	    (uintptr_t)buf < ((uintptr_t)sp->sl_base + sp->sl_len));
}

#undef panic

static void
slab_nextptr_panic(mcl_slab_t *sp, void *addr)
{
	int i;
	unsigned int chunk_len = sp->sl_len / sp->sl_chunks;
	uintptr_t buf = (uintptr_t)sp->sl_base;

	for (i = 0; i < sp->sl_chunks; i++, buf += chunk_len) {
		void *next = ((mcache_obj_t *)buf)->obj_next;
		if (next != addr)
			continue;
		if (!mclverify) {
			if (next != NULL && !MBUF_IN_MAP(next)) {
				mcache_t *cp = m_cache(sp->sl_class);
				panic("%s: %s buffer %p in slab %p modified "
				    "after free at offset 0: %p out of range "
				    "[%p-%p)\n", __func__, cp->mc_name,
				    (void *)buf, sp, next, mbutl, embutl);
				/* NOTREACHED */
			}
		} else {
			mcache_audit_t *mca = mcl_audit_buf2mca(sp->sl_class,
			    (mcache_obj_t *)buf);
			mcl_audit_verify_nextptr(next, mca);
		}
	}
}

static void
slab_detach(mcl_slab_t *sp)
{
	sp->sl_link.tqe_next = (mcl_slab_t *)-1;
	sp->sl_link.tqe_prev = (mcl_slab_t **)-1;
	sp->sl_flags |= SLF_DETACHED;
}

static boolean_t
slab_is_detached(mcl_slab_t *sp)
{
	return ((intptr_t)sp->sl_link.tqe_next == -1 &&
	    (intptr_t)sp->sl_link.tqe_prev == -1 &&
	    (sp->sl_flags & SLF_DETACHED));
}

static void
mcl_audit_init(void *buf, mcache_audit_t **mca_list,
    mcache_obj_t **con_list, size_t con_size, unsigned int num)
{
	mcache_audit_t *mca, *mca_tail;
	mcache_obj_t *con = NULL;
	boolean_t save_contents = (con_list != NULL);
	unsigned int i, ix;

	ASSERT(num <= NMBPBG);
	ASSERT(con_list == NULL || con_size != 0);

	ix = MTOBG(buf);
	VERIFY(ix < maxclaudit);

	/* Make sure we haven't been here before */
	for (i = 0; i < NMBPBG; i++)
		VERIFY(mclaudit[ix].cl_audit[i] == NULL);

	mca = mca_tail = *mca_list;
	if (save_contents)
		con = *con_list;

	for (i = 0; i < num; i++) {
		mcache_audit_t *next;

		next = mca->mca_next;
		bzero(mca, sizeof (*mca));
		mca->mca_next = next;
		mclaudit[ix].cl_audit[i] = mca;

		/* Attach the contents buffer if requested */
		if (save_contents) {
			VERIFY(con != NULL);
			mca->mca_contents_size = con_size;
			mca->mca_contents = con;
			con = con->obj_next;
			bzero(mca->mca_contents, mca->mca_contents_size);
		}

		mca_tail = mca;
		mca = mca->mca_next;
	}

	if (save_contents)
		*con_list = con;

	*mca_list = mca_tail->mca_next;
	mca_tail->mca_next = NULL;
}

/*
 * Given an address of a buffer (mbuf/2KB/4KB/16KB), return
 * the corresponding audit structure for that buffer.
 */
static mcache_audit_t *
mcl_audit_buf2mca(mbuf_class_t class, mcache_obj_t *o)
{
	mcache_audit_t *mca = NULL;
	int ix = MTOBG(o);

	VERIFY(ix < maxclaudit);
	VERIFY(IS_P2ALIGNED(o, MIN(m_maxsize(class), NBPG)));

	switch (class) {
	case MC_MBUF:
		/*
		 * For the mbuf case, find the index of the page
		 * used by the mbuf and use that index to locate the
		 * base address of the page.  Then find out the
		 * mbuf index relative to the page base and use
		 * it to locate the audit structure.
		 */
		VERIFY(MCLIDX(BGTOM(ix), o) < (int)NMBPBG);
		mca = mclaudit[ix].cl_audit[MCLIDX(BGTOM(ix), o)];
		break;

	case MC_CL:
		/*
		 * Same thing as above, but for 2KB clusters in a page.
		 */
		VERIFY(CLBGIDX(BGTOM(ix), o) < (int)NCLPBG);
		mca = mclaudit[ix].cl_audit[CLBGIDX(BGTOM(ix), o)];
		break;

	case MC_BIGCL:
	case MC_16KCL:
		/*
		 * Same as above, but only return the first element.
		 */
		mca = mclaudit[ix].cl_audit[0];
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (mca);
}

static void
mcl_audit_mbuf(mcache_audit_t *mca, void *addr, boolean_t composite,
    boolean_t alloc)
{
	struct mbuf *m = addr;
	mcache_obj_t *next = ((mcache_obj_t *)m)->obj_next;

	VERIFY(mca->mca_contents != NULL &&
	    mca->mca_contents_size == AUDIT_CONTENTS_SIZE);

	if (mclverify)
		mcl_audit_verify_nextptr(next, mca);

	if (!alloc) {
		/* Save constructed mbuf fields */
		mcl_audit_save_mbuf(m, mca);
		if (mclverify) {
			mcache_set_pattern(MCACHE_FREE_PATTERN, m,
			    m_maxsize(MC_MBUF));
		}
		((mcache_obj_t *)m)->obj_next = next;
		return;
	}

	/* Check if the buffer has been corrupted while in freelist */
	if (mclverify) {
		mcache_audit_free_verify_set(mca, addr, 0, m_maxsize(MC_MBUF));
	}
	/* Restore constructed mbuf fields */
	mcl_audit_restore_mbuf(m, mca, composite);
}

static void
mcl_audit_restore_mbuf(struct mbuf *m, mcache_audit_t *mca, boolean_t composite)
{
	struct mbuf *ms = (struct mbuf *)mca->mca_contents;

	if (composite) {
		struct mbuf *next = m->m_next;
		VERIFY(ms->m_flags == M_EXT && MEXT_RFA(ms) != NULL &&
		    MBUF_IS_COMPOSITE(ms));
		/*
		 * We could have hand-picked the mbuf fields and restore
		 * them individually, but that will be a maintenance
		 * headache.  Instead, restore everything that was saved;
		 * the mbuf layer will recheck and reinitialize anyway.
		 */
		bcopy(ms, m, mca->mca_contents_size);
		m->m_next = next;
	} else {
		/*
		 * For a regular mbuf (no cluster attached) there's nothing
		 * to restore other than the type field, which is expected
		 * to be MT_FREE.
		 */
		m->m_type = ms->m_type;
	}
	_MCHECK(m);
}

static void
mcl_audit_save_mbuf(struct mbuf *m, mcache_audit_t *mca)
{
	_MCHECK(m);
	bcopy(m, mca->mca_contents, mca->mca_contents_size);
}

static void
mcl_audit_cluster(mcache_audit_t *mca, void *addr, size_t size, boolean_t alloc,
    boolean_t save_next)
{
	mcache_obj_t *next = ((mcache_obj_t *)addr)->obj_next;

	if (!alloc) {
		if (mclverify) {
			mcache_set_pattern(MCACHE_FREE_PATTERN, addr, size);
		}
		if (save_next) {
			mcl_audit_verify_nextptr(next, mca);
			((mcache_obj_t *)addr)->obj_next = next;
		}
	} else if (mclverify) {
		/* Check if the buffer has been corrupted while in freelist */
		mcl_audit_verify_nextptr(next, mca);
		mcache_audit_free_verify_set(mca, addr, 0, size);
	}
}

static void
mcl_audit_mcheck_panic(struct mbuf *m)
{
	mcache_audit_t *mca;

	MRANGE(m);
	mca = mcl_audit_buf2mca(MC_MBUF, (mcache_obj_t *)m);

	panic("mcl_audit: freed mbuf %p with type 0x%x (instead of 0x%x)\n%s\n",
	    m, (u_int16_t)m->m_type, MT_FREE, mcache_dump_mca(mca));
	/* NOTREACHED */
}

static void
mcl_audit_verify_nextptr(void *next, mcache_audit_t *mca)
{
	if (next != NULL && !MBUF_IN_MAP(next) &&
	    (next != (void *)MCACHE_FREE_PATTERN || !mclverify)) {
		panic("mcl_audit: buffer %p modified after free at offset 0: "
		    "%p out of range [%p-%p)\n%s\n",
		    mca->mca_addr, next, mbutl, embutl, mcache_dump_mca(mca));
		/* NOTREACHED */
	}
}

/* This function turns on mbuf leak detection */
static void
mleak_activate(void)
{
	mleak_table.mleak_sample_factor = MLEAK_SAMPLE_FACTOR;
	PE_parse_boot_argn("mleak_sample_factor",
	    &mleak_table.mleak_sample_factor,
	    sizeof (mleak_table.mleak_sample_factor));

	if (mleak_table.mleak_sample_factor == 0)
		mclfindleak = 0;

	if (mclfindleak == 0)
		return;

	vm_size_t alloc_size =
	    mleak_alloc_buckets * sizeof (struct mallocation);
	vm_size_t trace_size = mleak_trace_buckets * sizeof (struct mtrace);

	MALLOC(mleak_allocations, struct mallocation *, alloc_size,
	    M_TEMP, M_WAITOK | M_ZERO);
	VERIFY(mleak_allocations != NULL);

	MALLOC(mleak_traces, struct mtrace *, trace_size,
	    M_TEMP, M_WAITOK | M_ZERO);
	VERIFY(mleak_traces != NULL);

	MALLOC(mleak_stat, mleak_stat_t *, MLEAK_STAT_SIZE(MLEAK_NUM_TRACES),
	    M_TEMP, M_WAITOK | M_ZERO);
	VERIFY(mleak_stat != NULL);
	mleak_stat->ml_cnt = MLEAK_NUM_TRACES;
#ifdef __LP64__
	mleak_stat->ml_isaddr64 = 1;
#endif /* __LP64__ */
}

static void
mleak_logger(u_int32_t num, mcache_obj_t *addr, boolean_t alloc)
{
	int temp;

	if (mclfindleak == 0)
		return;

	if (!alloc)
		return (mleak_free(addr));

	temp = atomic_add_32_ov(&mleak_table.mleak_capture, 1);

	if ((temp % mleak_table.mleak_sample_factor) == 0 && addr != NULL) {
		uintptr_t bt[MLEAK_STACK_DEPTH];
		int logged = fastbacktrace(bt, MLEAK_STACK_DEPTH);
		mleak_log(bt, addr, logged, num);
	}
}

/*
 * This function records the allocation in the mleak_allocations table
 * and the backtrace in the mleak_traces table; if allocation slot is in use,
 * replace old allocation with new one if the trace slot is in use, return
 * (or increment refcount if same trace).
 */
static boolean_t
mleak_log(uintptr_t *bt, mcache_obj_t *addr, uint32_t depth, int num)
{
	struct mallocation *allocation;
	struct mtrace *trace;
	uint32_t trace_index;
	int i;

	/* Quit if someone else modifying the tables */
	if (!lck_mtx_try_lock_spin(mleak_lock)) {
		mleak_table.total_conflicts++;
		return (FALSE);
	}

	allocation = &mleak_allocations[hashaddr((uintptr_t)addr,
	    mleak_alloc_buckets)];
	trace_index = hashbacktrace(bt, depth, mleak_trace_buckets);
	trace = &mleak_traces[trace_index];

	VERIFY(allocation <= &mleak_allocations[mleak_alloc_buckets - 1]);
	VERIFY(trace <= &mleak_traces[mleak_trace_buckets - 1]);

	allocation->hitcount++;
	trace->hitcount++;

	/*
	 * If the allocation bucket we want is occupied
	 * and the occupier has the same trace, just bail.
	 */
	if (allocation->element != NULL &&
	    trace_index == allocation->trace_index) {
		mleak_table.alloc_collisions++;
		lck_mtx_unlock(mleak_lock);
		return (TRUE);
	}

	/*
	 * Store the backtrace in the traces array;
	 * Size of zero = trace bucket is free.
	 */
	if (trace->allocs > 0 &&
	    bcmp(trace->addr, bt, (depth * sizeof (uintptr_t))) != 0) {
		/* Different, unique trace, but the same hash! Bail out. */
		trace->collisions++;
		mleak_table.trace_collisions++;
		lck_mtx_unlock(mleak_lock);
		return (TRUE);
	} else if (trace->allocs > 0) {
		/* Same trace, already added, so increment refcount */
		trace->allocs++;
	} else {
		/* Found an unused trace bucket, so record the trace here */
		if (trace->depth != 0) {
			/* this slot previously used but not currently in use */
			mleak_table.trace_overwrites++;
		}
		mleak_table.trace_recorded++;
		trace->allocs = 1;
		memcpy(trace->addr, bt, (depth * sizeof (uintptr_t)));
		trace->depth = depth;
		trace->collisions = 0;
	}

	/* Step 2: Store the allocation record in the allocations array */
	if (allocation->element != NULL) {
		/*
		 * Replace an existing allocation.  No need to preserve
		 * because only a subset of the allocations are being
		 * recorded anyway.
		 */
		mleak_table.alloc_collisions++;
	} else if (allocation->trace_index != 0) {
		mleak_table.alloc_overwrites++;
	}
	allocation->element = addr;
	allocation->trace_index = trace_index;
	allocation->count = num;
	mleak_table.alloc_recorded++;
	mleak_table.outstanding_allocs++;

	/* keep a log of the last 5 traces to be top trace, in order */
	for (i = 0; i < MLEAK_NUM_TRACES; i++) {
		if (mleak_top_trace[i] == NULL ||
		    mleak_top_trace[i]->allocs <= trace->allocs) {
			if (mleak_top_trace[i] != trace) {
				int j = MLEAK_NUM_TRACES;
				while (--j > i) {
					mleak_top_trace[j] =
					    mleak_top_trace[j - 1];
				}
				mleak_top_trace[i] = trace;
			}
			break;
		}
	}

	lck_mtx_unlock(mleak_lock);
	return (TRUE);
}

static void
mleak_free(mcache_obj_t *addr)
{
	while (addr != NULL) {
		struct mallocation *allocation = &mleak_allocations
		    [hashaddr((uintptr_t)addr, mleak_alloc_buckets)];

		if (allocation->element == addr &&
		    allocation->trace_index < mleak_trace_buckets) {
			lck_mtx_lock_spin(mleak_lock);
			if (allocation->element == addr &&
			    allocation->trace_index < mleak_trace_buckets) {
				struct mtrace *trace;
				trace = &mleak_traces[allocation->trace_index];
				/* allocs = 0 means trace bucket is unused */
				if (trace->allocs > 0)
					trace->allocs--;
				if (trace->allocs == 0)
					trace->depth = 0;
				/* NULL element means alloc bucket is unused */
				allocation->element = NULL;
				mleak_table.outstanding_allocs--;
			}
			lck_mtx_unlock(mleak_lock);
		}
		addr = addr->obj_next;
	}
}

static struct mbtypes {
	int		mt_type;
	const char	*mt_name;
} mbtypes[] = {
	{ MT_DATA,	"data" },
	{ MT_OOBDATA,	"oob data" },
	{ MT_CONTROL,	"ancillary data" },
	{ MT_HEADER,	"packet headers" },
	{ MT_SOCKET,	"socket structures" },
	{ MT_PCB,	"protocol control blocks" },
	{ MT_RTABLE,	"routing table entries" },
	{ MT_HTABLE,	"IMP host table entries" },
	{ MT_ATABLE,	"address resolution tables" },
	{ MT_FTABLE,	"fragment reassembly queue headers" },
	{ MT_SONAME,	"socket names and addresses" },
	{ MT_SOOPTS,	"socket options" },
	{ MT_RIGHTS,	"access rights" },
	{ MT_IFADDR,	"interface addresses" },
	{ MT_TAG,	"packet tags" },
	{ 0,		NULL }
};

#define	MBUF_DUMP_BUF_CHK() {	\
	clen -= k;		\
	if (clen < 1)		\
		goto done;	\
	c += k;			\
}

static char *
mbuf_dump(void)
{
	unsigned long totmem = 0, totfree = 0, totmbufs, totused, totpct;
	u_int32_t m_mbufs = 0, m_clfree = 0, m_bigclfree = 0;
	u_int32_t m_mbufclfree = 0, m_mbufbigclfree = 0;
	u_int32_t m_16kclusters = 0, m_16kclfree = 0, m_mbuf16kclfree = 0;
	int nmbtypes = sizeof (mbstat.m_mtypes) / sizeof (short);
	uint8_t seen[256];
	struct mbtypes *mp;
	mb_class_stat_t *sp;
	char *c = mbuf_dump_buf;
	int i, k, clen = sizeof (mbuf_dump_buf);

	mbuf_dump_buf[0] = '\0';

	/* synchronize all statistics in the mbuf table */
	mbuf_stat_sync();
	mbuf_mtypes_sync(TRUE);

	sp = &mb_stat->mbs_class[0];
	for (i = 0; i < mb_stat->mbs_cnt; i++, sp++) {
		u_int32_t mem;

		if (m_class(i) == MC_MBUF) {
			m_mbufs = sp->mbcl_active;
		} else if (m_class(i) == MC_CL) {
			m_clfree = sp->mbcl_total - sp->mbcl_active;
		} else if (m_class(i) == MC_BIGCL) {
			m_bigclfree = sp->mbcl_total - sp->mbcl_active;
		} else if (njcl > 0 && m_class(i) == MC_16KCL) {
			m_16kclfree = sp->mbcl_total - sp->mbcl_active;
			m_16kclusters = sp->mbcl_total;
		} else if (m_class(i) == MC_MBUF_CL) {
			m_mbufclfree = sp->mbcl_total - sp->mbcl_active;
		} else if (m_class(i) == MC_MBUF_BIGCL) {
			m_mbufbigclfree = sp->mbcl_total - sp->mbcl_active;
		} else if (njcl > 0 && m_class(i) == MC_MBUF_16KCL) {
			m_mbuf16kclfree = sp->mbcl_total - sp->mbcl_active;
		}

		mem = sp->mbcl_ctotal * sp->mbcl_size;
		totmem += mem;
		totfree += (sp->mbcl_mc_cached + sp->mbcl_infree) *
		    sp->mbcl_size;

	}

	/* adjust free counts to include composite caches */
	m_clfree += m_mbufclfree;
	m_bigclfree += m_mbufbigclfree;
	m_16kclfree += m_mbuf16kclfree;

	totmbufs = 0;
	for (mp = mbtypes; mp->mt_name != NULL; mp++)
		totmbufs += mbstat.m_mtypes[mp->mt_type];
	if (totmbufs > m_mbufs)
		totmbufs = m_mbufs;
	k = snprintf(c, clen, "%lu/%u mbufs in use:\n", totmbufs, m_mbufs);
	MBUF_DUMP_BUF_CHK();

	bzero(&seen, sizeof (seen));
	for (mp = mbtypes; mp->mt_name != NULL; mp++) {
		if (mbstat.m_mtypes[mp->mt_type] != 0) {
			seen[mp->mt_type] = 1;
			k = snprintf(c, clen, "\t%u mbufs allocated to %s\n",
			    mbstat.m_mtypes[mp->mt_type], mp->mt_name);
			MBUF_DUMP_BUF_CHK();
		}
	}
	seen[MT_FREE] = 1;
	for (i = 0; i < nmbtypes; i++)
		if (!seen[i] && mbstat.m_mtypes[i] != 0) {
			k = snprintf(c, clen, "\t%u mbufs allocated to "
			    "<mbuf type %d>\n", mbstat.m_mtypes[i], i);
			MBUF_DUMP_BUF_CHK();
		}
	if ((m_mbufs - totmbufs) > 0) {
		k = snprintf(c, clen, "\t%lu mbufs allocated to caches\n",
		    m_mbufs - totmbufs);
		MBUF_DUMP_BUF_CHK();
	}
	k = snprintf(c, clen, "%u/%u mbuf 2KB clusters in use\n"
	    "%u/%u mbuf 4KB clusters in use\n",
	    (unsigned int)(mbstat.m_clusters - m_clfree),
	    (unsigned int)mbstat.m_clusters,
	    (unsigned int)(mbstat.m_bigclusters - m_bigclfree),
	    (unsigned int)mbstat.m_bigclusters);
	MBUF_DUMP_BUF_CHK();

	if (njcl > 0) {
		k = snprintf(c, clen, "%u/%u mbuf %uKB clusters in use\n",
		    m_16kclusters - m_16kclfree, m_16kclusters,
		    njclbytes / 1024);
		MBUF_DUMP_BUF_CHK();
	}
	totused = totmem - totfree;
	if (totmem == 0) {
		totpct = 0;
	} else if (totused < (ULONG_MAX / 100)) {
		totpct = (totused * 100) / totmem;
	} else {
		u_long totmem1 = totmem / 100;
		u_long totused1 = totused / 100;
		totpct = (totused1 * 100) / totmem1;
	}
	k = snprintf(c, clen, "%lu KB allocated to network (approx. %lu%% "
	    "in use)\n", totmem / 1024, totpct);
	MBUF_DUMP_BUF_CHK();

done:
	return (mbuf_dump_buf);
}

#undef MBUF_DUMP_BUF_CHK

SYSCTL_DECL(_kern_ipc);
SYSCTL_PROC(_kern_ipc, KIPC_MBSTAT, mbstat,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, mbstat_sysctl, "S,mbstat", "");
SYSCTL_PROC(_kern_ipc, OID_AUTO, mb_stat,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, mb_stat_sysctl, "S,mb_stat", "");
SYSCTL_PROC(_kern_ipc, OID_AUTO, mleak_top_trace,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, mleak_top_trace_sysctl, "S,mb_top_trace", "");
SYSCTL_PROC(_kern_ipc, OID_AUTO, mleak_table,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, mleak_table_sysctl, "S,mleak_table", "");
SYSCTL_INT(_kern_ipc, OID_AUTO, mleak_sample_factor,
    CTLFLAG_RW | CTLFLAG_LOCKED, &mleak_table.mleak_sample_factor, 0, "");
SYSCTL_INT(_kern_ipc, OID_AUTO, mb_normalized,
    CTLFLAG_RD | CTLFLAG_LOCKED, &mb_normalized, 0, "");
SYSCTL_INT(_kern_ipc, OID_AUTO, mb_watchdog,
    CTLFLAG_RW | CTLFLAG_LOCKED, &mb_watchdog, 0, "");
