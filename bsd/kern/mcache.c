/*
 * Copyright (c) 2006-2011 Apple Inc. All rights reserved.
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

/*
 * Memory allocator with per-CPU caching, derived from the kmem magazine
 * concept and implementation as described in the following paper:
 * http://www.usenix.org/events/usenix01/full_papers/bonwick/bonwick.pdf
 * That implementation is Copyright 2006 Sun Microsystems, Inc.  All rights
 * reserved.  Use is subject to license terms.
 *
 * There are several major differences between this and the original kmem
 * magazine: this derivative implementation allows for multiple objects to
 * be allocated and freed from/to the object cache in one call; in addition,
 * it provides for better flexibility where the user is allowed to define
 * its own slab allocator (instead of the default zone allocator).  Finally,
 * no object construction/destruction takes place at the moment, although
 * this could be added in future to improve efficiency.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/queue.h>
#include <sys/kernel.h>
#include <sys/systm.h>

#include <kern/debug.h>
#include <kern/zalloc.h>
#include <kern/cpu_number.h>
#include <kern/locks.h>

#include <libkern/libkern.h>
#include <libkern/OSAtomic.h>
#include <libkern/OSDebug.h>

#include <mach/vm_param.h>
#include <machine/limits.h>
#include <machine/machine_routines.h>

#include <string.h>

#include <sys/mcache.h>

#define	MCACHE_SIZE(n) \
	((size_t)(&((mcache_t *)0)->mc_cpu[n]))

/* Allocate extra in case we need to manually align the pointer */
#define	MCACHE_ALLOC_SIZE \
	(sizeof (void *) + MCACHE_SIZE(ncpu) + CPU_CACHE_SIZE)

#define	MCACHE_CPU(c) \
	(mcache_cpu_t *)((void *)((char *)(c) + MCACHE_SIZE(cpu_number())))

/*
 * MCACHE_LIST_LOCK() and MCACHE_LIST_UNLOCK() are macros used
 * to serialize accesses to the global list of caches in the system.
 * They also record the thread currently running in the critical
 * section, so that we can avoid recursive requests to reap the
 * caches when memory runs low.
 */
#define	MCACHE_LIST_LOCK() {				\
	lck_mtx_lock(mcache_llock);			\
	mcache_llock_owner = current_thread();		\
}

#define	MCACHE_LIST_UNLOCK() {				\
	mcache_llock_owner = NULL;			\
	lck_mtx_unlock(mcache_llock);			\
}

#define	MCACHE_LOCK(l)		lck_mtx_lock(l)
#define	MCACHE_UNLOCK(l)	lck_mtx_unlock(l)
#define	MCACHE_LOCK_TRY(l)	lck_mtx_try_lock(l)

static int ncpu;
static lck_mtx_t *mcache_llock;
static struct thread *mcache_llock_owner;
static lck_attr_t *mcache_llock_attr;
static lck_grp_t *mcache_llock_grp;
static lck_grp_attr_t *mcache_llock_grp_attr;
static struct zone *mcache_zone;
static unsigned int mcache_reap_interval;
static UInt32 mcache_reaping;
static int mcache_ready;
static int mcache_updating;

static int mcache_bkt_contention = 3;
#if DEBUG
static unsigned int mcache_flags = MCF_DEBUG;
#else
static unsigned int mcache_flags = 0;
#endif

#define	DUMP_MCA_BUF_SIZE	512
static char *mca_dump_buf;

static mcache_bkttype_t mcache_bkttype[] = {
	{ 1,	4096,	32768,	NULL },
	{ 3,	2048,	16384,	NULL },
	{ 7,	1024,	12288,	NULL },
	{ 15,	256,	8192,	NULL },
	{ 31,	64,	4096,	NULL },
	{ 47,	0,	2048,	NULL },
	{ 63,	0,	1024,	NULL },
	{ 95,	0,	512,	NULL },
	{ 143,	0,	256,	NULL },
	{ 165,	0,	0,	NULL },
};

static mcache_t *mcache_create_common(const char *, size_t, size_t,
    mcache_allocfn_t, mcache_freefn_t, mcache_auditfn_t, mcache_logfn_t,
    mcache_notifyfn_t, void *, u_int32_t, int, int);
static unsigned int mcache_slab_alloc(void *, mcache_obj_t ***,
    unsigned int, int);
static void mcache_slab_free(void *, mcache_obj_t *, boolean_t);
static void mcache_slab_audit(void *, mcache_obj_t *, boolean_t);
static void mcache_cpu_refill(mcache_cpu_t *, mcache_bkt_t *, int);
static mcache_bkt_t *mcache_bkt_alloc(mcache_t *, mcache_bktlist_t *,
    mcache_bkttype_t **);
static void mcache_bkt_free(mcache_t *, mcache_bktlist_t *, mcache_bkt_t *);
static void mcache_cache_bkt_enable(mcache_t *);
static void mcache_bkt_purge(mcache_t *);
static void mcache_bkt_destroy(mcache_t *, mcache_bkttype_t *,
    mcache_bkt_t *, int);
static void mcache_bkt_ws_update(mcache_t *);
static void mcache_bkt_ws_reap(mcache_t *);
static void mcache_dispatch(void (*)(void *), void *);
static void mcache_cache_reap(mcache_t *);
static void mcache_cache_update(mcache_t *);
static void mcache_cache_bkt_resize(void *);
static void mcache_cache_enable(void *);
static void mcache_update(void *);
static void mcache_update_timeout(void *);
static void mcache_applyall(void (*)(mcache_t *));
static void mcache_reap_start(void *);
static void mcache_reap_done(void *);
static void mcache_reap_timeout(void *);
static void mcache_notify(mcache_t *, u_int32_t);
static void mcache_purge(void *);

static LIST_HEAD(, mcache) mcache_head;
mcache_t *mcache_audit_cache;

/*
 * Initialize the framework; this is currently called as part of BSD init.
 */
__private_extern__ void
mcache_init(void)
{
	mcache_bkttype_t *btp;
	unsigned int i;
	char name[32];

	ncpu = ml_get_max_cpus();

	mcache_llock_grp_attr = lck_grp_attr_alloc_init();
	mcache_llock_grp = lck_grp_alloc_init("mcache.list",
	    mcache_llock_grp_attr);
	mcache_llock_attr = lck_attr_alloc_init();
	mcache_llock = lck_mtx_alloc_init(mcache_llock_grp, mcache_llock_attr);

	mcache_zone = zinit(MCACHE_ALLOC_SIZE, 256 * MCACHE_ALLOC_SIZE,
	    PAGE_SIZE, "mcache");
	if (mcache_zone == NULL)
		panic("mcache_init: failed to allocate mcache zone\n");
	zone_change(mcache_zone, Z_CALLERACCT, FALSE);

	LIST_INIT(&mcache_head);

	for (i = 0; i < sizeof (mcache_bkttype) / sizeof (*btp); i++) {
		btp = &mcache_bkttype[i];
		(void) snprintf(name, sizeof (name), "bkt_%d",
		    btp->bt_bktsize);
		btp->bt_cache = mcache_create(name,
		    (btp->bt_bktsize + 1) * sizeof (void *), 0, 0, MCR_SLEEP);
	}

	PE_parse_boot_argn("mcache_flags", &mcache_flags, sizeof (mcache_flags));
	mcache_flags &= MCF_FLAGS_MASK;

	mcache_audit_cache = mcache_create("audit", sizeof (mcache_audit_t),
	    0, 0, MCR_SLEEP);

	mcache_reap_interval = 15 * hz;
	mcache_applyall(mcache_cache_bkt_enable);
	mcache_ready = 1;
}

/*
 * Return the global mcache flags.
 */
__private_extern__ unsigned int
mcache_getflags(void)
{
	return (mcache_flags);
}

/*
 * Create a cache using the zone allocator as the backend slab allocator.
 * The caller may specify any alignment for the object; if it specifies 0
 * the default alignment (MCACHE_ALIGN) will be used.
 */
__private_extern__ mcache_t *
mcache_create(const char *name, size_t bufsize, size_t align,
    u_int32_t flags, int wait)
{
	return (mcache_create_common(name, bufsize, align, mcache_slab_alloc,
	    mcache_slab_free, mcache_slab_audit, NULL, NULL, NULL, flags, 1,
	    wait));
}

/*
 * Create a cache using a custom backend slab allocator.  Since the caller
 * is responsible for allocation, no alignment guarantee will be provided
 * by this framework.
 */
__private_extern__ mcache_t *
mcache_create_ext(const char *name, size_t bufsize,
    mcache_allocfn_t allocfn, mcache_freefn_t freefn, mcache_auditfn_t auditfn,
    mcache_logfn_t logfn, mcache_notifyfn_t notifyfn, void *arg,
    u_int32_t flags, int wait)
{
	return (mcache_create_common(name, bufsize, 0, allocfn,
	    freefn, auditfn, logfn, notifyfn, arg, flags, 0, wait));
}

/*
 * Common cache creation routine.
 */
static mcache_t *
mcache_create_common(const char *name, size_t bufsize, size_t align,
    mcache_allocfn_t allocfn, mcache_freefn_t freefn, mcache_auditfn_t auditfn,
    mcache_logfn_t logfn, mcache_notifyfn_t notifyfn, void *arg,
    u_int32_t flags, int need_zone, int wait)
{
	mcache_bkttype_t *btp;
	mcache_t *cp = NULL;
	size_t chunksize;
	void *buf, **pbuf;
	int c;
	char lck_name[64];

	/* If auditing is on and print buffer is NULL, allocate it now */
	if ((flags & MCF_DEBUG) && mca_dump_buf == NULL) {
		int malloc_wait = (wait & MCR_NOSLEEP) ? M_NOWAIT : M_WAITOK;
		MALLOC(mca_dump_buf, char *, DUMP_MCA_BUF_SIZE, M_TEMP,
		    malloc_wait | M_ZERO);
		if (mca_dump_buf == NULL)
			return (NULL);
	}

	if (!(wait & MCR_NOSLEEP))
		buf = zalloc(mcache_zone);
	else
		buf = zalloc_noblock(mcache_zone);

	if (buf == NULL)
		goto fail;

	bzero(buf, MCACHE_ALLOC_SIZE);

	/*
	 * In case we didn't get a cache-aligned memory, round it up
	 * accordingly.  This is needed in order to get the rest of
	 * structure members aligned properly.  It also means that
	 * the memory span gets shifted due to the round up, but it
	 * is okay since we've allocated extra space for this.
	 */
	cp = (mcache_t *)
	    P2ROUNDUP((intptr_t)buf + sizeof (void *), CPU_CACHE_SIZE);
	pbuf = (void **)((intptr_t)cp - sizeof (void *));
	*pbuf = buf;

	/*
	 * Guaranteed alignment is valid only when we use the internal
	 * slab allocator (currently set to use the zone allocator).
	 */
	if (!need_zone)
		align = 1;
	else if (align == 0)
		align = MCACHE_ALIGN;

	if ((align & (align - 1)) != 0)
		panic("mcache_create: bad alignment %lu", align);

	cp->mc_align = align;
	cp->mc_slab_alloc = allocfn;
	cp->mc_slab_free = freefn;
	cp->mc_slab_audit = auditfn;
	cp->mc_slab_log = logfn;
	cp->mc_slab_notify = notifyfn;
	cp->mc_private = need_zone ? cp : arg;
	cp->mc_bufsize = bufsize;
	cp->mc_flags = (flags & MCF_FLAGS_MASK) | mcache_flags;

	(void) snprintf(cp->mc_name, sizeof (cp->mc_name), "mcache.%s", name);

	(void) snprintf(lck_name, sizeof (lck_name), "%s.cpu", cp->mc_name);
	cp->mc_cpu_lock_grp_attr = lck_grp_attr_alloc_init();
	cp->mc_cpu_lock_grp = lck_grp_alloc_init(lck_name,
	    cp->mc_cpu_lock_grp_attr);
	cp->mc_cpu_lock_attr = lck_attr_alloc_init();

	/*
	 * Allocation chunk size is the object's size plus any extra size
	 * needed to satisfy the object's alignment.  It is enforced to be
	 * at least the size of an LP64 pointer to simplify auditing and to
	 * handle multiple-element allocation requests, where the elements
	 * returned are linked together in a list.
	 */
	chunksize = MAX(bufsize, sizeof (u_int64_t));
	if (need_zone) {
		/* Enforce 64-bit minimum alignment for zone-based buffers */
		align = MAX(align, sizeof (u_int64_t));
		chunksize += sizeof (void *) + align;
		chunksize = P2ROUNDUP(chunksize, align);
		if ((cp->mc_slab_zone = zinit(chunksize, 64 * 1024 * ncpu,
		    PAGE_SIZE, cp->mc_name)) == NULL)
			goto fail;
		zone_change(cp->mc_slab_zone, Z_EXPAND, TRUE);
	}
	cp->mc_chunksize = chunksize;

	/*
	 * Initialize the bucket layer.
	 */
	(void) snprintf(lck_name, sizeof (lck_name), "%s.bkt", cp->mc_name);
	cp->mc_bkt_lock_grp_attr = lck_grp_attr_alloc_init();
	cp->mc_bkt_lock_grp = lck_grp_alloc_init(lck_name,
	    cp->mc_bkt_lock_grp_attr);
	cp->mc_bkt_lock_attr = lck_attr_alloc_init();
	lck_mtx_init(&cp->mc_bkt_lock, cp->mc_bkt_lock_grp,
	    cp->mc_bkt_lock_attr);

	(void) snprintf(lck_name, sizeof (lck_name), "%s.sync", cp->mc_name);
	cp->mc_sync_lock_grp_attr = lck_grp_attr_alloc_init();
	cp->mc_sync_lock_grp = lck_grp_alloc_init(lck_name,
	    cp->mc_sync_lock_grp_attr);
	cp->mc_sync_lock_attr = lck_attr_alloc_init();
	lck_mtx_init(&cp->mc_sync_lock, cp->mc_sync_lock_grp,
	    cp->mc_sync_lock_attr);

	for (btp = mcache_bkttype; chunksize <= btp->bt_minbuf; btp++)
		continue;

	cp->cache_bkttype = btp;

	/*
	 * Initialize the CPU layer.  Each per-CPU structure is aligned
	 * on the CPU cache line boundary to prevent false sharing.
	 */
	for (c = 0; c < ncpu; c++) {
		mcache_cpu_t *ccp = &cp->mc_cpu[c];

		VERIFY(IS_P2ALIGNED(ccp, CPU_CACHE_SIZE));
		lck_mtx_init(&ccp->cc_lock, cp->mc_cpu_lock_grp,
		    cp->mc_cpu_lock_attr);
		ccp->cc_objs = -1;
		ccp->cc_pobjs = -1;
	}

	if (mcache_ready)
		mcache_cache_bkt_enable(cp);

	/* TODO: dynamically create sysctl for stats */

	MCACHE_LIST_LOCK();
	LIST_INSERT_HEAD(&mcache_head, cp, mc_list);
	MCACHE_LIST_UNLOCK();

	/*
	 * If cache buckets are enabled and this is the first cache
	 * created, start the periodic cache update.
	 */
	if (!(mcache_flags & MCF_NOCPUCACHE) && !mcache_updating) {
		mcache_updating = 1;
		mcache_update_timeout(NULL);
	}
	if (cp->mc_flags & MCF_DEBUG) {
		printf("mcache_create: %s (%s) arg %p bufsize %lu align %lu "
		    "chunksize %lu bktsize %d\n", name, need_zone ? "i" : "e",
		    arg, bufsize, cp->mc_align, chunksize, btp->bt_bktsize);
	}
	return (cp);

fail:
	if (buf != NULL)
		zfree(mcache_zone, buf);
	return (NULL);
}

/*
 * Allocate one or more objects from a cache.
 */
__private_extern__ unsigned int
mcache_alloc_ext(mcache_t *cp, mcache_obj_t **list, unsigned int num, int wait)
{
	mcache_cpu_t *ccp;
	mcache_obj_t **top = &(*list);
	mcache_bkt_t *bkt;
	unsigned int need = num;
	boolean_t nwretry = FALSE;

	/* MCR_NOSLEEP and MCR_FAILOK are mutually exclusive */
	VERIFY((wait & (MCR_NOSLEEP|MCR_FAILOK)) != (MCR_NOSLEEP|MCR_FAILOK));

	ASSERT(list != NULL);
	*list = NULL;

	if (num == 0)
		return (0);

retry_alloc:
	/* We may not always be running in the same CPU in case of retries */
	ccp = MCACHE_CPU(cp);

	MCACHE_LOCK(&ccp->cc_lock);
	for (;;) {
		/*
		 * If we have an object in the current CPU's filled bucket,
		 * chain the object to any previous objects and return if
		 * we've satisfied the number of requested objects.
		 */
		if (ccp->cc_objs > 0) {
			mcache_obj_t *tail;
			int objs;

			/*
			 * Objects in the bucket are already linked together
			 * with the most recently freed object at the head of
			 * the list; grab as many objects as we can.
			 */
			objs = MIN((unsigned int)ccp->cc_objs, need);
			*list = ccp->cc_filled->bkt_obj[ccp->cc_objs - 1];
			ccp->cc_objs -= objs;
			ccp->cc_alloc += objs;

			tail = ccp->cc_filled->bkt_obj[ccp->cc_objs];
			list = &tail->obj_next;
			*list = NULL;

			/* If we got them all, return to caller */
			if ((need -= objs) == 0) {
				MCACHE_UNLOCK(&ccp->cc_lock);

				if (!(cp->mc_flags & MCF_NOLEAKLOG) &&
				    cp->mc_slab_log != NULL)
					(*cp->mc_slab_log)(num, *top, TRUE);

				if (cp->mc_flags & MCF_DEBUG)
					goto debug_alloc;

				return (num);
			}
		}

		/*
		 * The CPU's filled bucket is empty.  If the previous filled
		 * bucket was full, exchange and try again.
		 */
		if (ccp->cc_pobjs > 0) {
			mcache_cpu_refill(ccp, ccp->cc_pfilled, ccp->cc_pobjs);
			continue;
		}

		/*
		 * If the bucket layer is disabled, allocate from slab.  This
		 * can happen either because MCF_NOCPUCACHE is set, or because
		 * the bucket layer is currently being resized.
		 */
		if (ccp->cc_bktsize == 0)
			break;

		/*
		 * Both of the CPU's buckets are empty; try to get a full
		 * bucket from the bucket layer.  Upon success, refill this
		 * CPU and place any empty bucket into the empty list.
		 */
		bkt = mcache_bkt_alloc(cp, &cp->mc_full, NULL);
		if (bkt != NULL) {
			if (ccp->cc_pfilled != NULL)
				mcache_bkt_free(cp, &cp->mc_empty,
				    ccp->cc_pfilled);
			mcache_cpu_refill(ccp, bkt, ccp->cc_bktsize);
			continue;
		}

		/*
		 * The bucket layer has no full buckets; allocate the
		 * object(s) directly from the slab layer.
		 */
		break;
	}
	MCACHE_UNLOCK(&ccp->cc_lock);

	need -= (*cp->mc_slab_alloc)(cp->mc_private, &list, need, wait);

	/*
	 * If this is a blocking allocation, or if it is non-blocking and
	 * the cache's full bucket is non-empty, then retry the allocation.
	 */
	if (need > 0) {
		if (!(wait & MCR_NONBLOCKING)) {
			atomic_add_32(&cp->mc_wretry_cnt, 1);
			goto retry_alloc;
		} else if ((wait & (MCR_NOSLEEP | MCR_TRYHARD)) &&
		    !mcache_bkt_isempty(cp)) {
			if (!nwretry)
				nwretry = TRUE;
			atomic_add_32(&cp->mc_nwretry_cnt, 1);
			goto retry_alloc;
		} else if (nwretry) {
			atomic_add_32(&cp->mc_nwfail_cnt, 1);
		}
	}

	if (!(cp->mc_flags & MCF_NOLEAKLOG) && cp->mc_slab_log != NULL)
		(*cp->mc_slab_log)((num - need), *top, TRUE);

	if (!(cp->mc_flags & MCF_DEBUG))
		return (num - need);

debug_alloc:
	if (cp->mc_flags & MCF_DEBUG) {
		mcache_obj_t **o = top;
		unsigned int n;

		n = 0;
		/*
		 * Verify that the chain of objects have the same count as
		 * what we are about to report to the caller.  Any mismatch
		 * here means that the object list is insanely broken and
		 * therefore we must panic.
		 */
		while (*o != NULL) {
			o = &(*o)->obj_next;
			++n;
		}
		if (n != (num - need)) {
			panic("mcache_alloc_ext: %s cp %p corrupted list "
			    "(got %d actual %d)\n", cp->mc_name,
			    (void *)cp, num - need, n);
		}
	}

	/* Invoke the slab layer audit callback if auditing is enabled */
	if ((cp->mc_flags & MCF_DEBUG) && cp->mc_slab_audit != NULL)
		(*cp->mc_slab_audit)(cp->mc_private, *top, TRUE);

	return (num - need);
}

/*
 * Allocate a single object from a cache.
 */
__private_extern__ void *
mcache_alloc(mcache_t *cp, int wait)
{
	mcache_obj_t *buf;

	(void) mcache_alloc_ext(cp, &buf, 1, wait);
	return (buf);
}

__private_extern__ void
mcache_waiter_inc(mcache_t *cp)
{
	atomic_add_32(&cp->mc_waiter_cnt, 1);
}

__private_extern__ void
mcache_waiter_dec(mcache_t *cp)
{
	atomic_add_32(&cp->mc_waiter_cnt, -1);
}

__private_extern__ boolean_t
mcache_bkt_isempty(mcache_t *cp)
{
	/*
	 * This isn't meant to accurately tell whether there are
	 * any full buckets in the cache; it is simply a way to
	 * obtain "hints" about the state of the cache.
	 */
	return (cp->mc_full.bl_total == 0);
}

/*
 * Notify the slab layer about an event.
 */
static void
mcache_notify(mcache_t *cp, u_int32_t event)
{
	if (cp->mc_slab_notify != NULL)
		(*cp->mc_slab_notify)(cp->mc_private, event);
}

/*
 * Purge the cache and disable its buckets.
 */
static void
mcache_purge(void *arg)
{
	mcache_t *cp = arg;

	mcache_bkt_purge(cp);
	/*
	 * We cannot simply call mcache_cache_bkt_enable() from here as
	 * a bucket resize may be in flight and we would cause the CPU
	 * layers of the cache to point to different sizes.  Therefore,
	 * we simply increment the enable count so that during the next
	 * periodic cache update the buckets can be reenabled.
	 */
	lck_mtx_lock_spin(&cp->mc_sync_lock);
	cp->mc_enable_cnt++;
	lck_mtx_unlock(&cp->mc_sync_lock);

}

__private_extern__ boolean_t
mcache_purge_cache(mcache_t *cp)
{
	/*
	 * Purging a cache that has no per-CPU caches or is already
	 * in the process of being purged is rather pointless.
	 */
	if (cp->mc_flags & MCF_NOCPUCACHE)
		return (FALSE);

	lck_mtx_lock_spin(&cp->mc_sync_lock);
	if (cp->mc_purge_cnt > 0) {
		lck_mtx_unlock(&cp->mc_sync_lock);
		return (FALSE);
	}
	cp->mc_purge_cnt++;
	lck_mtx_unlock(&cp->mc_sync_lock);

	mcache_dispatch(mcache_purge, cp);

	return (TRUE);
}

/*
 * Free a single object to a cache.
 */
__private_extern__ void
mcache_free(mcache_t *cp, void *buf)
{
	((mcache_obj_t *)buf)->obj_next = NULL;
	mcache_free_ext(cp, (mcache_obj_t *)buf);
}

/*
 * Free one or more objects to a cache.
 */
__private_extern__ void
mcache_free_ext(mcache_t *cp, mcache_obj_t *list)
{
	mcache_cpu_t *ccp = MCACHE_CPU(cp);
	mcache_bkttype_t *btp;
	mcache_obj_t *nlist;
	mcache_bkt_t *bkt;

	if (!(cp->mc_flags & MCF_NOLEAKLOG) && cp->mc_slab_log != NULL)
		(*cp->mc_slab_log)(0, list, FALSE);

	/* Invoke the slab layer audit callback if auditing is enabled */
	if ((cp->mc_flags & MCF_DEBUG) && cp->mc_slab_audit != NULL)
		(*cp->mc_slab_audit)(cp->mc_private, list, FALSE);

	MCACHE_LOCK(&ccp->cc_lock);
	for (;;) {
		/*
		 * If there is space in the current CPU's filled bucket, put
		 * the object there and return once all objects are freed.
		 * Note the cast to unsigned integer takes care of the case
		 * where the bucket layer is disabled (when cc_objs is -1).
		 */
		if ((unsigned int)ccp->cc_objs <
		    (unsigned int)ccp->cc_bktsize) {
			/*
			 * Reverse the list while we place the object into the
			 * bucket; this effectively causes the most recently
			 * freed object(s) to be reused during allocation.
			 */
			nlist = list->obj_next;
			list->obj_next = (ccp->cc_objs == 0) ? NULL :
			    ccp->cc_filled->bkt_obj[ccp->cc_objs - 1];
			ccp->cc_filled->bkt_obj[ccp->cc_objs++] = list;
			ccp->cc_free++;

			if ((list = nlist) != NULL)
				continue;

			/* We are done; return to caller */
			MCACHE_UNLOCK(&ccp->cc_lock);

			/* If there is a waiter below, notify it */
			if (cp->mc_waiter_cnt > 0)
				mcache_notify(cp, MCN_RETRYALLOC);
			return;
		}

		/*
		 * The CPU's filled bucket is full.  If the previous filled
		 * bucket was empty, exchange and try again.
		 */
		if (ccp->cc_pobjs == 0) {
			mcache_cpu_refill(ccp, ccp->cc_pfilled, ccp->cc_pobjs);
			continue;
		}

		/*
		 * If the bucket layer is disabled, free to slab.  This can
		 * happen either because MCF_NOCPUCACHE is set, or because
		 * the bucket layer is currently being resized.
		 */
		if (ccp->cc_bktsize == 0)
			break;

		/*
		 * Both of the CPU's buckets are full; try to get an empty
		 * bucket from the bucket layer.  Upon success, empty this
		 * CPU and place any full bucket into the full list.
		 */
		bkt = mcache_bkt_alloc(cp, &cp->mc_empty, &btp);
		if (bkt != NULL) {
			if (ccp->cc_pfilled != NULL)
				mcache_bkt_free(cp, &cp->mc_full,
				    ccp->cc_pfilled);
			mcache_cpu_refill(ccp, bkt, 0);
			continue;
		}

		/*
		 * We need an empty bucket to put our freed objects into
		 * but couldn't get an empty bucket from the bucket layer;
		 * attempt to allocate one.  We do not want to block for
		 * allocation here, and if the bucket allocation fails
		 * we will simply fall through to the slab layer.
		 */
		MCACHE_UNLOCK(&ccp->cc_lock);
		bkt = mcache_alloc(btp->bt_cache, MCR_NOSLEEP);
		MCACHE_LOCK(&ccp->cc_lock);

		if (bkt != NULL) {
			/*
			 * We have an empty bucket, but since we drop the
			 * CPU lock above, the cache's bucket size may have
			 * changed.  If so, free the bucket and try again.
			 */
			if (ccp->cc_bktsize != btp->bt_bktsize) {
				MCACHE_UNLOCK(&ccp->cc_lock);
				mcache_free(btp->bt_cache, bkt);
				MCACHE_LOCK(&ccp->cc_lock);
				continue;
			}

			/*
			 * We have an empty bucket of the right size;
			 * add it to the bucket layer and try again.
			 */
			mcache_bkt_free(cp, &cp->mc_empty, bkt);
			continue;
		}

		/*
		 * The bucket layer has no empty buckets; free the
		 * object(s) directly to the slab layer.
		 */
		break;
	}
	MCACHE_UNLOCK(&ccp->cc_lock);

	/* If there is a waiter below, notify it */
	if (cp->mc_waiter_cnt > 0)
		mcache_notify(cp, MCN_RETRYALLOC);

	/* Advise the slab layer to purge the object(s) */
	(*cp->mc_slab_free)(cp->mc_private, list,
	    (cp->mc_flags & MCF_DEBUG) || cp->mc_purge_cnt);
}

/*
 * Cache destruction routine.
 */
__private_extern__ void
mcache_destroy(mcache_t *cp)
{
	void **pbuf;

	MCACHE_LIST_LOCK();
	LIST_REMOVE(cp, mc_list);
	MCACHE_LIST_UNLOCK();

	mcache_bkt_purge(cp);

	/*
	 * This cache is dead; there should be no further transaction.
	 * If it's still invoked, make sure that it induces a fault.
	 */
	cp->mc_slab_alloc = NULL;
	cp->mc_slab_free = NULL;
	cp->mc_slab_audit = NULL;

	lck_attr_free(cp->mc_bkt_lock_attr);
	lck_grp_free(cp->mc_bkt_lock_grp);
	lck_grp_attr_free(cp->mc_bkt_lock_grp_attr);

	lck_attr_free(cp->mc_cpu_lock_attr);
	lck_grp_free(cp->mc_cpu_lock_grp);
	lck_grp_attr_free(cp->mc_cpu_lock_grp_attr);

	lck_attr_free(cp->mc_sync_lock_attr);
	lck_grp_free(cp->mc_sync_lock_grp);
	lck_grp_attr_free(cp->mc_sync_lock_grp_attr);

	/*
	 * TODO: We need to destroy the zone here, but cannot do it
	 * because there is no such way to achieve that.  Until then
	 * the memory allocated for the zone structure is leaked.
	 * Once it is achievable, uncomment these lines:
	 *
	 *	if (cp->mc_slab_zone != NULL) {
	 *		zdestroy(cp->mc_slab_zone);
	 *		cp->mc_slab_zone = NULL;
	 *	}
	 */

	/* Get the original address since we're about to free it */
	pbuf = (void **)((intptr_t)cp - sizeof (void *));

	zfree(mcache_zone, *pbuf);
}

/*
 * Internal slab allocator used as a backend for simple caches.  The current
 * implementation uses the zone allocator for simplicity reasons.
 */
static unsigned int
mcache_slab_alloc(void *arg, mcache_obj_t ***plist, unsigned int num, int wait)
{
	mcache_t *cp = arg;
	unsigned int need = num;
	size_t offset = 0;
	size_t rsize = P2ROUNDUP(cp->mc_bufsize, sizeof (u_int64_t));
	u_int32_t flags = cp->mc_flags;
	void *buf, *base, **pbuf;
	mcache_obj_t **list = *plist;

	*list = NULL;

	/*
	 * The address of the object returned to the caller is an
	 * offset from the 64-bit aligned base address only if the
	 * cache's alignment requirement is neither 1 nor 8 bytes.
	 */
	if (cp->mc_align != 1 && cp->mc_align != sizeof (u_int64_t))
		offset = cp->mc_align;

	for (;;) {
		if (!(wait & MCR_NOSLEEP))
			buf = zalloc(cp->mc_slab_zone);
		else
			buf = zalloc_noblock(cp->mc_slab_zone);

		if (buf == NULL)
			break;

		/* Get the 64-bit aligned base address for this object */
		base = (void *)P2ROUNDUP((intptr_t)buf + sizeof (u_int64_t),
		    sizeof (u_int64_t));

		/*
		 * Wind back a pointer size from the aligned base and
		 * save the original address so we can free it later.
		 */
		pbuf = (void **)((intptr_t)base - sizeof (void *));
		*pbuf = buf;

		/*
		 * If auditing is enabled, patternize the contents of
		 * the buffer starting from the 64-bit aligned base to
		 * the end of the buffer; the length is rounded up to
		 * the nearest 64-bit multiply; this is because we use
		 * 64-bit memory access to set/check the pattern.
		 */
		if (flags & MCF_DEBUG) {
			VERIFY(((intptr_t)base + rsize) <=
			    ((intptr_t)buf + cp->mc_chunksize));
			mcache_set_pattern(MCACHE_FREE_PATTERN, base, rsize);
		}

		/*
		 * Fix up the object's address to fulfill the cache's
		 * alignment requirement (if needed) and return this
		 * to the caller.
		 */
		VERIFY(((intptr_t)base + offset + cp->mc_bufsize) <=
		    ((intptr_t)buf + cp->mc_chunksize));
		*list = (mcache_obj_t *)((intptr_t)base + offset);

		(*list)->obj_next = NULL;
		list = *plist = &(*list)->obj_next;

		/* If we got them all, return to mcache */
		if (--need == 0)
			break;
	}

	return (num - need);
}

/*
 * Internal slab deallocator used as a backend for simple caches.
 */
static void
mcache_slab_free(void *arg, mcache_obj_t *list, __unused boolean_t purged)
{
	mcache_t *cp = arg;
	mcache_obj_t *nlist;
	size_t offset = 0;
	size_t rsize = P2ROUNDUP(cp->mc_bufsize, sizeof (u_int64_t));
	u_int32_t flags = cp->mc_flags;
	void *base;
	void **pbuf;

	/*
	 * The address of the object is an offset from a 64-bit
	 * aligned base address only if the cache's alignment
	 * requirement is neither 1 nor 8 bytes.
	 */
	if (cp->mc_align != 1 && cp->mc_align != sizeof (u_int64_t))
		offset = cp->mc_align;

	for (;;) {
		nlist = list->obj_next;
		list->obj_next = NULL;

		/* Get the 64-bit aligned base address of this object */
		base = (void *)((intptr_t)list - offset);
		VERIFY(IS_P2ALIGNED(base, sizeof (u_int64_t)));

		/* Get the original address since we're about to free it */
		pbuf = (void **)((intptr_t)base - sizeof (void *));

		if (flags & MCF_DEBUG) {
			VERIFY(((intptr_t)base + rsize) <=
			    ((intptr_t)*pbuf + cp->mc_chunksize));
			mcache_audit_free_verify(NULL, base, offset, rsize);
		}

		/* Free it to zone */
		VERIFY(((intptr_t)base + offset + cp->mc_bufsize) <=
		    ((intptr_t)*pbuf + cp->mc_chunksize));
		zfree(cp->mc_slab_zone, *pbuf);

		/* No more objects to free; return to mcache */
		if ((list = nlist) == NULL)
			break;
	}
}

/*
 * Internal slab auditor for simple caches.
 */
static void
mcache_slab_audit(void *arg, mcache_obj_t *list, boolean_t alloc)
{
	mcache_t *cp = arg;
	size_t offset = 0;
	size_t rsize = P2ROUNDUP(cp->mc_bufsize, sizeof (u_int64_t));
	void *base, **pbuf;

	/*
	 * The address of the object returned to the caller is an
	 * offset from the 64-bit aligned base address only if the
	 * cache's alignment requirement is neither 1 nor 8 bytes.
	 */
	if (cp->mc_align != 1 && cp->mc_align != sizeof (u_int64_t))
		offset = cp->mc_align;

	while (list != NULL) {
		mcache_obj_t *next = list->obj_next;

		/* Get the 64-bit aligned base address of this object */
		base = (void *)((intptr_t)list - offset);
		VERIFY(IS_P2ALIGNED(base, sizeof (u_int64_t)));

		/* Get the original address */
		pbuf = (void **)((intptr_t)base - sizeof (void *));

		VERIFY(((intptr_t)base + rsize) <=
		    ((intptr_t)*pbuf + cp->mc_chunksize));

		if (!alloc)
			mcache_set_pattern(MCACHE_FREE_PATTERN, base, rsize);
		else
			mcache_audit_free_verify_set(NULL, base, offset, rsize);

		list = list->obj_next = next;
	}
}

/*
 * Refill the CPU's filled bucket with bkt and save the previous one.
 */
static void
mcache_cpu_refill(mcache_cpu_t *ccp, mcache_bkt_t *bkt, int objs)
{
	ASSERT((ccp->cc_filled == NULL && ccp->cc_objs == -1) ||
	    (ccp->cc_filled && ccp->cc_objs + objs == ccp->cc_bktsize));
	ASSERT(ccp->cc_bktsize > 0);

	ccp->cc_pfilled = ccp->cc_filled;
	ccp->cc_pobjs = ccp->cc_objs;
	ccp->cc_filled = bkt;
	ccp->cc_objs = objs;
}

/*
 * Allocate a bucket from the bucket layer.
 */
static mcache_bkt_t *
mcache_bkt_alloc(mcache_t *cp, mcache_bktlist_t *blp, mcache_bkttype_t **btp)
{
	mcache_bkt_t *bkt;

	if (!MCACHE_LOCK_TRY(&cp->mc_bkt_lock)) {
		/*
		 * The bucket layer lock is held by another CPU; increase
		 * the contention count so that we can later resize the
		 * bucket size accordingly.
		 */
		MCACHE_LOCK(&cp->mc_bkt_lock);
		cp->mc_bkt_contention++;
	}

	if ((bkt = blp->bl_list) != NULL) {
		blp->bl_list = bkt->bkt_next;
		if (--blp->bl_total < blp->bl_min)
			blp->bl_min = blp->bl_total;
		blp->bl_alloc++;
	}

	if (btp != NULL)
		*btp = cp->cache_bkttype;

	MCACHE_UNLOCK(&cp->mc_bkt_lock);

	return (bkt);
}

/*
 * Free a bucket to the bucket layer.
 */
static void
mcache_bkt_free(mcache_t *cp, mcache_bktlist_t *blp, mcache_bkt_t *bkt)
{
	MCACHE_LOCK(&cp->mc_bkt_lock);

	bkt->bkt_next = blp->bl_list;
	blp->bl_list = bkt;
	blp->bl_total++;

	MCACHE_UNLOCK(&cp->mc_bkt_lock);
}

/*
 * Enable the bucket layer of a cache.
 */
static void
mcache_cache_bkt_enable(mcache_t *cp)
{
	mcache_cpu_t *ccp;
	int cpu;

	if (cp->mc_flags & MCF_NOCPUCACHE)
		return;

	for (cpu = 0; cpu < ncpu; cpu++) {
		ccp = &cp->mc_cpu[cpu];
		MCACHE_LOCK(&ccp->cc_lock);
		ccp->cc_bktsize = cp->cache_bkttype->bt_bktsize;
		MCACHE_UNLOCK(&ccp->cc_lock);
	}
}

/*
 * Purge all buckets from a cache and disable its bucket layer.
 */
static void
mcache_bkt_purge(mcache_t *cp)
{
	mcache_cpu_t *ccp;
	mcache_bkt_t *bp, *pbp;
	mcache_bkttype_t *btp;
	int cpu, objs, pobjs;

	for (cpu = 0; cpu < ncpu; cpu++) {
		ccp = &cp->mc_cpu[cpu];

		MCACHE_LOCK(&ccp->cc_lock);

		btp = cp->cache_bkttype;
		bp = ccp->cc_filled;
		pbp = ccp->cc_pfilled;
		objs = ccp->cc_objs;
		pobjs = ccp->cc_pobjs;
		ccp->cc_filled = NULL;
		ccp->cc_pfilled = NULL;
		ccp->cc_objs = -1;
		ccp->cc_pobjs = -1;
		ccp->cc_bktsize = 0;

		MCACHE_UNLOCK(&ccp->cc_lock);

		if (bp != NULL)
			mcache_bkt_destroy(cp, btp, bp, objs);
		if (pbp != NULL)
			mcache_bkt_destroy(cp, btp, pbp, pobjs);
	}

	/*
	 * Updating the working set back to back essentially sets
	 * the working set size to zero, so everything is reapable.
	 */
	mcache_bkt_ws_update(cp);
	mcache_bkt_ws_update(cp);

	mcache_bkt_ws_reap(cp);
}

/*
 * Free one or more objects in the bucket to the slab layer,
 * and also free the bucket itself.
 */
static void
mcache_bkt_destroy(mcache_t *cp, mcache_bkttype_t *btp, mcache_bkt_t *bkt,
    int nobjs)
{
	if (nobjs > 0) {
		mcache_obj_t *top = bkt->bkt_obj[nobjs - 1];

		if (cp->mc_flags & MCF_DEBUG) {
			mcache_obj_t *o = top;
			int cnt = 0;

			/*
			 * Verify that the chain of objects in the bucket is
			 * valid.  Any mismatch here means a mistake when the
			 * object(s) were freed to the CPU layer, so we panic.
			 */
			while (o != NULL) {
				o = o->obj_next;
				++cnt;
			}
			if (cnt != nobjs) {
				panic("mcache_bkt_destroy: %s cp %p corrupted "
				    "list in bkt %p (nobjs %d actual %d)\n",
				    cp->mc_name, (void *)cp, (void *)bkt,
				    nobjs, cnt);
			}
		}

		/* Advise the slab layer to purge the object(s) */
		(*cp->mc_slab_free)(cp->mc_private, top,
		    (cp->mc_flags & MCF_DEBUG) || cp->mc_purge_cnt);
	}
	mcache_free(btp->bt_cache, bkt);
}

/*
 * Update the bucket layer working set statistics.
 */
static void
mcache_bkt_ws_update(mcache_t *cp)
{
	MCACHE_LOCK(&cp->mc_bkt_lock);

	cp->mc_full.bl_reaplimit = cp->mc_full.bl_min;
	cp->mc_full.bl_min = cp->mc_full.bl_total;
	cp->mc_empty.bl_reaplimit = cp->mc_empty.bl_min;
	cp->mc_empty.bl_min = cp->mc_empty.bl_total;

	MCACHE_UNLOCK(&cp->mc_bkt_lock);
}

/*
 * Reap all buckets that are beyond the working set.
 */
static void
mcache_bkt_ws_reap(mcache_t *cp)
{
	long reap;
	mcache_bkt_t *bkt;
	mcache_bkttype_t *btp;

	reap = MIN(cp->mc_full.bl_reaplimit, cp->mc_full.bl_min);
	while (reap-- &&
	    (bkt = mcache_bkt_alloc(cp, &cp->mc_full, &btp)) != NULL)
		mcache_bkt_destroy(cp, btp, bkt, btp->bt_bktsize);

	reap = MIN(cp->mc_empty.bl_reaplimit, cp->mc_empty.bl_min);
	while (reap-- &&
	    (bkt = mcache_bkt_alloc(cp, &cp->mc_empty, &btp)) != NULL)
		mcache_bkt_destroy(cp, btp, bkt, 0);
}

static void
mcache_reap_timeout(void *arg)
{
	volatile UInt32 *flag = arg;

	ASSERT(flag == &mcache_reaping);

	*flag = 0;
}

static void
mcache_reap_done(void *flag)
{
	timeout(mcache_reap_timeout, flag, mcache_reap_interval);
}

static void
mcache_reap_start(void *arg)
{
	UInt32 *flag = arg;

	ASSERT(flag == &mcache_reaping);

	mcache_applyall(mcache_cache_reap);
	mcache_dispatch(mcache_reap_done, flag);
}

__private_extern__ void
mcache_reap(void)
{
	UInt32 *flag = &mcache_reaping;

	if (mcache_llock_owner == current_thread() ||
	    !OSCompareAndSwap(0, 1, flag))
		return;

	mcache_dispatch(mcache_reap_start, flag);
}

static void
mcache_cache_reap(mcache_t *cp)
{
	mcache_bkt_ws_reap(cp);
}

/*
 * Performs period maintenance on a cache.
 */
static void
mcache_cache_update(mcache_t *cp)
{
	int need_bkt_resize = 0;
	int need_bkt_reenable = 0;

	lck_mtx_assert(mcache_llock, LCK_MTX_ASSERT_OWNED);

	mcache_bkt_ws_update(cp);

	/*
	 * Cache resize and post-purge reenable are mutually exclusive.
	 * If the cache was previously purged, there is no point of
	 * increasing the bucket size as there was an indication of
	 * memory pressure on the system.
	 */
	lck_mtx_lock_spin(&cp->mc_sync_lock);
	if (!(cp->mc_flags & MCF_NOCPUCACHE) && cp->mc_enable_cnt)
		need_bkt_reenable = 1;
	lck_mtx_unlock(&cp->mc_sync_lock);

	MCACHE_LOCK(&cp->mc_bkt_lock);
	/*
	 * If the contention count is greater than the threshold, and if
	 * we are not already at the maximum bucket size, increase it.
	 * Otherwise, if this cache was previously purged by the user
	 * then we simply reenable it.
	 */
	if ((unsigned int)cp->mc_chunksize < cp->cache_bkttype->bt_maxbuf &&
	    (int)(cp->mc_bkt_contention - cp->mc_bkt_contention_prev) >
	    mcache_bkt_contention && !need_bkt_reenable)
		need_bkt_resize = 1;

	cp ->mc_bkt_contention_prev = cp->mc_bkt_contention;
	MCACHE_UNLOCK(&cp->mc_bkt_lock);

	if (need_bkt_resize)
		mcache_dispatch(mcache_cache_bkt_resize, cp);
	else if (need_bkt_reenable)
		mcache_dispatch(mcache_cache_enable, cp);
}

/*
 * Recompute a cache's bucket size.  This is an expensive operation
 * and should not be done frequently; larger buckets provide for a
 * higher transfer rate with the bucket while smaller buckets reduce
 * the memory consumption.
 */
static void
mcache_cache_bkt_resize(void *arg)
{
	mcache_t *cp = arg;
	mcache_bkttype_t *btp = cp->cache_bkttype;

	if ((unsigned int)cp->mc_chunksize < btp->bt_maxbuf) {
		mcache_bkt_purge(cp);

		/*
		 * Upgrade to the next bucket type with larger bucket size;
		 * temporarily set the previous contention snapshot to a
		 * negative number to prevent unnecessary resize request.
		 */
		MCACHE_LOCK(&cp->mc_bkt_lock);
		cp->cache_bkttype = ++btp;
		cp ->mc_bkt_contention_prev = cp->mc_bkt_contention + INT_MAX;
		MCACHE_UNLOCK(&cp->mc_bkt_lock);

		mcache_cache_enable(cp);
	}
}

/*
 * Reenable a previously disabled cache due to purge.
 */
static void
mcache_cache_enable(void *arg)
{
	mcache_t *cp = arg;

	lck_mtx_lock_spin(&cp->mc_sync_lock);
	cp->mc_purge_cnt = 0;
	cp->mc_enable_cnt = 0;
	lck_mtx_unlock(&cp->mc_sync_lock);

	mcache_cache_bkt_enable(cp);
}

static void
mcache_update_timeout(__unused void *arg)
{
	timeout(mcache_update, NULL, mcache_reap_interval);
}

static void
mcache_update(__unused void *arg)
{
	mcache_applyall(mcache_cache_update);
	mcache_dispatch(mcache_update_timeout, NULL);
}

static void
mcache_applyall(void (*func)(mcache_t *))
{
	mcache_t *cp;

	MCACHE_LIST_LOCK();
	LIST_FOREACH(cp, &mcache_head, mc_list) {
		func(cp);
	}
	MCACHE_LIST_UNLOCK();
}

static void
mcache_dispatch(void (*func)(void *), void *arg)
{
	ASSERT(func != NULL);
	timeout(func, arg, hz/1000);
}

__private_extern__ void
mcache_buffer_log(mcache_audit_t *mca, void *addr, mcache_t *cp)
{
	mca->mca_addr = addr;
	mca->mca_cache = cp;
	mca->mca_pthread = mca->mca_thread;
	mca->mca_thread = current_thread();
	bcopy(mca->mca_stack, mca->mca_pstack, sizeof (mca->mca_pstack));
	mca->mca_pdepth = mca->mca_depth;
	bzero(mca->mca_stack, sizeof (mca->mca_stack));
	mca->mca_depth = OSBacktrace(mca->mca_stack, MCACHE_STACK_DEPTH);
}

__private_extern__ void
mcache_set_pattern(u_int64_t pattern, void *buf_arg, size_t size)
{
	u_int64_t *buf_end = (u_int64_t *)((void *)((char *)buf_arg + size));
	u_int64_t *buf = (u_int64_t *)buf_arg;

	VERIFY(IS_P2ALIGNED(buf_arg, sizeof (u_int64_t)));
	VERIFY(IS_P2ALIGNED(size, sizeof (u_int64_t)));

	while (buf < buf_end)
		*buf++ = pattern;
}

__private_extern__ void *
mcache_verify_pattern(u_int64_t pattern, void *buf_arg, size_t size)
{
	u_int64_t *buf_end = (u_int64_t *)((void *)((char *)buf_arg + size));
	u_int64_t *buf;

	VERIFY(IS_P2ALIGNED(buf_arg, sizeof (u_int64_t)));
	VERIFY(IS_P2ALIGNED(size, sizeof (u_int64_t)));

	for (buf = buf_arg; buf < buf_end; buf++) {
		if (*buf != pattern)
			return (buf);
	}
	return (NULL);
}

__private_extern__ void *
mcache_verify_set_pattern(u_int64_t old, u_int64_t new, void *buf_arg,
    size_t size)
{
	u_int64_t *buf_end = (u_int64_t *)((void *)((char *)buf_arg + size));
	u_int64_t *buf;

	VERIFY(IS_P2ALIGNED(buf_arg, sizeof (u_int64_t)));
	VERIFY(IS_P2ALIGNED(size, sizeof (u_int64_t)));

	for (buf = buf_arg; buf < buf_end; buf++) {
		if (*buf != old) {
			mcache_set_pattern(old, buf_arg,
			    (uintptr_t)buf - (uintptr_t)buf_arg);
			return (buf);
		}
		*buf = new;
	}
	return (NULL);
}

__private_extern__ void
mcache_audit_free_verify(mcache_audit_t *mca, void *base, size_t offset,
    size_t size)
{
	void *addr;
	u_int64_t *oaddr64;
	mcache_obj_t *next;

	addr = (void *)((uintptr_t)base + offset);
	next = ((mcache_obj_t *)addr)->obj_next;

	/* For the "obj_next" pointer in the buffer */
	oaddr64 = (u_int64_t *)P2ROUNDDOWN(addr, sizeof (u_int64_t));
	*oaddr64 = MCACHE_FREE_PATTERN;

	if ((oaddr64 = mcache_verify_pattern(MCACHE_FREE_PATTERN,
	    (caddr_t)base, size)) != NULL) {
		mcache_audit_panic(mca, addr, (caddr_t)oaddr64 - (caddr_t)base,
		    (int64_t)MCACHE_FREE_PATTERN, (int64_t)*oaddr64);
		/* NOTREACHED */
	}
	((mcache_obj_t *)addr)->obj_next = next;
}

__private_extern__ void
mcache_audit_free_verify_set(mcache_audit_t *mca, void *base, size_t offset,
    size_t size)
{
	void *addr;
	u_int64_t *oaddr64;
	mcache_obj_t *next;

	addr = (void *)((uintptr_t)base + offset);
	next = ((mcache_obj_t *)addr)->obj_next;

	/* For the "obj_next" pointer in the buffer */
	oaddr64 = (u_int64_t *)P2ROUNDDOWN(addr, sizeof (u_int64_t));
	*oaddr64 = MCACHE_FREE_PATTERN;

	if ((oaddr64 = mcache_verify_set_pattern(MCACHE_FREE_PATTERN,
	    MCACHE_UNINITIALIZED_PATTERN, (caddr_t)base, size)) != NULL) {
		mcache_audit_panic(mca, addr, (caddr_t)oaddr64 - (caddr_t)base,
		    (int64_t)MCACHE_FREE_PATTERN, (int64_t)*oaddr64);
		/* NOTREACHED */
	}
	((mcache_obj_t *)addr)->obj_next = next;
}

#undef panic

__private_extern__ char *
mcache_dump_mca(mcache_audit_t *mca)
{
	if (mca_dump_buf == NULL)
		return (NULL);

	snprintf(mca_dump_buf, DUMP_MCA_BUF_SIZE,
	    "mca %p: addr %p, cache %p (%s)\n"
	    "last transaction; thread %p, saved PC stack (%d deep):\n"
	    "\t%p, %p, %p, %p, %p, %p, %p, %p\n"
	    "\t%p, %p, %p, %p, %p, %p, %p, %p\n"
	    "previous transaction; thread %p, saved PC stack (%d deep):\n"
	    "\t%p, %p, %p, %p, %p, %p, %p, %p\n"
	    "\t%p, %p, %p, %p, %p, %p, %p, %p\n",
	    mca, mca->mca_addr, mca->mca_cache,
	    mca->mca_cache ? mca->mca_cache->mc_name : "?",
	    mca->mca_thread, mca->mca_depth,
	    mca->mca_stack[0], mca->mca_stack[1], mca->mca_stack[2],
	    mca->mca_stack[3], mca->mca_stack[4], mca->mca_stack[5],
	    mca->mca_stack[6], mca->mca_stack[7], mca->mca_stack[8],
	    mca->mca_stack[9], mca->mca_stack[10], mca->mca_stack[11],
	    mca->mca_stack[12], mca->mca_stack[13], mca->mca_stack[14],
	    mca->mca_stack[15],
	    mca->mca_pthread, mca->mca_pdepth,
	    mca->mca_pstack[0], mca->mca_pstack[1], mca->mca_pstack[2],
	    mca->mca_pstack[3], mca->mca_pstack[4], mca->mca_pstack[5],
	    mca->mca_pstack[6], mca->mca_pstack[7], mca->mca_pstack[8],
	    mca->mca_pstack[9], mca->mca_pstack[10], mca->mca_pstack[11],
	    mca->mca_pstack[12], mca->mca_pstack[13], mca->mca_pstack[14],
	    mca->mca_pstack[15]);

	return (mca_dump_buf);
}

__private_extern__ void
mcache_audit_panic(mcache_audit_t *mca, void *addr, size_t offset,
    int64_t expected, int64_t got)
{
	if (mca == NULL) {
		panic("mcache_audit: buffer %p modified after free at "
		    "offset 0x%lx (0x%llx instead of 0x%llx)\n", addr,
		    offset, got, expected);
		/* NOTREACHED */
	}

	panic("mcache_audit: buffer %p modified after free at offset 0x%lx "
	    "(0x%llx instead of 0x%llx)\n%s\n",
	    addr, offset, got, expected, mcache_dump_mca(mca));
	/* NOTREACHED */
}

__private_extern__ int
assfail(const char *a, const char *f, int l)
{
	panic("assertion failed: %s, file: %s, line: %d", a, f, l);
	return (0);
}
