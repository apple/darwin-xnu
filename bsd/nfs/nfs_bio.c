/*
 * Copyright (c) 2000-2010 Apple Inc. All rights reserved.
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
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Rick Macklem at The University of Guelph.
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
 *	@(#)nfs_bio.c	8.9 (Berkeley) 3/30/95
 * FreeBSD-Id: nfs_bio.c,v 1.44 1997/09/10 19:52:25 phk Exp $
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/resourcevar.h>
#include <sys/signalvar.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/malloc.h>
#include <sys/vnode.h>
#include <sys/dirent.h>
#include <sys/mount_internal.h>
#include <sys/kernel.h>
#include <sys/ubc_internal.h>
#include <sys/uio_internal.h>
#include <sys/kpi_mbuf.h>

#include <sys/vm.h>
#include <sys/vmparam.h>

#include <sys/time.h>
#include <kern/clock.h>
#include <libkern/OSAtomic.h>
#include <kern/kalloc.h>
#include <kern/thread_call.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfs_gss.h>
#include <nfs/nfsmount.h>
#include <nfs/nfsnode.h>
#include <sys/buf_internal.h>
#include <libkern/OSAtomic.h>

kern_return_t	thread_terminate(thread_t); /* XXX */

#define	NFSBUFHASH(np, lbn)	\
	(&nfsbufhashtbl[((long)(np) / sizeof(*(np)) + (int)(lbn)) & nfsbufhash])
LIST_HEAD(nfsbufhashhead, nfsbuf) *nfsbufhashtbl;
struct nfsbuffreehead nfsbuffree, nfsbuffreemeta, nfsbufdelwri;
u_long nfsbufhash;
int nfsbufcnt, nfsbufmin, nfsbufmax, nfsbufmetacnt, nfsbufmetamax;
int nfsbuffreecnt, nfsbuffreemetacnt, nfsbufdelwricnt, nfsneedbuffer;
int nfs_nbdwrite;
int nfs_buf_timer_on = 0;
thread_t nfsbufdelwrithd = NULL;

lck_grp_t *nfs_buf_lck_grp;
lck_mtx_t *nfs_buf_mutex;

#define NFSBUF_FREE_PERIOD	30	/* seconds */
#define NFSBUF_LRU_STALE	120
#define NFSBUF_META_STALE	240

/* number of nfsbufs nfs_buf_freeup() should attempt to free from nfsbuffree list */
#define LRU_TO_FREEUP			6
/* number of nfsbufs nfs_buf_freeup() should attempt to free from nfsbuffreemeta list */
#define META_TO_FREEUP			3
/* total number of nfsbufs nfs_buf_freeup() should attempt to free */
#define TOTAL_TO_FREEUP			(LRU_TO_FREEUP+META_TO_FREEUP)
/* fraction of nfsbufs nfs_buf_freeup() should attempt to free from nfsbuffree list when called from timer */
#define LRU_FREEUP_FRAC_ON_TIMER	8
/* fraction of nfsbufs nfs_buf_freeup() should attempt to free from nfsbuffreemeta list when called from timer */
#define META_FREEUP_FRAC_ON_TIMER	16
/* fraction of total nfsbufs that nfsbuffreecnt should exceed before bothering to call nfs_buf_freeup() */
#define LRU_FREEUP_MIN_FRAC		4
/* fraction of total nfsbufs that nfsbuffreemetacnt should exceed before bothering to call nfs_buf_freeup() */
#define META_FREEUP_MIN_FRAC		2

#define NFS_BUF_FREEUP() \
	do { \
		/* only call nfs_buf_freeup() if it has work to do: */ \
		if (((nfsbuffreecnt > nfsbufcnt/LRU_FREEUP_MIN_FRAC) || \
		     (nfsbuffreemetacnt > nfsbufcnt/META_FREEUP_MIN_FRAC)) && \
		    ((nfsbufcnt - TOTAL_TO_FREEUP) > nfsbufmin)) \
			nfs_buf_freeup(0); \
	} while (0)

/*
 * Initialize nfsbuf lists
 */
void
nfs_nbinit(void)
{
	nfs_buf_lck_grp = lck_grp_alloc_init("nfs_buf", LCK_GRP_ATTR_NULL);
	nfs_buf_mutex = lck_mtx_alloc_init(nfs_buf_lck_grp, LCK_ATTR_NULL);

	nfsbufcnt = nfsbufmetacnt =
	nfsbuffreecnt = nfsbuffreemetacnt = nfsbufdelwricnt = 0;
	nfsbufmin = 128;
	/* size nfsbufmax to cover at most half sane_size (w/default buf size) */
	nfsbufmax = (sane_size >> PAGE_SHIFT) / (2 * (NFS_RWSIZE >> PAGE_SHIFT));
	nfsbufmetamax = nfsbufmax / 4;
	nfsneedbuffer = 0;
	nfs_nbdwrite = 0;

	nfsbufhashtbl = hashinit(nfsbufmax/4, M_TEMP, &nfsbufhash);
	TAILQ_INIT(&nfsbuffree);
	TAILQ_INIT(&nfsbuffreemeta);
	TAILQ_INIT(&nfsbufdelwri);

}

/*
 * Check periodically for stale/unused nfs bufs
 */
void
nfs_buf_timer(__unused void *param0, __unused void *param1)
{
	nfs_buf_freeup(1);

	lck_mtx_lock(nfs_buf_mutex);
	if (nfsbufcnt <= nfsbufmin) {
		nfs_buf_timer_on = 0;
		lck_mtx_unlock(nfs_buf_mutex);
		return;
	}
	lck_mtx_unlock(nfs_buf_mutex);

	nfs_interval_timer_start(nfs_buf_timer_call,
		NFSBUF_FREE_PERIOD * 1000);
}

/*
 * try to free up some excess, unused nfsbufs
 */
void
nfs_buf_freeup(int timer)
{
	struct nfsbuf *fbp;
	struct timeval now;
	int count;
	struct nfsbuffreehead nfsbuffreeup;

	TAILQ_INIT(&nfsbuffreeup);

	lck_mtx_lock(nfs_buf_mutex);

	microuptime(&now);

	FSDBG(320, nfsbufcnt, nfsbuffreecnt, nfsbuffreemetacnt, 0);

	count = timer ? nfsbuffreecnt/LRU_FREEUP_FRAC_ON_TIMER : LRU_TO_FREEUP;
	while ((nfsbufcnt > nfsbufmin) && (count-- > 0)) {
		fbp = TAILQ_FIRST(&nfsbuffree);
		if (!fbp)
			break;
		if (fbp->nb_refs)
			break;
		if (NBUFSTAMPVALID(fbp) &&
		    (fbp->nb_timestamp + (2*NFSBUF_LRU_STALE)) > now.tv_sec)
			break;
		nfs_buf_remfree(fbp);
		/* disassociate buffer from any nfsnode */
		if (fbp->nb_np) {
			if (fbp->nb_vnbufs.le_next != NFSNOLIST) {
				LIST_REMOVE(fbp, nb_vnbufs);
				fbp->nb_vnbufs.le_next = NFSNOLIST;
			}
			fbp->nb_np = NULL;
		}
		LIST_REMOVE(fbp, nb_hash);
		TAILQ_INSERT_TAIL(&nfsbuffreeup, fbp, nb_free);
		nfsbufcnt--;
	}

	count = timer ? nfsbuffreemetacnt/META_FREEUP_FRAC_ON_TIMER : META_TO_FREEUP;
	while ((nfsbufcnt > nfsbufmin) && (count-- > 0)) {
		fbp = TAILQ_FIRST(&nfsbuffreemeta);
		if (!fbp)
			break;
		if (fbp->nb_refs)
			break;
		if (NBUFSTAMPVALID(fbp) &&
		    (fbp->nb_timestamp + (2*NFSBUF_META_STALE)) > now.tv_sec)
			break;
		nfs_buf_remfree(fbp);
		/* disassociate buffer from any nfsnode */
		if (fbp->nb_np) {
			if (fbp->nb_vnbufs.le_next != NFSNOLIST) {
				LIST_REMOVE(fbp, nb_vnbufs);
				fbp->nb_vnbufs.le_next = NFSNOLIST;
			}
			fbp->nb_np = NULL;
		}
		LIST_REMOVE(fbp, nb_hash);
		TAILQ_INSERT_TAIL(&nfsbuffreeup, fbp, nb_free);
		nfsbufcnt--;
		nfsbufmetacnt--;
	}

	FSDBG(320, nfsbufcnt, nfsbuffreecnt, nfsbuffreemetacnt, 0);
	NFSBUFCNTCHK();

	lck_mtx_unlock(nfs_buf_mutex);

	while ((fbp = TAILQ_FIRST(&nfsbuffreeup))) {
		TAILQ_REMOVE(&nfsbuffreeup, fbp, nb_free);
		/* nuke any creds */
		if (IS_VALID_CRED(fbp->nb_rcred))
			kauth_cred_unref(&fbp->nb_rcred);
		if (IS_VALID_CRED(fbp->nb_wcred))
			kauth_cred_unref(&fbp->nb_wcred);
		/* if buf was NB_META, dump buffer */
		if (ISSET(fbp->nb_flags, NB_META) && fbp->nb_data)
			kfree(fbp->nb_data, fbp->nb_bufsize);
		FREE(fbp, M_TEMP);
	}

}

/*
 * remove a buffer from the freelist
 * (must be called with nfs_buf_mutex held)
 */
void
nfs_buf_remfree(struct nfsbuf *bp)
{
	if (bp->nb_free.tqe_next == NFSNOLIST)
		panic("nfsbuf not on free list");
	if (ISSET(bp->nb_flags, NB_DELWRI)) {
		nfsbufdelwricnt--;
		TAILQ_REMOVE(&nfsbufdelwri, bp, nb_free);
	} else if (ISSET(bp->nb_flags, NB_META)) {
		nfsbuffreemetacnt--;
		TAILQ_REMOVE(&nfsbuffreemeta, bp, nb_free);
	} else {
		nfsbuffreecnt--;
		TAILQ_REMOVE(&nfsbuffree, bp, nb_free);
	}
	bp->nb_free.tqe_next = NFSNOLIST;
	NFSBUFCNTCHK();
}

/*
 * check for existence of nfsbuf in cache
 */
boolean_t
nfs_buf_is_incore(nfsnode_t np, daddr64_t blkno)
{
	boolean_t rv;
	lck_mtx_lock(nfs_buf_mutex);
	if (nfs_buf_incore(np, blkno))
		rv = TRUE;
	else
		rv = FALSE;
	lck_mtx_unlock(nfs_buf_mutex);
	return (rv);
}

/*
 * return incore buffer (must be called with nfs_buf_mutex held)
 */
struct nfsbuf *
nfs_buf_incore(nfsnode_t np, daddr64_t blkno)
{
	/* Search hash chain */
	struct nfsbuf * bp = NFSBUFHASH(np, blkno)->lh_first;
	for (; bp != NULL; bp = bp->nb_hash.le_next)
		if ((bp->nb_lblkno == blkno) && (bp->nb_np == np)) {
			if (!ISSET(bp->nb_flags, NB_INVAL)) {
				FSDBG(547, bp, blkno, bp->nb_flags, bp->nb_np);
				return (bp);
			}
		}
	return (NULL);
}

/*
 * Check if it's OK to drop a page.
 *
 * Called by vnode_pager() on pageout request of non-dirty page.
 * We need to make sure that it's not part of a delayed write.
 * If it is, we can't let the VM drop it because we may need it
 * later when/if we need to write the data (again).
 */
int
nfs_buf_page_inval(vnode_t vp, off_t offset)
{
	struct nfsmount *nmp = VTONMP(vp);
	struct nfsbuf *bp;
	int error = 0;

	if (!nmp)
		return (ENXIO);

	lck_mtx_lock(nfs_buf_mutex);
	bp = nfs_buf_incore(VTONFS(vp), (daddr64_t)(offset / nmp->nm_biosize));
	if (!bp)
		goto out;
	FSDBG(325, bp, bp->nb_flags, bp->nb_dirtyoff, bp->nb_dirtyend);
	if (ISSET(bp->nb_lflags, NBL_BUSY)) {
		error = EBUSY;
		goto out;
	}
	/*
	 * If there's a dirty range in the buffer, check to
	 * see if this page intersects with the dirty range.
	 * If it does, we can't let the pager drop the page.
	 */
	if (bp->nb_dirtyend > 0) {
		int start = offset - NBOFF(bp);
		if ((bp->nb_dirtyend > start) &&
		    (bp->nb_dirtyoff < (start + PAGE_SIZE))) {
			/*
			 * Before returning the bad news, move the
			 * buffer to the start of the delwri list and
			 * give the list a push to try to flush the
			 * buffer out.
			 */
			error = EBUSY;
			nfs_buf_remfree(bp);
			TAILQ_INSERT_HEAD(&nfsbufdelwri, bp, nb_free);
			nfsbufdelwricnt++;
			nfs_buf_delwri_push(1);
		}
	}
out:
	lck_mtx_unlock(nfs_buf_mutex);
	return (error);
}

/*
 * set up the UPL for a buffer
 * (must NOT be called with nfs_buf_mutex held)
 */
int
nfs_buf_upl_setup(struct nfsbuf *bp)
{
	kern_return_t kret;
	upl_t upl;
	int upl_flags;

	if (ISSET(bp->nb_flags, NB_PAGELIST))
		return (0);

	upl_flags = UPL_PRECIOUS;
	if (!ISSET(bp->nb_flags, NB_READ)) {
		/*
		 * We're doing a "write", so we intend to modify
		 * the pages we're gathering.
		 */
		upl_flags |= UPL_WILL_MODIFY;
	}
	kret = ubc_create_upl(NFSTOV(bp->nb_np), NBOFF(bp), bp->nb_bufsize,
				&upl, NULL, upl_flags);
	if (kret == KERN_INVALID_ARGUMENT) {
		/* vm object probably doesn't exist any more */
		bp->nb_pagelist = NULL;
		return (EINVAL);
	}
	if (kret != KERN_SUCCESS) {
		printf("nfs_buf_upl_setup(): failed to get pagelist %d\n", kret);
		bp->nb_pagelist = NULL;
		return (EIO);
	}

	FSDBG(538, bp, NBOFF(bp), bp->nb_bufsize, bp->nb_np);

	bp->nb_pagelist = upl;
	SET(bp->nb_flags, NB_PAGELIST);
	return (0);
}

/*
 * update buffer's valid/dirty info from UBC
 * (must NOT be called with nfs_buf_mutex held)
 */
void
nfs_buf_upl_check(struct nfsbuf *bp)
{
	upl_page_info_t *pl;
	off_t filesize, fileoffset;
	int i, npages;

	if (!ISSET(bp->nb_flags, NB_PAGELIST))
		return;

	npages = round_page_32(bp->nb_bufsize) / PAGE_SIZE;
	filesize = ubc_getsize(NFSTOV(bp->nb_np));
	fileoffset = NBOFF(bp);
	if (fileoffset < filesize)
		SET(bp->nb_flags, NB_CACHE);
	else
		CLR(bp->nb_flags, NB_CACHE);

	pl = ubc_upl_pageinfo(bp->nb_pagelist);
	bp->nb_valid = bp->nb_dirty = 0;

	for (i=0; i < npages; i++, fileoffset += PAGE_SIZE_64) {
		/* anything beyond the end of the file is not valid or dirty */
		if (fileoffset >= filesize)
			break;
		if (!upl_valid_page(pl, i)) {
			CLR(bp->nb_flags, NB_CACHE);
			continue;
		}
		NBPGVALID_SET(bp,i);
		if (upl_dirty_page(pl, i))
			NBPGDIRTY_SET(bp, i);
	}
	fileoffset = NBOFF(bp);
	if (ISSET(bp->nb_flags, NB_CACHE)) {
		bp->nb_validoff = 0;
		bp->nb_validend = bp->nb_bufsize;
		if (fileoffset + bp->nb_validend > filesize)
			bp->nb_validend = filesize - fileoffset;
	} else {
		bp->nb_validoff = bp->nb_validend = -1;
	}
	FSDBG(539, bp, fileoffset, bp->nb_valid, bp->nb_dirty);
	FSDBG(539, bp->nb_validoff, bp->nb_validend, bp->nb_dirtyoff, bp->nb_dirtyend);
}

/*
 * make sure that a buffer is mapped
 * (must NOT be called with nfs_buf_mutex held)
 */
int
nfs_buf_map(struct nfsbuf *bp)
{
	kern_return_t kret;

	if (bp->nb_data)
		return (0);
	if (!ISSET(bp->nb_flags, NB_PAGELIST))
		return (EINVAL);

	kret = ubc_upl_map(bp->nb_pagelist, (vm_offset_t *)&(bp->nb_data));
	if (kret != KERN_SUCCESS)
		panic("nfs_buf_map: ubc_upl_map() failed with (%d)", kret);
	if (bp->nb_data == 0)
		panic("ubc_upl_map mapped 0");
	FSDBG(540, bp, bp->nb_flags, NBOFF(bp), bp->nb_data);
	return (0);
}

/*
 * normalize an nfsbuf's valid range
 *
 * the read/write code guarantees that we'll always have a valid
 * region that is an integral number of pages.  If either end
 * of the valid range isn't page-aligned, it gets corrected
 * here as we extend the valid range through all of the
 * contiguous valid pages.
 */
void
nfs_buf_normalize_valid_range(nfsnode_t np, struct nfsbuf *bp)
{
	int pg, npg;
	/* pull validoff back to start of contiguous valid page range */
	pg = bp->nb_validoff/PAGE_SIZE;
	while (pg >= 0 && NBPGVALID(bp,pg))
		pg--;
	bp->nb_validoff = (pg+1) * PAGE_SIZE;
	/* push validend forward to end of contiguous valid page range */
	npg = bp->nb_bufsize/PAGE_SIZE;
	pg = bp->nb_validend/PAGE_SIZE;
	while (pg < npg && NBPGVALID(bp,pg))
		pg++;
	bp->nb_validend = pg * PAGE_SIZE;
	/* clip to EOF */
	if (NBOFF(bp) + bp->nb_validend > (off_t)np->n_size)
		bp->nb_validend = np->n_size % bp->nb_bufsize;
}

/*
 * process some entries on the delayed write queue
 * (must be called with nfs_buf_mutex held)
 */
void
nfs_buf_delwri_service(void)
{
	struct nfsbuf *bp;
	nfsnode_t np;
	int error, i = 0;

	while (i < 8 && (bp = TAILQ_FIRST(&nfsbufdelwri)) != NULL) {
		np = bp->nb_np;
		nfs_buf_remfree(bp);
		nfs_buf_refget(bp);
		while ((error = nfs_buf_acquire(bp, 0, 0, 0)) == EAGAIN);
		nfs_buf_refrele(bp);
		if (error)
			break;
		if (!bp->nb_np) {
			/* buffer is no longer valid */
			nfs_buf_drop(bp);
			continue;
		}
		if (ISSET(bp->nb_flags, NB_NEEDCOMMIT))
			nfs_buf_check_write_verifier(np, bp);
		if (ISSET(bp->nb_flags, NB_NEEDCOMMIT)) {
			/* put buffer at end of delwri list */
			TAILQ_INSERT_TAIL(&nfsbufdelwri, bp, nb_free);
			nfsbufdelwricnt++;
			nfs_buf_drop(bp);
			lck_mtx_unlock(nfs_buf_mutex);
			nfs_flushcommits(np, 1);
		} else {
			SET(bp->nb_flags, NB_ASYNC);
			lck_mtx_unlock(nfs_buf_mutex);
			nfs_buf_write(bp);
		}
		i++;
		lck_mtx_lock(nfs_buf_mutex);
	}
}

/*
 * thread to service the delayed write queue when asked
 */
void
nfs_buf_delwri_thread(__unused void *arg, __unused wait_result_t wr)
{
	struct timespec ts = { 30, 0 };
	int error = 0;

	lck_mtx_lock(nfs_buf_mutex);
	while (!error) {
		nfs_buf_delwri_service();
		error = msleep(&nfsbufdelwrithd, nfs_buf_mutex, 0, "nfsbufdelwri", &ts);
	}
	nfsbufdelwrithd = NULL;
	lck_mtx_unlock(nfs_buf_mutex);
	thread_terminate(nfsbufdelwrithd);
}

/*
 * try to push out some delayed/uncommitted writes
 * ("locked" indicates whether nfs_buf_mutex is already held)
 */
void
nfs_buf_delwri_push(int locked)
{
	if (TAILQ_EMPTY(&nfsbufdelwri))
		return;
	if (!locked)
		lck_mtx_lock(nfs_buf_mutex);
	/* wake up the delayed write service thread */
	if (nfsbufdelwrithd)
		wakeup(&nfsbufdelwrithd);
	else if (kernel_thread_start(nfs_buf_delwri_thread, NULL, &nfsbufdelwrithd) == KERN_SUCCESS)
		thread_deallocate(nfsbufdelwrithd);
	/* otherwise, try to do some of the work ourselves */
	if (!nfsbufdelwrithd)
		nfs_buf_delwri_service();
	if (!locked)
		lck_mtx_unlock(nfs_buf_mutex);
}

/*
 * Get an nfs buffer.
 *
 * Returns errno on error, 0 otherwise.
 * Any buffer is returned in *bpp.
 *
 * If NBLK_ONLYVALID is set, only return buffer if found in cache.
 * If NBLK_NOWAIT is set, don't wait for the buffer if it's marked BUSY.
 *
 * Check for existence of buffer in cache.
 * Or attempt to reuse a buffer from one of the free lists.
 * Or allocate a new buffer if we haven't already hit max allocation.
 * Or wait for a free buffer.
 *
 * If available buffer found, prepare it, and return it.
 *
 * If the calling process is interrupted by a signal for
 * an interruptible mount point, return EINTR.
 */
int
nfs_buf_get(
	nfsnode_t np,
	daddr64_t blkno,
	uint32_t size,
	thread_t thd,
	int flags,
	struct nfsbuf **bpp)
{
	vnode_t vp = NFSTOV(np);
	struct nfsmount *nmp = VTONMP(vp);
	struct nfsbuf *bp;
	uint32_t bufsize;
	int slpflag = PCATCH;
	int operation = (flags & NBLK_OPMASK);
	int error = 0;
	struct timespec ts;

	FSDBG_TOP(541, np, blkno, size, flags);
	*bpp = NULL;

	bufsize = size;
	if (bufsize > NFS_MAXBSIZE)
		panic("nfs_buf_get: buffer larger than NFS_MAXBSIZE requested");

	if (!nmp) {
		FSDBG_BOT(541, np, blkno, 0, ENXIO);
		return (ENXIO);
	}

	if (!UBCINFOEXISTS(vp)) {
		operation = NBLK_META;
	} else if (bufsize < (uint32_t)nmp->nm_biosize) {
		/* reg files should always have biosize blocks */
		bufsize = nmp->nm_biosize;
	}

	/* if NBLK_WRITE, check for too many delayed/uncommitted writes */
	if ((operation == NBLK_WRITE) && (nfs_nbdwrite > NFS_A_LOT_OF_DELAYED_WRITES)) {
		FSDBG_TOP(542, np, blkno, nfs_nbdwrite, NFS_A_LOT_OF_DELAYED_WRITES);

		/* poke the delwri list */
		nfs_buf_delwri_push(0);

		/* sleep to let other threads run... */
		tsleep(&nfs_nbdwrite, PCATCH, "nfs_nbdwrite", 1);
		FSDBG_BOT(542, np, blkno, nfs_nbdwrite, NFS_A_LOT_OF_DELAYED_WRITES);
	}

loop:
	lck_mtx_lock(nfs_buf_mutex);

	/* wait for any buffer invalidation/flushing to complete */
	while (np->n_bflag & NBINVALINPROG) {
		np->n_bflag |= NBINVALWANT;
		ts.tv_sec = 2;
		ts.tv_nsec = 0;
		msleep(&np->n_bflag, nfs_buf_mutex, slpflag, "nfs_buf_get_invalwait", &ts);
		if ((error = nfs_sigintr(VTONMP(vp), NULL, thd, 0))) {
			lck_mtx_unlock(nfs_buf_mutex);
			FSDBG_BOT(541, np, blkno, 0, error);
			return (error);
		}
		if (np->n_bflag & NBINVALINPROG)
			slpflag = 0;
	}

	/* check for existence of nfsbuf in cache */
	if ((bp = nfs_buf_incore(np, blkno))) {
		/* if busy, set wanted and wait */
		if (ISSET(bp->nb_lflags, NBL_BUSY)) {
			if (flags & NBLK_NOWAIT) {
				lck_mtx_unlock(nfs_buf_mutex);
				FSDBG_BOT(541, np, blkno, bp, 0xbcbcbcbc);
				return (0);
			}
			FSDBG_TOP(543, np, blkno, bp, bp->nb_flags);
			SET(bp->nb_lflags, NBL_WANTED);

			ts.tv_sec = 2;
			ts.tv_nsec = 0;
			msleep(bp, nfs_buf_mutex, slpflag|(PRIBIO+1)|PDROP,
					"nfsbufget", (slpflag == PCATCH) ? NULL : &ts);
			slpflag = 0;
			FSDBG_BOT(543, np, blkno, bp, bp->nb_flags);
			if ((error = nfs_sigintr(VTONMP(vp), NULL, thd, 0))) {
				FSDBG_BOT(541, np, blkno, 0, error);
				return (error);
			}
			goto loop;
		}
		if (bp->nb_bufsize != bufsize)
			panic("nfsbuf size mismatch");
		SET(bp->nb_lflags, NBL_BUSY);
		SET(bp->nb_flags, NB_CACHE);
		nfs_buf_remfree(bp);
		/* additional paranoia: */
		if (ISSET(bp->nb_flags, NB_PAGELIST))
			panic("pagelist buffer was not busy");
		goto buffer_setup;
	}

	if (flags & NBLK_ONLYVALID) {
		lck_mtx_unlock(nfs_buf_mutex);
		FSDBG_BOT(541, np, blkno, 0, 0x0000cace);
		return (0);
	}

	/*
	 * where to get a free buffer:
	 * - if meta and maxmeta reached, must reuse meta
	 * - alloc new if we haven't reached min bufs
	 * - if free lists are NOT empty
	 *   - if free list is stale, use it
	 *   - else if freemeta list is stale, use it
	 *   - else if max bufs allocated, use least-time-to-stale
	 * - alloc new if we haven't reached max allowed
	 * - start clearing out delwri list and try again
	 */

	if ((operation == NBLK_META) && (nfsbufmetacnt >= nfsbufmetamax)) {
		/* if we've hit max meta buffers, must reuse a meta buffer */
		bp = TAILQ_FIRST(&nfsbuffreemeta);
	} else if ((nfsbufcnt > nfsbufmin) &&
	    (!TAILQ_EMPTY(&nfsbuffree) || !TAILQ_EMPTY(&nfsbuffreemeta))) {
		/* try to pull an nfsbuf off a free list */
		struct nfsbuf *lrubp, *metabp;
		struct timeval now;
		microuptime(&now);

		/* if the next LRU or META buffer is invalid or stale, use it */
		lrubp = TAILQ_FIRST(&nfsbuffree);
		if (lrubp && (!NBUFSTAMPVALID(lrubp) ||
		    ((lrubp->nb_timestamp + NFSBUF_LRU_STALE) < now.tv_sec)))
			bp = lrubp;
		metabp = TAILQ_FIRST(&nfsbuffreemeta);
		if (!bp && metabp && (!NBUFSTAMPVALID(metabp) ||
		    ((metabp->nb_timestamp + NFSBUF_META_STALE) < now.tv_sec)))
			bp = metabp;

		if (!bp && (nfsbufcnt >= nfsbufmax)) {
			/* we've already allocated all bufs, so */
			/* choose the buffer that'll go stale first */
			if (!metabp)
				bp = lrubp;
			else if (!lrubp)
				bp = metabp;
			else {
				int32_t lru_stale_time, meta_stale_time;
				lru_stale_time = lrubp->nb_timestamp + NFSBUF_LRU_STALE;
				meta_stale_time = metabp->nb_timestamp + NFSBUF_META_STALE;
				if (lru_stale_time <= meta_stale_time)
					bp = lrubp;
				else
					bp = metabp;
			}
		}
	}

	if (bp) {
		/* we have a buffer to reuse */
		FSDBG(544, np, blkno, bp, bp->nb_flags);
		nfs_buf_remfree(bp);
		if (ISSET(bp->nb_flags, NB_DELWRI))
			panic("nfs_buf_get: delwri");
		SET(bp->nb_lflags, NBL_BUSY);
		/* disassociate buffer from previous nfsnode */
		if (bp->nb_np) {
			if (bp->nb_vnbufs.le_next != NFSNOLIST) {
				LIST_REMOVE(bp, nb_vnbufs);
				bp->nb_vnbufs.le_next = NFSNOLIST;
			}
			bp->nb_np = NULL;
		}
		LIST_REMOVE(bp, nb_hash);
		/* nuke any creds we're holding */
		if (IS_VALID_CRED(bp->nb_rcred))
			kauth_cred_unref(&bp->nb_rcred);
		if (IS_VALID_CRED(bp->nb_wcred))
			kauth_cred_unref(&bp->nb_wcred);
		/* if buf will no longer be NB_META, dump old buffer */
		if (operation == NBLK_META) {
			if (!ISSET(bp->nb_flags, NB_META))
				nfsbufmetacnt++;
		} else if (ISSET(bp->nb_flags, NB_META)) {
			if (bp->nb_data) {
				kfree(bp->nb_data, bp->nb_bufsize);
				bp->nb_data = NULL;
			}
			nfsbufmetacnt--;
		}
		/* re-init buf fields */
		bp->nb_error = 0;
		bp->nb_validoff = bp->nb_validend = -1;
		bp->nb_dirtyoff = bp->nb_dirtyend = 0;
		bp->nb_valid = 0;
		bp->nb_dirty = 0;
		bp->nb_verf = 0;
	} else {
		/* no buffer to reuse */
		if ((nfsbufcnt < nfsbufmax) &&
		    ((operation != NBLK_META) || (nfsbufmetacnt < nfsbufmetamax))) {
			/* just alloc a new one */
			MALLOC(bp, struct nfsbuf *, sizeof(struct nfsbuf), M_TEMP, M_WAITOK);
			if (!bp) {
				lck_mtx_unlock(nfs_buf_mutex);
				FSDBG_BOT(541, np, blkno, 0, error);
				return (ENOMEM);
			}
			nfsbufcnt++;

			/*
			 * If any excess bufs, make sure the timer
			 * is running to free them up later.
			 */
			if (nfsbufcnt > nfsbufmin && !nfs_buf_timer_on) {
				nfs_buf_timer_on = 1;
				nfs_interval_timer_start(nfs_buf_timer_call,
					NFSBUF_FREE_PERIOD * 1000);
			}

			if (operation == NBLK_META)
				nfsbufmetacnt++;
			NFSBUFCNTCHK();
			/* init nfsbuf */
			bzero(bp, sizeof(*bp));
			bp->nb_free.tqe_next = NFSNOLIST;
			bp->nb_validoff = bp->nb_validend = -1;
			FSDBG(545, np, blkno, bp, 0);
		} else {
			/* too many bufs... wait for buffers to free up */
			FSDBG_TOP(546, np, blkno, nfsbufcnt, nfsbufmax);

			/* poke the delwri list */
			nfs_buf_delwri_push(1);

			nfsneedbuffer = 1;
			msleep(&nfsneedbuffer, nfs_buf_mutex, PCATCH|PDROP, "nfsbufget", NULL);
			FSDBG_BOT(546, np, blkno, nfsbufcnt, nfsbufmax);
			if ((error = nfs_sigintr(VTONMP(vp), NULL, thd, 0))) {
				FSDBG_BOT(541, np, blkno, 0, error);
				return (error);
			}
			goto loop;
		}
	}

	/* set up nfsbuf */
	SET(bp->nb_lflags, NBL_BUSY);
	bp->nb_flags = 0;
	bp->nb_lblkno = blkno;
	/* insert buf in hash */
	LIST_INSERT_HEAD(NFSBUFHASH(np, blkno), bp, nb_hash);
	/* associate buffer with new nfsnode */
	bp->nb_np = np;
	LIST_INSERT_HEAD(&np->n_cleanblkhd, bp, nb_vnbufs);

buffer_setup:

	/* unlock hash */
	lck_mtx_unlock(nfs_buf_mutex);

	switch (operation) {
	case NBLK_META:
		SET(bp->nb_flags, NB_META);
		if ((bp->nb_bufsize != bufsize) && bp->nb_data) {
			kfree(bp->nb_data, bp->nb_bufsize);
			bp->nb_data = NULL;
			bp->nb_validoff = bp->nb_validend = -1;
			bp->nb_dirtyoff = bp->nb_dirtyend = 0;
			bp->nb_valid = 0;
			bp->nb_dirty = 0;
			CLR(bp->nb_flags, NB_CACHE);
		}
		if (!bp->nb_data)
			bp->nb_data = kalloc(bufsize);
		if (!bp->nb_data) {
			/* Ack! couldn't allocate the data buffer! */
			/* clean up buffer and return error */
			lck_mtx_lock(nfs_buf_mutex);
			LIST_REMOVE(bp, nb_vnbufs);
			bp->nb_vnbufs.le_next = NFSNOLIST;
			bp->nb_np = NULL;
			/* invalidate usage timestamp to allow immediate freeing */
			NBUFSTAMPINVALIDATE(bp);
			if (bp->nb_free.tqe_next != NFSNOLIST)
				panic("nfsbuf on freelist");
			TAILQ_INSERT_HEAD(&nfsbuffree, bp, nb_free);
			nfsbuffreecnt++;
			lck_mtx_unlock(nfs_buf_mutex);
			FSDBG_BOT(541, np, blkno, 0xb00, ENOMEM);
			return (ENOMEM);
		}
		bp->nb_bufsize = bufsize;
		break;

	case NBLK_READ:
	case NBLK_WRITE:
		/*
		 * Set or clear NB_READ now to let the UPL subsystem know
		 * if we intend to modify the pages or not.
		 */
		if (operation == NBLK_READ) {
			SET(bp->nb_flags, NB_READ);
		} else {
			CLR(bp->nb_flags, NB_READ);
		}
		if (bufsize < PAGE_SIZE)
			bufsize = PAGE_SIZE;
		bp->nb_bufsize = bufsize;
		bp->nb_validoff = bp->nb_validend = -1;

		if (UBCINFOEXISTS(vp)) {
			/* set up upl */
			if (nfs_buf_upl_setup(bp)) {
				/* unable to create upl */
				/* vm object must no longer exist */
				/* clean up buffer and return error */
				lck_mtx_lock(nfs_buf_mutex);
				LIST_REMOVE(bp, nb_vnbufs);
				bp->nb_vnbufs.le_next = NFSNOLIST;
				bp->nb_np = NULL;
				/* invalidate usage timestamp to allow immediate freeing */
				NBUFSTAMPINVALIDATE(bp);
				if (bp->nb_free.tqe_next != NFSNOLIST)
					panic("nfsbuf on freelist");
				TAILQ_INSERT_HEAD(&nfsbuffree, bp, nb_free);
				nfsbuffreecnt++;
				lck_mtx_unlock(nfs_buf_mutex);
				FSDBG_BOT(541, np, blkno, 0x2bc, EIO);
				return (EIO);
			}
			nfs_buf_upl_check(bp);
		}
		break;

	default:
		panic("nfs_buf_get: %d unknown operation", operation);
	}

	*bpp = bp;

	FSDBG_BOT(541, np, blkno, bp, bp->nb_flags);

	return (0);
}

void
nfs_buf_release(struct nfsbuf *bp, int freeup)
{
	nfsnode_t np = bp->nb_np;
	vnode_t vp;
	struct timeval now;
	int wakeup_needbuffer, wakeup_buffer, wakeup_nbdwrite;

	FSDBG_TOP(548, bp, NBOFF(bp), bp->nb_flags, bp->nb_data);
	FSDBG(548, bp->nb_validoff, bp->nb_validend, bp->nb_dirtyoff, bp->nb_dirtyend);
	FSDBG(548, bp->nb_valid, 0, bp->nb_dirty, 0);

	vp = np ? NFSTOV(np) : NULL;
	if (vp && UBCINFOEXISTS(vp) && bp->nb_bufsize) {
		int upl_flags, rv;
		upl_t upl;
		uint32_t i;

		if (!ISSET(bp->nb_flags, NB_PAGELIST) && !ISSET(bp->nb_flags, NB_INVAL)) {
			rv = nfs_buf_upl_setup(bp);
			if (rv)
				printf("nfs_buf_release: upl create failed %d\n", rv);
			else
				nfs_buf_upl_check(bp);
		}
		upl = bp->nb_pagelist;
		if (!upl)
			goto pagelist_cleanup_done;
		if (bp->nb_data) {
			if (ubc_upl_unmap(upl) != KERN_SUCCESS)
				panic("ubc_upl_unmap failed");
			bp->nb_data = NULL;
		}
		/*
		 * Abort the pages on error or: if this is an invalid or
		 * non-needcommit nocache buffer AND no pages are dirty.
		 */
		if (ISSET(bp->nb_flags, NB_ERROR) || (!bp->nb_dirty && (ISSET(bp->nb_flags, NB_INVAL) ||
		    (ISSET(bp->nb_flags, NB_NOCACHE) && !ISSET(bp->nb_flags, (NB_NEEDCOMMIT | NB_DELWRI)))))) {
			if (ISSET(bp->nb_flags, (NB_READ | NB_INVAL | NB_NOCACHE)))
				upl_flags = UPL_ABORT_DUMP_PAGES;
			else
				upl_flags = 0;
			ubc_upl_abort(upl, upl_flags);
			goto pagelist_cleanup_done;
		}
		for (i=0; i <= (bp->nb_bufsize - 1)/PAGE_SIZE; i++) {
			if (!NBPGVALID(bp,i))
				ubc_upl_abort_range(upl,
					i*PAGE_SIZE, PAGE_SIZE,
					UPL_ABORT_DUMP_PAGES |
					UPL_ABORT_FREE_ON_EMPTY);
			else {
				if (NBPGDIRTY(bp,i))
					upl_flags = UPL_COMMIT_SET_DIRTY;
				else
					upl_flags = UPL_COMMIT_CLEAR_DIRTY;
				
				if (!ISSET(bp->nb_flags, (NB_NEEDCOMMIT | NB_DELWRI)))
					upl_flags |= UPL_COMMIT_CLEAR_PRECIOUS;

				ubc_upl_commit_range(upl,
					i*PAGE_SIZE, PAGE_SIZE,
					upl_flags |
					UPL_COMMIT_INACTIVATE |
					UPL_COMMIT_FREE_ON_EMPTY);
			}
		}
pagelist_cleanup_done:
		/* invalidate any pages past EOF */
		if (NBOFF(bp) + bp->nb_bufsize > (off_t)(np->n_size)) {
			off_t start, end;
			start = trunc_page_64(np->n_size) + PAGE_SIZE_64;
			end = trunc_page_64(NBOFF(bp) + bp->nb_bufsize);
			if (start < NBOFF(bp))
				start = NBOFF(bp);
			if (end > start) {
				if ((rv = ubc_msync(vp, start, end, NULL, UBC_INVALIDATE)))
					printf("nfs_buf_release(): ubc_msync failed!, error %d\n", rv);
			}
		}
		CLR(bp->nb_flags, NB_PAGELIST);
		bp->nb_pagelist = NULL;
	}

	lck_mtx_lock(nfs_buf_mutex);

	wakeup_needbuffer = wakeup_buffer = wakeup_nbdwrite = 0;

	/* Wake up any processes waiting for any buffer to become free. */
	if (nfsneedbuffer) {
		nfsneedbuffer = 0;
		wakeup_needbuffer = 1;
	}
	/* Wake up any processes waiting for _this_ buffer to become free. */
	if (ISSET(bp->nb_lflags, NBL_WANTED)) {
		CLR(bp->nb_lflags, NBL_WANTED);
		wakeup_buffer = 1;
	}

	/* If it's non-needcommit nocache, or an error, mark it invalid. */
	if (ISSET(bp->nb_flags, NB_ERROR) ||
	    (ISSET(bp->nb_flags, NB_NOCACHE) && !ISSET(bp->nb_flags, (NB_NEEDCOMMIT | NB_DELWRI))))
		SET(bp->nb_flags, NB_INVAL);

	if ((bp->nb_bufsize <= 0) || ISSET(bp->nb_flags, NB_INVAL)) {
		/* If it's invalid or empty, dissociate it from its nfsnode */
		if (bp->nb_vnbufs.le_next != NFSNOLIST) {
			LIST_REMOVE(bp, nb_vnbufs);
			bp->nb_vnbufs.le_next = NFSNOLIST;
		}
		bp->nb_np = NULL;
		/* if this was a delayed write, wakeup anyone */
		/* waiting for delayed writes to complete */
		if (ISSET(bp->nb_flags, NB_DELWRI)) {
			CLR(bp->nb_flags, NB_DELWRI);
			nfs_nbdwrite--;
			NFSBUFCNTCHK();
			wakeup_nbdwrite = 1;
		}
		/* invalidate usage timestamp to allow immediate freeing */
		NBUFSTAMPINVALIDATE(bp);
		/* put buffer at head of free list */
		if (bp->nb_free.tqe_next != NFSNOLIST)
			panic("nfsbuf on freelist");
		SET(bp->nb_flags, NB_INVAL);
		if (ISSET(bp->nb_flags, NB_META)) {
			TAILQ_INSERT_HEAD(&nfsbuffreemeta, bp, nb_free);
			nfsbuffreemetacnt++;
		} else {
			TAILQ_INSERT_HEAD(&nfsbuffree, bp, nb_free);
			nfsbuffreecnt++;
		}
	} else if (ISSET(bp->nb_flags, NB_DELWRI)) {
		/* put buffer at end of delwri list */
		if (bp->nb_free.tqe_next != NFSNOLIST)
			panic("nfsbuf on freelist");
		TAILQ_INSERT_TAIL(&nfsbufdelwri, bp, nb_free);
		nfsbufdelwricnt++;
		freeup = 0;
	} else {
		/* update usage timestamp */
		microuptime(&now);
		bp->nb_timestamp = now.tv_sec;
		/* put buffer at end of free list */
		if (bp->nb_free.tqe_next != NFSNOLIST)
			panic("nfsbuf on freelist");
		if (ISSET(bp->nb_flags, NB_META)) {
			TAILQ_INSERT_TAIL(&nfsbuffreemeta, bp, nb_free);
			nfsbuffreemetacnt++;
		} else {
			TAILQ_INSERT_TAIL(&nfsbuffree, bp, nb_free);
			nfsbuffreecnt++;
		}
	}

	NFSBUFCNTCHK();

	/* Unlock the buffer. */
	CLR(bp->nb_flags, (NB_ASYNC | NB_STABLE));
	CLR(bp->nb_lflags, NBL_BUSY);

	FSDBG_BOT(548, bp, NBOFF(bp), bp->nb_flags, bp->nb_data);

	lck_mtx_unlock(nfs_buf_mutex);

	if (wakeup_needbuffer)
		wakeup(&nfsneedbuffer);
	if (wakeup_buffer)
		wakeup(bp);
	if (wakeup_nbdwrite)
		wakeup(&nfs_nbdwrite);
	if (freeup)
		NFS_BUF_FREEUP();
}

/*
 * Wait for operations on the buffer to complete.
 * When they do, extract and return the I/O's error value.
 */
int
nfs_buf_iowait(struct nfsbuf *bp)
{
	FSDBG_TOP(549, bp, NBOFF(bp), bp->nb_flags, bp->nb_error);

	lck_mtx_lock(nfs_buf_mutex);

	while (!ISSET(bp->nb_flags, NB_DONE))
		msleep(bp, nfs_buf_mutex, PRIBIO + 1, "nfs_buf_iowait", NULL);

	lck_mtx_unlock(nfs_buf_mutex);

	FSDBG_BOT(549, bp, NBOFF(bp), bp->nb_flags, bp->nb_error);

	/* check for interruption of I/O, then errors. */
	if (ISSET(bp->nb_flags, NB_EINTR)) {
		CLR(bp->nb_flags, NB_EINTR);
		return (EINTR);
	} else if (ISSET(bp->nb_flags, NB_ERROR))
		return (bp->nb_error ? bp->nb_error : EIO);
	return (0);
}

/*
 * Mark I/O complete on a buffer.
 */
void
nfs_buf_iodone(struct nfsbuf *bp)
{

	FSDBG_TOP(550, bp, NBOFF(bp), bp->nb_flags, bp->nb_error);

	if (ISSET(bp->nb_flags, NB_DONE))
		panic("nfs_buf_iodone already");

	if (!ISSET(bp->nb_flags, NB_READ)) {
		CLR(bp->nb_flags, NB_WRITEINPROG);
		/*
		 * vnode_writedone() takes care of waking up
		 * any throttled write operations
		 */
		vnode_writedone(NFSTOV(bp->nb_np));
		nfs_node_lock_force(bp->nb_np);
		bp->nb_np->n_numoutput--;
		nfs_node_unlock(bp->nb_np);
	}
	if (ISSET(bp->nb_flags, NB_ASYNC)) {	/* if async, release it */
		SET(bp->nb_flags, NB_DONE);		/* note that it's done */
		nfs_buf_release(bp, 1);
	} else {		                        /* or just wakeup the buffer */	
	        lck_mtx_lock(nfs_buf_mutex);
		SET(bp->nb_flags, NB_DONE);		/* note that it's done */
		CLR(bp->nb_lflags, NBL_WANTED);
	        lck_mtx_unlock(nfs_buf_mutex);
		wakeup(bp);
	}

	FSDBG_BOT(550, bp, NBOFF(bp), bp->nb_flags, bp->nb_error);
}

void
nfs_buf_write_delayed(struct nfsbuf *bp)
{
	nfsnode_t np = bp->nb_np;

	FSDBG_TOP(551, bp, NBOFF(bp), bp->nb_flags, 0);
	FSDBG(551, bp, bp->nb_dirtyoff, bp->nb_dirtyend, bp->nb_dirty);

	/*
	 * If the block hasn't been seen before:
	 *	(1) Mark it as having been seen,
	 *	(2) Make sure it's on its node's correct block list,
	 */
	if (!ISSET(bp->nb_flags, NB_DELWRI)) {
		SET(bp->nb_flags, NB_DELWRI);
		/* move to dirty list */
		lck_mtx_lock(nfs_buf_mutex);
		nfs_nbdwrite++;
		NFSBUFCNTCHK();
		if (bp->nb_vnbufs.le_next != NFSNOLIST)
			LIST_REMOVE(bp, nb_vnbufs);
		LIST_INSERT_HEAD(&np->n_dirtyblkhd, bp, nb_vnbufs);
		lck_mtx_unlock(nfs_buf_mutex);
	}

	/*
	 * If the vnode has "too many" write operations in progress
	 * wait for them to finish the IO
	 */
	vnode_waitforwrites(NFSTOV(np), VNODE_ASYNC_THROTTLE, 0, 0, "nfs_buf_write_delayed");

	/* the file is in a modified state, so make sure the flag's set */
	nfs_node_lock_force(np);
	np->n_flag |= NMODIFIED;
	nfs_node_unlock(np);

	/*
	 * If we have too many delayed write buffers,
	 * just fall back to doing the async write.
	 */
	if (nfs_nbdwrite < 0)
		panic("nfs_buf_write_delayed: Negative nfs_nbdwrite");
	if (nfs_nbdwrite > NFS_A_LOT_OF_DELAYED_WRITES) {
		/* issue async write */
		SET(bp->nb_flags, NB_ASYNC);
		nfs_buf_write(bp);
		FSDBG_BOT(551, bp, NBOFF(bp), bp->nb_flags, bp->nb_error);
		return;
	}

	/* Otherwise, the "write" is done, so mark and release the buffer. */
	SET(bp->nb_flags, NB_DONE);
	nfs_buf_release(bp, 1);
	FSDBG_BOT(551, bp, NBOFF(bp), bp->nb_flags, 0);
	return;
}

/*
 * Check that a "needcommit" buffer can still be committed.
 * If the write verifier has changed, we need to clear the
 * the needcommit flag.
 */
void
nfs_buf_check_write_verifier(nfsnode_t np, struct nfsbuf *bp)
{
	struct nfsmount *nmp;

	if (!ISSET(bp->nb_flags, NB_NEEDCOMMIT))
		return;

	nmp = NFSTONMP(np);
	if (!nmp)
		return;
	if (!ISSET(bp->nb_flags, NB_STALEWVERF) && (bp->nb_verf == nmp->nm_verf))
		return;

	/* write verifier changed, clear commit/wverf flags */
	CLR(bp->nb_flags, (NB_NEEDCOMMIT | NB_STALEWVERF));
	bp->nb_verf = 0;
	nfs_node_lock_force(np);
	np->n_needcommitcnt--;
	CHECK_NEEDCOMMITCNT(np);
	nfs_node_unlock(np);
}

/*
 * add a reference to a buffer so it doesn't disappear while being used
 * (must be called with nfs_buf_mutex held)
 */
void
nfs_buf_refget(struct nfsbuf *bp)
{
	bp->nb_refs++;
}
/*
 * release a reference on a buffer
 * (must be called with nfs_buf_mutex held)
 */
void
nfs_buf_refrele(struct nfsbuf *bp)
{
	bp->nb_refs--;
}

/*
 * mark a particular buffer as BUSY
 * (must be called with nfs_buf_mutex held)
 */
errno_t
nfs_buf_acquire(struct nfsbuf *bp, int flags, int slpflag, int slptimeo)
{
	errno_t error;
	struct timespec ts;

	if (ISSET(bp->nb_lflags, NBL_BUSY)) {
		/*	
		 * since the lck_mtx_lock may block, the buffer
		 * may become BUSY, so we need to recheck for
		 * a NOWAIT request
		 */
	        if (flags & NBAC_NOWAIT)
			return (EBUSY);
	        SET(bp->nb_lflags, NBL_WANTED);

		ts.tv_sec = (slptimeo/100);
		/* the hz value is 100; which leads to 10ms */
		ts.tv_nsec = (slptimeo % 100) * 10  * NSEC_PER_USEC * 1000;

		error = msleep(bp, nfs_buf_mutex, slpflag | (PRIBIO + 1),
			"nfs_buf_acquire", &ts);
		if (error)
			return (error);
		return (EAGAIN);
	}
	if (flags & NBAC_REMOVE)
	        nfs_buf_remfree(bp);
	SET(bp->nb_lflags, NBL_BUSY);

	return (0);
}

/*
 * simply drop the BUSY status of a buffer
 * (must be called with nfs_buf_mutex held)
 */
void
nfs_buf_drop(struct nfsbuf *bp)
{
	int need_wakeup = 0;

	if (!ISSET(bp->nb_lflags, NBL_BUSY))
		panic("nfs_buf_drop: buffer not busy!");
	if (ISSET(bp->nb_lflags, NBL_WANTED)) {
	        /* delay the actual wakeup until after we clear NBL_BUSY */
		need_wakeup = 1;
	}
	/* Unlock the buffer. */
	CLR(bp->nb_lflags, (NBL_BUSY | NBL_WANTED));

	if (need_wakeup)
	        wakeup(bp);
}

/*
 * prepare for iterating over an nfsnode's buffer list
 * this lock protects the queue manipulation
 * (must be called with nfs_buf_mutex held)
 */
int
nfs_buf_iterprepare(nfsnode_t np, struct nfsbuflists *iterheadp, int flags)
{
	struct nfsbuflists *listheadp;

	if (flags & NBI_DIRTY)
		listheadp = &np->n_dirtyblkhd;
	else
		listheadp = &np->n_cleanblkhd;

	if ((flags & NBI_NOWAIT) && (np->n_bufiterflags & NBI_ITER)) {
	        LIST_INIT(iterheadp);
		return(EWOULDBLOCK);
	}

	while (np->n_bufiterflags & NBI_ITER) 	{
	        np->n_bufiterflags |= NBI_ITERWANT;
		msleep(&np->n_bufiterflags, nfs_buf_mutex, 0, "nfs_buf_iterprepare", NULL);
	}
	if (LIST_EMPTY(listheadp)) {
	        LIST_INIT(iterheadp);
		return(EINVAL);
	}
	np->n_bufiterflags |= NBI_ITER;

	iterheadp->lh_first = listheadp->lh_first;
	listheadp->lh_first->nb_vnbufs.le_prev = &iterheadp->lh_first;	
	LIST_INIT(listheadp);

	return(0);
}

/*
 * clean up after iterating over an nfsnode's buffer list
 * this lock protects the queue manipulation
 * (must be called with nfs_buf_mutex held)
 */
void
nfs_buf_itercomplete(nfsnode_t np, struct nfsbuflists *iterheadp, int flags)
{
	struct nfsbuflists * listheadp;
	struct nfsbuf *bp;

	if (flags & NBI_DIRTY)
		listheadp = &np->n_dirtyblkhd;
	else
		listheadp = &np->n_cleanblkhd;

	while (!LIST_EMPTY(iterheadp)) {
		bp = LIST_FIRST(iterheadp);
		LIST_REMOVE(bp, nb_vnbufs);
		LIST_INSERT_HEAD(listheadp, bp, nb_vnbufs);
	}

	np->n_bufiterflags &= ~NBI_ITER;
	if (np->n_bufiterflags & NBI_ITERWANT) {
		np->n_bufiterflags &= ~NBI_ITERWANT;
		wakeup(&np->n_bufiterflags);
	}
}


/*
 * Read an NFS buffer for a file.
 */
int
nfs_buf_read(struct nfsbuf *bp)
{
	int error = 0;
	nfsnode_t np;
	thread_t thd;
	kauth_cred_t cred;

	np = bp->nb_np;
	cred = bp->nb_rcred;
	if (IS_VALID_CRED(cred))
		kauth_cred_ref(cred);
	thd = ISSET(bp->nb_flags, NB_ASYNC) ? NULL : current_thread();

	/* sanity checks */
	if (!ISSET(bp->nb_flags, NB_READ))
		panic("nfs_buf_read: !NB_READ");
	if (ISSET(bp->nb_flags, NB_DONE))
		CLR(bp->nb_flags, NB_DONE);

	NFS_BUF_MAP(bp);

	OSAddAtomic64(1, &nfsstats.read_bios);

	error = nfs_buf_read_rpc(bp, thd, cred);
	/*
	 * For async I/O, the callbacks will finish up the
	 * read.  Otherwise, the read has already been finished.
	 */

	if (IS_VALID_CRED(cred))
		kauth_cred_unref(&cred);
	return (error);
}

/*
 * finish the reading of a buffer
 */
void
nfs_buf_read_finish(struct nfsbuf *bp)
{
	nfsnode_t np = bp->nb_np;
	struct nfsmount *nmp;

	if (!ISSET(bp->nb_flags, NB_ERROR)) {
		/* update valid range */
		bp->nb_validoff = 0;
		bp->nb_validend = bp->nb_endio;
		if (bp->nb_endio < (int)bp->nb_bufsize) { 
			/*
			 * The read may be short because we have unflushed writes
			 * that are extending the file size and the reads hit the
			 * (old) EOF on the server.  So, just make sure nb_validend
			 * correctly tracks EOF.
			 * Note that the missing data should have already been zeroed
			 * in nfs_buf_read_rpc_finish().
			 */
			off_t boff = NBOFF(bp);
			if ((off_t)np->n_size >= (boff + bp->nb_bufsize))
				bp->nb_validend = bp->nb_bufsize;
			else if ((off_t)np->n_size >= boff)
				bp->nb_validend = np->n_size - boff;
			else
				bp->nb_validend = 0;
		}
		if ((nmp = NFSTONMP(np)) && (nmp->nm_vers == NFS_VER2) &&
		    ((NBOFF(bp) + bp->nb_validend) > 0x100000000LL))
			bp->nb_validend = 0x100000000LL - NBOFF(bp);
		bp->nb_valid = (1 << (round_page_32(bp->nb_validend) / PAGE_SIZE)) - 1;
		if (bp->nb_validend & PAGE_MASK) {
			/* zero-fill remainder of last page */
			bzero(bp->nb_data + bp->nb_validend, PAGE_SIZE - (bp->nb_validend & PAGE_MASK));
		}
	}
	nfs_buf_iodone(bp);
}

/*
 * initiate the NFS READ RPC(s) for a buffer
 */
int
nfs_buf_read_rpc(struct nfsbuf *bp, thread_t thd, kauth_cred_t cred)
{
	struct nfsmount *nmp;
	nfsnode_t np = bp->nb_np;
	int error = 0, nfsvers, async;
	int offset, nrpcs;
	uint32_t nmrsize, length, len;
	off_t boff;
	struct nfsreq *req;
	struct nfsreq_cbinfo cb;

	nmp = NFSTONMP(np);
	if (!nmp) {
		bp->nb_error = error = ENXIO;
		SET(bp->nb_flags, NB_ERROR);
		nfs_buf_iodone(bp);
		return (error);
	}
	nfsvers = nmp->nm_vers;
	nmrsize = nmp->nm_rsize;

	boff = NBOFF(bp);
	offset = 0;
	length = bp->nb_bufsize;

	if (nfsvers == NFS_VER2) {
		if (boff > 0xffffffffLL) {
			bp->nb_error = error = EFBIG;
			SET(bp->nb_flags, NB_ERROR);
			nfs_buf_iodone(bp);
			return (error);
		}
		if ((boff + length - 1) > 0xffffffffLL)
			length = 0x100000000LL - boff;
	}

	/* Note: Can only do async I/O if nfsiods are configured. */
	async = (bp->nb_flags & NB_ASYNC);
	cb.rcb_func = async ? nfs_buf_read_rpc_finish : NULL;
	cb.rcb_bp = bp;

	bp->nb_offio = bp->nb_endio = 0;
	bp->nb_rpcs = nrpcs = (length + nmrsize - 1) / nmrsize;
	if (async && (nrpcs > 1)) {
		SET(bp->nb_flags, NB_MULTASYNCRPC);
	} else {
		CLR(bp->nb_flags, NB_MULTASYNCRPC);
	}

	while (length > 0) {
		if (ISSET(bp->nb_flags, NB_ERROR)) {
			error = bp->nb_error;
			break;
		}
		len = (length > nmrsize) ? nmrsize : length;
		cb.rcb_args[0] = offset;
		cb.rcb_args[1] = len;
		if (nmp->nm_vers >= NFS_VER4)
			cb.rcb_args[2] = nmp->nm_stategenid;
		req = NULL;
		error = nmp->nm_funcs->nf_read_rpc_async(np, boff + offset, len, thd, cred, &cb, &req);
		if (error)
			break;
		offset += len;
		length -= len;
		if (async)
			continue;
		nfs_buf_read_rpc_finish(req);
		if (ISSET(bp->nb_flags, NB_ERROR)) {
			error = bp->nb_error;
			break;
		}
	}

	if (length > 0) {
		/*
		 * Something bad happened while trying to send the RPC(s).
		 * Wait for any outstanding requests to complete.
		 */
		bp->nb_error = error;
		SET(bp->nb_flags, NB_ERROR);
		if (ISSET(bp->nb_flags, NB_MULTASYNCRPC)) {
			nrpcs = (length + nmrsize - 1) / nmrsize;
			lck_mtx_lock(nfs_buf_mutex);
			bp->nb_rpcs -= nrpcs;
			if (bp->nb_rpcs == 0) {
				/* No RPCs left, so the buffer's done */
				lck_mtx_unlock(nfs_buf_mutex);
				nfs_buf_iodone(bp);
			} else {
				/* wait for the last RPC to mark it done */
				while (bp->nb_rpcs > 0)
					msleep(&bp->nb_rpcs, nfs_buf_mutex, 0,
						"nfs_buf_read_rpc_cancel", NULL);
				lck_mtx_unlock(nfs_buf_mutex);
			}
		} else {
			nfs_buf_iodone(bp);
		}
	}

	return (error);
}

/*
 * finish up an NFS READ RPC on a buffer
 */
void
nfs_buf_read_rpc_finish(struct nfsreq *req)
{
	struct nfsmount *nmp;
	size_t rlen;
	struct nfsreq_cbinfo cb;
	struct nfsbuf *bp;
	int error = 0, nfsvers, offset, length, eof = 0, multasyncrpc, finished;
	void *wakeme = NULL;
	struct nfsreq *rreq = NULL;
	nfsnode_t np;
	thread_t thd;
	kauth_cred_t cred;
	uio_t auio;
	char uio_buf [ UIO_SIZEOF(1) ];

finish:
	np = req->r_np;
	thd = req->r_thread;
	cred = req->r_cred;
	if (IS_VALID_CRED(cred))
		kauth_cred_ref(cred);
	cb = req->r_callback;
	bp = cb.rcb_bp;
	if (cb.rcb_func) /* take an extra reference on the nfsreq in case we want to resend it later due to grace error */
		nfs_request_ref(req, 0);

	nmp = NFSTONMP(np);
	if (!nmp) {
		SET(bp->nb_flags, NB_ERROR);
		bp->nb_error = error = ENXIO;
	}
	if (error || ISSET(bp->nb_flags, NB_ERROR)) {
		/* just drop it */
		nfs_request_async_cancel(req);
		goto out;
	}

	nfsvers = nmp->nm_vers;
	offset = cb.rcb_args[0];
	rlen = length = cb.rcb_args[1];

	auio = uio_createwithbuffer(1, NBOFF(bp) + offset, UIO_SYSSPACE,
                                UIO_READ, &uio_buf, sizeof(uio_buf));
	uio_addiov(auio, CAST_USER_ADDR_T(bp->nb_data + offset), length);

	/* finish the RPC */
	error = nmp->nm_funcs->nf_read_rpc_async_finish(np, req, auio, &rlen, &eof);
	if ((error == EINPROGRESS) && cb.rcb_func) {
		/* async request restarted */
		if (cb.rcb_func)
			nfs_request_rele(req);
		if (IS_VALID_CRED(cred))
			kauth_cred_unref(&cred);
		return;
	}
	if ((nmp->nm_vers >= NFS_VER4) && nfs_mount_state_error_should_restart(error) && !ISSET(bp->nb_flags, NB_ERROR)) {
		lck_mtx_lock(&nmp->nm_lock);
		if ((error != NFSERR_OLD_STATEID) && (error != NFSERR_GRACE) && (cb.rcb_args[2] == nmp->nm_stategenid)) {
			NP(np, "nfs_buf_read_rpc_finish: error %d @ 0x%llx, 0x%x 0x%x, initiating recovery",
				error, NBOFF(bp)+offset, cb.rcb_args[2], nmp->nm_stategenid);
			nfs_need_recover(nmp, error);
		}
		lck_mtx_unlock(&nmp->nm_lock);
		if (np->n_flag & NREVOKE) {
			error = EIO;
		} else {
			if (error == NFSERR_GRACE) {
				if (cb.rcb_func) {
					/*
					 * For an async I/O request, handle a grace delay just like
					 * jukebox errors.  Set the resend time and queue it up.
					 */
					struct timeval now;
					if (req->r_nmrep.nmc_mhead) {
						mbuf_freem(req->r_nmrep.nmc_mhead);
						req->r_nmrep.nmc_mhead = NULL;
					}
					req->r_error = 0;
					microuptime(&now);
					lck_mtx_lock(&req->r_mtx);
					req->r_resendtime = now.tv_sec + 2;
					req->r_xid = 0;                 // get a new XID
					req->r_flags |= R_RESTART;
					req->r_start = 0;
					nfs_asyncio_resend(req);
					lck_mtx_unlock(&req->r_mtx);
					if (IS_VALID_CRED(cred))
						kauth_cred_unref(&cred);
					/* Note: nfsreq reference taken will be dropped later when finished */
					return;
				}
				/* otherwise, just pause a couple seconds and retry */
				tsleep(&nmp->nm_state, (PZERO-1), "nfsgrace", 2*hz);
			}
			if (!(error = nfs_mount_state_wait_for_recovery(nmp))) {
				rlen = 0;
				goto readagain;
			}
		}
	}
	if (error) {
		SET(bp->nb_flags, NB_ERROR);
		bp->nb_error = error;
		goto out;
	}

	if ((rlen > 0) && (bp->nb_endio < (offset + (int)rlen)))
		bp->nb_endio = offset + rlen;

	if ((nfsvers == NFS_VER2) || eof || (rlen == 0)) {
		/* zero out the remaining data (up to EOF) */
		off_t rpcrem, eofrem, rem;
		rpcrem = (length - rlen);
		eofrem = np->n_size - (NBOFF(bp) + offset + rlen);
		rem = (rpcrem < eofrem) ? rpcrem : eofrem;
		if (rem > 0)
			bzero(bp->nb_data + offset + rlen, rem);
	} else if (((int)rlen < length) && !ISSET(bp->nb_flags, NB_ERROR)) {
		/*
		 * short read
		 *
		 * We haven't hit EOF and we didn't get all the data
		 * requested, so we need to issue another read for the rest.
		 * (Don't bother if the buffer already hit an error.)
		 */
readagain:
		offset += rlen;
		length -= rlen;
		cb.rcb_args[0] = offset;
		cb.rcb_args[1] = length;
		if (nmp->nm_vers >= NFS_VER4)
			cb.rcb_args[2] = nmp->nm_stategenid;
		error = nmp->nm_funcs->nf_read_rpc_async(np, NBOFF(bp) + offset, length, thd, cred, &cb, &rreq);
		if (!error) {
			if (IS_VALID_CRED(cred))
				kauth_cred_unref(&cred);
			if (!cb.rcb_func) {
				/* if !async we'll need to wait for this RPC to finish */
				req = rreq;
				rreq = NULL;
				goto finish;
			}
			nfs_request_rele(req);
			/*
			 * We're done here.
			 * Outstanding RPC count is unchanged.
			 * Callback will be called when RPC is done.
			 */
			return;
		}
		SET(bp->nb_flags, NB_ERROR);
		bp->nb_error = error;
	}

out:
	if (cb.rcb_func)
		nfs_request_rele(req);
	if (IS_VALID_CRED(cred))
		kauth_cred_unref(&cred);

	/*
	 * Decrement outstanding RPC count on buffer
	 * and call nfs_buf_read_finish on last RPC.
	 *
	 * (Note: when there are multiple async RPCs issued for a
	 * buffer we need nfs_buffer_mutex to avoid problems when
	 * aborting a partially-initiated set of RPCs)
	 */

	multasyncrpc = ISSET(bp->nb_flags, NB_MULTASYNCRPC);
	if (multasyncrpc)
		lck_mtx_lock(nfs_buf_mutex);

	bp->nb_rpcs--;
	finished = (bp->nb_rpcs == 0);

	if (multasyncrpc)
		lck_mtx_unlock(nfs_buf_mutex);

	if (finished) {
		if (multasyncrpc)
			wakeme = &bp->nb_rpcs;
		nfs_buf_read_finish(bp);
		if (wakeme)
			wakeup(wakeme);
	}
}

/*
 * Do buffer readahead.
 * Initiate async I/O to read buffers not in cache.
 */
int
nfs_buf_readahead(nfsnode_t np, int ioflag, daddr64_t *rabnp, daddr64_t lastrabn, thread_t thd, kauth_cred_t cred)
{
	struct nfsmount *nmp = NFSTONMP(np);
	struct nfsbuf *bp;
	int error = 0;
	uint32_t nra;

	if (!nmp)
		return (ENXIO);
	if (nmp->nm_readahead <= 0)
		return (0);
	if (*rabnp > lastrabn)
		return (0);

	for (nra = 0; (nra < nmp->nm_readahead) && (*rabnp <= lastrabn); nra++, *rabnp = *rabnp + 1) {
		/* check if block exists and is valid. */
		if ((*rabnp * nmp->nm_biosize) >= (off_t)np->n_size) {
			/* stop reading ahead if we're beyond EOF */
			*rabnp = lastrabn;
			break;
		}
		error = nfs_buf_get(np, *rabnp, nmp->nm_biosize, thd, NBLK_READ|NBLK_NOWAIT, &bp);
		if (error)
			break;
		nfs_node_lock_force(np);
		np->n_lastrahead = *rabnp;
		nfs_node_unlock(np);
		if (!bp)
			continue;
		if ((ioflag & IO_NOCACHE) && ISSET(bp->nb_flags, NB_CACHE) &&
		    !bp->nb_dirty && !ISSET(bp->nb_flags, (NB_DELWRI|NB_NCRDAHEAD))) {
			CLR(bp->nb_flags, NB_CACHE);
			bp->nb_valid = 0;
			bp->nb_validoff = bp->nb_validend = -1;
		}
		if ((bp->nb_dirtyend <= 0) && !bp->nb_dirty &&
		    !ISSET(bp->nb_flags, (NB_CACHE|NB_DELWRI))) {
			SET(bp->nb_flags, (NB_READ|NB_ASYNC));
			if (ioflag & IO_NOCACHE)
				SET(bp->nb_flags, NB_NCRDAHEAD);
			if (!IS_VALID_CRED(bp->nb_rcred) && IS_VALID_CRED(cred)) {
				kauth_cred_ref(cred);
				bp->nb_rcred = cred;
			}
			if ((error = nfs_buf_read(bp)))
				break;
			continue;
		}
		nfs_buf_release(bp, 1);
	}
	return (error);
}

/*
 * NFS buffer I/O for reading files.
 */
int
nfs_bioread(nfsnode_t np, uio_t uio, int ioflag, vfs_context_t ctx)
{
	vnode_t vp = NFSTOV(np);
	struct nfsbuf *bp = NULL;
	struct nfsmount *nmp = VTONMP(vp);
	daddr64_t lbn, rabn = 0, lastrabn, maxrabn = -1;
	off_t diff;
	int error = 0, n = 0, on = 0;
	int nfsvers, biosize, modified, readaheads = 0;
	thread_t thd;
	kauth_cred_t cred;
	int64_t io_resid;

	FSDBG_TOP(514, np, uio_offset(uio), uio_resid(uio), ioflag);

	nfsvers = nmp->nm_vers;
	biosize = nmp->nm_biosize;
	thd = vfs_context_thread(ctx);
	cred = vfs_context_ucred(ctx);

	if (vnode_vtype(vp) != VREG) {
		printf("nfs_bioread: type %x unexpected\n", vnode_vtype(vp));
		FSDBG_BOT(514, np, 0xd1e0016, 0, EINVAL);
		return (EINVAL);
	}

	/*
	 * For NFS, cache consistency can only be maintained approximately.
	 * Although RFC1094 does not specify the criteria, the following is
	 * believed to be compatible with the reference port.
	 * 
	 * If the file has changed since the last read RPC or you have
	 * written to the file, you may have lost data cache consistency
	 * with the server.  So, check for a change, and flush all of the
	 * file's data out of the cache.
	 * NB: This implies that cache data can be read when up to
	 * NFS_MAXATTRTIMO seconds out of date. If you find that you
	 * need current attributes, nfs_getattr() can be forced to fetch
	 * new attributes (via NATTRINVALIDATE() or NGA_UNCACHED).
	 */

	if (ISSET(np->n_flag, NUPDATESIZE))
		nfs_data_update_size(np, 0);

	if ((error = nfs_node_lock(np))) {
		FSDBG_BOT(514, np, 0xd1e0222, 0, error);
		return (error);
	}

	if (np->n_flag & NNEEDINVALIDATE) {
		np->n_flag &= ~NNEEDINVALIDATE;
		nfs_node_unlock(np);
		error = nfs_vinvalbuf(vp, V_SAVE|V_IGNORE_WRITEERR, ctx, 1);
		if (!error)
			error = nfs_node_lock(np);
		if (error) {
			FSDBG_BOT(514, np, 0xd1e0322, 0, error);
			return (error);
		}
	}

	modified = (np->n_flag & NMODIFIED);
	nfs_node_unlock(np);
	/* nfs_getattr() will check changed and purge caches */
	error = nfs_getattr(np, NULL, ctx, modified ? NGA_UNCACHED : NGA_CACHED);
	if (error) {
		FSDBG_BOT(514, np, 0xd1e0004, 0, error);
		return (error);
	}

	if (uio_resid(uio) == 0) {
		FSDBG_BOT(514, np, 0xd1e0001, 0, 0);
		return (0);
	}
	if (uio_offset(uio) < 0) {
		FSDBG_BOT(514, np, 0xd1e0002, 0, EINVAL);
		return (EINVAL);
	}

	/*
	 * set up readahead - which may be limited by:
	 * + current request length (for IO_NOCACHE)
	 * + readahead setting
	 * + file size
	 */
	if (nmp->nm_readahead > 0) {
		off_t end = uio_offset(uio) + uio_resid(uio);
		if (end > (off_t)np->n_size)
			end = np->n_size;
		rabn = uio_offset(uio) / biosize;
		maxrabn = (end - 1) / biosize;
		nfs_node_lock_force(np);
		if (!(ioflag & IO_NOCACHE) &&
		    (!rabn || (rabn == np->n_lastread) || (rabn == (np->n_lastread+1)))) {
			maxrabn += nmp->nm_readahead;
			if ((maxrabn * biosize) >= (off_t)np->n_size)
				maxrabn = ((off_t)np->n_size - 1)/biosize;
		}
		if (maxrabn < np->n_lastrahead)
			np->n_lastrahead = -1;
		if (rabn < np->n_lastrahead)
			rabn = np->n_lastrahead + 1;
		nfs_node_unlock(np);
	} else {
		rabn = maxrabn = 0;
	}

	do {

		nfs_data_lock(np, NFS_DATA_LOCK_SHARED);
		lbn = uio_offset(uio) / biosize;

		/*
		 * Copy directly from any cached pages without grabbing the bufs.
		 * (If we are NOCACHE and we've issued readahead requests, we need
		 * to grab the NB_NCRDAHEAD bufs to drop them.)
		 */
		if ((!(ioflag & IO_NOCACHE) || !readaheads) &&
		    ((uio->uio_segflg == UIO_USERSPACE32 ||
		      uio->uio_segflg == UIO_USERSPACE64 ||
		      uio->uio_segflg == UIO_USERSPACE))) {
			io_resid = uio_resid(uio);
			diff = np->n_size - uio_offset(uio);
			if (diff < io_resid)
				io_resid = diff;
			if (io_resid > 0) {
				int count = (io_resid > INT_MAX) ? INT_MAX : io_resid;
				error = cluster_copy_ubc_data(vp, uio, &count, 0);
				if (error) {
					nfs_data_unlock(np);
					FSDBG_BOT(514, np, uio_offset(uio), 0xcacefeed, error);
					return (error);
				}
			}
			/* count any biocache reads that we just copied directly */
			if (lbn != (uio_offset(uio)/biosize)) {
				OSAddAtomic64((uio_offset(uio)/biosize) - lbn, &nfsstats.biocache_reads);
				FSDBG(514, np, 0xcacefeed, uio_offset(uio), error);
			}
		}

		lbn = uio_offset(uio) / biosize;
		on = uio_offset(uio) % biosize;
		nfs_node_lock_force(np);
		np->n_lastread = (uio_offset(uio) - 1) / biosize;
		nfs_node_unlock(np);

		if ((uio_resid(uio) <= 0) || (uio_offset(uio) >= (off_t)np->n_size)) {
			nfs_data_unlock(np);
			FSDBG_BOT(514, np, uio_offset(uio), uio_resid(uio), 0xaaaaaaaa);
			return (0);
		}

		/* adjust readahead block number, if necessary */
		if (rabn < lbn)
			rabn = lbn;
		lastrabn = MIN(maxrabn, lbn + nmp->nm_readahead);
		if (rabn <= lastrabn) { /* start readaheads */
			error = nfs_buf_readahead(np, ioflag, &rabn, lastrabn, thd, cred);
			if (error) {
				nfs_data_unlock(np);
				FSDBG_BOT(514, np, 0xd1e000b, 1, error);
				return (error);
			}
			readaheads = 1;
		}

		OSAddAtomic64(1, &nfsstats.biocache_reads);

		/*
		 * If the block is in the cache and has the required data
		 * in a valid region, just copy it out.
		 * Otherwise, get the block and write back/read in,
		 * as required.
		 */
again:
		io_resid = uio_resid(uio);
		n = (io_resid > (biosize - on)) ? (biosize - on) : io_resid;
		diff = np->n_size - uio_offset(uio);
		if (diff < n)
			n = diff;

		error = nfs_buf_get(np, lbn, biosize, thd, NBLK_READ, &bp);
		if (error) {
			nfs_data_unlock(np);
			FSDBG_BOT(514, np, 0xd1e000c, 0, error);
			return (error);
		}

		if ((ioflag & IO_NOCACHE) && ISSET(bp->nb_flags, NB_CACHE)) {
			/*
			 * IO_NOCACHE found a cached buffer.
			 * Flush the buffer if it's dirty.
			 * Invalidate the data if it wasn't just read
			 * in as part of a "nocache readahead".
			 */
			if (bp->nb_dirty || (bp->nb_dirtyend > 0)) {
				/* so write the buffer out and try again */
				SET(bp->nb_flags, NB_NOCACHE);
				goto flushbuffer;
			}
			if (ISSET(bp->nb_flags, NB_NCRDAHEAD)) {
				CLR(bp->nb_flags, NB_NCRDAHEAD);
				SET(bp->nb_flags, NB_NOCACHE);
			}
		}

		/* if any pages are valid... */
		if (bp->nb_valid) {
			/* ...check for any invalid pages in the read range */
			int pg, firstpg, lastpg, dirtypg;
			dirtypg = firstpg = lastpg = -1;
			pg = on/PAGE_SIZE;
			while (pg <= (on + n - 1)/PAGE_SIZE) {
				if (!NBPGVALID(bp,pg)) {
					if (firstpg < 0)
						firstpg = pg;
					lastpg = pg;
				} else if (firstpg >= 0 && dirtypg < 0 && NBPGDIRTY(bp,pg))
					dirtypg = pg;
				pg++;
			}

			/* if there are no invalid pages, we're all set */
			if (firstpg < 0) {
				if (bp->nb_validoff < 0) {
					/* valid range isn't set up, so */
					/* set it to what we know is valid */
					bp->nb_validoff = trunc_page(on);
					bp->nb_validend = round_page(on+n);
					nfs_buf_normalize_valid_range(np, bp);
				}
				goto buffer_ready;
			}

			/* there are invalid pages in the read range */
			if (((dirtypg > firstpg) && (dirtypg < lastpg)) ||
			    (((firstpg*PAGE_SIZE) < bp->nb_dirtyend) && (((lastpg+1)*PAGE_SIZE) > bp->nb_dirtyoff))) {
				/* there are also dirty page(s) (or range) in the read range, */
				/* so write the buffer out and try again */
flushbuffer:
				CLR(bp->nb_flags, (NB_DONE | NB_ERROR | NB_INVAL));
				SET(bp->nb_flags, NB_ASYNC);
				if (!IS_VALID_CRED(bp->nb_wcred)) {
					kauth_cred_ref(cred);
					bp->nb_wcred = cred;
				}
				error = nfs_buf_write(bp);
				if (error) {
					nfs_data_unlock(np);
					FSDBG_BOT(514, np, 0xd1e000d, 0, error);
					return (error);
				}
				goto again;
			}
			if (!bp->nb_dirty && bp->nb_dirtyend <= 0 &&
			    (lastpg - firstpg + 1) > (biosize/PAGE_SIZE)/2) {
				/* we need to read in more than half the buffer and the */
				/* buffer's not dirty, so just fetch the whole buffer */
				bp->nb_valid = 0;
			} else {
				/* read the page range in */
				uio_t auio;
				char uio_buf[ UIO_SIZEOF(1) ];
				
				NFS_BUF_MAP(bp);
				auio = uio_createwithbuffer(1, (NBOFF(bp) + firstpg * PAGE_SIZE_64),
						UIO_SYSSPACE, UIO_READ, &uio_buf[0], sizeof(uio_buf));
				if (!auio) {
					error = ENOMEM;
				} else {
					uio_addiov(auio, CAST_USER_ADDR_T(bp->nb_data + (firstpg * PAGE_SIZE)),
							((lastpg - firstpg + 1) * PAGE_SIZE));
					error = nfs_read_rpc(np, auio, ctx);
				}
				if (error) {
					if (ioflag & IO_NOCACHE)
						SET(bp->nb_flags, NB_NOCACHE);
					nfs_buf_release(bp, 1);
					nfs_data_unlock(np);
					FSDBG_BOT(514, np, 0xd1e000e, 0, error);
					return (error);
				}
				/* Make sure that the valid range is set to cover this read. */
				bp->nb_validoff = trunc_page_32(on);
				bp->nb_validend = round_page_32(on+n);
				nfs_buf_normalize_valid_range(np, bp);
				if (uio_resid(auio) > 0) {
					/* if short read, must have hit EOF, */
					/* so zero the rest of the range */
					bzero(CAST_DOWN(caddr_t, uio_curriovbase(auio)), uio_resid(auio));
				}
				/* mark the pages (successfully read) as valid */
				for (pg=firstpg; pg <= lastpg; pg++)
					NBPGVALID_SET(bp,pg);
			}
		}
		/* if no pages are valid, read the whole block */
		if (!bp->nb_valid) {
			if (!IS_VALID_CRED(bp->nb_rcred) && IS_VALID_CRED(cred)) {
				kauth_cred_ref(cred);
				bp->nb_rcred = cred;
			}
			SET(bp->nb_flags, NB_READ);
			CLR(bp->nb_flags, (NB_DONE | NB_ERROR | NB_INVAL));
			error = nfs_buf_read(bp);
			if (ioflag & IO_NOCACHE)
				SET(bp->nb_flags, NB_NOCACHE);
			if (error) {
				nfs_data_unlock(np);
				nfs_buf_release(bp, 1);
				FSDBG_BOT(514, np, 0xd1e000f, 0, error);
				return (error);
			}
		}
buffer_ready:
		/* validate read range against valid range and clip */
		if (bp->nb_validend > 0) {
			diff = (on >= bp->nb_validend) ? 0 : (bp->nb_validend - on);
			if (diff < n)
				n = diff;
		}
		if (n > 0) {
			NFS_BUF_MAP(bp);
			error = uiomove(bp->nb_data + on, n, uio);
		}

		nfs_buf_release(bp, 1);
		nfs_data_unlock(np);
		nfs_node_lock_force(np);
		np->n_lastread = (uio_offset(uio) - 1) / biosize;
		nfs_node_unlock(np);
	} while (error == 0 && uio_resid(uio) > 0 && n > 0);
	FSDBG_BOT(514, np, uio_offset(uio), uio_resid(uio), error);
	return (error);
}

/*
 * limit the number of outstanding async I/O writes
 */
int
nfs_async_write_start(struct nfsmount *nmp)
{
	int error = 0, slpflag = NMFLAG(nmp, INTR) ? PCATCH : 0;
	struct timespec ts = {1, 0};

	if (nfs_max_async_writes <= 0)
		return (0);
	lck_mtx_lock(&nmp->nm_lock);
	while ((nfs_max_async_writes > 0) && (nmp->nm_asyncwrites >= nfs_max_async_writes)) {
		if ((error = nfs_sigintr(nmp, NULL, current_thread(), 1)))
			break;
		msleep(&nmp->nm_asyncwrites, &nmp->nm_lock, slpflag|(PZERO-1), "nfsasyncwrites", &ts);
		slpflag = 0;
	}
	if (!error)
		nmp->nm_asyncwrites++;
	lck_mtx_unlock(&nmp->nm_lock);
	return (error);
}
void
nfs_async_write_done(struct nfsmount *nmp)
{
	if (nmp->nm_asyncwrites <= 0)
		return;
	lck_mtx_lock(&nmp->nm_lock);
	if (nmp->nm_asyncwrites-- >= nfs_max_async_writes)
		wakeup(&nmp->nm_asyncwrites);
	lck_mtx_unlock(&nmp->nm_lock);
}

/*
 * write (or commit) the given NFS buffer
 *
 * Commit the buffer if we can.
 * Write out any dirty range.
 * If any dirty pages remain, write them out.
 * Mark buffer done.
 *
 * For async requests, all the work beyond sending the initial
 * write RPC is handled in the RPC callback(s).
 */
int
nfs_buf_write(struct nfsbuf *bp)
{
	int error = 0, oldflags, async;
	nfsnode_t np;
	thread_t thd;
	kauth_cred_t cred;
	proc_t p = current_proc();
	int iomode, doff, dend, firstpg, lastpg;
	uint32_t pagemask;

	FSDBG_TOP(553, bp, NBOFF(bp), bp->nb_flags, 0);

	if (!ISSET(bp->nb_lflags, NBL_BUSY))
		panic("nfs_buf_write: buffer is not busy???");

	np = bp->nb_np;
	async = ISSET(bp->nb_flags, NB_ASYNC);
	oldflags = bp->nb_flags;

	CLR(bp->nb_flags, (NB_READ|NB_DONE|NB_ERROR|NB_DELWRI));
	if (ISSET(oldflags, NB_DELWRI)) {
		lck_mtx_lock(nfs_buf_mutex);
		nfs_nbdwrite--;
		NFSBUFCNTCHK();
		lck_mtx_unlock(nfs_buf_mutex);
		wakeup(&nfs_nbdwrite);
	}

	/* move to clean list */
	if (ISSET(oldflags, (NB_ASYNC|NB_DELWRI))) {
		lck_mtx_lock(nfs_buf_mutex);
		if (bp->nb_vnbufs.le_next != NFSNOLIST)
			LIST_REMOVE(bp, nb_vnbufs);
		LIST_INSERT_HEAD(&np->n_cleanblkhd, bp, nb_vnbufs);
		lck_mtx_unlock(nfs_buf_mutex);
	}
	nfs_node_lock_force(np);
	np->n_numoutput++;
	nfs_node_unlock(np);
	vnode_startwrite(NFSTOV(np));

	if (p && p->p_stats)
		OSIncrementAtomicLong(&p->p_stats->p_ru.ru_oublock);

	cred = bp->nb_wcred;
	if (!IS_VALID_CRED(cred) && ISSET(bp->nb_flags, NB_READ))
		cred = bp->nb_rcred;  /* shouldn't really happen, but... */
	if (IS_VALID_CRED(cred))
		kauth_cred_ref(cred);
	thd = async ? NULL : current_thread();

	/* We need to make sure the pages are locked before doing I/O.  */
	if (!ISSET(bp->nb_flags, NB_META) && UBCINFOEXISTS(NFSTOV(np))) {
		if (!ISSET(bp->nb_flags, NB_PAGELIST)) {
			error = nfs_buf_upl_setup(bp);
			if (error) {
				printf("nfs_buf_write: upl create failed %d\n", error);
				SET(bp->nb_flags, NB_ERROR);
				bp->nb_error = error = EIO;
				nfs_buf_iodone(bp);
				goto out;
			}
			nfs_buf_upl_check(bp);
		}
	}

	/* If NB_NEEDCOMMIT is set, a commit RPC may do the trick. */
	if (ISSET(bp->nb_flags, NB_NEEDCOMMIT))
		nfs_buf_check_write_verifier(np, bp);
	if (ISSET(bp->nb_flags, NB_NEEDCOMMIT)) {
		struct nfsmount *nmp = NFSTONMP(np);
		if (!nmp) {
			SET(bp->nb_flags, NB_ERROR);
			bp->nb_error = error = EIO;
			nfs_buf_iodone(bp);
			goto out;
		}
		SET(bp->nb_flags, NB_WRITEINPROG);
		error = nmp->nm_funcs->nf_commit_rpc(np, NBOFF(bp) + bp->nb_dirtyoff,
				bp->nb_dirtyend - bp->nb_dirtyoff, bp->nb_wcred, bp->nb_verf);
		CLR(bp->nb_flags, NB_WRITEINPROG);
		if (error) {
			if (error != NFSERR_STALEWRITEVERF) {
				SET(bp->nb_flags, NB_ERROR);
				bp->nb_error = error;
			}
			nfs_buf_iodone(bp);
			goto out;
		}
		bp->nb_dirtyoff = bp->nb_dirtyend = 0;
		CLR(bp->nb_flags, NB_NEEDCOMMIT);
		nfs_node_lock_force(np);
		np->n_needcommitcnt--;
		CHECK_NEEDCOMMITCNT(np);
		nfs_node_unlock(np);
	}
	if (!error && (bp->nb_dirtyend > 0)) {
		/* sanity check the dirty range */
		if (NBOFF(bp) + bp->nb_dirtyend > (off_t) np->n_size) {
			bp->nb_dirtyend = np->n_size - NBOFF(bp);
			if (bp->nb_dirtyoff >= bp->nb_dirtyend)
				bp->nb_dirtyoff = bp->nb_dirtyend = 0;
		}
	}
	if (!error && (bp->nb_dirtyend > 0)) {
		/* there's a dirty range that needs to be written out */
		NFS_BUF_MAP(bp);

		doff = bp->nb_dirtyoff;
		dend = bp->nb_dirtyend;

		/* if doff page is dirty, move doff to start of page */
		if (NBPGDIRTY(bp, doff / PAGE_SIZE))
			doff -= doff & PAGE_MASK;
		/* try to expand write range to include preceding dirty pages */
		if (!(doff & PAGE_MASK))
			while ((doff > 0) && NBPGDIRTY(bp, (doff - 1) / PAGE_SIZE))
				doff -= PAGE_SIZE;
		/* if dend page is dirty, move dend to start of next page */
		if ((dend & PAGE_MASK) && NBPGDIRTY(bp, dend / PAGE_SIZE))
			dend = round_page_32(dend);
		/* try to expand write range to include trailing dirty pages */
		if (!(dend & PAGE_MASK))
			while ((dend < (int)bp->nb_bufsize) && NBPGDIRTY(bp, dend / PAGE_SIZE))
				dend += PAGE_SIZE;
		/* make sure to keep dend clipped to EOF */
		if ((NBOFF(bp) + dend) > (off_t) np->n_size)
			dend = np->n_size - NBOFF(bp);
		/* calculate range of complete pages being written */
		firstpg = round_page_32(doff) / PAGE_SIZE;
		lastpg = (trunc_page_32(dend) - 1) / PAGE_SIZE;
		/* calculate mask for that page range */
		pagemask = ((1 << (lastpg + 1)) - 1) & ~((1 << firstpg) - 1);

		/*
		 * compare page mask to nb_dirty; if there are other dirty pages
		 * then write FILESYNC; otherwise, write UNSTABLE if async and
		 * not needcommit/stable; otherwise write FILESYNC
		 */
		if (bp->nb_dirty & ~pagemask)
			iomode = NFS_WRITE_FILESYNC;
		else if ((bp->nb_flags & (NB_ASYNC | NB_NEEDCOMMIT | NB_STABLE)) == NB_ASYNC)
			iomode = NFS_WRITE_UNSTABLE;
		else
			iomode = NFS_WRITE_FILESYNC;

		/* write the whole contiguous dirty range */
		bp->nb_offio = doff;
		bp->nb_endio = dend;

		OSAddAtomic64(1, &nfsstats.write_bios);

		SET(bp->nb_flags, NB_WRITEINPROG);
		error = nfs_buf_write_rpc(bp, iomode, thd, cred);
		/*
		 * For async I/O, the callbacks will finish up the
		 * write and push out any dirty pages.  Otherwise,
		 * the write has already been finished and any dirty
		 * pages pushed out.
		 */
	} else {
		if (!error && bp->nb_dirty) /* write out any dirty pages */
			error = nfs_buf_write_dirty_pages(bp, thd, cred);
		nfs_buf_iodone(bp);
	}
	/* note: bp is still valid only for !async case */
out:
	if (!async) {
		error = nfs_buf_iowait(bp);
		/* move to clean list */
		if (oldflags & NB_DELWRI) {
			lck_mtx_lock(nfs_buf_mutex);
			if (bp->nb_vnbufs.le_next != NFSNOLIST)
				LIST_REMOVE(bp, nb_vnbufs);
			LIST_INSERT_HEAD(&np->n_cleanblkhd, bp, nb_vnbufs);
			lck_mtx_unlock(nfs_buf_mutex);
		}
		FSDBG_BOT(553, bp, NBOFF(bp), bp->nb_flags, error);
		nfs_buf_release(bp, 1);
		/* check if we need to invalidate (and we can) */
		if ((np->n_flag & NNEEDINVALIDATE) &&
		    !(np->n_bflag & (NBINVALINPROG|NBFLUSHINPROG))) {
			int invalidate = 0;
			nfs_node_lock_force(np);
			if (np->n_flag & NNEEDINVALIDATE) {
				invalidate = 1;
				np->n_flag &= ~NNEEDINVALIDATE;
			}
			nfs_node_unlock(np);
			if (invalidate) {
				/*
				 * There was a write error and we need to
				 * invalidate attrs and flush buffers in
				 * order to sync up with the server.
				 * (if this write was extending the file,
				 * we may no longer know the correct size)
				 *
				 * But we couldn't call vinvalbuf while holding
				 * the buffer busy.  So we call vinvalbuf() after
				 * releasing the buffer.
				 */
				nfs_vinvalbuf2(NFSTOV(np), V_SAVE|V_IGNORE_WRITEERR, thd, cred, 1);
			}
		}
	}

	if (IS_VALID_CRED(cred))
		kauth_cred_unref(&cred);
	return (error);
}

/*
 * finish the writing of a buffer
 */
void
nfs_buf_write_finish(struct nfsbuf *bp, thread_t thd, kauth_cred_t cred)
{
	nfsnode_t np = bp->nb_np;
	int error = (bp->nb_flags & NB_ERROR) ? bp->nb_error : 0;
	int firstpg, lastpg;
	uint32_t pagemask;

	if ((error == EINTR) || (error == ERESTART)) {
		CLR(bp->nb_flags, NB_ERROR);
		SET(bp->nb_flags, NB_EINTR);
	}

	if (!error) {
		/* calculate range of complete pages being written */
		firstpg = round_page_32(bp->nb_offio) / PAGE_SIZE;
		lastpg = (trunc_page_32(bp->nb_endio) - 1) / PAGE_SIZE;
		/* calculate mask for that page range written */
		pagemask = ((1 << (lastpg + 1)) - 1) & ~((1 << firstpg) - 1);
		/* clear dirty bits for pages we've written */
		bp->nb_dirty &= ~pagemask;
	}

	/* manage needcommit state */
	if (!error && (bp->nb_commitlevel == NFS_WRITE_UNSTABLE)) {
		if (!ISSET(bp->nb_flags, NB_NEEDCOMMIT)) {
			nfs_node_lock_force(np);
			np->n_needcommitcnt++;
			nfs_node_unlock(np);
			SET(bp->nb_flags, NB_NEEDCOMMIT);
		}
		/* make sure nb_dirtyoff/nb_dirtyend reflect actual range written */
		bp->nb_dirtyoff = bp->nb_offio;
		bp->nb_dirtyend = bp->nb_endio;
	} else if (ISSET(bp->nb_flags, NB_NEEDCOMMIT)) {
		nfs_node_lock_force(np);
		np->n_needcommitcnt--;
		CHECK_NEEDCOMMITCNT(np);
		nfs_node_unlock(np);
		CLR(bp->nb_flags, NB_NEEDCOMMIT);
	}

	CLR(bp->nb_flags, NB_WRITEINPROG);

	/*
	 * For an unstable write, the buffer is still treated as dirty until
	 * a commit (or stable (re)write) is performed.  Buffers needing only
	 * a commit are marked with the NB_DELWRI and NB_NEEDCOMMIT flags.
	 *
	 * If the write was interrupted we set NB_EINTR.  Don't set NB_ERROR
	 * because that would cause the buffer to be dropped.  The buffer is
	 * still valid and simply needs to be written again.
	 */
	if ((error == EINTR) || (error == ERESTART) || (!error && (bp->nb_flags & NB_NEEDCOMMIT))) {
		CLR(bp->nb_flags, NB_INVAL);
		if (!ISSET(bp->nb_flags, NB_DELWRI)) {
			SET(bp->nb_flags, NB_DELWRI);
			lck_mtx_lock(nfs_buf_mutex);
			nfs_nbdwrite++;
			NFSBUFCNTCHK();
			lck_mtx_unlock(nfs_buf_mutex);
		}
		/*
		 * Since for the NB_ASYNC case, we've reassigned the buffer to the
		 * clean list, we have to reassign it back to the dirty one. Ugh.
		 */
		if (ISSET(bp->nb_flags, NB_ASYNC)) {
			/* move to dirty list */
			lck_mtx_lock(nfs_buf_mutex);
			if (bp->nb_vnbufs.le_next != NFSNOLIST)
				LIST_REMOVE(bp, nb_vnbufs);
			LIST_INSERT_HEAD(&np->n_dirtyblkhd, bp, nb_vnbufs);
			lck_mtx_unlock(nfs_buf_mutex);
		}
	} else {
		/* either there's an error or we don't need to commit */
		if (error) {
			/*
			 * There was a write error and we need to invalidate
			 * attrs and flush buffers in order to sync up with the
			 * server.  (if this write was extending the file, we
			 * may no longer know the correct size)
			 *
			 * But we can't call vinvalbuf while holding this
			 * buffer busy.  Set a flag to do it after releasing
			 * the buffer.
			 */
			nfs_node_lock_force(np);
			np->n_error = error;
			np->n_flag |= (NWRITEERR | NNEEDINVALIDATE);
			NATTRINVALIDATE(np);
			nfs_node_unlock(np);
		}
		/* clear the dirty range */
		bp->nb_dirtyoff = bp->nb_dirtyend = 0;
	}

	if (!error && bp->nb_dirty)
		nfs_buf_write_dirty_pages(bp, thd, cred);
	nfs_buf_iodone(bp);
}

/*
 * write out any pages marked dirty in a buffer
 *
 * We do use unstable writes and follow up with a commit.
 * If we catch the write verifier changing we'll restart
 * do the writes filesync.
 */
int
nfs_buf_write_dirty_pages(struct nfsbuf *bp, thread_t thd, kauth_cred_t cred)
{
	nfsnode_t np = bp->nb_np;
	struct nfsmount *nmp = NFSTONMP(np);
	int error = 0, commit, iomode, iomode2, len, pg, count, npages, off;
	uint32_t dirty = bp->nb_dirty;
	uint64_t wverf;
	uio_t auio;
	char uio_buf [ UIO_SIZEOF(1) ];

	if (!bp->nb_dirty)
		return (0);

	/* there are pages marked dirty that need to be written out */
	OSAddAtomic64(1, &nfsstats.write_bios);
	NFS_BUF_MAP(bp);
	SET(bp->nb_flags, NB_WRITEINPROG);
	npages = bp->nb_bufsize / PAGE_SIZE;
	iomode = NFS_WRITE_UNSTABLE;

	auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_WRITE,
		&uio_buf, sizeof(uio_buf));

again:
	dirty = bp->nb_dirty;
	wverf = bp->nb_verf;
	commit = NFS_WRITE_FILESYNC;
	for (pg = 0; pg < npages; pg++) {
		if (!NBPGDIRTY(bp, pg))
			continue;
		count = 1;
		while (((pg + count) < npages) && NBPGDIRTY(bp, pg + count))
			count++;
		/* write count pages starting with page pg */
		off = pg * PAGE_SIZE;
		len = count * PAGE_SIZE;
		/* clip writes to EOF */
		if (NBOFF(bp) + off + len > (off_t) np->n_size)
			len -= (NBOFF(bp) + off + len) - np->n_size;
		if (len > 0) {
			iomode2 = iomode;
			uio_reset(auio, NBOFF(bp) + off, UIO_SYSSPACE, UIO_WRITE);
			uio_addiov(auio, CAST_USER_ADDR_T(bp->nb_data + off), len);
			error = nfs_write_rpc2(np, auio, thd, cred, &iomode2, &bp->nb_verf);
			if (error)
				break;
			if (iomode2 < commit) /* Retain the lowest commitment level returned. */
				commit = iomode2;
			if ((commit != NFS_WRITE_FILESYNC) && (wverf != bp->nb_verf)) {
				/* verifier changed, redo all the writes filesync */
				iomode = NFS_WRITE_FILESYNC;
				goto again;
			}
		}
		/* clear dirty bits */
		while (count--) {
			dirty &= ~(1 << pg);
			if (count) /* leave pg on last page */
				pg++;
		}
	}
	CLR(bp->nb_flags, NB_WRITEINPROG);

	if (!error && (commit != NFS_WRITE_FILESYNC)) {
		error = nmp->nm_funcs->nf_commit_rpc(np, NBOFF(bp), bp->nb_bufsize, cred, wverf);
		if (error == NFSERR_STALEWRITEVERF) {
			/* verifier changed, so we need to restart all the writes */
			iomode = NFS_WRITE_FILESYNC;
			goto again;
		}
	}
	if (!error) {
		bp->nb_dirty = dirty;
	} else {
		SET(bp->nb_flags, NB_ERROR);
		bp->nb_error = error;
	}
	return (error);
}

/*
 * initiate the NFS WRITE RPC(s) for a buffer
 */
int
nfs_buf_write_rpc(struct nfsbuf *bp, int iomode, thread_t thd, kauth_cred_t cred)
{
	struct nfsmount *nmp;
	nfsnode_t np = bp->nb_np;
	int error = 0, nfsvers, async;
	int offset, nrpcs;
	uint32_t nmwsize, length, len;
	struct nfsreq *req;
	struct nfsreq_cbinfo cb;
	uio_t auio;
	char uio_buf [ UIO_SIZEOF(1) ];

	nmp = NFSTONMP(np);
	if (!nmp) {
		bp->nb_error = error = ENXIO;
		SET(bp->nb_flags, NB_ERROR);
		nfs_buf_iodone(bp);
		return (error);
	}
	nfsvers = nmp->nm_vers;
	nmwsize = nmp->nm_wsize;

	offset = bp->nb_offio;
	length = bp->nb_endio - bp->nb_offio;

	/* Note: Can only do async I/O if nfsiods are configured. */
	async = (bp->nb_flags & NB_ASYNC) && (NFSIOD_MAX > 0);
	bp->nb_commitlevel = NFS_WRITE_FILESYNC;
	cb.rcb_func = async ? nfs_buf_write_rpc_finish : NULL;
	cb.rcb_bp = bp;

	if ((nfsvers == NFS_VER2) && ((NBOFF(bp) + bp->nb_endio) > 0xffffffffLL)) {
		bp->nb_error = error = EFBIG;
		SET(bp->nb_flags, NB_ERROR);
		nfs_buf_iodone(bp);
		return (error);
	}

	auio = uio_createwithbuffer(1, NBOFF(bp) + offset, UIO_SYSSPACE,
		UIO_WRITE, &uio_buf, sizeof(uio_buf));
	uio_addiov(auio, CAST_USER_ADDR_T(bp->nb_data + offset), length);

	bp->nb_rpcs = nrpcs = (length + nmwsize - 1) / nmwsize;
	if (async && (nrpcs > 1)) {
		SET(bp->nb_flags, NB_MULTASYNCRPC);
	} else {
		CLR(bp->nb_flags, NB_MULTASYNCRPC);
	}

	while (length > 0) {
		if (ISSET(bp->nb_flags, NB_ERROR)) {
			error = bp->nb_error;
			break;
		}
		len = (length > nmwsize) ? nmwsize : length;
		cb.rcb_args[0] = offset;
		cb.rcb_args[1] = len;
		if (nmp->nm_vers >= NFS_VER4)
			cb.rcb_args[2] = nmp->nm_stategenid;
		if (async && ((error = nfs_async_write_start(nmp))))
			break;
		req = NULL;
		error = nmp->nm_funcs->nf_write_rpc_async(np, auio, len, thd, cred,
				iomode, &cb, &req);
		if (error) {
			if (async)
				nfs_async_write_done(nmp);
			break;
		}
		offset += len;
		length -= len;
		if (async)
			continue;
		nfs_buf_write_rpc_finish(req);
	}

	if (length > 0) {
		/*
		 * Something bad happened while trying to send the RPCs.
		 * Wait for any outstanding requests to complete.
		 */
		bp->nb_error = error;
		SET(bp->nb_flags, NB_ERROR);
		if (ISSET(bp->nb_flags, NB_MULTASYNCRPC)) {
			nrpcs = (length + nmwsize - 1) / nmwsize;
			lck_mtx_lock(nfs_buf_mutex);
			bp->nb_rpcs -= nrpcs;
			if (bp->nb_rpcs == 0) {
				/* No RPCs left, so the buffer's done */
				lck_mtx_unlock(nfs_buf_mutex);
				nfs_buf_write_finish(bp, thd, cred);
			} else {
				/* wait for the last RPC to mark it done */
				while (bp->nb_rpcs > 0)
					msleep(&bp->nb_rpcs, nfs_buf_mutex, 0,
						"nfs_buf_write_rpc_cancel", NULL);
				lck_mtx_unlock(nfs_buf_mutex);
			}
		} else {
			nfs_buf_write_finish(bp, thd, cred);
		}
		/* It may have just been an interrupt... that's OK */
		if (!ISSET(bp->nb_flags, NB_ERROR))
			error = 0;
	}

	return (error);
}

/*
 * finish up an NFS WRITE RPC on a buffer
 */
void
nfs_buf_write_rpc_finish(struct nfsreq *req)
{
	int error = 0, nfsvers, offset, length, multasyncrpc, finished;
	int committed = NFS_WRITE_FILESYNC;
	uint64_t wverf = 0;
	size_t rlen;
	void *wakeme = NULL;
	struct nfsreq_cbinfo cb;
	struct nfsreq *wreq = NULL;
	struct nfsbuf *bp;
	struct nfsmount *nmp;
	nfsnode_t np;
	thread_t thd;
	kauth_cred_t cred;
	uio_t auio;
	char uio_buf [ UIO_SIZEOF(1) ];

finish:
	np = req->r_np;
	thd = req->r_thread;
	cred = req->r_cred;
	if (IS_VALID_CRED(cred))
		kauth_cred_ref(cred);
	cb = req->r_callback;
	bp = cb.rcb_bp;
	if (cb.rcb_func) /* take an extra reference on the nfsreq in case we want to resend it later due to grace error */
		nfs_request_ref(req, 0);

	nmp = NFSTONMP(np);
	if (!nmp) {
		SET(bp->nb_flags, NB_ERROR);
		bp->nb_error = error = ENXIO;
	}
	if (error || ISSET(bp->nb_flags, NB_ERROR)) {
		/* just drop it */
		nfs_request_async_cancel(req);
		goto out;
	}
	nfsvers = nmp->nm_vers;

	offset = cb.rcb_args[0];
	rlen = length = cb.rcb_args[1];

	/* finish the RPC */
	error = nmp->nm_funcs->nf_write_rpc_async_finish(np, req, &committed, &rlen, &wverf);
	if ((error == EINPROGRESS) && cb.rcb_func) {
		/* async request restarted */
		if (cb.rcb_func)
			nfs_request_rele(req);
		if (IS_VALID_CRED(cred))
			kauth_cred_unref(&cred);
		return;
	}
	if ((nmp->nm_vers >= NFS_VER4) && nfs_mount_state_error_should_restart(error) && !ISSET(bp->nb_flags, NB_ERROR)) {
		lck_mtx_lock(&nmp->nm_lock);
		if ((error != NFSERR_OLD_STATEID) && (error != NFSERR_GRACE) && (cb.rcb_args[2] == nmp->nm_stategenid)) {
			NP(np, "nfs_buf_write_rpc_finish: error %d @ 0x%llx, 0x%x 0x%x, initiating recovery",
				error, NBOFF(bp)+offset, cb.rcb_args[2], nmp->nm_stategenid);
			nfs_need_recover(nmp, error);
		}
		lck_mtx_unlock(&nmp->nm_lock);
		if (np->n_flag & NREVOKE) {
			error = EIO;
		} else {
			if (error == NFSERR_GRACE) {
				if (cb.rcb_func) {
					/*
					 * For an async I/O request, handle a grace delay just like
					 * jukebox errors.  Set the resend time and queue it up.
					 */
					struct timeval now;
					if (req->r_nmrep.nmc_mhead) {
						mbuf_freem(req->r_nmrep.nmc_mhead);
						req->r_nmrep.nmc_mhead = NULL;
					}
					req->r_error = 0;
					microuptime(&now);
					lck_mtx_lock(&req->r_mtx);
					req->r_resendtime = now.tv_sec + 2;
					req->r_xid = 0;                 // get a new XID
					req->r_flags |= R_RESTART;
					req->r_start = 0;
					nfs_asyncio_resend(req);
					lck_mtx_unlock(&req->r_mtx);
					if (IS_VALID_CRED(cred))
						kauth_cred_unref(&cred);
					/* Note: nfsreq reference taken will be dropped later when finished */
					return;
				}
				/* otherwise, just pause a couple seconds and retry */
				tsleep(&nmp->nm_state, (PZERO-1), "nfsgrace", 2*hz);
			}
			if (!(error = nfs_mount_state_wait_for_recovery(nmp))) {
				rlen = 0;
				goto writeagain;
			}
		}
	}
	if (error) {
		SET(bp->nb_flags, NB_ERROR);
		bp->nb_error = error;
	}
	if (error || (nfsvers == NFS_VER2))
		goto out;
	if (rlen <= 0) {
		SET(bp->nb_flags, NB_ERROR);
		bp->nb_error = error = EIO;
		goto out;
	}

	/* save lowest commit level returned */
	if (committed < bp->nb_commitlevel)
		bp->nb_commitlevel = committed;

	/* check the write verifier */
	if (!bp->nb_verf) {
		bp->nb_verf = wverf;
	} else if (bp->nb_verf != wverf) {
		/* verifier changed, so buffer will need to be rewritten */
		bp->nb_flags |= NB_STALEWVERF;
		bp->nb_commitlevel = NFS_WRITE_UNSTABLE;
		bp->nb_verf = wverf;
	}

	/*
	 * check for a short write
	 *
	 * If the server didn't write all the data, then we
	 * need to issue another write for the rest of it.
	 * (Don't bother if the buffer hit an error or stale wverf.)
	 */
	if (((int)rlen < length) && !(bp->nb_flags & (NB_STALEWVERF|NB_ERROR))) {
writeagain:
		offset += rlen;
		length -= rlen;

		auio = uio_createwithbuffer(1, NBOFF(bp) + offset, UIO_SYSSPACE,
			UIO_WRITE, &uio_buf, sizeof(uio_buf));
		uio_addiov(auio, CAST_USER_ADDR_T(bp->nb_data + offset), length);

		cb.rcb_args[0] = offset;
		cb.rcb_args[1] = length;
		if (nmp->nm_vers >= NFS_VER4)
			cb.rcb_args[2] = nmp->nm_stategenid;

		// XXX iomode should really match the original request
		error = nmp->nm_funcs->nf_write_rpc_async(np, auio, length, thd, cred,
				NFS_WRITE_FILESYNC, &cb, &wreq);
		if (!error) {
			if (IS_VALID_CRED(cred))
				kauth_cred_unref(&cred);
			if (!cb.rcb_func) {
				/* if !async we'll need to wait for this RPC to finish */
				req = wreq;
				wreq = NULL;
				goto finish;
			}
			nfs_request_rele(req);
			/*
			 * We're done here.
			 * Outstanding RPC count is unchanged.
			 * Callback will be called when RPC is done.
			 */
			return;
		}
		SET(bp->nb_flags, NB_ERROR);
		bp->nb_error = error;
	}

out:
	if (cb.rcb_func) {
		nfs_async_write_done(nmp);
		nfs_request_rele(req);
	}
	/*
	 * Decrement outstanding RPC count on buffer
	 * and call nfs_buf_write_finish on last RPC.
	 *
	 * (Note: when there are multiple async RPCs issued for a
	 * buffer we need nfs_buffer_mutex to avoid problems when
	 * aborting a partially-initiated set of RPCs)
	 */
	multasyncrpc = ISSET(bp->nb_flags, NB_MULTASYNCRPC);
	if (multasyncrpc)
		lck_mtx_lock(nfs_buf_mutex);

	bp->nb_rpcs--;
	finished = (bp->nb_rpcs == 0);

	if (multasyncrpc)
		lck_mtx_unlock(nfs_buf_mutex);

	if (finished) {
		if (multasyncrpc)
			wakeme = &bp->nb_rpcs;
		nfs_buf_write_finish(bp, thd, cred);
		if (wakeme)
			wakeup(wakeme);
	}

	if (IS_VALID_CRED(cred))
		kauth_cred_unref(&cred);
}

/*
 * Send commit(s) for the given node's "needcommit" buffers 
 */
int
nfs_flushcommits(nfsnode_t np, int nowait)
{
	struct nfsmount *nmp;
	struct nfsbuf *bp, *prevlbp, *lbp;
	struct nfsbuflists blist, commitlist;
	int error = 0, retv, wcred_set, flags, dirty;
	u_quad_t off, endoff, toff;
	uint64_t wverf;
	u_int32_t count;
	kauth_cred_t wcred = NULL;

	FSDBG_TOP(557, np, 0, 0, 0);

	/*
	 * A nb_flags == (NB_DELWRI | NB_NEEDCOMMIT) block has been written to the
	 * server, but nas not been committed to stable storage on the server
	 * yet. The byte range is worked out for as many nfsbufs as we can handle
	 * and the commit rpc is done.
	 */
	if (!LIST_EMPTY(&np->n_dirtyblkhd)) {
		error = nfs_node_lock(np);
		if (error)
			goto done;
		np->n_flag |= NMODIFIED;
		nfs_node_unlock(np);
	}

	off = (u_quad_t)-1;
	endoff = 0;
	wcred_set = 0;
	LIST_INIT(&commitlist);

	nmp = NFSTONMP(np);
	if (!nmp) {
		error = ENXIO;
		goto done;
	}
	if (nmp->nm_vers == NFS_VER2) {
		error = EINVAL;
		goto done;
	}

	flags = NBI_DIRTY;
	if (nowait)
		flags |= NBI_NOWAIT;
	lck_mtx_lock(nfs_buf_mutex);
	wverf = nmp->nm_verf;
	if (!nfs_buf_iterprepare(np, &blist, flags)) {
		while ((bp = LIST_FIRST(&blist))) {
			LIST_REMOVE(bp, nb_vnbufs);
			LIST_INSERT_HEAD(&np->n_dirtyblkhd, bp, nb_vnbufs);
			error = nfs_buf_acquire(bp, NBAC_NOWAIT, 0, 0);
			if (error)
				continue;
			if (ISSET(bp->nb_flags, NB_NEEDCOMMIT))
				nfs_buf_check_write_verifier(np, bp);
			if (((bp->nb_flags & (NB_DELWRI | NB_NEEDCOMMIT)) != (NB_DELWRI | NB_NEEDCOMMIT)) ||
			    (bp->nb_verf != wverf)) {
				nfs_buf_drop(bp);
				continue;
			}
			nfs_buf_remfree(bp);

			/* buffer UPLs will be grabbed *in order* below */

			FSDBG(557, bp, bp->nb_flags, bp->nb_valid, bp->nb_dirty);
			FSDBG(557, bp->nb_validoff, bp->nb_validend,
			      bp->nb_dirtyoff, bp->nb_dirtyend);

			/*
			 * Work out if all buffers are using the same cred
			 * so we can deal with them all with one commit.
			 *
			 * Note: creds in bp's must be obtained by kauth_cred_ref
			 * on the same original cred in order for them to be equal.
			 */
			if (wcred_set == 0) {
				wcred = bp->nb_wcred;
				if (!IS_VALID_CRED(wcred))
					panic("nfs: needcommit w/out wcred");
				wcred_set = 1;
			} else if ((wcred_set == 1) && wcred != bp->nb_wcred) {
				wcred_set = -1;
			}
			SET(bp->nb_flags, NB_WRITEINPROG);

			/*
			 * Add this buffer to the list of buffers we are committing.
			 * Buffers are inserted into the list in ascending order so that
			 * we can take the UPLs in order after the list is complete.
			 */
			prevlbp = NULL;
			LIST_FOREACH(lbp, &commitlist, nb_vnbufs) {
				if (bp->nb_lblkno < lbp->nb_lblkno)
					break;
				prevlbp = lbp;
			}
			LIST_REMOVE(bp, nb_vnbufs);
			if (prevlbp)
				LIST_INSERT_AFTER(prevlbp, bp, nb_vnbufs);
			else
				LIST_INSERT_HEAD(&commitlist, bp, nb_vnbufs);

			/* update commit range start, end */
			toff = NBOFF(bp) + bp->nb_dirtyoff;
			if (toff < off)
				off = toff;
			toff += (u_quad_t)(bp->nb_dirtyend - bp->nb_dirtyoff);
			if (toff > endoff)
				endoff = toff;
		}
		nfs_buf_itercomplete(np, &blist, NBI_DIRTY);
	}
	lck_mtx_unlock(nfs_buf_mutex);

	if (LIST_EMPTY(&commitlist)) {
		error = ENOBUFS;
		goto done;
	}

	/*
	 * We need a UPL to prevent others from accessing the buffers during
	 * our commit RPC(s).
	 *
	 * We used to also check for dirty pages here; if there were any we'd
	 * abort the commit and force the entire buffer to be written again.
	 * Instead of doing that, we just go ahead and commit the dirty range,
	 * and then leave the buffer around with dirty pages that will be
	 * written out later.
	 */
	LIST_FOREACH(bp, &commitlist, nb_vnbufs) {
		if (!ISSET(bp->nb_flags, NB_PAGELIST)) {
			retv = nfs_buf_upl_setup(bp);
			if (retv) {
				/* Unable to create the UPL, the VM object probably no longer exists. */
				printf("nfs_flushcommits: upl create failed %d\n", retv);
				bp->nb_valid = bp->nb_dirty = 0;
			}
		}
		nfs_buf_upl_check(bp);
	}

	/*
	 * Commit data on the server, as required.
	 * If all bufs are using the same wcred, then use that with
	 * one call for all of them, otherwise commit each one
	 * separately.
	 */
	if (wcred_set == 1) {
		/*
		 * Note, it's possible the commit range could be >2^32-1.
		 * If it is, we'll send one commit that covers the whole file.
		 */
		if ((endoff - off) > 0xffffffff)
			count = 0;
		else
			count = (endoff - off);
		retv = nmp->nm_funcs->nf_commit_rpc(np, off, count, wcred, wverf);
	} else {
		retv = 0;
		LIST_FOREACH(bp, &commitlist, nb_vnbufs) {
			toff = NBOFF(bp) + bp->nb_dirtyoff;
			count = bp->nb_dirtyend - bp->nb_dirtyoff;
			retv = nmp->nm_funcs->nf_commit_rpc(np, toff, count, bp->nb_wcred, wverf);
			if (retv)
				break;
		}
	}

	/*
	 * Now, either mark the blocks I/O done or mark the
	 * blocks dirty, depending on whether the commit
	 * succeeded.
	 */
	while ((bp = LIST_FIRST(&commitlist))) {
		LIST_REMOVE(bp, nb_vnbufs);
		FSDBG(557, bp, retv, bp->nb_flags, bp->nb_dirty);
		nfs_node_lock_force(np);
		CLR(bp->nb_flags, (NB_NEEDCOMMIT | NB_WRITEINPROG));
		np->n_needcommitcnt--;
		CHECK_NEEDCOMMITCNT(np);
		nfs_node_unlock(np);

		if (retv) {
			/* move back to dirty list */
			lck_mtx_lock(nfs_buf_mutex);
			LIST_INSERT_HEAD(&np->n_dirtyblkhd, bp, nb_vnbufs);
			lck_mtx_unlock(nfs_buf_mutex);
			nfs_buf_release(bp, 1);
			continue;
		}

		nfs_node_lock_force(np);
		np->n_numoutput++;
		nfs_node_unlock(np);
		vnode_startwrite(NFSTOV(np));
		if (ISSET(bp->nb_flags, NB_DELWRI)) {
			lck_mtx_lock(nfs_buf_mutex);
			nfs_nbdwrite--;
			NFSBUFCNTCHK();
			lck_mtx_unlock(nfs_buf_mutex);
			wakeup(&nfs_nbdwrite);
		}
		CLR(bp->nb_flags, (NB_READ|NB_DONE|NB_ERROR|NB_DELWRI));
		/* if block still has dirty pages, we don't want it to */
		/* be released in nfs_buf_iodone().  So, don't set NB_ASYNC. */
		if (!(dirty = bp->nb_dirty))
			SET(bp->nb_flags, NB_ASYNC);
		else
			CLR(bp->nb_flags, NB_ASYNC);

		/* move to clean list */
		lck_mtx_lock(nfs_buf_mutex);
		LIST_INSERT_HEAD(&np->n_cleanblkhd, bp, nb_vnbufs);
		lck_mtx_unlock(nfs_buf_mutex);

		bp->nb_dirtyoff = bp->nb_dirtyend = 0;

		nfs_buf_iodone(bp);
		if (dirty) {
			/* throw it back in as a delayed write buffer */
			CLR(bp->nb_flags, NB_DONE);
			nfs_buf_write_delayed(bp);
		}
	}

done:
	FSDBG_BOT(557, np, 0, 0, error);
	return (error);
}

/*
 * Flush all the blocks associated with a vnode.
 * 	Walk through the buffer pool and push any dirty pages
 *	associated with the vnode.
 */
int
nfs_flush(nfsnode_t np, int waitfor, thread_t thd, int ignore_writeerr)
{
	struct nfsbuf *bp;
	struct nfsbuflists blist;
	struct nfsmount *nmp = NFSTONMP(np);
	int error = 0, error2, slptimeo = 0, slpflag = 0;
	int nfsvers, flags, passone = 1;

	FSDBG_TOP(517, np, waitfor, ignore_writeerr, 0);

	if (!nmp) {
		error = ENXIO;
		goto out;
	}
	nfsvers = nmp->nm_vers;
	if (NMFLAG(nmp, INTR))
		slpflag = PCATCH;

	if (!LIST_EMPTY(&np->n_dirtyblkhd)) {
		nfs_node_lock_force(np);
		np->n_flag |= NMODIFIED;
		nfs_node_unlock(np);
	}

	lck_mtx_lock(nfs_buf_mutex);
	while (np->n_bflag & NBFLUSHINPROG) {
		np->n_bflag |= NBFLUSHWANT;
		error = msleep(&np->n_bflag, nfs_buf_mutex, slpflag, "nfs_flush", NULL);
		if ((error && (error != EWOULDBLOCK)) ||
		    ((error = nfs_sigintr(NFSTONMP(np), NULL, thd, 0)))) {
			lck_mtx_unlock(nfs_buf_mutex);
			goto out;
		}
	}
	np->n_bflag |= NBFLUSHINPROG;

	/*
	 * On the first pass, start async/unstable writes on all
	 * delayed write buffers.  Then wait for all writes to complete
	 * and call nfs_flushcommits() to commit any uncommitted buffers.
	 * On all subsequent passes, start STABLE writes on any remaining
	 * dirty buffers.  Then wait for all writes to complete.
	 */
again:
	FSDBG(518, LIST_FIRST(&np->n_dirtyblkhd), np->n_flag, 0, 0);
	if (!NFSTONMP(np)) {
		lck_mtx_unlock(nfs_buf_mutex);
		error = ENXIO;
		goto done;
	}

	/* Start/do any write(s) that are required. */
	if (!nfs_buf_iterprepare(np, &blist, NBI_DIRTY)) {
		while ((bp = LIST_FIRST(&blist))) {
			LIST_REMOVE(bp, nb_vnbufs);
			LIST_INSERT_HEAD(&np->n_dirtyblkhd, bp, nb_vnbufs);
			flags = (passone || !(waitfor == MNT_WAIT || waitfor == MNT_DWAIT)) ? NBAC_NOWAIT : 0;
			if (flags != NBAC_NOWAIT)
				nfs_buf_refget(bp);
			while ((error = nfs_buf_acquire(bp, flags, slpflag, slptimeo))) {
				FSDBG(524, bp, flags, bp->nb_lflags, bp->nb_flags);
				if (error == EBUSY)
					break;
				if (error) {
					error2 = nfs_sigintr(NFSTONMP(np), NULL, thd, 0);
					if (error2) {
						if (flags != NBAC_NOWAIT)
							nfs_buf_refrele(bp);
						nfs_buf_itercomplete(np, &blist, NBI_DIRTY);
						lck_mtx_unlock(nfs_buf_mutex);
						error = error2;
						goto done;
					}
					if (slpflag == PCATCH) {
						slpflag = 0;
						slptimeo = 2 * hz;
					}
				}
			}
			if (flags != NBAC_NOWAIT)
				nfs_buf_refrele(bp);
			if (error == EBUSY)
				continue;
			if (!bp->nb_np) {
				/* buffer is no longer valid */
				nfs_buf_drop(bp);
				continue;
			}
			if (ISSET(bp->nb_flags, NB_NEEDCOMMIT))
				nfs_buf_check_write_verifier(np, bp);
			if (!ISSET(bp->nb_flags, NB_DELWRI)) {
				/* buffer is no longer dirty */
				nfs_buf_drop(bp);
				continue;
			}
			FSDBG(525, bp, passone, bp->nb_lflags, bp->nb_flags);
			if ((passone || !(waitfor == MNT_WAIT || waitfor == MNT_DWAIT)) &&
			    ISSET(bp->nb_flags, NB_NEEDCOMMIT)) {
				nfs_buf_drop(bp);
				continue;
			}
			nfs_buf_remfree(bp);
			lck_mtx_unlock(nfs_buf_mutex);
			if (ISSET(bp->nb_flags, NB_ERROR)) {
				nfs_node_lock_force(np);
				np->n_error = bp->nb_error ? bp->nb_error : EIO;
				np->n_flag |= NWRITEERR;
				nfs_node_unlock(np);
				nfs_buf_release(bp, 1);
				lck_mtx_lock(nfs_buf_mutex);
				continue;
			}
			SET(bp->nb_flags, NB_ASYNC);
			if (!passone) {
				/* NB_STABLE forces this to be written FILESYNC */
				SET(bp->nb_flags, NB_STABLE);
			}
			nfs_buf_write(bp);
			lck_mtx_lock(nfs_buf_mutex);
		}
		nfs_buf_itercomplete(np, &blist, NBI_DIRTY);
	}
	lck_mtx_unlock(nfs_buf_mutex);

	if (waitfor == MNT_WAIT || waitfor == MNT_DWAIT) {
	        while ((error = vnode_waitforwrites(NFSTOV(np), 0, slpflag, slptimeo, "nfsflush"))) {
		        error2 = nfs_sigintr(NFSTONMP(np), NULL, thd, 0);
			if (error2) {
			        error = error2;
				goto done;
			}
			if (slpflag == PCATCH) {
				slpflag = 0;
				slptimeo = 2 * hz;
			}
		}
	}

	if (nfsvers != NFS_VER2) {
		/* loop while it looks like there are still buffers to be */
		/* commited and nfs_flushcommits() seems to be handling them. */
		while (np->n_needcommitcnt)
			if (nfs_flushcommits(np, 0))
				break;
	}

	if (passone) {
		passone = 0;
		if (!LIST_EMPTY(&np->n_dirtyblkhd)) {
			nfs_node_lock_force(np);
			np->n_flag |= NMODIFIED;
			nfs_node_unlock(np);
		}
		lck_mtx_lock(nfs_buf_mutex);
		goto again;
	}

	if (waitfor == MNT_WAIT || waitfor == MNT_DWAIT) {
		if (!LIST_EMPTY(&np->n_dirtyblkhd)) {
			nfs_node_lock_force(np);
			np->n_flag |= NMODIFIED;
			nfs_node_unlock(np);
		}
		lck_mtx_lock(nfs_buf_mutex);
		if (!LIST_EMPTY(&np->n_dirtyblkhd))
			goto again;
		lck_mtx_unlock(nfs_buf_mutex);
		nfs_node_lock_force(np);
		/*
		 * OK, it looks like there are no dirty blocks.  If we have no
		 * writes in flight and no one in the write code, we can clear
		 * the modified flag.  In order to make sure we see the latest
		 * attributes and size, we also invalidate the attributes and
		 * advance the attribute cache XID to guarantee that attributes
		 * newer than our clearing of NMODIFIED will get loaded next.
		 * (If we don't do this, it's possible for the flush's final
		 * write/commit (xid1) to be executed in parallel with a subsequent
		 * getattr request (xid2).  The getattr could return attributes
		 * from *before* the write/commit completed but the stale attributes
		 * would be preferred because of the xid ordering.)
		 */
		if (!np->n_wrbusy && !np->n_numoutput) {
			np->n_flag &= ~NMODIFIED;
			NATTRINVALIDATE(np);
			nfs_get_xid(&np->n_xid);
		}
	} else {
		nfs_node_lock_force(np);
	}

	FSDBG(526, np->n_flag, np->n_error, 0, 0);
	if (!ignore_writeerr && (np->n_flag & NWRITEERR)) {
		error = np->n_error;
		np->n_flag &= ~NWRITEERR;
	}
	nfs_node_unlock(np);
done:
	lck_mtx_lock(nfs_buf_mutex);
	flags = np->n_bflag;
	np->n_bflag &= ~(NBFLUSHINPROG|NBFLUSHWANT);
	lck_mtx_unlock(nfs_buf_mutex);
	if (flags & NBFLUSHWANT)
		wakeup(&np->n_bflag);
out:
	FSDBG_BOT(517, np, error, ignore_writeerr, 0);
	return (error);
}

/*
 * Flush out and invalidate all buffers associated with a vnode.
 * Called with the underlying object locked.
 */
int
nfs_vinvalbuf_internal(
	nfsnode_t np,
	int flags,
	thread_t thd,
	kauth_cred_t cred,
	int slpflag,
	int slptimeo)
{
	struct nfsbuf *bp;
	struct nfsbuflists blist;
	int list, error = 0;

	if (flags & V_SAVE) {
		if ((error = nfs_flush(np, MNT_WAIT, thd, (flags & V_IGNORE_WRITEERR))))
			return (error);
	}

	lck_mtx_lock(nfs_buf_mutex);
	for (;;) {
		list = NBI_CLEAN;
		if (nfs_buf_iterprepare(np, &blist, list)) {
			list = NBI_DIRTY;
			if (nfs_buf_iterprepare(np, &blist, list))
				break;
		}
		while ((bp = LIST_FIRST(&blist))) {
			LIST_REMOVE(bp, nb_vnbufs);
			if (list == NBI_CLEAN)
				LIST_INSERT_HEAD(&np->n_cleanblkhd, bp, nb_vnbufs);
			else
				LIST_INSERT_HEAD(&np->n_dirtyblkhd, bp, nb_vnbufs);
			nfs_buf_refget(bp);
			while ((error = nfs_buf_acquire(bp, NBAC_REMOVE, slpflag, slptimeo))) {
				FSDBG(556, np, bp, NBOFF(bp), bp->nb_flags);
				if (error != EAGAIN) {
					FSDBG(554, np, bp, -1, error);
					nfs_buf_refrele(bp);
					nfs_buf_itercomplete(np, &blist, list);
					lck_mtx_unlock(nfs_buf_mutex);
					return (error);
				}
			}
			nfs_buf_refrele(bp);
			FSDBG(554, np, bp, NBOFF(bp), bp->nb_flags);
			lck_mtx_unlock(nfs_buf_mutex);
			if ((flags & V_SAVE) && UBCINFOEXISTS(NFSTOV(np)) && bp->nb_np &&
			    (NBOFF(bp) < (off_t)np->n_size)) {
				/* extra paranoia: make sure we're not */
				/* somehow leaving any dirty data around */
				int mustwrite = 0;
				int end = (NBOFF(bp) + bp->nb_bufsize > (off_t)np->n_size) ?
				    ((off_t)np->n_size - NBOFF(bp)) : bp->nb_bufsize;
				if (!ISSET(bp->nb_flags, NB_PAGELIST)) {
					error = nfs_buf_upl_setup(bp);
					if (error == EINVAL) {
						/* vm object must no longer exist */
						/* hopefully we don't need to do */
						/* anything for this buffer */
					} else if (error)
						printf("nfs_vinvalbuf: upl setup failed %d\n", error);
					bp->nb_valid = bp->nb_dirty = 0;
				}
				nfs_buf_upl_check(bp);
				/* check for any dirty data before the EOF */
				if ((bp->nb_dirtyend > 0) && (bp->nb_dirtyoff < end)) {
					/* clip dirty range to EOF */
					if (bp->nb_dirtyend > end) {
						bp->nb_dirtyend = end;
						if (bp->nb_dirtyoff >= bp->nb_dirtyend)
							bp->nb_dirtyoff = bp->nb_dirtyend = 0;
					}
					if ((bp->nb_dirtyend > 0) && (bp->nb_dirtyoff < end))
						mustwrite++;
				}
				bp->nb_dirty &= (1 << (round_page_32(end)/PAGE_SIZE)) - 1;
				if (bp->nb_dirty)
					mustwrite++;
				/* also make sure we'll have a credential to do the write */
				if (mustwrite && !IS_VALID_CRED(bp->nb_wcred) && !IS_VALID_CRED(cred)) {
					printf("nfs_vinvalbuf: found dirty buffer with no write creds\n");
					mustwrite = 0;
				}
				if (mustwrite) {
					FSDBG(554, np, bp, 0xd00dee, bp->nb_flags);
					if (!ISSET(bp->nb_flags, NB_PAGELIST))
						panic("nfs_vinvalbuf: dirty buffer without upl");
					/* gotta write out dirty data before invalidating */
					/* (NB_STABLE indicates that data writes should be FILESYNC) */
					/* (NB_NOCACHE indicates buffer should be discarded) */
					CLR(bp->nb_flags, (NB_DONE | NB_ERROR | NB_INVAL | NB_ASYNC));
					SET(bp->nb_flags, NB_STABLE | NB_NOCACHE);
					if (!IS_VALID_CRED(bp->nb_wcred)) {
						kauth_cred_ref(cred);
						bp->nb_wcred = cred;
					}
					error = nfs_buf_write(bp);
					// Note: bp has been released
					if (error) {
						FSDBG(554, bp, 0xd00dee, 0xbad, error);
						nfs_node_lock_force(np);
						if ((error != EINTR) && (error != ERESTART)) {
							np->n_error = error;
							np->n_flag |= NWRITEERR;
						}
						/*
						 * There was a write error and we need to
						 * invalidate attrs to sync with server.
						 * (if this write was extending the file,
						 * we may no longer know the correct size)
						 */
						NATTRINVALIDATE(np);
						nfs_node_unlock(np);
						if ((error == EINTR) || (error == ERESTART)) {
							/*
							 * Abort on EINTR.  If we don't, we could
							 * be stuck in this loop forever because
							 * the buffer will continue to stay dirty.
							 */
							lck_mtx_lock(nfs_buf_mutex);
							nfs_buf_itercomplete(np, &blist, list);
							lck_mtx_unlock(nfs_buf_mutex);
							return (error);
						}
						error = 0;
					}
					lck_mtx_lock(nfs_buf_mutex);
					continue;
				}
			}
			SET(bp->nb_flags, NB_INVAL);
			// hold off on FREEUPs until we're done here
			nfs_buf_release(bp, 0);
			lck_mtx_lock(nfs_buf_mutex);
		}
		nfs_buf_itercomplete(np, &blist, list);
	}
	if (!LIST_EMPTY(&(np)->n_dirtyblkhd) || !LIST_EMPTY(&(np)->n_cleanblkhd))
		panic("nfs_vinvalbuf: flush/inval failed");
	lck_mtx_unlock(nfs_buf_mutex);
	nfs_node_lock_force(np);
	if (!(flags & V_SAVE))
		np->n_flag &= ~NMODIFIED;
	if (vnode_vtype(NFSTOV(np)) == VREG)
		np->n_lastrahead = -1;
	nfs_node_unlock(np);
	NFS_BUF_FREEUP();
	return (0);
}


/*
 * Flush and invalidate all dirty buffers. If another process is already
 * doing the flush, just wait for completion.
 */
int
nfs_vinvalbuf(vnode_t vp, int flags, vfs_context_t ctx, int intrflg)
{
	return nfs_vinvalbuf2(vp, flags, vfs_context_thread(ctx), vfs_context_ucred(ctx), intrflg);
}

int
nfs_vinvalbuf2(vnode_t vp, int flags, thread_t thd, kauth_cred_t cred, int intrflg)
{
	nfsnode_t np = VTONFS(vp);
	struct nfsmount *nmp = VTONMP(vp);
	int error, slpflag, slptimeo, nflags, retry = 0;
	struct timespec ts = { 2, 0 };
	off_t size;

	FSDBG_TOP(554, np, flags, intrflg, 0);

	if (nmp && !NMFLAG(nmp, INTR))
		intrflg = 0;
	if (intrflg) {
		slpflag = PCATCH;
		slptimeo = 2 * hz;
	} else {
		slpflag = 0;
		slptimeo = 0;
	}

	/* First wait for any other process doing a flush to complete.  */
	lck_mtx_lock(nfs_buf_mutex);
	while (np->n_bflag & NBINVALINPROG) {
		np->n_bflag |= NBINVALWANT;
		msleep(&np->n_bflag, nfs_buf_mutex, slpflag, "nfs_vinvalbuf", &ts);
		if ((error = nfs_sigintr(VTONMP(vp), NULL, thd, 0))) {
			lck_mtx_unlock(nfs_buf_mutex);
			return (error);
		}
		if (np->n_bflag & NBINVALINPROG)
			slpflag = 0;
	}
	np->n_bflag |= NBINVALINPROG;
	lck_mtx_unlock(nfs_buf_mutex);

	/* Now, flush as required.  */
again:
	error = nfs_vinvalbuf_internal(np, flags, thd, cred, slpflag, 0);
	while (error) {
		FSDBG(554, np, 0, 0, error);
		if ((error = nfs_sigintr(VTONMP(vp), NULL, thd, 0)))
			goto done;
		error = nfs_vinvalbuf_internal(np, flags, thd, cred, 0, slptimeo);
	}

	/* get the pages out of vm also */
	if (UBCINFOEXISTS(vp) && (size = ubc_getsize(vp)))
		if ((error = ubc_msync(vp, 0, size, NULL, UBC_PUSHALL | UBC_SYNC | UBC_INVALIDATE))) {
			if (error == EINVAL)
				panic("nfs_vinvalbuf(): ubc_msync failed!, error %d", error);
			if (retry++ < 10) /* retry invalidating a few times */
				goto again;
			/* give up */
			printf("nfs_vinvalbuf(): ubc_msync failed!, error %d", error);

		}
done:
	lck_mtx_lock(nfs_buf_mutex);
	nflags = np->n_bflag;
	np->n_bflag &= ~(NBINVALINPROG|NBINVALWANT);
	lck_mtx_unlock(nfs_buf_mutex);
	if (nflags & NBINVALWANT)
		wakeup(&np->n_bflag);

	FSDBG_BOT(554, np, flags, intrflg, error);
	return (error);
}

/*
 * Wait for any busy buffers to complete.
 */
void
nfs_wait_bufs(nfsnode_t np)
{
	struct nfsbuf *bp;
	struct nfsbuflists blist;
	int error = 0;

	lck_mtx_lock(nfs_buf_mutex);
	if (!nfs_buf_iterprepare(np, &blist, NBI_CLEAN)) {
		while ((bp = LIST_FIRST(&blist))) {
			LIST_REMOVE(bp, nb_vnbufs);
			LIST_INSERT_HEAD(&np->n_cleanblkhd, bp, nb_vnbufs);
			nfs_buf_refget(bp);
			while ((error = nfs_buf_acquire(bp, 0, 0, 0))) {
				if (error != EAGAIN) {
					nfs_buf_refrele(bp);
					nfs_buf_itercomplete(np, &blist, NBI_CLEAN);
					lck_mtx_unlock(nfs_buf_mutex);
					return;
				}
			}
			nfs_buf_refrele(bp);
			nfs_buf_drop(bp);
		}
		nfs_buf_itercomplete(np, &blist, NBI_CLEAN);
	}
	if (!nfs_buf_iterprepare(np, &blist, NBI_DIRTY)) {
		while ((bp = LIST_FIRST(&blist))) {
			LIST_REMOVE(bp, nb_vnbufs);
			LIST_INSERT_HEAD(&np->n_dirtyblkhd, bp, nb_vnbufs);
			nfs_buf_refget(bp);
			while ((error = nfs_buf_acquire(bp, 0, 0, 0))) {
				if (error != EAGAIN) {
					nfs_buf_refrele(bp);
					nfs_buf_itercomplete(np, &blist, NBI_DIRTY);
					lck_mtx_unlock(nfs_buf_mutex);
					return;
				}
			}
			nfs_buf_refrele(bp);
			nfs_buf_drop(bp);
		}
		nfs_buf_itercomplete(np, &blist, NBI_DIRTY);
	}
	lck_mtx_unlock(nfs_buf_mutex);
}


/*
 * Add an async I/O request to the mount's async I/O queue and make
 * sure that an nfsiod will service it.
 */
void
nfs_asyncio_finish(struct nfsreq *req)
{
	struct nfsmount *nmp;
	struct nfsiod *niod;
	int started = 0;

	FSDBG_TOP(552, nmp, 0, 0, 0);
again:
	if (((nmp = req->r_nmp)) == NULL)
		return;
	lck_mtx_lock(nfsiod_mutex);
	niod = nmp->nm_niod;

	/* grab an nfsiod if we don't have one already */
	if (!niod) {
		niod = TAILQ_FIRST(&nfsiodfree);
		if (niod) {
			TAILQ_REMOVE(&nfsiodfree, niod, niod_link);
			TAILQ_INSERT_TAIL(&nfsiodwork, niod, niod_link);
			niod->niod_nmp = nmp;
		} else if (((nfsiod_thread_count < NFSIOD_MAX) || (nfsiod_thread_count <= 0)) && (started < 4)) {
			/*
			 * Try starting a new thread.
			 * We may try a couple times if other callers
			 * get the new threads before we do.
			 */
			lck_mtx_unlock(nfsiod_mutex);
			started++;
			if (!nfsiod_start())
				goto again;
			lck_mtx_lock(nfsiod_mutex);
		}
	}

	if (req->r_achain.tqe_next == NFSREQNOLIST)
		TAILQ_INSERT_TAIL(&nmp->nm_iodq, req, r_achain);

	/* If this mount doesn't already have an nfsiod working on it... */
	if (!nmp->nm_niod) {
		if (niod) { /* give it the nfsiod we just grabbed */
			nmp->nm_niod = niod;
			lck_mtx_unlock(nfsiod_mutex);
			wakeup(niod);
		} else if (nfsiod_thread_count > 0) {
			/* just queue it up on nfsiod mounts queue */
			TAILQ_INSERT_TAIL(&nfsiodmounts, nmp, nm_iodlink);
			lck_mtx_unlock(nfsiod_mutex);
		} else {
			printf("nfs_asyncio(): no nfsiods? %d %d (%d)\n", nfsiod_thread_count, NFSIOD_MAX, started);
			lck_mtx_unlock(nfsiod_mutex);
			/* we have no other option but to be persistent */
			started = 0;
			goto again;
		}
	} else {
		lck_mtx_unlock(nfsiod_mutex);
	}

	FSDBG_BOT(552, nmp, 0, 0, 0);
}

/*
 * queue up async I/O request for resend
 */
void
nfs_asyncio_resend(struct nfsreq *req)
{
	struct nfsmount *nmp = req->r_nmp;

	if (!nmp)
		return;
	nfs_gss_clnt_rpcdone(req);
	lck_mtx_lock(&nmp->nm_lock);
	if (!(req->r_flags & R_RESENDQ)) {
		TAILQ_INSERT_TAIL(&nmp->nm_resendq, req, r_rchain);
		req->r_flags |= R_RESENDQ;
	}
	nfs_mount_sock_thread_wake(nmp);
	lck_mtx_unlock(&nmp->nm_lock);
}

/*
 * Read directory data into a buffer.
 *
 * Buffer will be filled (unless EOF is hit).
 * Buffers after this one may also be completely/partially filled.
 */
int
nfs_buf_readdir(struct nfsbuf *bp, vfs_context_t ctx)
{
	nfsnode_t np = bp->nb_np;
	struct nfsmount *nmp = NFSTONMP(np);
	int error = 0;

	if (!nmp)
		return (ENXIO);

	if (nmp->nm_vers < NFS_VER4)
		error = nfs3_readdir_rpc(np, bp, ctx);
	else
		error = nfs4_readdir_rpc(np, bp, ctx);

	if (error && (error != NFSERR_DIRBUFDROPPED)) {
		SET(bp->nb_flags, NB_ERROR);
		bp->nb_error = error;
	}
	return (error);
}
