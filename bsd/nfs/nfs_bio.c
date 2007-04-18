/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
#include <sys/sysctl.h>
#include <sys/ubc_internal.h>
#include <sys/uio_internal.h>

#include <sys/vm.h>
#include <sys/vmparam.h>

#include <sys/time.h>
#include <kern/clock.h>
#include <libkern/OSAtomic.h>
#include <kern/kalloc.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfsmount.h>
#include <nfs/nfsnode.h>
#include <sys/buf_internal.h>

#include <sys/kdebug.h>

#define FSDBG(A, B, C, D, E) \
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, (A))) | DBG_FUNC_NONE, \
		(int)(B), (int)(C), (int)(D), (int)(E), 0)
#define FSDBG_TOP(A, B, C, D, E) \
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, (A))) | DBG_FUNC_START, \
		(int)(B), (int)(C), (int)(D), (int)(E), 0)
#define FSDBG_BOT(A, B, C, D, E) \
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, (A))) | DBG_FUNC_END, \
		(int)(B), (int)(C), (int)(D), (int)(E), 0)

extern int nfs_numasync;
extern int nfs_ioddelwri;
extern struct nfsstats nfsstats;

#define	NFSBUFHASH(np, lbn)	\
	(&nfsbufhashtbl[((long)(np) / sizeof(*(np)) + (int)(lbn)) & nfsbufhash])
LIST_HEAD(nfsbufhashhead, nfsbuf) *nfsbufhashtbl;
struct nfsbuffreehead nfsbuffree, nfsbuffreemeta, nfsbufdelwri;
u_long nfsbufhash;
int nfsbufcnt, nfsbufmin, nfsbufmax, nfsbufmetacnt, nfsbufmetamax;
int nfsbuffreecnt, nfsbuffreemetacnt, nfsbufdelwricnt, nfsneedbuffer;
int nfs_nbdwrite;
time_t nfsbuffreeuptimestamp;

lck_grp_t *nfs_buf_lck_grp;
lck_grp_attr_t *nfs_buf_lck_grp_attr;
lck_attr_t *nfs_buf_lck_attr;
lck_mtx_t *nfs_buf_mutex;

#define NFSBUFWRITE_THROTTLE	9
#define NFSBUF_LRU_STALE	120
#define NFSBUF_META_STALE	240

/* number of nfsbufs nfs_buf_freeup() should attempt to free from nfsbuffree list */
#define LRU_TO_FREEUP			6
/* number of nfsbufs nfs_buf_freeup() should attempt to free from nfsbuffreemeta list */
#define META_TO_FREEUP			3
/* total number of nfsbufs nfs_buf_freeup() should attempt to free */
#define TOTAL_TO_FREEUP			(LRU_TO_FREEUP+META_TO_FREEUP)
/* fraction of nfsbufs nfs_buf_freeup() should attempt to free from nfsbuffree list when called from nfs_timer() */
#define LRU_FREEUP_FRAC_ON_TIMER	8
/* fraction of nfsbufs nfs_buf_freeup() should attempt to free from nfsbuffreemeta list when called from nfs_timer() */
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
	nfs_buf_lck_grp_attr = lck_grp_attr_alloc_init();
	lck_grp_attr_setstat(nfs_buf_lck_grp_attr);
	nfs_buf_lck_grp = lck_grp_alloc_init("nfs_buf", nfs_buf_lck_grp_attr);

	nfs_buf_lck_attr = lck_attr_alloc_init();

	nfs_buf_mutex = lck_mtx_alloc_init(nfs_buf_lck_grp, nfs_buf_lck_attr);

	nfsbufcnt = nfsbufmetacnt =
	nfsbuffreecnt = nfsbuffreemetacnt = nfsbufdelwricnt = 0;
	nfsbufmin = 128;
	nfsbufmax = (sane_size >> PAGE_SHIFT) / 4;
	nfsbufmetamax = (sane_size >> PAGE_SHIFT) / 16;
	nfsneedbuffer = 0;
	nfs_nbdwrite = 0;
	nfsbuffreeuptimestamp = 0;

	nfsbufhashtbl = hashinit(nfsbufmax/4, M_TEMP, &nfsbufhash);
	TAILQ_INIT(&nfsbuffree);
	TAILQ_INIT(&nfsbuffreemeta);
	TAILQ_INIT(&nfsbufdelwri);

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
	nfsbuffreeuptimestamp = now.tv_sec;

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
		/* disassociate buffer from any vnode */
		if (fbp->nb_vp) {
			if (fbp->nb_vnbufs.le_next != NFSNOLIST) {
				LIST_REMOVE(fbp, nb_vnbufs);
				fbp->nb_vnbufs.le_next = NFSNOLIST;
			}
			fbp->nb_vp = NULL;
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
		/* disassociate buffer from any vnode */
		if (fbp->nb_vp) {
			if (fbp->nb_vnbufs.le_next != NFSNOLIST) {
				LIST_REMOVE(fbp, nb_vnbufs);
				fbp->nb_vnbufs.le_next = NFSNOLIST;
			}
			fbp->nb_vp = NULL;
		}
		LIST_REMOVE(fbp, nb_hash);
		TAILQ_INSERT_TAIL(&nfsbuffreeup, fbp, nb_free);
		nfsbufcnt--;
		nfsbufmetacnt--;
	}

	FSDBG(320, nfsbufcnt, nfsbuffreecnt, nfsbuffreemetacnt, 0);
	NFSBUFCNTCHK(1);

	lck_mtx_unlock(nfs_buf_mutex);

	while ((fbp = TAILQ_FIRST(&nfsbuffreeup))) {
		TAILQ_REMOVE(&nfsbuffreeup, fbp, nb_free);
		/* nuke any creds */
		if (fbp->nb_rcred != NOCRED) {
			kauth_cred_rele(fbp->nb_rcred);
			fbp->nb_rcred = NOCRED;
		}
		if (fbp->nb_wcred != NOCRED) {
			kauth_cred_rele(fbp->nb_wcred);
			fbp->nb_wcred = NOCRED;
		}
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
	NFSBUFCNTCHK(1);
}

/*
 * check for existence of nfsbuf in cache
 */
boolean_t
nfs_buf_is_incore(vnode_t vp, daddr64_t blkno)
{
	boolean_t rv;
	lck_mtx_lock(nfs_buf_mutex);
	if (nfs_buf_incore(vp, blkno))
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
nfs_buf_incore(vnode_t vp, daddr64_t blkno)
{
	/* Search hash chain */
	struct nfsbuf * bp = NFSBUFHASH(VTONFS(vp), blkno)->lh_first;
	for (; bp != NULL; bp = bp->nb_hash.le_next)
		if (bp->nb_lblkno == blkno && bp->nb_vp == vp) {
			if (!ISSET(bp->nb_flags, NB_INVAL)) {
				FSDBG(547, bp, blkno, bp->nb_flags, bp->nb_vp);
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
	struct nfsbuf *bp;
	int error = 0;

	lck_mtx_lock(nfs_buf_mutex);
	bp = nfs_buf_incore(vp, ubc_offtoblk(vp, offset));
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
		if (bp->nb_dirtyend <= start ||
		    bp->nb_dirtyoff >= (start + PAGE_SIZE))
			error = 0;
		else
			error = EBUSY;
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
	if (! ISSET(bp->nb_flags, NB_READ)) {
		/*
		 * We're doing a "write", so we intend to modify
		 * the pages we're gathering.
		 */
		upl_flags |= UPL_WILL_MODIFY;
	}
	kret = ubc_create_upl(bp->nb_vp, NBOFF(bp), bp->nb_bufsize,
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

	FSDBG(538, bp, NBOFF(bp), bp->nb_bufsize, bp->nb_vp);

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
	filesize = ubc_getsize(bp->nb_vp);
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
		if (upl_dirty_page(pl, i)) {
			NBPGDIRTY_SET(bp, i);
			if (!ISSET(bp->nb_flags, NB_WASDIRTY))
				SET(bp->nb_flags, NB_WASDIRTY);
		}
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
static int
nfs_buf_map(struct nfsbuf *bp)
{
	kern_return_t kret;

	if (bp->nb_data)
		return (0);
	if (!ISSET(bp->nb_flags, NB_PAGELIST))
		return (EINVAL);

	kret = ubc_upl_map(bp->nb_pagelist, (vm_address_t *)&(bp->nb_data));
	if (kret != KERN_SUCCESS)
		panic("nfs_buf_map: ubc_upl_map() failed with (%d)", kret);
	if (bp->nb_data == 0)
		panic("ubc_upl_map mapped 0");
	FSDBG(540, bp, bp->nb_flags, NBOFF(bp), bp->nb_data);
	return (0);
}

/*
 * check range of pages in nfsbuf's UPL for validity
 */
static int
nfs_buf_upl_valid_range(struct nfsbuf *bp, int off, int size)
{
	off_t fileoffset, filesize;
	int pg, lastpg;
	upl_page_info_t *pl;

	if (!ISSET(bp->nb_flags, NB_PAGELIST))
		return (0);
	pl = ubc_upl_pageinfo(bp->nb_pagelist);

	size += off & PAGE_MASK;
	off &= ~PAGE_MASK;
	fileoffset = NBOFF(bp);
	filesize = VTONFS(bp->nb_vp)->n_size;
	if ((fileoffset + off + size) > filesize)
		size = filesize - (fileoffset + off);

	pg = off/PAGE_SIZE;
	lastpg = (off + size - 1)/PAGE_SIZE;
	while (pg <= lastpg) {
		if (!upl_valid_page(pl, pg))
			return (0);
		pg++;
	}
	return (1);
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
static void
nfs_buf_normalize_valid_range(struct nfsnode *np, struct nfsbuf *bp)
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
 * try to push out some delayed/uncommitted writes
 * ("locked" indicates whether nfs_buf_mutex is already held)
 */
static void
nfs_buf_delwri_push(int locked)
{
	struct nfsbuf *bp;
	int i, error;

	if (TAILQ_EMPTY(&nfsbufdelwri))
		return;

	/* first try to tell the nfsiods to do it */
	if (nfs_asyncio(NULL, NULL) == 0)
		return;

	/* otherwise, try to do some of the work ourselves */
	i = 0;
	if (!locked)
		lck_mtx_lock(nfs_buf_mutex);
	while (i < 8 && (bp = TAILQ_FIRST(&nfsbufdelwri)) != NULL) {
		struct nfsnode *np = VTONFS(bp->nb_vp);
		nfs_buf_remfree(bp);
		nfs_buf_refget(bp);
		while ((error = nfs_buf_acquire(bp, 0, 0, 0)) == EAGAIN);
		nfs_buf_refrele(bp);
		if (error)
			break;
		if (!bp->nb_vp) {
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
			nfs_flushcommits(np->n_vnode, NULL, 1);
		} else {
			SET(bp->nb_flags, NB_ASYNC);
			lck_mtx_unlock(nfs_buf_mutex);
			nfs_buf_write(bp);
		}
		i++;
		lck_mtx_lock(nfs_buf_mutex);
	}
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
	vnode_t vp,
	daddr64_t blkno,
	int size,
	proc_t p,
	int flags,
	struct nfsbuf **bpp)
{
	struct nfsnode *np = VTONFS(vp);
	struct nfsbuf *bp;
	int biosize, bufsize;
	kauth_cred_t cred;
	int slpflag = PCATCH;
	int operation = (flags & NBLK_OPMASK);
	int error = 0;
	struct timespec ts;

	FSDBG_TOP(541, vp, blkno, size, flags);
	*bpp = NULL;

	bufsize = size;
	if (bufsize > MAXBSIZE)
		panic("nfs_buf_get: buffer larger than MAXBSIZE requested");

	biosize = vfs_statfs(vnode_mount(vp))->f_iosize;

	if (UBCINVALID(vp) || !UBCINFOEXISTS(vp)) {
		operation = NBLK_META;
	} else if (bufsize < biosize) {
		/* reg files should always have biosize blocks */
		bufsize = biosize;
	}

	/* if NBLK_WRITE, check for too many delayed/uncommitted writes */
	if ((operation == NBLK_WRITE) && (nfs_nbdwrite > ((nfsbufcnt*3)/4))) {
		FSDBG_TOP(542, vp, blkno, nfs_nbdwrite, ((nfsbufcnt*3)/4));

		/* poke the delwri list */
		nfs_buf_delwri_push(0);

		/* sleep to let other threads run... */
		tsleep(&nfs_nbdwrite, PCATCH, "nfs_nbdwrite", 1);
		FSDBG_BOT(542, vp, blkno, nfs_nbdwrite, ((nfsbufcnt*3)/4));
	}

loop:
	lck_mtx_lock(nfs_buf_mutex);

	/* check for existence of nfsbuf in cache */
	if ((bp = nfs_buf_incore(vp, blkno))) {
		/* if busy, set wanted and wait */
		if (ISSET(bp->nb_lflags, NBL_BUSY)) {
			if (flags & NBLK_NOWAIT) {
				lck_mtx_unlock(nfs_buf_mutex);
				FSDBG_BOT(541, vp, blkno, bp, 0xbcbcbcbc);
				return (0);
			}
			FSDBG_TOP(543, vp, blkno, bp, bp->nb_flags);
			SET(bp->nb_lflags, NBL_WANTED);

			ts.tv_sec = 2;
			ts.tv_nsec = 0;
			msleep(bp, nfs_buf_mutex, slpflag|(PRIBIO+1)|PDROP,
				"nfsbufget", (slpflag == PCATCH) ? 0 : &ts);
			slpflag = 0;
			FSDBG_BOT(543, vp, blkno, bp, bp->nb_flags);
			if ((error = nfs_sigintr(VFSTONFS(vnode_mount(vp)), NULL, p))) {
				FSDBG_BOT(541, vp, blkno, 0, error);
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
		FSDBG_BOT(541, vp, blkno, 0, 0x0000cace);
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
		FSDBG(544, vp, blkno, bp, bp->nb_flags);
		nfs_buf_remfree(bp);
		if (ISSET(bp->nb_flags, NB_DELWRI))
			panic("nfs_buf_get: delwri");
		SET(bp->nb_lflags, NBL_BUSY);
		/* disassociate buffer from previous vnode */
		if (bp->nb_vp) {
			if (bp->nb_vnbufs.le_next != NFSNOLIST) {
				LIST_REMOVE(bp, nb_vnbufs);
				bp->nb_vnbufs.le_next = NFSNOLIST;
			}
			bp->nb_vp = NULL;
		}
		LIST_REMOVE(bp, nb_hash);
		/* nuke any creds we're holding */
		cred = bp->nb_rcred;
		if (cred != NOCRED) {
			bp->nb_rcred = NOCRED; 
			kauth_cred_rele(cred);
		}
		cred = bp->nb_wcred;
		if (cred != NOCRED) {
			bp->nb_wcred = NOCRED; 
			kauth_cred_rele(cred);
		}
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
				FSDBG_BOT(541, vp, blkno, 0, error);
				return (ENOMEM);
			}
			nfsbufcnt++;
			if (operation == NBLK_META)
				nfsbufmetacnt++;
			NFSBUFCNTCHK(1);
			/* init nfsbuf */
			bzero(bp, sizeof(*bp));
			bp->nb_free.tqe_next = NFSNOLIST;
			bp->nb_validoff = bp->nb_validend = -1;
			FSDBG(545, vp, blkno, bp, 0);
		} else {
			/* too many bufs... wait for buffers to free up */
			FSDBG_TOP(546, vp, blkno, nfsbufcnt, nfsbufmax);

			/* poke the delwri list */
			nfs_buf_delwri_push(1);

			nfsneedbuffer = 1;
			msleep(&nfsneedbuffer, nfs_buf_mutex, PCATCH|PDROP,
				"nfsbufget", 0);
			FSDBG_BOT(546, vp, blkno, nfsbufcnt, nfsbufmax);
			if ((error = nfs_sigintr(VFSTONFS(vnode_mount(vp)), NULL, p))) {
				FSDBG_BOT(541, vp, blkno, 0, error);
				return (error);
			}
			goto loop;
		}
	}

	/* setup nfsbuf */
	bp->nb_lflags = NBL_BUSY;
	bp->nb_flags = 0;
	bp->nb_lblkno = blkno;
	/* insert buf in hash */
	LIST_INSERT_HEAD(NFSBUFHASH(np, blkno), bp, nb_hash);
	/* associate buffer with new vnode */
	bp->nb_vp = vp;
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
			/* cleanup buffer and return error */
			lck_mtx_lock(nfs_buf_mutex);
			LIST_REMOVE(bp, nb_vnbufs);
			bp->nb_vnbufs.le_next = NFSNOLIST;
			bp->nb_vp = NULL;
			/* invalidate usage timestamp to allow immediate freeing */
			NBUFSTAMPINVALIDATE(bp);
			if (bp->nb_free.tqe_next != NFSNOLIST)
				panic("nfsbuf on freelist");
			TAILQ_INSERT_HEAD(&nfsbuffree, bp, nb_free);
			nfsbuffreecnt++;
			lck_mtx_unlock(nfs_buf_mutex);
			FSDBG_BOT(541, vp, blkno, 0xb00, ENOMEM);
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
			/* setup upl */
			if (nfs_buf_upl_setup(bp)) {
				/* unable to create upl */
				/* vm object must no longer exist */
				/* cleanup buffer and return error */
				lck_mtx_lock(nfs_buf_mutex);
				LIST_REMOVE(bp, nb_vnbufs);
				bp->nb_vnbufs.le_next = NFSNOLIST;
				bp->nb_vp = NULL;
				/* invalidate usage timestamp to allow immediate freeing */
				NBUFSTAMPINVALIDATE(bp);
				if (bp->nb_free.tqe_next != NFSNOLIST)
					panic("nfsbuf on freelist");
				TAILQ_INSERT_HEAD(&nfsbuffree, bp, nb_free);
				nfsbuffreecnt++;
				lck_mtx_unlock(nfs_buf_mutex);
				FSDBG_BOT(541, vp, blkno, 0x2bc, EIO);
				return (EIO);
			}
			nfs_buf_upl_check(bp);
		}
		break;

	default:
		panic("nfs_buf_get: %d unknown operation", operation);
	}

	*bpp = bp;

	FSDBG_BOT(541, vp, blkno, bp, bp->nb_flags);

	return (0);
}

void
nfs_buf_release(struct nfsbuf *bp, int freeup)
{
	vnode_t vp = bp->nb_vp;
	struct timeval now;
	int wakeup_needbuffer, wakeup_buffer, wakeup_nbdwrite;

	FSDBG_TOP(548, bp, NBOFF(bp), bp->nb_flags, bp->nb_data);
	FSDBG(548, bp->nb_validoff, bp->nb_validend, bp->nb_dirtyoff, bp->nb_dirtyend);
	FSDBG(548, bp->nb_valid, 0, bp->nb_dirty, 0);

	if (UBCINFOEXISTS(vp) && bp->nb_bufsize) {
		int upl_flags;
		upl_t upl;
		int i, rv;

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
		if (bp->nb_flags & (NB_ERROR | NB_INVAL | NB_NOCACHE)) {
			if (bp->nb_flags & (NB_READ | NB_INVAL | NB_NOCACHE))
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
				ubc_upl_commit_range(upl,
					i*PAGE_SIZE, PAGE_SIZE,
					upl_flags |
					UPL_COMMIT_INACTIVATE |
					UPL_COMMIT_FREE_ON_EMPTY);
			}
		}
pagelist_cleanup_done:
		/* was this the last buffer in the file? */
		if (NBOFF(bp) + bp->nb_bufsize > (off_t)(VTONFS(vp)->n_size)) {
			/* if so, invalidate all pages of last buffer past EOF */
			int biosize = vfs_statfs(vnode_mount(vp))->f_iosize;
			off_t start, end;
			start = trunc_page_64(VTONFS(vp)->n_size) + PAGE_SIZE_64;
			end = trunc_page_64(NBOFF(bp) + biosize);
			if (end > start) {
				if (!(rv = ubc_sync_range(vp, start, end, UBC_INVALIDATE)))
					printf("nfs_buf_release(): ubc_sync_range failed!\n");
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

	/* If it's not cacheable, or an error, mark it invalid. */
	if (ISSET(bp->nb_flags, (NB_NOCACHE|NB_ERROR)))
		SET(bp->nb_flags, NB_INVAL);

	if ((bp->nb_bufsize <= 0) || ISSET(bp->nb_flags, NB_INVAL)) {
		/* If it's invalid or empty, dissociate it from its vnode */
		if (bp->nb_vnbufs.le_next != NFSNOLIST) {
			LIST_REMOVE(bp, nb_vnbufs);
			bp->nb_vnbufs.le_next = NFSNOLIST;
		}
		bp->nb_vp = NULL;
		/* if this was a delayed write, wakeup anyone */
		/* waiting for delayed writes to complete */
		if (ISSET(bp->nb_flags, NB_DELWRI)) {
			CLR(bp->nb_flags, NB_DELWRI);
			OSAddAtomic(-1, (SInt32*)&nfs_nbdwrite);
			NFSBUFCNTCHK(1);
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

	NFSBUFCNTCHK(1);

	/* Unlock the buffer. */
	CLR(bp->nb_flags, (NB_ASYNC | NB_NOCACHE | NB_STABLE | NB_IOD));
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
		msleep(bp, nfs_buf_mutex, PRIBIO + 1, "nfs_buf_iowait", 0);

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
	/*
	 * I/O was done, so don't believe
	 * the DIRTY state from VM anymore
	 */
	CLR(bp->nb_flags, NB_WASDIRTY);

	if (!ISSET(bp->nb_flags, NB_READ)) {
		CLR(bp->nb_flags, NB_WRITEINPROG);
		/*
		 * vnode_writedone() takes care of waking up
		 * any throttled write operations
		 */
		vnode_writedone(bp->nb_vp);
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
nfs_buf_write_delayed(struct nfsbuf *bp, proc_t p)
{
	vnode_t vp = bp->nb_vp;

	FSDBG_TOP(551, bp, NBOFF(bp), bp->nb_flags, 0);
	FSDBG(551, bp, bp->nb_dirtyoff, bp->nb_dirtyend, bp->nb_dirty);

	/*
	 * If the block hasn't been seen before:
	 *	(1) Mark it as having been seen,
	 *	(2) Charge for the write.
	 *	(3) Make sure it's on its vnode's correct block list,
	 */
	if (!ISSET(bp->nb_flags, NB_DELWRI)) {
		SET(bp->nb_flags, NB_DELWRI);
		if (p && p->p_stats) 
			p->p_stats->p_ru.ru_oublock++;		/* XXX */
		OSAddAtomic(1, (SInt32*)&nfs_nbdwrite);
		NFSBUFCNTCHK(0);
		/* move to dirty list */
		lck_mtx_lock(nfs_buf_mutex);
		if (bp->nb_vnbufs.le_next != NFSNOLIST)
			LIST_REMOVE(bp, nb_vnbufs);
		LIST_INSERT_HEAD(&VTONFS(vp)->n_dirtyblkhd, bp, nb_vnbufs);
		lck_mtx_unlock(nfs_buf_mutex);
	}

	/*
	 * If the vnode has "too many" write operations in progress
	 * wait for them to finish the IO
	 */
	(void)vnode_waitforwrites(vp, VNODE_ASYNC_THROTTLE, 0, 0, "nfs_buf_write_delayed");

	/*
	 * If we have too many delayed write buffers, 
	 * more than we can "safely" handle, just fall back to
	 * doing the async write
	 */
	if (nfs_nbdwrite < 0)
		panic("nfs_buf_write_delayed: Negative nfs_nbdwrite");

	if (nfs_nbdwrite > ((nfsbufcnt/4)*3)) {
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
nfs_buf_check_write_verifier(struct nfsnode *np, struct nfsbuf *bp)
{
	struct nfsmount *nmp;

	if (!ISSET(bp->nb_flags, NB_NEEDCOMMIT))
		return;

	nmp = VFSTONFS(vnode_mount(NFSTOV(np)));
	if (!nmp || (bp->nb_verf == nmp->nm_verf))
		return;

	/* write verifier changed, clear commit flag */
	bp->nb_flags &= ~NB_NEEDCOMMIT;
	np->n_needcommitcnt--;
	CHECK_NEEDCOMMITCNT(np);
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
		 * since the mutex_lock may block, the buffer
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
	        /*	
		 * delay the actual wakeup until after we
		 * clear NBL_BUSY and we've dropped nfs_buf_mutex
		 */
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
nfs_buf_iterprepare(struct nfsnode *np, struct nfsbuflists *iterheadp, int flags)
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
		msleep(&np->n_bufiterflags, nfs_buf_mutex, 0, "nfs_buf_iterprepare", 0);	
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
 * cleanup after iterating over an nfsnode's buffer list
 * this lock protects the queue manipulation
 * (must be called with nfs_buf_mutex held)
 */
void
nfs_buf_itercomplete(struct nfsnode *np, struct nfsbuflists *iterheadp, int flags)
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
 * Vnode op for read using bio
 * Any similarity to readip() is purely coincidental
 */
int
nfs_bioread(
	vnode_t vp,
	struct uio *uio,
	__unused int ioflag,
	kauth_cred_t cred,
	proc_t p)
{
	struct nfsnode *np = VTONFS(vp);
	int biosize;
	off_t diff;
	struct nfsbuf *bp = NULL, *rabp;
	struct nfs_vattr nvattr;
	struct nfsmount *nmp = VFSTONFS(vnode_mount(vp));
	daddr64_t lbn, rabn, lastrabn = -1, tlbn;
	int bufsize;
	int nra, error = 0, n = 0, on = 0;
	caddr_t dp;
	struct dirent *direntp = NULL;
	enum vtype vtype;
	int nocachereadahead = 0;

	FSDBG_TOP(514, vp, uio->uio_offset, uio_uio_resid(uio), ioflag);

#if DIAGNOSTIC
	if (uio->uio_rw != UIO_READ)
		panic("nfs_read mode");
#endif
	if (uio_uio_resid(uio) == 0) {
		FSDBG_BOT(514, vp, 0xd1e0001, 0, 0);
		return (0);
	}
	if (uio->uio_offset < 0) {
		FSDBG_BOT(514, vp, 0xd1e0002, 0, EINVAL);
		return (EINVAL);
	}

	if ((nmp->nm_flag & NFSMNT_NFSV3) && !(nmp->nm_state & NFSSTA_GOTFSINFO))
		nfs_fsinfo(nmp, vp, cred, p);
	biosize = vfs_statfs(vnode_mount(vp))->f_iosize;
	vtype = vnode_vtype(vp);
	/*
	 * For nfs, cache consistency can only be maintained approximately.
	 * Although RFC1094 does not specify the criteria, the following is
	 * believed to be compatible with the reference port.
	 * For nfs:
	 * If the file's modify time on the server has changed since the
	 * last read rpc or you have written to the file,
	 * you may have lost data cache consistency with the
	 * server, so flush all of the file's data out of the cache.
	 * Then force a getattr rpc to ensure that you have up to date
	 * attributes.
	 * NB: This implies that cache data can be read when up to
	 * NFS_MAXATTRTIMEO seconds out of date. If you find that you need
	 * current attributes this could be forced by setting calling
	 * NATTRINVALIDATE() before the nfs_getattr() call.
	 */
	if (np->n_flag & NNEEDINVALIDATE) {
		np->n_flag &= ~NNEEDINVALIDATE;
		nfs_vinvalbuf(vp, V_SAVE|V_IGNORE_WRITEERR, cred, p, 1);
	}
	if (np->n_flag & NMODIFIED) {
		if (vtype != VREG) {
			if (vtype != VDIR)
				panic("nfs: bioread, not dir");
			nfs_invaldir(vp);
			error = nfs_vinvalbuf(vp, V_SAVE, cred, p, 1);
			if (error) {
				FSDBG_BOT(514, vp, 0xd1e0003, 0, error);
				return (error);
			}
		}
		NATTRINVALIDATE(np);
		error = nfs_getattr(vp, &nvattr, cred, p);
		if (error) {
			FSDBG_BOT(514, vp, 0xd1e0004, 0, error);
			return (error);
		}
		if (vtype == VDIR) {
			/* if directory changed, purge any name cache entries */
			if (nfstimespeccmp(&np->n_ncmtime, &nvattr.nva_mtime, !=))
				cache_purge(vp);
			np->n_ncmtime = nvattr.nva_mtime;
		}
		np->n_mtime = nvattr.nva_mtime;
	} else {
		error = nfs_getattr(vp, &nvattr, cred, p);
		if (error) {
			FSDBG_BOT(514, vp, 0xd1e0005, 0, error);
			return (error);
		}
		if (nfstimespeccmp(&np->n_mtime, &nvattr.nva_mtime, !=)) {
			if (vtype == VDIR) {
				nfs_invaldir(vp);
				/* purge name cache entries */
				if (nfstimespeccmp(&np->n_ncmtime, &nvattr.nva_mtime, !=))
					cache_purge(vp);
			}
			error = nfs_vinvalbuf(vp, V_SAVE, cred, p, 1);
			if (error) {
				FSDBG_BOT(514, vp, 0xd1e0006, 0, error);
				return (error);
			}
			if (vtype == VDIR)
				np->n_ncmtime = nvattr.nva_mtime;
			np->n_mtime = nvattr.nva_mtime;
		}
	}

	if (vnode_isnocache(vp)) {
		if (!(np->n_flag & NNOCACHE)) {
			if (NVALIDBUFS(np)) {
				error = nfs_vinvalbuf(vp, V_SAVE, cred, p, 1);
				if (error) {
					FSDBG_BOT(514, vp, 0xd1e000a, 0, error);
					return (error);
				}
			}
			np->n_flag |= NNOCACHE;
		}
	} else if (np->n_flag & NNOCACHE) {
		np->n_flag &= ~NNOCACHE;
	}

	do {
	    if (np->n_flag & NNOCACHE) {
		switch (vtype) {
		case VREG:
			/*
			 * If we have only a block or so to read,
			 *     just do the rpc directly.
			 * If we have a couple blocks or more to read,
			 *     then we'll take advantage of readahead within
			 *     this loop to try to fetch all the data in parallel
			 */
			if (!nocachereadahead && (uio_uio_resid(uio) < 2*biosize)) {
				error = nfs_readrpc(vp, uio, cred, p);
				FSDBG_BOT(514, vp, uio->uio_offset, uio_uio_resid(uio), error);
				return (error);
			}
			nocachereadahead = 1;
			break;
		case VLNK:
			error = nfs_readlinkrpc(vp, uio, cred, p);
			FSDBG_BOT(514, vp, uio->uio_offset, uio_uio_resid(uio), error);
			return (error);
		case VDIR:
			break;
		default:
			printf(" NFSNOCACHE: type %x unexpected\n", vtype);
		};
	    }
	    switch (vtype) {
	    case VREG:
		lbn = uio->uio_offset / biosize;

		/*
		 * Copy directly from any cached pages without grabbing the bufs.
		 *
		 * Note: for "nocache" reads, we don't copy directly from UBC
		 * because any cached pages will be for readahead buffers that
		 * need to be invalidated anyway before we finish this request.
		 */
		if (!(np->n_flag & NNOCACHE) &&
			(uio->uio_segflg == UIO_USERSPACE32 || 
			 uio->uio_segflg == UIO_USERSPACE64 ||
			 uio->uio_segflg == UIO_USERSPACE)) {
			// LP64todo - fix this!
			int io_resid = uio_uio_resid(uio);
			diff = np->n_size - uio->uio_offset;
			if (diff < io_resid)
				io_resid = diff;
			if (io_resid > 0) {
				error = cluster_copy_ubc_data(vp, uio, &io_resid, 0);
				if (error) {
					FSDBG_BOT(514, vp, uio->uio_offset, 0xcacefeed, error);
					return (error);
				}
			}
			/* count any biocache reads that we just copied directly */
			if (lbn != uio->uio_offset / biosize) {
				OSAddAtomic((uio->uio_offset / biosize) - lbn, (SInt32*)&nfsstats.biocache_reads);
				FSDBG(514, vp, 0xcacefeed, uio->uio_offset, error);
			}
		}

		lbn = uio->uio_offset / biosize;
		on = uio->uio_offset % biosize;

		/*
		 * Start the read ahead(s), as required.
		 */
		if (nfs_numasync > 0 && nmp->nm_readahead > 0) {
			for (nra = 0; nra < nmp->nm_readahead; nra++) {
				rabn = lbn + 1 + nra;
				if (rabn <= lastrabn) {
					/* we've already (tried to) read this block */
					/* no need to try it again... */
					continue;
				}
				lastrabn = rabn;
				if ((off_t)rabn * biosize >= (off_t)np->n_size)
					break;
				if ((np->n_flag & NNOCACHE) &&
				   (((off_t)rabn * biosize) >= (uio->uio_offset + uio_uio_resid(uio))))
					/* for uncached readahead, don't go beyond end of request */
					break;
				/* check if block exists and is valid. */
				error = nfs_buf_get(vp, rabn, biosize, p, NBLK_READ|NBLK_NOWAIT, &rabp);
				if (error) {
					FSDBG_BOT(514, vp, 0xd1e000b, 1, error);
					return (error);
				}
				if (!rabp)
					continue;
				if (nfs_buf_upl_valid_range(rabp, 0, rabp->nb_bufsize)) {
					nfs_buf_release(rabp, 1);
					continue;
				}
				if (!ISSET(rabp->nb_flags, (NB_CACHE|NB_DELWRI))) {
					SET(rabp->nb_flags, (NB_READ|NB_ASYNC));
					if (nfs_asyncio(rabp, cred)) {
						SET(rabp->nb_flags, (NB_INVAL|NB_ERROR));
						rabp->nb_error = EIO;
						nfs_buf_release(rabp, 1);
					}
				} else
					nfs_buf_release(rabp, 1);
			}
		}

		if ((uio_uio_resid(uio) <= 0) || (uio->uio_offset >= (off_t)np->n_size)) {
			FSDBG_BOT(514, vp, uio->uio_offset, uio_uio_resid(uio), 0xaaaaaaaa);
			return (0);
		}

		OSAddAtomic(1, (SInt32*)&nfsstats.biocache_reads);

		/*
		 * If the block is in the cache and has the required data
		 * in a valid region, just copy it out.
		 * Otherwise, get the block and write back/read in,
		 * as required.
		 */
again:
		bufsize = biosize;
		// LP64todo - fix this!
		n = min((unsigned)(bufsize - on), uio_uio_resid(uio));
		diff = np->n_size - uio->uio_offset;
		if (diff < n)
			n = diff;

		error = nfs_buf_get(vp, lbn, bufsize, p, NBLK_READ, &bp);
		if (error) {
			FSDBG_BOT(514, vp, 0xd1e000c, 0, EINTR);
			return (EINTR);
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
			if ((dirtypg > firstpg) && (dirtypg < lastpg)) {
				/* there are also dirty page(s) in the range, */
				/* so write the buffer out and try again */
				CLR(bp->nb_flags, (NB_DONE | NB_ERROR | NB_INVAL));
				SET(bp->nb_flags, NB_ASYNC);
				if (bp->nb_wcred == NOCRED)  {
					kauth_cred_ref(cred);
					bp->nb_wcred = cred;
				}
				error = nfs_buf_write(bp);
				if (error) {
					FSDBG_BOT(514, vp, 0xd1e000d, 0, error);
					return (error);
				}
				goto again;
			}
			if (!bp->nb_dirty && bp->nb_dirtyend <= 0 &&
			    (lastpg - firstpg + 1) > (bufsize/PAGE_SIZE)/2) {
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
					uio_addiov(auio, CAST_USER_ADDR_T((bp->nb_data + firstpg * PAGE_SIZE)), 
							((lastpg - firstpg + 1) * PAGE_SIZE));
					error = nfs_readrpc(vp, auio, cred, p);
				}
				if (error) {
					if (np->n_flag & NNOCACHE)
						SET(bp->nb_flags, NB_NOCACHE);
					nfs_buf_release(bp, 1);
					FSDBG_BOT(514, vp, 0xd1e000e, 0, error);
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
			SET(bp->nb_flags, NB_READ);
			CLR(bp->nb_flags, (NB_DONE | NB_ERROR | NB_INVAL));
			error = nfs_doio(bp, cred, p);
			if (error) {
				if (np->n_flag & NNOCACHE)
					SET(bp->nb_flags, NB_NOCACHE);
				nfs_buf_release(bp, 1);
				FSDBG_BOT(514, vp, 0xd1e000f, 0, error);
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
		if (n > 0)
			NFS_BUF_MAP(bp);
		break;
	    case VLNK:
		OSAddAtomic(1, (SInt32*)&nfsstats.biocache_readlinks);
		error = nfs_buf_get(vp, 0, NFS_MAXPATHLEN, p, NBLK_READ, &bp);
		if (error) {
			FSDBG_BOT(514, vp, 0xd1e0010, 0, error);
			return (error);
		}
		if (!ISSET(bp->nb_flags, NB_CACHE)) {
			SET(bp->nb_flags, NB_READ);
			error = nfs_doio(bp, cred, p);
			if (error) {
				SET(bp->nb_flags, NB_ERROR);
				nfs_buf_release(bp, 1);
				FSDBG_BOT(514, vp, 0xd1e0011, 0, error);
				return (error);
			}
		}
		// LP64todo - fix this!
		n = min(uio_uio_resid(uio), bp->nb_validend);
		on = 0;
		break;
	    case VDIR:
		OSAddAtomic(1, (SInt32*)&nfsstats.biocache_readdirs);
		if (np->n_direofoffset && uio->uio_offset >= np->n_direofoffset) {
			FSDBG_BOT(514, vp, 0xde0f0001, 0, 0);
			return (0);
		}
		lbn = uio->uio_offset / NFS_DIRBLKSIZ;
		on = uio->uio_offset & (NFS_DIRBLKSIZ - 1);
		error = nfs_buf_get(vp, lbn, NFS_DIRBLKSIZ, p, NBLK_READ, &bp);
		if (error) {
			FSDBG_BOT(514, vp, 0xd1e0012, 0, error);
			return (error);
		}
		if (!ISSET(bp->nb_flags, NB_CACHE)) {
		    SET(bp->nb_flags, NB_READ);
		    error = nfs_doio(bp, cred, p);
		    if (error) {
			nfs_buf_release(bp, 1);
		    }
		    while (error == NFSERR_BAD_COOKIE) {
			nfs_invaldir(vp);
			error = nfs_vinvalbuf(vp, 0, cred, p, 1);
			/*
			 * Yuck! The directory has been modified on the
			 * server. The only way to get the block is by
			 * reading from the beginning to get all the
			 * offset cookies.
			 */
			for (tlbn = 0; tlbn <= lbn && !error; tlbn++) {
			    if (np->n_direofoffset
				&& (tlbn * NFS_DIRBLKSIZ) >= np->n_direofoffset) {
				    FSDBG_BOT(514, vp, 0xde0f0002, 0, 0);
				    return (0);
			    }
			    error = nfs_buf_get(vp, tlbn, NFS_DIRBLKSIZ, p, NBLK_READ, &bp);
			    if (error) {
				    FSDBG_BOT(514, vp, 0xd1e0013, 0, error);
				    return (error);
			    }
			    if (!ISSET(bp->nb_flags, NB_CACHE)) {
				    SET(bp->nb_flags, NB_READ);
				    error = nfs_doio(bp, cred, p);
				    /*
				     * no error + NB_INVAL == directory EOF,
				     * use the block.
				     */
				    if (error == 0 && (bp->nb_flags & NB_INVAL))
					    break;
			    }
			    /*
			     * An error will throw away the block and the
			     * for loop will break out.  If no error and this
			     * is not the block we want, we throw away the
			     * block and go for the next one via the for loop.
			     */
			    if (error || tlbn < lbn)
				    nfs_buf_release(bp, 1);
			}
		    }
		    /*
		     * The above while is repeated if we hit another cookie
		     * error.  If we hit an error and it wasn't a cookie error,
		     * we give up.
		     */
		    if (error) {
		        FSDBG_BOT(514, vp, 0xd1e0014, 0, error);
			return (error);
		    }
		}

		/*
		 * If not eof and read aheads are enabled, start one.
		 * (You need the current block first, so that you have the
		 *  directory offset cookie of the next block.)
		 */
		if (nfs_numasync > 0 && nmp->nm_readahead > 0 &&
		    (np->n_direofoffset == 0 ||
		    (lbn + 1) * NFS_DIRBLKSIZ < np->n_direofoffset) &&
		    !nfs_buf_is_incore(vp, lbn + 1)) {
			error = nfs_buf_get(vp, lbn + 1, NFS_DIRBLKSIZ, p, NBLK_READ|NBLK_NOWAIT, &rabp);
			if (error) {
		            FSDBG_BOT(514, vp, 0xd1e0015, 0, error);
			    return (error);
			}
			if (rabp) {
			    if (!ISSET(rabp->nb_flags, (NB_CACHE))) {
				SET(rabp->nb_flags, (NB_READ | NB_ASYNC));
				if (nfs_asyncio(rabp, cred)) {
				    SET(rabp->nb_flags, (NB_INVAL|NB_ERROR));
				    rabp->nb_error = EIO;
				    nfs_buf_release(rabp, 1);
				}
			    } else {
				nfs_buf_release(rabp, 1);
			    }
			}
		}
		/*
		 * Make sure we use a signed variant of min() since
		 * the second term may be negative.
		 */
		// LP64todo - fix this!
		n = lmin(uio_uio_resid(uio), bp->nb_validend - on);
		/*
		 * We keep track of the directory eof in
		 * np->n_direofoffset and chop it off as an
		 * extra step right here.
		 */
		if (np->n_direofoffset &&
		    n > np->n_direofoffset - uio->uio_offset)
			n = np->n_direofoffset - uio->uio_offset;
		/*
		 * Make sure that we return an integral number of entries so
		 * that any subsequent calls will start copying from the start
		 * of the next entry.
		 *
		 * If the current value of n has the last entry cut short,
		 * set n to copy everything up to the last entry instead.
		 */
		if (n > 0) {
			dp = bp->nb_data + on;
			while (dp < (bp->nb_data + on + n)) {
				direntp = (struct dirent *)dp;
				dp += direntp->d_reclen;
			}
			if (dp > (bp->nb_data + on + n))
				n = (dp - direntp->d_reclen) - (bp->nb_data + on);
		}
		break;
	    default:
		printf("nfs_bioread: type %x unexpected\n", vtype);
		FSDBG_BOT(514, vp, 0xd1e0016, 0, EINVAL);
		return (EINVAL);
	    };

	    if (n > 0) {
		error = uiomove(bp->nb_data + on, (int)n, uio);
	    }
	    switch (vtype) {
	    case VREG:
		if (np->n_flag & NNOCACHE)
			SET(bp->nb_flags, NB_NOCACHE);
		break;
	    case VLNK:
		n = 0;
		break;
	    case VDIR:
		break;
	    default:
		break;
	    }
	    nfs_buf_release(bp, 1);
	} while (error == 0 && uio_uio_resid(uio) > 0 && n > 0);
	FSDBG_BOT(514, vp, uio->uio_offset, uio_uio_resid(uio), error);
	return (error);
}


/*
 * Vnode op for write using bio
 */
int
nfs_write(ap)
	struct vnop_write_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		struct uio *a_uio;
		int a_ioflag;
		vfs_context_t a_context;
	} */ *ap;
{
	struct uio *uio = ap->a_uio;
	vnode_t vp = ap->a_vp;
	struct nfsnode *np = VTONFS(vp);
	proc_t p;
	kauth_cred_t cred;
	int ioflag = ap->a_ioflag;
	struct nfsbuf *bp;
	struct nfs_vattr nvattr;
	struct nfsmount *nmp = VFSTONFS(vnode_mount(vp));
	daddr64_t lbn;
	int biosize, bufsize;
	int n, on, error = 0;
	off_t boff, start, end, cureof;
	struct iovec_32 iov;
	struct uio auio;

	FSDBG_TOP(515, vp, uio->uio_offset, uio_uio_resid(uio), ioflag);

#if DIAGNOSTIC
	if (uio->uio_rw != UIO_WRITE)
		panic("nfs_write mode");
	if (UIO_SEG_IS_USER_SPACE(uio->uio_segflg))
		panic("nfs_write proc");
#endif

	p = vfs_context_proc(ap->a_context);
	cred = vfs_context_ucred(ap->a_context);

	if (vnode_vtype(vp) != VREG)
		return (EIO);

	np->n_flag |= NWRBUSY;

	if (np->n_flag & NNEEDINVALIDATE) {
		np->n_flag &= ~NNEEDINVALIDATE;
		nfs_vinvalbuf(vp, V_SAVE|V_IGNORE_WRITEERR, cred, p, 1);
	}
	if (np->n_flag & NWRITEERR) {
		np->n_flag &= ~(NWRITEERR | NWRBUSY);
		FSDBG_BOT(515, vp, uio->uio_offset, uio_uio_resid(uio), np->n_error);
		return (np->n_error);
	}
	if ((nmp->nm_flag & NFSMNT_NFSV3) &&
	    !(nmp->nm_state & NFSSTA_GOTFSINFO))
		(void)nfs_fsinfo(nmp, vp, cred, p);
	if (ioflag & (IO_APPEND | IO_SYNC)) {
		if (np->n_flag & NMODIFIED) {
			NATTRINVALIDATE(np);
			error = nfs_vinvalbuf(vp, V_SAVE, cred, p, 1);
			if (error) {
				np->n_flag &= ~NWRBUSY;
				FSDBG_BOT(515, vp, uio->uio_offset, 0x10bad01, error);
				return (error);
			}
		}
		if (ioflag & IO_APPEND) {
			NATTRINVALIDATE(np);
			error = nfs_getattr(vp, &nvattr, cred, p);
			if (error) {
				np->n_flag &= ~NWRBUSY;
				FSDBG_BOT(515, vp, uio->uio_offset, 0x10bad02, error);
				return (error);
			}
			uio->uio_offset = np->n_size;
		}
	}
	if (uio->uio_offset < 0) {
		np->n_flag &= ~NWRBUSY;
		FSDBG_BOT(515, vp, uio->uio_offset, 0xbad0ff, EINVAL);
		return (EINVAL);
	}
	if (uio_uio_resid(uio) == 0) {
		np->n_flag &= ~NWRBUSY;
		FSDBG_BOT(515, vp, uio->uio_offset, uio_uio_resid(uio), 0);
		return (0);
	}

	biosize = vfs_statfs(vnode_mount(vp))->f_iosize;

	if (vnode_isnocache(vp)) {
		if (!(np->n_flag & NNOCACHE)) {
			if (NVALIDBUFS(np)) {
				error = nfs_vinvalbuf(vp, V_SAVE, cred, p, 1);
				if (error) {
					np->n_flag &= ~NWRBUSY;
					FSDBG_BOT(515, vp, 0, 0, error);
					return (error);
				}
			}
			np->n_flag |= NNOCACHE;
		}
	} else if (np->n_flag & NNOCACHE) {
		np->n_flag &= ~NNOCACHE;
	}

	do {
		OSAddAtomic(1, (SInt32*)&nfsstats.biocache_writes);
		lbn = uio->uio_offset / biosize;
		on = uio->uio_offset % biosize;
		// LP64todo - fix this
		n = min((unsigned)(biosize - on), uio_uio_resid(uio));
again:
		bufsize = biosize;
		/*
		 * Get a cache block for writing.  The range to be written is
		 * (off..off+n) within the block.  We ensure that the block
		 * either has no dirty region or that the given range is
		 * contiguous with the existing dirty region.
		 */
		error = nfs_buf_get(vp, lbn, bufsize, p, NBLK_WRITE, &bp);
		if (error) {
			np->n_flag &= ~NWRBUSY;
			FSDBG_BOT(515, vp, uio->uio_offset, uio_uio_resid(uio), error);
			return (error);
		}
		/* map the block because we know we're going to write to it */
		NFS_BUF_MAP(bp);

		if (np->n_flag & NNOCACHE)
			SET(bp->nb_flags, (NB_NOCACHE|NB_STABLE));

		if (bp->nb_wcred == NOCRED) {
			kauth_cred_ref(cred);
			bp->nb_wcred = cred;
		}

		/*
		 * If there's already a dirty range AND dirty pages in this block we
		 * need to send a commit AND write the dirty pages before continuing.
		 *
		 * If there's already a dirty range OR dirty pages in this block
		 * and the new write range is not contiguous with the existing range,
		 * then force the buffer to be written out now.
		 * (We used to just extend the dirty range to cover the valid,
		 * but unwritten, data in between also.  But writing ranges
		 * of data that weren't actually written by an application
		 * risks overwriting some other client's data with stale data
		 * that's just masquerading as new written data.)
		 */
		if (bp->nb_dirtyend > 0) {
		    if (on > bp->nb_dirtyend || (on + n) < bp->nb_dirtyoff || bp->nb_dirty) {
			FSDBG(515, vp, uio->uio_offset, bp, 0xd15c001);
			/* write/commit buffer "synchronously" */
			/* (NB_STABLE indicates that data writes should be FILESYNC) */
			CLR(bp->nb_flags, (NB_DONE | NB_ERROR | NB_INVAL));
			SET(bp->nb_flags, (NB_ASYNC | NB_STABLE));
			error = nfs_buf_write(bp);
			if (error) {
			    np->n_flag &= ~NWRBUSY;
			    FSDBG_BOT(515, vp, uio->uio_offset, uio_uio_resid(uio), error);
			    return (error);
			}
			goto again;
		    }
		} else if (bp->nb_dirty) {
		    int firstpg, lastpg;
		    u_int32_t pagemask;
		    /* calculate write range pagemask */
		    firstpg = on/PAGE_SIZE;
		    lastpg = (on+n-1)/PAGE_SIZE;
		    pagemask = ((1 << (lastpg+1)) - 1) & ~((1 << firstpg) - 1);
		    /* check if there are dirty pages outside the write range */
		    if (bp->nb_dirty & ~pagemask) {
			FSDBG(515, vp, uio->uio_offset, bp, 0xd15c002);
			/* write/commit buffer "synchronously" */
			/* (NB_STABLE indicates that data writes should be FILESYNC) */
			CLR(bp->nb_flags, (NB_DONE | NB_ERROR | NB_INVAL));
			SET(bp->nb_flags, (NB_ASYNC | NB_STABLE));
			error = nfs_buf_write(bp);
			if (error) {
			    np->n_flag &= ~NWRBUSY;
			    FSDBG_BOT(515, vp, uio->uio_offset, uio_uio_resid(uio), error);
			    return (error);
			}
			goto again;
		    }
		    /* if the first or last pages are already dirty */
		    /* make sure that the dirty range encompasses those pages */
		    if (NBPGDIRTY(bp,firstpg) || NBPGDIRTY(bp,lastpg)) {
			FSDBG(515, vp, uio->uio_offset, bp, 0xd15c003);
		    	bp->nb_dirtyoff = min(on, firstpg * PAGE_SIZE);
			if (NBPGDIRTY(bp,lastpg)) {
			    bp->nb_dirtyend = (lastpg+1) * PAGE_SIZE;
			    /* clip to EOF */
			    if (NBOFF(bp) + bp->nb_dirtyend > (off_t)np->n_size)
				    bp->nb_dirtyend = np->n_size - NBOFF(bp);
			} else
			    bp->nb_dirtyend = on+n;
		    }
		}

		/*
		 * Are we extending the size of the file with this write?
		 * If so, update file size now that we have the block.
		 * If there was a partial buf at the old eof, validate
		 * and zero the new bytes. 
		 */
		cureof = (off_t)np->n_size;
		if (uio->uio_offset + n > (off_t)np->n_size) {
			struct nfsbuf *eofbp = NULL;
			daddr64_t eofbn = np->n_size / biosize;
			int eofoff = np->n_size % biosize;
			int neweofoff = (uio->uio_offset + n) % biosize;

			FSDBG(515, 0xb1ffa000, uio->uio_offset + n, eofoff, neweofoff);

			if (eofoff && (eofbn < lbn)) {
				error = nfs_buf_get(vp, eofbn, biosize, p, NBLK_WRITE|NBLK_ONLYVALID, &eofbp);
				if (error) {
					np->n_flag &= ~NWRBUSY;
					FSDBG_BOT(515, vp, uio->uio_offset, uio_uio_resid(uio), error);
					return (error);
				}
			}

			/* if we're extending within the same last block */
			/* and the block is flagged as being cached... */
			if ((lbn == eofbn) && ISSET(bp->nb_flags, NB_CACHE)) {
				/* ...check that all pages in buffer are valid */
				int endpg = ((neweofoff ? neweofoff : biosize) - 1)/PAGE_SIZE;
				u_int32_t pagemask;
				/* pagemask only has to extend to last page being written to */
				pagemask = (1 << (endpg+1)) - 1;
				FSDBG(515, 0xb1ffa001, bp->nb_valid, pagemask, 0);
				if ((bp->nb_valid & pagemask) != pagemask) {
					/* zerofill any hole */
					if (on > bp->nb_validend) {
						int i;
						for (i=bp->nb_validend/PAGE_SIZE; i <= (on - 1)/PAGE_SIZE; i++)
							NBPGVALID_SET(bp, i);
						NFS_BUF_MAP(bp);
						FSDBG(516, bp, bp->nb_validend, on - bp->nb_validend, 0xf01e);
						bzero((char *)bp->nb_data + bp->nb_validend,
							on - bp->nb_validend);
					}
					/* zerofill any trailing data in the last page */
					if (neweofoff) {
						NFS_BUF_MAP(bp);
						FSDBG(516, bp, neweofoff, PAGE_SIZE - (neweofoff & PAGE_MASK), 0xe0f);
						bzero((char *)bp->nb_data + neweofoff,
							PAGE_SIZE - (neweofoff & PAGE_MASK));
					}
				}
			}
			np->n_flag |= NMODIFIED;
			np->n_size = uio->uio_offset + n;
			ubc_setsize(vp, (off_t)np->n_size); /* XXX errors */
			if (eofbp) {
				/*
				 * We may need to zero any previously invalid data
				 * after the old EOF in the previous EOF buffer.
				 *
				 * For the old last page, don't zero bytes if there
				 * are invalid bytes in that page (i.e. the page isn't
				 * currently valid).
				 * For pages after the old last page, zero them and
				 * mark them as valid.
				 */
				char *d;
				int i;
				if (np->n_flag & NNOCACHE)
					SET(eofbp->nb_flags, (NB_NOCACHE|NB_STABLE));
				NFS_BUF_MAP(eofbp);
				FSDBG(516, eofbp, eofoff, biosize - eofoff, 0xe0fff01e);
				d = eofbp->nb_data;
				i = eofoff/PAGE_SIZE;
				while (eofoff < biosize) {
					int poff = eofoff & PAGE_MASK;
					if (!poff || NBPGVALID(eofbp,i)) {
						bzero(d + eofoff, PAGE_SIZE - poff);
						NBPGVALID_SET(eofbp, i);
					}
					if (bp->nb_validend == eofoff)
						bp->nb_validend += PAGE_SIZE - poff;
					eofoff += PAGE_SIZE - poff;
					i++;
				}
				nfs_buf_release(eofbp, 1);
			}
		}
		/*
		 * If dirtyend exceeds file size, chop it down.  This should
		 * not occur unless there is a race.
		 */
		if (NBOFF(bp) + bp->nb_dirtyend > (off_t)np->n_size)
			bp->nb_dirtyend = np->n_size - NBOFF(bp);
		/*
		 * UBC doesn't handle partial pages, so we need to make sure
		 * that any pages left in the page cache are completely valid.
		 *
		 * Writes that are smaller than a block are delayed if they
		 * don't extend to the end of the block.
		 *
		 * If the block isn't (completely) cached, we may need to read
		 * in some parts of pages that aren't covered by the write.
		 * If the write offset (on) isn't page aligned, we'll need to
		 * read the start of the first page being written to.  Likewise,
		 * if the offset of the end of the write (on+n) isn't page aligned,
		 * we'll need to read the end of the last page being written to.
		 *
		 * Notes:
		 * We don't want to read anything we're just going to write over.
		 * We don't want to issue multiple I/Os if we don't have to
		 *   (because they're synchronous rpcs).
		 * We don't want to read anything we already have modified in the
		 *   page cache.
		 */
		if (!ISSET(bp->nb_flags, NB_CACHE) && n < biosize) {
			int firstpg, lastpg, dirtypg;
			int firstpgoff, lastpgoff;
			start = end = -1;
			firstpg = on/PAGE_SIZE;
			firstpgoff = on & PAGE_MASK;
			lastpg = (on+n-1)/PAGE_SIZE;
			lastpgoff = (on+n) & PAGE_MASK;
			if (firstpgoff && !NBPGVALID(bp,firstpg)) {
				/* need to read start of first page */
				start = firstpg * PAGE_SIZE;
				end = start + firstpgoff;
			}
			if (lastpgoff && !NBPGVALID(bp,lastpg)) {
				/* need to read end of last page */
				if (start < 0)
					start = (lastpg * PAGE_SIZE) + lastpgoff;
				end = (lastpg + 1) * PAGE_SIZE;
			}
			if (end > start) {
				/* need to read the data in range: start...end-1 */

				/* first, check for dirty pages in between */
				/* if there are, we'll have to do two reads because */
				/* we don't want to overwrite the dirty pages. */
				for (dirtypg=start/PAGE_SIZE; dirtypg <= (end-1)/PAGE_SIZE; dirtypg++)
					if (NBPGDIRTY(bp,dirtypg))
						break;

				/* if start is at beginning of page, try */
				/* to get any preceeding pages as well. */
				if (!(start & PAGE_MASK)) {
					/* stop at next dirty/valid page or start of block */
					for (; start > 0; start-=PAGE_SIZE)
						if (NBPGVALID(bp,((start-1)/PAGE_SIZE)))
							break;
				}

				NFS_BUF_MAP(bp);
				/* setup uio for read(s) */
				boff = NBOFF(bp);
				auio.uio_iovs.iov32p = &iov;
				auio.uio_iovcnt = 1;
#if 1   /* LP64todo - can't use new segment flags until the drivers are ready */
				auio.uio_segflg = UIO_SYSSPACE;
#else
				auio.uio_segflg = UIO_SYSSPACE32;
#endif 
				auio.uio_rw = UIO_READ;

				if (dirtypg <= (end-1)/PAGE_SIZE) {
					/* there's a dirty page in the way, so just do two reads */
					/* we'll read the preceding data here */
					auio.uio_offset = boff + start;
					iov.iov_len = on - start;
					uio_uio_resid_set(&auio, iov.iov_len);
					iov.iov_base = (uintptr_t) bp->nb_data + start;
					error = nfs_readrpc(vp, &auio, cred, p);
					if (error) {
						bp->nb_error = error;
						SET(bp->nb_flags, NB_ERROR);
						printf("nfs_write: readrpc %d", error);
					}
					if (uio_uio_resid(&auio) > 0) {
						FSDBG(516, bp, iov.iov_base - bp->nb_data, uio_uio_resid(&auio), 0xd00dee01);
						// LP64todo - fix this
						bzero((caddr_t)iov.iov_base, uio_uio_resid(&auio));
					}
					/* update validoff/validend if necessary */
					if ((bp->nb_validoff < 0) || (bp->nb_validoff > start))
						bp->nb_validoff = start;
					if ((bp->nb_validend < 0) || (bp->nb_validend < on))
						bp->nb_validend = on;
					if ((off_t)np->n_size > boff + bp->nb_validend)
						bp->nb_validend = min(np->n_size - (boff + start), biosize);
					/* validate any pages before the write offset */
					for (; start < on/PAGE_SIZE; start+=PAGE_SIZE)
						NBPGVALID_SET(bp, start/PAGE_SIZE);
					/* adjust start to read any trailing data */
					start = on+n;
				}

				/* if end is at end of page, try to */
				/* get any following pages as well. */
				if (!(end & PAGE_MASK)) {
					/* stop at next valid page or end of block */
					for (; end < bufsize; end+=PAGE_SIZE)
						if (NBPGVALID(bp,end/PAGE_SIZE))
							break;
				}

				if (((boff+start) >= cureof) || ((start >= on) && ((boff + on + n) >= cureof))) {
					/*
					 * Either this entire read is beyond the current EOF
					 * or the range that we won't be modifying (on+n...end)
					 * is all beyond the current EOF.
					 * No need to make a trip across the network to
					 * read nothing.  So, just zero the buffer instead.
					 */
					FSDBG(516, bp, start, end - start, 0xd00dee00);
					bzero(bp->nb_data + start, end - start);
				} else {
					/* now we'll read the (rest of the) data */
					auio.uio_offset = boff + start;
					iov.iov_len = end - start;
					uio_uio_resid_set(&auio, iov.iov_len);
					iov.iov_base = (uintptr_t) (bp->nb_data + start);
					error = nfs_readrpc(vp, &auio, cred, p);
					if (error) {
						bp->nb_error = error;
						SET(bp->nb_flags, NB_ERROR);
						printf("nfs_write: readrpc %d", error);
					}
					if (uio_uio_resid(&auio) > 0) {
						FSDBG(516, bp, iov.iov_base - bp->nb_data, uio_uio_resid(&auio), 0xd00dee02);
						// LP64todo - fix this
						bzero((caddr_t)iov.iov_base, uio_uio_resid(&auio));
					}
				}
				/* update validoff/validend if necessary */
				if ((bp->nb_validoff < 0) || (bp->nb_validoff > start))
					bp->nb_validoff = start;
				if ((bp->nb_validend < 0) || (bp->nb_validend < end))
					bp->nb_validend = end;
				if ((off_t)np->n_size > boff + bp->nb_validend)
					bp->nb_validend = min(np->n_size - (boff + start), biosize);
				/* validate any pages before the write offset's page */
				for (; start < trunc_page_32(on); start+=PAGE_SIZE)
					NBPGVALID_SET(bp, start/PAGE_SIZE);
				/* validate any pages after the range of pages being written to */
				for (; (end - 1) > round_page_32(on+n-1); end-=PAGE_SIZE)
					NBPGVALID_SET(bp, (end-1)/PAGE_SIZE);
				/* Note: pages being written to will be validated when written */
			}
		}

		if (ISSET(bp->nb_flags, NB_ERROR)) {
			error = bp->nb_error;
			nfs_buf_release(bp, 1);
			np->n_flag &= ~NWRBUSY;
			FSDBG_BOT(515, vp, uio->uio_offset, uio_uio_resid(uio), error);
			return (error);
		}

		np->n_flag |= NMODIFIED;

		NFS_BUF_MAP(bp);
		error = uiomove((char *)bp->nb_data + on, n, uio);
		if (error) {
			SET(bp->nb_flags, NB_ERROR);
			nfs_buf_release(bp, 1);
			np->n_flag &= ~NWRBUSY;
			FSDBG_BOT(515, vp, uio->uio_offset, uio_uio_resid(uio), error);
			return (error);
		}

		/* validate any pages written to */
		start = on & ~PAGE_MASK;
		for (; start < on+n; start += PAGE_SIZE) {
			NBPGVALID_SET(bp, start/PAGE_SIZE);
			/*
			 * This may seem a little weird, but we don't actually set the
			 * dirty bits for writes.  This is because we keep the dirty range
			 * in the nb_dirtyoff/nb_dirtyend fields.  Also, particularly for
			 * delayed writes, when we give the pages back to the VM we don't
			 * want to keep them marked dirty, because when we later write the
			 * buffer we won't be able to tell which pages were written dirty
			 * and which pages were mmapped and dirtied.
			 */
		}
		if (bp->nb_dirtyend > 0) {
			bp->nb_dirtyoff = min(on, bp->nb_dirtyoff);
			bp->nb_dirtyend = max((on + n), bp->nb_dirtyend);
		} else {
			bp->nb_dirtyoff = on;
			bp->nb_dirtyend = on + n;
		}
		if (bp->nb_validend <= 0 || bp->nb_validend < bp->nb_dirtyoff ||
		    bp->nb_validoff > bp->nb_dirtyend) {
			bp->nb_validoff = bp->nb_dirtyoff;
			bp->nb_validend = bp->nb_dirtyend;
		} else {
			bp->nb_validoff = min(bp->nb_validoff, bp->nb_dirtyoff);
			bp->nb_validend = max(bp->nb_validend, bp->nb_dirtyend);
		}
		if (!ISSET(bp->nb_flags, NB_CACHE))
			nfs_buf_normalize_valid_range(np, bp);

		/*
		 * Since this block is being modified, it must be written
		 * again and not just committed.
		 */
		if (ISSET(bp->nb_flags, NB_NEEDCOMMIT)) {
			np->n_needcommitcnt--;
			CHECK_NEEDCOMMITCNT(np);
		}
		CLR(bp->nb_flags, NB_NEEDCOMMIT);

		if (ioflag & IO_SYNC) {
			bp->nb_proc = p;
			error = nfs_buf_write(bp);
			if (error) {
				np->n_flag &= ~NWRBUSY;
				FSDBG_BOT(515, vp, uio->uio_offset,
					uio_uio_resid(uio), error);
				return (error);
			}
		} else if (((n + on) == biosize) || (np->n_flag & NNOCACHE)) {
			bp->nb_proc = NULL;
			SET(bp->nb_flags, NB_ASYNC);
			nfs_buf_write(bp);
		} else
			nfs_buf_write_delayed(bp, p);

		if (np->n_needcommitcnt > (nfsbufcnt/16))
		        nfs_flushcommits(vp, p, 1);

	} while (uio_uio_resid(uio) > 0 && n > 0);

	np->n_flag &= ~NWRBUSY;
	FSDBG_BOT(515, vp, uio->uio_offset, uio_uio_resid(uio), 0);
	return (0);
}

/*
 * Flush out and invalidate all buffers associated with a vnode.
 * Called with the underlying object locked.
 */
static int
nfs_vinvalbuf_internal(
	vnode_t vp,
	int flags,
	kauth_cred_t cred,
	proc_t p,
	int slpflag,
	int slptimeo)
{
	struct nfsbuf *bp;
	struct nfsbuflists blist;
	int list, error = 0;
	struct nfsnode *np = VTONFS(vp);

	if (flags & V_SAVE) {
		if ((error = nfs_flush(vp, MNT_WAIT, cred, p,
					(flags & V_IGNORE_WRITEERR))))
			return (error);
		if (!LIST_EMPTY(&np->n_dirtyblkhd))
			panic("nfs_vinvalbuf: dirty bufs (vp 0x%x, bp 0x%x)",
				vp, LIST_FIRST(&np->n_dirtyblkhd));
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
				FSDBG(556, vp, bp, NBOFF(bp), bp->nb_flags);
				if (error != EAGAIN) {
					FSDBG(554, vp, bp, -1, error);
					nfs_buf_refrele(bp);
					nfs_buf_itercomplete(np, &blist, list);
					lck_mtx_unlock(nfs_buf_mutex);
					return (error);
				}
			}
			nfs_buf_refrele(bp);
			FSDBG(554, vp, bp, NBOFF(bp), bp->nb_flags);
			lck_mtx_unlock(nfs_buf_mutex);
			if ((flags & V_SAVE) && UBCINFOEXISTS(vp) && bp->nb_vp &&
			    (NBOFF(bp) < (off_t)np->n_size)) {
				/* XXX extra paranoia: make sure we're not */
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
				if (bp->nb_dirtyend && bp->nb_dirtyoff < end) {
					/* clip dirty range to EOF */
					if (bp->nb_dirtyend > end)
						bp->nb_dirtyend = end;
					mustwrite++;
				}
				bp->nb_dirty &= (1 << (round_page_32(end)/PAGE_SIZE)) - 1;
				/* also make sure we'll have a credential to do the write */
				if (mustwrite && (bp->nb_wcred == NOCRED) && (cred == NOCRED)) {
					printf("nfs_vinvalbuf: found dirty buffer with no write creds\n");
					mustwrite = 0;
				}
				if (mustwrite) {
					FSDBG(554, vp, bp, 0xd00dee, bp->nb_flags);
					if (!ISSET(bp->nb_flags, NB_PAGELIST))
						panic("nfs_vinvalbuf: dirty buffer without upl");
					/* gotta write out dirty data before invalidating */
					/* (NB_STABLE indicates that data writes should be FILESYNC) */
					/* (NB_NOCACHE indicates buffer should be discarded) */
					CLR(bp->nb_flags, (NB_DONE | NB_ERROR | NB_INVAL | NB_ASYNC));
					SET(bp->nb_flags, NB_STABLE | NB_NOCACHE);
					if (bp->nb_wcred == NOCRED) {
						kauth_cred_ref(cred);
						bp->nb_wcred = cred;
					}
					error = nfs_buf_write(bp);
					// Note: bp has been released
					if (error) {
						FSDBG(554, bp, 0xd00dee, 0xbad, error);
						np->n_error = error;
						np->n_flag |= NWRITEERR;
						/*
						 * There was a write error and we need to
						 * invalidate attrs to sync with server.
						 * (if this write was extending the file,
						 * we may no longer know the correct size)
						 */
						NATTRINVALIDATE(np);
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
	lck_mtx_unlock(nfs_buf_mutex);
	NFS_BUF_FREEUP();
	if (NVALIDBUFS(np))
		panic("nfs_vinvalbuf: flush failed");
	return (0);
}


/*
 * Flush and invalidate all dirty buffers. If another process is already
 * doing the flush, just wait for completion.
 */
int
nfs_vinvalbuf(
	vnode_t vp,
	int flags,
	kauth_cred_t cred,
	proc_t p,
	int intrflg)
{
	struct nfsnode *np = VTONFS(vp);
	struct nfsmount *nmp = VFSTONFS(vnode_mount(vp));
	int error = 0, slpflag, slptimeo;
	off_t size;

	FSDBG_TOP(554, vp, flags, intrflg, 0);

	if (nmp && ((nmp->nm_flag & NFSMNT_INT) == 0))
		intrflg = 0;
	if (intrflg) {
		slpflag = PCATCH;
		slptimeo = 2 * hz;
	} else {
		slpflag = 0;
		slptimeo = 0;
	}
	/*
	 * First wait for any other process doing a flush to complete.
	 */
	while (np->n_flag & NFLUSHINPROG) {
		np->n_flag |= NFLUSHWANT;
		FSDBG_TOP(555, vp, flags, intrflg, np->n_flag);
		error = tsleep((caddr_t)&np->n_flag, PRIBIO + 2, "nfsvinval", slptimeo);
		FSDBG_BOT(555, vp, flags, intrflg, np->n_flag);
		if (error && (error = nfs_sigintr(VFSTONFS(vnode_mount(vp)), NULL, p))) {
			FSDBG_BOT(554, vp, flags, intrflg, error);
			return (error);
		}
	}

	/*
	 * Now, flush as required.
	 */
	np->n_flag |= NFLUSHINPROG;
	error = nfs_vinvalbuf_internal(vp, flags, cred, p, slpflag, 0);
	while (error) {
		FSDBG(554, vp, 0, 0, error);
		error = nfs_sigintr(VFSTONFS(vnode_mount(vp)), NULL, p);
		if (error) {
			np->n_flag &= ~NFLUSHINPROG;
			if (np->n_flag & NFLUSHWANT) {
				np->n_flag &= ~NFLUSHWANT;
				wakeup((caddr_t)&np->n_flag);
			}
			FSDBG_BOT(554, vp, flags, intrflg, error);
			return (error);
		}
		error = nfs_vinvalbuf_internal(vp, flags, cred, p, 0, slptimeo);
	}
	np->n_flag &= ~(NMODIFIED | NFLUSHINPROG);
	if (np->n_flag & NFLUSHWANT) {
		np->n_flag &= ~NFLUSHWANT;
		wakeup((caddr_t)&np->n_flag);
	}
	/*
	 * get the pages out of vm also
	 */
	if (UBCINFOEXISTS(vp) && (size = ubc_getsize(vp))) {
		int rv = ubc_sync_range(vp, 0, size, UBC_PUSHALL | UBC_INVALIDATE);
		if (!rv)
			panic("nfs_vinvalbuf(): ubc_sync_range failed!");
	}

	FSDBG_BOT(554, vp, flags, intrflg, 0);
	return (0);
}

/*
 * Initiate asynchronous I/O. Return an error if no nfsiods are available.
 * This is mainly to avoid queueing async I/O requests when the nfsiods
 * are all hung on a dead server.
 */
int
nfs_asyncio(bp, cred)
	struct nfsbuf *bp;
	kauth_cred_t cred;
{
	struct nfsmount *nmp;
	int i;
	int gotiod;
	int slpflag = 0;
	int slptimeo = 0;
	int error, error2;
	void *wakeme = NULL;
	struct timespec ts;

	if (nfs_numasync == 0)
		return (EIO);

	FSDBG_TOP(552, bp, bp ? NBOFF(bp) : 0, bp ? bp->nb_flags : 0, 0);

	nmp = ((bp != NULL) ? VFSTONFS(vnode_mount(bp->nb_vp)) : NULL);
again:
	if (nmp && nmp->nm_flag & NFSMNT_INT)
		slpflag = PCATCH;
	gotiod = FALSE;

	lck_mtx_lock(nfs_iod_mutex);

	/* no nfsbuf means tell nfsiod to process delwri list */
	if (!bp)
		nfs_ioddelwri = 1;

	/*
	 * Find a free iod to process this request.
	 */
	for (i = 0; i < NFS_MAXASYNCDAEMON; i++)
		if (nfs_iodwant[i]) {
			/*
			 * Found one, so wake it up and tell it which
			 * mount to process.
			 */
			nfs_iodwant[i] = NULL;
			nfs_iodmount[i] = nmp;
			if (nmp)
				nmp->nm_bufqiods++;
			wakeme = &nfs_iodwant[i];
			gotiod = TRUE;
			break;
		}

	/* if we're just poking the delwri list, we're done */
	if (!bp) {
		lck_mtx_unlock(nfs_iod_mutex);
		if (wakeme)
			wakeup(wakeme);
		FSDBG_BOT(552, bp, 0x10101010, wakeme, 0);
		return (0);
	}

	/*
	 * If none are free, we may already have an iod working on this mount
	 * point.  If so, it will process our request.
	 */
	if (!gotiod) {
		if (nmp->nm_bufqiods > 0) {
			gotiod = TRUE;
		}
	}

	/*
	 * If we have an iod which can process the request, then queue
	 * the buffer.
	 */
	FSDBG(552, bp, gotiod, i, nmp->nm_bufqiods);
	if (gotiod) {
		/*
		 * Ensure that the queue never grows too large.
		 */
		while (nmp->nm_bufqlen >= 2*nfs_numasync) {
			if (ISSET(bp->nb_flags, NB_IOD)) {
				/* An nfsiod is attempting this async operation so */
				/* we must not fall asleep on the bufq because we */
				/* could be waiting on ourself.  Just return error */
				/* and we'll do this operation syncrhonously. */
				goto out;
			}
			FSDBG(552, bp, nmp->nm_bufqlen, 2*nfs_numasync, -1);
			nmp->nm_bufqwant = TRUE;

			ts.tv_sec = (slptimeo/100);
			/* the hz value is 100; which leads to 10ms */
			ts.tv_nsec = (slptimeo % 100) * 10  * NSEC_PER_USEC * 1000;

			error = msleep(&nmp->nm_bufq, nfs_iod_mutex, slpflag | PRIBIO,
				       "nfsaio", &ts);
			if (error) {
				error2 = nfs_sigintr(nmp, NULL, bp->nb_proc);
				if (error2) {
					lck_mtx_unlock(nfs_iod_mutex);
					FSDBG_BOT(552, bp, NBOFF(bp), bp->nb_flags, error2);
					return (error2);
				}
				if (slpflag == PCATCH) {
					slpflag = 0;
					slptimeo = 2 * hz;
				}
			}
			/*
			 * We might have lost our iod while sleeping,
			 * so check and loop if nescessary.
			 */
			if (nmp->nm_bufqiods == 0) {
				lck_mtx_unlock(nfs_iod_mutex);
				goto again;
			}
		}

		if (ISSET(bp->nb_flags, NB_READ)) {
			if (bp->nb_rcred == NOCRED && cred != NOCRED) {
				kauth_cred_ref(cred);
				bp->nb_rcred = cred;
			}
		} else {
			SET(bp->nb_flags, NB_WRITEINPROG);
			if (bp->nb_wcred == NOCRED && cred != NOCRED) {
				kauth_cred_ref(cred);
				bp->nb_wcred = cred;
			}
		}

		TAILQ_INSERT_TAIL(&nmp->nm_bufq, bp, nb_free);
		nmp->nm_bufqlen++;
		lck_mtx_unlock(nfs_iod_mutex);
		if (wakeme)
			wakeup(wakeme);
		FSDBG_BOT(552, bp, NBOFF(bp), bp->nb_flags, 0);
		return (0);
	}

out:
	lck_mtx_unlock(nfs_iod_mutex);
	/*
	 * All the iods are busy on other mounts, so return EIO to
	 * force the caller to process the i/o synchronously.
	 */
	FSDBG_BOT(552, bp, NBOFF(bp), bp->nb_flags, EIO);
	return (EIO);
}

/*
 * Do an I/O operation to/from a cache block. This may be called
 * synchronously or from an nfsiod.
 */
int
nfs_doio(struct nfsbuf *bp, kauth_cred_t cr, proc_t p)
{
	struct uio *uiop;
	vnode_t vp;
	struct nfsnode *np;
	struct nfsmount *nmp;
	int error = 0, diff, len, iomode, invalidate = 0;
	struct uio uio;
	struct iovec_32 io;
	enum vtype vtype;

	vp = bp->nb_vp;
	vtype = vnode_vtype(vp);
	np = VTONFS(vp);
	nmp = VFSTONFS(vnode_mount(vp));
	uiop = &uio;
	uiop->uio_iovs.iov32p = &io;
	uiop->uio_iovcnt = 1;
#if 1   /* LP64todo - can't use new segment flags until the drivers are ready */
	uiop->uio_segflg = UIO_SYSSPACE;
#else
	uiop->uio_segflg = UIO_SYSSPACE32;
#endif 

	/*
	 * we've decided to perform I/O for this block,
	 * so we couldn't possibly NB_DONE.  So, clear it.
	 */
	if (ISSET(bp->nb_flags, NB_DONE)) {
		if (!ISSET(bp->nb_flags, NB_ASYNC))
			panic("nfs_doio: done and not async");
		CLR(bp->nb_flags, NB_DONE);
	}
	FSDBG_TOP(256, np->n_size, NBOFF(bp), bp->nb_bufsize, bp->nb_flags);
	FSDBG(257, bp->nb_validoff, bp->nb_validend, bp->nb_dirtyoff,
	      bp->nb_dirtyend);

	if (ISSET(bp->nb_flags, NB_READ)) {
	    if (vtype == VREG)
		    NFS_BUF_MAP(bp);
	    io.iov_len = bp->nb_bufsize;
	    uio_uio_resid_set(uiop, io.iov_len);
	    io.iov_base = (uintptr_t) bp->nb_data;
	    uiop->uio_rw = UIO_READ;
	    switch (vtype) {
	    case VREG:
		uiop->uio_offset = NBOFF(bp);
		OSAddAtomic(1, (SInt32*)&nfsstats.read_bios);
		error = nfs_readrpc(vp, uiop, cr, p);
		FSDBG(262, np->n_size, NBOFF(bp), uio_uio_resid(uiop), error);
		if (!error) {
		    /* update valid range */
		    bp->nb_validoff = 0;
		    if (uio_uio_resid(uiop) != 0) {
			/*
			 * If len > 0, there is a hole in the file and
			 * no writes after the hole have been pushed to
			 * the server yet.
			 * Just zero fill the rest of the valid area.
			 */
			// LP64todo - fix this
			diff = bp->nb_bufsize - uio_uio_resid(uiop);
			len = np->n_size - (NBOFF(bp) + diff);
			if (len > 0) {
				// LP64todo - fix this
				len = min(len, uio_uio_resid(uiop));
				bzero((char *)bp->nb_data + diff, len);
				bp->nb_validend = diff + len;
				FSDBG(258, diff, len, 0, 1);
			} else
				bp->nb_validend = diff;
		    } else
				bp->nb_validend = bp->nb_bufsize;
		    bp->nb_valid = (1 << (round_page_32(bp->nb_validend)/PAGE_SIZE)) - 1;
		    if (bp->nb_validend & PAGE_MASK) {
			    /* valid range ends in the middle of a page so we */
			    /* need to zero-fill any invalid data at the end */
			    /* of the last page */
			    bzero((caddr_t)(bp->nb_data + bp->nb_validend),
			          bp->nb_bufsize - bp->nb_validend);
			    FSDBG(258, bp->nb_validend,
			          bp->nb_bufsize - bp->nb_validend, 0, 2);
		    }
		}
		break;
	    case VLNK:
		uiop->uio_offset = (off_t)0;
		OSAddAtomic(1, (SInt32*)&nfsstats.readlink_bios);
		error = nfs_readlinkrpc(vp, uiop, cr, p);
		if (!error) {
			bp->nb_validoff = 0;
			bp->nb_validend = uiop->uio_offset;
		}
		break;
	    case VDIR:
		OSAddAtomic(1, (SInt32*)&nfsstats.readdir_bios);
		uiop->uio_offset = NBOFF(bp);
		if (!(nmp->nm_flag & NFSMNT_NFSV3))
			nmp->nm_flag &= ~NFSMNT_RDIRPLUS; /* dk@farm.org */
		if (nmp->nm_flag & NFSMNT_RDIRPLUS) {
			error = nfs_readdirplusrpc(vp, uiop, cr, p);
			if (error == NFSERR_NOTSUPP)
				nmp->nm_flag &= ~NFSMNT_RDIRPLUS;
		}
		if ((nmp->nm_flag & NFSMNT_RDIRPLUS) == 0)
			error = nfs_readdirrpc(vp, uiop, cr, p);
		if (!error) {
			bp->nb_validoff = 0;
			bp->nb_validend = uiop->uio_offset - NBOFF(bp);
			bp->nb_valid = (1 << (round_page_32(bp->nb_validend)/PAGE_SIZE)) - 1;
		}
		break;
	    default:
		printf("nfs_doio: type %x unexpected\n", vtype);
		break;
	    };
	    if (error) {
		SET(bp->nb_flags, NB_ERROR);
		bp->nb_error = error;
	    }

	} else {
	    /* we're doing a write */
	    int doff, dend = 0;

	    /* We need to make sure the pages are locked before doing I/O.  */
	    if (!ISSET(bp->nb_flags, NB_META) && UBCINFOEXISTS(vp)) {
		if (!ISSET(bp->nb_flags, NB_PAGELIST)) {
		    error = nfs_buf_upl_setup(bp);
		    if (error) {
			printf("nfs_doio: upl create failed %d\n", error);
			SET(bp->nb_flags, NB_ERROR);
			bp->nb_error = EIO;
			return (EIO);
		    }
		    nfs_buf_upl_check(bp);
		}
	    }

	    if (ISSET(bp->nb_flags, NB_WASDIRTY)) {
		FSDBG(256, bp, NBOFF(bp), bp->nb_dirty, 0xd00dee);
		/*
		 * There are pages marked dirty that need to be written out.
		 *
		 * We don't want to just combine the write range with the
		 * range of pages that are dirty because that could cause us
		 * to write data that wasn't actually written to.
		 * We also don't want to write data more than once.
		 *
		 * If the dirty range just needs to be committed, we do that.
		 * Otherwise, we write the dirty range and clear the dirty bits
		 * for any COMPLETE pages covered by that range.
		 * If there are dirty pages left after that, we write out the
		 * parts that we haven't written yet.
		 */
	    }

	    /*
	     * If NB_NEEDCOMMIT is set, a commit rpc may do the trick. If not
	     * an actual write will have to be done.
	     * If NB_WRITEINPROG is already set, then push it with a write anyhow.
	     */
	    if (ISSET(bp->nb_flags, NB_NEEDCOMMIT))
	    	nfs_buf_check_write_verifier(np, bp);
	    if ((bp->nb_flags & (NB_NEEDCOMMIT | NB_WRITEINPROG)) == NB_NEEDCOMMIT) {
		doff = NBOFF(bp) + bp->nb_dirtyoff;
		SET(bp->nb_flags, NB_WRITEINPROG);
		error = nfs_commit(vp, doff, bp->nb_dirtyend - bp->nb_dirtyoff,
				bp->nb_wcred, bp->nb_proc);
		CLR(bp->nb_flags, NB_WRITEINPROG);
		if (!error) {
		    bp->nb_dirtyoff = bp->nb_dirtyend = 0;
		    CLR(bp->nb_flags, NB_NEEDCOMMIT);
		    np->n_needcommitcnt--;
		    CHECK_NEEDCOMMITCNT(np);
		}
	    }

	    if (!error && bp->nb_dirtyend > 0) {
		/* there's a dirty range that needs to be written out */
		u_int32_t pagemask;
		int firstpg, lastpg;

		if (NBOFF(bp) + bp->nb_dirtyend > (off_t)np->n_size)
		    bp->nb_dirtyend = np->n_size - NBOFF(bp);

		NFS_BUF_MAP(bp);

		doff = bp->nb_dirtyoff;
		dend = bp->nb_dirtyend;

		/* if doff page is dirty, move doff to start of page */
		if (NBPGDIRTY(bp,doff/PAGE_SIZE))
		    doff -= doff & PAGE_MASK;
		/* try to expand write range to include preceding dirty pages */
		if (!(doff & PAGE_MASK))
		    while (doff > 0 && NBPGDIRTY(bp,(doff-1)/PAGE_SIZE))
		    	doff -= PAGE_SIZE;
		/* if dend page is dirty, move dend to start of next page */
		if ((dend & PAGE_MASK) && NBPGDIRTY(bp,dend/PAGE_SIZE))
		    dend = round_page_32(dend);
		/* try to expand write range to include trailing dirty pages */
		if (!(dend & PAGE_MASK))
		    while (dend < bp->nb_bufsize && NBPGDIRTY(bp,dend/PAGE_SIZE))
		    	dend += PAGE_SIZE;
		/* make sure to keep dend clipped to EOF */
		if (NBOFF(bp) + dend > (off_t)np->n_size)
		    dend = np->n_size - NBOFF(bp);
		/* calculate range of complete pages being written */
		firstpg = round_page_32(doff) / PAGE_SIZE;
		lastpg = (trunc_page_32(dend) - 1)/ PAGE_SIZE;
		/* calculate mask for that page range */
		pagemask = ((1 << (lastpg+1)) - 1) & ~((1 << firstpg) - 1);

		/* compare page mask to nb_dirty; if there are other dirty pages */
		/* then write FILESYNC; otherwise, write UNSTABLE if async and */
		/* not needcommit/nocache/call; otherwise write FILESYNC */
		if (bp->nb_dirty & ~pagemask)
		    iomode = NFSV3WRITE_FILESYNC;
		else if ((bp->nb_flags & (NB_ASYNC | NB_NEEDCOMMIT | NB_NOCACHE | NB_STABLE)) == NB_ASYNC)
		    iomode = NFSV3WRITE_UNSTABLE;
		else
		    iomode = NFSV3WRITE_FILESYNC;

		/* write the dirty range */
		io.iov_len = dend - doff;
		uio_uio_resid_set(uiop, io.iov_len);
		uiop->uio_offset = NBOFF(bp) + doff;
		io.iov_base = (uintptr_t) bp->nb_data + doff;
		uiop->uio_rw = UIO_WRITE;

		OSAddAtomic(1, (SInt32*)&nfsstats.write_bios);

		SET(bp->nb_flags, NB_WRITEINPROG);
		error = nfs_writerpc(vp, uiop, cr, p, &iomode, &bp->nb_verf);
		/* clear dirty bits for pages we've written */
		if (!error)
		    bp->nb_dirty &= ~pagemask;
		/* set/clear needcommit flag */
		if (!error && iomode == NFSV3WRITE_UNSTABLE) {
		    if (!ISSET(bp->nb_flags, NB_NEEDCOMMIT))
			np->n_needcommitcnt++;
		    SET(bp->nb_flags, NB_NEEDCOMMIT);
		    /* make sure nb_dirtyoff/nb_dirtyend reflect actual range written */
		    bp->nb_dirtyoff = doff;
		    bp->nb_dirtyend = dend;
		} else {
		    if (ISSET(bp->nb_flags, NB_NEEDCOMMIT)) {
			np->n_needcommitcnt--;
			CHECK_NEEDCOMMITCNT(np);
		    }
		    CLR(bp->nb_flags, NB_NEEDCOMMIT);
		}
		CLR(bp->nb_flags, NB_WRITEINPROG);
		/*
		 * For an interrupted write, the buffer is still valid and the write
		 * hasn't been pushed to the server yet, so we can't set NB_ERROR and
		 * report the interruption by setting NB_EINTR.  For the NB_ASYNC case,
		 * NB_EINTR is not relevant.
		 *
		 * For the case of a V3 write rpc not being committed to stable
		 * storage, the block is still dirty and requires either a commit rpc
		 * or another write rpc with iomode == NFSV3WRITE_FILESYNC before the
		 * block is reused. This is indicated by setting the NB_DELWRI and
		 * NB_NEEDCOMMIT flags.
		 */
		if (error == EINTR || (!error && bp->nb_flags & NB_NEEDCOMMIT)) {
		    CLR(bp->nb_flags, NB_INVAL | NB_NOCACHE);
		    if (!ISSET(bp->nb_flags, NB_DELWRI)) {
			SET(bp->nb_flags, NB_DELWRI);
			OSAddAtomic(1, (SInt32*)&nfs_nbdwrite);
			NFSBUFCNTCHK(0);
		    }
		    FSDBG(261, bp->nb_validoff, bp->nb_validend,
			  bp->nb_bufsize, 0);
		    /*
		     * Since for the NB_ASYNC case, nfs_bwrite() has
		     * reassigned the buffer to the clean list, we have to
		     * reassign it back to the dirty one. Ugh.
		     */
		    if (ISSET(bp->nb_flags, NB_ASYNC)) {
			/* move to dirty list */
			lck_mtx_lock(nfs_buf_mutex);
			if (bp->nb_vnbufs.le_next != NFSNOLIST)
			    LIST_REMOVE(bp, nb_vnbufs);
			LIST_INSERT_HEAD(&np->n_dirtyblkhd, bp, nb_vnbufs);
			lck_mtx_unlock(nfs_buf_mutex);
		    } else {
			SET(bp->nb_flags, NB_EINTR);
		    }
		} else {
			/* either there's an error or we don't need to commit */
			if (error) {
			    SET(bp->nb_flags, NB_ERROR);
			    bp->nb_error = np->n_error = error;
			    np->n_flag |= NWRITEERR;
			    /*
			     * There was a write error and we need to
			     * invalidate attrs and flush buffers in
			     * order to sync up with the server.
			     * (if this write was extending the file,
			     * we may no longer know the correct size)
			     *
			     * But we can't call vinvalbuf while holding
			     * this buffer busy.  Set a flag to do it after
			     * releasing the buffer.
			     *
			     * Note we can only invalidate in this function
			     * if this is an async write and so the iodone
			     * below will release the buffer.  Also, we
			     * shouldn't call vinvalbuf from nfsiod because
			     * that may deadlock waiting for the completion
			     * of writes that are queued up behind this one.
			     */
			    if (ISSET(bp->nb_flags, NB_ASYNC) &&
			        !ISSET(bp->nb_flags, NB_IOD)) {
				    invalidate = 1;
			    } else {
				    /* invalidate later */
				    np->n_flag |= NNEEDINVALIDATE;
			    }
			    NATTRINVALIDATE(np);
			}
			/* clear the dirty range */
			bp->nb_dirtyoff = bp->nb_dirtyend = 0;
		}
	    }

	    if (!error && bp->nb_dirty) {
		/* there are pages marked dirty that need to be written out */
		int pg, count, npages, off;

		OSAddAtomic(1, (SInt32*)&nfsstats.write_bios);

		NFS_BUF_MAP(bp);

		/*
		 * we do these writes synchronously because we can't really
		 * support the unstable/needommit method.  We could write
		 * them unstable, clear the dirty bits, and then commit the
		 * whole block later, but if we need to rewrite the data, we
		 * won't have any idea which pages were written because that
		 * info can't be stored in the nb_dirtyoff/nb_dirtyend.  We
		 * also can't leave the dirty bits set because then we wouldn't
		 * be able to tell if the pages were re-dirtied between the end
		 * of the write and the commit.
		 */
		iomode = NFSV3WRITE_FILESYNC;
		uiop->uio_rw = UIO_WRITE;

		SET(bp->nb_flags, NB_WRITEINPROG);
		npages = bp->nb_bufsize/PAGE_SIZE;
		for (pg=0; pg < npages; pg++) {
		    if (!NBPGDIRTY(bp,pg))
		    	continue;
		    count = 1;
		    while (((pg+count) < npages) && NBPGDIRTY(bp,pg+count))
			    count++;
		    /* write count pages starting with page pg */
		    off = pg * PAGE_SIZE;
		    len = count * PAGE_SIZE;

		    /* clip writes to EOF */
		    if (NBOFF(bp) + off + len > (off_t)np->n_size)
		    	len -= (NBOFF(bp) + off + len) - np->n_size;
		    if (len > 0) {
			io.iov_len = len;
			uio_uio_resid_set(uiop, io.iov_len);
			uiop->uio_offset = NBOFF(bp) + off;
			io.iov_base = (uintptr_t) bp->nb_data + off;
			error = nfs_writerpc(vp, uiop, cr, p, &iomode, &bp->nb_verf);
			if (error)
			    break;
		    }
		    /* clear dirty bits */
		    while (count--) {
			   bp->nb_dirty &= ~(1 << pg);
			   /* leave pg on last page */
			   if (count) pg++;
		    }
		}
		if (!error) {
		    if (ISSET(bp->nb_flags, NB_NEEDCOMMIT)) {
			np->n_needcommitcnt--;
			CHECK_NEEDCOMMITCNT(np);
		    }
		    CLR(bp->nb_flags, NB_NEEDCOMMIT);
		}
		CLR(bp->nb_flags, NB_WRITEINPROG);
		FSDBG_BOT(256, bp->nb_validoff, bp->nb_validend, bp->nb_bufsize,
			  np->n_size);
	    }

	    if (error) {
		SET(bp->nb_flags, NB_ERROR);
		bp->nb_error = error;
	    }
	}

	FSDBG_BOT(256, bp->nb_validoff, bp->nb_validend, bp->nb_bufsize, error);

	nfs_buf_iodone(bp);

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
		 *
		 * Note: we don't bother calling nfs_vinvalbuf() if
		 * there's already a flush in progress.
		 */
		if (!(np->n_flag & NFLUSHINPROG))
			nfs_vinvalbuf(vp, V_SAVE|V_IGNORE_WRITEERR, cr, p, 1);
	}

	return (error);
}
