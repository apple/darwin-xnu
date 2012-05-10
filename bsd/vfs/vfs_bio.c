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
/*-
 * Copyright (c) 1994 Christopher G. Demetriou
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	@(#)vfs_bio.c	8.6 (Berkeley) 1/11/94
 */

/*
 * Some references:
 *	Bach: The Design of the UNIX Operating System (Prentice Hall, 1986)
 *	Leffler, et al.: The Design and Implementation of the 4.3BSD
 *		UNIX Operating System (Addison Welley, 1989)
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc_internal.h>
#include <sys/buf_internal.h>
#include <sys/vnode_internal.h>
#include <sys/mount_internal.h>
#include <sys/trace.h>
#include <sys/malloc.h>
#include <sys/resourcevar.h>
#include <miscfs/specfs/specdev.h>
#include <sys/ubc.h>
#include <sys/kauth.h>
#if DIAGNOSTIC
#include <kern/assert.h>
#endif /* DIAGNOSTIC */
#include <kern/task.h>
#include <kern/zalloc.h>
#include <kern/lock.h>

#include <sys/fslog.h>		/* fslog_io_error() */

#include <mach/mach_types.h>
#include <mach/memory_object_types.h>
#include <kern/sched_prim.h>	/* thread_block() */

#include <vm/vm_kern.h>
#include <vm/vm_pageout.h>

#include <sys/kdebug.h>

#include <libkern/OSAtomic.h>
#include <libkern/OSDebug.h>
#include <sys/ubc_internal.h>

#include <sys/sdt.h>


#if BALANCE_QUEUES
static __inline__ void bufqinc(int q);
static __inline__ void bufqdec(int q);
#endif

int	bcleanbuf(buf_t bp, boolean_t discard);
static int	brecover_data(buf_t bp);
static boolean_t incore(vnode_t vp, daddr64_t blkno);
/* timeout is in msecs */
static buf_t	getnewbuf(int slpflag, int slptimeo, int *queue);
static void	bremfree_locked(buf_t bp);
static void	buf_reassign(buf_t bp, vnode_t newvp);
static errno_t	buf_acquire_locked(buf_t bp, int flags, int slpflag, int slptimeo);
static int	buf_iterprepare(vnode_t vp, struct buflists *, int flags);
static void	buf_itercomplete(vnode_t vp, struct buflists *, int flags);
static boolean_t buffer_cache_gc(int);
static buf_t	buf_brelse_shadow(buf_t bp);
static void	buf_free_meta_store(buf_t bp);

static buf_t	buf_create_shadow_internal(buf_t bp, boolean_t force_copy,
					   uintptr_t external_storage, void (*iodone)(buf_t, void *), void *arg, int priv);


__private_extern__ int  bdwrite_internal(buf_t, int);

/* zone allocated buffer headers */
static void	bufzoneinit(void) __attribute__((section("__TEXT, initcode")));
static void	bcleanbuf_thread_init(void) __attribute__((section("__TEXT, initcode")));
static void	bcleanbuf_thread(void);

static zone_t	buf_hdr_zone;
static int	buf_hdr_count;


/*
 * Definitions for the buffer hash lists.
 */
#define	BUFHASH(dvp, lbn)	\
	(&bufhashtbl[((long)(dvp) / sizeof(*(dvp)) + (int)(lbn)) & bufhash])
LIST_HEAD(bufhashhdr, buf) *bufhashtbl, invalhash;
u_long	bufhash;

static buf_t	incore_locked(vnode_t vp, daddr64_t blkno, struct bufhashhdr *dp);

/* Definitions for the buffer stats. */
struct bufstats bufstats;

/* Number of delayed write buffers */
long nbdwrite = 0;
int blaundrycnt = 0;
static int boot_nbuf_headers = 0;

static TAILQ_HEAD(delayqueue, buf) delaybufqueue;

static TAILQ_HEAD(ioqueue, buf) iobufqueue;
static TAILQ_HEAD(bqueues, buf) bufqueues[BQUEUES];
static int needbuffer;
static int need_iobuffer;

static lck_grp_t	*buf_mtx_grp;
static lck_attr_t	*buf_mtx_attr;
static lck_grp_attr_t   *buf_mtx_grp_attr;
static lck_mtx_t	*iobuffer_mtxp;
static lck_mtx_t	*buf_mtxp;

static int buf_busycount;

static __inline__ int
buf_timestamp(void)
{
	struct	timeval		t;
	microuptime(&t);
	return (t.tv_sec);
}

/*
 * Insq/Remq for the buffer free lists.
 */
#if BALANCE_QUEUES
#define	binsheadfree(bp, dp, whichq)	do { \
				    TAILQ_INSERT_HEAD(dp, bp, b_freelist); \
					bufqinc((whichq));	\
				} while (0)

#define	binstailfree(bp, dp, whichq)	do { \
				    TAILQ_INSERT_TAIL(dp, bp, b_freelist); \
					bufqinc((whichq));	\
				} while (0)
#else
#define	binsheadfree(bp, dp, whichq)	do { \
				    TAILQ_INSERT_HEAD(dp, bp, b_freelist); \
				} while (0)

#define	binstailfree(bp, dp, whichq)	do { \
				    TAILQ_INSERT_TAIL(dp, bp, b_freelist); \
				} while (0)
#endif


#define BHASHENTCHECK(bp)	\
	if ((bp)->b_hash.le_prev != (struct buf **)0xdeadbeef)	\
		panic("%p: b_hash.le_prev is not deadbeef", (bp));

#define BLISTNONE(bp)	\
	(bp)->b_hash.le_next = (struct buf *)0;	\
	(bp)->b_hash.le_prev = (struct buf **)0xdeadbeef;

/*
 * Insq/Remq for the vnode usage lists.
 */
#define	bufinsvn(bp, dp)	LIST_INSERT_HEAD(dp, bp, b_vnbufs)
#define	bufremvn(bp) {							\
	LIST_REMOVE(bp, b_vnbufs);					\
	(bp)->b_vnbufs.le_next = NOLIST;				\
}

/*
 * Time in seconds before a buffer on a list is 
 * considered as a stale buffer 
 */
#define LRU_IS_STALE 120 /* default value for the LRU */
#define AGE_IS_STALE 60  /* default value for the AGE */
#define META_IS_STALE 180 /* default value for the BQ_META */

int lru_is_stale = LRU_IS_STALE;
int age_is_stale = AGE_IS_STALE;
int meta_is_stale = META_IS_STALE;

#define MAXLAUNDRY	10

/* LIST_INSERT_HEAD() with assertions */
static __inline__ void
blistenterhead(struct bufhashhdr * head, buf_t bp)
{
	if ((bp->b_hash.le_next = (head)->lh_first) != NULL)
		(head)->lh_first->b_hash.le_prev = &(bp)->b_hash.le_next;
	(head)->lh_first = bp;
	bp->b_hash.le_prev = &(head)->lh_first;
	if (bp->b_hash.le_prev == (struct buf **)0xdeadbeef) 
		panic("blistenterhead: le_prev is deadbeef");
}

static __inline__ void 
binshash(buf_t bp, struct bufhashhdr *dp)
{
#if DIAGNOSTIC
	buf_t	nbp;
#endif /* DIAGNOSTIC */

	BHASHENTCHECK(bp);

#if DIAGNOSTIC
	nbp = dp->lh_first;
	for(; nbp != NULL; nbp = nbp->b_hash.le_next) {
		if(nbp == bp) 
			panic("buf already in hashlist");
	}
#endif /* DIAGNOSTIC */

	blistenterhead(dp, bp);
}

static __inline__ void 
bremhash(buf_t	bp) 
{
	if (bp->b_hash.le_prev == (struct buf **)0xdeadbeef) 
		panic("bremhash le_prev is deadbeef");
	if (bp->b_hash.le_next == bp) 
		panic("bremhash: next points to self");

	if (bp->b_hash.le_next != NULL)
		bp->b_hash.le_next->b_hash.le_prev = bp->b_hash.le_prev;
	*bp->b_hash.le_prev = (bp)->b_hash.le_next;
}

/*
 * buf_mtxp held.
 */
static __inline__ void
bmovelaundry(buf_t bp)
{
	bp->b_whichq = BQ_LAUNDRY;
	bp->b_timestamp = buf_timestamp();
	binstailfree(bp, &bufqueues[BQ_LAUNDRY], BQ_LAUNDRY);
	blaundrycnt++;
}

static __inline__ void
buf_release_credentials(buf_t bp)
{
	if (IS_VALID_CRED(bp->b_rcred)) {
		kauth_cred_unref(&bp->b_rcred);
	}
	if (IS_VALID_CRED(bp->b_wcred)) {
		kauth_cred_unref(&bp->b_wcred);
	}
}


int
buf_valid(buf_t bp) {

        if ( (bp->b_flags & (B_DONE | B_DELWRI)) )
	        return 1;
	return 0;
}

int
buf_fromcache(buf_t bp) {

        if ( (bp->b_flags & B_CACHE) )
	        return 1;
	return 0;
}

void
buf_markinvalid(buf_t bp) {
  
        SET(bp->b_flags, B_INVAL);
}

void
buf_markdelayed(buf_t bp) {
  
	if (!ISSET(bp->b_flags, B_DELWRI)) {
		SET(bp->b_flags, B_DELWRI);

		OSAddAtomicLong(1, &nbdwrite);
		buf_reassign(bp, bp->b_vp);
	}
        SET(bp->b_flags, B_DONE);
}

void
buf_markclean(buf_t bp) {

	if (ISSET(bp->b_flags, B_DELWRI)) {
		CLR(bp->b_flags, B_DELWRI);

		OSAddAtomicLong(-1, &nbdwrite);
		buf_reassign(bp, bp->b_vp);
	}
}

void
buf_markeintr(buf_t bp) {
  
        SET(bp->b_flags, B_EINTR);
}


void
buf_markaged(buf_t bp) {
  
        SET(bp->b_flags, B_AGE);
}

int
buf_fua(buf_t bp) {

        if ((bp->b_flags & B_FUA) == B_FUA)
	        return 1;
	return 0;
}

void 
buf_markfua(buf_t bp) {

        SET(bp->b_flags, B_FUA);
}

#ifdef CONFIG_PROTECT
void *
buf_getcpaddr(buf_t bp) {
	return bp->b_cpentry;
}

void 
buf_setcpaddr(buf_t bp, void *cp_entry_addr) {
	bp->b_cpentry = (struct cprotect *) cp_entry_addr;
}

#else
void *
buf_getcpaddr(buf_t bp __unused) {
	return NULL;
}

void 
buf_setcpaddr(buf_t bp __unused, void *cp_entry_addr __unused) {
	return;
}
#endif /* CONFIG_PROTECT */

int
bufattr_throttled(bufattr_t bap) {
	if ( (bap->ba_flags & BA_THROTTLED_IO) )
		return 1;
	return 0;
}

bufattr_t
buf_attr(buf_t bp) {
	return &bp->b_attr;
}

errno_t
buf_error(buf_t bp) {
        
        return (bp->b_error);
}

void
buf_seterror(buf_t bp, errno_t error) {

        if ((bp->b_error = error))
	        SET(bp->b_flags, B_ERROR);
	else
	        CLR(bp->b_flags, B_ERROR);
}

void
buf_setflags(buf_t bp, int32_t flags) {

        SET(bp->b_flags, (flags & BUF_X_WRFLAGS));
}

void
buf_clearflags(buf_t bp, int32_t flags) {

        CLR(bp->b_flags, (flags & BUF_X_WRFLAGS));
}

int32_t
buf_flags(buf_t bp) {
        
        return ((bp->b_flags & BUF_X_RDFLAGS));
}

void
buf_reset(buf_t bp, int32_t io_flags) {
        
        CLR(bp->b_flags, (B_READ | B_WRITE | B_ERROR | B_DONE | B_INVAL | B_ASYNC | B_NOCACHE | B_FUA));
	SET(bp->b_flags, (io_flags & (B_ASYNC | B_READ | B_WRITE | B_NOCACHE)));

	bp->b_error = 0;
}

uint32_t
buf_count(buf_t bp) {
        
        return (bp->b_bcount);
}

void
buf_setcount(buf_t bp, uint32_t bcount) {
        
        bp->b_bcount = bcount;
}

uint32_t
buf_size(buf_t bp) {
        
        return (bp->b_bufsize);
}

void
buf_setsize(buf_t bp, uint32_t bufsize) {
        
        bp->b_bufsize = bufsize;
}

uint32_t
buf_resid(buf_t bp) {
        
        return (bp->b_resid);
}

void
buf_setresid(buf_t bp, uint32_t resid) {
        
        bp->b_resid = resid;
}

uint32_t
buf_dirtyoff(buf_t bp) {

        return (bp->b_dirtyoff);
}

uint32_t
buf_dirtyend(buf_t bp) {

        return (bp->b_dirtyend);
}

void
buf_setdirtyoff(buf_t bp, uint32_t dirtyoff) {
        
        bp->b_dirtyoff = dirtyoff;
}

void
buf_setdirtyend(buf_t bp, uint32_t dirtyend) {
        
        bp->b_dirtyend = dirtyend;
}

uintptr_t
buf_dataptr(buf_t bp) {
        
        return (bp->b_datap);
}

void
buf_setdataptr(buf_t bp, uintptr_t data) {
        
        bp->b_datap = data;
}

vnode_t
buf_vnode(buf_t bp) {
        
        return (bp->b_vp);
}

void
buf_setvnode(buf_t bp, vnode_t vp) {
        
        bp->b_vp = vp;
}


void *
buf_callback(buf_t bp)
{
        if ( !(bp->b_flags & B_CALL) )
	        return ((void *) NULL);

	return ((void *)bp->b_iodone);
}


errno_t
buf_setcallback(buf_t bp, void (*callback)(buf_t, void *), void *transaction)
{
	if (callback)
	        bp->b_flags |= (B_CALL | B_ASYNC);
	else
	        bp->b_flags &= ~B_CALL;
	bp->b_transaction = transaction;
	bp->b_iodone = callback;

	return (0);
}

errno_t
buf_setupl(buf_t bp, upl_t upl, uint32_t offset)
{

        if ( !(bp->b_lflags & BL_IOBUF) )
	        return (EINVAL);

	if (upl)
	        bp->b_flags |= B_CLUSTER;
	else
	        bp->b_flags &= ~B_CLUSTER;
	bp->b_upl = upl;
	bp->b_uploffset = offset;

	return (0);
}

buf_t
buf_clone(buf_t bp, int io_offset, int io_size, void (*iodone)(buf_t, void *), void *arg)
{
        buf_t	io_bp;

	if (io_offset < 0 || io_size < 0)
	        return (NULL);

	if ((unsigned)(io_offset + io_size) > (unsigned)bp->b_bcount)
	        return (NULL);

	if (bp->b_flags & B_CLUSTER) {
	        if (io_offset && ((bp->b_uploffset + io_offset) & PAGE_MASK))
		        return (NULL);

	        if (((bp->b_uploffset + io_offset + io_size) & PAGE_MASK) && ((io_offset + io_size) < bp->b_bcount))
		        return (NULL);
	}
	io_bp = alloc_io_buf(bp->b_vp, 0);

	io_bp->b_flags = bp->b_flags & (B_COMMIT_UPL | B_META | B_PAGEIO | B_CLUSTER | B_PHYS | B_RAW | B_ASYNC | B_READ | B_FUA);

	if (iodone) {
	        io_bp->b_transaction = arg;
		io_bp->b_iodone = iodone;
		io_bp->b_flags |= B_CALL;
	}
	if (bp->b_flags & B_CLUSTER) {
	        io_bp->b_upl = bp->b_upl;
		io_bp->b_uploffset = bp->b_uploffset + io_offset;
	} else {
	        io_bp->b_datap  = (uintptr_t)(((char *)bp->b_datap) + io_offset);
	}
	io_bp->b_bcount = io_size;

	return (io_bp);
}


int
buf_shadow(buf_t bp)
{
	if (bp->b_lflags & BL_SHADOW)
		return 1;
	return 0;
}


buf_t
buf_create_shadow_priv(buf_t bp, boolean_t force_copy, uintptr_t external_storage, void (*iodone)(buf_t, void *), void *arg)
{
	return (buf_create_shadow_internal(bp, force_copy, external_storage, iodone, arg, 1));
}

buf_t
buf_create_shadow(buf_t bp, boolean_t force_copy, uintptr_t external_storage, void (*iodone)(buf_t, void *), void *arg)
{
	return (buf_create_shadow_internal(bp, force_copy, external_storage, iodone, arg, 0));
}


static buf_t
buf_create_shadow_internal(buf_t bp, boolean_t force_copy, uintptr_t external_storage, void (*iodone)(buf_t, void *), void *arg, int priv)
{
        buf_t	io_bp;

	KERNEL_DEBUG(0xbbbbc000 | DBG_FUNC_START, bp, 0, 0, 0, 0);

	if ( !(bp->b_flags & B_META) || (bp->b_lflags & BL_IOBUF)) {

		KERNEL_DEBUG(0xbbbbc000 | DBG_FUNC_END, bp, 0, 0, 0, 0);
		return (NULL);
	}
#ifdef BUF_MAKE_PRIVATE
	if (bp->b_shadow_ref && bp->b_data_ref == 0 && external_storage == 0)
		panic("buf_create_shadow: %p is in the private state (%d, %d)", bp, bp->b_shadow_ref, bp->b_data_ref);
#endif
	io_bp = alloc_io_buf(bp->b_vp, priv);

	io_bp->b_flags = bp->b_flags & (B_META | B_ZALLOC | B_ASYNC | B_READ | B_FUA);
	io_bp->b_blkno = bp->b_blkno;
	io_bp->b_lblkno = bp->b_lblkno;

	if (iodone) {
	        io_bp->b_transaction = arg;
		io_bp->b_iodone = iodone;
		io_bp->b_flags |= B_CALL;
	}
	if (force_copy == FALSE) {
		io_bp->b_bcount = bp->b_bcount;
		io_bp->b_bufsize = bp->b_bufsize;

		if (external_storage) {
			io_bp->b_datap = external_storage;
#ifdef BUF_MAKE_PRIVATE
			io_bp->b_data_store = NULL;
#endif
		} else {
			io_bp->b_datap = bp->b_datap;
#ifdef BUF_MAKE_PRIVATE
			io_bp->b_data_store = bp;
#endif
		}
		*(buf_t *)(&io_bp->b_orig) = bp;

		lck_mtx_lock_spin(buf_mtxp);

		io_bp->b_lflags |= BL_SHADOW;
		io_bp->b_shadow = bp->b_shadow;
		bp->b_shadow = io_bp;
		bp->b_shadow_ref++;

#ifdef BUF_MAKE_PRIVATE
		if (external_storage)
			io_bp->b_lflags |= BL_EXTERNAL;
		else
			bp->b_data_ref++;
#endif
		lck_mtx_unlock(buf_mtxp);
	} else {
		if (external_storage) {
#ifdef BUF_MAKE_PRIVATE
			io_bp->b_lflags |= BL_EXTERNAL;
#endif
			io_bp->b_bcount = bp->b_bcount;
			io_bp->b_bufsize = bp->b_bufsize;
			io_bp->b_datap = external_storage;
		} else {
			allocbuf(io_bp, bp->b_bcount);

			io_bp->b_lflags |= BL_IOBUF_ALLOC;
		}
		bcopy((caddr_t)bp->b_datap, (caddr_t)io_bp->b_datap, bp->b_bcount);

#ifdef BUF_MAKE_PRIVATE
		io_bp->b_data_store = NULL;
#endif
	}
	KERNEL_DEBUG(0xbbbbc000 | DBG_FUNC_END, bp, bp->b_shadow_ref, 0, io_bp, 0);

	return (io_bp);
}


#ifdef BUF_MAKE_PRIVATE
errno_t
buf_make_private(buf_t bp)
{
	buf_t	ds_bp;
	buf_t	t_bp;
	struct buf my_buf;

	KERNEL_DEBUG(0xbbbbc004 | DBG_FUNC_START, bp, bp->b_shadow_ref, 0, 0, 0);

	if (bp->b_shadow_ref == 0 || bp->b_data_ref == 0 || ISSET(bp->b_lflags, BL_SHADOW)) {

		KERNEL_DEBUG(0xbbbbc004 | DBG_FUNC_END, bp, bp->b_shadow_ref, 0, EINVAL, 0);
		return (EINVAL);
	}
	my_buf.b_flags = B_META;
	my_buf.b_datap = (uintptr_t)NULL;
	allocbuf(&my_buf, bp->b_bcount);

	bcopy((caddr_t)bp->b_datap, (caddr_t)my_buf.b_datap, bp->b_bcount);

	lck_mtx_lock_spin(buf_mtxp);

	for (t_bp = bp->b_shadow; t_bp; t_bp = t_bp->b_shadow) {
		if ( !ISSET(bp->b_lflags, BL_EXTERNAL))
			break;
	}
	ds_bp = t_bp;

	if (ds_bp == NULL && bp->b_data_ref)
		panic("buf_make_private: b_data_ref != 0 && ds_bp == NULL");

	if (ds_bp && (bp->b_data_ref == 0 || bp->b_shadow_ref == 0))
		panic("buf_make_private: ref_count == 0 && ds_bp != NULL");

	if (ds_bp == NULL) {
		lck_mtx_unlock(buf_mtxp);

		buf_free_meta_store(&my_buf);

		KERNEL_DEBUG(0xbbbbc004 | DBG_FUNC_END, bp, bp->b_shadow_ref, 0, EINVAL, 0);
		return (EINVAL);
	}
	for (t_bp = bp->b_shadow; t_bp; t_bp = t_bp->b_shadow) {
		if ( !ISSET(t_bp->b_lflags, BL_EXTERNAL))
			t_bp->b_data_store = ds_bp;
	}
	ds_bp->b_data_ref = bp->b_data_ref;

	bp->b_data_ref = 0;
	bp->b_datap = my_buf.b_datap;

	lck_mtx_unlock(buf_mtxp);

	KERNEL_DEBUG(0xbbbbc004 | DBG_FUNC_END, bp, bp->b_shadow_ref, 0, 0, 0);
	return (0);
}
#endif


void
buf_setfilter(buf_t bp, void (*filter)(buf_t, void *), void *transaction,
			  void (**old_iodone)(buf_t, void *), void **old_transaction)
{
	if (old_iodone)
		*old_iodone = bp->b_iodone;
	if (old_transaction)
		*old_transaction = bp->b_transaction;

	bp->b_transaction = transaction;
	bp->b_iodone = filter;
	if (filter)
	        bp->b_flags |= B_FILTER;
	else
	        bp->b_flags &= ~B_FILTER;
}


daddr64_t
buf_blkno(buf_t bp) {

        return (bp->b_blkno);
}

daddr64_t
buf_lblkno(buf_t bp) {

        return (bp->b_lblkno);
}

void
buf_setblkno(buf_t bp, daddr64_t blkno) {

        bp->b_blkno = blkno;
}

void
buf_setlblkno(buf_t bp, daddr64_t lblkno) {

        bp->b_lblkno = lblkno;
}

dev_t
buf_device(buf_t bp) {
        
        return (bp->b_dev);
}

errno_t
buf_setdevice(buf_t bp, vnode_t vp) {

        if ((vp->v_type != VBLK) && (vp->v_type != VCHR))
	        return EINVAL;
	bp->b_dev = vp->v_rdev;

	return 0;
}


void *
buf_drvdata(buf_t bp) {

        return (bp->b_drvdata);
}

void
buf_setdrvdata(buf_t bp, void *drvdata) {

        bp->b_drvdata = drvdata;
}

void *
buf_fsprivate(buf_t bp) {

        return (bp->b_fsprivate);
}

void
buf_setfsprivate(buf_t bp, void *fsprivate) {

        bp->b_fsprivate = fsprivate;
}

kauth_cred_t
buf_rcred(buf_t bp) {

        return (bp->b_rcred);
}

kauth_cred_t
buf_wcred(buf_t bp) {

        return (bp->b_wcred);
}

void *
buf_upl(buf_t bp) {

        return (bp->b_upl);
}

uint32_t
buf_uploffset(buf_t bp) {

        return ((uint32_t)(bp->b_uploffset));
}

proc_t
buf_proc(buf_t bp) {

        return (bp->b_proc);
}


errno_t
buf_map(buf_t bp, caddr_t *io_addr)
{
        buf_t		real_bp;
        vm_offset_t	vaddr;
        kern_return_t	kret;

        if ( !(bp->b_flags & B_CLUSTER)) {
	        *io_addr = (caddr_t)bp->b_datap;
		return (0);
	}
	real_bp = (buf_t)(bp->b_real_bp);

	if (real_bp && real_bp->b_datap) {
	        /*
		 * b_real_bp is only valid if B_CLUSTER is SET
		 * if it's non-zero, than someone did a cluster_bp call
		 * if the backing physical pages were already mapped
		 * in before the call to cluster_bp (non-zero b_datap),
		 * than we just use that mapping
		 */
	        *io_addr = (caddr_t)real_bp->b_datap;
		return (0);
	}
	kret = ubc_upl_map(bp->b_upl, &vaddr);    /* Map it in */

	if (kret != KERN_SUCCESS) {
	        *io_addr = NULL;

	        return(ENOMEM);
	}
	vaddr += bp->b_uploffset;                                       

	*io_addr = (caddr_t)vaddr;

	return (0);
}

errno_t
buf_unmap(buf_t bp)
{
        buf_t		real_bp;
        kern_return_t	kret;

        if ( !(bp->b_flags & B_CLUSTER))
	        return (0);
	/*
	 * see buf_map for the explanation
	 */
	real_bp = (buf_t)(bp->b_real_bp);

	if (real_bp && real_bp->b_datap)
	        return (0);

	if ((bp->b_lflags & BL_IOBUF) &&
	    ((bp->b_flags & (B_PAGEIO | B_READ)) != (B_PAGEIO | B_READ))) {
	        /*
		 * ignore pageins... the 'right' thing will
		 * happen due to the way we handle speculative
		 * clusters...
		 *
		 * when we commit these pages, we'll hit
		 * it with UPL_COMMIT_INACTIVE which
		 * will clear the reference bit that got
		 * turned on when we touched the mapping
		 */
	        bp->b_flags |= B_AGE;
	}
	kret = ubc_upl_unmap(bp->b_upl);

	if (kret != KERN_SUCCESS)
	        return (EINVAL);
	return (0);
}


void
buf_clear(buf_t bp) {
        caddr_t baddr;
  
        if (buf_map(bp, &baddr) == 0) {
	        bzero(baddr, bp->b_bcount);
		buf_unmap(bp);
	}
	bp->b_resid = 0;
}

/*
 * Read or write a buffer that is not contiguous on disk.
 * buffer is marked done/error at the conclusion
 */
static int
buf_strategy_fragmented(vnode_t devvp, buf_t bp, off_t f_offset, size_t contig_bytes)
{
	vnode_t	vp = buf_vnode(bp);
	buf_t	io_bp;			 /* For reading or writing a single block */
	int	io_direction;
	int	io_resid;
	size_t	io_contig_bytes;
        daddr64_t io_blkno;
	int	error = 0;
	int	bmap_flags;

	/*
	 * save our starting point... the bp was already mapped
	 * in buf_strategy before we got called
	 * no sense doing it again.
	 */
	io_blkno = bp->b_blkno;
	/*
	 * Make sure we redo this mapping for the next I/O
	 * i.e. this can never be a 'permanent' mapping
	 */
	bp->b_blkno = bp->b_lblkno;
	
	/*
	 * Get an io buffer to do the deblocking
	 */
	io_bp = alloc_io_buf(devvp, 0);

	io_bp->b_lblkno = bp->b_lblkno;
	io_bp->b_datap  = bp->b_datap;
	io_resid	= bp->b_bcount;
        io_direction	= bp->b_flags & B_READ;
	io_contig_bytes = contig_bytes;
	
	if (bp->b_flags & B_READ)
	        bmap_flags = VNODE_READ;
	else
	        bmap_flags = VNODE_WRITE;

	for (;;) {
		if (io_blkno == -1)
		        /*
			 * this is unexepected, but we'll allow for it
			 */
		        bzero((caddr_t)io_bp->b_datap, (int)io_contig_bytes);
		else {
		        io_bp->b_bcount	 = io_contig_bytes;
			io_bp->b_bufsize = io_contig_bytes;
			io_bp->b_resid   = io_contig_bytes;
			io_bp->b_blkno   = io_blkno;

			buf_reset(io_bp, io_direction);

			/*
			 * Call the device to do the I/O and wait for it.  Make sure the appropriate party is charged for write
			 */

			if (!ISSET(bp->b_flags, B_READ))
			        OSAddAtomic(1, &devvp->v_numoutput);

			if ((error = VNOP_STRATEGY(io_bp)))
			        break;
			if ((error = (int)buf_biowait(io_bp)))
			        break;
			if (io_bp->b_resid) {
			        io_resid -= (io_contig_bytes - io_bp->b_resid);
				break;
			}
		}
		if ((io_resid -= io_contig_bytes) == 0)
		        break;
		f_offset       += io_contig_bytes;
		io_bp->b_datap += io_contig_bytes;

		/*
		 * Map the current position to a physical block number
		 */
		if ((error = VNOP_BLOCKMAP(vp, f_offset, io_resid, &io_blkno, &io_contig_bytes, NULL, bmap_flags, NULL)))
		        break;
	}
	buf_free(io_bp);
	
	if (error)
	        buf_seterror(bp, error);
	bp->b_resid = io_resid;
	/*
	 * This I/O is now complete
	 */
	buf_biodone(bp);

	return error;
}


/*
 * struct vnop_strategy_args {
 *      struct buf *a_bp;
 * } *ap;
 */
errno_t
buf_strategy(vnode_t devvp, void *ap)
{
        buf_t	bp = ((struct vnop_strategy_args *)ap)->a_bp;
	vnode_t	vp = bp->b_vp;
	int	bmap_flags;
        errno_t error;
#if CONFIG_DTRACE
	int dtrace_io_start_flag = 0;	 /* We only want to trip the io:::start
					  * probe once, with the true phisical
					  * block in place (b_blkno)
					  */

#endif	

	if (vp == NULL || vp->v_type == VCHR || vp->v_type == VBLK)
	        panic("buf_strategy: b_vp == NULL || vtype == VCHR | VBLK\n");
	/*
	 * associate the physical device with
	 * with this buf_t even if we don't
	 * end up issuing the I/O...
	 */
	bp->b_dev = devvp->v_rdev;

	if (bp->b_flags & B_READ)
	        bmap_flags = VNODE_READ;
	else
	        bmap_flags = VNODE_WRITE;

        if ( !(bp->b_flags & B_CLUSTER)) {

	        if ( (bp->b_upl) ) {
		        /*
			 * we have a UPL associated with this bp
			 * go through cluster_bp which knows how
			 * to deal with filesystem block sizes
			 * that aren't equal to the page size
			 */
			DTRACE_IO1(start, buf_t, bp);
		        return (cluster_bp(bp));
		}
		if (bp->b_blkno == bp->b_lblkno) {
		        off_t	f_offset;
			size_t 	contig_bytes;
		  
			if ((error = VNOP_BLKTOOFF(vp, bp->b_lblkno, &f_offset))) {
				DTRACE_IO1(start, buf_t, bp);
			        buf_seterror(bp, error);
				buf_biodone(bp);

			        return (error);
			}
			if ((error = VNOP_BLOCKMAP(vp, f_offset, bp->b_bcount, &bp->b_blkno, &contig_bytes, NULL, bmap_flags, NULL))) {
				DTRACE_IO1(start, buf_t, bp);
			        buf_seterror(bp, error);
				buf_biodone(bp);

			        return (error);
			}
			
			DTRACE_IO1(start, buf_t, bp);
#if CONFIG_DTRACE
			dtrace_io_start_flag = 1;
#endif /* CONFIG_DTRACE */			
			
			if ((bp->b_blkno == -1) || (contig_bytes == 0)) {
				/* Set block number to force biodone later */
				bp->b_blkno = -1;
			        buf_clear(bp);
			}
			else if ((long)contig_bytes < bp->b_bcount) {
			        return (buf_strategy_fragmented(devvp, bp, f_offset, contig_bytes));
			}
		}
		
#if CONFIG_DTRACE
		if (dtrace_io_start_flag == 0) {
			DTRACE_IO1(start, buf_t, bp);
			dtrace_io_start_flag = 1;
		}
#endif /* CONFIG_DTRACE */
		
		if (bp->b_blkno == -1) {
		        buf_biodone(bp);
			return (0);
		}
	}

#if CONFIG_DTRACE
	if (dtrace_io_start_flag == 0)
		DTRACE_IO1(start, buf_t, bp);
#endif /* CONFIG_DTRACE */
	
	/*
	 * we can issue the I/O because...
	 * either B_CLUSTER is set which
	 * means that the I/O is properly set
	 * up to be a multiple of the page size, or
	 * we were able to successfully set up the
	 * phsyical block mapping
	 */
	return (VOCALL(devvp->v_op, VOFFSET(vnop_strategy), ap));
}



buf_t
buf_alloc(vnode_t vp)
{
        return(alloc_io_buf(vp, 0));
}

void
buf_free(buf_t bp) {
        
        free_io_buf(bp);
}


/*
 * iterate buffers for the specified vp. 
 *   if BUF_SCAN_DIRTY is set, do the dirty list
 *   if BUF_SCAN_CLEAN is set, do the clean list
 *   if neither flag is set, default to BUF_SCAN_DIRTY
 *   if BUF_NOTIFY_BUSY is set, call the callout function using a NULL bp for busy pages
 */

struct buf_iterate_info_t {
	int flag;
	struct buflists *listhead;
};

void
buf_iterate(vnode_t vp, int (*callout)(buf_t, void *), int flags, void *arg)
{
	buf_t 	bp;
	int	retval;
	struct	buflists local_iterblkhd;
	int	lock_flags = BAC_NOWAIT | BAC_REMOVE;
	int	notify_busy = flags & BUF_NOTIFY_BUSY;
	struct buf_iterate_info_t list[2];
	int	num_lists, i;

	if (flags & BUF_SKIP_LOCKED)
	        lock_flags |= BAC_SKIP_LOCKED;
	if (flags & BUF_SKIP_NONLOCKED)
	        lock_flags |= BAC_SKIP_NONLOCKED;

	if ( !(flags & (BUF_SCAN_DIRTY | BUF_SCAN_CLEAN)))
	        flags |= BUF_SCAN_DIRTY;

	num_lists = 0;

	if (flags & BUF_SCAN_DIRTY) {
	        list[num_lists].flag = VBI_DIRTY;
		list[num_lists].listhead = &vp->v_dirtyblkhd;
		num_lists++;
	}
	if (flags & BUF_SCAN_CLEAN) {
		list[num_lists].flag = VBI_CLEAN;
		list[num_lists].listhead = &vp->v_cleanblkhd;
		num_lists++;
	}

	for (i = 0; i < num_lists; i++) {
		lck_mtx_lock(buf_mtxp);
	
		if (buf_iterprepare(vp, &local_iterblkhd, list[i].flag))  {
			lck_mtx_unlock(buf_mtxp);
			continue;
		}
		while (!LIST_EMPTY(&local_iterblkhd)) {
			bp = LIST_FIRST(&local_iterblkhd);
			LIST_REMOVE(bp, b_vnbufs);
			LIST_INSERT_HEAD(list[i].listhead, bp, b_vnbufs);

			if (buf_acquire_locked(bp, lock_flags, 0, 0)) {
				if (notify_busy) {
					bp = NULL;
				} else {
					continue;
				}
			}

			lck_mtx_unlock(buf_mtxp);

			retval = callout(bp, arg);

			switch (retval) {
			case BUF_RETURNED:
				if (bp)
					buf_brelse(bp);
				break;
			case BUF_CLAIMED:
				break;
			case BUF_RETURNED_DONE:
				if (bp)
					buf_brelse(bp);
				lck_mtx_lock(buf_mtxp);
				goto out;
			case BUF_CLAIMED_DONE:
				lck_mtx_lock(buf_mtxp);
				goto out;
			}
			lck_mtx_lock(buf_mtxp);
		} /* while list has more nodes */
	  out:
		buf_itercomplete(vp, &local_iterblkhd, list[i].flag);
		lck_mtx_unlock(buf_mtxp);
	} /* for each list */
} /* buf_iterate */


/*
 * Flush out and invalidate all buffers associated with a vnode.
 */
int
buf_invalidateblks(vnode_t vp, int flags, int slpflag, int slptimeo)
{
	buf_t	bp;
	int	aflags;
	int	error = 0;
	int	must_rescan = 1;
	struct	buflists local_iterblkhd;


	if (LIST_EMPTY(&vp->v_cleanblkhd) && LIST_EMPTY(&vp->v_dirtyblkhd))
		return (0);

	lck_mtx_lock(buf_mtxp);

	for (;;) {
		if (must_rescan == 0)
		        /*
			 * the lists may not be empty, but all that's left at this
			 * point are metadata or B_LOCKED buffers which are being
			 * skipped... we know this because we made it through both
			 * the clean and dirty lists without dropping buf_mtxp...
			 * each time we drop buf_mtxp we bump "must_rescan"
			 */
		        break;
		if (LIST_EMPTY(&vp->v_cleanblkhd) && LIST_EMPTY(&vp->v_dirtyblkhd))
		        break;
		must_rescan = 0;
		/*
		 * iterate the clean list
		 */
		if (buf_iterprepare(vp, &local_iterblkhd, VBI_CLEAN)) {
		        goto try_dirty_list;
		}
		while (!LIST_EMPTY(&local_iterblkhd)) {

			bp = LIST_FIRST(&local_iterblkhd);

			LIST_REMOVE(bp, b_vnbufs);
			LIST_INSERT_HEAD(&vp->v_cleanblkhd, bp, b_vnbufs);

			/*
			 * some filesystems distinguish meta data blocks with a negative logical block #
			 */
			if ((flags & BUF_SKIP_META) && (bp->b_lblkno < 0 || ISSET(bp->b_flags, B_META)))
				continue;

			aflags = BAC_REMOVE;

			if ( !(flags & BUF_INVALIDATE_LOCKED) )
				aflags |= BAC_SKIP_LOCKED;

			if ( (error = (int)buf_acquire_locked(bp, aflags, slpflag, slptimeo)) ) {
			        if (error == EDEADLK)
				        /*	
					 * this buffer was marked B_LOCKED... 
					 * we didn't drop buf_mtxp, so we
					 * we don't need to rescan
					 */
				        continue;
			        if (error == EAGAIN) {
				        /*
					 * found a busy buffer... we blocked and
					 * dropped buf_mtxp, so we're going to
					 * need to rescan after this pass is completed
					 */
				        must_rescan++;
				        continue;
				}
				/*
				 * got some kind of 'real' error out of the msleep
				 * in buf_acquire_locked, terminate the scan and return the error
				 */
				buf_itercomplete(vp, &local_iterblkhd, VBI_CLEAN);

				lck_mtx_unlock(buf_mtxp);
				return (error);
			}
			lck_mtx_unlock(buf_mtxp);

			if (bp->b_flags & B_LOCKED)
				KERNEL_DEBUG(0xbbbbc038, bp, 0, 0, 0, 0);

			CLR(bp->b_flags, B_LOCKED);
			SET(bp->b_flags, B_INVAL);
			buf_brelse(bp);

			lck_mtx_lock(buf_mtxp);

			/*
			 * by dropping buf_mtxp, we allow new
			 * buffers to be added to the vnode list(s)
			 * we'll have to rescan at least once more
			 * if the queues aren't empty
			 */
			must_rescan++;
		}
		buf_itercomplete(vp, &local_iterblkhd, VBI_CLEAN);

try_dirty_list:
		/*
		 * Now iterate on dirty blks
		 */
		if (buf_iterprepare(vp, &local_iterblkhd, VBI_DIRTY)) {
			continue;
		}
		while (!LIST_EMPTY(&local_iterblkhd)) {
			bp = LIST_FIRST(&local_iterblkhd);

			LIST_REMOVE(bp, b_vnbufs);
			LIST_INSERT_HEAD(&vp->v_dirtyblkhd, bp, b_vnbufs);

			/*
			 * some filesystems distinguish meta data blocks with a negative logical block #
			 */
			if ((flags & BUF_SKIP_META) && (bp->b_lblkno < 0 || ISSET(bp->b_flags, B_META)))
				continue;

			aflags = BAC_REMOVE;

			if ( !(flags & BUF_INVALIDATE_LOCKED) )
				aflags |= BAC_SKIP_LOCKED;

			if ( (error = (int)buf_acquire_locked(bp, aflags, slpflag, slptimeo)) ) {
			        if (error == EDEADLK)
				        /*	
					 * this buffer was marked B_LOCKED... 
					 * we didn't drop buf_mtxp, so we
					 * we don't need to rescan
					 */
				        continue;
			        if (error == EAGAIN) {
				        /*
					 * found a busy buffer... we blocked and
					 * dropped buf_mtxp, so we're going to
					 * need to rescan after this pass is completed
					 */
				        must_rescan++;
				        continue;
				}
				/*
				 * got some kind of 'real' error out of the msleep
				 * in buf_acquire_locked, terminate the scan and return the error
				 */
				buf_itercomplete(vp, &local_iterblkhd, VBI_DIRTY);

				lck_mtx_unlock(buf_mtxp);
				return (error);
			}
			lck_mtx_unlock(buf_mtxp);

			if (bp->b_flags & B_LOCKED)
				KERNEL_DEBUG(0xbbbbc038, bp, 0, 0, 1, 0);

			CLR(bp->b_flags, B_LOCKED);
			SET(bp->b_flags, B_INVAL);

			if (ISSET(bp->b_flags, B_DELWRI) && (flags & BUF_WRITE_DATA))
				(void) VNOP_BWRITE(bp);
			else
				buf_brelse(bp);

			lck_mtx_lock(buf_mtxp);
			/*
			 * by dropping buf_mtxp, we allow new
			 * buffers to be added to the vnode list(s)
			 * we'll have to rescan at least once more
			 * if the queues aren't empty
			 */
			must_rescan++;
		}
		buf_itercomplete(vp, &local_iterblkhd, VBI_DIRTY);
	}
	lck_mtx_unlock(buf_mtxp);

	return (0);
}

void
buf_flushdirtyblks(vnode_t vp, int wait, int flags, const char *msg) {
	buf_t	bp;
	int	writes_issued = 0;
	errno_t	error;
	int	busy = 0;
	struct	buflists local_iterblkhd;
	int	lock_flags = BAC_NOWAIT | BAC_REMOVE;

	if (flags & BUF_SKIP_LOCKED)
	        lock_flags |= BAC_SKIP_LOCKED;
	if (flags & BUF_SKIP_NONLOCKED)
	        lock_flags |= BAC_SKIP_NONLOCKED;
loop:
	lck_mtx_lock(buf_mtxp);

	if (buf_iterprepare(vp, &local_iterblkhd, VBI_DIRTY) == 0)  {
	        while (!LIST_EMPTY(&local_iterblkhd)) {
			bp = LIST_FIRST(&local_iterblkhd);
			LIST_REMOVE(bp, b_vnbufs);
			LIST_INSERT_HEAD(&vp->v_dirtyblkhd, bp, b_vnbufs);
			
			if ((error = buf_acquire_locked(bp, lock_flags, 0, 0)) == EBUSY)
			        busy++;
			if (error)
			        continue;
			lck_mtx_unlock(buf_mtxp);

			bp->b_flags &= ~B_LOCKED;

			/*
			 * Wait for I/O associated with indirect blocks to complete,
			 * since there is no way to quickly wait for them below.
			 */
			if ((bp->b_vp == vp) || (wait == 0))
			        (void) buf_bawrite(bp);
			else
			        (void) VNOP_BWRITE(bp);
			writes_issued++;

			lck_mtx_lock(buf_mtxp);
		}
		buf_itercomplete(vp, &local_iterblkhd, VBI_DIRTY);
	}
	lck_mtx_unlock(buf_mtxp);
	
	if (wait) {
	        (void)vnode_waitforwrites(vp, 0, 0, 0, msg);

		if (vp->v_dirtyblkhd.lh_first && busy) {
		        /*
			 * we had one or more BUSY buffers on
			 * the dirtyblock list... most likely
			 * these are due to delayed writes that
			 * were moved to the bclean queue but
			 * have not yet been 'written'.
			 * if we issued some writes on the 
			 * previous pass, we try again immediately
			 * if we didn't, we'll sleep for some time
			 * to allow the state to change...
			 */
		        if (writes_issued == 0) {
			        (void)tsleep((caddr_t)&vp->v_numoutput,
					     PRIBIO + 1, "vnode_flushdirtyblks", hz/20);
			}
			writes_issued = 0;
			busy = 0;

			goto loop;
		}
	}
}


/*
 * called with buf_mtxp held...
 * this lock protects the queue manipulation
 */
static int
buf_iterprepare(vnode_t vp, struct buflists *iterheadp, int flags)
{
	struct buflists * listheadp;

	if (flags & VBI_DIRTY)
		listheadp = &vp->v_dirtyblkhd;
	else
		listheadp = &vp->v_cleanblkhd;
		
	while (vp->v_iterblkflags & VBI_ITER) 	{
	        vp->v_iterblkflags |= VBI_ITERWANT;
		msleep(&vp->v_iterblkflags, buf_mtxp, 0, "buf_iterprepare", NULL);	
	}
	if (LIST_EMPTY(listheadp)) {
	        LIST_INIT(iterheadp);
		return(EINVAL);
	}
	vp->v_iterblkflags |= VBI_ITER;

	iterheadp->lh_first = listheadp->lh_first;
	listheadp->lh_first->b_vnbufs.le_prev = &iterheadp->lh_first;	
	LIST_INIT(listheadp);

	return(0);
}

/*
 * called with buf_mtxp held...
 * this lock protects the queue manipulation
 */
static void
buf_itercomplete(vnode_t vp, struct buflists *iterheadp, int flags)
{
	struct buflists * listheadp;
	buf_t bp;

	if (flags & VBI_DIRTY)
		listheadp = &vp->v_dirtyblkhd;
	else
		listheadp = &vp->v_cleanblkhd;

	while (!LIST_EMPTY(iterheadp)) {
		bp = LIST_FIRST(iterheadp);
		LIST_REMOVE(bp, b_vnbufs);
		LIST_INSERT_HEAD(listheadp, bp, b_vnbufs);
	}
	vp->v_iterblkflags &= ~VBI_ITER;

	if  (vp->v_iterblkflags & VBI_ITERWANT) 	{
		vp->v_iterblkflags &= ~VBI_ITERWANT;
		wakeup(&vp->v_iterblkflags);
	}
}


static void
bremfree_locked(buf_t bp)
{
	struct bqueues *dp = NULL;
	int whichq;

	whichq = bp->b_whichq;

	if (whichq == -1) {
		if (bp->b_shadow_ref == 0)
			panic("bremfree_locked: %p not on freelist", bp);
		/*
		 * there are clones pointing to 'bp'...
		 * therefore, it was not put on a freelist
		 * when buf_brelse was last called on 'bp'
		 */
		return;
	}
	/*
	 * We only calculate the head of the freelist when removing
	 * the last element of the list as that is the only time that
	 * it is needed (e.g. to reset the tail pointer).
	 *
	 * NB: This makes an assumption about how tailq's are implemented.
	 */
	if (bp->b_freelist.tqe_next == NULL) {
	        dp = &bufqueues[whichq];

		if (dp->tqh_last != &bp->b_freelist.tqe_next)
			panic("bremfree: lost tail");
	}
	TAILQ_REMOVE(dp, bp, b_freelist);

#if BALANCE_QUEUES
	bufqdec(whichq);
#endif
	if (whichq == BQ_LAUNDRY)
	        blaundrycnt--;

	bp->b_whichq = -1;
	bp->b_timestamp = 0; 
	bp->b_shadow = 0;
}

/*
 * Associate a buffer with a vnode.
 * buf_mtxp must be locked on entry
 */
static void
bgetvp_locked(vnode_t vp, buf_t bp)
{

	if (bp->b_vp != vp)
		panic("bgetvp_locked: not free");

	if (vp->v_type == VBLK || vp->v_type == VCHR)
		bp->b_dev = vp->v_rdev;
	else
		bp->b_dev = NODEV;
	/*
	 * Insert onto list for new vnode.
	 */
	bufinsvn(bp, &vp->v_cleanblkhd);
}

/*
 * Disassociate a buffer from a vnode.
 * buf_mtxp must be locked on entry
 */
static void
brelvp_locked(buf_t bp)
{
	/*
	 * Delete from old vnode list, if on one.
	 */
	if (bp->b_vnbufs.le_next != NOLIST)
		bufremvn(bp);

	bp->b_vp = (vnode_t)NULL;
}

/*
 * Reassign a buffer from one vnode to another.
 * Used to assign file specific control information
 * (indirect blocks) to the vnode to which they belong.
 */
static void
buf_reassign(buf_t bp, vnode_t newvp)
{
	struct buflists *listheadp;

	if (newvp == NULL) {
		printf("buf_reassign: NULL");
		return;
	}
	lck_mtx_lock_spin(buf_mtxp);

	/*
	 * Delete from old vnode list, if on one.
	 */
	if (bp->b_vnbufs.le_next != NOLIST)
		bufremvn(bp);
	/*
	 * If dirty, put on list of dirty buffers;
	 * otherwise insert onto list of clean buffers.
	 */
	if (ISSET(bp->b_flags, B_DELWRI))
		listheadp = &newvp->v_dirtyblkhd;
	else
		listheadp = &newvp->v_cleanblkhd;
	bufinsvn(bp, listheadp);

	lck_mtx_unlock(buf_mtxp);
}

static __inline__ void
bufhdrinit(buf_t bp)
{
	bzero((char *)bp, sizeof *bp);
	bp->b_dev = NODEV;
	bp->b_rcred = NOCRED;
	bp->b_wcred = NOCRED;
	bp->b_vnbufs.le_next = NOLIST;
	bp->b_flags = B_INVAL;

	return;
}

/*
 * Initialize buffers and hash links for buffers.
 */
__private_extern__ void
bufinit(void)
{
	buf_t	bp;
	struct bqueues *dp;
	int	i;

	nbuf_headers = 0;
	/* Initialize the buffer queues ('freelists') and the hash table */
	for (dp = bufqueues; dp < &bufqueues[BQUEUES]; dp++)
		TAILQ_INIT(dp);
	bufhashtbl = hashinit(nbuf_hashelements, M_CACHE, &bufhash);

	buf_busycount = 0;

	/* Initialize the buffer headers */
	for (i = 0; i < max_nbuf_headers; i++) {
		nbuf_headers++;
		bp = &buf_headers[i];
		bufhdrinit(bp);

		BLISTNONE(bp);
		dp = &bufqueues[BQ_EMPTY];
		bp->b_whichq = BQ_EMPTY;
		bp->b_timestamp = buf_timestamp();
		binsheadfree(bp, dp, BQ_EMPTY);
		binshash(bp, &invalhash);
	}
	boot_nbuf_headers = nbuf_headers;

	TAILQ_INIT(&iobufqueue);
	TAILQ_INIT(&delaybufqueue);

	for (; i < nbuf_headers + niobuf_headers; i++) {
		bp = &buf_headers[i];
		bufhdrinit(bp);
		bp->b_whichq = -1;
		binsheadfree(bp, &iobufqueue, -1);
	}

	/*
	 * allocate lock group attribute and group
	 */
	buf_mtx_grp_attr = lck_grp_attr_alloc_init();
	buf_mtx_grp = lck_grp_alloc_init("buffer cache", buf_mtx_grp_attr);
		
	/*
	 * allocate the lock attribute
	 */
	buf_mtx_attr = lck_attr_alloc_init();

	/*
	 * allocate and initialize mutex's for the buffer and iobuffer pools
	 */
	buf_mtxp	= lck_mtx_alloc_init(buf_mtx_grp, buf_mtx_attr);
	iobuffer_mtxp	= lck_mtx_alloc_init(buf_mtx_grp, buf_mtx_attr);

	if (iobuffer_mtxp == NULL)
	        panic("couldn't create iobuffer mutex");

	if (buf_mtxp == NULL)
	        panic("couldn't create buf mutex");

	/*
	 * allocate and initialize cluster specific global locks...
	 */
	cluster_init();

	printf("using %d buffer headers and %d cluster IO buffer headers\n",
		nbuf_headers, niobuf_headers);

	/* Set up zones used by the buffer cache */
	bufzoneinit();

	/* start the bcleanbuf() thread */
	bcleanbuf_thread_init();

	/* Register a callout for relieving vm pressure */
	if (vm_set_buffer_cleanup_callout(buffer_cache_gc) != KERN_SUCCESS) {
		panic("Couldn't register buffer cache callout for vm pressure!\n");
	}

#if BALANCE_QUEUES
	{
	static void bufq_balance_thread_init(void) __attribute__((section("__TEXT, initcode")));
	/* create a thread to do dynamic buffer queue balancing */
	bufq_balance_thread_init();
	}
#endif /* notyet */
}



/*
 * Zones for the meta data buffers
 */

#define MINMETA 512
#define MAXMETA 8192

struct meta_zone_entry {
	zone_t mz_zone;
	vm_size_t mz_size;
	vm_size_t mz_max;
	const char *mz_name;
};

struct meta_zone_entry meta_zones[] = {
	{NULL, (MINMETA * 1), 128 * (MINMETA * 1), "buf.512" },
	{NULL, (MINMETA * 2),  64 * (MINMETA * 2), "buf.1024" },
	{NULL, (MINMETA * 4),  16 * (MINMETA * 4), "buf.2048" },
	{NULL, (MINMETA * 8), 512 * (MINMETA * 8), "buf.4096" },
	{NULL, (MINMETA * 16), 512 * (MINMETA * 16), "buf.8192" },
	{NULL, 0, 0, "" } /* End */
};

/*
 * Initialize the meta data zones
 */
static void
bufzoneinit(void)
{
	int i;

	for (i = 0; meta_zones[i].mz_size != 0; i++) {
		meta_zones[i].mz_zone = 
				zinit(meta_zones[i].mz_size,
					meta_zones[i].mz_max,
					PAGE_SIZE,
					meta_zones[i].mz_name);
		zone_change(meta_zones[i].mz_zone, Z_CALLERACCT, FALSE);
	}
	buf_hdr_zone = zinit(sizeof(struct buf), 32, PAGE_SIZE, "buf headers");
	zone_change(buf_hdr_zone, Z_CALLERACCT, FALSE);
}

static __inline__ zone_t
getbufzone(size_t size)
{
	int i;

	if ((size % 512) || (size < MINMETA) || (size > MAXMETA))
		panic("getbufzone: incorect size = %lu", size);

	for (i = 0; meta_zones[i].mz_size != 0; i++) {
		if (meta_zones[i].mz_size >= size)
			break;
	}

	return (meta_zones[i].mz_zone);
}



static struct buf *
bio_doread(vnode_t vp, daddr64_t blkno, int size, kauth_cred_t cred, int async, int queuetype)
{
	buf_t	bp;

	bp = buf_getblk(vp, blkno, size, 0, 0, queuetype);

	/*
	 * If buffer does not have data valid, start a read.
	 * Note that if buffer is B_INVAL, buf_getblk() won't return it.
	 * Therefore, it's valid if it's I/O has completed or been delayed.
	 */
	if (!ISSET(bp->b_flags, (B_DONE | B_DELWRI))) {
		struct proc *p;

		p = current_proc();

		/* Start I/O for the buffer (keeping credentials). */
		SET(bp->b_flags, B_READ | async);
		if (IS_VALID_CRED(cred) && !IS_VALID_CRED(bp->b_rcred)) {
			kauth_cred_ref(cred);
			bp->b_rcred = cred;
		}

		VNOP_STRATEGY(bp);

		trace(TR_BREADMISS, pack(vp, size), blkno);

		/* Pay for the read. */
		if (p && p->p_stats) 
			OSIncrementAtomicLong(&p->p_stats->p_ru.ru_inblock);		/* XXX */

		if (async) {
		        /*
			 * since we asked for an ASYNC I/O
			 * the biodone will do the brelse
			 * we don't want to pass back a bp
			 * that we don't 'own'
			 */
		        bp = NULL;
		}
	} else if (async) {
		buf_brelse(bp);
		bp = NULL;
	}

	trace(TR_BREADHIT, pack(vp, size), blkno);

	return (bp);
}

/*
 * Perform the reads for buf_breadn() and buf_meta_breadn(). 
 * Trivial modification to the breada algorithm presented in Bach (p.55). 
 */
static errno_t
do_breadn_for_type(vnode_t vp, daddr64_t blkno, int size, daddr64_t *rablks, int *rasizes, 
		   int nrablks, kauth_cred_t cred, buf_t *bpp, int queuetype)
{
	buf_t	bp;
	int	i;

	bp = *bpp = bio_doread(vp, blkno, size, cred, 0, queuetype);

	/*
	 * For each of the read-ahead blocks, start a read, if necessary.
	 */
	for (i = 0; i < nrablks; i++) {
		/* If it's in the cache, just go on to next one. */
		if (incore(vp, rablks[i]))
			continue;

		/* Get a buffer for the read-ahead block */
		(void) bio_doread(vp, rablks[i], rasizes[i], cred, B_ASYNC, queuetype);
	}

	/* Otherwise, we had to start a read for it; wait until it's valid. */
	return (buf_biowait(bp));
}


/*
 * Read a disk block.
 * This algorithm described in Bach (p.54).
 */
errno_t
buf_bread(vnode_t vp, daddr64_t blkno, int size, kauth_cred_t cred, buf_t *bpp)
{
	buf_t	bp;

	/* Get buffer for block. */
	bp = *bpp = bio_doread(vp, blkno, size, cred, 0, BLK_READ);

	/* Wait for the read to complete, and return result. */
	return (buf_biowait(bp));
}

/*
 * Read a disk block. [bread() for meta-data]
 * This algorithm described in Bach (p.54).
 */
errno_t
buf_meta_bread(vnode_t vp, daddr64_t blkno, int size, kauth_cred_t cred, buf_t *bpp)
{
	buf_t	bp;

	/* Get buffer for block. */
	bp = *bpp = bio_doread(vp, blkno, size, cred, 0, BLK_META);

	/* Wait for the read to complete, and return result. */
	return (buf_biowait(bp));
}

/*
 * Read-ahead multiple disk blocks. The first is sync, the rest async.
 */
errno_t
buf_breadn(vnode_t vp, daddr64_t blkno, int size, daddr64_t *rablks, int *rasizes, int nrablks, kauth_cred_t cred, buf_t *bpp)
{
	return (do_breadn_for_type(vp, blkno, size, rablks, rasizes, nrablks, cred, bpp, BLK_READ));
}

/*
 * Read-ahead multiple disk blocks. The first is sync, the rest async.
 * [buf_breadn() for meta-data]
 */
errno_t
buf_meta_breadn(vnode_t vp, daddr64_t blkno, int size, daddr64_t *rablks, int *rasizes, int nrablks, kauth_cred_t cred, buf_t *bpp)
{
	return (do_breadn_for_type(vp, blkno, size, rablks, rasizes, nrablks, cred, bpp, BLK_META));
}

/*
 * Block write.  Described in Bach (p.56)
 */
errno_t
buf_bwrite(buf_t bp)
{
	int	sync, wasdelayed;
	errno_t	rv;
	proc_t	p = current_proc();
	vnode_t	vp = bp->b_vp;

	if (bp->b_datap == 0) {
	        if (brecover_data(bp) == 0)
		        return (0);
	}
	/* Remember buffer type, to switch on it later. */
	sync = !ISSET(bp->b_flags, B_ASYNC);
	wasdelayed = ISSET(bp->b_flags, B_DELWRI);
	CLR(bp->b_flags, (B_READ | B_DONE | B_ERROR | B_DELWRI));

	if (wasdelayed)
		OSAddAtomicLong(-1, &nbdwrite);

	if (!sync) {
		/*
		 * If not synchronous, pay for the I/O operation and make
		 * sure the buf is on the correct vnode queue.  We have
		 * to do this now, because if we don't, the vnode may not
		 * be properly notified that its I/O has completed.
		 */
		if (wasdelayed)
			buf_reassign(bp, vp);
		else
		if (p && p->p_stats) 
			OSIncrementAtomicLong(&p->p_stats->p_ru.ru_oublock);	/* XXX */
	}
	trace(TR_BUFWRITE, pack(vp, bp->b_bcount), bp->b_lblkno);

	/* Initiate disk write.  Make sure the appropriate party is charged. */

        OSAddAtomic(1, &vp->v_numoutput);
	
	VNOP_STRATEGY(bp);

	if (sync) {
		/*
		 * If I/O was synchronous, wait for it to complete.
		 */
		rv = buf_biowait(bp);

		/*
		 * Pay for the I/O operation, if it's not been paid for, and
		 * make sure it's on the correct vnode queue. (async operatings
		 * were payed for above.)
		 */
		if (wasdelayed)
			buf_reassign(bp, vp);
		else
		if (p && p->p_stats) 
			OSIncrementAtomicLong(&p->p_stats->p_ru.ru_oublock);	/* XXX */

		/* Release the buffer. */
		// XXXdbg - only if the unused bit is set
		if (!ISSET(bp->b_flags, B_NORELSE)) {
		    buf_brelse(bp);
		} else {
		    CLR(bp->b_flags, B_NORELSE);
		}

		return (rv);
	} else {
		return (0);
	}
}

int
vn_bwrite(struct vnop_bwrite_args *ap)
{
	return (buf_bwrite(ap->a_bp));
}

/*
 * Delayed write.
 *
 * The buffer is marked dirty, but is not queued for I/O.
 * This routine should be used when the buffer is expected
 * to be modified again soon, typically a small write that
 * partially fills a buffer.
 *
 * NB: magnetic tapes cannot be delayed; they must be
 * written in the order that the writes are requested.
 *
 * Described in Leffler, et al. (pp. 208-213).
 *
 * Note: With the ability to allocate additional buffer
 * headers, we can get in to the situation where "too" many 
 * buf_bdwrite()s can create situation where the kernel can create
 * buffers faster than the disks can service. Doing a buf_bawrite() in
 * cases where we have "too many" outstanding buf_bdwrite()s avoids that.
 */
__private_extern__ int
bdwrite_internal(buf_t bp, int return_error)
{
	proc_t	p  = current_proc();
	vnode_t	vp = bp->b_vp;

	/*
	 * If the block hasn't been seen before:
	 *	(1) Mark it as having been seen,
	 *	(2) Charge for the write.
	 *	(3) Make sure it's on its vnode's correct block list,
	 */
	if (!ISSET(bp->b_flags, B_DELWRI)) {
		SET(bp->b_flags, B_DELWRI);
		if (p && p->p_stats) 
			OSIncrementAtomicLong(&p->p_stats->p_ru.ru_oublock);	/* XXX */
		OSAddAtomicLong(1, &nbdwrite);
		buf_reassign(bp, vp);
	}

	/*
	 * if we're not LOCKED, but the total number of delayed writes
	 * has climbed above 75% of the total buffers in the system
	 * return an error if the caller has indicated that it can 
	 * handle one in this case, otherwise schedule the I/O now
	 * this is done to prevent us from allocating tons of extra
	 * buffers when dealing with virtual disks (i.e. DiskImages),
	 * because additional buffers are dynamically allocated to prevent
	 * deadlocks from occurring
	 *
	 * however, can't do a buf_bawrite() if the LOCKED bit is set because the
	 * buffer is part of a transaction and can't go to disk until
	 * the LOCKED bit is cleared.
	 */
	if (!ISSET(bp->b_flags, B_LOCKED) && nbdwrite > ((nbuf_headers/4)*3)) {
		if (return_error)
			return (EAGAIN);
		/*
		 * If the vnode has "too many" write operations in progress
		 * wait for them to finish the IO
		 */
		(void)vnode_waitforwrites(vp, VNODE_ASYNC_THROTTLE, 0, 0, "buf_bdwrite");

		return (buf_bawrite(bp));
	}
	 
	/* Otherwise, the "write" is done, so mark and release the buffer. */
	SET(bp->b_flags, B_DONE);
	buf_brelse(bp);
	return (0);
}

errno_t
buf_bdwrite(buf_t bp)
{
	return (bdwrite_internal(bp, 0));
}
 

/*
 * Asynchronous block write; just an asynchronous buf_bwrite().
 *
 * Note: With the abilitty to allocate additional buffer
 * headers, we can get in to the situation where "too" many 
 * buf_bawrite()s can create situation where the kernel can create
 * buffers faster than the disks can service.
 * We limit the number of "in flight" writes a vnode can have to
 * avoid this.
 */
static int
bawrite_internal(buf_t bp, int throttle)
{
	vnode_t	vp = bp->b_vp;

	if (vp) {
	        if (throttle)
		        /*
			 * If the vnode has "too many" write operations in progress
			 * wait for them to finish the IO
			 */
		        (void)vnode_waitforwrites(vp, VNODE_ASYNC_THROTTLE, 0, 0, (const char *)"buf_bawrite");
		else if (vp->v_numoutput >= VNODE_ASYNC_THROTTLE)
		        /*
			 * return to the caller and 
			 * let him decide what to do
			 */
		        return (EWOULDBLOCK);
	}
	SET(bp->b_flags, B_ASYNC);

	return (VNOP_BWRITE(bp));
}

errno_t
buf_bawrite(buf_t bp)
{
	return (bawrite_internal(bp, 1));
}



static void
buf_free_meta_store(buf_t bp)
{
	if (bp->b_bufsize) {
		if (ISSET(bp->b_flags, B_ZALLOC)) {
			zone_t z;

			z = getbufzone(bp->b_bufsize);
			zfree(z, (void *)bp->b_datap);
		} else
			kmem_free(kernel_map, bp->b_datap, bp->b_bufsize); 

		bp->b_datap = (uintptr_t)NULL;
		bp->b_bufsize = 0;
	}
}


static buf_t
buf_brelse_shadow(buf_t bp)
{
	buf_t	bp_head;
	buf_t	bp_temp;
	buf_t	bp_return = NULL;
#ifdef BUF_MAKE_PRIVATE
	buf_t	bp_data;
	int	data_ref = 0;
#endif
	lck_mtx_lock_spin(buf_mtxp);

	bp_head = (buf_t)bp->b_orig;

	if (bp_head->b_whichq != -1)
		panic("buf_brelse_shadow: bp_head on freelist %d\n", bp_head->b_whichq);

#ifdef BUF_MAKE_PRIVATE
	if (bp_data = bp->b_data_store) {
		bp_data->b_data_ref--;
		/*
		 * snapshot the ref count so that we can check it 
		 * outside of the lock... we only want the guy going
		 * from 1 -> 0 to try and release the storage
		 */
		data_ref = bp_data->b_data_ref;
	}
#endif
	KERNEL_DEBUG(0xbbbbc008 | DBG_FUNC_START, bp, bp_head, bp_head->b_shadow_ref, 0, 0);

	bp_head->b_shadow_ref--;

	for (bp_temp = bp_head; bp_temp && bp != bp_temp->b_shadow; bp_temp = bp_temp->b_shadow);

	if (bp_temp == NULL)
		panic("buf_brelse_shadow: bp not on list %p", bp_head);

	bp_temp->b_shadow = bp_temp->b_shadow->b_shadow;

#ifdef BUF_MAKE_PRIVATE
	/*
	 * we're about to free the current 'owner' of the data buffer and
	 * there is at least one other shadow buf_t still pointing at it
	 * so transfer it to the first shadow buf left in the chain
	 */
	if (bp == bp_data && data_ref) {
		if ((bp_data = bp_head->b_shadow) == NULL)
			panic("buf_brelse_shadow: data_ref mismatch bp(%p)", bp);

		for (bp_temp = bp_data; bp_temp; bp_temp = bp_temp->b_shadow)
			bp_temp->b_data_store = bp_data;
		bp_data->b_data_ref = data_ref;
	}
#endif
	if (bp_head->b_shadow_ref == 0 && bp_head->b_shadow)
		panic("buf_relse_shadow: b_shadow != NULL && b_shadow_ref == 0  bp(%p)", bp); 
	if (bp_head->b_shadow_ref && bp_head->b_shadow == 0)
		panic("buf_relse_shadow: b_shadow == NULL && b_shadow_ref != 0  bp(%p)", bp); 

	if (bp_head->b_shadow_ref == 0) {
		if (!ISSET(bp_head->b_lflags, BL_BUSY)) {

			CLR(bp_head->b_flags, B_AGE);
			bp_head->b_timestamp = buf_timestamp();

			if (ISSET(bp_head->b_flags, B_LOCKED)) {
				bp_head->b_whichq = BQ_LOCKED;
				binstailfree(bp_head, &bufqueues[BQ_LOCKED], BQ_LOCKED);
			} else {
				bp_head->b_whichq = BQ_META;
				binstailfree(bp_head, &bufqueues[BQ_META], BQ_META);
			}
		} else if (ISSET(bp_head->b_lflags, BL_WAITSHADOW)) {
			CLR(bp_head->b_lflags, BL_WAITSHADOW);

			bp_return = bp_head;
		}
	}
	lck_mtx_unlock(buf_mtxp);
#ifdef BUF_MAKE_PRIVATE	
	if (bp == bp_data && data_ref == 0)
		buf_free_meta_store(bp);

	bp->b_data_store = NULL;
#endif
	KERNEL_DEBUG(0xbbbbc008 | DBG_FUNC_END, bp, 0, 0, 0, 0);

	return (bp_return);
}


/*
 * Release a buffer on to the free lists.
 * Described in Bach (p. 46).
 */
void
buf_brelse(buf_t bp)
{
	struct bqueues *bufq;
	long	whichq;
	upl_t	upl;
	int need_wakeup = 0;
	int need_bp_wakeup = 0;


	if (bp->b_whichq != -1 || !(bp->b_lflags & BL_BUSY))
	        panic("buf_brelse: bad buffer = %p\n", bp);

#ifdef JOE_DEBUG
	(void) OSBacktrace(&bp->b_stackbrelse[0], 6);

	bp->b_lastbrelse = current_thread();
	bp->b_tag = 0;
#endif
	if (bp->b_lflags & BL_IOBUF) {
		buf_t	shadow_master_bp = NULL;

		if (ISSET(bp->b_lflags, BL_SHADOW))
			shadow_master_bp = buf_brelse_shadow(bp);
		else if (ISSET(bp->b_lflags, BL_IOBUF_ALLOC))
			 buf_free_meta_store(bp);
	        free_io_buf(bp);

		if (shadow_master_bp) {
			bp = shadow_master_bp;
			goto finish_shadow_master;
		}
		return;
	}

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 388)) | DBG_FUNC_START,
		     bp->b_lblkno * PAGE_SIZE, bp, bp->b_datap,
		     bp->b_flags, 0);

	trace(TR_BRELSE, pack(bp->b_vp, bp->b_bufsize), bp->b_lblkno);

	/*
	 * if we're invalidating a buffer that has the B_FILTER bit
	 * set then call the b_iodone function so it gets cleaned
	 * up properly.
	 *
	 * the HFS journal code depends on this
	 */
	if (ISSET(bp->b_flags, B_META) && ISSET(bp->b_flags, B_INVAL)) {
		if (ISSET(bp->b_flags, B_FILTER)) {	/* if necessary, call out */
			void	(*iodone_func)(struct buf *, void *) = bp->b_iodone;
			void 	*arg = bp->b_transaction;

			CLR(bp->b_flags, B_FILTER);	/* but note callout done */
			bp->b_iodone = NULL;
			bp->b_transaction = NULL;

			if (iodone_func == NULL) {
				panic("brelse: bp @ %p has NULL b_iodone!\n", bp);
			}
			(*iodone_func)(bp, arg);
		}
	}
	/*
	 * I/O is done. Cleanup the UPL state
	 */
	upl = bp->b_upl;

	if ( !ISSET(bp->b_flags, B_META) && UBCINFOEXISTS(bp->b_vp) && bp->b_bufsize) {
		kern_return_t kret;
		int           upl_flags;

		if (upl == NULL) {
		        if ( !ISSET(bp->b_flags, B_INVAL)) {
				kret = ubc_create_upl(bp->b_vp, 
						      ubc_blktooff(bp->b_vp, bp->b_lblkno),
						      bp->b_bufsize, 
						      &upl,
						      NULL,
						      UPL_PRECIOUS);

				if (kret != KERN_SUCCESS)
				        panic("brelse: Failed to create UPL");
#if  UPL_DEBUG
				upl_ubc_alias_set(upl, (uintptr_t) bp, (uintptr_t) 5);
#endif /* UPL_DEBUG */
			}
		} else {
			if (bp->b_datap) {
			        kret = ubc_upl_unmap(upl);

				if (kret != KERN_SUCCESS)
				        panic("ubc_upl_unmap failed");
				bp->b_datap = (uintptr_t)NULL;
			}
		}
		if (upl) {
			if (bp->b_flags & (B_ERROR | B_INVAL)) {
			        if (bp->b_flags & (B_READ | B_INVAL))
				        upl_flags = UPL_ABORT_DUMP_PAGES;
				else
				        upl_flags = 0;

				ubc_upl_abort(upl, upl_flags);
			} else {
			        if (ISSET(bp->b_flags, B_DELWRI | B_WASDIRTY))
				        upl_flags = UPL_COMMIT_SET_DIRTY ;
				else
				        upl_flags = UPL_COMMIT_CLEAR_DIRTY ;

				ubc_upl_commit_range(upl, 0, bp->b_bufsize, upl_flags |
						     UPL_COMMIT_INACTIVATE | UPL_COMMIT_FREE_ON_EMPTY);
			}
			bp->b_upl = NULL;
		}
	} else {
		if ( (upl) )
			panic("brelse: UPL set for non VREG; vp=%p", bp->b_vp);
	}	

	/*
	 * If it's locked, don't report an error; try again later.
	 */
	if (ISSET(bp->b_flags, (B_LOCKED|B_ERROR)) == (B_LOCKED|B_ERROR))
		CLR(bp->b_flags, B_ERROR);
	/*
	 * If it's not cacheable, or an error, mark it invalid.
	 */
	if (ISSET(bp->b_flags, (B_NOCACHE|B_ERROR)))
		SET(bp->b_flags, B_INVAL);
	
	if ((bp->b_bufsize <= 0) || 
			ISSET(bp->b_flags, B_INVAL) || 
			(ISSET(bp->b_lflags, BL_WANTDEALLOC) && !ISSET(bp->b_flags, B_DELWRI))) {

		boolean_t	delayed_buf_free_meta_store = FALSE;

		/*
		 * If it's invalid or empty, dissociate it from its vnode,
		 * release its storage if B_META, and
		 * clean it up a bit and put it on the EMPTY queue
		 */
		if (ISSET(bp->b_flags, B_DELWRI))
			OSAddAtomicLong(-1, &nbdwrite);

		if (ISSET(bp->b_flags, B_META)) {
			if (bp->b_shadow_ref)
				delayed_buf_free_meta_store = TRUE;
			else
				buf_free_meta_store(bp);
		}
		/*
		 * nuke any credentials we were holding
		 */
		buf_release_credentials(bp);

		lck_mtx_lock_spin(buf_mtxp);

		if (bp->b_shadow_ref) {
			SET(bp->b_lflags, BL_WAITSHADOW);
			
			lck_mtx_unlock(buf_mtxp);
			
			return;
		}
		if (delayed_buf_free_meta_store == TRUE) {

			lck_mtx_unlock(buf_mtxp);
finish_shadow_master:
			buf_free_meta_store(bp);

			lck_mtx_lock_spin(buf_mtxp);
		}
		CLR(bp->b_flags, (B_META | B_ZALLOC | B_DELWRI | B_LOCKED | B_AGE | B_ASYNC | B_NOCACHE | B_FUA));

		if (bp->b_vp)
			brelvp_locked(bp);

		bremhash(bp);
		BLISTNONE(bp);
		binshash(bp, &invalhash);

		bp->b_whichq = BQ_EMPTY;
		binsheadfree(bp, &bufqueues[BQ_EMPTY], BQ_EMPTY);
	} else {

		/*
		 * It has valid data.  Put it on the end of the appropriate
		 * queue, so that it'll stick around for as long as possible.
		 */
		if (ISSET(bp->b_flags, B_LOCKED))
			whichq = BQ_LOCKED;		/* locked in core */
		else if (ISSET(bp->b_flags, B_META))
			whichq = BQ_META;		/* meta-data */
		else if (ISSET(bp->b_flags, B_AGE))
			whichq = BQ_AGE;		/* stale but valid data */
		else
			whichq = BQ_LRU;		/* valid data */
		bufq = &bufqueues[whichq];

		bp->b_timestamp = buf_timestamp();

		lck_mtx_lock_spin(buf_mtxp);
		
		/*
		 * the buf_brelse_shadow routine doesn't take 'ownership'
		 * of the parent buf_t... it updates state that is protected by
		 * the buf_mtxp, and checks for BL_BUSY to determine whether to
		 * put the buf_t back on a free list.  b_shadow_ref is protected
		 * by the lock, and since we have not yet cleared B_BUSY, we need
		 * to check it while holding the lock to insure that one of us
		 * puts this buf_t back on a free list when it is safe to do so
		 */
		if (bp->b_shadow_ref == 0) {
			CLR(bp->b_flags, (B_AGE | B_ASYNC | B_NOCACHE));
			bp->b_whichq = whichq;
			binstailfree(bp, bufq, whichq);
		} else {
			/*
			 * there are still cloned buf_t's pointing
			 * at this guy... need to keep it off the
			 * freelists until a buf_brelse is done on 
			 * the last clone
			 */
			CLR(bp->b_flags, (B_ASYNC | B_NOCACHE));
		}
	}
	if (needbuffer) {
	        /*
		 * needbuffer is a global
		 * we're currently using buf_mtxp to protect it
		 * delay doing the actual wakeup until after
		 * we drop buf_mtxp
		 */
		needbuffer = 0;
		need_wakeup = 1;
	}
	if (ISSET(bp->b_lflags, BL_WANTED)) {
	        /*	
		 * delay the actual wakeup until after we
		 * clear BL_BUSY and we've dropped buf_mtxp
		 */
		need_bp_wakeup = 1;
	}
	/*
	 * Unlock the buffer.
	 */
	CLR(bp->b_lflags, (BL_BUSY | BL_WANTED));
	buf_busycount--;

	lck_mtx_unlock(buf_mtxp);

	if (need_wakeup) {
	        /*
		 * Wake up any processes waiting for any buffer to become free.
		 */
	        wakeup(&needbuffer);
	}
	if (need_bp_wakeup) {
	        /*
		 * Wake up any proceeses waiting for _this_ buffer to become free.
		 */
	        wakeup(bp);
	}
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 388)) | DBG_FUNC_END,
		     bp, bp->b_datap, bp->b_flags, 0, 0);
}

/*
 * Determine if a block is in the cache.
 * Just look on what would be its hash chain.  If it's there, return
 * a pointer to it, unless it's marked invalid.  If it's marked invalid,
 * we normally don't return the buffer, unless the caller explicitly
 * wants us to.
 */
static boolean_t
incore(vnode_t vp, daddr64_t blkno)
{
        boolean_t retval;
	struct	bufhashhdr *dp;

	dp = BUFHASH(vp, blkno);

	lck_mtx_lock_spin(buf_mtxp);

	if (incore_locked(vp, blkno, dp))
	        retval = TRUE;
	else
	        retval = FALSE;
	lck_mtx_unlock(buf_mtxp);

	return (retval);
}


static buf_t
incore_locked(vnode_t vp, daddr64_t blkno, struct bufhashhdr *dp)
{
	struct buf *bp;

	/* Search hash chain */
	for (bp = dp->lh_first; bp != NULL; bp = bp->b_hash.le_next) {
		if (bp->b_lblkno == blkno && bp->b_vp == vp &&
		    !ISSET(bp->b_flags, B_INVAL)) {
			return (bp);
		}
	}
	return (NULL);
}


/* XXX FIXME -- Update the comment to reflect the UBC changes (please) -- */
/*
 * Get a block of requested size that is associated with
 * a given vnode and block offset. If it is found in the
 * block cache, mark it as having been found, make it busy
 * and return it. Otherwise, return an empty block of the
 * correct size. It is up to the caller to insure that the
 * cached blocks be of the correct size.
 */
buf_t
buf_getblk(vnode_t vp, daddr64_t blkno, int size, int slpflag, int slptimeo, int operation)
{
	buf_t bp;
	int   err;
	upl_t upl;
	upl_page_info_t *pl;
	kern_return_t kret;
	int ret_only_valid;
	struct timespec ts;
	int upl_flags;
	struct	bufhashhdr *dp;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 386)) | DBG_FUNC_START,
		     (uintptr_t)(blkno * PAGE_SIZE), size, operation, 0, 0);

	ret_only_valid = operation & BLK_ONLYVALID;
	operation &= ~BLK_ONLYVALID;
	dp = BUFHASH(vp, blkno);
start:
	lck_mtx_lock_spin(buf_mtxp);

	if ((bp = incore_locked(vp, blkno, dp))) {
		/*
		 * Found in the Buffer Cache
		 */
		if (ISSET(bp->b_lflags, BL_BUSY)) {
			/*
			 * but is busy
			 */
			switch (operation) {
			case BLK_READ:
			case BLK_WRITE:
			case BLK_META:
				SET(bp->b_lflags, BL_WANTED);
				bufstats.bufs_busyincore++;

				/*
				 * don't retake the mutex after being awakened...
				 * the time out is in msecs 
				 */
				ts.tv_sec = (slptimeo/1000);
				ts.tv_nsec = (slptimeo % 1000) * 10  * NSEC_PER_USEC * 1000;

				KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 396)) | DBG_FUNC_NONE,
					     (uintptr_t)blkno, size, operation, 0, 0);

				err = msleep(bp, buf_mtxp, slpflag | PDROP | (PRIBIO + 1), "buf_getblk", &ts);

				/*
				 * Callers who call with PCATCH or timeout are
				 * willing to deal with the NULL pointer
				 */
				if (err && ((slpflag & PCATCH) || ((err == EWOULDBLOCK) && slptimeo)))
					return (NULL);
				goto start;
				/*NOTREACHED*/
				break;

			default:
			        /*
				 * unknown operation requested
				 */
				panic("getblk: paging or unknown operation for incore busy buffer - %x\n", operation);
				/*NOTREACHED*/
				break;
			}		
		} else {
			/*
			 * buffer in core and not busy
			 */
			SET(bp->b_lflags, BL_BUSY);
			SET(bp->b_flags, B_CACHE);
			buf_busycount++;

			bremfree_locked(bp);
			bufstats.bufs_incore++;
			
			lck_mtx_unlock(buf_mtxp);
#ifdef JOE_DEBUG
			bp->b_owner = current_thread();
			bp->b_tag   = 1;
#endif
			if ( (bp->b_upl) )
			        panic("buffer has UPL, but not marked BUSY: %p", bp);

			if ( !ret_only_valid && bp->b_bufsize != size)
			        allocbuf(bp, size);

			upl_flags = 0;
			switch (operation) {
			case BLK_WRITE:
				/*
				 * "write" operation:  let the UPL subsystem
				 * know that we intend to modify the buffer
				 * cache pages we're gathering.
				 */
				upl_flags |= UPL_WILL_MODIFY;
			case BLK_READ:
				upl_flags |= UPL_PRECIOUS;
			        if (UBCINFOEXISTS(bp->b_vp) && bp->b_bufsize) {
					kret = ubc_create_upl(vp,
							      ubc_blktooff(vp, bp->b_lblkno), 
							      bp->b_bufsize, 
							      &upl, 
							      &pl,
							      upl_flags);
					if (kret != KERN_SUCCESS)
					        panic("Failed to create UPL");

					bp->b_upl = upl;

					if (upl_valid_page(pl, 0)) {
					        if (upl_dirty_page(pl, 0))
						        SET(bp->b_flags, B_WASDIRTY);
						else
						        CLR(bp->b_flags, B_WASDIRTY);
					} else 
					        CLR(bp->b_flags, (B_DONE | B_CACHE | B_WASDIRTY | B_DELWRI));

					kret = ubc_upl_map(upl, (vm_offset_t*)&(bp->b_datap));

					if (kret != KERN_SUCCESS)
					        panic("getblk: ubc_upl_map() failed with (%d)", kret);
				}
				break;

			case BLK_META:
				/*
				 * VM is not involved in IO for the meta data
				 * buffer already has valid data 
				 */
				break;

			default:
				panic("getblk: paging or unknown operation for incore buffer- %d\n", operation);
				/*NOTREACHED*/
				break;
			}
		}
	} else { /* not incore() */
		int queue = BQ_EMPTY; /* Start with no preference */
		
		if (ret_only_valid) {
			lck_mtx_unlock(buf_mtxp);
			return (NULL);
		}
		if ((vnode_isreg(vp) == 0) || (UBCINFOEXISTS(vp) == 0) /*|| (vnode_issystem(vp) == 1)*/)
			operation = BLK_META;

		if ((bp = getnewbuf(slpflag, slptimeo, &queue)) == NULL)
			goto start;

		/*
		 * getnewbuf may block for a number of different reasons...
		 * if it does, it's then possible for someone else to
		 * create a buffer for the same block and insert it into
		 * the hash... if we see it incore at this point we dump
		 * the buffer we were working on and start over
		 */
		if (incore_locked(vp, blkno, dp)) {
			SET(bp->b_flags, B_INVAL);
			binshash(bp, &invalhash);

			lck_mtx_unlock(buf_mtxp);

			buf_brelse(bp);
			goto start;
		}
		/*
		 * NOTE: YOU CAN NOT BLOCK UNTIL binshash() HAS BEEN
		 *       CALLED!  BE CAREFUL.
		 */

		/*
		 * mark the buffer as B_META if indicated
		 * so that when buffer is released it will goto META queue
		 */
		if (operation == BLK_META)
		        SET(bp->b_flags, B_META);

		bp->b_blkno = bp->b_lblkno = blkno;
		bp->b_vp = vp;

		/*
		 * Insert in the hash so that incore() can find it 
		 */
		binshash(bp, BUFHASH(vp, blkno)); 

		bgetvp_locked(vp, bp);

		lck_mtx_unlock(buf_mtxp);

		allocbuf(bp, size);

		upl_flags = 0;
		switch (operation) {
		case BLK_META:
			/*
			 * buffer data is invalid...
			 *
			 * I don't want to have to retake buf_mtxp,
			 * so the miss and vmhits counters are done
			 * with Atomic updates... all other counters
			 * in bufstats are protected with either
			 * buf_mtxp or iobuffer_mtxp
			 */
		        OSAddAtomicLong(1, &bufstats.bufs_miss);
			break;

		case BLK_WRITE:
			/*
			 * "write" operation:  let the UPL subsystem know
			 * that we intend to modify the buffer cache pages
			 * we're gathering.
			 */
			upl_flags |= UPL_WILL_MODIFY;
		case BLK_READ:
		  {     off_t	f_offset;
			size_t 	contig_bytes;
			int	bmap_flags;

			if ( (bp->b_upl) )
				panic("bp already has UPL: %p",bp);

			f_offset = ubc_blktooff(vp, blkno);

			upl_flags |= UPL_PRECIOUS;
			kret = ubc_create_upl(vp,
					      f_offset,
					      bp->b_bufsize, 
					      &upl,
					      &pl,
					      upl_flags);

			if (kret != KERN_SUCCESS)
				panic("Failed to create UPL");
#if  UPL_DEBUG
			upl_ubc_alias_set(upl, (uintptr_t) bp, (uintptr_t) 4);
#endif /* UPL_DEBUG */
			bp->b_upl = upl;

			if (upl_valid_page(pl, 0)) {

			        if (operation == BLK_READ)
				        bmap_flags = VNODE_READ;
				else
				        bmap_flags = VNODE_WRITE;

				SET(bp->b_flags, B_CACHE | B_DONE);

			        OSAddAtomicLong(1, &bufstats.bufs_vmhits);

				bp->b_validoff = 0;
				bp->b_dirtyoff = 0;

				if (upl_dirty_page(pl, 0)) {
					/* page is dirty */
				        SET(bp->b_flags, B_WASDIRTY);

					bp->b_validend = bp->b_bcount;
					bp->b_dirtyend = bp->b_bcount;
				} else {
					/* page is clean */
					bp->b_validend = bp->b_bcount;
					bp->b_dirtyend = 0;
				}
				/*
				 * try to recreate the physical block number associated with
				 * this buffer...
				 */
				if (VNOP_BLOCKMAP(vp, f_offset, bp->b_bcount, &bp->b_blkno, &contig_bytes, NULL, bmap_flags, NULL))
				        panic("getblk: VNOP_BLOCKMAP failed");
				/*
				 * if the extent represented by this buffer
				 * is not completely physically contiguous on
				 * disk, than we can't cache the physical mapping
				 * in the buffer header
				 */
				if ((long)contig_bytes < bp->b_bcount)
				        bp->b_blkno = bp->b_lblkno;
			} else {
			        OSAddAtomicLong(1, &bufstats.bufs_miss);
			}
			kret = ubc_upl_map(upl, (vm_offset_t *)&(bp->b_datap));

			if (kret != KERN_SUCCESS)
			        panic("getblk: ubc_upl_map() failed with (%d)", kret);
			break;
		  }
		default:
			panic("getblk: paging or unknown operation - %x", operation);
			/*NOTREACHED*/
			break;
		}
	}
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 386)) | DBG_FUNC_END,
		     bp, bp->b_datap, bp->b_flags, 3, 0);

#ifdef JOE_DEBUG
	(void) OSBacktrace(&bp->b_stackgetblk[0], 6);
#endif
	return (bp);
}

/*
 * Get an empty, disassociated buffer of given size.
 */
buf_t
buf_geteblk(int size)
{
	buf_t	bp = NULL;
	int queue = BQ_EMPTY;

	do {
		lck_mtx_lock_spin(buf_mtxp);

		bp = getnewbuf(0, 0, &queue);
	} while (bp == NULL);

	SET(bp->b_flags, (B_META|B_INVAL));

#if DIAGNOSTIC
	assert(queue == BQ_EMPTY);
#endif /* DIAGNOSTIC */
	/* XXX need to implement logic to deal with other queues */

	binshash(bp, &invalhash);
	bufstats.bufs_eblk++;

	lck_mtx_unlock(buf_mtxp);

	allocbuf(bp, size);

	return (bp);
}

uint32_t
buf_redundancy_flags(buf_t bp)
{
	return bp->b_redundancy_flags;
}

void
buf_set_redundancy_flags(buf_t bp, uint32_t flags)
{
	SET(bp->b_redundancy_flags, flags);
}

void
buf_clear_redundancy_flags(buf_t bp, uint32_t flags)
{
	CLR(bp->b_redundancy_flags, flags);
}

/*
 * With UBC, there is no need to expand / shrink the file data 
 * buffer. The VM uses the same pages, hence no waste.
 * All the file data buffers can have one size.
 * In fact expand / shrink would be an expensive operation.
 *
 * Only exception to this is meta-data buffers. Most of the
 * meta data operations are smaller than PAGE_SIZE. Having the
 * meta-data buffers grow and shrink as needed, optimizes use
 * of the kernel wired memory.
 */

int
allocbuf(buf_t bp, int size)
{
	vm_size_t desired_size;

	desired_size = roundup(size, CLBYTES);

	if (desired_size < PAGE_SIZE)
		desired_size = PAGE_SIZE;
	if (desired_size > MAXBSIZE)
		panic("allocbuf: buffer larger than MAXBSIZE requested");

	if (ISSET(bp->b_flags, B_META)) {
		zone_t zprev, z;
		int    nsize = roundup(size, MINMETA);

		if (bp->b_datap) {
			vm_offset_t elem = (vm_offset_t)bp->b_datap;

			if (ISSET(bp->b_flags, B_ZALLOC)) {
			        if (bp->b_bufsize < nsize) {
				        /* reallocate to a bigger size */

				        zprev = getbufzone(bp->b_bufsize);
					if (nsize <= MAXMETA) {
					        desired_size = nsize;
						z = getbufzone(nsize);
						/* b_datap not really a ptr */
						*(void **)(&bp->b_datap) = zalloc(z);
					} else {
					        bp->b_datap = (uintptr_t)NULL;
					        kmem_alloc_kobject(kernel_map, (vm_offset_t *)&bp->b_datap, desired_size);
						CLR(bp->b_flags, B_ZALLOC);
					}
					bcopy((void *)elem, (caddr_t)bp->b_datap, bp->b_bufsize);
					zfree(zprev, (void *)elem);
				} else {
				        desired_size = bp->b_bufsize;
				}

			} else {
				if ((vm_size_t)bp->b_bufsize < desired_size) {
					/* reallocate to a bigger size */
				        bp->b_datap = (uintptr_t)NULL;
					kmem_alloc_kobject(kernel_map, (vm_offset_t *)&bp->b_datap, desired_size);
					bcopy((const void *)elem, (caddr_t)bp->b_datap, bp->b_bufsize);
					kmem_free(kernel_map, elem, bp->b_bufsize); 
				} else {
					desired_size = bp->b_bufsize;
				}
			}
		} else {
			/* new allocation */
			if (nsize <= MAXMETA) {
				desired_size = nsize;
				z = getbufzone(nsize);
				/* b_datap not really a ptr */
				*(void **)(&bp->b_datap) = zalloc(z);
				SET(bp->b_flags, B_ZALLOC);
			} else
				kmem_alloc_kobject(kernel_map, (vm_offset_t *)&bp->b_datap, desired_size);
		}

		if (bp->b_datap == 0)
		        panic("allocbuf: NULL b_datap");
	}
	bp->b_bufsize = desired_size;
	bp->b_bcount = size;

	return (0);
}

/*
 *	Get a new buffer from one of the free lists.
 *
 *	Request for a queue is passes in. The queue from which the buffer was taken
 *	from is returned. Out of range queue requests get BQ_EMPTY. Request for
 *	BQUEUE means no preference. Use heuristics in that case.
 *	Heuristics is as follows:
 *	Try BQ_AGE, BQ_LRU, BQ_EMPTY, BQ_META in that order.
 *	If none available block till one is made available.
 *	If buffers available on both BQ_AGE and BQ_LRU, check the timestamps.
 *	Pick the most stale buffer.
 *	If found buffer was marked delayed write, start the async. write
 *	and restart the search.
 *	Initialize the fields and disassociate the buffer from the vnode.
 *	Remove the buffer from the hash. Return the buffer and the queue
 *	on which it was found.
 *
 *	buf_mtxp is held upon entry
 *	returns with buf_mtxp locked if new buf available
 *	returns with buf_mtxp UNlocked if new buf NOT available
 */

static buf_t
getnewbuf(int slpflag, int slptimeo, int * queue)
{
	buf_t	bp;
	buf_t	lru_bp;
	buf_t	age_bp;
	buf_t	meta_bp;
	int	age_time, lru_time, bp_time, meta_time;
	int	req = *queue;	/* save it for restarts */
	struct timespec ts;

start:
	/*
	 * invalid request gets empty queue
	 */
	if ((*queue >= BQUEUES) || (*queue < 0)
		|| (*queue == BQ_LAUNDRY) || (*queue == BQ_LOCKED))
		*queue = BQ_EMPTY;


	if (*queue == BQ_EMPTY && (bp = bufqueues[*queue].tqh_first))
	        goto found;

	/*
	 * need to grow number of bufs, add another one rather than recycling
	 */
	if (nbuf_headers < max_nbuf_headers) {
		/*
		 * Increment  count now as lock 
		 * is dropped for allocation.
		 * That avoids over commits
		 */
		nbuf_headers++;
		goto add_newbufs;
	}
	/* Try for the requested queue first */
	bp = bufqueues[*queue].tqh_first;
	if (bp)
	        goto found;

	/* Unable to use requested queue */
	age_bp = bufqueues[BQ_AGE].tqh_first;
	lru_bp = bufqueues[BQ_LRU].tqh_first;
	meta_bp = bufqueues[BQ_META].tqh_first;

	if (!age_bp && !lru_bp && !meta_bp) {
		/*
		 * Unavailble on AGE or LRU or META queues
		 * Try the empty list first
		 */
		bp = bufqueues[BQ_EMPTY].tqh_first;
		if (bp) {
			*queue = BQ_EMPTY;
			goto found;
		}
		/*
		 * We have seen is this is hard to trigger.
		 * This is an overcommit of nbufs but needed 
		 * in some scenarios with diskiamges
		 */

add_newbufs:
		lck_mtx_unlock(buf_mtxp);

		/* Create a new temporary buffer header */
		bp = (struct buf *)zalloc(buf_hdr_zone);
		
		if (bp) {
			bufhdrinit(bp);
			bp->b_whichq = BQ_EMPTY;
			bp->b_timestamp = buf_timestamp();
			BLISTNONE(bp);
			SET(bp->b_flags, B_HDRALLOC);
			*queue = BQ_EMPTY;
		}
		lck_mtx_lock_spin(buf_mtxp);

		if (bp) {
			binshash(bp, &invalhash);
			binsheadfree(bp, &bufqueues[BQ_EMPTY], BQ_EMPTY);
			buf_hdr_count++;
			goto found;
		}
		/* subtract already accounted bufcount */
		nbuf_headers--;

		bufstats.bufs_sleeps++;

		/* wait for a free buffer of any kind */
		needbuffer = 1;
		/* hz value is 100 */
		ts.tv_sec = (slptimeo/1000);
		/* the hz value is 100; which leads to 10ms */
		ts.tv_nsec = (slptimeo % 1000) * NSEC_PER_USEC * 1000 * 10;

		msleep(&needbuffer, buf_mtxp, slpflag | PDROP | (PRIBIO+1), "getnewbuf", &ts);
		return (NULL);
	}

	/* Buffer available either on AGE or LRU or META */
	bp = NULL;
	*queue = -1;

	/* Buffer available either on AGE or LRU */
	if (!age_bp) {
		bp = lru_bp;
		*queue = BQ_LRU;
	} else if (!lru_bp) {
		bp = age_bp;
		*queue = BQ_AGE;
	} else { /* buffer available on both AGE and LRU */
		int		t = buf_timestamp();

		age_time = t - age_bp->b_timestamp;
		lru_time = t - lru_bp->b_timestamp;
		if ((age_time < 0) || (lru_time < 0)) { /* time set backwards */
			bp = age_bp;
			*queue = BQ_AGE;
			/*
			 * we should probably re-timestamp eveything in the
			 * queues at this point with the current time
			 */
		} else {
			if ((lru_time >= lru_is_stale) && (age_time < age_is_stale)) {
				bp = lru_bp;
				*queue = BQ_LRU;
			} else {
				bp = age_bp;
				*queue = BQ_AGE;
			}
		}
	}

	if (!bp) { /* Neither on AGE nor on LRU */
		bp = meta_bp;
		*queue = BQ_META;
	}  else if (meta_bp) {
		int		t = buf_timestamp();

		bp_time = t - bp->b_timestamp;
		meta_time = t - meta_bp->b_timestamp;

		if (!(bp_time < 0) && !(meta_time < 0)) {
			/* time not set backwards */
			int bp_is_stale;
			bp_is_stale = (*queue == BQ_LRU) ? 
					lru_is_stale : age_is_stale;

			if ((meta_time >= meta_is_stale) && 
					(bp_time < bp_is_stale)) {
				bp = meta_bp;
				*queue = BQ_META;
			}
		}
	}
found:
	if (ISSET(bp->b_flags, B_LOCKED) || ISSET(bp->b_lflags, BL_BUSY))
	        panic("getnewbuf: bp @ %p is LOCKED or BUSY! (flags 0x%x)\n", bp, bp->b_flags);

	/* Clean it */
	if (bcleanbuf(bp, FALSE)) {
		/*
		 * moved to the laundry thread, buffer not ready
		 */
		*queue = req;
		goto start;
	}
	return (bp); 
}


/* 
 * Clean a buffer.
 * Returns 0 if buffer is ready to use,
 * Returns 1 if issued a buf_bawrite() to indicate 
 * that the buffer is not ready.
 * 
 * buf_mtxp is held upon entry
 * returns with buf_mtxp locked
 */
int
bcleanbuf(buf_t bp, boolean_t discard)
{
	/* Remove from the queue */
	bremfree_locked(bp);

#ifdef JOE_DEBUG
	bp->b_owner = current_thread();
	bp->b_tag   = 2;
#endif
	/*
	 * If buffer was a delayed write, start the IO by queuing
	 * it on the LAUNDRY queue, and return 1
	 */
	if (ISSET(bp->b_flags, B_DELWRI)) {
		if (discard) {
			SET(bp->b_lflags, BL_WANTDEALLOC);
		}

		bmovelaundry(bp);

		lck_mtx_unlock(buf_mtxp);

		wakeup(&bufqueues[BQ_LAUNDRY]);
		/*
		 * and give it a chance to run
		 */
		(void)thread_block(THREAD_CONTINUE_NULL);

		lck_mtx_lock_spin(buf_mtxp);

		return (1);
	}
#ifdef JOE_DEBUG
	bp->b_owner = current_thread();
	bp->b_tag   = 8;
#endif
	/*
	 * Buffer is no longer on any free list... we own it
	 */
	SET(bp->b_lflags, BL_BUSY);
	buf_busycount++;
	
	bremhash(bp);

	/*
	 * disassociate us from our vnode, if we had one...
	 */
	if (bp->b_vp)
		brelvp_locked(bp);

	lck_mtx_unlock(buf_mtxp);

	BLISTNONE(bp);

	if (ISSET(bp->b_flags, B_META))
		buf_free_meta_store(bp);

	trace(TR_BRELSE, pack(bp->b_vp, bp->b_bufsize), bp->b_lblkno);

	buf_release_credentials(bp);

	/* If discarding, just move to the empty queue */
	if (discard) {
		lck_mtx_lock_spin(buf_mtxp);
		CLR(bp->b_flags, (B_META | B_ZALLOC | B_DELWRI | B_LOCKED | B_AGE | B_ASYNC | B_NOCACHE | B_FUA));
		bp->b_whichq = BQ_EMPTY;
		binshash(bp, &invalhash);
		binsheadfree(bp, &bufqueues[BQ_EMPTY], BQ_EMPTY);
		CLR(bp->b_lflags, BL_BUSY);
		buf_busycount--;
	} else {
		/* Not discarding: clean up and prepare for reuse */
		bp->b_bufsize = 0;
		bp->b_datap = (uintptr_t)NULL;
		bp->b_upl = (void *)NULL;
		/*
		 * preserve the state of whether this buffer
		 * was allocated on the fly or not...
		 * the only other flag that should be set at
		 * this point is BL_BUSY...
		 */
#ifdef JOE_DEBUG
		bp->b_owner = current_thread();
		bp->b_tag   = 3;
#endif
		bp->b_lflags = BL_BUSY;
		bp->b_flags = (bp->b_flags & B_HDRALLOC);
		bp->b_dev = NODEV;
		bp->b_blkno = bp->b_lblkno = 0;
		bp->b_iodone = NULL;
		bp->b_error = 0;
		bp->b_resid = 0;
		bp->b_bcount = 0;
		bp->b_dirtyoff = bp->b_dirtyend = 0;
		bp->b_validoff = bp->b_validend = 0;
#ifdef CONFIG_PROTECT
		bp->b_cpentry = 0;
#endif
		bzero(&bp->b_attr, sizeof(struct bufattr));

		lck_mtx_lock_spin(buf_mtxp);
	}
	return (0);
}



errno_t
buf_invalblkno(vnode_t vp, daddr64_t lblkno, int flags)
{
        buf_t	bp;
	errno_t	error;
	struct bufhashhdr *dp;

	dp = BUFHASH(vp, lblkno);

relook:	
	lck_mtx_lock_spin(buf_mtxp);

	if ((bp = incore_locked(vp, lblkno, dp)) == (struct buf *)0) {
	        lck_mtx_unlock(buf_mtxp);
		return (0);
	}
	if (ISSET(bp->b_lflags, BL_BUSY)) {
	        if ( !ISSET(flags, BUF_WAIT)) {
		        lck_mtx_unlock(buf_mtxp);
			return (EBUSY);
		}
	        SET(bp->b_lflags, BL_WANTED);

		error = msleep((caddr_t)bp, buf_mtxp, PDROP | (PRIBIO + 1), "buf_invalblkno", NULL);

		if (error) {
			return (error);
		}
		goto relook;
	}
	bremfree_locked(bp);
	SET(bp->b_lflags, BL_BUSY);
	SET(bp->b_flags, B_INVAL);
	buf_busycount++;
#ifdef JOE_DEBUG
	bp->b_owner = current_thread();
	bp->b_tag   = 4;
#endif
	lck_mtx_unlock(buf_mtxp);
	buf_brelse(bp);

	return (0);
}


void
buf_drop(buf_t bp)
{
        int need_wakeup = 0;

	lck_mtx_lock_spin(buf_mtxp);

	if (ISSET(bp->b_lflags, BL_WANTED)) {
	        /*	
		 * delay the actual wakeup until after we
		 * clear BL_BUSY and we've dropped buf_mtxp
		 */
		need_wakeup = 1;
	}
#ifdef JOE_DEBUG
	bp->b_owner = current_thread();
	bp->b_tag   = 9;
#endif
	/*
	 * Unlock the buffer.
	 */
	CLR(bp->b_lflags, (BL_BUSY | BL_WANTED));
	buf_busycount--;

	lck_mtx_unlock(buf_mtxp);

	if (need_wakeup) {
	        /*
		 * Wake up any proceeses waiting for _this_ buffer to become free.
		 */
	        wakeup(bp);
	}
}


errno_t
buf_acquire(buf_t bp, int flags, int slpflag, int slptimeo) {
        errno_t error;

        lck_mtx_lock_spin(buf_mtxp);

	error = buf_acquire_locked(bp, flags, slpflag, slptimeo);

       	lck_mtx_unlock(buf_mtxp);

	return (error);
}


static errno_t
buf_acquire_locked(buf_t bp, int flags, int slpflag, int slptimeo)
{
	errno_t error;
	struct timespec ts;

	if (ISSET(bp->b_flags, B_LOCKED)) {
	        if ((flags & BAC_SKIP_LOCKED))
			return (EDEADLK);
	} else {
	        if ((flags & BAC_SKIP_NONLOCKED))
			return (EDEADLK);
	}
        if (ISSET(bp->b_lflags, BL_BUSY)) {
	        /*	
		 * since the lck_mtx_lock may block, the buffer
		 * may become BUSY, so we need to
		 * recheck for a NOWAIT request
		 */
	        if (flags & BAC_NOWAIT)
			return (EBUSY);
	        SET(bp->b_lflags, BL_WANTED);

		/* the hz value is 100; which leads to 10ms */
		ts.tv_sec = (slptimeo/100);
		ts.tv_nsec = (slptimeo % 100) * 10  * NSEC_PER_USEC * 1000;
		error = msleep((caddr_t)bp, buf_mtxp, slpflag | (PRIBIO + 1), "buf_acquire", &ts);

		if (error)
			return (error);
		return (EAGAIN);
	}
	if (flags & BAC_REMOVE)
	        bremfree_locked(bp);
	SET(bp->b_lflags, BL_BUSY);
	buf_busycount++;

#ifdef JOE_DEBUG
	bp->b_owner = current_thread();
	bp->b_tag   = 5;
#endif
	return (0);
}


/*
 * Wait for operations on the buffer to complete.
 * When they do, extract and return the I/O's error value.
 */
errno_t
buf_biowait(buf_t bp)
{
	while (!ISSET(bp->b_flags, B_DONE)) {

		lck_mtx_lock_spin(buf_mtxp);

		if (!ISSET(bp->b_flags, B_DONE)) {
			DTRACE_IO1(wait__start, buf_t, bp);
			(void) msleep(bp, buf_mtxp, PDROP | (PRIBIO+1), "buf_biowait", NULL);
			DTRACE_IO1(wait__done, buf_t, bp);
		} else
			lck_mtx_unlock(buf_mtxp);
	}
	/* check for interruption of I/O (e.g. via NFS), then errors. */
	if (ISSET(bp->b_flags, B_EINTR)) {
		CLR(bp->b_flags, B_EINTR);
		return (EINTR);
	} else if (ISSET(bp->b_flags, B_ERROR))
		return (bp->b_error ? bp->b_error : EIO);
	else
		return (0);
}


/*
 * Mark I/O complete on a buffer.
 *
 * If a callback has been requested, e.g. the pageout
 * daemon, do so. Otherwise, awaken waiting processes.
 *
 * [ Leffler, et al., says on p.247:
 *	"This routine wakes up the blocked process, frees the buffer
 *	for an asynchronous write, or, for a request by the pagedaemon
 *	process, invokes a procedure specified in the buffer structure" ]
 *
 * In real life, the pagedaemon (or other system processes) wants
 * to do async stuff to, and doesn't want the buffer buf_brelse()'d.
 * (for swap pager, that puts swap buffers on the free lists (!!!),
 * for the vn device, that puts malloc'd buffers on the free lists!)
 */
extern struct timeval priority_IO_timestamp_for_root;
extern int hard_throttle_on_root;

void
buf_biodone(buf_t bp)
{
	mount_t mp;
	
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 387)) | DBG_FUNC_START,
		     bp, bp->b_datap, bp->b_flags, 0, 0);

	if (ISSET(bp->b_flags, B_DONE))
		panic("biodone already");

	if (ISSET(bp->b_flags, B_ERROR)) {
		fslog_io_error(bp);
	}

	if (bp->b_vp && bp->b_vp->v_mount) {
		mp = bp->b_vp->v_mount;
	} else {
		mp = NULL;
	}
	
	if (mp && (bp->b_flags & B_READ) == 0) {
		update_last_io_time(mp);
		INCR_PENDING_IO(-(pending_io_t)buf_count(bp), mp->mnt_pending_write_size);
	} else if (mp) {
		INCR_PENDING_IO(-(pending_io_t)buf_count(bp), mp->mnt_pending_read_size);
	}

        if (kdebug_enable) {
	        int    code = DKIO_DONE;

		if (bp->b_flags & B_READ)
		        code |= DKIO_READ;
		if (bp->b_flags & B_ASYNC)
		        code |= DKIO_ASYNC;

		if (bp->b_flags & B_META)
		        code |= DKIO_META;
		else if (bp->b_flags & B_PAGEIO)
		        code |= DKIO_PAGING;

		if (bp->b_flags & B_THROTTLED_IO)
			code |= DKIO_THROTTLE;
		else if (bp->b_flags & B_PASSIVE)
			code |= DKIO_PASSIVE;

		KERNEL_DEBUG_CONSTANT(FSDBG_CODE(DBG_DKRW, code) | DBG_FUNC_NONE,
                              bp, (uintptr_t)bp->b_vp,
				      bp->b_resid, bp->b_error, 0);
        }
	if ((bp->b_vp != NULLVP) &&
	    ((bp->b_flags & (B_IOSTREAMING | B_PAGEIO | B_READ)) == (B_PAGEIO | B_READ)) &&
	    (bp->b_vp->v_mount->mnt_kern_flag & MNTK_ROOTDEV)) {
	        microuptime(&priority_IO_timestamp_for_root);
	        hard_throttle_on_root = 0;
	}

	/*
	 * I/O was done, so don't believe
	 * the DIRTY state from VM anymore...
	 * and we need to reset the THROTTLED/PASSIVE
	 * indicators
	 */
	CLR(bp->b_flags, (B_WASDIRTY | B_THROTTLED_IO | B_PASSIVE));
	CLR(bp->b_attr.ba_flags, (BA_THROTTLED_IO));
	DTRACE_IO1(done, buf_t, bp);

	if (!ISSET(bp->b_flags, B_READ) && !ISSET(bp->b_flags, B_RAW))
	        /*
		 * wake up any writer's blocked
		 * on throttle or waiting for I/O
		 * to drain
		 */
		vnode_writedone(bp->b_vp);

	if (ISSET(bp->b_flags, (B_CALL | B_FILTER))) {	/* if necessary, call out */
		void	(*iodone_func)(struct buf *, void *) = bp->b_iodone;
		void 	*arg = bp->b_transaction;
		int     callout = ISSET(bp->b_flags, B_CALL);

		if (iodone_func == NULL)
			panic("biodone: bp @ %p has NULL b_iodone!\n", bp);			

		CLR(bp->b_flags, (B_CALL | B_FILTER));	/* filters and callouts are one-shot */
		bp->b_iodone = NULL;
		bp->b_transaction = NULL;

		if (callout)
		        SET(bp->b_flags, B_DONE);	/* note that it's done */

		(*iodone_func)(bp, arg);

		if (callout) {
			/*
			 * assumes that the callback function takes
			 * ownership of the bp and deals with releasing it if necessary
			 */
			goto biodone_done;
		}
		/*
		 * in this case the call back function is acting
		 * strictly as a filter... it does not take
		 * ownership of the bp and is expecting us
		 * to finish cleaning up... this is currently used
		 * by the HFS journaling code
		 */
	}
	if (ISSET(bp->b_flags, B_ASYNC)) {	/* if async, release it */
		SET(bp->b_flags, B_DONE);	/* note that it's done */

		buf_brelse(bp);
	} else {				/* or just wakeup the buffer */	
	        /*
		 * by taking the mutex, we serialize
		 * the buf owner calling buf_biowait so that we'll
		 * only see him in one of 2 states...
		 * state 1: B_DONE wasn't set and he's
		 * blocked in msleep
		 * state 2: he's blocked trying to take the
		 * mutex before looking at B_DONE
		 * BL_WANTED is cleared in case anyone else
		 * is blocked waiting for the buffer... note
		 * that we haven't cleared B_BUSY yet, so if
		 * they do get to run, their going to re-set
		 * BL_WANTED and go back to sleep
		 */
	        lck_mtx_lock_spin(buf_mtxp);

		CLR(bp->b_lflags, BL_WANTED);
		SET(bp->b_flags, B_DONE);		/* note that it's done */

	        lck_mtx_unlock(buf_mtxp);

		wakeup(bp);
	}
biodone_done:
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 387)) | DBG_FUNC_END,
                 (uintptr_t)bp, (uintptr_t)bp->b_datap, bp->b_flags, 0, 0);
}

/*
 * Return a count of buffers on the "locked" queue.
 */
int
count_lock_queue(void)
{
	buf_t	bp;
	int	n = 0;

	lck_mtx_lock_spin(buf_mtxp);

	for (bp = bufqueues[BQ_LOCKED].tqh_first; bp;
	    bp = bp->b_freelist.tqe_next)
		n++;
	lck_mtx_unlock(buf_mtxp);

	return (n);
}

/*
 * Return a count of 'busy' buffers. Used at the time of shutdown.
 */
int
count_busy_buffers(void)
{
	return buf_busycount + bufstats.bufs_iobufinuse;
}

#if DIAGNOSTIC
/*
 * Print out statistics on the current allocation of the buffer pool.
 * Can be enabled to print out on every ``sync'' by setting "syncprt"
 * in vfs_syscalls.c using sysctl.
 */
void
vfs_bufstats()
{
	int i, j, count;
	struct buf *bp;
	struct bqueues *dp;
	int counts[MAXBSIZE/CLBYTES+1];
	static char *bname[BQUEUES] =
		{ "LOCKED", "LRU", "AGE", "EMPTY", "META", "LAUNDRY" };

	for (dp = bufqueues, i = 0; dp < &bufqueues[BQUEUES]; dp++, i++) {
		count = 0;
		for (j = 0; j <= MAXBSIZE/CLBYTES; j++)
			counts[j] = 0;

		lck_mtx_lock(buf_mtxp);

		for (bp = dp->tqh_first; bp; bp = bp->b_freelist.tqe_next) {
			counts[bp->b_bufsize/CLBYTES]++;
			count++;
		}
		lck_mtx_unlock(buf_mtxp);

		printf("%s: total-%d", bname[i], count);
		for (j = 0; j <= MAXBSIZE/CLBYTES; j++)
			if (counts[j] != 0)
				printf(", %d-%d", j * CLBYTES, counts[j]);
		printf("\n");
	}
}
#endif /* DIAGNOSTIC */

#define	NRESERVEDIOBUFS	128


buf_t
alloc_io_buf(vnode_t vp, int priv)
{
	buf_t	bp;

	lck_mtx_lock_spin(iobuffer_mtxp);

	while (((niobuf_headers - NRESERVEDIOBUFS < bufstats.bufs_iobufinuse) && !priv) || 
	       (bp = iobufqueue.tqh_first) == NULL) {
		bufstats.bufs_iobufsleeps++;

		need_iobuffer = 1;
		(void) msleep(&need_iobuffer, iobuffer_mtxp, PSPIN | (PRIBIO+1), (const char *)"alloc_io_buf", NULL);
	}
	TAILQ_REMOVE(&iobufqueue, bp, b_freelist);

	bufstats.bufs_iobufinuse++;
	if (bufstats.bufs_iobufinuse > bufstats.bufs_iobufmax)
		bufstats.bufs_iobufmax = bufstats.bufs_iobufinuse;

	lck_mtx_unlock(iobuffer_mtxp);

	/*
	 * initialize various fields
	 * we don't need to hold the mutex since the buffer
	 * is now private... the vp should have a reference 
	 * on it and is not protected by this mutex in any event
	 */
	bp->b_timestamp = 0; 
	bp->b_proc = NULL;

	bp->b_datap = 0;
	bp->b_flags = 0;
	bp->b_lflags = BL_BUSY | BL_IOBUF;
	bp->b_redundancy_flags = 0;
	bp->b_blkno = bp->b_lblkno = 0;
#ifdef JOE_DEBUG
	bp->b_owner = current_thread();
	bp->b_tag   = 6;
#endif
	bp->b_iodone = NULL;
	bp->b_error = 0;
	bp->b_resid = 0;
	bp->b_bcount = 0;
	bp->b_bufsize = 0;
	bp->b_upl = NULL;
	bp->b_vp = vp;
#ifdef CONFIG_PROTECT
	bp->b_cpentry = 0;
#endif
	bzero(&bp->b_attr, sizeof(struct bufattr));

	if (vp && (vp->v_type == VBLK || vp->v_type == VCHR))
		bp->b_dev = vp->v_rdev;
	else
		bp->b_dev = NODEV;

	return (bp);
}


void
free_io_buf(buf_t bp)
{
        int need_wakeup = 0;

	/*
	 * put buffer back on the head of the iobufqueue
	 */
	bp->b_vp = NULL;
	bp->b_flags = B_INVAL;

	lck_mtx_lock_spin(iobuffer_mtxp);

	binsheadfree(bp, &iobufqueue, -1);

	if (need_iobuffer) {
	        /*
		 * Wake up any processes waiting because they need an io buffer
		 *
		 * do the wakeup after we drop the mutex... it's possible that the
		 * wakeup will be superfluous if need_iobuffer gets set again and
		 * another thread runs this path, but it's highly unlikely, doesn't
		 * hurt, and it means we don't hold up I/O progress if the wakeup blocks
		 * trying to grab a task related lock...
		 */
		need_iobuffer = 0;
		need_wakeup = 1;
	}
	if (bufstats.bufs_iobufinuse <= 0)
		panic("free_io_buf: bp(%p) - bufstats.bufs_iobufinuse < 0", bp);

	bufstats.bufs_iobufinuse--;

	lck_mtx_unlock(iobuffer_mtxp);

	if (need_wakeup)
	        wakeup(&need_iobuffer);
}


void
buf_list_lock(void)
{
        lck_mtx_lock_spin(buf_mtxp);
}

void
buf_list_unlock(void)
{
        lck_mtx_unlock(buf_mtxp);
}

/*
 * If getnewbuf() calls bcleanbuf() on the same thread
 * there is a potential for stack overrun and deadlocks.
 * So we always handoff the work to a worker thread for completion
 */


static void
bcleanbuf_thread_init(void)
{
	thread_t	thread = THREAD_NULL;

	/* create worker thread */
	kernel_thread_start((thread_continue_t)bcleanbuf_thread, NULL, &thread);
	thread_deallocate(thread);
}

typedef int (*bcleanbufcontinuation)(int);

static void
bcleanbuf_thread(void)
{
	struct buf *bp;
	int error = 0;
	int loopcnt = 0;

	for (;;) {
	        lck_mtx_lock_spin(buf_mtxp);

		while ( (bp = TAILQ_FIRST(&bufqueues[BQ_LAUNDRY])) == NULL) {
			(void)msleep0(&bufqueues[BQ_LAUNDRY], buf_mtxp, PRIBIO|PDROP, "blaundry", 0, (bcleanbufcontinuation)bcleanbuf_thread);
		}
		
		/*
		 * Remove from the queue
		 */
		bremfree_locked(bp);

		/*
		 * Buffer is no longer on any free list
		 */
		SET(bp->b_lflags, BL_BUSY);
		buf_busycount++;

#ifdef JOE_DEBUG
		bp->b_owner = current_thread();
		bp->b_tag   = 10;
#endif

		lck_mtx_unlock(buf_mtxp);
		/*
		 * do the IO
		 */
		error = bawrite_internal(bp, 0);

		if (error) {
		        bp->b_whichq = BQ_LAUNDRY;
			bp->b_timestamp = buf_timestamp();

		        lck_mtx_lock_spin(buf_mtxp);

			binstailfree(bp, &bufqueues[BQ_LAUNDRY], BQ_LAUNDRY);
			blaundrycnt++;

			/* we never leave a busy page on the laundry queue */
			CLR(bp->b_lflags, BL_BUSY);
			buf_busycount--;
#ifdef JOE_DEBUG
			bp->b_owner = current_thread();
			bp->b_tag   = 11;
#endif

			lck_mtx_unlock(buf_mtxp);
			
			if (loopcnt > MAXLAUNDRY) {
				/*
				 * bawrite_internal() can return errors if we're throttled. If we've
				 * done several I/Os and failed, give the system some time to unthrottle
				 * the vnode
				 */
				(void)tsleep((void *)&bufqueues[BQ_LAUNDRY], PRIBIO, "blaundry", 1);
				loopcnt = 0;
			} else {
				/* give other threads a chance to run */
				(void)thread_block(THREAD_CONTINUE_NULL);
				loopcnt++;
			}
		}
	}
}


static int
brecover_data(buf_t bp)
{
	int	upl_offset;
        upl_t	upl;
	upl_page_info_t *pl;
	kern_return_t kret;
	vnode_t	vp = bp->b_vp;
	int upl_flags;


	if ( !UBCINFOEXISTS(vp) || bp->b_bufsize == 0)
	        goto dump_buffer;

	upl_flags = UPL_PRECIOUS;
	if (! (buf_flags(bp) & B_READ)) {
		/*
		 * "write" operation:  let the UPL subsystem know
		 * that we intend to modify the buffer cache pages we're
		 * gathering.
		 */
		upl_flags |= UPL_WILL_MODIFY;
	}
		
	kret = ubc_create_upl(vp,
			      ubc_blktooff(vp, bp->b_lblkno), 
			      bp->b_bufsize, 
			      &upl, 
			      &pl,
			      upl_flags);
	if (kret != KERN_SUCCESS)
	        panic("Failed to create UPL");

	for (upl_offset = 0; upl_offset < bp->b_bufsize; upl_offset += PAGE_SIZE) {

	        if (!upl_valid_page(pl, upl_offset / PAGE_SIZE) || !upl_dirty_page(pl, upl_offset / PAGE_SIZE)) {
		        ubc_upl_abort(upl, 0);
			goto dump_buffer;
		}
	}
	bp->b_upl = upl;
					
	kret = ubc_upl_map(upl, (vm_offset_t *)&(bp->b_datap));

	if (kret != KERN_SUCCESS)
	        panic("getblk: ubc_upl_map() failed with (%d)", kret);
	return (1);

dump_buffer:
	bp->b_bufsize = 0;
	SET(bp->b_flags, B_INVAL);
	buf_brelse(bp);

	return(0);
}

boolean_t 
buffer_cache_gc(int all)
{
	buf_t bp;
	boolean_t did_large_zfree = FALSE;
	boolean_t need_wakeup = FALSE;
	int now = buf_timestamp();
	uint32_t found = 0, total_found = 0;
	struct bqueues privq;
	int thresh_hold = BUF_STALE_THRESHHOLD;

	if (all)
		thresh_hold = 0;
	/* 
	 * We only care about metadata (incore storage comes from zalloc()).
	 * No more than 1024 buffers total, and only those not accessed within the
	 * last 30s.  We will also only examine 128 buffers during a single grab
	 * of the lock in order to limit lock hold time.
	 */
	lck_mtx_lock(buf_mtxp);
	do {
		found = 0;
		TAILQ_INIT(&privq);
		need_wakeup = FALSE;

		while (((bp = TAILQ_FIRST(&bufqueues[BQ_META]))) && 
				(now > bp->b_timestamp) &&
				(now - bp->b_timestamp > thresh_hold) && 
				(found < BUF_MAX_GC_BATCH_SIZE)) {

			/* Remove from free list */
			bremfree_locked(bp);
			found++;

#ifdef JOE_DEBUG
			bp->b_owner = current_thread();
			bp->b_tag   = 12;
#endif

			/* If dirty, move to laundry queue and remember to do wakeup */
			if (ISSET(bp->b_flags, B_DELWRI)) {
				SET(bp->b_lflags, BL_WANTDEALLOC);

				bmovelaundry(bp);
				need_wakeup = TRUE;

				continue;
			}

			/* 
			 * Mark busy and put on private list.  We could technically get 
			 * away without setting BL_BUSY here.
			 */
			SET(bp->b_lflags, BL_BUSY);
			buf_busycount++;

			/* 
			 * Remove from hash and dissociate from vp.
			 */
			bremhash(bp);
			if (bp->b_vp) {
				brelvp_locked(bp);
			}

			TAILQ_INSERT_TAIL(&privq, bp, b_freelist);
		}

		if (found == 0) {
			break;
		}

		/* Drop lock for batch processing */
		lck_mtx_unlock(buf_mtxp);

		/* Wakeup and yield for laundry if need be */
		if (need_wakeup) {
			wakeup(&bufqueues[BQ_LAUNDRY]);
			(void)thread_block(THREAD_CONTINUE_NULL);
		}

		/* Clean up every buffer on private list */
		TAILQ_FOREACH(bp, &privq, b_freelist) {
			/* Take note if we've definitely freed at least a page to a zone */
			if ((ISSET(bp->b_flags, B_ZALLOC)) && (buf_size(bp) >= PAGE_SIZE)) {
				did_large_zfree = TRUE;
			}    

			trace(TR_BRELSE, pack(bp->b_vp, bp->b_bufsize), bp->b_lblkno);

			/* Free Storage */
			buf_free_meta_store(bp);

			/* Release credentials */
			buf_release_credentials(bp);

			/* Prepare for moving to empty queue */
			CLR(bp->b_flags, (B_META | B_ZALLOC | B_DELWRI | B_LOCKED 
						| B_AGE | B_ASYNC | B_NOCACHE | B_FUA));
			bp->b_whichq = BQ_EMPTY;
			BLISTNONE(bp);
		}

		lck_mtx_lock(buf_mtxp);

		/* Back under lock, move them all to invalid hash and clear busy */
		TAILQ_FOREACH(bp, &privq, b_freelist) {
			binshash(bp, &invalhash);
			CLR(bp->b_lflags, BL_BUSY);
			buf_busycount--;

#ifdef JOE_DEBUG
			if (bp->b_owner != current_thread()) {
				panic("Buffer stolen from buffer_cache_gc()");
			}
			bp->b_owner = current_thread();
			bp->b_tag   = 13;
#endif
		}

		/* And do a big bulk move to the empty queue */
		TAILQ_CONCAT(&bufqueues[BQ_EMPTY], &privq, b_freelist);
		total_found += found;

	} while ((all || (total_found < BUF_MAX_GC_COUNT)) && (found == BUF_MAX_GC_BATCH_SIZE));

	lck_mtx_unlock(buf_mtxp);

	return did_large_zfree;
}


/*
 * disabled for now
 */

#if FLUSH_QUEUES

#define NFLUSH 32

static int
bp_cmp(void *a, void *b)
{
    buf_t *bp_a = *(buf_t **)a,
          *bp_b = *(buf_t **)b;
    daddr64_t res;

    // don't have to worry about negative block
    // numbers so this is ok to do.
    //
    res = (bp_a->b_blkno - bp_b->b_blkno);

    return (int)res;
}


int
bflushq(int whichq, mount_t mp)
{
	buf_t	bp, next;
	int	i, buf_count;
	int	total_writes = 0;
	static buf_t flush_table[NFLUSH];

	if (whichq < 0 || whichq >= BQUEUES) {
	    return (0);
	}

  restart:
	lck_mtx_lock(buf_mtxp);

	bp = TAILQ_FIRST(&bufqueues[whichq]);

	for (buf_count = 0; bp; bp = next) {
	    next = bp->b_freelist.tqe_next;
			
	    if (bp->b_vp == NULL || bp->b_vp->v_mount != mp) {
		continue;
	    }

	    if (ISSET(bp->b_flags, B_DELWRI) && !ISSET(bp->b_lflags, BL_BUSY)) {

		bremfree_locked(bp);
#ifdef JOE_DEBUG
		bp->b_owner = current_thread();
		bp->b_tag   = 7;
#endif
		SET(bp->b_lflags, BL_BUSY);
		buf_busycount++;

		flush_table[buf_count] = bp;
		buf_count++;
		total_writes++;

		if (buf_count >= NFLUSH) {
		    lck_mtx_unlock(buf_mtxp);

		    qsort(flush_table, buf_count, sizeof(struct buf *), bp_cmp);

		    for (i = 0; i < buf_count; i++) {
			buf_bawrite(flush_table[i]);
		    }
		    goto restart;
		}
	    }
	}
	lck_mtx_unlock(buf_mtxp);

	if (buf_count > 0) {
	    qsort(flush_table, buf_count, sizeof(struct buf *), bp_cmp);

	    for (i = 0; i < buf_count; i++) {
		buf_bawrite(flush_table[i]);
	    }
	}

	return (total_writes);
}
#endif


#if BALANCE_QUEUES

/* XXX move this to a separate file */

/*
 * NOTE: THIS CODE HAS NOT BEEN UPDATED
 * WITH RESPECT TO THE NEW LOCKING MODEL
 */
   

/*
 * Dynamic Scaling of the Buffer Queues
 */

typedef long long blsize_t;

blsize_t MAXNBUF; /* initialize to (sane_size / PAGE_SIZE) */
/* Global tunable limits */
blsize_t nbufh;			/* number of buffer headers */
blsize_t nbuflow;		/* minimum number of buffer headers required */
blsize_t nbufhigh;		/* maximum number of buffer headers allowed */
blsize_t nbuftarget;	/* preferred number of buffer headers */

/*
 * assertions:
 *
 * 1.	0 < nbuflow <= nbufh <= nbufhigh
 * 2.	nbufhigh <= MAXNBUF
 * 3.	0 < nbuflow <= nbuftarget <= nbufhigh
 * 4.	nbufh can not be set by sysctl().
 */

/* Per queue tunable limits */

struct bufqlim {
	blsize_t	bl_nlow;	/* minimum number of buffer headers required */
	blsize_t	bl_num;		/* number of buffer headers on the queue */
	blsize_t	bl_nlhigh;	/* maximum number of buffer headers allowed */
	blsize_t	bl_target;	/* preferred number of buffer headers */
	long	bl_stale;	/* Seconds after which a buffer is considered stale */
} bufqlim[BQUEUES];

/*
 * assertions:
 *
 * 1.	0 <= bl_nlow <= bl_num <= bl_nlhigh
 * 2.	bl_nlhigh <= MAXNBUF
 * 3.  bufqlim[BQ_META].bl_nlow != 0
 * 4.  bufqlim[BQ_META].bl_nlow > (number of possible concurrent 
 *									file system IO operations)
 * 5.	bl_num can not be set by sysctl().
 * 6.	bl_nhigh <= nbufhigh
 */

/*
 * Rationale:
 * ----------
 * Defining it blsize_t as long permits 2^31 buffer headers per queue.
 * Which can describe (2^31 * PAGE_SIZE) memory per queue.
 * 
 * These limits are exported to by means of sysctl().
 * It was decided to define blsize_t as a 64 bit quantity.
 * This will make sure that we will not be required to change it
 * as long as we do not exceed 64 bit address space for the kernel.
 * 
 * low and high numbers parameters initialized at compile time
 * and boot arguments can be used to override them. sysctl() 
 * would not change the value. sysctl() can get all the values 
 * but can set only target. num is the current level.
 *
 * Advantages of having a "bufqscan" thread doing the balancing are, 
 * Keep enough bufs on BQ_EMPTY.
 *	getnewbuf() by default will always select a buffer from the BQ_EMPTY.
 *		getnewbuf() perfoms best if a buffer was found there.
 *		Also this minimizes the possibility of starting IO
 *		from getnewbuf(). That's a performance win, too.
 *
 *	Localize complex logic [balancing as well as time aging]
 *		to balancebufq().
 *
 *	Simplify getnewbuf() logic by elimination of time aging code.
 */

/* 
 * Algorithm:
 * -----------
 * The goal of the dynamic scaling of the buffer queues to to keep
 * the size of the LRU close to bl_target. Buffers on a queue would
 * be time aged.
 *
 * There would be a thread which will be responsible for "balancing"
 * the buffer cache queues.
 *
 * The scan order would be:	AGE, LRU, META, EMPTY.
 */

long bufqscanwait = 0;

static void bufqscan_thread();
static int balancebufq(int q);
static int btrimempty(int n);
static __inline__ int initbufqscan(void);
static __inline__ int nextbufq(int q);
static void buqlimprt(int all);


static __inline__ void
bufqinc(int q)
{
	if ((q < 0) || (q >= BQUEUES))
		return;

	bufqlim[q].bl_num++;
	return;
}

static __inline__ void
bufqdec(int q)
{
	if ((q < 0) || (q >= BQUEUES))
		return; 

	bufqlim[q].bl_num--;
	return;
}

static void
bufq_balance_thread_init(void)
{
	thread_t	thread = THREAD_NULL;

	if (bufqscanwait++ == 0) {

		/* Initalize globals */
		MAXNBUF = (sane_size / PAGE_SIZE);
		nbufh = nbuf_headers;
		nbuflow = min(nbufh, 100);
		nbufhigh = min(MAXNBUF, max(nbufh, 2048));
		nbuftarget = (sane_size >> 5) / PAGE_SIZE;
		nbuftarget = max(nbuflow, nbuftarget);
		nbuftarget = min(nbufhigh, nbuftarget);

		/*
		 * Initialize the bufqlim 
		 */ 

		/* LOCKED queue */
		bufqlim[BQ_LOCKED].bl_nlow = 0;
		bufqlim[BQ_LOCKED].bl_nlhigh = 32;
		bufqlim[BQ_LOCKED].bl_target = 0;
		bufqlim[BQ_LOCKED].bl_stale = 30;

		/* LRU queue */
		bufqlim[BQ_LRU].bl_nlow = 0;
		bufqlim[BQ_LRU].bl_nlhigh = nbufhigh/4;
		bufqlim[BQ_LRU].bl_target = nbuftarget/4;
		bufqlim[BQ_LRU].bl_stale = LRU_IS_STALE;

		/* AGE queue */
		bufqlim[BQ_AGE].bl_nlow = 0;
		bufqlim[BQ_AGE].bl_nlhigh = nbufhigh/4;
		bufqlim[BQ_AGE].bl_target = nbuftarget/4;
		bufqlim[BQ_AGE].bl_stale = AGE_IS_STALE;

		/* EMPTY queue */
		bufqlim[BQ_EMPTY].bl_nlow = 0;
		bufqlim[BQ_EMPTY].bl_nlhigh = nbufhigh/4;
		bufqlim[BQ_EMPTY].bl_target = nbuftarget/4;
		bufqlim[BQ_EMPTY].bl_stale = 600000;

		/* META queue */
		bufqlim[BQ_META].bl_nlow = 0;
		bufqlim[BQ_META].bl_nlhigh = nbufhigh/4;
		bufqlim[BQ_META].bl_target = nbuftarget/4;
		bufqlim[BQ_META].bl_stale = META_IS_STALE;

		/* LAUNDRY queue */
		bufqlim[BQ_LOCKED].bl_nlow = 0;
		bufqlim[BQ_LOCKED].bl_nlhigh = 32;
		bufqlim[BQ_LOCKED].bl_target = 0;
		bufqlim[BQ_LOCKED].bl_stale = 30;

		buqlimprt(1);
	}

	/* create worker thread */
	kernel_thread_start((thread_continue_t)bufqscan_thread, NULL, &thread);
	thread_deallocate(thread);
}

/* The workloop for the buffer balancing thread */
static void
bufqscan_thread()
{
	int moretodo = 0;

	for(;;) {
		do {
			int q;	/* buffer queue to process */
		
			q = initbufqscan();
			for (; q; ) {
				moretodo |= balancebufq(q);
				q = nextbufq(q);
			}
		} while (moretodo);

#if DIAGNOSTIC
		vfs_bufstats();
		buqlimprt(0);
#endif
		(void)tsleep((void *)&bufqscanwait, PRIBIO, "bufqscanwait", 60 * hz);
		moretodo = 0;
	}
}

/* Seed for the buffer queue balancing */
static __inline__ int
initbufqscan()
{
	/* Start with AGE queue */
	return (BQ_AGE);
}

/* Pick next buffer queue to balance */
static __inline__ int
nextbufq(int q)
{
	int order[] = { BQ_AGE, BQ_LRU, BQ_META, BQ_EMPTY, 0 };
	
	q++;
	q %= sizeof(order);
	return (order[q]);
}

/* function to balance the buffer queues */
static int
balancebufq(int q)
{
	int moretodo = 0;
	int n, t;
	
	/* reject invalid q */
	if ((q < 0) || (q >= BQUEUES))
		goto out;

	/* LOCKED or LAUNDRY queue MUST not be balanced */
	if ((q == BQ_LOCKED) || (q == BQ_LAUNDRY))
		goto out;

	n = (bufqlim[q].bl_num - bufqlim[q].bl_target);

	/* If queue has less than target nothing more to do */
	if (n < 0)
		goto out;

	if ( n > 8 ) {
		/* Balance only a small amount (12.5%) at a time */
		n >>= 3;
	}

	/* EMPTY queue needs special handling */
	if (q == BQ_EMPTY) {
		moretodo |= btrimempty(n);
		goto out;
	}

	t = buf_timestamp():
	
	for (; n > 0; n--) {
		struct buf *bp = bufqueues[q].tqh_first;
		if (!bp)
			break;
		
		/* check if it's stale */
		if ((t - bp->b_timestamp) > bufqlim[q].bl_stale) {
			if (bcleanbuf(bp, FALSE)) {
				/* buf_bawrite() issued, bp not ready */
				moretodo = 1;
			} else {
				/* release the cleaned buffer to BQ_EMPTY */
				SET(bp->b_flags, B_INVAL);
				buf_brelse(bp);
			}
		} else
			break;		
	}

out:
	return (moretodo);		
}

static int
btrimempty(int n)
{
	/*
	 * When struct buf are allocated dynamically, this would
	 * reclaim upto 'n' struct buf from the empty queue.
	 */
	 
	 return (0);
}

static void
buqlimprt(int all)
{
	int i;
    static char *bname[BQUEUES] =
		{ "LOCKED", "LRU", "AGE", "EMPTY", "META", "LAUNDRY" };

	if (all)
		for (i = 0; i < BQUEUES; i++) {
			printf("%s : ", bname[i]);
			printf("min = %ld, ", (long)bufqlim[i].bl_nlow);
			printf("cur = %ld, ", (long)bufqlim[i].bl_num);
			printf("max = %ld, ", (long)bufqlim[i].bl_nlhigh);
			printf("target = %ld, ", (long)bufqlim[i].bl_target);
			printf("stale after %ld seconds\n", bufqlim[i].bl_stale);
		}
	else
		for (i = 0; i < BQUEUES; i++) {
			printf("%s : ", bname[i]);
			printf("cur = %ld, ", (long)bufqlim[i].bl_num);
		}
}

#endif


