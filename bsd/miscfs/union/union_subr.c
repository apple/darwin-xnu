/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
 * Copyright (c) 1994 Jan-Simon Pendry
 * Copyright (c) 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Jan-Simon Pendry.
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
 *	@(#)union_subr.c	8.20 (Berkeley) 5/20/95
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/vnode_internal.h>
#include <sys/namei.h>
#include <sys/malloc.h>
#include <sys/file_internal.h>
#include <sys/filedesc.h>
#include <sys/queue.h>
#include <sys/mount_internal.h>
#include <sys/stat.h>
#include <sys/ubc.h>
#include <sys/uio_internal.h>
#include <miscfs/union/union.h>
#include <sys/lock.h>
#include <sys/kdebug.h>
#if CONFIG_MACF
#include <security/mac_framework.h>
#endif


static int union_vn_close(struct vnode *vp, int fmode, vfs_context_t ctx);

/* must be power of two, otherwise change UNION_HASH() */
#define NHASH 32

/* unsigned int ... */
#define UNION_HASH(u, l) \
	(((((unsigned long) (u)) + ((unsigned long) l)) >> 8) & (NHASH-1))

static LIST_HEAD(unhead, union_node) unhead[NHASH];
static int unvplock[NHASH];

static lck_grp_t * union_lck_grp;
static lck_grp_attr_t * union_lck_grp_attr;
static lck_attr_t * union_lck_attr;
static lck_mtx_t *  union_mtxp;

static int union_dircheck(struct vnode **, struct fileproc *, vfs_context_t ctx);
static void union_newlower(struct union_node *, struct vnode *);
static void union_newupper(struct union_node *, struct vnode *);


int
union_init(__unused struct vfsconf *vfsp)
{
	int i;

	union_lck_grp_attr= lck_grp_attr_alloc_init();
#if DIAGNOSTIC
	lck_grp_attr_setstat(union_lck_grp_attr);
#endif
	union_lck_grp = lck_grp_alloc_init("union",  union_lck_grp_attr);
	union_lck_attr = lck_attr_alloc_init();
#if DIAGNOSTIC
	lck_attr_setdebug(union_lck_attr);
#endif
	union_mtxp = lck_mtx_alloc_init(union_lck_grp, union_lck_attr);

	for (i = 0; i < NHASH; i++)
		LIST_INIT(&unhead[i]);
	bzero((caddr_t) unvplock, sizeof(unvplock));
	/* add the hook for getdirentries */
	union_dircheckp = union_dircheck;
	
	return (0);
}

void
union_lock()
{
	lck_mtx_lock(union_mtxp);
}

void
union_unlock()
{
	lck_mtx_unlock(union_mtxp);
}


static int
union_list_lock(int ix)
{

	if (unvplock[ix] & UNVP_LOCKED) {
		unvplock[ix] |= UNVP_WANT;
		msleep((caddr_t) &unvplock[ix], union_mtxp, PINOD, "union_list_lock", NULL);
		return (1);
	}

	unvplock[ix] |= UNVP_LOCKED;

	return (0);
}

static void
union_list_unlock(int ix)
{

	unvplock[ix] &= ~UNVP_LOCKED;

	if (unvplock[ix] & UNVP_WANT) {
		unvplock[ix] &= ~UNVP_WANT;
		wakeup((caddr_t) &unvplock[ix]);
	}
}

/*
 *	union_updatevp:
 *
 *	The uppervp, if not NULL, must be referenced and not locked by us
 *	The lowervp, if not NULL, must be referenced.
 *
 *	If uppervp and lowervp match pointers already installed, then
 *	nothing happens. The passed vp's (when matching) are not adjusted.
 *
 *	This routine may only be called by union_newupper() and
 *	union_newlower().
 */

/* always called with union lock held */
void
union_updatevp(struct union_node *un, struct vnode *uppervp,
		struct vnode *lowervp)
{
	int ohash = UNION_HASH(un->un_uppervp, un->un_lowervp);
	int nhash = UNION_HASH(uppervp, lowervp);
	int docache = (lowervp != NULLVP || uppervp != NULLVP);
	int lhash, uhash;
	vnode_t freevp;
	vnode_t freedirvp;
	caddr_t freepath;

	/*
	 * Ensure locking is ordered from lower to higher
	 * to avoid deadlocks.
	 */
	if (nhash < ohash) {
		lhash = nhash;
		uhash = ohash;
	} else {
		lhash = ohash;
		uhash = nhash;
	}

	if (lhash != uhash) {
		while (union_list_lock(lhash))
			continue;
	}

	while (union_list_lock(uhash))
		continue;

	if (ohash != nhash || !docache) {
		if (un->un_flags & UN_CACHED) {
			un->un_flags &= ~UN_CACHED;
			LIST_REMOVE(un, un_cache);
		}
	}

	if (ohash != nhash)
		union_list_unlock(ohash);

	if (un->un_lowervp != lowervp) {
		freevp = freedirvp = NULLVP;
		freepath = (caddr_t)0;
		if (un->un_lowervp) {
			freevp = un->un_lowervp;
			un->un_lowervp = lowervp;
			if (un->un_path) {
				freepath = un->un_path; 
				un->un_path = 0;
			}
			if (un->un_dirvp) {
				freedirvp = un->un_dirvp;
				un->un_dirvp = NULLVP;
			}
			union_unlock();
			if (freevp)
				vnode_put(freevp);
			if (freedirvp)
				vnode_put(freedirvp);
			if (freepath)
				_FREE(un->un_path, M_TEMP);
			union_lock();
		} else 
			un->un_lowervp = lowervp;
		if (lowervp != NULLVP)
			un->un_lowervid = vnode_vid(lowervp);
		un->un_lowersz = VNOVAL;
	}

	if (un->un_uppervp != uppervp) {
		freevp = NULLVP;
		if (un->un_uppervp) {
			freevp = un->un_uppervp;
		}
		un->un_uppervp = uppervp;
		if (uppervp != NULLVP)
			un->un_uppervid = vnode_vid(uppervp);
		un->un_uppersz = VNOVAL;
		union_unlock();
		if (freevp)
			vnode_put(freevp);
		union_lock();
	}

	if (docache && (ohash != nhash)) {
		LIST_INSERT_HEAD(&unhead[nhash], un, un_cache);
		un->un_flags |= UN_CACHED;
	}

	union_list_unlock(nhash);
}

/*
 * Set a new lowervp.  The passed lowervp must be referenced and will be
 * stored in the vp in a referenced state. 
 */
/* always called with union lock held */

static void
union_newlower(un, lowervp)
	struct union_node *un;
	struct vnode *lowervp;
{
	union_updatevp(un, un->un_uppervp, lowervp);
}

/*
 * Set a new uppervp.  The passed uppervp must be locked and will be 
 * stored in the vp in a locked state.  The caller should not unlock
 * uppervp.
 */

/* always called with union lock held */
static void
union_newupper(un, uppervp)
	struct union_node *un;
	struct vnode *uppervp;
{
	union_updatevp(un, uppervp, un->un_lowervp);
}

/*
 * Keep track of size changes in the underlying vnodes.
 * If the size changes, then callback to the vm layer
 * giving priority to the upper layer size.
 */
/* always called with union lock held */
void
union_newsize(vp, uppersz, lowersz)
	struct vnode *vp;
	off_t uppersz, lowersz;
{
	struct union_node *un;
	off_t sz;

	/* only interested in regular files */
	if (vp->v_type != VREG)
		return;

	un = VTOUNION(vp);
	sz = VNOVAL;

	if ((uppersz != VNOVAL) && (un->un_uppersz != uppersz)) {
		un->un_uppersz = uppersz;
		if (sz == VNOVAL)
			sz = un->un_uppersz;
	}

	if ((lowersz != VNOVAL) && (un->un_lowersz != lowersz)) {
		un->un_lowersz = lowersz;
		if (sz == VNOVAL)
			sz = un->un_lowersz;
	}

	if (sz != VNOVAL) {
#ifdef UNION_DIAGNOSTIC
		printf("union: %s size now %ld\n",
			uppersz != VNOVAL ? "upper" : "lower", (long) sz);
#endif
		union_unlock();
		ubc_setsize(vp, sz);
		union_lock();
	}
}

/*
 *	union_allocvp:	allocate a union_node and associate it with a
 *			parent union_node and one or two vnodes.
 *
 *	vpp	Holds the returned vnode locked and referenced if no 
 *		error occurs.
 *
 *	mp	Holds the mount point.  mp may or may not be busied. 
 *		allocvp() makes no changes to mp.
 *
 *	dvp	Holds the parent union_node to the one we wish to create.
 *		XXX may only be used to traverse an uncopied lowervp-based
 *		tree?  XXX
 *
 *		dvp may or may not be locked.  allocvp() makes no changes
 *		to dvp.
 *
 *	upperdvp Holds the parent vnode to uppervp, generally used along
 *		with path component information to create a shadow of
 *		lowervp when uppervp does not exist.
 *
 *		upperdvp is referenced but unlocked on entry, and will be
 *		dereferenced on return.
 *
 *	uppervp	Holds the new uppervp vnode to be stored in the 
 *		union_node we are allocating.  uppervp is referenced but
 *		not locked, and will be dereferenced on return.
 *
 *	lowervp	Holds the new lowervp vnode to be stored in the
 *		union_node we are allocating.  lowervp is referenced but
 *		not locked, and will be dereferenced on return.
 * 
 *	cnp	Holds path component information to be coupled with
 *		lowervp and upperdvp to allow unionfs to create an uppervp
 *		later on.  Only used if lowervp is valid.  The contents
 *		of cnp is only valid for the duration of the call.
 *
 *	docache	Determine whether this node should be entered in the
 *		cache or whether it should be destroyed as soon as possible.
 *
 * All union_nodes are maintained on a singly-linked
 * list.  New nodes are only allocated when they cannot
 * be found on this list.  Entries on the list are
 * removed when the vfs reclaim entry is called.
 *
 * A single lock is kept for the entire list.  This is
 * needed because the getnewvnode() function can block
 * waiting for a vnode to become free, in which case there
 * may be more than one process trying to get the same
 * vnode.  This lock is only taken if we are going to
 * call getnewvnode(), since the kernel itself is single-threaded.
 *
 * If an entry is found on the list, then call vget() to
 * take a reference.  This is done because there may be
 * zero references to it and so it needs to removed from
 * the vnode free list.
 */

/* always called with union lock held */

int
union_allocvp(struct vnode **vpp,
	struct mount *mp,
	struct vnode *undvp,
	struct vnode *dvp,
	struct componentname *cnp,
	struct vnode *uppervp,
	struct vnode *lowervp,
	int docache)
{
	int error;
	struct union_node *un = NULL;
	struct union_node *unp;
	struct vnode *xlowervp = NULLVP;
	struct union_mount *um = MOUNTTOUNIONMOUNT(mp);
	int hash = 0;		/* protected by docache */
	int markroot;
	int try;
	struct vnode_fsparam vfsp;
	enum vtype vtype;

	if (uppervp == NULLVP && lowervp == NULLVP)
		panic("union: unidentifiable allocation");

	/*
	 * if both upper and lower vp are provided and are off different type
	 * consider lowervp as NULL
	 */
	if (uppervp && lowervp && (uppervp->v_type != lowervp->v_type)) {
		xlowervp = lowervp;
		lowervp = NULLVP;
	}

	/* detect the root vnode (and aliases) */
	markroot = 0;
	if ((uppervp == um->um_uppervp) &&
	    ((lowervp == NULLVP) || lowervp == um->um_lowervp)) {
		if (lowervp == NULLVP) {
			lowervp = um->um_lowervp;
			if (lowervp != NULLVP) {
				union_unlock();
				vnode_get(lowervp);
				union_lock();
			}
		}
		markroot = VROOT;
	}

loop:
	if (!docache) {
		un = NULL;
	} else for (try = 0; try < 3; try++) {
		switch (try) {
		case 0:
			if (lowervp == NULLVP)
				continue;
			hash = UNION_HASH(uppervp, lowervp);
			break;

		case 1:
			if (uppervp == NULLVP)
				continue;
			hash = UNION_HASH(uppervp, NULLVP);
			break;

		case 2:
			if (lowervp == NULLVP)
				continue;
			/* Not sure how this path gets exercised ? */
			hash = UNION_HASH(NULLVP, lowervp);
			break;
		}

		while (union_list_lock(hash))
			continue;

		for (un = unhead[hash].lh_first; un != 0;
					un = un->un_cache.le_next) {
			if ((un->un_lowervp == lowervp ||
			     un->un_lowervp == NULLVP) &&
			    (un->un_uppervp == uppervp ||
			     un->un_uppervp == NULLVP) &&
			    (un->un_mount == mp)) {
				break;
			}
		}

		union_list_unlock(hash);

		if (un)
			break;
	}

	if (un) {
		/*
		 * Obtain a lock on the union_node.
		 * uppervp is locked, though un->un_uppervp
		 * may not be.  this doesn't break the locking
		 * hierarchy since in the case that un->un_uppervp
		 * is not yet locked it will be vnode_put'd and replaced
		 * with uppervp.
		 */

		if (un->un_flags & UN_LOCKED) {
			un->un_flags |= UN_WANT;
			msleep((caddr_t) &un->un_flags, union_mtxp, PINOD, "union node locked", 0);
			goto loop;
		}       
		un->un_flags |= UN_LOCKED;
                        
		union_unlock();
		if (UNIONTOV(un) == NULLVP)
			panic("null vnode in union node\n");
		if (vnode_get(UNIONTOV(un))) {
			union_lock();
			un->un_flags &= ~UN_LOCKED;
			if ((un->un_flags & UN_WANT) == UN_WANT) {
				un->un_flags &=  ~UN_LOCKED;
				wakeup(&un->un_flags);
			}
			goto loop;
		}
		union_lock();

		/*
		 * At this point, the union_node is locked,
		 * un->un_uppervp may not be locked, and uppervp
		 * is locked or nil.
		 */

		/*
		 * Save information about the upper layer.
		 */
		if (uppervp != un->un_uppervp) {
			union_newupper(un, uppervp);
		} else if (uppervp) {
			union_unlock();
			vnode_put(uppervp);
			union_lock();
		}

		/*
		 * Save information about the lower layer.
		 * This needs to keep track of pathname
		 * and directory information which union_vn_create
		 * might need.
		 */
		if (lowervp != un->un_lowervp) {
			union_newlower(un, lowervp);
			if (cnp && (lowervp != NULLVP)) {
				un->un_hash = cnp->cn_hash;
				union_unlock();
				MALLOC(un->un_path, caddr_t, cnp->cn_namelen+1,
						M_TEMP, M_WAITOK);
				bcopy(cnp->cn_nameptr, un->un_path,
						cnp->cn_namelen);
				vnode_get(dvp);
				union_lock();
				un->un_path[cnp->cn_namelen] = '\0';
				un->un_dirvp = dvp;
			}
		} else if (lowervp) {
			union_unlock();
			vnode_put(lowervp);
			union_lock();
		}
		*vpp = UNIONTOV(un);
		un->un_flags &= ~UN_LOCKED;
		if ((un->un_flags & UN_WANT) == UN_WANT) {
			un->un_flags &= ~UN_WANT;
			wakeup(&un->un_flags);
		}
		return (0);
	}

	if (docache) {
		/*
		 * otherwise lock the vp list while we call getnewvnode
		 * since that can block.
		 */ 
		hash = UNION_HASH(uppervp, lowervp);

		if (union_list_lock(hash))
			goto loop;
	}

	union_unlock();
	MALLOC(unp, void *, sizeof(struct union_node), M_TEMP, M_WAITOK);
	union_lock();

	bzero(unp, sizeof(struct union_node));
	un = unp;
	un->un_uppervp = uppervp;
	if (uppervp != NULLVP)
		un->un_uppervid = vnode_vid(uppervp);
	un->un_uppersz = VNOVAL;
	un->un_lowervp = lowervp;
	if (lowervp != NULLVP)
		un->un_lowervid = vnode_vid(lowervp);
	un->un_lowersz = VNOVAL;
	un->un_pvp = undvp;
	if (undvp != NULLVP)
		vnode_get(undvp);
	un->un_dircache = 0;
	un->un_openl = 0;
	un->un_mount = mp;
	un->un_flags = UN_LOCKED;
#ifdef FAULTFS
	if (UNION_FAULTIN(um))
		un->un_flags |= UN_FAULTFS;
#endif

	if (docache) {
		/* Insert with lock held */
		LIST_INSERT_HEAD(&unhead[hash], un, un_cache);
		un->un_flags |= UN_CACHED;
		union_list_unlock(hash);
	}

	union_unlock();

	if (uppervp)
		vtype = uppervp->v_type;
	else
		vtype = lowervp->v_type;

	bzero(&vfsp, sizeof(struct vnode_fsparam));
	vfsp.vnfs_mp = mp;
	vfsp.vnfs_vtype = vtype;
	vfsp.vnfs_str = "unionfs";
	vfsp.vnfs_dvp = undvp;
	vfsp.vnfs_fsnode = unp;
	vfsp.vnfs_cnp = cnp;
	vfsp.vnfs_vops = union_vnodeop_p;
	vfsp.vnfs_rdev = 0;
	vfsp.vnfs_filesize = 0;
	vfsp.vnfs_flags = VNFS_NOCACHE | VNFS_CANTCACHE;
	vfsp.vnfs_marksystem = 0;
	vfsp.vnfs_markroot = markroot;

	error = vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &vfsp, vpp);
	if (error) {
		/*  XXXXX Is this right ????  XXXXXXX */
		if (uppervp) {
		        vnode_put(uppervp);
		}
		if (lowervp)
			vnode_put(lowervp);

		union_lock();
		if (un->un_flags & UN_CACHED) {
			un->un_flags &= ~UN_CACHED;
			LIST_REMOVE(un, un_cache);
		}
		if (docache)
			union_list_unlock(hash);

		FREE(unp, M_TEMP);

		return (error);
	}

	if (cnp && (lowervp != NULLVP)) {
		un->un_hash = cnp->cn_hash;
		un->un_path = _MALLOC(cnp->cn_namelen+1, M_TEMP, M_WAITOK);
		bcopy(cnp->cn_nameptr, un->un_path, cnp->cn_namelen);
		un->un_path[cnp->cn_namelen] = '\0';
		vnode_get(dvp);
		un->un_dirvp = dvp;
	} else {
		un->un_hash = 0;
		un->un_path = 0;
		un->un_dirvp = 0;
	}

	if (xlowervp)
		vnode_put(xlowervp);

	union_lock();

	vnode_settag(*vpp, VT_UNION);
	un->un_vnode = *vpp;
	if (un->un_vnode->v_type == VDIR) {
		if (un->un_uppervp == NULLVP) {
			panic("faulting fs and no upper vp for dir?");
		}

	}


	un->un_flags &= ~UN_LOCKED;
	if ((un->un_flags & UN_WANT) == UN_WANT) {
		un->un_flags &=  ~UN_WANT;
		wakeup(&un->un_flags);
	} 

	return(error);

}

/* always called with union lock held */
int
union_freevp(struct vnode *vp)
{
	struct union_node *un = VTOUNION(vp);

	if (un->un_flags & UN_CACHED) {
		un->un_flags &= ~UN_CACHED;
		LIST_REMOVE(un, un_cache);
	}

	union_unlock();
	if (un->un_pvp != NULLVP)
		vnode_put(un->un_pvp);
	if (un->un_uppervp != NULLVP)
		vnode_put(un->un_uppervp);
	if (un->un_lowervp != NULLVP)
		vnode_put(un->un_lowervp);
	if (un->un_dirvp != NULLVP)
		vnode_put(un->un_dirvp);
	if (un->un_path)
		_FREE(un->un_path, M_TEMP);

	FREE(vp->v_data, M_TEMP);
	vp->v_data = 0;
	union_lock();

	return (0);
}

/*
 * copyfile.  copy the vnode (fvp) to the vnode (tvp)
 * using a sequence of reads and writes.  both (fvp)
 * and (tvp) are locked on entry and exit.
 */
/* called with no union lock held */
int
union_copyfile(struct vnode *fvp, struct vnode *tvp, vfs_context_t context)
{
	char *bufp;
	struct uio uio;
	struct iovec_32 iov;
	int error = 0;

	/*
	 * strategy:
	 * allocate a buffer of size MAXPHYSIO.
	 * loop doing reads and writes, keeping track
	 * of the current uio offset.
	 * give up at the first sign of trouble.
	 */


#if 1   /* LP64todo - can't use new segment flags until the drivers are ready */
	uio.uio_segflg = UIO_SYSSPACE;
#else
	uio.uio_segflg = UIO_SYSSPACE32;
#endif 
	uio.uio_offset = 0;

	bufp = _MALLOC(MAXPHYSIO, M_TEMP, M_WAITOK);

	/* ugly loop follows... */
	do {
		off_t offset = uio.uio_offset;

		uio.uio_iovs.iov32p = &iov;
		uio.uio_iovcnt = 1;
		iov.iov_base = (uintptr_t)bufp;
		iov.iov_len = MAXPHYSIO;
		uio_setresid(&uio, iov.iov_len);
		uio.uio_rw = UIO_READ;
		error = VNOP_READ(fvp, &uio, 0, context);

		if (error == 0) {
			uio.uio_iovs.iov32p = &iov;
			uio.uio_iovcnt = 1;
			iov.iov_base = (uintptr_t)bufp;
			iov.iov_len = MAXPHYSIO - uio_resid(&uio);
			uio.uio_offset = offset;
			uio.uio_rw = UIO_WRITE;
			uio_setresid(&uio, iov.iov_len);

			if (uio_resid(&uio) == 0)
				break;

			do {
				error = VNOP_WRITE(tvp, &uio, 0, context);
			} while ((uio_resid(&uio) > 0) && (error == 0));
		}

	} while (error == 0);

	_FREE(bufp, M_TEMP);
	return (error);
}

/*
 * (un) is assumed to be locked on entry and remains
 * locked on exit.
 */
/* always called with union lock held */
int
union_copyup(struct union_node *un, int docopy, vfs_context_t context)
{
	int error;
	struct vnode *lvp, *uvp;
	struct vnode_attr vattr;
	mode_t  cmode = 0;

	
	lvp = un->un_lowervp;

	union_unlock();

	if (UNNODE_FAULTIN(un)) {
		/* Need to inherit exec mode in faulting fs */
		VATTR_INIT(&vattr);
		VATTR_WANTED(&vattr, va_flags);
		if (vnode_getattr(lvp, &vattr, context) == 0 )
			cmode = vattr.va_mode;
		
	}
	error = union_vn_create(&uvp, un, cmode, context);
	if (error) {
		union_lock();
		if (error == EEXIST) {
			if (uvp != NULLVP) {
				union_newupper(un, uvp);
				error = 0;	
			} 
		}
		return (error);
	}

	union_lock();
	/* at this point, uppervp is locked */
	union_newupper(un, uvp);
	union_unlock();


	if (docopy) {
		/*
		 * XX - should not ignore errors
		 * from vnop_close
		 */
		error = VNOP_OPEN(lvp, FREAD, context);
		if (error == 0) {
			error = union_copyfile(lvp, uvp, context);
			(void) VNOP_CLOSE(lvp, FREAD, context);
		}
#ifdef UNION_DIAGNOSTIC
		if (error == 0)
			uprintf("union: copied up %s\n", un->un_path);
#endif

	}
	union_vn_close(uvp, FWRITE, context);

	/*
	 * Subsequent IOs will go to the top layer, so
	 * call close on the lower vnode and open on the
	 * upper vnode to ensure that the filesystem keeps
	 * its references counts right.  This doesn't do
	 * the right thing with (cred) and (FREAD) though.
	 * Ignoring error returns is not right, either.
	 */

	/* No need to hold the lock as the union node should be locked for this(it is in faultin mode) */
	if (error == 0) {
		int i;

		for (i = 0; i < un->un_openl; i++) {
			(void) VNOP_CLOSE(lvp, FREAD, context);
			(void) VNOP_OPEN(uvp, FREAD, context);
		}
		un->un_openl = 0;
	}

	union_lock();

	return (error);

}


int 
union_faultin_copyup(struct vnode **vpp, vnode_t udvp, vnode_t lvp, struct componentname * cnp, vfs_context_t context)
{
	int error;
	struct vnode *uvp;
	struct vnode_attr vattr;
	struct vnode_attr *vap;
	mode_t  cmode = 0;
	int fmode = FFLAGS(O_WRONLY|O_CREAT|O_TRUNC|O_EXCL);
	struct proc * p = vfs_context_proc(context);
	struct componentname cn;
	

	vap = &vattr;
	VATTR_INIT(vap);
	VATTR_WANTED(vap, va_flags);
	if (vnode_getattr(lvp, vap, context) == 0 )
		cmode = vattr.va_mode;
		
	*vpp = NULLVP;


	if (cmode == (mode_t)0)
		cmode = UN_FILEMODE & ~p->p_fd->fd_cmask;
	else
		cmode = cmode & ~p->p_fd->fd_cmask;


	/*
	 * Build a new componentname structure (for the same
	 * reasons outlines in union_mkshadow()).
	 * The difference here is that the file is owned by
	 * the current user, rather than by the person who
	 * did the mount, since the current user needs to be
	 * able to write the file (that's why it is being
	 * copied in the first place).
	 */
	bzero(&cn, sizeof(struct componentname));

	cn.cn_namelen = cnp->cn_namelen;
	cn.cn_pnbuf = (caddr_t) _MALLOC_ZONE(cn.cn_namelen+1,
						M_NAMEI, M_WAITOK);
	cn.cn_pnlen = cn.cn_namelen+1;
	bcopy(cnp->cn_nameptr, cn.cn_pnbuf, cn.cn_namelen+1);
	cn.cn_nameiop = CREATE;
	cn.cn_flags = (HASBUF|SAVENAME|SAVESTART|ISLASTCN|UNIONCREATED);
	cn.cn_context = context;
	cn.cn_nameptr = cn.cn_pnbuf;
	cn.cn_hash = 0;
	cn.cn_consume = 0;

	/*
	 * Pass dvp unlocked and referenced on call to relookup().
	 *
	 * If an error occurs, dvp will be returned unlocked and dereferenced.
	 */
	if ((error = relookup(udvp, &uvp, &cn)) != 0) {
		goto out;
	}

	/*
	 * If no error occurs, dvp will be returned locked with the reference
	 * left as before, and vpp will be returned referenced and locked.
	 */
	if (uvp) {
		*vpp = uvp;
		error = EEXIST;
		goto out;
	}

	/*
	 * Good - there was no race to create the file
	 * so go ahead and create it.  The permissions
	 * on the file will be 0666 modified by the
	 * current user's umask.  Access to the file, while
	 * it is unioned, will require access to the top *and*
	 * bottom files.  Access when not unioned will simply
	 * require access to the top-level file.
	 *
	 * TODO: confirm choice of access permissions.
	 *       decide on authorisation behaviour
	 */
	
	VATTR_INIT(vap);
	VATTR_SET(vap, va_type, VREG);
	VATTR_SET(vap, va_mode, cmode);

	cn.cn_flags |= (UNIONCREATED);
	if ((error = vn_create(udvp, &uvp, &cn, vap, 0, context)) != 0) {
		goto out;
	}

	
	if ((error = VNOP_OPEN(uvp, fmode, context)) != 0) {
		vn_clearunionwait(uvp, 0);
		vnode_recycle(uvp);
		vnode_put(uvp);
		goto out;
	}

	error = vnode_ref_ext(uvp, fmode);
	if (error ) {
		vn_clearunionwait(uvp, 0);
		VNOP_CLOSE(uvp, fmode, context);
		vnode_recycle(uvp);
		vnode_put(uvp);
		goto out;
	}


	/*
	 * XX - should not ignore errors
	 * from vnop_close
	 */
	error = VNOP_OPEN(lvp, FREAD, context);
	if (error == 0) {
		error = union_copyfile(lvp, uvp, context);
		(void) VNOP_CLOSE(lvp, FREAD, context);
	}

	VNOP_CLOSE(uvp, fmode, context);
	vnode_rele_ext(uvp, fmode, 0);
	vn_clearunionwait(uvp, 0);

	*vpp = uvp;
out:
	if ((cn.cn_flags & HASBUF) == HASBUF) {
		FREE_ZONE(cn.cn_pnbuf, cn.cn_pnlen, M_NAMEI);
		cn.cn_flags &= ~HASBUF;
	}
	return (error);
}


/*
 *	union_relookup:
 *
 *	dvp should be locked on entry and will be locked on return.  No
 *	net change in the ref count will occur.
 *
 *	If an error is returned, *vpp will be invalid, otherwise it
 *	will hold a locked, referenced vnode.  If *vpp == dvp then
 *	remember that only one exclusive lock is held.
 */

/* No union lock held for this call */
static int
union_relookup(
#ifdef XXX_HELP_ME
	struct union_mount *um,
#else	/* !XXX_HELP_ME */
	__unused struct union_mount *um,
#endif	/* !XXX_HELP_ME */
	struct vnode *dvp,
	struct vnode **vpp,
	struct componentname *cnp,
	struct componentname *cn,
	char *path,
	int pathlen)
{
	int error;

	/*
	 * A new componentname structure must be faked up because
	 * there is no way to know where the upper level cnp came
	 * from or what it is being used for.  This must duplicate
	 * some of the work done by NDINIT, some of the work done
	 * by namei, some of the work done by lookup and some of
	 * the work done by vnop_lookup when given a CREATE flag.
	 * Conclusion: Horrible.
	 */
	cn->cn_namelen = pathlen;
	cn->cn_pnbuf = _MALLOC_ZONE(cn->cn_namelen+1, M_NAMEI, M_WAITOK);
	cn->cn_pnlen = cn->cn_namelen+1;
	bcopy(path, cn->cn_pnbuf, cn->cn_namelen);
	cn->cn_pnbuf[cn->cn_namelen] = '\0';

	cn->cn_nameiop = CREATE;
	cn->cn_flags = (HASBUF|SAVENAME|SAVESTART|ISLASTCN );
#ifdef XXX_HELP_ME
	cn->cn_proc = cnp->cn_proc;
	if (um->um_op == UNMNT_ABOVE)
		cn->cn_cred = cnp->cn_cred;
	else
		cn->cn_cred = um->um_cred;
#endif
	cn->cn_context = cnp->cn_context;	/* XXX !UNMNT_ABOVE  case ??? */
	cn->cn_nameptr = cn->cn_pnbuf;
	cn->cn_hash = 0;
	cn->cn_consume = cnp->cn_consume;

	vnode_get(dvp);
	error = relookup(dvp, vpp, cn);
	vnode_put(dvp);

	return (error);
}

/*
 * Create a shadow directory in the upper layer.
 * The new vnode is returned locked.
 *
 * (um) points to the union mount structure for access to the
 * the mounting process's credentials.
 * (dvp) is the directory in which to create the shadow directory,
 * It is locked (but not ref'd) on entry and return.
 * (cnp) is the component name to be created.
 * (vpp) is the returned newly created shadow directory, which
 * is returned locked and ref'd
 */
/* No union lock held for this call */
int
union_mkshadow(um, dvp, cnp, vpp)
	struct union_mount *um;
	struct vnode *dvp;
	struct componentname *cnp;
	struct vnode **vpp;
{
	int error;
	struct vnode_attr va;
	struct componentname cn;

	bzero(&cn, sizeof(struct componentname));


	error = union_relookup(um, dvp, vpp, cnp, &cn,
			cnp->cn_nameptr, cnp->cn_namelen);
	if (error) 
		goto out;

	if (*vpp) {
		error = EEXIST;
		goto out;
	}

	/*
	 * Policy: when creating the shadow directory in the
	 * upper layer, create it owned by the user who did
	 * the mount, group from parent directory, and mode
	 * 777 modified by umask (ie mostly identical to the
	 * mkdir syscall).  (jsp, kb)
	 */

	VATTR_INIT(&va);
	VATTR_SET(&va, va_type, VDIR);
	VATTR_SET(&va, va_mode, um->um_cmode);

	error = vn_create(dvp, vpp, &cn, &va, 0, cnp->cn_context);
out:
	if ((cn.cn_flags & HASBUF) == HASBUF) {
		FREE_ZONE(cn.cn_pnbuf, cn.cn_pnlen, M_NAMEI);
		cn.cn_flags &= ~HASBUF;
	}
	return (error);
}

/*
 * Create a whiteout entry in the upper layer.
 *
 * (um) points to the union mount structure for access to the
 * the mounting process's credentials.
 * (dvp) is the directory in which to create the whiteout.
 * it is locked on entry and exit.
 * (cnp) is the componentname to be created.
 */
/* No union lock held for this call */
int
union_mkwhiteout(um, dvp, cnp, path)
	struct union_mount *um;
	struct vnode *dvp;
	struct componentname *cnp;
	char *path;
{
	int error;
	struct vnode *wvp;
	struct componentname cn;

	bzero(&cn, sizeof(struct componentname));

	error = union_relookup(um, dvp, &wvp, cnp, &cn, path, strlen(path));
	if (error) {
		goto out;
	}
	if (wvp) {
		error = EEXIST;
		goto out;
	}

	error = VNOP_WHITEOUT(dvp, &cn, CREATE, cnp->cn_context);

out:
	if ((cn.cn_flags & HASBUF) == HASBUF) {
		FREE_ZONE(cn.cn_pnbuf, cn.cn_pnlen, M_NAMEI);
		cn.cn_flags &= ~HASBUF;
	}
	return (error);
}


/*
 * union_vn_create: creates and opens a new shadow file
 * on the upper union layer.  This function is similar
 * in spirit to calling vn_open() but it avoids calling namei().
 * The problem with calling namei() is that a) it locks too many
 * things, and b) it doesn't start at the "right" directory,
 * whereas relookup() is told where to start.
 *
 * On entry, the vnode associated with un is locked.  It remains locked
 * on return.
 *
 * If no error occurs, *vpp contains a locked referenced vnode for your
 * use.  If an error occurs *vpp iis undefined.
 */
/* called with no union lock held */
int
union_vn_create(struct vnode **vpp, struct union_node *un, mode_t cmode, vfs_context_t  context)
{
	struct vnode *vp;
	struct vnode_attr vat;
	struct vnode_attr *vap = &vat;
	int fmode = FFLAGS(O_WRONLY|O_CREAT|O_TRUNC|O_EXCL);
	int error;
	struct proc * p = vfs_context_proc(context);
	struct componentname cn;

	bzero(&cn, sizeof(struct componentname));
	*vpp = NULLVP;

	if (cmode == (mode_t)0)
		cmode = UN_FILEMODE & ~p->p_fd->fd_cmask;
	else
		cmode = cmode & ~p->p_fd->fd_cmask;


	/*
	 * Build a new componentname structure (for the same
	 * reasons outlines in union_mkshadow()).
	 * The difference here is that the file is owned by
	 * the current user, rather than by the person who
	 * did the mount, since the current user needs to be
	 * able to write the file (that's why it is being
	 * copied in the first place).
	 */
	cn.cn_namelen = strlen(un->un_path);
	cn.cn_pnbuf = (caddr_t) _MALLOC_ZONE(cn.cn_namelen+1,
						M_NAMEI, M_WAITOK);
	cn.cn_pnlen = cn.cn_namelen+1;
	bcopy(un->un_path, cn.cn_pnbuf, cn.cn_namelen+1);
	cn.cn_nameiop = CREATE;
	if (UNNODE_FAULTIN(un))
		cn.cn_flags = (HASBUF|SAVENAME|SAVESTART|ISLASTCN|UNIONCREATED);
	else
		cn.cn_flags = (HASBUF|SAVENAME|SAVESTART|ISLASTCN);
	cn.cn_context = context;
	cn.cn_nameptr = cn.cn_pnbuf;
	cn.cn_hash = un->un_hash;
	cn.cn_consume = 0;

	/*
	 * Pass dvp unlocked and referenced on call to relookup().
	 *
	 * If an error occurs, dvp will be returned unlocked and dereferenced.
	 */
	vnode_get(un->un_dirvp);
	if ((error = relookup(un->un_dirvp, &vp, &cn)) != 0) {
		vnode_put(un->un_dirvp);
		goto out;
	}
	vnode_put(un->un_dirvp);

	/*
	 * If no error occurs, dvp will be returned locked with the reference
	 * left as before, and vpp will be returned referenced and locked.
	 */
	if (vp) {
		*vpp = vp;
		error = EEXIST;
		goto out;
	}

	/*
	 * Good - there was no race to create the file
	 * so go ahead and create it.  The permissions
	 * on the file will be 0666 modified by the
	 * current user's umask.  Access to the file, while
	 * it is unioned, will require access to the top *and*
	 * bottom files.  Access when not unioned will simply
	 * require access to the top-level file.
	 *
	 * TODO: confirm choice of access permissions.
	 *       decide on authorisation behaviour
	 */
	
	VATTR_INIT(vap);
	VATTR_SET(vap, va_type, VREG);
	VATTR_SET(vap, va_mode, cmode);

	if ((error = vn_create(un->un_dirvp, &vp, &cn, vap, 0, context)) != 0) {
		goto out;
	}

	if ((error = VNOP_OPEN(vp, fmode, context)) != 0) {
		vnode_put(vp);
		goto out;
	}

	vnode_lock(vp);
	if (++vp->v_writecount <= 0)
		panic("union: v_writecount");
	vnode_unlock(vp);
	*vpp = vp;
	error = 0;

out:
	if ((cn.cn_flags & HASBUF) == HASBUF) {
		FREE_ZONE(cn.cn_pnbuf, cn.cn_pnlen, M_NAMEI);
		cn.cn_flags &= ~HASBUF;
	}
	return(error);
}

/* called with no union lock held */
static int
union_vn_close(struct vnode *vp, int fmode, vfs_context_t context)
{

	if (fmode & FWRITE) {
		vnode_lock(vp);
		--vp->v_writecount;
		vnode_unlock(vp);
	}
	return (VNOP_CLOSE(vp, fmode, context));
}

/*
 *	union_removed_upper:
 *
 *	An upper-only file/directory has been removed; un-cache it so
 *	that unionfs vnode gets reclaimed and the last uppervp reference
 *	disappears.
 *
 *	Called with union_node unlocked.
 */
/* always called with union lock held */
void
union_removed_upper(un)
	struct union_node *un;
{
	union_newupper(un, NULLVP);
	if (un->un_flags & UN_CACHED) {
		un->un_flags &= ~UN_CACHED;
		LIST_REMOVE(un, un_cache);
	}

}

#if 0
struct vnode *
union_lowervp(vp)
	struct vnode *vp;
{
	struct union_node *un = VTOUNION(vp);

	if ((un->un_lowervp != NULLVP) &&
	    (vp->v_type == un->un_lowervp->v_type)) {
		if (vnode_get(un->un_lowervp) == 0)
			return (un->un_lowervp);
	}

	return (NULLVP);
}
#endif

/*
 * Determine whether a whiteout is needed
 * during a remove/rmdir operation.
 */
/* called with no union lock held */
int
union_dowhiteout(struct union_node *un, vfs_context_t ctx)
{
	struct vnode_attr va;

	if (UNNODE_FAULTIN(un))
		return(0);

	if ((un->un_lowervp != NULLVP) )
		return (1);

	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_flags);
	if (vnode_getattr(un->un_uppervp, &va, ctx) == 0 &&
	    (va.va_flags & OPAQUE))
		return (1);

	return (0);
}

/* called with no union lock held */
static void
union_dircache_r(struct vnode *vp, struct vnode ***vppp, int *cntp)
{
	struct union_node *un;

	if (vp->v_op != union_vnodeop_p) {
		if (vppp) {
			vnode_get(vp);
			*(*vppp)++ = vp;
			if (--(*cntp) == 0)
				panic("union: dircache table too small");
		} else {
			(*cntp)++;
		}

		return;
	}

	un = VTOUNION(vp);
	if (un->un_uppervp != NULLVP)
		union_dircache_r(un->un_uppervp, vppp, cntp);
	if (un->un_lowervp != NULLVP)
		union_dircache_r(un->un_lowervp, vppp, cntp);
}

/* called with no union lock held */
struct vnode *
union_dircache(struct vnode *vp, __unused vfs_context_t context)
{
	int count;
	struct vnode *nvp, *lvp;
	struct vnode **vpp;
	struct vnode **dircache, **newdircache;
	struct union_node *un;
	int error;
	int alloced = 0;

	union_lock();
	newdircache = NULL;

	nvp = NULLVP;
	un = VTOUNION(vp);

	dircache = un->un_dircache;
	if (dircache == 0) {
		union_unlock();
		count = 0;
		union_dircache_r(vp, 0, &count);
		count++;
#if 0
		/* too bad; we need Union now! */
#if MAC_XXX
                panic("MAC Framework doesn't support unionfs (yet)\n");
#endif /* MAC */
#endif

		dircache = (struct vnode **)
				_MALLOC(count * sizeof(struct vnode *),
					M_TEMP, M_WAITOK);
		newdircache = dircache;
		alloced = 1;
		vpp = dircache;
		union_dircache_r(vp, &vpp, &count);
		*vpp = NULLVP;
		vpp = dircache + 1;
		union_lock();
	} else {
		vpp = dircache;
		do {
			if (*vpp++ == un->un_uppervp)
				break;
		} while (*vpp != NULLVP);
	}

	lvp = *vpp;
	union_unlock();
	if (lvp == NULLVP) {
		goto out;
	}

	vnode_get(lvp);
	union_lock();

	error = union_allocvp(&nvp, vp->v_mount, NULLVP, NULLVP, 0, lvp, NULLVP, 0);
	if (error) {
		union_unlock();
		vnode_put(lvp);
		goto out;
	}

	un->un_dircache = 0;
	un = VTOUNION(nvp);
#if 0
	if ((alloced != 0) && (un->un_dircache != 0)) {
		union_unlock();
		for (vpp = newdircache; *vpp != NULLVP; vpp++)
			vnode_put(*vpp);
		_FREE(newdircache, M_TEMP);
		newdircache = NULL;
		union_lock();
		if (nvp != NULLVP)
			union_freevp(nvp);
		goto loop;
	}
#endif
	un->un_dircache = dircache;
	un->un_flags |= UN_DIRENVN;
	
	newdircache = NULL;
	union_unlock();
	return (nvp);

out:
	/*
	 * If we allocated a new dircache and couldn't attach
	 * it to a new vp, free the resources we allocated.
	 */
	if (newdircache) {
		for (vpp = newdircache; *vpp != NULLVP; vpp++)
			vnode_put(*vpp);
		_FREE(newdircache, M_TEMP);
	}
	return (NULLVP);
}

/*
 * Module glue to remove #ifdef UNION from vfs_syscalls.c
 */
/* Called with no union lock, the union_dircache takes locks when necessary */
static int
union_dircheck(struct vnode **vpp, struct fileproc *fp, vfs_context_t ctx)
{
	int error = 0;
	vnode_t vp = *vpp;
	
	if (vp->v_op == union_vnodeop_p) {
		struct vnode *lvp;

		lvp = union_dircache(vp, ctx);
		if (lvp != NULLVP) {
			struct vnode_attr va;
			/*
			 * If the directory is opaque,
			 * then don't show lower entries
			 */
			VATTR_INIT(&va);
			VATTR_WANTED(&va, va_flags);
			error = vnode_getattr(vp, &va, ctx);
			if (va.va_flags & OPAQUE) {
				vnode_put(lvp);
				lvp = NULL;
			}
		}

		if (lvp != NULLVP) {
#if CONFIG_MACF
			error = mac_vnode_check_open(ctx, lvp, FREAD);
			if (error) {
				vnode_put(lvp);
				return(error);
			}
#endif /* MAC */
			error = VNOP_OPEN(lvp, FREAD, ctx);
			if (error) {
				vnode_put(lvp);
				return(error);
			}
			vnode_ref(lvp);
			fp->f_fglob->fg_data = (caddr_t) lvp;
			fp->f_fglob->fg_offset = 0;

			error = VNOP_CLOSE(vp, FREAD, ctx);
			vnode_rele(vp);
			vnode_put(vp);
			if (error)
				return(error);

			*vpp = lvp;
			return -1;	/* goto unionread */
		}
	}
	return error;
}

/*  called from inactive with union lock held */
void
union_dircache_free(struct union_node *un)
{
	struct vnode **vpp;

	vpp = un->un_dircache;
	un->un_dircache = NULL;
	union_unlock();	
	
	for (; *vpp != NULLVP; vpp++)
		vnode_put(*vpp);
	_FREE(un->un_dircache, M_TEMP);
	union_lock();
}

