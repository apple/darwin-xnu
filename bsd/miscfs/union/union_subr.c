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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/namei.h>
#include <sys/malloc.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/queue.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/ubc.h>
#include <miscfs/union/union.h>

#if DIAGNOSTIC
#include <sys/proc.h>
#endif

/* must be power of two, otherwise change UNION_HASH() */
#define NHASH 32

/* unsigned int ... */
#define UNION_HASH(u, l) \
	(((((unsigned long) (u)) + ((unsigned long) l)) >> 8) & (NHASH-1))

static LIST_HEAD(unhead, union_node) unhead[NHASH];
static int unvplock[NHASH];

int
union_init()
{
	int i;

	for (i = 0; i < NHASH; i++)
		LIST_INIT(&unhead[i]);
	bzero((caddr_t) unvplock, sizeof(unvplock));
}

static int
union_list_lock(ix)
	int ix;
{

	if (unvplock[ix] & UN_LOCKED) {
		unvplock[ix] |= UN_WANT;
		sleep((caddr_t) &unvplock[ix], PINOD);
		return (1);
	}

	unvplock[ix] |= UN_LOCKED;

	return (0);
}

static void
union_list_unlock(ix)
	int ix;
{

	unvplock[ix] &= ~UN_LOCKED;

	if (unvplock[ix] & UN_WANT) {
		unvplock[ix] &= ~UN_WANT;
		wakeup((caddr_t) &unvplock[ix]);
	}
}

void
union_updatevp(un, uppervp, lowervp)
	struct union_node *un;
	struct vnode *uppervp;
	struct vnode *lowervp;
{
	int ohash = UNION_HASH(un->un_uppervp, un->un_lowervp);
	int nhash = UNION_HASH(uppervp, lowervp);
	int docache = (lowervp != NULLVP || uppervp != NULLVP);
	int lhash, hhash, uhash;

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

	if (lhash != uhash)
		while (union_list_lock(lhash))
			continue;

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
		if (un->un_lowervp) {
			vrele(un->un_lowervp);
			if (un->un_path) {
				_FREE(un->un_path, M_TEMP);
				un->un_path = 0;
			}
			if (un->un_dirvp) {
				vrele(un->un_dirvp);
				un->un_dirvp = NULLVP;
			}
		}
		un->un_lowervp = lowervp;
		un->un_lowersz = VNOVAL;
	}

	if (un->un_uppervp != uppervp) {
		if (un->un_uppervp)
			vrele(un->un_uppervp);

		un->un_uppervp = uppervp;
		un->un_uppersz = VNOVAL;
	}

	if (docache && (ohash != nhash)) {
		LIST_INSERT_HEAD(&unhead[nhash], un, un_cache);
		un->un_flags |= UN_CACHED;
	}

	union_list_unlock(nhash);
}

void
union_newlower(un, lowervp)
	struct union_node *un;
	struct vnode *lowervp;
{

	union_updatevp(un, un->un_uppervp, lowervp);
}

void
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
        if (UBCISVALID(vp))
			ubc_setsize(vp, sz); /* XXX check error */
	}
}

/*
 * allocate a union_node/vnode pair.  the vnode is
 * referenced and locked.  the new vnode is returned
 * via (vpp).  (mp) is the mountpoint of the union filesystem,
 * (dvp) is the parent directory where the upper layer object
 * should exist (but doesn't) and (cnp) is the componentname
 * information which is partially copied to allow the upper
 * layer object to be created at a later time.  (uppervp)
 * and (lowervp) reference the upper and lower layer objects
 * being mapped.  either, but not both, can be nil.
 * if supplied, (uppervp) is locked.
 * the reference is either maintained in the new union_node
 * object which is allocated, or they are vrele'd.
 *
 * all union_nodes are maintained on a singly-linked
 * list.  new nodes are only allocated when they cannot
 * be found on this list.  entries on the list are
 * removed when the vfs reclaim entry is called.
 *
 * a single lock is kept for the entire list.  this is
 * needed because the getnewvnode() function can block
 * waiting for a vnode to become free, in which case there
 * may be more than one process trying to get the same
 * vnode.  this lock is only taken if we are going to
 * call getnewvnode, since the kernel itself is single-threaded.
 *
 * if an entry is found on the list, then call vget() to
 * take a reference.  this is done because there may be
 * zero references to it and so it needs to removed from
 * the vnode free list.
 */
int
union_allocvp(vpp, mp, undvp, dvp, cnp, uppervp, lowervp, docache)
	struct vnode **vpp;
	struct mount *mp;
	struct vnode *undvp;		/* parent union vnode */
	struct vnode *dvp;		/* may be null */
	struct componentname *cnp;	/* may be null */
	struct vnode *uppervp;		/* may be null */
	struct vnode *lowervp;		/* may be null */
	int docache;
{
	int error;
	struct union_node *un;
	struct union_node **pp;
	struct vnode *xlowervp = NULLVP;
	struct union_mount *um = MOUNTTOUNIONMOUNT(mp);
	int hash;
	int vflag;
	int try;
	struct union_node *unp;

	if (uppervp == NULLVP && lowervp == NULLVP)
		panic("union: unidentifiable allocation");

	if (uppervp && lowervp && (uppervp->v_type != lowervp->v_type)) {
		xlowervp = lowervp;
		lowervp = NULLVP;
	}

	/* detect the root vnode (and aliases) */
	vflag = 0;
	if ((uppervp == um->um_uppervp) &&
	    ((lowervp == NULLVP) || lowervp == um->um_lowervp)) {
		if (lowervp == NULLVP) {
			lowervp = um->um_lowervp;
			if (lowervp != NULLVP)
				VREF(lowervp);
		}
		vflag = VROOT;
	}

loop:
	if (!docache) {
		un = 0;
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
			    (UNIONTOV(un)->v_mount == mp)) {
				if (vget(UNIONTOV(un), 0,
				    cnp ? cnp->cn_proc : NULL)) {
					union_list_unlock(hash);
					goto loop;
				}
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
		 * is not yet locked it will be vrele'd and replaced
		 * with uppervp.
		 */

		if ((dvp != NULLVP) && (uppervp == dvp)) {
			/*
			 * Access ``.'', so (un) will already
			 * be locked.  Since this process has
			 * the lock on (uppervp) no other
			 * process can hold the lock on (un).
			 */
#if DIAGNOSTIC
			if ((un->un_flags & UN_LOCKED) == 0)
				panic("union: . not locked");
			else if (current_proc() && un->un_pid != current_proc()->p_pid &&
				    un->un_pid > -1 && current_proc()->p_pid > -1)
				panic("union: allocvp not lock owner");
#endif
		} else {
			if (un->un_flags & UN_LOCKED) {
				vrele(UNIONTOV(un));
				un->un_flags |= UN_WANT;
				sleep((caddr_t) &un->un_flags, PINOD);
				goto loop;
			}
			un->un_flags |= UN_LOCKED;

#if DIAGNOSTIC
			if (current_proc())
				un->un_pid = current_proc()->p_pid;
			else
				un->un_pid = -1;
#endif
		}

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
			vrele(uppervp);
		}

		if (un->un_uppervp) {
			un->un_flags |= UN_ULOCK;
			un->un_flags &= ~UN_KLOCK;
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
				MALLOC(un->un_path, caddr_t, cnp->cn_namelen+1,
						M_TEMP, M_WAITOK);
				bcopy(cnp->cn_nameptr, un->un_path,
						cnp->cn_namelen);
				un->un_path[cnp->cn_namelen] = '\0';
				VREF(dvp);
				un->un_dirvp = dvp;
			}
		} else if (lowervp) {
			vrele(lowervp);
		}
		*vpp = UNIONTOV(un);
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

	MALLOC(unp, void *, sizeof(struct union_node), M_TEMP, M_WAITOK);
	error = getnewvnode(VT_UNION, mp, union_vnodeop_p, vpp);
	if (error) {
		FREE(unp, M_TEMP);
		if (uppervp) {
			if (dvp == uppervp)
				vrele(uppervp);
			else
				vput(uppervp);
		}
		if (lowervp)
			vrele(lowervp);

		goto out;
	}

	(*vpp)->v_data = unp;
	(*vpp)->v_flag |= vflag;
	if (uppervp)
		(*vpp)->v_type = uppervp->v_type;
	else
		(*vpp)->v_type = lowervp->v_type;

	if ((*vpp)->v_type == VREG)
		ubc_info_init(*vpp);

	un = VTOUNION(*vpp);
	un->un_vnode = *vpp;
	un->un_uppervp = uppervp;
	un->un_uppersz = VNOVAL;
	un->un_lowervp = lowervp;
	un->un_lowersz = VNOVAL;
	un->un_pvp = undvp;
	if (undvp != NULLVP)
		VREF(undvp);
	un->un_dircache = 0;
	un->un_openl = 0;
	un->un_flags = UN_LOCKED;
	if (un->un_uppervp)
		un->un_flags |= UN_ULOCK;
#if DIAGNOSTIC
	if (current_proc())
		un->un_pid = current_proc()->p_pid;
	else
		un->un_pid = -1;
#endif
	if (cnp && (lowervp != NULLVP)) {
		un->un_hash = cnp->cn_hash;
		un->un_path = _MALLOC(cnp->cn_namelen+1, M_TEMP, M_WAITOK);
		bcopy(cnp->cn_nameptr, un->un_path, cnp->cn_namelen);
		un->un_path[cnp->cn_namelen] = '\0';
		VREF(dvp);
		un->un_dirvp = dvp;
	} else {
		un->un_hash = 0;
		un->un_path = 0;
		un->un_dirvp = 0;
	}

	if (docache) {
		LIST_INSERT_HEAD(&unhead[hash], un, un_cache);
		un->un_flags |= UN_CACHED;
	}

	if (xlowervp)
		vrele(xlowervp);

out:
	if (docache)
		union_list_unlock(hash);

	return (error);
}

int
union_freevp(vp)
	struct vnode *vp;
{
	struct union_node *un = VTOUNION(vp);

	if (un->un_flags & UN_CACHED) {
		un->un_flags &= ~UN_CACHED;
		LIST_REMOVE(un, un_cache);
	}

	if (un->un_pvp != NULLVP)
		vrele(un->un_pvp);
	if (un->un_uppervp != NULLVP)
		vrele(un->un_uppervp);
	if (un->un_lowervp != NULLVP)
		vrele(un->un_lowervp);
	if (un->un_dirvp != NULLVP)
		vrele(un->un_dirvp);
	if (un->un_path)
		_FREE(un->un_path, M_TEMP);

	FREE(vp->v_data, M_TEMP);
	vp->v_data = 0;

	return (0);
}

/*
 * copyfile.  copy the vnode (fvp) to the vnode (tvp)
 * using a sequence of reads and writes.  both (fvp)
 * and (tvp) are locked on entry and exit.
 */
int
union_copyfile(fvp, tvp, cred, p)
	struct vnode *fvp;
	struct vnode *tvp;
	struct ucred *cred;
	struct proc *p;
{
	char *buf;
	struct uio uio;
	struct iovec iov;
	int error = 0;

	/*
	 * strategy:
	 * allocate a buffer of size MAXPHYSIO.
	 * loop doing reads and writes, keeping track
	 * of the current uio offset.
	 * give up at the first sign of trouble.
	 */

	uio.uio_procp = p;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_offset = 0;

	VOP_UNLOCK(fvp, 0, p);				/* XXX */
	VOP_LEASE(fvp, p, cred, LEASE_READ);
	vn_lock(fvp, LK_EXCLUSIVE | LK_RETRY, p);	/* XXX */
	VOP_UNLOCK(tvp, 0, p);				/* XXX */
	VOP_LEASE(tvp, p, cred, LEASE_WRITE);
	vn_lock(tvp, LK_EXCLUSIVE | LK_RETRY, p);	/* XXX */

	buf = _MALLOC(MAXPHYSIO, M_TEMP, M_WAITOK);

	/* ugly loop follows... */
	do {
		off_t offset = uio.uio_offset;

		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		iov.iov_base = buf;
		iov.iov_len = MAXPHYSIO;
		uio.uio_resid = iov.iov_len;
		uio.uio_rw = UIO_READ;
		error = VOP_READ(fvp, &uio, 0, cred);

		if (error == 0) {
			uio.uio_iov = &iov;
			uio.uio_iovcnt = 1;
			iov.iov_base = buf;
			iov.iov_len = MAXPHYSIO - uio.uio_resid;
			uio.uio_offset = offset;
			uio.uio_rw = UIO_WRITE;
			uio.uio_resid = iov.iov_len;

			if (uio.uio_resid == 0)
				break;

			do {
				error = VOP_WRITE(tvp, &uio, 0, cred);
			} while ((uio.uio_resid > 0) && (error == 0));
		}

	} while (error == 0);

	_FREE(buf, M_TEMP);
	return (error);
}

/*
 * (un) is assumed to be locked on entry and remains
 * locked on exit.
 */
int
union_copyup(un, docopy, cred, p)
	struct union_node *un;
	int docopy;
	struct ucred *cred;
	struct proc *p;
{
	int error;
	struct vnode *lvp, *uvp;

	error = union_vn_create(&uvp, un, p);
	if (error)
		return (error);

	/* at this point, uppervp is locked */
	union_newupper(un, uvp);
	un->un_flags |= UN_ULOCK;

	lvp = un->un_lowervp;

	if (docopy) {
		/*
		 * XX - should not ignore errors
		 * from VOP_CLOSE
		 */
		vn_lock(lvp, LK_EXCLUSIVE | LK_RETRY, p);
		error = VOP_OPEN(lvp, FREAD, cred, p);
		if (error == 0) {
			error = union_copyfile(lvp, uvp, cred, p);
			VOP_UNLOCK(lvp, 0, p);
			(void) VOP_CLOSE(lvp, FREAD, cred, p);
		}
#ifdef UNION_DIAGNOSTIC
		if (error == 0)
			uprintf("union: copied up %s\n", un->un_path);
#endif

	}
	un->un_flags &= ~UN_ULOCK;
	VOP_UNLOCK(uvp, 0, p);
	union_vn_close(uvp, FWRITE, cred, p);
	vn_lock(uvp, LK_EXCLUSIVE | LK_RETRY, p);
	un->un_flags |= UN_ULOCK;

	/*
	 * Subsequent IOs will go to the top layer, so
	 * call close on the lower vnode and open on the
	 * upper vnode to ensure that the filesystem keeps
	 * its references counts right.  This doesn't do
	 * the right thing with (cred) and (FREAD) though.
	 * Ignoring error returns is not right, either.
	 */
	if (error == 0) {
		int i;

		for (i = 0; i < un->un_openl; i++) {
			(void) VOP_CLOSE(lvp, FREAD, cred, p);
			(void) VOP_OPEN(uvp, FREAD, cred, p);
		}
		un->un_openl = 0;
	}

	return (error);

}

static int
union_relookup(um, dvp, vpp, cnp, cn, path, pathlen)
	struct union_mount *um;
	struct vnode *dvp;
	struct vnode **vpp;
	struct componentname *cnp;
	struct componentname *cn;
	char *path;
	int pathlen;
{
	int error;

	/*
	 * A new componentname structure must be faked up because
	 * there is no way to know where the upper level cnp came
	 * from or what it is being used for.  This must duplicate
	 * some of the work done by NDINIT, some of the work done
	 * by namei, some of the work done by lookup and some of
	 * the work done by VOP_LOOKUP when given a CREATE flag.
	 * Conclusion: Horrible.
	 *
	 * The pathname buffer will be FREEed by VOP_MKDIR.
	 */
	cn->cn_namelen = pathlen;
	cn->cn_pnbuf = _MALLOC_ZONE(cn->cn_namelen+1, M_NAMEI, M_WAITOK);
	cn->cn_pnlen = cn->cn_namelen+1;
	bcopy(path, cn->cn_pnbuf, cn->cn_namelen);
	cn->cn_pnbuf[cn->cn_namelen] = '\0';

	cn->cn_nameiop = CREATE;
	cn->cn_flags = (LOCKPARENT|HASBUF|SAVENAME|SAVESTART|ISLASTCN);
	cn->cn_proc = cnp->cn_proc;
	if (um->um_op == UNMNT_ABOVE)
		cn->cn_cred = cnp->cn_cred;
	else
		cn->cn_cred = um->um_cred;
	cn->cn_nameptr = cn->cn_pnbuf;
	cn->cn_hash = cnp->cn_hash;
	cn->cn_consume = cnp->cn_consume;

	VREF(dvp);
	error = relookup(dvp, vpp, cn);
	if (!error)
		vrele(dvp);

	return (error);
}

/*
 * Create a shadow directory in the upper layer.
 * The new vnode is returned locked.
 *
 * (um) points to the union mount structure for access to the
 * the mounting process's credentials.
 * (dvp) is the directory in which to create the shadow directory.
 * it is unlocked on entry and exit.
 * (cnp) is the componentname to be created.
 * (vpp) is the returned newly created shadow directory, which
 * is returned locked.
 */
int
union_mkshadow(um, dvp, cnp, vpp)
	struct union_mount *um;
	struct vnode *dvp;
	struct componentname *cnp;
	struct vnode **vpp;
{
	int error;
	struct vattr va;
	struct proc *p = cnp->cn_proc;
	struct componentname cn;

	error = union_relookup(um, dvp, vpp, cnp, &cn,
			cnp->cn_nameptr, cnp->cn_namelen);
	if (error)
		return (error);

	if (*vpp) {
		VOP_ABORTOP(dvp, &cn);
		VOP_UNLOCK(dvp, 0, p);
		vrele(*vpp);
		*vpp = NULLVP;
		return (EEXIST);
	}

	/*
	 * policy: when creating the shadow directory in the
	 * upper layer, create it owned by the user who did
	 * the mount, group from parent directory, and mode
	 * 777 modified by umask (ie mostly identical to the
	 * mkdir syscall).  (jsp, kb)
	 */

	VATTR_NULL(&va);
	va.va_type = VDIR;
	va.va_mode = um->um_cmode;

	/* VOP_LEASE: dvp is locked */
	VOP_LEASE(dvp, p, cn.cn_cred, LEASE_WRITE);

	error = VOP_MKDIR(dvp, vpp, &cn, &va);
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
int
union_mkwhiteout(um, dvp, cnp, path)
	struct union_mount *um;
	struct vnode *dvp;
	struct componentname *cnp;
	char *path;
{
	int error;
	struct vattr va;
	struct proc *p = cnp->cn_proc;
	struct vnode *wvp;
	struct componentname cn;

	VOP_UNLOCK(dvp, 0, p);
	error = union_relookup(um, dvp, &wvp, cnp, &cn, path, strlen(path));
	if (error) {
		vn_lock(dvp, LK_EXCLUSIVE | LK_RETRY, p);
		return (error);
	}

	if (wvp) {
		VOP_ABORTOP(dvp, &cn);
		vrele(dvp);
		vrele(wvp);
		return (EEXIST);
	}

	/* VOP_LEASE: dvp is locked */
	VOP_LEASE(dvp, p, p->p_ucred, LEASE_WRITE);

	error = VOP_WHITEOUT(dvp, &cn, CREATE);
	if (error)
		VOP_ABORTOP(dvp, &cn);

	vrele(dvp);

	return (error);
}

/*
 * union_vn_create: creates and opens a new shadow file
 * on the upper union layer.  this function is similar
 * in spirit to calling vn_open but it avoids calling namei().
 * the problem with calling namei is that a) it locks too many
 * things, and b) it doesn't start at the "right" directory,
 * whereas relookup is told where to start.
 */
int
union_vn_create(vpp, un, p)
	struct vnode **vpp;
	struct union_node *un;
	struct proc *p;
{
	struct vnode *vp;
	struct ucred *cred = p->p_ucred;
	struct vattr vat;
	struct vattr *vap = &vat;
	int fmode = FFLAGS(O_WRONLY|O_CREAT|O_TRUNC|O_EXCL);
	int error;
	int cmode = UN_FILEMODE & ~p->p_fd->fd_cmask;
	char *cp;
	struct componentname cn;

	*vpp = NULLVP;

	/*
	 * Build a new componentname structure (for the same
	 * reasons outlines in union_mkshadow).
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
	cn.cn_flags = (LOCKPARENT|HASBUF|SAVENAME|SAVESTART|ISLASTCN);
	cn.cn_proc = p;
	cn.cn_cred = p->p_ucred;
	cn.cn_nameptr = cn.cn_pnbuf;
	cn.cn_hash = un->un_hash;
	cn.cn_consume = 0;

	VREF(un->un_dirvp);
	if (error = relookup(un->un_dirvp, &vp, &cn))
		return (error);
	vrele(un->un_dirvp);

	if (vp) {
		VOP_ABORTOP(un->un_dirvp, &cn);
		if (un->un_dirvp == vp)
			vrele(un->un_dirvp);
		else
			vput(un->un_dirvp);
		vrele(vp);
		return (EEXIST);
	}

	/*
	 * Good - there was no race to create the file
	 * so go ahead and create it.  The permissions
	 * on the file will be 0666 modified by the
	 * current user's umask.  Access to the file, while
	 * it is unioned, will require access to the top *and*
	 * bottom files.  Access when not unioned will simply
	 * require access to the top-level file.
	 * TODO: confirm choice of access permissions.
	 */
	VATTR_NULL(vap);
	vap->va_type = VREG;
	vap->va_mode = cmode;
	VOP_LEASE(un->un_dirvp, p, cred, LEASE_WRITE);
	if (error = VOP_CREATE(un->un_dirvp, &vp, &cn, vap))
		return (error);

	if (error = VOP_OPEN(vp, fmode, cred, p)) {
		vput(vp);
		return (error);
	}

	if (++vp->v_writecount <= 0)
		panic("union: v_writecount");
	*vpp = vp;
	return (0);
}

int
union_vn_close(vp, fmode, cred, p)
	struct vnode *vp;
	int fmode;
	struct ucred *cred;
	struct proc *p;
{

	if (fmode & FWRITE)
		--vp->v_writecount;
	return (VOP_CLOSE(vp, fmode, cred, p));
}

void
union_removed_upper(un)
	struct union_node *un;
{
	struct proc *p = current_proc();	/* XXX */

	union_newupper(un, NULLVP);
	if (un->un_flags & UN_CACHED) {
		un->un_flags &= ~UN_CACHED;
		LIST_REMOVE(un, un_cache);
	}

	if (un->un_flags & UN_ULOCK) {
		un->un_flags &= ~UN_ULOCK;
		VOP_UNLOCK(un->un_uppervp, 0, p);
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
		if (vget(un->un_lowervp, 0, current_proc()) == 0)
			return (un->un_lowervp);
	}

	return (NULLVP);
}
#endif

/*
 * determine whether a whiteout is needed
 * during a remove/rmdir operation.
 */
int
union_dowhiteout(un, cred, p)
	struct union_node *un;
	struct ucred *cred;
	struct proc *p;
{
	struct vattr va;

	if (un->un_lowervp != NULLVP)
		return (1);

	if (VOP_GETATTR(un->un_uppervp, &va, cred, p) == 0 &&
	    (va.va_flags & OPAQUE))
		return (1);

	return (0);
}

static void
union_dircache_r(vp, vppp, cntp)
	struct vnode *vp;
	struct vnode ***vppp;
	int *cntp;
{
	struct union_node *un;

	if (vp->v_op != union_vnodeop_p) {
		if (vppp) {
			VREF(vp);
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

struct vnode *
union_dircache(vp, p)
	struct vnode *vp;
	struct proc *p;
{
	int cnt;
	struct vnode *nvp;
	struct vnode **vpp;
	struct vnode **dircache;
	struct union_node *un;
	int error;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	dircache = VTOUNION(vp)->un_dircache;

	nvp = NULLVP;

	if (dircache == 0) {
		cnt = 0;
		union_dircache_r(vp, 0, &cnt);
		cnt++;
		dircache = (struct vnode **)
				_MALLOC(cnt * sizeof(struct vnode *),
					M_TEMP, M_WAITOK);
		vpp = dircache;
		union_dircache_r(vp, &vpp, &cnt);
		*vpp = NULLVP;
		vpp = dircache + 1;
	} else {
		vpp = dircache;
		do {
			if (*vpp++ == VTOUNION(vp)->un_uppervp)
				break;
		} while (*vpp != NULLVP);
	}

	if (*vpp == NULLVP)
		goto out;

	vn_lock(*vpp, LK_EXCLUSIVE | LK_RETRY, p);
	VREF(*vpp);
	error = union_allocvp(&nvp, vp->v_mount, NULLVP, NULLVP, 0, *vpp, NULLVP, 0);
	if (error)
		goto out;

	VTOUNION(vp)->un_dircache = 0;
	un = VTOUNION(nvp);
	un->un_dircache = dircache;

out:
	VOP_UNLOCK(vp, 0, p);
	return (nvp);
}
