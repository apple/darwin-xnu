/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/vnode_internal.h>
#include <sys/namei.h>
#include <sys/malloc.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/queue.h>
#include <sys/mount_internal.h>
#include <sys/stat.h>
#include <sys/ubc.h>
#include <sys/uio_internal.h>
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
	int lhash, uhash;

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
			vnode_put(un->un_lowervp);
			if (un->un_path) {
				_FREE(un->un_path, M_TEMP);
				un->un_path = 0;
			}
			if (un->un_dirvp) {
				vnode_put(un->un_dirvp);
				un->un_dirvp = NULLVP;
			}
		}
		un->un_lowervp = lowervp;
		un->un_lowersz = VNOVAL;
	}

	if (un->un_uppervp != uppervp) {
		if (un->un_uppervp)
			vnode_put(un->un_uppervp);

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
		ubc_setsize(vp, sz);
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
 * object which is allocated, or they are vnode_put'd.
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
 * if an entry is found on the list, then call vnode_get() to
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
	int markroot;
	int try;
	struct union_node *unp;
	struct vnode_fsparam vfsp;
	enum vtype vtype;

	if (uppervp == NULLVP && lowervp == NULLVP)
		panic("union: unidentifiable allocation");

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
			if (lowervp != NULLVP)
				vnode_get(lowervp);
		}
		markroot = VROOT;
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
				if (vnode_get(UNIONTOV(un))) {
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
		 * is not yet locked it will be vnode_put'd and replaced
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
				vnode_put(UNIONTOV(un));
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
			vnode_put(uppervp);
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
				vnode_get(dvp);
				un->un_dirvp = dvp;
			}
		} else if (lowervp) {
			vnode_put(lowervp);
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

	if (uppervp)
		vtype = uppervp->v_type;
	else
		vtype = lowervp->v_type;
	//bzero(&vfsp, sizeof(struct vnode_fsparam));
	vfsp.vnfs_mp = mp;
	vfsp.vnfs_vtype = vtype;
	vfsp.vnfs_str = "unionfs";
	vfsp.vnfs_dvp = dvp;
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
		FREE(unp, M_TEMP);
		if (uppervp) {
		        vnode_put(uppervp);
		}
		if (lowervp)
			vnode_put(lowervp);

		goto out;
	}

	(*vpp)->v_tag = VT_UNION;
	un = VTOUNION(*vpp);
	un->un_vnode = *vpp;
	un->un_uppervp = uppervp;
	un->un_uppersz = VNOVAL;
	un->un_lowervp = lowervp;
	un->un_lowersz = VNOVAL;
	un->un_pvp = undvp;
	if (undvp != NULLVP)
		vnode_get(undvp);
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
		vnode_get(dvp);
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
		vnode_put(xlowervp);

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

	return (0);
}

/*
 * copyfile.  copy the vnode (fvp) to the vnode (tvp)
 * using a sequence of reads and writes.  both (fvp)
 * and (tvp) are locked on entry and exit.
 */
int
union_copyfile(struct vnode *fvp, struct vnode *tvp, kauth_cred_t cred,
	struct proc *p)
{
	char *bufp;
	struct uio uio;
	struct iovec_32 iov;
	struct vfs_context context;
	int error = 0;

	/*
	 * strategy:
	 * allocate a buffer of size MAXPHYSIO.
	 * loop doing reads and writes, keeping track
	 * of the current uio offset.
	 * give up at the first sign of trouble.
	 */

	context.vc_proc = p;
	context.vc_ucred = cred;

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
		error = VNOP_READ(fvp, &uio, 0, &context);

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
				error = VNOP_WRITE(tvp, &uio, 0, &context);
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
int
union_copyup(struct union_node *un, int docopy, kauth_cred_t cred,
	struct proc *p)
{
	int error;
	struct vnode *lvp, *uvp;
	struct vfs_context context;

	error = union_vn_create(&uvp, un, p);
	if (error)
		return (error);

	context.vc_proc = p;
	context.vc_ucred = cred;

	/* at this point, uppervp is locked */
	union_newupper(un, uvp);
	un->un_flags |= UN_ULOCK;

	lvp = un->un_lowervp;

	if (docopy) {
		/*
		 * XX - should not ignore errors
		 * from vnop_close
		 */
		error = VNOP_OPEN(lvp, FREAD, &context);
		if (error == 0) {
			error = union_copyfile(lvp, uvp, cred, p);
			(void) VNOP_CLOSE(lvp, FREAD, &context);
		}
#ifdef UNION_DIAGNOSTIC
		if (error == 0)
			uprintf("union: copied up %s\n", un->un_path);
#endif

	}
	un->un_flags &= ~UN_ULOCK;
	union_vn_close(uvp, FWRITE, cred, p);
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
			(void) VNOP_CLOSE(lvp, FREAD, &context);
			(void) VNOP_OPEN(uvp, FREAD, &context);
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
	 * the work done by vnop_lookup when given a CREATE flag.
	 * Conclusion: Horrible.
	 */
	cn->cn_namelen = pathlen;
	cn->cn_pnbuf = _MALLOC_ZONE(cn->cn_namelen+1, M_NAMEI, M_WAITOK);
	cn->cn_pnlen = cn->cn_namelen+1;
	bcopy(path, cn->cn_pnbuf, cn->cn_namelen);
	cn->cn_pnbuf[cn->cn_namelen] = '\0';

	cn->cn_nameiop = CREATE;
	cn->cn_flags = (LOCKPARENT|HASBUF|SAVENAME|SAVESTART|ISLASTCN);
#ifdef XXX_HELP_ME
	cn->cn_proc = cnp->cn_proc;
	if (um->um_op == UNMNT_ABOVE)
		cn->cn_cred = cnp->cn_cred;
	else
		cn->cn_cred = um->um_cred;
#endif
	cn->cn_context = cnp->cn_context;	/* XXX !UNMNT_ABOVE  case ??? */
	cn->cn_nameptr = cn->cn_pnbuf;
	cn->cn_hash = cnp->cn_hash;
	cn->cn_consume = cnp->cn_consume;

	vnode_get(dvp);
	error = relookup(dvp, vpp, cn);
	if (!error)
		vnode_put(dvp);

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
	struct vnode_attr va;
	struct componentname cn;

	error = union_relookup(um, dvp, vpp, cnp, &cn,
			cnp->cn_nameptr, cnp->cn_namelen);
	if (error)
		return (error);

	if (*vpp) {
		vnode_put(*vpp);
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
	VATTR_INIT(&va);
	VATTR_SET(&va, va_type, VDIR);
	VATTR_SET(&va, va_mode, um->um_cmode);

	error = vn_create(dvp, vpp, &cn, &va, 0, cnp->cn_context);
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
	struct vnode *wvp;
	struct componentname cn;

	error = union_relookup(um, dvp, &wvp, cnp, &cn, path, strlen(path));
	if (error) {
		return (error);
	}
	if (wvp) {
		vnode_put(dvp);
		vnode_put(wvp);
		return (EEXIST);
	}

	error = VNOP_WHITEOUT(dvp, &cn, CREATE, cnp->cn_context);

	vnode_put(dvp);

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
	kauth_cred_t cred = p->p_ucred;
	struct vnode_attr vat;
	struct vnode_attr *vap = &vat;
	struct vfs_context context;
	int fmode = FFLAGS(O_WRONLY|O_CREAT|O_TRUNC|O_EXCL);
	int error;
	int cmode = UN_FILEMODE & ~p->p_fd->fd_cmask;
	char *cp;
	struct componentname cn;

	*vpp = NULLVP;

	context.vc_proc = p;
	context.vc_ucred = p->p_ucred;

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
	cn.cn_context = &context;
	cn.cn_nameptr = cn.cn_pnbuf;
	cn.cn_hash = un->un_hash;
	cn.cn_consume = 0;

	vnode_get(un->un_dirvp);
	if (error = relookup(un->un_dirvp, &vp, &cn))
		return (error);
	vnode_put(un->un_dirvp);

	if (vp) {
	        vnode_put(un->un_dirvp);
		vnode_put(vp);
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
	 *
	 * TODO: confirm choice of access permissions.
	 *       decide on authorisation behaviour
	 */
	
	VATTR_INIT(vap);
	VATTR_SET(vap, va_type, VREG);
	VATTR_SET(vap, va_mode, cmode);

	if (error = vn_create(un->un_dirvp, &vp, &cn, vap, 0, &context))
		return (error);

	if (error = VNOP_OPEN(vp, fmode, &context)) {
		vnode_put(vp);
		return (error);
	}

	vnode_lock(vp);
	if (++vp->v_writecount <= 0)
		panic("union: v_writecount");
	vnode_unlock(vp);
	*vpp = vp;
	return (0);
}

int
union_vn_close(struct vnode *vp, int fmode, kauth_cred_t cred,
	struct proc *p)
{
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = cred;

	if (fmode & FWRITE) {
		vnode_lock(vp);
		--vp->v_writecount;
		vnode_unlock(vp);
	}
	return (VNOP_CLOSE(vp, fmode, &context));
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
 * determine whether a whiteout is needed
 * during a remove/rmdir operation.
 */
int
union_dowhiteout(struct union_node *un, vfs_context_t ctx)
{
	struct vnode_attr va;

	if (un->un_lowervp != NULLVP)
		return (1);

	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_flags);
	if (vnode_getattr(un->un_uppervp, &va, ctx) == 0 &&
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

struct vnode *
union_dircache(vp, p)
	struct vnode *vp;
	struct proc *p;
{
	int count;
	struct vnode *nvp;
	struct vnode **vpp;
	struct vnode **dircache;
	struct union_node *un;
	int error;

	dircache = VTOUNION(vp)->un_dircache;

	nvp = NULLVP;

	if (dircache == 0) {
		count = 0;
		union_dircache_r(vp, 0, &count);
		count++;
		dircache = (struct vnode **)
				_MALLOC(count * sizeof(struct vnode *),
					M_TEMP, M_WAITOK);
		vpp = dircache;
		union_dircache_r(vp, &vpp, &count);
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

	vnode_get(*vpp);
	error = union_allocvp(&nvp, vp->v_mount, NULLVP, NULLVP, 0, *vpp, NULLVP, 0);
	if (error)
		goto out;

	VTOUNION(vp)->un_dircache = 0;
	un = VTOUNION(nvp);
	un->un_dircache = dircache;

out:
	return (nvp);
}
