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
 *	@(#)nfs_node.c	8.6 (Berkeley) 5/22/95
 * FreeBSD-Id: nfs_node.c,v 1.22 1997/10/28 14:06:20 bde Exp $
 */


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/malloc.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfsnode.h>
#include <nfs/nfsmount.h>

#ifdef MALLOC_DEFINE
static MALLOC_DEFINE(M_NFSNODE, "NFS node", "NFS vnode private part");
#endif

LIST_HEAD(nfsnodehashhead, nfsnode) *nfsnodehashtbl;
u_long nfsnodehash;

#define TRUE	1
#define	FALSE	0

/*
 * Initialize hash links for nfsnodes
 * and build nfsnode free list.
 */
void
nfs_nhinit()
{
	nfsnodehashtbl = hashinit(desiredvnodes, M_NFSNODE, &nfsnodehash);
}

/*
 * Compute an entry in the NFS hash table structure
 */
u_long
nfs_hash(fhp, fhsize)
	register nfsfh_t *fhp;
	int fhsize;
{
	register u_char *fhpp;
	register u_long fhsum;
	register int i;

	fhpp = &fhp->fh_bytes[0];
	fhsum = 0;
	for (i = 0; i < fhsize; i++)
		fhsum += *fhpp++;
	return (fhsum);
}

/*
 * Look up a vnode/nfsnode by file handle.
 * Callers must check for mount points!!
 * In all cases, a pointer to a
 * nfsnode structure is returned.
 */
int nfs_node_hash_lock;

int
nfs_nget(mntp, fhp, fhsize, npp)
	struct mount *mntp;
	register nfsfh_t *fhp;
	int fhsize;
	struct nfsnode **npp;
{
	struct proc *p = current_proc();	/* XXX */
	struct nfsnode *np;
	struct nfsnodehashhead *nhpp;
	register struct vnode *vp;
	struct vnode *nvp;
	int error;

	/* Check for unmount in progress */
	if (mntp->mnt_kern_flag & MNTK_UNMOUNT) {
		*npp = 0;
		return (EPERM);
	}

	nhpp = NFSNOHASH(nfs_hash(fhp, fhsize));
loop:
	for (np = nhpp->lh_first; np != 0; np = np->n_hash.le_next) {
		if (mntp != NFSTOV(np)->v_mount || np->n_fhsize != fhsize ||
		    bcmp((caddr_t)fhp, (caddr_t)np->n_fhp, fhsize))
			continue;
		vp = NFSTOV(np);
		if (vget(vp, LK_EXCLUSIVE, p))
			goto loop;
		*npp = np;
		return(0);
	}
	/*
	 * Obtain a lock to prevent a race condition if the getnewvnode()
	 * or MALLOC() below happens to block.
	 */
	if (nfs_node_hash_lock) {
		while (nfs_node_hash_lock) {
			nfs_node_hash_lock = -1;
			tsleep(&nfs_node_hash_lock, PVM, "nfsngt", 0);
		}
		goto loop;
	}
	nfs_node_hash_lock = 1;

	/*
	 * Do the MALLOC before the getnewvnode since doing so afterward
	 * might cause a bogus v_data pointer to get dereferenced
	 * elsewhere if MALLOC should block.
	 */
	MALLOC_ZONE(np, struct nfsnode *, sizeof *np, M_NFSNODE, M_WAITOK);
		
	error = getnewvnode(VT_NFS, mntp, nfsv2_vnodeop_p, &nvp);
	if (error) {
		if (nfs_node_hash_lock < 0)
			wakeup(&nfs_node_hash_lock);
		nfs_node_hash_lock = 0;
		*npp = 0;
		FREE_ZONE(np, sizeof *np, M_NFSNODE);
		return (error);
	}
	vp = nvp;
	bzero((caddr_t)np, sizeof *np);
	vp->v_data = np;
	np->n_vnode = vp;
	/*
	 * Insert the nfsnode in the hash queue for its new file handle
	 */
	LIST_INSERT_HEAD(nhpp, np, n_hash);
	if (fhsize > NFS_SMALLFH) {
		MALLOC_ZONE(np->n_fhp, nfsfh_t *,
				fhsize, M_NFSBIGFH, M_WAITOK);
	} else
		np->n_fhp = &np->n_fh;
	bcopy((caddr_t)fhp, (caddr_t)np->n_fhp, fhsize);
	np->n_fhsize = fhsize;
	*npp = np;

	if (nfs_node_hash_lock < 0)
		wakeup(&nfs_node_hash_lock);
	nfs_node_hash_lock = 0;

	/*
	 * Lock the new nfsnode.
	 */
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);

	return (0);
}

int
nfs_inactive(ap)
	struct vop_inactive_args /* {
		struct vnode *a_vp;
		struct proc *a_p;
	} */ *ap;
{
	register struct nfsnode *np;
	register struct sillyrename *sp;
	struct proc *p = current_proc();	/* XXX */
	extern int prtactive;
	struct ucred *cred;

	np = VTONFS(ap->a_vp);
	if (prtactive && ap->a_vp->v_usecount != 0)
		vprint("nfs_inactive: pushing active", ap->a_vp);
	if (ap->a_vp->v_type != VDIR) {
		sp = np->n_sillyrename;
		np->n_sillyrename = (struct sillyrename *)0;
	} else
		sp = (struct sillyrename *)0;

	if (sp) {
		/*
		 * Remove the silly file that was rename'd earlier
		 */
#if DIAGNOSTIC
		kprintf("nfs_inactive removing %s, dvp=%x, a_vp=%x, ap=%x, np=%x, sp=%x\n", &sp->s_name[0], (unsigned)sp->s_dvp, (unsigned)ap->a_vp, (unsigned)ap, (unsigned)np, (unsigned)sp);
#endif
		/*
		 * We get a reference (vget) to ensure getnewvnode()
		 * doesn't recycle vp while we're asleep awaiting I/O.
		 * Note we don't need the reference unless usecount is
		 * already zero.  In the case of a forcible unmount it
		 * wont be zero and doing a vget would fail because
		 * vclean holds VXLOCK.
		 */
                if (ap->a_vp->v_usecount > 0) {
                        VREF(ap->a_vp);
                } else if (vget(ap->a_vp, 0, ap->a_p))
			panic("nfs_inactive: vget failed");
		(void) nfs_vinvalbuf(ap->a_vp, 0, sp->s_cred, p, 1);
		ubc_setsize(ap->a_vp, (off_t)0);

                /* We have a problem. The dvp could have gone away on us
                 * while in the unmount path. Thus it appears as VBAD and we
                 * cannot use it. If we tried locking the parent (future), for silly
                 * rename files, it is unclear where we would lock. The unmount
                 * code just pulls unlocked vnodes as it goes thru its list and
                 * yanks them. Could unmount be smarter to see if a busy reg vnode has
                 * a parent, and not yank it yet? Put in more passes at unmount
                 * time? In the meantime, just check if it went away on us. Could
                 * have gone away during the nfs_vinvalbuf or ubc_setsize which block.
                 * Or perhaps even before nfs_inactive got called.
                 */
                if ((sp->s_dvp)->v_type != VBAD) 
                        nfs_removeit(sp); /* uses the dvp */
		cred = sp->s_cred;
		if (cred != NOCRED) {
			sp->s_cred = NOCRED;
			crfree(cred);
		}
		vrele(sp->s_dvp);
		FREE_ZONE((caddr_t)sp, sizeof (struct sillyrename), M_NFSREQ);
		vrele(ap->a_vp);
	}
	np->n_flag &= (NMODIFIED | NFLUSHINPROG | NFLUSHWANT | NQNFSEVICTED |
		NQNFSNONCACHE | NQNFSWRITE);
	VOP_UNLOCK(ap->a_vp, 0, ap->a_p);
	return (0);
}

/*
 * Reclaim an nfsnode so that it can be used for other purposes.
 */
int
nfs_reclaim(ap)
	struct vop_reclaim_args /* {
		struct vnode *a_vp;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	register struct nfsnode *np = VTONFS(vp);
	register struct nfsmount *nmp = VFSTONFS(vp->v_mount);
	register struct nfsdmap *dp, *dp2;
	extern int prtactive;

	if (prtactive && vp->v_usecount != 0)
		vprint("nfs_reclaim: pushing active", vp);

	LIST_REMOVE(np, n_hash);

        /*
         * In case we block during FREE_ZONEs below, get the entry out
         * of tbe name cache now so subsequent lookups won't find it.
         */ 
        cache_purge(vp); 

	/*
	 * For nqnfs, take it off the timer queue as required.
	 */
	if ((nmp->nm_flag & NFSMNT_NQNFS) && np->n_timer.cqe_next != 0) {
		CIRCLEQ_REMOVE(&nmp->nm_timerhead, np, n_timer);
	}

	/*
	 * Free up any directory cookie structures and
	 * large file handle structures that might be associated with
	 * this nfs node.
	 */
	if (vp->v_type == VDIR) {
		dp = np->n_cookies.lh_first;
		while (dp) {
			dp2 = dp;
			dp = dp->ndm_list.le_next;
			FREE_ZONE((caddr_t)dp2,
					sizeof (struct nfsdmap), M_NFSDIROFF);
		}
	}
	if (np->n_fhsize > NFS_SMALLFH) {
		FREE_ZONE((caddr_t)np->n_fhp, np->n_fhsize, M_NFSBIGFH);
	}

	FREE_ZONE(vp->v_data, sizeof (struct nfsnode), M_NFSNODE);
	vp->v_data = (void *)0;
	return (0);
}

#if 0
/*
 * Lock an nfsnode
 */
int
nfs_lock(ap)
	struct vop_lock_args /* {
		struct vnode *a_vp;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;

	/*
	 * Ugh, another place where interruptible mounts will get hung.
	 * If you make this sleep interruptible, then you have to fix all
	 * the VOP_LOCK() calls to expect interruptibility.
	 */
	while (vp->v_flag & VXLOCK) {
		vp->v_flag |= VXWANT;
		(void) tsleep((caddr_t)vp, PINOD, "nfslck", 0);
	}
	if (vp->v_tag == VT_NON)
		return (ENOENT);

#if 0
	/*
	 * Only lock regular files.  If a server crashed while we were
	 * holding a directory lock, we could easily end up sleeping
	 * until the server rebooted while holding a lock on the root.
	 * Locks are only needed for protecting critical sections in
	 * VMIO at the moment.
	 * New vnodes will have type VNON but they should be locked
	 * since they may become VREG.  This is checked in loadattrcache
	 * and unwanted locks are released there.
	 */
	if (vp->v_type == VREG || vp->v_type == VNON) {
		while (np->n_flag & NLOCKED) {
			np->n_flag |= NWANTED;
			(void) tsleep((caddr_t) np, PINOD, "nfslck2", 0);
			/*
			 * If the vnode has transmuted into a VDIR while we
			 * were asleep, then skip the lock.
			 */
			if (vp->v_type != VREG && vp->v_type != VNON)
				return (0);
		}
		np->n_flag |= NLOCKED;
	}
#endif

	return (0);
}

/*
 * Unlock an nfsnode
 */
int
nfs_unlock(ap)
	struct vop_unlock_args /* {
		struct vnode *a_vp;
	} */ *ap;
{
#if 0
	struct vnode* vp = ap->a_vp;
        struct nfsnode* np = VTONFS(vp);

	if (vp->v_type == VREG || vp->v_type == VNON) {
		if (!(np->n_flag & NLOCKED))
			panic("nfs_unlock: nfsnode not locked");
		np->n_flag &= ~NLOCKED;
		if (np->n_flag & NWANTED) {
			np->n_flag &= ~NWANTED;
			wakeup((caddr_t) np);
		}
	}
#endif

	return (0);
}

/*
 * Check for a locked nfsnode
 */
int
nfs_islocked(ap)
	struct vop_islocked_args /* {
		struct vnode *a_vp;
	} */ *ap;
{
	return VTONFS(ap->a_vp)->n_flag & NLOCKED ? 1 : 0;
}
#endif

/*
 * Nfs abort op, called after namei() when a CREATE/DELETE isn't actually
 * done. Currently nothing to do.
 */
/* ARGSUSED */
int
nfs_abortop(ap)
	struct vop_abortop_args /* {
		struct vnode *a_dvp;
		struct componentname *a_cnp;
	} */ *ap;
{

	if ((ap->a_cnp->cn_flags & (HASBUF | SAVESTART)) == HASBUF)
		FREE_ZONE(ap->a_cnp->cn_pnbuf, ap->a_cnp->cn_pnlen, M_NAMEI);
	return (0);
}
