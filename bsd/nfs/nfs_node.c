/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
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

LIST_HEAD(nfsnodehashhead, nfsnode) *nfsnodehashtbl;
u_long nfsnodehash;

#define TRUE	1
#define	FALSE	0

/*
 * Initialize hash links for nfsnodes
 * and build nfsnode free list.
 */
void
nfs_nhinit(void)
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
	struct mount *mp;

	/* Check for unmount in progress */
	if (!mntp || (mntp->mnt_kern_flag & MNTK_UNMOUNT)) {
		*npp = 0;
		return (!mntp ? ENXIO : EPERM);
	}

	nhpp = NFSNOHASH(nfs_hash(fhp, fhsize));
loop:
	for (np = nhpp->lh_first; np != 0; np = np->n_hash.le_next) {
		mp = (np->n_flag & NINIT) ? np->n_mount : NFSTOV(np)->v_mount;
		if (mntp != mp || np->n_fhsize != fhsize ||
		    bcmp((caddr_t)fhp, (caddr_t)np->n_fhp, fhsize))
			continue;
		/* if the node is still being initialized, sleep on it */
		if (np->n_flag & NINIT) {
			np->n_flag |= NWINIT;
			tsleep(np, PINOD, "nfsngt", 0);
			goto loop;
		}
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
	 * allocate and initialize nfsnode and stick it in the hash
	 * before calling getnewvnode().  Anyone finding it in the
	 * hash before initialization is complete will wait for it.
	 */
	MALLOC_ZONE(np, struct nfsnode *, sizeof *np, M_NFSNODE, M_WAITOK);
	bzero((caddr_t)np, sizeof *np);
	np->n_flag |= NINIT;
	np->n_mount = mntp;
	lockinit(&np->n_lock, PINOD, "nfsnode", 0, 0);
	/* lock the new nfsnode */
	lockmgr(&np->n_lock, LK_EXCLUSIVE, NULL, p);

	/* Insert the nfsnode in the hash queue for its new file handle */
	if (fhsize > NFS_SMALLFH) {
		MALLOC_ZONE(np->n_fhp, nfsfh_t *,
				fhsize, M_NFSBIGFH, M_WAITOK);
	} else
		np->n_fhp = &np->n_fh;
	bcopy((caddr_t)fhp, (caddr_t)np->n_fhp, fhsize);
	np->n_fhsize = fhsize;
	LIST_INSERT_HEAD(nhpp, np, n_hash);
	np->n_flag |= NHASHED;

	/* release lock on hash table */
	if (nfs_node_hash_lock < 0)
		wakeup(&nfs_node_hash_lock);
	nfs_node_hash_lock = 0;

	/* now, attempt to get a new vnode */
	error = getnewvnode(VT_NFS, mntp, nfsv2_vnodeop_p, &nvp);
	if (error) {
		LIST_REMOVE(np, n_hash);
		np->n_flag &= ~NHASHED;
		if (np->n_fhsize > NFS_SMALLFH)
			FREE_ZONE((caddr_t)np->n_fhp, np->n_fhsize, M_NFSBIGFH);
		FREE_ZONE(np, sizeof *np, M_NFSNODE);
		*npp = 0;
		return (error);
	}
	vp = nvp;
	vp->v_data = np;
	np->n_vnode = vp;
	*npp = np;

	/* node is now initialized, check if anyone's waiting for it */
	np->n_flag &= ~NINIT;
	if (np->n_flag & NWINIT) {
		np->n_flag &= ~NWINIT;
		wakeup((caddr_t)np);
	}

	return (error);
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
		(void) nfs_vinvalbuf(ap->a_vp, 0, sp->s_cred, p, 1);
		np->n_size = 0;
		ubc_setsize(ap->a_vp, (off_t)0);
		nfs_removeit(sp);
		/*
		 * remove nfsnode from hash now so we can't accidentally find it
		 * again if another object gets created with the same filehandle
		 * before this vnode gets reclaimed
		 */
		LIST_REMOVE(np, n_hash);
		np->n_flag &= ~NHASHED;
		cred = sp->s_cred;
		if (cred != NOCRED) {
			sp->s_cred = NOCRED;
			crfree(cred);
		}
		vrele(sp->s_dvp);
		FREE_ZONE((caddr_t)sp, sizeof (struct sillyrename), M_NFSREQ);
	}
	np->n_flag &= (NMODIFIED | NFLUSHINPROG | NFLUSHWANT | NQNFSEVICTED |
		NQNFSNONCACHE | NQNFSWRITE | NHASHED);
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
	register struct nfsmount *nmp;
	register struct nfsdmap *dp, *dp2;
	extern int prtactive;

	if (prtactive && vp->v_usecount != 0)
		vprint("nfs_reclaim: pushing active", vp);

	if (np->n_flag & NHASHED) {
		LIST_REMOVE(np, n_hash);
		np->n_flag &= ~NHASHED;
	}

        /*
         * In case we block during FREE_ZONEs below, get the entry out
         * of tbe name cache now so subsequent lookups won't find it.
         */ 
        cache_purge(vp); 

	/*
	 * For nqnfs, take it off the timer queue as required.
	 */
	nmp = VFSTONFS(vp->v_mount);
	if (nmp && (nmp->nm_flag & NFSMNT_NQNFS) && np->n_timer.cqe_next != 0) {
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

/*
 * Lock an nfsnode
 */
int
nfs_lock(ap)
	struct vop_lock_args /* {
                struct vnode *a_vp;
                int a_flags;
                struct proc *a_p;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;

	/*
	 * Ugh, another place where interruptible mounts will get hung.
	 * If you make this call interruptible, then you have to fix all
	 * the VOP_LOCK() calls to expect interruptibility.
	 */
	if (vp->v_tag == VT_NON)
		return (ENOENT); /* ??? -- got to check something and error, but what? */
	 
	return(lockmgr(&VTONFS(vp)->n_lock, ap->a_flags, &vp->v_interlock,
                ap->a_p));
	
}

/*
 * Unlock an nfsnode
 */
int
nfs_unlock(ap)
        struct vop_unlock_args /* {
                struct vnode *a_vp;
                int a_flags;
                struct proc *a_p;
        } */ *ap;
{
        struct vnode *vp = ap->a_vp;

        return (lockmgr(&VTONFS(vp)->n_lock, ap->a_flags | LK_RELEASE,
                &vp->v_interlock, ap->a_p));
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
	return (lockstatus(&VTONFS(ap->a_vp)->n_lock));

}
