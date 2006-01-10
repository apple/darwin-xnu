/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
#include <sys/kauth.h>
#include <sys/mount_internal.h>
#include <sys/vnode.h>
#include <sys/ubc.h>
#include <sys/malloc.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfsnode.h>
#include <nfs/nfsmount.h>

LIST_HEAD(nfsnodehashhead, nfsnode) *nfsnodehashtbl;
u_long nfsnodehash;

lck_grp_t * nfs_node_hash_lck_grp;
lck_grp_attr_t * nfs_node_hash_lck_grp_attr;
lck_attr_t * nfs_node_hash_lck_attr;
lck_mtx_t *nfs_node_hash_mutex;

/*
 * Initialize hash links for nfsnodes
 * and build nfsnode free list.
 */
void
nfs_nhinit(void)
{
	nfsnodehashtbl = hashinit(desiredvnodes, M_NFSNODE, &nfsnodehash);

	nfs_node_hash_lck_grp_attr = lck_grp_attr_alloc_init();
	lck_grp_attr_setstat(nfs_node_hash_lck_grp_attr);
	nfs_node_hash_lck_grp = lck_grp_alloc_init("nfs_node_hash", nfs_node_hash_lck_grp_attr);

	nfs_node_hash_lck_attr = lck_attr_alloc_init();

	nfs_node_hash_mutex = lck_mtx_alloc_init(nfs_node_hash_lck_grp, nfs_node_hash_lck_attr);
}

/*
 * Compute an entry in the NFS hash table structure
 */
u_long
nfs_hash(u_char *fhp, int fhsize)
{
	u_long fhsum;
	int i;

	fhsum = 0;
	for (i = 0; i < fhsize; i++)
		fhsum += *fhp++;
	return (fhsum);
}

/*
 * Look up a vnode/nfsnode by file handle.
 * Callers must check for mount points!!
 * In all cases, a pointer to a
 * nfsnode structure is returned.
 */
int
nfs_nget(
	mount_t mntp,
	vnode_t dvp,
	struct componentname *cnp,
	u_char *fhp,
	int fhsize,
	struct nfs_vattr *nvap,
	u_int64_t *xidp,
	int flags,
	struct nfsnode **npp)
{
	struct nfsnode *np;
	struct nfsnodehashhead *nhpp;
	vnode_t vp, nvp;
	int error;
	mount_t mp;
	struct vnode_fsparam vfsp;
	uint32_t vid;

	/* Check for unmount in progress */
	if (!mntp || (mntp->mnt_kern_flag & MNTK_UNMOUNT)) {
		*npp = 0;
		return (!mntp ? ENXIO : EPERM);
	}

	nhpp = NFSNOHASH(nfs_hash(fhp, fhsize));
loop:
	lck_mtx_lock(nfs_node_hash_mutex);
	for (np = nhpp->lh_first; np != 0; np = np->n_hash.le_next) {
		mp = (np->n_flag & NINIT) ? np->n_mount : vnode_mount(NFSTOV(np));
		if (mntp != mp || np->n_fhsize != fhsize ||
		    bcmp(fhp, np->n_fhp, fhsize))
			continue;
		/* if the node is still being initialized, sleep on it */
		if (np->n_flag & NINIT) {
			np->n_flag |= NWINIT;
			msleep(np, nfs_node_hash_mutex, PDROP | PINOD, "nfs_nget", 0);
			goto loop;
		}
		vp = NFSTOV(np);
		vid = vnode_vid(vp);
		lck_mtx_unlock(nfs_node_hash_mutex);
		if ((error = vnode_getwithvid(vp, vid))) {
			/*
			 * If vnode is being reclaimed or has already
			 * changed identity, no need to wait.
			 */
			return (error);
		} 
		/* update attributes */
		error = nfs_loadattrcache(np, nvap, xidp, 0);
		if (error) {
			vnode_put(vp);
		} else {
			if (dvp && cnp && (flags & NG_MAKEENTRY))
				cache_enter(dvp, vp, cnp);
			*npp = np;
		}
		return(error);
	}

	/*
	 * allocate and initialize nfsnode and stick it in the hash
	 * before calling getnewvnode().  Anyone finding it in the
	 * hash before initialization is complete will wait for it.
	 */
	MALLOC_ZONE(np, struct nfsnode *, sizeof *np, M_NFSNODE, M_WAITOK);
	if (!np) {
		lck_mtx_unlock(nfs_node_hash_mutex);
		*npp = 0;
		return (ENOMEM);
	}
	bzero((caddr_t)np, sizeof *np);
	np->n_flag |= NINIT;
	np->n_mount = mntp;

	/* setup node's file handle */
	if (fhsize > NFS_SMALLFH) {
		MALLOC_ZONE(np->n_fhp, u_char *,
				fhsize, M_NFSBIGFH, M_WAITOK);
		if (!np->n_fhp) {
			lck_mtx_unlock(nfs_node_hash_mutex);
			FREE_ZONE(np, sizeof *np, M_NFSNODE);
			*npp = 0;
			return (ENOMEM);
		}
	} else {
		np->n_fhp = &np->n_fh[0];
	}
	bcopy(fhp, np->n_fhp, fhsize);
	np->n_fhsize = fhsize;

	/* Insert the nfsnode in the hash queue for its new file handle */
	np->n_flag |= NHASHED;
	LIST_INSERT_HEAD(nhpp, np, n_hash);

	/* release lock on hash table */
	lck_mtx_unlock(nfs_node_hash_mutex);

	/* do initial loading of attributes */
	error = nfs_loadattrcache(np, nvap, xidp, 1);
	if (error) {
		lck_mtx_lock(nfs_node_hash_mutex);
		LIST_REMOVE(np, n_hash);
		np->n_flag &= ~(NHASHED|NINIT);
		if (np->n_flag & NWINIT) {
			np->n_flag &= ~NWINIT;
			wakeup((caddr_t)np);
		}
		lck_mtx_unlock(nfs_node_hash_mutex);
		if (np->n_fhsize > NFS_SMALLFH)
			FREE_ZONE(np->n_fhp, np->n_fhsize, M_NFSBIGFH);
		FREE_ZONE(np, sizeof *np, M_NFSNODE);
		*npp = 0;
		return (error);
	}
	np->n_mtime = nvap->nva_mtime;
	if (nvap->nva_type == VDIR)
		np->n_ncmtime = nvap->nva_mtime;
	NMODEINVALIDATE(np);

	/* now, attempt to get a new vnode */
	vfsp.vnfs_mp = mntp;
	vfsp.vnfs_vtype = nvap->nva_type;
	vfsp.vnfs_str = "nfs";
	vfsp.vnfs_dvp = dvp;
	vfsp.vnfs_fsnode = np;
	if (nvap->nva_type == VFIFO)
		vfsp.vnfs_vops = fifo_nfsv2nodeop_p;
	else if (nvap->nva_type == VBLK || nvap->nva_type == VCHR)
		vfsp.vnfs_vops = spec_nfsv2nodeop_p;
	else
		vfsp.vnfs_vops = nfsv2_vnodeop_p;
	vfsp.vnfs_markroot = (flags & NG_MARKROOT) ? 1 : 0;
	vfsp.vnfs_marksystem = 0;
	vfsp.vnfs_rdev = 0;
	vfsp.vnfs_filesize = nvap->nva_size;
	vfsp.vnfs_cnp = cnp;
	if (dvp && cnp && (flags & NG_MAKEENTRY))
		vfsp.vnfs_flags = 0;
	else
		vfsp.vnfs_flags = VNFS_NOCACHE;
	error = vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &vfsp, &nvp);
	if (error) {
		lck_mtx_lock(nfs_node_hash_mutex);
		LIST_REMOVE(np, n_hash);
		np->n_flag &= ~(NHASHED|NINIT);
		if (np->n_flag & NWINIT) {
			np->n_flag &= ~NWINIT;
			wakeup((caddr_t)np);
		}
		lck_mtx_unlock(nfs_node_hash_mutex);
		if (np->n_fhsize > NFS_SMALLFH)
			FREE_ZONE(np->n_fhp, np->n_fhsize, M_NFSBIGFH);
		FREE_ZONE(np, sizeof *np, M_NFSNODE);
		*npp = 0;
		return (error);
	}
	vp = nvp;
	np->n_vnode = vp;
	vnode_addfsref(vp);
	vnode_settag(vp, VT_NFS); // XXX shouldn't this be a vnode_create() parameter?
	*npp = np;
	/* node is now initialized */

	/* check if anyone's waiting on this node */
	lck_mtx_lock(nfs_node_hash_mutex);
	np->n_flag &= ~NINIT;
	if (np->n_flag & NWINIT) {
		np->n_flag &= ~NWINIT;
		wakeup((caddr_t)np);
	}
	lck_mtx_unlock(nfs_node_hash_mutex);

	return (error);
}


int
nfs_inactive(ap)
	struct vnop_inactive_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		vfs_context_t a_context;
	} */ *ap;
{
	register struct nfsnode *np;
	register struct sillyrename *sp;
	kauth_cred_t cred;

	np = VTONFS(ap->a_vp);
	if (vnode_vtype(ap->a_vp) != VDIR) {
		sp = np->n_sillyrename;
		np->n_sillyrename = (struct sillyrename *)0;
	} else
		sp = (struct sillyrename *)0;

	if (sp) {
		/*
		 * Remove the silly file that was rename'd earlier
		 */
#if DIAGNOSTIC
		kprintf("nfs_inactive removing %s, dvp=%x, a_vp=%x, ap=%x, np=%x, sp=%x\n",
			&sp->s_name[0], (unsigned)sp->s_dvp, (unsigned)ap->a_vp, (unsigned)ap,
			(unsigned)np, (unsigned)sp);
#endif
		nfs_vinvalbuf(ap->a_vp, 0, sp->s_cred, vfs_context_proc(ap->a_context), 1);
		np->n_size = 0;
		ubc_setsize(ap->a_vp, (off_t)0);
		nfs_removeit(sp);
		/*
		 * remove nfsnode from hash now so we can't accidentally find it
		 * again if another object gets created with the same filehandle
		 * before this vnode gets reclaimed
		 */
		lck_mtx_lock(nfs_node_hash_mutex);
		LIST_REMOVE(np, n_hash);
		np->n_flag &= ~NHASHED;
		lck_mtx_unlock(nfs_node_hash_mutex);
		cred = sp->s_cred;
		if (cred != NOCRED) {
			sp->s_cred = NOCRED;
			kauth_cred_rele(cred);
		}
		vnode_rele(sp->s_dvp);
		FREE_ZONE((caddr_t)sp, sizeof (struct sillyrename), M_NFSREQ);
		vnode_recycle(ap->a_vp);
	}
	/* clear all flags other than these */
	np->n_flag &= (NMODIFIED | NFLUSHINPROG | NFLUSHWANT | NHASHED);
	return (0);
}

/*
 * Reclaim an nfsnode so that it can be used for other purposes.
 */
int
nfs_reclaim(ap)
	struct vnop_reclaim_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		vfs_context_t a_context;
	} */ *ap;
{
	vnode_t vp = ap->a_vp;
	struct nfsnode *np = VTONFS(vp);
	struct nfsdmap *dp, *dp2;

	vnode_removefsref(vp);

	if (np->n_flag & NHASHED) {
		lck_mtx_lock(nfs_node_hash_mutex);
		LIST_REMOVE(np, n_hash);
		np->n_flag &= ~NHASHED;
		lck_mtx_unlock(nfs_node_hash_mutex);
	}

	/*
	 * Free up any directory cookie structures and
	 * large file handle structures that might be associated with
	 * this nfs node.
	 */
	if (vnode_vtype(vp) == VDIR) {
		dp = np->n_cookies.lh_first;
		while (dp) {
			dp2 = dp;
			dp = dp->ndm_list.le_next;
			FREE_ZONE((caddr_t)dp2,
					sizeof (struct nfsdmap), M_NFSDIROFF);
		}
	}
	if (np->n_fhsize > NFS_SMALLFH) {
		FREE_ZONE(np->n_fhp, np->n_fhsize, M_NFSBIGFH);
	}
	vnode_clearfsnode(vp);

	FREE_ZONE(np, sizeof(struct nfsnode), M_NFSNODE);
	return (0);
}

