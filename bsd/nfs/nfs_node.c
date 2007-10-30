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
#include <nfs/nfs_gss.h>
#include <nfs/nfsmount.h>

#define	NFSNOHASH(fhsum) \
	(&nfsnodehashtbl[(fhsum) & nfsnodehash])
static LIST_HEAD(nfsnodehashhead, nfsnode) *nfsnodehashtbl;
static u_long nfsnodehash;

static lck_grp_t *nfs_node_hash_lck_grp;
static lck_grp_t *nfs_node_lck_grp;
lck_mtx_t *nfs_node_hash_mutex;

/*
 * Initialize hash links for nfsnodes
 * and build nfsnode free list.
 */
void
nfs_nhinit(void)
{
	nfs_node_hash_lck_grp = lck_grp_alloc_init("nfs_node_hash", LCK_GRP_ATTR_NULL);
	nfs_node_hash_mutex = lck_mtx_alloc_init(nfs_node_hash_lck_grp, LCK_ATTR_NULL);
	nfs_node_lck_grp = lck_grp_alloc_init("nfs_node", LCK_GRP_ATTR_NULL);
}

void
nfs_nhinit_finish(void)
{
	lck_mtx_lock(nfs_node_hash_mutex);
	if (!nfsnodehashtbl)
		nfsnodehashtbl = hashinit(desiredvnodes, M_NFSNODE, &nfsnodehash);
	lck_mtx_unlock(nfs_node_hash_mutex);
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
	mount_t mp,
	nfsnode_t dnp,
	struct componentname *cnp,
	u_char *fhp,
	int fhsize,
	struct nfs_vattr *nvap,
	u_int64_t *xidp,
	int flags,
	nfsnode_t *npp)
{
	nfsnode_t np;
	struct nfsnodehashhead *nhpp;
	vnode_t vp;
	int error, nfsvers;
	mount_t mp2;
	struct vnode_fsparam vfsp;
	uint32_t vid;

	FSDBG_TOP(263, mp, dnp, flags, npp);

	/* Check for unmount in progress */
	if (!mp || (mp->mnt_kern_flag & MNTK_FRCUNMOUNT)) {
		*npp = NULL;
		error = ENXIO;
		FSDBG_BOT(263, mp, dnp, 0xd1e, error);
		return (error);
	}
	nfsvers = VFSTONFS(mp)->nm_vers;

	nhpp = NFSNOHASH(nfs_hash(fhp, fhsize));
loop:
	lck_mtx_lock(nfs_node_hash_mutex);
	for (np = nhpp->lh_first; np != 0; np = np->n_hash.le_next) {
		mp2 = (np->n_hflag & NHINIT) ? np->n_mount : NFSTOMP(np);
		if (mp != mp2 || np->n_fhsize != fhsize ||
		    bcmp(fhp, np->n_fhp, fhsize))
			continue;
		FSDBG(263, dnp, np, np->n_flag, 0xcace0000);
		/* if the node is locked, sleep on it */
		if (np->n_hflag & NHLOCKED) {
			np->n_hflag |= NHLOCKWANT;
			FSDBG(263, dnp, np, np->n_flag, 0xcace2222);
			msleep(np, nfs_node_hash_mutex, PDROP | PINOD, "nfs_nget", NULL);
			FSDBG(263, dnp, np, np->n_flag, 0xcace3333);
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
			FSDBG_BOT(263, dnp, *npp, 0xcace0d1e, error);
			return (error);
		}
		if ((error = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE))) {
			/* this only fails if the node is now unhashed */
			/* so let's see if we can find/create it again */
			FSDBG(263, dnp, *npp, 0xcaced1e2, error);
			vnode_put(vp);
			goto loop;
		}
		/* update attributes */
		error = nfs_loadattrcache(np, nvap, xidp, 0);
		if (error) {
			nfs_unlock(np);
			vnode_put(vp);
		} else {
			if (dnp && cnp && (flags & NG_MAKEENTRY))
				cache_enter(NFSTOV(dnp), vp, cnp);
			*npp = np;
		}
		FSDBG_BOT(263, dnp, *npp, 0xcace0000, error);
		return(error);
	}

	FSDBG(263, mp, dnp, npp, 0xaaaaaaaa);

	/*
	 * allocate and initialize nfsnode and stick it in the hash
	 * before calling getnewvnode().  Anyone finding it in the
	 * hash before initialization is complete will wait for it.
	 */
	MALLOC_ZONE(np, nfsnode_t, sizeof *np, M_NFSNODE, M_WAITOK);
	if (!np) {
		lck_mtx_unlock(nfs_node_hash_mutex);
		*npp = 0;
		FSDBG_BOT(263, dnp, *npp, 0x80000001, ENOMEM);
		return (ENOMEM);
	}
	bzero(np, sizeof *np);
	np->n_hflag |= (NHINIT | NHLOCKED);
	np->n_mount = mp;

	if (dnp && cnp && ((cnp->cn_namelen != 2) ||
	    (cnp->cn_nameptr[0] != '.') || (cnp->cn_nameptr[1] != '.'))) {
		vnode_t dvp = NFSTOV(dnp);
		if (!vnode_get(dvp)) {
			if (!vnode_ref(dvp))
				np->n_parent = dvp;
			vnode_put(dvp);
		}
	}

	/* setup node's file handle */
	if (fhsize > NFS_SMALLFH) {
		MALLOC_ZONE(np->n_fhp, u_char *,
				fhsize, M_NFSBIGFH, M_WAITOK);
		if (!np->n_fhp) {
			lck_mtx_unlock(nfs_node_hash_mutex);
			FREE_ZONE(np, sizeof *np, M_NFSNODE);
			*npp = 0;
			FSDBG_BOT(263, dnp, *npp, 0x80000002, ENOMEM);
			return (ENOMEM);
		}
	} else {
		np->n_fhp = &np->n_fh[0];
	}
	bcopy(fhp, np->n_fhp, fhsize);
	np->n_fhsize = fhsize;

	/* Insert the nfsnode in the hash queue for its new file handle */
	LIST_INSERT_HEAD(nhpp, np, n_hash);
	np->n_hflag |= NHHASHED;
	FSDBG(266, 0, np, np->n_flag, np->n_hflag);

	/* lock the new nfsnode */
	lck_rw_init(&np->n_lock, nfs_node_lck_grp, LCK_ATTR_NULL);
	lck_rw_init(&np->n_datalock, nfs_node_lck_grp, LCK_ATTR_NULL);
	nfs_lock(np, NFS_NODE_LOCK_FORCE);

	/* release lock on hash table */
	lck_mtx_unlock(nfs_node_hash_mutex);

	/* do initial loading of attributes */
	error = nfs_loadattrcache(np, nvap, xidp, 1);
	if (error) {
		FSDBG(266, 0, np, np->n_flag, 0xb1eb1e);
		nfs_unlock(np);
		lck_mtx_lock(nfs_node_hash_mutex);
		LIST_REMOVE(np, n_hash);
		np->n_hflag &= ~(NHHASHED|NHINIT|NHLOCKED);
		if (np->n_hflag & NHLOCKWANT) {
			np->n_hflag &= ~NHLOCKWANT;
			wakeup(np);
		}
		lck_mtx_unlock(nfs_node_hash_mutex);
		if (np->n_parent) {
			if (!vnode_get(np->n_parent)) {
				vnode_rele(np->n_parent);
				vnode_put(np->n_parent);
			}
			np->n_parent = NULL;
		}
		lck_rw_destroy(&np->n_lock, nfs_node_lck_grp);
		lck_rw_destroy(&np->n_datalock, nfs_node_lck_grp);
		if (np->n_fhsize > NFS_SMALLFH)
			FREE_ZONE(np->n_fhp, np->n_fhsize, M_NFSBIGFH);
		FREE_ZONE(np, sizeof *np, M_NFSNODE);
		*npp = 0;
		FSDBG_BOT(263, dnp, *npp, 0x80000003, error);
		return (error);
	}
	NFS_CHANGED_UPDATE(nfsvers, np, nvap);
	if (nvap->nva_type == VDIR)
		NFS_CHANGED_UPDATE_NC(nfsvers, np, nvap);
	NMODEINVALIDATE(np);

	/* now, attempt to get a new vnode */
	vfsp.vnfs_mp = mp;
	vfsp.vnfs_vtype = nvap->nva_type;
	vfsp.vnfs_str = "nfs";
	vfsp.vnfs_dvp = dnp ? NFSTOV(dnp) : NULL;
	vfsp.vnfs_fsnode = np;
	if (nfsvers == NFS_VER4) {
#if FIFO
		if (nvap->nva_type == VFIFO)
			vfsp.vnfs_vops = fifo_nfsv4nodeop_p;
		else
#endif /* FIFO */
		if (nvap->nva_type == VBLK || nvap->nva_type == VCHR)
			vfsp.vnfs_vops = spec_nfsv4nodeop_p;
		else
			vfsp.vnfs_vops = nfsv4_vnodeop_p;
	} else {
#if FIFO
		if (nvap->nva_type == VFIFO)
			vfsp.vnfs_vops = fifo_nfsv2nodeop_p;
		else
#endif /* FIFO */
		if (nvap->nva_type == VBLK || nvap->nva_type == VCHR)
			vfsp.vnfs_vops = spec_nfsv2nodeop_p;
		else
			vfsp.vnfs_vops = nfsv2_vnodeop_p;
	}
	vfsp.vnfs_markroot = (flags & NG_MARKROOT) ? 1 : 0;
	vfsp.vnfs_marksystem = 0;
	vfsp.vnfs_rdev = 0;
	vfsp.vnfs_filesize = nvap->nva_size;
	vfsp.vnfs_cnp = cnp;
	vfsp.vnfs_flags = VNFS_ADDFSREF;
	if (!dnp || !cnp || !(flags & NG_MAKEENTRY))
		vfsp.vnfs_flags |= VNFS_NOCACHE;

	error = vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &vfsp, &np->n_vnode);
	if (error) {
		FSDBG(266, 0, np, np->n_flag, 0xb1eb1e);
		nfs_unlock(np);
		lck_mtx_lock(nfs_node_hash_mutex);
		LIST_REMOVE(np, n_hash);
		np->n_hflag &= ~(NHHASHED|NHINIT|NHLOCKED);
		if (np->n_hflag & NHLOCKWANT) {
			np->n_hflag &= ~NHLOCKWANT;
			wakeup(np);
		}
		lck_mtx_unlock(nfs_node_hash_mutex);
		if (np->n_parent) {
			if (!vnode_get(np->n_parent)) {
				vnode_rele(np->n_parent);
				vnode_put(np->n_parent);
			}
			np->n_parent = NULL;
		}
		lck_rw_destroy(&np->n_lock, nfs_node_lck_grp);
		lck_rw_destroy(&np->n_datalock, nfs_node_lck_grp);
		if (np->n_fhsize > NFS_SMALLFH)
			FREE_ZONE(np->n_fhp, np->n_fhsize, M_NFSBIGFH);
		FREE_ZONE(np, sizeof *np, M_NFSNODE);
		*npp = 0;
		FSDBG_BOT(263, dnp, *npp, 0x80000004, error);
		return (error);
	}
	vp = np->n_vnode;
	vnode_settag(vp, VT_NFS);
	/* node is now initialized */

	/* check if anyone's waiting on this node */
	lck_mtx_lock(nfs_node_hash_mutex);
	np->n_hflag &= ~(NHINIT|NHLOCKED);
	if (np->n_hflag & NHLOCKWANT) {
		np->n_hflag &= ~NHLOCKWANT;
		wakeup(np);
	}
	lck_mtx_unlock(nfs_node_hash_mutex);

	*npp = np;

	FSDBG_BOT(263, dnp, vp, *npp, error);
	return (error);
}


int
nfs_vnop_inactive(ap)
	struct vnop_inactive_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		vfs_context_t a_context;
	} */ *ap;
{
	vnode_t vp;
	nfsnode_t np;
	struct nfs_sillyrename *nsp;
	struct nfs_vattr nvattr;
	int unhash, attrerr;

	vp = ap->a_vp;
	np = VTONFS(ap->a_vp);

	nfs_lock(np, NFS_NODE_LOCK_FORCE);

	if (vnode_vtype(vp) != VDIR) {
		nsp = np->n_sillyrename;
		np->n_sillyrename = NULL;
	} else
		nsp = NULL;

	FSDBG_TOP(264, vp, np, np->n_flag, nsp);

	if (!nsp) {
		/* no silly file to clean up... */
		/* clear all flags other than these */
		np->n_flag &= (NMODIFIED);
		nfs_unlock(np);
		FSDBG_BOT(264, vp, np, np->n_flag, 0);
		return (0);
	}

	/* Remove the silly file that was rename'd earlier */

	/* flush all the buffers */
	nfs_unlock(np);
	nfs_vinvalbuf2(vp, V_SAVE, vfs_context_thread(ap->a_context), nsp->nsr_cred, 1);

	/* purge the name cache to deter others from finding it */
	cache_purge(vp);

	/* try to get the latest attributes */
	attrerr = nfs_getattr(np, &nvattr, ap->a_context, 0);

	/* Check if we should remove it from the node hash. */
	/* Leave it if inuse or it has multiple hard links. */
	if (vnode_isinuse(vp, 0) || (!attrerr && (nvattr.nva_nlink > 1))) {
		unhash = 0;
	} else {
		unhash = 1;
		ubc_setsize(vp, 0);
	}

	/* grab node lock on this node and the directory */
	nfs_lock2(nsp->nsr_dnp, np, NFS_NODE_LOCK_FORCE);

	/* lock the node while we remove the silly file */
	lck_mtx_lock(nfs_node_hash_mutex);
	while (np->n_hflag & NHLOCKED) {
		np->n_hflag |= NHLOCKWANT;
		msleep(np, nfs_node_hash_mutex, PINOD, "nfs_inactive", NULL);
	}
	np->n_hflag |= NHLOCKED;
	lck_mtx_unlock(nfs_node_hash_mutex);

	/* purge again in case it was looked up while we were locking */
	cache_purge(vp);

	FSDBG(264, np, np->n_size, np->n_vattr.nva_size, 0xf00d00f1);

	/* now remove the silly file */
	nfs_removeit(nsp);

	/* clear all flags other than these */
	np->n_flag &= (NMODIFIED);
	nfs_unlock2(nsp->nsr_dnp, np);

	if (unhash && vnode_isinuse(vp, 0)) {
		/* vnode now inuse after silly remove? */
		unhash = 0;
		ubc_setsize(vp, np->n_size);
	}

	lck_mtx_lock(nfs_node_hash_mutex);
	if (unhash) {
		/*
		 * remove nfsnode from hash now so we can't accidentally find it
		 * again if another object gets created with the same filehandle
		 * before this vnode gets reclaimed
		 */
		if (np->n_hflag & NHHASHED) {
			LIST_REMOVE(np, n_hash);
			np->n_hflag &= ~NHHASHED;
			FSDBG(266, 0, np, np->n_flag, 0xb1eb1e);
		}
		vnode_recycle(vp);
	}
	/* unlock the node */
	np->n_hflag &= ~NHLOCKED;
	if (np->n_hflag & NHLOCKWANT) {
		np->n_hflag &= ~NHLOCKWANT;
		wakeup(np);
	}
	lck_mtx_unlock(nfs_node_hash_mutex);

	/* cleanup sillyrename info */
	if (nsp->nsr_cred != NOCRED)
		kauth_cred_unref(&nsp->nsr_cred);
	vnode_rele(NFSTOV(nsp->nsr_dnp));
	FREE_ZONE(nsp, sizeof(*nsp), M_NFSREQ);

	FSDBG_BOT(264, vp, np, np->n_flag, 0);
	return (0);
}

/*
 * Reclaim an nfsnode so that it can be used for other purposes.
 */
int
nfs_vnop_reclaim(ap)
	struct vnop_reclaim_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		vfs_context_t a_context;
	} */ *ap;
{
	vnode_t vp = ap->a_vp;
	nfsnode_t np = VTONFS(vp);
	struct nfsdmap *dp, *dp2;

	FSDBG_TOP(265, vp, np, np->n_flag, 0);

	lck_mtx_lock(nfs_node_hash_mutex);

	if ((vnode_vtype(vp) != VDIR) && np->n_sillyrename)
		printf("nfs_reclaim: leaving unlinked file %s\n", np->n_sillyrename->nsr_name);

	vnode_removefsref(vp);

	if (np->n_hflag & NHHASHED) {
		LIST_REMOVE(np, n_hash);
		np->n_hflag &= ~NHHASHED;
		FSDBG(266, 0, np, np->n_flag, 0xb1eb1e);
	}
	lck_mtx_unlock(nfs_node_hash_mutex);

	/*
	 * Free up any directory cookie structures and
	 * large file handle structures that might be associated with
	 * this nfs node.
	 */
	nfs_lock(np, NFS_NODE_LOCK_FORCE);
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

	nfs_unlock(np);
	vnode_clearfsnode(vp);

	if (np->n_parent) {
		if (!vnode_get(np->n_parent)) {
			vnode_rele(np->n_parent);
			vnode_put(np->n_parent);
		}
		np->n_parent = NULL;
	}

	lck_rw_destroy(&np->n_lock, nfs_node_lck_grp);
	lck_rw_destroy(&np->n_datalock, nfs_node_lck_grp);

	FSDBG_BOT(265, vp, np, np->n_flag, 0xd1ed1e);
	FREE_ZONE(np, sizeof(struct nfsnode), M_NFSNODE);
	return (0);
}

/*
 * Acquire an NFS node lock
 */
int
nfs_lock(nfsnode_t np, int locktype)
{
	FSDBG_TOP(268, np, locktype, np->n_lockowner, 0);
	if (locktype == NFS_NODE_LOCK_SHARED) {
		lck_rw_lock_shared(&np->n_lock);
	} else {
		lck_rw_lock_exclusive(&np->n_lock);
		np->n_lockowner = current_thread();
	}
	if ((locktype != NFS_NODE_LOCK_FORCE) && !(np->n_hflag && NHHASHED)) {
		FSDBG_BOT(268, np, 0xdead, np->n_lockowner, 0);
		nfs_unlock(np);
		return (ENOENT);
	}
	FSDBG_BOT(268, np, locktype, np->n_lockowner, 0);
	return (0);
}

/*
 * Release an NFS node lock
 */
void
nfs_unlock(nfsnode_t np)
{
	FSDBG(269, np, np->n_lockowner, current_thread(), 0);
	np->n_lockowner = NULL;
	lck_rw_done(&np->n_lock);
}

/*
 * Acquire 2 NFS node locks
 *   - locks taken in order given (assumed to be parent-child order)
 *   - both or neither of the locks are taken
 *   - only one lock taken per node (dup nodes are skipped)
 */
int
nfs_lock2(nfsnode_t np1, nfsnode_t np2, int locktype)
{
	int error;

	if ((error = nfs_lock(np1, locktype)))
		return (error);
	if (np1 == np2)
		return (error);
	if ((error = nfs_lock(np2, locktype)))
		nfs_unlock(np1);
	return (error);
}

/*
 * Unlock a couple of NFS nodes
 */
void
nfs_unlock2(nfsnode_t np1, nfsnode_t np2)
{
	nfs_unlock(np1);
	if (np1 != np2)
		nfs_unlock(np2);
}

/*
 * Acquire 4 NFS node locks
 *   - fdnp/fnp and tdnp/tnp locks taken in order given
 *   - otherwise locks taken in node address order.
 *   - all or none of the locks are taken
 *   - only one lock taken per node (dup nodes are skipped)
 *   - some of the node pointers may be null
 */
int
nfs_lock4(nfsnode_t fdnp, nfsnode_t fnp, nfsnode_t tdnp, nfsnode_t tnp, int locktype)
{
	nfsnode_t list[4];
	int i, lcnt = 0, error;

	if (fdnp == tdnp) {
		list[lcnt++] = fdnp;
	} else if (fdnp->n_parent && (tdnp == VTONFS(fdnp->n_parent))) {
		list[lcnt++] = tdnp;
		list[lcnt++] = fdnp;
	} else if (tdnp->n_parent && (fdnp == VTONFS(tdnp->n_parent))) {
		list[lcnt++] = fdnp;
		list[lcnt++] = tdnp;
	} else if (fdnp < tdnp) {
		list[lcnt++] = fdnp;
		list[lcnt++] = tdnp;
	} else {
		list[lcnt++] = tdnp;
		list[lcnt++] = fdnp;
	}

	if (!tnp || (fnp == tnp) || (tnp == fdnp)) {
		list[lcnt++] = fnp;
	} else if (fnp < tnp) {
		list[lcnt++] = fnp;
		list[lcnt++] = tnp;
	} else {
		list[lcnt++] = tnp;
		list[lcnt++] = fnp;
	}

	/* Now we can lock using list[0 - lcnt-1] */
	for (i = 0; i < lcnt; ++i) {
		if (list[i])
			if ((error = nfs_lock(list[i], locktype))) {
				/* Drop any locks we acquired. */
				while (--i >= 0) {
					if (list[i])
						nfs_unlock(list[i]);
				}
				return (error);
			}
	}
	return (0);
}

/*
 * Unlock a group of NFS nodes
 */
void
nfs_unlock4(nfsnode_t np1, nfsnode_t np2, nfsnode_t np3, nfsnode_t np4)
{
	nfsnode_t list[4];
	int i, k = 0;
	
	if (np1) {
		nfs_unlock(np1);
		list[k++] = np1;
	}
	if (np2) {
		for (i = 0; i < k; ++i)
			if (list[i] == np2)
				goto skip2;
		nfs_unlock(np2);
		list[k++] = np2;
	}
skip2:
	if (np3) {
		for (i = 0; i < k; ++i)
			if (list[i] == np3)
				goto skip3;
		nfs_unlock(np3);
		list[k++] = np3;
	}
skip3:
	if (np4) {
		for (i = 0; i < k; ++i)
			if (list[i] == np4)
				return;
		nfs_unlock(np4);
	}
}

/*
 * Acquire an NFS node data lock
 */
void
nfs_data_lock(nfsnode_t np, int locktype)
{
	nfs_data_lock2(np, locktype, 1);
}
void
nfs_data_lock2(nfsnode_t np, int locktype, int updatesize)
{
	FSDBG_TOP(270, np, locktype, np->n_datalockowner, 0);
	if (locktype == NFS_NODE_LOCK_SHARED) {
		if (updatesize && ISSET(np->n_flag, NUPDATESIZE))
			nfs_data_update_size(np, 0);
		lck_rw_lock_shared(&np->n_datalock);
	} else {
		lck_rw_lock_exclusive(&np->n_datalock);
		np->n_datalockowner = current_thread();
		if (updatesize && ISSET(np->n_flag, NUPDATESIZE))
			nfs_data_update_size(np, 1);
	}
	FSDBG_BOT(270, np, locktype, np->n_datalockowner, 0);
}

/*
 * Release an NFS node data lock
 */
void
nfs_data_unlock(nfsnode_t np)
{
	nfs_data_unlock2(np, 1);
}
void
nfs_data_unlock2(nfsnode_t np, int updatesize)
{
	int mine = (np->n_datalockowner == current_thread());
	FSDBG_TOP(271, np, np->n_datalockowner, current_thread(), 0);
	if (updatesize && mine && ISSET(np->n_flag, NUPDATESIZE))
		nfs_data_update_size(np, 1);
	np->n_datalockowner = NULL;
	lck_rw_done(&np->n_datalock);
	if (updatesize && !mine && ISSET(np->n_flag, NUPDATESIZE))
		nfs_data_update_size(np, 0);
	FSDBG_BOT(271, np, np->n_datalockowner, current_thread(), 0);
}


/*
 * update an NFS node's size
 */
void
nfs_data_update_size(nfsnode_t np, int datalocked)
{
	int error;

	FSDBG_TOP(272, np, np->n_flag, np->n_size, np->n_newsize);
	if (!datalocked) {
		nfs_data_lock(np, NFS_NODE_LOCK_EXCLUSIVE);
		/* grabbing data lock will automatically update size */
		nfs_data_unlock(np);
		FSDBG_BOT(272, np, np->n_flag, np->n_size, np->n_newsize);
		return;
	}
	error = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE);
	if (error || !ISSET(np->n_flag, NUPDATESIZE)) {
		if (!error)
			nfs_unlock(np);
		FSDBG_BOT(272, np, np->n_flag, np->n_size, np->n_newsize);
		return;
	}
	CLR(np->n_flag, NUPDATESIZE);
	np->n_size = np->n_newsize;
	/* make sure we invalidate buffers the next chance we get */
	SET(np->n_flag, NNEEDINVALIDATE);
	nfs_unlock(np);
	ubc_setsize(NFSTOV(np), (off_t)np->n_size); /* XXX error? */
	FSDBG_BOT(272, np, np->n_flag, np->n_size, np->n_newsize);
}

