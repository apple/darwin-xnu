/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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
#include <sys/kernel.h>
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
static lck_grp_t *nfs_data_lck_grp;
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
	nfs_data_lck_grp = lck_grp_alloc_init("nfs_data", LCK_GRP_ATTR_NULL);
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
		if ((np->n_hflag & NHLOCKED) && !(flags & NG_NOCREATE)) {
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
		if ((error = nfs_node_lock(np))) {
			/* this only fails if the node is now unhashed */
			/* so let's see if we can find/create it again */
			FSDBG(263, dnp, *npp, 0xcaced1e2, error);
			vnode_put(vp);
			if (flags & NG_NOCREATE) {
				*npp = 0;
				FSDBG_BOT(263, dnp, *npp, 0xcaced1e0, ENOENT);
				return (ENOENT);
			}
			goto loop;
		}
		/* update attributes */
		if (nvap)
			error = nfs_loadattrcache(np, nvap, xidp, 0);
		if (error) {
			nfs_node_unlock(np);
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

	if (flags & NG_NOCREATE) {
		lck_mtx_unlock(nfs_node_hash_mutex);
		*npp = 0;
		FSDBG_BOT(263, dnp, *npp, 0x80000001, ENOENT);
		return (ENOENT);
	}

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
	TAILQ_INIT(&np->n_opens);
	TAILQ_INIT(&np->n_lock_owners);
	TAILQ_INIT(&np->n_locks);
	np->n_dlink.tqe_next = NFSNOLIST;

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
	lck_mtx_init(&np->n_lock, nfs_node_lck_grp, LCK_ATTR_NULL);
	lck_rw_init(&np->n_datalock, nfs_data_lck_grp, LCK_ATTR_NULL);
	lck_mtx_init(&np->n_openlock, nfs_open_grp, LCK_ATTR_NULL);
	lck_mtx_lock(&np->n_lock);

	/* release lock on hash table */
	lck_mtx_unlock(nfs_node_hash_mutex);

	/* do initial loading of attributes */
	error = nfs_loadattrcache(np, nvap, xidp, 1);
	if (error) {
		FSDBG(266, 0, np, np->n_flag, 0xb1eb1e);
		nfs_node_unlock(np);
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
		lck_mtx_destroy(&np->n_lock, nfs_node_lck_grp);
		lck_rw_destroy(&np->n_datalock, nfs_data_lck_grp);
		lck_mtx_destroy(&np->n_openlock, nfs_open_grp);
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
		nfs_node_unlock(np);
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
		lck_mtx_destroy(&np->n_lock, nfs_node_lck_grp);
		lck_rw_destroy(&np->n_datalock, nfs_data_lck_grp);
		lck_mtx_destroy(&np->n_openlock, nfs_open_grp);
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
	vnode_t vp = ap->a_vp;
	vfs_context_t ctx = ap->a_context;
	nfsnode_t np = VTONFS(ap->a_vp);
	struct nfs_sillyrename *nsp;
	struct nfs_vattr nvattr;
	int unhash, attrerr, busyerror, error, inuse, busied;
	struct nfs_open_file *nofp;
	const char *vname = NULL;
	struct componentname cn;
	struct nfsmount *nmp = NFSTONMP(np);

restart:
	error = 0;
	inuse = ((nmp->nm_vers >= NFS_VER4) && (nfs_mount_state_in_use_start(nmp) == 0));

	/* There shouldn't be any open or lock state at this point */
	lck_mtx_lock(&np->n_openlock);
	if (np->n_openrefcnt) {
		vname = vnode_getname(vp);
		printf("nfs_vnop_inactive: still open: %d %s\n", np->n_openrefcnt, vname ? vname : "//");
	}
	TAILQ_FOREACH(nofp, &np->n_opens, nof_link) {
		lck_mtx_lock(&nofp->nof_lock);
		if (nofp->nof_flags & NFS_OPEN_FILE_BUSY) {
			if (!vname)
				vname = vnode_getname(vp);
			printf("nfs_vnop_inactive: open file busy: %s\n", vname ? vname : "//");
			busied = 0;
		} else {
			nofp->nof_flags |= NFS_OPEN_FILE_BUSY;
			busied = 1;
		}
		lck_mtx_unlock(&nofp->nof_lock);
		/*
		 * If we just created the file, we already had it open in
		 * anticipation of getting a subsequent open call.  If the
		 * node has gone inactive without being open, we need to
		 * clean up (close) the open done in the create.
		 */
		if ((nofp->nof_flags & NFS_OPEN_FILE_CREATE) && nofp->nof_creator) {
			if (nofp->nof_flags & NFS_OPEN_FILE_REOPEN) {
				lck_mtx_unlock(&np->n_openlock);
				if (busied)
					nfs_open_file_clear_busy(nofp);
				if (inuse)
					nfs_mount_state_in_use_end(nmp, 0);
				nfs4_reopen(nofp, vfs_context_thread(ctx));
				goto restart;
			}
			nofp->nof_flags &= ~NFS_OPEN_FILE_CREATE;
			lck_mtx_unlock(&np->n_openlock);
			error = nfs4_close(np, nofp, NFS_OPEN_SHARE_ACCESS_BOTH, NFS_OPEN_SHARE_DENY_NONE, ctx);
			if (error) {
				if (!vname)
					vname = vnode_getname(vp);
				printf("nfs_vnop_inactive: create close error: %d, %s\n", error, vname);
				nofp->nof_flags |= NFS_OPEN_FILE_CREATE;
			}
			if (busied)
				nfs_open_file_clear_busy(nofp);
			if (inuse)
				nfs_mount_state_in_use_end(nmp, error);
			goto restart;
		}
		if (nofp->nof_flags & NFS_OPEN_FILE_NEEDCLOSE) {
			/*
			 * If the file is marked as needing reopen, but this was the only
			 * open on the file, just drop the open.
			 */
			nofp->nof_flags &= ~NFS_OPEN_FILE_NEEDCLOSE;
			if ((nofp->nof_flags & NFS_OPEN_FILE_REOPEN) && (nofp->nof_opencnt == 1)) {
				nofp->nof_flags &= ~NFS_OPEN_FILE_REOPEN;
				nofp->nof_r--;
				nofp->nof_opencnt--;
				nofp->nof_access = 0;
			} else {
				lck_mtx_unlock(&np->n_openlock);
				if (nofp->nof_flags & NFS_OPEN_FILE_REOPEN) {
					if (busied)
						nfs_open_file_clear_busy(nofp);
					if (inuse)
						nfs_mount_state_in_use_end(nmp, 0);
					nfs4_reopen(nofp, vfs_context_thread(ctx));
					goto restart;
				}
				error = nfs4_close(np, nofp, NFS_OPEN_SHARE_ACCESS_READ, NFS_OPEN_SHARE_DENY_NONE, ctx);
				if (error) {
					if (!vname)
						vname = vnode_getname(vp);
					printf("nfs_vnop_inactive: need close error: %d, %s\n", error, vname);
					nofp->nof_flags |= NFS_OPEN_FILE_NEEDCLOSE;
				}
				if (busied)
					nfs_open_file_clear_busy(nofp);
				if (inuse)
					nfs_mount_state_in_use_end(nmp, error);
				goto restart;
			}
		}
		if (nofp->nof_opencnt) {
			if (!vname)
				vname = vnode_getname(vp);
			printf("nfs_vnop_inactive: file still open: %d %s\n", nofp->nof_opencnt, vname ? vname : "//");
		}
		if (nofp->nof_access || nofp->nof_deny ||
		    nofp->nof_mmap_access || nofp->nof_mmap_deny ||
		    nofp->nof_r || nofp->nof_w || nofp->nof_rw ||
		    nofp->nof_r_dw || nofp->nof_w_dw || nofp->nof_rw_dw ||
		    nofp->nof_r_drw || nofp->nof_w_drw || nofp->nof_rw_drw) {
			if (!vname)
				vname = vnode_getname(vp);
			printf("nfs_vnop_inactive: non-zero access: %d %d %d %d # %u %u %u dw %u %u %u drw %u %u %u %s\n",
				nofp->nof_access, nofp->nof_deny,
				nofp->nof_mmap_access, nofp->nof_mmap_deny,
				nofp->nof_r, nofp->nof_w, nofp->nof_rw,
				nofp->nof_r_dw, nofp->nof_w_dw, nofp->nof_rw_dw,
				nofp->nof_r_drw, nofp->nof_w_drw, nofp->nof_rw_drw,
				vname ? vname : "//");
		}
		if (busied)
			nfs_open_file_clear_busy(nofp);
	}
	lck_mtx_unlock(&np->n_openlock);
	if (vname)
		vnode_putname(vname);

	if (inuse && nfs_mount_state_in_use_end(nmp, error))
		goto restart;

	nfs_node_lock_force(np);

	if (vnode_vtype(vp) != VDIR) {
		nsp = np->n_sillyrename; 
		np->n_sillyrename = NULL;
	} else {
		nsp = NULL;
	}

	FSDBG_TOP(264, vp, np, np->n_flag, nsp);

	if (!nsp) {
		/* no silly file to clean up... */
		/* clear all flags other than these */
		np->n_flag &= (NMODIFIED);
		nfs_node_unlock(np);
		FSDBG_BOT(264, vp, np, np->n_flag, 0);
		return (0);
	}
	nfs_node_unlock(np);

	/* Remove the silly file that was rename'd earlier */

	/* flush all the buffers */
	nfs_vinvalbuf2(vp, V_SAVE, vfs_context_thread(ctx), nsp->nsr_cred, 1);

	/* try to get the latest attributes */
	attrerr = nfs_getattr(np, &nvattr, ctx, NGA_UNCACHED);

	/* Check if we should remove it from the node hash. */
	/* Leave it if inuse or it has multiple hard links. */
	if (vnode_isinuse(vp, 0) || (!attrerr && (nvattr.nva_nlink > 1))) {
		unhash = 0;
	} else {
		unhash = 1;
		ubc_setsize(vp, 0);
	}

	/* mark this node and the directory busy while we do the remove */
	busyerror = nfs_node_set_busy2(nsp->nsr_dnp, np, vfs_context_thread(ctx));

	/* lock the node while we remove the silly file */
	lck_mtx_lock(nfs_node_hash_mutex);
	while (np->n_hflag & NHLOCKED) {
		np->n_hflag |= NHLOCKWANT;
		msleep(np, nfs_node_hash_mutex, PINOD, "nfs_inactive", NULL);
	}
	np->n_hflag |= NHLOCKED;
	lck_mtx_unlock(nfs_node_hash_mutex);

	/* purge the name cache to deter others from finding it */
	bzero(&cn, sizeof(cn));
	cn.cn_nameptr = nsp->nsr_name;
	cn.cn_namelen = nsp->nsr_namlen;
	nfs_name_cache_purge(nsp->nsr_dnp, np, &cn, ctx);

	FSDBG(264, np, np->n_size, np->n_vattr.nva_size, 0xf00d00f1);

	/* now remove the silly file */
	nfs_removeit(nsp);

	/* clear all flags other than these */
	nfs_node_lock_force(np);
	np->n_flag &= (NMODIFIED);
	nfs_node_unlock(np);

	if (!busyerror)
		nfs_node_clear_busy2(nsp->nsr_dnp, np);

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
	vfs_context_t ctx = ap->a_context;
	struct nfs_open_file *nofp, *nextnofp;
	struct nfs_file_lock *nflp, *nextnflp;
	struct nfs_lock_owner *nlop, *nextnlop;
	const char *vname = NULL;
	struct nfsmount *nmp = np->n_mount ? VFSTONFS(np->n_mount) : NFSTONMP(np);

	FSDBG_TOP(265, vp, np, np->n_flag, 0);

	/* There shouldn't be any open or lock state at this point */
	lck_mtx_lock(&np->n_openlock);

	if (nmp && (nmp->nm_vers >= NFS_VER4)) {
		/* need to drop a delegation */
		if (np->n_dlink.tqe_next != NFSNOLIST) {
			/* remove this node from the recall list */
			lck_mtx_lock(&nmp->nm_lock);
			if (np->n_dlink.tqe_next != NFSNOLIST) {
				TAILQ_REMOVE(&nmp->nm_recallq, np, n_dlink);
				np->n_dlink.tqe_next = NFSNOLIST;
			}
			lck_mtx_unlock(&nmp->nm_lock);
		}
		if (np->n_openflags & N_DELEG_MASK) {
			np->n_openflags &= ~N_DELEG_MASK;
			nfs4_delegreturn_rpc(nmp, np->n_fhp, np->n_fhsize, &np->n_dstateid,
				vfs_context_thread(ctx), vfs_context_ucred(ctx));
		}
	}

	/* clean up file locks */
	TAILQ_FOREACH_SAFE(nflp, &np->n_locks, nfl_link, nextnflp) {
		if (!(nflp->nfl_flags & NFS_FILE_LOCK_DEAD)) {
			if (!vname)
				vname = vnode_getname(vp);
			printf("nfs_vnop_reclaim: lock 0x%llx 0x%llx 0x%x (bc %d) %s\n",
				nflp->nfl_start, nflp->nfl_end, nflp->nfl_flags,
				nflp->nfl_blockcnt, vname ? vname : "//");
		}
		if (!(nflp->nfl_flags & NFS_FILE_LOCK_BLOCKED)) {
			lck_mtx_lock(&nflp->nfl_owner->nlo_lock);
			TAILQ_REMOVE(&nflp->nfl_owner->nlo_locks, nflp, nfl_lolink);
			lck_mtx_unlock(&nflp->nfl_owner->nlo_lock);
		}
		TAILQ_REMOVE(&np->n_locks, nflp, nfl_link);
		nfs_file_lock_destroy(nflp);
	}
	/* clean up lock owners */
	TAILQ_FOREACH_SAFE(nlop, &np->n_lock_owners, nlo_link, nextnlop) {
		if (!TAILQ_EMPTY(&nlop->nlo_locks)) {
			if (!vname)
				vname = vnode_getname(vp);
			printf("nfs_vnop_reclaim: lock owner with locks %s\n",
				vname ? vname : "//");
		}
		TAILQ_REMOVE(&np->n_lock_owners, nlop, nlo_link);
		nfs_lock_owner_destroy(nlop);
	}
	/* clean up open state */
	if (np->n_openrefcnt) {
		if (!vname)
			vname = vnode_getname(vp);
		printf("nfs_vnop_reclaim: still open: %d %s\n",
			np->n_openrefcnt, vname ? vname : "//");
	}
	TAILQ_FOREACH_SAFE(nofp, &np->n_opens, nof_link, nextnofp) {
		if (nofp->nof_flags & NFS_OPEN_FILE_BUSY) {
			if (!vname)
				vname = vnode_getname(vp);
			printf("nfs_vnop_reclaim: open file busy: %s\n",
				vname ? vname : "//");
		}
		if (nofp->nof_opencnt) {
			if (!vname)
				vname = vnode_getname(vp);
			printf("nfs_vnop_reclaim: file still open: %d %s\n",
				nofp->nof_opencnt, vname ? vname : "//");
		}
		if (nofp->nof_access || nofp->nof_deny ||
		    nofp->nof_mmap_access || nofp->nof_mmap_deny ||
		    nofp->nof_r || nofp->nof_w || nofp->nof_rw ||
		    nofp->nof_r_dw || nofp->nof_w_dw || nofp->nof_rw_dw ||
		    nofp->nof_r_drw || nofp->nof_w_drw || nofp->nof_rw_drw) {
			if (!vname)
				vname = vnode_getname(vp);
			printf("nfs_vnop_reclaim: non-zero access: %d %d %d %d # %u %u %u dw %u %u %u drw %u %u %u %s\n",
				nofp->nof_access, nofp->nof_deny,
				nofp->nof_mmap_access, nofp->nof_mmap_deny,
				nofp->nof_r, nofp->nof_w, nofp->nof_rw,
				nofp->nof_r_dw, nofp->nof_w_dw, nofp->nof_rw_dw,
				nofp->nof_r_drw, nofp->nof_w_drw, nofp->nof_rw_drw,
				vname ? vname : "//");
		}
		TAILQ_REMOVE(&np->n_opens, nofp, nof_link);
		nfs_open_file_destroy(nofp);
	}
	lck_mtx_unlock(&np->n_openlock);

	lck_mtx_lock(nfs_buf_mutex);
	if (!LIST_EMPTY(&np->n_dirtyblkhd) || !LIST_EMPTY(&np->n_cleanblkhd)) {
		if (!vname)
			vname = vnode_getname(vp);
		printf("nfs_reclaim: dropping %s buffers for file %s\n",
			(!LIST_EMPTY(&np->n_dirtyblkhd) ? "dirty" : "clean"),
			(vname ? vname : "//"));
	}
	lck_mtx_unlock(nfs_buf_mutex);
	if (vname)
		vnode_putname(vname);
	nfs_vinvalbuf(vp, V_IGNORE_WRITEERR, ap->a_context, 0);

	lck_mtx_lock(nfs_node_hash_mutex);

	if ((vnode_vtype(vp) != VDIR) && np->n_sillyrename) {
		printf("nfs_reclaim: leaving unlinked file %s\n", np->n_sillyrename->nsr_name);
		if (np->n_sillyrename->nsr_cred != NOCRED)
			kauth_cred_unref(&np->n_sillyrename->nsr_cred);
		vnode_rele(NFSTOV(np->n_sillyrename->nsr_dnp));
		FREE_ZONE(np->n_sillyrename, sizeof(*np->n_sillyrename), M_NFSREQ);
	}

	vnode_removefsref(vp);

	if (np->n_hflag & NHHASHED) {
		LIST_REMOVE(np, n_hash);
		np->n_hflag &= ~NHHASHED;
		FSDBG(266, 0, np, np->n_flag, 0xb1eb1e);
	}
	lck_mtx_unlock(nfs_node_hash_mutex);

	/*
	 * Free up any directory cookie structures and large file handle
	 * structures that might be associated with this nfs node.
	 */
	nfs_node_lock_force(np);
	if ((vnode_vtype(vp) == VDIR) && np->n_cookiecache)
		FREE_ZONE(np->n_cookiecache, sizeof(struct nfsdmap), M_NFSDIROFF);
	if (np->n_fhsize > NFS_SMALLFH)
		FREE_ZONE(np->n_fhp, np->n_fhsize, M_NFSBIGFH);
	nfs_node_unlock(np);
	vnode_clearfsnode(vp);

	if (np->n_parent) {
		if (!vnode_get(np->n_parent)) {
			vnode_rele(np->n_parent);
			vnode_put(np->n_parent);
		}
		np->n_parent = NULL;
	}

	lck_mtx_destroy(&np->n_lock, nfs_node_lck_grp);
	lck_rw_destroy(&np->n_datalock, nfs_data_lck_grp);
	lck_mtx_destroy(&np->n_openlock, nfs_open_grp);

	FSDBG_BOT(265, vp, np, np->n_flag, 0xd1ed1e);
	FREE_ZONE(np, sizeof(struct nfsnode), M_NFSNODE);
	return (0);
}

/*
 * Acquire an NFS node lock
 */

int
nfs_node_lock_internal(nfsnode_t np, int force)
{
	FSDBG_TOP(268, np, force, 0, 0);
	lck_mtx_lock(&np->n_lock);
	if (!force && !(np->n_hflag && NHHASHED)) {
		FSDBG_BOT(268, np, 0xdead, 0, 0);
		lck_mtx_unlock(&np->n_lock);
		return (ENOENT);
	}
	FSDBG_BOT(268, np, force, 0, 0);
	return (0);
}

int
nfs_node_lock(nfsnode_t np)
{
	return nfs_node_lock_internal(np, 0);
}

void
nfs_node_lock_force(nfsnode_t np)
{
	nfs_node_lock_internal(np, 1);
}

/*
 * Release an NFS node lock
 */
void
nfs_node_unlock(nfsnode_t np)
{
	FSDBG(269, np, current_thread(), 0, 0);
	lck_mtx_unlock(&np->n_lock);
}

/*
 * Acquire 2 NFS node locks
 *   - locks taken in reverse address order
 *   - both or neither of the locks are taken
 *   - only one lock taken per node (dup nodes are skipped)
 */
int
nfs_node_lock2(nfsnode_t np1, nfsnode_t np2)
{
	nfsnode_t first, second;
	int error;

	first = (np1 > np2) ? np1 : np2;
	second = (np1 > np2) ? np2 : np1;
	if ((error = nfs_node_lock(first)))
		return (error);
	if (np1 == np2)
		return (error);
	if ((error = nfs_node_lock(second)))
		nfs_node_unlock(first);
	return (error);
}

void
nfs_node_unlock2(nfsnode_t np1, nfsnode_t np2)
{
	nfs_node_unlock(np1);
	if (np1 != np2)
		nfs_node_unlock(np2);
}

/*
 * Manage NFS node busy state.
 * (Similar to NFS node locks above)
 */
int
nfs_node_set_busy(nfsnode_t np, thread_t thd)
{
	struct timespec ts = { 2, 0 };
	int error;

	if ((error = nfs_node_lock(np)))
		return (error);
	while (ISSET(np->n_flag, NBUSY)) {
		SET(np->n_flag, NBUSYWANT);
		msleep(np, &np->n_lock, PZERO-1, "nfsbusywant", &ts);
		if ((error = nfs_sigintr(NFSTONMP(np), NULL, thd, 0)))
			break;
	}
	if (!error)
		SET(np->n_flag, NBUSY);
	nfs_node_unlock(np);
	return (error);
}

void
nfs_node_clear_busy(nfsnode_t np)
{
	int wanted;

	nfs_node_lock_force(np);
	wanted = ISSET(np->n_flag, NBUSYWANT);
	CLR(np->n_flag, NBUSY|NBUSYWANT);
	nfs_node_unlock(np);
	if (wanted)
		wakeup(np);
}

int
nfs_node_set_busy2(nfsnode_t np1, nfsnode_t np2, thread_t thd)
{
	nfsnode_t first, second;
	int error;

	first = (np1 > np2) ? np1 : np2;
	second = (np1 > np2) ? np2 : np1;
	if ((error = nfs_node_set_busy(first, thd)))
		return (error);
	if (np1 == np2)
		return (error);
	if ((error = nfs_node_set_busy(second, thd)))
		nfs_node_clear_busy(first);
	return (error);
}

void
nfs_node_clear_busy2(nfsnode_t np1, nfsnode_t np2)
{
	nfs_node_clear_busy(np1);
	if (np1 != np2)
		nfs_node_clear_busy(np2);
}

/* helper function to sort four nodes in reverse address order (no dupes) */
static void
nfs_node_sort4(nfsnode_t np1, nfsnode_t np2, nfsnode_t np3, nfsnode_t np4, nfsnode_t *list, int *lcntp)
{
	nfsnode_t na[2], nb[2];
	int a, b, i, lcnt;

	/* sort pairs then merge */
	na[0] = (np1 > np2) ? np1 : np2;
	na[1] = (np1 > np2) ? np2 : np1;
	nb[0] = (np3 > np4) ? np3 : np4;
	nb[1] = (np3 > np4) ? np4 : np3;
	for (a = b = i = lcnt = 0; i < 4; i++) {
		if (a >= 2)
			list[lcnt] = nb[b++];
		else if ((b >= 2) || (na[a] >= nb[b]))
			list[lcnt] = na[a++];
		else
			list[lcnt] = nb[b++];
		if ((lcnt <= 0) || (list[lcnt] != list[lcnt-1]))
			lcnt++; /* omit dups */
	}
	if (list[lcnt-1] == NULL)
		lcnt--;
	*lcntp = lcnt;
}

int
nfs_node_set_busy4(nfsnode_t np1, nfsnode_t np2, nfsnode_t np3, nfsnode_t np4, thread_t thd)
{
	nfsnode_t list[4];
	int i, lcnt, error;

	nfs_node_sort4(np1, np2, np3, np4, list, &lcnt);

	/* Now we can lock using list[0 - lcnt-1] */
	for (i = 0; i < lcnt; ++i)
		if ((error = nfs_node_set_busy(list[i], thd))) {
			/* Drop any locks we acquired. */
			while (--i >= 0)
				nfs_node_clear_busy(list[i]);
			return (error);
		}
	return (0);
}

void
nfs_node_clear_busy4(nfsnode_t np1, nfsnode_t np2, nfsnode_t np3, nfsnode_t np4)
{
	nfsnode_t list[4];
	int lcnt;

	nfs_node_sort4(np1, np2, np3, np4, list, &lcnt);
	while (--lcnt >= 0)
		nfs_node_clear_busy(list[lcnt]);
}

/*
 * Acquire an NFS node data lock
 */
void
nfs_data_lock(nfsnode_t np, int locktype)
{
	nfs_data_lock_internal(np, locktype, 1);
}
void
nfs_data_lock_noupdate(nfsnode_t np, int locktype)
{
	nfs_data_lock_internal(np, locktype, 0);
}
void
nfs_data_lock_internal(nfsnode_t np, int locktype, int updatesize)
{
	FSDBG_TOP(270, np, locktype, np->n_datalockowner, 0);
	if (locktype == NFS_DATA_LOCK_SHARED) {
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
	nfs_data_unlock_internal(np, 1);
}
void
nfs_data_unlock_noupdate(nfsnode_t np)
{
	nfs_data_unlock_internal(np, 0);
}
void
nfs_data_unlock_internal(nfsnode_t np, int updatesize)
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
		nfs_data_lock(np, NFS_DATA_LOCK_EXCLUSIVE);
		/* grabbing data lock will automatically update size */
		nfs_data_unlock(np);
		FSDBG_BOT(272, np, np->n_flag, np->n_size, np->n_newsize);
		return;
	}
	error = nfs_node_lock(np);
	if (error || !ISSET(np->n_flag, NUPDATESIZE)) {
		if (!error)
			nfs_node_unlock(np);
		FSDBG_BOT(272, np, np->n_flag, np->n_size, np->n_newsize);
		return;
	}
	CLR(np->n_flag, NUPDATESIZE);
	np->n_size = np->n_newsize;
	/* make sure we invalidate buffers the next chance we get */
	SET(np->n_flag, NNEEDINVALIDATE);
	nfs_node_unlock(np);
	ubc_setsize(NFSTOV(np), (off_t)np->n_size); /* XXX error? */
	FSDBG_BOT(272, np, np->n_flag, np->n_size, np->n_newsize);
}

