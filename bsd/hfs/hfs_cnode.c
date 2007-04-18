/*
 * Copyright (c) 2002-2005 Apple Computer, Inc. All rights reserved.
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
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/time.h>
#include <sys/ubc.h>
#include <sys/quota.h>
#include <sys/kdebug.h>

#include <kern/locks.h>

#include <miscfs/specfs/specdev.h>
#include <miscfs/fifofs/fifo.h>

#include <hfs/hfs.h>
#include <hfs/hfs_catalog.h>
#include <hfs/hfs_cnode.h>
#include <hfs/hfs_quota.h>

extern int prtactive;

extern lck_attr_t *  hfs_lock_attr;
extern lck_grp_t *  hfs_mutex_group;
extern lck_grp_t *  hfs_rwlock_group;

static int  hfs_filedone(struct vnode *vp, vfs_context_t context);

static void  hfs_reclaim_cnode(struct cnode *);

static int  hfs_valid_cnode(struct hfsmount *, struct vnode *, struct componentname *, cnid_t);

static int hfs_isordered(struct cnode *, struct cnode *);

int hfs_vnop_inactive(struct vnop_inactive_args *);

int hfs_vnop_reclaim(struct vnop_reclaim_args *);


/*
 * Last reference to an cnode.  If necessary, write or delete it.
 */
__private_extern__
int
hfs_vnop_inactive(struct vnop_inactive_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct cnode *cp;
	struct hfsmount *hfsmp = VTOHFS(vp);
	struct proc *p = vfs_context_proc(ap->a_context);
	int error = 0;
	int recycle = 0;
	int forkcount = 0;
	int truncated = 0;
	int started_tr = 0;
	int took_trunc_lock = 0;
	cat_cookie_t cookie;
	int cat_reserve = 0;
	int lockflags;
	enum vtype v_type;

	v_type = vnode_vtype(vp);
	cp = VTOC(vp);

	if ((hfsmp->hfs_flags & HFS_READ_ONLY) || vnode_issystem(vp) ||
	    (hfsmp->hfs_freezing_proc == p)) {
		return (0);
	}

	/*
	 * Ignore nodes related to stale file handles.
	 */
	if (cp->c_mode == 0) {
		vnode_recycle(vp);
		return (0);
	}

	if ((v_type == VREG) &&
	    (ISSET(cp->c_flag, C_DELETED) || VTOF(vp)->ff_blocks)) {
		hfs_lock_truncate(cp, TRUE);
		took_trunc_lock = 1;
	}

	/*
	 * We do the ubc_setsize before we take the cnode
	 * lock and before the hfs_truncate (since we'll
	 * be inside a transaction).
	 */
	if ((v_type == VREG || v_type == VLNK) &&
	    (cp->c_flag & C_DELETED) &&
	    (VTOF(vp)->ff_blocks != 0)) {
		ubc_setsize(vp, 0);
	}

	(void) hfs_lock(cp, HFS_FORCE_LOCK);

	if (v_type == VREG && !ISSET(cp->c_flag, C_DELETED) && VTOF(vp)->ff_blocks) {
		hfs_filedone(vp, ap->a_context);
	}
	/* 
	 * Remove any directory hints
	 */
	if (v_type == VDIR)
		hfs_reldirhints(cp, 0);

	if (cp->c_datafork)
		++forkcount;
	if (cp->c_rsrcfork)
		++forkcount;

	/* If needed, get rid of any fork's data for a deleted file */
	if ((v_type == VREG || v_type == VLNK) && (cp->c_flag & C_DELETED)) {
		if (VTOF(vp)->ff_blocks != 0) {
		    // start the transaction out here so that
		    // the truncate and the removal of the file
		    // are all in one transaction.  otherwise
		    // because this cnode is marked for deletion
		    // the truncate won't cause the catalog entry
		    // to get updated which means that we could
		    // free blocks but still keep a reference to
		    // them in the catalog entry and then double
		    // free them later.
		    //
//		    if (hfs_start_transaction(hfsmp) != 0) {
//			error = EINVAL;
//			goto out;
//		    }
//		    started_tr = 1;
		    
			/*
			 * Since we're already inside a transaction,
			 * tell hfs_truncate to skip the ubc_setsize.
			 */
			error = hfs_truncate(vp, (off_t)0, IO_NDELAY, 1, ap->a_context);
			if (error)
				goto out;
			truncated = 1;
		}
		recycle = 1;
	}

	/*
	 * Check for a postponed deletion.
	 * (only delete cnode when the last fork goes inactive)
	 */
	if ((cp->c_flag & C_DELETED) && (forkcount <= 1)) {			
		/*
		 * Mark cnode in transit so that no one can get this 
		 * cnode from cnode hash.
		 */
	        hfs_chash_mark_in_transit(cp);

		cp->c_flag &= ~C_DELETED;
		cp->c_flag |= C_NOEXISTS;   // XXXdbg
		cp->c_rdev = 0;

		if (started_tr == 0) {
		    if (hfs_start_transaction(hfsmp) != 0) {
			error = EINVAL;
			goto out;
		    }
		    started_tr = 1;
		}
		
		/*
		 * Reserve some space in the Catalog file.
		 */
		if ((error = cat_preflight(hfsmp, CAT_DELETE, &cookie, p))) {
			goto out;
		}
		cat_reserve = 1;

		lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG | SFL_ATTRIBUTE, HFS_EXCLUSIVE_LOCK);

		if (cp->c_blocks > 0)
			printf("hfs_inactive: attempting to delete a non-empty file!");


		//
		// release the name pointer in the descriptor so that
		// cat_delete() will use the file-id to do the deletion.
		// in the case of hard links this is imperative (in the
		// case of regular files the fileid and cnid are the
		// same so it doesn't matter).
		//
		cat_releasedesc(&cp->c_desc);
		
		/*
		 * The descriptor name may be zero,
		 * in which case the fileid is used.
		 */
		error = cat_delete(hfsmp, &cp->c_desc, &cp->c_attr);
		
		if (error && truncated && (error != ENXIO))
			printf("hfs_inactive: couldn't delete a truncated file!");

  		/* Update HFS Private Data dir */
		if (error == 0) {
			hfsmp->hfs_privdir_attr.ca_entries--;
			(void)cat_update(hfsmp, &hfsmp->hfs_privdir_desc,
				&hfsmp->hfs_privdir_attr, NULL, NULL);
		}

		if (error == 0) {
			/* Delete any attributes, ignore errors */
			(void) hfs_removeallattr(hfsmp, cp->c_fileid);
		}

		hfs_systemfile_unlock(hfsmp, lockflags);

		if (error)
			goto out;

#if QUOTA
		(void)hfs_chkiq(cp, -1, NOCRED, 0);
#endif /* QUOTA */

		cp->c_mode = 0;
		cp->c_flag |= C_NOEXISTS;
		cp->c_touch_chgtime = TRUE;
		cp->c_touch_modtime = TRUE;

		if (error == 0)
 			hfs_volupdate(hfsmp, VOL_RMFILE, 0);
	}

	if ((cp->c_flag & C_MODIFIED) ||
	    cp->c_touch_acctime || cp->c_touch_chgtime || cp->c_touch_modtime) {
		hfs_update(vp, 0);
	}
out:
	if (cat_reserve)
		cat_postflight(hfsmp, &cookie, p);

	// XXXdbg - have to do this because a goto could have come here
	if (started_tr) {
	    hfs_end_transaction(hfsmp);
	    started_tr = 0;
	}

	hfs_unlock(cp);

	if (took_trunc_lock)
		hfs_unlock_truncate(cp);

	/*
	 * If we are done with the vnode, reclaim it
	 * so that it can be reused immediately.
	 */
	if (cp->c_mode == 0 || recycle)
		vnode_recycle(vp);

	return (error);
}

/*
 * File clean-up (zero fill and shrink peof).
 */
static int
hfs_filedone(struct vnode *vp, vfs_context_t context)
{
	struct cnode *cp;
	struct filefork *fp;
	struct hfsmount *hfsmp;
	off_t leof;
	u_long blks, blocksize;

	cp = VTOC(vp);
	fp = VTOF(vp);
	hfsmp = VTOHFS(vp);
	leof = fp->ff_size;

	if ((hfsmp->hfs_flags & HFS_READ_ONLY) || (fp->ff_blocks == 0))
		return (0);

	hfs_unlock(cp);
	(void) cluster_push(vp, IO_CLOSE);
	hfs_lock(cp, HFS_FORCE_LOCK);

	/*
	 * Explicitly zero out the areas of file
	 * that are currently marked invalid.
	 */
	while (!CIRCLEQ_EMPTY(&fp->ff_invalidranges)) {
		struct rl_entry *invalid_range = CIRCLEQ_FIRST(&fp->ff_invalidranges);
		off_t start = invalid_range->rl_start;
		off_t end = invalid_range->rl_end;
	
		/* The range about to be written must be validated
		 * first, so that VNOP_BLOCKMAP() will return the
		 * appropriate mapping for the cluster code:
		 */
		rl_remove(start, end, &fp->ff_invalidranges);

		hfs_unlock(cp);
		(void) cluster_write(vp, (struct uio *) 0,
				     leof, end + 1, start, (off_t)0,
				     IO_HEADZEROFILL | IO_NOZERODIRTY | IO_NOCACHE);
		hfs_lock(cp, HFS_FORCE_LOCK);
		cp->c_flag |= C_MODIFIED;
	}
	cp->c_flag &= ~C_ZFWANTSYNC;
	cp->c_zftimeout = 0;
	blocksize = VTOVCB(vp)->blockSize;
	blks = leof / blocksize;
	if (((off_t)blks * (off_t)blocksize) != leof)
		blks++;
	/*
	 * Shrink the peof to the smallest size neccessary to contain the leof.
	 */
	if (blks < fp->ff_blocks)
		(void) hfs_truncate(vp, leof, IO_NDELAY, 0, context);
	hfs_unlock(cp);
	(void) cluster_push(vp, IO_CLOSE);
	hfs_lock(cp, HFS_FORCE_LOCK);
	
	/*
	 * If the hfs_truncate didn't happen to flush the vnode's
	 * information out to disk, force it to be updated now that
	 * all invalid ranges have been zero-filled and validated:
	 */
	if (cp->c_flag & C_MODIFIED) {
		hfs_update(vp, 0);
	}
	return (0);
}


/*
 * Reclaim a cnode so that it can be used for other purposes.
 */
__private_extern__
int
hfs_vnop_reclaim(struct vnop_reclaim_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct cnode *cp;
	struct filefork *fp = NULL;
	struct filefork *altfp = NULL;
	int reclaim_cnode = 0;

	(void) hfs_lock(VTOC(vp), HFS_FORCE_LOCK);
	cp = VTOC(vp);

	/*
	 * Keep track of an inactive hot file.
	 */
	if (!vnode_isdir(vp) && !vnode_issystem(vp))
  		(void) hfs_addhotfile(vp);

	vnode_removefsref(vp);

	/*
	 * Find file fork for this vnode (if any)
	 * Also check if another fork is active
	 */
	if (cp->c_vp == vp) {
	        fp = cp->c_datafork;
		altfp = cp->c_rsrcfork;

		cp->c_datafork = NULL;
		cp->c_vp = NULL;
	} else if (cp->c_rsrc_vp == vp) {
	        fp = cp->c_rsrcfork;
		altfp = cp->c_datafork;

		cp->c_rsrcfork = NULL;
		cp->c_rsrc_vp = NULL;
	} else {
	        panic("hfs_vnop_reclaim: vp points to wrong cnode\n");
	}
	/*
	 * On the last fork, remove the cnode from its hash chain.
	 */
	if (altfp == NULL) {
		/* If we can't remove it then the cnode must persist! */
		if (hfs_chashremove(cp) == 0)
			reclaim_cnode = 1;
		/* 
		 * Remove any directory hints
		 */
		if (vnode_isdir(vp)) {
			hfs_reldirhints(cp, 0);
		}
	}
	/* Release the file fork and related data */
	if (fp) {
		/* Dump cached symlink data */
		if (vnode_islnk(vp) && (fp->ff_symlinkptr != NULL)) {
			FREE(fp->ff_symlinkptr, M_TEMP);
		}		
		FREE_ZONE(fp, sizeof(struct filefork), M_HFSFORK);
	}

	/* 
	 * If there was only one active fork then we can release the cnode.
	 */
	if (reclaim_cnode) {
		hfs_chashwakeup(cp, H_ALLOC | H_TRANSIT);
		hfs_reclaim_cnode(cp);
	} else /* cnode in use */ {
		hfs_unlock(cp);
	}

	vnode_clearfsnode(vp);
	return (0);
}


extern int (**hfs_vnodeop_p) (void *);
extern int (**hfs_specop_p)  (void *);
extern int (**hfs_fifoop_p)  (void *);

/*
 * hfs_getnewvnode - get new default vnode
 *
 * The vnode is returned with an iocount and the cnode locked
 */
__private_extern__
int
hfs_getnewvnode(
	struct hfsmount *hfsmp,
	struct vnode *dvp,
	struct componentname *cnp,
	struct cat_desc *descp,
	int wantrsrc,
	struct cat_attr *attrp,
	struct cat_fork *forkp,
	struct vnode **vpp)
{
	struct mount *mp = HFSTOVFS(hfsmp);
	struct vnode *vp = NULL;
	struct vnode **cvpp;
	struct vnode *tvp = NULLVP;
	struct cnode *cp = NULL;
	struct filefork *fp = NULL;
	int i;
	int retval;
	int issystemfile;
	struct vnode_fsparam vfsp;
	enum vtype vtype;

	if (attrp->ca_fileid == 0) {
		*vpp = NULL;
		return (ENOENT);
	}

#if !FIFO
	if (IFTOVT(attrp->ca_mode) == VFIFO) {
		*vpp = NULL;
		return (ENOTSUP);
	}
#endif
	vtype = IFTOVT(attrp->ca_mode);
	issystemfile = (descp->cd_flags & CD_ISMETA) && (vtype == VREG);

	/*
	 * Get a cnode (new or existing)
	 * skip getting the cnode lock if we are getting resource fork (wantrsrc == 2)
	 */
	cp = hfs_chash_getcnode(hfsmp->hfs_raw_dev, attrp->ca_fileid, vpp, wantrsrc, (wantrsrc == 2));

	/* Hardlinks may need an updated catalog descriptor */
	if ((cp->c_flag & C_HARDLINK) && descp->cd_nameptr && descp->cd_namelen > 0) {
		replace_desc(cp, descp);
	}
	/* Check if we found a matching vnode */
	if (*vpp != NULL)
		return (0);

	/*
	 * If this is a new cnode then initialize it.
	 */
	if (ISSET(cp->c_hflag, H_ALLOC)) {
		lck_rw_init(&cp->c_truncatelock, hfs_rwlock_group, hfs_lock_attr);

		/* Make sure its still valid (ie exists on disk). */
		if (!hfs_valid_cnode(hfsmp, dvp, (wantrsrc ? NULL : cnp), cp->c_fileid)) {
			hfs_chash_abort(cp);
			hfs_reclaim_cnode(cp);
			*vpp = NULL;
			return (ENOENT);
		}
		bcopy(attrp, &cp->c_attr, sizeof(struct cat_attr));
		bcopy(descp, &cp->c_desc, sizeof(struct cat_desc));

		/* The name was inherited so clear descriptor state... */
		descp->cd_namelen = 0;
		descp->cd_nameptr = NULL;
		descp->cd_flags &= ~CD_HASBUF;

		/* Tag hardlinks */
		if (IFTOVT(cp->c_mode) == VREG &&
		    (descp->cd_cnid != attrp->ca_fileid)) {
			cp->c_flag |= C_HARDLINK;
		}

		/* Take one dev reference for each non-directory cnode */
		if (IFTOVT(cp->c_mode) != VDIR) {
			cp->c_devvp = hfsmp->hfs_devvp;
			vnode_ref(cp->c_devvp);
		}
#if QUOTA
		for (i = 0; i < MAXQUOTAS; i++)
			cp->c_dquot[i] = NODQUOT;
#endif /* QUOTA */
	}

	if (IFTOVT(cp->c_mode) == VDIR) {
	        if (cp->c_vp != NULL)
		        panic("hfs_getnewvnode: orphaned vnode (data)");
		cvpp = &cp->c_vp;
	} else {
		if (forkp && attrp->ca_blocks < forkp->cf_blocks)
			panic("hfs_getnewvnode: bad ca_blocks (too small)");
		/*
		 * Allocate and initialize a file fork...
		 */
		MALLOC_ZONE(fp, struct filefork *, sizeof(struct filefork),
			M_HFSFORK, M_WAITOK);
		fp->ff_cp = cp;
		if (forkp)
			bcopy(forkp, &fp->ff_data, sizeof(struct cat_fork));
		else
			bzero(&fp->ff_data, sizeof(struct cat_fork));
		rl_init(&fp->ff_invalidranges);
		fp->ff_sysfileinfo = 0;

		if (wantrsrc) {
			if (cp->c_rsrcfork != NULL)
				panic("hfs_getnewvnode: orphaned rsrc fork");
			if (cp->c_rsrc_vp != NULL)
			        panic("hfs_getnewvnode: orphaned vnode (rsrc)");
			cp->c_rsrcfork = fp;
			cvpp = &cp->c_rsrc_vp;
			if ( (tvp = cp->c_vp) != NULLVP )
			        cp->c_flag |= C_NEED_DVNODE_PUT;
		} else {
			if (cp->c_datafork != NULL)
				panic("hfs_getnewvnode: orphaned data fork");
			if (cp->c_vp != NULL)
			        panic("hfs_getnewvnode: orphaned vnode (data)");
			cp->c_datafork = fp;
			cvpp = &cp->c_vp;
			if ( (tvp = cp->c_rsrc_vp) != NULLVP)
			        cp->c_flag |= C_NEED_RVNODE_PUT;
		}
	}
	if (tvp != NULLVP) {
	        /*
		 * grab an iocount on the vnode we weren't
		 * interested in (i.e. we want the resource fork
		 * but the cnode already has the data fork)
		 * to prevent it from being
		 * recycled by us when we call vnode_create
		 * which will result in a deadlock when we
		 * try to take the cnode lock in hfs_vnop_fsync or
		 * hfs_vnop_reclaim... vnode_get can be called here
		 * because we already hold the cnode lock which will
		 * prevent the vnode from changing identity until
		 * we drop it.. vnode_get will not block waiting for
		 * a change of state... however, it will return an
		 * error if the current iocount == 0 and we've already
		 * started to terminate the vnode... we don't need/want to
		 * grab an iocount in the case since we can't cause
		 * the fileystem to be re-entered on this thread for this vp
		 *
		 * the matching vnode_put will happen in hfs_unlock
		 * after we've dropped the cnode lock
		 */
	        if ( vnode_get(tvp) != 0)
		        cp->c_flag &= ~(C_NEED_RVNODE_PUT | C_NEED_DVNODE_PUT);
	}
	vfsp.vnfs_mp = mp;
	vfsp.vnfs_vtype = vtype;
	vfsp.vnfs_str = "hfs";
	vfsp.vnfs_dvp = dvp;
	vfsp.vnfs_fsnode = cp;
	vfsp.vnfs_cnp = cnp;
	if (vtype == VFIFO )
		vfsp.vnfs_vops = hfs_fifoop_p;
	else if (vtype == VBLK || vtype == VCHR)
		vfsp.vnfs_vops = hfs_specop_p;
	else
		vfsp.vnfs_vops = hfs_vnodeop_p;
		
	if (vtype == VBLK || vtype == VCHR)
		vfsp.vnfs_rdev = attrp->ca_rdev;
	else
		vfsp.vnfs_rdev = 0;

	if (forkp) 
		vfsp.vnfs_filesize = forkp->cf_size;
	else
		vfsp.vnfs_filesize = 0;

	if (dvp && cnp && (cnp->cn_flags & MAKEENTRY))
		vfsp.vnfs_flags = 0;
	else
		vfsp.vnfs_flags = VNFS_NOCACHE;

	/* Tag system files */
	vfsp.vnfs_marksystem = issystemfile;

	/* Tag root directory */
	if (descp->cd_cnid == kHFSRootFolderID)
		vfsp.vnfs_markroot = 1;
	else	
		vfsp.vnfs_markroot = 0;

	if ((retval = vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &vfsp, cvpp))) {
	        if (fp) {
			if (fp == cp->c_datafork)
			        cp->c_datafork = NULL;
			else
			        cp->c_rsrcfork = NULL;

		        FREE_ZONE(fp, sizeof(struct filefork), M_HFSFORK);
		}
		/*
		 * If this is a newly created cnode or a vnode reclaim
		 * occurred during the attachment, then cleanup the cnode.
		 */
		if ((cp->c_vp == NULL) && (cp->c_rsrc_vp == NULL)) {
		        hfs_chash_abort(cp);
			hfs_reclaim_cnode(cp);
		} else {
		        hfs_chashwakeup(cp, H_ALLOC | H_ATTACH);
			hfs_unlock(cp);
		}
		*vpp = NULL;
		return (retval);
	}
	vp = *cvpp;
	vnode_addfsref(vp);
	vnode_settag(vp, VT_HFS);
	if (cp->c_flag & C_HARDLINK)
		vnode_set_hard_link(vp);
	hfs_chashwakeup(cp, H_ALLOC | H_ATTACH);

	/*
	 * Stop tracking an active hot file.
	 */
	if (!vnode_isdir(vp) && !vnode_issystem(vp))
		(void) hfs_removehotfile(vp);

	*vpp = vp;
	return (0);
}


static void
hfs_reclaim_cnode(struct cnode *cp)
{
#if QUOTA
	int i;

	for (i = 0; i < MAXQUOTAS; i++) {
		if (cp->c_dquot[i] != NODQUOT) {
			dqreclaim(cp->c_dquot[i]);
			cp->c_dquot[i] = NODQUOT;
		}
	}
#endif /* QUOTA */

	if (cp->c_devvp) {
		struct vnode *tmp_vp = cp->c_devvp;

		cp->c_devvp = NULL;
		vnode_rele(tmp_vp);
	}

	/* 
	 * If the descriptor has a name then release it
	 */
	if (cp->c_desc.cd_flags & CD_HASBUF) {
		char *nameptr;

		nameptr = cp->c_desc.cd_nameptr;
		cp->c_desc.cd_nameptr = 0;
		cp->c_desc.cd_flags &= ~CD_HASBUF;
		cp->c_desc.cd_namelen = 0;
		vfs_removename(nameptr);
	}

	lck_rw_destroy(&cp->c_rwlock, hfs_rwlock_group);
	lck_rw_destroy(&cp->c_truncatelock, hfs_rwlock_group);
	bzero(cp, sizeof(struct cnode));
	FREE_ZONE(cp, sizeof(struct cnode), M_HFSNODE);
}


static int
hfs_valid_cnode(struct hfsmount *hfsmp, struct vnode *dvp, struct componentname *cnp, cnid_t cnid)
{
	struct cat_attr attr;
	struct cat_desc cndesc;
	int stillvalid = 0;
	int lockflags;

	/* System files are always valid */
	if (cnid < kHFSFirstUserCatalogNodeID)
		return (1);

	/* XXX optimization:  check write count in dvp */

	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);

	if (dvp && cnp) {
		bzero(&cndesc, sizeof(cndesc));
		cndesc.cd_nameptr = cnp->cn_nameptr;
		cndesc.cd_namelen = cnp->cn_namelen;
		cndesc.cd_parentcnid = VTOC(dvp)->c_cnid;
		cndesc.cd_hint = VTOC(dvp)->c_childhint;

		if ((cat_lookup(hfsmp, &cndesc, 0, NULL, &attr, NULL, NULL) == 0) &&
		    (cnid == attr.ca_fileid)) {
			stillvalid = 1;
		}
	} else {
		if (cat_idlookup(hfsmp, cnid, NULL, NULL, NULL) == 0) {
			stillvalid = 1;
		}
	}
	hfs_systemfile_unlock(hfsmp, lockflags);

	return (stillvalid);
}

/*
 * Touch cnode times based on c_touch_xxx flags
 *
 * cnode must be locked exclusive
 *
 * This will also update the volume modify time
 */
__private_extern__
void
hfs_touchtimes(struct hfsmount *hfsmp, struct cnode* cp)
{
	/* HFS Standard doesn't support access times */
	if (hfsmp->hfs_flags & HFS_STANDARD) {
		cp->c_touch_acctime = FALSE;
	}

	if (cp->c_touch_acctime || cp->c_touch_chgtime || cp->c_touch_modtime) {
		struct timeval tv;
		int touchvol = 0;

		microtime(&tv);
		    
		if (cp->c_touch_acctime) {
			cp->c_atime = tv.tv_sec;
			/*
			 * When the access time is the only thing changing
			 * then make sure its sufficiently newer before
			 * committing it to disk.
			 */
			if ((((u_int32_t)cp->c_atime - (u_int32_t)(cp)->c_attr.ca_atimeondisk) >
			      ATIME_ONDISK_ACCURACY)) {
				cp->c_flag |= C_MODIFIED;
			}
			cp->c_touch_acctime = FALSE;
		}
		if (cp->c_touch_modtime) {
			cp->c_mtime = tv.tv_sec;
			cp->c_touch_modtime = FALSE;
			cp->c_flag |= C_MODIFIED;
			touchvol = 1;
#if 1
			/*
			 * HFS dates that WE set must be adjusted for DST
			 */
			if ((hfsmp->hfs_flags & HFS_STANDARD) && gTimeZone.tz_dsttime) {
				cp->c_mtime += 3600;
			}
#endif
		}
		if (cp->c_touch_chgtime) {
			cp->c_ctime = tv.tv_sec;
			cp->c_touch_chgtime = FALSE;
			cp->c_flag |= C_MODIFIED;
			touchvol = 1;
		}

		/* Touch the volume modtime if needed */
		if (touchvol) {
			HFSTOVCB(hfsmp)->vcbFlags |= 0xFF00;
			HFSTOVCB(hfsmp)->vcbLsMod = tv.tv_sec;
		}
	}
}

/*
 * Lock a cnode.
 */
__private_extern__
int
hfs_lock(struct cnode *cp, enum hfslocktype locktype)
{
	void * thread = current_thread();

	/* System files need to keep track of owner */
	if ((cp->c_fileid < kHFSFirstUserCatalogNodeID) &&
	    (cp->c_fileid > kHFSRootFolderID) &&
	    (locktype != HFS_SHARED_LOCK)) {

		/*
		 * The extents and bitmap file locks support
		 * recursion and are always taken exclusive.
		 */
		if (cp->c_fileid == kHFSExtentsFileID ||
		    cp->c_fileid == kHFSAllocationFileID) {
			if (cp->c_lockowner == thread) {
				cp->c_syslockcount++;
			} else {
				lck_rw_lock_exclusive(&cp->c_rwlock);
				cp->c_lockowner = thread;
				cp->c_syslockcount = 1;
			}
		} else {
			lck_rw_lock_exclusive(&cp->c_rwlock);
			cp->c_lockowner = thread;
		}
	} else if (locktype == HFS_SHARED_LOCK) {
		lck_rw_lock_shared(&cp->c_rwlock);
		cp->c_lockowner = HFS_SHARED_OWNER;
	} else {
		lck_rw_lock_exclusive(&cp->c_rwlock);
		cp->c_lockowner = thread;
	}
	/*
	 * Skip cnodes that no longer exist (were deleted).
	 */
	if ((locktype != HFS_FORCE_LOCK) &&
	    ((cp->c_desc.cd_flags & CD_ISMETA) == 0) &&
	    (cp->c_flag & C_NOEXISTS)) {
		hfs_unlock(cp);
		return (ENOENT);
	}
	return (0);
}

/*
 * Lock a pair of cnodes.
 */
__private_extern__
int
hfs_lockpair(struct cnode *cp1, struct cnode *cp2, enum hfslocktype locktype)
{
	struct cnode *first, *last;
	int error;

	/*
	 * If cnodes match then just lock one.
	 */
	if (cp1 == cp2) {
		return hfs_lock(cp1, locktype);
	}

	/*
	 * Lock in cnode parent-child order (if there is a relationship);
	 * otherwise lock in cnode address order.
	 */
	if ((IFTOVT(cp1->c_mode) == VDIR) && (cp1->c_fileid == cp2->c_parentcnid)) {
		first = cp1;
		last = cp2;
	} else if (cp1 < cp2) {
		first = cp1;
		last = cp2;
	} else {
		first = cp2;
		last = cp1;
	}

	if ( (error = hfs_lock(first, locktype))) {
		return (error);
	}
	if ( (error = hfs_lock(last, locktype))) {
		hfs_unlock(first);
		return (error);
	}
	return (0);
}

/*
 * Check ordering of two cnodes. Return true if they are are in-order.
 */
static int
hfs_isordered(struct cnode *cp1, struct cnode *cp2)
{
	if (cp1 == cp2)
		return (0);
	if (cp1 == NULL || cp2 == (struct cnode *)0xffffffff)
		return (1);
	if (cp2 == NULL || cp1 == (struct cnode *)0xffffffff)
		return (0);
	if (cp1->c_fileid == cp2->c_parentcnid)
		return (1);  /* cp1 is the parent and should go first */
	if (cp2->c_fileid == cp1->c_parentcnid)
		return (0);  /* cp1 is the child and should go last */

	return (cp1 < cp2);  /* fall-back is to use address order */
}

/*
 * Acquire 4 cnode locks.
 *   - locked in cnode parent-child order (if there is a relationship)
 *     otherwise lock in cnode address order (lesser address first).
 *   - all or none of the locks are taken
 *   - only one lock taken per cnode (dup cnodes are skipped)
 *   - some of the cnode pointers may be null
 */
__private_extern__
int
hfs_lockfour(struct cnode *cp1, struct cnode *cp2, struct cnode *cp3,
             struct cnode *cp4, enum hfslocktype locktype)
{
	struct cnode * a[3];
	struct cnode * b[3];
	struct cnode * list[4];
	struct cnode * tmp;
	int i, j, k;
	int error;

	if (hfs_isordered(cp1, cp2)) {
		a[0] = cp1; a[1] = cp2;
	} else {
		a[0] = cp2; a[1] = cp1;
	}
	if (hfs_isordered(cp3, cp4)) {
		b[0] = cp3; b[1] = cp4;
	} else {
		b[0] = cp4; b[1] = cp3;
	}
	a[2] = (struct cnode *)0xffffffff;  /* sentinel value */
	b[2] = (struct cnode *)0xffffffff;  /* sentinel value */

	/*
	 * Build the lock list, skipping over duplicates
	 */
	for (i = 0, j = 0, k = 0; (i < 2 || j < 2); ) {
		tmp = hfs_isordered(a[i], b[j]) ? a[i++] : b[j++];
		if (k == 0 || tmp != list[k-1])
			list[k++] = tmp;
	}

	/*
	 * Now we can lock using list[0 - k].
	 * Skip over NULL entries.
	 */
	for (i = 0; i < k; ++i) {
		if (list[i])
			if ((error = hfs_lock(list[i], locktype))) {
				/* Drop any locks we acquired. */
				while (--i >= 0) {
					if (list[i])
						hfs_unlock(list[i]);
				}
				return (error);
			}
	}
	return (0);
}


/*
 * Unlock a cnode.
 */
__private_extern__
void
hfs_unlock(struct cnode *cp)
{
        vnode_t rvp = NULLVP;
        vnode_t vp = NULLVP;
	u_int32_t c_flag;

	/* System files need to keep track of owner */
	if ((cp->c_fileid < kHFSFirstUserCatalogNodeID) &&
	    (cp->c_fileid > kHFSRootFolderID) &&
	    (cp->c_datafork != NULL)) {
		/*
		 * The extents and bitmap file locks support
		 * recursion and are always taken exclusive.
		 */
		if (cp->c_fileid == kHFSExtentsFileID ||
		    cp->c_fileid == kHFSAllocationFileID) {
			if (--cp->c_syslockcount > 0) {
				return;
			}
		}
	}
	c_flag = cp->c_flag;
	cp->c_flag &= ~(C_NEED_DVNODE_PUT | C_NEED_RVNODE_PUT | C_NEED_DATA_SETSIZE | C_NEED_RSRC_SETSIZE);
	if (c_flag & (C_NEED_DVNODE_PUT | C_NEED_DATA_SETSIZE)) {
		vp = cp->c_vp;
	}
	if (c_flag & (C_NEED_RVNODE_PUT | C_NEED_RSRC_SETSIZE)) {
                rvp = cp->c_rsrc_vp;
	}

	cp->c_lockowner = NULL;
	lck_rw_done(&cp->c_rwlock);

	/* Perform any vnode post processing after cnode lock is dropped. */
	if (vp) {
		if (c_flag & C_NEED_DATA_SETSIZE)
			ubc_setsize(vp, 0);
		if (c_flag & C_NEED_DVNODE_PUT)
			vnode_put(vp);
	}
	if (rvp) {
		if (c_flag & C_NEED_RSRC_SETSIZE)
			ubc_setsize(rvp, 0);
		if (c_flag & C_NEED_RVNODE_PUT)
			vnode_put(rvp);
	}
}

/*
 * Unlock a pair of cnodes.
 */
__private_extern__
void
hfs_unlockpair(struct cnode *cp1, struct cnode *cp2)
{
	hfs_unlock(cp1);
	if (cp2 != cp1)
		hfs_unlock(cp2);
}

/*
 * Unlock a group of cnodes.
 */
__private_extern__
void
hfs_unlockfour(struct cnode *cp1, struct cnode *cp2, struct cnode *cp3, struct cnode *cp4)
{
	struct cnode * list[4];
	int i, k = 0;

	if (cp1) {
		hfs_unlock(cp1);
		list[k++] = cp1;
	}
	if (cp2) {
		for (i = 0; i < k; ++i) {
			if (list[i] == cp2)
				goto skip1;
		}
		hfs_unlock(cp2);
		list[k++] = cp2;
	}
skip1:
	if (cp3) {
		for (i = 0; i < k; ++i) {
			if (list[i] == cp3)
				goto skip2;
		}
		hfs_unlock(cp3);
		list[k++] = cp3;
	}
skip2:
	if (cp4) {
		for (i = 0; i < k; ++i) {
			if (list[i] == cp4)
				return;
		}
		hfs_unlock(cp4);
	}
}


/*
 * Protect a cnode against a truncation.
 *
 * Used mainly by read/write since they don't hold the
 * cnode lock across calls to the cluster layer.
 *
 * The process doing a truncation must take the lock
 * exclusive. The read/write processes can take it
 * non-exclusive.
 */
__private_extern__
void
hfs_lock_truncate(struct cnode *cp, int exclusive)
{
	if (cp->c_lockowner == current_thread())
		panic("hfs_lock_truncate: cnode 0x%08x locked!", cp);

	if (exclusive)
		lck_rw_lock_exclusive(&cp->c_truncatelock);
	else
		lck_rw_lock_shared(&cp->c_truncatelock);
}

__private_extern__
void
hfs_unlock_truncate(struct cnode *cp)
{
	lck_rw_done(&cp->c_truncatelock);
}




