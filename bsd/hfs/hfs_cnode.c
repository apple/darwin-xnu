/*
 * Copyright (c) 2002-2008 Apple Inc. All rights reserved.
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

static int hfs_isordered(struct cnode *, struct cnode *);


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
	 * We are peeking at the cnode flag without the lock, but if C_NOEXISTS
	 * is set, that means the cnode doesn't have any backing store in the 
	 * catalog anymore, and is otherwise safe to force a recycle
	 */
	
	if (cp->c_flag & C_NOEXISTS) {
		vnode_recycle(vp);
		return (0);
	}

	if ((v_type == VREG || v_type == VLNK)) {
		hfs_lock_truncate(cp, TRUE);
		took_trunc_lock = 1;
	}

	(void) hfs_lock(cp, HFS_FORCE_LOCK);

	if (cp->c_datafork)
		++forkcount;
	if (cp->c_rsrcfork)
		++forkcount;

	/*
	 * We should lock cnode before checking the flags in the 
	 * condition below and should unlock the cnode before calling 
	 * ubc_setsize() as cluster code can call other HFS vnops which
	 * will try to acquire the same cnode lock and cause deadlock.
	 * Only call ubc_setsize to 0 if we are the last fork.
	 */
	if ((v_type == VREG || v_type == VLNK) &&
			(cp->c_flag & C_DELETED) &&
			(VTOF(vp)->ff_blocks != 0) && (forkcount == 1)) {
		hfs_unlock(cp); 
		ubc_setsize(vp, 0);
		(void) hfs_lock(cp, HFS_FORCE_LOCK);
	}

	if (v_type == VREG && !ISSET(cp->c_flag, C_DELETED) && VTOF(vp)->ff_blocks) {
		hfs_filedone(vp, ap->a_context);
	}
	/* 
	 * Remove any directory hints or cached origins
	 */
	if (v_type == VDIR) {
		hfs_reldirhints(cp, 0);
	}
	if (cp->c_flag & C_HARDLINK) {
		hfs_relorigins(cp);
	}

	/* Hurry the recycling process along if we're an open-unlinked file */
	if((v_type == VREG || v_type == VLNK) && (cp->c_flag & C_DELETED)) {
		recycle = 1;	
	}

	/*
	 * This check is slightly complicated.  We should only truncate data 
	 * in very specific cases for open-unlinked files.  This is because
	 * we want to ensure that the resource fork continues to be available
	 * if the caller has the data fork open.  However, this is not symmetric; 
	 * someone who has the resource fork open need not be able to access the data
	 * fork once the data fork has gone inactive.
	 * 
	 * If we're the last fork, then we have cleaning up to do.
	 * 
	 * A) last fork, and vp == c_vp
	 *	Truncate away own fork dat. If rsrc fork is not in core, truncate it too.
	 *
	 * B) last fork, and vp == c_rsrc_vp
	 *	Truncate ourselves, assume data fork has been cleaned due to C).
	 *
	 * If we're not the last fork, then things are a little different:
	 *
	 * C) not the last fork, vp == c_vp
	 *	Truncate ourselves.  Once the file has gone out of the namespace,
	 *	it cannot be further opened.  Further access to the rsrc fork may 
	 *	continue, however.
	 *
	 * D) not the last fork, vp == c_rsrc_vp
	 *	Don't enter the block below, just clean up vnode and push it out of core.
	 */

	if ((v_type == VREG || v_type == VLNK) && (cp->c_flag & C_DELETED) &&
			((forkcount == 1) || (!VNODE_IS_RSRC(vp)))) {
		if (VTOF(vp)->ff_blocks != 0) {
			/*
			 * Since we're already inside a transaction,
			 * tell hfs_truncate to skip the ubc_setsize.
			 */
			error = hfs_truncate(vp, (off_t)0, IO_NDELAY, 1, 0, ap->a_context);
			if (error)
				goto out;
			truncated = 1;
		}

		/* 
		 * If c_blocks > 0 and we are the last fork (data fork), then
		 * we can go and and truncate away the rsrc fork blocks if
		 * they were not in core.
		 */
		if ((cp->c_blocks > 0) && (forkcount == 1) && (vp != cp->c_rsrc_vp)) {
			struct vnode *rvp = NULLVP;

			error = hfs_vgetrsrc(hfsmp, vp, &rvp, FALSE);
			if (error)
				goto out;
			/*
			 * Defer the vnode_put and ubc_setsize on rvp until hfs_unlock().
			 */
			cp->c_flag |= C_NEED_RVNODE_PUT | C_NEED_RSRC_SETSIZE;
			error = hfs_truncate(rvp, (off_t)0, IO_NDELAY, 1, 0, ap->a_context);
			if (error)
				goto out;
			vnode_recycle(rvp);  /* all done with this vnode */
		}
	}

	// If needed, get rid of any xattrs that this file (or directory) may have.
	// Note that this must happen outside of any other transactions
	// because it starts/ends its own transactions and grabs its
	// own locks.  This is to prevent a file with a lot of attributes
	// from creating a transaction that is too large (which panics).
	//
	if ((cp->c_attr.ca_recflags & kHFSHasAttributesMask) != 0 && 
			(cp->c_flag & C_DELETED) && (forkcount <= 1)) {
		hfs_removeallattr(hfsmp, cp->c_fileid);
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
	        // hfs_chash_mark_in_transit(hfsmp, cp);
	        // XXXdbg - remove the cnode from the hash table since it's deleted
	        //          otherwise someone could go to sleep on the cnode and not
	        //          be woken up until this vnode gets recycled which could be
	        //          a very long time...
		hfs_chashremove(hfsmp, cp);

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

		if (cp->c_blocks > 0) {
			printf("hfs_inactive: deleting non-empty%sfile %d, "
			       "blks %d\n", VNODE_IS_RSRC(vp) ? " rsrc " : " ",
			       (int)cp->c_fileid, (int)cp->c_blocks);
		}

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
			hfsmp->hfs_private_attr[FILE_HARDLINKS].ca_entries--;
			if (vnode_isdir(vp)) {
				DEC_FOLDERCOUNT(hfsmp, hfsmp->hfs_private_attr[FILE_HARDLINKS]);
			}
			(void)cat_update(hfsmp, &hfsmp->hfs_private_desc[FILE_HARDLINKS],
				&hfsmp->hfs_private_attr[FILE_HARDLINKS], NULL, NULL);
		}

		hfs_systemfile_unlock(hfsmp, lockflags);

		if (error)
			goto out;

#if QUOTA
		if (hfsmp->hfs_flags & HFS_QUOTAS)
			(void)hfs_chkiq(cp, -1, NOCRED, 0);
#endif /* QUOTA */
		
		/* Already set C_NOEXISTS at the beginning of this block */
		cp->c_flag &= ~C_DELETED;
		cp->c_touch_chgtime = TRUE;
		cp->c_touch_modtime = TRUE;

		if (error == 0)
			hfs_volupdate(hfsmp, (v_type == VDIR) ? VOL_RMDIR : VOL_RMFILE, 0);
	}

	/*
	 * A file may have had delayed allocations, in which case hfs_update
	 * would not have updated the catalog record (cat_update).  We need
	 * to do that now, before we lose our fork data.  We also need to
	 * force the update, or hfs_update will again skip the cat_update.
	 */
	if ((cp->c_flag & C_MODIFIED) ||
	    cp->c_touch_acctime || cp->c_touch_chgtime || cp->c_touch_modtime) {
	    if ((cp->c_flag & C_MODIFIED) || cp->c_touch_modtime){
			cp->c_flag |= C_FORCEUPDATE;
		}	
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
	/* 
	 * This has been removed from the namespace and has no backing store
	 * in the catalog, so we should force a reclaim as soon as possible.
	 * Also, we want to check the flag while we still have the cnode lock.
	 */
	if (cp->c_flag & C_NOEXISTS) 
		recycle = 1;

	hfs_unlock(cp);

	if (took_trunc_lock)
	    hfs_unlock_truncate(cp, TRUE);

	/*
	 * If we are done with the vnode, reclaim it
	 * so that it can be reused immediately.
	 */
	if (recycle)
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
	struct rl_entry *invalid_range;
	off_t leof;
	u_int32_t blks, blocksize;

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
	while ((invalid_range = TAILQ_FIRST(&fp->ff_invalidranges))) {
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
		(void) hfs_truncate(vp, leof, IO_NDELAY, 0, 0, context);
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
	struct hfsmount *hfsmp = VTOHFS(vp);
	int reclaim_cnode = 0;

	(void) hfs_lock(VTOC(vp), HFS_FORCE_LOCK);
	cp = VTOC(vp);
	
	/*
	 * A file may have had delayed allocations, in which case hfs_update
	 * would not have updated the catalog record (cat_update).  We need
	 * to do that now, before we lose our fork data.  We also need to
	 * force the update, or hfs_update will again skip the cat_update.
	 */
	if ((cp->c_flag & C_MODIFIED) ||
	    cp->c_touch_acctime || cp->c_touch_chgtime || cp->c_touch_modtime) {
	    if ((cp->c_flag & C_MODIFIED) || cp->c_touch_modtime){
			cp->c_flag |= C_FORCEUPDATE;
		}
		hfs_update(vp, 0);
	}

	/*
	 * Keep track of an inactive hot file.
	 */
	if (!vnode_isdir(vp) &&
	    !vnode_issystem(vp) &&
	    !(cp->c_flag & (C_DELETED | C_NOEXISTS)) ) {
  		(void) hfs_addhotfile(vp);
	}
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
	        panic("hfs_vnop_reclaim: vp points to wrong cnode (vp=%p cp->c_vp=%p cp->c_rsrc_vp=%p)\n", vp, cp->c_vp, cp->c_rsrc_vp);
	}
	/*
	 * On the last fork, remove the cnode from its hash chain.
	 */
	if (altfp == NULL) {
		/* If we can't remove it then the cnode must persist! */
		if (hfs_chashremove(hfsmp, cp) == 0)
			reclaim_cnode = 1;
		/* 
		 * Remove any directory hints
		 */
		if (vnode_isdir(vp)) {
			hfs_reldirhints(cp, 0);
		}
		
		if(cp->c_flag & C_HARDLINK) {
			hfs_relorigins(cp);
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
		hfs_chashwakeup(hfsmp, cp, H_ALLOC | H_TRANSIT);
		hfs_reclaim_cnode(cp);
	} else /* cnode in use */ {
		hfs_unlock(cp);
	}

	vnode_clearfsnode(vp);
	return (0);
}


extern int (**hfs_vnodeop_p) (void *);
extern int (**hfs_std_vnodeop_p) (void *);
extern int (**hfs_specop_p)  (void *);
#if FIFO
extern int (**hfs_fifoop_p)  (void *);
#endif

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
	int flags,
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
	int hfs_standard = 0;
	int retval;
	int issystemfile;
	int wantrsrc;
	struct vnode_fsparam vfsp;
	enum vtype vtype;
#if QUOTA
	int i;
#endif /* QUOTA */

	hfs_standard = (hfsmp->hfs_flags & HFS_STANDARD);

	if (attrp->ca_fileid == 0) {
		*vpp = NULL;
		return (ENOENT);
	}

#if !FIFO
	if (IFTOVT(attrp->ca_mode) == VFIFO) {
		*vpp = NULL;
		return (ENOTSUP);
	}
#endif /* !FIFO */
	vtype = IFTOVT(attrp->ca_mode);
	issystemfile = (descp->cd_flags & CD_ISMETA) && (vtype == VREG);
	wantrsrc = flags & GNV_WANTRSRC;

#ifdef HFS_CHECK_LOCK_ORDER
	/*
	 * The only case were its permissible to hold the parent cnode
	 * lock is during a create operation (hfs_makenode) or when
	 * we don't need the cnode lock (GNV_SKIPLOCK).
	 */
	if ((dvp != NULL) &&
	    (flags & (GNV_CREATE | GNV_SKIPLOCK)) == 0 &&
	    VTOC(dvp)->c_lockowner == current_thread()) {
		panic("hfs_getnewvnode: unexpected hold of parent cnode %p", VTOC(dvp));
	}
#endif /* HFS_CHECK_LOCK_ORDER */

	/*
	 * Get a cnode (new or existing)
	 */
	cp = hfs_chash_getcnode(hfsmp, attrp->ca_fileid, vpp, wantrsrc, (flags & GNV_SKIPLOCK));

	/*
	 * If the id is no longer valid for lookups we'll get back a NULL cp.
	 */
	if (cp == NULL) {
		return (ENOENT);
	}

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
#if HFS_COMPRESSION
		cp->c_decmp = NULL;
#endif

		/* Make sure its still valid (ie exists on disk). */
		if (!(flags & GNV_CREATE) &&
		    !hfs_valid_cnode(hfsmp, dvp, (wantrsrc ? NULL : cnp), cp->c_fileid)) {
			hfs_chash_abort(hfsmp, cp);
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
		if ((vtype == VREG || vtype == VDIR) &&
		    ((descp->cd_cnid != attrp->ca_fileid) ||
		     (attrp->ca_recflags & kHFSHasLinkChainMask))) {
			cp->c_flag |= C_HARDLINK;
		}
		/*
		 * Fix-up dir link counts.
		 *
		 * Earlier versions of Leopard used ca_linkcount for posix
		 * nlink support (effectively the sub-directory count + 2).
		 * That is now accomplished using the ca_dircount field with
		 * the corresponding kHFSHasFolderCountMask flag.
		 *
		 * For directories the ca_linkcount is the true link count,
		 * tracking the number of actual hardlinks to a directory.
		 *
		 * We only do this if the mount has HFS_FOLDERCOUNT set;
		 * at the moment, we only set that for HFSX volumes.
		 */
		if ((hfsmp->hfs_flags & HFS_FOLDERCOUNT) && 
		    (vtype == VDIR) &&
		    !(attrp->ca_recflags & kHFSHasFolderCountMask) &&
		    (cp->c_attr.ca_linkcount > 1)) {
			if (cp->c_attr.ca_entries == 0)
				cp->c_attr.ca_dircount = 0;
			else
				cp->c_attr.ca_dircount = cp->c_attr.ca_linkcount - 2;

			cp->c_attr.ca_linkcount = 1;
			cp->c_attr.ca_recflags |= kHFSHasFolderCountMask;
			if ( !(hfsmp->hfs_flags & HFS_READ_ONLY) )
				cp->c_flag |= C_MODIFIED;
		}
#if QUOTA
		if (hfsmp->hfs_flags & HFS_QUOTAS) {
			for (i = 0; i < MAXQUOTAS; i++)
				cp->c_dquot[i] = NODQUOT;
		}
#endif /* QUOTA */
	}

	if (vtype == VDIR) {
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
	if ((cp->c_flag & C_HARDLINK) && (vtype == VDIR)) {
		vfsp.vnfs_dvp = NULL;  /* no parent for me! */
		vfsp.vnfs_cnp = NULL;  /* no name for me! */
	} else {
		vfsp.vnfs_dvp = dvp;
		vfsp.vnfs_cnp = cnp;
	}
	vfsp.vnfs_fsnode = cp;

	/*
	 * Special Case HFS Standard VNOPs from HFS+, since
	 * HFS standard is readonly/deprecated as of 10.6 
	 */

#if FIFO
	if (vtype == VFIFO ) 
		vfsp.vnfs_vops = hfs_fifoop_p;
	else
#endif
	if (vtype == VBLK || vtype == VCHR)
		vfsp.vnfs_vops = hfs_specop_p;
	else if (hfs_standard)
		vfsp.vnfs_vops = hfs_std_vnodeop_p;
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

	vfsp.vnfs_flags = VNFS_ADDFSREF;
	if (dvp == NULLVP || cnp == NULL || !(cnp->cn_flags & MAKEENTRY))
		vfsp.vnfs_flags |= VNFS_NOCACHE;

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
			hfs_chash_abort(hfsmp, cp);
			hfs_reclaim_cnode(cp);
		} 
		else {
			hfs_chashwakeup(hfsmp, cp, H_ALLOC | H_ATTACH);
			if ((flags & GNV_SKIPLOCK) == 0){
				hfs_unlock(cp);
			}
		}
		*vpp = NULL;
		return (retval);
	}
	vp = *cvpp;
	vnode_settag(vp, VT_HFS);
	if (cp->c_flag & C_HARDLINK) {
		vnode_setmultipath(vp);
	}
	/*
	 * Tag resource fork vnodes as needing an VNOP_INACTIVE
	 * so that any deferred removes (open unlinked files)
	 * have the chance to process the resource fork.
	 */
	if (VNODE_IS_RSRC(vp)) {
		int err;
		KERNEL_DEBUG_CONSTANT((FSDBG_CODE(DBG_FSRW, 37)), cp->c_vp, cp->c_rsrc_vp, 0, 0, 0);

		/* Force VL_NEEDINACTIVE on this vnode */
		err = vnode_ref(vp);
		if (err == 0) {
			vnode_rele(vp);
		}
	}
	hfs_chashwakeup(hfsmp, cp, H_ALLOC | H_ATTACH);

	/*
	 * Stop tracking an active hot file.
	 */
	if (!(flags & GNV_CREATE) && (vtype != VDIR) && !issystemfile) {
		(void) hfs_removehotfile(vp);
	}

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

	/* 
	 * If the descriptor has a name then release it
	 */
	if ((cp->c_desc.cd_flags & CD_HASBUF) && (cp->c_desc.cd_nameptr != 0)) {
		const char *nameptr;

		nameptr = (const char *) cp->c_desc.cd_nameptr;
		cp->c_desc.cd_nameptr = 0;
		cp->c_desc.cd_flags &= ~CD_HASBUF;
		cp->c_desc.cd_namelen = 0;
		vfs_removename(nameptr);
	}

	lck_rw_destroy(&cp->c_rwlock, hfs_rwlock_group);
	lck_rw_destroy(&cp->c_truncatelock, hfs_rwlock_group);
#if HFS_COMPRESSION
	if (cp->c_decmp) {
		decmpfs_cnode_destroy(cp->c_decmp);
		FREE_ZONE(cp->c_decmp, sizeof(*(cp->c_decmp)), M_DECMPFS_CNODE);
	}
#endif
	bzero(cp, sizeof(struct cnode));
	FREE_ZONE(cp, sizeof(struct cnode), M_HFSNODE);
}


__private_extern__
int
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
		cndesc.cd_nameptr = (const u_int8_t *)cnp->cn_nameptr;
		cndesc.cd_namelen = cnp->cn_namelen;
		cndesc.cd_parentcnid = VTOC(dvp)->c_fileid;
		cndesc.cd_hint = VTOC(dvp)->c_childhint;

		if ((cat_lookup(hfsmp, &cndesc, 0, NULL, &attr, NULL, NULL) == 0) &&
		    (cnid == attr.ca_fileid)) {
			stillvalid = 1;
		}
	} else {
		if (cat_idlookup(hfsmp, cnid, 0, NULL, NULL, NULL) == 0) {
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
	/* don't modify times if volume is read-only */
	if (hfsmp->hfs_flags & HFS_READ_ONLY) {
		cp->c_touch_acctime = FALSE;
		cp->c_touch_chgtime = FALSE;
		cp->c_touch_modtime = FALSE;
	}
	else if (hfsmp->hfs_flags & HFS_STANDARD) {
	/* HFS Standard doesn't support access times */
		cp->c_touch_acctime = FALSE;
	}

	/*
	 * Skip access time updates if:
	 *	. MNT_NOATIME is set
	 *	. a file system freeze is in progress
	 *	. a file system resize is in progress
	 *	. the vnode associated with this cnode is marked for rapid aging
	 */
	if (cp->c_touch_acctime) {
		if ((vfs_flags(hfsmp->hfs_mp) & MNT_NOATIME) ||
		    (hfsmp->hfs_freezing_proc != NULL) ||
		    (hfsmp->hfs_flags & HFS_RESIZE_IN_PROGRESS) ||
		    (cp->c_vp && vnode_israge(cp->c_vp)))
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
			MarkVCBDirty(hfsmp);
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

	if (cp->c_lockowner == thread) {
		/*
		 * Only the extents and bitmap file's support lock recursion.
		 */
		if ((cp->c_fileid == kHFSExtentsFileID) ||
		    (cp->c_fileid == kHFSAllocationFileID)) {
			cp->c_syslockcount++;
		} else {
			panic("hfs_lock: locking against myself!");
		}
	} else if (locktype == HFS_SHARED_LOCK) {
		lck_rw_lock_shared(&cp->c_rwlock);
		cp->c_lockowner = HFS_SHARED_OWNER;

	} else /* HFS_EXCLUSIVE_LOCK */ {
		lck_rw_lock_exclusive(&cp->c_rwlock);
		cp->c_lockowner = thread;

		/*
		 * Only the extents and bitmap file's support lock recursion.
		 */
		if ((cp->c_fileid == kHFSExtentsFileID) ||
		    (cp->c_fileid == kHFSAllocationFileID)) {
			cp->c_syslockcount = 1;
		}
	}

#ifdef HFS_CHECK_LOCK_ORDER
	/*
	 * Regular cnodes (non-system files) cannot be locked
	 * while holding the journal lock or a system file lock.
	 */
	if (!(cp->c_desc.cd_flags & CD_ISMETA) &&
            ((cp->c_fileid > kHFSFirstUserCatalogNodeID) || (cp->c_fileid == kHFSRootFolderID))) {
		vnode_t vp = NULLVP;

		/* Find corresponding vnode. */
		if (cp->c_vp != NULLVP && VTOC(cp->c_vp) == cp) {
			vp = cp->c_vp;
		} else if (cp->c_rsrc_vp != NULLVP && VTOC(cp->c_rsrc_vp) == cp) {
			vp = cp->c_rsrc_vp;
		}
		if (vp != NULLVP) {
			struct hfsmount *hfsmp = VTOHFS(vp);

			if (hfsmp->jnl && (journal_owner(hfsmp->jnl) == thread)) {
				/* This will eventually be a panic here. */
				printf("hfs_lock: bad lock order (cnode after journal)\n");
			}
			if (hfsmp->hfs_catalog_cp && hfsmp->hfs_catalog_cp->c_lockowner == thread) {
				panic("hfs_lock: bad lock order (cnode after catalog)");
			}
			if (hfsmp->hfs_attribute_cp && hfsmp->hfs_attribute_cp->c_lockowner == thread) {
				panic("hfs_lock: bad lock order (cnode after attribute)");
			}
			if (hfsmp->hfs_extents_cp && hfsmp->hfs_extents_cp->c_lockowner == thread) {
				panic("hfs_lock: bad lock order (cnode after extents)");
			}
		}
	}
#endif /* HFS_CHECK_LOCK_ORDER */
	
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
	 * Lock in cnode address order.
	 */
	if (cp1 < cp2) {
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
	/*
	 * Locking order is cnode address order.
	 */
	return (cp1 < cp2);
}

/*
 * Acquire 4 cnode locks.
 *   - locked in cnode address order (lesser address first).
 *   - all or none of the locks are taken
 *   - only one lock taken per cnode (dup cnodes are skipped)
 *   - some of the cnode pointers may be null
 */
__private_extern__
int
hfs_lockfour(struct cnode *cp1, struct cnode *cp2, struct cnode *cp3,
             struct cnode *cp4, enum hfslocktype locktype, struct cnode **error_cnode)
{
	struct cnode * a[3];
	struct cnode * b[3];
	struct cnode * list[4];
	struct cnode * tmp;
	int i, j, k;
	int error;
	if (error_cnode) {
		*error_cnode = NULL;
	}

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
				/* Only stuff error_cnode if requested */
				if (error_cnode) {
					*error_cnode = list[i];
				}
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
	void *lockowner;

	/*
	 * Only the extents and bitmap file's support lock recursion.
	 */
	if ((cp->c_fileid == kHFSExtentsFileID) ||
	    (cp->c_fileid == kHFSAllocationFileID)) {
		if (--cp->c_syslockcount > 0) {
			return;
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

	lockowner = cp->c_lockowner;
	if (lockowner == current_thread()) {
	    cp->c_lockowner = NULL;
	    lck_rw_unlock_exclusive(&cp->c_rwlock);
	} else {
	    lck_rw_unlock_shared(&cp->c_rwlock);
	}

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
#ifdef HFS_CHECK_LOCK_ORDER
	if (cp->c_lockowner == current_thread())
		panic("hfs_lock_truncate: cnode %p locked!", cp);
#endif /* HFS_CHECK_LOCK_ORDER */

	if (exclusive)
		lck_rw_lock_exclusive(&cp->c_truncatelock);
	else
		lck_rw_lock_shared(&cp->c_truncatelock);
}

__private_extern__
void
hfs_unlock_truncate(struct cnode *cp, int exclusive)
{
    if (exclusive) {
	lck_rw_unlock_exclusive(&cp->c_truncatelock);
    } else {
	lck_rw_unlock_shared(&cp->c_truncatelock);
    }
}




