/*
 * Copyright (c) 2002-2014 Apple Inc. All rights reserved.
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
#include <libkern/OSByteOrder.h>
#include <sys/buf_internal.h>

#include <kern/locks.h>

#include <miscfs/specfs/specdev.h>
#include <miscfs/fifofs/fifo.h>

#include <hfs/hfs.h>
#include <hfs/hfs_catalog.h>
#include <hfs/hfs_cnode.h>
#include <hfs/hfs_quota.h>
#include <hfs/hfs_format.h>
#include <hfs/hfs_kdebug.h>

extern int prtactive;

extern lck_attr_t *  hfs_lock_attr;
extern lck_grp_t *  hfs_mutex_group;
extern lck_grp_t *  hfs_rwlock_group;

static void  hfs_reclaim_cnode(struct cnode *);
static int hfs_cnode_teardown (struct vnode *vp, vfs_context_t ctx, int reclaim);
static int hfs_isordered(struct cnode *, struct cnode *);

extern int hfs_removefile_callback(struct buf *bp, void *hfsmp);


__inline__ int hfs_checkdeleted (struct cnode *cp) {
	return ((cp->c_flag & (C_DELETED | C_NOEXISTS)) ? ENOENT : 0);	
}

/*
 * Function used by a special fcntl() that decorates a cnode/vnode that
 * indicates it is backing another filesystem, like a disk image.
 *
 * the argument 'val' indicates whether or not to set the bit in the cnode flags
 * 
 * Returns non-zero on failure. 0 on success 
 */
int hfs_set_backingstore (struct vnode *vp, int val) {
	struct cnode *cp = NULL;
	int err = 0;
	
	cp = VTOC(vp);
	if (!vnode_isreg(vp) && !vnode_isdir(vp)) {
		return EINVAL;
	}

	/* lock the cnode */
	err = hfs_lock (cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
	if (err) {
		return err;
	}
	
	if (val) {
		cp->c_flag |= C_BACKINGSTORE;
	}
	else {
		cp->c_flag &= ~C_BACKINGSTORE;
	}

	/* unlock everything */
	hfs_unlock (cp);

	return err;
}

/*
 * Function used by a special fcntl() that check to see if a cnode/vnode
 * indicates it is backing another filesystem, like a disk image.
 *
 * the argument 'val' is an output argument for whether or not the bit is set
 * 
 * Returns non-zero on failure. 0 on success 
 */

int hfs_is_backingstore (struct vnode *vp, int *val) {
	struct cnode *cp = NULL;
	int err = 0;

	if (!vnode_isreg(vp) && !vnode_isdir(vp)) {
		*val = 0;
		return 0;
	}

	cp = VTOC(vp);

	/* lock the cnode */
	err = hfs_lock (cp, HFS_SHARED_LOCK, HFS_LOCK_DEFAULT);
	if (err) {
		return err;
	}

	if (cp->c_flag & C_BACKINGSTORE) {
		*val = 1;
	}	
	else {
		*val = 0;
	}

	/* unlock everything */
	hfs_unlock (cp);

	return err;
}


/*
 * hfs_cnode_teardown
 *
 * This is an internal function that is invoked from both hfs_vnop_inactive
 * and hfs_vnop_reclaim.  As VNOP_INACTIVE is not necessarily called from vnodes
 * being recycled and reclaimed, it is important that we do any post-processing
 * necessary for the cnode in both places.  Important tasks include things such as
 * releasing the blocks from an open-unlinked file when all references to it have dropped,
 * and handling resource forks separately from data forks.
 *
 * Note that we take only the vnode as an argument here (rather than the cnode).
 * Recall that each cnode supports two forks (rsrc/data), and we can always get the right
 * cnode from either of the vnodes, but the reverse is not true -- we can't determine which
 * vnode we need to reclaim if only the cnode is supplied. 
 *
 * This function is idempotent and safe to call from both hfs_vnop_inactive and hfs_vnop_reclaim
 * if both are invoked right after the other.  In the second call, most of this function's if()
 * conditions will fail, since they apply generally to cnodes still marked with C_DELETED.  
 * As a quick check to see if this function is necessary, determine if the cnode is already
 * marked C_NOEXISTS.  If it is, then it is safe to skip this function.  The only tasks that 
 * remain for cnodes marked in such a fashion is to teardown their fork references and 
 * release all directory hints and hardlink origins.  However, both of those are done 
 * in hfs_vnop_reclaim.  hfs_update, by definition, is not necessary if the cnode's catalog
 * entry is no longer there.  
 *
 * 'reclaim' argument specifies whether or not we were called from hfs_vnop_reclaim.  If we are
 * invoked from hfs_vnop_reclaim, we can not call functions that cluster_push since the UBC info 
 * is totally gone by that point.
 *
 * Assumes that both truncate and cnode locks for 'cp' are held.
 */
static 
int hfs_cnode_teardown (struct vnode *vp, vfs_context_t ctx, int reclaim) 
{
	int forkcount = 0;
	enum vtype v_type;
	struct cnode *cp;
	int error = 0;
	int started_tr = 0;
	struct hfsmount *hfsmp = VTOHFS(vp);
	struct proc *p = vfs_context_proc(ctx);
	int truncated = 0;
    cat_cookie_t cookie;
    int cat_reserve = 0;
    int lockflags;
	int ea_error = 0;
	
	v_type = vnode_vtype(vp);
	cp = VTOC(vp);
	
	if (cp->c_datafork) {
		++forkcount;
	}
	if (cp->c_rsrcfork) {
		++forkcount;
	}
	
	
	/*
	 * Skip the call to ubc_setsize if we're being invoked on behalf of reclaim.
	 * The dirty regions would have already been synced to disk, so informing UBC
	 * that they can toss the pages doesn't help anyone at this point. 
	 * 
	 * Note that this is a performance problem if the vnode goes straight to reclaim
	 * (and skips inactive), since there would be no way for anyone to notify the UBC
	 * that all pages in this file are basically useless.
	 */	
	if (reclaim == 0) {
		/*
		 * Check whether we are tearing down a cnode with only one remaining fork.
		 * If there are blocks in its filefork, then we need to unlock the cnode
		 * before calling ubc_setsize.  The cluster layer may re-enter the filesystem
		 * (i.e. VNOP_BLOCKMAP), and if we retain the cnode lock, we could double-lock
		 * panic.  
		 */
		
		if ((v_type == VREG || v_type == VLNK) &&
			(cp->c_flag & C_DELETED) &&
			(VTOF(vp)->ff_blocks != 0) && (forkcount == 1)) {
			hfs_unlock(cp); 
			/* ubc_setsize just fails if we were to call this from VNOP_RECLAIM */
			ubc_setsize(vp, 0);
			(void) hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);
		}	
	}
	
	/* 
	 * Push file data out for normal files that haven't been evicted from 
	 * the namespace.  We only do this if this function was not called from reclaim,
	 * because by that point the UBC information has been totally torn down.  
	 * 
	 * There should also be no way that a normal file that has NOT been deleted from 
	 * the namespace to skip INACTIVE and go straight to RECLAIM.  That race only happens
	 * when the file becomes open-unlinked. 
	 */
	if ((v_type == VREG) && 
		(!ISSET(cp->c_flag, C_DELETED)) && 
		(!ISSET(cp->c_flag, C_NOEXISTS)) &&
		(VTOF(vp)->ff_blocks) &&
		(reclaim == 0)) {
		/* 
		 * Note that if content protection is enabled, then this is where we will
		 * attempt to issue IOs for all dirty regions of this file.  
		 *
		 * If we're called from hfs_vnop_inactive, all this means is at the time 
		 * the logic for deciding to call this function, there were not any lingering
		 * mmap/fd references for this file.  However, there is nothing preventing the system
		 * from creating a new reference in between the time that logic was checked
		 * and we entered hfs_vnop_inactive.  As a result, the only time we can guarantee
		 * that there aren't any references is during vnop_reclaim.
		 */
		hfs_filedone(vp, ctx, 0);
	}

	/* 
	 * We're holding the cnode lock now.  Stall behind any shadow BPs that may
	 * be involved with this vnode if it is a symlink.  We don't want to allow 
	 * the blocks that we're about to release to be put back into the pool if there
	 * is pending I/O to them.
	 */
	if (v_type == VLNK) {	
		/* 
		 * This will block if the asynchronous journal flush is in progress.
		 * If this symlink is not being renamed over and doesn't have any open FDs,
		 * then we'll remove it from the journal's bufs below in kill_block.
		 */
		buf_wait_for_shadow_io (vp, 0);
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
	 *	Truncate away own fork data. If rsrc fork is not in core, truncate it too.
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
	
	if ((v_type == VREG || v_type == VLNK) && 
			(cp->c_flag & C_DELETED) &&
			((forkcount == 1) || (!VNODE_IS_RSRC(vp)))) {
			
		/* Truncate away our own fork data. (Case A, B, C above) */
		if (VTOF(vp)->ff_blocks != 0) {

			/* 
			 * SYMLINKS only:
			 *
			 * Encapsulate the entire change (including truncating the link) in 
			 * nested transactions if we are modifying a symlink, because we know that its
			 * file length will be at most 4k, and we can fit both the truncation and 
			 * any relevant bitmap changes into a single journal transaction.  We also want
			 * the kill_block code to execute in the same transaction so that any dirty symlink
			 * blocks will not be written. Otherwise, rely on
			 * hfs_truncate doing its own transactions to ensure that we don't blow up
			 * the journal.
			 */ 
			if ((started_tr == 0) && (v_type == VLNK)) {
				if (hfs_start_transaction(hfsmp) != 0) {
					error = EINVAL;
					goto out;
				}
				else {
					started_tr = 1;
				}
			}

			/*
			 * At this point, we have decided that this cnode is
			 * suitable for full removal.  We are about to deallocate
			 * its blocks and remove its entry from the catalog. 
			 * If it was a symlink, then it's possible that the operation
			 * which created it is still in the current transaction group
			 * due to coalescing.  Take action here to kill the data blocks
			 * of the symlink out of the journal before moving to 
			 * deallocate the blocks.  We need to be in the middle of
			 * a transaction before calling buf_iterate like this.
			 * 
			 * Note: we have to kill any potential symlink buffers out of 
			 * the journal prior to deallocating their blocks.  This is so 
			 * that we don't race with another thread that may be doing an 
			 * an allocation concurrently and pick up these blocks. It could
			 * generate I/O against them which could go out ahead of our journal
			 * transaction.
			 */

			if (hfsmp->jnl && vnode_islnk(vp)) {
				buf_iterate(vp, hfs_removefile_callback, BUF_SKIP_NONLOCKED, (void *)hfsmp);
			}


			/*
			 * This truncate call (and the one below) is fine from VNOP_RECLAIM's 
			 * context because we're only removing blocks, not zero-filling new 
			 * ones.  The C_DELETED check above makes things much simpler. 
			 */
			error = hfs_truncate(vp, (off_t)0, IO_NDELAY, 0, ctx);
			if (error) {
				goto out;
			}
			truncated = 1;

			/* (SYMLINKS ONLY): Close/End our transaction after truncating the file record */
			if (started_tr) {
				hfs_end_transaction(hfsmp);
				started_tr = 0;
			}

		}
		
		/* 
		 * Truncate away the resource fork, if we represent the data fork and
		 * it is the last fork.  That means, by definition, the rsrc fork is not in 
		 * core.  To avoid bringing a vnode into core for the sole purpose of deleting the
		 * data in the resource fork, we call cat_lookup directly, then hfs_release_storage
		 * to get rid of the resource fork's data. Note that because we are holding the 
		 * cnode lock, it is impossible for a competing thread to create the resource fork
		 * vnode from underneath us while we do this.
		 * 
		 * This is invoked via case A above only.
		 */
		if ((cp->c_blocks > 0) && (forkcount == 1) && (vp != cp->c_rsrc_vp)) {
			struct cat_lookup_buffer *lookup_rsrc = NULL;
			struct cat_desc *desc_ptr = NULL;
			lockflags = 0;

			MALLOC(lookup_rsrc, struct cat_lookup_buffer*, sizeof (struct cat_lookup_buffer), M_TEMP, M_WAITOK);
			if (lookup_rsrc == NULL) {
				printf("hfs_cnode_teardown: ENOMEM from MALLOC\n");
				error = ENOMEM;
				goto out;
			}
			else {
				bzero (lookup_rsrc, sizeof (struct cat_lookup_buffer));
			}

			if (cp->c_desc.cd_namelen == 0) {
				/* Initialize the rsrc descriptor for lookup if necessary*/
				MAKE_DELETED_NAME (lookup_rsrc->lookup_name, HFS_TEMPLOOKUP_NAMELEN, cp->c_fileid);
				
				lookup_rsrc->lookup_desc.cd_nameptr = (const uint8_t*) lookup_rsrc->lookup_name;
				lookup_rsrc->lookup_desc.cd_namelen = strlen (lookup_rsrc->lookup_name);
				lookup_rsrc->lookup_desc.cd_parentcnid = hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid;
				lookup_rsrc->lookup_desc.cd_cnid = cp->c_cnid;	
				
				desc_ptr = &lookup_rsrc->lookup_desc;
			}
			else {
				desc_ptr = &cp->c_desc;	
			}

			lockflags = hfs_systemfile_lock (hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);

			error = cat_lookup (hfsmp, desc_ptr, 1, 0, (struct cat_desc *) NULL, 
					(struct cat_attr*) NULL, &lookup_rsrc->lookup_fork.ff_data, NULL);

			hfs_systemfile_unlock (hfsmp, lockflags);
			
			if (error) {
				FREE (lookup_rsrc, M_TEMP);
				goto out;
			}

			/*
			 * Make the filefork in our temporary struct look like a real 
			 * filefork.  Fill in the cp, sysfileinfo and rangelist fields..
			 */
			rl_init (&lookup_rsrc->lookup_fork.ff_invalidranges);
			lookup_rsrc->lookup_fork.ff_cp = cp;

			/* 
			 * If there were no errors, then we have the catalog's fork information 
			 * for the resource fork in question.  Go ahead and delete the data in it now.
			 */

			error = hfs_release_storage (hfsmp, NULL, &lookup_rsrc->lookup_fork, cp->c_fileid);
			FREE(lookup_rsrc, M_TEMP);

			if (error) {
				goto out;
			}

			/*
			 * This fileid's resource fork extents have now been fully deleted on-disk
			 * and this CNID is no longer valid. At this point, we should be able to
			 * zero out cp->c_blocks to indicate there is no data left in this file.
			 */
			cp->c_blocks = 0;
		}
	}
	
	/*
	 * If we represent the last fork (or none in the case of a dir), 
	 * and the cnode has become open-unlinked,
	 * AND it has EA's, then we need to get rid of them.
	 *
	 * Note that this must happen outside of any other transactions
	 * because it starts/ends its own transactions and grabs its
	 * own locks.  This is to prevent a file with a lot of attributes
	 * from creating a transaction that is too large (which panics).
	 */
    if ((cp->c_attr.ca_recflags & kHFSHasAttributesMask) != 0 &&
		(cp->c_flag & C_DELETED) && 
		(forkcount <= 1)) {
		
        ea_error = hfs_removeallattr(hfsmp, cp->c_fileid);
    }
	
	
	/*
	 * If the cnode represented an open-unlinked file, then now
	 * actually remove the cnode's catalog entry and release all blocks
	 * it may have been using.  
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
		
        if (error && truncated && (error != ENXIO)) {
            printf("hfs_inactive: couldn't delete a truncated file!");
	}
		
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
		
        if (error) {			
			goto out;
		}
		
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
	 *
	 * If the file has C_NOEXISTS set, then we can skip the hfs_update call
	 * because the catalog entry has already been removed.  There would be no point
     * to looking up the entry in the catalog to modify it when we already know it's gone
	 */
    if ((!ISSET(cp->c_flag, C_NOEXISTS)) &&
		((cp->c_flag & C_MODIFIED) || cp->c_touch_acctime || 
		 cp->c_touch_chgtime || cp->c_touch_modtime)) {
			
			if ((cp->c_flag & C_MODIFIED) || cp->c_touch_modtime){
				cp->c_flag |= C_FORCEUPDATE;
			}
			hfs_update(vp, 0);
		}

	/*
	 * Since we are about to finish what might be an inactive call, propagate
	 * any remaining modified or touch bits from the cnode to the vnode.  This
	 * serves as a hint to vnode recycling that we shouldn't recycle this vnode
	 * synchronously.
	 */
	if (ISSET(cp->c_flag, C_MODIFIED) || ISSET(cp->c_flag, C_FORCEUPDATE) ||
		cp->c_touch_acctime || cp->c_touch_chgtime ||
		cp->c_touch_modtime || ISSET(cp->c_flag, C_NEEDS_DATEADDED) ||
		ISSET(cp->c_flag, C_DELETED)) {
		vnode_setdirty(vp);
	} else {
		vnode_cleardirty(vp);
	}
        
out:
    if (cat_reserve)
        cat_postflight(hfsmp, &cookie, p);
	
    // XXXdbg - have to do this because a goto could have come here
    if (started_tr) {
        hfs_end_transaction(hfsmp);
        started_tr = 0;
    }

#if 0
#if CONFIG_PROTECT
	/* 
	 * cnode truncate lock and cnode lock are both held exclusive here. 
	 *
	 * Go ahead and flush the keys out if this cnode is the last fork
	 * and it is not class F.  Class F keys should not be purged because they only
	 * exist in memory and have no persistent keys.  Only do this 
	 * if we haven't already done it yet (maybe a vnode skipped inactive 
	 * and went straight to reclaim).  This function gets called from both reclaim and
	 * inactive, so it will happen first in inactive if possible.
	 * 
	 * We need to be mindful that all pending IO for this file has already been
	 * issued and completed before we bzero out the key.  This is because
	 * if it isn't, tossing the key here could result in garbage IO being
	 * written (by using the bzero'd key) if the writes are happening asynchronously.
	 * 
	 * In addition, class A files may have already been purged due to the 
	 * lock event occurring.
	 */
	if (forkcount == 1) {
		struct cprotect *entry = cp->c_cpentry;
		if ((entry) && ( CP_CLASS(entry->cp_pclass) != PROTECTION_CLASS_F)) {
			if ((cp->c_cpentry->cp_flags & CP_KEY_FLUSHED) == 0) {
				cp->c_cpentry->cp_flags |= CP_KEY_FLUSHED;
				bzero (cp->c_cpentry->cp_cache_key, cp->c_cpentry->cp_cache_key_len);
				bzero (cp->c_cpentry->cp_cache_iv_ctx, sizeof(aes_encrypt_ctx));
			}
		}
	}
#endif
#endif
	
	return error;	
}


/*
 * hfs_vnop_inactive
 *
 * The last usecount on the vnode has gone away, so we need to tear down
 * any remaining data still residing in the cnode.  If necessary, write out
 * remaining blocks or delete the cnode's entry in the catalog.
 */
int
hfs_vnop_inactive(struct vnop_inactive_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct cnode *cp;
	struct hfsmount *hfsmp = VTOHFS(vp);
	struct proc *p = vfs_context_proc(ap->a_context);
	int error = 0;
	int took_trunc_lock = 0;
	enum vtype v_type;
	
	v_type = vnode_vtype(vp);
	cp = VTOC(vp);

	if ((hfsmp->hfs_flags & HFS_READ_ONLY) || vnode_issystem(vp) ||
	    (hfsmp->hfs_freezing_proc == p)) {
		error = 0;
		goto inactive_done;
	}	
	
	/*
	 * For safety, do NOT call vnode_recycle from inside this function.  This can cause 
	 * problems in the following scenario:
	 * 
	 * vnode_create -> vnode_reclaim_internal -> vclean -> VNOP_INACTIVE
	 * 
	 * If we're being invoked as a result of a reclaim that was already in-flight, then we
	 * cannot call vnode_recycle again.  Being in reclaim means that there are no usecounts or
	 * iocounts by definition.  As a result, if we were to call vnode_recycle, it would immediately
	 * try to re-enter reclaim again and panic.  
	 *
	 * Currently, there are three things that can cause us (VNOP_INACTIVE) to get called.
	 * 1) last usecount goes away on the vnode (vnode_rele)
	 * 2) last iocount goes away on a vnode that previously had usecounts but didn't have 
	 * 		vnode_recycle called (vnode_put)
	 * 3) vclean by way of reclaim
	 *
	 * In this function we would generally want to call vnode_recycle to speed things 
	 * along to ensure that we don't leak blocks due to open-unlinked files.  However, by 
	 * virtue of being in this function already, we can call hfs_cnode_teardown, which 
	 * will release blocks held by open-unlinked files, and mark them C_NOEXISTS so that 
	 * there's no entry in the catalog and no backing store anymore.  If that's the case, 
	 * then we really don't care all that much when the vnode actually goes through reclaim.
	 * Further, the HFS VNOPs that manipulated the namespace in order to create the open-
	 * unlinked file in the first place should have already called vnode_recycle on the vnode
	 * to guarantee that it would go through reclaim in a speedy way.
	 */
	
	if (cp->c_flag & C_NOEXISTS) {
		/* 
		 * If the cnode has already had its cat entry removed, then 
		 * just skip to the end. We don't need to do anything here.
		 */
		error = 0;
		goto inactive_done;
	}
	
	if ((v_type == VREG || v_type == VLNK)) {
		hfs_lock_truncate(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
		took_trunc_lock = 1;
	}
	
	(void) hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);
	
	/* 
	 * Call cnode_teardown to push out dirty blocks to disk, release open-unlinked
	 * files' blocks from being in use, and move the cnode from C_DELETED to C_NOEXISTS.
	 */
	error = hfs_cnode_teardown (vp, ap->a_context, 0);

    /*
     * Drop the truncate lock before unlocking the cnode
     * (which can potentially perform a vnode_put and
     * recycle the vnode which in turn might require the
     * truncate lock)
     */
	if (took_trunc_lock) {
	    hfs_unlock_truncate(cp, HFS_LOCK_DEFAULT);
	}

	hfs_unlock(cp);
	
inactive_done: 
	
	return error;
}


/*
 * File clean-up (zero fill and shrink peof).
 */

int
hfs_filedone(struct vnode *vp, vfs_context_t context,
			 hfs_file_done_opts_t opts)
{
	struct cnode *cp;
	struct filefork *fp;
	struct hfsmount *hfsmp;
	struct rl_entry *invalid_range;
	off_t leof;
	u_int32_t blks, blocksize;
	/* flags for zero-filling sparse ranges */
	int cluster_flags = IO_CLOSE;
	int cluster_zero_flags = IO_HEADZEROFILL | IO_NOZERODIRTY | IO_NOCACHE;

	cp = VTOC(vp);
	fp = VTOF(vp);
	hfsmp = VTOHFS(vp);
	leof = fp->ff_size;

	if ((hfsmp->hfs_flags & HFS_READ_ONLY) || (fp->ff_blocks == 0))
		return (0);

	if (!ISSET(opts, HFS_FILE_DONE_NO_SYNC)) {
#if CONFIG_PROTECT
		/* 
		 * Figure out if we need to do synchronous IO. 
		 * 
		 * If the file represents a content-protected file, we may need
		 * to issue synchronous IO when we dispatch to the cluster layer.
		 * If we didn't, then the IO would go out to the disk asynchronously.
		 * If the vnode hits the end of inactive before getting reclaimed, the
		 * content protection keys would be wiped/bzeroed out, and we'd end up
		 * trying to issue the IO with an invalid key.  This will lead to file 
		 * corruption.  IO_SYNC will force the cluster_push to wait until all IOs
		 * have completed (though they may be in the track cache).
		 */
		if (cp_fs_protected(VTOVFS(vp))) {
			cluster_flags |= IO_SYNC;
			cluster_zero_flags |= IO_SYNC;
		}
#endif

		hfs_unlock(cp);
		(void) cluster_push(vp, cluster_flags);
		hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);
	}

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
				     leof, end + 1, start, (off_t)0, cluster_zero_flags);
		hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);
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
	if (blks < fp->ff_blocks) {
		(void) hfs_truncate(vp, leof, IO_NDELAY, HFS_TRUNCATE_SKIPTIMES, context);
	}

	if (!ISSET(opts, HFS_FILE_DONE_NO_SYNC)) {
		hfs_unlock(cp);
		(void) cluster_push(vp, cluster_flags);
		hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);
	
		/*
		 * If the hfs_truncate didn't happen to flush the vnode's
		 * information out to disk, force it to be updated now that
		 * all invalid ranges have been zero-filled and validated:
		 */
		if (cp->c_flag & C_MODIFIED) {
			hfs_update(vp, 0);
		}
	}

	return (0);
}


/*
 * Reclaim a cnode so that it can be used for other purposes.
 */
int
hfs_vnop_reclaim(struct vnop_reclaim_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct cnode *cp;
	struct filefork *fp = NULL;
	struct filefork *altfp = NULL;
	struct hfsmount *hfsmp = VTOHFS(vp);
	vfs_context_t ctx = ap->a_context;
	int reclaim_cnode = 0;
	int err = 0;
	enum vtype v_type;
	
	v_type = vnode_vtype(vp);
	cp = VTOC(vp);
	
	/* 
	 * We don't take the truncate lock since by the time reclaim comes along,
	 * all dirty pages have been synced and nobody should be competing
	 * with us for this thread.
	 */
	(void) hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);

	/* 
	 * Sync to disk any remaining data in the cnode/vnode.  This includes
	 * a call to hfs_update if the cnode has outbound data.
	 * 
	 * If C_NOEXISTS is set on the cnode, then there's nothing teardown needs to do
	 * because the catalog entry for this cnode is already gone.
	 */
	if (!ISSET(cp->c_flag, C_NOEXISTS)) {
		err = hfs_cnode_teardown(vp, ctx, 1);
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
		hfs_unlock(cp);
		hfs_reclaim_cnode(cp);
	} 
	else  {
		/* 
		 * cnode in use.  If it is a directory, it could have 
		 * no live forks. Just release the lock.
		 */
		hfs_unlock(cp);
	}

	vnode_clearfsnode(vp);
	return (0);
}


extern int (**hfs_vnodeop_p) (void *);
extern int (**hfs_specop_p)  (void *);
#if FIFO
extern int (**hfs_fifoop_p)  (void *);
#endif

#if CONFIG_HFS_STD
extern int (**hfs_std_vnodeop_p) (void *);
#endif

/*
 * hfs_getnewvnode - get new default vnode
 *
 * The vnode is returned with an iocount and the cnode locked
 */
int
hfs_getnewvnode(
	struct hfsmount *hfsmp,
	struct vnode *dvp,
	struct componentname *cnp,
	struct cat_desc *descp,
	int flags,
	struct cat_attr *attrp,
	struct cat_fork *forkp,
	struct vnode **vpp,
	int *out_flags)
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
	int hflags = 0;
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

	/* Sanity check the vtype and mode */
	if (vtype == VBAD) {
		/* Mark the FS as corrupt and bail out */
		hfs_mark_inconsistent(hfsmp, HFS_INCONSISTENCY_DETECTED);
		return EINVAL;
	}

	/* Zero out the out_flags */
	*out_flags = 0;

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
	cp = hfs_chash_getcnode(hfsmp, attrp->ca_fileid, vpp, wantrsrc, 
							(flags & GNV_SKIPLOCK), out_flags, &hflags);

	/*
	 * If the id is no longer valid for lookups we'll get back a NULL cp.
	 */
	if (cp == NULL) {
		return (ENOENT);
	}

	/* 
	 * If we get a cnode/vnode pair out of hfs_chash_getcnode, then update the 
	 * descriptor in the cnode as needed if the cnode represents a hardlink.  
	 * We want the caller to get the most up-to-date copy of the descriptor
	 * as possible. However, we only do anything here if there was a valid vnode.
	 * If there isn't a vnode, then the cnode is brand new and needs to be initialized
	 * as it doesn't have a descriptor or cat_attr yet.
	 * 
	 * If we are about to replace the descriptor with the user-supplied one, then validate
	 * that the descriptor correctly acknowledges this item is a hardlink.  We could be
	 * subject to a race where the calling thread invoked cat_lookup, got a valid lookup 
	 * result but the file was not yet a hardlink. With sufficient delay between there
	 * and here, we might accidentally copy in the raw inode ID into the descriptor in the
	 * call below.  If the descriptor's CNID is the same as the fileID then it must
	 * not yet have been a hardlink when the lookup occurred.
	 */
	
	if (!(hfs_checkdeleted(cp))) {
		if ((cp->c_flag & C_HARDLINK) && descp->cd_nameptr && descp->cd_namelen > 0) {
			/* If cnode is uninitialized, its c_attr will be zeroed out; cnids wont match. */
			if ((descp->cd_cnid == cp->c_attr.ca_fileid)  &&
					(attrp->ca_linkcount != cp->c_attr.ca_linkcount)){
				if ((flags & GNV_SKIPLOCK) == 0) {
					/* 
					 * Then we took the lock. Drop it before calling
					 * vnode_put, which may invoke hfs_vnop_inactive and need to take 
					 * the cnode lock again.
					 */
					hfs_unlock(cp);
				}
				
				/* 
				 * Emit ERECYCLE and GNV_CAT_ATTRCHANGED to 
				 * force a re-drive in the lookup routine.  
				 * Drop the iocount on the vnode obtained from 
				 * chash_getcnode if needed.
				 */	
				if (*vpp != NULL) {
					vnode_put (*vpp);
					*vpp = NULL;
				}
				
				/*
				 * If we raced with VNOP_RECLAIM for this vnode, the hash code could
				 * have observed it after the c_vp or c_rsrc_vp fields had been torn down;
				 * the hash code peeks at those fields without holding the cnode lock because
				 * it needs to be fast.  As a result, we may have set H_ATTACH in the chash
				 * call above.  Since we're bailing out, unset whatever flags we just set, and
				 * wake up all waiters for this cnode.
				 */
				if (hflags) {
					hfs_chashwakeup(hfsmp, cp, hflags);
				}
				
				*out_flags = GNV_CAT_ATTRCHANGED;
				return ERECYCLE;	
			}
			else {
				/* 
				 * Otherwise, CNID != fileid. Go ahead and copy in the new descriptor. 
				 *
				 * Replacing the descriptor here is fine because we looked up the item without
				 * a vnode in hand before.  If a vnode existed, its identity must be attached to this
				 * item.  We are not susceptible to the lookup fastpath issue at this point.
				 */
				replace_desc(cp, descp);

				/*
				 * This item was a hardlink, and its name needed to be updated. By replacing the 
				 * descriptor above, we've now updated the cnode's internal representation of
				 * its link ID/CNID, parent ID, and its name.  However, VFS must now be alerted
				 * to the fact that this vnode now has a new parent, since we cannot guarantee
				 * that the new link lived in the same directory as the alternative name for
				 * this item.  
				 */
				if ((*vpp != NULL) && (cnp)) {
					/* we could be requesting the rsrc of a hardlink file... */
					vnode_update_identity (*vpp, dvp, cnp->cn_nameptr, cnp->cn_namelen, cnp->cn_hash,
							(VNODE_UPDATE_PARENT | VNODE_UPDATE_NAME));
				}
			}
		}
	}
	
	/* Check if we found a matching vnode */
	if (*vpp != NULL) {
		return (0);
	}

	/*
	 * If this is a new cnode then initialize it.
	 */
	if (ISSET(cp->c_hflag, H_ALLOC)) {
		lck_rw_init(&cp->c_truncatelock, hfs_rwlock_group, hfs_lock_attr);
#if HFS_COMPRESSION
		cp->c_decmp = NULL;
#endif

		/* Make sure its still valid (ie exists on disk). */
		if (!(flags & GNV_CREATE)) {
			int error = 0;
			if (!hfs_valid_cnode (hfsmp, dvp, (wantrsrc ? NULL : cnp), cp->c_fileid, attrp, &error)) {
				hfs_chash_abort(hfsmp, cp);
				if ((flags & GNV_SKIPLOCK) == 0) {
					hfs_unlock(cp);
				}
				hfs_reclaim_cnode(cp);
				*vpp = NULL;
				/* 
				 * If we hit this case, that means that the entry was there in the catalog when
				 * we did a cat_lookup earlier.  Think hfs_lookup.  However, in between the time
				 * that we checked the catalog and the time we went to get a vnode/cnode for it,
				 * it had been removed from the namespace and the vnode totally reclaimed.  As a result,
				 * it's not there in the catalog during the check in hfs_valid_cnode and we bubble out
				 * an ENOENT.  To indicate to the caller that they should really double-check the
				 * entry (it could have been renamed over and gotten a new fileid), we mark a bit
				 * in the output flags.
				 */
				if (error == ENOENT) {
					*out_flags = GNV_CAT_DELETED;
					return ENOENT;	
				}

				/*
				 * Also, we need to protect the cat_attr acquired during hfs_lookup and passed into
				 * this function as an argument because the catalog may have changed w.r.t hardlink
				 * link counts and the firstlink field.  If that validation check fails, then let 
				 * lookup re-drive itself to get valid/consistent data with the same failure condition below.
				 */
				if (error == ERECYCLE) {
					*out_flags = GNV_CAT_ATTRCHANGED;
					return (ERECYCLE);
				}
			}
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
		/* Mark the output flag that we're vending a new cnode */
		*out_flags |= GNV_NEW_CNODE;
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
#if CONFIG_HFS_STD
	else if (hfs_standard)
		vfsp.vnfs_vops = hfs_std_vnodeop_p;
#endif
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
	if (dvp == NULLVP || cnp == NULL || !(cnp->cn_flags & MAKEENTRY) || (flags & GNV_NOCACHE))
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

		KERNEL_DEBUG_CONSTANT(HFSDBG_GETNEWVNODE, VM_KERNEL_ADDRPERM(cp->c_vp), VM_KERNEL_ADDRPERM(cp->c_rsrc_vp), 0, 0, 0);

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
	
#if CONFIG_PROTECT
	/* Initialize the cp data structures. The key should be in place now. */
	if (!issystemfile && (*out_flags & GNV_NEW_CNODE)) {
		cp_entry_init(cp, mp);
	}
#endif

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
	
	/*
	 * We only call this function if we are in hfs_vnop_reclaim and 
	 * attempting to reclaim a cnode with only one live fork.  Because the vnode
	 * went through reclaim, any future attempts to use this item will have to
	 * go through lookup again, which will need to create a new vnode.  Thus,
	 * destroying the locks below is safe.
	 */	
	
	lck_rw_destroy(&cp->c_rwlock, hfs_rwlock_group);
	lck_rw_destroy(&cp->c_truncatelock, hfs_rwlock_group);
#if HFS_COMPRESSION
	if (cp->c_decmp) {
		decmpfs_cnode_destroy(cp->c_decmp);
		FREE_ZONE(cp->c_decmp, sizeof(*(cp->c_decmp)), M_DECMPFS_CNODE);
	}
#endif
#if CONFIG_PROTECT
	cp_entry_destroy(cp->c_cpentry);
	cp->c_cpentry = NULL;
#endif
	
	
	bzero(cp, sizeof(struct cnode));
	FREE_ZONE(cp, sizeof(struct cnode), M_HFSNODE);
}


/*
 * hfs_valid_cnode
 *
 * This function is used to validate data that is stored in-core against what is contained
 * in the catalog.  Common uses include validating that the parent-child relationship still exist
 * for a specific directory entry (guaranteeing it has not been renamed into a different spot) at
 * the point of the check.
 */
int
hfs_valid_cnode(struct hfsmount *hfsmp, struct vnode *dvp, struct componentname *cnp, 
		cnid_t cnid, struct cat_attr *cattr, int *error)
{
	struct cat_attr attr;
	struct cat_desc cndesc;
	int stillvalid = 0;
	int lockflags;

	/* System files are always valid */
	if (cnid < kHFSFirstUserCatalogNodeID) {
		*error = 0;
		return (1);
	}

	/* XXX optimization:  check write count in dvp */

	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);

	if (dvp && cnp) {
		int lookup = 0;
		struct cat_fork fork;
		bzero(&cndesc, sizeof(cndesc));
		cndesc.cd_nameptr = (const u_int8_t *)cnp->cn_nameptr;
		cndesc.cd_namelen = cnp->cn_namelen;
		cndesc.cd_parentcnid = VTOC(dvp)->c_fileid;
		cndesc.cd_hint = VTOC(dvp)->c_childhint;

		/* 
		 * We have to be careful when calling cat_lookup.  The result argument
		 * 'attr' may get different results based on whether or not you ask
		 * for the filefork to be supplied as output.  This is because cat_lookupbykey
		 * will attempt to do basic validation/smoke tests against the resident
		 * extents if there are no overflow extent records, but it needs someplace
		 * in memory to store the on-disk fork structures.
		 *
		 * Since hfs_lookup calls cat_lookup with a filefork argument, we should
		 * do the same here, to verify that block count differences are not
		 * due to calling the function with different styles.  cat_lookupbykey
		 * will request the volume be fsck'd if there is true on-disk corruption
		 * where the number of blocks does not match the number generated by 
		 * summing the number of blocks in the resident extents.
		 */
		
		lookup = cat_lookup (hfsmp, &cndesc, 0, 0, NULL, &attr, &fork, NULL);

		if ((lookup == 0) && (cnid == attr.ca_fileid)) {
			stillvalid = 1;
			*error = 0;
		}
		else {
			*error = ENOENT;
		}
	
		/*
		 * In hfs_getnewvnode, we may encounter a time-of-check vs. time-of-vnode creation 
		 * race.  Specifically, if there is no vnode/cnode pair for the directory entry 
		 * being looked up, we have to go to the catalog.  But since we don't hold any locks (aside
		 * from the dvp in 'shared' mode) there is nothing to protect us against the catalog record
		 * changing in between the time we do the cat_lookup there and the time we re-grab the 
		 * catalog lock above to do another cat_lookup. 
		 * 
		 * However, we need to check more than just the CNID and parent-child name relationships above.  
		 * Hardlinks can suffer the same race in the following scenario:  Suppose we do a 
		 * cat_lookup, and find a leaf record and a raw inode for a hardlink.  Now, we have 
		 * the cat_attr in hand (passed in above).  But in between then and now, the vnode was 
		 * created by a competing hfs_getnewvnode call, and is manipulated and reclaimed before we get 
		 * a chance to do anything.  This is possible if there are a lot of threads thrashing around
		 * with the cnode hash.  In this case, if we don't check/validate the cat_attr in-hand, we will
		 * blindly stuff it into the cnode, which will make the in-core data inconsistent with what is 
		 * on disk.  So validate the cat_attr below, if required.  This race cannot happen if the cnode/vnode
		 * already exists, as it does in the case of rename and delete. 
		 */ 
		if (stillvalid && cattr != NULL) {
			if (cattr->ca_linkcount != attr.ca_linkcount) {
				stillvalid = 0;
				*error = ERECYCLE;
				goto notvalid;
			}
			
			if (cattr->ca_union1.cau_linkref != attr.ca_union1.cau_linkref) {
				stillvalid = 0;
				*error = ERECYCLE;
				goto notvalid;
			}

			if (cattr->ca_union3.cau_firstlink != attr.ca_union3.cau_firstlink) {
				stillvalid = 0;
				*error = ERECYCLE;
				goto notvalid;
			}

			if (cattr->ca_union2.cau_blocks != attr.ca_union2.cau_blocks) {
				stillvalid = 0;
				*error = ERECYCLE;
				goto notvalid;
			}
		}
	} else {
		if (cat_idlookup(hfsmp, cnid, 0, 0, NULL, NULL, NULL) == 0) {
			stillvalid = 1;
			*error = 0;
		}
		else {
			*error = ENOENT;
		}
	}
notvalid:
	hfs_systemfile_unlock(hfsmp, lockflags);

	return (stillvalid);
}


/*
 * Per HI and Finder requirements, HFS should add in the
 * date/time that a particular directory entry was added 
 * to the containing directory. 
 * This is stored in the extended Finder Info for the 
 * item in question.
 *
 * Note that this field is also set explicitly in the hfs_vnop_setxattr code.
 * We must ignore user attempts to set this part of the finderinfo, and
 * so we need to save a local copy of the date added, write in the user 
 * finderinfo, then stuff the value back in.  
 */
void hfs_write_dateadded (struct cat_attr *attrp, u_int32_t dateadded) {
	u_int8_t *finfo = NULL;

	/* overlay the FinderInfo to the correct pointer, and advance */
	finfo = (u_int8_t*)attrp->ca_finderinfo;
	finfo = finfo + 16;

	/* 
	 * Make sure to write it out as big endian, since that's how
	 * finder info is defined.  
	 * 
	 * NOTE: This is a Unix-epoch timestamp, not a HFS/Traditional Mac timestamp.
	 */
	if (S_ISREG(attrp->ca_mode)) {
		struct FndrExtendedFileInfo *extinfo = (struct FndrExtendedFileInfo *)finfo;
		extinfo->date_added = OSSwapHostToBigInt32(dateadded);
		attrp->ca_recflags |= kHFSHasDateAddedMask; 
	}
	else if (S_ISDIR(attrp->ca_mode)) {
		struct FndrExtendedDirInfo *extinfo = (struct FndrExtendedDirInfo *)finfo;
		extinfo->date_added = OSSwapHostToBigInt32(dateadded);		
				attrp->ca_recflags |= kHFSHasDateAddedMask; 
	}
	/* If it were neither directory/file, then we'd bail out */
	return;
}

static u_int32_t
hfs_get_dateadded_internal(const uint8_t *finderinfo, mode_t mode)
{
	u_int8_t *finfo = NULL;
	u_int32_t dateadded = 0;



	/* overlay the FinderInfo to the correct pointer, and advance */
	finfo = (u_int8_t*)finderinfo + 16;

	/* 
	 * FinderInfo is written out in big endian... make sure to convert it to host
	 * native before we use it.
	 */
	if (S_ISREG(mode)) {
		struct FndrExtendedFileInfo *extinfo = (struct FndrExtendedFileInfo *)finfo;
		dateadded = OSSwapBigToHostInt32 (extinfo->date_added);
	}
	else if (S_ISDIR(mode)) {
		struct FndrExtendedDirInfo *extinfo = (struct FndrExtendedDirInfo *)finfo;
		dateadded = OSSwapBigToHostInt32 (extinfo->date_added);
	}

	return dateadded;
}

u_int32_t
hfs_get_dateadded(struct cnode *cp)
{
	if ((cp->c_attr.ca_recflags & kHFSHasDateAddedMask) == 0) {
		/* Date added was never set.  Return 0. */
		return (0);
	}

	return (hfs_get_dateadded_internal((u_int8_t*)cp->c_finderinfo,
	    cp->c_attr.ca_mode));
}

u_int32_t
hfs_get_dateadded_from_blob(const uint8_t *finderinfo, mode_t mode)
{
	return (hfs_get_dateadded_internal(finderinfo, mode));
}

/*
 * Per HI and Finder requirements, HFS maintains a "write/generation
 * count" for each file that is incremented on any write & pageout.
 * It should start at 1 to reserve "0" as a special value.  If it
 * should ever wrap around, it will skip using 0.
 *
 * Note that finderinfo is manipulated in hfs_vnop_setxattr and care
 * is and should be taken to ignore user attempts to set the part of
 * the finderinfo that records the generation counter.
 *
 * Any change to the generation counter *must* not be visible before
 * the change that caused it (for obvious reasons), and given the
 * limitations of our current architecture, the change to the
 * generation counter may occur some time afterwards (particularly in
 * the case where a file is mapped writable---more on that below).
 *
 * We make no guarantees about the consistency of a file.  In other
 * words, a reader that is operating concurrently with a writer might
 * see some, but not all of writer's changes, and the generation
 * counter will *not* necessarily tell you this has happened.  To
 * enforce consistency, clients must make their own arrangements
 * e.g. use file locking.
 *
 * We treat files that are mapped writable as a special case: when
 * that happens, clients requesting the generation count will be told
 * it has a generation count of zero and they use that knowledge as a
 * hint that the file is changing and it therefore might be prudent to
 * wait until it is no longer mapped writable.  Clients should *not*
 * rely on this behaviour however; we might decide that it's better
 * for us to publish the fact that a file is mapped writable via
 * alternate means and return the generation counter when it is mapped
 * writable as it still has some, albeit limited, use.  We reserve the
 * right to make this change.
 *
 * Lastly, it's important to realise that because data and metadata
 * take different paths through the system, it's possible upon crash
 * or sudden power loss and after a restart, that a change may be
 * visible to the rest of the system without a corresponding change to
 * the generation counter.  The reverse may also be true, but for all
 * practical applications this shouldn't be an issue.
 */
void hfs_write_gencount (struct cat_attr *attrp, uint32_t gencount) {
	u_int8_t *finfo = NULL;

	/* overlay the FinderInfo to the correct pointer, and advance */
	finfo = (u_int8_t*)attrp->ca_finderinfo;
	finfo = finfo + 16;

	/* 
	 * Make sure to write it out as big endian, since that's how
	 * finder info is defined.  
	 *
	 * Generation count is only supported for files.
	 */
	if (S_ISREG(attrp->ca_mode)) {
		struct FndrExtendedFileInfo *extinfo = (struct FndrExtendedFileInfo *)finfo;
		extinfo->write_gen_counter = OSSwapHostToBigInt32(gencount);
	}

	/* If it were neither directory/file, then we'd bail out */
	return;
}

/*
 * Increase the gen count by 1; if it wraps around to 0, increment by
 * two.  The cnode *must* be locked exclusively by the caller.  
 *
 * You may think holding the lock is unnecessary because we only need
 * to change the counter, but consider this sequence of events: thread
 * A calls hfs_incr_gencount and the generation counter is 2 upon
 * entry.  A context switch occurs and thread B increments the counter
 * to 3, thread C now gets the generation counter (for whatever
 * purpose), and then another thread makes another change and the
 * generation counter is incremented again---it's now 4.  Now thread A
 * continues and it sets the generation counter back to 3.  So you can
 * see, thread C would miss the change that caused the generation
 * counter to increment to 4 and for this reason the cnode *must*
 * always be locked exclusively.
 */
uint32_t hfs_incr_gencount (struct cnode *cp) {
	u_int8_t *finfo = NULL;
	u_int32_t gcount = 0;

	/* overlay the FinderInfo to the correct pointer, and advance */
	finfo = (u_int8_t*)cp->c_finderinfo;
	finfo = finfo + 16;

	/* 
	 * FinderInfo is written out in big endian... make sure to convert it to host
	 * native before we use it.
	 *
	 * NOTE: the write_gen_counter is stored in the same location in both the
	 *       FndrExtendedFileInfo and FndrExtendedDirInfo structs (it's the
	 *       last 32-bit word) so it is safe to have one code path here.
	 */
	if (S_ISDIR(cp->c_attr.ca_mode) || S_ISREG(cp->c_attr.ca_mode)) {
		struct FndrExtendedFileInfo *extinfo = (struct FndrExtendedFileInfo *)finfo;
		gcount = OSSwapBigToHostInt32 (extinfo->write_gen_counter);

		/* Was it zero to begin with (file originated in 10.8 or earlier?) */
		if (gcount == 0) {
			gcount++;
		}

		/* now bump it */
		gcount++;

		/* Did it wrap around ? */
		if (gcount == 0) {
			gcount++;
		}
		extinfo->write_gen_counter = OSSwapHostToBigInt32 (gcount);

		SET(cp->c_flag, C_MODIFIED);
	}
	else {
		gcount = 0;
	}	

	return gcount;
}

/*
 * There is no need for any locks here (other than an iocount on an
 * associated vnode) because reading and writing an aligned 32 bit
 * integer should be atomic on all platforms we support.
 */
static u_int32_t
hfs_get_gencount_internal(const uint8_t *finderinfo, mode_t mode)
{
	u_int8_t *finfo = NULL;
	u_int32_t gcount = 0;

	/* overlay the FinderInfo to the correct pointer, and advance */
	finfo = (u_int8_t*)finderinfo;
	finfo = finfo + 16;

	/* 
	 * FinderInfo is written out in big endian... make sure to convert it to host
	 * native before we use it.
	 *
	 * NOTE: the write_gen_counter is stored in the same location in both the
	 *       FndrExtendedFileInfo and FndrExtendedDirInfo structs (it's the
	 *       last 32-bit word) so it is safe to have one code path here.
	 */
	if (S_ISDIR(mode) || S_ISREG(mode)) {
		struct FndrExtendedFileInfo *extinfo = (struct FndrExtendedFileInfo *)finfo;
		gcount = OSSwapBigToHostInt32 (extinfo->write_gen_counter);
		
		/* 
		 * Is it zero?  File might originate in 10.8 or earlier. We lie and bump it to 1,
		 * since the incrementer code is able to handle this case and will double-increment
		 * for us.
		 */
		if (gcount == 0) {
			gcount++;	
		}
	}

	return gcount;
}

/* Getter for the gen count */
u_int32_t hfs_get_gencount (struct cnode *cp) {
	return hfs_get_gencount_internal(cp->c_finderinfo, cp->c_attr.ca_mode);
}

/* Getter for the gen count from a buffer (currently pointer to finderinfo)*/
u_int32_t hfs_get_gencount_from_blob (const uint8_t *finfoblob, mode_t mode) {
	return hfs_get_gencount_internal(finfoblob, mode);
}

void hfs_clear_might_be_dirty_flag(cnode_t *cp)
{
	/*
	 * If we're about to touch both mtime and ctime, we can clear the
	 * C_MIGHT_BE_DIRTY_FROM_MAPPING since we can guarantee that
	 * subsequent page-outs can only be for data made dirty before
	 * now.
	 */
	CLR(cp->c_flag, C_MIGHT_BE_DIRTY_FROM_MAPPING);
}

/*
 * Touch cnode times based on c_touch_xxx flags
 *
 * cnode must be locked exclusive
 *
 * This will also update the volume modify time
 */
void
hfs_touchtimes(struct hfsmount *hfsmp, struct cnode* cp)
{
	vfs_context_t ctx;
	/* don't modify times if volume is read-only */
	if (hfsmp->hfs_flags & HFS_READ_ONLY) {
		cp->c_touch_acctime = FALSE;
		cp->c_touch_chgtime = FALSE;
		cp->c_touch_modtime = FALSE;
		return;
	}
#if CONFIG_HFS_STD
	else if (hfsmp->hfs_flags & HFS_STANDARD) {
	/* HFS Standard doesn't support access times */
		cp->c_touch_acctime = FALSE;
	}
#endif

	ctx = vfs_context_current();
	/*
	 * Skip access time updates if:
	 *	. MNT_NOATIME is set
	 *	. a file system freeze is in progress
	 *	. a file system resize is in progress
	 *	. the vnode associated with this cnode is marked for rapid aging
	 */
	if (cp->c_touch_acctime) {
		if ((vfs_flags(hfsmp->hfs_mp) & MNT_NOATIME) ||
		    hfsmp->hfs_freeze_state != HFS_THAWED ||
		    (hfsmp->hfs_flags & HFS_RESIZE_IN_PROGRESS) ||
		    (cp->c_vp && ((vnode_israge(cp->c_vp) || (vfs_ctx_skipatime(ctx)))))) {
				
			cp->c_touch_acctime = FALSE;
		}
	}
	if (cp->c_touch_acctime || cp->c_touch_chgtime || 
		cp->c_touch_modtime || (cp->c_flag & C_NEEDS_DATEADDED)) {
		struct timeval tv;
		int touchvol = 0;

		if (cp->c_touch_modtime && cp->c_touch_chgtime)
			hfs_clear_might_be_dirty_flag(cp);

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
#if CONFIG_HFS_STD
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

		if (cp->c_flag & C_NEEDS_DATEADDED) {
			hfs_write_dateadded (&(cp->c_attr), tv.tv_sec);
			cp->c_flag |= C_MODIFIED;
			/* untwiddle the bit */
			cp->c_flag &= ~C_NEEDS_DATEADDED;
			touchvol = 1;
		}

		/* Touch the volume modtime if needed */
		if (touchvol) {
			MarkVCBDirty(hfsmp);
			HFSTOVCB(hfsmp)->vcbLsMod = tv.tv_sec;
		}
	}
}

// Use this if you don't want to check the return code
void hfs_lock_always(cnode_t *cp, enum hfs_locktype locktype)
{
	hfs_lock(cp, locktype, HFS_LOCK_ALWAYS);
}

/*
 * Lock a cnode.
 * N.B. If you add any failure cases, *make* sure hfs_lock_always works
 */
int
hfs_lock(struct cnode *cp, enum hfs_locktype locktype, enum hfs_lockflags flags)
{
	thread_t thread = current_thread();

	if (cp->c_lockowner == thread) {
		/* Only the extents and bitmap files support lock recursion. */
		if ((cp->c_fileid == kHFSExtentsFileID) ||
		    (cp->c_fileid == kHFSAllocationFileID)) {
			cp->c_syslockcount++;
		} else {
			panic("hfs_lock: locking against myself!");
		}
	} else if (locktype == HFS_SHARED_LOCK) {
		lck_rw_lock_shared(&cp->c_rwlock);
		cp->c_lockowner = HFS_SHARED_OWNER;

	} else { /* HFS_EXCLUSIVE_LOCK */
		lck_rw_lock_exclusive(&cp->c_rwlock);
		cp->c_lockowner = thread;

		/* Only the extents and bitmap files support lock recursion. */
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
	 * Skip cnodes for regular files that no longer exist 
	 * (marked deleted, catalog entry gone).
	 */
	if (((flags & HFS_LOCK_ALLOW_NOEXISTS) == 0) && 
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
int
hfs_lockpair(struct cnode *cp1, struct cnode *cp2, enum hfs_locktype locktype)
{
	struct cnode *first, *last;
	int error;

	/*
	 * If cnodes match then just lock one.
	 */
	if (cp1 == cp2) {
		return hfs_lock(cp1, locktype, HFS_LOCK_DEFAULT);
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

	if ( (error = hfs_lock(first, locktype, HFS_LOCK_DEFAULT))) {
		return (error);
	}
	if ( (error = hfs_lock(last, locktype, HFS_LOCK_DEFAULT))) {
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
int
hfs_lockfour(struct cnode *cp1, struct cnode *cp2, struct cnode *cp3,
             struct cnode *cp4, enum hfs_locktype locktype, struct cnode **error_cnode)
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
			if ((error = hfs_lock(list[i], locktype, HFS_LOCK_DEFAULT))) {
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
void
hfs_unlock(struct cnode *cp)
{
	vnode_t rvp = NULLVP;
	vnode_t vp = NULLVP;
	u_int32_t c_flag;

	/*
	 * Only the extents and bitmap file's support lock recursion.
	 */
	if ((cp->c_fileid == kHFSExtentsFileID) ||
	    (cp->c_fileid == kHFSAllocationFileID)) {
		if (--cp->c_syslockcount > 0) {
			return;
		}
	}

	const thread_t thread = current_thread();

	if (cp->c_lockowner == thread) {
		c_flag = cp->c_flag;

		// If we have the truncate lock, we must defer the puts
		if (cp->c_truncatelockowner == thread) {
			if (ISSET(c_flag, C_NEED_DVNODE_PUT)
				&& !cp->c_need_dvnode_put_after_truncate_unlock) {
				CLR(c_flag, C_NEED_DVNODE_PUT);
				cp->c_need_dvnode_put_after_truncate_unlock = true;
			}
			if (ISSET(c_flag, C_NEED_RVNODE_PUT)
				&& !cp->c_need_rvnode_put_after_truncate_unlock) {
				CLR(c_flag, C_NEED_RVNODE_PUT);
				cp->c_need_rvnode_put_after_truncate_unlock = true;
			}
		}

		CLR(cp->c_flag, (C_NEED_DATA_SETSIZE | C_NEED_RSRC_SETSIZE
						 | C_NEED_DVNODE_PUT | C_NEED_RVNODE_PUT));

		if (c_flag & (C_NEED_DVNODE_PUT | C_NEED_DATA_SETSIZE)) {
	        vp = cp->c_vp;
		}
		if (c_flag & (C_NEED_RVNODE_PUT | C_NEED_RSRC_SETSIZE)) {
	        rvp = cp->c_rsrc_vp;
		}

	    cp->c_lockowner = NULL;
	    lck_rw_unlock_exclusive(&cp->c_rwlock);
	} else {
	    lck_rw_unlock_shared(&cp->c_rwlock);
	}

	/* Perform any vnode post processing after cnode lock is dropped. */
	if (vp) {
		if (c_flag & C_NEED_DATA_SETSIZE) {
			ubc_setsize(vp, VTOF(vp)->ff_size);
#if HFS_COMPRESSION
			/*
			 * If this is a compressed file, we need to reset the
			 * compression state.  We will have set the size to zero
			 * above and it will get fixed up later (in exactly the
			 * same way that new vnodes are fixed up).  Note that we
			 * should only be able to get here if the truncate lock is
			 * held exclusively and so we do the reset when that's
			 * unlocked.
			 */
			decmpfs_cnode *dp = VTOCMP(vp);
			if (dp && decmpfs_cnode_get_vnode_state(dp) != FILE_TYPE_UNKNOWN)
				cp->c_need_decmpfs_reset = true;
#endif
		}
		if (c_flag & C_NEED_DVNODE_PUT)
			vnode_put(vp);
	}
	if (rvp) {
		if (c_flag & C_NEED_RSRC_SETSIZE)
			ubc_setsize(rvp, VTOF(rvp)->ff_size);
		if (c_flag & C_NEED_RVNODE_PUT)
	        	vnode_put(rvp);
	}
}

/*
 * Unlock a pair of cnodes.
 */
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
 * shared.  The locktype argument is the same as supplied to
 * hfs_lock.
 */
void
hfs_lock_truncate(struct cnode *cp, enum hfs_locktype locktype, enum hfs_lockflags flags)
{
	thread_t thread = current_thread();

	if (cp->c_truncatelockowner == thread) {
		/* 
		 * Ignore grabbing the lock if it the current thread already 
		 * holds exclusive lock.
		 * 
		 * This is needed on the hfs_vnop_pagein path where we need to ensure
		 * the file does not change sizes while we are paging in.  However,
		 * we may already hold the lock exclusive due to another 
		 * VNOP from earlier in the call stack.  So if we already hold 
		 * the truncate lock exclusive, allow it to proceed, but ONLY if 
		 * it's in the recursive case.
		 */
		if ((flags & HFS_LOCK_SKIP_IF_EXCLUSIVE) == 0) {
			panic("hfs_lock_truncate: cnode %p locked!", cp);
		}
	} else if (locktype == HFS_SHARED_LOCK) {
		lck_rw_lock_shared(&cp->c_truncatelock);
		cp->c_truncatelockowner = HFS_SHARED_OWNER;
	} else { /* HFS_EXCLUSIVE_LOCK */
		lck_rw_lock_exclusive(&cp->c_truncatelock);
		cp->c_truncatelockowner = thread;
	}
}


/*
 * Attempt to get the truncate lock.  If it cannot be acquired, error out.
 * This function is needed in the degenerate hfs_vnop_pagein during force unmount
 * case.  To prevent deadlocks while a VM copy object is moving pages, HFS vnop pagein will
 * temporarily need to disable V2 semantics.  
 */
int hfs_try_trunclock (struct cnode *cp, enum hfs_locktype locktype, enum hfs_lockflags flags)
{
	thread_t thread = current_thread();
	boolean_t didlock = false;

	if (cp->c_truncatelockowner == thread) {
		/* 
		 * Ignore grabbing the lock if the current thread already 
		 * holds exclusive lock.
		 * 
		 * This is needed on the hfs_vnop_pagein path where we need to ensure
		 * the file does not change sizes while we are paging in.  However,
		 * we may already hold the lock exclusive due to another 
		 * VNOP from earlier in the call stack.  So if we already hold 
		 * the truncate lock exclusive, allow it to proceed, but ONLY if 
		 * it's in the recursive case.
		 */
		if ((flags & HFS_LOCK_SKIP_IF_EXCLUSIVE) == 0) {
			panic("hfs_lock_truncate: cnode %p locked!", cp);
		}
	} else if (locktype == HFS_SHARED_LOCK) {
		didlock = lck_rw_try_lock(&cp->c_truncatelock, LCK_RW_TYPE_SHARED);
		if (didlock) {
			cp->c_truncatelockowner = HFS_SHARED_OWNER;
		}
	} else { /* HFS_EXCLUSIVE_LOCK */
		didlock = lck_rw_try_lock (&cp->c_truncatelock, LCK_RW_TYPE_EXCLUSIVE);
		if (didlock) {
			cp->c_truncatelockowner = thread;
		}
	}
	
	return didlock;
}


/*
 * Unlock the truncate lock, which protects against size changes.
 * 
 * If HFS_LOCK_SKIP_IF_EXCLUSIVE flag was set, it means that a previous 
 * hfs_lock_truncate() might have skipped grabbing a lock because 
 * the current thread was already holding the lock exclusive and 
 * we may need to return from this function without actually unlocking 
 * the truncate lock.
 */
void
hfs_unlock_truncate(struct cnode *cp, enum hfs_lockflags flags)
{
	thread_t thread = current_thread();	

	/*
	 * If HFS_LOCK_SKIP_IF_EXCLUSIVE is set in the flags AND the current 
	 * lock owner of the truncate lock is our current thread, then 
	 * we must have skipped taking the lock earlier by in 
	 * hfs_lock_truncate() by setting HFS_LOCK_SKIP_IF_EXCLUSIVE in the 
	 * flags (as the current thread was current lock owner).
	 *
	 * If HFS_LOCK_SKIP_IF_EXCLUSIVE is not set (most of the time) then 
	 * we check the lockowner field to infer whether the lock was taken 
	 * exclusively or shared in order to know what underlying lock 
	 * routine to call. 
	 */
	if (flags & HFS_LOCK_SKIP_IF_EXCLUSIVE) {
		if (cp->c_truncatelockowner == thread) {
			return;	
		}
	}

	/* HFS_LOCK_EXCLUSIVE */
	if (thread == cp->c_truncatelockowner) {
		vnode_t vp = NULL, rvp = NULL;

		/*
		 * Deal with any pending set sizes.  We need to call
		 * ubc_setsize before we drop the exclusive lock.  Ideally,
		 * hfs_unlock should be called before hfs_unlock_truncate but
		 * that's a lot to ask people to remember :-)
		 */
		if (cp->c_lockowner == thread
			&& ISSET(cp->c_flag, C_NEED_DATA_SETSIZE | C_NEED_RSRC_SETSIZE)) {
			// hfs_unlock will do the setsize calls for us
			hfs_unlock(cp);
			hfs_lock_always(cp, HFS_EXCLUSIVE_LOCK);
		}
 
		if (cp->c_need_dvnode_put_after_truncate_unlock) {
			vp = cp->c_vp;
			cp->c_need_dvnode_put_after_truncate_unlock = false;
		}
		if (cp->c_need_rvnode_put_after_truncate_unlock) {
			rvp = cp->c_rsrc_vp;
			cp->c_need_rvnode_put_after_truncate_unlock = false;
		}

#if HFS_COMPRESSION
		bool reset_decmpfs = cp->c_need_decmpfs_reset;
		cp->c_need_decmpfs_reset = false;
#endif

		cp->c_truncatelockowner = NULL;
		lck_rw_unlock_exclusive(&cp->c_truncatelock);

#if HFS_COMPRESSION
		if (reset_decmpfs) {
			decmpfs_cnode *dp = cp->c_decmp;
			if (dp && decmpfs_cnode_get_vnode_state(dp) != FILE_TYPE_UNKNOWN)
				decmpfs_cnode_set_vnode_state(dp, FILE_TYPE_UNKNOWN, 0);
		}
#endif

		// Do the puts now
		if (vp)
			vnode_put(vp);
		if (rvp)
			vnode_put(rvp);
	} else { /* HFS_LOCK_SHARED */
		lck_rw_unlock_shared(&cp->c_truncatelock);
	}
}
