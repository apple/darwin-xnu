/*
 * Copyright (c) 1999-2014 Apple Inc. All rights reserved.
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


#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <vfs/vfs_support.h>
#include <libkern/libkern.h>
#include <sys/fsctl.h>

#include "hfs.h"
#include "hfs_catalog.h"
#include "hfs_format.h"
#include "hfs_endian.h"


static int cur_link_id = 0;

/*
 * Private directories where hardlink inodes reside.
 */
const char *hfs_private_names[] = {
	HFSPLUSMETADATAFOLDER,      /* FILE HARDLINKS */
	HFSPLUS_DIR_METADATA_FOLDER /* DIRECTORY HARDLINKS */
};


/*
 * Hardlink inodes save the head of their link chain in a
 * private extended attribute.  The following calls are
 * used to access this attribute.
 */
static int  setfirstlink(struct hfsmount * hfsmp, cnid_t fileid, cnid_t firstlink);
static int  getfirstlink(struct hfsmount * hfsmp, cnid_t fileid, cnid_t *firstlink);

int hfs_makelink(struct hfsmount *hfsmp, struct vnode *src_vp, struct cnode *cp, 
		struct cnode *dcp, struct componentname *cnp);
/*
 * Create a new catalog link record
 *
 * An indirect link is a reference to an inode (the real
 * file or directory record).
 *
 * All the indirect links for a given inode are chained
 * together in a doubly linked list.
 *
 * Pre-Leopard file hard links do not have kHFSHasLinkChainBit 
 * set and do not have first/prev/next link IDs i.e. the values 
 * are zero.  If a new link is being added to an existing 
 * pre-Leopard file hard link chain, do not set kHFSHasLinkChainBit.
 */
static int
createindirectlink(struct hfsmount *hfsmp, u_int32_t linknum, struct cat_desc *descp,
                   cnid_t nextcnid, cnid_t *linkcnid, int is_inode_linkchain_set)
{
	struct FndrFileInfo *fip;
	struct cat_attr attr;

	if (linknum == 0) {
		printf("hfs: createindirectlink: linknum is zero!\n");
		return (EINVAL);
	}

	/* Setup the default attributes */
	bzero(&attr, sizeof(attr));
	
	/* Links are matched to inodes by link ID and to volumes by create date */
	attr.ca_linkref = linknum;
	attr.ca_itime = hfsmp->hfs_metadata_createdate;
	attr.ca_mode = S_IFREG | S_IRUSR | S_IRGRP | S_IROTH;
	attr.ca_recflags = kHFSHasLinkChainMask | kHFSThreadExistsMask;
	attr.ca_flags = UF_IMMUTABLE;
	fip = (struct FndrFileInfo *)&attr.ca_finderinfo;

	if (descp->cd_flags & CD_ISDIR) {
		fip->fdType    = SWAP_BE32 (kHFSAliasType);
		fip->fdCreator = SWAP_BE32 (kHFSAliasCreator);
		fip->fdFlags   = SWAP_BE16 (kIsAlias);
	} else /* file */ {
		fip->fdType    = SWAP_BE32 (kHardLinkFileType);
		fip->fdCreator = SWAP_BE32 (kHFSPlusCreator);
		fip->fdFlags   = SWAP_BE16 (kHasBeenInited);
		/* If the file inode does not have kHFSHasLinkChainBit set 
		 * and the next link chain ID is zero, assume that this 
		 * is pre-Leopard file inode.  Therefore clear the bit.
		 */
		if ((is_inode_linkchain_set == 0) && (nextcnid == 0)) {
			attr.ca_recflags &= ~kHFSHasLinkChainMask;
		}
	}
	/* Create the indirect link directly in the catalog */
	return cat_createlink(hfsmp, descp, &attr, nextcnid, linkcnid);
}


/*
 * Make a link to the cnode cp in the directory dp
 * using the name in cnp.  src_vp is the vnode that 
 * corresponds to 'cp' which was part of the arguments to
 * hfs_vnop_link.
 *
 * The cnodes cp and dcp must be locked.
 */
int
hfs_makelink(struct hfsmount *hfsmp, struct vnode *src_vp, struct cnode *cp, 
		struct cnode *dcp, struct componentname *cnp)
{
	vfs_context_t ctx = cnp->cn_context;
	struct proc *p = vfs_context_proc(ctx);
	u_int32_t indnodeno = 0;
	char inodename[32]; 
	struct cat_desc to_desc;
	struct cat_desc link_desc;
	int newlink = 0;
	int lockflags;
	int retval = 0;
	cat_cookie_t cookie;
	cnid_t orig_cnid;
	cnid_t linkcnid;
	cnid_t orig_firstlink;
	enum privdirtype type;

	type = S_ISDIR(cp->c_mode) ? DIR_HARDLINKS : FILE_HARDLINKS;

	if (cur_link_id == 0) {
		cur_link_id = ((random() & 0x3fffffff) + 100);
	}
	
	/* We don't allow link nodes in our private system directories. */
	if (dcp->c_fileid == hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid ||
	    dcp->c_fileid == hfsmp->hfs_private_desc[DIR_HARDLINKS].cd_cnid) {
		return (EPERM);
	}

	bzero(&cookie, sizeof(cat_cookie_t));
	/* Reserve some space in the Catalog file. */
	if ((retval = cat_preflight(hfsmp, (2 * CAT_CREATE)+ CAT_RENAME, &cookie, p))) {
		return (retval);
	}

	lockflags = SFL_CATALOG | SFL_ATTRIBUTE;
	/* Directory hard links allocate space for a symlink. */
	if (type == DIR_HARDLINKS) {
		lockflags |= SFL_BITMAP;
	}
	lockflags = hfs_systemfile_lock(hfsmp, lockflags, HFS_EXCLUSIVE_LOCK);

	/* Save the current cnid value so we restore it if an error occurs. */
	orig_cnid = cp->c_desc.cd_cnid;

	/*
	 * If this is a new hardlink then we need to create the inode
	 * and replace the original file/dir object with a link node.
	 */
	if ((cp->c_linkcount == 2) && !(cp->c_flag & C_HARDLINK)) {
		newlink = 1;
		bzero(&to_desc, sizeof(to_desc));
		to_desc.cd_parentcnid = hfsmp->hfs_private_desc[type].cd_cnid;
		to_desc.cd_cnid = cp->c_fileid;
		to_desc.cd_flags = (type == DIR_HARDLINKS) ? CD_ISDIR : 0;

		do {
			if (type == DIR_HARDLINKS) {
				/* Directory hardlinks always use the cnid. */
				indnodeno = cp->c_fileid;
				MAKE_DIRINODE_NAME(inodename, sizeof(inodename),
							indnodeno);
			} else {
				/* Get a unique indirect node number */
				if (retval == 0) {
					indnodeno = cp->c_fileid;
				} else {
					indnodeno = cur_link_id++;
				}
				MAKE_INODE_NAME(inodename, sizeof(inodename),
						indnodeno);
			}
			/* Move original file/dir to data node directory */
			to_desc.cd_nameptr = (const u_int8_t *)inodename;
			to_desc.cd_namelen = strlen(inodename);
		
			retval = cat_rename(hfsmp, &cp->c_desc, &hfsmp->hfs_private_desc[type],
					&to_desc, NULL);

			if (retval != 0 && retval != EEXIST) {
			    printf("hfs_makelink: cat_rename to %s failed (%d) fileid=%d, vol=%s\n",
				inodename, retval, cp->c_fileid, hfsmp->vcbVN);
			}
		} while ((retval == EEXIST) && (type == FILE_HARDLINKS));
		if (retval)
			goto out;

		/*
		 * Replace original file/dir with a link record.
		 */
		
		bzero(&link_desc, sizeof(link_desc));
		link_desc.cd_nameptr = cp->c_desc.cd_nameptr;
		link_desc.cd_namelen = cp->c_desc.cd_namelen;
		link_desc.cd_parentcnid = cp->c_parentcnid;
		link_desc.cd_flags = S_ISDIR(cp->c_mode) ? CD_ISDIR : 0;

		retval = createindirectlink(hfsmp, indnodeno, &link_desc, 0, &linkcnid, true);
		if (retval) {
			int err;

			/* Restore the cnode's cnid. */
			cp->c_desc.cd_cnid = orig_cnid;

			/* Put the original file back. */
			err = cat_rename(hfsmp, &to_desc, &dcp->c_desc, &cp->c_desc, NULL);
			if (err) {
				if (err != EIO && err != ENXIO)
					printf("hfs_makelink: error %d from cat_rename backout 1", err);
				hfs_mark_inconsistent(hfsmp, HFS_ROLLBACK_FAILED);
			}
			if (retval != EIO && retval != ENXIO) {
				printf("hfs_makelink: createindirectlink (1) failed: %d\n", retval);
				retval = EIO;
			}
			goto out;
		}
		cp->c_attr.ca_linkref = indnodeno;
		cp->c_desc.cd_cnid = linkcnid;
		/* Directory hard links store the first link in an attribute. */
		if (type == DIR_HARDLINKS) {
			if (setfirstlink(hfsmp, cp->c_fileid, linkcnid) == 0)
				cp->c_attr.ca_recflags |= kHFSHasAttributesMask;
		} else /* FILE_HARDLINKS */ {
			cp->c_attr.ca_firstlink = linkcnid;
		}
		cp->c_attr.ca_recflags |= kHFSHasLinkChainMask;
	} else {
		indnodeno = cp->c_attr.ca_linkref;
	}

	/*
	 * Create a catalog entry for the new link (parentID + name).
	 */
	
	bzero(&link_desc, sizeof(link_desc));
	link_desc.cd_nameptr = (const u_int8_t *)cnp->cn_nameptr;
	link_desc.cd_namelen = strlen(cnp->cn_nameptr);
	link_desc.cd_parentcnid = dcp->c_fileid;
	link_desc.cd_flags = S_ISDIR(cp->c_mode) ? CD_ISDIR : 0;

	/* Directory hard links store the first link in an attribute. */
	if (type == DIR_HARDLINKS) {
		retval = getfirstlink(hfsmp, cp->c_fileid, &orig_firstlink);
	} else /* FILE_HARDLINKS */ {
		orig_firstlink = cp->c_attr.ca_firstlink;
	}
	if (retval == 0)
		retval = createindirectlink(hfsmp, indnodeno, &link_desc, 
				orig_firstlink, &linkcnid, 
				(cp->c_attr.ca_recflags & kHFSHasLinkChainMask));
	if (retval && newlink) {
		int err;

		/* Get rid of new link */
		(void) cat_delete(hfsmp, &cp->c_desc, &cp->c_attr);
		
		/* Restore the cnode's cnid. */
		cp->c_desc.cd_cnid = orig_cnid;
		
		/* Put the original file back. */
		err = cat_rename(hfsmp, &to_desc, &dcp->c_desc, &cp->c_desc, NULL);
		if (err) {
			if (err != EIO && err != ENXIO)
				printf("hfs_makelink: error %d from cat_rename backout 2", err);
			hfs_mark_inconsistent(hfsmp, HFS_ROLLBACK_FAILED);
		}

		cp->c_attr.ca_linkref = 0;

		if (retval != EIO && retval != ENXIO) {
			printf("hfs_makelink: createindirectlink (2) failed: %d\n", retval);
			retval = EIO;
		}
		goto out;
	} else if (retval == 0) {

	    /* Update the original first link to point back to the new first link. */
	    if (cp->c_attr.ca_recflags & kHFSHasLinkChainMask) {
		(void) cat_update_siblinglinks(hfsmp, orig_firstlink, linkcnid, HFS_IGNORABLE_LINK);

		/* Update the inode's first link value. */
		if (type == DIR_HARDLINKS) {
		    if (setfirstlink(hfsmp, cp->c_fileid, linkcnid) == 0)
			cp->c_attr.ca_recflags |= kHFSHasAttributesMask;
		} else {
		    cp->c_attr.ca_firstlink = linkcnid;
		}
	    }
	    /*
	     * Finally, if this is a new hardlink then:
	     *  - update the private system directory
	     *  - mark the cnode as a hard link
	     */
	    if (newlink) {
		vnode_t vp;
		
		hfsmp->hfs_private_attr[type].ca_entries++;
		/* From application perspective, directory hard link is a 
		 * normal directory.  Therefore count the new directory 
		 * hard link for folder count calculation.
		 */
		if (type == DIR_HARDLINKS) {
			INC_FOLDERCOUNT(hfsmp, hfsmp->hfs_private_attr[type]);
		}
		retval = cat_update(hfsmp, &hfsmp->hfs_private_desc[type],
		    &hfsmp->hfs_private_attr[type], NULL, NULL);
		if (retval) {
			if (retval != EIO && retval != ENXIO) {
				printf("hfs_makelink: cat_update of privdir failed! (%d)\n", retval);
				retval = EIO;
			}
			hfs_mark_inconsistent(hfsmp, HFS_OP_INCOMPLETE);
		}
		cp->c_flag |= C_HARDLINK;

		/*
		 * Now we need to mark the vnodes as being hardlinks via the vnode_setmultipath call.
		 * Note that we're calling vnode_get here, which should simply add an iocount if possible, without
		 * doing much checking.  It's safe to call this because we are protected by the cnode lock, which
		 * ensures that anyone trying to reclaim it will block until we release it.  vnode_get will usually 
		 * give us an extra iocount, unless the vnode is about to be reclaimed (and has no iocounts).  
		 * In that case, we'd error out, but we'd also not care if we added the VISHARDLINK bit to the vnode.  
		 * 
		 * As for the iocount we're about to add, we can't necessarily always call vnode_put here.  
		 * If the one we add is the only iocount on the vnode, and there was
		 * sufficient vnode pressure, it could go through VNOP_INACTIVE immediately, which would
		 * require the cnode lock and cause us to double-lock panic.  We can only call vnode_put if we know
		 * that the vnode we're operating on is the one with which we came into hfs_vnop_link, because
		 * that means VFS took an iocount on it for us.  If it's *not* the one that we came into the call 
		 * with, then mark it as NEED_VNODE_PUT to have hfs_unlock drop it for us.  hfs_vnop_link will 
		 * unlock the cnode when it is finished.
		 */
		if ((vp = cp->c_vp) != NULLVP) {
			if (vnode_get(vp) == 0) {
				vnode_setmultipath(vp);
				if (vp == src_vp) {
					/* we have an iocount on data fork vnode already. */
					vnode_put(vp);
				}
				else {
					cp->c_flag |= C_NEED_DVNODE_PUT;
				}
			}
		}
		if ((vp = cp->c_rsrc_vp) != NULLVP) {
			if (vnode_get(vp) == 0) {
				vnode_setmultipath(vp);
				if (vp == src_vp) {
					vnode_put(vp);
				}
				else {
					cp->c_flag |= C_NEED_RVNODE_PUT;
				}
			}
		}
		cp->c_touch_chgtime = TRUE;
		cp->c_flag |= C_FORCEUPDATE;
	    }
	    dcp->c_flag |= C_FORCEUPDATE;
	}
out:
	hfs_systemfile_unlock(hfsmp, lockflags);

	cat_postflight(hfsmp, &cookie, p);
	
	if (retval == 0 && newlink) {
		hfs_volupdate(hfsmp, VOL_MKFILE, 0);
	}
	return (retval);
}


/*
 * link vnode operation
 *
 *  IN vnode_t  a_vp;
 *  IN vnode_t  a_tdvp;
 *  IN struct componentname  *a_cnp;
 *  IN vfs_context_t  a_context;
 */
int
hfs_vnop_link(struct vnop_link_args *ap)
{
	struct hfsmount *hfsmp;
	struct vnode *vp = ap->a_vp;
	struct vnode *tdvp = ap->a_tdvp;
	struct vnode *fdvp = NULLVP;
	struct componentname *cnp = ap->a_cnp;
	struct cnode *cp;
	struct cnode *tdcp;
	struct cnode *fdcp = NULL;
	struct cat_desc todesc;
	cnid_t parentcnid;
	int lockflags = 0;
	int intrans = 0;
	enum vtype v_type;
	int error, ret;

	hfsmp = VTOHFS(vp);
	v_type = vnode_vtype(vp);

	/* No hard links in HFS standard file systems. */
	if (hfsmp->hfs_flags & HFS_STANDARD) {
		return (ENOTSUP);
	}
	/* Linking to a special file is not permitted. */
	if (v_type == VBLK || v_type == VCHR) {
		return (EPERM);  
	}

	/*
	 * For now, return ENOTSUP for a symlink target. This can happen
	 * for linkat(2) when called without AT_SYMLINK_FOLLOW.
	 */
	if (v_type == VLNK)
		return (ENOTSUP);

	if (v_type == VDIR) {
#if CONFIG_HFS_DIRLINK
		/* Make sure our private directory exists. */
		if (hfsmp->hfs_private_desc[DIR_HARDLINKS].cd_cnid == 0) {
			return (EPERM);
		}
		/*
		 * Directory hardlinks (ADLs) have only been qualified on
		 * journaled HFS+.  If/when they are tested on non-journaled
		 * file systems then this test can be removed.
		 */
		if (hfsmp->jnl == NULL) {
			return (EPERM);
		}
		/* Directory hardlinks also need the parent of the original directory. */
		if ((error = hfs_vget(hfsmp, hfs_currentparent(VTOC(vp)), &fdvp, 1, 0))) {
			return (error);
		}
#else
		/* some platforms don't support directory hardlinks. */
		return EPERM;
#endif
	} else {
		/* Make sure our private directory exists. */
		if (hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid == 0) {
			return (ENOTSUP);
		}
	}
	if (hfs_freeblks(hfsmp, 0) == 0) {
		if (fdvp) {
			vnode_put(fdvp);
		}
		return (ENOSPC);
	}

	check_for_tracked_file(vp, VTOC(vp)->c_ctime, NAMESPACE_HANDLER_LINK_CREATE, NULL);


	/* Lock the cnodes. */
	if (fdvp) {
		if ((error = hfs_lockfour(VTOC(tdvp), VTOC(vp), VTOC(fdvp), NULL, HFS_EXCLUSIVE_LOCK, NULL))) {
			if (fdvp) {
				vnode_put(fdvp);
		    	}
			return (error);
		}
		fdcp = VTOC(fdvp);
	} else {
		if ((error = hfs_lockpair(VTOC(tdvp), VTOC(vp), HFS_EXCLUSIVE_LOCK))) {
			return (error);
		}
	}
	tdcp = VTOC(tdvp);
	cp = VTOC(vp);
	/* grab the parent CNID from originlist after grabbing cnode locks */
	parentcnid = hfs_currentparent(cp);

	/* 
	 * Make sure we didn't race the src or dst parent directories with rmdir.
	 * Note that we should only have a src parent directory cnode lock 
	 * if we're dealing with a directory hardlink here.
	 */
	if (fdcp) {
		if (fdcp->c_flag & (C_NOEXISTS | C_DELETED)) {
			error = ENOENT;
			goto out;
		}
	}

	if (tdcp->c_flag & (C_NOEXISTS | C_DELETED)) {
		error = ENOENT;
		goto out;
	}

	/* Check the source for errors: 
	 * too many links, immutable, race with unlink
	 */
	if (cp->c_linkcount >= HFS_LINK_MAX) {
		error = EMLINK;
		goto out;
	}
	if (cp->c_bsdflags & (IMMUTABLE | APPEND)) {
		error = EPERM;
		goto out;
	}
	if (cp->c_flag & (C_NOEXISTS | C_DELETED)) {
		error = ENOENT;
		goto out;
	}

	tdcp->c_flag |= C_DIR_MODIFICATION;

	if (hfs_start_transaction(hfsmp) != 0) {
		error = EINVAL;
		goto out;
	}
	intrans = 1;

	todesc.cd_flags = (v_type == VDIR) ? CD_ISDIR : 0;
	todesc.cd_encoding = 0;
	todesc.cd_nameptr = (const u_int8_t *)cnp->cn_nameptr;
	todesc.cd_namelen = cnp->cn_namelen;
	todesc.cd_parentcnid = tdcp->c_fileid;
	todesc.cd_hint = 0;
	todesc.cd_cnid = 0;

	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);

	/* If destination exists then we lost a race with create. */
	if (cat_lookup(hfsmp, &todesc, 0, 0, NULL, NULL, NULL, NULL) == 0) {
		error = EEXIST;
		goto out;
	}
	if (cp->c_flag & C_HARDLINK) {
		struct cat_attr cattr;

		/* If inode is missing then we lost a race with unlink. */
		if ((cat_idlookup(hfsmp, cp->c_fileid, 0, 0, NULL, &cattr, NULL) != 0) ||
		    (cattr.ca_fileid != cp->c_fileid)) {
			error = ENOENT;
			goto out;
		}
	} else {
		cnid_t fileid;

		/* If source is missing then we lost a race with unlink. */
		if ((cat_lookup(hfsmp, &cp->c_desc, 0, 0, NULL, NULL, NULL, &fileid) != 0) ||
		    (fileid != cp->c_fileid)) {
			error = ENOENT;
			goto out;
		}
	}
	/* 
	 * All directory links must reside in an non-ARCHIVED hierarchy.
	 */
	if (v_type == VDIR) {
		/*
		 * - Source parent and destination parent cannot match
		 * - A link is not permitted in the root directory
		 * - Parent of 'pointed at' directory is not the root directory
		 * - The 'pointed at' directory (source) is not an ancestor
		 *   of the new directory hard link (destination).
		 * - No ancestor of the new directory hard link (destination) 
		 *   is a directory hard link.
		 */
		if ((parentcnid == tdcp->c_fileid) ||
		    (tdcp->c_fileid == kHFSRootFolderID) ||
		    (parentcnid == kHFSRootFolderID) ||
		    cat_check_link_ancestry(hfsmp, tdcp->c_fileid, cp->c_fileid)) {
			error = EPERM;  /* abide by the rules, you did not */
			goto out;
		}
	}
	hfs_systemfile_unlock(hfsmp, lockflags);
	lockflags = 0;

	cp->c_linkcount++;
	cp->c_touch_chgtime = TRUE;
	error = hfs_makelink(hfsmp, vp, cp, tdcp, cnp);
	if (error) {
		cp->c_linkcount--;
		hfs_volupdate(hfsmp, VOL_UPDATE, 0);
	} else {
		/* Invalidate negative cache entries in the destination directory */
		if (tdcp->c_flag & C_NEG_ENTRIES) {
			cache_purge_negatives(tdvp);
			tdcp->c_flag &= ~C_NEG_ENTRIES;
		}

		/* Update the target directory and volume stats */
		tdcp->c_entries++;
		if (v_type == VDIR) {
			INC_FOLDERCOUNT(hfsmp, tdcp->c_attr);
			tdcp->c_attr.ca_recflags |= kHFSHasChildLinkMask;

			/* Set kHFSHasChildLinkBit in the destination hierarchy */
			error = cat_set_childlinkbit(hfsmp, tdcp->c_parentcnid);
			if (error) {
				printf ("hfs_vnop_link: error updating destination parent chain for id=%u, vol=%s\n", tdcp->c_cnid, hfsmp->vcbVN);
				error = 0;
			}
		}
		tdcp->c_dirchangecnt++;
		hfs_incr_gencount(tdcp);
		tdcp->c_touch_chgtime = TRUE;
		tdcp->c_touch_modtime = TRUE;
		tdcp->c_flag |= C_FORCEUPDATE;

		error = hfs_update(tdvp, 0);
		if (error) {
			if (error != EIO && error != ENXIO) {
				printf("hfs_vnop_link: error %d updating tdvp %p\n", error, tdvp);
				error = EIO;
			}
			hfs_mark_inconsistent(hfsmp, HFS_OP_INCOMPLETE);
		}

		if ((v_type == VDIR) && 
		    (fdcp != NULL) && 
		    ((fdcp->c_attr.ca_recflags & kHFSHasChildLinkMask) == 0)) {

			fdcp->c_attr.ca_recflags |= kHFSHasChildLinkMask;
			fdcp->c_touch_chgtime = TRUE;
			fdcp->c_flag |= C_FORCEUPDATE;
			error = hfs_update(fdvp, 0);
			if (error) {
				if (error != EIO && error != ENXIO) {
					printf("hfs_vnop_link: error %d updating fdvp %p\n", error, fdvp);
					// No point changing error as it's set immediate below
				}
				hfs_mark_inconsistent(hfsmp, HFS_OP_INCOMPLETE);
			}

			/* Set kHFSHasChildLinkBit in the source hierarchy */
			error = cat_set_childlinkbit(hfsmp, fdcp->c_parentcnid);
			if (error) {
				printf ("hfs_vnop_link: error updating source parent chain for id=%u, vol=%s\n", fdcp->c_cnid, hfsmp->vcbVN);
				error = 0;
			}
		}
		hfs_volupdate(hfsmp, VOL_MKFILE,
			(tdcp->c_cnid == kHFSRootFolderID));
	}
	/* Make sure update occurs inside transaction */
	cp->c_flag |= C_FORCEUPDATE;  

	if (error == 0 && (ret = hfs_update(vp, TRUE)) != 0) {
		if (ret != EIO && ret != ENXIO)
			printf("hfs_vnop_link: error %d updating vp @ %p\n", ret, vp);
		hfs_mark_inconsistent(hfsmp, HFS_OP_INCOMPLETE);
	}

out:
	if (lockflags) {
		hfs_systemfile_unlock(hfsmp, lockflags);
	}
	if (intrans) {
		hfs_end_transaction(hfsmp);
	}

	tdcp->c_flag &= ~C_DIR_MODIFICATION;
	wakeup((caddr_t)&tdcp->c_flag);

	if (fdcp) {
		hfs_unlockfour(tdcp, cp, fdcp, NULL);
	} else {
		hfs_unlockpair(tdcp, cp);
	}
	if (fdvp) {
		vnode_put(fdvp);
	}
	return (error);
}


/*
 * Remove a link to a hardlink file/dir.
 *
 * Note: dvp and vp cnodes are already locked.
 */
int
hfs_unlink(struct hfsmount *hfsmp, struct vnode *dvp, struct vnode *vp, struct componentname *cnp, int skip_reserve)
{
	struct cnode *cp;
	struct cnode *dcp;
	struct cat_desc cndesc;
	struct timeval tv;
	char inodename[32];
	cnid_t  prevlinkid;
	cnid_t  nextlinkid;
	int lockflags = 0;
	int started_tr;
	int error;
	
	if (hfsmp->hfs_flags & HFS_STANDARD) {
		return (EPERM);
	}
	cp = VTOC(vp);
	dcp = VTOC(dvp);

	dcp->c_flag |= C_DIR_MODIFICATION;
	
	/* Remove the entry from the namei cache: */
	cache_purge(vp);

	if ((error = hfs_start_transaction(hfsmp)) != 0) {
		started_tr = 0;
		goto out;
	}
	started_tr = 1;

	/* 
	 * Protect against a race with rename by using the component
	 * name passed in and parent id from dvp (instead of using 
	 * the cp->c_desc which may have changed).  
	 *
	 * Re-lookup the component name so we get the correct cnid
	 * for the name (as opposed to the c_cnid in the cnode which
	 * could have changed before the cnode was locked).
	 */
	cndesc.cd_flags = vnode_isdir(vp) ? CD_ISDIR : 0;
	cndesc.cd_encoding = cp->c_desc.cd_encoding;
	cndesc.cd_nameptr = (const u_int8_t *)cnp->cn_nameptr;
	cndesc.cd_namelen = cnp->cn_namelen;
	cndesc.cd_parentcnid = dcp->c_fileid;
	cndesc.cd_hint = dcp->c_childhint;

	lockflags = SFL_CATALOG | SFL_ATTRIBUTE;
	if (cndesc.cd_flags & CD_ISDIR) {
		/* We'll be removing the alias resource allocation blocks. */
		lockflags |= SFL_BITMAP;
	}
	lockflags = hfs_systemfile_lock(hfsmp, lockflags, HFS_EXCLUSIVE_LOCK);

	if ((error = cat_lookuplink(hfsmp, &cndesc, &cndesc.cd_cnid, &prevlinkid, &nextlinkid))) {
		goto out;
	}

	/* Reserve some space in the catalog file. */
	if (!skip_reserve && (error = cat_preflight(hfsmp, 2 * CAT_DELETE, NULL, 0))) {
		goto out;
	}

	/* Purge any cached origin entries for a directory or file hard link. */
	hfs_relorigin(cp, dcp->c_fileid);
	if (dcp->c_fileid != dcp->c_cnid) {
		hfs_relorigin(cp, dcp->c_cnid);
	}

	/* Delete the link record. */
	if ((error = cat_deletelink(hfsmp, &cndesc))) {
		goto out;
	}

	/* Update the parent directory. */
	if (dcp->c_entries > 0) {
		dcp->c_entries--;
	}
	if (cndesc.cd_flags & CD_ISDIR) {
		DEC_FOLDERCOUNT(hfsmp, dcp->c_attr);
	}
	dcp->c_dirchangecnt++;
	hfs_incr_gencount(dcp);
	microtime(&tv);
	dcp->c_ctime = tv.tv_sec;
	dcp->c_mtime = tv.tv_sec;
	(void ) cat_update(hfsmp, &dcp->c_desc, &dcp->c_attr, NULL, NULL);

	/*
	 * If this is the last link then we need to process the inode.
	 * Otherwise we need to fix up the link chain.
	 */
	--cp->c_linkcount;
	if (cp->c_linkcount < 1) {
		char delname[32];
		struct cat_desc to_desc;
		struct cat_desc from_desc;

		/*
		 * If a file inode or directory inode is being deleted, rename 
		 * it to an open deleted file.  This ensures that deletion 
		 * of inode and its corresponding extended attributes does 
		 * not overflow the journal.  This inode will be deleted 
		 * either in hfs_vnop_inactive() or in hfs_remove_orphans(). 
		 * Note: a rename failure here is not fatal.
		 */	
		bzero(&from_desc, sizeof(from_desc));
		bzero(&to_desc, sizeof(to_desc));
		if (vnode_isdir(vp)) {
			if (cp->c_entries != 0) {
				panic("hfs_unlink: dir not empty (id %d, %d entries)", cp->c_fileid, cp->c_entries);
			}
			MAKE_DIRINODE_NAME(inodename, sizeof(inodename),
						cp->c_attr.ca_linkref);
			from_desc.cd_parentcnid = hfsmp->hfs_private_desc[DIR_HARDLINKS].cd_cnid;
			from_desc.cd_flags = CD_ISDIR;
			to_desc.cd_flags = CD_ISDIR;
		} else { 
			MAKE_INODE_NAME(inodename, sizeof(inodename),
					cp->c_attr.ca_linkref);
			from_desc.cd_parentcnid = hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid;
			from_desc.cd_flags = 0;
			to_desc.cd_flags = 0;
		}
		from_desc.cd_nameptr = (const u_int8_t *)inodename;
		from_desc.cd_namelen = strlen(inodename);
		from_desc.cd_cnid = cp->c_fileid;

		MAKE_DELETED_NAME(delname, sizeof(delname), cp->c_fileid);
		to_desc.cd_nameptr = (const u_int8_t *)delname;
		to_desc.cd_namelen = strlen(delname);
		to_desc.cd_parentcnid = hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid;
		to_desc.cd_cnid = cp->c_fileid;

		error = cat_rename(hfsmp, &from_desc, &hfsmp->hfs_private_desc[FILE_HARDLINKS],
				   &to_desc, (struct cat_desc *)NULL);
		if (error == 0) {
			cp->c_flag |= C_DELETED;
			cp->c_attr.ca_recflags &= ~kHFSHasLinkChainMask;
			cp->c_attr.ca_firstlink = 0;
			if (vnode_isdir(vp)) {
				hfsmp->hfs_private_attr[DIR_HARDLINKS].ca_entries--;
				DEC_FOLDERCOUNT(hfsmp, hfsmp->hfs_private_attr[DIR_HARDLINKS]);

				hfsmp->hfs_private_attr[FILE_HARDLINKS].ca_entries++;
				INC_FOLDERCOUNT(hfsmp, hfsmp->hfs_private_attr[FILE_HARDLINKS]);

				(void)cat_update(hfsmp, &hfsmp->hfs_private_desc[DIR_HARDLINKS],
					&hfsmp->hfs_private_attr[DIR_HARDLINKS], NULL, NULL);
				(void)cat_update(hfsmp, &hfsmp->hfs_private_desc[FILE_HARDLINKS],
					&hfsmp->hfs_private_attr[FILE_HARDLINKS], NULL, NULL);
			}
		} else {
			error = 0;  /* rename failure here is not fatal */
		}
	} else /* Still some links left */ {
		cnid_t firstlink;

		/*
		 * Update the start of the link chain.
		 * Note: Directory hard links store the first link in an attribute.
		 */
		if (vnode_isdir(vp) &&
		    getfirstlink(hfsmp, cp->c_fileid, &firstlink) == 0 &&
		    firstlink == cndesc.cd_cnid) {
			if (setfirstlink(hfsmp, cp->c_fileid, nextlinkid) == 0)
				cp->c_attr.ca_recflags |= kHFSHasAttributesMask;
		} else if (vnode_isreg(vp) && cp->c_attr.ca_firstlink == cndesc.cd_cnid) {
			cp->c_attr.ca_firstlink = nextlinkid;
		}
		/* Update previous link. */
		if (prevlinkid) {
			(void) cat_update_siblinglinks(hfsmp, prevlinkid, HFS_IGNORABLE_LINK, nextlinkid);
		}
		/* Update next link. */
		if (nextlinkid) {
			(void) cat_update_siblinglinks(hfsmp, nextlinkid, prevlinkid, HFS_IGNORABLE_LINK);
		}

		/*
		 * The call to cat_releasedesc below will only release the name buffer;
		 * it does not zero out the rest of the fields in the 'cat_desc' data structure.
		 * 
		 * As a result, since there are still other links at this point, we need
		 * to make the current cnode descriptor point to the raw inode.  If a path-based
		 * system call comes along first, it will replace the descriptor with a valid link
		 * ID.  If a userland process already has a file descriptor open, then they will
		 * bypass that lookup, though.  Replacing the descriptor CNID with the raw
		 * inode will force it to generate a new full path.
		 */
		cp->c_cnid = cp->c_fileid;

	}

	/* Push new link count to disk. */
	cp->c_ctime = tv.tv_sec;	
	(void) cat_update(hfsmp, &cp->c_desc, &cp->c_attr, NULL, NULL);

	/* All done with the system files. */
	hfs_systemfile_unlock(hfsmp, lockflags);
	lockflags = 0;

	/* Update file system stats. */
	hfs_volupdate(hfsmp, VOL_RMFILE, (dcp->c_cnid == kHFSRootFolderID));

	/*
	 * All done with this cnode's descriptor...
	 *
	 * Note: all future catalog calls for this cnode may be
	 * by fileid only.  This is OK for HFS (which doesn't have
	 * file thread records) since HFS doesn't support hard links.
	 */
	cat_releasedesc(&cp->c_desc);

out:
	if (lockflags) {
		hfs_systemfile_unlock(hfsmp, lockflags);
	}
	if (started_tr) {
		hfs_end_transaction(hfsmp);
	}

	dcp->c_flag &= ~C_DIR_MODIFICATION;
	wakeup((caddr_t)&dcp->c_flag);

	return (error);
}


/*
 * Initialize the HFS+ private system directories.
 *
 * These directories are used to hold the inodes
 * for file and directory hardlinks as well as
 * open-unlinked files.
 *
 * If they don't yet exist they will get created.
 *
 * This call is assumed to be made during mount.
 */
void
hfs_privatedir_init(struct hfsmount * hfsmp, enum privdirtype type)
{
	struct vnode * dvp = NULLVP;
	struct cnode * dcp = NULL;
	struct cat_desc *priv_descp;
	struct cat_attr *priv_attrp;
	struct FndrDirInfo * fndrinfo;
	struct timeval tv;
	int lockflags;
	int trans = 0;
	int error;
	
	if (hfsmp->hfs_flags & HFS_STANDARD) {
		return;
	}

	priv_descp = &hfsmp->hfs_private_desc[type];
	priv_attrp = &hfsmp->hfs_private_attr[type];

	/* Check if directory already exists. */
	if (priv_descp->cd_cnid != 0) {
		return;
	}

	priv_descp->cd_parentcnid = kRootDirID;
	priv_descp->cd_nameptr = (const u_int8_t *)hfs_private_names[type];
	priv_descp->cd_namelen = strlen((const char *)priv_descp->cd_nameptr);
	priv_descp->cd_flags = CD_ISDIR | CD_DECOMPOSED;

	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);
	error = cat_lookup(hfsmp, priv_descp, 0, 0, NULL, priv_attrp, NULL, NULL);
	hfs_systemfile_unlock(hfsmp, lockflags);

	if (error == 0) {
		if (type == FILE_HARDLINKS) {
			hfsmp->hfs_metadata_createdate = priv_attrp->ca_itime;
		}
		priv_descp->cd_cnid = priv_attrp->ca_fileid;
		goto exit;
	}

	/* Directory is missing, if this is read-only then we're done. */
	if (hfsmp->hfs_flags & HFS_READ_ONLY) {
		goto exit;
	}

	/* Grab the root directory so we can update it later. */
	if (hfs_vget(hfsmp, kRootDirID, &dvp, 0, 0) != 0) {
		goto exit;
	}
	dcp = VTOC(dvp);

	/* Setup the default attributes */
	bzero(priv_attrp, sizeof(struct cat_attr));
	priv_attrp->ca_flags = UF_IMMUTABLE | UF_HIDDEN;
	priv_attrp->ca_mode = S_IFDIR;
	if (type == DIR_HARDLINKS) {
		priv_attrp->ca_mode |= S_ISVTX | S_IRUSR | S_IXUSR | S_IRGRP |
		                       S_IXGRP | S_IROTH | S_IXOTH;
	}
	priv_attrp->ca_linkcount = 1;
	priv_attrp->ca_itime = hfsmp->hfs_itime;
	priv_attrp->ca_recflags = kHFSHasFolderCountMask;
	
	fndrinfo = (struct FndrDirInfo *)&priv_attrp->ca_finderinfo;
	fndrinfo->frLocation.v = SWAP_BE16(16384);
	fndrinfo->frLocation.h = SWAP_BE16(16384);
	fndrinfo->frFlags = SWAP_BE16(kIsInvisible + kNameLocked);		

	if (hfs_start_transaction(hfsmp) != 0) {
		goto exit;
	}
	trans = 1;

	/* Need the catalog and EA b-trees for CNID acquisition */
	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG | SFL_ATTRIBUTE, HFS_EXCLUSIVE_LOCK);

	/* Make sure there's space in the Catalog file. */
	if (cat_preflight(hfsmp, CAT_CREATE, NULL, 0) != 0) {
		hfs_systemfile_unlock(hfsmp, lockflags);
		goto exit;
	}

	/* Get the CNID for use */
	cnid_t new_id;
	if ((error = cat_acquire_cnid(hfsmp, &new_id))) {
		hfs_systemfile_unlock (hfsmp, lockflags);
		goto exit;
	}
	
	/* Create the private directory on disk. */
	error = cat_create(hfsmp, new_id, priv_descp, priv_attrp, NULL);
	if (error == 0) {
		priv_descp->cd_cnid = priv_attrp->ca_fileid;

		/* Update the parent directory */
		dcp->c_entries++;
		INC_FOLDERCOUNT(hfsmp, dcp->c_attr);
		dcp->c_dirchangecnt++;
		hfs_incr_gencount(dcp);
		microtime(&tv);
		dcp->c_ctime = tv.tv_sec;
		dcp->c_mtime = tv.tv_sec;
		(void) cat_update(hfsmp, &dcp->c_desc, &dcp->c_attr, NULL, NULL);
	}

	hfs_systemfile_unlock(hfsmp, lockflags);
	
	if (error) {
		goto exit;
	}
	if (type == FILE_HARDLINKS) {
		hfsmp->hfs_metadata_createdate = priv_attrp->ca_itime;
	}
	hfs_volupdate(hfsmp, VOL_MKDIR, 1);
exit:
	if (trans) {
		hfs_end_transaction(hfsmp);
	}
	if (dvp) {
		hfs_unlock(dcp);
		vnode_put(dvp);
	}
	if ((error == 0) && (type == DIR_HARDLINKS)) {
		hfs_xattr_init(hfsmp);
	}
}


/*
 * Lookup a hardlink link (from chain)
 */
int
hfs_lookup_siblinglinks(struct hfsmount *hfsmp, cnid_t linkfileid, cnid_t *prevlinkid,  cnid_t *nextlinkid)
{
	int lockflags;
	int error;

	*prevlinkid = 0;
	*nextlinkid = 0;

	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);

	error = cat_lookup_siblinglinks(hfsmp, linkfileid, prevlinkid, nextlinkid);
	if (error == ENOLINK) {
		hfs_systemfile_unlock(hfsmp, lockflags);
		lockflags = hfs_systemfile_lock(hfsmp, SFL_ATTRIBUTE, HFS_SHARED_LOCK);

		error = getfirstlink(hfsmp, linkfileid, nextlinkid);
	}
	hfs_systemfile_unlock(hfsmp, lockflags);

	return (error);
}


/* Find the oldest / last hardlink in the link chain */
int 
hfs_lookup_lastlink (struct hfsmount *hfsmp, cnid_t linkfileid, 
		cnid_t *lastid, struct cat_desc *cdesc) {
	int lockflags;
	int error;

	*lastid = 0;
	
	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);

	error = cat_lookup_lastlink(hfsmp, linkfileid, lastid, cdesc);
	
	hfs_systemfile_unlock(hfsmp, lockflags);
	
	/*
	 * cat_lookup_lastlink will zero out the lastid/cdesc arguments as needed
	 * upon error cases.
	 */ 	
	return error;
}


/*
 * Cache the origin of a directory or file hard link
 *
 * cnode must be lock on entry
 */
__private_extern__
void
hfs_savelinkorigin(cnode_t *cp, cnid_t parentcnid)
{
	linkorigin_t *origin = NULL;
	thread_t thread = current_thread();
	int count = 0;
	int maxorigins = (S_ISDIR(cp->c_mode)) ? MAX_CACHED_ORIGINS : MAX_CACHED_FILE_ORIGINS;
	/*
	 *  Look for an existing origin first.  If not found, create/steal one.
	 */
	TAILQ_FOREACH(origin, &cp->c_originlist, lo_link) {
		++count;
		if (origin->lo_thread == thread) {
			TAILQ_REMOVE(&cp->c_originlist, origin, lo_link);
			break;
		}
	}
	if (origin == NULL) {
		/* Recycle the last (i.e., the oldest) if we have too many. */
		if (count > maxorigins) {
			origin = TAILQ_LAST(&cp->c_originlist, hfs_originhead);
			TAILQ_REMOVE(&cp->c_originlist, origin, lo_link);
		} else {
			MALLOC(origin, linkorigin_t *, sizeof(linkorigin_t), M_TEMP, M_WAITOK);
		}
		origin->lo_thread = thread;
	}
	origin->lo_cnid = cp->c_cnid;
	origin->lo_parentcnid = parentcnid;
	TAILQ_INSERT_HEAD(&cp->c_originlist, origin, lo_link);
}

/*
 * Release any cached origins for a directory or file hard link
 *
 * cnode must be lock on entry
 */
__private_extern__
void
hfs_relorigins(struct cnode *cp)
{
	linkorigin_t *origin, *prev;

	TAILQ_FOREACH_SAFE(origin, &cp->c_originlist, lo_link, prev) {
		FREE(origin, M_TEMP);
	}
	TAILQ_INIT(&cp->c_originlist);
}

/*
 * Release a specific origin for a directory or file hard link
 *
 * cnode must be lock on entry
 */
__private_extern__
void
hfs_relorigin(struct cnode *cp, cnid_t parentcnid)
{
	linkorigin_t *origin, *prev;
	thread_t thread = current_thread();

	TAILQ_FOREACH_SAFE(origin, &cp->c_originlist, lo_link, prev) {
		if ((origin->lo_thread == thread) ||
		    (origin->lo_parentcnid == parentcnid)) {
			TAILQ_REMOVE(&cp->c_originlist, origin, lo_link);
			FREE(origin, M_TEMP);
			break;
		}
	}
}

/*
 * Test if a directory or file hard link has a cached origin
 *
 * cnode must be lock on entry
 */
__private_extern__
int
hfs_haslinkorigin(cnode_t *cp)
{
	if (cp->c_flag & C_HARDLINK) {
		linkorigin_t *origin;
		thread_t thread = current_thread();
	
		TAILQ_FOREACH(origin, &cp->c_originlist, lo_link) {
			if (origin->lo_thread == thread) {
				return (1);
			}
		}
	}
	return (0);
}

/*
 * Obtain the current parent cnid of a directory or file hard link
 *
 * cnode must be lock on entry
 */
__private_extern__
cnid_t
hfs_currentparent(cnode_t *cp)
{
	if (cp->c_flag & C_HARDLINK) {
		linkorigin_t *origin;
		thread_t thread = current_thread();
	
		TAILQ_FOREACH(origin, &cp->c_originlist, lo_link) {
			if (origin->lo_thread == thread) {
				return (origin->lo_parentcnid);
			}
		}
	}
	return (cp->c_parentcnid);
}

/*
 * Obtain the current cnid of a directory or file hard link
 *
 * cnode must be lock on entry
 */
__private_extern__
cnid_t
hfs_currentcnid(cnode_t *cp)
{
	if (cp->c_flag & C_HARDLINK) {
		linkorigin_t *origin;
		thread_t thread = current_thread();
	
		TAILQ_FOREACH(origin, &cp->c_originlist, lo_link) {
			if (origin->lo_thread == thread) {
				return (origin->lo_cnid);
			}
		}
	}
	return (cp->c_cnid);
}


/*
 * Set the first link attribute for a given file id.
 *
 * The attributes b-tree must already be locked.
 * If journaling is enabled, a transaction must already be started.
 */
static int
setfirstlink(struct hfsmount * hfsmp, cnid_t fileid, cnid_t firstlink)
{
	FCB * btfile;
	BTreeIterator * iterator;
	FSBufferDescriptor btdata;
	u_int8_t attrdata[FIRST_LINK_XATTR_REC_SIZE];
	HFSPlusAttrData *dataptr;
	int result;
	u_int16_t datasize;

	if (hfsmp->hfs_attribute_cp == NULL) {
		return (EPERM);
	}
	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));

	result = hfs_buildattrkey(fileid, FIRST_LINK_XATTR_NAME, (HFSPlusAttrKey *)&iterator->key);
	if (result) {
		goto out;
	}
	dataptr = (HFSPlusAttrData *)&attrdata[0];
	dataptr->recordType = kHFSPlusAttrInlineData;
	dataptr->reserved[0] = 0;
	dataptr->reserved[1] = 0;

	/*
	 * Since attrData is variable length, we calculate the size of
	 * attrData by subtracting the size of all other members of
	 * structure HFSPlusAttData from the size of attrdata.
	 */
	(void)snprintf((char *)&dataptr->attrData[0],
			sizeof(dataptr) - (4 * sizeof(uint32_t)),
		        "%lu", (unsigned long)firstlink);
	dataptr->attrSize = 1 + strlen((char *)&dataptr->attrData[0]);

	/* Calculate size of record rounded up to multiple of 2 bytes. */
	datasize = sizeof(HFSPlusAttrData) - 2 + dataptr->attrSize + ((dataptr->attrSize & 1) ? 1 : 0);

	btdata.bufferAddress = dataptr;
	btdata.itemSize = datasize;
	btdata.itemCount = 1;

	btfile = hfsmp->hfs_attribute_cp->c_datafork;

	/* Insert the attribute. */
	result = BTInsertRecord(btfile, iterator, &btdata, datasize);
	if (result == btExists) {
		result = BTReplaceRecord(btfile, iterator, &btdata, datasize);
	}
	(void) BTFlushPath(btfile);
out:
	FREE(iterator, M_TEMP);

	return MacToVFSError(result);
}

/*
 * Get the first link attribute for a given file id.
 *
 * The attributes b-tree must already be locked.
 */
static int
getfirstlink(struct hfsmount * hfsmp, cnid_t fileid, cnid_t *firstlink)
{
	FCB * btfile;
	BTreeIterator * iterator;
	FSBufferDescriptor btdata;
	u_int8_t attrdata[FIRST_LINK_XATTR_REC_SIZE];
	HFSPlusAttrData *dataptr;
	int result;
	u_int16_t datasize;

	if (hfsmp->hfs_attribute_cp == NULL) {
		return (EPERM);
	}
	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));

	result = hfs_buildattrkey(fileid, FIRST_LINK_XATTR_NAME, (HFSPlusAttrKey *)&iterator->key);
	if (result)
		goto out;

	dataptr = (HFSPlusAttrData *)&attrdata[0];
	datasize = sizeof(attrdata);

	btdata.bufferAddress = dataptr;
	btdata.itemSize = sizeof(attrdata);
	btdata.itemCount = 1;

	btfile = hfsmp->hfs_attribute_cp->c_datafork;

	result = BTSearchRecord(btfile, iterator, &btdata, NULL, NULL);
	if (result)
		goto out;

	if (dataptr->attrSize < 3) {
		result = ENOENT;
		goto out;
	}
	*firstlink = strtoul((char*)&dataptr->attrData[0], NULL, 10);
out:
	FREE(iterator, M_TEMP);

	return MacToVFSError(result);
}

