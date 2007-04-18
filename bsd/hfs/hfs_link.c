/*
 * Copyright (c) 1999-2004 Apple Computer, Inc. All rights reserved.
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

#include "hfs.h"
#include "hfs_catalog.h"
#include "hfs_format.h"
#include "hfs_endian.h"


static int cur_link_id = 0;


/*
 * Create a new indirect link
 *
 * An indirect link is a reference to a data node.  The only useable
 * fields in the link are the link number, parentID, name and text
 * encoding.  All other catalog fields are ignored.
 */
static int
createindirectlink(struct hfsmount *hfsmp, u_int32_t linknum,
			u_int32_t linkparid, char *linkName, cnid_t *linkcnid)
{
	struct FndrFileInfo *fip;
	struct cat_desc desc;
	struct cat_attr attr;
	int result;

	/* Setup the descriptor */
	bzero(&desc, sizeof(desc));
	desc.cd_nameptr = linkName;
	desc.cd_namelen = strlen(linkName);
	desc.cd_parentcnid = linkparid;

	/* Setup the default attributes */
	bzero(&attr, sizeof(attr));
	
	/* links are matched to data nodes by link ID and to volumes by create date */
	attr.ca_rdev = linknum;  /* note: cat backend overloads ca_rdev to be the linknum when nlink = 0 */
	attr.ca_itime = HFSTOVCB(hfsmp)->vcbCrDate;
	attr.ca_mode = S_IFREG;

	fip = (struct FndrFileInfo *)&attr.ca_finderinfo;
	fip->fdType    = SWAP_BE32 (kHardLinkFileType);	/* 'hlnk' */
	fip->fdCreator = SWAP_BE32 (kHFSPlusCreator);	/* 'hfs+' */
	fip->fdFlags   = SWAP_BE16 (kHasBeenInited);

	/* Create the indirect link directly in the catalog */
	result = cat_create(hfsmp, &desc, &attr, NULL);

	if (result == 0 && linkcnid != NULL)
		*linkcnid = attr.ca_fileid;

	return (result);
}


/*
 * 2 locks are needed (dvp and vp)
 * also need catalog lock
 *
 * caller's responsibility:
 *		componentname cleanup
 *		unlocking dvp and vp
 */
static int
hfs_makelink(struct hfsmount *hfsmp, struct cnode *cp, struct cnode *dcp,
		struct componentname *cnp)
{
	vfs_context_t ctx = cnp->cn_context;
	struct proc *p = vfs_context_proc(ctx);
	u_int32_t indnodeno = 0;
	char inodename[32]; 
	struct cat_desc to_desc;
	int newlink = 0;
	int lockflags;
	int retval;
	cat_cookie_t cookie;
	cnid_t orig_cnid;

	if (cur_link_id == 0) {
	    cur_link_id = ((random() & 0x3fffffff) + 100);
	    // printf("hfs: initializing cur link id to: 0x%.8x\n", cur_link_id);
	}
	
	/* We don't allow link nodes in our Private Meta Data folder! */
	if (dcp->c_fileid == hfsmp->hfs_privdir_desc.cd_cnid)
		return (EPERM);

	if (hfs_freeblks(hfsmp, 0) == 0)
		return (ENOSPC);

	bzero(&cookie, sizeof(cat_cookie_t));
	/* Reserve some space in the Catalog file. */
	if ((retval = cat_preflight(hfsmp, (2 * CAT_CREATE)+ CAT_RENAME, &cookie, p))) {
		return (retval);
	}

	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_EXCLUSIVE_LOCK);

	// save off a copy of the current cnid so we can put 
	// it back if we get errors down below
	orig_cnid = cp->c_desc.cd_cnid;

	/*
	 * If this is a new hardlink then we need to create the data
	 * node (inode) and replace the original file with a link node.
	 */
	if (cp->c_nlink == 2 && (cp->c_flag & C_HARDLINK) == 0) {
		newlink = 1;
		bzero(&to_desc, sizeof(to_desc));
		to_desc.cd_parentcnid = hfsmp->hfs_privdir_desc.cd_cnid;
		to_desc.cd_cnid = cp->c_fileid;

		do {
			/* get a unique indirect node number */
			if (retval == 0) {
			    indnodeno = cp->c_fileid;
			} else {
			    indnodeno = cur_link_id++;
			}

			MAKE_INODE_NAME(inodename, indnodeno);

			/* move source file to data node directory */
			to_desc.cd_nameptr = inodename;
			to_desc.cd_namelen = strlen(inodename);
		
			retval = cat_rename(hfsmp, &cp->c_desc, &hfsmp->hfs_privdir_desc,
					&to_desc, NULL);

			if (retval != 0 && retval != EEXIST) {
			    printf("hfs_makelink: cat_rename to %s failed (%d). fileid %d\n",
				inodename, retval, cp->c_fileid);
			}

		} while (retval == EEXIST);
		if (retval)
			goto out;

		/* Replace source file with link node */
		retval = createindirectlink(hfsmp, indnodeno, cp->c_parentcnid,
				cp->c_desc.cd_nameptr, &cp->c_desc.cd_cnid);
		if (retval) {
		    /* put it source file back */
		    int err;

		    // Put this back to what it was before.
		    cp->c_desc.cd_cnid = orig_cnid;

		    err = cat_rename(hfsmp, &to_desc, &dcp->c_desc, &cp->c_desc, NULL);
		    if (err)
			panic("hfs_makelink: error %d from cat_rename backout 1", err);
		    goto out;
		}
		cp->c_rdev = indnodeno;
	} else {
		indnodeno = cp->c_rdev;
	}

	/*
	 * Create a catalog entry for the new link (parentID + name).
	 */
	retval = createindirectlink(hfsmp, indnodeno, dcp->c_fileid, cnp->cn_nameptr, NULL);
	if (retval && newlink) {
	    int err;

	    /* Get rid of new link */
	    (void) cat_delete(hfsmp, &cp->c_desc, &cp->c_attr);
	    
	    // Put this back to what it was before.
	    cp->c_desc.cd_cnid = orig_cnid;

	    /* Put the source file back */
	    err = cat_rename(hfsmp, &to_desc, &dcp->c_desc, &cp->c_desc, NULL);
	    if (err)
		panic("hfs_makelink: error %d from cat_rename backout 2", err);

	    goto out;
	}

	/*
	 * Finally, if this is a new hardlink then:
	 *  - update HFS Private Data dir
	 *  - mark the cnode as a hard link
	 */
	if (newlink) {
		vnode_t vp;
		
	    if (retval != 0) {
		panic("hfs_makelink: retval %d but newlink = 1!\n", retval);
	    }
	    
		hfsmp->hfs_privdir_attr.ca_entries++;
		retval = cat_update(hfsmp, &hfsmp->hfs_privdir_desc,
				    &hfsmp->hfs_privdir_attr, NULL, NULL);
		if (retval != 0) {
		    panic("hfs_makelink: cat_update of privdir failed! (%d)\n",
			  retval);
		}
		hfs_volupdate(hfsmp, VOL_MKFILE, 0);
		cp->c_flag |= C_HARDLINK;
		if ((vp = cp->c_vp) != NULLVP) {
			if (vnode_get(vp) == 0) {
				vnode_set_hard_link(vp);
				vnode_put(vp);
			}
		}
		if ((vp = cp->c_rsrc_vp) != NULLVP) {
			if (vnode_get(vp) == 0) {
				vnode_set_hard_link(vp);
				vnode_put(vp);
			}
		}
		cp->c_touch_chgtime = TRUE;
		cp->c_flag |= C_FORCEUPDATE;
	}
	dcp->c_flag |= C_FORCEUPDATE;

out:
	hfs_systemfile_unlock(hfsmp, lockflags);

	cat_postflight(hfsmp, &cookie, p);
	return (retval);
}


/*
 * link vnode call
#% link		vp	U U U
#% link		tdvp	L U U
#
 vnop_link {
     IN WILLRELE struct vnode *vp;
     IN struct vnode *targetPar_vp;
     IN struct componentname *cnp;
     IN vfs_context_t context;

     */
__private_extern__
int
hfs_vnop_link(struct vnop_link_args *ap)
{
	struct hfsmount *hfsmp;
	struct vnode *vp = ap->a_vp;
	struct vnode *tdvp = ap->a_tdvp;
	struct componentname *cnp = ap->a_cnp;
	struct cnode *cp;
	struct cnode *tdcp;
	enum vtype v_type;
	int error, ret, lockflags;
	struct cat_desc cndesc;

	if (VTOVCB(tdvp)->vcbSigWord != kHFSPlusSigWord) {
		return err_link(ap);	/* hfs disks don't support hard links */
	}
	if (VTOHFS(vp)->hfs_privdir_desc.cd_cnid == 0) {
		return err_link(ap);	/* no private metadata dir, no links possible */
	}
	if (vnode_mount(tdvp) != vnode_mount(vp)) {
		return (EXDEV);
	}
	if ((error = hfs_lockpair(VTOC(tdvp), VTOC(vp), HFS_EXCLUSIVE_LOCK))) {
		return (error);
	}
	tdcp = VTOC(tdvp);
	cp = VTOC(vp);
	hfsmp = VTOHFS(vp);

	if (cp->c_nlink >= HFS_LINK_MAX) {
		error = EMLINK;
		goto out;
	}
	if (cp->c_flags & (IMMUTABLE | APPEND)) {
		error = EPERM;
		goto out;
	}
	if (cp->c_flag & (C_NOEXISTS | C_DELETED)) {
	    error = ENOENT;
	    goto out;
	}
	
	v_type = vnode_vtype(vp);
	if (v_type == VBLK || v_type == VCHR) {
		error = EINVAL;  /* cannot link to a special file */
		goto out;
	}

	if (hfs_start_transaction(hfsmp) != 0) {
	    error = EINVAL;  /* cannot link to a special file */
	    goto out;
	}

	cp->c_nlink++;
	cp->c_touch_chgtime = TRUE;

	error = hfs_makelink(hfsmp, cp, tdcp, cnp);
	if (error) {
		cp->c_nlink--;
		hfs_volupdate(hfsmp, VOL_UPDATE, 0);
	} else {
		/* Invalidate negative cache entries in the destination directory */
		if (hfsmp->hfs_flags & HFS_CASE_SENSITIVE)
			cache_purge_negatives(tdvp);

		/* Update the target directory and volume stats */
		tdcp->c_nlink++;
		tdcp->c_entries++;
		tdcp->c_touch_chgtime = TRUE;
		tdcp->c_touch_modtime = TRUE;
		tdcp->c_flag |= C_FORCEUPDATE;

		error = hfs_update(tdvp, 0);
		if (error) {
		    panic("hfs_vnop_link: error updating tdvp 0x%x\n", tdvp);
		}

		hfs_volupdate(hfsmp, VOL_MKFILE,
			(tdcp->c_cnid == kHFSRootFolderID));
	}

	cp->c_flag |= C_FORCEUPDATE;    // otherwise hfs_update() might skip the update

	if ((ret = hfs_update(vp, TRUE)) != 0) {
	    panic("hfs_vnop_link: error %d updating vp @ 0x%x\n", ret, vp);
	}

	hfs_end_transaction(hfsmp);
	
	HFS_KNOTE(vp, NOTE_LINK);
	HFS_KNOTE(tdvp, NOTE_WRITE);
out:
	hfs_unlockpair(tdcp, cp);
	return (error);
}
