/*
 * Copyright (c) 1999-2003 Apple Computer, Inc. All rights reserved.
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


#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <vfs/vfs_support.h>
#include <libkern/libkern.h>

#include "hfs.h"
#include "hfs_catalog.h"
#include "hfs_format.h"
#include "hfs_endian.h"


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

	hfs_global_shared_lock_acquire(hfsmp);
	if (hfsmp->jnl) {
	    if (journal_start_transaction(hfsmp->jnl) != 0) {
			hfs_global_shared_lock_release(hfsmp);
			return EINVAL;
	    }
	}

	/* Create the indirect link directly in the catalog */
	result = cat_create(hfsmp, &desc, &attr, NULL);

	if (result == 0 && linkcnid != NULL)
		*linkcnid = attr.ca_fileid;

	if (hfsmp->jnl) {
	    journal_end_transaction(hfsmp->jnl);
	}
	hfs_global_shared_lock_release(hfsmp);

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
	struct proc *p = cnp->cn_proc;
	u_int32_t indnodeno = 0;
	char inodename[32];
	struct cat_desc to_desc;
	int newlink = 0;
	int retval;
	cat_cookie_t cookie = {0};


	/* We don't allow link nodes in our Private Meta Data folder! */
	if (dcp->c_fileid == hfsmp->hfs_privdir_desc.cd_cnid)
		return (EPERM);

	if (hfs_freeblks(hfsmp, 0) == 0)
		return (ENOSPC);

	/* Reserve some space in the Catalog file. */
	if ((retval = cat_preflight(hfsmp, (2 * CAT_CREATE)+ CAT_RENAME, &cookie, p))) {
		return (retval);
	}

	/* Lock catalog b-tree */
	retval = hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_EXCLUSIVE, p);
	if (retval) {
	   goto out2;
	}

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
			indnodeno = ((random() & 0x3fffffff) + 100);
			MAKE_INODE_NAME(inodename, indnodeno);

			/* move source file to data node directory */
			to_desc.cd_nameptr = inodename;
			to_desc.cd_namelen = strlen(inodename);
		
			retval = cat_rename(hfsmp, &cp->c_desc, &hfsmp->hfs_privdir_desc,
					&to_desc, NULL);

		} while (retval == EEXIST);
		if (retval)
			goto out;

		/* Replace source file with link node */
		retval = createindirectlink(hfsmp, indnodeno, cp->c_parentcnid,
				cp->c_desc.cd_nameptr, &cp->c_desc.cd_cnid);
		if (retval) {
			/* put it source file back */
		// XXXdbg
		#if 1
		    {
		    	int err;
				err = cat_rename(hfsmp, &to_desc, &dcp->c_desc, &cp->c_desc, NULL);
				if (err)
					panic("hfs_makelink: error %d from cat_rename backout 1", err);
		    }
		#else
			(void) cat_rename(hfsmp, &to_desc, &dcp->c_desc, &cp->c_desc, NULL);
		#endif
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
		/* Get rid of new link */
		(void) cat_delete(hfsmp, &cp->c_desc, &cp->c_attr);

		/* Put the source file back */
	// XXXdbg
	#if 1
		{
			int err;
			err = cat_rename(hfsmp, &to_desc, &dcp->c_desc, &cp->c_desc, NULL);
			if (err)
				panic("hfs_makelink: error %d from cat_rename backout 2", err);
		}
	#else
		(void) cat_rename(hfsmp, &to_desc, &dcp->c_desc, &cp->c_desc, NULL);
	#endif
		goto out;
	}

	/*
	 * Finally, if this is a new hardlink then:
	 *  - update HFS Private Data dir
	 *  - mark the cnode as a hard link
	 */
	if (newlink) {
		hfsmp->hfs_privdir_attr.ca_entries++;
		(void)cat_update(hfsmp, &hfsmp->hfs_privdir_desc,
			&hfsmp->hfs_privdir_attr, NULL, NULL);
		hfs_volupdate(hfsmp, VOL_MKFILE, 0);
		cp->c_flag |= (C_CHANGE | C_HARDLINK);
	}

out:
	/* Unlock catalog b-tree */
	(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, p);
out2:
	cat_postflight(hfsmp, &cookie, p);
	return (retval);
}


/*
 * link vnode call
#% link		vp	U U U
#% link		tdvp	L U U
#
 vop_link {
     IN WILLRELE struct vnode *vp;
     IN struct vnode *targetPar_vp;
     IN struct componentname *cnp;

     */
__private_extern__
int
hfs_link(ap)
	struct vop_link_args /* {
		struct vnode *a_vp;
		struct vnode *a_tdvp;
		struct componentname *a_cnp;
	} */ *ap;
{
	struct hfsmount *hfsmp;
	struct vnode *vp = ap->a_vp;
	struct vnode *tdvp = ap->a_tdvp;
	struct componentname *cnp = ap->a_cnp;
	struct proc *p = cnp->cn_proc;
	struct cnode *cp;
	struct cnode *tdcp;
	struct timeval tv;
	int error;

	hfsmp = VTOHFS(vp);
	
#if HFS_DIAGNOSTIC
	if ((cnp->cn_flags & HASBUF) == 0)
		panic("hfs_link: no name");
#endif
	if (tdvp->v_mount != vp->v_mount) {
		VOP_ABORTOP(tdvp, cnp);
		error = EXDEV;
		goto out2;
	}
	if (VTOVCB(tdvp)->vcbSigWord != kHFSPlusSigWord)
		return err_link(ap);	/* hfs disks don't support hard links */
	
	if (hfsmp->hfs_privdir_desc.cd_cnid == 0)
		return err_link(ap);	/* no private metadata dir, no links possible */

	if (tdvp != vp && (error = vn_lock(vp, LK_EXCLUSIVE, p))) {
		VOP_ABORTOP(tdvp, cnp);
		goto out2;
	}
	cp = VTOC(vp);
	tdcp = VTOC(tdvp);

	if (cp->c_nlink >= HFS_LINK_MAX) {
		VOP_ABORTOP(tdvp, cnp);
		error = EMLINK;
		goto out1;
	}
	if (cp->c_flags & (IMMUTABLE | APPEND)) {
		VOP_ABORTOP(tdvp, cnp);
		error = EPERM;
		goto out1;
	}
	if (vp->v_type == VBLK || vp->v_type == VCHR) {
		VOP_ABORTOP(tdvp, cnp);
		error = EINVAL;  /* cannot link to a special file */
		goto out1;
	}

	hfs_global_shared_lock_acquire(hfsmp);
	if (hfsmp->jnl) {
	    if (journal_start_transaction(hfsmp->jnl) != 0) {
			hfs_global_shared_lock_release(hfsmp);
			VOP_ABORTOP(tdvp, cnp);
			error = EINVAL;  /* cannot link to a special file */
			goto out1;
	    }
	}

	cp->c_nlink++;
	cp->c_flag |= C_CHANGE;
	tv = time;

	error = VOP_UPDATE(vp, &tv, &tv, 1);
	if (!error) {
		error = hfs_makelink(hfsmp, cp, tdcp, cnp);
	}
	if (error) {
		cp->c_nlink--;
		cp->c_flag |= C_CHANGE;
	} else {
		/* Update the target directory and volume stats */
		tdcp->c_nlink++;
		tdcp->c_entries++;
		tdcp->c_flag |= C_CHANGE | C_UPDATE;
		tv = time;
		(void) VOP_UPDATE(tdvp, &tv, &tv, 0);

		hfs_volupdate(hfsmp, VOL_MKFILE,
			(tdcp->c_cnid == kHFSRootFolderID));
	}

	// XXXdbg - need to do this here as well because cp could have changed
	(void) VOP_UPDATE(vp, &tv, &tv, 1);


	if (hfsmp->jnl) {
	    journal_end_transaction(hfsmp->jnl);
	}
	hfs_global_shared_lock_release(hfsmp);

	/* free the pathname buffer */
	{
		char *tmp = cnp->cn_pnbuf;
		cnp->cn_pnbuf = NULL;
		cnp->cn_flags &= ~HASBUF;
		FREE_ZONE(tmp, cnp->cn_pnlen, M_NAMEI);
	}
	
	HFS_KNOTE(vp, NOTE_LINK);
	HFS_KNOTE(tdvp, NOTE_WRITE);

out1:
	if (tdvp != vp)
		VOP_UNLOCK(vp, 0, p);
out2:
	vput(tdvp);
	return (error);
}
