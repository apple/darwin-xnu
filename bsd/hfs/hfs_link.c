/*
 * Copyright (c) 1999-2000 Apple Computer, Inc. All rights reserved.
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

#if HFS_HARDLINKS

#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/namei.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <vfs/vfs_support.h>
#include <libkern/libkern.h>

#include "hfs.h"
#include "hfscommon/headers/FileMgrInternal.h"


/*
 * Create a new indirect link
 *
 * An indirect link is a reference to a data node.  The only useable fields in the
 * link are the parentID, name and text encoding.  All other catalog fields
 * are ignored.
 */
static int
createindirectlink(struct hfsnode *dnhp, UInt32 linkPID, char *linkName)
{
	struct hfsCatalogInfo catInfo;
	struct FInfo *fip;
	ExtendedVCB *vcb;
	int result;

	vcb = HTOVCB(dnhp);

	/* Create the indirect link directly in the catalog */
	result = hfsCreate(vcb, linkPID, linkName, IFREG);
	if (result) return (result);

	/* 
	 * XXX SER Here is a good example where hfsCreate should pass in a catinfo and return
	 * things like the hint and file ID there should be no reason to call lookup here 
	 */
	catInfo.hint = 0;
	INIT_CATALOGDATA(&catInfo.nodeData, kCatNameNoCopyName);

	result = hfs_getcatalog(vcb, linkPID, linkName, -1, &catInfo);
	if (result) goto errExit;

	fip = (struct FInfo *)&catInfo.nodeData.cnd_finderInfo;
	fip->fdType = kHardLinkFileType;	/* 'hlnk' */
	fip->fdCreator = kHFSPlusCreator;	/* 'hfs+' */
	fip->fdFlags |= kHasBeenInited;

	/* links are matched to data nodes by nodeID and to volumes by create date */
	catInfo.nodeData.cnd_iNodeNum = dnhp->h_meta->h_indnodeno;
	catInfo.nodeData.cnd_createDate = vcb->vcbCrDate;

	result = UpdateCatalogNode(vcb, linkPID, linkName, catInfo.hint, &catInfo.nodeData);
	if (result) goto errExit;

	CLEAN_CATALOGDATA(&catInfo.nodeData);
	return (0);

errExit:
	CLEAN_CATALOGDATA(&catInfo.nodeData);

	/* get rid of link node */
	(void) hfsDelete(vcb, linkPID, linkName, TRUE, 0);

	return (result);
}


/*
 * 2 locks are needed (dvp and hp)
 * also need catalog lock
 *
 * caller's responsibility:
 *		componentname cleanup
 *		unlocking dvp and hp
 */
static int
hfs_makelink(hp, dvp, cnp)
	struct hfsnode *hp;
	struct vnode *dvp;
	register struct componentname *cnp;
{
	struct proc *p = cnp->cn_proc;
	struct hfsnode *dhp = VTOH(dvp);
	u_int32_t ldirID;	/* directory ID of linked nodes directory */
	ExtendedVCB *vcb = VTOVCB(dvp);
	u_int32_t hint;
	u_int32_t indnodeno = 0;
	char inodename[32];
	int retval;

	ldirID = VTOHFS(dvp)->hfs_private_metadata_dir;

	/* We don't allow link nodes in our Private Meta Data folder! */
	if ( H_FILEID(dhp) == ldirID)
		return (EPERM);

	if (vcb->freeBlocks == 0)
		return (ENOSPC);

	/* lock catalog b-tree */
	retval = hfs_metafilelocking(VTOHFS(dvp), kHFSCatalogFileID, LK_EXCLUSIVE, p);
	if (retval != E_NONE)
		return retval;

	/*
	 * If this is a new hardlink then we need to create the data
	 * node (inode) and replace the original file with a link node.
	 */
	if (hp->h_meta->h_nlink == 1) {
		do {
			/* get a unique indirect node number */
			indnodeno = ((random() & 0x3fffffff) + 100);
			MAKE_INODE_NAME(inodename, indnodeno);

			/* move source file to data node directory */
			hint = 0;
			retval = hfsMoveRename(vcb, H_DIRID(hp), H_NAME(hp), ldirID, inodename, &hint);
		} while (retval == cmExists);

		if (retval) goto out;

		hp->h_meta->h_indnodeno = indnodeno;
		
		/* replace source file with link node */
		retval = createindirectlink(hp, H_DIRID(hp), H_NAME(hp));
		if (retval) {
			/* put it source file back */
			hint = 0;
			(void) hfsMoveRename(vcb, ldirID, inodename, H_DIRID(hp), H_NAME(hp), &hint);
			goto out;
		}
  	}

	/*
	 * Create a catalog entry for the new link (parentID + name).
	 */
	retval = createindirectlink(hp, H_FILEID(dhp), cnp->cn_nameptr);
	if (retval && hp->h_meta->h_nlink == 1) {
		/* get rid of new link */
		(void) hfsDelete(vcb, H_DIRID(hp), H_NAME(hp), TRUE, 0);

		/* put it source file back */
		hint = 0;
		(void) hfsMoveRename(vcb, ldirID, inodename, H_DIRID(hp), H_NAME(hp), &hint);
		goto out;
	}

	/*
	 * Finally, if this is a new hardlink then we need to mark the hfs node
	 */
	if (hp->h_meta->h_nlink == 1) {
		hp->h_meta->h_nlink++;
		hp->h_nodeflags |= IN_CHANGE;
		hp->h_meta->h_metaflags |= IN_DATANODE;
	}

out:
	/* unlock catalog b-tree */
	(void) hfs_metafilelocking(VTOHFS(dvp), kHFSCatalogFileID, LK_RELEASE, p);

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
int
hfs_link(ap)
struct vop_link_args /* {
	struct vnode *a_vp;
	struct vnode *a_tdvp;
	struct componentname *a_cnp;
} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct vnode *tdvp = ap->a_tdvp;
	struct componentname *cnp = ap->a_cnp;
	struct proc *p = cnp->cn_proc;
	struct hfsnode *hp;
	struct timeval tv;
	int error;

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
	
	if (VTOHFS(vp)->hfs_private_metadata_dir == 0)
		return err_link(ap);	/* no private metadata dir, no links possible */

	if (tdvp != vp && (error = vn_lock(vp, LK_EXCLUSIVE, p))) {
		VOP_ABORTOP(tdvp, cnp);
		goto out2;
	}
	hp = VTOH(vp);
	if (hp->h_meta->h_nlink >= HFS_LINK_MAX) {
		VOP_ABORTOP(tdvp, cnp);
		error = EMLINK;
		goto out1;
	}
	if (hp->h_meta->h_pflags & (IMMUTABLE | APPEND)) {
		VOP_ABORTOP(tdvp, cnp);
		error = EPERM;
		goto out1;
	}
	if (vp->v_type == VBLK || vp->v_type == VCHR) {
		VOP_ABORTOP(tdvp, cnp);
		error = EINVAL;  /* cannot link to a special file */
		goto out1;
	}

	hp->h_meta->h_nlink++;
	hp->h_nodeflags |= IN_CHANGE;
	tv = time;
	error = VOP_UPDATE(vp, &tv, &tv, 1);
	if (!error)
		error = hfs_makelink(hp, tdvp, cnp);
	if (error) {
		hp->h_meta->h_nlink--;
		hp->h_nodeflags |= IN_CHANGE;
	}
	FREE_ZONE(cnp->cn_pnbuf, cnp->cn_pnlen, M_NAMEI);
out1:
	if (tdvp != vp)
		VOP_UNLOCK(vp, 0, p);
out2:
	vput(tdvp);
	return (error);
}

#endif
