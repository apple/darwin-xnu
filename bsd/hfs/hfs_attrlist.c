/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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

/*
 * hfs_attrlist.c - HFS attribute list processing
 *
 * Copyright (c) 1998-2002, Apple Computer, Inc.  All Rights Reserved.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <sys/unistd.h>

#include "hfs.h"
#include "hfs_cnode.h"
#include "hfs_mount.h"
#include "hfs_dbg.h"
#include "hfs_attrlist.h"



extern uid_t console_user;


/* Routines that are shared by hfs_setattr: */
extern int hfs_write_access(struct vnode *vp, struct ucred *cred,
			struct proc *p, Boolean considerFlags);

extern int hfs_chflags(struct vnode *vp, u_long flags, struct ucred *cred,
			struct proc *p);

extern int hfs_chmod(struct vnode *vp, int mode, struct ucred *cred,
			struct proc *p);

extern int hfs_chown(struct vnode *vp, uid_t uid, gid_t gid, struct ucred *cred,
			struct proc *p);

extern char * hfs_getnamehint(struct cnode *dcp, int index);

extern void   hfs_savenamehint(struct cnode *dcp, int index, const char * namehint);

extern void   hfs_relnamehint(struct cnode *dcp, int index);

/* Packing routines: */


static void packvolcommonattr(struct attrblock *abp, struct hfsmount *hfsmp,
			struct vnode *vp);

static void packvolattr(struct attrblock *abp, struct hfsmount *hfsmp,
			struct vnode *vp);

static void packcommonattr(struct attrblock *abp, struct hfsmount *hfsmp,
			struct vnode *vp, struct cat_desc * cdp,
			struct cat_attr * cap);

static void packfileattr(struct attrblock *abp, struct hfsmount *hfsmp,
			struct cat_attr *cattrp, struct cat_fork *datafork,
			struct cat_fork *rsrcfork);

static void packdirattr(struct attrblock *abp, struct hfsmount *hfsmp,
			struct vnode *vp, struct cat_desc * descp,
			struct cat_attr * cattrp);

static void unpackattrblk(struct attrblock *abp, struct vnode *vp);

static void unpackcommonattr(struct attrblock *abp, struct vnode *vp);

static void unpackvolattr(struct attrblock *abp, struct hfsmount *hfsmp,
			struct vnode *rootvp);


/*

#
#% getattrlist	vp	= = =
#
 vop_getattrlist {
     IN struct vnode *vp;
     IN struct attrlist *alist;
     INOUT struct uio *uio;
     IN struct ucred *cred;
     IN struct proc *p;
 };

 */
__private_extern__
int
hfs_getattrlist(ap)
	struct vop_getattrlist_args /* {
		struct vnode *a_vp;
		struct attrlist *a_alist
		struct uio *a_uio;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct cnode *cp = VTOC(vp);
	struct hfsmount *hfsmp = VTOHFS(vp);
	struct attrlist *alist = ap->a_alist;
	struct timeval tv;
	int fixedblocksize;
	int attrblocksize;
	int attrbufsize;
	void *attrbufptr;
	void *attrptr;
	void *varptr;
	struct attrblock attrblk;
	struct cat_fork *datafp = NULL;
	struct cat_fork *rsrcfp = NULL;
	struct cat_fork rsrcfork = {0};
	int error = 0;

	if ((alist->bitmapcount != ATTR_BIT_MAP_COUNT) ||
	    ((alist->commonattr & ~ATTR_CMN_VALIDMASK) != 0) ||
	    ((alist->volattr & ~ATTR_VOL_VALIDMASK) != 0) ||
	    ((alist->dirattr & ~ATTR_DIR_VALIDMASK) != 0) ||
	    ((alist->fileattr & ~ATTR_FILE_VALIDMASK) != 0)) {
		return (EINVAL);
	}

	/*
	 * Requesting volume information requires setting the
	 * ATTR_VOL_INFO bit. Also, volume info requests are
	 * mutually exclusive with all other info requests.
	 */
	if ((alist->volattr != 0) &&
	    (((alist->volattr & ATTR_VOL_INFO) == 0) ||
	     (alist->dirattr != 0) || (alist->fileattr != 0))) {
		return (EINVAL);
	}

	/* Reject requests for unsupported options for now: */
	if ((alist->commonattr & (ATTR_CMN_NAMEDATTRCOUNT | ATTR_CMN_NAMEDATTRLIST)) ||
	    (alist->fileattr & (ATTR_FILE_FILETYPE | ATTR_FILE_FORKCOUNT | ATTR_FILE_FORKLIST))) {
		return (EINVAL);
	}

	/* Requesting volume information requires root vnode */ 
	if ((alist->volattr) && cp->c_fileid != kRootDirID)
		return (EINVAL);

	/* Asking for data fork attributes from the rsrc fork is not supported */
	if (VNODE_IS_RSRC(vp) && (alist->fileattr & ATTR_DATAFORK_MASK))
		return (EINVAL);

	/* This file no longer exists! */
	if (cp->c_flag & (C_NOEXISTS | C_DELETED))
		return (ENOENT);

	/* This file doesn't have a name! */
	if ((cp->c_desc.cd_namelen == 0) && (alist->commonattr & ATTR_CMN_NAME))
		return (ENOENT);

	/* Update cnode times if needed */
	tv = time;
	CTIMES(cp, &tv, &tv);

	/*
	 * If a File ID (ATTR_CMN_OBJPERMANENTID) is requested on
	 * an HFS volume we must be sure to create the thread
	 * record before returning it. (yikes)
	 */
	if ((vp->v_type == VREG) &&
	    (alist->commonattr & ATTR_CMN_OBJPERMANENTID) &&
	    (VTOVCB(vp)->vcbSigWord != kHFSPlusSigWord)) {

		if (VTOVFS(vp)->mnt_flag & MNT_RDONLY)
			return (EROFS);
		if ((error = hfs_write_access(vp, ap->a_cred, ap->a_p, false)) != 0)
        		return (error);

		/* Lock catalog b-tree */
		error = hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_SHARED, ap->a_p);
		if (error)
			return (error);

		error = cat_insertfilethread(hfsmp, &cp->c_desc);

		/* Unlock catalog b-tree */
		(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, ap->a_p);
		if (error)
			return (error);
	}

	/* Establish known fork data */
	if (cp->c_datafork != NULL) {
		datafp = &cp->c_datafork->ff_data;
		if ((cp->c_rsrcfork == NULL) &&
		    (cp->c_blocks == datafp->cf_blocks))
			rsrcfp = &rsrcfork;	/* rsrc fork is empty */
	}
	if (cp->c_rsrcfork != NULL)
		rsrcfp = &cp->c_rsrcfork->ff_data;
	
	/*
	 * When resource fork data is requested and its not available
	 * in the cnode and the fork is not empty then it needs to be
	 * fetched from the catalog.
	 */
	if ((alist->fileattr & ATTR_RSRCFORK_MASK) && (rsrcfp == NULL)) {
		/* Lock catalog b-tree */
		error = hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_SHARED, ap->a_p);
		if (error)
			return (error);

		/* Get resource fork data */
		error = cat_lookup(hfsmp, &cp->c_desc, 1,
				(struct cat_desc *)0, (struct cat_attr *)0, &rsrcfork);

		/* Unlock the Catalog */
		(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, ap->a_p);
		if (error)
			return (error);

		rsrcfp = &rsrcfork;
	}

	fixedblocksize = hfs_attrblksize(alist);
	attrblocksize = fixedblocksize + (sizeof(u_long));  /* u_long for length longword */
	if (alist->commonattr & ATTR_CMN_NAME)
		attrblocksize += kHFSPlusMaxFileNameBytes + 1;
	if (alist->volattr & ATTR_VOL_MOUNTPOINT)
		attrblocksize += PATH_MAX;
	if (alist->volattr & ATTR_VOL_NAME)
		attrblocksize += kHFSPlusMaxFileNameBytes + 1;
#if 0
	if (alist->commonattr & ATTR_CMN_NAMEDATTRLIST)
		attrblocksize += 0;
	if (alist->fileattr & ATTR_FILE_FORKLIST)
		attrblocksize += 0;
#endif
	attrbufsize = MIN(ap->a_uio->uio_resid, attrblocksize);
	MALLOC(attrbufptr, void *, attrblocksize, M_TEMP, M_WAITOK);
	attrptr = attrbufptr;
	*((u_long *)attrptr) = 0;  /* Set buffer length in case of errors */
	++((u_long *)attrptr);     /* Reserve space for length field */
	varptr = ((char *)attrptr) + fixedblocksize;

	attrblk.ab_attrlist = alist;
	attrblk.ab_attrbufpp = &attrptr;
	attrblk.ab_varbufpp = &varptr;
	attrblk.ab_flags = 0;
	attrblk.ab_blocksize = attrblocksize;

	hfs_packattrblk(&attrblk, hfsmp, vp, &cp->c_desc, &cp->c_attr,
			datafp, rsrcfp);

	/* Don't copy out more data than was generated */
	attrbufsize = MIN(attrbufsize, (u_int)varptr - (u_int)attrbufptr);
	 /* Set actual buffer length for return to caller */
	*((u_long *)attrbufptr) = attrbufsize;
	error = uiomove((caddr_t)attrbufptr, attrbufsize, ap->a_uio);

	FREE(attrbufptr, M_TEMP);
	return (error);
}


/*

#
#% setattrlist	vp	L L L
#
 vop_setattrlist {
     IN struct vnode *vp;
     IN struct attrlist *alist;
     INOUT struct uio *uio;
     IN struct ucred *cred;
     IN struct proc *p;
 };

 */
__private_extern__
int
hfs_setattrlist(ap)
	struct vop_setattrlist_args /* {
		struct vnode *a_vp;
		struct attrlist *a_alist
		struct uio *a_uio;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct cnode *cp = VTOC(vp);
	struct hfsmount * hfsmp = VTOHFS(vp);
	struct attrlist *alist = ap->a_alist;
	struct ucred *cred = ap->a_cred;
	struct proc *p = ap->a_p;
	int attrblocksize;
	void *attrbufptr = NULL;
	void *attrptr;
	void *varptr = NULL;
	struct attrblock attrblk;
	uid_t saved_uid;
	gid_t saved_gid;
	mode_t saved_mode;
	u_long saved_flags;
	int error = 0;

	if (VTOVFS(vp)->mnt_flag & MNT_RDONLY)
		return (EROFS);
	if ((alist->bitmapcount != ATTR_BIT_MAP_COUNT)     ||
	    ((alist->commonattr & ~ATTR_CMN_SETMASK) != 0) ||
	    ((alist->volattr & ~ATTR_VOL_SETMASK) != 0)    ||
	    ((alist->dirattr & ~ATTR_DIR_SETMASK) != 0)    ||
	    ((alist->fileattr & ~ATTR_FILE_SETMASK) != 0)) {
		return (EINVAL);
	}
	/* 
	 * When setting volume attributes make sure
	 * that ATTR_VOL_INFO is set and that all
	 * the attributes are valid.
	 */
	if ((alist->volattr != 0) &&
	    (((alist->volattr & ATTR_VOL_INFO) == 0) ||
	    (alist->commonattr & ~ATTR_CMN_VOLSETMASK) ||
	    (cp->c_fileid != kRootDirID))) {
	    	if ((alist->volattr & ATTR_VOL_INFO) == 0)
			printf("hfs_setattrlist: you forgot to set ATTR_VOL_INFO bit!\n");
		else
			printf("hfs_setattrlist: you cannot set bits 0x%08X!\n",
				alist->commonattr & ~ATTR_CMN_VOLSETMASK);
		return (EINVAL);
	}
	if (cp->c_flag & (C_NOEXISTS | C_DELETED))
		return (ENOENT);
	/*
	 * Ownership of a file is required in one of two classes of calls:
	 *
	 * (a) When setting any ownership-requiring attribute other
	 *     than ATTR_CMN_FLAGS, or
	 * (b) When setting ATTR_CMN_FLAGS on a volume that's not
	 *     plain HFS (for which no real per-object ownership
	 *     information is stored)
	 */
	if ((alist->commonattr & (ATTR_OWNERSHIP_SETMASK & ~ATTR_CMN_FLAGS)) ||
	    ((alist->commonattr & ATTR_CMN_FLAGS) &&
	     (VTOVCB(vp)->vcbSigWord != kHFSSigWord))) {
		/*
		 * NOTE: The following isn't ENTIRELY complete: even if
		 * you're the superuser you cannot change the flags as
		 * long as SF_IMMUTABLE or SF_APPEND is set and the
		 * securelevel > 0.  This is verified in hfs_chflags
		 * which gets invoked to do the actual flags field
		 * change so this check is sufficient for now.
		 */
		if ((error = hfs_owner_rights(hfsmp, cp->c_uid, cred, p, true)) != 0)
        		return (error);
	}
	/*
	 * For any other attributes, check to see if the user has
	 * write access to the cnode in question [unlike VOP_ACCESS,
	 * ignore IMMUTABLE here]:
	 */ 
	if (((alist->commonattr & ~ATTR_OWNERSHIP_SETMASK) != 0) ||
	    (alist->volattr != 0) || (alist->dirattr != 0) ||
	    (alist->fileattr != 0)) {
		if ((error = hfs_write_access(vp, cred, p, false)) != 0)
        		return (error);
	}

	/*
	 * Allocate the buffer now to minimize the time we might
	 * be blocked holding the catalog lock.
	 */
	attrblocksize = ap->a_uio->uio_resid;
	if (attrblocksize < hfs_attrblksize(alist))
		return (EINVAL);

	MALLOC(attrbufptr, void *, attrblocksize, M_TEMP, M_WAITOK);

	error = uiomove((caddr_t)attrbufptr, attrblocksize, ap->a_uio);
	if (error)
		goto ErrorExit;

	/* Save original state so changes can be detected. */
	saved_uid = cp->c_uid;
	saved_gid = cp->c_gid;
	saved_mode = cp->c_mode;
	saved_flags = cp->c_flags;

	attrptr = attrbufptr;
	attrblk.ab_attrlist = alist;
	attrblk.ab_attrbufpp = &attrptr;
	attrblk.ab_varbufpp = &varptr;
	attrblk.ab_flags = 0;
	attrblk.ab_blocksize = attrblocksize;
	unpackattrblk(&attrblk, vp);

	/* If unpacking changed the owner/group then call hfs_chown() */
	if ((saved_uid != cp->c_uid) || (saved_gid != cp->c_gid)) {
		uid_t uid;
		gid_t gid;
		
		uid = cp->c_uid;
 		cp->c_uid = saved_uid;
		gid = cp->c_gid;
		cp->c_gid = saved_gid;
		if ((error = hfs_chown(vp, uid, gid, cred, p)))
			goto ErrorExit;
	}
	/* If unpacking changed the mode then call hfs_chmod() */
	if (saved_mode != cp->c_mode) {
		mode_t mode;

		mode = cp->c_mode;
		cp->c_mode = saved_mode;
		if ((error = hfs_chmod(vp, mode, cred, p)))
			goto ErrorExit;
	}
	/* If unpacking changed the flags then call hfs_chflags() */
	if (saved_flags !=cp->c_flags) {
		u_long flags;

		flags = cp->c_flags;
		cp->c_flags = saved_flags;
		if ((error = hfs_chflags(vp, flags, cred, p)))
			goto ErrorExit;
	}
	/*
	 * If any cnode attributes changed then do an update.
	 */
	if (alist->volattr == 0) {
		struct timeval atime, mtime;

		atime.tv_sec = cp->c_atime;
		atime.tv_usec = 0;
		mtime.tv_sec = cp->c_mtime;
		mtime.tv_usec = cp->c_mtime_nsec / 1000;
		cp->c_flag |= C_MODIFIED;
		if ((error = VOP_UPDATE(vp, &atime, &mtime, 1)))
			goto ErrorExit;
	}
	/* Volume Rename */
	if (alist->volattr & ATTR_VOL_NAME) {
		ExtendedVCB *vcb = VTOVCB(vp);
	
		if (vcb->vcbVN[0] == 0) {
			/*
			 * Ignore attempts to rename a volume to a zero-length name:
			 * restore the original name from the cnode.
			 */
			copystr(cp->c_desc.cd_nameptr, vcb->vcbVN, sizeof(vcb->vcbVN), NULL);
		} else {
			struct cat_desc to_desc = {0};
			struct cat_desc todir_desc = {0};
			struct cat_desc new_desc = {0};

			todir_desc.cd_parentcnid = kRootParID;
			todir_desc.cd_cnid = kRootParID;
			todir_desc.cd_flags = CD_ISDIR;

			to_desc.cd_nameptr = vcb->vcbVN;
			to_desc.cd_namelen = strlen(vcb->vcbVN);
			to_desc.cd_parentcnid = kRootParID;
			to_desc.cd_cnid = cp->c_cnid;
			to_desc.cd_flags = CD_ISDIR;

			/* Lock catalog b-tree */
			error = hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_EXCLUSIVE, p);
			if (error) {
				/* Restore the old name in the VCB */
				copystr(cp->c_desc.cd_nameptr, vcb->vcbVN, sizeof(vcb->vcbVN), NULL);
				vcb->vcbFlags |= 0xFF00;
				goto ErrorExit;
			}

			error = cat_rename(hfsmp, &cp->c_desc, &todir_desc, &to_desc, &new_desc);

			/* Unlock the Catalog */
			(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, p);

			if (error) {
				/* Restore the old name in the VCB */
				copystr(cp->c_desc.cd_nameptr, vcb->vcbVN, sizeof(vcb->vcbVN), NULL);
				vcb->vcbFlags |= 0xFF00;
				goto ErrorExit;
			}
			/* Release old allocated name buffer */
			if (cp->c_desc.cd_flags & CD_HASBUF) {
				char *name = cp->c_desc.cd_nameptr;
		
				cp->c_desc.cd_nameptr = 0;
				cp->c_desc.cd_namelen = 0;
				cp->c_desc.cd_flags &= ~CD_HASBUF;
				FREE(name, M_TEMP);
			}			
			/* Update cnode's catalog descriptor */
			replace_desc(cp, &new_desc);
			vcb->volumeNameEncodingHint = new_desc.cd_encoding;
			cp->c_flag |= C_CHANGE;
		}
	}

	/*
	 * When the volume name changes or the volume's finder info
	 * changes then force them to disk immediately.
	 */
	if ((alist->volattr & ATTR_VOL_INFO) &&
	    ((alist->volattr & ATTR_VOL_NAME) ||
	     (alist->commonattr & ATTR_CMN_FNDRINFO))) {
		(void) hfs_flushvolumeheader(hfsmp, MNT_WAIT, 0);
	}
ErrorExit:
	if (attrbufptr)
		FREE(attrbufptr, M_TEMP);

	return (error);
}


/*
 * readdirattr operation will return attributes for the items in the
 * directory specified. 
 *
 * It does not do . and .. entries. The problem is if you are at the root of the
 * hfs directory and go to .. you could be crossing a mountpoint into a
 * different (ufs) file system. The attributes that apply for it may not 
 * apply for the file system you are doing the readdirattr on. To make life 
 * simpler, this call will only return entries in its directory, hfs like.
 * TO DO LATER: 
 * 1. more than one for uiovcnt support.
 * 2. put knohint (hints) in state for next call in
 * 3. credentials checking when rest of hfs does it.
 * 4. Do return permissions concatenation ???
 */

/* 			
#
#% readdirattr	vp	L L L
#
vop_readdirattr {
	IN struct vnode *vp;
	IN struct attrlist *alist;
	INOUT struct uio *uio;
	IN u_long maxcount:
	IN u_long options;
	OUT u_long *newstate;
	OUT int *eofflag;
	OUT u_long *actualCount;
	OUT u_long **cookies;
	IN struct ucred *cred;
};
*/
__private_extern__
int
hfs_readdirattr(ap)
	struct vop_readdirattr_args /* {
		struct vnode *a_vp;
		struct attrlist *a_alist;
		struct uio *a_uio;
		u_long a_maxcount;
		u_long a_options;
		u_long *a_newstate;
		int *a_eofflag;
		u_long *a_actualcount;
		u_long **a_cookies;
		struct ucred *a_cred;
	} */ *ap;
{
	struct vnode *dvp = ap->a_vp;
	struct cnode *dcp = VTOC(dvp);
	struct hfsmount * hfsmp = VTOHFS(dvp);
	struct attrlist *alist = ap->a_alist;
	struct uio *uio = ap->a_uio;
	int maxcount = ap->a_maxcount;
	struct proc *p = current_proc();
	u_long fixedblocksize;
	u_long maxattrblocksize;
	u_long currattrbufsize;
	void *attrbufptr = NULL;
	void *attrptr;
	void *varptr;
	struct attrblock attrblk;
	int error = 0;
	int depleted = 0;
	int index, startindex;
	int i;
	struct cat_desc *lastdescp = NULL;
	struct cat_desc prevdesc;
	char * prevnamebuf = NULL;
	struct cat_entrylist *ce_list = NULL;

	*(ap->a_actualcount) = 0;
	*(ap->a_eofflag) = 0;
	
	if (ap->a_cookies != NULL) {
		printf("readdirattr: no cookies!\n");
		return (EINVAL);
	}

	/* Check for invalid options and buffer space. */
	if (((ap->a_options & ~(FSOPT_NOINMEMUPDATE | FSOPT_NOFOLLOW)) != 0)
	||  (uio->uio_resid <= 0) || (uio->uio_iovcnt > 1) || (maxcount <= 0))
		return (EINVAL);

	/* This call doesn't take volume attributes. */
	if ((alist->bitmapcount != ATTR_BIT_MAP_COUNT) ||
	    ((alist->commonattr & ~ATTR_CMN_VALIDMASK) != 0) ||
	    (alist->volattr  != 0) ||
	    ((alist->dirattr & ~ATTR_DIR_VALIDMASK) != 0) ||
	    ((alist->fileattr & ~ATTR_FILE_VALIDMASK) != 0)) 
		return (EINVAL);

	/* Reject requests for unsupported options. */
	if ((alist->commonattr & (ATTR_CMN_NAMEDATTRCOUNT | ATTR_CMN_NAMEDATTRLIST |
	     ATTR_CMN_OBJPERMANENTID)) ||
	    (alist->fileattr & (ATTR_FILE_FILETYPE | ATTR_FILE_FORKCOUNT |
	     ATTR_FILE_FORKLIST | ATTR_FILE_DATAEXTENTS | ATTR_FILE_RSRCEXTENTS))) {
		printf("readdirattr: unsupported attributes! (%s)\n", dcp->c_desc.cd_nameptr);
		return (EINVAL);
	}

	/* Convert uio_offset into a directory index. */
	startindex = index = uio->uio_offset / sizeof(struct dirent);
	if ((index + 1) > dcp->c_entries) {
		*(ap->a_eofflag) = 1;
		error = 0;
		goto exit;
	}

	/* Get a buffer to hold packed attributes. */
	fixedblocksize = (sizeof(u_long) + hfs_attrblksize(alist)); /* u_long for length */
	maxattrblocksize = fixedblocksize;
	if (alist->commonattr & ATTR_CMN_NAME) 
		maxattrblocksize += kHFSPlusMaxFileNameBytes + 1;
	MALLOC(attrbufptr, void *, maxattrblocksize, M_TEMP, M_WAITOK);
	attrptr = attrbufptr;
	varptr = (char *)attrbufptr + fixedblocksize;  /* Point to variable-length storage */

	/* Initialize a catalog entry list. */
	MALLOC(ce_list, struct cat_entrylist *, sizeof(*ce_list), M_TEMP, M_WAITOK);
	bzero(ce_list, sizeof(*ce_list));
	ce_list->maxentries = MAXCATENTRIES;

	/* Initialize a starting descriptor. */
	bzero(&prevdesc, sizeof(prevdesc));
	prevdesc.cd_flags = CD_DECOMPOSED;
	prevdesc.cd_hint = dcp->c_childhint;
	prevdesc.cd_parentcnid = dcp->c_cnid;
	prevdesc.cd_nameptr = hfs_getnamehint(dcp, index);
	prevdesc.cd_namelen = prevdesc.cd_nameptr ? strlen(prevdesc.cd_nameptr) : 0;
	
	/*
	 * Obtain a list of catalog entries and pack their attributes until
	 * the output buffer is full or maxcount entries have been packed.
	 */
	while (!depleted) {
		int maxentries;

		/* Constrain our list size. */
		maxentries = uio->uio_resid / (fixedblocksize + HFS_AVERAGE_NAME_SIZE);
		maxentries = min(maxentries, dcp->c_entries - index);
		maxentries = min(maxentries, maxcount);
		ce_list->maxentries = min(maxentries, ce_list->maxentries);
		lastdescp = NULL;

		/* Lock catalog b-tree. */
		error = hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_SHARED, p);
		if (error)
			goto exit;
		 
		error = cat_getentriesattr(hfsmp, &prevdesc, index, ce_list);
		/* Don't forget to release the descriptors later! */

		/* Unlock catalog b-tree. */
 		(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, p);
 
		if (error == ENOENT) {
			*(ap->a_eofflag) = TRUE;
			error = 0;
			depleted = 1;
		}
		if (error)
			break;
 
		/* Process the catalog entries. */
		for (i = 0; i < ce_list->realentries; ++i) {
			struct cnode *cp = NULL;
			struct vnode *vp = NULL;
			struct vnode *rvp = NULL;
			struct cat_desc * cdescp;
			struct cat_attr * cattrp;
			struct cat_fork c_datafork = {0};
			struct cat_fork c_rsrcfork = {0};

			cdescp = &ce_list->entry[i].ce_desc;
			cattrp = &ce_list->entry[i].ce_attr;
			c_datafork.cf_size   = ce_list->entry[i].ce_datasize;
			c_datafork.cf_blocks = ce_list->entry[i].ce_datablks;
			c_rsrcfork.cf_size   = ce_list->entry[i].ce_rsrcsize;
			c_rsrcfork.cf_blocks = ce_list->entry[i].ce_rsrcblks;
			/*
			 * Get in memory cnode data (if any).
			 */
			if (!(ap->a_options & FSOPT_NOINMEMUPDATE)) {
				cp = hfs_chashget(dcp->c_dev, cattrp->ca_fileid, 0, &vp, &rvp);
				if (cp != NULL) {
					/* Only use cnode's decriptor for non-hardlinks */
					if (!(cp->c_flag & C_HARDLINK))
						cdescp = &cp->c_desc;
					cattrp = &cp->c_attr;
					if (cp->c_datafork) {
						c_datafork.cf_size   = cp->c_datafork->ff_data.cf_size;
						c_datafork.cf_clump  = cp->c_datafork->ff_data.cf_clump;
						c_datafork.cf_blocks = cp->c_datafork->ff_data.cf_blocks;
					}
					if (cp->c_rsrcfork) {
						c_rsrcfork.cf_size   = cp->c_rsrcfork->ff_data.cf_size;
						c_rsrcfork.cf_clump  = cp->c_rsrcfork->ff_data.cf_clump;
						c_rsrcfork.cf_blocks = cp->c_rsrcfork->ff_data.cf_blocks;
					}
				}
			}
			*((u_long *)attrptr)++ = 0; /* move it past length */
			attrblk.ab_attrlist = alist;
			attrblk.ab_attrbufpp = &attrptr;
			attrblk.ab_varbufpp = &varptr;
			attrblk.ab_flags = 0;
			attrblk.ab_blocksize = maxattrblocksize;

			/* Pack catalog entries into attribute buffer. */
			hfs_packattrblk(&attrblk, hfsmp, vp, cdescp, cattrp,
					&c_datafork, &c_rsrcfork);
			currattrbufsize = ((char *)varptr - (char *)attrbufptr);
		
			/* All done with cnode. */
			if (vp) {
				vput(vp);
				vp = NULL;
			} else if (rvp) {
				vput(rvp);
				rvp = NULL;
			}
			cp = NULL;

			/* Make sure there's enough buffer space remaining. */
			if (currattrbufsize > uio->uio_resid) {
				depleted = 1;
				break;
			} else {
				*((u_long *)attrbufptr) = currattrbufsize;
				error = uiomove((caddr_t)attrbufptr, currattrbufsize, ap->a_uio);
				if (error != E_NONE) {
					depleted = 1;
					break;
				}
				attrptr = attrbufptr;
				varptr = (char *)attrbufptr + fixedblocksize;  /* Point to variable-length storage */
				/* Save the last valid catalog entry */
				lastdescp = &ce_list->entry[i].ce_desc;
				index++;
				*ap->a_actualcount += 1;

				/* Termination checks */
				if ((--maxcount <= 0) ||
				    (uio->uio_resid < (fixedblocksize + HFS_AVERAGE_NAME_SIZE)) ||
				    (index >= dcp->c_entries)) {
					depleted = 1;
					break;
				}
			}
		} /* for each catalog entry */

		/* If there are more entries then save the last name. */
		if (index < dcp->c_entries
		&&  !(*(ap->a_eofflag))
		&&  lastdescp != NULL) {
			if (prevnamebuf == NULL)
				MALLOC(prevnamebuf, char *, kHFSPlusMaxFileNameBytes + 1, M_TEMP, M_WAITOK);
			bcopy(lastdescp->cd_nameptr, prevnamebuf, lastdescp->cd_namelen + 1);
			if (!depleted) {
				prevdesc.cd_hint = lastdescp->cd_hint;
				prevdesc.cd_nameptr = prevnamebuf;
				prevdesc.cd_namelen = lastdescp->cd_namelen + 1;
			}
		}
			
		/* All done with the catalog descriptors. */
		for (i = 0; i < ce_list->realentries; ++i)
			cat_releasedesc(&ce_list->entry[i].ce_desc);
		ce_list->realentries = 0;

	} /* while not depleted */

	*ap->a_newstate = dcp->c_mtime;
	
	/* All done with last name hint */
	hfs_relnamehint(dcp, startindex);
	startindex = 0;

	/* Convert directory index into uio_offset. */
	uio->uio_offset = index * sizeof(struct dirent);

	/* Save a name hint if there are more entries */
	if ((error == 0) && prevnamebuf && (index + 1) < dcp->c_entries)
		hfs_savenamehint(dcp, index, prevnamebuf);
exit:
	if (startindex > 0)
		hfs_relnamehint(dcp, startindex);

	if (attrbufptr)
		FREE(attrbufptr, M_TEMP);
	if (ce_list)
		FREE(ce_list, M_TEMP);
	if (prevnamebuf)
		FREE(prevnamebuf, M_TEMP);
		
	return (error);
}


/*==================== Attribute list support routines ====================*/

/*
 * Pack cnode attributes into an attribute block.
 */
 __private_extern__
void
hfs_packattrblk(struct attrblock *abp,
		struct hfsmount *hfsmp,
		struct vnode *vp,
		struct cat_desc *descp,
		struct cat_attr *attrp,
		struct cat_fork *datafork,
		struct cat_fork *rsrcfork)
{
	struct attrlist *attrlistp = abp->ab_attrlist;

	if (attrlistp->volattr) {
		if (attrlistp->commonattr)
			packvolcommonattr(abp, hfsmp, vp);

		if (attrlistp->volattr & ~ATTR_VOL_INFO)
			packvolattr(abp, hfsmp, vp);
	} else {
		if (attrlistp->commonattr)
			packcommonattr(abp, hfsmp, vp, descp, attrp);
	
		if (attrlistp->dirattr && S_ISDIR(attrp->ca_mode))
			packdirattr(abp, hfsmp, vp, descp,attrp);
	
		if (attrlistp->fileattr && !S_ISDIR(attrp->ca_mode))
			packfileattr(abp, hfsmp, attrp, datafork, rsrcfork);
	}
}


static char*
mountpointname(struct mount *mp)
{
	size_t namelength = strlen(mp->mnt_stat.f_mntonname);
	int foundchars = 0;
	char *c;
	
	if (namelength == 0)
		return (NULL);
	
	/*
	 * Look backwards through the name string, looking for
	 * the first slash encountered (which must precede the
	 * last part of the pathname).
	 */
	for (c = mp->mnt_stat.f_mntonname + namelength - 1;
	     namelength > 0; --c, --namelength) {
		if (*c != '/') {
			foundchars = 1;
		} else if (foundchars) {
			return (c + 1);
		}
	}
	
	return (mp->mnt_stat.f_mntonname);
}


static void
packnameattr(
	struct attrblock *abp,
	struct vnode *vp,
	char *name,
	int namelen)
{
	void *varbufptr;
	struct attrreference * attr_refptr;
	char *mpname;
	size_t mpnamelen;
	u_long attrlength;
	char empty = 0;
	
	/* A cnode's name may be incorrect for the root of a mounted
	 * filesystem (it can be mounted on a different directory name
	 * than the name of the volume, such as "blah-1").  So for the
	 * root directory, it's best to return the last element of the
	 location where the volume's mounted:
	 */
	if ((vp != NULL) && (vp->v_flag & VROOT) &&
	    (mpname = mountpointname(vp->v_mount))) {
		mpnamelen = strlen(mpname);
		
		/* Trim off any trailing slashes: */
		while ((mpnamelen > 0) && (mpname[mpnamelen-1] == '/'))
			--mpnamelen;

		/* If there's anything left, use it instead of the volume's name */
		if (mpnamelen > 0) {
			name = mpname;
			namelen = mpnamelen;
		}
	}
	if (name == NULL) {
		name = &empty;
		namelen = 0;
	}

	varbufptr = *abp->ab_varbufpp;
	attr_refptr = (struct attrreference *)(*abp->ab_attrbufpp);

	attrlength = namelen + 1;
	attr_refptr->attr_dataoffset = (char *)varbufptr - (char *)attr_refptr;
	attr_refptr->attr_length = attrlength;
	(void) strncpy((unsigned char *)varbufptr, name, attrlength);
	/*
	 * Advance beyond the space just allocated and
	 * round up to the next 4-byte boundary:
	 */
	(char *)(varbufptr) += attrlength + ((4 - (attrlength & 3)) & 3);
	++attr_refptr;

	*abp->ab_attrbufpp = attr_refptr;
	*abp->ab_varbufpp = varbufptr;
}

/*
 * Pack common volume attributes.
 */
static void
packvolcommonattr(struct attrblock *abp, struct hfsmount *hfsmp, struct vnode *vp)
{
	attrgroup_t attr;
	void *attrbufptr = *abp->ab_attrbufpp;
	void *varbufptr = *abp->ab_varbufpp;
	struct cnode *cp = VTOC(vp);
	struct mount *mp = VTOVFS(vp);
	ExtendedVCB *vcb = HFSTOVCB(hfsmp);
	u_long attrlength;

	attr = abp->ab_attrlist->commonattr;

	if (ATTR_CMN_NAME & attr) {
		packnameattr(abp, vp, cp->c_desc.cd_nameptr, cp->c_desc.cd_namelen);
		attrbufptr = *abp->ab_attrbufpp;
		varbufptr = *abp->ab_varbufpp;
	}
	if (ATTR_CMN_DEVID & attr) {
		*((dev_t *)attrbufptr)++ = hfsmp->hfs_raw_dev;
	}
	if (ATTR_CMN_FSID & attr) {
		*((fsid_t *)attrbufptr) = mp->mnt_stat.f_fsid;
		++((fsid_t *)attrbufptr);
	}
	if (ATTR_CMN_OBJTYPE & attr) {
		*((fsobj_type_t *)attrbufptr)++ = 0;
	}
	if (ATTR_CMN_OBJTAG & attr) {
		*((fsobj_tag_t *)attrbufptr)++ = VT_HFS;
	}
	if (ATTR_CMN_OBJID & attr)	{
		((fsobj_id_t *)attrbufptr)->fid_objno = 0;
		((fsobj_id_t *)attrbufptr)->fid_generation = 0;
		++((fsobj_id_t *)attrbufptr);
	}
        if (ATTR_CMN_OBJPERMANENTID & attr) {
		((fsobj_id_t *)attrbufptr)->fid_objno = 0;
		((fsobj_id_t *)attrbufptr)->fid_generation = 0;
		++((fsobj_id_t *)attrbufptr);
        }
	if (ATTR_CMN_PAROBJID & attr) {
		((fsobj_id_t *)attrbufptr)->fid_objno = 0;
		((fsobj_id_t *)attrbufptr)->fid_generation = 0;
		++((fsobj_id_t *)attrbufptr);
	}
        if (ATTR_CMN_SCRIPT & attr) {
        	u_long encoding;
 
        	if (vcb->vcbSigWord == kHFSPlusSigWord)
        		encoding = vcb->volumeNameEncodingHint;
        	else
        		encoding = hfsmp->hfs_encoding;
        	*((text_encoding_t *)attrbufptr)++ = encoding;
	}
	if (ATTR_CMN_CRTIME & attr) {
		((struct timespec *)attrbufptr)->tv_sec = vcb->vcbCrDate;
		((struct timespec *)attrbufptr)->tv_nsec = 0;
		++((struct timespec *)attrbufptr);
	}
	if (ATTR_CMN_MODTIME & attr) {
		((struct timespec *)attrbufptr)->tv_sec = vcb->vcbLsMod;
		((struct timespec *)attrbufptr)->tv_nsec = 0;
		++((struct timespec *)attrbufptr);
	}
	if (ATTR_CMN_CHGTIME & attr) {
		((struct timespec *)attrbufptr)->tv_sec = vcb->vcbLsMod;
		((struct timespec *)attrbufptr)->tv_nsec = 0;
		++((struct timespec *)attrbufptr);
	}
	if (ATTR_CMN_ACCTIME & attr) {
		((struct timespec *)attrbufptr)->tv_sec = vcb->vcbLsMod;
		((struct timespec *)attrbufptr)->tv_nsec = 0;
		++((struct timespec *)attrbufptr);
	}
	if (ATTR_CMN_BKUPTIME & attr) {
		((struct timespec *)attrbufptr)->tv_sec = vcb->vcbVolBkUp;
		((struct timespec *)attrbufptr)->tv_nsec = 0;
		++((struct timespec *)attrbufptr);
	}
	if (ATTR_CMN_FNDRINFO & attr) {
		bcopy (&vcb->vcbFndrInfo, attrbufptr, sizeof(vcb->vcbFndrInfo));
		(char *)attrbufptr += sizeof(vcb->vcbFndrInfo);
	}
	if (ATTR_CMN_OWNERID & attr) {
		if (cp->c_uid == UNKNOWNUID)
			*((uid_t *)attrbufptr)++ = console_user;
		else
			*((uid_t *)attrbufptr)++ = cp->c_uid;
	}
	if (ATTR_CMN_GRPID & attr) {
		*((gid_t *)attrbufptr)++ = cp->c_gid;
	}
	if (ATTR_CMN_ACCESSMASK & attr) {
		/*
		 * [2856576]  Since we are dynamically changing the owner, also
		 * effectively turn off the set-user-id and set-group-id bits,
		 * just like chmod(2) would when changing ownership.  This prevents
		 * a security hole where set-user-id programs run as whoever is
		 * logged on (or root if nobody is logged in yet!)
		 */
		*((u_long *)attrbufptr)++ =
			(cp->c_uid == UNKNOWNUID) ? cp->c_mode & ~(S_ISUID | S_ISGID) : cp->c_mode;
	}
	if (ATTR_CMN_NAMEDATTRCOUNT & attr) {
		*((u_long *)attrbufptr)++ = 0;	/* XXX PPD TBC */
	}
	if (ATTR_CMN_NAMEDATTRLIST & attr) {
		attrlength = 0;
		((struct attrreference *)attrbufptr)->attr_dataoffset = 0;
		((struct attrreference *)attrbufptr)->attr_length = attrlength;
		/*
		 * Advance beyond the space just allocated and
		 * round up to the next 4-byte boundary:
		 */
		(char *)varbufptr += attrlength + ((4 - (attrlength & 3)) & 3);
		++((struct attrreference *)attrbufptr);
	}
	if (ATTR_CMN_FLAGS & attr) {
		*((u_long *)attrbufptr)++ = cp->c_flags;
	}
	if (ATTR_CMN_USERACCESS & attr) {
		*((u_long *)attrbufptr)++ =
			DerivePermissionSummary(cp->c_uid, cp->c_gid, cp->c_mode,
				VTOVFS(vp), current_proc()->p_ucred, current_proc());
	}

	*abp->ab_attrbufpp = attrbufptr;
	*abp->ab_varbufpp = varbufptr;
}


static void
packvolattr(struct attrblock *abp, struct hfsmount *hfsmp, struct vnode *vp)
{
	attrgroup_t attr;
	void *attrbufptr = *abp->ab_attrbufpp;
	void *varbufptr = *abp->ab_varbufpp;
	struct cnode *cp = VTOC(vp);
	struct mount *mp = VTOVFS(vp);
	ExtendedVCB *vcb = HFSTOVCB(hfsmp);
	u_long attrlength;

	attr = abp->ab_attrlist->volattr;

	if (ATTR_VOL_FSTYPE & attr) {
		*((u_long *)attrbufptr)++ = (u_long)mp->mnt_vfc->vfc_typenum;
	}
	if (ATTR_VOL_SIGNATURE & attr) {
		*((u_long *)attrbufptr)++ = (u_long)vcb->vcbSigWord;
	}
	if (ATTR_VOL_SIZE & attr) {
		*((off_t *)attrbufptr)++ =
				(off_t)vcb->totalBlocks * (off_t)vcb->blockSize;
	}
	if (ATTR_VOL_SPACEFREE & attr) {
		*((off_t *)attrbufptr)++ = (off_t)hfs_freeblks(hfsmp, 0) *
		                           (off_t)vcb->blockSize;
		
	}
	if (ATTR_VOL_SPACEAVAIL & attr) {
		*((off_t *)attrbufptr)++ = (off_t)hfs_freeblks(hfsmp, 1) *
		                           (off_t)vcb->blockSize;
	}
	if (ATTR_VOL_MINALLOCATION & attr) {
		*((off_t *)attrbufptr)++ = (off_t)vcb->blockSize;
	}
	if (ATTR_VOL_ALLOCATIONCLUMP & attr) {
		*((off_t *)attrbufptr)++ = (off_t)(vcb->vcbClpSiz);
	}
	if (ATTR_VOL_IOBLOCKSIZE & attr) {
		*((u_long *)attrbufptr)++ = (u_long)hfsmp->hfs_logBlockSize;
	}
	if (ATTR_VOL_OBJCOUNT & attr) {
		*((u_long *)attrbufptr)++ =
				(u_long)vcb->vcbFilCnt + (u_long)vcb->vcbDirCnt;
	}
	if (ATTR_VOL_FILECOUNT & attr) {
		*((u_long *)attrbufptr)++ = (u_long)vcb->vcbFilCnt;
	}
	if (ATTR_VOL_DIRCOUNT & attr) {
		*((u_long *)attrbufptr)++ = (u_long)vcb->vcbDirCnt;
	}
	if (ATTR_VOL_MAXOBJCOUNT & attr) {
		*((u_long *)attrbufptr)++ = 0xFFFFFFFF;
	}
	if (ATTR_VOL_MOUNTPOINT & attr) {
		((struct attrreference *)attrbufptr)->attr_dataoffset =
				(char *)varbufptr - (char *)attrbufptr;
		((struct attrreference *)attrbufptr)->attr_length =
				strlen(mp->mnt_stat.f_mntonname) + 1;
		attrlength = ((struct attrreference *)attrbufptr)->attr_length;
		/* round up to the next 4-byte boundary: */
		attrlength = attrlength + ((4 - (attrlength & 3)) & 3);
		(void) bcopy(mp->mnt_stat.f_mntonname, varbufptr, attrlength);
			
		/* Advance beyond the space just allocated: */
		(char *)varbufptr += attrlength;
		++((struct attrreference *)attrbufptr);
	}
	if (ATTR_VOL_NAME & attr) {
		((struct attrreference *)attrbufptr)->attr_dataoffset =
				(char *)varbufptr - (char *)attrbufptr;
		((struct attrreference *)attrbufptr)->attr_length =
				cp->c_desc.cd_namelen + 1;
		attrlength = ((struct attrreference *)attrbufptr)->attr_length;
		/* round up to the next 4-byte boundary: */
		attrlength = attrlength + ((4 - (attrlength & 3)) & 3);
		/* XXX this could read off the end of cd_nameptr! */
		bcopy(cp->c_desc.cd_nameptr, varbufptr, attrlength);

		/* Advance beyond the space just allocated: */
		(char *)varbufptr += attrlength;
		++((struct attrreference *)attrbufptr);
	}
        if (ATTR_VOL_MOUNTFLAGS & attr) {
        	*((u_long *)attrbufptr)++ = (u_long)mp->mnt_flag;
        }
	if (ATTR_VOL_MOUNTEDDEVICE & attr) {
		((struct attrreference *)attrbufptr)->attr_dataoffset =
				(char *)varbufptr - (char *)attrbufptr;
		((struct attrreference *)attrbufptr)->attr_length =
				strlen(mp->mnt_stat.f_mntfromname) + 1;
		attrlength = ((struct attrreference *)attrbufptr)->attr_length;
		/* round up to the next 4-byte boundary: */
		attrlength = attrlength + ((4 - (attrlength & 3)) & 3);
		(void) bcopy(mp->mnt_stat.f_mntfromname, varbufptr, attrlength);
			
		/* Advance beyond the space just allocated: */
		(char *)varbufptr += attrlength;
		++((struct attrreference *)attrbufptr);
        }
	if (ATTR_VOL_ENCODINGSUSED & attr) {
		*((unsigned long long *)attrbufptr)++ =
				(unsigned long long)vcb->encodingsBitmap;
	}
	if (ATTR_VOL_CAPABILITIES & attr) {
		vol_capabilities_attr_t *vcapattrptr;
	
		vcapattrptr = (vol_capabilities_attr_t *)attrbufptr;

		if (vcb->vcbSigWord == kHFSPlusSigWord) {
			vcapattrptr->capabilities[VOL_CAPABILITIES_FORMAT] =
					VOL_CAP_FMT_PERSISTENTOBJECTIDS |
					VOL_CAP_FMT_SYMBOLICLINKS |
					VOL_CAP_FMT_HARDLINKS;
		} else { /* Plain HFS */
			vcapattrptr->capabilities[VOL_CAPABILITIES_FORMAT] =
					VOL_CAP_FMT_PERSISTENTOBJECTIDS;
		}
        	vcapattrptr->capabilities[VOL_CAPABILITIES_INTERFACES] =
        				VOL_CAP_INT_SEARCHFS |
        				VOL_CAP_INT_ATTRLIST |
        				VOL_CAP_INT_NFSEXPORT |
        				VOL_CAP_INT_READDIRATTR ;
        	vcapattrptr->capabilities[VOL_CAPABILITIES_RESERVED1] = 0;
        	vcapattrptr->capabilities[VOL_CAPABILITIES_RESERVED2] = 0;

		vcapattrptr->valid[VOL_CAPABILITIES_FORMAT] =
					VOL_CAP_FMT_PERSISTENTOBJECTIDS |
					VOL_CAP_FMT_SYMBOLICLINKS |
					VOL_CAP_FMT_HARDLINKS;
        	vcapattrptr->valid[VOL_CAPABILITIES_INTERFACES] =
        				VOL_CAP_INT_SEARCHFS |
        				VOL_CAP_INT_ATTRLIST |
        				VOL_CAP_INT_NFSEXPORT |
        				VOL_CAP_INT_READDIRATTR ;
        	vcapattrptr->valid[VOL_CAPABILITIES_RESERVED1] = 0;
        	vcapattrptr->valid[VOL_CAPABILITIES_RESERVED2] = 0;

		++((vol_capabilities_attr_t *)attrbufptr);
	}
	if (ATTR_VOL_ATTRIBUTES & attr) {
		vol_attributes_attr_t *volattrattrp;
		
		volattrattrp = (vol_attributes_attr_t *)attrbufptr;
        	volattrattrp->validattr.commonattr = ATTR_CMN_VALIDMASK;
        	volattrattrp->validattr.volattr = ATTR_VOL_VALIDMASK;
        	volattrattrp->validattr.dirattr = ATTR_DIR_VALIDMASK;
        	volattrattrp->validattr.fileattr = ATTR_FILE_VALIDMASK;
        	volattrattrp->validattr.forkattr = ATTR_FORK_VALIDMASK;

        	volattrattrp->nativeattr.commonattr = ATTR_CMN_VALIDMASK;
        	volattrattrp->nativeattr.volattr = ATTR_VOL_VALIDMASK;
        	volattrattrp->nativeattr.dirattr = ATTR_DIR_VALIDMASK;
        	volattrattrp->nativeattr.fileattr = ATTR_FILE_VALIDMASK;
        	volattrattrp->nativeattr.forkattr = ATTR_FORK_VALIDMASK;
		++((vol_attributes_attr_t *)attrbufptr);
	}
	
	*abp->ab_attrbufpp = attrbufptr;
	*abp->ab_varbufpp = varbufptr;
}


static void
packcommonattr(
	struct attrblock *abp,
	struct hfsmount *hfsmp,
	struct vnode *vp,
	struct cat_desc * cdp,
	struct cat_attr * cap)
{
	attrgroup_t attr = abp->ab_attrlist->commonattr;
	struct mount *mp = HFSTOVFS(hfsmp);
	void *attrbufptr = *abp->ab_attrbufpp;
	void *varbufptr = *abp->ab_varbufpp;
	u_long attrlength = 0;
	
	if (ATTR_CMN_NAME & attr) {
		packnameattr(abp, vp, cdp->cd_nameptr, cdp->cd_namelen);
		attrbufptr = *abp->ab_attrbufpp;
		varbufptr = *abp->ab_varbufpp;
	}
	if (ATTR_CMN_DEVID & attr) {
		*((dev_t *)attrbufptr)++ = hfsmp->hfs_raw_dev;
	}
	if (ATTR_CMN_FSID & attr) {
		*((fsid_t *)attrbufptr) = mp->mnt_stat.f_fsid;
		++((fsid_t *)attrbufptr);
	}
	if (ATTR_CMN_OBJTYPE & attr) {
		*((fsobj_type_t *)attrbufptr)++ = IFTOVT(cap->ca_mode);
	}
	if (ATTR_CMN_OBJTAG & attr) {
		*((fsobj_tag_t *)attrbufptr)++ = VT_HFS;
	}
	/*
	 * Exporting file IDs from HFS Plus:
	 *
	 * For "normal" files the c_fileid is the same value as the
	 * c_cnid.  But for hard link files, they are different - the
	 * c_cnid belongs to the active directory entry (ie the link)
	 * and the c_fileid is for the actual inode (ie the data file).
	 *
	 * The stat call (getattr) will always return the c_fileid
	 * and Carbon APIs, which are hardlink-ignorant, will always
	 * receive the c_cnid (from getattrlist).
	 */
        if (ATTR_CMN_OBJID & attr) {
		((fsobj_id_t *)attrbufptr)->fid_objno = cdp->cd_cnid;
		((fsobj_id_t *)attrbufptr)->fid_generation = 0;
		++((fsobj_id_t *)attrbufptr);
	}
	if (ATTR_CMN_OBJPERMANENTID & attr) {
		((fsobj_id_t *)attrbufptr)->fid_objno = cdp->cd_cnid;
		((fsobj_id_t *)attrbufptr)->fid_generation = 0;
		++((fsobj_id_t *)attrbufptr);
	}
	if (ATTR_CMN_PAROBJID & attr) {
		((fsobj_id_t *)attrbufptr)->fid_objno = cdp->cd_parentcnid;
		((fsobj_id_t *)attrbufptr)->fid_generation = 0;
		++((fsobj_id_t *)attrbufptr);
	}
	if (ATTR_CMN_SCRIPT & attr) {
		*((text_encoding_t *)attrbufptr)++ = cdp->cd_encoding;
	}
	if (ATTR_CMN_CRTIME & attr) {
		((struct timespec *)attrbufptr)->tv_sec = cap->ca_itime;
		((struct timespec *)attrbufptr)->tv_nsec = 0;
		++((struct timespec *)attrbufptr);
	}
	if (ATTR_CMN_MODTIME & attr) {
		((struct timespec *)attrbufptr)->tv_sec = cap->ca_mtime;
		((struct timespec *)attrbufptr)->tv_nsec = 0;
		++((struct timespec *)attrbufptr);
	}
	if (ATTR_CMN_CHGTIME & attr) {
		((struct timespec *)attrbufptr)->tv_sec = cap->ca_ctime;
		((struct timespec *)attrbufptr)->tv_nsec = 0;
		++((struct timespec *)attrbufptr);
	}
	if (ATTR_CMN_ACCTIME & attr) {
		((struct timespec *)attrbufptr)->tv_sec = cap->ca_atime;
		((struct timespec *)attrbufptr)->tv_nsec = 0;
		++((struct timespec *)attrbufptr);
	}
	if (ATTR_CMN_BKUPTIME & attr) {
		((struct timespec *)attrbufptr)->tv_sec = cap->ca_btime;
		((struct timespec *)attrbufptr)->tv_nsec = 0;
		++((struct timespec *)attrbufptr);
	}
	if (ATTR_CMN_FNDRINFO & attr) {
		bcopy(&cap->ca_finderinfo, attrbufptr, sizeof(u_int8_t) * 32);
		(char *)attrbufptr += sizeof(u_int8_t) * 32;
	}
	if (ATTR_CMN_OWNERID & attr) {
		*((uid_t *)attrbufptr)++ =
			(cap->ca_uid == UNKNOWNUID) ? console_user : cap->ca_uid;
	}
	if (ATTR_CMN_GRPID & attr) {
		*((gid_t *)attrbufptr)++ = cap->ca_gid;
	}
	if (ATTR_CMN_ACCESSMASK & attr) {
		/*
		 * [2856576]  Since we are dynamically changing the owner, also
		 * effectively turn off the set-user-id and set-group-id bits,
		 * just like chmod(2) would when changing ownership.  This prevents
		 * a security hole where set-user-id programs run as whoever is
		 * logged on (or root if nobody is logged in yet!)
		 */
		*((u_long *)attrbufptr)++ =
			(cap->ca_uid == UNKNOWNUID) ? cap->ca_mode & ~(S_ISUID | S_ISGID) : cap->ca_mode;
	}
	if (ATTR_CMN_NAMEDATTRCOUNT & attr) {
		*((u_long *)attrbufptr)++ = 0;
	}
	if (ATTR_CMN_NAMEDATTRLIST & attr) {
		attrlength = 0;
		((struct attrreference *)attrbufptr)->attr_dataoffset = 0;
		((struct attrreference *)attrbufptr)->attr_length = attrlength;
		/*
		 * Advance beyond the space just allocated and
		 * round up to the next 4-byte boundary:
		 */
		(char *)varbufptr += attrlength + ((4 - (attrlength & 3)) & 3);
		++((struct attrreference *)attrbufptr);
	}
	if (ATTR_CMN_FLAGS & attr) {
		*((u_long *)attrbufptr)++ = cap->ca_flags;
	}
	if (ATTR_CMN_USERACCESS & attr) {
		*((u_long *)attrbufptr)++ =
			DerivePermissionSummary(cap->ca_uid, cap->ca_gid,
				cap->ca_mode, mp, current_proc()->p_ucred,
				current_proc());
	}
	
	*abp->ab_attrbufpp = attrbufptr;
	*abp->ab_varbufpp = varbufptr;
}

static void
packdirattr(
	struct attrblock *abp,
	struct hfsmount *hfsmp,
	struct vnode *vp,
	struct cat_desc * descp,
	struct cat_attr * cattrp)
{
	attrgroup_t attr = abp->ab_attrlist->dirattr;
	void *attrbufptr = *abp->ab_attrbufpp;
	
	if (ATTR_DIR_LINKCOUNT & attr)
		*((u_long *)attrbufptr)++ = cattrp->ca_nlink;
	if (ATTR_DIR_ENTRYCOUNT & attr) {
		u_long entries = cattrp->ca_entries;

		if ((descp->cd_parentcnid == kRootParID) &&
		    (hfsmp->hfs_private_metadata_dir != 0))
			--entries;	/* hide private dir */

		*((u_long *)attrbufptr)++ = entries;
	}
	if (ATTR_DIR_MOUNTSTATUS & attr) {
		if (vp != NULL && vp->v_mountedhere != NULL)
			*((u_long *)attrbufptr)++ = DIR_MNTSTATUS_MNTPOINT;
		else
			*((u_long *)attrbufptr)++ = 0;
	}
	*abp->ab_attrbufpp = attrbufptr;
}

static void
packfileattr(
	struct attrblock *abp,
	struct hfsmount *hfsmp,
	struct cat_attr *cattrp,
	struct cat_fork *datafork,
	struct cat_fork *rsrcfork)
{
	attrgroup_t attr = abp->ab_attrlist->fileattr;
	void *attrbufptr = *abp->ab_attrbufpp;
	void *varbufptr = *abp->ab_varbufpp;
	u_long attrlength;
	u_long allocblksize;

	allocblksize = HFSTOVCB(hfsmp)->blockSize;

	if (ATTR_FILE_LINKCOUNT & attr) {
		*((u_long *)attrbufptr)++ = cattrp->ca_nlink;
	}
	if (ATTR_FILE_TOTALSIZE & attr) {
		*((off_t *)attrbufptr)++ = datafork->cf_size + rsrcfork->cf_size;
	}
	if (ATTR_FILE_ALLOCSIZE & attr) {
		*((off_t *)attrbufptr)++ =
			(off_t)cattrp->ca_blocks * (off_t)allocblksize;
	}
	if (ATTR_FILE_IOBLOCKSIZE & attr) {
		*((u_long *)attrbufptr)++ = hfsmp->hfs_logBlockSize;
	}
	if (ATTR_FILE_CLUMPSIZE & attr) {
		*((u_long *)attrbufptr)++ = datafork->cf_clump;  /* XXX ambiguity */
	}
	if (ATTR_FILE_DEVTYPE & attr) {
		if (S_ISBLK(cattrp->ca_mode) || S_ISCHR(cattrp->ca_mode))
			*((u_long *)attrbufptr)++ = (u_long)cattrp->ca_rdev;
		else
			*((u_long *)attrbufptr)++ = 0;
	}
	if (ATTR_FILE_FILETYPE & attr) {
		*((u_long *)attrbufptr)++ = 0;
	}
	if (ATTR_FILE_FORKCOUNT & attr) {
		*((u_long *)attrbufptr)++ = 2;
	}
	if (ATTR_FILE_FORKLIST & attr) {
		attrlength = 0;
		((struct attrreference *)attrbufptr)->attr_dataoffset = 0;
		((struct attrreference *)attrbufptr)->attr_length = attrlength;	
		/*
		 * Advance beyond the space just allocated and
		 * round up to the next 4-byte boundary:
		 */
		(char *)varbufptr += attrlength + ((4 - (attrlength & 3)) & 3);
		++((struct attrreference *)attrbufptr);
	}
	if (ATTR_FILE_DATALENGTH & attr) {
		*((off_t *)attrbufptr)++ = datafork->cf_size;
	}
	if (ATTR_FILE_DATAALLOCSIZE & attr) {
		*((off_t *)attrbufptr)++ =
			(off_t)datafork->cf_blocks * (off_t)allocblksize;
	}
	if (ATTR_FILE_DATAEXTENTS & attr) {
		bcopy(&datafork->cf_extents, attrbufptr, sizeof(extentrecord));
		(char *)attrbufptr += sizeof(extentrecord);
	}
	if (ATTR_FILE_RSRCLENGTH & attr) {
		*((off_t *)attrbufptr)++ = rsrcfork->cf_size;
	}
	if (ATTR_FILE_RSRCALLOCSIZE & attr) {
		*((off_t *)attrbufptr)++ =
			(off_t)rsrcfork->cf_blocks * (off_t)allocblksize;
	}
	if (ATTR_FILE_RSRCEXTENTS & attr) {
		bcopy(&rsrcfork->cf_extents, attrbufptr, sizeof(extentrecord));
		(char *)attrbufptr += sizeof(extentrecord);
	}
	*abp->ab_attrbufpp = attrbufptr;
	*abp->ab_varbufpp = varbufptr;
}


static void
unpackattrblk(struct attrblock *abp, struct vnode *vp)
{
	struct attrlist *attrlistp = abp->ab_attrlist;

	if (attrlistp->volattr)
		unpackvolattr(abp, VTOHFS(vp), vp);
	else if (attrlistp->commonattr)
		unpackcommonattr(abp, vp);
}


static void
unpackcommonattr(
	struct attrblock *abp,
	struct vnode *vp)
{
	attrgroup_t attr = abp->ab_attrlist->commonattr;
	void *attrbufptr = *abp->ab_attrbufpp;
	struct cnode *cp = VTOC(vp);

	if (ATTR_CMN_SCRIPT & attr) {
		cp->c_encoding = (u_int32_t)*((text_encoding_t *)attrbufptr)++;
		hfs_setencodingbits(VTOHFS(vp), cp->c_encoding);
	}
	if (ATTR_CMN_CRTIME & attr) {
		cp->c_itime = ((struct timespec *)attrbufptr)->tv_sec;
		++((struct timespec *)attrbufptr);
	}
	if (ATTR_CMN_MODTIME & attr) {
		cp->c_mtime = ((struct timespec *)attrbufptr)->tv_sec;
		cp->c_mtime_nsec = ((struct timespec *)attrbufptr)->tv_nsec;
		++((struct timespec *)attrbufptr);
		cp->c_flag &= ~C_UPDATE;
	}
	if (ATTR_CMN_CHGTIME & attr) {
		cp->c_ctime = ((struct timespec *)attrbufptr)->tv_sec;
		++((struct timespec *)attrbufptr);
		cp->c_flag &= ~C_CHANGE;
	}
	if (ATTR_CMN_ACCTIME & attr) {
		cp->c_atime = ((struct timespec *)attrbufptr)->tv_sec;
		++((struct timespec *)attrbufptr);
		cp->c_flag &= ~C_ACCESS;
	}
	if (ATTR_CMN_BKUPTIME & attr) {
		cp->c_btime = ((struct timespec *)attrbufptr)->tv_sec;
		++((struct timespec *)attrbufptr);
	}
	if (ATTR_CMN_FNDRINFO & attr) {
		bcopy(attrbufptr, &cp->c_attr.ca_finderinfo,
			sizeof(cp->c_attr.ca_finderinfo));
		(char *)attrbufptr += sizeof(cp->c_attr.ca_finderinfo);
	}
	if (ATTR_CMN_OWNERID & attr) {
		if (VTOVCB(vp)->vcbSigWord == kHFSPlusSigWord) {
			u_int32_t uid = (u_int32_t)*((uid_t *)attrbufptr)++;
			if (uid != (uid_t)VNOVAL)
				cp->c_uid = uid;
		} else {
			((uid_t *)attrbufptr)++;
		}
	}
	if (ATTR_CMN_GRPID & attr) {
		u_int32_t gid = (u_int32_t)*((gid_t *)attrbufptr)++;
		if (VTOVCB(vp)->vcbSigWord == kHFSPlusSigWord) {
		    if (gid != (gid_t)VNOVAL)
			cp->c_gid = gid;
		}
	}
	if (ATTR_CMN_ACCESSMASK & attr) {
        	u_int16_t mode = (u_int16_t)*((u_long *)attrbufptr)++;
        	if (VTOVCB(vp)->vcbSigWord == kHFSPlusSigWord) {
			if (mode != (mode_t)VNOVAL) {
                		cp->c_mode &= ~ALLPERMS;
                		cp->c_mode |= (mode & ALLPERMS);
			}
        	}
	}
	if (ATTR_CMN_FLAGS & attr) {
		u_long flags = *((u_long *)attrbufptr)++;
		/*
		 * Flags are settable only on HFS+ volumes.  A special
		 * exception is made for the IMMUTABLE flags
		 * (SF_IMMUTABLE and UF_IMMUTABLE), which can be set on
		 * HFS volumes as well:
		 */
		if ((VTOVCB(vp)->vcbSigWord == kHFSPlusSigWord) ||
		    ((VTOVCB(vp)->vcbSigWord == kHFSSigWord) &&
		     ((flags & ~IMMUTABLE) == 0))) {
			if (flags != (u_long)VNOVAL) {
				cp->c_flags = flags;
			}
		}
	}
	*abp->ab_attrbufpp = attrbufptr;
}


static void
unpackvolattr(
	struct attrblock *abp,
	struct hfsmount *hfsmp,
	struct vnode *rootvp)
{
	void *attrbufptr = *abp->ab_attrbufpp;
	ExtendedVCB *vcb = HFSTOVCB(hfsmp);
	attrgroup_t attr;

	attr = abp->ab_attrlist->commonattr;
	if (attr == 0)
		goto volattr;

	if (ATTR_CMN_SCRIPT & attr) {
		vcb->volumeNameEncodingHint =
				(u_int32_t)*(((text_encoding_t *)attrbufptr)++);
	}
	if (ATTR_CMN_CRTIME & attr) {
		vcb->vcbCrDate = ((struct timespec *)attrbufptr)->tv_sec;
		++((struct timespec *)attrbufptr);
		
		/* The volume's create date comes from the root directory */
		VTOC(rootvp)->c_itime = vcb->vcbCrDate;
		VTOC(rootvp)->c_flag |= C_MODIFIED;
		/*
		 * XXX Should we also do a relative change to the
		 * the volume header's create date in local time?
		 */
	}
	if (ATTR_CMN_MODTIME & attr) {
		vcb->vcbLsMod = ((struct timespec *)attrbufptr)->tv_sec;
		++((struct timespec *)attrbufptr);
	}
	if (ATTR_CMN_BKUPTIME & attr) {
		vcb->vcbVolBkUp = ((struct timespec *)attrbufptr)->tv_sec;
		++((struct timespec *)attrbufptr);
	}
	if (ATTR_CMN_FNDRINFO & attr) {
		bcopy(attrbufptr, &vcb->vcbFndrInfo, sizeof(vcb->vcbFndrInfo));
		(char *)attrbufptr += sizeof(vcb->vcbFndrInfo);
	}

volattr:	
	attr = abp->ab_attrlist->volattr & ~ATTR_VOL_INFO;
	/*
	 * XXX - no validation is done on the name!
	 * It could be empty or garbage (bad UTF-8).
	 */
	if (ATTR_VOL_NAME & attr) {
		copystr(((char *)attrbufptr) + *((u_long *)attrbufptr),
			vcb->vcbVN, sizeof(vcb->vcbVN), NULL);
		(char *)attrbufptr += sizeof(struct attrreference);
	}
	*abp->ab_attrbufpp = attrbufptr;

	vcb->vcbFlags |= 0xFF00;
}

/*
 * Calculate the total size of an attribute block.
 */
 __private_extern__
int
hfs_attrblksize(struct attrlist *attrlist)
{
	int size;
	attrgroup_t a;
	
#if ((ATTR_CMN_NAME | ATTR_CMN_DEVID | ATTR_CMN_FSID | ATTR_CMN_OBJTYPE	|  \
      ATTR_CMN_OBJTAG | ATTR_CMN_OBJID | ATTR_CMN_OBJPERMANENTID |         \
      ATTR_CMN_PAROBJID | ATTR_CMN_SCRIPT | ATTR_CMN_CRTIME |              \
      ATTR_CMN_MODTIME | ATTR_CMN_CHGTIME | ATTR_CMN_ACCTIME |             \
      ATTR_CMN_BKUPTIME | ATTR_CMN_FNDRINFO | ATTR_CMN_OWNERID |           \
      ATTR_CMN_GRPID | ATTR_CMN_ACCESSMASK | ATTR_CMN_NAMEDATTRCOUNT |     \
      ATTR_CMN_NAMEDATTRLIST | ATTR_CMN_FLAGS | ATTR_CMN_USERACCESS)       \
      != ATTR_CMN_VALIDMASK)
#error	hfs_attrblksize: Missing bits in common mask computation!
#endif
	DBG_ASSERT((attrlist->commonattr & ~ATTR_CMN_VALIDMASK) == 0);

#if ((ATTR_VOL_FSTYPE | ATTR_VOL_SIGNATURE | ATTR_VOL_SIZE |                \
      ATTR_VOL_SPACEFREE | ATTR_VOL_SPACEAVAIL | ATTR_VOL_MINALLOCATION |   \
      ATTR_VOL_ALLOCATIONCLUMP | ATTR_VOL_IOBLOCKSIZE |                     \
      ATTR_VOL_OBJCOUNT | ATTR_VOL_FILECOUNT | ATTR_VOL_DIRCOUNT |          \
      ATTR_VOL_MAXOBJCOUNT | ATTR_VOL_MOUNTPOINT | ATTR_VOL_NAME |          \
      ATTR_VOL_MOUNTFLAGS | ATTR_VOL_INFO | ATTR_VOL_MOUNTEDDEVICE |        \
      ATTR_VOL_ENCODINGSUSED | ATTR_VOL_CAPABILITIES | ATTR_VOL_ATTRIBUTES) \
      != ATTR_VOL_VALIDMASK)
#error	hfs_attrblksize: Missing bits in volume mask computation!
#endif
	DBG_ASSERT((attrlist->volattr & ~ATTR_VOL_VALIDMASK) == 0);

#if ((ATTR_DIR_LINKCOUNT | ATTR_DIR_ENTRYCOUNT | ATTR_DIR_MOUNTSTATUS)  \
      != ATTR_DIR_VALIDMASK)
#error	hfs_attrblksize: Missing bits in directory mask computation!
#endif
	DBG_ASSERT((attrlist->dirattr & ~ATTR_DIR_VALIDMASK) == 0);

#if ((ATTR_FILE_LINKCOUNT | ATTR_FILE_TOTALSIZE | ATTR_FILE_ALLOCSIZE |        \
      ATTR_FILE_IOBLOCKSIZE | ATTR_FILE_CLUMPSIZE | ATTR_FILE_DEVTYPE |        \
      ATTR_FILE_FILETYPE | ATTR_FILE_FORKCOUNT | ATTR_FILE_FORKLIST |          \
      ATTR_FILE_DATALENGTH | ATTR_FILE_DATAALLOCSIZE | ATTR_FILE_DATAEXTENTS | \
      ATTR_FILE_RSRCLENGTH | ATTR_FILE_RSRCALLOCSIZE | ATTR_FILE_RSRCEXTENTS)  \
      != ATTR_FILE_VALIDMASK)
#error	hfs_attrblksize: Missing bits in file mask computation!
#endif
	DBG_ASSERT((attrlist->fileattr & ~ATTR_FILE_VALIDMASK) == 0);

#if ((ATTR_FORK_TOTALSIZE | ATTR_FORK_ALLOCSIZE) != ATTR_FORK_VALIDMASK)
#error	hfs_attrblksize: Missing bits in fork mask computation!
#endif
	DBG_ASSERT((attrlist->forkattr & ~ATTR_FORK_VALIDMASK) == 0);

	size = 0;
	
	if ((a = attrlist->commonattr) != 0) {
        if (a & ATTR_CMN_NAME) size += sizeof(struct attrreference);
		if (a & ATTR_CMN_DEVID) size += sizeof(dev_t);
		if (a & ATTR_CMN_FSID) size += sizeof(fsid_t);
		if (a & ATTR_CMN_OBJTYPE) size += sizeof(fsobj_type_t);
		if (a & ATTR_CMN_OBJTAG) size += sizeof(fsobj_tag_t);
		if (a & ATTR_CMN_OBJID) size += sizeof(fsobj_id_t);
		if (a & ATTR_CMN_OBJPERMANENTID) size += sizeof(fsobj_id_t);
		if (a & ATTR_CMN_PAROBJID) size += sizeof(fsobj_id_t);
		if (a & ATTR_CMN_SCRIPT) size += sizeof(text_encoding_t);
		if (a & ATTR_CMN_CRTIME) size += sizeof(struct timespec);
		if (a & ATTR_CMN_MODTIME) size += sizeof(struct timespec);
		if (a & ATTR_CMN_CHGTIME) size += sizeof(struct timespec);
		if (a & ATTR_CMN_ACCTIME) size += sizeof(struct timespec);
		if (a & ATTR_CMN_BKUPTIME) size += sizeof(struct timespec);
		if (a & ATTR_CMN_FNDRINFO) size += 32 * sizeof(u_int8_t);
		if (a & ATTR_CMN_OWNERID) size += sizeof(uid_t);
		if (a & ATTR_CMN_GRPID) size += sizeof(gid_t);
		if (a & ATTR_CMN_ACCESSMASK) size += sizeof(u_long);
		if (a & ATTR_CMN_NAMEDATTRCOUNT) size += sizeof(u_long);
		if (a & ATTR_CMN_NAMEDATTRLIST) size += sizeof(struct attrreference);
		if (a & ATTR_CMN_FLAGS) size += sizeof(u_long);
		if (a & ATTR_CMN_USERACCESS) size += sizeof(u_long);
	};
	if ((a = attrlist->volattr) != 0) {
		if (a & ATTR_VOL_FSTYPE) size += sizeof(u_long);
		if (a & ATTR_VOL_SIGNATURE) size += sizeof(u_long);
		if (a & ATTR_VOL_SIZE) size += sizeof(off_t);
		if (a & ATTR_VOL_SPACEFREE) size += sizeof(off_t);
		if (a & ATTR_VOL_SPACEAVAIL) size += sizeof(off_t);
		if (a & ATTR_VOL_MINALLOCATION) size += sizeof(off_t);
		if (a & ATTR_VOL_ALLOCATIONCLUMP) size += sizeof(off_t);
		if (a & ATTR_VOL_IOBLOCKSIZE) size += sizeof(u_long);
		if (a & ATTR_VOL_OBJCOUNT) size += sizeof(u_long);
		if (a & ATTR_VOL_FILECOUNT) size += sizeof(u_long);
		if (a & ATTR_VOL_DIRCOUNT) size += sizeof(u_long);
		if (a & ATTR_VOL_MAXOBJCOUNT) size += sizeof(u_long);
		if (a & ATTR_VOL_MOUNTPOINT) size += sizeof(struct attrreference);
		if (a & ATTR_VOL_NAME) size += sizeof(struct attrreference);
		if (a & ATTR_VOL_MOUNTFLAGS) size += sizeof(u_long);
		if (a & ATTR_VOL_MOUNTEDDEVICE) size += sizeof(struct attrreference);
		if (a & ATTR_VOL_ENCODINGSUSED) size += sizeof(unsigned long long);
		if (a & ATTR_VOL_CAPABILITIES) size += sizeof(vol_capabilities_attr_t);
		if (a & ATTR_VOL_ATTRIBUTES) size += sizeof(vol_attributes_attr_t);
	};
	if ((a = attrlist->dirattr) != 0) {
		if (a & ATTR_DIR_LINKCOUNT) size += sizeof(u_long);
		if (a & ATTR_DIR_ENTRYCOUNT) size += sizeof(u_long);
		if (a & ATTR_DIR_MOUNTSTATUS) size += sizeof(u_long);
	};
	if ((a = attrlist->fileattr) != 0) {
		if (a & ATTR_FILE_LINKCOUNT) size += sizeof(u_long);
		if (a & ATTR_FILE_TOTALSIZE) size += sizeof(off_t);
		if (a & ATTR_FILE_ALLOCSIZE) size += sizeof(off_t);
		if (a & ATTR_FILE_IOBLOCKSIZE) size += sizeof(size_t);
		if (a & ATTR_FILE_CLUMPSIZE) size += sizeof(off_t);
		if (a & ATTR_FILE_DEVTYPE) size += sizeof(u_long);
		if (a & ATTR_FILE_FILETYPE) size += sizeof(u_long);
		if (a & ATTR_FILE_FORKCOUNT) size += sizeof(u_long);
		if (a & ATTR_FILE_FORKLIST) size += sizeof(struct attrreference);
		if (a & ATTR_FILE_DATALENGTH) size += sizeof(off_t);
		if (a & ATTR_FILE_DATAALLOCSIZE) size += sizeof(off_t);
		if (a & ATTR_FILE_DATAEXTENTS) size += sizeof(extentrecord);
		if (a & ATTR_FILE_RSRCLENGTH) size += sizeof(off_t);
		if (a & ATTR_FILE_RSRCALLOCSIZE) size += sizeof(off_t);
		if (a & ATTR_FILE_RSRCEXTENTS) size += sizeof(extentrecord);
	};
	if ((a = attrlist->forkattr) != 0) {
		if (a & ATTR_FORK_TOTALSIZE) size += sizeof(off_t);
		if (a & ATTR_FORK_ALLOCSIZE) size += sizeof(off_t);
	};

	return size;
}


__private_extern__
unsigned long
DerivePermissionSummary(uid_t obj_uid, gid_t obj_gid, mode_t obj_mode,
			struct mount *mp, struct ucred *cred, struct proc *p)
{
	register gid_t *gp;
	unsigned long permissions;
	int i;

	if (obj_uid == UNKNOWNUID)
		obj_uid = console_user;

	/* User id 0 (root) always gets access. */
	if (cred->cr_uid == 0) {
		permissions = R_OK | W_OK | X_OK;
		goto Exit;
	};

	/* Otherwise, check the owner. */
	if (hfs_owner_rights(VFSTOHFS(mp), obj_uid, cred, p, false) == 0) {
		permissions = ((unsigned long)obj_mode & S_IRWXU) >> 6;
		goto Exit;
	}

	/* Otherwise, check the groups. */
	if (! (mp->mnt_flag & MNT_UNKNOWNPERMISSIONS)) {
		for (i = 0, gp = cred->cr_groups; i < cred->cr_ngroups; i++, gp++) {
			if (obj_gid == *gp) {
				permissions = ((unsigned long)obj_mode & S_IRWXG) >> 3;
				goto Exit;
			}
		}
	}

	/* Otherwise, settle for 'others' access. */
	permissions = (unsigned long)obj_mode & S_IRWXO;

Exit:
	return (permissions);    
}

