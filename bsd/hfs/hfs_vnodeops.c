/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*	@(#)hfs_vnodeops.c	3.0
 *
*	(c) 1997-1999	Apple Computer, Inc.  All Rights Reserved
 *	(c) 1990, 1992 NeXT Computer, Inc.  All Rights Reserved
 *	
 *
 *	hfs_vnodeops.c -- vnode layer for loadable Macintosh file system
 *
 *	MODIFICATION HISTORY:
 *	 	11-Nov-1999	Scott Roberts	Does not update if times have not changed (#2409116)
 *	 	 9-Nov-1999	Scott Roberts	Added cluster_close to hfs_fsync(#2398208)
 *       9-Nov-1999	Don Brady	Fix locking bug in hfs_close [#2399157].
 *		15-Sep-1999	Pat Dirks	Changed hfs_setattrlist to allow changing flags on plain-HFS volumes w/o ownership [#2365108];
 *								Changed to use hfs_write_access instead of obsolete hfs_writepermission uniformly throughout.
 *       7-Sep-1999	Don Brady	Add HFS Plus hard-link support.
 *		 8-Sep-1999		Pat Dirks	Changed hfs_rename to change mod. date on parent directory [#2297825].
 *		26-Aug-1999		Pat Dirks	Changed hfs_chflags to allow locking on HFS volumes w. write access only as workaround [#2313439].
 *       2-Sep-1999     Pat Dirks       Fixed hfs_pathconf to return same info for hfs/hfs+ for max. name length [#2382208]
 *	26-Aug-1999	Pat Dirks	Changed hfs_chflags to allow locking on HFS volumes w. write access only as workaround [#2313439].
*       24-Jul-1999 	Earsh Nandkeshwar	Rewrote readdirattr.
*	15-Jul-1999	Pat Dirks	Fixed hfs_readdir to return EINVAL if design assumption of uio->uio_iovcnt == 1 is violated
 *								and cleaned up call to uiomove to check space available first.
 *       2-Jul-1999     Pat Dirks       Fixed hfs_setattrlist to ignore attempts to set null volume name (#2331829).
 *      18-May-1999	Don Brady		Add support for rooting from HFS Plus.
 *	 4-May-1999	Don Brady		Split off hfs_search.c
 *      15-Apr-1999	Don Brady		Change va_nlink back to 1 for directories in hfs_getattr.
 *       6-Apr-1999	Don Brady		Fix deference of NULL h_sibling in hfs_chid.
 *  29-Mar-1999 Scott Roberts	Put in the correct . and .. entries for readdir
 *  22-Mar-1999 Don Brady		Add UFS delete semantic support to hfs_remove.
 *       1-Mar-1999	Scott Roberts	h_meta is now released when the complex vnode is relesed
 *      26-Feb-1999	Pat Dirks (copied by Chw) Fixed hfs_lookup to check for
 *                                error return on vget.
 *      25-Feb-1999     Pat Dirks       Fixed hfs_remove to use a local copy of the h_sibling pointer around vnode_uncache.
 *	 3-Feb-1999	Pat Dirks		Changed to stop updating wrapper volume name in MDB since wrapper volume's
 *								catalog isn't updated and this inconsistency trips Disk First Aid's checks.
 *	22-Jan-1999	Pat Dirks		Changed hfs_rename, hfs_remove, and hfs_rmdir to call cache_purge.
 *	22-Jan-1999	Don Brady		After calling hfsMoveRename call hfs_getcatalog to get new name.
 *	12-Jan-1999	Don Brady		Fixed the size of ATTR_CMN_NAME buffer to NAME_MAX + 1.
 *	 8-Jan-1999	Pat Dirks		Added hfs_writepermission and change hfs_setattrlist to use it instead of
 *								including an incorrect derivative of hfs_access in-line.
 *	15-Dec-1998 Pat Dirks		Changed setattrlist to do permission checking as appropriate (Radar #2290212).
 *	17-Nov-1998 Scott Roberts	Added support for long volume names in SetAttrList().
 *	6-Nov-1998 Don Brady		Add support for UTF-8 names.
 *	 3-Nov-1998	Umesh Vaishampayan	Changes to deal with "struct timespec"
 *						change in the kernel.	
 *  21-Oct-1998 Scott Roberts	Added support for advisory locking (Radar #2237914).
 *  25-Sep-1998 Don Brady		Changed hfs_exchange to call hfs_chid after updating catalog (radar #2276605).
 *	23-Sep-1998 Don Brady		hfs_setattrlist now calls hfs_chown and hfs_chmod to change values.
 *	15-Sep-1998 Pat Dirks		Cleaned up vnode unlocking on various error exit paths and changed
 *								to use new error stub routines in place of hfs_mknod and hfs_link.
 *  16-Sep-1998	Don Brady		When renaming a volume in hfs_setattrlist, also update hfs+ wrapper name (radar #2272925).
 *   1-Sep-1998	Don Brady		Fix uninitiazed time variable in hfs_makenode (radar #2270372).
 *  31-Aug-1998	Don Brady		Adjust change time for DST in hfs_update (radar #2265075).
 *  12-Aug-1998	Don Brady		Update complex node name in hfs_rename (radar #2262111).
 *   5-Aug-1998	Don Brady		In hfs_setattrlist call MacToVFSError after calling UpdateCatalogNode (radar #2261247).
 *  21-Jul-1998	Don Brady		Fixed broken preflight in hfs_getattrlist.
 *      17-Jul-1998	Clark Warner		Fixed the one left out case of freeing M_NAMEI in hfs_abort
 *	13-Jul-1998	Don Brady		Add uio_resid preflight check to hfs_search (radar #2251855).
 *	30-Jun-1998	Scott Roberts	        Changed hfs_makenode and its callers to free M_NAMEI.
 *	29-Jun-1998	Don Brady		Fix unpacking order in UnpackSearchAttributeBlock (radar #2249248).
 *	13-Jun-1998	Scott Roberts		Integrated changes to hfs_lock (radar #2237243).
 *	 4-Jun-1998	Pat Dirks		Split off hfs_lookup.c and hfs_readwrite.c
 *	 3-Jun-1998	Don Brady		Fix hfs_rename bugs (radar #2229259, #2239823, 2231108 and #2237380).
 *								Removed extra vputs in hfs_rmdir (radar #2240309).
 *	28-May-1998	Don Brady		Fix hfs_truncate to correctly extend files (radar #2237242).
 *	20-May-1998	Don Brady		In hfs_close shrink the peof to the smallest size neccessary (radar #2230094).
 *	 5-May-1998	Don Brady		Fixed typo in hfs_rename (apply H_FILEID macro to VTOH result).
 *	29-Apr-1998	Joe Sokol		Don't do cluster I/O when logical block size is not 4K multiple.
 *	28-Apr-1998	Pat Dirks		Cleaned up unused variable physBlockNo in hfs_write.
 *	28-Apr-1998	Joe Sokol		Touched up support for cluster_read/cluster_write and enabled it.
 *	27-Apr-1998	Don Brady		Remove some DEBUG_BREAK calls in DbgVopTest.
 *	24-Apr-1998	Pat Dirks		Fixed read logic to read-ahead only ONE block, and of only logBlockSize instead of 64K...
 *								Added calls to brelse() on errors from bread[n]().
 *								Changed logic to add overall length field to AttrBlockSize only on attribute return operations.
 *	23-Apr-1998	Don Brady		The hfs_symlink call is only supported on HFS Plus disks.
 *	23-Apr-1998	Deric Horn		Fixed hfs_search bug where matches were skipped when buffer was full.
 *	22-Apr-1998	Scott Roberts		Return on error if catalog mgr returns an error in truncate.
 *	21-Apr-1998	Don Brady		Fix up time/date conversions.
 *	20-Apr-1998	Don Brady		Remove course-grained hfs metadata locking.
 *	17-Apr-1998	Pat Dirks		Officially enabled searchfs in vops table.
 *	17-Apr-1998	Deric Horn		Bug fixes to hfs_search, reenabled searchfs trap for upcoming kernel build.
 *	15-Apr-1998	Don Brady		Add locking for HFS B-trees. Don't lock file meta lock for VSYSTEM files.
 *								Don't call VOP_UPDATE for system files. Roll set_time into hfs_update.
 *	14-Apr-1998	Pat Dirks		Cleaned up fsync to skip complex nodes and not hit sibling nodes.
 *	14-Apr-1998	Deric Horn		Added hfs_search() and related routines for searchfs() support.
 *	14-Apr-1998	Scott Roberts		Fixed paramaters to ExchangeFileIDs()
 *	13-Apr-1998	Pat Dirks		Changed to update H_HINT whenever hfs_getcatalog was called.
 *	 8-Apr-1998	Pat Dirks		Added page-in and page-out passthrough routines to keep MapFS happy.
 *	 6-Apr-1998	Pat Dirks		Changed hfs_write to clean up code and fix bug that caused
 *								zeroes to be interspersed in data.  Added debug printf to hfs_read.
 *	 6-Apr-1998	Scott Roberts		Added complex file support.
 *	02-apr-1998	Don Brady		UpdateCatalogNode now takes parID and name as input.
 *	31-mar-1998	Don Brady		Sync up with final HFSVolumes.h header file.
 *	27-mar-1998	Don Brady		Check result from UFSToHFSStr to make sure hfs/hfs+ names are not greater than 31 characters.
 *	27-mar-1998	chw			minor link fixes.
 *	19-Mar-1998	ser			Added hfs_readdirattr.
 *	17-Mar-1998	ser			Removed CheckUserAccess. Added code to implement ExchangeFileIDs
 *	16-Mar-1998	Pat Dirks		Fixed logic in hfs_read to properly account for space
 *								remaining past selected offset and avoid premature panic.
 *	16-jun-1997	Scott Roberts
 *	   Dec-1991	Kevin Wells at NeXT:
 *			Significantly modified for Macintosh file system.
 *			Added support for NFS exportability.
 *	25-Jun-1990	Doug Mitchell at NeXT:
 *			Created (for DOS file system).
 */

#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/file.h>
#include <sys/dirent.h>
#include <sys/stat.h>
#include <sys/buf.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/namei.h>
#include <sys/attr.h>
#include <sys/ubc.h>
#include <sys/utfconv.h>
#include <miscfs/specfs/specdev.h>
#include <miscfs/fifofs/fifo.h>

#include <machine/spl.h>

#include <sys/kdebug.h>

#include	"hfs.h"
#include	"hfs_lockf.h"
#include	"hfs_dbg.h"
#include	"hfs_mount.h"

#include "hfscommon/headers/CatalogPrivate.h"
#include "hfscommon/headers/BTreesInternal.h"
#include "hfscommon/headers/FileMgrInternal.h"
#include "hfscommon/headers/HFSUnicodeWrappers.h"

#define OWNERSHIP_ONLY_ATTRS (ATTR_CMN_OWNERID | ATTR_CMN_GRPID | ATTR_CMN_ACCESSMASK | ATTR_CMN_FLAGS)

#define MAKE_DELETED_NAME(NAME,FID) \
	    (void) sprintf((NAME), "%s%d", HFS_DELETE_PREFIX, (FID))


extern uid_t console_user;

/* Global vfs data structures for hfs */
int (**hfs_vnodeop_p)(void *);

/* external routines defined in hfs_vhash.c */
extern void hfs_vhashrem(struct hfsnode *hp);
extern int 	vinvalbuf_vhash(register struct vnode *vp, int flags, struct ucred *cred, struct proc *p);
extern void hfs_vhashmove( struct hfsnode *hp,UInt32 nodeID);
extern struct vnode * hfs_vhashget(dev_t dev, UInt32 nodeID, UInt8 forkType);

extern OSErr PositionIterator(CatalogIterator *cip, UInt32 offset, BTreeIterator *bip, UInt16 *op);

extern void hfs_name_CatToMeta(CatalogNodeData *nodeData, struct hfsfilemeta *fm);

extern groupmember(gid_t gid, struct ucred *cred);

extern void hfs_resolvelink(ExtendedVCB *vcb, CatalogNodeData *cndp);

static int hfs_makenode( int mode,
	dev_t rawdev, struct vnode *dvp, struct vnode **vpp,
	struct componentname *cnp, struct proc *p);

static void hfs_chid(struct hfsnode *hp, u_int32_t fid, u_int32_t pid, char* name);

static int hfs_write_access(struct vnode *vp, struct ucred *cred, struct proc *p, Boolean considerFlags);

static int hfs_chown( struct vnode *vp, uid_t uid, gid_t gid, struct ucred *cred, struct proc *p);
static int hfs_chmod( struct vnode *vp, int mode, struct ucred *cred, struct proc *p);
static int hfs_chflags( struct vnode *vp, u_long flags, struct ucred *cred, struct proc *p);


int hfs_cache_lookup();		/* in hfs_lookup.c */
int hfs_lookup();		/* in hfs_lookup.c */
int hfs_read();			/* in hfs_readwrite.c */
int hfs_write();		/* in hfs_readwrite.c */
int hfs_ioctl();		/* in hfs_readwrite.c */
int hfs_select();		/* in hfs_readwrite.c */
int hfs_mmap();			/* in hfs_readwrite.c */
int hfs_seek();			/* in hfs_readwrite.c */
int hfs_bmap();			/* in hfs_readwrite.c */
int hfs_strategy();		/* in hfs_readwrite.c */
int hfs_reallocblks();	/* in hfs_readwrite.c */
int hfs_truncate();		/* in hfs_readwrite.c */
int hfs_allocate();		/* in hfs_readwrite.c */
int hfs_pagein();		/* in hfs_readwrite.c */
int hfs_pageout();		/* in hfs_readwrite.c */
int hfs_search();		/* in hfs_search.c */
int hfs_bwrite();		/* in hfs_readwrite.c */
int hfs_link();			/* in hfs_link.c */
int hfs_blktooff();		/* in hfs_readwrite.c */
int hfs_offtoblk();		/* in hfs_readwrite.c */
int hfs_cmap();		/* in hfs_readwrite.c */

/*****************************************************************************
*
*	Operations on vnodes
*
*****************************************************************************/

/*
 * Create a regular file
#% create	dvp	L U U
#% create	vpp	- L -
#
 vop_create {
     IN WILLRELE struct vnode *dvp;
     OUT struct vnode **vpp;
     IN struct componentname *cnp;
     IN struct vattr *vap;
	
     We are responsible for freeing the namei buffer,
	 it is done in hfs_makenode()
*/

static int
hfs_create(ap)
struct vop_create_args /* {
    struct vnode *a_dvp;
    struct vnode **a_vpp;
    struct componentname *a_cnp;
    struct vattr *a_vap;
} */ *ap;
{
	struct proc		*p = current_proc();
    int				retval;
    int				mode = MAKEIMODE(ap->a_vap->va_type, ap->a_vap->va_mode);
    DBG_FUNC_NAME("create");
    DBG_VOP_LOCKS_DECL(2);
    DBG_VOP_PRINT_FUNCNAME();
    DBG_VOP_PRINT_VNODE_INFO(ap->a_dvp);
    DBG_VOP_PRINT_CPN_INFO(ap->a_cnp);

    DBG_VOP_LOCKS_INIT(0,ap->a_dvp, VOPDBG_LOCKED, VOPDBG_UNLOCKED, VOPDBG_UNLOCKED, VOPDBG_POS);
    DBG_VOP_LOCKS_INIT(1,*ap->a_vpp, VOPDBG_IGNORE, VOPDBG_LOCKED, VOPDBG_IGNORE, VOPDBG_POS);
    DBG_VOP_CONT(("\tva_type %d va_mode 0x%x\n",
             ap->a_vap->va_type, ap->a_vap->va_mode));

#if HFS_DIAGNOSTIC
    DBG_HFS_NODE_CHECK(ap->a_dvp);
    DBG_ASSERT(ap->a_dvp->v_type == VDIR);
    if(ap->a_vap == NULL) {
        panic("NULL attr on create");
    }

    switch(ap->a_vap->va_type) {
        case VDIR:
    		VOP_ABORTOP(ap->a_dvp, ap->a_cnp);
            vput(ap->a_dvp);
            DBG_VOP_LOCKS_TEST(EISDIR);
            return (EISDIR);	/* use hfs_mkdir instead */
        case VREG:
        case VLNK:
            break;
        default:
            DBG_ERR(("%s: INVALID va_type: %d, %s, %s\n", funcname, ap->a_vap->va_type, H_NAME(VTOH(ap->a_dvp)), ap->a_cnp->cn_nameptr));
    		VOP_ABORTOP(ap->a_dvp, ap->a_cnp);
            vput(ap->a_dvp);
            DBG_VOP_LOCKS_TEST(EINVAL);
            return (EINVAL);
            }
//    if(ap->a_vap->va_mode & (VSUID | VSGID | VSVTX)) {
//        DBG_ERR(("%s: INVALID va_mode (%o): %s, %s\n", funcname, ap->a_vap->va_mode, H_NAME(VTOH(ap->a_dvp)), ap->a_cnp->cn_nameptr));
//        DBG_VOP_LOCKS_TEST(EINVAL);
//		  VOP_ABORTOP(ap->a_dvp, ap->a_cnp);
//        vput(ap->a_dvp);
//        return (EINVAL);		/* Can't do these */
//    };
#endif

	/* Create the vnode */
    retval = hfs_makenode(mode, 0, ap->a_dvp, ap->a_vpp, ap->a_cnp, p);
    DBG_VOP_UPDATE_VP(1, *ap->a_vpp);

    if (retval != E_NONE) {
        DBG_ERR(("%s: hfs_makenode FAILED: %s, %s\n", funcname, ap->a_cnp->cn_nameptr, H_NAME(VTOH(ap->a_dvp))));
	}
    DBG_VOP_LOCKS_TEST(retval);
    return (retval);
}


/*
 * Mknod vnode call

#% mknod	dvp	L U U
#% mknod	vpp	- X -
#
 vop_mknod {
     IN WILLRELE struct vnode *dvp;
     OUT WILLRELE struct vnode **vpp;
     IN struct componentname *cnp;
     IN struct vattr *vap;
     */
/* ARGSUSED */

static int
hfs_mknod(ap)
struct vop_mknod_args /* {
    struct vnode *a_dvp;
    struct vnode **a_vpp;
    struct componentname *a_cnp;
    struct vattr *a_vap;
} */ *ap;
{
	struct vattr *vap = ap->a_vap;
	struct vnode **vpp = ap->a_vpp;
    struct proc *p = current_proc();
	dev_t rawdev = 0;
	int error;

	if (VTOVCB(ap->a_dvp)->vcbSigWord != kHFSPlusSigWord) {
		VOP_ABORTOP(ap->a_dvp, ap->a_cnp);
		vput(ap->a_dvp);
		return (EOPNOTSUPP);
	}

	if (vap->va_rdev != VNOVAL) {
		/*
		 * Want to be able to use this to make badblock
		 * inodes, so don't truncate the dev number.
		 */
		rawdev = vap->va_rdev;
	}

	/* Create the vnode */
	error = hfs_makenode(MAKEIMODE(vap->va_type, vap->va_mode),
				rawdev, ap->a_dvp, vpp, ap->a_cnp, p);

	if (error != E_NONE) {
		return (error);
	}

	/*
	 * Remove inode so that it will be reloaded by lookup and
	 * checked to see if it is an alias of an existing vnode.
	 * Note: unlike UFS, we don't bash v_type here.
	 */
	vput(*vpp);
	vgone(*vpp);
	*vpp = 0;
	return (0);
}


/*
 * mkcomplex vnode call
 *

#% mkcomplex	dvp	L U U
#% mkcomplex	vpp	- L -
#
vop_mkcomplex {
	IN WILLRELE struct vnode *dvp;
	OUT struct vnode **vpp;
	IN struct componentname *cnp;
	IN struct vattr *vap;
	IN u_long type;
}

 */
 
static int
hfs_mkcomplex(ap)
struct vop_mkcomplex_args /* {
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
	struct vattr *a_vap;
	u_long a_type;
} */ *ap;
{
    int		retval = E_NONE;
    DBG_FUNC_NAME("make_complex");
    DBG_VOP_LOCKS_DECL(2);
    DBG_VOP_PRINT_FUNCNAME();
    DBG_VOP_PRINT_VNODE_INFO(ap->a_dvp);
    DBG_VOP_PRINT_CPN_INFO(ap->a_cnp);DBG_VOP_CONT(("\n"));

    DBG_VOP_LOCKS_INIT(0,ap->a_dvp, VOPDBG_LOCKED, VOPDBG_UNLOCKED, VOPDBG_UNLOCKED, VOPDBG_POS);
    DBG_VOP_LOCKS_INIT(1,*ap->a_vpp, VOPDBG_IGNORE, VOPDBG_LOCKED, VOPDBG_IGNORE, VOPDBG_POS);

    retval = VOP_CREATE(ap->a_dvp, ap->a_vpp, ap->a_cnp, ap->a_vap);

    DBG_VOP_LOCKS_TEST(retval);
    return retval;
}


/*
 * Open called.
#% open		vp	L L L
#
 vop_open {
     IN struct vnode *vp;
     IN int mode;
     IN struct ucred *cred;
     IN struct proc *p;
     */


static int
hfs_open(ap)
struct vop_open_args /* {
    struct vnode *a_vp;
    int  a_mode;
    struct ucred *a_cred;
    struct proc *a_p;
} */ *ap;
{
	struct hfsnode	*hp = VTOH(ap->a_vp);
	int				retval = E_NONE;
	DBG_FUNC_NAME("open");
	DBG_VOP_LOCKS_DECL(1);
	DBG_VOP_PRINT_FUNCNAME();
	DBG_VOP_CONT((" "));DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP_CONT(("\n"));
	DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_POS);

    if (ap->a_vp->v_type == VREG)	 /* Only files */
      {	
        /*
         * Files marked append-only must be opened for appending.
         */
        if ((hp->h_meta->h_pflags & APPEND) &&
            (ap->a_mode & (FWRITE | O_APPEND)) == FWRITE)
            retval = EPERM;
        }


    DBG_VOP_LOCKS_TEST(retval);
    return (retval);
}

/*
 * Close called.
 *
 * Update the times on the hfsnode.
#% close	vp	U U U
#
 vop_close {
     IN struct vnode *vp;
     IN int fflag;
     IN struct ucred *cred;
     IN struct proc *p;
     */


static int
hfs_close(ap)
struct vop_close_args /* {
    struct vnode *a_vp;
    int  a_fflag;
    struct ucred *a_cred;
    struct proc *a_p;
} */ *ap;
{
    register struct vnode	*vp = ap->a_vp;
    struct hfsnode 			*hp = VTOH(vp);
    struct proc				*p = ap->a_p;
	FCB						*fcb;
    struct timeval 			tv;
	off_t					leof;
	u_long					blks, blocksize;
    int 					retval = E_NONE;
    int						devBlockSize;
    int						forceUpdate = 0;

	DBG_FUNC_NAME("close");
	DBG_VOP_LOCKS_DECL(1);
	DBG_VOP_PRINT_FUNCNAME();
	DBG_VOP_CONT((" "));DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP_CONT(("\n"));
	DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_UNLOCKED, VOPDBG_UNLOCKED, VOPDBG_UNLOCKED, VOPDBG_POS);

	simple_lock(&vp->v_interlock);
	if (vp->v_usecount > (UBCINFOEXISTS(vp) ? 2 : 1)) {
		tv = time;
		HFSTIMES(hp, &tv, &tv);
	}
	simple_unlock(&vp->v_interlock);

	/*
	 * VOP_CLOSE can be called with vp locked (from vclean).
	 * We check for this case using VOP_ISLOCKED and bail.
	 *
	 * also, ignore complex nodes; there's no data associated with them.
	 */
	if (H_FORKTYPE(hp) == kDirectory || VOP_ISLOCKED(vp)) {
		DBG_VOP_LOCKS_TEST(E_NONE);
		return E_NONE;
	};

	fcb = HTOFCB(hp);
	leof = fcb->fcbEOF;
	
	if (leof != 0) {
		enum vtype our_type = vp->v_type;
		u_long our_id = vp->v_id;
		
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
		/*
		 * Since we can context switch in vn_lock our vnode
		 * could get recycled (eg umount -f).  Double check
		 * that its still ours.
		 */
		if (vp->v_type != our_type || vp->v_id != our_id) {
			VOP_UNLOCK(vp, 0, p);
			DBG_VOP_LOCKS_TEST(E_NONE);
			return(E_NONE);
		}

		/* Last chance to explicitly zero out the areas that are currently marked invalid: */
		VOP_DEVBLOCKSIZE(hp->h_meta->h_devvp, &devBlockSize);
		while (!CIRCLEQ_EMPTY(&hp->h_invalidranges)) {
    		struct rl_entry *invalid_range = CIRCLEQ_FIRST(&hp->h_invalidranges);
    		off_t start = invalid_range->rl_start;
    		off_t end = invalid_range->rl_end;
    		
    		/* The range about to be written must be validated first, so that
    		   VOP_CMAP() will return the appropriate mapping for the cluster code: */
    		rl_remove(start, end, &hp->h_invalidranges);
    		
			retval = cluster_write(vp, (struct uio *) 0, fcb->fcbEOF, invalid_range->rl_end + 1, invalid_range->rl_start,
			 (off_t)0, devBlockSize, IO_HEADZEROFILL | 0x8000);
			 
			 forceUpdate = 1;
		};
		/* Make sure the EOF gets written out at least once more
		   now that all invalid ranges have been zero-filled and validated: */
		if (forceUpdate) hp->h_nodeflags |= IN_MODIFIED;
		
		blocksize = HTOVCB(hp)->blockSize;
		blks = leof / blocksize;
		if (((off_t)blks * (off_t)blocksize) != leof)
			blks++;
	
		/*
		 * Shrink the peof to the smallest size neccessary to contain the leof.
		 */
		if (((off_t)blks * (off_t)blocksize) < fcb->fcbPLen) {
	 		retval = VOP_TRUNCATE(vp, leof, IO_NDELAY, ap->a_cred, p);
		}
		cluster_push(vp);
		
		/* If the VOP_TRUNCATE didn't happen to flush the vnode's information out to
		   disk, force it to be updated now that all invalid ranges have been zero-filled
		   and validated:
		 */
		if (hp->h_nodeflags & IN_MODIFIED) VOP_UPDATE(vp, &time, &time, 0);
		
		VOP_UNLOCK(vp, 0, p);
	}

	DBG_VOP_LOCKS_TEST(retval);
	return (retval);
}

/*
#% access	vp	L L L
#
 vop_access {
     IN struct vnode *vp;
     IN int mode;
     IN struct ucred *cred;
     IN struct proc *p;

     */

static int
hfs_access(ap)
struct vop_access_args /* {
    struct vnode *a_vp;
    int  a_mode;
    struct ucred *a_cred;
    struct proc *a_p;
} */ *ap;
{
    struct vnode *vp 			= ap->a_vp;
    struct ucred *cred 			= ap->a_cred;
    struct hfsnode *hp 			= VTOH(vp);
    ExtendedVCB	*vcb			= HTOVCB(hp);
    register gid_t *gp;
    mode_t mask, mode;
    Boolean isHFSPlus;
    int retval 					= E_NONE;
    int i;
    DBG_FUNC_NAME("access");
    DBG_VOP_LOCKS_DECL(1);
//    DBG_VOP_PRINT_FUNCNAME();
//    DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP_CONT(("\n"));

    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_POS);
   
	 mode 		= ap->a_mode;
     isHFSPlus	= (vcb->vcbSigWord == kHFSPlusSigWord );

     /*
      * Disallow write attempts on read-only file systems;
      * unless the file is a socket, fifo, or a block or
      * character device resident on the file system.
      */
     if (mode & VWRITE) {
         switch (vp->v_type) {
         case VDIR:
         case VLNK:
         case VREG:
             if (VTOVFS(vp)->mnt_flag & MNT_RDONLY)
                 return (EROFS);
             break;
		default:
			break;
         }
     }

     /* If immutable bit set, nobody gets to write it. */
     if ((mode & VWRITE) && (hp->h_meta->h_pflags & IMMUTABLE))
         return (EPERM);

     /* Otherwise, user id 0 always gets access. */
     if (ap->a_cred->cr_uid == 0) {
         retval = 0;
         goto Exit;
     };

     mask = 0;

    /* Otherwise, check the owner. */
    if (hfs_owner_rights(vp, cred, ap->a_p, false) == 0) {
        if (mode & VEXEC)
            mask |= S_IXUSR;
        if (mode & VREAD)
            mask |= S_IRUSR;
        if (mode & VWRITE)
            mask |= S_IWUSR;
        retval =  ((hp->h_meta->h_mode & mask) == mask ? 0 : EACCES);
        goto Exit;
    }

    /* Otherwise, check the groups. */
    if (! (VTOVFS(vp)->mnt_flag & MNT_UNKNOWNPERMISSIONS)) {
	    for (i = 0, gp = cred->cr_groups; i < cred->cr_ngroups; i++, gp++) {
	        if (hp->h_meta->h_gid == *gp) {
	            if (mode & VEXEC)
	                mask |= S_IXGRP;
	            if (mode & VREAD)
	                mask |= S_IRGRP;
	            if (mode & VWRITE)
	                mask |= S_IWGRP;
	            retval = ((hp->h_meta->h_mode & mask) == mask ? 0 : EACCES);
				goto Exit;
	        }
	    };
	};

    /* Otherwise, check everyone else. */
    if (mode & VEXEC)
        mask |= S_IXOTH;
    if (mode & VREAD)
        mask |= S_IROTH;
    if (mode & VWRITE)
        mask |= S_IWOTH;
    retval = ((hp->h_meta->h_mode & mask) == mask ? 0 : EACCES);

Exit:
	DBG_VOP_LOCKS_TEST(retval);
	return (retval);    
}



/*
#% getattr	vp	= = =
#
 vop_getattr {
     IN struct vnode *vp;
     IN struct vattr *vap;
     IN struct ucred *cred;
     IN struct proc *p;

     */


/* ARGSUSED */
static int
hfs_getattr(ap)
struct vop_getattr_args /* {
    struct vnode *a_vp;
    struct vattr *a_vap;
    struct ucred *a_cred;
    struct proc *a_p;
} */ *ap;
{
    register struct vnode 	*vp = ap->a_vp;
    register struct hfsnode *hp = VTOH(vp);
    register struct vattr	*vap = ap->a_vap;
    struct timeval 			tv;
    DBG_FUNC_NAME("getattr");
    DBG_VOP_LOCKS_DECL(1);
    DBG_VOP_PRINT_FUNCNAME();
    DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP_CONT(("\n"));

    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_SAME, VOPDBG_SAME, VOPDBG_SAME, VOPDBG_POS);

    DBG_HFS_NODE_CHECK(ap->a_vp);

    tv = time;
    HFSTIMES(hp, &tv, &tv);

    vap->va_fsid = H_DEV(hp);
    vap->va_fileid = H_FILEID(hp);
    vap->va_mode = hp->h_meta->h_mode;
    if (VTOVFS(vp)->mnt_flag & MNT_UNKNOWNPERMISSIONS) {
    	vap->va_uid = (VTOHFS(vp)->hfs_uid == UNKNOWNUID) ? console_user : VTOHFS(vp)->hfs_uid;
    } else {
    	vap->va_uid = (hp->h_meta->h_uid == UNKNOWNUID) ? console_user : hp->h_meta->h_uid;
    };
    vap->va_gid = hp->h_meta->h_gid;
    if (vp->v_type == VDIR) {
        vap->va_size = hp->h_meta->h_size;
        vap->va_bytes = 0;
        vap->va_rdev = 0;
	vap->va_nlink = hp->h_meta->h_nlink;
		/* 
		 * account for hidden data nodes directory
		 */
		if ((H_FILEID(hp) == kRootDirID) &&
		    (VTOHFS(vp)->hfs_private_metadata_dir != 0)) {
			vap->va_size -= AVERAGE_HFSDIRENTRY_SIZE;
			vap->va_nlink--;
		}
    }
    else {
        vap->va_size = hp->fcbEOF;
        vap->va_bytes = hp->h_meta->h_size;

		if (vp->v_type == VBLK || vp->v_type == VCHR)
			vap->va_rdev = hp->h_meta->h_rdev;
		else
			vap->va_rdev = 0;

		if (hp->h_meta->h_metaflags & IN_DELETED)
			vap->va_nlink = 0;
#if HFS_HARDLINKS
		else if ((hp->h_meta->h_metaflags & IN_DATANODE) &&
			 (hp->h_meta->h_nlink > 0))
			vap->va_nlink = hp->h_meta->h_nlink;
#endif
		else
			vap->va_nlink = 1;

    }

    vap->va_atime.tv_nsec = 0;
    vap->va_atime.tv_sec = hp->h_meta->h_atime;
    vap->va_mtime.tv_nsec = 0;
    vap->va_mtime.tv_sec = hp->h_meta->h_mtime;
    vap->va_ctime.tv_nsec = 0;
    vap->va_ctime.tv_sec = hp->h_meta->h_ctime;
    vap->va_flags = hp->h_meta->h_pflags;
    vap->va_gen = 0;
    /* this doesn't belong here */
    if (vp->v_type == VBLK)
        vap->va_blocksize = BLKDEV_IOSIZE;
    else if (vp->v_type == VCHR)
        vap->va_blocksize = MAXPHYSIO;
    else
        vap->va_blocksize = VTOVFS(vp)->mnt_stat.f_iosize;
	vap->va_type = vp->v_type;
    vap->va_filerev = 0;

    DBG_VOP_LOCKS_TEST(E_NONE);
    return (E_NONE);
}

/*
 * Set attribute vnode op. called from several syscalls
#% setattr	vp	L L L
#
 vop_setattr {
     IN struct vnode *vp;
     IN struct vattr *vap;
     IN struct ucred *cred;
     IN struct proc *p;

     */

static int
hfs_setattr(ap)
struct vop_setattr_args /* {
struct vnode *a_vp;
struct vattr *a_vap;
struct ucred *a_cred;
struct proc *a_p;
} */ *ap;
{
    struct vnode 	*vp = ap->a_vp;
    struct hfsnode 	*hp = VTOH(vp);
    struct vattr 	*vap = ap->a_vap;
    struct ucred 	*cred = ap->a_cred;
    struct proc 	*p = ap->a_p;
    struct timeval 	atimeval, mtimeval;
    int				retval;
    DBG_FUNC_NAME("setattr");
    DBG_VOP_LOCKS_DECL(1);
    DBG_VOP_PRINT_FUNCNAME();
    DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP_CONT(("\n"));
    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_POS);
    WRITE_CK(vp, funcname);
    DBG_HFS_NODE_CHECK(ap->a_vp);

    /*
     * Check for unsettable attributes.
     */
    if ((vap->va_type != VNON) || (vap->va_nlink != VNOVAL) ||
        (vap->va_fsid != VNOVAL) || (vap->va_fileid != VNOVAL) ||
        (vap->va_blocksize != VNOVAL) || (vap->va_rdev != VNOVAL) ||
        ((int)vap->va_bytes != VNOVAL) || (vap->va_gen != VNOVAL)) {
        retval = EINVAL;
        goto ErrorExit;
    }

    if (vap->va_flags != VNOVAL) {
        if (VTOVFS(vp)->mnt_flag & MNT_RDONLY) {
            retval = EROFS;
            goto ErrorExit;
        };
        if ((retval = hfs_chflags(vp, vap->va_flags, cred, p))) {
            goto ErrorExit;
        };
        if (vap->va_flags & (IMMUTABLE | APPEND)) {
            retval = 0;
            goto ErrorExit;
        };
    }

    if (hp->h_meta->h_pflags & (IMMUTABLE | APPEND)) {
        retval = EPERM;
        goto ErrorExit;
    };
    /*
     * Go through the fields and update iff not VNOVAL.
     */
    if (vap->va_uid != (uid_t)VNOVAL || vap->va_gid != (gid_t)VNOVAL) {
        if (VTOVFS(vp)->mnt_flag & MNT_RDONLY) {
            retval = EROFS;
            goto ErrorExit;
        };
        if ((retval = hfs_chown(vp, vap->va_uid, vap->va_gid, cred, p))) {
            goto ErrorExit;
        };
    }
    if (vap->va_size != VNOVAL) {
        /*
         * Disallow write attempts on read-only file systems;
         * unless the file is a socket, fifo, or a block or
         * character device resident on the file system.
         */
        switch (vp->v_type) {
            case VDIR:
                retval = EISDIR;
                goto ErrorExit;
            case VLNK:
            case VREG:
                if (VTOVFS(vp)->mnt_flag & MNT_RDONLY) {
                    retval = EROFS;
                    goto ErrorExit;
                };
                break;
            default:
                break;
        }
        if ((retval = VOP_TRUNCATE(vp, vap->va_size, 0, cred, p))) {
            goto ErrorExit;
        };
    }
    hp = VTOH(vp);
    if (vap->va_atime.tv_sec != VNOVAL || vap->va_mtime.tv_sec != VNOVAL) {
        if (VTOVFS(vp)->mnt_flag & MNT_RDONLY) {
            retval = EROFS;
            goto ErrorExit;
        };
        if (((retval = hfs_owner_rights(vp, cred, p, true)) != 0) &&
            ((vap->va_vaflags & VA_UTIMES_NULL) == 0 ||
             (retval = VOP_ACCESS(vp, VWRITE, cred, p)))) {
            goto ErrorExit;
        };
        if (vap->va_atime.tv_sec != VNOVAL)
            hp->h_nodeflags |= IN_ACCESS;
        if (vap->va_mtime.tv_sec != VNOVAL) {
            hp->h_nodeflags |= IN_CHANGE | IN_UPDATE;
	    /*
	     * The utimes system call can reset the modification time
	     * but it doesn't know about the HFS+ create time.  So we
	     * need to insure that the creation time is always at least
	     * as old as the modification time.
	     */
	    if (( VTOVCB(vp)->vcbSigWord == kHFSPlusSigWord )  &&
	        ( H_FILEID(hp) != kRootDirID )  &&
	        ( vap->va_mtime.tv_sec < hp->h_meta->h_crtime ))
		hp->h_meta->h_crtime = vap->va_mtime.tv_sec;
	}
        atimeval.tv_sec = vap->va_atime.tv_sec;
        atimeval.tv_usec = 0;
        mtimeval.tv_sec = vap->va_mtime.tv_sec;
        mtimeval.tv_usec = 0;
        if ((retval = VOP_UPDATE(vp, &atimeval, &mtimeval, 1))) {
            goto ErrorExit;
        };
    }
    retval = 0;
    if (vap->va_mode != (mode_t)VNOVAL) {
        if (VTOVFS(vp)->mnt_flag & MNT_RDONLY) {
            retval = EROFS;
            goto ErrorExit;
        };
        retval = hfs_chmod(vp, (int)vap->va_mode, cred, p);
    };

ErrorExit: ;

    DBG_VOP(("hfs_setattr: returning %d...\n", retval));
    DBG_VOP_LOCKS_TEST(retval);
    return (retval);
}


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

static int
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
    struct hfsnode *hp = VTOH(vp);
    struct attrlist *alist = ap->a_alist;
    int error = 0;
    struct hfsCatalogInfo catInfo;
    struct hfsCatalogInfo *catInfoPtr = NULL;
    struct timeval 			tv;
    int fixedblocksize;
    int attrblocksize;
    int attrbufsize;
    void *attrbufptr;
    void *attrptr;
    void *varptr;
    u_int32_t fileID;
    DBG_FUNC_NAME("getattrlist");
    DBG_VOP_LOCKS_DECL(1);

    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_SAME, VOPDBG_SAME, VOPDBG_SAME, VOPDBG_POS);
    DBG_HFS_NODE_CHECK(ap->a_vp);
    DBG_VOP(("%s: Common attr:0x%lx, buff size Ox%lX,\n",funcname, (u_long)alist->commonattr,(u_long)ap->a_uio->uio_resid));

    DBG_ASSERT(ap->a_uio->uio_rw == UIO_READ);

    if ((alist->bitmapcount != ATTR_BIT_MAP_COUNT) ||
        ((alist->commonattr & ~ATTR_CMN_VALIDMASK) != 0) ||
        ((alist->volattr & ~ATTR_VOL_VALIDMASK) != 0) ||
        ((alist->dirattr & ~ATTR_DIR_VALIDMASK) != 0) ||
        ((alist->fileattr & ~ATTR_FILE_VALIDMASK) != 0) ||
        ((alist->forkattr & ~ATTR_FORK_VALIDMASK) != 0)) {
        DBG_ERR(("%s: bad attrlist\n", funcname));
        DBG_VOP_LOCKS_TEST(EINVAL);
        return EINVAL;
        };

    /* Requesting volume information requires setting the ATTR_VOL_INFO bit and
        volume info requests are mutually exclusive with all other info requests: */
   if ((alist->volattr != 0) && (((alist->volattr & ATTR_VOL_INFO) == 0) ||
        (alist->dirattr != 0) || (alist->fileattr != 0) || (alist->forkattr != 0)
		)) {
        DBG_ERR(("%s: conflicting information requested\n", funcname));
        DBG_VOP_LOCKS_TEST(EINVAL);
        return EINVAL;
        };

    /* Reject requests for unsupported options for now: */
    if ((alist->commonattr & (ATTR_CMN_NAMEDATTRCOUNT | ATTR_CMN_NAMEDATTRLIST)) ||
        (alist->fileattr & (ATTR_FILE_FILETYPE | ATTR_FILE_FORKCOUNT | ATTR_FILE_FORKLIST))) {
        DBG_ERR(("%s: illegal bits in attlist\n", funcname));
        DBG_VOP_LOCKS_TEST(EINVAL);
        return EINVAL;
        };

	/* Requesting volume information requires root vnode */ 
    if ((alist->volattr) && (H_FILEID(hp) != kRootDirID)) {
        DBG_ERR(("%s: not root vnode\n", funcname));
        DBG_VOP_LOCKS_TEST(EINVAL);
        return EINVAL;
    	};


	/* Update times if needed */
	tv = time;
    HFSTIMES(hp, &tv, &tv);

	/* If a FileID (ATTR_CMN_OBJPERMANENTID) is requested on an HFS volume we must be sure
		to create the thread record before returning it:
		*/
	if ((vp->v_type == VREG) &&
		(alist->commonattr & ATTR_CMN_OBJPERMANENTID)) {
		/* Only HFS-Plus volumes are guaranteed to have a thread record in place already: */
		if (VTOVCB(vp)->vcbSigWord != kHFSPlusSigWord) {
			/* Create a thread record and return the FileID [which is the file's fileNumber] */
			/* lock catalog b-tree */
			error = hfs_metafilelocking(VTOHFS(vp), kHFSCatalogFileID, LK_EXCLUSIVE, ap->a_p);
			error = hfsCreateFileID(VTOVCB(vp), H_DIRID(hp), H_NAME(hp), H_HINT(hp), &fileID);
			(void) hfs_metafilelocking(VTOHFS(vp), kHFSCatalogFileID, LK_RELEASE, ap->a_p);
			if (error) {
				DBG_VOP_LOCKS_TEST(error);
				DBG_ERR(("hfs_getattrlist: error %d on CreateFileIDRef.\n", error));
				return error;
			};
			DBG_ASSERT(fileID == H_FILEID(hp));
		};
	};

	/* Asking for data fork attributes from the rsrc fork is not supported */
	if ((H_FORKTYPE(hp) == kRsrcFork) && (alist->fileattr & HFS_ATTR_FILE_LOOKUPMASK)) {
		return (EINVAL);
	}
	
    /*
	 * Avoid unnecessary catalog lookups for volume info which is available directly
	 * in the VCB and root vnode, or can be synthesized.
	 */
	INIT_CATALOGDATA(&catInfo.nodeData, 0);
	catInfo.hint = kNoHint;

    if (((alist->volattr == 0) && ((alist->commonattr & HFS_ATTR_CMN_LOOKUPMASK) != 0)) ||
        ((alist->dirattr & HFS_ATTR_DIR_LOOKUPMASK) != 0) ||
        ((alist->fileattr & HFS_ATTR_FILE_LOOKUPMASK) != 0) ||
        ((alist->commonattr & (ATTR_CMN_OBJID | ATTR_CMN_OBJPERMANENTID))
          && (hp->h_meta->h_metaflags & IN_DATANODE))) {

        /* lock catalog b-tree */
        error = hfs_metafilelocking(VTOHFS(vp), kHFSCatalogFileID, LK_SHARED, ap->a_p);
        if (error) goto GetCatalogErr_Exit;

        if (alist->volattr != 0) {
            /* Look up the root info, regardless of the vnode provided */
            error = hfs_getcatalog(VTOVCB(vp), 2, NULL,  -1, &catInfo);
        } else {
            error = hfs_getcatalog(VTOVCB(vp), H_DIRID(hp), H_NAME(hp),  -1, &catInfo);
            if (error == 0) H_HINT(hp) = catInfo.hint;						/* Remember the last valid hint */
        };
        
        /* unlock catalog b-tree */
        (void) hfs_metafilelocking(VTOHFS(vp), kHFSCatalogFileID, LK_RELEASE, ap->a_p);

        /*
		 * If a data fork has an active sibling and we need
		 * rsrc fork attributes then we need to lock the
		 * sibling and make a copy of its attributes.
		 */
        if ((hp->h_meta->h_usecount > 1)   &&
			(H_FORKTYPE(hp) == kDataFork)  &&
			(alist->fileattr & HFS_ATTR_FILE_LOOKUPMASK)) {
            struct vnode *sib_vp = NULL;
            struct hfsnode *nhp;
            struct proc *p = current_proc();
            
            DBG_ASSERT(hp->h_meta->h_siblinghead.cqh_first && 
                            (hp->h_meta->h_siblinghead.cqh_first != hp->h_meta->h_siblinghead.cqh_last));
            DBG_ASSERT(H_FORKTYPE(hp)==kDataFork || H_FORKTYPE(hp)==kRsrcFork);
    
            /* Loop through all siblings, skipping ourselves */
            simple_lock(&hp->h_meta->h_siblinglock);
            CIRCLEQ_FOREACH(nhp, &hp->h_meta->h_siblinghead, h_sibling) {
                if (nhp == hp)		/* skip ourselves */
                    continue;
                sib_vp = HTOV(nhp);
            };
            simple_unlock(&hp->h_meta->h_siblinglock);
    
            /* The only error that vget returns is when the vnode is going away, so ignore the vnode */
            if (vget(sib_vp, LK_EXCLUSIVE | LK_RETRY, p) == 0) {
                if (VTOH(sib_vp)->h_nodeflags & (IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE)) {
                    /* XXX SER No need to copy the whole thing over, just copy the fork info */
                    CopyVNodeToCatalogNode (sib_vp, &catInfo.nodeData);
                };
    
                vput(sib_vp);
            };	/* vget() */
        };	/* h_use_count > 1 */

        /* Update to the in-memory state, if it has been modified...just to make sure */
        if (VTOH(vp)->h_nodeflags & (IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE)) {
            /* XXX SER No need to copy the whole thing over, just copy the fork info */
            CopyVNodeToCatalogNode (vp, &catInfo.nodeData);
        };
 
         /* XXX What if hfs_getcatalog fails...we just continue??? */
        catInfoPtr = &catInfo;

   };

    fixedblocksize = AttributeBlockSize(alist);
    attrblocksize = fixedblocksize + (sizeof(u_long));							/* u_long for length longword */
    if (alist->commonattr & ATTR_CMN_NAME) attrblocksize += kHFSPlusMaxFileNameBytes + 1;
    if (alist->commonattr & ATTR_CMN_NAMEDATTRLIST) attrblocksize += 0;			/* XXX PPD */
    if (alist->volattr & ATTR_VOL_MOUNTPOINT) attrblocksize += PATH_MAX;
    if (alist->volattr & ATTR_VOL_NAME) attrblocksize += kHFSPlusMaxFileNameBytes + 1;
    if (alist->fileattr & ATTR_FILE_FORKLIST) attrblocksize += 0;				/* XXX PPD */

    attrbufsize = MIN(ap->a_uio->uio_resid, attrblocksize);
    DBG_VOP(("hfs_getattrlist: allocating Ox%X byte buffer (Ox%X + Ox%X) for attributes...\n",
             attrblocksize,
             fixedblocksize,
             attrblocksize - fixedblocksize));
    MALLOC(attrbufptr, void *, attrblocksize, M_TEMP, M_WAITOK);
    attrptr = attrbufptr;
    *((u_long *)attrptr) = 0;									/* Set buffer length in case of errors */
    ++((u_long *)attrptr);										/* Reserve space for length field */
    varptr = ((char *)attrptr) + fixedblocksize;				/* Point to variable-length storage */
    DBG_VOP(("hfs_getattrlist: attrptr = 0x%08X, varptr = 0x%08X...\n", (u_int)attrptr, (u_int)varptr));

    PackAttributeBlock(alist, vp, catInfoPtr, &attrptr, &varptr);
    attrbufsize = MIN(attrbufsize, (u_int)varptr - (u_int)attrbufptr);	/* Don't copy out more data than was generated */
    *((u_long *)attrbufptr) = attrbufsize;						/* Set actual buffer length for return to caller */
    DBG_VOP(("hfs_getattrlist: copying Ox%X bytes to user address 0x%08X.\n", attrbufsize, (u_int)ap->a_uio->uio_iov->iov_base));
    error = uiomove((caddr_t)attrbufptr, attrbufsize, ap->a_uio);
    if (error != E_NONE) {
        DBG_ERR(("hfs_getattrlist: error %d on uiomove.\n", error));
        };

    FREE(attrbufptr, M_TEMP);


GetCatalogErr_Exit:
	CLEAN_CATALOGDATA(&catInfo.nodeData);
    DBG_VOP_LOCKS_TEST(error);
    return error;
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

static int
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
    struct hfsnode *hp = VTOH(vp);
    struct attrlist *alist = ap->a_alist;
    struct ucred *cred = ap->a_cred;
    struct proc *p = ap->a_p;
    int error;
    struct hfsCatalogInfo catInfo;
    int attrblocksize;
    void *attrbufptr = NULL;
    void *attrptr;
    void *varptr = NULL;
	uid_t saved_uid;
	gid_t saved_gid;
	mode_t saved_mode;
    u_long saved_flags;
	char * filename;
	char iNodeName[32];
	u_int32_t pid;
    int retval = 0;

    DBG_FUNC_NAME("setattrlist");
    DBG_VOP_LOCKS_DECL(1);

    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_SAME, VOPDBG_SAME, VOPDBG_SAME, VOPDBG_POS);
    DBG_HFS_NODE_CHECK(ap->a_vp);
    DBG_VOP(("%s: Common attr:0x%x, buff size Ox%X,\n",funcname, (u_int)alist->commonattr,(u_int)ap->a_uio->uio_resid));

    DBG_ASSERT(ap->a_uio->uio_rw == UIO_WRITE);

    if ((alist->bitmapcount != ATTR_BIT_MAP_COUNT) ||
        ((alist->commonattr & ~ATTR_CMN_SETMASK) != 0) ||
        ((alist->volattr & ~ATTR_VOL_SETMASK) != 0) ||
        ((alist->dirattr & ~ATTR_DIR_SETMASK) != 0) ||
        ((alist->fileattr & ~ATTR_FILE_SETMASK) != 0) ||
        ((alist->forkattr & ~ATTR_FORK_SETMASK) != 0)) {
        DBG_ERR(("%s: Bad attrlist\n", funcname));
        DBG_VOP_LOCKS_TEST(EINVAL);
        return EINVAL;
        };

    if ((alist->volattr != 0) && 							/* Setting volume info */
		(((alist->volattr & ATTR_VOL_INFO) == 0) ||			/* Not explicitly indicating this or ... */
		 (alist->commonattr & ~ATTR_CMN_VOLSETMASK)))		/* ... setting invalid attributes for volume */
      {
        DBG_ERR(("%s: Bad attrlist\n", funcname));
        DBG_VOP_LOCKS_TEST(EINVAL);
        return EINVAL;
      };

    if (VTOVFS(vp)->mnt_flag & MNT_RDONLY) {
        DBG_VOP_LOCKS_TEST(EROFS);
        return EROFS;
    };

	/*
		Ownership of the file (in addition to write access, checked below,
		is required in one of two classes of calls:
		
		(a) When setting any ownership-requiring attribute other than ATTR_CMN_FLAGS, or
		(b) When setting ATTR_CMN_FLAGS on a volume that's not plain HFS (for which no
			real per-object ownership information is stored):
	 */
	if ((alist->commonattr & (OWNERSHIP_ONLY_ATTRS & ~ATTR_CMN_FLAGS)) ||
		((alist->commonattr & ATTR_CMN_FLAGS) && (VTOVCB(vp)->vcbSigWord != kHFSSigWord))) {
		/* NOTE: The following isn't ENTIRELY complete: even if you're the superuser
				 you cannot change the flags as long as SF_IMMUTABLE or SF_APPEND is
				 set and securelevel > 0.  This is verified in hfs_chflags which gets
				 invoked to do the actual flags field change so this check is sufficient
				 for now.
		 */
		/* Check to see if the user owns the object [or is superuser]: */
		if ((retval = hfs_owner_rights(vp, cred, p, true)) != 0) {
        	DBG_VOP_LOCKS_TEST(retval);
        	return retval;
        };
	} else {
		DBG_ASSERT(((alist->commonattr & OWNERSHIP_ONLY_ATTRS) == 0) ||
				   (((alist->commonattr & OWNERSHIP_ONLY_ATTRS) == ATTR_CMN_FLAGS) &&
					(VTOVCB(vp)->vcbSigWord == kHFSSigWord)));
		/* No ownership access is required: mere write access (checked below) will do... */
	};
	
	/* For any other attributes, check to see if the user has write access to
	    the object in question [unlike VOP_ACCESS, ignore IMMUTABLE here]: */
	    
	if ((((alist->commonattr & ~(OWNERSHIP_ONLY_ATTRS)) != 0) ||
		 (alist->volattr != 0) ||
		 (alist->dirattr != 0) ||
		 (alist->fileattr != 0) ||
		 (alist->forkattr != 0)) &&
		((retval = hfs_write_access(vp, cred, p, false)) != 0)) {
        DBG_VOP_LOCKS_TEST(retval);
        return retval;
	}; /* end of if ownership attr */
	
    /* Allocate the buffer now to minimize the time we might be blocked holding the catalog lock */
    attrblocksize = ap->a_uio->uio_resid;
    if (attrblocksize < AttributeBlockSize(alist)) {
        DBG_ERR(("%s: bad attrblocksize\n", funcname));
        DBG_VOP_LOCKS_TEST(EINVAL);
        return EINVAL;
    };

	MALLOC(attrbufptr, void *, attrblocksize, M_TEMP, M_WAITOK);

	INIT_CATALOGDATA(&catInfo.nodeData, kCatNameNoCopyName);
	catInfo.hint = kNoHint;

	filename = H_NAME(hp);
	pid = H_DIRID(hp);

#if HFS_HARDLINKS
	/*
	 * Force an update of the indirect node instead of the link
	 * by using the name and parent of the indirect node.
	 */
	if (hp->h_meta->h_metaflags & IN_DATANODE) {
		MAKE_INODE_NAME(iNodeName, hp->h_meta->h_indnodeno);
		filename = iNodeName;
		pid = VTOHFS(vp)->hfs_private_metadata_dir;
	}
#endif

	/* lock catalog b-tree */
	error = hfs_metafilelocking(VTOHFS(vp), kHFSCatalogFileID, LK_EXCLUSIVE, p);
	if (error != E_NONE)
		goto ErrorExit;

	error = hfs_getcatalog(VTOVCB(vp), pid, filename, -1, &catInfo);

	/* unlock catalog b-tree */
	(void) hfs_metafilelocking(VTOHFS(vp), kHFSCatalogFileID, LK_RELEASE, p);
	if (error != E_NONE)
		goto ErrorExit;

    H_HINT(hp) = catInfo.hint;						/* Remember the last valid hint */

    error = uiomove((caddr_t)attrbufptr, attrblocksize, ap->a_uio);
    if (error) goto ErrorExit;

    if ((alist->volattr) && (H_FILEID(hp) != kRootDirID)) {
        error = EINVAL;
        goto ErrorExit;
    };

	/* 
	 * If we are going to change the times:
	 * 1. do we have permission to change the dates?
	 * 2. Is there another fork? If so then clear any flags associated with the times
	 */
    if (alist->commonattr & (ATTR_CMN_MODTIME | ATTR_CMN_CHGTIME | ATTR_CMN_ACCTIME)) {
		if (alist->commonattr & (ATTR_CMN_CHGTIME | ATTR_CMN_ACCTIME)) {
			if ((error = hfs_owner_rights(vp, cred, p, true)) != 0)
				goto ErrorExit;
		}

		/* If there is another fork, clear the flags */
		if ((hp->h_meta->h_usecount > 1) && (H_FORKTYPE(hp) == kDataFork)) {
			struct vnode *sib_vp = NULL;
			struct hfsnode *nhp;
			
			/* Loop through all siblings, skipping ourselves */
			simple_lock(&hp->h_meta->h_siblinglock);
			CIRCLEQ_FOREACH(nhp, &hp->h_meta->h_siblinghead, h_sibling) {
				if (nhp == hp)		/* skip ourselves */
					continue;
				sib_vp = HTOV(nhp);
			}
			simple_unlock(&hp->h_meta->h_siblinglock);
	
			/* 
			 * The only error that vget returns is when the vnode is going away,
			 * so ignore the vnode
			 */
			if (sib_vp && vget(sib_vp, LK_EXCLUSIVE | LK_RETRY, p) == 0) {
				if ((sib_vp->v_tag == VT_HFS)
					&& VTOH(sib_vp)->h_nodeflags & (IN_ACCESS | IN_CHANGE | IN_UPDATE)) {
					if (alist->commonattr & ATTR_CMN_MODTIME)
							VTOH(sib_vp)->h_nodeflags &= ~IN_UPDATE;
					if (alist->commonattr & ATTR_CMN_CHGTIME)
							VTOH(sib_vp)->h_nodeflags &= ~IN_CHANGE;
					if (alist->commonattr & ATTR_CMN_ACCTIME)
							VTOH(sib_vp)->h_nodeflags &= ~IN_ACCESS;
				}
				vput(sib_vp);
			}
		}
	}

    /* save these in case hfs_chown() or hfs_chmod() fail */
	saved_uid = hp->h_meta->h_uid;
	saved_gid = hp->h_meta->h_gid;
    saved_mode = hp->h_meta->h_mode;
    saved_flags = hp->h_meta->h_pflags;

    attrptr = attrbufptr;
    UnpackAttributeBlock(alist, vp, &catInfo, &attrptr, &varptr);

	/* if unpacking changed the owner or group then call hfs_chown() */
    if (saved_uid != hp->h_meta->h_uid || saved_gid != hp->h_meta->h_gid) {
		uid_t uid;
		gid_t gid;
		
		uid = hp->h_meta->h_uid;
 		hp->h_meta->h_uid = saved_uid;
		gid = hp->h_meta->h_gid;
		hp->h_meta->h_gid = saved_gid;
        if ((error = hfs_chown(vp, uid, gid, cred, p)))
			goto ErrorExit;
    }

	/* if unpacking changed the mode then call hfs_chmod() */
	if (saved_mode != hp->h_meta->h_mode) {
		mode_t mode;

		mode = hp->h_meta->h_mode;
		hp->h_meta->h_mode = saved_mode;
		if ((error = hfs_chmod(vp, mode, cred, p)))
			goto ErrorExit;
	};

    /* if unpacking changed the flags then call hfs_chflags */
    if (saved_flags != hp->h_meta->h_pflags) {
        u_long flags;

        flags = hp->h_meta->h_pflags;
        hp->h_meta->h_pflags = saved_flags;
        if ((error = hfs_chflags(vp, flags, cred, p)))
            goto ErrorExit;
    };
	
	
	/* lock catalog b-tree */
	error = hfs_metafilelocking(VTOHFS(vp), kHFSCatalogFileID, LK_EXCLUSIVE, p);
	if (error != E_NONE)
		goto ErrorExit;

	/* Update Catalog Tree */
	if (alist->volattr == 0) {
		error = MacToVFSError( UpdateCatalogNode(HTOVCB(hp), pid, filename, H_HINT(hp), &catInfo.nodeData));
	}

	/* Volume Rename */
	if (alist->volattr & ATTR_VOL_NAME) {
			ExtendedVCB *vcb 	= VTOVCB(vp);
			int			namelen = strlen(vcb->vcbVN);
			
		if (vcb->vcbVN[0] == 0) {
			/*
			 *	Ignore attempts to rename a volume to a zero-length name:
			 *	restore the original name from the metadata.
			 */
			copystr(H_NAME(hp), vcb->vcbVN, sizeof(vcb->vcbVN), NULL);
		} else {
			UInt32 tehint = 0;

			/*
			 * Force Carbon renames to have MacUnicode encoding
			 */
			if ((hp->h_nodeflags & IN_BYCNID) && (!ISSET(p->p_flag, P_TBE))) {
				tehint = kTextEncodingMacUnicode;
			}

			error = MoveRenameCatalogNode(vcb, kRootParID, H_NAME(hp), H_HINT(hp), 
					kRootParID, vcb->vcbVN, &H_HINT(hp), tehint);
			if (error) {
					VCB_LOCK(vcb);
					copystr(H_NAME(hp), vcb->vcbVN, sizeof(vcb->vcbVN), NULL);	/* Restore the old name in the VCB */
					vcb->vcbFlags |= 0xFF00;		// Mark the VCB dirty
					VCB_UNLOCK(vcb);
					goto UnlockExit;
			};
		
			hfs_set_metaname(vcb->vcbVN, hp->h_meta, HTOHFS(hp));
			hp->h_nodeflags |= IN_CHANGE;
				
		}	 /* vcb->vcbVN[0] == 0 ... else ... */
	} 	/* alist->volattr & ATTR_VOL_NAME */

UnlockExit:
	/* unlock catalog b-tree */
	(void) hfs_metafilelocking(VTOHFS(vp), kHFSCatalogFileID, LK_RELEASE, p);

ErrorExit:

	CLEAN_CATALOGDATA(&catInfo.nodeData);

    if (attrbufptr) FREE(attrbufptr, M_TEMP);

    DBG_VOP_LOCKS_TEST(error);
    return error;
}

/*
 * Change the mode on a file.
 * Inode must be locked before calling.
 */
static int
hfs_chmod(vp, mode, cred, p)
register struct vnode *vp;
register int mode;
register struct ucred *cred;
struct proc *p;
{
    register struct hfsnode *hp = VTOH(vp);
    int retval;

    if (VTOVCB(vp)->vcbSigWord != kHFSPlusSigWord)
        return E_NONE;

#if OVERRIDE_UNKNOWN_PERMISSIONS
	if (VTOVFS(vp)->mnt_flag & MNT_UNKNOWNPERMISSIONS) {
		return E_NONE;
	};
#endif
	
	if ((retval = hfs_owner_rights(vp, cred, p, true)) != 0)
		return (retval);
	if (cred->cr_uid) {
		if (vp->v_type != VDIR && (mode & S_ISTXT))
			return (EFTYPE);
		if (!groupmember(hp->h_meta->h_gid, cred) && (mode & ISGID))
			return (EPERM);
	}
	hp->h_meta->h_mode &= ~ALLPERMS;
	hp->h_meta->h_mode |= (mode & ALLPERMS);
	hp->h_meta->h_metaflags &= ~IN_UNSETACCESS;
	hp->h_nodeflags |= IN_CHANGE;
	return (0);
}


static int
hfs_write_access(struct vnode *vp, struct ucred *cred, struct proc *p, Boolean considerFlags)
{
    struct hfsnode *hp 			= VTOH(vp);
    ExtendedVCB	*vcb			= HTOVCB(hp);
    gid_t *gp;
    Boolean isHFSPlus;
    int retval 					= E_NONE;
    int i;

    isHFSPlus = (vcb->vcbSigWord == kHFSPlusSigWord );

    /*
     * Disallow write attempts on read-only file systems;
     * unless the file is a socket, fifo, or a block or
     * character device resident on the file system.
     */
	switch (vp->v_type) {
	  case VDIR:
      case VLNK:
      case VREG:
        if (VTOVFS(vp)->mnt_flag & MNT_RDONLY)
            return (EROFS);
        break;
      default:
		break;
 	}
 
	/* If immutable bit set, nobody gets to write it. */
    if (considerFlags && (hp->h_meta->h_pflags & IMMUTABLE))
        return (EPERM);

    /* Otherwise, user id 0 always gets access. */
    if (cred->cr_uid == 0) {
        retval = 0;
        goto Exit;
    };

    /* Otherwise, check the owner. */
    if ((retval = hfs_owner_rights(vp, cred, p, false)) == 0) {
        retval = ((hp->h_meta->h_mode & S_IWUSR) == S_IWUSR ? 0 : EACCES);
        goto Exit;
    }
 
    /* Otherwise, check the groups. */
    for (i = 0, gp = cred->cr_groups; i < cred->cr_ngroups; i++, gp++)
        if (hp->h_meta->h_gid == *gp) {
            retval = ((hp->h_meta->h_mode & S_IWGRP) == S_IWGRP ? 0 : EACCES);
 			goto Exit;
        }
 
    /* Otherwise, check everyone else. */
	retval = ((hp->h_meta->h_mode & S_IWOTH) == S_IWOTH ? 0 : EACCES);

Exit:
	return (retval);    
}



/*
 * Change the flags on a file or directory.
 * Inode must be locked before calling.
 */
static int
hfs_chflags(vp, flags, cred, p)
register struct vnode *vp;
register u_long flags;
register struct ucred *cred;
struct proc *p;
{
    register struct hfsnode *hp = VTOH(vp);
    int retval;

	if (VTOVCB(vp)->vcbSigWord == kHFSSigWord) {
		if ((retval = hfs_write_access(vp, cred, p, false)) != 0) {
			return retval;
		};
	} else if ((retval = hfs_owner_rights(vp, cred, p, true)) != 0) {
		return retval;
	};

	if (cred->cr_uid == 0) {
		if ((hp->h_meta->h_pflags & (SF_IMMUTABLE | SF_APPEND)) &&
			securelevel > 0) {
			return EPERM;
		};
		hp->h_meta->h_pflags = flags;
	} else {
		if (hp->h_meta->h_pflags & (SF_IMMUTABLE | SF_APPEND) ||
			(flags & UF_SETTABLE) != flags) {
			return EPERM;
		};
		hp->h_meta->h_pflags &= SF_SETTABLE;
		hp->h_meta->h_pflags |= (flags & UF_SETTABLE);
	}
	hp->h_meta->h_metaflags &= ~IN_UNSETACCESS;
	hp->h_nodeflags |= IN_CHANGE;

    return 0;
}


/*
 * Perform chown operation on hfsnode hp;
 * hfsnode must be locked prior to call.
 */
static int
hfs_chown(vp, uid, gid, cred, p)
register struct vnode *vp;
uid_t uid;
gid_t gid;
struct ucred *cred;
struct proc *p;
{
    register struct hfsnode *hp = VTOH(vp);
    uid_t ouid;
    gid_t ogid;
    int retval = 0;

    if (VTOVCB(vp)->vcbSigWord != kHFSPlusSigWord)
        return EOPNOTSUPP;

	if (VTOVFS(vp)->mnt_flag & MNT_UNKNOWNPERMISSIONS) {
		return E_NONE;
	};
	
    if (uid == (uid_t)VNOVAL)
        uid = hp->h_meta->h_uid;
    if (gid == (gid_t)VNOVAL)
        gid = hp->h_meta->h_gid;
    /*
     * If we don't own the file, are trying to change the owner
     * of the file, or are not a member of the target group,
     * the caller must be superuser or the call fails.
     */
    if ((cred->cr_uid != hp->h_meta->h_uid || uid != hp->h_meta->h_uid ||
         (gid != hp->h_meta->h_gid && !groupmember((gid_t)gid, cred))) &&
        (retval = suser(cred, &p->p_acflag)))
        return (retval);
    
    ogid = hp->h_meta->h_gid;
    ouid = hp->h_meta->h_uid;
	
	hp->h_meta->h_gid = gid;
    hp->h_meta->h_uid = uid;

    hp->h_meta->h_metaflags &= ~IN_UNSETACCESS;
    if (ouid != uid || ogid != gid)
        hp->h_nodeflags |= IN_CHANGE;
    if (ouid != uid && cred->cr_uid != 0)
        hp->h_meta->h_mode &= ~ISUID;
    if (ogid != gid && cred->cr_uid != 0)
        hp->h_meta->h_mode &= ~ISGID;
    return (0);
}



/*
#
#% exchange fvp		L L L
#% exchange tvp		L L L
#
 vop_exchange {
     IN struct vnode *fvp;
     IN struct vnode *tvp;
     IN struct ucred *cred;
     IN struct proc *p;
 };

 */
 /*
  * exchange is a very tricky routine, because we might have to unlock the
  * passed in vnode, and then retry locking it and all its siblings, and then
  * unlocking them in reverse.
  * Also the sibling list lock must be kept during the whole operation to
  * make sure nothing changes underneath us.
  * Also it depends on behavior of the sibling list and hash, so
  * careful if you change anything.
  */
  
static int
hfs_exchange(ap)
struct vop_exchange_args /* {
struct vnode *a_fvp;
struct vnode *a_tvp;
struct ucred *a_cred;
struct proc *a_p;
} */ *ap;
{
	struct hfsnode *from_hp, *to_hp, *nhp;
	struct hfsnode *fromFirst, *fromSecond, *toFirst, *toSecond;
	struct vnode *from_vp, *to_vp;
	struct hfsmount *hfsmp;
	u_char tmp_name[kHFSPlusMaxFileNameBytes+1];		/* 766 bytes! */
	ExtendedVCB *vcb;
	u_int32_t fromFileID, toFileID;
	u_int32_t fromParID;
	u_int32_t tmpLong;
	int retval = E_NONE;
	DBG_FUNC_NAME("exchange");
	DBG_VOP_LOCKS_DECL(2);
	DBG_VOP_LOCKS_INIT(0,ap->a_fvp, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_POS);
	DBG_VOP_LOCKS_INIT(1,ap->a_tvp, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_POS);

	/* Set up variables and checks */
	from_vp 	= ap->a_fvp;
    to_vp 		= ap->a_tvp;
	from_hp		= VTOH(from_vp);
	to_hp		= VTOH(to_vp);
	hfsmp		= VTOHFS(from_vp);
	vcb			= HTOVCB(from_hp);
	toFileID 	= H_FILEID(to_hp);
	fromFileID 	= H_FILEID(from_hp);
	fromParID 	= H_DIRID(from_hp);

    if (from_vp->v_mount != to_vp->v_mount) {
		DBG_VOP_LOCKS_TEST(EXDEV);
		return EXDEV;
	}

	/* Can only exchange file objects */
    if (from_vp->v_type != VREG || to_vp->v_type != VREG) {
		DBG_VOP_LOCKS_TEST(EINVAL);
		return EINVAL;
	}

	/*
	 * Lock the siblink list
	 * Check for multiple forks
	 * If there are, we would need to:
	 * 1. Unlock ourselves
	 * 3. Traverse the list in a forward order...locking all vnodes
	 * 4. Flush all buffers
	 * 5. Perform the exchange
	 * 6. Traverse the list in a reverse order...unlocking all vnodes, except orignal
	 * Notice that the sibling lock is kept during the whole operation. This quarentees
	 * that no new forks are taken off or put on
	 */
	DBG_ASSERT(H_FORKTYPE(from_hp)==kDataFork && H_FORKTYPE(to_hp)==kDataFork);	
	fromFirst = fromSecond = toFirst = toSecond = NULL;

	if (from_hp->h_meta->h_usecount > 1) {
		/*
		 * This has siblings, so remember the passed-in vnode,
		 * unlock it if it is not the 'first' sibling,
		 * and then lock the rest of the vnodes by sibling order.
		 * Notice that the passed-in vnode is not vrele(), this
		 * keeps the usecount>0, so it wont go away.
		 */
		simple_lock(&from_hp->h_meta->h_siblinglock);
		fromFirst = from_hp->h_meta->h_siblinghead.cqh_first;
		fromSecond = fromFirst->h_sibling.cqe_next;
		simple_unlock(&from_hp->h_meta->h_siblinglock);
			
		if (fromFirst == from_hp) {
        	if (vget(HTOV(fromSecond), LK_EXCLUSIVE | LK_RETRY, ap->a_p))
				fromSecond = NULL;		/* its going away */
		} else {
        	VOP_UNLOCK(HTOV(from_hp), 0, ap->a_p);
        	if (vget(HTOV(fromFirst), LK_EXCLUSIVE | LK_RETRY, ap->a_p))
				fromFirst = NULL;		/* its going away */
        	if (vget(HTOV(fromSecond), LK_EXCLUSIVE | LK_RETRY, ap->a_p))
				fromSecond = NULL;		/* its going away */
		};

	} else {
		fromFirst = from_hp;
	};

	if (to_hp->h_meta->h_usecount > 1) {

	simple_lock(&to_hp->h_meta->h_siblinglock);
		toFirst = to_hp->h_meta->h_siblinghead.cqh_first;
		toSecond = toFirst->h_sibling.cqe_next;
		simple_unlock(&to_hp->h_meta->h_siblinglock);
		
		if (toFirst == to_hp) {
        	if (vget(HTOV(toSecond), LK_EXCLUSIVE | LK_RETRY, ap->a_p))
				toSecond = NULL;		/* its going away */
		} else {
        	VOP_UNLOCK(HTOV(to_hp), 0, ap->a_p);
        	if (vget(HTOV(toFirst), LK_EXCLUSIVE | LK_RETRY, ap->a_p))
				toFirst = NULL;			/* its going away */
        	if (vget(HTOV(toSecond), LK_EXCLUSIVE | LK_RETRY, ap->a_p))
				toSecond = NULL;		/* its going away */
		};

	} else {
		toFirst = to_hp;
	};


		/* Ignore any errors, we are doing a 'best effort' on flushing */
	if (fromFirst)
		(void) vinvalbuf(HTOV(fromFirst), V_SAVE, ap->a_cred, ap->a_p, 0, 0);
	if (fromSecond)
		(void) vinvalbuf(HTOV(fromSecond), V_SAVE, ap->a_cred, ap->a_p, 0, 0);
	if (toFirst)
		(void) vinvalbuf(HTOV(toFirst), V_SAVE, ap->a_cred, ap->a_p, 0, 0);
	if (toSecond)
		(void) vinvalbuf(HTOV(toSecond), V_SAVE, ap->a_cred, ap->a_p, 0, 0);


	/* lock catalog b-tree */
	retval = hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_EXCLUSIVE, ap->a_p);
	if (retval) goto Err_Exit;

	/* lock extents b-tree iff there are overflow extents */
	/* XXX SER ExchangeFileIDs() always tries to delete the virtual extent id for exchanging files
		so we neeed the tree to be always locked.
	*/
	retval = hfs_metafilelocking(hfsmp, kHFSExtentsFileID, LK_EXCLUSIVE, ap->a_p);
	if (retval) goto Err_Exit_Relse;

	/* Do the exchange */
	retval = MacToVFSError( ExchangeFileIDs(vcb, H_NAME(from_hp), H_NAME(to_hp), H_DIRID(from_hp), H_DIRID(to_hp), H_HINT(from_hp), H_HINT(to_hp) ));

	(void) hfs_metafilelocking(hfsmp, kHFSExtentsFileID, LK_RELEASE, ap->a_p);

	if (retval != E_NONE) {
		DBG_ERR(("/tError trying to exchange: %d\n", retval));
		goto Err_Exit_Relse;
	}

	
    /* Purge the vnodes from the name */
 	if (fromFirst)
		cache_purge(HTOV(fromFirst));
	if (fromSecond)
		cache_purge(HTOV(fromSecond));
	if (toFirst)
		cache_purge(HTOV(toFirst));
	if (toSecond)
		cache_purge(HTOV(toSecond));
	
	/* Now exchange fileID, parID, name for the vnode itself */
	copystr(H_NAME(from_hp), (char*) tmp_name, strlen(H_NAME(from_hp))+1, NULL);
	hfs_chid(from_hp, toFileID, H_DIRID(to_hp), H_NAME(to_hp));
	hfs_chid(to_hp, fromFileID, fromParID, (char*) tmp_name);
	
	/* copy rest */
	tmpLong = HTOFCB(from_hp)->fcbFlags;
	HTOFCB(from_hp)->fcbFlags = HTOFCB(to_hp)->fcbFlags;
	HTOFCB(to_hp)->fcbFlags = tmpLong;

	tmpLong = from_hp->h_meta->h_crtime;
	from_hp->h_meta->h_crtime = to_hp->h_meta->h_crtime;
	to_hp->h_meta->h_crtime = tmpLong;

	tmpLong = from_hp->h_meta->h_butime;
	from_hp->h_meta->h_butime = to_hp->h_meta->h_butime;
	to_hp->h_meta->h_butime = tmpLong;

	tmpLong = from_hp->h_meta->h_atime;
	from_hp->h_meta->h_atime = to_hp->h_meta->h_atime;
	to_hp->h_meta->h_atime = tmpLong;

	tmpLong = from_hp->h_meta->h_ctime;
	from_hp->h_meta->h_ctime = to_hp->h_meta->h_ctime;
	to_hp->h_meta->h_ctime = tmpLong;

	tmpLong = from_hp->h_meta->h_gid;
	from_hp->h_meta->h_gid = to_hp->h_meta->h_gid;
	to_hp->h_meta->h_gid = tmpLong;

	tmpLong = from_hp->h_meta->h_uid;
	from_hp->h_meta->h_uid = to_hp->h_meta->h_uid;
	to_hp->h_meta->h_uid = tmpLong;

	tmpLong = from_hp->h_meta->h_pflags; 
	from_hp->h_meta->h_pflags = to_hp->h_meta->h_pflags;
	to_hp->h_meta->h_pflags = tmpLong;

	tmpLong = from_hp->h_meta->h_mode;	
	from_hp->h_meta->h_mode = to_hp->h_meta->h_mode;
	to_hp->h_meta->h_mode = tmpLong;

	tmpLong = from_hp->h_meta->h_rdev;	
	from_hp->h_meta->h_rdev = to_hp->h_meta->h_rdev;
	to_hp->h_meta->h_rdev = tmpLong;

	tmpLong = from_hp->h_meta->h_size;	
	from_hp->h_meta->h_size = to_hp->h_meta->h_size;
	to_hp->h_meta->h_size = tmpLong;

	

Err_Exit_Relse:

	/* unlock catalog b-tree */
	(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, ap->a_p);


Err_Exit:


	/* XXX SER
	 * At this point, the vnodes' data is switched, but are on the old hash list.
	 * so move them to the right bucket. This couldnt be done until now, because the h_siblinglock
	 * was being held.
	 * Scenario:
	 * A fork is trying to be added while exchanging...It got the hash lock,
	 * but is waiting for the h_siblinglock. So we cannot try get the hash lock
	 * until we release h_siblinglock, so it could continue, so it adds to the sibling list
	 * and at the old place, so hfs_vhashmove has to move all vnodes with the old file id.
	 * Not very pretty, becarefull that this works ok
	 * Scenario 2:
	 * Same as the above, but before the move is made (like at this very spot), the new vnode
	 * is added and a vget is requested for that new vnode, it would have old data
	 *	WE MIGHT NEED TO LOCK THE HASH BECAUSE OF THIS !!!
	 * Scenario 3:
	 * Hey! Same as above, but it is added after all the moving
	 * So now there is a vnode with the old data, on the old hash...it will become
	 * lost next time that a vget()  is done
	 *
	 * XXX SER A solution might be to NOT move the hash, but the data (extents) or the
	 * opposite that we are doing now
	 */
	hfs_vhashmove(from_hp, fromFileID);
	hfs_vhashmove(to_hp, toFileID);


#if HFS_DIAGNOSTIC
	if (fromFirst)
		debug_check_vnode(HTOV(fromFirst), 0);
	if (fromSecond)
		debug_check_vnode(HTOV(fromSecond), 0);
	if (toFirst)
		debug_check_vnode(HTOV(toFirst),  0);
	if (toSecond)
		debug_check_vnode(HTOV(toSecond),  0);
#endif


	/* Unlock any forks, and the sibling list */
    if (to_hp->h_meta->h_usecount > 1) {
    	if (to_hp == toFirst) {
    		if (toSecond)
    			vput(HTOV(toSecond));
    	} else {
    		if (toSecond)
                vrele(HTOV(toSecond));		/* decrement,  return it locked */
    		if (toFirst)
    			vput(HTOV(toFirst));
     	}
	}
    if (from_hp->h_meta->h_usecount > 1) {
    	if (from_hp == fromFirst) {
    		if (fromSecond)
    			vput(HTOV(fromSecond));
    	} else {
    		if (fromSecond)
                vrele(HTOV(fromSecond));		/* decrement,  return it locked */
    		if (fromFirst)
    			vput(HTOV(fromFirst));
     	}
	}

	DBG_VOP_LOCKS_TEST(retval);
	return (retval);
}


/*
 * Change a vnode's file id, parent id and name
 * 
 * Assumes the vnode is locked and is of type VREG
 */
static void
hfs_chid(struct hfsnode *hp, u_int32_t fid, u_int32_t pid, char* name)
{
	DBG_ASSERT(HTOV(hp)->v_type == VREG);

	H_HINT(hp) = 0;
	H_FILEID(hp) = fid;					/* change h_nodeID */
	H_DIRID(hp) = pid;
	
	hfs_set_metaname(name, hp->h_meta, HTOHFS(hp));


}


/*

#% fsync	vp	L L L
#
 vop_fsync {
     IN struct vnode *vp;
     IN struct ucred *cred;
     IN int waitfor;
     IN struct proc *p;

     */


static int
hfs_fsync(ap)
struct vop_fsync_args /* {
    struct vnode *a_vp;
    struct ucred *a_cred;
    int a_waitfor;
    struct proc *a_p;
} */ *ap;
{
    struct vnode 		*vp = ap->a_vp ;
    struct hfsnode 		*hp	= VTOH(vp);
    int					retval = 0;
    register struct buf *bp;
    struct timeval 		tv;
    struct buf 			*nbp;
    int 				s;

    DBG_FUNC_NAME("fsync");
    DBG_VOP_LOCKS_DECL(1);
    DBG_VOP_PRINT_FUNCNAME();DBG_VOP_CONT(("  "));
    DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP_CONT(("\n"));
    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_ZERO);
    DBG_HFS_NODE_CHECK(ap->a_vp);
	
#if HFS_DIAGNOSTIC
    DBG_ASSERT(*((int*)&vp->v_interlock) == 0);
#endif


    /*
     * First of all, write out any clusters.
     */
    cluster_push(vp);

    /*
     * Flush all dirty buffers associated with a vnode.
     */
loop:
    s = splbio();
    for (bp = vp->v_dirtyblkhd.lh_first; bp; bp = nbp) {
        nbp = bp->b_vnbufs.le_next;
        if ((bp->b_flags & B_BUSY))
            continue;
        if ((bp->b_flags & B_DELWRI) == 0)
            panic("hfs_fsync: not dirty");
        bremfree(bp);
        bp->b_flags |= B_BUSY;
        bp->b_flags &= ~B_LOCKED;	/* Clear flag, should only be set on meta files */
        splx(s);
        /*
         * Wait for I/O associated with indirect blocks to complete,
         * since there is no way to quickly wait for them below.
         */
        DBG_VOP(("\t\t\tFlushing out phys block %d == log block %d\n", bp->b_blkno, bp->b_lblkno));
        if (bp->b_vp == vp || ap->a_waitfor == MNT_NOWAIT) {
            (void) bawrite(bp);
        } else {
            (void) VOP_BWRITE(bp);
	}
        goto loop;
    }
    if (vp->v_flag & VHASDIRTY)
	ubc_pushdirty(vp);

    if (ap->a_waitfor == MNT_WAIT) {
        while (vp->v_numoutput) {
            vp->v_flag |= VBWAIT;
            tsleep((caddr_t)&vp->v_numoutput, PRIBIO + 1, "hfs_fsync", 0);
        }

        /* I have seen this happen for swapfile. So it is safer to
         * check for dirty buffers again.  --Umesh
         */
        if (vp->v_dirtyblkhd.lh_first || (vp->v_flag & VHASDIRTY)) {
            vprint("hfs_fsync: dirty", vp);
            splx(s);
            goto loop;
        }
    }
    splx(s);

#if HFS_DIAGNOSTIC
    DBG_ASSERT(*((int*)&vp->v_interlock) == 0);
#endif

   	tv = time;
	if ((vp->v_flag & VSYSTEM) && (hp->fcbBTCBPtr!=NULL))
		BTSetLastSync(HTOFCB(hp), tv.tv_sec);

	if (H_FORKTYPE(hp) != kSysFile) {
    	retval = VOP_UPDATE(ap->a_vp, &tv, &tv, ap->a_waitfor == MNT_WAIT);

    	if (retval != E_NONE) {
        	DBG_ERR(("%s: FLUSH FAILED: %s\n", funcname, H_NAME(hp)));
    	}
    }
	else
		hp->h_nodeflags &= ~(IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE);

    if (ap->a_waitfor == MNT_WAIT) {
      DBG_ASSERT(vp->v_dirtyblkhd.lh_first == NULL);
    };
    DBG_VOP_LOCKS_TEST(retval);
    DBG_ASSERT(*((int*)&vp->v_interlock) == 0);
    return (retval);
}


int
hfs_fsync_transaction(struct vnode *vp)
{
    struct hfsnode 		*hp = VTOH(vp);
    register struct buf         *bp;
    struct timeval 		tv;
    struct buf 			*nbp;
    int 			s;

    /*
     * Flush all dirty buffers associated with a vnode.
     */
loop:
    s = splbio();

    for (bp = vp->v_dirtyblkhd.lh_first; bp; bp = nbp) {
        nbp = bp->b_vnbufs.le_next;
        if ((bp->b_flags & B_BUSY))
            continue;
        if ((bp->b_flags & B_DELWRI) == 0)
            panic("hfs_fsync: not dirty");
	if ( !(bp->b_flags & B_LOCKED))
	    continue;

        bremfree(bp);
        bp->b_flags |= B_BUSY;
        bp->b_flags &= ~B_LOCKED;	/* Clear flag, should only be set on meta files */
        splx(s);

	(void) bawrite(bp);

        goto loop;
    }
    splx(s);

    tv = time;
	if ((vp->v_flag & VSYSTEM) && (hp->fcbBTCBPtr!=NULL))
		(void) BTSetLastSync(VTOFCB(vp), tv.tv_sec);
    hp->h_nodeflags &= ~(IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE);

    return 0;
}

/*

#% remove	dvp	L U U
#% remove	vp	L U U
#
 vop_remove {
     IN WILLRELE struct vnode *dvp;
     IN WILLRELE struct vnode *vp;
     IN struct componentname *cnp;

     */

int
hfs_remove(ap)
struct vop_remove_args /* {
    struct vnode *a_dvp;
    struct vnode *a_vp;
    struct componentname *a_cnp;
} */ *ap;
{
        struct vnode *vp = ap->a_vp;
        struct vnode *dvp = ap->a_dvp;
        struct hfsnode *hp = VTOH(ap->a_vp);
        struct hfsmount *hfsmp = HTOHFS(hp);
        struct proc *p = current_proc();
        struct timeval tv;
        int retval, use_count;
        int filebusy = 0;
        int uncache = 0;
        DBG_FUNC_NAME("remove");
        DBG_VOP_LOCKS_DECL(2);
        DBG_VOP_PRINT_FUNCNAME();
        DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);
        DBG_VOP_PRINT_CPN_INFO(ap->a_cnp);DBG_VOP_CONT(("\n"));
        DBG_VOP_LOCKS_INIT(0,ap->a_dvp, VOPDBG_LOCKED, VOPDBG_UNLOCKED, VOPDBG_UNLOCKED, VOPDBG_POS);
        DBG_VOP_LOCKS_INIT(1,ap->a_vp, VOPDBG_LOCKED, VOPDBG_UNLOCKED, VOPDBG_UNLOCKED, VOPDBG_POS);

        retval = E_NONE;

        if ((hp->h_meta->h_pflags & (IMMUTABLE | APPEND)) ||
            (VTOH(dvp)->h_meta->h_pflags & APPEND)) {
                retval = EPERM;
                goto out;
        }

		if (vp->v_usecount > 1) {
			/*
			 * the namei done for the rename took a reference on the
			 * vnode. Hence set 1 in the tookref parameter 
			 * of ubc_isinuse().
			 */
			if(UBCISVALID(vp) && !ubc_isinuse(vp, 1))
				goto hfs_nobusy;
			if ((ap->a_cnp->cn_flags & NODELETEBUSY)
				|| (hfsmp->hfs_private_metadata_dir == 0)) {
				/* Carbon semantics prohibits deleting busy files */
				retval = EBUSY;
				goto out;
			} else
				filebusy = 1;
		}

hfs_nobusy:

                tv = time;					/* Done here, so all times are the same */

        /* Check other siblings for in use also */
        /* Uncache everything and make sure no other usecount */
        /*
         * This assumes the presence of the most 1 sibling
         *
         * a. loop through the siblings looking for another
         * b. If we find ourselves...skip it
         * If there was a sibling:
         * a. Check for a positve usecount
         * b. uncache any pages
         * c. Write out and memory changes
         * The idea is to keep the h_siblinglock as little as possible
         */
        if (hp->h_meta->h_usecount > 1) {
                struct vnode *sib_vp = NULL;
                struct hfsnode *nhp;

                DBG_ASSERT(hp->h_meta->h_siblinghead.cqh_first &&
                           (hp->h_meta->h_siblinghead.cqh_first != hp->h_meta->h_siblinghead.cqh_last));
                DBG_ASSERT(H_FORKTYPE(hp)==kDataFork || H_FORKTYPE(hp)==kRsrcFork);

                /* Loop through all siblings, skipping ourselves */
                simple_lock(&hp->h_meta->h_siblinglock);
                CIRCLEQ_FOREACH(nhp, &hp->h_meta->h_siblinghead, h_sibling) {
                        if (nhp == hp)		/* skip ourselves */
                                continue;
                        sib_vp = HTOV(nhp);
                };
                simple_unlock(&hp->h_meta->h_siblinglock);

                /* Check to see if the other fork is in use */
                DBG_ASSERT(sib_vp != NULL);
                simple_lock(&sib_vp->v_interlock);
                use_count = sib_vp->v_usecount;
                simple_unlock(&sib_vp->v_interlock);
                if (use_count > 0) {
					/*
					 * This is a sibling vnode and we did not take 
					 * a reference on it.
					 * Hence set 0 in the tookref parameter 
					 * of ubc_isinuse().
					 */
					if(UBCISVALID(sib_vp) && !ubc_isinuse(sib_vp, 0))
						goto hfs_nobusy2;
					if ((ap->a_cnp->cn_flags & NODELETEBUSY)
						|| (hfsmp->hfs_private_metadata_dir == 0)) {
						/* Carbon semantics prohibits deleting busy files */
						retval = EBUSY;
						goto out;
					} else
						filebusy = 1;
                }	/* use_count > 0 */

hfs_nobusy2:	

                /* The only error that vget returns is when the vnode is going away, so ignore the vnode */
                if (vget(sib_vp, LK_EXCLUSIVE | LK_RETRY, p) == 0) {
                        /*
                        * XXX SER An intelligient person would ask, why flush out changes
                        * that are going to be deleted? See the next comment.
                        */
                        if ((VTOH(sib_vp)->h_nodeflags & IN_MODIFIED) || (VTOFCB(sib_vp)->fcbFlags
                               		 & fcbModifiedMask)) {
                                DBG_ASSERT((VTOH(sib_vp)->h_nodeflags & IN_MODIFIED) != 0);
                                VOP_UPDATE(sib_vp, &tv, &tv, 0);
                        };

                        /* Invalidate the buffers, ignore the results */
                        (void) vinvalbuf(sib_vp, 0, NOCRED, p, 0, 0);

                        vput(sib_vp);
                };	/* vget() */
    };	/* h_use_count > 1 */

        /*
        * remove the entry from the namei cache:
        * We do it early before any linking/busy file wierdness, make sure the
        * original is gone
        */
        cache_purge(vp);
        
	/* Flush out any catalog changes */
	/* XXX SER: This is a hack, becasue hfsDelete reads the data from the disk
	 * and not from memory which is more correct
	 */
	if ((hp->h_nodeflags & IN_MODIFIED) || (HTOFCB(hp)->fcbFlags & fcbModifiedMask))
		{
                DBG_ASSERT((hp->h_nodeflags & IN_MODIFIED) != 0);
                VOP_UPDATE(vp, &tv, &tv, 0);
                }

	/* lock catalog b-tree */
	retval = hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_EXCLUSIVE, p);
	if (retval != E_NONE) {
                retval = EBUSY;
                goto out;
        }

    /*
     * After this point, any errors must goto out2, so the Catalog Tree gets unlocked
     */

#if HFS_HARDLINKS
	/*
         * Multi-linked files just need their link node deleted from the catalog
         */
	if (hp->h_meta->h_metaflags & IN_DATANODE) {

                if ((ap->a_cnp->cn_flags & HASBUF) == 0 ||
                    ap->a_cnp->cn_nameptr[0] == '\0') {
                        retval = ENOENT;	/* name missing */
                        goto out2;
                }

                /* lock extents b-tree (also protects volume bitmap) */
                retval = hfs_metafilelocking(hfsmp, kHFSExtentsFileID, LK_EXCLUSIVE, p);
                if (retval != E_NONE) {
                        retval = EBUSY;
                        goto out2;						/* unlock catalog b-tree on the way out */
                }

                retval = hfsDelete (HTOVCB(hp), H_FILEID(VTOH(dvp)),
                                    ap->a_cnp->cn_nameptr, TRUE, H_HINT(hp));

                (void) hfs_metafilelocking(hfsmp, kHFSExtentsFileID, LK_RELEASE, p);

                if (retval != 0)
                        goto out2;

                hp->h_meta->h_metaflags |=  IN_NOEXISTS;
                hp->h_nodeflags |= IN_CHANGE;
                if (--hp->h_meta->h_nlink < 1)
                        hp->h_meta->h_metaflags |= IN_DELETED;

                /* name and parent fields are no longer valid so invalidate them */
                H_DIRID(hp) = kUnknownID;
                hfs_set_metaname("\0", hp->h_meta, HTOHFS(hp));

                if ((ap->a_cnp->cn_flags & (HASBUF | SAVENAME)) == (HASBUF | SAVENAME))
                        FREE_ZONE(ap->a_cnp->cn_pnbuf, ap->a_cnp->cn_pnlen, M_NAMEI);
				/*
				 * This is a deleted file no new clients
				 * would be able to look it up. Maked the VM object
				 * not cachable so that it dies as soon as the last
				 * mapping disappears. This will reclaim the disk
				 * space as soon as possible.
				 */
				uncache = 1;
                goto out2;	/* link deleted, all done */
        }
#endif

	/*
         * To make the HFS filesystem follow UFS unlink semantics, a remove of
         * an active vnode is translated to a move/rename so the file appears
         * deleted. Later, the file is removed by hfs_inactive on the hfsnode.
         */
	if (filebusy) {
                UInt32 hint = H_HINT(hp);
                char nodeName[32];

                MAKE_DELETED_NAME(nodeName, H_FILEID(hp));

                retval = hfsMoveRename (HTOVCB(hp), H_DIRID(hp), H_NAME(hp),
                                        hfsmp->hfs_private_metadata_dir, nodeName, &hint);
                if (retval) goto out2;

                hp->h_meta->h_metaflags |= IN_DELETED;
                hp->h_nodeflags |= IN_CHANGE;

                /* update name so Catalog lookups succeed */
                H_HINT(hp) = hint;
                H_DIRID(hp) = hfsmp->hfs_private_metadata_dir;
                hfs_set_metaname(nodeName, hp->h_meta, HTOHFS(hp));

				/*
				 * This is an open deleted file no new clients
				 * would be able to look it up. Maked the VM object
				 * not cachable so that it dies as soon as the last
				 * mapping disappears. This will reclaim the disk
				 * space as soon as possible.
				 */
				uncache = 1;
                goto out2;	/* all done, unlock the catalog */
        }

	/* unlock the Catalog */
	(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, p);

	/* Invalidate the buffers */
	if ((retval= vinvalbuf(vp, 0, NOCRED, p, 0, 0)))
		goto out;
	
	if(UBCINFOEXISTS(vp))
		(void)ubc_setsize(vp, (off_t)0);

	
	/* lock catalog b-tree */
	retval = hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_EXCLUSIVE, p);
	if (retval != E_NONE) {
		retval = EBUSY;
		goto out;
	}
	/* lock extents b-tree (also protects volume bitmap) */
	retval = hfs_metafilelocking(hfsmp, kHFSExtentsFileID, LK_EXCLUSIVE, p);
	if (retval != E_NONE) {
                retval = EBUSY;
                goto out2;						/* unlock catalog b-tree on the way out */
        }

	/* remove entry from catalog and free any blocks used */
	retval = hfsDelete (HTOVCB(hp), H_DIRID(hp), H_NAME(hp), TRUE, H_HINT(hp));

	/* Clean up */
	(void) hfs_metafilelocking(hfsmp, kHFSExtentsFileID, LK_RELEASE, p);
	(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, p);

        if (retval != 0)
                goto out;

	hp->h_meta->h_metaflags |=  IN_NOEXISTS;
	hp->h_meta->h_mode = 0;	/* Makes the node go away...see inactive */
	/* clear the block mappings */
	hp->fcbPLen = (u_int64_t)0;
	bzero(&hp->fcbExtents, sizeof(HFSPlusExtentRecord));

	VTOH(dvp)->h_nodeflags |= IN_CHANGE | IN_UPDATE;

	uncache = 1;
	goto done;

out2:
	(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, p);

out:

	if (! retval)
                VTOH(dvp)->h_nodeflags |= IN_CHANGE | IN_UPDATE;

done:
	if (dvp != vp)
		VOP_UNLOCK(vp, 0, p);

	if (uncache)
		ubc_uncache(vp);

	vrele(vp);
	vput(dvp);

	DBG_VOP_LOCKS_TEST(retval);
	return (retval);
}


/*

#% rename	sourcePar_vp	U U U
#% rename	source_vp		U U U
#% rename	targetPar_vp	L U U
#% rename	target_vp		X U U
#
 vop_rename {
     IN WILLRELE struct vnode *sourcePar_vp;
     IN WILLRELE struct vnode *source_vp;
     IN struct componentname *source_cnp;
     IN WILLRELE struct vnode *targetPar_vp;
     IN WILLRELE struct vnode *target_vp;
     IN struct componentname *target_cnp;


     */
/*
* On entry:
*	source's parent directory is unlocked
*	source file or directory is unlocked
*	destination's parent directory is locked
*	destination file or directory is locked if it exists
*
* On exit:
*	all denodes should be released
*
*/

static int
hfs_rename(ap)
struct vop_rename_args  /* {
    struct vnode *a_fdvp;
    struct vnode *a_fvp;
    struct componentname *a_fcnp;
    struct vnode *a_tdvp;
    struct vnode *a_tvp;
    struct componentname *a_tcnp;
} */ *ap;
{
	struct vnode			*target_vp = ap->a_tvp;
	struct vnode			*targetPar_vp = ap->a_tdvp;
	struct vnode			*source_vp = ap->a_fvp;
	struct vnode			*sourcePar_vp = ap->a_fdvp;
	struct componentname	*target_cnp = ap->a_tcnp;
	struct componentname	*source_cnp = ap->a_fcnp;
	struct proc				*p = source_cnp->cn_proc;
	struct hfsnode			*target_hp, *targetPar_hp, *source_hp, *sourcePar_hp;
	u_int32_t				oldparent = 0, newparent = 0;
	int						doingdirectory = 0;
	int						retval = 0;
	struct timeval			tv;
	struct hfsCatalogInfo 	catInfo;
	u_int32_t tehint = 0;
	DBG_VOP_LOCKS_DECL(4);

    DBG_FUNC_NAME("rename");DBG_VOP_PRINT_FUNCNAME();DBG_VOP_CONT(("\n"));
    DBG_VOP_CONT(("\t"));DBG_VOP_CONT(("Source:\t"));DBG_VOP_PRINT_VNODE_INFO(ap->a_fvp);DBG_VOP_CONT(("\n"));
    DBG_VOP_CONT(("\t"));DBG_VOP_CONT(("SourcePar: "));DBG_VOP_PRINT_VNODE_INFO(ap->a_fdvp);DBG_VOP_CONT(("\n"));
    DBG_VOP_CONT(("\t"));DBG_VOP_CONT(("Target:\t"));DBG_VOP_PRINT_VNODE_INFO(ap->a_tvp);DBG_VOP_CONT(("\n"));
    DBG_VOP_CONT(("\t"));DBG_VOP_CONT(("TargetPar: "));DBG_VOP_PRINT_VNODE_INFO(ap->a_tdvp);DBG_VOP_CONT(("\n"));
    DBG_VOP_CONT(("\t"));DBG_VOP_CONT(("SourceName:\t"));DBG_VOP_PRINT_CPN_INFO(ap->a_fcnp);DBG_VOP_CONT(("\n"));
    DBG_VOP_CONT(("\t"));DBG_VOP_CONT(("TargetName:\t"));DBG_VOP_PRINT_CPN_INFO(ap->a_tcnp);DBG_VOP_CONT(("\n"));
    DBG_VOP_LOCKS_INIT(0,ap->a_fdvp, VOPDBG_UNLOCKED, VOPDBG_UNLOCKED, VOPDBG_UNLOCKED, VOPDBG_POS);
    DBG_VOP_LOCKS_INIT(1,ap->a_fvp, VOPDBG_UNLOCKED, VOPDBG_UNLOCKED, VOPDBG_UNLOCKED, VOPDBG_POS);
    DBG_VOP_LOCKS_INIT(2,ap->a_tdvp, VOPDBG_LOCKED, VOPDBG_UNLOCKED, VOPDBG_UNLOCKED, VOPDBG_POS);
    DBG_VOP_LOCKS_INIT(3,ap->a_tvp, VOPDBG_LOCKNOTNIL, VOPDBG_UNLOCKED, VOPDBG_UNLOCKED, VOPDBG_POS);
    WRITE_CK(ap->a_fdvp, funcname);
    DBG_HFS_NODE_CHECK(ap->a_fdvp);
    DBG_HFS_NODE_CHECK(ap->a_tdvp);

#if HFS_DIAGNOSTIC
    if ((target_cnp->cn_flags & HASBUF) == 0 ||
        (source_cnp->cn_flags & HASBUF) == 0)
        panic("hfs_rename: no name");
#endif

	DBG_ASSERT((ap->a_fdvp->v_type == VDIR) && (ap->a_tdvp->v_type == VDIR));
	target_hp = targetPar_hp = source_hp = sourcePar_hp = 0;

    /* If fvp is the same as tvp...then we are just changing case, ignore target_vp */
    /*
     * This must be done now, since the value of target_vp is used to 
     * determine wether to unlock it (for instance, goto abortit).
     * In this case, target_vp comes in unlocked
     */
    if (source_vp == target_vp)
        target_vp = NULL;
        
	/*
	 * Check for cross-device rename.
	 */
	if ((source_vp->v_mount != targetPar_vp->v_mount) ||
		(target_vp && (source_vp->v_mount != target_vp->v_mount))) {
		retval = EXDEV;
		goto abortit;
	}

	/*
	 * Check for access permissions
	 */
	if (target_vp && ((VTOH(target_vp)->h_meta->h_pflags & (IMMUTABLE | APPEND)) ||
					  (VTOH(targetPar_vp)->h_meta->h_pflags & APPEND))) {
		retval = EPERM;
		goto abortit;
	}

	/*
	 * Force Carbon renames to have MacUnicode encoding
	 */
	if ((VTOH(targetPar_vp)->h_nodeflags & IN_BYCNID) && (!ISSET(p->p_flag, P_TBE))) {
		tehint = kTextEncodingMacUnicode;
	}

	if ((retval = vn_lock(source_vp, LK_EXCLUSIVE, p)))
		goto abortit;

	sourcePar_hp = VTOH(sourcePar_vp);
	source_hp = VTOH(source_vp);
	oldparent = H_FILEID(sourcePar_hp);
	if ((source_hp->h_meta->h_pflags & (IMMUTABLE | APPEND)) || (sourcePar_hp->h_meta->h_pflags & APPEND)) {
		VOP_UNLOCK(source_vp, 0, p);
		retval = EPERM;
		goto abortit;
	}

	/*
	 * Be sure we are not renaming ".", "..", or an alias of ".". This
	 * leads to a crippled directory tree.	It's pretty tough to do a
	 * "ls" or "pwd" with the "." directory entry missing, and "cd .."
	 * doesn't work if the ".." entry is missing.
	 */
	if ((source_hp->h_meta->h_mode & IFMT) == IFDIR) {
		if ((source_cnp->cn_namelen == 1 && source_cnp->cn_nameptr[0] == '.')
			|| sourcePar_hp == source_hp
			|| (source_cnp->cn_flags&ISDOTDOT)
			|| (source_hp->h_nodeflags & IN_RENAME)) {
			VOP_UNLOCK(source_vp, 0, p);
			retval = EINVAL;
			goto abortit;
		}
		source_hp->h_nodeflags |= IN_RENAME;
		doingdirectory = TRUE;
	}

    /*
     *
     * >>>> Transit between abort and bad <<<<
     *
     */

    targetPar_hp = VTOH(targetPar_vp);
    if (target_vp)
    	target_hp = VTOH(target_vp);
    else
    	DBG_ASSERT(target_hp == NULL);

    newparent = H_FILEID(targetPar_hp);

	/* Test to make sure we are not crossing devices */
	/* XXX SER Is this necesary, does catalog manager take care of this? */
	if (target_vp) {
		if (H_DEV(target_hp) != H_DEV(targetPar_hp) || H_DEV(target_hp) != H_DEV(source_hp))
			panic("rename: EXDEV");
	}
	 else {
		if (H_DEV(targetPar_hp) != H_DEV(source_hp))
			panic("rename: EXDEV");
	};
	
    retval = VOP_ACCESS(source_vp, VWRITE, target_cnp->cn_cred, target_cnp->cn_proc);
    if (doingdirectory && (newparent != oldparent)) {
        if (retval)		/* write access check above */
            goto bad;
    }
	retval = 0;		/* Reset value from above, we dont care about it anymore */
	
	/*
	 * If the destination exists, then be sure its type (file or dir)
	 * matches that of the source.	And, if it is a directory make sure
	 * it is empty.	 Then delete the destination.
	 */
	if (target_vp) {

        /*
         * If the parent directory is "sticky", then the user must
         * own the parent directory, or the destination of the rename,
         * otherwise the destination may not be changed (except by
         * root). This implements append-only directories.
         */
        if ((targetPar_hp->h_meta->h_mode & S_ISTXT) && (target_cnp->cn_cred->cr_uid != 0) &&
            target_cnp->cn_cred->cr_uid != targetPar_hp->h_meta->h_uid &&
            target_cnp->cn_cred->cr_uid != target_hp->h_meta->h_uid) {
            retval = EPERM;
            goto bad;
        }

		/*
		 * VOP_REMOVE will vput targetPar_vp so we better bump 
		 * its ref count and relockit, always set target_vp to
		 * NULL afterwards to indicate that were done with it.
		 */
		VREF(targetPar_vp);

		cache_purge(target_vp);
            
#if HFS_HARDLINKS
		target_cnp->cn_flags &= ~SAVENAME;
#endif
		
		retval = VOP_REMOVE(targetPar_vp, target_vp, target_cnp);
		(void) vn_lock(targetPar_vp, LK_EXCLUSIVE | LK_RETRY, p);

		target_vp = NULL;
		target_hp = NULL;		
		
		if (retval) goto bad;

	};


	if (newparent != oldparent)
		vn_lock(sourcePar_vp, LK_EXCLUSIVE | LK_RETRY, p);

	/* remove the existing entry from the namei cache: */
	cache_purge(source_vp);

	INIT_CATALOGDATA(&catInfo.nodeData, 0);

	/* lock catalog b-tree */
	retval = hfs_metafilelocking(VTOHFS(source_vp), kHFSCatalogFileID, LK_EXCLUSIVE, p);
	if (retval) {
		if (newparent != oldparent)		/* unlock the lock we just got */
			VOP_UNLOCK(sourcePar_vp, 0, p);
		 goto bad;
 	};

	/* use source_cnp instead of H_NAME(source_hp) in case source is a hard link */
    retval = MoveRenameCatalogNode(HTOVCB(source_hp), H_DIRID(source_hp),
                                   source_cnp->cn_nameptr, H_HINT(source_hp),
                                   H_FILEID(VTOH(targetPar_vp)),
                                   target_cnp->cn_nameptr, &H_HINT(source_hp), tehint);
    retval = MacToVFSError(retval);

	if (retval == 0) {	
	    /* Look up the catalog entry just renamed since it might have been auto-decomposed */
	    catInfo.hint = H_HINT(source_hp);
	    retval = hfs_getcatalog(HTOVCB(source_hp), H_FILEID(targetPar_hp), target_cnp->cn_nameptr, target_cnp->cn_namelen, &catInfo);
	}

	/* unlock catalog b-tree */
	(void) hfs_metafilelocking(VTOHFS(source_vp), kHFSCatalogFileID, LK_RELEASE, p);

	if (newparent != oldparent)
		VOP_UNLOCK(sourcePar_vp, 0, p);

	if (retval)  goto bad;

	H_DIRID(source_hp) = H_FILEID(targetPar_hp);

	hfs_name_CatToMeta(&catInfo.nodeData, source_hp->h_meta);
	
	CLEAN_CATALOGDATA(&catInfo.nodeData);

	source_hp->h_nodeflags &= ~IN_RENAME;


	/*
	 * Timestamp both parent directories.
	 * Note that if this is a rename within the same directory,
	 * (where targetPar_hp == sourcePar_hp)
	 * the code below is still safe and correct.
	 */
	targetPar_hp->h_nodeflags |= IN_UPDATE;
	sourcePar_hp->h_nodeflags |= IN_UPDATE;
	tv = time;
	HFSTIMES(targetPar_hp, &tv, &tv);
	HFSTIMES(sourcePar_hp, &tv, &tv);

	vput(targetPar_vp);
	vrele(sourcePar_vp);
	vput(source_vp);

	DBG_VOP_LOCKS_TEST(retval);
	if (retval != E_NONE) {
		DBG_VOP_PRINT_FUNCNAME();DBG_VOP_CONT(("\tReturning with error %d\n",retval));
	}
	return (retval);

bad:;
	if (retval && doingdirectory)
		source_hp->h_nodeflags &= ~IN_RENAME;

    if (targetPar_vp == target_vp)
	    vrele(targetPar_vp);
    else
	    vput(targetPar_vp);

    if (target_vp)
	    vput(target_vp);

	vrele(sourcePar_vp);

    if (VOP_ISLOCKED(source_vp))
        vput(source_vp);
	else
    	vrele(source_vp);

    DBG_VOP_LOCKS_TEST(retval);
    if (retval != E_NONE) {
        DBG_VOP_PRINT_FUNCNAME();DBG_VOP_CONT(("\tReturning with error %d\n",retval));
    }
    return (retval);

abortit:;

    VOP_ABORTOP(targetPar_vp, target_cnp); /* XXX, why not in NFS? */

    if (targetPar_vp == target_vp)
	    vrele(targetPar_vp);
    else
	    vput(targetPar_vp);

    if (target_vp)
	    vput(target_vp);

    VOP_ABORTOP(sourcePar_vp, source_cnp); /* XXX, why not in NFS? */

	vrele(sourcePar_vp);
    vrele(source_vp);

    DBG_VOP_LOCKS_TEST(retval);
    if (retval != E_NONE) {
        DBG_VOP_PRINT_FUNCNAME();DBG_VOP_CONT(("\tReturning with error %d\n",retval));
    }
    return (retval);
}



/*
 * Mkdir system call
#% mkdir	dvp	L U U
#% mkdir	vpp	- L -
#
 vop_mkdir {
     IN WILLRELE struct vnode *dvp;
     OUT struct vnode **vpp;
     IN struct componentname *cnp;
     IN struct vattr *vap;

     We are responsible for freeing the namei buffer,
	 it is done in hfs_makenode()
*/

int
hfs_mkdir(ap)
struct vop_mkdir_args /* {
    struct vnode *a_dvp;
    struct vnode **a_vpp;
    struct componentname *a_cnp;
    struct vattr *a_vap;
} */ *ap;
{
	struct proc		*p = current_proc();
	int				retval;
	int				mode = MAKEIMODE(ap->a_vap->va_type, ap->a_vap->va_mode);

	DBG_FUNC_NAME("mkdir");
	DBG_VOP_LOCKS_DECL(2);
	DBG_VOP_PRINT_FUNCNAME();
	DBG_VOP_PRINT_VNODE_INFO(ap->a_dvp);
	DBG_VOP_PRINT_CPN_INFO(ap->a_cnp);DBG_VOP_CONT(("\n"));

	DBG_VOP_LOCKS_INIT(0,ap->a_dvp, VOPDBG_LOCKED, VOPDBG_UNLOCKED, VOPDBG_UNLOCKED, VOPDBG_POS);
	DBG_VOP_LOCKS_INIT(1,*ap->a_vpp, VOPDBG_IGNORE, VOPDBG_LOCKED, VOPDBG_IGNORE, VOPDBG_POS);

	DBG_VOP(("%s: parent 0x%x (%s)	ap->a_cnp->cn_nameptr %s\n", funcname, (u_int)VTOH(ap->a_dvp), H_NAME(VTOH(ap->a_dvp)), ap->a_cnp->cn_nameptr));
	WRITE_CK( ap->a_dvp, funcname);
	DBG_HFS_NODE_CHECK(ap->a_dvp);
	DBG_ASSERT(ap->a_dvp->v_type == VDIR);

	/* Create the vnode */
    DBG_ASSERT((ap->a_cnp->cn_flags & SAVESTART) == 0);
	retval = hfs_makenode(mode, 0, ap->a_dvp, ap->a_vpp, ap->a_cnp, p);
    DBG_VOP_UPDATE_VP(1, *ap->a_vpp);

    if (retval != E_NONE) {
        DBG_ERR(("%s: hfs_makenode FAILED: %s, %s\n", funcname, ap->a_cnp->cn_nameptr, H_NAME(VTOH(ap->a_dvp))));
        DBG_VOP_LOCKS_TEST(retval);
        return (retval);		
    }

    DBG_VOP_LOCKS_TEST(E_NONE);
    return (E_NONE);
}

/*
 * Rmdir system call.
#% rmdir	dvp	L U U
#% rmdir	vp	L U U
#
 vop_rmdir {
     IN WILLRELE struct vnode *dvp;
     IN WILLRELE struct vnode *vp;
     IN struct componentname *cnp;

     */

int
hfs_rmdir(ap)
struct vop_rmdir_args /* {
    struct vnode *a_dvp;
    struct vnode *a_vp;
    struct componentname *a_cnp;
} */ *ap;
{
    struct vnode *vp = ap->a_vp;
    struct vnode *dvp = ap->a_dvp;
    struct hfsnode *hp = VTOH(vp);
    struct proc *p = current_proc();
    int retval;
    DBG_FUNC_NAME("rmdir");
    DBG_VOP_LOCKS_DECL(2);
    DBG_VOP_PRINT_FUNCNAME();
    DBG_VOP(("\tParent: "));DBG_VOP_PRINT_VNODE_INFO(ap->a_dvp);DBG_VOP_CONT(("\n"));
    DBG_VOP(("\tTarget: "));DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP_CONT(("\n"));
    DBG_VOP(("\tTarget Name: "));DBG_VOP_PRINT_CPN_INFO(ap->a_cnp);DBG_VOP_CONT(("\n"));

    DBG_VOP_LOCKS_INIT(0,ap->a_dvp, VOPDBG_LOCKED, VOPDBG_UNLOCKED, VOPDBG_UNLOCKED, VOPDBG_POS);
    DBG_VOP_LOCKS_INIT(1,ap->a_vp, VOPDBG_LOCKED, VOPDBG_UNLOCKED, VOPDBG_UNLOCKED, VOPDBG_POS);

    if (dvp == vp) {
        vrele(vp);
        vput(vp);
        DBG_VOP_LOCKS_TEST(EINVAL);
        return (EINVAL);
    }
	
	/*
	 * HFS differs from UFS here in that we don't allow removing
	 * a directory that in use by others - even if its empty.
	 *
	 * In the future we might want to allow this just like we do
	 * for files (by renaming the busy directory).
	 */
#if 0
    if (vp->v_usecount > 1) {
        DBG_ERR(("%s: dir is busy, usecount is %d\n", funcname, vp->v_usecount ));
		retval = EBUSY;
		goto Err_Exit;
    }
#endif
    /* remove the entry from the namei cache: */
    cache_purge(vp);

	/* lock catalog b-tree */
	retval = hfs_metafilelocking(VTOHFS(vp), kHFSCatalogFileID, LK_EXCLUSIVE, p);
	if (retval != E_NONE) {
		goto Err_Exit;
	}

	/* remove entry from catalog */
    retval = hfsDelete (HTOVCB(hp), H_DIRID(hp), H_NAME(hp), FALSE, H_HINT(hp));

	/* unlock catalog b-tree */
	(void) hfs_metafilelocking(VTOHFS(vp), kHFSCatalogFileID, LK_RELEASE, p);

	if (! retval) {
		VTOH(dvp)->h_nodeflags |= IN_CHANGE | IN_UPDATE;	/* Set the parent to be updated */
        hp->h_meta->h_mode = 0;								/* Makes the vnode go away...see inactive */
		hp->h_meta->h_metaflags |= IN_NOEXISTS;
    }

Err_Exit:;
    if (dvp != 0) 
		vput(dvp);
    vput(vp);

    DBG_VOP_LOCKS_TEST(retval);
    return (retval);
}

/*
 * symlink -- make a symbolic link
#% symlink	dvp	L U U
#% symlink	vpp	- U -
#
# XXX - note that the return vnode has already been VRELE'ed
#	by the filesystem layer.  To use it you must use vget,
#	possibly with a further namei.
#
 vop_symlink {
     IN WILLRELE struct vnode *dvp;
     OUT WILLRELE struct vnode **vpp;
     IN struct componentname *cnp;
     IN struct vattr *vap;
     IN char *target;

     We are responsible for freeing the namei buffer, 
	 it is done in hfs_makenode().

*/

int
hfs_symlink(ap)
    struct vop_symlink_args /* {
        struct vnode *a_dvp;
        struct vnode **a_vpp;
        struct componentname *a_cnp;
        struct vattr *a_vap;
        char *a_target;
    } */ *ap;
{
    register struct vnode *vp, **vpp = ap->a_vpp;
	struct proc *p = current_proc();
	struct hfsnode *hp;
    int len, retval;
	struct buf *bp = NULL;

	/* HFS standard disks don't support symbolic links */
    if (VTOVCB(ap->a_dvp)->vcbSigWord != kHFSPlusSigWord) {
    	VOP_ABORTOP(ap->a_dvp, ap->a_cnp);
        vput(ap->a_dvp);
        return (EOPNOTSUPP);
    }

	/* Check for empty target name */
	if (ap->a_target[0] == 0) {
		VOP_ABORTOP(ap->a_dvp, ap->a_cnp);
		vput(ap->a_dvp);
		return (EINVAL);
	}

	/* Create the vnode */
	retval = hfs_makenode(IFLNK | ap->a_vap->va_mode, 0, ap->a_dvp,
				vpp, ap->a_cnp, p);
    DBG_VOP_UPDATE_VP(1, *ap->a_vpp);

    if (retval != E_NONE) {
        return (retval);
	}

    vp = *vpp;
    len = strlen(ap->a_target);
	hp = VTOH(vp);
	hp->fcbClmpSize = VTOVCB(vp)->blockSize;

	/* Allocate space for the link */
	retval = VOP_TRUNCATE(vp, len, IO_NOZEROFILL,
	                      ap->a_cnp->cn_cred, ap->a_cnp->cn_proc);
	if (retval)
		goto out;

	/* Write the link to disk */
	bp = getblk(vp, 0, roundup((int)hp->fcbEOF, kHFSBlockSize), 0, 0, BLK_META);
	bzero(bp->b_data, bp->b_bufsize);
	bcopy(ap->a_target, bp->b_data, len);
	bp->b_flags |= B_DIRTY;
	bawrite(bp);

out:
    vput(vp);
    return (retval);
}


/*
 * Dummy dirents to simulate the "." and ".." entries of the directory
 * in a hfs filesystem.  HFS doesn't provide these on disk.  Note that
 * the size of these entries is the smallest needed to represent them
 * (only 12 byte each).
 */
static hfsdotentry  rootdots[2] = {
	{
		1,				/* d_fileno */
		sizeof(struct hfsdotentry),	/* d_reclen */
		DT_DIR,				/* d_type */
		1,				/* d_namlen */
		"."				/* d_name */
    },
    {
		1,				/* d_fileno */
		sizeof(struct hfsdotentry),	/* d_reclen */
		DT_DIR,				/* d_type */
		2,				/* d_namlen */
		".."				/* d_name */
	}
};

static hfsdotentry  emptyentry = { 0 };

/*	4.3 Note:
*	There is some confusion as to what the semantics of uio_offset are.
*	In ufs, it represents the actual byte offset within the directory
*	"file."  HFS, however, just uses it as an entry counter - essentially
*	assuming that it has no meaning except to the hfs_readdir function.
*	This approach would be more efficient here, but some callers may
*	assume the uio_offset acts like a byte offset.  NFS in fact
*	monkeys around with the offset field a lot between readdir calls.
*
*	The use of the resid uiop->uio_resid and uiop->uio_iov->iov_len
*	fields is a mess as well.  The libc function readdir() returns
*	NULL (indicating the end of a directory) when either
*	the getdirentries() syscall (which calls this and returns
*	the size of the buffer passed in less the value of uiop->uio_resid)
*	returns 0, or a direct record with a d_reclen of zero.
*	nfs_server.c:rfs_readdir(), on the other hand, checks for the end
*	of the directory by testing uiop->uio_resid == 0.  The solution
*	is to pad the size of the last struct direct in a given
*	block to fill the block if we are not at the end of the directory.
*/

struct callbackstate {
	u_int32_t	cbs_parentID;
	u_int32_t	cbs_hiddenDirID;
	off_t		cbs_lastoffset;
	struct uio *	cbs_uio;
	ExtendedVCB *	cbs_vcb;
	int16_t		cbs_hfsPlus;
	int16_t		cbs_result;
};


SInt32
ProcessCatalogEntry(const CatalogKey *ckp, const CatalogRecord *crp,
		    u_int16_t recordLen, struct callbackstate *state)
{
	CatalogName *cnp;
	size_t utf8chars;
	u_int32_t curID;
	OSErr result;
	struct dirent catent;
	
	if (state->cbs_hfsPlus)
		curID = ckp->hfsPlus.parentID;
	else
		curID = ckp->hfs.parentID;

	/* We're done when parent directory changes */
	if (state->cbs_parentID != curID) {
lastitem:
/*
 * The NSDirectoryList class chokes on empty records (it doesnt check d_reclen!)
 * so remove padding for now...
 */
#if 0
		/*
		 * Pad the end of list with an empty record.
		 * This eliminates an extra call by readdir(3c).
		 */
		catent.d_fileno = 0;
		catent.d_reclen = 0;
		catent.d_type = 0;
		catent.d_namlen = 0;
		*(int32_t*)&catent.d_name[0] = 0;

		state->cbs_lastoffset = state->cbs_uio->uio_offset;

		state->cbs_result = uiomove((caddr_t) &catent, 12, state->cbs_uio);
		if (state->cbs_result == 0)
			state->cbs_result = ENOENT;
#else
		state->cbs_lastoffset = state->cbs_uio->uio_offset;
		state->cbs_result = ENOENT;
#endif
		return (0);	/* stop */
	}

	if (state->cbs_hfsPlus) {
		switch(crp->recordType) {
		case kHFSPlusFolderRecord:
			catent.d_type = DT_DIR;
			catent.d_fileno = crp->hfsPlusFolder.folderID;
			break;
		case kHFSPlusFileRecord:
			catent.d_type = DT_REG;
			catent.d_fileno = crp->hfsPlusFile.fileID;
			break;
		default:
			return (0);	/* stop */
		};

		cnp = (CatalogName*) &ckp->hfsPlus.nodeName;
		result = utf8_encodestr(cnp->ustr.unicode, cnp->ustr.length * sizeof(UniChar),
				catent.d_name, &utf8chars, kdirentMaxNameBytes + 1, ':', 0);
		if (result == ENAMETOOLONG) {
			result = ConvertUnicodeToUTF8Mangled(cnp->ustr.length * sizeof(UniChar),
			    	cnp->ustr.unicode, kdirentMaxNameBytes + 1, (ByteCount*)&utf8chars, catent.d_name, catent.d_fileno);		
		}
	} else { /* hfs */
		switch(crp->recordType) {
		case kHFSFolderRecord:
			catent.d_type = DT_DIR;
			catent.d_fileno = crp->hfsFolder.folderID;
			break;
		case kHFSFileRecord:
			catent.d_type = DT_REG;
			catent.d_fileno = crp->hfsFile.fileID;
			break;
		default:
			return (0);	/* stop */
		};

		cnp = (CatalogName*) ckp->hfs.nodeName;
		result = hfs_to_utf8(state->cbs_vcb, cnp->pstr, kdirentMaxNameBytes + 1,
				    (ByteCount *)&utf8chars, catent.d_name);
		/*
		 * When an HFS name cannot be encoded with the current
		 * volume encoding we use MacRoman as a fallback.
		 */
		if (result)
			result = mac_roman_to_utf8(cnp->pstr, kdirentMaxNameBytes + 1,
				    (ByteCount *)&utf8chars, catent.d_name);
	}

	catent.d_namlen = utf8chars;
	catent.d_reclen = DIRENTRY_SIZE(utf8chars);
	
	/* hide our private meta data directory */
	if (curID == kRootDirID				&&
	    catent.d_fileno == state->cbs_hiddenDirID	&&
	    catent.d_type == DT_DIR)
		goto lastitem;

	state->cbs_lastoffset = state->cbs_uio->uio_offset;

	/* if this entry won't fit then we're done */
	if (catent.d_reclen > state->cbs_uio->uio_resid)
		return (0);	/* stop */

	state->cbs_result = uiomove((caddr_t) &catent, catent.d_reclen, state->cbs_uio);

	/* continue iteration if there's room */
	return (state->cbs_result == 0  &&
		state->cbs_uio->uio_resid >= AVERAGE_HFSDIRENTRY_SIZE);
}

/*
 * NOTE: We require a minimal buffer size of DIRBLKSIZ for two reasons. One, it is the same value
 * returned be stat() call as the block size. This is mentioned in the man page for getdirentries():
 * "Nbytes must be greater than or equal to the block size associated with the file,
 * see stat(2)". Might as well settle on the same size of ufs. Second, this makes sure there is enough
 * room for the . and .. entries that have to added manually.
 */

/* 			
#% readdir	vp	L L L
#
vop_readdir {
    IN struct vnode *vp;
    INOUT struct uio *uio;
    IN struct ucred *cred;
    INOUT int *eofflag;
    OUT int *ncookies;
    INOUT u_long **cookies;
    */
static int
hfs_readdir(ap)
struct vop_readdir_args /* {
    struct vnode *vp;
    struct uio *uio;
    struct ucred *cred;
    int *eofflag;
    int *ncookies;
    u_long **cookies;
} */ *ap;
{
    register struct uio *uio = ap->a_uio;
    struct hfsnode 		*hp = VTOH(ap->a_vp);
    struct proc			*p = current_proc();
    ExtendedVCB 		*vcb = HTOVCB(hp);
    off_t 				off = uio->uio_offset;
	u_int32_t dirID = H_FILEID(hp);
	int retval = 0;
    OSErr				result = noErr;
	u_int32_t diroffset;
	BTreeIterator bi;
	CatalogIterator *cip;
	u_int16_t op;
	struct callbackstate state;
	int eofflag = 0;

    DBG_FUNC_NAME("readdir");
    DBG_VOP_LOCKS_DECL(1);

    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_POS);
    DBG_VOP_PRINT_FUNCNAME();
    DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP_CONT(("\n"));
    DBG_HFS_NODE_CHECK(ap->a_vp);

    /* We assume it's all one big buffer... */
	if (uio->uio_iovcnt > 1 || uio->uio_resid < AVERAGE_HFSDIRENTRY_SIZE) {
		return EINVAL;
	};

	/* Create the entries for . and .. */
	if (uio->uio_offset < sizeof(rootdots)) {
		caddr_t dep;
		size_t dotsize;
		
		rootdots[0].d_fileno = dirID;
		rootdots[1].d_fileno = H_DIRID(hp);

		if (uio->uio_offset == 0) {
			dep = (caddr_t) &rootdots[0];
			dotsize = 2* sizeof(struct hfsdotentry);
		} else if (uio->uio_offset == sizeof(struct hfsdotentry)) {
			dep = (caddr_t) &rootdots[1];
			dotsize = sizeof(struct hfsdotentry);
		} else {
			retval = EINVAL;
			goto Exit;
		}

		retval = uiomove(dep, dotsize, uio);
		if (retval != 0)
			goto Exit;
	}
	
	diroffset = uio->uio_offset;

	/* lock catalog b-tree */
	retval = hfs_metafilelocking(VTOHFS(ap->a_vp), kHFSCatalogFileID, LK_SHARED, p);
	if (retval != E_NONE)
		goto Exit;

	/* get an iterator and position it */
	cip = GetCatalogIterator(vcb, dirID, diroffset);

	result = PositionIterator(cip, diroffset, &bi, &op);
	if (result == cmNotFound) {
		eofflag = 1;
		retval = 0;
		AgeCatalogIterator(cip);
		goto cleanup;
	} else if ((retval = MacToVFSError(result)))
		goto cleanup;

	state.cbs_hiddenDirID = VCBTOHFS(vcb)->hfs_private_metadata_dir;
	state.cbs_lastoffset = cip->currentOffset;
	state.cbs_vcb = vcb;
	state.cbs_uio = uio;
	state.cbs_result = 0;
	state.cbs_parentID = dirID;

	if (vcb->vcbSigWord == kHFSPlusSigWord)
		state.cbs_hfsPlus = 1;
	else
		state.cbs_hfsPlus = 0;

	/* process as many entries as possible... */
	result = BTIterateRecords(GetFileControlBlock(vcb->catalogRefNum), op, &bi,
		 (IterateCallBackProcPtr)ProcessCatalogEntry, &state);

	if (state.cbs_result)
		retval = state.cbs_result;
	else
		retval = MacToVFSError(result);

	if (retval == ENOENT) {
		eofflag = 1;
		retval = 0;
	}

	if (retval == 0) {
		cip->currentOffset = state.cbs_lastoffset;
		cip->nextOffset = uio->uio_offset;
		UpdateCatalogIterator(&bi, cip);
	}

cleanup:
	if (retval) {
		cip->volume = 0;
		cip->folderID = 0;
		AgeCatalogIterator(cip);
	}

	(void) ReleaseCatalogIterator(cip);

	/* unlock catalog b-tree */
	(void) hfs_metafilelocking(VTOHFS(ap->a_vp), kHFSCatalogFileID, LK_RELEASE, p);

    if (retval != E_NONE) {
        DBG_ERR(("%s: retval %d when trying to read directory %ld: %s\n",funcname, retval,
                H_FILEID(hp), H_NAME(hp)));
		goto Exit;

	}
	
	/* were we already past eof ? */
	if (uio->uio_offset == off) {
		retval = E_NONE;
		goto Exit;
	}
	
	if (vcb->vcbSigWord == kHFSPlusSigWord)
		hp->h_nodeflags |= IN_ACCESS;

    /* Bake any cookies */
    if (!retval && ap->a_ncookies != NULL) {
        struct dirent* dpStart;
        struct dirent* dpEnd;
        struct dirent* dp;
        int ncookies;
        u_long *cookies;
        u_long *cookiep;

        /*
        * Only the NFS server uses cookies, and it loads the
        * directory block into system space, so we can just look at
        * it directly.
        */
	    if (uio->uio_segflg != UIO_SYSSPACE)
            panic("hfs_readdir: unexpected uio from NFS server");
        dpStart = (struct dirent *)(uio->uio_iov->iov_base - (uio->uio_offset - off));
        dpEnd = (struct dirent *) uio->uio_iov->iov_base;
        for (dp = dpStart, ncookies = 0;
            dp < dpEnd && dp->d_reclen != 0;
            dp = (struct dirent *)((caddr_t)dp + dp->d_reclen))
            ncookies++;
        MALLOC(cookies, u_long *, ncookies * sizeof(u_long), M_TEMP, M_WAITOK);
        for (dp = dpStart, cookiep = cookies;
            dp < dpEnd;
            dp = (struct dirent *)((caddr_t) dp + dp->d_reclen)) {
            off += dp->d_reclen;
            *cookiep++ = (u_long) off;
        }
        *ap->a_ncookies = ncookies;
        *ap->a_cookies = cookies;
    }

Exit:;

    if (ap->a_eofflag)
	    *ap->a_eofflag = eofflag;

    DBG_VOP_LOCKS_TEST(retval);
    return (retval);
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
     * 1.getattrlist creates a thread record if the objpermanentid attribute
     *  is requested. Just do EINVAL for now and fix later. 
     * 2. more than one for uiovcnt support.
     * 3. put knohint (hints) in state for next call in
     * 4. credentials checking when rest of hfs does it.
     * 5. Do return permissions concatenation ???
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
static int
hfs_readdirattr(ap)
struct vop_readdirattr_args /* {
    struct vnode *vp;
    struct attrlist *alist;
    struct uio *uio;
    u_long maxcount:
    u_long options;
    int *newstate;
    int *eofflag;
    u_long *actualcount;
    u_long **cookies;
    struct ucred *cred;
} */ *ap;
{
    struct vnode 	*vp = ap->a_vp;
    struct attrlist 	*alist = ap->a_alist;
    register struct 	uio *uio = ap->a_uio;
    u_long 		maxcount = ap->a_maxcount;
    u_long 		ncookies;
    ExtendedVCB 	*vcb = HTOVCB(VTOH(vp));
    UInt32		dirID =  H_FILEID(VTOH(vp));
    struct proc		*proc = current_proc(); /* could get this out of uio */
    off_t		startoffset = uio->uio_offset;
    struct hfsCatalogInfo catInfo;
    UInt32		index;
    int			retval = 0;
    u_long 		fixedblocksize;
    u_long 		maxattrblocksize;
    u_long		currattrbufsize;
    void 		*attrbufptr = NULL;
    void 		*attrptr;
    void 		*varptr; 

    *(ap->a_actualcount) = 0;
    *(ap->a_eofflag) = 0;

    /* check for invalid options, check vnode, and buffer space */
    if (((ap->a_options & ~FSOPT_NOINMEMUPDATE) != 0) ||
    	(vp == NULL) || 
		(uio->uio_resid <= 0) || (uio->uio_iovcnt > 1))
	   return EINVAL;

    /* this call doesn't take volume attributes */
    if ((alist->bitmapcount != ATTR_BIT_MAP_COUNT) ||
        ((alist->commonattr & ~ATTR_CMN_VALIDMASK) != 0) ||
        (alist->volattr  != 0) ||
        ((alist->dirattr & ~ATTR_DIR_VALIDMASK) != 0) ||
        ((alist->fileattr & ~ATTR_FILE_VALIDMASK) != 0) ||
        ((alist->forkattr & ~ATTR_FORK_VALIDMASK) != 0)) 
        return EINVAL;

    /* Reject requests for unsupported options for now: */
    if ((alist->commonattr & (ATTR_CMN_NAMEDATTRCOUNT | ATTR_CMN_NAMEDATTRLIST)) ||
        (alist->fileattr & (ATTR_FILE_FILETYPE | ATTR_FILE_FORKCOUNT | ATTR_FILE_FORKLIST)) ||
	(alist->commonattr & ATTR_CMN_OBJPERMANENTID) ) 
        return EINVAL;

    /* getattrlist and searchfs use a secondary buffer to malloc and then use
     * uiomove afterwards. It's an extra copy, but for now leave it alone
    */
    fixedblocksize = (sizeof(u_long) + AttributeBlockSize(alist)); /* u_long for length */
    maxattrblocksize = fixedblocksize;
    if (alist->commonattr & ATTR_CMN_NAME) 
	maxattrblocksize += kHFSPlusMaxFileNameBytes + 1;
    MALLOC(attrbufptr, void *, maxattrblocksize, M_TEMP, M_WAITOK);
    attrptr = attrbufptr;
    varptr = (char *)attrbufptr + fixedblocksize;  /* Point to variable-length storage */

    /* Since attributes passed back can contain variable ones (name), we can't just use 
     * uio_offset as is. We thus force it to represent fixed size of hfsdirentries
     * as hfs_readdir was originally doing. If this all we need to represent the current
     * state, then ap->a_state is not needed at all.
    */
    /* index = ap->a_state;  should not be less than 1 */
    index = (uio->uio_offset / sizeof(struct dirent)) + 1;
	INIT_CATALOGDATA(&catInfo.nodeData, 0);


    /* HFS Catalog does not have a bulk directory enumeration call. Do it one at
     * time, using hints. GetCatalogOffspring takes care of hfsplus and name issues
     * for us, so that's a win. Later, implement GetCatalogOffspringBulk.
    */
    catInfo.hint = kNoHint; /* note, we may want to save the latest in state */
    while ((uio->uio_resid >= 0) && (maxcount !=0 )) {
        /* better to check uio_resid against max or fixedblocksize, but won't work.
         * Depending on if dir or file, the attributes returned will be different.
         * Thus fixedblocksize is too large in some cases.Also, the variable
         * part (like name)  could be between fixedblocksize and the max.
        */
	OSErr result;

        /* Lock catalog b-tree */  
        if ((retval = hfs_metafilelocking(VTOHFS(vp), kHFSCatalogFileID, LK_SHARED, proc)) != E_NONE)
            goto exit;

		catInfo.nodeData.cnd_iNodeNumCopy = 0;
		result = GetCatalogOffspring(vcb, dirID, index, &catInfo.nodeData, NULL, NULL);
		if (result == 0)
			hfs_resolvelink(vcb, &catInfo.nodeData);
 
       /* Unlock catalog b-tree, unconditionally . Ties up the everything during enumeration */
        (void) hfs_metafilelocking( VTOHFS(ap->a_vp), kHFSCatalogFileID, LK_RELEASE, proc );
 
        if (result != noErr) {
            if (result == cmNotFound) {
                *(ap->a_eofflag) = TRUE;
                retval = E_NONE;
            }
            else retval = MacToVFSError(result);
            break;
        }

	/* hide our private meta data directory as does hfs_readdir */
	if ((dirID == kRootDirID)  &&
	    catInfo.nodeData.cnd_nodeID == VCBTOHFS(vcb)->hfs_private_metadata_dir  &&
	    catInfo.nodeData.cnd_type == kCatalogFolderNode) {

	    ++index;
	     CLEAN_CATALOGDATA(&catInfo.nodeData);
	     continue;
	}

        *((u_long *)attrptr)++ = 0; /* move it past length */

		/*
		 * Don't use data from cached vnodes when FSOPT_NOINMEMUPDATE
		 * option is active or if this entry is a hard link.
		 */
		if ((ap->a_options & FSOPT_NOINMEMUPDATE)
			|| (catInfo.nodeData.cnd_iNodeNumCopy != 0)) {
			/* vp okay to use instead of root vp */
			PackCatalogInfoAttributeBlock(alist, vp, &catInfo, &attrptr, &varptr);
		} else {
			struct vnode *entry_vp = NULL;
			struct vnode *rsrc_vp = NULL;
			int nodetype;
			UInt32 nodeid;

			/*
			 * Flush out any in-memory state to the catalog record.
			 *
			 * In the HFS locking hierarchy, the data fork vnode must
			 * be acquired before the resource fork vnode.
			 */
			nodeid = catInfo.nodeData.cnd_nodeID;
			if (catInfo.nodeData.cnd_type == kCatalogFolderNode)
				nodetype = kDirectory;
			else
				nodetype = kDataFork;
	
			/* Check for this entry's cached vnode: */
			entry_vp = hfs_vhashget(H_DEV(VTOH(vp)), nodeid, nodetype);

			/* Also check for a cached resource fork vnode: */
			if (nodetype == kDataFork) {
				rsrc_vp = hfs_vhashget(H_DEV(VTOH(vp)), nodeid, kRsrcFork);
				if ((rsrc_vp != NULL)
					&& (VTOH(rsrc_vp)->h_nodeflags & (IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE))) {
						/* Pick up resource fork info */
						CopyVNodeToCatalogNode(rsrc_vp, &catInfo.nodeData);
				}
			}
			
			if (entry_vp != NULL)
				PackAttributeBlock(alist, entry_vp, &catInfo, &attrptr, &varptr);
			else if (rsrc_vp != NULL)
				PackAttributeBlock(alist, rsrc_vp, &catInfo, &attrptr, &varptr);
			else
				PackCatalogInfoAttributeBlock(alist, vp, &catInfo, &attrptr, &varptr);
			
			if (rsrc_vp)
				vput(rsrc_vp);
			if (entry_vp)
				vput(entry_vp);
		}
		currattrbufsize = *((u_long *)attrbufptr) = ((char *)varptr - (char *)attrbufptr);
		
        /* now check if we can't fit in the buffer space remaining */
        if (currattrbufsize > uio->uio_resid) 
            break;
		else { 
	            retval = uiomove((caddr_t)attrbufptr, currattrbufsize, ap->a_uio);
	            if (retval != E_NONE)
	                break; 
	            attrptr = attrbufptr;
                    varptr = (char *)attrbufptr + fixedblocksize;  /* Point to variable-length storage */
	            index++;
		    *ap->a_actualcount += 1;
		    maxcount--;
		}
    /* Clean for the next loop */
	CLEAN_CATALOGDATA(&catInfo.nodeData);
    };
    *ap->a_newstate = VTOH(vp)->h_meta->h_mtime;/* before we unlock, know the mod date */
    
	CLEAN_CATALOGDATA(&catInfo.nodeData);

    if (!retval && ap->a_cookies != NULL) { /* CHECK THAT 0 wasn't passed in */
        void* dpStart;
        void* dpEnd;
        void* dp;
	u_long *cookies;
	u_long *cookiep;

        /* Only the NFS server uses cookies, and it loads the
         * directory block into system space, so we can just look at
         * it directly.
        */
        if (uio->uio_segflg != UIO_SYSSPACE) /* || uio->uio_iovcnt != 1 checked earlier */
            panic("hfs_readdirattr: unexpected uio from NFS server");
        dpStart = uio->uio_iov->iov_base - (uio->uio_offset - startoffset);
        dpEnd = uio->uio_iov->iov_base;
        MALLOC(cookies, u_long *, (*ap->a_actualcount)*sizeof(u_long), M_TEMP, M_WAITOK);
        for (dp = dpStart, cookiep = cookies;
            dp < dpEnd;
             dp = ((caddr_t) dp + *((u_long *)dp))) {
        	*cookiep++ = (u_long)((caddr_t)dp + sizeof(u_long));
        }
	*ap->a_cookies = cookies;
    }
    
   uio->uio_offset = startoffset + (*ap->a_actualcount)*sizeof(struct dirent);

exit:
    if (attrbufptr != NULL)
	FREE(attrbufptr, M_TEMP);
    return (retval);
}


/*
 * Return target name of a symbolic link
#% readlink	vp	L L L
#
 vop_readlink {
     IN struct vnode *vp;
     INOUT struct uio *uio;
     IN struct ucred *cred;
     */

int
hfs_readlink(ap)
struct vop_readlink_args /* {
struct vnode *a_vp;
struct uio *a_uio;
struct ucred *a_cred;
} */ *ap;
{
	int retval;
	struct vnode *vp = ap->a_vp;
	struct hfsnode *hp = VTOH(vp);

	if (vp->v_type != VLNK)
		return (EINVAL);
    
    /* Zero length sym links are not allowed */
    if (hp->fcbEOF == 0) {
        VTOVCB(vp)->vcbFlags |= kHFS_DamagedVolume;
        return (EINVAL);
    }
    
	/* Cache the path so we don't waste buffer cache resources */
	if (hp->h_symlinkptr == NULL) {
		struct buf *bp = NULL;

		if (H_ISBIGLINK(hp))
			MALLOC(hp->h_symlinkptr, char *, hp->fcbEOF, M_TEMP, M_WAITOK);

		retval = meta_bread(vp, 0, roundup((int)hp->fcbEOF, kHFSBlockSize), ap->a_cred, &bp);
		if (retval) {
			if (bp)
				brelse(bp);
			if (hp->h_symlinkptr) {
				FREE(hp->h_symlinkptr, M_TEMP);
				hp->h_symlinkptr = NULL;
			}
			return (retval);
		}
		
		bcopy(bp->b_data, H_SYMLINK(hp), (size_t)hp->fcbEOF);

		if (bp) {
			bp->b_flags |= B_INVAL;		/* data no longer needed */
			brelse(bp);
		}
	}

	retval = uiomove((caddr_t)H_SYMLINK(hp), (int)hp->fcbEOF, ap->a_uio);

	return (retval);
}


/*
 * hfs abort op, called after namei() when a CREATE/DELETE isn't actually
 * done. If a buffer has been saved in anticipation of a CREATE, delete it.
#% abortop	dvp	= = =
#
 vop_abortop {
     IN struct vnode *dvp;
     IN struct componentname *cnp;

     */

/* ARGSUSED */

static int
hfs_abortop(ap)
struct vop_abortop_args /* {
    struct vnode *a_dvp;
    struct componentname *a_cnp;
} */ *ap;
{
    DBG_FUNC_NAME("abortop");
    DBG_VOP_LOCKS_DECL(1);
    DBG_VOP_PRINT_FUNCNAME();
    DBG_VOP_PRINT_VNODE_INFO(ap->a_dvp);
    DBG_VOP_PRINT_CPN_INFO(ap->a_cnp);DBG_VOP_CONT(("\n"));


    DBG_VOP_LOCKS_INIT(0,ap->a_dvp, VOPDBG_IGNORE, VOPDBG_IGNORE, VOPDBG_IGNORE, VOPDBG_POS);

    if ((ap->a_cnp->cn_flags & (HASBUF | SAVESTART)) == HASBUF) {
        FREE_ZONE(ap->a_cnp->cn_pnbuf, ap->a_cnp->cn_pnlen, M_NAMEI);
    }
    DBG_VOP_LOCKS_TEST(E_NONE);
    return (E_NONE);
}

// int	prthfsactive = 0;		/* 1 => print out reclaim of active vnodes */

/*
#% inactive	vp	L U U
#
 vop_inactive {
     IN struct vnode *vp;
     IN struct proc *p;

*/

static int
hfs_inactive(ap)
struct vop_inactive_args /* {
    struct vnode *a_vp;
} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct hfsnode *hp = VTOH(vp);
	struct proc *p = ap->a_p;
	struct timeval tv;
	int error = 0;
	extern int prtactive;

	DBG_FUNC_NAME("inactive");
	DBG_VOP_LOCKS_DECL(1);
	DBG_VOP_PRINT_FUNCNAME();
	DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP_CONT(("\n"));

	DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_LOCKED, VOPDBG_UNLOCKED, VOPDBG_UNLOCKED, VOPDBG_ZERO);


	if (prtactive && vp->v_usecount <= 0)
		vprint("hfs_inactive: pushing active", vp);

	if (vp->v_usecount != 0)
		DBG_VOP(("%s: bad usecount = %d\n",funcname,vp->v_usecount ));

	/*
	 * Ignore nodes related to stale file handles.
	 */
	if (hp->h_meta->h_mode == 0)
		goto out;
	
	/*
	 * Check for a postponed deletion
	 */
	if (hp->h_meta->h_metaflags & IN_DELETED) {			
		hp->h_meta->h_metaflags &= ~IN_DELETED;

		error = vinvalbuf(vp, 0, NOCRED, p, 0, 0);
		if (error) goto out;
        
        if(UBCINFOEXISTS(vp))
                (void)ubc_setsize(vp, (off_t)0);

		/* Lock both trees
		 * Note: we do not need a lock on the private metadata directory
		 * since it never has a vnode associated with it.
		 */
        error = hfs_metafilelocking(VTOHFS(vp), kHFSCatalogFileID, LK_EXCLUSIVE | LK_CANRECURSE, p);
        if (error) goto out;
        error = hfs_metafilelocking(VTOHFS(vp), kHFSExtentsFileID, LK_EXCLUSIVE | LK_CANRECURSE, p);
        if (error) {
                (void) hfs_metafilelocking(VTOHFS(vp), kHFSCatalogFileID, LK_RELEASE, p);
                goto out;
        }

        if (hp->h_meta->h_metaflags & IN_DATANODE) {
                char iNodeName[32];

                MAKE_INODE_NAME(iNodeName, hp->h_meta->h_indnodeno);
                error = hfsDelete(HTOVCB(hp), VTOHFS(vp)->hfs_private_metadata_dir, iNodeName, TRUE, H_HINT(hp));
        } else {
                /* XXX can we leave orphaned sibling? */
                error = hfsDelete(HTOVCB(hp), H_DIRID(hp), H_NAME(hp), TRUE, H_HINT(hp));
                if (error == ENOENT) {
                        /* try by fileID as a backup */
                        error = hfsDelete(HTOVCB(hp), H_FILEID(hp), NULL, TRUE, H_HINT(hp));
                }
        }

        (void) hfs_metafilelocking(VTOHFS(vp), kHFSExtentsFileID, LK_RELEASE, p);
        (void) hfs_metafilelocking(VTOHFS(vp), kHFSCatalogFileID, LK_RELEASE, p);
        if (error) goto out;

        hp->h_meta->h_metaflags |=  IN_NOEXISTS;
        hp->h_meta->h_mode = 0;
		/* clear the block mappings */
		hp->fcbPLen = (u_int64_t)0;
		bzero(&hp->fcbExtents, sizeof(HFSPlusExtentRecord));

        hp->h_nodeflags &= ~(IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE);
        }

        if (hp->h_nodeflags & (IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE)) {
                tv = time;
                VOP_UPDATE(vp, &tv, &tv, 0);
        }

out:
	VOP_UNLOCK(vp, 0, p);
	/*
	 * If we are done with the inode, reclaim it
	 * so that it can be reused immediately.
	 */
	if (hp->h_meta->h_mode == 0)
		vrecycle(vp, (struct slock *)0, p);
	
	/* XXX SER Here we might want to get rid of any other forks
	 * The problem is that if we call vrecycle(), our structure
	 * disappear from under us, we would need to remember, and expect
	 * things to go to null or to disappear
	 * But it stillw would be a good thing to remove vnodes
	 * referencing stale data
		 */

	DBG_VOP_LOCKS_TEST(E_NONE);
	return (E_NONE);
}

/*
 Ignored since the locks are gone......
#% reclaim	vp	U I I
#
 vop_reclaim {
	 IN struct vnode *vp;
	 IN struct proc *p;

	 */

static int
hfs_reclaim(ap)
struct vop_reclaim_args /* {
	struct vnode *a_vp;
} */ *ap;
{
	struct vnode 	*vp = ap->a_vp;
	struct hfsnode 	*hp = VTOH(vp);
	void			*tdata = vp->v_data;
	char			*tname;
	Boolean			freeMeta = true;
	struct vnode 	*devvp = NULL;
	
	extern int prtactive;
	DBG_FUNC_NAME("reclaim");
	DBG_VOP_LOCKS_DECL(1);
	DBG_VOP_PRINT_FUNCNAME();
	DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP_CONT(("\n"));

	DBG_VOP_LOCKS_INIT(0, ap->a_vp, VOPDBG_UNLOCKED, VOPDBG_IGNORE, VOPDBG_IGNORE, VOPDBG_ZERO);

	/*
		NOTE: XXX vnodes need careful handling because fork vnodes that failed to be
			  created in their entirity could be getting cleaned up here.
	 */

	if (prtactive && vp->v_usecount != 0)
		vprint("hfs_reclaim(): pushing active", vp);

	hp->h_nodeflags |= IN_ALLOCATING;	/* Mark this as being incomplete */
	/*
	 * This will remove the entry from the hash AND the sibling list
	 * This will make sure everything is in a stable state to see if we can remove the meta
	 * i.e. if this is the only fork...the sibling list will be empty
	 */
	hfs_vhashrem(hp);	

	DBG_ASSERT(tdata != NULL);
	DBG_ASSERT(hp->h_meta != NULL);
   
   	devvp = hp->h_meta->h_devvp;		/* For later releasing */
	hp->h_meta->h_usecount--;   	

	/* release the file meta if this is the last fork */
    if (H_FORKTYPE(hp)==kDataFork || H_FORKTYPE(hp)==kRsrcFork) {
    	if (hp->h_meta->h_siblinghead.cqh_first != (void *) &hp->h_meta->h_siblinghead)
			freeMeta = false;
	};

    if (freeMeta) {
		DBG_ASSERT(hp->h_meta->h_usecount == 0);
		if (hp->h_meta->h_metaflags & IN_LONGNAME) {
			tname = H_NAME(hp);
			DBG_ASSERT(tname != NULL);
			FREE(tname, M_TEMP);
		  	}
		  FREE_ZONE(hp->h_meta, sizeof(struct hfsfilemeta), M_HFSFMETA);
		  hp->h_meta = NULL;
	    }
	else
		DBG_ASSERT(hp->h_meta->h_usecount == 1);

	/* Dump cached symlink data */
	if ((vp->v_type == VLNK) && (hp->h_symlinkptr != NULL)) {
			if (H_ISBIGLINK(hp))
				FREE(hp->h_symlinkptr, M_TEMP);
			hp->h_symlinkptr = NULL;
	}

	/*
	 * Purge old data structures associated with the inode.
	 */
	cache_purge(vp);
	if (devvp) {
		vrele(devvp);
	};

	/* Free our data structs */
	FREE_ZONE(tdata, sizeof(struct hfsnode), M_HFSNODE);
	vp->v_data = NULL;

	DBG_VOP_LOCKS_TEST(E_NONE);
	return (E_NONE);
}


/*
 * Lock an hfsnode. If its already locked, set the WANT bit and sleep.
#% lock		vp	U L U
#
 vop_lock {
     IN struct vnode *vp;
     IN int flags;
     IN struct proc *p;
     */

static int
hfs_lock(ap)
struct vop_lock_args /* {
    struct vnode *a_vp;
    int a_flags;
    struct proc *a_p;
} */ *ap;
{
	struct vnode * vp = ap->a_vp;
	struct hfsnode *hp = VTOH(ap->a_vp);
	int			retval;

	DBG_FUNC_NAME("lock");
	DBG_VOP_LOCKS_DECL(1);
	DBG_VOP_PRINT_FUNCNAME();DBG_VOP_CONT((" "));
	DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP_CONT((" flags = 0x%08X.\n", ap->a_flags));
	DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_UNLOCKED, VOPDBG_LOCKED, VOPDBG_UNLOCKED, VOPDBG_ZERO);

	retval = lockmgr(&hp->h_lock, ap->a_flags, &vp->v_interlock, ap->a_p);
	if (retval != E_NONE) {
		if ((ap->a_flags & LK_NOWAIT) == 0)
			DBG_ERR(("hfs_lock: error %d trying to lock vnode (flags = 0x%08X).\n", retval, ap->a_flags));
		goto Err_Exit;
	};

	if (vp->v_type == VDIR)
		hp->h_nodeflags &= ~IN_BYCNID;

Err_Exit:;
	DBG_ASSERT(*((int*)&vp->v_interlock) == 0);
	DBG_VOP_LOCKS_TEST(retval);
	return (retval);
}

/*
 * Unlock an hfsnode.
#% unlock	vp	L U L
#
 vop_unlock {
     IN struct vnode *vp;
     IN int flags;
     IN struct proc *p;

     */
int
hfs_unlock(ap)
struct vop_unlock_args /* {
    struct vnode *a_vp;
    int a_flags;
    struct proc *a_p;
} */ *ap;
{
	struct hfsnode *hp = VTOH(ap->a_vp);
	struct vnode *vp = ap->a_vp;
	int		retval = E_NONE;

	DBG_FUNC_NAME("unlock");
	DBG_VOP_LOCKS_DECL(1);
	DBG_VOP_PRINT_FUNCNAME();
	DBG_VOP_PRINT_VNODE_INFO(vp);DBG_VOP_CONT((" flags = 0x%08X.\n", ap->a_flags));
	DBG_VOP_LOCKS_INIT(0,vp, VOPDBG_LOCKED, VOPDBG_UNLOCKED, VOPDBG_LOCKED, VOPDBG_ZERO);

	if (vp->v_type == VDIR)
		hp->h_nodeflags &= ~IN_BYCNID;

	DBG_ASSERT((ap->a_flags & (LK_EXCLUSIVE|LK_SHARED)) == 0);
	retval = lockmgr(&hp->h_lock, ap->a_flags | LK_RELEASE, &vp->v_interlock, ap->a_p);
	if (retval != E_NONE) {
		DEBUG_BREAK_MSG(("hfs_unlock: error %d trying to unlock vnode (forktype = %d).\n", retval, H_FORKTYPE(hp)));
	};

	DBG_ASSERT(*((int*)&vp->v_interlock) == 0);
	DBG_VOP_LOCKS_TEST(retval);
	return (retval);
}


/*
 * Print out the contents of an hfsnode.
#% print	vp	= = =
#
 vop_print {
     IN struct vnode *vp;
     */
int
hfs_print(ap)
struct vop_print_args /* {
    struct vnode *a_vp;
} */ *ap;
{
	register struct vnode * vp = ap->a_vp;
	register struct hfsnode *hp = VTOH( vp);
	DBG_FUNC_NAME("print");
	DBG_VOP_LOCKS_DECL(1);
	DBG_VOP_PRINT_FUNCNAME();
	DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);

	DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_IGNORE, VOPDBG_IGNORE, VOPDBG_IGNORE, VOPDBG_POS);

	printf("tag VT_HFS, dirID %d, on dev %d, %d", H_DIRID(hp),
		   major(H_DEV(hp)), minor(H_DEV(hp)));
	/* lockmgr_printinfo(&hp->h_lock); */
	printf("\n");
	DBG_VOP_LOCKS_TEST(E_NONE);
	return (E_NONE);
}


/*
 * Check for a locked hfsnode.
#% islocked	vp	= = =
#
 vop_islocked {
     IN struct vnode *vp;

     */
int
hfs_islocked(ap)
struct vop_islocked_args /* {
    struct vnode *a_vp;
} */ *ap;
{
    int		lockStatus;
    //DBG_FUNC_NAME("islocked");
    //DBG_VOP_LOCKS_DECL(1);
    //DBG_VOP_PRINT_FUNCNAME();
    //DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);

    //DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_IGNORE, VOPDBG_IGNORE, VOPDBG_IGNORE, VOPDBG_ZERO);

    lockStatus = lockstatus(&VTOH( ap->a_vp)->h_lock);
    //DBG_VOP_LOCKS_TEST(E_NONE);
    return (lockStatus);
}

/*

#% pathconf	vp	L L L
#
 vop_pathconf {
     IN struct vnode *vp;
     IN int name;
     OUT register_t *retval;

     */
static int
hfs_pathconf(ap)
struct vop_pathconf_args /* {
    struct vnode *a_vp;
    int a_name;
    int *a_retval;
} */ *ap;
{
    int retval = E_NONE;
    DBG_FUNC_NAME("pathconf");
    DBG_VOP_LOCKS_DECL(1);
    DBG_VOP_PRINT_FUNCNAME();
    DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);

    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_POS);

    DBG_HFS_NODE_CHECK (ap->a_vp);

    switch (ap->a_name) {
        case _PC_LINK_MAX:
#if HFS_HARDLINKS
	if (VTOVCB(ap->a_vp)->vcbSigWord == kHFSPlusSigWord)
		*ap->a_retval = HFS_LINK_MAX;
	else
		*ap->a_retval = 1;
#else
	*ap->a_retval = 1;
#endif
            break;
        case _PC_NAME_MAX:
            *ap->a_retval = kHFSPlusMaxFileNameBytes;	/* max # of characters x max utf8 representation */
            break;
        case _PC_PATH_MAX:
            *ap->a_retval = PATH_MAX; /* 1024 */
            break;
        case _PC_CHOWN_RESTRICTED:
            *ap->a_retval = 1;
            break;
        case _PC_NO_TRUNC:
            *ap->a_retval = 0;
            break;
        case _PC_NAME_CHARS_MAX:
            *ap->a_retval = kHFSPlusMaxFileNameChars;
            break;
        case _PC_CASE_SENSITIVE:
            *ap->a_retval = 0;
            break;
        case _PC_CASE_PRESERVING:
            *ap->a_retval = 1;
            break;
        default:
            retval = EINVAL;
    }

    DBG_VOP_LOCKS_TEST(retval);
    return (retval);
}





/*
 * Advisory record locking support
#% advlock	vp	U U U
#
 vop_advlock {
     IN struct vnode *vp;
     IN caddr_t id;
     IN int op;
     IN struct flock *fl;
     IN int flags;

     */
int
hfs_advlock(ap)
struct vop_advlock_args /* {
    struct vnode *a_vp;
    caddr_t  a_id;
    int  a_op;
    struct flock *a_fl;
    int  a_flags;
} */ *ap;
{
    register struct hfsnode *hp = VTOH(ap->a_vp);
    register struct flock *fl = ap->a_fl;
    register struct hfslockf *lock;
    off_t start, end;
    int retval;
    DBG_FUNC_NAME("advlock");
    DBG_VOP_LOCKS_DECL(1);
    DBG_VOP_PRINT_FUNCNAME();
    DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP(("\n"));
    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_UNLOCKED, VOPDBG_UNLOCKED, VOPDBG_UNLOCKED, VOPDBG_POS);
    /*
     * Avoid the common case of unlocking when inode has no locks.
     */
    if (hp->h_lockf == (struct hfslockf *)0) {
        if (ap->a_op != F_SETLK) {
            fl->l_type = F_UNLCK;
            return (0);
        }
    }
    /*
     * Convert the flock structure into a start and end.
     */
    start = 0;
    switch (fl->l_whence) {
        case SEEK_SET:
        case SEEK_CUR:
            /*
             * Caller is responsible for adding any necessary offset
             * when SEEK_CUR is used.
             */
            start = fl->l_start;
            break;

        case SEEK_END:
            start = HTOFCB(hp)->fcbEOF + fl->l_start;
            break;

        default:
            return (EINVAL);
    }

    if (start < 0)
        return (EINVAL);
    if (fl->l_len == 0)
        end = -1;
    else
        end = start + fl->l_len - 1;

    /*
     * Create the hfslockf structure
     */
    MALLOC(lock, struct hfslockf *, sizeof *lock, M_LOCKF, M_WAITOK);
    lock->lf_start = start;
    lock->lf_end = end;
    lock->lf_id = ap->a_id;
    lock->lf_hfsnode = hp;
    lock->lf_type = fl->l_type;
    lock->lf_next = (struct hfslockf *)0;
    TAILQ_INIT(&lock->lf_blkhd);
    lock->lf_flags = ap->a_flags;
    /*
     * Do the requested operation.
     */
    switch(ap->a_op) {
        case F_SETLK:
            retval = hfs_setlock(lock);
            break;

        case F_UNLCK:
            retval = hfs_clearlock(lock);
            FREE(lock, M_LOCKF);
            break;

        case F_GETLK:
            retval = hfs_getlock(lock, fl);
            FREE(lock, M_LOCKF);
            break;

        default:
            retval = EINVAL;
            _FREE(lock, M_LOCKF);
            break;
    }

    DBG_VOP_LOCKS_TEST(retval);
    return (retval);
}



/*
 * Update the access, modified, and node change times as specified by the
 * IACCESS, IUPDATE, and ICHANGE flags respectively. The IMODIFIED flag is
 * used to specify that the node needs to be updated but that the times have
 * already been set. The access and modified times are taken from the second
 * and third parameters; the node change time is always taken from the current
 * time. If waitfor is set, then wait for the disk write of the node to
 * complete.
 */
/*
#% update	vp	L L L
	IN struct vnode *vp;
	IN struct timeval *access;
	IN struct timeval *modify;
	IN int waitfor;
*/

int
hfs_update(ap)
	struct vop_update_args /* {
		struct vnode *a_vp;
		struct timeval *a_access;
		struct timeval *a_modify;
		int a_waitfor;
	} */ *ap;
{
	struct hfsnode	*hp;
	struct proc		*p;
	hfsCatalogInfo 	catInfo;
	char 			*filename;
	char iNodeName[32];
	u_int32_t 		pid;
	int				retval;
	ExtendedVCB *vcb;
	DBG_FUNC_NAME("update");
	DBG_VOP_LOCKS_DECL(1);
	DBG_VOP_PRINT_FUNCNAME();
	DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP_CONT(("\n"));
	DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_ZERO);

	hp = VTOH(ap->a_vp);

	DBG_ASSERT(hp && hp->h_meta);
	DBG_ASSERT(*((int*)&ap->a_vp->v_interlock) == 0);

	if ((H_FORKTYPE(hp) == kSysFile) ||
	    (VTOVFS(ap->a_vp)->mnt_flag & MNT_RDONLY) ||
	    (hp->h_meta->h_mode == 0)) {
		hp->h_nodeflags &= ~(IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE);
		DBG_VOP_LOCKS_TEST(0);
		return (0);
	}

    if (H_FORKTYPE(hp) == kSysFile) {
        hp->h_nodeflags &= ~(IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE);
        DBG_VOP_LOCKS_TEST(0);
        return (0);
    }

    if (VTOVFS(ap->a_vp)->mnt_flag & MNT_RDONLY) {
        hp->h_nodeflags &= ~(IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE);
        DBG_VOP_LOCKS_TEST(0);
        return (0);
    }
	
    /* Check to see if MacOS set the fcb to be dirty, if so, translate it to IN_MODIFIED */
    if (HTOFCB(hp)->fcbFlags &fcbModifiedMask)
        hp->h_nodeflags |= IN_MODIFIED;

    if ((hp->h_nodeflags & (IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE)) == 0) {
        DBG_VOP_LOCKS_TEST(0);
        return (0);
    };

	if (hp->h_nodeflags & IN_ACCESS)
		hp->h_meta->h_atime = ap->a_access->tv_sec;
	if (hp->h_nodeflags & IN_UPDATE)
		hp->h_meta->h_mtime = ap->a_modify->tv_sec;
	if (hp->h_nodeflags & IN_CHANGE) {
		hp->h_meta->h_ctime = time.tv_sec;
		/*
		 * HFS dates that WE set must be adjusted for DST
		 */
		if ((HTOVCB(hp)->vcbSigWord == kHFSSigWord) && gTimeZone.tz_dsttime) {
			hp->h_meta->h_ctime += 3600;
			hp->h_meta->h_mtime = hp->h_meta->h_ctime;
		}
	}

	p = current_proc();
	filename = H_NAME(hp);
	pid = H_DIRID(hp);
	vcb = HTOVCB(hp);
	catInfo.hint = H_HINT(hp);

#if HFS_HARDLINKS
	/*
	 * Force an update of the indirect node instead of the link
	 * by using the name and parent of the indirect node.
	 */
	if (hp->h_meta->h_metaflags & IN_DATANODE) {
		MAKE_INODE_NAME(iNodeName, hp->h_meta->h_indnodeno);
		filename = iNodeName;
		pid = VCBTOHFS(vcb)->hfs_private_metadata_dir;
	}
#endif

	INIT_CATALOGDATA(&catInfo.nodeData, kCatNameNoCopyName);

	/*
	 * Since VOP_UPDATE can be called from withing another VOP (eg VOP_RENAME),
	 * the Catalog b-tree may aready be locked by the current thread. So we
	 * allow recursive locking of the Catalog from within VOP_UPDATE.
	 */
	/* Lock the Catalog b-tree file */
	retval = hfs_metafilelocking(HTOHFS(hp), kHFSCatalogFileID, LK_EXCLUSIVE | LK_CANRECURSE, p);
	if (retval) {
        DBG_VOP_LOCKS_TEST(retval);
        return (retval);
    };

	retval = hfs_getcatalog(vcb, pid, filename, -1, &catInfo);
	if (retval != noErr) {
		(void) hfs_metafilelocking(HTOHFS(hp), kHFSCatalogFileID, LK_RELEASE, p);
		retval = MacToVFSError(retval);
		goto Err_Exit;
	};

	H_HINT(hp) = catInfo.hint;
	CopyVNodeToCatalogNode (HTOV(hp), &catInfo.nodeData);

	retval = UpdateCatalogNode(vcb, pid, filename, H_HINT(hp), &catInfo.nodeData);

	 /* unlock the Catalog b-tree file */
	(void) hfs_metafilelocking(HTOHFS(hp), kHFSCatalogFileID, LK_RELEASE, p);

    if (retval != noErr) {				/* from UpdateCatalogNode() */
        retval = MacToVFSError(retval);
        goto Err_Exit;
    };

	/* After the updates are finished, clear the flags */
	hp->h_nodeflags &= ~(IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE);
	HTOFCB(hp)->fcbFlags &= ~fcbModifiedMask;

	/* Update general data */
    if (ap->a_vp->v_type == VDIR) {
    		hp->h_meta->h_nlink = 2 + catInfo.nodeData.cnd_valence;
		hp->h_meta->h_size = sizeof(rootdots) + 
			(catInfo.nodeData.cnd_valence * AVERAGE_HFSDIRENTRY_SIZE);
		if (hp->h_meta->h_size < MAX_HFSDIRENTRY_SIZE)
			hp->h_meta->h_size < MAX_HFSDIRENTRY_SIZE;
	} else {
		hp->h_meta->h_size = (off_t)vcb->blockSize *
		    (off_t)(catInfo.nodeData.cnd_rsrcfork.totalBlocks +
		     catInfo.nodeData.cnd_datafork.totalBlocks);
	}


Err_Exit:    

	CLEAN_CATALOGDATA(&catInfo.nodeData);

    DBG_VOP_LOCKS_TEST(retval);
	return (retval);
}


/*
 * Initialize the vnode associated with a new hfsnode, 
 * handle aliased vnodes.
 */
int
hfs_vinit(mntp, specops, fifoops, vpp)
	struct mount *mntp;
	int (**specops)(void *);
	int (**fifoops)(void *);
	struct vnode **vpp;
{
	struct hfsnode *hp;
	struct vnode *vp, *nvp;

	vp = *vpp;
	hp = VTOH(vp);
	/* vp->v_type set in CopyCatalogToHFSNode */ 
	switch(vp->v_type) {
	case VCHR:
	case VBLK:
		vp->v_op = specops;
		if ((nvp = checkalias(vp, hp->h_meta->h_rdev, mntp))) {
			/*
			 * Discard unneeded vnode, but save its hfsnode.
			 * Note that the lock is carried over in the hfsnode
			 * to the replacement vnode.
			 */
			nvp->v_data = vp->v_data;
			vp->v_data = NULL;
			vp->v_op = spec_vnodeop_p;
			vrele(vp);
			vgone(vp);
			/*
			 * Reinitialize aliased hfsnode.
			 */

			hp->h_vp = nvp;				
			vp = nvp;
		}
		break;
	case VFIFO:
#if FIFO
		vp->v_op = fifoops;
		break;
#else
		return (EOPNOTSUPP);
#endif
	default:
		break;
	}
	if (H_FILEID(hp) == kRootDirID)
                vp->v_flag |= VROOT;

	*vpp = vp;
	return (0);
}

/*
 * Allocate a new node
 *
 * Upon leaving, namei buffer must be freed.
 *
 */
static int
hfs_makenode(mode, rawdev, dvp, vpp, cnp, p)
    int mode;
    dev_t rawdev;
    struct vnode *dvp;
    struct vnode **vpp;
    struct componentname *cnp;
	struct proc *p;
{
    register struct hfsnode *hp, *parhp;
    struct timeval 			tv;
    struct vnode 			*tvp;
    struct hfsCatalogInfo 	catInfo;
    ExtendedVCB				*vcb;
    UInt8					forkType;
    int 					retval;
	int hasmetalock = 0;
	u_int32_t tehint = 0;
    DBG_FUNC_NAME("makenode");

    parhp	= VTOH(dvp);
    vcb		= HTOVCB(parhp);
    *vpp	= NULL;
	tvp 	= NULL;
    if ((mode & IFMT) == 0)
        mode |= IFREG;

#if HFS_DIAGNOSTIC
    if ((cnp->cn_flags & HASBUF) == 0)
        panic("hfs_makenode: no name");
#endif

	/* lock catalog b-tree */
	retval = hfs_metafilelocking(VTOHFS(dvp),
				kHFSCatalogFileID, LK_EXCLUSIVE, p);
	if (retval != E_NONE)
		goto bad1;
	else
		hasmetalock = 1;

	/*
	 * Force Carbon creates to have MacUnicode encoding
	 */
	if ((parhp->h_nodeflags & IN_BYCNID) && (!ISSET(p->p_flag, P_TBE))) {
		tehint = kTextEncodingMacUnicode;
	}

    /* Create the Catalog B*-Tree entry */
    retval = hfsCreate(vcb, H_FILEID(parhp), cnp->cn_nameptr, mode, tehint);
    if (retval != E_NONE) {
        DBG_ERR(("%s: hfsCreate FAILED: %s, %s\n", funcname, cnp->cn_nameptr, H_NAME(parhp)));
        goto bad1;
    }

    /* Look up the catalog entry just created: */
	INIT_CATALOGDATA(&catInfo.nodeData, 0);
	catInfo.hint = kNoHint;

    retval = hfs_getcatalog(vcb, H_FILEID(parhp), cnp->cn_nameptr, cnp->cn_namelen, &catInfo);
    if (retval != E_NONE) {
        DBG_ERR(("%s: hfs_getcatalog FAILED: %s, %s\n", funcname, cnp->cn_nameptr, H_NAME(parhp)));
        goto bad1;
    }

	/* unlock catalog b-tree */
	hasmetalock = 0;
	(void) hfs_metafilelocking(VTOHFS(dvp),
			kHFSCatalogFileID, LK_RELEASE, p);

	/* hfs plus has additional metadata to initialize */
	if (vcb->vcbSigWord == kHFSPlusSigWord) {
		u_int32_t pflags;
		int catmode;
		
		if (VTOVFS(dvp)->mnt_flag & MNT_UNKNOWNPERMISSIONS) {
			catInfo.nodeData.cnd_ownerID = VTOHFS(dvp)->hfs_uid;
			catInfo.nodeData.cnd_groupID = VTOHFS(dvp)->hfs_gid;
			catmode = mode;
		} else {
			catInfo.nodeData.cnd_ownerID = cnp->cn_cred->cr_uid;
			catInfo.nodeData.cnd_groupID = parhp->h_meta->h_gid;
			catmode = mode;
		}

		switch (catmode & IFMT) {
		case IFLNK:
			catInfo.nodeData.cnd_ownerID = parhp->h_meta->h_uid;
			break;

		case IFCHR:
		case IFBLK:
			/* XXX should we move this to post hfsGet? */
			catInfo.nodeData.cnd_rawDevice = rawdev;
			/*
			 * Don't tag as a special file (BLK or CHR) until *after*
			 * hfsGet is called.  This insures that the checkalias call
			 * is defered until hfs_mknod completes.
			 */
			catmode = (catmode & ~IFMT) | IFREG;
			break;
		}

		if ((catmode & ISGID) && !groupmember(parhp->h_meta->h_gid, cnp->cn_cred) &&
			suser(cnp->cn_cred, NULL))
			catmode &= ~ISGID;

		if (cnp->cn_flags & ISWHITEOUT)
			pflags = UF_OPAQUE;
		else
			pflags = 0;

		/*
		 * The 32-bit pflags field has two bytes of significance which
		 * are stored separately as admin and owner flags.
		 *
		 *		+------------------------------------+
		 * pflags:	|XXXXXXXX|   SF    |XXXXXXXX|   UF   |
		 *		+------------------------------------+
		 */
		catInfo.nodeData.cnd_adminFlags = (pflags >> 16) & 0x00FF;
		catInfo.nodeData.cnd_ownerFlags = pflags & 0x00FF;
		catInfo.nodeData.cnd_mode = catmode;
	}

    /* Create a vnode for the object just created: */
    forkType = (catInfo.nodeData.cnd_type == kCatalogFolderNode) ? kDirectory : kDataFork;
    retval = hfs_vcreate(vcb, &catInfo, forkType, &tvp);

	CLEAN_CATALOGDATA(&catInfo.nodeData);		/* Should do nothing */

    if (retval)  goto bad1;		/* from hfs_vcreate() */

	/* flush out pflags, mode, gid, uid and rdev */
    tv = time;
    if (vcb->vcbSigWord == kHFSPlusSigWord) {
        hp = VTOH(tvp);
		/* reset mode and v_type in case it was BLK/CHR */
		hp->h_meta->h_mode = mode;
		tvp->v_type = IFTOVT(mode);
        hp->h_meta->h_metaflags &= ~IN_UNSETACCESS;
        hp->h_nodeflags |= IN_ACCESS | IN_CHANGE | IN_UPDATE;
        if ((retval = VOP_UPDATE(tvp, &tv, &tv, 1)))
            goto bad2;
    }

	VTOH(dvp)->h_nodeflags |= IN_CHANGE | IN_UPDATE;
    if ((retval = VOP_UPDATE(dvp, &tv, &tv, 1)))
        goto bad2;

    if ((cnp->cn_flags & (HASBUF | SAVESTART)) == HASBUF) {
        FREE_ZONE(cnp->cn_pnbuf, cnp->cn_pnlen, M_NAMEI);
    };
    vput(dvp);
    if (UBCINFOMISSING(tvp) || UBCINFORECLAIMED(tvp))
        ubc_info_init(tvp);

    *vpp = tvp;
    return (0);

bad2:
    /*
     * Write retval occurred trying to update the node
     * or the directory so must deallocate the node.
    */
    /* XXX SER In the future maybe set *vpp to 0xdeadbeef for testing */
    vput(tvp);

bad1:
	if (hasmetalock) {
		/* unlock catalog b-tree */
		hasmetalock = 0;
		(void) hfs_metafilelocking(VTOHFS(dvp),
				kHFSCatalogFileID, LK_RELEASE, p);
	}
    if ((cnp->cn_flags & (HASBUF | SAVESTART)) == HASBUF) {
        FREE_ZONE(cnp->cn_pnbuf, cnp->cn_pnlen, M_NAMEI);
    };
    vput(dvp);

    return (retval);
}


#if DBG_VOP_TEST_LOCKS

/* XXX SER Add passing in the flags...might not be a serious error if locked */

void DbgVopTest( int maxSlots,
                 int retval,
                 VopDbgStoreRec *VopDbgStore,
                 char *funcname)
{
    int index;

    for (index = 0; index < maxSlots; index++)
      {
        if (VopDbgStore[index].id != index) {
            DEBUG_BREAK_MSG(("%s: DBG_VOP_LOCK: invalid id field (%d) in target entry (#%d).\n", funcname, VopDbgStore[index].id, index));
        };

        if ((VopDbgStore[index].vp != NULL) &&
            ((VopDbgStore[index].vp->v_data==NULL) || (VTOH(VopDbgStore[index].vp)->h_valid != HFS_VNODE_MAGIC)))
            continue;

        if (VopDbgStore[index].vp != NULL)
            debug_check_vnode(VopDbgStore[index].vp, 0);

        switch (VopDbgStore[index].inState)
          {
            case VOPDBG_IGNORE:
            case VOPDBG_SAME:
                /* Do Nothing !!! */
                break;
            case VOPDBG_LOCKED:
            case VOPDBG_UNLOCKED:
            case VOPDBG_LOCKNOTNIL:
              {
                  if (VopDbgStore[index].vp == NULL && (VopDbgStore[index].inState != VOPDBG_LOCKNOTNIL)) {
                      DBG_ERR (("%s: InState check: Null vnode ptr in entry #%d\n", funcname, index));
                  } else if (VopDbgStore[index].vp != NULL) {
                      switch (VopDbgStore[index].inState)
                        {
                          case VOPDBG_LOCKED:
                          case VOPDBG_LOCKNOTNIL:
                              if (VopDbgStore[index].inValue == 0)
                                {
                                  DBG_ERR (("%s: Entry: not LOCKED:", funcname));
                                  DBG_VOP_PRINT_VNODE_INFO(VopDbgStore[index].vp); 
                                  DBG_ERR (("\n"));
                                }
                              break;
                          case VOPDBG_UNLOCKED:
                              if (VopDbgStore[index].inValue != 0)
                                {
                                  DBG_ERR (("%s: Entry: not UNLOCKED:", funcname));
                                  DBG_VOP_PRINT_VNODE_INFO(VopDbgStore[index].vp);
                                  DBG_ERR (("\n"));
                                }
                              break;
                        }
                  }
                  break;
              }
            default:
                DBG_ERR (("%s: DBG_VOP_LOCK on entry: bad lock test value: %d\n", funcname, VopDbgStore[index].errState));
          }


        if (retval != 0)
          {
            switch (VopDbgStore[index].errState)
              {
                case VOPDBG_IGNORE:
                    /* Do Nothing !!! */
                    break;
                case VOPDBG_LOCKED:
                case VOPDBG_UNLOCKED:
                case VOPDBG_SAME:
                  {
                      if (VopDbgStore[index].vp == NULL) {
                          DBG_ERR (("%s: ErrState check: Null vnode ptr in entry #%d\n", funcname, index));
                      } else {
                          VopDbgStore[index].outValue = lockstatus(&VTOH(VopDbgStore[index].vp)->h_lock);
                          switch (VopDbgStore[index].errState)
                            {
                              case VOPDBG_LOCKED:
                                  if (VopDbgStore[index].outValue == 0)
                                    {
                                      DBG_ERR (("%s: Error: not LOCKED:", funcname));
                                      DBG_VOP_PRINT_VNODE_INFO(VopDbgStore[index].vp); 
                                      DBG_ERR(("\n"));
                                   }
                                  break;
                              case VOPDBG_UNLOCKED:
                                  if (VopDbgStore[index].outValue != 0)
                                    {
                                      DBG_ERR (("%s: Error: not UNLOCKED:", funcname));
                                      DBG_VOP_PRINT_VNODE_INFO(VopDbgStore[index].vp); 
                                      DBG_ERR(("\n"));
                                    }
                                  break;
                              case VOPDBG_SAME:
                                  if (VopDbgStore[index].outValue != VopDbgStore[index].inValue)
                                      DBG_ERR (("%s: Error: In/Out locks are DIFFERENT: 0x%x, inis %d and out is %d\n", funcname, (u_int)VopDbgStore[index].vp, VopDbgStore[index].inValue, VopDbgStore[index].outValue));
                                  break;
                            }
                      }
                      break;
                  }
                case VOPDBG_LOCKNOTNIL:
                    if (VopDbgStore[index].vp != NULL) {
                        VopDbgStore[index].outValue = lockstatus(&VTOH(VopDbgStore[index].vp)->h_lock);
                        if (VopDbgStore[index].outValue == 0)
                            DBG_ERR (("%s: Error: Not LOCKED: 0x%x\n", funcname, (u_int)VopDbgStore[index].vp));
                    }
                    break;
                default:
                    DBG_ERR (("%s: Error: bad lock test value: %d\n", funcname, VopDbgStore[index].errState));
              }
          }
        else
          {
            switch (VopDbgStore[index].outState)
              {
                case VOPDBG_IGNORE:
                    /* Do Nothing !!! */
                    break;
                case VOPDBG_LOCKED:
                case VOPDBG_UNLOCKED:
                case VOPDBG_SAME:
                    if (VopDbgStore[index].vp == NULL) {
                        DBG_ERR (("%s: OutState: Null vnode ptr in entry #%d\n", funcname, index));
                    };
                    if (VopDbgStore[index].vp != NULL)
                      {
                        VopDbgStore[index].outValue = lockstatus(&VTOH(VopDbgStore[index].vp)->h_lock);
                        switch (VopDbgStore[index].outState)
                          {
                            case VOPDBG_LOCKED:
                                if (VopDbgStore[index].outValue == 0)
                                  {
                                    DBG_ERR (("%s: Out: not LOCKED:", funcname));
                                    DBG_VOP_PRINT_VNODE_INFO(VopDbgStore[index].vp); 
                                    DBG_ERR (("\n"));
                                 }
                                break;
                            case VOPDBG_UNLOCKED:
                                if (VopDbgStore[index].outValue != 0)
                                  {
                                    DBG_ERR (("%s: Out: not UNLOCKED:", funcname));
                                    DBG_VOP_PRINT_VNODE_INFO(VopDbgStore[index].vp); 
                                    DBG_ERR (("\n"));
                                  }
                                break;
                            case VOPDBG_SAME:
                                if (VopDbgStore[index].outValue != VopDbgStore[index].inValue)
                                    DBG_ERR (("%s: Out: In/Out locks are DIFFERENT: 0x%x, in is %d and out is %d\n", funcname, (u_int)VopDbgStore[index].vp, VopDbgStore[index].inValue, VopDbgStore[index].outValue));
                                break;
                          }
                      }
                    break;
                case VOPDBG_LOCKNOTNIL:
                    if (VopDbgStore[index].vp != NULL) {
                        if (&VTOH(VopDbgStore[index].vp)->h_lock == NULL) {
                            DBG_ERR (("%s: DBG_VOP_LOCK on out: Null lock on vnode 0x%x\n", funcname, (u_int)VopDbgStore[index].vp));
                        }
                        else {
                            VopDbgStore[index].outValue = lockstatus(&VTOH(VopDbgStore[index].vp)->h_lock);
                            if (VopDbgStore[index].outValue == 0)
                              {
                                DBG_ERR (("%s: DBG_VOP_LOCK on out: Should be LOCKED:", funcname));
                                DBG_VOP_PRINT_VNODE_INFO(VopDbgStore[index].vp); DBG_ERR (("\n"));
                              }
                        }
                    }
                    break;
                default:
                    DBG_ERR (("%s: DBG_VOP_LOCK on out: bad lock test value: %d\n", funcname, VopDbgStore[index].outState));
              }
          }

        VopDbgStore[index].id = -1;		/* Invalidate the entry to allow panic-free re-use */
      }	
}

#endif /* DBG_VOP_TEST_LOCKS */

/*
 * Wrapper for special device reads
 */
int
hfsspec_read(ap)
	struct vop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{

	/*
	 * Set access flag.
	 */
	VTOH(ap->a_vp)->h_nodeflags |= IN_ACCESS;
	return (VOCALL (spec_vnodeop_p, VOFFSET(vop_read), ap));
}

/*
 * Wrapper for special device writes
 */
int
hfsspec_write(ap)
	struct vop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{

	/*
	 * Set update and change flags.
	 */
	VTOH(ap->a_vp)->h_nodeflags |= IN_CHANGE | IN_UPDATE;
	return (VOCALL (spec_vnodeop_p, VOFFSET(vop_write), ap));
}

/*
 * Wrapper for special device close
 *
 * Update the times on the hfsnode then do device close.
 */
int
hfsspec_close(ap)
	struct vop_close_args /* {
		struct vnode *a_vp;
		int  a_fflag;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct hfsnode *hp = VTOH(vp);

	simple_lock(&vp->v_interlock);
	if (ap->a_vp->v_usecount > 1)
		HFSTIMES(hp, &time, &time);
	simple_unlock(&vp->v_interlock);
	return (VOCALL (spec_vnodeop_p, VOFFSET(vop_close), ap));
}

#if FIFO
/*
 * Wrapper for fifo reads
 */
int
hfsfifo_read(ap)
	struct vop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{
	extern int (**fifo_vnodeop_p)(void *);

	/*
	 * Set access flag.
	 */
	VTOH(ap->a_vp)->h_nodeflags |= IN_ACCESS;
	return (VOCALL (fifo_vnodeop_p, VOFFSET(vop_read), ap));
}

/*
 * Wrapper for fifo writes
 */
int
hfsfifo_write(ap)
	struct vop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{
	extern int (**fifo_vnodeop_p)(void *);

	/*
	 * Set update and change flags.
	 */
	VTOH(ap->a_vp)->h_nodeflags |= IN_CHANGE | IN_UPDATE;
	return (VOCALL (fifo_vnodeop_p, VOFFSET(vop_write), ap));
}

/*
 * Wrapper for fifo close
 *
 * Update the times on the hfsnode then do device close.
 */
int
hfsfifo_close(ap)
	struct vop_close_args /* {
		struct vnode *a_vp;
		int  a_fflag;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	extern int (**fifo_vnodeop_p)(void *);
	struct vnode *vp = ap->a_vp;
	struct hfsnode *hp = VTOH(vp);

	simple_lock(&vp->v_interlock);
	if (ap->a_vp->v_usecount > 1)
		HFSTIMES(hp, &time, &time);
	simple_unlock(&vp->v_interlock);
	return (VOCALL (fifo_vnodeop_p, VOFFSET(vop_close), ap));
}
#endif /* FIFO */


/*****************************************************************************
*
*	VOP Tables
*
*****************************************************************************/

#define VOPFUNC int (*)(void *)

struct vnodeopv_entry_desc hfs_vnodeop_entries[] = {
    { &vop_default_desc, (VOPFUNC)vn_default_error },
    { &vop_lookup_desc, (VOPFUNC)hfs_cache_lookup },		/* lookup */
    { &vop_create_desc, (VOPFUNC)hfs_create },			/* create */
    { &vop_mknod_desc, (VOPFUNC)hfs_mknod },			/* mknod */
    { &vop_open_desc, (VOPFUNC)hfs_open },			/* open */
    { &vop_close_desc, (VOPFUNC)hfs_close },			/* close */
    { &vop_access_desc, (VOPFUNC)hfs_access },			/* access */
    { &vop_getattr_desc, (VOPFUNC)hfs_getattr },		/* getattr */
    { &vop_setattr_desc, (VOPFUNC)hfs_setattr },		/* setattr */
    { &vop_read_desc, (VOPFUNC)hfs_read },			/* read */
    { &vop_write_desc, (VOPFUNC)hfs_write },			/* write */
    { &vop_ioctl_desc, (VOPFUNC)hfs_ioctl },			/* ioctl */
    { &vop_select_desc, (VOPFUNC)hfs_select },			/* select */
    { &vop_exchange_desc, (VOPFUNC)hfs_exchange },		/* exchange */
    { &vop_mmap_desc, (VOPFUNC)hfs_mmap },			/* mmap */
    { &vop_fsync_desc, (VOPFUNC)hfs_fsync },			/* fsync */
    { &vop_seek_desc, (VOPFUNC)hfs_seek },			/* seek */
    { &vop_remove_desc, (VOPFUNC)hfs_remove },			/* remove */
#if HFS_HARDLINKS
    { &vop_link_desc, (VOPFUNC)hfs_link },			/* link */
#else
    { &vop_link_desc, (VOPFUNC)err_link },	/* link (NOT SUPPORTED) */
#endif
    { &vop_rename_desc, (VOPFUNC)hfs_rename },			/* rename */
    { &vop_mkdir_desc, (VOPFUNC)hfs_mkdir },			/* mkdir */
    { &vop_rmdir_desc, (VOPFUNC)hfs_rmdir },			/* rmdir */
    { &vop_mkcomplex_desc, (VOPFUNC)hfs_mkcomplex },		/* mkcomplex */
    { &vop_getattrlist_desc, (VOPFUNC)hfs_getattrlist },  /* getattrlist */
    { &vop_setattrlist_desc, (VOPFUNC)hfs_setattrlist },  /* setattrlist */
    { &vop_symlink_desc, (VOPFUNC)hfs_symlink },		/* symlink */
    { &vop_readdir_desc, (VOPFUNC)hfs_readdir },		/* readdir */
    { &vop_readdirattr_desc, (VOPFUNC)hfs_readdirattr },  /* readdirattr */
    { &vop_readlink_desc, (VOPFUNC)hfs_readlink },		/* readlink */
    { &vop_abortop_desc, (VOPFUNC)hfs_abortop },		/* abortop */
    { &vop_inactive_desc, (VOPFUNC)hfs_inactive },		/* inactive */
    { &vop_reclaim_desc, (VOPFUNC)hfs_reclaim },		/* reclaim */
    { &vop_lock_desc, (VOPFUNC)hfs_lock },			/* lock */
    { &vop_unlock_desc, (VOPFUNC)hfs_unlock },			/* unlock */
    { &vop_bmap_desc, (VOPFUNC)hfs_bmap },			/* bmap */
    { &vop_strategy_desc, (VOPFUNC)hfs_strategy },		/* strategy */
    { &vop_print_desc, (VOPFUNC)hfs_print },			/* print */
    { &vop_islocked_desc, (VOPFUNC)hfs_islocked },		/* islocked */
    { &vop_pathconf_desc, (VOPFUNC)hfs_pathconf },		/* pathconf */
    { &vop_advlock_desc, (VOPFUNC)hfs_advlock },		/* advlock */
    { &vop_reallocblks_desc, (VOPFUNC)hfs_reallocblks },  /* reallocblks */
    { &vop_truncate_desc, (VOPFUNC)hfs_truncate },		/* truncate */
    { &vop_allocate_desc, (VOPFUNC)hfs_allocate },		/* allocate */
    { &vop_update_desc, (VOPFUNC)hfs_update },			/* update */
    { &vop_searchfs_desc, (VOPFUNC)hfs_search },		/* search fs */
    { &vop_bwrite_desc, (VOPFUNC)hfs_bwrite },			/* bwrite */
    { &vop_pagein_desc, (VOPFUNC)hfs_pagein },			/* pagein */
    { &vop_pageout_desc,(VOPFUNC) hfs_pageout },		/* pageout */
    { &vop_copyfile_desc, (VOPFUNC)err_copyfile },		/* copyfile */
    { &vop_blktooff_desc, (VOPFUNC)hfs_blktooff },		/* blktooff */
    { &vop_offtoblk_desc, (VOPFUNC)hfs_offtoblk },		/* offtoblk */
    { &vop_cmap_desc, (VOPFUNC)hfs_cmap },			/* cmap */
    { NULL, (VOPFUNC)NULL }
};

struct vnodeopv_desc hfs_vnodeop_opv_desc =
{ &hfs_vnodeop_p, hfs_vnodeop_entries };

int (**hfs_specop_p)(void *);
struct vnodeopv_entry_desc hfs_specop_entries[] = {
	{ &vop_default_desc, (VOPFUNC)vn_default_error },
	{ &vop_lookup_desc, (VOPFUNC)spec_lookup },		/* lookup */
	{ &vop_create_desc, (VOPFUNC)spec_create },		/* create */
	{ &vop_mknod_desc, (VOPFUNC)spec_mknod },		/* mknod */
	{ &vop_open_desc, (VOPFUNC)spec_open },			/* open */
	{ &vop_close_desc, (VOPFUNC)hfsspec_close },		/* close */
	{ &vop_access_desc, (VOPFUNC)hfs_access },		/* access */
	{ &vop_getattr_desc, (VOPFUNC)hfs_getattr },		/* getattr */
	{ &vop_setattr_desc, (VOPFUNC)hfs_setattr },		/* setattr */
	{ &vop_read_desc, (VOPFUNC)hfsspec_read },		/* read */
	{ &vop_write_desc, (VOPFUNC)hfsspec_write },		/* write */
	{ &vop_lease_desc, (VOPFUNC)spec_lease_check },		/* lease */
	{ &vop_ioctl_desc, (VOPFUNC)spec_ioctl },		/* ioctl */
	{ &vop_select_desc, (VOPFUNC)spec_select },		/* select */
	{ &vop_revoke_desc, (VOPFUNC)spec_revoke },		/* revoke */
	{ &vop_mmap_desc, (VOPFUNC)spec_mmap },			/* mmap */
	{ &vop_fsync_desc, (VOPFUNC)hfs_fsync },		/* fsync */
	{ &vop_seek_desc, (VOPFUNC)spec_seek },			/* seek */
	{ &vop_remove_desc, (VOPFUNC)spec_remove },		/* remove */
	{ &vop_link_desc, (VOPFUNC)spec_link },			/* link */
	{ &vop_rename_desc, (VOPFUNC)spec_rename },		/* rename */
	{ &vop_mkdir_desc, (VOPFUNC)spec_mkdir },		/* mkdir */
	{ &vop_rmdir_desc, (VOPFUNC)spec_rmdir },		/* rmdir */
	{ &vop_symlink_desc, (VOPFUNC)spec_symlink },		/* symlink */
	{ &vop_readdir_desc, (VOPFUNC)spec_readdir },		/* readdir */
	{ &vop_readlink_desc, (VOPFUNC)spec_readlink },		/* readlink */
	{ &vop_abortop_desc, (VOPFUNC)spec_abortop },		/* abortop */
	{ &vop_inactive_desc, (VOPFUNC)hfs_inactive },		/* inactive */
	{ &vop_reclaim_desc, (VOPFUNC)hfs_reclaim },		/* reclaim */
	{ &vop_lock_desc, (VOPFUNC)hfs_lock },			/* lock */
	{ &vop_unlock_desc, (VOPFUNC)hfs_unlock },		/* unlock */
	{ &vop_bmap_desc, (VOPFUNC)spec_bmap },			/* bmap */
	{ &vop_strategy_desc, (VOPFUNC)spec_strategy },		/* strategy */
	{ &vop_print_desc, (VOPFUNC)hfs_print },		/* print */
	{ &vop_islocked_desc, (VOPFUNC)hfs_islocked },		/* islocked */
	{ &vop_pathconf_desc, (VOPFUNC)spec_pathconf },		/* pathconf */
	{ &vop_advlock_desc, (VOPFUNC)spec_advlock },		/* advlock */
	{ &vop_blkatoff_desc, (VOPFUNC)spec_blkatoff },		/* blkatoff */
	{ &vop_valloc_desc, (VOPFUNC)spec_valloc },		/* valloc */
	{ &vop_reallocblks_desc, (VOPFUNC)spec_reallocblks },	/* reallocblks */
	{ &vop_vfree_desc, (VOPFUNC)err_vfree },		/* vfree */
	{ &vop_truncate_desc, (VOPFUNC)spec_truncate },		/* truncate */
	{ &vop_update_desc, (VOPFUNC)hfs_update },		/* update */
	{ &vop_bwrite_desc, (VOPFUNC)hfs_bwrite },
	{ &vop_devblocksize_desc, (VOPFUNC)spec_devblocksize }, /* devblocksize */
	{ &vop_pagein_desc, (VOPFUNC)hfs_pagein },		/* Pagein */
	{ &vop_pageout_desc, (VOPFUNC)hfs_pageout },		/* Pageout */
        { &vop_copyfile_desc, (VOPFUNC)err_copyfile },		/* copyfile */
	{ &vop_blktooff_desc, (VOPFUNC)hfs_blktooff },		/* blktooff */
	{ &vop_offtoblk_desc, (VOPFUNC)hfs_offtoblk },		/* offtoblk */
	{ (struct vnodeop_desc*)NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc hfs_specop_opv_desc =
	{ &hfs_specop_p, hfs_specop_entries };

#if FIFO
int (**hfs_fifoop_p)(void *);
struct vnodeopv_entry_desc hfs_fifoop_entries[] = {
	{ &vop_default_desc, (VOPFUNC)vn_default_error },
	{ &vop_lookup_desc, (VOPFUNC)fifo_lookup },		/* lookup */
	{ &vop_create_desc, (VOPFUNC)fifo_create },		/* create */
	{ &vop_mknod_desc, (VOPFUNC)fifo_mknod },		/* mknod */
	{ &vop_open_desc, (VOPFUNC)fifo_open },			/* open */
	{ &vop_close_desc, (VOPFUNC)hfsfifo_close },		/* close */
	{ &vop_access_desc, (VOPFUNC)hfs_access },		/* access */
	{ &vop_getattr_desc, (VOPFUNC)hfs_getattr },		/* getattr */
	{ &vop_setattr_desc, (VOPFUNC)hfs_setattr },		/* setattr */
	{ &vop_read_desc, (VOPFUNC)hfsfifo_read },		/* read */
	{ &vop_write_desc, (VOPFUNC)hfsfifo_write },		/* write */
	{ &vop_lease_desc, (VOPFUNC)fifo_lease_check },		/* lease */
	{ &vop_ioctl_desc, (VOPFUNC)fifo_ioctl },		/* ioctl */
	{ &vop_select_desc, (VOPFUNC)fifo_select },		/* select */
	{ &vop_revoke_desc, (VOPFUNC)fifo_revoke },		/* revoke */
	{ &vop_mmap_desc, (VOPFUNC)fifo_mmap },			/* mmap */
	{ &vop_fsync_desc, (VOPFUNC)hfs_fsync },		/* fsync */
	{ &vop_seek_desc, (VOPFUNC)fifo_seek },			/* seek */
	{ &vop_remove_desc, (VOPFUNC)fifo_remove },		/* remove */
	{ &vop_link_desc, (VOPFUNC)fifo_link },			/* link */
	{ &vop_rename_desc, (VOPFUNC)fifo_rename },		/* rename */
	{ &vop_mkdir_desc, (VOPFUNC)fifo_mkdir },		/* mkdir */
	{ &vop_rmdir_desc, (VOPFUNC)fifo_rmdir },		/* rmdir */
	{ &vop_symlink_desc, (VOPFUNC)fifo_symlink },		/* symlink */
	{ &vop_readdir_desc, (VOPFUNC)fifo_readdir },		/* readdir */
	{ &vop_readlink_desc, (VOPFUNC)fifo_readlink },		/* readlink */
	{ &vop_abortop_desc, (VOPFUNC)fifo_abortop },		/* abortop */
	{ &vop_inactive_desc, (VOPFUNC)hfs_inactive },		/* inactive */
	{ &vop_reclaim_desc, (VOPFUNC)hfs_reclaim },		/* reclaim */
	{ &vop_lock_desc, (VOPFUNC)hfs_lock },			/* lock */
	{ &vop_unlock_desc, (VOPFUNC)hfs_unlock },		/* unlock */
	{ &vop_bmap_desc, (VOPFUNC)fifo_bmap },			/* bmap */
	{ &vop_strategy_desc, (VOPFUNC)fifo_strategy },		/* strategy */
	{ &vop_print_desc, (VOPFUNC)hfs_print },		/* print */
	{ &vop_islocked_desc, (VOPFUNC)hfs_islocked },		/* islocked */
	{ &vop_pathconf_desc, (VOPFUNC)fifo_pathconf },		/* pathconf */
	{ &vop_advlock_desc, (VOPFUNC)fifo_advlock },		/* advlock */
	{ &vop_blkatoff_desc, (VOPFUNC)fifo_blkatoff },		/* blkatoff */
	{ &vop_valloc_desc, (VOPFUNC)fifo_valloc },		/* valloc */
	{ &vop_reallocblks_desc, (VOPFUNC)fifo_reallocblks },  /* reallocblks */
	{ &vop_vfree_desc, (VOPFUNC)err_vfree },		/* vfree */
	{ &vop_truncate_desc, (VOPFUNC)fifo_truncate },		/* truncate */
	{ &vop_update_desc, (VOPFUNC)hfs_update },		/* update */
	{ &vop_bwrite_desc, (VOPFUNC)hfs_bwrite },
	{ &vop_pagein_desc, (VOPFUNC)hfs_pagein },		/* Pagein */
	{ &vop_pageout_desc, (VOPFUNC)hfs_pageout },		/* Pageout */
    { &vop_copyfile_desc, (VOPFUNC)err_copyfile }, 		/* copyfile */
	{ &vop_blktooff_desc, (VOPFUNC)hfs_blktooff },		/* blktooff */
	{ &vop_offtoblk_desc, (VOPFUNC)hfs_offtoblk },		/* offtoblk */
  	{ &vop_cmap_desc, (VOPFUNC)hfs_cmap },			/* cmap */
	{ (struct vnodeop_desc*)NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc hfs_fifoop_opv_desc =
	{ &hfs_fifoop_p, hfs_fifoop_entries };
#endif /* FIFO */



