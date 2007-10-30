/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
/*
 * Copyright (c) 1998-1999 Apple Computer, Inc. All Rights Reserved.
 *
 *	Modification History:
 *
 *	02-Feb-2000	Clark Warner    Added copyfile to table	
 *	17-Aug-1999	Pat Dirks	New today.
 */

#include <mach/mach_types.h>
#include <mach/machine/boolean.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/conf.h>
#include <sys/mount_internal.h>
#include <sys/vnode_internal.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/namei.h>
#include <sys/attr.h>
#include <sys/uio_internal.h>

#include <sys/vm.h>
#include <sys/errno.h>
#include <vfs/vfs_support.h>

#include "synthfs.h"

#define RWSUPPORT 0

#if RWSUPPORT
#error NOT PORTED FOR UBC
#include <sys/ubc.h>
#endif

static int synthfs_remove_internal(struct vnode *dvp, struct vnode *vp,
                                   struct componentname *cnp, vfs_context_t context);


#define VOPFUNC int (*)(void *)

/* Global vfs data structures for synthfs. */
int (**synthfs_vnodeop_p) (void *);
struct vnodeopv_entry_desc synthfs_vnodeop_entries[] = {
    {&vnop_default_desc, (VOPFUNC)vn_default_error},
    {&vnop_strategy_desc, (VOPFUNC)err_strategy},		/* strategy		- not supported  */
    {&vnop_bwrite_desc, (VOPFUNC)err_bwrite},			/* bwrite		- not supported  */
    {&vnop_lookup_desc, (VOPFUNC)synthfs_cached_lookup},	/* cached lookup */
    {&vnop_create_desc, (VOPFUNC)synthfs_create},		/* create		- DEBUGGER */
    {&vnop_whiteout_desc, (VOPFUNC)err_whiteout},		/* whiteout		- not supported  */
    {&vnop_mknod_desc, (VOPFUNC)err_mknod},			/* mknod		- not supported  */
    {&vnop_open_desc, (VOPFUNC)synthfs_open},			/* open			- DEBUGGER */
    {&vnop_close_desc, (VOPFUNC)nop_close},			/* close		- NOP */
    {&vnop_getattr_desc, (VOPFUNC)synthfs_getattr},		/* getattr */
    {&vnop_setattr_desc, (VOPFUNC)synthfs_setattr},		/* setattr */
    {&vnop_getattrlist_desc, (VOPFUNC)err_getattrlist},	/* getattrlist	- not supported  */
    {&vnop_setattrlist_desc, (VOPFUNC)err_setattrlist},	/* setattrlist	- not supported  */
    {&vnop_read_desc, (VOPFUNC)err_read},			/* read			- not supported  */
    {&vnop_write_desc, (VOPFUNC)err_write},			/* write		- not supported  */
    {&vnop_ioctl_desc, (VOPFUNC)err_ioctl},			/* ioctl		- not supported  */
    {&vnop_select_desc, (VOPFUNC)synthfs_select},		/* select */
    {&vnop_exchange_desc, (VOPFUNC)err_exchange},		/* exchange		- not supported  */
    {&vnop_revoke_desc, (VOPFUNC)nop_revoke},			/* revoke		- NOP */
    {&vnop_mmap_desc, (VOPFUNC)synthfs_mmap},			/* mmap			- DEBUGGER */
    {&vnop_fsync_desc, (VOPFUNC)nop_fsync},			/* fsync		- NOP */
    {&vnop_remove_desc, (VOPFUNC)synthfs_remove},		/* remove */
    {&vnop_link_desc, (VOPFUNC)err_link},			/* link			- not supported  */
    {&vnop_rename_desc, (VOPFUNC)synthfs_rename},		/* rename */
    {&vnop_mkdir_desc, (VOPFUNC)synthfs_mkdir},			/* mkdir */
    {&vnop_rmdir_desc, (VOPFUNC)synthfs_rmdir},			/* rmdir */
    {&vnop_symlink_desc, (VOPFUNC)synthfs_symlink},		/* symlink */
    {&vnop_readdir_desc, (VOPFUNC)synthfs_readdir},		/* readdir */
    {&vnop_readdirattr_desc, (VOPFUNC)err_readdirattr},	/* readdirattr	- not supported  */
    {&vnop_readlink_desc, (VOPFUNC)synthfs_readlink},		/* readlink */
    {&vnop_inactive_desc, (VOPFUNC)synthfs_inactive},		/* inactive */
    {&vnop_reclaim_desc, (VOPFUNC)synthfs_reclaim},		/* reclaim */
    {&vnop_pathconf_desc, (VOPFUNC)synthfs_pathconf},		/* pathconf */
    {&vnop_advlock_desc, (VOPFUNC)err_advlock},			/* advlock		- not supported  */
    {&vnop_allocate_desc, (VOPFUNC)err_allocate},		/* allocate		- not supported  */
	{&vnop_pagein_desc, (VOPFUNC)err_pagein},		/* pagein		- not supported  */
	{&vnop_pageout_desc, (VOPFUNC)err_pageout},		/* pageout		- not supported  */
	{&vnop_devblocksize_desc, (VOPFUNC)err_devblocksize},	/* devblocksize - not supported  */
	{&vnop_searchfs_desc, (VOPFUNC)err_searchfs},		/* searchfs		- not supported */
	{&vnop_copyfile_desc, (VOPFUNC)err_copyfile},		/* copyfile - not supported */
 	{ &vnop_blktooff_desc, (VOPFUNC)err_blktooff },		/* blktooff not supported */
	{ &vnop_offtoblk_desc, (VOPFUNC)err_offtoblk },		/* offtoblk  not supported */
	{ &vnop_blockmap_desc, (VOPFUNC)err_blockmap },		/* blockmap  not supported */
   {(struct vnodeop_desc *) NULL, (int (*) ()) NULL}
};

/*
 * Oh what a tangled web we weave.  This structure will be used by
 * bsd/vfs/vfs_conf.c to actually do the initialization of synthfs_vnodeop_p
 */
struct vnodeopv_desc synthfs_vnodeop_opv_desc =
{&synthfs_vnodeop_p, synthfs_vnodeop_entries};



/*
 * Create a regular file
#% create	dvp	L U U
#% create	vpp	- L -
#
 vnop_create {
     IN WILLRELE struct vnode *dvp;
     OUT struct vnode **vpp;
     IN struct componentname *cnp;
     IN struct vnode_attr *vap;
	
     We are responsible for freeing the namei buffer, it is done in hfs_makenode(), unless there is
	a previous error.

*/

int
synthfs_create(ap)
struct vnop_create_args /* {
    struct vnode *a_dvp;
    struct vnode **a_vpp;
    struct componentname *a_cnp;
    struct vnode_attr *a_vap;
    vfs_context_t a_context;
} */ *ap;
{
#if DEBUG
	struct vnode *dvp = ap->a_dvp;
	char debugmsg[255];
	
	sprintf(debugmsg, "synthfs_create: attempt to create '%s' in '%s' ?!", ap->a_cnp->cn_nameptr, VTOS(dvp)->s_name);
	Debugger(debugmsg);
#endif

	return err_create(ap);
}



/*
 * Open called.
#% open		vp	L L L
#
 vnop_open {
     IN struct vnode *vp;
     IN int mode;
     IN vfs_context_t a_context;
 */

int
synthfs_open(ap)
struct vnop_open_args /* {
    struct vnode *a_vp;
    int  a_mode;
    vfs_context_t a_context;
} */ *ap;
{
	struct vnode *vp = ap->a_vp;

	if (vp->v_type == VDIR) {
	  return 0;
	} else {
#if DEBUG
		struct synthfsnode *sp = VTOS(vp);
		char debugmsg[255];
	
		sprintf(debugmsg, "synthfs_open: attempt to open '/%s' ?!", sp->s_name);
		Debugger(debugmsg);
#endif
	};

	return 0;
}



/*
 * Mmap a file
 *
 * NB Currently unsupported.
# XXX - not used
#
 vnop_mmap {
     IN struct vnode *vp;
     IN int fflags;
     IN kauth_cred_t cred;
     IN struct proc *p;

     */

/* ARGSUSED */

int
synthfs_mmap(__unused struct vnop_mmap_args *ap)
{
    return EINVAL;
}



/*
#% getattr	vp	= = =
#
 vnop_getattr {
     IN struct vnode *vp;
     IN struct vnode_attr *vap;
     IN vfs_context_t context;

*/
int
synthfs_getattr(ap)
struct vnop_getattr_args /* {
    struct vnode *a_vp;
    struct vnode_attr *a_vap;
    vfs_context_t a_context;
} */ *ap;
{
	struct vnode *vp     = ap->a_vp;
	struct vnode_attr *vap    = ap->a_vap;
	struct synthfsnode *sp = VTOS(vp);

	VATTR_RETURN(vap, va_type, vp->v_type);
	VATTR_RETURN(vap, va_mode, sp->s_mode);
	VATTR_RETURN(vap, va_nlink, sp->s_linkcount);
	VATTR_RETURN(vap, va_uid, sp->s_uid);
	VATTR_RETURN(vap, va_gid, sp->s_gid);
	VATTR_RETURN(vap, va_fsid, VTOVFS(vp)->mnt_vfsstat.f_fsid.val[0]);
	VATTR_RETURN(vap, va_fileid, sp->s_nodeid);
	switch (vp->v_type) {
	case VDIR:
		VATTR_RETURN(vap, va_data_size, (sp->s_u.d.d_entrycount + 2) * sizeof(struct dirent));
		break;
	  
	case VREG:
	  	VATTR_RETURN(vap, va_data_size, sp->s_u.f.f_size);
	  	break;
	
	case VLNK:
		VATTR_RETURN(vap, va_data_size, sp->s_u.s.s_length);
		break;
	
	default:
		VATTR_RETURN(vap, va_data_size, 0);
	};
	VATTR_RETURN(vap, va_iosize, 512);
	vap->va_access_time.tv_sec = sp->s_accesstime.tv_sec;
	vap->va_access_time.tv_nsec = sp->s_accesstime.tv_usec * 1000;
	VATTR_SET_SUPPORTED(vap, va_access_time);
	vap->va_modify_time.tv_sec = sp->s_modificationtime.tv_sec;
	vap->va_modify_time.tv_nsec = sp->s_modificationtime.tv_usec * 1000;
	VATTR_SET_SUPPORTED(vap, va_modify_time);
	vap->va_change_time.tv_sec = sp->s_changetime.tv_sec;
	vap->va_change_time.tv_nsec = sp->s_changetime.tv_usec * 1000;
	VATTR_SET_SUPPORTED(vap, va_change_time);
	VATTR_RETURN(vap, va_gen, sp->s_generation);
	VATTR_RETURN(vap, va_flags, sp->s_flags);
	VATTR_RETURN(vap, va_rdev, sp->s_rdev);
	VATTR_RETURN(vap, va_filerev, 0);
	VATTR_RETURN(vap, va_acl, NULL);

	return (0);
}



/*
 * Change the mode on a file or directory.
 * vnode vp must be locked on entry.
 */
int synthfs_chmod(struct vnode *vp, int mode, kauth_cred_t cred, struct proc *p)
{
    struct synthfsnode *sp = VTOS(vp);
    int result;

    sp->s_mode &= ~ALLPERMS;
    sp->s_mode |= (mode & ALLPERMS);
    sp->s_nodeflags |= IN_CHANGE;
#if RWSUPPORT
    if ((vp->v_flag & VTEXT) && (sp->s_mode & S_ISTXT) == 0) (void) vnode_uncache(vp);
#endif

    return 0;
}



/*
 * Change the flags on a file or directory.
 * vnode vp must be locked on entry.
 */
int synthfs_chflags(struct vnode *vp, u_long flags, kauth_cred_t cred, struct proc *p)
{
    struct synthfsnode *sp = VTOS(vp);

    sp->s_flags = flags;
    sp->s_nodeflags |= IN_CHANGE;

    return 0;
}



/*
 * Perform chown operation on vnode vp;
 * vnode vp must be locked on entry.
 */
int synthfs_chown(struct vnode *vp, uid_t uid, gid_t gid, kauth_cred_t cred, struct proc *p)
{
    struct synthfsnode *sp = VTOS(vp);
    uid_t ouid;
    gid_t ogid;
    int result = 0;
    int is_member;

    if (uid == (uid_t)VNOVAL) uid = sp->s_uid;
    if (gid == (gid_t)VNOVAL) gid = sp->s_gid;

    ogid = sp->s_gid;
    ouid = sp->s_uid;

    sp->s_gid = gid;
    sp->s_uid = uid;

    if (ouid != uid || ogid != gid) sp->s_nodeflags |= IN_CHANGE;
    if (ouid != uid && suser(cred, NULL)) sp->s_mode &= ~S_ISUID;
    if (ogid != gid && suser(cred, NULL)) sp->s_mode &= ~S_ISGID;

    return 0;
}



/*
 * Set attribute vnode op. called from several syscalls
#% setattr      vp      L L L
#
 vnop_setattr {
     IN struct vnode *vp;
     IN struct vnode_attr *vap;
     IN vfs_context_t context;
     */

int
synthfs_setattr(ap)
struct vnop_setattr_args /* {
struct vnode *a_vp;
struct vnode_attr *a_vap;
vfs_context_t a_context;
} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct synthfsnode *sp = VTOS(vp);
	struct vnode_attr *vap = ap->a_vap;
	kauth_cred_t cred = vfs_context_ucred(ap->a_context);
	struct proc *p = vfs_context_proc(ap->a_context);
	struct timeval atimeval, mtimeval;
	uid_t nuid;
	gid_t ngid;
	int result;

	result = 0;

	if (VATTR_IS_ACTIVE(vap, va_flags)) {
		if ((result = synthfs_chflags(vp, vap->va_flags, cred, p))) {
			goto Err_Exit;
		}
	}
	VATTR_SET_SUPPORTED(vap, va_flags);

	nuid = (uid_t)ngid = (gid_t)VNOVAL;
	if (VATTR_IS_ACTIVE(vap, va_uid))
		nuid = vap->va_uid;
	if (VATTR_IS_ACTIVE(vap, va_gid))
		ngid = vap->va_gid;
	if (nuid != (uid_t)VNOVAL || ngid != (gid_t)VNOVAL) {
		if ((result = synthfs_chown(vp, nuid, ngid, cred, p))) {
			goto Err_Exit;
		}
	}
	VATTR_SET_SUPPORTED(vap, va_uid);
	VATTR_SET_SUPPORTED(vap, va_gid);

	if (VATTR_IS_ACTIVE(vap, va_data_size)) {
#if RWSUPPORT
		if ((result = vnode_setsize(vp, vap->va_data_size, 0, ap->a_context))) {
			goto Err_Exit;
		};
		VATTR_SET_SUPPORTED(vap, va_data_size);
#else
		result = EINVAL;
		goto Err_Exit;
#endif
	}

	sp = VTOS(vp);
	if (VATTR_IS_ACTIVE(vap, va_access_time) || VATTR_IS_ACTIVE(vap, va_modify_time)) {
		if (VATTR_IS_ACTIVE(vap, va_access_time)) {
			sp->s_nodeflags |= IN_ACCESS;
			atimeval.tv_sec = vap->va_access_time.tv_sec;
			atimeval.tv_usec = vap->va_access_time.tv_nsec / 1000;
		}
		if (VATTR_IS_ACTIVE(vap, va_modify_time)) {
			sp->s_nodeflags |= IN_CHANGE | IN_UPDATE;
			mtimeval.tv_sec = vap->va_modify_time.tv_sec;
			mtimeval.tv_usec = vap->va_modify_time.tv_nsec / 1000;
		}
		if ((result = synthfs_update(vp, &atimeval, &mtimeval, 1))) {
			goto Err_Exit;
		}
	}
	VATTR_SET_SUPPORTED(vap, va_access_time);
	VATTR_SET_SUPPORTED(vap, va_modify_time);

	if (VATTR_IS_ACTIVE(vap, va_mode))
		result = synthfs_chmod(vp, (int)vap->va_mode, cred, p);
	VATTR_SET_SUPPORTED(vap, va_mode);

	Err_Exit:

	DBG_VOP(("synthfs_setattr: returning %d...\n", result));

	return (result);
}



/*

#% rename	sourcePar_vp	U U U
#% rename	source_vp		U U U
#% rename	targetPar_vp	L U U
#% rename	target_vp		X U U
#
 vnop_rename {
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

int
synthfs_rename(ap)
struct vnop_rename_args  /* {
    struct vnode *a_fdvp;
    struct vnode *a_fvp;
    struct componentname *a_fcnp;
    struct vnode *a_tdvp;
    struct vnode *a_tvp;
    struct componentname *a_tcnp;
    vfs_context_t a_context;
} */ *ap;
{
	struct vnode			*target_vp = ap->a_tvp;
	struct vnode			*targetPar_vp = ap->a_tdvp;
	struct vnode			*source_vp = ap->a_fvp;
	struct vnode			*sourcePar_vp = ap->a_fdvp;
	struct componentname	*target_cnp = ap->a_tcnp;
	struct componentname	*source_cnp = ap->a_fcnp;
	struct synthfsnode		*target_sp, *targetPar_sp, *source_sp, *sourcePar_sp;
	u_short					doingdirectory = 0, oldparent = 0, newparent = 0;
	int						retval = 0;
	struct timeval			tv;

#if SYNTHFS_DIAGNOSTIC
    if ((target_cnp->cn_flags & HASBUF) == 0 ||
        (source_cnp->cn_flags & HASBUF) == 0)
        panic("synthfs_rename: no name");
#endif

	DBG_ASSERT((ap->a_fdvp->v_type == VDIR) && (ap->a_tdvp->v_type == VDIR));
	target_sp = targetPar_sp = source_sp = sourcePar_sp = NULL;


	sourcePar_sp = VTOS(sourcePar_vp);
	source_sp = VTOS(source_vp);
	oldparent = sourcePar_sp->s_nodeid;

	/*
	 * Be sure we are not renaming ".", "..", or an alias of ".". This
	 * leads to a crippled directory tree.	It's pretty tough to do a
	 * "ls" or "pwd" with the "." directory entry missing, and "cd .."
	 * doesn't work if the ".." entry is missing.
	 */
	if (source_sp->s_type == SYNTHFS_DIRECTORY) {
		if ((source_cnp->cn_namelen == 1 && source_cnp->cn_nameptr[0] == '.')
			|| sourcePar_sp == source_sp
			|| (source_cnp->cn_flags & ISDOTDOT)
			|| (source_sp->s_nodeflags & IN_RENAME)) {
			retval = EINVAL;
			goto abortit;
		}
		source_sp->s_nodeflags |= IN_RENAME;
		doingdirectory = TRUE;
	}

	/* Transit between abort and bad */

    targetPar_sp = VTOS(targetPar_vp);
    target_sp = target_vp ? VTOS(target_vp) : NULL;
    newparent = targetPar_sp->s_nodeid;


	/*
	 * If the destination exists, then be sure its type (file or dir)
	 * matches that of the source.	And, if it is a directory make sure
	 * it is empty.	 Then delete the destination.
	 */
	if (target_vp) {

#if RWSUPPORT
		if (target_vp->v_type == VREG) {
			(void) vnode_uncache(target_vp);
		};
#endif
		cache_purge(target_vp);
            
		retval = synthfs_remove_internal(targetPar_vp, target_vp, target_cnp, ap->a_context);

		target_vp = NULL;
		target_sp = NULL;		
		
		if (retval) goto bad;
	};


	/* remove the existing entry from the namei cache: */
	if (source_vp->v_type == VREG) cache_purge(source_vp);

	retval = synthfs_move_rename_entry( source_vp, targetPar_vp, target_cnp->cn_nameptr);

	if (retval) goto bad;

	source_sp->s_nodeflags &= ~IN_RENAME;

	/*
	 * Timestamp both parent directories.
	 * Note that if this is a rename within the same directory,
	 * (where targetPar_hp == sourcePar_hp)
	 * the code below is still safe and correct.
	 */
	targetPar_sp->s_nodeflags |= IN_UPDATE;
	sourcePar_sp->s_nodeflags |= IN_UPDATE;
	
	microtime(&tv);
	SYNTHFSTIMES(targetPar_sp, &tv, &tv);
	SYNTHFSTIMES(sourcePar_sp, &tv, &tv);

	return (retval);

bad:;
	if (retval && doingdirectory)
		source_sp->s_nodeflags &= ~IN_RENAME;

	return (retval);

abortit:;
	return (retval);
}



/*
 * Mkdir system call

#% mkdir	dvp	L U U
#% mkdir	vpp	- L -
#
 vnop_mkdir {
     IN WILLRELE struct vnode *dvp;
     OUT struct vnode **vpp;
     IN struct componentname *cnp;
     IN struct vnode_attr *vap;
     IN vfs_context_t context;

     We are responsible for freeing the namei buffer, it is done in synthfs_makenode(), unless there is
    a previous error.

*/

int
synthfs_mkdir(ap)
struct vnop_mkdir_args /* {
    struct vnode *a_dvp;
    struct vnode **a_vpp;
    struct componentname *a_cnp;
    struct vnode_attr *a_vap;
    vfs_context_t a_context;
} */ *ap;
{
	int retval;
	struct vnode *dvp = ap->a_dvp;
	struct componentname *cnp = ap->a_cnp;
	int mode = MAKEIMODE(ap->a_vap->va_type, ap->a_vap->va_mode);
	struct vnode *vp = NULL;

	*ap->a_vpp = NULL;

	retval = synthfs_new_directory(VTOVFS(dvp), dvp, cnp->cn_nameptr, VTOSFS(dvp)->synthfs_nextid++, mode, vfs_context_proc(cnp->cn_context), &vp);
	if (retval) goto Error_Exit;

	*ap->a_vpp = vp;

	retval = vnode_setattr(vp, ap->a_vap, ap->a_context);
	if (retval != 0) goto Error_Exit;

	Error_Exit:;
	if (retval != 0) {
		if (vp) synthfs_remove_directory(vp);
	}

	return retval;
}



/*

#% remove	dvp	L U U
#% remove	vp	L U U
#
 vnop_remove {
     IN WILLRELE struct vnode *dvp;
     IN WILLRELE struct vnode *vp;
     IN struct componentname *cnp;
     IN vfs_context_t context;
    
     */

int
synthfs_remove(ap)
struct vnop_remove_args /* {
    struct vnode *a_dvp;
    struct vnode *a_vp;
    struct componentname *a_cnp;
    vfs_context_t a_context;
} */ *ap;
{
	return synthfs_remove_internal(ap->a_dvp, ap->a_vp, ap->a_cnp, ap->a_context);
}

static int
synthfs_remove_internal(struct vnode *dvp, struct vnode *vp,
			__unused struct componentname *cnp,
			__unused vfs_context_t context)
{
	struct synthfsnode *sp = VTOS(vp);
	struct timeval tv;
	int retval = 0;

	/* This is sort of silly right now but someday it may make sense... */
	if (sp->s_nodeflags & IN_MODIFIED) {
		microtime(&tv);
		synthfs_update(vp, &tv, &tv, 0);
	};
	
	/* remove the entry from the namei cache: */
	cache_purge(vp);

	/* remove entry from tree and reclaim any resources consumed: */
	switch (sp->s_type) {
		case SYNTHFS_DIRECTORY:
			synthfs_remove_directory(vp);
			break;
		
		
		case SYNTHFS_SYMLINK:
			synthfs_remove_symlink(vp);
			break;
		
		case SYNTHFS_FILE:
			/* Fall through to default case */
		
		default:
			synthfs_remove_entry(vp);
	};

out:

	if (! retval)
		VTOS(dvp)->s_nodeflags |= IN_CHANGE | IN_UPDATE;

	return (retval);
}



/*
#% rmdir	dvp	L U U
#% rmdir	vp	L U U
#
 vnop_rmdir {
     IN WILLRELE struct vnode *dvp;
     IN WILLRELE struct vnode *vp;
     IN struct componentname *cnp;
     IN vfs_context_t context;

     */

int
synthfs_rmdir(ap)
    struct vnop_rmdir_args /* {
    	struct vnode *a_dvp;
    	struct vnode *a_vp;
        struct componentname *a_cnp;
	vfs_context_t a_context;
} */ *ap;
{
	return synthfs_remove((struct vnop_remove_args *)ap);
}



/*
 * synthfs_select - just say OK.  Only possible op is readdir
 *
 * Locking policy: ignore
 */
int
synthfs_select(__unused
struct vnop_select_args /* {
    struct vnode *a_vp;
    int  a_which;
    int  a_fflags;
    kauth_cred_t a_cred;
	void *a_wql;
    struct proc *a_p;
} */ *ap)
{
    DBG_VOP(("synthfs_select called\n"));

    return (1);
}

/*
#
#% symlink	dvp	L U U
#% symlink	vpp	- U -
#
# XXX - note that the return vnode has already been vnode_put'ed
#	by the filesystem layer.  To use it you must use vnode_get,
#	possibly with a further namei.
#
 vnop_symlink {
     IN WILLRELE struct vnode *dvp;
     OUT WILLRELE struct vnode **vpp;
     IN struct componentname *cnp;
     IN struct vnode_attr *vap;
     IN char *target;

     We are responsible for freeing the namei buffer, it is done in synthfs_makenode(), unless there is
    a previous error.


*/

int
synthfs_symlink(ap)
    struct vnop_symlink_args /* {
        struct vnode *a_dvp;
        struct vnode **a_vpp;
        struct componentname *a_cnp;
        struct vnode_attr *a_vap;
        char *a_target;
	vfs_context_t a_context;
    } */ *ap;
{
    struct vnode *dvp = ap->a_dvp;
    struct vnode **vpp = ap->a_vpp;
    struct componentname *cnp = ap->a_cnp;
    int retval;

    *vpp = NULL;

    retval = synthfs_new_symlink(VTOVFS(dvp), dvp, cnp->cn_nameptr, VTOSFS(dvp)->synthfs_nextid++, ap->a_target, vfs_context_proc(cnp->cn_context), vpp);

    return (retval);
}



/*
#
#% readlink	vp	L L L
#
 vnop_readlink {
     IN struct vnode *vp;
     INOUT struct uio *uio;
     IN kauth_cred_t cred;
     */

int
synthfs_readlink(ap)
struct vnop_readlink_args /* {
	struct vnode *a_vp;
	struct uio *a_uio;
	vfs_context_t a_context;
} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct synthfsnode *sp = VTOS(vp);
    struct uio *uio = ap->a_uio;
    int retval;
    unsigned long count;
    
    if (ap->a_uio->uio_offset > sp->s_u.s.s_length) {
        return 0;
    };

	// LP64todo - fix this!
    if (uio->uio_offset + uio_resid(uio) <= sp->s_u.s.s_length) {
    	count = uio_resid(uio);
    } else {
    	count = sp->s_u.s.s_length - uio->uio_offset;
    };
    retval = uiomove((void *)((unsigned char *)sp->s_u.s.s_symlinktarget + uio->uio_offset), count, uio);
    return (retval);

}






/* 			
 * Read directory entries.
 */
int
synthfs_readdir(ap)
struct vnop_readdir_args /* {
	struct vnode *a_vp;
	struct uio *a_uio;
	int a_flags;
	int *a_eofflag;
	int *a_numdirent;
	vfs_context_t a_context;
} */ *ap;
{
    struct synthfsnode *sp = VTOS(ap->a_vp);
    register struct uio *uio = ap->a_uio;
    off_t diroffset;						/* Offset into simulated directory file */
    struct synthfsnode *entry;

    DBG_VOP(("\tuio_offset = %d, uio_resid = %lld\n", (int) uio->uio_offset, uio_resid(uio)));

	if (ap->a_flags & (VNODE_READDIR_EXTENDED | VNODE_READDIR_REQSEEKOFF))
		return (EINVAL);
	
	/* We assume it's all one big buffer... */
    if (uio->uio_iovcnt > 1) {
    	DBG_VOP(("\tuio->uio_iovcnt = %d?\n", uio->uio_iovcnt));
    	return EINVAL;
    };
	
 	diroffset = 0;
 	
    /*
     * We must synthesize . and ..
     */
    DBG_VOP(("\tstarting ... uio_offset = %d, uio_resid = %lld\n", (int) uio->uio_offset, uio_resid(uio)));
    if (uio->uio_offset == diroffset)
      {
        DBG_VOP(("\tAdding .\n"));
		diroffset += synthfs_adddirentry(sp->s_nodeid, DT_DIR, ".", uio);
        DBG_VOP(("\t   after adding ., uio_offset = %d, uio_resid = %lld\n", (int) uio->uio_offset, uio_resid(uio)));
      }
    if ((uio_resid(uio) > 0) && (diroffset > uio->uio_offset)) {
    	/* Oops - we skipped over a partial entry: at best, diroffset should've just matched uio->uio_offset */
		return EINVAL;
	};
	
    if (uio->uio_offset == diroffset)
      {
        DBG_VOP(("\tAdding ..\n"));
        if (sp->s_parent != NULL) {
            diroffset += synthfs_adddirentry(sp->s_parent->s_nodeid, DT_DIR, "..", uio);
        } else {
            diroffset += synthfs_adddirentry(sp->s_nodeid, DT_DIR, "..", uio);
        }
        DBG_VOP(("\t   after adding .., uio_offset = %d, uio_resid = %lld\n", (int) uio->uio_offset, uio_resid(uio)));
      }
    if ((uio_resid(uio) > 0) && (diroffset > uio->uio_offset)) {
    	/* Oops - we skipped over a partial entry: at best, diroffset should've just matched uio->uio_offset */
		return EINVAL;
	};

	/* OK, so much for the fakes.  Now for the "real thing": */
	TAILQ_FOREACH(entry, &sp->s_u.d.d_subnodes, s_sibling) {
		if (diroffset == uio->uio_offset) {
			/* Return this entry */
			diroffset += synthfs_adddirentry(entry->s_nodeid, VTTOIF(STOV(entry)->v_type), entry->s_name, uio);
		};
    	if ((uio_resid(uio) > 0) && (diroffset > uio->uio_offset)) {
	    	/* Oops - we skipped over a partial entry: at best, diroffset should've just matched uio->uio_offset */
			return EINVAL;
		};
	};
    
    if (ap->a_eofflag)
        *ap->a_eofflag = (entry == NULL);		/* If we ran all the way through the list, there is no more */

    return 0;
}



/*	

#% lookup	dvp L ? ?
#% lookup	vpp - L -

 */

int
synthfs_cached_lookup(ap)
	struct vnop_lookup_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
	} */ *ap;
{
    struct vnode *dp = ap->a_dvp;
    struct componentname *cnp = ap->a_cnp;
    u_long nameiop = cnp->cn_nameiop;
    u_long flags = cnp->cn_flags;
    struct vnode **vpp = ap->a_vpp;
    int result = 0;

    DBG_VOP(("synthfs_cached_lookup called, name = %s, namelen = %ld\n", ap->a_cnp->cn_nameptr, ap->a_cnp->cn_namelen));
#if DEBUG
    if (flags & ISLASTCN) DBG_VOP(("\tISLASTCN is set\n"));
#endif

    *vpp = NULL;

	/*
	 * Look up an entry in the namei cache
	 */
	
	result = cache_lookup(dp, vpp, cnp);
	if (result == 0) {
		/* There was no entry in the cache for this parent vnode/name pair:
		   do the full-blown pathname lookup
		 */
		return synthfs_lookup(ap);
	};
	if (result == ENOENT) return result;
	
	/* An entry matching the parent vnode/name was found in the cache: */
	
	return (0);
	
Err_Exit:;
	return result;
}



int
synthfs_lookup(ap)
	struct vnop_lookup_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		vfs_context_t a_context;
	} */ *ap;
{
    struct vnode *dp = ap->a_dvp;
    struct synthfsnode *dsp = VTOS(dp);
    struct componentname *cnp = ap->a_cnp;
    u_long nameiop = cnp->cn_nameiop;
//  char *nameptr = cnp->cn_nameptr;
    u_long flags = cnp->cn_flags;
    long namelen = cnp->cn_namelen;
//  struct proc *p = cnp->cn_proc;
    vfs_context_t ctx = cnp->cn_context;
    kauth_cred_t cred = vfs_context_ucred(ctx);
    struct synthfsnode *entry;
    struct vnode *target_vp = NULL;
    int result = 0;
    boolean_t found = FALSE;
    boolean_t isDot = FALSE;
    boolean_t isDotDot = FALSE;
	struct vnode *starting_parent = dp;
	
    DBG_VOP(("synthfs_lookup called, name = %s, namelen = %ld\n", ap->a_cnp->cn_nameptr, ap->a_cnp->cn_namelen));
#if DEBUG
    if (flags & LOCKPARENT) DBG_VOP(("\tLOCKPARENT is set\n"));
    if (flags & ISLASTCN) DBG_VOP(("\tISLASTCN is set\n"));
#endif

    *ap->a_vpp = NULL;

	/* first check for "." and ".." */
	if (cnp->cn_nameptr[0] == '.') {
		if (namelen == 1) {
			/*
			   "." requested
			 */
            isDot = TRUE;
            found = TRUE;

            target_vp = dp;
            vnode_get(target_vp);
            
            result = 0;
            
            goto Std_Exit;
        } else if ((namelen == 2) && (cnp->cn_nameptr[1] == '.')) {
			/* 
			   ".." requested
			 */
            isDotDot = TRUE;
            found = TRUE;

            if ((dsp->s_parent != NULL) && (dsp->s_parent != VTOS(dp))) {
                target_vp = STOV(dsp->s_parent);
                /*
                 * Special case for ".." to prevent deadlock:
                 * always release the parent vnode BEFORE trying to acquire
                 * ITS parent.  This avoids deadlocking with another lookup
                 * starting from the target_vp trying to vnode_get() this directory.
                 */
                result = vnode_get(target_vp);

            } else {
                target_vp = dp;
                /* dp is alread locked and ref'ed */
                result = 0;
            }
            
            goto Std_Exit;
		}
	}

	/* finally, just look for entries by name (making sure the entry's length
	   matches the cnp's namelen... */
    TAILQ_FOREACH(entry, &dsp->s_u.d.d_subnodes, s_sibling) {
    	if ((bcmp(cnp->cn_nameptr, entry->s_name, (unsigned)namelen) == 0) &&
    		(*(entry->s_name + namelen) == (char)0)) {
            found = TRUE;
			target_vp = STOV(entry);
            result = vnode_getwithref(target_vp);		/* refcount is always > 0 for any vnode in this list... */
			if (result != 0) {
				goto Err_Exit;
			};

            /* The specified entry was found and successfully acquired: */
			goto Std_Exit;
        };
	};

    found = FALSE;

Std_Exit:;
    if (found) {
        if ((nameiop == DELETE) && (flags & ISLASTCN)) {

            /*
             * If the parent directory is "sticky" then the user must own
             * the directory, or the file in it, in order to be allowed to
             * delete it (unless the user is root).  This implements
             * append-only directories
             */
            if ((dsp->s_mode & S_ISVTX) &&
                suser(cred, NULL) &&
                (kauth_cred_getuid(cred) != dsp->s_uid) &&
                (target_vp != NULL) &&
                (target_vp->v_type != VLNK) &&
                (VTOS(target_vp)->s_uid != kauth_cred_getuid(cred))) {
                vnode_put(target_vp);
                result = EPERM;
                goto Err_Exit;
            };
        };

        if ((nameiop == RENAME) && (flags & WANTPARENT) && (flags * ISLASTCN)) {

            if (isDot) {
                vnode_put(target_vp);
                result = EISDIR;
                goto Err_Exit;
            };
        };
    } else {
        /* The specified entry wasn't found: */
        result = ENOENT;

        if ((flags & ISLASTCN) &&
            ((nameiop == CREATE) ||
             (nameiop == RENAME) ||
             ((nameiop == DELETE) && (flags & DOWHITEOUT) && (flags & ISWHITEOUT)))) {
		/* create a new entry */
            result = EJUSTRETURN;
        }
    };

    *ap->a_vpp = target_vp;

Err_Exit:;
	DBG_VOP(("synthfs_lookup: result = %d.\n", result));
	if (found) {
		if (target_vp) {
				DBG_VOP(("synthfs_lookup: target_vp = 0x%08X \n", (u_long)target_vp));
		} else {
			DBG_VOP(("synthfs_lookup: found = true but target_vp = NULL?\n"));
		};
	} else {
		DBG_VOP(("synthf_lookup: target not found.\n"));
	};
		DBG_VOP(("synthfs_lookup: dp = %08X; starting_parent = 0x%08X .\n", (u_long)dp, (u_long)starting_parent));
	
   return result;
}



/*

#% pathconf	vp	L L L
#
 vnop_pathconf {
     IN struct vnode *vp;
     IN int name;
     OUT register_t *retval;
*/
int
synthfs_pathconf(ap)
struct vnop_pathconf_args /* {
    struct vnode *a_vp;
    int a_name;
    int *a_retval;
    vfs_context_t a_context;
} */ *ap;
{
    DBG_VOP(("synthfs_pathconf called\n"));

    switch (ap->a_name)
      {
        case _PC_LINK_MAX:
            *ap->a_retval = LINK_MAX;
            return (0);
        case _PC_NAME_MAX:
            *ap->a_retval = NAME_MAX;
            return (0);
        case _PC_PATH_MAX:
            *ap->a_retval = PATH_MAX;
            return (0);
        case _PC_PIPE_BUF:
            *ap->a_retval = PIPE_BUF;
            return (0);
        case _PC_CHOWN_RESTRICTED:
            *ap->a_retval = 1;
            return (0);
        case _PC_NO_TRUNC:
            *ap->a_retval = 1;
            return (0);
        default:
            return (EINVAL);
      }
    /* NOTREACHED */
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

int
synthfs_update(struct vnode *vp, struct timeval *access, struct timeval *modify, __unused int waitfor)
{
	struct synthfsnode *sp = VTOS(vp);
	struct timeval tv;

	DBG_ASSERT(sp != NULL);

	if (((sp->s_nodeflags & (IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE)) != 0) &&
		!(VTOVFS(vp)->mnt_flag & MNT_RDONLY)) {
		if (sp->s_nodeflags & IN_ACCESS) sp->s_accesstime = *access;
		if (sp->s_nodeflags & IN_UPDATE) sp->s_modificationtime = *modify;
		if (sp->s_nodeflags & IN_CHANGE) {

			microtime(&tv);
			sp->s_changetime = tv;
		}
	};
	
	/* After the updates are finished, clear the flags */
	sp->s_nodeflags &= ~(IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE);

	return 0;
}



/*******************************************************************************************

	Utility/housekeeping vnode operations:
	
 ******************************************************************************************/


/*
#
#% inactive	vp	L U U
#
 vnop_inactive {
     IN struct vnode *vp;
     IN struct proc *p;

*/

int
synthfs_inactive(ap)
struct vnop_inactive_args /* {
    struct vnode *a_vp;
    vfs_context_t a_context;
} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct synthfsnode *sp = VTOS(vp);
	struct timeval tv;

#if DEBUG
	if (vp->v_usecount != 0)
        DBG_VOP(("synthfs_inactive: bad usecount = %d\n", vp->v_usecount ));
#endif

	/*
	 * Ignore nodes related to stale file handles.
	 */
	if (vp->v_type == VNON)
		goto out;
	
	/* This is sort of silly but might make sense in the future: */
	if (sp->s_nodeflags & (IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE)) {
		microtime(&tv);
		synthfs_update(vp, &tv, &tv, 0);
	}

out:
	/*
	 * If we are done with the inode, reclaim it
	 * so that it can be reused immediately.
	 */
	if (vp->v_type == VNON) {
		vnode_recycle(vp);
	};
	
	return 0;
}



/*
 * synthfs_reclaim - Reclaim a vnode so that it can be used for other purposes.
 *
 * Locking policy: ignored
 */
int
synthfs_reclaim(ap)
    struct vnop_reclaim_args /* { struct vnode *a_vp; struct proc *a_p; } */ *ap;
{
    struct vnode *vp = ap->a_vp;
    struct synthfsnode *sp = VTOS(vp);
    void *name = sp->s_name;
    
    sp->s_name = NULL;
    FREE(name, M_TEMP);

	vp->v_data = NULL;
    FREE((void *)sp, M_SYNTHFS);

    return (0);
}
