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
#include <sys/buf.h>
#include <sys/proc.h>
#include <sys/conf.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/namei.h>
#include <sys/attr.h>

#include <sys/vm.h>
#include <sys/errno.h>
#include <vfs/vfs_support.h>

#include "synthfs.h"

#define RWSUPPORT 0

#if RWSUPPORT
#error NOT PORTED FOR UBC
/* when porting to UBC,  do not just replace 
 * vnode_uncache by ubc_uncache - there's more
 * to it than that!
 */
#include <sys/ubc.h>
#endif

/* external routines defined in vfs_cache.c */
extern void cache_purge (struct vnode *vp);
extern int cache_lookup (struct vnode *dvp, struct vnode **vpp, struct componentname *cnp);
extern void cache_enter (struct vnode *dvp, struct vnode *vpp, struct componentname *cnp);

//extern void vnode_uncache(struct vnode *);

extern int groupmember(gid_t gid, struct ucred* cred);

#define VOPFUNC int (*)(void *)

/* Global vfs data structures for synthfs. */
int (**synthfs_vnodeop_p) (void *);
struct vnodeopv_entry_desc synthfs_vnodeop_entries[] = {
    {&vop_default_desc, (VOPFUNC)vn_default_error},
    {&vop_strategy_desc, (VOPFUNC)err_strategy},		/* strategy		- not supported  */
    {&vop_bwrite_desc, (VOPFUNC)err_bwrite},			/* bwrite		- not supported  */
    {&vop_lookup_desc, (VOPFUNC)synthfs_cached_lookup},	/* cached lookup */
    {&vop_create_desc, (VOPFUNC)synthfs_create},		/* create		- DEBUGGER */
    {&vop_whiteout_desc, (VOPFUNC)err_whiteout},		/* whiteout		- not supported  */
    {&vop_mknod_desc, (VOPFUNC)err_mknod},			/* mknod		- not supported  */
    {&vop_mkcomplex_desc, (VOPFUNC)err_mkcomplex},		/* mkcomplex	- not supported  */
    {&vop_open_desc, (VOPFUNC)synthfs_open},			/* open			- DEBUGGER */
    {&vop_close_desc, (VOPFUNC)nop_close},			/* close		- NOP */
    {&vop_access_desc, (VOPFUNC)synthfs_access},		/* access */
    {&vop_getattr_desc, (VOPFUNC)synthfs_getattr},		/* getattr */
    {&vop_setattr_desc, (VOPFUNC)synthfs_setattr},		/* setattr */
    {&vop_getattrlist_desc, (VOPFUNC)err_getattrlist},	/* getattrlist	- not supported  */
    {&vop_setattrlist_desc, (VOPFUNC)err_setattrlist},	/* setattrlist	- not supported  */
    {&vop_read_desc, (VOPFUNC)err_read},			/* read			- not supported  */
    {&vop_write_desc, (VOPFUNC)err_write},			/* write		- not supported  */
    {&vop_lease_desc, (VOPFUNC)err_lease},			/* lease		- not supported  */
    {&vop_ioctl_desc, (VOPFUNC)err_ioctl},			/* ioctl		- not supported  */
    {&vop_select_desc, (VOPFUNC)synthfs_select},		/* select */
    {&vop_exchange_desc, (VOPFUNC)err_exchange},		/* exchange		- not supported  */
    {&vop_revoke_desc, (VOPFUNC)nop_revoke},			/* revoke		- NOP */
    {&vop_mmap_desc, (VOPFUNC)synthfs_mmap},			/* mmap			- DEBUGGER */
    {&vop_fsync_desc, (VOPFUNC)nop_fsync},			/* fsync		- NOP */
    {&vop_seek_desc, (VOPFUNC)nop_seek},			/* seek			- NOP */
    {&vop_remove_desc, (VOPFUNC)synthfs_remove},		/* remove */
    {&vop_link_desc, (VOPFUNC)err_link},			/* link			- not supported  */
    {&vop_rename_desc, (VOPFUNC)synthfs_rename},		/* rename */
    {&vop_mkdir_desc, (VOPFUNC)synthfs_mkdir},			/* mkdir */
    {&vop_rmdir_desc, (VOPFUNC)synthfs_rmdir},			/* rmdir */
    {&vop_symlink_desc, (VOPFUNC)synthfs_symlink},		/* symlink */
    {&vop_readdir_desc, (VOPFUNC)synthfs_readdir},		/* readdir */
    {&vop_readdirattr_desc, (VOPFUNC)err_readdirattr},	/* readdirattr	- not supported  */
    {&vop_readlink_desc, (VOPFUNC)synthfs_readlink},		/* readlink */
    {&vop_abortop_desc, (VOPFUNC)nop_abortop},			/* abortop		- NOP */
    {&vop_inactive_desc, (VOPFUNC)synthfs_inactive},		/* inactive */
    {&vop_reclaim_desc, (VOPFUNC)synthfs_reclaim},		/* reclaim */
    {&vop_lock_desc, (VOPFUNC)synthfs_lock},			/* lock */
    {&vop_unlock_desc, (VOPFUNC)synthfs_unlock},		/* unlock */
    {&vop_bmap_desc, (VOPFUNC)err_bmap},					/* bmap			- not supported  */
    {&vop_print_desc, (VOPFUNC)err_print},			/* print		- not supported  */
    {&vop_islocked_desc, (VOPFUNC)synthfs_islocked},		/* islocked */
    {&vop_pathconf_desc, (VOPFUNC)synthfs_pathconf},		/* pathconf */
    {&vop_advlock_desc, (VOPFUNC)err_advlock},			/* advlock		- not supported  */
    {&vop_blkatoff_desc, (VOPFUNC)err_blkatoff},		/* blkatoff		- not supported  */
    {&vop_valloc_desc, (VOPFUNC)err_valloc},			/* valloc		- not supported  */
    {&vop_reallocblks_desc, (VOPFUNC)err_reallocblks},	/* reallocblks	- not supported  */
    {&vop_vfree_desc, (VOPFUNC)err_vfree},			/* vfree		- not supported  */
    {&vop_truncate_desc, (VOPFUNC)err_truncate},		/* truncate		- not supported  */
    {&vop_allocate_desc, (VOPFUNC)err_allocate},		/* allocate		- not supported  */
    {&vop_update_desc, (VOPFUNC)synthfs_update},		/* update */
	{&vop_pgrd_desc, (VOPFUNC)err_pgrd},			/* pgrd			- not supported  */
	{&vop_pgwr_desc, (VOPFUNC)err_pgwr},			/* pgwr			- not supported  */
	{&vop_pagein_desc, (VOPFUNC)err_pagein},		/* pagein		- not supported  */
	{&vop_pageout_desc, (VOPFUNC)err_pageout},		/* pageout		- not supported  */
	{&vop_devblocksize_desc, (VOPFUNC)err_devblocksize},	/* devblocksize - not supported  */
	{&vop_searchfs_desc, (VOPFUNC)err_searchfs},		/* searchfs		- not supported */
	{&vop_copyfile_desc, (VOPFUNC)err_copyfile},		/* copyfile - not supported */
 	{ &vop_blktooff_desc, (VOPFUNC)err_blktooff },		/* blktooff not supported */
	{ &vop_offtoblk_desc, (VOPFUNC)err_offtoblk },		/* offtoblk  not supported */
	{ &vop_cmap_desc, (VOPFUNC)err_cmap },		/* cmap  not supported */
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
 vop_create {
     IN WILLRELE struct vnode *dvp;
     OUT struct vnode **vpp;
     IN struct componentname *cnp;
     IN struct vattr *vap;
	
     We are responsible for freeing the namei buffer, it is done in hfs_makenode(), unless there is
	a previous error.

*/

int
synthfs_create(ap)
struct vop_create_args /* {
    struct vnode *a_dvp;
    struct vnode **a_vpp;
    struct componentname *a_cnp;
    struct vattr *a_vap;
} */ *ap;
{
#if DEBUG
	struct vnode *dvp = ap->a_dvp;
	char debugmsg[255];
	
	sprintf(debugmsg, "synthfs_create: attempt to create '%s' in '%s' ?!", ap->a_cnp->cn_nameptr, VTOS(dvp)->s_name);
	Debugger(debugmsg);
#endif

	return EOPNOTSUPP;
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

int
synthfs_open(ap)
struct vop_open_args /* {
    struct vnode *a_vp;
    int  a_mode;
    struct ucred *a_cred;
    struct proc *a_p;
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
 vop_mmap {
     IN struct vnode *vp;
     IN int fflags;
     IN struct ucred *cred;
     IN struct proc *p;

     */

/* ARGSUSED */

int
synthfs_mmap(ap)
struct vop_mmap_args /* {
    struct vnode *a_vp;
    int  a_fflags;
    struct ucred *a_cred;
    struct proc *a_p;
} */ *ap;
{
#if DEBUG
	struct vnode *vp = ap->a_vp;
	char debugmsg[255];
	
	sprintf(debugmsg, "synthfs_mmap: attempt to map '/%s' ?!", VTOS(vp)->s_name);
	Debugger(debugmsg);
#endif
	
    return EINVAL;
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

int
synthfs_access(ap)
struct vop_access_args /* {
    struct vnode *a_vp;
    int  a_mode;
    struct ucred *a_cred;
    struct proc *a_p;
} */ *ap;
{
    struct vnode *vp 			= ap->a_vp;
    mode_t mode					= ap->a_mode;
    struct ucred *cred 			= ap->a_cred;
    struct synthfsnode *sp 		= VTOS(vp);
    register gid_t *gp;
    mode_t mask;
    int retval 					= 0;
    int i;

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
    if ((mode & VWRITE) && (sp->s_flags & IMMUTABLE))
        return (EPERM);

    /* Otherwise, user id 0 always gets access. */
    if (ap->a_cred->cr_uid == 0) {
        retval = 0;
        goto Exit;
    };

    mask = 0;

    /* Otherwise, check the owner. */
    if (cred->cr_uid == sp->s_uid) {
        if (mode & VEXEC)
            mask |= S_IXUSR;
        if (mode & VREAD)
            mask |= S_IRUSR;
        if (mode & VWRITE)
            mask |= S_IWUSR;
        retval = ((sp->s_mode & mask) == mask ? 0 : EACCES);
        goto Exit;
    }
 
    /* Otherwise, check the groups. */
    for (i = 0, gp = cred->cr_groups; i < cred->cr_ngroups; i++, gp++)
        if (sp->s_gid == *gp) {
            if (mode & VEXEC)
                mask |= S_IXGRP;
            if (mode & VREAD)
                mask |= S_IRGRP;
            if (mode & VWRITE)
                mask |= S_IWGRP;
            retval = ((sp->s_mode & mask) == mask ? 0 : EACCES);
 			goto Exit;
        }
 
    /* Otherwise, check everyone else. */
    if (mode & VEXEC)
        mask |= S_IXOTH;
    if (mode & VREAD)
        mask |= S_IROTH;
    if (mode & VWRITE)
        mask |= S_IWOTH;
    retval = ((sp->s_mode & mask) == mask ? 0 : EACCES);
 
Exit:
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
int
synthfs_getattr(ap)
struct vop_getattr_args /* {
    struct vnode *a_vp;
    struct vattr *a_vap;
    struct ucred *a_cred;
    struct proc *a_p;
} */ *ap;
{
    struct vnode *vp     = ap->a_vp;
    struct vattr *vap    = ap->a_vap;
    struct synthfsnode *sp = VTOS(vp);
    struct synthfs_mntdata *smp = VTOSFS(vp);

	vap->va_type = vp->v_type;
	vap->va_mode = sp->s_mode;
	vap->va_nlink = sp->s_linkcount;
	vap->va_uid = sp->s_uid;
	vap->va_gid = sp->s_gid;
	vap->va_fsid = VTOVFS(vp)->mnt_stat.f_fsid.val[0];
	vap->va_fileid = sp->s_nodeid;
	switch (vp->v_type) {
	  case VDIR:
          vap->va_size = (sp->s_u.d.d_entrycount + 2) * sizeof(struct dirent);
		break;
	  
	  case VREG:
	  	vap->va_size = sp->s_u.f.f_size;
	  	break;
	
	  case VLNK:
		vap->va_size = sp->s_u.s.s_length;
		break;
	
	  default:
		vap->va_size = 0;
	};
    vap->va_blocksize = 512;
    vap->va_atime.tv_sec = sp->s_accesstime.tv_sec;
    vap->va_atime.tv_nsec = sp->s_accesstime.tv_usec * 1000;
    vap->va_mtime.tv_sec = sp->s_modificationtime.tv_sec;
    vap->va_mtime.tv_nsec = sp->s_modificationtime.tv_usec * 1000;
    vap->va_ctime.tv_sec = sp->s_changetime.tv_sec;
    vap->va_ctime.tv_nsec = sp->s_changetime.tv_usec * 1000;
    vap->va_gen = sp->s_generation;
    vap->va_flags = sp->s_flags;
    vap->va_rdev = sp->s_rdev;
    vap->va_bytes = vap->va_blocksize * ((vap->va_size + vap->va_blocksize - 1) / vap->va_blocksize);
    vap->va_filerev = 0;
    vap->va_vaflags = 0;

    return (0);
}



/*
 * Change the mode on a file or directory.
 * vnode vp must be locked on entry.
 */
int synthfs_chmod(struct vnode *vp, int mode, struct ucred *cred, struct proc *p)
{
    struct synthfsnode *sp = VTOS(vp);
    int result;

    if ((cred->cr_uid != sp->s_uid) &&
        (result = suser(cred, &p->p_acflag)))
        return result;
    if (cred->cr_uid) {
        if (vp->v_type != VDIR && (mode & S_ISTXT))
            return EFTYPE;
        if (!groupmember(sp->s_gid, cred) && (mode & S_ISGID))
            return (EPERM);
    }
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
int synthfs_chflags(struct vnode *vp, u_long flags, struct ucred *cred, struct proc *p)
{
    struct synthfsnode *sp = VTOS(vp);
    int result;

    if (cred->cr_uid != sp->s_uid &&
        (result = suser(cred, &p->p_acflag)))
        return result;

    if (cred->cr_uid == 0) {
        if ((sp->s_flags & (SF_IMMUTABLE | SF_APPEND)) &&
            securelevel > 0) {
            return EPERM;
        };
        sp->s_flags = flags;
    } else {
        if (sp->s_flags & (SF_IMMUTABLE | SF_APPEND) ||
            (flags & UF_SETTABLE) != flags) {
            return EPERM;
        };
        sp->s_flags &= SF_SETTABLE;
        sp->s_flags |= (flags & UF_SETTABLE);
    }
    sp->s_nodeflags |= IN_CHANGE;

    return 0;
}



/*
 * Perform chown operation on vnode vp;
 * vnode vp must be locked on entry.
 */
int synthfs_chown(struct vnode *vp, uid_t uid, gid_t gid, struct ucred *cred, struct proc *p)
{
    struct synthfsnode *sp = VTOS(vp);
    uid_t ouid;
    gid_t ogid;
    int result = 0;

    if (uid == (uid_t)VNOVAL) uid = sp->s_uid;
    if (gid == (gid_t)VNOVAL) gid = sp->s_gid;

    /*
     * If we don't own the file, are trying to change the owner
     * of the file, or are not a member of the target group,
     * the caller must be superuser or the call fails.
     */
    if ((cred->cr_uid != sp->s_uid || uid != sp->s_uid ||
         (gid != sp->s_gid && !groupmember((gid_t)gid, cred))) &&
        (result = suser(cred, &p->p_acflag)))
        return result;

    ogid = sp->s_gid;
    ouid = sp->s_uid;

    sp->s_gid = gid;
    sp->s_uid = uid;

    if (ouid != uid || ogid != gid) sp->s_nodeflags |= IN_CHANGE;
    if (ouid != uid && cred->cr_uid != 0) sp->s_mode &= ~S_ISUID;
    if (ogid != gid && cred->cr_uid != 0) sp->s_mode &= ~S_ISGID;

    return 0;
}



/*
 * Set attribute vnode op. called from several syscalls
#% setattr      vp      L L L
#
 vop_setattr {
     IN struct vnode *vp;
     IN struct vattr *vap;
     IN struct ucred *cred;
     IN struct proc *p;

     */

int
synthfs_setattr(ap)
struct vop_setattr_args /* {
struct vnode *a_vp;
struct vattr *a_vap;
struct ucred *a_cred;
struct proc *a_p;
} */ *ap;
{
    struct vnode *vp = ap->a_vp;
    struct synthfsnode *sp = VTOS(vp);
    struct vattr *vap = ap->a_vap;
    struct ucred *cred = ap->a_cred;
    struct proc *p = ap->a_p;
    struct timeval atimeval, mtimeval;
    int result;

    /*
     * Check for unsettable attributes.
     */
    if (((vap->va_type != VNON) && (vap->va_type != vp->v_type)) ||
        (vap->va_nlink != VNOVAL) ||
        (vap->va_fsid != VNOVAL) || (vap->va_fileid != VNOVAL) ||
        (vap->va_blocksize != VNOVAL) || (vap->va_rdev != VNOVAL) ||
        ((int)vap->va_bytes != VNOVAL) || (vap->va_gen != VNOVAL)) {
        result = EINVAL;
        goto Err_Exit;
    }

    if (vap->va_flags != VNOVAL) {
        if (VTOVFS(vp)->mnt_flag & MNT_RDONLY) {
            result = EROFS;
            goto Err_Exit;
        };
        if ((result = synthfs_chflags(vp, vap->va_flags, cred, p))) {
            goto Err_Exit;
        };
        if (vap->va_flags & (IMMUTABLE | APPEND)) {
            result = 0;
            goto Err_Exit;
        };
    }

    if (sp->s_flags & (IMMUTABLE | APPEND)) {
        result = EPERM;
        goto Err_Exit;
    };

    /*
     * Go through the fields and update iff not VNOVAL.
     */
    if (vap->va_uid != (uid_t)VNOVAL || vap->va_gid != (gid_t)VNOVAL) {
        if (VTOVFS(vp)->mnt_flag & MNT_RDONLY) {
            result = EROFS;
            goto Err_Exit;
        };
        if ((result = synthfs_chown(vp, vap->va_uid, vap->va_gid, cred, p))) {
            goto Err_Exit;
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
                result = EISDIR;
                goto Err_Exit;
            case VLNK:
            case VREG:
                if (VTOVFS(vp)->mnt_flag & MNT_RDONLY) {
                    result = EROFS;
                    goto Err_Exit;
                };
                break;
            default:
                break;
        }
#if RWSUPPORT
        if ((result = VOP_TRUNCATE(vp, vap->va_size, 0, cred, p))) {
            goto Err_Exit;
        };
#else
        result = EINVAL;
        goto Err_Exit;
#endif
    }

    sp = VTOS(vp);
    if (vap->va_atime.tv_sec != VNOVAL || vap->va_mtime.tv_sec != VNOVAL) {
        if (VTOVFS(vp)->mnt_flag & MNT_RDONLY) {
            result = EROFS;
            goto Err_Exit;
        };
        if (cred->cr_uid != sp->s_uid &&
            (result = suser(cred, &p->p_acflag)) &&
            ((vap->va_vaflags & VA_UTIMES_NULL) == 0 ||
             (result = VOP_ACCESS(vp, VWRITE, cred, p)))) {
            goto Err_Exit;
        };
        if (vap->va_atime.tv_sec != VNOVAL)
            sp->s_nodeflags |= IN_ACCESS;
        if (vap->va_mtime.tv_sec != VNOVAL)
            sp->s_nodeflags |= IN_CHANGE | IN_UPDATE;
        atimeval.tv_sec = vap->va_atime.tv_sec;
        atimeval.tv_usec = vap->va_atime.tv_nsec / 1000;
        mtimeval.tv_sec = vap->va_mtime.tv_sec;
        mtimeval.tv_usec = vap->va_mtime.tv_nsec / 1000;
        if ((result = VOP_UPDATE(vp, &atimeval, &mtimeval, 1))) {
            goto Err_Exit;
        };
    }

    result = 0;
    if (vap->va_mode != (mode_t)VNOVAL) {
        if (VTOVFS(vp)->mnt_flag & MNT_RDONLY) {
            result = EROFS;
            goto Err_Exit;
        };
        result = synthfs_chmod(vp, (int)vap->va_mode, cred, p);
    };

Err_Exit: ;

    DBG_VOP(("synthfs_setattr: returning %d...\n", result));

    return (result);
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

int
synthfs_rename(ap)
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
	if (target_vp && ((VTOS(target_vp)->s_pflags & (IMMUTABLE | APPEND)) ||
					  (VTOS(targetPar_vp)->s_pflags & APPEND))) {
		retval = EPERM;
		goto abortit;
	}

	if ((retval = vn_lock(source_vp, LK_EXCLUSIVE, p)))
		goto abortit;

	sourcePar_sp = VTOS(sourcePar_vp);
	source_sp = VTOS(source_vp);
	oldparent = sourcePar_sp->s_nodeid;
	if ((source_sp->s_pflags & (IMMUTABLE | APPEND)) || (sourcePar_sp->s_pflags & APPEND)) {
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
	if (source_sp->s_type == SYNTHFS_DIRECTORY) {
		if ((source_cnp->cn_namelen == 1 && source_cnp->cn_nameptr[0] == '.')
			|| sourcePar_sp == source_sp
			|| (source_cnp->cn_flags & ISDOTDOT)
			|| (source_sp->s_nodeflags & IN_RENAME)) {
			VOP_UNLOCK(source_vp, 0, p);
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

    retval = VOP_ACCESS(source_vp, VWRITE, target_cnp->cn_cred, target_cnp->cn_proc);
    if (doingdirectory && (newparent != oldparent)) {
        if (retval)		/* write access check above */
            goto bad;
    }

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
        if ((targetPar_sp->s_mode & S_ISTXT) && target_cnp->cn_cred->cr_uid != 0 &&
            target_cnp->cn_cred->cr_uid != targetPar_sp->s_uid &&
            target_sp->s_uid != target_cnp->cn_cred->cr_uid) {
            retval = EPERM;
            goto bad;
        }

		/*
		 * VOP_REMOVE will vput targetPar_vp so we better bump 
		 * its ref count and relockit, always set target_vp to
		 * NULL afterwards to indicate that were done with it.
		 */
		VREF(targetPar_vp);
#if RWSUPPORT
        if (target_vp->v_type == VREG) {
            (void) vnode_uncache(target_vp);
        };
#endif
        cache_purge(target_vp);
            
		target_cnp->cn_flags &= ~SAVENAME;
		retval = VOP_REMOVE(targetPar_vp, target_vp, target_cnp);
		(void) vn_lock(targetPar_vp, LK_EXCLUSIVE | LK_RETRY, p);

		target_vp = NULL;
		target_sp = NULL;		
		
		if (retval) goto bad;
	};


	if (newparent != oldparent)
		vn_lock(sourcePar_vp, LK_EXCLUSIVE | LK_RETRY, p);

	/* remove the existing entry from the namei cache: */
	if (source_vp->v_type == VREG) cache_purge(source_vp);

	retval = synthfs_move_rename_entry( source_vp, targetPar_vp, target_cnp->cn_nameptr);

	if (newparent != oldparent)
		VOP_UNLOCK(sourcePar_vp, 0, p);

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
	tv = time;
	SYNTHFSTIMES(targetPar_sp, &tv, &tv);
	SYNTHFSTIMES(sourcePar_sp, &tv, &tv);

	vput(targetPar_vp);
	vrele(sourcePar_vp);
	vput(source_vp);

	return (retval);

bad:;
	if (retval && doingdirectory)
		source_sp->s_nodeflags &= ~IN_RENAME;

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

     We are responsible for freeing the namei buffer, it is done in synthfs_makenode(), unless there is
    a previous error.

*/

int
synthfs_mkdir(ap)
struct vop_mkdir_args /* {
    struct vnode *a_dvp;
    struct vnode **a_vpp;
    struct componentname *a_cnp;
    struct vattr *a_vap;
} */ *ap;
{
	int retval;
	struct vnode *dvp = ap->a_dvp;
	struct componentname *cnp = ap->a_cnp;
	int mode = MAKEIMODE(ap->a_vap->va_type, ap->a_vap->va_mode);
	struct vnode *vp = NULL;

    *ap->a_vpp = NULL;

    retval = synthfs_new_directory(VTOVFS(dvp), dvp, cnp->cn_nameptr, VTOSFS(dvp)->synthfs_nextid++, mode, ap->a_cnp->cn_proc, &vp);
    if (retval) goto Error_Exit;

    retval = VOP_SETATTR(vp, ap->a_vap, cnp->cn_cred, cnp->cn_proc);
    if (retval != 0) goto Error_Exit;

    *ap->a_vpp = vp;

Error_Exit:;
    if (retval != 0) {
        if (vp) synthfs_remove_directory(vp);
        VOP_ABORTOP(dvp, cnp);
    }
    vput(dvp);

	return retval;
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
synthfs_remove(ap)
struct vop_remove_args /* {
    struct vnode *a_dvp;
    struct vnode *a_vp;
    struct componentname *a_cnp;
} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct vnode *dvp = ap->a_dvp;
	struct synthfsnode *sp = VTOS(vp);
    struct timeval tv;
	int retval = 0;

	if ((sp->s_flags & (IMMUTABLE | APPEND)) ||
		(VTOS(dvp)->s_flags & APPEND)) {
		retval = EPERM;
		goto out;
	};
	
	/* This is sort of silly right now but someday it may make sense... */
	if (sp->s_nodeflags & IN_MODIFIED) {
        tv = time;
		VOP_UPDATE(vp, &tv, &tv, 0);
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

	if (dvp == vp) {
		vrele(vp);
	} else {
		vput(vp);
	};

	vput(dvp);
	return (retval);
}



/*
#% rmdir	dvp	L U U
#% rmdir	vp	L U U
#
 vop_rmdir {
     IN WILLRELE struct vnode *dvp;
     IN WILLRELE struct vnode *vp;
     IN struct componentname *cnp;

     */

int
synthfs_rmdir(ap)
    struct vop_rmdir_args /* {
    	struct vnode *a_dvp;
    	struct vnode *a_vp;
        struct componentname *a_cnp;
} */ *ap;
{
    DBG_VOP(("synthfs_rmdir called\n"));
	return synthfs_remove((struct vop_remove_args *)ap);
}



/*
 * synthfs_select - just say OK.  Only possible op is readdir
 *
 * Locking policy: ignore
 */
int
synthfs_select(ap)
struct vop_select_args /* {
    struct vnode *a_vp;
    int  a_which;
    int  a_fflags;
    struct ucred *a_cred;
    struct proc *a_p;
} */ *ap;
{
    DBG_VOP(("synthfs_select called\n"));

    return (1);
}

/*
#
#% symlink	dvp	L U U
#% symlink	vpp	- U -
#
# XXX - note that the return vnode has already been vrele'ed
#	by the filesystem layer.  To use it you must use vget,
#	possibly with a further namei.
#
 vop_symlink {
     IN WILLRELE struct vnode *dvp;
     OUT WILLRELE struct vnode **vpp;
     IN struct componentname *cnp;
     IN struct vattr *vap;
     IN char *target;

     We are responsible for freeing the namei buffer, it is done in synthfs_makenode(), unless there is
    a previous error.


*/

int
synthfs_symlink(ap)
    struct vop_symlink_args /* {
        struct vnode *a_dvp;
        struct vnode **a_vpp;
        struct componentname *a_cnp;
        struct vattr *a_vap;
        char *a_target;
    } */ *ap;
{
    struct vnode *dvp = ap->a_dvp;
    struct vnode **vpp = ap->a_vpp;
    struct componentname *cnp = ap->a_cnp;
    int retval;

    *vpp = NULL;

    retval = synthfs_new_symlink(VTOVFS(dvp), dvp, cnp->cn_nameptr, VTOSFS(dvp)->synthfs_nextid++, ap->a_target, ap->a_cnp->cn_proc, vpp);
    if (retval) goto Error_Exit;

    VOP_UNLOCK(*vpp, 0, cnp->cn_proc);

Error_Exit:;

    if (retval != 0) {
        VOP_ABORTOP(dvp, cnp);
    }
    vput(dvp);

    return (retval);
}



/*
#
#% readlink	vp	L L L
#
 vop_readlink {
     IN struct vnode *vp;
     INOUT struct uio *uio;
     IN struct ucred *cred;
     */

int
synthfs_readlink(ap)
struct vop_readlink_args /* {
	struct vnode *a_vp;
	struct uio *a_uio;
	struct ucred *a_cred;
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

    if (uio->uio_offset + uio->uio_resid <= sp->s_u.s.s_length) {
    	count = uio->uio_resid;
    } else {
    	count = sp->s_u.s.s_length - uio->uio_offset;
    };
    retval = uiomove((void *)((unsigned char *)sp->s_u.s.s_symlinktarget + uio->uio_offset), count, uio);
    return (retval);

}






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


int
synthfs_readdir(ap)
struct vop_readdir_args /* {
    struct vnode *vp;
    struct uio *uio;
    struct ucred *cred;
    int *eofflag;
    int *ncookies;
    u_long **cookies;
} */ *ap;
{
    struct synthfsnode *sp = VTOS(ap->a_vp);
    register struct uio *uio = ap->a_uio;
    off_t diroffset;						/* Offset into simulated directory file */
    struct synthfsnode *entry;

    DBG_VOP(("\tuio_offset = %d, uio_resid = %d\n", (int) uio->uio_offset, uio->uio_resid));
	
	/* We assume it's all one big buffer... */
    if (uio->uio_iovcnt > 1) {
    	DBG_VOP(("\tuio->uio_iovcnt = %d?\n", uio->uio_iovcnt));
    	return EINVAL;
    };

	/*
		NFS cookies are not supported:
	 */
	if ((ap->a_cookies != NULL) || (ap->a_ncookies != NULL)) {
		return EINVAL;
	};
	
 	diroffset = 0;
 	
    /*
     * We must synthesize . and ..
     */
    DBG_VOP(("\tstarting ... uio_offset = %d, uio_resid = %d\n", (int) uio->uio_offset, uio->uio_resid));
    if (uio->uio_offset == diroffset)
      {
        DBG_VOP(("\tAdding .\n"));
		diroffset += synthfs_adddirentry(sp->s_nodeid, DT_DIR, ".", uio);
        DBG_VOP(("\t   after adding ., uio_offset = %d, uio_resid = %d\n", (int) uio->uio_offset, uio->uio_resid));
      }
    if ((uio->uio_resid > 0) && (diroffset > uio->uio_offset)) {
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
        DBG_VOP(("\t   after adding .., uio_offset = %d, uio_resid = %d\n", (int) uio->uio_offset, uio->uio_resid));
      }
    if ((uio->uio_resid > 0) && (diroffset > uio->uio_offset)) {
    	/* Oops - we skipped over a partial entry: at best, diroffset should've just matched uio->uio_offset */
		return EINVAL;
	};

	/* OK, so much for the fakes.  Now for the "real thing": */
	TAILQ_FOREACH(entry, &sp->s_u.d.d_subnodes, s_sibling) {
		if (diroffset == uio->uio_offset) {
			/* Return this entry */
			diroffset += synthfs_adddirentry(entry->s_nodeid, VTTOIF(STOV(entry)->v_type), entry->s_name, uio);
		};
    	if ((uio->uio_resid > 0) && (diroffset > uio->uio_offset)) {
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
	struct vop_cachedlookup_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
	} */ *ap;
{
    struct vnode *dp = ap->a_dvp;
    struct componentname *cnp = ap->a_cnp;
    u_long nameiop = cnp->cn_nameiop;
    u_long flags = cnp->cn_flags;
    boolean_t lockparent = (flags & LOCKPARENT);
    struct proc *p = cnp->cn_proc;
    struct ucred *cred = cnp->cn_cred;
    struct vnode *target_vp = NULL;
    u_int32_t target_vnode_id;					/* Capability ID of the target vnode for .. unlock/relock handling check */
    struct vnode **vpp = ap->a_vpp;
    int result = 0;

    DBG_VOP(("synthfs_cached_lookup called, name = %s, namelen = %ld\n", ap->a_cnp->cn_nameptr, ap->a_cnp->cn_namelen));
    if (flags & LOCKPARENT) DBG_VOP(("\tLOCKPARENT is set\n"));
    if (flags & ISLASTCN) DBG_VOP(("\tISLASTCN is set\n"));

    *vpp = NULL;

    if (dp->v_type != VDIR) {
        result = ENOTDIR;
        goto Err_Exit;
    };

	if ((flags & ISLASTCN) &&
		(VTOVFS(dp)->mnt_flag & MNT_RDONLY) &&
		((nameiop == DELETE) || (nameiop == RENAME))) {
		result = EROFS;
		goto Err_Exit;
	};
	
	result = VOP_ACCESS(dp, VEXEC, cred, cnp->cn_proc);
	if (result != 0) goto Err_Exit;
	
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
	

	target_vp = *vpp;
	target_vnode_id = target_vp->v_id;
	if (target_vp == dp) {
		/* lookup on "." */
		VREF(target_vp);
		result = 0;
	} else if (flags & ISDOTDOT) {
		/*
		 * Carefully now: trying to step from child to parent;
		 * must release lock on child before trying to lock parent
		 * vnode.
		 */
		VOP_UNLOCK(dp, 0, p);
		result = vget(target_vp, LK_EXCLUSIVE, p);
		if ((result == 0) && lockparent && (flags & ISLASTCN)) {
			result = vn_lock(dp, LK_EXCLUSIVE, p);
		}
	} else {
		result = vget(target_vp, LK_EXCLUSIVE, p);
		if (!lockparent || (result != 0) || !(flags & ISLASTCN)) {
			VOP_UNLOCK(dp, 0, p);
		};
	};
	
	/*
	   Check to make sure the target vnode ID didn't change while we
	   tried to lock it:
	 */
	 if (result == 0) {
	 	if (target_vnode_id == target_vp->v_id) {
	 		return 0;					/* THIS IS THE NORMAL EXIT PATH */
	 	};
	 	
	 	/* The vnode ID didn't match anymore: we've got another vnode! */
	 	vput(target_vp);
	 	/* Unlock the parent vnode in the cases where it should've been left locked: */
	 	if (lockparent && (dp != target_vp) && (flags & ISLASTCN)) {
	 		VOP_UNLOCK(dp, 0, p);
	 	};
	 };
	 
	 /* One last try for a successful lookup through the complete lookup path: */
	 result = vn_lock(dp, LK_EXCLUSIVE, p);
	 if (result == 0) {
	 	return synthfs_lookup(ap);
	 };
	
Err_Exit:;
   return result;
}



int
synthfs_lookup(ap)
	struct vop_cachedlookup_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
	} */ *ap;
{
    struct vnode *dp = ap->a_dvp;
    struct synthfsnode *dsp = VTOS(dp);
    struct componentname *cnp = ap->a_cnp;
    u_long nameiop = cnp->cn_nameiop;
//  char *nameptr = cnp->cn_nameptr;
    u_long flags = cnp->cn_flags;
    long namelen = cnp->cn_namelen;
    struct proc *p = cnp->cn_proc;
    struct ucred *cred = cnp->cn_cred;
    struct synthfsnode *entry;
    struct vnode *target_vp = NULL;
    int result = 0;
    boolean_t found = FALSE;
    boolean_t isDot = FALSE;
    boolean_t isDotDot = FALSE;
	struct vnode *starting_parent = dp;
	
    DBG_VOP(("synthfs_lookup called, name = %s, namelen = %ld\n", ap->a_cnp->cn_nameptr, ap->a_cnp->cn_namelen));
    if (flags & LOCKPARENT) DBG_VOP(("\tLOCKPARENT is set\n"));
    if (flags & ISLASTCN) DBG_VOP(("\tISLASTCN is set\n"));

    *ap->a_vpp = NULL;

    if (dp->v_type != VDIR) {
        result = ENOTDIR;
        goto Err_Exit;
    };

	if ((flags & ISLASTCN) &&
		(VTOVFS(dp)->mnt_flag & MNT_RDONLY) &&
		((nameiop == DELETE) || (nameiop == RENAME))) {
		result = EROFS;
		goto Err_Exit;
	};
	
	result = VOP_ACCESS(dp, VEXEC, cred, cnp->cn_proc);
	if (result != 0) goto Err_Exit;
	
	/* first check for "." and ".." */
	if (cnp->cn_nameptr[0] == '.') {
		if (namelen == 1) {
			/*
			   "." requested
			 */
            isDot = TRUE;
            found = TRUE;

            target_vp = dp;
            VREF(target_vp);
            
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
                 * starting from the target_vp trying to vget() this directory.
                 */
                VOP_UNLOCK(dp, 0, p);
                result = vget(target_vp, LK_EXCLUSIVE | LK_RETRY, p);
                if (result != 0) {
                    vn_lock(dp, LK_EXCLUSIVE | LK_RETRY, p);
                    goto Err_Exit;
                }
                if ((flags & LOCKPARENT) && (flags & ISLASTCN)) {
                    result = vn_lock(dp, LK_EXCLUSIVE, p);
                    // vput(target_vp);		/* XXX WHY WAS THIS HERE? */
                }
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
            result = vget(target_vp, LK_EXCLUSIVE | LK_RETRY, p);		/* vget is not really needed because refcount is always > 0... */
			if (result != 0) {
                vrele(target_vp);
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
             * Deleting entries requires write access:
             */
            result = VOP_ACCESS(dp, VWRITE, cred, p);
            if (result != 0) goto Err_Exit;

            /*
             * If the parent directory is "sticky" then the user must own
             * the directory, or the file in it, in order to be allowed to
             * delete it (unless the user is root).  This implements
             * append-only directories
             */
            if ((dsp->s_mode & S_ISVTX) &&
                (cred->cr_uid != 0) &&
                (cred->cr_uid != dsp->s_uid) &&
                (target_vp != NULL) &&
                (target_vp->v_type != VLNK) &&
                (VTOS(target_vp)->s_uid != cred->cr_uid)) {
                vput(target_vp);
                result = EPERM;
                goto Err_Exit;
            };
        };

        if ((nameiop == RENAME) && (flags & WANTPARENT) && (flags * ISLASTCN)) {
        	result = VOP_ACCESS(dp, VWRITE, cred, p);
            if (result != 0) goto Err_Exit;

            if (isDot) {
                vrele(target_vp);
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
            /* Write access is required to create entries in the directory: */
            result = VOP_ACCESS(dp, VWRITE, cred, p);
            if (result != 0) goto Err_Exit;

			cnp->cn_flags |= SAVENAME;
			
            result = EJUSTRETURN;
        }
    };

    /* XXX PPD Should we do something special in case LOCKLEAF isn't set? */
    if (found && !isDot && !isDotDot && (!(flags & LOCKPARENT) || !(flags & ISLASTCN))) {
        VOP_UNLOCK(dp, 0, p);
    };
    
    *ap->a_vpp = target_vp;

Err_Exit:;
	DBG_VOP(("synthfs_lookup: result = %d.\n", result));
	if (found) {
		if (target_vp) {
			if (VOP_ISLOCKED(target_vp)) {
				DBG_VOP(("synthfs_lookup: target_vp = 0x%08X (locked).\n", (u_long)target_vp));
			} else {
				DBG_VOP(("synthfs_lookup: target_vp = 0x%08X (NOT locked?).\n", (u_long)target_vp));
			};
		} else {
			DBG_VOP(("synthfs_lookup: found = true but target_vp = NULL?\n"));
		};
	} else {
		DBG_VOP(("synthf_lookup: target not found.\n"));
	};
	if (VOP_ISLOCKED(starting_parent)) {
		DBG_VOP(("synthfs_lookup: dp = %08X; starting_parent = 0x%08X (LOCKED).\n", (u_long)dp, (u_long)starting_parent));
	} else {
		DBG_VOP(("synthfs_lookup: dp = %08X; starting_parent = 0x%08X (UNLOCKED).\n", (u_long)dp, (u_long)starting_parent));
	};
	
   return result;
}



/*

#% pathconf	vp	L L L
#
 vop_pathconf {
     IN struct vnode *vp;
     IN int name;
     OUT register_t *retval;
*/
int
synthfs_pathconf(ap)
struct vop_pathconf_args /* {
    struct vnode *a_vp;
    int a_name;
    int *a_retval;
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
/*
#% update	vp	L L L
	IN struct vnode *vp;
	IN struct timeval *access;
	IN struct timeval *modify;
	IN int waitfor;
*/

int
synthfs_update(ap)
	struct vop_update_args /* {
		struct vnode *a_vp;
		struct timeval *a_access;
		struct timeval *a_modify;
		int a_waitfor;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct synthfsnode *sp = VTOS(vp);

	DBG_ASSERT(sp != NULL);
	DBG_ASSERT(*((int*)&vp->v_interlock) == 0);

	if (((sp->s_nodeflags & (IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE)) != 0) &&
		!(VTOVFS(ap->a_vp)->mnt_flag & MNT_RDONLY)) {
		if (sp->s_nodeflags & IN_ACCESS) sp->s_accesstime = *ap->a_access;
		if (sp->s_nodeflags & IN_UPDATE) sp->s_modificationtime = *ap->a_modify;
		if (sp->s_nodeflags & IN_CHANGE) sp->s_changetime = time;
	};
	
	/* After the updates are finished, clear the flags */
	sp->s_nodeflags &= ~(IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE);

//  DBG_ASSERT(*((int*)&ap->a_vp->v_interlock) == 0);
	return 0;
}



/*******************************************************************************************

	Utility/housekeeping vnode operations:
	
 ******************************************************************************************/


/*
#% lock		vp	U L U
#
 vop_lock {
     IN struct vnode *vp;
     IN int flags;
     IN struct proc *p;
*/

int
synthfs_lock(ap)
struct vop_lock_args /* {
    struct vnode *a_vp;
    int a_flags;
    struct proc *a_p;
} */ *ap;
{
    return lockmgr(&VTOS(ap->a_vp)->s_lock, ap->a_flags, &ap->a_vp->v_interlock, ap->a_p);
}

/*
 * Unlock an synthfsnode.
#% unlock	vp	L U L
#
 vop_unlock {
     IN struct vnode *vp;
     IN int flags;
     IN struct proc *p;

     */
int
synthfs_unlock(ap)
struct vop_unlock_args /* {
    struct vnode *a_vp;
    int a_flags;
    struct proc *a_p;
} */ *ap;
{
    return lockmgr(&VTOS(ap->a_vp)->s_lock, ap->a_flags | LK_RELEASE, &ap->a_vp->v_interlock, ap->a_p);
}

/*
 * Check for a locked synthfsnode.
#% islocked	vp	= = =
#
 vop_islocked {
     IN struct vnode *vp;

     */
int
synthfs_islocked(ap)
struct vop_islocked_args /* {
    struct vnode *a_vp;
} */ *ap;
{
    return lockstatus(&VTOS(ap->a_vp)->s_lock);
}



/*
#
#% inactive	vp	L U U
#
 vop_inactive {
     IN struct vnode *vp;
     IN struct proc *p;

*/

int
synthfs_inactive(ap)
struct vop_inactive_args /* {
    struct vnode *a_vp;
    struct proc *a_p;
} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct proc *p = ap->a_p;
	struct synthfsnode *sp = VTOS(vp);
	struct timeval tv;

	if (vp->v_usecount != 0)
        DBG_VOP(("synthfs_inactive: bad usecount = %d\n", vp->v_usecount ));

	/*
	 * Ignore nodes related to stale file handles.
	 */
	if (vp->v_type == VNON)
		goto out;
	
	/* This is sort of silly but might make sense in the future: */
	if (sp->s_nodeflags & (IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE)) {
		tv = time;
		VOP_UPDATE(vp, &tv, &tv, 0);
	}

out:
	VOP_UNLOCK(vp, 0, p);
	/*
	 * If we are done with the inode, reclaim it
	 * so that it can be reused immediately.
	 */
	if (vp->v_type == VNON) {
		vrecycle(vp, (struct slock *)0, p);
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
    struct vop_reclaim_args /* { struct vnode *a_vp; struct proc *a_p; } */ *ap;
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
