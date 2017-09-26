/*
 * Copyright (c) 2015 Apple Inc. All rights reserved.
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
#include <sys/kernel.h>
#include <sys/vnode_internal.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/mount_internal.h>
#include <sys/fcntl.h>
#include <sys/unistd.h>
#include <sys/malloc.h>
#include <vfs/vfs_support.h>

#include <libkern/OSAtomic.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

#include "routefs.h"

static int routefs_init(__unused struct vfsconf *vfsp);
static int routefs_mount(struct mount *mp, __unused vnode_t devvp, __unused user_addr_t data, vfs_context_t ctx);
static int routefs_start(__unused struct mount *mp, __unused int flags, __unused vfs_context_t ctx);
static int routefs_unmount( struct mount *mp, int mntflags, __unused vfs_context_t ctx);
static int routefs_root(struct mount *mp, struct vnode **vpp, __unused vfs_context_t ctx);
static int routefs_statfs( struct mount *mp, struct vfsstatfs *sbp, __unused vfs_context_t ctx);
static int routefs_vfs_getattr(__unused mount_t mp, struct vfs_attr *fsap, __unused vfs_context_t ctx);
static int routefs_sync(__unused struct mount *mp, __unused int waitfor, __unused vfs_context_t ctx);
static int routefs_vget(__unused struct mount *mp, __unused ino64_t ino, __unused struct vnode **vpp, __unused vfs_context_t ctx);
static int routefs_fhtovp (__unused struct mount *mp, __unused int fhlen, __unused unsigned char *fhp, __unused struct vnode **vpp, __unused vfs_context_t ctx);
static int routefs_vptofh (__unused struct vnode *vp, __unused int *fhlenp, __unused unsigned char *fhp, __unused vfs_context_t ctx);
static int routefs_sysctl(__unused int *name, __unused u_int namelen, __unused user_addr_t oldp,
                          __unused size_t *oldlenp, __unused user_addr_t newp,
                          __unused size_t newlen, __unused vfs_context_t ctx);
static int routefserr_lookup(__unused struct vnop_lookup_args * args);

static int routefserr_setlabel(__unused struct vnop_setlabel_args * args);


lck_grp_t       * routefs_lck_grp;
lck_grp_attr_t  * routefs_lck_grp_attr;
lck_attr_t      * routefs_lck_attr;
lck_mtx_t         routefs_mutex;

#define ROUTEFS_LOCK()    lck_mtx_lock(&routefs_mutex)
#define ROUTEFS_UNLOCK()  lck_mtx_unlock(&routefs_mutex)
static int _lock_inited = 0;
static boolean_t _fs_alreadyMounted = FALSE;  /* atleast a mount of this filesystem is present */

static int
routefs_init(__unused struct vfsconf *vfsp)
{
    routefs_lck_grp_attr = lck_grp_attr_alloc_init();
    routefs_lck_grp = lck_grp_alloc_init("routefs_lock", routefs_lck_grp_attr);
    routefs_lck_attr = lck_attr_alloc_init();
    lck_mtx_init(&routefs_mutex, routefs_lck_grp, routefs_lck_attr);
    _lock_inited = 1;
    
    return 0;
}

static int
routefs_mount(struct mount *mp, __unused vnode_t devvp,  user_addr_t data, vfs_context_t ctx)
{
    struct routefs_mount *routefs_mp_p = NULL;	/* routefs specific mount info */
	int error=EINVAL;
    struct routefs_args * rargs = (struct routefs_args *)data;
    
	/*-
	 *  If they just want to update, we don't need to do anything.
	 */
	if (mp->mnt_flag & MNT_UPDATE)
	{
		return 0;
	}

    
    /* check for root mount only */
    if ((error = proc_suser(current_proc()))!= 0) {
        goto out;
    }
        
    if (vfs_iskernelmount(mp) == FALSE) {
        error = EPERM;
        goto out;
    }
    
    if (_fs_alreadyMounted == TRUE) {
        /* if a filesystem is mounted, it needs to be unmounted prior to mount again */
        error = EPERM;
        goto out;
    }
    
	/* Advisory locking should be handled at the VFS layer */
	vfs_setlocklocal(mp);

	/*-
	 *  Well, it's not an update, it's a real mount request.
	 *  Time to get dirty.
	 * HERE we should check to see if we are already mounted here.
	 */

	MALLOC(routefs_mp_p, struct routefs_mount *, sizeof(struct routefs_mount),
	       M_TEMP, M_WAITOK);
	if (routefs_mp_p == NULL)
		return (ENOMEM);
	bzero(routefs_mp_p, sizeof(*routefs_mp_p));
    
	routefs_mp_p->route_mount = mp;

    if (rargs->route_rvp == NULLVP) {
        error = EACCES;
        goto out;
    }
        
    strlcpy(routefs_mp_p->route_path,rargs->route_path, MAXPATHLEN);
    routefs_mp_p->route_rvp = rargs->route_rvp;
    routefs_mp_p->route_vpvid = vnode_vid(rargs->route_rvp);
    
    if (vnode_ref(routefs_mp_p->route_rvp) != 0) {
        error = EACCES;
        goto out;
    }

    /*
	 *  Fill out some fields
	 */
	__IGNORE_WCASTALIGN(mp->mnt_data = (qaddr_t)routefs_mp_p);
	mp->mnt_vfsstat.f_fsid.val[0] = (int32_t)(uintptr_t)routefs_mp_p;
	mp->mnt_vfsstat.f_fsid.val[1] = vfs_typenum(mp);
	mp->mnt_flag |= MNT_LOCAL;

	/*-
	 *  Copy in the name of the directory the filesystem
	 *  is to be mounted on.
	 *  And we clear the remainder of the character strings
	 *  to be tidy.
	 */
	
	bzero(mp->mnt_vfsstat.f_mntfromname, MAXPATHLEN);
	bcopy("routefs",mp->mnt_vfsstat.f_mntfromname, 5);
	(void)routefs_statfs(mp, &mp->mnt_vfsstat, ctx);
    _fs_alreadyMounted = TRUE;      /* yep, fs is in play now */
	error = 0;
out:
    if (error != 0) {
        if (routefs_mp_p != NULL)
            FREE((caddr_t)routefs_mp_p, M_TEMP);
    }
	return error;
}


static int
routefs_start(__unused struct mount *mp, __unused int flags, __unused vfs_context_t ctx)
{
	return 0;
}

/*-
 *  Unmount the filesystem described by mp.
 */
static int
routefs_unmount( struct mount *mp, int mntflags, __unused vfs_context_t ctx)
{
	struct routefs_mount *routefs_mp_p = (struct routefs_mount *)mp->mnt_data;
	int flags = 0;
	int force = 0;
	int error;
	
    /* check for root unmount only */
    if ((error = proc_suser(current_proc()))!= 0) {
        return(error);
    }

	if (mntflags & MNT_FORCE) {
		flags |= FORCECLOSE;
		force = 1;
	}
    /* giveup the ioref of vnode, no longer need it */
    if (routefs_mp_p->route_rvp != NULLVP) {
        if (vnode_getwithref(routefs_mp_p->route_rvp) == 0) {
            vnode_rele(routefs_mp_p->route_rvp);
            vnode_put(routefs_mp_p->route_rvp);
            routefs_mp_p->route_rvp = NULLVP;
        }
    }
    /* no vnodes, ignore any errors */
    (void)vflush(mp, NULLVP, flags);
	FREE((caddr_t)routefs_mp_p, M_TEMP);
	mp->mnt_data = (qaddr_t)0;
	mp->mnt_flag &= ~MNT_LOCAL;
    _fs_alreadyMounted = FALSE; /* unmounted the fs, only one allowed at a time */
	return 0;
}

/* return the address of the root vnode  in *vpp */
static int
routefs_root(struct mount *mp, struct vnode **vpp, __unused vfs_context_t ctx)
{
	struct routefs_mount *routefs_mp_p = (struct routefs_mount *)(mp->mnt_data);
	int error=0;

    /* check for nullvp incase its being rolled */
    if (routefs_mp_p->route_rvp == NULLVP) {
        ROUTEFS_LOCK();
        if (routefs_mp_p->route_rvp == NULLVP) {
            ROUTEFS_UNLOCK();
            error = EACCES;
            goto out;
        }
        ROUTEFS_UNLOCK();
    }
    if (vnode_getwithvid(routefs_mp_p->route_rvp, routefs_mp_p->route_vpvid) != 0) {
        /* only one in the path., since no vnodes with this, you can hold across this call */
        ROUTEFS_LOCK();
        if (vnode_getwithref(routefs_mp_p->route_rvp) == 0) {
            vnode_rele(routefs_mp_p->route_rvp);
            vnode_put(routefs_mp_p->route_rvp);
            routefs_mp_p->route_rvp = NULLVP;
            routefs_mp_p->route_vpvid = -1;
            error = vnode_lookup(routefs_mp_p->route_path, FREAD|O_DIRECTORY, &routefs_mp_p->route_rvp, ctx);
            if (error == 0)
                routefs_mp_p->route_vpvid = vnode_vid(routefs_mp_p->route_rvp);
        } else {
            error = EACCES;
        }
        ROUTEFS_UNLOCK();
        
        if (error != 0)
        	goto out;
    }
    *vpp = routefs_mp_p->route_rvp;
out:
	return error;
}

static int
routefs_statfs( struct mount *mp, struct vfsstatfs *sbp, __unused vfs_context_t ctx)
{
	struct routefs_mount *routefs_mp_p = (struct routefs_mount *)mp->mnt_data;

	/*-
	 *  Fill in the stat block.
	 */
	//sbp->f_type   = mp->mnt_vfsstat.f_type;
	sbp->f_flags  = 0;		/* XXX */
	sbp->f_bsize  = 512;
	sbp->f_iosize = 512;
	sbp->f_blocks = (sizeof(struct routefs_mount)+ sbp->f_bsize) / sbp->f_bsize;
	sbp->f_bfree  = 0;
	sbp->f_bavail = 0;
	sbp->f_files  = 0;
	sbp->f_ffree  = 0;
	sbp->f_fsid.val[0] = (int32_t)(uintptr_t)routefs_mp_p;
	sbp->f_fsid.val[1] = vfs_typenum(mp);

	return 0;
}

static int
routefs_vfs_getattr(__unused mount_t mp, struct vfs_attr *fsap, __unused vfs_context_t ctx)
{
	VFSATTR_RETURN(fsap, f_objcount, 1);
	VFSATTR_RETURN(fsap, f_maxobjcount, 1);
	VFSATTR_RETURN(fsap, f_bsize, 512);
	VFSATTR_RETURN(fsap, f_iosize, 512);
	if (VFSATTR_IS_ACTIVE(fsap, f_blocks) || VFSATTR_IS_ACTIVE(fsap, f_bused)) {
		fsap->f_blocks = (sizeof(struct routefs_mount)+ fsap->f_bsize) / fsap->f_bsize;
		fsap->f_bused = fsap->f_blocks;
		VFSATTR_SET_SUPPORTED(fsap, f_blocks);
		VFSATTR_SET_SUPPORTED(fsap, f_bused);
	}
	VFSATTR_RETURN(fsap, f_bfree, 0);
	VFSATTR_RETURN(fsap, f_bavail, 0);
	VFSATTR_RETURN(fsap, f_files, 0);
	VFSATTR_RETURN(fsap, f_ffree, 0);
	VFSATTR_RETURN(fsap, f_fssubtype, 0);
	
	if (VFSATTR_IS_ACTIVE(fsap, f_capabilities)) {
		fsap->f_capabilities.capabilities[VOL_CAPABILITIES_FORMAT] =
			VOL_CAP_FMT_SYMBOLICLINKS |
			VOL_CAP_FMT_HARDLINKS |
			VOL_CAP_FMT_NO_ROOT_TIMES |
			VOL_CAP_FMT_CASE_SENSITIVE |
			VOL_CAP_FMT_CASE_PRESERVING |
			VOL_CAP_FMT_FAST_STATFS |
			VOL_CAP_FMT_2TB_FILESIZE |
			VOL_CAP_FMT_HIDDEN_FILES;
		fsap->f_capabilities.capabilities[VOL_CAPABILITIES_INTERFACES] =
			VOL_CAP_INT_ATTRLIST ;
		fsap->f_capabilities.capabilities[VOL_CAPABILITIES_RESERVED1] = 0;
		fsap->f_capabilities.capabilities[VOL_CAPABILITIES_RESERVED2] = 0;
		
		fsap->f_capabilities.valid[VOL_CAPABILITIES_FORMAT] =
			VOL_CAP_FMT_PERSISTENTOBJECTIDS |
			VOL_CAP_FMT_SYMBOLICLINKS |
			VOL_CAP_FMT_HARDLINKS |
			VOL_CAP_FMT_JOURNAL |
			VOL_CAP_FMT_JOURNAL_ACTIVE |
			VOL_CAP_FMT_NO_ROOT_TIMES |
			VOL_CAP_FMT_SPARSE_FILES |
			VOL_CAP_FMT_ZERO_RUNS |
			VOL_CAP_FMT_CASE_SENSITIVE |
			VOL_CAP_FMT_CASE_PRESERVING |
			VOL_CAP_FMT_FAST_STATFS |
			VOL_CAP_FMT_2TB_FILESIZE |
			VOL_CAP_FMT_OPENDENYMODES |
			VOL_CAP_FMT_HIDDEN_FILES |
			VOL_CAP_FMT_PATH_FROM_ID |
			VOL_CAP_FMT_NO_VOLUME_SIZES;
		fsap->f_capabilities.valid[VOL_CAPABILITIES_INTERFACES] =
			VOL_CAP_INT_SEARCHFS |
			VOL_CAP_INT_ATTRLIST |
			VOL_CAP_INT_NFSEXPORT |
			VOL_CAP_INT_READDIRATTR |
			VOL_CAP_INT_EXCHANGEDATA |
			VOL_CAP_INT_COPYFILE |
			VOL_CAP_INT_ALLOCATE |
			VOL_CAP_INT_VOL_RENAME |
			VOL_CAP_INT_ADVLOCK |
			VOL_CAP_INT_FLOCK |
			VOL_CAP_INT_EXTENDED_SECURITY |
			VOL_CAP_INT_USERACCESS |
			VOL_CAP_INT_MANLOCK |
			VOL_CAP_INT_EXTENDED_ATTR |
			VOL_CAP_INT_NAMEDSTREAMS;
		fsap->f_capabilities.valid[VOL_CAPABILITIES_RESERVED1] = 0;
		fsap->f_capabilities.valid[VOL_CAPABILITIES_RESERVED2] = 0;
		
		VFSATTR_SET_SUPPORTED(fsap, f_capabilities);
	}
	
	if (VFSATTR_IS_ACTIVE(fsap, f_attributes)) {
		fsap->f_attributes.validattr.commonattr =
			ATTR_CMN_NAME | ATTR_CMN_DEVID | ATTR_CMN_FSID |
			ATTR_CMN_OBJTYPE | ATTR_CMN_OBJTAG | ATTR_CMN_OBJID |
			ATTR_CMN_PAROBJID |
			ATTR_CMN_MODTIME | ATTR_CMN_CHGTIME | ATTR_CMN_ACCTIME |
			ATTR_CMN_OWNERID | ATTR_CMN_GRPID | ATTR_CMN_ACCESSMASK |
			ATTR_CMN_FLAGS | ATTR_CMN_USERACCESS | ATTR_CMN_FILEID;
		fsap->f_attributes.validattr.volattr =
			ATTR_VOL_FSTYPE | ATTR_VOL_SIZE | ATTR_VOL_SPACEFREE |
			ATTR_VOL_SPACEAVAIL | ATTR_VOL_MINALLOCATION |
			ATTR_VOL_OBJCOUNT | ATTR_VOL_MAXOBJCOUNT |
			ATTR_VOL_MOUNTPOINT | ATTR_VOL_MOUNTFLAGS |
			ATTR_VOL_MOUNTEDDEVICE | ATTR_VOL_CAPABILITIES |
			ATTR_VOL_ATTRIBUTES;
		fsap->f_attributes.validattr.dirattr =
			ATTR_DIR_LINKCOUNT | ATTR_DIR_MOUNTSTATUS;
		fsap->f_attributes.validattr.fileattr =
			ATTR_FILE_LINKCOUNT | ATTR_FILE_TOTALSIZE |
			ATTR_FILE_IOBLOCKSIZE | ATTR_FILE_DEVTYPE |
			ATTR_FILE_DATALENGTH;
		fsap->f_attributes.validattr.forkattr = 0;
		
		fsap->f_attributes.nativeattr.commonattr =
			ATTR_CMN_NAME | ATTR_CMN_DEVID | ATTR_CMN_FSID |
			ATTR_CMN_OBJTYPE | ATTR_CMN_OBJTAG | ATTR_CMN_OBJID |
			ATTR_CMN_PAROBJID |
			ATTR_CMN_MODTIME | ATTR_CMN_CHGTIME | ATTR_CMN_ACCTIME |
			ATTR_CMN_OWNERID | ATTR_CMN_GRPID | ATTR_CMN_ACCESSMASK |
			ATTR_CMN_FLAGS | ATTR_CMN_USERACCESS | ATTR_CMN_FILEID;
		fsap->f_attributes.nativeattr.volattr =
			ATTR_VOL_FSTYPE | ATTR_VOL_SIZE | ATTR_VOL_SPACEFREE |
			ATTR_VOL_SPACEAVAIL | ATTR_VOL_MINALLOCATION |
			ATTR_VOL_OBJCOUNT | ATTR_VOL_MAXOBJCOUNT |
			ATTR_VOL_MOUNTPOINT | ATTR_VOL_MOUNTFLAGS |
			ATTR_VOL_MOUNTEDDEVICE | ATTR_VOL_CAPABILITIES |
			ATTR_VOL_ATTRIBUTES;
		fsap->f_attributes.nativeattr.dirattr =
			ATTR_DIR_MOUNTSTATUS;
		fsap->f_attributes.nativeattr.fileattr =
			ATTR_FILE_LINKCOUNT | ATTR_FILE_TOTALSIZE |
			ATTR_FILE_IOBLOCKSIZE | ATTR_FILE_DEVTYPE |
			ATTR_FILE_DATALENGTH;
		fsap->f_attributes.nativeattr.forkattr = 0;

		VFSATTR_SET_SUPPORTED(fsap, f_attributes);
	}
	
	return 0;
}

static int
routefs_sync(__unused struct mount *mp, __unused int waitfor, __unused vfs_context_t ctx)
{
    return (0);
}


static int
routefs_vget(__unused struct mount *mp, __unused ino64_t ino, __unused struct vnode **vpp, __unused vfs_context_t ctx)
{
	return ENOTSUP;
}

static int
routefs_fhtovp (__unused struct mount *mp, __unused int fhlen, __unused unsigned char *fhp, __unused struct vnode **vpp, __unused vfs_context_t ctx)
{
	return (EINVAL);
}


static int
routefs_vptofh (__unused struct vnode *vp, __unused int *fhlenp, __unused unsigned char *fhp, __unused vfs_context_t ctx)
{
	return (EINVAL);
}

static int
routefs_sysctl(__unused int *name, __unused u_int namelen, __unused user_addr_t oldp,
             __unused size_t *oldlenp, __unused user_addr_t newp, 
             __unused size_t newlen, __unused vfs_context_t ctx)
{
    return (ENOTSUP);
}

#include <sys/namei.h>
#define MOBILE_DIR_PATH "/private/var/mobile"
/*
 * Function: routefs_kernel_mount
 * Purpose:
 *   Mount routefs at the given mount point from within the kernel.
 */
int
routefs_kernel_mount(char * routepath)
{
    int error = EINVAL;
	vfs_context_t ctx = vfs_context_kernel();
	char fsname[] = "routefs";
    struct routefs_args args;
    char mounthere[] = MOBILE_DIR_PATH;  /* !const because of internal casting */
    
    bzero(&args, sizeof(struct routefs_args));
    strlcpy(args.route_path, routepath, MAXPATHLEN);
    error = vnode_lookup(args.route_path, FREAD|O_DIRECTORY, &args.route_rvp, ctx);
    if (error) {
        goto out;
	}

    if (!vnode_isdir(args.route_rvp)) {
        error = EACCES;
        goto out;
    }

    error = kernel_mount(fsname, NULLVP, NULLVP, mounthere, &args, 0, MNT_DONTBROWSE, KERNEL_MOUNT_NOAUTH, ctx);
	if (error) {
		goto out;
	}

out:
    if(args.route_rvp != NULLVP)
        (void) vnode_put(args.route_rvp);
	return (error);
}

struct vfsops routefs_vfsops = {
	.vfs_mount = routefs_mount,
	.vfs_start = routefs_start,
	.vfs_unmount = routefs_unmount,
	.vfs_root = routefs_root,
	.vfs_getattr = routefs_vfs_getattr,
	.vfs_sync = routefs_sync,
	.vfs_vget = routefs_vget,
	.vfs_fhtovp = routefs_fhtovp,
	.vfs_vptofh = routefs_vptofh,
	.vfs_init = routefs_init,
	.vfs_sysctl = routefs_sysctl,
	// There are other VFS ops that we do not support
};

static int routefserr_lookup(__unused struct vnop_lookup_args * args)
{
    return (ENOTSUP);
}

static int routefserr_setlabel(__unused struct vnop_setlabel_args * args)
{
    return (ENOTSUP);
    
}

#define VOPFUNC int (*)(void *)

/* The following ops are used by directories and symlinks */
int (**routefs_vnodeop_p)(void *);
static struct vnodeopv_entry_desc routefs_vnodeop_entries[] = {
    { &vnop_default_desc, (VOPFUNC)vn_default_error },
    { &vnop_lookup_desc, (VOPFUNC)routefserr_lookup },		/* lookup */
    { &vnop_create_desc, (VOPFUNC)err_create },		/* create */
    { &vnop_whiteout_desc, (VOPFUNC)err_whiteout },		/* whiteout */
    { &vnop_mknod_desc, (VOPFUNC)err_mknod },		/* mknod */
    { &vnop_open_desc, (VOPFUNC)err_open },			/* open */
    { &vnop_close_desc, (VOPFUNC)err_close },		/* close */
    { &vnop_getattr_desc, (VOPFUNC)err_getattr },		/* getattr */
    { &vnop_setattr_desc, (VOPFUNC)err_setattr },		/* setattr */
    { &vnop_read_desc, (VOPFUNC)err_read },		/* read */
    { &vnop_write_desc, (VOPFUNC)err_write },		/* write */
    { &vnop_ioctl_desc, (VOPFUNC)err_ioctl },		/* ioctl */
    { &vnop_select_desc, (VOPFUNC)err_select },		/* select */
    { &vnop_revoke_desc, (VOPFUNC)err_revoke },		/* revoke */
    { &vnop_mmap_desc, (VOPFUNC)err_mmap },			/* mmap */
    { &vnop_fsync_desc, (VOPFUNC)nop_fsync },		/* fsync */
    { &vnop_remove_desc, (VOPFUNC)err_remove },	/* remove */
    { &vnop_link_desc, (VOPFUNC)err_link },		/* link */
    { &vnop_rename_desc, (VOPFUNC)err_rename },		/* rename */
    { &vnop_mkdir_desc, (VOPFUNC)err_mkdir },		/* mkdir */
    { &vnop_rmdir_desc, (VOPFUNC)err_rmdir },		/* rmdir */
    { &vnop_symlink_desc, (VOPFUNC)err_symlink },		/* symlink */
    { &vnop_readdir_desc, (VOPFUNC)err_readdir },		/* readdir */
    { &vnop_readlink_desc, (VOPFUNC)err_readlink },	/* readlink */
    { &vnop_inactive_desc, (VOPFUNC)err_inactive },	/* inactive */
    { &vnop_reclaim_desc, (VOPFUNC)err_reclaim },		/* reclaim */
    { &vnop_strategy_desc, (VOPFUNC)err_strategy },		/* strategy */
    { &vnop_pathconf_desc, (VOPFUNC)err_pathconf },	/* pathconf */
    { &vnop_advlock_desc, (VOPFUNC)err_advlock },		/* advlock */
    { &vnop_bwrite_desc, (VOPFUNC)err_bwrite },
    { &vnop_pagein_desc, (VOPFUNC)err_pagein },		/* Pagein */
    { &vnop_pageout_desc, (VOPFUNC)err_pageout },		/* Pageout */
    { &vnop_copyfile_desc, (VOPFUNC)err_copyfile },		/* Copyfile */
    { &vnop_blktooff_desc, (VOPFUNC)err_blktooff },		/* blktooff */
    { &vnop_offtoblk_desc, (VOPFUNC)err_offtoblk },		/* offtoblk */
    { &vnop_blockmap_desc, (VOPFUNC)err_blockmap },		/* blockmap */
#if CONFIG_MACF
    { &vnop_setlabel_desc, (VOPFUNC)routefserr_setlabel },       /* setlabel */
#endif
    { (struct vnodeop_desc*)NULL, (int(*)(void *))NULL }
};
struct vnodeopv_desc routefs_vnodeop_opv_desc =
{ &routefs_vnodeop_p, routefs_vnodeop_entries };



