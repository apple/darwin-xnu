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
 *	  2/10/2000     Clark Warner    Added copyfile	
 *	  5/24/1999	Don Brady	Fixed security hole in get_fsvnode.
 *	 11/18/1998 Don Brady		Special case 2 to mean the root of a file system.
 *	  9/28/1998	Umesh Vaishampayan	Use the default vnode ops. Cleanup 
 *									header includes.
 *	11/12/1998	Scott Roberts	validfsnode only checks to see if the volfs mount flag is set
 *	  8/5/1998	Don Brady	fix validfsnode logic to handle a "bad" VFS_GET
 *	  7/5/1998	Don Brady	In volfs_reclaim set vp->v_data to NULL after private data is free (VFS expects a NULL).
 *	  4/5/1998	Don Brady	Changed lockstatus calls to VOP_ISLOCKED (radar #2231108);
 *	 3/25/1998	Pat Dirks	Added include for sys/attr.h, which is no longer included indirectly.
 */

#include <mach/mach_types.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/resourcevar.h>
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

#include "volfs.h"

/*
 * volfs acts as a bridge between the requirements of the MacOS API and the Unix API.
 * MacOS applications describe files by a <Volume ID><Directory ID><File Name> triple.
 * The Unix API describes files by pathname.  Volfs is a virtual file system that sits over
 * the HFS VFS interface and allows files to be described by a <Volume ID>/<Directory ID>/<File Name>
 * pathname.
 *
 * The root of the volfs filesystem consists of directories named the volume ID's of all the
 * currently mounted filesystems which support the VFS vget() routine.  Each of those directories
 * supports the lookup by file ID of all files and directories within the filesystem.  When a
 * file or directory is resolved its vnode from that filesystem rather than a volfs vnode is returned
 * allowing immediate access to the target file or directory.
 *
 * Readdir on the root of the volfs filesystem returns the list of available file systems.  Readdir
 * on a filesystem node, however, returns only . and .. since it is not practical to list all
 * of the file ID's in a timely fashion and furthermore VFS does not provide a mechanism for
 * enumerating all of the file id's.
 *
 * Volume ID's are taken from the low 32 bits of the f_fsid field, formatted as a base 10 ASCII
 * string with no leading zeros (volume ID 1 is represented as "1").
 *
 * File ID's are created in same manner, with their 32 bits formatted as a base 10 ASCII
 * string with no leading zeros.
 *
 * Volfs does create a security hole since it is possible to bypass directory permissions higher
 * in the namespace tree.  This security hole is about the same as the one created by NFS which uses
 * a similar mechanism.
 */

#define VOPFUNC int (*)(void *)

/* Global vfs data structures for volfs. */
int                 (**volfs_vnodeop_p) (void *);
struct vnodeopv_entry_desc volfs_vnodeop_entries[] = {
    {&vop_default_desc, (VOPFUNC)vn_default_error},
    {&vop_strategy_desc, (VOPFUNC)err_strategy},	/* strategy */
    {&vop_bwrite_desc, (VOPFUNC)err_bwrite},		/* bwrite */
    {&vop_lookup_desc, (VOPFUNC)volfs_lookup},		/* lookup */
    {&vop_create_desc, (VOPFUNC)err_create},		/* create */
    {&vop_whiteout_desc, (VOPFUNC)err_whiteout},	/* whiteout */
    {&vop_mknod_desc, (VOPFUNC)err_mknod},		/* mknod */
    {&vop_mkcomplex_desc, (VOPFUNC)err_mkcomplex},	/* mkcomplex */
    {&vop_open_desc, (VOPFUNC)nop_open},		/* open */
    {&vop_close_desc, (VOPFUNC)nop_close},		/* close */
    {&vop_access_desc, (VOPFUNC)volfs_access},		/* access */
    {&vop_getattr_desc, (VOPFUNC)volfs_getattr},	/* getattr */
    {&vop_setattr_desc, (VOPFUNC)err_setattr},		/* setattr */
    {&vop_getattrlist_desc, (VOPFUNC)err_getattrlist},	/* getattrlist */
    {&vop_setattrlist_desc, (VOPFUNC)err_setattrlist},	/* setattrlist */
    {&vop_read_desc, (VOPFUNC)err_read},		/* read */
    {&vop_write_desc, (VOPFUNC)err_write},		/* write */
    {&vop_lease_desc, (VOPFUNC)err_lease},		/* lease */
    {&vop_ioctl_desc, (VOPFUNC)err_ioctl},		/* ioctl */
    {&vop_select_desc, (VOPFUNC)volfs_select},		/* select */
    {&vop_exchange_desc, (VOPFUNC)err_exchange},	/* exchange */
    {&vop_revoke_desc, (VOPFUNC)nop_revoke},		/* revoke */
    {&vop_mmap_desc, (VOPFUNC)err_mmap},		/* mmap */
    {&vop_fsync_desc, (VOPFUNC)err_fsync},		/* fsync */
    {&vop_seek_desc, (VOPFUNC)nop_seek},		/* seek */
    {&vop_remove_desc, (VOPFUNC)err_remove},		/* remove */
    {&vop_link_desc, (VOPFUNC)err_link},		/* link */
    {&vop_rename_desc, (VOPFUNC)err_rename},		/* rename */
    {&vop_mkdir_desc, (VOPFUNC)err_mkdir},		/* mkdir */
    {&vop_rmdir_desc, (VOPFUNC)volfs_rmdir},		/* rmdir */
    {&vop_symlink_desc, (VOPFUNC)err_symlink},		/* symlink */
    {&vop_readdir_desc, (VOPFUNC)volfs_readdir},	/* readdir */
    {&vop_readdirattr_desc, (VOPFUNC)err_readdirattr},	/* readdirattr */
    {&vop_readlink_desc, (VOPFUNC)err_readlink},	/* readlink */
    {&vop_abortop_desc, (VOPFUNC)err_abortop},		/* abortop */
    {&vop_inactive_desc, (VOPFUNC)err_inactive},	/* inactive */
    {&vop_reclaim_desc, (VOPFUNC)volfs_reclaim},	/* reclaim */
    {&vop_lock_desc, (VOPFUNC)volfs_lock},		/* lock */
    {&vop_unlock_desc, (VOPFUNC)volfs_unlock},		/* unlock */
    {&vop_bmap_desc, (VOPFUNC)err_bmap},		/* bmap */
    {&vop_print_desc, (VOPFUNC)err_print},		/* print */
    {&vop_islocked_desc, (VOPFUNC)volfs_islocked},	/* islocked */
    {&vop_pathconf_desc, (VOPFUNC)volfs_pathconf},	/* pathconf */
    {&vop_advlock_desc, (VOPFUNC)err_advlock},		/* advlock */
    {&vop_blkatoff_desc, (VOPFUNC)err_blkatoff},	/* blkatoff */
    {&vop_valloc_desc, (VOPFUNC)err_valloc},		/* valloc */
    {&vop_reallocblks_desc, (VOPFUNC)err_reallocblks},	/* reallocblks */
    {&vop_vfree_desc, (VOPFUNC)err_vfree},		/* vfree */
    {&vop_truncate_desc, (VOPFUNC)err_truncate},	/* truncate */
    {&vop_allocate_desc, (VOPFUNC)err_allocate},	/* allocate */
    {&vop_update_desc, (VOPFUNC)err_update},		/* update */
	{&vop_pgrd_desc, (VOPFUNC)err_pgrd},		/* pgrd */
	{&vop_pgwr_desc, (VOPFUNC)err_pgwr},		/* pgwr */
	{&vop_pagein_desc, (VOPFUNC)err_pagein},	/* pagein */
	{&vop_pageout_desc, (VOPFUNC)err_pageout},	/* pageout */
	{&vop_devblocksize_desc, (VOPFUNC)err_devblocksize},	/* devblocksize */
	{&vop_searchfs_desc, (VOPFUNC)err_searchfs},	/* searchfs */
        {&vop_copyfile_desc, (VOPFUNC)err_copyfile },	/* Copyfile */
	{&vop_blktooff_desc, (VOPFUNC)err_blktooff},	/* blktooff */
	{&vop_offtoblk_desc, (VOPFUNC)err_offtoblk },	/* offtoblk */
 	{&vop_cmap_desc, (VOPFUNC)err_cmap },		/* cmap */
   {(struct vnodeop_desc *) NULL, (int (*) ()) NULL}
};

/*
 * Oh what a tangled web we weave.  This structure will be used by
 * bsd/vfs/vfs_conf.c to actually do the initialization of volfs_vnodeop_p
 */
struct vnodeopv_desc volfs_vnodeop_opv_desc =
{&volfs_vnodeop_p, volfs_vnodeop_entries};


static int validfsnode(struct mount *fsnode);

#if DBG_VOP_TEST_LOCKS
static void DbgVopTest (int max, int error, VopDbgStoreRec *VopDbgStore, char *funcname);
#endif /* DBG_VOP_TEST_LOCKS */


/*
 * volfs_reclaim - Reclaim a vnode so that it can be used for other purposes.
 *
 * Locking policy: ignored
 */
int
volfs_reclaim(ap)
    struct vop_reclaim_args /* { struct vnode *a_vp; struct proc *a_p; } */ *ap;
{
    struct vnode *vp = ap->a_vp;
    void *data = vp->v_data;

    DBG_FUNC_NAME("volfs_reclaim");
    DBG_VOP_LOCKS_DECL(1);
    DBG_VOP_PRINT_FUNCNAME();DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP(("\n"));

    DBG_VOP_LOCKS_INIT(0, vp, VOPDBG_UNLOCKED, VOPDBG_IGNORE, VOPDBG_IGNORE, VOPDBG_ZERO);

	vp->v_data = NULL;
    FREE(data, M_VOLFSNODE);

    DBG_VOP_LOCKS_TEST(0);
    return (0);
}

/*
 * volfs_access - same access policy for all vnodes and all users (file/directory vnodes
 * 		for the actual file systems are handled by actual file system)
 *
 * Locking policy: a_vp locked on input and output
 */
int
volfs_access(ap)
    struct vop_access_args	/* { struct vnode *a_vp; int  a_mode; struct
        ucred *a_cred; struct proc *a_p; } */ *ap;
{
    int 	ret_err;
    DBG_FUNC_NAME("volfs_access");
    DBG_VOP_LOCKS_DECL(1);
    DBG_VOP_PRINT_FUNCNAME();DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP(("\n"));

    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_POS);

    /*
     * We don't need to check credentials!  FS is read-only for everyone
     */
    if (ap->a_mode == VREAD || ap->a_mode == VEXEC)
        ret_err = 0;
    else
        ret_err = EACCES;

    DBG_VOP_LOCKS_TEST(ret_err);
    return (ret_err);
}

/*
 * volfs_getattr - fill in the attributes for this vnode
 *
 * Locking policy: don't change anything
 */
int
volfs_getattr(ap)
    struct vop_getattr_args	/* { struct vnode *a_vp; struct vattr *a_vap;
        struct ucred *a_cred; struct proc *a_p; } */ *ap;
{
    struct volfs_vndata *priv_data;
    struct vnode       *a_vp;
    struct vattr       *a_vap;
    int                 numMounts = 0;
    DBG_FUNC_NAME("volfs_getattr");
    DBG_VOP_LOCKS_DECL(1);
    DBG_VOP_PRINT_FUNCNAME();DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP(("\n"));

    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_SAME, VOPDBG_SAME, VOPDBG_SAME, VOPDBG_POS);

    a_vp = ap->a_vp;
    a_vap = ap->a_vap;

    priv_data = a_vp->v_data;

    a_vap->va_type = VDIR;
    a_vap->va_mode = 0444;	/* Yup, hard - coded to read - only */
    a_vap->va_nlink = 2;
    a_vap->va_uid = 0;		/* Always owned by root */
    a_vap->va_gid = 0;		/* Always part of group 0 */
    a_vap->va_fsid = (int) a_vp->v_mount->mnt_stat.f_fsid.val[0];
    a_vap->va_fileid = priv_data->nodeID;

    /*
     * If it's the root vnode calculate its size based on the number of eligible
     * file systems
     */
    if (priv_data->vnode_type == VOLFS_ROOT)
      {
        register struct mount *mp, *nmp;

        simple_lock(&mountlist_slock);
        for (mp = mountlist.cqh_first; mp != (void *)&mountlist; mp = nmp) {
            if (vfs_busy(mp, LK_NOWAIT, &mountlist_slock, ap->a_p)) {
                nmp = mp->mnt_list.cqe_next;
                continue;
            }

            if (mp != a_vp->v_mount && validfsnode(mp))
                numMounts++;

            simple_lock(&mountlist_slock);
            nmp = mp->mnt_list.cqe_next;
            vfs_unbusy(mp, ap->a_p);
        }
        simple_unlock(&mountlist_slock);

        DBG_VOP(("found %d file systems that volfs can support\n", numMounts));
        a_vap->va_size = (numMounts + 2) * VLFSDIRENTLEN;
      }
    else
      {
        a_vap->va_size = 2 * VLFSDIRENTLEN;
      }
    DBG_VOP(("va_size = %d, VLFSDIRENTLEN = %ld\n", (int) a_vap->va_size, VLFSDIRENTLEN));
    a_vap->va_blocksize = 512;

    a_vap->va_atime.tv_sec = boottime.tv_sec;
    a_vap->va_atime.tv_nsec = 0;

    a_vap->va_mtime.tv_sec = boottime.tv_sec;
    a_vap->va_mtime.tv_nsec = 0;

    a_vap->va_ctime.tv_sec = boottime.tv_sec;
    a_vap->va_ctime.tv_nsec = 0;

    a_vap->va_gen = 0;
    a_vap->va_flags = 0;
    a_vap->va_rdev = 0;
    a_vap->va_bytes = a_vap->va_size;
    a_vap->va_filerev = 0;
    a_vap->va_vaflags = 0;

    DBG_VOP_LOCKS_TEST(0);
    return (0);
}

/*
 * volfs_select - just say OK.  Only possible op is readdir
 *
 * Locking policy: ignore
 */
int
volfs_select(ap)
    struct vop_select_args	/* { struct vnode *a_vp; int  a_which; int
				 * a_fflags; struct ucred *a_cred; void * a_wql; struct
        proc *a_p; } */ *ap;
{
    DBG_VOP(("volfs_select called\n"));

    return (1);
}

/*
 * vofls_rmdir - not possible to remove directories in volfs
 *
 * Locking policy: a_dvp & a_vp - locked on entry, unlocked on exit
 */
int
volfs_rmdir(ap)
    struct vop_rmdir_args	/* { struct vnode *a_dvp; struct vnode *a_vp;
        struct componentname *a_cnp; } */ *ap;
{
    DBG_VOP(("volfs_rmdir called\n"));
    if (ap->a_dvp == ap->a_vp) {
		(void) nop_rmdir(ap);
		return (EINVAL);
    } else
		return (err_rmdir(ap));
}

/*
 * volfs_readdir - Get directory entries
 *
 * Directory listings are only produced for the root volfs node.  Filesystems
 * just return . & ..
 * Filesystems contained within the volfs root are named by the decimal
 * equivalent of the f_fsid.val[0] from their mount structure (typically
 * the device id of the volume).  The maximum length for a name, then is
 * 10 characters.
 *
 * Locking policy: a_vp locked on entry and exit
 */
int
volfs_readdir(ap)
    struct vop_readdir_args	/* { struct vnode *a_vp; struct uio *a_uio;
				 * struct ucred *a_cred; int *a_eofflag; int
        *ncookies; u_long **a_cookies; } */ *ap;
{
    struct volfs_vndata *priv_data;
    register struct uio *uio = ap->a_uio;
    int                 error = 0;
    size_t              count, lost;
    int                 rec_offset;
    struct dirent       local_dir;
    int                 i;
    int					starting_resid;
    off_t               off;
    DBG_FUNC_NAME("volfs_readdir");
    DBG_VOP_LOCKS_DECL(1);

    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_LOCKED, VOPDBG_POS);
    DBG_VOP_PRINT_FUNCNAME();DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP(("\n"));

    DBG_VOP(("\tuio_offset = %d, uio_resid = %d\n", (int) uio->uio_offset, uio->uio_resid));
	/* We assume it's all one big buffer... */
    if (uio->uio_iovcnt > 1)
    	DBG_VOP(("\tuio->uio_iovcnt = %d?\n", uio->uio_iovcnt));

	off = uio->uio_offset;
    priv_data = ap->a_vp->v_data;
    starting_resid = uio->uio_resid;
    count = uio->uio_resid;
 
    /* Make sure we don't return partial entries. */
    count -= (uio->uio_offset + count) & (VLFSDIRENTLEN - 1);
    if (count <= 0)
		{
        DBG_VOP(("volfs_readdir: Not enough buffer to read in entries\n"));
        DBG_VOP_LOCKS_TEST(EINVAL);
        return (EINVAL);
		}
    /*
     * Make sure we're starting on a directory boundary
     */
    if (off & (VLFSDIRENTLEN - 1))
        {
        DBG_VOP_LOCKS_TEST(EINVAL);
        return (EINVAL);
        }
    rec_offset = off / VLFSDIRENTLEN;
    lost = uio->uio_resid - count;
    uio->uio_resid = count;
    uio->uio_iov->iov_len = count;

    local_dir.d_reclen = VLFSDIRENTLEN;
    /*
     * We must synthesize . and ..
     */
    DBG_VOP(("\tstarting ... uio_offset = %d, uio_resid = %d\n",
            (int) uio->uio_offset, uio->uio_resid));
    if (rec_offset == 0)
      {
        DBG_VOP(("\tAdding .\n"));
        /*
         * Synthesize .
         */
        local_dir.d_fileno = priv_data->nodeID;
        local_dir.d_type = DT_DIR;
        local_dir.d_namlen = 1;
        local_dir.d_name[0] = '.';
        for (i = 1; i < MAXVLFSNAMLEN; i++)
            local_dir.d_name[i] = 0;
        error = uiomove((char *) &local_dir, VLFSDIRENTLEN, uio);
        DBG_VOP(("\t   after adding ., uio_offset = %d, uio_resid = %d\n",
                (int) uio->uio_offset, uio->uio_resid));
        rec_offset++;
      }
    if (rec_offset == 1)
      {
        DBG_VOP(("\tAdding ..\n"));
        /*
         * Synthesize ..
         * We only have two levels in the volfs hierarchy.  Root's
         * .. points to itself and the second level points to root,
         * hence we've hardcoded d_fileno for .. here
         */
        local_dir.d_fileno = ROOT_DIRID;
        local_dir.d_type = DT_DIR;
        local_dir.d_namlen = 2;
        local_dir.d_name[0] = '.';
        local_dir.d_name[1] = '.';
        for (i = 2; i < MAXVLFSNAMLEN; i++)
            local_dir.d_name[i] = 0;
        error = uiomove((char *) &local_dir, VLFSDIRENTLEN, uio);
        rec_offset++;
        DBG_VOP(("\t   after adding .., uio_offset = %d, uio_resid = %d\n",
                (int) uio->uio_offset, uio->uio_resid));
      }

    /*
     * OK, we've given them the . & .. entries.  If this is a
     * filesystem node then we've gone as far as we're going
     * to go
     */
    if (priv_data->vnode_type == VOLFS_FSNODE)
        {
        *ap->a_eofflag = 1;	/* we got all the way to the end */
        DBG_VOP_LOCKS_TEST(error);
        return (error);
        }

    if (rec_offset > 1) {
        register struct mount *mp, *nmp;
        int					validnodeindex;
        struct proc 		*p = uio->uio_procp;

        validnodeindex = 1;	/* we always have "." and ".." */

        simple_lock(&mountlist_slock);
        for (mp = mountlist.cqh_first; mp != (void *)&mountlist; mp = nmp) {
            if (vfs_busy(mp, LK_NOWAIT, &mountlist_slock, p)) {
                nmp = mp->mnt_list.cqe_next;
                continue;
            }

            if (mp != ap->a_vp->v_mount && validfsnode(mp))
                validnodeindex++;

            if (rec_offset == validnodeindex)
              {
                local_dir.d_fileno = mp->mnt_stat.f_fsid.val[0];
                local_dir.d_type = DT_DIR;
                local_dir.d_reclen = VLFSDIRENTLEN;
                DBG_VOP(("\tAdding dir entry %d for offset %d\n", mp->mnt_stat.f_fsid.val[0], rec_offset));
                local_dir.d_namlen = sprintf(&local_dir.d_name[0], "%d", mp->mnt_stat.f_fsid.val[0]);
                error = uiomove((char *) &local_dir, VLFSDIRENTLEN, uio);
                DBG_VOP(("\t   after adding entry '%s', uio_offset = %d, uio_resid = %d\n",
                         &local_dir.d_name[0], (int) uio->uio_offset, uio->uio_resid));
                rec_offset++;
              }

            simple_lock(&mountlist_slock);
            nmp = mp->mnt_list.cqe_next;
            vfs_unbusy(mp, p);
        }
        simple_unlock(&mountlist_slock);

        if (mp == (void *) &mountlist)
            *ap->a_eofflag = 1;	/* we got all the way to the end */
    }

    uio->uio_resid += lost;
    if (starting_resid == uio->uio_resid)
        uio->uio_offset = 0;

    DBG_VOP(("\tExiting, uio_offset = %d, uio_resid = %d, ap->a_eofflag = %d\n",
            (int) uio->uio_offset, uio->uio_resid, *ap->a_eofflag));

    DBG_VOP_LOCKS_TEST(error);
    return (error);
}


/*
 * validfsnode - test to see if a file system supports VGET
 *
 * This can cause context switching, so caller should be lock safe
 */
static int
validfsnode(struct mount *fsnode)
{

	/*
	 * Just check to see if the the mount flag is set, if it is we assume the
	 * file system supports all of volfs symantecs
	 */

    if ((! (fsnode->mnt_kern_flag & MNTK_UNMOUNT)) && (fsnode->mnt_flag & MNT_DOVOLFS))
		return 1;
	else 
		return 0;
}

/*
 * volfs_lock - Lock an inode.
 * If its already locked, set the WANT bit and sleep.
 *
 * Locking policy: handled by lockmgr
 */
int
volfs_lock(ap)
    struct vop_lock_args	/* { struct vnode *a_vp; int a_flags; struct
        proc *a_p; } */ *ap;
{
    int                 retval;
    struct volfs_vndata *priv_data;
    DBG_FUNC_NAME("volfs_lock");
    DBG_VOP_LOCKS_DECL(1);
    DBG_VOP_PRINT_FUNCNAME();DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP(("\n"));

    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_UNLOCKED, VOPDBG_LOCKED, VOPDBG_UNLOCKED, VOPDBG_ZERO);

    priv_data = (struct volfs_vndata *) ap->a_vp->v_data;
    retval = lockmgr(&priv_data->lock, ap->a_flags, &ap->a_vp->v_interlock, ap->a_p);
    DBG_VOP_LOCKS_TEST(retval);
    return (retval);
}

/*
 * volfs_unlock - Unlock an inode.
 *
 * Locking policy: handled by lockmgr
 */
int
volfs_unlock(ap)
    struct vop_unlock_args	/* { struct vnode *a_vp; int a_flags; struct
        proc *a_p; } */ *ap;
{
    int                 retval;
    struct volfs_vndata *priv_data;
    DBG_FUNC_NAME("volfs_unlock");
    DBG_VOP_LOCKS_DECL(1);
    DBG_VOP_PRINT_FUNCNAME();DBG_VOP_PRINT_VNODE_INFO(ap->a_vp);DBG_VOP(("\n"));

    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_LOCKED, VOPDBG_UNLOCKED, VOPDBG_LOCKED, VOPDBG_ZERO);

    priv_data = (struct volfs_vndata *) ap->a_vp->v_data;
    retval = lockmgr(&priv_data->lock, ap->a_flags | LK_RELEASE,
		     &ap->a_vp->v_interlock, ap->a_p);

    DBG_VOP_LOCKS_TEST(retval);
    return (retval);
}

/*
 * volfs_islocked - Check for a locked inode.
 *
 * Locking policy: ignore
 */
int
volfs_islocked(ap)
    struct vop_islocked_args /* { struct vnode *a_vp; } */ *ap;
{
    int                 retval;
    struct volfs_vndata *priv_data;

    DBG_FUNC_NAME("volfs_islocked");
    DBG_VOP_LOCKS_DECL(1);
    //DBG_VOP_PRINT_FUNCNAME();DBG_VOP(("\n"));

    DBG_VOP_LOCKS_INIT(0,ap->a_vp, VOPDBG_IGNORE, VOPDBG_IGNORE, VOPDBG_IGNORE, VOPDBG_ZERO);
    priv_data = (struct volfs_vndata *) ap->a_vp->v_data;
    retval = lockstatus(&priv_data->lock);

    DBG_VOP_LOCKS_TEST(retval);
    return (retval);
}

/*
 * volfs_pathconf - Return POSIX pathconf information applicable to ufs filesystems.
 *
 * Locking policy: a_vp locked on input and output
 */
int
volfs_pathconf(ap)
    struct vop_pathconf_args	/* { struct vnode *a_vp; int a_name; int
        *a_retval; } */ *ap;
{
    DBG_VOP(("volfs_pathconf called\n"));

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
 * get_fsvnode - internal routine to create a vnode for a file system.  Called with mount pointer,
 *   id of filesystem to lookup and pointer to vnode pointer to fill in
 */
static int
get_fsvnode(our_mount, id, ret_vnode)
    struct mount       *our_mount;
    int id;
    struct vnode      **ret_vnode;
{
    register struct mount *mp;
    struct mount       *cur_mount;
    struct vnode       *cur_vnode;
    struct volfs_vndata *cur_privdata;
	int					retval;

    //DBG_VOP(("volfs: get_fsvnode called\n"));

    /*
     * OK, first look up the matching mount on the list of mounted file systems
     */
    cur_mount = NULL;
    simple_lock(&mountlist_slock);
    for (mp = mountlist.cqh_first; mp != (void *)&mountlist; mp = mp->mnt_list.cqe_next)
      {
        if (validfsnode(mp) && mp->mnt_stat.f_fsid.val[0] == id)
          {
            cur_mount = mp;
            break;
          }
      }
    simple_unlock(&mountlist_slock);

    if (cur_mount == NULL) {
        /*
         * No mounted file system by the specified ID currently exists in the system.
         *
         * XXX We could deal with a vnode that is still hanging about for an FS that
         * does not exists or has been unmounted now, or count on the update below
         * to happen later...
         */
        *ret_vnode = NULL;
        return ENOENT;
    };

    /*
     * Now search the list attached to the mount structure to
     * see if this vnode is already floating around
     */
search_vnodelist:
    cur_vnode = our_mount->mnt_vnodelist.lh_first;
    while (cur_vnode != NULL)
      {
        cur_privdata = (struct volfs_vndata *) cur_vnode->v_data;
        if (cur_privdata->nodeID == id)
            {
            if (cur_privdata->fs_mount != cur_mount) {
                DBG_VOP(("volfs get_fsvnode: Updating fs_mount for vnode 0x%08lX (id = %d) from 0x%08lX to 0x%08lX...\n",
                         (unsigned long)cur_vnode,
                         cur_privdata->nodeID,
                         (unsigned long)cur_privdata->fs_mount,
                         (unsigned long)cur_mount));
                cur_privdata->fs_mount = cur_mount;
            };
            break;
            }
        cur_vnode = cur_vnode->v_mntvnodes.le_next;
      }

    //DBG_VOP(("\tfinal cur_mount: 0x%x\n",cur_mount));
    if (cur_vnode) {
        /* If vget returns an error, cur_vnode will not be what we think it is, try again */
        if (vget(cur_vnode, LK_EXCLUSIVE, current_proc()) != 0) {
            goto search_vnodelist;
        };
        }
    else
      {
        MALLOC(cur_privdata, struct volfs_vndata *,
               sizeof(struct volfs_vndata), M_VOLFSNODE, M_WAITOK);
        retval = getnewvnode(VT_VOLFS, our_mount, volfs_vnodeop_p, &cur_vnode);
        if (retval != 0) {
            FREE(cur_privdata, M_VOLFSNODE);
            return retval;
        };
			
        cur_privdata->vnode_type = VOLFS_FSNODE;
        cur_privdata->nodeID = id;

        cur_privdata->fs_mount = cur_mount;
        lockinit(&cur_privdata->lock, PINOD, "volfsnode", 0, 0);
        lockmgr(&cur_privdata->lock, LK_EXCLUSIVE, (struct slock *)0, current_proc());
        cur_vnode->v_data = cur_privdata;
        cur_vnode->v_type = VDIR;
        DBG_VOP(("get_fsvnode returned with new node of "));
        DBG_VOP_PRINT_VNODE_INFO(cur_vnode);DBG_VOP(("\n"));
      }

    *ret_vnode = cur_vnode;

    return (0);
}



/*
 * get_filevnode - returns the vnode for the given id within a filesystem.  The parent vnode
 * 	   is a filesystem, id is the 32-bit id of the file/directory and ret_vnode is a pointer
 *		to a vnode pointer
 */
static int
get_filevnode(parent_fs, id, ret_vnode)
    struct mount      	*parent_fs;
    u_int 				id;
    struct vnode     	**ret_vnode;
{
    int                 retval;

    DBG_VOP(("get_filevnode called for ID %d\n", id));

	/*
	 * Special case 2 to mean the root of a file system
	 */
	if (id == 2)
		retval = VFS_ROOT(parent_fs, ret_vnode);
	else
    	retval = VFS_VGET(parent_fs, &id, ret_vnode);

    return (retval);
}


int
volfs_lookup(ap)
    struct vop_lookup_args	/* { struct vnode *a_dvp; struct vnode
        **a_vpp; struct componentname *a_cnp; } */ *ap;
{
    struct volfs_vndata *priv_data;
    char				*cnp;
    long				namelen;
    struct mount		*parent_fs;
    int					unlocked_parent = 0;
    int                 ret_err = ENOENT;
    DBG_FUNC_NAME("volfs_lookup");
    DBG_VOP_LOCKS_DECL(2);

    DBG_VOP(("volfs_lookup called, name = %s, namelen = %ld\n", ap->a_cnp->cn_nameptr, ap->a_cnp->cn_namelen));

    DBG_VOP_LOCKS_INIT(0,ap->a_dvp, VOPDBG_LOCKED, VOPDBG_IGNORE, VOPDBG_IGNORE, VOPDBG_POS);
    DBG_VOP_LOCKS_INIT(1,*ap->a_vpp, VOPDBG_IGNORE, VOPDBG_LOCKED, VOPDBG_IGNORE, VOPDBG_POS);
    DBG_VOP_PRINT_FUNCNAME();DBG_VOP(("\n"));
    DBG_VOP(("\t"));DBG_VOP_PRINT_CPN_INFO(ap->a_cnp);DBG_VOP(("\n"));
	if (ap->a_cnp->cn_flags & LOCKPARENT)
		DBG_VOP(("\tLOCKPARENT is set\n"));
	if (ap->a_cnp->cn_flags & ISLASTCN)
		{
		DBG_VOP(("\tISLASTCN is set\n"));
		if (ap->a_cnp->cn_nameiop == DELETE || ap->a_cnp->cn_nameiop == RENAME)		/* XXX PPD Shouldn't we check for CREATE, too? */
			{
			ret_err = EROFS;
			goto Err_Exit;
			}
		}
	priv_data = ap->a_dvp->v_data;
	cnp = ap->a_cnp->cn_nameptr;
	namelen = ap->a_cnp->cn_namelen;
	
#if VOLFS_DEBUG
    switch (priv_data->vnode_type) {
        case VOLFS_ROOT:
            DBG_VOP(("\tparent directory (vnode 0x%08lX) vnode_type is VOLFS_ROOT.\n", (unsigned long)ap->a_dvp));
            break;

        case VOLFS_FSNODE:
            DBG_VOP(("\tparent directory (vnode 0x%08lX) vnode_type is VOLFS_FSNODE, nodeID = %d, fs_mount = 0x%08lX.\n",
                     (unsigned long)ap->a_dvp,
                     priv_data->nodeID,
                     (unsigned long)priv_data->fs_mount));

        default:
            DBG_VOP(("\tparent directory (vnode 0x%08lX) has unknown vnode_type (%d), nodeID = %d.\n",
                     (unsigned long)ap->a_dvp,
                     priv_data->vnode_type,
                     priv_data->nodeID));
    };
#endif	/* VOLFS_DEBUG */

	/* first check for "." and ".." */
	if (cnp[0] == '.')
	{
		if (namelen == 1)
		{
			/* "." requested */
		    *ap->a_vpp = ap->a_dvp;
		    VREF(*ap->a_vpp);
            DBG_VOP_LOCKS_TEST(0);
            return (0);
		}
		else if (cnp[1] == '.' && namelen == 2)	
		{
			/* ".." requested */
			ret_err = volfs_root(ap->a_dvp->v_mount, ap->a_vpp);
		}
	}

	/* then look for special file system root symbol ('@') */
	else if (cnp[0] == '@')
	{
		if ((namelen == 1) && (priv_data->vnode_type != VOLFS_ROOT)) {
			parent_fs = priv_data->fs_mount;
			if (!(ap->a_cnp->cn_flags & LOCKPARENT) || !(ap->a_cnp->cn_flags & ISLASTCN)) {
				VOP_UNLOCK(ap->a_dvp, 0, ap->a_cnp->cn_proc);
				unlocked_parent = 1;
			};
			ret_err = VFS_ROOT(parent_fs, ap->a_vpp);
        } else {
            DBG_VOP(("volfs_lookup: pathname = '@' but namelen = %ld and parent vnode_type = %d.\n", namelen, priv_data->vnode_type));
            *ap->a_vpp = NULL;
            ret_err = ENOENT;
        };
	}

	/* finally, just look for numeric ids... */
	else if (namelen <= 10 && cnp[0] > '0' && cnp[0] <= '9') /* 10 digits max lead digit must be 1 - 9 */
	{
		char	*check_ptr;
		u_long	id;

		id = strtoul(cnp, &check_ptr, 10);

    	/*
		 * strtol will leave us at the first non-numeric character.
		 * we've checked to make sure the component name does
		 * begin with a numeric so check_ptr must wind up on
		 * the terminating null or there was other junk following the
		 * number
		 */
		if ((check_ptr - cnp) == namelen)
		{
		    if (priv_data->vnode_type == VOLFS_ROOT)
				ret_err = get_fsvnode(ap->a_dvp->v_mount, id, ap->a_vpp);
		    else {
		    	parent_fs = priv_data->fs_mount;
				if (!(ap->a_cnp->cn_flags & LOCKPARENT) || !(ap->a_cnp->cn_flags & ISLASTCN)) {
					VOP_UNLOCK(ap->a_dvp, 0, ap->a_cnp->cn_proc);
					unlocked_parent = 1;
				};
				ret_err = get_filevnode(parent_fs, id, ap->a_vpp);
			}
		}

	}

	if (!unlocked_parent && (!(ap->a_cnp->cn_flags & LOCKPARENT) || !(ap->a_cnp->cn_flags & ISLASTCN))) {
		VOP_UNLOCK(ap->a_dvp, 0, ap->a_cnp->cn_proc);
	};

	/* XXX PPD Should we do something special in case LOCKLEAF isn't set? */

Err_Exit:

	DBG_VOP_UPDATE_VP(1, *ap->a_vpp);
	DBG_VOP_LOCKS_TEST(ret_err);
    
    return (ret_err);
}

#if DBG_VOP_TEST_LOCKS

#if 0
static void DbgLookupTest(	char *funcname, struct componentname  *cnp, struct vnode *dvp, struct vnode *vp)
{
    int 		flags = cnp->cn_flags;
    int 		nameiop = cnp->cn_nameiop;

    DBG_VOP (("%s: Action:", funcname));
    switch (nameiop)
        {
        case LOOKUP:
            PRINTIT ("LOOKUP");
            break;
        case CREATE:
            PRINTIT ("CREATE");
            break;
        case DELETE:
            PRINTIT ("DELETE");
            break;
        case RENAME:
            PRINTIT ("RENAME");
            break;
        default:
            PRINTIT ("!!!UNKNOWN!!!!");
            break;
            }
    PRINTIT(" flags: 0x%x ",flags );
    if (flags & LOCKPARENT)
        PRINTIT (" Lock Parent");
    if (flags & ISLASTCN)
        PRINTIT (" Last Action");
    PRINTIT("\n");

    if (dvp)
        {
        PRINTIT ("%s: Parent vnode exited ", funcname);
    if (VOP_ISLOCKED(dvp))
            PRINTIT("LOCKED\n");
        else
            PRINTIT("UNLOCKED\n");
        }
    if (vp && vp==dvp)
        {
        PRINTIT ("%s: Found and Parent are the same\n", funcname);
        }
    else if (vp)
        {
        PRINTIT ("%s: Found vnode exited ", funcname);
    if (VOP_ISLOCKED(vp))
            PRINTIT("LOCKED\n");
        else
            PRINTIT("UNLOCKED\n");
        }
    else
        PRINTIT ("%s: Found vnode exited NULL\n", funcname);


}
#endif

static void DbgVopTest( int maxSlots,
                 int retval,
                 VopDbgStoreRec *VopDbgStore,
                 char *funcname)
{
    int index;

    for (index = 0; index < maxSlots; index++)
      {
        if (VopDbgStore[index].id != index) {
            PRINTIT("%s: DBG_VOP_LOCK: invalid id field (%d) in target entry (#%d).\n", funcname, VopDbgStore[index].id, index);
		return;
        };

        if ((VopDbgStore[index].vp != NULL) &&
            ((VopDbgStore[index].vp->v_data==NULL)))
            continue;

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
                      PRINTIT ("%s: InState check: Null vnode ptr in entry #%d\n", funcname, index);
                  } else if (VopDbgStore[index].vp != NULL) {
                      switch (VopDbgStore[index].inState)
                        {
                          case VOPDBG_LOCKED:
                          case VOPDBG_LOCKNOTNIL:
                              if (VopDbgStore[index].inValue == 0)
                                {
                                  PRINTIT ("%s: %d Entry: not LOCKED:", funcname, index); DBG_VOP(("\n"));
                                }
                              break;
                          case VOPDBG_UNLOCKED:
                              if (VopDbgStore[index].inValue != 0)
                                {
                                  PRINTIT ("%s: %d Entry: not UNLOCKED:", funcname, index); DBG_VOP(("\n"));
                                }
                              break;
                        }
                  }
                  break;
              }
            default:
                PRINTIT ("%s: DBG_VOP_LOCK on entry: bad lock test value: %d\n", funcname, VopDbgStore[index].errState);
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
                          PRINTIT ("%s: ErrState check: Null vnode ptr in entry #%d\n", funcname, index);
                      } else {
                          VopDbgStore[index].outValue = VOP_ISLOCKED(VopDbgStore[index].vp);
                          switch (VopDbgStore[index].errState)
                            {
                              case VOPDBG_LOCKED:
                                  if (VopDbgStore[index].outValue == 0)
                                    {
                                      PRINTIT ("%s: %d Error: not LOCKED:", funcname, index); DBG_VOP(("\n"));
                                    }
                                  break;
                              case VOPDBG_UNLOCKED:
                                  if (VopDbgStore[index].outValue != 0)
                                    {
                                      PRINTIT ("%s: %d Error: not UNLOCKED:", funcname, index); DBG_VOP(("\n"));
                                    }
                                  break;
                              case VOPDBG_SAME:
                                  if (VopDbgStore[index].outValue != VopDbgStore[index].inValue)
                                      PRINTIT ("%s: Error: In/Out locks are DIFFERENT: 0x%x, inis %d and out is %d\n", funcname, (u_int)VopDbgStore[index].vp, VopDbgStore[index].inValue, VopDbgStore[index].outValue);
                                  break;
                            }
                      }
                      break;
                  }
                case VOPDBG_LOCKNOTNIL:
                    if (VopDbgStore[index].vp != NULL) {
                    VopDbgStore[index].outValue = VOP_ISLOCKED(VopDbgStore[index].vp);
                        if (VopDbgStore[index].outValue == 0)
                            PRINTIT ("%s: Error: %d Not LOCKED: 0x%x\n", funcname, index, (u_int)VopDbgStore[index].vp);
                    }
                    break;
                default:
                    PRINTIT ("%s: Error: bad lock test value: %d\n", funcname, VopDbgStore[index].errState);
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
                        PRINTIT ("%s: OutState: Null vnode ptr in entry #%d\n", funcname, index);
                    };
                    if (VopDbgStore[index].vp != NULL)
                      {
                    VopDbgStore[index].outValue = VOP_ISLOCKED(VopDbgStore[index].vp);
                        switch (VopDbgStore[index].outState)
                          {
                            case VOPDBG_LOCKED:
                                if (VopDbgStore[index].outValue == 0)
                                  {
                                    PRINTIT ("%s: %d Out: not LOCKED:", funcname, index); DBG_VOP(("\n"));
                                  }
                                break;
                            case VOPDBG_UNLOCKED:
                                if (VopDbgStore[index].outValue != 0)
                                  {
                                    PRINTIT ("%s: %d Out: not UNLOCKED:", funcname, index); DBG_VOP(("\n"));
                                  }
                                break;
                            case VOPDBG_SAME:
                                if (VopDbgStore[index].outValue != VopDbgStore[index].inValue)
                                    PRINTIT ("%s: Out: In/Out locks are DIFFERENT: 0x%x, inis %d and out is %d\n", funcname, (u_int)VopDbgStore[index].vp, VopDbgStore[index].inValue, VopDbgStore[index].outValue);
                                break;
                          }
                      }
                    break;
                case VOPDBG_LOCKNOTNIL:
                    if (VopDbgStore[index].vp != NULL) {
                    if (&((struct volfs_vndata *)(VopDbgStore[index].vp->v_data))->lock == NULL)
                            PRINTIT ("%s: DBG_VOP_LOCK on out: Null lock on vnode 0x%x\n", funcname, (u_int)VopDbgStore[index].vp);
                        else {
                        VopDbgStore[index].outValue = VOP_ISLOCKED(VopDbgStore[index].vp);
                            if (VopDbgStore[index].outValue == 0)
                              {
                                PRINTIT ("%s: DBG_VOP_LOCK on out: Should be LOCKED:", funcname); DBG_VOP(("\n"));
                              }
                        }
                    }
                    break;
                default:
                    PRINTIT ("%s: DBG_VOP_LOCK on out: bad lock test value: %d\n", funcname, VopDbgStore[index].outState);
              }
          }

        VopDbgStore[index].id = -1;		/* Invalidate the entry to allow panic-free re-use */
      }	
}

#endif /* DBG_VOP_TEST_LOCKS */

