/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/* Copyright (c) 1998 Apple Computer, Inc. All Rights Reserved */
/*
 * Change History:
 *
 *	17-Aug-1999	Pat Dirks	New today.
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/namei.h>
#include <sys/filedesc.h>
#include <sys/proc_internal.h>
#include <sys/kernel.h>
#include <mach/machine/vm_types.h>
#include <sys/vnode_internal.h>
#include <sys/socket.h>
#include <sys/mount_internal.h>
#include <sys/mbuf.h>
#include <sys/file.h>
#include <sys/disk.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/attr.h>
#include <sys/uio_internal.h>

#include <miscfs/specfs/specdev.h>

#include "synthfs.h"

#define LOADABLE_FS 0

typedef int (*PFI)();

struct vfsops synthfs_vfsops = {
	synthfs_mount,
	synthfs_start,
	synthfs_unmount,
	synthfs_root,
	NULL,				/* quotactl */
	synthfs_vfs_getattr,
	synthfs_sync,
	synthfs_vget,
	synthfs_fhtovp,
	synthfs_vptofh,
	synthfs_init,
	synthfs_sysctl
};

#define ROOTMPMODE 0755
#define ROOTPLACEHOLDERMODE 0700
static char synthfs_fs_name[MFSTYPENAMELEN] = "synthfs";
static char synthfs_fake_mntfromname[] = "<synthfs>";


extern struct vnodeopv_desc synthfs_vnodeop_opv_desc;

/* The following refer to kernel global variables used in the loading/initialization: */
extern int maxvfsslots;				/* Total number of slots in the system's vfsconf table */
extern int maxvfsconf;				/* The highest fs type number [old-style ID] in use [dispite its name] */
extern int vfs_opv_numops;			/* The total number of defined vnode operations */

int vn_mkdir(struct proc *p, char *path, int mode);
int vn_symlink(struct proc *p, char *path, char *link);




#if LOADABLE_FS
void
synthfs_load(int loadArgument) {
	/* Should use vfs_fsadd kpi */
}



int synthfs_unload(void) {

	/* should use fs_fsremove kpi */
    return 0;
}
#endif



/*
 * VFS Operations.
 *
 * mount system call
 */
int
synthfs_mount_fs(struct mount *mp, vnode_t devvp, __unused user_addr_t data,  struct proc *p)
{
	struct synthfs_mntdata *priv_mnt_data;
    int	error;
    size_t size;

	DBG_VOP(("synthfs_mount_fs called.\n"));
	MALLOC(priv_mnt_data, struct synthfs_mntdata *, sizeof(struct synthfs_mntdata), M_SYNTHFS, M_WAITOK);
	DBG_VOP(("MALLOC succeeded...\n"));

	strncpy(mp->mnt_vfsstat.f_fstypename, synthfs_fs_name, sizeof(mp->mnt_vfsstat.f_fstypename));
	strncpy(mp->mnt_vfsstat.f_mntfromname, synthfs_fake_mntfromname, sizeof(mp->mnt_vfsstat.f_mntfromname));
    priv_mnt_data->synthfs_mounteddev = (dev_t)0;
    priv_mnt_data->synthfs_nextid = FIRST_SYNTHFS_ID;
    priv_mnt_data->synthfs_filecount = 0;
    priv_mnt_data->synthfs_dircount = 0;
    priv_mnt_data->synthfs_encodingsused = 0x00000001;
	
	/*
	   Set up the root vnode for fast reference in the future.
	   Note that synthfs_new_directory() returns the vnode with a refcount of +2.
	   The root vnode's refcount is maintained unlocked but with a pos. ref count until unmount.
	 */
    error = synthfs_new_directory(mp, NULL, "", ROOT_DIRID, (S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH), p, &priv_mnt_data->synthfs_rootvp);
	if (error) {
		DBG_VOP(("Attempt to create root directory failed with error %d.\n", error));
		return error;
	};
	priv_mnt_data->synthfs_rootvp->v_flag |= VROOT;

	priv_mnt_data->synthfs_mp = mp;
	mp->mnt_data = (void *)priv_mnt_data;

    /* Drop the freshly acquired reference on the root, leaving v_usecount=1 to prevent
       the vnode from beeing freed: */
    vnode_put(priv_mnt_data->synthfs_rootvp);

    return (0);
}



int
synthfs_mount(mp, devvp, data, context)
	register struct mount *mp;
	vnode_t devvp;
	user_addr_t data;
	vfs_context_t context;
{
	size_t size;

	return (synthfs_mount_fs(mp, devvp, data, vfs_context_proc(context)));
}






/*
 * Initialize the filesystem
 */
int
synthfs_init(vfsp)
	struct vfsconf *vfsp;
{
	DBG_VOP(("synthfs_init called.\n"));
	return 0;
}

int
synthfs_start(mp, flags, context)
struct mount * mp;
int	flags;
vfs_context_t context;
{
    DBG_VOP(("synthfs_start called.\n"));
    return 0;
}

/*
 * Return the root of a filesystem.
 */
int
synthfs_root(mp, vpp, context)
        struct mount *mp;
        struct vnode **vpp;
        vfs_context_t context;
{
    unsigned long root_nodeid = ROOT_DIRID;

    DBG_VOP(("synthfs_root called.\n"));

	*vpp = VFSTOSFS(mp)->synthfs_rootvp;
	return vnode_get(VFSTOSFS(mp)->synthfs_rootvp);
}

/*
 * unmount system call
 */
int
synthfs_unmount(mp, mntflags, context)
	struct mount *mp;
	int mntflags;
	vfs_context_t context;
{
    struct synthfs_mntdata *synth;
    struct vnode *root_vp;
    int		retval;

    DBG_VOP(("synthfs_unmount called.\n"));
    synth = (struct synthfs_mntdata *)mp->mnt_data;

    root_vp = synth->synthfs_rootvp;
    retval = vflush(mp, root_vp, (mntflags & MNT_FORCE) ? FORCECLOSE : 0);
    if (retval && ((mntflags & MNT_FORCE) == 0)) goto Err_Exit;

    /* Free the root vnode.
       the ref. count has been maintained at +1 ever since mount time. */
    if (root_vp) {
        if ((mntflags & MNT_FORCE) == 0) {
			if (retval) goto Err_Exit;
        
	        if (root_vp->v_usecount > 1) {
	            DBG_VOP(("synthfs ERROR: root vnode = %x, usecount = %d\n", (int)root_vp, synth->synthfs_rootvp->v_usecount));
	            retval = EBUSY;
	            goto Err_Exit;
	        };
        };
        
        synth->synthfs_rootvp = NULL;
        
        if (retval == 0) {
        	vnode_get(root_vp);
        	vnode_rele(root_vp);
        	vnode_recycle(root_vp);
        	vnode_put(root_vp);			/* This drops synthfs's own refcount */
        };
    };

	/* All vnodes should be gone, and no errors, clean up the last */

    mp->mnt_data = NULL;
    FREE(synth, M_SYNTHFS);

Err_Exit:

	if (mntflags & MNT_FORCE) retval = 0;
	
    return(retval);
}

/*
 * Get file system statistics.
 */
int
synthfs_vfs_getattr(mount_t mp, struct vfs_attr *fsap, vfs_context_t context)
{
	struct synthfs_mntdata *synthfs_mp = VFSTOSFS(mp);
	DBG_VOP(("synthfs_vfs_getattr called.\n"));

	VFSATTR_RETURN(fsap, f_bsize, 512);
	VFSATTR_RETURN(fsap, f_iosize, 512);
	VFSATTR_RETURN(fsap, f_blocks, 1024);
	VFSATTR_RETURN(fsap, f_bfree, 0);
	VFSATTR_RETURN(fsap, f_bavail, 0);
	VFSATTR_RETURN(fsap, f_bused, 1024);
	VFSATTR_RETURN(fsap, f_files, synthfs_mp->synthfs_filecount + synthfs_mp->synthfs_dircount);
	VFSATTR_RETURN(fsap, f_ffree, 0);
	VFSATTR_RETURN(fsap, f_fssubtype, 0);

	return 0;
}

/*
 * synthfs doesn't have any data or backing store and you can't write into any of the synthfs 
 * structures, so don't do anything
 */
int
synthfs_sync(mp, waitfor, context)
	struct mount *mp;
	int waitfor;
	vfs_context_t context;
{
//	DBG_VOP(("synthfs_sync called\n"));
	return 0;
}
/*
 * Look up a synthfs node by node number.
 */
int
synthfs_vget(mp, ino, vpp, context)
	struct mount *mp;
	ino64_t ino;
	struct vnode **vpp;
	vfs_context_t context;
{
	struct vnode *vp;
	int	vid = 0;
	
//	DBG_VOP(("synthfs_vget called\n"));

	/* Check for unmount in progress */
	if (mp->mnt_kern_flag & MNTK_UNMOUNT) {
		*vpp = NULL;
		return (EPERM);
	}

loop:
	TAILQ_FOREACH(vp, &mp->mnt_vnodelist, v_mntvnodes) {
		if (VTOS(vp)->s_nodeid == (unsigned long)ino) {
		        /*
			 * doing a vnode_getwithvid isn't technically 
			 * necessary since synthfs is an unsafe filesystem
			 * and we're running behind a funnel at this point
			 * however, vnode_get always succeeds, which isn't
			 * what we want if this vnode is in the process of
			 * being terminated
			 */
		        vid = vnode_vid(vp);

			if (vnode_getwithvid(vp, vid) != 0) {
			        goto loop;
			};
			*vpp = vp;
			return 0;
		};
	};
	*vpp = NULL;
	return -1;
}

/*
 * fast filesystem related variables.
 */
int
synthfs_sysctl(int *name, u_int namelen, user_addr_t oldp, size_t *oldlenp, 
               user_addr_t newp, size_t newlen, vfs_context_t context)
{
	DBG_VOP(("synthfs_sysctl called.\n"));
	return (ENOTSUP);
}

/*
 * File handle to vnode
 *
 */
int
synthfs_fhtovp(mp, fhlen, fhp, vpp, context)
	register struct mount *mp;
	int fhlen;
	unsigned char *fhp;
	struct vnode **vpp;
	vfs_context_t context;
{
	DBG_VOP(("synthfs_fhtovp called.\n"));
    return ENOTSUP;
}

/*
 * Vnode pointer to File handle
 */
/* ARGSUSED */
int
synthfs_vptofh(vp, fhlenp, fhp, context)
	struct vnode *vp;
	int *fhlenp;
	unsigned char *fhp;
	vfs_context_t context;
{
	DBG_VOP(("synthfs_vptofh called.\n"));
    return ENOTSUP;
}






int
vn_mkdir(struct proc *p, char *path, int mode)
{
	struct nameidata nd;
	struct vnode *vp;
	struct vnode_attr va;
	struct vfs_context context;
	int error;

	context.vc_proc = p;
	context.vc_ucred = proc_ucred(p);	/* XXX kauth_cred_get() ??? proxy */

	NDINIT(&nd, CREATE, LOCKPARENT, UIO_SYSSPACE32, CAST_USER_ADDR_T(path), &context);
	error = namei(&nd);
	if (error) {
		DBG_VOP(("vn_mkdir: error from namei, error = %d.\n", error));
		return (error);
	};
	vp = nd.ni_vp;

	if (vp == NULL) {
		VATTR_INIT(&va);
		VATTR_SET(&va, va_type, VDIR);
		VATTR_SET(&va, va_mode, (mode & ACCESSPERMS) &~ p->p_fd->fd_cmask);

		error = vn_create(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, &va, 0, &context);
		if (error)
		        DBG_VOP(("vn_mkdir: error from vnop_mkdir (%d).\n", error));
	} else {
		DBG_VOP(("vn_mkdir: target already exists; returning EEXIST.\n"));
	        error = EEXIST;
	}
	vnode_put(nd.ni_dvp);
	if (nd.ni_vp)
	        vnode_put(nd.ni_vp);
	nameidone(&nd);

	return (error);
}



int
vn_symlink(struct proc *p, char *path, char *link) {
	struct nameidata nd;
	struct vnode_attr va;
	struct vfs_context context;
	int error;

	context.vc_proc = p;
	context.vc_ucred = proc_ucred(p);	/* XXX kauth_cred_get() ??? proxy */

	NDINIT(&nd, CREATE, LOCKPARENT, UIO_SYSSPACE32, CAST_USER_ADDR_T(link), &context);
	if ((error = namei(&nd))) return error;

	if (nd.ni_vp == NULL) {
		VATTR_INIT(&va);
		VATTR_SET(&va, va_type, VLNK);
		VATTR_SET(&va, va_mode, ACCESSPERMS &~ p->p_fd->fd_cmask);

		error = VNOP_SYMLINK(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, &va, path, &context);
	} else
	        error = EEXIST;

	vnode_put(nd.ni_dvp);
	if (nd.ni_vp)
		vnode_put(nd.ni_vp);
	nameidone(&nd);

	return (error);
}


