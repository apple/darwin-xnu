/*
 * Copyright (c) 2000-2001 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
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
#include <sys/proc.h>
#include <sys/kernel.h>
#include <mach/machine/vm_types.h>
#include <sys/vnode.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/buf.h>
#include <sys/mbuf.h>
#include <sys/file.h>
#include <dev/disk.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/attr.h>

#include <miscfs/specfs/specdev.h>

#include "synthfs.h"

#define LOADABLE_FS 0

typedef int (*PFI)();

struct vfsops synthfs_vfsops = {
	synthfs_mount,
	synthfs_start,
	synthfs_unmount,
	synthfs_root,
	synthfs_quotactl,
	synthfs_statfs,
	synthfs_sync,
	synthfs_vget,
	synthfs_fhtovp,
	synthfs_vptofh,
	synthfs_init,
	synthfs_sysctl
};

#define ROOTMPMODE 0755
#define ROOTPLACEHOLDERMODE 0700
static char synthfs_fs_name[MFSNAMELEN] = "synthfs";
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
	struct vfsconf *newvfsconf = NULL;
	int j;
	int (***opv_desc_vector_p)() = NULL;
	int (**opv_desc_vector)();
	struct vnodeopv_entry_desc *opve_descp;
    int error = 0;
	
#pragma unused(loadArgument)

    /*
     * This routine is responsible for all the initialization that would
     * ordinarily be done as part of the system startup; it calls synthfs_init
     * to do the initialization that is strictly synthfs-specific.
     */

    DBG_VOP(("load_synthfs: starting ...\n"));

    MALLOC(newvfsconf, void *, sizeof(struct vfsconf), M_SYNTHFS, M_WAITOK);
    DBG_VOP(("load_synthfs: Allocated new vfsconf list entry, newvfsconf = 0x%08lx.\n", (unsigned long)newvfsconf));
    bzero(newvfsconf, sizeof(struct vfsconf));

    if (newvfsconf) {
        DBG_VOP(("load_synthfs: filling in newly allocated vfsconf entry at 0x%08lX.\n", (long)newvfsconf));
        newvfsconf->vfc_vfsops = &synthfs_vfsops;
        strncpy(&newvfsconf->vfc_name[0], synthfs_fs_name, MFSNAMELEN);
        newvfsconf->vfc_typenum = maxvfsconf++;
        newvfsconf->vfc_refcount = 0;
        newvfsconf->vfc_flags = 0;
        newvfsconf->vfc_mountroot = NULL;       /* Can't mount root of file system [yet] */

    	newvfsconf->vfc_next = NULL;

        /* Based on vfs_op_init and ... */
        opv_desc_vector_p = synthfs_vnodeop_opv_desc.opv_desc_vector_p;

        DBG_VOP(("load_synthfs: Allocating and initializing VNode ops vector...\n"));

        /*
         * Allocate and init the vector.
         * Also handle backwards compatibility.
         */

        MALLOC(*opv_desc_vector_p, PFI *, vfs_opv_numops*sizeof(PFI), M_SYNTHFS, M_WAITOK);
        bzero (*opv_desc_vector_p, vfs_opv_numops*sizeof(PFI));
        opv_desc_vector = *opv_desc_vector_p;
        for (j=0; synthfs_vnodeop_opv_desc.opv_desc_ops[j].opve_op; j++) {
            opve_descp = &(synthfs_vnodeop_opv_desc.opv_desc_ops[j]);

            /*
             * Sanity check:  is this operation listed
             * in the list of operations?  We check this
             * by seeing if its offest is zero.  Since
             * the default routine should always be listed
             * first, it should be the only one with a zero
             * offset.  Any other operation with a zero
             * offset is probably not listed in
             * vfs_op_descs, and so is probably an error.
             *
             * A panic here means the layer programmer
             * has committed the all-too common bug
             * of adding a new operation to the layer's
             * list of vnode operations but
             * not adding the operation to the system-wide
             * list of supported operations.
             */
            if (opve_descp->opve_op->vdesc_offset == 0 &&
                opve_descp->opve_op->vdesc_offset != VOFFSET(vop_default)) {
                DBG_VOP(("load_synthfs: operation %s not listed in %s.\n",
                       opve_descp->opve_op->vdesc_name,
                       "vfs_op_descs"));
                panic ("load_synthfs: bad operation");
                }
            /*
             * Fill in this entry.
             */
            opv_desc_vector[opve_descp->opve_op->vdesc_offset] =
                opve_descp->opve_impl;
            }

        /*
         * Finally, go back and replace unfilled routines
         * with their default.  (Sigh, an O(n^3) algorithm.  I
                                 * could make it better, but that'd be work, and n is small.)
         */
        opv_desc_vector_p = synthfs_vnodeop_opv_desc.opv_desc_vector_p;

        /*
         * Force every operations vector to have a default routine.
         */
        opv_desc_vector = *opv_desc_vector_p;
        if (opv_desc_vector[VOFFSET(vop_default)]==NULL) {
            panic("load_vp;fs: operation vector without default routine.");
            }
        for (j = 0;j<vfs_opv_numops; j++)
            if (opv_desc_vector[j] == NULL)
                opv_desc_vector[j] =
                    opv_desc_vector[VOFFSET(vop_default)];

		if (error = vfsconf_add(newvfsconf)) {
			goto ErrExit;
		};
		goto InitFS;


ErrExit: ;
		if (opv_desc_vector_p && *opv_desc_vector_p) FREE(*opv_desc_vector_p, M_SYNTHFS);
		
        if (newvfsconf) FREE (newvfsconf, M_SYNTHFS);
		goto StdExit;


InitFS: ;
        DBG_VOP(("load_synthfs: calling synthfs_init()...\n"));
        synthfs_init(newvfsconf);
        };

StdExit: ;
}



int synthfs_unload(void) {
    DBG_VOP(("synthfs: Entering synthfs_unload...\n"));

    return 0;
}
#endif



/*
 * VFS Operations.
 *
 * mount system call
 */
int
synthfs_mount_fs(struct mount *mp, char *path, caddr_t data, struct nameidata *ndp, struct proc *p)
{
	struct synthfs_mntdata *priv_mnt_data;
    int	error;
    size_t size;

	DBG_VOP(("synthfs_mount_fs called.\n"));
	MALLOC(priv_mnt_data, struct synthfs_mntdata *, sizeof(struct synthfs_mntdata), M_SYNTHFS, M_WAITOK);
	DBG_VOP(("MALLOC succeeded...\n"));

	strncpy(mp->mnt_stat.f_fstypename, synthfs_fs_name, sizeof(mp->mnt_stat.f_fstypename));
    (void) copyinstr(path, mp->mnt_stat.f_mntonname, sizeof(mp->mnt_stat.f_mntonname) - 1, &size);
	strncpy(mp->mnt_stat.f_mntfromname, synthfs_fake_mntfromname, sizeof(mp->mnt_stat.f_mntfromname));
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
    vput(priv_mnt_data->synthfs_rootvp);

    return (0);
}



int
synthfs_mount(mp, path, data, ndp, p)
	register struct mount *mp;
	char *path;
	caddr_t data;
	struct nameidata *ndp;
	struct proc *p;
{
	size_t size;

	(void) copyinstr(path, mp->mnt_stat.f_mntonname, sizeof(mp->mnt_stat.f_mntonname) - 1, &size);
	return (synthfs_mount_fs(mp, path, data, ndp, p));
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
synthfs_start(mp, flags, p)
struct mount * mp;
int	flags;
struct proc * p;
{
    DBG_VOP(("synthfs_start called.\n"));
    return 0;
}

/*
 * Return the root of a filesystem.
 */
int
synthfs_root(mp, vpp)
        struct mount *mp;
        struct vnode **vpp;
{
    unsigned long root_nodeid = ROOT_DIRID;

    DBG_VOP(("synthfs_root called.\n"));

	*vpp = VFSTOSFS(mp)->synthfs_rootvp;
	return vget(VFSTOSFS(mp)->synthfs_rootvp, LK_EXCLUSIVE | LK_RETRY, current_proc());
}

int
synthfs_quotactl(mp, cmds, uid, arg, p)
struct mount *mp;
int cmds;
uid_t uid;
caddr_t arg;
struct proc * p;
{
	DBG_VOP(("synthfs_quotactl called.\n"));
	return (0);
}

/*
 * unmount system call
 */
int
synthfs_unmount(mp, mntflags, p)
	struct mount *mp;
	int mntflags;
	struct proc *p;
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
       Note that there's no need to vget() or vref() it before locking it here:
       the ref. count has been maintained at +1 ever since mount time. */
    if (root_vp) {
        retval = vn_lock(root_vp, LK_EXCLUSIVE | LK_RETRY, p);
        if ((mntflags & MNT_FORCE) == 0) {
			if (retval) goto Err_Exit;
        
	        if (root_vp->v_usecount > 1) {
	            DBG_VOP(("synthfs ERROR: root vnode = %x, usecount = %d\n", (int)root_vp, synth->synthfs_rootvp->v_usecount));
	            VOP_UNLOCK(root_vp, 0, p);
	            retval = EBUSY;
	            goto Err_Exit;
	        };
        };
        
        synth->synthfs_rootvp = NULL;
        
        if (retval == 0) {
        	vput(root_vp);			/* This drops synthfs's own refcount */
        	vgone(root_vp);
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
synthfs_statfs(mp, sbp, p)
	struct mount *mp;
	register struct statfs *sbp;
	struct proc *p;
{
	DBG_VOP(("synthfs_statfs called.\n"));

	sbp->f_bsize = 512;
	sbp->f_iosize = 512;
	sbp->f_blocks = 1024;	// lies, darn lies and virtual file systems
	sbp->f_bfree = 0;		// Nope, can't write here!
	sbp->f_bavail = 0;
    sbp->f_files =  VFSTOSFS(mp)->synthfs_filecount + VFSTOSFS(mp)->synthfs_dircount;
	sbp->f_ffree = 0;
    strncpy(sbp->f_mntonname, mp->mnt_stat.f_mntonname, sizeof(sbp->f_mntonname));
    strncpy(sbp->f_mntfromname, mp->mnt_stat.f_mntfromname, sizeof(sbp->f_mntfromname));

	return (0);
}

/*
 * synthfs doesn't have any data or backing store and you can't write into any of the synthfs 
 * structures, so don't do anything
 */
int
synthfs_sync(mp, waitfor, cred, p)
	struct mount *mp;
	int waitfor;
	struct ucred *cred;
	struct proc *p;
{
//	DBG_VOP(("synthfs_sync called\n"));
	return 0;
}
/*
 * Look up a synthfs node by node number.
 */
int
synthfs_vget(mp, ino, vpp)
	struct mount *mp;
	void *ino;
	struct vnode **vpp;
{
	struct vnode *vp;
	
//	DBG_VOP(("synthfs_vget called\n"));

	/* Check for unmount in progress */
	if (mp->mnt_kern_flag & MNTK_UNMOUNT) {
		*vpp = NULL;
		return (EPERM);
	}

loop:
	simple_lock(&mntvnode_slock);
	LIST_FOREACH(vp, &mp->mnt_vnodelist, v_mntvnodes) {
		if (VTOS(vp)->s_nodeid == *((unsigned long *)ino)) {
            if (vget(vp, LK_EXCLUSIVE, current_proc()) != 0) {
				simple_unlock(&mntvnode_slock);
                goto loop;
            };
			simple_unlock(&mntvnode_slock);
			*vpp = vp;
			return 0;
		};
	};
	simple_unlock(&mntvnode_slock);
	*vpp = NULL;
	return -1;
}

/*
 * fast filesystem related variables.
 */
int
synthfs_sysctl(name, namelen, oldp, oldlenp, newp, newlen, p)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	struct proc *p;
{
	DBG_VOP(("synthfs_sysctl called.\n"));
	return (EOPNOTSUPP);
}

/*
 * File handle to vnode
 *
 */
int
synthfs_fhtovp(mp, fhp, nam, vpp, exflagsp, credanonp)
	register struct mount *mp;
	struct fid *fhp;
	struct mbuf *nam;
	struct vnode **vpp;
	int *exflagsp;
	struct ucred **credanonp;
{
	DBG_VOP(("synthfs_fhtovp called.\n"));
    return EOPNOTSUPP;
}

/*
 * Vnode pointer to File handle
 */
/* ARGSUSED */
int
synthfs_vptofh(vp, fhp)
	struct vnode *vp;
	struct fid *fhp;
{
	DBG_VOP(("synthfs_vptofh called.\n"));
    return EOPNOTSUPP;
}






int
vn_mkdir(struct proc *p, char *path, int mode) {
	struct nameidata nd;
	struct vnode *vp;
	struct vattr vattr;
	int error;

	NDINIT(&nd, CREATE, LOCKPARENT, UIO_SYSSPACE, path, p);
	if (error = namei(&nd)) {
		DBG_VOP(("vn_mkdir: error from namei, error = %d.\n", error));
		return (error);
	};
	vp = nd.ni_vp;
	if (vp != NULL) {
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (nd.ni_dvp == vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		vrele(vp);
		DBG_VOP(("vn_mkdir: target already exists; returning EEXIST.\n"));
		return (EEXIST);
	}
	VATTR_NULL(&vattr);
	vattr.va_type = VDIR;
	vattr.va_mode = (mode & ACCESSPERMS) &~ p->p_fd->fd_cmask;
	VOP_LEASE(nd.ni_dvp, p, p->p_ucred, LEASE_WRITE);
	error = VOP_MKDIR(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, &vattr);
	if (error) {
		DBG_VOP(("vn_mkdir: error from VOP_MKDIR (%d).\n", error));
	} else {
		vput(nd.ni_vp);
	};
	return (error);
}



int
vn_symlink(struct proc *p, char *path, char *link) {
	struct nameidata nd;
	struct vattr vattr;
	int error;

	NDINIT(&nd, CREATE, LOCKPARENT, UIO_SYSSPACE, link, p);
	if (error = namei(&nd)) return error;

	if (nd.ni_vp) {
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (nd.ni_dvp == nd.ni_vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		vrele(nd.ni_vp);
		return EEXIST;
	}
	VATTR_NULL(&vattr);
	vattr.va_mode = ACCESSPERMS &~ p->p_fd->fd_cmask;
	VOP_LEASE(nd.ni_dvp, p, p->p_ucred, LEASE_WRITE);
	return VOP_SYMLINK(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, &vattr, path);
}


