/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 *	29-May-1998	Pat Dirks	Changed to cache pointer to root vnode until unmount.
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/namei.h>
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
#include <dev/ldd.h>

#include <miscfs/specfs/specdev.h>
#include "volfs.h"

struct vfsops volfs_vfsops = {
	volfs_mount,
	volfs_start,
	volfs_unmount,
	volfs_root,
	volfs_quotactl,
	volfs_statfs,
	volfs_sync,
	volfs_vget,
	volfs_fhtovp,
	volfs_vptofh,
	volfs_init,
	volfs_sysctl
};

static char volfs_fs_name[MFSNAMELEN] = "volfs";
extern struct vnodeopv_desc volfs_vnodeop_opv_desc;

/* The following refer to kernel global variables used in the loading/initialization: */
extern int                      maxvfsslots;            /* Total number of slots in the system's vfsconf table */
extern int                      maxvfsconf;             /* The highest fs type number [old-style ID] in use [dispite its name] */
extern int                      vfs_opv_numops; /* The total number of defined vnode operations */
extern int kdp_flag;

void
volfs_load(int loadArgument) {
    struct vfsconf *vfsconflistentry;
    int entriesRemaining;
    struct vfsconf *newvfsconf = NULL;
    struct vfsconf *lastentry = NULL;
        int j;
        int (***opv_desc_vector_p)();
        int (**opv_desc_vector)();
        struct vnodeopv_entry_desc *opve_descp;

#pragma unused(loadArgument)

        /*
         * This routine is responsible for all the initialization that would
         * ordinarily be done as part of the system startup; it calls volfs_init
         * to do the initialization that is strictly volfs-specific.
         */

        /*
           prevvfsconf is supposed to be the entry preceding the new entry.
           To make sure we can always get hooked in SOMEWHERE in the list,
           start it out at the first entry of the list.  This assumes the
           first entry in the list will be non-empty and not volfs.

           This becomes irrelevant when volfs is compiled into the list.
         */
        DBG_VOP(("load_volfs: Scanning vfsconf list...\n"));
    vfsconflistentry = vfsconf;
    for (entriesRemaining = maxvfsslots; entriesRemaining > 0; --entriesRemaining) {
        if (vfsconflistentry->vfc_vfsops != NULL) {
            /*
             * Check to see if we're reloading a new version of volfs during debugging
             * and overwrite the previously assigned entry if we find one:
             */
            if (strcmp(vfsconflistentry->vfc_name, volfs_fs_name) == 0) {
                newvfsconf = vfsconflistentry;
                break;
            } else {
                lastentry = vfsconflistentry;
            };
        } else {
            /*
             * This is at least a POSSIBLE place to insert the new entry...
             */
            newvfsconf = vfsconflistentry;
        };
        ++vfsconflistentry;
    };

    if (newvfsconf) {
                DBG_VOP(("load_volfs: filling in vfsconf entry at 0x%08lX; lastentry = 0x%08lX.\n", (long)newvfsconf, (long)lastentry));
        newvfsconf->vfc_vfsops = &volfs_vfsops;
        strncpy(&newvfsconf->vfc_name[0], "volfs", MFSNAMELEN);
        newvfsconf->vfc_typenum = maxvfsconf++;
        newvfsconf->vfc_refcount = 0;
        newvfsconf->vfc_flags = 0;
        newvfsconf->vfc_mountroot = NULL;       /* Can't mount root of file system [yet] */

                /* Hook into the list: */
        newvfsconf->vfc_next = NULL;
        if (lastentry) {
            newvfsconf->vfc_next = lastentry->vfc_next;
            lastentry->vfc_next = newvfsconf;
        };

        /* Based on vfs_op_init and ... */
        opv_desc_vector_p = volfs_vnodeop_opv_desc.opv_desc_vector_p;

        DBG_VOP(("load_volfs: Allocating and initializing VNode ops vector...\n"));

        /*
         * Allocate and init the vector.
         * Also handle backwards compatibility.
         */
        MALLOC(*opv_desc_vector_p, PFI *, vfs_opv_numops*sizeof(PFI), M_TEMP, M_WAITOK);

        bzero (*opv_desc_vector_p, vfs_opv_numops*sizeof(PFI));

        opv_desc_vector = *opv_desc_vector_p;
        for (j=0; volfs_vnodeop_opv_desc.opv_desc_ops[j].opve_op; j++) {
            opve_descp = &(volfs_vnodeop_opv_desc.opv_desc_ops[j]);

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
                DBG_VOP(("load_volfs: operation %s not listed in %s.\n",
                       opve_descp->opve_op->vdesc_name,
                       "vfs_op_descs"));
                panic ("load_volfs: bad operation");
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
        opv_desc_vector_p = volfs_vnodeop_opv_desc.opv_desc_vector_p;

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

        DBG_VOP(("load_volfs: calling volfs_init()...\n"));
        volfs_init(newvfsconf);
        };
}

/*
 * VFS Operations.
 *
 * mount system call
 */
int
volfs_mount(mp, path, data, ndp, p)
	register struct mount *mp;
	char *path;
	caddr_t data;
	struct nameidata *ndp;
	struct proc *p;
{
	struct volfs_mntdata *priv_mnt_data;
    struct vnode *root_vp;
    struct volfs_vndata	*priv_vn_data;
    int	error;
    size_t size;

	DBG_VOP(("volfs_mount called\n"));
	MALLOC(priv_mnt_data, struct volfs_mntdata *, sizeof(struct volfs_mntdata),
		M_VOLFSMNT, M_WAITOK);
	DBG_VOP(("MALLOC succeeded\n"));
	LIST_INIT(&priv_mnt_data->volfs_fsvnodes);
	DBG_VOP(("LIST_INIT succeeded\n"));

	mp->mnt_data = (void *)priv_mnt_data;
	strcpy(mp->mnt_stat.f_fstypename, "volfs");
        (void) copyinstr(path, mp->mnt_stat.f_mntonname, sizeof(mp->mnt_stat.f_mntonname) - 1, &size);
	strcpy(mp->mnt_stat.f_mntfromname, "<volfs>");
	
	/* Set up the root vnode for fast reference in the future.
	   Note that the root is maintained unlocked but with a pos. ref count until unmount. */
	
    MALLOC(priv_vn_data, struct volfs_vndata *, sizeof(struct volfs_vndata), M_VOLFSNODE, M_WAITOK);
    error = getnewvnode(VT_VOLFS, mp, volfs_vnodeop_p, &root_vp);
	if (error != 0)
	{
		FREE(priv_mnt_data, M_VOLFSMNT);
		FREE(priv_vn_data, M_VOLFSNODE);
		DBG_VOP(("getnewvnode failed with error code %d\n", error));
		return(error);
	}
    root_vp->v_type = VDIR;
    root_vp->v_flag |= VROOT;
    lockinit(&priv_vn_data->lock, PINOD, "volfsnode", 0, 0);
    priv_vn_data->vnode_type = VOLFS_ROOT;
    priv_vn_data->nodeID = 0;
    priv_vn_data->fs_mount = mp;
    root_vp->v_data = priv_vn_data;

    priv_mnt_data->volfs_rootvp = root_vp;
	
    return (0);
}

int
volfs_start(mp, flags, p)
struct mount * mp;
int	flags;
struct proc * p;
{
	DBG_VOP(("volfs_start called\n"));
	return (0);
}

/*
 * Return the root of a filesystem.  For volfs the root vnode is a directory
 * containing the list of all filesystems volfs can work with.
 */
int
volfs_root(mp, vpp)
        struct mount *mp;
        struct vnode **vpp;
{
	struct volfs_mntdata *priv_data;
    // struct volfs_vndata	*priv_vn_data;
    // int	error;

    DBG_VOP(("volfs_root called\n"));
	priv_data = (struct volfs_mntdata *)mp->mnt_data;

    if (priv_data->volfs_rootvp) {
        vref(priv_data->volfs_rootvp);
        VOP_LOCK(priv_data->volfs_rootvp, LK_EXCLUSIVE, current_proc());
		*vpp = priv_data->volfs_rootvp;
	} else {
		panic("volfs: root vnode missing!");
    };
    
    DBG_VOP(("volfs_root returned with "));
    DBG_VOP_PRINT_VNODE_INFO(*vpp);DBG_VOP(("\n"));
    
    return(0);
}

int
volfs_quotactl(mp, cmds, uid, arg, p)
struct mount *mp;
int cmds;
uid_t uid;
caddr_t arg;
struct proc * p;
{
	DBG_VOP(("volfs_quotactl called\n"));
	return (0);
}

/*
 * unmount system call
 */
int
volfs_unmount(mp, mntflags, p)
	struct mount *mp;
	int mntflags;
	struct proc *p;
{
    struct	volfs_mntdata	*priv_data;
    struct vnode *root_vp;
    int		retval;

    DBG_VOP(("volfs_unmount called\n"));
    priv_data = (struct volfs_mntdata *)mp->mnt_data;

    root_vp = priv_data->volfs_rootvp;
    retval = vflush(mp, root_vp, 0);
    if (retval) goto Err_Exit;

    /* Free the root vnode.
         Note that there's no need to vget() or vref() it before locking it here:
         the ref. count has been maintained at +1 ever since mount time. */
    if (root_vp) {
        retval = vn_lock(root_vp, LK_EXCLUSIVE, p);
		if (retval) goto Err_Exit;
        if (root_vp->v_usecount > 1) {
            DBG_VOP(("VOLFS ERROR: root vnode = %x, usecount = %d\n", (int)root_vp, priv_data->volfs_rootvp->v_usecount));
            VOP_UNLOCK(root_vp, 0, p);
            retval = EBUSY;
            goto Err_Exit;
        };

        priv_data->volfs_rootvp = NULL;
        vput(root_vp);				/* This drops volfs's own refcount */
        vgone(root_vp);
    };

	/* All vnodes should be gone, and no errors, clean up the last */
    /* XXX DBG_ASSERT(mp->mnt_vnodelist.lh_first == NULL); */
    /* XXX DBG_ASSERT(retval == 0); */

    mp->mnt_data = NULL;
    FREE(priv_data, M_VOLFSMNT);

Err_Exit:

    return(retval);
}

/*
 * Get file system statistics.
 */
int
volfs_statfs(mp, sbp, p)
	struct mount *mp;
	register struct statfs *sbp;
	struct proc *p;
{
	DBG_VOP(("volfs_statfs called\n"));
	sbp->f_bsize = 512;
	sbp->f_iosize = 512;
	sbp->f_blocks = 1024;	// lies, darn lies and virtual file systems
	sbp->f_bfree = 0;	// Nope, can't write here!
	sbp->f_bavail = 0;
	sbp->f_files =  0;	// Hmmm...maybe later
	sbp->f_ffree = 0;
	return (0);
}

/*
 * volfs doesn't have any data and you can't write into any of the volfs 
 * structures, so don't do anything
 */
int
volfs_sync(mp, waitfor, cred, p)
	struct mount *mp;
	int waitfor;
	struct ucred *cred;
	struct proc *p;
{
//	DBG_VOP(("volfs_sync called\n"));
	return 0;
}
/*
 * Look up a FFS dinode number to find its incore vnode, otherwise read it
 * in from disk.  If it is in core, wait for the lock bit to clear, then
 * return the inode locked.  Detection and handling of mount points must be
 * done by the calling routine.
 */
int
volfs_vget(mp, ino, vpp)
	struct mount *mp;
	void *ino;
	struct vnode **vpp;
{
//	DBG_VOP(("volfs_vget called\n"));
	return(0);
}
/*
 * File handle to vnode
 *
 * Have to be really careful about stale file handles:
 * - check that the inode number is valid
 * - call ffs_vget() to get the locked inode
 * - check for an unallocated inode (i_mode == 0)
 * - check that the given client host has export rights and return
 *   those rights via. exflagsp and credanonp
 */
int
volfs_fhtovp(mp, fhp, nam, vpp, exflagsp, credanonp)
	register struct mount *mp;
	struct fid *fhp;
	struct mbuf *nam;
	struct vnode **vpp;
	int *exflagsp;
	struct ucred **credanonp;
{
	DBG_VOP(("volfs_fhtovp called\n"));
	return(0);
}
/*
 * Vnode pointer to File handle
 */
/* ARGSUSED */
int
volfs_vptofh(vp, fhp)
	struct vnode *vp;
	struct fid *fhp;
{
	DBG_VOP(("volfs_vptofh called\n"));
	return(0);
}
/*
 * Initialize the filesystem
 */
int
volfs_init(vfsp)
	struct vfsconf *vfsp;
{
	DBG_VOP(("volfs_init called\n"));
	return (0);
}

/*
 * fast filesystem related variables.
 */
int
volfs_sysctl(name, namelen, oldp, oldlenp, newp, newlen, p)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	struct proc *p;
{
	DBG_VOP(("volfs_sysctl called\n"));
	return (EOPNOTSUPP);
}

