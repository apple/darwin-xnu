/*
 * Copyright (c) 1998-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <mach/machine/vm_types.h>
#include <sys/vnode.h>
#include <sys/socket.h>
#include <sys/mount_internal.h>
#include <sys/mbuf.h>
#include <sys/file.h>
#include <sys/disk.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <dev/ldd.h>

#include <miscfs/specfs/specdev.h>
#include "volfs.h"

static int  volfs_mount(struct mount *, vnode_t , user_addr_t, vfs_context_t);
static int  volfs_start(struct mount *, int, vfs_context_t);
static int  volfs_unmount(struct mount *, int, vfs_context_t);
static int  volfs_root(struct mount *, struct vnode **, vfs_context_t);
static int  volfs_vfs_getattr(mount_t mp, struct vfs_attr *fsap, vfs_context_t context);
static int  volfs_sync(struct mount *, int, vfs_context_t);
static int  volfs_vget(struct mount *, ino64_t, struct vnode **, vfs_context_t);
static int  volfs_fhtovp(struct mount *, int, unsigned char *, struct vnode **, vfs_context_t);
static int  volfs_vptofh(struct vnode *, int *, unsigned char *, vfs_context_t);
static int  volfs_init(struct vfsconf *);
static int  volfs_sysctl(int *, u_int, user_addr_t, size_t *, user_addr_t, size_t, vfs_context_t);
void volfs_load(int loadArgument);


struct vfsops volfs_vfsops = {
	volfs_mount,
	volfs_start,
	volfs_unmount,
	volfs_root,
	NULL,		/* quotactl */
	volfs_vfs_getattr,
	volfs_sync,
	volfs_vget,
	volfs_fhtovp,
	volfs_vptofh,
	volfs_init,
	volfs_sysctl
};

// static char volfs_fs_name[MFSNAMELEN] = "volfs";
extern struct vnodeopv_desc volfs_vnodeop_opv_desc;

extern int (**volfs_vnodeop_p)(void *);

/* The following refer to kernel global variables used in the loading/initialization: */
extern int                      vfs_opv_numops; /* The total number of defined vnode operations */
extern int kdp_flag;

void
volfs_load(__unused int loadArgument) 
{
#if 0
    struct vfsconf *vfsconflistentry;
    int entriesRemaining;
    struct vfsconf *newvfsconf = NULL;
    struct vfsconf *lastentry = NULL;
        int j;
        int (***opv_desc_vector_p)();
        int (**opv_desc_vector)();
        struct vnodeopv_entry_desc *opve_descp;
        
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
                opve_descp->opve_op->vdesc_offset != VOFFSET(vnop_default)) {
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
        if (opv_desc_vector[VOFFSET(vnop_default)]==NULL) {
            panic("load_vp;fs: operation vector without default routine.");
            }
        for (j = 0;j<vfs_opv_numops; j++)
            if (opv_desc_vector[j] == NULL)
                opv_desc_vector[j] =
                    opv_desc_vector[VOFFSET(vnop_default)];

         volfs_init(newvfsconf);
        };
#else
	panic("volfs load not ported");
#endif
}

/*
 * VFS Operations.
 *
 * mount system call
 */
static int
volfs_mount(struct mount *mp, __unused vnode_t devvp, __unused user_addr_t data,  __unused vfs_context_t context)
{
	struct volfs_mntdata *priv_mnt_data;
	struct vnode *root_vp;
	struct volfs_vndata	*priv_vn_data;
	int	error;
	struct vnode_fsparam vfsp;

	MALLOC(priv_mnt_data, struct volfs_mntdata *, sizeof(struct volfs_mntdata),
		M_VOLFSMNT, M_WAITOK);

	mp->mnt_data = (void *)priv_mnt_data;
	strcpy(mp->mnt_vfsstat.f_fstypename, "volfs");
	strcpy(mp->mnt_vfsstat.f_mntfromname, "<volfs>");
	
	/* Set up the root vnode for fast reference in the future.
	   Note that the root is maintained unlocked but with a pos. ref count until unmount. */
	
	MALLOC(priv_vn_data, struct volfs_vndata *, sizeof(struct volfs_vndata), M_VOLFSNODE, M_WAITOK);

	priv_vn_data->vnode_type = VOLFS_ROOT;
	priv_vn_data->nodeID = ROOT_DIRID;
	priv_vn_data->fs_mount = mp;
	priv_vn_data->fs_fsid = mp->mnt_vfsstat.f_fsid;

	vfsp.vnfs_mp = mp;
	vfsp.vnfs_vtype = VDIR;
	vfsp.vnfs_str = "volfs";
	vfsp.vnfs_dvp = 0;
	vfsp.vnfs_fsnode = priv_vn_data;
	vfsp.vnfs_cnp = 0;
	vfsp.vnfs_vops = volfs_vnodeop_p;
	vfsp.vnfs_rdev = 0;
	vfsp.vnfs_filesize = 0;
	vfsp.vnfs_flags = VNFS_NOCACHE | VNFS_CANTCACHE;
	vfsp.vnfs_marksystem = 0;
	vfsp.vnfs_markroot = 1;

	error = vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &vfsp, &root_vp);
	if (error != 0) {
		FREE(priv_mnt_data, M_VOLFSMNT);
		FREE(priv_vn_data, M_VOLFSNODE);
		return(error);
	}
	vnode_ref(root_vp);
	vnode_put(root_vp);

	/* obtain a new fsid for the mount point */
	vfs_getnewfsid(mp);

	vnode_settag(root_vp, VT_VOLFS);
    
	priv_mnt_data->volfs_rootvp = root_vp;
	mp->mnt_flag &= ~MNT_RDONLY;

	mp->mnt_vtable->vfc_threadsafe = TRUE;
	
	return (0);
}

static int
volfs_start(__unused struct mount * mp, __unused int flags, __unused vfs_context_t context)
{
	return (0);
}

/*
 * Return the root of a filesystem.  For volfs the root vnode is a directory
 * containing the list of all filesystems volfs can work with.
 */
static int
volfs_root(struct mount *mp, struct vnode **vpp, __unused vfs_context_t context)
{
	struct volfs_mntdata *priv_data;

	priv_data = (struct volfs_mntdata *)mp->mnt_data;

	if (priv_data->volfs_rootvp) {
		vnode_get(priv_data->volfs_rootvp);
		*vpp = priv_data->volfs_rootvp;
	} else {
		panic("volfs: root vnode missing!");
	};

	return(0);
}

/*
 * unmount system call
 */
static int
volfs_unmount(struct mount *mp, __unused int mntflags, __unused vfs_context_t context)
{
    struct	volfs_mntdata	*priv_data;
    struct vnode *root_vp;
    int		retval;

    priv_data = (struct volfs_mntdata *)mp->mnt_data;

    root_vp = priv_data->volfs_rootvp;
    retval = vflush(mp, root_vp, 0);
    if (retval) goto Err_Exit;

    /* Free the root vnode.
         Note that there's no need to vget() or vref() it before locking it here:
         the ref. count has been maintained at +1 ever since mount time. */
    if (root_vp) {
        if (vnode_isinuse(root_vp, 1)) {
             retval = EBUSY;
            goto Err_Exit;
        };

        priv_data->volfs_rootvp = NULL;
        vnode_rele(root_vp);				/* This drops volfs's own refcount */
        vnode_reclaim(root_vp);
    };

	/* All vnodes should be gone, and no errors, clean up the last */

    mp->mnt_data = NULL;
    FREE(priv_data, M_VOLFSMNT);

Err_Exit:

    return(retval);
}

/*
 * Get file system statistics.
 */
static int
volfs_vfs_getattr(mount_t mp, struct vfs_attr *fsap, vfs_context_t context)
{
	VFSATTR_RETURN(fsap, f_bsize, 512);
	VFSATTR_RETURN(fsap, f_iosize, 512);
	VFSATTR_RETURN(fsap, f_blocks, 1024);
	VFSATTR_RETURN(fsap, f_bfree, 0);
	VFSATTR_RETURN(fsap, f_bavail, 0);
	VFSATTR_RETURN(fsap, f_bused, 1024);
	VFSATTR_RETURN(fsap, f_files, 0);
	VFSATTR_RETURN(fsap, f_ffree, 0);
	VFSATTR_RETURN(fsap, f_fssubtype, 0);
	return 0;
}

/*
 * volfs doesn't have any data and you can't write into any of the volfs 
 * structures, so don't do anything
 */
static int
volfs_sync(__unused struct mount *mp, __unused int waitfor, __unused vfs_context_t context)
{
	return 0;
}

/*
 *
 */
static int
volfs_vget(__unused struct mount *mp, __unused ino64_t ino, 
		   __unused struct vnode **vpp, __unused vfs_context_t context)
{
	return(ENOTSUP);
}

/*
 * File handle to vnode
 */
static int
volfs_fhtovp(__unused struct mount *mp, __unused int fhlen,  
			 __unused unsigned char *fhp, __unused struct vnode **vpp,
			 __unused vfs_context_t context)
{
	return(ENOTSUP);
}

/*
 * Vnode pointer to File handle
 */
static int
volfs_vptofh(__unused struct vnode *vp, __unused int *fhlenp, __unused unsigned char *fhp, __unused vfs_context_t context)
{
	return(ENOTSUP);
}

/*
 * Initialize the filesystem
 */
static int
volfs_init(__unused struct vfsconf *vfsp)
{	
	return (0);
}

/*
 * fast filesystem related variables.
 */
static int
volfs_sysctl(__unused int *name, __unused u_int namelen, __unused user_addr_t oldp, 
			 __unused size_t *oldlenp, __unused user_addr_t newp, __unused size_t newlen, 
			 __unused vfs_context_t context)
{
	return (ENOTSUP);
}

