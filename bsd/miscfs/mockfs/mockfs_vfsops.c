/*
 * Copyright (c) 2012 Apple Inc. All rights reserved.
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

#include <kern/assert.h>
#include <kern/debug.h>
#include <libkern/libkern.h>
#include <miscfs/mockfs/mockfs.h>
#include <miscfs/mockfs/mockfs_fsnode.h>
#include <miscfs/mockfs/mockfs_vnops.h>
#include <miscfs/specfs/specdev.h>
#include <sys/disk.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/mount_internal.h>
#include <sys/vnode_internal.h>

lck_attr_t * mockfs_mtx_attr = (lck_attr_t *) 0;
lck_grp_attr_t * mockfs_grp_attr = (lck_grp_attr_t *) 0;
lck_grp_t * mockfs_mtx_grp = (lck_grp_t *) 0;

int mockfs_mountroot(mount_t mp, vnode_t rvp, __unused vfs_context_t ctx);

/*
 * Functions that are part of the mockfs_vfsops structure.
 */
int mockfs_unmount(__unused struct mount *mp, __unused int mntflags, __unused vfs_context_t ctx);
int mockfs_root(mount_t mp, vnode_t * vpp, __unused vfs_context_t ctx);
int mockfs_sync(__unused struct mount *mp, __unused int waitfor, __unused vfs_context_t ctx);
int mockfs_init(__unused struct vfsconf * vfsc);

/*
 * mockfs_mountroot:
 *   Given a mount (mp) and a vnode for the root device (rvp), builds a fake filesystem for rvp.  This consists
 *   of three nodes; a directory node (to serve as a mountpoint for devfs), a file node meant to serve as an
 *   executable frontend for rootvp (we will assume that rootvp is an executable, that the kernel can subsequently
 *   run), and the root node for the mockfs filesystem.  The structure of mockfs is memory-backed; only the
 *   contents of the file node refer to the backing device.
 *
 * Returns 0 on success, or an error.
 */
int
mockfs_mountroot(mount_t mp, vnode_t rvp, __unused vfs_context_t ctx)
{
	int rvalue = 0;
	mockfs_fsnode_t root_fsnode = NULL;
	mockfs_fsnode_t dev_fsnode = NULL;
	mockfs_fsnode_t file_fsnode = NULL;
	mockfs_mount_t mockfs_mount_data = NULL;
	dk_memdev_info_t memdev_info;

	/*
	 * TODO: Validate that the device at least LOOKS like a mach-o (has a sane header); this would prevent us
	 *   from causing EBADMACHO panics further along the boot path.
	 */

	/*
	 * There are no M_MOCKFS* definitions at the moment, just use M_TEMP.
	 */

	MALLOC(mockfs_mount_data, mockfs_mount_t, sizeof(*mockfs_mount_data), M_TEMP, M_WAITOK | M_ZERO);
	mockfs_fsnode_create(mp, MOCKFS_ROOT, &root_fsnode);
	mockfs_fsnode_create(mp, MOCKFS_DEV, &dev_fsnode);
	mockfs_fsnode_create(mp, MOCKFS_FILE, &file_fsnode);

	if (!mockfs_mount_data || !root_fsnode || !dev_fsnode || !file_fsnode) {
		rvalue = ENOMEM;
		goto done;
	}

	/*
	 * If rvp is a memory device (with a few caveats), we can point to the same physical memory as the device
	 *   and avoid pointless paging/copying; query the device node for the information we need to determine
	 *   if we can do this.
	 */
	bzero(&memdev_info, sizeof(memdev_info));

	if (!VNOP_IOCTL(rvp, DKIOCGETMEMDEVINFO, (caddr_t)&memdev_info, 0, NULL)) {
		/*
		 * For the moment, we won't try to optimize when mi_phys is true.
		 */
		if (!mockfs_mount_data->mockfs_physical_memory) {
			mockfs_mount_data->mockfs_memory_backed = memdev_info.mi_mdev;
			mockfs_mount_data->mockfs_physical_memory = memdev_info.mi_phys;
			mockfs_mount_data->mockfs_memdev_base = memdev_info.mi_base;
			mockfs_mount_data->mockfs_memdev_size = memdev_info.mi_size;
		}
	}

	lck_mtx_init(&mockfs_mount_data->mockfs_mnt_mtx, mockfs_mtx_grp, mockfs_mtx_attr);

	/*
	 * All of the needed nodes/structures have been set up; now we just need to establish the relationships
	 *   between the various mockfs nodes.
	 */
	if ((rvalue = mockfs_fsnode_adopt(root_fsnode, dev_fsnode))) {
		goto done;
	}

	if ((rvalue = mockfs_fsnode_adopt(root_fsnode, file_fsnode))) {
		goto done;
	}

	mockfs_mount_data->mockfs_root = root_fsnode;
	mp->mnt_data = (typeof(mp->mnt_data))mockfs_mount_data;

done:
	if (rvalue) {
		if (file_fsnode) {
			mockfs_fsnode_destroy(file_fsnode);
		}
		if (dev_fsnode) {
			mockfs_fsnode_destroy(dev_fsnode);
		}
		if (root_fsnode) {
			mockfs_fsnode_destroy(root_fsnode);
		}
		if (mockfs_mount_data) {
			lck_mtx_destroy(&mockfs_mount_data->mockfs_mnt_mtx, mockfs_mtx_grp);
			FREE(mockfs_mount_data, M_TEMP);
		}
	}

	return rvalue;
}

/*
 * mockfs_unmount:
 *   Given a mount (mp), and associated flags (mntflags), performs the necessary teardown to destroy the mount.
 *
 * Returns 0 on success, or an error.
 */
int
mockfs_unmount(struct mount *mp, int mntflags, __unused vfs_context_t ctx)
{
	int rvalue;
	int vflush_flags;
	mockfs_fsnode_t root_fsnode;
	mockfs_mount_t mockfs_mnt;

	vflush_flags = 0;
	mockfs_mnt = (mockfs_mount_t) mp->mnt_data;

	/*
	 * Reclaim the vnodes for the mount (forcibly, if requested; given that mockfs only support mountroot
	 *   at the moment, this should ALWAYS be forced),
	 */
	if (mntflags & MNT_FORCE) {
		vflush_flags |= FORCECLOSE;
	}

	rvalue = vflush(mp, NULL, vflush_flags);

	if (rvalue) {
		return rvalue;
	}

	/*
	 * Past this point, errors are likely to be unrecoverable, so panic if we're given any excuse; we
	 *   need to teardown the mockfs_mnt data now, so that VFS can cleanup the mount structure.  Note
	 *   that clearing mockfs_root before destroying the fsnode tree is related to an implementation
	 *   detail of mockfs_fsnode_destroy (which will refuse to destroy the root node).
	 */
	root_fsnode = mockfs_mnt->mockfs_root;
	mockfs_mnt->mockfs_root = NULL;
	rvalue = mockfs_fsnode_destroy(root_fsnode);

	if (rvalue) {
		panic("mockfs_unmount: Failed to destroy the fsnode tree");
	}

	lck_mtx_destroy(&mockfs_mnt->mockfs_mnt_mtx, mockfs_mtx_grp);
	FREE(mockfs_mnt, M_TEMP);
	mp->mnt_data = NULL;

	return rvalue;
}

/*
 * mockfs_root:
 *   Given a mount (mp), returns the root vnode (*vpp) for that mount with an iocount.
 *
 * Returns 0 on success, or an error.
 */
int
mockfs_root(mount_t mp, vnode_t * vpp, __unused vfs_context_t ctx)
{
	int rvalue;

	rvalue = mockfs_fsnode_vnode(((mockfs_mount_t) mp->mnt_data)->mockfs_root, vpp);
	return rvalue;
}

/*
 * mockfs_sync:
 *  Returns success because we're a read-only filesystem.
 *
 * Returns 0.
 */
int
mockfs_sync(__unused struct mount *mp, __unused int waitfor, __unused vfs_context_t ctx)
{
	return 0;
}

/*
 * mockfs_init:
 *   Run once (during VFS initialization); takes care of generic mockfs initialization (which for now, means
 *   global lock information).
 *
 * Returns 0 on success, or an error.
 */
int
mockfs_init(__unused struct vfsconf * vfsc)
{
	mockfs_mtx_attr = lck_attr_alloc_init();
	mockfs_grp_attr = lck_grp_attr_alloc_init();
	mockfs_mtx_grp = lck_grp_alloc_init("mockfs-mutex", mockfs_grp_attr);

	/*
	 * If we've failed to allocate this early in boot, something is horrendously wrong; it should be fine to
	 *   panic (for now).
	 */
	if (!mockfs_mtx_attr || !mockfs_grp_attr || !mockfs_mtx_grp) {
		panic("mockfs_init failed to allocate lock information");
	}

	return 0;
}

struct vfsops mockfs_vfsops = {
	.vfs_unmount = mockfs_unmount,
	.vfs_root = mockfs_root,
	.vfs_sync = mockfs_sync,
	.vfs_init = mockfs_init,
};
