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

#include <miscfs/mockfs/mockfs.h>
#include <miscfs/mockfs/mockfs_fsnode.h>
#include <miscfs/mockfs/mockfs_vnops.h>
#include <miscfs/specfs/specdev.h>
#include <sys/disk.h>
#include <sys/mount_internal.h>
#include <sys/ubc_internal.h>
#include <sys/vnode_internal.h>
#include <vm/vm_protos.h>

#include <libkern/libkern.h>

/*
 * For the moment, most operations that change the fsnode will be called only in the context of
 *   mockfs_mountroot, so they should not need to use a mutex.  The exceptions are mockfs_fsnode_vnode,
 *   and mockfs_fsnode_drop_vnode, which will use a tree-wide mutex (that lives in the mockfs_mount_t
 *   for the mount).
 *
 * mockfs_fsnode_child_by_type doesn't require locking right now (we're only looking at the structure of
 *   the node tree, which should not change during VNOP operations.
 */

/* mockfs_fsnode_create:
 *   Given a mount (mp) and mockfs node type (type), creates a new fsnode for that mountpoint (*fsnpp).
 *   For the moment (while type == fileid) we should have at most one node of any given type.
 *
 * Returns 0 on success, or an error.
 */
int mockfs_fsnode_create(mount_t mp, uint8_t type, mockfs_fsnode_t * fsnpp)
{
	int rvalue;
	uint64_t new_size;

	rvalue = 0;
	new_size = 0;

	if (!fsnpp || !mp) {
		rvalue = EINVAL;
		goto done;
	}

	switch (type) {
		case MOCKFS_ROOT:
			break;	
		case MOCKFS_DEV:
			break;
		case MOCKFS_FILE:
			/*
			 * For a regular file, size is meaningful, but it will always be equal to the
			 * size of the backing device.
			 */
			new_size = mp->mnt_devvp->v_specinfo->si_devsize;
			break;
		default:
			rvalue = EINVAL;
			goto done;
	}

	MALLOC(*fsnpp, typeof(*fsnpp), sizeof(**fsnpp), M_TEMP, M_WAITOK | M_ZERO);

	if (!*fsnpp) {
		rvalue = ENOMEM;
		goto done;
	}

	(*fsnpp)->size = new_size;
	(*fsnpp)->type = type;
	(*fsnpp)->mnt = mp;

done:
	return rvalue;
}

/*
 * mockfs_fsnode_destroy:
 *   Given a node (fsnp), tears down and deallocates that node and the entire subtree that it is the
 *   root of (deallocates you, and your children, and your children's children! ...for three months).
 *
 * Returns 0 on success, or an error.
 */
int mockfs_fsnode_destroy(mockfs_fsnode_t fsnp)
{
	int rvalue;

	rvalue = 0;

	/*
	 * We will not destroy a root node that is actively pointed to by the mount structure; the
	 *   mount must drop the reference to the mockfs tree before we can deallocate it.
	 */
	if (!fsnp || (((mockfs_mount_t)fsnp->mnt->mnt_data)->mockfs_root == fsnp)) {
		rvalue = EINVAL;
		goto done;
	}

	/*
	 * For now, panic in this case; I don't expect anyone to ask us to destroy a node with a live
	 *   vfs reference, but this will tell me if that assumption is untrue.
	 */
	if (fsnp->vp)
		panic("mockfs_fsnode_destroy called on node with live vnode; fsnp = %p (in case gdb is screwing with you)", fsnp);

	/*
	 * If this node has children, we need to destroy them.
	 *
	 * At least for now, we aren't guaranteeing destroy will be clean; we may get partway through
	 *   and encounter an error, in which case we will panic (we may still have a sane tree, but
	 *   we've failed to destroy the subtree, which means someone called destroy when they should
	 *   not have done so).
	 */
	if (fsnp->child_a)
		if ((rvalue = mockfs_fsnode_destroy(fsnp->child_a)))
			panic("mockfs_fsnode_destroy failed on child_a; fsnp = %p (in case gdb is screwing with you), rvalue = %d", fsnp, rvalue);

	if (fsnp->child_b)
		if ((rvalue = mockfs_fsnode_destroy(fsnp->child_b)))
			panic("mockfs_fsnode_destroy failed on child_b; fsnp = %p (in case gdb is screwing with you), rvalue = %d", fsnp, rvalue);

	/*
	 * We need to orphan this node before we destroy it.
	 */
	if (fsnp->parent)
		if ((rvalue = mockfs_fsnode_orphan(fsnp)))
			panic("mockfs_fsnode_orphan failed during destroy; fsnp = %p (in case gdb is screwing with you), rvalue = %d", fsnp, rvalue);

	FREE(fsnp, M_TEMP);
done:
	return rvalue;
}

/*
 * mockfs_fsnode_adopt:
 *   Given two nodes (parent, child), makes one node the child of the other node.
 *
 * Returns 0 on success, or an error.
 */
int mockfs_fsnode_adopt(mockfs_fsnode_t parent, mockfs_fsnode_t child)
{
	int rvalue;

	rvalue = 0;

	/*
	 * The child must be an orphan, and the parent cannot be the child.
	 */
	if ((!parent || !child || child->parent) && (parent != child)) {
		rvalue = EINVAL;
		goto done;
	}

	/*
	 * Nodes are actually tied to a specific mount, so assert that both nodes belong to the same mount.
	 */
	if (parent->mnt != child->mnt) {
		rvalue = EINVAL;
		goto done;
	}

	/*
	 * TODO: Get rid of this check if I ever get around to making the tree non-binary.
	 * TODO: Enforce that the parent cannot have two children of the same type (for the moment, this is
	 *   implicit in the structure of the tree constructed by mockfs_mountroot, so we don't need to
	 *   worry about it).
	 * 
	 * Can the parent support another child (food, shelter, unused pointers)?
	 */
	if (!parent->child_a) {
		parent->child_a = child;
		child->parent = parent;
	}
	else if (!parent->child_b) {
		parent->child_b = child;
		child->parent = parent;
	}
	else {
		rvalue = ENOMEM;
	}

done:
	return rvalue;
}

/*
 * mockfs_fsnode_orphan:
 *
 * Returns 0 on success, or an error.
 */
int mockfs_fsnode_orphan(mockfs_fsnode_t fsnp)
{
	int rvalue;
	mockfs_fsnode_t parent;

	rvalue = 0;

	if (!fsnp || !fsnp->parent) {
		rvalue = EINVAL;
		goto done;
	}

	/*
	 * Disallow orphaning a node with a live vnode for now.
	 */
	if (fsnp->vp)
		panic("mockfs_fsnode_orphan called on node with live vnode; fsnp = %p (in case gdb is screwing with you)", fsnp);

	parent = fsnp->parent;

	if (parent->child_a == fsnp) {
		parent->child_a = NULL;
		fsnp->parent = NULL;
	}
	else if (parent->child_b == fsnp) {
		parent->child_b = NULL;
		fsnp->parent = NULL;
	}
	else
		panic("mockfs_fsnode_orphan insanity, fsnp->parent != parent->child; fsnp = %p (in case gdb is screwing with you)", fsnp);

done:
	return rvalue;
}

/*
 * mockfs_fsnode_child_by_type:
 *   Given a node (parent) and a type (type), returns the first child (*child) found corresponding to the
 *   requested type.  This method exists to support lookup (which is responsible for mapping names, which
 *   we have no conception of currently, onto vnodes).
 *
 * This should be safe, as we are walking the read-only parts of the filesystem structure (not touching 
 *   the vnode).
 *
 * Returns 0 on success, or an error.
 */
int mockfs_fsnode_child_by_type(mockfs_fsnode_t parent, uint8_t type, mockfs_fsnode_t * child)
{
	int rvalue;
	
	rvalue = 0;
	
	if (!parent || !child) {
		rvalue = EINVAL;
		goto done;
	}

	if ((parent->child_a) && (parent->child_a->type == type))
		*child = parent->child_a;
	else if ((parent->child_b) && (parent->child_b->type == type))
		*child = parent->child_b;
	else
		rvalue = ENOENT;

done:
	return rvalue;
}

/*
 * mockfs_fsnode_vnode:
 *   Given a mockfs node (fsnp), returns a vnode (*vpp) corresponding to the mockfs node; the vnode will
 *   have an iocount on it.
 *
 * Returns 0 on success, or an error.
 */
int mockfs_fsnode_vnode(mockfs_fsnode_t fsnp, vnode_t * vpp)
{
	int rvalue;
	memory_object_control_t ubc_mem_object;
	mockfs_mount_t mockfs_mnt;
	struct vnode_fsparam vnfs_param;

	if ((!fsnp) || (!vpp)) {
		rvalue = EINVAL;
		goto done;
	}

	mockfs_mnt = ((mockfs_mount_t) fsnp->mnt->mnt_data);
	lck_mtx_lock(&mockfs_mnt->mockfs_mnt_mtx);

	if (fsnp->vp) {
		/*
		 * The vnode already exists; this should be easy.
		 */
		rvalue = vnode_get(fsnp->vp);
		if (!rvalue) {
			*vpp = fsnp->vp;
		}
	}
	else {
		/*
		 * We need to create the vnode; this will be unpleasant.
		 */
		vnfs_param.vnfs_mp = fsnp->mnt;
		vnfs_param.vnfs_vtype = (fsnp->type == MOCKFS_FILE) ? VREG : VDIR;
		vnfs_param.vnfs_str = "mockfs";
		vnfs_param.vnfs_dvp = (fsnp->type == MOCKFS_ROOT) ? NULL : fsnp->parent->vp;
		vnfs_param.vnfs_fsnode = fsnp;
		vnfs_param.vnfs_vops = mockfs_vnodeop_p;
		vnfs_param.vnfs_markroot = (fsnp->type == MOCKFS_ROOT);
		vnfs_param.vnfs_marksystem = 0;
		vnfs_param.vnfs_rdev = 0;
		vnfs_param.vnfs_filesize = fsnp->size;
		vnfs_param.vnfs_cnp = NULL;
		vnfs_param.vnfs_flags = VNFS_CANTCACHE | VNFS_NOCACHE;
		rvalue = vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &vnfs_param, &fsnp->vp);

		if ((!rvalue) && (fsnp->type == MOCKFS_FILE) && (mockfs_mnt->mockfs_memory_backed)) {
			/*
			 * We're memory backed; point the pager towards the backing store of the device.
			 */
			ubc_mem_object = ubc_getobject(fsnp->vp, 0);

			if (!ubc_mem_object)
				panic("mockfs_fsvnode failed to get ubc_mem_object for a new vnode");

			rvalue = pager_map_to_phys_contiguous(ubc_mem_object, 0, (mockfs_mnt->mockfs_memdev_base << PAGE_SHIFT), fsnp->size);

			if (rvalue)
				panic("mockfs_fsnode_vnode failed to create fictitious pages for a memory-backed device; rvalue = %d", rvalue);
		}

		if (!rvalue)
			*vpp = fsnp->vp;
	}

	lck_mtx_unlock(&mockfs_mnt->mockfs_mnt_mtx);

done:
	return rvalue;
}

/*
 * mockfs_fsnode_vnode:
 *   Given a mockfs node (fsnp) that has a vnode associated with it, causes them to drop their
 *   references to each other.  This exists to support mockfs_reclaim.  This method will grab the tree
 *   mutex, as this will mutate the tree.
 *
 * Returns 0 on success, or an error.
 */
int mockfs_fsnode_drop_vnode(mockfs_fsnode_t fsnp)
{
	int rvalue;
	mockfs_mount_t mockfs_mnt;
	vnode_t vp;

	rvalue = 0;

	if (!fsnp) {
		rvalue = EINVAL;
		goto done;
	}

	mockfs_mnt = ((mockfs_mount_t) fsnp->mnt->mnt_data);
	lck_mtx_lock(&mockfs_mnt->mockfs_mnt_mtx);

	if (!(fsnp->vp)) {
		panic("mock_fsnode_drop_vnode: target fsnode does not have an associated vnode");
	}

	vp = fsnp->vp;
	fsnp->vp = NULL;
	vnode_clearfsnode(vp);

	lck_mtx_unlock(&mockfs_mnt->mockfs_mnt_mtx);
done:
	return rvalue;
}

