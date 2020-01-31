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
#include <miscfs/mockfs/mockfs_vnops.h>
#include <sys/ubc.h>
#include <sys/mount_internal.h>
#include <sys/vnode_internal.h>
#include <vfs/vfs_support.h>

#include <libkern/libkern.h>
#include <kern/debug.h>

/*
 * VOPFUNC macro; why do we have so many distinct definitions of this?
 */
#define VOPFUNC int (*)(void *)

/*
 * VNOP functions that mockfs implements.  See xnu/bsd/sys/vnode_if.h for information on what
 *   each function does in generic terms.
 */
int mockfs_lookup(struct vnop_lookup_args * ap);
int mockfs_getattr(struct vnop_getattr_args * ap);
int mockfs_read(struct vnop_read_args * ap);
int mockfs_strategy(struct vnop_strategy_args * ap);
int mockfs_pagein(struct vnop_pagein_args * ap);
int mockfs_reclaim(__unused struct vnop_reclaim_args * ap);
int mockfs_blockmap(struct vnop_blockmap_args * ap);

/*
 * struct vnop_lookup_args {
 *   struct vnodeop_desc *a_desc; // We don't care about this (for now)
 *   vnode_t a_dvp;               // vnode for the directory we are performing the lookup in
 *   vnode_t *a_vpp;              // Return parameter: the vnode we matched the lookup to
 *   struct componentname *a_cnp; // Description of the file we are looking for
 *   vfs_context_t a_context;     // We don't care about this (for now)
 * };
 *
 * mockfs_lookup:
 *   Given a vnode for a directory (a_dvp) and a file description (a_cnp), looks for a file matching
 *   the description in the directory, and give a vnode with an iocount for the file (*a_vpp), if the
 *   file was found.  For mockfs, because we realistically have 3 vnodes, the filesystem information
 *   is extremely sparse, so the details on naming are all implemented in mockfs_lookup; the generic VFS
 *   information is enough for us to distinguish between all 3 files.  Any lookup not done in the root
 *   vnode fails, by definition.  Each vnode has the following names in relation to the root vnode:
 *
 *   The root vnode:
 *     "sbin"
 *
 *   The devfs vnode:
 *     "dev"
 *
 *   The executable vnode
 *     "launchd"
 *
 * Returns 0 on success, or an error.
 */
int
mockfs_lookup(struct vnop_lookup_args * ap)
{
	char held_char;
	int rvalue;
	int op;
	mockfs_fsnode_t fsnode;
	mockfs_fsnode_t target_fsnode;
	vnode_t dvp;
	vnode_t * vpp;
	vfs_context_t ctx;
	struct componentname * cnp;

	rvalue = 0;
	dvp = ap->a_dvp;
	vpp = ap->a_vpp;
	cnp = ap->a_cnp;
	ctx = ap->a_context;
	op = cnp->cn_nameiop;
	fsnode = (mockfs_fsnode_t) dvp->v_data;
	target_fsnode = NULL;

	if ((op == LOOKUP) && (fsnode->type == MOCKFS_ROOT)) {
		/*
		 * Okay, we're looking in the root directory, so we aren't necessarily
		 *   going to fail.  What are we looking for?
		 */

		held_char = cnp->cn_nameptr[cnp->cn_namelen];
		cnp->cn_nameptr[cnp->cn_namelen] = '\0';

		/*
		 * We'll resolve sbin to /, and launchd to the executable for the moment, so that I don't
		 *   accidentally commit a change to the init_process pathname.  We map from name to node type
		 *   here, as mockfs doesn't current use names; just unique types.
		 */
		if (!strncmp(cnp->cn_nameptr, "sbin", 5)) {
			target_fsnode = fsnode;
		} else if (!strncmp(cnp->cn_nameptr, "dev", 4)) {
			mockfs_fsnode_child_by_type(fsnode, MOCKFS_DEV, &target_fsnode);
		} else if (!strncmp(cnp->cn_nameptr, "launchd", 8)) {
			mockfs_fsnode_child_by_type(fsnode, MOCKFS_FILE, &target_fsnode);
		} else {
			rvalue = ENOENT;
		}

		cnp->cn_nameptr[cnp->cn_namelen] = held_char;

		if (target_fsnode) {
			rvalue = mockfs_fsnode_vnode(target_fsnode, vpp);
		}
	} else {
		/*
		 * We aren't looking in root; the query may actually be reasonable, but we're not
		 *   going to support it.
		 */
		rvalue = ENOENT;
	}

	return rvalue;
}

/*
 * struct vnop_getattr_args {
 *   struct vnodeop_desc *a_desc; // We don't care about this (for now)
 *   vnode_t a_vp;                // Pointer to the vnode we are interested in
 *   struct vnode_attr *a_vap;    // Details the requested attributes, and used to return attributes
 *   vfs_context_t a_context;     // We don't care about this (for now)
 * };
 *
 * mockfs_getattr:
 *   Given a vnode (a_vp), returns the attributes requested for that vnode (*a_vap).  For mockfs, we don't care
 *   about the majority of attributes (we are not a fully featured filesystem).  We will return a minimal set of
 *   attributes for any request, regardless of which attributes were requested, to ensure that we look like a sane
 *   file, and so that permissions are set appropriately to allow execution of the executable vnode.
 *
 * Returns 0 on success, or an error.
 */
int
mockfs_getattr(struct vnop_getattr_args * ap)
{
	/*
	 * For the moment, we don't actually care about most attributes.  We'll
	 *   deal with actually managing attributes as part of the general cleanup.
	 */
	vnode_t vp;
	mockfs_fsnode_t fsnode;
	struct vnode_attr * vap;

	vp = ap->a_vp;
	fsnode = (mockfs_fsnode_t)vp->v_data;
	vap = ap->a_vap;
	bzero(vap, sizeof(*vap));
	VATTR_RETURN(vap, va_nlink, 1); /* Simply assert that someone has at least one link to us */
	VATTR_RETURN(vap, va_mode, VREAD | VWRITE | VEXEC);
	VATTR_RETURN(vap, va_fileid, fsnode->type);
	VATTR_RETURN(vap, va_total_size, fsnode->size);
	VATTR_RETURN(vap, va_total_alloc, fsnode->size);
	VATTR_RETURN(vap, va_data_size, fsnode->size);
	VATTR_RETURN(vap, va_data_alloc, fsnode->size);

	return 0;
}

/*
 * struct vnop_read_args {
 *   struct vnodeop_desc *a_desc; // We don't care about this (for now)
 *   vnode_t a_vp;                // Pointer to the vnode we are interested in
 *   struct uio *a_uio;           // Description of the request
 *   int a_ioflag;                // IO flags (we don't care about these)
 *   vfs_context_t a_context;     // We don't care about this (for now)
 * };
 *
 * mockfs_read:
 *   Given a vnode (a_vp), a set of flags (a_ioflag), and a description of a read request (a_uio), executes the read
 *   request and returns the resulting data through the description (a_uio).  mockfs has very little to do here; we
 *   merely mandate that any read attempt MUST be on VREG (our MOCKFS_FILE object), as it is the only vnode that has
 *   a backing store that can support a read (the other node types being purely in-memory hacks).  Because we do not
 *   support VNOP_OPEN, we can probably assume that the kernel is the only entity that will ever issue a VNOP_READ
 *   (as part of the exec path) to a mockfs vnode.
 *
 * Returns 0 on success, or an error.
 */
int
mockfs_read(struct vnop_read_args * ap)
{
	int rvalue;
	vnode_t vp;
	mockfs_fsnode_t fsnode;

	vp = ap->a_vp;
	fsnode = (mockfs_fsnode_t) vp->v_data;

	/*
	 * We're just an ugly frontend for the devnode, so we shouldn't need to do much for reads;
	 *   pass the work to cluster_read.
	 */
	if (vp->v_type == VREG) {
		rvalue = cluster_read(vp, ap->a_uio, fsnode->size, ap->a_ioflag);
	} else {
		/*
		 * You've tried to read from a nonregular file; I hate you.
		 */
		rvalue = ENOTSUP;
	}

	return rvalue;
}

/*
 * struct vnop_reclaim_args {
 *   struct vnodeop_desc *a_desc; // We don't care about this (for now)
 *   vnode_t a_vp;                // Pointer to the vnode we are reclaiming
 *   vfs_context_t a_context;     // We don't care about this (for now)
 * };
 *
 * mockfs_reclaim:
 *   Given a vnode (a_vp), performs any cleanup needed to allow VFS to reclaim the vnode.  Because the mockfs tree
 *   is always in memory, we have very little to do as part of reclaim, so we'll just zero a few pointers and let
 *   VFS reclaim the vnode.
 */
int
mockfs_reclaim(struct vnop_reclaim_args * ap)
{
	int rvalue;
	vnode_t vp;
	mockfs_fsnode_t fsnode;

	vp = ap->a_vp;
	fsnode = (mockfs_fsnode_t) vnode_fsnode(vp);
	rvalue = mockfs_fsnode_drop_vnode(fsnode);

	return rvalue;
}

/*
 * struct vnop_strategy_args {
 *   struct vnodeop_desc *a_desc; // We don't care about this (for now)
 *   struct buf *a_bp;            // Description of the desired IO
 * };
 *
 * mockfs_strategy:
 *   Given an IO description (a_bp), does any preparations required by the filesystem, and then passes the IO off to
 *   the appropriate device.  mockfs doesn't need to do anything to prepare for the IO, so we simply pass it off to
 *   our backing device.
 *
 * Returns 0 on success, or an error.
 */
int
mockfs_strategy(struct vnop_strategy_args * ap)
{
	int rvalue;
	vnode_t dvp;

	/*
	 * We'll avoid checking for a memory-backed device here; we already do this for blockmap, which will be
	 *   called as part of the IO path.
	 */

	dvp = vfs_devvp(buf_vnode(ap->a_bp)->v_mount);

	if (dvp) {
		rvalue = buf_strategy(dvp, ap);
		vnode_put(dvp);
	} else {
		/*
		 * I'm not certain this is the BEST error to return for this case.
		 */
		rvalue = EIO;
	}

	return rvalue;
}

/*
 * struct vnop_pagein_args {
 *   struct vnodeop_desc *a_desc; // We don't care about this (for now)
 *   vnode_t a_vp;                // Pointer to the vnode we are interested in
 *   upl_t a_pl;                  // Describes the pages that need to be paged in
 *   upl_offset_t a_pl_offset;    // Offset in the UPL to start placing data at
 *   off_t a_f_offset;            // File offset to begin paging in at
 *   size_t a_size;               // Bytes of data to page in
 *   int a_flags;                 // UPL flags (we don't care about these)
 *   vfs_context_t a_context;     // We don't care about this (for now)
 * };
 *
 * mockfs_pagegin:
 *   Given a vnode (a_vp), and a region, described by an offset (a_f_offset) and a size (a_size), pages the region
 *   into the given UPL (a_pl), starting at the UPL offset (a_pl_offset).  For mockfs, we don't have anything significant
 *   to do for pagein, so we largely serve as a wrapper to the cluster_pagein routine.
 *
 * Returns 0 on success, or an error.
 */
int
mockfs_pagein(struct vnop_pagein_args * ap)
{
	mockfs_fsnode_t fsnode;
	mockfs_mount_t mockfs_mnt;

	/*
	 * Nothing special needed from us; just nab the filesize and kick the work over to cluster_pagein.
	 */
	fsnode = (mockfs_fsnode_t) ap->a_vp->v_data;
	mockfs_mnt = ((mockfs_mount_t) fsnode->mnt->mnt_data);

	/*
	 * If we represent a memory backed device, we should be pointing directly to the backing store; we should never
	 *   see a pagein in this case.
	 */
	if (mockfs_mnt->mockfs_memory_backed) {
		panic("mockfs_pagein called for a memory-backed device");
	}

	return cluster_pagein(ap->a_vp, ap->a_pl, ap->a_pl_offset, ap->a_f_offset, ap->a_size, fsnode->size, ap->a_flags);
}

/*
 * struct vnop_blockmap_args {
 *   struct vnodeop_desc *a_desc; // We don't care about this (for now)
 *   vnode_t a_vp;                // Pointer to the vnode we are interested in
 *   off_t a_foffset;             // File offset we are interested in
 *   size_t a_size;               // Size of the region we are interested in
 *   daddr64_t *a_bpn;            // Return parameter: physical block number the region we are interest in starts at
 *   size_t *a_run;               // Return parameter: number of contiguous bytes of data
 *   void *a_poff;                // Unused, as far as I know
 *   int a_flags;                 // Used to distinguish reads and writes; we don't care
 *   vfs_context_t a_context;     // We don't care about this (for now)
 * };
 *
 * mockfs_blockmap:
 *   Given a vnode (a_vp), and a region, described by an offset (a_foffset), and a size (a_size), tells the caller
 *   which physical block (on the backing device) the region begins at (*a_bpn), and how many bytes can be read
 *   before the first discontinuity (*a_run).  For mockfs, because only VREG files are eligible for IO, and because
 *   all VREG files are simply a frontend for the backing device, this mapping will always be one to one, and all we
 *   need to do is convert the physical offset to the physical block number.
 *
 * Returns 0 on success, or an error.
 */
int
mockfs_blockmap(struct vnop_blockmap_args * ap)
{
	int rvalue;
	off_t foffset;
	size_t * run;
	uint32_t blksize;
	daddr64_t * bpn;
	vnode_t vp;
	mockfs_fsnode_t fsnode;

	rvalue = 0;
	foffset = ap->a_foffset;
	run = ap->a_run;
	bpn = ap->a_bpn;
	vp = ap->a_vp;
	fsnode = (mockfs_fsnode_t) vp->v_data;
	blksize = vp->v_mount->mnt_devblocksize;

	/*
	 * If we represent a memory backed device, we should be pointing directly to the backing store; all IO should
	 *   be satisfied from the UBC, and any called to blockmap (inidicating an attempted IO to the backing store)
	 *   is therefore disallowed.
	 */
	if (((mockfs_mount_t) fsnode->mnt->mnt_data)->mockfs_memory_backed) {
		printf("mockfs_blockmap called for a memory-backed device\n");
	}

	/*
	 * This will ultimately be simple; the vnode must be VREG (init), and the mapping will be 1 to 1.
	 *   This also means that their request should always be contiguous, so the run calculation is easy!
	 */
	if (vp->v_type == VREG) {
		*bpn = foffset / blksize;
		*run = fsnode->size - foffset;

		if (ap->a_size > *run) {
			/* We've been asked for more data than the backing device can provide; we're done. */
			panic("mockfs_blockmap was asked for a region that extended past the end of the backing device");
		}
	} else {
		rvalue = ENOTSUP;
	}

	return rvalue;
}

int(**mockfs_vnodeop_p)(void *);
struct vnodeopv_entry_desc mockfs_vnodeop_entries[] = {
	{ &vnop_default_desc, (VOPFUNC) vn_default_error }, /* default */
	{ &vnop_lookup_desc, (VOPFUNC) mockfs_lookup }, /* lookup */
	{ &vnop_create_desc, (VOPFUNC) err_create },/* create */
	{ &vnop_open_desc, (VOPFUNC) err_open }, /* open */
	{ &vnop_mknod_desc, (VOPFUNC) err_mknod }, /* mknod */
	{ &vnop_close_desc, (VOPFUNC) err_close }, /* close */
	{ &vnop_access_desc, (VOPFUNC) err_access }, /* access */
	{ &vnop_getattr_desc, (VOPFUNC) mockfs_getattr }, /* getattr */
	{ &vnop_setattr_desc, (VOPFUNC) err_setattr }, /* setattr */
	{ &vnop_read_desc, (VOPFUNC) mockfs_read }, /* read */
	{ &vnop_write_desc, (VOPFUNC) err_write }, /* write */
	{ &vnop_ioctl_desc, (VOPFUNC) err_ioctl }, /* ioctl */
	{ &vnop_select_desc, (VOPFUNC) err_select }, /* select */
	{ &vnop_mmap_desc, (VOPFUNC) err_mmap }, /* mmap */
	{ &vnop_fsync_desc, (VOPFUNC) nop_fsync }, /* fsync */
	{ &vnop_remove_desc, (VOPFUNC) err_remove }, /* remove */
	{ &vnop_link_desc, (VOPFUNC) err_link }, /* link */
	{ &vnop_rename_desc, (VOPFUNC) err_rename }, /* rename */
	{ &vnop_mkdir_desc, (VOPFUNC) err_mkdir }, /* mkdir */
	{ &vnop_rmdir_desc, (VOPFUNC) err_rmdir }, /* rmdir */
	{ &vnop_symlink_desc, (VOPFUNC) err_symlink }, /* symlink */
	{ &vnop_readdir_desc, (VOPFUNC) err_readdir }, /* readdir */
	{ &vnop_readlink_desc, (VOPFUNC) err_readlink }, /* readlink */
	{ &vnop_inactive_desc, (VOPFUNC) err_inactive }, /* inactive */
	{ &vnop_reclaim_desc, (VOPFUNC) mockfs_reclaim }, /* reclaim */
	{ &vnop_strategy_desc, (VOPFUNC) mockfs_strategy }, /* strategy */
	{ &vnop_pathconf_desc, (VOPFUNC) err_pathconf }, /* pathconf */
	{ &vnop_advlock_desc, (VOPFUNC) err_advlock }, /* advlock */
	{ &vnop_bwrite_desc, (VOPFUNC) err_bwrite }, /* bwrite */
	{ &vnop_pagein_desc, (VOPFUNC) mockfs_pagein }, /* pagein */
	{ &vnop_pageout_desc, (VOPFUNC) err_pageout }, /* pageout */
	{ &vnop_copyfile_desc, (VOPFUNC) err_copyfile }, /* copyfile */
	{ &vnop_blktooff_desc, (VOPFUNC) err_blktooff }, /* blktooff */
	{ &vnop_offtoblk_desc, (VOPFUNC) err_offtoblk }, /* offtoblk */
	{ &vnop_blockmap_desc, (VOPFUNC) mockfs_blockmap }, /* blockmap */
	{ (struct vnodeop_desc *) NULL, (VOPFUNC) NULL }
};

struct vnodeopv_desc mockfs_vnodeop_opv_desc = {
	&mockfs_vnodeop_p,
	mockfs_vnodeop_entries
};
