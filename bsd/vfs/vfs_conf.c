/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1989, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)vfs_conf.c	8.11 (Berkeley) 5/10/95
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mount_internal.h>
#include <sys/vnode_internal.h>

#include <nfs/nfs_conf.h>

/*
 * These define the root filesystem, device, and root filesystem type.
 */
struct mount *rootfs;
struct vnode *rootvnode;

#ifdef CONFIG_IMGSRC_ACCESS
struct vnode *imgsrc_rootvnodes[MAX_IMAGEBOOT_NESTING]; /* [0] -> source volume, [1] -> first disk image */
#endif /* CONFIG_IMGSRC_ACCESS */

int (*mountroot)(void) = NULL;

/*
 * Set up the initial array of known filesystem types.
 */
extern  struct vfsops mfs_vfsops;
extern  int mfs_mountroot(mount_t, vnode_t, vfs_context_t);     /* dead */
extern  struct vfsops nfs_vfsops;
extern  int nfs_mountroot(void);
extern  struct vfsops afs_vfsops;
extern  struct vfsops null_vfsops;
extern  struct vfsops devfs_vfsops;
extern  const struct vfsops routefs_vfsops;
extern  struct vfsops nullfs_vfsops;

#if MOCKFS
extern  struct vfsops mockfs_vfsops;
extern  int mockfs_mountroot(mount_t, vnode_t, vfs_context_t);
#endif /* MOCKFS */

/*
 * For nfs_mountroot(void) cast.  nfs_mountroot ignores its parameters, if
 * invoked through this table.
 */
typedef int (*mountroot_t)(mount_t, vnode_t, vfs_context_t);

enum fs_type_num {
	FT_NFS = 2,
	FT_DEVFS = 19,
	FT_SYNTHFS = 20,
	FT_ROUTEFS = 21,
	FT_NULLFS = 22,
	FT_MOCKFS  = 0x6D6F636B
};

/*
 * Set up the filesystem operations for vnodes.
 */
static struct vfstable vfstbllist[] = {
	/* Sun-compatible Network Filesystem */
#if CONFIG_NFS_CLIENT
	{
		.vfc_vfsops = &nfs_vfsops,
		.vfc_name = "nfs",
		.vfc_typenum = FT_NFS,
		.vfc_refcount = 0,
		.vfc_flags = 0,
		.vfc_mountroot = NULL,
		.vfc_next = NULL,
		.vfc_reserved1 = 0,
		.vfc_reserved2 = 0,
		.vfc_vfsflags = VFC_VFSGENERICARGS | VFC_VFSPREFLIGHT | VFC_VFS64BITREADY | VFC_VFSREADDIR_EXTENDED,
		.vfc_descptr = NULL,
		.vfc_descsize = 0,
		.vfc_sysctl = NULL
	},
#endif /* CONFIG_NFS_CLIENT */

	/* Device Filesystem */
#if DEVFS
#if CONFIG_MACF
	{
		.vfc_vfsops = &devfs_vfsops,
		.vfc_name = "devfs",
		.vfc_typenum = FT_DEVFS,
		.vfc_refcount = 0,
		.vfc_flags = MNT_MULTILABEL,
		.vfc_mountroot = NULL,
		.vfc_next = NULL,
		.vfc_reserved1 = 0,
		.vfc_reserved2 = 0,
		.vfc_vfsflags = VFC_VFSGENERICARGS | VFC_VFS64BITREADY,
		.vfc_descptr = NULL,
		.vfc_descsize = 0,
		.vfc_sysctl = NULL
	},
#else /* !CONFIG_MAC */
	{
		.vfc_vfsops = &devfs_vfsops,
		.vfc_name = "devfs",
		.vfc_typenum = FT_DEVFS,
		.vfc_refcount = 0,
		.vfc_flags = 0,
		.vfc_mountroot = NULL,
		.vfc_next = NULL,
		.vfc_reserved1 = 0,
		.vfc_reserved2 = 0,
		.vfc_vfsflags = VFC_VFSGENERICARGS | VFC_VFS64BITREADY,
		.vfc_descptr = NULL,
		.vfc_descsize = 0,
		.vfc_sysctl = NULL
	},
#endif /* CONFIG_MAC */
#endif /* DEVFS */

#ifndef __LP64__
#endif /* __LP64__ */

#if NULLFS
	{
		.vfc_vfsops = &nullfs_vfsops,
		.vfc_name = "nullfs",
		.vfc_typenum = FT_NULLFS,
		.vfc_refcount = 0,
		.vfc_flags = MNT_DONTBROWSE | MNT_RDONLY,
		.vfc_mountroot = NULL,
		.vfc_next = NULL,
		.vfc_reserved1 = 0,
		.vfc_reserved2 = 0,
		.vfc_vfsflags = VFC_VFS64BITREADY,
		.vfc_descptr = NULL,
		.vfc_descsize = 0,
		.vfc_sysctl = NULL
	},
#endif /* NULLFS */

#if MOCKFS
	/* If we are configured for it, mockfs should always be the last standard entry (and thus the last FS we attempt mountroot with) */
	{
		.vfc_vfsops = &mockfs_vfsops,
		.vfc_name = "mockfs",
		.vfc_typenum = FT_MOCKFS,
		.vfc_refcount = 0,
		.vfc_flags = MNT_LOCAL,
		.vfc_mountroot = mockfs_mountroot,
		.vfc_next = NULL,
		.vfc_reserved1 = 0,
		.vfc_reserved2 = 0,
		.vfc_vfsflags = VFC_VFSGENERICARGS,
		.vfc_descptr = NULL,
		.vfc_descsize = 0,
		.vfc_sysctl = NULL
	},
#endif /* MOCKFS */

#if ROUTEFS
	/* If we are configured for it, mockfs should always be the last standard entry (and thus the last FS we attempt mountroot with) */
	{
		.vfc_vfsops = &routefs_vfsops,
		.vfc_name = "routefs",
		.vfc_typenum = FT_ROUTEFS,
		.vfc_refcount = 0,
		.vfc_flags = MNT_LOCAL,
		.vfc_mountroot = NULL,
		.vfc_next = NULL,
		.vfc_reserved1 = 0,
		.vfc_reserved2 = 0,
		.vfc_vfsflags = VFC_VFSGENERICARGS | VFC_VFS64BITREADY,
		.vfc_descptr = NULL,
		.vfc_descsize = 0,
		.vfc_sysctl = NULL
	},
#endif /* ROUTEFS */

	{
		.vfc_vfsops = NULL,
		.vfc_name = "<unassigned>",
		.vfc_typenum = 0,
		.vfc_refcount = 0,
		.vfc_flags = 0,
		.vfc_mountroot = NULL,
		.vfc_next = NULL,
		.vfc_reserved1 = 0,
		.vfc_reserved2 = 0,
		.vfc_vfsflags = 0,
		.vfc_descptr = NULL,
		.vfc_descsize = 0,
		.vfc_sysctl = NULL
	},
	{
		.vfc_vfsops = NULL,
		.vfc_name = "<unassigned>",
		.vfc_typenum = 0,
		.vfc_refcount = 0,
		.vfc_flags = 0,
		.vfc_mountroot = NULL,
		.vfc_next = NULL,
		.vfc_reserved1 = 0,
		.vfc_reserved2 = 0,
		.vfc_vfsflags = 0,
		.vfc_descptr = NULL,
		.vfc_descsize = 0,
		.vfc_sysctl = NULL
	},
};

/*
 * vfs_init will set maxvfstypenum to the highest defined type number.
 */
const int maxvfsslots = sizeof(vfstbllist) / sizeof(struct vfstable);
int numused_vfsslots = 0;
int numregistered_fses = 0;
int maxvfstypenum = VT_NON + 1;
struct vfstable *vfsconf = vfstbllist;

/*
 *
 * vfs_opv_descs enumerates the list of vnode classes, each with it's own
 * vnode operation vector.  It is consulted at system boot to build operation
 * vectors.  It is NULL terminated.
 *
 */
extern struct vnodeopv_desc mfs_vnodeop_opv_desc;
extern const struct vnodeopv_desc dead_vnodeop_opv_desc;
#if FIFO && SOCKETS
extern const struct vnodeopv_desc fifo_vnodeop_opv_desc;
#endif /* SOCKETS */
extern const struct vnodeopv_desc spec_vnodeop_opv_desc;
extern const struct vnodeopv_desc nfsv2_vnodeop_opv_desc;
extern const struct vnodeopv_desc spec_nfsv2nodeop_opv_desc;
extern const struct vnodeopv_desc fifo_nfsv2nodeop_opv_desc;
#if CONFIG_NFS4
extern const struct vnodeopv_desc nfsv4_vnodeop_opv_desc;
extern const struct vnodeopv_desc spec_nfsv4nodeop_opv_desc;
extern const struct vnodeopv_desc fifo_nfsv4nodeop_opv_desc;
#endif
extern struct vnodeopv_desc null_vnodeop_opv_desc;
extern struct vnodeopv_desc devfs_vnodeop_opv_desc;
extern struct vnodeopv_desc devfs_spec_vnodeop_opv_desc;
#if FDESC
extern struct vnodeopv_desc devfs_devfd_vnodeop_opv_desc;
extern const struct vnodeopv_desc devfs_fdesc_vnodeop_opv_desc;
#endif /* FDESC */

#if MOCKFS
extern const struct vnodeopv_desc mockfs_vnodeop_opv_desc;
#endif /* MOCKFS */

extern const struct vnodeopv_desc nullfs_vnodeop_opv_desc;

const struct vnodeopv_desc *vfs_opv_descs[] = {
	&dead_vnodeop_opv_desc,
#if FIFO && SOCKETS
	&fifo_vnodeop_opv_desc,
#endif
	&spec_vnodeop_opv_desc,
#if MFS
	&mfs_vnodeop_opv_desc,
#endif
#if CONFIG_NFS_CLIENT
	&nfsv2_vnodeop_opv_desc,
	&spec_nfsv2nodeop_opv_desc,
#if CONFIG_NFS4
	&nfsv4_vnodeop_opv_desc,
	&spec_nfsv4nodeop_opv_desc,
#endif
#if FIFO
	&fifo_nfsv2nodeop_opv_desc,
#if CONFIG_NFS4
	&fifo_nfsv4nodeop_opv_desc,
#endif /* CONFIG_NFS4 */
#endif /* FIFO */
#endif /* CONFIG_NFS_CLIENT */
#if DEVFS
	&devfs_vnodeop_opv_desc,
	&devfs_spec_vnodeop_opv_desc,
#if FDESC
	&devfs_devfd_vnodeop_opv_desc,
	&devfs_fdesc_vnodeop_opv_desc,
#endif /* FDESC */
#endif /* DEVFS */
#if NULLFS
	&nullfs_vnodeop_opv_desc,
#endif /* NULLFS */
#if MOCKFS
	&mockfs_vnodeop_opv_desc,
#endif /* MOCKFS */
	NULL
};
