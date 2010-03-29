/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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

#ifndef __LP64__ 
#define VFS_THREAD_SAFE_FLAG VFC_VFSTHREADSAFE /* This is only defined for 32-bit */
#else 
#define VFS_THREAD_SAFE_FLAG 0
#endif /* __LP64__  */


/*
 * These define the root filesystem, device, and root filesystem type.
 */
struct mount *rootfs;
struct vnode *rootvnode;

#ifdef CONFIG_IMGSRC_ACCESS
struct vnode *imgsrc_rootvnode;
#endif /* IMGSRC_ACESS */

int (*mountroot)(void) = NULL;

/*
 * Set up the initial array of known filesystem types.
 */
extern	struct vfsops mfs_vfsops;
extern	int mfs_mountroot(mount_t, vnode_t, vfs_context_t);	/* dead */
extern  struct vfsops hfs_vfsops;
extern	int hfs_mountroot(mount_t, vnode_t, vfs_context_t);
extern	struct vfsops nfs_vfsops;
extern	int nfs_mountroot(void);
extern	struct vfsops afs_vfsops;
extern	struct vfsops null_vfsops;
extern	struct vfsops union_vfsops;
extern	struct vfsops devfs_vfsops;

/*
 * For nfs_mountroot(void) cast.  nfs_mountroot ignores its parameters, if
 * invoked through this table.
 */
typedef int (*mountroot_t)(mount_t, vnode_t, vfs_context_t);

/*
 * Set up the filesystem operations for vnodes.
 */
static struct vfstable vfstbllist[] = {
	/* HFS/HFS+ Filesystem */
#if HFS
	{ &hfs_vfsops, "hfs", 17, 0, (MNT_LOCAL | MNT_DOVOLFS), hfs_mountroot, NULL, 0, 0, VFC_VFSLOCALARGS | VFC_VFSREADDIR_EXTENDED | VFS_THREAD_SAFE_FLAG | VFC_VFS64BITREADY | VFC_VFSVNOP_PAGEOUTV2, NULL, 0},
#endif

	/* Memory-based Filesystem */

#ifndef __LP64__
#if MFS
	{ &mfs_vfsops, "mfs", 3, 0, MNT_LOCAL, mfs_mountroot, NULL, 0, 0, VFC_VFSGENERICARGS, NULL, 0},
#endif
#endif /* __LP64__ */

	/* Sun-compatible Network Filesystem */
#if NFSCLIENT
	{ &nfs_vfsops, "nfs", 2, 0, 0, NULL, NULL, 0, 0, VFC_VFSGENERICARGS | VFC_VFSPREFLIGHT | VFS_THREAD_SAFE_FLAG | VFC_VFS64BITREADY | VFC_VFSREADDIR_EXTENDED, NULL, 0},
#endif

	/* Andrew Filesystem */
#ifndef __LP64__
#if AFS
	{ &afs_vfsops, "andrewfs", 13, 0, 0, afs_mountroot, NULL, 0, 0, VFC_VFSGENERICARGS , NULL, 0},
#endif
#endif /* __LP64__ */

	/* Loopback (Minimal) Filesystem Layer */
#ifndef __LP64__
#if NULLFS
	{ &null_vfsops, "loopback", 9, 0, 0, NULL, NULL, 0, 0, VFC_VFSGENERICARGS , NULL, 0},
#endif
#endif /* __LP64__ */

	/* Union (translucent) Filesystem */
#if UNION
	{ &union_vfsops, "unionfs", 15, 0, 0, NULL, NULL, 0, 0, VFC_VFSGENERICARGS | VFS_THREAD_SAFE_FLAG | VFC_VFS64BITREADY, NULL, 0},
#endif

	/* Device Filesystem */
#if DEVFS
#if CONFIG_MACF
	{ &devfs_vfsops, "devfs", 19, 0, (MNT_DONTBROWSE | MNT_MULTILABEL), NULL, NULL, 0, 0, VFC_VFSGENERICARGS | VFS_THREAD_SAFE_FLAG | VFC_VFS64BITREADY, NULL, 0},
#else
	{ &devfs_vfsops, "devfs", 19, 0, MNT_DONTBROWSE, NULL, NULL, 0, 0, VFC_VFSGENERICARGS | VFS_THREAD_SAFE_FLAG | VFC_VFS64BITREADY, NULL, 0},
#endif /* MAC */
#endif

#ifndef __LP64__
#endif /* __LP64__ */

	{NULL, "<unassigned>", 0, 0, 0, NULL, NULL, 0, 0, 0, NULL, 0},
	{NULL, "<unassigned>", 0, 0, 0, NULL, NULL, 0, 0, 0, NULL, 0},
	{NULL, "<unassigned>", 0, 0, 0, NULL, NULL, 0, 0, 0, NULL, 0},
	{NULL, "<unassigned>", 0, 0, 0, NULL, NULL, 0, 0, 0, NULL, 0},
	{NULL, "<unassigned>", 0, 0, 0, NULL, NULL, 0, 0, 0, NULL, 0},
	{NULL, "<unassigned>", 0, 0, 0, NULL, NULL, 0, 0, 0, NULL, 0},
	{NULL, "<unassigned>", 0, 0, 0, NULL, NULL, 0, 0, 0, NULL, 0},
	{NULL, "<unassigned>", 0, 0, 0, NULL, NULL, 0, 0, 0, NULL, 0},
	{NULL, "<unassigned>", 0, 0, 0, NULL, NULL, 0, 0, 0, NULL, 0},
	{NULL, "<unassigned>", 0, 0, 0, NULL, NULL, 0, 0, 0, NULL, 0},
	{NULL, "<unassigned>", 0, 0, 0, NULL, NULL, 0, 0, 0, NULL, 0},
	{NULL, "<unassigned>", 0, 0, 0, NULL, NULL, 0, 0, 0, NULL, 0},
	{NULL, "<unassigned>", 0, 0, 0, NULL, NULL, 0, 0, 0, NULL, 0},
	{NULL, "<unassigned>", 0, 0, 0, NULL, NULL, 0, 0, 0, NULL, 0},
	{NULL, "<unassigned>", 0, 0, 0, NULL, NULL, 0, 0, 0, NULL, 0}
};

/*
 * Initially the size of the list, vfs_init will set maxvfsconf
 * to the highest defined type number.
 */
int maxvfsslots = sizeof(vfstbllist) / sizeof (struct vfstable);
int numused_vfsslots = 0;
int maxvfsconf = sizeof(vfstbllist) / sizeof (struct vfstable);
struct vfstable *vfsconf = vfstbllist;

/*
 *
 * vfs_opv_descs enumerates the list of vnode classes, each with it's own
 * vnode operation vector.  It is consulted at system boot to build operation
 * vectors.  It is NULL terminated.
 *
 */
extern struct vnodeopv_desc mfs_vnodeop_opv_desc;
extern struct vnodeopv_desc dead_vnodeop_opv_desc;
#if FIFO && SOCKETS
extern struct vnodeopv_desc fifo_vnodeop_opv_desc;
#endif /* SOCKETS */
extern struct vnodeopv_desc spec_vnodeop_opv_desc;
extern struct vnodeopv_desc nfsv2_vnodeop_opv_desc;
extern struct vnodeopv_desc spec_nfsv2nodeop_opv_desc;
extern struct vnodeopv_desc fifo_nfsv2nodeop_opv_desc;
extern struct vnodeopv_desc nfsv4_vnodeop_opv_desc;
extern struct vnodeopv_desc spec_nfsv4nodeop_opv_desc;
extern struct vnodeopv_desc fifo_nfsv4nodeop_opv_desc;
extern struct vnodeopv_desc null_vnodeop_opv_desc;
extern struct vnodeopv_desc hfs_vnodeop_opv_desc;
extern struct vnodeopv_desc hfs_std_vnodeop_opv_desc;
extern struct vnodeopv_desc hfs_specop_opv_desc;
extern struct vnodeopv_desc hfs_fifoop_opv_desc;
extern struct vnodeopv_desc union_vnodeop_opv_desc;
extern struct vnodeopv_desc devfs_vnodeop_opv_desc;
extern struct vnodeopv_desc devfs_spec_vnodeop_opv_desc;
#if FDESC
extern struct vnodeopv_desc devfs_devfd_vnodeop_opv_desc;
extern struct vnodeopv_desc devfs_fdesc_vnodeop_opv_desc;
#endif /* FDESC */

struct vnodeopv_desc *vfs_opv_descs[] = {
	&dead_vnodeop_opv_desc,
#if FIFO && SOCKETS
	&fifo_vnodeop_opv_desc,
#endif
	&spec_vnodeop_opv_desc,
#if MFS
	&mfs_vnodeop_opv_desc,
#endif
#if NFSCLIENT
	&nfsv2_vnodeop_opv_desc,
	&spec_nfsv2nodeop_opv_desc,
	&nfsv4_vnodeop_opv_desc,
	&spec_nfsv4nodeop_opv_desc,
#if FIFO
	&fifo_nfsv2nodeop_opv_desc,
	&fifo_nfsv4nodeop_opv_desc,
#endif
#endif
#if NULLFS
	&null_vnodeop_opv_desc,
#endif
#if HFS
	&hfs_vnodeop_opv_desc,
	&hfs_std_vnodeop_opv_desc,
	&hfs_specop_opv_desc,
#if FIFO
	&hfs_fifoop_opv_desc,
#endif
#endif
#if UNION
	&union_vnodeop_opv_desc,
#endif
#if DEVFS
	&devfs_vnodeop_opv_desc,
	&devfs_spec_vnodeop_opv_desc,
#if FDESC
	&devfs_devfd_vnodeop_opv_desc,
	&devfs_fdesc_vnodeop_opv_desc,
#endif /* FDESC */
#endif /* DEVFS */
	NULL
};
