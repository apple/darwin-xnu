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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mount_internal.h>
#include <sys/vnode_internal.h>

/*
 * These define the root filesystem, device, and root filesystem type.
 */
struct mount *rootfs;
struct vnode *rootvnode;
int (*mountroot)() = NULL;

/*
 * Set up the initial array of known filesystem types.
 */
extern	struct vfsops ufs_vfsops;
#if FFS
extern	int ffs_mountroot();
#endif
extern	struct vfsops mfs_vfsops;
extern	int mfs_mountroot();
extern  struct vfsops hfs_vfsops;
extern	int hfs_mountroot();
extern  struct vfsops volfs_vfsops;
extern	struct vfsops cd9660_vfsops;
extern	int cd9660_mountroot();
extern	struct vfsops nfs_vfsops;
extern	int nfs_mountroot();
extern	struct vfsops afs_vfsops;
extern	struct vfsops null_vfsops;
extern	struct vfsops union_vfsops;
extern	struct vfsops fdesc_vfsops;
extern	struct vfsops devfs_vfsops;

/*
 * Set up the filesystem operations for vnodes.
 */
static struct vfstable vfsconflist[] = {
	/* HFS/HFS+ Filesystem */
#if HFS
	{ &hfs_vfsops, "hfs", 17, 0, MNT_LOCAL | MNT_DOVOLFS, hfs_mountroot, NULL, 0, {0}, VFC_VFSLOCALARGS, 0, 0 },
#endif

	/* Fast Filesystem */
#if FFS
	{ &ufs_vfsops, "ufs", 1, 0, MNT_LOCAL, ffs_mountroot, NULL, 0, {0}, VFC_VFSLOCALARGS, 0, 0  },
#endif

	/* ISO9660 (aka CDROM) Filesystem */
#if CD9660
	{ &cd9660_vfsops, "cd9660", 14, 0, MNT_LOCAL, cd9660_mountroot, NULL, 0, {0}, VFC_VFSLOCALARGS, 0, 0 },
#endif

	/* Memory-based Filesystem */
#if MFS
	{ &mfs_vfsops, "mfs", 3, 0, MNT_LOCAL, mfs_mountroot, NULL, 0, {0}, VFC_VFSGENERICARGS , 0, 0},
#endif

	/* Sun-compatible Network Filesystem */
#if NFSCLIENT
	{ &nfs_vfsops, "nfs", 2, 0, 0, nfs_mountroot, NULL, 0, {0}, VFC_VFSGENERICARGS , 0, 0},
#endif

	/* Andrew Filesystem */
#if AFS
	{ &afs_vfsops, "andrewfs", 13, 0, 0, afs_mountroot, NULL, 0, {0}, VFC_VFSGENERICARGS , 0, 0},
#endif

	/* Loopback (Minimal) Filesystem Layer */
#if NULLFS
	{ &null_vfsops, "loopback", 9, 0, 0, NULL, NULL, 0, {0}, VFC_VFSGENERICARGS , 0, 0},
#endif

	/* Union (translucent) Filesystem */
#if UNION
	{ &union_vfsops, "union", 15, 0, 0, NULL, NULL, 0, {0}, VFC_VFSGENERICARGS , 0, 0},
#endif

	/* File Descriptor Filesystem */
#if FDESC
	{ &fdesc_vfsops, "fdesc", 7, 0, 0, NULL, NULL, 0, {0}, VFC_VFSGENERICARGS , 0, 0},
#endif

	/* Volume ID Filesystem */
#if VOLFS
	{ &volfs_vfsops, "volfs", 18, 0, 0, NULL, NULL, 0, {0}, VFC_VFSGENERICARGS , 0, 0},
#endif

	/* Device Filesystem */
#if DEVFS
	{ &devfs_vfsops, "devfs", 19, 0, 0, NULL, NULL, 0, {0}, VFC_VFSGENERICARGS , 0, 0},
#endif

	{0},
	{0},
	{0},
	{0},
	{0},
	{0},
	{0},
	{0},
	{0},
	{0},
	{0},
	{0},
	{0},
	{0}
};

/*
 * Initially the size of the list, vfs_init will set maxvfsconf
 * to the highest defined type number.
 */
int maxvfsslots = sizeof(vfsconflist) / sizeof (struct vfsconf);
int numused_vfsslots = 0;
int maxvfsconf = sizeof(vfsconflist) / sizeof (struct vfsconf);
struct vfstable *vfsconf = vfsconflist;

/*
 *
 * vfs_opv_descs enumerates the list of vnode classes, each with it's own
 * vnode operation vector.  It is consulted at system boot to build operation
 * vectors.  It is NULL terminated.
 *
 */
#if FFS
extern struct vnodeopv_desc ffs_vnodeop_opv_desc;
extern struct vnodeopv_desc ffs_specop_opv_desc;
extern struct vnodeopv_desc ffs_fifoop_opv_desc;
#endif
extern struct vnodeopv_desc mfs_vnodeop_opv_desc;
extern struct vnodeopv_desc dead_vnodeop_opv_desc;
extern struct vnodeopv_desc fifo_vnodeop_opv_desc;
extern struct vnodeopv_desc spec_vnodeop_opv_desc;
extern struct vnodeopv_desc nfsv2_vnodeop_opv_desc;
extern struct vnodeopv_desc spec_nfsv2nodeop_opv_desc;
extern struct vnodeopv_desc fifo_nfsv2nodeop_opv_desc;
extern struct vnodeopv_desc fdesc_vnodeop_opv_desc;
extern struct vnodeopv_desc null_vnodeop_opv_desc;
extern struct vnodeopv_desc hfs_vnodeop_opv_desc;
extern struct vnodeopv_desc hfs_specop_opv_desc;
extern struct vnodeopv_desc hfs_fifoop_opv_desc;
extern struct vnodeopv_desc volfs_vnodeop_opv_desc;
extern struct vnodeopv_desc cd9660_vnodeop_opv_desc;
extern struct vnodeopv_desc cd9660_cdxaop_opv_desc;
extern struct vnodeopv_desc cd9660_specop_opv_desc;
extern struct vnodeopv_desc cd9660_fifoop_opv_desc;
extern struct vnodeopv_desc union_vnodeop_opv_desc;
extern struct vnodeopv_desc devfs_vnodeop_opv_desc;
extern struct vnodeopv_desc devfs_spec_vnodeop_opv_desc;

struct vnodeopv_desc *vfs_opv_descs[] = {
#if FFS
	&ffs_vnodeop_opv_desc,
	&ffs_specop_opv_desc,
#if FIFO
	&ffs_fifoop_opv_desc,
#endif
#endif
	&dead_vnodeop_opv_desc,
#if FIFO
	&fifo_vnodeop_opv_desc,
#endif
	&spec_vnodeop_opv_desc,
#if MFS
	&mfs_vnodeop_opv_desc,
#endif
#if NFSCLIENT
	&nfsv2_vnodeop_opv_desc,
	&spec_nfsv2nodeop_opv_desc,
#if FIFO
	&fifo_nfsv2nodeop_opv_desc,
#endif
#endif
#if FDESC
	&fdesc_vnodeop_opv_desc,
#endif
#if NULLFS
	&null_vnodeop_opv_desc,
#endif
#if HFS
	&hfs_vnodeop_opv_desc,
	&hfs_specop_opv_desc,
#if FIFO
	&hfs_fifoop_opv_desc,
#endif
#endif
#if CD9660
	&cd9660_vnodeop_opv_desc,
	&cd9660_cdxaop_opv_desc,
	&cd9660_specop_opv_desc,
#if FIFO
	&cd9660_fifoop_opv_desc,
#endif
#endif
#if UNION
	&union_vnodeop_opv_desc,
#endif
#if VOLFS
	&volfs_vnodeop_opv_desc,
#endif
#if DEVFS
	&devfs_vnodeop_opv_desc,
	&devfs_spec_vnodeop_opv_desc,
#endif
	NULL
};
