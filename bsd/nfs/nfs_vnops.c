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
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Rick Macklem at The University of Guelph.
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
 *	@(#)nfs_vnops.c	8.16 (Berkeley) 5/27/95
 * FreeBSD-Id: nfs_vnops.c,v 1.72 1997/11/07 09:20:48 phk Exp $
 */


/*
 * vnode op calls for Sun NFS version 2 and 3
 */
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/resourcevar.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/mount_internal.h>
#include <sys/malloc.h>
#include <sys/kpi_mbuf.h>
#include <sys/conf.h>
#include <sys/vnode_internal.h>
#include <sys/dirent.h>
#include <sys/fcntl.h>
#include <sys/lockf.h>
#include <sys/ubc_internal.h>
#include <sys/attr.h>
#include <sys/signalvar.h>
#include <sys/uio_internal.h>

#include <vfs/vfs_support.h>

#include <sys/vm.h>

#include <sys/time.h>
#include <kern/clock.h>
#include <libkern/OSAtomic.h>

#include <miscfs/fifofs/fifo.h>
#include <miscfs/specfs/specdev.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfsnode.h>
#include <nfs/nfs_gss.h>
#include <nfs/nfsmount.h>
#include <nfs/nfs_lock.h>
#include <nfs/xdr_subs.h>
#include <nfs/nfsm_subs.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <vm/vm_kern.h>

#include <kern/task.h>
#include <kern/sched_prim.h>
#include <libkern/OSAtomic.h>

/*
 * NFS vnode ops
 */
static int	nfs_vnop_lookup(struct vnop_lookup_args *);
static int	nfsspec_vnop_read(struct vnop_read_args *);
static int	nfsspec_vnop_write(struct vnop_write_args *);
static int	nfsspec_vnop_close(struct vnop_close_args *);
#if FIFO
static int	nfsfifo_vnop_read(struct vnop_read_args *);
static int	nfsfifo_vnop_write(struct vnop_write_args *);
static int	nfsfifo_vnop_close(struct vnop_close_args *);
#endif
static int	nfs_vnop_ioctl(struct vnop_ioctl_args *);
static int	nfs_vnop_select(struct vnop_select_args *);
static int	nfs_vnop_setattr(struct vnop_setattr_args *);
static int	nfs_vnop_read(struct vnop_read_args *);
static int	nfs_vnop_mmap(struct vnop_mmap_args *);
static int	nfs_vnop_fsync(struct vnop_fsync_args *);
static int	nfs_vnop_remove(struct vnop_remove_args *);
static int	nfs_vnop_rename(struct vnop_rename_args *);
static int	nfs_vnop_readdir(struct vnop_readdir_args *);
static int	nfs_vnop_readlink(struct vnop_readlink_args *);
static int	nfs_vnop_pathconf(struct vnop_pathconf_args *);
static int	nfs_vnop_pagein(struct vnop_pagein_args *);
static int	nfs_vnop_pageout(struct vnop_pageout_args *);
static int	nfs_vnop_blktooff(struct vnop_blktooff_args *);
static int	nfs_vnop_offtoblk(struct vnop_offtoblk_args *);
static int	nfs_vnop_blockmap(struct vnop_blockmap_args *);

static int	nfs3_vnop_create(struct vnop_create_args *);
static int	nfs3_vnop_mknod(struct vnop_mknod_args *);
static int	nfs3_vnop_getattr(struct vnop_getattr_args *);
static int	nfs3_vnop_link(struct vnop_link_args *);
static int	nfs3_vnop_mkdir(struct vnop_mkdir_args *);
static int	nfs3_vnop_rmdir(struct vnop_rmdir_args *);
static int	nfs3_vnop_symlink(struct vnop_symlink_args *);

vnop_t **nfsv2_vnodeop_p;
static struct vnodeopv_entry_desc nfsv2_vnodeop_entries[] = {
	{ &vnop_default_desc, (vnop_t *)vn_default_error },
	{ &vnop_lookup_desc, (vnop_t *)nfs_vnop_lookup },	/* lookup */
	{ &vnop_create_desc, (vnop_t *)nfs3_vnop_create },	/* create */
	{ &vnop_mknod_desc, (vnop_t *)nfs3_vnop_mknod },	/* mknod */
	{ &vnop_open_desc, (vnop_t *)nfs3_vnop_open },		/* open */
	{ &vnop_close_desc, (vnop_t *)nfs3_vnop_close },	/* close */
	{ &vnop_access_desc, (vnop_t *)nfs_vnop_access },	/* access */
	{ &vnop_getattr_desc, (vnop_t *)nfs3_vnop_getattr },	/* getattr */
	{ &vnop_setattr_desc, (vnop_t *)nfs_vnop_setattr },	/* setattr */
	{ &vnop_read_desc, (vnop_t *)nfs_vnop_read },		/* read */
	{ &vnop_write_desc, (vnop_t *)nfs_vnop_write },		/* write */
	{ &vnop_ioctl_desc, (vnop_t *)nfs_vnop_ioctl },		/* ioctl */
	{ &vnop_select_desc, (vnop_t *)nfs_vnop_select },	/* select */
	{ &vnop_revoke_desc, (vnop_t *)nfs_vnop_revoke },	/* revoke */
	{ &vnop_mmap_desc, (vnop_t *)nfs_vnop_mmap },		/* mmap */
	{ &vnop_fsync_desc, (vnop_t *)nfs_vnop_fsync },		/* fsync */
	{ &vnop_remove_desc, (vnop_t *)nfs_vnop_remove },	/* remove */
	{ &vnop_link_desc, (vnop_t *)nfs3_vnop_link },		/* link */
	{ &vnop_rename_desc, (vnop_t *)nfs_vnop_rename },	/* rename */
	{ &vnop_mkdir_desc, (vnop_t *)nfs3_vnop_mkdir },	/* mkdir */
	{ &vnop_rmdir_desc, (vnop_t *)nfs3_vnop_rmdir },	/* rmdir */
	{ &vnop_symlink_desc, (vnop_t *)nfs3_vnop_symlink },	/* symlink */
	{ &vnop_readdir_desc, (vnop_t *)nfs_vnop_readdir },	/* readdir */
	{ &vnop_readlink_desc, (vnop_t *)nfs_vnop_readlink },	/* readlink */
	{ &vnop_inactive_desc, (vnop_t *)nfs_vnop_inactive },	/* inactive */
	{ &vnop_reclaim_desc, (vnop_t *)nfs_vnop_reclaim },	/* reclaim */
	{ &vnop_strategy_desc, (vnop_t *)err_strategy },	/* strategy */
	{ &vnop_pathconf_desc, (vnop_t *)nfs_vnop_pathconf },	/* pathconf */
	{ &vnop_advlock_desc, (vnop_t *)nfs3_vnop_advlock },	/* advlock */
	{ &vnop_bwrite_desc, (vnop_t *)err_bwrite },		/* bwrite */
	{ &vnop_pagein_desc, (vnop_t *)nfs_vnop_pagein },	/* Pagein */
	{ &vnop_pageout_desc, (vnop_t *)nfs_vnop_pageout },	/* Pageout */
	{ &vnop_copyfile_desc, (vnop_t *)err_copyfile },	/* Copyfile */
	{ &vnop_blktooff_desc, (vnop_t *)nfs_vnop_blktooff },	/* blktooff */
	{ &vnop_offtoblk_desc, (vnop_t *)nfs_vnop_offtoblk },	/* offtoblk */
	{ &vnop_blockmap_desc, (vnop_t *)nfs_vnop_blockmap },	/* blockmap */
	{ NULL, NULL }
};
struct vnodeopv_desc nfsv2_vnodeop_opv_desc =
	{ &nfsv2_vnodeop_p, nfsv2_vnodeop_entries };

vnop_t **nfsv4_vnodeop_p;
static struct vnodeopv_entry_desc nfsv4_vnodeop_entries[] = {
	{ &vnop_default_desc, (vnop_t *)vn_default_error },
	{ &vnop_lookup_desc, (vnop_t *)nfs_vnop_lookup },	/* lookup */
	{ &vnop_create_desc, (vnop_t *)nfs4_vnop_create },	/* create */
	{ &vnop_mknod_desc, (vnop_t *)nfs4_vnop_mknod },	/* mknod */
	{ &vnop_open_desc, (vnop_t *)nfs4_vnop_open },		/* open */
	{ &vnop_close_desc, (vnop_t *)nfs4_vnop_close },	/* close */
	{ &vnop_access_desc, (vnop_t *)nfs_vnop_access },	/* access */
	{ &vnop_getattr_desc, (vnop_t *)nfs4_vnop_getattr },	/* getattr */
	{ &vnop_setattr_desc, (vnop_t *)nfs_vnop_setattr },	/* setattr */
	{ &vnop_read_desc, (vnop_t *)nfs_vnop_read },		/* read */
	{ &vnop_write_desc, (vnop_t *)nfs_vnop_write },		/* write */
	{ &vnop_ioctl_desc, (vnop_t *)nfs_vnop_ioctl },		/* ioctl */
	{ &vnop_select_desc, (vnop_t *)nfs_vnop_select },	/* select */
	{ &vnop_revoke_desc, (vnop_t *)nfs_vnop_revoke },	/* revoke */
	{ &vnop_mmap_desc, (vnop_t *)nfs_vnop_mmap },		/* mmap */
	{ &vnop_fsync_desc, (vnop_t *)nfs_vnop_fsync },		/* fsync */
	{ &vnop_remove_desc, (vnop_t *)nfs_vnop_remove },	/* remove */
	{ &vnop_link_desc, (vnop_t *)nfs4_vnop_link },		/* link */
	{ &vnop_rename_desc, (vnop_t *)nfs_vnop_rename },	/* rename */
	{ &vnop_mkdir_desc, (vnop_t *)nfs4_vnop_mkdir },	/* mkdir */
	{ &vnop_rmdir_desc, (vnop_t *)nfs4_vnop_rmdir },	/* rmdir */
	{ &vnop_symlink_desc, (vnop_t *)nfs4_vnop_symlink },	/* symlink */
	{ &vnop_readdir_desc, (vnop_t *)nfs_vnop_readdir },	/* readdir */
	{ &vnop_readlink_desc, (vnop_t *)nfs_vnop_readlink },	/* readlink */
	{ &vnop_inactive_desc, (vnop_t *)nfs_vnop_inactive },	/* inactive */
	{ &vnop_reclaim_desc, (vnop_t *)nfs_vnop_reclaim },	/* reclaim */
	{ &vnop_strategy_desc, (vnop_t *)err_strategy },	/* strategy */
	{ &vnop_pathconf_desc, (vnop_t *)nfs_vnop_pathconf },	/* pathconf */
	{ &vnop_advlock_desc, (vnop_t *)nfs4_vnop_advlock },	/* advlock */
	{ &vnop_bwrite_desc, (vnop_t *)err_bwrite },		/* bwrite */
	{ &vnop_pagein_desc, (vnop_t *)nfs_vnop_pagein },	/* Pagein */
	{ &vnop_pageout_desc, (vnop_t *)nfs_vnop_pageout },	/* Pageout */
	{ &vnop_copyfile_desc, (vnop_t *)err_copyfile },	/* Copyfile */
	{ &vnop_blktooff_desc, (vnop_t *)nfs_vnop_blktooff },	/* blktooff */
	{ &vnop_offtoblk_desc, (vnop_t *)nfs_vnop_offtoblk },	/* offtoblk */
	{ &vnop_blockmap_desc, (vnop_t *)nfs_vnop_blockmap },	/* blockmap */
	{ NULL, NULL }
};
struct vnodeopv_desc nfsv4_vnodeop_opv_desc =
	{ &nfsv4_vnodeop_p, nfsv4_vnodeop_entries };

/*
 * Special device vnode ops
 */
vnop_t **spec_nfsv2nodeop_p;
static struct vnodeopv_entry_desc spec_nfsv2nodeop_entries[] = {
	{ &vnop_default_desc, (vnop_t *)vn_default_error },
	{ &vnop_lookup_desc, (vnop_t *)spec_lookup },		/* lookup */
	{ &vnop_create_desc, (vnop_t *)spec_create },		/* create */
	{ &vnop_mknod_desc, (vnop_t *)spec_mknod },		/* mknod */
	{ &vnop_open_desc, (vnop_t *)spec_open },		/* open */
	{ &vnop_close_desc, (vnop_t *)nfsspec_vnop_close },	/* close */
	{ &vnop_getattr_desc, (vnop_t *)nfs3_vnop_getattr },	/* getattr */
	{ &vnop_setattr_desc, (vnop_t *)nfs_vnop_setattr },	/* setattr */
	{ &vnop_read_desc, (vnop_t *)nfsspec_vnop_read },	/* read */
	{ &vnop_write_desc, (vnop_t *)nfsspec_vnop_write },	/* write */
	{ &vnop_ioctl_desc, (vnop_t *)spec_ioctl },		/* ioctl */
	{ &vnop_select_desc, (vnop_t *)spec_select },		/* select */
	{ &vnop_revoke_desc, (vnop_t *)spec_revoke },		/* revoke */
	{ &vnop_mmap_desc, (vnop_t *)spec_mmap },		/* mmap */
	{ &vnop_fsync_desc, (vnop_t *)nfs_vnop_fsync },		/* fsync */
	{ &vnop_remove_desc, (vnop_t *)spec_remove },		/* remove */
	{ &vnop_link_desc, (vnop_t *)spec_link },		/* link */
	{ &vnop_rename_desc, (vnop_t *)spec_rename },		/* rename */
	{ &vnop_mkdir_desc, (vnop_t *)spec_mkdir },		/* mkdir */
	{ &vnop_rmdir_desc, (vnop_t *)spec_rmdir },		/* rmdir */
	{ &vnop_symlink_desc, (vnop_t *)spec_symlink },		/* symlink */
	{ &vnop_readdir_desc, (vnop_t *)spec_readdir },		/* readdir */
	{ &vnop_readlink_desc, (vnop_t *)spec_readlink },	/* readlink */
	{ &vnop_inactive_desc, (vnop_t *)nfs_vnop_inactive },	/* inactive */
	{ &vnop_reclaim_desc, (vnop_t *)nfs_vnop_reclaim },	/* reclaim */
	{ &vnop_strategy_desc, (vnop_t *)spec_strategy },	/* strategy */
	{ &vnop_pathconf_desc, (vnop_t *)spec_pathconf },	/* pathconf */
	{ &vnop_advlock_desc, (vnop_t *)spec_advlock },		/* advlock */
	{ &vnop_bwrite_desc, (vnop_t *)vn_bwrite },		/* bwrite */
	{ &vnop_pagein_desc, (vnop_t *)nfs_vnop_pagein },	/* Pagein */
	{ &vnop_pageout_desc, (vnop_t *)nfs_vnop_pageout },	/* Pageout */
	{ &vnop_blktooff_desc, (vnop_t *)nfs_vnop_blktooff },	/* blktooff */
	{ &vnop_offtoblk_desc, (vnop_t *)nfs_vnop_offtoblk },	/* offtoblk */
	{ &vnop_blockmap_desc, (vnop_t *)nfs_vnop_blockmap },	/* blockmap */
	{ NULL, NULL }
};
struct vnodeopv_desc spec_nfsv2nodeop_opv_desc =
	{ &spec_nfsv2nodeop_p, spec_nfsv2nodeop_entries };
vnop_t **spec_nfsv4nodeop_p;
static struct vnodeopv_entry_desc spec_nfsv4nodeop_entries[] = {
	{ &vnop_default_desc, (vnop_t *)vn_default_error },
	{ &vnop_lookup_desc, (vnop_t *)spec_lookup },		/* lookup */
	{ &vnop_create_desc, (vnop_t *)spec_create },		/* create */
	{ &vnop_mknod_desc, (vnop_t *)spec_mknod },		/* mknod */
	{ &vnop_open_desc, (vnop_t *)spec_open },		/* open */
	{ &vnop_close_desc, (vnop_t *)nfsspec_vnop_close },	/* close */
	{ &vnop_getattr_desc, (vnop_t *)nfs4_vnop_getattr },	/* getattr */
	{ &vnop_setattr_desc, (vnop_t *)nfs_vnop_setattr },	/* setattr */
	{ &vnop_read_desc, (vnop_t *)nfsspec_vnop_read },	/* read */
	{ &vnop_write_desc, (vnop_t *)nfsspec_vnop_write },	/* write */
	{ &vnop_ioctl_desc, (vnop_t *)spec_ioctl },		/* ioctl */
	{ &vnop_select_desc, (vnop_t *)spec_select },		/* select */
	{ &vnop_revoke_desc, (vnop_t *)spec_revoke },		/* revoke */
	{ &vnop_mmap_desc, (vnop_t *)spec_mmap },		/* mmap */
	{ &vnop_fsync_desc, (vnop_t *)nfs_vnop_fsync },		/* fsync */
	{ &vnop_remove_desc, (vnop_t *)spec_remove },		/* remove */
	{ &vnop_link_desc, (vnop_t *)spec_link },		/* link */
	{ &vnop_rename_desc, (vnop_t *)spec_rename },		/* rename */
	{ &vnop_mkdir_desc, (vnop_t *)spec_mkdir },		/* mkdir */
	{ &vnop_rmdir_desc, (vnop_t *)spec_rmdir },		/* rmdir */
	{ &vnop_symlink_desc, (vnop_t *)spec_symlink },		/* symlink */
	{ &vnop_readdir_desc, (vnop_t *)spec_readdir },		/* readdir */
	{ &vnop_readlink_desc, (vnop_t *)spec_readlink },	/* readlink */
	{ &vnop_inactive_desc, (vnop_t *)nfs_vnop_inactive },	/* inactive */
	{ &vnop_reclaim_desc, (vnop_t *)nfs_vnop_reclaim },	/* reclaim */
	{ &vnop_strategy_desc, (vnop_t *)spec_strategy },	/* strategy */
	{ &vnop_pathconf_desc, (vnop_t *)spec_pathconf },	/* pathconf */
	{ &vnop_advlock_desc, (vnop_t *)spec_advlock },		/* advlock */
	{ &vnop_bwrite_desc, (vnop_t *)vn_bwrite },		/* bwrite */
	{ &vnop_pagein_desc, (vnop_t *)nfs_vnop_pagein },	/* Pagein */
	{ &vnop_pageout_desc, (vnop_t *)nfs_vnop_pageout },	/* Pageout */
	{ &vnop_blktooff_desc, (vnop_t *)nfs_vnop_blktooff },	/* blktooff */
	{ &vnop_offtoblk_desc, (vnop_t *)nfs_vnop_offtoblk },	/* offtoblk */
	{ &vnop_blockmap_desc, (vnop_t *)nfs_vnop_blockmap },	/* blockmap */
	{ NULL, NULL }
};
struct vnodeopv_desc spec_nfsv4nodeop_opv_desc =
	{ &spec_nfsv4nodeop_p, spec_nfsv4nodeop_entries };

#if FIFO
vnop_t **fifo_nfsv2nodeop_p;
static struct vnodeopv_entry_desc fifo_nfsv2nodeop_entries[] = {
	{ &vnop_default_desc, (vnop_t *)vn_default_error },
	{ &vnop_lookup_desc, (vnop_t *)fifo_lookup },		/* lookup */
	{ &vnop_create_desc, (vnop_t *)fifo_create },		/* create */
	{ &vnop_mknod_desc, (vnop_t *)fifo_mknod },		/* mknod */
	{ &vnop_open_desc, (vnop_t *)fifo_open },		/* open */
	{ &vnop_close_desc, (vnop_t *)nfsfifo_vnop_close },	/* close */
	{ &vnop_getattr_desc, (vnop_t *)nfs3_vnop_getattr },	/* getattr */
	{ &vnop_setattr_desc, (vnop_t *)nfs_vnop_setattr },	/* setattr */
	{ &vnop_read_desc, (vnop_t *)nfsfifo_vnop_read },	/* read */
	{ &vnop_write_desc, (vnop_t *)nfsfifo_vnop_write },	/* write */
	{ &vnop_ioctl_desc, (vnop_t *)fifo_ioctl },		/* ioctl */
	{ &vnop_select_desc, (vnop_t *)fifo_select },		/* select */
	{ &vnop_revoke_desc, (vnop_t *)fifo_revoke },		/* revoke */
	{ &vnop_mmap_desc, (vnop_t *)fifo_mmap },		/* mmap */
	{ &vnop_fsync_desc, (vnop_t *)nfs_vnop_fsync },		/* fsync */
	{ &vnop_remove_desc, (vnop_t *)fifo_remove },		/* remove */
	{ &vnop_link_desc, (vnop_t *)fifo_link },		/* link */
	{ &vnop_rename_desc, (vnop_t *)fifo_rename },		/* rename */
	{ &vnop_mkdir_desc, (vnop_t *)fifo_mkdir },		/* mkdir */
	{ &vnop_rmdir_desc, (vnop_t *)fifo_rmdir },		/* rmdir */
	{ &vnop_symlink_desc, (vnop_t *)fifo_symlink },		/* symlink */
	{ &vnop_readdir_desc, (vnop_t *)fifo_readdir },		/* readdir */
	{ &vnop_readlink_desc, (vnop_t *)fifo_readlink },	/* readlink */
	{ &vnop_inactive_desc, (vnop_t *)nfs_vnop_inactive },	/* inactive */
	{ &vnop_reclaim_desc, (vnop_t *)nfs_vnop_reclaim },	/* reclaim */
	{ &vnop_strategy_desc, (vnop_t *)fifo_strategy },	/* strategy */
	{ &vnop_pathconf_desc, (vnop_t *)fifo_pathconf },	/* pathconf */
	{ &vnop_advlock_desc, (vnop_t *)fifo_advlock },		/* advlock */
	{ &vnop_bwrite_desc, (vnop_t *)vn_bwrite },		/* bwrite */
	{ &vnop_pagein_desc, (vnop_t *)nfs_vnop_pagein },	/* Pagein */
	{ &vnop_pageout_desc, (vnop_t *)nfs_vnop_pageout },	/* Pageout */
	{ &vnop_blktooff_desc, (vnop_t *)nfs_vnop_blktooff },	/* blktooff */
	{ &vnop_offtoblk_desc, (vnop_t *)nfs_vnop_offtoblk },	/* offtoblk */
	{ &vnop_blockmap_desc, (vnop_t *)nfs_vnop_blockmap },	/* blockmap */
	{ NULL, NULL }
};
struct vnodeopv_desc fifo_nfsv2nodeop_opv_desc =
	{ &fifo_nfsv2nodeop_p, fifo_nfsv2nodeop_entries };

vnop_t **fifo_nfsv4nodeop_p;
static struct vnodeopv_entry_desc fifo_nfsv4nodeop_entries[] = {
	{ &vnop_default_desc, (vnop_t *)vn_default_error },
	{ &vnop_lookup_desc, (vnop_t *)fifo_lookup },		/* lookup */
	{ &vnop_create_desc, (vnop_t *)fifo_create },		/* create */
	{ &vnop_mknod_desc, (vnop_t *)fifo_mknod },		/* mknod */
	{ &vnop_open_desc, (vnop_t *)fifo_open },		/* open */
	{ &vnop_close_desc, (vnop_t *)nfsfifo_vnop_close },	/* close */
	{ &vnop_getattr_desc, (vnop_t *)nfs4_vnop_getattr },	/* getattr */
	{ &vnop_setattr_desc, (vnop_t *)nfs_vnop_setattr },	/* setattr */
	{ &vnop_read_desc, (vnop_t *)nfsfifo_vnop_read },	/* read */
	{ &vnop_write_desc, (vnop_t *)nfsfifo_vnop_write },	/* write */
	{ &vnop_ioctl_desc, (vnop_t *)fifo_ioctl },		/* ioctl */
	{ &vnop_select_desc, (vnop_t *)fifo_select },		/* select */
	{ &vnop_revoke_desc, (vnop_t *)fifo_revoke },		/* revoke */
	{ &vnop_mmap_desc, (vnop_t *)fifo_mmap },		/* mmap */
	{ &vnop_fsync_desc, (vnop_t *)nfs_vnop_fsync },		/* fsync */
	{ &vnop_remove_desc, (vnop_t *)fifo_remove },		/* remove */
	{ &vnop_link_desc, (vnop_t *)fifo_link },		/* link */
	{ &vnop_rename_desc, (vnop_t *)fifo_rename },		/* rename */
	{ &vnop_mkdir_desc, (vnop_t *)fifo_mkdir },		/* mkdir */
	{ &vnop_rmdir_desc, (vnop_t *)fifo_rmdir },		/* rmdir */
	{ &vnop_symlink_desc, (vnop_t *)fifo_symlink },		/* symlink */
	{ &vnop_readdir_desc, (vnop_t *)fifo_readdir },		/* readdir */
	{ &vnop_readlink_desc, (vnop_t *)fifo_readlink },	/* readlink */
	{ &vnop_inactive_desc, (vnop_t *)nfs_vnop_inactive },	/* inactive */
	{ &vnop_reclaim_desc, (vnop_t *)nfs_vnop_reclaim },	/* reclaim */
	{ &vnop_strategy_desc, (vnop_t *)fifo_strategy },	/* strategy */
	{ &vnop_pathconf_desc, (vnop_t *)fifo_pathconf },	/* pathconf */
	{ &vnop_advlock_desc, (vnop_t *)fifo_advlock },		/* advlock */
	{ &vnop_bwrite_desc, (vnop_t *)vn_bwrite },		/* bwrite */
	{ &vnop_pagein_desc, (vnop_t *)nfs_vnop_pagein },	/* Pagein */
	{ &vnop_pageout_desc, (vnop_t *)nfs_vnop_pageout },	/* Pageout */
	{ &vnop_blktooff_desc, (vnop_t *)nfs_vnop_blktooff },	/* blktooff */
	{ &vnop_offtoblk_desc, (vnop_t *)nfs_vnop_offtoblk },	/* offtoblk */
	{ &vnop_blockmap_desc, (vnop_t *)nfs_vnop_blockmap },	/* blockmap */
	{ NULL, NULL }
};
struct vnodeopv_desc fifo_nfsv4nodeop_opv_desc =
	{ &fifo_nfsv4nodeop_p, fifo_nfsv4nodeop_entries };
#endif /* FIFO */


static int	nfs_sillyrename(nfsnode_t,nfsnode_t,struct componentname *,vfs_context_t);

/*
 * Find the slot in the access cache for this UID.
 * If adding and no existing slot is found, reuse slots in FIFO order.
 * The index of the next slot to use is kept in the last entry of the n_mode array.
 */
int
nfs_node_mode_slot(nfsnode_t np, uid_t uid, int add)
{
	int slot;

	for (slot=0; slot < NFS_ACCESS_CACHE_SIZE; slot++)
		if (np->n_modeuid[slot] == uid)
			break;
	if (slot == NFS_ACCESS_CACHE_SIZE) {
		if (!add)
			return (-1);
		slot = np->n_mode[NFS_ACCESS_CACHE_SIZE];
		np->n_mode[NFS_ACCESS_CACHE_SIZE] = (slot + 1) % NFS_ACCESS_CACHE_SIZE;
	}
	return (slot);
}

int
nfs3_access_rpc(nfsnode_t np, u_long *mode, vfs_context_t ctx)
{
	int error = 0, status, slot;
	uint32_t access = 0;
	u_int64_t xid;
	struct nfsm_chain nmreq, nmrep;
	struct timeval now;
	uid_t uid;

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	nfsm_chain_build_alloc_init(error, &nmreq, NFSX_FH(NFS_VER3) + NFSX_UNSIGNED);
	nfsm_chain_add_fh(error, &nmreq, NFS_VER3, np->n_fhp, np->n_fhsize);
	nfsm_chain_add_32(error, &nmreq, *mode);
	nfsm_chain_build_done(error, &nmreq);
	nfsmout_if(error);
	error = nfs_request(np, NULL, &nmreq, NFSPROC_ACCESS, ctx,
			&nmrep, &xid, &status);
	nfsm_chain_postop_attr_update(error, &nmrep, np, &xid);
	if (!error)
		error = status;
	nfsm_chain_get_32(error, &nmrep, access);
	nfsmout_if(error);

	uid = kauth_cred_getuid(vfs_context_ucred(ctx));
	slot = nfs_node_mode_slot(np, uid, 1);
	np->n_modeuid[slot] = uid;
	microuptime(&now);
	np->n_modestamp[slot] = now.tv_sec;
	np->n_mode[slot] = access;

	/*
	 * If we asked for DELETE but didn't get it, the server
	 * may simply not support returning that bit (possible
	 * on UNIX systems).  So, we'll assume that it is OK,
	 * and just let any subsequent delete action fail if it
	 * really isn't deletable.
	 */
	if ((*mode & NFS_ACCESS_DELETE) &&
	    !(np->n_mode[slot] & NFS_ACCESS_DELETE))
		np->n_mode[slot] |= NFS_ACCESS_DELETE;
	/* pass back the mode returned with this request */
	*mode = np->n_mode[slot];
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

/*
 * NFS access vnode op.
 * For NFS version 2, just return ok. File accesses may fail later.
 * For NFS version 3+, use the access RPC to check accessibility. If file modes
 * are changed on the server, accesses might still fail later.
 */
int
nfs_vnop_access(
	struct vnop_access_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		int a_action;
		vfs_context_t a_context;
	} */ *ap)
{
	vfs_context_t ctx = ap->a_context;
	vnode_t vp = ap->a_vp;
	int error = 0, slot, dorpc;
	u_long mode, wmode;
	nfsnode_t np = VTONFS(vp);
	struct nfsmount *nmp;
	int nfsvers;
	struct timeval now;
	uid_t uid;

	nmp = VTONMP(vp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	if (nfsvers == NFS_VER2) {
		if ((ap->a_action & KAUTH_VNODE_WRITE_RIGHTS) &&
		    vfs_isrdonly(vnode_mount(vp)))
			return (EROFS);
		return (0);
	}

	/*
	 * For NFS v3, do an access rpc, otherwise you are stuck emulating
	 * ufs_access() locally using the vattr. This may not be correct,
	 * since the server may apply other access criteria such as
	 * client uid-->server uid mapping that we do not know about, but
	 * this is better than just returning anything that is lying about
	 * in the cache.
	 */

	/*
	 * Convert KAUTH primitives to NFS access rights.
	 */
	mode = 0;
	if (vnode_isdir(vp)) {
		/* directory */
		if (ap->a_action &
		    (KAUTH_VNODE_LIST_DIRECTORY |
		    KAUTH_VNODE_READ_EXTATTRIBUTES))
			mode |= NFS_ACCESS_READ;
		if (ap->a_action & KAUTH_VNODE_SEARCH)
			mode |= NFS_ACCESS_LOOKUP;
		if (ap->a_action &
		    (KAUTH_VNODE_ADD_FILE |
		    KAUTH_VNODE_ADD_SUBDIRECTORY))
			mode |= NFS_ACCESS_MODIFY | NFS_ACCESS_EXTEND;
		if (ap->a_action & KAUTH_VNODE_DELETE_CHILD)
			mode |= NFS_ACCESS_MODIFY;
	} else {
		/* file */
		if (ap->a_action &
		    (KAUTH_VNODE_READ_DATA |
		    KAUTH_VNODE_READ_EXTATTRIBUTES))
			mode |= NFS_ACCESS_READ;
		if (ap->a_action & KAUTH_VNODE_WRITE_DATA)
			mode |= NFS_ACCESS_MODIFY | NFS_ACCESS_EXTEND;
		if (ap->a_action & KAUTH_VNODE_APPEND_DATA)
			mode |= NFS_ACCESS_EXTEND;
		if (ap->a_action & KAUTH_VNODE_EXECUTE)
			mode |= NFS_ACCESS_EXECUTE;
	}
	/* common */
	if (ap->a_action & KAUTH_VNODE_DELETE)
		mode |= NFS_ACCESS_DELETE;
	if (ap->a_action &
	    (KAUTH_VNODE_WRITE_ATTRIBUTES |
	    KAUTH_VNODE_WRITE_EXTATTRIBUTES |
	    KAUTH_VNODE_WRITE_SECURITY))
		mode |= NFS_ACCESS_MODIFY;
	/* XXX this is pretty dubious */
	if (ap->a_action & KAUTH_VNODE_CHANGE_OWNER)
		mode |= NFS_ACCESS_MODIFY;

	/* if caching, always ask for every right */
	if (nfs_access_cache_timeout > 0) {
		wmode = NFS_ACCESS_READ | NFS_ACCESS_MODIFY |
			NFS_ACCESS_EXTEND | NFS_ACCESS_EXECUTE |
			NFS_ACCESS_DELETE | NFS_ACCESS_LOOKUP;
	} else {
		wmode = mode;
	}

	if ((error = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
		return (error);

	/*
	 * Does our cached result allow us to give a definite yes to
	 * this request?
	 */
	uid = kauth_cred_getuid(vfs_context_ucred(ctx));
	slot = nfs_node_mode_slot(np, uid, 0);
	dorpc = 1;
	if (NMODEVALID(np, slot)) {
		microuptime(&now);
		if ((now.tv_sec < (np->n_modestamp[slot] + nfs_access_cache_timeout)) &&
		    ((np->n_mode[slot] & mode) == mode)) {
			/* OSAddAtomic(1, (SInt32*)&nfsstats.accesscache_hits); */
			dorpc = 0;
			wmode = np->n_mode[slot];
		}
	}
	if (dorpc) {
		/* Either a no, or a don't know.  Go to the wire. */
		/* OSAddAtomic(1, (SInt32*)&nfsstats.accesscache_misses); */
		error = nmp->nm_funcs->nf_access_rpc(np, &wmode, ctx);
	}
	if (!error && ((wmode & mode) != mode))
		error = EACCES;
	nfs_unlock(np);

	return (error);
}

/*
 * NFS open vnode op
 */
int
nfs3_vnop_open(
	struct vnop_open_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		int a_mode;
		vfs_context_t a_context;
	} */ *ap)
{
	vfs_context_t ctx = ap->a_context;
	vnode_t vp = ap->a_vp;
	nfsnode_t np = VTONFS(vp);
	struct nfsmount *nmp;
	struct nfs_vattr nvattr;
	enum vtype vtype;
	int error, nfsvers;

	nmp = VTONMP(vp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	vtype = vnode_vtype(vp);
	if ((vtype != VREG) && (vtype != VDIR) && (vtype != VLNK))
		return (EACCES);
	if (ISSET(np->n_flag, NUPDATESIZE))
		nfs_data_update_size(np, 0);
	if ((error = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
		return (error);
	if (np->n_flag & NNEEDINVALIDATE) {
		np->n_flag &= ~NNEEDINVALIDATE;
		nfs_unlock(np);
		nfs_vinvalbuf(vp, V_SAVE|V_IGNORE_WRITEERR, ctx, 1);
		if ((error = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
			return (error);
	}
	if (np->n_flag & NMODIFIED) {
		nfs_unlock(np);
		if ((error = nfs_vinvalbuf(vp, V_SAVE, ctx, 1)) == EINTR)
			return (error);
		if ((error = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
			return (error);
		if (vtype == VDIR)
			np->n_direofoffset = 0;
		NATTRINVALIDATE(np); /* For Open/Close consistency */
		error = nfs_getattr(np, &nvattr, ctx, 1);
		if (error) {
			nfs_unlock(np);
			return (error);
		}
		if (vtype == VDIR) {
			/* if directory changed, purge any name cache entries */
			if (NFS_CHANGED_NC(nfsvers, np, &nvattr)) {
				np->n_flag &= ~NNEGNCENTRIES;
				cache_purge(vp);
			}
			NFS_CHANGED_UPDATE_NC(nfsvers, np, &nvattr);
		}
		NFS_CHANGED_UPDATE(nfsvers, np, &nvattr);
	} else {
		NATTRINVALIDATE(np); /* For Open/Close consistency */
		error = nfs_getattr(np, &nvattr, ctx, 1);
		if (error) {
			nfs_unlock(np);
			return (error);
		}
		if (NFS_CHANGED(nfsvers, np, &nvattr)) {
			if (vtype == VDIR) {
				np->n_direofoffset = 0;
				nfs_invaldir(np);
				/* purge name cache entries */
				if (NFS_CHANGED_NC(nfsvers, np, &nvattr)) {
					np->n_flag &= ~NNEGNCENTRIES;
					cache_purge(vp);
				}
			}
			nfs_unlock(np);
			if ((error = nfs_vinvalbuf(vp, V_SAVE, ctx, 1)) == EINTR)
				return (error);
			if ((error = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
				return (error);
			if (vtype == VDIR)
				NFS_CHANGED_UPDATE_NC(nfsvers, np, &nvattr);
			NFS_CHANGED_UPDATE(nfsvers, np, &nvattr);
		}
	}
	nfs_unlock(np);
	return (0);
}

/*
 * NFS close vnode op
 * What an NFS client should do upon close after writing is a debatable issue.
 * Most NFS clients push delayed writes to the server upon close, basically for
 * two reasons:
 * 1 - So that any write errors may be reported back to the client process
 *     doing the close system call. By far the two most likely errors are
 *     NFSERR_NOSPC and NFSERR_DQUOT to indicate space allocation failure.
 * 2 - To put a worst case upper bound on cache inconsistency between
 *     multiple clients for the file.
 * There is also a consistency problem for Version 2 of the protocol w.r.t.
 * not being able to tell if other clients are writing a file concurrently,
 * since there is no way of knowing if the changed modify time in the reply
 * is only due to the write for this client.
 * (NFS Version 3 provides weak cache consistency data in the reply that
 *  should be sufficient to detect and handle this case.)
 *
 * The current code does the following:
 * for NFS Version 2 - play it safe and flush/invalidate all dirty buffers
 * for NFS Version 3 - flush dirty buffers to the server but don't invalidate
 *                     them.
 */
int
nfs3_vnop_close(
	struct vnop_close_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		int a_fflag;
		vfs_context_t a_context;
	} */ *ap)
{
	vfs_context_t ctx = ap->a_context;
	vnode_t vp = ap->a_vp;
	nfsnode_t np = VTONFS(vp);
	struct nfsmount *nmp;
	int nfsvers;
	int error = 0;

	if (vnode_vtype(vp) != VREG)
		return (0);
	nmp = VTONMP(vp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	if (ISSET(np->n_flag, NUPDATESIZE))
		nfs_data_update_size(np, 0);
	if ((error = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
		return (error);
	if (np->n_flag & NNEEDINVALIDATE) {
		np->n_flag &= ~NNEEDINVALIDATE;
		nfs_unlock(np);
		nfs_vinvalbuf(vp, V_SAVE|V_IGNORE_WRITEERR, ctx, 1);
		if ((error = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
			return (error);
	}
	if (np->n_flag & NMODIFIED) {
		nfs_unlock(np);
		if (nfsvers != NFS_VER2)
			error = nfs_flush(np, MNT_WAIT, vfs_context_thread(ctx), 0);
		else
			error = nfs_vinvalbuf(vp, V_SAVE, ctx, 1);
		if (error)
			return (error);
		nfs_lock(np, NFS_NODE_LOCK_FORCE);
		NATTRINVALIDATE(np);
	}
	if (np->n_flag & NWRITEERR) {
		np->n_flag &= ~NWRITEERR;
		error = np->n_error;
	}
	nfs_unlock(np);
	return (error);
}


int
nfs3_getattr_rpc(
	nfsnode_t np,
	mount_t mp,
	u_char *fhp,
	size_t fhsize,
	vfs_context_t ctx,
	struct nfs_vattr *nvap,
	u_int64_t *xidp)
{
	struct nfsmount *nmp = mp ? VFSTONFS(mp) : NFSTONMP(np);
	int error = 0, status, nfsvers;
	struct nfsm_chain nmreq, nmrep;

	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	nfsm_chain_build_alloc_init(error, &nmreq, NFSX_FH(nfsvers));
	if (nfsvers != NFS_VER2)
		nfsm_chain_add_32(error, &nmreq, fhsize);
	nfsm_chain_add_opaque(error, &nmreq, fhp, fhsize);
	nfsm_chain_build_done(error, &nmreq);
	nfsmout_if(error);
	error = nfs_request(np, mp, &nmreq, NFSPROC_GETATTR, ctx,
			&nmrep, xidp, &status);
	if (!error)
		error = status;
	nfsmout_if(error);
	error = nfs_parsefattr(&nmrep, nfsvers, nvap);
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}


int
nfs_getattr(nfsnode_t np, struct nfs_vattr *nvap, vfs_context_t ctx, int alreadylocked)
{
	struct nfsmount *nmp;
	int error = 0, lockerror = ENOENT, nfsvers, avoidfloods;
	u_int64_t xid;

	FSDBG_TOP(513, np->n_size, np, np->n_vattr.nva_size, np->n_flag);

	/* Update local times for special files. */
	if (np->n_flag & (NACC | NUPD)) {
		if (!alreadylocked)
			nfs_lock(np, NFS_NODE_LOCK_FORCE);
		np->n_flag |= NCHG;
		if (!alreadylocked)
			nfs_unlock(np);
	}
	/* Update size, if necessary */
	if (!alreadylocked && ISSET(np->n_flag, NUPDATESIZE))
		nfs_data_update_size(np, 0);

	/*
	 * First look in the cache.
	 */
	if ((error = nfs_getattrcache(np, nvap, alreadylocked)) == 0)
		goto nfsmout;
	if (error != ENOENT)
		goto nfsmout;

	nmp = NFSTONMP(np);
	if (!nmp) {
		error = ENXIO;
		goto nfsmout;
	}
	nfsvers = nmp->nm_vers;

	/*
	 * Try to get both the attributes and access info by making an
	 * ACCESS call and seeing if it returns updated attributes.
	 * But don't bother if we aren't caching access info or if the
	 * attributes returned wouldn't be cached.
	 */
	if ((nfsvers != NFS_VER2) && (nfs_access_cache_timeout > 0)) {
		if (!alreadylocked && ((error = lockerror = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE))))
			goto nfsmout;
		if (nfs_attrcachetimeout(np) > 0) {
			/*  OSAddAtomic(1, (SInt32*)&nfsstats.accesscache_misses); */
			u_long mode = NFS_ACCESS_ALL;
			error = nmp->nm_funcs->nf_access_rpc(np, &mode, ctx);
			if (error)
				goto nfsmout;
			if ((error = nfs_getattrcache(np, nvap, 1)) == 0)
				goto nfsmout;
			if (error != ENOENT)
				goto nfsmout;
			error = 0;
		}
	} else if (!alreadylocked) {
		error = lockerror = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE);
		nfsmout_if(error);
	}
	avoidfloods = 0;
tryagain:
	error = nmp->nm_funcs->nf_getattr_rpc(np, NULL, np->n_fhp, np->n_fhsize, ctx, nvap, &xid);
	nfsmout_if(error);
	error = nfs_loadattrcache(np, nvap, &xid, 0);
	nfsmout_if(error);
	if (!xid) { /* out-of-order rpc - attributes were dropped */
		FSDBG(513, -1, np, np->n_xid >> 32, np->n_xid);
		if (avoidfloods++ < 100)
			goto tryagain;
		/* avoidfloods>1 is bizarre.  at 100 pull the plug */
		panic("nfs_getattr: getattr flood\n");
	}
	if (NFS_CHANGED(nfsvers, np, nvap)) {
		vnode_t vp = NFSTOV(np);
		enum vtype vtype = vnode_vtype(vp);
		FSDBG(513, -1, np, -1, np);
		if (vtype == VDIR) {
			nfs_invaldir(np);
			/* purge name cache entries */
			if (NFS_CHANGED_NC(nfsvers, np, nvap)) {
				np->n_flag &= ~NNEGNCENTRIES;
				cache_purge(vp);
			}
		}
		if (!alreadylocked) {
			nfs_unlock(np);
			lockerror = ENOENT;
			error = nfs_vinvalbuf(vp, V_SAVE, ctx, 1);
			FSDBG(513, -1, np, -2, error);
			if (!error)
				error = lockerror = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE);
			if (!error) {
				if (vtype == VDIR)
					NFS_CHANGED_UPDATE_NC(nfsvers, np, nvap);
				NFS_CHANGED_UPDATE(nfsvers, np, nvap);
			}
		} else {
			/* invalidate later */
			np->n_flag |= NNEEDINVALIDATE;
		}
	}
nfsmout:
	if (!lockerror)
		nfs_unlock(np);
	FSDBG_BOT(513, np->n_size, error, np->n_vattr.nva_size, np->n_flag);
	return (error);
}

/*
 * NFS getattr call from vfs.
 */
static int
nfs3_vnop_getattr(
	struct vnop_getattr_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		struct vnode_attr *a_vap;
		vfs_context_t a_context;
	} */ *ap)
{
	int error;
	struct nfs_vattr nva;
	struct vnode_attr *vap = ap->a_vap;
	dev_t rdev;

	error = nfs_getattr(VTONFS(ap->a_vp), &nva, ap->a_context, 0);
	if (error)
		return (error);

	/* copy nva to *a_vap */
	VATTR_RETURN(vap, va_type, nva.nva_type);
	VATTR_RETURN(vap, va_mode, nva.nva_mode);
	rdev = makedev(nva.nva_rawdev.specdata1, nva.nva_rawdev.specdata2);
	VATTR_RETURN(vap, va_rdev, rdev);
	VATTR_RETURN(vap, va_uid, nva.nva_uid);
	VATTR_RETURN(vap, va_gid, nva.nva_gid);
	VATTR_RETURN(vap, va_nlink, nva.nva_nlink);
	VATTR_RETURN(vap, va_fileid, nva.nva_fileid);
	VATTR_RETURN(vap, va_data_size, nva.nva_size);
	VATTR_RETURN(vap, va_data_alloc, nva.nva_bytes);
	VATTR_RETURN(vap, va_iosize, nfs_iosize);
	vap->va_access_time.tv_sec = nva.nva_timesec[NFSTIME_ACCESS];
	vap->va_access_time.tv_nsec = nva.nva_timensec[NFSTIME_ACCESS];
	VATTR_SET_SUPPORTED(vap, va_access_time);
	vap->va_modify_time.tv_sec = nva.nva_timesec[NFSTIME_MODIFY];
	vap->va_modify_time.tv_nsec = nva.nva_timensec[NFSTIME_MODIFY];
	VATTR_SET_SUPPORTED(vap, va_modify_time);
	vap->va_change_time.tv_sec = nva.nva_timesec[NFSTIME_CHANGE];
	vap->va_change_time.tv_nsec = nva.nva_timensec[NFSTIME_CHANGE];
	VATTR_SET_SUPPORTED(vap, va_change_time);

	// VATTR_RETURN(vap, va_encoding, 0xffff /* kTextEncodingUnknown */);
	return (error);
}

/*
 * NFS setattr call.
 */
static int
nfs_vnop_setattr(
	struct vnop_setattr_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		struct vnode_attr *a_vap;
		vfs_context_t a_context;
	} */ *ap)
{
	vfs_context_t ctx = ap->a_context;
	vnode_t vp = ap->a_vp;
	nfsnode_t np = VTONFS(vp);
	struct nfsmount *nmp;
	struct vnode_attr *vap = ap->a_vap;
	int error = 0;
	int biosize, nfsvers;
	u_quad_t origsize;
	struct nfs_dulookup dul;
	nfsnode_t dnp = NULL;
	vnode_t dvp = NULL;
	const char *vname = NULL;

	nmp = VTONMP(vp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;
	biosize = nmp->nm_biosize;

	/* Disallow write attempts if the filesystem is mounted read-only. */
	if (vnode_vfsisrdonly(vp))
		return (EROFS);

	origsize = np->n_size;
	if (VATTR_IS_ACTIVE(vap, va_data_size)) {
		switch (vnode_vtype(vp)) {
		case VDIR:
			return (EISDIR);
		case VCHR:
		case VBLK:
		case VSOCK:
		case VFIFO:
			if (!VATTR_IS_ACTIVE(vap, va_modify_time) &&
			    !VATTR_IS_ACTIVE(vap, va_access_time) &&
			    !VATTR_IS_ACTIVE(vap, va_mode) &&
			    !VATTR_IS_ACTIVE(vap, va_uid) &&
			    !VATTR_IS_ACTIVE(vap, va_gid)) {
				return (0);
			}
			VATTR_CLEAR_ACTIVE(vap, va_data_size);
			break;
		default:
			/*
			 * Disallow write attempts if the filesystem is
			 * mounted read-only.
			 */
			if (vnode_vfsisrdonly(vp))
				return (EROFS);
			FSDBG_TOP(512, np->n_size, vap->va_data_size,
				  np->n_vattr.nva_size, np->n_flag);
			/* clear NNEEDINVALIDATE, if set */
			if ((error = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
				return (error);
			if (np->n_flag & NNEEDINVALIDATE)
				np->n_flag &= ~NNEEDINVALIDATE;
			nfs_unlock(np);
			/* flush everything */
			error = nfs_vinvalbuf(vp, (vap->va_data_size ? V_SAVE : 0) , ctx, 1);
			if (error) {
				printf("nfs_setattr: nfs_vinvalbuf %d\n", error);
				FSDBG_BOT(512, np->n_size, vap->va_data_size, np->n_vattr.nva_size, -1);
				return (error);
			}
			nfs_data_lock(np, NFS_NODE_LOCK_EXCLUSIVE);
			if (np->n_size > vap->va_data_size) { /* shrinking? */
				daddr64_t obn, bn;
				int neweofoff, mustwrite;
				struct nfsbuf *bp;

				obn = (np->n_size - 1) / biosize;
				bn = vap->va_data_size / biosize;
				for ( ; obn >= bn; obn--) {
					if (!nfs_buf_is_incore(np, obn))
						continue;
					error = nfs_buf_get(np, obn, biosize, NULL, NBLK_READ, &bp);
					if (error)
						continue;
					if (obn != bn) {
						FSDBG(512, bp, bp->nb_flags, 0, obn);
						SET(bp->nb_flags, NB_INVAL);
						nfs_buf_release(bp, 1);
						continue;
					}
					mustwrite = 0;
					neweofoff = vap->va_data_size - NBOFF(bp);
					/* check for any dirty data before the new EOF */
					if ((bp->nb_dirtyend > 0) && (bp->nb_dirtyoff < neweofoff)) {
						/* clip dirty range to EOF */
						if (bp->nb_dirtyend > neweofoff) {
							bp->nb_dirtyend = neweofoff;
							if (bp->nb_dirtyoff >= bp->nb_dirtyend)
								bp->nb_dirtyoff = bp->nb_dirtyend = 0;
						}
						if ((bp->nb_dirtyend > 0) && (bp->nb_dirtyoff < neweofoff))
							mustwrite++;
					}
					bp->nb_dirty &= (1 << round_page_32(neweofoff)/PAGE_SIZE) - 1;
					if (bp->nb_dirty)
						mustwrite++;
					if (!mustwrite) {
						FSDBG(512, bp, bp->nb_flags, 0, obn);
						SET(bp->nb_flags, NB_INVAL);
						nfs_buf_release(bp, 1);
						continue;
					}
					/* gotta write out dirty data before invalidating */
					/* (NB_STABLE indicates that data writes should be FILESYNC) */
					/* (NB_NOCACHE indicates buffer should be discarded) */
					CLR(bp->nb_flags, (NB_DONE | NB_ERROR | NB_INVAL | NB_ASYNC | NB_READ));
					SET(bp->nb_flags, NB_STABLE | NB_NOCACHE);
					if (!IS_VALID_CRED(bp->nb_wcred)) {
						kauth_cred_t cred = vfs_context_ucred(ctx);
						kauth_cred_ref(cred);
						bp->nb_wcred = cred;
					}
					error = nfs_buf_write(bp);
					// Note: bp has been released
					if (error) {
						FSDBG(512, bp, 0xd00dee, 0xbad, error);
						nfs_lock(np, NFS_NODE_LOCK_FORCE);
						np->n_error = error;
						np->n_flag |= NWRITEERR;
						/*
						 * There was a write error and we need to
						 * invalidate attrs and flush buffers in
						 * order to sync up with the server.
						 * (if this write was extending the file,
						 * we may no longer know the correct size)
						 */
						NATTRINVALIDATE(np);
						nfs_unlock(np);
						nfs_data_unlock(np);
						nfs_vinvalbuf(vp, V_SAVE|V_IGNORE_WRITEERR, ctx, 1);
						nfs_data_lock(np, NFS_NODE_LOCK_EXCLUSIVE);
						error = 0;
					}
				}
			}
			if (vap->va_data_size != np->n_size)
				ubc_setsize(vp, (off_t)vap->va_data_size); /* XXX error? */
			origsize = np->n_size;
			np->n_size = np->n_vattr.nva_size = vap->va_data_size;
			CLR(np->n_flag, NUPDATESIZE);
			FSDBG(512, np, np->n_size, np->n_vattr.nva_size, 0xf00d0001);
		}
	} else if (VATTR_IS_ACTIVE(vap, va_modify_time) ||
		    VATTR_IS_ACTIVE(vap, va_access_time) ||
		    (vap->va_vaflags & VA_UTIMES_NULL)) {
		if ((error = nfs_lock(np, NFS_NODE_LOCK_SHARED)))
			return (error);
		if ((np->n_flag & NMODIFIED) && (vnode_vtype(vp) == VREG)) {
			nfs_unlock(np);
			error = nfs_vinvalbuf(vp, V_SAVE, ctx, 1);
			if (error == EINTR)
				return (error);
		} else {
			nfs_unlock(np);
		}
	}
	if (VATTR_IS_ACTIVE(vap, va_mode) ||
	    VATTR_IS_ACTIVE(vap, va_uid) ||
	    VATTR_IS_ACTIVE(vap, va_gid)) {
		if ((error = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE))) {
			if (VATTR_IS_ACTIVE(vap, va_data_size))
				nfs_data_unlock(np);
			return (error);
		}
		NMODEINVALIDATE(np);
		nfs_unlock(np);
		dvp = vnode_getparent(vp);
		vname = vnode_getname(vp);
		dnp = (dvp && vname) ? VTONFS(dvp) : NULL;
		if (dnp) {
			error = nfs_lock(dnp, NFS_NODE_LOCK_EXCLUSIVE);
			if (error) {
				dnp = NULL;
				error = 0;
			}
		}
		if (dnp) {
			nfs_dulookup_init(&dul, dnp, vname, strlen(vname));
			nfs_dulookup_start(&dul, dnp, ctx);
		}
	}

	error = nmp->nm_funcs->nf_setattr_rpc(np, vap, ctx, 0);

	if (VATTR_IS_ACTIVE(vap, va_mode) ||
	    VATTR_IS_ACTIVE(vap, va_uid) ||
	    VATTR_IS_ACTIVE(vap, va_gid)) {
		if (dnp) {
			nfs_dulookup_finish(&dul, dnp, ctx);
			nfs_unlock(dnp);
		}
		if (dvp != NULLVP)
			vnode_put(dvp);
		if (vname != NULL)
			vnode_putname(vname);
	}

	FSDBG_BOT(512, np->n_size, vap->va_data_size, np->n_vattr.nva_size, error);
	if (VATTR_IS_ACTIVE(vap, va_data_size)) {
		if (error && (origsize != np->n_size)) {
			/* make every effort to resync file size w/ server... */
			int err; /* preserve "error" for return */
			np->n_size = np->n_vattr.nva_size = origsize;
			CLR(np->n_flag, NUPDATESIZE);
			FSDBG(512, np, np->n_size, np->n_vattr.nva_size, 0xf00d0002);
			ubc_setsize(vp, (off_t)np->n_size); /* XXX check error */
			vap->va_data_size = origsize;
			err = nmp->nm_funcs->nf_setattr_rpc(np, vap, ctx, 0);
			if (err)
				printf("nfs_vnop_setattr: nfs%d_setattr_rpc %d %d\n", nfsvers, error, err);
		}
		nfs_data_unlock(np);
	}
	return (error);
}

/*
 * Do an NFS setattr RPC.
 */
int
nfs3_setattr_rpc(
	nfsnode_t np,
	struct vnode_attr *vap,
	vfs_context_t ctx,
	int alreadylocked)
{
	struct nfsmount *nmp = NFSTONMP(np);
	int error = 0, lockerror = ENOENT, status, wccpostattr = 0, nfsvers;
	u_int64_t xid;
	struct nfsm_chain nmreq, nmrep;

	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	VATTR_SET_SUPPORTED(vap, va_mode);
	VATTR_SET_SUPPORTED(vap, va_uid);
	VATTR_SET_SUPPORTED(vap, va_gid);
	VATTR_SET_SUPPORTED(vap, va_data_size);
	VATTR_SET_SUPPORTED(vap, va_access_time);
	VATTR_SET_SUPPORTED(vap, va_modify_time);

	if (VATTR_IS_ACTIVE(vap, va_flags)) {
		if (vap->va_flags) {	/* we don't support setting flags */
			if (vap->va_active & ~VNODE_ATTR_va_flags)
				return (EINVAL);	/* return EINVAL if other attributes also set */
			else
				return (ENOTSUP);	/* return ENOTSUP for chflags(2) */
		}
		/* no flags set, so we'll just ignore it */
		if (!(vap->va_active & ~VNODE_ATTR_va_flags))
			return (0); /* no (other) attributes to set, so nothing to do */
	}

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	nfsm_chain_build_alloc_init(error, &nmreq,
		NFSX_FH(nfsvers) + NFSX_SATTR(nfsvers));
	nfsm_chain_add_fh(error, &nmreq, nfsvers, np->n_fhp, np->n_fhsize);
	if (nfsvers == NFS_VER3) {
		if (VATTR_IS_ACTIVE(vap, va_mode)) {
			nfsm_chain_add_32(error, &nmreq, TRUE);
			nfsm_chain_add_32(error, &nmreq, vap->va_mode);
		} else {
			nfsm_chain_add_32(error, &nmreq, FALSE);
		}
		if (VATTR_IS_ACTIVE(vap, va_uid)) {
			nfsm_chain_add_32(error, &nmreq, TRUE);
			nfsm_chain_add_32(error, &nmreq, vap->va_uid);
		} else {
			nfsm_chain_add_32(error, &nmreq, FALSE);
		}
		if (VATTR_IS_ACTIVE(vap, va_gid)) {
			nfsm_chain_add_32(error, &nmreq, TRUE);
			nfsm_chain_add_32(error, &nmreq, vap->va_gid);
		} else {
			nfsm_chain_add_32(error, &nmreq, FALSE);
		}
		if (VATTR_IS_ACTIVE(vap, va_data_size)) {
			nfsm_chain_add_32(error, &nmreq, TRUE);
			nfsm_chain_add_64(error, &nmreq, vap->va_data_size);
		} else {
			nfsm_chain_add_32(error, &nmreq, FALSE);
		}
		if (vap->va_vaflags & VA_UTIMES_NULL) {
			nfsm_chain_add_32(error, &nmreq, NFS_TIME_SET_TO_SERVER);
			nfsm_chain_add_32(error, &nmreq, NFS_TIME_SET_TO_SERVER);
		} else {
			if (VATTR_IS_ACTIVE(vap, va_access_time)) {
				nfsm_chain_add_32(error, &nmreq, NFS_TIME_SET_TO_CLIENT);
				nfsm_chain_add_32(error, &nmreq, vap->va_access_time.tv_sec);
				nfsm_chain_add_32(error, &nmreq, vap->va_access_time.tv_nsec);
			} else {
				nfsm_chain_add_32(error, &nmreq, NFS_TIME_DONT_CHANGE);
			}
			if (VATTR_IS_ACTIVE(vap, va_modify_time)) {
				nfsm_chain_add_32(error, &nmreq, NFS_TIME_SET_TO_CLIENT);
				nfsm_chain_add_32(error, &nmreq, vap->va_modify_time.tv_sec);
				nfsm_chain_add_32(error, &nmreq, vap->va_modify_time.tv_nsec);
			} else {
				nfsm_chain_add_32(error, &nmreq, NFS_TIME_DONT_CHANGE);
			}
		}
		nfsm_chain_add_32(error, &nmreq, FALSE);
	} else {
		nfsm_chain_add_32(error, &nmreq, VATTR_IS_ACTIVE(vap, va_mode) ?
			vtonfsv2_mode(vnode_vtype(NFSTOV(np)), vap->va_mode) : -1);
		nfsm_chain_add_32(error, &nmreq, VATTR_IS_ACTIVE(vap, va_uid) ?
			vap->va_uid : (uint32_t)-1);
		nfsm_chain_add_32(error, &nmreq, VATTR_IS_ACTIVE(vap, va_gid) ?
			vap->va_gid : (uint32_t)-1);
		nfsm_chain_add_32(error, &nmreq, VATTR_IS_ACTIVE(vap, va_data_size) ?
			vap->va_data_size : (uint32_t)-1);
		if (VATTR_IS_ACTIVE(vap, va_access_time)) {
			nfsm_chain_add_32(error, &nmreq, vap->va_access_time.tv_sec);
			nfsm_chain_add_32(error, &nmreq, (vap->va_access_time.tv_nsec != -1) ?
				((uint32_t)vap->va_access_time.tv_nsec / 1000) : 0xffffffff);
		} else {
			nfsm_chain_add_32(error, &nmreq, -1);
			nfsm_chain_add_32(error, &nmreq, -1);
		}
		if (VATTR_IS_ACTIVE(vap, va_modify_time)) {
			nfsm_chain_add_32(error, &nmreq, vap->va_modify_time.tv_sec);
			nfsm_chain_add_32(error, &nmreq, (vap->va_modify_time.tv_nsec != -1) ?
				((uint32_t)vap->va_modify_time.tv_nsec / 1000) : 0xffffffff);
		} else {
			nfsm_chain_add_32(error, &nmreq, -1);
			nfsm_chain_add_32(error, &nmreq, -1);
		}
	}
	nfsm_chain_build_done(error, &nmreq);
	nfsmout_if(error);
	error = nfs_request(np, NULL, &nmreq, NFSPROC_SETATTR, ctx,
			&nmrep, &xid, &status);
	if (!alreadylocked && ((lockerror = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE))))
		error = lockerror;
	if (nfsvers == NFS_VER3) {
		struct timespec premtime = { 0, 0 };
		nfsm_chain_get_wcc_data(error, &nmrep, np, &premtime, &wccpostattr, &xid);
		nfsmout_if(error);
		/* if file hadn't changed, update cached mtime */
		if (nfstimespeccmp(&np->n_mtime, &premtime, ==))
			NFS_CHANGED_UPDATE(nfsvers, np, &np->n_vattr);
		/* if directory hadn't changed, update namecache mtime */
		if ((vnode_vtype(NFSTOV(np)) == VDIR) &&
		    nfstimespeccmp(&np->n_ncmtime, &premtime, ==))
			NFS_CHANGED_UPDATE_NC(nfsvers, np, &np->n_vattr);
		if (!wccpostattr)
			NATTRINVALIDATE(np);
		error = status;
	} else {
		if (!error)
			error = status;
		nfsm_chain_loadattr(error, &nmrep, np, nfsvers, NULL, &xid);
	}
nfsmout:
	if (!alreadylocked && !lockerror)
		nfs_unlock(np);
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

/*
 * NFS lookup call, one step at a time...
 * First look in cache
 * If not found, unlock the directory nfsnode and do the RPC
 */
static int
nfs_vnop_lookup(
	struct vnop_lookup_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_dvp;
		vnode_t *a_vpp;
		struct componentname *a_cnp;
		vfs_context_t a_context;
	} */ *ap)
{
	vfs_context_t ctx = ap->a_context;
	struct componentname *cnp = ap->a_cnp;
	vnode_t dvp = ap->a_dvp;
	vnode_t *vpp = ap->a_vpp;
	int flags = cnp->cn_flags;
	vnode_t newvp;
	nfsnode_t dnp, np;
	struct nfsmount *nmp;
	mount_t mp;
	int nfsvers, error, lockerror = ENOENT, isdot, isdotdot, negnamecache;
	u_int64_t xid;
	struct nfs_vattr nvattr;
	int ngflags;
	struct vnop_access_args naa;
	fhandle_t fh;
	struct nfsreq rq, *req = &rq;

	*vpp = NULLVP;

	dnp = VTONFS(dvp);

	mp = vnode_mount(dvp);
	nmp = VFSTONFS(mp);
	if (!nmp) {
		error = ENXIO;
		goto error_return;
	}
	nfsvers = nmp->nm_vers;
	negnamecache = !(nmp->nm_flag & NFSMNT_NONEGNAMECACHE);

	error = lockerror = nfs_lock(dnp, NFS_NODE_LOCK_EXCLUSIVE);
	if (!error)
		error = nfs_getattr(dnp, &nvattr, ctx, 1);
	if (error)
		goto error_return;
	if (NFS_CHANGED_NC(nfsvers, dnp, &nvattr)) {
		/*
		 * This directory has changed on us.
		 * Purge any name cache entries.
		 */
		dnp->n_flag &= ~NNEGNCENTRIES;
		cache_purge(dvp);
		NFS_CHANGED_UPDATE_NC(nfsvers, dnp, &nvattr);
	}

	error = cache_lookup(dvp, vpp, cnp);
	switch (error) {
	case ENOENT:
		/* negative cache entry */
		goto error_return;
	case 0:
		/* cache miss */
		break;
	case -1:
		/* cache hit, not really an error */
		OSAddAtomic(1, (SInt32*)&nfsstats.lookupcache_hits);

		nfs_unlock(dnp);
		lockerror = ENOENT;

		/* check for directory access */
		naa.a_vp = dvp;
		naa.a_action = KAUTH_VNODE_SEARCH;
		naa.a_context = ctx;

		/* compute actual success/failure based on accessibility */
		error = nfs_vnop_access(&naa);
		/* FALLTHROUGH */
	default:
		/* unexpected error from cache_lookup */
		goto error_return;
	}

	/* skip lookup, if we know who we are: "." or ".." */
	isdot = isdotdot = 0;
	if (cnp->cn_nameptr[0] == '.') {
		if (cnp->cn_namelen == 1)
			isdot = 1;
		if ((cnp->cn_namelen == 2) && (cnp->cn_nameptr[1] == '.'))
			isdotdot = 1;
	}
	if (isdotdot || isdot) {
		fh.fh_len = 0;
		goto found;
	}

	/* do we know this name is too long? */
	nmp = VTONMP(dvp);
	if (!nmp) {
		error = ENXIO;
		goto error_return;
	}
	if (NFS_BITMAP_ISSET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_MAXNAME) &&
	     (cnp->cn_namelen > (long)nmp->nm_fsattr.nfsa_maxname)) {
		error = ENAMETOOLONG;
		goto error_return;
	}

	error = 0;
	newvp = NULLVP;

	OSAddAtomic(1, (SInt32*)&nfsstats.lookupcache_misses);

	error = nmp->nm_funcs->nf_lookup_rpc_async(dnp, cnp->cn_nameptr, cnp->cn_namelen, ctx, &req);
	nfsmout_if(error);
	error = nmp->nm_funcs->nf_lookup_rpc_async_finish(dnp, ctx, req, &xid, &fh, &nvattr);
	nfsmout_if(error);

	/* is the file handle the same as this directory's file handle? */
	isdot = NFS_CMPFH(dnp, fh.fh_data, fh.fh_len);

found:

	if (flags & ISLASTCN) {
		switch (cnp->cn_nameiop) {
		case DELETE:
			cnp->cn_flags &= ~MAKEENTRY;
			break;
		case RENAME:
			cnp->cn_flags &= ~MAKEENTRY;
			if (isdot) {
				error = EISDIR;
				goto error_return;
			}
			break;
		}
	}

	if (isdotdot) {
		nfs_unlock(dnp);
		lockerror = ENOENT;
		newvp = vnode_getparent(dvp);
		if (!newvp) {
			error = ENOENT;
			goto error_return;
		}
	} else if (isdot) {
		error = vnode_get(dvp);
		if (error)
			goto error_return;
		newvp = dvp;
		if (fh.fh_len && (dnp->n_xid <= xid))
			nfs_loadattrcache(dnp, &nvattr, &xid, 0);
	} else {
		ngflags = (cnp->cn_flags & MAKEENTRY) ? NG_MAKEENTRY : 0;
		error = nfs_nget(mp, dnp, cnp, fh.fh_data, fh.fh_len, &nvattr, &xid, ngflags, &np);
		if (error)
			goto error_return;
		newvp = NFSTOV(np);
		nfs_unlock(np);
	}
	*vpp = newvp;

nfsmout:
	if (error) {
		if (((cnp->cn_nameiop == CREATE) || (cnp->cn_nameiop == RENAME)) &&
		    (flags & ISLASTCN) && (error == ENOENT)) {
			if (vnode_mount(dvp) && vnode_vfsisrdonly(dvp))
				error = EROFS;
			else
				error = EJUSTRETURN;
		}
	}
	if ((error == ENOENT) && (cnp->cn_flags & MAKEENTRY) &&
	    (cnp->cn_nameiop != CREATE) && negnamecache) {
		/* add a negative entry in the name cache */
		cache_enter(dvp, NULL, cnp);
		dnp->n_flag |= NNEGNCENTRIES;
	}
error_return:
	if (!lockerror)
		nfs_unlock(dnp);
	if (error && *vpp) {
	        vnode_put(*vpp);
		*vpp = NULLVP;
	}
	return (error);
}

/*
 * NFS read call.
 * Just call nfs_bioread() to do the work.
 */
static int
nfs_vnop_read(
	struct vnop_read_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		struct uio *a_uio;
		int a_ioflag;
		vfs_context_t a_context;
	} */ *ap)
{
	if (vnode_vtype(ap->a_vp) != VREG)
		return (EPERM);
	return (nfs_bioread(VTONFS(ap->a_vp), ap->a_uio, ap->a_ioflag, NULL, ap->a_context));
}


/*
 * NFS readlink call
 */
static int
nfs_vnop_readlink(
	struct vnop_readlink_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		struct uio *a_uio;
		vfs_context_t a_context;
	} */ *ap)
{
	vfs_context_t ctx = ap->a_context;
	nfsnode_t np = VTONFS(ap->a_vp);
	struct nfsmount *nmp;
	int error = 0, lockerror, nfsvers, changed = 0, n;
	uint32_t buflen;
	struct uio *uio = ap->a_uio;
	struct nfs_vattr nvattr;
	struct nfsbuf *bp = NULL;

	if (vnode_vtype(ap->a_vp) != VLNK)
		return (EPERM);

	if (uio_uio_resid(uio) == 0)
		return (0);
	if (uio->uio_offset < 0)
		return (EINVAL);

	nmp = VTONMP(ap->a_vp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	error = lockerror = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE);
	if (!error)
		error = nfs_getattr(np, &nvattr, ctx, 1);
	if (error) {
		if (!lockerror)
			nfs_unlock(np);
		FSDBG(531, np, 0xd1e0001, 0, error);
		return (error);
	}
	if (NFS_CHANGED(nfsvers, np, &nvattr)) {
		/* link changed, so just ignore NB_CACHE */
		changed = 1;
		NFS_CHANGED_UPDATE(nfsvers, np, &nvattr);
	}
	nfs_unlock(np);

	OSAddAtomic(1, (SInt32*)&nfsstats.biocache_readlinks);
	error = nfs_buf_get(np, 0, NFS_MAXPATHLEN, vfs_context_thread(ctx), NBLK_READ, &bp);
	if (error) {
		FSDBG(531, np, 0xd1e0002, 0, error);
		return (error);
	}
	if (changed)
		CLR(bp->nb_flags, NB_CACHE);
	if (!ISSET(bp->nb_flags, NB_CACHE)) {
		SET(bp->nb_flags, NB_READ);
		CLR(bp->nb_flags, NB_DONE);
		OSAddAtomic(1, (SInt32*)&nfsstats.readlink_bios);
		buflen = bp->nb_bufsize;
		error = nmp->nm_funcs->nf_readlink_rpc(np, bp->nb_data, &buflen, ctx);
		if (error) {
			SET(bp->nb_flags, NB_ERROR);
			bp->nb_error = error;
		} else {
			bp->nb_validoff = 0;
			bp->nb_validend = buflen;
		}
		nfs_buf_iodone(bp);
	}
	if (!error) {
		// LP64todo - fix this!
		n = min(uio_uio_resid(uio), bp->nb_validend);
		if (n > 0)
			error = uiomove(bp->nb_data, n, uio);
	}
	FSDBG(531, np, bp->nb_validend, 0, error);
	nfs_buf_release(bp, 1);
	return (error);
}

/*
 * Do a readlink RPC.
 */
int
nfs3_readlink_rpc(nfsnode_t np, char *buf, uint32_t *buflenp, vfs_context_t ctx)
{
	struct nfsmount *nmp;
	int error = 0, lockerror = ENOENT, nfsvers, status;
	uint32_t len;
	u_int64_t xid;
	struct nfsm_chain nmreq, nmrep;

	nmp = NFSTONMP(np);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;
	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	nfsm_chain_build_alloc_init(error, &nmreq, NFSX_FH(nfsvers));
	nfsm_chain_add_fh(error, &nmreq, nfsvers, np->n_fhp, np->n_fhsize);
	nfsm_chain_build_done(error, &nmreq);
	nfsmout_if(error);
	error = nfs_request(np, NULL, &nmreq, NFSPROC_READLINK, ctx,
			&nmrep, &xid, &status);
	if ((lockerror = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
		error = lockerror;
	if (nfsvers == NFS_VER3)
		nfsm_chain_postop_attr_update(error, &nmrep, np, &xid);
	if (!error)
		error = status;
	nfsm_chain_get_32(error, &nmrep, len);
	nfsmout_if(error);
	if ((nfsvers == NFS_VER2) && (len > *buflenp)) {
		error = EBADRPC;
		goto nfsmout;
	}
	if (len >= *buflenp) {
		if (np->n_size && (np->n_size < *buflenp))
			len = np->n_size;
		else
			len = *buflenp - 1;
	}
	nfsm_chain_get_opaque(error, &nmrep, len, buf);
	if (!error)
		*buflenp = len;
nfsmout:
	if (!lockerror)
		nfs_unlock(np);
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

/*
 * NFS read RPC call
 * Ditto above
 */
int
nfs_read_rpc(nfsnode_t np, struct uio *uiop, vfs_context_t ctx)
{
	struct nfsmount *nmp;
	int error = 0, nfsvers, eof = 0;
	size_t nmrsize, len, retlen, tsiz;
	off_t txoffset;
	struct nfsreq rq, *req = &rq;

	FSDBG_TOP(536, np, uiop->uio_offset, uio_uio_resid(uiop), 0);
	nmp = NFSTONMP(np);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;
	nmrsize = nmp->nm_rsize;

	// LP64todo - fix this
	tsiz = uio_uio_resid(uiop);
	if (((u_int64_t)uiop->uio_offset + (unsigned int)tsiz > 0xffffffff) && (nfsvers == NFS_VER2)) {
		FSDBG_BOT(536, np, uiop->uio_offset, uio_uio_resid(uiop), EFBIG);
		return (EFBIG);
	}

	txoffset = uiop->uio_offset;

	while (tsiz > 0) {
		len = retlen = (tsiz > nmrsize) ? nmrsize : tsiz;
		FSDBG(536, np, txoffset, len, 0);
		error = nmp->nm_funcs->nf_read_rpc_async(np, txoffset, len,
				vfs_context_thread(ctx), vfs_context_ucred(ctx), NULL, &req);
		if (!error)
			error = nmp->nm_funcs->nf_read_rpc_async_finish(np, req, uiop, &retlen, &eof);
		if (error)
			break;
		txoffset += retlen;
		tsiz -= retlen;
		if (nfsvers != NFS_VER2) {
			if (eof || (retlen == 0))
				tsiz = 0;
		} else if (retlen < len)
			tsiz = 0;
	}

	FSDBG_BOT(536, np, eof, uio_uio_resid(uiop), error);
	return (error);
}

int
nfs3_read_rpc_async(
	nfsnode_t np,
	off_t offset,
	size_t len,
	thread_t thd,
	kauth_cred_t cred,
	struct nfsreq_cbinfo *cb,
	struct nfsreq **reqp)
{
	struct nfsmount *nmp;
	int error = 0, nfsvers;
	struct nfsm_chain nmreq;

	nmp = NFSTONMP(np);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	nfsm_chain_null(&nmreq);
	nfsm_chain_build_alloc_init(error, &nmreq, NFSX_FH(nfsvers) + 3 * NFSX_UNSIGNED);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, np->n_fhp, np->n_fhsize);
	if (nfsvers == NFS_VER3) {
		nfsm_chain_add_64(error, &nmreq, offset);
		nfsm_chain_add_32(error, &nmreq, len);
	} else {
		nfsm_chain_add_32(error, &nmreq, offset);
		nfsm_chain_add_32(error, &nmreq, len);
		nfsm_chain_add_32(error, &nmreq, 0);
	}
	nfsm_chain_build_done(error, &nmreq);
	nfsmout_if(error);
	error = nfs_request_async(np, NULL, &nmreq, NFSPROC_READ, thd, cred, cb, reqp);
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	return (error);
}

int
nfs3_read_rpc_async_finish(
	nfsnode_t np,
	struct nfsreq *req,
	struct uio *uiop,
	size_t *lenp,
	int *eofp)
{
	int error = 0, lockerror, nfsvers, status, eof = 0;
	size_t retlen = 0;
	uint64_t xid;
	struct nfsmount *nmp;
	struct nfsm_chain nmrep;

	nmp = NFSTONMP(np);
	if (!nmp) {
		nfs_request_async_cancel(req);
		return (ENXIO);
	}
	nfsvers = nmp->nm_vers;

	nfsm_chain_null(&nmrep);

	error = nfs_request_async_finish(req, &nmrep, &xid, &status);
	if (error == EINPROGRESS) /* async request restarted */
		return (error);

	if ((lockerror = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
		error = lockerror;
	if (nfsvers == NFS_VER3)
		nfsm_chain_postop_attr_update(error, &nmrep, np, &xid);
	if (!error)
		error = status;
	if (nfsvers == NFS_VER3) {
		nfsm_chain_adv(error, &nmrep, NFSX_UNSIGNED);
		nfsm_chain_get_32(error, &nmrep, eof);
	} else {
		nfsm_chain_loadattr(error, &nmrep, np, nfsvers, NULL, &xid);
	}
	if (!lockerror)
		nfs_unlock(np);
	nfsm_chain_get_32(error, &nmrep, retlen);
	if ((nfsvers == NFS_VER2) && (retlen > *lenp))
		error = EBADRPC;
	nfsmout_if(error);
	error = nfsm_chain_get_uio(&nmrep, MIN(retlen, *lenp), uiop);
	if (eofp) {
		if (nfsvers == NFS_VER3) {
			if (!eof && !retlen)
				eof = 1;
		} else if (retlen < *lenp) {
			eof = 1;
		}
		*eofp = eof;
	}
	*lenp = MIN(retlen, *lenp);
nfsmout:
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

/*
 * NFS write call
 */
int
nfs_vnop_write(
	struct vnop_write_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		struct uio *a_uio;
		int a_ioflag;
		vfs_context_t a_context;
	} */ *ap)
{
	vfs_context_t ctx = ap->a_context;
	struct uio *uio = ap->a_uio;
	vnode_t vp = ap->a_vp;
	nfsnode_t np = VTONFS(vp);
	int ioflag = ap->a_ioflag;
	struct nfsbuf *bp;
	struct nfs_vattr nvattr;
	struct nfsmount *nmp = VTONMP(vp);
	daddr64_t lbn;
	int biosize;
	int n, on, error = 0;
	off_t boff, start, end;
	struct iovec_32 iov;
	struct uio auio;
	thread_t thd;
	kauth_cred_t cred;

	FSDBG_TOP(515, np, uio->uio_offset, uio_uio_resid(uio), ioflag);

	if (vnode_vtype(vp) != VREG) {
		FSDBG_BOT(515, np, uio->uio_offset, uio_uio_resid(uio), EIO);
		return (EIO);
	}

	thd = vfs_context_thread(ctx);
	cred = vfs_context_ucred(ctx);

	nfs_data_lock(np, NFS_NODE_LOCK_SHARED);

	if ((error = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE))) {
		nfs_data_unlock(np);
		FSDBG_BOT(515, np, uio->uio_offset, uio_uio_resid(uio), error);
		return (error);
	}
	np->n_wrbusy++;

	if (np->n_flag & NWRITEERR) {
		error = np->n_error;
		np->n_flag &= ~NWRITEERR;
	}
	if (np->n_flag & NNEEDINVALIDATE) {
		np->n_flag &= ~NNEEDINVALIDATE;
		nfs_unlock(np);
		nfs_data_unlock(np);
		nfs_vinvalbuf(vp, V_SAVE|V_IGNORE_WRITEERR, ctx, 1);
		nfs_data_lock(np, NFS_NODE_LOCK_SHARED);
		if (error || ((error = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE))))
			goto out;
	}
	if (error) {
		nfs_unlock(np);
		goto out;
	}

	biosize = nmp->nm_biosize;

	if (ioflag & (IO_APPEND | IO_SYNC)) {
		if (np->n_flag & NMODIFIED) {
			NATTRINVALIDATE(np);
			nfs_unlock(np);
			nfs_data_unlock(np);
			error = nfs_vinvalbuf(vp, V_SAVE, ctx, 1);
			nfs_data_lock(np, NFS_NODE_LOCK_SHARED);
			if (error || ((error = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))) {
				FSDBG(515, np, uio->uio_offset, 0x10bad01, error);
				goto out;
			}
		}
		if (ioflag & IO_APPEND) {
			NATTRINVALIDATE(np);
			nfs_unlock(np);
			nfs_data_unlock(np);
			error = nfs_getattr(np, &nvattr, ctx, 0);
			/* we'll be extending the file, so take the data lock exclusive */
			nfs_data_lock(np, NFS_NODE_LOCK_EXCLUSIVE);
			if (error || ((error = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))) {
				FSDBG(515, np, uio->uio_offset, 0x10bad02, error);
				goto out;
			}
			uio->uio_offset = np->n_size;
		}
	}
	if (uio->uio_offset < 0) {
		nfs_unlock(np);
		error = EINVAL;
		FSDBG_BOT(515, np, uio->uio_offset, 0xbad0ff, error);
		goto out;
	}
	if (uio_uio_resid(uio) == 0) {
		nfs_unlock(np);
		goto out;
	}

	nfs_unlock(np);

	if (((uio->uio_offset + uio_uio_resid(uio)) > (off_t)np->n_size) && !(ioflag & IO_APPEND)) {
		/* it looks like we'll be extending the file, so take the data lock exclusive */
		nfs_data_unlock(np);
		nfs_data_lock(np, NFS_NODE_LOCK_EXCLUSIVE);
	}

	do {
		OSAddAtomic(1, (SInt32*)&nfsstats.biocache_writes);
		lbn = uio->uio_offset / biosize;
		on = uio->uio_offset % biosize;
		// LP64todo - fix this
		n = min((unsigned)(biosize - on), uio_uio_resid(uio));
again:
		/*
		 * Get a cache block for writing.  The range to be written is
		 * (off..off+n) within the block.  We ensure that the block
		 * either has no dirty region or that the given range is
		 * contiguous with the existing dirty region.
		 */
		error = nfs_buf_get(np, lbn, biosize, thd, NBLK_WRITE, &bp);
		if (error)
			goto out;
		/* map the block because we know we're going to write to it */
		NFS_BUF_MAP(bp);

		if (ioflag & IO_NOCACHE)
			SET(bp->nb_flags, NB_NOCACHE);

		if (!IS_VALID_CRED(bp->nb_wcred)) {
			kauth_cred_ref(cred);
			bp->nb_wcred = cred;
		}

		/*
		 * If there's already a dirty range AND dirty pages in this block we
		 * need to send a commit AND write the dirty pages before continuing.
		 *
		 * If there's already a dirty range OR dirty pages in this block
		 * and the new write range is not contiguous with the existing range,
		 * then force the buffer to be written out now.
		 * (We used to just extend the dirty range to cover the valid,
		 * but unwritten, data in between also.  But writing ranges
		 * of data that weren't actually written by an application
		 * risks overwriting some other client's data with stale data
		 * that's just masquerading as new written data.)
		 */
		if (bp->nb_dirtyend > 0) {
		    if (on > bp->nb_dirtyend || (on + n) < bp->nb_dirtyoff || bp->nb_dirty) {
			FSDBG(515, np, uio->uio_offset, bp, 0xd15c001);
			/* write/commit buffer "synchronously" */
			/* (NB_STABLE indicates that data writes should be FILESYNC) */
			CLR(bp->nb_flags, (NB_DONE | NB_ERROR | NB_INVAL));
			SET(bp->nb_flags, (NB_ASYNC | NB_STABLE));
			error = nfs_buf_write(bp);
			if (error)
			    goto out;
			goto again;
		    }
		} else if (bp->nb_dirty) {
		    int firstpg, lastpg;
		    u_int32_t pagemask;
		    /* calculate write range pagemask */
		    firstpg = on/PAGE_SIZE;
		    lastpg = (on+n-1)/PAGE_SIZE;
		    pagemask = ((1 << (lastpg+1)) - 1) & ~((1 << firstpg) - 1);
		    /* check if there are dirty pages outside the write range */
		    if (bp->nb_dirty & ~pagemask) {
			FSDBG(515, np, uio->uio_offset, bp, 0xd15c002);
			/* write/commit buffer "synchronously" */
			/* (NB_STABLE indicates that data writes should be FILESYNC) */
			CLR(bp->nb_flags, (NB_DONE | NB_ERROR | NB_INVAL));
			SET(bp->nb_flags, (NB_ASYNC | NB_STABLE));
			error = nfs_buf_write(bp);
			if (error)
			    goto out;
			goto again;
		    }
		    /* if the first or last pages are already dirty */
		    /* make sure that the dirty range encompasses those pages */
		    if (NBPGDIRTY(bp,firstpg) || NBPGDIRTY(bp,lastpg)) {
			FSDBG(515, np, uio->uio_offset, bp, 0xd15c003);
		    	bp->nb_dirtyoff = min(on, firstpg * PAGE_SIZE);
			if (NBPGDIRTY(bp,lastpg)) {
			    bp->nb_dirtyend = (lastpg+1) * PAGE_SIZE;
			    /* clip to EOF */
			    if (NBOFF(bp) + bp->nb_dirtyend > (off_t)np->n_size) {
				    bp->nb_dirtyend = np->n_size - NBOFF(bp);
				    if (bp->nb_dirtyoff >= bp->nb_dirtyend)
					    bp->nb_dirtyoff = bp->nb_dirtyend = 0;
			    }
			} else
			    bp->nb_dirtyend = on+n;
		    }
		}

		/*
		 * Are we extending the size of the file with this write?
		 * If so, update file size now that we have the block.
		 * If there was a partial buf at the old eof, validate
		 * and zero the new bytes.
		 */
		if ((uio->uio_offset + n) > (off_t)np->n_size) {
			struct nfsbuf *eofbp = NULL;
			daddr64_t eofbn = np->n_size / biosize;
			int eofoff = np->n_size % biosize;
			int neweofoff = (uio->uio_offset + n) % biosize;

			FSDBG(515, 0xb1ffa000, uio->uio_offset + n, eofoff, neweofoff);

			if (eofoff && (eofbn < lbn) &&
			    ((error = nfs_buf_get(np, eofbn, biosize, thd, NBLK_WRITE|NBLK_ONLYVALID, &eofbp))))
				goto out;

			/* if we're extending within the same last block */
			/* and the block is flagged as being cached... */
			if ((lbn == eofbn) && ISSET(bp->nb_flags, NB_CACHE)) {
				/* ...check that all pages in buffer are valid */
				int endpg = ((neweofoff ? neweofoff : biosize) - 1)/PAGE_SIZE;
				u_int32_t pagemask;
				/* pagemask only has to extend to last page being written to */
				pagemask = (1 << (endpg+1)) - 1;
				FSDBG(515, 0xb1ffa001, bp->nb_valid, pagemask, 0);
				if ((bp->nb_valid & pagemask) != pagemask) {
					/* zerofill any hole */
					if (on > bp->nb_validend) {
						int i;
						for (i=bp->nb_validend/PAGE_SIZE; i <= (on - 1)/PAGE_SIZE; i++)
							NBPGVALID_SET(bp, i);
						NFS_BUF_MAP(bp);
						FSDBG(516, bp, bp->nb_validend, on - bp->nb_validend, 0xf01e);
						bzero((char *)bp->nb_data + bp->nb_validend,
							on - bp->nb_validend);
					}
					/* zerofill any trailing data in the last page */
					if (neweofoff) {
						NFS_BUF_MAP(bp);
						FSDBG(516, bp, neweofoff, PAGE_SIZE - (neweofoff & PAGE_MASK), 0xe0f);
						bzero((char *)bp->nb_data + neweofoff,
							PAGE_SIZE - (neweofoff & PAGE_MASK));
					}
				}
			}
			np->n_size = uio->uio_offset + n;
			nfs_lock(np, NFS_NODE_LOCK_FORCE);
			CLR(np->n_flag, NUPDATESIZE);
			np->n_flag |= NMODIFIED;
			nfs_unlock(np);
			FSDBG(516, np, np->n_size, np->n_vattr.nva_size, 0xf00d0001);
			ubc_setsize(vp, (off_t)np->n_size); /* XXX errors */
			if (eofbp) {
				/*
				 * We may need to zero any previously invalid data
				 * after the old EOF in the previous EOF buffer.
				 *
				 * For the old last page, don't zero bytes if there
				 * are invalid bytes in that page (i.e. the page isn't
				 * currently valid).
				 * For pages after the old last page, zero them and
				 * mark them as valid.
				 */
				char *d;
				int i;
				if (ioflag & IO_NOCACHE)
					SET(eofbp->nb_flags, NB_NOCACHE);
				NFS_BUF_MAP(eofbp);
				FSDBG(516, eofbp, eofoff, biosize - eofoff, 0xe0fff01e);
				d = eofbp->nb_data;
				i = eofoff/PAGE_SIZE;
				while (eofoff < biosize) {
					int poff = eofoff & PAGE_MASK;
					if (!poff || NBPGVALID(eofbp,i)) {
						bzero(d + eofoff, PAGE_SIZE - poff);
						NBPGVALID_SET(eofbp, i);
					}
					if (bp->nb_validend == eofoff)
						bp->nb_validend += PAGE_SIZE - poff;
					eofoff += PAGE_SIZE - poff;
					i++;
				}
				nfs_buf_release(eofbp, 1);
			}
		}
		/*
		 * If dirtyend exceeds file size, chop it down.  This should
		 * not occur unless there is a race.
		 */
		if (NBOFF(bp) + bp->nb_dirtyend > (off_t)np->n_size) {
			bp->nb_dirtyend = np->n_size - NBOFF(bp);
			if (bp->nb_dirtyoff >= bp->nb_dirtyend)
				bp->nb_dirtyoff = bp->nb_dirtyend = 0;
		}
		/*
		 * UBC doesn't handle partial pages, so we need to make sure
		 * that any pages left in the page cache are completely valid.
		 *
		 * Writes that are smaller than a block are delayed if they
		 * don't extend to the end of the block.
		 *
		 * If the block isn't (completely) cached, we may need to read
		 * in some parts of pages that aren't covered by the write.
		 * If the write offset (on) isn't page aligned, we'll need to
		 * read the start of the first page being written to.  Likewise,
		 * if the offset of the end of the write (on+n) isn't page aligned,
		 * we'll need to read the end of the last page being written to.
		 *
		 * Notes:
		 * We don't want to read anything we're just going to write over.
		 * We don't want to issue multiple I/Os if we don't have to
		 *   (because they're synchronous rpcs).
		 * We don't want to read anything we already have modified in the
		 *   page cache.
		 */
		if (!ISSET(bp->nb_flags, NB_NOCACHE) && !ISSET(bp->nb_flags, NB_CACHE) && (n < biosize)) {
			int firstpg, lastpg, dirtypg;
			int firstpgoff, lastpgoff;
			start = end = -1;
			firstpg = on/PAGE_SIZE;
			firstpgoff = on & PAGE_MASK;
			lastpg = (on+n-1)/PAGE_SIZE;
			lastpgoff = (on+n) & PAGE_MASK;
			if (firstpgoff && !NBPGVALID(bp,firstpg)) {
				/* need to read start of first page */
				start = firstpg * PAGE_SIZE;
				end = start + firstpgoff;
			}
			if (lastpgoff && !NBPGVALID(bp,lastpg)) {
				/* need to read end of last page */
				if (start < 0)
					start = (lastpg * PAGE_SIZE) + lastpgoff;
				end = (lastpg + 1) * PAGE_SIZE;
			}
			if (end > start) {
				/* need to read the data in range: start...end-1 */

				/* first, check for dirty pages in between */
				/* if there are, we'll have to do two reads because */
				/* we don't want to overwrite the dirty pages. */
				for (dirtypg=start/PAGE_SIZE; dirtypg <= (end-1)/PAGE_SIZE; dirtypg++)
					if (NBPGDIRTY(bp,dirtypg))
						break;

				/* if start is at beginning of page, try */
				/* to get any preceeding pages as well. */
				if (!(start & PAGE_MASK)) {
					/* stop at next dirty/valid page or start of block */
					for (; start > 0; start-=PAGE_SIZE)
						if (NBPGVALID(bp,((start-1)/PAGE_SIZE)))
							break;
				}

				NFS_BUF_MAP(bp);
				/* setup uio for read(s) */
				boff = NBOFF(bp);
				auio.uio_iovs.iov32p = &iov;
				auio.uio_iovcnt = 1;
#if 1   /* LP64todo - can't use new segment flags until the drivers are ready */
				auio.uio_segflg = UIO_SYSSPACE;
#else
				auio.uio_segflg = UIO_SYSSPACE32;
#endif
				auio.uio_rw = UIO_READ;

				if (dirtypg <= (end-1)/PAGE_SIZE) {
					/* there's a dirty page in the way, so just do two reads */
					/* we'll read the preceding data here */
					auio.uio_offset = boff + start;
					iov.iov_len = on - start;
					uio_uio_resid_set(&auio, iov.iov_len);
					iov.iov_base = (uintptr_t) bp->nb_data + start;
					error = nfs_read_rpc(np, &auio, ctx);
					if (error) /* couldn't read the data, so treat buffer as NOCACHE */
						SET(bp->nb_flags, (NB_NOCACHE|NB_STABLE));
					if (uio_uio_resid(&auio) > 0) {
						FSDBG(516, bp, (caddr_t)iov.iov_base - bp->nb_data, uio_uio_resid(&auio), 0xd00dee01);
						// LP64todo - fix this
						bzero((caddr_t)iov.iov_base, uio_uio_resid(&auio));
					}
					if (!error) {
						/* update validoff/validend if necessary */
						if ((bp->nb_validoff < 0) || (bp->nb_validoff > start))
							bp->nb_validoff = start;
						if ((bp->nb_validend < 0) || (bp->nb_validend < on))
							bp->nb_validend = on;
						if ((off_t)np->n_size > boff + bp->nb_validend)
							bp->nb_validend = min(np->n_size - (boff + start), biosize);
						/* validate any pages before the write offset */
						for (; start < on/PAGE_SIZE; start+=PAGE_SIZE)
							NBPGVALID_SET(bp, start/PAGE_SIZE);
					}
					/* adjust start to read any trailing data */
					start = on+n;
				}

				/* if end is at end of page, try to */
				/* get any following pages as well. */
				if (!(end & PAGE_MASK)) {
					/* stop at next valid page or end of block */
					for (; end < biosize; end+=PAGE_SIZE)
						if (NBPGVALID(bp,end/PAGE_SIZE))
							break;
				}

				if (((boff+start) >= (off_t)np->n_size) ||
				    ((start >= on) && ((boff + on + n) >= (off_t)np->n_size))) {
					/*
					 * Either this entire read is beyond the current EOF
					 * or the range that we won't be modifying (on+n...end)
					 * is all beyond the current EOF.
					 * No need to make a trip across the network to
					 * read nothing.  So, just zero the buffer instead.
					 */
					FSDBG(516, bp, start, end - start, 0xd00dee00);
					bzero(bp->nb_data + start, end - start);
					error = 0;
				} else if (!ISSET(bp->nb_flags, NB_NOCACHE)) {
					/* now we'll read the (rest of the) data */
					auio.uio_offset = boff + start;
					iov.iov_len = end - start;
					uio_uio_resid_set(&auio, iov.iov_len);
					iov.iov_base = (uintptr_t) (bp->nb_data + start);
					error = nfs_read_rpc(np, &auio, ctx);
					if (error) /* couldn't read the data, so treat buffer as NOCACHE */
						SET(bp->nb_flags, (NB_NOCACHE|NB_STABLE));
					if (uio_uio_resid(&auio) > 0) {
						FSDBG(516, bp, (caddr_t)iov.iov_base - bp->nb_data, uio_uio_resid(&auio), 0xd00dee02);
						// LP64todo - fix this
						bzero((caddr_t)iov.iov_base, uio_uio_resid(&auio));
					}
				}
				if (!error) {
					/* update validoff/validend if necessary */
					if ((bp->nb_validoff < 0) || (bp->nb_validoff > start))
						bp->nb_validoff = start;
					if ((bp->nb_validend < 0) || (bp->nb_validend < end))
						bp->nb_validend = end;
					if ((off_t)np->n_size > boff + bp->nb_validend)
						bp->nb_validend = min(np->n_size - (boff + start), biosize);
					/* validate any pages before the write offset's page */
					for (; start < trunc_page_32(on); start+=PAGE_SIZE)
						NBPGVALID_SET(bp, start/PAGE_SIZE);
					/* validate any pages after the range of pages being written to */
					for (; (end - 1) > round_page_32(on+n-1); end-=PAGE_SIZE)
						NBPGVALID_SET(bp, (end-1)/PAGE_SIZE);
				}
				/* Note: pages being written to will be validated when written */
			}
		}

		if (ISSET(bp->nb_flags, NB_ERROR)) {
			error = bp->nb_error;
			nfs_buf_release(bp, 1);
			goto out;
		}

		nfs_lock(np, NFS_NODE_LOCK_FORCE);
		np->n_flag |= NMODIFIED;
		nfs_unlock(np);

		NFS_BUF_MAP(bp);
		error = uiomove((char *)bp->nb_data + on, n, uio);
		if (error) {
			SET(bp->nb_flags, NB_ERROR);
			nfs_buf_release(bp, 1);
			goto out;
		}

		/* validate any pages written to */
		start = on & ~PAGE_MASK;
		for (; start < on+n; start += PAGE_SIZE) {
			NBPGVALID_SET(bp, start/PAGE_SIZE);
			/*
			 * This may seem a little weird, but we don't actually set the
			 * dirty bits for writes.  This is because we keep the dirty range
			 * in the nb_dirtyoff/nb_dirtyend fields.  Also, particularly for
			 * delayed writes, when we give the pages back to the VM we don't
			 * want to keep them marked dirty, because when we later write the
			 * buffer we won't be able to tell which pages were written dirty
			 * and which pages were mmapped and dirtied.
			 */
		}
		if (bp->nb_dirtyend > 0) {
			bp->nb_dirtyoff = min(on, bp->nb_dirtyoff);
			bp->nb_dirtyend = max((on + n), bp->nb_dirtyend);
		} else {
			bp->nb_dirtyoff = on;
			bp->nb_dirtyend = on + n;
		}
		if (bp->nb_validend <= 0 || bp->nb_validend < bp->nb_dirtyoff ||
		    bp->nb_validoff > bp->nb_dirtyend) {
			bp->nb_validoff = bp->nb_dirtyoff;
			bp->nb_validend = bp->nb_dirtyend;
		} else {
			bp->nb_validoff = min(bp->nb_validoff, bp->nb_dirtyoff);
			bp->nb_validend = max(bp->nb_validend, bp->nb_dirtyend);
		}
		if (!ISSET(bp->nb_flags, NB_CACHE))
			nfs_buf_normalize_valid_range(np, bp);

		/*
		 * Since this block is being modified, it must be written
		 * again and not just committed.
		 */
		if (ISSET(bp->nb_flags, NB_NEEDCOMMIT)) {
			nfs_lock(np, NFS_NODE_LOCK_FORCE);
			if (ISSET(bp->nb_flags, NB_NEEDCOMMIT)) {
				np->n_needcommitcnt--;
				CHECK_NEEDCOMMITCNT(np);
			}
			CLR(bp->nb_flags, NB_NEEDCOMMIT);
			nfs_unlock(np);
		}

		if (ioflag & IO_SYNC) {
			error = nfs_buf_write(bp);
			if (error)
				goto out;
		} else if (((n + on) == biosize) || (ioflag & IO_NOCACHE) || ISSET(bp->nb_flags, NB_NOCACHE)) {
			SET(bp->nb_flags, NB_ASYNC);
			error = nfs_buf_write(bp);
			if (error)
				goto out;
		} else {
			/* If the block wasn't already delayed: charge for the write */
			if (!ISSET(bp->nb_flags, NB_DELWRI)) {
				proc_t p = vfs_context_proc(ctx);
				if (p && p->p_stats)
					OSIncrementAtomic(&p->p_stats->p_ru.ru_oublock);
			}
			nfs_buf_write_delayed(bp);
		}
		if (np->n_needcommitcnt >= NFS_A_LOT_OF_NEEDCOMMITS)
		        nfs_flushcommits(np, 1);

	} while (uio_uio_resid(uio) > 0 && n > 0);

out:
	nfs_lock(np, NFS_NODE_LOCK_FORCE);
	np->n_wrbusy--;
	nfs_unlock(np);
	nfs_data_unlock(np);
	FSDBG_BOT(515, np, uio->uio_offset, uio_uio_resid(uio), error);
	return (error);
}


/*
 * NFS write call
 */
int
nfs_write_rpc(
	nfsnode_t np,
	struct uio *uiop,
	vfs_context_t ctx,
	int *iomodep,
	uint64_t *wverfp)
{
	return nfs_write_rpc2(np, uiop, vfs_context_thread(ctx), vfs_context_ucred(ctx), iomodep, wverfp);
}

int
nfs_write_rpc2(
	nfsnode_t np,
	struct uio *uiop,
	thread_t thd,
	kauth_cred_t cred,
	int *iomodep,
	uint64_t *wverfp)
{
	struct nfsmount *nmp;
	int error = 0, nfsvers, restart;
	int backup, wverfset, commit, committed;
	uint64_t wverf = 0, wverf2;
	size_t nmwsize, totalsize, tsiz, len, rlen;
	struct nfsreq rq, *req = &rq;

#if DIAGNOSTIC
	/* XXX limitation based on need to back up uio on short write */
	if (uiop->uio_iovcnt != 1)
		panic("nfs3_write_rpc: iovcnt > 1");
#endif
	FSDBG_TOP(537, np, uiop->uio_offset, uio_uio_resid(uiop), *iomodep);
	nmp = NFSTONMP(np);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;
	nmwsize = nmp->nm_wsize;

	restart = wverfset = 0;
	committed = NFS_WRITE_FILESYNC;

	// LP64todo - fix this
	totalsize = tsiz = uio_uio_resid(uiop);
	if (((u_int64_t)uiop->uio_offset + (unsigned int)tsiz > 0xffffffff) && (nfsvers == NFS_VER2)) {
		FSDBG_BOT(537, np, uiop->uio_offset, uio_uio_resid(uiop), EFBIG);
		return (EFBIG);
	}

	while (tsiz > 0) {
		len = (tsiz > nmwsize) ? nmwsize : tsiz;
		FSDBG(537, np, uiop->uio_offset, len, 0);
		error = nmp->nm_funcs->nf_write_rpc_async(np, uiop, len, thd, cred, *iomodep, NULL, &req);
		if (!error)
			error = nmp->nm_funcs->nf_write_rpc_async_finish(np, req, &commit, &rlen, &wverf2);
		nmp = NFSTONMP(np);
		if (!nmp)
			error = ENXIO;
		if (error)
			break;
		if (nfsvers == NFS_VER2) {
			tsiz -= len;
			continue;
		}

		/* check for a short write */
		if (rlen < len) {
			backup = len - rlen;
			uio_iov_base_add(uiop, -backup);
			uio_iov_len_add(uiop, backup);
			uiop->uio_offset -= backup;
			uio_uio_resid_add(uiop, backup);
			len = rlen;
		}

		/* return lowest commit level returned */
		if (commit < committed)
			committed = commit;

		tsiz -= len;

		/* check write verifier */
		if (!wverfset) {
			wverf = wverf2;
			wverfset = 1;
		} else if (wverf != wverf2) {
			/* verifier changed, so we need to restart all the writes */
			if (++restart > 10) {
				/* give up after too many restarts */
				error = EIO;
				break;
			}
			backup = totalsize - tsiz;
			uio_iov_base_add(uiop, -backup);
			uio_iov_len_add(uiop, backup);
			uiop->uio_offset -= backup;
			uio_uio_resid_add(uiop, backup);
			committed = NFS_WRITE_FILESYNC;
			wverfset = 0;
			tsiz = totalsize;
		}
	}
	if (wverfset && wverfp)
		*wverfp = wverf;
	*iomodep = committed;
	if (error)
		uio_uio_resid_set(uiop, tsiz);
	FSDBG_BOT(537, np, committed, uio_uio_resid(uiop), error);
	return (error);
}

int
nfs3_write_rpc_async(
	nfsnode_t np,
	struct uio *uiop,
	size_t len,
	thread_t thd,
	kauth_cred_t cred,
	int iomode,
	struct nfsreq_cbinfo *cb,
	struct nfsreq **reqp)
{
	struct nfsmount *nmp;
	int error = 0, nfsvers;
	off_t offset;
	struct nfsm_chain nmreq;

	nmp = NFSTONMP(np);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	offset = uiop->uio_offset;

	nfsm_chain_null(&nmreq);
	nfsm_chain_build_alloc_init(error, &nmreq,
		NFSX_FH(nfsvers) + 5 * NFSX_UNSIGNED + nfsm_rndup(len));
	nfsm_chain_add_fh(error, &nmreq, nfsvers, np->n_fhp, np->n_fhsize);
	if (nfsvers == NFS_VER3) {
		nfsm_chain_add_64(error, &nmreq, offset);
		nfsm_chain_add_32(error, &nmreq, len);
		nfsm_chain_add_32(error, &nmreq, iomode);
	} else {
		nfsm_chain_add_32(error, &nmreq, 0);
		nfsm_chain_add_32(error, &nmreq, offset);
		nfsm_chain_add_32(error, &nmreq, 0);
	}
	nfsm_chain_add_32(error, &nmreq, len);
	nfsmout_if(error);
	error = nfsm_chain_add_uio(&nmreq, uiop, len);
	nfsm_chain_build_done(error, &nmreq);
	nfsmout_if(error);
	error = nfs_request_async(np, NULL, &nmreq, NFSPROC_WRITE, thd, cred, cb, reqp);
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	return (error);
}

int
nfs3_write_rpc_async_finish(
	nfsnode_t np,
	struct nfsreq *req,
	int *iomodep,
	size_t *rlenp,
	uint64_t *wverfp)
{
	struct nfsmount *nmp;
	int error = 0, lockerror = ENOENT, nfsvers, status;
	int updatemtime = 0, wccpostattr = 0, rlen, committed = NFS_WRITE_FILESYNC;
	u_int64_t xid, wverf;
	mount_t mp;
	struct nfsm_chain nmrep;

	nmp = NFSTONMP(np);
	if (!nmp) {
		nfs_request_async_cancel(req);
		return (ENXIO);
	}
	nfsvers = nmp->nm_vers;

	nfsm_chain_null(&nmrep);

	error = nfs_request_async_finish(req, &nmrep, &xid, &status);
	if (error == EINPROGRESS) /* async request restarted */
		return (error);
	nmp = NFSTONMP(np);
	if (!nmp)
		error = ENXIO;
	if (!error && (lockerror = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
		error = lockerror;
	if (nfsvers == NFS_VER3) {
		struct timespec premtime = { 0, 0 };
		nfsm_chain_get_wcc_data(error, &nmrep, np, &premtime, &wccpostattr, &xid);
		if (nfstimespeccmp(&np->n_mtime, &premtime, ==))
			updatemtime = 1;
		if (!error)
			error = status;
		nfsm_chain_get_32(error, &nmrep, rlen);
		nfsmout_if(error);
		*rlenp = rlen;
		if (rlen <= 0)
			error = NFSERR_IO;
		nfsm_chain_get_32(error, &nmrep, committed);
		nfsm_chain_get_64(error, &nmrep, wverf);
		nfsmout_if(error);
		if (wverfp)
			*wverfp = wverf;
		lck_mtx_lock(&nmp->nm_lock);
		if (!(nmp->nm_state & NFSSTA_HASWRITEVERF)) {
			nmp->nm_verf = wverf;
			nmp->nm_state |= NFSSTA_HASWRITEVERF;
		} else if (nmp->nm_verf != wverf) {
			nmp->nm_verf = wverf;
		}
		lck_mtx_unlock(&nmp->nm_lock);
	} else {
		if (!error)
			error = status;
		nfsm_chain_loadattr(error, &nmrep, np, nfsvers, NULL, &xid);
		nfsmout_if(error);
	}
	if (updatemtime)
		NFS_CHANGED_UPDATE(nfsvers, np, &np->n_vattr);
nfsmout:
	if (!lockerror)
		nfs_unlock(np);
	nfsm_chain_cleanup(&nmrep);
	if ((committed != NFS_WRITE_FILESYNC) && nfs_allow_async &&
	    ((mp = NFSTOMP(np))) && (vfs_flags(mp) & MNT_ASYNC))
		committed = NFS_WRITE_FILESYNC;
	*iomodep = committed;
	return (error);
}

/*
 * NFS mknod vnode op
 *
 * For NFS v2 this is a kludge. Use a create RPC but with the IFMT bits of the
 * mode set to specify the file type and the size field for rdev.
 */
static int
nfs3_vnop_mknod(
	struct vnop_mknod_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_dvp;
		vnode_t *a_vpp;
		struct componentname *a_cnp;
		struct vnode_attr *a_vap;
		vfs_context_t a_context;
	} */ *ap)
{
	vnode_t dvp = ap->a_dvp;
	vnode_t *vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	struct vnode_attr *vap = ap->a_vap;
	vfs_context_t ctx = ap->a_context;
	vnode_t newvp = NULL;
	nfsnode_t np = NULL;
	struct nfsmount *nmp;
	nfsnode_t dnp = VTONFS(dvp);
	struct nfs_vattr nvattr, dnvattr;
	fhandle_t fh;
	int error = 0, lockerror = ENOENT, status, wccpostattr = 0;
	struct timespec premtime = { 0, 0 };
	u_long rdev;
	u_int64_t xid, dxid;
	int nfsvers, gotuid, gotgid;
	struct nfsm_chain nmreq, nmrep;

	nmp = VTONMP(dvp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	if (!VATTR_IS_ACTIVE(vap, va_type))
		return (EINVAL);
	if (vap->va_type == VCHR || vap->va_type == VBLK) {
		if (!VATTR_IS_ACTIVE(vap, va_rdev))
			return (EINVAL);
		rdev = vap->va_rdev;
	} else if (vap->va_type == VFIFO || vap->va_type == VSOCK)
		rdev = 0xffffffff;
	else {
		return (ENOTSUP);
	}
	if ((nfsvers == NFS_VER2) && (cnp->cn_namelen > NFS_MAXNAMLEN))
		return (ENAMETOOLONG);

	VATTR_SET_SUPPORTED(vap, va_mode);
	VATTR_SET_SUPPORTED(vap, va_uid);
	VATTR_SET_SUPPORTED(vap, va_gid);
	VATTR_SET_SUPPORTED(vap, va_data_size);
	VATTR_SET_SUPPORTED(vap, va_access_time);
	VATTR_SET_SUPPORTED(vap, va_modify_time);
	gotuid = VATTR_IS_ACTIVE(vap, va_uid);
	gotgid = VATTR_IS_ACTIVE(vap, va_gid);

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	nfsm_chain_build_alloc_init(error, &nmreq,
		NFSX_FH(nfsvers) + 4 * NFSX_UNSIGNED +
		nfsm_rndup(cnp->cn_namelen) + NFSX_SATTR(nfsvers));
	nfsm_chain_add_fh(error, &nmreq, nfsvers, dnp->n_fhp, dnp->n_fhsize);
	nfsm_chain_add_string(error, &nmreq, cnp->cn_nameptr, cnp->cn_namelen);
	if (nfsvers == NFS_VER3) {
		nfsm_chain_add_32(error, &nmreq, vtonfs_type(vap->va_type, nfsvers));
		nfsm_chain_add_v3sattr(error, &nmreq, vap);
		if (vap->va_type == VCHR || vap->va_type == VBLK) {
			nfsm_chain_add_32(error, &nmreq, major(vap->va_rdev));
			nfsm_chain_add_32(error, &nmreq, minor(vap->va_rdev));
		}
	} else {
		nfsm_chain_add_v2sattr(error, &nmreq, vap, rdev);
	}
	nfsm_chain_build_done(error, &nmreq);
	nfsmout_if(error);
	if ((lockerror = nfs_lock(dnp, NFS_NODE_LOCK_EXCLUSIVE)))
		error = lockerror;
	nfsmout_if(error);

	error = nfs_request(dnp, NULL, &nmreq, NFSPROC_MKNOD, ctx, &nmrep, &xid, &status);

	/* XXX no EEXIST kludge here? */
	dxid = xid;
	if (!error && !status) {
		if (dnp->n_flag & NNEGNCENTRIES) {
			dnp->n_flag &= ~NNEGNCENTRIES;
			cache_purge_negatives(dvp);
		}
		error = nfsm_chain_get_fh_attr(&nmrep, dnp, ctx, nfsvers, &xid, &fh, &nvattr);
	}
	if (nfsvers == NFS_VER3)
		nfsm_chain_get_wcc_data(error, &nmrep, dnp, &premtime, &wccpostattr, &dxid);
	if (!error)
		error = status;
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);

	if (!lockerror) {
		dnp->n_flag |= NMODIFIED;
		/* if directory hadn't changed, update namecache mtime */
		if (nfstimespeccmp(&dnp->n_ncmtime, &premtime, ==))
			NFS_CHANGED_UPDATE_NC(nfsvers, dnp, &dnp->n_vattr);
		if (!wccpostattr)
			NATTRINVALIDATE(dnp);
		if (!nfs_getattr(dnp, &dnvattr, ctx, 1)) {
			if (NFS_CHANGED_NC(nfsvers, dnp, &dnvattr)) {
				dnp->n_flag &= ~NNEGNCENTRIES;
				cache_purge(dvp);
				NFS_CHANGED_UPDATE_NC(nfsvers, dnp, &dnvattr);
			}
		}
	}

	if (!error && fh.fh_len)
		error = nfs_nget(NFSTOMP(dnp), dnp, cnp, fh.fh_data, fh.fh_len, &nvattr, &xid, NG_MAKEENTRY, &np);
	if (!error && !np)
		error = nfs_lookitup(dnp, cnp->cn_nameptr, cnp->cn_namelen, ctx, &np);
	if (!error && np)
		newvp = NFSTOV(np);
	if (!lockerror)
		nfs_unlock(dnp);

	if (!error && (gotuid || gotgid) &&
	    (!newvp || nfs_getattrcache(np, &nvattr, 1) ||
	     (gotuid && (nvattr.nva_uid != vap->va_uid)) ||
	     (gotgid && (nvattr.nva_gid != vap->va_gid)))) {
		/* clear ID bits if server didn't use them (or we can't tell) */
		VATTR_CLEAR_SUPPORTED(vap, va_uid);
		VATTR_CLEAR_SUPPORTED(vap, va_gid);
	}
	if (error) {
		if (newvp) {
			nfs_unlock(np);
			vnode_put(newvp);
		}
	} else {
		*vpp = newvp;
		nfs_unlock(np);
	}
	return (error);
}

static u_long create_verf;
/*
 * NFS file create call
 */
static int
nfs3_vnop_create(
	struct vnop_create_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_dvp;
		vnode_t *a_vpp;
		struct componentname *a_cnp;
		struct vnode_attr *a_vap;
		vfs_context_t a_context;
	} */ *ap)
{
	vfs_context_t ctx = ap->a_context;
	vnode_t dvp = ap->a_dvp;
	struct vnode_attr *vap = ap->a_vap;
	struct componentname *cnp = ap->a_cnp;
	struct nfs_vattr nvattr, dnvattr;
	fhandle_t fh;
	nfsnode_t np = NULL;
	struct nfsmount *nmp;
	nfsnode_t dnp = VTONFS(dvp);
	vnode_t newvp = NULL;
	int error = 0, lockerror = ENOENT, status, wccpostattr = 0, fmode = 0;
	struct timespec premtime = { 0, 0 };
	int nfsvers, gotuid, gotgid;
	u_int64_t xid, dxid;
	uint32_t val;
	struct nfsm_chain nmreq, nmrep;
	struct nfsreq *req;
	struct nfs_dulookup dul;

	nmp = VTONMP(dvp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	if ((nfsvers == NFS_VER2) && (cnp->cn_namelen > NFS_MAXNAMLEN))
		return (ENAMETOOLONG);

	VATTR_SET_SUPPORTED(vap, va_mode);
	VATTR_SET_SUPPORTED(vap, va_uid);
	VATTR_SET_SUPPORTED(vap, va_gid);
	VATTR_SET_SUPPORTED(vap, va_data_size);
	VATTR_SET_SUPPORTED(vap, va_access_time);
	VATTR_SET_SUPPORTED(vap, va_modify_time);
	gotuid = VATTR_IS_ACTIVE(vap, va_uid);
	gotgid = VATTR_IS_ACTIVE(vap, va_gid);

	if (vap->va_vaflags & VA_EXCLUSIVE)
		fmode |= O_EXCL;

again:
	req = NULL;
	nfs_dulookup_init(&dul, dnp, cnp->cn_nameptr, cnp->cn_namelen);

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	nfsm_chain_build_alloc_init(error, &nmreq,
		NFSX_FH(nfsvers) + 2 * NFSX_UNSIGNED +
		nfsm_rndup(cnp->cn_namelen) + NFSX_SATTR(nfsvers));
	nfsm_chain_add_fh(error, &nmreq, nfsvers, dnp->n_fhp, dnp->n_fhsize);
	nfsm_chain_add_string(error, &nmreq, cnp->cn_nameptr, cnp->cn_namelen);
	if (nfsvers == NFS_VER3) {
		if (fmode & O_EXCL) {
			nfsm_chain_add_32(error, &nmreq, NFS_CREATE_EXCLUSIVE);
			if (!TAILQ_EMPTY(&in_ifaddrhead))
				val = IA_SIN(in_ifaddrhead.tqh_first)->sin_addr.s_addr;
			else
				val = create_verf;
			nfsm_chain_add_32(error, &nmreq, val);
			++create_verf;
			nfsm_chain_add_32(error, &nmreq, create_verf);
		} else {
			nfsm_chain_add_32(error, &nmreq, NFS_CREATE_UNCHECKED);
			nfsm_chain_add_v3sattr(error, &nmreq, vap);
		}
	} else {
		nfsm_chain_add_v2sattr(error, &nmreq, vap, 0);
	}
	nfsm_chain_build_done(error, &nmreq);
	nfsmout_if(error);
	if ((lockerror = nfs_lock(dnp, NFS_NODE_LOCK_EXCLUSIVE)))
		error = lockerror;
	nfsmout_if(error);

	error = nfs_request_async(dnp, NULL, &nmreq, NFSPROC_CREATE,
			vfs_context_thread(ctx), vfs_context_ucred(ctx), NULL, &req);
	if (!error) {
		nfs_dulookup_start(&dul, dnp, ctx);
		error = nfs_request_async_finish(req, &nmrep, &xid, &status);
	}

	dxid = xid;
	if (!error && !status) {
		if (dnp->n_flag & NNEGNCENTRIES) {
			dnp->n_flag &= ~NNEGNCENTRIES;
			cache_purge_negatives(dvp);
		}
		error = nfsm_chain_get_fh_attr(&nmrep, dnp, ctx, nfsvers, &xid, &fh, &nvattr);
	}
	if (nfsvers == NFS_VER3)
		nfsm_chain_get_wcc_data(error, &nmrep, dnp, &premtime, &wccpostattr, &dxid);
	if (!error)
		error = status;
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);

	if (!lockerror) {
		dnp->n_flag |= NMODIFIED;
		/* if directory hadn't changed, update namecache mtime */
		if (nfstimespeccmp(&dnp->n_ncmtime, &premtime, ==))
			NFS_CHANGED_UPDATE_NC(nfsvers, dnp, &dnp->n_vattr);
		if (!wccpostattr)
			NATTRINVALIDATE(dnp);
		if (!nfs_getattr(dnp, &dnvattr, ctx, 1)) {
			if (NFS_CHANGED_NC(nfsvers, dnp, &dnvattr)) {
				dnp->n_flag &= ~NNEGNCENTRIES;
				cache_purge(dvp);
				NFS_CHANGED_UPDATE_NC(nfsvers, dnp, &dnvattr);
			}
		}
	}

	if (!error && fh.fh_len)
		error = nfs_nget(NFSTOMP(dnp), dnp, cnp, fh.fh_data, fh.fh_len, &nvattr, &xid, NG_MAKEENTRY, &np);
	if (!error && !np)
		error = nfs_lookitup(dnp, cnp->cn_nameptr, cnp->cn_namelen, ctx, &np);
	if (!error && np)
		newvp = NFSTOV(np);

	nfs_dulookup_finish(&dul, dnp, ctx);
	if (!lockerror)
		nfs_unlock(dnp);

	if (error) {
		if ((nfsvers == NFS_VER3) && (fmode & O_EXCL) && (error == NFSERR_NOTSUPP)) {
			fmode &= ~O_EXCL;
			goto again;
		}
		if (newvp) {
			nfs_unlock(np);
			vnode_put(newvp);
		}
	} else if ((nfsvers == NFS_VER3) && (fmode & O_EXCL)) {
		error = nfs3_setattr_rpc(np, vap, ctx, 1);
		if (error && (gotuid || gotgid)) {
			/* it's possible the server didn't like our attempt to set IDs. */
			/* so, let's try it again without those */
			VATTR_CLEAR_ACTIVE(vap, va_uid);
			VATTR_CLEAR_ACTIVE(vap, va_gid);
			error = nfs3_setattr_rpc(np, vap, ctx, 1);
		}
		if (error) {
			nfs_unlock(np);
			vnode_put(newvp);
		}
	}
	if (!error)
		*ap->a_vpp = newvp;
	if (!error && (gotuid || gotgid) &&
	    (!newvp || nfs_getattrcache(np, &nvattr, 1) ||
	     (gotuid && (nvattr.nva_uid != vap->va_uid)) ||
	     (gotgid && (nvattr.nva_gid != vap->va_gid)))) {
		/* clear ID bits if server didn't use them (or we can't tell) */
		VATTR_CLEAR_SUPPORTED(vap, va_uid);
		VATTR_CLEAR_SUPPORTED(vap, va_gid);
	}
	if (!error)
		nfs_unlock(np);
	return (error);
}

/*
 * NFS file remove call
 * To try and make NFS semantics closer to UFS semantics, a file that has
 * other processes using the vnode is renamed instead of removed and then
 * removed later on the last close.
 * - If vnode_isinuse()
 *	  If a rename is not already in the works
 *	     call nfs_sillyrename() to set it up
 *     else
 *	  do the remove RPC
 */
static int
nfs_vnop_remove(
	struct vnop_remove_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_dvp;
		vnode_t a_vp;
		struct componentname *a_cnp;
		int a_flags;
		vfs_context_t a_context;
	} */ *ap)
{
	vfs_context_t ctx = ap->a_context;
	vnode_t vp = ap->a_vp;
	vnode_t dvp = ap->a_dvp;
	struct componentname *cnp = ap->a_cnp;
	nfsnode_t dnp = VTONFS(dvp);
	nfsnode_t np = VTONFS(vp);
	int error = 0, nfsvers, inuse, gotattr = 0, flushed = 0, setsize = 0;
	struct nfs_vattr nvattr;
	struct nfsmount *nmp;
	struct nfs_dulookup dul;

	/* XXX prevent removing a sillyrenamed file? */

	nmp = NFSTONMP(dnp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

again_relock:
	error = nfs_lock2(dnp, np, NFS_NODE_LOCK_EXCLUSIVE);
	if (error)
		return (error);

	/* lock the node while we remove the file */
	lck_mtx_lock(nfs_node_hash_mutex);
	while (np->n_hflag & NHLOCKED) {
		np->n_hflag |= NHLOCKWANT;
		msleep(np, nfs_node_hash_mutex, PINOD, "nfs_remove", NULL);
	}
	np->n_hflag |= NHLOCKED;
	lck_mtx_unlock(nfs_node_hash_mutex);

	nfs_dulookup_init(&dul, dnp, cnp->cn_nameptr, cnp->cn_namelen);
again:
	inuse = vnode_isinuse(vp, 0);
	if ((ap->a_flags & VNODE_REMOVE_NODELETEBUSY) && inuse) {
		/* Caller requested Carbon delete semantics, but file is busy */
		error = EBUSY;
		goto out;
	}
	if (inuse && !gotattr) {
		if (nfs_getattr(np, &nvattr, ctx, 1))
			nvattr.nva_nlink = 1;
		gotattr = 1;
		goto again;
	}
	if (!inuse || (np->n_sillyrename && (nvattr.nva_nlink > 1))) {

		if (!inuse && !flushed) { /* flush all the buffers first */
			/* unlock the node */
			lck_mtx_lock(nfs_node_hash_mutex);
			np->n_hflag &= ~NHLOCKED;
			if (np->n_hflag & NHLOCKWANT) {
				np->n_hflag &= ~NHLOCKWANT;
				wakeup(np);
			}
			lck_mtx_unlock(nfs_node_hash_mutex);
			nfs_unlock2(dnp, np);
			error = nfs_vinvalbuf(vp, V_SAVE, ctx, 1);
			FSDBG(260, np, np->n_size, np->n_vattr.nva_size, 0xf00d0011);
			flushed = 1;
			if (error == EINTR) {
				nfs_lock(np, NFS_NODE_LOCK_FORCE);
				NATTRINVALIDATE(np);
				nfs_unlock(np);
				return (error);
			}
			goto again_relock;
		}

		/*
		 * Purge the name cache so that the chance of a lookup for
		 * the name succeeding while the remove is in progress is
		 * minimized.
		 */
		cache_purge(vp);

		nfs_dulookup_start(&dul, dnp, ctx);

		/* Do the rpc */
		error = nmp->nm_funcs->nf_remove_rpc(dnp, cnp->cn_nameptr, cnp->cn_namelen,
				vfs_context_thread(ctx), vfs_context_ucred(ctx));

		/*
		 * Kludge City: If the first reply to the remove rpc is lost..
		 *   the reply to the retransmitted request will be ENOENT
		 *   since the file was in fact removed
		 *   Therefore, we cheat and return success.
		 */
		if (error == ENOENT)
			error = 0;

		if (!error && !inuse && !np->n_sillyrename) {
			/*
			 * removal succeeded, it's not in use, and not silly renamed so
			 * remove nfsnode from hash now so we can't accidentally find it
			 * again if another object gets created with the same filehandle
			 * before this vnode gets reclaimed
			 */
			lck_mtx_lock(nfs_node_hash_mutex);
			if (np->n_hflag & NHHASHED) {
				LIST_REMOVE(np, n_hash);
				np->n_hflag &= ~NHHASHED;
				FSDBG(266, 0, np, np->n_flag, 0xb1eb1e);
			}
			lck_mtx_unlock(nfs_node_hash_mutex);
			/* clear flags now: won't get nfs_vnop_inactive for recycled vnode */
			/* clear all flags other than these */
			np->n_flag &= (NMODIFIED);
			vnode_recycle(vp);
			NATTRINVALIDATE(np);
			setsize = 1;
		} else {
			NATTRINVALIDATE(np);
		}
	} else if (!np->n_sillyrename) {
		nfs_dulookup_start(&dul, dnp, ctx);
		error = nfs_sillyrename(dnp, np, cnp, ctx);
		NATTRINVALIDATE(np);
	} else {
		NATTRINVALIDATE(np);
		nfs_dulookup_start(&dul, dnp, ctx);
	}

	if (!nfs_getattr(dnp, &nvattr, ctx, 1)) {
		if (NFS_CHANGED_NC(nfsvers, dnp, &nvattr)) {
			dnp->n_flag &= ~NNEGNCENTRIES;
			cache_purge(dvp);
			NFS_CHANGED_UPDATE_NC(nfsvers, dnp, &nvattr);
		}
	}
	nfs_dulookup_finish(&dul, dnp, ctx);
out:
	/* unlock the node */
	lck_mtx_lock(nfs_node_hash_mutex);
	np->n_hflag &= ~NHLOCKED;
	if (np->n_hflag & NHLOCKWANT) {
		np->n_hflag &= ~NHLOCKWANT;
		wakeup(np);
	}
	lck_mtx_unlock(nfs_node_hash_mutex);
	nfs_unlock2(dnp, np);
	if (setsize)
		ubc_setsize(vp, 0);
	return (error);
}

/*
 * NFS silly-renamed file removal function called from nfs_vnop_inactive
 */
int
nfs_removeit(struct nfs_sillyrename *nsp)
{
	struct nfsmount *nmp = NFSTONMP(nsp->nsr_dnp);
	if (!nmp)
		return (ENXIO);
	return nmp->nm_funcs->nf_remove_rpc(nsp->nsr_dnp, nsp->nsr_name, nsp->nsr_namlen, NULL, nsp->nsr_cred);
}

/*
 * NFS remove rpc, called from nfs_remove() and nfs_removeit().
 */
int
nfs3_remove_rpc(
	nfsnode_t dnp,
	char *name,
	int namelen,
	thread_t thd,
	kauth_cred_t cred)
{
	int error = 0, status, wccpostattr = 0;
	struct timespec premtime = { 0, 0 };
	struct nfsmount *nmp;
	int nfsvers;
	u_int64_t xid;
	struct nfsm_chain nmreq, nmrep;

	nmp = NFSTONMP(dnp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;
	if ((nfsvers == NFS_VER2) && (namelen > NFS_MAXNAMLEN))
		return (ENAMETOOLONG);

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	nfsm_chain_build_alloc_init(error, &nmreq,
		NFSX_FH(nfsvers) + NFSX_UNSIGNED + nfsm_rndup(namelen));
	nfsm_chain_add_fh(error, &nmreq, nfsvers, dnp->n_fhp, dnp->n_fhsize);
	nfsm_chain_add_string(error, &nmreq, name, namelen);
	nfsm_chain_build_done(error, &nmreq);
	nfsmout_if(error);

	error = nfs_request2(dnp, NULL, &nmreq, NFSPROC_REMOVE, thd, cred, 0, &nmrep, &xid, &status);

	if (nfsvers == NFS_VER3)
		nfsm_chain_get_wcc_data(error, &nmrep, dnp, &premtime, &wccpostattr, &xid);
	dnp->n_flag |= NMODIFIED;
	/* if directory hadn't changed, update namecache mtime */
	if (nfstimespeccmp(&dnp->n_ncmtime, &premtime, ==))
		NFS_CHANGED_UPDATE_NC(nfsvers, dnp, &dnp->n_vattr);
	if (!wccpostattr)
		NATTRINVALIDATE(dnp);
	if (!error)
		error = status;
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

/*
 * NFS file rename call
 */
static int
nfs_vnop_rename(
	struct vnop_rename_args  /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_fdvp;
		vnode_t a_fvp;
		struct componentname *a_fcnp;
		vnode_t a_tdvp;
		vnode_t a_tvp;
		struct componentname *a_tcnp;
		vfs_context_t a_context;
	} */ *ap)
{
	vfs_context_t ctx = ap->a_context;
	vnode_t fdvp = ap->a_fdvp;
	vnode_t fvp = ap->a_fvp;
	vnode_t tdvp = ap->a_tdvp;
	vnode_t tvp = ap->a_tvp;
	nfsnode_t fdnp, fnp, tdnp, tnp;
	struct componentname *tcnp = ap->a_tcnp;
	struct componentname *fcnp = ap->a_fcnp;
	int error, nfsvers, inuse=0, tvprecycle=0, locked=0;
	mount_t fmp, tdmp, tmp;
	struct nfs_vattr nvattr;
	struct nfsmount *nmp;
	struct nfs_dulookup fdul, tdul;

	fdnp = VTONFS(fdvp);
	fnp = VTONFS(fvp);
	tdnp = VTONFS(tdvp);
	tnp = tvp ? VTONFS(tvp) : NULL;

	nmp = NFSTONMP(fdnp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	error = nfs_lock4(fdnp, fnp, tdnp, tnp, NFS_NODE_LOCK_EXCLUSIVE);
	if (error)
		return (error);

	if (tvp && (tvp != fvp)) {
		/* lock the node while we rename over the existing file */
		lck_mtx_lock(nfs_node_hash_mutex);
		while (tnp->n_hflag & NHLOCKED) {
			tnp->n_hflag |= NHLOCKWANT;
			msleep(tnp, nfs_node_hash_mutex, PINOD, "nfs_rename", NULL);
		}
		tnp->n_hflag |= NHLOCKED;
		lck_mtx_unlock(nfs_node_hash_mutex);
		locked = 1;
	}

	nfs_dulookup_init(&fdul, fdnp, fcnp->cn_nameptr, fcnp->cn_namelen);
	nfs_dulookup_init(&tdul, tdnp, tcnp->cn_nameptr, tcnp->cn_namelen);

	/* Check for cross-device rename */
	fmp = vnode_mount(fvp);
	tmp = tvp ? vnode_mount(tvp) : NULL;
	tdmp = vnode_mount(tdvp);
	if ((fmp != tdmp) || (tvp && (fmp != tmp))) {
		error = EXDEV;
		goto out;
	}

	/* XXX prevent renaming from/over a sillyrenamed file? */

	/*
	 * If the tvp exists and is in use, sillyrename it before doing the
	 * rename of the new file over it.
	 * XXX Can't sillyrename a directory.
	 * Don't sillyrename if source and target are same vnode (hard
	 * links or case-variants)
	 */
	if (tvp && (tvp != fvp))
		inuse = vnode_isinuse(tvp, 0);
	if (inuse && !tnp->n_sillyrename && (vnode_vtype(tvp) != VDIR)) {
		error = nfs_sillyrename(tdnp, tnp, tcnp, ctx);
		if (error) {
			/* sillyrename failed. Instead of pressing on, return error */
			goto out; /* should not be ENOENT. */
		} else {
			/* sillyrename succeeded.*/
			tvp = NULL;
		}
	}

	nfs_dulookup_start(&fdul, fdnp, ctx);
	nfs_dulookup_start(&tdul, tdnp, ctx);

	error = nmp->nm_funcs->nf_rename_rpc(fdnp, fcnp->cn_nameptr, fcnp->cn_namelen,
			tdnp, tcnp->cn_nameptr, tcnp->cn_namelen, ctx);

	/*
	 * Kludge: Map ENOENT => 0 assuming that it is a reply to a retry.
	 */
	if (error == ENOENT)
		error = 0;

	if (tvp && (tvp != fvp) && !tnp->n_sillyrename) {
		tvprecycle = (!error && !vnode_isinuse(tvp, 0) &&
		    (nfs_getattrcache(tnp, &nvattr, 1) || (nvattr.nva_nlink == 1)));
		lck_mtx_lock(nfs_node_hash_mutex);
		if (tvprecycle && (tnp->n_hflag & NHHASHED)) {
			/*
			 * remove nfsnode from hash now so we can't accidentally find it
			 * again if another object gets created with the same filehandle
			 * before this vnode gets reclaimed
			 */
			LIST_REMOVE(tnp, n_hash);
			tnp->n_hflag &= ~NHHASHED;
			FSDBG(266, 0, tnp, tnp->n_flag, 0xb1eb1e);
		}
		lck_mtx_unlock(nfs_node_hash_mutex);
	}

	/* purge the old name cache entries and enter the new one */
	cache_purge(fvp);
	if (tvp) {
		cache_purge(tvp);
		if (tvprecycle) {
			/* clear flags now: won't get nfs_vnop_inactive for recycled vnode */
			/* clear all flags other than these */
			tnp->n_flag &= (NMODIFIED);
			vnode_recycle(tvp);
		}
	}
	if (!error) {
		if (tdnp->n_flag & NNEGNCENTRIES) {
			tdnp->n_flag &= ~NNEGNCENTRIES;
			cache_purge_negatives(tdvp);
		}
		cache_enter(tdvp, fvp, tcnp);
		if (tdvp != fdvp) {	/* update parent pointer */
			if (fnp->n_parent && !vnode_get(fnp->n_parent)) {
				/* remove ref from old parent */
				vnode_rele(fnp->n_parent);
				vnode_put(fnp->n_parent);
			}
			fnp->n_parent = tdvp;
			if (tdvp && !vnode_get(tdvp)) {
				/* add ref to new parent */
				vnode_ref(tdvp);
				vnode_put(tdvp);
			} else {
				fnp->n_parent = NULL;
			}
		}
	}
out:
	if (!nfs_getattr(fdnp, &nvattr, ctx, 1)) {
		if (NFS_CHANGED_NC(nfsvers, fdnp, &nvattr)) {
			fdnp->n_flag &= ~NNEGNCENTRIES;
			cache_purge(fdvp);
			NFS_CHANGED_UPDATE_NC(nfsvers, fdnp, &nvattr);
		}
	}
	if (!nfs_getattr(tdnp, &nvattr, ctx, 1)) {
		if (NFS_CHANGED_NC(nfsvers, tdnp, &nvattr)) {
			tdnp->n_flag &= ~NNEGNCENTRIES;
			cache_purge(tdvp);
			NFS_CHANGED_UPDATE_NC(nfsvers, tdnp, &nvattr);
		}
	}
	nfs_dulookup_finish(&fdul, fdnp, ctx);
	nfs_dulookup_finish(&tdul, tdnp, ctx);
	if (locked) {
		/* unlock node */
		lck_mtx_lock(nfs_node_hash_mutex);
		tnp->n_hflag &= ~NHLOCKED;
		if (tnp->n_hflag & NHLOCKWANT) {
			tnp->n_hflag &= ~NHLOCKWANT;
			wakeup(tnp);
		}
		lck_mtx_unlock(nfs_node_hash_mutex);
	}
	nfs_unlock4(fdnp, fnp, tdnp, tnp);
	return (error);
}

/*
 * Do an NFS rename rpc. Called from nfs_vnop_rename() and nfs_sillyrename().
 */
int
nfs3_rename_rpc(
	nfsnode_t fdnp,
	char *fnameptr,
	int fnamelen,
	nfsnode_t tdnp,
	char *tnameptr,
	int tnamelen,
	vfs_context_t ctx)
{
	int error = 0, status, fwccpostattr = 0, twccpostattr = 0;
	struct timespec fpremtime = { 0, 0 }, tpremtime = { 0, 0 };
	struct nfsmount *nmp;
	int nfsvers;
	u_int64_t xid, txid;
	struct nfsm_chain nmreq, nmrep;

	nmp = NFSTONMP(fdnp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;
	if ((nfsvers == NFS_VER2) &&
	    ((fnamelen > NFS_MAXNAMLEN) || (tnamelen > NFS_MAXNAMLEN)))
		return (ENAMETOOLONG);

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	nfsm_chain_build_alloc_init(error, &nmreq,
		(NFSX_FH(nfsvers) + NFSX_UNSIGNED) * 2 +
		nfsm_rndup(fnamelen) + nfsm_rndup(tnamelen));
	nfsm_chain_add_fh(error, &nmreq, nfsvers, fdnp->n_fhp, fdnp->n_fhsize);
	nfsm_chain_add_string(error, &nmreq, fnameptr, fnamelen);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, tdnp->n_fhp, tdnp->n_fhsize);
	nfsm_chain_add_string(error, &nmreq, tnameptr, tnamelen);
	nfsm_chain_build_done(error, &nmreq);
	nfsmout_if(error);

	error = nfs_request(fdnp, NULL, &nmreq, NFSPROC_RENAME, ctx, &nmrep, &xid, &status);

	if (nfsvers == NFS_VER3) {
		txid = xid;
		nfsm_chain_get_wcc_data(error, &nmrep, fdnp, &fpremtime, &fwccpostattr, &xid);
		nfsm_chain_get_wcc_data(error, &nmrep, tdnp, &tpremtime, &twccpostattr, &txid);
	}
	if (!error)
		error = status;
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	fdnp->n_flag |= NMODIFIED;
	/* if directory hadn't changed, update namecache mtime */
	if (nfstimespeccmp(&fdnp->n_ncmtime, &fpremtime, ==))
		NFS_CHANGED_UPDATE_NC(nfsvers, fdnp, &fdnp->n_vattr);
	if (!fwccpostattr)
		NATTRINVALIDATE(fdnp);
	tdnp->n_flag |= NMODIFIED;
	/* if directory hadn't changed, update namecache mtime */
	if (nfstimespeccmp(&tdnp->n_ncmtime, &tpremtime, ==))
		NFS_CHANGED_UPDATE_NC(nfsvers, tdnp, &tdnp->n_vattr);
	if (!twccpostattr)
		NATTRINVALIDATE(tdnp);
	return (error);
}

/*
 * NFS hard link create call
 */
static int
nfs3_vnop_link(
	struct vnop_link_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		vnode_t a_tdvp;
		struct componentname *a_cnp;
		vfs_context_t a_context;
	} */ *ap)
{
	vfs_context_t ctx = ap->a_context;
	vnode_t vp = ap->a_vp;
	vnode_t tdvp = ap->a_tdvp;
	struct componentname *cnp = ap->a_cnp;
	int error = 0, status, wccpostattr = 0, attrflag = 0;
	struct timespec premtime = { 0, 0 };
	struct nfsmount *nmp;
	nfsnode_t np = VTONFS(vp);
	nfsnode_t tdnp = VTONFS(tdvp);
	int nfsvers;
	u_int64_t xid, txid;
	struct nfsm_chain nmreq, nmrep;

	if (vnode_mount(vp) != vnode_mount(tdvp))
		return (EXDEV);

	nmp = VTONMP(vp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;
	if ((nfsvers == NFS_VER2) && (cnp->cn_namelen > NFS_MAXNAMLEN))
		return (ENAMETOOLONG);

	/*
	 * Push all writes to the server, so that the attribute cache
	 * doesn't get "out of sync" with the server.
	 * XXX There should be a better way!
	 */
	nfs_flush(np, MNT_WAIT, vfs_context_thread(ctx), V_IGNORE_WRITEERR);

	error = nfs_lock2(tdnp, np, NFS_NODE_LOCK_EXCLUSIVE);
	if (error)
		return (error);

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	nfsm_chain_build_alloc_init(error, &nmreq,
		NFSX_FH(nfsvers)*2 + NFSX_UNSIGNED + nfsm_rndup(cnp->cn_namelen));
	nfsm_chain_add_fh(error, &nmreq, nfsvers, np->n_fhp, np->n_fhsize);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, tdnp->n_fhp, tdnp->n_fhsize);
	nfsm_chain_add_string(error, &nmreq, cnp->cn_nameptr, cnp->cn_namelen);
	nfsm_chain_build_done(error, &nmreq);
	nfsmout_if(error);
	error = nfs_request(np, NULL, &nmreq, NFSPROC_LINK, ctx,
			&nmrep, &xid, &status);
	if (nfsvers == NFS_VER3) {
		txid = xid;
		nfsm_chain_postop_attr_update_flag(error, &nmrep, np, attrflag, &xid);
		nfsm_chain_get_wcc_data(error, &nmrep, tdnp, &premtime, &wccpostattr, &txid);
	}
	if (!error)
		error = status;
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	tdnp->n_flag |= NMODIFIED;
	if (!attrflag)
		NATTRINVALIDATE(np);
	/* if directory hadn't changed, update namecache mtime */
	if (nfstimespeccmp(&tdnp->n_ncmtime, &premtime, ==))
		NFS_CHANGED_UPDATE_NC(nfsvers, tdnp, &tdnp->n_vattr);
	if (!wccpostattr)
		NATTRINVALIDATE(tdnp);
	if (!error && (tdnp->n_flag & NNEGNCENTRIES)) {
		tdnp->n_flag &= ~NNEGNCENTRIES;
		cache_purge_negatives(tdvp);
	}
	nfs_unlock2(tdnp, np);
	/*
	 * Kludge: Map EEXIST => 0 assuming that it is a reply to a retry.
	 */
	if (error == EEXIST)
		error = 0;
	return (error);
}

/*
 * NFS symbolic link create call
 */
static int
nfs3_vnop_symlink(
	struct vnop_symlink_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_dvp;
		vnode_t *a_vpp;
		struct componentname *a_cnp;
		struct vnode_attr *a_vap;
		char *a_target;
		vfs_context_t a_context;
	} */ *ap)
{
	vfs_context_t ctx = ap->a_context;
	vnode_t dvp = ap->a_dvp;
	struct vnode_attr *vap = ap->a_vap;
	struct componentname *cnp = ap->a_cnp;
	struct nfs_vattr nvattr, dnvattr;
	fhandle_t fh;
	int slen, error = 0, lockerror = ENOENT, status, wccpostattr = 0;
	struct timespec premtime = { 0, 0 };
	vnode_t newvp = NULL;
	int nfsvers, gotuid, gotgid;
	u_int64_t xid, dxid;
	nfsnode_t np = NULL;
	nfsnode_t dnp = VTONFS(dvp);
	struct nfsmount *nmp;
	struct nfsm_chain nmreq, nmrep;
	struct nfsreq *req = NULL;
	struct nfs_dulookup dul;

	nmp = VTONMP(dvp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	slen = strlen(ap->a_target);
	if ((nfsvers == NFS_VER2) &&
	    ((cnp->cn_namelen > NFS_MAXNAMLEN) || (slen > NFS_MAXPATHLEN)))
		return (ENAMETOOLONG);

	VATTR_SET_SUPPORTED(vap, va_mode);
	VATTR_SET_SUPPORTED(vap, va_uid);
	VATTR_SET_SUPPORTED(vap, va_gid);
	VATTR_SET_SUPPORTED(vap, va_data_size);
	VATTR_SET_SUPPORTED(vap, va_access_time);
	VATTR_SET_SUPPORTED(vap, va_modify_time);
	gotuid = VATTR_IS_ACTIVE(vap, va_uid);
	gotgid = VATTR_IS_ACTIVE(vap, va_gid);

	nfs_dulookup_init(&dul, dnp, cnp->cn_nameptr, cnp->cn_namelen);

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	nfsm_chain_build_alloc_init(error, &nmreq,
		NFSX_FH(nfsvers) + 2 * NFSX_UNSIGNED +
		nfsm_rndup(cnp->cn_namelen) + nfsm_rndup(slen) + NFSX_SATTR(nfsvers));
	nfsm_chain_add_fh(error, &nmreq, nfsvers, dnp->n_fhp, dnp->n_fhsize);
	nfsm_chain_add_string(error, &nmreq, cnp->cn_nameptr, cnp->cn_namelen);
	if (nfsvers == NFS_VER3)
		nfsm_chain_add_v3sattr(error, &nmreq, vap);
	nfsm_chain_add_string(error, &nmreq, ap->a_target, slen);
	if (nfsvers == NFS_VER2)
		nfsm_chain_add_v2sattr(error, &nmreq, vap, -1);
	nfsm_chain_build_done(error, &nmreq);
	nfsmout_if(error);
	if ((lockerror = nfs_lock(dnp, NFS_NODE_LOCK_EXCLUSIVE)))
		error = lockerror;
	nfsmout_if(error);

	error = nfs_request_async(dnp, NULL, &nmreq, NFSPROC_SYMLINK,
			vfs_context_thread(ctx), vfs_context_ucred(ctx), NULL, &req);
	if (!error) {
		nfs_dulookup_start(&dul, dnp, ctx);
		error = nfs_request_async_finish(req, &nmrep, &xid, &status);
	}

	dxid = xid;
	if (!error && !status) {
		if (dnp->n_flag & NNEGNCENTRIES) {
			dnp->n_flag &= ~NNEGNCENTRIES;
			cache_purge_negatives(dvp);
		}
		if (nfsvers == NFS_VER3)
			error = nfsm_chain_get_fh_attr(&nmrep, dnp, ctx, nfsvers, &xid, &fh, &nvattr);
		else
			fh.fh_len = 0;
	}
	if (nfsvers == NFS_VER3)
		nfsm_chain_get_wcc_data(error, &nmrep, dnp, &premtime, &wccpostattr, &dxid);
	if (!error)
		error = status;
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);

	if (!lockerror) {
		dnp->n_flag |= NMODIFIED;
		/* if directory hadn't changed, update namecache mtime */
		if (nfstimespeccmp(&dnp->n_ncmtime, &premtime, ==))
			NFS_CHANGED_UPDATE_NC(nfsvers, dnp, &dnp->n_vattr);
		if (!wccpostattr)
			NATTRINVALIDATE(dnp);
		if (!nfs_getattr(dnp, &dnvattr, ctx, 1)) {
			if (NFS_CHANGED_NC(nfsvers, dnp, &dnvattr)) {
				dnp->n_flag &= ~NNEGNCENTRIES;
				cache_purge(dvp);
				NFS_CHANGED_UPDATE_NC(nfsvers, dnp, &dnvattr);
			}
		}
	}

	if (!error && fh.fh_len)
		error = nfs_nget(NFSTOMP(dnp), dnp, cnp, fh.fh_data, fh.fh_len, &nvattr, &xid, NG_MAKEENTRY, &np);
	if (!error && np)
		newvp = NFSTOV(np);

	nfs_dulookup_finish(&dul, dnp, ctx);

	/*
	 * Kludge: Map EEXIST => 0 assuming that you have a reply to a retry
	 * if we can succeed in looking up the symlink.
	 */
	if ((error == EEXIST) || (!error && !newvp)) {
		if (newvp) {
			nfs_unlock(np);
			vnode_put(newvp);
			newvp = NULL;
		}
		error = nfs_lookitup(dnp, cnp->cn_nameptr, cnp->cn_namelen, ctx, &np);
		if (!error) {
			newvp = NFSTOV(np);
			if (vnode_vtype(newvp) != VLNK)
				error = EEXIST;
		}
	}
	if (!lockerror)
		nfs_unlock(dnp);
	if (!error && (gotuid || gotgid) &&
	    (!newvp || nfs_getattrcache(np, &nvattr, 1) ||
	     (gotuid && (nvattr.nva_uid != vap->va_uid)) ||
	     (gotgid && (nvattr.nva_gid != vap->va_gid)))) {
		/* clear ID bits if server didn't use them (or we can't tell) */
		VATTR_CLEAR_SUPPORTED(vap, va_uid);
		VATTR_CLEAR_SUPPORTED(vap, va_gid);
	}
	if (error) {
		if (newvp) {
			nfs_unlock(np);
			vnode_put(newvp);
		}
	} else {
		nfs_unlock(np);
		*ap->a_vpp = newvp;
	}
	return (error);
}

/*
 * NFS make dir call
 */
static int
nfs3_vnop_mkdir(
	struct vnop_mkdir_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_dvp;
		vnode_t *a_vpp;
		struct componentname *a_cnp;
		struct vnode_attr *a_vap;
		vfs_context_t a_context;
	} */ *ap)
{
	vfs_context_t ctx = ap->a_context;
	vnode_t dvp = ap->a_dvp;
	struct vnode_attr *vap = ap->a_vap;
	struct componentname *cnp = ap->a_cnp;
	struct nfs_vattr nvattr, dnvattr;
	nfsnode_t np = NULL;
	struct nfsmount *nmp;
	nfsnode_t dnp = VTONFS(dvp);
	vnode_t newvp = NULL;
	int error = 0, lockerror = ENOENT, status, wccpostattr = 0;
	struct timespec premtime = { 0, 0 };
	int nfsvers, gotuid, gotgid;
	u_int64_t xid, dxid;
	fhandle_t fh;
	struct nfsm_chain nmreq, nmrep;
	struct nfsreq *req = NULL;
	struct nfs_dulookup dul;

	nmp = VTONMP(dvp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;
	if ((nfsvers == NFS_VER2) && (cnp->cn_namelen > NFS_MAXNAMLEN))
		return (ENAMETOOLONG);

	VATTR_SET_SUPPORTED(vap, va_mode);
	VATTR_SET_SUPPORTED(vap, va_uid);
	VATTR_SET_SUPPORTED(vap, va_gid);
	VATTR_SET_SUPPORTED(vap, va_data_size);
	VATTR_SET_SUPPORTED(vap, va_access_time);
	VATTR_SET_SUPPORTED(vap, va_modify_time);
	gotuid = VATTR_IS_ACTIVE(vap, va_uid);
	gotgid = VATTR_IS_ACTIVE(vap, va_gid);

	nfs_dulookup_init(&dul, dnp, cnp->cn_nameptr, cnp->cn_namelen);

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	nfsm_chain_build_alloc_init(error, &nmreq,
		NFSX_FH(nfsvers) + NFSX_UNSIGNED +
		nfsm_rndup(cnp->cn_namelen) + NFSX_SATTR(nfsvers));
	nfsm_chain_add_fh(error, &nmreq, nfsvers, dnp->n_fhp, dnp->n_fhsize);
	nfsm_chain_add_string(error, &nmreq, cnp->cn_nameptr, cnp->cn_namelen);
	if (nfsvers == NFS_VER3)
		nfsm_chain_add_v3sattr(error, &nmreq, vap);
	else
		nfsm_chain_add_v2sattr(error, &nmreq, vap, -1);
	nfsm_chain_build_done(error, &nmreq);
	nfsmout_if(error);
	if ((lockerror = nfs_lock(dnp, NFS_NODE_LOCK_EXCLUSIVE)))
		error = lockerror;
	nfsmout_if(error);

	error = nfs_request_async(dnp, NULL, &nmreq, NFSPROC_MKDIR,
			vfs_context_thread(ctx), vfs_context_ucred(ctx), NULL, &req);
	if (!error) {
		nfs_dulookup_start(&dul, dnp, ctx);
		error = nfs_request_async_finish(req, &nmrep, &xid, &status);
	}

	dxid = xid;
	if (!error && !status) {
		if (dnp->n_flag & NNEGNCENTRIES) {
			dnp->n_flag &= ~NNEGNCENTRIES;
			cache_purge_negatives(dvp);
		}
		error = nfsm_chain_get_fh_attr(&nmrep, dnp, ctx, nfsvers, &xid, &fh, &nvattr);
	}
	if (nfsvers == NFS_VER3)
		nfsm_chain_get_wcc_data(error, &nmrep, dnp, &premtime, &wccpostattr, &dxid);
	if (!error)
		error = status;
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);

	if (!lockerror) {
		dnp->n_flag |= NMODIFIED;
		/* if directory hadn't changed, update namecache mtime */
		if (nfstimespeccmp(&dnp->n_ncmtime, &premtime, ==))
			NFS_CHANGED_UPDATE_NC(nfsvers, dnp, &dnp->n_vattr);
		if (!wccpostattr)
			NATTRINVALIDATE(dnp);
		if (!nfs_getattr(dnp, &dnvattr, ctx, 1)) {
			if (NFS_CHANGED_NC(nfsvers, dnp, &dnvattr)) {
				dnp->n_flag &= ~NNEGNCENTRIES;
				cache_purge(dvp);
				NFS_CHANGED_UPDATE_NC(nfsvers, dnp, &dnvattr);
			}
		}
	}

	if (!error && fh.fh_len)
		error = nfs_nget(NFSTOMP(dnp), dnp, cnp, fh.fh_data, fh.fh_len, &nvattr, &xid, NG_MAKEENTRY, &np);
	if (!error && np)
		newvp = NFSTOV(np);

	nfs_dulookup_finish(&dul, dnp, ctx);

	/*
	 * Kludge: Map EEXIST => 0 assuming that you have a reply to a retry
	 * if we can succeed in looking up the directory.
	 */
	if (error == EEXIST || (!error && !newvp)) {
		if (newvp) {
			nfs_unlock(np);
			vnode_put(newvp);
			newvp = NULL;
		}
		error = nfs_lookitup(dnp, cnp->cn_nameptr, cnp->cn_namelen, ctx, &np);
		if (!error) {
			newvp = NFSTOV(np);
			if (vnode_vtype(newvp) != VDIR)
				error = EEXIST;
		}
	}
	if (!lockerror)
		nfs_unlock(dnp);
	if (!error && (gotuid || gotgid) &&
	    (!newvp || nfs_getattrcache(np, &nvattr, 1) ||
	     (gotuid && (nvattr.nva_uid != vap->va_uid)) ||
	     (gotgid && (nvattr.nva_gid != vap->va_gid)))) {
		/* clear ID bits if server didn't use them (or we can't tell) */
		VATTR_CLEAR_SUPPORTED(vap, va_uid);
		VATTR_CLEAR_SUPPORTED(vap, va_gid);
	}
	if (error) {
		if (newvp) {
			nfs_unlock(np);
			vnode_put(newvp);
		}
	} else {
		nfs_unlock(np);
		*ap->a_vpp = newvp;
	}
	return (error);
}

/*
 * NFS remove directory call
 */
static int
nfs3_vnop_rmdir(
	struct vnop_rmdir_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_dvp;
		vnode_t a_vp;
		struct componentname *a_cnp;
		vfs_context_t a_context;
	} */ *ap)
{
	vfs_context_t ctx = ap->a_context;
	vnode_t vp = ap->a_vp;
	vnode_t dvp = ap->a_dvp;
	struct componentname *cnp = ap->a_cnp;
	int error = 0, status, wccpostattr = 0;
	struct timespec premtime = { 0, 0 };
	struct nfsmount *nmp;
	nfsnode_t np = VTONFS(vp);
	nfsnode_t dnp = VTONFS(dvp);
	struct nfs_vattr dnvattr;
	int nfsvers;
	u_int64_t xid;
	struct nfsm_chain nmreq, nmrep;
	struct nfsreq *req = NULL;
	struct nfs_dulookup dul;

	nmp = VTONMP(vp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;
	if ((nfsvers == NFS_VER2) && (cnp->cn_namelen > NFS_MAXNAMLEN))
		return (ENAMETOOLONG);

	nfs_dulookup_init(&dul, dnp, cnp->cn_nameptr, cnp->cn_namelen);

	if ((error = nfs_lock2(dnp, np, NFS_NODE_LOCK_EXCLUSIVE)))
		return (error);

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	nfsm_chain_build_alloc_init(error, &nmreq,
		NFSX_FH(nfsvers) + NFSX_UNSIGNED + nfsm_rndup(cnp->cn_namelen));
	nfsm_chain_add_fh(error, &nmreq, nfsvers, dnp->n_fhp, dnp->n_fhsize);
	nfsm_chain_add_string(error, &nmreq, cnp->cn_nameptr, cnp->cn_namelen);
	nfsm_chain_build_done(error, &nmreq);
	nfsmout_if(error);

	error = nfs_request_async(dnp, NULL, &nmreq, NFSPROC_RMDIR,
			vfs_context_thread(ctx), vfs_context_ucred(ctx), NULL, &req);
	if (!error) {
		nfs_dulookup_start(&dul, dnp, ctx);
		error = nfs_request_async_finish(req, &nmrep, &xid, &status);
	}

	if (nfsvers == NFS_VER3)
		nfsm_chain_get_wcc_data(error, &nmrep, dnp, &premtime, &wccpostattr, &xid);
	if (!error)
		error = status;
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);

	dnp->n_flag |= NMODIFIED;
	/* if directory hadn't changed, update namecache mtime */
	if (nfstimespeccmp(&dnp->n_ncmtime, &premtime, ==))
		NFS_CHANGED_UPDATE_NC(nfsvers, dnp, &dnp->n_vattr);
	if (!wccpostattr)
		NATTRINVALIDATE(dnp);
	cache_purge(vp);
	if (!nfs_getattr(dnp, &dnvattr, ctx, 1)) {
		if (NFS_CHANGED_NC(nfsvers, dnp, &dnvattr)) {
			dnp->n_flag &= ~NNEGNCENTRIES;
			cache_purge(dvp);
			NFS_CHANGED_UPDATE_NC(nfsvers, dnp, &dnvattr);
		}
	}
	nfs_dulookup_finish(&dul, dnp, ctx);
	nfs_unlock2(dnp, np);

	/*
	 * Kludge: Map ENOENT => 0 assuming that you have a reply to a retry.
	 */
	if (error == ENOENT)
		error = 0;
	if (!error) {
		/*
		 * remove nfsnode from hash now so we can't accidentally find it
		 * again if another object gets created with the same filehandle
		 * before this vnode gets reclaimed
		 */
		lck_mtx_lock(nfs_node_hash_mutex);
		if (np->n_hflag & NHHASHED) {
			LIST_REMOVE(np, n_hash);
			np->n_hflag &= ~NHHASHED;
			FSDBG(266, 0, np, np->n_flag, 0xb1eb1e);
		}
		lck_mtx_unlock(nfs_node_hash_mutex);
	}
	return (error);
}

/*
 * NFS readdir call
 */
static int
nfs_vnop_readdir(
	struct vnop_readdir_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		struct uio *a_uio;
		int *a_eofflag;
		int *a_ncookies;
		u_long **a_cookies;
		vfs_context_t a_context;
	} */ *ap)
{
	vfs_context_t ctx = ap->a_context;
	vnode_t vp = ap->a_vp;
	nfsnode_t np = VTONFS(vp);
	struct nfsmount *nmp;
	struct uio *uio = ap->a_uio;
	int tresid, error, nfsvers;
	struct nfs_vattr nvattr;

	if (vnode_vtype(vp) != VDIR)
		return (EPERM);

	nmp = VTONMP(vp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	if ((error = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
		return (error);

	/*
	 * First, check for hit on the EOF offset cache
	 */
	if (np->n_direofoffset > 0 && uio->uio_offset >= np->n_direofoffset &&
	    (np->n_flag & NMODIFIED) == 0) {
		if (!nfs_getattr(np, &nvattr, ctx, 1)) {
			if (!NFS_CHANGED(nfsvers, np, &nvattr)) {
				nfs_unlock(np);
				OSAddAtomic(1, (SInt32*)&nfsstats.direofcache_hits);
				if (ap->a_eofflag)
					*ap->a_eofflag = 1;
				return (0);
			}
			if (NFS_CHANGED_NC(nfsvers, np, &nvattr)) {
				/* directory changed, purge any name cache entries */
				np->n_flag &= ~NNEGNCENTRIES;
				cache_purge(vp);
			}
		}
	}
	nfs_unlock(np);
	if (ap->a_eofflag)
		*ap->a_eofflag = 0;

	/*
	 * Call nfs_bioread() to do the real work.
	 */
	// LP64todo - fix this
	tresid = uio_uio_resid(uio);
	error = nfs_bioread(np, uio, 0, ap->a_eofflag, ctx);

	if (!error && uio_uio_resid(uio) == tresid)
		OSAddAtomic(1, (SInt32*)&nfsstats.direofcache_misses);
	return (error);
}

/*
 * Readdir RPC call.
 * Called from below the buffer cache by nfs_buf_readdir().
 */
#define	DIRHDSIZ	((int)(sizeof(struct dirent) - (MAXNAMLEN + 1)))
int
nfs3_readdir_rpc(nfsnode_t dnp, struct uio *uiop, vfs_context_t ctx)
{
	int len, skiplen, left;
	struct dirent *dp = NULL;
	nfsuint64 *cookiep;
	nfsuint64 cookie;
	struct nfsmount *nmp;
	u_quad_t fileno;
	int error = 0, lockerror, status, tlen, more_dirs = 1, blksiz = 0, bigenough = 1, eof;
	int nfsvers, nmreaddirsize;
	u_int64_t xid;
	struct nfsm_chain nmreq, nmrep;
	char *cp;

#if DIAGNOSTIC
	/* XXX limitation based on need to adjust uio */
	if (uiop->uio_iovcnt != 1 || (uiop->uio_offset & (DIRBLKSIZ - 1)) ||
		(uio_uio_resid(uiop) & (DIRBLKSIZ - 1)))
		panic("nfs_readdirrpc: bad uio");
#endif
	nmp = NFSTONMP(dnp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;
	nmreaddirsize = nmp->nm_readdirsize;

	if ((lockerror = nfs_lock(dnp, NFS_NODE_LOCK_SHARED)))
		return (lockerror);

	/*
	 * If there is no cookie, assume directory was stale.
	 */
	cookiep = nfs_getcookie(dnp, uiop->uio_offset, 0);
	if (cookiep)
		cookie = *cookiep;
	else {
		nfs_unlock(dnp);
		return (NFSERR_BAD_COOKIE);
	}

	/*
	 * Loop around doing readdir rpc's of size nm_readdirsize
	 * truncated to a multiple of DIRBLKSIZ.
	 * The stopping criteria is EOF or buffer full.
	 */
	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);
	while (more_dirs && bigenough) {
		nfsm_chain_build_alloc_init(error, &nmreq,
			NFSX_FH(nfsvers) + NFSX_READDIR(nfsvers));
		nfsm_chain_add_fh(error, &nmreq, nfsvers, dnp->n_fhp, dnp->n_fhsize);
		if (nfsvers == NFS_VER3) {
			/* opaque values don't need swapping, but as long */
			/* as we are consistent about it, it should be ok */
			nfsm_chain_add_32(error, &nmreq, cookie.nfsuquad[0]);
			nfsm_chain_add_32(error, &nmreq, cookie.nfsuquad[1]);
			nfsm_chain_add_32(error, &nmreq, dnp->n_cookieverf.nfsuquad[0]);
			nfsm_chain_add_32(error, &nmreq, dnp->n_cookieverf.nfsuquad[1]);
		} else {
			nfsm_chain_add_32(error, &nmreq, cookie.nfsuquad[0]);
		}
		nfsm_chain_add_32(error, &nmreq, nmreaddirsize);
		nfsm_chain_build_done(error, &nmreq);
		nfs_unlock(dnp);
		lockerror = ENOENT;
		nfsmout_if(error);

		error = nfs_request(dnp, NULL, &nmreq, NFSPROC_READDIR, ctx,
				&nmrep, &xid, &status);

		if ((lockerror = nfs_lock(dnp, NFS_NODE_LOCK_EXCLUSIVE)))
			error = lockerror;

		if (nfsvers == NFS_VER3)
			nfsm_chain_postop_attr_update(error, &nmrep, dnp, &xid);
		if (!error)
			error = status;
		if (nfsvers == NFS_VER3) {
			nfsm_chain_get_32(error, &nmrep, dnp->n_cookieverf.nfsuquad[0]);
			nfsm_chain_get_32(error, &nmrep, dnp->n_cookieverf.nfsuquad[1]);
		}
		nfsm_chain_get_32(error, &nmrep, more_dirs);

		if (!lockerror) {
			nfs_unlock(dnp);
			lockerror = ENOENT;
		}
		nfsmout_if(error);

		/* loop thru the dir entries, doctoring them to 4bsd form */
		while (more_dirs && bigenough) {
			if (nfsvers == NFS_VER3)
				nfsm_chain_get_64(error, &nmrep, fileno);
			else
				nfsm_chain_get_32(error, &nmrep, fileno);
			nfsm_chain_get_32(error, &nmrep, len);
			nfsmout_if(error);
			/* Note: v3 supports longer names, but struct dirent doesn't */
			/* so we just truncate the names to fit */
			if (len <= 0) {
				error = EBADRPC;
				goto nfsmout;
			}
			if (len > MAXNAMLEN) {
				skiplen = len - MAXNAMLEN;
				len = MAXNAMLEN;
			} else {
				skiplen = 0;
			}
			tlen = nfsm_rndup(len);
			if (tlen == len)
				tlen += 4;	/* To ensure null termination */
			left = DIRBLKSIZ - blksiz;
			if ((tlen + DIRHDSIZ) > left) {
				dp->d_reclen += left;
				uio_iov_base_add(uiop, left);
				uio_iov_len_add(uiop, -left);
				uiop->uio_offset += left;
				uio_uio_resid_add(uiop, -left);
				blksiz = 0;
			}
			if ((tlen + DIRHDSIZ) > uio_uio_resid(uiop))
				bigenough = 0;
			if (bigenough) {
				// LP64todo - fix this!
				dp = (struct dirent *) CAST_DOWN(caddr_t, uio_iov_base(uiop));
				dp->d_fileno = (int)fileno;
				dp->d_namlen = len;
				dp->d_reclen = tlen + DIRHDSIZ;
				dp->d_type = DT_UNKNOWN;
				blksiz += dp->d_reclen;
				if (blksiz == DIRBLKSIZ)
					blksiz = 0;
				uiop->uio_offset += DIRHDSIZ;
#if LP64KERN
				uio_uio_resid_add(uiop, -((int64_t)DIRHDSIZ));
				uio_iov_len_add(uiop, -((int64_t)DIRHDSIZ));
#else
				uio_uio_resid_add(uiop, -((int)DIRHDSIZ));
				uio_iov_len_add(uiop, -((int)DIRHDSIZ));
#endif
				uio_iov_base_add(uiop, DIRHDSIZ);
				error = nfsm_chain_get_uio(&nmrep, len, uiop);
				nfsmout_if(error);
				// LP64todo - fix this!
				cp = CAST_DOWN(caddr_t, uio_iov_base(uiop));
				tlen -= len;
				*cp = '\0';	/* null terminate */
				uio_iov_base_add(uiop, tlen);
				uio_iov_len_add(uiop, -tlen);
				uiop->uio_offset += tlen;
				uio_uio_resid_add(uiop, -tlen);
				if (skiplen)
					nfsm_chain_adv(error, &nmrep,
						nfsm_rndup(len + skiplen) - nfsm_rndup(len));
			} else {
				nfsm_chain_adv(error, &nmrep, nfsm_rndup(len + skiplen));
			}
			if (bigenough) {
				nfsm_chain_get_32(error, &nmrep, cookie.nfsuquad[0]);
				if (nfsvers == NFS_VER3)
					nfsm_chain_get_32(error, &nmrep, cookie.nfsuquad[1]);
			} else if (nfsvers == NFS_VER3)
				nfsm_chain_adv(error, &nmrep, 2 * NFSX_UNSIGNED);
			else
				nfsm_chain_adv(error, &nmrep, NFSX_UNSIGNED);
			nfsm_chain_get_32(error, &nmrep, more_dirs);
			nfsmout_if(error);
		}
		/*
		 * If at end of rpc data, get the eof boolean
		 */
		if (!more_dirs) {
			nfsm_chain_get_32(error, &nmrep, eof);
			if (!error)
				more_dirs = (eof == 0);
		}
		if ((lockerror = nfs_lock(dnp, NFS_NODE_LOCK_SHARED)))
			error = lockerror;
		nfsmout_if(error);
		nfsm_chain_cleanup(&nmrep);
		nfsm_chain_null(&nmreq);
	}
	if (!lockerror) {
		nfs_unlock(dnp);
		lockerror = ENOENT;
	}
	/*
	 * Fill last record, iff any, out to a multiple of DIRBLKSIZ
	 * by increasing d_reclen for the last record.
	 */
	if (blksiz > 0) {
		left = DIRBLKSIZ - blksiz;
		dp->d_reclen += left;
		uio_iov_base_add(uiop, left);
		uio_iov_len_add(uiop, -left);
		uiop->uio_offset += left;
		uio_uio_resid_add(uiop, -left);
	}

	if ((lockerror = nfs_lock(dnp, NFS_NODE_LOCK_EXCLUSIVE)))
		error = lockerror;
	nfsmout_if(error);

	/*
	 * We are now either at the end of the directory or have filled the
	 * block.
	 */
	if (bigenough)
		dnp->n_direofoffset = uiop->uio_offset;
	else {
		if (uio_uio_resid(uiop) > 0)
			printf("EEK! readdirrpc resid > 0\n");
		cookiep = nfs_getcookie(dnp, uiop->uio_offset, 1);
		if (cookiep)
			*cookiep = cookie;
	}

nfsmout:
	if (!lockerror)
		nfs_unlock(dnp);
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

/*
 * NFS V3 readdir plus RPC. Used in place of nfs_readdirrpc().
 */
int
nfs3_readdirplus_rpc(nfsnode_t dnp, struct uio *uiop, vfs_context_t ctx)
{
	size_t len, tlen, skiplen, left;
	struct dirent *dp = NULL;
	vnode_t newvp;
	nfsuint64 *cookiep;
	struct componentname cn, *cnp = &cn;
	nfsuint64 cookie;
	struct nfsmount *nmp;
	nfsnode_t np;
	u_char *fhp;
	u_quad_t fileno;
	int error = 0, lockerror, status, more_dirs = 1, blksiz = 0, doit, bigenough = 1;
	int nfsvers, nmreaddirsize, nmrsize, attrflag, eof;
	size_t fhsize;
	u_int64_t xid, savexid;
	struct nfs_vattr nvattr;
	struct nfsm_chain nmreq, nmrep;
	char *cp;

#if DIAGNOSTIC
	/* XXX limitation based on need to adjust uio */
	if (uiop->uio_iovcnt != 1 || (uiop->uio_offset & (DIRBLKSIZ - 1)) ||
		(uio_uio_resid(uiop) & (DIRBLKSIZ - 1)))
		panic("nfs3_readdirplus_rpc: bad uio");
#endif
	nmp = NFSTONMP(dnp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;
	nmreaddirsize = nmp->nm_readdirsize;
	nmrsize = nmp->nm_rsize;

	bzero(cnp, sizeof(*cnp));
	newvp = NULLVP;

	if ((lockerror = nfs_lock(dnp, NFS_NODE_LOCK_SHARED)))
		return (lockerror);

	/*
	 * If there is no cookie, assume directory was stale.
	 */
	cookiep = nfs_getcookie(dnp, uiop->uio_offset, 0);
	if (cookiep)
		cookie = *cookiep;
	else {
		nfs_unlock(dnp);
		return (NFSERR_BAD_COOKIE);
	}

	/*
	 * Loop around doing readdir rpc's of size nm_readdirsize
	 * truncated to a multiple of DIRBLKSIZ.
	 * The stopping criteria is EOF or buffer full.
	 */
	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);
	while (more_dirs && bigenough) {
		nfsm_chain_build_alloc_init(error, &nmreq,
			NFSX_FH(NFS_VER3) + 6 * NFSX_UNSIGNED);
		nfsm_chain_add_fh(error, &nmreq, nfsvers, dnp->n_fhp, dnp->n_fhsize);
		/* opaque values don't need swapping, but as long */
		/* as we are consistent about it, it should be ok */
		nfsm_chain_add_32(error, &nmreq, cookie.nfsuquad[0]);
		nfsm_chain_add_32(error, &nmreq, cookie.nfsuquad[1]);
		nfsm_chain_add_32(error, &nmreq, dnp->n_cookieverf.nfsuquad[0]);
		nfsm_chain_add_32(error, &nmreq, dnp->n_cookieverf.nfsuquad[1]);
		nfsm_chain_add_32(error, &nmreq, nmreaddirsize);
		nfsm_chain_add_32(error, &nmreq, nmrsize);
		nfsm_chain_build_done(error, &nmreq);
		nfs_unlock(dnp);
		lockerror = ENOENT;
		nfsmout_if(error);

		error = nfs_request(dnp, NULL, &nmreq, NFSPROC_READDIRPLUS, ctx,
				&nmrep, &xid, &status);

		if ((lockerror = nfs_lock(dnp, NFS_NODE_LOCK_EXCLUSIVE)))
			error = lockerror;

		savexid = xid;
		nfsm_chain_postop_attr_update(error, &nmrep, dnp, &xid);
		if (!error)
			error = status;
		nfsm_chain_get_32(error, &nmrep, dnp->n_cookieverf.nfsuquad[0]);
		nfsm_chain_get_32(error, &nmrep, dnp->n_cookieverf.nfsuquad[1]);
		nfsm_chain_get_32(error, &nmrep, more_dirs);

		if (!lockerror) {
			nfs_unlock(dnp);
			lockerror = ENOENT;
		}
		nfsmout_if(error);
		nfsmout_if(error);

		/* loop thru the dir entries, doctoring them to 4bsd form */
		while (more_dirs && bigenough) {
			nfsm_chain_get_64(error, &nmrep, fileno);
			nfsm_chain_get_32(error, &nmrep, len);
			nfsmout_if(error);
			/* Note: v3 supports longer names, but struct dirent doesn't */
			/* so we just truncate the names to fit */
			if (len <= 0) {
				error = EBADRPC;
				goto nfsmout;
			}
			if (len > MAXNAMLEN) {
				skiplen = len - MAXNAMLEN;
				len = MAXNAMLEN;
			} else {
				skiplen = 0;
			}
			tlen = nfsm_rndup(len);
			if (tlen == len)
				tlen += 4;	/* To ensure null termination */
			left = DIRBLKSIZ - blksiz;
			if ((tlen + DIRHDSIZ) > left) {
				dp->d_reclen += left;
				uio_iov_base_add(uiop, left);
				uio_iov_len_add(uiop, -left);
				uiop->uio_offset += left;
				uio_uio_resid_add(uiop, -left);
				blksiz = 0;
			}
			if ((tlen + DIRHDSIZ) > uio_uio_resid(uiop))
				bigenough = 0;
			if (bigenough) {
				// LP64todo - fix this!
				dp = (struct dirent *) CAST_DOWN(caddr_t, uio_iov_base(uiop));
				dp->d_fileno = (int)fileno;
				dp->d_namlen = len;
				dp->d_reclen = tlen + DIRHDSIZ;
				dp->d_type = DT_UNKNOWN;
				blksiz += dp->d_reclen;
				if (blksiz == DIRBLKSIZ)
					blksiz = 0;
				uiop->uio_offset += DIRHDSIZ;
#if LP64KERN
				uio_uio_resid_add(uiop, -((int64_t)DIRHDSIZ));
				uio_iov_len_add(uiop, -((int64_t)DIRHDSIZ));
#else
				uio_uio_resid_add(uiop, -((int)DIRHDSIZ));
				uio_iov_len_add(uiop, -((int)DIRHDSIZ));
#endif
				uio_iov_base_add(uiop, DIRHDSIZ);
				// LP64todo - fix this!
				cnp->cn_nameptr = CAST_DOWN(caddr_t, uio_iov_base(uiop));
				cnp->cn_namelen = len;
				error = nfsm_chain_get_uio(&nmrep, len, uiop);
				nfsmout_if(error);
				cp = CAST_DOWN(caddr_t, uio_iov_base(uiop));
				tlen -= len;
				*cp = '\0';
				uio_iov_base_add(uiop, tlen);
				uio_iov_len_add(uiop, -tlen);
				uiop->uio_offset += tlen;
				uio_uio_resid_add(uiop, -tlen);
				if (skiplen)
					nfsm_chain_adv(error, &nmrep,
						nfsm_rndup(len + skiplen) - nfsm_rndup(len));
			} else {
				nfsm_chain_adv(error, &nmrep, nfsm_rndup(len + skiplen));
			}
			if (bigenough) {
				nfsm_chain_get_32(error, &nmrep, cookie.nfsuquad[0]);
				nfsm_chain_get_32(error, &nmrep, cookie.nfsuquad[1]);
			} else
				nfsm_chain_adv(error, &nmrep, 2 * NFSX_UNSIGNED);

			nfsm_chain_get_32(error, &nmrep, attrflag);
			nfsmout_if(error);
			if (attrflag) {
			    /* grab attributes */
			    error = nfs_parsefattr(&nmrep, NFS_VER3, &nvattr);
			    nfsmout_if(error);
			    dp->d_type = IFTODT(VTTOIF(nvattr.nva_type));
			    /* check for file handle */
			    nfsm_chain_get_32(error, &nmrep, doit);
			    nfsmout_if(error);
			    if (doit) {
				nfsm_chain_get_fh_ptr(error, &nmrep, NFS_VER3, fhp, fhsize);
				nfsmout_if(error);
				if (NFS_CMPFH(dnp, fhp, fhsize)) {
				    error = vnode_ref(NFSTOV(dnp));
				    if (error) {
					doit = 0;
				    } else {
					if ((lockerror = nfs_lock(dnp, NFS_NODE_LOCK_EXCLUSIVE)))
					    error = lockerror;
					if (error) {
					    vnode_rele(NFSTOV(dnp));
					    goto nfsmout;
					}
					newvp = NFSTOV(dnp);
					np = dnp;
				    }
				} else if (!bigenough ||
				        (cnp->cn_namelen == 2 &&
					 cnp->cn_nameptr[1] == '.' &&
					 cnp->cn_nameptr[0] == '.')) {
				    /*
				     * XXXmacko I don't think this ".." thing is a problem anymore.
				     * don't doit if we can't guarantee
				     * that this entry is NOT ".." because
				     * we would have to drop the lock on
				     * the directory before getting the
				     * lock on the ".." vnode... and we
				     * don't want to drop the dvp lock in
				     * the middle of a readdirplus.
				     */
				    doit = 0;
				} else {
				    cnp->cn_hash = 0;

				    error = nfs_nget(NFSTOMP(dnp), dnp, cnp,
				    		fhp, fhsize, &nvattr, &xid, NG_MAKEENTRY, &np);
				    if (error)
					doit = 0;
				    else
					newvp = NFSTOV(np);
				}
			    }
			    /* update attributes if not already updated */
			    if (doit && bigenough && (np->n_xid <= savexid)) {
				xid = savexid;
				nfs_loadattrcache(np, &nvattr, &xid, 0);
				/* any error can be ignored */
			    }
			} else {
			    /* Just skip over the file handle */
			    nfsm_chain_get_32(error, &nmrep, fhsize);
			    nfsm_chain_adv(error, &nmrep, nfsm_rndup(fhsize));
			}
			if (newvp != NULLVP) {
			    nfs_unlock(np);
			    if (newvp == NFSTOV(dnp))
				vnode_rele(newvp);
			    else
				vnode_put(newvp);
			    newvp = NULLVP;
			}
			nfsm_chain_get_32(error, &nmrep, more_dirs);
			nfsmout_if(error);
		}
		/*
		 * If at end of rpc data, get the eof boolean
		 */
		if (!more_dirs) {
			nfsm_chain_get_32(error, &nmrep, eof);
			if (!error)
				more_dirs = (eof == 0);
		}
		if ((lockerror = nfs_lock(dnp, NFS_NODE_LOCK_SHARED)))
			error = lockerror;
		nfsmout_if(error);
		nfsm_chain_cleanup(&nmrep);
		nfsm_chain_null(&nmreq);
	}
	if (!lockerror) {
		nfs_unlock(dnp);
		lockerror = ENOENT;
	}
	/*
	 * Fill last record, iff any, out to a multiple of DIRBLKSIZ
	 * by increasing d_reclen for the last record.
	 */
	if (blksiz > 0) {
		left = DIRBLKSIZ - blksiz;
		dp->d_reclen += left;
		uio_iov_base_add(uiop, left);
		uio_iov_len_add(uiop, -left);
		uiop->uio_offset += left;
		uio_uio_resid_add(uiop, -left);
	}

	if ((lockerror = nfs_lock(dnp, NFS_NODE_LOCK_EXCLUSIVE)))
		error = lockerror;
	nfsmout_if(error);

	/*
	 * We are now either at the end of the directory or have filled the
	 * block.
	 */
	if (bigenough)
		dnp->n_direofoffset = uiop->uio_offset;
	else {
		if (uio_uio_resid(uiop) > 0)
			printf("EEK! readdirplus_rpc resid > 0\n");
		cookiep = nfs_getcookie(dnp, uiop->uio_offset, 1);
		if (cookiep)
			*cookiep = cookie;
	}

nfsmout:
	if (!lockerror)
		nfs_unlock(dnp);
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

/*
 * Silly rename. To make the NFS filesystem that is stateless look a little
 * more like the "ufs" a remove of an active vnode is translated to a rename
 * to a funny looking filename that is removed by nfs_vnop_inactive on the
 * nfsnode. There is the potential for another process on a different client
 * to create the same funny name between when the lookitup() fails and the
 * rename() completes, but...
 */

/* format of "random" silly names - includes a number and pid */
/* (note: shouldn't exceed size of nfs_sillyrename.nsr_name) */
#define NFS_SILLYNAME_FORMAT ".nfs.%08x.%04x"
/* starting from zero isn't silly enough */
static uint32_t nfs_sillyrename_number = 0x20051025;

static int
nfs_sillyrename(
	nfsnode_t dnp,
	nfsnode_t np,
	struct componentname *cnp,
	vfs_context_t ctx)
{
	struct nfs_sillyrename *nsp;
	int error;
	short pid;
	kauth_cred_t cred;
	uint32_t num;
	struct nfsmount *nmp;

	nmp = NFSTONMP(dnp);
	if (!nmp)
		return (ENXIO);

	cache_purge(NFSTOV(np));

	MALLOC_ZONE(nsp, struct nfs_sillyrename *,
			sizeof (struct nfs_sillyrename), M_NFSREQ, M_WAITOK);
	if (!nsp)
		return (ENOMEM);
	cred = vfs_context_ucred(ctx);
	kauth_cred_ref(cred);
	nsp->nsr_cred = cred;
	nsp->nsr_dnp = dnp;
	error = vnode_ref(NFSTOV(dnp));
	if (error)
		goto bad_norele;

	/* Fudge together a funny name */
	pid = vfs_context_pid(ctx);
	num = OSAddAtomic(1, (SInt32*)&nfs_sillyrename_number);
	nsp->nsr_namlen = snprintf(nsp->nsr_name, sizeof(nsp->nsr_name),
				NFS_SILLYNAME_FORMAT, num, (pid & 0xffff));
	if (nsp->nsr_namlen >= (int)sizeof(nsp->nsr_name))
		nsp->nsr_namlen = sizeof(nsp->nsr_name) - 1;

	/* Try lookitups until we get one that isn't there */
	while (nfs_lookitup(dnp, nsp->nsr_name, nsp->nsr_namlen, ctx, NULL) == 0) {
		num = OSAddAtomic(1, (SInt32*)&nfs_sillyrename_number);
		nsp->nsr_namlen = snprintf(nsp->nsr_name, sizeof(nsp->nsr_name),
					NFS_SILLYNAME_FORMAT, num, (pid & 0xffff));
		if (nsp->nsr_namlen >= (int)sizeof(nsp->nsr_name))
			nsp->nsr_namlen = sizeof(nsp->nsr_name) - 1;
	}

	/* now, do the rename */
	error = nmp->nm_funcs->nf_rename_rpc(dnp, cnp->cn_nameptr, cnp->cn_namelen,
					dnp, nsp->nsr_name, nsp->nsr_namlen, ctx);
	if (!error && (dnp->n_flag & NNEGNCENTRIES)) {
		dnp->n_flag &= ~NNEGNCENTRIES;
		cache_purge_negatives(NFSTOV(dnp));
	}
	FSDBG(267, dnp, np, num, error);
	if (error)
		goto bad;
	error = nfs_lookitup(dnp, nsp->nsr_name, nsp->nsr_namlen, ctx, &np);
	np->n_sillyrename = nsp;
	return (0);
bad:
	vnode_rele(NFSTOV(dnp));
bad_norele:
	nsp->nsr_cred = NOCRED;
	kauth_cred_unref(&cred);
	FREE_ZONE(nsp, sizeof(*nsp), M_NFSREQ);
	return (error);
}

int
nfs3_lookup_rpc_async(
	nfsnode_t dnp,
	char *name,
	int namelen,
	vfs_context_t ctx,
	struct nfsreq **reqp)
{
	struct nfsmount *nmp;
	struct nfsm_chain nmreq;
	int error = 0, nfsvers;

	nmp = NFSTONMP(dnp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	nfsm_chain_null(&nmreq);

	nfsm_chain_build_alloc_init(error, &nmreq,
		NFSX_FH(nfsvers) + NFSX_UNSIGNED + nfsm_rndup(namelen));
	nfsm_chain_add_fh(error, &nmreq, nfsvers, dnp->n_fhp, dnp->n_fhsize);
	nfsm_chain_add_string(error, &nmreq, name, namelen);
	nfsm_chain_build_done(error, &nmreq);
	nfsmout_if(error);
	error = nfs_request_async(dnp, NULL, &nmreq, NFSPROC_LOOKUP,
			vfs_context_thread(ctx), vfs_context_ucred(ctx), NULL, reqp);
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	return (error);
}

int
nfs3_lookup_rpc_async_finish(
	nfsnode_t dnp,
	vfs_context_t ctx,
	struct nfsreq *req,
	u_int64_t *xidp,
	fhandle_t *fhp,
	struct nfs_vattr *nvap)
{
	int error = 0, status, nfsvers, attrflag;
	u_int64_t xid;
	struct nfsmount *nmp;
	struct nfsm_chain nmrep;

	nmp = NFSTONMP(dnp);
	nfsvers = nmp->nm_vers;

	nfsm_chain_null(&nmrep);

	error = nfs_request_async_finish(req, &nmrep, xidp, &status);

	xid = *xidp;
	if (error || status) {
		if (nfsvers == NFS_VER3)
			nfsm_chain_postop_attr_update(error, &nmrep, dnp, &xid);
		if (!error)
			error = status;
		goto nfsmout;
	}

	nfsmout_if(error || !fhp || !nvap);

	/* get the file handle */
	nfsm_chain_get_fh(error, &nmrep, nfsvers, fhp);

	/* get the attributes */
	if (nfsvers == NFS_VER3) {
		nfsm_chain_postop_attr_get(error, &nmrep, attrflag, nvap);
		nfsm_chain_postop_attr_update(error, &nmrep, dnp, &xid);
		if (!error && !attrflag)
			error = nfs3_getattr_rpc(NULL, NFSTOMP(dnp), fhp->fh_data, fhp->fh_len, ctx, nvap, xidp);
	} else {
		error = nfs_parsefattr(&nmrep, nfsvers, nvap);
	}
nfsmout:
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

/*
 * Look up a file name and optionally either update the file handle or
 * allocate an nfsnode, depending on the value of npp.
 * npp == NULL	--> just do the lookup
 * *npp == NULL --> allocate a new nfsnode and make sure attributes are
 *			handled too
 * *npp != NULL --> update the file handle in the vnode
 */
int
nfs_lookitup(
	nfsnode_t dnp,
	char *name,
	int namelen,
	vfs_context_t ctx,
	nfsnode_t *npp)
{
	int error = 0;
	nfsnode_t np, newnp = NULL;
	u_int64_t xid;
	fhandle_t fh;
	struct nfsmount *nmp;
	struct nfs_vattr nvattr;
	struct nfsreq rq, *req = &rq;

	nmp = NFSTONMP(dnp);
	if (!nmp)
		return (ENXIO);

	if (NFS_BITMAP_ISSET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_MAXNAME) &&
	    (namelen > (long)nmp->nm_fsattr.nfsa_maxname))
		return (ENAMETOOLONG);

	/* check for lookup of "." */
	if ((name[0] == '.') && (namelen == 1)) {
		/* skip lookup, we know who we are */
		fh.fh_len = 0;
		newnp = dnp;
		goto nfsmout;
	}

	error = nmp->nm_funcs->nf_lookup_rpc_async(dnp, name, namelen, ctx, &req);
	nfsmout_if(error);
	error = nmp->nm_funcs->nf_lookup_rpc_async_finish(dnp, ctx, req, &xid, &fh, &nvattr);
	nfsmout_if(!npp || error);

	if (*npp) {
		np = *npp;
		if (fh.fh_len != np->n_fhsize) {
			u_char *oldbuf = (np->n_fhsize > NFS_SMALLFH) ? np->n_fhp : NULL;
			if (fh.fh_len > NFS_SMALLFH) {
				MALLOC_ZONE(np->n_fhp, u_char *, fh.fh_len, M_NFSBIGFH, M_WAITOK);
				if (!np->n_fhp) {
				    np->n_fhp = oldbuf;
				    error = ENOMEM;
				    goto nfsmout;
				}
			} else {
				np->n_fhp = &np->n_fh[0];
			}
			if (oldbuf)
				FREE_ZONE(oldbuf, np->n_fhsize, M_NFSBIGFH);
		}
		bcopy(fh.fh_data, np->n_fhp, fh.fh_len);
		np->n_fhsize = fh.fh_len;
		error = nfs_loadattrcache(np, &nvattr, &xid, 0);
		nfsmout_if(error);
		newnp = np;
	} else if (NFS_CMPFH(dnp, fh.fh_data, fh.fh_len)) {
		if (dnp->n_xid <= xid)
			error = nfs_loadattrcache(dnp, &nvattr, &xid, 0);
		nfsmout_if(error);
		newnp = dnp;
	} else {
		struct componentname cn, *cnp = &cn;
		bzero(cnp, sizeof(*cnp));
		cnp->cn_nameptr = name;
		cnp->cn_namelen = namelen;
		error = nfs_nget(NFSTOMP(dnp), dnp, cnp, fh.fh_data, fh.fh_len,
			    &nvattr, &xid, NG_MAKEENTRY, &np);
		nfsmout_if(error);
		newnp = np;
	}

nfsmout:
	if (npp && !*npp && !error)
		*npp = newnp;
	return (error);
}

/*
 * set up and initialize a "._" file lookup structure used for
 * performing async lookups.
 */
void
nfs_dulookup_init(struct nfs_dulookup *dulp, nfsnode_t dnp, const char *name, int namelen)
{
	int error, du_namelen;
	vnode_t du_vp;

	/* check for ._ file in name cache */
	dulp->du_flags = 0;
	bzero(&dulp->du_cn, sizeof(dulp->du_cn));
	du_namelen = namelen + 2;
	if ((namelen >= 2) && (name[0] == '.') && (name[1] == '_'))
		return;
	if (du_namelen >= (int)sizeof(dulp->du_smallname))
		MALLOC(dulp->du_cn.cn_nameptr, char *, du_namelen + 1, M_TEMP, M_WAITOK);
	else
		dulp->du_cn.cn_nameptr = dulp->du_smallname;
	if (!dulp->du_cn.cn_nameptr)
		return;
	dulp->du_cn.cn_namelen = du_namelen;
	snprintf(dulp->du_cn.cn_nameptr, du_namelen + 1, "._%s", name);
	dulp->du_cn.cn_nameptr[du_namelen] = '\0';

	error = cache_lookup(NFSTOV(dnp), &du_vp, &dulp->du_cn);
	if (error == -1)
		vnode_put(du_vp);
	else if (!error)
		dulp->du_flags |= NFS_DULOOKUP_DOIT;
	else if (dulp->du_cn.cn_nameptr != dulp->du_smallname)
		FREE(dulp->du_cn.cn_nameptr, M_TEMP);
}

/*
 * start an async "._" file lookup request
 */
void
nfs_dulookup_start(struct nfs_dulookup *dulp, nfsnode_t dnp, vfs_context_t ctx)
{
	struct nfsmount *nmp = NFSTONMP(dnp);
	struct nfsreq *req = &dulp->du_req;

	if (!nmp || !(dulp->du_flags & NFS_DULOOKUP_DOIT))
		return;
	if (!nmp->nm_funcs->nf_lookup_rpc_async(dnp, dulp->du_cn.cn_nameptr,
			dulp->du_cn.cn_namelen, ctx, &req))
		dulp->du_flags |= NFS_DULOOKUP_INPROG;
}

/*
 * finish an async "._" file lookup request and clean up the structure
 */
void
nfs_dulookup_finish(struct nfs_dulookup *dulp, nfsnode_t dnp, vfs_context_t ctx)
{
	struct nfsmount *nmp = NFSTONMP(dnp);
	int error;
	nfsnode_t du_np;
	u_int64_t xid;
	fhandle_t fh;
	struct nfs_vattr nvattr;

	if (!nmp || !(dulp->du_flags & NFS_DULOOKUP_INPROG))
		goto out;

	error = nmp->nm_funcs->nf_lookup_rpc_async_finish(dnp, ctx, &dulp->du_req, &xid, &fh, &nvattr);
	dulp->du_flags &= ~NFS_DULOOKUP_INPROG;
	if (error == ENOENT) {
		/* add a negative entry in the name cache */
		cache_enter(NFSTOV(dnp), NULL, &dulp->du_cn);
		dnp->n_flag |= NNEGNCENTRIES;
	} else if (!error) {
		error = nfs_nget(NFSTOMP(dnp), dnp, &dulp->du_cn, fh.fh_data, fh.fh_len,
			    &nvattr, &xid, NG_MAKEENTRY, &du_np);
		if (!error) {
			nfs_unlock(du_np);
			vnode_put(NFSTOV(du_np));
		}
	}
out:
	if (dulp->du_flags & NFS_DULOOKUP_INPROG)
		nfs_request_async_cancel(&dulp->du_req);
	if (dulp->du_cn.cn_nameptr && (dulp->du_cn.cn_nameptr != dulp->du_smallname))
		FREE(dulp->du_cn.cn_nameptr, M_TEMP);
}


/*
 * NFS Version 3 commit RPC
 */
int
nfs3_commit_rpc(
	nfsnode_t np,
	u_int64_t offset,
	u_int64_t count,
	kauth_cred_t cred)
{
	struct nfsmount *nmp;
	int error = 0, lockerror, status, wccpostattr = 0, nfsvers;
	struct timespec premtime = { 0, 0 };
	u_int64_t xid, wverf;
	uint32_t count32;
	struct nfsm_chain nmreq, nmrep;

	nmp = NFSTONMP(np);
	FSDBG(521, np, offset, count, nmp ? nmp->nm_state : 0);
	if (!nmp)
		return (ENXIO);
	if (!(nmp->nm_state & NFSSTA_HASWRITEVERF))
		return (0);
	nfsvers = nmp->nm_vers;

	if (count > UINT32_MAX)
		count32 = 0;
	else
		count32 = count;

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	nfsm_chain_build_alloc_init(error, &nmreq, NFSX_FH(NFS_VER3));
	nfsm_chain_add_fh(error, &nmreq, nfsvers, np->n_fhp, np->n_fhsize);
	nfsm_chain_add_64(error, &nmreq, offset);
	nfsm_chain_add_32(error, &nmreq, count32);
	nfsm_chain_build_done(error, &nmreq);
	nfsmout_if(error);
	error = nfs_request2(np, NULL, &nmreq, NFSPROC_COMMIT,
			current_thread(), cred, 0, &nmrep, &xid, &status);
	if ((lockerror = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
		error = lockerror;
	/* can we do anything useful with the wcc info? */
	nfsm_chain_get_wcc_data(error, &nmrep, np, &premtime, &wccpostattr, &xid);
	if (!lockerror)
		nfs_unlock(np);
	if (!error)
		error = status;
	nfsm_chain_get_64(error, &nmrep, wverf);
	nfsmout_if(error);
	lck_mtx_lock(&nmp->nm_lock);
	if (nmp->nm_verf != wverf) {
		nmp->nm_verf = wverf;
		error = NFSERR_STALEWRITEVERF;
	}
	lck_mtx_unlock(&nmp->nm_lock);
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}


static int
nfs_vnop_blockmap(
	__unused struct vnop_blockmap_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		off_t a_foffset;
		size_t a_size;
		daddr64_t *a_bpn;
		size_t *a_run;
		void *a_poff;
		int a_flags;
	} */ *ap)
{
	return (ENOTSUP);
}

/*
 * Mmap a file
 *
 * NB Currently unsupported.
 */
/*ARGSUSED*/
static int
nfs_vnop_mmap(
	__unused struct vnop_mmap_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		int a_fflags;
		vfs_context_t a_context;
	} */ *ap)
{
	return (EINVAL);
}

/*
 * fsync vnode op. Just call nfs_flush().
 */
/* ARGSUSED */
static int
nfs_vnop_fsync(
	struct vnop_fsync_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		int a_waitfor;
		vfs_context_t a_context;
	} */ *ap)
{
	return (nfs_flush(VTONFS(ap->a_vp), ap->a_waitfor, vfs_context_thread(ap->a_context), 0));
}


/*
 * Do an NFS pathconf RPC.
 */
int
nfs3_pathconf_rpc(
	nfsnode_t np,
	struct nfs_fsattr *nfsap,
	vfs_context_t ctx)
{
	u_int64_t xid;
	int error = 0, lockerror, status, nfsvers;
	struct nfsm_chain nmreq, nmrep;
	struct nfsmount *nmp = NFSTONMP(np);
	uint32_t val = 0;

	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	/* fetch pathconf info from server */
	nfsm_chain_build_alloc_init(error, &nmreq, NFSX_FH(NFS_VER3));
	nfsm_chain_add_fh(error, &nmreq, nfsvers, np->n_fhp, np->n_fhsize);
	nfsm_chain_build_done(error, &nmreq);
	nfsmout_if(error);
	error = nfs_request(np, NULL, &nmreq, NFSPROC_PATHCONF, ctx,
			&nmrep, &xid, &status);
	if ((lockerror = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
		error = lockerror;
	nfsm_chain_postop_attr_update(error, &nmrep, np, &xid);
	if (!lockerror)
		nfs_unlock(np);
	if (!error)
		error = status;
	nfsm_chain_get_32(error, &nmrep, nfsap->nfsa_maxlink);
	nfsm_chain_get_32(error, &nmrep, nfsap->nfsa_maxname);
	nfsm_chain_get_32(error, &nmrep, val);
	if (val)
		nfsap->nfsa_flags |= NFS_FSFLAG_NO_TRUNC;
	nfsm_chain_get_32(error, &nmrep, val);
	if (val)
		nfsap->nfsa_flags |= NFS_FSFLAG_CHOWN_RESTRICTED;
	nfsm_chain_get_32(error, &nmrep, val);
	if (val)
		nfsap->nfsa_flags |= NFS_FSFLAG_CASE_INSENSITIVE;
	nfsm_chain_get_32(error, &nmrep, val);
	if (val)
		nfsap->nfsa_flags |= NFS_FSFLAG_CASE_PRESERVING;
	NFS_BITMAP_SET(nfsap->nfsa_bitmap, NFS_FATTR_MAXLINK);
	NFS_BITMAP_SET(nfsap->nfsa_bitmap, NFS_FATTR_MAXNAME);
	NFS_BITMAP_SET(nfsap->nfsa_bitmap, NFS_FATTR_NO_TRUNC);
	NFS_BITMAP_SET(nfsap->nfsa_bitmap, NFS_FATTR_CHOWN_RESTRICTED);
	NFS_BITMAP_SET(nfsap->nfsa_bitmap, NFS_FATTR_CASE_INSENSITIVE);
	NFS_BITMAP_SET(nfsap->nfsa_bitmap, NFS_FATTR_CASE_PRESERVING);
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

/* save pathconf info for NFSv3 mount */
void
nfs3_pathconf_cache(struct nfsmount *nmp, struct nfs_fsattr *nfsap)
{
	nmp->nm_fsattr.nfsa_maxlink = nfsap->nfsa_maxlink;
	nmp->nm_fsattr.nfsa_maxname = nfsap->nfsa_maxname;
	nmp->nm_fsattr.nfsa_flags |= nfsap->nfsa_flags & NFS_FSFLAG_NO_TRUNC;
	nmp->nm_fsattr.nfsa_flags |= nfsap->nfsa_flags & NFS_FSFLAG_CHOWN_RESTRICTED;
	nmp->nm_fsattr.nfsa_flags |= nfsap->nfsa_flags & NFS_FSFLAG_CASE_INSENSITIVE;
	nmp->nm_fsattr.nfsa_flags |= nfsap->nfsa_flags & NFS_FSFLAG_CASE_PRESERVING;
	NFS_BITMAP_SET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_MAXLINK);
	NFS_BITMAP_SET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_MAXNAME);
	NFS_BITMAP_SET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_NO_TRUNC);
	NFS_BITMAP_SET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_CHOWN_RESTRICTED);
	NFS_BITMAP_SET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_CASE_INSENSITIVE);
	NFS_BITMAP_SET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_CASE_PRESERVING);
	nmp->nm_state |= NFSSTA_GOTPATHCONF;
}

/*
 * Return POSIX pathconf information applicable to nfs.
 *
 * The NFS V2 protocol doesn't support this, so just return EINVAL
 * for V2.
 */
/* ARGSUSED */
static int
nfs_vnop_pathconf(
	struct vnop_pathconf_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		int a_name;
		register_t *a_retval;
		vfs_context_t a_context;
	} */ *ap)
{
	vnode_t vp = ap->a_vp;
	nfsnode_t np = VTONFS(vp);
	struct nfsmount *nmp;
	struct nfs_fsattr nfsa, *nfsap;
	int error = 0;
	uint64_t maxFileSize;
	uint nbits;

	nmp = VTONMP(vp);
	if (!nmp)
		return (ENXIO);

	switch (ap->a_name) {
	case _PC_LINK_MAX:
	case _PC_NAME_MAX:
	case _PC_CHOWN_RESTRICTED:
	case _PC_NO_TRUNC:
	case _PC_CASE_SENSITIVE:
	case _PC_CASE_PRESERVING:
		break;
	case _PC_FILESIZEBITS:
		if (nmp->nm_vers == NFS_VER2) {
			*ap->a_retval = 32;
			return (0);
		}
		break;
	default:
		/* don't bother contacting the server if we know the answer */
		return (EINVAL);
	}

	if (nmp->nm_vers == NFS_VER2)
		return (EINVAL);

	lck_mtx_lock(&nmp->nm_lock);
	if (nmp->nm_vers == NFS_VER3) {
		if (!(nmp->nm_state & NFSSTA_GOTPATHCONF)) {
			/* no pathconf info cached */
			lck_mtx_unlock(&nmp->nm_lock);
			NFS_CLEAR_ATTRIBUTES(nfsa.nfsa_bitmap);
			error = nfs3_pathconf_rpc(np, &nfsa, ap->a_context);
			if (error)
				return (error);
			nmp = VTONMP(vp);
			if (!nmp)
				return (ENXIO);
			lck_mtx_lock(&nmp->nm_lock);
			if (nmp->nm_fsattr.nfsa_flags & NFS_FSFLAG_HOMOGENEOUS) {
				/* all files have the same pathconf info, */
				/* so cache a copy of the results */
				nfs3_pathconf_cache(nmp, &nfsa);
			}
			nfsap = &nfsa;
		} else {
			nfsap = &nmp->nm_fsattr;
		}
	} else if (!(nmp->nm_fsattr.nfsa_flags & NFS_FSFLAG_HOMOGENEOUS)) {
		/* no pathconf info cached */
		lck_mtx_unlock(&nmp->nm_lock);
		NFS_CLEAR_ATTRIBUTES(nfsa.nfsa_bitmap);
		error = nfs4_pathconf_rpc(np, &nfsa, ap->a_context);
		if (error)
			return (error);
		nmp = VTONMP(vp);
		if (!nmp)
			return (ENXIO);
		lck_mtx_lock(&nmp->nm_lock);
		nfsap = &nfsa;
	} else {
		nfsap = &nmp->nm_fsattr;
	}

	switch (ap->a_name) {
	case _PC_LINK_MAX:
		if (NFS_BITMAP_ISSET(nfsap->nfsa_bitmap, NFS_FATTR_MAXLINK))
			*ap->a_retval = nfsap->nfsa_maxlink;
		else if ((nmp->nm_vers == NFS_VER4) && NFS_BITMAP_ISSET(np->n_vattr.nva_bitmap, NFS_FATTR_MAXLINK))
			*ap->a_retval = np->n_vattr.nva_maxlink;
		else
			error = EINVAL;
		break;
	case _PC_NAME_MAX:
		if (NFS_BITMAP_ISSET(nfsap->nfsa_bitmap, NFS_FATTR_MAXNAME))
			*ap->a_retval = nfsap->nfsa_maxname;
		else
			error = EINVAL;
		break;
	case _PC_CHOWN_RESTRICTED:
		if (NFS_BITMAP_ISSET(nfsap->nfsa_bitmap, NFS_FATTR_CHOWN_RESTRICTED))
			*ap->a_retval = (nmp->nm_fsattr.nfsa_flags & NFS_FSFLAG_CHOWN_RESTRICTED) ? 200112 /* _POSIX_CHOWN_RESTRICTED */ : 0;
		else
			error = EINVAL;
		break;
	case _PC_NO_TRUNC:
		if (NFS_BITMAP_ISSET(nfsap->nfsa_bitmap, NFS_FATTR_NO_TRUNC))
			*ap->a_retval = (nmp->nm_fsattr.nfsa_flags & NFS_FSFLAG_NO_TRUNC) ? 200112 /* _POSIX_NO_TRUNC */ : 0;
		else
			error = EINVAL;
		break;
	case _PC_CASE_SENSITIVE:
		if (NFS_BITMAP_ISSET(nfsap->nfsa_bitmap, NFS_FATTR_CASE_INSENSITIVE))
			*ap->a_retval = (nmp->nm_fsattr.nfsa_flags & NFS_FSFLAG_CASE_INSENSITIVE) ? 0 : 1;
		else
			error = EINVAL;
		break;
	case _PC_CASE_PRESERVING:
		if (NFS_BITMAP_ISSET(nfsap->nfsa_bitmap, NFS_FATTR_CASE_PRESERVING))
			*ap->a_retval = (nmp->nm_fsattr.nfsa_flags & NFS_FSFLAG_CASE_PRESERVING) ? 1 : 0;
		else
			error = EINVAL;
		break;
	case _PC_FILESIZEBITS:
		if (!NFS_BITMAP_ISSET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_MAXFILESIZE)) {
			*ap->a_retval = 64;
			error = 0;
			break;
		}
		maxFileSize = nmp->nm_fsattr.nfsa_maxfilesize;
		nbits = 1;
		if (maxFileSize & 0xffffffff00000000ULL) {
			nbits += 32;
			maxFileSize >>= 32;
		}
		if (maxFileSize & 0xffff0000) {
			nbits += 16;
			maxFileSize >>= 16;
		}
		if (maxFileSize & 0xff00) {
			nbits += 8;
			maxFileSize >>= 8;
		}
		if (maxFileSize & 0xf0) {
			nbits += 4;
			maxFileSize >>= 4;
		}
		if (maxFileSize & 0xc) {
			nbits += 2;
			maxFileSize >>= 2;
		}
		if (maxFileSize & 0x2) {
			nbits += 1;
		}
		*ap->a_retval = nbits;
		break;
	default:
		error = EINVAL;
	}

	lck_mtx_unlock(&nmp->nm_lock);

	return (error);
}

/*
 * Read wrapper for special devices.
 */
static int
nfsspec_vnop_read(
	struct vnop_read_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		struct uio *a_uio;
		int a_ioflag;
		vfs_context_t a_context;
	} */ *ap)
{
	nfsnode_t np = VTONFS(ap->a_vp);
	struct timeval now;
	int error;

	/*
	 * Set access flag.
	 */
	if ((error = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
		return (error);
	np->n_flag |= NACC;
	microtime(&now);
	np->n_atim.tv_sec = now.tv_sec;
	np->n_atim.tv_nsec = now.tv_usec * 1000;
	nfs_unlock(np);
	return (VOCALL(spec_vnodeop_p, VOFFSET(vnop_read), ap));
}

/*
 * Write wrapper for special devices.
 */
static int
nfsspec_vnop_write(
	struct vnop_write_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		struct uio *a_uio;
		int a_ioflag;
		vfs_context_t a_context;
	} */ *ap)
{
	nfsnode_t np = VTONFS(ap->a_vp);
	struct timeval now;
	int error;

	/*
	 * Set update flag.
	 */
	if ((error = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
		return (error);
	np->n_flag |= NUPD;
	microtime(&now);
	np->n_mtim.tv_sec = now.tv_sec;
	np->n_mtim.tv_nsec = now.tv_usec * 1000;
	nfs_unlock(np);
	return (VOCALL(spec_vnodeop_p, VOFFSET(vnop_write), ap));
}

/*
 * Close wrapper for special devices.
 *
 * Update the times on the nfsnode then do device close.
 */
static int
nfsspec_vnop_close(
	struct vnop_close_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		int a_fflag;
		vfs_context_t a_context;
	} */ *ap)
{
	vnode_t vp = ap->a_vp;
	nfsnode_t np = VTONFS(vp);
	struct vnode_attr vattr;
	mount_t mp;
	int error;

	if ((error = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
		return (error);
	if (np->n_flag & (NACC | NUPD)) {
		np->n_flag |= NCHG;
		if (!vnode_isinuse(vp, 1) && (mp = vnode_mount(vp)) && !vfs_isrdonly(mp)) {
			VATTR_INIT(&vattr);
			if (np->n_flag & NACC) {
				vattr.va_access_time = np->n_atim;
				VATTR_SET_ACTIVE(&vattr, va_access_time);
			}
			if (np->n_flag & NUPD) {
				vattr.va_modify_time = np->n_mtim;
				VATTR_SET_ACTIVE(&vattr, va_modify_time);
			}
			nfs_unlock(np);
			vnode_setattr(vp, &vattr, ap->a_context);
		} else {
			nfs_unlock(np);
		}
	} else {
		nfs_unlock(np);
	}
	return (VOCALL(spec_vnodeop_p, VOFFSET(vnop_close), ap));
}

#if FIFO
extern vnop_t **fifo_vnodeop_p;

/*
 * Read wrapper for fifos.
 */
static int
nfsfifo_vnop_read(
	struct vnop_read_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		struct uio *a_uio;
		int a_ioflag;
		vfs_context_t a_context;
	} */ *ap)
{
	nfsnode_t np = VTONFS(ap->a_vp);
	struct timeval now;
	int error;

	/*
	 * Set access flag.
	 */
	if ((error = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
		return (error);
	np->n_flag |= NACC;
	microtime(&now);
	np->n_atim.tv_sec = now.tv_sec;
	np->n_atim.tv_nsec = now.tv_usec * 1000;
	nfs_unlock(np);
	return (VOCALL(fifo_vnodeop_p, VOFFSET(vnop_read), ap));
}

/*
 * Write wrapper for fifos.
 */
static int
nfsfifo_vnop_write(
	struct vnop_write_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		struct uio *a_uio;
		int a_ioflag;
		vfs_context_t a_context;
	} */ *ap)
{
	nfsnode_t np = VTONFS(ap->a_vp);
	struct timeval now;
	int error;

	/*
	 * Set update flag.
	 */
	if ((error = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
		return (error);
	np->n_flag |= NUPD;
	microtime(&now);
	np->n_mtim.tv_sec = now.tv_sec;
	np->n_mtim.tv_nsec = now.tv_usec * 1000;
	nfs_unlock(np);
	return (VOCALL(fifo_vnodeop_p, VOFFSET(vnop_write), ap));
}

/*
 * Close wrapper for fifos.
 *
 * Update the times on the nfsnode then do fifo close.
 */
static int
nfsfifo_vnop_close(
	struct vnop_close_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		int a_fflag;
		vfs_context_t a_context;
	} */ *ap)
{
	vnode_t vp = ap->a_vp;
	nfsnode_t np = VTONFS(vp);
	struct vnode_attr vattr;
	struct timeval now;
	mount_t mp;
	int error;

	if ((error = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
		return (error);
	if (np->n_flag & (NACC | NUPD)) {
		microtime(&now);
		if (np->n_flag & NACC) {
			np->n_atim.tv_sec = now.tv_sec;
			np->n_atim.tv_nsec = now.tv_usec * 1000;
		}
		if (np->n_flag & NUPD) {
			np->n_mtim.tv_sec = now.tv_sec;
			np->n_mtim.tv_nsec = now.tv_usec * 1000;
		}
		np->n_flag |= NCHG;
		if (!vnode_isinuse(vp, 1) && (mp = vnode_mount(vp)) && !vfs_isrdonly(mp)) {
			VATTR_INIT(&vattr);
			if (np->n_flag & NACC) {
				vattr.va_access_time = np->n_atim;
				VATTR_SET_ACTIVE(&vattr, va_access_time);
			}
			if (np->n_flag & NUPD) {
				vattr.va_modify_time = np->n_mtim;
				VATTR_SET_ACTIVE(&vattr, va_modify_time);
			}
			nfs_unlock(np);
			vnode_setattr(vp, &vattr, ap->a_context);
		} else {
			nfs_unlock(np);
		}
	} else {
		nfs_unlock(np);
	}
	return (VOCALL(fifo_vnodeop_p, VOFFSET(vnop_close), ap));
}
#endif /* FIFO */

/*ARGSUSED*/
static int
nfs_vnop_ioctl(
	__unused struct vnop_ioctl_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		u_long a_command;
		caddr_t a_data;
		int a_fflag;
		vfs_context_t a_context;
	} */ *ap)
{

	/*
	 * XXX we were once bogusly enoictl() which returned this (ENOTTY).
	 * Probably we should return ENODEV.
	 */
	return (ENOTTY);
}

/*ARGSUSED*/
static int
nfs_vnop_select(
	__unused struct vnop_select_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		int a_which;
		int a_fflags;
		void *a_wql;
		vfs_context_t a_context;
	} */ *ap)
{

	/*
	 * We were once bogusly seltrue() which returns 1.  Is this right?
	 */
	return (1);
}

/*
 * vnode OP for pagein using UPL
 *
 * No buffer I/O, just RPCs straight into the mapped pages.
 */
static int
nfs_vnop_pagein(
	struct vnop_pagein_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		upl_t a_pl;
		vm_offset_t a_pl_offset;
		off_t a_f_offset;
		size_t a_size;
		int a_flags;
		vfs_context_t a_context;
	} */ *ap)
{
	vnode_t vp = ap->a_vp;
	upl_t pl = ap->a_pl;
	size_t size = ap->a_size;
	off_t f_offset = ap->a_f_offset;
	vm_offset_t pl_offset = ap->a_pl_offset;
	int flags = ap->a_flags;
	thread_t thd;
	kauth_cred_t cred;
	nfsnode_t np = VTONFS(vp);
	size_t nmrsize, iosize, txsize, rxsize, retsize;
	off_t txoffset;
	struct nfsmount *nmp;
	int error = 0;
	vm_offset_t ioaddr;
	struct uio	auio;
	struct iovec_32	aiov;
	struct uio * uio = &auio;
	int nofreeupl = flags & UPL_NOCOMMIT;
	upl_page_info_t *plinfo;
#define MAXPAGINGREQS	16	/* max outstanding RPCs for pagein/pageout */
	struct nfsreq *req[MAXPAGINGREQS];
	int nextsend, nextwait;

	FSDBG(322, np, f_offset, size, flags);
	if (pl == (upl_t)NULL)
		panic("nfs_pagein: no upl");

	if (size <= 0) {
		printf("nfs_pagein: invalid size %ld", size);
		if (!nofreeupl)
			(void) ubc_upl_abort(pl, 0);
		return (EINVAL);
	}
	if (f_offset < 0 || f_offset >= (off_t)np->n_size || (f_offset & PAGE_MASK_64)) {
		if (!nofreeupl)
			ubc_upl_abort_range(pl, pl_offset, size,
				UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
		return (EINVAL);
	}

	thd = vfs_context_thread(ap->a_context);
	cred = ubc_getcred(vp);
	if (!IS_VALID_CRED(cred))
		cred = vfs_context_ucred(ap->a_context);

	auio.uio_offset = f_offset;
#if 1   /* LP64todo - can't use new segment flags until the drivers are ready */
	auio.uio_segflg = UIO_SYSSPACE;
#else
	auio.uio_segflg = UIO_SYSSPACE32;
#endif
	auio.uio_rw = UIO_READ;
	auio.uio_procp = vfs_context_proc(ap->a_context);

	nmp = VTONMP(vp);
	if (!nmp) {
		if (!nofreeupl)
			ubc_upl_abort_range(pl, pl_offset, size,
				UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
		return (ENXIO);
	}
	nmrsize = nmp->nm_rsize;

	plinfo = ubc_upl_pageinfo(pl);
	ubc_upl_map(pl, &ioaddr);
	ioaddr += pl_offset;
	txsize = rxsize = size;
	txoffset = f_offset;

	bzero(req, sizeof(req));
	nextsend = nextwait = 0;
	do {
		/* send requests while we need to and have available slots */
		while ((txsize > 0) && (req[nextsend] == NULL)) {
			iosize = MIN(nmrsize, txsize);
			if ((error = nmp->nm_funcs->nf_read_rpc_async(np, txoffset, iosize, thd, cred, NULL, &req[nextsend]))) {
				req[nextsend] = NULL;
				break;
			}
			txoffset += iosize;
			txsize -= iosize;
			nextsend = (nextsend + 1) % MAXPAGINGREQS;
		}
		/* wait while we need to and break out if more requests to send */
		while ((rxsize > 0) && req[nextwait]) {
			iosize = retsize = MIN(nmrsize, rxsize);
			aiov.iov_len  = iosize;
			aiov.iov_base = (uintptr_t)ioaddr;
			auio.uio_iovs.iov32p = &aiov;
			auio.uio_iovcnt = 1;
			uio_uio_resid_set(&auio, iosize);
			FSDBG(322, uio->uio_offset, uio_uio_resid(uio), ioaddr, rxsize);
#ifdef UPL_DEBUG
			upl_ubc_alias_set(pl, current_thread(), 2);
#endif /* UPL_DEBUG */
			OSAddAtomic(1, (SInt32*)&nfsstats.pageins);
			error = nmp->nm_funcs->nf_read_rpc_async_finish(np, req[nextwait], uio, &retsize, NULL);
			req[nextwait] = NULL;
			nextwait = (nextwait + 1) % MAXPAGINGREQS;
			if (error) {
				FSDBG(322, uio->uio_offset, uio_uio_resid(uio), error, -1);
				break;
			}
			if (retsize < iosize) {
				/* Just zero fill the rest of the valid area. */
				// LP64todo - fix this
				int zcnt = iosize - retsize;
				bzero((char *)ioaddr + retsize, zcnt);
				FSDBG(324, uio->uio_offset, retsize, zcnt, ioaddr);
				uio->uio_offset += zcnt;
			}
			ioaddr += iosize;	
			rxsize -= iosize;
			if (txsize)
				break;
		}
	} while (!error && (txsize || rxsize));

	ubc_upl_unmap(pl);

	if (error) {
		/* cancel any outstanding requests */
		while (req[nextwait]) {
			nfs_request_async_cancel(req[nextwait]);
			req[nextwait] = NULL;
			nextwait = (nextwait + 1) % MAXPAGINGREQS;
		}
	}

	if (!nofreeupl) {
		if (error)
			ubc_upl_abort_range(pl, pl_offset, size,
					    UPL_ABORT_ERROR |
					    UPL_ABORT_FREE_ON_EMPTY);
		else
			ubc_upl_commit_range(pl, pl_offset, size,
					     UPL_COMMIT_CLEAR_DIRTY |
					     UPL_COMMIT_FREE_ON_EMPTY);
	}
	return (error);
}


/*
 * the following are needed only by nfs_pageout to know how to handle errors
 * see nfs_pageout comments on explanation of actions.
 * the errors here are copied from errno.h and errors returned by servers
 * are expected to match the same numbers here. If not, our actions maybe
 * erroneous.
 */
enum actiontype {NOACTION, DUMP, DUMPANDLOG, RETRY, RETRYWITHSLEEP, SEVER};
#define NFS_ELAST 88
static u_char errorcount[NFS_ELAST+1]; /* better be zeros when initialized */
static const char errortooutcome[NFS_ELAST+1] = {
	NOACTION,
	DUMP,			/* EPERM	1	Operation not permitted */
	DUMP,			/* ENOENT	2	No such file or directory */
	DUMPANDLOG,		/* ESRCH	3	No such process */
	RETRY,			/* EINTR 	4	Interrupted system call */
	DUMP,			/* EIO		5	Input/output error */
	DUMP,			/* ENXIO	6	Device not configured */
	DUMPANDLOG,		/* E2BIG	7	Argument list too long */
	DUMPANDLOG,		/* ENOEXEC	8	Exec format error */
	DUMPANDLOG,		/* EBADF	9	Bad file descriptor */
	DUMPANDLOG,		/* ECHILD	10	No child processes */
	DUMPANDLOG,		/* EDEADLK	11	Resource deadlock avoided - was EAGAIN */
	RETRY,			/* ENOMEM	12	Cannot allocate memory */
	DUMP,			/* EACCES	13	Permission denied */
	DUMPANDLOG,		/* EFAULT	14	Bad address */
	DUMPANDLOG,		/* ENOTBLK	15	POSIX - Block device required */
	RETRY,			/* EBUSY	16	Device busy */
	DUMP,			/* EEXIST	17	File exists */
	DUMP,			/* EXDEV	18	Cross-device link */
	DUMP,			/* ENODEV	19	Operation not supported by device */
	DUMP,			/* ENOTDIR	20	Not a directory */
	DUMP,			/* EISDIR 	21	Is a directory */
	DUMP,			/* EINVAL	22	Invalid argument */
	DUMPANDLOG,		/* ENFILE	23	Too many open files in system */
	DUMPANDLOG,		/* EMFILE	24	Too many open files */
	DUMPANDLOG,		/* ENOTTY	25	Inappropriate ioctl for device */
	DUMPANDLOG,		/* ETXTBSY	26	Text file busy - POSIX */
	DUMP,			/* EFBIG	27	File too large */
	DUMP,			/* ENOSPC	28	No space left on device */
	DUMPANDLOG,		/* ESPIPE	29	Illegal seek */
	DUMP,			/* EROFS	30	Read-only file system */
	DUMP,			/* EMLINK	31	Too many links */
	RETRY,			/* EPIPE	32	Broken pipe */
	/* math software */
	DUMPANDLOG,		/* EDOM				33	Numerical argument out of domain */
	DUMPANDLOG,		/* ERANGE			34	Result too large */
	RETRY,			/* EAGAIN/EWOULDBLOCK	35	Resource temporarily unavailable */
	DUMPANDLOG,		/* EINPROGRESS		36	Operation now in progress */
	DUMPANDLOG,		/* EALREADY			37	Operation already in progress */
	/* ipc/network software -- argument errors */
	DUMPANDLOG,		/* ENOTSOC			38	Socket operation on non-socket */
	DUMPANDLOG,		/* EDESTADDRREQ		39	Destination address required */
	DUMPANDLOG,		/* EMSGSIZE			40	Message too long */
	DUMPANDLOG,		/* EPROTOTYPE		41	Protocol wrong type for socket */
	DUMPANDLOG,		/* ENOPROTOOPT		42	Protocol not available */
	DUMPANDLOG,		/* EPROTONOSUPPORT	43	Protocol not supported */
	DUMPANDLOG,		/* ESOCKTNOSUPPORT	44	Socket type not supported */
	DUMPANDLOG,		/* ENOTSUP			45	Operation not supported */
	DUMPANDLOG,		/* EPFNOSUPPORT		46	Protocol family not supported */
	DUMPANDLOG,		/* EAFNOSUPPORT		47	Address family not supported by protocol family */
	DUMPANDLOG,		/* EADDRINUSE		48	Address already in use */
	DUMPANDLOG,		/* EADDRNOTAVAIL	49	Can't assign requested address */
	/* ipc/network software -- operational errors */
	RETRY,			/* ENETDOWN			50	Network is down */
	RETRY,			/* ENETUNREACH		51	Network is unreachable */
	RETRY,			/* ENETRESET		52	Network dropped connection on reset */
	RETRY,			/* ECONNABORTED		53	Software caused connection abort */
	RETRY,			/* ECONNRESET		54	Connection reset by peer */
	RETRY,			/* ENOBUFS			55	No buffer space available */
	RETRY,			/* EISCONN			56	Socket is already connected */
	RETRY,			/* ENOTCONN			57	Socket is not connected */
	RETRY,			/* ESHUTDOWN		58	Can't send after socket shutdown */
	RETRY,			/* ETOOMANYREFS		59	Too many references: can't splice */
	RETRY,			/* ETIMEDOUT		60	Operation timed out */
	RETRY,			/* ECONNREFUSED		61	Connection refused */

	DUMPANDLOG,		/* ELOOP			62	Too many levels of symbolic links */
	DUMP,			/* ENAMETOOLONG		63	File name too long */
	RETRY,			/* EHOSTDOWN		64	Host is down */
	RETRY,			/* EHOSTUNREACH		65	No route to host */
	DUMP,			/* ENOTEMPTY		66	Directory not empty */
	/* quotas & mush */
	DUMPANDLOG,		/* PROCLIM			67	Too many processes */
	DUMPANDLOG,		/* EUSERS			68	Too many users */
	DUMPANDLOG,		/* EDQUOT			69	Disc quota exceeded */
	/* Network File System */
	DUMP,			/* ESTALE			70	Stale NFS file handle */
	DUMP,			/* EREMOTE			71	Too many levels of remote in path */
	DUMPANDLOG,		/* EBADRPC			72	RPC struct is bad */
	DUMPANDLOG,		/* ERPCMISMATCH		73	RPC version wrong */
	DUMPANDLOG,		/* EPROGUNAVAIL		74	RPC prog. not avail */
	DUMPANDLOG,		/* EPROGMISMATCH	75	Program version wrong */
	DUMPANDLOG,		/* EPROCUNAVAIL		76	Bad procedure for program */

	DUMPANDLOG,		/* ENOLCK			77	No locks available */
	DUMPANDLOG,		/* ENOSYS			78	Function not implemented */
	DUMPANDLOG,		/* EFTYPE			79	Inappropriate file type or format */
	DUMPANDLOG,		/* EAUTH			80	Authentication error */
	DUMPANDLOG,		/* ENEEDAUTH		81	Need authenticator */
	/* Intelligent device errors */
	DUMPANDLOG,		/* EPWROFF			82	Device power is off */
	DUMPANDLOG,		/* EDEVERR			83	Device error, e.g. paper out */
	DUMPANDLOG,		/* EOVERFLOW		84	Value too large to be stored in data type */
	/* Program loading errors */
	DUMPANDLOG,		/* EBADEXEC			85	Bad executable */
	DUMPANDLOG,		/* EBADARCH			86	Bad CPU type in executable */
	DUMPANDLOG,		/* ESHLIBVERS		87	Shared library version mismatch */
	DUMPANDLOG,		/* EBADMACHO		88	Malformed Macho file */
};

static char
nfs_pageouterrorhandler(int error)
{
	if (error > NFS_ELAST)
		return(DUMP);
	else
		return(errortooutcome[error]);
}


/*
 * vnode OP for pageout using UPL
 *
 * No buffer I/O, just RPCs straight from the mapped pages.
 * File size changes are not permitted in pageout.
 */
static int
nfs_vnop_pageout(
	struct vnop_pageout_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		upl_t a_pl;
		vm_offset_t a_pl_offset;
		off_t a_f_offset;
		size_t a_size;
		int a_flags;
		vfs_context_t a_context;
	} */ *ap)
{
	vnode_t vp = ap->a_vp;
	upl_t pl = ap->a_pl;
	size_t size = ap->a_size;
	off_t f_offset = ap->a_f_offset;
	vm_offset_t pl_offset = ap->a_pl_offset;
	int flags = ap->a_flags;
	nfsnode_t np = VTONFS(vp);
	thread_t thd;
	kauth_cred_t cred;
	struct nfsbuf *bp;
	struct nfsmount *nmp = VTONMP(vp);
	daddr64_t lbn;
	int error = 0, iomode;
	off_t off, txoffset, rxoffset;
	vm_offset_t ioaddr, txaddr, rxaddr;
	struct uio	auio;
	struct iovec_32	aiov;
	int nofreeupl = flags & UPL_NOCOMMIT;
	size_t nmwsize, biosize, iosize, pgsize, txsize, rxsize, xsize, remsize;
	struct nfsreq *req[MAXPAGINGREQS];
	int nextsend, nextwait, wverfset, commit, restart = 0;
	uint64_t wverf, wverf2;

	FSDBG(323, f_offset, size, pl, pl_offset);

	if (pl == (upl_t)NULL)
		panic("nfs_pageout: no upl");

	if (size <= 0) {
		printf("nfs_pageout: invalid size %ld", size);
		if (!nofreeupl)
			ubc_upl_abort(pl, 0);
		return (EINVAL);
	}

	if (!nmp) {
		if (!nofreeupl)
			ubc_upl_abort(pl, UPL_ABORT_DUMP_PAGES|UPL_ABORT_FREE_ON_EMPTY);
		return (ENXIO);
	}
	biosize = nmp->nm_biosize;
	nmwsize = nmp->nm_wsize;

	nfs_data_lock2(np, NFS_NODE_LOCK_SHARED, 0);

	/*
	 * Check to see whether the buffer is incore.
	 * If incore and not busy, invalidate it from the cache.
	 */
	for (iosize = 0; iosize < size; iosize += xsize) {
		off = f_offset + iosize;
		/* need make sure we do things on block boundaries */
		xsize = biosize - (off % biosize);
		if (off + xsize > f_offset + size)
			xsize = f_offset + size - off;
		lbn = (daddr64_t)(off / biosize);
		lck_mtx_lock(nfs_buf_mutex);
		if ((bp = nfs_buf_incore(np, lbn))) {
			FSDBG(323, off, bp, bp->nb_lflags, bp->nb_flags);
			if (nfs_buf_acquire(bp, NBAC_NOWAIT, 0, 0)) {
				lck_mtx_unlock(nfs_buf_mutex);
				nfs_data_unlock2(np, 0);
				/* no panic. just tell vm we are busy */
				if (!nofreeupl)
					ubc_upl_abort(pl, 0);
				return (EBUSY);
			}
			if (bp->nb_dirtyend > 0) {
				/*
				 * if there's a dirty range in the buffer, check
				 * to see if it extends beyond the pageout region
				 *
				 * if the dirty region lies completely within the
				 * pageout region, we just invalidate the buffer
				 * because it's all being written out now anyway.
				 *
				 * if any of the dirty region lies outside the
				 * pageout region, we'll try to clip the dirty
				 * region to eliminate the portion that's being
				 * paged out.  If that's not possible, because
				 * the dirty region extends before and after the
				 * pageout region, then we'll just return EBUSY.
				 */
				off_t boff, start, end;
				boff = NBOFF(bp);
				start = off;
				end = off + xsize;
				/* clip end to EOF */
				if (end > (off_t)np->n_size)
					end = np->n_size;
				start -= boff;
				end -= boff;
				if ((bp->nb_dirtyoff < start) &&
				    (bp->nb_dirtyend > end)) {
				    /* not gonna be able to clip the dirty region */
				    FSDBG(323, np, bp, 0xd00deebc, EBUSY);
				    nfs_buf_drop(bp);
				    lck_mtx_unlock(nfs_buf_mutex);
				    nfs_data_unlock2(np, 0);
				    if (!nofreeupl)
					ubc_upl_abort(pl, 0);
				    return (EBUSY);
				}
				if ((bp->nb_dirtyoff < start) ||
				    (bp->nb_dirtyend > end)) {
				    /* clip dirty region, if necessary */
				    if (bp->nb_dirtyoff < start)
					bp->nb_dirtyend = min(bp->nb_dirtyend, start);
				    if (bp->nb_dirtyend > end)
					bp->nb_dirtyoff = max(bp->nb_dirtyoff, end);
				    FSDBG(323, bp, bp->nb_dirtyoff, bp->nb_dirtyend, 0xd00dee00);
				    /* we're leaving this block dirty */
				    nfs_buf_drop(bp);
				    lck_mtx_unlock(nfs_buf_mutex);
				    continue;
				}
			}
			nfs_buf_remfree(bp);
			lck_mtx_unlock(nfs_buf_mutex);
			SET(bp->nb_flags, NB_INVAL);
			nfs_lock(np, NFS_NODE_LOCK_FORCE);
			if (ISSET(bp->nb_flags, NB_NEEDCOMMIT)) {
				CLR(bp->nb_flags, NB_NEEDCOMMIT);
				np->n_needcommitcnt--;
				CHECK_NEEDCOMMITCNT(np);
			}
			nfs_unlock(np);
			nfs_buf_release(bp, 1);
		} else {
			lck_mtx_unlock(nfs_buf_mutex);
		}
	}

	thd = vfs_context_thread(ap->a_context);
	cred = ubc_getcred(vp);
	if (!IS_VALID_CRED(cred))
		cred = vfs_context_ucred(ap->a_context);

	nfs_lock(np, NFS_NODE_LOCK_FORCE);
	if (np->n_flag & NWRITEERR) {
		error = np->n_error;
		nfs_unlock(np);
		nfs_data_unlock2(np, 0);
		if (!nofreeupl)
			ubc_upl_abort_range(pl, pl_offset, size,
					    UPL_ABORT_FREE_ON_EMPTY);
		return (error);
	}
	nfs_unlock(np);

	if (f_offset < 0 || f_offset >= (off_t)np->n_size ||
	    f_offset & PAGE_MASK_64 || size & PAGE_MASK_64) {
		nfs_data_unlock2(np, 0);
		if (!nofreeupl)
			ubc_upl_abort_range(pl, pl_offset, size,
					    UPL_ABORT_FREE_ON_EMPTY);
		return (EINVAL);
	}

	ubc_upl_map(pl, &ioaddr);
	ioaddr += pl_offset;

	if ((u_quad_t)f_offset + size > np->n_size)
		xsize = np->n_size - f_offset;
	else
		xsize = size;

	pgsize = round_page_64(xsize);
	if ((size > pgsize) && !nofreeupl)
		ubc_upl_abort_range(pl, pl_offset + pgsize, size - pgsize,
				    UPL_ABORT_FREE_ON_EMPTY);

	/*
	 * check for partial page and clear the
	 * contents past end of the file before
	 * releasing it in the VM page cache
	 */
	if ((u_quad_t)f_offset < np->n_size && (u_quad_t)f_offset + size > np->n_size) {
		size_t io = np->n_size - f_offset;
		bzero((caddr_t)(ioaddr + io), size - io);
		FSDBG(321, np->n_size, f_offset, f_offset + io, size - io);
	}
	nfs_data_unlock2(np, 0);

#if 1   /* LP64todo - can't use new segment flags until the drivers are ready */
	auio.uio_segflg = UIO_SYSSPACE;
#else
	auio.uio_segflg = UIO_SYSSPACE32;
#endif
	auio.uio_rw = UIO_WRITE;
	auio.uio_procp = vfs_context_proc(ap->a_context);

tryagain:
	wverf = wverf2 = wverfset = 0;
	txsize = rxsize = xsize;
	txoffset = rxoffset = f_offset;
	txaddr = rxaddr = ioaddr;
	commit = NFS_WRITE_FILESYNC;

	bzero(req, sizeof(req));
	nextsend = nextwait = 0;
	do {
		/* send requests while we need to and have available slots */
		while ((txsize > 0) && (req[nextsend] == NULL)) {
			iosize = MIN(nmwsize, txsize);
			aiov.iov_len = iosize;
			aiov.iov_base = (uintptr_t)txaddr;
			auio.uio_iovs.iov32p = &aiov;
			auio.uio_iovcnt = 1;
			auio.uio_offset = txoffset;
			uio_uio_resid_set(&auio, iosize);
			FSDBG(323, auio.uio_offset, iosize, txaddr, txsize);
			OSAddAtomic(1, (SInt32*)&nfsstats.pageouts);
			vnode_startwrite(vp);
			iomode = NFS_WRITE_UNSTABLE;
			if ((error = nmp->nm_funcs->nf_write_rpc_async(np, &auio, iosize, thd, cred, iomode, NULL, &req[nextsend]))) {
				req[nextsend] = NULL;
				vnode_writedone(vp);
				break;
			}
			txaddr += iosize;
			txoffset += iosize;
			txsize -= iosize;
			nextsend = (nextsend + 1) % MAXPAGINGREQS;
		}
		/* wait while we need to and break out if more requests to send */
		while ((rxsize > 0) && req[nextwait]) {
			iosize = remsize = MIN(nmwsize, rxsize);
			error = nmp->nm_funcs->nf_write_rpc_async_finish(np, req[nextwait], &iomode, &iosize, &wverf2);
			req[nextwait] = NULL;
			nextwait = (nextwait + 1) % MAXPAGINGREQS;
			vnode_writedone(vp);
			if (error) {
				FSDBG(323, rxoffset, rxsize, error, -1);
				break;
			}
			if (!wverfset) {
				wverf = wverf2;
				wverfset = 1;
			} else if (wverf != wverf2) {
				/* verifier changed, so we need to restart all the writes */
				restart++;
				goto cancel;
			}
			/* Retain the lowest commitment level returned. */
			if (iomode < commit)
				commit = iomode;
			rxaddr += iosize;	
			rxoffset += iosize;	
			rxsize -= iosize;
			remsize -= iosize;
			if (remsize > 0) {
				/* need to try sending the remainder */
				iosize = remsize;
				aiov.iov_len = remsize;
				aiov.iov_base = (uintptr_t)rxaddr;
				auio.uio_iovs.iov32p = &aiov;
				auio.uio_iovcnt = 1;
				auio.uio_offset = rxoffset;
				uio_uio_resid_set(&auio, remsize);
				iomode = NFS_WRITE_UNSTABLE;
				error = nfs_write_rpc2(np, &auio, thd, cred, &iomode, &wverf2);
				if (error) {
					FSDBG(323, rxoffset, rxsize, error, -1);
					break;
				}
				if (wverf != wverf2) {
					/* verifier changed, so we need to restart all the writes */
					restart++;
					goto cancel;
				}
				if (iomode < commit)
					commit = iomode;
				rxaddr += iosize;	
				rxoffset += iosize;	
				rxsize -= iosize;
			}
			if (txsize)
				break;
		}
	} while (!error && (txsize || rxsize));

	restart = 0;

	if (!error && (commit != NFS_WRITE_FILESYNC)) {
		error = nmp->nm_funcs->nf_commit_rpc(np, f_offset, xsize, cred);
		if (error == NFSERR_STALEWRITEVERF) {
			restart++;
			error = EIO;
		}
	}

	if (error) {
cancel:
		/* cancel any outstanding requests */
		while (req[nextwait]) {
			nfs_request_async_cancel(req[nextwait]);
			req[nextwait] = NULL;
			nextwait = (nextwait + 1) % MAXPAGINGREQS;
			vnode_writedone(vp);
		}
		if (restart) {
			if (restart <= 10)
				goto tryagain;
			printf("nfs_pageout: too many restarts, aborting.\n");
			FSDBG(323, f_offset, xsize, ERESTART, -1);
		}
	}

	ubc_upl_unmap(pl);

	/*
	 * We've had several different solutions on what to do when the pageout
	 * gets an error. If we don't handle it, and return an error to the
	 * caller, vm, it will retry . This can end in endless looping
	 * between vm and here doing retries of the same page. Doing a dump
	 * back to vm, will get it out of vm's knowledge and we lose whatever
	 * data existed. This is risky, but in some cases necessary. For
	 * example, the initial fix here was to do that for ESTALE. In that case
	 * the server is telling us that the file is no longer the same. We
	 * would not want to keep paging out to that. We also saw some 151
	 * errors from Auspex server and NFSv3 can return errors higher than
	 * ELAST. Those along with NFS known server errors we will "dump" from
	 * vm.  Errors we don't expect to occur, we dump and log for further
	 * analysis. Errors that could be transient, networking ones,
	 * we let vm "retry". Lastly, errors that we retry, but may have potential
	 * to storm the network, we "retrywithsleep". "sever" will be used in
	 * in the future to dump all pages of object for cases like ESTALE.
	 * All this is the basis for the states returned and first guesses on
	 * error handling. Tweaking expected as more statistics are gathered.
	 * Note, in the long run we may need another more robust solution to
	 * have some kind of persistant store when the vm cannot dump nor keep
	 * retrying as a solution, but this would be a file architectural change
	 */
	if (!nofreeupl) { /* otherwise stacked file system has to handle this */
		if (error) {
			int abortflags = 0;
			char action = nfs_pageouterrorhandler(error);
			
			switch (action) {
				case DUMP:
					abortflags = UPL_ABORT_DUMP_PAGES|UPL_ABORT_FREE_ON_EMPTY;
					break;
				case DUMPANDLOG:
					abortflags = UPL_ABORT_DUMP_PAGES|UPL_ABORT_FREE_ON_EMPTY;
					if (error <= NFS_ELAST) {
						if ((errorcount[error] % 100) == 0)
							printf("nfs_pageout: unexpected error %d. dumping vm page\n", error);
						errorcount[error]++;
					}
					break;
				case RETRY:
					abortflags = UPL_ABORT_FREE_ON_EMPTY;
					break;
				case RETRYWITHSLEEP:
					abortflags = UPL_ABORT_FREE_ON_EMPTY;
					/* pri unused. PSOCK for placeholder. */
					tsleep(&lbolt, PSOCK, "nfspageout", 0);
					break;
				case SEVER: /* not implemented */
				default:
					printf("nfs_pageout: action %d not expected\n", action);
					break;
			}

			ubc_upl_abort_range(pl, pl_offset, pgsize, abortflags);
			/* return error in all cases above */

		} else {
			ubc_upl_commit_range(pl, pl_offset, pgsize,
					     UPL_COMMIT_CLEAR_DIRTY |
					     UPL_COMMIT_FREE_ON_EMPTY);
		}
	}
	return (error);
}

/* Blktooff derives file offset given a logical block number */
static int
nfs_vnop_blktooff(
	struct vnop_blktooff_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		daddr64_t a_lblkno;
		off_t *a_offset;
	} */ *ap)
{
	int biosize;
	vnode_t vp = ap->a_vp;
	struct nfsmount *nmp = VTONMP(vp);

	if (!nmp)
		return (ENXIO);
	biosize = nmp->nm_biosize;

	*ap->a_offset = (off_t)(ap->a_lblkno * biosize);

	return (0);
}

static int
nfs_vnop_offtoblk(
	struct vnop_offtoblk_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		off_t a_offset;
		daddr64_t *a_lblkno;
	} */ *ap)
{
	int biosize;
	vnode_t vp = ap->a_vp;
	struct nfsmount *nmp = VTONMP(vp);

	if (!nmp)
		return (ENXIO);
	biosize = nmp->nm_biosize;

	*ap->a_lblkno = (daddr64_t)(ap->a_offset / biosize);

	return (0);
}

