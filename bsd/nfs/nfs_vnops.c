/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/buf.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/conf.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/dirent.h>
#include <sys/fcntl.h>
#include <sys/lockf.h>
#include <sys/ubc.h>

#include <ufs/ufs/dir.h>
#include <vfs/vfs_support.h>

#include <sys/vm.h>
#include <machine/spl.h>
#include <vm/vm_pageout.h>

#include <sys/time.h> 
#include <kern/clock.h>

#include <miscfs/fifofs/fifo.h>
#include <miscfs/specfs/specdev.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfsnode.h>
#include <nfs/nfsmount.h>
#include <nfs/xdr_subs.h>
#include <nfs/nfsm_subs.h>
#include <nfs/nqnfs.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <kern/task.h>
#include <vm/vm_kern.h>

#include <sys/kdebug.h>

#define	TRUE	1
#define	FALSE	0

static int	nfsspec_read __P((struct vop_read_args *));
static int	nfsspec_write __P((struct vop_write_args *));
static int	nfsfifo_read __P((struct vop_read_args *));
static int	nfsfifo_write __P((struct vop_write_args *));
static int	nfsspec_close __P((struct vop_close_args *));
static int	nfsfifo_close __P((struct vop_close_args *));
#define nfs_poll vop_nopoll
static int	nfs_ioctl __P((struct vop_ioctl_args *));
static int	nfs_select __P((struct vop_select_args *));
static int	nfs_flush __P((struct vnode *,struct ucred *,int,struct proc *,int));
static int	nfs_setattrrpc __P((struct vnode *,struct vattr *,struct ucred *,struct proc *));
static	int	nfs_lookup __P((struct vop_lookup_args *));
static	int	nfs_create __P((struct vop_create_args *));
static	int	nfs_mknod __P((struct vop_mknod_args *));
static	int	nfs_open __P((struct vop_open_args *));
static	int	nfs_close __P((struct vop_close_args *));
static	int	nfs_access __P((struct vop_access_args *));
static	int	nfs_getattr __P((struct vop_getattr_args *));
static	int	nfs_setattr __P((struct vop_setattr_args *));
static	int	nfs_read __P((struct vop_read_args *));
static	int	nfs_mmap __P((struct vop_mmap_args *));
static	int	nfs_fsync __P((struct vop_fsync_args *));
static	int	nfs_remove __P((struct vop_remove_args *));
static	int	nfs_link __P((struct vop_link_args *));
static	int	nfs_rename __P((struct vop_rename_args *));
static	int	nfs_mkdir __P((struct vop_mkdir_args *));
static	int	nfs_rmdir __P((struct vop_rmdir_args *));
static	int	nfs_symlink __P((struct vop_symlink_args *));
static	int	nfs_readdir __P((struct vop_readdir_args *));
static	int	nfs_bmap __P((struct vop_bmap_args *));
static	int	nfs_strategy __P((struct vop_strategy_args *));
static	int	nfs_lookitup __P((struct vnode *,char *,int,struct ucred *,struct proc *,struct nfsnode **));
static	int	nfs_sillyrename __P((struct vnode *,struct vnode *,struct componentname *));
static int	nfsspec_access __P((struct vop_access_args *));
static int	nfs_readlink __P((struct vop_readlink_args *));
static int	nfs_print __P((struct vop_print_args *));
static int	nfs_pathconf __P((struct vop_pathconf_args *));
static int	nfs_advlock __P((struct vop_advlock_args *));
static int	nfs_blkatoff __P((struct vop_blkatoff_args *));
static int	nfs_bwrite __P((struct vop_bwrite_args *));
static int	nfs_valloc __P((struct vop_valloc_args *));
static int	nfs_vfree __P((struct vop_vfree_args *));
static int	nfs_truncate __P((struct vop_truncate_args *));
static int	nfs_update __P((struct vop_update_args *));
static	int	nfs_pagein __P((struct vop_pagein_args *));
static	int	nfs_pageout __P((struct vop_pageout_args *));
static	int nfs_blktooff __P((struct vop_blktooff_args *));
static	int nfs_offtoblk __P((struct vop_offtoblk_args *));
static	int nfs_cmap __P((struct vop_cmap_args *));

/*
 * Global vfs data structures for nfs
 */
vop_t **nfsv2_vnodeop_p;
static struct vnodeopv_entry_desc nfsv2_vnodeop_entries[] = {
	{ &vop_default_desc, (vop_t *)vn_default_error },
	{ &vop_lookup_desc, (vop_t *)nfs_lookup },	/* lookup */
	{ &vop_create_desc, (vop_t *)nfs_create },	/* create */
	{ &vop_mknod_desc, (vop_t *)nfs_mknod },	/* mknod */
	{ &vop_open_desc, (vop_t *)nfs_open },		/* open */
	{ &vop_close_desc, (vop_t *)nfs_close },	/* close */
	{ &vop_access_desc, (vop_t *)nfs_access },	/* access */
	{ &vop_getattr_desc, (vop_t *)nfs_getattr },	/* getattr */
	{ &vop_setattr_desc, (vop_t *)nfs_setattr },	/* setattr */
	{ &vop_read_desc, (vop_t *)nfs_read },		/* read */
	{ &vop_write_desc, (vop_t *)nfs_write },	/* write */
	{ &vop_lease_desc, (vop_t *)nfs_lease_check },	/* lease */
	{ &vop_ioctl_desc, (vop_t *)nfs_ioctl },	/* ioctl */
	{ &vop_select_desc, (vop_t *)nfs_select },	/* select */
	{ &vop_revoke_desc, (vop_t *)nfs_revoke },	/* revoke */
	{ &vop_mmap_desc, (vop_t *)nfs_mmap },		/* mmap */
	{ &vop_fsync_desc, (vop_t *)nfs_fsync },	/* fsync */
	{ &vop_seek_desc, (vop_t *)nfs_seek },		/* seek */
	{ &vop_remove_desc, (vop_t *)nfs_remove },	/* remove */
	{ &vop_link_desc, (vop_t *)nfs_link },		/* link */
	{ &vop_rename_desc, (vop_t *)nfs_rename },	/* rename */
	{ &vop_mkdir_desc, (vop_t *)nfs_mkdir },	/* mkdir */
	{ &vop_rmdir_desc, (vop_t *)nfs_rmdir },	/* rmdir */
	{ &vop_symlink_desc, (vop_t *)nfs_symlink },	/* symlink */
	{ &vop_readdir_desc, (vop_t *)nfs_readdir },	/* readdir */
	{ &vop_readlink_desc, (vop_t *)nfs_readlink },	/* readlink */
	{ &vop_abortop_desc, (vop_t *)nfs_abortop },	/* abortop */
	{ &vop_inactive_desc, (vop_t *)nfs_inactive },	/* inactive */
	{ &vop_reclaim_desc, (vop_t *)nfs_reclaim },	/* reclaim */
	{ &vop_lock_desc, (vop_t *)nfs_lock },		/* lock */
	{ &vop_unlock_desc, (vop_t *)nfs_unlock },	/* unlock */
	{ &vop_bmap_desc, (vop_t *)nfs_bmap },		/* bmap */
	{ &vop_strategy_desc, (vop_t *)nfs_strategy },	/* strategy */
	{ &vop_print_desc, (vop_t *)nfs_print },	/* print */
	{ &vop_islocked_desc, (vop_t *)nfs_islocked },	/* islocked */
	{ &vop_pathconf_desc, (vop_t *)nfs_pathconf },	/* pathconf */
	{ &vop_advlock_desc, (vop_t *)nfs_advlock },	/* advlock */
	{ &vop_blkatoff_desc, (vop_t *)nfs_blkatoff },	/* blkatoff */
	{ &vop_valloc_desc, (vop_t *)nfs_valloc },	/* valloc */
	{ &vop_reallocblks_desc, (vop_t *)nfs_reallocblks },	/* reallocblks */
	{ &vop_vfree_desc, (vop_t *)nfs_vfree },	/* vfree */
	{ &vop_truncate_desc, (vop_t *)nfs_truncate },	/* truncate */
	{ &vop_update_desc, (vop_t *)nfs_update },	/* update */
	{ &vop_bwrite_desc, (vop_t *)nfs_bwrite },	/* bwrite */
	{ &vop_pagein_desc, (vop_t *)nfs_pagein },		/* Pagein */
	{ &vop_pageout_desc, (vop_t *)nfs_pageout },		/* Pageout */
	{ &vop_copyfile_desc, (vop_t *)err_copyfile },		/* Copyfile */
	{ &vop_blktooff_desc, (vop_t *)nfs_blktooff },		/* blktooff */
	{ &vop_offtoblk_desc, (vop_t *)nfs_offtoblk },		/* offtoblk */
	{ &vop_cmap_desc, (vop_t *)nfs_cmap },		/* cmap */
	{ NULL, NULL }
};
struct vnodeopv_desc nfsv2_vnodeop_opv_desc =
	{ &nfsv2_vnodeop_p, nfsv2_vnodeop_entries };
#ifdef __FreeBSD__
VNODEOP_SET(nfsv2_vnodeop_opv_desc);
#endif

/*
 * Special device vnode ops
 */
vop_t **spec_nfsv2nodeop_p;
static struct vnodeopv_entry_desc spec_nfsv2nodeop_entries[] = {
	{ &vop_default_desc, (vop_t *)vn_default_error },
	{ &vop_lookup_desc, (vop_t *)spec_lookup },	/* lookup */
	{ &vop_create_desc, (vop_t *)spec_create },	/* create */
	{ &vop_mknod_desc, (vop_t *)spec_mknod },	/* mknod */
	{ &vop_open_desc, (vop_t *)spec_open },		/* open */
	{ &vop_close_desc, (vop_t *)nfsspec_close },	/* close */
	{ &vop_access_desc, (vop_t *)nfsspec_access },	/* access */
	{ &vop_getattr_desc, (vop_t *)nfs_getattr },	/* getattr */
	{ &vop_setattr_desc, (vop_t *)nfs_setattr },	/* setattr */
	{ &vop_read_desc, (vop_t *)nfsspec_read },	/* read */
	{ &vop_write_desc, (vop_t *)nfsspec_write },	/* write */
	{ &vop_lease_desc, (vop_t *)spec_lease_check },	/* lease */
	{ &vop_ioctl_desc, (vop_t *)spec_ioctl },	/* ioctl */
	{ &vop_select_desc, (vop_t *)spec_select },	/* select */
	{ &vop_revoke_desc, (vop_t *)spec_revoke },	/* revoke */
	{ &vop_mmap_desc, (vop_t *)spec_mmap },		/* mmap */
	{ &vop_fsync_desc, (vop_t *)nfs_fsync },	/* fsync */
	{ &vop_seek_desc, (vop_t *)spec_seek },		/* seek */
	{ &vop_remove_desc, (vop_t *)spec_remove },	/* remove */
	{ &vop_link_desc, (vop_t *)spec_link },		/* link */
	{ &vop_rename_desc, (vop_t *)spec_rename },	/* rename */
	{ &vop_mkdir_desc, (vop_t *)spec_mkdir },	/* mkdir */
	{ &vop_rmdir_desc, (vop_t *)spec_rmdir },	/* rmdir */
	{ &vop_symlink_desc, (vop_t *)spec_symlink },	/* symlink */
	{ &vop_readdir_desc, (vop_t *)spec_readdir },	/* readdir */
	{ &vop_readlink_desc, (vop_t *)spec_readlink },	/* readlink */
	{ &vop_abortop_desc, (vop_t *)spec_abortop },	/* abortop */
	{ &vop_inactive_desc, (vop_t *)nfs_inactive },	/* inactive */
	{ &vop_reclaim_desc, (vop_t *)nfs_reclaim },	/* reclaim */
	{ &vop_lock_desc, (vop_t *)nfs_lock },		/* lock */
	{ &vop_unlock_desc, (vop_t *)nfs_unlock },	/* unlock */
	{ &vop_bmap_desc, (vop_t *)spec_bmap },		/* bmap */
	{ &vop_strategy_desc, (vop_t *)spec_strategy },	/* strategy */
	{ &vop_print_desc, (vop_t *)nfs_print },	/* print */
	{ &vop_islocked_desc, (vop_t *)nfs_islocked },	/* islocked */
	{ &vop_pathconf_desc, (vop_t *)spec_pathconf },	/* pathconf */
	{ &vop_advlock_desc, (vop_t *)spec_advlock },	/* advlock */
	{ &vop_blkatoff_desc, (vop_t *)spec_blkatoff },	/* blkatoff */
	{ &vop_valloc_desc, (vop_t *)spec_valloc },	/* valloc */
	{ &vop_reallocblks_desc, (vop_t *)spec_reallocblks },	/* reallocblks */
	{ &vop_vfree_desc, (vop_t *)spec_vfree },	/* vfree */
	{ &vop_truncate_desc, (vop_t *)spec_truncate },	/* truncate */
	{ &vop_update_desc, (vop_t *)nfs_update },	/* update */
	{ &vop_bwrite_desc, (vop_t *)vn_bwrite },	/* bwrite */
	{ &vop_devblocksize_desc, (vop_t *)spec_devblocksize },  /* devblocksize */
	{ &vop_pagein_desc, (vop_t *)nfs_pagein },		/* Pagein */
	{ &vop_pageout_desc, (vop_t *)nfs_pageout },		/* Pageout */
	{ &vop_blktooff_desc, (vop_t *)nfs_blktooff },		/* blktooff */
	{ &vop_offtoblk_desc, (vop_t *)nfs_offtoblk },		/* offtoblk */
	{ &vop_cmap_desc, (vop_t *)nfs_cmap },		/* cmap */
	{ NULL, NULL }
};
struct vnodeopv_desc spec_nfsv2nodeop_opv_desc =
	{ &spec_nfsv2nodeop_p, spec_nfsv2nodeop_entries };
#ifdef __FreeBSD__
VNODEOP_SET(spec_nfsv2nodeop_opv_desc);
#endif

vop_t **fifo_nfsv2nodeop_p;
static struct vnodeopv_entry_desc fifo_nfsv2nodeop_entries[] = {
	{ &vop_default_desc, (vop_t *)vn_default_error },
	{ &vop_lookup_desc, (vop_t *)fifo_lookup },	/* lookup */
	{ &vop_create_desc, (vop_t *)fifo_create },	/* create */
	{ &vop_mknod_desc, (vop_t *)fifo_mknod },	/* mknod */
	{ &vop_open_desc, (vop_t *)fifo_open },		/* open */
	{ &vop_close_desc, (vop_t *)nfsfifo_close },	/* close */
	{ &vop_access_desc, (vop_t *)nfsspec_access },	/* access */
	{ &vop_getattr_desc, (vop_t *)nfs_getattr },	/* getattr */
	{ &vop_setattr_desc, (vop_t *)nfs_setattr },	/* setattr */
	{ &vop_read_desc, (vop_t *)nfsfifo_read },	/* read */
	{ &vop_write_desc, (vop_t *)nfsfifo_write },	/* write */
	{ &vop_lease_desc, (vop_t *)fifo_lease_check },	/* lease */
	{ &vop_ioctl_desc, (vop_t *)fifo_ioctl },	/* ioctl */
	{ &vop_select_desc, (vop_t *)fifo_select },	/* select */
	{ &vop_revoke_desc, (vop_t *)fifo_revoke },	/* revoke */
	{ &vop_mmap_desc, (vop_t *)fifo_mmap },		/* mmap */
	{ &vop_fsync_desc, (vop_t *)nfs_fsync },	/* fsync */
	{ &vop_seek_desc, (vop_t *)fifo_seek },		/* seek */
	{ &vop_remove_desc, (vop_t *)fifo_remove },	/* remove */
	{ &vop_link_desc, (vop_t *)fifo_link },		/* link */
	{ &vop_rename_desc, (vop_t *)fifo_rename },	/* rename */
	{ &vop_mkdir_desc, (vop_t *)fifo_mkdir },	/* mkdir */
	{ &vop_rmdir_desc, (vop_t *)fifo_rmdir },	/* rmdir */
	{ &vop_symlink_desc, (vop_t *)fifo_symlink },	/* symlink */
	{ &vop_readdir_desc, (vop_t *)fifo_readdir },	/* readdir */
	{ &vop_readlink_desc, (vop_t *)fifo_readlink },	/* readlink */
	{ &vop_abortop_desc, (vop_t *)fifo_abortop },	/* abortop */
	{ &vop_inactive_desc, (vop_t *)nfs_inactive },	/* inactive */
	{ &vop_reclaim_desc, (vop_t *)nfs_reclaim },	/* reclaim */
	{ &vop_lock_desc, (vop_t *)nfs_lock },		/* lock */
	{ &vop_unlock_desc, (vop_t *)nfs_unlock },	/* unlock */
	{ &vop_bmap_desc, (vop_t *)fifo_bmap },		/* bmap */
	{ &vop_strategy_desc, (vop_t *)fifo_strategy },	/* strategy */
	{ &vop_print_desc, (vop_t *)nfs_print },	/* print */
	{ &vop_islocked_desc, (vop_t *)nfs_islocked },	/* islocked */
	{ &vop_pathconf_desc, (vop_t *)fifo_pathconf },	/* pathconf */
	{ &vop_advlock_desc, (vop_t *)fifo_advlock },	/* advlock */
	{ &vop_blkatoff_desc, (vop_t *)fifo_blkatoff },	/* blkatoff */
	{ &vop_valloc_desc, (vop_t *)fifo_valloc },	/* valloc */
	{ &vop_reallocblks_desc, (vop_t *)fifo_reallocblks },	/* reallocblks */
	{ &vop_vfree_desc, (vop_t *)fifo_vfree },	/* vfree */
	{ &vop_truncate_desc, (vop_t *)fifo_truncate },	/* truncate */
	{ &vop_update_desc, (vop_t *)nfs_update },	/* update */
	{ &vop_bwrite_desc, (vop_t *)vn_bwrite },	/* bwrite */
	{ &vop_pagein_desc, (vop_t *)nfs_pagein },		/* Pagein */
	{ &vop_pageout_desc, (vop_t *)nfs_pageout },		/* Pageout */
	{ &vop_blktooff_desc, (vop_t *)nfs_blktooff },		/* blktooff */
	{ &vop_offtoblk_desc, (vop_t *)nfs_offtoblk },		/* offtoblk */
	{ &vop_cmap_desc, (vop_t *)nfs_cmap },		/* cmap */
	{ NULL, NULL }
};
struct vnodeopv_desc fifo_nfsv2nodeop_opv_desc =
	{ &fifo_nfsv2nodeop_p, fifo_nfsv2nodeop_entries };
#ifdef __FreeBSD__
VNODEOP_SET(fifo_nfsv2nodeop_opv_desc);
#endif

static int	nfs_commit __P((struct vnode *vp, u_quad_t offset, int cnt,
				struct ucred *cred, struct proc *procp));
static int	nfs_mknodrpc __P((struct vnode *dvp, struct vnode **vpp,
				  struct componentname *cnp,
				  struct vattr *vap));
static int	nfs_removerpc __P((struct vnode *dvp, char *name, int namelen,
				   struct ucred *cred, struct proc *proc));
static int	nfs_renamerpc __P((struct vnode *fdvp, char *fnameptr,
				   int fnamelen, struct vnode *tdvp,
				   char *tnameptr, int tnamelen,
				   struct ucred *cred, struct proc *proc));
static int	nfs_renameit __P((struct vnode *sdvp,
				  struct componentname *scnp,
				  struct sillyrename *sp));

/*
 * Global variables
 */
extern u_long nfs_true, nfs_false;
extern struct nfsstats nfsstats;
extern nfstype nfsv3_type[9];
struct proc *nfs_iodwant[NFS_MAXASYNCDAEMON];
struct nfsmount *nfs_iodmount[NFS_MAXASYNCDAEMON];
int nfs_numasync = 0;
#define	DIRHDSIZ	(sizeof (struct dirent) - (MAXNAMLEN + 1))

static int	nfsaccess_cache_timeout = NFS_MAXATTRTIMO;
/* SYSCTL_INT(_vfs_nfs, OID_AUTO, access_cache_timeout, CTLFLAG_RW,
           &nfsaccess_cache_timeout, 0, "NFS ACCESS cache timeout");
*/
#define	NFSV3ACCESS_ALL (NFSV3ACCESS_READ | NFSV3ACCESS_MODIFY		\
			 | NFSV3ACCESS_EXTEND | NFSV3ACCESS_EXECUTE	\
			 | NFSV3ACCESS_DELETE | NFSV3ACCESS_LOOKUP)
                         

/* 
 * the following are needed only by nfs_pageout to know how to handle errors
 * see nfs_pageout comments on explanation of actions.
 * the errors here are copied from errno.h and errors returned by servers
 * are expected to match the same numbers here. If not, our actions maybe
 * erroneous.
 */
enum actiontype {NOACTION, DUMP, DUMPANDLOG, RETRY, RETRYWITHSLEEP, SEVER};

static int errorcount[ELAST+1]; /* better be zeros when initialized */

static const short errortooutcome[ELAST+1] = {
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


static short
nfs_pageouterrorhandler(error)
	int error;
{
	if (error > ELAST) 
		return(DUMP);
	else 
		return(errortooutcome[error]);
}

static int
nfs3_access_otw(struct vnode *vp,  
		int wmode,
		struct proc *p,
		struct ucred *cred)  
{
	const int v3 = 1;
	u_int32_t *tl;
	int error = 0, attrflag;

	struct mbuf *mreq, *mrep, *md, *mb, *mb2;
	caddr_t bpos, dpos, cp2;
	register int32_t t1, t2;
	register caddr_t cp;
	u_int32_t rmode;
	struct nfsnode *np = VTONFS(vp);

	nfsstats.rpccnt[NFSPROC_ACCESS]++;   
	nfsm_reqhead(vp, NFSPROC_ACCESS, NFSX_FH(v3) + NFSX_UNSIGNED);
	nfsm_fhtom(vp, v3);
	nfsm_build(tl, u_int32_t *, NFSX_UNSIGNED);
	*tl = txdr_unsigned(wmode);
	nfsm_request(vp, NFSPROC_ACCESS, p, cred);
	nfsm_postop_attr(vp, attrflag);
	if (!error) {
		nfsm_dissect(tl, u_int32_t *, NFSX_UNSIGNED);
		rmode = fxdr_unsigned(u_int32_t, *tl);
		np->n_mode = rmode;
		np->n_modeuid = cred->cr_uid;
		np->n_modestamp = time_second;
		}
	nfsm_reqdone;
	return error;
}

/*
 * nfs access vnode op.
 * For nfs version 2, just return ok. File accesses may fail later.
 * For nfs version 3, use the access rpc to check accessibility. If file modes
 * are changed on the server, accesses might still fail later.
 */
static int
nfs_access(ap)
	struct vop_access_args /* {
		struct vnode *a_vp;
		int  a_mode;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	int error = 0;
	u_long mode, wmode;
	int v3 = NFS_ISV3(vp);
	struct nfsnode *np = VTONFS(vp);

	/*
	 * For nfs v3, do an access rpc, otherwise you are stuck emulating
	 * ufs_access() locally using the vattr. This may not be correct,
	 * since the server may apply other access criteria such as
	 * client uid-->server uid mapping that we do not know about, but
	 * this is better than just returning anything that is lying about
	 * in the cache.
	 */
	if (v3) {
		if (ap->a_mode & VREAD)
			mode = NFSV3ACCESS_READ;
		else
			mode = 0;
		if (vp->v_type == VDIR) {
			if (ap->a_mode & VWRITE)
				mode |= (NFSV3ACCESS_MODIFY | NFSV3ACCESS_EXTEND |
					 NFSV3ACCESS_DELETE);
			if (ap->a_mode & VEXEC)
				mode |= NFSV3ACCESS_LOOKUP;
		} else {
			if (ap->a_mode & VWRITE)
				mode |= (NFSV3ACCESS_MODIFY | NFSV3ACCESS_EXTEND);
			if (ap->a_mode & VEXEC)
				mode |= NFSV3ACCESS_EXECUTE;
		}
		/* XXX safety belt, only make blanket request if caching */
		if (nfsaccess_cache_timeout > 0) {
			wmode = NFSV3ACCESS_READ | NFSV3ACCESS_MODIFY |
					NFSV3ACCESS_EXTEND | NFSV3ACCESS_EXECUTE |
					NFSV3ACCESS_DELETE | NFSV3ACCESS_LOOKUP;
		} else
			wmode = mode;
                
		/*
		 * Does our cached result allow us to give a definite yes to
		 * this request?
		 */     
		if ((time_second < (np->n_modestamp + nfsaccess_cache_timeout)) &&
			(ap->a_cred->cr_uid == np->n_modeuid) &&
			((np->n_mode & mode) == mode)) {
			/* nfsstats.accesscache_hits++; */
		} else {
			/*
			 * Either a no, or a don't know.  Go to the wire.
			 */
			/* nfsstats.accesscache_misses++; */
			error = nfs3_access_otw(vp, wmode, ap->a_p,ap->a_cred);
			if (!error) {
				if ((np->n_mode & mode) != mode)
					error = EACCES;
					}
				}
	} else
		return (nfsspec_access(ap)); /* NFSv2 case checks for EROFS here */
	/*
	 * Disallow write attempts on filesystems mounted read-only;
	 * unless the file is a socket, fifo, or a block or character
	 * device resident on the filesystem.
	 * CSM - moved EROFS check down per NetBSD rev 1.71.  So you
	 * get the correct error value with layered filesystems. 
	 * EKN - moved the return(error) below this so it does get called.	 
	 */
	if (!error && (ap->a_mode & VWRITE) && (vp->v_mount->mnt_flag & MNT_RDONLY)) {
		switch (vp->v_type) {
			case VREG: case VDIR: case VLNK:
				error = EROFS;
			default: 
				break;
			}
		}
	return (error);
}

/*
 * nfs open vnode op
 * Check to see if the type is ok
 * and that deletion is not in progress.
 * For paged in text files, you will need to flush the page cache
 * if consistency is lost.
 */
/* ARGSUSED */
static int
nfs_open(ap)
	struct vop_open_args /* {
		struct vnode *a_vp;
		int  a_mode;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	struct nfsnode *np = VTONFS(vp);
	struct nfsmount *nmp = VFSTONFS(vp->v_mount);
	struct vattr vattr;
	int error;

	if (vp->v_type != VREG && vp->v_type != VDIR && vp->v_type != VLNK)
{ printf("open eacces vtyp=%d\n",vp->v_type);
		return (EACCES);
}
	/*
	 * Get a valid lease. If cached data is stale, flush it.
	 */
	if (nmp->nm_flag & NFSMNT_NQNFS) {
		if (NQNFS_CKINVALID(vp, np, ND_READ)) {
		    do {
			error = nqnfs_getlease(vp, ND_READ, ap->a_cred,
			    ap->a_p);
		    } while (error == NQNFS_EXPIRED);
		    if (error)
			return (error);
		    if (np->n_lrev != np->n_brev ||
			(np->n_flag & NQNFSNONCACHE)) {
			if ((error = nfs_vinvalbuf(vp, V_SAVE, ap->a_cred,
				ap->a_p, 1)) == EINTR)
				return (error);
			np->n_brev = np->n_lrev;
		    }
		}
	} else {
		if (np->n_flag & NMODIFIED) {
			if ((error = nfs_vinvalbuf(vp, V_SAVE, ap->a_cred,
				ap->a_p, 1)) == EINTR)
				return (error);
			np->n_attrstamp = 0;
			if (vp->v_type == VDIR)
				np->n_direofoffset = 0;
			error = VOP_GETATTR(vp, &vattr, ap->a_cred, ap->a_p);
			if (error)
				return (error);
			np->n_mtime = vattr.va_mtime.tv_sec;
		} else {
			error = VOP_GETATTR(vp, &vattr, ap->a_cred, ap->a_p);
			if (error)
				return (error);
			if (np->n_mtime != vattr.va_mtime.tv_sec) {
				if (vp->v_type == VDIR)
					np->n_direofoffset = 0;
				if ((error = nfs_vinvalbuf(vp, V_SAVE,
					ap->a_cred, ap->a_p, 1)) == EINTR)
					return (error);
				np->n_mtime = vattr.va_mtime.tv_sec;
			}
		}
	}
	if ((nmp->nm_flag & NFSMNT_NQNFS) == 0)
		np->n_attrstamp = 0; /* For Open/Close consistency */
	return (0);
}

/*
 * nfs close vnode op
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
 *                     or commit them (this satisfies 1 and 2 except for the
 *                     case where the server crashes after this close but
 *                     before the commit RPC, which is felt to be "good
 *                     enough". Changing the last argument to nfs_flush() to
 *                     a 1 would force a commit operation, if it is felt a
 *                     commit is necessary now.
 * for NQNFS         - do nothing now, since 2 is dealt with via leases and
 *                     1 should be dealt with via an fsync() system call for
 *                     cases where write errors are important.
 */
/* ARGSUSED */
static int
nfs_close(ap)
	struct vop_close_args /* {
		struct vnodeop_desc *a_desc;
		struct vnode *a_vp;
		int  a_fflag;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	register struct nfsnode *np = VTONFS(vp);
	int error = 0;

	if (vp->v_type == VREG) {
#if DIAGNOSTIC
	    register struct sillyrename *sp = np->n_sillyrename;
	    if (sp)
                kprintf("nfs_close: %s, dvp=%x, vp=%x, ap=%x, np=%x, sp=%x\n",
                	&sp->s_name[0], (unsigned)(sp->s_dvp), (unsigned)vp,
                	(unsigned)ap, (unsigned)np, (unsigned)sp);
#endif
	    if ((VFSTONFS(vp->v_mount)->nm_flag & NFSMNT_NQNFS) == 0 &&
		(np->n_flag & NMODIFIED)) {
		if (NFS_ISV3(vp)) {
		    error = nfs_flush(vp, ap->a_cred, MNT_WAIT, ap->a_p, 0);
		    np->n_flag &= ~NMODIFIED;
		} else
		    error = nfs_vinvalbuf(vp, V_SAVE, ap->a_cred, ap->a_p, 1);
		np->n_attrstamp = 0;
	    }
	    if (np->n_flag & NWRITEERR) {
		np->n_flag &= ~NWRITEERR;
		error = np->n_error;
	    }
	}
	return (error);
}

/*
 * nfs getattr call from vfs.
 */
static int
nfs_getattr(ap)
	struct vop_getattr_args /* {
		struct vnode *a_vp;
		struct vattr *a_vap;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	register struct nfsnode *np = VTONFS(vp);
	register caddr_t cp;
	register u_long *tl;
	register int t1, t2;
	caddr_t bpos, dpos;
	int error = 0;
	struct mbuf *mreq, *mrep, *md, *mb, *mb2;
	int v3 = NFS_ISV3(vp);
	
	/*
	 * Update local times for special files.
	 */
	if (np->n_flag & (NACC | NUPD))
		np->n_flag |= NCHG;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 513)) | DBG_FUNC_START,
		     (int)np->n_size, 0, (int)np->n_vattr.va_size, np->n_flag, 0);

	/*
	 * First look in the cache.
	 */
	if ((error = nfs_getattrcache(vp, ap->a_vap)) == 0) {
	        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 513)) | DBG_FUNC_END,
			     (int)np->n_size, 0, (int)np->n_vattr.va_size, np->n_flag, 0);

		return (0);
	}
	if (error != ENOENT)
		return (error);
	error = 0;
        
	if (v3 && nfsaccess_cache_timeout > 0) {
		/*  nfsstats.accesscache_misses++; */
		if (error = nfs3_access_otw(vp, NFSV3ACCESS_ALL, ap->a_p, ap->a_cred))
                    return (error);
		if ((error = nfs_getattrcache(vp, ap->a_vap)) == 0)
			return (0);
		if (error != ENOENT)
			return (error);
		error = 0;
	}

	nfsstats.rpccnt[NFSPROC_GETATTR]++;
	nfsm_reqhead(vp, NFSPROC_GETATTR, NFSX_FH(v3));
	nfsm_fhtom(vp, v3);
	nfsm_request(vp, NFSPROC_GETATTR, ap->a_p, ap->a_cred);
	if (!error) {
		nfsm_loadattr(vp, ap->a_vap);
		if (np->n_mtime != ap->a_vap->va_mtime.tv_sec) {
			NFSTRACE(NFSTRC_GA_INV, vp);
			if (vp->v_type == VDIR)
				nfs_invaldir(vp);
			error = nfs_vinvalbuf(vp, V_SAVE, ap->a_cred,
					      ap->a_p, 1);
			if (!error) {
				NFSTRACE(NFSTRC_GA_INV1, vp);
				np->n_mtime = ap->a_vap->va_mtime.tv_sec;
			} else {
				NFSTRACE(NFSTRC_GA_INV2, error);
			}
		}
	}
	nfsm_reqdone;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 513)) | DBG_FUNC_END,
		     (int)np->n_size, -1, (int)np->n_vattr.va_size, error, 0);

	return (error);
}

/*
 * nfs setattr call.
 */
static int
nfs_setattr(ap)
	struct vop_setattr_args /* {
		struct vnodeop_desc *a_desc;
		struct vnode *a_vp;
		struct vattr *a_vap;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	register struct nfsnode *np = VTONFS(vp);
	register struct vattr *vap = ap->a_vap;
	int error = 0;
	u_quad_t tsize;

#ifndef nolint
	tsize = (u_quad_t)0;
#endif
	/*
	 * Disallow write attempts if the filesystem is mounted read-only.
	 */
  	if ((vap->va_flags != VNOVAL || vap->va_uid != (uid_t)VNOVAL ||
	    vap->va_gid != (gid_t)VNOVAL || vap->va_atime.tv_sec != VNOVAL ||
	    vap->va_mtime.tv_sec != VNOVAL || vap->va_mode != (mode_t)VNOVAL) &&
	    (vp->v_mount->mnt_flag & MNT_RDONLY))
		return (EROFS);
	if (vap->va_size != VNOVAL) {
 		switch (vp->v_type) {
 		case VDIR:
 			return (EISDIR);
 		case VCHR:
 		case VBLK:
 		case VSOCK:
 		case VFIFO:
			if (vap->va_mtime.tv_sec == VNOVAL &&
			    vap->va_atime.tv_sec == VNOVAL &&
			    vap->va_mode == (u_short)VNOVAL &&
			    vap->va_uid == (uid_t)VNOVAL &&
			    vap->va_gid == (gid_t)VNOVAL)
				return (0);
 			vap->va_size = VNOVAL;
 			break;
 		default:
			/*
			 * Disallow write attempts if the filesystem is
			 * mounted read-only.
			 */
			if (vp->v_mount->mnt_flag & MNT_RDONLY)
				return (EROFS);
			np->n_flag |= NMODIFIED;
 			tsize = np->n_size;
			
			KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 512)) | DBG_FUNC_START,
				     (int)np->n_size, (int)vap->va_size, (int)np->n_vattr.va_size, np->n_flag, 0);

 			if (vap->va_size == 0)
 				error = nfs_vinvalbuf(vp, 0,
 					ap->a_cred, ap->a_p, 1);
 			else
 				error = nfs_vinvalbuf(vp, V_SAVE,
 					ap->a_cred, ap->a_p, 1);

			if (UBCISVALID(vp))
				ubc_setsize(vp, (off_t)vap->va_size); /* XXX check error */

 			if (error) {
				printf("nfs_setattr: nfs_vinvalbuf %d\n", error);

#if DIAGNOSTIC
				kprintf("nfs_setattr: nfs_vinvalbuf %d\n",
					error);
#endif /* DIAGNOSTIC */
				if (UBCISVALID(vp))
				        ubc_setsize(vp, (off_t)tsize); /* XXX check error */

				KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 512)) | DBG_FUNC_END,
					     (int)np->n_size, (int)vap->va_size, (int)np->n_vattr.va_size, -1, 0);

 				return (error);
			}
			np->n_size = np->n_vattr.va_size = vap->va_size;

  		};
  	} else if ((vap->va_mtime.tv_sec != VNOVAL ||
		    vap->va_atime.tv_sec != VNOVAL) && (np->n_flag & NMODIFIED) &&
		   vp->v_type == VREG &&
		   (error = nfs_vinvalbuf(vp, V_SAVE, ap->a_cred,
					  ap->a_p, 1)) == EINTR)
	        return (error);

	error = nfs_setattrrpc(vp, vap, ap->a_cred, ap->a_p);

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 512)) | DBG_FUNC_END,
		     (int)np->n_size, (int)vap->va_size, (int)np->n_vattr.va_size, error, 0);

	if (error && vap->va_size != VNOVAL) {
		/* make every effort to resync file size w/ server... */
		int err = 0; /* preserve "error" for return */

		printf("nfs_setattr: nfs_setattrrpc %d\n", error);
#if DIAGNOSTIC
		kprintf("nfs_setattr: nfs_setattrrpc %d\n", error);
#endif /* DIAGNOSTIC */
		np->n_size = np->n_vattr.va_size = tsize;
		if (UBCISVALID(vp))
			ubc_setsize(vp, (off_t)np->n_size); /* XXX check error */
		vap->va_size = tsize;
		err = nfs_setattrrpc(vp, vap, ap->a_cred, ap->a_p);

		if (err)
			printf("nfs_setattr1: nfs_setattrrpc %d\n", err);
#if DIAGNOSTIC
		if (err)
			kprintf("nfs_setattr nfs_setattrrpc %d\n", err);
#endif /* DIAGNOSTIC */
	}
	return (error);
}

/*
 * Do an nfs setattr rpc.
 */
static int
nfs_setattrrpc(vp, vap, cred, procp)
	register struct vnode *vp;
	register struct vattr *vap;
	struct ucred *cred;
	struct proc *procp;
{
	register struct nfsv2_sattr *sp;
	register caddr_t cp;
	register long t1, t2;
	caddr_t bpos, dpos, cp2;
	u_long *tl;
	int error = 0, wccflag = NFSV3_WCCRATTR;
	struct mbuf *mreq, *mrep, *md, *mb, *mb2;
	int v3 = NFS_ISV3(vp);

	nfsstats.rpccnt[NFSPROC_SETATTR]++;
	nfsm_reqhead(vp, NFSPROC_SETATTR, NFSX_FH(v3) + NFSX_SATTR(v3));
	nfsm_fhtom(vp, v3);
	if (v3) {
		if (vap->va_mode != (u_short)VNOVAL) {
			nfsm_build(tl, u_long *, 2 * NFSX_UNSIGNED);
			*tl++ = nfs_true;
			*tl = txdr_unsigned(vap->va_mode);
		} else {
			nfsm_build(tl, u_long *, NFSX_UNSIGNED);
			*tl = nfs_false;
		}
		if (vap->va_uid != (uid_t)VNOVAL) {
			nfsm_build(tl, u_long *, 2 * NFSX_UNSIGNED);
			*tl++ = nfs_true;
			*tl = txdr_unsigned(vap->va_uid);
		} else {
			nfsm_build(tl, u_long *, NFSX_UNSIGNED);
			*tl = nfs_false;
		}
		if (vap->va_gid != (gid_t)VNOVAL) {
			nfsm_build(tl, u_long *, 2 * NFSX_UNSIGNED);
			*tl++ = nfs_true;
			*tl = txdr_unsigned(vap->va_gid);
		} else {
			nfsm_build(tl, u_long *, NFSX_UNSIGNED);
			*tl = nfs_false;
		}
		if (vap->va_size != VNOVAL) {
			nfsm_build(tl, u_long *, 3 * NFSX_UNSIGNED);
			*tl++ = nfs_true;
			txdr_hyper(&vap->va_size, tl);
		} else {
			nfsm_build(tl, u_long *, NFSX_UNSIGNED);
			*tl = nfs_false;
		}
		if (vap->va_atime.tv_sec != VNOVAL) {
			if (vap->va_atime.tv_sec != time.tv_sec) {
				nfsm_build(tl, u_long *, 3 * NFSX_UNSIGNED);
				*tl++ = txdr_unsigned(NFSV3SATTRTIME_TOCLIENT);
				txdr_nfsv3time(&vap->va_atime, tl);
			} else {
				nfsm_build(tl, u_long *, NFSX_UNSIGNED);
				*tl = txdr_unsigned(NFSV3SATTRTIME_TOSERVER);
			}
		} else {
			nfsm_build(tl, u_long *, NFSX_UNSIGNED);
			*tl = txdr_unsigned(NFSV3SATTRTIME_DONTCHANGE);
		}
		if (vap->va_mtime.tv_sec != VNOVAL) {
			if (vap->va_mtime.tv_sec != time.tv_sec) {
				nfsm_build(tl, u_long *, 3 * NFSX_UNSIGNED);
				*tl++ = txdr_unsigned(NFSV3SATTRTIME_TOCLIENT);
				txdr_nfsv3time(&vap->va_mtime, tl);
			} else {
				nfsm_build(tl, u_long *, NFSX_UNSIGNED);
				*tl = txdr_unsigned(NFSV3SATTRTIME_TOSERVER);
			}
		} else {
			nfsm_build(tl, u_long *, NFSX_UNSIGNED);
			*tl = txdr_unsigned(NFSV3SATTRTIME_DONTCHANGE);
		}
		nfsm_build(tl, u_long *, NFSX_UNSIGNED);
		*tl = nfs_false;
	} else {
		nfsm_build(sp, struct nfsv2_sattr *, NFSX_V2SATTR);
		if (vap->va_mode == (u_short)VNOVAL)
			sp->sa_mode = VNOVAL;
		else
			sp->sa_mode = vtonfsv2_mode(vp->v_type, vap->va_mode);
		if (vap->va_uid == (uid_t)VNOVAL)
			sp->sa_uid = VNOVAL;
		else
			sp->sa_uid = txdr_unsigned(vap->va_uid);
		if (vap->va_gid == (gid_t)VNOVAL)
			sp->sa_gid = VNOVAL;
		else
			sp->sa_gid = txdr_unsigned(vap->va_gid);
		sp->sa_size = txdr_unsigned(vap->va_size);
		txdr_nfsv2time(&vap->va_atime, &sp->sa_atime);
		txdr_nfsv2time(&vap->va_mtime, &sp->sa_mtime);
	}
	nfsm_request(vp, NFSPROC_SETATTR, procp, cred);
	if (v3) {
		nfsm_wcc_data(vp, wccflag);
        	if ((!wccflag) && (vp->v_type != VBAD)) /* EINVAL set on VBAD vnode */
                	VTONFS(vp)->n_attrstamp = 0;
	} else
		nfsm_loadattr(vp, (struct vattr *)0);
	nfsm_reqdone;
	return (error);
}

/*
 * nfs lookup call, one step at a time...
 * First look in cache
 * If not found, unlock the directory nfsnode and do the rpc
 */
static int
nfs_lookup(ap)
	struct vop_lookup_args /* {
		struct vnodeop_desc *a_desc;
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
	} */ *ap;
{
	register struct componentname *cnp = ap->a_cnp;
	register struct vnode *dvp = ap->a_dvp;
	register struct vnode **vpp = ap->a_vpp;
	register int flags = cnp->cn_flags;
	register struct vnode *newvp;
	register u_long *tl;
	register caddr_t cp;
	register long t1, t2;
	struct nfsmount *nmp;
	caddr_t bpos, dpos, cp2;
	struct mbuf *mreq, *mrep, *md, *mb, *mb2;
	long len;
	nfsfh_t *fhp;
	struct nfsnode *np;
	int lockparent, wantparent, error = 0, attrflag, fhsize;
	int v3 = NFS_ISV3(dvp);
	struct proc *p = cnp->cn_proc;
	int worldbuildworkaround = 1;

	if ((flags & ISLASTCN) && (dvp->v_mount->mnt_flag & MNT_RDONLY) &&
	    (cnp->cn_nameiop == DELETE || cnp->cn_nameiop == RENAME))
		return (EROFS);
	*vpp = NULLVP;
	if (dvp->v_type != VDIR)
		return (ENOTDIR);
	lockparent = flags & LOCKPARENT;
	wantparent = flags & (LOCKPARENT|WANTPARENT);
	nmp = VFSTONFS(dvp->v_mount);
	np = VTONFS(dvp);
        
	if (worldbuildworkaround) {
		/* 
		 * Temporary workaround for world builds to not have dvp go
		 * VBAD on during server calls in this routine. When
		 * the real ref counting problem is found take this out.
		 * Note if this was later and before the nfsm_request
		 * set up, the workaround did not work (NOTE other difference
		 * was I only put one VREF in that time. Thus it needs
		 * to be above the cache_lookup branch or with 2 VREFS. Not
		 * sure which. Can't play with world builds right now to see
		 * which.  VOP_ACCESS could also make it go to server.  - EKN
		 */
		VREF(dvp);   /* hang on to this dvp - EKN */
		VREF(dvp);   /* hang on tight - EKN  */
		}

	if ((error = cache_lookup(dvp, vpp, cnp)) && error != ENOENT) {
		struct vattr vattr;
		int vpid;

		if ((error = VOP_ACCESS(dvp, VEXEC, cnp->cn_cred, p))) {
			*vpp = NULLVP;
			goto error_return;
			}
                
		/* got to check to make sure the vnode didn't go away if access went to server */
		if ((*vpp)->v_type == VBAD) {
			error = EINVAL;
			goto error_return;
			}

		newvp = *vpp;
		vpid = newvp->v_id;
		/*
		 * See the comment starting `Step through' in ufs/ufs_lookup.c
		 * for an explanation of the locking protocol
		 */
		if (dvp == newvp) {
			VREF(newvp);
			error = 0;
		} else if (flags & ISDOTDOT) {
			VOP_UNLOCK(dvp, 0, p);
			error = vget(newvp, LK_EXCLUSIVE, p);
			if (!error && lockparent && (flags & ISLASTCN))
				error = vn_lock(dvp, LK_EXCLUSIVE, p);
		} else {
			error = vget(newvp, LK_EXCLUSIVE, p);
			if (!lockparent || error || !(flags & ISLASTCN))
				VOP_UNLOCK(dvp, 0, p);
		}
		if (!error) {
			if (vpid == newvp->v_id) {
			   if (!VOP_GETATTR(newvp, &vattr, cnp->cn_cred, p)
					&& vattr.va_ctime.tv_sec == VTONFS(newvp)->n_ctime) {
					nfsstats.lookupcache_hits++;
					if (cnp->cn_nameiop != LOOKUP && (flags & ISLASTCN))
						cnp->cn_flags |= SAVENAME;
					error = 0; /* ignore any from VOP_GETATTR  */
					goto error_return;
				}
				cache_purge(newvp);
			}
			vput(newvp);
			if (lockparent && dvp != newvp && (flags & ISLASTCN))
				VOP_UNLOCK(dvp, 0, p);
		}
		error = vn_lock(dvp, LK_EXCLUSIVE, p);
		*vpp = NULLVP;
		if (error) 
			goto error_return;
	}
        
	/* 
	 * Got to check to make sure the vnode didn't go away if VOP_GETATTR went to server
	 * or callers prior to this blocked and had it go VBAD.
	 */
	if (dvp->v_type == VBAD) { 
		error = EINVAL;
		goto error_return;
	}

	error = 0;
	newvp = NULLVP;
	nfsstats.lookupcache_misses++;
	nfsstats.rpccnt[NFSPROC_LOOKUP]++;
	len = cnp->cn_namelen;
	nfsm_reqhead(dvp, NFSPROC_LOOKUP,
		NFSX_FH(v3) + NFSX_UNSIGNED + nfsm_rndup(len));
	nfsm_fhtom(dvp, v3);
	nfsm_strtom(cnp->cn_nameptr, len, NFS_MAXNAMLEN);
	/* nfsm_request for NFSv2 causes you to goto to nfsmout upon errors */
	nfsm_request(dvp, NFSPROC_LOOKUP, cnp->cn_proc, cnp->cn_cred); 

	if (error) {
		nfsm_postop_attr(dvp, attrflag);
		m_freem(mrep);
		goto nfsmout;
	}
	nfsm_getfh(fhp, fhsize, v3);

	/*
	 * Handle RENAME case...
	 */
	if (cnp->cn_nameiop == RENAME && wantparent && (flags & ISLASTCN)) {
		if (NFS_CMPFH(np, fhp, fhsize)) {
			m_freem(mrep);
			error = EISDIR;
			goto error_return;
		}
		if ((error = nfs_nget(dvp->v_mount, fhp, fhsize, &np))) {
			m_freem(mrep);
			goto error_return;
		}
		newvp = NFSTOV(np);
		if (v3) {
			nfsm_postop_attr(newvp, attrflag);
			nfsm_postop_attr(dvp, attrflag);
		} else
			nfsm_loadattr(newvp, (struct vattr *)0);
		*vpp = newvp;
		m_freem(mrep);
		cnp->cn_flags |= SAVENAME;
		if (!lockparent)
			VOP_UNLOCK(dvp, 0, p);
		error = 0;
		goto error_return;
	}

	if (flags & ISDOTDOT) {
		VOP_UNLOCK(dvp, 0, p);
		error = nfs_nget(dvp->v_mount, fhp, fhsize, &np);
		if (error) {
			vn_lock(dvp, LK_EXCLUSIVE + LK_RETRY, p);
			goto error_return;
		}
		newvp = NFSTOV(np);
		if (lockparent && (flags & ISLASTCN) &&
		    (error = vn_lock(dvp, LK_EXCLUSIVE, p))) {
		    	vput(newvp);
			goto error_return;
		}
	} else if (NFS_CMPFH(np, fhp, fhsize)) {
		VREF(dvp);
		newvp = dvp;
	} else {
		if ((error = nfs_nget(dvp->v_mount, fhp, fhsize, &np))) {
			m_freem(mrep);
			goto error_return;
		}
		if (!lockparent || !(flags & ISLASTCN))
			VOP_UNLOCK(dvp, 0, p);
		newvp = NFSTOV(np);
	}
	if (v3) {
		nfsm_postop_attr(newvp, attrflag);
		nfsm_postop_attr(dvp, attrflag);
	} else
		nfsm_loadattr(newvp, (struct vattr *)0);
	if (cnp->cn_nameiop != LOOKUP && (flags & ISLASTCN))
		cnp->cn_flags |= SAVENAME;
	if ((cnp->cn_flags & MAKEENTRY) &&
	    (cnp->cn_nameiop != DELETE || !(flags & ISLASTCN))) {
		np->n_ctime = np->n_vattr.va_ctime.tv_sec;
		cache_enter(dvp, newvp, cnp);
	}
	*vpp = newvp;
	nfsm_reqdone;
	if (error) {
		if (newvp != NULLVP) {
			vrele(newvp);
			*vpp = NULLVP;
		}
		if ((cnp->cn_nameiop == CREATE || cnp->cn_nameiop == RENAME) &&
		    (flags & ISLASTCN) && error == ENOENT) {
			if (!lockparent)
				VOP_UNLOCK(dvp, 0, p);
			if (dvp->v_mount->mnt_flag & MNT_RDONLY)
				error = EROFS;
			else
				error = EJUSTRETURN;
		}
		if (cnp->cn_nameiop != LOOKUP && (flags & ISLASTCN))
			cnp->cn_flags |= SAVENAME;
	}
error_return:
	/*
	 * These "vreles" set dvp refcounts back to where they were
	 * before we took extra 2 VREFS to avoid VBAD vnode on dvp
	 * during server calls for world builds. Remove when real
	 * fix is found. - EKN 
	 */
	if (worldbuildworkaround) {
		vrele(dvp);  /* end of hanging on tight to dvp - EKN */
		vrele(dvp);  /* end of hanging on tight to dvp - EKN */
	}

	return (error);
}

/*
 * nfs read call.
 * Just call nfs_bioread() to do the work.
 */
static int
nfs_read(ap)
	struct vop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;

	if (vp->v_type != VREG)
		return (EPERM);
	return (nfs_bioread(vp, ap->a_uio, ap->a_ioflag, ap->a_cred, 0));
}

/*
 * nfs readlink call
 */
static int
nfs_readlink(ap)
	struct vop_readlink_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		struct ucred *a_cred;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;

	if (vp->v_type != VLNK)
		return (EPERM);
	return (nfs_bioread(vp, ap->a_uio, 0, ap->a_cred, 0));
}

/*
 * Do a readlink rpc.
 * Called by nfs_doio() from below the buffer cache.
 */
int
nfs_readlinkrpc(vp, uiop, cred)
	register struct vnode *vp;
	struct uio *uiop;
	struct ucred *cred;
{
	register u_long *tl;
	register caddr_t cp;
	register long t1, t2;
	caddr_t bpos, dpos, cp2;
	int error = 0, len, attrflag;
	struct mbuf *mreq, *mrep, *md, *mb, *mb2;
	int v3 = NFS_ISV3(vp);

	nfsstats.rpccnt[NFSPROC_READLINK]++;
	nfsm_reqhead(vp, NFSPROC_READLINK, NFSX_FH(v3));
	nfsm_fhtom(vp, v3);
	nfsm_request(vp, NFSPROC_READLINK, uiop->uio_procp, cred);
	if (v3)
		nfsm_postop_attr(vp, attrflag);
	if (!error) {
		nfsm_strsiz(len, NFS_MAXPATHLEN);
               if (len == NFS_MAXPATHLEN) {
                        struct nfsnode *np = VTONFS(vp);
#if DIAGNOSTIC
                        if (!np)
                                panic("nfs_readlinkrpc: null np");
#endif  
                        if (np->n_size && np->n_size < NFS_MAXPATHLEN)
                                len = np->n_size;
                }
		nfsm_mtouio(uiop, len);
	}
	nfsm_reqdone;
	return (error);
}

/*
 * nfs read rpc call
 * Ditto above
 */
int
nfs_readrpc(vp, uiop, cred)
	register struct vnode *vp;
	struct uio *uiop;
	struct ucred *cred;
{
	register u_long *tl;
	register caddr_t cp;
	register long t1, t2;
	caddr_t bpos, dpos, cp2;
	struct mbuf *mreq, *mrep, *md, *mb, *mb2;
	struct nfsmount *nmp;
	int error = 0, len, retlen, tsiz, eof, attrflag;
	int v3 = NFS_ISV3(vp);

#ifndef nolint
	eof = 0;
#endif
	nmp = VFSTONFS(vp->v_mount);
	tsiz = uiop->uio_resid;
        if (((u_int64_t)uiop->uio_offset + (unsigned int)tsiz > 0xffffffff) && !v3)
		return (EFBIG);
	while (tsiz > 0) {
		nfsstats.rpccnt[NFSPROC_READ]++;
		len = (tsiz > nmp->nm_rsize) ? nmp->nm_rsize : tsiz;
		nfsm_reqhead(vp, NFSPROC_READ, NFSX_FH(v3) + NFSX_UNSIGNED * 3);
		nfsm_fhtom(vp, v3);
		nfsm_build(tl, u_long *, NFSX_UNSIGNED * 3);
		if (v3) {
			txdr_hyper(&uiop->uio_offset, tl);
			*(tl + 2) = txdr_unsigned(len);
		} else {
			*tl++ = txdr_unsigned(uiop->uio_offset);
			*tl++ = txdr_unsigned(len);
			*tl = 0;
		}
		nfsm_request(vp, NFSPROC_READ, uiop->uio_procp, cred);
		if (v3) {
			nfsm_postop_attr(vp, attrflag);
			if (error) {
				m_freem(mrep);
				goto nfsmout;
			}
			nfsm_dissect(tl, u_long *, 2 * NFSX_UNSIGNED);
			eof = fxdr_unsigned(int, *(tl + 1));
		} else
			nfsm_loadattr(vp, (struct vattr *)0);
		nfsm_strsiz(retlen, nmp->nm_rsize);
		nfsm_mtouio(uiop, retlen);
		m_freem(mrep);
		tsiz -= retlen;
		if (v3) {
			if (eof || retlen == 0)
				tsiz = 0;
		} else if (retlen < len)
			tsiz = 0;
	}
nfsmout:
	return (error);
}

/*
 * nfs write call
 */
int
nfs_writerpc(vp, uiop, cred, iomode, must_commit)
	register struct vnode *vp;
	register struct uio *uiop;
	struct ucred *cred;
	int *iomode, *must_commit;
{
	register u_long *tl;
	register caddr_t cp;
	register int t1, t2, backup;
	caddr_t bpos, dpos, cp2;
	struct mbuf *mreq, *mrep, *md, *mb, *mb2;
	struct nfsmount *nmp = VFSTONFS(vp->v_mount);
	int error = 0, len, tsiz, wccflag = NFSV3_WCCRATTR, rlen, commit;
	int v3 = NFS_ISV3(vp), committed = NFSV3WRITE_FILESYNC;

#if DIAGNOSTIC
	if (uiop->uio_iovcnt != 1)
		panic("nfs_writerpc: iovcnt > 1");
#endif
	*must_commit = 0;
	tsiz = uiop->uio_resid;
        if (((u_int64_t)uiop->uio_offset + (unsigned int)tsiz > 0xffffffff) && !v3)
		return (EFBIG);
	while (tsiz > 0) {
		nfsstats.rpccnt[NFSPROC_WRITE]++;
		len = (tsiz > nmp->nm_wsize) ? nmp->nm_wsize : tsiz;
		nfsm_reqhead(vp, NFSPROC_WRITE,
			NFSX_FH(v3) + 5 * NFSX_UNSIGNED + nfsm_rndup(len));
		nfsm_fhtom(vp, v3);
		if (v3) {
			nfsm_build(tl, u_long *, 5 * NFSX_UNSIGNED);
			txdr_hyper(&uiop->uio_offset, tl);
			tl += 2;
			*tl++ = txdr_unsigned(len);
			*tl++ = txdr_unsigned(*iomode);
		} else {
			nfsm_build(tl, u_long *, 4 * NFSX_UNSIGNED);
			*++tl = txdr_unsigned(uiop->uio_offset);
			tl += 2;
		}
		*tl = txdr_unsigned(len);
		nfsm_uiotom(uiop, len);
		nfsm_request(vp, NFSPROC_WRITE, uiop->uio_procp, cred);
		if (v3) {
			wccflag = NFSV3_WCCCHK;
			nfsm_wcc_data(vp, wccflag);
			if (!error) {
				nfsm_dissect(tl, u_long *, 2 * NFSX_UNSIGNED +
					NFSX_V3WRITEVERF);
				rlen = fxdr_unsigned(int, *tl++);
				if (rlen <= 0) {
					error = NFSERR_IO;
					break;
				} else if (rlen < len) {
					backup = len - rlen;
					uiop->uio_iov->iov_base -= backup;
					uiop->uio_iov->iov_len += backup;
					uiop->uio_offset -= backup;
					uiop->uio_resid += backup;
					len = rlen;
				}
				commit = fxdr_unsigned(int, *tl++);

				/*
				 * Return the lowest committment level
				 * obtained by any of the RPCs.
				 */
				if (committed == NFSV3WRITE_FILESYNC)
					committed = commit;
				else if (committed == NFSV3WRITE_DATASYNC &&
					commit == NFSV3WRITE_UNSTABLE)
					committed = commit;
				if ((nmp->nm_flag & NFSMNT_HASWRITEVERF) == 0) {
				    bcopy((caddr_t)tl, (caddr_t)nmp->nm_verf,
					NFSX_V3WRITEVERF);
				    nmp->nm_flag |= NFSMNT_HASWRITEVERF;
				} else if (bcmp((caddr_t)tl,
				    (caddr_t)nmp->nm_verf, NFSX_V3WRITEVERF)) {
				    *must_commit = 1;
				    bcopy((caddr_t)tl, (caddr_t)nmp->nm_verf,
					NFSX_V3WRITEVERF);
				}
			}
		} else
		    nfsm_loadattr(vp, (struct vattr *)0);
		if ((wccflag) && (vp->v_type != VBAD))  /* EINVAL set on VBAD vnode */
		    VTONFS(vp)->n_mtime = VTONFS(vp)->n_vattr.va_mtime.tv_sec;
		m_freem(mrep);
                /*
                 * we seem to have a case where we end up looping on shutdown and taking down nfs servers.
                 * For V3, error cases, there is no way to terminate loop, if the len was 0, meaning,
                 * nmp->nm_wsize was trashed. FreeBSD has this fix in it. Let's try it.
                 */
                if (error)
                    break;
                tsiz -= len;
	}
nfsmout:
        /* does it make sense to even say it was committed if we had an error? EKN */
        /* okay well just don't on bad vnodes then. EINVAL will be returned on bad vnodes */
        if ((vp->v_type != VBAD) && (vp->v_mount->mnt_flag & MNT_ASYNC))
		committed = NFSV3WRITE_FILESYNC;
        *iomode = committed;
	if (error)
		uiop->uio_resid = tsiz;
	return (error);
}

/*
 * nfs mknod rpc
 * For NFS v2 this is a kludge. Use a create rpc but with the IFMT bits of the
 * mode set to specify the file type and the size field for rdev.
 */
static int
nfs_mknodrpc(dvp, vpp, cnp, vap)
	register struct vnode *dvp;
	register struct vnode **vpp;
	register struct componentname *cnp;
	register struct vattr *vap;
{
	register struct nfsv2_sattr *sp;
	register struct nfsv3_sattr *sp3;
	register u_long *tl;
	register caddr_t cp;
	register long t1, t2;
	struct vnode *newvp = (struct vnode *)0;
	struct nfsnode *np = (struct nfsnode *)0;
	struct vattr vattr;
	char *cp2;
	caddr_t bpos, dpos;
	int error = 0, wccflag = NFSV3_WCCRATTR, gotvp = 0;
	struct mbuf *mreq, *mrep, *md, *mb, *mb2;
	u_long rdev;
	int v3 = NFS_ISV3(dvp);

	if (vap->va_type == VCHR || vap->va_type == VBLK)
		rdev = txdr_unsigned(vap->va_rdev);
	else if (vap->va_type == VFIFO || vap->va_type == VSOCK)
		rdev = 0xffffffff;
	else {
		VOP_ABORTOP(dvp, cnp);
		vput(dvp);
		return (EOPNOTSUPP);
	}
	if ((error = VOP_GETATTR(dvp, &vattr, cnp->cn_cred, cnp->cn_proc))) {
		VOP_ABORTOP(dvp, cnp);
		vput(dvp);
		return (error);
	}
	nfsstats.rpccnt[NFSPROC_MKNOD]++;
	nfsm_reqhead(dvp, NFSPROC_MKNOD, NFSX_FH(v3) + 4 * NFSX_UNSIGNED +
		+ nfsm_rndup(cnp->cn_namelen) + NFSX_SATTR(v3));
	nfsm_fhtom(dvp, v3);
	nfsm_strtom(cnp->cn_nameptr, cnp->cn_namelen, NFS_MAXNAMLEN);
	if (v3) {
		nfsm_build(tl, u_long *, NFSX_UNSIGNED + NFSX_V3SRVSATTR);
		*tl++ = vtonfsv3_type(vap->va_type);
		sp3 = (struct nfsv3_sattr *)tl;
		nfsm_v3sattr(sp3, vap, cnp->cn_cred->cr_uid, vattr.va_gid);
		if (vap->va_type == VCHR || vap->va_type == VBLK) {
			nfsm_build(tl, u_long *, 2 * NFSX_UNSIGNED);
			*tl++ = txdr_unsigned(major(vap->va_rdev));
			*tl = txdr_unsigned(minor(vap->va_rdev));
		}
	} else {
		nfsm_build(sp, struct nfsv2_sattr *, NFSX_V2SATTR);
		sp->sa_mode = vtonfsv2_mode(vap->va_type, vap->va_mode);
		sp->sa_uid = txdr_unsigned(cnp->cn_cred->cr_uid);
		sp->sa_gid = txdr_unsigned(vattr.va_gid);
		sp->sa_size = rdev;
		txdr_nfsv2time(&vap->va_atime, &sp->sa_atime);
		txdr_nfsv2time(&vap->va_mtime, &sp->sa_mtime);
	}
	nfsm_request(dvp, NFSPROC_MKNOD, cnp->cn_proc, cnp->cn_cred);
	if (!error) {
		nfsm_mtofh(dvp, newvp, v3, gotvp);
		if (!gotvp) {
			if (newvp) {
				vput(newvp);
				newvp = (struct vnode *)0;
			}
			error = nfs_lookitup(dvp, cnp->cn_nameptr,
			    cnp->cn_namelen, cnp->cn_cred, cnp->cn_proc, &np);
			if (!error)
				newvp = NFSTOV(np);
		}
	}
	if (v3)
		nfsm_wcc_data(dvp, wccflag);
	nfsm_reqdone;
	if (error) {
		if (newvp)
			vput(newvp);
	} else {
		if (cnp->cn_flags & MAKEENTRY)
			cache_enter(dvp, newvp, cnp);
		*vpp = newvp;
	}
	FREE_ZONE(cnp->cn_pnbuf, cnp->cn_pnlen, M_NAMEI);
        if (dvp->v_type != VBAD) { /* EINVAL set on VBAD vnode */
            VTONFS(dvp)->n_flag |= NMODIFIED;
            if (!wccflag)
		VTONFS(dvp)->n_attrstamp = 0;
            }
	vput(dvp);
	return (error);
}

/*
 * nfs mknod vop
 * just call nfs_mknodrpc() to do the work.
 */
/* ARGSUSED */
static int
nfs_mknod(ap)
	struct vop_mknod_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
	} */ *ap;
{
	struct vnode *newvp;
	int error;

	error = nfs_mknodrpc(ap->a_dvp, &newvp, ap->a_cnp, ap->a_vap);
	if (!error)
		vput(newvp);
	return (error);
}

static u_long create_verf;
/*
 * nfs file create call
 */
static int
nfs_create(ap)
	struct vop_create_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
	} */ *ap;
{
	register struct vnode *dvp = ap->a_dvp;
	register struct vattr *vap = ap->a_vap;
	register struct componentname *cnp = ap->a_cnp;
	register struct nfsv2_sattr *sp;
	register struct nfsv3_sattr *sp3;
	register u_long *tl;
	register caddr_t cp;
	register long t1, t2;
	struct nfsnode *np = (struct nfsnode *)0;
	struct vnode *newvp = (struct vnode *)0;
	caddr_t bpos, dpos, cp2;
	int error = 0, wccflag = NFSV3_WCCRATTR, gotvp = 0, fmode = 0;
	struct mbuf *mreq, *mrep, *md, *mb, *mb2;
	struct vattr vattr;
	int v3 = NFS_ISV3(dvp);

	/*
	 * Oops, not for me..
	 */
	if (vap->va_type == VSOCK)
		return (nfs_mknodrpc(dvp, ap->a_vpp, cnp, vap));

	if ((error = VOP_GETATTR(dvp, &vattr, cnp->cn_cred, cnp->cn_proc))) {
		VOP_ABORTOP(dvp, cnp);
		vput(dvp);
		return (error);
	}
	if (vap->va_vaflags & VA_EXCLUSIVE)
		fmode |= O_EXCL;
again:
	nfsstats.rpccnt[NFSPROC_CREATE]++;
	nfsm_reqhead(dvp, NFSPROC_CREATE, NFSX_FH(v3) + 2 * NFSX_UNSIGNED +
		nfsm_rndup(cnp->cn_namelen) + NFSX_SATTR(v3));
	nfsm_fhtom(dvp, v3);
	nfsm_strtom(cnp->cn_nameptr, cnp->cn_namelen, NFS_MAXNAMLEN);
	if (v3) {
		nfsm_build(tl, u_long *, NFSX_UNSIGNED);
		if (fmode & O_EXCL) {
		    *tl = txdr_unsigned(NFSV3CREATE_EXCLUSIVE);
		    nfsm_build(tl, u_long *, NFSX_V3CREATEVERF);
		    if (!TAILQ_EMPTY(&in_ifaddrhead))
			*tl++ = IA_SIN(in_ifaddrhead.tqh_first)->sin_addr.s_addr;
		    else
			*tl++ = create_verf;
		    *tl = ++create_verf;
		} else {
		    *tl = txdr_unsigned(NFSV3CREATE_UNCHECKED);
		    nfsm_build(tl, u_long *, NFSX_V3SRVSATTR);
		    sp3 = (struct nfsv3_sattr *)tl;
		    nfsm_v3sattr(sp3, vap, cnp->cn_cred->cr_uid, vattr.va_gid);
		}
	} else {
		nfsm_build(sp, struct nfsv2_sattr *, NFSX_V2SATTR);
		sp->sa_mode = vtonfsv2_mode(vap->va_type, vap->va_mode);
		sp->sa_uid = txdr_unsigned(cnp->cn_cred->cr_uid);
		sp->sa_gid = txdr_unsigned(vattr.va_gid);
		sp->sa_size = 0;
		txdr_nfsv2time(&vap->va_atime, &sp->sa_atime);
		txdr_nfsv2time(&vap->va_mtime, &sp->sa_mtime);
	}
	nfsm_request(dvp, NFSPROC_CREATE, cnp->cn_proc, cnp->cn_cred);
	if (!error) {
		nfsm_mtofh(dvp, newvp, v3, gotvp);
		if (!gotvp) {
			if (newvp) {
				vput(newvp);
				newvp = (struct vnode *)0;
			}
			error = nfs_lookitup(dvp, cnp->cn_nameptr,
			    cnp->cn_namelen, cnp->cn_cred, cnp->cn_proc, &np);
			if (!error)
				newvp = NFSTOV(np);
		}
	}
	if (v3)
		nfsm_wcc_data(dvp, wccflag);
	nfsm_reqdone;
	if (error) {
		if (v3 && (fmode & O_EXCL) && error == NFSERR_NOTSUPP) {
			fmode &= ~O_EXCL;
			goto again;
		}
		if (newvp)
			vput(newvp);
	} else if (v3 && (fmode & O_EXCL))
		error = nfs_setattrrpc(newvp, vap, cnp->cn_cred, cnp->cn_proc);
	if (!error) {
		if (cnp->cn_flags & MAKEENTRY)
			cache_enter(dvp, newvp, cnp);
		*ap->a_vpp = newvp;
	}
	FREE_ZONE(cnp->cn_pnbuf, cnp->cn_pnlen, M_NAMEI);
        if (dvp->v_type != VBAD) { /* EINVAL set on VBAD vnode */
            VTONFS(dvp)->n_flag |= NMODIFIED;
            if (!wccflag)
                    VTONFS(dvp)->n_attrstamp = 0;
        }
	vput(dvp);
	return (error);
}

/*
 * nfs file remove call
 * To try and make nfs semantics closer to ufs semantics, a file that has
 * other processes using the vnode is renamed instead of removed and then
 * removed later on the last close.
 * - If v_usecount > 1
 *	  If a rename is not already in the works
 *	     call nfs_sillyrename() to set it up
 *     else
 *	  do the remove rpc
 */
static int
nfs_remove(ap)
	struct vop_remove_args /* {
		struct vnodeop_desc *a_desc;
		struct vnode * a_dvp;
		struct vnode * a_vp;
		struct componentname * a_cnp;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	register struct vnode *dvp = ap->a_dvp;
	register struct componentname *cnp = ap->a_cnp;
	register struct nfsnode *np = VTONFS(vp);
	int error = 0;
	struct vattr vattr;
	int file_deleted = 0;

#if DIAGNOSTIC
	if ((cnp->cn_flags & HASBUF) == 0)
		panic("nfs_remove: no name");
	if (vp->v_usecount < 1)
		panic("nfs_remove: bad v_usecount");
#endif
	if (vp->v_usecount == 1 || 
		(UBCISVALID(vp)&&(vp->v_usecount==2)) || 
		(np->n_sillyrename &&
	    VOP_GETATTR(vp, &vattr, cnp->cn_cred, cnp->cn_proc) == 0 &&
	    vattr.va_nlink > 1)) {
		/*
		 * Purge the name cache so that the chance of a lookup for
		 * the name succeeding while the remove is in progress is
		 * minimized. Without node locking it can still happen, such
		 * that an I/O op returns ESTALE, but since you get this if
		 * another host removes the file..
		 */
		cache_purge(vp);
		/*
		 * throw away biocache buffers, mainly to avoid
		 * unnecessary delayed writes later.
		 */
		error = nfs_vinvalbuf(vp, 0, cnp->cn_cred, cnp->cn_proc, 1);
		ubc_setsize(vp, (off_t)0);
		/* Do the rpc */
		if (error != EINTR)
			error = nfs_removerpc(dvp, cnp->cn_nameptr,
				cnp->cn_namelen, cnp->cn_cred, cnp->cn_proc);
		/*
		 * Kludge City: If the first reply to the remove rpc is lost..
		 *   the reply to the retransmitted request will be ENOENT
		 *   since the file was in fact removed
		 *   Therefore, we cheat and return success.
		 */
		if (error == ENOENT)
			error = 0;
		file_deleted = 1;
	} else if (!np->n_sillyrename) {
		error = nfs_sillyrename(dvp, vp, cnp);
	}

	FREE_ZONE(cnp->cn_pnbuf, cnp->cn_pnlen, M_NAMEI);
	np->n_attrstamp = 0;
	vput(dvp);

	VOP_UNLOCK(vp, 0, cnp->cn_proc);

	if (file_deleted)
		ubc_uncache(vp);

	vrele(vp);

	return (error);
}

/*
 * nfs file remove rpc called from nfs_inactive
 */
int
nfs_removeit(sp)
	register struct sillyrename *sp;
{

	return (nfs_removerpc(sp->s_dvp, sp->s_name, sp->s_namlen, sp->s_cred,
		(struct proc *)0));
}

/*
 * Nfs remove rpc, called from nfs_remove() and nfs_removeit().
 */
static int
nfs_removerpc(dvp, name, namelen, cred, proc)
	register struct vnode *dvp;
	char *name;
	int namelen;
	struct ucred *cred;
	struct proc *proc;
{
	register u_long *tl;
	register caddr_t cp;
	register long t1, t2;
	caddr_t bpos, dpos, cp2;
	int error = 0, wccflag = NFSV3_WCCRATTR;
	struct mbuf *mreq, *mrep, *md, *mb, *mb2;
	int v3 = NFS_ISV3(dvp);

	nfsstats.rpccnt[NFSPROC_REMOVE]++;
	nfsm_reqhead(dvp, NFSPROC_REMOVE,
		NFSX_FH(v3) + NFSX_UNSIGNED + nfsm_rndup(namelen));
	nfsm_fhtom(dvp, v3);
	nfsm_strtom(name, namelen, NFS_MAXNAMLEN);
	nfsm_request(dvp, NFSPROC_REMOVE, proc, cred);
	if (v3)
		nfsm_wcc_data(dvp, wccflag);
	nfsm_reqdone;
	if (dvp->v_type != VBAD) { /* EINVAL set on VBAD vnode */
		VTONFS(dvp)->n_flag |= NMODIFIED;
		if (!wccflag)
			VTONFS(dvp)->n_attrstamp = 0;
		}
	return (error);
}

/*
 * nfs file rename call
 */
static int
nfs_rename(ap)
	struct vop_rename_args  /* {
		struct vnode *a_fdvp;
		struct vnode *a_fvp;
		struct componentname *a_fcnp;
		struct vnode *a_tdvp;
		struct vnode *a_tvp;
		struct componentname *a_tcnp;
	} */ *ap;
{
	register struct vnode *fvp = ap->a_fvp;
	register struct vnode *tvp = ap->a_tvp;
	register struct vnode *fdvp = ap->a_fdvp;
	register struct vnode *tdvp = ap->a_tdvp;
	register struct componentname *tcnp = ap->a_tcnp;
	register struct componentname *fcnp = ap->a_fcnp;
	int error;

#if DIAGNOSTIC
	if ((tcnp->cn_flags & HASBUF) == 0 ||
	    (fcnp->cn_flags & HASBUF) == 0)
		panic("nfs_rename: no name");
#endif
	/* Check for cross-device rename */
	if ((fvp->v_mount != tdvp->v_mount) ||
	    (tvp && (fvp->v_mount != tvp->v_mount))) {
		error = EXDEV;
		goto out;
	}

	/*
	 * If the tvp exists and is in use, sillyrename it before doing the
	 * rename of the new file over it.
	 * XXX Can't sillyrename a directory.
	 */
	if (tvp && (tvp->v_usecount>(UBCISVALID(tvp) ? 2 : 1)) &&
			!VTONFS(tvp)->n_sillyrename &&
		tvp->v_type != VDIR && !nfs_sillyrename(tdvp, tvp, tcnp)) {
		vput(tvp);
		tvp = NULL;
	}

	error = nfs_renamerpc(fdvp, fcnp->cn_nameptr, fcnp->cn_namelen,
		tdvp, tcnp->cn_nameptr, tcnp->cn_namelen, tcnp->cn_cred,
		tcnp->cn_proc);

	if (fvp->v_type == VDIR) {
		if (tvp != NULL && tvp->v_type == VDIR)
			cache_purge(tdvp);
		cache_purge(fdvp);
	}
out:
	if (tdvp == tvp)
		vrele(tdvp);
	else
		vput(tdvp);
	if (tvp)
		vput(tvp);
	vrele(fdvp);
	vrele(fvp);
	/*
	 * Kludge: Map ENOENT => 0 assuming that it is a reply to a retry.
	 */
	if (error == ENOENT)
		error = 0;
	return (error);
}

/*
 * nfs file rename rpc called from nfs_remove() above
 */
static int
nfs_renameit(sdvp, scnp, sp)
	struct vnode *sdvp;
	struct componentname *scnp;
	register struct sillyrename *sp;
{
	return (nfs_renamerpc(sdvp, scnp->cn_nameptr, scnp->cn_namelen,
		sdvp, sp->s_name, sp->s_namlen, scnp->cn_cred, scnp->cn_proc));
}

/*
 * Do an nfs rename rpc. Called from nfs_rename() and nfs_renameit().
 */
static int
nfs_renamerpc(fdvp, fnameptr, fnamelen, tdvp, tnameptr, tnamelen, cred, proc)
	register struct vnode *fdvp;
	char *fnameptr;
	int fnamelen;
	register struct vnode *tdvp;
	char *tnameptr;
	int tnamelen;
	struct ucred *cred;
	struct proc *proc;
{
	register u_long *tl;
	register caddr_t cp;
	register long t1, t2;
	caddr_t bpos, dpos, cp2;
	int error = 0, fwccflag = NFSV3_WCCRATTR, twccflag = NFSV3_WCCRATTR;
	struct mbuf *mreq, *mrep, *md, *mb, *mb2;
	int v3 = NFS_ISV3(fdvp);

	nfsstats.rpccnt[NFSPROC_RENAME]++;
	nfsm_reqhead(fdvp, NFSPROC_RENAME,
		(NFSX_FH(v3) + NFSX_UNSIGNED)*2 + nfsm_rndup(fnamelen) +
		nfsm_rndup(tnamelen));
	nfsm_fhtom(fdvp, v3);
	nfsm_strtom(fnameptr, fnamelen, NFS_MAXNAMLEN);
	nfsm_fhtom(tdvp, v3);
	nfsm_strtom(tnameptr, tnamelen, NFS_MAXNAMLEN);
	nfsm_request(fdvp, NFSPROC_RENAME, proc, cred);
	if (v3) {
		nfsm_wcc_data(fdvp, fwccflag);
		nfsm_wcc_data(tdvp, twccflag);
	}
	nfsm_reqdone;
        if (fdvp->v_type != VBAD) { /* EINVAL set on VBAD vnode */
            VTONFS(fdvp)->n_flag |= NMODIFIED;
            if (!fwccflag)
		VTONFS(fdvp)->n_attrstamp = 0;
        }
        if (tdvp->v_type != VBAD) { /* EINVAL set on VBAD vnode */
            VTONFS(tdvp)->n_flag |= NMODIFIED;
            if (!twccflag)
                    VTONFS(tdvp)->n_attrstamp = 0;
        }
	return (error);
}

/*
 * nfs hard link create call
 */
static int
nfs_link(ap)
	struct vop_link_args /* {
		struct vnode *a_vp;
		struct vnode *a_tdvp;
		struct componentname *a_cnp;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	register struct vnode *tdvp = ap->a_tdvp;
	register struct componentname *cnp = ap->a_cnp;
	register u_long *tl;
	register caddr_t cp;
	register long t1, t2;
	caddr_t bpos, dpos, cp2;
	int error = 0, wccflag = NFSV3_WCCRATTR, attrflag = 0;
	struct mbuf *mreq, *mrep, *md, *mb, *mb2;
	int v3 = NFS_ISV3(vp);

	if (vp->v_mount != tdvp->v_mount) {
		VOP_ABORTOP(vp, cnp);
		if (tdvp == vp)
			vrele(tdvp);
		else
			vput(tdvp);
		return (EXDEV);
	}

	/*
	 * Push all writes to the server, so that the attribute cache
	 * doesn't get "out of sync" with the server.
	 * XXX There should be a better way!
	 */
	VOP_FSYNC(vp, cnp->cn_cred, MNT_WAIT, cnp->cn_proc);

	nfsstats.rpccnt[NFSPROC_LINK]++;
	nfsm_reqhead(vp, NFSPROC_LINK,
		NFSX_FH(v3)*2 + NFSX_UNSIGNED + nfsm_rndup(cnp->cn_namelen));
	nfsm_fhtom(vp, v3);
	nfsm_fhtom(tdvp, v3);
	nfsm_strtom(cnp->cn_nameptr, cnp->cn_namelen, NFS_MAXNAMLEN);
	nfsm_request(vp, NFSPROC_LINK, cnp->cn_proc, cnp->cn_cred);
	if (v3) {
		nfsm_postop_attr(vp, attrflag);
		nfsm_wcc_data(tdvp, wccflag);
	}
	nfsm_reqdone;
	FREE_ZONE(cnp->cn_pnbuf, cnp->cn_pnlen, M_NAMEI);

	VTONFS(tdvp)->n_flag |= NMODIFIED;
	if ((!attrflag) && (vp->v_type != VBAD))  /* EINVAL set on VBAD vnode */
		VTONFS(vp)->n_attrstamp = 0;
	if ((!wccflag) && (tdvp->v_type != VBAD))  /* EINVAL set on VBAD vnode */
		VTONFS(tdvp)->n_attrstamp = 0;
	vput(tdvp);
	/*
	 * Kludge: Map EEXIST => 0 assuming that it is a reply to a retry.
	 */
	if (error == EEXIST)
		error = 0;
	return (error);
}

/*
 * nfs symbolic link create call
 */
static int
nfs_symlink(ap)
	struct vop_symlink_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
		char *a_target;
	} */ *ap;
{
	register struct vnode *dvp = ap->a_dvp;
	register struct vattr *vap = ap->a_vap;
	register struct componentname *cnp = ap->a_cnp;
	register struct nfsv2_sattr *sp;
	register struct nfsv3_sattr *sp3;
	register u_long *tl;
	register caddr_t cp;
	register long t1, t2;
	caddr_t bpos, dpos, cp2;
	int slen, error = 0, wccflag = NFSV3_WCCRATTR, gotvp;
	struct mbuf *mreq, *mrep, *md, *mb, *mb2;
	struct vnode *newvp = (struct vnode *)0;
	int v3 = NFS_ISV3(dvp);

	nfsstats.rpccnt[NFSPROC_SYMLINK]++;
	slen = strlen(ap->a_target);
	nfsm_reqhead(dvp, NFSPROC_SYMLINK, NFSX_FH(v3) + 2*NFSX_UNSIGNED +
	    nfsm_rndup(cnp->cn_namelen) + nfsm_rndup(slen) + NFSX_SATTR(v3));
	nfsm_fhtom(dvp, v3);
	nfsm_strtom(cnp->cn_nameptr, cnp->cn_namelen, NFS_MAXNAMLEN);
	if (v3) {
		nfsm_build(sp3, struct nfsv3_sattr *, NFSX_V3SRVSATTR);
		nfsm_v3sattr(sp3, vap, cnp->cn_cred->cr_uid,
			cnp->cn_cred->cr_gid);
	}
	nfsm_strtom(ap->a_target, slen, NFS_MAXPATHLEN);
	if (!v3) {
		nfsm_build(sp, struct nfsv2_sattr *, NFSX_V2SATTR);
		sp->sa_mode = vtonfsv2_mode(VLNK, vap->va_mode);
		sp->sa_uid = txdr_unsigned(cnp->cn_cred->cr_uid);
		sp->sa_gid = txdr_unsigned(cnp->cn_cred->cr_gid);
		sp->sa_size = -1;
		txdr_nfsv2time(&vap->va_atime, &sp->sa_atime);
		txdr_nfsv2time(&vap->va_mtime, &sp->sa_mtime);
	}
	nfsm_request(dvp, NFSPROC_SYMLINK, cnp->cn_proc, cnp->cn_cred);
	if (v3) {
		if (!error)
			nfsm_mtofh(dvp, newvp, v3, gotvp);
		nfsm_wcc_data(dvp, wccflag);
	}
	nfsm_reqdone;
	if (newvp)
		vput(newvp);
	FREE_ZONE(cnp->cn_pnbuf, cnp->cn_pnlen, M_NAMEI);
        if (dvp->v_type != VBAD) { /* EINVAL set on VBAD vnode */
            VTONFS(dvp)->n_flag |= NMODIFIED;
            if (!wccflag)
		VTONFS(dvp)->n_attrstamp = 0;
        }
	vput(dvp);
	/*
	 * Kludge: Map EEXIST => 0 assuming that it is a reply to a retry.
	 */
	if (error == EEXIST)
		error = 0;
	return (error);
}

/*
 * nfs make dir call
 */
static int
nfs_mkdir(ap)
	struct vop_mkdir_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
	} */ *ap;
{
	register struct vnode *dvp = ap->a_dvp;
	register struct vattr *vap = ap->a_vap;
	register struct componentname *cnp = ap->a_cnp;
	register struct nfsv2_sattr *sp;
	register struct nfsv3_sattr *sp3;
	register u_long *tl;
	register caddr_t cp;
	register long t1, t2;
	register int len;
	struct nfsnode *np = (struct nfsnode *)0;
	struct vnode *newvp = (struct vnode *)0;
	caddr_t bpos, dpos, cp2;
	int error = 0, wccflag = NFSV3_WCCRATTR;
	int gotvp = 0;
	struct mbuf *mreq, *mrep, *md, *mb, *mb2;
	struct vattr vattr;
	int v3 = NFS_ISV3(dvp);

	if ((error = VOP_GETATTR(dvp, &vattr, cnp->cn_cred, cnp->cn_proc))) {
		VOP_ABORTOP(dvp, cnp);
		vput(dvp);
		return (error);
	}
	len = cnp->cn_namelen;
	nfsstats.rpccnt[NFSPROC_MKDIR]++;
	nfsm_reqhead(dvp, NFSPROC_MKDIR,
	  NFSX_FH(v3) + NFSX_UNSIGNED + nfsm_rndup(len) + NFSX_SATTR(v3));
	nfsm_fhtom(dvp, v3);
	nfsm_strtom(cnp->cn_nameptr, len, NFS_MAXNAMLEN);
	if (v3) {
		nfsm_build(sp3, struct nfsv3_sattr *, NFSX_V3SRVSATTR);
		nfsm_v3sattr(sp3, vap, cnp->cn_cred->cr_uid, vattr.va_gid);
	} else {
		nfsm_build(sp, struct nfsv2_sattr *, NFSX_V2SATTR);
		sp->sa_mode = vtonfsv2_mode(VDIR, vap->va_mode);
		sp->sa_uid = txdr_unsigned(cnp->cn_cred->cr_uid);
		sp->sa_gid = txdr_unsigned(vattr.va_gid);
		sp->sa_size = -1;
		txdr_nfsv2time(&vap->va_atime, &sp->sa_atime);
		txdr_nfsv2time(&vap->va_mtime, &sp->sa_mtime);
	}
	nfsm_request(dvp, NFSPROC_MKDIR, cnp->cn_proc, cnp->cn_cred);
	if (!error)
		nfsm_mtofh(dvp, newvp, v3, gotvp);
	if (v3)
		nfsm_wcc_data(dvp, wccflag);
	nfsm_reqdone;
	if (dvp->v_type != VBAD) { /* EINVAL set on this case */
		VTONFS(dvp)->n_flag |= NMODIFIED;
		if (!wccflag)
			VTONFS(dvp)->n_attrstamp = 0;
		}
	/*
	 * Kludge: Map EEXIST => 0 assuming that you have a reply to a retry
	 * if we can succeed in looking up the directory.
	 */
	if (error == EEXIST || (!error && !gotvp)) {
		if (newvp) {
			vrele(newvp);
			newvp = (struct vnode *)0;
		}
		error = nfs_lookitup(dvp, cnp->cn_nameptr, len, cnp->cn_cred,
			cnp->cn_proc, &np);
		if (!error) {
			newvp = NFSTOV(np);
			if (newvp->v_type != VDIR)
				error = EEXIST;
		}
	}
	if (error) {
		if (newvp)
			vrele(newvp);
	} else
		*ap->a_vpp = newvp;
	FREE_ZONE(cnp->cn_pnbuf, cnp->cn_pnlen, M_NAMEI);
	vput(dvp);
	return (error);
}

/*
 * nfs remove directory call
 */
static int
nfs_rmdir(ap)
	struct vop_rmdir_args /* {
		struct vnode *a_dvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	register struct vnode *dvp = ap->a_dvp;
	register struct componentname *cnp = ap->a_cnp;
	register u_long *tl;
	register caddr_t cp;
	register long t1, t2;
	caddr_t bpos, dpos, cp2;
	int error = 0, wccflag = NFSV3_WCCRATTR;
	struct mbuf *mreq, *mrep, *md, *mb, *mb2;
	int v3 = NFS_ISV3(dvp);

	nfsstats.rpccnt[NFSPROC_RMDIR]++;
	nfsm_reqhead(dvp, NFSPROC_RMDIR,
		NFSX_FH(v3) + NFSX_UNSIGNED + nfsm_rndup(cnp->cn_namelen));
	nfsm_fhtom(dvp, v3);
	nfsm_strtom(cnp->cn_nameptr, cnp->cn_namelen, NFS_MAXNAMLEN);
	nfsm_request(dvp, NFSPROC_RMDIR, cnp->cn_proc, cnp->cn_cred);
	if (v3)
		nfsm_wcc_data(dvp, wccflag);
	nfsm_reqdone;
	FREE_ZONE(cnp->cn_pnbuf, cnp->cn_pnlen, M_NAMEI);
        if (dvp->v_type != VBAD) { /* EINVAL set on this case */
            VTONFS(dvp)->n_flag |= NMODIFIED;
            if (!wccflag)
		VTONFS(dvp)->n_attrstamp = 0;
        }
	cache_purge(dvp);
	cache_purge(vp);
	vput(vp);
	vput(dvp);
	/*
	 * Kludge: Map ENOENT => 0 assuming that you have a reply to a retry.
	 */
	if (error == ENOENT)
		error = 0;
	return (error);
}

/*
 * nfs readdir call
 */
static int
nfs_readdir(ap)
	struct vop_readdir_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		struct ucred *a_cred;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	register struct nfsnode *np = VTONFS(vp);
	register struct uio *uio = ap->a_uio;
	int tresid, error;
	struct vattr vattr;

	if (vp->v_type != VDIR)
		return (EPERM);
	/*
	 * First, check for hit on the EOF offset cache
	 */
	if (np->n_direofoffset > 0 && uio->uio_offset >= np->n_direofoffset &&
	    (np->n_flag & NMODIFIED) == 0) {
		if (VFSTONFS(vp->v_mount)->nm_flag & NFSMNT_NQNFS) {
			if (NQNFS_CKCACHABLE(vp, ND_READ)) {
				nfsstats.direofcache_hits++;
				return (0);
			}
		} else if (VOP_GETATTR(vp, &vattr, ap->a_cred, uio->uio_procp) == 0 &&
			np->n_mtime == vattr.va_mtime.tv_sec) {
			nfsstats.direofcache_hits++;
			return (0);
		}
	}

	/*
	 * Call nfs_bioread() to do the real work.
	 */
	tresid = uio->uio_resid;
	error = nfs_bioread(vp, uio, 0, ap->a_cred, 0);

	if (!error && uio->uio_resid == tresid)
		nfsstats.direofcache_misses++;
	return (error);
}

/*
 * Readdir rpc call.
 * Called from below the buffer cache by nfs_doio().
 */
int
nfs_readdirrpc(vp, uiop, cred)
	struct vnode *vp;
	register struct uio *uiop;
	struct ucred *cred;

{
	register int len, left;
	register struct dirent *dp;
	register u_long *tl;
	register caddr_t cp;
	register long t1, t2;
	register nfsuint64 *cookiep;
	caddr_t bpos, dpos, cp2;
	struct mbuf *mreq, *mrep, *md, *mb, *mb2;
	nfsuint64 cookie;
	struct nfsmount *nmp = VFSTONFS(vp->v_mount);
	struct nfsnode *dnp = VTONFS(vp);
	u_quad_t fileno;
	int error = 0, tlen, more_dirs = 1, blksiz = 0, bigenough = 1;
	int attrflag;
	int v3 = NFS_ISV3(vp);

#ifndef nolint
	dp = (struct dirent *)0;
#endif
#if DIAGNOSTIC
	if (uiop->uio_iovcnt != 1 || (uiop->uio_offset & (NFS_DIRBLKSIZ - 1)) ||
		(uiop->uio_resid & (NFS_DIRBLKSIZ - 1)))
		panic("nfs_readdirrpc: bad uio");
#endif

	/*
	 * If there is no cookie, assume directory was stale.
	 */
	cookiep = nfs_getcookie(dnp, uiop->uio_offset, 0);
	if (cookiep)
		cookie = *cookiep;
	else
		return (NFSERR_BAD_COOKIE);
	/*
	 * Loop around doing readdir rpc's of size nm_readdirsize
	 * truncated to a multiple of DIRBLKSIZ.
	 * The stopping criteria is EOF or buffer full.
	 */
	while (more_dirs && bigenough) {
		nfsstats.rpccnt[NFSPROC_READDIR]++;
		nfsm_reqhead(vp, NFSPROC_READDIR, NFSX_FH(v3) +
			NFSX_READDIR(v3));
		nfsm_fhtom(vp, v3);
		if (v3) {
			nfsm_build(tl, u_long *, 5 * NFSX_UNSIGNED);
			*tl++ = cookie.nfsuquad[0];
			*tl++ = cookie.nfsuquad[1];
			*tl++ = dnp->n_cookieverf.nfsuquad[0];
			*tl++ = dnp->n_cookieverf.nfsuquad[1];
		} else {
			nfsm_build(tl, u_long *, 2 * NFSX_UNSIGNED);
			*tl++ = cookie.nfsuquad[0];
		}
		*tl = txdr_unsigned(nmp->nm_readdirsize);
		nfsm_request(vp, NFSPROC_READDIR, uiop->uio_procp, cred);
		if (v3) {
			nfsm_postop_attr(vp, attrflag);
			if (!error) {
				nfsm_dissect(tl, u_long *, 2 * NFSX_UNSIGNED);
				dnp->n_cookieverf.nfsuquad[0] = *tl++;
				dnp->n_cookieverf.nfsuquad[1] = *tl;
			} else {
				m_freem(mrep);
				goto nfsmout;
			}
		}
		nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
		more_dirs = fxdr_unsigned(int, *tl);
	
		/* loop thru the dir entries, doctoring them to 4bsd form */
		while (more_dirs && bigenough) {
			if (v3) {
				nfsm_dissect(tl, u_long *, 3 * NFSX_UNSIGNED);
				fxdr_hyper(tl, &fileno);
				len = fxdr_unsigned(int, *(tl + 2));
			} else {
				nfsm_dissect(tl, u_long *, 2 * NFSX_UNSIGNED);
				fileno = fxdr_unsigned(u_quad_t, *tl++);
				len = fxdr_unsigned(int, *tl);
			}
			if (len <= 0 || len > NFS_MAXNAMLEN) {
				error = EBADRPC;
				m_freem(mrep);
				goto nfsmout;
			}
			tlen = nfsm_rndup(len);
			if (tlen == len)
				tlen += 4;	/* To ensure null termination */
			left = DIRBLKSIZ - blksiz;
			if ((tlen + DIRHDSIZ) > left) {
				dp->d_reclen += left;
				uiop->uio_iov->iov_base += left;
				uiop->uio_iov->iov_len -= left;
				uiop->uio_offset += left;
				uiop->uio_resid -= left;
				blksiz = 0;
			}
			if ((tlen + DIRHDSIZ) > uiop->uio_resid)
				bigenough = 0;
			if (bigenough) {
				dp = (struct dirent *)uiop->uio_iov->iov_base;
				dp->d_fileno = (int)fileno;
				dp->d_namlen = len;
				dp->d_reclen = tlen + DIRHDSIZ;
				dp->d_type = DT_UNKNOWN;
				blksiz += dp->d_reclen;
				if (blksiz == DIRBLKSIZ)
					blksiz = 0;
				uiop->uio_offset += DIRHDSIZ;
				uiop->uio_resid -= DIRHDSIZ;
				uiop->uio_iov->iov_base += DIRHDSIZ;
				uiop->uio_iov->iov_len -= DIRHDSIZ;
				nfsm_mtouio(uiop, len);
				cp = uiop->uio_iov->iov_base;
				tlen -= len;
				*cp = '\0';	/* null terminate */
				uiop->uio_iov->iov_base += tlen;
				uiop->uio_iov->iov_len -= tlen;
				uiop->uio_offset += tlen;
				uiop->uio_resid -= tlen;
			} else
				nfsm_adv(nfsm_rndup(len));
			if (v3) {
				nfsm_dissect(tl, u_long *, 3 * NFSX_UNSIGNED);
			} else {
				nfsm_dissect(tl, u_long *, 2 * NFSX_UNSIGNED);
			}
			if (bigenough) {
				cookie.nfsuquad[0] = *tl++;
				if (v3)
					cookie.nfsuquad[1] = *tl++;
			} else if (v3)
				tl += 2;
			else
				tl++;
			more_dirs = fxdr_unsigned(int, *tl);
		}
		/*
		 * If at end of rpc data, get the eof boolean
		 */
		if (!more_dirs) {
			nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
			more_dirs = (fxdr_unsigned(int, *tl) == 0);
		}
		m_freem(mrep);
	}
	/*
	 * Fill last record, iff any, out to a multiple of DIRBLKSIZ
	 * by increasing d_reclen for the last record.
	 */
	if (blksiz > 0) {
		left = DIRBLKSIZ - blksiz;
		dp->d_reclen += left;
		uiop->uio_iov->iov_base += left;
		uiop->uio_iov->iov_len -= left;
		uiop->uio_offset += left;
		uiop->uio_resid -= left;
	}

	/*
	 * We are now either at the end of the directory or have filled the
	 * block.
	 */
	if (bigenough)
		dnp->n_direofoffset = uiop->uio_offset;
	else {
		if (uiop->uio_resid > 0)
			printf("EEK! readdirrpc resid > 0\n");
		cookiep = nfs_getcookie(dnp, uiop->uio_offset, 1);
		*cookiep = cookie;
	}
nfsmout:
	return (error);
}

/*
 * NFS V3 readdir plus RPC. Used in place of nfs_readdirrpc().
 */
int
nfs_readdirplusrpc(vp, uiop, cred)
	struct vnode *vp;
	register struct uio *uiop;
	struct ucred *cred;
{
	register int len, left;
	register struct dirent *dp;
	register u_long *tl;
	register caddr_t cp;
	register long t1, t2;
	register struct vnode *newvp;
	register nfsuint64 *cookiep;
	caddr_t bpos, dpos, cp2, dpossav1, dpossav2;
	struct mbuf *mreq, *mrep, *md, *mb, *mb2, *mdsav1, *mdsav2;
	struct nameidata nami, *ndp = &nami;
	struct componentname *cnp = &ndp->ni_cnd;
	nfsuint64 cookie;
	struct nfsmount *nmp = VFSTONFS(vp->v_mount);
	struct nfsnode *dnp = VTONFS(vp), *np;
	nfsfh_t *fhp;
	u_quad_t fileno;
	int error = 0, tlen, more_dirs = 1, blksiz = 0, doit, bigenough = 1, i;
	int attrflag, fhsize;

#ifndef nolint
	dp = (struct dirent *)0;
#endif
#if DIAGNOSTIC
	if (uiop->uio_iovcnt != 1 || (uiop->uio_offset & (DIRBLKSIZ - 1)) ||
		(uiop->uio_resid & (DIRBLKSIZ - 1)))
		panic("nfs_readdirplusrpc: bad uio");
#endif
	ndp->ni_dvp = vp;
	newvp = NULLVP;

	/*
	 * If there is no cookie, assume directory was stale.
	 */
	cookiep = nfs_getcookie(dnp, uiop->uio_offset, 0);
	if (cookiep)
		cookie = *cookiep;
	else
		return (NFSERR_BAD_COOKIE);
	/*
	 * Loop around doing readdir rpc's of size nm_readdirsize
	 * truncated to a multiple of DIRBLKSIZ.
	 * The stopping criteria is EOF or buffer full.
	 */
	while (more_dirs && bigenough) {
		nfsstats.rpccnt[NFSPROC_READDIRPLUS]++;
		nfsm_reqhead(vp, NFSPROC_READDIRPLUS,
			NFSX_FH(1) + 6 * NFSX_UNSIGNED);
		nfsm_fhtom(vp, 1);
 		nfsm_build(tl, u_long *, 6 * NFSX_UNSIGNED);
		*tl++ = cookie.nfsuquad[0];
		*tl++ = cookie.nfsuquad[1];
		*tl++ = dnp->n_cookieverf.nfsuquad[0];
		*tl++ = dnp->n_cookieverf.nfsuquad[1];
		*tl++ = txdr_unsigned(nmp->nm_readdirsize);
		*tl = txdr_unsigned(nmp->nm_rsize);
		nfsm_request(vp, NFSPROC_READDIRPLUS, uiop->uio_procp, cred);
		nfsm_postop_attr(vp, attrflag);
		if (error) {
			m_freem(mrep);
			goto nfsmout;
		}
		nfsm_dissect(tl, u_long *, 3 * NFSX_UNSIGNED);
		dnp->n_cookieverf.nfsuquad[0] = *tl++;
		dnp->n_cookieverf.nfsuquad[1] = *tl++;
		more_dirs = fxdr_unsigned(int, *tl);

		/* loop thru the dir entries, doctoring them to 4bsd form */
		while (more_dirs && bigenough) {
			nfsm_dissect(tl, u_long *, 3 * NFSX_UNSIGNED);
			fxdr_hyper(tl, &fileno);
			len = fxdr_unsigned(int, *(tl + 2));
			if (len <= 0 || len > NFS_MAXNAMLEN) {
				error = EBADRPC;
				m_freem(mrep);
				goto nfsmout;
			}
			tlen = nfsm_rndup(len);
			if (tlen == len)
				tlen += 4;	/* To ensure null termination*/
			left = DIRBLKSIZ - blksiz;
			if ((tlen + DIRHDSIZ) > left) {
				dp->d_reclen += left;
				uiop->uio_iov->iov_base += left;
				uiop->uio_iov->iov_len -= left;
				uiop->uio_offset += left;
				uiop->uio_resid -= left;
				blksiz = 0;
			}
			if ((tlen + DIRHDSIZ) > uiop->uio_resid)
				bigenough = 0;
			if (bigenough) {
				dp = (struct dirent *)uiop->uio_iov->iov_base;
				dp->d_fileno = (int)fileno;
				dp->d_namlen = len;
				dp->d_reclen = tlen + DIRHDSIZ;
				dp->d_type = DT_UNKNOWN;
				blksiz += dp->d_reclen;
				if (blksiz == DIRBLKSIZ)
					blksiz = 0;
				uiop->uio_offset += DIRHDSIZ;
				uiop->uio_resid -= DIRHDSIZ;
				uiop->uio_iov->iov_base += DIRHDSIZ;
				uiop->uio_iov->iov_len -= DIRHDSIZ;
				cnp->cn_nameptr = uiop->uio_iov->iov_base;
				cnp->cn_namelen = len;
				nfsm_mtouio(uiop, len);
				cp = uiop->uio_iov->iov_base;
				tlen -= len;
				*cp = '\0';
				uiop->uio_iov->iov_base += tlen;
				uiop->uio_iov->iov_len -= tlen;
				uiop->uio_offset += tlen;
				uiop->uio_resid -= tlen;
			} else
				nfsm_adv(nfsm_rndup(len));
			nfsm_dissect(tl, u_long *, 3 * NFSX_UNSIGNED);
			if (bigenough) {
				cookie.nfsuquad[0] = *tl++;
				cookie.nfsuquad[1] = *tl++;
			} else
				tl += 2;

			/*
			 * Since the attributes are before the file handle
			 * (sigh), we must skip over the attributes and then
			 * come back and get them.
			 */
			attrflag = fxdr_unsigned(int, *tl);
			if (attrflag) {
			    dpossav1 = dpos;
			    mdsav1 = md;
			    nfsm_adv(NFSX_V3FATTR);
			    nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
			    doit = fxdr_unsigned(int, *tl);
			    if (doit) {
				nfsm_getfh(fhp, fhsize, 1);
				if (NFS_CMPFH(dnp, fhp, fhsize)) {
				    VREF(vp);
				    newvp = vp;
				    np = dnp;
				} else {
				    if ((error = nfs_nget(vp->v_mount, fhp,
					fhsize, &np)))
					doit = 0;
				    else
					newvp = NFSTOV(np);
				}
			    }
			    if (doit) {
				dpossav2 = dpos;
				dpos = dpossav1;
				mdsav2 = md;
				md = mdsav1;
				nfsm_loadattr(newvp, (struct vattr *)0);
				dpos = dpossav2;
				md = mdsav2;
				dp->d_type =
				    IFTODT(VTTOIF(np->n_vattr.va_type));
				ndp->ni_vp = newvp;
				cnp->cn_hash = 0;
				for (cp = cnp->cn_nameptr, i = 1; i <= len;
				    i++, cp++)
				    cnp->cn_hash += (unsigned char)*cp * i;
				if (cnp->cn_namelen <= NCHNAMLEN)
				    cache_enter(ndp->ni_dvp, ndp->ni_vp, cnp);
			    }
			} else {
			    /* Just skip over the file handle */
			    nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
			    i = fxdr_unsigned(int, *tl);
			    nfsm_adv(nfsm_rndup(i));
			}
			if (newvp != NULLVP) {
			    vrele(newvp);
			    newvp = NULLVP;
			}
			nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
			more_dirs = fxdr_unsigned(int, *tl);
		}
		/*
		 * If at end of rpc data, get the eof boolean
		 */
		if (!more_dirs) {
			nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
			more_dirs = (fxdr_unsigned(int, *tl) == 0);
		}
		m_freem(mrep);
	}
	/*
	 * Fill last record, iff any, out to a multiple of NFS_DIRBLKSIZ
	 * by increasing d_reclen for the last record.
	 */
	if (blksiz > 0) {
		left = DIRBLKSIZ - blksiz;
		dp->d_reclen += left;
		uiop->uio_iov->iov_base += left;
		uiop->uio_iov->iov_len -= left;
		uiop->uio_offset += left;
		uiop->uio_resid -= left;
	}

	/*
	 * We are now either at the end of the directory or have filled the
	 * block.
	 */
	if (bigenough)
		dnp->n_direofoffset = uiop->uio_offset;
	else {
		if (uiop->uio_resid > 0)
			printf("EEK! readdirplusrpc resid > 0\n");
		cookiep = nfs_getcookie(dnp, uiop->uio_offset, 1);
		*cookiep = cookie;
	}
nfsmout:
	if (newvp != NULLVP) {
	        if (newvp == vp)
			vrele(newvp);
		else
			vput(newvp);
		newvp = NULLVP;
	}
	return (error);
}

/*
 * Silly rename. To make the NFS filesystem that is stateless look a little
 * more like the "ufs" a remove of an active vnode is translated to a rename
 * to a funny looking filename that is removed by nfs_inactive on the
 * nfsnode. There is the potential for another process on a different client
 * to create the same funny name between the nfs_lookitup() fails and the
 * nfs_rename() completes, but...
 */
static int
nfs_sillyrename(dvp, vp, cnp)
	struct vnode *dvp, *vp;
	struct componentname *cnp;
{
	register struct sillyrename *sp;
	struct nfsnode *np;
	int error;
	short pid;
	struct ucred *cred;

	cache_purge(dvp);
	np = VTONFS(vp);
#if DIAGNOSTIC
	if (vp->v_type == VDIR)
		panic("nfs_sillyrename: dir");
#endif
	MALLOC_ZONE(sp, struct sillyrename *,
			sizeof (struct sillyrename), M_NFSREQ, M_WAITOK);
	sp->s_cred = crdup(cnp->cn_cred);
	sp->s_dvp = dvp;
	VREF(dvp);

	/* Fudge together a funny name */
	pid = cnp->cn_proc->p_pid;
	sp->s_namlen = sprintf(sp->s_name, ".nfsA%04x4.4", pid);

	/* Try lookitups until we get one that isn't there */
	while (nfs_lookitup(dvp, sp->s_name, sp->s_namlen, sp->s_cred,
		cnp->cn_proc, (struct nfsnode **)0) == 0) {
		sp->s_name[4]++;
		if (sp->s_name[4] > 'z') {
			error = EINVAL;
			goto bad;
		}
	}
	if ((error = nfs_renameit(dvp, cnp, sp)))
		goto bad;
	error = nfs_lookitup(dvp, sp->s_name, sp->s_namlen, sp->s_cred,
		cnp->cn_proc, &np);
#if DIAGNOSTIC
	kprintf("sillyrename: %s, vp=%x, np=%x, dvp=%x\n",
		&sp->s_name[0], (unsigned)vp, (unsigned)np, (unsigned)dvp);
#endif
	np->n_sillyrename = sp;
	return (0);
bad:
	vrele(sp->s_dvp);
	cred = sp->s_cred;
	sp->s_cred = NOCRED;
	crfree(cred);
	_FREE_ZONE((caddr_t)sp, sizeof (struct sillyrename), M_NFSREQ);
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
static int
nfs_lookitup(dvp, name, len, cred, procp, npp)
	register struct vnode *dvp;
	char *name;
	int len;
	struct ucred *cred;
	struct proc *procp;
	struct nfsnode **npp;
{
	register u_long *tl;
	register caddr_t cp;
	register long t1, t2;
	struct vnode *newvp = (struct vnode *)0;
	struct nfsnode *np, *dnp = VTONFS(dvp);
	caddr_t bpos, dpos, cp2;
	int error = 0, fhlen, attrflag;
	struct mbuf *mreq, *mrep, *md, *mb, *mb2;
	nfsfh_t *nfhp;
	int v3 = NFS_ISV3(dvp);

	nfsstats.rpccnt[NFSPROC_LOOKUP]++;
	nfsm_reqhead(dvp, NFSPROC_LOOKUP,
		NFSX_FH(v3) + NFSX_UNSIGNED + nfsm_rndup(len));
	nfsm_fhtom(dvp, v3);
	nfsm_strtom(name, len, NFS_MAXNAMLEN);
	nfsm_request(dvp, NFSPROC_LOOKUP, procp, cred);
	if (npp && !error) {
		nfsm_getfh(nfhp, fhlen, v3);
		if (*npp) {
		    np = *npp;
		    if (np->n_fhsize > NFS_SMALLFH && fhlen <= NFS_SMALLFH) {
			_FREE_ZONE((caddr_t)np->n_fhp,
					np->n_fhsize, M_NFSBIGFH);
			np->n_fhp = &np->n_fh;
		    } else if (np->n_fhsize <= NFS_SMALLFH && fhlen>NFS_SMALLFH)
			MALLOC_ZONE(np->n_fhp, nfsfh_t *,
						fhlen, M_NFSBIGFH, M_WAITOK);
		    bcopy((caddr_t)nfhp, (caddr_t)np->n_fhp, fhlen);
		    np->n_fhsize = fhlen;
		    newvp = NFSTOV(np);
		} else if (NFS_CMPFH(dnp, nfhp, fhlen)) {
		    VREF(dvp);
		    newvp = dvp;
		} else {
		    error = nfs_nget(dvp->v_mount, nfhp, fhlen, &np);
		    if (error) {
			m_freem(mrep);
			return (error);
		    }
		    newvp = NFSTOV(np);
		}
		if (v3) {
			nfsm_postop_attr(newvp, attrflag);
			if (!attrflag && *npp == NULL) {
				m_freem(mrep);
				if (newvp == dvp)
					vrele(newvp);
				else
					vput(newvp);
				return (ENOENT);
			}
		} else
			nfsm_loadattr(newvp, (struct vattr *)0);
	}
	nfsm_reqdone;
	if (npp && *npp == NULL) {
		if (error) {
			if (newvp)
				if (newvp == dvp)
					vrele(newvp);
				else
					vput(newvp);
		} else
			*npp = np;
	}
	return (error);
}

/*
 * Nfs Version 3 commit rpc
 */
static int
nfs_commit(vp, offset, cnt, cred, procp)
	register struct vnode *vp;
	u_quad_t offset;
	int cnt;
	struct ucred *cred;
	struct proc *procp;
{
	register caddr_t cp;
	register u_long *tl;
	register int t1, t2;
	register struct nfsmount *nmp = VFSTONFS(vp->v_mount);
	caddr_t bpos, dpos, cp2;
	int error = 0, wccflag = NFSV3_WCCRATTR;
	struct mbuf *mreq, *mrep, *md, *mb, *mb2;
	
	if ((nmp->nm_flag & NFSMNT_HASWRITEVERF) == 0)
		return (0);
	nfsstats.rpccnt[NFSPROC_COMMIT]++;
	nfsm_reqhead(vp, NFSPROC_COMMIT, NFSX_FH(1));
	nfsm_fhtom(vp, 1);
	nfsm_build(tl, u_long *, 3 * NFSX_UNSIGNED);
	txdr_hyper(&offset, tl);
	tl += 2;
	*tl = txdr_unsigned(cnt);
	nfsm_request(vp, NFSPROC_COMMIT, procp, cred);
	nfsm_wcc_data(vp, wccflag);
	if (!error) {
		nfsm_dissect(tl, u_long *, NFSX_V3WRITEVERF);
		if (bcmp((caddr_t)nmp->nm_verf, (caddr_t)tl,
			NFSX_V3WRITEVERF)) {
			bcopy((caddr_t)tl, (caddr_t)nmp->nm_verf,
				NFSX_V3WRITEVERF);
			error = NFSERR_STALEWRITEVERF;
		}
	}
	nfsm_reqdone;
	return (error);
}

/*
 * Kludge City..
 * - make nfs_bmap() essentially a no-op that does no translation
 * - do nfs_strategy() by doing I/O with nfs_readrpc/nfs_writerpc
 *   (Maybe I could use the process's page mapping, but I was concerned that
 *    Kernel Write might not be enabled and also figured copyout() would do
 *    a lot more work than bcopy() and also it currently happens in the
 *    context of the swapper process (2).
 */
static int
nfs_bmap(ap)
	struct vop_bmap_args /* {
		struct vnode *a_vp;
		daddr_t  a_bn;
		struct vnode **a_vpp;
		daddr_t *a_bnp;
		int *a_runp;
		int *a_runb;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	int devBlockSize = DEV_BSIZE;

	if (ap->a_vpp != NULL)
		*ap->a_vpp = vp;
	if (ap->a_bnp != NULL)
		*ap->a_bnp = ap->a_bn * btodb(vp->v_mount->mnt_stat.f_iosize,
					      devBlockSize);
	if (ap->a_runp != NULL)
		*ap->a_runp = 0;
#ifdef notyet
	if (ap->a_runb != NULL)
		*ap->a_runb = 0;
#endif
	return (0);
}

/*
 * Strategy routine.
 * For async requests when nfsiod(s) are running, queue the request by
 * calling nfs_asyncio(), otherwise just all nfs_doio() to do the
 * request.
 */
static int
nfs_strategy(ap)
	struct vop_strategy_args *ap;
{
	register struct buf *bp = ap->a_bp;
	struct ucred *cr;
	struct proc *p;
	int error = 0;

	if (ISSET(bp->b_flags, B_PHYS))
		panic("nfs_strategy: physio");
	if (ISSET(bp->b_flags, B_ASYNC))
		p = (struct proc *)0;
	else
		p = current_proc();	/* XXX */
	if (ISSET(bp->b_flags, B_READ))
		cr = bp->b_rcred;
	else
		cr = bp->b_wcred;
	/*
	 * If the op is asynchronous and an i/o daemon is waiting
	 * queue the request, wake it up and wait for completion
	 * otherwise just do it ourselves.
	 */
	if (!ISSET(bp->b_flags, B_ASYNC) || nfs_asyncio(bp, NOCRED))
		error = nfs_doio(bp, cr, p);
	return (error);
}

/*
 * Mmap a file
 *
 * NB Currently unsupported.
 */
/* ARGSUSED */
static int
nfs_mmap(ap)
	struct vop_mmap_args /* {
		struct vnode *a_vp;
		int  a_fflags;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{

	return (EINVAL);
}

/*
 * fsync vnode op. Just call nfs_flush() with commit == 1.
 */
/* ARGSUSED */
static int
nfs_fsync(ap)
	struct vop_fsync_args /* {
		struct vnodeop_desc *a_desc;
		struct vnode * a_vp;
		struct ucred * a_cred;
		int  a_waitfor;
		struct proc * a_p;
	} */ *ap;
{

	return (nfs_flush(ap->a_vp, ap->a_cred, ap->a_waitfor, ap->a_p, 1));
}

/*
 * Flush all the blocks associated with a vnode.
 * 	Walk through the buffer pool and push any dirty pages
 *	associated with the vnode.
 */
static int
nfs_flush(vp, cred, waitfor, p, commit)
	register struct vnode *vp;
	struct ucred *cred;
	int waitfor;
	struct proc *p;
	int commit;
{
	register struct nfsnode *np = VTONFS(vp);
	register struct buf *bp;
	register int i;
	struct buf *nbp;
	struct nfsmount *nmp = VFSTONFS(vp->v_mount);
	int s, error = 0, slptimeo = 0, slpflag = 0, retv, bvecpos, err;
	int passone = 1;
	u_quad_t off, endoff, toff;
	struct ucred* wcred = NULL;
	struct buf **bvec = NULL;
	kern_return_t kret;
	upl_t *upls = NULL;


#ifndef NFS_COMMITBVECSIZ
#define NFS_COMMITBVECSIZ	20
#endif
	struct buf *bvec_on_stack[NFS_COMMITBVECSIZ];
	struct upl_t *upls_on_stack[NFS_COMMITBVECSIZ]; 
	int bvecsize = 0, bveccount, buplpos;

	if (nmp->nm_flag & NFSMNT_INT)
		slpflag = PCATCH;
	if (!commit)
		passone = 0;

	/*
	 * A b_flags == (B_DELWRI | B_NEEDCOMMIT) block has been written to the
	 * server, but nas not been committed to stable storage on the server
	 * yet. On the first pass, the byte range is worked out and the commit
	 * rpc is done. On the second pass, nfs_writebp() is called to do the
	 * job.
	 */
again:
	if (vp->v_dirtyblkhd.lh_first)
		np->n_flag |= NMODIFIED;
	off = (u_quad_t)-1;
	endoff = 0;
	bvecpos = 0;
	buplpos = 0;
	if (NFS_ISV3(vp) && commit) {
		s = splbio();
		/*
		 * Count up how many buffers waiting for a commit.
		 */
		bveccount = 0;
		for (bp = vp->v_dirtyblkhd.lh_first; bp; bp = nbp) {
			nbp = bp->b_vnbufs.le_next;
			if ((bp->b_flags & (B_BUSY | B_DELWRI | B_NEEDCOMMIT))
			    == (B_DELWRI | B_NEEDCOMMIT))
				bveccount++;
		}
		/*
		 * Allocate space to remember the list of bufs to commit.  It is
		 * important to use M_NOWAIT here to avoid a race with nfs_write.
		 * If we can't get memory (for whatever reason), we will end up
		 * committing the buffers one-by-one in the loop below.
		 */
		if (bvec != NULL && bvec != bvec_on_stack)
				_FREE(bvec, M_TEMP);
		if (upls != NULL && upls != (upl_t *) upls_on_stack)
				_FREE(upls, M_TEMP);
				
		bvecsize = NFS_COMMITBVECSIZ;
		if (bveccount > NFS_COMMITBVECSIZ) {
			MALLOC(bvec, struct buf **,
					bveccount * sizeof(struct buf *), M_TEMP, M_NOWAIT);
			MALLOC(upls, upl_t *,
					bveccount * sizeof(upl_t), M_TEMP, M_NOWAIT);
			if ((bvec == NULL) || (upls == NULL)) {
				if (bvec) 
					_FREE(bvec, M_TEMP);
				if (upls)
					_FREE(upls, M_TEMP);
				bvec = bvec_on_stack;
				upls = (upl_t *) upls_on_stack;
			} else
				bvecsize = bveccount;
		} else {
			bvec = bvec_on_stack;
			upls = (upl_t *) upls_on_stack;
		}

		for (bp = vp->v_dirtyblkhd.lh_first; bp; bp = nbp) {
			nbp = bp->b_vnbufs.le_next;
			if (bvecpos >= bvecsize)
				break;
			if ((bp->b_flags & (B_BUSY | B_DELWRI | B_NEEDCOMMIT))
				!= (B_DELWRI | B_NEEDCOMMIT))
				continue;
			bremfree(bp);
			/*
			 * Work out if all buffers are using the same cred
			 * so we can deal with them all with one commit.
			 */
			if (wcred == NULL)
				wcred = bp->b_wcred;
			else if (wcred != bp->b_wcred)
				wcred = NOCRED;
			SET(bp->b_flags, (B_BUSY | B_WRITEINPROG));

			/*
			 * we need ubc_create_upl so if vm decides to
			 * do paging while we are waiting on commit rpc,
			 * that it doesn't pick these pages.
			 */
			if (!ISSET(bp->b_flags, B_PAGELIST)) {
				kret = ubc_create_upl(vp,
								ubc_blktooff(vp, bp->b_lblkno),
								bp->b_bufsize,
								&(upls[buplpos]),
								NULL,	  
								UPL_PRECIOUS);
				if (kret != KERN_SUCCESS) 
					panic("nfs_getcacheblk: get pagelists failed with (%d)", kret);
                                    
#ifdef UBC_DEBUG
				upl_ubc_alias_set(upls[buplpos], ioaddr, 1);
#endif /* UBC_DEBUG */
				buplpos++; /* not same as bvecpos if upl existed already */
			}

			/*
			 * A list of these buffers is kept so that the
			 * second loop knows which buffers have actually
			 * been committed. This is necessary, since there
			 * may be a race between the commit rpc and new
			 * uncommitted writes on the file.
			 */
			bvec[bvecpos++] = bp;
			toff = ((u_quad_t)bp->b_blkno) * DEV_BSIZE +
				bp->b_dirtyoff;
			if (toff < off)
				off = toff;
			toff += (u_quad_t)(bp->b_dirtyend - bp->b_dirtyoff);
			if (toff > endoff)
				endoff = toff;
		}
		splx(s);
	}
	if (bvecpos > 0) {
		/*
		 * Commit data on the server, as required.
		 * If all bufs are using the same wcred, then use that with
		 * one call for all of them, otherwise commit each one
		 * separately.
		 */
		if (wcred != NOCRED)
			retv = nfs_commit(vp, off, (int)(endoff - off),
					  wcred, p);
		else {
			retv = 0;
			for (i = 0; i < bvecpos; i++) {
				off_t off, size;
				bp = bvec[i];
				off = ((u_quad_t)bp->b_blkno) * DEV_BSIZE +
					bp->b_dirtyoff;
				size = (u_quad_t)(bp->b_dirtyend
						  - bp->b_dirtyoff);
				retv = nfs_commit(vp, off, (int)size,
						  bp->b_wcred, p);
				if (retv) break;
			}
		}

		if (retv == NFSERR_STALEWRITEVERF)
			nfs_clearcommit(vp->v_mount);
                        
        for (i = 0; i < buplpos; i++) {
			/*
			 * Before the VOP_BWRITE and biodone(ASYNC)/brelse, we have to undo
			 * holding the vm page or we we will deadlock on another vm_fault_list_request.
			 * Here's a convenient place to put it. 
			 * Better if we could hold it by setting the PAGELIST flag and kernel_upl_map
			 * as does nfs_writebp. Then normal biodones and brelse will clean it up and 
			 * we can avoid this abort. For now make minimal changes.
			 */
			err = ubc_upl_abort(upls[i], NULL); 
			if (err)
				printf("nfs_flush: kernel_upl_abort %d\n", err);
		}


		/*
		 * Now, either mark the blocks I/O done or mark the
		 * blocks dirty, depending on whether the commit
		 * succeeded.
		 */
		for (i = 0; i < bvecpos; i++) {
                        
			bp = bvec[i];
			CLR(bp->b_flags, (B_NEEDCOMMIT | B_WRITEINPROG));
			if (retv) {
			    brelse(bp);
			} else {
			    vp->v_numoutput++;
			    SET(bp->b_flags, B_ASYNC);
			    s = splbio();
			    CLR(bp->b_flags, (B_READ|B_DONE|B_ERROR|B_DELWRI));
			    bp->b_dirtyoff = bp->b_dirtyend = 0;
			    reassignbuf(bp, vp);
			    splx(s);
			    biodone(bp);
			}
		}

	}

	/*
	 * Start/do any write(s) that are required.
	 * There is a window here where B_BUSY protects the buffer. The vm pages have been
	 * freed up, yet B_BUSY is set. Don't think you will hit any busy/incore problems while
	 * we sleep, but not absolutely sure. Keep an eye on it. Otherwise we will have to hold
	 * vm page across this locked. - EKN
	 */
loop:
	if (current_thread_aborted()) {
		error = EINTR;
		goto done;
	}
	s = splbio();
	for (bp = vp->v_dirtyblkhd.lh_first; bp; bp = nbp) {
		nbp = bp->b_vnbufs.le_next;
		if (ISSET(bp->b_flags, B_BUSY)) {
			if (waitfor != MNT_WAIT || passone)
				continue;
			SET(bp->b_flags, B_WANTED);
			error = tsleep((caddr_t)bp, slpflag | (PRIBIO + 1),
				"nfsfsync", slptimeo);
			splx(s);
			if (error) {
			    if (nfs_sigintr(nmp, (struct nfsreq *)0, p)) {
				error = EINTR;
				goto done;
			    }
			    if (slpflag == PCATCH) {
				slpflag = 0;
				slptimeo = 2 * hz;
			    }
			}
			goto loop;
		}
		if (!ISSET(bp->b_flags, B_DELWRI))
			panic("nfs_fsync: not dirty");
		if ((passone || !commit) && ISSET(bp->b_flags, B_NEEDCOMMIT))
			continue;
		bremfree(bp);
		if (passone || !commit)
            SET(bp->b_flags, (B_BUSY|B_ASYNC));
		else
            SET(bp->b_flags, (B_BUSY|B_ASYNC|B_WRITEINPROG|B_NEEDCOMMIT));

		splx(s);
		VOP_BWRITE(bp);
		goto loop;
	}
	splx(s);
	if (passone) {
		passone = 0;
		goto again;
	}
	if (waitfor == MNT_WAIT) {
		while (vp->v_numoutput) {
			vp->v_flag |= VBWAIT;
			error = tsleep((caddr_t)&vp->v_numoutput,
				slpflag | (PRIBIO + 1), "nfsfsync", slptimeo);
			if (error) {
			    if (nfs_sigintr(nmp, (struct nfsreq *)0, p)) {
				error = EINTR;
				goto done;
			    }
			    if (slpflag == PCATCH) {
				slpflag = 0;
				slptimeo = 2 * hz;
			    }
			}
		}
		if (vp->v_dirtyblkhd.lh_first && commit) {
			goto loop;
		}
	}
	if (np->n_flag & NWRITEERR) {
		error = np->n_error;
		np->n_flag &= ~NWRITEERR;
	}
done:
	if (bvec != NULL && bvec != bvec_on_stack)
		_FREE(bvec, M_TEMP);
	if (upls != NULL && upls != (upl_t *) upls_on_stack)
        _FREE(upls, M_TEMP);
	return (error);
}

/*
 * Return POSIX pathconf information applicable to nfs.
 *
 * The NFS V2 protocol doesn't support this, so just return EINVAL
 * for V2.
 */
/* ARGSUSED */
static int
nfs_pathconf(ap)
	struct vop_pathconf_args /* {
		struct vnode *a_vp;
		int a_name;
		int *a_retval;
	} */ *ap;
{

	return (EINVAL);
}

/*
 * NFS advisory byte-level locks.
 * Currently unsupported.
 */
static int
nfs_advlock(ap)
	struct vop_advlock_args /* {
		struct vnode *a_vp;
		caddr_t  a_id;
		int  a_op;
		struct flock *a_fl;
		int  a_flags;
	} */ *ap;
{
#ifdef __FreeBSD__
	register struct nfsnode *np = VTONFS(ap->a_vp);

	/*
	 * The following kludge is to allow diskless support to work
	 * until a real NFS lockd is implemented. Basically, just pretend
	 * that this is a local lock.
	 */
	return (lf_advlock(ap, &(np->n_lockf), np->n_size));
#else
#if DIAGNOSTIC
	printf("nfs_advlock: pid %d comm %s\n", current_proc()->p_pid, current_proc()->p_comm);
#endif
	return (EOPNOTSUPP);
#endif
}

/*
 * Print out the contents of an nfsnode.
 */
static int
nfs_print(ap)
	struct vop_print_args /* {
		struct vnode *a_vp;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	register struct nfsnode *np = VTONFS(vp);

	printf("tag VT_NFS, fileid %ld fsid 0x%lx",
		np->n_vattr.va_fileid, np->n_vattr.va_fsid);
	if (vp->v_type == VFIFO)
		fifo_printinfo(vp);
	printf("\n");
	return (0);
}

/*
 * NFS directory offset lookup.
 * Currently unsupported.
 */
static int
nfs_blkatoff(ap)
	struct vop_blkatoff_args /* {
		struct vnode *a_vp;
		off_t a_offset;
		char **a_res;
		struct buf **a_bpp;
	} */ *ap;
{

#if DIAGNOSTIC
	printf("nfs_blkatoff: unimplemented!!");
#endif
	return (EOPNOTSUPP);
}

/*
 * NFS flat namespace allocation.
 * Currently unsupported.
 */
static int
nfs_valloc(ap)
	struct vop_valloc_args /* {
		struct vnode *a_pvp;
		int a_mode;
		struct ucred *a_cred;
		struct vnode **a_vpp;
	} */ *ap;
{

	return (EOPNOTSUPP);
}

/*
 * NFS flat namespace free.
 * Currently unsupported.
 */
static int
nfs_vfree(ap)
	struct vop_vfree_args /* {
		struct vnode *a_pvp;
		ino_t a_ino;
		int a_mode;
	} */ *ap;
{

#if DIAGNOSTIC
	printf("nfs_vfree: unimplemented!!");
#endif
	return (EOPNOTSUPP);
}

/*
 * NFS file truncation.
 */
static int
nfs_truncate(ap)
	struct vop_truncate_args /* {
		struct vnode *a_vp;
		off_t a_length;
		int a_flags;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{

	/* Use nfs_setattr */
#if DIAGNOSTIC
	printf("nfs_truncate: unimplemented!!");
#endif
	return (EOPNOTSUPP);
}

/*
 * NFS update.
 */
static int
nfs_update(ap)
	struct vop_update_args /* {
		struct vnode *a_vp;
		struct timeval *a_ta;
		struct timeval *a_tm;
		int a_waitfor;
	} */ *ap;
{

	/* Use nfs_setattr */
#if DIAGNOSTIC
	printf("nfs_update: unimplemented!!");
#endif
	return (EOPNOTSUPP);
}

int				nfs_aio_threads = 0; /* 1 per nfd (arbitrary) */
struct slock			nfs_aio_slock;
TAILQ_HEAD(bqueues, buf)	nfs_aio_bufq;
int				nfs_aio_bufq_len = 0; /* diagnostic only */

void
nfs_aio_thread()
{	/* see comment below in nfs_bwrite() for some rationale */
	struct buf	*bp;
	boolean_t funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	for(;;) {
		simple_lock(&nfs_aio_slock);
		if ((bp = nfs_aio_bufq.tqh_first)) {
			TAILQ_REMOVE(&nfs_aio_bufq, bp, b_freelist);
			nfs_aio_bufq_len--;
			simple_unlock(&nfs_aio_slock);
			nfs_writebp(bp, 1);
		} else { /* nothing to do - goodnight */
			assert_wait(&nfs_aio_bufq, THREAD_UNINT);
			simple_unlock(&nfs_aio_slock);
			(void)tsleep((caddr_t)0, PRIBIO+1, "nfs_aio_bufq", 0);
		}
	}
	(void) thread_funnel_set(kernel_flock, FALSE);
}


void
nfs_aio_thread_init()
{
	if (nfs_aio_threads++ == 0) {
		simple_lock_init(&nfs_aio_slock);
		TAILQ_INIT(&nfs_aio_bufq);
	}
	kernel_thread(kernel_task, nfs_aio_thread);
}


/*
 * Just call nfs_writebp() with the force argument set to 1.
 */
static int
nfs_bwrite(ap)
	struct vop_bwrite_args /* {
		struct vnode *a_bp;
	} */ *ap;
{
	extern void wakeup_one(caddr_t chan);

	/*
	 * nfs_writebp will issue a synchronous rpc to if B_ASYNC then
	 * to avoid distributed deadlocks we handoff the write to the
	 * nfs_aio threads.  Doing so allows us to complete the
	 * current request, rather than blocking on a server which may
	 * be ourself (or blocked on ourself).
	 *
	 * Note the loopback deadlocks happened when the thread
	 * invoking us was nfsd, and also when it was the pagedaemon.
	 *
	 * This solution has one known problem.  If *ALL* buffers get
	 * on the nfs_aio queue then no forward progress can be made
	 * until one of those writes complete.  And if the current
	 * nfs_aio writes-in-progress block due to a non-responsive server we
	 * are in a deadlock circle.  Probably the cure is to limit the
	 * async write concurrency in getnewbuf as in FreeBSD 3.2.
	 */
	if (nfs_aio_threads && ISSET(ap->a_bp->b_flags, B_ASYNC)) {
		simple_lock(&nfs_aio_slock);
		nfs_aio_bufq_len++;
		TAILQ_INSERT_TAIL(&nfs_aio_bufq, ap->a_bp, b_freelist);
		simple_unlock(&nfs_aio_slock);
		wakeup_one((caddr_t)&nfs_aio_bufq);
		return (0);
	}
	return (nfs_writebp(ap->a_bp, 1));
}

/*
 * This is a clone of vn_bwrite(), except that B_WRITEINPROG isn't set unless
 * the force flag is one and it also handles the B_NEEDCOMMIT flag.
 */
int
nfs_writebp(bp, force)
	register struct buf *bp;
	int force;
{
	int s;
	register int oldflags = bp->b_flags, retv = 1;
	off_t off;
	upl_t upl;
	kern_return_t kret;
	struct vnode *vp = bp->b_vp;
	upl_page_info_t *pl;

	if(!ISSET(bp->b_flags, B_BUSY))
		panic("nfs_writebp: buffer is not busy???");

	s = splbio();
	CLR(bp->b_flags, (B_READ|B_DONE|B_ERROR|B_DELWRI));

	if (ISSET(oldflags, (B_ASYNC|B_DELWRI))) {
		reassignbuf(bp, vp);
	}

	vp->v_numoutput++;
	current_proc()->p_stats->p_ru.ru_oublock++;
	splx(s);
        
        /* 
         * Since the B_BUSY flag is set, we need to lock the page before doing nfs_commit.
         * Otherwise we may block and get a busy incore pages during a vm pageout.
         * Move the existing code up before the commit.
         */

        if (!ISSET(bp->b_flags, B_META) && UBCISVALID(vp)) {
    
            if (!ISSET(bp->b_flags, B_PAGELIST)) {
				kret = ubc_create_upl(vp,
								ubc_blktooff(vp, bp->b_lblkno),
								bp->b_bufsize,
								&upl,
								&pl,
								UPL_PRECIOUS);
				if (kret != KERN_SUCCESS) {
					panic("nfs_writebp: get pagelists failed with (%d)", kret);
				}
                    
#ifdef UBC_DEBUG
				upl_ubc_alias_set(upl, ioaddr, 2);
#endif /* UBC_DEBUG */

				s = splbio();

				bp->b_pagelist = upl;
				SET(bp->b_flags, B_PAGELIST);
				splx(s);
                    
				kret = ubc_upl_map(upl, (vm_address_t *)&(bp->b_data));
				if (kret != KERN_SUCCESS) {
					panic("nfs_writebp: ubc_upl_map() failed with (%d)", kret);
				}
				if(bp->b_data == 0) 
					panic("nfs_writebp: upl_map mapped 0");

				if (!upl_page_present(pl, 0)) {
					/* 
					 * may be the page got paged out.
					 * let's just read it in. It is marked
					 * busy so we should not have any one
					 * yanking this page underneath the fileIO
					 */
					panic("nfs_writebp: nopage");
				}
		}
	}

	/*
	 * If B_NEEDCOMMIT is set, a commit rpc may do the trick. If not
	 * an actual write will have to be scheduled via. VOP_STRATEGY().
	 * If B_WRITEINPROG is already set, then push it with a write anyhow.
	 */
	if ((oldflags & (B_NEEDCOMMIT | B_WRITEINPROG)) == B_NEEDCOMMIT) {
		off = ((u_quad_t)bp->b_blkno) * DEV_BSIZE + bp->b_dirtyoff;
		SET(bp->b_flags, B_WRITEINPROG);
		retv = nfs_commit(vp, off, bp->b_dirtyend-bp->b_dirtyoff,
			bp->b_wcred, bp->b_proc);
		CLR(bp->b_flags, B_WRITEINPROG);
		if (!retv) {
			bp->b_dirtyoff = bp->b_dirtyend = 0;
			CLR(bp->b_flags, B_NEEDCOMMIT);
			biodone(bp);  /* on B_ASYNC will brelse the buffer */
                        
		} else if (retv == NFSERR_STALEWRITEVERF)
			nfs_clearcommit(vp->v_mount);
	}
	if (retv) {
		if (force)
			SET(bp->b_flags, B_WRITEINPROG);
		VOP_STRATEGY(bp);
	} 
        
	if( (oldflags & B_ASYNC) == 0) {
		int rtval = biowait(bp);

		if (oldflags & B_DELWRI) {
			s = splbio();
			reassignbuf(bp, vp);
			splx(s);
		}
		brelse(bp);
		return (rtval);
	} 

	return (0);
}

/*
 * nfs special file access vnode op.
 * Essentially just get vattr and then imitate iaccess() since the device is
 * local to the client.
 */
static int
nfsspec_access(ap)
	struct vop_access_args /* {
		struct vnode *a_vp;
		int  a_mode;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	register struct vattr *vap;
	register gid_t *gp;
	register struct ucred *cred = ap->a_cred;
	struct vnode *vp = ap->a_vp;
	mode_t mode = ap->a_mode;
	struct vattr vattr;
	register int i;
	int error;

	/*
	 * Disallow write attempts on filesystems mounted read-only;
	 * unless the file is a socket, fifo, or a block or character
	 * device resident on the filesystem.
	 */
	if ((mode & VWRITE) && (vp->v_mount->mnt_flag & MNT_RDONLY)) {
		switch (vp->v_type) {
		case VREG: case VDIR: case VLNK:
			return (EROFS);
		}
	}
	/*
	 * If you're the super-user,
	 * you always get access.
	 */
	if (cred->cr_uid == 0)
		return (0);
	vap = &vattr;
	error = VOP_GETATTR(vp, vap, cred, ap->a_p);
	if (error)
		return (error);
	/*
	 * Access check is based on only one of owner, group, public.
	 * If not owner, then check group. If not a member of the
	 * group, then check public access.
	 */
	if (cred->cr_uid != vap->va_uid) {
		mode >>= 3;
		gp = cred->cr_groups;
		for (i = 0; i < cred->cr_ngroups; i++, gp++)
			if (vap->va_gid == *gp)
				goto found;
		mode >>= 3;
found:
		;
	}
	error = (vap->va_mode & mode) == mode ? 0 : EACCES;
	return (error);
}

/*
 * Read wrapper for special devices.
 */
static int
nfsspec_read(ap)
	struct vop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{
	register struct nfsnode *np = VTONFS(ap->a_vp);

	/*
	 * Set access flag.
	 */
	np->n_flag |= NACC;
	np->n_atim.tv_sec = time.tv_sec;
	np->n_atim.tv_nsec = time.tv_usec * 1000;
	return (VOCALL(spec_vnodeop_p, VOFFSET(vop_read), ap));
}

/*
 * Write wrapper for special devices.
 */
static int
nfsspec_write(ap)
	struct vop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{
	register struct nfsnode *np = VTONFS(ap->a_vp);

	/*
	 * Set update flag.
	 */
	np->n_flag |= NUPD;
	np->n_mtim.tv_sec = time.tv_sec;
	np->n_mtim.tv_nsec = time.tv_usec * 1000;
	return (VOCALL(spec_vnodeop_p, VOFFSET(vop_write), ap));
}

/*
 * Close wrapper for special devices.
 *
 * Update the times on the nfsnode then do device close.
 */
static int
nfsspec_close(ap)
	struct vop_close_args /* {
		struct vnode *a_vp;
		int  a_fflag;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	register struct nfsnode *np = VTONFS(vp);
	struct vattr vattr;

	if (np->n_flag & (NACC | NUPD)) {
		np->n_flag |= NCHG;
		if (vp->v_usecount == 1 &&
		    (vp->v_mount->mnt_flag & MNT_RDONLY) == 0) {
			VATTR_NULL(&vattr);
			if (np->n_flag & NACC)
				vattr.va_atime = np->n_atim;
			if (np->n_flag & NUPD)
				vattr.va_mtime = np->n_mtim;
			(void)VOP_SETATTR(vp, &vattr, ap->a_cred, ap->a_p);
		}
	}
	return (VOCALL(spec_vnodeop_p, VOFFSET(vop_close), ap));
}

/*
 * Read wrapper for fifos.
 */
static int
nfsfifo_read(ap)
	struct vop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{
        extern vop_t **fifo_vnodeop_p;
	register struct nfsnode *np = VTONFS(ap->a_vp);

	/*
	 * Set access flag.
	 */
	np->n_flag |= NACC;
	np->n_atim.tv_sec = time.tv_sec;
	np->n_atim.tv_nsec = time.tv_usec * 1000;
	return (VOCALL(fifo_vnodeop_p, VOFFSET(vop_read), ap));
}

/*
 * Write wrapper for fifos.
 */
static int
nfsfifo_write(ap)
	struct vop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{
        extern vop_t **fifo_vnodeop_p;
	register struct nfsnode *np = VTONFS(ap->a_vp);

	/*
	 * Set update flag.
	 */
	np->n_flag |= NUPD;
	np->n_mtim.tv_sec = time.tv_sec;
	np->n_mtim.tv_nsec = time.tv_usec * 1000;
	return (VOCALL(fifo_vnodeop_p, VOFFSET(vop_write), ap));
}

/*
 * Close wrapper for fifos.
 *
 * Update the times on the nfsnode then do fifo close.
 */
static int
nfsfifo_close(ap)
	struct vop_close_args /* {
		struct vnode *a_vp;
		int  a_fflag;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	register struct nfsnode *np = VTONFS(vp);
	struct vattr vattr;
        extern vop_t **fifo_vnodeop_p;

	if (np->n_flag & (NACC | NUPD)) {
		if (np->n_flag & NACC) {
			np->n_atim.tv_sec = time.tv_sec;
			np->n_atim.tv_nsec = time.tv_usec * 1000;
		}
		if (np->n_flag & NUPD) {
			np->n_mtim.tv_sec = time.tv_sec;
			np->n_mtim.tv_nsec = time.tv_usec * 1000;
		}
		np->n_flag |= NCHG;
		if (vp->v_usecount == 1 &&
		    (vp->v_mount->mnt_flag & MNT_RDONLY) == 0) {
			VATTR_NULL(&vattr);
			if (np->n_flag & NACC)
				vattr.va_atime = np->n_atim;
			if (np->n_flag & NUPD)
				vattr.va_mtime = np->n_mtim;
			(void)VOP_SETATTR(vp, &vattr, ap->a_cred, ap->a_p);
		}
	}
	return (VOCALL(fifo_vnodeop_p, VOFFSET(vop_close), ap));
}

static int
nfs_ioctl(ap)
	struct vop_ioctl_args *ap;
{

	/*
	 * XXX we were once bogusly enoictl() which returned this (ENOTTY).
	 * Probably we should return ENODEV.
	 */
	return (ENOTTY);
}

static int
nfs_select(ap)
	struct vop_select_args *ap;
{

	/*
	 * We were once bogusly seltrue() which returns 1.  Is this right?
	 */
	return (1);
}

/* XXX Eliminate use of struct bp here */
/*
 * Vnode op for pagein using getblk_pages
 * derived from nfs_bioread()
 * No read aheads are started from pagein operation
 */
static int
nfs_pagein(ap)
	struct vop_pagein_args /* {
	   	struct vnode *a_vp,
	   	upl_t 	a_pl,
		vm_offset_t   a_pl_offset,
		off_t         a_f_offset,
		size_t        a_size,
		struct ucred *a_cred,
		int           a_flags
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	upl_t pl = ap->a_pl;
	size_t size= ap->a_size;
	off_t f_offset = ap->a_f_offset;
	vm_offset_t pl_offset = ap->a_pl_offset;
	int flags  = ap->a_flags;
	struct ucred *cred;
	register struct nfsnode *np = VTONFS(vp);
	register int biosize;
	register int xsize;
	struct vattr vattr;
	struct proc *p = current_proc();
	struct nfsmount *nmp = VFSTONFS(vp->v_mount);
	int error = 0;
	vm_offset_t ioaddr;
	struct uio	auio;
	struct iovec	aiov;
	struct uio * uio = &auio;
	int nocommit = flags & UPL_NOCOMMIT;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 322)) | DBG_FUNC_NONE,
		     (int)f_offset, size, pl, pl_offset, 0);

	if (UBCINVALID(vp)) {
#if DIAGNOSTIC
		panic("nfs_pagein: invalid vp");
#endif /* DIAGNOSTIC */
		return (EPERM);
	}

	UBCINFOCHECK("nfs_pagein", vp);
	if(pl == (upl_t)NULL) {
		panic("nfs_pagein: no upl");
	}

	cred = ubc_getcred(vp);
	if (cred == NOCRED)
		cred = ap->a_cred;

	if (size <= 0)
		return (EINVAL);

	if (f_offset < 0 || f_offset >= np->n_size 
					|| (f_offset & PAGE_MASK_64)) {
		if (!nocommit)
			ubc_upl_abort_range(pl, pl_offset, size, 
				UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
		return (EINVAL);
	}

	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_offset = f_offset;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_rw = UIO_READ;
	auio.uio_procp = NULL;


	if ((nmp->nm_flag & (NFSMNT_NFSV3 | NFSMNT_GOTFSINFO)) == NFSMNT_NFSV3)
		(void)nfs_fsinfo(nmp, vp, cred, p);
	biosize = min(vp->v_mount->mnt_stat.f_iosize, size);

	if (biosize & PAGE_MASK)
	        panic("nfs_pagein(%x): biosize not page aligned", biosize);

#if 0 /* Why bother? */
/* DO NOT BOTHER WITH "approximately maintained cache consistency" */
/* Does not make sense in paging paths -- Umesh*/
	/*
	 * For nfs, cache consistency can only be maintained approximately.
	 * Although RFC1094 does not specify the criteria, the following is
	 * believed to be compatible with the reference port.
	 * For nqnfs, full cache consistency is maintained within the loop.
	 * For nfs:
	 * If the file's modify time on the server has changed since the
	 * last read rpc or you have written to the file,
	 * you may have lost data cache consistency with the
	 * server, so flush all of the file's data out of the cache.
	 * Then force a getattr rpc to ensure that you have up to date
	 * attributes.
	 * NB: This implies that cache data can be read when up to
	 * NFS_ATTRTIMEO seconds out of date. If you find that you need current
	 * attributes this could be forced by setting n_attrstamp to 0 before
	 * the VOP_GETATTR() call.
	 */
	if ((nmp->nm_flag & NFSMNT_NQNFS) == 0) {
		if (np->n_flag & NMODIFIED) {
			np->n_attrstamp = 0;
			error = VOP_GETATTR(vp, &vattr, cred, p);
			if (error) {
				if (!nocommit)
					ubc_upl_abort_range(pl, pl_offset, size, 
							UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
				return (error);
			}
			np->n_mtime = vattr.va_mtime.tv_sec;
		} else {
			error = VOP_GETATTR(vp, &vattr, cred, p);
			if (error){
				if (!nocommit)
					ubc_upl_abort_range(pl, pl_offset, size,  
							UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
				return (error);
			}
			if (np->n_mtime != vattr.va_mtime.tv_sec) {
				error = nfs_vinvalbuf(vp, V_SAVE, cred, p, 1);
				if (error){
				        if (!nocommit)
					        ubc_upl_abort_range(pl, pl_offset, size, 
								UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
					return (error);
				}
				np->n_mtime = vattr.va_mtime.tv_sec;
			}
		}
	}
#endif 0 /* Why bother? */

	ubc_upl_map(pl, &ioaddr);
	ioaddr += pl_offset;
	xsize = size;

	do {
		uio->uio_resid = min(biosize, xsize);
		aiov.iov_len  = uio->uio_resid;
		aiov.iov_base = (caddr_t)ioaddr;

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 322)) | DBG_FUNC_NONE,
			(int)uio->uio_offset, uio->uio_resid, ioaddr, xsize, 0);

#warning nfs_pagein does not support NQNFS yet.
#if 0 /* why bother? */
/* NO RESOURCES TO FIX NQNFS CASE */
/* We need to deal with this later -- Umesh */
		/*
		 * Get a valid lease. If cached data is stale, flush it.
		 */
		if (nmp->nm_flag & NFSMNT_NQNFS) {
			if (NQNFS_CKINVALID(vp, np, ND_READ)) {
				do {
					error = nqnfs_getlease(vp, ND_READ, cred, p);
				} while (error == NQNFS_EXPIRED);
				if (error){
					ubc_upl_unmap(pl);
					if (!nocommit)
						ubc_upl_abort_range(pl, pl_offset, size,
								UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);

					return (error);
				}
				if (np->n_lrev != np->n_brev ||
					(np->n_flag & NQNFSNONCACHE)) {
					error = nfs_vinvalbuf(vp, V_SAVE, cred, p, 1);
					if (error) {
						ubc_upl_unmap(pl);
					if (!nocommit)
						ubc_upl_abort_range(pl,	pl_offset, size,
								UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
						return (error);
					}
					np->n_brev = np->n_lrev;
				}
			}
		}
#endif 0 /* why bother? */

		if (np->n_flag & NQNFSNONCACHE) {
			error = nfs_readrpc(vp, uio, cred);
			ubc_upl_unmap(pl);

			if (!nocommit) {
				if(error) 
					ubc_upl_abort_range(pl, pl_offset, size,
						UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
				else
					ubc_upl_commit_range(pl, pl_offset, size, 
						UPL_COMMIT_CLEAR_DIRTY | UPL_COMMIT_FREE_ON_EMPTY);
			}
			return (error);
		}

		/*
		 * With UBC we get here only when the file data is not in the VM
		 * page cache, so go ahead and read in.
		 */
#ifdef UBC_DEBUG
		upl_ubc_alias_set(pl, ioaddr, 2);
#endif /* UBC_DEBUG */
		nfsstats.pageins++;
		error = nfs_readrpc(vp, uio, cred);

		if (!error) {
			int zoff;
			int zcnt;

			if (uio->uio_resid) {
				/*
				 * If uio_resid > 0, there is a hole in the file and
				 * no writes after the hole have been pushed to
				 * the server yet... or we're at the EOF
				 * Just zero fill the rest of the valid area.
				 */
				zcnt = uio->uio_resid;
				zoff = biosize - zcnt;
				bzero((char *)ioaddr + zoff, zcnt);

				KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 324)) | DBG_FUNC_NONE,
					(int)uio->uio_offset, zoff, zcnt, ioaddr, 0);

				uio->uio_offset += zcnt;
			}
			ioaddr += biosize;	
			xsize  -= biosize;
		} else
			KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 322)) | DBG_FUNC_NONE,
				(int)uio->uio_offset, uio->uio_resid, error, -1, 0);

		if (p && (vp->v_flag & VTEXT) &&
				(((nmp->nm_flag & NFSMNT_NQNFS) &&
				NQNFS_CKINVALID(vp, np, ND_READ) &&
				np->n_lrev != np->n_brev) ||
				(!(nmp->nm_flag & NFSMNT_NQNFS) &&
				np->n_mtime != np->n_vattr.va_mtime.tv_sec))) { 
			uprintf("Process killed due to text file modification\n");
			psignal(p, SIGKILL);
			p->p_flag |= P_NOSWAP;
		}

	} while (error == 0 && xsize > 0);

	ubc_upl_unmap(pl);

	if (!nocommit) {
		if (error) 
			ubc_upl_abort_range(pl, pl_offset, size, 
					UPL_ABORT_ERROR |  UPL_ABORT_FREE_ON_EMPTY);
		else
			ubc_upl_commit_range(pl, pl_offset, size,
					UPL_COMMIT_CLEAR_DIRTY | UPL_COMMIT_FREE_ON_EMPTY);
	}

	return (error);
}



/*
 * Vnode op for pageout using UPL
 * Derived from nfs_write()
 * File size changes are not permitted in pageout.
 */
static int
nfs_pageout(ap)
	struct vop_pageout_args /* {
		struct vnode *a_vp,
		upl_t 	a_pl,
		vm_offset_t   a_pl_offset,
		off_t         a_f_offset,
		size_t        a_size,
		struct ucred *a_cred,
		int           a_flags
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	upl_t pl = ap->a_pl;
	size_t size= ap->a_size;
	off_t f_offset = ap->a_f_offset;
	vm_offset_t pl_offset = ap->a_pl_offset;
	int flags  = ap->a_flags;
	int ioflag = ap->a_flags;
	register int biosize;
	struct proc *p = current_proc();
	struct nfsnode *np = VTONFS(vp);
	register struct ucred *cred;
	struct buf *bp;
	struct nfsmount *nmp = VFSTONFS(vp->v_mount);
	daddr_t lbn;
	int bufsize;
	int n = 0, on, error = 0, iomode, must_commit, s;
	off_t off;
	vm_offset_t ioaddr;
	struct uio	auio;
	struct iovec	aiov;
	struct uio * uio = &auio;
	int nocommit = flags & UPL_NOCOMMIT;
	int iosize;
	int pgsize;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 323)) | DBG_FUNC_NONE,
		(int)f_offset, size, pl, pl_offset, 0);

	if (UBCINVALID(vp)) {
#if DIAGNOSTIC
		panic("nfs_pageout: invalid vnode");
#endif
		return (EIO);
	}
	UBCINFOCHECK("nfs_pageout", vp);

	if (size <= 0)
		return (EINVAL);

	if (pl == (upl_t)NULL) {
		panic("nfs_pageout: no upl");
	}

	/*
	 * I use nm_rsize, not nm_wsize so that all buffer cache blocks
	 * will be the same size within a filesystem. nfs_writerpc will
	 * still use nm_wsize when sizing the rpc's.
	 */
	biosize = min(vp->v_mount->mnt_stat.f_iosize, size);

	if (biosize & PAGE_MASK)
		panic("nfs_pageout(%x): biosize not page aligned", biosize);


	/*
	 * Check to see whether the buffer is incore
	 * If incore and not busy invalidate it from the cache
	 * we should not find it BUSY, since we always do a 
	 * vm_fault_list_request in 'getblk' before returning
	 * which would block on the page busy status
	 */
	lbn = f_offset / PAGE_SIZE; /* to match the size getblk uses */
        
	for (iosize = size; iosize > 0; iosize -= PAGE_SIZE, lbn++) {

		s = splbio();
		if (bp = incore(vp, lbn)) {
			if (ISSET(bp->b_flags, B_BUSY)) {
				/* don't panic incore. just tell vm we are busy */
				(void) ubc_upl_abort(pl, NULL); 
				return(EBUSY);
			};

			bremfree(bp);
			SET(bp->b_flags, (B_BUSY | B_INVAL));
			brelse(bp);
		}
		splx(s);
	}

	cred = ubc_getcred(vp);
	if (cred == NOCRED)
		cred = ap->a_cred;

	if (np->n_flag & NWRITEERR) {
		np->n_flag &= ~NWRITEERR;
		if (!nocommit)
			ubc_upl_abort_range(pl, pl_offset, size, UPL_ABORT_FREE_ON_EMPTY);
		return (np->n_error);
	}
	if ((nmp->nm_flag & (NFSMNT_NFSV3 | NFSMNT_GOTFSINFO)) == NFSMNT_NFSV3)
		(void)nfs_fsinfo(nmp, vp, cred, p);

	if (f_offset < 0 || f_offset >= np->n_size ||
	   (f_offset & PAGE_MASK_64) || (size & PAGE_MASK)) {
		if (!nocommit)
			ubc_upl_abort_range(pl, pl_offset, size, UPL_ABORT_FREE_ON_EMPTY);
		return (EINVAL);
	}

	ubc_upl_map(pl, &ioaddr);

	if ((f_offset + size) > np->n_size)
		iosize = np->n_size - f_offset;
	else
		iosize = size;

	pgsize = (iosize + (PAGE_SIZE - 1)) & ~PAGE_MASK;

	if (size > pgsize) {
		if (!nocommit)
			ubc_upl_abort_range(pl, pl_offset + pgsize, size - pgsize,
					UPL_ABORT_FREE_ON_EMPTY);
	}
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_offset = f_offset;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_rw = UIO_READ;
	auio.uio_resid = iosize;
	auio.uio_procp = NULL;

	aiov.iov_len = iosize;
	aiov.iov_base = (caddr_t)ioaddr + pl_offset;

	/* 
	 * check for partial page and clear the
	 * contents past end of the file before
	 * releasing it in the VM page cache
	 */
	if ((f_offset < np->n_size) && (f_offset + size) > np->n_size) {
		size_t io = np->n_size - f_offset;

		bzero((caddr_t)(ioaddr + pl_offset + io), size - io);

		KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 321)) | DBG_FUNC_NONE,
			(int)np->n_size, (int)f_offset, (int)f_offset + io, size - io, 0);
	}

	do {

#warning nfs_pageout does not support NQNFS yet.
#if 0 /* why bother? */
/* NO RESOURCES TO FIX NQNFS CASE */
/* We need to deal with this later -- Umesh */

		/*
		 * Check for a valid write lease.
		 */
		if ((nmp->nm_flag & NFSMNT_NQNFS) &&
		    NQNFS_CKINVALID(vp, np, ND_WRITE)) {
			do {
				error = nqnfs_getlease(vp, ND_WRITE, cred, p);
			} while (error == NQNFS_EXPIRED);
			if (error) {
				ubc_upl_unmap(pl);
				if (!nocommit)
					ubc_upl_abort_range(pl, pl_offset, size, 
							UPL_ABORT_FREE_ON_EMPTY);
				return (error);
			}
			if (np->n_lrev != np->n_brev ||
			    (np->n_flag & NQNFSNONCACHE)) {
				error = nfs_vinvalbuf(vp, V_SAVE, cred, p, 1);
				if (error) {
					ubc_upl_unmap(pl);
					if (!nocommit)
						ubc_upl_abort_range(pl, pl_offset, size, 
					 			UPL_ABORT_FREE_ON_EMPTY);
					return (error);
				}
				np->n_brev = np->n_lrev;
			}
		}
#endif 0 /* why bother? */

		if ((np->n_flag & NQNFSNONCACHE) && uio->uio_iovcnt == 1) {
			iomode = NFSV3WRITE_FILESYNC;
			error = nfs_writerpc(vp, uio, cred, &iomode, &must_commit);
			if (must_commit)
				nfs_clearcommit(vp->v_mount);
			ubc_upl_unmap(pl);
                        
			/* copied from non-nqnfs case below. see there for comments */
			if (!nocommit) {
				if (error) {
					int abortflags; 
					short action = nfs_pageouterrorhandler(error);
					
					switch (action) {
						case DUMP:
							abortflags = UPL_ABORT_DUMP_PAGES|UPL_ABORT_FREE_ON_EMPTY;
							break;
						case DUMPANDLOG:
							abortflags = UPL_ABORT_DUMP_PAGES|UPL_ABORT_FREE_ON_EMPTY;
							if ((error <= ELAST) && (errorcount[error] % 100 == 0)) 
								printf("nfs_pageout: unexpected error %d. dumping vm page\n", error);
							errorcount[error]++;
							break;
						case RETRY:
							abortflags = UPL_ABORT_FREE_ON_EMPTY;
							break;
						case RETRYWITHSLEEP:
							abortflags = UPL_ABORT_FREE_ON_EMPTY;
							(void) tsleep(&lbolt, PSOCK, "nfspageout", 0); /* pri unused. PSOCK for placeholder. */
							break;
						case SEVER: /* not implemented */
						default:
							printf("nfs_pageout: action %d not expected\n", action);
							break;
					}
						
					ubc_upl_abort_range(pl, pl_offset, size, abortflags);
					/* return error in all cases above */

				} else
					ubc_upl_commit_range(pl, 
						pl_offset, size, 
						UPL_COMMIT_CLEAR_DIRTY | UPL_COMMIT_FREE_ON_EMPTY);
			}
			return (error); /* note this early return */
		}

		nfsstats.pageouts++;
		lbn = uio->uio_offset / biosize;
		on = uio->uio_offset & (biosize-1);
		n = min((unsigned)(biosize - on), uio->uio_resid);
again:
		bufsize = biosize;
#if 0
		if ((lbn + 1) * biosize > np->n_size) {
			bufsize = np->n_size - lbn * biosize;
			bufsize = (bufsize + DEV_BSIZE - 1) & ~(DEV_BSIZE - 1);
		}
#endif
		vp->v_numoutput++;

		np->n_flag |= NMODIFIED;

#if 0 /* why bother? */
/* NO RESOURCES TO FIX NQNFS CASE */
/* We need to deal with this later -- Umesh */
		/*
		 * Check for valid write lease and get one as required.
		 * In case getblk() and/or bwrite() delayed us.
		 */
		if ((nmp->nm_flag & NFSMNT_NQNFS) &&
		    NQNFS_CKINVALID(vp, np, ND_WRITE)) {
			do {
				error = nqnfs_getlease(vp, ND_WRITE, cred, p);
			} while (error == NQNFS_EXPIRED);
			if (error)
				goto cleanup;

			if (np->n_lrev != np->n_brev ||
			    (np->n_flag & NQNFSNONCACHE)) {
					error = nfs_vinvalbuf(vp, V_SAVE, cred, p, 1);
					if (error) {
						ubc_upl_unmap(pl);
						if (!nocommit)
							ubc_upl_abort_range(pl, pl_offset, size,
									UPL_ABORT_FREE_ON_EMPTY);

						return (error);
					}
					np->n_brev = np->n_lrev;
					goto again;
			}
		}
#endif 0 /* why bother? */

		iomode = NFSV3WRITE_FILESYNC;
		error = nfs_writerpc(vp, uio, cred, &iomode, &must_commit);
		if (must_commit)
			nfs_clearcommit(vp->v_mount);
		vp->v_numoutput--;

		if (error)
			goto cleanup;

		if (n > 0) {
			uio->uio_resid -= n;
			uio->uio_offset += n;
			uio->uio_iov->iov_base += n;
			uio->uio_iov->iov_len -= n;
		}
	} while (uio->uio_resid > 0 && n > 0);

cleanup:
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
	 * ELAST. Those along with NFS known server errors we will "dump" from vm. 
	 * Errors we don't expect to occur, we dump and log for further
	 * analysis. Errors that could be transient, networking ones,
	 * we let vm "retry". Lastly, errors that we retry, but may have potential
	 * to storm the network, we "retrywithsleep". "sever" will be used in
	 * in the future to dump all pages of object for cases like ESTALE.
	 * All this is the basis for the states returned and first guesses on
	 * error handling. Tweaking expected as more statistics are gathered.
	 * Note, in the long run we may need another more robust solution to
	 * have some kind of persistant store when the vm cannot dump nor keep
	 * retrying as a solution, but this would be a file architectural change.
	 */
	  
	if (!nocommit) { /* otherwise stacked file system has to handle this */
		if (error) {
			int abortflags; 
			short action = nfs_pageouterrorhandler(error);
			
			switch (action) {
				case DUMP:
					abortflags = UPL_ABORT_DUMP_PAGES|UPL_ABORT_FREE_ON_EMPTY;
					break;
				case DUMPANDLOG:
					abortflags = UPL_ABORT_DUMP_PAGES|UPL_ABORT_FREE_ON_EMPTY;
					if ((error <= ELAST) && (errorcount[error] % 100 == 0)) 
						printf("nfs_pageout: unexpected error %d. dumping vm page\n", error);
					errorcount[error]++;
					break;
				case RETRY:
					abortflags = UPL_ABORT_FREE_ON_EMPTY;
					break;
				case RETRYWITHSLEEP:
					abortflags = UPL_ABORT_FREE_ON_EMPTY;
					(void) tsleep(&lbolt, PSOCK, "nfspageout", 0); /* pri unused. PSOCK for placeholder. */
					break;
				case SEVER: /* not implemented */
				default:
					printf("nfs_pageout: action %d not expected\n", action);
					break;
			}
				
			ubc_upl_abort_range(pl, pl_offset, size, abortflags);
			/* return error in all cases above */
			
		} else 
			ubc_upl_commit_range(pl, pl_offset, pgsize,
				UPL_COMMIT_CLEAR_DIRTY | UPL_COMMIT_FREE_ON_EMPTY);
	}
	return (error);
}

/* Blktooff derives file offset given a logical block number */
static int
nfs_blktooff(ap)
	struct vop_blktooff_args /* {
		struct vnode *a_vp;
		daddr_t a_lblkno;
		off_t *a_offset;    
	} */ *ap;
{
	int biosize;
	register struct vnode *vp = ap->a_vp;

	biosize = min(vp->v_mount->mnt_stat.f_iosize, PAGE_SIZE); /* nfs_bio.c */

	*ap->a_offset = (off_t)(ap->a_lblkno *  biosize);

	return (0);
}

/* Blktooff derives file offset given a logical block number */
static int
nfs_offtoblk(ap)
	struct vop_offtoblk_args /* {
		struct vnode *a_vp;
		off_t a_offset;    
		daddr_t *a_lblkno;
	} */ *ap;
{
	int biosize;
	register struct vnode *vp = ap->a_vp;

	biosize = min(vp->v_mount->mnt_stat.f_iosize, PAGE_SIZE); /* nfs_bio.c */

	*ap->a_lblkno = (daddr_t)(ap->a_offset /  biosize);

	return (0);
}
static int
nfs_cmap(ap)
	struct vop_cmap_args /* {
		struct vnode *a_vp;
		off_t a_offset;    
		size_t a_size;
		daddr_t *a_bpn;
		size_t *a_run;
		void *a_poff;
	} */ *ap;
{
	return (EOPNOTSUPP);
}
