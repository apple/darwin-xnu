/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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

#include <sys/kdebug.h>

#define FSDBG(A, B, C, D, E) \
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, (A))) | DBG_FUNC_NONE, \
		(int)(B), (int)(C), (int)(D), (int)(E), 0)
#define FSDBG_TOP(A, B, C, D, E) \
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, (A))) | DBG_FUNC_START, \
		(int)(B), (int)(C), (int)(D), (int)(E), 0)
#define FSDBG_BOT(A, B, C, D, E) \
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, (A))) | DBG_FUNC_END, \
		(int)(B), (int)(C), (int)(D), (int)(E), 0)

static int	nfsspec_read(struct vnop_read_args *);
static int	nfsspec_write(struct vnop_write_args *);
static int	nfsfifo_read(struct vnop_read_args *);
static int	nfsfifo_write(struct vnop_write_args *);
static int	nfsspec_close(struct vnop_close_args *);
static int	nfsfifo_close(struct vnop_close_args *);
static int	nfs_ioctl(struct vnop_ioctl_args *);
static int	nfs_select(struct vnop_select_args *);
static int	nfs_setattrrpc(vnode_t,struct vnode_attr *,kauth_cred_t,proc_t);
static	int	nfs_lookup(struct vnop_lookup_args *);
static	int	nfs_create(struct vnop_create_args *);
static	int	nfs_mknod(struct vnop_mknod_args *);
static	int	nfs_open(struct vnop_open_args *);
static	int	nfs_close(struct vnop_close_args *);
static	int	nfs_access(struct vnop_access_args *);
static	int	nfs_vnop_getattr(struct vnop_getattr_args *);
static	int	nfs_setattr(struct vnop_setattr_args *);
static	int	nfs_read(struct vnop_read_args *);
static	int	nfs_mmap(struct vnop_mmap_args *);
static	int	nfs_fsync(struct vnop_fsync_args *);
static	int	nfs_remove(struct vnop_remove_args *);
static	int	nfs_link(struct vnop_link_args *);
static	int	nfs_rename(struct vnop_rename_args *);
static	int	nfs_mkdir(struct vnop_mkdir_args *);
static	int	nfs_rmdir(struct vnop_rmdir_args *);
static	int	nfs_symlink(struct vnop_symlink_args *);
static	int	nfs_readdir(struct vnop_readdir_args *);
static	int	nfs_lookitup(vnode_t,char *,int,kauth_cred_t,proc_t,struct nfsnode **);
static	int	nfs_sillyrename(vnode_t,vnode_t,struct componentname *,kauth_cred_t,proc_t);
static int	nfs_readlink(struct vnop_readlink_args *);
static int	nfs_pathconf(struct vnop_pathconf_args *);
static int	nfs_advlock(struct vnop_advlock_args *);
static	int	nfs_pagein(struct vnop_pagein_args *);
static	int	nfs_pageout(struct vnop_pageout_args *);
static	int nfs_blktooff(struct vnop_blktooff_args *);
static	int nfs_offtoblk(struct vnop_offtoblk_args *);
static	int nfs_blockmap(struct vnop_blockmap_args *);

/*
 * Global vfs data structures for nfs
 */
vnop_t **nfsv2_vnodeop_p;
static struct vnodeopv_entry_desc nfsv2_vnodeop_entries[] = {
	{ &vnop_default_desc, (vnop_t *)vn_default_error },
	{ &vnop_lookup_desc, (vnop_t *)nfs_lookup },		/* lookup */
	{ &vnop_create_desc, (vnop_t *)nfs_create },		/* create */
	{ &vnop_mknod_desc, (vnop_t *)nfs_mknod },		/* mknod */
	{ &vnop_open_desc, (vnop_t *)nfs_open },		/* open */
	{ &vnop_close_desc, (vnop_t *)nfs_close },		/* close */
	{ &vnop_access_desc, (vnop_t *)nfs_access },		/* access */
	{ &vnop_getattr_desc, (vnop_t *)nfs_vnop_getattr },	/* getattr */
	{ &vnop_setattr_desc, (vnop_t *)nfs_setattr },		/* setattr */
	{ &vnop_read_desc, (vnop_t *)nfs_read },		/* read */
	{ &vnop_write_desc, (vnop_t *)nfs_write },		/* write */
	{ &vnop_ioctl_desc, (vnop_t *)nfs_ioctl },		/* ioctl */
	{ &vnop_select_desc, (vnop_t *)nfs_select },		/* select */
	{ &vnop_revoke_desc, (vnop_t *)nfs_revoke },		/* revoke */
	{ &vnop_mmap_desc, (vnop_t *)nfs_mmap },		/* mmap */
	{ &vnop_fsync_desc, (vnop_t *)nfs_fsync },		/* fsync */
	{ &vnop_remove_desc, (vnop_t *)nfs_remove },		/* remove */
	{ &vnop_link_desc, (vnop_t *)nfs_link },		/* link */
	{ &vnop_rename_desc, (vnop_t *)nfs_rename },		/* rename */
	{ &vnop_mkdir_desc, (vnop_t *)nfs_mkdir },		/* mkdir */
	{ &vnop_rmdir_desc, (vnop_t *)nfs_rmdir },		/* rmdir */
	{ &vnop_symlink_desc, (vnop_t *)nfs_symlink },		/* symlink */
	{ &vnop_readdir_desc, (vnop_t *)nfs_readdir },		/* readdir */
	{ &vnop_readlink_desc, (vnop_t *)nfs_readlink },	/* readlink */
	{ &vnop_inactive_desc, (vnop_t *)nfs_inactive },	/* inactive */
	{ &vnop_reclaim_desc, (vnop_t *)nfs_reclaim },		/* reclaim */
	{ &vnop_strategy_desc, (vnop_t *)err_strategy },	/* strategy */
	{ &vnop_pathconf_desc, (vnop_t *)nfs_pathconf },	/* pathconf */
	{ &vnop_advlock_desc, (vnop_t *)nfs_advlock },		/* advlock */
	{ &vnop_bwrite_desc, (vnop_t *)err_bwrite },		/* bwrite */
	{ &vnop_pagein_desc, (vnop_t *)nfs_pagein },		/* Pagein */
	{ &vnop_pageout_desc, (vnop_t *)nfs_pageout },		/* Pageout */
	{ &vnop_copyfile_desc, (vnop_t *)err_copyfile },	/* Copyfile */
	{ &vnop_blktooff_desc, (vnop_t *)nfs_blktooff },	/* blktooff */
	{ &vnop_offtoblk_desc, (vnop_t *)nfs_offtoblk },	/* offtoblk */
	{ &vnop_blockmap_desc, (vnop_t *)nfs_blockmap },	/* blockmap */
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
vnop_t **spec_nfsv2nodeop_p;
static struct vnodeopv_entry_desc spec_nfsv2nodeop_entries[] = {
	{ &vnop_default_desc, (vnop_t *)vn_default_error },
	{ &vnop_lookup_desc, (vnop_t *)spec_lookup },		/* lookup */
	{ &vnop_create_desc, (vnop_t *)spec_create },		/* create */
	{ &vnop_mknod_desc, (vnop_t *)spec_mknod },		/* mknod */
	{ &vnop_open_desc, (vnop_t *)spec_open },		/* open */
	{ &vnop_close_desc, (vnop_t *)nfsspec_close },		/* close */
	{ &vnop_getattr_desc, (vnop_t *)nfs_vnop_getattr },	/* getattr */
	{ &vnop_setattr_desc, (vnop_t *)nfs_setattr },		/* setattr */
	{ &vnop_read_desc, (vnop_t *)nfsspec_read },		/* read */
	{ &vnop_write_desc, (vnop_t *)nfsspec_write },		/* write */
	{ &vnop_ioctl_desc, (vnop_t *)spec_ioctl },		/* ioctl */
	{ &vnop_select_desc, (vnop_t *)spec_select },		/* select */
	{ &vnop_revoke_desc, (vnop_t *)spec_revoke },		/* revoke */
	{ &vnop_mmap_desc, (vnop_t *)spec_mmap },		/* mmap */
	{ &vnop_fsync_desc, (vnop_t *)nfs_fsync },		/* fsync */
	{ &vnop_remove_desc, (vnop_t *)spec_remove },		/* remove */
	{ &vnop_link_desc, (vnop_t *)spec_link },		/* link */
	{ &vnop_rename_desc, (vnop_t *)spec_rename },		/* rename */
	{ &vnop_mkdir_desc, (vnop_t *)spec_mkdir },		/* mkdir */
	{ &vnop_rmdir_desc, (vnop_t *)spec_rmdir },		/* rmdir */
	{ &vnop_symlink_desc, (vnop_t *)spec_symlink },		/* symlink */
	{ &vnop_readdir_desc, (vnop_t *)spec_readdir },		/* readdir */
	{ &vnop_readlink_desc, (vnop_t *)spec_readlink },	/* readlink */
	{ &vnop_inactive_desc, (vnop_t *)nfs_inactive },	/* inactive */
	{ &vnop_reclaim_desc, (vnop_t *)nfs_reclaim },		/* reclaim */
	{ &vnop_strategy_desc, (vnop_t *)spec_strategy },	/* strategy */
	{ &vnop_pathconf_desc, (vnop_t *)spec_pathconf },	/* pathconf */
	{ &vnop_advlock_desc, (vnop_t *)spec_advlock },		/* advlock */
	{ &vnop_bwrite_desc, (vnop_t *)vn_bwrite },		/* bwrite */
	{ &vnop_pagein_desc, (vnop_t *)nfs_pagein },		/* Pagein */
	{ &vnop_pageout_desc, (vnop_t *)nfs_pageout },		/* Pageout */
	{ &vnop_blktooff_desc, (vnop_t *)nfs_blktooff },	/* blktooff */
	{ &vnop_offtoblk_desc, (vnop_t *)nfs_offtoblk },	/* offtoblk */
	{ &vnop_blockmap_desc, (vnop_t *)nfs_blockmap },	/* blockmap */
	{ NULL, NULL }
};
struct vnodeopv_desc spec_nfsv2nodeop_opv_desc =
	{ &spec_nfsv2nodeop_p, spec_nfsv2nodeop_entries };
#ifdef __FreeBSD__
VNODEOP_SET(spec_nfsv2nodeop_opv_desc);
#endif

vnop_t **fifo_nfsv2nodeop_p;
static struct vnodeopv_entry_desc fifo_nfsv2nodeop_entries[] = {
	{ &vnop_default_desc, (vnop_t *)vn_default_error },
	{ &vnop_lookup_desc, (vnop_t *)fifo_lookup },		/* lookup */
	{ &vnop_create_desc, (vnop_t *)fifo_create },		/* create */
	{ &vnop_mknod_desc, (vnop_t *)fifo_mknod },		/* mknod */
	{ &vnop_open_desc, (vnop_t *)fifo_open },		/* open */
	{ &vnop_close_desc, (vnop_t *)nfsfifo_close },		/* close */
	{ &vnop_getattr_desc, (vnop_t *)nfs_vnop_getattr },	/* getattr */
	{ &vnop_setattr_desc, (vnop_t *)nfs_setattr },		/* setattr */
	{ &vnop_read_desc, (vnop_t *)nfsfifo_read },		/* read */
	{ &vnop_write_desc, (vnop_t *)nfsfifo_write },		/* write */
	{ &vnop_ioctl_desc, (vnop_t *)fifo_ioctl },		/* ioctl */
	{ &vnop_select_desc, (vnop_t *)fifo_select },		/* select */
	{ &vnop_revoke_desc, (vnop_t *)fifo_revoke },		/* revoke */
	{ &vnop_mmap_desc, (vnop_t *)fifo_mmap },		/* mmap */
	{ &vnop_fsync_desc, (vnop_t *)nfs_fsync },		/* fsync */
	{ &vnop_remove_desc, (vnop_t *)fifo_remove },		/* remove */
	{ &vnop_link_desc, (vnop_t *)fifo_link },		/* link */
	{ &vnop_rename_desc, (vnop_t *)fifo_rename },		/* rename */
	{ &vnop_mkdir_desc, (vnop_t *)fifo_mkdir },		/* mkdir */
	{ &vnop_rmdir_desc, (vnop_t *)fifo_rmdir },		/* rmdir */
	{ &vnop_symlink_desc, (vnop_t *)fifo_symlink },		/* symlink */
	{ &vnop_readdir_desc, (vnop_t *)fifo_readdir },		/* readdir */
	{ &vnop_readlink_desc, (vnop_t *)fifo_readlink },	/* readlink */
	{ &vnop_inactive_desc, (vnop_t *)nfs_inactive },	/* inactive */
	{ &vnop_reclaim_desc, (vnop_t *)nfs_reclaim },		/* reclaim */
	{ &vnop_strategy_desc, (vnop_t *)fifo_strategy },	/* strategy */
	{ &vnop_pathconf_desc, (vnop_t *)fifo_pathconf },	/* pathconf */
	{ &vnop_advlock_desc, (vnop_t *)fifo_advlock },		/* advlock */
	{ &vnop_bwrite_desc, (vnop_t *)vn_bwrite },		/* bwrite */
	{ &vnop_pagein_desc, (vnop_t *)nfs_pagein },		/* Pagein */
	{ &vnop_pageout_desc, (vnop_t *)nfs_pageout },		/* Pageout */
	{ &vnop_blktooff_desc, (vnop_t *)nfs_blktooff },	/* blktooff */
	{ &vnop_offtoblk_desc, (vnop_t *)nfs_offtoblk },	/* offtoblk */
	{ &vnop_blockmap_desc, (vnop_t *)nfs_blockmap },	/* blockmap */
	{ NULL, NULL }
};
struct vnodeopv_desc fifo_nfsv2nodeop_opv_desc =
	{ &fifo_nfsv2nodeop_p, fifo_nfsv2nodeop_entries };
#ifdef __FreeBSD__
VNODEOP_SET(fifo_nfsv2nodeop_opv_desc);
#endif

static int	nfs_mknodrpc(vnode_t dvp, vnode_t *vpp,
				struct componentname *cnp,
				struct vnode_attr *vap,
				kauth_cred_t cred, proc_t p);
static int	nfs_removerpc(vnode_t dvp, char *name, int namelen,
				kauth_cred_t cred, proc_t proc);
static int	nfs_renamerpc(vnode_t fdvp, char *fnameptr,
				int fnamelen, vnode_t tdvp,
				char *tnameptr, int tnamelen,
				kauth_cred_t cred, proc_t proc);

/*
 * Global variables
 */
extern u_long nfs_xdrneg1;
extern u_long nfs_true, nfs_false;
extern struct nfsstats nfsstats;
extern nfstype nfsv3_type[9];
proc_t nfs_iodwant[NFS_MAXASYNCDAEMON];
struct nfsmount *nfs_iodmount[NFS_MAXASYNCDAEMON];

lck_grp_t *nfs_iod_lck_grp;
lck_grp_attr_t *nfs_iod_lck_grp_attr;
lck_attr_t *nfs_iod_lck_attr;
lck_mtx_t *nfs_iod_mutex;

int nfs_numasync = 0;
int nfs_ioddelwri = 0;

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
nfs_pageouterrorhandler(int error)
{
	if (error > ELAST) 
		return(DUMP);
	else 
		return(errortooutcome[error]);
}

static int
nfs3_access_otw(vnode_t vp,  
		int wmode,
		proc_t p,
		kauth_cred_t cred)  
{
	const int v3 = 1;
	u_long *tl;
	int error = 0, attrflag;

	mbuf_t mreq, mrep, md, mb, mb2;
	caddr_t bpos, dpos, cp2;
	register long t1, t2;
	register caddr_t cp;
	u_int32_t rmode;
	struct nfsnode *np = VTONFS(vp);
	u_int64_t xid;
	struct timeval now;

	nfsm_reqhead(NFSX_FH(v3) + NFSX_UNSIGNED);
	if (error)
		return (error);
	OSAddAtomic(1, (SInt32*)&nfsstats.rpccnt[NFSPROC_ACCESS]);   
	nfsm_fhtom(vp, v3);
	nfsm_build(tl, u_long *, NFSX_UNSIGNED);
	*tl = txdr_unsigned(wmode);
	nfsm_request(vp, NFSPROC_ACCESS, p, cred, &xid);
	if (mrep) {
		nfsm_postop_attr_update(vp, 1, attrflag, &xid);
	}
	if (!error) {
		nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
		rmode = fxdr_unsigned(u_int32_t, *tl);
		np->n_mode = rmode;
		np->n_modeuid = kauth_cred_getuid(cred);
		microuptime(&now);
		np->n_modestamp = now.tv_sec;
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
	struct vnop_access_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		int a_mode;
		vfs_context_t a_context;
	} */ *ap;
{
	vnode_t vp = ap->a_vp;
	int error = 0, dorpc;
	u_long mode, wmode;
	int v3 = NFS_ISV3(vp);
	struct nfsnode *np = VTONFS(vp);
	struct timeval now;
	kauth_cred_t cred;

	/*
	 * For nfs v3, do an access rpc, otherwise you are stuck emulating
	 * ufs_access() locally using the vattr. This may not be correct,
	 * since the server may apply other access criteria such as
	 * client uid-->server uid mapping that we do not know about, but
	 * this is better than just returning anything that is lying about
	 * in the cache.
	 */
	if (v3) {
		/*
		 * Convert KAUTH primitives to NFS access rights.
		 */
		mode = 0;
		if (vnode_isdir(vp)) {
			/* directory */
			if (ap->a_action &
			    (KAUTH_VNODE_LIST_DIRECTORY |
			    KAUTH_VNODE_READ_EXTATTRIBUTES))
				mode |= NFSV3ACCESS_READ;
			if (ap->a_action & KAUTH_VNODE_SEARCH)
				mode |= NFSV3ACCESS_LOOKUP;
			if (ap->a_action &
			    (KAUTH_VNODE_ADD_FILE |
			    KAUTH_VNODE_ADD_SUBDIRECTORY))
				mode |= NFSV3ACCESS_MODIFY | NFSV3ACCESS_EXTEND;
			if (ap->a_action & KAUTH_VNODE_DELETE_CHILD)
				mode |= NFSV3ACCESS_MODIFY;
		} else {
			/* file */
			if (ap->a_action &
			    (KAUTH_VNODE_READ_DATA |
			    KAUTH_VNODE_READ_EXTATTRIBUTES))
				mode |= NFSV3ACCESS_READ;
			if (ap->a_action & KAUTH_VNODE_WRITE_DATA)
				mode |= NFSV3ACCESS_MODIFY | NFSV3ACCESS_EXTEND;
			if (ap->a_action & KAUTH_VNODE_APPEND_DATA)
				mode |= NFSV3ACCESS_EXTEND;
			if (ap->a_action & KAUTH_VNODE_EXECUTE)
				mode |= NFSV3ACCESS_EXECUTE;
		}
		/* common */
		if (ap->a_action & KAUTH_VNODE_DELETE)
			mode |= NFSV3ACCESS_DELETE;
		if (ap->a_action &
		    (KAUTH_VNODE_WRITE_ATTRIBUTES |
		    KAUTH_VNODE_WRITE_EXTATTRIBUTES |
		    KAUTH_VNODE_WRITE_SECURITY))
			mode |= NFSV3ACCESS_MODIFY;
		/* XXX this is pretty dubious */
		if (ap->a_action & KAUTH_VNODE_CHANGE_OWNER)
			mode |= NFSV3ACCESS_MODIFY;

		/* if caching, always ask for every right */
		if (nfsaccess_cache_timeout > 0) {
			wmode = NFSV3ACCESS_READ | NFSV3ACCESS_MODIFY |
				NFSV3ACCESS_EXTEND | NFSV3ACCESS_EXECUTE |
				NFSV3ACCESS_DELETE | NFSV3ACCESS_LOOKUP;
		} else
			wmode = mode;
                
		cred = vfs_context_ucred(ap->a_context);

		/*
		 * Does our cached result allow us to give a definite yes to
		 * this request?
		 */     
		dorpc = 1;
		if (NMODEVALID(np)) {
			microuptime(&now);
			if ((now.tv_sec < (np->n_modestamp + nfsaccess_cache_timeout)) &&
			    (kauth_cred_getuid(cred) == np->n_modeuid) &&
			    ((np->n_mode & mode) == mode)) {
				/* OSAddAtomic(1, (SInt32*)&nfsstats.accesscache_hits); */
				dorpc = 0;
			}
		}
		if (dorpc) {
			/* Either a no, or a don't know.  Go to the wire. */
			/* OSAddAtomic(1, (SInt32*)&nfsstats.accesscache_misses); */
			error = nfs3_access_otw(vp, wmode, vfs_context_proc(ap->a_context), cred);
		}
		if (!error) {
			/*
			 * If we asked for DELETE but didn't get it, the server
			 * may simply not support returning that bit (possible
			 * on UNIX systems).  So, we'll assume that it is OK,
			 * and just let any subsequent delete action fail if it
			 * really isn't deletable.
			 */
			if ((mode & NFSV3ACCESS_DELETE) &&
			    !(np->n_mode & NFSV3ACCESS_DELETE))
				np->n_mode |= NFSV3ACCESS_DELETE;
			if ((np->n_mode & mode) != mode)
				error = EACCES;
		}
	} else {
		/* v2 */
		if ((ap->a_action & KAUTH_VNODE_WRITE_RIGHTS) && vfs_isrdonly(vnode_mount(vp))) {
			error = EROFS;
		} else {
			error = 0;
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
	struct vnop_open_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		int a_mode;
		vfs_context_t a_context;
	} */ *ap;
{
	vnode_t vp = ap->a_vp;
	struct nfsnode *np = VTONFS(vp);
	struct nfs_vattr nvattr;
	kauth_cred_t cred;
	proc_t p;
	enum vtype vtype;
	int error;

	vtype = vnode_vtype(vp);
	if (vtype != VREG && vtype != VDIR && vtype != VLNK) {
		return (EACCES);
	}

	cred = vfs_context_ucred(ap->a_context);
	p = vfs_context_proc(ap->a_context);

	if (np->n_flag & NNEEDINVALIDATE) {
		np->n_flag &= ~NNEEDINVALIDATE;
		nfs_vinvalbuf(vp, V_SAVE|V_IGNORE_WRITEERR, cred, p, 1);
	}
	if (np->n_flag & NMODIFIED) {
		if ((error = nfs_vinvalbuf(vp, V_SAVE, cred, p, 1)) == EINTR)
			return (error);
		NATTRINVALIDATE(np);
		if (vtype == VDIR)
			np->n_direofoffset = 0;
		error = nfs_getattr(vp, &nvattr, cred, p);
		if (error)
			return (error);
		if (vtype == VDIR) {
			/* if directory changed, purge any name cache entries */
			if (nfstimespeccmp(&np->n_ncmtime, &nvattr.nva_mtime, !=))
				cache_purge(vp);
			np->n_ncmtime = nvattr.nva_mtime;
		}
		np->n_mtime = nvattr.nva_mtime;
	} else {
		error = nfs_getattr(vp, &nvattr, cred, p);
		if (error)
			return (error);
		if (nfstimespeccmp(&np->n_mtime, &nvattr.nva_mtime, !=)) {
			if (vtype == VDIR) {
				np->n_direofoffset = 0;
				nfs_invaldir(vp);
				/* purge name cache entries */
				if (nfstimespeccmp(&np->n_ncmtime, &nvattr.nva_mtime, !=))
					cache_purge(vp);
			}
			if ((error = nfs_vinvalbuf(vp, V_SAVE, cred, p, 1)) == EINTR)
				return (error);
			if (vtype == VDIR)
				np->n_ncmtime = nvattr.nva_mtime;
			np->n_mtime = nvattr.nva_mtime;
		}
	}
	NATTRINVALIDATE(np); /* For Open/Close consistency */
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
 *                     them.
 */
/* ARGSUSED */
static int
nfs_close(ap)
	struct vnop_close_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		int a_fflag;
		vfs_context_t a_context;
	} */ *ap;
{
	vnode_t vp = ap->a_vp;
	struct nfsnode *np = VTONFS(vp);
	struct nfsmount *nmp;
	kauth_cred_t cred;
	proc_t p;
	int error = 0;

	cred = vfs_context_ucred(ap->a_context);
	p = vfs_context_proc(ap->a_context);

	if (vnode_vtype(vp) == VREG) {
#if DIAGNOSTIC
	    register struct sillyrename *sp = np->n_sillyrename;
	    if (sp)
                kprintf("nfs_close: %s, dvp=%x, vp=%x, ap=%x, np=%x, sp=%x\n",
                	&sp->s_name[0], (unsigned)(sp->s_dvp), (unsigned)vp,
                	(unsigned)ap, (unsigned)np, (unsigned)sp);
#endif
	    nmp = VFSTONFS(vnode_mount(vp));
	    if (!nmp)
	   	return (ENXIO);
	    if (np->n_flag & NNEEDINVALIDATE) {
		np->n_flag &= ~NNEEDINVALIDATE;
		nfs_vinvalbuf(vp, V_SAVE|V_IGNORE_WRITEERR, cred, p, 1);
	    }
	    if (np->n_flag & NMODIFIED) {
		if (NFS_ISV3(vp)) {
		    error = nfs_flush(vp, MNT_WAIT, cred, p, 0);
                    /*
                     * We cannot clear the NMODIFIED bit in np->n_flag due to
                     * potential races with other processes
		     * NMODIFIED is a hint
                     */
		    /* np->n_flag &= ~NMODIFIED; */
		} else {
		    error = nfs_vinvalbuf(vp, V_SAVE, cred, p, 1);
		}
		NATTRINVALIDATE(np);
	    }
	    if (np->n_flag & NWRITEERR) {
		np->n_flag &= ~NWRITEERR;
		error = np->n_error;
	    }
	}
	return (error);
}


int
nfs_getattr_no_vnode(
	mount_t mp,
	u_char *fhp,
	int fhsize,
	kauth_cred_t cred,
	proc_t p,
	struct nfs_vattr *nvap,
	u_int64_t *xidp)
{
	mbuf_t mreq, mrep, md, mb, mb2;
	caddr_t bpos, dpos;
	int t2;
	u_long *tl;
	caddr_t cp;
	struct nfsmount *nmp = VFSTONFS(mp);
	int v3 = (nmp->nm_flag & NFSMNT_NFSV3);
	int hsiz;
	int error = 0;

	// XXX fix this to use macros once the macros get cleaned up
	//nfsm_reqhead(NFSX_FH(v3));
		hsiz = NFSX_FH(v3);
		mb = NULL;
		if (hsiz >= nfs_mbuf_minclsize)
			error = mbuf_mclget(MBUF_WAITOK, MBUF_TYPE_DATA, &mb);
		else
			error = mbuf_get(MBUF_WAITOK, MBUF_TYPE_DATA, &mb);
		if (error)
			return (error);
		bpos = mbuf_data(mb);
		mreq = mb;
	OSAddAtomic(1, (SInt32*)&nfsstats.rpccnt[NFSPROC_GETATTR]);
	//nfsm_fhtom(vp, v3);
	      if (v3) {
			t2 = nfsm_rndup(fhsize) + NFSX_UNSIGNED;
			if (t2 <= mbuf_trailingspace(mb)) {
				nfsm_build(tl, u_long *, t2);
				*tl++ = txdr_unsigned(fhsize);
				*(tl + ((t2>>2) - 2)) = 0;
				bcopy((caddr_t)fhp,(caddr_t)tl, fhsize);
			} else if ((t2 = nfsm_strtmbuf(&mb, &bpos, (caddr_t)fhp, fhsize))) {
				error = t2;
				mbuf_freem(mreq);
				goto nfsmout;
			}
		} else {
			nfsm_build(cp, caddr_t, NFSX_V2FH);
			bcopy((caddr_t)fhp, cp, NFSX_V2FH);
		}
	//nfsm_request(vp, NFSPROC_GETATTR, p, cred, xidp);
		if ((error = nfs_request(NULL, mp, mreq, NFSPROC_GETATTR, p, cred, &mrep, &md, &dpos, xidp))) {
			if (error & NFSERR_RETERR)
				error &= ~NFSERR_RETERR;
			else
				goto nfsmout;
		}
	if (!error) {
		//nfsm_loadattr(vp, nvap, xidp);
		error = nfs_parsefattr(&md, &dpos, v3, nvap);
		if (error) {
			mbuf_freem(mrep);
			goto nfsmout;
		}
	}
	nfsm_reqdone;
	return (error);
}

/*
 * nfs getattr call from vfs.
 */
int
nfs_getattr(
	vnode_t vp,
	struct nfs_vattr *nvap,
	kauth_cred_t cred,
	proc_t p)
{
	struct nfsnode *np = VTONFS(vp);
	caddr_t cp;
	u_long *tl;
	int t1, t2;
	caddr_t bpos, dpos;
	int error = 0;
	mbuf_t mreq, mrep, md, mb, mb2;
	int v3;
	u_int64_t xid;
	int avoidfloods;

	FSDBG_TOP(513, np->n_size, np, np->n_vattr.nva_size, np->n_flag);

	/*
	 * Update local times for special files.
	 */
	if (np->n_flag & (NACC | NUPD))
		np->n_flag |= NCHG;
	/*
	 * First look in the cache.
	 */
	if ((error = nfs_getattrcache(vp, nvap)) == 0) {
		FSDBG_BOT(513, np->n_size, 0, np->n_vattr.nva_size, np->n_flag);
		return (0);
	}
	if (error != ENOENT) {
		FSDBG_BOT(513, np->n_size, error, np->n_vattr.nva_size,
			  np->n_flag);
		return (error);
	}

	if (!VFSTONFS(vnode_mount(vp))) {
		FSDBG_BOT(513, np->n_size, ENXIO, np->n_vattr.nva_size, np->n_flag);
		return (ENXIO);
	}
	v3 = NFS_ISV3(vp);
	error = 0;

	/*
	 * Try to get both the attributes and access info by making an
	 * ACCESS call and seeing if it returns updated attributes.
	 * But don't bother if we aren't caching access info or if the
	 * attributes returned wouldn't be cached.
	 */
	if (v3 && (nfsaccess_cache_timeout > 0) &&
	    (nfs_attrcachetimeout(vp) > 0)) {
		/*  OSAddAtomic(1, (SInt32*)&nfsstats.accesscache_misses); */
		if ((error = nfs3_access_otw(vp, NFSV3ACCESS_ALL, p, cred)))
			return (error);
		if ((error = nfs_getattrcache(vp, nvap)) == 0)
			return (0);
		if (error != ENOENT)
			return (error);
		error = 0;
	}
	avoidfloods = 0;
tryagain:
	nfsm_reqhead(NFSX_FH(v3));
	if (error) {
		FSDBG_BOT(513, np->n_size, error, np->n_vattr.nva_size, np->n_flag);
		return (error);
	}
	OSAddAtomic(1, (SInt32*)&nfsstats.rpccnt[NFSPROC_GETATTR]);
	nfsm_fhtom(vp, v3);
	nfsm_request(vp, NFSPROC_GETATTR, p, cred, &xid);
	if (!error) {
		nfsm_loadattr(vp, v3, nvap, &xid);
		if (!xid) { /* out-of-order rpc - attributes were dropped */
			mbuf_freem(mrep);
			mrep = NULL;
			FSDBG(513, -1, np, np->n_xid << 32, np->n_xid);
			if (avoidfloods++ < 100)
				goto tryagain;
			/*
			 * avoidfloods>1 is bizarre.  at 100 pull the plug
			 */
			panic("nfs_getattr: getattr flood\n");
		}
		if (nfstimespeccmp(&np->n_mtime, &nvap->nva_mtime, !=)) {
			enum vtype vtype = vnode_vtype(vp);
			FSDBG(513, -1, np, -1, vp);
			if (vtype == VDIR) {
				nfs_invaldir(vp);
				/* purge name cache entries */
				if (nfstimespeccmp(&np->n_ncmtime, &nvap->nva_mtime, !=))
					cache_purge(vp);
			}
			error = nfs_vinvalbuf(vp, V_SAVE, cred, p, 1);
			FSDBG(513, -1, np, -2, error);
			if (!error) {
				if (vtype == VDIR)
					np->n_ncmtime = nvap->nva_mtime;
				np->n_mtime = nvap->nva_mtime;
			}
		}
	}
	nfsm_reqdone;

	FSDBG_BOT(513, np->n_size, -1, np->n_vattr.nva_size, error);
	return (error);
}


static int
nfs_vnop_getattr(
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

	error = nfs_getattr(ap->a_vp, &nva,
		vfs_context_ucred(ap->a_context),
		vfs_context_proc(ap->a_context));
	if (error)
		return (error);

	/* copy nva to *a_vap */
 	VATTR_RETURN(vap, va_type, nva.nva_type);
 	VATTR_RETURN(vap, va_mode, nva.nva_mode);
 	VATTR_RETURN(vap, va_rdev, nva.nva_rdev);
 	VATTR_RETURN(vap, va_uid, nva.nva_uid);
 	VATTR_RETURN(vap, va_gid, nva.nva_gid);
 	VATTR_RETURN(vap, va_nlink, nva.nva_nlink);
 	VATTR_RETURN(vap, va_fileid, nva.nva_fileid);
 	VATTR_RETURN(vap, va_data_size, nva.nva_size);
 	VATTR_RETURN(vap, va_data_alloc, nva.nva_bytes);
 	VATTR_RETURN(vap, va_iosize, nva.nva_blocksize);  /* should this just be f_iosize? */
 	VATTR_RETURN(vap, va_fsid, nva.nva_fsid);
 	vap->va_access_time.tv_sec = nva.nva_atime.tv_sec;
 	vap->va_access_time.tv_nsec = nva.nva_atime.tv_nsec;
 	VATTR_SET_SUPPORTED(vap, va_access_time);
 	vap->va_modify_time.tv_sec = nva.nva_mtime.tv_sec;
 	vap->va_modify_time.tv_nsec = nva.nva_mtime.tv_nsec;
 	VATTR_SET_SUPPORTED(vap, va_modify_time);
 	vap->va_change_time.tv_sec = nva.nva_ctime.tv_sec;
 	vap->va_change_time.tv_nsec = nva.nva_ctime.tv_nsec;
 	VATTR_SET_SUPPORTED(vap, va_change_time);

	return (error);
}

/*
 * nfs setattr call.
 */
static int
nfs_setattr(ap)
	struct vnop_setattr_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		struct vnode_attr *a_vap;
		vfs_context_t a_context;
	} */ *ap;
{
	vnode_t vp = ap->a_vp;
	struct nfsnode *np = VTONFS(vp);
	struct vnode_attr *vap = ap->a_vap;
	int error = 0;
	u_quad_t tsize;
	kauth_cred_t cred;
	proc_t p;

#ifndef nolint
	tsize = (u_quad_t)0;
#endif

	/* Setting of flags is not supported. */
	if (VATTR_IS_ACTIVE(vap, va_flags))
		return (ENOTSUP);

	cred = vfs_context_ucred(ap->a_context);
	p = vfs_context_proc(ap->a_context);

	VATTR_SET_SUPPORTED(vap, va_mode);
	VATTR_SET_SUPPORTED(vap, va_uid);
	VATTR_SET_SUPPORTED(vap, va_gid);
	VATTR_SET_SUPPORTED(vap, va_data_size);
	VATTR_SET_SUPPORTED(vap, va_access_time);
	VATTR_SET_SUPPORTED(vap, va_modify_time);

	/* Disallow write attempts if the filesystem is mounted read-only. */
	if ((VATTR_IS_ACTIVE(vap, va_flags) || VATTR_IS_ACTIVE(vap, va_mode) ||
	     VATTR_IS_ACTIVE(vap, va_uid) || VATTR_IS_ACTIVE(vap, va_gid) ||
	     VATTR_IS_ACTIVE(vap, va_access_time) ||
	     VATTR_IS_ACTIVE(vap, va_modify_time)) &&
	    vnode_vfsisrdonly(vp))
		return (EROFS);

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
			    !VATTR_IS_ACTIVE(vap, va_gid))
				return (0);
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
			if (np->n_flag & NMODIFIED) {
 				if (vap->va_data_size == 0)
 					error = nfs_vinvalbuf(vp, 0, cred, p, 1);
 				else
 					error = nfs_vinvalbuf(vp, V_SAVE, cred, p, 1);
	 			if (error) {
					printf("nfs_setattr: nfs_vinvalbuf %d\n", error);
					FSDBG_BOT(512, np->n_size, vap->va_data_size,
						  np->n_vattr.nva_size, -1);
 					return (error);
				}
			} else if (np->n_size > vap->va_data_size) { /* shrinking? */
				daddr64_t obn, bn;
				int biosize, neweofoff, mustwrite;
				struct nfsbuf *bp;

				biosize = vfs_statfs(vnode_mount(vp))->f_iosize;
				obn = (np->n_size - 1) / biosize;
				bn = vap->va_data_size / biosize; 
				for ( ; obn >= bn; obn--) {
					if (!nfs_buf_is_incore(vp, obn))
						continue;
					error = nfs_buf_get(vp, obn, biosize, 0, NBLK_READ, &bp);
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
					if (bp->nb_dirtyend && bp->nb_dirtyoff < neweofoff) {
						/* clip dirty range to EOF */
						if (bp->nb_dirtyend > neweofoff)
							bp->nb_dirtyend = neweofoff;
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
					if (bp->nb_wcred == NOCRED) {
						kauth_cred_ref(cred);
						bp->nb_wcred = cred;
					}
					error = nfs_buf_write(bp);
					// Note: bp has been released
					if (error) {
						FSDBG(512, bp, 0xd00dee, 0xbad, error);
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
						nfs_vinvalbuf(vp, V_SAVE|V_IGNORE_WRITEERR, cred, p, 1);
						error = 0;
					}
				}
			}
 			tsize = np->n_size;
			np->n_size = np->n_vattr.nva_size = vap->va_data_size;
			ubc_setsize(vp, (off_t)vap->va_data_size); /* XXX error? */
  		}
	} else if ((VATTR_IS_ACTIVE(vap, va_modify_time) ||
		    VATTR_IS_ACTIVE(vap, va_access_time)) &&
		   (np->n_flag & NMODIFIED) && (vnode_vtype(vp) == VREG)) {
		error = nfs_vinvalbuf(vp, V_SAVE, cred, p, 1);
		if (error == EINTR)
			return (error);
	}
	if (VATTR_IS_ACTIVE(vap, va_mode)) {
		NMODEINVALIDATE(np);
	}
	error = nfs_setattrrpc(vp, vap, cred, p);
	FSDBG_BOT(512, np->n_size, vap->va_data_size, np->n_vattr.nva_size, error);
	if (error && VATTR_IS_ACTIVE(vap, va_data_size)) {
		/* make every effort to resync file size w/ server... */
		int err; /* preserve "error" for return */

		np->n_size = np->n_vattr.nva_size = tsize;
		ubc_setsize(vp, (off_t)np->n_size); /* XXX check error */
		vap->va_data_size = tsize;
		err = nfs_setattrrpc(vp, vap, cred, p);
		printf("nfs_setattr: nfs_setattrrpc %d %d\n", error, err);
	}
	return (error);
}

/*
 * Do an nfs setattr rpc.
 */
static int
nfs_setattrrpc(vp, vap, cred, procp)
	vnode_t vp;
	struct vnode_attr *vap;
	kauth_cred_t cred;
	proc_t procp;
{
	register struct nfsv2_sattr *sp;
	register caddr_t cp;
	register long t1, t2;
	caddr_t bpos, dpos, cp2;
	u_long *tl;
	int error = 0, wccpostattr = 0;
	mbuf_t mreq, mrep, md, mb, mb2;
	int v3;
	u_int64_t xid;
	struct timeval now;

	if (!VFSTONFS(vnode_mount(vp)))
		return (ENXIO);
	v3 = NFS_ISV3(vp);

	nfsm_reqhead(NFSX_FH(v3) + NFSX_SATTR(v3));
	if (error)
		return (error);
	OSAddAtomic(1, (SInt32*)&nfsstats.rpccnt[NFSPROC_SETATTR]);
	nfsm_fhtom(vp, v3);
	if (v3) {
		if (VATTR_IS_ACTIVE(vap, va_mode)) {
			nfsm_build(tl, u_long *, 2 * NFSX_UNSIGNED);
			*tl++ = nfs_true;
			*tl = txdr_unsigned(vap->va_mode);
		} else {
			nfsm_build(tl, u_long *, NFSX_UNSIGNED);
			*tl = nfs_false;
		}
		if (VATTR_IS_ACTIVE(vap, va_uid)) {
			nfsm_build(tl, u_long *, 2 * NFSX_UNSIGNED);
			*tl++ = nfs_true;
			*tl = txdr_unsigned(vap->va_uid);
		} else {
			nfsm_build(tl, u_long *, NFSX_UNSIGNED);
			*tl = nfs_false;
		}
		if (VATTR_IS_ACTIVE(vap, va_gid)) {
			nfsm_build(tl, u_long *, 2 * NFSX_UNSIGNED);
			*tl++ = nfs_true;
			*tl = txdr_unsigned(vap->va_gid);
		} else {
			nfsm_build(tl, u_long *, NFSX_UNSIGNED);
			*tl = nfs_false;
		}
		if (VATTR_IS_ACTIVE(vap, va_data_size)) {
			nfsm_build(tl, u_long *, 3 * NFSX_UNSIGNED);
			*tl++ = nfs_true;
			txdr_hyper(&vap->va_data_size, tl);
		} else {
			nfsm_build(tl, u_long *, NFSX_UNSIGNED);
			*tl = nfs_false;
		}
		microtime(&now);
		if (VATTR_IS_ACTIVE(vap, va_access_time)) {
			if (vap->va_access_time.tv_sec != now.tv_sec) {
				nfsm_build(tl, u_long *, 3 * NFSX_UNSIGNED);
				*tl++ = txdr_unsigned(NFSV3SATTRTIME_TOCLIENT);
				txdr_nfsv3time(&vap->va_access_time, tl);
			} else {
				nfsm_build(tl, u_long *, NFSX_UNSIGNED);
				*tl = txdr_unsigned(NFSV3SATTRTIME_TOSERVER);
			}
		} else {
			nfsm_build(tl, u_long *, NFSX_UNSIGNED);
			*tl = txdr_unsigned(NFSV3SATTRTIME_DONTCHANGE);
		}
		if (VATTR_IS_ACTIVE(vap, va_modify_time)) {
			if (vap->va_modify_time.tv_sec != now.tv_sec) {
				nfsm_build(tl, u_long *, 3 * NFSX_UNSIGNED);
				*tl++ = txdr_unsigned(NFSV3SATTRTIME_TOCLIENT);
				txdr_nfsv3time(&vap->va_modify_time, tl);
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
		struct timespec neg1time = { -1, -1 };
		nfsm_build(sp, struct nfsv2_sattr *, NFSX_V2SATTR);
		if (VATTR_IS_ACTIVE(vap, va_mode))
			sp->sa_mode = vtonfsv2_mode(vnode_vtype(vp), vap->va_mode);
		else
			sp->sa_mode = nfs_xdrneg1;
		if (VATTR_IS_ACTIVE(vap, va_uid))
			sp->sa_uid = txdr_unsigned(vap->va_uid);
		else
			sp->sa_uid = nfs_xdrneg1;
		if (VATTR_IS_ACTIVE(vap, va_gid))
			sp->sa_gid = txdr_unsigned(vap->va_gid);
		else
			sp->sa_gid = nfs_xdrneg1;
		if (VATTR_IS_ACTIVE(vap, va_data_size))
			sp->sa_size = txdr_unsigned(vap->va_data_size);
		else
			sp->sa_size = nfs_xdrneg1;
		if (VATTR_IS_ACTIVE(vap, va_access_time)) {
			txdr_nfsv2time(&vap->va_access_time, &sp->sa_atime);
		} else {
			txdr_nfsv2time(&neg1time, &sp->sa_atime);
		}
		if (VATTR_IS_ACTIVE(vap, va_modify_time)) {
			txdr_nfsv2time(&vap->va_modify_time, &sp->sa_mtime);
		} else {
			txdr_nfsv2time(&neg1time, &sp->sa_mtime);
		}
	}
	nfsm_request(vp, NFSPROC_SETATTR, procp, cred, &xid);
	if (v3) {
		struct timespec premtime = { 0, 0 };
		if (mrep) {
			nfsm_wcc_data(vp, &premtime, wccpostattr, &xid);
		}
		/* if file hadn't changed, update cached mtime */
		if (nfstimespeccmp(&VTONFS(vp)->n_mtime, &premtime, ==)) {
			VTONFS(vp)->n_mtime = VTONFS(vp)->n_vattr.nva_mtime;
		}
		/* if directory hadn't changed, update namecache mtime */
		if ((vnode_vtype(vp) == VDIR) &&
		    nfstimespeccmp(&VTONFS(vp)->n_ncmtime, &premtime, ==)) {
			VTONFS(vp)->n_ncmtime = VTONFS(vp)->n_vattr.nva_mtime;
		}
		if (!wccpostattr)
			NATTRINVALIDATE(VTONFS(vp));
	} else {
		if (mrep) {
			nfsm_loadattr(vp, v3, NULL, &xid);
		}
	}
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
	struct vnop_lookup_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_dvp;
		vnode_t *a_vpp;
		struct componentname *a_cnp;
		vfs_context_t a_context;
	} */ *ap;
{
	struct componentname *cnp = ap->a_cnp;
	vnode_t dvp = ap->a_dvp;
	vnode_t *vpp = ap->a_vpp;
	int flags = cnp->cn_flags;
	vnode_t newvp;
	u_long *tl;
	caddr_t cp;
	long t1, t2;
	caddr_t bpos, dpos, cp2;
	mbuf_t mreq, mrep, md, mb, mb2;
	long len;
	u_char *fhp;
	struct nfsnode *dnp, *np;
	int wantparent, error, attrflag, dattrflag, fhsize, fhisdvp;
	int v3 = NFS_ISV3(dvp);
	u_int64_t xid, dxid;
	struct nfs_vattr nvattr;
	kauth_cred_t cred;
	proc_t p;
	int ngflags;

	*vpp = NULLVP;

	cred = vfs_context_ucred(ap->a_context);
	p = vfs_context_proc(ap->a_context);

	wantparent = flags & (LOCKPARENT|WANTPARENT);
	dnp = VTONFS(dvp);

	error = nfs_getattr(dvp, &nvattr, cred, p);
	if (error)
		goto error_return;
	if (nfstimespeccmp(&dnp->n_ncmtime, &nvattr.nva_mtime, !=)) {
		/*
		 * This directory has changed on us.
		 * Purge any name cache entries.
		 */
		cache_purge(dvp);
		dnp->n_ncmtime = nvattr.nva_mtime;
	}

	error = cache_lookup(dvp, vpp, cnp);
	switch (error) {
	case ENOENT:
		/* negative cache entry same as cache miss */
		error = 0;
		/* FALLTHROUGH */
	case 0:
		/* cache miss */
		break;
	case -1:
		/* cache hit, not really an error */
	{
		struct vnop_access_args naa;

		OSAddAtomic(1, (SInt32*)&nfsstats.lookupcache_hits);

		/* check for directory access */
		naa.a_vp = dvp;
		naa.a_action = KAUTH_VNODE_SEARCH;
		naa.a_context = ap->a_context;

		/* compute actual success/failure based on accessibility */
		error = nfs_access(&naa);
	}
		/* FALLTHROUGH */
	default:
		/* unexpected error from cache_lookup */
		goto error_return;
	}
	
	/* check for lookup of "." */
	if ((cnp->cn_nameptr[0] == '.') && (cnp->cn_namelen == 1)) {
		/* skip lookup, we know who we are */
		fhisdvp = 1;
		fhp = NULL;
		fhsize = 0;
		mrep = NULL;
		goto found;
	}

	/* do we know this name is too long? */
	if (v3) {
		/* For NFSv3: need uniform pathconf info to test pc_namemax */
		struct nfsmount *nmp = VFSTONFS(vnode_mount(dvp));
		if (!nmp) {
			error = ENXIO;
			goto error_return;
		}
		if (((nmp->nm_state & (NFSSTA_GOTFSINFO|NFSSTA_GOTPATHCONF)) ==
			(NFSSTA_GOTFSINFO|NFSSTA_GOTPATHCONF)) &&
		     (nmp->nm_fsinfo.fsproperties & NFSV3FSINFO_HOMOGENEOUS) &&
		     (cnp->cn_namelen > (long)nmp->nm_fsinfo.namemax)) {
			error = ENAMETOOLONG;
			goto error_return;
		}
	} else if (cnp->cn_namelen > NFS_MAXNAMLEN) {
		error = ENAMETOOLONG;
		goto error_return;
	}

	error = 0;
	newvp = NULLVP;

	OSAddAtomic(1, (SInt32*)&nfsstats.lookupcache_misses);
	len = cnp->cn_namelen;
	nfsm_reqhead(NFSX_FH(v3) + NFSX_UNSIGNED + nfsm_rndup(len));
	if (error)
		goto error_return;
	OSAddAtomic(1, (SInt32*)&nfsstats.rpccnt[NFSPROC_LOOKUP]);
	nfsm_fhtom(dvp, v3);
	nfsm_strtom(cnp->cn_nameptr, len, NFS_MAXNAMLEN, v3);
	/* nfsm_request for NFSv2 causes you to goto to nfsmout upon errors */
	nfsm_request(dvp, NFSPROC_LOOKUP, p, cred, &xid); 

	if (error) {
		if (mrep) {
			nfsm_postop_attr_update(dvp, v3, dattrflag, &xid);
			mbuf_freem(mrep);
		}
		goto nfsmout;
	}

	/* get the filehandle */
	nfsm_getfh(fhp, fhsize, v3);
	/* is the file handle the same as this directory's file handle? */
	fhisdvp = NFS_CMPFH(dnp, fhp, fhsize);

	/* get attributes */
	if (v3) {
		dxid = xid;
		nfsm_postop_attr_get(v3, attrflag, &nvattr);
		nfsm_postop_attr_update(dvp, v3, dattrflag, &dxid);
		if (!attrflag && (!fhisdvp || !dattrflag)) {
			/* We need valid attributes in order */
			/* to call nfs_nget/vnode_create().  */
			error = nfs_getattr_no_vnode(vnode_mount(dvp),
					fhp, fhsize, cred, p, &nvattr, &xid);
			if (error) {
				mbuf_freem(mrep);
				goto error_return;
			}
		}
	} else {
		nfsm_attr_get(v3, &nvattr);
	}

found:

	/*
	 * Handle RENAME case...
	 */
	if (cnp->cn_nameiop == RENAME && wantparent && (flags & ISLASTCN)) {
		if (fhisdvp) {
			mbuf_freem(mrep);
			error = EISDIR;
			goto error_return;
		}
		error = nfs_nget(vnode_mount(dvp), dvp, cnp, fhp, fhsize,
				&nvattr, &xid, 0, &np);
		if (error) {
			mbuf_freem(mrep);
			goto error_return;
		}
		*vpp = NFSTOV(np);
		mbuf_freem(mrep);

		goto error_return;
	}

	if ((cnp->cn_flags & MAKEENTRY) &&
	    (cnp->cn_nameiop != DELETE || !(flags & ISLASTCN)))
		ngflags = NG_MAKEENTRY;
	else
		ngflags = 0;

	if (fhisdvp) {
		error = vnode_get(dvp);
		if (error) {
			mbuf_freem(mrep);
			goto error_return;
		}
		newvp = dvp;
		/* test fhp to see if we have valid attributes in nvattr */
		if (fhp && (dnp->n_xid <= xid)) {
			error = nfs_loadattrcache(dnp, &nvattr, &xid, 0);
			if (error) {
				vnode_put(dvp);
				mbuf_freem(mrep);
				goto error_return;
			}
		}
	} else {
		error = nfs_nget(vnode_mount(dvp), dvp, cnp, fhp, fhsize,
				&nvattr, &xid, ngflags, &np);
		if (error) {
			mbuf_freem(mrep);
			goto error_return;
		}
		newvp = NFSTOV(np);
	}
	*vpp = newvp;
//	if (error == 0 && *vpp != NULL && *vpp != dvp)
//		nfs_unlock(VTONFS(*vpp));

	nfsm_reqdone;
	if (error) {
		if ((cnp->cn_nameiop == CREATE || cnp->cn_nameiop == RENAME) &&
		    (flags & ISLASTCN) && error == ENOENT) {
			if (vnode_mount(dvp) && vnode_vfsisrdonly(dvp))
				error = EROFS;
			else
				error = EJUSTRETURN;
		}
	}
error_return:
	if (error && *vpp) {
	        vnode_put(*vpp);
		*vpp = NULLVP;
	}
	return (error);
}

/*
 * nfs read call.
 * Just call nfs_bioread() to do the work.
 */
static int
nfs_read(ap)
	struct vnop_read_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		struct uio *a_uio;
		int a_ioflag;
		vfs_context_t a_context;
	} */ *ap;
{
	if (vnode_vtype(ap->a_vp) != VREG)
		return (EPERM);
	return (nfs_bioread(ap->a_vp, ap->a_uio, ap->a_ioflag,
		vfs_context_ucred(ap->a_context),
		vfs_context_proc(ap->a_context)));
}


/*
 * nfs readlink call
 */
static int
nfs_readlink(ap)
	struct vnop_readlink_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		struct uio *a_uio;
		vfs_context_t a_context;
	} */ *ap;
{
	if (vnode_vtype(ap->a_vp) != VLNK)
		return (EPERM);
	return (nfs_bioread(ap->a_vp, ap->a_uio, 0,
		vfs_context_ucred(ap->a_context),
		vfs_context_proc(ap->a_context)));
}

/*
 * Do a readlink rpc.
 * Called by nfs_doio() from below the buffer cache.
 */
int
nfs_readlinkrpc(
	vnode_t vp,
	struct uio *uiop,
	kauth_cred_t cred,
	proc_t p)
{
	register u_long *tl;
	register caddr_t cp;
	register long t1, t2;
	caddr_t bpos, dpos, cp2;
	int error = 0, len, attrflag;
	mbuf_t mreq, mrep, md, mb, mb2;
	int v3;
	u_int64_t xid;

	if (!VFSTONFS(vnode_mount(vp)))
		return (ENXIO);
	v3 = NFS_ISV3(vp);

	nfsm_reqhead(NFSX_FH(v3));
	if (error)
		return (error);
	OSAddAtomic(1, (SInt32*)&nfsstats.rpccnt[NFSPROC_READLINK]);
	nfsm_fhtom(vp, v3);
	nfsm_request(vp, NFSPROC_READLINK, p, cred, &xid);
	if (v3 && mrep)
		nfsm_postop_attr_update(vp, v3, attrflag, &xid);
	if (!error) {
		nfsm_strsiz(len, NFS_MAXPATHLEN, v3);
		if (len >= NFS_MAXPATHLEN) {
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
nfs_readrpc(
	vnode_t vp,
	struct uio *uiop,
	kauth_cred_t cred,
	proc_t p)
{
	register u_long *tl;
	register caddr_t cp;
	register long t1, t2;
	caddr_t bpos, dpos, cp2;
	mbuf_t mreq, mrep, md, mb, mb2;
	struct nfsmount *nmp;
	int error = 0, len, retlen, tsiz, eof = 0, attrflag;
	int v3, nmrsize;
	u_int64_t xid;

	FSDBG_TOP(536, vp, uiop->uio_offset, uio_uio_resid(uiop), 0);
	nmp = VFSTONFS(vnode_mount(vp));
	if (!nmp)
		return (ENXIO);
	v3 = NFS_ISV3(vp);
	nmrsize = nmp->nm_rsize;

	// LP64todo - fix this
	tsiz = uio_uio_resid(uiop);
        if (((u_int64_t)uiop->uio_offset + (unsigned int)tsiz > 0xffffffff) && !v3) {
		FSDBG_BOT(536, vp, uiop->uio_offset, uio_uio_resid(uiop), EFBIG);
		return (EFBIG);
	}
	while (tsiz > 0) {
		len = (tsiz > nmrsize) ? nmrsize : tsiz;
		nfsm_reqhead(NFSX_FH(v3) + NFSX_UNSIGNED * 3);
		if (error)
			break;
		OSAddAtomic(1, (SInt32*)&nfsstats.rpccnt[NFSPROC_READ]);
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
		FSDBG(536, vp, uiop->uio_offset, len, 0);
		nfsm_request(vp, NFSPROC_READ, p, cred, &xid);
		if (v3) {
			if (mrep) {
				nfsm_postop_attr_update(vp, v3, attrflag, &xid);
			}
			if (error) {
				mbuf_freem(mrep);
				goto nfsmout;
			}
			nfsm_dissect(tl, u_long *, 2 * NFSX_UNSIGNED);
			eof = fxdr_unsigned(int, *(tl + 1));
		} else {
			if (mrep) {
				nfsm_loadattr(vp, v3, NULL, &xid);
			}
		}
		if (mrep) {
			nfsm_strsiz(retlen, nmrsize, 0);
			nfsm_mtouio(uiop, retlen);
			mbuf_freem(mrep);
		} else {
			retlen = 0;
		}
		tsiz -= retlen;
		if (v3) {
			if (eof || retlen == 0)
				tsiz = 0;
		} else if (retlen < len)
			tsiz = 0;
	}
nfsmout:
	FSDBG_BOT(536, vp, eof, uio_uio_resid(uiop), error);
	return (error);
}

/*
 * nfs write call
 */
int
nfs_writerpc(
	vnode_t vp,
	struct uio *uiop,
	kauth_cred_t cred,
	proc_t p,
	int *iomode,
	int *must_commit)
{
	register u_long *tl;
	register caddr_t cp;
	register int t1, t2, backup;
	caddr_t bpos, dpos, cp2;
	mbuf_t mreq, mrep, md, mb, mb2;
	struct nfsmount *nmp;
	int error = 0, len, tsiz, updatemtime = 0, wccpostattr = 0, rlen, commit;
	int v3, committed = NFSV3WRITE_FILESYNC;
	u_int64_t xid;
	mount_t mp;

#if DIAGNOSTIC
	if (uiop->uio_iovcnt != 1)
		panic("nfs_writerpc: iovcnt > 1");
#endif
	FSDBG_TOP(537, vp, uiop->uio_offset, uio_uio_resid(uiop), *iomode);
	nmp = VFSTONFS(vnode_mount(vp));
	if (!nmp)
		return (ENXIO);
	v3 = NFS_ISV3(vp);
	*must_commit = 0;
	// LP64todo - fix this
	tsiz = uio_uio_resid(uiop);
        if (((u_int64_t)uiop->uio_offset + (unsigned int)tsiz > 0xffffffff) && !v3) {
		FSDBG_BOT(537, vp, uiop->uio_offset, uio_uio_resid(uiop), EFBIG);
		return (EFBIG);
	}
	while (tsiz > 0) {
		nmp = VFSTONFS(vnode_mount(vp));
		if (!nmp) {
			error = ENXIO;
			break;
		}
		len = (tsiz > nmp->nm_wsize) ? nmp->nm_wsize : tsiz;
		nfsm_reqhead(NFSX_FH(v3) + 5 * NFSX_UNSIGNED + nfsm_rndup(len));
		if (error)
			break;
		OSAddAtomic(1, (SInt32*)&nfsstats.rpccnt[NFSPROC_WRITE]);
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
		FSDBG(537, vp, uiop->uio_offset, len, 0);
		nfsm_uiotom(uiop, len);
		nfsm_request(vp, NFSPROC_WRITE, p, cred, &xid);
		nmp = VFSTONFS(vnode_mount(vp));
		if (!nmp)
			error = ENXIO;
		if (v3) {
			if (mrep) {
				struct timespec premtime;
				nfsm_wcc_data(vp, &premtime, wccpostattr, &xid);
				if (nfstimespeccmp(&VTONFS(vp)->n_mtime, &premtime, ==))
					updatemtime = 1;
			}
			if (!error) {
				nfsm_dissect(tl, u_long *, 2 * NFSX_UNSIGNED +
					NFSX_V3WRITEVERF);
				rlen = fxdr_unsigned(int, *tl++);
				if (rlen <= 0) {
					error = NFSERR_IO;
					break;
				} else if (rlen < len) {
					backup = len - rlen;
					uio_iov_base_add(uiop, -backup);
					uio_iov_len_add(uiop, backup);
					uiop->uio_offset -= backup;
					uio_uio_resid_add(uiop, backup);
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
				if ((nmp->nm_state & NFSSTA_HASWRITEVERF) == 0) {
				    bcopy((caddr_t)tl, (caddr_t)nmp->nm_verf,
					NFSX_V3WRITEVERF);
				    nmp->nm_state |= NFSSTA_HASWRITEVERF;
				} else if (bcmp((caddr_t)tl,
				    (caddr_t)nmp->nm_verf, NFSX_V3WRITEVERF)) {
				    *must_commit = 1;
				    bcopy((caddr_t)tl, (caddr_t)nmp->nm_verf,
					NFSX_V3WRITEVERF);
				}
			}
		} else {
			if (mrep) {
				nfsm_loadattr(vp, v3, NULL, &xid);
			}
		}

		if (updatemtime)
			VTONFS(vp)->n_mtime = VTONFS(vp)->n_vattr.nva_mtime;
		mbuf_freem(mrep);
		/*
		 * we seem to have a case where we end up looping on shutdown
		 * and taking down nfs servers.  For V3, error cases, there is
		 * no way to terminate loop, if the len was 0, meaning,
		 * nmp->nm_wsize was trashed. FreeBSD has this fix in it.
		 * Let's try it.
		 */
		if (error)
			break;
		tsiz -= len;
	}
nfsmout:
        if ((mp = vnode_mount(vp)) && (vfs_flags(mp) & MNT_ASYNC))
		committed = NFSV3WRITE_FILESYNC;
        *iomode = committed;
	if (error)
		uio_uio_resid_set(uiop, tsiz);
	FSDBG_BOT(537, vp, committed, uio_uio_resid(uiop), error);
	return (error);
}

/*
 * nfs mknod rpc
 * For NFS v2 this is a kludge. Use a create rpc but with the IFMT bits of the
 * mode set to specify the file type and the size field for rdev.
 */
static int
nfs_mknodrpc(
	vnode_t dvp,
	vnode_t *vpp,
	struct componentname *cnp,
	struct vnode_attr *vap,
	kauth_cred_t cred,
	proc_t p)
{
	register struct nfsv2_sattr *sp;
	register u_long *tl;
	register caddr_t cp;
	register long t1, t2;
	vnode_t newvp = (vnode_t)0;
	struct nfsnode *np = (struct nfsnode *)0;
	struct nfs_vattr nvattr;
	char *cp2;
	caddr_t bpos, dpos;
	int error = 0, wccpostattr = 0, gotvp = 0;
	struct timespec premtime = { 0, 0 };
	mbuf_t mreq, mrep, md, mb, mb2;
	u_long rdev;
	u_int64_t xid;
	int v3 = NFS_ISV3(dvp);
	int gotuid, gotgid;

	if (!VATTR_IS_ACTIVE(vap, va_type))
		return (EINVAL);
	if (vap->va_type == VCHR || vap->va_type == VBLK) {
		if (!VATTR_IS_ACTIVE(vap, va_rdev))
			return (EINVAL);
		rdev = txdr_unsigned(vap->va_rdev);
	} else if (vap->va_type == VFIFO || vap->va_type == VSOCK)
		rdev = 0xffffffff;
	else {
		return (ENOTSUP);
	}
	nfsm_reqhead(NFSX_FH(v3) + 4 * NFSX_UNSIGNED +
		nfsm_rndup(cnp->cn_namelen) + NFSX_SATTR(v3));
	if (error)
		return (error);

	VATTR_SET_SUPPORTED(vap, va_mode);
	VATTR_SET_SUPPORTED(vap, va_uid);
	VATTR_SET_SUPPORTED(vap, va_gid);
	VATTR_SET_SUPPORTED(vap, va_data_size);
	VATTR_SET_SUPPORTED(vap, va_access_time);
	VATTR_SET_SUPPORTED(vap, va_modify_time);
	gotuid = VATTR_IS_ACTIVE(vap, va_uid);
	gotgid = VATTR_IS_ACTIVE(vap, va_gid);

	OSAddAtomic(1, (SInt32*)&nfsstats.rpccnt[NFSPROC_MKNOD]);
	nfsm_fhtom(dvp, v3);
	nfsm_strtom(cnp->cn_nameptr, cnp->cn_namelen, NFS_MAXNAMLEN, v3);
	if (v3) {
		nfsm_build(tl, u_long *, NFSX_UNSIGNED);
		*tl++ = vtonfsv3_type(vap->va_type);
		nfsm_v3sattr(vap);
		if (vap->va_type == VCHR || vap->va_type == VBLK) {
			nfsm_build(tl, u_long *, 2 * NFSX_UNSIGNED);
			*tl++ = txdr_unsigned(major(vap->va_rdev));
			*tl = txdr_unsigned(minor(vap->va_rdev));
		}
	} else {
		struct timespec neg1time = { -1, -1 };
		nfsm_build(sp, struct nfsv2_sattr *, NFSX_V2SATTR);
		sp->sa_mode = vtonfsv2_mode(vap->va_type,
			(VATTR_IS_ACTIVE(vap, va_mode) ? vap->va_mode : 0600));
		sp->sa_uid = gotuid ? (u_long)txdr_unsigned(vap->va_uid) : nfs_xdrneg1;
		sp->sa_gid = gotgid ? (u_long)txdr_unsigned(vap->va_gid) : nfs_xdrneg1;
		sp->sa_size = rdev;
		if (VATTR_IS_ACTIVE(vap, va_access_time)) {
			txdr_nfsv2time(&vap->va_access_time, &sp->sa_atime);
		} else {
			txdr_nfsv2time(&neg1time, &sp->sa_atime);
		}
		if (VATTR_IS_ACTIVE(vap, va_modify_time)) {
			txdr_nfsv2time(&vap->va_modify_time, &sp->sa_mtime);
		} else {
			txdr_nfsv2time(&neg1time, &sp->sa_mtime);
		}
	}
	nfsm_request(dvp, NFSPROC_MKNOD, p, cred, &xid);
	/* XXX no EEXIST kludge here? */
	if (!error) {
		nfsm_mtofh(dvp, cnp, newvp, v3, &xid, gotvp);
		if (!gotvp) {
			error = nfs_lookitup(dvp, cnp->cn_nameptr,
			    cnp->cn_namelen, cred, p, &np);
			if (!error)
				newvp = NFSTOV(np);
		}
	}
	if (v3 && mrep)
		nfsm_wcc_data(dvp, &premtime, wccpostattr, &xid);
	if (!error && (gotuid || gotgid) &&
	    (!newvp || nfs_getattrcache(newvp, &nvattr) ||
	     (gotuid && (nvattr.nva_uid != vap->va_uid)) ||
	     (gotgid && (nvattr.nva_gid != vap->va_gid)))) {
		/* clear ID bits if server didn't use them (or we can't tell) */
		VATTR_CLEAR_SUPPORTED(vap, va_uid);
		VATTR_CLEAR_SUPPORTED(vap, va_gid);
	}
	nfsm_reqdone;
	if (error) {
		if (newvp)
			vnode_put(newvp);
	} else {
		*vpp = newvp;
	}
	VTONFS(dvp)->n_flag |= NMODIFIED;
	/* if directory hadn't changed, update namecache mtime */
	if (nfstimespeccmp(&VTONFS(dvp)->n_ncmtime, &premtime, ==))
		VTONFS(dvp)->n_ncmtime = VTONFS(dvp)->n_vattr.nva_mtime;
	if (!wccpostattr)
		NATTRINVALIDATE(VTONFS(dvp));
	return (error);
}

/*
 * nfs mknod vop
 * just call nfs_mknodrpc() to do the work.
 */
/* ARGSUSED */
static int
nfs_mknod(ap)
	struct vnop_mknod_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_dvp;
		vnode_t *a_vpp;
		struct componentname *a_cnp;
		struct vnode_attr *a_vap;
		vfs_context_t a_context;
	} */ *ap;
{
	int error;

	error = nfs_mknodrpc(ap->a_dvp, ap->a_vpp, ap->a_cnp, ap->a_vap,
			vfs_context_ucred(ap->a_context),
			vfs_context_proc(ap->a_context));

	return (error);
}

static u_long create_verf;
/*
 * nfs file create call
 */
static int
nfs_create(ap)
	struct vnop_create_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_dvp;
		vnode_t *a_vpp;
		struct componentname *a_cnp;
		struct vnode_attr *a_vap;
		vfs_context_t a_context;
	} */ *ap;
{
	vnode_t dvp = ap->a_dvp;
	struct vnode_attr *vap = ap->a_vap;
	struct componentname *cnp = ap->a_cnp;
	struct nfs_vattr nvattr;
	struct nfsv2_sattr *sp;
	u_long *tl;
	caddr_t cp;
	long t1, t2;
	struct nfsnode *np = (struct nfsnode *)0;
	vnode_t newvp = (vnode_t)0;
	caddr_t bpos, dpos, cp2;
	int error = 0, wccpostattr = 0, gotvp = 0, fmode = 0;
	struct timespec premtime = { 0, 0 };
	mbuf_t mreq, mrep, md, mb, mb2;
	int v3 = NFS_ISV3(dvp);
	int gotuid, gotgid;
	u_int64_t xid;
	kauth_cred_t cred;
	proc_t p;

	cred = vfs_context_ucred(ap->a_context);
	p = vfs_context_proc(ap->a_context);

	if (!VATTR_IS_ACTIVE(vap, va_type))
		return (EINVAL);

	/*
	 * Oops, not for me..
	 */
	if (vap->va_type == VSOCK)
		return (nfs_mknodrpc(dvp, ap->a_vpp, cnp, vap, cred, p));

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
	nfsm_reqhead(NFSX_FH(v3) + 2 * NFSX_UNSIGNED +
		nfsm_rndup(cnp->cn_namelen) + NFSX_SATTR(v3));
	if (error)
		return (error);
	OSAddAtomic(1, (SInt32*)&nfsstats.rpccnt[NFSPROC_CREATE]);
	nfsm_fhtom(dvp, v3);
	nfsm_strtom(cnp->cn_nameptr, cnp->cn_namelen, NFS_MAXNAMLEN, v3);
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
		    nfsm_v3sattr(vap);
		}
	} else {
		struct timespec neg1time = { -1, -1 };
		nfsm_build(sp, struct nfsv2_sattr *, NFSX_V2SATTR);
		sp->sa_mode = vtonfsv2_mode(vap->va_type,
			(VATTR_IS_ACTIVE(vap, va_mode) ? vap->va_mode : 0600));
		sp->sa_uid = gotuid ? (u_long)txdr_unsigned(vap->va_uid) : nfs_xdrneg1;
		sp->sa_gid = gotgid ? (u_long)txdr_unsigned(vap->va_gid) : nfs_xdrneg1;
		sp->sa_size = 0;
		if (VATTR_IS_ACTIVE(vap, va_access_time)) {
			txdr_nfsv2time(&vap->va_access_time, &sp->sa_atime);
		} else {
			txdr_nfsv2time(&neg1time, &sp->sa_atime);
		}
		if (VATTR_IS_ACTIVE(vap, va_modify_time)) {
			txdr_nfsv2time(&vap->va_modify_time, &sp->sa_mtime);
		} else {
			txdr_nfsv2time(&neg1time, &sp->sa_mtime);
		}
	}
	nfsm_request(dvp, NFSPROC_CREATE, p, cred, &xid);
	if (!error) {
		nfsm_mtofh(dvp, cnp, newvp, v3, &xid, gotvp);
		if (!gotvp) {
			error = nfs_lookitup(dvp, cnp->cn_nameptr,
			    cnp->cn_namelen, cred, p, &np);
			if (!error)
				newvp = NFSTOV(np);
		}
	}
	if (v3 && mrep)
		nfsm_wcc_data(dvp, &premtime, wccpostattr, &xid);
	nfsm_reqdone;
	if (error) {
		if (v3 && (fmode & O_EXCL) && error == NFSERR_NOTSUPP) {
			fmode &= ~O_EXCL;
			goto again;
		}
		if (newvp)
			vnode_put(newvp);
	} else if (v3 && (fmode & O_EXCL)) {
		error = nfs_setattrrpc(newvp, vap, cred, p);
		if (error && (gotuid || gotgid)) {
			/* it's possible the server didn't like our attempt to set IDs. */
			/* so, let's try it again without those */
			VATTR_CLEAR_ACTIVE(vap, va_uid);
			VATTR_CLEAR_ACTIVE(vap, va_gid);
			error = nfs_setattrrpc(newvp, vap, cred, p);
		}
		if (error)
			vnode_put(newvp);
	}
	if (!error) {
		*ap->a_vpp = newvp;
	}
	VTONFS(dvp)->n_flag |= NMODIFIED;
	/* if directory hadn't changed, update namecache mtime */
	if (nfstimespeccmp(&VTONFS(dvp)->n_ncmtime, &premtime, ==))
		VTONFS(dvp)->n_ncmtime = VTONFS(dvp)->n_vattr.nva_mtime;
	if (!wccpostattr)
		NATTRINVALIDATE(VTONFS(dvp));
	if (!error && (gotuid || gotgid) &&
	    (!newvp || nfs_getattrcache(newvp, &nvattr) ||
	     (gotuid && (nvattr.nva_uid != vap->va_uid)) ||
	     (gotgid && (nvattr.nva_gid != vap->va_gid)))) {
		/* clear ID bits if server didn't use them (or we can't tell) */
		VATTR_CLEAR_SUPPORTED(vap, va_uid);
		VATTR_CLEAR_SUPPORTED(vap, va_gid);
	}
	return (error);
}

/*
 * nfs file remove call
 * To try and make nfs semantics closer to ufs semantics, a file that has
 * other processes using the vnode is renamed instead of removed and then
 * removed later on the last close.
 * - If vnode_isinuse()
 *	  If a rename is not already in the works
 *	     call nfs_sillyrename() to set it up
 *     else
 *	  do the remove rpc
 */
static int
nfs_remove(ap)
	struct vnop_remove_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_dvp;
		vnode_t a_vp;
		struct componentname *a_cnp;
		int a_flags;
		vfs_context_t a_context;
	} */ *ap;
{
	vnode_t vp = ap->a_vp;
	vnode_t dvp = ap->a_dvp;
	struct componentname *cnp = ap->a_cnp;
	struct nfsnode *np = VTONFS(vp);
	int error = 0, gofree = 0;
	struct nfs_vattr nvattr;
	kauth_cred_t cred;
	proc_t p;

	cred = vfs_context_ucred(ap->a_context);
	p = vfs_context_proc(ap->a_context);

	gofree = vnode_isinuse(vp, 0) ? 0 : 1;
	if ((ap->a_flags & VNODE_REMOVE_NODELETEBUSY) && !gofree) {
		/* Caller requested Carbon delete semantics, but file is busy */
		return (EBUSY);
	}
	if (gofree || (np->n_sillyrename &&
		nfs_getattr(vp, &nvattr, cred, p) == 0 &&
		nvattr.nva_nlink > 1)) {
		/*
		 * Purge the name cache so that the chance of a lookup for
		 * the name succeeding while the remove is in progress is
		 * minimized.
		 */
		cache_purge(vp);
		/*
		 * throw away biocache buffers, mainly to avoid
		 * unnecessary delayed writes later.
		 */
		error = nfs_vinvalbuf(vp, 0, cred, p, 1);
		np->n_size = 0;
		ubc_setsize(vp, (off_t)0); /* XXX check error */
		/* Do the rpc */
		if (error != EINTR)
			error = nfs_removerpc(dvp, cnp->cn_nameptr,
				cnp->cn_namelen, cred, p);
		/*
		 * Kludge City: If the first reply to the remove rpc is lost..
		 *   the reply to the retransmitted request will be ENOENT
		 *   since the file was in fact removed
		 *   Therefore, we cheat and return success.
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
			LIST_REMOVE(np, n_hash);
			np->n_flag &= ~NHASHED;
			lck_mtx_unlock(nfs_node_hash_mutex);
		}
		if (!error && !np->n_sillyrename) {
			/* clear flags now: won't get nfs_inactive for recycled vnode */
			/* clear all flags other than these */
			np->n_flag &= (NMODIFIED | NFLUSHINPROG | NFLUSHWANT | NHASHED);
			vnode_recycle(vp);
		}
	} else if (!np->n_sillyrename) {
		error = nfs_sillyrename(dvp, vp, cnp, cred, p);
	}
	NATTRINVALIDATE(np);

	return (error);
}

/*
 * nfs file remove rpc called from nfs_inactive
 */
int
nfs_removeit(struct sillyrename *sp)
{
	return (nfs_removerpc(sp->s_dvp, sp->s_name, sp->s_namlen, sp->s_cred, NULL));
}

/*
 * Nfs remove rpc, called from nfs_remove() and nfs_removeit().
 */
static int
nfs_removerpc(dvp, name, namelen, cred, proc)
	vnode_t dvp;
	char *name;
	int namelen;
	kauth_cred_t cred;
	proc_t proc;
{
	register u_long *tl;
	register caddr_t cp;
	register long t1, t2;
	caddr_t bpos, dpos, cp2;
	int error = 0, wccpostattr = 0;
	struct timespec premtime = { 0, 0 };
	mbuf_t mreq, mrep, md, mb, mb2;
	int v3;
	u_int64_t xid;

	if (!VFSTONFS(vnode_mount(dvp)))
		return (ENXIO);
	v3 = NFS_ISV3(dvp);

	nfsm_reqhead(NFSX_FH(v3) + NFSX_UNSIGNED + nfsm_rndup(namelen));
	if (error)
		return (error);
	OSAddAtomic(1, (SInt32*)&nfsstats.rpccnt[NFSPROC_REMOVE]);
	nfsm_fhtom(dvp, v3);
	nfsm_strtom(name, namelen, NFS_MAXNAMLEN, v3);
	nfsm_request(dvp, NFSPROC_REMOVE, proc, cred, &xid);
	if (v3 && mrep)
		nfsm_wcc_data(dvp, &premtime, wccpostattr, &xid);
	nfsm_reqdone;
	VTONFS(dvp)->n_flag |= NMODIFIED;
	/* if directory hadn't changed, update namecache mtime */
	if (nfstimespeccmp(&VTONFS(dvp)->n_ncmtime, &premtime, ==))
		VTONFS(dvp)->n_ncmtime = VTONFS(dvp)->n_vattr.nva_mtime;
	if (!wccpostattr)
		NATTRINVALIDATE(VTONFS(dvp));
	return (error);
}

/*
 * nfs file rename call
 */
static int
nfs_rename(ap)
	struct vnop_rename_args  /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_fdvp;
		vnode_t a_fvp;
		struct componentname *a_fcnp;
		vnode_t a_tdvp;
		vnode_t a_tvp;
		struct componentname *a_tcnp;
		vfs_context_t a_context;
	} */ *ap;
{
	vnode_t fvp = ap->a_fvp;
	vnode_t tvp = ap->a_tvp;
	vnode_t fdvp = ap->a_fdvp;
	vnode_t tdvp = ap->a_tdvp;
	struct componentname *tcnp = ap->a_tcnp;
	struct componentname *fcnp = ap->a_fcnp;
	int error, inuse=0;
	mount_t fmp, tdmp, tmp;
	struct nfsnode *tnp;
	kauth_cred_t cred;
	proc_t p;

	cred = vfs_context_ucred(ap->a_context);
	p = vfs_context_proc(ap->a_context);

	tnp = tvp ? VTONFS(tvp) : NULL;

	/* Check for cross-device rename */
	fmp = vnode_mount(fvp);
	tmp = tvp ? vnode_mount(tvp) : NULL;
	tdmp = vnode_mount(tdvp);
	if ((fmp != tdmp) || (tvp && (fmp != tmp))) {
		error = EXDEV;
		goto out;
	}

	/*
	 * If the tvp exists and is in use, sillyrename it before doing the
	 * rename of the new file over it.
	 * XXX Can't sillyrename a directory.
	 * Don't sillyrename if source and target are same vnode (hard
	 * links or case-variants)
	 */
	if (tvp && tvp != fvp) {
		inuse = vnode_isinuse(tvp, 0);
	}
	if (inuse && !tnp->n_sillyrename && vnode_vtype(tvp) != VDIR) {
		if  ((error = nfs_sillyrename(tdvp, tvp, tcnp, cred, p))) {
			/* sillyrename failed. Instead of pressing on, return error */
			goto out; /* should not be ENOENT. */
		} else {
			/* sillyrename succeeded.*/
			tvp = NULL;
		}
	}

	error = nfs_renamerpc(fdvp, fcnp->cn_nameptr, fcnp->cn_namelen,
		tdvp, tcnp->cn_nameptr, tcnp->cn_namelen, cred, p);

	/*
	 * Kludge: Map ENOENT => 0 assuming that it is a reply to a retry.
	 */
	if (error == ENOENT)
		error = 0;

	if (!error && tvp && tvp != fvp && !tnp->n_sillyrename) {
		/*
		 * remove nfsnode from hash now so we can't accidentally find it
		 * again if another object gets created with the same filehandle
		 * before this vnode gets reclaimed
		 */
		lck_mtx_lock(nfs_node_hash_mutex);
		LIST_REMOVE(tnp, n_hash);
		tnp->n_flag &= ~NHASHED;
		lck_mtx_unlock(nfs_node_hash_mutex);
	}
	
	/* purge the old name cache entries and enter the new one */
	cache_purge(fvp);
	if (tvp) {
		cache_purge(tvp);
		if (!error && !tnp->n_sillyrename) {
			/* clear flags now: won't get nfs_inactive for recycled vnode */
			/* clear all flags other than these */
			tnp->n_flag &= (NMODIFIED | NFLUSHINPROG | NFLUSHWANT | NHASHED);
			vnode_recycle(tvp);
		}
	}
	if (!error)
		cache_enter(tdvp, fvp, tcnp);

out:
	/*
	 * Kludge: Map ENOENT => 0 assuming that it is a reply to a retry.
	 */
	if (error == ENOENT)
		error = 0;
	return (error);
}

/*
 * Do an nfs rename rpc. Called from nfs_rename() and nfs_sillyrename().
 */
static int
nfs_renamerpc(fdvp, fnameptr, fnamelen, tdvp, tnameptr, tnamelen, cred, proc)
	vnode_t fdvp;
	char *fnameptr;
	int fnamelen;
	vnode_t tdvp;
	char *tnameptr;
	int tnamelen;
	kauth_cred_t cred;
	proc_t proc;
{
	register u_long *tl;
	register caddr_t cp;
	register long t1, t2;
	caddr_t bpos, dpos, cp2;
	int error = 0, fwccpostattr = 0, twccpostattr = 0;
	struct timespec fpremtime = { 0, 0 }, tpremtime = { 0, 0 };
	mbuf_t mreq, mrep, md, mb, mb2;
	int v3;
	u_int64_t xid;

	if (!VFSTONFS(vnode_mount(fdvp)))
		return (ENXIO);
	v3 = NFS_ISV3(fdvp);

	nfsm_reqhead((NFSX_FH(v3) + NFSX_UNSIGNED)*2 + nfsm_rndup(fnamelen) +
		      nfsm_rndup(tnamelen));
	if (error)
		return (error);
	OSAddAtomic(1, (SInt32*)&nfsstats.rpccnt[NFSPROC_RENAME]);
	nfsm_fhtom(fdvp, v3);
	nfsm_strtom(fnameptr, fnamelen, NFS_MAXNAMLEN, v3);
	nfsm_fhtom(tdvp, v3);
	nfsm_strtom(tnameptr, tnamelen, NFS_MAXNAMLEN, v3);
	nfsm_request(fdvp, NFSPROC_RENAME, proc, cred, &xid);
	if (v3 && mrep) {
		u_int64_t txid = xid;

		nfsm_wcc_data(fdvp, &fpremtime, fwccpostattr, &xid);
		nfsm_wcc_data(tdvp, &tpremtime, twccpostattr, &txid);
	}
	nfsm_reqdone;
	VTONFS(fdvp)->n_flag |= NMODIFIED;
	/* if directory hadn't changed, update namecache mtime */
	if (nfstimespeccmp(&VTONFS(fdvp)->n_ncmtime, &fpremtime, ==))
		VTONFS(fdvp)->n_ncmtime = VTONFS(fdvp)->n_vattr.nva_mtime;
	if (!fwccpostattr)
		NATTRINVALIDATE(VTONFS(fdvp));
	VTONFS(tdvp)->n_flag |= NMODIFIED;
	/* if directory hadn't changed, update namecache mtime */
	if (nfstimespeccmp(&VTONFS(tdvp)->n_ncmtime, &tpremtime, ==))
		VTONFS(tdvp)->n_ncmtime = VTONFS(tdvp)->n_vattr.nva_mtime;
	if (!twccpostattr)
		NATTRINVALIDATE(VTONFS(tdvp));
	return (error);
}

/*
 * nfs hard link create call
 */
static int
nfs_link(ap)
	struct vnop_link_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		vnode_t a_tdvp;
		struct componentname *a_cnp;
		vfs_context_t a_context;
	} */ *ap;
{
	vnode_t vp = ap->a_vp;
	vnode_t tdvp = ap->a_tdvp;
	struct componentname *cnp = ap->a_cnp;
	u_long *tl;
	caddr_t cp;
	long t1, t2;
	caddr_t bpos, dpos, cp2;
	int error = 0, wccpostattr = 0, attrflag = 0;
	struct timespec premtime = { 0, 0 };
	mbuf_t mreq, mrep, md, mb, mb2;
	int v3;
	u_int64_t xid;
	kauth_cred_t cred;
	proc_t p;

	if (vnode_mount(vp) != vnode_mount(tdvp)) {
		return (EXDEV);
	}

	cred = vfs_context_ucred(ap->a_context);
	p = vfs_context_proc(ap->a_context);

	v3 = NFS_ISV3(vp);

	/*
	 * Push all writes to the server, so that the attribute cache
	 * doesn't get "out of sync" with the server.
	 * XXX There should be a better way!
	 */
	nfs_flush(vp, MNT_WAIT, cred, p, 0);

	nfsm_reqhead(NFSX_FH(v3)*2 + NFSX_UNSIGNED + nfsm_rndup(cnp->cn_namelen));
	if (error)
		return (error);
	OSAddAtomic(1, (SInt32*)&nfsstats.rpccnt[NFSPROC_LINK]);
	nfsm_fhtom(vp, v3);
	nfsm_fhtom(tdvp, v3);
	nfsm_strtom(cnp->cn_nameptr, cnp->cn_namelen, NFS_MAXNAMLEN, v3);
	nfsm_request(vp, NFSPROC_LINK, p, cred, &xid);
	if (v3 && mrep) {
		u_int64_t txid = xid;

		nfsm_postop_attr_update(vp, v3, attrflag, &xid);
		nfsm_wcc_data(tdvp, &premtime, wccpostattr, &txid);
	}
	nfsm_reqdone;

	VTONFS(tdvp)->n_flag |= NMODIFIED;
	if (!attrflag)
		NATTRINVALIDATE(VTONFS(vp));
	/* if directory hadn't changed, update namecache mtime */
	if (nfstimespeccmp(&VTONFS(tdvp)->n_ncmtime, &premtime, ==))
		VTONFS(tdvp)->n_ncmtime = VTONFS(tdvp)->n_vattr.nva_mtime;
	if (!wccpostattr)
		NATTRINVALIDATE(VTONFS(tdvp));
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
	struct vnop_symlink_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_dvp;
		vnode_t *a_vpp;
		struct componentname *a_cnp;
		struct vnode_attr *a_vap;
		char *a_target;
		vfs_context_t a_context;
	} */ *ap;
{
	vnode_t dvp = ap->a_dvp;
	struct vnode_attr *vap = ap->a_vap;
	struct componentname *cnp = ap->a_cnp;
	struct nfs_vattr nvattr;
	struct nfsv2_sattr *sp;
	u_long *tl;
	caddr_t cp;
	long t1, t2;
	caddr_t bpos, dpos, cp2;
	int slen, error = 0, wccpostattr = 0, gotvp = 0;
	struct timespec premtime = { 0, 0 };
	mbuf_t mreq, mrep, md, mb, mb2;
	vnode_t newvp = (vnode_t)0;
	int v3 = NFS_ISV3(dvp);
	int gotuid, gotgid;
	u_int64_t xid;
	kauth_cred_t cred;
	proc_t p;
	struct nfsnode *np = NULL;

	cred = vfs_context_ucred(ap->a_context);
	p = vfs_context_proc(ap->a_context);

	slen = strlen(ap->a_target);
	nfsm_reqhead(NFSX_FH(v3) + 2*NFSX_UNSIGNED +
	    nfsm_rndup(cnp->cn_namelen) + nfsm_rndup(slen) + NFSX_SATTR(v3));
	if (error)
		return (error);

	VATTR_SET_SUPPORTED(vap, va_mode);
	VATTR_SET_SUPPORTED(vap, va_uid);
	VATTR_SET_SUPPORTED(vap, va_gid);
	VATTR_SET_SUPPORTED(vap, va_data_size);
	VATTR_SET_SUPPORTED(vap, va_access_time);
	VATTR_SET_SUPPORTED(vap, va_modify_time);
	gotuid = VATTR_IS_ACTIVE(vap, va_uid);
	gotgid = VATTR_IS_ACTIVE(vap, va_gid);

	OSAddAtomic(1, (SInt32*)&nfsstats.rpccnt[NFSPROC_SYMLINK]);
	nfsm_fhtom(dvp, v3);
	nfsm_strtom(cnp->cn_nameptr, cnp->cn_namelen, NFS_MAXNAMLEN, v3);
	if (v3) {
		nfsm_v3sattr(vap);
	}
	nfsm_strtom(ap->a_target, slen, NFS_MAXPATHLEN, v3);
	if (!v3) {
		struct timespec neg1time = { -1, -1 };
		nfsm_build(sp, struct nfsv2_sattr *, NFSX_V2SATTR);
		sp->sa_mode = vtonfsv2_mode(VLNK,
			(VATTR_IS_ACTIVE(vap, va_mode) ? vap->va_mode : 0600));
		sp->sa_uid = gotuid ? (u_long)txdr_unsigned(vap->va_uid) : nfs_xdrneg1;
		sp->sa_gid = gotgid ? (u_long)txdr_unsigned(vap->va_gid) : nfs_xdrneg1;
		sp->sa_size = nfs_xdrneg1;
		if (VATTR_IS_ACTIVE(vap, va_access_time)) {
			txdr_nfsv2time(&vap->va_access_time, &sp->sa_atime);
		} else {
			txdr_nfsv2time(&neg1time, &sp->sa_atime);
		}
		if (VATTR_IS_ACTIVE(vap, va_modify_time)) {
			txdr_nfsv2time(&vap->va_modify_time, &sp->sa_mtime);
		} else {
			txdr_nfsv2time(&neg1time, &sp->sa_mtime);
		}
	}
	nfsm_request(dvp, NFSPROC_SYMLINK, p, cred, &xid);
	if (v3 && mrep) {
		u_int64_t dxid = xid;

		if (!error)
			nfsm_mtofh(dvp, cnp, newvp, v3, &xid, gotvp);
		nfsm_wcc_data(dvp, &premtime, wccpostattr, &dxid);
	}
	nfsm_reqdone;

	VTONFS(dvp)->n_flag |= NMODIFIED;
	/* if directory hadn't changed, update namecache mtime */
	if (nfstimespeccmp(&VTONFS(dvp)->n_ncmtime, &premtime, ==))
		VTONFS(dvp)->n_ncmtime = VTONFS(dvp)->n_vattr.nva_mtime;
	if (!wccpostattr)
		NATTRINVALIDATE(VTONFS(dvp));

	/*
	 * Kludge: Map EEXIST => 0 assuming that you have a reply to a retry
	 * if we can succeed in looking up the symlink.
	 */
	if ((error == EEXIST) || (!error && !gotvp)) {
		if (newvp) {
			vnode_put(newvp);
			newvp = NULL;
		}
		error = nfs_lookitup(dvp, cnp->cn_nameptr, cnp->cn_namelen, cred, p, &np);
		if (!error) {
			newvp = NFSTOV(np);
			if (vnode_vtype(newvp) != VLNK)
				error = EEXIST;
		}
	}
	if (!error && (gotuid || gotgid) &&
	    (!newvp || nfs_getattrcache(newvp, &nvattr) ||
	     (gotuid && (nvattr.nva_uid != vap->va_uid)) ||
	     (gotgid && (nvattr.nva_gid != vap->va_gid)))) {
		/* clear ID bits if server didn't use them (or we can't tell) */
		VATTR_CLEAR_SUPPORTED(vap, va_uid);
		VATTR_CLEAR_SUPPORTED(vap, va_gid);
	}
	if (error) {
		if (newvp)
			vnode_put(newvp);
	} else {
		*ap->a_vpp = newvp;
	}
	return (error);
}

/*
 * nfs make dir call
 */
static int
nfs_mkdir(ap)
	struct vnop_mkdir_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_dvp;
		vnode_t *a_vpp;
		struct componentname *a_cnp;
		struct vnode_attr *a_vap;
		vfs_context_t a_context;
	} */ *ap;
{
	vnode_t dvp = ap->a_dvp;
	struct vnode_attr *vap = ap->a_vap;
	struct componentname *cnp = ap->a_cnp;
	struct nfs_vattr nvattr;
	struct nfsv2_sattr *sp;
	u_long *tl;
	caddr_t cp;
	long t1, t2;
	int len;
	struct nfsnode *np = (struct nfsnode *)0;
	vnode_t newvp = (vnode_t)0;
	caddr_t bpos, dpos, cp2;
	int error = 0, wccpostattr = 0;
	struct timespec premtime = { 0, 0 };
	int gotvp = 0;
	mbuf_t mreq, mrep, md, mb, mb2;
	int v3 = NFS_ISV3(dvp);
	int gotuid, gotgid;
	u_int64_t xid, dxid;
	kauth_cred_t cred;
	proc_t p;

	cred = vfs_context_ucred(ap->a_context);
	p = vfs_context_proc(ap->a_context);

	len = cnp->cn_namelen;
	nfsm_reqhead(NFSX_FH(v3) + NFSX_UNSIGNED + nfsm_rndup(len) + NFSX_SATTR(v3));
	if (error)
		return (error);

	VATTR_SET_SUPPORTED(vap, va_mode);
	VATTR_SET_SUPPORTED(vap, va_uid);
	VATTR_SET_SUPPORTED(vap, va_gid);
	VATTR_SET_SUPPORTED(vap, va_data_size);
	VATTR_SET_SUPPORTED(vap, va_access_time);
	VATTR_SET_SUPPORTED(vap, va_modify_time);
	gotuid = VATTR_IS_ACTIVE(vap, va_uid);
	gotgid = VATTR_IS_ACTIVE(vap, va_gid);

	OSAddAtomic(1, (SInt32*)&nfsstats.rpccnt[NFSPROC_MKDIR]);
	nfsm_fhtom(dvp, v3);
	nfsm_strtom(cnp->cn_nameptr, len, NFS_MAXNAMLEN, v3);
	if (v3) {
		nfsm_v3sattr(vap);
	} else {
		struct timespec neg1time = { -1, -1 };
		nfsm_build(sp, struct nfsv2_sattr *, NFSX_V2SATTR);
		sp->sa_mode = vtonfsv2_mode(VDIR,
			(VATTR_IS_ACTIVE(vap, va_mode) ? vap->va_mode : 0600));
		sp->sa_uid = gotuid ? (u_long)txdr_unsigned(vap->va_uid) : nfs_xdrneg1;
		sp->sa_gid = gotgid ? (u_long)txdr_unsigned(vap->va_gid) : nfs_xdrneg1;
		sp->sa_size = nfs_xdrneg1;
		if (VATTR_IS_ACTIVE(vap, va_access_time)) {
			txdr_nfsv2time(&vap->va_access_time, &sp->sa_atime);
		} else {
			txdr_nfsv2time(&neg1time, &sp->sa_atime);
		}
		if (VATTR_IS_ACTIVE(vap, va_modify_time)) {
			txdr_nfsv2time(&vap->va_modify_time, &sp->sa_mtime);
		} else {
			txdr_nfsv2time(&neg1time, &sp->sa_mtime);
		}
	}
	nfsm_request(dvp, NFSPROC_MKDIR, p, cred, &xid);
	dxid = xid;
	if (!error)
		nfsm_mtofh(dvp, cnp, newvp, v3, &xid, gotvp);
	if (v3 && mrep)
		nfsm_wcc_data(dvp, &premtime, wccpostattr, &dxid);
	nfsm_reqdone;
	VTONFS(dvp)->n_flag |= NMODIFIED;
	/* if directory hadn't changed, update namecache mtime */
	if (nfstimespeccmp(&VTONFS(dvp)->n_ncmtime, &premtime, ==))
		VTONFS(dvp)->n_ncmtime = VTONFS(dvp)->n_vattr.nva_mtime;
	if (!wccpostattr)
		NATTRINVALIDATE(VTONFS(dvp));
	/*
	 * Kludge: Map EEXIST => 0 assuming that you have a reply to a retry
	 * if we can succeed in looking up the directory.
	 */
	if (error == EEXIST || (!error && !gotvp)) {
		if (newvp) {
			vnode_put(newvp);
			newvp = NULL;
		}
		error = nfs_lookitup(dvp, cnp->cn_nameptr, len, cred, p, &np);
		if (!error) {
			newvp = NFSTOV(np);
			if (vnode_vtype(newvp) != VDIR)
				error = EEXIST;
		}
	}
	if (!error && (gotuid || gotgid) &&
	    (!newvp || nfs_getattrcache(newvp, &nvattr) ||
	     (gotuid && (nvattr.nva_uid != vap->va_uid)) ||
	     (gotgid && (nvattr.nva_gid != vap->va_gid)))) {
		/* clear ID bits if server didn't use them (or we can't tell) */
		VATTR_CLEAR_SUPPORTED(vap, va_uid);
		VATTR_CLEAR_SUPPORTED(vap, va_gid);
	}
	if (error) {
		if (newvp)
			vnode_put(newvp);
	} else {
		*ap->a_vpp = newvp;
	}
	return (error);
}

/*
 * nfs remove directory call
 */
static int
nfs_rmdir(ap)
	struct vnop_rmdir_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_dvp;
		vnode_t a_vp;
		struct componentname *a_cnp;
		vfs_context_t a_context;
	} */ *ap;
{
	vnode_t vp = ap->a_vp;
	vnode_t dvp = ap->a_dvp;
	struct componentname *cnp = ap->a_cnp;
	u_long *tl;
	caddr_t cp;
	long t1, t2;
	caddr_t bpos, dpos, cp2;
	int error = 0, wccpostattr = 0;
	struct timespec premtime = { 0, 0 };
	mbuf_t mreq, mrep, md, mb, mb2;
	int v3 = NFS_ISV3(dvp);
	u_int64_t xid;
	kauth_cred_t cred;
	proc_t p;

	cred = vfs_context_ucred(ap->a_context);
	p = vfs_context_proc(ap->a_context);

	nfsm_reqhead(NFSX_FH(v3) + NFSX_UNSIGNED + nfsm_rndup(cnp->cn_namelen));
	if (error)
		return (error);
	OSAddAtomic(1, (SInt32*)&nfsstats.rpccnt[NFSPROC_RMDIR]);
	nfsm_fhtom(dvp, v3);
	nfsm_strtom(cnp->cn_nameptr, cnp->cn_namelen, NFS_MAXNAMLEN, v3);
	nfsm_request(dvp, NFSPROC_RMDIR, p, cred, &xid);
	if (v3 && mrep)
		nfsm_wcc_data(dvp, &premtime, wccpostattr, &xid);
	nfsm_reqdone;
	VTONFS(dvp)->n_flag |= NMODIFIED;
	/* if directory hadn't changed, update namecache mtime */
	if (nfstimespeccmp(&VTONFS(dvp)->n_ncmtime, &premtime, ==))
		VTONFS(dvp)->n_ncmtime = VTONFS(dvp)->n_vattr.nva_mtime;
	if (!wccpostattr)
		NATTRINVALIDATE(VTONFS(dvp));
	cache_purge(vp);
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
		LIST_REMOVE(VTONFS(vp), n_hash);
		VTONFS(vp)->n_flag &= ~NHASHED;
		lck_mtx_unlock(nfs_node_hash_mutex);
	}
	return (error);
}

/*
 * nfs readdir call
 */
static int
nfs_readdir(ap)
	struct vnop_readdir_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		struct uio *a_uio;
		int *a_eofflag;
		int *a_ncookies;
		u_long **a_cookies;
		vfs_context_t a_context;
	} */ *ap;
{
	vnode_t vp = ap->a_vp;
	struct nfsnode *np = VTONFS(vp);
	struct uio *uio = ap->a_uio;
	int tresid, error;
	struct nfs_vattr nvattr;
	kauth_cred_t cred;
	proc_t p;

	if (vnode_vtype(vp) != VDIR)
		return (EPERM);

	cred = vfs_context_ucred(ap->a_context);
	p = vfs_context_proc(ap->a_context);

	/*
	 * First, check for hit on the EOF offset cache
	 */
	if (np->n_direofoffset > 0 && uio->uio_offset >= np->n_direofoffset &&
	    (np->n_flag & NMODIFIED) == 0) {
		if (!nfs_getattr(vp, &nvattr, cred, p)) {
			if (nfstimespeccmp(&np->n_mtime, &nvattr.nva_mtime, ==)) {
				OSAddAtomic(1, (SInt32*)&nfsstats.direofcache_hits);
				return (0);
			}
			if (nfstimespeccmp(&np->n_ncmtime, &nvattr.nva_mtime, !=)) {
				/* directory changed, purge any name cache entries */
				cache_purge(vp);
			}
		}
	}

	/*
	 * Call nfs_bioread() to do the real work.
	 */
	// LP64todo - fix this
	tresid = uio_uio_resid(uio);
	error = nfs_bioread(vp, uio, 0, cred, p);

	if (!error && uio_uio_resid(uio) == tresid)
		OSAddAtomic(1, (SInt32*)&nfsstats.direofcache_misses);
	return (error);
}

/*
 * Readdir rpc call.
 * Called from below the buffer cache by nfs_doio().
 */
int
nfs_readdirrpc(
	vnode_t vp,
	struct uio *uiop,
	kauth_cred_t cred,
	proc_t p)
{
	register int len, skiplen, left;
	register struct dirent *dp;
	register u_long *tl;
	register caddr_t cp;
	register long t1, t2;
	register nfsuint64 *cookiep;
	caddr_t bpos, dpos, cp2;
	mbuf_t mreq, mrep, md, mb, mb2;
	nfsuint64 cookie;
	struct nfsmount *nmp;
	struct nfsnode *dnp = VTONFS(vp);
	u_quad_t fileno;
	int error = 0, tlen, more_dirs = 1, blksiz = 0, bigenough = 1;
	int attrflag;
	int v3, nmreaddirsize;
	u_int64_t xid;

#ifndef nolint
	dp = (struct dirent *)0;
#endif
#if DIAGNOSTIC
	if (uiop->uio_iovcnt != 1 || (uiop->uio_offset & (NFS_DIRBLKSIZ - 1)) ||
		(uio_uio_resid(uiop) & (NFS_DIRBLKSIZ - 1)))
		panic("nfs_readdirrpc: bad uio");
#endif
	nmp = VFSTONFS(vnode_mount(vp));
	if (!nmp)
		return (ENXIO);
	v3 = NFS_ISV3(vp);
	nmreaddirsize = nmp->nm_readdirsize;

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
		nfsm_reqhead(NFSX_FH(v3) + NFSX_READDIR(v3));
		if (error)
			goto nfsmout;
		OSAddAtomic(1, (SInt32*)&nfsstats.rpccnt[NFSPROC_READDIR]);
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
		*tl = txdr_unsigned(nmreaddirsize);
		nfsm_request(vp, NFSPROC_READDIR, p, cred, &xid);
		if (v3) {
			if (mrep) {
				nfsm_postop_attr_update(vp, v3, attrflag, &xid);
			}
			if (!error) {
				nfsm_dissect(tl, u_long *, 2 * NFSX_UNSIGNED);
				dnp->n_cookieverf.nfsuquad[0] = *tl++;
				dnp->n_cookieverf.nfsuquad[1] = *tl;
			} else {
				mbuf_freem(mrep);
				goto nfsmout;
			}
		} else if (!mrep) {
			// XXX assert error?
			goto nfsmout;
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
			/* Note: v3 supports longer names, but struct dirent doesn't */
			/* so we just truncate the names to fit */
			if (len <= 0) {
				error = EBADRPC;
				mbuf_freem(mrep);
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
			if ((tlen + (int)DIRHDSIZ) > left) {
				dp->d_reclen += left;
				uio_iov_base_add(uiop, left);
				uio_iov_len_add(uiop, -left);
				uiop->uio_offset += left;
				uio_uio_resid_add(uiop, -left);
				blksiz = 0;
			}
			if ((tlen + (int)DIRHDSIZ) > uio_uio_resid(uiop))
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
				nfsm_mtouio(uiop, len);
				// LP64todo - fix this!
				cp = CAST_DOWN(caddr_t, uio_iov_base(uiop));
				tlen -= len;
				*cp = '\0';	/* null terminate */
				uio_iov_base_add(uiop, tlen);
				uio_iov_len_add(uiop, -tlen);
				uiop->uio_offset += tlen;
				uio_uio_resid_add(uiop, -tlen);
			} else {
				nfsm_adv(nfsm_rndup(len));
			}
			if (skiplen)
				nfsm_adv(nfsm_rndup(skiplen));
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
		mbuf_freem(mrep);
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
	return (error);
}

/*
 * NFS V3 readdir plus RPC. Used in place of nfs_readdirrpc().
 */
int
nfs_readdirplusrpc(
	vnode_t vp,
	struct uio *uiop,
	kauth_cred_t cred,
	proc_t p)
{
	int len, skiplen, left;
	struct dirent *dp;
	u_long *tl;
	caddr_t cp;
	long t1, t2;
	vnode_t newvp;
	nfsuint64 *cookiep;
	caddr_t bpos, dpos, cp2;
	mbuf_t mreq, mrep, md, mb, mb2;
	struct componentname cn, *cnp = &cn;
	nfsuint64 cookie;
	struct nfsmount *nmp;
	struct nfsnode *dnp = VTONFS(vp), *np;
	u_char *fhp;
	u_quad_t fileno;
	int error = 0, tlen, more_dirs = 1, blksiz = 0, doit, bigenough = 1, i;
	int attrflag, fhsize, nmreaddirsize, nmrsize;
	u_int64_t xid, savexid;
	struct nfs_vattr nvattr;

#ifndef nolint
	dp = (struct dirent *)0;
#endif
#if DIAGNOSTIC
	if (uiop->uio_iovcnt != 1 || (uiop->uio_offset & (DIRBLKSIZ - 1)) ||
		(uio_uio_resid(uiop) & (DIRBLKSIZ - 1)))
		panic("nfs_readdirplusrpc: bad uio");
#endif
	nmp = VFSTONFS(vnode_mount(vp));
	if (!nmp)
		return (ENXIO);
	nmreaddirsize = nmp->nm_readdirsize;
	nmrsize = nmp->nm_rsize;

	bzero(cnp, sizeof(*cnp));
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
		nfsm_reqhead(NFSX_FH(1) + 6 * NFSX_UNSIGNED);
		if (error)
			goto nfsmout;
		OSAddAtomic(1, (SInt32*)&nfsstats.rpccnt[NFSPROC_READDIRPLUS]);
		nfsm_fhtom(vp, 1);
 		nfsm_build(tl, u_long *, 6 * NFSX_UNSIGNED);
		*tl++ = cookie.nfsuquad[0];
		*tl++ = cookie.nfsuquad[1];
		*tl++ = dnp->n_cookieverf.nfsuquad[0];
		*tl++ = dnp->n_cookieverf.nfsuquad[1];
		*tl++ = txdr_unsigned(nmreaddirsize);
		*tl = txdr_unsigned(nmrsize);
		nfsm_request(vp, NFSPROC_READDIRPLUS, p, cred, &xid);
		savexid = xid;
		if (mrep) {
			nfsm_postop_attr_update(vp, 1, attrflag, &xid);
		}
		if (error) {
			mbuf_freem(mrep);
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
			/* Note: v3 supports longer names, but struct dirent doesn't */
			/* so we just truncate the names to fit */
			if (len <= 0) {
				error = EBADRPC;
				mbuf_freem(mrep);
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
				tlen += 4;	/* To ensure null termination*/
			left = DIRBLKSIZ - blksiz;
			if ((tlen + (int)DIRHDSIZ) > left) {
				dp->d_reclen += left;
				uio_iov_base_add(uiop, left);
				uio_iov_len_add(uiop, -left);
				uiop->uio_offset += left;
				uio_uio_resid_add(uiop, -left);
				blksiz = 0;
			}
			if ((tlen + (int)DIRHDSIZ) > uio_uio_resid(uiop))
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
				nfsm_mtouio(uiop, len);
				cp = CAST_DOWN(caddr_t, uio_iov_base(uiop));
				tlen -= len;
				*cp = '\0';
				uio_iov_base_add(uiop, tlen);
				uio_iov_len_add(uiop, -tlen);
				uiop->uio_offset += tlen;
				uio_uio_resid_add(uiop, -tlen);
			} else {
				nfsm_adv(nfsm_rndup(len));
			}
			if (skiplen)
				nfsm_adv(nfsm_rndup(skiplen));
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
			    /* grab attributes */
			    nfsm_attr_get(1, &nvattr);
			    dp->d_type = IFTODT(VTTOIF(nvattr.nva_type));
			    /* check for file handle */
			    nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
			    doit = fxdr_unsigned(int, *tl);
			    if (doit) {
				nfsm_getfh(fhp, fhsize, 1);
				if (NFS_CMPFH(dnp, fhp, fhsize)) {
				    error = vnode_ref(vp);
				    if (error) {
					doit = 0;
				    } else {
					newvp = vp;
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

				    error = nfs_nget(vnode_mount(vp), vp, cnp,
				    		fhp, fhsize, &nvattr, &xid,
						NG_MAKEENTRY, &np);
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
			    nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
			    i = fxdr_unsigned(int, *tl);
			    nfsm_adv(nfsm_rndup(i));
			}
			if (newvp != NULLVP) {
			    if (newvp == vp)
				vnode_rele(newvp);
			    else
				vnode_put(newvp);
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
		mbuf_freem(mrep);
	}
	/*
	 * Fill last record, iff any, out to a multiple of NFS_DIRBLKSIZ
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

	/*
	 * We are now either at the end of the directory or have filled the
	 * block.
	 */
	if (bigenough)
		dnp->n_direofoffset = uiop->uio_offset;
	else {
		if (uio_uio_resid(uiop) > 0)
			printf("EEK! readdirplusrpc resid > 0\n");
		cookiep = nfs_getcookie(dnp, uiop->uio_offset, 1);
		if (cookiep)
			*cookiep = cookie;
	}
nfsmout:
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

/* format of "random" names and next name to try */
/* (note: shouldn't exceed size of sillyrename.s_name) */
static char sillyrename_name[] = ".nfsAAA%04x4.4";

static int
nfs_sillyrename(
	vnode_t dvp,
	vnode_t vp,
	struct componentname *cnp,
	kauth_cred_t cred,
	proc_t p)
{
	register struct sillyrename *sp;
	struct nfsnode *np;
	int error;
	short pid;
	kauth_cred_t tmpcred;
	int i, j, k;

	cache_purge(vp);
	np = VTONFS(vp);
#if DIAGNOSTIC
	if (vnode_vtype(vp) == VDIR)
		panic("nfs_sillyrename: dir");
#endif
	MALLOC_ZONE(sp, struct sillyrename *,
			sizeof (struct sillyrename), M_NFSREQ, M_WAITOK);
	if (!sp)
		return (ENOMEM);
	kauth_cred_ref(cred);
	sp->s_cred = cred;
	sp->s_dvp = dvp;
	error = vnode_ref(dvp);
	if (error)
		goto bad_norele;

	/* Fudge together a funny name */
	pid = proc_pid(p);
	sp->s_namlen = sprintf(sp->s_name, sillyrename_name, pid);

	/* Try lookitups until we get one that isn't there */
	i = j = k = 0;
	while (nfs_lookitup(dvp, sp->s_name, sp->s_namlen, sp->s_cred, p, NULL) == 0) {
		if (sp->s_name[4]++ >= 'z')
			sp->s_name[4] = 'A';
		if (++i > ('z' - 'A' + 1)) {
			i = 0;
			if (sp->s_name[5]++ >= 'z')
				sp->s_name[5] = 'A';
			if (++j > ('z' - 'A' + 1)) {
				j = 0;
				if (sp->s_name[6]++ >= 'z')
					sp->s_name[6] = 'A';
				if (++k > ('z' - 'A' + 1)) {
					error = EINVAL;
					goto bad;
				}
			}
		}
	}
	/* make note of next "random" name to try */
	if ((sillyrename_name[4] = (sp->s_name[4] + 1)) > 'z') {
		sillyrename_name[4] = 'A';
		if ((sillyrename_name[5] = (sp->s_name[5] + 1)) > 'z') {
			sillyrename_name[5] = 'A';
			if ((sillyrename_name[6] = (sp->s_name[6] + 1)) > 'z')
				sillyrename_name[6] = 'A';
		}
	}
	/* now, do the rename */
	error = nfs_renamerpc(dvp, cnp->cn_nameptr, cnp->cn_namelen,
				dvp, sp->s_name, sp->s_namlen, sp->s_cred, p);
	if (error)
		goto bad;
	error = nfs_lookitup(dvp, sp->s_name, sp->s_namlen, sp->s_cred, p, &np);
#if DIAGNOSTIC
	kprintf("sillyrename: %s, vp=%x, np=%x, dvp=%x\n",
		&sp->s_name[0], (unsigned)vp, (unsigned)np, (unsigned)dvp);
#endif
	np->n_sillyrename = sp;
	return (0);
bad:
	vnode_rele(sp->s_dvp);
bad_norele:
	tmpcred = sp->s_cred;
	sp->s_cred = NOCRED;
	kauth_cred_rele(tmpcred);
	FREE_ZONE((caddr_t)sp, sizeof (struct sillyrename), M_NFSREQ);
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
	vnode_t dvp;
	char *name;
	int len;
	kauth_cred_t cred;
	proc_t procp;
	struct nfsnode **npp;
{
	u_long *tl;
	caddr_t cp;
	long t1, t2;
	vnode_t newvp = (vnode_t)0;
	struct nfsnode *np, *dnp = VTONFS(dvp);
	caddr_t bpos, dpos, cp2;
	int error = 0, fhlen, attrflag;
	mbuf_t mreq, mrep, md, mb, mb2;
	u_char *nfhp;
	int v3;
	u_int64_t xid, dxid, savedxid;
	struct nfs_vattr nvattr;

	if (!VFSTONFS(vnode_mount(dvp)))
		return (ENXIO);
	v3 = NFS_ISV3(dvp);

	nfsm_reqhead(NFSX_FH(v3) + NFSX_UNSIGNED + nfsm_rndup(len));
	if (error)
		return (error);
	OSAddAtomic(1, (SInt32*)&nfsstats.rpccnt[NFSPROC_LOOKUP]);
	nfsm_fhtom(dvp, v3);
	nfsm_strtom(name, len, NFS_MAXNAMLEN, v3);
	nfsm_request(dvp, NFSPROC_LOOKUP, procp, cred, &xid);
	if (npp && !error) {
		savedxid = xid;
		nfsm_getfh(nfhp, fhlen, v3);
		/* get attributes */
		if (v3) {
			nfsm_postop_attr_get(v3, attrflag, &nvattr);
			if (!attrflag) {
				/* We need valid attributes in order */
				/* to call nfs_nget/vnode_create().  */
				error = nfs_getattr_no_vnode(vnode_mount(dvp),
						nfhp, fhlen, cred, procp, &nvattr, &xid);
				if (error) {
					mbuf_freem(mrep);
					goto nfsmout;
				}
			}
			dxid = savedxid;
			nfsm_postop_attr_update(dvp, v3, attrflag, &dxid);
		} else {
			nfsm_attr_get(v3, &nvattr);
		}
		if (*npp) {
		    np = *npp;
		    if (fhlen != np->n_fhsize) {
			u_char *oldbuf = (np->n_fhsize > NFS_SMALLFH) ? np->n_fhp : NULL;
			if (fhlen > NFS_SMALLFH) {
			    MALLOC_ZONE(np->n_fhp, u_char *, fhlen, M_NFSBIGFH, M_WAITOK);
			    if (!np->n_fhp) {
				np->n_fhp = oldbuf;
				error = ENOMEM;
				mbuf_freem(mrep);
				goto nfsmout;
			    }
			} else {
			    np->n_fhp = &np->n_fh[0];
			}
			if (oldbuf) {
			    FREE_ZONE(oldbuf, np->n_fhsize, M_NFSBIGFH);
			}
		    }
		    bcopy(nfhp, np->n_fhp, fhlen);
		    np->n_fhsize = fhlen;
		    newvp = NFSTOV(np);
		    error = nfs_loadattrcache(np, &nvattr, &xid, 0);
		    if (error) {
			mbuf_freem(mrep);
			goto nfsmout;
		    }
		} else if (NFS_CMPFH(dnp, nfhp, fhlen)) {
		    newvp = dvp;
		    if (dnp->n_xid <= savedxid) {
			dxid = savedxid;
			error = nfs_loadattrcache(dnp, &nvattr, &dxid, 0);
			if (error) {
			    mbuf_freem(mrep);
			    goto nfsmout;
			}
		    }
		} else {
		    struct componentname cn, *cnp = &cn;
		    bzero(cnp, sizeof(*cnp));
		    cnp->cn_nameptr = name;
		    cnp->cn_namelen = len;

		    error = nfs_nget(vnode_mount(dvp), dvp, cnp, nfhp, fhlen,
				&nvattr, &xid, NG_MAKEENTRY, &np);
		    if (error) {
			mbuf_freem(mrep);
			return (error);
		    }
		    newvp = NFSTOV(np);
		}
	}
	nfsm_reqdone;
	if (npp && *npp == NULL) {
		if (error) {
			if (newvp) {
				if (newvp == dvp)
					vnode_rele(newvp);
				else
					vnode_put(newvp);
			}
		} else
			*npp = np;
	}
	return (error);
}

/*
 * Nfs Version 3 commit rpc
 */
int
nfs_commit(vp, offset, count, cred, procp)
	vnode_t vp;
	u_quad_t offset;
	u_int32_t count;
	kauth_cred_t cred;
	proc_t procp;
{
	caddr_t cp;
	u_long *tl;
	int t1, t2;
	struct nfsmount *nmp = VFSTONFS(vnode_mount(vp));
	caddr_t bpos, dpos, cp2;
	int error = 0, wccpostattr = 0;
	struct timespec premtime = { 0, 0 };
	mbuf_t mreq, mrep, md, mb, mb2;
	u_int64_t xid;
	
	FSDBG(521, vp, offset, count, nmp->nm_state);
	if (!nmp)
		return (ENXIO);
	if ((nmp->nm_state & NFSSTA_HASWRITEVERF) == 0)
		return (0);
	nfsm_reqhead(NFSX_FH(1));
	if (error)
		return (error);
	OSAddAtomic(1, (SInt32*)&nfsstats.rpccnt[NFSPROC_COMMIT]);
	nfsm_fhtom(vp, 1);
	nfsm_build(tl, u_long *, 3 * NFSX_UNSIGNED);
	txdr_hyper(&offset, tl);
	tl += 2;
	*tl = txdr_unsigned(count);
	nfsm_request(vp, NFSPROC_COMMIT, procp, cred, &xid);
	if (mrep) {
		nfsm_wcc_data(vp, &premtime, wccpostattr, &xid);
		/* XXX can we do anything useful with the wcc info? */
	}
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

static int
nfs_blockmap(
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
nfs_mmap(
	__unused struct vnop_mmap_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		int a_fflags;
		kauth_cred_t a_cred;
		proc_t a_p;
	} */ *ap)
{

	return (EINVAL);
}

/*
 * fsync vnode op. Just call nfs_flush() with commit == 1.
 */
/* ARGSUSED */
static int
nfs_fsync(ap)
	struct vnop_fsync_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		int a_waitfor;
		vfs_context_t a_context;
	} */ *ap;
{
	kauth_cred_t cred = vfs_context_ucred(ap->a_context);
	proc_t p = vfs_context_proc(ap->a_context);
	struct nfsnode *np = VTONFS(ap->a_vp);
	int error;

	np->n_flag |= NWRBUSY;
	error = nfs_flush(ap->a_vp, ap->a_waitfor, cred, p, 0);
	np->n_flag &= ~NWRBUSY;
	return (error);
}
 
int
nfs_flushcommits(vnode_t vp, proc_t p, int nowait)
{
	struct nfsnode *np = VTONFS(vp);
	struct nfsbuf *bp;
	struct nfsbuflists blist, commitlist;
	int error = 0, retv, wcred_set, flags;
	u_quad_t off, endoff, toff;
	u_int32_t count;
	kauth_cred_t wcred = NULL;

	FSDBG_TOP(557, vp, np, 0, 0);

	/*
	 * A nb_flags == (NB_DELWRI | NB_NEEDCOMMIT) block has been written to the
	 * server, but nas not been committed to stable storage on the server
	 * yet. The byte range is worked out for as many nfsbufs as we can handle
	 * and the commit rpc is done.
	 */
	if (!LIST_EMPTY(&np->n_dirtyblkhd))
		np->n_flag |= NMODIFIED;

	off = (u_quad_t)-1;
	endoff = 0;
	wcred_set = 0;
	LIST_INIT(&commitlist);

	if (!VFSTONFS(vnode_mount(vp))) {
		error = ENXIO;
		goto done;
	}
	if (!NFS_ISV3(vp)) {
		error = EINVAL;
		goto done;
	}

	flags = NBI_DIRTY;
	if (nowait)
		flags |= NBI_NOWAIT;
	lck_mtx_lock(nfs_buf_mutex);
	if (!nfs_buf_iterprepare(np, &blist, flags)) {
		while ((bp = LIST_FIRST(&blist))) {
			LIST_REMOVE(bp, nb_vnbufs);
			LIST_INSERT_HEAD(&np->n_dirtyblkhd, bp, nb_vnbufs);
			error = nfs_buf_acquire(bp, NBAC_NOWAIT, 0, 0);
			if (error)
				continue;
			if (((bp->nb_flags & (NB_DELWRI | NB_NEEDCOMMIT))
				!= (NB_DELWRI | NB_NEEDCOMMIT))) {
				nfs_buf_drop(bp);
				continue;
			}
			nfs_buf_remfree(bp);
			lck_mtx_unlock(nfs_buf_mutex);
			/*
			 * we need a upl to see if the page has been
			 * dirtied (think mmap) since the unstable write, and
			 * also to prevent vm from paging it during our commit rpc
			 */
			if (!ISSET(bp->nb_flags, NB_PAGELIST)) {
				retv = nfs_buf_upl_setup(bp);
				if (retv) {
					/* unable to create upl */
					/* vm object must no longer exist */
					/* this could be fatal if we need */
					/* to write the data again, we'll see...  */
					printf("nfs_flushcommits: upl create failed %d\n", retv);
					bp->nb_valid = bp->nb_dirty = 0;
				}
			}
			nfs_buf_upl_check(bp);
			lck_mtx_lock(nfs_buf_mutex);

			FSDBG(557, bp, bp->nb_flags, bp->nb_valid, bp->nb_dirty);
			FSDBG(557, bp->nb_validoff, bp->nb_validend,
			      bp->nb_dirtyoff, bp->nb_dirtyend);

			/*
			 * We used to check for dirty pages here; if there were any
			 * we'd abort the commit and force the entire buffer to be
			 * written again.
			 *
			 * Instead of doing that, we now go ahead and commit the dirty
			 * range, and then leave the buffer around with dirty pages
			 * that will be written out later.
			 */

			/*
			 * Work out if all buffers are using the same cred
			 * so we can deal with them all with one commit.
			 *
			 * XXX creds in bp's must be obtained by kauth_cred_ref on
			 *     the same original cred in order for them to be equal.
			 */
			if (wcred_set == 0) {
				wcred = bp->nb_wcred;
				if (wcred == NOCRED)
					panic("nfs: needcommit w/out wcred");
				wcred_set = 1;
			} else if ((wcred_set == 1) && wcred != bp->nb_wcred) {
				wcred_set = -1;
			}
			SET(bp->nb_flags, NB_WRITEINPROG);

			/*
			 * A list of these buffers is kept so that the
			 * second loop knows which buffers have actually
			 * been committed. This is necessary, since there
			 * may be a race between the commit rpc and new
			 * uncommitted writes on the file.
			 */
			LIST_REMOVE(bp, nb_vnbufs);
			LIST_INSERT_HEAD(&commitlist, bp, nb_vnbufs);
			toff = NBOFF(bp) + bp->nb_dirtyoff;
			if (toff < off)
				off = toff;
			toff += (u_quad_t)(bp->nb_dirtyend - bp->nb_dirtyoff);
			if (toff > endoff)
				endoff = toff;
		}
		nfs_buf_itercomplete(np, &blist, NBI_DIRTY);
	}
	lck_mtx_unlock(nfs_buf_mutex);

	if (LIST_EMPTY(&commitlist)) {
		error = ENOBUFS;
		goto done;
	}

	/*
	 * Commit data on the server, as required.
	 * If all bufs are using the same wcred, then use that with
	 * one call for all of them, otherwise commit each one
	 * separately.
	 */
	if (wcred_set == 1) {
		/*
		 * Note, it's possible the commit range could be >2^32-1.
		 * If it is, we'll send one commit that covers the whole file.
		 */
		if ((endoff - off) > 0xffffffff)
			count = 0; 
		else
			count = (endoff - off); 
		retv = nfs_commit(vp, off, count, wcred, p);
	} else {
		retv = 0;
		LIST_FOREACH(bp, &commitlist, nb_vnbufs) {
			toff = NBOFF(bp) + bp->nb_dirtyoff;
			count = bp->nb_dirtyend - bp->nb_dirtyoff;
			retv = nfs_commit(vp, toff, count, bp->nb_wcred, p);
			if (retv)
				break;
		}
	}
	if (retv == NFSERR_STALEWRITEVERF)
		nfs_clearcommit(vnode_mount(vp));

	/*
	 * Now, either mark the blocks I/O done or mark the
	 * blocks dirty, depending on whether the commit
	 * succeeded.
	 */
	while ((bp = LIST_FIRST(&commitlist))) {
		LIST_REMOVE(bp, nb_vnbufs);
		FSDBG(557, bp, retv, bp->nb_flags, bp->nb_dirty);
		CLR(bp->nb_flags, (NB_NEEDCOMMIT | NB_WRITEINPROG));
		np->n_needcommitcnt--;
		CHECK_NEEDCOMMITCNT(np);

		if (retv) {
			/* move back to dirty list */
			lck_mtx_lock(nfs_buf_mutex);
			LIST_INSERT_HEAD(&VTONFS(vp)->n_dirtyblkhd, bp, nb_vnbufs);
			lck_mtx_unlock(nfs_buf_mutex);
			nfs_buf_release(bp, 1);
			continue;
		}

		vnode_startwrite(vp);
		if (ISSET(bp->nb_flags, NB_DELWRI)) {
			OSAddAtomic(-1, (SInt32*)&nfs_nbdwrite);
			NFSBUFCNTCHK(0);
			wakeup(&nfs_nbdwrite);
		}
		CLR(bp->nb_flags, (NB_READ|NB_DONE|NB_ERROR|NB_DELWRI));
		/* if block still has dirty pages, we don't want it to */
		/* be released in nfs_buf_iodone().  So, don't set NB_ASYNC. */
		if (!bp->nb_dirty)
			SET(bp->nb_flags, NB_ASYNC);

		/* move to clean list */
		lck_mtx_lock(nfs_buf_mutex);
		LIST_INSERT_HEAD(&VTONFS(vp)->n_cleanblkhd, bp, nb_vnbufs);
		lck_mtx_unlock(nfs_buf_mutex);

		bp->nb_dirtyoff = bp->nb_dirtyend = 0;

		nfs_buf_iodone(bp);
		if (bp->nb_dirty) {
			/* throw it back in as a delayed write buffer */
			CLR(bp->nb_flags, NB_DONE);
			nfs_buf_write_delayed(bp, p);
		}
	}

done:
	FSDBG_BOT(557, vp, np, 0, error);
	return (error);
}

/*
 * Flush all the blocks associated with a vnode.
 * 	Walk through the buffer pool and push any dirty pages
 *	associated with the vnode.
 */
int
nfs_flush(
	vnode_t vp,
	int waitfor,
	__unused kauth_cred_t cred,
	proc_t p,
	int ignore_writeerr)
{
	struct nfsnode *np = VTONFS(vp);
	struct nfsbuf *bp;
	struct nfsbuflists blist;
	struct nfsmount *nmp = VFSTONFS(vnode_mount(vp));
	int error = 0, error2, slptimeo = 0, slpflag = 0;
	int flags, passone = 1;

	FSDBG_TOP(517, vp, np, waitfor, 0);

	if (!nmp) {
		error = ENXIO;
		goto done;
	}
	if (nmp->nm_flag & NFSMNT_INT)
		slpflag = PCATCH;

	/*
	 * On the first pass, start async/unstable writes on all
	 * delayed write buffers.  Then wait for all writes to complete
	 * and call nfs_flushcommits() to commit any uncommitted buffers.
	 * On all subsequent passes, start STABLE writes on any remaining
	 * dirty buffers.  Then wait for all writes to complete.
	 */
again:
	lck_mtx_lock(nfs_buf_mutex);
	FSDBG(518, LIST_FIRST(&np->n_dirtyblkhd), np->n_flag, 0, 0);
	if (!LIST_EMPTY(&np->n_dirtyblkhd))
		np->n_flag |= NMODIFIED;
	if (!VFSTONFS(vnode_mount(vp))) {
		lck_mtx_unlock(nfs_buf_mutex);
		error = ENXIO;
		goto done;
	}

	/* Start/do any write(s) that are required. */
	if (!nfs_buf_iterprepare(np, &blist, NBI_DIRTY)) {
		while ((bp = LIST_FIRST(&blist))) {
			LIST_REMOVE(bp, nb_vnbufs);
			LIST_INSERT_HEAD(&np->n_dirtyblkhd, bp, nb_vnbufs);
			flags = (passone || (waitfor != MNT_WAIT)) ? NBAC_NOWAIT : 0;
			if (flags != NBAC_NOWAIT)
				nfs_buf_refget(bp);
			while ((error = nfs_buf_acquire(bp, flags, slpflag, slptimeo))) {
				FSDBG(524, bp, flags, bp->nb_lflags, bp->nb_flags);
				if (error == EBUSY)
					break;
				if (error) {
					error2 = nfs_sigintr(VFSTONFS(vnode_mount(vp)), NULL, p);
					if (error2) {
						if (flags != NBAC_NOWAIT)
							nfs_buf_refrele(bp);
						nfs_buf_itercomplete(np, &blist, NBI_DIRTY);
						lck_mtx_unlock(nfs_buf_mutex);
						error = error2;
						goto done;
					}
					if (slpflag == PCATCH) {
						slpflag = 0;
						slptimeo = 2 * hz;
					}
				}
			}
			if (flags != NBAC_NOWAIT)
				nfs_buf_refrele(bp);
			if (error == EBUSY)
				continue;
			if (!bp->nb_vp) {
				/* buffer is no longer valid */
				nfs_buf_drop(bp);
				continue;
			}
			if (!ISSET(bp->nb_flags, NB_DELWRI))
				panic("nfs_flush: not dirty");
			FSDBG(525, bp, passone, bp->nb_lflags, bp->nb_flags);
			if ((passone || (waitfor != MNT_WAIT)) &&
			    ISSET(bp->nb_flags, NB_NEEDCOMMIT)) {
				nfs_buf_drop(bp);
				continue;
			}
			nfs_buf_remfree(bp);
			lck_mtx_unlock(nfs_buf_mutex);
			if (ISSET(bp->nb_flags, NB_ERROR)) {
				np->n_error = bp->nb_error ? bp->nb_error : EIO;
				np->n_flag |= NWRITEERR;
				nfs_buf_release(bp, 1);
				lck_mtx_lock(nfs_buf_mutex);
				continue;
			}
			SET(bp->nb_flags, NB_ASYNC);
			if (!passone) {
				/* NB_STABLE forces this to be written FILESYNC */
				SET(bp->nb_flags, NB_STABLE);
			}
			nfs_buf_write(bp);
			lck_mtx_lock(nfs_buf_mutex);
		}
		nfs_buf_itercomplete(np, &blist, NBI_DIRTY);
	}
	lck_mtx_unlock(nfs_buf_mutex);

	if (waitfor == MNT_WAIT) {
	        while ((error = vnode_waitforwrites(vp, 0, slpflag, slptimeo, "nfsflush"))) {
		        error2 = nfs_sigintr(VFSTONFS(vnode_mount(vp)), NULL, p);
			if (error2) {
			        error = error2;
				goto done;
			}
			if (slpflag == PCATCH) {
				slpflag = 0;
				slptimeo = 2 * hz;
			}
		}
	}

	if (NFS_ISV3(vp)) {
		/* loop while it looks like there are still buffers to be */
		/* commited and nfs_flushcommits() seems to be handling them. */
		while (np->n_needcommitcnt)
			if (nfs_flushcommits(vp, p, 0))
				break;
	}

	if (passone) {
		passone = 0;
		goto again;
	}

	if ((waitfor == MNT_WAIT) && !LIST_EMPTY(&np->n_dirtyblkhd)) {
		goto again;
	}

	FSDBG(526, np->n_flag, np->n_error, 0, 0);
	if (!ignore_writeerr && (np->n_flag & NWRITEERR)) {
		error = np->n_error;
		np->n_flag &= ~NWRITEERR;
	}
done:
	FSDBG_BOT(517, vp, np, error, 0);
	return (error);
}

/*
 * Do an nfs pathconf rpc.
 */
int
nfs_pathconfrpc(
	vnode_t vp,
	struct nfsv3_pathconf *pc,
	kauth_cred_t cred,
	proc_t procp)
{
	mbuf_t mreq, mrep, md, mb, mb2;
	caddr_t bpos, dpos, cp, cp2;
	int32_t t1, t2;
	u_long *tl;
	u_int64_t xid;
	int attrflag, error = 0;
	struct nfsv3_pathconf *mpc;

	/* fetch pathconf info from server */
	nfsm_reqhead(NFSX_FH(1));
	if (error)
		return (error);
	nfsm_fhtom(vp, 1);
	nfsm_request(vp, NFSPROC_PATHCONF, procp, cred, &xid);
	nfsm_postop_attr_update(vp, 1, attrflag, &xid);
	if (!error) {
		nfsm_dissect(mpc, struct nfsv3_pathconf *, NFSX_V3PATHCONF);
		pc->pc_linkmax = fxdr_unsigned(long, mpc->pc_linkmax);
		pc->pc_namemax = fxdr_unsigned(long, mpc->pc_namemax);
		pc->pc_chownrestricted = fxdr_unsigned(long, mpc->pc_chownrestricted);
		pc->pc_notrunc = fxdr_unsigned(long, mpc->pc_notrunc);
		pc->pc_caseinsensitive = fxdr_unsigned(long, mpc->pc_caseinsensitive);
		pc->pc_casepreserving = fxdr_unsigned(long, mpc->pc_casepreserving);
	}
	nfsm_reqdone;

	return (error);
}

void
nfs_pathconf_cache(struct nfsmount *nmp, struct nfsv3_pathconf *pc)
{
	nmp->nm_state |= NFSSTA_GOTPATHCONF;
	nmp->nm_fsinfo.linkmax = pc->pc_linkmax;
	nmp->nm_fsinfo.namemax = pc->pc_namemax;
	nmp->nm_fsinfo.pcflags = 0;
	if (pc->pc_notrunc)
		nmp->nm_fsinfo.pcflags |= NFSPCINFO_NOTRUNC;
	if (pc->pc_chownrestricted)
		nmp->nm_fsinfo.pcflags |= NFSPCINFO_CHOWN_RESTRICTED;
	if (pc->pc_caseinsensitive)
		nmp->nm_fsinfo.pcflags |= NFSPCINFO_CASE_INSENSITIVE;
	if (pc->pc_casepreserving)
		nmp->nm_fsinfo.pcflags |= NFSPCINFO_CASE_PRESERVING;
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
	struct vnop_pathconf_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		int a_name;
		register_t *a_retval;
		vfs_context_t a_context;
	} */ *ap;
{
	vnode_t vp = ap->a_vp;
	struct nfsmount *nmp;
	struct nfsv3_pathconf pc;
	int error = 0, cached;

	nmp = VFSTONFS(vnode_mount(vp));
	if (!nmp)
		return (ENXIO);
	if (!NFS_ISV3(vp))
		return (EINVAL);

	switch (ap->a_name) {
	case _PC_LINK_MAX:
	case _PC_NAME_MAX:
	case _PC_CHOWN_RESTRICTED:
	case _PC_NO_TRUNC:
	case _PC_CASE_SENSITIVE:
	case _PC_CASE_PRESERVING:
		break;
	default:
		/* don't bother contacting the server if we know the answer */
		return (EINVAL);
	}

	if (!(nmp->nm_state & NFSSTA_GOTPATHCONF)) {
		/* no pathconf info cached */
		kauth_cred_t cred = vfs_context_ucred(ap->a_context);
		proc_t p = vfs_context_proc(ap->a_context);
		error = nfs_pathconfrpc(vp, &pc, cred, p);
		if (error)
			return (error);
		nmp = VFSTONFS(vnode_mount(vp));
		if (!nmp)
			return (ENXIO);
		if (!(nmp->nm_state & NFSSTA_GOTFSINFO)) {
			nfs_fsinfo(nmp, vp, cred, p);
			nmp = VFSTONFS(vnode_mount(vp));
			if (!nmp)
				return (ENXIO);
		}
		if ((nmp->nm_state & NFSSTA_GOTFSINFO) &&
		    (nmp->nm_fsinfo.fsproperties & NFSV3FSINFO_HOMOGENEOUS)) {
			/* all files have the same pathconf info, */
			/* so cache a copy of the results */
			nfs_pathconf_cache(nmp, &pc);
		}
	}

	cached = (nmp->nm_state & NFSSTA_GOTPATHCONF);

	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*ap->a_retval = cached ? nmp->nm_fsinfo.linkmax : pc.pc_linkmax;
		break;
	case _PC_NAME_MAX:
		*ap->a_retval = cached ? nmp->nm_fsinfo.namemax : pc.pc_namemax;
		break;
	case _PC_CHOWN_RESTRICTED:
		if (cached)
			*ap->a_retval = (nmp->nm_fsinfo.pcflags & NFSPCINFO_CHOWN_RESTRICTED) ? 1 : 0;
		else
			*ap->a_retval = pc.pc_chownrestricted;
		break;
	case _PC_NO_TRUNC:
		if (cached)
			*ap->a_retval = (nmp->nm_fsinfo.pcflags & NFSPCINFO_NOTRUNC) ? 1 : 0;
		else
			*ap->a_retval = pc.pc_notrunc;
		break;
	case _PC_CASE_SENSITIVE:
		if (cached)
			*ap->a_retval = (nmp->nm_fsinfo.pcflags & NFSPCINFO_CASE_INSENSITIVE) ? 0 : 1;
		else
			*ap->a_retval = !pc.pc_caseinsensitive;
		break;
	case _PC_CASE_PRESERVING:
		if (cached)
			*ap->a_retval = (nmp->nm_fsinfo.pcflags & NFSPCINFO_CASE_PRESERVING) ? 1 : 0;
		else
			*ap->a_retval = pc.pc_casepreserving;
		break;
	default:
		error = EINVAL;
	}

	return (error);
}

/*
 * NFS advisory byte-level locks (client)
 */
static int
nfs_advlock(ap)
	struct vnop_advlock_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		caddr_t a_id;
		int a_op;
		struct flock *a_fl;
		int a_flags;
		vfs_context_t a_context;
	} */ *ap;
{
	return (nfs_dolock(ap));
}

/*
 * write (or commit) the given NFS buffer
 */
int
nfs_buf_write(struct nfsbuf *bp)
{
	int oldflags = bp->nb_flags, rv = 0;
	vnode_t vp = bp->nb_vp;
	struct nfsnode *np = VTONFS(vp);
	kauth_cred_t cr;
	proc_t p = current_proc(); // XXX

	FSDBG_TOP(553, bp, NBOFF(bp), bp->nb_flags, 0);

	if (!ISSET(bp->nb_lflags, NBL_BUSY))
		panic("nfs_buf_write: buffer is not busy???");

	CLR(bp->nb_flags, (NB_READ|NB_DONE|NB_ERROR|NB_DELWRI));
	if (ISSET(oldflags, NB_DELWRI)) {
		OSAddAtomic(-1, (SInt32*)&nfs_nbdwrite);
		NFSBUFCNTCHK(0);
		wakeup(&nfs_nbdwrite);
	}

	/* move to clean list */
	if (ISSET(oldflags, (NB_ASYNC|NB_DELWRI))) {
		lck_mtx_lock(nfs_buf_mutex);
		if (bp->nb_vnbufs.le_next != NFSNOLIST)
			LIST_REMOVE(bp, nb_vnbufs);
		LIST_INSERT_HEAD(&VTONFS(vp)->n_cleanblkhd, bp, nb_vnbufs);
		lck_mtx_unlock(nfs_buf_mutex);
	}
	vnode_startwrite(vp);

	if (p && p->p_stats)
		p->p_stats->p_ru.ru_oublock++;

	/*
	 * For async requests when nfsiod(s) are running, queue the request by
	 * calling nfs_asyncio(), otherwise just all nfs_doio() to do the request.
	 */
	if (ISSET(bp->nb_flags, NB_ASYNC))
		p = NULL;
	if (ISSET(bp->nb_flags, NB_READ))
		cr = bp->nb_rcred;
	else
		cr = bp->nb_wcred;
	if (!ISSET(bp->nb_flags, NB_ASYNC) || nfs_asyncio(bp, NOCRED))
		rv = nfs_doio(bp, cr, p);

	if ((oldflags & NB_ASYNC) == 0) {
		rv = nfs_buf_iowait(bp);
		/* move to clean list */
		if (oldflags & NB_DELWRI) {
			lck_mtx_lock(nfs_buf_mutex);
			if (bp->nb_vnbufs.le_next != NFSNOLIST)
				LIST_REMOVE(bp, nb_vnbufs);
			LIST_INSERT_HEAD(&VTONFS(vp)->n_cleanblkhd, bp, nb_vnbufs);
			lck_mtx_unlock(nfs_buf_mutex);
		}
		oldflags = bp->nb_flags;
		FSDBG_BOT(553, bp, NBOFF(bp), bp->nb_flags, rv);
		if (cr) {
			kauth_cred_ref(cr);
		}
		nfs_buf_release(bp, 1);
		if (ISSET(oldflags, NB_ERROR) && !(np->n_flag & NFLUSHINPROG)) {
			/*
			 * There was a write error and we need to
			 * invalidate attrs and flush buffers in
			 * order to sync up with the server.
			 * (if this write was extending the file,
			 * we may no longer know the correct size)
			 *
			 * But we couldn't call vinvalbuf while holding
			 * the buffer busy.  So we call vinvalbuf() after
			 * releasing the buffer.
			 */
			nfs_vinvalbuf(vp, V_SAVE|V_IGNORE_WRITEERR, cr, p, 1);
		}
		if (cr)
			kauth_cred_rele(cr);
		return (rv);
	} 

	FSDBG_BOT(553, bp, NBOFF(bp), bp->nb_flags, rv);
	return (rv);
}

/*
 * Read wrapper for special devices.
 */
static int
nfsspec_read(ap)
	struct vnop_read_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		struct uio *a_uio;
		int a_ioflag;
		vfs_context_t a_context;
	} */ *ap;
{
	register struct nfsnode *np = VTONFS(ap->a_vp);
	struct timeval now;

	/*
	 * Set access flag.
	 */
	np->n_flag |= NACC;
	microtime(&now);
	np->n_atim.tv_sec = now.tv_sec;
	np->n_atim.tv_nsec = now.tv_usec * 1000;
	return (VOCALL(spec_vnodeop_p, VOFFSET(vnop_read), ap));
}

/*
 * Write wrapper for special devices.
 */
static int
nfsspec_write(ap)
	struct vnop_write_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		struct uio *a_uio;
		int a_ioflag;
		vfs_context_t a_context;
	} */ *ap;
{
	register struct nfsnode *np = VTONFS(ap->a_vp);
	struct timeval now;

	/*
	 * Set update flag.
	 */
	np->n_flag |= NUPD;
	microtime(&now);
	np->n_mtim.tv_sec = now.tv_sec;
	np->n_mtim.tv_nsec = now.tv_usec * 1000;
	return (VOCALL(spec_vnodeop_p, VOFFSET(vnop_write), ap));
}

/*
 * Close wrapper for special devices.
 *
 * Update the times on the nfsnode then do device close.
 */
static int
nfsspec_close(ap)
	struct vnop_close_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		int a_fflag;
		vfs_context_t a_context;
	} */ *ap;
{
	vnode_t vp = ap->a_vp;
	struct nfsnode *np = VTONFS(vp);
	struct vnode_attr vattr;
	mount_t mp;

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
			vnode_setattr(vp, &vattr, ap->a_context);
		}
	}
	return (VOCALL(spec_vnodeop_p, VOFFSET(vnop_close), ap));
}

extern vnop_t **fifo_vnodeop_p;

/*
 * Read wrapper for fifos.
 */
static int
nfsfifo_read(ap)
	struct vnop_read_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		struct uio *a_uio;
		int a_ioflag;
		vfs_context_t a_context;
	} */ *ap;
{
	register struct nfsnode *np = VTONFS(ap->a_vp);
	struct timeval now;

	/*
	 * Set access flag.
	 */
	np->n_flag |= NACC;
	microtime(&now);
	np->n_atim.tv_sec = now.tv_sec;
	np->n_atim.tv_nsec = now.tv_usec * 1000;
	return (VOCALL(fifo_vnodeop_p, VOFFSET(vnop_read), ap));
}

/*
 * Write wrapper for fifos.
 */
static int
nfsfifo_write(ap)
	struct vnop_write_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		struct uio *a_uio;
		int a_ioflag;
		vfs_context_t a_context;
	} */ *ap;
{
	register struct nfsnode *np = VTONFS(ap->a_vp);
	struct timeval now;

	/*
	 * Set update flag.
	 */
	np->n_flag |= NUPD;
	microtime(&now);
	np->n_mtim.tv_sec = now.tv_sec;
	np->n_mtim.tv_nsec = now.tv_usec * 1000;
	return (VOCALL(fifo_vnodeop_p, VOFFSET(vnop_write), ap));
}

/*
 * Close wrapper for fifos.
 *
 * Update the times on the nfsnode then do fifo close.
 */
static int
nfsfifo_close(ap)
	struct vnop_close_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		int a_fflag;
		vfs_context_t a_context;
	} */ *ap;
{
	vnode_t vp = ap->a_vp;
	struct nfsnode *np = VTONFS(vp);
	struct vnode_attr vattr;
	struct timeval now;
	mount_t mp;

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
			vnode_setattr(vp, &vattr, ap->a_context);
		}
	}
	return (VOCALL(fifo_vnodeop_p, VOFFSET(vnop_close), ap));
}

/*ARGSUSED*/
static int
nfs_ioctl(
	__unused struct vnop_ioctl_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		u_long a_command;
		caddr_t a_data;
		int a_fflag;
		kauth_cred_t a_cred;
		proc_t a_p;
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
nfs_select(
	__unused struct vnop_select_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		int a_which;
		int a_fflags;
		kauth_cred_t a_cred;
		void *a_wql;
		proc_t a_p;
	} */ *ap)
{

	/*
	 * We were once bogusly seltrue() which returns 1.  Is this right?
	 */
	return (1);
}

/*
 * Vnode op for pagein using getblk_pages
 * derived from nfs_bioread()
 * No read aheads are started from pagein operation
 */
static int
nfs_pagein(ap)
	struct vnop_pagein_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		upl_t a_pl;
		vm_offset_t a_pl_offset;
		off_t a_f_offset;
		size_t a_size;
		int a_flags;
		vfs_context_t a_context;
	} */ *ap;
{
	vnode_t vp = ap->a_vp;
	upl_t pl = ap->a_pl;
	size_t size= ap->a_size;
	off_t f_offset = ap->a_f_offset;
	vm_offset_t pl_offset = ap->a_pl_offset;
	int flags  = ap->a_flags;
	kauth_cred_t cred;
	proc_t p;
	struct nfsnode *np = VTONFS(vp);
	int biosize, xsize, iosize;
	struct nfsmount *nmp;
	int error = 0;
	vm_offset_t ioaddr;
	struct uio	auio;
	struct iovec_32	aiov;
	struct uio * uio = &auio;
	int nofreeupl = flags & UPL_NOCOMMIT;
	upl_page_info_t *plinfo;

	FSDBG(322, vp, f_offset, size, flags);
	if (pl == (upl_t)NULL)
		panic("nfs_pagein: no upl");

	if (UBCINVALID(vp)) {
		printf("nfs_pagein: invalid vnode 0x%x", (int)vp);
		if (!nofreeupl)
			(void) ubc_upl_abort(pl, 0); 
		return (EPERM);
	}
	UBCINFOCHECK("nfs_pagein", vp);

	if (size <= 0) {
		printf("nfs_pagein: invalid size %d", size);
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

	cred = ubc_getcred(vp);
	if (cred == NOCRED)
		cred = vfs_context_ucred(ap->a_context);
	p = vfs_context_proc(ap->a_context);

	auio.uio_offset = f_offset;
#if 1   /* LP64todo - can't use new segment flags until the drivers are ready */
	auio.uio_segflg = UIO_SYSSPACE;
#else
	auio.uio_segflg = UIO_SYSSPACE32;
#endif 
	auio.uio_rw = UIO_READ;
	auio.uio_procp = p;

	nmp = VFSTONFS(vnode_mount(vp));
	if (!nmp) {
		if (!nofreeupl)
			ubc_upl_abort_range(pl, pl_offset, size, 
				UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
		return (ENXIO);
	}
	if ((nmp->nm_flag & NFSMNT_NFSV3) && !(nmp->nm_state & NFSSTA_GOTFSINFO))
		(void)nfs_fsinfo(nmp, vp, cred, p);
	biosize = vfs_statfs(vnode_mount(vp))->f_iosize;

	plinfo = ubc_upl_pageinfo(pl);
	ubc_upl_map(pl, &ioaddr);
	ioaddr += pl_offset;
	xsize = size;

	do {
		/*
		 * It would be nice to be able to issue all these requests
		 * in parallel instead of waiting for each one to complete
		 * before sending the next one.
		 * XXX Should we align these requests to block boundaries?
		 */
		iosize = min(biosize, xsize);
		aiov.iov_len  = iosize;
		aiov.iov_base = (uintptr_t)ioaddr;
		auio.uio_iovs.iov32p = &aiov;
		auio.uio_iovcnt = 1;
		uio_uio_resid_set(&auio, iosize);

		FSDBG(322, uio->uio_offset, uio_uio_resid(uio), ioaddr, xsize);
		/*
		 * With UBC we get here only when the file data is not in the VM
		 * page cache, so go ahead and read in.
		 */
#ifdef UPL_DEBUG
		upl_ubc_alias_set(pl, current_thread(), 2);
#endif /* UPL_DEBUG */
		OSAddAtomic(1, (SInt32*)&nfsstats.pageins);

		error = nfs_readrpc(vp, uio, cred, p);

		if (!error) {
			if (uio_uio_resid(uio)) {
				/*
				 * If uio_resid > 0, there is a hole in the file
				 * and no writes after the hole have been pushed
				 * to the server yet... or we're at the EOF
				 * Just zero fill the rest of the valid area.
				 */
				// LP64todo - fix this
				int zcnt = uio_uio_resid(uio);
				int zoff = iosize - zcnt;
				bzero((char *)ioaddr + zoff, zcnt);

				FSDBG(324, uio->uio_offset, zoff, zcnt, ioaddr);
				uio->uio_offset += zcnt;
			}
			ioaddr += iosize;	
			xsize  -= iosize;
		} else {
			FSDBG(322, uio->uio_offset, uio_uio_resid(uio), error, -1);
		}

		nmp = VFSTONFS(vnode_mount(vp));
	} while (error == 0 && xsize > 0);

	ubc_upl_unmap(pl);

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
 * Vnode op for pageout using UPL
 * Derived from nfs_write()
 * File size changes are not permitted in pageout.
 */
static int
nfs_pageout(ap)
	struct vnop_pageout_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		upl_t a_pl;
		vm_offset_t a_pl_offset;
		off_t a_f_offset;
		size_t a_size;
		int a_flags;
		vfs_context_t a_context;
	} */ *ap;
{
	vnode_t vp = ap->a_vp;
	upl_t pl = ap->a_pl;
	size_t size= ap->a_size;
	off_t f_offset = ap->a_f_offset;
	vm_offset_t pl_offset = ap->a_pl_offset;
	int flags  = ap->a_flags;
	struct nfsnode *np = VTONFS(vp);
	kauth_cred_t cred;
	proc_t p;
	struct nfsbuf *bp;
	struct nfsmount *nmp = VFSTONFS(vnode_mount(vp));
	daddr64_t lbn;
	int error = 0, iomode, must_commit;
	off_t off;
	vm_offset_t ioaddr;
	struct uio	auio;
	struct iovec_32	aiov;
	int nofreeupl = flags & UPL_NOCOMMIT;
	size_t biosize, iosize, pgsize, xsize;

	FSDBG(323, f_offset, size, pl, pl_offset);

	if (pl == (upl_t)NULL)
		panic("nfs_pageout: no upl");

	if (UBCINVALID(vp)) {
		printf("nfs_pageout: invalid vnode 0x%x", (int)vp);
		if (!nofreeupl)
			ubc_upl_abort(pl, 0); 
		return (EIO);
	}
	UBCINFOCHECK("nfs_pageout", vp);

	if (size <= 0) {
		printf("nfs_pageout: invalid size %d", size);
		if (!nofreeupl)
			ubc_upl_abort(pl, 0); 
		return (EINVAL);
	}

	if (!nmp) {
		if (!nofreeupl)
			ubc_upl_abort(pl, UPL_ABORT_DUMP_PAGES|UPL_ABORT_FREE_ON_EMPTY);
		return (ENXIO);
	}
	biosize = vfs_statfs(vnode_mount(vp))->f_iosize;

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
		lbn = ubc_offtoblk(vp, off);
		lck_mtx_lock(nfs_buf_mutex);
		if ((bp = nfs_buf_incore(vp, lbn))) {
			FSDBG(323, off, bp, bp->nb_lflags, bp->nb_flags);
			if (nfs_buf_acquire(bp, NBAC_NOWAIT, 0, 0)) {
				lck_mtx_unlock(nfs_buf_mutex);
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
				    FSDBG(323, vp, bp, 0xd00deebc, EBUSY);
				    nfs_buf_drop(bp);
				    lck_mtx_unlock(nfs_buf_mutex);
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
			if (ISSET(bp->nb_flags, NB_NEEDCOMMIT)) {
				CLR(bp->nb_flags, NB_NEEDCOMMIT);
				np->n_needcommitcnt--;
				CHECK_NEEDCOMMITCNT(np);
			}
			nfs_buf_release(bp, 1);
		} else {
			lck_mtx_unlock(nfs_buf_mutex);
		}
	}

	cred = ubc_getcred(vp);
	if (cred == NOCRED)
		cred = vfs_context_ucred(ap->a_context);
	p = vfs_context_proc(ap->a_context);

	if (np->n_flag & NWRITEERR) {
		np->n_flag &= ~NWRITEERR;
		if (!nofreeupl)
			ubc_upl_abort_range(pl, pl_offset, size,
					    UPL_ABORT_FREE_ON_EMPTY);
		return (np->n_error);
	}
	if ((nmp->nm_flag & NFSMNT_NFSV3) && !(nmp->nm_state & NFSSTA_GOTFSINFO))
		nfs_fsinfo(nmp, vp, cred, p);

	if (f_offset < 0 || f_offset >= (off_t)np->n_size ||
	    f_offset & PAGE_MASK_64 || size & PAGE_MASK_64) {
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
	if (size > pgsize) {
		if (!nofreeupl)
			ubc_upl_abort_range(pl, pl_offset + pgsize,
					    size - pgsize,
					    UPL_ABORT_FREE_ON_EMPTY);
	}

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

	auio.uio_offset = f_offset;
#if 1   /* LP64todo - can't use new segment flags until the drivers are ready */
	auio.uio_segflg = UIO_SYSSPACE;
#else
	auio.uio_segflg = UIO_SYSSPACE32;
#endif 
	auio.uio_rw = UIO_READ;
	auio.uio_procp = p;

	do {
		/*
		 * It would be nice to be able to issue all these requests
		 * in parallel instead of waiting for each one to complete
		 * before sending the next one.
		 * XXX Should we align these requests to block boundaries?
		 */
		iosize = min(biosize, xsize);
		uio_uio_resid_set(&auio, iosize);
		aiov.iov_len = iosize;
		aiov.iov_base = (uintptr_t)ioaddr;
		auio.uio_iovs.iov32p = &aiov;
		auio.uio_iovcnt = 1;

		FSDBG(323, auio.uio_offset, uio_uio_resid(&auio), ioaddr, xsize);
		OSAddAtomic(1, (SInt32*)&nfsstats.pageouts);

		vnode_startwrite(vp);

		/* NMODIFIED would be set here if doing unstable writes */
		iomode = NFSV3WRITE_FILESYNC;
		error = nfs_writerpc(vp, &auio, cred, p, &iomode, &must_commit);
		if (must_commit)
			nfs_clearcommit(vnode_mount(vp));
		vnode_writedone(vp);
		if (error)
			goto cleanup;
		/* Note: no need to check uio_resid, because */
		/* it'll only be set if there was an error. */
		ioaddr += iosize;
		xsize -= iosize;
	} while (xsize > 0);

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
			short action = nfs_pageouterrorhandler(error);
			
			switch (action) {
				case DUMP:
					abortflags = UPL_ABORT_DUMP_PAGES|UPL_ABORT_FREE_ON_EMPTY;
					break;
				case DUMPANDLOG:
					abortflags = UPL_ABORT_DUMP_PAGES|UPL_ABORT_FREE_ON_EMPTY;
					if (error <= ELAST &&
					    (errorcount[error] % 100 == 0)) 
						printf("nfs_pageout: unexpected error %d. dumping vm page\n", error);
					errorcount[error]++;
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
				
			ubc_upl_abort_range(pl, pl_offset, size, abortflags);
			/* return error in all cases above */
			
		} else 
			ubc_upl_commit_range(pl, pl_offset, pgsize,
					     UPL_COMMIT_CLEAR_DIRTY |
					     UPL_COMMIT_FREE_ON_EMPTY);
	}
	return (error);
}

/* Blktooff derives file offset given a logical block number */
static int
nfs_blktooff(ap)
	struct vnop_blktooff_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		daddr64_t a_lblkno;
		off_t *a_offset;
	} */ *ap;
{
	int biosize;
	vnode_t vp = ap->a_vp;
	mount_t mp = vnode_mount(vp);

	if (!mp)
		return (ENXIO);

	biosize = vfs_statfs(mp)->f_iosize;

	*ap->a_offset = (off_t)(ap->a_lblkno * biosize);

	return (0);
}

static int
nfs_offtoblk(ap)
	struct vnop_offtoblk_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		off_t a_offset;
		daddr64_t *a_lblkno;
	} */ *ap;
{
	int biosize;
	vnode_t vp = ap->a_vp;
	mount_t mp = vnode_mount(vp);

	if (!mp)
		return (ENXIO);

	biosize = vfs_statfs(mp)->f_iosize;

	*ap->a_lblkno = (daddr64_t)(ap->a_offset / biosize);

	return (0);
}

