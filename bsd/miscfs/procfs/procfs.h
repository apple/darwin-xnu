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
/*	$NetBSD: procfs.h,v 1.13 1995/03/29 22:08:30 briggs Exp $	*/

/*
 * Copyright (c) 1993 Jan-Simon Pendry
 * Copyright (c) 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Jan-Simon Pendry.
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
 *	@(#)procfs.h	8.7 (Berkeley) 6/15/94
 */

/*
 * The different types of node in a procfs filesystem
 */
typedef enum {
	Proot,		/* the filesystem root */
	Pcurproc,	/* symbolic link for curproc */
	Pproc,		/* a process-specific sub-directory */
	Pfile,		/* the executable file */
	Pmem,		/* the process's memory image */
	Pregs,		/* the process's register set */
	Pfpregs,	/* the process's FP register set */
	Pctl,		/* process control */
	Pstatus,	/* process status */
	Pnote,		/* process notifier */
	Pnotepg		/* process group notifier */
} pfstype;

/*
 * control data for the proc file system.
 */
struct pfsnode {
	struct pfsnode	*pfs_next;	/* next on list */
	struct vnode	*pfs_vnode;	/* vnode associated with this pfsnode */
	pfstype		pfs_type;	/* type of procfs node */
	pid_t		pfs_pid;	/* associated process */
	u_short		pfs_mode;	/* mode bits for stat() */
	u_long		pfs_flags;	/* open flags */
	u_long		pfs_fileno;	/* unique file id */
};

#define PROCFS_NOTELEN	64	/* max length of a note (/proc/$pid/note) */
#define PROCFS_CTLLEN 	8	/* max length of a ctl msg (/proc/$pid/ctl */

/*
 * Kernel stuff follows
 */
#ifdef KERNEL
#define CNEQ(cnp, s, len) \
	 ((cnp)->cn_namelen == (len) && \
	  (bcmp((s), (cnp)->cn_nameptr, (len)) == 0))

/*
 * Format of a directory entry in /proc, ...
 * This must map onto struct dirent (see <dirent.h>)
 */
#define PROCFS_NAMELEN 8
struct pfsdent {
	u_int32_t	d_fileno;
	u_int16_t	d_reclen;
	u_int8_t	d_type;
	u_int8_t	d_namlen;
	char		d_name[PROCFS_NAMELEN];
};
#define UIO_MX sizeof(struct pfsdent)
#define PROCFS_FILENO(pid, type) \
	(((type) < Pproc) ? \
			((type) + 2) : \
			((((pid)+1) << 4) + ((int) (type))))

/*
 * Convert between pfsnode vnode
 */
#define VTOPFS(vp)	((struct pfsnode *)(vp)->v_data)
#define PFSTOV(pfs)	((pfs)->pfs_vnode)

typedef struct vfs_namemap vfs_namemap_t;
struct vfs_namemap {
	const char *nm_name;
	int nm_val;
};

int vfs_getuserstr __P((struct uio *, char *, int *));
vfs_namemap_t *vfs_findname __P((vfs_namemap_t *, char *, int));

#define PFIND(pid) ((pid) ? pfind(pid) : &kernel_proc)
int procfs_freevp __P((struct vnode *));
int procfs_allocvp __P((struct mount *, struct vnode **, long, pfstype));
struct vnode *procfs_findtextvp __P((struct proc *));
int procfs_donote __P((struct proc *, struct proc *, struct pfsnode *pfsp, struct uio *uio));
int procfs_doregs __P((struct proc *, struct proc *, struct pfsnode *pfsp, struct uio *uio));
int procfs_dofpregs __P((struct proc *, struct proc *, struct pfsnode *pfsp, struct uio *uio));
int procfs_domem __P((struct proc *, struct proc *, struct pfsnode *pfsp, struct uio *uio));
int procfs_doctl __P((struct proc *, struct proc *, struct pfsnode *pfsp, struct uio *uio));
int procfs_dostatus __P((struct proc *, struct proc *, struct pfsnode *pfsp, struct uio *uio));

/* functions to check whether or not files should be displayed */
int procfs_validfile __P((struct proc *));
int procfs_validfpregs __P((struct proc *));
int procfs_validregs __P((struct proc *));

#define PROCFS_LOCKED	0x01
#define PROCFS_WANT	0x02

extern int (**procfs_vnodeop_p)(void *);
extern struct vfsops procfs_vfsops;

/*
 * Prototypes for procfs vnode ops
 */
int	procfs_badop();	/* varargs */
int	procfs_rw __P((struct vop_read_args *));
int	procfs_lookup __P((struct vop_lookup_args *));
#define procfs_create ((int (*) __P((struct vop_create_args *))) procfs_badop)
#define procfs_mknod ((int (*) __P((struct vop_mknod_args *))) procfs_badop)
int	procfs_open __P((struct vop_open_args *));
int	procfs_close __P((struct vop_close_args *));
int	procfs_access __P((struct vop_access_args *));
int	procfs_getattr __P((struct vop_getattr_args *));
int	procfs_setattr __P((struct vop_setattr_args *));
#define	procfs_read procfs_rw
#define	procfs_write procfs_rw
int	procfs_ioctl __P((struct vop_ioctl_args *));
#define procfs_select ((int (*) __P((struct vop_select_args *))) procfs_badop)
#define procfs_mmap ((int (*) __P((struct vop_mmap_args *))) procfs_badop)
#define procfs_fsync ((int (*) __P((struct vop_fsync_args *))) procfs_badop)
#define procfs_seek ((int (*) __P((struct vop_seek_args *))) procfs_badop)
#define procfs_remove ((int (*) __P((struct vop_remove_args *))) procfs_badop)
#define procfs_link ((int (*) __P((struct vop_link_args *))) procfs_badop)
#define procfs_rename ((int (*) __P((struct vop_rename_args *))) procfs_badop)
#define procfs_mkdir ((int (*) __P((struct vop_mkdir_args *))) procfs_badop)
#define procfs_rmdir ((int (*) __P((struct vop_rmdir_args *))) procfs_badop)
#define procfs_symlink ((int (*) __P((struct vop_symlink_args *))) procfs_badop)
int	procfs_readdir __P((struct vop_readdir_args *));
int	procfs_readlink __P((struct vop_readlink_args *));
int	procfs_abortop __P((struct vop_abortop_args *));
int	procfs_inactive __P((struct vop_inactive_args *));
int	procfs_reclaim __P((struct vop_reclaim_args *));
#define procfs_lock ((int (*) __P((struct vop_lock_args *))) nullop)
#define procfs_unlock ((int (*) __P((struct vop_unlock_args *))) nullop)
int	procfs_bmap __P((struct vop_bmap_args *));
#define	procfs_strategy ((int (*) __P((struct vop_strategy_args *))) procfs_badop)
int	procfs_print __P((struct vop_print_args *));
#define procfs_islocked ((int (*) __P((struct vop_islocked_args *))) nullop)
#define procfs_advlock ((int (*) __P((struct vop_advlock_args *))) procfs_badop)
#define procfs_blkatoff ((int (*) __P((struct vop_blkatoff_args *))) procfs_badop)
#define procfs_valloc ((int (*) __P((struct vop_valloc_args *))) procfs_badop)
#define procfs_vfree ((int (*) __P((struct vop_vfree_args *))) nullop)
#define procfs_truncate ((int (*) __P((struct vop_truncate_args *))) procfs_badop)
#define procfs_update ((int (*) __P((struct vop_update_args *))) nullop)
#endif /* KERNEL */
