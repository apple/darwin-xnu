/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*-
 * Copyright (c) 1991, 1993, 1994
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
 *	@(#)ufs_extern.h	8.10 (Berkeley) 5/14/95
 */
#ifndef _UFS_EXTERN_H_
#define _UFS_EXTERN_H_

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE
struct buf;
struct direct;
struct disklabel;
struct fid;
struct flock;
struct inode;
struct mbuf;
struct mount;
struct nameidata;
struct proc;
struct ucred;
struct ufs_args;
struct uio;
struct vattr;
struct vfsconf;
struct vnode;

__BEGIN_DECLS
void	 diskerr
	    __P((struct buf *, char *, char *, int, int, struct disklabel *));
void	 disksort __P((struct buf *, struct buf *));
u_int	 dkcksum __P((struct disklabel *));
char	*readdisklabel __P((dev_t, int (*)(), struct disklabel *));
int	 setdisklabel __P((struct disklabel *, struct disklabel *, u_long));
int	 writedisklabel __P((dev_t, int (*)(), struct disklabel *));

int	 ufs_access __P((struct vop_access_args *));
int	 ufs_advlock __P((struct vop_advlock_args *));
int	 ufs_bmap __P((struct vop_bmap_args *));
int	 ufs_check_export __P((struct mount *, struct ufid *, struct mbuf *,
		struct vnode **, int *exflagsp, struct ucred **));
int	 ufs_checkpath __P((struct inode *, struct inode *, struct ucred *));
int	 ufs_close __P((struct vop_close_args *));
int	 ufs_create __P((struct vop_create_args *));
void	 ufs_dirbad __P((struct inode *, doff_t, char *));
int	 ufs_dirbadentry __P((struct vnode *, struct direct *, int));
int	 ufs_dirempty __P((struct inode *, ino_t, struct ucred *));
int	 ufs_direnter __P((struct inode *, struct vnode *,struct componentname *));
int	 ufs_dirremove __P((struct vnode *, struct componentname*));
int	 ufs_dirrewrite
	    __P((struct inode *, struct inode *, struct componentname *));
int	 ufs_getattr __P((struct vop_getattr_args *));
int	 ufs_getattrlist __P((struct vop_getattrlist_args *));
int	 ufs_getlbns __P((struct vnode *, ufs_daddr_t, struct indir *, int *));
struct vnode *
	 ufs_ihashget __P((dev_t, ino_t));
void	 ufs_ihashinit __P((void));
void	 ufs_ihashins __P((struct inode *));
struct vnode *
	 ufs_ihashlookup __P((dev_t, ino_t));
void	 ufs_ihashrem __P((struct inode *));
int	 ufs_inactive __P((struct vop_inactive_args *));
int	 ufs_init __P((struct vfsconf *));
int	 ufs_ioctl __P((struct vop_ioctl_args *));
int	 ufs_islocked __P((struct vop_islocked_args *));
#if NFSSERVER
int	 lease_check __P((struct vop_lease_args *));
#define	 ufs_lease_check lease_check
#else
#define	 ufs_lease_check ((int (*) __P((struct vop_lease_args *)))nullop)
#endif
int	 ufs_link __P((struct vop_link_args *));
int	 ufs_lock __P((struct vop_lock_args *));
int	 ufs_lookup __P((struct vop_lookup_args *));
int	 ufs_makeinode __P((int mode, struct vnode *, struct vnode **, struct componentname *));
int	 ufs_mkdir __P((struct vop_mkdir_args *));
int	 ufs_mknod __P((struct vop_mknod_args *));
int	 ufs_mmap __P((struct vop_mmap_args *));
int	 ufs_open __P((struct vop_open_args *));
int	 ufs_pathconf __P((struct vop_pathconf_args *));
int	 ufs_print __P((struct vop_print_args *));
int	 ufs_readdir __P((struct vop_readdir_args *));
int	 ufs_readlink __P((struct vop_readlink_args *));
int	 ufs_reclaim __P((struct vnode *, struct proc *));
int	 ufs_remove __P((struct vop_remove_args *));
int	 ufs_rename __P((struct vop_rename_args *));
#define	 ufs_revoke vop_revoke
int	 ufs_rmdir __P((struct vop_rmdir_args *));
int	 ufs_root __P((struct mount *, struct vnode **));
int	 ufs_seek __P((struct vop_seek_args *));
int	 ufs_select __P((struct vop_select_args *));
int	 ufs_kqfilt_add __P((struct vop_kqfilt_add_args *));
int	 ufs_setattr __P((struct vop_setattr_args *));
int	 ufs_setattrlist __P((struct vop_setattrlist_args *));
int	 ufs_start __P((struct mount *, int, struct proc *));
int	 ufs_strategy __P((struct vop_strategy_args *));
int	 ufs_symlink __P((struct vop_symlink_args *));
int	 ufs_unlock __P((struct vop_unlock_args *));
int	 ufs_whiteout __P((struct vop_whiteout_args *));
int	 ufs_vinit __P((struct mount *,
	    int (**)(), int (**)(), struct vnode **));
int	 ufsspec_close __P((struct vop_close_args *));
int	 ufsspec_read __P((struct vop_read_args *));
int	 ufsspec_write __P((struct vop_write_args *));

#if FIFO
int	ufsfifo_read __P((struct vop_read_args *));
int	ufsfifo_write __P((struct vop_write_args *));
int	ufsfifo_close __P((struct vop_close_args *));
int ufsfifo_kqfilt_add __P((struct vop_kqfilt_add_args *));
#endif
int	 ufs_blktooff __P((struct vop_blktooff_args *));
int	 ufs_cmap __P((struct vop_cmap_args *));

__END_DECLS

#endif /* __APPLE_API_PRIVATE */
#endif /* ! _UFS_EXTERN_H_ */
