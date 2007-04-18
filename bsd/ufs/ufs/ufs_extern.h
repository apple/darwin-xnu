/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
struct flock;
struct inode;
struct mbuf;
struct mount;
struct nameidata;
struct proc;
struct ucred;
struct ufs_args;
struct uio;
struct vnode_attr;
struct vfsconf;
struct vnode;

__BEGIN_DECLS
int	ufs_remove_internal(vnode_t, vnode_t, struct componentname *, int);
int	ufs_access_internal(vnode_t, mode_t, ucred_t);

int	ffs_read_internal(vnode_t, struct uio *, int);
int	ffs_write_internal(vnode_t, struct uio *, int, ucred_t);
int	ffs_truncate_internal(vnode_t, off_t, int, ucred_t);

void	 diskerr
	   (struct buf *, char *, char *, int, int, struct disklabel *);
void	 disksort(struct buf *, struct buf *);
u_int	 dkcksum(struct disklabel *);
char	*readdisklabel(dev_t, int (*)(), struct disklabel *);
int	 setdisklabel(struct disklabel *, struct disklabel *, u_long);
int	 writedisklabel(dev_t, int (*)(), struct disklabel *);

int	 ufs_access(struct vnop_access_args *);
int	 ufs_checkpath(struct inode *, struct inode *, struct ucred *);
int	 ufs_close(struct vnop_close_args *);
int	 ufs_create(struct vnop_create_args *);
void	 ufs_dirbad(struct inode *, doff_t, const char *);
int	 ufs_dirbadentry(struct vnode *, struct direct *, int);
int	 ufs_dirempty(struct inode *, ino_t, struct ucred *);
int	 ufs_direnter(struct inode *, struct vnode *,struct componentname *);
int	 ufs_dirremove(struct vnode *, struct componentname*);
int	 ufs_dirrewrite
	   (struct inode *, struct inode *, struct componentname *);
int	 ufs_getattr(struct vnop_getattr_args *);
int	 ufs_getlbns(struct vnode *, ufs_daddr_t, struct indir *, int *);
struct vnode *
	 ufs_ihashget(dev_t, ino_t);
void	 ufs_ihashinit(void);
void	 ufs_ihashins(struct inode *);
struct vnode *
	 ufs_ihashlookup(dev_t, ino_t);
void	 ufs_ihashrem(struct inode *);
int	 ufs_inactive(struct vnop_inactive_args *);
int	 ufs_init(struct vfsconf *);
int	 ufs_ioctl(struct vnop_ioctl_args *);
int	 ufs_link(struct vnop_link_args *);
int	 ufs_lookup(struct vnop_lookup_args *);
int	 ufs_makeinode(struct vnode_attr *, struct vnode *, struct vnode **, struct componentname *);
int	 ufs_mkdir(struct vnop_mkdir_args *);
int	 ufs_mknod(struct vnop_mknod_args *);
int	 ufs_mmap(struct vnop_mmap_args *);
int	 ufs_open(struct vnop_open_args *);
int	 ufs_pathconf(struct vnop_pathconf_args *);
int	 ufs_readdir(struct vnop_readdir_args *);
int	 ufs_readlink(struct vnop_readlink_args *);
int	 ufs_reclaim(struct vnode *, struct proc *);
int	 ufs_remove(struct vnop_remove_args *);
int	 ufs_rename(struct vnop_rename_args *);
#define	 ufs_revoke nop_revoke
int	 ufs_rmdir(struct vnop_rmdir_args *);
int	 ufs_root(struct mount *, struct vnode **, vfs_context_t);
int	 ufs_select(struct vnop_select_args *);
int	 ufs_kqfilt_add(struct vnop_kqfilt_add_args *);
int	 ufs_setattr(struct vnop_setattr_args *);
int	 ufs_start(struct mount *, int, vfs_context_t);
int	 ufs_strategy(struct vnop_strategy_args *);
int	 ufs_symlink(struct vnop_symlink_args *);
int	 ufs_whiteout(struct vnop_whiteout_args *);
int	 ufsspec_close(struct vnop_close_args *);
int	 ufsspec_read(struct vnop_read_args *);
int	 ufsspec_write(struct vnop_write_args *);

#if FIFO
int	ufsfifo_read(struct vnop_read_args *);
int	ufsfifo_write(struct vnop_write_args *);
int	ufsfifo_close(struct vnop_close_args *);
int	ufsfifo_kqfilt_add(struct vnop_kqfilt_add_args *);
#endif
int	 ufs_blktooff(struct vnop_blktooff_args *);
int	 ufs_blockmap(struct vnop_blockmap_args *);

__END_DECLS

#endif /* __APPLE_API_PRIVATE */
#endif /* ! _UFS_EXTERN_H_ */
