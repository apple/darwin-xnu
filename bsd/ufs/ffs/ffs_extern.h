/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
 *	@(#)ffs_extern.h	8.6 (Berkeley) 3/30/95
 */
#ifndef __UFS_FFS_FFS_EXTERN_H__
#define __UFS_FFS_FFS_EXTERN_H__

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_UNSTABLE
/*
 * Sysctl values for the fast filesystem.
 */
#define FFS_CLUSTERREAD		1	/* cluster reading enabled */
#define FFS_CLUSTERWRITE	2	/* cluster writing enabled */
#define FFS_REALLOCBLKS		3	/* block reallocation enabled */
#define FFS_ASYNCFREE		4	/* asynchronous block freeing enabled */
#define	FFS_MAXID		5	/* number of valid ffs ids */

#define FFS_NAMES { \
	{ 0, 0 }, \
	{ "doclusterread", CTLTYPE_INT }, \
	{ "doclusterwrite", CTLTYPE_INT }, \
	{ "doreallocblks", CTLTYPE_INT }, \
	{ "doasyncfree", CTLTYPE_INT }, \
}
#endif /* __APPLE_API_UNSTABLE */

struct buf;
struct fs;
struct inode;
struct mount;
struct nameidata;
struct proc;
struct vfsstatfs;
struct timeval;
struct ucred;
struct uio;
struct vnode;
struct mbuf;
struct vfsconf;

#ifdef __APPLE_API_PRIVATE
__BEGIN_DECLS
int	ffs_fsync_internal(vnode_t, int);

int	ffs_blkatoff(vnode_t, off_t, char **, buf_t *);

int	ffs_alloc(struct inode *,
	    ufs_daddr_t, ufs_daddr_t, int, struct ucred *, ufs_daddr_t *);
int	ffs_balloc(struct inode *,
	    ufs_daddr_t, int, struct ucred *, struct buf **, int, int *);
void	ffs_blkfree(struct inode *, ufs_daddr_t, long);
ufs_daddr_t ffs_blkpref(struct inode *, ufs_daddr_t, int, ufs_daddr_t *);
void	ffs_clrblock(struct fs *, u_char *, ufs_daddr_t);
int	ffs_fhtovp(struct mount *, int, unsigned char *, struct vnode **, vfs_context_t);
void	ffs_fragacct(struct fs *, int, int32_t [], int);
int	ffs_fsync(struct vnop_fsync_args *);
int	ffs_init(struct vfsconf *);
int	ffs_isblock(struct fs *, u_char *, ufs_daddr_t);
int	ffs_mount(struct mount *, vnode_t , user_addr_t, vfs_context_t);
int	ffs_mountfs(struct vnode *, struct mount *, vfs_context_t);
int	ffs_mountroot(mount_t, vnode_t, vfs_context_t);
int	ffs_read(struct vnop_read_args *);
int	ffs_realloccg(struct inode *,
	    ufs_daddr_t, ufs_daddr_t, int, int, struct ucred *, struct buf **);
int	ffs_reclaim(struct vnop_reclaim_args *);
void	ffs_setblock(struct fs *, u_char *, ufs_daddr_t);
int	ffs_vfs_getattr(struct mount *, struct vfs_attr *, vfs_context_t);
int	ffs_vfs_setattr(struct mount *, struct vfs_attr *, vfs_context_t);
int	ffs_sync(struct mount *, int, vfs_context_t);
int	ffs_sysctl(int *, u_int, user_addr_t, size_t *, user_addr_t, size_t, vfs_context_t);
int	ffs_unmount(struct mount *, int, vfs_context_t);
int	ffs_update(struct vnode *, struct timeval *, struct timeval *, int);
int	ffs_valloc(vnode_t dvp, mode_t mode, kauth_cred_t cred, vnode_t *vpp);
int	ffs_vfree(struct vnode *vp, ino_t ino, int mode);
int	ffs_vget(struct mount *, ino64_t, struct vnode **, vfs_context_t);
int	ffs_vptofh(struct vnode *, int *, unsigned char *, vfs_context_t);
int	ffs_write(struct vnop_write_args *);
int ffs_pagein(struct vnop_pagein_args *);
int ffs_pageout(struct vnop_pageout_args *);
int ffs_blktooff(struct vnop_blktooff_args *);
int ffs_offtoblk(struct vnop_offtoblk_args *);

__END_DECLS

extern int (**ffs_vnodeop_p)(void *);
extern int (**ffs_specop_p)(void *);
#if FIFO
extern int (**ffs_fifoop_p)(void *);
#define FFS_FIFOOPS ffs_fifoop_p
#else
#define FFS_FIFOOPS NULL
#endif

#endif /* __APPLE_API_PRIVATE */
#endif /* __UFS_FFS_FFS_EXTERN_H__ */
