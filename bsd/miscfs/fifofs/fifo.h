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
/*
 * Copyright (c) 1991, 1993
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
 *	@(#)fifo.h	8.3 (Berkeley) 8/10/94
 */
#ifndef __FIFOFS_FOFO_H__
#define __FIFOFS_FOFO_H__

#include  <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE
/*
 * Prototypes for fifo operations on vnodes.
 */
int	fifo_ebadf();

int	fifo_lookup __P((struct vop_lookup_args *));
#define fifo_create ((int (*) __P((struct  vop_create_args *)))err_create)
#define fifo_mknod ((int (*) __P((struct  vop_mknod_args *)))err_mknod)
int	fifo_open __P((struct vop_open_args *));
int	fifo_close __P((struct vop_close_args *));
#define fifo_access ((int (*) __P((struct  vop_access_args *)))fifo_ebadf)
#define fifo_getattr ((int (*) __P((struct  vop_getattr_args *)))fifo_ebadf)
#define fifo_setattr ((int (*) __P((struct  vop_setattr_args *)))fifo_ebadf)
int	fifo_read __P((struct vop_read_args *));
int	fifo_write __P((struct vop_write_args *));
#define fifo_lease_check ((int (*) __P((struct  vop_lease_args *)))nullop)
int	fifo_ioctl __P((struct vop_ioctl_args *));
int	fifo_select __P((struct vop_select_args *));
#define	fifo_revoke vop_revoke
#define fifo_mmap ((int (*) __P((struct  vop_mmap_args *)))err_mmap)
#define fifo_fsync ((int (*) __P((struct  vop_fsync_args *)))nullop)
#define fifo_seek ((int (*) __P((struct  vop_seek_args *)))err_seek)
#define fifo_remove ((int (*) __P((struct  vop_remove_args *)))err_remove)
#define fifo_link ((int (*) __P((struct  vop_link_args *)))err_link)
#define fifo_rename ((int (*) __P((struct  vop_rename_args *)))err_rename)
#define fifo_mkdir ((int (*) __P((struct  vop_mkdir_args *)))err_mkdir)
#define fifo_rmdir ((int (*) __P((struct  vop_rmdir_args *)))err_rmdir)
#define fifo_symlink ((int (*) __P((struct  vop_symlink_args *)))err_symlink)
#define fifo_readdir ((int (*) __P((struct  vop_readdir_args *)))err_readdir)
#define fifo_readlink ((int (*) __P((struct  vop_readlink_args *)))err_readlink)
#define fifo_abortop ((int (*) __P((struct  vop_abortop_args *)))err_abortop)
int	fifo_inactive __P((struct  vop_inactive_args *));
#define fifo_reclaim ((int (*) __P((struct  vop_reclaim_args *)))nullop)
#define fifo_lock ((int (*) __P((struct  vop_lock_args *)))vop_nolock)
#define fifo_unlock ((int (*) __P((struct  vop_unlock_args *)))vop_nounlock)
int	fifo_bmap __P((struct vop_bmap_args *));
#define fifo_strategy ((int (*) __P((struct  vop_strategy_args *)))err_strategy)
int	fifo_print __P((struct vop_print_args *));
#define fifo_islocked ((int(*) __P((struct vop_islocked_args *)))vop_noislocked)
int	fifo_pathconf __P((struct vop_pathconf_args *));
int	fifo_advlock __P((struct vop_advlock_args *));
#define fifo_blkatoff ((int (*) __P((struct  vop_blkatoff_args *)))err_blkatoff)
#define fifo_valloc ((int (*) __P((struct  vop_valloc_args *)))err_valloc)
#define fifo_reallocblks \
	((int (*) __P((struct  vop_reallocblks_args *)))err_reallocblks)
#define fifo_vfree ((int (*) __P((struct  vop_vfree_args *)))err_vfree)
#define fifo_truncate ((int (*) __P((struct  vop_truncate_args *)))nullop)
#define fifo_update ((int (*) __P((struct  vop_update_args *)))nullop)
#define fifo_bwrite ((int (*) __P((struct  vop_bwrite_args *)))nullop)
#define fifo_blktooff ((int (*) __P((struct vop_blktooff_args *)))err_blktooff)

#endif /* __APPLE_API_PRIVATE */
#endif /* __FIFOFS_FOFO_H__ */
