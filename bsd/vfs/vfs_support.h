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
/*
 * Copyright (c) 1998 Apple Computer, Inc.  All rights reserved.
 *
 *  File:  vfs/vfs_support.h
 *
 *	Prototypes for the default vfs routines. A VFS plugin can use these
 *	functions in case it does not want to implement all. These functions
 *	take care of releasing locks and free up memory that they are
 *	supposed to.
 *
 * HISTORY
 *  18-Aug-1998 Umesh Vaishampayan (umeshv@apple.com)
 *      Created. 
 */

#ifndef	_VFS_VFS_SUPPORT_H_
#define	_VFS_VFS_SUPPORT_H_

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/namei.h>
#include <sys/resourcevar.h>
#include <sys/kernel.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/buf.h>
#include <sys/proc.h>
#include <sys/conf.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <vm/vm_pageout.h>

extern int nop_create(struct vop_create_args *ap);
extern int err_create(struct vop_create_args *ap);

extern int nop_whiteout(struct vop_whiteout_args *ap);
extern int err_whiteout(struct vop_whiteout_args *ap);

extern int nop_mknod(struct vop_mknod_args *ap);
extern int err_mknod(struct vop_mknod_args *ap);

extern int nop_mkcomplex(struct vop_mkcomplex_args *ap);
extern int err_mkcomplex(struct vop_mkcomplex_args *ap);

extern int nop_open(struct vop_open_args *ap);
extern int err_open(struct vop_open_args *ap);

extern int nop_close(struct vop_close_args *ap);
extern int err_close(struct vop_close_args *ap);

extern int nop_access(struct vop_access_args *ap);
extern int err_access(struct vop_access_args *ap);

extern int nop_getattr(struct vop_getattr_args *ap);
extern int err_getattr(struct vop_getattr_args *ap);

extern int nop_setattr(struct vop_setattr_args *ap);
extern int err_setattr(struct vop_setattr_args *ap);

extern int nop_getattrlist(struct vop_getattrlist_args *ap);
extern int err_getattrlist(struct vop_getattrlist_args *ap);

extern int nop_setattrlist(struct vop_setattrlist_args *ap);
extern int err_setattrlist(struct vop_setattrlist_args *ap);

extern int nop_read(struct vop_read_args *ap);
extern int err_read(struct vop_read_args *ap);

extern int nop_write(struct vop_write_args *ap);
extern int err_write(struct vop_write_args *ap);

extern int nop_lease(struct vop_lease_args *ap);
extern int err_lease(struct vop_lease_args *ap);

extern int nop_ioctl(struct vop_ioctl_args *ap);
extern int err_ioctl(struct vop_ioctl_args *ap);

extern int nop_select(struct vop_select_args *ap);
extern int err_select(struct vop_select_args *ap);

extern int nop_exchange(struct vop_exchange_args *ap);
extern int err_exchange(struct vop_exchange_args *ap);

extern int nop_revoke(struct vop_revoke_args *ap);
extern int err_revoke(struct vop_revoke_args *ap);

extern int nop_mmap(struct vop_mmap_args *ap);
extern int err_mmap(struct vop_mmap_args *ap);

extern int nop_fsync(struct vop_fsync_args *ap);
extern int err_fsync(struct vop_fsync_args *ap);

extern int nop_seek(struct vop_seek_args *ap);
extern int err_seek(struct vop_seek_args *ap);

extern int nop_remove(struct vop_remove_args *ap);
extern int err_remove(struct vop_remove_args *ap);

extern int nop_link(struct vop_link_args *ap);
extern int err_link(struct vop_link_args *ap);

extern int nop_rename(struct vop_rename_args *ap);
extern int err_rename(struct vop_rename_args *ap);

extern int nop_mkdir(struct vop_mkdir_args *ap);
extern int err_mkdir(struct vop_mkdir_args *ap);

extern int nop_rmdir(struct vop_rmdir_args *ap);
extern int err_rmdir(struct vop_rmdir_args *ap);

extern int nop_symlink(struct vop_symlink_args *ap);
extern int err_symlink(struct vop_symlink_args *ap);

extern int nop_readdir(struct vop_readdir_args *ap);
extern int err_readdir(struct vop_readdir_args *ap);

extern int nop_readdirattr(struct vop_readdirattr_args *ap);
extern int err_readdirattr(struct vop_readdirattr_args *ap);

extern int nop_readlink(struct vop_readlink_args *ap);
extern int err_readlink(struct vop_readlink_args *ap);

extern int nop_abortop(struct vop_abortop_args *ap);
extern int err_abortop(struct vop_abortop_args *ap);

extern int nop_inactive(struct vop_inactive_args *ap);
extern int err_inactive(struct vop_inactive_args *ap);

extern int nop_reclaim(struct vop_reclaim_args *ap);
extern int err_reclaim(struct vop_reclaim_args *ap);

extern int nop_lock(struct vop_lock_args *ap);
extern int err_lock(struct vop_lock_args *ap);

extern int nop_unlock(struct vop_unlock_args *ap);
extern int err_unlock(struct vop_unlock_args *ap);

extern int nop_bmap(struct vop_bmap_args *ap);
extern int err_bmap(struct vop_bmap_args *ap);

extern int nop_strategy(struct vop_strategy_args *ap);
extern int err_strategy(struct vop_strategy_args *ap);

extern int nop_print(struct vop_print_args *ap);
extern int err_print(struct vop_print_args *ap);

extern int nop_islocked(struct vop_islocked_args *ap);
extern int err_islocked(struct vop_islocked_args *ap);

extern int nop_pathconf(struct vop_pathconf_args *ap);
extern int err_pathconf(struct vop_pathconf_args *ap);

extern int nop_advlock(struct vop_advlock_args *ap);
extern int err_advlock(struct vop_advlock_args *ap);

extern int nop_blkatoff(struct vop_blkatoff_args *ap);
extern int err_blkatoff(struct vop_blkatoff_args *ap);

extern int nop_valloc(struct vop_valloc_args *ap);
extern int err_valloc(struct vop_valloc_args *ap);

extern int nop_reallocblks(struct vop_reallocblks_args *ap);
extern int err_reallocblks(struct vop_reallocblks_args *ap);

extern int nop_vfree(struct vop_vfree_args *ap);
extern int err_vfree(struct vop_vfree_args *ap);

extern int nop_truncate(struct vop_truncate_args *ap);
extern int err_truncate(struct vop_truncate_args *ap);

extern int nop_allocate(struct vop_allocate_args *ap);
extern int err_allocate(struct vop_allocate_args *ap);

extern int nop_update(struct vop_update_args *ap);
extern int err_update(struct vop_update_args *ap);

extern int nop_pgrd(struct vop_pgrd_args *ap);
extern int err_pgrd(struct vop_pgrd_args *ap);

extern int nop_pgwr(struct vop_pgwr_args *ap);
extern int err_pgwr(struct vop_pgwr_args *ap);

extern int nop_bwrite(struct vop_bwrite_args *ap);
extern int err_bwrite(struct vop_bwrite_args *ap);

extern int nop_pagein(struct vop_pagein_args *ap);
extern int err_pagein(struct vop_pagein_args *ap);

extern int nop_pageout(struct vop_pageout_args *ap);
extern int err_pageout(struct vop_pageout_args *ap);

extern int nop_devblocksize(struct vop_devblocksize_args *ap);
extern int err_devblocksize(struct vop_devblocksize_args *ap);

extern int nop_searchfs(struct vop_searchfs_args *ap);
extern int err_searchfs(struct vop_searchfs_args *ap);

extern int nop_copyfile(struct vop_copyfile_args *ap);
extern int err_copyfile(struct vop_copyfile_args *ap);

extern int nop_blktooff(struct vop_blktooff_args *ap);
extern int err_blktooff(struct vop_blktooff_args *ap);

extern int nop_offtoblk(struct vop_offtoblk_args *ap);
extern int err_offtoblk(struct vop_offtoblk_args *ap);

extern int nop_cmap(struct vop_cmap_args *ap);
extern int err_cmap(struct vop_cmap_args *ap);
#endif	/* _VFS_VFS_SUPPORT_H_ */
