
/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
/*
 * Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved
 * Copyright (c) 1992, 1993, 1994, 1995
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
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS AND
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
 */


/*
 * Warning: This file is generated automatically.
 * (Modifications made here may easily be lost!)
 *
 * Created by the script:
 *	@(#)vnode_if.sh	8.7 (Berkeley) 5/11/95
 */


#ifndef _SYS_VNODE_IF_H_
#define _SYS_VNODE_IF_H_

#include <sys/appleapiopts.h>
#include <sys/cdefs.h>
#include <sys/kernel_types.h>
#include <sys/buf.h>
#ifdef BSD_KERNEL_PRIVATE
#include <sys/vm.h>
#endif
#include <mach/memory_object_types.h>


#ifdef KERNEL

extern struct vnodeop_desc vnop_default_desc;
extern struct vnodeop_desc vnop_lookup_desc;
extern struct vnodeop_desc vnop_create_desc;
extern struct vnodeop_desc vnop_whiteout_desc;
extern struct vnodeop_desc vnop_mknod_desc;
extern struct vnodeop_desc vnop_open_desc;
extern struct vnodeop_desc vnop_close_desc;
extern struct vnodeop_desc vnop_access_desc;
extern struct vnodeop_desc vnop_getattr_desc;
extern struct vnodeop_desc vnop_setattr_desc;
extern struct vnodeop_desc vnop_getattrlist_desc;
extern struct vnodeop_desc vnop_setattrlist_desc;
extern struct vnodeop_desc vnop_read_desc;
extern struct vnodeop_desc vnop_write_desc;
extern struct vnodeop_desc vnop_ioctl_desc;
extern struct vnodeop_desc vnop_select_desc;
extern struct vnodeop_desc vnop_exchange_desc;
extern struct vnodeop_desc vnop_revoke_desc;
extern struct vnodeop_desc vnop_mmap_desc;
extern struct vnodeop_desc vnop_mnomap_desc;
extern struct vnodeop_desc vnop_fsync_desc;
extern struct vnodeop_desc vnop_remove_desc;
extern struct vnodeop_desc vnop_link_desc;
extern struct vnodeop_desc vnop_rename_desc;
extern struct vnodeop_desc vnop_mkdir_desc;
extern struct vnodeop_desc vnop_rmdir_desc;
extern struct vnodeop_desc vnop_symlink_desc;
extern struct vnodeop_desc vnop_readdir_desc;
extern struct vnodeop_desc vnop_readdirattr_desc;
extern struct vnodeop_desc vnop_readlink_desc;
extern struct vnodeop_desc vnop_inactive_desc;
extern struct vnodeop_desc vnop_reclaim_desc;
extern struct vnodeop_desc vnop_print_desc;
extern struct vnodeop_desc vnop_pathconf_desc;
extern struct vnodeop_desc vnop_advlock_desc;
extern struct vnodeop_desc vnop_truncate_desc;
extern struct vnodeop_desc vnop_allocate_desc;
extern struct vnodeop_desc vnop_pagein_desc;
extern struct vnodeop_desc vnop_pageout_desc;
extern struct vnodeop_desc vnop_searchfs_desc;
extern struct vnodeop_desc vnop_copyfile_desc;
extern struct vnodeop_desc vnop_blktooff_desc;
extern struct vnodeop_desc vnop_offtoblk_desc;
extern struct vnodeop_desc vnop_blockmap_desc;
extern struct vnodeop_desc vnop_strategy_desc;
extern struct vnodeop_desc vnop_bwrite_desc;

__BEGIN_DECLS
/*
 *# 
 *#% lookup       dvp     L ? ?
 *#% lookup       vpp     - L -
 */
struct vnop_lookup_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_dvp;
	vnode_t *a_vpp;
	struct componentname *a_cnp;
	vfs_context_t a_context;
};
extern errno_t VNOP_LOOKUP(vnode_t, vnode_t *, struct componentname *, vfs_context_t);


/*
 *#
 *#% create       dvp     L L L
 *#% create       vpp     - L -
 *#
 */
 
struct vnop_create_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_dvp;
	vnode_t *a_vpp;
	struct componentname *a_cnp;
	struct vnode_attr *a_vap;
	vfs_context_t a_context;
};
extern errno_t VNOP_CREATE(vnode_t, vnode_t *, struct componentname *, struct vnode_attr *, vfs_context_t);

/*
 *#
 *#% whiteout     dvp     L L L
 *#% whiteout     cnp     - - -
 *#% whiteout     flag    - - -
 *#
 */
struct vnop_whiteout_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_dvp;
	struct componentname *a_cnp;
	int a_flags;
	vfs_context_t a_context;
};
extern errno_t VNOP_WHITEOUT(vnode_t, struct componentname *, int, vfs_context_t);

/*
 *#
 *#% mknod        dvp     L U U
 *#% mknod        vpp     - X -
 *#
 */
struct vnop_mknod_args {
       struct vnodeop_desc *a_desc;
       vnode_t a_dvp;
       vnode_t *a_vpp;
       struct componentname *a_cnp;
       struct vnode_attr *a_vap;
       vfs_context_t a_context;
};
extern errno_t VNOP_MKNOD(vnode_t, vnode_t *, struct componentname *, struct vnode_attr *, vfs_context_t);

/*
 *#
 *#% open         vp      L L L
 *#
 */
struct vnop_open_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	int a_mode;
	vfs_context_t a_context;
};
extern errno_t VNOP_OPEN(vnode_t, int, vfs_context_t);

/*
 *#
 *#% close        vp      U U U
 *#
 */
struct vnop_close_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	int a_fflag;
	vfs_context_t a_context;
};
extern errno_t VNOP_CLOSE(vnode_t, int, vfs_context_t);

/*
 *#
 *#% access       vp      L L L
 *#
 */
struct vnop_access_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	int a_action;
	vfs_context_t a_context;
};
extern errno_t VNOP_ACCESS(vnode_t, int, vfs_context_t);


/*
 *#
 *#% getattr      vp      = = =
 *#
 */
struct vnop_getattr_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct vnode_attr *a_vap;
	vfs_context_t a_context;
};
extern errno_t VNOP_GETATTR(vnode_t, struct vnode_attr *, vfs_context_t);

/*
 *#
 *#% setattr      vp      L L L
 *#
 */
struct vnop_setattr_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct vnode_attr *a_vap;
	vfs_context_t a_context;
};
extern errno_t VNOP_SETATTR(vnode_t, struct vnode_attr *, vfs_context_t);

/*
 *#
 *#% getattrlist  vp      = = =
 *#
 */
struct vnop_getattrlist_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct attrlist *a_alist;
	struct uio *a_uio;
	int a_options;
	vfs_context_t a_context;
};
extern errno_t VNOP_GETATTRLIST(vnode_t, struct attrlist *, struct uio *, int, vfs_context_t);


/*
 *#
 *#% setattrlist  vp      L L L
 *#
 */
struct vnop_setattrlist_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct attrlist *a_alist;
	struct uio *a_uio;
	int a_options;
	vfs_context_t a_context;
};
extern errno_t VNOP_SETATTRLIST(vnode_t, struct attrlist *, struct uio *, int, vfs_context_t);


/*
 *#
 *#% read         vp      L L L
 *#
 */
struct vnop_read_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct uio *a_uio;
	int a_ioflag;
	vfs_context_t a_context;
};
extern errno_t VNOP_READ(vnode_t, struct uio *, int, vfs_context_t);


/*
 *#
 *#% write        vp      L L L
 *#
 */
struct vnop_write_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct uio *a_uio;
	int a_ioflag;
	vfs_context_t a_context;
};
extern errno_t VNOP_WRITE(vnode_t, struct uio *, int, vfs_context_t);


/*
 *#
 *#% ioctl        vp      U U U
 *#
 */
struct vnop_ioctl_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	u_long a_command;
	caddr_t a_data;
	int a_fflag;
	vfs_context_t a_context;
};
extern errno_t VNOP_IOCTL(vnode_t, u_long, caddr_t, int, vfs_context_t);


/*
 *#
 *#% select       vp      U U U
 *#
 */
struct vnop_select_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	int a_which;
	int a_fflags;
	void *a_wql;
	vfs_context_t a_context;
};
extern errno_t VNOP_SELECT(vnode_t, int, int, void *, vfs_context_t);


/*
 *#
 *#% exchange fvp         L L L
 *#% exchange tvp         L L L
 *#
 */
struct vnop_exchange_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_fvp;
        vnode_t a_tvp;
	int a_options;
	vfs_context_t a_context;
};
extern errno_t VNOP_EXCHANGE(vnode_t, vnode_t, int, vfs_context_t);


/*
 *#
 *#% revoke       vp      U U U
 *#
 */
struct vnop_revoke_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	int a_flags;
	vfs_context_t a_context;
};
extern errno_t VNOP_REVOKE(vnode_t, int, vfs_context_t);


/*
 *#
 *# mmap - vp U U U
 *#
 */
struct vnop_mmap_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	int a_fflags;
	vfs_context_t a_context;
};
extern errno_t VNOP_MMAP(vnode_t, int, vfs_context_t);

/*
 *#
 *# mnomap - vp U U U
 *#
 */
struct vnop_mnomap_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	vfs_context_t a_context;
};
extern errno_t VNOP_MNOMAP(vnode_t, vfs_context_t);


/*
 *#
 *#% fsync        vp      L L L
 *#
 */
struct vnop_fsync_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	int a_waitfor;
	vfs_context_t a_context;
};
extern errno_t VNOP_FSYNC(vnode_t, int, vfs_context_t);


/*
 *#
 *#% remove       dvp     L U U
 *#% remove       vp      L U U
 *#
 */
struct vnop_remove_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_dvp;
	vnode_t a_vp;
	struct componentname *a_cnp;
	int a_flags;
	vfs_context_t a_context;
};
extern errno_t VNOP_REMOVE(vnode_t, vnode_t, struct componentname *, int, vfs_context_t);


/*
 *#
 *#% link         vp      U U U
 *#% link         tdvp    L U U
 *#
 */
struct vnop_link_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	vnode_t a_tdvp;
	struct componentname *a_cnp;
	vfs_context_t a_context;
};
extern errno_t VNOP_LINK(vnode_t, vnode_t, struct componentname *, vfs_context_t);


/*
 *#
 *#% rename       fdvp    U U U
 *#% rename       fvp     U U U
 *#% rename       tdvp    L U U
 *#% rename       tvp     X U U
 *#
 */
struct vnop_rename_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_fdvp;
	vnode_t a_fvp;
	struct componentname *a_fcnp;
	vnode_t a_tdvp;
	vnode_t a_tvp;
	struct componentname *a_tcnp;
	vfs_context_t a_context;
};
extern errno_t VNOP_RENAME(vnode_t, vnode_t, struct componentname *, vnode_t, vnode_t, struct componentname *, vfs_context_t);


/*
 *#
 *#% mkdir        dvp     L U U
 *#% mkdir        vpp     - L -
 *#
 */
struct vnop_mkdir_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_dvp;
	vnode_t *a_vpp;
	struct componentname *a_cnp;
	struct vnode_attr *a_vap;
	vfs_context_t a_context;
	};
extern errno_t VNOP_MKDIR(vnode_t, vnode_t *, struct componentname *, struct vnode_attr *, vfs_context_t);


/*
 *#
 *#% rmdir        dvp     L U U
 *#% rmdir        vp      L U U
 *#
 */
struct vnop_rmdir_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_dvp;
	vnode_t a_vp;
	struct componentname *a_cnp;
	vfs_context_t a_context;
};
extern errno_t VNOP_RMDIR(vnode_t, vnode_t, struct componentname *, vfs_context_t);


/*
 *#
 *#% symlink      dvp     L U U
 *#% symlink      vpp     - U -
 *#
 */
struct vnop_symlink_args {
       struct vnodeop_desc *a_desc;
       vnode_t a_dvp;
       vnode_t *a_vpp;
       struct componentname *a_cnp;
       struct vnode_attr *a_vap;
       char *a_target;
       vfs_context_t a_context;
};
extern errno_t VNOP_SYMLINK(vnode_t, vnode_t *, struct componentname *, struct vnode_attr *, char *, vfs_context_t);


/*
 *#
 *#% readdir      vp      L L L
 *#
 *
 *  When VNOP_READDIR is called from the NFS Server, the nfs_data
 *  argument is non-NULL.
 *
 *  The value of nfs_eofflag should be set to TRUE if the end of
 *  the directory was reached while reading.
 *
 *  The directory seek offset (cookies) are returned to the NFS client and
 *  may be used later to restart a directory read part way through
 *  the directory. There is one cookie returned for each directory
 *  entry returned and its size is determince from nfs_sizeofcookie.
 *  The value of the cookie should be the logical offset within the
 *  directory where the on-disc version of the appropriate directory
 *  entry starts. Memory for the cookies is allocated from M_TEMP
 *  and it is freed by the caller of VNOP_READDIR.
 *
 */

struct vnop_readdir_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct uio *a_uio;
	int a_flags;
	int *a_eofflag;
	int *a_numdirent;
	vfs_context_t a_context;
};
extern errno_t VNOP_READDIR(vnode_t, struct uio *, int, int *, int *, vfs_context_t);


/*
 *#
 *#% readdirattr  vp      L L L
 *#
 */
struct vnop_readdirattr_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct attrlist *a_alist;
	struct uio *a_uio;
	u_long a_maxcount;
	u_long a_options;
	u_long *a_newstate;
	int *a_eofflag;
	u_long *a_actualcount;
	vfs_context_t a_context;
};
extern errno_t VNOP_READDIRATTR(vnode_t, struct attrlist *, struct uio *, u_long, u_long, u_long *, int *, u_long *, vfs_context_t);


/*
 *#
 *#% readlink     vp      L L L
 *#
 */
struct vnop_readlink_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct uio *a_uio;
	vfs_context_t a_context;
};
extern errno_t VNOP_READLINK(vnode_t, struct uio *, vfs_context_t);


/*
 *#
 *#% inactive     vp      L U U
 *#
 */
struct vnop_inactive_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	vfs_context_t a_context;
};
extern errno_t VNOP_INACTIVE(vnode_t, vfs_context_t);


/*
 *#
 *#% reclaim      vp      U U U
 *#
 */
struct vnop_reclaim_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	vfs_context_t a_context;
};
extern errno_t VNOP_RECLAIM(vnode_t, vfs_context_t);


/*
 *#
 *#% pathconf     vp      L L L
 *#
 */
struct vnop_pathconf_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	int a_name;
	register_t *a_retval;
	vfs_context_t a_context;
};
extern errno_t VNOP_PATHCONF(vnode_t, int, register_t *, vfs_context_t); /* register_t??????? */


/*
 *#
 *#% advlock      vp      U U U
 *#
 */
struct vnop_advlock_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	caddr_t a_id;
	int a_op;
	struct flock *a_fl;
	int a_flags;
	vfs_context_t a_context;
};
extern errno_t VNOP_ADVLOCK(vnode_t, caddr_t, int, struct flock *, int, vfs_context_t);

/*
 *#
 *#% allocate     vp      L L L
 *#
 */
struct vnop_allocate_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	off_t a_length;
	u_int32_t a_flags;
	off_t *a_bytesallocated;
	off_t a_offset;
	vfs_context_t a_context;
};
extern errno_t VNOP_ALLOCATE(vnode_t, off_t, u_int32_t, off_t *, off_t, vfs_context_t);

/*
 *#
 *#% pagein       vp      = = =
 *#
 */
struct vnop_pagein_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	upl_t a_pl;
	vm_offset_t a_pl_offset;
	off_t a_f_offset;
	size_t a_size;
	int a_flags;
	vfs_context_t a_context;
};
extern errno_t VNOP_PAGEIN(vnode_t, upl_t, vm_offset_t, off_t, size_t, int, vfs_context_t); /* vm_offset_t ? */


/*
 *#
 *#% pageout      vp      = = =
 *#
 */
struct vnop_pageout_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	upl_t a_pl;
	vm_offset_t a_pl_offset;
	off_t a_f_offset;
	size_t a_size;
	int a_flags;
	vfs_context_t a_context;
};
extern errno_t VNOP_PAGEOUT(vnode_t, upl_t, vm_offset_t, off_t, size_t, int, vfs_context_t);


/*
 *#
 *#% searchfs     vp      L L L
 *#
 */
struct vnop_searchfs_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	void *a_searchparams1;
	void *a_searchparams2;
	struct attrlist *a_searchattrs;
	u_long a_maxmatches;
	struct timeval *a_timelimit;
	struct attrlist *a_returnattrs;
	u_long *a_nummatches;
	u_long a_scriptcode;
	u_long a_options;
	struct uio *a_uio;
	struct searchstate *a_searchstate;
	vfs_context_t a_context;
};
extern errno_t VNOP_SEARCHFS(vnode_t, void *, void *, struct attrlist *, u_long, struct timeval *, struct attrlist *, u_long *, u_long, u_long, struct uio *, struct searchstate *, vfs_context_t);


/*
 *#
 *#% copyfile fvp U U U
 *#% copyfile tdvp L U U
 *#% copyfile tvp X U U
 *#
 */
struct vnop_copyfile_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_fvp;
	vnode_t a_tdvp;
	vnode_t a_tvp;
	struct componentname *a_tcnp;
	int a_mode;
	int a_flags;
	vfs_context_t a_context;
};
extern errno_t VNOP_COPYFILE(vnode_t, vnode_t, vnode_t, struct componentname *, int, int, vfs_context_t);


struct vnop_getxattr_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	char * a_name;
	uio_t a_uio;
	size_t *a_size;
	int a_options;
	vfs_context_t a_context;
};
extern struct vnodeop_desc vnop_getxattr_desc;
extern errno_t VNOP_GETXATTR(vnode_t, const char *, uio_t, size_t *, int, vfs_context_t);

struct vnop_setxattr_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	char * a_name;
	uio_t a_uio;
	int a_options;
	vfs_context_t a_context;
};
extern struct vnodeop_desc vnop_setxattr_desc;
extern errno_t VNOP_SETXATTR(vnode_t, const char *, uio_t, int, vfs_context_t);

struct vnop_removexattr_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	char * a_name;
	int a_options;
	vfs_context_t a_context;
};
extern struct vnodeop_desc vnop_removexattr_desc;
extern errno_t VNOP_REMOVEXATTR(vnode_t, const char *, int, vfs_context_t);

struct vnop_listxattr_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	uio_t a_uio;
	size_t *a_size;
	int a_options;
	vfs_context_t a_context;
};
extern struct vnodeop_desc vnop_listxattr_desc;
extern errno_t VNOP_LISTXATTR(vnode_t, uio_t, size_t *, int, vfs_context_t);


/*
 *#
 *#% blktooff vp = = =
 *#
 */
struct vnop_blktooff_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	daddr64_t a_lblkno;
	off_t *a_offset;
};
extern errno_t VNOP_BLKTOOFF(vnode_t, daddr64_t, off_t *); 


/*
 *#
 *#% offtoblk vp = = =
 *#
 */
struct vnop_offtoblk_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	off_t a_offset;
	daddr64_t *a_lblkno;
};
extern errno_t VNOP_OFFTOBLK(vnode_t, off_t, daddr64_t *); 


/*
 *#
 *#% blockmap vp L L L
 *#
 */
struct vnop_blockmap_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	off_t a_foffset;
	size_t a_size;
	daddr64_t *a_bpn;
	size_t *a_run;
	void *a_poff;
	int a_flags;
	vfs_context_t a_context;
};
extern errno_t VNOP_BLOCKMAP(vnode_t, off_t, size_t, daddr64_t *, size_t *, void *,
                             int, vfs_context_t);

struct vnop_strategy_args {
	struct vnodeop_desc *a_desc;
	struct buf *a_bp;
};
extern errno_t VNOP_STRATEGY(struct buf *bp);

struct vnop_bwrite_args {
	struct vnodeop_desc *a_desc;
	buf_t a_bp;
};
extern errno_t VNOP_BWRITE(buf_t);


struct vnop_kqfilt_add_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	struct knote *a_kn;
	vfs_context_t a_context;
};
extern struct vnodeop_desc vnop_kqfilt_add_desc;
extern errno_t VNOP_KQFILT_ADD(vnode_t , struct knote *, vfs_context_t);

struct vnop_kqfilt_remove_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	uintptr_t a_ident;
	vfs_context_t a_context;
};
extern struct vnodeop_desc vnop_kqfilt_remove_desc;
errno_t VNOP_KQFILT_REMOVE(vnode_t , uintptr_t , vfs_context_t);

__END_DECLS

#endif /* KERNEL */

#endif /* !_SYS_VNODE_IF_H_ */
