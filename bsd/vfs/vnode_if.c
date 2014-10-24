
/*
 * Copyright (c) 2000-2014 Apple Computer, Inc. All rights reserved.
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


#include <sys/param.h>
#include <sys/mount_internal.h>
#include <sys/vm.h>
#include <sys/vnode_internal.h>

struct vnodeop_desc vnop_default_desc = {
	0,
	"default",
	0,
	NULL,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	NULL
};


int vnop_lookup_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_lookup_args,a_dvp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_lookup_desc = {
	0,
	"vnop_lookup",
	0,
	vnop_lookup_vp_offsets,
	VOPARG_OFFSETOF(struct vnop_lookup_args, a_vpp),
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_lookup_args, a_cnp),
	VOPARG_OFFSETOF(struct vnop_lookup_args, a_context),
	NULL
};

int vnop_compound_open_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_compound_open_args, a_dvp),
	VDESC_NO_OFFSET
};

struct vnodeop_desc vnop_compound_open_desc = {
	0,
	"vnop_compound_open",
	0 | VDESC_VP0_WILLRELE,
	vnop_compound_open_vp_offsets, 
	VOPARG_OFFSETOF(struct vnop_compound_open_args, a_vpp),
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_compound_open_args, a_cnp),
	VOPARG_OFFSETOF(struct vnop_compound_open_args, a_context),
	NULL
};

int vnop_create_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_create_args,a_dvp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_create_desc = {
	0,
	"vnop_create",
	0 | VDESC_VP0_WILLRELE,
	vnop_create_vp_offsets,
	VOPARG_OFFSETOF(struct vnop_create_args, a_vpp),
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_create_args, a_cnp),
	VOPARG_OFFSETOF(struct vnop_create_args, a_context),
	NULL
};

int vnop_whiteout_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_whiteout_args,a_dvp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_whiteout_desc = {
	0,
	"vnop_whiteout",
	0 | VDESC_VP0_WILLRELE,
	vnop_whiteout_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_whiteout_args, a_cnp),
	VOPARG_OFFSETOF(struct vnop_whiteout_args, a_context),
	NULL
};

int vnop_mknod_vp_offsets[] = {
       VOPARG_OFFSETOF(struct vnop_mknod_args,a_dvp),
       VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_mknod_desc = {
       0,
       "vnop_mknod",
       0 | VDESC_VP0_WILLRELE | VDESC_VPP_WILLRELE,
       vnop_mknod_vp_offsets,
       VOPARG_OFFSETOF(struct vnop_mknod_args, a_vpp),
       VDESC_NO_OFFSET,
       VDESC_NO_OFFSET,
       VOPARG_OFFSETOF(struct vnop_mknod_args, a_cnp),
       VOPARG_OFFSETOF(struct vnop_mknod_args, a_context),
       NULL
};

int vnop_open_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_open_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_open_desc = {
	0,
	"vnop_open",
	0,
	vnop_open_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_open_args, a_context),
	NULL
};

int vnop_close_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_close_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_close_desc = {
	0,
	"vnop_close",
	0,
	vnop_close_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_close_args, a_context),
	NULL
};

int vnop_access_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_access_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_access_desc = {
	0,
	"vnop_access",
	0,
	vnop_access_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_close_args, a_context),
	NULL
};

int vnop_getattr_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_getattr_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_getattr_desc = {
	0,
	"vnop_getattr",
	0,
	vnop_getattr_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_getattr_args, a_context),
	NULL
};

int vnop_setattr_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_setattr_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_setattr_desc = {
	0,
	"vnop_setattr",
	0,
	vnop_setattr_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_setattr_args, a_context),
	NULL
};

int vnop_read_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_read_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_read_desc = {
	0,
	"vnop_read",
	0,
	vnop_read_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_read_args, a_context),
	NULL
};

int vnop_write_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_write_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_write_desc = {
	0,
	"vnop_write",
	0,
	vnop_write_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_write_args, a_context),
	NULL
};

int vnop_ioctl_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_ioctl_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_ioctl_desc = {
	0,
	"vnop_ioctl",
	0,
	vnop_ioctl_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_ioctl_args, a_context),
	NULL
};

int vnop_select_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_select_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_select_desc = {
	0,
	"vnop_select",
	0,
	vnop_select_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_select_args, a_context),
	NULL
};

int vnop_exchange_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_exchange_args,a_fvp),
	VOPARG_OFFSETOF(struct vnop_exchange_args,a_tvp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_exchange_desc = {
	0,
	"vnop_exchange",
	0,
	vnop_exchange_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_exchange_args, a_context),
	NULL
};

int vnop_kqfilt_add_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_kqfilt_add_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_kqfilt_add_desc = {
	0,
	"vnop_kqfilt_add",
	0,
	vnop_kqfilt_add_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_kqfilt_add_args, a_context),
	NULL
};

int vnop_kqfilt_remove_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_kqfilt_remove_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_kqfilt_remove_desc = {
	0,
	"vnop_kqfilt_remove",
	0,
	vnop_kqfilt_remove_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_kqfilt_remove_args, a_context),
	NULL
};

int vnop_monitor_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_monitor_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_monitor_desc = {
	0,
	"vnop_monitor",
	0,
	vnop_monitor_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_monitor_args, a_context),
	NULL
};

int vnop_setlabel_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_setlabel_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_setlabel_desc = {
	0,
	"vnop_setlabel",
	0,
	vnop_setlabel_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_setlabel_args, a_context),
	NULL,
};

int vnop_revoke_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_revoke_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_revoke_desc = {
	0,
	"vnop_revoke",
	0,
	vnop_revoke_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	NULL
};


int vnop_mmap_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_mmap_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_mmap_desc = {
	0,
	"vnop_mmap",
	0,
	vnop_mmap_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	NULL
};


int vnop_mnomap_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_mnomap_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_mnomap_desc = {
	0,
	"vnop_mnomap",
	0,
	vnop_mnomap_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	NULL
};


int vnop_fsync_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_fsync_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_fsync_desc = {
	0,
	"vnop_fsync",
	0,
	vnop_fsync_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_fsync_args, a_context),
	NULL
};

int vnop_remove_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_remove_args,a_dvp),
	VOPARG_OFFSETOF(struct vnop_remove_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_remove_desc = {
	0,
	"vnop_remove",
	0 | VDESC_VP0_WILLRELE | VDESC_VP1_WILLRELE,
	vnop_remove_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_remove_args, a_cnp),
	VOPARG_OFFSETOF(struct vnop_remove_args, a_context),
	NULL
};

int vnop_remove_extended_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_remove_args,a_dvp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_compound_remove_desc = {
	0,
	"vnop_compound_remove",
	0,
	vnop_remove_vp_offsets,
	VOPARG_OFFSETOF(struct vnop_compound_remove_args, a_vpp),
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_remove_args, a_cnp),
	VOPARG_OFFSETOF(struct vnop_remove_args, a_context),
	NULL
};

int vnop_link_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_link_args,a_vp),
	VOPARG_OFFSETOF(struct vnop_link_args,a_tdvp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_link_desc = {
	0,
	"vnop_link",
	0 | VDESC_VP1_WILLRELE,
	vnop_link_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_link_args, a_cnp),
	VOPARG_OFFSETOF(struct vnop_link_args, a_context),
	NULL
};

int vnop_rename_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_rename_args,a_fdvp),
	VOPARG_OFFSETOF(struct vnop_rename_args,a_fvp),
	VOPARG_OFFSETOF(struct vnop_rename_args,a_tdvp),
	VOPARG_OFFSETOF(struct vnop_rename_args,a_tvp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_rename_desc = {
	0,
	"vnop_rename",
	0 | VDESC_VP0_WILLRELE | VDESC_VP1_WILLRELE | VDESC_VP2_WILLRELE | VDESC_VP3_WILLRELE,
	vnop_rename_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_rename_args, a_fcnp),
	VOPARG_OFFSETOF(struct vnop_rename_args, a_context),
	NULL
};

int vnop_compound_rename_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_compound_rename_args,a_fdvp),
	VOPARG_OFFSETOF(struct vnop_compound_rename_args,a_fvpp),
	VOPARG_OFFSETOF(struct vnop_compound_rename_args,a_tdvp),
	VOPARG_OFFSETOF(struct vnop_compound_rename_args,a_tvpp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_compound_rename_desc = {
	0,
	"vnop_compound_rename",
	0 | VDESC_VP0_WILLRELE | VDESC_VP1_WILLRELE | VDESC_VP2_WILLRELE | VDESC_VP3_WILLRELE,
	vnop_compound_rename_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_compound_rename_args, a_fcnp),
	VOPARG_OFFSETOF(struct vnop_compound_rename_args, a_context),
	NULL
};

int vnop_mkdir_vp_offsets[] = {
       VOPARG_OFFSETOF(struct vnop_mkdir_args,a_dvp),
       VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_mkdir_desc = {
       0,
       "vnop_mkdir",
       0 | VDESC_VP0_WILLRELE,
       vnop_mkdir_vp_offsets,
       VOPARG_OFFSETOF(struct vnop_mkdir_args, a_vpp),
       VDESC_NO_OFFSET,
       VDESC_NO_OFFSET,
       VOPARG_OFFSETOF(struct vnop_mkdir_args, a_cnp),
       VOPARG_OFFSETOF(struct vnop_mkdir_args, a_context),
       NULL
};

int vnop_compound_mkdir_vp_offsets[] = {
       VOPARG_OFFSETOF(struct vnop_compound_mkdir_args,a_dvp),
       VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_compound_mkdir_desc = {
       0,
       "vnop_compound_mkdir",
       0 | VDESC_VP0_WILLRELE,
       vnop_compound_mkdir_vp_offsets,
       VOPARG_OFFSETOF(struct vnop_compound_mkdir_args, a_vpp),
       VDESC_NO_OFFSET,
       VDESC_NO_OFFSET,
       VOPARG_OFFSETOF(struct vnop_compound_mkdir_args, a_cnp),
       VOPARG_OFFSETOF(struct vnop_compound_mkdir_args, a_context),
       NULL
};


int vnop_rmdir_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_rmdir_args,a_dvp),
	VOPARG_OFFSETOF(struct vnop_rmdir_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_rmdir_desc = {
	0,
	"vnop_rmdir",
	0 | VDESC_VP0_WILLRELE | VDESC_VP1_WILLRELE,
	vnop_rmdir_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_rmdir_args, a_cnp),
	VOPARG_OFFSETOF(struct vnop_rmdir_args, a_context),
	NULL
};

int vnop_compound_rmdir_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_compound_rmdir_args,a_dvp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_compound_rmdir_desc = {
	0,
	"vnop_compound_rmdir",
	0 | VDESC_VP0_WILLRELE | VDESC_VP1_WILLRELE,
	vnop_rmdir_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_compound_rmdir_args, a_cnp),
	VOPARG_OFFSETOF(struct vnop_compound_rmdir_args, a_context),
	NULL
};

int vnop_symlink_vp_offsets[] = {
       VOPARG_OFFSETOF(struct vnop_symlink_args,a_dvp),
       VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_symlink_desc = {
       0,
       "vnop_symlink",
       0 | VDESC_VP0_WILLRELE | VDESC_VPP_WILLRELE,
       vnop_symlink_vp_offsets,
       VOPARG_OFFSETOF(struct vnop_symlink_args, a_vpp),
       VDESC_NO_OFFSET,
       VDESC_NO_OFFSET,
       VOPARG_OFFSETOF(struct vnop_symlink_args, a_cnp),
       VOPARG_OFFSETOF(struct vnop_symlink_args, a_context),
       NULL
};

int vnop_readdir_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_readdir_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_readdir_desc = {
	0,
	"vnop_readdir",
	0,
	vnop_readdir_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_symlink_args, a_context),
	NULL
};

int vnop_readdirattr_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_readdirattr_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_readdirattr_desc = {
	0,
	"vnop_readdirattr",
	0,
	vnop_readdirattr_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_readdirattr_args, a_context),
	NULL
};

int vnop_getattrlistbulk_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_getattrlistbulk_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_getattrlistbulk_desc = {
	0,
	"vnop_getattrlistbulk",
	0,
	vnop_getattrlistbulk_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_getattrlistbulk_args, a_context),
	NULL
};

int vnop_readlink_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_readlink_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_readlink_desc = {
	0,
	"vnop_readlink",
	0,
	vnop_readlink_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_readlink_args, a_context),
	NULL
};

int vnop_inactive_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_inactive_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_inactive_desc = {
	0,
	"vnop_inactive",
	0,
	vnop_inactive_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_inactive_args, a_context),
	NULL
};

int vnop_reclaim_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_reclaim_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_reclaim_desc = {
	0,
	"vnop_reclaim",
	0,
	vnop_reclaim_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_reclaim_args, a_context),
	NULL
};

int vnop_pathconf_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_pathconf_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_pathconf_desc = {
	0,
	"vnop_pathconf",
	0,
	vnop_pathconf_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_pathconf_args, a_context),
	NULL
};

int vnop_advlock_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_advlock_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_advlock_desc = {
	0,
	"vnop_advlock",
	0,
	vnop_advlock_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_advlock_args, a_context),
	NULL
};

int vnop_allocate_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_allocate_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_allocate_desc = {
	0,
	"vnop_allocate",
	0,
	vnop_allocate_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_allocate_args, a_context),
	NULL
};

int vnop_pagein_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_pagein_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_pagein_desc = {
	0,
	"vnop_pagein",
	0,
	vnop_pagein_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_pagein_args, a_context),
	NULL
};

int vnop_pageout_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_pageout_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_pageout_desc = {
	0,
	"vnop_pageout",
	0,
	vnop_pageout_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_pageout_args, a_context),
	NULL
};

int vnop_searchfs_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_searchfs_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_searchfs_desc = {
	0,
	"vnop_searchfs",
	0,
	vnop_searchfs_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	NULL
};

int vnop_copyfile_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_copyfile_args,a_fvp),
	VOPARG_OFFSETOF(struct vnop_copyfile_args,a_tdvp),
	VOPARG_OFFSETOF(struct vnop_copyfile_args,a_tvp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_copyfile_desc = {
	0,
	"vnop_copyfile",
	0 | VDESC_VP0_WILLRELE | VDESC_VP1_WILLRELE | VDESC_VP2_WILLRELE,
	vnop_copyfile_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_copyfile_args, a_tcnp),
	VDESC_NO_OFFSET,
	NULL
};

int vop_getxattr_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_getxattr_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_getxattr_desc = {
	0,
	"vnop_getxattr",
	0,
	vop_getxattr_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_getxattr_args, a_context),
	NULL
};

int vop_setxattr_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_setxattr_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_setxattr_desc = {
	0,
	"vnop_setxattr",
	0,
	vop_setxattr_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_setxattr_args, a_context),
	NULL
};

int vop_removexattr_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_removexattr_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_removexattr_desc = {
	0,
	"vnop_removexattr",
	0,
	vop_removexattr_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_removexattr_args, a_context),
	NULL
};

int vop_listxattr_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_listxattr_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_listxattr_desc = {
	0,
	"vnop_listxattr",
	0,
	vop_listxattr_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_listxattr_args, a_context),
	NULL
};

int vnop_blktooff_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_blktooff_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_blktooff_desc = {
	0,
	"vnop_blktooff",
	0,
	vnop_blktooff_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	NULL
};

int vnop_offtoblk_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_offtoblk_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_offtoblk_desc = {
	0,
	"vnop_offtoblk",
	0,
	vnop_offtoblk_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	NULL
};

int vnop_blockmap_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_blockmap_args,a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_blockmap_desc = {
	0,
	"vnop_blockmap",
	0,
	vnop_blockmap_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	NULL
};

#if NAMEDSTREAMS
int vnop_getnamedstream_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_getnamedstream_args, a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_getnamedstream_desc = {
	0,
	"vnop_getnamedstream",
	0,
	vnop_getnamedstream_vp_offsets,
	VOPARG_OFFSETOF(struct vnop_getnamedstream_args, a_svpp),
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_getnamedstream_args, a_name),
	VOPARG_OFFSETOF(struct vnop_getnamedstream_args, a_context),
	NULL
};

int vnop_makenamedstream_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_makenamedstream_args, a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_makenamedstream_desc = {
	0,
	"vnop_makenamedstream",
	0, /* flags */
	vnop_makenamedstream_vp_offsets,
	VOPARG_OFFSETOF(struct vnop_makenamedstream_args, a_svpp),
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_makenamedstream_args, a_name),
	VOPARG_OFFSETOF(struct vnop_makenamedstream_args, a_context),
	NULL
};

int vnop_removenamedstream_vp_offsets[] = {
	VOPARG_OFFSETOF(struct vnop_removenamedstream_args, a_vp),
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_removenamedstream_desc = {
	0,
	"vnop_removenamedstream",
	0,
	vnop_removenamedstream_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VOPARG_OFFSETOF(struct vnop_removenamedstream_args, a_name),
	VOPARG_OFFSETOF(struct vnop_removenamedstream_args, a_context),
	NULL
};
#else
/* These symbols are in the exports list so they need to always be defined. */
int vnop_getnamedstream_desc;
int vnop_makenamedstream_desc;
int vnop_removenamedstream_desc;
#endif

/* Special cases: */

int vnop_strategy_vp_offsets[] = {
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_strategy_desc = {
	0,
	"vnop_strategy",
	0,
	vnop_strategy_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	NULL
};

int vnop_bwrite_vp_offsets[] = {
	VDESC_NO_OFFSET
};
struct vnodeop_desc vnop_bwrite_desc = {
	0,
	"vnop_bwrite",
	0,
	vnop_bwrite_vp_offsets,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	VDESC_NO_OFFSET,
	NULL
};

/* End of special cases. */

struct vnodeop_desc *vfs_op_descs[] = {
	&vnop_default_desc,	/* MUST BE FIRST */
	&vnop_strategy_desc,	/* XXX: SPECIAL CASE */
	&vnop_bwrite_desc,	/* XXX: SPECIAL CASE */

	&vnop_lookup_desc,
	&vnop_create_desc,
	&vnop_mknod_desc,
	&vnop_whiteout_desc,
	&vnop_open_desc,
	&vnop_compound_open_desc,
	&vnop_close_desc,
	&vnop_access_desc,
	&vnop_getattr_desc,
	&vnop_setattr_desc,
	&vnop_read_desc,
	&vnop_write_desc,
	&vnop_ioctl_desc,
	&vnop_select_desc,
	&vnop_exchange_desc,
	&vnop_kqfilt_add_desc,
	&vnop_kqfilt_remove_desc,
	&vnop_setlabel_desc,
	&vnop_revoke_desc,
	&vnop_mmap_desc,
	&vnop_mnomap_desc,
	&vnop_fsync_desc,
	&vnop_remove_desc,
	&vnop_compound_remove_desc,
	&vnop_link_desc,
	&vnop_rename_desc,
	&vnop_compound_rename_desc,
	&vnop_mkdir_desc,
	&vnop_compound_mkdir_desc,
	&vnop_rmdir_desc,
	&vnop_compound_rmdir_desc,
	&vnop_symlink_desc,
	&vnop_readdir_desc,
	&vnop_readdirattr_desc,
	&vnop_getattrlistbulk_desc,
	&vnop_readlink_desc,
	&vnop_inactive_desc,
	&vnop_reclaim_desc,
	&vnop_pathconf_desc,
	&vnop_advlock_desc,
	&vnop_allocate_desc,
	&vnop_pagein_desc,
	&vnop_pageout_desc,
	&vnop_searchfs_desc,
	&vnop_copyfile_desc,
	&vnop_getxattr_desc,
	&vnop_setxattr_desc,
	&vnop_removexattr_desc,
	&vnop_listxattr_desc,
	&vnop_blktooff_desc,
	&vnop_offtoblk_desc,
	&vnop_blockmap_desc,
	&vnop_monitor_desc,
#if NAMEDSTREAMS
	&vnop_getnamedstream_desc,
	&vnop_makenamedstream_desc,
	&vnop_removenamedstream_desc,
#endif
	NULL
};

