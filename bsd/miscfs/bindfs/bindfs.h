/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

/*-
 * Portions Copyright (c) 1992, 1993
 *  The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software donated to Berkeley by
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
 *  @(#)null.h  8.3 (Berkeley) 8/20/94
 *
 * $FreeBSD$
 */

#ifndef FS_BIND_H
#define FS_BIND_H

#include <sys/appleapiopts.h>
#include <libkern/libkern.h>
#include <sys/vnode.h>
#include <sys/vnode_if.h>
#include <sys/ubc.h>
#include <vfs/vfs_support.h>
#include <sys/lock.h>

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/syslimits.h>

#if KERNEL
#include <libkern/tree.h>
#else
#include <System/libkern/tree.h>
#endif

//#define BINDFS_DEBUG 0

#define BINDM_CACHE 0x0001
#define BINDM_CASEINSENSITIVE 0x0000000000000002

typedef int (*vop_t)(void *);

struct bind_mount {
	struct vnode * bindm_rootvp;       /* Reference to root bind_node (inode 1) */
	struct vnode * bindm_lowerrootvp;  /* reference to the root of the tree we are
	                                    * relocating (in the other file system) */
	uint32_t bindm_lowerrootvid;       /* store the lower root vid so we can check
	                                    * before we build the shadow vnode lazily */
	uint64_t bindm_flags;
};

#ifdef KERNEL

#define BIND_FLAG_HASHED 0x000000001

/*
 * A cache of vnode references
 */
struct bind_node {
	LIST_ENTRY(bind_node) bind_hash; /* Hash list */
	struct vnode * bind_lowervp;     /* VREFed once */
	struct vnode * bind_vnode;       /* Back pointer */
	uint32_t bind_lowervid;          /* vid for lowervp to detect lowervp getting recycled out
	                                  *  from under us */
	uint32_t bind_myvid;
	uint32_t bind_flags;
};

struct vnodeop_desc_fake {
	int vdesc_offset;
	const char * vdesc_name;
	/* other stuff */
};

#define BINDV_NOUNLOCK 0x0001
#define BINDV_DROP 0x0002

#define MOUNTTOBINDMOUNT(mp) ((struct bind_mount *)(vfs_fsprivate(mp)))
#define VTOBIND(vp) ((struct bind_node *)vnode_fsnode(vp))
#define BINDTOV(xp) ((xp)->bind_vnode)

__BEGIN_DECLS

int bindfs_init(struct vfsconf * vfsp);
int bindfs_init_lck(lck_mtx_t * lck);
int bindfs_destroy_lck(lck_mtx_t * lck);
int bindfs_destroy(void);
int bind_nodeget(
	struct mount * mp, struct vnode * lowervp, struct vnode * dvp, struct vnode ** vpp, struct componentname * cnp, int root);
int bind_hashget(struct mount * mp, struct vnode * lowervp, struct vnode ** vpp);
int bind_getnewvnode(
	struct mount * mp, struct vnode * lowervp, struct vnode * dvp, struct vnode ** vpp, struct componentname * cnp, int root);
void bind_hashrem(struct bind_node * xp);

int bindfs_getbackingvnode(vnode_t in_vp, vnode_t* out_vpp);

#define BINDVPTOLOWERVP(vp) (VTOBIND(vp)->bind_lowervp)
#define BINDVPTOLOWERVID(vp) (VTOBIND(vp)->bind_lowervid)
#define BINDVPTOMYVID(vp) (VTOBIND(vp)->bind_myvid)

extern const struct vnodeopv_desc bindfs_vnodeop_opv_desc;

extern vop_t * bindfs_vnodeop_p;

__END_DECLS

#ifdef BINDFS_DEBUG
#define BINDFSDEBUG(format, args...) printf("DEBUG: BindFS %s: " format, __FUNCTION__, ##args)
#else
#define BINDFSDEBUG(format, args...)
#endif /* BINDFS_DEBUG */

#define BINDFSERROR(format, args...) printf("ERROR: BindFS %s: " format, __FUNCTION__, ##args)

#endif /* KERNEL */

#endif
