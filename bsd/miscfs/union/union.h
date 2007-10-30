/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
/*
 * Copyright (c) 1994 The Regents of the University of California.
 * Copyright (c) 1994 Jan-Simon Pendry.
 * All rights reserved.
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
 *	@(#)union.h	8.9 (Berkeley) 12/10/94
 */
#ifndef __UNION_UNION_H__
#define __UNION_UNION_H__

#include  <sys/appleapiopts.h>
#include  <sys/cdefs.h>

#ifdef __APPLE_API_PRIVATE
struct union_args {
	char		*target;	/* Target of loopback  */
	int		mntflags;	/* Options on the mount */
};

#define UNMNT_ABOVE	0x0001		/* Target appears above mount point */
#define UNMNT_BELOW	0x0002		/* Target appears below mount point */
#define UNMNT_REPLACE	0x0003		/* Target replaces mount point */
#ifdef FAULTFS
#define UNMNT_FAULTIN	0x0004		/* get the files to TOT on lookup */
#define UNMNT_OPMASK	0x0007
#else
#define UNMNT_OPMASK	0x0003
#endif

#ifdef BSD_KERNEL_PRIVATE

struct union_mount {
	struct vnode	*um_uppervp;	/* */
	int		um_uppervid;	/* vid of upper vnode */
	struct vnode	*um_lowervp;	/* Left unlocked */
	int		um_lowervid;	/* vid of lower vnode */
	kauth_cred_t	um_cred;	/* Credentials of user calling mount */
	int		um_cmode;	/* cmask from mount process */
	int		um_op;		/* Operation mode */
	dev_t		um_upperdev;	/* Upper root node fsid[0]*/
};


#define  UNION_ABOVE(x) (x->um_op == UNMNT_ABOVE)
#define  UNION_LOWER(x) (x->um_op == UNMNT_BELOW)
#define  UNION_REPLACE(x) (x->um_op == UNMNT_REPLACE)
#ifdef FAULTFS
#define  UNION_FAULTIN(x) (x->um_op == UNMNT_FAULTIN)
#else
#define  UNION_FAULTIN(x) (0)

#endif

/* LP64 version of union_args.  all pointers 
 * grow when we're dealing with a 64-bit process.
 * WARNING - keep in sync with union_args
 */

struct user_union_args {
	user_addr_t	target;		/* Target of loopback  */
	int			mntflags;	/* Options on the mount */
	char		_pad[4];
};

/*
 * DEFDIRMODE is the mode bits used to create a shadow directory.
 */
#define VRWXMODE (VREAD|VWRITE|VEXEC)
#define VRWMODE (VREAD|VWRITE)
#define UN_DIRMODE ((VRWXMODE)|(VRWXMODE>>3)|(VRWXMODE>>6))
#define UN_FILEMODE ((VRWMODE)|(VRWMODE>>3)|(VRWMODE>>6))

/*
 * A cache of vnode references
 */
struct union_node {
	LIST_ENTRY(union_node)	un_cache;	/* Hash chain */
	struct vnode		*un_vnode;	/* Back pointer */

	struct vnode	        *un_uppervp;	/* overlaying object */
	int			un_uppervid;	/* vid of upper vnode */
	off_t			un_uppersz;	/* size of upper object */

	struct vnode	        *un_lowervp;	/* underlying object */
	int			un_lowervid;	/* vid of upper vnode */
	off_t			un_lowersz;	/* size of lower object */

	struct vnode		*un_dirvp;	/* Parent dir of uppervp */
	struct vnode		*un_pvp;	/* Parent vnode */

	char			*un_path;	/* saved component name */
	int			un_hash;	/* saved un_path hash value */
	int			un_openl;	/* # of opens on lowervp */
	int			un_exclcnt;	/* exclusive count */
	unsigned int		un_flags;
	mount_t			un_mount;
	struct vnode		**un_dircache;	/* cached union stack */
};

#define UN_WANT		0x01		/* union node is needed */
#define UN_LOCKED	0x02		/* union node is locked */
#define UN_CACHED	0x04		/* In union cache */
#define UN_TRANSIT	0x08		/* The union node is in creation */
#define UN_DELETED	0x10		/* The union node is deleted  */
#ifdef FAULTFS
#define UN_FAULTFS	0x80		/* The union node is for faultfs */
#endif
#define UN_DIRENVN	0x100		/* The union node is created for dir enumeration */


#ifdef FAULTFS
#define  UNNODE_FAULTIN(x) ((x->un_flags & UN_FAULTFS)== UN_FAULTFS)
#else
#define  UNNODE_FAULTIN(x) (0)
#endif
/*
 * Hash table locking flags
 */

#define UNVP_WANT	0x01
#define UNVP_LOCKED	0x02

#define	MOUNTTOUNIONMOUNT(mp) ((struct union_mount *)((mp)->mnt_data))
#define	VTOUNION(vp) ((struct union_node *)(vp)->v_data)
#define	UNIONTOV(un) ((un)->un_vnode)
#define	LOWERVP(vp) (VTOUNION(vp)->un_lowervp)
#define	UPPERVP(vp) (VTOUNION(vp)->un_uppervp)
#define OTHERVP(vp) (UPPERVP(vp) ? UPPERVP(vp) : LOWERVP(vp))


extern int union_allocvp(struct vnode **, struct mount *,
				struct vnode *, struct vnode *,
				struct componentname *, struct vnode *,
				struct vnode *, int);
extern int union_freevp(struct vnode *);
extern struct vnode * union_dircache(struct vnode *, vfs_context_t);
extern int union_copyfile(struct vnode *, struct vnode *,vfs_context_t );
extern int union_copyup(struct union_node *, int, vfs_context_t );
extern int union_dowhiteout(struct union_node *, vfs_context_t);
extern int union_mkshadow(struct union_mount *, struct vnode *,
				struct componentname *, struct vnode **);
extern int union_mkwhiteout(struct union_mount *, struct vnode *,
				struct componentname *, char *);
extern int union_vn_create(struct vnode **, struct union_node *, mode_t  mode, vfs_context_t context);
extern int union_cn_close(struct vnode *, int, vfs_context_t context);
extern void union_removed_upper(struct union_node *un);
extern struct vnode *union_lowervp(struct vnode *);
extern void union_newsize(struct vnode *, off_t, off_t);
extern int union_init(struct vfsconf *);
extern void union_updatevp(struct union_node *, struct vnode *, struct vnode *);
extern void union_dircache_free(struct union_node *);
extern int (*union_dircheckp)(struct vnode **, struct fileproc *, vfs_context_t);
extern int union_faultin_copyup(struct vnode ** uvpp, vnode_t udvp, vnode_t lvp, struct componentname * cnp, vfs_context_t context);
extern int (**union_vnodeop_p)(void *);
extern struct vfsops union_vfsops;
void union_lock(void);
void union_unlock(void);

#endif /* BSD_KERNEL_PRIVATE */

#endif /* __APPLE_API_PRIVATE */

#endif /* __UNION_UNION_H__ */
