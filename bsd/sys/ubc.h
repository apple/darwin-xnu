/*
 * Copyright (c) 1999, 2000-2002 Apple Computer, Inc. All rights reserved.
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
 *	File:	ubc.h
 *	Author:	Umesh Vaishampayan [umeshv@apple.com]
 *		05-Aug-1999	umeshv	Created.
 *
 *	Header file for Unified Buffer Cache.
 *
 */ 

#ifndef	_SYS_UBC_H_
#define	_SYS_UBC_H_

#include <sys/appleapiopts.h>
#include <sys/types.h>
#include <sys/ucred.h>
#include <sys/vnode.h>

#include <sys/cdefs.h>

#include <mach/memory_object_types.h>

#define UBC_INFO_NULL	((struct ubc_info *) 0)
#define UBC_NOINFO		((struct ubc_info *)0xDEADD1ED)

#ifdef __APPLE_API_PRIVATE
extern struct zone	*ubc_info_zone;

/*
 *	The following data structure keeps the information to associate
 *	a vnode to the correspondig VM objects.
 */

struct ubc_info {
	memory_object_t			ui_pager;	/* pager */
	memory_object_control_t	ui_control;	/* VM control for the pager */
	long					ui_flags;	/* flags */
	struct vnode 			*ui_vnode;	/* The vnode for this ubc_info */
	struct ucred 			*ui_ucred;	/* holds credentials for NFS paging */
	int						ui_refcount;/* ref count on the ubc_info */
	off_t					ui_size;	/* file size for the vnode */
	long					ui_mapped;	/* is it currently mapped */
};

/* Defines for ui_flags */
#define	UI_NONE			0x00000000		/* none */
#define	UI_HASPAGER		0x00000001		/* has a pager associated */
#define	UI_INITED		0x00000002		/* newly initialized vnode */
#define UI_HASOBJREF	0x00000004		/* hold a reference on object */
#define UI_WASMAPPED	0x00000008		/* vnode was mapped */
#define	UI_DONTCACHE	0x00000010		/* do not cache object */

#endif /* __APPLE_API_PRIVATE */

#ifdef __APPLE_API_EVOLVING
/*
 * exported primitives for loadable file systems.
 */

__BEGIN_DECLS
int	ubc_info_init __P((struct vnode *));
void	ubc_info_deallocate  __P((struct ubc_info *));
int	ubc_setsize __P((struct vnode *, off_t));
off_t	ubc_getsize __P((struct vnode *));
int	ubc_uncache __P((struct vnode *));
int	ubc_umount __P((struct mount *));
void	ubc_unmountall __P(());
int	ubc_setcred __P((struct vnode *, struct proc *));
struct ucred *ubc_getcred __P((struct vnode *));
memory_object_t ubc_getpager __P((struct vnode *));
memory_object_control_t ubc_getobject __P((struct vnode *, int));
int ubc_setpager __P((struct vnode *, memory_object_t));
int ubc_setflags __P((struct vnode *, int));
int ubc_clearflags __P((struct vnode *, int));
int ubc_issetflags __P((struct vnode *, int));
off_t ubc_blktooff __P((struct vnode *, daddr_t));
daddr_t ubc_offtoblk __P((struct vnode *, off_t));
int ubc_clean __P((struct vnode *, int));
int	ubc_pushdirty __P((struct vnode *));
int	ubc_pushdirty_range __P((struct vnode *, off_t, off_t));
int ubc_hold __P((struct vnode *));
void ubc_rele __P((struct vnode *));
void ubc_map __P((struct vnode *));
int	ubc_destroy_named __P((struct vnode *));
int	ubc_release_named __P((struct vnode *));
int	ubc_invalidate __P((struct vnode *, off_t, size_t));
int	ubc_isinuse __P((struct vnode *, int));

int	ubc_page_op __P((struct vnode *, off_t, int, vm_offset_t *, int *));

/* cluster IO routines */
int	cluster_read __P((struct vnode *, struct uio *, off_t, int, int));
int	advisory_read __P((struct vnode *, off_t, off_t, int, int));
int	cluster_write __P((struct vnode *, struct uio*, off_t, off_t,
		off_t, off_t,  int, int));
int	cluster_push __P((struct vnode *));
int	cluster_pageout __P((struct vnode *, upl_t, vm_offset_t, off_t, int,
		off_t, int, int));
int	cluster_pagein __P((struct vnode *, upl_t, vm_offset_t, off_t, int,
		off_t, int, int));
int	cluster_bp __P((struct buf *));

/* UPL routines */
int	ubc_create_upl __P((struct vnode *, off_t, long, upl_t *,
		upl_page_info_t **, int));
int ubc_upl_map __P((upl_t, vm_offset_t *));
int ubc_upl_unmap __P((upl_t));
int ubc_upl_commit __P((upl_t));
int ubc_upl_commit_range __P((upl_t, vm_offset_t, vm_size_t, int));
int ubc_upl_abort __P((upl_t, int));
int ubc_upl_abort_range __P((upl_t, vm_offset_t, vm_size_t, int));
upl_page_info_t *ubc_upl_pageinfo __P((upl_t));
__END_DECLS

#define UBCINFOMISSING(vp) \
	((vp) && ((vp)->v_type == VREG) && ((vp)->v_ubcinfo == UBC_INFO_NULL))

#define UBCINFORECLAIMED(vp) \
	((vp) && ((vp)->v_type == VREG) && ((vp)->v_ubcinfo == UBC_NOINFO))

#define UBCINFOEXISTS(vp) \
	((vp) && ((vp)->v_type == VREG) && \
		((vp)->v_ubcinfo) && ((vp)->v_ubcinfo != UBC_NOINFO))

#define UBCISVALID(vp) \
	((vp) && ((vp)->v_type == VREG) && !((vp)->v_flag & VSYSTEM))

#define UBCINVALID(vp) \
	(((vp) == NULL) || ((vp) && ((vp)->v_type != VREG))     \
		|| ((vp) && ((vp)->v_flag & VSYSTEM)))

#define UBCINFOCHECK(fun, vp)  \
	if ((vp) && ((vp)->v_type == VREG) &&   \
			(((vp)->v_ubcinfo == UBC_INFO_NULL)     \
			|| ((vp)->v_ubcinfo == UBC_NOINFO))) \
		panic("%s: lost ubc_info", (fun));

/* Flags for ubc_getobject() */
#define UBC_FLAGS_NONE		0x0000
#define UBC_HOLDOBJECT		0x0001

#endif /* __APPLE_API_EVOLVING */

#endif	/* _SYS_UBC_H_ */

