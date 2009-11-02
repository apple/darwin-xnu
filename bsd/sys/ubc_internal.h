/*
 * Copyright (c) 1999-2004 Apple Computer, Inc. All rights reserved.
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

#ifndef	_SYS_UBC_INTERNAL_H_
#define	_SYS_UBC_INTERNAL_H_

#include <sys/appleapiopts.h>
#include <sys/types.h>
#include <sys/kernel_types.h>
#include <sys/ucred.h>
#include <sys/vnode.h>
#include <sys/ubc.h>
#include <sys/mman.h>

#include <sys/cdefs.h>

#include <kern/locks.h>
#include <mach/memory_object_types.h>


#define UBC_INFO_NULL	((struct ubc_info *) 0)


extern struct zone	*ubc_info_zone;


#define MAX_CLUSTERS 4	/* maximum number of vfs clusters per vnode */

struct cl_extent {
	daddr64_t	b_addr;
	daddr64_t	e_addr;
};

struct cl_wextent {
	daddr64_t	b_addr;
	daddr64_t	e_addr;
        int		io_nocache;
};

struct cl_readahead {
	lck_mtx_t	cl_lockr;
	daddr64_t	cl_lastr;			/* last block read by client */
	daddr64_t	cl_maxra;			/* last block prefetched by the read ahead */
	int		cl_ralen;			/* length of last prefetch */
};

struct cl_writebehind {
	lck_mtx_t	cl_lockw;
        int		cl_hasbeenpaged;		/* if set, indicates pager has cleaned pages associated with this file */
        void	*	cl_scmap;			/* pointer to sparse cluster map */
        int		cl_scdirty;			/* number of dirty pages in the sparse cluster map */
	int		cl_number;			/* number of packed write behind clusters currently valid */
	struct cl_wextent cl_clusters[MAX_CLUSTERS];	/* packed write behind clusters */
};


/*
 *	The following data structure keeps the information to associate
 *	a vnode to the correspondig VM objects.
 */
struct ubc_info {
	memory_object_t			ui_pager;	/* pager */
	memory_object_control_t	ui_control;		/* VM control for the pager */
	long				ui_flags;	/* flags */
	vnode_t 			*ui_vnode;	/* The vnode for this ubc_info */
	ucred_t	 			*ui_ucred;	/* holds credentials for NFS paging */
	off_t				ui_size;	/* file size for the vnode */

        struct	cl_readahead   *cl_rahead;		/* cluster read ahead context */
        struct	cl_writebehind *cl_wbehind;		/* cluster write behind context */
};

/* Defines for ui_flags */
#define	UI_NONE			0x00000000		/* none */
#define	UI_HASPAGER		0x00000001		/* has a pager associated */
#define	UI_INITED		0x00000002		/* newly initialized vnode */
#define UI_HASOBJREF	0x00000004		/* hold a reference on object */
#define UI_WASMAPPED	0x00000008		/* vnode was mapped */
#define	UI_ISMAPPED	0x00000010		/* vnode is currently mapped */

/*
 * exported primitives for loadable file systems.
 */

__BEGIN_DECLS
__private_extern__ int	ubc_umount(struct mount *mp);
__private_extern__ void	ubc_unmountall(void);
__private_extern__ memory_object_t ubc_getpager(struct vnode *);
__private_extern__ int  ubc_map(struct vnode *, int);
__private_extern__ int	ubc_destroy_named(struct vnode *);

/* internal only */
__private_extern__ void	cluster_release(struct ubc_info *);


/* Flags for ubc_getobject() */
#define UBC_FLAGS_NONE		0x0000
#define UBC_HOLDOBJECT		0x0001
#define UBC_FOR_PAGEOUT         0x0002

memory_object_control_t ubc_getobject(struct vnode *, int);

int	ubc_info_init(struct vnode *);
void	ubc_info_deallocate (struct ubc_info *);

int	ubc_isinuse(struct vnode *, int);

int	ubc_page_op(vnode_t, off_t, int, ppnum_t *, int *);
int	ubc_range_op(vnode_t, off_t, off_t, int, int *);


int	cluster_copy_upl_data(struct uio *, upl_t, int, int);
int	cluster_copy_ubc_data(vnode_t, struct uio *, int *, int);


int UBCINFOMISSING(vnode_t);
int UBCINFORECLAIMED(vnode_t);
int UBCINFOEXISTS(vnode_t);
int UBCISVALID(vnode_t);
int UBCINVALID(vnode_t);
int UBCINFOCHECK(const char *, vnode_t);

__END_DECLS


#endif	/* _SYS_UBC_INTERNAL_H_ */

