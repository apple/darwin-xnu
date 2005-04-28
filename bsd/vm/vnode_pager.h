/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 * Mach Operating System
 * Copyright (c) 1987 Carnegie-Mellon University
 * All rights reserved.  The CMU software License Agreement specifies
 * the terms and conditions for use and redistribution.
 */

#ifndef	_VNODE_PAGER_
#define	_VNODE_PAGER_	1

#include <mach/kern_return.h>
#include <sys/types.h>
#include <kern/queue.h>

#ifdef	KERNEL
#include <mach/boolean.h>
#include <mach/memory_object_types.h>
#include <mach/vm_types.h>
#include <vm/vm_pager.h>

vm_pager_t	vnode_pager_setup(struct vnode *, memory_object_t);

/*
 *  Vstructs are the internal (to us) description of a unit of backing store.
 *  The are the link between memory objects and the backing store they represent.
 *  For the vnode pager, backing store comes in two flavors: normal files and
 *  swap files.
 *
 *  For objects that page to and from normal files (e.g. objects that represent
 *  program text segments), we maintain some simple parameters that allow us to
 *  access the file's contents directly through the vnode interface.
 *
 *  Data for objects without associated vnodes is maintained in the swap files.
 *  Each object that uses one of these as backing store has a vstruct indicating
 *  the swap file of preference (vs_pf) and a mapping between contiguous object
 *  offsets and swap file offsets (vs_pmap).  Each entry in this mapping specifies
 *  the pager file to use, and the offset of the page in that pager file.  These
 *  mapping entries are of type pfMapEntry.
 */

/*
 * Pager file structure.  One per swap file.
 */
typedef struct pager_file {
	queue_chain_t	pf_chain;	/* link to other paging files */
	struct	vnode	*pf_vp;		/* vnode of paging file */
	u_int		pf_count;	/* Number of vstruct using this file */
	u_char		*pf_bmap; 	/* Map of used blocks */
	long		pf_npgs;	/* Size of file in pages */
	long		pf_pfree;	/* Number of unused pages */
	long		pf_lowat;	/* Low water page */
	long		pf_hipage;	/* Highest page allocated */
	long		pf_hint;	/* Lowest page unallocated */
	char		*pf_name;	/* Filename of this file */
	boolean_t	pf_prefer;
	int		pf_index;	/* index into the pager_file array */
	void *		pf_lock;	/* Lock for alloc and dealloc */
} *pager_file_t;

#define	PAGER_FILE_NULL	(pager_file_t) 0

#define	MAXPAGERFILES 16

#define MAX_BACKING_STORE 100

struct bs_map {
	struct vnode    *vp;   
	void     	*bs;
};
extern struct bs_map  bs_port_table[];



/*
 * Pager file data structures.
 */
#define	INDEX_NULL	0
typedef struct {
	unsigned int index:8;	/* paging file this block is in */
	unsigned int offset:24;	/* page number where block resides */
} pf_entry;

typedef enum {
		IS_INODE,	/* Local disk */
		IS_RNODE	/* NFS */
	} vpager_fstype;

/*
 *  Basic vnode pager structure.  One per object, backing-store pair.
 */
typedef struct vstruct {
	boolean_t	is_device;	/* Must be first - see vm_pager.h */
	pager_file_t	vs_pf;		/* Pager file this uses */
	pf_entry	**vs_pmap;	/* Map of pages into paging file */
	unsigned int
	/* boolean_t */	vs_swapfile:1;	/* vnode is a swapfile */
	short		vs_count;	/* use count */
	int		vs_size;	/* size of this chunk in pages*/
	struct vnode	*vs_vp;		/* vnode to page to */
} *vnode_pager_t;

#define	VNODE_PAGER_NULL	((vnode_pager_t) 0)


pager_return_t	vnode_pagein(struct vnode *, upl_t,
			     upl_offset_t, vm_object_offset_t,
			     upl_size_t, int, int *);
pager_return_t	vnode_pageout(struct vnode *, upl_t,
			      upl_offset_t, vm_object_offset_t,
			      upl_size_t, int, int *);

extern vm_object_offset_t vnode_pager_get_filesize(
	struct vnode *vp);

#endif	/* KERNEL */

#endif	/* _VNODE_PAGER_ */
