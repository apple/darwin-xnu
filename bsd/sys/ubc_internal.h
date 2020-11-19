/*
 * Copyright (c) 1999-2020 Apple Inc. All rights reserved.
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
 *	File:	ubc.h
 *	Author:	Umesh Vaishampayan [umeshv@apple.com]
 *		05-Aug-1999	umeshv	Created.
 *
 *	Header file for Unified Buffer Cache.
 *
 */

#ifndef _SYS_UBC_INTERNAL_H_
#define _SYS_UBC_INTERNAL_H_

#include <sys/appleapiopts.h>
#include <sys/types.h>
#include <sys/kernel_types.h>
#include <sys/ucred.h>
#include <sys/vnode.h>
#include <sys/ubc.h>
#include <sys/mman.h>
#include <sys/codesign.h>

#include <sys/cdefs.h>

#include <kern/locks.h>
#include <mach/memory_object_types.h>

#include <libkern/ptrauth_utils.h>

#define UBC_INFO_NULL   ((struct ubc_info *) 0)


extern struct zone      *ubc_info_zone;

/*
 * Maximum number of vfs clusters per vnode
 */
#define MAX_CLUSTERS    CONFIG_MAX_CLUSTERS

#define SPARSE_PUSH_LIMIT 4     /* limit on number of concurrent sparse pushes outside of the cl_lockw */
                                /* once we reach this limit, we'll hold the lock */

struct cl_extent {
	daddr64_t       b_addr;
	daddr64_t       e_addr;
};

struct cl_wextent {
	daddr64_t       b_addr;
	daddr64_t       e_addr;
	int             io_flags;
};

struct cl_readahead {
	lck_mtx_t       cl_lockr;
	daddr64_t       cl_lastr;                       /* last block read by client */
	daddr64_t       cl_maxra;                       /* last block prefetched by the read ahead */
	int             cl_ralen;                       /* length of last prefetch */
};

struct cl_writebehind {
	lck_mtx_t       cl_lockw;
	void    *       cl_scmap;                       /* pointer to sparse cluster map */
	off_t           cl_last_write;                  /* offset of the end of the last write */
	off_t           cl_seq_written;                 /* sequentially written bytes */
	int             cl_sparse_pushes;               /* number of pushes outside of the cl_lockw in progress */
	int             cl_sparse_wait;                 /* synchronous push is in progress */
	int             cl_number;                      /* number of packed write behind clusters currently valid */
	struct cl_wextent cl_clusters[MAX_CLUSTERS];    /* packed write behind clusters */
};

struct cs_hash;

uint8_t cs_hash_type(struct cs_hash const *);

struct cs_blob {
	struct cs_blob  * XNU_PTRAUTH_SIGNED_PTR("cs_blob.csb_next") csb_next;
	cpu_type_t      csb_cpu_type;
	cpu_subtype_t   csb_cpu_subtype;
	unsigned int    csb_flags;
	off_t           csb_base_offset;        /* Offset of Mach-O binary in fat binary */
	off_t           csb_start_offset;       /* Blob coverage area start, from csb_base_offset */
	off_t           csb_end_offset;         /* Blob coverage area end, from csb_base_offset */
	vm_size_t       csb_mem_size;
	vm_offset_t     csb_mem_offset;
	vm_address_t    csb_mem_kaddr;
	unsigned char   csb_cdhash[CS_CDHASH_LEN];
	ptrauth_generic_signature_t csb_cdhash_signature;
	const struct cs_hash  *csb_hashtype;
#if CONFIG_SUPPLEMENTAL_SIGNATURES
	unsigned char   csb_linkage[CS_CDHASH_LEN];
	const struct cs_hash  *csb_linkage_hashtype;
#endif
	int             csb_hash_pageshift;
	int             csb_hash_firstlevel_pageshift;   /* First hash this many bytes, then hash the hashes together */
	const CS_CodeDirectory * XNU_PTRAUTH_SIGNED_PTR("cs_blob.csb_cd") csb_cd;
	const char      * XNU_PTRAUTH_SIGNED_PTR("cs_blob.csb_teamid") csb_teamid;
#if CONFIG_SUPPLEMENTAL_SIGNATURES
	char            * XNU_PTRAUTH_SIGNED_PTR("cs_blob.csb_supplement_teamid") csb_supplement_teamid;
#endif
	const CS_GenericBlob * XNU_PTRAUTH_SIGNED_PTR("cs_blob.csb_entitlements_blob") csb_entitlements_blob;    /* raw blob, subrange of csb_mem_kaddr */
	void *          XNU_PTRAUTH_SIGNED_PTR("cs_blob.csb_entitlements") csb_entitlements;       /* The entitlements as an OSDictionary */
	unsigned int    csb_signer_type;
	unsigned int    csb_reconstituted;      /* signature has potentially been modified after validation */
	/* The following two will be replaced by the csb_signer_type. */
	unsigned int    csb_platform_binary:1;
	unsigned int    csb_platform_path:1;

};

/*
 *	The following data structure keeps the information to associate
 *	a vnode to the correspondig VM objects.
 */
struct ubc_info {
	memory_object_t         ui_pager;       /* pager */
	memory_object_control_t ui_control;     /* VM control for the pager */
	vnode_t                 XNU_PTRAUTH_SIGNED_PTR("ubc_info.ui_vnode") ui_vnode;       /* vnode for this ubc_info */
	kauth_cred_t            ui_ucred;       /* holds credentials for NFS paging */
	off_t                   ui_size;        /* file size for the vnode */
	uint32_t                ui_flags;       /* flags */
	uint32_t                cs_add_gen;     /* generation count when csblob was validated */

	struct  cl_readahead   *cl_rahead;      /* cluster read ahead context */
	struct  cl_writebehind *cl_wbehind;     /* cluster write behind context */

	struct timespec         cs_mtime;       /* modify time of file when
	                                         *   first cs_blob was loaded */
	struct  cs_blob         * XNU_PTRAUTH_SIGNED_PTR("ubc_info.cs_blobs") cs_blobs; /* for CODE SIGNING */
#if CONFIG_SUPPLEMENTAL_SIGNATURES
	struct  cs_blob         * XNU_PTRAUTH_SIGNED_PTR("ubc_info.cs_blob_supplement") cs_blob_supplement;/* supplemental blob (note that there can only be one supplement) */
#endif
#if CHECK_CS_VALIDATION_BITMAP
	void                    * XNU_PTRAUTH_SIGNED_PTR("ubc_info.cs_valid_bitmap") cs_valid_bitmap;     /* right now: used only for signed files on the read-only root volume */
	uint64_t                cs_valid_bitmap_size; /* Save original bitmap size in case the file size changes.
	                                               * In the future, we may want to reconsider changing the
	                                               * underlying bitmap to reflect the new file size changes.
	                                               */
#endif /* CHECK_CS_VALIDATION_BITMAP */
};

/* Defines for ui_flags */
#define UI_NONE         0x00000000      /* none */
#define UI_HASPAGER     0x00000001      /* has a pager associated */
#define UI_INITED       0x00000002      /* newly initialized vnode */
#define UI_HASOBJREF    0x00000004      /* hold a reference on object */
#define UI_WASMAPPED    0x00000008      /* vnode was mapped */
#define UI_ISMAPPED     0x00000010      /* vnode is currently mapped */
#define UI_MAPBUSY      0x00000020      /* vnode is being mapped or unmapped */
#define UI_MAPWAITING   0x00000040      /* someone waiting for UI_MAPBUSY */
#define UI_MAPPEDWRITE  0x00000080      /* it's mapped with PROT_WRITE */

/*
 * exported primitives for loadable file systems.
 */

__BEGIN_DECLS

__private_extern__ int  ubc_umount(mount_t mp);
__private_extern__ void ubc_unmountall(void);
__private_extern__ memory_object_t ubc_getpager(vnode_t);
__private_extern__ void ubc_destroy_named(vnode_t);

/* internal only */
__private_extern__ void cluster_release(struct ubc_info *);
__private_extern__ uint32_t cluster_throttle_io_limit(vnode_t, uint32_t *);


/* Flags for ubc_getobject() */
#define UBC_FLAGS_NONE          0x0000
#define UBC_HOLDOBJECT          0x0001
#define UBC_FOR_PAGEOUT         0x0002

memory_object_control_t ubc_getobject(vnode_t, int);

int     ubc_info_init(vnode_t);
int     ubc_info_init_withsize(vnode_t, off_t);
void    ubc_info_deallocate(struct ubc_info *);

int     ubc_isinuse(vnode_t, int);
int     ubc_isinuse_locked(vnode_t, int, int);

int     ubc_getcdhash(vnode_t, off_t, unsigned char *);

#ifdef XNU_KERNEL_PRIVATE
int UBCINFOEXISTS(const struct vnode *);
#endif /* XNU_KERNEL_PRIVATE */

/* code signing */
struct cs_blob;
int     ubc_cs_blob_add(vnode_t, uint32_t, cpu_type_t, cpu_subtype_t, off_t, vm_address_t *, vm_size_t, struct image_params *, int, struct cs_blob **);
#if CONFIG_SUPPLEMENTAL_SIGNATURES
int     ubc_cs_blob_add_supplement(vnode_t, vnode_t, off_t, vm_address_t *, vm_size_t, struct cs_blob **);
#endif
struct cs_blob *ubc_get_cs_blobs(vnode_t);
#if CONFIG_SUPPLEMENTAL_SIGNATURES
struct cs_blob *ubc_get_cs_supplement(vnode_t);
#endif
void    ubc_get_cs_mtime(vnode_t, struct timespec *);
int     ubc_cs_getcdhash(vnode_t, off_t, unsigned char *);
kern_return_t ubc_cs_blob_allocate(vm_offset_t *, vm_size_t *);
void ubc_cs_blob_deallocate(vm_offset_t, vm_size_t);
boolean_t ubc_cs_is_range_codesigned(vnode_t, mach_vm_offset_t, mach_vm_size_t);

kern_return_t   ubc_cs_validation_bitmap_allocate( vnode_t );
void            ubc_cs_validation_bitmap_deallocate( vnode_t );
__END_DECLS


#endif  /* _SYS_UBC_INTERNAL_H_ */
