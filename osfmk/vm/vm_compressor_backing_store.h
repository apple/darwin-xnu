/*
 * Copyright (c) 2000-2013 Apple Inc. All rights reserved.
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

#include <kern/kern_types.h>
#include <kern/locks.h>
#include <kern/kalloc.h>
#include <vm/vm_kern.h>
#include <mach/kern_return.h>
#include <kern/queue.h>
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>
#include <vm/vm_compressor.h>
#include <libkern/crypto/aes.h>
#include <kern/host_statistics.h>


#define SANITY_CHECK_SWAP_ROUTINES	0

#if SANITY_CHECK_SWAP_ROUTINES

#define MIN_SWAP_FILE_SIZE		(4 * 1024)

#define MAX_SWAP_FILE_SIZE		(4 * 1024)

#define	COMPRESSED_SWAP_CHUNK_SIZE	(4 * 1024)

#define VM_SWAPFILE_HIWATER_SEGS	(MIN_SWAP_FILE_SIZE / COMPRESSED_SWAP_CHUNK_SIZE)

#define SWAPFILE_RECLAIM_THRESHOLD_SEGS	(MIN_SWAP_FILE_SIZE / COMPRESSED_SWAP_CHUNK_SIZE)

#else /* SANITY_CHECK_SWAP_ROUTINES */


#define MIN_SWAP_FILE_SIZE		(256 * 1024 * 1024)

#define MAX_SWAP_FILE_SIZE		(1 * 1024 * 1024 * 1024)


#define	COMPRESSED_SWAP_CHUNK_SIZE	(C_SEG_BUFSIZE)

#define VM_SWAPFILE_HIWATER_SEGS	(MIN_SWAP_FILE_SIZE / COMPRESSED_SWAP_CHUNK_SIZE)

#define SWAPFILE_RECLAIM_THRESHOLD_SEGS	((15 * (MAX_SWAP_FILE_SIZE / COMPRESSED_SWAP_CHUNK_SIZE)) / 10)

#endif /* SANITY_CHECK_SWAP_ROUTINES */

#define SWAP_FILE_NAME		"/var/vm/swapfile"
#define SWAPFILENAME_LEN	(int)(strlen(SWAP_FILE_NAME))
#define SWAPFILENAME_INDEX_LEN	2	/* Doesn't include the terminating NULL character */

#define SWAP_SLOT_MASK		0x1FFFFFFFF
#define SWAP_DEVICE_SHIFT	33

extern int		vm_num_swap_files;
extern boolean_t	vm_swap_up;

struct swapfile;
lck_grp_attr_t	vm_swap_data_lock_grp_attr;
lck_grp_t	vm_swap_data_lock_grp;
lck_attr_t	vm_swap_data_lock_attr;
lck_mtx_ext_t	vm_swap_data_lock_ext;
lck_mtx_t	vm_swap_data_lock;

void vm_swap_init(void);
boolean_t vm_swap_create_file(void);
kern_return_t vm_swap_put(vm_offset_t, uint64_t*, uint64_t, c_segment_t);
void vm_swap_flush(void);
void vm_swap_reclaim(void);
void vm_swap_encrypt(c_segment_t);
uint64_t vm_swap_get_total_space(void);
uint64_t vm_swap_get_used_space(void);
uint64_t vm_swap_get_free_space(void);

struct vnode;
extern void vm_swapfile_open(const char *path, struct vnode **vp);
extern void vm_swapfile_close(uint64_t path, struct vnode *vp);
extern int vm_swapfile_preallocate(struct vnode *vp, uint64_t *size);
extern uint64_t vm_swapfile_get_blksize(struct vnode *vp);
extern uint64_t vm_swapfile_get_transfer_size(struct vnode *vp);
extern int vm_swapfile_io(struct vnode *vp, uint64_t offset, uint64_t start, int npages, int flags);


