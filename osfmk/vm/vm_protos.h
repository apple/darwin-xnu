/*
 * Copyright (c) 2004-2007 Apple Inc. All rights reserved.
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

#ifdef	XNU_KERNEL_PRIVATE

#ifndef _VM_VM_PROTOS_H_
#define _VM_VM_PROTOS_H_

#include <mach/mach_types.h>
#include <kern/kern_types.h>

/*
 * This file contains various type definitions and routine prototypes
 * that are needed to avoid compilation warnings for VM code (in osfmk,
 * default_pager and bsd).
 * Most of these should eventually go into more appropriate header files.
 *
 * Include it after all other header files since it doesn't include any
 * type definitions and it works around some conflicts with other header
 * files.
 */

/*
 * iokit
 */
extern kern_return_t device_data_action(
	uintptr_t               device_handle, 
	ipc_port_t              device_pager,
	vm_prot_t               protection, 
	vm_object_offset_t      offset, 
	vm_size_t               size);

extern kern_return_t device_close(
	uintptr_t     device_handle);

/*
 * default_pager
 */
extern int start_def_pager(
	char *bs_device);
extern int default_pager_init_flag;

/*
 * osfmk
 */
#ifndef _IPC_IPC_PORT_H_
extern mach_port_name_t ipc_port_copyout_send(
	ipc_port_t	sright,
	ipc_space_t	space);
extern task_t port_name_to_task(
	mach_port_name_t name);
#endif /* _IPC_IPC_PORT_H_ */

extern ipc_space_t  get_task_ipcspace(
	task_t t);

/* Some loose-ends VM stuff */

extern vm_map_t		kalloc_map;
extern vm_size_t	msg_ool_size_small;
extern vm_map_t		zone_map;

extern void consider_machine_adjust(void);
extern pmap_t get_map_pmap(vm_map_t);
extern vm_map_offset_t get_map_min(vm_map_t);
extern vm_map_offset_t get_map_max(vm_map_t);
extern vm_map_size_t get_vmmap_size(vm_map_t);
extern int get_vmmap_entries(vm_map_t);

int vm_map_page_mask(vm_map_t);

extern boolean_t coredumpok(vm_map_t map, vm_offset_t va);

/*
 * VM routines that used to be published to
 * user space, and are now restricted to the kernel.
 *
 * They should eventually go away entirely -
 * to be replaced with standard vm_map() and
 * vm_deallocate() calls.
 */

extern kern_return_t vm_upl_map
(
	vm_map_t target_task,
	upl_t upl,
	vm_address_t *address
);

extern kern_return_t vm_upl_unmap
(
	vm_map_t target_task,
	upl_t upl
);

extern kern_return_t vm_region_object_create
(
	vm_map_t target_task,
	vm_size_t size,
	ipc_port_t *object_handle
);

extern mach_vm_offset_t mach_get_vm_start(vm_map_t);
extern mach_vm_offset_t mach_get_vm_end(vm_map_t);

#if CONFIG_CODE_DECRYPTION
struct pager_crypt_info;
extern kern_return_t vm_map_apple_protected(
					    vm_map_t	map,
					    vm_map_offset_t	start,
					    vm_map_offset_t	end,
					    struct pager_crypt_info *crypt_info);
extern void apple_protect_pager_bootstrap(void);
extern memory_object_t apple_protect_pager_setup(vm_object_t backing_object,
						 struct pager_crypt_info *crypt_info);
#endif	/* CONFIG_CODE_DECRYPTION */

struct vnode;
extern void swapfile_pager_bootstrap(void);
extern memory_object_t swapfile_pager_setup(struct vnode *vp);
extern memory_object_control_t swapfile_pager_control(memory_object_t mem_obj);


/*
 * bsd
 */
struct vnode;
extern void vnode_pager_shutdown(void);
extern void *upl_get_internal_page_list(
	upl_t upl);

extern void vnode_setswapmount(struct vnode *);

typedef int pager_return_t;
extern pager_return_t	vnode_pagein(
	struct vnode *, upl_t,
	upl_offset_t, vm_object_offset_t,
	upl_size_t, int, int *);
extern pager_return_t	vnode_pageout(
	struct vnode *, upl_t,
	upl_offset_t, vm_object_offset_t,
	upl_size_t, int, int *);
extern uint32_t vnode_trim (struct vnode *, int64_t offset, unsigned long len);
extern memory_object_t vnode_pager_setup(
	struct vnode *, memory_object_t);
extern vm_object_offset_t vnode_pager_get_filesize(
	struct vnode *);
extern uint32_t vnode_pager_isinuse(
	struct vnode *);
extern boolean_t vnode_pager_isSSD(
	struct vnode *);
extern void vnode_pager_throttle(
	void);
extern uint32_t vnode_pager_return_throttle_io_limit(
	struct vnode *,
	uint32_t     *);
extern kern_return_t vnode_pager_get_name(
	struct vnode	*vp,
	char		*pathname,
	vm_size_t	pathname_len,
	char		*filename,
	vm_size_t	filename_len,
	boolean_t	*truncated_path_p);
struct timespec;
extern kern_return_t vnode_pager_get_mtime(
	struct vnode	*vp,
	struct timespec	*mtime,
	struct timespec	*cs_mtime);
extern kern_return_t vnode_pager_get_cs_blobs(
	struct vnode	*vp,
	void		**blobs);

#if CONFIG_IOSCHED
void vnode_pager_issue_reprioritize_io(
	struct vnode 	*devvp, 
	uint64_t 	blkno, 
	uint32_t 	len,
	int 		priority);
#endif

#if CHECK_CS_VALIDATION_BITMAP	
/* used by the vnode_pager_cs_validation_bitmap routine*/
#define CS_BITMAP_SET	1
#define CS_BITMAP_CLEAR	2
#define CS_BITMAP_CHECK	3

#endif /* CHECK_CS_VALIDATION_BITMAP */

extern void vnode_pager_bootstrap(void);
extern kern_return_t
vnode_pager_data_unlock(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	memory_object_size_t		size,
	vm_prot_t		desired_access);
extern kern_return_t vnode_pager_init(
	memory_object_t, 
	memory_object_control_t, 
	memory_object_cluster_size_t);
extern kern_return_t vnode_pager_get_object_size(
	memory_object_t,
	memory_object_offset_t *);

#if CONFIG_IOSCHED
extern kern_return_t vnode_pager_get_object_devvp(
        memory_object_t,
        uintptr_t *);
#endif

extern kern_return_t vnode_pager_get_isinuse(
	memory_object_t,
	uint32_t *);
extern kern_return_t vnode_pager_get_isSSD(
	memory_object_t,
	boolean_t *);
extern kern_return_t vnode_pager_get_throttle_io_limit(
	memory_object_t,
	uint32_t *);
extern kern_return_t vnode_pager_get_object_name(
	memory_object_t	mem_obj,
	char		*pathname,
	vm_size_t	pathname_len,
	char		*filename,
	vm_size_t	filename_len,
	boolean_t	*truncated_path_p);
extern kern_return_t vnode_pager_get_object_mtime(
	memory_object_t	mem_obj,
	struct timespec *mtime,
	struct timespec	*cs_mtime);
extern kern_return_t vnode_pager_get_object_cs_blobs(
	memory_object_t	mem_obj,
	void		**blobs);

#if CHECK_CS_VALIDATION_BITMAP	
extern kern_return_t vnode_pager_cs_check_validation_bitmap( 
	memory_object_t	mem_obj, 
	memory_object_offset_t	offset,
	int		optype);
#endif /*CHECK_CS_VALIDATION_BITMAP*/

extern	kern_return_t ubc_cs_check_validation_bitmap (
	struct vnode *vp, 
	memory_object_offset_t offset,
	int optype);

extern kern_return_t vnode_pager_data_request( 
	memory_object_t, 
	memory_object_offset_t,
	memory_object_cluster_size_t,
	vm_prot_t,
	memory_object_fault_info_t);
extern kern_return_t vnode_pager_data_return(
	memory_object_t,
	memory_object_offset_t,
	memory_object_cluster_size_t,
	memory_object_offset_t *,
	int *,
	boolean_t,
	boolean_t,
	int);
extern kern_return_t vnode_pager_data_initialize(
	memory_object_t,
	memory_object_offset_t,
	memory_object_cluster_size_t);
extern void vnode_pager_reference(
	memory_object_t		mem_obj);
extern kern_return_t vnode_pager_synchronize(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	memory_object_size_t		length,
	vm_sync_t		sync_flags);
extern kern_return_t vnode_pager_map(
	memory_object_t		mem_obj,
	vm_prot_t		prot);
extern kern_return_t vnode_pager_last_unmap(
	memory_object_t		mem_obj);
extern void vnode_pager_deallocate(
	memory_object_t);
extern kern_return_t vnode_pager_terminate(
	memory_object_t);
extern void vnode_pager_vrele(
	struct vnode *vp);
extern void vnode_pager_release_from_cache(
	int	*);
extern int  ubc_map(
	struct vnode *vp,
	int flags);
extern void ubc_unmap(
	struct vnode *vp);

struct vm_map_entry;
extern struct vm_object *find_vnode_object(struct vm_map_entry *entry);

extern void   dp_memory_object_reference(memory_object_t);
extern void   dp_memory_object_deallocate(memory_object_t);
#ifndef _memory_object_server_
extern kern_return_t   dp_memory_object_init(memory_object_t,
					     memory_object_control_t,
					     memory_object_cluster_size_t);
extern	kern_return_t dp_memory_object_terminate(memory_object_t);
extern	kern_return_t   dp_memory_object_data_request(memory_object_t, 
						      memory_object_offset_t,
						      memory_object_cluster_size_t,
						      vm_prot_t,
						      memory_object_fault_info_t);
extern kern_return_t dp_memory_object_data_return(memory_object_t,
						    memory_object_offset_t,
						    memory_object_cluster_size_t,
						    memory_object_offset_t *,
						    int *,
						    boolean_t,
						    boolean_t,
						    int);
extern kern_return_t dp_memory_object_data_initialize(memory_object_t,
						      memory_object_offset_t,
						      memory_object_cluster_size_t);
extern kern_return_t dp_memory_object_data_unlock(memory_object_t,
						  memory_object_offset_t,
						  memory_object_size_t,
						  vm_prot_t);
extern kern_return_t dp_memory_object_synchronize(memory_object_t,
						  memory_object_offset_t,
						  memory_object_size_t,
						  vm_sync_t);
extern kern_return_t dp_memory_object_map(memory_object_t,
					  vm_prot_t);
extern kern_return_t dp_memory_object_last_unmap(memory_object_t);
#endif /* _memory_object_server_ */
#ifndef _memory_object_default_server_
extern kern_return_t default_pager_memory_object_create(
	memory_object_default_t,
	vm_size_t,
	memory_object_t *);
#endif /* _memory_object_default_server_ */

#if CONFIG_FREEZE
extern unsigned int default_pager_swap_pages_free(void);
struct default_freezer_handle;
struct vm_page;
__private_extern__ void	default_freezer_init(void);
__private_extern__ struct default_freezer_handle* default_freezer_handle_allocate(void);
__private_extern__ kern_return_t
default_freezer_handle_init(
	struct  default_freezer_handle *df_handle);
__private_extern__ void
default_freezer_handle_deallocate(
	struct default_freezer_handle *df_handle);
__private_extern__ void
default_freezer_pageout(
	struct default_freezer_handle *df_handle);
__private_extern__ kern_return_t
default_freezer_pack(
	unsigned int		*purgeable_count,
	unsigned int		*wired_count,
	unsigned int		*clean_count,
	unsigned int		*dirty_count,
	unsigned int		dirty_budget,
	boolean_t		*shared,
	vm_object_t		src_object,
	struct default_freezer_handle *df_handle);
__private_extern__ kern_return_t
default_freezer_unpack(
	struct default_freezer_handle *df_handle);	
__private_extern__ void
default_freezer_pack_page(
	struct vm_page* p,
	struct default_freezer_handle *df_handle);

#endif /* CONFIG_FREEZE */

extern void   device_pager_reference(memory_object_t);
extern void   device_pager_deallocate(memory_object_t);
extern kern_return_t   device_pager_init(memory_object_t,
					 memory_object_control_t,
					 memory_object_cluster_size_t);
extern	kern_return_t device_pager_terminate(memory_object_t);
extern	kern_return_t   device_pager_data_request(memory_object_t, 
						  memory_object_offset_t,
						  memory_object_cluster_size_t,
						  vm_prot_t,
						  memory_object_fault_info_t);
extern kern_return_t device_pager_data_return(memory_object_t,
					      memory_object_offset_t,
					      memory_object_cluster_size_t,
					      memory_object_offset_t *,
					      int *,
					      boolean_t,
					      boolean_t,
					      int);
extern kern_return_t device_pager_data_initialize(memory_object_t,
						  memory_object_offset_t,
						  memory_object_cluster_size_t);
extern kern_return_t device_pager_data_unlock(memory_object_t,
					      memory_object_offset_t,
					      memory_object_size_t,
					      vm_prot_t);
extern kern_return_t device_pager_synchronize(memory_object_t,
					      memory_object_offset_t,
					      memory_object_size_t,
					      vm_sync_t);
extern kern_return_t device_pager_map(memory_object_t, vm_prot_t);
extern kern_return_t device_pager_last_unmap(memory_object_t);
extern kern_return_t device_pager_populate_object(
	memory_object_t		device,
	memory_object_offset_t	offset,
	ppnum_t			page_num,
	vm_size_t		size);
extern memory_object_t device_pager_setup(
	memory_object_t,
	uintptr_t,
	vm_size_t,
	int);
extern void device_pager_bootstrap(void);

extern kern_return_t pager_map_to_phys_contiguous(
	memory_object_control_t	object,
	memory_object_offset_t	offset,
	addr64_t		base_vaddr,
	vm_size_t		size);

extern kern_return_t memory_object_create_named(
	memory_object_t	pager,
	memory_object_offset_t	size,
	memory_object_control_t		*control);

struct macx_triggers_args;
extern int mach_macx_triggers(
	struct macx_triggers_args	*args);

extern int macx_swapinfo(
	memory_object_size_t	*total_p,
	memory_object_size_t	*avail_p,
	vm_size_t		*pagesize_p,
	boolean_t		*encrypted_p);

extern void log_stack_execution_failure(addr64_t vaddr, vm_prot_t prot);
extern void log_unnest_badness(vm_map_t, vm_map_offset_t, vm_map_offset_t);

struct proc;
extern int cs_allow_invalid(struct proc *p);
extern int cs_invalid_page(addr64_t vaddr);

#define CS_VALIDATE_TAINTED	0x00000001
#define CS_VALIDATE_NX		0x00000002
extern boolean_t cs_validate_page(void *blobs,
				  memory_object_t pager,
				  memory_object_offset_t offset, 
				  const void *data,
				  unsigned *result);

extern kern_return_t mach_memory_entry_purgable_control(
	ipc_port_t	entry_port,
	vm_purgable_t	control,
	int		*state);

extern kern_return_t mach_memory_entry_get_page_counts(
	ipc_port_t	entry_port,
	unsigned int	*resident_page_count,
	unsigned int	*dirty_page_count);

extern kern_return_t mach_memory_entry_page_op(
	ipc_port_t		entry_port,
	vm_object_offset_t	offset,
	int			ops,
	ppnum_t			*phys_entry,
	int			*flags);

extern kern_return_t mach_memory_entry_range_op(
	ipc_port_t		entry_port,
	vm_object_offset_t	offset_beg,
	vm_object_offset_t	offset_end,
	int                     ops,
	int                     *range);

extern void mach_memory_entry_port_release(ipc_port_t port);
extern void mach_destroy_memory_entry(ipc_port_t port);
extern kern_return_t mach_memory_entry_allocate(
	struct vm_named_entry **user_entry_p,
	ipc_port_t *user_handle_p);

extern void vm_paging_map_init(void);

extern int macx_backing_store_compaction(int flags);
extern unsigned int mach_vm_ctl_page_free_wanted(void);

extern int no_paging_space_action(void);

#define VM_TOGGLE_CLEAR		0
#define VM_TOGGLE_SET		1
#define VM_TOGGLE_GETVALUE	999
int vm_toggle_entry_reuse(int, int*);

#define	SWAP_WRITE		0x00000000	/* Write buffer (pseudo flag). */
#define	SWAP_READ		0x00000001	/* Read buffer. */
#define	SWAP_ASYNC		0x00000002	/* Start I/O, do not wait. */

extern void vm_compressor_pager_init(void);
extern kern_return_t compressor_memory_object_create(
	memory_object_size_t,
	memory_object_t *);

#if CONFIG_JETSAM
extern int proc_get_memstat_priority(struct proc*, boolean_t);
#endif /* CONFIG_JETSAM */

/* the object purger. purges the next eligible object from memory. */
/* returns TRUE if an object was purged, otherwise FALSE. */
boolean_t vm_purgeable_object_purge_one_unlocked(int force_purge_below_group);
void vm_purgeable_disown(task_t task);

struct trim_list {
	uint64_t	tl_offset;
	uint64_t	tl_length;
	struct trim_list *tl_next;
};

u_int32_t vnode_trim_list(struct vnode *vp, struct trim_list *tl, boolean_t route_only);

#define MAX_SWAPFILENAME_LEN	1024
#define SWAPFILENAME_INDEX_LEN	2	/* Doesn't include the terminating NULL character */

extern char	swapfilename[MAX_SWAPFILENAME_LEN + 1];

struct vm_counters {
	unsigned int	do_collapse_compressor;
	unsigned int	do_collapse_compressor_pages;
	unsigned int	do_collapse_terminate;
	unsigned int	do_collapse_terminate_failure;
	unsigned int	should_cow_but_wired;
	unsigned int	create_upl_extra_cow;
	unsigned int	create_upl_extra_cow_pages;
	unsigned int	create_upl_lookup_failure_write;
	unsigned int	create_upl_lookup_failure_copy;
};
extern struct vm_counters vm_counters;

#endif	/* _VM_VM_PROTOS_H_ */

#endif	/* XNU_KERNEL_PRIVATE */
