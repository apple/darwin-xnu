/*
 * Copyright (c) 2004-2006 Apple Computer, Inc. All rights reserved.
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
	int                     device_handle, 
	ipc_port_t              device_pager,
	vm_prot_t               protection, 
	vm_object_offset_t      offset, 
	vm_size_t               size);

extern kern_return_t device_close(
	int     device_handle);

/*
 * default_pager
 */
extern int start_def_pager(
	char *bs_device);
extern int default_pager_init_flag;

/*
 * osfmk
 */
#ifndef _KERN_IPC_TT_H_	/* XXX FBDP */
/* these should be exported cleanly from OSFMK since BSD needs them */
extern ipc_port_t convert_task_to_port(
	task_t		task);
extern ipc_port_t convert_task_name_to_port(
	task_name_t	task_name);
#endif /* _KERN_IPC_TT_H_ */
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

/*
 * Legacy routines to get the start and end for a vm_map_t.  They
 * return them in the vm_offset_t format.  So, they should only be
 * called on maps that are the same size as the kernel map for
 * accurate results.
 */
extern vm_offset_t get_vm_start(vm_map_t);
extern vm_offset_t get_vm_end(vm_map_t);

/*
 * LP64todo - map in the commpage cleanly and remove these.
 */
extern void vm_map_commpage64( vm_map_t );
extern void vm_map_remove_commpage( vm_map_t );
#ifdef __i386__
extern void vm_map_commpage32(vm_map_t);
extern kern_return_t vm_map_apple_protected(
	vm_map_t	map,
	vm_map_offset_t	start,
	vm_map_offset_t	end);
extern void apple_protect_pager_bootstrap(void);
extern memory_object_t apple_protect_pager_setup(vm_object_t backing_object);
extern void apple_protect_pager_map(memory_object_t mem_obj);
#endif	/* __i386__ */


/*
 * bsd
 */
struct vnode;
extern int is_suser(void);
extern int bsd_read_page_cache_file(
	unsigned int	user,
	int		*fid,
	int		*mod,
	char		*app_name,
	struct vnode	*app_vp,
	vm_offset_t	*buffer,
	vm_offset_t	*bufsize);
extern int bsd_write_page_cache_file(
	unsigned int	user,
	char	 	*file_name,
	caddr_t		buffer,
	vm_size_t	size,
	int		mod,
	int		fid);
extern int prepare_profile_database(
	int	user);
extern void vnode_pager_shutdown(void);
extern void *upl_get_internal_page_list(
	upl_t upl);
#ifndef _VNODE_PAGER_
typedef int pager_return_t;
extern pager_return_t	vnode_pagein(
	struct vnode *, upl_t,
	vm_offset_t, vm_object_offset_t,
	vm_size_t, int, int *);
extern pager_return_t	vnode_pageout(
	struct vnode *, upl_t,
	vm_offset_t, vm_object_offset_t,
	vm_size_t, int, int *);
extern memory_object_t vnode_pager_setup(
	struct vnode *, memory_object_t);
extern vm_object_offset_t vnode_pager_get_filesize(
	struct vnode *);
extern kern_return_t vnode_pager_get_pathname(
	struct vnode	*vp,
	char		*pathname,
	vm_size_t	*length_p);
extern kern_return_t vnode_pager_get_filename(
	struct vnode	*vp,
	char		**filename);
	
#endif /* _VNODE_PAGER_ */
extern void vnode_pager_bootstrap(void);
extern kern_return_t
vnode_pager_data_unlock(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	vm_size_t		size,
	vm_prot_t		desired_access);
extern kern_return_t vnode_pager_init(
	memory_object_t, 
	memory_object_control_t, 
	vm_size_t);
extern kern_return_t vnode_pager_get_object_size(
	memory_object_t,
	memory_object_offset_t *);
extern kern_return_t vnode_pager_get_object_pathname(
	memory_object_t	mem_obj,
	char		*pathname,
	vm_size_t	*length_p);
extern kern_return_t vnode_pager_get_object_filename(
	memory_object_t	mem_obj,
	char		**filename);
extern kern_return_t vnode_pager_data_request( 
	memory_object_t, 
	memory_object_offset_t, 
	vm_size_t, 
	vm_prot_t);
extern kern_return_t vnode_pager_data_return(
	memory_object_t,
	memory_object_offset_t,
	vm_size_t,
	memory_object_offset_t *,
	int *,
	boolean_t,
	boolean_t,
	int);
extern kern_return_t vnode_pager_data_initialize(
	memory_object_t,
	memory_object_offset_t,
	vm_size_t);
extern void vnode_pager_reference(
	memory_object_t		mem_obj);
extern kern_return_t vnode_pager_synchronize(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	vm_size_t		length,
	vm_sync_t		sync_flags);
extern kern_return_t vnode_pager_unmap(
	memory_object_t		mem_obj);
extern void vnode_pager_deallocate(
	memory_object_t);
extern kern_return_t vnode_pager_terminate(
	memory_object_t);
extern void vnode_pager_vrele(
	struct vnode *vp);
extern void vnode_pager_release_from_cache(
	int	*);
extern void ubc_unmap(
	struct vnode *vp);

extern void   dp_memory_object_reference(memory_object_t);
extern void   dp_memory_object_deallocate(memory_object_t);
#ifndef _memory_object_server_
extern kern_return_t   dp_memory_object_init(memory_object_t,
					     memory_object_control_t,
					     vm_size_t);
extern	kern_return_t dp_memory_object_terminate(memory_object_t);
extern	kern_return_t   dp_memory_object_data_request(memory_object_t, 
			memory_object_offset_t, vm_size_t, vm_prot_t);
extern kern_return_t dp_memory_object_data_return(memory_object_t,
						    memory_object_offset_t,
						    vm_size_t,
						    vm_size_t *,
						    int *,
						    boolean_t,
						    boolean_t,
						    int);
extern kern_return_t dp_memory_object_data_initialize(memory_object_t,
						      memory_object_offset_t,
						      vm_size_t);
extern kern_return_t dp_memory_object_data_unlock(memory_object_t,
						  memory_object_offset_t,
						  vm_size_t,
						  vm_prot_t);
extern kern_return_t dp_memory_object_synchronize(memory_object_t,
						  memory_object_offset_t,
						  vm_size_t,
						  vm_sync_t);
extern kern_return_t dp_memory_object_unmap(memory_object_t);
#endif /* _memory_object_server_ */
#ifndef _memory_object_default_server_
extern kern_return_t default_pager_memory_object_create(
	memory_object_default_t,
	vm_size_t,
	memory_object_t *);
#endif /* _memory_object_default_server_ */

extern void   device_pager_reference(memory_object_t);
extern void   device_pager_deallocate(memory_object_t);
extern kern_return_t   device_pager_init(memory_object_t,
					 memory_object_control_t,
					 vm_size_t);
extern	kern_return_t device_pager_terminate(memory_object_t);
extern	kern_return_t   device_pager_data_request(memory_object_t, 
						  memory_object_offset_t,
						  vm_size_t,
						  vm_prot_t);
extern kern_return_t device_pager_data_return(memory_object_t,
					      memory_object_offset_t,
					      vm_size_t,
					      memory_object_offset_t *,
					      int *,
					      boolean_t,
					      boolean_t,
					      int);
extern kern_return_t device_pager_data_initialize(memory_object_t,
						  memory_object_offset_t,
						  vm_size_t);
extern kern_return_t device_pager_data_unlock(memory_object_t,
					      memory_object_offset_t,
					      vm_size_t,
					      vm_prot_t);
extern kern_return_t device_pager_synchronize(memory_object_t,
					      memory_object_offset_t,
					      vm_size_t,
					      vm_sync_t);
extern kern_return_t device_pager_unmap(memory_object_t);
extern kern_return_t device_pager_populate_object(
	memory_object_t		device,
	memory_object_offset_t	offset,
	ppnum_t			page_num,
	vm_size_t		size);
extern memory_object_t device_pager_setup(
	memory_object_t,
	int,
	vm_size_t,
	int);
extern void device_pager_bootstrap(void);

extern kern_return_t memory_object_create_named(
	memory_object_t	pager,
	memory_object_offset_t	size,
	memory_object_control_t		*control);


extern int macx_swapinfo(
	memory_object_size_t	*total_p,
	memory_object_size_t	*avail_p,
	vm_size_t		*pagesize_p,
	boolean_t		*encrypted_p);

extern void log_nx_failure(addr64_t vaddr, vm_prot_t prot);

#endif	/* _VM_VM_PROTOS_H_ */

#endif	/* XNU_KERNEL_PRIVATE */
