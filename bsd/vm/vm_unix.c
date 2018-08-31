/*
 * Copyright (c) 2000-2018 Apple Inc. All rights reserved.
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
 * Mach Operating System
 * Copyright (c) 1987 Carnegie-Mellon University
 * All rights reserved.  The CMU software License Agreement specifies
 * the terms and conditions for use and redistribution.
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2006 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
#include <vm/vm_options.h>

#include <kern/task.h>
#include <kern/thread.h>
#include <kern/debug.h>
#include <kern/extmod_statistics.h>
#include <mach/mach_traps.h>
#include <mach/port.h>
#include <mach/sdt.h>
#include <mach/task.h>
#include <mach/task_access.h>
#include <mach/task_special_ports.h>
#include <mach/time_value.h>
#include <mach/vm_map.h>
#include <mach/vm_param.h>
#include <mach/vm_prot.h>

#include <sys/file_internal.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/dir.h>
#include <sys/namei.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/vm.h>
#include <sys/file.h>
#include <sys/vnode_internal.h>
#include <sys/mount.h>
#include <sys/trace.h>
#include <sys/kernel.h>
#include <sys/ubc_internal.h>
#include <sys/user.h>
#include <sys/syslog.h>
#include <sys/stat.h>
#include <sys/sysproto.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/cprotect.h>
#include <sys/kpi_socket.h>
#include <sys/kas_info.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#if NECP
#include <net/necp.h>
#endif /* NECP */

#include <security/audit/audit.h>
#include <security/mac.h>
#include <bsm/audit_kevents.h>

#include <kern/kalloc.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_pageout.h>

#include <mach/shared_region.h>
#include <vm/vm_shared_region.h>

#include <vm/vm_protos.h>

#include <sys/kern_memorystatus.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

int _shared_region_map_and_slide(struct proc*, int, unsigned int, struct shared_file_mapping_np*, uint32_t, user_addr_t, user_addr_t);
int shared_region_copyin_mappings(struct proc*, user_addr_t, unsigned int, struct shared_file_mapping_np *);

#if VM_MAP_DEBUG_APPLE_PROTECT
SYSCTL_INT(_vm, OID_AUTO, map_debug_apple_protect, CTLFLAG_RW | CTLFLAG_LOCKED, &vm_map_debug_apple_protect, 0, "");
#endif /* VM_MAP_DEBUG_APPLE_PROTECT */

#if VM_MAP_DEBUG_FOURK
SYSCTL_INT(_vm, OID_AUTO, map_debug_fourk, CTLFLAG_RW | CTLFLAG_LOCKED, &vm_map_debug_fourk, 0, "");
#endif /* VM_MAP_DEBUG_FOURK */

#if DEVELOPMENT || DEBUG

static int
sysctl_kmem_alloc_contig SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	vm_offset_t	kaddr;
	kern_return_t	kr;
	int	error = 0;
	int	size = 0;

	error = sysctl_handle_int(oidp, &size, 0, req);
	if (error || !req->newptr)
		return (error);

	kr = kmem_alloc_contig(kernel_map, &kaddr, (vm_size_t)size, 0, 0, 0, 0, VM_KERN_MEMORY_IOKIT);

	if (kr == KERN_SUCCESS)
		kmem_free(kernel_map, kaddr, size);

	return error;
}

SYSCTL_PROC(_vm, OID_AUTO, kmem_alloc_contig, CTLTYPE_INT|CTLFLAG_WR|CTLFLAG_LOCKED|CTLFLAG_MASKED,
	    0, 0, &sysctl_kmem_alloc_contig, "I", "");

extern int vm_region_footprint;
SYSCTL_INT(_vm, OID_AUTO, region_footprint, CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_LOCKED, &vm_region_footprint, 0, "");
static int
sysctl_vm_self_region_footprint SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	int	error = 0;
	int	value;

	value = task_self_region_footprint();
	error = SYSCTL_OUT(req, &value, sizeof (int));
	if (error) {
		return error;
	}

	if (!req->newptr) {
		return 0;
	}

	error = SYSCTL_IN(req, &value, sizeof (int));
	if (error) {
		return (error);
	}
	task_self_region_footprint_set(value);
	return 0;
}
SYSCTL_PROC(_vm, OID_AUTO, self_region_footprint, CTLTYPE_INT|CTLFLAG_RW|CTLFLAG_ANYBODY|CTLFLAG_LOCKED|CTLFLAG_MASKED, 0, 0, &sysctl_vm_self_region_footprint, "I", "");

#endif /* DEVELOPMENT || DEBUG */


#if CONFIG_EMBEDDED

#if DEVELOPMENT || DEBUG
extern int panic_on_unsigned_execute;
SYSCTL_INT(_vm, OID_AUTO, panic_on_unsigned_execute, CTLFLAG_RW | CTLFLAG_LOCKED, &panic_on_unsigned_execute, 0, "");
#endif /* DEVELOPMENT || DEBUG */

extern int log_executable_mem_entry;
extern int cs_executable_create_upl;
extern int cs_executable_mem_entry;
extern int cs_executable_wire;
SYSCTL_INT(_vm, OID_AUTO, log_executable_mem_entry, CTLFLAG_RD | CTLFLAG_LOCKED, &log_executable_mem_entry, 0, "");
SYSCTL_INT(_vm, OID_AUTO, cs_executable_create_upl, CTLFLAG_RD | CTLFLAG_LOCKED, &cs_executable_create_upl, 0, "");
SYSCTL_INT(_vm, OID_AUTO, cs_executable_mem_entry, CTLFLAG_RD | CTLFLAG_LOCKED, &cs_executable_mem_entry, 0, "");
SYSCTL_INT(_vm, OID_AUTO, cs_executable_wire, CTLFLAG_RD | CTLFLAG_LOCKED, &cs_executable_wire, 0, "");
#endif /* CONFIG_EMBEDDED */

#if DEVELOPMENT || DEBUG
extern int radar_20146450;
SYSCTL_INT(_vm, OID_AUTO, radar_20146450, CTLFLAG_RW | CTLFLAG_LOCKED, &radar_20146450, 0, "");

extern int macho_printf;
SYSCTL_INT(_vm, OID_AUTO, macho_printf, CTLFLAG_RW | CTLFLAG_LOCKED, &macho_printf, 0, "");

extern int apple_protect_pager_data_request_debug;
SYSCTL_INT(_vm, OID_AUTO, apple_protect_pager_data_request_debug, CTLFLAG_RW | CTLFLAG_LOCKED, &apple_protect_pager_data_request_debug, 0, "");

#if __arm__ || __arm64__
/* These are meant to support the page table accounting unit test. */
extern unsigned int arm_hardware_page_size;
extern unsigned int arm_pt_desc_size;
extern unsigned int arm_pt_root_size;
extern unsigned int free_page_size_tt_count;
extern unsigned int free_two_page_size_tt_count;
extern unsigned int free_tt_count;
extern unsigned int inuse_user_tteroot_count;
extern unsigned int inuse_kernel_tteroot_count;
extern unsigned int inuse_user_ttepages_count;
extern unsigned int inuse_kernel_ttepages_count;
extern unsigned int inuse_user_ptepages_count;
extern unsigned int inuse_kernel_ptepages_count;
SYSCTL_UINT(_vm, OID_AUTO, native_hw_pagesize, CTLFLAG_RD | CTLFLAG_LOCKED, &arm_hardware_page_size, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, arm_pt_desc_size, CTLFLAG_RD | CTLFLAG_LOCKED, &arm_pt_desc_size, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, arm_pt_root_size, CTLFLAG_RD | CTLFLAG_LOCKED, &arm_pt_root_size, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, free_1page_tte_root, CTLFLAG_RD | CTLFLAG_LOCKED, &free_page_size_tt_count, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, free_2page_tte_root, CTLFLAG_RD | CTLFLAG_LOCKED, &free_two_page_size_tt_count, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, free_tte_root, CTLFLAG_RD | CTLFLAG_LOCKED, &free_tt_count, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, user_tte_root, CTLFLAG_RD | CTLFLAG_LOCKED, &inuse_user_tteroot_count, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, kernel_tte_root, CTLFLAG_RD | CTLFLAG_LOCKED, &inuse_kernel_tteroot_count, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, user_tte_pages, CTLFLAG_RD | CTLFLAG_LOCKED, &inuse_user_ttepages_count, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, kernel_tte_pages, CTLFLAG_RD | CTLFLAG_LOCKED, &inuse_kernel_ttepages_count, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, user_pte_pages, CTLFLAG_RD | CTLFLAG_LOCKED, &inuse_user_ptepages_count, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, kernel_pte_pages, CTLFLAG_RD | CTLFLAG_LOCKED, &inuse_kernel_ptepages_count, 0, "");
#endif /* __arm__ || __arm64__ */

#if __arm64__
extern int fourk_pager_data_request_debug;
SYSCTL_INT(_vm, OID_AUTO, fourk_pager_data_request_debug, CTLFLAG_RW | CTLFLAG_LOCKED, &fourk_pager_data_request_debug, 0, "");
#endif /* __arm64__ */
#endif /* DEVELOPMENT || DEBUG */

SYSCTL_INT(_vm, OID_AUTO, vm_do_collapse_compressor, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_counters.do_collapse_compressor, 0, "");
SYSCTL_INT(_vm, OID_AUTO, vm_do_collapse_compressor_pages, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_counters.do_collapse_compressor_pages, 0, "");
SYSCTL_INT(_vm, OID_AUTO, vm_do_collapse_terminate, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_counters.do_collapse_terminate, 0, "");
SYSCTL_INT(_vm, OID_AUTO, vm_do_collapse_terminate_failure, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_counters.do_collapse_terminate_failure, 0, "");
SYSCTL_INT(_vm, OID_AUTO, vm_should_cow_but_wired, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_counters.should_cow_but_wired, 0, "");
SYSCTL_INT(_vm, OID_AUTO, vm_create_upl_extra_cow, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_counters.create_upl_extra_cow, 0, "");
SYSCTL_INT(_vm, OID_AUTO, vm_create_upl_extra_cow_pages, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_counters.create_upl_extra_cow_pages, 0, "");
SYSCTL_INT(_vm, OID_AUTO, vm_create_upl_lookup_failure_write, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_counters.create_upl_lookup_failure_write, 0, "");
SYSCTL_INT(_vm, OID_AUTO, vm_create_upl_lookup_failure_copy, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_counters.create_upl_lookup_failure_copy, 0, "");
#if VM_SCAN_FOR_SHADOW_CHAIN
static int vm_shadow_max_enabled = 0;    /* Disabled by default */
extern int proc_shadow_max(void);
static int
vm_shadow_max SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	int value = 0;

	if (vm_shadow_max_enabled)
		value = proc_shadow_max();

	return SYSCTL_OUT(req, &value, sizeof(value));
}
SYSCTL_PROC(_vm, OID_AUTO, vm_shadow_max, CTLTYPE_INT|CTLFLAG_RD|CTLFLAG_LOCKED,
    0, 0, &vm_shadow_max, "I", "");

SYSCTL_INT(_vm, OID_AUTO, vm_shadow_max_enabled, CTLFLAG_RW | CTLFLAG_LOCKED, &vm_shadow_max_enabled, 0, "");

#endif /* VM_SCAN_FOR_SHADOW_CHAIN */

SYSCTL_INT(_vm, OID_AUTO, vm_debug_events, CTLFLAG_RW | CTLFLAG_LOCKED, &vm_debug_events, 0, "");

__attribute__((noinline)) int __KERNEL_WAITING_ON_TASKGATED_CHECK_ACCESS_UPCALL__(
	mach_port_t task_access_port, int32_t calling_pid, uint32_t calling_gid, int32_t target_pid);
/*
 * Sysctl's related to data/stack execution.  See osfmk/vm/vm_map.c
 */

#if DEVELOPMENT || DEBUG
extern int allow_stack_exec, allow_data_exec;

SYSCTL_INT(_vm, OID_AUTO, allow_stack_exec, CTLFLAG_RW | CTLFLAG_LOCKED, &allow_stack_exec, 0, "");
SYSCTL_INT(_vm, OID_AUTO, allow_data_exec, CTLFLAG_RW | CTLFLAG_LOCKED, &allow_data_exec, 0, "");

#if __arm64__
extern int fourk_binary_compatibility_unsafe;
extern int fourk_binary_compatibility_allow_wx;
SYSCTL_INT(_vm, OID_AUTO, fourk_binary_compatibility_unsafe, CTLFLAG_RW | CTLFLAG_LOCKED, &fourk_binary_compatibility_unsafe, 0, "");
SYSCTL_INT(_vm, OID_AUTO, fourk_binary_compatibility_allow_wx, CTLFLAG_RW | CTLFLAG_LOCKED, &fourk_binary_compatibility_allow_wx, 0, "");
#endif /* __arm64__ */
#endif /* DEVELOPMENT || DEBUG */

static const char *prot_values[] = {
	"none",
	"read-only",
	"write-only",
	"read-write",
	"execute-only",
	"read-execute",
	"write-execute",
	"read-write-execute"
};

void
log_stack_execution_failure(addr64_t vaddr, vm_prot_t prot)
{
	printf("Data/Stack execution not permitted: %s[pid %d] at virtual address 0x%qx, protections were %s\n", 
		current_proc()->p_comm, current_proc()->p_pid, vaddr, prot_values[prot & VM_PROT_ALL]);
}

/*
 * shared_region_unnest_logging: level of logging of unnesting events
 * 0	- no logging
 * 1	- throttled logging of unexpected unnesting events (default)
 * 2	- unthrottled logging of unexpected unnesting events
 * 3+	- unthrottled logging of all unnesting events
 */
int shared_region_unnest_logging = 1;

SYSCTL_INT(_vm, OID_AUTO, shared_region_unnest_logging, CTLFLAG_RW | CTLFLAG_LOCKED,
	   &shared_region_unnest_logging, 0, "");

int vm_shared_region_unnest_log_interval = 10;
int shared_region_unnest_log_count_threshold = 5;

/*
 * Shared cache path enforcement.
 */

#ifndef CONFIG_EMBEDDED
static int scdir_enforce = 1;
static char scdir_path[] = "/var/db/dyld/";
#else
static int scdir_enforce = 0;
static char scdir_path[] = "/System/Library/Caches/com.apple.dyld/";
#endif

#ifndef SECURE_KERNEL
SYSCTL_INT(_vm, OID_AUTO, enforce_shared_cache_dir, CTLFLAG_RW | CTLFLAG_LOCKED, &scdir_enforce, 0, "");
#endif

/* These log rate throttling state variables aren't thread safe, but
 * are sufficient unto the task.
 */
static int64_t last_unnest_log_time = 0; 
static int shared_region_unnest_log_count = 0;

void
log_unnest_badness(
	vm_map_t	m,
	vm_map_offset_t s,
	vm_map_offset_t e,
	boolean_t	is_nested_map,
	vm_map_offset_t	lowest_unnestable_addr)
{
	struct timeval	tv;

	if (shared_region_unnest_logging == 0)
		return;

	if (shared_region_unnest_logging <= 2 &&
	    is_nested_map &&
	    s >= lowest_unnestable_addr) {
		/*
		 * Unnesting of writable map entries is fine.
		 */
		return;
	}

	if (shared_region_unnest_logging <= 1) {
		microtime(&tv);
		if ((tv.tv_sec - last_unnest_log_time) <
		    vm_shared_region_unnest_log_interval) {
			if (shared_region_unnest_log_count++ >
			    shared_region_unnest_log_count_threshold)
				return;
		} else {
			last_unnest_log_time = tv.tv_sec;
			shared_region_unnest_log_count = 0;
		}
	}

	DTRACE_VM4(log_unnest_badness,
		   vm_map_t, m,
		   vm_map_offset_t, s,
		   vm_map_offset_t, e,
		   vm_map_offset_t, lowest_unnestable_addr);
	printf("%s[%d] triggered unnest of range 0x%qx->0x%qx of DYLD shared region in VM map %p. While not abnormal for debuggers, this increases system memory footprint until the target exits.\n", current_proc()->p_comm, current_proc()->p_pid, (uint64_t)s, (uint64_t)e, (void *) VM_KERNEL_ADDRPERM(m));
}

int
useracc(
	user_addr_t	addr,
	user_size_t	len,
	int	prot)
{
	vm_map_t	map;

	map = current_map();
	return (vm_map_check_protection(
			map,
			vm_map_trunc_page(addr,
					  vm_map_page_mask(map)),
			vm_map_round_page(addr+len,
					  vm_map_page_mask(map)),
			prot == B_READ ? VM_PROT_READ : VM_PROT_WRITE));
}

int
vslock(
	user_addr_t	addr,
	user_size_t	len)
{
	kern_return_t	kret;
	vm_map_t	map;

	map = current_map();
	kret = vm_map_wire_kernel(map,
			   vm_map_trunc_page(addr,
					     vm_map_page_mask(map)),
			   vm_map_round_page(addr+len,
					     vm_map_page_mask(map)), 
			   VM_PROT_READ | VM_PROT_WRITE, VM_KERN_MEMORY_BSD,
			   FALSE);

	switch (kret) {
	case KERN_SUCCESS:
		return (0);
	case KERN_INVALID_ADDRESS:
	case KERN_NO_SPACE:
		return (ENOMEM);
	case KERN_PROTECTION_FAILURE:
		return (EACCES);
	default:
		return (EINVAL);
	}
}

int
vsunlock(
	user_addr_t addr,
	user_size_t len,
	__unused int dirtied)
{
#if FIXME  /* [ */
	pmap_t		pmap;
	vm_page_t	pg;
	vm_map_offset_t	vaddr;
	ppnum_t		paddr;
#endif  /* FIXME ] */
	kern_return_t	kret;
	vm_map_t	map;

	map = current_map();

#if FIXME  /* [ */
	if (dirtied) {
		pmap = get_task_pmap(current_task());
		for (vaddr = vm_map_trunc_page(addr, PAGE_MASK);
		     vaddr < vm_map_round_page(addr+len, PAGE_MASK);
		     vaddr += PAGE_SIZE) {
			paddr = pmap_extract(pmap, vaddr);
			pg = PHYS_TO_VM_PAGE(paddr);
			vm_page_set_modified(pg);
		}
	}
#endif  /* FIXME ] */
#ifdef	lint
	dirtied++;
#endif	/* lint */
	kret = vm_map_unwire(map,
			     vm_map_trunc_page(addr,
					       vm_map_page_mask(map)),
			     vm_map_round_page(addr+len,
					       vm_map_page_mask(map)),
			     FALSE);
	switch (kret) {
	case KERN_SUCCESS:
		return (0);
	case KERN_INVALID_ADDRESS:
	case KERN_NO_SPACE:
		return (ENOMEM);
	case KERN_PROTECTION_FAILURE:
		return (EACCES);
	default:
		return (EINVAL);
	}
}

int
subyte(
	user_addr_t addr,
	int byte)
{
	char character;
	
	character = (char)byte;
	return (copyout((void *)&(character), addr, sizeof(char)) == 0 ? 0 : -1);
}

int
suibyte(
	user_addr_t addr,
	int byte)
{
	char character;
	
	character = (char)byte;
	return (copyout((void *)&(character), addr, sizeof(char)) == 0 ? 0 : -1);
}

int fubyte(user_addr_t addr)
{
	unsigned char byte;

	if (copyin(addr, (void *) &byte, sizeof(char)))
		return(-1);
	return(byte);
}

int fuibyte(user_addr_t addr)
{
	unsigned char byte;

	if (copyin(addr, (void *) &(byte), sizeof(char)))
		return(-1);
	return(byte);
}

int
suword(
	user_addr_t addr,
	long word)
{
	return (copyout((void *) &word, addr, sizeof(int)) == 0 ? 0 : -1);
}

long fuword(user_addr_t addr)
{
	long word = 0;

	if (copyin(addr, (void *) &word, sizeof(int)))
		return(-1);
	return(word);
}

/* suiword and fuiword are the same as suword and fuword, respectively */

int
suiword(
	user_addr_t addr,
	long word)
{
	return (copyout((void *) &word, addr, sizeof(int)) == 0 ? 0 : -1);
}

long fuiword(user_addr_t addr)
{
	long word = 0;

	if (copyin(addr, (void *) &word, sizeof(int)))
		return(-1);
	return(word);
}

/*
 * With a 32-bit kernel and mixed 32/64-bit user tasks, this interface allows the
 * fetching and setting of process-sized size_t and pointer values.
 */
int
sulong(user_addr_t addr, int64_t word)
{

	if (IS_64BIT_PROCESS(current_proc())) {
		return(copyout((void *)&word, addr, sizeof(word)) == 0 ? 0 : -1);
	} else {
		return(suiword(addr, (long)word));
	}
}

int64_t
fulong(user_addr_t addr)
{
	int64_t longword;

	if (IS_64BIT_PROCESS(current_proc())) {
		if (copyin(addr, (void *)&longword, sizeof(longword)) != 0)
			return(-1);
		return(longword);
	} else {
		return((int64_t)fuiword(addr));
	}
}

int
suulong(user_addr_t addr, uint64_t uword)
{

	if (IS_64BIT_PROCESS(current_proc())) {
		return(copyout((void *)&uword, addr, sizeof(uword)) == 0 ? 0 : -1);
	} else {
		return(suiword(addr, (uint32_t)uword));
	}
}

uint64_t
fuulong(user_addr_t addr)
{
	uint64_t ulongword;

	if (IS_64BIT_PROCESS(current_proc())) {
		if (copyin(addr, (void *)&ulongword, sizeof(ulongword)) != 0)
			return(-1ULL);
		return(ulongword);
	} else {
		return((uint64_t)fuiword(addr));
	}
}

int
swapon(__unused proc_t procp, __unused struct swapon_args *uap, __unused int *retval)
{
	return(ENOTSUP);
}

/*
 * pid_for_task
 *
 * Find the BSD process ID for the Mach task associated with the given Mach port 
 * name
 *
 * Parameters:	args		User argument descriptor (see below)
 *
 * Indirect parameters:	args->t		Mach port name
 * 			args->pid	Process ID (returned value; see below)
 *
 * Returns:	KERL_SUCCESS	Success
 * 		KERN_FAILURE	Not success           
 *
 * Implicit returns: args->pid		Process ID
 *
 */
kern_return_t
pid_for_task(
	struct pid_for_task_args *args)
{
	mach_port_name_t	t = args->t;
	user_addr_t		pid_addr  = args->pid;  
	proc_t p;
	task_t		t1;
	int	pid = -1;
	kern_return_t	err = KERN_SUCCESS;

	AUDIT_MACH_SYSCALL_ENTER(AUE_PIDFORTASK);
	AUDIT_ARG(mach_port1, t);

	t1 = port_name_to_task_inspect(t);

	if (t1 == TASK_NULL) {
		err = KERN_FAILURE;
		goto pftout;
	} else {
		p = get_bsdtask_info(t1);
		if (p) {
			pid  = proc_pid(p);
			err = KERN_SUCCESS;
		} else if (is_corpsetask(t1)) {
			pid = task_pid(t1);
			err = KERN_SUCCESS;
		}else {
			err = KERN_FAILURE;
		}
	}
	task_deallocate(t1);
pftout:
	AUDIT_ARG(pid, pid);
	(void) copyout((char *) &pid, pid_addr, sizeof(int));
	AUDIT_MACH_SYSCALL_EXIT(err);
	return(err);
}

/* 
 *
 * tfp_policy = KERN_TFP_POLICY_DENY; Deny Mode: None allowed except for self
 * tfp_policy = KERN_TFP_POLICY_DEFAULT; default mode: all posix checks and upcall via task port for authentication
 *
 */
static  int tfp_policy = KERN_TFP_POLICY_DEFAULT;

/*
 *	Routine:	task_for_pid_posix_check
 *	Purpose:
 *			Verify that the current process should be allowed to
 *			get the target process's task port. This is only 
 *			permitted if:
 *			- The current process is root
 *			OR all of the following are true:
 *			- The target process's real, effective, and saved uids
 *			  are the same as the current proc's euid,
 *			- The target process's group set is a subset of the
 *			  calling process's group set, and
 *			- The target process hasn't switched credentials.
 *
 *	Returns:	TRUE: permitted
 *			FALSE: denied
 */
static int
task_for_pid_posix_check(proc_t target)
{
	kauth_cred_t targetcred, mycred;
	uid_t myuid;
	int allowed; 

	/* No task_for_pid on bad targets */
	if (target->p_stat == SZOMB) {
		return FALSE;
	}

	mycred = kauth_cred_get();
	myuid = kauth_cred_getuid(mycred);

	/* If we're running as root, the check passes */
	if (kauth_cred_issuser(mycred))
		return TRUE;

	/* We're allowed to get our own task port */
	if (target == current_proc())
		return TRUE;

	/* 
	 * Under DENY, only root can get another proc's task port,
	 * so no more checks are needed.
	 */
	if (tfp_policy == KERN_TFP_POLICY_DENY) { 
		return FALSE;
	}

	targetcred = kauth_cred_proc_ref(target);
	allowed = TRUE;

	/* Do target's ruid, euid, and saved uid match my euid? */
	if ((kauth_cred_getuid(targetcred) != myuid) || 
			(kauth_cred_getruid(targetcred) != myuid) ||
			(kauth_cred_getsvuid(targetcred) != myuid)) {
		allowed = FALSE;
		goto out;
	}

	/* Are target's groups a subset of my groups? */
	if (kauth_cred_gid_subset(targetcred, mycred, &allowed) ||
			allowed == 0) {
		allowed = FALSE;
		goto out;
	}

	/* Has target switched credentials? */
	if (target->p_flag & P_SUGID) {
		allowed = FALSE;
		goto out;
	}
	
out:
	kauth_cred_unref(&targetcred);
	return allowed;
}

/*
 *	__KERNEL_WAITING_ON_TASKGATED_CHECK_ACCESS_UPCALL__
 *
 *	Description:	Waits for the user space daemon to respond to the request
 *			we made. Function declared non inline to be visible in
 *			stackshots and spindumps as well as debugging.
 */
__attribute__((noinline)) int __KERNEL_WAITING_ON_TASKGATED_CHECK_ACCESS_UPCALL__(
	mach_port_t task_access_port, int32_t calling_pid, uint32_t calling_gid, int32_t target_pid)
{
	return check_task_access(task_access_port, calling_pid, calling_gid, target_pid);
}

/*
 *	Routine:	task_for_pid
 *	Purpose:
 *		Get the task port for another "process", named by its
 *		process ID on the same host as "target_task".
 *
 *		Only permitted to privileged processes, or processes
 *		with the same user ID.
 *
 *		Note: if pid == 0, an error is return no matter who is calling.
 *
 * XXX This should be a BSD system call, not a Mach trap!!!
 */
kern_return_t
task_for_pid(
	struct task_for_pid_args *args)
{
	mach_port_name_t	target_tport = args->target_tport;
	int			pid = args->pid;
	user_addr_t		task_addr = args->t;
	proc_t 			p = PROC_NULL;
	task_t			t1 = TASK_NULL;
	task_t			task = TASK_NULL;
	mach_port_name_t	tret = MACH_PORT_NULL;
	ipc_port_t 		tfpport = MACH_PORT_NULL;
	void * sright;
	int error = 0;

	AUDIT_MACH_SYSCALL_ENTER(AUE_TASKFORPID);
	AUDIT_ARG(pid, pid);
	AUDIT_ARG(mach_port1, target_tport);

	/* Always check if pid == 0 */
	if (pid == 0) {
		(void ) copyout((char *)&t1, task_addr, sizeof(mach_port_name_t));
		AUDIT_MACH_SYSCALL_EXIT(KERN_FAILURE);
		return(KERN_FAILURE);
	}

	t1 = port_name_to_task(target_tport);
	if (t1 == TASK_NULL) {
		(void) copyout((char *)&t1, task_addr, sizeof(mach_port_name_t));
		AUDIT_MACH_SYSCALL_EXIT(KERN_FAILURE);
		return(KERN_FAILURE);
	} 


	p = proc_find(pid);
	if (p == PROC_NULL) {
		error = KERN_FAILURE;
		goto tfpout;
	}

#if CONFIG_AUDIT
	AUDIT_ARG(process, p);
#endif

	if (!(task_for_pid_posix_check(p))) {
		error = KERN_FAILURE;
		goto tfpout;
	}

	if (p->task == TASK_NULL) {
		error = KERN_SUCCESS;
		goto tfpout;
	}

#if CONFIG_MACF
	error = mac_proc_check_get_task(kauth_cred_get(), p);
	if (error) {
		error = KERN_FAILURE;
		goto tfpout;
	}
#endif

	/* Grab a task reference since the proc ref might be dropped if an upcall to task access server is made */
	task = p->task;
	task_reference(task);

	/* If we aren't root and target's task access port is set... */
	if (!kauth_cred_issuser(kauth_cred_get()) &&
		p != current_proc() &&
		(task_get_task_access_port(task, &tfpport) == 0) &&
		(tfpport != IPC_PORT_NULL)) {

		if (tfpport == IPC_PORT_DEAD) {
			error = KERN_PROTECTION_FAILURE;
			goto tfpout;
		}

		/*
		 * Drop the proc_find proc ref before making an upcall
		 * to taskgated, since holding a proc_find
		 * ref while making an upcall can cause deadlock.
		 */
		proc_rele(p);
		p = PROC_NULL;

		/* Call up to the task access server */
		error = __KERNEL_WAITING_ON_TASKGATED_CHECK_ACCESS_UPCALL__(tfpport, proc_selfpid(), kauth_getgid(), pid);

		if (error != MACH_MSG_SUCCESS) {
			if (error == MACH_RCV_INTERRUPTED)
				error = KERN_ABORTED;
			else
				error = KERN_FAILURE;
			goto tfpout;
		}
	}

	/* Grant task port access */
	extmod_statistics_incr_task_for_pid(task);
	sright = (void *) convert_task_to_port(task);

	/* Check if the task has been corpsified */
	if (is_corpsetask(task)) {
		/* task ref consumed by convert_task_to_port */
		task = TASK_NULL;
		ipc_port_release_send(sright);
		error = KERN_FAILURE;
		goto tfpout;
	}

	/* task ref consumed by convert_task_to_port */
	task = TASK_NULL;
	tret = ipc_port_copyout_send(
			sright,
			get_task_ipcspace(current_task()));

	error = KERN_SUCCESS;

tfpout:
	task_deallocate(t1);
	AUDIT_ARG(mach_port2, tret);
	(void) copyout((char *) &tret, task_addr, sizeof(mach_port_name_t));

	if (tfpport != IPC_PORT_NULL) {
		ipc_port_release_send(tfpport);
	}
	if (task != TASK_NULL) {
		task_deallocate(task);
	}
	if (p != PROC_NULL)
		proc_rele(p);
	AUDIT_MACH_SYSCALL_EXIT(error);
	return(error);
}

/*
 *	Routine:	task_name_for_pid
 *	Purpose:
 *		Get the task name port for another "process", named by its
 *		process ID on the same host as "target_task".
 *
 *		Only permitted to privileged processes, or processes
 *		with the same user ID.
 *
 * XXX This should be a BSD system call, not a Mach trap!!!
 */

kern_return_t
task_name_for_pid(
	struct task_name_for_pid_args *args)
{
	mach_port_name_t	target_tport = args->target_tport;
	int			pid = args->pid;
	user_addr_t		task_addr = args->t;
	proc_t		p = PROC_NULL;
	task_t		t1;
	mach_port_name_t	tret;
	void * sright;
	int error = 0, refheld = 0;
	kauth_cred_t target_cred;

	AUDIT_MACH_SYSCALL_ENTER(AUE_TASKNAMEFORPID);
	AUDIT_ARG(pid, pid);
	AUDIT_ARG(mach_port1, target_tport);

	t1 = port_name_to_task(target_tport);
	if (t1 == TASK_NULL) {
		(void) copyout((char *)&t1, task_addr, sizeof(mach_port_name_t));
		AUDIT_MACH_SYSCALL_EXIT(KERN_FAILURE);
		return(KERN_FAILURE);
	} 

	p = proc_find(pid);
	if (p != PROC_NULL) {
		AUDIT_ARG(process, p);
		target_cred = kauth_cred_proc_ref(p);
		refheld = 1;

		if ((p->p_stat != SZOMB)
		    && ((current_proc() == p)
			|| kauth_cred_issuser(kauth_cred_get()) 
			|| ((kauth_cred_getuid(target_cred) == kauth_cred_getuid(kauth_cred_get())) && 
			    ((kauth_cred_getruid(target_cred) == kauth_getruid()))))) {

			if (p->task != TASK_NULL) {
				task_reference(p->task);
#if CONFIG_MACF
				error = mac_proc_check_get_task_name(kauth_cred_get(),  p);
				if (error) {
					task_deallocate(p->task);
					goto noperm;
				}
#endif
				sright = (void *)convert_task_name_to_port(p->task);
				tret = ipc_port_copyout_send(sright, 
						get_task_ipcspace(current_task()));
			} else
				tret  = MACH_PORT_NULL;

			AUDIT_ARG(mach_port2, tret);
			(void) copyout((char *)&tret, task_addr, sizeof(mach_port_name_t));
			task_deallocate(t1);
			error = KERN_SUCCESS;
			goto tnfpout;
		}
	}

#if CONFIG_MACF
noperm:
#endif
    task_deallocate(t1);
	tret = MACH_PORT_NULL;
	(void) copyout((char *) &tret, task_addr, sizeof(mach_port_name_t));
	error = KERN_FAILURE;
tnfpout:
	if (refheld != 0)
		kauth_cred_unref(&target_cred);
	if (p != PROC_NULL)
		proc_rele(p);
	AUDIT_MACH_SYSCALL_EXIT(error);
	return(error);
}

kern_return_t
pid_suspend(struct proc *p __unused, struct pid_suspend_args *args, int *ret)
{
	task_t	target = NULL;
	proc_t	targetproc = PROC_NULL;
	int 	pid = args->pid;
	int 	error = 0;

#if CONFIG_MACF
	error = mac_proc_check_suspend_resume(p, MAC_PROC_CHECK_SUSPEND);
	if (error) {
		error = EPERM;
		goto out;
	}
#endif

	if (pid == 0) {
		error = EPERM;
		goto out;
	}

	targetproc = proc_find(pid);
	if (targetproc == PROC_NULL) {
		error = ESRCH;
		goto out;
	}

	if (!task_for_pid_posix_check(targetproc)) {
		error = EPERM;
		goto out;
	}

	target = targetproc->task;
#ifndef CONFIG_EMBEDDED
	if (target != TASK_NULL) {
		mach_port_t tfpport;

		/* If we aren't root and target's task access port is set... */
		if (!kauth_cred_issuser(kauth_cred_get()) &&
			targetproc != current_proc() &&
			(task_get_task_access_port(target, &tfpport) == 0) &&
			(tfpport != IPC_PORT_NULL)) {

			if (tfpport == IPC_PORT_DEAD) {
				error = EACCES;
				goto out;
			}

			/* Call up to the task access server */
			error = __KERNEL_WAITING_ON_TASKGATED_CHECK_ACCESS_UPCALL__(tfpport, proc_selfpid(), kauth_getgid(), pid);

			if (error != MACH_MSG_SUCCESS) {
				if (error == MACH_RCV_INTERRUPTED)
					error = EINTR;
				else
					error = EPERM;
				goto out;
			}
		}
	}
#endif

	task_reference(target);
	error = task_pidsuspend(target);
	if (error) {
		if (error == KERN_INVALID_ARGUMENT) {
			error = EINVAL;
		} else {
			error = EPERM;
		}
	}
#if CONFIG_MEMORYSTATUS
	else {
		memorystatus_on_suspend(targetproc);
	}
#endif

	task_deallocate(target);

out:
	if (targetproc != PROC_NULL)
		proc_rele(targetproc);
	*ret = error;
	return error;
}

kern_return_t
pid_resume(struct proc *p __unused, struct pid_resume_args *args, int *ret)
{
	task_t	target = NULL;
	proc_t	targetproc = PROC_NULL;
	int 	pid = args->pid;
	int 	error = 0;

#if CONFIG_MACF
	error = mac_proc_check_suspend_resume(p, MAC_PROC_CHECK_RESUME);
	if (error) {
		error = EPERM;
		goto out;
	}
#endif

	if (pid == 0) {
		error = EPERM;
		goto out;
	}

	targetproc = proc_find(pid);
	if (targetproc == PROC_NULL) {
		error = ESRCH;
		goto out;
	}

	if (!task_for_pid_posix_check(targetproc)) {
		error = EPERM;
		goto out;
	}

	target = targetproc->task;
#ifndef CONFIG_EMBEDDED
	if (target != TASK_NULL) {
		mach_port_t tfpport;

		/* If we aren't root and target's task access port is set... */
		if (!kauth_cred_issuser(kauth_cred_get()) &&
			targetproc != current_proc() &&
			(task_get_task_access_port(target, &tfpport) == 0) &&
			(tfpport != IPC_PORT_NULL)) {

			if (tfpport == IPC_PORT_DEAD) {
				error = EACCES;
				goto out;
			}

			/* Call up to the task access server */
			error = __KERNEL_WAITING_ON_TASKGATED_CHECK_ACCESS_UPCALL__(tfpport, proc_selfpid(), kauth_getgid(), pid);

			if (error != MACH_MSG_SUCCESS) {
				if (error == MACH_RCV_INTERRUPTED)
					error = EINTR;
				else
					error = EPERM;
				goto out;
			}
		}
	}
#endif

#if CONFIG_EMBEDDED
#if SOCKETS
	resume_proc_sockets(targetproc);
#endif /* SOCKETS */
#endif /* CONFIG_EMBEDDED */

	task_reference(target);

#if CONFIG_MEMORYSTATUS
	memorystatus_on_resume(targetproc);
#endif

	error = task_pidresume(target);
	if (error) {
		if (error == KERN_INVALID_ARGUMENT) {
			error = EINVAL;
		} else {
			if (error == KERN_MEMORY_ERROR) {
				psignal(targetproc, SIGKILL);
				error = EIO;
			} else
				error = EPERM;
		}
	}
	
	task_deallocate(target);

out:
	if (targetproc != PROC_NULL)
		proc_rele(targetproc);
	
	*ret = error;
	return error;
}

#if CONFIG_EMBEDDED
/*
 * Freeze the specified process (provided in args->pid), or find and freeze a PID.
 * When a process is specified, this call is blocking, otherwise we wake up the
 * freezer thread and do not block on a process being frozen.
 */
kern_return_t
pid_hibernate(struct proc *p __unused, struct pid_hibernate_args *args, int *ret)
{
	int 	error = 0;
	proc_t	targetproc = PROC_NULL;
	int 	pid = args->pid;

#ifndef CONFIG_FREEZE
	#pragma unused(pid)
#else

#if CONFIG_MACF
	error = mac_proc_check_suspend_resume(p, MAC_PROC_CHECK_HIBERNATE);
	if (error) {
		error = EPERM;
		goto out;
	}
#endif

	/*
	 * If a pid has been provided, we obtain the process handle and call task_for_pid_posix_check().
	 */

	if (pid >= 0) {
		targetproc = proc_find(pid);

		if (targetproc == PROC_NULL) {
			error = ESRCH;
			goto out;
		}

		if (!task_for_pid_posix_check(targetproc)) {
			error = EPERM;
			goto out;
		}
	}

	if (pid == -2) {
		vm_pageout_anonymous_pages();
	} else if (pid == -1) {
		memorystatus_on_inactivity(targetproc);
	} else {
		error = memorystatus_freeze_process_sync(targetproc);
	}

out:

#endif /* CONFIG_FREEZE */

	if (targetproc != PROC_NULL)
		proc_rele(targetproc);
	*ret = error;
	return error;
}
#endif /* CONFIG_EMBEDDED */

#if SOCKETS
int
networking_memstatus_callout(proc_t p, uint32_t status)
{
	struct filedesc	*fdp;
	int i;

	/*
	 * proc list lock NOT held
	 * proc lock NOT held
	 * a reference on the proc has been held / shall be dropped by the caller.
	 */
	LCK_MTX_ASSERT(proc_list_mlock, LCK_MTX_ASSERT_NOTOWNED);
	LCK_MTX_ASSERT(&p->p_mlock, LCK_MTX_ASSERT_NOTOWNED);

	proc_fdlock(p);
	fdp = p->p_fd;
	for (i = 0; i < fdp->fd_nfiles; i++) {
		struct fileproc	*fp;

		fp = fdp->fd_ofiles[i];
		if (fp == NULL || (fdp->fd_ofileflags[i] & UF_RESERVED) != 0) {
			continue;
		}
		switch (FILEGLOB_DTYPE(fp->f_fglob)) {
#if NECP
		case DTYPE_NETPOLICY:
			necp_fd_memstatus(p, status,
			    (struct necp_fd_data *)fp->f_fglob->fg_data);
			break;
#endif /* NECP */
		default:
			break;
		}
	}
	proc_fdunlock(p);

	return (1);
}


static int
networking_defunct_callout(proc_t p, void *arg)
{
	struct pid_shutdown_sockets_args *args = arg;
	int pid = args->pid;
	int level = args->level;
	struct filedesc	*fdp;
	int i;

	proc_fdlock(p);
	fdp = p->p_fd;
	for (i = 0; i < fdp->fd_nfiles; i++) {
		struct fileproc	*fp = fdp->fd_ofiles[i];
		struct fileglob *fg;

		if (fp == NULL || (fdp->fd_ofileflags[i] & UF_RESERVED) != 0) {
			continue;
		}

		fg = fp->f_fglob;
		switch (FILEGLOB_DTYPE(fg)) {
		case DTYPE_SOCKET: {
			struct socket *so = (struct socket *)fg->fg_data;
			if (p->p_pid == pid || so->last_pid == pid || 
			    ((so->so_flags & SOF_DELEGATED) && so->e_pid == pid)) {
				/* Call networking stack with socket and level */
				(void) socket_defunct(p, so, level);
			}
			break;
		}
#if NECP
		case DTYPE_NETPOLICY:
			/* first pass: defunct necp and get stats for ntstat */
			if (p->p_pid == pid) {
				necp_fd_defunct(p,
				    (struct necp_fd_data *)fg->fg_data);
			}
			break;
#endif /* NECP */
		default:
			break;
		}
	}

	proc_fdunlock(p);

	return (PROC_RETURNED);
}

int
pid_shutdown_sockets(struct proc *p __unused, struct pid_shutdown_sockets_args *args, int *ret)
{
	int 				error = 0;
	proc_t				targetproc = PROC_NULL;
	int				pid = args->pid;
	int				level = args->level;

	if (level != SHUTDOWN_SOCKET_LEVEL_DISCONNECT_SVC &&
	    level != SHUTDOWN_SOCKET_LEVEL_DISCONNECT_ALL) {
		error = EINVAL;
		goto out;
	}

#if CONFIG_MACF
	error = mac_proc_check_suspend_resume(p, MAC_PROC_CHECK_SHUTDOWN_SOCKETS);
	if (error) {
		error = EPERM;
		goto out;
	}
#endif

	targetproc = proc_find(pid);
	if (targetproc == PROC_NULL) {
		error = ESRCH;
		goto out;
	}

	if (!task_for_pid_posix_check(targetproc)) {
		error = EPERM;
		goto out;
	}

	proc_iterate(PROC_ALLPROCLIST | PROC_NOWAITTRANS,
	    networking_defunct_callout, args, NULL, NULL);

out:
	if (targetproc != PROC_NULL)
		proc_rele(targetproc);
	*ret = error;
	return error;
}

#endif /* SOCKETS */

static int
sysctl_settfp_policy(__unused struct sysctl_oid *oidp, void *arg1,
    __unused int arg2, struct sysctl_req *req)
{
    int error = 0;
	int new_value;

    error = SYSCTL_OUT(req, arg1, sizeof(int));
    if (error || req->newptr == USER_ADDR_NULL)
        return(error);

	if (!kauth_cred_issuser(kauth_cred_get()))
		return(EPERM);

	if ((error = SYSCTL_IN(req, &new_value, sizeof(int)))) {
		goto out;
	}
	if ((new_value == KERN_TFP_POLICY_DENY) 
		|| (new_value == KERN_TFP_POLICY_DEFAULT))
			tfp_policy = new_value;
	else
			error = EINVAL;		
out:
    return(error);

}

#if defined(SECURE_KERNEL)
static int kern_secure_kernel = 1;
#else
static int kern_secure_kernel = 0;
#endif

SYSCTL_INT(_kern, OID_AUTO, secure_kernel, CTLFLAG_RD | CTLFLAG_LOCKED, &kern_secure_kernel, 0, "");

SYSCTL_NODE(_kern, KERN_TFP, tfp, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "tfp");
SYSCTL_PROC(_kern_tfp, KERN_TFP_POLICY, policy, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &tfp_policy, sizeof(uint32_t), &sysctl_settfp_policy ,"I","policy");

SYSCTL_INT(_vm, OID_AUTO, shared_region_trace_level, CTLFLAG_RW | CTLFLAG_LOCKED,
	   &shared_region_trace_level, 0, "");
SYSCTL_INT(_vm, OID_AUTO, shared_region_version, CTLFLAG_RD | CTLFLAG_LOCKED,
	   &shared_region_version, 0, "");
SYSCTL_INT(_vm, OID_AUTO, shared_region_persistence, CTLFLAG_RW | CTLFLAG_LOCKED,
	   &shared_region_persistence, 0, "");

/*
 * shared_region_check_np:
 *
 * This system call is intended for dyld.
 *
 * dyld calls this when any process starts to see if the process's shared
 * region is already set up and ready to use.
 * This call returns the base address of the first mapping in the
 * process's shared region's first mapping.
 * dyld will then check what's mapped at that address.
 *
 * If the shared region is empty, dyld will then attempt to map the shared
 * cache file in the shared region via the shared_region_map_np() system call.
 *
 * If something's already mapped in the shared region, dyld will check if it
 * matches the shared cache it would like to use for that process.
 * If it matches, evrything's ready and the process can proceed and use the
 * shared region.
 * If it doesn't match, dyld will unmap the shared region and map the shared
 * cache into the process's address space via mmap().
 *
 * ERROR VALUES
 * EINVAL	no shared region
 * ENOMEM	shared region is empty
 * EFAULT	bad address for "start_address"
 */
int
shared_region_check_np(
	__unused struct proc			*p,
	struct shared_region_check_np_args	*uap,
	__unused int				*retvalp)
{
	vm_shared_region_t	shared_region;
	mach_vm_offset_t	start_address = 0;
	int			error;
	kern_return_t		kr;

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: %p [%d(%s)] -> check_np(0x%llx)\n",
		 (void *)VM_KERNEL_ADDRPERM(current_thread()),
		 p->p_pid, p->p_comm,
		 (uint64_t)uap->start_address));

	/* retrieve the current tasks's shared region */
	shared_region = vm_shared_region_get(current_task());
	if (shared_region != NULL) {
		/* retrieve address of its first mapping... */
		kr = vm_shared_region_start_address(shared_region,
						    &start_address);
		if (kr != KERN_SUCCESS) {
			error = ENOMEM;
		} else {
			/* ... and give it to the caller */
			error = copyout(&start_address,
					(user_addr_t) uap->start_address,
					sizeof (start_address));
			if (error) {
				SHARED_REGION_TRACE_ERROR(
					("shared_region: %p [%d(%s)] "
					 "check_np(0x%llx) "
					 "copyout(0x%llx) error %d\n",
					 (void *)VM_KERNEL_ADDRPERM(current_thread()),
					 p->p_pid, p->p_comm,
					 (uint64_t)uap->start_address, (uint64_t)start_address,
					 error));
			}
		}
		vm_shared_region_deallocate(shared_region);
	} else {
		/* no shared region ! */
		error = EINVAL;
	}

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: %p [%d(%s)] check_np(0x%llx) <- 0x%llx %d\n",
		 (void *)VM_KERNEL_ADDRPERM(current_thread()),
		 p->p_pid, p->p_comm,
		 (uint64_t)uap->start_address, (uint64_t)start_address, error));

	return error;
}


int
shared_region_copyin_mappings(
		struct proc			*p,
		user_addr_t			user_mappings,
		unsigned int			mappings_count,
		struct shared_file_mapping_np	*mappings)
{
	int		error = 0;
	vm_size_t	mappings_size = 0;

	/* get the list of mappings the caller wants us to establish */
	mappings_size = (vm_size_t) (mappings_count * sizeof (mappings[0]));
	error = copyin(user_mappings,
		       mappings,
		       mappings_size);
	if (error) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(): "
			 "copyin(0x%llx, %d) failed (error=%d)\n",
			 (void *)VM_KERNEL_ADDRPERM(current_thread()),
			 p->p_pid, p->p_comm,
			 (uint64_t)user_mappings, mappings_count, error));
	}
	return error;
}
/*
 * shared_region_map_np()
 *
 * This system call is intended for dyld.
 *
 * dyld uses this to map a shared cache file into a shared region.
 * This is usually done only the first time a shared cache is needed.
 * Subsequent processes will just use the populated shared region without
 * requiring any further setup.
 */
int
_shared_region_map_and_slide(
	struct proc				*p,
	int					fd,
	uint32_t				mappings_count,
	struct shared_file_mapping_np		*mappings,
	uint32_t				slide,
	user_addr_t				slide_start,
	user_addr_t				slide_size)
{
	int				error;
	kern_return_t			kr;
	struct fileproc			*fp;
	struct vnode			*vp, *root_vp, *scdir_vp;
	struct vnode_attr		va;
	off_t				fs;
	memory_object_size_t		file_size;
#if CONFIG_MACF
	vm_prot_t			maxprot = VM_PROT_ALL;
#endif
	memory_object_control_t		file_control;
	struct vm_shared_region		*shared_region;
	uint32_t			i;

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: %p [%d(%s)] -> map\n",
		 (void *)VM_KERNEL_ADDRPERM(current_thread()),
		 p->p_pid, p->p_comm));

	shared_region = NULL;
	fp = NULL;
	vp = NULL;
	scdir_vp = NULL;

	/* get file structure from file descriptor */
	error = fp_lookup(p, fd, &fp, 0);
	if (error) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map: "
			 "fd=%d lookup failed (error=%d)\n",
			 (void *)VM_KERNEL_ADDRPERM(current_thread()),
			 p->p_pid, p->p_comm, fd, error));
		goto done;
	}

	/* make sure we're attempting to map a vnode */
	if (FILEGLOB_DTYPE(fp->f_fglob) != DTYPE_VNODE) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map: "
			 "fd=%d not a vnode (type=%d)\n",
			 (void *)VM_KERNEL_ADDRPERM(current_thread()),
			 p->p_pid, p->p_comm,
			 fd, FILEGLOB_DTYPE(fp->f_fglob)));
		error = EINVAL;
		goto done;
	}

	/* we need at least read permission on the file */
	if (! (fp->f_fglob->fg_flag & FREAD)) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map: "
			 "fd=%d not readable\n",
			 (void *)VM_KERNEL_ADDRPERM(current_thread()),
			 p->p_pid, p->p_comm, fd));
		error = EPERM;
		goto done;
	}

	/* get vnode from file structure */
	error = vnode_getwithref((vnode_t) fp->f_fglob->fg_data);
	if (error) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map: "
			 "fd=%d getwithref failed (error=%d)\n",
			 (void *)VM_KERNEL_ADDRPERM(current_thread()),
			 p->p_pid, p->p_comm, fd, error));
		goto done;
	}
	vp = (struct vnode *) fp->f_fglob->fg_data;

	/* make sure the vnode is a regular file */
	if (vp->v_type != VREG) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(%p:'%s'): "
			 "not a file (type=%d)\n",
			 (void *)VM_KERNEL_ADDRPERM(current_thread()),
			 p->p_pid, p->p_comm,
			 (void *)VM_KERNEL_ADDRPERM(vp),
			 vp->v_name, vp->v_type));
		error = EINVAL;
		goto done;
	}

#if CONFIG_MACF
	/* pass in 0 for the offset argument because AMFI does not need the offset
		of the shared cache */
	error = mac_file_check_mmap(vfs_context_ucred(vfs_context_current()),
			fp->f_fglob, VM_PROT_ALL, MAP_FILE, 0, &maxprot);
	if (error) {
		goto done;
	}
#endif /* MAC */

	/* make sure vnode is on the process's root volume */
	root_vp = p->p_fd->fd_rdir;
	if (root_vp == NULL) {
		root_vp = rootvnode;
	} else {
		/*
		 * Chroot-ed processes can't use the shared_region.
		 */
		error = EINVAL;
		goto done;
	}

	if (vp->v_mount != root_vp->v_mount) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(%p:'%s'): "
			 "not on process's root volume\n",
			 (void *)VM_KERNEL_ADDRPERM(current_thread()),
			 p->p_pid, p->p_comm,
			 (void *)VM_KERNEL_ADDRPERM(vp), vp->v_name));
		error = EPERM;
		goto done;
	}

	/* make sure vnode is owned by "root" */
	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_uid);
	error = vnode_getattr(vp, &va, vfs_context_current());
	if (error) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(%p:'%s'): "
			 "vnode_getattr(%p) failed (error=%d)\n",
			 (void *)VM_KERNEL_ADDRPERM(current_thread()),
			 p->p_pid, p->p_comm,
			 (void *)VM_KERNEL_ADDRPERM(vp), vp->v_name,
			 (void *)VM_KERNEL_ADDRPERM(vp), error));
		goto done;
	}
	if (va.va_uid != 0) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(%p:'%s'): "
			 "owned by uid=%d instead of 0\n",
			 (void *)VM_KERNEL_ADDRPERM(current_thread()),
			 p->p_pid, p->p_comm,
			 (void *)VM_KERNEL_ADDRPERM(vp),
			 vp->v_name, va.va_uid));
		error = EPERM;
		goto done;
	}

	if (scdir_enforce) {
		/* get vnode for scdir_path */
		error = vnode_lookup(scdir_path, 0, &scdir_vp, vfs_context_current());
		if (error) {
			SHARED_REGION_TRACE_ERROR(
				("shared_region: %p [%d(%s)] map(%p:'%s'): "
				 "vnode_lookup(%s) failed (error=%d)\n",
				 (void *)VM_KERNEL_ADDRPERM(current_thread()),
				 p->p_pid, p->p_comm,
				 (void *)VM_KERNEL_ADDRPERM(vp), vp->v_name,
				 scdir_path, error));
			goto done;
		}

		/* ensure parent is scdir_vp */
		if (vnode_parent(vp) != scdir_vp) {
			SHARED_REGION_TRACE_ERROR(
				("shared_region: %p [%d(%s)] map(%p:'%s'): "
				 "shared cache file not in %s\n",
				 (void *)VM_KERNEL_ADDRPERM(current_thread()),
				 p->p_pid, p->p_comm,
				 (void *)VM_KERNEL_ADDRPERM(vp),
				 vp->v_name, scdir_path));
			error = EPERM;
			goto done;
		}
	}

	/* get vnode size */
	error = vnode_size(vp, &fs, vfs_context_current());
	if (error) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(%p:'%s'): "
			 "vnode_size(%p) failed (error=%d)\n",
			 (void *)VM_KERNEL_ADDRPERM(current_thread()),
			 p->p_pid, p->p_comm,
			 (void *)VM_KERNEL_ADDRPERM(vp), vp->v_name,
			 (void *)VM_KERNEL_ADDRPERM(vp), error));
		goto done;
	}
	file_size = fs;

	/* get the file's memory object handle */
	file_control = ubc_getobject(vp, UBC_HOLDOBJECT);
	if (file_control == MEMORY_OBJECT_CONTROL_NULL) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(%p:'%s'): "
			 "no memory object\n",
			 (void *)VM_KERNEL_ADDRPERM(current_thread()),
			 p->p_pid, p->p_comm,
			 (void *)VM_KERNEL_ADDRPERM(vp), vp->v_name));
		error = EINVAL;
		goto done;
	}

	/* check that the mappings are properly covered by code signatures */
	if (!cs_enforcement(NULL)) {
		/* code signing is not enforced: no need to check */
	} else for (i = 0; i < mappings_count; i++) {
		if (mappings[i].sfm_init_prot & VM_PROT_ZF) {
			/* zero-filled mapping: not backed by the file */
			continue;
		}
		if (ubc_cs_is_range_codesigned(vp,
					       mappings[i].sfm_file_offset,
					       mappings[i].sfm_size)) {
			/* this mapping is fully covered by code signatures */
			continue;
		}
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(%p:'%s'): "
			 "mapping #%d/%d [0x%llx:0x%llx:0x%llx:0x%x:0x%x] "
			 "is not code-signed\n",
			 (void *)VM_KERNEL_ADDRPERM(current_thread()),
			 p->p_pid, p->p_comm,
			 (void *)VM_KERNEL_ADDRPERM(vp), vp->v_name,
			 i, mappings_count,
			 mappings[i].sfm_address,
			 mappings[i].sfm_size,
			 mappings[i].sfm_file_offset,
			 mappings[i].sfm_max_prot,
			 mappings[i].sfm_init_prot));
		error = EINVAL;
		goto done;
	}

	/* get the process's shared region (setup in vm_map_exec()) */
	shared_region = vm_shared_region_get(current_task());
	if (shared_region == NULL) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(%p:'%s'): "
			 "no shared region\n",
			 (void *)VM_KERNEL_ADDRPERM(current_thread()),
			 p->p_pid, p->p_comm,
			 (void *)VM_KERNEL_ADDRPERM(vp), vp->v_name));
		goto done;
	}

	/* map the file into that shared region's submap */
	kr = vm_shared_region_map_file(shared_region,
				       mappings_count,
				       mappings,
				       file_control,
				       file_size,
				       (void *) p->p_fd->fd_rdir,
				       slide,
				       slide_start,
				       slide_size);
	if (kr != KERN_SUCCESS) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(%p:'%s'): "
			 "vm_shared_region_map_file() failed kr=0x%x\n",
			 (void *)VM_KERNEL_ADDRPERM(current_thread()),
			 p->p_pid, p->p_comm,
			 (void *)VM_KERNEL_ADDRPERM(vp), vp->v_name, kr));
		switch (kr) {
		case KERN_INVALID_ADDRESS:
			error = EFAULT;
			break;
		case KERN_PROTECTION_FAILURE:
			error = EPERM;
			break;
		case KERN_NO_SPACE:
			error = ENOMEM;
			break;
		case KERN_FAILURE:
		case KERN_INVALID_ARGUMENT:
		default:
			error = EINVAL;
			break;
		}
		goto done;
	}

	error = 0;

	vnode_lock_spin(vp);

	vp->v_flag |= VSHARED_DYLD;

	vnode_unlock(vp);

	/* update the vnode's access time */
	if (! (vnode_vfsvisflags(vp) & MNT_NOATIME)) {
		VATTR_INIT(&va);
		nanotime(&va.va_access_time);
		VATTR_SET_ACTIVE(&va, va_access_time);
		vnode_setattr(vp, &va, vfs_context_current());
	}

	if (p->p_flag & P_NOSHLIB) {
		/* signal that this process is now using split libraries */
		OSBitAndAtomic(~((uint32_t)P_NOSHLIB), &p->p_flag);
	}

done:
	if (vp != NULL) {
		/*
		 * release the vnode...
		 * ubc_map() still holds it for us in the non-error case
		 */
		(void) vnode_put(vp);
		vp = NULL;
	}
	if (fp != NULL) {
		/* release the file descriptor */
		fp_drop(p, fd, fp, 0);
		fp = NULL;
	}
	if (scdir_vp != NULL) {
		(void)vnode_put(scdir_vp);
		scdir_vp = NULL;
	}

	if (shared_region != NULL) {
		vm_shared_region_deallocate(shared_region);
	}

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: %p [%d(%s)] <- map\n",
		 (void *)VM_KERNEL_ADDRPERM(current_thread()),
		 p->p_pid, p->p_comm));

	return error;
}

int
shared_region_map_and_slide_np(
	struct proc				*p,
	struct shared_region_map_and_slide_np_args	*uap,
	__unused int					*retvalp)
{
	struct shared_file_mapping_np	*mappings;
	unsigned int			mappings_count = uap->count;
	kern_return_t			kr = KERN_SUCCESS;
	uint32_t			slide = uap->slide;
	
#define SFM_MAX_STACK	8
	struct shared_file_mapping_np	stack_mappings[SFM_MAX_STACK];

	/* Is the process chrooted?? */
	if (p->p_fd->fd_rdir != NULL) {
		kr = EINVAL;
		goto done;
	}
		
	if ((kr = vm_shared_region_sliding_valid(slide)) != KERN_SUCCESS) {
		if (kr == KERN_INVALID_ARGUMENT) {
			/*
			 * This will happen if we request sliding again 
			 * with the same slide value that was used earlier
			 * for the very first sliding.
			 */
			kr = KERN_SUCCESS;
		}
		goto done;
	}

	if (mappings_count == 0) {
		SHARED_REGION_TRACE_INFO(
			("shared_region: %p [%d(%s)] map(): "
			 "no mappings\n",
			 (void *)VM_KERNEL_ADDRPERM(current_thread()),
			 p->p_pid, p->p_comm));
		kr = 0;	/* no mappings: we're done ! */
		goto done;
	} else if (mappings_count <= SFM_MAX_STACK) {
		mappings = &stack_mappings[0];
	} else {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(): "
			 "too many mappings (%d)\n",
			 (void *)VM_KERNEL_ADDRPERM(current_thread()),
			 p->p_pid, p->p_comm,
			 mappings_count));
		kr = KERN_FAILURE;
		goto done;
	}

	if ( (kr = shared_region_copyin_mappings(p, uap->mappings, uap->count, mappings))) {
		goto done;
	}


	kr = _shared_region_map_and_slide(p, uap->fd, mappings_count, mappings,
					  slide,
					  uap->slide_start, uap->slide_size);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

done:
	return kr;
}

/* sysctl overflow room */

SYSCTL_INT (_vm, OID_AUTO, pagesize, CTLFLAG_RD | CTLFLAG_LOCKED,
	    (int *) &page_size, 0, "vm page size");

/* vm_page_free_target is provided as a makeshift solution for applications that want to
	allocate buffer space, possibly purgeable memory, but not cause inactive pages to be
	reclaimed. It allows the app to calculate how much memory is free outside the free target. */
extern unsigned int	vm_page_free_target;
SYSCTL_INT(_vm, OID_AUTO, vm_page_free_target, CTLFLAG_RD | CTLFLAG_LOCKED, 
		   &vm_page_free_target, 0, "Pageout daemon free target");

extern unsigned int	vm_memory_pressure;
SYSCTL_INT(_vm, OID_AUTO, memory_pressure, CTLFLAG_RD | CTLFLAG_LOCKED,
	   &vm_memory_pressure, 0, "Memory pressure indicator");

static int
vm_ctl_page_free_wanted SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int page_free_wanted;

	page_free_wanted = mach_vm_ctl_page_free_wanted();
	return SYSCTL_OUT(req, &page_free_wanted, sizeof (page_free_wanted));
}
SYSCTL_PROC(_vm, OID_AUTO, page_free_wanted,
	    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
	    0, 0, vm_ctl_page_free_wanted, "I", "");

extern unsigned int	vm_page_purgeable_count;
SYSCTL_INT(_vm, OID_AUTO, page_purgeable_count, CTLFLAG_RD | CTLFLAG_LOCKED,
	   &vm_page_purgeable_count, 0, "Purgeable page count");

extern unsigned int	vm_page_purgeable_wired_count;
SYSCTL_INT(_vm, OID_AUTO, page_purgeable_wired_count, CTLFLAG_RD | CTLFLAG_LOCKED,
	   &vm_page_purgeable_wired_count, 0, "Wired purgeable page count");

extern unsigned int	vm_pageout_purged_objects;
SYSCTL_INT(_vm, OID_AUTO, pageout_purged_objects, CTLFLAG_RD | CTLFLAG_LOCKED,
	   &vm_pageout_purged_objects, 0, "System purged object count");

extern int madvise_free_debug;
SYSCTL_INT(_vm, OID_AUTO, madvise_free_debug, CTLFLAG_RW | CTLFLAG_LOCKED,
	   &madvise_free_debug, 0, "zero-fill on madvise(MADV_FREE*)");

SYSCTL_INT(_vm, OID_AUTO, page_reusable_count, CTLFLAG_RD | CTLFLAG_LOCKED,
	   &vm_page_stats_reusable.reusable_count, 0, "Reusable page count");
SYSCTL_QUAD(_vm, OID_AUTO, reusable_success, CTLFLAG_RD | CTLFLAG_LOCKED,
	   &vm_page_stats_reusable.reusable_pages_success, "");
SYSCTL_QUAD(_vm, OID_AUTO, reusable_failure, CTLFLAG_RD | CTLFLAG_LOCKED,
	   &vm_page_stats_reusable.reusable_pages_failure, "");
SYSCTL_QUAD(_vm, OID_AUTO, reusable_pages_shared, CTLFLAG_RD | CTLFLAG_LOCKED,
	   &vm_page_stats_reusable.reusable_pages_shared, "");
SYSCTL_QUAD(_vm, OID_AUTO, all_reusable_calls, CTLFLAG_RD | CTLFLAG_LOCKED,
	   &vm_page_stats_reusable.all_reusable_calls, "");
SYSCTL_QUAD(_vm, OID_AUTO, partial_reusable_calls, CTLFLAG_RD | CTLFLAG_LOCKED,
	   &vm_page_stats_reusable.partial_reusable_calls, "");
SYSCTL_QUAD(_vm, OID_AUTO, reuse_success, CTLFLAG_RD | CTLFLAG_LOCKED,
	   &vm_page_stats_reusable.reuse_pages_success, "");
SYSCTL_QUAD(_vm, OID_AUTO, reuse_failure, CTLFLAG_RD | CTLFLAG_LOCKED,
	   &vm_page_stats_reusable.reuse_pages_failure, "");
SYSCTL_QUAD(_vm, OID_AUTO, all_reuse_calls, CTLFLAG_RD | CTLFLAG_LOCKED,
	   &vm_page_stats_reusable.all_reuse_calls, "");
SYSCTL_QUAD(_vm, OID_AUTO, partial_reuse_calls, CTLFLAG_RD | CTLFLAG_LOCKED,
	   &vm_page_stats_reusable.partial_reuse_calls, "");
SYSCTL_QUAD(_vm, OID_AUTO, can_reuse_success, CTLFLAG_RD | CTLFLAG_LOCKED,
	   &vm_page_stats_reusable.can_reuse_success, "");
SYSCTL_QUAD(_vm, OID_AUTO, can_reuse_failure, CTLFLAG_RD | CTLFLAG_LOCKED,
	   &vm_page_stats_reusable.can_reuse_failure, "");
SYSCTL_QUAD(_vm, OID_AUTO, reusable_reclaimed, CTLFLAG_RD | CTLFLAG_LOCKED,
	   &vm_page_stats_reusable.reusable_reclaimed, "");
SYSCTL_QUAD(_vm, OID_AUTO, reusable_nonwritable, CTLFLAG_RD | CTLFLAG_LOCKED,
	   &vm_page_stats_reusable.reusable_nonwritable, "");
SYSCTL_QUAD(_vm, OID_AUTO, reusable_shared, CTLFLAG_RD | CTLFLAG_LOCKED,
	   &vm_page_stats_reusable.reusable_shared, "");
SYSCTL_QUAD(_vm, OID_AUTO, free_shared, CTLFLAG_RD | CTLFLAG_LOCKED,
	   &vm_page_stats_reusable.free_shared, "");


extern unsigned int vm_page_free_count, vm_page_speculative_count;
SYSCTL_UINT(_vm, OID_AUTO, page_free_count, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_free_count, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, page_speculative_count, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_speculative_count, 0, "");

extern unsigned int vm_page_cleaned_count;
SYSCTL_UINT(_vm, OID_AUTO, page_cleaned_count, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_cleaned_count, 0, "Cleaned queue size");

extern unsigned int vm_page_pageable_internal_count, vm_page_pageable_external_count;
SYSCTL_UINT(_vm, OID_AUTO, page_pageable_internal_count, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_pageable_internal_count, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, page_pageable_external_count, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_pageable_external_count, 0, "");

/* pageout counts */
extern unsigned int vm_pageout_inactive_dirty_internal, vm_pageout_inactive_dirty_external, vm_pageout_inactive_clean, vm_pageout_speculative_clean, vm_pageout_inactive_used;
extern unsigned int vm_pageout_freed_from_inactive_clean, vm_pageout_freed_from_speculative;
SYSCTL_UINT(_vm, OID_AUTO, pageout_inactive_dirty_internal, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_inactive_dirty_internal, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, pageout_inactive_dirty_external, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_inactive_dirty_external, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, pageout_inactive_clean, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_inactive_clean, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, pageout_speculative_clean, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_speculative_clean, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, pageout_inactive_used, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_inactive_used, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, pageout_freed_from_inactive_clean, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_freed_from_inactive_clean, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, pageout_freed_from_speculative, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_freed_from_speculative, 0, "");

extern unsigned int vm_pageout_freed_from_cleaned;
SYSCTL_UINT(_vm, OID_AUTO, pageout_freed_from_cleaned, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_freed_from_cleaned, 0, "");

/* counts of pages entering the cleaned queue */
extern unsigned int vm_pageout_enqueued_cleaned, vm_pageout_enqueued_cleaned_from_inactive_dirty;
SYSCTL_UINT(_vm, OID_AUTO, pageout_enqueued_cleaned, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_enqueued_cleaned, 0, ""); /* sum of next two */
SYSCTL_UINT(_vm, OID_AUTO, pageout_enqueued_cleaned_from_inactive_dirty, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_enqueued_cleaned_from_inactive_dirty, 0, "");

/* counts of pages leaving the cleaned queue */
extern unsigned int vm_pageout_cleaned_reclaimed, vm_pageout_cleaned_reactivated, vm_pageout_cleaned_reference_reactivated, vm_pageout_cleaned_volatile_reactivated, vm_pageout_cleaned_fault_reactivated, vm_pageout_cleaned_commit_reactivated, vm_pageout_cleaned_busy, vm_pageout_cleaned_nolock;
SYSCTL_UINT(_vm, OID_AUTO, pageout_cleaned, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_cleaned_reclaimed, 0, "Cleaned pages reclaimed");
SYSCTL_UINT(_vm, OID_AUTO, pageout_cleaned_reactivated, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_cleaned_reactivated, 0, "Cleaned pages reactivated"); /* sum of all reactivated AND busy and nolock (even though those actually get reDEactivated */
SYSCTL_UINT(_vm, OID_AUTO, pageout_cleaned_reference_reactivated, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_cleaned_reference_reactivated, 0, "Cleaned pages reference reactivated");
SYSCTL_UINT(_vm, OID_AUTO, pageout_cleaned_volatile_reactivated, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_cleaned_volatile_reactivated, 0, "Cleaned pages volatile reactivated");
SYSCTL_UINT(_vm, OID_AUTO, pageout_cleaned_fault_reactivated, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_cleaned_fault_reactivated, 0, "Cleaned pages fault reactivated");
SYSCTL_UINT(_vm, OID_AUTO, pageout_cleaned_commit_reactivated, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_cleaned_commit_reactivated, 0, "Cleaned pages commit reactivated");
SYSCTL_UINT(_vm, OID_AUTO, pageout_cleaned_busy, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_cleaned_busy, 0, "Cleaned pages busy (deactivated)");
SYSCTL_UINT(_vm, OID_AUTO, pageout_cleaned_nolock, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_cleaned_nolock, 0, "Cleaned pages no-lock (deactivated)");

/* counts of pages prefaulted when entering a memory object */
extern int64_t vm_prefault_nb_pages, vm_prefault_nb_bailout;
SYSCTL_QUAD(_vm, OID_AUTO, prefault_nb_pages, CTLFLAG_RW | CTLFLAG_LOCKED, &vm_prefault_nb_pages, "");
SYSCTL_QUAD(_vm, OID_AUTO, prefault_nb_bailout, CTLFLAG_RW | CTLFLAG_LOCKED, &vm_prefault_nb_bailout, "");

#if defined (__x86_64__)
extern unsigned int vm_clump_promote_threshold;
SYSCTL_UINT(_vm, OID_AUTO, vm_clump_promote_threshold, CTLFLAG_RW | CTLFLAG_LOCKED, &vm_clump_promote_threshold, 0, "clump size threshold for promotes");
#if DEVELOPMENT || DEBUG
extern unsigned long vm_clump_stats[];
SYSCTL_LONG(_vm, OID_AUTO, vm_clump_stats1, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_clump_stats[1], "free page allocations from clump of 1 page");
SYSCTL_LONG(_vm, OID_AUTO, vm_clump_stats2, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_clump_stats[2], "free page allocations from clump of 2 pages");
SYSCTL_LONG(_vm, OID_AUTO, vm_clump_stats3, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_clump_stats[3], "free page allocations from clump of 3 pages");
SYSCTL_LONG(_vm, OID_AUTO, vm_clump_stats4, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_clump_stats[4], "free page allocations from clump of 4 pages");
SYSCTL_LONG(_vm, OID_AUTO, vm_clump_stats5, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_clump_stats[5], "free page allocations from clump of 5 pages");
SYSCTL_LONG(_vm, OID_AUTO, vm_clump_stats6, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_clump_stats[6], "free page allocations from clump of 6 pages");
SYSCTL_LONG(_vm, OID_AUTO, vm_clump_stats7, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_clump_stats[7], "free page allocations from clump of 7 pages");
SYSCTL_LONG(_vm, OID_AUTO, vm_clump_stats8, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_clump_stats[8], "free page allocations from clump of 8 pages");
SYSCTL_LONG(_vm, OID_AUTO, vm_clump_stats9, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_clump_stats[9], "free page allocations from clump of 9 pages");
SYSCTL_LONG(_vm, OID_AUTO, vm_clump_stats10, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_clump_stats[10], "free page allocations from clump of 10 pages");
SYSCTL_LONG(_vm, OID_AUTO, vm_clump_stats11, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_clump_stats[11], "free page allocations from clump of 11 pages");
SYSCTL_LONG(_vm, OID_AUTO, vm_clump_stats12, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_clump_stats[12], "free page allocations from clump of 12 pages");
SYSCTL_LONG(_vm, OID_AUTO, vm_clump_stats13, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_clump_stats[13], "free page allocations from clump of 13 pages");
SYSCTL_LONG(_vm, OID_AUTO, vm_clump_stats14, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_clump_stats[14], "free page allocations from clump of 14 pages");
SYSCTL_LONG(_vm, OID_AUTO, vm_clump_stats15, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_clump_stats[15], "free page allocations from clump of 15 pages");
SYSCTL_LONG(_vm, OID_AUTO, vm_clump_stats16, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_clump_stats[16], "free page allocations from clump of 16 pages");
extern unsigned long vm_clump_allocs, vm_clump_inserts, vm_clump_inrange, vm_clump_promotes;
SYSCTL_LONG(_vm, OID_AUTO, vm_clump_alloc, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_clump_allocs, "free page allocations");
SYSCTL_LONG(_vm, OID_AUTO, vm_clump_inserts, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_clump_inserts, "free page insertions");
SYSCTL_LONG(_vm, OID_AUTO, vm_clump_inrange, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_clump_inrange, "free page insertions that are part of vm_pages");
SYSCTL_LONG(_vm, OID_AUTO, vm_clump_promotes, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_clump_promotes, "pages promoted to head");
#endif  /* if DEVELOPMENT || DEBUG */
#endif  /* #if defined (__x86_64__) */

#if CONFIG_SECLUDED_MEMORY

SYSCTL_UINT(_vm, OID_AUTO, num_tasks_can_use_secluded_mem, CTLFLAG_RD | CTLFLAG_LOCKED, &num_tasks_can_use_secluded_mem, 0, "");
extern unsigned int vm_page_secluded_target;
extern unsigned int vm_page_secluded_count;
extern unsigned int vm_page_secluded_count_free;
extern unsigned int vm_page_secluded_count_inuse;
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_target, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded_target, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_count, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded_count, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_count_free, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded_count_free, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_count_inuse, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded_count_inuse, 0, "");

extern struct vm_page_secluded_data vm_page_secluded;
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_eligible, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded.eligible_for_secluded, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_grab_success_free, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded.grab_success_free, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_grab_success_other, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded.grab_success_other, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_grab_failure_locked, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded.grab_failure_locked, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_grab_failure_state, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded.grab_failure_state, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_grab_failure_dirty, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded.grab_failure_dirty, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_grab_for_iokit, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded.grab_for_iokit, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_grab_for_iokit_success, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded.grab_for_iokit_success, 0, "");

extern uint64_t vm_pageout_secluded_burst_count;
SYSCTL_QUAD(_vm, OID_AUTO, pageout_secluded_burst_count, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_secluded_burst_count, "");

#endif /* CONFIG_SECLUDED_MEMORY */

#include <kern/thread.h>
#include <sys/user.h>

void vm_pageout_io_throttle(void);

void vm_pageout_io_throttle(void) {
	struct uthread *uthread = get_bsdthread_info(current_thread());
 
               /*
                * thread is marked as a low priority I/O type
                * and the I/O we issued while in this cleaning operation
                * collided with normal I/O operations... we'll
                * delay in order to mitigate the impact of this
                * task on the normal operation of the system
                */

	if (uthread->uu_lowpri_window) {
		throttle_lowpri_io(1);
	}

}

int
vm_pressure_monitor(
	__unused struct proc *p,
	struct vm_pressure_monitor_args *uap,
	int *retval)
{
	kern_return_t	kr;
	uint32_t	pages_reclaimed;
	uint32_t	pages_wanted;

	kr = mach_vm_pressure_monitor(
		(boolean_t) uap->wait_for_pressure,
		uap->nsecs_monitored,
		(uap->pages_reclaimed) ? &pages_reclaimed : NULL,
		&pages_wanted);

	switch (kr) {
	case KERN_SUCCESS:
		break;
	case KERN_ABORTED:
		return EINTR;
	default:
		return EINVAL;
	}

	if (uap->pages_reclaimed) {
		if (copyout((void *)&pages_reclaimed,
			    uap->pages_reclaimed,
			    sizeof (pages_reclaimed)) != 0) {
			return EFAULT;
		}
	}

	*retval = (int) pages_wanted;
	return 0;
}

int
kas_info(struct proc *p,
			  struct kas_info_args *uap,
			  int *retval __unused)
{
#ifdef SECURE_KERNEL
	(void)p;
	(void)uap;
	return ENOTSUP;
#else /* !SECURE_KERNEL */
	int			selector = uap->selector;
	user_addr_t	valuep = uap->value;
	user_addr_t	sizep = uap->size;
	user_size_t size;
	int			error;

	if (!kauth_cred_issuser(kauth_cred_get())) {
		return EPERM;
	}

#if CONFIG_MACF
	error = mac_system_check_kas_info(kauth_cred_get(), selector);
	if (error) {
		return error;
	}
#endif

	if (IS_64BIT_PROCESS(p)) {
		user64_size_t size64;
		error = copyin(sizep, &size64, sizeof(size64));
		size = (user_size_t)size64;
	} else {
		user32_size_t size32;
		error = copyin(sizep, &size32, sizeof(size32));
		size = (user_size_t)size32;
	}
	if (error) {
		return error;
	}

	switch (selector) {
		case KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR:
			{
				uint64_t slide = vm_kernel_slide;

				if (sizeof(slide) != size) {
					return EINVAL;
				}
				
				if (IS_64BIT_PROCESS(p)) {
					user64_size_t size64 = (user64_size_t)size;
					error = copyout(&size64, sizep, sizeof(size64));
				} else {
					user32_size_t size32 = (user32_size_t)size;
					error = copyout(&size32, sizep, sizeof(size32));
				}
				if (error) {
					return error;
				}
				
				error = copyout(&slide, valuep, sizeof(slide));
				if (error) {
					return error;
				}
			}
			break;
		default:
			return EINVAL;
	}

	return 0;
#endif /* !SECURE_KERNEL */
}


#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
#pragma clang diagnostic ignored "-Wunused-function"

static void asserts() {
	static_assert(sizeof(vm_min_kernel_address) == sizeof(unsigned long));
	static_assert(sizeof(vm_max_kernel_address) == sizeof(unsigned long));
}

SYSCTL_ULONG(_vm, OID_AUTO, vm_min_kernel_address, CTLFLAG_RD, (unsigned long *) &vm_min_kernel_address, "");
SYSCTL_ULONG(_vm, OID_AUTO, vm_max_kernel_address, CTLFLAG_RD, (unsigned long *) &vm_max_kernel_address, "");
#pragma clang diagnostic pop

extern uint32_t vm_page_pages;
SYSCTL_UINT(_vm, OID_AUTO, pages, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_pages, 0, "");

#if (__arm__ || __arm64__) && (DEVELOPMENT || DEBUG)
extern void pmap_footprint_suspend(vm_map_t map, boolean_t suspend);
static int
sysctl_vm_footprint_suspend SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error = 0;
	int new_value;

	if (req->newptr == USER_ADDR_NULL) {
		return 0;
	}
	error = SYSCTL_IN(req, &new_value, sizeof(int));
	if (error) {
		return error;
	}
	pmap_footprint_suspend(current_map(), new_value);
	return 0;
}
SYSCTL_PROC(_vm, OID_AUTO, footprint_suspend,
	    CTLTYPE_INT|CTLFLAG_WR|CTLFLAG_ANYBODY|CTLFLAG_LOCKED|CTLFLAG_MASKED,
	    0, 0, &sysctl_vm_footprint_suspend, "I", "");
#endif /* (__arm__ || __arm64__) && (DEVELOPMENT || DEBUG) */
