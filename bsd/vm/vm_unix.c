/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
#include <machine/machine_routines.h>

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
#include <sys/xattr.h>
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
#include <sys/random.h>
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
#include <sys/kern_memorystatus_freeze.h>
#include <sys/proc_internal.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

#include <kern/bits.h>

#if CONFIG_CSR
#include <sys/csr.h>
#endif /* CONFIG_CSR */
#include <IOKit/IOBSD.h>

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
	vm_offset_t     kaddr;
	kern_return_t   kr;
	int     error = 0;
	int     size = 0;

	error = sysctl_handle_int(oidp, &size, 0, req);
	if (error || !req->newptr) {
		return error;
	}

	kr = kmem_alloc_contig(kernel_map, &kaddr, (vm_size_t)size, 0, 0, 0, 0, VM_KERN_MEMORY_IOKIT);

	if (kr == KERN_SUCCESS) {
		kmem_free(kernel_map, kaddr, size);
	}

	return error;
}

SYSCTL_PROC(_vm, OID_AUTO, kmem_alloc_contig, CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_LOCKED | CTLFLAG_MASKED,
    0, 0, &sysctl_kmem_alloc_contig, "I", "");

extern int vm_region_footprint;
SYSCTL_INT(_vm, OID_AUTO, region_footprint, CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_LOCKED, &vm_region_footprint, 0, "");

#endif /* DEVELOPMENT || DEBUG */

static int
sysctl_vm_self_region_footprint SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	int     error = 0;
	int     value;

	value = task_self_region_footprint();
	error = SYSCTL_OUT(req, &value, sizeof(int));
	if (error) {
		return error;
	}

	if (!req->newptr) {
		return 0;
	}

	error = SYSCTL_IN(req, &value, sizeof(int));
	if (error) {
		return error;
	}
	task_self_region_footprint_set(value);
	return 0;
}
SYSCTL_PROC(_vm, OID_AUTO, self_region_footprint, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_LOCKED | CTLFLAG_MASKED, 0, 0, &sysctl_vm_self_region_footprint, "I", "");

static int
sysctl_vm_self_region_page_size SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	int     error = 0;
	int     value;

	value = (1 << thread_self_region_page_shift());
	error = SYSCTL_OUT(req, &value, sizeof(int));
	if (error) {
		return error;
	}

	if (!req->newptr) {
		return 0;
	}

	error = SYSCTL_IN(req, &value, sizeof(int));
	if (error) {
		return error;
	}

	if (value != 0 && value != 4096 && value != 16384) {
		return EINVAL;
	}

#if !__ARM_MIXED_PAGE_SIZE__
	if (value != vm_map_page_size(current_map())) {
		return EINVAL;
	}
#endif /* !__ARM_MIXED_PAGE_SIZE__ */

	thread_self_region_page_shift_set(bit_first(value));
	return 0;
}
SYSCTL_PROC(_vm, OID_AUTO, self_region_page_size, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_LOCKED | CTLFLAG_MASKED, 0, 0, &sysctl_vm_self_region_page_size, "I", "");


#if DEVELOPMENT || DEBUG
extern int panic_on_unsigned_execute;
SYSCTL_INT(_vm, OID_AUTO, panic_on_unsigned_execute, CTLFLAG_RW | CTLFLAG_LOCKED, &panic_on_unsigned_execute, 0, "");
#endif /* DEVELOPMENT || DEBUG */

extern int cs_executable_create_upl;
extern int cs_executable_wire;
SYSCTL_INT(_vm, OID_AUTO, cs_executable_create_upl, CTLFLAG_RD | CTLFLAG_LOCKED, &cs_executable_create_upl, 0, "");
SYSCTL_INT(_vm, OID_AUTO, cs_executable_wire, CTLFLAG_RD | CTLFLAG_LOCKED, &cs_executable_wire, 0, "");

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
#if DEVELOPMENT || DEBUG
extern unsigned long pmap_asid_flushes;
SYSCTL_ULONG(_vm, OID_AUTO, pmap_asid_flushes, CTLFLAG_RD | CTLFLAG_LOCKED, &pmap_asid_flushes, "");
extern unsigned long pmap_asid_hits;
SYSCTL_ULONG(_vm, OID_AUTO, pmap_asid_hits, CTLFLAG_RD | CTLFLAG_LOCKED, &pmap_asid_hits, "");
extern unsigned long pmap_asid_misses;
SYSCTL_ULONG(_vm, OID_AUTO, pmap_asid_misses, CTLFLAG_RD | CTLFLAG_LOCKED, &pmap_asid_misses, "");
#endif
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

	if (vm_shadow_max_enabled) {
		value = proc_shadow_max();
	}

	return SYSCTL_OUT(req, &value, sizeof(value));
}
SYSCTL_PROC(_vm, OID_AUTO, vm_shadow_max, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
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

#if XNU_TARGET_OS_OSX

#if defined (__x86_64__)
static int scdir_enforce = 1;
#else /* defined (__x86_64__) */
static int scdir_enforce = 0;   /* AOT caches live elsewhere */
#endif /* defined (__x86_64__) */

static char scdir_path[] = "/System/Library/dyld/";

#else /* XNU_TARGET_OS_OSX */

static int scdir_enforce = 0;
static char scdir_path[] = "/System/Library/Caches/com.apple.dyld/";

#endif /* XNU_TARGET_OS_OSX */

#ifndef SECURE_KERNEL
static int sysctl_scdir_enforce SYSCTL_HANDLER_ARGS
{
#if CONFIG_CSR
	if (csr_check(CSR_ALLOW_UNRESTRICTED_FS) != 0) {
		printf("Failed attempt to set vm.enforce_shared_cache_dir sysctl\n");
		return EPERM;
	}
#endif /* CONFIG_CSR */
	return sysctl_handle_int(oidp, arg1, arg2, req);
}

SYSCTL_PROC(_vm, OID_AUTO, enforce_shared_cache_dir, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &scdir_enforce, 0, sysctl_scdir_enforce, "I", "");
#endif

/* These log rate throttling state variables aren't thread safe, but
 * are sufficient unto the task.
 */
static int64_t last_unnest_log_time = 0;
static int shared_region_unnest_log_count = 0;

void
log_unnest_badness(
	vm_map_t        m,
	vm_map_offset_t s,
	vm_map_offset_t e,
	boolean_t       is_nested_map,
	vm_map_offset_t lowest_unnestable_addr)
{
	struct timeval  tv;

	if (shared_region_unnest_logging == 0) {
		return;
	}

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
			    shared_region_unnest_log_count_threshold) {
				return;
			}
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
	user_addr_t     addr,
	user_size_t     len,
	int     prot)
{
	vm_map_t        map;

	map = current_map();
	return vm_map_check_protection(
		map,
		vm_map_trunc_page(addr,
		vm_map_page_mask(map)),
		vm_map_round_page(addr + len,
		vm_map_page_mask(map)),
		prot == B_READ ? VM_PROT_READ : VM_PROT_WRITE);
}

int
vslock(
	user_addr_t     addr,
	user_size_t     len)
{
	kern_return_t   kret;
	vm_map_t        map;

	map = current_map();
	kret = vm_map_wire_kernel(map,
	    vm_map_trunc_page(addr,
	    vm_map_page_mask(map)),
	    vm_map_round_page(addr + len,
	    vm_map_page_mask(map)),
	    VM_PROT_READ | VM_PROT_WRITE, VM_KERN_MEMORY_BSD,
	    FALSE);

	switch (kret) {
	case KERN_SUCCESS:
		return 0;
	case KERN_INVALID_ADDRESS:
	case KERN_NO_SPACE:
		return ENOMEM;
	case KERN_PROTECTION_FAILURE:
		return EACCES;
	default:
		return EINVAL;
	}
}

int
vsunlock(
	user_addr_t addr,
	user_size_t len,
	__unused int dirtied)
{
#if FIXME  /* [ */
	pmap_t          pmap;
	vm_page_t       pg;
	vm_map_offset_t vaddr;
	ppnum_t         paddr;
#endif  /* FIXME ] */
	kern_return_t   kret;
	vm_map_t        map;

	map = current_map();

#if FIXME  /* [ */
	if (dirtied) {
		pmap = get_task_pmap(current_task());
		for (vaddr = vm_map_trunc_page(addr, PAGE_MASK);
		    vaddr < vm_map_round_page(addr + len, PAGE_MASK);
		    vaddr += PAGE_SIZE) {
			paddr = pmap_find_phys(pmap, vaddr);
			pg = PHYS_TO_VM_PAGE(paddr);
			vm_page_set_modified(pg);
		}
	}
#endif  /* FIXME ] */
#ifdef  lint
	dirtied++;
#endif  /* lint */
	kret = vm_map_unwire(map,
	    vm_map_trunc_page(addr,
	    vm_map_page_mask(map)),
	    vm_map_round_page(addr + len,
	    vm_map_page_mask(map)),
	    FALSE);
	switch (kret) {
	case KERN_SUCCESS:
		return 0;
	case KERN_INVALID_ADDRESS:
	case KERN_NO_SPACE:
		return ENOMEM;
	case KERN_PROTECTION_FAILURE:
		return EACCES;
	default:
		return EINVAL;
	}
}

int
subyte(
	user_addr_t addr,
	int byte)
{
	char character;

	character = (char)byte;
	return copyout((void *)&(character), addr, sizeof(char)) == 0 ? 0 : -1;
}

int
suibyte(
	user_addr_t addr,
	int byte)
{
	char character;

	character = (char)byte;
	return copyout((void *)&(character), addr, sizeof(char)) == 0 ? 0 : -1;
}

int
fubyte(user_addr_t addr)
{
	unsigned char byte;

	if (copyin(addr, (void *) &byte, sizeof(char))) {
		return -1;
	}
	return byte;
}

int
fuibyte(user_addr_t addr)
{
	unsigned char byte;

	if (copyin(addr, (void *) &(byte), sizeof(char))) {
		return -1;
	}
	return byte;
}

int
suword(
	user_addr_t addr,
	long word)
{
	return copyout((void *) &word, addr, sizeof(int)) == 0 ? 0 : -1;
}

long
fuword(user_addr_t addr)
{
	long word = 0;

	if (copyin(addr, (void *) &word, sizeof(int))) {
		return -1;
	}
	return word;
}

/* suiword and fuiword are the same as suword and fuword, respectively */

int
suiword(
	user_addr_t addr,
	long word)
{
	return copyout((void *) &word, addr, sizeof(int)) == 0 ? 0 : -1;
}

long
fuiword(user_addr_t addr)
{
	long word = 0;

	if (copyin(addr, (void *) &word, sizeof(int))) {
		return -1;
	}
	return word;
}

/*
 * With a 32-bit kernel and mixed 32/64-bit user tasks, this interface allows the
 * fetching and setting of process-sized size_t and pointer values.
 */
int
sulong(user_addr_t addr, int64_t word)
{
	if (IS_64BIT_PROCESS(current_proc())) {
		return copyout((void *)&word, addr, sizeof(word)) == 0 ? 0 : -1;
	} else {
		return suiword(addr, (long)word);
	}
}

int64_t
fulong(user_addr_t addr)
{
	int64_t longword;

	if (IS_64BIT_PROCESS(current_proc())) {
		if (copyin(addr, (void *)&longword, sizeof(longword)) != 0) {
			return -1;
		}
		return longword;
	} else {
		return (int64_t)fuiword(addr);
	}
}

int
suulong(user_addr_t addr, uint64_t uword)
{
	if (IS_64BIT_PROCESS(current_proc())) {
		return copyout((void *)&uword, addr, sizeof(uword)) == 0 ? 0 : -1;
	} else {
		return suiword(addr, (uint32_t)uword);
	}
}

uint64_t
fuulong(user_addr_t addr)
{
	uint64_t ulongword;

	if (IS_64BIT_PROCESS(current_proc())) {
		if (copyin(addr, (void *)&ulongword, sizeof(ulongword)) != 0) {
			return -1ULL;
		}
		return ulongword;
	} else {
		return (uint64_t)fuiword(addr);
	}
}

int
swapon(__unused proc_t procp, __unused struct swapon_args *uap, __unused int *retval)
{
	return ENOTSUP;
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
 *                      args->pid	Process ID (returned value; see below)
 *
 * Returns:	KERL_SUCCESS	Success
 *              KERN_FAILURE	Not success
 *
 * Implicit returns: args->pid		Process ID
 *
 */
kern_return_t
pid_for_task(
	struct pid_for_task_args *args)
{
	mach_port_name_t        t = args->t;
	user_addr_t             pid_addr  = args->pid;
	proc_t p;
	task_t          t1;
	int     pid = -1;
	kern_return_t   err = KERN_SUCCESS;

	AUDIT_MACH_SYSCALL_ENTER(AUE_PIDFORTASK);
	AUDIT_ARG(mach_port1, t);

	t1 = port_name_to_task_name(t);

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
		} else {
			err = KERN_FAILURE;
		}
	}
	task_deallocate(t1);
pftout:
	AUDIT_ARG(pid, pid);
	(void) copyout((char *) &pid, pid_addr, sizeof(int));
	AUDIT_MACH_SYSCALL_EXIT(err);
	return err;
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
	if (kauth_cred_issuser(mycred)) {
		return TRUE;
	}

	/* We're allowed to get our own task port */
	if (target == current_proc()) {
		return TRUE;
	}

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
__attribute__((noinline)) int
__KERNEL_WAITING_ON_TASKGATED_CHECK_ACCESS_UPCALL__(
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
	mach_port_name_t        target_tport = args->target_tport;
	int                     pid = args->pid;
	user_addr_t             task_addr = args->t;
	proc_t                  p = PROC_NULL;
	task_t                  t1 = TASK_NULL;
	task_t                  task = TASK_NULL;
	mach_port_name_t        tret = MACH_PORT_NULL;
	ipc_port_t              tfpport = MACH_PORT_NULL;
	void                    * sright = NULL;
	int                     error = 0;
	boolean_t               is_current_proc = FALSE;
	struct proc_ident       pident = {0};

	AUDIT_MACH_SYSCALL_ENTER(AUE_TASKFORPID);
	AUDIT_ARG(pid, pid);
	AUDIT_ARG(mach_port1, target_tport);

	/* Always check if pid == 0 */
	if (pid == 0) {
		(void) copyout((char *)&t1, task_addr, sizeof(mach_port_name_t));
		AUDIT_MACH_SYSCALL_EXIT(KERN_FAILURE);
		return KERN_FAILURE;
	}

	t1 = port_name_to_task(target_tport);
	if (t1 == TASK_NULL) {
		(void) copyout((char *)&t1, task_addr, sizeof(mach_port_name_t));
		AUDIT_MACH_SYSCALL_EXIT(KERN_FAILURE);
		return KERN_FAILURE;
	}


	p = proc_find(pid);
	if (p == PROC_NULL) {
		error = KERN_FAILURE;
		goto tfpout;
	}
	pident = proc_ident(p);
	is_current_proc = (p == current_proc());

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

	/*
	 * Grab a task reference and drop the proc reference as the proc ref
	 * shouldn't be held accross upcalls.
	 */
	task = p->task;
	task_reference(task);

	proc_rele(p);
	p = PROC_NULL;

#if CONFIG_MACF
	error = mac_proc_check_get_task(kauth_cred_get(), &pident);
	if (error) {
		error = KERN_FAILURE;
		goto tfpout;
	}
#endif

	/* If we aren't root and target's task access port is set... */
	if (!kauth_cred_issuser(kauth_cred_get()) &&
	    !is_current_proc &&
	    (task_get_task_access_port(task, &tfpport) == 0) &&
	    (tfpport != IPC_PORT_NULL)) {
		if (tfpport == IPC_PORT_DEAD) {
			error = KERN_PROTECTION_FAILURE;
			goto tfpout;
		}

		/* Call up to the task access server */
		error = __KERNEL_WAITING_ON_TASKGATED_CHECK_ACCESS_UPCALL__(tfpport, proc_selfpid(), kauth_getgid(), pid);

		if (error != MACH_MSG_SUCCESS) {
			if (error == MACH_RCV_INTERRUPTED) {
				error = KERN_ABORTED;
			} else {
				error = KERN_FAILURE;
			}
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
	if (p != PROC_NULL) {
		proc_rele(p);
	}
	AUDIT_MACH_SYSCALL_EXIT(error);
	return error;
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
	mach_port_name_t        target_tport = args->target_tport;
	int                     pid = args->pid;
	user_addr_t             task_addr = args->t;
	proc_t          p = PROC_NULL;
	task_t          t1;
	mach_port_name_t        tret;
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
		return KERN_FAILURE;
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
				struct proc_ident pident = proc_ident(p);

				task_t task = p->task;

				task_reference(p->task);
				proc_rele(p);
				p = PROC_NULL;
#if CONFIG_MACF
				error = mac_proc_check_get_task_name(kauth_cred_get(), &pident);
				if (error) {
					task_deallocate(task);
					goto noperm;
				}
#endif
				sright = (void *)convert_task_name_to_port(task);
				task = NULL;
				tret = ipc_port_copyout_send(sright,
				    get_task_ipcspace(current_task()));
			} else {
				tret  = MACH_PORT_NULL;
			}

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
	if (refheld != 0) {
		kauth_cred_unref(&target_cred);
	}
	if (p != PROC_NULL) {
		proc_rele(p);
	}
	AUDIT_MACH_SYSCALL_EXIT(error);
	return error;
}

/*
 *	Routine:	task_inspect_for_pid
 *	Purpose:
 *		Get the task inspect port for another "process", named by its
 *		process ID on the same host as "target_task".
 */
int
task_inspect_for_pid(struct proc *p __unused, struct task_inspect_for_pid_args *args, int *ret)
{
	mach_port_name_t        target_tport = args->target_tport;
	int                     pid = args->pid;
	user_addr_t             task_addr = args->t;

	proc_t                  proc = PROC_NULL;
	task_t                  t1 = TASK_NULL;
	task_inspect_t          task_insp = TASK_INSPECT_NULL;
	mach_port_name_t        tret = MACH_PORT_NULL;
	ipc_port_t              tfpport = MACH_PORT_NULL;
	int                     error = 0;
	void                    *sright = NULL;
	boolean_t               is_current_proc = FALSE;
	struct proc_ident       pident = {0};

	/* Disallow inspect port for kernel_task */
	if (pid == 0) {
		(void) copyout((char *)&t1, task_addr, sizeof(mach_port_name_t));
		return EPERM;
	}

	t1 = port_name_to_task(target_tport);
	if (t1 == TASK_NULL) {
		(void) copyout((char *) &t1, task_addr, sizeof(mach_port_name_t));
		return EINVAL;
	}

	proc = proc_find(pid);
	if (proc == PROC_NULL) {
		error = ESRCH;
		goto tifpout;
	}
	pident = proc_ident(proc);
	is_current_proc = (proc == current_proc());

	if (!(task_for_pid_posix_check(proc))) {
		error = EPERM;
		goto tifpout;
	}

	task_insp = proc->task;
	if (task_insp == TASK_INSPECT_NULL) {
		goto tifpout;
	}

	/*
	 * Grab a task reference and drop the proc reference before making any upcalls.
	 */
	task_reference(task_insp);

	proc_rele(proc);
	proc = PROC_NULL;

	/*
	 * For now, it performs the same set of permission checks as task_for_pid. This
	 * will be addressed in rdar://problem/53478660
	 */
#if CONFIG_MACF
	error = mac_proc_check_get_task(kauth_cred_get(), &pident);
	if (error) {
		error = EPERM;
		goto tifpout;
	}
#endif

	/* If we aren't root and target's task access port is set... */
	if (!kauth_cred_issuser(kauth_cred_get()) &&
	    !is_current_proc &&
	    (task_get_task_access_port(task_insp, &tfpport) == 0) &&
	    (tfpport != IPC_PORT_NULL)) {
		if (tfpport == IPC_PORT_DEAD) {
			error = EACCES;
			goto tifpout;
		}


		/* Call up to the task access server */
		error = __KERNEL_WAITING_ON_TASKGATED_CHECK_ACCESS_UPCALL__(tfpport, proc_selfpid(), kauth_getgid(), pid);

		if (error != MACH_MSG_SUCCESS) {
			if (error == MACH_RCV_INTERRUPTED) {
				error = EINTR;
			} else {
				error = EPERM;
			}
			goto tifpout;
		}
	}

	/* Check if the task has been corpsified */
	if (is_corpsetask(task_insp)) {
		error = EACCES;
		goto tifpout;
	}

	/* could be IP_NULL, consumes a ref */
	sright = (void*) convert_task_inspect_to_port(task_insp);
	task_insp = TASK_INSPECT_NULL;
	tret = ipc_port_copyout_send(sright, get_task_ipcspace(current_task()));

tifpout:
	task_deallocate(t1);
	(void) copyout((char *) &tret, task_addr, sizeof(mach_port_name_t));
	if (proc != PROC_NULL) {
		proc_rele(proc);
	}
	if (tfpport != IPC_PORT_NULL) {
		ipc_port_release_send(tfpport);
	}
	if (task_insp != TASK_INSPECT_NULL) {
		task_deallocate(task_insp);
	}

	*ret = error;
	return error;
}

/*
 *	Routine:	task_read_for_pid
 *	Purpose:
 *		Get the task read port for another "process", named by its
 *		process ID on the same host as "target_task".
 */
int
task_read_for_pid(struct proc *p __unused, struct task_read_for_pid_args *args, int *ret)
{
	mach_port_name_t        target_tport = args->target_tport;
	int                     pid = args->pid;
	user_addr_t             task_addr = args->t;

	proc_t                  proc = PROC_NULL;
	task_t                  t1 = TASK_NULL;
	task_read_t             task_read = TASK_READ_NULL;
	mach_port_name_t        tret = MACH_PORT_NULL;
	ipc_port_t              tfpport = MACH_PORT_NULL;
	int                     error = 0;
	void                    *sright = NULL;
	boolean_t               is_current_proc = FALSE;
	struct proc_ident       pident = {0};

	/* Disallow read port for kernel_task */
	if (pid == 0) {
		(void) copyout((char *)&t1, task_addr, sizeof(mach_port_name_t));
		return EPERM;
	}

	t1 = port_name_to_task(target_tport);
	if (t1 == TASK_NULL) {
		(void) copyout((char *) &t1, task_addr, sizeof(mach_port_name_t));
		return EINVAL;
	}

	proc = proc_find(pid);
	if (proc == PROC_NULL) {
		error = ESRCH;
		goto trfpout;
	}
	pident = proc_ident(proc);
	is_current_proc = (proc == current_proc());

	if (!(task_for_pid_posix_check(proc))) {
		error = EPERM;
		goto trfpout;
	}

	task_read = proc->task;
	if (task_read == TASK_INSPECT_NULL) {
		goto trfpout;
	}

	/*
	 * Grab a task reference and drop the proc reference before making any upcalls.
	 */
	task_reference(task_read);

	proc_rele(proc);
	proc = PROC_NULL;

	/*
	 * For now, it performs the same set of permission checks as task_for_pid. This
	 * will be addressed in rdar://problem/53478660
	 */
#if CONFIG_MACF
	error = mac_proc_check_get_task(kauth_cred_get(), &pident);
	if (error) {
		error = EPERM;
		goto trfpout;
	}
#endif

	/* If we aren't root and target's task access port is set... */
	if (!kauth_cred_issuser(kauth_cred_get()) &&
	    !is_current_proc &&
	    (task_get_task_access_port(task_read, &tfpport) == 0) &&
	    (tfpport != IPC_PORT_NULL)) {
		if (tfpport == IPC_PORT_DEAD) {
			error = EACCES;
			goto trfpout;
		}


		/* Call up to the task access server */
		error = __KERNEL_WAITING_ON_TASKGATED_CHECK_ACCESS_UPCALL__(tfpport, proc_selfpid(), kauth_getgid(), pid);

		if (error != MACH_MSG_SUCCESS) {
			if (error == MACH_RCV_INTERRUPTED) {
				error = EINTR;
			} else {
				error = EPERM;
			}
			goto trfpout;
		}
	}

	/* Check if the task has been corpsified */
	if (is_corpsetask(task_read)) {
		error = EACCES;
		goto trfpout;
	}

	/* could be IP_NULL, consumes a ref */
	sright = (void*) convert_task_read_to_port(task_read);
	task_read = TASK_READ_NULL;
	tret = ipc_port_copyout_send(sright, get_task_ipcspace(current_task()));

trfpout:
	task_deallocate(t1);
	(void) copyout((char *) &tret, task_addr, sizeof(mach_port_name_t));
	if (proc != PROC_NULL) {
		proc_rele(proc);
	}
	if (tfpport != IPC_PORT_NULL) {
		ipc_port_release_send(tfpport);
	}
	if (task_read != TASK_READ_NULL) {
		task_deallocate(task_read);
	}

	*ret = error;
	return error;
}

kern_return_t
pid_suspend(struct proc *p __unused, struct pid_suspend_args *args, int *ret)
{
	task_t  target = NULL;
	proc_t  targetproc = PROC_NULL;
	int     pid = args->pid;
	int     error = 0;
	mach_port_t tfpport = MACH_PORT_NULL;

	if (pid == 0) {
		error = EPERM;
		goto out;
	}

	targetproc = proc_find(pid);
	if (targetproc == PROC_NULL) {
		error = ESRCH;
		goto out;
	}

	if (!task_for_pid_posix_check(targetproc) &&
	    !IOTaskHasEntitlement(current_task(), PROCESS_RESUME_SUSPEND_ENTITLEMENT)) {
		error = EPERM;
		goto out;
	}

#if CONFIG_MACF
	error = mac_proc_check_suspend_resume(targetproc, MAC_PROC_CHECK_SUSPEND);
	if (error) {
		error = EPERM;
		goto out;
	}
#endif

	target = targetproc->task;
#ifndef CONFIG_EMBEDDED
	if (target != TASK_NULL) {
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
				if (error == MACH_RCV_INTERRUPTED) {
					error = EINTR;
				} else {
					error = EPERM;
				}
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
	if (tfpport != IPC_PORT_NULL) {
		ipc_port_release_send(tfpport);
	}

	if (targetproc != PROC_NULL) {
		proc_rele(targetproc);
	}
	*ret = error;
	return error;
}

kern_return_t
debug_control_port_for_pid(struct debug_control_port_for_pid_args *args)
{
	mach_port_name_t        target_tport = args->target_tport;
	int                     pid = args->pid;
	user_addr_t             task_addr = args->t;
	proc_t                  p = PROC_NULL;
	task_t                  t1 = TASK_NULL;
	task_t                  task = TASK_NULL;
	mach_port_name_t        tret = MACH_PORT_NULL;
	ipc_port_t              tfpport = MACH_PORT_NULL;
	ipc_port_t              sright = NULL;
	int                     error = 0;
	boolean_t               is_current_proc = FALSE;
	struct proc_ident       pident = {0};

	AUDIT_MACH_SYSCALL_ENTER(AUE_DBGPORTFORPID);
	AUDIT_ARG(pid, pid);
	AUDIT_ARG(mach_port1, target_tport);

	/* Always check if pid == 0 */
	if (pid == 0) {
		(void) copyout((char *)&t1, task_addr, sizeof(mach_port_name_t));
		AUDIT_MACH_SYSCALL_EXIT(KERN_FAILURE);
		return KERN_FAILURE;
	}

	t1 = port_name_to_task(target_tport);
	if (t1 == TASK_NULL) {
		(void) copyout((char *)&t1, task_addr, sizeof(mach_port_name_t));
		AUDIT_MACH_SYSCALL_EXIT(KERN_FAILURE);
		return KERN_FAILURE;
	}

	p = proc_find(pid);
	if (p == PROC_NULL) {
		error = KERN_FAILURE;
		goto tfpout;
	}
	pident = proc_ident(p);
	is_current_proc = (p == current_proc());

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

	/*
	 * Grab a task reference and drop the proc reference before making any upcalls.
	 */
	task = p->task;
	task_reference(task);

	proc_rele(p);
	p = PROC_NULL;

	if (!IOTaskHasEntitlement(current_task(), DEBUG_PORT_ENTITLEMENT)) {
#if CONFIG_MACF
		error = mac_proc_check_get_task(kauth_cred_get(), &pident);
		if (error) {
			error = KERN_FAILURE;
			goto tfpout;
		}
#endif

		/* If we aren't root and target's task access port is set... */
		if (!kauth_cred_issuser(kauth_cred_get()) &&
		    !is_current_proc &&
		    (task_get_task_access_port(task, &tfpport) == 0) &&
		    (tfpport != IPC_PORT_NULL)) {
			if (tfpport == IPC_PORT_DEAD) {
				error = KERN_PROTECTION_FAILURE;
				goto tfpout;
			}


			/* Call up to the task access server */
			error = __KERNEL_WAITING_ON_TASKGATED_CHECK_ACCESS_UPCALL__(tfpport, proc_selfpid(), kauth_getgid(), pid);

			if (error != MACH_MSG_SUCCESS) {
				if (error == MACH_RCV_INTERRUPTED) {
					error = KERN_ABORTED;
				} else {
					error = KERN_FAILURE;
				}
				goto tfpout;
			}
		}
	}

	/* Check if the task has been corpsified */
	if (is_corpsetask(task)) {
		error = KERN_FAILURE;
		goto tfpout;
	}

	error = task_get_debug_control_port(task, &sright);
	if (error != KERN_SUCCESS) {
		goto tfpout;
	}

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
	if (p != PROC_NULL) {
		proc_rele(p);
	}
	AUDIT_MACH_SYSCALL_EXIT(error);
	return error;
}

kern_return_t
pid_resume(struct proc *p __unused, struct pid_resume_args *args, int *ret)
{
	task_t  target = NULL;
	proc_t  targetproc = PROC_NULL;
	int     pid = args->pid;
	int     error = 0;
	mach_port_t tfpport = MACH_PORT_NULL;

	if (pid == 0) {
		error = EPERM;
		goto out;
	}

	targetproc = proc_find(pid);
	if (targetproc == PROC_NULL) {
		error = ESRCH;
		goto out;
	}

	if (!task_for_pid_posix_check(targetproc) &&
	    !IOTaskHasEntitlement(current_task(), PROCESS_RESUME_SUSPEND_ENTITLEMENT)) {
		error = EPERM;
		goto out;
	}

#if CONFIG_MACF
	error = mac_proc_check_suspend_resume(targetproc, MAC_PROC_CHECK_RESUME);
	if (error) {
		error = EPERM;
		goto out;
	}
#endif

	target = targetproc->task;
#ifndef CONFIG_EMBEDDED
	if (target != TASK_NULL) {
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
				if (error == MACH_RCV_INTERRUPTED) {
					error = EINTR;
				} else {
					error = EPERM;
				}
				goto out;
			}
		}
	}
#endif

#if !XNU_TARGET_OS_OSX
#if SOCKETS
	resume_proc_sockets(targetproc);
#endif /* SOCKETS */
#endif /* !XNU_TARGET_OS_OSX */

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
			} else {
				error = EPERM;
			}
		}
	}

	task_deallocate(target);

out:
	if (tfpport != IPC_PORT_NULL) {
		ipc_port_release_send(tfpport);
	}

	if (targetproc != PROC_NULL) {
		proc_rele(targetproc);
	}

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
	int     error = 0;
	proc_t  targetproc = PROC_NULL;
	int     pid = args->pid;

#ifndef CONFIG_FREEZE
	#pragma unused(pid)
#else

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

#if CONFIG_MACF
	//Note that targetproc may be null
	error = mac_proc_check_suspend_resume(targetproc, MAC_PROC_CHECK_HIBERNATE);
	if (error) {
		error = EPERM;
		goto out;
	}
#endif

	if (pid == -2) {
		vm_pageout_anonymous_pages();
	} else if (pid == -1) {
		memorystatus_on_inactivity(targetproc);
	} else {
		error = memorystatus_freeze_process_sync(targetproc);
	}

out:

#endif /* CONFIG_FREEZE */

	if (targetproc != PROC_NULL) {
		proc_rele(targetproc);
	}
	*ret = error;
	return error;
}
#endif /* CONFIG_EMBEDDED */

#if SOCKETS
int
networking_memstatus_callout(proc_t p, uint32_t status)
{
	struct fileproc *fp;

	/*
	 * proc list lock NOT held
	 * proc lock NOT held
	 * a reference on the proc has been held / shall be dropped by the caller.
	 */
	LCK_MTX_ASSERT(proc_list_mlock, LCK_MTX_ASSERT_NOTOWNED);
	LCK_MTX_ASSERT(&p->p_mlock, LCK_MTX_ASSERT_NOTOWNED);

	proc_fdlock(p);

	fdt_foreach(fp, p) {
		switch (FILEGLOB_DTYPE(fp->fp_glob)) {
#if NECP
		case DTYPE_NETPOLICY:
			necp_fd_memstatus(p, status,
			    (struct necp_fd_data *)fp->fp_glob->fg_data);
			break;
#endif /* NECP */
		default:
			break;
		}
	}
	proc_fdunlock(p);

	return 1;
}


static int
networking_defunct_callout(proc_t p, void *arg)
{
	struct pid_shutdown_sockets_args *args = arg;
	int pid = args->pid;
	int level = args->level;
	struct fileproc *fp;

	proc_fdlock(p);

	fdt_foreach(fp, p) {
		struct fileglob *fg = fp->fp_glob;

		switch (FILEGLOB_DTYPE(fg)) {
		case DTYPE_SOCKET: {
			struct socket *so = (struct socket *)fg->fg_data;
			if (p->p_pid == pid || so->last_pid == pid ||
			    ((so->so_flags & SOF_DELEGATED) && so->e_pid == pid)) {
				/* Call networking stack with socket and level */
				(void)socket_defunct(p, so, level);
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

	return PROC_RETURNED;
}

int
pid_shutdown_sockets(struct proc *p __unused, struct pid_shutdown_sockets_args *args, int *ret)
{
	int                             error = 0;
	proc_t                          targetproc = PROC_NULL;
	int                             pid = args->pid;
	int                             level = args->level;

	if (level != SHUTDOWN_SOCKET_LEVEL_DISCONNECT_SVC &&
	    level != SHUTDOWN_SOCKET_LEVEL_DISCONNECT_ALL) {
		error = EINVAL;
		goto out;
	}

	targetproc = proc_find(pid);
	if (targetproc == PROC_NULL) {
		error = ESRCH;
		goto out;
	}

	if (!task_for_pid_posix_check(targetproc) &&
	    !IOTaskHasEntitlement(current_task(), PROCESS_RESUME_SUSPEND_ENTITLEMENT)) {
		error = EPERM;
		goto out;
	}

#if CONFIG_MACF
	error = mac_proc_check_suspend_resume(targetproc, MAC_PROC_CHECK_SHUTDOWN_SOCKETS);
	if (error) {
		error = EPERM;
		goto out;
	}
#endif

	proc_iterate(PROC_ALLPROCLIST | PROC_NOWAITTRANS,
	    networking_defunct_callout, args, NULL, NULL);

out:
	if (targetproc != PROC_NULL) {
		proc_rele(targetproc);
	}
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
	if (error || req->newptr == USER_ADDR_NULL) {
		return error;
	}

	if (!kauth_cred_issuser(kauth_cred_get())) {
		return EPERM;
	}

	if ((error = SYSCTL_IN(req, &new_value, sizeof(int)))) {
		goto out;
	}
	if ((new_value == KERN_TFP_POLICY_DENY)
	    || (new_value == KERN_TFP_POLICY_DEFAULT)) {
		tfp_policy = new_value;
	} else {
		error = EINVAL;
	}
out:
	return error;
}

#if defined(SECURE_KERNEL)
static int kern_secure_kernel = 1;
#else
static int kern_secure_kernel = 0;
#endif

SYSCTL_INT(_kern, OID_AUTO, secure_kernel, CTLFLAG_RD | CTLFLAG_LOCKED, &kern_secure_kernel, 0, "");

SYSCTL_NODE(_kern, KERN_TFP, tfp, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "tfp");
SYSCTL_PROC(_kern_tfp, KERN_TFP_POLICY, policy, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &tfp_policy, sizeof(uint32_t), &sysctl_settfp_policy, "I", "policy");

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
	__unused struct proc                    *p,
	struct shared_region_check_np_args      *uap,
	__unused int                            *retvalp)
{
	vm_shared_region_t      shared_region;
	mach_vm_offset_t        start_address = 0;
	int                     error = 0;
	kern_return_t           kr;

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: %p [%d(%s)] -> check_np(0x%llx)\n",
		(void *)VM_KERNEL_ADDRPERM(current_thread()),
		p->p_pid, p->p_comm,
		(uint64_t)uap->start_address));

	/* retrieve the current tasks's shared region */
	shared_region = vm_shared_region_get(current_task());
	if (shared_region != NULL) {
		/* retrieve address of its first mapping... */
		kr = vm_shared_region_start_address(shared_region, &start_address);
		if (kr != KERN_SUCCESS) {
			error = ENOMEM;
		} else {
#if __has_feature(ptrauth_calls)
			/*
			 * Remap any section of the shared library that
			 * has authenticated pointers into private memory.
			 */
			if (vm_shared_region_auth_remap(shared_region) != KERN_SUCCESS) {
				error = ENOMEM;
			}
#endif /* __has_feature(ptrauth_calls) */

			/* ... and give it to the caller */
			if (error == 0) {
				error = copyout(&start_address,
				    (user_addr_t) uap->start_address,
				    sizeof(start_address));
			}
			if (error != 0) {
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


static int
shared_region_copyin(
	struct proc  *p,
	user_addr_t  user_addr,
	unsigned int count,
	unsigned int element_size,
	void         *kernel_data)
{
	int             error = 0;
	vm_size_t       size = count * element_size;

	error = copyin(user_addr, kernel_data, size);
	if (error) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(): "
			"copyin(0x%llx, %ld) failed (error=%d)\n",
			(void *)VM_KERNEL_ADDRPERM(current_thread()),
			p->p_pid, p->p_comm,
			(uint64_t)user_addr, (long)size, error));
	}
	return error;
}

#define _SR_FILE_MAPPINGS_MAX_FILES 2

/* forward declaration */
__attribute__((noinline))
static void shared_region_map_and_slide_cleanup(
	struct proc              *p,
	uint32_t                 files_count,
	struct _sr_file_mappings *sr_file_mappings,
	struct vm_shared_region  *shared_region,
	struct vnode             *scdir_vp);

/*
 * Setup part of _shared_region_map_and_slide().
 * It had to be broken out of _shared_region_map_and_slide() to
 * prevent compiler inlining from blowing out the stack.
 */
__attribute__((noinline))
static int
shared_region_map_and_slide_setup(
	struct proc                         *p,
	uint32_t                            files_count,
	struct shared_file_np               *files,
	uint32_t                            mappings_count,
	struct shared_file_mapping_slide_np *mappings,
	struct _sr_file_mappings            **sr_file_mappings,
	struct vm_shared_region             **shared_region_ptr,
	struct vnode                        **scdir_vp,
	struct vnode                        *rdir_vp)
{
	int                             error = 0;
	struct _sr_file_mappings        *srfmp;
	uint32_t                        mappings_next;
	struct vnode_attr               va;
	off_t                           fs;
#if CONFIG_MACF
	vm_prot_t                       maxprot = VM_PROT_ALL;
#endif
	uint32_t                        i;
	struct vm_shared_region         *shared_region;

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: %p [%d(%s)] -> map\n",
		(void *)VM_KERNEL_ADDRPERM(current_thread()),
		p->p_pid, p->p_comm));

	if (files_count > _SR_FILE_MAPPINGS_MAX_FILES) {
		error = E2BIG;
		goto done;
	}
	if (files_count == 0) {
		error = EINVAL;
		goto done;
	}
	*sr_file_mappings = kheap_alloc(KHEAP_TEMP, files_count * sizeof(struct _sr_file_mappings), Z_WAITOK);
	if (*sr_file_mappings == NULL) {
		error = ENOMEM;
		goto done;
	}
	bzero(*sr_file_mappings, files_count * sizeof(struct _sr_file_mappings));
	mappings_next = 0;
	for (i = 0; i < files_count; i++) {
		srfmp = &(*sr_file_mappings)[i];
		srfmp->fd = files[i].sf_fd;
		srfmp->mappings_count = files[i].sf_mappings_count;
		srfmp->mappings = &mappings[mappings_next];
		mappings_next += srfmp->mappings_count;
		if (mappings_next > mappings_count) {
			error = EINVAL;
			goto done;
		}
		srfmp->slide = files[i].sf_slide;
	}

	if (scdir_enforce) {
		/* get vnode for scdir_path */
		error = vnode_lookup(scdir_path, 0, scdir_vp, vfs_context_current());
		if (error) {
			SHARED_REGION_TRACE_ERROR(
				("shared_region: %p [%d(%s)]: "
				"vnode_lookup(%s) failed (error=%d)\n",
				(void *)VM_KERNEL_ADDRPERM(current_thread()),
				p->p_pid, p->p_comm,
				scdir_path, error));
			goto done;
		}
	}

	/* get the process's shared region (setup in vm_map_exec()) */
	shared_region = vm_shared_region_trim_and_get(current_task());
	*shared_region_ptr = shared_region;
	if (shared_region == NULL) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(): "
			"no shared region\n",
			(void *)VM_KERNEL_ADDRPERM(current_thread()),
			p->p_pid, p->p_comm));
		error = EINVAL;
		goto done;
	}

	/*
	 * Check the shared region matches the current root
	 * directory of this process.  Deny the mapping to
	 * avoid tainting the shared region with something that
	 * doesn't quite belong into it.
	 */
	struct vnode *sr_vnode = vm_shared_region_root_dir(shared_region);
	if (sr_vnode != NULL ?  rdir_vp != sr_vnode : rdir_vp != rootvnode) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: map(%p) root_dir mismatch\n",
			(void *)VM_KERNEL_ADDRPERM(current_thread())));
		error = EPERM;
		goto done;
	}


	for (srfmp = &(*sr_file_mappings)[0];
	    srfmp < &(*sr_file_mappings)[files_count];
	    srfmp++) {
		if (srfmp->mappings_count == 0) {
			/* no mappings here... */
			continue;
		}

		/* get file structure from file descriptor */
		error = fp_get_ftype(p, srfmp->fd, DTYPE_VNODE, EINVAL, &srfmp->fp);
		if (error) {
			SHARED_REGION_TRACE_ERROR(
				("shared_region: %p [%d(%s)] map: "
				"fd=%d lookup failed (error=%d)\n",
				(void *)VM_KERNEL_ADDRPERM(current_thread()),
				p->p_pid, p->p_comm, srfmp->fd, error));
			goto done;
		}

		/* we need at least read permission on the file */
		if (!(srfmp->fp->fp_glob->fg_flag & FREAD)) {
			SHARED_REGION_TRACE_ERROR(
				("shared_region: %p [%d(%s)] map: "
				"fd=%d not readable\n",
				(void *)VM_KERNEL_ADDRPERM(current_thread()),
				p->p_pid, p->p_comm, srfmp->fd));
			error = EPERM;
			goto done;
		}

		/* get vnode from file structure */
		error = vnode_getwithref((vnode_t) srfmp->fp->fp_glob->fg_data);
		if (error) {
			SHARED_REGION_TRACE_ERROR(
				("shared_region: %p [%d(%s)] map: "
				"fd=%d getwithref failed (error=%d)\n",
				(void *)VM_KERNEL_ADDRPERM(current_thread()),
				p->p_pid, p->p_comm, srfmp->fd, error));
			goto done;
		}
		srfmp->vp = (struct vnode *) srfmp->fp->fp_glob->fg_data;

		/* make sure the vnode is a regular file */
		if (srfmp->vp->v_type != VREG) {
			SHARED_REGION_TRACE_ERROR(
				("shared_region: %p [%d(%s)] map(%p:'%s'): "
				"not a file (type=%d)\n",
				(void *)VM_KERNEL_ADDRPERM(current_thread()),
				p->p_pid, p->p_comm,
				(void *)VM_KERNEL_ADDRPERM(srfmp->vp),
				srfmp->vp->v_name, srfmp->vp->v_type));
			error = EINVAL;
			goto done;
		}

#if CONFIG_MACF
		/* pass in 0 for the offset argument because AMFI does not need the offset
		 *       of the shared cache */
		error = mac_file_check_mmap(vfs_context_ucred(vfs_context_current()),
		    srfmp->fp->fp_glob, VM_PROT_ALL, MAP_FILE, 0, &maxprot);
		if (error) {
			goto done;
		}
#endif /* MAC */

#if XNU_TARGET_OS_OSX && defined(__arm64__)
		/*
		 * Check if the shared cache is in the trust cache;
		 * if so, we can skip the root ownership check.
		 */
#if DEVELOPMENT || DEBUG
		/*
		 * Skip both root ownership and trust cache check if
		 * enforcement is disabled.
		 */
		if (!cs_system_enforcement()) {
			goto after_root_check;
		}
#endif /* DEVELOPMENT || DEBUG */
		struct cs_blob *blob = csvnode_get_blob(srfmp->vp, 0);
		if (blob == NULL) {
			SHARED_REGION_TRACE_ERROR(
				("shared_region: %p [%d(%s)] map(%p:'%s'): "
				"missing CS blob\n",
				(void *)VM_KERNEL_ADDRPERM(current_thread()),
				p->p_pid, p->p_comm,
				(void *)VM_KERNEL_ADDRPERM(srfmp->vp),
				srfmp->vp->v_name));
			goto root_check;
		}
		const uint8_t *cdhash = csblob_get_cdhash(blob);
		if (cdhash == NULL) {
			SHARED_REGION_TRACE_ERROR(
				("shared_region: %p [%d(%s)] map(%p:'%s'): "
				"missing cdhash\n",
				(void *)VM_KERNEL_ADDRPERM(current_thread()),
				p->p_pid, p->p_comm,
				(void *)VM_KERNEL_ADDRPERM(srfmp->vp),
				srfmp->vp->v_name));
			goto root_check;
		}
		uint32_t result = pmap_lookup_in_static_trust_cache(cdhash);
		boolean_t in_trust_cache = result & (TC_LOOKUP_FOUND << TC_LOOKUP_RESULT_SHIFT);
		if (!in_trust_cache) {
			SHARED_REGION_TRACE_ERROR(
				("shared_region: %p [%d(%s)] map(%p:'%s'): "
				"not in trust cache\n",
				(void *)VM_KERNEL_ADDRPERM(current_thread()),
				p->p_pid, p->p_comm,
				(void *)VM_KERNEL_ADDRPERM(srfmp->vp),
				srfmp->vp->v_name));
			goto root_check;
		}
		goto after_root_check;
root_check:
#endif /* XNU_TARGET_OS_OSX && defined(__arm64__) */

		/* The shared cache file must be owned by root */
		VATTR_INIT(&va);
		VATTR_WANTED(&va, va_uid);
		error = vnode_getattr(srfmp->vp, &va, vfs_context_current());
		if (error) {
			SHARED_REGION_TRACE_ERROR(
				("shared_region: %p [%d(%s)] map(%p:'%s'): "
				"vnode_getattr(%p) failed (error=%d)\n",
				(void *)VM_KERNEL_ADDRPERM(current_thread()),
				p->p_pid, p->p_comm,
				(void *)VM_KERNEL_ADDRPERM(srfmp->vp),
				srfmp->vp->v_name,
				(void *)VM_KERNEL_ADDRPERM(srfmp->vp),
				error));
			goto done;
		}
		if (va.va_uid != 0) {
			SHARED_REGION_TRACE_ERROR(
				("shared_region: %p [%d(%s)] map(%p:'%s'): "
				"owned by uid=%d instead of 0\n",
				(void *)VM_KERNEL_ADDRPERM(current_thread()),
				p->p_pid, p->p_comm,
				(void *)VM_KERNEL_ADDRPERM(srfmp->vp),
				srfmp->vp->v_name, va.va_uid));
			error = EPERM;
			goto done;
		}

#if XNU_TARGET_OS_OSX && defined(__arm64__)
after_root_check:
#endif /* XNU_TARGET_OS_OSX && defined(__arm64__) */

#if CONFIG_CSR
		if (csr_check(CSR_ALLOW_UNRESTRICTED_FS) != 0) {
			VATTR_INIT(&va);
			VATTR_WANTED(&va, va_flags);
			error = vnode_getattr(srfmp->vp, &va, vfs_context_current());
			if (error) {
				SHARED_REGION_TRACE_ERROR(
					("shared_region: %p [%d(%s)] map(%p:'%s'): "
					"vnode_getattr(%p) failed (error=%d)\n",
					(void *)VM_KERNEL_ADDRPERM(current_thread()),
					p->p_pid, p->p_comm,
					(void *)VM_KERNEL_ADDRPERM(srfmp->vp),
					srfmp->vp->v_name,
					(void *)VM_KERNEL_ADDRPERM(srfmp->vp),
					error));
				goto done;
			}

			if (!(va.va_flags & SF_RESTRICTED)) {
				/*
				 * CSR is not configured in CSR_ALLOW_UNRESTRICTED_FS mode, and
				 * the shared cache file is NOT SIP-protected, so reject the
				 * mapping request
				 */
				SHARED_REGION_TRACE_ERROR(
					("shared_region: %p [%d(%s)] map(%p:'%s'), "
					"vnode is not SIP-protected. \n",
					(void *)VM_KERNEL_ADDRPERM(current_thread()),
					p->p_pid, p->p_comm,
					(void *)VM_KERNEL_ADDRPERM(srfmp->vp),
					srfmp->vp->v_name));
				error = EPERM;
				goto done;
			}
		}
#else /* CONFIG_CSR */
		/* Devices without SIP/ROSP need to make sure that the shared cache is on the root volume. */

		assert(rdir_vp != NULL);
		if (srfmp->vp->v_mount != rdir_vp->v_mount) {
			SHARED_REGION_TRACE_ERROR(
				("shared_region: %p [%d(%s)] map(%p:'%s'): "
				"not on process's root volume\n",
				(void *)VM_KERNEL_ADDRPERM(current_thread()),
				p->p_pid, p->p_comm,
				(void *)VM_KERNEL_ADDRPERM(srfmp->vp),
				srfmp->vp->v_name));
			error = EPERM;
			goto done;
		}
#endif /* CONFIG_CSR */

		if (scdir_enforce) {
			/* ensure parent is scdir_vp */
			assert(*scdir_vp != NULL);
			if (vnode_parent(srfmp->vp) != *scdir_vp) {
				SHARED_REGION_TRACE_ERROR(
					("shared_region: %p [%d(%s)] map(%p:'%s'): "
					"shared cache file not in %s\n",
					(void *)VM_KERNEL_ADDRPERM(current_thread()),
					p->p_pid, p->p_comm,
					(void *)VM_KERNEL_ADDRPERM(srfmp->vp),
					srfmp->vp->v_name, scdir_path));
				error = EPERM;
				goto done;
			}
		}

		/* get vnode size */
		error = vnode_size(srfmp->vp, &fs, vfs_context_current());
		if (error) {
			SHARED_REGION_TRACE_ERROR(
				("shared_region: %p [%d(%s)] map(%p:'%s'): "
				"vnode_size(%p) failed (error=%d)\n",
				(void *)VM_KERNEL_ADDRPERM(current_thread()),
				p->p_pid, p->p_comm,
				(void *)VM_KERNEL_ADDRPERM(srfmp->vp),
				srfmp->vp->v_name,
				(void *)VM_KERNEL_ADDRPERM(srfmp->vp), error));
			goto done;
		}
		srfmp->file_size = fs;

		/* get the file's memory object handle */
		srfmp->file_control = ubc_getobject(srfmp->vp, UBC_HOLDOBJECT);
		if (srfmp->file_control == MEMORY_OBJECT_CONTROL_NULL) {
			SHARED_REGION_TRACE_ERROR(
				("shared_region: %p [%d(%s)] map(%p:'%s'): "
				"no memory object\n",
				(void *)VM_KERNEL_ADDRPERM(current_thread()),
				p->p_pid, p->p_comm,
				(void *)VM_KERNEL_ADDRPERM(srfmp->vp),
				srfmp->vp->v_name));
			error = EINVAL;
			goto done;
		}

		/* check that the mappings are properly covered by code signatures */
		if (!cs_system_enforcement()) {
			/* code signing is not enforced: no need to check */
		} else {
			for (i = 0; i < srfmp->mappings_count; i++) {
				if (srfmp->mappings[i].sms_init_prot & VM_PROT_ZF) {
					/* zero-filled mapping: not backed by the file */
					continue;
				}
				if (ubc_cs_is_range_codesigned(srfmp->vp,
				    srfmp->mappings[i].sms_file_offset,
				    srfmp->mappings[i].sms_size)) {
					/* this mapping is fully covered by code signatures */
					continue;
				}
				SHARED_REGION_TRACE_ERROR(
					("shared_region: %p [%d(%s)] map(%p:'%s'): "
					"mapping #%d/%d [0x%llx:0x%llx:0x%llx:0x%x:0x%x] "
					"is not code-signed\n",
					(void *)VM_KERNEL_ADDRPERM(current_thread()),
					p->p_pid, p->p_comm,
					(void *)VM_KERNEL_ADDRPERM(srfmp->vp),
					srfmp->vp->v_name,
					i, srfmp->mappings_count,
					srfmp->mappings[i].sms_address,
					srfmp->mappings[i].sms_size,
					srfmp->mappings[i].sms_file_offset,
					srfmp->mappings[i].sms_max_prot,
					srfmp->mappings[i].sms_init_prot));
				error = EINVAL;
				goto done;
			}
		}
	}
done:
	if (error != 0) {
		shared_region_map_and_slide_cleanup(p, files_count, *sr_file_mappings, shared_region, *scdir_vp);
		*sr_file_mappings = NULL;
		*shared_region_ptr = NULL;
		*scdir_vp = NULL;
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
static int
_shared_region_map_and_slide(
	struct proc                         *p,
	uint32_t                            files_count,
	struct shared_file_np               *files,
	uint32_t                            mappings_count,
	struct shared_file_mapping_slide_np *mappings)
{
	int                             error = 0;
	kern_return_t                   kr = KERN_SUCCESS;
	struct _sr_file_mappings        *sr_file_mappings = NULL;
	struct vnode                    *scdir_vp = NULL;
	struct vnode                    *rdir_vp = NULL;
	struct vm_shared_region         *shared_region = NULL;

	/*
	 * Get a reference to the current proc's root dir.
	 * Need this to prevent racing with chroot.
	 */
	proc_fdlock(p);
	rdir_vp = p->p_fd->fd_rdir;
	if (rdir_vp == NULL) {
		rdir_vp = rootvnode;
	}
	assert(rdir_vp != NULL);
	vnode_get(rdir_vp);
	proc_fdunlock(p);

	/*
	 * Turn files, mappings into sr_file_mappings and other setup.
	 */
	error = shared_region_map_and_slide_setup(p, files_count,
	    files, mappings_count, mappings,
	    &sr_file_mappings, &shared_region, &scdir_vp, rdir_vp);
	if (error != 0) {
		vnode_put(rdir_vp);
		return error;
	}

	/* map the file(s) into that shared region's submap */
	kr = vm_shared_region_map_file(shared_region, files_count, sr_file_mappings);
	if (kr != KERN_SUCCESS) {
		SHARED_REGION_TRACE_ERROR(("shared_region: %p [%d(%s)] map(): "
		    "vm_shared_region_map_file() failed kr=0x%x\n",
		    (void *)VM_KERNEL_ADDRPERM(current_thread()),
		    p->p_pid, p->p_comm, kr));
	}

	/* convert kern_return_t to errno */
	switch (kr) {
	case KERN_SUCCESS:
		error = 0;
		break;
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

	/*
	 * Mark that this process is now using split libraries.
	 */
	if (error == 0 && (p->p_flag & P_NOSHLIB)) {
		OSBitAndAtomic(~((uint32_t)P_NOSHLIB), &p->p_flag);
	}

	vnode_put(rdir_vp);
	shared_region_map_and_slide_cleanup(p, files_count, sr_file_mappings, shared_region, scdir_vp);

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: %p [%d(%s)] <- map\n",
		(void *)VM_KERNEL_ADDRPERM(current_thread()),
		p->p_pid, p->p_comm));

	return error;
}

/*
 * Clean up part of _shared_region_map_and_slide()
 * It had to be broken out of _shared_region_map_and_slide() to
 * prevent compiler inlining from blowing out the stack.
 */
__attribute__((noinline))
static void
shared_region_map_and_slide_cleanup(
	struct proc              *p,
	uint32_t                 files_count,
	struct _sr_file_mappings *sr_file_mappings,
	struct vm_shared_region  *shared_region,
	struct vnode             *scdir_vp)
{
	struct _sr_file_mappings *srfmp;
	struct vnode_attr        va;

	if (sr_file_mappings != NULL) {
		for (srfmp = &sr_file_mappings[0]; srfmp < &sr_file_mappings[files_count]; srfmp++) {
			if (srfmp->vp != NULL) {
				vnode_lock_spin(srfmp->vp);
				srfmp->vp->v_flag |= VSHARED_DYLD;
				vnode_unlock(srfmp->vp);

				/* update the vnode's access time */
				if (!(vnode_vfsvisflags(srfmp->vp) & MNT_NOATIME)) {
					VATTR_INIT(&va);
					nanotime(&va.va_access_time);
					VATTR_SET_ACTIVE(&va, va_access_time);
					vnode_setattr(srfmp->vp, &va, vfs_context_current());
				}

#if NAMEDSTREAMS
				/*
				 * If the shared cache is compressed, it may
				 * have a namedstream vnode instantiated for
				 * for it. That namedstream vnode will also
				 * have to be marked with VSHARED_DYLD.
				 */
				if (vnode_hasnamedstreams(srfmp->vp)) {
					vnode_t svp;
					if (vnode_getnamedstream(srfmp->vp, &svp, XATTR_RESOURCEFORK_NAME,
					    NS_OPEN, 0, vfs_context_kernel()) == 0) {
						vnode_lock_spin(svp);
						svp->v_flag |= VSHARED_DYLD;
						vnode_unlock(svp);
						vnode_put(svp);
					}
				}
#endif /* NAMEDSTREAMS */
				/*
				 * release the vnode...
				 * ubc_map() still holds it for us in the non-error case
				 */
				(void) vnode_put(srfmp->vp);
				srfmp->vp = NULL;
			}
			if (srfmp->fp != NULL) {
				/* release the file descriptor */
				fp_drop(p, srfmp->fd, srfmp->fp, 0);
				srfmp->fp = NULL;
			}
		}
		kheap_free(KHEAP_TEMP, sr_file_mappings, files_count * sizeof(*sr_file_mappings));
	}

	if (scdir_vp != NULL) {
		(void)vnode_put(scdir_vp);
		scdir_vp = NULL;
	}

	if (shared_region != NULL) {
		vm_shared_region_deallocate(shared_region);
	}
}


#define SFM_MAX       1024    /* max mapping structs allowed to pass in */

/*
 * This interface is used by dyld to map shared caches which are
 * for any architecture which doesn't have run time support of pointer
 * authentication. Note dyld could also use the new ...map_and_slide_2_np()
 * call for this case, however, it just doesn't do that yet.
 */
int
shared_region_map_and_slide_np(
	struct proc                                *p,
	struct shared_region_map_and_slide_np_args *uap,
	__unused int                               *retvalp)
{
	unsigned int                        mappings_count = uap->count;
	unsigned int                        m;
	uint32_t                            slide = uap->slide;
	struct shared_file_np               shared_files[1];
	struct shared_file_mapping_np       legacy_mapping;
	struct shared_file_mapping_slide_np *mappings = NULL;
	kern_return_t                       kr = KERN_SUCCESS;

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
		kr = 0; /* no mappings: we're done ! */
		goto done;
	} else if (mappings_count <= SFM_MAX) {
		mappings = kheap_alloc(KHEAP_TEMP,
		    mappings_count * sizeof(mappings[0]), Z_WAITOK);
		if (mappings == NULL) {
			kr = KERN_RESOURCE_SHORTAGE;
			goto done;
		}
	} else {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(): "
			"too many mappings (%d) max %d\n",
			(void *)VM_KERNEL_ADDRPERM(current_thread()),
			p->p_pid, p->p_comm,
			mappings_count, SFM_MAX));
		kr = KERN_FAILURE;
		goto done;
	}

	/*
	 * Read in the mappings and translate to new format.
	 */
	for (m = 0; m < mappings_count; ++m) {
		user_addr_t from_uaddr = uap->mappings + (m * sizeof(struct shared_file_mapping_np));
		kr = shared_region_copyin(p, from_uaddr, 1, sizeof(legacy_mapping), &legacy_mapping);
		if (kr != 0) {
			goto done;
		}
		mappings[m].sms_address = legacy_mapping.sfm_address;
		mappings[m].sms_size = legacy_mapping.sfm_size;
		mappings[m].sms_file_offset = legacy_mapping.sfm_file_offset;
		mappings[m].sms_max_prot = legacy_mapping.sfm_max_prot;
		mappings[m].sms_init_prot = legacy_mapping.sfm_init_prot;
		mappings[m].sms_slide_size = uap->slide_size;
		mappings[m].sms_slide_start = uap->slide_start;
	}

	bzero(shared_files, sizeof(shared_files));
	shared_files[0].sf_fd = uap->fd;
	shared_files[0].sf_mappings_count = mappings_count;
	shared_files[0].sf_slide = slide;

	kr = _shared_region_map_and_slide(p,
	    1,                 /* # of files to map */
	    &shared_files[0],  /* files to map */
	    mappings_count,
	    mappings);

done:
	if (mappings != NULL) {
		kheap_free(KHEAP_TEMP, mappings, mappings_count * sizeof(mappings[0]));
		mappings = NULL;
	}
	return kr;
}

/*
 * This interface for setting up shared region mappings is what dyld
 * uses for shared caches that have __AUTH sections. All other shared
 * caches use the non _2 version.
 *
 * The slide used for shared regions setup using this interface is done differently
 * from the old interface. The slide value passed in the shared_files_np represents
 * a max value. The kernel will choose a random value based on that, then use it
 * for all shared regions.
 */
#define SLIDE_AMOUNT_MASK ~PAGE_MASK

int
shared_region_map_and_slide_2_np(
	struct proc                                  *p,
	struct shared_region_map_and_slide_2_np_args *uap,
	__unused int                                 *retvalp)
{
	unsigned int                  files_count;
	struct shared_file_np         *shared_files = NULL;
	unsigned int                  mappings_count;
	struct shared_file_mapping_slide_np *mappings = NULL;
	kern_return_t                 kr = KERN_SUCCESS;
	boolean_t                     should_slide_mappings = TRUE;

	files_count = uap->files_count;
	mappings_count = uap->mappings_count;


	if (files_count == 0) {
		SHARED_REGION_TRACE_INFO(
			("shared_region: %p [%d(%s)] map(): "
			"no files\n",
			(void *)VM_KERNEL_ADDRPERM(current_thread()),
			p->p_pid, p->p_comm));
		kr = 0; /* no files to map: we're done ! */
		goto done;
	} else if (files_count <= _SR_FILE_MAPPINGS_MAX_FILES) {
		shared_files = kheap_alloc(KHEAP_TEMP,
		    files_count * sizeof(shared_files[0]), Z_WAITOK);
		if (shared_files == NULL) {
			kr = KERN_RESOURCE_SHORTAGE;
			goto done;
		}
	} else {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(): "
			"too many files (%d) max %d\n",
			(void *)VM_KERNEL_ADDRPERM(current_thread()),
			p->p_pid, p->p_comm,
			files_count, _SR_FILE_MAPPINGS_MAX_FILES));
		kr = KERN_FAILURE;
		goto done;
	}

	if (mappings_count == 0) {
		SHARED_REGION_TRACE_INFO(
			("shared_region: %p [%d(%s)] map(): "
			"no mappings\n",
			(void *)VM_KERNEL_ADDRPERM(current_thread()),
			p->p_pid, p->p_comm));
		kr = 0; /* no mappings: we're done ! */
		goto done;
	} else if (mappings_count <= SFM_MAX) {
		mappings = kheap_alloc(KHEAP_TEMP,
		    mappings_count * sizeof(mappings[0]), Z_WAITOK);
		if (mappings == NULL) {
			kr = KERN_RESOURCE_SHORTAGE;
			goto done;
		}
	} else {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(): "
			"too many mappings (%d) max %d\n",
			(void *)VM_KERNEL_ADDRPERM(current_thread()),
			p->p_pid, p->p_comm,
			mappings_count, SFM_MAX));
		kr = KERN_FAILURE;
		goto done;
	}

	kr = shared_region_copyin(p, uap->files, files_count, sizeof(shared_files[0]), shared_files);
	if (kr != KERN_SUCCESS) {
		goto done;
	}

	kr = shared_region_copyin(p, uap->mappings, mappings_count, sizeof(mappings[0]), mappings);
	if (kr != KERN_SUCCESS) {
		goto done;
	}

	if (should_slide_mappings) {
		uint32_t max_slide = shared_files[0].sf_slide;
		uint32_t random_val;
		uint32_t slide_amount;

		if (max_slide != 0) {
			read_random(&random_val, sizeof random_val);
			slide_amount = ((random_val % max_slide) & SLIDE_AMOUNT_MASK);
		} else {
			slide_amount = 0;
		}

		/*
		 * Fix up the mappings to reflect the desired slide.
		 */
		unsigned int f;
		unsigned int m = 0;
		unsigned int i;
		for (f = 0; f < files_count; ++f) {
			shared_files[f].sf_slide = slide_amount;
			for (i = 0; i < shared_files[f].sf_mappings_count; ++i, ++m) {
				if (m >= mappings_count) {
					SHARED_REGION_TRACE_ERROR(
						("shared_region: %p [%d(%s)] map(): "
						"mapping count argument was too small\n",
						(void *)VM_KERNEL_ADDRPERM(current_thread()),
						p->p_pid, p->p_comm));
					kr = KERN_FAILURE;
					goto done;
				}
				mappings[m].sms_address += slide_amount;
				if (mappings[m].sms_slide_size != 0) {
					mappings[i].sms_slide_start += slide_amount;
				}
			}
		}
	}
	kr = _shared_region_map_and_slide(p, files_count, shared_files, mappings_count, mappings);
done:
	if (shared_files != NULL) {
		kheap_free(KHEAP_TEMP, shared_files, files_count * sizeof(shared_files[0]));
		shared_files = NULL;
	}
	if (mappings != NULL) {
		kheap_free(KHEAP_TEMP, mappings, mappings_count * sizeof(mappings[0]));
		mappings = NULL;
	}
	return kr;
}

/* sysctl overflow room */

SYSCTL_INT(_vm, OID_AUTO, pagesize, CTLFLAG_RD | CTLFLAG_LOCKED,
    (int *) &page_size, 0, "vm page size");

/* vm_page_free_target is provided as a makeshift solution for applications that want to
 *       allocate buffer space, possibly purgeable memory, but not cause inactive pages to be
 *       reclaimed. It allows the app to calculate how much memory is free outside the free target. */
extern unsigned int     vm_page_free_target;
SYSCTL_INT(_vm, OID_AUTO, vm_page_free_target, CTLFLAG_RD | CTLFLAG_LOCKED,
    &vm_page_free_target, 0, "Pageout daemon free target");

SYSCTL_INT(_vm, OID_AUTO, memory_pressure, CTLFLAG_RD | CTLFLAG_LOCKED,
    &vm_pageout_state.vm_memory_pressure, 0, "Memory pressure indicator");

static int
vm_ctl_page_free_wanted SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int page_free_wanted;

	page_free_wanted = mach_vm_ctl_page_free_wanted();
	return SYSCTL_OUT(req, &page_free_wanted, sizeof(page_free_wanted));
}
SYSCTL_PROC(_vm, OID_AUTO, page_free_wanted,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, vm_ctl_page_free_wanted, "I", "");

extern unsigned int     vm_page_purgeable_count;
SYSCTL_INT(_vm, OID_AUTO, page_purgeable_count, CTLFLAG_RD | CTLFLAG_LOCKED,
    &vm_page_purgeable_count, 0, "Purgeable page count");

extern unsigned int     vm_page_purgeable_wired_count;
SYSCTL_INT(_vm, OID_AUTO, page_purgeable_wired_count, CTLFLAG_RD | CTLFLAG_LOCKED,
    &vm_page_purgeable_wired_count, 0, "Wired purgeable page count");

extern unsigned int vm_page_kern_lpage_count;
SYSCTL_INT(_vm, OID_AUTO, kern_lpage_count, CTLFLAG_RD | CTLFLAG_LOCKED,
    &vm_page_kern_lpage_count, 0, "kernel used large pages");

#if DEVELOPMENT || DEBUG
#if __ARM_MIXED_PAGE_SIZE__
static int vm_mixed_pagesize_supported = 1;
#else
static int vm_mixed_pagesize_supported = 0;
#endif /*__ARM_MIXED_PAGE_SIZE__ */
SYSCTL_INT(_debug, OID_AUTO, vm_mixed_pagesize_supported, CTLFLAG_ANYBODY | CTLFLAG_RD | CTLFLAG_LOCKED,
    &vm_mixed_pagesize_supported, 0, "kernel support for mixed pagesize");


extern uint64_t get_pages_grabbed_count(void);

static int
pages_grabbed SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	uint64_t value = get_pages_grabbed_count();
	return SYSCTL_OUT(req, &value, sizeof(value));
}

SYSCTL_PROC(_vm, OID_AUTO, pages_grabbed, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, &pages_grabbed, "QU", "Total pages grabbed");
SYSCTL_ULONG(_vm, OID_AUTO, pages_freed, CTLFLAG_RD | CTLFLAG_LOCKED,
    &vm_pageout_vminfo.vm_page_pages_freed, "Total pages freed");

SYSCTL_INT(_vm, OID_AUTO, pageout_purged_objects, CTLFLAG_RD | CTLFLAG_LOCKED,
    &vm_pageout_debug.vm_pageout_purged_objects, 0, "System purged object count");
SYSCTL_UINT(_vm, OID_AUTO, pageout_cleaned_busy, CTLFLAG_RD | CTLFLAG_LOCKED,
    &vm_pageout_debug.vm_pageout_cleaned_busy, 0, "Cleaned pages busy (deactivated)");
SYSCTL_UINT(_vm, OID_AUTO, pageout_cleaned_nolock, CTLFLAG_RD | CTLFLAG_LOCKED,
    &vm_pageout_debug.vm_pageout_cleaned_nolock, 0, "Cleaned pages no-lock (deactivated)");

SYSCTL_UINT(_vm, OID_AUTO, pageout_cleaned_volatile_reactivated, CTLFLAG_RD | CTLFLAG_LOCKED,
    &vm_pageout_debug.vm_pageout_cleaned_volatile_reactivated, 0, "Cleaned pages volatile reactivated");
SYSCTL_UINT(_vm, OID_AUTO, pageout_cleaned_fault_reactivated, CTLFLAG_RD | CTLFLAG_LOCKED,
    &vm_pageout_debug.vm_pageout_cleaned_fault_reactivated, 0, "Cleaned pages fault reactivated");
SYSCTL_UINT(_vm, OID_AUTO, pageout_cleaned_reactivated, CTLFLAG_RD | CTLFLAG_LOCKED,
    &vm_pageout_debug.vm_pageout_cleaned_reactivated, 0, "Cleaned pages reactivated");         /* sum of all reactivated AND busy and nolock (even though those actually get reDEactivated */
SYSCTL_ULONG(_vm, OID_AUTO, pageout_cleaned, CTLFLAG_RD | CTLFLAG_LOCKED,
    &vm_pageout_vminfo.vm_pageout_freed_cleaned, "Cleaned pages freed");
SYSCTL_UINT(_vm, OID_AUTO, pageout_cleaned_reference_reactivated, CTLFLAG_RD | CTLFLAG_LOCKED,
    &vm_pageout_debug.vm_pageout_cleaned_reference_reactivated, 0, "Cleaned pages reference reactivated");
SYSCTL_UINT(_vm, OID_AUTO, pageout_enqueued_cleaned, CTLFLAG_RD | CTLFLAG_LOCKED,
    &vm_pageout_debug.vm_pageout_enqueued_cleaned, 0, "");         /* sum of next two */
#endif /* DEVELOPMENT || DEBUG */

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
SYSCTL_UINT(_vm, OID_AUTO, pageout_inactive_clean, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_state.vm_pageout_inactive_clean, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, pageout_inactive_used, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_state.vm_pageout_inactive_used, 0, "");

SYSCTL_ULONG(_vm, OID_AUTO, pageout_inactive_dirty_internal, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_vminfo.vm_pageout_inactive_dirty_internal, "");
SYSCTL_ULONG(_vm, OID_AUTO, pageout_inactive_dirty_external, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_vminfo.vm_pageout_inactive_dirty_external, "");
SYSCTL_ULONG(_vm, OID_AUTO, pageout_speculative_clean, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_vminfo.vm_pageout_freed_speculative, "");
SYSCTL_ULONG(_vm, OID_AUTO, pageout_freed_external, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_vminfo.vm_pageout_freed_external, "");
SYSCTL_ULONG(_vm, OID_AUTO, pageout_freed_speculative, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_vminfo.vm_pageout_freed_speculative, "");
SYSCTL_ULONG(_vm, OID_AUTO, pageout_freed_cleaned, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_pageout_vminfo.vm_pageout_freed_cleaned, "");


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
extern unsigned int vm_page_secluded_count_over_target;
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_target, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded_target, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_count, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded_count, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_count_free, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded_count_free, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_count_inuse, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded_count_inuse, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_count_over_target, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded_count_over_target, 0, "");

extern struct vm_page_secluded_data vm_page_secluded;
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_eligible, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded.eligible_for_secluded, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_grab_success_free, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded.grab_success_free, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_grab_success_other, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded.grab_success_other, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_grab_failure_locked, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded.grab_failure_locked, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_grab_failure_state, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded.grab_failure_state, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_grab_failure_dirty, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded.grab_failure_dirty, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_grab_for_iokit, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded.grab_for_iokit, 0, "");
SYSCTL_UINT(_vm, OID_AUTO, page_secluded_grab_for_iokit_success, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_secluded.grab_for_iokit_success, 0, "");

#endif /* CONFIG_SECLUDED_MEMORY */

#include <kern/thread.h>
#include <sys/user.h>

void vm_pageout_io_throttle(void);

void
vm_pageout_io_throttle(void)
{
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
	kern_return_t   kr;
	uint32_t        pages_reclaimed;
	uint32_t        pages_wanted;

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
		    sizeof(pages_reclaimed)) != 0) {
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
#ifndef CONFIG_KAS_INFO
	(void)p;
	(void)uap;
	return ENOTSUP;
#else /* CONFIG_KAS_INFO */
	int                     selector = uap->selector;
	user_addr_t     valuep = uap->value;
	user_addr_t     sizep = uap->size;
	user_size_t size, rsize;
	int                     error;

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

		error = copyout(&slide, valuep, sizeof(slide));
		if (error) {
			return error;
		}
		rsize = size;
	}
	break;
	case KAS_INFO_KERNEL_SEGMENT_VMADDR_SELECTOR:
	{
		uint32_t i;
		kernel_mach_header_t *mh = &_mh_execute_header;
		struct load_command *cmd;
		cmd = (struct load_command*) &mh[1];
		uint64_t *bases;
		rsize = mh->ncmds * sizeof(uint64_t);

		/*
		 * Return the size if no data was passed
		 */
		if (valuep == 0) {
			break;
		}

		if (rsize > size) {
			return EINVAL;
		}

		bases = kheap_alloc(KHEAP_TEMP, rsize, Z_WAITOK | Z_ZERO);

		for (i = 0; i < mh->ncmds; i++) {
			if (cmd->cmd == LC_SEGMENT_KERNEL) {
				__IGNORE_WCASTALIGN(kernel_segment_command_t * sg = (kernel_segment_command_t *) cmd);
				bases[i] = (uint64_t)sg->vmaddr;
			}
			cmd = (struct load_command *) ((uintptr_t) cmd + cmd->cmdsize);
		}

		error = copyout(bases, valuep, rsize);

		kheap_free(KHEAP_TEMP, bases, rsize);

		if (error) {
			return error;
		}
	}
	break;
	default:
		return EINVAL;
	}

	if (IS_64BIT_PROCESS(p)) {
		user64_size_t size64 = (user64_size_t)rsize;
		error = copyout(&size64, sizep, sizeof(size64));
	} else {
		user32_size_t size32 = (user32_size_t)rsize;
		error = copyout(&size32, sizep, sizeof(size32));
	}

	return error;
#endif /* CONFIG_KAS_INFO */
}

#if __has_feature(ptrauth_calls)
/*
 * Generate a random pointer signing key that isn't 0.
 */
uint64_t
generate_jop_key(void)
{
	uint64_t key;

	do {
		read_random(&key, sizeof key);
	} while (key == 0);
	return key;
}
#endif /* __has_feature(ptrauth_calls) */


#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
#pragma clang diagnostic ignored "-Wunused-function"

static void
asserts()
{
	static_assert(sizeof(vm_min_kernel_address) == sizeof(unsigned long));
	static_assert(sizeof(vm_max_kernel_address) == sizeof(unsigned long));
}

SYSCTL_ULONG(_vm, OID_AUTO, vm_min_kernel_address, CTLFLAG_RD, (unsigned long *) &vm_min_kernel_address, "");
SYSCTL_ULONG(_vm, OID_AUTO, vm_max_kernel_address, CTLFLAG_RD, (unsigned long *) &vm_max_kernel_address, "");
#pragma clang diagnostic pop

extern uint32_t vm_page_pages;
SYSCTL_UINT(_vm, OID_AUTO, pages, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_pages, 0, "");

extern uint32_t vm_page_busy_absent_skipped;
SYSCTL_UINT(_vm, OID_AUTO, page_busy_absent_skipped, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_busy_absent_skipped, 0, "");

extern uint32_t vm_page_upl_tainted;
SYSCTL_UINT(_vm, OID_AUTO, upl_pages_tainted, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_upl_tainted, 0, "");

extern uint32_t vm_page_iopl_tainted;
SYSCTL_UINT(_vm, OID_AUTO, iopl_pages_tainted, CTLFLAG_RD | CTLFLAG_LOCKED, &vm_page_iopl_tainted, 0, "");

#if (__arm__ || __arm64__) && (DEVELOPMENT || DEBUG)
extern int vm_footprint_suspend_allowed;
SYSCTL_INT(_vm, OID_AUTO, footprint_suspend_allowed, CTLFLAG_RW | CTLFLAG_LOCKED, &vm_footprint_suspend_allowed, 0, "");

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
	if (!vm_footprint_suspend_allowed) {
		if (new_value != 0) {
			/* suspends are not allowed... */
			return 0;
		}
		/* ... but let resumes proceed */
	}
	DTRACE_VM2(footprint_suspend,
	    vm_map_t, current_map(),
	    int, new_value);

	pmap_footprint_suspend(current_map(), new_value);

	return 0;
}
SYSCTL_PROC(_vm, OID_AUTO, footprint_suspend,
    CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_ANYBODY | CTLFLAG_LOCKED | CTLFLAG_MASKED,
    0, 0, &sysctl_vm_footprint_suspend, "I", "");
#endif /* (__arm__ || __arm64__) && (DEVELOPMENT || DEBUG) */

extern uint64_t vm_map_corpse_footprint_count;
extern uint64_t vm_map_corpse_footprint_size_avg;
extern uint64_t vm_map_corpse_footprint_size_max;
extern uint64_t vm_map_corpse_footprint_full;
extern uint64_t vm_map_corpse_footprint_no_buf;
SYSCTL_QUAD(_vm, OID_AUTO, corpse_footprint_count,
    CTLFLAG_RD | CTLFLAG_LOCKED, &vm_map_corpse_footprint_count, "");
SYSCTL_QUAD(_vm, OID_AUTO, corpse_footprint_size_avg,
    CTLFLAG_RD | CTLFLAG_LOCKED, &vm_map_corpse_footprint_size_avg, "");
SYSCTL_QUAD(_vm, OID_AUTO, corpse_footprint_size_max,
    CTLFLAG_RD | CTLFLAG_LOCKED, &vm_map_corpse_footprint_size_max, "");
SYSCTL_QUAD(_vm, OID_AUTO, corpse_footprint_full,
    CTLFLAG_RD | CTLFLAG_LOCKED, &vm_map_corpse_footprint_full, "");
SYSCTL_QUAD(_vm, OID_AUTO, corpse_footprint_no_buf,
    CTLFLAG_RD | CTLFLAG_LOCKED, &vm_map_corpse_footprint_no_buf, "");


extern uint64_t shared_region_pager_copied;
extern uint64_t shared_region_pager_slid;
extern uint64_t shared_region_pager_slid_error;
extern uint64_t shared_region_pager_reclaimed;
SYSCTL_QUAD(_vm, OID_AUTO, shared_region_pager_copied,
    CTLFLAG_RD | CTLFLAG_LOCKED, &shared_region_pager_copied, "");
SYSCTL_QUAD(_vm, OID_AUTO, shared_region_pager_slid,
    CTLFLAG_RD | CTLFLAG_LOCKED, &shared_region_pager_slid, "");
SYSCTL_QUAD(_vm, OID_AUTO, shared_region_pager_slid_error,
    CTLFLAG_RD | CTLFLAG_LOCKED, &shared_region_pager_slid_error, "");
SYSCTL_QUAD(_vm, OID_AUTO, shared_region_pager_reclaimed,
    CTLFLAG_RD | CTLFLAG_LOCKED, &shared_region_pager_reclaimed, "");
extern int shared_region_destroy_delay;
SYSCTL_INT(_vm, OID_AUTO, shared_region_destroy_delay,
    CTLFLAG_RW | CTLFLAG_LOCKED, &shared_region_destroy_delay, 0, "");

#if MACH_ASSERT
extern int pmap_ledgers_panic_leeway;
SYSCTL_INT(_vm, OID_AUTO, pmap_ledgers_panic_leeway, CTLFLAG_RW | CTLFLAG_LOCKED, &pmap_ledgers_panic_leeway, 0, "");
#endif /* MACH_ASSERT */

extern int vm_protect_privileged_from_untrusted;
SYSCTL_INT(_vm, OID_AUTO, protect_privileged_from_untrusted,
    CTLFLAG_RW | CTLFLAG_LOCKED, &vm_protect_privileged_from_untrusted, 0, "");
extern uint64_t vm_copied_on_read;
SYSCTL_QUAD(_vm, OID_AUTO, copied_on_read,
    CTLFLAG_RD | CTLFLAG_LOCKED, &vm_copied_on_read, "");

extern int vm_shared_region_count;
extern int vm_shared_region_peak;
SYSCTL_INT(_vm, OID_AUTO, shared_region_count,
    CTLFLAG_RD | CTLFLAG_LOCKED, &vm_shared_region_count, 0, "");
SYSCTL_INT(_vm, OID_AUTO, shared_region_peak,
    CTLFLAG_RD | CTLFLAG_LOCKED, &vm_shared_region_peak, 0, "");
#if DEVELOPMENT || DEBUG
extern unsigned int shared_region_pagers_resident_count;
SYSCTL_INT(_vm, OID_AUTO, shared_region_pagers_resident_count,
    CTLFLAG_RD | CTLFLAG_LOCKED, &shared_region_pagers_resident_count, 0, "");
extern unsigned int shared_region_pagers_resident_peak;
SYSCTL_INT(_vm, OID_AUTO, shared_region_pagers_resident_peak,
    CTLFLAG_RD | CTLFLAG_LOCKED, &shared_region_pagers_resident_peak, 0, "");
extern int shared_region_pager_count;
SYSCTL_INT(_vm, OID_AUTO, shared_region_pager_count,
    CTLFLAG_RD | CTLFLAG_LOCKED, &shared_region_pager_count, 0, "");
#if __has_feature(ptrauth_calls)
extern int shared_region_key_count;
SYSCTL_INT(_vm, OID_AUTO, shared_region_key_count,
    CTLFLAG_RD | CTLFLAG_LOCKED, &shared_region_key_count, 0, "");
extern int vm_shared_region_reslide_count;
SYSCTL_INT(_vm, OID_AUTO, shared_region_reslide_count,
    CTLFLAG_RD | CTLFLAG_LOCKED, &vm_shared_region_reslide_count, 0, "");
#endif /* __has_feature(ptrauth_calls) */
#endif /* DEVELOPMENT || DEBUG */

#if MACH_ASSERT
extern int debug4k_filter;
SYSCTL_INT(_vm, OID_AUTO, debug4k_filter, CTLFLAG_RW | CTLFLAG_LOCKED, &debug4k_filter, 0, "");
extern int debug4k_panic_on_terminate;
SYSCTL_INT(_vm, OID_AUTO, debug4k_panic_on_terminate, CTLFLAG_RW | CTLFLAG_LOCKED, &debug4k_panic_on_terminate, 0, "");
extern int debug4k_panic_on_exception;
SYSCTL_INT(_vm, OID_AUTO, debug4k_panic_on_exception, CTLFLAG_RW | CTLFLAG_LOCKED, &debug4k_panic_on_exception, 0, "");
extern int debug4k_panic_on_misaligned_sharing;
SYSCTL_INT(_vm, OID_AUTO, debug4k_panic_on_misaligned_sharing, CTLFLAG_RW | CTLFLAG_LOCKED, &debug4k_panic_on_misaligned_sharing, 0, "");
#endif /* MACH_ASSERT */

/*
 * A sysctl which causes all existing shared regions to become stale. They
 * will no longer be used by anything new and will be torn down as soon as
 * the last existing user exits. A write of non-zero value causes that to happen.
 * This should only be used by launchd, so we check that this is initproc.
 */
static int
shared_region_pivot(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	unsigned int value = 0;
	int changed = 0;
	int error = sysctl_io_number(req, 0, sizeof(value), &value, &changed);
	if (error || !changed) {
		return error;
	}
	if (current_proc() != initproc) {
		return EPERM;
	}

	vm_shared_region_pivot();

	return 0;
}

SYSCTL_PROC(_vm, OID_AUTO, shared_region_pivot,
    CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_LOCKED,
    0, 0, shared_region_pivot, "I", "");

extern int vm_remap_old_path, vm_remap_new_path;
SYSCTL_INT(_vm, OID_AUTO, remap_old_path,
    CTLFLAG_RD | CTLFLAG_LOCKED, &vm_remap_old_path, 0, "");
SYSCTL_INT(_vm, OID_AUTO, remap_new_path,
    CTLFLAG_RD | CTLFLAG_LOCKED, &vm_remap_new_path, 0, "");
