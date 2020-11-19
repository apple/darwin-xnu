/*
 * Copyright (c) 2019-2020 Apple Inc. All rights reserved.
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

#include <pexpert/arm64/board_config.h>

#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)

#include <vm/pmap.h>
#include <libkern/section_keywords.h>
#include <libkern/kernel_mach_header.h>
#include <pexpert/pexpert.h>
#include <pexpert/device_tree.h>
#include <machine/atomic.h>
#include <arm/cpu_internal.h>
#include <arm/caches_internal.h>
#include <arm/machine_routines.h>
#include <arm/pmap.h>
#include <arm64/tlb.h>
#include <arm64/amcc_rorgn.h>
#include <memmap_types.h>

#if HIBERNATION
#include <arm64/pal_hibernate.h>
#endif /* HIBERNATION */

#if HAS_IOA
#define MAX_LOCK_GROUPS 2                                       // 2 lock groups (AMCC, IOA)
#define IOA_LOCK_GROUP  1                                       // IOA lock group index
#else
#define MAX_LOCK_GROUPS 1                                       // 1 lock group (AMCC)
#endif
#define AMCC_LOCK_GROUP 0                                       // AMCC lock group index
#define MAX_APERTURES   16                                      // Maximum number of register apertures
#define MAX_PLANES      16                                      // Maximum number of planes within each aperture

#define LOCK_GROUP_HAS_CACHE_STATUS_REG (1 << 0)                // Look for cache status register in the lock group
#define LOCK_GROUP_HAS_MASTER_LOCK_REG  (1 << 1)                // Look for master lock register in the lock group

#define LOCK_TYPE_HAS_LOCK_REG          (1 << 0)                // Look for lock register in the lock type

extern vm_offset_t   segLOWESTRO;
extern vm_offset_t   segHIGHESTRO;

extern vm_offset_t   segLASTB;
extern vm_offset_t   segTEXTEXECB;
extern unsigned long segSizeLAST;
extern unsigned long segSizeLASTDATACONST;
extern unsigned long segSizeTEXTEXEC;

typedef struct lock_reg {
	uint32_t        reg_offset;                             // Register offset
	uint32_t        reg_mask;                               // Register mask
	uint32_t        reg_value;                              // Regsiter value
} lock_reg_t;

typedef struct lock_type {
	uint32_t        page_size_shift;                        // page shift used in lower/upper limit registers
	lock_reg_t      lower_limit_reg;                        // Lower limit register description
	lock_reg_t      upper_limit_reg;                        // Upper limit register description
	lock_reg_t      enable_reg;                             // Enable register description
	lock_reg_t      write_disable_reg;                      // Write disable register description
	lock_reg_t      lock_reg;                               // Lock register description
} lock_type_t;

typedef struct lock_group {
	uint32_t        aperture_count;                         // Aperture count
	uint32_t        aperture_size;                          // Aperture size
	uint32_t        plane_count;                            // Number of planes in the aperture
	uint32_t        plane_stride;                           // Stride between planes in the aperture
	uint64_t        aperture_phys_addr[MAX_APERTURES];      // Apreture physical addresses
	lock_reg_t      cache_status_reg;                       // Cache status register description
#if HAS_IOA
	lock_reg_t      master_lock_reg;                        // Master lock register description
#endif
	lock_type_t     ctrr_a;                                 // CTRR-A (KTRR) lock
} lock_group_t;

SECURITY_READ_ONLY_LATE(lock_group_t) _lock_group[MAX_LOCK_GROUPS] = { {0} };
SECURITY_READ_ONLY_LATE(bool) lock_regs_set = false;

static vm_offset_t rorgn_begin = 0;
static vm_offset_t rorgn_end = 0;
SECURITY_READ_ONLY_LATE(vm_offset_t) ctrr_begin = 0;
SECURITY_READ_ONLY_LATE(vm_offset_t) ctrr_end = 0;

static uint64_t lock_group_va[MAX_LOCK_GROUPS][MAX_APERTURES];

#if CONFIG_CSR_FROM_DT
SECURITY_READ_ONLY_LATE(bool) csr_unsafe_kernel_text = false;
#endif

#if defined(KERNEL_INTEGRITY_KTRR)
#define CTRR_LOCK_MSR ARM64_REG_KTRR_LOCK_EL1
#elif defined(KERNEL_INTEGRITY_CTRR)
#define CTRR_LOCK_MSR ARM64_REG_CTRR_LOCK_EL1
#endif

/*
 * lock_group_t - describes all the parameters xnu needs to know to
 * lock down the AMCC/IOA (Lock Group) Read Only Region(s) on cold start.
 * This description assumes that each AMCC/IOA in a given system will
 * be identical, respectively. The only variable are the number of
 * apertures present and the physical base address of each aperture.
 *
 * General xnu lock group lockdown flow:
 * - for each lock group:
 *   - ml_io_map all present lock group physical base addresses
 *   - assert all lock group begin/end page numbers set by iboot are identical
 *   - convert lock group begin/end page number to physical address
 *   - assert lock group begin/end page numbers match xnu view of read only region
 *   - assert lock group is not currently locked
 *   - ensure lock group master cache is disabled
 *   - write enable/lock registers to enable/lock the lock group read only region
 */

static bool
_dt_get_uint32(DTEntry node, char const *name, uint32_t *dest)
{
	uint32_t const *value;
	unsigned int size;

	if (SecureDTGetProperty(node, name, (void const **)&value, &size) != kSuccess) {
		return false;
	}

	if (size != sizeof(uint32_t)) {
		panic("lock-regs: unexpected size %u", size);
	}

	*dest = *value;

	return true;
}

static uint32_t
_dt_get_uint32_required(DTEntry node, char const *name)
{
	uint32_t value;

	if (!_dt_get_uint32(node, name, &value)) {
		panic("lock-regs: cannot find required property '%s'", name);
	}

	return value;
}

static bool
_dt_get_lock_reg(DTEntry node, lock_reg_t *reg, const char *parent_name, const char *reg_name, bool required, bool with_value)
{
	char prop_name[32];
	bool found;

	snprintf(prop_name, sizeof(prop_name), "%s-reg-offset", reg_name);
	found = _dt_get_uint32(node, prop_name, &reg->reg_offset);
	if (!found) {
		if (required) {
			panic("%s: missing property '%s'", parent_name, prop_name);
		} else {
			return false;
		}
	}

	snprintf(prop_name, sizeof(prop_name), "%s-reg-mask", reg_name);
	found = _dt_get_uint32(node, prop_name, &reg->reg_mask);
	if (!found) {
		panic("%s: missing property '%s'", parent_name, prop_name);
	}

	if (with_value) {
		snprintf(prop_name, sizeof(prop_name), "%s-reg-value", reg_name);
		found = _dt_get_uint32(node, prop_name, &reg->reg_value);
		if (!found) {
			panic("%s: missing property '%s'", parent_name, prop_name);
		}
	}

	return true;
}

static DTEntry
_dt_get_lock_group(DTEntry lock_regs_node, lock_group_t* lock_group, const char *group_name, uint32_t options)
{
	DTEntry group_node;

	// Find the lock group node.
	if (SecureDTLookupEntry(lock_regs_node, group_name, &group_node) != kSuccess) {
		panic("lock-regs: /chosen/lock-regs/%s not found", group_name);
	}

	lock_group->aperture_count = _dt_get_uint32_required(group_node, "aperture-count");

	if (lock_group->aperture_count > MAX_APERTURES) {
		panic("%s: %s %u exceeds maximum %u", group_name, "aperture-count", lock_group->aperture_count, MAX_APERTURES);
	}

	lock_group->aperture_size = _dt_get_uint32_required(group_node, "aperture-size");

	if ((lock_group->aperture_count > 0) && (lock_group->aperture_size == 0)) {
		panic("%s: have %u apertures, but 0 size", group_name, lock_group->aperture_count);
	}

	lock_group->plane_count = _dt_get_uint32_required(group_node, "plane-count");

	if (lock_group->plane_count > MAX_PLANES) {
		panic("%s: %s %u exceeds maximum %u", group_name, "plane-count", lock_group->plane_count, MAX_PLANES);
	}

	if (!_dt_get_uint32(group_node, "plane-stride", &lock_group->plane_stride)) {
		lock_group->plane_stride = 0;
	}

	if (lock_group->plane_count > 1) {
		uint32_t aperture_size;

		if (lock_group->plane_stride == 0) {
			panic("%s: plane-count (%u) > 1, but stride is 0/missing", group_name, lock_group->plane_count);
		}

		if (os_mul_overflow(lock_group->plane_count, lock_group->plane_stride, &aperture_size)
		    || (aperture_size > lock_group->aperture_size)) {
			panic("%s: aperture-size (%#x) is insufficent to cover plane-count (%#x) of plane-stride (%#x) bytes", group_name, lock_group->aperture_size, lock_group->plane_count, lock_group->plane_stride);
		}
	}

	uint64_t const *phys_bases = NULL;
	unsigned int prop_size;
	if (SecureDTGetProperty(group_node, "aperture-phys-addr", (const void**)&phys_bases, &prop_size) != kSuccess) {
		panic("%s: missing required %s", group_name, "aperture-phys-addr");
	}

	if (prop_size != lock_group->aperture_count * sizeof(lock_group->aperture_phys_addr[0])) {
		panic("%s: aperture-phys-addr size (%#x) != (aperture-count (%#x) * PA size (%#zx) = %#lx)",
		    group_name, prop_size, lock_group->aperture_count, sizeof(lock_group->aperture_phys_addr[0]),
		    lock_group->aperture_count * sizeof(lock_group->aperture_phys_addr[0]));
	}

	memcpy(lock_group->aperture_phys_addr, phys_bases, prop_size);

	if (options & LOCK_GROUP_HAS_CACHE_STATUS_REG) {
		_dt_get_lock_reg(group_node, &lock_group->cache_status_reg, group_name, "cache-status", true, true);
	}

#if HAS_IOA
	if (options & LOCK_GROUP_HAS_MASTER_LOCK_REG) {
		_dt_get_lock_reg(group_node, &lock_group->master_lock_reg, group_name, "master-lock", true, true);
	}
#endif

	return group_node;
}

static void
_dt_get_lock_type(DTEntry group_node, lock_type_t *lock_type, const char *group_name, const char *type_name, uint32_t options)
{
	DTEntry type_node;
	bool has_lock = options & LOCK_TYPE_HAS_LOCK_REG;

	// Find the lock type type_node.
	if (SecureDTLookupEntry(group_node, type_name, &type_node) != kSuccess) {
		panic("lock-regs: /chosen/lock-regs/%s/%s not found", group_name, type_name);
	}

	lock_type->page_size_shift = _dt_get_uint32_required(type_node, "page-size-shift");

	// Find all of the regsiters for this lock type.
	//               Parent     Register Descriptor            Parent Name Reg Name        Required Value
	_dt_get_lock_reg(type_node, &lock_type->lower_limit_reg, type_name, "lower-limit", true, false);
	_dt_get_lock_reg(type_node, &lock_type->upper_limit_reg, type_name, "upper-limit", true, false);
	_dt_get_lock_reg(type_node, &lock_type->lock_reg, type_name, "lock", has_lock, true);
	_dt_get_lock_reg(type_node, &lock_type->enable_reg, type_name, "enable", false, true);
	_dt_get_lock_reg(type_node, &lock_type->write_disable_reg, type_name, "write-disable", false, true);
}

/*
 * find_lock_group_data:
 *
 * finds and gathers lock group (AMCC/IOA) data from device tree, returns it as lock_group_t
 *
 * called first time before IOKit start while still uniprocessor
 *
 */
static lock_group_t const * _Nonnull
find_lock_group_data(void)
{
	DTEntry lock_regs_node = NULL;
	DTEntry amcc_node = NULL;

	// Return the lock group data pointer if we already found and populated one.
	if (lock_regs_set) {
		return _lock_group;
	}

	if (SecureDTLookupEntry(NULL, "/chosen/lock-regs", &lock_regs_node) != kSuccess) {
		panic("lock-regs: /chosen/lock-regs not found (your iBoot or EDT may be too old)");
	}

	amcc_node = _dt_get_lock_group(lock_regs_node, &_lock_group[AMCC_LOCK_GROUP], "amcc", LOCK_GROUP_HAS_CACHE_STATUS_REG);
	_dt_get_lock_type(amcc_node, &_lock_group[AMCC_LOCK_GROUP].ctrr_a, "amcc", "amcc-ctrr-a", LOCK_TYPE_HAS_LOCK_REG);

#if HAS_IOA
	DTEntry ioa_node = _dt_get_lock_group(lock_regs_node, &_lock_group[IOA_LOCK_GROUP], "ioa", LOCK_GROUP_HAS_MASTER_LOCK_REG);
	_dt_get_lock_type(ioa_node, &_lock_group[IOA_LOCK_GROUP].ctrr_a, "ioa", "ioa-ctrr-a", 0);
#endif

	lock_regs_set = true;

	return _lock_group;
}

void
rorgn_stash_range(void)
{
#if DEVELOPMENT || DEBUG || CONFIG_DTRACE || CONFIG_CSR_FROM_DT
	boolean_t rorgn_disable = FALSE;

#if DEVELOPMENT || DEBUG
	PE_parse_boot_argn("-unsafe_kernel_text", &rorgn_disable, sizeof(rorgn_disable));
#endif

#if CONFIG_CSR_FROM_DT
	if (csr_unsafe_kernel_text) {
		rorgn_disable = true;
	}
#endif

	if (rorgn_disable) {
		/* take early out if boot arg present, don't query any machine registers to avoid
		 * dependency on amcc DT entry
		 */
		return;
	}
#endif
	lock_group_t const * const lock_group = find_lock_group_data();

	/* Get the lock group read-only region range values, and stash them into rorgn_begin, rorgn_end. */
	uint64_t rorgn_begin_page[MAX_LOCK_GROUPS][MAX_APERTURES][MAX_PLANES];
	uint64_t rorgn_end_page[MAX_LOCK_GROUPS][MAX_APERTURES][MAX_PLANES];

	for (unsigned int lg = 0; lg < MAX_LOCK_GROUPS; lg++) {
		for (unsigned int aperture = 0; aperture < lock_group[lg].aperture_count; aperture++) {
			const uint64_t amcc_pa = lock_group[lg].aperture_phys_addr[aperture];

			// VA space will be unmapped and freed after lockdown complete in rorgn_lockdown()
			lock_group_va[lg][aperture] = ml_io_map(amcc_pa, lock_group[lg].aperture_size);

			if (lock_group_va[lg][aperture] == 0) {
				panic("map aperture_phys_addr[%u]/%#x failed", aperture, lock_group[lg].aperture_size);
			}

			for (unsigned int plane = 0; plane < lock_group[lg].plane_count; plane++) {
				uint64_t reg_addr;

				reg_addr = lock_group_va[lg][aperture] + (plane * lock_group[lg].plane_stride) + lock_group[lg].ctrr_a.lower_limit_reg.reg_offset;
				rorgn_begin_page[lg][aperture][plane] = *(volatile uint32_t *)reg_addr;
				reg_addr = lock_group_va[lg][aperture] + (plane * lock_group[lg].plane_stride) + lock_group[lg].ctrr_a.upper_limit_reg.reg_offset;
				rorgn_end_page[lg][aperture][plane] = *(volatile uint32_t *)reg_addr;
			}
		}

		assert(rorgn_end_page[lg][0][0] > rorgn_begin_page[lg][0][0]);

		for (unsigned int aperture = 0; aperture < lock_group[lg].aperture_count; aperture++) {
			for (unsigned int plane = 0; plane < lock_group[lg].plane_count; plane++) {
				if ((rorgn_begin_page[lg][aperture][plane] != rorgn_begin_page[0][0][0])
				    || (rorgn_end_page[lg][aperture][plane] != rorgn_end_page[0][0][0])) {
					panic("Inconsistent memory config");
				}
			}
		}

		uint64_t page_bytes = 1ULL << lock_group[lg].ctrr_a.page_size_shift;

		/* rorgn_begin and rorgn_end are first and last byte inclusive of lock group read only region as determined by iBoot. */
		rorgn_begin = (rorgn_begin_page[0][0][0] << lock_group[lg].ctrr_a.page_size_shift) + gDramBase;
		rorgn_end = (rorgn_end_page[0][0][0] << lock_group[lg].ctrr_a.page_size_shift) + gDramBase + page_bytes - 1;
	}

	assert(segLOWESTRO && gVirtBase && gPhysBase);

	/* ctrr_begin and end are first and last bytes inclusive of MMU KTRR/CTRR region */
	ctrr_begin = kvtophys(segLOWESTRO);

#if defined(KERNEL_INTEGRITY_KTRR)

	/* __LAST is not part of the MMU KTRR region (it is however part of the AMCC read only region)
	 *
	 * +------------------+-----------+-----------------------------------+
	 * | Largest Address  |    LAST   | <- AMCC RO Region End (rorgn_end) |
	 * +------------------+-----------+-----------------------------------+
	 * |                  | TEXT_EXEC | <- KTRR RO Region End (ctrr_end)  |
	 * +------------------+-----------+-----------------------------------+
	 * |                  |    ...    |                                   |
	 * +------------------+-----------+-----------------------------------+
	 * | Smallest Address |   LOWEST  | <- KTRR/AMCC RO Region Begin      |
	 * |                  |           |     (ctrr_begin/rorgn_begin)      |
	 * +------------------+-----------+-----------------------------------+
	 *
	 */

	ctrr_end = kvtophys(segLASTB) - segSizeLASTDATACONST - 1;

	/* assert not booted from kernel collection */
	assert(!segHIGHESTRO);

	/* assert that __LAST segment containing privileged insns is only a single page */
	assert(segSizeLAST == PAGE_SIZE);

	/* assert that segLAST is contiguous and just after/above/numerically higher than KTRR end */
	assert((ctrr_end + 1) == kvtophys(segTEXTEXECB) + segSizeTEXTEXEC);

	/* ensure that iboot and xnu agree on the amcc rorgn range */
	assert((rorgn_begin == ctrr_begin) && (rorgn_end == (ctrr_end + segSizeLASTDATACONST + segSizeLAST)));
#elif defined(KERNEL_INTEGRITY_CTRR)

	/* __LAST is part of MMU CTRR region. Can't use the KTRR style method of making
	 * __pinst no execute because PXN applies with MMU off in CTRR.
	 *
	 * +------------------+-----------+------------------------------+
	 * | Largest Address  |    LAST   |  <- CTRR/AMCC RO Region End  |
	 * |                  |           |     (ctrr_end/rorgn_end)     |
	 * +------------------+-----------+------------------------------+
	 * |                  | TEXT_EXEC |                              |
	 * +------------------+-----------+------------------------------+
	 * |                  |    ...    |                              |
	 * +------------------+-----------+------------------------------+
	 * | Smallest Address |   LOWEST  | <- CTRR/AMCC RO Region Begin |
	 * |                  |           |    (ctrr_begin/rorgn_begin)  |
	 * +------------------+-----------+------------------------------+
	 *
	 */

	if (segHIGHESTRO) {
		/*
		 * kernel collections may have additional kext RO data after kernel LAST
		 */
		assert(segLASTB + segSizeLAST <= segHIGHESTRO);
		ctrr_end = kvtophys(segHIGHESTRO) - 1;
	} else {
		ctrr_end = kvtophys(segLASTB) + segSizeLAST - 1;
	}

	/* ensure that iboot and xnu agree on the amcc rorgn range */
	assert((rorgn_begin == ctrr_begin) && (rorgn_end == ctrr_end));
#endif
}

#if DEVELOPMENT || DEBUG
static void
assert_all_lock_groups_unlocked(lock_group_t const *lock_groups)
{
	uint64_t reg_addr;
	uint64_t ctrr_lock = 0;
	bool locked = false;
	bool write_disabled = false;;

	assert(lock_groups);

	for (unsigned int lg = 0; lg < MAX_LOCK_GROUPS; lg++) {
		for (unsigned int aperture = 0; aperture < lock_groups[lg].aperture_count; aperture++) {
#if HAS_IOA
			// Does the lock group define a master lock register?
			if (lock_groups[lg].master_lock_reg.reg_mask != 0) {
				reg_addr = lock_group_va[lg][aperture] + lock_groups[lg].master_lock_reg.reg_offset;
				locked |= ((*(volatile uint32_t *)reg_addr & lock_groups[lg].master_lock_reg.reg_mask) == lock_groups[lg].master_lock_reg.reg_value);
			}
#endif
			for (unsigned int plane = 0; plane < lock_groups[lg].plane_count; plane++) {
				// Does the lock group define a write disable register?
				if (lock_groups[lg].ctrr_a.write_disable_reg.reg_mask != 0) {
					reg_addr = lock_group_va[lg][aperture] + (plane * lock_groups[lg].plane_stride) + lock_groups[lg].ctrr_a.write_disable_reg.reg_offset;
					write_disabled |= ((*(volatile uint32_t *)reg_addr & lock_groups[lg].ctrr_a.write_disable_reg.reg_mask) == lock_groups[lg].ctrr_a.write_disable_reg.reg_value);
				}

				// Does the lock group define a lock register?
				if (lock_groups[lg].ctrr_a.lock_reg.reg_mask != 0) {
					reg_addr = lock_group_va[lg][aperture] + (plane * lock_groups[lg].plane_stride) + lock_groups[lg].ctrr_a.lock_reg.reg_offset;
					locked |= ((*(volatile uint32_t *)reg_addr & lock_groups[lg].ctrr_a.lock_reg.reg_mask) == lock_groups[lg].ctrr_a.lock_reg.reg_value);
				}
			}
		}
	}

	ctrr_lock = __builtin_arm_rsr64(CTRR_LOCK_MSR);

	assert(!ctrr_lock);
	assert(!write_disabled && !locked);
}
#endif

static void
lock_all_lock_groups(lock_group_t const *lock_group, vm_offset_t begin, vm_offset_t end)
{
	uint64_t reg_addr;
	assert(lock_group);

	/*
	 * [x] - ensure all in flight writes are flushed to the lock group before enabling RO Region Lock
	 *
	 * begin and end are first and last byte inclusive of lock group read only region
	 */

	CleanPoC_DcacheRegion_Force(begin, end - begin + 1);

	for (unsigned int lg = 0; lg < MAX_LOCK_GROUPS; lg++) {
		for (unsigned int aperture = 0; aperture < lock_group[lg].aperture_count; aperture++) {
			/* lock planes in reverse order: plane 0 should be locked last */
			unsigned int plane = lock_group[lg].plane_count - 1;
			do {
				// Enable the protection region if the lock group defines an enable register.
				if (lock_group[lg].ctrr_a.enable_reg.reg_mask != 0) {
					reg_addr = lock_group_va[lg][aperture] + (plane * lock_group[lg].plane_stride) + lock_group[lg].ctrr_a.enable_reg.reg_offset;
					*(volatile uint32_t *)reg_addr = lock_group[lg].ctrr_a.enable_reg.reg_value;
				}

				// Disable writes if the lock group defines a write disable register.
				if (lock_group[lg].ctrr_a.write_disable_reg.reg_mask != 0) {
					reg_addr = lock_group_va[lg][aperture] + (plane * lock_group[lg].plane_stride) + lock_group[lg].ctrr_a.write_disable_reg.reg_offset;
					*(volatile uint32_t *)reg_addr = lock_group[lg].ctrr_a.write_disable_reg.reg_value;
				}

				// Lock the lock if the lock group defines an enable register.
				if (lock_group[lg].ctrr_a.lock_reg.reg_mask != 0) {
					reg_addr = lock_group_va[lg][aperture] + (plane * lock_group[lg].plane_stride) + lock_group[lg].ctrr_a.lock_reg.reg_offset;
					*(volatile uint32_t *)reg_addr = lock_group[lg].ctrr_a.lock_reg.reg_value;
				}

				__builtin_arm_isb(ISB_SY);
			} while (plane-- > 0);
#if HAS_IOA
			// Lock the master lock if the lock group define a master lock register.
			if (lock_group[lg].master_lock_reg.reg_mask != 0) {
				reg_addr = lock_group_va[lg][aperture] + lock_group[lg].master_lock_reg.reg_offset;
				*(volatile uint32_t *)reg_addr = lock_group[lg].master_lock_reg.reg_value;
			}
			__builtin_arm_isb(ISB_SY);
#endif
		}
	}
}

static void
lock_mmu(uint64_t begin, uint64_t end)
{
#if defined(KERNEL_INTEGRITY_KTRR)

	__builtin_arm_wsr64(ARM64_REG_KTRR_LOWER_EL1, begin);
	__builtin_arm_wsr64(ARM64_REG_KTRR_UPPER_EL1, end);
	__builtin_arm_wsr64(ARM64_REG_KTRR_LOCK_EL1, 1ULL);

	/* flush TLB */

	__builtin_arm_isb(ISB_SY);
	flush_mmu_tlb();

#elif defined (KERNEL_INTEGRITY_CTRR)
	/* this will lock the entire bootstrap cluster. non bootstrap clusters
	 * will be locked by respective cluster master in start.s */

	__builtin_arm_wsr64(ARM64_REG_CTRR_A_LWR_EL1, begin);
	__builtin_arm_wsr64(ARM64_REG_CTRR_A_UPR_EL1, end);

#if !defined(APPLEVORTEX)
	/* H12+ changed sequence, must invalidate TLB immediately after setting CTRR bounds */
	__builtin_arm_isb(ISB_SY); /* ensure all prior MSRs are complete */
	flush_mmu_tlb();
#endif /* !defined(APPLEVORTEX) */

	__builtin_arm_wsr64(ARM64_REG_CTRR_CTL_EL1, CTRR_CTL_EL1_A_PXN | CTRR_CTL_EL1_A_MMUON_WRPROTECT);
	__builtin_arm_wsr64(ARM64_REG_CTRR_LOCK_EL1, 1ULL);

	uint64_t current_el = __builtin_arm_rsr64("CurrentEL");
	if (current_el == PSR64_MODE_EL2) {
		// CTRR v2 has explicit registers for cluster config. they can only be written in EL2

		__builtin_arm_wsr64(ACC_CTRR_A_LWR_EL2, begin);
		__builtin_arm_wsr64(ACC_CTRR_A_UPR_EL2, end);
		__builtin_arm_wsr64(ACC_CTRR_CTL_EL2, CTRR_CTL_EL1_A_PXN | CTRR_CTL_EL1_A_MMUON_WRPROTECT);
		__builtin_arm_wsr64(ACC_CTRR_LOCK_EL2, 1ULL);
	}

	__builtin_arm_isb(ISB_SY); /* ensure all prior MSRs are complete */
#if defined(APPLEVORTEX)
	flush_mmu_tlb();
#endif /* defined(APPLEVORTEX) */

#else /* defined(KERNEL_INTEGRITY_KTRR) */
#error KERNEL_INTEGRITY config error
#endif /* defined(KERNEL_INTEGRITY_KTRR) */
}

#if DEVELOPMENT || DEBUG
static void
assert_amcc_cache_disabled(lock_group_t const *lock_group)
{
	assert(lock_group);

	const lock_reg_t *cache_status_reg = &lock_group[AMCC_LOCK_GROUP].cache_status_reg;

	// If the platform does not define a cache status register, then we're done here.
	if (cache_status_reg->reg_mask != 0) {
		return;
	}

	for (unsigned int aperture = 0; aperture < lock_group[AMCC_LOCK_GROUP].aperture_count; aperture++) {
		for (unsigned int plane = 0; plane < lock_group[AMCC_LOCK_GROUP].plane_count; plane++) {
			uint64_t reg_addr = lock_group_va[AMCC_LOCK_GROUP][aperture] + (plane * lock_group[AMCC_LOCK_GROUP].plane_stride) + cache_status_reg->reg_offset;
			uint32_t reg_value = *(volatile uint32_t *)reg_addr;
			assert((reg_value & cache_status_reg->reg_mask) == cache_status_reg->reg_value);
		}
	}
}
#endif /* DEVELOPMENT || DEBUG */

/*
 * void rorgn_lockdown(void)
 *
 * Lock the MMU and AMCC RORegion within lower and upper boundaries if not already locked
 *
 * [ ] - ensure this is being called ASAP on secondary CPUs: KTRR programming and lockdown handled in
 *       start.s:start_cpu() for subsequent wake/resume of all cores
 */
void
rorgn_lockdown(void)
{
	boolean_t ctrr_disable = FALSE;

#if DEVELOPMENT || DEBUG
	PE_parse_boot_argn("-unsafe_kernel_text", &ctrr_disable, sizeof(ctrr_disable));
#endif /* DEVELOPMENT || DEBUG */

#if CONFIG_CSR_FROM_DT
	if (csr_unsafe_kernel_text) {
		ctrr_disable = true;
	}
#endif /* CONFIG_CSR_FROM_DT */

	if (!ctrr_disable) {
		lock_group_t const * const lock_group = find_lock_group_data();

#if DEVELOPMENT || DEBUG
		assert_all_lock_groups_unlocked(lock_group);

		printf("RO Region Begin: %p End: %p\n", (void *)rorgn_begin, (void *)rorgn_end);
		printf("CTRR (MMU) Begin: %p End: %p, setting lockdown\n", (void *)ctrr_begin, (void *)ctrr_end);

		assert_amcc_cache_disabled(lock_group);
#endif /* DEVELOPMENT || DEBUG */

		// Lock the AMCC/IOA PIO lock registers.
		lock_all_lock_groups(lock_group, phystokv(rorgn_begin), phystokv(rorgn_end));

		/*
		 * KTRR/CTRR registers are inclusive of the smallest page size granule supported by processor MMU
		 * rather than the actual page size in use. Load the last byte of the end page, and let the HW
		 * truncate per the smallest page granule supported. Must use same treament in start.s for warm
		 * start of APs.
		 */
		lock_mmu(ctrr_begin, ctrr_end);

		// Unmap and free PIO VA space needed to lockdown the lock groups.
		for (unsigned int lg = 0; lg < MAX_LOCK_GROUPS; lg++) {
			for (unsigned int aperture = 0; aperture < lock_group[lg].aperture_count; aperture++) {
				ml_io_unmap(lock_group_va[lg][aperture], lock_group[lg].aperture_size);
			}
		}
	}

#if defined(KERNEL_INTEGRITY_CTRR)
	/* wake any threads blocked on cluster master lockdown */
	cpu_data_t *cdp;

	cdp = getCpuDatap();

	cdp->cpu_cluster_id = ml_get_cluster_number_local();
	assert(cdp->cpu_cluster_id <= (uint32_t)ml_get_max_cluster_number());
	ctrr_cluster_locked[cdp->cpu_cluster_id] = CTRR_LOCKED;
	thread_wakeup(&ctrr_cluster_locked[cdp->cpu_cluster_id]);
#endif
}

#endif /* defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR) */
