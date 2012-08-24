/*
 * Copyright (c) 2000-2011 Apple Computer, Inc. All rights reserved.
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

#include <mach/kern_return.h>
#include <kern/kalloc.h>
#include <kern/cpu_number.h>
#include <kern/cpu_data.h>
#include <i386/cpuid.h>
#include <i386/mp.h>
#include <i386/proc_reg.h>
#include <i386/mtrr.h>
#include <i386/machine_check.h>

struct mtrr_var_range {
	uint64_t  base;		/* in IA32_MTRR_PHYSBASE format */
	uint64_t  mask;		/* in IA32_MTRR_PHYSMASK format */
	uint32_t  refcnt;	/* var ranges reference count */
};

struct mtrr_fix_range {
	uint64_t  types;	/* fixed-range type octet */
};

typedef struct mtrr_var_range mtrr_var_range_t;
typedef struct mtrr_fix_range mtrr_fix_range_t;

static struct {
	uint64_t            MTRRcap;
	uint64_t            MTRRdefType;
	mtrr_var_range_t *  var_range;
	unsigned int        var_count;
	mtrr_fix_range_t    fix_range[11];
} mtrr_state;

static boolean_t mtrr_initialized = FALSE;

decl_simple_lock_data(static, mtrr_lock);
#define MTRR_LOCK()	simple_lock(&mtrr_lock);
#define MTRR_UNLOCK()	simple_unlock(&mtrr_lock);

//#define MTRR_DEBUG 1
#if	MTRR_DEBUG
#define DBG(x...)	kprintf(x)
#else
#define DBG(x...)
#endif

/* Private functions */
static void mtrr_get_var_ranges(mtrr_var_range_t * range, int count);
static void mtrr_set_var_ranges(const mtrr_var_range_t * range, int count);
static void mtrr_get_fix_ranges(mtrr_fix_range_t * range);
static void mtrr_set_fix_ranges(const mtrr_fix_range_t * range);
static void mtrr_update_setup(void * param);
static void mtrr_update_teardown(void * param);
static void mtrr_update_action(void * param);
static void var_range_encode(mtrr_var_range_t * range, addr64_t address,
                             uint64_t length, uint32_t type, int valid);
static int  var_range_overlap(mtrr_var_range_t * range, addr64_t address,
                              uint64_t length, uint32_t type);

#define CACHE_CONTROL_MTRR		(NULL)
#define CACHE_CONTROL_PAT		((void *)1)

/*
 * MTRR MSR bit fields.
 */
#define IA32_MTRR_DEF_TYPE_MT		0x000000ff
#define IA32_MTRR_DEF_TYPE_FE		0x00000400
#define IA32_MTRR_DEF_TYPE_E		0x00000800

#define IA32_MTRRCAP_VCNT		0x000000ff
#define IA32_MTRRCAP_FIX		0x00000100
#define IA32_MTRRCAP_WC			0x00000400

/* 0 < bits <= 64 */
#define PHYS_BITS_TO_MASK(bits) \
	((((1ULL << (bits-1)) - 1) << 1) | 1)

/*
 * Default mask for 36 physical address bits, this can
 * change depending on the cpu model.
 */
static uint64_t mtrr_phys_mask = PHYS_BITS_TO_MASK(36);

#define IA32_MTRR_PHYMASK_VALID		0x0000000000000800ULL
#define IA32_MTRR_PHYSBASE_MASK		(mtrr_phys_mask & ~0x0000000000000FFFULL)
#define IA32_MTRR_PHYSBASE_TYPE		0x00000000000000FFULL

/*
 * Variable-range mask to/from length conversions.
 */
#define MASK_TO_LEN(mask) \
	((~((mask) & IA32_MTRR_PHYSBASE_MASK) & mtrr_phys_mask) + 1)

#define LEN_TO_MASK(len)  \
	(~((len) - 1) & IA32_MTRR_PHYSBASE_MASK)

#define LSB(x)		((x) & (~((x) - 1)))

/*
 * Fetch variable-range MTRR register pairs.
 */
static void
mtrr_get_var_ranges(mtrr_var_range_t * range, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		range[i].base = rdmsr64(MSR_IA32_MTRR_PHYSBASE(i));
		range[i].mask = rdmsr64(MSR_IA32_MTRR_PHYSMASK(i));

		/* bump ref count for firmware configured ranges */
		if (range[i].mask & IA32_MTRR_PHYMASK_VALID)
			range[i].refcnt = 1;
		else
			range[i].refcnt = 0;
	}
}

/*
 * Update variable-range MTRR register pairs.
 */
static void
mtrr_set_var_ranges(const mtrr_var_range_t * range, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		wrmsr64(MSR_IA32_MTRR_PHYSBASE(i), range[i].base);
		wrmsr64(MSR_IA32_MTRR_PHYSMASK(i), range[i].mask);
	}
}

/*
 * Fetch all fixed-range MTRR's. Note MSR offsets are not consecutive.
 */
static void
mtrr_get_fix_ranges(mtrr_fix_range_t * range)
{
	int i;

	/* assume 11 fix range registers */
	range[0].types = rdmsr64(MSR_IA32_MTRR_FIX64K_00000);
	range[1].types = rdmsr64(MSR_IA32_MTRR_FIX16K_80000);
	range[2].types = rdmsr64(MSR_IA32_MTRR_FIX16K_A0000);
	for (i = 0; i < 8; i++)
		range[3 + i].types = rdmsr64(MSR_IA32_MTRR_FIX4K_C0000 + i);
}

/*
 * Update all fixed-range MTRR's.
 */
static void
mtrr_set_fix_ranges(const struct mtrr_fix_range * range)
{
	int i;

	/* assume 11 fix range registers */
	wrmsr64(MSR_IA32_MTRR_FIX64K_00000, range[0].types);
	wrmsr64(MSR_IA32_MTRR_FIX16K_80000, range[1].types);
	wrmsr64(MSR_IA32_MTRR_FIX16K_A0000, range[2].types);
	for (i = 0; i < 8; i++)
		wrmsr64(MSR_IA32_MTRR_FIX4K_C0000 + i, range[3 + i].types);
}

static boolean_t
mtrr_check_fix_ranges(const struct mtrr_fix_range * range)
{
	int		i;
	boolean_t	match = TRUE;

	DBG("CPU%d: %s\n", get_cpu_number(), __FUNCTION__);

	/* assume 11 fix range registers */
	match = range[0].types == rdmsr64(MSR_IA32_MTRR_FIX64K_00000) &&
		range[1].types == rdmsr64(MSR_IA32_MTRR_FIX16K_80000) &&
		range[2].types == rdmsr64(MSR_IA32_MTRR_FIX16K_A0000);
	for (i = 0; match && i < 8; i++) {
		match = range[3 + i].types ==
			rdmsr64(MSR_IA32_MTRR_FIX4K_C0000 + i);
	}

	return match;
}

static boolean_t
mtrr_check_var_ranges(mtrr_var_range_t * range, int count)
{
	int		i;
	boolean_t	match = TRUE;
 
	DBG("CPU%d: %s\n", get_cpu_number(), __FUNCTION__);

	for (i = 0; match && i < count; i++) {
		match = range[i].base == rdmsr64(MSR_IA32_MTRR_PHYSBASE(i)) &&
			range[i].mask == rdmsr64(MSR_IA32_MTRR_PHYSMASK(i));
	}

	return match;
}

#if MTRR_DEBUG
static void
mtrr_msr_dump(void)
{
	int i;
	int count = rdmsr64(MSR_IA32_MTRRCAP) & IA32_MTRRCAP_VCNT;

	DBG("VAR -- BASE -------------- MASK -------------- SIZE\n");
	for (i = 0; i < count; i++) {
		DBG(" %02x    0x%016llx  0x%016llx  0x%llx\n", i,
		    rdmsr64(MSR_IA32_MTRR_PHYSBASE(i)),
		    rdmsr64(MSR_IA32_MTRR_PHYSMASK(i)),
		    MASK_TO_LEN(rdmsr64(MSR_IA32_MTRR_PHYSMASK(i))));
	}
	DBG("\n");

	DBG("FIX64K_00000: 0x%016llx\n", rdmsr64(MSR_IA32_MTRR_FIX64K_00000));
	DBG("FIX16K_80000: 0x%016llx\n", rdmsr64(MSR_IA32_MTRR_FIX16K_80000));
	DBG("FIX16K_A0000: 0x%016llx\n", rdmsr64(MSR_IA32_MTRR_FIX16K_A0000));
	DBG(" FIX4K_C0000: 0x%016llx\n", rdmsr64(MSR_IA32_MTRR_FIX4K_C0000));
	DBG(" FIX4K_C8000: 0x%016llx\n", rdmsr64(MSR_IA32_MTRR_FIX4K_C8000));
	DBG(" FIX4K_D0000: 0x%016llx\n", rdmsr64(MSR_IA32_MTRR_FIX4K_D0000));
	DBG(" FIX4K_D8000: 0x%016llx\n", rdmsr64(MSR_IA32_MTRR_FIX4K_D8000));
	DBG(" FIX4K_E0000: 0x%016llx\n", rdmsr64(MSR_IA32_MTRR_FIX4K_E0000));
	DBG(" FIX4K_E8000: 0x%016llx\n", rdmsr64(MSR_IA32_MTRR_FIX4K_E8000));
	DBG(" FIX4K_F0000: 0x%016llx\n", rdmsr64(MSR_IA32_MTRR_FIX4K_F0000));
	DBG(" FIX4K_F8000: 0x%016llx\n", rdmsr64(MSR_IA32_MTRR_FIX4K_F8000));

	DBG("\nMTRRcap = 0x%llx MTRRdefType = 0x%llx\n",
            rdmsr64(MSR_IA32_MTRRCAP), rdmsr64(MSR_IA32_MTRR_DEF_TYPE));
}
#endif /* MTRR_DEBUG */

/*
 * Called by the boot processor (BP) early during boot to initialize MTRR
 * support.  The MTRR state on the BP is saved, any additional processors
 * will have the same settings applied to ensure MTRR consistency.
 */
void
mtrr_init(void)
{
	/* no reason to init more than once */
	if (mtrr_initialized == TRUE)
		return;

	/* check for presence of MTRR feature on the processor */
	if ((cpuid_features() & CPUID_FEATURE_MTRR) == 0)
        	return;  /* no MTRR feature */

	/* use a lock to serialize MTRR changes */
	bzero((void *)&mtrr_state, sizeof(mtrr_state));
	simple_lock_init(&mtrr_lock, 0);

	mtrr_state.MTRRcap     = rdmsr64(MSR_IA32_MTRRCAP);
	mtrr_state.MTRRdefType = rdmsr64(MSR_IA32_MTRR_DEF_TYPE);
	mtrr_state.var_count   = (unsigned int)(mtrr_state.MTRRcap & IA32_MTRRCAP_VCNT);

	/* allocate storage for variable ranges (can block?) */
	if (mtrr_state.var_count) {
		mtrr_state.var_range = (mtrr_var_range_t *)
		                       kalloc(sizeof(mtrr_var_range_t) *
		                              mtrr_state.var_count);
		if (mtrr_state.var_range == NULL)
			mtrr_state.var_count = 0;
	}

	/* fetch the initial firmware configured variable ranges */
	if (mtrr_state.var_count)
		mtrr_get_var_ranges(mtrr_state.var_range,
				    mtrr_state.var_count);

	/* fetch the initial firmware configured fixed ranges */
	if (mtrr_state.MTRRcap & IA32_MTRRCAP_FIX)
		mtrr_get_fix_ranges(mtrr_state.fix_range);

	mtrr_initialized = TRUE;

#if MTRR_DEBUG
	mtrr_msr_dump();	/* dump firmware settings */
#endif

}

/*
 * Performs the Intel recommended procedure for changing the MTRR
 * in a MP system. Leverage rendezvous mechanism for the required
 * barrier synchronization among all processors. This function is
 * called from the rendezvous IPI handler, and mtrr_update_cpu().
 */
static void
mtrr_update_action(void * cache_control_type)
{
	uintptr_t cr0, cr4;
	uintptr_t tmp;

	cr0 = get_cr0();
	cr4 = get_cr4();

	/* enter no-fill cache mode */
	tmp = cr0 | CR0_CD;
	tmp &= ~CR0_NW;
	set_cr0(tmp);

	/* flush caches */
	wbinvd();

	/* clear the PGE flag in CR4 */
	if (cr4 & CR4_PGE)
		set_cr4(cr4 & ~CR4_PGE);

	/* flush TLBs */
	flush_tlb_raw();

	if (CACHE_CONTROL_PAT == cache_control_type) {
		/* Change PA6 attribute field to WC */
		uint64_t pat = rdmsr64(MSR_IA32_CR_PAT);
		DBG("CPU%d PAT: was 0x%016llx\n", get_cpu_number(), pat);
		pat &= ~(0x0FULL << 48);
		pat |=  (0x01ULL << 48);
		wrmsr64(MSR_IA32_CR_PAT, pat);
		DBG("CPU%d PAT: is  0x%016llx\n",
		    get_cpu_number(), rdmsr64(MSR_IA32_CR_PAT));
	}
	else {
		/* disable all MTRR ranges */
		wrmsr64(MSR_IA32_MTRR_DEF_TYPE,
			mtrr_state.MTRRdefType & ~IA32_MTRR_DEF_TYPE_E);

		/* apply MTRR settings */
		if (mtrr_state.var_count)
			mtrr_set_var_ranges(mtrr_state.var_range,
					mtrr_state.var_count);

		if (mtrr_state.MTRRcap & IA32_MTRRCAP_FIX)
			mtrr_set_fix_ranges(mtrr_state.fix_range);

		/* enable all MTRR range registers (what if E was not set?) */
		wrmsr64(MSR_IA32_MTRR_DEF_TYPE,
			mtrr_state.MTRRdefType | IA32_MTRR_DEF_TYPE_E);
	}

	/* flush all caches and TLBs a second time */
	wbinvd();
	flush_tlb_raw();

	/* restore normal cache mode */
	set_cr0(cr0);

	/* restore PGE flag */
	if (cr4 & CR4_PGE)
		set_cr4(cr4);

	DBG("CPU%d: %s\n", get_cpu_number(), __FUNCTION__);
}

static void
mtrr_update_setup(__unused void * param_not_used)
{
	/* disable interrupts before the first barrier */
	current_cpu_datap()->cpu_iflag = ml_set_interrupts_enabled(FALSE);
	DBG("CPU%d: %s\n", get_cpu_number(), __FUNCTION__);
}

static void
mtrr_update_teardown(__unused void * param_not_used)
{
	/* restore interrupt flag following MTRR changes */
	ml_set_interrupts_enabled(current_cpu_datap()->cpu_iflag);
	DBG("CPU%d: %s\n", get_cpu_number(), __FUNCTION__);
}

/*
 * Update MTRR settings on all processors.
 */
kern_return_t
mtrr_update_all_cpus(void)
{
	if (mtrr_initialized == FALSE)
		return KERN_NOT_SUPPORTED;

	MTRR_LOCK();
	mp_rendezvous(mtrr_update_setup,
		      mtrr_update_action,
		      mtrr_update_teardown, NULL);
	MTRR_UNLOCK();

	return KERN_SUCCESS;
}

/*
 * Verify that a processor has been set with the BSP's MTRR settings. Called
 * during slave processor initialization to check and set MTRR settings
 * discovered on the boot processor by mtrr_init().
 */
kern_return_t
mtrr_update_cpu(void)
{
	boolean_t	match = TRUE;

	if (mtrr_initialized == FALSE)
		return KERN_NOT_SUPPORTED;

	DBG("CPU%d: %s\n", get_cpu_number(), __FUNCTION__);

	MTRR_LOCK();

	/* Check MSR_IA32_MTRR_DEF_TYPE MSR */
	match = mtrr_state.MTRRdefType == rdmsr64(MSR_IA32_MTRR_DEF_TYPE);

	/* Check MSR_IA32_MTRRCAP MSR */
	if (match) {
		match = mtrr_state.MTRRcap == rdmsr64(MSR_IA32_MTRRCAP);
	}

	/* Check variable ranges */
	if (match && mtrr_state.var_count) {
		match = mtrr_check_var_ranges(mtrr_state.var_range,
					      mtrr_state.var_count);
	}

	/* Check fixed ranges */
	if (match && (mtrr_state.MTRRcap & IA32_MTRRCAP_FIX)) {
		match = mtrr_check_fix_ranges(mtrr_state.fix_range);
	}

#if MTRR_DEBUG
	if (!match)
		mtrr_msr_dump();
#endif
	if (!match) {
		DBG("mtrr_update_cpu() setting MTRR for cpu %d\n",
			get_cpu_number());
		mtrr_update_action(NULL);
	}
#if MTRR_DEBUG
	if (!match)
		mtrr_msr_dump();
#endif

	MTRR_UNLOCK();

	return KERN_SUCCESS;
}

/*
 * Add a MTRR range to associate the physical memory range specified
 * with a given memory caching type.
 */
kern_return_t
mtrr_range_add(addr64_t address, uint64_t length, uint32_t type)
{
	mtrr_var_range_t * vr;
	mtrr_var_range_t * free_range;
	kern_return_t      ret = KERN_NO_SPACE;
	int                overlap;
	unsigned int       i;

	DBG("mtrr_range_add base = 0x%llx, size = 0x%llx, type = %d\n",
            address, length, type);

	if (mtrr_initialized == FALSE) {
		return KERN_NOT_SUPPORTED;
	}

	/* check memory type (GPF exception for undefined types) */
	if ((type != MTRR_TYPE_UNCACHEABLE)  &&
	    (type != MTRR_TYPE_WRITECOMBINE) &&
	    (type != MTRR_TYPE_WRITETHROUGH) &&
	    (type != MTRR_TYPE_WRITEPROTECT) &&
	    (type != MTRR_TYPE_WRITEBACK)) {
		return KERN_INVALID_ARGUMENT;
	}

	/* check WC support if requested */
	if ((type == MTRR_TYPE_WRITECOMBINE) &&
	    (mtrr_state.MTRRcap & IA32_MTRRCAP_WC) == 0) {
		return KERN_NOT_SUPPORTED;
	}

	/* leave the fix range area below 1MB alone */
	if (address < 0x100000 || mtrr_state.var_count == 0) {
		return KERN_NOT_SUPPORTED;
	}

	/*
	 * Length must be a power of 2 given by 2^n, where n >= 12.
	 * Base address alignment must be larger than or equal to length.
	 */
	if ((length < 0x1000)       ||
	    (LSB(length) != length) ||
            (address && (length > LSB(address)))) {
		return KERN_INVALID_ARGUMENT;
	}

	MTRR_LOCK();

	/*
	 * Check for overlap and locate a free range.
	 */
	for (i = 0, free_range = NULL; i < mtrr_state.var_count; i++)
	{
		vr = &mtrr_state.var_range[i];

		if (vr->refcnt == 0) {
			/* free range candidate if no overlaps are found */
			free_range = vr;
			continue;
		}

		overlap = var_range_overlap(vr, address, length, type);
		if (overlap > 0) {
			/*
			 * identical overlap permitted, increment ref count.
			 * no hardware update required.
			 */
			free_range = vr;
			break;
		}
		if (overlap < 0) {
			/* unsupported overlapping of memory types */
			free_range = NULL;
			break;
		}
	}

	if (free_range) {
		if (free_range->refcnt++ == 0) {
			var_range_encode(free_range, address, length, type, 1);
			mp_rendezvous(mtrr_update_setup,
				      mtrr_update_action,
				      mtrr_update_teardown, NULL);
		}
		ret = KERN_SUCCESS;
	}

#if MTRR_DEBUG
	mtrr_msr_dump();
#endif

	MTRR_UNLOCK();

	return ret;
}

/*
 * Remove a previously added MTRR range. The same arguments used for adding
 * the memory range must be supplied again.
 */
kern_return_t
mtrr_range_remove(addr64_t address, uint64_t length, uint32_t type)
{
	mtrr_var_range_t * vr;
	int                result = KERN_FAILURE;
	int                cpu_update = 0;
	unsigned int       i;

	DBG("mtrr_range_remove base = 0x%llx, size = 0x%llx, type = %d\n",
            address, length, type);

	if (mtrr_initialized == FALSE) {
		return KERN_NOT_SUPPORTED;
	}

	MTRR_LOCK();

	for (i = 0; i < mtrr_state.var_count; i++) {
		vr = &mtrr_state.var_range[i];

		if (vr->refcnt &&
		    var_range_overlap(vr, address, length, type) > 0) {
			/* found specified variable range */
			if (--mtrr_state.var_range[i].refcnt == 0) {
				var_range_encode(vr, address, length, type, 0);
				cpu_update = 1;
			}
			result = KERN_SUCCESS;
			break;
		}
	}

	if (cpu_update) {
		mp_rendezvous(mtrr_update_setup,
			      mtrr_update_action,
			      mtrr_update_teardown, NULL);
		result = KERN_SUCCESS;
	}

#if MTRR_DEBUG
	mtrr_msr_dump();
#endif

	MTRR_UNLOCK();

	return result;
}

/*
 * Variable range helper routines
 */
static void
var_range_encode(mtrr_var_range_t * range, addr64_t address,
		 uint64_t length, uint32_t type, int valid)
{
	range->base = (address & IA32_MTRR_PHYSBASE_MASK) |
		      (type    & (uint32_t)IA32_MTRR_PHYSBASE_TYPE);

	range->mask = LEN_TO_MASK(length) |
		      (valid ? IA32_MTRR_PHYMASK_VALID : 0);
}

static int
var_range_overlap(mtrr_var_range_t * range, addr64_t address,
		  uint64_t length, uint32_t type)
{
	uint64_t  v_address, v_length;
	uint32_t  v_type;
	int       result = 0;  /* no overlap, or overlap ok */

	v_address = range->base & IA32_MTRR_PHYSBASE_MASK;
	v_type    = (uint32_t)(range->base & IA32_MTRR_PHYSBASE_TYPE);
	v_length  = MASK_TO_LEN(range->mask);

	/* detect range overlap */
	if ((v_address >= address && v_address < (address + length)) ||
	    (address >= v_address && address < (v_address + v_length))) {

		if (v_address == address && v_length == length && v_type == type)
			result = 1; /* identical overlap ok */
		else if ( v_type == MTRR_TYPE_UNCACHEABLE &&
			    type == MTRR_TYPE_UNCACHEABLE ) {
			/* UC ranges can overlap */
		}
		else if ((v_type == MTRR_TYPE_UNCACHEABLE &&
		            type == MTRR_TYPE_WRITEBACK)  ||
			 (v_type == MTRR_TYPE_WRITEBACK &&
			    type == MTRR_TYPE_UNCACHEABLE)) {
			/* UC/WB can overlap - effective type becomes UC */
		}
		else {
			/* anything else may cause undefined behavior */
			result = -1;
		}
	}

	return result;
}

/*
 * Initialize PAT (Page Attribute Table)
 */
void
pat_init(void)
{
	boolean_t	istate;
	uint64_t	pat;

	if (!(cpuid_features() & CPUID_FEATURE_PAT))
		return;

	istate = ml_set_interrupts_enabled(FALSE);

	pat = rdmsr64(MSR_IA32_CR_PAT);
	DBG("CPU%d PAT: was 0x%016llx\n", get_cpu_number(), pat);

	/* Change PA6 attribute field to WC if required */
	if ((pat & ~(0x0FULL << 48)) != (0x01ULL << 48)) {
		mtrr_update_action(CACHE_CONTROL_PAT);
	}
	ml_set_interrupts_enabled(istate);
}

#if DEBUG
void
mtrr_lapic_cached(void);
void
mtrr_lapic_cached(void)
{
	boolean_t	istate;
	uint32_t	lo;
	uint32_t	hi;
	uint64_t	lapic_pbase;
	uint64_t	base;
	uint64_t	length;
	uint32_t	type;
	unsigned int	i;

	/* Find the local APIC physical base address */
	rdmsr(MSR_IA32_APIC_BASE, lo, hi);
	lapic_pbase = (lo &  MSR_IA32_APIC_BASE_BASE);

	DBG("mtrr_lapic_cached() on cpu %d, lapic_pbase: 0x%016llx\n",
	    get_cpu_number(), lapic_pbase);

	istate = ml_set_interrupts_enabled(FALSE);

	/*
	 * Search for the variable range MTRR mapping the lapic.
	 * Flip its type to WC and return.
	 */
	for (i = 0; i < mtrr_state.var_count; i++) {
		if (!(mtrr_state.var_range[i].mask & IA32_MTRR_PHYMASK_VALID))
			continue;
		base = mtrr_state.var_range[i].base & IA32_MTRR_PHYSBASE_MASK;
		type = (uint32_t)(mtrr_state.var_range[i].base & IA32_MTRR_PHYSBASE_TYPE);
		length = MASK_TO_LEN(mtrr_state.var_range[i].mask);
		DBG("%d: base: 0x%016llx size: 0x%016llx type: %d\n",
		     i, base, length, type);
		if (base <= lapic_pbase &&
		    lapic_pbase <= base + length - PAGE_SIZE) {
			DBG("mtrr_lapic_cached() matched var: %d\n", i);
			mtrr_state.var_range[i].base &=~IA32_MTRR_PHYSBASE_TYPE;
			mtrr_state.var_range[i].base |= MTRR_TYPE_WRITECOMBINE;
			ml_set_interrupts_enabled(istate);
		}
	}

	/*
	 * In case we didn't find a covering variable range,
	 * we slam WC into the default memory type.
	 */
	mtrr_state.MTRRdefType = MTRR_TYPE_WRITECOMBINE;

	mtrr_update_cpu(); 

	ml_set_interrupts_enabled(istate);

	return;
}
#endif /* DEBUG */
