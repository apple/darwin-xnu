/*
 * Copyright (c) 2003-2004 Apple Computer, Inc. All rights reserved.
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

#include <mach/std_types.h>
#include <i386/cpu_data.h>
#include <i386/cpu_number.h>
#include <i386/perfmon.h>
#include <i386/proc_reg.h>
#include <i386/cpu_threads.h>
#include <i386/lapic.h>
#include <i386/cpuid.h>
#include <i386/lock.h>
#include <vm/vm_kern.h>
#include <kern/task.h>

#if DEBUG
#define	DBG(x...)	kprintf(x)
#else
#define	DBG(x...)
#endif

static decl_simple_lock_data(,pmc_lock)
static task_t		pmc_owner = TASK_NULL;
static int		pmc_thread_count = 0;
static boolean_t	pmc_inited = FALSE;

/* PMC Facility Owner:
 * TASK_NULL - no one owns it
 * kernel_task - owned by pmc
 * other task - owned by another task
 */

/*
 * Table of ESCRs and addresses associated with performance counters/CCCRs.
 * See Intel SDM Vol 3, Table 15-4 (section 15.9):
 */
static uint16_t pmc_escr_addr_table[18][8] = {
	[MSR_BPU_COUNTER0] {
		[MSR_BSU_ESCR0]		0x3a0,
		[MSR_FSB_ESCR0]		0x3a2,
		[MSR_MOB_ESCR0]		0x3aa,
		[MSR_PMH_ESCR0]		0x3ac,
		[MSR_BPU_ESCR0]		0x3b2,
		[MSR_IS_ESCR0]		0x3b4,
		[MSR_ITLB_ESCR0]	0x3b6,
		[MSR_IX_ESCR0]		0x3c8,
	},
	[MSR_BPU_COUNTER1] {
		[MSR_BSU_ESCR0]		0x3a0,
		[MSR_FSB_ESCR0]		0x3a2,
		[MSR_MOB_ESCR0]		0x3aa,
		[MSR_PMH_ESCR0]		0x3ac,
		[MSR_BPU_ESCR0]		0x3b2,
		[MSR_IS_ESCR0]		0x3b4,
		[MSR_ITLB_ESCR0]	0x3b6,
		[MSR_IX_ESCR0]		0x3c8,
	},
	[MSR_BPU_COUNTER2] {
		[MSR_BSU_ESCR1]		0x3a1,
		[MSR_FSB_ESCR1]		0x3a3,
		[MSR_MOB_ESCR1]		0x3ab,
		[MSR_PMH_ESCR1]		0x3ad,
		[MSR_BPU_ESCR1]		0x3b3,
		[MSR_IS_ESCR1]		0x3b5,
		[MSR_ITLB_ESCR1]	0x3b7,
		[MSR_IX_ESCR1]		0x3c9,
	},
	[MSR_BPU_COUNTER3] {
		[MSR_BSU_ESCR1]		0x3a1,
		[MSR_FSB_ESCR1]		0x3a3,
		[MSR_MOB_ESCR1]		0x3ab,
		[MSR_PMH_ESCR1]		0x3ad,
		[MSR_BPU_ESCR1]		0x3b3,
		[MSR_IS_ESCR1]		0x3b5,
		[MSR_ITLB_ESCR1]	0x3b7,
		[MSR_IX_ESCR1]		0x3c9,
	},
	[MSR_MS_COUNTER0] {
		[MSR_MS_ESCR1]		0x3c1,
		[MSR_TBPU_ESCR1]	0x3c3,
		[MSR_TC_ESCR1]		0x3c5,
	},
	[MSR_MS_COUNTER1] {
		[MSR_MS_ESCR1]		0x3c1,
		[MSR_TBPU_ESCR1]	0x3c3,
		[MSR_TC_ESCR1]		0x3c5,
	},
	[MSR_MS_COUNTER2] {
		[MSR_MS_ESCR1]		0x3c1,
		[MSR_TBPU_ESCR1]	0x3c3,
		[MSR_TC_ESCR1]		0x3c5,
	},
	[MSR_MS_COUNTER3] {
		[MSR_MS_ESCR1]		0x3c1,
		[MSR_TBPU_ESCR1]	0x3c3,
		[MSR_TC_ESCR1]		0x3c5,
	},
	[MSR_FLAME_COUNTER0] {
		[MSR_FIRM_ESCR0]	0x3a4,
		[MSR_FLAME_ESCR0]	0x3a6,
		[MSR_DAC_ESCR0]		0x3a8,
		[MSR_SAT_ESCR0]		0x3ae,
		[MSR_U2L_ESCR0]		0x3b0,
	},
	[MSR_FLAME_COUNTER1] {
		[MSR_FIRM_ESCR0]	0x3a4,
		[MSR_FLAME_ESCR0]	0x3a6,
		[MSR_DAC_ESCR0]		0x3a8,
		[MSR_SAT_ESCR0]		0x3ae,
		[MSR_U2L_ESCR0]		0x3b0,
	},
	[MSR_FLAME_COUNTER2] {
		[MSR_FIRM_ESCR1]	0x3a5,
		[MSR_FLAME_ESCR1]	0x3a7,
		[MSR_DAC_ESCR1]		0x3a9,
		[MSR_SAT_ESCR1]		0x3af,
		[MSR_U2L_ESCR1]		0x3b1,
	},
	[MSR_FLAME_COUNTER3] {
		[MSR_FIRM_ESCR1]	0x3a5,
		[MSR_FLAME_ESCR1]	0x3a7,
		[MSR_DAC_ESCR1]		0x3a9,
		[MSR_SAT_ESCR1]		0x3af,
		[MSR_U2L_ESCR1]		0x3b1,
	},
	[MSR_IQ_COUNTER0] {
		[MSR_CRU_ESCR0]		0x3b8,
		[MSR_CRU_ESCR2]		0x3cc,
		[MSR_CRU_ESCR4]		0x3e0,
		[MSR_IQ_ESCR0]		0x3ba,
		[MSR_RAT_ESCR0]		0x3bc,
		[MSR_SSU_ESCR0]		0x3be,
		[MSR_AFL_ESCR0]		0x3ca,
	},
	[MSR_IQ_COUNTER1] {
		[MSR_CRU_ESCR0]		0x3b8,
		[MSR_CRU_ESCR2]		0x3cc,
		[MSR_CRU_ESCR4]		0x3e0,
		[MSR_IQ_ESCR0]		0x3ba,
		[MSR_RAT_ESCR0]		0x3bc,
		[MSR_SSU_ESCR0]		0x3be,
		[MSR_AFL_ESCR0]		0x3ca,
	},
	[MSR_IQ_COUNTER2] {
		[MSR_CRU_ESCR1]		0x3b9,
		[MSR_CRU_ESCR3]		0x3cd,
		[MSR_CRU_ESCR5]		0x3e1,
		[MSR_IQ_ESCR1]		0x3bb,
		[MSR_RAT_ESCR1]		0x3bd,
		[MSR_AFL_ESCR1]		0x3cb,
	},
	[MSR_IQ_COUNTER3] {
		[MSR_CRU_ESCR1]		0x3b9,
		[MSR_CRU_ESCR3]		0x3cd,
		[MSR_CRU_ESCR5]		0x3e1,
		[MSR_IQ_ESCR1]		0x3bb,
		[MSR_RAT_ESCR1]		0x3bd,
		[MSR_AFL_ESCR1]		0x3cb,
	},
	[MSR_IQ_COUNTER4] {
		[MSR_CRU_ESCR0]		0x3b8,
		[MSR_CRU_ESCR2]		0x3cc,
		[MSR_CRU_ESCR4]		0x3e0,
		[MSR_IQ_ESCR0]		0x3ba,
		[MSR_RAT_ESCR0]		0x3bc,
		[MSR_SSU_ESCR0]		0x3be,
		[MSR_AFL_ESCR0]		0x3ca,
	},
	[MSR_IQ_COUNTER5] {
		[MSR_CRU_ESCR1]		0x3b9,
		[MSR_CRU_ESCR3]		0x3cd,
		[MSR_CRU_ESCR5]		0x3e1,
		[MSR_IQ_ESCR1]		0x3bb,
		[MSR_RAT_ESCR1]		0x3bd,
		[MSR_AFL_ESCR1]		0x3cb,
	},
};
#define PMC_ESCR_ADDR(id,esid)	pmc_escr_addr_table[id][esid]

typedef struct {
	pmc_id_t	id_max;			/* Maximum counter id */
	pmc_machine_t	machine_type;		/* P6 or P4/Xeon */
	uint32_t	msr_counter_base;	/* First counter MSR */
	uint32_t	msr_control_base;	/* First control MSR */
	union {
	    struct {
		boolean_t	reserved[2];
		pmc_ovf_func_t	*ovf_func[2];
	    } P6;
	    struct {
		boolean_t	reserved[2];
		pmc_ovf_func_t	*ovf_func[2];
		uint32_t	msr_global_ctrl;
		uint32_t	msr_global_ovf_ctrl;
		uint32_t	msr_global_status;
	    } Core;
	    struct {
		boolean_t	reserved[18];
		pmc_ovf_func_t	*ovf_func[18];
#ifdef DEBUG
		pmc_cccr_t	cccr_shadow[18];	/* Last cccr set */
		pmc_counter_t	counter_shadow[18];	/* Last counter set */
		uint32_t	ovfs_unexpected[18];	/* Unexpected intrs */
#endif
	    } P4;
	};
} pmc_table_t;

static pmc_machine_t
_pmc_machine_type(void)
{
	i386_cpu_info_t	*infop = cpuid_info();
        
	if (strncmp(infop->cpuid_vendor, CPUID_VID_INTEL, sizeof(CPUID_VID_INTEL)) != 0)
		return pmc_none;
	
	if (!pmc_is_available())
		return pmc_none;

	switch (infop->cpuid_family) {
	case 0x6:
		switch (infop->cpuid_model) {
		case 15:
			return pmc_Core;
		default:
			return pmc_P6;
		}
	case 0xf:
		return pmc_P4_Xeon;
	default:
		return pmc_unknown;
	}
}

static void
pmc_p4_intr(void *state)
{
	pmc_table_t	*pmc_table = (pmc_table_t *) x86_lcpu()->pmc;
	uint32_t	cccr_addr;
	pmc_cccr_t	cccr;
	pmc_id_t	id;
	int		my_logical_cpu = cpu_to_logical_cpu(cpu_number());

	/*
	 * Scan through table for reserved counters with overflow and
	 * with a registered overflow function.
	 */
	for (id = 0; id <= pmc_table->id_max; id++) {
		if (!pmc_table->P4.reserved[id])
			continue;
		cccr_addr = pmc_table->msr_control_base + id;
		cccr.u_u64 = rdmsr64(cccr_addr);
#ifdef DEBUG
		pmc_table->P4.cccr_shadow[id] = cccr;
		pmc_table->P4.counter_shadow[id].u64 =
			rdmsr64(pmc_table->msr_counter_base + id);
#endif
		if (cccr.u_htt.ovf == 0)
			continue;
		if ((cccr.u_htt.ovf_pmi_t0 == 1 && my_logical_cpu == 0) ||
		    (cccr.u_htt.ovf_pmi_t1 == 1 && my_logical_cpu == 1)) {
			if (pmc_table->P4.ovf_func[id]) {
				(*pmc_table->P4.ovf_func[id])(id, state);
				/* func expected to clear overflow */
				continue;
			}
		}
		/* Clear overflow for unexpected interrupt */
#ifdef DEBUG
		pmc_table->P4.ovfs_unexpected[id]++;
#endif
	}
}

static void
pmc_p6_intr(void *state)
{
	pmc_table_t	*pmc_table = (pmc_table_t *) x86_lcpu()->pmc;
	pmc_id_t	id;

	/*
	 * Can't determine which counter has overflow
	 * so call all registered functions.
	 */
	for (id = 0; id <= pmc_table->id_max; id++)
		if (pmc_table->P6.reserved[id] && pmc_table->P6.ovf_func[id])
			(*pmc_table->P6.ovf_func[id])(id, state);
}

static void
pmc_core_intr(void *state)
{
	pmc_table_t	*pmc_table = (pmc_table_t *) x86_lcpu()->pmc;
	pmc_id_t	id;
	pmc_global_status_t	ovf_status;

	ovf_status.u64 = rdmsr64(pmc_table->Core.msr_global_status);
	/*
	 * Scan through table for reserved counters with overflow and
	 * with a registered overflow function.
	 */
	for (id = 0; id <= pmc_table->id_max; id++) {
		if (!pmc_table->Core.reserved[id])
			continue;
		if ((id == 0 && ovf_status.fld.PMC0_overflow) ||
		    (id == 1 && ovf_status.fld.PMC1_overflow)) {
			if (pmc_table->Core.ovf_func[id]) {
				(*pmc_table->Core.ovf_func[id])(id, state);
				/* func expected to clear overflow */
				continue;
			}
		}
	}
}

void *
pmc_alloc(void)
{
	int		ret;
	pmc_table_t	*pmc_table;
	pmc_machine_t	pmc_type;

	if (!pmc_inited) {
		simple_lock_init(&pmc_lock, 0);
		pmc_inited = TRUE;
	}

	pmc_type = _pmc_machine_type();
	if (pmc_type == pmc_none) {
		return NULL;
	}
	
	ret = kmem_alloc(kernel_map,
		(void *) &pmc_table, sizeof(pmc_table_t));
	if (ret != KERN_SUCCESS)
		panic("pmc_init() kmem_alloc returned %d\n", ret);
	bzero((void *)pmc_table, sizeof(pmc_table_t));

	pmc_table->machine_type = pmc_type;
	switch (pmc_type) {
	case pmc_P4_Xeon:
		pmc_table->id_max = 17;
		pmc_table->msr_counter_base = MSR_COUNTER_ADDR(0);
		pmc_table->msr_control_base = MSR_CCCR_ADDR(0);
		lapic_set_pmi_func((i386_intr_func_t) &pmc_p4_intr);
		break;
	case pmc_Core:
		pmc_table->id_max = 1;
		pmc_table->msr_counter_base = MSR_IA32_PMC(0);
		pmc_table->msr_control_base = MSR_IA32_PERFEVTSEL(0);
		pmc_table->Core.msr_global_ctrl = MSR_PERF_GLOBAL_CTRL;
		pmc_table->Core.msr_global_ovf_ctrl = MSR_PERF_GLOBAL_OVF_CTRL;
		pmc_table->Core.msr_global_status = MSR_PERF_GLOBAL_STATUS;
		lapic_set_pmi_func((i386_intr_func_t) &pmc_core_intr);
		break;
	case pmc_P6:
		pmc_table->id_max = 1;
		pmc_table->msr_counter_base = MSR_P6_COUNTER_ADDR(0);
		pmc_table->msr_control_base = MSR_P6_PES_ADDR(0);
		lapic_set_pmi_func((i386_intr_func_t) &pmc_p6_intr);
		break;
	default:
		break;
	}
	DBG("pmc_alloc() type=%d msr_counter_base=%p msr_control_base=%p\n",
		pmc_table->machine_type,
	(void *) pmc_table->msr_counter_base,
	(void *) pmc_table->msr_control_base);
	return (void *) pmc_table;
}


static inline pmc_table_t *
pmc_table_valid(pmc_id_t id)
{
	x86_lcpu_t	*my_lcpu = x86_lcpu();
	pmc_table_t	*pmc;

	assert(my_lcpu != NULL);
	
	pmc = (pmc_table_t *) my_lcpu->pmc;
	if ((pmc == NULL) ||
	    (id > pmc->id_max) ||
	    (pmc->machine_type == pmc_P4_Xeon && !pmc->P4.reserved[id]) ||
	    (pmc->machine_type == pmc_P6      && !pmc->P6.reserved[id]) ||
	    (pmc->machine_type == pmc_Core    && !pmc->Core.reserved[id]))
		return NULL;
	return pmc;
}

int
pmc_machine_type(pmc_machine_t *type)
{
	x86_lcpu_t	*my_lcpu = x86_lcpu();
	pmc_table_t	*pmc_table;

	assert(my_lcpu != NULL);

	pmc_table = (pmc_table_t *) my_lcpu->pmc;
	if (pmc_table == NULL)
		return KERN_FAILURE;

	*type = pmc_table->machine_type;
	
	return KERN_SUCCESS;
}

int
pmc_reserve(pmc_id_t id)
{
	x86_lcpu_t	*my_lcpu = x86_lcpu();
	pmc_table_t	*pmc_table;

	assert(my_lcpu != NULL);

	pmc_table = (pmc_table_t *) my_lcpu->pmc;
	if (pmc_table == NULL)
		return KERN_FAILURE;
	if (id > pmc_table->id_max)
		return KERN_INVALID_ARGUMENT;
	switch (pmc_table->machine_type) {
	case pmc_P4_Xeon:
		if (pmc_table->P4.reserved[id])
			return KERN_FAILURE;
		pmc_table->P4.reserved[id] = TRUE;
		return KERN_SUCCESS;
	case pmc_P6:
		if (pmc_table->P6.reserved[id])
			return KERN_FAILURE;
		pmc_table->P6.reserved[id] = TRUE;
		return KERN_SUCCESS;
	case pmc_Core:
		if (pmc_table->Core.reserved[id])
			return KERN_FAILURE;
		pmc_table->Core.reserved[id] = TRUE;
		pmc_global_ctrl_t ctrl;
		ctrl.u64 = rdmsr64(pmc_table->Core.msr_global_ctrl);
		if (id == 0)
			ctrl.fld.PMC0_enable = 1;
		else
			ctrl.fld.PMC1_enable = 1;
		wrmsr64(pmc_table->Core.msr_global_ctrl, ctrl.u64);
		return KERN_SUCCESS;
	default:
		return KERN_FAILURE;
	}
}

boolean_t
pmc_is_reserved(pmc_id_t id)
{
	return pmc_table_valid(id) != NULL;
}

int
pmc_free(pmc_id_t id)
{
	pmc_table_t	*pmc_table = pmc_table_valid(id);

	if (pmc_table == NULL)
		return KERN_INVALID_ARGUMENT;

	pmc_cccr_write(id, 0x0ULL);
	switch (pmc_table->machine_type) {
	case pmc_P4_Xeon:
		pmc_table->P4.reserved[id] = FALSE;
		pmc_table->P4.ovf_func[id] = NULL;
		break;
	case pmc_P6:
		pmc_table->P6.reserved[id] = FALSE;
		pmc_table->P6.ovf_func[id] = NULL;
		break;
	case pmc_Core:
		pmc_table->Core.reserved[id] = FALSE;
		pmc_table->Core.ovf_func[id] = NULL;
		pmc_global_ctrl_t ctrl;
		ctrl.u64 = rdmsr64(pmc_table->Core.msr_global_ctrl);
		if (id == 0)
			ctrl.fld.PMC0_enable = 0;
		else
			ctrl.fld.PMC1_enable = 0;
		wrmsr64(pmc_table->Core.msr_global_ctrl, ctrl.u64);
		break;
	default:
		return KERN_INVALID_ARGUMENT;
	}

	return KERN_SUCCESS;
}

int
pmc_counter_read(pmc_id_t id, pmc_counter_t *val)
{
	pmc_table_t	*pmc_table = pmc_table_valid(id);

	if (pmc_table == NULL)
		return KERN_INVALID_ARGUMENT;
	
	*(uint64_t *)val = rdmsr64(pmc_table->msr_counter_base + id);

	return KERN_SUCCESS;
}

int
pmc_counter_write(pmc_id_t id, pmc_counter_t *val)
{
	pmc_table_t	*pmc_table = pmc_table_valid(id);

	if (pmc_table == NULL)
		return KERN_INVALID_ARGUMENT;
	
	wrmsr64(pmc_table->msr_counter_base + id, *(uint64_t *)val);

	return KERN_SUCCESS;
}

int
pmc_cccr_read(pmc_id_t id, pmc_cccr_t *cccr)
{
	pmc_table_t	*pmc_table = pmc_table_valid(id);

	if (pmc_table == NULL)
		return KERN_INVALID_ARGUMENT;
	
	if (pmc_table->machine_type != pmc_P4_Xeon)
		return KERN_FAILURE;
	
	*(uint64_t *)cccr = rdmsr64(pmc_table->msr_control_base + id);

	return KERN_SUCCESS;
}

int
pmc_cccr_write(pmc_id_t id, pmc_cccr_t *cccr)
{
	pmc_table_t	*pmc_table = pmc_table_valid(id);

	if (pmc_table == NULL)
		return KERN_INVALID_ARGUMENT;

	if (pmc_table->machine_type != pmc_P4_Xeon)
		return KERN_FAILURE;
	
	wrmsr64(pmc_table->msr_control_base + id, *(uint64_t *)cccr);

	return KERN_SUCCESS;
}

int
pmc_evtsel_read(pmc_id_t id, pmc_evtsel_t *evtsel)
{
	pmc_table_t	*pmc_table = pmc_table_valid(id);

	if (pmc_table == NULL)
		return KERN_INVALID_ARGUMENT;
	
	if (!(pmc_table->machine_type == pmc_P6 ||
	      pmc_table->machine_type == pmc_Core))
		return KERN_FAILURE;
	
	evtsel->u64 = rdmsr64(pmc_table->msr_control_base + id);

	return KERN_SUCCESS;
}

int
pmc_evtsel_write(pmc_id_t id, pmc_evtsel_t *evtsel)
{
	pmc_table_t	*pmc_table = pmc_table_valid(id);

	if (pmc_table == NULL)
		return KERN_INVALID_ARGUMENT;

	if (!(pmc_table->machine_type == pmc_P6 ||
	      pmc_table->machine_type == pmc_Core))
		return KERN_FAILURE;
	
	wrmsr64(pmc_table->msr_control_base + id, evtsel->u64);

	return KERN_SUCCESS;
}

int
pmc_escr_read(pmc_id_t id, pmc_escr_id_t esid, pmc_escr_t *escr)
{
	uint32_t	addr;
	pmc_table_t	*pmc_table = pmc_table_valid(id);

	if (pmc_table == NULL)
		return KERN_INVALID_ARGUMENT;

	if (pmc_table->machine_type != pmc_P4_Xeon)
		return KERN_FAILURE;
	
	if (esid > PMC_ESID_MAX)
		return KERN_INVALID_ARGUMENT;

	addr = PMC_ESCR_ADDR(id, esid);
	if (addr == 0)
		return KERN_INVALID_ARGUMENT;

	*(uint64_t *)escr = rdmsr64(addr);

	return KERN_SUCCESS;
}

int
pmc_escr_write(pmc_id_t id, pmc_escr_id_t esid, pmc_escr_t *escr)
{
	uint32_t	addr;
	pmc_table_t	*pmc_table = pmc_table_valid(id);

	if (pmc_table == NULL)
		return KERN_FAILURE;

	if (pmc_table->machine_type != pmc_P4_Xeon)
		return KERN_FAILURE;
	
	if (esid > PMC_ESID_MAX)
		return KERN_INVALID_ARGUMENT;

	addr = PMC_ESCR_ADDR(id, esid);
	if (addr == 0)
		return KERN_INVALID_ARGUMENT;

	wrmsr64(addr, *(uint64_t *)escr);

	return KERN_SUCCESS;
}

int
pmc_set_ovf_func(pmc_id_t id, pmc_ovf_func_t func)
{
	pmc_table_t	*pmc_table = pmc_table_valid(id);

	if (pmc_table == NULL)
		return KERN_INVALID_ARGUMENT;

	switch (pmc_table->machine_type) {
	case pmc_P4_Xeon:
		pmc_table->P4.ovf_func[id] = func;
		break;
	case pmc_P6:
		pmc_table->P6.ovf_func[id] = func;
		break;
	case pmc_Core:
		pmc_table->Core.ovf_func[id] = func;
		break;
	default:
		return KERN_INVALID_ARGUMENT;
	}

	return KERN_SUCCESS;
}

int
pmc_acquire(task_t task)
{
	kern_return_t retval = KERN_SUCCESS;
  
	if (!pmc_inited)
		return KERN_FAILURE;

	simple_lock(&pmc_lock);
  
	if(pmc_owner == task) {
		DBG("pmc_acquire - "
		    "ACQUIRED: already owner\n");
		retval = KERN_SUCCESS;
		/* already own it */
	} else if(pmc_owner == TASK_NULL) { /* no one owns it */
		pmc_owner = task;
		pmc_thread_count = 0;
		DBG("pmc_acquire - "
		    "ACQUIRED: no current owner - made new owner\n");
		retval = KERN_SUCCESS;
	} else { /* someone already owns it */
		if(pmc_owner == kernel_task) {
			if(pmc_thread_count == 0) {
				/* kernel owns it but no threads using it */
				pmc_owner = task;
				pmc_thread_count = 0;
				DBG("pmc_acquire - "
				    "ACQUIRED: owned by kernel, no threads\n");
				retval = KERN_SUCCESS;
			} else {
				DBG("pmc_acquire - "
				    "DENIED: owned by kernel, in use\n");
				retval = KERN_RESOURCE_SHORTAGE;
			}
		} else { /* non-kernel owner */
			DBG("pmc_acquire - "	
			    "DENIED: owned by another task\n");
			retval = KERN_RESOURCE_SHORTAGE;
		}
	}
  
	simple_unlock(&pmc_lock);
	return retval;
}

int
pmc_release(task_t task)
{
	kern_return_t retval = KERN_SUCCESS;
	task_t old_pmc_owner = pmc_owner;
  
	if (!pmc_inited)
		return KERN_FAILURE;

	simple_lock(&pmc_lock);
  
	if(task != pmc_owner) {
		retval = KERN_NO_ACCESS;
	} else {
		if(old_pmc_owner == kernel_task) {
			if(pmc_thread_count>0) {
				DBG("pmc_release - "
				    "NOT RELEASED: owned by kernel, in use\n");
				retval = KERN_NO_ACCESS;
			} else {
				DBG("pmc_release - "
				    "RELEASED: was owned by kernel\n");
				pmc_owner = TASK_NULL;
				retval = KERN_SUCCESS;
			}
		} else {
			DBG("pmc_release - "
			    "RELEASED: was owned by user\n");
			pmc_owner = TASK_NULL;
			retval = KERN_SUCCESS;
		}
	}

	simple_unlock(&pmc_lock);
	return retval;
}

