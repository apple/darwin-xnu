/*
 * Copyright (c) 2003-2004 Apple Computer, Inc. All rights reserved.
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

#include <mach/std_types.h>
#include <i386/cpu_data.h>
#include <i386/cpu_number.h>
#include <i386/perfmon.h>
#include <i386/proc_reg.h>
#include <i386/cpu_threads.h>
#include <i386/mp.h>
#include <i386/cpuid.h>
#include <i386/lock.h>
#include <vm/vm_kern.h>

#ifdef DEBUG
#define	DBG(x...)	kprintf(x)
#else
#define	DBG(x...)
#endif

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
	boolean_t	reserved[18];		/* Max-sized arrays... */
	pmc_ovf_func_t	*ovf_func[18];
#ifdef DEBUG
	pmc_cccr_t	cccr_shadow[18];	/* Last cccr values set */
	pmc_counter_t	counter_shadow[18];	/* Last counter values set */
	uint32_t	ovfs_unexpected[18];	/* Count of unexpected intrs */
#endif
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
		return pmc_P6;
	case 0xf:
		return pmc_P4_Xeon;
	default:
		return pmc_unknown;
	}
}

static void
pmc_p4_intr(void *state)
{
	pmc_table_t	*pmc_table = (pmc_table_t *) cpu_core()->pmc;
	uint32_t	cccr_addr;
	pmc_cccr_t	cccr;
	pmc_id_t	id;
	int		my_logical_cpu = cpu_to_logical_cpu(cpu_number());

	/*
	 * Scan through table for reserved counters with overflow and
	 * with a registered overflow function.
	 */
	for (id = 0; id <= pmc_table->id_max; id++) {
		if (!pmc_table->reserved[id])
			continue;
		cccr_addr = pmc_table->msr_control_base + id;
		cccr.u_u64 = rdmsr64(cccr_addr);
#ifdef DEBUG
		pmc_table->cccr_shadow[id] = cccr;
		*((uint64_t *) &pmc_table->counter_shadow[id]) =
			rdmsr64(pmc_table->msr_counter_base + id);
#endif
		if (cccr.u_htt.ovf == 0)
			continue;
		if ((cccr.u_htt.ovf_pmi_t0 == 1 && my_logical_cpu == 0) ||
		    (cccr.u_htt.ovf_pmi_t1 == 1 && my_logical_cpu == 1)) {
			if (pmc_table->ovf_func[id]) {
				(*pmc_table->ovf_func[id])(id, state);
				/* func expected to clear overflow */
				continue;
			}
		}
		/* Clear overflow for unexpected interrupt */
#ifdef DEBUG
		pmc_table->ovfs_unexpected[id]++;
#endif
	}
}

static void
pmc_p6_intr(void *state)
{
	pmc_table_t	*pmc_table = (pmc_table_t *) cpu_core()->pmc;
	pmc_id_t	id;

	/*
	 * Can't determine which counter has overflow
	 * so call all registered functions.
	 */
	for (id = 0; id <= pmc_table->id_max; id++)
		if (pmc_table->reserved[id] && pmc_table->ovf_func[id])
			(*pmc_table->ovf_func[id])(id, state);
}

int
pmc_init(void)
{
	int		ret;
	cpu_core_t	*my_core;
	pmc_table_t	*pmc_table;
	pmc_machine_t	pmc_type;

	my_core = cpu_core();
	assert(my_core);

	pmc_type = _pmc_machine_type();
	if (pmc_type == pmc_none) {
		return KERN_FAILURE;
	}
	
	pmc_table = (pmc_table_t *) my_core->pmc;
	if (pmc_table == NULL) {
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
			lapic_set_pmi_func(&pmc_p4_intr);
			break;
		case pmc_P6:
			pmc_table->id_max = 1;
			pmc_table->msr_counter_base = MSR_P6_COUNTER_ADDR(0);
			pmc_table->msr_control_base = MSR_P6_PES_ADDR(0);
			lapic_set_pmi_func(&pmc_p6_intr);
			break;
		default:
			break;
		}
		if (!atomic_cmpxchg((uint32_t *) &my_core->pmc,
				    0, (uint32_t) pmc_table)) {
			kmem_free(kernel_map,
				  (vm_offset_t) pmc_table, sizeof(pmc_table_t));
		}
	}
	DBG("pmc_init() done for cpu %d my_core->pmc=0x%x type=%d\n",
		cpu_number(), my_core->pmc, pmc_type);

	return KERN_SUCCESS;
}

static inline pmc_table_t *
pmc_table_valid(pmc_id_t id)
{
	cpu_core_t	*my_core = cpu_core();
	pmc_table_t	*pmc_table;

	assert(my_core);
	
	pmc_table = (pmc_table_t *) my_core->pmc;
	return (pmc_table == NULL ||
		id > pmc_table->id_max ||
		!pmc_table->reserved[id]) ? NULL : pmc_table;
}

int
pmc_machine_type(pmc_machine_t *type)
{
	cpu_core_t	*my_core = cpu_core();
	pmc_table_t	*pmc_table;

	assert(my_core);

	pmc_table = (pmc_table_t *) my_core->pmc;
	if (pmc_table == NULL)
		return KERN_FAILURE;

	*type = pmc_table->machine_type;
	
	return KERN_SUCCESS;
}

int
pmc_reserve(pmc_id_t id)
{
	cpu_core_t	*my_core = cpu_core();
	pmc_table_t	*pmc_table;

	assert(my_core);

	pmc_table = (pmc_table_t *) my_core->pmc;
	if (pmc_table == NULL)
		return KERN_FAILURE;
	if (id > pmc_table->id_max)
		return KERN_INVALID_ARGUMENT;
	if (pmc_table->reserved[id])
		return KERN_FAILURE;

	pmc_table->reserved[id] = TRUE;

	return KERN_SUCCESS;
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
	pmc_table->reserved[id] = FALSE;
	pmc_table->ovf_func[id] = NULL;

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
	
	if (pmc_table->machine_type != pmc_P6)
		return KERN_FAILURE;
	
	*(uint64_t *)evtsel = rdmsr64(pmc_table->msr_control_base + id);

	return KERN_SUCCESS;
}

int
pmc_evtsel_write(pmc_id_t id, pmc_evtsel_t *evtsel)
{
	pmc_table_t	*pmc_table = pmc_table_valid(id);

	if (pmc_table == NULL)
		return KERN_INVALID_ARGUMENT;

	if (pmc_table->machine_type != pmc_P4_Xeon)
		return KERN_FAILURE;
	
	wrmsr64(pmc_table->msr_control_base + id, *(uint64_t *)evtsel);

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

	pmc_table->ovf_func[id] = func;

	return KERN_SUCCESS;
}
