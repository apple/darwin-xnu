/*
 * Copyright (c) 2007-2010 Apple Inc. All rights reserved.
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

#include <mach/machine.h>
#include <mach/processor.h>
#include <kern/kalloc.h>
#include <i386/cpu_affinity.h>
#include <i386/cpu_topology.h>
#include <i386/cpu_threads.h>
#include <i386/machine_cpu.h>
#include <i386/bit_routines.h>
#include <i386/cpu_data.h>
#include <i386/lapic.h>
#include <i386/machine_routines.h>
#include <stddef.h>

__private_extern__ void qsort(
	void * array,
	size_t nmembers,
	size_t member_size,
	int (*)(const void *, const void *));

static int lapicid_cmp(const void *x, const void *y);
static x86_affinity_set_t *find_cache_affinity(x86_cpu_cache_t *L2_cachep);

x86_affinity_set_t      *x86_affinities = NULL;
static int              x86_affinity_count = 0;

extern cpu_data_t cpshadows[];

#if DEVELOPMENT || DEBUG
void iotrace_init(int ncpus);
void traptrace_init(int ncpus);
#endif /* DEVELOPMENT || DEBUG */


/* Re-sort double-mapped CPU data shadows after topology discovery sorts the
 * primary CPU data structures by physical/APIC CPU ID.
 */
static void
cpu_shadow_sort(int ncpus)
{
	for (int i = 0; i < ncpus; i++) {
		cpu_data_t      *cpup = cpu_datap(i);
		ptrdiff_t       coff = cpup - cpu_datap(0);

		cpup->cd_shadow = &cpshadows[coff];
	}
}

/*
 * cpu_topology_sort() is called after all processors have been registered but
 * before any non-boot processor is started.  We establish canonical logical
 * processor numbering - logical cpus must be contiguous, zero-based and
 * assigned in physical (local apic id) order.  This step is required because
 * the discovery/registration order is non-deterministic - cores are registered
 * in differing orders over boots.  Enforcing canonical numbering simplifies
 * identification of processors.
 */
void
cpu_topology_sort(int ncpus)
{
	int             i;
	boolean_t       istate;
	processor_t             lprim = NULL;

	assert(machine_info.physical_cpu == 1);
	assert(machine_info.logical_cpu == 1);
	assert(master_cpu == 0);
	assert(cpu_number() == 0);
	assert(cpu_datap(0)->cpu_number == 0);

	/* Lights out for this */
	istate = ml_set_interrupts_enabled(FALSE);

	if (topo_dbg) {
		TOPO_DBG("cpu_topology_start() %d cpu%s registered\n",
		    ncpus, (ncpus > 1) ? "s" : "");
		for (i = 0; i < ncpus; i++) {
			cpu_data_t      *cpup = cpu_datap(i);
			TOPO_DBG("\tcpu_data[%d]:%p local apic 0x%x\n",
			    i, (void *) cpup, cpup->cpu_phys_number);
		}
	}

	/*
	 * Re-order the cpu_data_ptr vector sorting by physical id.
	 * Skip the boot processor, it's required to be correct.
	 */
	if (ncpus > 1) {
		qsort((void *) &cpu_data_ptr[1],
		    ncpus - 1,
		    sizeof(cpu_data_t *),
		    lapicid_cmp);
	}
	if (topo_dbg) {
		TOPO_DBG("cpu_topology_start() after sorting:\n");
		for (i = 0; i < ncpus; i++) {
			cpu_data_t      *cpup = cpu_datap(i);
			TOPO_DBG("\tcpu_data[%d]:%p local apic 0x%x\n",
			    i, (void *) cpup, cpup->cpu_phys_number);
		}
	}

	/*
	 * Finalize logical numbers and map kept by the lapic code.
	 */
	for (i = 0; i < ncpus; i++) {
		cpu_data_t      *cpup = cpu_datap(i);

		if (cpup->cpu_number != i) {
			kprintf("cpu_datap(%d):%p local apic id 0x%x "
			    "remapped from %d\n",
			    i, cpup, cpup->cpu_phys_number,
			    cpup->cpu_number);
		}
		cpup->cpu_number = i;
		lapic_cpu_map(cpup->cpu_phys_number, i);
		x86_set_logical_topology(&cpup->lcpu, cpup->cpu_phys_number, i);
	}

	cpu_shadow_sort(ncpus);
	x86_validate_topology();

	ml_set_interrupts_enabled(istate);
	TOPO_DBG("cpu_topology_start() LLC is L%d\n", topoParms.LLCDepth + 1);

#if DEVELOPMENT || DEBUG
	iotrace_init(ncpus);
	traptrace_init(ncpus);
#endif /* DEVELOPMENT || DEBUG */

	/*
	 * Let the CPU Power Management know that the topology is stable.
	 */
	topoParms.stable = TRUE;
	pmCPUStateInit();

	/*
	 * Iterate over all logical cpus finding or creating the affinity set
	 * for their LLC cache. Each affinity set possesses a processor set
	 * into which each logical processor is added.
	 */
	TOPO_DBG("cpu_topology_start() creating affinity sets:\n");
	for (i = 0; i < ncpus; i++) {
		cpu_data_t              *cpup = cpu_datap(i);
		x86_lcpu_t              *lcpup = cpu_to_lcpu(i);
		x86_cpu_cache_t         *LLC_cachep;
		x86_affinity_set_t      *aset;

		LLC_cachep = lcpup->caches[topoParms.LLCDepth];
		assert(LLC_cachep->type == CPU_CACHE_TYPE_UNIF);
		aset = find_cache_affinity(LLC_cachep);
		if (aset == NULL) {
			aset = (x86_affinity_set_t *) kalloc(sizeof(*aset));
			if (aset == NULL) {
				panic("cpu_topology_start() failed aset alloc");
			}
			aset->next = x86_affinities;
			x86_affinities = aset;
			aset->num = x86_affinity_count++;
			aset->cache = LLC_cachep;
			aset->pset = (i == master_cpu) ?
			    processor_pset(master_processor) :
			    pset_create(pset_node_root());
			if (aset->pset == PROCESSOR_SET_NULL) {
				panic("cpu_topology_start: pset_create");
			}
			TOPO_DBG("\tnew set %p(%d) pset %p for cache %p\n",
			    aset, aset->num, aset->pset, aset->cache);
		}

		TOPO_DBG("\tprocessor_init set %p(%d) lcpup %p(%d) cpu %p processor %p\n",
		    aset, aset->num, lcpup, lcpup->cpu_num, cpup, cpup->cpu_processor);

		if (i != master_cpu) {
			processor_init(cpup->cpu_processor, i, aset->pset);
		}

		if (lcpup->core->num_lcpus > 1) {
			if (lcpup->lnum == 0) {
				lprim = cpup->cpu_processor;
			}

			processor_set_primary(cpup->cpu_processor, lprim);
		}
	}
}

/* We got a request to start a CPU. Check that this CPU is within the
 * max cpu limit set before we do.
 */
kern_return_t
cpu_topology_start_cpu( int cpunum )
{
	int             ncpus = machine_info.max_cpus;
	int             i = cpunum;

	/* Decide whether to start a CPU, and actually start it */
	TOPO_DBG("cpu_topology_start() processor_start():\n");
	if (i < ncpus) {
		TOPO_DBG("\tlcpu %d\n", cpu_datap(i)->cpu_number);
		processor_start(cpu_datap(i)->cpu_processor);
		return KERN_SUCCESS;
	} else {
		return KERN_FAILURE;
	}
}

static int
lapicid_cmp(const void *x, const void *y)
{
	cpu_data_t      *cpu_x = *((cpu_data_t **)(uintptr_t)x);
	cpu_data_t      *cpu_y = *((cpu_data_t **)(uintptr_t)y);

	TOPO_DBG("lapicid_cmp(%p,%p) (%d,%d)\n",
	    x, y, cpu_x->cpu_phys_number, cpu_y->cpu_phys_number);
	if (cpu_x->cpu_phys_number < cpu_y->cpu_phys_number) {
		return -1;
	}
	if (cpu_x->cpu_phys_number == cpu_y->cpu_phys_number) {
		return 0;
	}
	return 1;
}

static x86_affinity_set_t *
find_cache_affinity(x86_cpu_cache_t *l2_cachep)
{
	x86_affinity_set_t      *aset;

	for (aset = x86_affinities; aset != NULL; aset = aset->next) {
		if (l2_cachep == aset->cache) {
			break;
		}
	}
	return aset;
}

int
ml_get_max_affinity_sets(void)
{
	return x86_affinity_count;
}

processor_set_t
ml_affinity_to_pset(uint32_t affinity_num)
{
	x86_affinity_set_t      *aset;

	for (aset = x86_affinities; aset != NULL; aset = aset->next) {
		if (affinity_num == aset->num) {
			break;
		}
	}
	return (aset == NULL) ? PROCESSOR_SET_NULL : aset->pset;
}

uint64_t
ml_cpu_cache_size(unsigned int level)
{
	x86_cpu_cache_t *cachep;

	if (level == 0) {
		return machine_info.max_mem;
	} else if (1 <= level && level <= MAX_CACHE_DEPTH) {
		cachep = current_cpu_datap()->lcpu.caches[level - 1];
		return cachep ? cachep->cache_size : 0;
	} else {
		return 0;
	}
}

uint64_t
ml_cpu_cache_sharing(unsigned int level)
{
	x86_cpu_cache_t *cachep;

	if (level == 0) {
		return machine_info.max_cpus;
	} else if (1 <= level && level <= MAX_CACHE_DEPTH) {
		cachep = current_cpu_datap()->lcpu.caches[level - 1];
		return cachep ? cachep->nlcpus : 0;
	} else {
		return 0;
	}
}

#if     DEVELOPMENT || DEBUG
volatile int mmiotrace_enabled = 1;
int iotrace_generators = 0;
int iotrace_entries_per_cpu = 0;
int *iotrace_next;
iotrace_entry_t **iotrace_ring;

volatile int traptrace_enabled = 1;
int traptrace_generators = 0;
int traptrace_entries_per_cpu = 0;
int *traptrace_next;
traptrace_entry_t **traptrace_ring;

static void
init_trace_bufs(int cpucnt, int entries_per_cpu, void ***ring, int entry_size,
    int **next_array, int *allocated_entries_per_cpu, int *allocated_generator_count)
{
	int i;

	*next_array = kalloc_tag(cpucnt * sizeof(int), VM_KERN_MEMORY_DIAG);
	if (__improbable(*next_array == NULL)) {
		*allocated_generator_count = 0;
		return;
	} else {
		bzero(*next_array, cpucnt * sizeof(int));
	}

	*ring = kalloc_tag(cpucnt * sizeof(void *), VM_KERN_MEMORY_DIAG);
	if (__improbable(*ring == NULL)) {
		kfree(*next_array, cpucnt * sizeof(int));
		*next_array = NULL;
		*allocated_generator_count = 0;
		return;
	}
	for (i = 0; i < cpucnt; i++) {
		(*ring)[i] = kalloc_tag(entries_per_cpu * entry_size, VM_KERN_MEMORY_DIAG);
		if (__improbable((*ring)[i] == NULL)) {
			kfree(*next_array, cpucnt * sizeof(int));
			*next_array = NULL;
			for (int j = 0; j < i; j++) {
				kfree((*ring)[j], entries_per_cpu * entry_size);
			}
			kfree(*ring, cpucnt * sizeof(void *));
			*ring = NULL;
			return;
		}
		bzero((*ring)[i], entries_per_cpu * entry_size);
	}

	*allocated_entries_per_cpu = entries_per_cpu;
	*allocated_generator_count = cpucnt;
}


static void
init_iotrace_bufs(int cpucnt, int entries_per_cpu)
{
	init_trace_bufs(cpucnt, entries_per_cpu, (void ***)&iotrace_ring, sizeof(iotrace_entry_t),
	    &iotrace_next, &iotrace_entries_per_cpu, &iotrace_generators);
}

static void
init_traptrace_bufs(int cpucnt, int entries_per_cpu)
{
	init_trace_bufs(cpucnt, entries_per_cpu, (void ***)&traptrace_ring, sizeof(traptrace_entry_t),
	    &traptrace_next, &traptrace_entries_per_cpu, &traptrace_generators);
}

static void
gentrace_configure_from_bootargs(const char *ena_prop, int *ena_valp, const char *epc_prop,
    int *epcp, int max_epc, int def_epc, int override)
{
	if (kern_feature_override(override)) {
		*ena_valp = 0;
	}

	(void) PE_parse_boot_argn(ena_prop, ena_valp, sizeof(*ena_valp));

	if (*ena_valp == 0) {
		return;
	}

	if (PE_parse_boot_argn(epc_prop, epcp, sizeof(*epcp)) &&
	    (*epcp < 1 || *epcp > max_epc)) {
		*epcp = def_epc;
	}
}

void
iotrace_init(int ncpus)
{
	int entries_per_cpu = DEFAULT_IOTRACE_ENTRIES_PER_CPU;
	int enable = mmiotrace_enabled;

	gentrace_configure_from_bootargs("iotrace", &enable, "iotrace_epc", &entries_per_cpu,
	    IOTRACE_MAX_ENTRIES_PER_CPU, DEFAULT_IOTRACE_ENTRIES_PER_CPU, KF_IOTRACE_OVRD);

	mmiotrace_enabled = enable;

	if (mmiotrace_enabled) {
		init_iotrace_bufs(ncpus, entries_per_cpu);
	}
}

void
traptrace_init(int ncpus)
{
	int entries_per_cpu = DEFAULT_TRAPTRACE_ENTRIES_PER_CPU;
	int enable = traptrace_enabled;

	gentrace_configure_from_bootargs("traptrace", &enable, "traptrace_epc", &entries_per_cpu,
	    TRAPTRACE_MAX_ENTRIES_PER_CPU, DEFAULT_TRAPTRACE_ENTRIES_PER_CPU, KF_TRAPTRACE_OVRD);

	traptrace_enabled = enable;

	if (traptrace_enabled) {
		init_traptrace_bufs(ncpus, entries_per_cpu);
	}
}

#endif /* DEVELOPMENT || DEBUG */
