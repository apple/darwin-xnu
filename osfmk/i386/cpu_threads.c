/*
 * Copyright (c) 2003-2008 Apple Inc. All rights reserved.
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
#include <vm/vm_kern.h>
#include <kern/kalloc.h>
#include <mach/machine.h>
#include <i386/cpu_threads.h>
#include <i386/cpuid.h>
#include <i386/machine_cpu.h>
#include <i386/lock.h>
#include <i386/perfmon.h>
#include <i386/pmCPU.h>

#define bitmask(h,l)	((bit(h)|(bit(h)-1)) & ~(bit(l)-1))
#define bitfield(x,h,l)	(((x) & bitmask(h,l)) >> l)

/*
 * Kernel parameter determining whether threads are halted unconditionally
 * in the idle state.  This is the default behavior.
 * See machine_idle() for use.
 */
int idlehalt = 1;

x86_pkg_t	*x86_pkgs	= NULL;
uint32_t	num_packages	= 0;
uint32_t	num_Lx_caches[MAX_CACHE_DEPTH]	= { 0 };

static x86_pkg_t	*free_pkgs	= NULL;
static x86_core_t	*free_cores	= NULL;

static x86_cpu_cache_t	*x86_caches	= NULL;
static uint32_t		num_caches	= 0;

decl_simple_lock_data(, x86_topo_lock);

static x86_cpu_cache_t *
x86_cache_alloc(void)
{
    x86_cpu_cache_t	*cache;
    int			i;

    if (x86_caches == NULL) {
	cache = kalloc(sizeof(x86_cpu_cache_t) + (MAX_CPUS * sizeof(x86_lcpu_t *)));
	if (cache == NULL)
	    return(NULL);
    } else {
	cache = x86_caches;
	x86_caches = cache->next;
	cache->next = NULL;
    }

    bzero(cache, sizeof(x86_cpu_cache_t));
    cache->next = NULL;
    cache->maxcpus = MAX_CPUS;
    for (i = 0; i < cache->maxcpus; i += 1) {
	cache->cpus[i] = NULL;
    }

    num_caches += 1;

    return(cache);
}

static void
x86_cache_free(x86_cpu_cache_t *cache)
{
    num_caches -= 1;
    if (cache->level > 0 && cache->level <= MAX_CACHE_DEPTH)
	num_Lx_caches[cache->level - 1] -= 1;
    cache->next = x86_caches;
    x86_caches = cache;
}

/*
 * This returns a list of cache structures that represent the
 * caches for a CPU.  Some of the structures may have to be
 * "freed" if they are actually shared between CPUs.
 */
static x86_cpu_cache_t *
x86_cache_list(void)
{
    x86_cpu_cache_t	*root	= NULL;
    x86_cpu_cache_t	*cur	= NULL;
    x86_cpu_cache_t	*last	= NULL;
    uint32_t		index;
    uint32_t		cache_info[4];
    uint32_t		nsets;

    do_cpuid(0, cache_info);

    if (cache_info[eax] < 4) {
	/*
	 * Processor does not support deterministic
	 * cache information. Don't report anything
	 */
	return NULL;
    }

    for (index = 0; ; index += 1) {
	cache_info[eax] = 4;
	cache_info[ecx] = index;
	cache_info[ebx] = 0;
	cache_info[edx] = 0;

	cpuid(cache_info);

	/*
	 * See if all levels have been queried.
	 */
	if (bitfield(cache_info[eax], 4, 0) == 0)
	    break;

	cur = x86_cache_alloc();
	if (cur == NULL) {
	    break;
	}

	cur->type = bitfield(cache_info[eax], 4, 0);
	cur->level = bitfield(cache_info[eax], 7, 5);
	cur->nlcpus = bitfield(cache_info[eax], 25, 14) + 1;
	cur->line_size = bitfield(cache_info[ebx], 11, 0) + 1;
	cur->partitions = bitfield(cache_info[ebx], 21, 12) + 1;
	cur->ways = bitfield(cache_info[ebx], 31, 22) + 1;
	nsets = bitfield(cache_info[ecx], 31, 0) + 1;
	cur->cache_size = cur->line_size * cur->ways * cur->partitions * nsets;

	if (last == NULL) {
	    root = cur;
	    last = cur;
	} else {
	    last->next = cur;
	    last = cur;
	}

	num_Lx_caches[cur->level - 1] += 1;
    }

    return(root);
}

static boolean_t
cpu_is_hyperthreaded(void)
{
    if  (cpuid_features() & CPUID_FEATURE_HTT)
	return (cpuid_info()->cpuid_logical_per_package /
		cpuid_info()->cpuid_cores_per_package) > 1;
    else
	return FALSE;
}

static void
x86_lcpu_init(int cpu)
{
    cpu_data_t		*cpup;
    x86_lcpu_t		*lcpu;
    int			i;

    cpup = cpu_datap(cpu);

    lcpu = &cpup->lcpu;
    lcpu->lcpu = lcpu;
    lcpu->cpu  = cpup;
    lcpu->next = NULL;
    lcpu->core = NULL;
    lcpu->lnum = cpu;
    lcpu->pnum = cpup->cpu_phys_number;
    lcpu->halted = FALSE;	/* XXX is this correct? */
    lcpu->idle   = FALSE;	/* XXX is this correct? */
    for (i = 0; i < MAX_CACHE_DEPTH; i += 1)
	lcpu->caches[i] = NULL;

    lcpu->master = (lcpu->pnum == (unsigned int) master_cpu);
    lcpu->primary = (lcpu->pnum % cpuid_info()->cpuid_logical_per_package) == 0;
}

static x86_core_t *
x86_core_alloc(int cpu)
{
    x86_core_t	*core;
    cpu_data_t	*cpup;
    uint32_t	cpu_in_pkg;
    uint32_t	lcpus_per_core;

    cpup = cpu_datap(cpu);

    simple_lock(&x86_topo_lock);
    if (free_cores != NULL) {
	core = free_cores;
	free_cores = core->next;
	core->next = NULL;
	simple_unlock(&x86_topo_lock);
    } else {
	simple_unlock(&x86_topo_lock);
	core = kalloc(sizeof(x86_core_t));
	if (core == NULL)
	    panic("x86_core_alloc() kalloc of x86_core_t failed!\n");
    }

    bzero((void *) core, sizeof(x86_core_t));

    cpu_in_pkg = cpu % cpuid_info()->cpuid_logical_per_package;
    lcpus_per_core = cpuid_info()->cpuid_logical_per_package /
		     cpuid_info()->cpuid_cores_per_package;

    core->pcore_num = cpup->cpu_phys_number / lcpus_per_core;
    core->lcore_num = core->pcore_num % cpuid_info()->cpuid_cores_per_package;

    core->flags = X86CORE_FL_PRESENT | X86CORE_FL_READY
	        | X86CORE_FL_HALTED | X86CORE_FL_IDLE;

    return(core);
}

static void
x86_core_free(x86_core_t *core)
{
    simple_lock(&x86_topo_lock);
    core->next = free_cores;
    free_cores = core;
    simple_unlock(&x86_topo_lock);
}

static x86_pkg_t *
x86_package_find(int cpu)
{
    x86_pkg_t	*pkg;
    cpu_data_t	*cpup;
    uint32_t	pkg_num;

    cpup = cpu_datap(cpu);

    pkg_num = cpup->cpu_phys_number / cpuid_info()->cpuid_logical_per_package;

    pkg = x86_pkgs;
    while (pkg != NULL) {
	if (pkg->ppkg_num == pkg_num)
	    break;
	pkg = pkg->next;
    }

    return(pkg);
}

static x86_core_t *
x86_core_find(int cpu)
{
    x86_core_t	*core;
    x86_pkg_t	*pkg;
    cpu_data_t	*cpup;
    uint32_t	core_num;

    cpup = cpu_datap(cpu);

    core_num = cpup->cpu_phys_number
	       / (cpuid_info()->cpuid_logical_per_package
		  / cpuid_info()->cpuid_cores_per_package);

    pkg = x86_package_find(cpu);
    if (pkg == NULL)
	return(NULL);

    core = pkg->cores;
    while (core != NULL) {
	if (core->pcore_num == core_num)
	    break;
	core = core->next;
    }

    return(core);
}

static void
x86_core_add_lcpu(x86_core_t *core, x86_lcpu_t *lcpu)
{
    x86_cpu_cache_t	*list;
    x86_cpu_cache_t	*cur;
    x86_core_t		*cur_core;
    x86_lcpu_t		*cur_lcpu;
    boolean_t		found;
    int			level;
    int			i;
    uint32_t		cpu_mask;

    assert(core != NULL);
    assert(lcpu != NULL);

    /*
     * Add the cache data to the topology.
     */
    list = x86_cache_list();

    simple_lock(&x86_topo_lock);

    while (list != NULL) {
	/*
	 * Remove the cache from the front of the list.
	 */
	cur = list;
	list = cur->next;
	cur->next = NULL;
	level = cur->level - 1;

	/*
	 * If the cache isn't shared then just put it where it
	 * belongs.
	 */
	if (cur->nlcpus == 1) {
	    goto found_first;
	}

	/*
	 * We'll assume that all of the caches at a particular level
	 * have the same sharing.  So if we have a cache already at
	 * this level, we'll just skip looking for the match.
	 */
	if (lcpu->caches[level] != NULL) {
	    x86_cache_free(cur);
	    continue;
	}

	/*
	 * This is a shared cache, so we have to figure out if
	 * this is the first time we've seen this cache.  We do
	 * this by searching through the package and seeing if
	 * a related core is already describing this cache.
	 *
	 * NOTE: This assumes that CPUs whose ID mod <# sharing cache>
	 * are indeed sharing the cache.
	 */
	cpu_mask = lcpu->pnum & ~(cur->nlcpus - 1);
	cur_core = core->package->cores;
	found = FALSE;

	while (cur_core != NULL && !found) {
	    cur_lcpu = cur_core->lcpus;
	    while (cur_lcpu != NULL && !found) {
		if ((cur_lcpu->pnum & ~(cur->nlcpus - 1)) == cpu_mask) {
		    lcpu->caches[level] = cur_lcpu->caches[level];
		    found = TRUE;
		    x86_cache_free(cur);

		    /*
		     * Put the new CPU into the list of the cache.
		     */
		    cur = lcpu->caches[level];
		    for (i = 0; i < cur->nlcpus; i += 1) {
			if (cur->cpus[i] == NULL) {
			    cur->cpus[i] = lcpu;
			    break;
			}
		    }
		}
		cur_lcpu = cur_lcpu->next;
	    }

	    cur_core = cur_core->next;
	}

	if (!found) {
found_first:
	    cur->next = lcpu->caches[level];
	    lcpu->caches[level] = cur;
	    cur->cpus[0] = lcpu;
	}
    }

    /*
     * Add the Logical CPU to the core.
     */
    lcpu->next = core->lcpus;
    lcpu->core = core;
    core->lcpus = lcpu;
    core->num_lcpus += 1;

    simple_unlock(&x86_topo_lock);
}

static x86_pkg_t *
x86_package_alloc(int cpu)
{
    x86_pkg_t	*pkg;
    cpu_data_t	*cpup;

    cpup = cpu_datap(cpu);

    simple_lock(&x86_topo_lock);
    if (free_pkgs != NULL) {
	pkg = free_pkgs;
	free_pkgs = pkg->next;
	pkg->next = NULL;
	simple_unlock(&x86_topo_lock);
    } else {
	simple_unlock(&x86_topo_lock);
	pkg = kalloc(sizeof(x86_pkg_t));
	if (pkg == NULL)
	    panic("x86_package_alloc() kalloc of x86_pkg_t failed!\n");
    }

    bzero((void *) pkg, sizeof(x86_pkg_t));

    pkg->ppkg_num = cpup->cpu_phys_number
		    / cpuid_info()->cpuid_logical_per_package;

    pkg->lpkg_num = num_packages;
    atomic_incl((long *) &num_packages, 1);

    pkg->flags = X86PKG_FL_PRESENT | X86PKG_FL_READY;
    return(pkg);
}

static void
x86_package_free(x86_pkg_t *pkg)
{
    simple_lock(&x86_topo_lock);
    pkg->next = free_pkgs;
    free_pkgs = pkg;
    atomic_decl((long *) &num_packages, 1);
    simple_unlock(&x86_topo_lock);
}

static void
x86_package_add_core(x86_pkg_t *pkg, x86_core_t *core)
{
    assert(pkg != NULL);
    assert(core != NULL);

    core->next = pkg->cores;
    core->package = pkg;
    pkg->cores = core;
    pkg->num_cores += 1;
}

void *
cpu_thread_alloc(int cpu)
{
    x86_core_t	*core;
    x86_pkg_t	*pkg;
    cpu_data_t	*cpup;
    uint32_t	phys_cpu;

    cpup = cpu_datap(cpu);

    phys_cpu = cpup->cpu_phys_number;

    x86_lcpu_init(cpu);

    /*
     * Assume that all cpus have the same features.
     */
    if (cpu_is_hyperthreaded()) {
	cpup->cpu_threadtype = CPU_THREADTYPE_INTEL_HTT;
    } else {
	cpup->cpu_threadtype = CPU_THREADTYPE_NONE;
    }

    /*
     * Only allow one to manipulate the topology at a time.
     */
    simple_lock(&x86_topo_lock);

    /*
     * Get the core for this logical CPU.
     */
  core_again:
    core = x86_core_find(cpu);
    if (core == NULL) {
	/*
	 * Core structure hasn't been created yet, do it now.
	 *
	 * Get the package that the core is part of.
	 */
      package_again:
	pkg = x86_package_find(cpu);
	if (pkg == NULL) {
	    /*
	     * Package structure hasn't been created yet, do it now.
	     */
	    simple_unlock(&x86_topo_lock);
	    pkg = x86_package_alloc(cpu);
	    simple_lock(&x86_topo_lock);
	    if (x86_package_find(cpu) != NULL) {
		x86_package_free(pkg);
		goto package_again;
	    }
	    
	    /*
	     * Add the new package to the global list of packages.
	     */
	    pkg->next = x86_pkgs;
	    x86_pkgs = pkg;
	}

	/*
	 * Allocate the core structure now.
	 */
	simple_unlock(&x86_topo_lock);
	core = x86_core_alloc(cpu);
	simple_lock(&x86_topo_lock);
	if (x86_core_find(cpu) != NULL) {
	    x86_core_free(core);
	    goto core_again;
	}

	/*
	 * Add it to the package.
	 */
	x86_package_add_core(pkg, core);
	machine_info.physical_cpu_max += 1;

	/*
	 * Allocate performance counter structure.
	 */
	simple_unlock(&x86_topo_lock);
	core->pmc = pmc_alloc();
	simple_lock(&x86_topo_lock);
    }
    
    /*
     * Done manipulating the topology, so others can get in.
     */
    machine_info.logical_cpu_max += 1;
    simple_unlock(&x86_topo_lock);

    x86_core_add_lcpu(core, &cpup->lcpu);

    return (void *) core;
}

void
cpu_thread_init(void)
{
    int		my_cpu	= get_cpu_number();
    cpu_data_t	*cpup	= current_cpu_datap();
    x86_core_t	*core;
    static int	initialized = 0;

    /*
     * If we're the boot processor, we do all of the initialization of
     * the CPU topology infrastructure.
     */
    if (my_cpu == master_cpu && !initialized) {
	simple_lock_init(&x86_topo_lock, 0);

	/*
	 * Put this logical CPU into the physical CPU topology.
	 */
	cpup->lcpu.core = cpu_thread_alloc(my_cpu);

	initialized = 1;
    }

    /*
     * Do the CPU accounting.
     */
    core = cpup->lcpu.core;
    simple_lock(&x86_topo_lock);
    machine_info.logical_cpu += 1;
    if (core->active_lcpus == 0)
	machine_info.physical_cpu += 1;
    core->active_lcpus += 1;
    cpup->lcpu.halted = FALSE;
    cpup->lcpu.idle   = FALSE;
    simple_unlock(&x86_topo_lock);

    pmCPUMarkRunning(cpup);
    etimer_resync_deadlines();
}

/*
 * Called for a cpu to halt permanently
 * (as opposed to halting and expecting an interrupt to awaken it).
 */
void
cpu_thread_halt(void)
{
    x86_core_t	*core;
    cpu_data_t	*cpup = current_cpu_datap();

    simple_lock(&x86_topo_lock);
    machine_info.logical_cpu -= 1;
    cpup->lcpu.idle   = TRUE;
    core = cpup->lcpu.core;
    core->active_lcpus -= 1;
    if (core->active_lcpus == 0)
	machine_info.physical_cpu -= 1;
    simple_unlock(&x86_topo_lock);

    /*
     * Let the power management code determine the best way to "stop"
     * the processor.
     */
    ml_set_interrupts_enabled(FALSE);
    while (1) {
	pmCPUHalt(PM_HALT_NORMAL);
    }
    /* NOT REACHED */
}
