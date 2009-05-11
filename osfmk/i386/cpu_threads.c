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

//#define TOPO_DEBUG		1
#if TOPO_DEBUG
void debug_topology_print(void);
#define DBG(x...)	kprintf("DBG: " x)
#else
#define DBG(x...)
#endif /* TOPO_DEBUG */

void validate_topology(void);

#define bitmask(h,l)	((bit(h)|(bit(h)-1)) & ~(bit(l)-1))
#define bitfield(x,h,l)	(((x) & bitmask(h,l)) >> l)

x86_pkg_t	*x86_pkgs		= NULL;
uint32_t	num_Lx_caches[MAX_CACHE_DEPTH]	= { 0 };

static x86_pkg_t	*free_pkgs	= NULL;
static x86_die_t	*free_dies	= NULL;
static x86_core_t	*free_cores	= NULL;
static uint32_t		num_dies	= 0;

static x86_cpu_cache_t	*x86_caches	= NULL;
static uint32_t		num_caches	= 0;

static boolean_t	topoParmsInited	= FALSE;
x86_topology_parameters_t	topoParms;

decl_simple_lock_data(, x86_topo_lock);
 
static boolean_t
cpu_is_hyperthreaded(void)
{
    i386_cpu_info_t	*cpuinfo;

    cpuinfo = cpuid_info();
    return(cpuinfo->thread_count > cpuinfo->core_count);
}

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
x86_LLC_info(void)
{
    uint32_t		index;
    uint32_t		cache_info[4];
    uint32_t		cache_level	= 0;
    uint32_t		nCPUsSharing	= 1;
    i386_cpu_info_t	*cpuinfo;

    cpuinfo = cpuid_info();

    do_cpuid(0, cache_info);

    if (cache_info[eax] < 4) {
	/*
	 * Processor does not support deterministic
	 * cache information. Set LLC sharing to 1, since
	 * we have no better information.
	 */
	if (cpu_is_hyperthreaded()) {
	    topoParms.nCoresSharingLLC = 1;
	    topoParms.nLCPUsSharingLLC = 2;
	    topoParms.maxSharingLLC = 2;
	} else {
	    topoParms.nCoresSharingLLC = 1;
	    topoParms.nLCPUsSharingLLC = 1;
	    topoParms.maxSharingLLC = 1;
	}
	return;
    }

    for (index = 0; ; index += 1) {
	uint32_t		this_level;

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

	/*
	 * Get the current level.
	 */
	this_level = bitfield(cache_info[eax], 7, 5);

	/*
	 * Only worry about it if it's a deeper level than
	 * what we've seen before.
	 */
	if (this_level > cache_level) {
	    cache_level = this_level;

	    /*
	     * Save the number of CPUs sharing this cache.
	     */
	    nCPUsSharing = bitfield(cache_info[eax], 25, 14) + 1;
	}
    }

    /*
     * Make the level of the LLC be 0 based.
     */
    topoParms.LLCDepth = cache_level - 1;

    /*
     * nCPUsSharing represents the *maximum* number of cores or
     * logical CPUs sharing the cache.
     */
    topoParms.maxSharingLLC = nCPUsSharing;

    topoParms.nCoresSharingLLC = nCPUsSharing;
    topoParms.nLCPUsSharingLLC = nCPUsSharing;

    /*
     * nCPUsSharing may not be the number of *active* cores or
     * threads that are sharing the cache.
     */
    if (nCPUsSharing > cpuinfo->core_count)
	topoParms.nCoresSharingLLC = cpuinfo->core_count;
    if (nCPUsSharing > cpuinfo->thread_count)
	topoParms.nLCPUsSharingLLC = cpuinfo->thread_count;
}

static void
initTopoParms(void)
{
    i386_cpu_info_t	*cpuinfo;

    cpuinfo = cpuid_info();

    /*
     * We need to start with getting the LLC information correct.
     */
    x86_LLC_info();

    /*
     * Compute the number of threads (logical CPUs) per core.
     */
    topoParms.nLThreadsPerCore = cpuinfo->thread_count / cpuinfo->core_count;
    topoParms.nPThreadsPerCore = cpuinfo->cpuid_logical_per_package / cpuinfo->cpuid_cores_per_package;

    /*
     * Compute the number of dies per package.
     */
    topoParms.nLDiesPerPackage = cpuinfo->core_count / topoParms.nCoresSharingLLC;
    topoParms.nPDiesPerPackage = cpuinfo->cpuid_cores_per_package / (topoParms.maxSharingLLC / topoParms.nPThreadsPerCore);

    /*
     * Compute the number of cores per die.
     */
    topoParms.nLCoresPerDie = topoParms.nCoresSharingLLC;
    topoParms.nPCoresPerDie = (topoParms.maxSharingLLC / topoParms.nPThreadsPerCore);

    /*
     * Compute the number of threads per die.
     */
    topoParms.nLThreadsPerDie = topoParms.nLThreadsPerCore * topoParms.nLCoresPerDie;
    topoParms.nPThreadsPerDie = topoParms.nPThreadsPerCore * topoParms.nPCoresPerDie;

    /*
     * Compute the number of cores per package.
     */
    topoParms.nLCoresPerPackage = topoParms.nLCoresPerDie * topoParms.nLDiesPerPackage;
    topoParms.nPCoresPerPackage = topoParms.nPCoresPerDie * topoParms.nPDiesPerPackage;

    /*
     * Compute the number of threads per package.
     */
    topoParms.nLThreadsPerPackage = topoParms.nLThreadsPerCore * topoParms.nLCoresPerPackage;
    topoParms.nPThreadsPerPackage = topoParms.nPThreadsPerCore * topoParms.nPCoresPerPackage;

    DBG("\nLogical Topology Parameters:\n");
    DBG("\tThreads per Core:  %d\n", topoParms.nLThreadsPerCore);
    DBG("\tCores per Die:     %d\n", topoParms.nLCoresPerDie);
    DBG("\tThreads per Die:   %d\n", topoParms.nLThreadsPerDie);
    DBG("\tDies per Package:  %d\n", topoParms.nLDiesPerPackage);
    DBG("\tCores per Package: %d\n", topoParms.nLCoresPerPackage);
    DBG("\tThreads per Package: %d\n", topoParms.nLThreadsPerPackage);

    DBG("\nPhysical Topology Parameters:\n");
    DBG("\tThreads per Core: %d\n", topoParms.nPThreadsPerCore);
    DBG("\tCores per Die:     %d\n", topoParms.nPCoresPerDie);
    DBG("\tThreads per Die:   %d\n", topoParms.nPThreadsPerDie);
    DBG("\tDies per Package:  %d\n", topoParms.nPDiesPerPackage);
    DBG("\tCores per Package: %d\n", topoParms.nPCoresPerPackage);
    DBG("\tThreads per Package: %d\n", topoParms.nPThreadsPerPackage);

    topoParmsInited = TRUE;
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
	cur->maxcpus = (bitfield(cache_info[eax], 25, 14) + 1);
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

	cur->nlcpus = 0;
	num_Lx_caches[cur->level - 1] += 1;
    }

    return(root);
}

static x86_cpu_cache_t *
x86_match_cache(x86_cpu_cache_t *list, x86_cpu_cache_t *matcher)
{
    x86_cpu_cache_t	*cur_cache;

    cur_cache = list;
    while (cur_cache != NULL) {
	if (cur_cache->maxcpus  == matcher->maxcpus
	    && cur_cache->type  == matcher->type
	    && cur_cache->level == matcher->level
	    && cur_cache->ways  == matcher->ways
	    && cur_cache->partitions == matcher->partitions
	    && cur_cache->line_size  == matcher->line_size
	    && cur_cache->cache_size == matcher->cache_size)
	    break;

	cur_cache = cur_cache->next;
    }

    return(cur_cache);
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
    lcpu->next_in_core = NULL;
    lcpu->next_in_die  = NULL;
    lcpu->next_in_pkg  = NULL;
    lcpu->core         = NULL;
    lcpu->die          = NULL;
    lcpu->package      = NULL;
    lcpu->cpu_num = cpu;
    lcpu->lnum = cpu;
    lcpu->pnum = cpup->cpu_phys_number;
    lcpu->state = LCPU_OFF;
    for (i = 0; i < MAX_CACHE_DEPTH; i += 1)
	lcpu->caches[i] = NULL;

    lcpu->master = (lcpu->cpu_num == (unsigned int) master_cpu);
    lcpu->primary = (lcpu->pnum % topoParms.nPThreadsPerPackage) == 0;
}

static x86_core_t *
x86_core_alloc(int cpu)
{
    x86_core_t	*core;
    cpu_data_t	*cpup;

    cpup = cpu_datap(cpu);

    simple_lock(&x86_topo_lock);
    if (free_cores != NULL) {
	core = free_cores;
	free_cores = core->next_in_die;
	core->next_in_die = NULL;
	simple_unlock(&x86_topo_lock);
    } else {
	simple_unlock(&x86_topo_lock);
	core = kalloc(sizeof(x86_core_t));
	if (core == NULL)
	    panic("x86_core_alloc() kalloc of x86_core_t failed!\n");
    }

    bzero((void *) core, sizeof(x86_core_t));

    core->pcore_num = cpup->cpu_phys_number / topoParms.nPThreadsPerCore;
    core->lcore_num = core->pcore_num % topoParms.nPCoresPerPackage;

    core->flags = X86CORE_FL_PRESENT | X86CORE_FL_READY
	        | X86CORE_FL_HALTED | X86CORE_FL_IDLE;

    return(core);
}

static void
x86_core_free(x86_core_t *core)
{
    simple_lock(&x86_topo_lock);
    core->next_in_die = free_cores;
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

    pkg_num = cpup->cpu_phys_number / topoParms.nPThreadsPerPackage;

    pkg = x86_pkgs;
    while (pkg != NULL) {
	if (pkg->ppkg_num == pkg_num)
	    break;
	pkg = pkg->next;
    }

    return(pkg);
}
 
static x86_die_t *
x86_die_find(int cpu)
{
    x86_die_t	*die;
    x86_pkg_t	*pkg;
    cpu_data_t	*cpup;
    uint32_t	die_num;

    cpup = cpu_datap(cpu);

    die_num = cpup->cpu_phys_number / topoParms.nPThreadsPerDie;

    pkg = x86_package_find(cpu);
    if (pkg == NULL)
	return(NULL);

    die = pkg->dies;
    while (die != NULL) {
	if (die->pdie_num == die_num)
	    break;
	die = die->next_in_pkg;
    }

    return(die);
}

static x86_core_t *
x86_core_find(int cpu)
{
    x86_core_t	*core;
    x86_die_t	*die;
    cpu_data_t	*cpup;
    uint32_t	core_num;

    cpup = cpu_datap(cpu);

    core_num = cpup->cpu_phys_number / topoParms.nPThreadsPerCore;

    die = x86_die_find(cpu);
    if (die == NULL)
	return(NULL);

    core = die->cores;
    while (core != NULL) {
	if (core->pcore_num == core_num)
	    break;
	core = core->next_in_die;
    }

    return(core);
}
 
void
x86_set_lcpu_numbers(x86_lcpu_t *lcpu)
{
    lcpu->lnum = lcpu->cpu_num % topoParms.nLThreadsPerCore;
}

void
x86_set_core_numbers(x86_core_t *core, x86_lcpu_t *lcpu)
{
    core->pcore_num = lcpu->cpu_num / topoParms.nLThreadsPerCore;
    core->lcore_num = core->pcore_num % topoParms.nLCoresPerDie;
}

void
x86_set_die_numbers(x86_die_t *die, x86_lcpu_t *lcpu)
{
    die->pdie_num = lcpu->cpu_num / (topoParms.nLThreadsPerCore * topoParms.nLCoresPerDie);
    die->ldie_num = die->pdie_num % topoParms.nLDiesPerPackage;
}

void
x86_set_pkg_numbers(x86_pkg_t *pkg, x86_lcpu_t *lcpu)
{
    pkg->ppkg_num = lcpu->cpu_num / topoParms.nLThreadsPerPackage;
    pkg->lpkg_num = pkg->ppkg_num;
}

static x86_die_t *
x86_die_alloc(int cpu)
{
    x86_die_t	*die;
    cpu_data_t	*cpup;

    cpup = cpu_datap(cpu);

    simple_lock(&x86_topo_lock);
    if (free_dies != NULL) {
	die = free_dies;
	free_dies = die->next_in_pkg;
	die->next_in_pkg = NULL;
	simple_unlock(&x86_topo_lock);
    } else {
	simple_unlock(&x86_topo_lock);
	die = kalloc(sizeof(x86_die_t));
	if (die == NULL)
	    panic("x86_die_alloc() kalloc of x86_die_t failed!\n");
    }

    bzero((void *) die, sizeof(x86_die_t));

    die->pdie_num = cpup->cpu_phys_number / topoParms.nPThreadsPerDie;

    die->ldie_num = num_dies;
    atomic_incl((long *) &num_dies, 1);

    die->flags = X86DIE_FL_PRESENT;
    return(die);
}

static void
x86_die_free(x86_die_t *die)
{
    simple_lock(&x86_topo_lock);
    die->next_in_pkg = free_dies;
    free_dies = die;
    atomic_decl((long *) &num_dies, 1);
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

    pkg->ppkg_num = cpup->cpu_phys_number / topoParms.nPThreadsPerPackage;

    pkg->lpkg_num = topoParms.nPackages;
    atomic_incl((long *) &topoParms.nPackages, 1);

    pkg->flags = X86PKG_FL_PRESENT | X86PKG_FL_READY;
    return(pkg);
}

static void
x86_package_free(x86_pkg_t *pkg)
{
    simple_lock(&x86_topo_lock);
    pkg->next = free_pkgs;
    free_pkgs = pkg;
    atomic_decl((long *) &topoParms.nPackages, 1);
    simple_unlock(&x86_topo_lock);
}

static void
x86_cache_add_lcpu(x86_cpu_cache_t *cache, x86_lcpu_t *lcpu)
{
    x86_cpu_cache_t	*cur_cache;
    int			i;

    /*
     * Put the new CPU into the list of the cache.
     */
    cur_cache = lcpu->caches[cache->level - 1];
    lcpu->caches[cache->level - 1] = cache;
    cache->next = cur_cache;
    cache->nlcpus += 1;
    for (i = 0; i < cache->nlcpus; i += 1) {
	if (cache->cpus[i] == NULL) {
	    cache->cpus[i] = lcpu;
	    break;
	}
    }
}

static void
x86_lcpu_add_caches(x86_lcpu_t *lcpu)
{
    x86_cpu_cache_t	*list;
    x86_cpu_cache_t	*cur;
    x86_cpu_cache_t	*match;
    x86_die_t		*die;
    x86_core_t		*core;
    x86_lcpu_t		*cur_lcpu;
    uint32_t		level;
    boolean_t		found		= FALSE;

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
	if (cur->maxcpus == 1) {
	    x86_cache_add_lcpu(cur, lcpu);
	    continue;
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
	 * this by searching through the topology and seeing if
	 * this cache is already described.
	 *
	 * Assume that L{LLC-1} are all at the core level and that
	 * LLC is shared at the die level.
	 */
	if (level < topoParms.LLCDepth) {
	    /*
	     * Shared at the core.
	     */
	    core = lcpu->core;
	    cur_lcpu = core->lcpus;
	    while (cur_lcpu != NULL) {
		/*
		 * Skip ourselves.
		 */
		if (cur_lcpu == lcpu) {
		    cur_lcpu = cur_lcpu->next_in_core;
		    continue;
		}

		/*
		 * If there's a cache on this logical CPU,
		 * then use that one.
		 */
		match = x86_match_cache(cur_lcpu->caches[level], cur);
		if (match != NULL) {
		    x86_cache_free(cur);
		    x86_cache_add_lcpu(match, lcpu);
		    found = TRUE;
		    break;
		}

		cur_lcpu = cur_lcpu->next_in_core;
	    }
	} else {
	    /*
	     * Shared at the die.
	     */
	    die = lcpu->die;
	    cur_lcpu = die->lcpus;
	    while (cur_lcpu != NULL) {
		/*
		 * Skip ourselves.
		 */
		if (cur_lcpu == lcpu) {
		    cur_lcpu = cur_lcpu->next_in_die;
		    continue;
		}

		/*
		 * If there's a cache on this logical CPU,
		 * then use that one.
		 */
		match = x86_match_cache(cur_lcpu->caches[level], cur);
		if (match != NULL) {
		    x86_cache_free(cur);
		    x86_cache_add_lcpu(match, lcpu);
		    found = TRUE;
		    break;
		}

		cur_lcpu = cur_lcpu->next_in_die;
	    }
	}

	/*
	 * If a shared cache wasn't found, then this logical CPU must
	 * be the first one encountered.
	 */
	if (!found) {
	    x86_cache_add_lcpu(cur, lcpu);
	}
    }

    simple_unlock(&x86_topo_lock);
}

static void
x86_core_add_lcpu(x86_core_t *core, x86_lcpu_t *lcpu)
{
    assert(core != NULL);
    assert(lcpu != NULL);

    simple_lock(&x86_topo_lock);

    lcpu->next_in_core = core->lcpus;
    lcpu->core = core;
    core->lcpus = lcpu;
    core->num_lcpus += 1;
    simple_unlock(&x86_topo_lock);
}

static void
x86_die_add_lcpu(x86_die_t *die, x86_lcpu_t *lcpu)
{
    assert(die != NULL);
    assert(lcpu != NULL);
 
    lcpu->next_in_die = die->lcpus;
    lcpu->die = die;
    die->lcpus = lcpu;
}

static void
x86_die_add_core(x86_die_t *die, x86_core_t *core)
{
    assert(die != NULL);
    assert(core != NULL);

    core->next_in_die = die->cores;
    core->die = die;
    die->cores = core;
    die->num_cores += 1;
}

 static void
x86_package_add_lcpu(x86_pkg_t *pkg, x86_lcpu_t *lcpu)
{
    assert(pkg != NULL);
    assert(lcpu != NULL);

    lcpu->next_in_pkg = pkg->lcpus;
    lcpu->package = pkg;
    pkg->lcpus = lcpu;
}

static void
x86_package_add_core(x86_pkg_t *pkg, x86_core_t *core)
{
    assert(pkg != NULL);
    assert(core != NULL);

    core->next_in_pkg = pkg->cores;
    core->package = pkg;
    pkg->cores = core;
}

static void
x86_package_add_die(x86_pkg_t *pkg, x86_die_t *die)
{
    assert(pkg != NULL);
    assert(die != NULL);

    die->next_in_pkg = pkg->dies;
    die->package = pkg;
    pkg->dies = die;
    pkg->num_dies += 1;
}

void *
cpu_thread_alloc(int cpu)
{
    x86_core_t	*core		= NULL;
    x86_die_t	*die		= NULL;
    x86_pkg_t	*pkg		= NULL;
    cpu_data_t	*cpup;
    uint32_t	phys_cpu;

    /*
     * Only allow one to manipulate the topology at a time.
     */
    simple_lock(&x86_topo_lock);

    /*
     * Make sure all of the topology parameters have been initialized.
     */
    if (!topoParmsInited)
	initTopoParms();

    cpup = cpu_datap(cpu);

    phys_cpu = cpup->cpu_phys_number;

    x86_lcpu_init(cpu);

     /*
     * Allocate performance counter structure.
     */
    simple_unlock(&x86_topo_lock);
    cpup->lcpu.pmc = pmc_alloc();
    simple_lock(&x86_topo_lock);

    /*
     * Assume that all cpus have the same features.
     */
    if (cpu_is_hyperthreaded()) {
	cpup->cpu_threadtype = CPU_THREADTYPE_INTEL_HTT;
    } else {
	cpup->cpu_threadtype = CPU_THREADTYPE_NONE;
    }

    /*
     * Get the package that the logical CPU is in.
     */
    do {
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
		continue;
	    }
	    
	    /*
	     * Add the new package to the global list of packages.
	     */
	    pkg->next = x86_pkgs;
	    x86_pkgs = pkg;
	}
    } while (pkg == NULL);

    /*
     * Get the die that the logical CPU is in.
     */
    do {
	die = x86_die_find(cpu);
	if (die == NULL) {
	    /*
	     * Die structure hasn't been created yet, do it now.
	     */
	    simple_unlock(&x86_topo_lock);
	    die = x86_die_alloc(cpu);
	    simple_lock(&x86_topo_lock);
	    if (x86_die_find(cpu) != NULL) {
		x86_die_free(die);
		continue;
	    }

	    /*
	     * Add the die to the package.
	     */
	    x86_package_add_die(pkg, die);
	}
    } while (die == NULL);

    /*
     * Get the core for this logical CPU.
     */
    do {
	core = x86_core_find(cpu);
	if (core == NULL) {
	    /*
	     * Allocate the core structure now.
	     */
	    simple_unlock(&x86_topo_lock);
	    core = x86_core_alloc(cpu);
	    simple_lock(&x86_topo_lock);
	    if (x86_core_find(cpu) != NULL) {
		x86_core_free(core);
		continue;
	    }

	    /*
	     * Add the core to the die & package.
	     */
	    x86_die_add_core(die, core);
	    x86_package_add_core(pkg, core);
	    machine_info.physical_cpu_max += 1;
	}
    } while (core == NULL);

    
    /*
     * Done manipulating the topology, so others can get in.
     */
    machine_info.logical_cpu_max += 1;
    simple_unlock(&x86_topo_lock);

    /*
     * Add the logical CPU to the other topology structures.
     */
    x86_core_add_lcpu(core, &cpup->lcpu);
    x86_die_add_lcpu(core->die, &cpup->lcpu);
    x86_package_add_lcpu(core->package, &cpup->lcpu);
    x86_lcpu_add_caches(&cpup->lcpu);

    return (void *) core;
}

void
cpu_thread_init(void)
{
    int		my_cpu		= get_cpu_number();
    cpu_data_t	*cpup		= current_cpu_datap();
    x86_core_t	*core;
    static int	initialized	= 0;

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

/*
 * Validates that the topology was built correctly.  Must be called only
 * after the complete topology is built and no other changes are being made.
 */
void
validate_topology(void)
{
    x86_pkg_t		*pkg;
    x86_die_t		*die;
    x86_core_t		*core;
    x86_lcpu_t		*lcpu;
    uint32_t		nDies;
    uint32_t		nCores;
    uint32_t		nCPUs;

    /*
     * XXX
     *
     * Right now this only works if the number of CPUs started is the total
     * number of CPUs.  However, when specifying cpus=n the topology is only
     * partially constructed and the checks below will fail.
     *
     * We should *always* build the complete topology and only start the CPUs
     * indicated by cpus=n.  Until that happens, this code will not check the
     * topology if the number of cpus defined is < that described the the
     * topology parameters.
     */
    nCPUs = topoParms.nPackages * topoParms.nLThreadsPerPackage;
    if (nCPUs > real_ncpus)
	return;

    pkg = x86_pkgs;
    while (pkg != NULL) {
	/*
	 * Make sure that the package has the correct number of dies.
	 */
	nDies = 0;
	die = pkg->dies;
	while (die != NULL) {
	    if (die->package == NULL)
		panic("Die(%d)->package is NULL",
		      die->pdie_num);
	    if (die->package != pkg)
		panic("Die %d points to package %d, should be %d",
		      die->pdie_num, die->package->lpkg_num, pkg->lpkg_num);

	    DBG("Die(%d)->package %d\n",
		die->pdie_num, pkg->lpkg_num);

	    /*
	     * Make sure that the die has the correct number of cores.
	     */
	    DBG("Die(%d)->cores: ");
	    nCores = 0;
	    core = die->cores;
	    while (core != NULL) {
		if (core->die == NULL)
		    panic("Core(%d)->die is NULL",
			  core->pcore_num);
		if (core->die != die)
		    panic("Core %d points to die %d, should be %d",
			  core->pcore_num, core->die->pdie_num, die->pdie_num);
		nCores += 1;
		DBG("%d ", core->pcore_num);
		core = core->next_in_die;
	    }
	    DBG("\n");

	    if (nCores != topoParms.nLCoresPerDie)
		panic("Should have %d Cores, but only found %d for Die %d",
		      topoParms.nLCoresPerDie, nCores, die->pdie_num);

	    /*
	     * Make sure that the die has the correct number of CPUs.
	     */
	    DBG("Die(%d)->lcpus: ", die->pdie_num);
	    nCPUs = 0;
	    lcpu = die->lcpus;
	    while (lcpu != NULL) {
		if (lcpu->die == NULL)
		    panic("CPU(%d)->die is NULL",
			  lcpu->cpu_num);
		if (lcpu->die != die)
		    panic("CPU %d points to die %d, should be %d",
			  lcpu->cpu_num, lcpu->die->pdie_num, die->pdie_num);
		nCPUs += 1;
		DBG("%d ", lcpu->cpu_num);
		lcpu = lcpu->next_in_die;
	    }
	    DBG("\n");

	    if (nCPUs != topoParms.nLThreadsPerDie)
		panic("Should have %d Threads, but only found %d for Die %d",
		      topoParms.nLThreadsPerDie, nCPUs, die->pdie_num);

	    nDies += 1;
	    die = die->next_in_pkg;
	}

	if (nDies != topoParms.nLDiesPerPackage)
	    panic("Should have %d Dies, but only found %d for package %d",
		  topoParms.nLDiesPerPackage, nDies, pkg->lpkg_num);

	/*
	 * Make sure that the package has the correct number of cores.
	 */
	nCores = 0;
	core = pkg->cores;
	while (core != NULL) {
	    if (core->package == NULL)
		panic("Core(%d)->package is NULL",
		      core->pcore_num);
	    if (core->package != pkg)
		panic("Core %d points to package %d, should be %d",
		      core->pcore_num, core->package->lpkg_num, pkg->lpkg_num);
	    DBG("Core(%d)->package %d\n",
		core->pcore_num, pkg->lpkg_num);

	    /*
	     * Make sure that the core has the correct number of CPUs.
	     */
	    nCPUs = 0;
	    lcpu = core->lcpus;
	    DBG("Core(%d)->lcpus: ");
	    while (lcpu != NULL) {
		if (lcpu->core == NULL)
		    panic("CPU(%d)->core is NULL",
			  lcpu->cpu_num);
		if (lcpu->core != core)
		    panic("CPU %d points to core %d, should be %d",
			  lcpu->cpu_num, lcpu->core->pcore_num, core->pcore_num);
		DBG("%d ", lcpu->cpu_num);
		nCPUs += 1;
		lcpu = lcpu->next_in_core;
	    }
	    DBG("\n");

	    if (nCPUs != topoParms.nLThreadsPerCore)
		panic("Should have %d Threads, but only found %d for Core %d",
		      topoParms.nLThreadsPerCore, nCPUs, core->pcore_num);
	    nCores += 1;
	    core = core->next_in_pkg;
	}

	if (nCores != topoParms.nLCoresPerPackage)
	    panic("Should have %d Cores, but only found %d for package %d",
		  topoParms.nLCoresPerPackage, nCores, pkg->lpkg_num);

	/*
	 * Make sure that the package has the correct number of CPUs.
	 */
	nCPUs = 0;
	lcpu = pkg->lcpus;
	while (lcpu != NULL) {
	    if (lcpu->package == NULL)
		panic("CPU(%d)->package is NULL",
		      lcpu->cpu_num);
	    if (lcpu->package != pkg)
		panic("CPU %d points to package %d, should be %d",
		      lcpu->cpu_num, lcpu->package->lpkg_num, pkg->lpkg_num);
	    DBG("CPU(%d)->package %d\n",
		lcpu->cpu_num, pkg->lpkg_num);
	    nCPUs += 1;
	    lcpu = lcpu->next_in_pkg;
	}

	if (nCPUs != topoParms.nLThreadsPerPackage)
	    panic("Should have %d Threads, but only found %d for package %d",
		  topoParms.nLThreadsPerPackage, nCPUs, pkg->lpkg_num);

	pkg = pkg->next;
    }
}

#if TOPO_DEBUG
/*
 * Prints out the topology
 */
void
debug_topology_print(void)
{
    x86_pkg_t		*pkg;
    x86_die_t		*die;
    x86_core_t		*core;
    x86_lcpu_t		*cpu;

    pkg = x86_pkgs;
    while (pkg != NULL) {
	kprintf("Package:\n");
	kprintf("    Physical: %d\n", pkg->ppkg_num);
	kprintf("    Logical:  %d\n", pkg->lpkg_num);

	die = pkg->dies;
	while (die != NULL) {
	    kprintf("    Die:\n");
	    kprintf("        Physical: %d\n", die->pdie_num);
	    kprintf("        Logical:  %d\n", die->ldie_num);

	    core = die->cores;
	    while (core != NULL) {
		kprintf("        Core:\n");
		kprintf("            Physical: %d\n", core->pcore_num);
		kprintf("            Logical:  %d\n", core->lcore_num);

		cpu = core->lcpus;
		while (cpu != NULL) {
		    kprintf("            LCPU:\n");
		    kprintf("                CPU #:    %d\n", cpu->cpu_num);
		    kprintf("                Physical: %d\n", cpu->pnum);
		    kprintf("                Logical:  %d\n", cpu->lnum);
		    kprintf("                Flags:    ");
		    if (cpu->master)
			kprintf("MASTER ");
		    if (cpu->primary)
			kprintf("PRIMARY");
		    if (!cpu->master && !cpu->primary)
			kprintf("(NONE)");
		    kprintf("\n");

		    cpu = cpu->next_in_core;
		}

		core = core->next_in_die;
	    }

	    die = die->next_in_pkg;
	}

	pkg = pkg->next;
    }
}
#endif /* TOPO_DEBUG */
