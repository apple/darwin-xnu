/*
 * Copyright (c) 2003-2007 Apple Inc. All rights reserved.
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
#ifdef KERNEL_PRIVATE
#ifndef _I386_CPU_TOPOLOGY_H_
#define _I386_CPU_TOPOLOGY_H_

/*
 * This was originally part of cpu_threads.h.  It was split out so that
 * these structures could be referenced without pulling in all of the headers
 * required for the definition of cpu_data.  These data structures are
 * used by KEXTs in order to deal with the physical topology.
 *
 * NOTE: this header must stand on its own as much as possible
 * and not be dependent upon any unexported, kernel-private header.
 */

/*
 * Cache structure that can be used to identify the cache heirarchy.
 */
typedef struct x86_cpu_cache
{
    struct x86_cpu_cache *next;		/* next cache at this level/lcpu */
    uint8_t		maxcpus;	/* maximum # of cpus that can share */
    uint8_t		nlcpus;		/* # of logical cpus sharing this cache */
    uint8_t		type;		/* type of cache */
    uint8_t		level;		/* level of cache */
    uint16_t		ways;		/* # of ways in cache */
    uint16_t		partitions;	/* # of partitions in cache */
    uint16_t		line_size;	/* size of a cache line */
    uint32_t		cache_size;	/* total size of cache */
    struct x86_lcpu	*cpus[0];	/* cpus sharing this cache */
} x86_cpu_cache_t;

#define CPU_CACHE_TYPE_DATA	1	/* data cache */
#define CPU_CACHE_TYPE_INST	2	/* instruction cache */
#define CPU_CACHE_TYPE_UNIF	3	/* unified cache */

#define CPU_CACHE_DEPTH_L1	0
#define CPU_CACHE_DEPTH_L2	1
#define CPU_CACHE_DEPTH_L3	2

#define MAX_CACHE_DEPTH		3	/* deepest cache */

struct pmc;
struct cpu_data;

typedef struct x86_lcpu
{
    struct x86_lcpu	*next;	/* next logical cpu in core */
    struct x86_lcpu	*lcpu;	/* pointer back to self */
    struct x86_core	*core;	/* core containing the logical cpu */
    struct cpu_data	*cpu;	/* cpu_data structure */
    uint32_t		lnum;	/* logical cpu number */
    uint32_t		pnum;	/* physical cpu number */
    boolean_t		master;	/* logical cpu is the master (boot) CPU */
    boolean_t		primary;/* logical cpu is primary CPU in package */
    boolean_t		halted;	/* logical cpu is halted */
    boolean_t		idle;	/* logical cpu is idle */
    uint64_t		rtcPop;	/* when etimer wants a timer pop */
    uint64_t		rtcDeadline;
    x86_cpu_cache_t	*caches[MAX_CACHE_DEPTH];
} x86_lcpu_t;

#define X86CORE_FL_PRESENT	0x80000000	/* core is present */
#define X86CORE_FL_READY	0x40000000	/* core struct is init'd */
#define X86CORE_FL_HALTED	0x00008000	/* core is halted */
#define X86CORE_FL_IDLE		0x00004000	/* core is idle */

typedef struct x86_core
{
    struct x86_core	*next;		/* next core in package */
    struct x86_lcpu	*lcpus;		/* list of logical cpus in core */
    struct x86_pkg	*package;	/* package containing core */
    uint32_t		flags;
    uint32_t		lcore_num;	/* logical core # (unique to package) */
    uint32_t		pcore_num;	/* physical core # (globally unique) */
    uint32_t		num_lcpus;	/* Number of logical cpus */
    uint32_t		active_lcpus;	/* Number of non-halted cpus */
    struct pmc		*pmc;		/* Pointer to perfmon data */
    struct hpetTimer	*Hpet;		/* Address of the HPET for this core */
    uint32_t		HpetVec;	/* Interrupt vector for HPET */
    uint64_t		HpetInt;	/* Number of HPET Interrupts */
    uint64_t		HpetCmp;	/* HPET Comparitor */
    uint64_t		HpetCfg;	/* HPET configuration */
    uint64_t		HpetTime;
    void		*pmStats;	/* Power management stats for core */
    void		*pmState;	/* Power management state for core */
} x86_core_t;

#define X86PKG_FL_PRESENT	0x80000000	/* package is present */
#define X86PKG_FL_READY		0x40000000	/* package struct init'd */
#define X86PKG_FL_HAS_HPET	0x10000000	/* package has HPET assigned */
#define X86PKG_FL_HALTED	0x00008000	/* package is halted */
#define X86PKG_FL_IDLE		0x00004000	/* package is idle */

typedef struct x86_pkg
{
    struct x86_pkg	*next;		/* next package */
    struct x86_core	*cores;		/* list of cores in package */
    uint32_t		flags;
    uint32_t		lpkg_num;	/* logical package # */
    uint32_t		ppkg_num;	/* physical package # */
    uint32_t		num_cores;	/* number of cores in package */
    struct hpetTimer	*Hpet;		/* address of HPET for this package */
    uint32_t		HpetVec;	/* Interrupt vector for HPET */
    uint64_t		HpetInt;	/* Number of HPET interrupts */
    uint64_t		HpetCmp;	/* HPET comparitor */
    uint64_t		HpetCfg;	/* HPET configuration */
    uint64_t		HpetTime;
    void		*pmStats;	/* Power Management stats for package*/
    void		*pmState;	/* Power Management state for package*/
} x86_pkg_t;

extern x86_pkg_t	*x86_pkgs;	/* root of all CPU packages */

/* Called after cpu discovery */
extern void		cpu_topology_start(void);

extern int idlehalt;

#endif /* _I386_CPU_TOPOLOGY_H_ */
#endif /* KERNEL_PRIVATE */
