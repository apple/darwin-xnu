/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
/*-
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Karels at Berkeley Software Design, Inc.
 *
 * Quite extensively rewritten by Poul-Henning Kamp of the FreeBSD
 * project, to make these variables more userfriendly.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)kern_sysctl.c	8.4 (Berkeley) 4/14/94
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/proc_internal.h>
#include <sys/unistd.h>

#if defined(SMP)
#include <machine/smp.h>
#endif

#include <sys/param.h>  /* XXX prune includes */
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/file_internal.h>
#include <sys/vnode.h>
#include <sys/unistd.h>
#include <sys/ioctl.h>
#include <sys/namei.h>
#include <sys/tty.h>
#include <sys/disklabel.h>
#include <sys/vm.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <mach/machine.h>
#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <kern/task.h>
#include <vm/vm_kern.h>
#include <mach/host_info.h>
#include <kern/pms.h>

extern vm_map_t bsd_pageable_map;

#include <sys/mount_internal.h>
#include <sys/kdebug.h>

#include <IOKit/IOPlatformExpert.h>
#include <pexpert/pexpert.h>

#include <machine/machine_routines.h>
#include <machine/cpu_capabilities.h>

#include <mach/mach_host.h>		/* for host_info() */

#ifdef __i386__
#include <i386/cpuid.h>		/* for cpuid_info() */
#endif



#ifndef MAX
#define MAX(a,b) (a >= b ? a : b)
#endif

/* XXX This should be in a BSD accessible Mach header, but isn't. */
extern unsigned int vm_page_wire_count;

static int	cputype, cpusubtype, cputhreadtype, cpufamily, cpu64bit;
static uint64_t	cacheconfig[10], cachesize[10];
static int	packages;

SYSCTL_NODE(, 0,	  sysctl, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"Sysctl internal magic");
SYSCTL_NODE(, CTL_KERN,	  kern,   CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"High kernel, proc, limits &c");
SYSCTL_NODE(, CTL_VM,	  vm,     CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"Virtual memory");
SYSCTL_NODE(, CTL_VFS,	  vfs,     CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"File system");
SYSCTL_NODE(, CTL_NET,	  net,    CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"Network, (see socket.h)");
SYSCTL_NODE(, CTL_DEBUG,  debug,  CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"Debugging");
SYSCTL_NODE(, CTL_HW,	  hw,     CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"hardware");
SYSCTL_NODE(, CTL_MACHDEP, machdep, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"machine dependent");
SYSCTL_NODE(, CTL_USER,	  user,   CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"user-level");

#define SYSCTL_RETURN(r, x)	SYSCTL_OUT(r, &x, sizeof(x))

/******************************************************************************
 * hw.* MIB
 */

#define CTLHW_RETQUAD	(1 << 31)
#define CTLHW_LOCAL	(1 << 30)

#define HW_LOCAL_CPUTHREADTYPE	(1 | CTLHW_LOCAL)
#define HW_LOCAL_PHYSICALCPU	(2 | CTLHW_LOCAL)
#define HW_LOCAL_PHYSICALCPUMAX	(3 | CTLHW_LOCAL)
#define HW_LOCAL_LOGICALCPU	(4 | CTLHW_LOCAL)
#define HW_LOCAL_LOGICALCPUMAX	(5 | CTLHW_LOCAL)


/*
 * Supporting some variables requires us to do "real" work.  We 
 * gather some of that here.
 */
static int
sysctl_hw_generic(__unused struct sysctl_oid *oidp, __unused void *arg1,
	int arg2, struct sysctl_req *req)
{
	char dummy[65];
	int  epochTemp;
	ml_cpu_info_t cpu_info;
	int val, doquad;
	long long qval;
	host_basic_info_data_t hinfo;
	kern_return_t kret;
	mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;

	/*
	 * Test and mask off the 'return quad' flag.
	 * Note that only some things here support it.
	 */
	doquad = arg2 & CTLHW_RETQUAD;
	arg2 &= ~CTLHW_RETQUAD;

	ml_cpu_get_info(&cpu_info);

#define BSD_HOST 1
	kret = host_info((host_t)BSD_HOST, HOST_BASIC_INFO, (host_info_t)&hinfo, &count);

	/*
	 * Handle various OIDs.
	 *
	 * OIDs that can return int or quad set val and qval and then break.
	 * Errors and int-only values return inline.
	 */
	switch (arg2) {
	case HW_NCPU:
		if (kret == KERN_SUCCESS) {
			return(SYSCTL_RETURN(req, hinfo.max_cpus));
		} else {
			return(EINVAL);
		}
	case HW_AVAILCPU:
		if (kret == KERN_SUCCESS) {
			return(SYSCTL_RETURN(req, hinfo.avail_cpus));
		} else {
			return(EINVAL);
		}
	case HW_LOCAL_PHYSICALCPU:
		if (kret == KERN_SUCCESS) {
			return(SYSCTL_RETURN(req, hinfo.physical_cpu));
		} else {
			return(EINVAL);
		}
	case HW_LOCAL_PHYSICALCPUMAX:
		if (kret == KERN_SUCCESS) {
			return(SYSCTL_RETURN(req, hinfo.physical_cpu_max));
		} else {
			return(EINVAL);
		}
	case HW_LOCAL_LOGICALCPU:
		if (kret == KERN_SUCCESS) {
			return(SYSCTL_RETURN(req, hinfo.logical_cpu));
		} else {
			return(EINVAL);
		}
	case HW_LOCAL_LOGICALCPUMAX:
		if (kret == KERN_SUCCESS) {
			return(SYSCTL_RETURN(req, hinfo.logical_cpu_max));
		} else {
			return(EINVAL);
		}
	case HW_CACHELINE:
		val = cpu_info.cache_line_size;
		qval = (long long)val;
		break;
	case HW_L1ICACHESIZE:
		val = cpu_info.l1_icache_size;
		qval = (long long)val;
		break;
	case HW_L1DCACHESIZE:
		val = cpu_info.l1_dcache_size;
		qval = (long long)val;
		break;
	case HW_L2CACHESIZE:
		if (cpu_info.l2_cache_size == 0xFFFFFFFF)
			return(EINVAL);
		val = cpu_info.l2_cache_size;
		qval = (long long)val;
		break;
	case HW_L3CACHESIZE:
		if (cpu_info.l3_cache_size == 0xFFFFFFFF)
			return(EINVAL);
		val = cpu_info.l3_cache_size;
		qval = (long long)val;
		break;

		/*
		 * Deprecated variables.  We still support these for
		 * backwards compatibility purposes only.
		 */
	case HW_MACHINE:
		bzero(dummy, sizeof(dummy));
		if(!PEGetMachineName(dummy,64))
			return(EINVAL);
		dummy[64] = 0;
		return(SYSCTL_OUT(req, dummy, strlen(dummy) + 1));
	case HW_MODEL:
		bzero(dummy, sizeof(dummy));
		if(!PEGetModelName(dummy,64))
			return(EINVAL);
		dummy[64] = 0;
		return(SYSCTL_OUT(req, dummy, strlen(dummy) + 1));
	case HW_USERMEM:
		{
		int usermem = mem_size - vm_page_wire_count * page_size;

			return(SYSCTL_RETURN(req, usermem));
		}
	case HW_EPOCH:
	        epochTemp = PEGetPlatformEpoch();
		if (epochTemp == -1)
			return(EINVAL);
		return(SYSCTL_RETURN(req, epochTemp));
	case HW_VECTORUNIT: {
		int vector = cpu_info.vector_unit == 0? 0 : 1;
		return(SYSCTL_RETURN(req, vector));
	}
	case HW_L2SETTINGS:
		if (cpu_info.l2_cache_size == 0xFFFFFFFF)
			return(EINVAL);
		return(SYSCTL_RETURN(req, cpu_info.l2_settings));
	case HW_L3SETTINGS:
		if (cpu_info.l3_cache_size == 0xFFFFFFFF)
			return(EINVAL);
		return(SYSCTL_RETURN(req, cpu_info.l3_settings));
	default:
		return(ENOTSUP);
	}
	/*
	 * Callers may come to us with either int or quad buffers.
	 */
	if (doquad) {
		return(SYSCTL_RETURN(req, qval));
	}
	return(SYSCTL_RETURN(req, val));
}

/* hw.pagesize and hw.tbfrequency are expected as 64 bit values */
static int
sysctl_pagesize
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	long long l = page_size;
	return sysctl_io_number(req, l, sizeof(l), NULL, NULL);
}

static int
sysctl_tbfrequency
(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	long long l = gPEClockFrequencyInfo.timebase_frequency_hz;
	return sysctl_io_number(req, l, sizeof(l), NULL, NULL);
}

/*
 * hw.* MIB variables.
 */
SYSCTL_PROC    (_hw, HW_NCPU, ncpu, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN, 0, HW_NCPU, sysctl_hw_generic, "I", "");
SYSCTL_PROC    (_hw, HW_AVAILCPU, activecpu, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN, 0, HW_AVAILCPU, sysctl_hw_generic, "I", "");
SYSCTL_PROC    (_hw, OID_AUTO, physicalcpu, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN, 0, HW_LOCAL_PHYSICALCPU, sysctl_hw_generic, "I", "");
SYSCTL_PROC    (_hw, OID_AUTO, physicalcpu_max, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN, 0, HW_LOCAL_PHYSICALCPUMAX, sysctl_hw_generic, "I", "");
SYSCTL_PROC    (_hw, OID_AUTO, logicalcpu, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN, 0, HW_LOCAL_LOGICALCPU, sysctl_hw_generic, "I", "");
SYSCTL_PROC    (_hw, OID_AUTO, logicalcpu_max, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_KERN, 0, HW_LOCAL_LOGICALCPUMAX, sysctl_hw_generic, "I", "");
SYSCTL_INT     (_hw, HW_BYTEORDER, byteorder, CTLFLAG_RD | CTLFLAG_KERN, NULL, BYTE_ORDER, "");
SYSCTL_INT     (_hw, OID_AUTO, cputype, CTLFLAG_RD | CTLFLAG_KERN, &cputype, 0, "");
SYSCTL_INT     (_hw, OID_AUTO, cpusubtype, CTLFLAG_RD | CTLFLAG_KERN, &cpusubtype, 0, "");
SYSCTL_INT     (_hw, OID_AUTO, cpu64bit_capable, CTLFLAG_RD | CTLFLAG_KERN, &cpu64bit, 0, "");
SYSCTL_INT     (_hw, OID_AUTO, cpufamily, CTLFLAG_RD | CTLFLAG_KERN, &cpufamily, 0, "");
SYSCTL_OPAQUE  (_hw, OID_AUTO, cacheconfig, CTLFLAG_RD, &cacheconfig, sizeof(cacheconfig), "Q", "");
SYSCTL_OPAQUE  (_hw, OID_AUTO, cachesize, CTLFLAG_RD, &cachesize, sizeof(cachesize), "Q", "");
SYSCTL_PROC	   (_hw, OID_AUTO, pagesize, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_KERN, 0, 0, sysctl_pagesize, "Q", "");
SYSCTL_QUAD    (_hw, OID_AUTO, busfrequency, CTLFLAG_RD | CTLFLAG_KERN, &gPEClockFrequencyInfo.bus_frequency_hz, "");
SYSCTL_QUAD    (_hw, OID_AUTO, busfrequency_min, CTLFLAG_RD | CTLFLAG_KERN, &gPEClockFrequencyInfo.bus_frequency_min_hz, "");
SYSCTL_QUAD    (_hw, OID_AUTO, busfrequency_max, CTLFLAG_RD | CTLFLAG_KERN, &gPEClockFrequencyInfo.bus_frequency_max_hz, "");
SYSCTL_QUAD    (_hw, OID_AUTO, cpufrequency, CTLFLAG_RD | CTLFLAG_KERN, &gPEClockFrequencyInfo.cpu_frequency_hz, "");
SYSCTL_QUAD    (_hw, OID_AUTO, cpufrequency_min, CTLFLAG_RD | CTLFLAG_KERN, &gPEClockFrequencyInfo.cpu_frequency_min_hz, "");
SYSCTL_QUAD    (_hw, OID_AUTO, cpufrequency_max, CTLFLAG_RD | CTLFLAG_KERN, &gPEClockFrequencyInfo.cpu_frequency_max_hz, "");
SYSCTL_PROC    (_hw, OID_AUTO, cachelinesize, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_KERN, 0, HW_CACHELINE | CTLHW_RETQUAD, sysctl_hw_generic, "Q", "");
SYSCTL_PROC    (_hw, OID_AUTO, l1icachesize, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_KERN, 0, HW_L1ICACHESIZE | CTLHW_RETQUAD, sysctl_hw_generic, "Q", "");
SYSCTL_PROC    (_hw, OID_AUTO, l1dcachesize, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_KERN, 0, HW_L1DCACHESIZE | CTLHW_RETQUAD, sysctl_hw_generic, "Q", "");
SYSCTL_PROC    (_hw, OID_AUTO, l2cachesize, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_KERN, 0, HW_L2CACHESIZE | CTLHW_RETQUAD, sysctl_hw_generic, "Q", "");
SYSCTL_PROC    (_hw, OID_AUTO, l3cachesize, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_KERN, 0, HW_L3CACHESIZE | CTLHW_RETQUAD, sysctl_hw_generic, "Q", "");
SYSCTL_PROC(_hw, OID_AUTO, tbfrequency, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_KERN, 0, 0, sysctl_tbfrequency, "Q", "");
SYSCTL_QUAD    (_hw, HW_MEMSIZE, memsize, CTLFLAG_RD | CTLFLAG_KERN, &max_mem, "");
SYSCTL_INT     (_hw, OID_AUTO, packages, CTLFLAG_RD | CTLFLAG_KERN, &packages, 0, "");

/*
 * Optional features can register nodes below hw.optional.
 *
 * If the feature is not present, the node should either not be registered,
 * or it should return -1.  If the feature is present, the node should return
 * 0.  If the feature is present and its use is advised, the node should 
 * return 1.
 */
SYSCTL_NODE(_hw, OID_AUTO, optional, CTLFLAG_RW|CTLFLAG_LOCKED, NULL, "optional features");

SYSCTL_INT(_hw_optional, OID_AUTO, floatingpoint, CTLFLAG_RD | CTLFLAG_KERN, 0, 1, "");	/* always set */

/*
 * Deprecated variables.  These are supported for backwards compatibility
 * purposes only.  The MASKED flag requests that the variables not be
 * printed by sysctl(8) and similar utilities.
 *
 * The variables named *_compat here are int-sized versions of variables
 * that are now exported as quads.  The int-sized versions are normally
 * looked up only by number, wheras the quad-sized versions should be
 * looked up by name.
 *
 * The *_compat nodes are *NOT* visible within the kernel.
 */
SYSCTL_INT (_hw, HW_PAGESIZE,     pagesize_compat, CTLFLAG_RD | CTLFLAG_MASKED, &page_size, 0, "");
SYSCTL_INT (_hw, HW_BUS_FREQ,     busfrequency_compat, CTLFLAG_RD | CTLFLAG_MASKED, &gPEClockFrequencyInfo.bus_clock_rate_hz, 0, "");
SYSCTL_INT (_hw, HW_CPU_FREQ,     cpufrequency_compat, CTLFLAG_RD | CTLFLAG_MASKED, &gPEClockFrequencyInfo.cpu_clock_rate_hz, 0, "");
SYSCTL_PROC(_hw, HW_CACHELINE,    cachelinesize_compat, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED, 0, HW_CACHELINE, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, HW_L1ICACHESIZE, l1icachesize_compat, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED, 0, HW_L1ICACHESIZE, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, HW_L1DCACHESIZE, l1dcachesize_compat, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED, 0, HW_L1DCACHESIZE, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, HW_L2CACHESIZE,  l2cachesize_compat, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED, 0, HW_L2CACHESIZE, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, HW_L3CACHESIZE,  l3cachesize_compat, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED, 0, HW_L3CACHESIZE, sysctl_hw_generic, "I", "");
SYSCTL_INT (_hw, HW_TB_FREQ,      tbfrequency_compat, CTLFLAG_RD | CTLFLAG_MASKED, &gPEClockFrequencyInfo.timebase_frequency_hz, 0, "");
SYSCTL_PROC(_hw, HW_MACHINE,      machine, CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MASKED, 0, HW_MACHINE, sysctl_hw_generic, "A", "");
SYSCTL_PROC(_hw, HW_MODEL,        model, CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MASKED, 0, HW_MODEL, sysctl_hw_generic, "A", "");
SYSCTL_UINT(_hw, HW_PHYSMEM,      physmem, CTLFLAG_RD | CTLFLAG_MASKED, &mem_size, 0, "");
SYSCTL_PROC(_hw, HW_USERMEM,      usermem, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED, 0, HW_USERMEM,	sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, HW_EPOCH,        epoch, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED, 0, HW_EPOCH, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, HW_VECTORUNIT,   vectorunit, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED, 0, HW_VECTORUNIT, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, HW_L2SETTINGS,   l2settings, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED, 0, HW_L2SETTINGS, sysctl_hw_generic, "I", "");
SYSCTL_PROC(_hw, HW_L3SETTINGS,   l3settings, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED, 0, HW_L3SETTINGS, sysctl_hw_generic, "I", "");
SYSCTL_INT (_hw, OID_AUTO, cputhreadtype, CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN, &cputhreadtype, 0, "");

#ifdef __ppc__
int altivec_flag = -1;
int graphicsops_flag = -1;
int x64bitops_flag = -1;
int fsqrt_flag = -1;
int stfiwx_flag = -1;
int dcba_flag = -1;
int datastreams_flag = -1;
int dcbtstreams_flag = -1;

SYSCTL_INT(_hw_optional, OID_AUTO, altivec, CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN, &altivec_flag, 0, "");
SYSCTL_INT(_hw_optional, OID_AUTO, graphicsops, CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN, &graphicsops_flag, 0, "");
SYSCTL_INT(_hw_optional, OID_AUTO, 64bitops, CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN, &x64bitops_flag, 0, "");
SYSCTL_INT(_hw_optional, OID_AUTO, fsqrt, CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN, &fsqrt_flag, 0, "");
SYSCTL_INT(_hw_optional, OID_AUTO, stfiwx, CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN, &stfiwx_flag, 0, "");
SYSCTL_INT(_hw_optional, OID_AUTO, dcba, CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN, &dcba_flag, 0, "");
SYSCTL_INT(_hw_optional, OID_AUTO, datastreams, CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN, &datastreams_flag, 0, "");
SYSCTL_INT(_hw_optional, OID_AUTO, dcbtstreams, CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN, &dcbtstreams_flag, 0, "");
#elif defined (__i386__)
int mmx_flag = -1;
int sse_flag = -1;
int sse2_flag = -1;
int sse3_flag = -1;
int sse4_1_flag = -1;
int sse4_2_flag = -1;
int x86_64_flag = -1;
int supplementalsse3_flag = -1;

SYSCTL_INT(_hw_optional, OID_AUTO, mmx, CTLFLAG_RD | CTLFLAG_KERN, &mmx_flag, 0, "");
SYSCTL_INT(_hw_optional, OID_AUTO, sse, CTLFLAG_RD | CTLFLAG_KERN, &sse_flag, 0, "");
SYSCTL_INT(_hw_optional, OID_AUTO, sse2, CTLFLAG_RD | CTLFLAG_KERN, &sse2_flag, 0, "");
SYSCTL_INT(_hw_optional, OID_AUTO, sse3, CTLFLAG_RD | CTLFLAG_KERN, &sse3_flag, 0, "");
SYSCTL_INT(_hw_optional, OID_AUTO, supplementalsse3, CTLFLAG_RD | CTLFLAG_KERN, &supplementalsse3_flag, 0, "");
SYSCTL_INT(_hw_optional, OID_AUTO, sse4_1, CTLFLAG_RD | CTLFLAG_KERN, &sse4_1_flag, 0, "");
SYSCTL_INT(_hw_optional, OID_AUTO, sse4_2, CTLFLAG_RD | CTLFLAG_KERN, &sse4_2_flag, 0, "");
SYSCTL_INT(_hw_optional, OID_AUTO, x86_64, CTLFLAG_RD | CTLFLAG_KERN, &x86_64_flag, 0, "");
#endif /* __ppc__ */

/*
 * Debugging interface to the CPU power management code.
 */
static int
pmsSysctl(__unused struct sysctl_oid *oidp, __unused void *arg1,
	  __unused int arg2, struct sysctl_req *req)
{
	pmsctl_t	ctl;
	int		error;
	boolean_t	intr;

	if ((error = SYSCTL_IN(req, &ctl, sizeof(ctl))))
		return(error);

	intr = ml_set_interrupts_enabled(FALSE);		/* No interruptions in here */
	error = pmsControl(ctl.request, (user_addr_t)(unsigned long)ctl.reqaddr, ctl.reqsize);
	(void)ml_set_interrupts_enabled(intr);			/* Restore interruptions */

	return(error);
}

SYSCTL_PROC(_hw, OID_AUTO, pms, CTLTYPE_STRUCT | CTLFLAG_WR, 0, 0, pmsSysctl, "S", "Processor Power Management");



/******************************************************************************
 * Generic MIB initialisation.
 *
 * This is a hack, and should be replaced with SYSINITs
 * at some point.
 */
void
sysctl_mib_init(void)
{
	cputype = cpu_type();
	cpusubtype = cpu_subtype();
	cputhreadtype = cpu_threadtype();
#if defined(__ppc__)
    cpu64bit = (_cpu_capabilities & k64Bit) == k64Bit;
#elif defined(__i386__)
    cpu64bit = (_get_cpu_capabilities() & k64Bit) == k64Bit;
#elif defined(__arm__)
    cpu64bit = 0; // FIXME make this not hard-coded
#endif

	/*
	 * Populate the optional portion of the hw.* MIB.
	 *
	 * XXX This could be broken out into parts of the code
	 *     that actually directly relate to the functions in
	 *     question.
	 */

	if (cputhreadtype != CPU_THREADTYPE_NONE) {
		sysctl_register_oid(&sysctl__hw_cputhreadtype);
	}

#ifdef __ppc__
/*
 * The convention for these is as follows:
 * If the sysctl does not exist, the functionality is not present in the CPU.
 * If the sysctl exists, it will not crash, and should otherwise function
 *   corectly.
 * If the sysctl exists and returns 0, we advise against using this feature.
 * If the sysctl exists and returns 1, we advise it's use.
 */

	if (_cpu_capabilities & kHasAltivec) {
		altivec_flag = 1;
		sysctl_register_oid(&sysctl__hw_optional_altivec);
	}
	if (_cpu_capabilities & kHasGraphicsOps) {
		graphicsops_flag = 1;
		sysctl_register_oid(&sysctl__hw_optional_graphicsops);
	}		
	if (_cpu_capabilities & k64Bit) {
		x64bitops_flag = 1;
		sysctl_register_oid(&sysctl__hw_optional_64bitops);
	}		
	if (_cpu_capabilities & kHasFsqrt) {
		fsqrt_flag = 1;
		sysctl_register_oid(&sysctl__hw_optional_fsqrt);
	}		
	if (_cpu_capabilities & kHasStfiwx) {
		stfiwx_flag = 1;
		sysctl_register_oid(&sysctl__hw_optional_stfiwx);
	}		
	if (_cpu_capabilities & kDcbaAvailable)
		dcba_flag = 0;
	if (_cpu_capabilities & kDcbaRecommended)
		dcba_flag = 1;
	if (dcba_flag >= 0)
		sysctl_register_oid(&sysctl__hw_optional_dcba);
	if (_cpu_capabilities & kDataStreamsAvailable)
		datastreams_flag = 0;
	if (_cpu_capabilities & kDataStreamsRecommended)
		datastreams_flag = 1;
	if (datastreams_flag >= 0)
		sysctl_register_oid(&sysctl__hw_optional_datastreams);
	if (_cpu_capabilities & kDcbtStreamsAvailable)
		dcbtstreams_flag = 0;
	if (_cpu_capabilities & kDcbtStreamsRecommended)
		dcbtstreams_flag = 1;
	if (dcbtstreams_flag >= 0)
		sysctl_register_oid(&sysctl__hw_optional_dcbtstreams);

	/* hw.cpufamily */
	switch (cpusubtype) {
	case CPU_SUBTYPE_POWERPC_750:
		cpufamily = CPUFAMILY_POWERPC_G3;
		break;
	case CPU_SUBTYPE_POWERPC_7400:
	case CPU_SUBTYPE_POWERPC_7450:
		cpufamily = CPUFAMILY_POWERPC_G4;
		break;
	case CPU_SUBTYPE_POWERPC_970:
		cpufamily = CPUFAMILY_POWERPC_G5;
		break;
	default:
		cpufamily = CPUFAMILY_UNKNOWN;
	}

	ml_cpu_info_t cpu_info;
	ml_cpu_get_info(&cpu_info);

	host_basic_info_data_t hinfo;
	mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;
	kern_return_t kret = host_info((host_t)BSD_HOST, HOST_BASIC_INFO, (host_info_t)&hinfo, &count);
	if(kret != KERN_SUCCESS)
	{
		hinfo.max_cpus = 1;
	}

	/* hw.cachesize */
	cachesize[0] = max_mem;
	cachesize[1] = cpu_info.l1_dcache_size;
	cachesize[2] = cpu_info.l2_settings ? cpu_info.l2_cache_size : 0;
	cachesize[3] = cpu_info.l3_settings ? cpu_info.l3_cache_size : 0;
	cachesize[4] = 0;
	
	/* hw.cacheconfig */
	cacheconfig[0] = hinfo.max_cpus;
	cacheconfig[1] = 1;
	cacheconfig[2] = cachesize[2] ? 1 : 0;
	cacheconfig[3] = cachesize[3] ? 1 : 0;
	cacheconfig[4] = 0;

	/* hw.packages */
	if (cpusubtype == CPU_SUBTYPE_POWERPC_970 && 
	    cpu_info.l2_cache_size == 1 * 1024 * 1024)
		/* The signature of the dual-core G5 */
		packages = hinfo.max_cpus / 2;
	else
		packages = hinfo.max_cpus;

#elif defined (__i386__)
	mmx_flag = ((_get_cpu_capabilities() & kHasMMX) == kHasMMX)? 1 : 0;
	sse_flag = ((_get_cpu_capabilities() & kHasSSE) == kHasSSE)? 1 : 0;
	sse2_flag = ((_get_cpu_capabilities() & kHasSSE2) == kHasSSE2)? 1 : 0;
	sse3_flag = ((_get_cpu_capabilities() & kHasSSE3) == kHasSSE3)? 1 : 0;
	supplementalsse3_flag = ((_get_cpu_capabilities() & kHasSupplementalSSE3) == kHasSupplementalSSE3)? 1 : 0;
	sse4_1_flag = ((_get_cpu_capabilities() & kHasSSE4_1) == kHasSSE4_1)? 1 : 0;
	sse4_2_flag = ((_get_cpu_capabilities() & kHasSSE4_2) == kHasSSE4_2)? 1 : 0;
	x86_64_flag = ((_get_cpu_capabilities() & k64Bit) == k64Bit)? 1 : 0;

	/* hw.cpufamily */
	switch (cpuid_info()->cpuid_family) {
	case 6:
		switch (cpuid_info()->cpuid_model) {
		case 13:
			cpufamily = CPUFAMILY_INTEL_6_13;
			break;
		case 14:
			cpufamily = CPUFAMILY_INTEL_6_14; /* Core Solo/Duo */
			break;
		case 15:
			cpufamily = CPUFAMILY_INTEL_6_15; /* Core 2 */
			break;
		case 23:
			cpufamily = CPUFAMILY_INTEL_6_23;
			break;
		case 26:
			cpufamily = CPUFAMILY_INTEL_6_26;
			break;
		default:
			cpufamily = CPUFAMILY_UNKNOWN;
		}
		break;
	default:
		cpufamily = CPUFAMILY_UNKNOWN;
	}
	/* hw.cacheconfig */
	cacheconfig[0] = ml_cpu_cache_sharing(0);
	cacheconfig[1] = ml_cpu_cache_sharing(1);
	cacheconfig[2] = ml_cpu_cache_sharing(2);
	cacheconfig[3] = ml_cpu_cache_sharing(3);
	cacheconfig[4] = 0;

	/* hw.cachesize */
	cachesize[0] = ml_cpu_cache_size(0);
	cachesize[1] = ml_cpu_cache_size(1);
	cachesize[2] = ml_cpu_cache_size(2);
	cachesize[3] = ml_cpu_cache_size(3);
	cachesize[4] = 0;

	/* hw.packages */
	packages = ml_cpu_cache_sharing(0) /
			cpuid_info()->cpuid_cores_per_package;
	
#elif defined(__arm__) /* end __i386 */
	switch (cpuid_info()->arm_info.arm_part) {
		case CPU_PART_1136JFS:
		case CPU_PART_1176JZFS:
			cpufamily = CPUFAMILY_ARM_11;
			break;
		case CPU_PART_920T:
			cpufamily = CPUFAMILY_ARM_9;
			break;
		default:
			cpufamily = CPUFAMILY_UNKNOWN;
	}

	cacheconfig[0] = cache_info()->c_unified;
	cacheconfig[1] = cache_info()->c_isize;
	cacheconfig[2] = cache_info()->c_dsize;
	cacheconfig[3] = cache_info()->c_type;
	cacheconfig[4] = cache_info()->c_linesz;
	cacheconfig[5] = cache_info()->c_assoc;
	cacheconfig[6] = 0;

	packages = 1;
#else /* end __arm__ */
# warning we do not support this platform yet
#endif /* __ppc__ */


}

