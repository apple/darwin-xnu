/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */
/*
 * Microkernel interface to common profiling.
 */

#include <profiling/profile-mk.h>
#include <string.h>
#include <kern/cpu_number.h>
#include <kern/processor.h>
#include <kern/spl.h>
#include <kern/misc_protos.h>
#include <vm/vm_kern.h>
#include <mach/vm_param.h>

#include <device/ds_routines.h>
#include <device/io_req.h>
#include <device/buf.h>

extern char etext[], pstart[];

#if NCPUS > 1
struct profile_vars *_profile_vars_cpus[NCPUS] = { &_profile_vars };
struct profile_vars _profile_vars_aux[NCPUS-1];
#endif

void *
_profile_alloc_pages (size_t size)
{
	vm_offset_t addr;

	/*
	 * For the MK, we can't support allocating pages at runtime, because we
	 * might be at interrupt level, so abort if we didn't size the table
	 * properly.
	 */

	if (PROFILE_VARS(0)->active) {
		panic("Call to _profile_alloc_pages while profiling is running.");
	}

	if (kmem_alloc(kernel_map, &addr, size)) {
		panic("Could not allocate memory for profiling");
	}

	memset((void *)addr, '\0', size);
	if (PROFILE_VARS(0)->debug) {
		printf("Allocated %d bytes for profiling, address 0x%x\n", (int)size, (int)addr);
	}

	return((caddr_t)addr);
}

void
_profile_free_pages(void *addr, size_t size)
{
	if (PROFILE_VARS(0)->debug) {
		printf("Freed %d bytes for profiling, address 0x%x\n", (int)size, (int)addr);
	}

	kmem_free(kernel_map, (vm_offset_t)addr, size);
	return;
}

void _profile_error(struct profile_vars *pv)
{
	panic("Fatal error in profiling");
}

void
kmstartup(void)
{
	prof_uptrint_t textsize;
	prof_uptrint_t monsize;
	prof_uptrint_t lowpc;
	prof_uptrint_t highpc;
	int i;
	struct profile_vars *pv;

	/*
	 * round lowpc and highpc to multiples of the density we're using
	 * so the rest of the scaling (here and in gprof) stays in ints.
	 */

	lowpc = ROUNDDOWN((prof_uptrint_t)&pstart[0], HISTFRACTION*sizeof(LHISTCOUNTER));
	highpc = ROUNDUP((prof_uptrint_t)&etext[0], HISTFRACTION*sizeof(LHISTCOUNTER));
	textsize = highpc - lowpc;
	monsize = (textsize / HISTFRACTION) * sizeof(LHISTCOUNTER);

	for (i = 0; i < NCPUS; i++) {
		pv = PROFILE_VARS(i);

#if NCPUS > 1
		if (!pv) {
			_profile_vars_cpus[i] = pv = &_profile_vars_aux[i-i];
		}
#endif

#ifdef DEBUG_PROFILE
		pv->debug = 1;
#endif
		pv->page_size = PAGE_SIZE;
		_profile_md_init(pv, PROFILE_GPROF, PROFILE_ALLOC_MEM_YES);

		/* Profil related variables */
		pv->profil_buf = _profile_alloc (pv, monsize, ACONTEXT_PROFIL);
		pv->profil_info.highpc = highpc;
		pv->profil_info.lowpc = lowpc;
		pv->profil_info.text_len = textsize;
		pv->profil_info.profil_len = monsize;
		pv->profil_info.counter_size = sizeof(LHISTCOUNTER);
		pv->profil_info.scale = 0x10000 / HISTFRACTION;
		pv->stats.profil_buckets = monsize / sizeof(LHISTCOUNTER);

		/* Other gprof variables */
		pv->stats.my_cpu = i;
		pv->stats.max_cpu = NCPUS;
		pv->init = 1;
		pv->active = 1;
		pv->use_dci = 0;
		pv->use_profil = 1;
		pv->check_funcs = 1;		/* for now */

		if (pv->debug) {
			printf("Profiling kernel, s_textsize=%ld, monsize=%ld [0x%lx..0x%lx], cpu = %d\n",
			       (long)textsize,
			       (long)monsize,
			       (long)lowpc,
			       (long)highpc,
			       i);
		}
	}

	_profile_md_start();
}

/* driver component */

int
gprofprobe(caddr_t port, void *ctlr)
{
	return(1);
}

void
gprofattach(void)
{
	kmstartup();
	return;
}

/* struct bus_device *gprofinfo[NGPROF]; */
struct bus_device *gprofinfo[1];

struct	bus_driver	gprof_driver = {
	gprofprobe, 0, gprofattach, 0, 0, "gprof", gprofinfo, "gprofc", 0, 0};


io_return_t
gprofopen(dev_t dev,
	  int flags,
	  io_req_t ior)
{
	ior->io_error = D_SUCCESS;
	return(0);
}

void
gprofclose(dev_t dev)
{
	return;
}

void
gprofstrategy(io_req_t ior)
{
	void *sys_ptr = (void *)0;

	long count = _profile_kgmon(!(ior->io_op & IO_READ),
				    ior->io_count,
				    ior->io_recnum,
				    NCPUS,
				    &sys_ptr,
				    (void (*)(kgmon_control_t))0);

	if (count < 0) {
		ior->io_error = D_INVALID_RECNUM;

	} else {
		if (count > 0 && sys_ptr != (void *)0) {
			if (ior->io_op & IO_READ) {
				memcpy((void *)ior->io_data, sys_ptr, count);
			} else {
				memcpy(sys_ptr, (void *)ior->io_data, count);
			}
		}

		ior->io_error = D_SUCCESS;
		ior->io_residual = ior->io_count - count;
	}

	iodone(ior);
}

io_return_t
gprofread(dev_t dev,
	  io_req_t ior)
{
	return(block_io(gprofstrategy, minphys, ior));
}

io_return_t
gprofwrite(dev_t dev,
	   io_req_t ior)
{
	return (block_io(gprofstrategy, minphys, ior));
}
