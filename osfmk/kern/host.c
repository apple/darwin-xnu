/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */

/*
 *	host.c
 *
 *	Non-ipc host functions.
 */

#include <cpus.h>
#include <mach_host.h>

#include <mach/boolean.h>
#include <kern/assert.h>
#include <kern/kalloc.h>
#include <kern/host.h>
#include <kern/host_statistics.h>
#include <kern/ipc_host.h>
#include <kern/misc_protos.h>
#include <mach/host_info.h>
#include <mach/kern_return.h>
#include <mach/machine.h>
#include <mach/port.h>
#include <kern/processor.h>
#include <mach/processor_info.h>
#include <mach/vm_param.h>
#include <mach/mach_host_server.h>
#if     DIPC
#include <dipc/dipc_funcs.h>
#include <dipc/special_ports.h>
#endif

vm_statistics_data_t	vm_stat[NCPUS];

host_data_t	realhost;

kern_return_t
host_processors(
	host_priv_t		host_priv,
	processor_array_t	*processor_list,
	mach_msg_type_number_t	*countp)
{
	register int		i;
	register processor_t	*tp;
	vm_offset_t		addr;
	unsigned int		count;

	if (host_priv == HOST_PRIV_NULL)
		return(KERN_INVALID_ARGUMENT);

	assert(host_priv == &realhost);

	/*
	 *	Determine how many processors we have.
	 *	(This number shouldn't change.)
	 */

	count = 0;
	for (i = 0; i < NCPUS; i++)
		if (machine_slot[i].is_cpu)
			count++;

	if (count == 0)
		panic("host_processors");

	addr = kalloc((vm_size_t) (count * sizeof(mach_port_t)));
	if (addr == 0)
		return KERN_RESOURCE_SHORTAGE;

	tp = (processor_t *) addr;
	for (i = 0; i < NCPUS; i++)
		if (machine_slot[i].is_cpu)
			*tp++ = cpu_to_processor(i);

	*countp = count;
	*processor_list = (processor_array_t)addr;

	/* do the conversion that Mig should handle */

	tp = (processor_t *) addr;
	for (i = 0; i < count; i++)
		((mach_port_t *) tp)[i] =
		      (mach_port_t)convert_processor_to_port(tp[i]);

	return KERN_SUCCESS;
}

kern_return_t
host_info(
	host_t					host,
	host_flavor_t			flavor,
	host_info_t				info,
	mach_msg_type_number_t	*count)
{

	if (host == HOST_NULL)
		return(KERN_INVALID_ARGUMENT);
	
	switch(flavor) {

	case HOST_BASIC_INFO:
	{
		register host_basic_info_t	basic_info;

		/*
		 *	Basic information about this host.
		 */
		if (*count < HOST_BASIC_INFO_COUNT)
			return(KERN_FAILURE);

		basic_info = (host_basic_info_t) info;

		basic_info->max_cpus = machine_info.max_cpus;
		basic_info->avail_cpus = machine_info.avail_cpus;
		basic_info->memory_size = machine_info.memory_size;
		basic_info->cpu_type =
			machine_slot[master_processor->slot_num].cpu_type;
		basic_info->cpu_subtype =
			machine_slot[master_processor->slot_num].cpu_subtype;

		*count = HOST_BASIC_INFO_COUNT;

		return(KERN_SUCCESS);
	}

	case HOST_SCHED_INFO:
	{
		register host_sched_info_t	sched_info;
		extern int tick; /* XXX */

		/*
		 *	Return scheduler information.
		 */
		if (*count < HOST_SCHED_INFO_COUNT)
			return(KERN_FAILURE);

		sched_info = (host_sched_info_t) info;

		sched_info->min_timeout = tick / 1000; /* XXX */
		sched_info->min_quantum = tick / 1000; /* XXX */

		*count = HOST_SCHED_INFO_COUNT;

		return(KERN_SUCCESS);
	}

	case HOST_RESOURCE_SIZES:
	{ 
		/*
		 * Return sizes of kernel data structures
		 */
		if (*count < HOST_RESOURCE_SIZES_COUNT)
			return(KERN_FAILURE);

		/* XXX Fail until ledgers are implemented */
		return(KERN_INVALID_ARGUMENT);
	}
                  
	case HOST_PRIORITY_INFO:
	{
		register host_priority_info_t	priority_info;

		if (*count < HOST_PRIORITY_INFO_COUNT)
			return(KERN_FAILURE);

		priority_info = (host_priority_info_t) info;

		priority_info->kernel_priority	= MINPRI_KERNBAND;
		priority_info->system_priority	= MINPRI_KERNBAND;
		priority_info->server_priority	= MINPRI_HIGHBAND;
		priority_info->user_priority	= BASEPRI_DEFAULT;
		priority_info->depress_priority	= DEPRESSPRI;
		priority_info->idle_priority	= IDLEPRI;
		priority_info->minimum_priority	= MINPRI_STANDARD;
		priority_info->maximum_priority	= MAXPRI_HIGHBAND;

		*count = HOST_PRIORITY_INFO_COUNT;

		return(KERN_SUCCESS);
	}

	/*
	 * JMM - Temporary check to see if semaphore traps are
	 * supported on this machine.  Sadly, just trying to call
	 * the traps gets your process terminated instead of
	 * returning an error, so we have to query during mach_init
	 * to see if the machine supports them.
	 *
	 * KERN_INVALID_ARGUMENT - kernel has no semaphore traps
	 * KERN_SUCCESS - kernel has sema traps (up to semaphore_signal_wait)
	 * KERN_SEMAPHORE_DESTROYED - kernel has the latest semaphore traps
	 */
	case HOST_SEMAPHORE_TRAPS:
	{
		*count = 0;
		return KERN_SUCCESS;
	}

	default:
		return(KERN_INVALID_ARGUMENT);
	}
}

kern_return_t
host_statistics(
	host_t			host,
	host_flavor_t		flavor,
	host_info_t		info,
	mach_msg_type_number_t	*count)
{

	if (host == HOST_NULL)
		return(KERN_INVALID_HOST);
	
	switch(flavor) {

	case HOST_LOAD_INFO: {
		register host_load_info_t load_info;
		extern integer_t avenrun[3], mach_factor[3];

		if (*count < HOST_LOAD_INFO_COUNT)
			return(KERN_FAILURE);

		load_info = (host_load_info_t) info;

		bcopy((char *) avenrun,
		      (char *) load_info->avenrun,
		      sizeof avenrun);
		bcopy((char *) mach_factor,
		      (char *) load_info->mach_factor,
		      sizeof mach_factor);

		*count = HOST_LOAD_INFO_COUNT;
		return(KERN_SUCCESS);
	    }

	case HOST_VM_INFO: {
		register vm_statistics_t stat;
		vm_statistics_data_t host_vm_stat;
		extern int vm_page_free_count, vm_page_active_count,
			   vm_page_inactive_count, vm_page_wire_count;
                
		if (*count < HOST_VM_INFO_COUNT)
			return(KERN_FAILURE);

		stat = &vm_stat[0];
		host_vm_stat = *stat;
#if NCPUS > 1
		{
			register int i;

			for (i = 1; i < NCPUS; i++) {
				stat++;
				host_vm_stat.zero_fill_count +=
						stat->zero_fill_count;
				host_vm_stat.reactivations +=
						stat->reactivations;
				host_vm_stat.pageins += stat->pageins;
				host_vm_stat.pageouts += stat->pageouts;
				host_vm_stat.faults += stat->faults;
				host_vm_stat.cow_faults += stat->cow_faults;
				host_vm_stat.lookups += stat->lookups;
				host_vm_stat.hits += stat->hits;
			}
		}
#endif

		stat = (vm_statistics_t) info;

                stat->free_count = vm_page_free_count;
                stat->active_count = vm_page_active_count;
                stat->inactive_count = vm_page_inactive_count;
                stat->wire_count = vm_page_wire_count;
                stat->zero_fill_count = host_vm_stat.zero_fill_count;
                stat->reactivations = host_vm_stat.reactivations;
                stat->pageins = host_vm_stat.pageins;
                stat->pageouts = host_vm_stat.pageouts;
                stat->faults = host_vm_stat.faults;
                stat->cow_faults = host_vm_stat.cow_faults;
                stat->lookups = host_vm_stat.lookups;
                stat->hits = host_vm_stat.hits;

		*count = HOST_VM_INFO_COUNT;
		return(KERN_SUCCESS);
	    }
                
	case HOST_CPU_LOAD_INFO: {
		host_cpu_load_info_t	cpu_load_info;
		unsigned long		ticks_value1, ticks_value2;
		int			i;

#define GET_TICKS_VALUE(__cpu,__state) \
MACRO_BEGIN \
	do { \
		ticks_value1 = *(volatile integer_t *) \
			(&machine_slot[(__cpu)].cpu_ticks[(__state)]); \
		ticks_value2 = *(volatile integer_t *) \
			(&machine_slot[(__cpu)].cpu_ticks[(__state)]); \
	} while (ticks_value1 != ticks_value2); \
	cpu_load_info->cpu_ticks[(__state)] += ticks_value1; \
MACRO_END

		if (*count < HOST_CPU_LOAD_INFO_COUNT)
			return KERN_FAILURE;

		cpu_load_info = (host_cpu_load_info_t) info;

		cpu_load_info->cpu_ticks[CPU_STATE_USER] = 0;
		cpu_load_info->cpu_ticks[CPU_STATE_NICE] = 0;
		cpu_load_info->cpu_ticks[CPU_STATE_SYSTEM] = 0;
		cpu_load_info->cpu_ticks[CPU_STATE_IDLE] = 0;
		for (i = 0; i < NCPUS; i++) {
			if (!machine_slot[i].is_cpu ||
			    !machine_slot[i].running)
				continue;
			GET_TICKS_VALUE(i, CPU_STATE_USER);
			GET_TICKS_VALUE(i, CPU_STATE_NICE);
			GET_TICKS_VALUE(i, CPU_STATE_SYSTEM);
			GET_TICKS_VALUE(i, CPU_STATE_IDLE);
		}

		*count = HOST_CPU_LOAD_INFO_COUNT;
		return KERN_SUCCESS;
	    }

	default:
		return(KERN_INVALID_ARGUMENT);
	}
}

/*
 * Get host statistics that require privilege.
 * None for now, just call the un-privileged version.
 */
kern_return_t
host_priv_statistics(
	host_priv_t		host_priv,
	host_flavor_t		flavor,
	host_info_t		info,
	mach_msg_type_number_t	*count)
{
	return(host_statistics((host_t)host_priv, flavor, info, count));
}


kern_return_t
host_page_size(
	host_t		host,
	vm_size_t	*out_page_size)
{
	if (host == HOST_NULL)
		return(KERN_INVALID_ARGUMENT);

        *out_page_size = PAGE_SIZE;

	return(KERN_SUCCESS);
}

/*
 *	Return kernel version string (more than you ever
 *	wanted to know about what version of the kernel this is).
 */

kern_return_t
host_kernel_version(
	host_t			host,
	kernel_version_t	out_version)
{
	extern char	version[];

	if (host == HOST_NULL)
		return(KERN_INVALID_ARGUMENT);

	(void) strncpy(out_version, version, sizeof(kernel_version_t));

	return(KERN_SUCCESS);
}

/*
 *	host_processor_sets:
 *
 *	List all processor sets on the host.
 */
kern_return_t
host_processor_sets(
	host_priv_t			host_priv,
	processor_set_name_array_t	*pset_list,
	mach_msg_type_number_t		*count)
{
	vm_offset_t addr;

	if (host_priv == HOST_PRIV_NULL)
		return KERN_INVALID_ARGUMENT;

	/*
	 *	Allocate memory.  Can be pageable because it won't be
	 *	touched while holding a lock.
	 */

	addr = kalloc((vm_size_t) sizeof(mach_port_t));
	if (addr == 0)
		return KERN_RESOURCE_SHORTAGE;

	/* take ref for convert_pset_name_to_port */
	pset_reference(&default_pset);
	/* do the conversion that Mig should handle */
	*((ipc_port_t *) addr) = convert_pset_name_to_port(&default_pset);

	*pset_list = (processor_set_array_t)addr;
	*count = 1;

	return KERN_SUCCESS;
}

/*
 *	host_processor_set_priv:
 *
 *	Return control port for given processor set.
 */
kern_return_t
host_processor_set_priv(
	host_priv_t	host_priv,
	processor_set_t	pset_name,
	processor_set_t	*pset)
{
    if ((host_priv == HOST_PRIV_NULL) || (pset_name == PROCESSOR_SET_NULL)) {
	*pset = PROCESSOR_SET_NULL;
	return(KERN_INVALID_ARGUMENT);
    }

    *pset = pset_name;
    pset_reference(*pset);
    return(KERN_SUCCESS);
}

/*
 *	host_processor_info
 *
 *	Return info about the processors on this host.  It will return
 *	the number of processors, and the specific type of info requested
 *	in an OOL array.
 */
kern_return_t
host_processor_info(
	host_t			host,
	processor_flavor_t	flavor,
	natural_t		*proc_count,
	processor_info_array_t	*proc_info,
	mach_msg_type_number_t	*proc_info_count)
{
	int i;
	int num;
	int count;
	vm_size_t size;
	vm_offset_t addr;
	kern_return_t kr;
	vm_map_copy_t copy;
	processor_info_t proc_data;

	if (host == HOST_NULL)
		return KERN_INVALID_ARGUMENT;

	kr = processor_info_count(flavor, &count);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	    
	for (num = i = 0; i < NCPUS; i++)
		if (machine_slot[i].is_cpu)
			num++;

	size = (vm_size_t)round_page(num * count * sizeof(natural_t));

	kr = vm_allocate(ipc_kernel_map, &addr, size, TRUE);
	if (kr != KERN_SUCCESS)
		return KERN_RESOURCE_SHORTAGE;

	kr = vm_map_wire(ipc_kernel_map, addr, addr + size,
			 VM_PROT_READ|VM_PROT_WRITE, FALSE);
	if (kr != KERN_SUCCESS) {
		kmem_free(ipc_kernel_map, addr, size);
		return KERN_RESOURCE_SHORTAGE;
	}

	proc_data = (processor_info_t) addr;
	for (i = 0; i < NCPUS; i++) {
		int count2 = count;
		host_t host2;

		if (machine_slot[i].is_cpu) {
			kr = processor_info(cpu_to_processor(i),
					    flavor,
					    &host2,
					    proc_data,
					    &count2);
			if (kr != KERN_SUCCESS) {
				kmem_free(ipc_kernel_map, addr, size);
				return kr;
			}
			assert(count == count2);
			proc_data += count;
		}
	}

	kr = vm_map_unwire(ipc_kernel_map, addr, addr + size, FALSE);
	assert(kr == KERN_SUCCESS);
	size = (vm_size_t)(num * count * sizeof(natural_t));
	kr = vm_map_copyin(ipc_kernel_map, addr, size, TRUE, &copy);
	assert(kr == KERN_SUCCESS);

	*proc_count = num;
	*proc_info = (processor_info_array_t) copy;
	*proc_info_count = num * count;
	return(KERN_SUCCESS);
}


/*
 * 	host_get_io_master
 *
 *	Return the IO master access port for this host.
 */
kern_return_t
host_get_io_master(
        host_t host,
        io_master_t *io_master)
{
	if (host == HOST_NULL)
		return KERN_INVALID_ARGUMENT;
	*io_master = ipc_port_copy_send(realhost.io_master);
        return KERN_SUCCESS;
}

#define io_master_deallocate(x)

/*
 * 	host_get_io_master
 *
 *	Return the IO master access port for this host.
 */
kern_return_t
host_set_io_master(
        host_priv_t host_priv,
        io_master_t io_master)
{
	io_master_t old_master;

	if (host_priv == HOST_PRIV_NULL)
		return KERN_INVALID_ARGUMENT;

	old_master = realhost.io_master;
	realhost.io_master = io_master;
	io_master_deallocate(old_master);
        return KERN_SUCCESS;
}

/*
 *      User interface for setting a special port.
 *
 *      Only permits the user to set a user-owned special port
 *      ID, rejecting a kernel-owned special port ID.
 *
 *      A special kernel port cannot be set up using this
 *      routine; use kernel_set_special_port() instead.
 */
kern_return_t
host_set_special_port(
        host_priv_t     host_priv,
        int             id,
        ipc_port_t      port)
{
#if     DIPC
        return norma_set_special_port(host_priv, id, port);
#else
        return KERN_FAILURE;
#endif
}


/*
 *      User interface for retrieving a special port.
 *
 *      When all processing is local, this call does not block.
 *      If processing goes remote to discover a remote UID,
 *      this call blocks but not indefinitely.  If the remote
 *      node does not exist, has panic'ed, or is booting but
 *      hasn't yet turned on DIPC, then we expect the transport
 *      to return an error.
 *
 *      This routine always returns SUCCESS, even if there's
 *      no resulting port.
 *
 *      Note that there is nothing to prevent a user special
 *      port from disappearing after it has been discovered by
 *      the caller; thus, using a special port can always result
 *      in a "port not valid" error.
 */

kern_return_t
host_get_special_port(
        host_priv_t     host_priv,
        int             node,
        int             id,
        ipc_port_t      *portp)
{
#if     DIPC
        return norma_get_special_port(host_priv, node, id, portp);
#else
        return KERN_FAILURE;
#endif
}

host_t
host_self(void)
{
  return &realhost;
}

host_priv_t
host_priv_self(void)
{
  return &realhost;
}

host_security_t
host_security_self(void)
{
  return &realhost;
}
	  
