/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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

#include <mach_host.h>

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/host_info.h>
#include <mach/host_special_ports.h>
#include <mach/kern_return.h>
#include <mach/machine.h>
#include <mach/port.h>
#include <mach/processor_info.h>
#include <mach/vm_param.h>
#include <mach/processor.h>
#include <mach/mach_host_server.h>
#include <mach/host_priv_server.h>
#include <mach/vm_map.h>

#include <kern/kern_types.h>
#include <kern/assert.h>
#include <kern/kalloc.h>
#include <kern/host.h>
#include <kern/host_statistics.h>
#include <kern/ipc_host.h>
#include <kern/misc_protos.h>
#include <kern/sched.h>
#include <kern/processor.h>

#include <vm/vm_map.h>

#if     DIPC
#include <dipc/dipc_funcs.h>
#include <dipc/special_ports.h>
#endif

host_data_t	realhost;

kern_return_t
host_processors(
	host_priv_t				host_priv,
	processor_array_t		*out_array,
	mach_msg_type_number_t	*countp)
{
	register processor_t	processor, *tp;
	void					*addr;
	unsigned int			count, i;

	if (host_priv == HOST_PRIV_NULL)
		return (KERN_INVALID_ARGUMENT);

	assert(host_priv == &realhost);

	count = processor_count;
	assert(count != 0);

	addr = kalloc((vm_size_t) (count * sizeof(mach_port_t)));
	if (addr == 0)
		return (KERN_RESOURCE_SHORTAGE);

	tp = (processor_t *) addr;
	*tp++ = processor = processor_list;

	if (count > 1) {
		simple_lock(&processor_list_lock);

		for (i = 1; i < count; i++)
			*tp++ = processor = processor->processor_list;

		simple_unlock(&processor_list_lock);
	}

	*countp = count;
	*out_array = (processor_array_t)addr;

	/* do the conversion that Mig should handle */

	tp = (processor_t *) addr;
	for (i = 0; i < count; i++)
		((mach_port_t *) tp)[i] =
		      (mach_port_t)convert_processor_to_port(tp[i]);

	return (KERN_SUCCESS);
}

kern_return_t
host_info(
	host_t					host,
	host_flavor_t			flavor,
	host_info_t				info,
	mach_msg_type_number_t	*count)
{

	if (host == HOST_NULL)
		return (KERN_INVALID_ARGUMENT);
	
	switch (flavor) {

	case HOST_BASIC_INFO:
	{
		register host_basic_info_t	basic_info;
		register int				master_slot;

		/*
		 *	Basic information about this host.
		 */
		if (*count < HOST_BASIC_INFO_OLD_COUNT)
			return (KERN_FAILURE);

		basic_info = (host_basic_info_t) info;

		basic_info->max_cpus = machine_info.max_cpus;
		basic_info->avail_cpus = machine_info.avail_cpus;
		basic_info->memory_size = machine_info.memory_size;
		master_slot = PROCESSOR_DATA(master_processor, slot_num);
		basic_info->cpu_type = slot_type(master_slot);
		basic_info->cpu_subtype = slot_subtype(master_slot);

		if (*count >= HOST_BASIC_INFO_COUNT) {
			basic_info->cpu_threadtype = slot_threadtype(master_slot);
			basic_info->physical_cpu = machine_info.physical_cpu;
			basic_info->physical_cpu_max = machine_info.physical_cpu_max;
			basic_info->logical_cpu = machine_info.logical_cpu;
			basic_info->logical_cpu_max = machine_info.logical_cpu_max;
			basic_info->max_mem = machine_info.max_mem;

			*count = HOST_BASIC_INFO_COUNT;
		} else {
			*count = HOST_BASIC_INFO_OLD_COUNT;
		}

		return (KERN_SUCCESS);
	}

	case HOST_SCHED_INFO:
	{
		register host_sched_info_t	sched_info;

		/*
		 *	Return scheduler information.
		 */
		if (*count < HOST_SCHED_INFO_COUNT)
			return (KERN_FAILURE);

		sched_info = (host_sched_info_t) info;

		sched_info->min_timeout = 
			sched_info->min_quantum = std_quantum_us / 1000;

		*count = HOST_SCHED_INFO_COUNT;

		return (KERN_SUCCESS);
	}

	case HOST_RESOURCE_SIZES:
	{ 
		/*
		 * Return sizes of kernel data structures
		 */
		if (*count < HOST_RESOURCE_SIZES_COUNT)
			return (KERN_FAILURE);

		/* XXX Fail until ledgers are implemented */
		return (KERN_INVALID_ARGUMENT);
	}
                  
	case HOST_PRIORITY_INFO:
	{
		register host_priority_info_t	priority_info;

		if (*count < HOST_PRIORITY_INFO_COUNT)
			return (KERN_FAILURE);

		priority_info = (host_priority_info_t) info;

		priority_info->kernel_priority	= MINPRI_KERNEL;
		priority_info->system_priority	= MINPRI_KERNEL;
		priority_info->server_priority	= MINPRI_RESERVED;
		priority_info->user_priority	= BASEPRI_DEFAULT;
		priority_info->depress_priority	= DEPRESSPRI;
		priority_info->idle_priority	= IDLEPRI;
		priority_info->minimum_priority	= MINPRI_USER;
		priority_info->maximum_priority	= MAXPRI_RESERVED;

		*count = HOST_PRIORITY_INFO_COUNT;

		return (KERN_SUCCESS);
	}

	/*
	 * Gestalt for various trap facilities.
	 */
	case HOST_MACH_MSG_TRAP:
	case HOST_SEMAPHORE_TRAPS:
	{
		*count = 0;
		return (KERN_SUCCESS);
	}

	default:
		return (KERN_INVALID_ARGUMENT);
	}
}

kern_return_t
host_statistics(
	host_t					host,
	host_flavor_t			flavor,
	host_info_t				info,
	mach_msg_type_number_t	*count)
{

	if (host == HOST_NULL)
		return (KERN_INVALID_HOST);
	
	switch(flavor) {

	case HOST_LOAD_INFO:
	{
		host_load_info_t	load_info;

		if (*count < HOST_LOAD_INFO_COUNT)
			return (KERN_FAILURE);

		load_info = (host_load_info_t) info;

		bcopy((char *) avenrun,
			  (char *) load_info->avenrun, sizeof avenrun);
		bcopy((char *) mach_factor,
			  (char *) load_info->mach_factor, sizeof mach_factor);

		*count = HOST_LOAD_INFO_COUNT;
		return (KERN_SUCCESS);
	}

	case HOST_VM_INFO:
	{
		register processor_t		processor;
		register vm_statistics_t	stat;
		vm_statistics_data_t		host_vm_stat;
                
		if (*count < HOST_VM_INFO_REV0_COUNT)
			return (KERN_FAILURE);

		processor = processor_list;
		stat = &PROCESSOR_DATA(processor, vm_stat);
		host_vm_stat = *stat;

		if (processor_count > 1) {
			simple_lock(&processor_list_lock);

			while ((processor = processor->processor_list) != NULL) {
				stat = &PROCESSOR_DATA(processor, vm_stat);

				host_vm_stat.zero_fill_count +=	stat->zero_fill_count;
				host_vm_stat.reactivations += stat->reactivations;
				host_vm_stat.pageins += stat->pageins;
				host_vm_stat.pageouts += stat->pageouts;
				host_vm_stat.faults += stat->faults;
				host_vm_stat.cow_faults += stat->cow_faults;
				host_vm_stat.lookups += stat->lookups;
				host_vm_stat.hits += stat->hits;
			}

			simple_unlock(&processor_list_lock);
		}

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

		if (*count >= HOST_VM_INFO_COUNT) {
			/* info that was not in revision 0 of that interface */
			stat->purgeable_count = vm_page_purgeable_count;
			stat->purges = vm_page_purged_count;
			*count = HOST_VM_INFO_COUNT;
		} else {
			*count = HOST_VM_INFO_REV0_COUNT;
		}

		return (KERN_SUCCESS);
	}
                
	case HOST_CPU_LOAD_INFO:
	{
		register processor_t	processor;
		host_cpu_load_info_t	cpu_load_info;
		unsigned long			ticks_value1, ticks_value2;

		if (*count < HOST_CPU_LOAD_INFO_COUNT)
			return (KERN_FAILURE);

#define GET_TICKS_VALUE(processor, state)	 					\
MACRO_BEGIN														\
	do {														\
		ticks_value1 = *(volatile integer_t *)					\
			&PROCESSOR_DATA((processor), cpu_ticks[(state)]);	\
		ticks_value2 = *(volatile integer_t *)					\
			&PROCESSOR_DATA((processor), cpu_ticks[(state)]);	\
	} while (ticks_value1 != ticks_value2);						\
																\
	cpu_load_info->cpu_ticks[(state)] += ticks_value1;			\
MACRO_END

		cpu_load_info = (host_cpu_load_info_t)info;
		cpu_load_info->cpu_ticks[CPU_STATE_USER] = 0;
		cpu_load_info->cpu_ticks[CPU_STATE_NICE] = 0;
		cpu_load_info->cpu_ticks[CPU_STATE_SYSTEM] = 0;
		cpu_load_info->cpu_ticks[CPU_STATE_IDLE] = 0;

		processor = processor_list;
		GET_TICKS_VALUE(processor, CPU_STATE_USER);
		GET_TICKS_VALUE(processor, CPU_STATE_NICE);
		GET_TICKS_VALUE(processor, CPU_STATE_SYSTEM);
		GET_TICKS_VALUE(processor, CPU_STATE_IDLE);

		if (processor_count > 1) {
			simple_lock(&processor_list_lock);

			while ((processor = processor->processor_list) != NULL) {
				GET_TICKS_VALUE(processor, CPU_STATE_USER);
				GET_TICKS_VALUE(processor, CPU_STATE_NICE);
				GET_TICKS_VALUE(processor, CPU_STATE_SYSTEM);
				GET_TICKS_VALUE(processor, CPU_STATE_IDLE);
			}

			simple_unlock(&processor_list_lock);
		}

		*count = HOST_CPU_LOAD_INFO_COUNT;

		return (KERN_SUCCESS);
	}

	default:
		return (KERN_INVALID_ARGUMENT);
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
extern char	version[];

kern_return_t
host_kernel_version(
	host_t			host,
	kernel_version_t	out_version)
{

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
	void *addr;

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
	host_t					host,
	processor_flavor_t		flavor,
	natural_t				*out_pcount,
	processor_info_array_t	*out_array,
	mach_msg_type_number_t	*out_array_count)
{
	kern_return_t			result;
	processor_t				processor;
	host_t					thost;
	processor_info_t		info;
	unsigned int			icount, tcount;
	unsigned int			pcount, i;
	vm_offset_t				addr;
	vm_size_t				size;
	vm_map_copy_t			copy;

	if (host == HOST_NULL)
		return (KERN_INVALID_ARGUMENT);

	result = processor_info_count(flavor, &icount);
	if (result != KERN_SUCCESS)
		return (result);

	pcount = processor_count;
	assert(pcount != 0);

	size = round_page(pcount * icount * sizeof(natural_t));
	result = kmem_alloc(ipc_kernel_map, &addr, size);
	if (result != KERN_SUCCESS)
		return (KERN_RESOURCE_SHORTAGE);

	info = (processor_info_t) addr;
	processor = processor_list;
	tcount = icount;

	result = processor_info(processor, flavor, &thost, info, &tcount);
	if (result != KERN_SUCCESS) {
		kmem_free(ipc_kernel_map, addr, size);
		return (result);
	}

	if (pcount > 1) {
		for (i = 1; i < pcount; i++) {
			simple_lock(&processor_list_lock);
			processor = processor->processor_list;
			simple_unlock(&processor_list_lock);

			info += icount;
			tcount = icount;
			result = processor_info(processor, flavor, &thost, info, &tcount);
			if (result != KERN_SUCCESS) {
				kmem_free(ipc_kernel_map, addr, size);
				return (result);
			}
		}
	}

	result = vm_map_unwire(ipc_kernel_map, vm_map_trunc_page(addr),
			       vm_map_round_page(addr + size), FALSE);
	assert(result == KERN_SUCCESS);
	result = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)addr,
			       (vm_map_size_t)size, TRUE, &copy);
	assert(result == KERN_SUCCESS);

	*out_pcount = pcount;
	*out_array = (processor_info_array_t) copy;
	*out_array_count = pcount * icount;

	return (KERN_SUCCESS);
}

/*
 *      Kernel interface for setting a special port.
 */
kern_return_t
kernel_set_special_port(
	host_priv_t	host_priv,		
	int		id,
	ipc_port_t	port)
{
	ipc_port_t old_port;

	host_lock(host_priv);
	old_port = host_priv->special[id];
	host_priv->special[id] = port;
	host_unlock(host_priv);
	if (IP_VALID(old_port))
		ipc_port_release_send(old_port);
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
	if (host_priv == HOST_PRIV_NULL ||
	    id <= HOST_MAX_SPECIAL_KERNEL_PORT || id > HOST_MAX_SPECIAL_PORT ) {
		if (IP_VALID(port))
			ipc_port_release_send(port);
		return KERN_INVALID_ARGUMENT;
	}

	return kernel_set_special_port(host_priv, id, port);
}


/*
 *      User interface for retrieving a special port.
 *
 *      Note that there is nothing to prevent a user special
 *      port from disappearing after it has been discovered by
 *      the caller; thus, using a special port can always result
 *      in a "port not valid" error.
 */

kern_return_t
host_get_special_port(
        host_priv_t     host_priv,
        __unused int    node,
        int             id,
        ipc_port_t      *portp)
{
	ipc_port_t	port;

	if (host_priv == HOST_PRIV_NULL ||
	    id == HOST_SECURITY_PORT || id > HOST_MAX_SPECIAL_PORT )
		return KERN_INVALID_ARGUMENT;

#if     DIPC
	if (node != HOST_LOCAL_NODE)
        	return norma_get_special_port(host_priv, node, id, portp);
#endif

	host_lock(host_priv);
	port = realhost.special[id];
	*portp = ipc_port_copy_send(port);
	host_unlock(host_priv);

	return KERN_SUCCESS;
}


/*
 * 	host_get_io_master
 *
 *	Return the IO master access port for this host.
 */
kern_return_t
host_get_io_master(
        host_t host,
        io_master_t *io_masterp)
{
	if (host == HOST_NULL)
		return KERN_INVALID_ARGUMENT;

	return (host_get_io_master_port(host_priv_self(), io_masterp));
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
	  
