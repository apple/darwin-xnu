/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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
 *	kern/ipc_host.c
 *
 *	Routines to implement host ports.
 */
#include <mach/message.h>
#include <mach/mach_traps.h>
#include <mach/mach_host_server.h>
#include <mach/host_priv_server.h>
#include <kern/host.h>
#include <kern/processor.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/ipc_host.h>
#include <kern/ipc_kobject.h>
#include <kern/misc_protos.h>
#include <kern/spl.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>

#if CONFIG_MACF
#include <security/mac_mach_internal.h>
#endif

/*
 * Forward declarations
 */

boolean_t
ref_pset_port_locked(
	ipc_port_t port, boolean_t matchn, processor_set_t *ppset);

/*
 *	ipc_host_init: set up various things.
 */

extern lck_grp_t		host_notify_lock_grp;
extern lck_attr_t		host_notify_lock_attr;

void ipc_host_init(void)
{
	ipc_port_t	port;
	int i;

	lck_mtx_init(&realhost.lock, &host_notify_lock_grp, &host_notify_lock_attr);

	/*
	 *	Allocate and set up the two host ports.
	 */
	port = ipc_port_alloc_kernel();
	if (port == IP_NULL)
		panic("ipc_host_init");

	ipc_kobject_set(port, (ipc_kobject_t) &realhost, IKOT_HOST_SECURITY);
	kernel_set_special_port(&realhost, HOST_SECURITY_PORT,
				ipc_port_make_send(port));

	port = ipc_port_alloc_kernel();
	if (port == IP_NULL)
		panic("ipc_host_init");

	ipc_kobject_set(port, (ipc_kobject_t) &realhost, IKOT_HOST);
	kernel_set_special_port(&realhost, HOST_PORT,
				ipc_port_make_send(port));

	port = ipc_port_alloc_kernel();
	if (port == IP_NULL)
		panic("ipc_host_init");

	ipc_kobject_set(port, (ipc_kobject_t) &realhost, IKOT_HOST_PRIV);
	kernel_set_special_port(&realhost, HOST_PRIV_PORT,
				ipc_port_make_send(port));

	/* the rest of the special ports will be set up later */

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
			realhost.exc_actions[i].port = IP_NULL;
			realhost.exc_actions[i].label = NULL;
			/* The mac framework is not yet initialized, so we defer
			 * initializing the labels to later, when they are set
			 * for the first time. */
		}/* for */

	/*
	 *	Set up ipc for default processor set.
	 */
	ipc_pset_init(&pset0);
	ipc_pset_enable(&pset0);

	/*
	 *	And for master processor
	 */
	ipc_processor_init(master_processor);
	ipc_processor_enable(master_processor);
}

/*
 *	Routine:	host_self_trap [mach trap]
 *	Purpose:
 *		Give the caller send rights for his own host port.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_PORT_NULL if there are any resource failures
 *		or other errors.
 */

mach_port_name_t
host_self_trap(
	__unused struct host_self_trap_args *args)
{
	ipc_port_t sright;
	mach_port_name_t name;

	sright = ipc_port_copy_send(current_task()->itk_host);
	name = ipc_port_copyout_send(sright, current_space());
	return name;
}

/*
 *	ipc_processor_init:
 *
 *	Initialize ipc access to processor by allocating port.
 */

void
ipc_processor_init(
	processor_t	processor)
{
	ipc_port_t	port;

	port = ipc_port_alloc_kernel();
	if (port == IP_NULL)
		panic("ipc_processor_init");
	processor->processor_self = port;
}

/*
 *	ipc_processor_enable:
 *
 *	Enable ipc control of processor by setting port object.
 */
void
ipc_processor_enable(
	processor_t	processor)
{
	ipc_port_t	myport;

	myport = processor->processor_self;
	ipc_kobject_set(myport, (ipc_kobject_t) processor, IKOT_PROCESSOR);
}
	
/*
 *	ipc_pset_init:
 *
 *	Initialize ipc control of a processor set by allocating its ports.
 */

void
ipc_pset_init(
	processor_set_t		pset)
{
	ipc_port_t	port;

	port = ipc_port_alloc_kernel();
	if (port == IP_NULL)
		panic("ipc_pset_init");
	pset->pset_self = port;

	port = ipc_port_alloc_kernel();
	if (port == IP_NULL)
		panic("ipc_pset_init");
	pset->pset_name_self = port;
}

/*
 *	ipc_pset_enable:
 *
 *	Enable ipc access to a processor set.
 */
void
ipc_pset_enable(
	processor_set_t		pset)
{
	ipc_kobject_set(pset->pset_self, (ipc_kobject_t) pset, IKOT_PSET);
	ipc_kobject_set(pset->pset_name_self, (ipc_kobject_t) pset, IKOT_PSET_NAME);
}

/*
 *	processor_set_default:
 *
 *	Return ports for manipulating default_processor set.
 */
kern_return_t
processor_set_default(
	host_t			host,
	processor_set_t		*pset)
{
	if (host == HOST_NULL)
		return(KERN_INVALID_ARGUMENT);

	*pset = &pset0;

	return (KERN_SUCCESS);
}

/*
 *	Routine:	convert_port_to_host
 *	Purpose:
 *		Convert from a port to a host.
 *		Doesn't consume the port ref; the host produced may be null.
 *	Conditions:
 *		Nothing locked.
 */

host_t
convert_port_to_host(
	ipc_port_t	port)
{
	host_t host = HOST_NULL;

	if (IP_VALID(port)) {
		if (ip_kotype(port) == IKOT_HOST ||
		    ip_kotype(port) == IKOT_HOST_PRIV) {
			host = (host_t) port->ip_kobject;
			assert(ip_active(port));
		}
	}
	return host;
}

/*
 *	Routine:	convert_port_to_host_priv
 *	Purpose:
 *		Convert from a port to a host.
 *		Doesn't consume the port ref; the host produced may be null.
 *	Conditions:
 *		Nothing locked.
 */

host_t
convert_port_to_host_priv(
	ipc_port_t	port)
{
	host_t host = HOST_NULL;

	if (IP_VALID(port)) {
		ip_lock(port);
		if (ip_active(port) &&
		    (ip_kotype(port) == IKOT_HOST_PRIV))
			host = (host_t) port->ip_kobject;
		ip_unlock(port);
	}

	return host;
}

/*
 *	Routine:	convert_port_to_processor
 *	Purpose:
 *		Convert from a port to a processor.
 *		Doesn't consume the port ref;
 *		the processor produced may be null.
 *	Conditions:
 *		Nothing locked.
 */

processor_t
convert_port_to_processor(
	ipc_port_t	port)
{
	processor_t processor = PROCESSOR_NULL;

	if (IP_VALID(port)) {
		ip_lock(port);
		if (ip_active(port) &&
		    (ip_kotype(port) == IKOT_PROCESSOR))
			processor = (processor_t) port->ip_kobject;
		ip_unlock(port);
	}

	return processor;
}

/*
 *	Routine:	convert_port_to_pset
 *	Purpose:
 *		Convert from a port to a pset.
 *		Doesn't consume the port ref; produces a pset ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */

processor_set_t
convert_port_to_pset(
	ipc_port_t	port)
{
	boolean_t r;
	processor_set_t pset = PROCESSOR_SET_NULL;

	r = FALSE;
	while (!r && IP_VALID(port)) {
		ip_lock(port);
		r = ref_pset_port_locked(port, FALSE, &pset);
		/* port unlocked */
	}
	return pset;
}

/*
 *	Routine:	convert_port_to_pset_name
 *	Purpose:
 *		Convert from a port to a pset.
 *		Doesn't consume the port ref; produces a pset ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */

processor_set_name_t
convert_port_to_pset_name(
	ipc_port_t	port)
{
	boolean_t r;
	processor_set_t pset = PROCESSOR_SET_NULL;

	r = FALSE;
	while (!r && IP_VALID(port)) {
		ip_lock(port);
		r = ref_pset_port_locked(port, TRUE, &pset);
		/* port unlocked */
	}
	return pset;
}

boolean_t
ref_pset_port_locked(ipc_port_t port, boolean_t matchn, processor_set_t *ppset)
{
	processor_set_t pset;

	pset = PROCESSOR_SET_NULL;
	if (ip_active(port) &&
		((ip_kotype(port) == IKOT_PSET) ||
			(matchn && (ip_kotype(port) == IKOT_PSET_NAME)))) {
		pset = (processor_set_t) port->ip_kobject;
	}

	*ppset = pset;
	ip_unlock(port);

	return (TRUE);
}

/*
 *	Routine:	convert_host_to_port
 *	Purpose:
 *		Convert from a host to a port.
 *		Produces a naked send right which may be invalid.
 *	Conditions:
 *		Nothing locked.
 */

ipc_port_t
convert_host_to_port(
	host_t		host)
{
	ipc_port_t port;

	host_get_host_port(host, &port);
	return port;
}

/*
 *	Routine:	convert_processor_to_port
 *	Purpose:
 *		Convert from a processor to a port.
 *		Produces a naked send right which may be invalid.
 *		Processors are not reference counted, so nothing to release.
 *	Conditions:
 *		Nothing locked.
 */

ipc_port_t
convert_processor_to_port(
	processor_t		processor)
{
	ipc_port_t port = processor->processor_self;

	if (port != IP_NULL)
		port = ipc_port_make_send(port);
	return port;
}

/*
 *	Routine:	convert_pset_to_port
 *	Purpose:
 *		Convert from a pset to a port.
 *		Produces a naked send right which may be invalid.
 *		Processor sets are not reference counted, so nothing to release.
 *	Conditions:
 *		Nothing locked.
 */

ipc_port_t
convert_pset_to_port(
	processor_set_t		pset)
{
	ipc_port_t port = pset->pset_self;

	if (port != IP_NULL)
		port = ipc_port_make_send(port);

	return port;
}

/*
 *	Routine:	convert_pset_name_to_port
 *	Purpose:
 *		Convert from a pset to a port.
 *		Produces a naked send right which may be invalid.
 *		Processor sets are not reference counted, so nothing to release.
 *	Conditions:
 *		Nothing locked.
 */

ipc_port_t
convert_pset_name_to_port(
	processor_set_name_t		pset)
{
	ipc_port_t port = pset->pset_name_self;

	if (port != IP_NULL)
		port = ipc_port_make_send(port);

	return port;
}

/*
 *	Routine:	convert_port_to_host_security
 *	Purpose:
 *		Convert from a port to a host security.
 *		Doesn't consume the port ref; the port produced may be null.
 *	Conditions:
 *		Nothing locked.
 */

host_t
convert_port_to_host_security(
	ipc_port_t port)
{
	host_t host = HOST_NULL;

	if (IP_VALID(port)) {
		ip_lock(port);
		if (ip_active(port) &&
		    (ip_kotype(port) == IKOT_HOST_SECURITY))
			host = (host_t) port->ip_kobject;
		ip_unlock(port);
	}

	return host;
}

/*
 *	Routine:	host_set_exception_ports [kernel call]
 *	Purpose:
 *			Sets the host exception port, flavor and
 *			behavior for the exception types specified by the mask.
 *			There will be one send right per exception per valid
 *			port.
 *	Conditions:
 *		Nothing locked.  If successful, consumes
 *		the supplied send right.
 *	Returns:
 *		KERN_SUCCESS		Changed the special port.
 *		KERN_INVALID_ARGUMENT	The host_priv is not valid,
 *					Illegal mask bit set.
 *					Illegal exception behavior
 */
kern_return_t
host_set_exception_ports(
	host_priv_t			host_priv,
	exception_mask_t		exception_mask,
	ipc_port_t			new_port,
	exception_behavior_t		new_behavior,
	thread_state_flavor_t		new_flavor)
{
	int	i;
	ipc_port_t	old_port[EXC_TYPES_COUNT];

	if (host_priv == HOST_PRIV_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (exception_mask & ~EXC_MASK_VALID) {
		return KERN_INVALID_ARGUMENT;
	}

	if (IP_VALID(new_port)) {
		switch (new_behavior & ~MACH_EXCEPTION_CODES) {
		case EXCEPTION_DEFAULT:
		case EXCEPTION_STATE:
		case EXCEPTION_STATE_IDENTITY:
			break;
		default:
			return KERN_INVALID_ARGUMENT;
		}
	}

	/*
	 * Check the validity of the thread_state_flavor by calling the
	 * VALID_THREAD_STATE_FLAVOR architecture dependent macro defined in
	 * osfmk/mach/ARCHITECTURE/thread_status.h
	 */
	if (new_flavor != 0 && !VALID_THREAD_STATE_FLAVOR(new_flavor))
		return (KERN_INVALID_ARGUMENT);

#if CONFIG_MACF
	if (mac_task_check_set_host_exception_ports(current_task(), exception_mask) != 0)
		return KERN_NO_ACCESS;
#endif

	assert(host_priv == &realhost);

	host_lock(host_priv);

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
#if CONFIG_MACF
		if (host_priv->exc_actions[i].label == NULL) {
			// Lazy initialization (see ipc_port_init).
			mac_exc_action_label_init(host_priv->exc_actions + i);
		}
#endif

		if ((exception_mask & (1 << i))
#if CONFIG_MACF
			&& mac_exc_action_label_update(current_task(), host_priv->exc_actions + i) == 0
#endif
			) {
			old_port[i] = host_priv->exc_actions[i].port;

			host_priv->exc_actions[i].port =
				ipc_port_copy_send(new_port);
			host_priv->exc_actions[i].behavior = new_behavior;
			host_priv->exc_actions[i].flavor = new_flavor;
		} else {
			old_port[i] = IP_NULL;
		}
	}/* for */

	/*
	 * Consume send rights without any lock held.
	 */
	host_unlock(host_priv);
	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++)
		if (IP_VALID(old_port[i]))
			ipc_port_release_send(old_port[i]);
	if (IP_VALID(new_port))		 /* consume send right */
		ipc_port_release_send(new_port);

        return KERN_SUCCESS;
}

/*
 *	Routine:	host_get_exception_ports [kernel call]
 *	Purpose:
 *		Clones a send right for each of the host's exception
 *		ports specified in the mask and returns the behaviour
 *		and flavor of said port.
 *
 *		Returns upto [in} CountCnt elements.
 *
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Extracted a send right.
 *		KERN_INVALID_ARGUMENT	Invalid host_priv specified,
 *					Invalid special port,
 *					Illegal mask bit set.
 *		KERN_FAILURE		The thread is dead.
 */
kern_return_t
host_get_exception_ports(
	host_priv_t			host_priv,
	exception_mask_t                exception_mask,
	exception_mask_array_t		masks,
	mach_msg_type_number_t		* CountCnt,
	exception_port_array_t		ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors		)
{
	unsigned int	i, j, count;

	if (host_priv == HOST_PRIV_NULL)
		return KERN_INVALID_ARGUMENT;

	if (exception_mask & ~EXC_MASK_VALID) {
		return KERN_INVALID_ARGUMENT;
	}

	assert (host_priv == &realhost);

	host_lock(host_priv);

	count = 0;

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
#if CONFIG_MACF
		if (host_priv->exc_actions[i].label == NULL) {
			// Lazy initialization (see ipc_port_init).
			mac_exc_action_label_init(host_priv->exc_actions + i);
		}
#endif

		if (exception_mask & (1 << i)) {
			for (j = 0; j < count; j++) {
/*
 *				search for an identical entry, if found
 *				set corresponding mask for this exception.
 */
				if (host_priv->exc_actions[i].port == ports[j] &&
					host_priv->exc_actions[i].behavior == behaviors[j]
				  && host_priv->exc_actions[i].flavor == flavors[j])
				{
					masks[j] |= (1 << i);
					break;
				}
			}/* for */
			if (j == count) {
				masks[j] = (1 << i);
				ports[j] =
				  ipc_port_copy_send(host_priv->exc_actions[i].port);
				behaviors[j] = host_priv->exc_actions[i].behavior;
				flavors[j] = host_priv->exc_actions[i].flavor;
				count++;
				if (count > *CountCnt) {
					break;
				}
			}
		}
	}/* for */
	host_unlock(host_priv);

	*CountCnt = count;
	return KERN_SUCCESS;
}

kern_return_t
host_swap_exception_ports(
	host_priv_t			host_priv,
	exception_mask_t		exception_mask,
	ipc_port_t			new_port,
	exception_behavior_t		new_behavior,
	thread_state_flavor_t		new_flavor,
	exception_mask_array_t		masks,
	mach_msg_type_number_t		* CountCnt,
	exception_port_array_t		ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors		)
{
	unsigned int	i,
			j,
			count;
	ipc_port_t	old_port[EXC_TYPES_COUNT];

	if (host_priv == HOST_PRIV_NULL)
		return KERN_INVALID_ARGUMENT;

	if (exception_mask & ~EXC_MASK_VALID) {
		return KERN_INVALID_ARGUMENT;
	}

	if (IP_VALID(new_port)) {
		switch (new_behavior) {
		case EXCEPTION_DEFAULT:
		case EXCEPTION_STATE:
		case EXCEPTION_STATE_IDENTITY:
			break;
		default:
			return KERN_INVALID_ARGUMENT;
		}
	}

	if (new_flavor != 0 && !VALID_THREAD_STATE_FLAVOR(new_flavor))
		return (KERN_INVALID_ARGUMENT);

#if CONFIG_MACF
	if (mac_task_check_set_host_exception_ports(current_task(), exception_mask) != 0)
		return KERN_NO_ACCESS;
#endif /* CONFIG_MACF */

	host_lock(host_priv);

	assert(EXC_TYPES_COUNT > FIRST_EXCEPTION);
	for (count=0, i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT && count < *CountCnt; i++) {
#if CONFIG_MACF
		if (host_priv->exc_actions[i].label == NULL) {
			// Lazy initialization (see ipc_port_init).
			mac_exc_action_label_init(host_priv->exc_actions + i);
		}
#endif

		if ((exception_mask & (1 << i))
#if CONFIG_MACF
			&& mac_exc_action_label_update(current_task(), host_priv->exc_actions + i) == 0
#endif
			) {
			for (j = 0; j < count; j++) {
/*
 *				search for an identical entry, if found
 *				set corresponding mask for this exception.
 */
				if (host_priv->exc_actions[i].port == ports[j] &&
				  host_priv->exc_actions[i].behavior == behaviors[j]
				  && host_priv->exc_actions[i].flavor == flavors[j])
				{
					masks[j] |= (1 << i);
					break;
				}
			}/* for */
			if (j == count) {
				masks[j] = (1 << i);
				ports[j] =
				ipc_port_copy_send(host_priv->exc_actions[i].port);
				behaviors[j] = host_priv->exc_actions[i].behavior;
				flavors[j] = host_priv->exc_actions[i].flavor;
				count++;
			}
			old_port[i] = host_priv->exc_actions[i].port;
			host_priv->exc_actions[i].port =
				ipc_port_copy_send(new_port);
			host_priv->exc_actions[i].behavior = new_behavior;
			host_priv->exc_actions[i].flavor = new_flavor;
		} else
			old_port[i] = IP_NULL;
	}/* for */
	host_unlock(host_priv);

	/*
	 * Consume send rights without any lock held.
	 */
	while (--i >= FIRST_EXCEPTION) {
		if (IP_VALID(old_port[i]))
			ipc_port_release_send(old_port[i]);
	}

	if (IP_VALID(new_port))		 /* consume send right */
		ipc_port_release_send(new_port);
	*CountCnt = count;

	return KERN_SUCCESS;
}
