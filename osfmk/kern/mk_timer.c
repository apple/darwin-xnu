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
 * Copyright (c) 2000 Apple Computer, Inc.  All rights reserved.
 *
 * HISTORY
 *
 * 29 June 2000 (debo)
 *  Created.
 */

#include <mach/mach_types.h>
#include <mach/mach_port_server.h>

#include <mach/mk_timer.h>

#include <ipc/ipc_space.h>

#include <kern/mk_timer.h>
#include <kern/thread_call.h>

static zone_t		mk_timer_zone;

static mach_port_qos_t mk_timer_qos = {
	FALSE, TRUE, 0, sizeof (mk_timer_expire_msg_t)
};

static void	mk_timer_expire(
				void			*p0,
				void			*p1);

mach_port_name_t
mk_timer_create(void)
{
	mk_timer_t			timer;
	ipc_space_t			myspace = current_space();
	mach_port_name_t	name = MACH_PORT_NULL;
	ipc_port_t			port;
	kern_return_t		result;

	timer = (mk_timer_t)zalloc(mk_timer_zone);
	if (timer == NULL)
		return (MACH_PORT_NULL);

	result = mach_port_allocate_qos(myspace, MACH_PORT_RIGHT_RECEIVE,
														&mk_timer_qos, &name);
	if (result == KERN_SUCCESS)
		result = ipc_port_translate_receive(myspace, name, &port);

	if (result != KERN_SUCCESS) {
		zfree(mk_timer_zone, (vm_offset_t)timer);

		return (MACH_PORT_NULL);
	}

	simple_lock_init(&timer->lock, ETAP_MISC_TIMER);
	call_entry_setup(&timer->call_entry, mk_timer_expire, timer);
	timer->is_armed = timer->is_dead = FALSE;
	timer->active = 0;

	timer->port = port;
	ipc_kobject_set_atomically(port, (ipc_kobject_t)timer, IKOT_TIMER);

	port->ip_srights++;
	ip_reference(port);
	ip_unlock(port);

	return (name);
}

void
mk_timer_port_destroy(
	ipc_port_t			port)
{
	mk_timer_t			timer = NULL;

	ip_lock(port);
	if (ip_kotype(port) == IKOT_TIMER) {
		timer = (mk_timer_t)port->ip_kobject;
		assert(timer != NULL);
		ipc_kobject_set_atomically(port, IKO_NULL, IKOT_NONE);
		simple_lock(&timer->lock);
		assert(timer->port == port);
	}
	ip_unlock(port);

	if (timer != NULL) {
		if (thread_call_cancel(&timer->call_entry))
			timer->active--;
		timer->is_armed = FALSE;

		timer->is_dead = TRUE;
		if (timer->active == 0) {
			simple_unlock(&timer->lock);
			zfree(mk_timer_zone, (vm_offset_t)timer);

			ipc_port_release_send(port);
			return;
		}

		simple_unlock(&timer->lock);
	}
}

void
mk_timer_initialize(void)
{
	int			s = sizeof (mk_timer_data_t);

	assert(!(mk_timer_zone != NULL));

	mk_timer_zone = zinit(s, (4096 * s), (16 * s), "mk_timer");
}

static void
mk_timer_expire(
	void			*p0,
	void			*p1)
{
	uint64_t			time_of_posting;
	mk_timer_t			timer = p0;
	ipc_port_t			port;

	clock_get_uptime(&time_of_posting);

	simple_lock(&timer->lock);

	if (timer->active > 1) {
		timer->active--;
		simple_unlock(&timer->lock);
		return;
	}

	port = timer->port;
	assert(port != IP_NULL);

	while (		timer->is_armed										&&
				!thread_call_is_delayed(&timer->call_entry, NULL)		) {
		mk_timer_expire_msg_t		msg;

		timer->is_armed = FALSE;

		msg.time_of_arming = timer->time_of_arming;
		msg.armed_time = timer->call_entry.deadline;
		msg.time_of_posting = time_of_posting;

		simple_unlock(&timer->lock);

		msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
		msg.header.msgh_remote_port = port;
		msg.header.msgh_local_port = MACH_PORT_NULL;
		msg.header.msgh_reserved = msg.header.msgh_id = 0;

		(void) mach_msg_send_from_kernel(&msg.header, sizeof (msg));

		simple_lock(&timer->lock);
	}

	if (--timer->active == 0 && timer->is_dead) {
		simple_unlock(&timer->lock);
		zfree(mk_timer_zone, (vm_offset_t)timer);

		ipc_port_release_send(port);
		return;
	}

	simple_unlock(&timer->lock);
}

kern_return_t
mk_timer_destroy(
	mach_port_name_t	name)
{
	ipc_space_t			myspace = current_space();
	ipc_port_t			port;
	kern_return_t		result;

	result = ipc_port_translate_receive(myspace, name, &port);
	if (result != KERN_SUCCESS)
		return (result);

	if (ip_kotype(port) == IKOT_TIMER) {
		ip_unlock(port);
		result = mach_port_destroy(myspace, name);
	}
	else {
		ip_unlock(port);
		result = KERN_INVALID_ARGUMENT;
	}

	return (result);
}

kern_return_t
mk_timer_arm(
	mach_port_name_t	name,
	uint64_t			expire_time)
{
	uint64_t			time_of_arming;
	mk_timer_t			timer;
	ipc_space_t			myspace = current_space();
	ipc_port_t			port;
	kern_return_t		result;

	clock_get_uptime(&time_of_arming);

	result = ipc_port_translate_receive(myspace, name, &port);
	if (result != KERN_SUCCESS)
		return (result);

	if (ip_kotype(port) == IKOT_TIMER) {
		timer = (mk_timer_t)port->ip_kobject;
		assert(timer != NULL);
		simple_lock(&timer->lock);
		assert(timer->port == port);
		ip_unlock(port);

		timer->time_of_arming = time_of_arming;
		timer->is_armed = TRUE;

		if (!thread_call_enter_delayed(&timer->call_entry, expire_time))
			timer->active++;
		simple_unlock(&timer->lock);
	}
	else {
		ip_unlock(port);
		result = KERN_INVALID_ARGUMENT;
	}

	return (result);
}

kern_return_t
mk_timer_cancel(
	mach_port_name_t	name,
	uint64_t			*result_time)
{
	uint64_t			armed_time = 0;
	mk_timer_t			timer;
	ipc_space_t			myspace = current_space();
	ipc_port_t			port;
	kern_return_t		result;

	result = ipc_port_translate_receive(myspace, name, &port);
	if (result != KERN_SUCCESS)
		return (result);

	if (ip_kotype(port) == IKOT_TIMER) {
		timer = (mk_timer_t)port->ip_kobject;
		assert(timer != NULL);
		simple_lock(&timer->lock);
		assert(timer->port == port);
		ip_unlock(port);

		if (timer->is_armed) {
			armed_time = timer->call_entry.deadline;
			if (thread_call_cancel(&timer->call_entry))
				timer->active--;
			timer->is_armed = FALSE;
		}

		simple_unlock(&timer->lock);
	}
	else {
		ip_unlock(port);
		result = KERN_INVALID_ARGUMENT;
	}

	if (result == KERN_SUCCESS)
		if (	result_time	!= NULL										&&
				copyout((void *)&armed_time, (void *)result_time,
								sizeof (armed_time)) != 0					)
			result = KERN_FAILURE;

	return (result);
}
