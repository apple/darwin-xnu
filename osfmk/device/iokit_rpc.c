/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
#include <zone_debug.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/mig_errors.h>
#include <mach/port.h>
#include <mach/vm_param.h>
#include <mach/notify.h>
//#include <mach/mach_host_server.h>
#include <mach/mach_types.h>

#include <machine/machparam.h>          /* spl definitions */

#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>

#include <kern/clock.h>
#include <kern/spl.h>
#include <kern/counters.h>
#include <kern/queue.h>
#include <kern/zalloc.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <kern/sched_prim.h>
#include <kern/misc_protos.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>

#include <device/device_types.h>
#include <device/device_port.h>
#include <device/device_server.h>

#include <machine/machparam.h>

#if defined(__i386__) || defined(__x86_64__)
#include <i386/pmap.h>
#endif
#if defined(__arm__) || defined(__arm64__)
#include <arm/pmap.h>
#endif
#include <IOKit/IOKitServer.h>

#define EXTERN
#define MIGEXTERN

/*
 * Lookup a device by its port.
 * Doesn't consume the naked send right; produces a device reference.
 */
io_object_t
iokit_lookup_io_object(ipc_port_t port, ipc_kobject_type_t type)
{
	io_object_t     obj;

	if (!IP_VALID(port)) {
		return NULL;
	}

	iokit_lock_port(port);
	if (ip_active(port) && (ip_kotype(port) == type)) {
		obj = (io_object_t) port->ip_kobject;
		iokit_add_reference( obj, type );
	} else {
		obj = NULL;
	}

	iokit_unlock_port(port);

	return obj;
}

MIGEXTERN io_object_t
iokit_lookup_object_port(
	ipc_port_t      port)
{
	return iokit_lookup_io_object(port, IKOT_IOKIT_OBJECT);
}

MIGEXTERN io_object_t
iokit_lookup_connect_port(
	ipc_port_t      port)
{
	return iokit_lookup_io_object(port, IKOT_IOKIT_CONNECT);
}

MIGEXTERN io_object_t
iokit_lookup_uext_object_port(
	ipc_port_t      port)
{
	return iokit_lookup_io_object(port, IKOT_UEXT_OBJECT);
}

static io_object_t
iokit_lookup_object_in_space_with_port_name(mach_port_name_t name, ipc_kobject_type_t type, ipc_space_t space)
{
	io_object_t obj = NULL;

	if (name && MACH_PORT_VALID(name)) {
		ipc_port_t port;
		kern_return_t kr;

		kr = ipc_port_translate_send(space, name, &port);

		if (kr == KERN_SUCCESS) {
			assert(IP_VALID(port));
			require_ip_active(port);
			ip_reference(port);
			ip_unlock(port);

			iokit_lock_port(port);
			if (ip_kotype(port) == type) {
				obj = (io_object_t) port->ip_kobject;
				iokit_add_reference(obj, type);
			}
			iokit_unlock_port(port);

			ip_release(port);
		}
	}

	return obj;
}

EXTERN io_object_t
iokit_lookup_object_with_port_name(mach_port_name_t name, ipc_kobject_type_t type, task_t task)
{
	return iokit_lookup_object_in_space_with_port_name(name, type, task->itk_space);
}

EXTERN io_object_t
iokit_lookup_connect_ref_current_task(mach_port_name_t name)
{
	return iokit_lookup_object_in_space_with_port_name(name, IKOT_IOKIT_CONNECT, current_space());
}

EXTERN io_object_t
iokit_lookup_uext_ref_current_task(mach_port_name_t name)
{
	return iokit_lookup_object_in_space_with_port_name(name, IKOT_UEXT_OBJECT, current_space());
}

EXTERN void
iokit_retain_port( ipc_port_t port )
{
	ipc_port_reference( port );
}

EXTERN void
iokit_release_port( ipc_port_t port )
{
	ipc_port_release( port );
}

EXTERN void
iokit_release_port_send( ipc_port_t port )
{
	ipc_port_release_send( port );
}

extern lck_mtx_t iokit_obj_to_port_binding_lock;

EXTERN void
iokit_lock_port( __unused ipc_port_t port )
{
	lck_mtx_lock(&iokit_obj_to_port_binding_lock);
}

EXTERN void
iokit_unlock_port( __unused ipc_port_t port )
{
	lck_mtx_unlock(&iokit_obj_to_port_binding_lock);
}

/*
 * Get the port for a device.
 * Consumes a device reference; produces a naked send right.
 */

static ipc_port_t
iokit_make_port_of_type(io_object_t obj, ipc_kobject_type_t type)
{
	ipc_port_t  port;
	ipc_port_t  sendPort;

	if (obj == NULL) {
		return IP_NULL;
	}

	port = iokit_port_for_object( obj, type );
	if (port) {
		sendPort = ipc_port_make_send( port);
		iokit_release_port( port );
	} else {
		sendPort = IP_NULL;
	}

	iokit_remove_reference( obj );

	return sendPort;
}

MIGEXTERN ipc_port_t
iokit_make_object_port(
	io_object_t     obj )
{
	return iokit_make_port_of_type(obj, IKOT_IOKIT_OBJECT);
}

MIGEXTERN ipc_port_t
iokit_make_connect_port(
	io_object_t     obj )
{
	return iokit_make_port_of_type(obj, IKOT_IOKIT_CONNECT);
}

int gIOKitPortCount;

EXTERN ipc_port_t
iokit_alloc_object_port( io_object_t obj, ipc_kobject_type_t type )
{
	/* Allocate port, keeping a reference for it. */
	gIOKitPortCount++;
	ipc_kobject_alloc_options_t options = IPC_KOBJECT_ALLOC_NSREQUEST;
	if (type == IKOT_IOKIT_CONNECT) {
		options |= IPC_KOBJECT_ALLOC_IMMOVABLE_SEND;
	}
	return ipc_kobject_alloc_port((ipc_kobject_t) obj, type, options);
}

EXTERN kern_return_t
iokit_destroy_object_port( ipc_port_t port )
{
	iokit_lock_port(port);
	ipc_kobject_set( port, IKO_NULL, IKOT_NONE);

//    iokit_remove_reference( obj );
	iokit_unlock_port(port);
	ipc_port_dealloc_kernel( port);
	gIOKitPortCount--;

	return KERN_SUCCESS;
}

EXTERN kern_return_t
iokit_switch_object_port( ipc_port_t port, io_object_t obj, ipc_kobject_type_t type )
{
	iokit_lock_port(port);
	ipc_kobject_set( port, (ipc_kobject_t) obj, type);
	iokit_unlock_port(port);

	return KERN_SUCCESS;
}

EXTERN mach_port_name_t
iokit_make_send_right( task_t task, io_object_t obj, ipc_kobject_type_t type )
{
	ipc_port_t          port;
	ipc_port_t          sendPort;
	mach_port_name_t    name = 0;

	if (obj == NULL) {
		return MACH_PORT_NULL;
	}

	port = iokit_port_for_object( obj, type );
	if (port) {
		sendPort = ipc_port_make_send( port);
		iokit_release_port( port );
	} else {
		sendPort = IP_NULL;
	}

	if (IP_VALID( sendPort )) {
		kern_return_t   kr;
		// Remove once <rdar://problem/45522961> is fixed.
		// We need to make ith_knote NULL as ipc_object_copyout() uses
		// thread-argument-passing and its value should not be garbage
		current_thread()->ith_knote = ITH_KNOTE_NULL;
		kr = ipc_object_copyout( task->itk_space, ip_to_object(sendPort),
		    MACH_MSG_TYPE_PORT_SEND, NULL, NULL, &name);
		if (kr != KERN_SUCCESS) {
			ipc_port_release_send( sendPort );
			name = MACH_PORT_NULL;
		}
	} else if (sendPort == IP_NULL) {
		name = MACH_PORT_NULL;
	} else if (sendPort == IP_DEAD) {
		name = MACH_PORT_DEAD;
	}

	return name;
}

EXTERN kern_return_t
iokit_mod_send_right( task_t task, mach_port_name_t name, mach_port_delta_t delta )
{
	return mach_port_mod_refs( task->itk_space, name, MACH_PORT_RIGHT_SEND, delta );
}

/*
 * Handle the No-More_Senders notification generated from a device port destroy.
 * Since there are no longer any tasks which hold a send right to this device
 * port a NMS notification has been generated.
 */

static void
iokit_no_senders( mach_no_senders_notification_t * notification )
{
	ipc_port_t          port;
	io_object_t         obj = NULL;
	ipc_kobject_type_t  type = IKOT_NONE;
	ipc_port_t          notify;

	port = notification->not_header.msgh_remote_port;

	// convert a port to io_object_t.
	if (IP_VALID(port)) {
		iokit_lock_port(port);
		if (ip_active(port)) {
			obj = (io_object_t) port->ip_kobject;
			type = ip_kotype( port );
			if ((IKOT_IOKIT_OBJECT == type)
			    || (IKOT_IOKIT_CONNECT == type)
			    || (IKOT_IOKIT_IDENT == type)
			    || (IKOT_UEXT_OBJECT == type)) {
				iokit_add_reference( obj, IKOT_IOKIT_OBJECT );
			} else {
				obj = NULL;
			}
		}
		iokit_unlock_port(port);

		if (obj) {
			mach_port_mscount_t mscount = notification->not_count;

			if (KERN_SUCCESS != iokit_client_died( obj, port, type, &mscount )) {
				/* Re-request no-senders notifications on the port (if still active) */
				ip_lock(port);
				if (ip_active(port)) {
					notify = ipc_port_make_sonce_locked(port);
					ipc_port_nsrequest( port, mscount + 1, notify, &notify);
					/* port unlocked */
					if (notify != IP_NULL) {
						ipc_port_release_sonce(notify);
					}
				} else {
					ip_unlock(port);
				}
			}
			iokit_remove_reference( obj );
		}
	}
}


EXTERN
boolean_t
iokit_notify( mach_msg_header_t * msg )
{
	switch (msg->msgh_id) {
	case MACH_NOTIFY_NO_SENDERS:
		iokit_no_senders((mach_no_senders_notification_t *) msg);
		return TRUE;

	case MACH_NOTIFY_PORT_DELETED:
	case MACH_NOTIFY_PORT_DESTROYED:
	case MACH_NOTIFY_SEND_ONCE:
	case MACH_NOTIFY_DEAD_NAME:
	default:
		printf("iokit_notify: strange notification %d\n", msg->msgh_id);
		return FALSE;
	}
}

/* need to create a pmap function to generalize */
unsigned int
IODefaultCacheBits(addr64_t pa)
{
	return pmap_cache_attributes((ppnum_t)(pa >> PAGE_SHIFT));
}

kern_return_t
IOMapPages(vm_map_t map, mach_vm_address_t va, mach_vm_address_t pa,
    mach_vm_size_t length, unsigned int options)
{
	vm_prot_t    prot;
	unsigned int flags;
	ppnum_t      pagenum;
	pmap_t       pmap = map->pmap;

	prot = (options & kIOMapReadOnly)
	    ? VM_PROT_READ : (VM_PROT_READ | VM_PROT_WRITE);

	pagenum = (ppnum_t)atop_64(pa);

	switch (options & kIOMapCacheMask) {                    /* What cache mode do we need? */
	case kIOMapDefaultCache:
	default:
		flags = IODefaultCacheBits(pa);
		break;

	case kIOMapInhibitCache:
		flags = VM_WIMG_IO;
		break;

	case kIOMapWriteThruCache:
		flags = VM_WIMG_WTHRU;
		break;

	case kIOMapWriteCombineCache:
		flags = VM_WIMG_WCOMB;
		break;

	case kIOMapCopybackCache:
		flags = VM_WIMG_COPYBACK;
		break;

	case kIOMapCopybackInnerCache:
		flags = VM_WIMG_INNERWBACK;
		break;

	case kIOMapPostedWrite:
		flags = VM_WIMG_POSTED;
		break;

	case kIOMapRealTimeCache:
		flags = VM_WIMG_RT;
		break;
	}

	pmap_set_cache_attributes(pagenum, flags);

	vm_map_set_cache_attr(map, (vm_map_offset_t)va);


	// Set up a block mapped area
	return pmap_map_block(pmap, va, pagenum, (uint32_t) atop_64(round_page_64(length)), prot, 0, 0);
}

kern_return_t
IOUnmapPages(vm_map_t map, mach_vm_address_t va, mach_vm_size_t length)
{
	pmap_t      pmap = map->pmap;

	pmap_remove(pmap, trunc_page_64(va), round_page_64(va + length));

	return KERN_SUCCESS;
}

kern_return_t
IOProtectCacheMode(vm_map_t __unused map, mach_vm_address_t __unused va,
    mach_vm_size_t __unused length, unsigned int __unused options)
{
	mach_vm_size_t off;
	vm_prot_t      prot;
	unsigned int   flags;
	pmap_t         pmap = map->pmap;
	pmap_flush_context  pmap_flush_context_storage;
	boolean_t           delayed_pmap_flush = FALSE;

	prot = (options & kIOMapReadOnly)
	    ? VM_PROT_READ : (VM_PROT_READ | VM_PROT_WRITE);

	switch (options & kIOMapCacheMask) {
	// what cache mode do we need?
	case kIOMapDefaultCache:
	default:
		return KERN_INVALID_ARGUMENT;

	case kIOMapInhibitCache:
		flags = VM_WIMG_IO;
		break;

	case kIOMapWriteThruCache:
		flags = VM_WIMG_WTHRU;
		break;

	case kIOMapWriteCombineCache:
		flags = VM_WIMG_WCOMB;
		break;

	case kIOMapCopybackCache:
		flags = VM_WIMG_COPYBACK;
		break;

	case kIOMapCopybackInnerCache:
		flags = VM_WIMG_INNERWBACK;
		break;

	case kIOMapPostedWrite:
		flags = VM_WIMG_POSTED;
		break;

	case kIOMapRealTimeCache:
		flags = VM_WIMG_RT;
		break;
	}

	pmap_flush_context_init(&pmap_flush_context_storage);
	delayed_pmap_flush = FALSE;

	//  enter each page's physical address in the target map
	for (off = 0; off < length; off += page_size) {
		ppnum_t ppnum = pmap_find_phys(pmap, va + off);
		if (ppnum) {
			pmap_enter_options(pmap, va + off, ppnum, prot, VM_PROT_NONE, flags, TRUE,
			    PMAP_OPTIONS_NOFLUSH, (void *)&pmap_flush_context_storage);
			delayed_pmap_flush = TRUE;
		}
	}
	if (delayed_pmap_flush == TRUE) {
		pmap_flush(&pmap_flush_context_storage);
	}

	return KERN_SUCCESS;
}

ppnum_t
IOGetLastPageNumber(void)
{
#if __i386__ || __x86_64__
	ppnum_t  lastPage, highest = 0;
	unsigned int idx;

	for (idx = 0; idx < pmap_memory_region_count; idx++) {
		lastPage = pmap_memory_regions[idx].end - 1;
		if (lastPage > highest) {
			highest = lastPage;
		}
	}
	return highest;
#elif __arm__ || __arm64__
	return 0;
#else
#error unknown arch
#endif
}


void IOGetTime( mach_timespec_t * clock_time);
void
IOGetTime( mach_timespec_t * clock_time)
{
	clock_sec_t sec;
	clock_nsec_t nsec;
	clock_get_system_nanotime(&sec, &nsec);
	clock_time->tv_sec = (typeof(clock_time->tv_sec))sec;
	clock_time->tv_nsec = nsec;
}
