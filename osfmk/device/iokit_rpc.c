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

#include <machine/machparam.h>		/* spl definitions */

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
#include <IOKit/IOTypes.h>

#define EXTERN
#define MIGEXTERN

/*
 * Functions in iokit:IOUserClient.cpp
 */

extern void iokit_add_reference( io_object_t obj );
extern void iokit_add_connect_reference( io_object_t obj );

extern ipc_port_t iokit_port_for_object( io_object_t obj,
			ipc_kobject_type_t type );

extern kern_return_t iokit_client_died( io_object_t obj,
                        ipc_port_t port, ipc_kobject_type_t type, mach_port_mscount_t * mscount );

extern kern_return_t
iokit_client_memory_for_type(
	io_object_t	connect,
	unsigned int	type,
	unsigned int *	flags,
	vm_address_t *	address,
	vm_size_t    *	size );


extern ppnum_t IOGetLastPageNumber(void);

/*
 * Functions imported by iokit:IOUserClient.cpp
 */

extern ipc_port_t iokit_alloc_object_port( io_object_t obj,
			ipc_kobject_type_t type );

extern kern_return_t iokit_destroy_object_port( ipc_port_t port );

extern mach_port_name_t iokit_make_send_right( task_t task,
				io_object_t obj, ipc_kobject_type_t type );

extern kern_return_t iokit_mod_send_right( task_t task, mach_port_name_t name, mach_port_delta_t delta );

extern io_object_t iokit_lookup_connect_ref(io_object_t clientRef, ipc_space_t task);

extern io_object_t iokit_lookup_connect_ref_current_task(io_object_t clientRef);

extern void iokit_retain_port( ipc_port_t port );
extern void iokit_release_port( ipc_port_t port );
extern void iokit_release_port_send( ipc_port_t port );

extern void iokit_lock_port(ipc_port_t port);
extern void iokit_unlock_port(ipc_port_t port);

extern kern_return_t iokit_switch_object_port( ipc_port_t port, io_object_t obj, ipc_kobject_type_t type );

/*
 * Functions imported by iokit:IOMemoryDescriptor.cpp
 */

extern kern_return_t IOMapPages(vm_map_t map, mach_vm_address_t va, mach_vm_address_t pa,
                                 mach_vm_size_t length, unsigned int mapFlags);

extern kern_return_t IOUnmapPages(vm_map_t map, mach_vm_address_t va, mach_vm_size_t length);

extern kern_return_t IOProtectCacheMode(vm_map_t map, mach_vm_address_t va,
					mach_vm_size_t length, unsigned int options);

extern unsigned int IODefaultCacheBits(addr64_t pa);

/*
 * Lookup a device by its port.
 * Doesn't consume the naked send right; produces a device reference.
 */
MIGEXTERN io_object_t
iokit_lookup_object_port(
	ipc_port_t	port)
{
	io_object_t	obj;

	if (!IP_VALID(port))
	    return (NULL);

	iokit_lock_port(port);
	if (ip_active(port) && (ip_kotype(port) == IKOT_IOKIT_OBJECT)) {
	    obj = (io_object_t) port->ip_kobject;
	    iokit_add_reference( obj );
	}
	else
	    obj = NULL;

	iokit_unlock_port(port);

	return( obj );
}

MIGEXTERN io_object_t
iokit_lookup_connect_port(
	ipc_port_t	port)
{
	io_object_t	obj;

	if (!IP_VALID(port))
	    return (NULL);

	iokit_lock_port(port);
	if (ip_active(port) && (ip_kotype(port) == IKOT_IOKIT_CONNECT)) {
	    obj = (io_object_t) port->ip_kobject;
	    iokit_add_connect_reference( obj );
	}
	else
	    obj = NULL;

	iokit_unlock_port(port);

	return( obj );
}

EXTERN io_object_t
iokit_lookup_connect_ref(io_object_t connectRef, ipc_space_t space)
{
	io_object_t obj = NULL;

	if (connectRef && MACH_PORT_VALID(CAST_MACH_PORT_TO_NAME(connectRef))) {
		ipc_port_t port;
		kern_return_t kr;

		kr = ipc_object_translate(space, CAST_MACH_PORT_TO_NAME(connectRef), MACH_PORT_RIGHT_SEND, (ipc_object_t *)&port);

		if (kr == KERN_SUCCESS) {
			assert(IP_VALID(port));

			ip_reference(port);
			ip_unlock(port);

			iokit_lock_port(port);
			if (ip_active(port) && (ip_kotype(port) == IKOT_IOKIT_CONNECT)) {
				obj = (io_object_t) port->ip_kobject;
				iokit_add_connect_reference(obj);
			}
			iokit_unlock_port(port);

			ip_release(port);
		}
	}

	return obj;
}

EXTERN io_object_t
iokit_lookup_connect_ref_current_task(io_object_t connectRef)
{
	return iokit_lookup_connect_ref(connectRef, current_space());
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
MIGEXTERN ipc_port_t
iokit_make_object_port(
	io_object_t	obj )
{
    ipc_port_t	port;
    ipc_port_t	sendPort;

    if( obj == NULL)
        return IP_NULL;

    port = iokit_port_for_object( obj, IKOT_IOKIT_OBJECT );
    if( port) {
	sendPort = ipc_port_make_send( port);
	iokit_release_port( port );
    } else
	sendPort = IP_NULL;

    iokit_remove_reference( obj );

    return( sendPort);
}

MIGEXTERN ipc_port_t
iokit_make_connect_port(
	io_object_t	obj )
{
    ipc_port_t	port;
    ipc_port_t	sendPort;

    if( obj == NULL)
        return IP_NULL;

    port = iokit_port_for_object( obj, IKOT_IOKIT_CONNECT );
    if( port) {
	sendPort = ipc_port_make_send( port);
	iokit_release_port( port );
    } else
	sendPort = IP_NULL;

    iokit_remove_reference( obj );

    return( sendPort);
}

int gIOKitPortCount;

EXTERN ipc_port_t
iokit_alloc_object_port( io_object_t obj, ipc_kobject_type_t type )
{
    ipc_port_t		notify;
    ipc_port_t		port;

    do {

	/* Allocate port, keeping a reference for it. */
        port = ipc_port_alloc_kernel();
        if( port == IP_NULL)
            continue;

        /* set kobject & type */
//	iokit_add_reference( obj );
	ipc_kobject_set( port, (ipc_kobject_t) obj, type);

        /* Request no-senders notifications on the port. */
        ip_lock( port);
        notify = ipc_port_make_sonce_locked( port);
        ipc_port_nsrequest( port, 1, notify, &notify);
	/* port unlocked */
        assert( notify == IP_NULL);
	gIOKitPortCount++;

    } while( FALSE);

    return( port );
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

    return( KERN_SUCCESS);
}

EXTERN kern_return_t
iokit_switch_object_port( ipc_port_t port, io_object_t obj, ipc_kobject_type_t type )
{
    iokit_lock_port(port);
    ipc_kobject_set( port, (ipc_kobject_t) obj, type);
    iokit_unlock_port(port);

    return( KERN_SUCCESS);
}

EXTERN mach_port_name_t
iokit_make_send_right( task_t task, io_object_t obj, ipc_kobject_type_t type )
{
    ipc_port_t		port;
    ipc_port_t		sendPort;
    mach_port_name_t	name = 0;

    if( obj == NULL)
        return MACH_PORT_NULL;

    port = iokit_port_for_object( obj, type );
    if( port) {
	sendPort = ipc_port_make_send( port);
	iokit_release_port( port );
    } else
	sendPort = IP_NULL;

    if (IP_VALID( sendPort )) {
    	kern_return_t	kr;
    	kr = ipc_object_copyout( task->itk_space, (ipc_object_t) sendPort,
				MACH_MSG_TYPE_PORT_SEND, TRUE, &name);
	if ( kr != KERN_SUCCESS) {
	    ipc_port_release_send( sendPort );
	    name = MACH_PORT_NULL;
	}
    } else if ( sendPort == IP_NULL)
        name = MACH_PORT_NULL;
    else if ( sendPort == IP_DEAD)
    	name = MACH_PORT_DEAD;

    iokit_remove_reference( obj );

    return( name );
}

EXTERN kern_return_t
iokit_mod_send_right( task_t task, mach_port_name_t name, mach_port_delta_t delta )
{
    return (mach_port_mod_refs( task->itk_space, name, MACH_PORT_RIGHT_SEND, delta ));
}

/*
 * Handle the No-More_Senders notification generated from a device port destroy.
 * Since there are no longer any tasks which hold a send right to this device
 * port a NMS notification has been generated. 
 */

static void
iokit_no_senders( mach_no_senders_notification_t * notification )
{
    ipc_port_t		port;
    io_object_t		obj = NULL;
    ipc_kobject_type_t	type = IKOT_NONE;
    ipc_port_t		notify;

    port = (ipc_port_t) notification->not_header.msgh_remote_port;

    // convert a port to io_object_t.
    if( IP_VALID(port)) {
        iokit_lock_port(port);
        if( ip_active(port)) {
            obj = (io_object_t) port->ip_kobject;
	    type = ip_kotype( port );
            if( (IKOT_IOKIT_OBJECT  == type)
	     || (IKOT_IOKIT_CONNECT == type))
                iokit_add_reference( obj );
            else
                obj = NULL;
	}
        iokit_unlock_port(port);

        if( obj ) {

	    mach_port_mscount_t mscount = notification->not_count;

            if( KERN_SUCCESS != iokit_client_died( obj, port, type, &mscount ))
	    {
		/* Re-request no-senders notifications on the port (if still active) */
		ip_lock(port);
		if (ip_active(port)) {
			notify = ipc_port_make_sonce_locked(port);
			ipc_port_nsrequest( port, mscount + 1, notify, &notify);
			/* port unlocked */
			if ( notify != IP_NULL)
				ipc_port_release_sonce(notify);
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
unsigned int IODefaultCacheBits(addr64_t pa)
{
	return(pmap_cache_attributes((ppnum_t)(pa >> PAGE_SHIFT)));
}

kern_return_t IOMapPages(vm_map_t map, mach_vm_address_t va, mach_vm_address_t pa,
			mach_vm_size_t length, unsigned int options)
{
    vm_prot_t	 prot;
    unsigned int flags;
    ppnum_t	 pagenum;
    pmap_t 	 pmap = map->pmap;

    prot = (options & kIOMapReadOnly)
		? VM_PROT_READ : (VM_PROT_READ|VM_PROT_WRITE);

    pagenum = (ppnum_t)atop_64(pa);

    switch(options & kIOMapCacheMask ) {			/* What cache mode do we need? */

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
    }

    pmap_set_cache_attributes(pagenum, flags);

    vm_map_set_cache_attr(map, (vm_map_offset_t)va);


    // Set up a block mapped area
    return pmap_map_block(pmap, va, pagenum, (uint32_t) atop_64(round_page_64(length)), prot, 0, 0);
}

kern_return_t IOUnmapPages(vm_map_t map, mach_vm_address_t va, mach_vm_size_t length)
{
    pmap_t	pmap = map->pmap;

    pmap_remove(pmap, trunc_page_64(va), round_page_64(va + length));

    return( KERN_SUCCESS );
}

kern_return_t IOProtectCacheMode(vm_map_t __unused map, mach_vm_address_t __unused va,
					mach_vm_size_t __unused length, unsigned int __unused options)
{
    mach_vm_size_t off;
    vm_prot_t	   prot;
    unsigned int   flags;
    pmap_t 	   pmap = map->pmap;
    pmap_flush_context	pmap_flush_context_storage;
    boolean_t		delayed_pmap_flush = FALSE;

    prot = (options & kIOMapReadOnly)
		? VM_PROT_READ : (VM_PROT_READ|VM_PROT_WRITE);

    switch (options & kIOMapCacheMask)
    {
	// what cache mode do we need?
	case kIOMapDefaultCache:
	default:
	    return (KERN_INVALID_ARGUMENT);

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
    }

    pmap_flush_context_init(&pmap_flush_context_storage);
    delayed_pmap_flush = FALSE;

    //  enter each page's physical address in the target map
    for (off = 0; off < length; off += page_size)
    {
	ppnum_t ppnum = pmap_find_phys(pmap, va + off);
	if (ppnum) {
		pmap_enter_options(pmap, va + off, ppnum, prot, VM_PROT_NONE, flags, TRUE, 
				   PMAP_OPTIONS_NOFLUSH, (void *)&pmap_flush_context_storage);
		delayed_pmap_flush = TRUE;
	}
    }
    if (delayed_pmap_flush == TRUE)
	    pmap_flush(&pmap_flush_context_storage);

    return (KERN_SUCCESS);
}

ppnum_t IOGetLastPageNumber(void)
{
#if __i386__ || __x86_64__
	ppnum_t	 lastPage, highest = 0;
	unsigned int idx;

	for (idx = 0; idx < pmap_memory_region_count; idx++)
	{
		lastPage = pmap_memory_regions[idx].end - 1;
		if (lastPage > highest)
			highest = lastPage;
	}
	return (highest);
#elif __arm__ || __arm64__
	return 0;
#else
#error unknown arch
#endif
}


void IOGetTime( mach_timespec_t * clock_time);
void IOGetTime( mach_timespec_t * clock_time)
{
	clock_sec_t sec;
	clock_nsec_t nsec;
	clock_get_system_nanotime(&sec, &nsec);
	clock_time->tv_sec = (typeof(clock_time->tv_sec))sec;
	clock_time->tv_nsec = nsec;
}

