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
#include <mach_kdb.h>
#include <zone_debug.h>
#include <mach_kdb.h>

#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/mig_errors.h>
#include <mach/port.h>
#include <mach/vm_param.h>
#include <mach/notify.h>
#include <mach/mach_host_server.h>
#include <mach/mach_types.h>

#include <machine/machparam.h>		/* spl definitions */

#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>

#include <kern/clock.h>
#include <kern/spl.h>
#include <kern/ast.h>
#include <kern/counters.h>
#include <kern/queue.h>
#include <kern/zalloc.h>
#include <kern/thread.h>
#include <kern/thread_swap.h>
#include <kern/task.h>
#include <kern/sched_prim.h>
#include <kern/misc_protos.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>

#include <device/device_types.h>
#include <device/device_port.h>
#include <device/device_server.h>

#include <sys/ioctl.h>

#include <machine/machparam.h>

#ifdef __ppc__
#include <ppc/mappings.h>
#include <ppc/pmap_internals.h>
#endif
#include <IOKit/IOTypes.h>

#define EXTERN
#define MIGEXTERN

/*
 * Functions in iokit:IOUserClient.cpp
 */

extern void iokit_add_reference( io_object_t obj );

extern void iokit_remove_reference( io_object_t obj );

extern ipc_port_t iokit_port_for_object( io_object_t obj,
			ipc_kobject_type_t type );

extern kern_return_t iokit_client_died( io_object_t obj,
                        ipc_port_t port, ipc_kobject_type_t type );

extern kern_return_t
iokit_client_memory_for_type(
	io_object_t	connect,
	unsigned int	type,
	unsigned int *	flags,
	vm_address_t *	address,
	vm_size_t    *	size );

/*
 * Lookup a device by its port.
 * Doesn't consume the naked send right; produces a device reference.
 */
MIGEXTERN io_object_t
iokit_lookup_object_port(
	ipc_port_t	port)
{
	register io_object_t	obj;

	if (!IP_VALID(port))
	    return (NULL);

	ip_lock(port);
	if (ip_active(port) && (ip_kotype(port) == IKOT_IOKIT_OBJECT)) {
	    obj = (io_object_t) port->ip_kobject;
	    iokit_add_reference( obj );
	}
	else
	    obj = NULL;

	ip_unlock(port);

	return( obj );
}

MIGEXTERN io_object_t
iokit_lookup_connect_port(
	ipc_port_t	port)
{
	register io_object_t	obj;

	if (!IP_VALID(port))
	    return (NULL);

	ip_lock(port);
	if (ip_active(port) && (ip_kotype(port) == IKOT_IOKIT_CONNECT)) {
	    obj = (io_object_t) port->ip_kobject;
	    iokit_add_reference( obj );
	}
	else
	    obj = NULL;

	ip_unlock(port);

	return( obj );
}

EXTERN io_object_t
iokit_lookup_connect_ref(io_object_t connectRef, ipc_space_t space)
{
	io_object_t obj = NULL;

	if (connectRef && MACH_PORT_VALID((mach_port_name_t)connectRef)) {
		ipc_port_t port;
		kern_return_t kr;

		kr = ipc_object_translate(space, (mach_port_name_t)connectRef, MACH_PORT_RIGHT_SEND, (ipc_object_t *)&port);

		if (kr == KERN_SUCCESS) {
            assert(IP_VALID(port));
            
            if (ip_active(port) && (ip_kotype(port) == IKOT_IOKIT_CONNECT)) {
                obj = (io_object_t) port->ip_kobject;
                iokit_add_reference(obj);
            }
            
            ip_unlock(port);
		}
	}

	return obj;
}

EXTERN io_object_t
iokit_lookup_connect_ref_current_task(io_object_t connectRef)
{
	return iokit_lookup_connect_ref(connectRef, current_space());
}

/*
 * Get the port for a device.
 * Consumes a device reference; produces a naked send right.
 */
MIGEXTERN ipc_port_t
iokit_make_object_port(
	io_object_t	obj )
{
    register ipc_port_t	port;

    if( obj == NULL)
        return IP_NULL;

    port = iokit_port_for_object( obj, IKOT_IOKIT_OBJECT );
    if( port)
	port = ipc_port_make_send( port);

    iokit_remove_reference( obj );

    return( port);
}

MIGEXTERN ipc_port_t
iokit_make_connect_port(
	io_object_t	obj )
{
    register ipc_port_t	port;

    if( obj == NULL)
        return IP_NULL;

    port = iokit_port_for_object( obj, IKOT_IOKIT_CONNECT );
    if( port)
        port = ipc_port_make_send( port);

    iokit_remove_reference( obj );

    return( port);
}


EXTERN ipc_port_t
iokit_alloc_object_port( io_object_t obj, ipc_kobject_type_t type );

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
        notify = ipc_port_make_sonce( port);
        ip_lock( port);
        ipc_port_nsrequest( port, 1, notify, &notify);
        assert( notify == IP_NULL);
	gIOKitPortCount++;

    } while( FALSE);

    return( port );
}


EXTERN kern_return_t
iokit_destroy_object_port( ipc_port_t port )
{
    ipc_kobject_set( port, IKO_NULL, IKOT_NONE);

//    iokit_remove_reference( obj );

    ipc_port_dealloc_kernel( port);
    gIOKitPortCount--;

    return( KERN_SUCCESS);
}

EXTERN mach_port_name_t
iokit_make_send_right( task_t task, io_object_t obj, ipc_kobject_type_t type )
{
    kern_return_t	kr;
    ipc_port_t		port;
    mach_port_name_t	name;

    if( obj == NULL)
        return MACH_PORT_NULL;

    port = iokit_port_for_object( obj, type );
    if( port)
        port = ipc_port_make_send( port);
    if( port == IP_NULL)
        return MACH_PORT_NULL;

    kr = ipc_object_copyout( task->itk_space, (ipc_object_t) port,
				MACH_MSG_TYPE_PORT_SEND, TRUE, &name);

    if( kr != KERN_SUCCESS)
	name = MACH_PORT_NULL;

    iokit_remove_reference( obj );

    return( name );
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
    ipc_kobject_type_t	type;

    port = (ipc_port_t) notification->not_header.msgh_remote_port;

    // convert a port to io_object_t.
    if( IP_VALID(port)) {
        ip_lock(port);
        if( ip_active(port)) {
            obj = (io_object_t) port->ip_kobject;
	    type = ip_kotype( port );
            if( (IKOT_IOKIT_OBJECT  == type)
	     || (IKOT_IOKIT_CONNECT == type))
                iokit_add_reference( obj );
            else
                obj = NULL;
	}
        ip_unlock(port);

        if( obj ) {
            (void) iokit_client_died( obj, port, type );
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
            printf("iokit_notify: strange notification %ld\n", msg->msgh_id);
            return FALSE;
    }
}

kern_return_t IOMapPages(vm_map_t map, vm_offset_t va, vm_offset_t pa,
			vm_size_t length, unsigned int options)
{
    vm_size_t	off;
    vm_prot_t	prot;
    int			memattr;
    struct phys_entry *pp;
    pmap_t 		pmap = map->pmap;

    prot = (options & kIOMapReadOnly)
		? VM_PROT_READ : (VM_PROT_READ|VM_PROT_WRITE);

#if __ppc__

	switch(options & kIOMapCacheMask ) {			/* What cache mode do we need? */

		case kIOMapDefaultCache:
		default:
			if(pp = pmap_find_physentry(pa)) {		/* Find physical address */
				memattr = ((pp->pte1 & 0x00000078) >> 3);	/* Use physical attributes as default */
			}
			else {									/* If no physical, just hard code attributes */
				memattr = PTE_WIMG_UNCACHED_COHERENT_GUARDED;
			}
			break;
	
		case kIOMapInhibitCache:
			memattr = PTE_WIMG_UNCACHED_COHERENT_GUARDED;
			break;
	
		case kIOMapWriteThruCache:
			memattr = PTE_WIMG_WT_CACHED_COHERENT_GUARDED;
			break;

		case kIOMapCopybackCache:
			memattr = PTE_WIMG_CB_CACHED_COHERENT;
			break;
	}

	pmap_map_block(pmap, va, pa, length, prot, memattr, 0);	/* Set up a block mapped area */
	
#else
// 	enter each page's physical address in the target map
	for (off = 0; off < length; off += page_size) {		/* Loop for the whole length */
	 	pmap_enter(pmap, va + off, pa + off, prot, TRUE);			/* Map it in */
	}
#endif

    return( KERN_SUCCESS );
}

kern_return_t IOUnmapPages(vm_map_t map, vm_offset_t va, vm_size_t length)
{
    pmap_t	pmap = map->pmap;
    vm_size_t	off;
    boolean_t	b;

#if __ppc__
    b = mapping_remove(pmap, va);
#else
    pmap_remove(pmap, va, va + length);
    b = TRUE;
#endif

    return( b ? KERN_SUCCESS : KERN_INVALID_ADDRESS );
}

void IOGetTime( mach_timespec_t * clock_time);
void IOGetTime( mach_timespec_t * clock_time)
{
	*clock_time = clock_get_system_value();
}
