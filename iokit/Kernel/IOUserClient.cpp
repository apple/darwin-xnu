/*
 * Copyright (c) 1998-2014 Apple Inc. All rights reserved.
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


#include <libkern/c++/OSKext.h>
#include <IOKit/IOKitServer.h>
#include <IOKit/IOKitKeysPrivate.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOService.h>
#include <IOKit/IORegistryEntry.h>
#include <IOKit/IOCatalogue.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOStatisticsPrivate.h>
#include <IOKit/IOTimeStamp.h>
#include <IOKit/system.h>
#include <libkern/OSDebug.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/codesign.h>

#include <mach/sdt.h>

#if CONFIG_MACF

extern "C" {
#include <security/mac_framework.h>
};
#include <sys/kauth.h>

#define IOMACF_LOG 0

#endif /* CONFIG_MACF */

#include <IOKit/assert.h>

#include "IOServicePrivate.h"
#include "IOKitKernelInternal.h"

#define SCALAR64(x) ((io_user_scalar_t)((unsigned int)x))
#define SCALAR32(x) ((uint32_t )x)
#define ARG32(x)    ((void *)(uintptr_t)SCALAR32(x))
#define REF64(x)    ((io_user_reference_t)((UInt64)(x)))
#define REF32(x)    ((int)(x))

enum
{
    kIOUCAsync0Flags          = 3ULL,
    kIOUCAsync64Flag          = 1ULL,
    kIOUCAsyncErrorLoggedFlag = 2ULL
};

#if IOKITSTATS

#define IOStatisticsRegisterCounter() \
do { \
	reserved->counter = IOStatistics::registerUserClient(this); \
} while (0)

#define IOStatisticsUnregisterCounter() \
do { \
	if (reserved) \
		IOStatistics::unregisterUserClient(reserved->counter); \
} while (0)

#define IOStatisticsClientCall() \
do { \
	IOStatistics::countUserClientCall(client); \
} while (0)

#else

#define IOStatisticsRegisterCounter()
#define IOStatisticsUnregisterCounter()
#define IOStatisticsClientCall()

#endif /* IOKITSTATS */

#if DEVELOPMENT || DEBUG

#define FAKE_STACK_FRAME(a)                                             \
        const void ** __frameptr;                                       \
        const void  * __retaddr;                                        \
        __frameptr = (typeof(__frameptr)) __builtin_frame_address(0);   \
        __retaddr = __frameptr[1];                                      \
        __frameptr[1] = (a);

#define FAKE_STACK_FRAME_END()                                          \
        __frameptr[1] = __retaddr;

#else /* DEVELOPMENT || DEBUG */

#define FAKE_STACK_FRAME(a)
#define FAKE_STACK_FRAME_END()

#endif /* DEVELOPMENT || DEBUG */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// definitions we should get from osfmk

//typedef struct ipc_port * ipc_port_t;
typedef natural_t ipc_kobject_type_t;

#define IKOT_IOKIT_SPARE	27
#define IKOT_IOKIT_CONNECT	29
#define IKOT_IOKIT_OBJECT	30

extern "C" {

extern ipc_port_t iokit_alloc_object_port( io_object_t obj,
			ipc_kobject_type_t type );

extern kern_return_t iokit_destroy_object_port( ipc_port_t port );

extern mach_port_name_t iokit_make_send_right( task_t task,
				io_object_t obj, ipc_kobject_type_t type );

extern kern_return_t iokit_mod_send_right( task_t task, mach_port_name_t name, mach_port_delta_t delta );

extern io_object_t iokit_lookup_connect_ref(io_object_t clientRef, ipc_space_t task);

extern io_object_t iokit_lookup_connect_ref_current_task(io_object_t clientRef);

extern ipc_port_t master_device_port;

extern void iokit_retain_port( ipc_port_t port );
extern void iokit_release_port( ipc_port_t port );
extern void iokit_release_port_send( ipc_port_t port );

extern kern_return_t iokit_switch_object_port( ipc_port_t port, io_object_t obj, ipc_kobject_type_t type );

#include <mach/mach_traps.h>
#include <vm/vm_map.h>

} /* extern "C" */


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// IOMachPort maps OSObjects to ports, avoiding adding an ivar to OSObject.

class IOMachPort : public OSObject
{
    OSDeclareDefaultStructors(IOMachPort)
public:
    OSObject *	object;
    ipc_port_t	port;
    UInt32      mscount;
    UInt8	holdDestroy;

    static IOMachPort * portForObject( OSObject * obj,
				ipc_kobject_type_t type );
    static bool noMoreSendersForObject( OSObject * obj,
				ipc_kobject_type_t type, mach_port_mscount_t * mscount );
    static void releasePortForObject( OSObject * obj,
				ipc_kobject_type_t type );
    static void setHoldDestroy( OSObject * obj, ipc_kobject_type_t type );

    static OSDictionary * dictForType( ipc_kobject_type_t type );

    static mach_port_name_t makeSendRightForTask( task_t task,
				io_object_t obj, ipc_kobject_type_t type );

    virtual void free() APPLE_KEXT_OVERRIDE;
};

#define super OSObject
OSDefineMetaClassAndStructors(IOMachPort, OSObject)

static IOLock *		gIOObjectPortLock;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// not in dictForType() for debugging ease
static OSDictionary *	gIOObjectPorts;
static OSDictionary *	gIOConnectPorts;

OSDictionary * IOMachPort::dictForType( ipc_kobject_type_t type )
{
    OSDictionary **	 	dict;

    if( IKOT_IOKIT_OBJECT == type )
	dict = &gIOObjectPorts;
    else if( IKOT_IOKIT_CONNECT == type )
	dict = &gIOConnectPorts;
    else
	return( 0 );

    if( 0 == *dict)
        *dict = OSDictionary::withCapacity( 1 );

    return( *dict );
}

IOMachPort * IOMachPort::portForObject ( OSObject * obj,
				ipc_kobject_type_t type )
{
    IOMachPort * 	inst = 0;
    OSDictionary *	dict;

    IOTakeLock( gIOObjectPortLock);

    do {

	dict = dictForType( type );
	if( !dict)
	    continue;

        if( (inst = (IOMachPort *)
                dict->getObject( (const OSSymbol *) obj ))) {
	    inst->mscount++;
	    inst->retain();
            continue;
	}

        inst = new IOMachPort;
        if( inst && !inst->init()) {
            inst = 0;
            continue;
	}

        inst->port = iokit_alloc_object_port( obj, type );
        if( inst->port) {
	    // retains obj
            dict->setObject( (const OSSymbol *) obj, inst );
	    inst->mscount++;

        } else {
            inst->release();
            inst = 0;
        }

    } while( false );

    IOUnlock( gIOObjectPortLock);

    return( inst );
}

bool IOMachPort::noMoreSendersForObject( OSObject * obj,
				ipc_kobject_type_t type, mach_port_mscount_t * mscount )
{
    OSDictionary *	dict;
    IOMachPort *	machPort;
    IOUserClient *      uc;
    bool		destroyed = true;

    IOTakeLock( gIOObjectPortLock);

    if( (dict = dictForType( type ))) {
        obj->retain();

	machPort = (IOMachPort *) dict->getObject( (const OSSymbol *) obj );
	if( machPort) {
	    destroyed = (machPort->mscount <= *mscount);
	    if (!destroyed) *mscount = machPort->mscount;
            else
            {
		if ((IKOT_IOKIT_CONNECT == type) && (uc = OSDynamicCast(IOUserClient, obj)))
		{
		    uc->noMoreSenders();
		}
		dict->removeObject( (const OSSymbol *) obj );
	    }
	} 
	obj->release();
    }

    IOUnlock( gIOObjectPortLock);

    return( destroyed );
}

void IOMachPort::releasePortForObject( OSObject * obj,
				ipc_kobject_type_t type )
{
    OSDictionary *	dict;
    IOMachPort *	machPort;

    assert(IKOT_IOKIT_CONNECT != type);

    IOTakeLock( gIOObjectPortLock);

    if( (dict = dictForType( type ))) {
        obj->retain();
	machPort = (IOMachPort *) dict->getObject( (const OSSymbol *) obj );
	if( machPort && !machPort->holdDestroy)
            dict->removeObject( (const OSSymbol *) obj );
        obj->release();
    }

    IOUnlock( gIOObjectPortLock);
}

void IOMachPort::setHoldDestroy( OSObject * obj, ipc_kobject_type_t type )
{
    OSDictionary *	dict;
    IOMachPort * 	machPort;

    IOLockLock( gIOObjectPortLock );

    if( (dict = dictForType( type ))) {
        machPort = (IOMachPort *) dict->getObject( (const OSSymbol *) obj );
        if( machPort)
            machPort->holdDestroy = true;
    }

    IOLockUnlock( gIOObjectPortLock );
}

void IOUserClient::destroyUserReferences( OSObject * obj )
{
    IOMachPort::releasePortForObject( obj, IKOT_IOKIT_OBJECT );

    // panther, 3160200
    // IOMachPort::releasePortForObject( obj, IKOT_IOKIT_CONNECT );

    OSDictionary * dict;

    IOTakeLock( gIOObjectPortLock);
    obj->retain();

    if( (dict = IOMachPort::dictForType( IKOT_IOKIT_CONNECT )))
    {
	IOMachPort * port;
	port = (IOMachPort *) dict->getObject( (const OSSymbol *) obj );
	if (port)
	{
	    IOUserClient * uc;
	    if ((uc = OSDynamicCast(IOUserClient, obj)))
	    {
                uc->noMoreSenders();
                if (uc->mappings)
                {
                    dict->setObject((const OSSymbol *) uc->mappings, port);
                    iokit_switch_object_port(port->port, uc->mappings, IKOT_IOKIT_CONNECT);

                    uc->mappings->release();
                    uc->mappings = 0;
                }
            }
	    dict->removeObject( (const OSSymbol *) obj );
	}
    }
    obj->release();
    IOUnlock( gIOObjectPortLock);
}

mach_port_name_t IOMachPort::makeSendRightForTask( task_t task,
				io_object_t obj, ipc_kobject_type_t type )
{
    return( iokit_make_send_right( task, obj, type ));
}

void IOMachPort::free( void )
{
    if( port)
	iokit_destroy_object_port( port );
    super::free();
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

class IOUserIterator : public OSIterator
{
    OSDeclareDefaultStructors(IOUserIterator)
public:
    OSObject 	* 	userIteratorObject;
    IOLock 	*	lock;

    static IOUserIterator * withIterator(OSIterator * iter);
    virtual bool init( void ) APPLE_KEXT_OVERRIDE;
    virtual void free() APPLE_KEXT_OVERRIDE;

    virtual void reset() APPLE_KEXT_OVERRIDE;
    virtual bool isValid() APPLE_KEXT_OVERRIDE;
    virtual OSObject * getNextObject() APPLE_KEXT_OVERRIDE;
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

class IOUserNotification : public IOUserIterator
{
    OSDeclareDefaultStructors(IOUserNotification)

#define holdNotify	userIteratorObject

public:

    virtual void free() APPLE_KEXT_OVERRIDE;

    virtual void setNotification( IONotifier * obj );

    virtual void reset() APPLE_KEXT_OVERRIDE;
    virtual bool isValid() APPLE_KEXT_OVERRIDE;
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSDefineMetaClassAndStructors( IOUserIterator, OSIterator )

IOUserIterator *
IOUserIterator::withIterator(OSIterator * iter)
{
    IOUserIterator * me;

    if (!iter) return (0);

    me = new IOUserIterator;
    if (me && !me->init())
    {
	me->release();
	me = 0;
    }
    if (!me) return me;
    me->userIteratorObject = iter;

    return (me);
}

bool
IOUserIterator::init( void )
{
    if (!OSObject::init()) return (false);

    lock = IOLockAlloc();
    if( !lock)
        return( false );

    return (true);
}

void
IOUserIterator::free()
{
    if (userIteratorObject) userIteratorObject->release();
    if (lock) IOLockFree(lock);
    OSObject::free();
}

void
IOUserIterator::reset()
{
    IOLockLock(lock);
    assert(OSDynamicCast(OSIterator, userIteratorObject));
    ((OSIterator *)userIteratorObject)->reset();
    IOLockUnlock(lock);
}

bool
IOUserIterator::isValid()
{
    bool ret;

    IOLockLock(lock);
    assert(OSDynamicCast(OSIterator, userIteratorObject));
    ret = ((OSIterator *)userIteratorObject)->isValid();
    IOLockUnlock(lock);

    return (ret);
}

OSObject *
IOUserIterator::getNextObject()
{
    OSObject * ret;

    IOLockLock(lock);
    assert(OSDynamicCast(OSIterator, userIteratorObject));
    ret = ((OSIterator *)userIteratorObject)->getNextObject();
    IOLockUnlock(lock);

    return (ret);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
extern "C" {

// functions called from osfmk/device/iokit_rpc.c

void
iokit_add_reference( io_object_t obj )
{
    if( obj)
	obj->retain();
}

void
iokit_remove_reference( io_object_t obj )
{
    if( obj)
	obj->release();
}

void
iokit_add_connect_reference( io_object_t obj )
{
    IOUserClient * uc;

    if (!obj) return;

    if ((uc = OSDynamicCast(IOUserClient, obj))) OSIncrementAtomic(&uc->__ipc);

    obj->retain();
}

void
iokit_remove_connect_reference( io_object_t obj )
{
    IOUserClient * uc;
    bool           finalize = false;

    if (!obj) return;

    if ((uc = OSDynamicCast(IOUserClient, obj)))
    {
	if (1 == OSDecrementAtomic(&uc->__ipc) && uc->isInactive())
	{
	    IOLockLock(gIOObjectPortLock);
	    if ((finalize = uc->__ipcFinal)) uc->__ipcFinal = false;
	    IOLockUnlock(gIOObjectPortLock);
	}
	if (finalize) uc->scheduleFinalize(true);
    }

    obj->release();
}

bool
IOUserClient::finalizeUserReferences(OSObject * obj)
{
    IOUserClient * uc;
    bool           ok = true;

    if ((uc = OSDynamicCast(IOUserClient, obj)))
    {
	IOLockLock(gIOObjectPortLock);
	if ((uc->__ipcFinal = (0 != uc->__ipc))) ok = false;
	IOLockUnlock(gIOObjectPortLock);
    }
    return (ok);
}

ipc_port_t
iokit_port_for_object( io_object_t obj, ipc_kobject_type_t type )
{
    IOMachPort * machPort;
    ipc_port_t	 port;

    if( (machPort = IOMachPort::portForObject( obj, type ))) {

	port = machPort->port;
	if( port)
	    iokit_retain_port( port );

	machPort->release();

    } else
	port = NULL;

    return( port );
}

kern_return_t
iokit_client_died( io_object_t obj, ipc_port_t /* port */,
			ipc_kobject_type_t type, mach_port_mscount_t * mscount )
{
    IOUserClient *	client;
    IOMemoryMap *	map;
    IOUserNotification * notify;

    if( !IOMachPort::noMoreSendersForObject( obj, type, mscount ))
	return( kIOReturnNotReady );

    if( IKOT_IOKIT_CONNECT == type)
    {
	if( (client = OSDynamicCast( IOUserClient, obj )))
	{
	    IOStatisticsClientCall();
	    client->clientDied();
        }
    }
    else if( IKOT_IOKIT_OBJECT == type)
    {
	if( (map = OSDynamicCast( IOMemoryMap, obj )))
	    map->taskDied();
	else if( (notify = OSDynamicCast( IOUserNotification, obj )))
	    notify->setNotification( 0 );
    }

    return( kIOReturnSuccess );
}

};	/* extern "C" */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

class IOServiceUserNotification : public IOUserNotification
{
    OSDeclareDefaultStructors(IOServiceUserNotification)

    struct PingMsg {
        mach_msg_header_t		msgHdr;
        OSNotificationHeader64		notifyHeader;
    };

    enum { kMaxOutstanding = 1024 };

    PingMsg	*	pingMsg;
    vm_size_t		msgSize;
    OSArray 	*	newSet;
    OSObject	*	lastEntry;
    bool		armed;
    bool                ipcLogged;

public:

    virtual bool init( mach_port_t port, natural_t type,
                       void * reference, vm_size_t referenceSize,
		       bool clientIs64 );
    virtual void free() APPLE_KEXT_OVERRIDE;

    static bool _handler( void * target,
                          void * ref, IOService * newService, IONotifier * notifier );
    virtual bool handler( void * ref, IOService * newService );

    virtual OSObject * getNextObject() APPLE_KEXT_OVERRIDE;
};

class IOServiceMessageUserNotification : public IOUserNotification
{
    OSDeclareDefaultStructors(IOServiceMessageUserNotification)

    struct PingMsg {
        mach_msg_header_t		msgHdr;
	mach_msg_body_t			msgBody;
	mach_msg_port_descriptor_t	ports[1];
        OSNotificationHeader64		notifyHeader __attribute__ ((packed));
    };

    PingMsg *		pingMsg;
    vm_size_t		msgSize;
    uint8_t		clientIs64;
    int			owningPID;
    bool                ipcLogged;

public:

    virtual bool init( mach_port_t port, natural_t type,
		       void * reference, vm_size_t referenceSize,
		       vm_size_t extraSize,
		       bool clientIs64 );

    virtual void free() APPLE_KEXT_OVERRIDE;
    
    static IOReturn _handler( void * target, void * ref,
                              UInt32 messageType, IOService * provider,
                              void * messageArgument, vm_size_t argSize );
    virtual IOReturn handler( void * ref,
                              UInt32 messageType, IOService * provider,
                              void * messageArgument, vm_size_t argSize );

    virtual OSObject * getNextObject() APPLE_KEXT_OVERRIDE;
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOUserIterator
OSDefineMetaClass( IOUserNotification, IOUserIterator )
OSDefineAbstractStructors( IOUserNotification, IOUserIterator )

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void IOUserNotification::free( void )
{
    if (holdNotify)
    {
	assert(OSDynamicCast(IONotifier, holdNotify));
	((IONotifier *)holdNotify)->remove();
	holdNotify = 0;
    }
    // can't be in handler now

    super::free();
}


void IOUserNotification::setNotification( IONotifier * notify )
{
    OSObject * previousNotify;

    IOLockLock( gIOObjectPortLock);

    previousNotify = holdNotify;
    holdNotify = notify;

    IOLockUnlock( gIOObjectPortLock);

    if( previousNotify)
    {
	assert(OSDynamicCast(IONotifier, previousNotify));
	((IONotifier *)previousNotify)->remove();
    }
}

void IOUserNotification::reset()
{
    // ?
}

bool IOUserNotification::isValid()
{
    return( true );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOUserNotification
OSDefineMetaClassAndStructors(IOServiceUserNotification, IOUserNotification)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool IOServiceUserNotification::init( mach_port_t port, natural_t type,
				       void * reference, vm_size_t referenceSize,
				       bool clientIs64 )
{
    if( !super::init())
        return( false );

    newSet = OSArray::withCapacity( 1 );
    if( !newSet)
        return( false );

    if (referenceSize > sizeof(OSAsyncReference64))
        return( false );

    msgSize = sizeof(PingMsg) - sizeof(OSAsyncReference64) + referenceSize;
    pingMsg = (PingMsg *) IOMalloc( msgSize);
    if( !pingMsg)
        return( false );

    bzero( pingMsg, msgSize);

    pingMsg->msgHdr.msgh_remote_port	= port;
    pingMsg->msgHdr.msgh_bits 		= MACH_MSGH_BITS(
                                            MACH_MSG_TYPE_COPY_SEND /*remote*/,
                                            MACH_MSG_TYPE_MAKE_SEND /*local*/);
    pingMsg->msgHdr.msgh_size 		= msgSize;
    pingMsg->msgHdr.msgh_id		= kOSNotificationMessageID;

    pingMsg->notifyHeader.size = 0;
    pingMsg->notifyHeader.type = type;
    bcopy( reference, pingMsg->notifyHeader.reference, referenceSize );

    return( true );
}

void IOServiceUserNotification::free( void )
{
    PingMsg   *	_pingMsg;
    vm_size_t	_msgSize;
    OSArray   *	_newSet;
    OSObject  *	_lastEntry;

    _pingMsg   = pingMsg;
    _msgSize   = msgSize;
    _lastEntry = lastEntry;
    _newSet    = newSet;

    super::free();

    if( _pingMsg && _msgSize) {
		if (_pingMsg->msgHdr.msgh_remote_port) {
			iokit_release_port_send(_pingMsg->msgHdr.msgh_remote_port);
		}
        IOFree(_pingMsg, _msgSize);
	}

    if( _lastEntry)
        _lastEntry->release();

    if( _newSet)
        _newSet->release();
}

bool IOServiceUserNotification::_handler( void * target,
                                    void * ref, IOService * newService, IONotifier * notifier )
{
    return( ((IOServiceUserNotification *) target)->handler( ref, newService ));
}

bool IOServiceUserNotification::handler( void * ref,
                                IOService * newService )
{
    unsigned int	count;
    kern_return_t	kr;
    ipc_port_t		port = NULL;
    bool		sendPing = false;

    IOTakeLock( lock );

    count = newSet->getCount();
    if( count < kMaxOutstanding) {

        newSet->setObject( newService );
        if( (sendPing = (armed && (0 == count))))
            armed = false;
    }

    IOUnlock( lock );

    if( kIOServiceTerminatedNotificationType == pingMsg->notifyHeader.type)
        IOMachPort::setHoldDestroy( newService, IKOT_IOKIT_OBJECT );

    if( sendPing) {
	if( (port = iokit_port_for_object( this, IKOT_IOKIT_OBJECT ) ))
            pingMsg->msgHdr.msgh_local_port = port;
	else
            pingMsg->msgHdr.msgh_local_port = NULL;

        kr = mach_msg_send_from_kernel_with_options( &pingMsg->msgHdr,
						     pingMsg->msgHdr.msgh_size,
						     (MACH_SEND_MSG | MACH_SEND_ALWAYS | MACH_SEND_IMPORTANCE),
						     0);
	if( port)
	    iokit_release_port( port );

        if( (KERN_SUCCESS != kr) && !ipcLogged)
        {
            ipcLogged = true;
            IOLog("%s: mach_msg_send_from_kernel_proper(0x%x)\n", __PRETTY_FUNCTION__, kr );
        }
    }

    return( true );
}

OSObject * IOServiceUserNotification::getNextObject()
{
    unsigned int	count;
    OSObject *		result;
    OSObject *		releaseEntry;

    IOLockLock(lock);

    releaseEntry = lastEntry;
    count = newSet->getCount();
    if( count ) {
        result = newSet->getObject( count - 1 );
        result->retain();
        newSet->removeObject( count - 1);
    } else {
        result = 0;
        armed = true;
    }
    lastEntry = result;

    IOLockUnlock(lock);

    if (releaseEntry) releaseEntry->release();

    return( result );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSDefineMetaClassAndStructors(IOServiceMessageUserNotification, IOUserNotification)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool IOServiceMessageUserNotification::init( mach_port_t port, natural_t type,
				void * reference, vm_size_t referenceSize, vm_size_t extraSize,
				bool client64 )
{
    if( !super::init())
        return( false );

    if (referenceSize > sizeof(OSAsyncReference64))
        return( false );

    clientIs64 = client64;

    owningPID = proc_selfpid();

    extraSize += sizeof(IOServiceInterestContent64);
    msgSize = sizeof(PingMsg) - sizeof(OSAsyncReference64) + referenceSize;
    pingMsg = (PingMsg *) IOMalloc( msgSize);
    if( !pingMsg)
        return( false );

    bzero( pingMsg, msgSize);

    pingMsg->msgHdr.msgh_remote_port	= port;
    pingMsg->msgHdr.msgh_bits 		= MACH_MSGH_BITS_COMPLEX
					|  MACH_MSGH_BITS(
                                            MACH_MSG_TYPE_COPY_SEND /*remote*/,
                                            MACH_MSG_TYPE_MAKE_SEND /*local*/);
    pingMsg->msgHdr.msgh_size 		= msgSize;
    pingMsg->msgHdr.msgh_id		= kOSNotificationMessageID;

    pingMsg->msgBody.msgh_descriptor_count = 1;

    pingMsg->ports[0].name 		= 0;
    pingMsg->ports[0].disposition 	= MACH_MSG_TYPE_MAKE_SEND;
    pingMsg->ports[0].type 		= MACH_MSG_PORT_DESCRIPTOR;

    pingMsg->notifyHeader.size 		= extraSize;
    pingMsg->notifyHeader.type 		= type;
    bcopy( reference, pingMsg->notifyHeader.reference, referenceSize );

    return( true );
}

void IOServiceMessageUserNotification::free( void )
{
    PingMsg *	_pingMsg;
    vm_size_t	_msgSize;

    _pingMsg   = pingMsg;
    _msgSize   = msgSize;

    super::free();

    if( _pingMsg && _msgSize) {
		if (_pingMsg->msgHdr.msgh_remote_port) {
			iokit_release_port_send(_pingMsg->msgHdr.msgh_remote_port);
		}
        IOFree( _pingMsg, _msgSize);
	}
}

IOReturn IOServiceMessageUserNotification::_handler( void * target, void * ref,
                                            UInt32 messageType, IOService * provider,
                                            void * argument, vm_size_t argSize )
{
    return( ((IOServiceMessageUserNotification *) target)->handler(
                                ref, messageType, provider, argument, argSize));
}

IOReturn IOServiceMessageUserNotification::handler( void * ref,
                                    UInt32 messageType, IOService * provider,
                                    void * messageArgument, vm_size_t callerArgSize )
{
    enum 			 { kLocalMsgSize = 0x100 };
    uint64_t                     stackMsg[kLocalMsgSize / sizeof(uint64_t)];
    void *                       allocMsg;
    kern_return_t		 kr;
    vm_size_t  			 argSize;
    vm_size_t  			 thisMsgSize;
    ipc_port_t 			 thisPort, providerPort;
    struct PingMsg *             thisMsg;
    IOServiceInterestContent64 * data;

    if (kIOMessageCopyClientID == messageType)
    {
        *((void **) messageArgument) = OSNumber::withNumber(owningPID, 32);
        return (kIOReturnSuccess);
    }

    if (callerArgSize == 0)
    {
	if (clientIs64) argSize = sizeof(data->messageArgument[0]);
	else            argSize = sizeof(uint32_t);
    }
    else
    {
        argSize = callerArgSize;
        if( argSize > kIOUserNotifyMaxMessageSize)
            argSize = kIOUserNotifyMaxMessageSize;
    }

    // adjust message size for ipc restrictions
    natural_t type;
    type = pingMsg->notifyHeader.type;
    type &= ~(kIOKitNoticationMsgSizeMask << kIOKitNoticationTypeSizeAdjShift);
    type |= ((argSize & kIOKitNoticationMsgSizeMask) << kIOKitNoticationTypeSizeAdjShift);
    argSize = (argSize + kIOKitNoticationMsgSizeMask) & ~kIOKitNoticationMsgSizeMask;

    thisMsgSize = msgSize
		+ sizeof( IOServiceInterestContent64 )
		- sizeof( data->messageArgument)
		+ argSize;

    if (thisMsgSize > sizeof(stackMsg))
    {
	allocMsg = IOMalloc(thisMsgSize);
	if (!allocMsg) return (kIOReturnNoMemory);
	thisMsg = (typeof(thisMsg)) allocMsg;
    }
    else
    {
	allocMsg = 0;
	thisMsg  = (typeof(thisMsg)) stackMsg;
    }

    bcopy(pingMsg, thisMsg, msgSize);
    thisMsg->notifyHeader.type = type;
    data = (IOServiceInterestContent64 *) (((uint8_t *) thisMsg) + msgSize);
	// == pingMsg->notifyHeader.content;
    data->messageType = messageType;

    if (callerArgSize == 0)
    {
	data->messageArgument[0] = (io_user_reference_t) messageArgument;
	if (!clientIs64)
	{
	    data->messageArgument[0] |= (data->messageArgument[0] << 32);
	}
    }
    else
    {
        bcopy( messageArgument, data->messageArgument, callerArgSize );
        bzero((void *)(((uintptr_t) &data->messageArgument[0]) + callerArgSize), argSize - callerArgSize);
    }

    thisMsg->notifyHeader.type = type;
    thisMsg->msgHdr.msgh_size  = thisMsgSize;

    providerPort = iokit_port_for_object( provider, IKOT_IOKIT_OBJECT );
    thisMsg->ports[0].name = providerPort;
    thisPort = iokit_port_for_object( this, IKOT_IOKIT_OBJECT );
    thisMsg->msgHdr.msgh_local_port = thisPort;

    kr = mach_msg_send_from_kernel_with_options( &thisMsg->msgHdr,
						 thisMsg->msgHdr.msgh_size,
						 (MACH_SEND_MSG | MACH_SEND_ALWAYS | MACH_SEND_IMPORTANCE),
						 0);
    if( thisPort)
	iokit_release_port( thisPort );
    if( providerPort)
	iokit_release_port( providerPort );

    if (allocMsg)
        IOFree(allocMsg, thisMsgSize);

    if((KERN_SUCCESS != kr) && !ipcLogged)
    {
        ipcLogged = true;
        IOLog("%s: mach_msg_send_from_kernel_proper (0x%x)\n", __PRETTY_FUNCTION__, kr );
    }

    return( kIOReturnSuccess );
}

OSObject * IOServiceMessageUserNotification::getNextObject()
{
    return( 0 );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOService
OSDefineMetaClassAndAbstractStructors( IOUserClient, IOService )

IOLock       * gIOUserClientOwnersLock;

void IOUserClient::initialize( void )
{
    gIOObjectPortLock       = IOLockAlloc();
    gIOUserClientOwnersLock = IOLockAlloc();
    assert(gIOObjectPortLock && gIOUserClientOwnersLock);
}

void IOUserClient::setAsyncReference(OSAsyncReference asyncRef,
                                     mach_port_t wakePort,
                                     void *callback, void *refcon)
{
    asyncRef[kIOAsyncReservedIndex]      = ((uintptr_t) wakePort) 
					 | (kIOUCAsync0Flags & asyncRef[kIOAsyncReservedIndex]);
    asyncRef[kIOAsyncCalloutFuncIndex]   = (uintptr_t) callback;
    asyncRef[kIOAsyncCalloutRefconIndex] = (uintptr_t) refcon;
}

void IOUserClient::setAsyncReference64(OSAsyncReference64 asyncRef,
					mach_port_t wakePort,
					mach_vm_address_t callback, io_user_reference_t refcon)
{
    asyncRef[kIOAsyncReservedIndex]      = ((io_user_reference_t) wakePort)
					 | (kIOUCAsync0Flags & asyncRef[kIOAsyncReservedIndex]);
    asyncRef[kIOAsyncCalloutFuncIndex]   = (io_user_reference_t) callback;
    asyncRef[kIOAsyncCalloutRefconIndex] = refcon;
}

void IOUserClient::setAsyncReference64(OSAsyncReference64 asyncRef,
					mach_port_t wakePort,
					mach_vm_address_t callback, io_user_reference_t refcon, task_t task)
{
    setAsyncReference64(asyncRef, wakePort, callback, refcon);
    if (vm_map_is_64bit(get_task_map(task))) {
            asyncRef[kIOAsyncReservedIndex] |= kIOUCAsync64Flag;
    }
}

static OSDictionary * CopyConsoleUser(UInt32 uid)
{
	OSArray * array;
	OSDictionary * user = 0; 

	if ((array = OSDynamicCast(OSArray,
	    IORegistryEntry::getRegistryRoot()->copyProperty(gIOConsoleUsersKey))))
	{
	    for (unsigned int idx = 0;
		    (user = OSDynamicCast(OSDictionary, array->getObject(idx)));
		    idx++) {
            OSNumber * num;
            
            if ((num = OSDynamicCast(OSNumber, user->getObject(gIOConsoleSessionUIDKey)))
              && (uid == num->unsigned32BitValue())) {
                user->retain();
                break;
            }
	    }
	    array->release();
	}
    return user;
}

static OSDictionary * CopyUserOnConsole(void)
{
    OSArray * array;
    OSDictionary * user = 0; 
    
    if ((array = OSDynamicCast(OSArray,
	IORegistryEntry::getRegistryRoot()->copyProperty(gIOConsoleUsersKey))))
    {
	for (unsigned int idx = 0;
		(user = OSDynamicCast(OSDictionary, array->getObject(idx)));
		idx++)
	{
	    if (kOSBooleanTrue == user->getObject(gIOConsoleSessionOnConsoleKey))
	    {
		user->retain();
		break;
	    }
	}
	array->release();
    }
    return (user);
}

IOReturn IOUserClient::clientHasAuthorization( task_t task,
                                               IOService * service )
{
    proc_t p;
    
    p = (proc_t) get_bsdtask_info(task);
    if (p)
    {
        uint64_t authorizationID;

        authorizationID = proc_uniqueid(p);
        if (authorizationID)
        {
            if (service->getAuthorizationID() == authorizationID)
            {
                return (kIOReturnSuccess);
            }
        }
    }

    return (kIOReturnNotPermitted);
}

IOReturn IOUserClient::clientHasPrivilege( void * securityToken,
                                            const char * privilegeName )
{
    kern_return_t           kr;
    security_token_t        token;
    mach_msg_type_number_t  count;
    task_t                  task;
    OSDictionary *          user;
    bool                    secureConsole;


    if (!strncmp(privilegeName, kIOClientPrivilegeForeground, 
                sizeof(kIOClientPrivilegeForeground)))
    {
	if (task_is_gpu_denied(current_task()))
		return (kIOReturnNotPrivileged);
	else
		return (kIOReturnSuccess);
    }

    if (!strncmp(privilegeName, kIOClientPrivilegeConsoleSession,
                                sizeof(kIOClientPrivilegeConsoleSession)))
    {
	kauth_cred_t cred;
	proc_t       p;

        task = (task_t) securityToken;
	if (!task)
	    task = current_task();
	p = (proc_t) get_bsdtask_info(task);
	kr = kIOReturnNotPrivileged;

	if (p && (cred = kauth_cred_proc_ref(p)))
	{
	    user = CopyUserOnConsole();
	    if (user)
	    {
		OSNumber * num;
		if ((num = OSDynamicCast(OSNumber, user->getObject(gIOConsoleSessionAuditIDKey)))
		  && (cred->cr_audit.as_aia_p->ai_asid == (au_asid_t) num->unsigned32BitValue()))
		{
		    kr = kIOReturnSuccess;
		}
		user->release();
	    }
	    kauth_cred_unref(&cred);
	}
	return (kr);
    }

    if ((secureConsole = !strncmp(privilegeName, kIOClientPrivilegeSecureConsoleProcess,
            sizeof(kIOClientPrivilegeSecureConsoleProcess))))
        task = (task_t)((IOUCProcessToken *)securityToken)->token;
    else
        task = (task_t)securityToken;

    count = TASK_SECURITY_TOKEN_COUNT;
    kr = task_info( task, TASK_SECURITY_TOKEN, (task_info_t) &token, &count );

    if (KERN_SUCCESS != kr)
    {}
    else if (!strncmp(privilegeName, kIOClientPrivilegeAdministrator, 
                sizeof(kIOClientPrivilegeAdministrator))) {
        if (0 != token.val[0])
            kr = kIOReturnNotPrivileged;
    } else if (!strncmp(privilegeName, kIOClientPrivilegeLocalUser,
                sizeof(kIOClientPrivilegeLocalUser))) {
        user = CopyConsoleUser(token.val[0]);
        if ( user )
            user->release();
        else
            kr = kIOReturnNotPrivileged;            
    } else if (secureConsole || !strncmp(privilegeName, kIOClientPrivilegeConsoleUser,
                                    sizeof(kIOClientPrivilegeConsoleUser))) {
        user = CopyConsoleUser(token.val[0]);
        if ( user ) {
            if (user->getObject(gIOConsoleSessionOnConsoleKey) != kOSBooleanTrue)
                kr = kIOReturnNotPrivileged;
            else if ( secureConsole ) {
                OSNumber * pid = OSDynamicCast(OSNumber, user->getObject(gIOConsoleSessionSecureInputPIDKey));
                if ( pid && pid->unsigned32BitValue() != ((IOUCProcessToken *)securityToken)->pid)
                    kr = kIOReturnNotPrivileged;
            }
            user->release();
        }
        else 
            kr = kIOReturnNotPrivileged;
    } else
        kr = kIOReturnUnsupported;

    return (kr);
}

OSObject * IOUserClient::copyClientEntitlement( task_t task,
                                                const char * entitlement )
{
#define	MAX_ENTITLEMENTS_LEN	(128 * 1024)

	proc_t p = NULL;
	pid_t pid = 0;
	char procname[MAXCOMLEN + 1] = "";
	size_t len = 0;
	void *entitlements_blob = NULL;
	char *entitlements_data = NULL;
	OSObject *entitlements_obj = NULL;
	OSDictionary *entitlements = NULL;
	OSString *errorString = NULL;
	OSObject *value = NULL;

	p = (proc_t)get_bsdtask_info(task);
	if (p == NULL)
		goto fail;
	pid = proc_pid(p);
	proc_name(pid, procname, (int)sizeof(procname));

	if (cs_entitlements_blob_get(p, &entitlements_blob, &len) != 0)
		goto fail;

	if (len <= offsetof(CS_GenericBlob, data))
		goto fail;

	/*
	 * Per <rdar://problem/11593877>, enforce a limit on the amount of XML
	 * we'll try to parse in the kernel.
	 */
	len -= offsetof(CS_GenericBlob, data);
	if (len > MAX_ENTITLEMENTS_LEN) {
		IOLog("failed to parse entitlements for %s[%u]: %lu bytes of entitlements exceeds maximum of %u\n", procname, pid, len, MAX_ENTITLEMENTS_LEN);
		goto fail;
	}

	/*
	 * OSUnserializeXML() expects a nul-terminated string, but that isn't
	 * what is stored in the entitlements blob.  Copy the string and
	 * terminate it.
	 */
	entitlements_data = (char *)IOMalloc(len + 1);
	if (entitlements_data == NULL)
		goto fail;
	memcpy(entitlements_data, ((CS_GenericBlob *)entitlements_blob)->data, len);
	entitlements_data[len] = '\0';

	entitlements_obj = OSUnserializeXML(entitlements_data, len + 1, &errorString);
	if (errorString != NULL) {
		IOLog("failed to parse entitlements for %s[%u]: %s\n", procname, pid, errorString->getCStringNoCopy());
		goto fail;
	}
	if (entitlements_obj == NULL)
		goto fail;

	entitlements = OSDynamicCast(OSDictionary, entitlements_obj);
	if (entitlements == NULL)
		goto fail;

	/* Fetch the entitlement value from the dictionary. */
	value = entitlements->getObject(entitlement);
	if (value != NULL)
		value->retain();

fail:
	if (entitlements_data != NULL)
		IOFree(entitlements_data, len + 1);
	if (entitlements_obj != NULL)
		entitlements_obj->release();
	if (errorString != NULL)
		errorString->release();
	return value;
}

bool IOUserClient::init()
{
	if (getPropertyTable() || super::init())
		return reserve();
	
	return false;
}

bool IOUserClient::init(OSDictionary * dictionary)
{
	if (getPropertyTable() || super::init(dictionary))
		return reserve();
	
	return false;
}

bool IOUserClient::initWithTask(task_t owningTask,
                                void * securityID,
                                UInt32 type )
{	
	if (getPropertyTable() || super::init())
		return reserve();
	
	return false;
}

bool IOUserClient::initWithTask(task_t owningTask,
                                void * securityID,
                                UInt32 type,
                                OSDictionary * properties )
{
    bool ok;

    ok = super::init( properties );
    ok &= initWithTask( owningTask, securityID, type );

    return( ok );
}

bool IOUserClient::reserve()
{		
    if(!reserved) {
	reserved = IONew(ExpansionData, 1);
	if (!reserved) {
	    return false;
	}
    }
    setTerminateDefer(NULL, true);
    IOStatisticsRegisterCounter();
    
    return true;
}

struct IOUserClientOwner
{
    task_t         task;
    queue_chain_t  taskLink;
    IOUserClient * uc;
    queue_chain_t  ucLink;
};

IOReturn
IOUserClient::registerOwner(task_t task)
{
    IOUserClientOwner * owner;
    IOReturn            ret;
    bool                newOwner;

    IOLockLock(gIOUserClientOwnersLock);

    newOwner = true;
    ret = kIOReturnSuccess;

    if (!owners.next) queue_init(&owners);
    else
    {
        queue_iterate(&owners, owner, IOUserClientOwner *, ucLink)
        {
            if (task != owner->task) continue;
            newOwner = false;
            break;
        }
    }
    if (newOwner)
    {
        owner = IONew(IOUserClientOwner, 1);
        if (!newOwner) ret = kIOReturnNoMemory;
        else
        {
            owner->task = task;
            owner->uc   = this;
            queue_enter_first(&owners, owner, IOUserClientOwner *, ucLink);
            queue_enter_first(task_io_user_clients(task), owner, IOUserClientOwner *, taskLink);
        }
    }

    IOLockUnlock(gIOUserClientOwnersLock);

    return (ret);
}

void
IOUserClient::noMoreSenders(void)
{
    IOUserClientOwner * owner;

    IOLockLock(gIOUserClientOwnersLock);

    if (owners.next)
    {
        while (!queue_empty(&owners))
        {
            owner = (IOUserClientOwner *)(void *) queue_first(&owners);
            queue_remove(task_io_user_clients(owner->task), owner, IOUserClientOwner *, taskLink);
            queue_remove(&owners, owner, IOUserClientOwner *, ucLink);
            IODelete(owner, IOUserClientOwner, 1);
        }
        owners.next = owners.prev = NULL;
    }

    IOLockUnlock(gIOUserClientOwnersLock);
}

extern "C" kern_return_t
iokit_task_terminate(task_t task)
{
    IOUserClientOwner * owner;
    IOUserClient      * dead;
    IOUserClient      * uc;
    queue_head_t      * taskque;

    IOLockLock(gIOUserClientOwnersLock);

    taskque = task_io_user_clients(task);
    dead = NULL;
    while (!queue_empty(taskque))
    {
        owner = (IOUserClientOwner *)(void *) queue_first(taskque);
        uc = owner->uc;
        queue_remove(taskque, owner, IOUserClientOwner *, taskLink);
        queue_remove(&uc->owners, owner, IOUserClientOwner *, ucLink);
        if (queue_empty(&uc->owners))
        {
            uc->retain();
            IOLog("destroying out of band connect for %s\n", uc->getName());
            // now using the uc queue head as a singly linked queue,
            // leaving .next as NULL to mark it empty
            uc->owners.next = NULL;
            uc->owners.prev = (queue_entry_t) dead;
            dead = uc;
        }
        IODelete(owner, IOUserClientOwner, 1);
    }

    IOLockUnlock(gIOUserClientOwnersLock);

    while (dead)
    {
        uc = dead;
        dead = (IOUserClient *)(void *) dead->owners.prev;
        uc->owners.prev = NULL;
        if (uc->sharedInstance || !uc->closed) uc->clientDied();
        uc->release();
    }

    return (KERN_SUCCESS);
}

void IOUserClient::free()
{
    if( mappings) mappings->release();
		
    IOStatisticsUnregisterCounter();

    assert(!owners.next);
    assert(!owners.prev);

    if (reserved) IODelete(reserved, ExpansionData, 1);
		
    super::free();
}

IOReturn IOUserClient::clientDied( void )
{
    IOReturn ret = kIOReturnNotReady;

    if (sharedInstance || OSCompareAndSwap8(0, 1, &closed)) 
    {
	ret = clientClose();
    }

    return (ret);
}

IOReturn IOUserClient::clientClose( void )
{
    return( kIOReturnUnsupported );
}

IOService * IOUserClient::getService( void )
{
    return( 0 );
}

IOReturn IOUserClient::registerNotificationPort(
		mach_port_t 	/* port */,
		UInt32		/* type */,
                UInt32		/* refCon */)
{
    return( kIOReturnUnsupported);
}

IOReturn IOUserClient::registerNotificationPort(
		mach_port_t port,
		UInt32		type,
		io_user_reference_t refCon)
{
    return (registerNotificationPort(port, type, (UInt32) refCon));
}

IOReturn IOUserClient::getNotificationSemaphore( UInt32 notification_type,
                                    semaphore_t * semaphore )
{
    return( kIOReturnUnsupported);
}

IOReturn IOUserClient::connectClient( IOUserClient * /* client */ )
{
    return( kIOReturnUnsupported);
}

IOReturn IOUserClient::clientMemoryForType( UInt32 type,
			        IOOptionBits * options,
				IOMemoryDescriptor ** memory )
{
    return( kIOReturnUnsupported);
}

#if !__LP64__
IOMemoryMap * IOUserClient::mapClientMemory( 
	IOOptionBits		type,
	task_t			task,
	IOOptionBits		mapFlags,
	IOVirtualAddress	atAddress )
{
    return (NULL);
}
#endif

IOMemoryMap * IOUserClient::mapClientMemory64( 
	IOOptionBits		type,
	task_t			task,
	IOOptionBits		mapFlags,
	mach_vm_address_t	atAddress )
{
    IOReturn		err;
    IOOptionBits	options = 0;
    IOMemoryDescriptor * memory;
    IOMemoryMap *	map = 0;

    err = clientMemoryForType( (UInt32) type, &options, &memory );

    if( memory && (kIOReturnSuccess == err)) {

        FAKE_STACK_FRAME(getMetaClass());

        options = (options & ~kIOMapUserOptionsMask)
		| (mapFlags & kIOMapUserOptionsMask);
	map = memory->createMappingInTask( task, atAddress, options );
	memory->release();

        FAKE_STACK_FRAME_END();
    }

    return( map );
}

IOReturn IOUserClient::exportObjectToClient(task_t task,
			OSObject *obj, io_object_t *clientObj)
{
    mach_port_name_t	name;

    name = IOMachPort::makeSendRightForTask( task, obj, IKOT_IOKIT_OBJECT );

    *(mach_port_name_t *)clientObj = name;
    return kIOReturnSuccess;
}

IOExternalMethod * IOUserClient::getExternalMethodForIndex( UInt32 /* index */)
{
    return( 0 );
}

IOExternalAsyncMethod * IOUserClient::getExternalAsyncMethodForIndex( UInt32 /* index */)
{
    return( 0 );
}

IOExternalTrap * IOUserClient::
getExternalTrapForIndex(UInt32 index)
{
	return NULL;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// Suppressing the deprecated-declarations warning. Avoiding the use of deprecated
// functions can break clients of kexts implementing getExternalMethodForIndex()
IOExternalMethod * IOUserClient::
getTargetAndMethodForIndex(IOService **targetP, UInt32 index)
{
    IOExternalMethod *method = getExternalMethodForIndex(index);

    if (method)
        *targetP = (IOService *) method->object;

    return method;
}

IOExternalAsyncMethod * IOUserClient::
getAsyncTargetAndMethodForIndex(IOService ** targetP, UInt32 index)
{
    IOExternalAsyncMethod *method = getExternalAsyncMethodForIndex(index);

    if (method)
        *targetP = (IOService *) method->object;

    return method;
}

IOExternalTrap * IOUserClient::
getTargetAndTrapForIndex(IOService ** targetP, UInt32 index)
{
      IOExternalTrap *trap = getExternalTrapForIndex(index);

      if (trap) {
              *targetP = trap->object;
      }

      return trap;
}
#pragma clang diagnostic pop

IOReturn IOUserClient::releaseAsyncReference64(OSAsyncReference64 reference)
{
    mach_port_t port;
    port = (mach_port_t) (reference[0] & ~kIOUCAsync0Flags);

    if (MACH_PORT_NULL != port)
	iokit_release_port_send(port);

    return (kIOReturnSuccess);
}

IOReturn IOUserClient::releaseNotificationPort(mach_port_t port)
{
    if (MACH_PORT_NULL != port)
	iokit_release_port_send(port);

    return (kIOReturnSuccess);
}

IOReturn IOUserClient::sendAsyncResult(OSAsyncReference reference,
                                       IOReturn result, void *args[], UInt32 numArgs)
{
    OSAsyncReference64  reference64;
    io_user_reference_t args64[kMaxAsyncArgs];
    unsigned int        idx;

    if (numArgs > kMaxAsyncArgs)
        return kIOReturnMessageTooLarge;

    for (idx = 0; idx < kOSAsyncRef64Count; idx++)
	reference64[idx] = REF64(reference[idx]);

    for (idx = 0; idx < numArgs; idx++)
	args64[idx] = REF64(args[idx]);

    return (sendAsyncResult64(reference64, result, args64, numArgs));
}

IOReturn IOUserClient::sendAsyncResult64WithOptions(OSAsyncReference64 reference,
                                        IOReturn result, io_user_reference_t args[], UInt32 numArgs, IOOptionBits options)
{
	return _sendAsyncResult64(reference, result, args, numArgs, options);
}

IOReturn IOUserClient::sendAsyncResult64(OSAsyncReference64 reference,
                                        IOReturn result, io_user_reference_t args[], UInt32 numArgs)
{
        return _sendAsyncResult64(reference, result, args, numArgs, 0);
}

IOReturn IOUserClient::_sendAsyncResult64(OSAsyncReference64 reference,
                                        IOReturn result, io_user_reference_t args[], UInt32 numArgs, IOOptionBits options)
{
    struct ReplyMsg
    {
	mach_msg_header_t msgHdr;
	union
	{
	    struct
	    {
		OSNotificationHeader	 notifyHdr;
		IOAsyncCompletionContent asyncContent;
		uint32_t		 args[kMaxAsyncArgs];
	    } msg32;
	    struct
	    {
		OSNotificationHeader64	 notifyHdr;
		IOAsyncCompletionContent asyncContent;
		io_user_reference_t	 args[kMaxAsyncArgs] __attribute__ ((packed));
	    } msg64;
	} m;
    };
    ReplyMsg      replyMsg;
    mach_port_t	  replyPort;
    kern_return_t kr;

    // If no reply port, do nothing.
    replyPort = (mach_port_t) (reference[0] & ~kIOUCAsync0Flags);
    if (replyPort == MACH_PORT_NULL)
        return kIOReturnSuccess;
    
    if (numArgs > kMaxAsyncArgs)
        return kIOReturnMessageTooLarge;

    bzero(&replyMsg, sizeof(replyMsg));
    replyMsg.msgHdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND /*remote*/,
						0 /*local*/);
    replyMsg.msgHdr.msgh_remote_port = replyPort;
    replyMsg.msgHdr.msgh_local_port  = 0;
    replyMsg.msgHdr.msgh_id          = kOSNotificationMessageID;
    if (kIOUCAsync64Flag & reference[0])
    {
	replyMsg.msgHdr.msgh_size =
	    sizeof(replyMsg.msgHdr) + sizeof(replyMsg.m.msg64) 
	    - (kMaxAsyncArgs - numArgs) * sizeof(io_user_reference_t);
	replyMsg.m.msg64.notifyHdr.size = sizeof(IOAsyncCompletionContent)
					+ numArgs * sizeof(io_user_reference_t);
	replyMsg.m.msg64.notifyHdr.type = kIOAsyncCompletionNotificationType;
	bcopy(reference, replyMsg.m.msg64.notifyHdr.reference, sizeof(OSAsyncReference64));

	replyMsg.m.msg64.asyncContent.result = result;
	if (numArgs)
	    bcopy(args, replyMsg.m.msg64.args, numArgs * sizeof(io_user_reference_t));
    }
    else
    {
	unsigned int idx;

	replyMsg.msgHdr.msgh_size =
	    sizeof(replyMsg.msgHdr) + sizeof(replyMsg.m.msg32)
	    - (kMaxAsyncArgs - numArgs) * sizeof(uint32_t);

	replyMsg.m.msg32.notifyHdr.size = sizeof(IOAsyncCompletionContent)
					+ numArgs * sizeof(uint32_t);
	replyMsg.m.msg32.notifyHdr.type = kIOAsyncCompletionNotificationType;

	for (idx = 0; idx < kOSAsyncRefCount; idx++)
	    replyMsg.m.msg32.notifyHdr.reference[idx] = REF32(reference[idx]);

	replyMsg.m.msg32.asyncContent.result = result;

	for (idx = 0; idx < numArgs; idx++)
	    replyMsg.m.msg32.args[idx] = REF32(args[idx]);
    }

	if ((options & kIOUserNotifyOptionCanDrop) != 0) { 
		kr = mach_msg_send_from_kernel_with_options( &replyMsg.msgHdr,
										 replyMsg.msgHdr.msgh_size, MACH_SEND_TIMEOUT, MACH_MSG_TIMEOUT_NONE);
	} else {
		/* Fail on full queue. */
		kr = mach_msg_send_from_kernel_proper( &replyMsg.msgHdr,
										 replyMsg.msgHdr.msgh_size);
	}
    if ((KERN_SUCCESS != kr) && (MACH_SEND_TIMED_OUT != kr) && !(kIOUCAsyncErrorLoggedFlag & reference[0]))
    {
        reference[0] |= kIOUCAsyncErrorLoggedFlag;
        IOLog("%s: mach_msg_send_from_kernel_proper(0x%x)\n", __PRETTY_FUNCTION__, kr );
    }
    return kr;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

extern "C" {

#define CHECK(cls,obj,out)			\
	cls * out;				\
	if( !(out = OSDynamicCast( cls, obj)))	\
	    return( kIOReturnBadArgument )

#define CHECKLOCKED(cls,obj,out)					\
	IOUserIterator * oIter;						\
	cls * out;							\
	if( !(oIter = OSDynamicCast(IOUserIterator, obj)))		\
	    return (kIOReturnBadArgument);				\
	if( !(out = OSDynamicCast(cls, oIter->userIteratorObject)))	\
	    return (kIOReturnBadArgument)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Create a vm_map_copy_t or kalloc'ed data for memory
// to be copied out. ipc will free after the copyout.

static kern_return_t copyoutkdata( const void * data, vm_size_t len,
                                    io_buf_ptr_t * buf )
{
    kern_return_t	err;
    vm_map_copy_t	copy;

    err = vm_map_copyin( kernel_map, CAST_USER_ADDR_T(data), len,
                    false /* src_destroy */, &copy);

    assert( err == KERN_SUCCESS );
    if( err == KERN_SUCCESS )
        *buf = (char *) copy;

    return( err );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* Routine io_server_version */
kern_return_t is_io_server_version(
	mach_port_t master_port,
	uint64_t *version)
{
    *version = IOKIT_SERVER_VERSION;
    return (kIOReturnSuccess);
}

/* Routine io_object_get_class */
kern_return_t is_io_object_get_class(
    io_object_t object,
    io_name_t className )
{
    const OSMetaClass* my_obj = NULL;
	
    if( !object)
        return( kIOReturnBadArgument );
		
    my_obj = object->getMetaClass();
    if (!my_obj) {
        return (kIOReturnNotFound);
    }

    strlcpy( className, my_obj->getClassName(), sizeof(io_name_t));

    return( kIOReturnSuccess );
}

/* Routine io_object_get_superclass */
kern_return_t is_io_object_get_superclass(
	mach_port_t master_port,
	io_name_t obj_name, 
	io_name_t class_name)
{
	const OSMetaClass* my_obj = NULL;
	const OSMetaClass* superclass = NULL;
	const OSSymbol *my_name = NULL;
	const char *my_cstr = NULL;

	if (!obj_name || !class_name) 
		return (kIOReturnBadArgument);

    if( master_port != master_device_port)
        return( kIOReturnNotPrivileged);

	my_name = OSSymbol::withCString(obj_name);
	
	if (my_name) {
		my_obj = OSMetaClass::getMetaClassWithName(my_name);
		my_name->release();
	}
	if (my_obj) {
		superclass = my_obj->getSuperClass();
	}
	
	if (!superclass)  {
		return( kIOReturnNotFound );
	}

	my_cstr = superclass->getClassName();
		
	if (my_cstr) {
		strlcpy(class_name, my_cstr, sizeof(io_name_t));
		return( kIOReturnSuccess );
	}
	return (kIOReturnNotFound);
}

/* Routine io_object_get_bundle_identifier */
kern_return_t is_io_object_get_bundle_identifier(
	mach_port_t master_port,
	io_name_t obj_name, 
	io_name_t bundle_name)
{
	const OSMetaClass* my_obj = NULL;
	const OSSymbol *my_name = NULL;
	const OSSymbol *identifier = NULL;
	const char *my_cstr = NULL;

	if (!obj_name || !bundle_name) 
		return (kIOReturnBadArgument);

    if( master_port != master_device_port)
        return( kIOReturnNotPrivileged);
	
	my_name = OSSymbol::withCString(obj_name);	
	
	if (my_name) {
		my_obj = OSMetaClass::getMetaClassWithName(my_name);
		my_name->release();
	}

	if (my_obj) {
		identifier = my_obj->getKmodName();
	}
	if (!identifier) {
		return( kIOReturnNotFound );
	}
	
	my_cstr = identifier->getCStringNoCopy();
	if (my_cstr) {
		strlcpy(bundle_name, identifier->getCStringNoCopy(), sizeof(io_name_t));
		return( kIOReturnSuccess );
	}

	return (kIOReturnBadArgument);
}

/* Routine io_object_conforms_to */
kern_return_t is_io_object_conforms_to(
	io_object_t object,
	io_name_t className,
	boolean_t *conforms )
{
    if( !object)
        return( kIOReturnBadArgument );

    *conforms = (0 != object->metaCast( className ));

    return( kIOReturnSuccess );
}

/* Routine io_object_get_retain_count */
kern_return_t is_io_object_get_retain_count(
	io_object_t object,
	uint32_t *retainCount )
{
    if( !object)
        return( kIOReturnBadArgument );

    *retainCount = object->getRetainCount();
    return( kIOReturnSuccess );
}

/* Routine io_iterator_next */
kern_return_t is_io_iterator_next(
	io_object_t iterator,
	io_object_t *object )
{
    IOReturn    ret;
    OSObject *	obj;

    CHECK( OSIterator, iterator, iter );

    obj = iter->getNextObject();
    if( obj) {
	obj->retain();
	*object = obj;
        ret = kIOReturnSuccess;
    } else
        ret = kIOReturnNoDevice;

    return (ret);
}

/* Routine io_iterator_reset */
kern_return_t is_io_iterator_reset(
	io_object_t iterator )
{
    CHECK( OSIterator, iterator, iter );

    iter->reset();

    return( kIOReturnSuccess );
}

/* Routine io_iterator_is_valid */
kern_return_t is_io_iterator_is_valid(
	io_object_t iterator,
	boolean_t *is_valid )
{
    CHECK( OSIterator, iterator, iter );

    *is_valid = iter->isValid();

    return( kIOReturnSuccess );
}


static kern_return_t internal_io_service_match_property_table(
	io_service_t _service,
	const char * matching,
	mach_msg_type_number_t matching_size,
	boolean_t *matches)
{
    CHECK( IOService, _service, service );

    kern_return_t	kr;
    OSObject *		obj;
    OSDictionary *	dict;

    assert(matching_size);
    obj = OSUnserializeXML(matching, matching_size);

    if( (dict = OSDynamicCast( OSDictionary, obj))) {
        *matches = service->passiveMatch( dict );
	kr = kIOReturnSuccess;
    } else
	kr = kIOReturnBadArgument;

    if( obj)
        obj->release();

    return( kr );
}

/* Routine io_service_match_property_table */
kern_return_t is_io_service_match_property_table(
	io_service_t service,
	io_string_t matching,
	boolean_t *matches )
{
    return (kIOReturnUnsupported);
}


/* Routine io_service_match_property_table_ool */
kern_return_t is_io_service_match_property_table_ool(
	io_object_t service,
	io_buf_ptr_t matching,
	mach_msg_type_number_t matchingCnt,
	kern_return_t *result,
	boolean_t *matches )
{
    kern_return_t	  kr;
    vm_offset_t 	  data;
    vm_map_offset_t	  map_data;

    kr = vm_map_copyout( kernel_map, &map_data, (vm_map_copy_t) matching );
    data = CAST_DOWN(vm_offset_t, map_data);

    if( KERN_SUCCESS == kr) {
        // must return success after vm_map_copyout() succeeds
	*result = internal_io_service_match_property_table(service,
		(const char *)data, matchingCnt, matches );
	vm_deallocate( kernel_map, data, matchingCnt );
    }

    return( kr );
}

/* Routine io_service_match_property_table_bin */
kern_return_t is_io_service_match_property_table_bin(
	io_object_t service,
	io_struct_inband_t matching,
	mach_msg_type_number_t matchingCnt,
	boolean_t *matches)
{
    return (internal_io_service_match_property_table(service, matching, matchingCnt, matches));
}

static kern_return_t internal_io_service_get_matching_services(
	mach_port_t master_port,
	const char * matching,
	mach_msg_type_number_t matching_size,
	io_iterator_t *existing )
{
    kern_return_t	kr;
    OSObject *		obj;
    OSDictionary *	dict;

    if( master_port != master_device_port)
        return( kIOReturnNotPrivileged);

    assert(matching_size);
    obj = OSUnserializeXML(matching, matching_size);

    if( (dict = OSDynamicCast( OSDictionary, obj))) {
        *existing = IOUserIterator::withIterator(IOService::getMatchingServices( dict ));
	kr = kIOReturnSuccess;
    } else
	kr = kIOReturnBadArgument;

    if( obj)
        obj->release();

    return( kr );
}

/* Routine io_service_get_matching_services */
kern_return_t is_io_service_get_matching_services(
	mach_port_t master_port,
	io_string_t matching,
	io_iterator_t *existing )
{
    return (kIOReturnUnsupported);
}

/* Routine io_service_get_matching_services_ool */
kern_return_t is_io_service_get_matching_services_ool(
	mach_port_t master_port,
	io_buf_ptr_t matching,
	mach_msg_type_number_t matchingCnt,
	kern_return_t *result,
	io_object_t *existing )
{
    kern_return_t	kr;
    vm_offset_t 	data;
    vm_map_offset_t	map_data;

    kr = vm_map_copyout( kernel_map, &map_data, (vm_map_copy_t) matching );
    data = CAST_DOWN(vm_offset_t, map_data);

    if( KERN_SUCCESS == kr) {
        // must return success after vm_map_copyout() succeeds
        // and mig will copy out objects on success
        *existing = 0;
	*result = internal_io_service_get_matching_services(master_port,
			(const char *) data, matchingCnt, existing);
	vm_deallocate( kernel_map, data, matchingCnt );
    }

    return( kr );
}

/* Routine io_service_get_matching_services_bin */
kern_return_t is_io_service_get_matching_services_bin(
	mach_port_t master_port,
	io_struct_inband_t matching,
	mach_msg_type_number_t matchingCnt,
	io_object_t *existing)
{
    return (internal_io_service_get_matching_services(master_port, matching, matchingCnt, existing));
}


static kern_return_t internal_io_service_get_matching_service(
	mach_port_t master_port,
	const char * matching,
	mach_msg_type_number_t matching_size,
	io_service_t *service )
{
    kern_return_t	kr;
    OSObject *		obj;
    OSDictionary *	dict;

    if( master_port != master_device_port)
        return( kIOReturnNotPrivileged);

    assert(matching_size);
    obj = OSUnserializeXML(matching, matching_size);

    if( (dict = OSDynamicCast( OSDictionary, obj))) {
        *service = IOService::copyMatchingService( dict );
	kr = *service ? kIOReturnSuccess : kIOReturnNotFound;
    } else
	kr = kIOReturnBadArgument;

    if( obj)
        obj->release();

    return( kr );
}

/* Routine io_service_get_matching_service */
kern_return_t is_io_service_get_matching_service(
	mach_port_t master_port,
	io_string_t matching,
	io_service_t *service )
{
    return (kIOReturnUnsupported);
}

/* Routine io_service_get_matching_services_ool */
kern_return_t is_io_service_get_matching_service_ool(
	mach_port_t master_port,
	io_buf_ptr_t matching,
	mach_msg_type_number_t matchingCnt,
	kern_return_t *result,
	io_object_t *service )
{
    kern_return_t	kr;
    vm_offset_t 	data;
    vm_map_offset_t	map_data;

    kr = vm_map_copyout( kernel_map, &map_data, (vm_map_copy_t) matching );
    data = CAST_DOWN(vm_offset_t, map_data);

    if( KERN_SUCCESS == kr) {
        // must return success after vm_map_copyout() succeeds
        // and mig will copy out objects on success
        *service = 0;
	*result = internal_io_service_get_matching_service(master_port,
			(const char *) data, matchingCnt, service );
	vm_deallocate( kernel_map, data, matchingCnt );
    }

    return( kr );
}

/* Routine io_service_get_matching_service_bin */
kern_return_t is_io_service_get_matching_service_bin(
	mach_port_t master_port,
	io_struct_inband_t matching,
	mach_msg_type_number_t matchingCnt,
	io_object_t *service)
{
    return (internal_io_service_get_matching_service(master_port, matching, matchingCnt, service));
}

static kern_return_t internal_io_service_add_notification(
	mach_port_t master_port,
	io_name_t notification_type,
	const char * matching,
	size_t matching_size,
	mach_port_t port,
	void * reference,
	vm_size_t referenceSize,
	bool client64,
	io_object_t * notification )
{
    IOServiceUserNotification *	userNotify = 0;
    IONotifier *		notify = 0;
    const OSSymbol *		sym;
    OSDictionary *		dict;
    IOReturn			err;
    unsigned long int		userMsgType;

    if( master_port != master_device_port)
        return( kIOReturnNotPrivileged);

    do {
        err = kIOReturnNoResources;

        if( !(sym = OSSymbol::withCString( notification_type )))
	    err = kIOReturnNoResources;

	assert(matching_size);
	dict = OSDynamicCast(OSDictionary, OSUnserializeXML(matching, matching_size));
        if (!dict) {
            err = kIOReturnBadArgument;
	    continue;
	}

	if( (sym == gIOPublishNotification)
	 || (sym == gIOFirstPublishNotification))
	    userMsgType = kIOServicePublishNotificationType;
	else if( (sym == gIOMatchedNotification)
	      || (sym == gIOFirstMatchNotification))
	    userMsgType = kIOServiceMatchedNotificationType;
	else if( sym == gIOTerminatedNotification)
	    userMsgType = kIOServiceTerminatedNotificationType;
	else
	    userMsgType = kLastIOKitNotificationType;

        userNotify = new IOServiceUserNotification;

        if( userNotify && !userNotify->init( port, userMsgType,
                                             reference, referenceSize, client64)) {
			iokit_release_port_send(port);
            userNotify->release();
            userNotify = 0;
        }
        if( !userNotify)
	    continue;

        notify = IOService::addMatchingNotification( sym, dict,
                                             &userNotify->_handler, userNotify );
	if( notify) {
            *notification = userNotify;
	    userNotify->setNotification( notify );
	    err = kIOReturnSuccess;
	} else
	    err = kIOReturnUnsupported;

    } while( false );

    if( sym)
	sym->release();
    if( dict)
	dict->release();

    return( err );
}


/* Routine io_service_add_notification */
kern_return_t is_io_service_add_notification(
	mach_port_t master_port,
	io_name_t notification_type,
	io_string_t matching,
	mach_port_t port,
	io_async_ref_t reference,
	mach_msg_type_number_t referenceCnt,
	io_object_t * notification )
{
    return (kIOReturnUnsupported);
}

/* Routine io_service_add_notification_64 */
kern_return_t is_io_service_add_notification_64(
	mach_port_t master_port,
	io_name_t notification_type,
	io_string_t matching,
	mach_port_t wake_port,
	io_async_ref64_t reference,
	mach_msg_type_number_t referenceCnt,
	io_object_t *notification )
{
    return (kIOReturnUnsupported);
}

/* Routine io_service_add_notification_bin */
kern_return_t is_io_service_add_notification_bin
(
	mach_port_t master_port,
	io_name_t notification_type,
	io_struct_inband_t matching,
	mach_msg_type_number_t matchingCnt,
	mach_port_t wake_port,
	io_async_ref_t reference,
	mach_msg_type_number_t referenceCnt,
	io_object_t *notification)
{
    return (internal_io_service_add_notification(master_port, notification_type, 
		matching, matchingCnt, wake_port, &reference[0], sizeof(io_async_ref_t),
		false, notification));
}

/* Routine io_service_add_notification_bin_64 */
kern_return_t is_io_service_add_notification_bin_64
(
	mach_port_t master_port,
	io_name_t notification_type,
	io_struct_inband_t matching,
	mach_msg_type_number_t matchingCnt,
	mach_port_t wake_port,
	io_async_ref64_t reference,
	mach_msg_type_number_t referenceCnt,
	io_object_t *notification)
{
    return (internal_io_service_add_notification(master_port, notification_type, 
		matching, matchingCnt, wake_port, &reference[0], sizeof(io_async_ref64_t),
		true, notification));
}

static kern_return_t internal_io_service_add_notification_ool(
	mach_port_t master_port,
	io_name_t notification_type,
	io_buf_ptr_t matching,
	mach_msg_type_number_t matchingCnt,
	mach_port_t wake_port,
	void * reference,
	vm_size_t referenceSize,
	bool client64,
	kern_return_t *result,
	io_object_t *notification )
{
    kern_return_t	kr;
    vm_offset_t 	data;
    vm_map_offset_t	map_data;

    kr = vm_map_copyout( kernel_map, &map_data, (vm_map_copy_t) matching );
    data = CAST_DOWN(vm_offset_t, map_data);

    if( KERN_SUCCESS == kr) {
        // must return success after vm_map_copyout() succeeds
        // and mig will copy out objects on success
        *notification = 0;
	*result = internal_io_service_add_notification( master_port, notification_type,
			(char *) data, matchingCnt, wake_port, reference, referenceSize, client64, notification );
	vm_deallocate( kernel_map, data, matchingCnt );
    }

    return( kr );
}

/* Routine io_service_add_notification_ool */
kern_return_t is_io_service_add_notification_ool(
	mach_port_t master_port,
	io_name_t notification_type,
	io_buf_ptr_t matching,
	mach_msg_type_number_t matchingCnt,
	mach_port_t wake_port,
	io_async_ref_t reference,
	mach_msg_type_number_t referenceCnt,
	kern_return_t *result,
	io_object_t *notification )
{
    return (internal_io_service_add_notification_ool(master_port, notification_type, 
		matching, matchingCnt, wake_port, &reference[0], sizeof(io_async_ref_t),
		false, result, notification));
}

/* Routine io_service_add_notification_ool_64 */
kern_return_t is_io_service_add_notification_ool_64(
	mach_port_t master_port,
	io_name_t notification_type,
	io_buf_ptr_t matching,
	mach_msg_type_number_t matchingCnt,
	mach_port_t wake_port,
	io_async_ref64_t reference,
	mach_msg_type_number_t referenceCnt,
	kern_return_t *result,
	io_object_t *notification )
{
    return (internal_io_service_add_notification_ool(master_port, notification_type, 
		matching, matchingCnt, wake_port, &reference[0], sizeof(io_async_ref64_t),
		true, result, notification));
}

/* Routine io_service_add_notification_old */
kern_return_t is_io_service_add_notification_old(
	mach_port_t master_port,
	io_name_t notification_type,
	io_string_t matching,
	mach_port_t port,
	// for binary compatibility reasons, this must be natural_t for ILP32
	natural_t ref,
	io_object_t * notification )
{
    return( is_io_service_add_notification( master_port, notification_type,
            matching, port, &ref, 1, notification ));
}


static kern_return_t internal_io_service_add_interest_notification(
        io_object_t _service,
        io_name_t type_of_interest,
        mach_port_t port,
	void * reference,
	vm_size_t referenceSize,
	bool client64,
        io_object_t * notification )
{

    IOServiceMessageUserNotification *	userNotify = 0;
    IONotifier *			notify = 0;
    const OSSymbol *			sym;
    IOReturn				err;

    CHECK( IOService, _service, service );

    err = kIOReturnNoResources;
    if( (sym = OSSymbol::withCString( type_of_interest ))) do {

        userNotify = new IOServiceMessageUserNotification;

        if( userNotify && !userNotify->init( port, kIOServiceMessageNotificationType,
                                             reference, referenceSize,
					     kIOUserNotifyMaxMessageSize,
					     client64 )) {
			iokit_release_port_send(port);
            userNotify->release();
            userNotify = 0;
        }
        if( !userNotify)
            continue;

        notify = service->registerInterest( sym,
                                    &userNotify->_handler, userNotify );
        if( notify) {
            *notification = userNotify;
            userNotify->setNotification( notify );
            err = kIOReturnSuccess;
        } else
            err = kIOReturnUnsupported;

	sym->release();

    } while( false );

    return( err );
}

/* Routine io_service_add_message_notification */
kern_return_t is_io_service_add_interest_notification(
        io_object_t service,
        io_name_t type_of_interest,
        mach_port_t port,
	io_async_ref_t reference,
	mach_msg_type_number_t referenceCnt,
        io_object_t * notification )
{
    return (internal_io_service_add_interest_notification(service, type_of_interest,
		    port, &reference[0], sizeof(io_async_ref_t), false, notification));
}

/* Routine io_service_add_interest_notification_64 */
kern_return_t is_io_service_add_interest_notification_64(
	io_object_t service,
	io_name_t type_of_interest,
	mach_port_t wake_port,
	io_async_ref64_t reference,
	mach_msg_type_number_t referenceCnt,
	io_object_t *notification )
{
    return (internal_io_service_add_interest_notification(service, type_of_interest,
		    wake_port, &reference[0], sizeof(io_async_ref64_t), true, notification));
}


/* Routine io_service_acknowledge_notification */
kern_return_t is_io_service_acknowledge_notification(
	io_object_t _service,
	natural_t notify_ref,
	natural_t response )
{
    CHECK( IOService, _service, service );

    return( service->acknowledgeNotification( (IONotificationRef)(uintptr_t) notify_ref,
                                              (IOOptionBits) response ));
    
}

/* Routine io_connect_get_semaphore */
kern_return_t is_io_connect_get_notification_semaphore(
	io_connect_t connection,
	natural_t notification_type,
	semaphore_t *semaphore )
{
    CHECK( IOUserClient, connection, client );

    IOStatisticsClientCall();
    return( client->getNotificationSemaphore( (UInt32) notification_type,
                                              semaphore ));
}

/* Routine io_registry_get_root_entry */
kern_return_t is_io_registry_get_root_entry(
	mach_port_t master_port,
	io_object_t *root )
{
    IORegistryEntry *	entry;

    if( master_port != master_device_port)
        return( kIOReturnNotPrivileged);

    entry = IORegistryEntry::getRegistryRoot();
    if( entry)
	entry->retain();
    *root = entry;

    return( kIOReturnSuccess );
}

/* Routine io_registry_create_iterator */
kern_return_t is_io_registry_create_iterator(
	mach_port_t master_port,
	io_name_t plane,
	uint32_t options,
	io_object_t *iterator )
{
    if( master_port != master_device_port)
        return( kIOReturnNotPrivileged);

    *iterator = IOUserIterator::withIterator(
	IORegistryIterator::iterateOver(
		IORegistryEntry::getPlane( plane ), options ));

    return( *iterator ? kIOReturnSuccess : kIOReturnBadArgument );
}

/* Routine io_registry_entry_create_iterator */
kern_return_t is_io_registry_entry_create_iterator(
	io_object_t registry_entry,
	io_name_t plane,
	uint32_t options,
	io_object_t *iterator )
{
    CHECK( IORegistryEntry, registry_entry, entry );

    *iterator = IOUserIterator::withIterator(
	IORegistryIterator::iterateOver( entry,
		IORegistryEntry::getPlane( plane ), options ));

    return( *iterator ? kIOReturnSuccess : kIOReturnBadArgument );
}

/* Routine io_registry_iterator_enter */
kern_return_t is_io_registry_iterator_enter_entry(
	io_object_t iterator )
{
    CHECKLOCKED( IORegistryIterator, iterator, iter );

    IOLockLock(oIter->lock);
    iter->enterEntry();
    IOLockUnlock(oIter->lock);

    return( kIOReturnSuccess );
}

/* Routine io_registry_iterator_exit */
kern_return_t is_io_registry_iterator_exit_entry(
	io_object_t iterator )
{
    bool	didIt;

    CHECKLOCKED( IORegistryIterator, iterator, iter );

    IOLockLock(oIter->lock);
    didIt = iter->exitEntry();
    IOLockUnlock(oIter->lock);

    return( didIt ? kIOReturnSuccess : kIOReturnNoDevice );
}

/* Routine io_registry_entry_from_path */
kern_return_t is_io_registry_entry_from_path(
	mach_port_t master_port,
	io_string_t path,
	io_object_t *registry_entry )
{
    IORegistryEntry *	entry;

    if( master_port != master_device_port)
        return( kIOReturnNotPrivileged);

    entry = IORegistryEntry::fromPath( path );

    *registry_entry = entry;

    return( kIOReturnSuccess );
}


/* Routine io_registry_entry_from_path */
kern_return_t is_io_registry_entry_from_path_ool(
	mach_port_t master_port,
	io_string_inband_t path,
	io_buf_ptr_t path_ool,
	mach_msg_type_number_t path_oolCnt,
	kern_return_t *result,
	io_object_t *registry_entry)
{
    IORegistryEntry *	entry;
    vm_map_offset_t	map_data;
    const char * 	cpath;
    IOReturn            res;
    kern_return_t       err;

    if (master_port != master_device_port) return(kIOReturnNotPrivileged);

    map_data = 0;
    entry    = 0;
    res = err = KERN_SUCCESS;
    if (path[0]) cpath = path;
    else
    {
	if (!path_oolCnt)                                      return(kIOReturnBadArgument);
	if (path_oolCnt > (sizeof(io_struct_inband_t) * 1024)) return(kIOReturnMessageTooLarge);

	err = vm_map_copyout(kernel_map, &map_data, (vm_map_copy_t) path_ool);
	if (KERN_SUCCESS == err)
	{
	    // must return success to mig after vm_map_copyout() succeeds, so result is actual
	    cpath = CAST_DOWN(const char *, map_data);
	    if (cpath[path_oolCnt - 1]) res = kIOReturnBadArgument;
	}
    }

    if ((KERN_SUCCESS == err) && (KERN_SUCCESS == res))
    {
	entry = IORegistryEntry::fromPath(cpath);
	res = entry ? kIOReturnSuccess : kIOReturnNotFound;
    }

    if (map_data) vm_deallocate(kernel_map, map_data, path_oolCnt);

    if (KERN_SUCCESS != err) res = err;
    *registry_entry = entry;
    *result = res;

    return (err);
}


/* Routine io_registry_entry_in_plane */
kern_return_t is_io_registry_entry_in_plane(
	io_object_t registry_entry,
	io_name_t plane,
	boolean_t *inPlane )
{
    CHECK( IORegistryEntry, registry_entry, entry );

    *inPlane = entry->inPlane( IORegistryEntry::getPlane( plane ));

    return( kIOReturnSuccess );
}


/* Routine io_registry_entry_get_path */
kern_return_t is_io_registry_entry_get_path(
	io_object_t registry_entry,
	io_name_t plane,
	io_string_t path )
{
    int		length;
    CHECK( IORegistryEntry, registry_entry, entry );

    length = sizeof( io_string_t);
    if( entry->getPath( path, &length, IORegistryEntry::getPlane( plane )))
	return( kIOReturnSuccess );
    else
	return( kIOReturnBadArgument );
}

/* Routine io_registry_entry_get_path */
kern_return_t is_io_registry_entry_get_path_ool(
	io_object_t registry_entry,
	io_name_t plane,
	io_string_inband_t path,
	io_buf_ptr_t *path_ool,
	mach_msg_type_number_t *path_oolCnt)
{
    enum   { kMaxPath = 16384 };
    IOReturn err;
    int      length;
    char   * buf;

    CHECK( IORegistryEntry, registry_entry, entry );

    *path_ool    = NULL;
    *path_oolCnt = 0;
    length = sizeof(io_string_inband_t);
    if (entry->getPath(path, &length, IORegistryEntry::getPlane(plane))) err = kIOReturnSuccess;
    else
    {
	length = kMaxPath;
	buf = IONew(char, length);
	if (!buf) err = kIOReturnNoMemory;
	else if (!entry->getPath(buf, &length, IORegistryEntry::getPlane(plane))) err = kIOReturnError;
	else
	{
	    *path_oolCnt = length;
	    err = copyoutkdata(buf, length, path_ool);
	}
	if (buf) IODelete(buf, char, kMaxPath);
    }

    return (err);
}


/* Routine io_registry_entry_get_name */
kern_return_t is_io_registry_entry_get_name(
	io_object_t registry_entry,
	io_name_t name )
{
    CHECK( IORegistryEntry, registry_entry, entry );

    strncpy( name, entry->getName(), sizeof( io_name_t));

    return( kIOReturnSuccess );
}

/* Routine io_registry_entry_get_name_in_plane */
kern_return_t is_io_registry_entry_get_name_in_plane(
	io_object_t registry_entry,
	io_name_t planeName,
	io_name_t name )
{
    const IORegistryPlane * plane;
    CHECK( IORegistryEntry, registry_entry, entry );

    if( planeName[0])
        plane = IORegistryEntry::getPlane( planeName );
    else
        plane = 0;

    strncpy( name, entry->getName( plane), sizeof( io_name_t));

    return( kIOReturnSuccess );
}

/* Routine io_registry_entry_get_location_in_plane */
kern_return_t is_io_registry_entry_get_location_in_plane(
	io_object_t registry_entry,
	io_name_t planeName,
	io_name_t location )
{
    const IORegistryPlane * plane;
    CHECK( IORegistryEntry, registry_entry, entry );

    if( planeName[0])
        plane = IORegistryEntry::getPlane( planeName );
    else
        plane = 0;

    const char * cstr = entry->getLocation( plane );

    if( cstr) {
        strncpy( location, cstr, sizeof( io_name_t));
        return( kIOReturnSuccess );
    } else
        return( kIOReturnNotFound );
}

/* Routine io_registry_entry_get_registry_entry_id */
kern_return_t is_io_registry_entry_get_registry_entry_id(
	io_object_t registry_entry,
	uint64_t *entry_id )
{
    CHECK( IORegistryEntry, registry_entry, entry );

    *entry_id = entry->getRegistryEntryID();

    return (kIOReturnSuccess);
}

/* Routine io_registry_entry_get_property */
kern_return_t is_io_registry_entry_get_property_bytes(
	io_object_t registry_entry,
	io_name_t property_name,
	io_struct_inband_t buf,
	mach_msg_type_number_t *dataCnt )
{
    OSObject	*	obj;
    OSData 	*	data;
    OSString 	*	str;
    OSBoolean	*	boo;
    OSNumber 	*	off;
    UInt64		offsetBytes;
    unsigned int	len = 0;
    const void *	bytes = 0;
    IOReturn		ret = kIOReturnSuccess;

    CHECK( IORegistryEntry, registry_entry, entry );

#if CONFIG_MACF
    if (0 != mac_iokit_check_get_property(kauth_cred_get(), entry, property_name))
        return kIOReturnNotPermitted;
#endif

    obj = entry->copyProperty(property_name);
    if( !obj)
        return( kIOReturnNoResources );

    // One day OSData will be a common container base class
    // until then...
    if( (data = OSDynamicCast( OSData, obj ))) {
	len = data->getLength();
	bytes = data->getBytesNoCopy();

    } else if( (str = OSDynamicCast( OSString, obj ))) {
	len = str->getLength() + 1;
	bytes = str->getCStringNoCopy();

    } else if( (boo = OSDynamicCast( OSBoolean, obj ))) {
	len = boo->isTrue() ? sizeof("Yes") : sizeof("No");
	bytes = boo->isTrue() ? "Yes" : "No";

    } else if( (off = OSDynamicCast( OSNumber, obj ))) {
	offsetBytes = off->unsigned64BitValue();
	len = off->numberOfBytes();
	bytes = &offsetBytes;
#ifdef __BIG_ENDIAN__
	bytes = (const void *)
		(((UInt32) bytes) + (sizeof( UInt64) - len));
#endif

    } else
	ret = kIOReturnBadArgument;

    if( bytes) {
	if( *dataCnt < len)
	    ret = kIOReturnIPCError;
	else {
            *dataCnt = len;
            bcopy( bytes, buf, len );
	}
    }
    obj->release();

    return( ret );
}


/* Routine io_registry_entry_get_property */
kern_return_t is_io_registry_entry_get_property(
	io_object_t registry_entry,
	io_name_t property_name,
	io_buf_ptr_t *properties,
	mach_msg_type_number_t *propertiesCnt )
{
    kern_return_t	err;
    vm_size_t 		len;
    OSObject *		obj;

    CHECK( IORegistryEntry, registry_entry, entry );

#if CONFIG_MACF
    if (0 != mac_iokit_check_get_property(kauth_cred_get(), entry, property_name))
        return kIOReturnNotPermitted;
#endif

    obj = entry->copyProperty(property_name);
    if( !obj)
        return( kIOReturnNotFound );

    OSSerialize * s = OSSerialize::withCapacity(4096);
    if( !s) {
        obj->release();
	return( kIOReturnNoMemory );
    }

    if( obj->serialize( s )) {
        len = s->getLength();
        *propertiesCnt = len;
        err = copyoutkdata( s->text(), len, properties );

    } else
        err = kIOReturnUnsupported;

    s->release();
    obj->release();

    return( err );
}

/* Routine io_registry_entry_get_property_recursively */
kern_return_t is_io_registry_entry_get_property_recursively(
	io_object_t registry_entry,
	io_name_t plane,
	io_name_t property_name,
        uint32_t options,
	io_buf_ptr_t *properties,
	mach_msg_type_number_t *propertiesCnt )
{
    kern_return_t	err;
    vm_size_t 		len;
    OSObject *		obj;

    CHECK( IORegistryEntry, registry_entry, entry );

#if CONFIG_MACF
    if (0 != mac_iokit_check_get_property(kauth_cred_get(), entry, property_name))
        return kIOReturnNotPermitted;
#endif

    obj = entry->copyProperty( property_name,
                               IORegistryEntry::getPlane( plane ), options );
    if( !obj)
        return( kIOReturnNotFound );

    OSSerialize * s = OSSerialize::withCapacity(4096);
    if( !s) {
        obj->release();
	return( kIOReturnNoMemory );
    }

    if( obj->serialize( s )) {
        len = s->getLength();
        *propertiesCnt = len;
        err = copyoutkdata( s->text(), len, properties );

    } else
        err = kIOReturnUnsupported;

    s->release();
    obj->release();

    return( err );
}

/* Routine io_registry_entry_get_properties */
kern_return_t is_io_registry_entry_get_properties(
	io_object_t registry_entry,
	io_buf_ptr_t *properties,
	mach_msg_type_number_t *propertiesCnt )
{
    return (kIOReturnUnsupported);
}

#if CONFIG_MACF

struct GetPropertiesEditorRef
{
    kauth_cred_t      cred;
    IORegistryEntry * entry;
    OSCollection    * root;
};

static const OSMetaClassBase *
GetPropertiesEditor(void                  * reference,
					OSSerialize           * s, 
					OSCollection          * container, 
					const OSSymbol        * name,
					const OSMetaClassBase * value)
{
    GetPropertiesEditorRef * ref = (typeof(ref)) reference;

    if (!ref->root) ref->root = container;
    if (ref->root == container)
    {
        if (0 != mac_iokit_check_get_property(ref->cred, ref->entry, name->getCStringNoCopy()))
        {
                value = 0;
        }
    }
    if (value) value->retain();
    return (value);
}

#endif /* CONFIG_MACF */

/* Routine io_registry_entry_get_properties */
kern_return_t is_io_registry_entry_get_properties_bin(
	io_object_t registry_entry,
	io_buf_ptr_t *properties,
	mach_msg_type_number_t *propertiesCnt)
{
    kern_return_t	       err = kIOReturnSuccess;
    vm_size_t 		       len;
    OSSerialize          * s;
    OSSerialize::Editor    editor = 0;
    void                 * editRef = 0;

    CHECK(IORegistryEntry, registry_entry, entry);

#if CONFIG_MACF
    GetPropertiesEditorRef ref;
    if (mac_iokit_check_filter_properties(kauth_cred_get(), entry))
    {
    	editor    = &GetPropertiesEditor;
    	editRef   = &ref;
    	ref.cred  = kauth_cred_get();
    	ref.entry = entry;
    	ref.root  = 0;
    }
#endif

    s = OSSerialize::binaryWithCapacity(4096, editor, editRef);
    if (!s) return (kIOReturnNoMemory);

    if (!entry->serializeProperties(s)) err = kIOReturnUnsupported;

    if (kIOReturnSuccess == err)
    {
        len = s->getLength();
        *propertiesCnt = len;
        err = copyoutkdata(s->text(), len, properties);
    }
    s->release();

    return (err);
}

/* Routine io_registry_entry_get_property_bin */
kern_return_t is_io_registry_entry_get_property_bin(
	io_object_t registry_entry,
	io_name_t plane,
	io_name_t property_name,
	uint32_t options,
	io_buf_ptr_t *properties,
	mach_msg_type_number_t *propertiesCnt )
{
    kern_return_t	err;
    vm_size_t 		len;
    OSObject *		obj;
    const OSSymbol *    sym;

    CHECK( IORegistryEntry, registry_entry, entry );

#if CONFIG_MACF
    if (0 != mac_iokit_check_get_property(kauth_cred_get(), entry, property_name))
        return kIOReturnNotPermitted;
#endif

    sym = OSSymbol::withCString(property_name);
    if (!sym) return (kIOReturnNoMemory);

    if (gIORegistryEntryPropertyKeysKey == sym)
    {
        obj = entry->copyPropertyKeys();
    }
    else
    {
        if ((kIORegistryIterateRecursively & options) && plane[0])
        {
            obj = entry->copyProperty(property_name,
                                      IORegistryEntry::getPlane(plane), options );
        }
        else
        {
            obj = entry->copyProperty(property_name);
        }
        if (obj && gIORemoveOnReadProperties->containsObject(sym)) entry->removeProperty(sym);
    }

    sym->release();
    if (!obj) return (kIOReturnNotFound);

    OSSerialize * s = OSSerialize::binaryWithCapacity(4096);
    if( !s) {
        obj->release();
	return( kIOReturnNoMemory );
    }

    if( obj->serialize( s )) {
        len = s->getLength();
        *propertiesCnt = len;
        err = copyoutkdata( s->text(), len, properties );

    } else err = kIOReturnUnsupported; 

    s->release();
    obj->release();

    return( err );
}


/* Routine io_registry_entry_set_properties */
kern_return_t is_io_registry_entry_set_properties
(
	io_object_t registry_entry,
	io_buf_ptr_t properties,
	mach_msg_type_number_t propertiesCnt,
        kern_return_t * result)
{
    OSObject *		obj;
    kern_return_t	err;
    IOReturn		res;
    vm_offset_t 	data;
    vm_map_offset_t	map_data;

    CHECK( IORegistryEntry, registry_entry, entry );

    if( propertiesCnt > sizeof(io_struct_inband_t) * 1024)
        return( kIOReturnMessageTooLarge);

    err = vm_map_copyout( kernel_map, &map_data, (vm_map_copy_t) properties );
    data = CAST_DOWN(vm_offset_t, map_data);

    if( KERN_SUCCESS == err) {

        FAKE_STACK_FRAME(entry->getMetaClass());

        // must return success after vm_map_copyout() succeeds
        obj = OSUnserializeXML( (const char *) data, propertiesCnt );
	vm_deallocate( kernel_map, data, propertiesCnt );

	if (!obj)
	    res = kIOReturnBadArgument;
#if CONFIG_MACF
	else if (0 != mac_iokit_check_set_properties(kauth_cred_get(),
	    registry_entry, obj))
	{
	    res = kIOReturnNotPermitted;
	}
#endif
	else
	{
	    res = entry->setProperties( obj );
	}

	if (obj)
	    obj->release();

        FAKE_STACK_FRAME_END();

    } else
        res = err;

    *result = res;
    return( err );
}

/* Routine io_registry_entry_get_child_iterator */
kern_return_t is_io_registry_entry_get_child_iterator(
	io_object_t registry_entry,
	io_name_t plane,
	io_object_t *iterator )
{
    CHECK( IORegistryEntry, registry_entry, entry );

    *iterator = entry->getChildIterator(
    IORegistryEntry::getPlane( plane ));

    return( kIOReturnSuccess );
}

/* Routine io_registry_entry_get_parent_iterator */
kern_return_t is_io_registry_entry_get_parent_iterator(
	io_object_t registry_entry,
	io_name_t plane,
	io_object_t *iterator)
{
    CHECK( IORegistryEntry, registry_entry, entry );

    *iterator = entry->getParentIterator(
	IORegistryEntry::getPlane( plane ));

    return( kIOReturnSuccess );
}

/* Routine io_service_get_busy_state */
kern_return_t is_io_service_get_busy_state(
	io_object_t _service,
	uint32_t *busyState )
{
    CHECK( IOService, _service, service );

    *busyState = service->getBusyState();

    return( kIOReturnSuccess );
}

/* Routine io_service_get_state */
kern_return_t is_io_service_get_state(
	io_object_t _service,
	uint64_t *state,
	uint32_t *busy_state,
	uint64_t *accumulated_busy_time )
{
    CHECK( IOService, _service, service );

    *state                 = service->getState();
    *busy_state            = service->getBusyState();
    *accumulated_busy_time = service->getAccumulatedBusyTime();

    return( kIOReturnSuccess );
}

/* Routine io_service_wait_quiet */
kern_return_t is_io_service_wait_quiet(
	io_object_t _service,
	mach_timespec_t wait_time )
{
    uint64_t    timeoutNS;
    
    CHECK( IOService, _service, service );

    timeoutNS = wait_time.tv_sec;
    timeoutNS *= kSecondScale;
    timeoutNS += wait_time.tv_nsec;
    
    return( service->waitQuiet(timeoutNS) );
}

/* Routine io_service_request_probe */
kern_return_t is_io_service_request_probe(
	io_object_t _service,
	uint32_t options )
{
    CHECK( IOService, _service, service );

    return( service->requestProbe( options ));
}

/* Routine io_service_get_authorization_id */
kern_return_t is_io_service_get_authorization_id(
	io_object_t _service,
	uint64_t *authorization_id )
{
    kern_return_t	   kr;

    CHECK( IOService, _service, service );

    kr = IOUserClient::clientHasPrivilege( (void *) current_task(),
                                            kIOClientPrivilegeAdministrator );
    if( kIOReturnSuccess != kr)
        return( kr );

    *authorization_id = service->getAuthorizationID();

    return( kr );
}

/* Routine io_service_set_authorization_id */
kern_return_t is_io_service_set_authorization_id(
	io_object_t _service,
	uint64_t authorization_id )
{
    CHECK( IOService, _service, service );

    return( service->setAuthorizationID( authorization_id ) );
}

/* Routine io_service_open_ndr */
kern_return_t is_io_service_open_extended(
	io_object_t _service,
	task_t owningTask,
	uint32_t connect_type,
	NDR_record_t ndr,
	io_buf_ptr_t properties,
	mach_msg_type_number_t propertiesCnt,
        kern_return_t * result,
	io_object_t *connection )
{
    IOUserClient * client = 0;
    kern_return_t  err = KERN_SUCCESS;
    IOReturn	   res = kIOReturnSuccess;
    OSDictionary * propertiesDict = 0;
    bool	   crossEndian;
    bool	   disallowAccess;

    CHECK( IOService, _service, service );

    if (!owningTask)                  return (kIOReturnBadArgument);
    assert(owningTask == current_task());
    if (owningTask != current_task()) return (kIOReturnBadArgument);

    do
    {
	if (properties)
	{
	    OSObject *	    obj;
	    vm_offset_t     data;
	    vm_map_offset_t map_data;

	    if( propertiesCnt > sizeof(io_struct_inband_t))
		return( kIOReturnMessageTooLarge);

	    err = vm_map_copyout( kernel_map, &map_data, (vm_map_copy_t) properties );
	    res = err;
	    data = CAST_DOWN(vm_offset_t, map_data);
	    if (KERN_SUCCESS == err)
	    {
		// must return success after vm_map_copyout() succeeds
		obj = OSUnserializeXML( (const char *) data, propertiesCnt );
		vm_deallocate( kernel_map, data, propertiesCnt );
		propertiesDict = OSDynamicCast(OSDictionary, obj);
		if (!propertiesDict)
		{
		    res = kIOReturnBadArgument;
		    if (obj)
			obj->release();
		}
	    }
	    if (kIOReturnSuccess != res)
		break;
	}

	crossEndian = (ndr.int_rep != NDR_record.int_rep);
	if (crossEndian)
	{
	    if (!propertiesDict)
		propertiesDict = OSDictionary::withCapacity(4);
	    OSData * data = OSData::withBytes(&ndr, sizeof(ndr));
	    if (data)
	    {
		if (propertiesDict)
		    propertiesDict->setObject(kIOUserClientCrossEndianKey, data);
		data->release();
	    }
	}

	res = service->newUserClient( owningTask, (void *) owningTask,
		    connect_type, propertiesDict, &client );

	if (propertiesDict)
	    propertiesDict->release();

	if (res == kIOReturnSuccess)
	{
	    assert( OSDynamicCast(IOUserClient, client) );

	    client->sharedInstance = (0 != client->getProperty(kIOUserClientSharedInstanceKey));
	    client->closed = false;

	    disallowAccess = (crossEndian
		&& (kOSBooleanTrue != service->getProperty(kIOUserClientCrossEndianCompatibleKey))
		&& (kOSBooleanTrue != client->getProperty(kIOUserClientCrossEndianCompatibleKey)));
            if (disallowAccess) res = kIOReturnUnsupported;
#if CONFIG_MACF
	    else if (0 != mac_iokit_check_open(kauth_cred_get(), client, connect_type))
		res = kIOReturnNotPermitted;
#endif

	    if (kIOReturnSuccess == res) res = client->registerOwner(owningTask);

	    if (kIOReturnSuccess != res)
	    {
		IOStatisticsClientCall();
		client->clientClose();
		client->release();
		client = 0;
		break;
	    }
	    OSString * creatorName = IOCopyLogNameForPID(proc_selfpid());
	    if (creatorName)
	    {
		client->setProperty(kIOUserClientCreatorKey, creatorName);
		creatorName->release();
	    }
	    client->setTerminateDefer(service, false);
	}
    }
    while (false);

    *connection = client;
    *result = res;

    return (err);
}

/* Routine io_service_close */
kern_return_t is_io_service_close(
	io_object_t connection )
{
    OSSet * mappings;
    if ((mappings = OSDynamicCast(OSSet, connection)))
	return( kIOReturnSuccess );

    CHECK( IOUserClient, connection, client );

    IOStatisticsClientCall();

    if (client->sharedInstance || OSCompareAndSwap8(0, 1, &client->closed)) 
    {
	client->clientClose();
    }
    else
    {
	IOLog("ignored is_io_service_close(0x%qx,%s)\n", 
		client->getRegistryEntryID(), client->getName());
    }

    return( kIOReturnSuccess );
}

/* Routine io_connect_get_service */
kern_return_t is_io_connect_get_service(
	io_object_t connection,
	io_object_t *service )
{
    IOService * theService;

    CHECK( IOUserClient, connection, client );

    theService = client->getService();
    if( theService)
	theService->retain();

    *service = theService;

    return( theService ? kIOReturnSuccess : kIOReturnUnsupported );
}

/* Routine io_connect_set_notification_port */
kern_return_t is_io_connect_set_notification_port(
	io_object_t connection,
	uint32_t notification_type,
	mach_port_t port,
	uint32_t reference)
{
    CHECK( IOUserClient, connection, client );

    IOStatisticsClientCall();
    return( client->registerNotificationPort( port, notification_type,
						(io_user_reference_t) reference ));
}

/* Routine io_connect_set_notification_port */
kern_return_t is_io_connect_set_notification_port_64(
	io_object_t connection,
	uint32_t notification_type,
	mach_port_t port,
	io_user_reference_t reference)
{
    CHECK( IOUserClient, connection, client );

    IOStatisticsClientCall();
    return( client->registerNotificationPort( port, notification_type,
						reference ));
}

/* Routine io_connect_map_memory_into_task */
kern_return_t is_io_connect_map_memory_into_task
(
	io_connect_t connection,
	uint32_t memory_type,
	task_t into_task,
	mach_vm_address_t *address,
	mach_vm_size_t *size,
	uint32_t flags
)
{
    IOReturn		err;
    IOMemoryMap *	map;

    CHECK( IOUserClient, connection, client );

    if (!into_task) return (kIOReturnBadArgument);

    IOStatisticsClientCall();
    map = client->mapClientMemory64( memory_type, into_task, flags, *address );

    if( map) {
        *address = map->getAddress();
        if( size)
            *size = map->getSize();

        if( client->sharedInstance
	    || (into_task != current_task())) {
            // push a name out to the task owning the map,
            // so we can clean up maps
	    mach_port_name_t name __unused =
		IOMachPort::makeSendRightForTask(
                                    into_task, map, IKOT_IOKIT_OBJECT );

        } else {
            // keep it with the user client
            IOLockLock( gIOObjectPortLock);
            if( 0 == client->mappings)
                client->mappings = OSSet::withCapacity(2);
            if( client->mappings)
                client->mappings->setObject( map);
            IOLockUnlock( gIOObjectPortLock);
            map->release();
        }
        err = kIOReturnSuccess;

    } else
	err = kIOReturnBadArgument;

    return( err );
}

/* Routine is_io_connect_map_memory */
kern_return_t is_io_connect_map_memory(
	io_object_t     connect,
	uint32_t	type,
	task_t		task,
	uint32_t  *	mapAddr,
	uint32_t  *	mapSize,
	uint32_t	flags )
{
    IOReturn	      err;
    mach_vm_address_t address;
    mach_vm_size_t    size;

    address = SCALAR64(*mapAddr);
    size    = SCALAR64(*mapSize);

    err = is_io_connect_map_memory_into_task(connect, type, task, &address, &size, flags);

    *mapAddr = SCALAR32(address);
    *mapSize = SCALAR32(size);

    return (err);
}

} /* extern "C" */

IOMemoryMap * IOUserClient::removeMappingForDescriptor(IOMemoryDescriptor * mem)
{
    OSIterator *  iter;
    IOMemoryMap * map = 0;

    IOLockLock(gIOObjectPortLock);

    iter = OSCollectionIterator::withCollection(mappings);
    if(iter)
    {
        while ((map = OSDynamicCast(IOMemoryMap, iter->getNextObject())))
        {
            if(mem == map->getMemoryDescriptor())
            {
                map->retain();
                mappings->removeObject(map);
                break;
            }
        }
        iter->release();
    }

    IOLockUnlock(gIOObjectPortLock);

    return (map);
}

extern "C" {

/* Routine io_connect_unmap_memory_from_task */
kern_return_t is_io_connect_unmap_memory_from_task
(
	io_connect_t connection,
	uint32_t memory_type,
	task_t from_task,
	mach_vm_address_t address)
{
    IOReturn		err;
    IOOptionBits	options = 0;
    IOMemoryDescriptor * memory;
    IOMemoryMap *	map;

    CHECK( IOUserClient, connection, client );

    if (!from_task) return (kIOReturnBadArgument);

    IOStatisticsClientCall();
    err = client->clientMemoryForType( (UInt32) memory_type, &options, &memory );

    if( memory && (kIOReturnSuccess == err)) {

        options = (options & ~kIOMapUserOptionsMask)
		| kIOMapAnywhere | kIOMapReference;

	map = memory->createMappingInTask( from_task, address, options );
	memory->release();
        if( map)
	{
            IOLockLock( gIOObjectPortLock);
            if( client->mappings)
                client->mappings->removeObject( map);
            IOLockUnlock( gIOObjectPortLock);

	    mach_port_name_t name = 0;
	    if (from_task != current_task())
		name = IOMachPort::makeSendRightForTask( from_task, map, IKOT_IOKIT_OBJECT );
	    if (name)
	    {
		map->userClientUnmap();
		err = iokit_mod_send_right( from_task, name, -2 );
		err = kIOReturnSuccess;
	    }
	    else
		IOMachPort::releasePortForObject( map, IKOT_IOKIT_OBJECT );
	    if (from_task == current_task())
		map->release();
        }
	else
            err = kIOReturnBadArgument;
    }

    return( err );
}

kern_return_t is_io_connect_unmap_memory(
	io_object_t     connect,
	uint32_t	type,
	task_t		task,
	uint32_t 	mapAddr )
{
    IOReturn		err;
    mach_vm_address_t   address;
    
    address = SCALAR64(mapAddr);
    
    err = is_io_connect_unmap_memory_from_task(connect, type, task, mapAddr);

    return (err);
}


/* Routine io_connect_add_client */
kern_return_t is_io_connect_add_client(
	io_object_t connection,
	io_object_t connect_to)
{
    CHECK( IOUserClient, connection, client );
    CHECK( IOUserClient, connect_to, to );

    IOStatisticsClientCall();
    return( client->connectClient( to ) );
}


/* Routine io_connect_set_properties */
kern_return_t is_io_connect_set_properties(
	io_object_t connection,
	io_buf_ptr_t properties,
	mach_msg_type_number_t propertiesCnt,
        kern_return_t * result)
{
    return( is_io_registry_entry_set_properties( connection, properties, propertiesCnt, result ));
}

/* Routine io_user_client_method */
kern_return_t is_io_connect_method_var_output
(
	io_connect_t connection,
	uint32_t selector,
	io_scalar_inband64_t scalar_input,
	mach_msg_type_number_t scalar_inputCnt,
	io_struct_inband_t inband_input,
	mach_msg_type_number_t inband_inputCnt,
	mach_vm_address_t ool_input,
	mach_vm_size_t ool_input_size,
	io_struct_inband_t inband_output,
	mach_msg_type_number_t *inband_outputCnt,
	io_scalar_inband64_t scalar_output,
	mach_msg_type_number_t *scalar_outputCnt,
	io_buf_ptr_t *var_output,
	mach_msg_type_number_t *var_outputCnt
)
{
    CHECK( IOUserClient, connection, client );

    IOExternalMethodArguments args;
    IOReturn ret;
    IOMemoryDescriptor * inputMD  = 0;
    OSObject *           structureVariableOutputData = 0;

    bzero(&args.__reserved[0], sizeof(args.__reserved));
    args.__reservedA = 0;
    args.version = kIOExternalMethodArgumentsCurrentVersion;

    args.selector = selector;

    args.asyncWakePort               = MACH_PORT_NULL;
    args.asyncReference              = 0;
    args.asyncReferenceCount         = 0;
    args.structureVariableOutputData = &structureVariableOutputData;

    args.scalarInput = scalar_input;
    args.scalarInputCount = scalar_inputCnt;
    args.structureInput = inband_input;
    args.structureInputSize = inband_inputCnt;

    if (ool_input)
	inputMD = IOMemoryDescriptor::withAddressRange(ool_input, ool_input_size, 
						    kIODirectionOut, current_task());

    args.structureInputDescriptor = inputMD;

    args.scalarOutput = scalar_output;
    args.scalarOutputCount = *scalar_outputCnt;
    bzero(&scalar_output[0], *scalar_outputCnt * sizeof(scalar_output[0]));
    args.structureOutput = inband_output;
    args.structureOutputSize = *inband_outputCnt;
    args.structureOutputDescriptor = NULL;
    args.structureOutputDescriptorSize = 0;

    IOStatisticsClientCall();
    ret = client->externalMethod( selector, &args );

    *scalar_outputCnt = args.scalarOutputCount;
    *inband_outputCnt = args.structureOutputSize;

    if (var_outputCnt && var_output && (kIOReturnSuccess == ret))
    {
    	OSSerialize * serialize;
    	OSData      * data;
	vm_size_t     len;

	if ((serialize = OSDynamicCast(OSSerialize, structureVariableOutputData)))
	{
	    len = serialize->getLength();
	    *var_outputCnt = len;
	    ret = copyoutkdata(serialize->text(), len, var_output);
	}
	else if ((data = OSDynamicCast(OSData, structureVariableOutputData)))
	{
	    len = data->getLength();
	    *var_outputCnt = len;
	    ret = copyoutkdata(data->getBytesNoCopy(), len, var_output);
	}
	else
	{
	    ret = kIOReturnUnderrun;
	}
    }

    if (inputMD)
	inputMD->release();
    if (structureVariableOutputData)
    	structureVariableOutputData->release();

    return (ret);
}

/* Routine io_user_client_method */
kern_return_t is_io_connect_method
(
	io_connect_t connection,
	uint32_t selector,
	io_scalar_inband64_t scalar_input,
	mach_msg_type_number_t scalar_inputCnt,
	io_struct_inband_t inband_input,
	mach_msg_type_number_t inband_inputCnt,
	mach_vm_address_t ool_input,
	mach_vm_size_t ool_input_size,
	io_struct_inband_t inband_output,
	mach_msg_type_number_t *inband_outputCnt,
	io_scalar_inband64_t scalar_output,
	mach_msg_type_number_t *scalar_outputCnt,
	mach_vm_address_t ool_output,
	mach_vm_size_t *ool_output_size
)
{
    CHECK( IOUserClient, connection, client );

    IOExternalMethodArguments args;
    IOReturn ret;
    IOMemoryDescriptor * inputMD  = 0;
    IOMemoryDescriptor * outputMD = 0;

    bzero(&args.__reserved[0], sizeof(args.__reserved));
    args.__reservedA = 0;
    args.version = kIOExternalMethodArgumentsCurrentVersion;

    args.selector = selector;

    args.asyncWakePort               = MACH_PORT_NULL;
    args.asyncReference              = 0;
    args.asyncReferenceCount         = 0;
    args.structureVariableOutputData = 0;

    args.scalarInput = scalar_input;
    args.scalarInputCount = scalar_inputCnt;
    args.structureInput = inband_input;
    args.structureInputSize = inband_inputCnt;

    if (ool_input)
	inputMD = IOMemoryDescriptor::withAddressRange(ool_input, ool_input_size, 
						    kIODirectionOut, current_task());

    args.structureInputDescriptor = inputMD;

    args.scalarOutput = scalar_output;
    args.scalarOutputCount = *scalar_outputCnt;
    bzero(&scalar_output[0], *scalar_outputCnt * sizeof(scalar_output[0]));
    args.structureOutput = inband_output;
    args.structureOutputSize = *inband_outputCnt;

    if (ool_output && ool_output_size)
    {
	outputMD = IOMemoryDescriptor::withAddressRange(ool_output, *ool_output_size, 
						    kIODirectionIn, current_task());
    }

    args.structureOutputDescriptor = outputMD;
    args.structureOutputDescriptorSize = ool_output_size ? *ool_output_size : 0;

    IOStatisticsClientCall();
    ret = client->externalMethod( selector, &args );

    *scalar_outputCnt = args.scalarOutputCount;
    *inband_outputCnt = args.structureOutputSize;
    *ool_output_size  = args.structureOutputDescriptorSize;

    if (inputMD)
	inputMD->release();
    if (outputMD)
	outputMD->release();

    return (ret);
}

/* Routine io_async_user_client_method */
kern_return_t is_io_connect_async_method
(
	io_connect_t connection,
	mach_port_t wake_port,
	io_async_ref64_t reference,
	mach_msg_type_number_t referenceCnt,
	uint32_t selector,
	io_scalar_inband64_t scalar_input,
	mach_msg_type_number_t scalar_inputCnt,
	io_struct_inband_t inband_input,
	mach_msg_type_number_t inband_inputCnt,
	mach_vm_address_t ool_input,
	mach_vm_size_t ool_input_size,
	io_struct_inband_t inband_output,
	mach_msg_type_number_t *inband_outputCnt,
	io_scalar_inband64_t scalar_output,
	mach_msg_type_number_t *scalar_outputCnt,
	mach_vm_address_t ool_output,
	mach_vm_size_t * ool_output_size
)
{
    CHECK( IOUserClient, connection, client );

    IOExternalMethodArguments args;
    IOReturn ret;
    IOMemoryDescriptor * inputMD  = 0;
    IOMemoryDescriptor * outputMD = 0;

    bzero(&args.__reserved[0], sizeof(args.__reserved));
    args.__reservedA = 0;
    args.version = kIOExternalMethodArgumentsCurrentVersion;

    reference[0]	     = (io_user_reference_t) wake_port;
    if (vm_map_is_64bit(get_task_map(current_task()))) 
	reference[0]	     |= kIOUCAsync64Flag;

    args.selector = selector;

    args.asyncWakePort       = wake_port;
    args.asyncReference      = reference;
    args.asyncReferenceCount = referenceCnt;

    args.scalarInput = scalar_input;
    args.scalarInputCount = scalar_inputCnt;
    args.structureInput = inband_input;
    args.structureInputSize = inband_inputCnt;

    if (ool_input)
	inputMD = IOMemoryDescriptor::withAddressRange(ool_input, ool_input_size,
						    kIODirectionOut, current_task());

    args.structureInputDescriptor = inputMD;

    args.scalarOutput = scalar_output;
    args.scalarOutputCount = *scalar_outputCnt;
    bzero(&scalar_output[0], *scalar_outputCnt * sizeof(scalar_output[0]));
    args.structureOutput = inband_output;
    args.structureOutputSize = *inband_outputCnt;

    if (ool_output)
    {
	outputMD = IOMemoryDescriptor::withAddressRange(ool_output, *ool_output_size,
						    kIODirectionIn, current_task());
    }

    args.structureOutputDescriptor = outputMD;
    args.structureOutputDescriptorSize = *ool_output_size;

    IOStatisticsClientCall();
    ret = client->externalMethod( selector, &args );

    *inband_outputCnt = args.structureOutputSize;
    *ool_output_size  = args.structureOutputDescriptorSize;

    if (inputMD)
	inputMD->release();
    if (outputMD)
	outputMD->release();

    return (ret);
}

/* Routine io_connect_method_scalarI_scalarO */
kern_return_t is_io_connect_method_scalarI_scalarO(
	io_object_t	   connect,
	uint32_t	   index,
        io_scalar_inband_t       input,
        mach_msg_type_number_t	 inputCount,
        io_scalar_inband_t       output,
        mach_msg_type_number_t * outputCount )
{
    IOReturn err;
    uint32_t i;
    io_scalar_inband64_t _input;
    io_scalar_inband64_t _output;

    mach_msg_type_number_t struct_outputCnt = 0;
    mach_vm_size_t ool_output_size = 0;

    bzero(&_output[0], sizeof(_output));
    for (i = 0; i < inputCount; i++)
	_input[i] = SCALAR64(input[i]);
	
    err = is_io_connect_method(connect, index, 
		    _input, inputCount, 
		    NULL, 0,
		    0, 0,
		    NULL, &struct_outputCnt,
		    _output, outputCount,
		    0, &ool_output_size);

    for (i = 0; i < *outputCount; i++)
	output[i] = SCALAR32(_output[i]);

    return (err);
}

kern_return_t shim_io_connect_method_scalarI_scalarO(
	IOExternalMethod *	method,
	IOService *		object,
        const io_user_scalar_t * input,
        mach_msg_type_number_t	 inputCount,
        io_user_scalar_t * output,
        mach_msg_type_number_t * outputCount )
{
    IOMethod		func;
    io_scalar_inband_t  _output;
    IOReturn 		err;
    err = kIOReturnBadArgument;

    bzero(&_output[0], sizeof(_output));
    do {

	if( inputCount != method->count0)
	{
	    IOLog("%s:%d %s: IOUserClient inputCount count mismatch 0x%llx 0x%llx\n", __FUNCTION__, __LINE__, object->getName(), (uint64_t)inputCount, (uint64_t)method->count0);
	    DTRACE_IO2(iokit_count_mismatch, uint64_t, (uint64_t)inputCount, uint64_t, (uint64_t)method->count0);
	    continue;
	}
	if( *outputCount != method->count1)
	{
	    IOLog("%s:%d %s: IOUserClient outputCount count mismatch 0x%llx 0x%llx\n", __FUNCTION__, __LINE__, object->getName(), (uint64_t)*outputCount, (uint64_t)method->count1);
	    DTRACE_IO2(iokit_count_mismatch, uint64_t, (uint64_t)*outputCount, uint64_t, (uint64_t)method->count1);
	    continue;
	}

	func = method->func;

	switch( inputCount) {

	    case 6:
		err = (object->*func)(  ARG32(input[0]), ARG32(input[1]), ARG32(input[2]),
					ARG32(input[3]), ARG32(input[4]), ARG32(input[5]) );
		break;
	    case 5:
		err = (object->*func)(  ARG32(input[0]), ARG32(input[1]), ARG32(input[2]),
					ARG32(input[3]), ARG32(input[4]), 
					&_output[0] );
		break;
	    case 4:
		err = (object->*func)(  ARG32(input[0]), ARG32(input[1]), ARG32(input[2]),
					ARG32(input[3]),
					&_output[0], &_output[1] );
		break;
	    case 3:
		err = (object->*func)(  ARG32(input[0]), ARG32(input[1]), ARG32(input[2]),
					&_output[0], &_output[1], &_output[2] );
		break;
	    case 2:
		err = (object->*func)(  ARG32(input[0]), ARG32(input[1]),
					&_output[0], &_output[1], &_output[2],
					&_output[3] );
		break;
	    case 1:
		err = (object->*func)(  ARG32(input[0]),
					&_output[0], &_output[1], &_output[2],
					&_output[3], &_output[4] );
		break;
	    case 0:
		err = (object->*func)(  &_output[0], &_output[1], &_output[2],
					&_output[3], &_output[4], &_output[5] );
		break;

	    default:
		IOLog("%s: Bad method table\n", object->getName());
	}
    }
    while( false);

    uint32_t i;
    for (i = 0; i < *outputCount; i++)
	output[i] = SCALAR32(_output[i]);

    return( err);
}

/* Routine io_async_method_scalarI_scalarO */
kern_return_t is_io_async_method_scalarI_scalarO(
	io_object_t	   connect,
	mach_port_t wake_port,
	io_async_ref_t reference,
	mach_msg_type_number_t referenceCnt,
	uint32_t	   index,
        io_scalar_inband_t       input,
        mach_msg_type_number_t	 inputCount,
        io_scalar_inband_t       output,
        mach_msg_type_number_t * outputCount )
{
    IOReturn err;
    uint32_t i;
    io_scalar_inband64_t _input;
    io_scalar_inband64_t _output;
    io_async_ref64_t _reference;

    bzero(&_output[0], sizeof(_output));
    for (i = 0; i < referenceCnt; i++)
	_reference[i] = REF64(reference[i]);

    mach_msg_type_number_t struct_outputCnt = 0;
    mach_vm_size_t ool_output_size = 0;

    for (i = 0; i < inputCount; i++)
	_input[i] = SCALAR64(input[i]);

    err = is_io_connect_async_method(connect, 
		    wake_port, _reference, referenceCnt,
		    index, 
		    _input, inputCount, 
		    NULL, 0,
		    0, 0,
		    NULL, &struct_outputCnt,
		    _output, outputCount,
		    0, &ool_output_size);

    for (i = 0; i < *outputCount; i++)
	output[i] = SCALAR32(_output[i]);

    return (err);
}
/* Routine io_async_method_scalarI_structureO */
kern_return_t is_io_async_method_scalarI_structureO(
	io_object_t	connect,
	mach_port_t wake_port,
	io_async_ref_t reference,
	mach_msg_type_number_t referenceCnt,
	uint32_t	index,
        io_scalar_inband_t input,
        mach_msg_type_number_t	inputCount,
        io_struct_inband_t		output,
        mach_msg_type_number_t *	outputCount )
{
    uint32_t i;
    io_scalar_inband64_t _input;
    io_async_ref64_t _reference;

    for (i = 0; i < referenceCnt; i++)
	_reference[i] = REF64(reference[i]);

    mach_msg_type_number_t scalar_outputCnt = 0;
    mach_vm_size_t ool_output_size = 0;

    for (i = 0; i < inputCount; i++)
	_input[i] = SCALAR64(input[i]);
	
    return (is_io_connect_async_method(connect, 
		    wake_port, _reference, referenceCnt,
		    index,
		    _input, inputCount, 
		    NULL, 0,
		    0, 0,
		    output, outputCount,
		    NULL, &scalar_outputCnt,
		    0, &ool_output_size));
}

/* Routine io_async_method_scalarI_structureI */
kern_return_t is_io_async_method_scalarI_structureI(
	io_connect_t		connect,
	mach_port_t wake_port,
	io_async_ref_t reference,
	mach_msg_type_number_t referenceCnt,
	uint32_t		index,
        io_scalar_inband_t	input,
        mach_msg_type_number_t	inputCount,
        io_struct_inband_t	inputStruct,
        mach_msg_type_number_t	inputStructCount )
{
    uint32_t i;
    io_scalar_inband64_t _input;
    io_async_ref64_t _reference;

    for (i = 0; i < referenceCnt; i++)
	_reference[i] = REF64(reference[i]);

    mach_msg_type_number_t scalar_outputCnt = 0;
    mach_msg_type_number_t inband_outputCnt = 0;
    mach_vm_size_t ool_output_size = 0;

    for (i = 0; i < inputCount; i++)
	_input[i] = SCALAR64(input[i]);
	
    return (is_io_connect_async_method(connect, 
		    wake_port, _reference, referenceCnt,
		    index,
		    _input, inputCount, 
		    inputStruct, inputStructCount,
		    0, 0,
		    NULL, &inband_outputCnt,
		    NULL, &scalar_outputCnt,
		    0, &ool_output_size));
}

/* Routine io_async_method_structureI_structureO */
kern_return_t is_io_async_method_structureI_structureO(
	io_object_t	connect,
	mach_port_t wake_port,
	io_async_ref_t reference,
	mach_msg_type_number_t referenceCnt,
	uint32_t	index,
        io_struct_inband_t		input,
        mach_msg_type_number_t	inputCount,
        io_struct_inband_t		output,
        mach_msg_type_number_t *	outputCount )
{
    uint32_t i;
    mach_msg_type_number_t scalar_outputCnt = 0;
    mach_vm_size_t ool_output_size = 0;
    io_async_ref64_t _reference;

    for (i = 0; i < referenceCnt; i++)
	_reference[i] = REF64(reference[i]);

    return (is_io_connect_async_method(connect,
		    wake_port, _reference, referenceCnt,
		    index,
		    NULL, 0, 
		    input, inputCount,
		    0, 0,
		    output, outputCount,
		    NULL, &scalar_outputCnt,
		    0, &ool_output_size));
}


kern_return_t shim_io_async_method_scalarI_scalarO(
	IOExternalAsyncMethod *	method,
	IOService *		object,
	mach_port_t             asyncWakePort,
	io_user_reference_t *   asyncReference,
	uint32_t                asyncReferenceCount,
        const io_user_scalar_t * input,
        mach_msg_type_number_t	 inputCount,
        io_user_scalar_t * output,
        mach_msg_type_number_t * outputCount )
{
    IOAsyncMethod	func;
    uint32_t		i;
    io_scalar_inband_t  _output;
    IOReturn 		err;
    io_async_ref_t	reference;

    bzero(&_output[0], sizeof(_output));
    for (i = 0; i < asyncReferenceCount; i++)
	reference[i] = REF32(asyncReference[i]);

    err = kIOReturnBadArgument;

    do {

	if( inputCount != method->count0)
	{
	    IOLog("%s:%d %s: IOUserClient inputCount count mismatch 0x%llx 0x%llx\n", __FUNCTION__, __LINE__, object->getName(), (uint64_t)inputCount, (uint64_t)method->count0);
	    DTRACE_IO2(iokit_count_mismatch, uint64_t, (uint64_t)inputCount, uint64_t, (uint64_t)method->count0);
	    continue;
	}
	if( *outputCount != method->count1)
	{
	    IOLog("%s:%d %s: IOUserClient outputCount count mismatch 0x%llx 0x%llx\n", __FUNCTION__, __LINE__, object->getName(), (uint64_t)*outputCount, (uint64_t)method->count1);
	    DTRACE_IO2(iokit_count_mismatch, uint64_t, (uint64_t)*outputCount, uint64_t, (uint64_t)method->count1);
	    continue;
	}

	func = method->func;

        switch( inputCount) {

            case 6:
                err = (object->*func)(	reference,
                                        ARG32(input[0]), ARG32(input[1]), ARG32(input[2]),
                                        ARG32(input[3]), ARG32(input[4]), ARG32(input[5]) );
                break;
            case 5:
                err = (object->*func)(  reference,
                                        ARG32(input[0]), ARG32(input[1]), ARG32(input[2]),
                                        ARG32(input[3]), ARG32(input[4]),
                                        &_output[0] );
                break;
            case 4:
                err = (object->*func)(  reference,
                                        ARG32(input[0]), ARG32(input[1]), ARG32(input[2]),
                                        ARG32(input[3]),
                                        &_output[0], &_output[1] );
                break;
            case 3:
                err = (object->*func)(  reference,
                                        ARG32(input[0]), ARG32(input[1]), ARG32(input[2]),
                                        &_output[0], &_output[1], &_output[2] );
                break;
            case 2:
                err = (object->*func)(  reference,
                                        ARG32(input[0]), ARG32(input[1]),
                                        &_output[0], &_output[1], &_output[2],
                                        &_output[3] );
                break;
            case 1:
                err = (object->*func)(  reference,
                                        ARG32(input[0]), 
					&_output[0], &_output[1], &_output[2],
                                        &_output[3], &_output[4] );
                break;
            case 0:
                err = (object->*func)(  reference,
                                        &_output[0], &_output[1], &_output[2],
                                        &_output[3], &_output[4], &_output[5] );
                break;

            default:
                IOLog("%s: Bad method table\n", object->getName());
        }
    }
    while( false);

    for (i = 0; i < *outputCount; i++)
	output[i] = SCALAR32(_output[i]);

    return( err);
}


/* Routine io_connect_method_scalarI_structureO */
kern_return_t is_io_connect_method_scalarI_structureO(
	io_object_t	connect,
	uint32_t	index,
        io_scalar_inband_t input,
        mach_msg_type_number_t	inputCount,
        io_struct_inband_t		output,
        mach_msg_type_number_t *	outputCount )
{
    uint32_t i;
    io_scalar_inband64_t _input;

    mach_msg_type_number_t scalar_outputCnt = 0;
    mach_vm_size_t ool_output_size = 0;

    for (i = 0; i < inputCount; i++)
	_input[i] = SCALAR64(input[i]);
	
    return (is_io_connect_method(connect, index, 
		    _input, inputCount, 
		    NULL, 0,
		    0, 0,
		    output, outputCount,
		    NULL, &scalar_outputCnt,
		    0, &ool_output_size));
}

kern_return_t shim_io_connect_method_scalarI_structureO(

	IOExternalMethod *	method,
	IOService *		object,
        const io_user_scalar_t * input,
        mach_msg_type_number_t	inputCount,
        io_struct_inband_t		output,
        IOByteCount *	outputCount )
{
    IOMethod		func;
    IOReturn 		err;

    err = kIOReturnBadArgument;

    do {
	if( inputCount != method->count0)
	{
	    IOLog("%s:%d %s: IOUserClient inputCount count mismatch 0x%llx 0x%llx\n", __FUNCTION__, __LINE__, object->getName(), (uint64_t)inputCount, (uint64_t)method->count0);
	    DTRACE_IO2(iokit_count_mismatch, uint64_t, (uint64_t)inputCount, uint64_t, (uint64_t)method->count0);
	    continue;
	}
	if( (kIOUCVariableStructureSize != method->count1)
		&& (*outputCount != method->count1))
	{
	    IOLog("%s:%d %s: IOUserClient outputCount count mismatch 0x%llx 0x%llx 0x%llx\n", __FUNCTION__, __LINE__, object->getName(), (uint64_t)*outputCount, (uint64_t)method->count1, (uint64_t)kIOUCVariableStructureSize);
	    DTRACE_IO2(iokit_count_mismatch, uint64_t, (uint64_t)*outputCount, uint64_t, (uint64_t)method->count1);
	    continue;
	}

	func = method->func;

	switch( inputCount) {

	    case 5:
		err = (object->*func)(  ARG32(input[0]), ARG32(input[1]), ARG32(input[2]),
                                        ARG32(input[3]), ARG32(input[4]),
                                        output );
		break;
	    case 4:
		err = (object->*func)(  ARG32(input[0]), ARG32(input[1]), ARG32(input[2]),
					ARG32(input[3]),
					output, (void *)outputCount );
		break;
	    case 3:
		err = (object->*func)(  ARG32(input[0]), ARG32(input[1]), ARG32(input[2]),
					output, (void *)outputCount, 0 );
		break;
	    case 2:
		err = (object->*func)(  ARG32(input[0]), ARG32(input[1]),
					output, (void *)outputCount, 0, 0 );
		break;
	    case 1:
		err = (object->*func)(  ARG32(input[0]),
					output, (void *)outputCount, 0, 0, 0 );
		break;
	    case 0:
		err = (object->*func)(  output, (void *)outputCount, 0, 0, 0, 0 );
		break;

	    default:
		IOLog("%s: Bad method table\n", object->getName());
	}
    }
    while( false);

    return( err);
}


kern_return_t shim_io_async_method_scalarI_structureO(
	IOExternalAsyncMethod *	method,
	IOService *		object,
	mach_port_t             asyncWakePort,
	io_user_reference_t *   asyncReference,
	uint32_t                asyncReferenceCount,
        const io_user_scalar_t * input,
        mach_msg_type_number_t	inputCount,
        io_struct_inband_t		output,
        mach_msg_type_number_t *	outputCount )
{
    IOAsyncMethod	func;
    uint32_t		i;
    IOReturn 		err;
    io_async_ref_t	reference;

    for (i = 0; i < asyncReferenceCount; i++)
	reference[i] = REF32(asyncReference[i]);

    err = kIOReturnBadArgument;
    do {
	if( inputCount != method->count0)
	{
	    IOLog("%s:%d %s: IOUserClient inputCount count mismatch 0x%llx 0x%llx\n", __FUNCTION__, __LINE__, object->getName(), (uint64_t)inputCount, (uint64_t)method->count0);
	    DTRACE_IO2(iokit_count_mismatch, uint64_t, (uint64_t)inputCount, uint64_t, (uint64_t)method->count0);
	    continue;
	}
	if( (kIOUCVariableStructureSize != method->count1)
		&& (*outputCount != method->count1))
	{
	    IOLog("%s:%d %s: IOUserClient outputCount count mismatch 0x%llx 0x%llx 0x%llx\n", __FUNCTION__, __LINE__, object->getName(), (uint64_t)*outputCount, (uint64_t)method->count1, (uint64_t)kIOUCVariableStructureSize);
	    DTRACE_IO2(iokit_count_mismatch, uint64_t, (uint64_t)*outputCount, uint64_t, (uint64_t)method->count1);
	    continue;
	}

	func = method->func;

        switch( inputCount) {

            case 5:
                err = (object->*func)(	reference,
                                        ARG32(input[0]), ARG32(input[1]), ARG32(input[2]),
                                        ARG32(input[3]), ARG32(input[4]),
                                        output );
                break;
            case 4:
                err = (object->*func)(	reference,
                                        ARG32(input[0]), ARG32(input[1]), ARG32(input[2]),
                                        ARG32(input[3]),
                                        output, (void *)outputCount );
                break;
            case 3:
                err = (object->*func)(	reference,
                                        ARG32(input[0]), ARG32(input[1]), ARG32(input[2]),
                                        output, (void *)outputCount, 0 );
                break;
            case 2:
                err = (object->*func)(	reference,
                                        ARG32(input[0]), ARG32(input[1]),
                                        output, (void *)outputCount, 0, 0 );
                break;
            case 1:
                err = (object->*func)(	reference,
                                        ARG32(input[0]),
                                        output, (void *)outputCount, 0, 0, 0 );
                break;
            case 0:
                err = (object->*func)(	reference,
                                        output, (void *)outputCount, 0, 0, 0, 0 );
                break;

            default:
                IOLog("%s: Bad method table\n", object->getName());
        }
    }
    while( false);

    return( err);
}

/* Routine io_connect_method_scalarI_structureI */
kern_return_t is_io_connect_method_scalarI_structureI(
	io_connect_t		connect,
	uint32_t		index,
        io_scalar_inband_t	input,
        mach_msg_type_number_t	inputCount,
        io_struct_inband_t	inputStruct,
        mach_msg_type_number_t	inputStructCount )
{
    uint32_t i;
    io_scalar_inband64_t _input;

    mach_msg_type_number_t scalar_outputCnt = 0;
    mach_msg_type_number_t inband_outputCnt = 0;
    mach_vm_size_t ool_output_size = 0;

    for (i = 0; i < inputCount; i++)
	_input[i] = SCALAR64(input[i]);
	
    return (is_io_connect_method(connect, index, 
		    _input, inputCount, 
		    inputStruct, inputStructCount,
		    0, 0,
		    NULL, &inband_outputCnt,
		    NULL, &scalar_outputCnt,
		    0, &ool_output_size));
}

kern_return_t shim_io_connect_method_scalarI_structureI(
    IOExternalMethod *	method,
    IOService *		object,
        const io_user_scalar_t * input,
        mach_msg_type_number_t	inputCount,
        io_struct_inband_t		inputStruct,
        mach_msg_type_number_t	inputStructCount )
{
    IOMethod		func;
    IOReturn		err = kIOReturnBadArgument;

    do
    {
	if (inputCount != method->count0)
	{
	    IOLog("%s:%d %s: IOUserClient inputCount count mismatch 0x%llx 0x%llx\n", __FUNCTION__, __LINE__, object->getName(), (uint64_t)inputCount, (uint64_t)method->count0);
	    DTRACE_IO2(iokit_count_mismatch, uint64_t, (uint64_t)inputCount, uint64_t, (uint64_t)method->count0);
	    continue;
	}
	if( (kIOUCVariableStructureSize != method->count1)
		&& (inputStructCount != method->count1))
	{
	    IOLog("%s:%d %s: IOUserClient outputCount count mismatch 0x%llx 0x%llx 0x%llx\n", __FUNCTION__, __LINE__, object->getName(), (uint64_t)inputStructCount, (uint64_t)method->count1, (uint64_t)kIOUCVariableStructureSize);
	    DTRACE_IO2(iokit_count_mismatch, uint64_t, (uint64_t)inputStructCount, uint64_t, (uint64_t)method->count1);
	    continue;
	}

	func = method->func;

	switch( inputCount) {

	    case 5:
		err = (object->*func)( ARG32(input[0]), ARG32(input[1]), ARG32(input[2]),
					ARG32(input[3]), ARG32(input[4]), 
					inputStruct );
		break;
	    case 4:
		err = (object->*func)( ARG32(input[0]), ARG32(input[1]), (void *)  input[2],
					ARG32(input[3]),
					inputStruct, (void *)(uintptr_t)inputStructCount );
		break;
	    case 3:
		err = (object->*func)( ARG32(input[0]), ARG32(input[1]), ARG32(input[2]),
					inputStruct, (void *)(uintptr_t)inputStructCount,
					0 );
		break;
	    case 2:
		err = (object->*func)( ARG32(input[0]), ARG32(input[1]),
					inputStruct, (void *)(uintptr_t)inputStructCount,
					0, 0 );
		break;
	    case 1:
		err = (object->*func)( ARG32(input[0]),
					inputStruct, (void *)(uintptr_t)inputStructCount,
					0, 0, 0 );
		break;
	    case 0:
		err = (object->*func)( inputStruct, (void *)(uintptr_t)inputStructCount,
					0, 0, 0, 0 );
		break;

	    default:
		IOLog("%s: Bad method table\n", object->getName());
	}
    }
    while (false);

    return( err);
}

kern_return_t shim_io_async_method_scalarI_structureI(
	IOExternalAsyncMethod *	method,
	IOService *		object,
	mach_port_t             asyncWakePort,
	io_user_reference_t *   asyncReference,
	uint32_t                asyncReferenceCount,
        const io_user_scalar_t * input,
        mach_msg_type_number_t	inputCount,
        io_struct_inband_t		inputStruct,
        mach_msg_type_number_t	inputStructCount )
{
    IOAsyncMethod	func;
    uint32_t		i;
    IOReturn		err = kIOReturnBadArgument;
    io_async_ref_t	reference;

    for (i = 0; i < asyncReferenceCount; i++)
	reference[i] = REF32(asyncReference[i]);

    do
    {
	if (inputCount != method->count0)
	{
	    IOLog("%s:%d %s: IOUserClient inputCount count mismatch 0x%llx 0x%llx\n", __FUNCTION__, __LINE__, object->getName(), (uint64_t)inputCount, (uint64_t)method->count0);
	    DTRACE_IO2(iokit_count_mismatch, uint64_t, (uint64_t)inputCount, uint64_t, (uint64_t)method->count0);
	    continue;
	}
	if( (kIOUCVariableStructureSize != method->count1)
		&& (inputStructCount != method->count1))
	{
	    IOLog("%s:%d %s: IOUserClient outputCount count mismatch 0x%llx 0x%llx 0x%llx\n", __FUNCTION__, __LINE__, object->getName(), (uint64_t)inputStructCount, (uint64_t)method->count1, (uint64_t)kIOUCVariableStructureSize);
	    DTRACE_IO2(iokit_count_mismatch, uint64_t, (uint64_t)inputStructCount, uint64_t, (uint64_t)method->count1);
	    continue;
	}

        func = method->func;

        switch( inputCount) {

            case 5:
                err = (object->*func)(	reference,
                                        ARG32(input[0]), ARG32(input[1]), ARG32(input[2]),
                                        ARG32(input[3]), ARG32(input[4]),
                                        inputStruct );
                break;
            case 4:
                err = (object->*func)(	reference,
                                        ARG32(input[0]), ARG32(input[1]), ARG32(input[2]),
                                        ARG32(input[3]),
                                        inputStruct, (void *)(uintptr_t)inputStructCount );
                break;
            case 3:
                err = (object->*func)(	reference,
                                        ARG32(input[0]), ARG32(input[1]), ARG32(input[2]),
                                        inputStruct, (void *)(uintptr_t)inputStructCount,
                                        0 );
                break;
            case 2:
                err = (object->*func)(	reference,
                                        ARG32(input[0]), ARG32(input[1]),
                                        inputStruct, (void *)(uintptr_t)inputStructCount,
                                        0, 0 );
                break;
            case 1:
                err = (object->*func)(	reference,
                                        ARG32(input[0]),
                                        inputStruct, (void *)(uintptr_t)inputStructCount,
                                        0, 0, 0 );
                break;
            case 0:
                err = (object->*func)(	reference,
                                        inputStruct, (void *)(uintptr_t)inputStructCount,
                                        0, 0, 0, 0 );
                break;

            default:
                IOLog("%s: Bad method table\n", object->getName());
        }
    }
    while (false);

    return( err);
}

/* Routine io_connect_method_structureI_structureO */
kern_return_t is_io_connect_method_structureI_structureO(
	io_object_t	connect,
	uint32_t	index,
        io_struct_inband_t		input,
        mach_msg_type_number_t	inputCount,
        io_struct_inband_t		output,
        mach_msg_type_number_t *	outputCount )
{
    mach_msg_type_number_t scalar_outputCnt = 0;
    mach_vm_size_t ool_output_size = 0;

    return (is_io_connect_method(connect, index, 
		    NULL, 0, 
		    input, inputCount,
		    0, 0,
		    output, outputCount,
		    NULL, &scalar_outputCnt,
		    0, &ool_output_size));
}

kern_return_t shim_io_connect_method_structureI_structureO(
    IOExternalMethod *	method,
    IOService *		object,
        io_struct_inband_t		input,
        mach_msg_type_number_t	inputCount,
        io_struct_inband_t		output,
        IOByteCount *	outputCount )
{
    IOMethod		func;
    IOReturn 		err = kIOReturnBadArgument;

    do 
    {
	if( (kIOUCVariableStructureSize != method->count0)
		&& (inputCount != method->count0))
	{
	    IOLog("%s:%d %s: IOUserClient inputCount count mismatch 0x%llx 0x%llx 0x%llx\n", __FUNCTION__, __LINE__, object->getName(), (uint64_t)inputCount, (uint64_t)method->count0, (uint64_t)kIOUCVariableStructureSize);
	    DTRACE_IO2(iokit_count_mismatch, uint64_t, (uint64_t)inputCount, uint64_t, (uint64_t)method->count0);
	    continue;
	}
	if( (kIOUCVariableStructureSize != method->count1)
		&& (*outputCount != method->count1))
	{
	    IOLog("%s:%d %s: IOUserClient outputCount count mismatch 0x%llx 0x%llx 0x%llx\n", __FUNCTION__, __LINE__, object->getName(), (uint64_t)*outputCount, (uint64_t)method->count1, (uint64_t)kIOUCVariableStructureSize);
	    DTRACE_IO2(iokit_count_mismatch, uint64_t, (uint64_t)*outputCount, uint64_t, (uint64_t)method->count1);
	    continue;
	}

	func = method->func;

	if( method->count1) {
	    if( method->count0) {
		err = (object->*func)( input, output,
					(void *)(uintptr_t)inputCount, outputCount, 0, 0 );
	    } else {
		err = (object->*func)( output, outputCount, 0, 0, 0, 0 );
	    }
	} else {
		err = (object->*func)( input, (void *)(uintptr_t)inputCount, 0, 0, 0, 0 );
	}
    }
    while( false);


    return( err);
}

kern_return_t shim_io_async_method_structureI_structureO(
	IOExternalAsyncMethod *	method,
	IOService *		object,
	mach_port_t           asyncWakePort,
	io_user_reference_t * asyncReference,
	uint32_t              asyncReferenceCount,
        io_struct_inband_t		input,
        mach_msg_type_number_t	inputCount,
        io_struct_inband_t		output,
        mach_msg_type_number_t *	outputCount )
{
    IOAsyncMethod	func;
    uint32_t            i;
    IOReturn 		err;
    io_async_ref_t	reference;

    for (i = 0; i < asyncReferenceCount; i++)
	reference[i] = REF32(asyncReference[i]);

    err = kIOReturnBadArgument;
    do 
    {
	if( (kIOUCVariableStructureSize != method->count0)
		&& (inputCount != method->count0))
	{
	    IOLog("%s:%d %s: IOUserClient inputCount count mismatch 0x%llx 0x%llx 0x%llx\n", __FUNCTION__, __LINE__, object->getName(), (uint64_t)inputCount, (uint64_t)method->count0, (uint64_t)kIOUCVariableStructureSize);
	    DTRACE_IO2(iokit_count_mismatch, uint64_t, (uint64_t)inputCount, uint64_t, (uint64_t)method->count0);
	    continue;
	}
	if( (kIOUCVariableStructureSize != method->count1)
		&& (*outputCount != method->count1))
	{
	    IOLog("%s:%d %s: IOUserClient outputCount count mismatch 0x%llx 0x%llx 0x%llx\n", __FUNCTION__, __LINE__, object->getName(), (uint64_t)*outputCount, (uint64_t)method->count1, (uint64_t)kIOUCVariableStructureSize);
	    DTRACE_IO2(iokit_count_mismatch, uint64_t, (uint64_t)*outputCount, uint64_t, (uint64_t)method->count1);
	    continue;
	}

        func = method->func;

        if( method->count1) {
            if( method->count0) {
                err = (object->*func)( reference,
                                       input, output,
                                        (void *)(uintptr_t)inputCount, outputCount, 0, 0 );
            } else {
                err = (object->*func)( reference,
                                       output, outputCount, 0, 0, 0, 0 );
            }
        } else {
                err = (object->*func)( reference,
                                       input, (void *)(uintptr_t)inputCount, 0, 0, 0, 0 );
        }
    }
    while( false);

    return( err);
}

#if !NO_KEXTD
bool gIOKextdClearedBusy = false;
#endif

/* Routine io_catalog_send_data */
kern_return_t is_io_catalog_send_data(
        mach_port_t		master_port,
        uint32_t                flag,
        io_buf_ptr_t 		inData,
        mach_msg_type_number_t 	inDataCount,
        kern_return_t *		result)
{
    OSObject * obj = 0;
    vm_offset_t data;
    kern_return_t kr = kIOReturnError;

    //printf("io_catalog_send_data called. flag: %d\n", flag);
    
    if( master_port != master_device_port)
        return kIOReturnNotPrivileged;

    if( (flag != kIOCatalogRemoveKernelLinker && 
            flag != kIOCatalogKextdActive &&
            flag != kIOCatalogKextdFinishedLaunching) && 
        ( !inData || !inDataCount) ) 
    {
        return kIOReturnBadArgument;
    }

    if (inData) {
        vm_map_offset_t map_data;

        if( inDataCount > sizeof(io_struct_inband_t) * 1024)
            return( kIOReturnMessageTooLarge);

        kr = vm_map_copyout( kernel_map, &map_data, (vm_map_copy_t)inData);
		data = CAST_DOWN(vm_offset_t, map_data);

        if( kr != KERN_SUCCESS)
            return kr;

        // must return success after vm_map_copyout() succeeds

        if( inDataCount ) {
            obj = (OSObject *)OSUnserializeXML((const char *)data, inDataCount);
            vm_deallocate( kernel_map, data, inDataCount );
            if( !obj) {
                *result = kIOReturnNoMemory;
                return( KERN_SUCCESS);
            }
        }
    }

    switch ( flag ) {
        case kIOCatalogResetDrivers:
        case kIOCatalogResetDriversNoMatch: {
                OSArray * array;

                array = OSDynamicCast(OSArray, obj);
                if (array) {
                   if ( !gIOCatalogue->resetAndAddDrivers(array,
                        flag == kIOCatalogResetDrivers) ) {

                        kr = kIOReturnError;
                    }
                } else {
                    kr = kIOReturnBadArgument;
                }
            }
            break;

        case kIOCatalogAddDrivers: 
        case kIOCatalogAddDriversNoMatch: {
                OSArray * array;

                array = OSDynamicCast(OSArray, obj);
                if ( array ) {
                    if ( !gIOCatalogue->addDrivers( array , 
                                          flag == kIOCatalogAddDrivers) ) {
                        kr = kIOReturnError;
                    }
                }
                else {
                    kr = kIOReturnBadArgument;
                }
            }
            break;

        case kIOCatalogRemoveDrivers: 
        case kIOCatalogRemoveDriversNoMatch: {
                OSDictionary * dict;

                dict = OSDynamicCast(OSDictionary, obj);
                if ( dict ) {
                    if ( !gIOCatalogue->removeDrivers( dict, 
                                          flag == kIOCatalogRemoveDrivers ) ) {
                        kr = kIOReturnError;
                    }
                }
                else {
                    kr = kIOReturnBadArgument;
                }
            }
            break;

        case kIOCatalogStartMatching: {
                OSDictionary * dict;

                dict = OSDynamicCast(OSDictionary, obj);
                if ( dict ) {
                    if ( !gIOCatalogue->startMatching( dict ) ) {
                        kr = kIOReturnError;
                    }
                }
                else {
                    kr = kIOReturnBadArgument;
                }
            }
            break;

        case kIOCatalogRemoveKernelLinker:
            kr = KERN_NOT_SUPPORTED;
            break;

        case kIOCatalogKextdActive:
#if !NO_KEXTD
            IOServiceTrace(IOSERVICE_KEXTD_ALIVE, 0, 0, 0, 0);
            OSKext::setKextdActive();

           /* Dump all nonloaded startup extensions; kextd will now send them
            * down on request.
            */
            OSKext::flushNonloadedKexts( /* flushPrelinkedKexts */ false);
#endif
            kr = kIOReturnSuccess;
            break;

        case kIOCatalogKextdFinishedLaunching: {
#if !NO_KEXTD
                if (!gIOKextdClearedBusy) {
                    IOService * serviceRoot = IOService::getServiceRoot();
                    if (serviceRoot) {
                        IOServiceTrace(IOSERVICE_KEXTD_READY, 0, 0, 0, 0);
                        serviceRoot->adjustBusy(-1);
                        gIOKextdClearedBusy = true;
                    }
                }
#endif
                kr = kIOReturnSuccess;
            }
            break;

        default:
            kr = kIOReturnBadArgument;
            break;
    }

    if (obj) obj->release();
    
    *result = kr;
    return( KERN_SUCCESS);
}

/* Routine io_catalog_terminate */
kern_return_t is_io_catalog_terminate(
	mach_port_t master_port,
	uint32_t flag,
	io_name_t name )
{
    kern_return_t	   kr;

    if( master_port != master_device_port )
        return kIOReturnNotPrivileged;

    kr = IOUserClient::clientHasPrivilege( (void *) current_task(),
                                            kIOClientPrivilegeAdministrator );
    if( kIOReturnSuccess != kr)
        return( kr );

    switch ( flag ) {
#if !defined(SECURE_KERNEL)
        case kIOCatalogServiceTerminate:
            OSIterator *	iter;
            IOService *		service;

            iter = IORegistryIterator::iterateOver(gIOServicePlane,
                                        kIORegistryIterateRecursively);
            if ( !iter )
                return kIOReturnNoMemory;

            do {
                iter->reset();
                while( (service = (IOService *)iter->getNextObject()) ) {
                    if( service->metaCast(name)) {
                        if ( !service->terminate( kIOServiceRequired
                                                | kIOServiceSynchronous) ) {
                            kr = kIOReturnUnsupported;
                            break;
                        }
                    }
                }
            } while( !service && !iter->isValid());
            iter->release();
            break;

        case kIOCatalogModuleUnload:
        case kIOCatalogModuleTerminate:
            kr = gIOCatalogue->terminateDriversForModule(name,
                                        flag == kIOCatalogModuleUnload);
            break;
#endif

        default:
            kr = kIOReturnBadArgument;
            break;
    }

    return( kr );
}

/* Routine io_catalog_get_data */
kern_return_t is_io_catalog_get_data(
        mach_port_t		master_port,
        uint32_t                flag,
        io_buf_ptr_t 		*outData,
        mach_msg_type_number_t 	*outDataCount)
{
    kern_return_t kr = kIOReturnSuccess;
    OSSerialize * s;
    
    if( master_port != master_device_port)
        return kIOReturnNotPrivileged;

    //printf("io_catalog_get_data called. flag: %d\n", flag);
    
    s = OSSerialize::withCapacity(4096);
    if ( !s )
        return kIOReturnNoMemory;

    kr = gIOCatalogue->serializeData(flag, s);

    if ( kr == kIOReturnSuccess ) {
        vm_offset_t data;
        vm_map_copy_t copy;
        vm_size_t size;

        size = s->getLength();
        kr = vm_allocate(kernel_map, &data, size, VM_FLAGS_ANYWHERE);
        if ( kr == kIOReturnSuccess ) {
            bcopy(s->text(), (void *)data, size);
            kr = vm_map_copyin(kernel_map, (vm_map_address_t)data,
			       (vm_map_size_t)size, true, &copy);
            *outData = (char *)copy;
            *outDataCount = size;
        }
    }

    s->release();

    return kr;
}

/* Routine io_catalog_get_gen_count */
kern_return_t is_io_catalog_get_gen_count(
        mach_port_t		master_port,
        uint32_t                *genCount)
{
    if( master_port != master_device_port)
        return kIOReturnNotPrivileged;

    //printf("io_catalog_get_gen_count called.\n");

    if ( !genCount )
        return kIOReturnBadArgument;

    *genCount = gIOCatalogue->getGenerationCount();
    
    return kIOReturnSuccess;
}

/* Routine io_catalog_module_loaded.
 * Is invoked from IOKitLib's IOCatalogueModuleLoaded(). Doesn't seem to be used.
 */
kern_return_t is_io_catalog_module_loaded(
        mach_port_t		master_port,
        io_name_t               name)
{
    if( master_port != master_device_port)
        return kIOReturnNotPrivileged;

    //printf("io_catalog_module_loaded called. name %s\n", name);
    
    if ( !name )
        return kIOReturnBadArgument;
    
    gIOCatalogue->moduleHasLoaded(name);
    
    return kIOReturnSuccess;
}

kern_return_t is_io_catalog_reset(
	mach_port_t		master_port,
	uint32_t		flag)
{
    if( master_port != master_device_port)
        return kIOReturnNotPrivileged;

    switch ( flag ) {
        case kIOCatalogResetDefault:
            gIOCatalogue->reset();
            break;

        default:
            return kIOReturnBadArgument;
    }
    
    return kIOReturnSuccess;
}

kern_return_t iokit_user_client_trap(struct iokit_user_client_trap_args *args)
{
    kern_return_t result = kIOReturnBadArgument;
    IOUserClient *userClient;

    if ((userClient = OSDynamicCast(IOUserClient,
            iokit_lookup_connect_ref_current_task((OSObject *)(args->userClientRef))))) {
        IOExternalTrap *trap;
        IOService *target = NULL;

        trap = userClient->getTargetAndTrapForIndex(&target, args->index);

        if (trap && target) {
            IOTrap func;

            func = trap->func;

            if (func) {
                result = (target->*func)(args->p1, args->p2, args->p3, args->p4, args->p5, args->p6);
            }
        }

	iokit_remove_connect_reference(userClient);
    }

    return result;
}

} /* extern "C" */

IOReturn IOUserClient::externalMethod( uint32_t selector, IOExternalMethodArguments * args,
					IOExternalMethodDispatch * dispatch, OSObject * target, void * reference )
{
    IOReturn    err;
    IOService * object;
    IOByteCount structureOutputSize;

    if (dispatch)
    {
	uint32_t count;
	count = dispatch->checkScalarInputCount;
	if ((kIOUCVariableStructureSize != count) && (count != args->scalarInputCount))
	{
	    return (kIOReturnBadArgument);
	}

	count = dispatch->checkStructureInputSize;
	if ((kIOUCVariableStructureSize != count) 
	    && (count != ((args->structureInputDescriptor) 
			    ? args->structureInputDescriptor->getLength() : args->structureInputSize)))
	{
	    return (kIOReturnBadArgument);
	}

	count = dispatch->checkScalarOutputCount;
	if ((kIOUCVariableStructureSize != count) && (count != args->scalarOutputCount))
	{
	    return (kIOReturnBadArgument);
	}

	count = dispatch->checkStructureOutputSize;
	if ((kIOUCVariableStructureSize != count) 
	    && (count != ((args->structureOutputDescriptor) 
			    ? args->structureOutputDescriptor->getLength() : args->structureOutputSize)))
	{
	    return (kIOReturnBadArgument);
	}

	if (dispatch->function)
	    err = (*dispatch->function)(target, reference, args);
	else
	    err = kIOReturnNoCompletion;	    /* implementator can dispatch */

	return (err);
    }


    // pre-Leopard API's don't do ool structs
    if (args->structureInputDescriptor || args->structureOutputDescriptor)
    {
       err = kIOReturnIPCError;
       return (err);
    }

    structureOutputSize = args->structureOutputSize;

    if (args->asyncWakePort)
    {
	IOExternalAsyncMethod *	method;
	object = 0;
	if( !(method = getAsyncTargetAndMethodForIndex(&object, selector)) || !object )
	    return (kIOReturnUnsupported);

    if (kIOUCForegroundOnly & method->flags)
    {
	if (task_is_gpu_denied(current_task()))
            return (kIOReturnNotPermitted);
    }

	switch (method->flags & kIOUCTypeMask)
	{
	    case kIOUCScalarIStructI:
		err = shim_io_async_method_scalarI_structureI( method, object,
					args->asyncWakePort, args->asyncReference, args->asyncReferenceCount,
					args->scalarInput, args->scalarInputCount,
					(char *)args->structureInput, args->structureInputSize );
		break;

	    case kIOUCScalarIScalarO:
		err = shim_io_async_method_scalarI_scalarO( method, object,
					args->asyncWakePort, args->asyncReference, args->asyncReferenceCount,
					args->scalarInput, args->scalarInputCount,
					args->scalarOutput, &args->scalarOutputCount );
		break;

	    case kIOUCScalarIStructO:
		err = shim_io_async_method_scalarI_structureO( method, object,
					args->asyncWakePort, args->asyncReference, args->asyncReferenceCount,
					args->scalarInput, args->scalarInputCount,
					(char *) args->structureOutput, &args->structureOutputSize );
		break;


	    case kIOUCStructIStructO:
		err = shim_io_async_method_structureI_structureO( method, object,
					args->asyncWakePort, args->asyncReference, args->asyncReferenceCount,
					(char *)args->structureInput, args->structureInputSize,
					(char *) args->structureOutput, &args->structureOutputSize );
		break;

	    default:
		err = kIOReturnBadArgument;
		break;
	}
    }
    else
    {
	IOExternalMethod *	method;
	object = 0;
	if( !(method = getTargetAndMethodForIndex(&object, selector)) || !object )
	    return (kIOReturnUnsupported);

    if (kIOUCForegroundOnly & method->flags)
    {
	if (task_is_gpu_denied(current_task()))
            return (kIOReturnNotPermitted);
    }

	switch (method->flags & kIOUCTypeMask)
	{
	    case kIOUCScalarIStructI:
		err = shim_io_connect_method_scalarI_structureI( method, object,
					args->scalarInput, args->scalarInputCount,
					(char *) args->structureInput, args->structureInputSize );
		break;

	    case kIOUCScalarIScalarO:
		err = shim_io_connect_method_scalarI_scalarO( method, object,
					args->scalarInput, args->scalarInputCount,
					args->scalarOutput, &args->scalarOutputCount );
		break;

	    case kIOUCScalarIStructO:
		err = shim_io_connect_method_scalarI_structureO( method, object,
					args->scalarInput, args->scalarInputCount,
					(char *) args->structureOutput, &structureOutputSize );
		break;


	    case kIOUCStructIStructO:
		err = shim_io_connect_method_structureI_structureO( method, object,
					(char *) args->structureInput, args->structureInputSize,
					(char *) args->structureOutput, &structureOutputSize );
		break;

	    default:
		err = kIOReturnBadArgument;
		break;
	}
    }

    args->structureOutputSize = structureOutputSize;

    return (err);
}

#if __LP64__
OSMetaClassDefineReservedUnused(IOUserClient, 0);
OSMetaClassDefineReservedUnused(IOUserClient, 1);
#else
OSMetaClassDefineReservedUsed(IOUserClient, 0);
OSMetaClassDefineReservedUsed(IOUserClient, 1);
#endif
OSMetaClassDefineReservedUnused(IOUserClient, 2);
OSMetaClassDefineReservedUnused(IOUserClient, 3);
OSMetaClassDefineReservedUnused(IOUserClient, 4);
OSMetaClassDefineReservedUnused(IOUserClient, 5);
OSMetaClassDefineReservedUnused(IOUserClient, 6);
OSMetaClassDefineReservedUnused(IOUserClient, 7);
OSMetaClassDefineReservedUnused(IOUserClient, 8);
OSMetaClassDefineReservedUnused(IOUserClient, 9);
OSMetaClassDefineReservedUnused(IOUserClient, 10);
OSMetaClassDefineReservedUnused(IOUserClient, 11);
OSMetaClassDefineReservedUnused(IOUserClient, 12);
OSMetaClassDefineReservedUnused(IOUserClient, 13);
OSMetaClassDefineReservedUnused(IOUserClient, 14);
OSMetaClassDefineReservedUnused(IOUserClient, 15);

