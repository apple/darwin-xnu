/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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


#include <IOKit/IOKitServer.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOService.h>
#include <IOKit/IOService.h>
#include <IOKit/IORegistryEntry.h>
#include <IOKit/IOCatalogue.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOLib.h>

#include <IOKit/assert.h>

#include "IOServicePrivate.h"

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

extern io_object_t iokit_lookup_connect_ref(io_object_t clientRef, ipc_space_t task);

extern io_object_t iokit_lookup_connect_ref_current_task(io_object_t clientRef);

extern ipc_port_t master_device_port;

extern void iokit_retain_port( ipc_port_t port );
extern void iokit_release_port( ipc_port_t port );

extern kern_return_t iokit_switch_object_port( ipc_port_t port, io_object_t obj, ipc_kobject_type_t type );

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

    virtual void free();
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
    bool		destroyed = true;

    IOTakeLock( gIOObjectPortLock);

    if( (dict = dictForType( type ))) {
        obj->retain();

	machPort = (IOMachPort *) dict->getObject( (const OSSymbol *) obj );
	if( machPort) {
	    destroyed = (machPort->mscount == *mscount);
	    if( destroyed)
		dict->removeObject( (const OSSymbol *) obj );
	    else
		*mscount = machPort->mscount;
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
	    if ((uc = OSDynamicCast(IOUserClient, obj)) && uc->mappings)
	    {
		dict->setObject((const OSSymbol *) uc->mappings, port);
		iokit_switch_object_port(port->port, uc->mappings, IKOT_IOKIT_CONNECT);

		uc->mappings->release();
		uc->mappings = 0;
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

class IOUserNotification : public OSIterator
{
    OSDeclareDefaultStructors(IOUserNotification)

    IONotifier 	* 	holdNotify;
    IOLock 	*	lock;

public:

    virtual bool init( void );
    virtual void free();

    virtual void setNotification( IONotifier * obj );

    virtual void reset();
    virtual bool isValid();
};

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
	    client->clientDied();
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
        OSNotificationHeader		notifyHeader;
    };

    enum { kMaxOutstanding = 1024 };

    PingMsg *		pingMsg;
    vm_size_t		msgSize;
    OSArray 	*	newSet;
    OSObject	*	lastEntry;
    bool		armed;

public:

    virtual bool init( mach_port_t port, natural_t type,
                       OSAsyncReference reference );
    virtual void free();

    static bool _handler( void * target,
                          void * ref, IOService * newService );
    virtual bool handler( void * ref, IOService * newService );

    virtual OSObject * getNextObject();
};

class IOServiceMessageUserNotification : public IOUserNotification
{
    OSDeclareDefaultStructors(IOServiceMessageUserNotification)

    struct PingMsg {
        mach_msg_header_t		msgHdr;
	mach_msg_body_t			msgBody;
	mach_msg_port_descriptor_t	ports[1];
        OSNotificationHeader		notifyHeader;
    };

    PingMsg *		pingMsg;
    vm_size_t		msgSize;

public:

    virtual bool init( mach_port_t port, natural_t type,
                       OSAsyncReference reference, vm_size_t extraSize );
    virtual void free();
    
    static IOReturn _handler( void * target, void * ref,
                              UInt32 messageType, IOService * provider,
                              void * messageArgument, vm_size_t argSize );
    virtual IOReturn handler( void * ref,
                              UInt32 messageType, IOService * provider,
                              void * messageArgument, vm_size_t argSize );

    virtual OSObject * getNextObject();
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super OSIterator
OSDefineMetaClass( IOUserNotification, OSIterator )
OSDefineAbstractStructors( IOUserNotification, OSIterator )

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool IOUserNotification::init( void )
{
    if( !super::init())
	return( false );

    lock = IOLockAlloc();
    if( !lock)
        return( false );

    return( true );
}

void IOUserNotification::free( void )
{
    if( holdNotify)
	holdNotify->remove();
    // can't be in handler now

    if( lock)
	IOLockFree( lock );

    super::free();
}


void IOUserNotification::setNotification( IONotifier * notify )
{
    IONotifier * previousNotify;

    IOLockLock( gIOObjectPortLock);

    previousNotify = holdNotify;
    holdNotify = notify;

    IOLockUnlock( gIOObjectPortLock);

    if( previousNotify)
	previousNotify->remove();
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
                                OSAsyncReference reference )
{
    newSet = OSArray::withCapacity( 1 );
    if( !newSet)
        return( false );

    msgSize = sizeof( PingMsg) + 0;
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
    bcopy( reference, pingMsg->notifyHeader.reference, sizeof(OSAsyncReference) );

    return( super::init() );
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

    if( _pingMsg && _msgSize)
        IOFree( _pingMsg, _msgSize);

    if( _lastEntry)
        _lastEntry->release();

    if( _newSet)
        _newSet->release();
}

bool IOServiceUserNotification::_handler( void * target,
                                    void * ref, IOService * newService )
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

        kr = mach_msg_send_from_kernel( &pingMsg->msgHdr,
                                        pingMsg->msgHdr.msgh_size);
	if( port)
	    iokit_release_port( port );

        if( KERN_SUCCESS != kr)
            IOLog("%s: mach_msg_send_from_kernel {%x}\n", __FILE__, kr );
    }

    return( true );
}

OSObject * IOServiceUserNotification::getNextObject()
{
    unsigned int	count;
    OSObject *		result;

    IOTakeLock( lock );

    if( lastEntry)
        lastEntry->release();

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

    IOUnlock( lock );

    return( result );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSDefineMetaClassAndStructors(IOServiceMessageUserNotification, IOUserNotification)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool IOServiceMessageUserNotification::init( mach_port_t port, natural_t type,
                       OSAsyncReference reference, vm_size_t extraSize )
{

    extraSize += sizeof(IOServiceInterestContent);
    msgSize = sizeof( PingMsg) + extraSize;
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
    bcopy( reference, pingMsg->notifyHeader.reference, sizeof(OSAsyncReference) );

    return( super::init() );
}

void IOServiceMessageUserNotification::free( void )
{
    PingMsg *	_pingMsg;
    vm_size_t	_msgSize;

    _pingMsg   = pingMsg;
    _msgSize   = msgSize;

    super::free();

    if( _pingMsg && _msgSize)
        IOFree( _pingMsg, _msgSize);
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
                                    void * messageArgument, vm_size_t argSize )
{
    kern_return_t		kr;
    ipc_port_t 			thisPort, providerPort;
    IOServiceInterestContent * 	data = (IOServiceInterestContent *)
                                       pingMsg->notifyHeader.content;

    data->messageType = messageType;
    if( argSize == 0) {
        argSize = sizeof( messageArgument);
        data->messageArgument[0] = messageArgument;
    } else {
        if( argSize > kIOUserNotifyMaxMessageSize)
            argSize = kIOUserNotifyMaxMessageSize;
        bcopy( messageArgument, data->messageArgument, argSize );
    }
    pingMsg->msgHdr.msgh_size = sizeof( PingMsg)
        + sizeof( IOServiceInterestContent )
        - sizeof( data->messageArgument)
        + argSize;

    providerPort = iokit_port_for_object( provider, IKOT_IOKIT_OBJECT );
    pingMsg->ports[0].name = providerPort;
    thisPort = iokit_port_for_object( this, IKOT_IOKIT_OBJECT );
    pingMsg->msgHdr.msgh_local_port = thisPort;
    kr = mach_msg_send_from_kernel( &pingMsg->msgHdr,
				    pingMsg->msgHdr.msgh_size);
    if( thisPort)
	iokit_release_port( thisPort );
    if( providerPort)
	iokit_release_port( providerPort );

    if( KERN_SUCCESS != kr)
        IOLog("%s: mach_msg_send_from_kernel {%x}\n", __FILE__, kr );

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

void IOUserClient::initialize( void )
{
    gIOObjectPortLock = IOLockAlloc();

    assert( gIOObjectPortLock );
}

void IOUserClient::setAsyncReference(OSAsyncReference asyncRef,
                                     mach_port_t wakePort,
                                     void *callback, void *refcon)
{
    asyncRef[kIOAsyncReservedIndex] = (natural_t) wakePort;
    asyncRef[kIOAsyncCalloutFuncIndex] = (natural_t) callback;
    asyncRef[kIOAsyncCalloutRefconIndex] = (natural_t) refcon;
}

IOReturn IOUserClient::clientHasPrivilege( void * securityToken,
                                            const char * privilegeName )
{
    kern_return_t	   kr;
    security_token_t	   token;
    mach_msg_type_number_t count;

    count = TASK_SECURITY_TOKEN_COUNT;
    kr = task_info( (task_t) securityToken, TASK_SECURITY_TOKEN,
		    (task_info_t) &token, &count );

    if (KERN_SUCCESS != kr)
    {}
    else if (!strcmp(privilegeName, kIOClientPrivilegeAdministrator))
    {
	if (0 != token.val[0])
	    kr = kIOReturnNotPrivileged;
    }
    else if (!strcmp(privilegeName, kIOClientPrivilegeLocalUser))
    {
	OSArray *      array;
	OSDictionary * user = 0;

	if ((array = OSDynamicCast(OSArray,
	    IORegistryEntry::getRegistryRoot()->copyProperty(gIOConsoleUsersKey))))
	{
	    for (unsigned int idx = 0;
		    (user = OSDynamicCast(OSDictionary, array->getObject(idx)));
		    idx++)
	    {
		OSNumber * num;
		if ((num = OSDynamicCast(OSNumber, user->getObject(gIOConsoleSessionUIDKey)))
		  && (token.val[0] == num->unsigned32BitValue()))
		    break;
	    }
	    array->release();
	}
	if (!user)
	    kr = kIOReturnNotPrivileged;
    }
    else
	kr = kIOReturnUnsupported;

    return (kr);
}

bool IOUserClient::initWithTask(task_t owningTask,
                                void * securityID,
                                UInt32 type )
{
    if( getPropertyTable())
        return true;
    else
        return super::init();
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

void IOUserClient::free()
{
    if( mappings)
        mappings->release();

    super::free();
}

IOReturn IOUserClient::clientDied( void )
{
    return( clientClose());
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

IOMemoryMap * IOUserClient::mapClientMemory( 
	IOOptionBits		type,
	task_t			task,
	IOOptionBits		mapFlags,
	IOVirtualAddress	atAddress )
{
    IOReturn		err;
    IOOptionBits	options = 0;
    IOMemoryDescriptor * memory;
    IOMemoryMap *	map = 0;

    err = clientMemoryForType( (UInt32) type, &options, &memory );

    if( memory && (kIOReturnSuccess == err)) {

        options = (options & ~kIOMapUserOptionsMask)
		| (mapFlags & kIOMapUserOptionsMask);
	map = memory->map( task, atAddress, options );
	memory->release();
    }

    return( map );
}

IOReturn IOUserClient::exportObjectToClient(task_t task,
			OSObject *obj, io_object_t *clientObj)
{
    mach_port_name_t	name;

    name = IOMachPort::makeSendRightForTask( task, obj, IKOT_IOKIT_OBJECT );
    assert( name );

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
getExternalTrapForIndex(UInt32 index)
{
	return NULL;
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

IOReturn IOUserClient::sendAsyncResult(OSAsyncReference reference,
                                       IOReturn result, void *args[], UInt32 numArgs)
{
    struct ReplyMsg {
        mach_msg_header_t	msgHdr;
        OSNotificationHeader	notifyHdr;
        IOAsyncCompletionContent asyncContent;
        void *			args[kMaxAsyncArgs];
    };
    ReplyMsg replyMsg;
    mach_port_t	replyPort;
    kern_return_t kr;

    // If no reply port, do nothing.
    replyPort = (mach_port_t) reference[0];
    if(replyPort == MACH_PORT_NULL)
        return kIOReturnSuccess;
    
    if(numArgs > kMaxAsyncArgs)
        return kIOReturnMessageTooLarge;
    replyMsg.msgHdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND /*remote*/,
                                                0 /*local*/);
    replyMsg.msgHdr.msgh_size =
        sizeof(replyMsg) - (kMaxAsyncArgs-numArgs)*sizeof(void *);
    replyMsg.msgHdr.msgh_remote_port = replyPort;
    replyMsg.msgHdr.msgh_local_port = 0;
    replyMsg.msgHdr.msgh_id = kOSNotificationMessageID;

    replyMsg.notifyHdr.size = sizeof(IOAsyncCompletionContent)
                            + numArgs*sizeof(void *);
    replyMsg.notifyHdr.type = kIOAsyncCompletionNotificationType;
    bcopy( reference, replyMsg.notifyHdr.reference, sizeof(OSAsyncReference));

    replyMsg.asyncContent.result = result;
    if(numArgs > 0)
        bcopy(args, replyMsg.args, sizeof(void *)*numArgs);
     kr = mach_msg_send_from_kernel( &replyMsg.msgHdr,
            replyMsg.msgHdr.msgh_size);
    if( KERN_SUCCESS != kr)
        IOLog("%s: mach_msg_send_from_kernel {%x}\n", __FILE__, kr );
    return kr;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

extern "C" {

#define CHECK(cls,obj,out)			\
	cls * out;				\
	if( !(out = OSDynamicCast( cls, obj)))	\
	    return( kIOReturnBadArgument )

/* Routine io_object_get_class */
kern_return_t is_io_object_get_class(
	io_object_t object,
	io_name_t className )
{
    if( !object)
        return( kIOReturnBadArgument );

    strcpy( className, object->getMetaClass()->getClassName());
    return( kIOReturnSuccess );
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
	int *retainCount )
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
    OSObject *	obj;

    CHECK( OSIterator, iterator, iter );

    obj = iter->getNextObject();
    if( obj) {
	obj->retain();
	*object = obj;
        return( kIOReturnSuccess );
    } else
        return( kIOReturnNoDevice );
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

/* Routine io_service_match_property_table */
kern_return_t is_io_service_match_property_table(
	io_service_t _service,
	io_string_t matching,
	boolean_t *matches )
{
    CHECK( IOService, _service, service );

    kern_return_t	kr;
    OSObject *		obj;
    OSDictionary *	dict;

    obj = OSUnserializeXML( matching );

    if( (dict = OSDynamicCast( OSDictionary, obj))) {
        *matches = service->passiveMatch( dict );
	kr = kIOReturnSuccess;
    } else
	kr = kIOReturnBadArgument;

    if( obj)
        obj->release();

    return( kr );
}

/* Routine io_service_match_property_table_ool */
kern_return_t is_io_service_match_property_table_ool(
	io_object_t service,
	io_buf_ptr_t matching,
	mach_msg_type_number_t matchingCnt,
	natural_t *result,
	boolean_t *matches )
{
    kern_return_t	kr;
    vm_offset_t 	data;

    kr = vm_map_copyout( kernel_map, &data, (vm_map_copy_t) matching );

    if( KERN_SUCCESS == kr) {
        // must return success after vm_map_copyout() succeeds
	*result = is_io_service_match_property_table( service,
		(char *) data, matches );
	vm_deallocate( kernel_map, data, matchingCnt );
    }

    return( kr );
}

/* Routine io_service_get_matching_services */
kern_return_t is_io_service_get_matching_services(
	mach_port_t master_port,
	io_string_t matching,
	io_iterator_t *existing )
{
    kern_return_t	kr;
    OSObject *		obj;
    OSDictionary *	dict;

    if( master_port != master_device_port)
        return( kIOReturnNotPrivileged);

    obj = OSUnserializeXML( matching );

    if( (dict = OSDynamicCast( OSDictionary, obj))) {
        *existing = IOService::getMatchingServices( dict );
	kr = kIOReturnSuccess;
    } else
	kr = kIOReturnBadArgument;

    if( obj)
        obj->release();

    return( kr );
}

/* Routine io_service_get_matching_services_ool */
kern_return_t is_io_service_get_matching_services_ool(
	mach_port_t master_port,
	io_buf_ptr_t matching,
	mach_msg_type_number_t matchingCnt,
	natural_t *result,
	io_object_t *existing )
{
    kern_return_t	kr;
    vm_offset_t 	data;

    kr = vm_map_copyout( kernel_map, &data, (vm_map_copy_t) matching );

    if( KERN_SUCCESS == kr) {
        // must return success after vm_map_copyout() succeeds
	*result = is_io_service_get_matching_services( master_port,
			(char *) data, existing );
	vm_deallocate( kernel_map, data, matchingCnt );
    }

    return( kr );
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

        if( !(dict = OSDynamicCast( OSDictionary,
                    OSUnserializeXML( matching )))) {
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
                                             reference)) {
            userNotify->release();
            userNotify = 0;
        }
        if( !userNotify)
	    continue;

        notify = IOService::addNotification( sym, dict,
                                             &userNotify->_handler, userNotify );
	if( notify) {
            dict = 0;
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

/* Routine io_service_add_notification_ool */
kern_return_t is_io_service_add_notification_ool(
	mach_port_t master_port,
	io_name_t notification_type,
	io_buf_ptr_t matching,
	mach_msg_type_number_t matchingCnt,
	mach_port_t wake_port,
	io_async_ref_t reference,
	mach_msg_type_number_t referenceCnt,
	natural_t *result,
	io_object_t *notification )
{
    kern_return_t	kr;
    vm_offset_t 	data;

    kr = vm_map_copyout( kernel_map, &data, (vm_map_copy_t) matching );

    if( KERN_SUCCESS == kr) {
        // must return success after vm_map_copyout() succeeds
	*result = is_io_service_add_notification( master_port, notification_type,
			(char *) data, wake_port, reference, referenceCnt, notification );
	vm_deallocate( kernel_map, data, matchingCnt );
    }

    return( kr );
}


/* Routine io_service_add_notification_old */
kern_return_t is_io_service_add_notification_old(
	mach_port_t master_port,
	io_name_t notification_type,
	io_string_t matching,
	mach_port_t port,
	natural_t ref,
	io_object_t * notification )
{
    return( is_io_service_add_notification( master_port, notification_type,
            matching, port, &ref, 1, notification ));
}

/* Routine io_service_add_message_notification */
kern_return_t is_io_service_add_interest_notification(
        io_object_t _service,
        io_name_t type_of_interest,
        mach_port_t port,
	io_async_ref_t reference,
	mach_msg_type_number_t referenceCnt,
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
                                             reference, kIOUserNotifyMaxMessageSize )) {
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

/* Routine io_service_acknowledge_notification */
kern_return_t is_io_service_acknowledge_notification(
	io_object_t _service,
	natural_t notify_ref,
	natural_t response )
{
    CHECK( IOService, _service, service );

    return( service->acknowledgeNotification( (IONotificationRef) notify_ref,
                                              (IOOptionBits) response ));
    
}

/* Routine io_connect_get_semaphore */
kern_return_t is_io_connect_get_notification_semaphore(
	io_connect_t connection,
	natural_t notification_type,
	semaphore_t *semaphore )
{
    CHECK( IOUserClient, connection, client );

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
	int options,
	io_object_t *iterator )
{
    if( master_port != master_device_port)
        return( kIOReturnNotPrivileged);

    *iterator = IORegistryIterator::iterateOver(
	IORegistryEntry::getPlane( plane ), options );

    return( *iterator ? kIOReturnSuccess : kIOReturnBadArgument );
}

/* Routine io_registry_entry_create_iterator */
kern_return_t is_io_registry_entry_create_iterator(
	io_object_t registry_entry,
	io_name_t plane,
	int options,
	io_object_t *iterator )
{
    CHECK( IORegistryEntry, registry_entry, entry );

    *iterator = IORegistryIterator::iterateOver( entry,
	IORegistryEntry::getPlane( plane ), options );

    return( *iterator ? kIOReturnSuccess : kIOReturnBadArgument );
}

/* Routine io_registry_iterator_enter */
kern_return_t is_io_registry_iterator_enter_entry(
	io_object_t iterator )
{
    CHECK( IORegistryIterator, iterator, iter );

    iter->enterEntry();

    return( kIOReturnSuccess );
}

/* Routine io_registry_iterator_exit */
kern_return_t is_io_registry_iterator_exit_entry(
	io_object_t iterator )
{
    bool	didIt;

    CHECK( IORegistryIterator, iterator, iter );

    didIt = iter->exitEntry();

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

// Create a vm_map_copy_t or kalloc'ed data for memory
// to be copied out. ipc will free after the copyout.

static kern_return_t copyoutkdata( void * data, vm_size_t len,
                                    io_buf_ptr_t * buf )
{
    kern_return_t	err;
    vm_map_copy_t	copy;

    err = vm_map_copyin( kernel_map, (vm_offset_t) data, len,
                    false /* src_destroy */, &copy);

    assert( err == KERN_SUCCESS );
    if( err == KERN_SUCCESS )
        *buf = (char *) copy;

    return( err );
}

/* Routine io_registry_entry_get_property */
kern_return_t is_io_registry_entry_get_property_bytes(
	io_object_t registry_entry,
	io_name_t property_name,
	io_scalar_inband_t buf,
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

    obj = entry->copyProperty(property_name);
    if( !obj)
        return( kIOReturnNotFound );

    OSSerialize * s = OSSerialize::withCapacity(4096);
    if( !s) {
        obj->release();
	return( kIOReturnNoMemory );
    }
    s->clearText();

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
        int options,
	io_buf_ptr_t *properties,
	mach_msg_type_number_t *propertiesCnt )
{
    kern_return_t	err;
    vm_size_t 		len;
    OSObject *		obj;

    CHECK( IORegistryEntry, registry_entry, entry );

    obj = entry->copyProperty( property_name,
                               IORegistryEntry::getPlane( plane ), options);
    if( !obj)
        return( kIOReturnNotFound );

    OSSerialize * s = OSSerialize::withCapacity(4096);
    if( !s) {
        obj->release();
	return( kIOReturnNoMemory );
    }

    s->clearText();

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
    kern_return_t	err;
    vm_size_t 		len;

    CHECK( IORegistryEntry, registry_entry, entry );

    OSSerialize * s = OSSerialize::withCapacity(4096);
    if( !s)
	return( kIOReturnNoMemory );

    s->clearText();

    if( entry->serializeProperties( s )) {
        len = s->getLength();
        *propertiesCnt = len;
        err = copyoutkdata( s->text(), len, properties );

    } else
        err = kIOReturnUnsupported;

    s->release();

    return( err );
}

/* Routine io_registry_entry_set_properties */
kern_return_t is_io_registry_entry_set_properties
(
	io_object_t registry_entry,
	io_buf_ptr_t properties,
	mach_msg_type_number_t propertiesCnt,
        natural_t * result)
{
    OSObject *		obj;
    kern_return_t	err;
    IOReturn		res;
    vm_offset_t 	data;

    CHECK( IORegistryEntry, registry_entry, entry );

    err = vm_map_copyout( kernel_map, &data, (vm_map_copy_t) properties );

    if( KERN_SUCCESS == err) {

        // must return success after vm_map_copyout() succeeds
        obj = OSUnserializeXML( (const char *) data );
	vm_deallocate( kernel_map, data, propertiesCnt );

        if( obj) {
            res = entry->setProperties( obj );
            obj->release();
        } else
            res = kIOReturnBadArgument;
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
	int *busyState )
{
    CHECK( IOService, _service, service );

    *busyState = service->getBusyState();

    return( kIOReturnSuccess );
}

/* Routine io_service_get_state */
kern_return_t is_io_service_get_state(
	io_object_t _service,
	uint64_t *state )
{
    CHECK( IOService, _service, service );

    *state = service->getState();

    return( kIOReturnSuccess );
}

/* Routine io_service_wait_quiet */
kern_return_t is_io_service_wait_quiet(
	io_object_t _service,
	mach_timespec_t wait_time )
{
    CHECK( IOService, _service, service );

    return( service->waitQuiet( &wait_time ));
}

/* Routine io_service_request_probe */
kern_return_t is_io_service_request_probe(
	io_object_t _service,
	int options )
{
    CHECK( IOService, _service, service );

    return( service->requestProbe( options ));
}


/* Routine io_service_open */
kern_return_t is_io_service_open(
	io_object_t _service,
	task_t owningTask,
	int connect_type,
	io_object_t *connection )
{
    IOUserClient	*	client;
    IOReturn 			err;

    CHECK( IOService, _service, service );

    err = service->newUserClient( owningTask, (void *) owningTask,
		connect_type, &client );

    if( err == kIOReturnSuccess) {
	assert( OSDynamicCast(IOUserClient, client) );
	*connection = client;
    }

    return( err);
}

/* Routine io_service_close */
kern_return_t is_io_service_close(
	io_object_t connection )
{
    OSSet * mappings;
    if ((mappings = OSDynamicCast(OSSet, connection)))
	return( kIOReturnSuccess );

    CHECK( IOUserClient, connection, client );

    client->clientClose();

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
	int notification_type,
	mach_port_t port,
	int reference)
{
    CHECK( IOUserClient, connection, client );

    return( client->registerNotificationPort( port, notification_type,
						reference ));
}

kern_return_t is_io_connect_map_memory(
	io_object_t     connect,
	int		type,
	task_t		task,
	vm_address_t *	mapAddr,
	vm_size_t    *	mapSize,
	int		flags )
{
    IOReturn		err;
    IOMemoryMap *	map;

    CHECK( IOUserClient, connect, client );

    map = client->mapClientMemory( type, task, flags, *mapAddr );

    if( map) {
        *mapAddr = map->getVirtualAddress();
        if( mapSize)
            *mapSize = map->getLength();

        if( task != current_task()) {
            // push a name out to the task owning the map,
            // so we can clean up maps
#if IOASSERT
	    mach_port_name_t name =
#endif
	    IOMachPort::makeSendRightForTask(
                                    task, map, IKOT_IOKIT_OBJECT );
            assert( name );

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

kern_return_t is_io_connect_unmap_memory(
	io_object_t     connect,
	int		type,
	task_t		task,
	vm_address_t 	mapAddr )
{
    IOReturn		err;
    IOOptionBits	options = 0;
    IOMemoryDescriptor * memory;
    IOMemoryMap *	map;

    CHECK( IOUserClient, connect, client );

    err = client->clientMemoryForType( (UInt32) type, &options, &memory );

    if( memory && (kIOReturnSuccess == err)) {

        options = (options & ~kIOMapUserOptionsMask)
		| kIOMapAnywhere | kIOMapReference;

	map = memory->map( task, mapAddr, options );
	memory->release();
        if( map) {
            IOLockLock( gIOObjectPortLock);
            if( client->mappings)
                client->mappings->removeObject( map);
            IOLockUnlock( gIOObjectPortLock);
            IOMachPort::releasePortForObject( map, IKOT_IOKIT_OBJECT );
            map->release();
        } else
            err = kIOReturnBadArgument;
    }

    return( err );
}


/* Routine io_connect_add_client */
kern_return_t is_io_connect_add_client(
	io_object_t connection,
	io_object_t connect_to)
{
    CHECK( IOUserClient, connection, client );
    CHECK( IOUserClient, connect_to, to );

    return( client->connectClient( to ) );
}


/* Routine io_connect_set_properties */
kern_return_t is_io_connect_set_properties(
	io_object_t connection,
	io_buf_ptr_t properties,
	mach_msg_type_number_t propertiesCnt,
        natural_t * result)
{
    return( is_io_registry_entry_set_properties( connection, properties, propertiesCnt, result ));
}


/* Routine io_connect_method_scalarI_scalarO */
kern_return_t is_io_connect_method_scalarI_scalarO(
	io_object_t	connect,
	UInt32		index,
        void *	 	input[],
        IOByteCount	inputCount,
        void *	 	output[],
        IOByteCount *	outputCount )
{
    IOReturn 		err;
    IOExternalMethod *	method;
    IOService *		object;
    IOMethod		func;

    CHECK( IOUserClient, connect, client);
    if( (method = client->getTargetAndMethodForIndex(&object, index))) {
      do {
        err = kIOReturnBadArgument;
	if( kIOUCScalarIScalarO != (method->flags & kIOUCTypeMask))
	    continue;
	if( inputCount != method->count0)
	    continue;
	if( *outputCount != method->count1)
	    continue;

	func = method->func;

	switch( inputCount) {

	    case 6:
		err = (object->*func)(  input[0], input[1], input[2],
					input[3], input[4], input[5] );
		break;
	    case 5:
		err = (object->*func)(  input[0], input[1], input[2],
					input[3], input[4], 
					&output[0] );
		break;
	    case 4:
		err = (object->*func)(  input[0], input[1], input[2],
					input[3],
					&output[0], &output[1] );
		break;
	    case 3:
		err = (object->*func)(  input[0], input[1], input[2],
					&output[0], &output[1], &output[2] );
		break;
	    case 2:
		err = (object->*func)(  input[0], input[1],
					&output[0], &output[1], &output[2],
					&output[3] );
		break;
	    case 1:
		err = (object->*func)(  input[0],
					&output[0], &output[1], &output[2],
					&output[3], &output[4] );
		break;
	    case 0:
		err = (object->*func)(  &output[0], &output[1], &output[2],
					&output[3], &output[4], &output[5] );
		break;

	    default:
		IOLog("%s: Bad method table\n", client->getName());
	}
      } while( false);

    } else
        err = kIOReturnUnsupported;

    return( err);
}

/* Routine io_connect_method_scalarI_structureO */
kern_return_t is_io_connect_method_scalarI_structureO(
	io_object_t	connect,
	UInt32		index,
        void *	 	input[],
        IOByteCount	inputCount,
        void *		output,
        IOByteCount *	outputCount )
{
    IOReturn 		err;
    IOExternalMethod *	method;
    IOService *		object;
    IOMethod		func;

    CHECK( IOUserClient, connect, client);

    if( (method = client->getTargetAndMethodForIndex(&object, index)) ) {
      do {
        err = kIOReturnBadArgument;
	if( kIOUCScalarIStructO != (method->flags & kIOUCTypeMask))
	    continue;
	if( inputCount != method->count0)
	    continue;
	if( (0xffffffff != method->count1)
		&& (*outputCount != method->count1))
	    continue;

	func = method->func;

	switch( inputCount) {

	    case 5:
		err = (object->*func)(  input[0], input[1], input[2],
                                        input[3], input[4],
                                        output );
		break;
	    case 4:
		err = (object->*func)(  input[0], input[1], input[2],
					input[3],
					output, (void *)outputCount );
		break;
	    case 3:
		err = (object->*func)(  input[0], input[1], input[2],
					output, (void *)outputCount, 0 );
		break;
	    case 2:
		err = (object->*func)(  input[0], input[1],
					output, (void *)outputCount, 0, 0 );
		break;
	    case 1:
		err = (object->*func)(  input[0],
					output, (void *)outputCount, 0, 0, 0 );
		break;
	    case 0:
		err = (object->*func)(  output, (void *)outputCount, 0, 0, 0, 0 );
		break;

	    default:
		IOLog("%s: Bad method table\n", client->getName());
	}
      } while( false);

    } else
        err = kIOReturnUnsupported;

    return( err);
}

/* Routine io_connect_method_scalarI_structureI */
kern_return_t is_io_connect_method_scalarI_structureI(
	io_connect_t 	connect,
	UInt32		index,
        void *	 	input[],
        IOByteCount	inputCount,
        UInt8 *		inputStruct,
        IOByteCount	inputStructCount )
{
    IOReturn 		err;
    IOExternalMethod *	method;
    IOService *		object;
    IOMethod		func;

    CHECK( IOUserClient, connect, client);

    if( (method = client->getTargetAndMethodForIndex(&object, index)) ) {
      do {
        err = kIOReturnBadArgument;
	if( kIOUCScalarIStructI != (method->flags & kIOUCTypeMask))
	    continue;
	if( (0xffffffff != method->count0)
		&& (inputCount != method->count0))
	    continue;
	if( (0xffffffff != method->count1)
		&& (inputStructCount != method->count1))
	    continue;

	func = method->func;

	switch( inputCount) {

	    case 5:
		err = (object->*func)( input[0], input[1], input[2],
					input[3], input[4], 
					inputStruct );
		break;
	    case 4:
		err = (object->*func)( input[0], input[1], input[2],
					input[3],
					inputStruct, (void *)inputStructCount );
		break;
	    case 3:
		err = (object->*func)( input[0], input[1], input[2],
					inputStruct, (void *)inputStructCount,
					0 );
		break;
	    case 2:
		err = (object->*func)( input[0], input[1],
					inputStruct, (void *)inputStructCount,
					0, 0 );
		break;
	    case 1:
		err = (object->*func)( input[0],
					inputStruct, (void *)inputStructCount,
					0, 0, 0 );
		break;
	    case 0:
		err = (object->*func)( inputStruct, (void *)inputStructCount,
					0, 0, 0, 0 );
		break;

	    default:
		IOLog("%s: Bad method table\n", client->getName());
	}
      } while( false);

    } else
        err = kIOReturnUnsupported;

    return( err);
}

/* Routine io_connect_method_structureI_structureO */
kern_return_t is_io_connect_method_structureI_structureO(
	io_object_t	connect,
	UInt32		index,
        UInt8 *		input,
        IOByteCount	inputCount,
        UInt8 *		output,
        IOByteCount *	outputCount )
{
    IOReturn 		err;
    IOExternalMethod *	method;
    IOService *		object;
    IOMethod		func;

    CHECK( IOUserClient, connect, client);

    if( (method = client->getTargetAndMethodForIndex(&object, index)) ) {
      do {
        err = kIOReturnBadArgument;
	if( kIOUCStructIStructO != (method->flags & kIOUCTypeMask))
	    continue;
	if( (0xffffffff != method->count0)
		&& (inputCount != method->count0))
	    continue;
	if( (0xffffffff != method->count1)
		&& (*outputCount != method->count1))
	    continue;

	func = method->func;

	if( method->count1) {
	    if( method->count0) {
		err = (object->*func)( input, output,
					(void *)inputCount, outputCount, 0, 0 );
	    } else {
		err = (object->*func)( output, outputCount, 0, 0, 0, 0 );
	    }
	} else {
		err = (object->*func)( input, (void *)inputCount, 0, 0, 0, 0 );
	}

      } while( false);

    } else
        err = kIOReturnUnsupported;

    return( err);
}

kern_return_t is_io_async_method_scalarI_scalarO(
        io_object_t	connect,
        mach_port_t	wakePort,
	io_async_ref_t		reference,
	mach_msg_type_number_t	referenceCnt,
        UInt32		index,
        void *	 	input[],
        IOByteCount	inputCount,
        void *	 	output[],
        IOByteCount *	outputCount )
{
    IOReturn 		err;
    IOExternalAsyncMethod *method;
    IOService *		object;
    IOAsyncMethod	func;

    CHECK( IOUserClient, connect, client);
    if( (method = client->getAsyncTargetAndMethodForIndex(&object, index)) ) {
      do {
        err = kIOReturnBadArgument;
        if( kIOUCScalarIScalarO != (method->flags & kIOUCTypeMask))
            continue;
        if( inputCount != method->count0)
            continue;
        if( *outputCount != method->count1)
            continue;

        reference[0] = (natural_t) wakePort;
        func = method->func;

        switch( inputCount) {

            case 6:
                err = (object->*func)(	reference,
                                        input[0], input[1], input[2],
                                        input[3], input[4], input[5] );
                break;
            case 5:
                err = (object->*func)(  reference,
                                        input[0], input[1], input[2],
                                        input[3], input[4],
                                        &output[0] );
                break;
            case 4:
                err = (object->*func)(  reference,
                                        input[0], input[1], input[2],
                                        input[3],
                                        &output[0], &output[1] );
                break;
            case 3:
                err = (object->*func)(  reference,
                                        input[0], input[1], input[2],
                                        &output[0], &output[1], &output[2] );
                break;
            case 2:
                err = (object->*func)(  reference,
                                        input[0], input[1],
                                        &output[0], &output[1], &output[2],
                                        &output[3] );
                break;
            case 1:
                err = (object->*func)(  reference,
                                        input[0],
                                        &output[0], &output[1], &output[2],
                                        &output[3], &output[4] );
                break;
            case 0:
                err = (object->*func)(  reference,
                                        &output[0], &output[1], &output[2],
                                        &output[3], &output[4], &output[5] );
                break;

            default:
                IOLog("%s: Bad method table\n", client->getName());
        }
      } while( false);

    } else
        err = kIOReturnUnsupported;

    return( err);
}

kern_return_t is_io_async_method_scalarI_structureO(
        io_object_t	connect,
        mach_port_t	wakePort,
	io_async_ref_t		reference,
	mach_msg_type_number_t	referenceCnt,
        UInt32		index,
        void *	 	input[],
        IOByteCount	inputCount,
        void *		output,
        IOByteCount *	outputCount )
{
    IOReturn 		err;
    IOExternalAsyncMethod *method;
    IOService *		object;
    IOAsyncMethod	func;

    CHECK( IOUserClient, connect, client);

    if( (method = client->getAsyncTargetAndMethodForIndex(&object, index)) ) {
      do {
        err = kIOReturnBadArgument;
        if( kIOUCScalarIStructO != (method->flags & kIOUCTypeMask))
            continue;
        if( inputCount != method->count0)
            continue;
        if( (0xffffffff != method->count1)
                && (*outputCount != method->count1))
            continue;

        reference[0] = (natural_t) wakePort;
        func = method->func;

        switch( inputCount) {

            case 5:
                err = (object->*func)(	reference,
                                        input[0], input[1], input[2],
                                        input[3], input[4],
                                        output );
                break;
            case 4:
                err = (object->*func)(	reference,
                                        input[0], input[1], input[2],
                                        input[3],
                                        output, (void *)outputCount );
                break;
            case 3:
                err = (object->*func)(	reference,
                                        input[0], input[1], input[2],
                                        output, (void *)outputCount, 0 );
                break;
            case 2:
                err = (object->*func)(	reference,
                                        input[0], input[1],
                                        output, (void *)outputCount, 0, 0 );
                break;
            case 1:
                err = (object->*func)(	reference,
                                        input[0],
                                        output, (void *)outputCount, 0, 0, 0 );
                break;
            case 0:
                err = (object->*func)(	reference,
                                        output, (void *)outputCount, 0, 0, 0, 0 );
                break;

            default:
                IOLog("%s: Bad method table\n", client->getName());
        }
      } while( false);

    } else
        err = kIOReturnUnsupported;

    return( err);
}

kern_return_t is_io_async_method_scalarI_structureI(
            io_connect_t 	connect,
            mach_port_t		wakePort,
	    io_async_ref_t	    reference,
	    mach_msg_type_number_t  referenceCnt,
            UInt32		index,
            void *	 	input[],
            IOByteCount	inputCount,
            UInt8 *		inputStruct,
            IOByteCount	inputStructCount )
{
    IOReturn 		err;
    IOExternalAsyncMethod *method;
    IOService *		object;
    IOAsyncMethod	func;

    CHECK( IOUserClient, connect, client);

    if( (method = client->getAsyncTargetAndMethodForIndex(&object, index)) ) {
      do {
        err = kIOReturnBadArgument;
        if( kIOUCScalarIStructI != (method->flags & kIOUCTypeMask))
            continue;
        if( (0xffffffff != method->count0)
                && (inputCount != method->count0))
            continue;
        if( (0xffffffff != method->count1)
                && (inputStructCount != method->count1))
            continue;

        reference[0] = (natural_t) wakePort;
        func = method->func;

        switch( inputCount) {

            case 5:
                err = (object->*func)(	reference,
                                        input[0], input[1], input[2],
                                        input[3], input[4],
                                        inputStruct );
                break;
            case 4:
                err = (object->*func)(	reference,
                                        input[0], input[1], input[2],
                                        input[3],
                                        inputStruct, (void *)inputStructCount );
                break;
            case 3:
                err = (object->*func)(	reference,
                                        input[0], input[1], input[2],
                                        inputStruct, (void *)inputStructCount,
                                        0 );
                break;
            case 2:
                err = (object->*func)(	reference,
                                        input[0], input[1],
                                        inputStruct, (void *)inputStructCount,
                                        0, 0 );
                break;
            case 1:
                err = (object->*func)(	reference,
                                        input[0],
                                        inputStruct, (void *)inputStructCount,
                                        0, 0, 0 );
                break;
            case 0:
                err = (object->*func)(	reference,
                                        inputStruct, (void *)inputStructCount,
                                        0, 0, 0, 0 );
                break;

            default:
                IOLog("%s: Bad method table\n", client->getName());
        }
      } while( false);

    } else
        err = kIOReturnUnsupported;

    return( err);
}

kern_return_t is_io_async_method_structureI_structureO(
        io_object_t	connect,
        mach_port_t wakePort,
	io_async_ref_t		reference,
	mach_msg_type_number_t	referenceCnt,
        UInt32		index,
        UInt8 *		input,
        IOByteCount	inputCount,
        UInt8 *		output,
        IOByteCount *	outputCount )
{
    IOReturn 		err;
    IOExternalAsyncMethod *method;
    IOService *		object;
    IOAsyncMethod	func;

    CHECK( IOUserClient, connect, client);

    if( (method = client->getAsyncTargetAndMethodForIndex(&object, index)) ) {
      do {
        err = kIOReturnBadArgument;
        if( kIOUCStructIStructO != (method->flags & kIOUCTypeMask))
            continue;
        if( (0xffffffff != method->count0)
                && (inputCount != method->count0))
            continue;
        if( (0xffffffff != method->count1)
                && (*outputCount != method->count1))
            continue;

        reference[0] = (natural_t) wakePort;
        func = method->func;

        if( method->count1) {
            if( method->count0) {
                err = (object->*func)( reference,
                                       input, output,
                                        (void *)inputCount, outputCount, 0, 0 );
            } else {
                err = (object->*func)( reference,
                                       output, outputCount, 0, 0, 0, 0 );
            }
        } else {
                err = (object->*func)( reference,
                                       input, (void *)inputCount, 0, 0, 0, 0 );
        }

      } while( false);

    } else
        err = kIOReturnUnsupported;

    return( err);
}
/* Routine io_make_matching */
kern_return_t is_io_make_matching(
	mach_port_t 	master_port,
	UInt32		type,
	IOOptionBits	options,
        UInt8 *		input,
        IOByteCount	inputCount,
	io_string_t	matching )
{
    OSSerialize * 	s;
    IOReturn		err = kIOReturnSuccess;
    OSDictionary *	dict;

    if( master_port != master_device_port)
        return( kIOReturnNotPrivileged);

    switch( type) {

	case kIOServiceMatching:
            dict = IOService::serviceMatching( gIOServiceKey );
	    break;

	case kIOBSDNameMatching:
	    dict = IOBSDNameMatching( (const char *) input );
	    break;

	case kIOOFPathMatching:
	    dict = IOOFPathMatching( (const char *) input,
                                    matching, sizeof( io_string_t));
	    break;

	default:
	    dict = 0;
    }

    if( !dict)
	return( kIOReturnUnsupported);

    do {
        s = OSSerialize::withCapacity(4096);
        if( !s) {
            err = kIOReturnNoMemory;
	    continue;
	}
        s->clearText();
        if( !dict->serialize( s )) {
            err = kIOReturnUnsupported;
	    continue;
        }

        if( s->getLength() > sizeof( io_string_t)) {
            err = kIOReturnNoMemory;
	    continue;
        } else
            strcpy( matching, s->text());

    } while( false);

    if( s)
	s->release();
    if( dict)
	dict->release();

    return( err);
}

/* Routine io_catalog_send_data */
kern_return_t is_io_catalog_send_data(
        mach_port_t		master_port,
        int                     flag,
        io_buf_ptr_t 		inData,
        mach_msg_type_number_t 	inDataCount,
        natural_t *		result)
{
    OSObject * obj = 0;
    vm_offset_t data;
    kern_return_t kr = kIOReturnError;

    //printf("io_catalog_send_data called. flag: %d\n", flag);
    
    if( master_port != master_device_port)
        return kIOReturnNotPrivileged;

    // FIXME: This is a hack. Should have own function for removeKernelLinker()
    if(flag != kIOCatalogRemoveKernelLinker && ( !inData || !inDataCount) )
        return kIOReturnBadArgument;

    if (data) {
        kr = vm_map_copyout( kernel_map, &data, (vm_map_copy_t)inData);
        if( kr != KERN_SUCCESS)
            return kr;

        // must return success after vm_map_copyout() succeeds

        if( inDataCount ) {
            obj = (OSObject *)OSUnserializeXML((const char *)data);
            vm_deallocate( kernel_map, data, inDataCount );
            if( !obj) {
                *result = kIOReturnNoMemory;
                return( KERN_SUCCESS);
            }
        }
    }

    switch ( flag ) {
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

        case kIOCatalogRemoveKernelLinker: {
                if (gIOCatalogue->removeKernelLinker() != KERN_SUCCESS) {
                    kr = kIOReturnError;
                } else {
                    kr = kIOReturnSuccess;
                }
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
	int flag,
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

        default:
            kr = kIOReturnBadArgument;
            break;
    }

    return( kr );
}

/* Routine io_catalog_get_data */
kern_return_t is_io_catalog_get_data(
        mach_port_t		master_port,
        int                     flag,
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

    s->clearText();

    kr = gIOCatalogue->serializeData(flag, s);

    if ( kr == kIOReturnSuccess ) {
        vm_offset_t data;
        vm_map_copy_t copy;
        vm_size_t size;

        size = s->getLength();
        kr = vm_allocate(kernel_map, &data, size, true);
        if ( kr == kIOReturnSuccess ) {
            bcopy(s->text(), (void *)data, size);
            kr = vm_map_copyin(kernel_map, data, size, true, &copy);
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
        int                     *genCount)
{
    if( master_port != master_device_port)
        return kIOReturnNotPrivileged;

    //printf("io_catalog_get_gen_count called.\n");

    if ( !genCount )
        return kIOReturnBadArgument;

    *genCount = gIOCatalogue->getGenerationCount();
    
    return kIOReturnSuccess;
}

/* Routine io_catalog_module_loaded */
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
	int			flag)
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

kern_return_t iokit_user_client_trap(io_object_t userClientRef, UInt32 index,
                                    void *p1, void *p2, void *p3,
                                    void *p4, void *p5, void *p6)
{
    kern_return_t result = kIOReturnBadArgument;
    IOUserClient *userClient;

    if ((userClient = OSDynamicCast(IOUserClient,
            iokit_lookup_connect_ref_current_task(userClientRef)))) {
        IOExternalTrap *trap;
        IOService *target = NULL;

        trap = userClient->getTargetAndTrapForIndex(&target, index);

        if (trap && target) {
            IOTrap func;

            func = trap->func;

            if (func) {
                result = (target->*func)(p1, p2, p3, p4, p5, p6);
            }
        }

        userClient->release();
    }

    return result;
}

};	/* extern "C" */

OSMetaClassDefineReservedUnused(IOUserClient, 0);
OSMetaClassDefineReservedUnused(IOUserClient, 1);
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

