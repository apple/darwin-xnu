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
/*
 * Copyright (c) 1998 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 *
 * 14 Aug 98 sdouglas created.
 * 08 Dec 98 sdouglas cpp.
 */

#define IOFRAMEBUFFER_PRIVATE
#include <IOKit/graphics/IOFramebufferShared.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMessage.h>
#include <libkern/c++/OSContainers.h>
#include <IOKit/IOBufferMemoryDescriptor.h>

#include <IOKit/IOPlatformExpert.h>

#include <IOKit/assert.h>

#include "IOFramebufferUserClient.h"

#include <IOKit/graphics/IOGraphicsEngine.h>


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOUserClient

OSDefineMetaClassAndStructors(IOFramebufferUserClient, IOUserClient)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static IOReturn myHandler(void *, void * , UInt32, IOService *, void *, unsigned int);
static IOLock * gSleepFramebuffersLock;
static OSOrderedSet * gSleepFramebuffers;
static UInt32 gWakeCount;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOFramebufferUserClient * IOFramebufferUserClient::withTask( task_t owningTask )
{
    IOFramebufferUserClient * inst;

    if( 0 == gSleepFramebuffersLock) {
        gSleepFramebuffersLock = IOLockAlloc();
        gSleepFramebuffers = OSOrderedSet::withCapacity(6);
        assert( gSleepFramebuffersLock && gSleepFramebuffers );
    }

    inst = new IOFramebufferUserClient;

    if( inst && !inst->init()) {
	inst->release();
	inst = 0;
    }

    return( inst );
}

bool IOFramebufferUserClient::start( IOService * _owner )
{
    static const IOExternalMethod methodTemplate[] = {
/* 0 */  { NULL, NULL, kIOUCScalarIScalarO, 3, 0 },
/* 1 */  { NULL, NULL, kIOUCScalarIStructO, 3, sizeof( IOPixelInformation) },
/* 2 */  { NULL, NULL, kIOUCScalarIScalarO, 0, 2 },
/* 3 */  { NULL, NULL, kIOUCScalarIScalarO, 2, 0 },
/* 4 */  { NULL, NULL, kIOUCScalarIScalarO, 2, 0 },
/* 5 */  { NULL, NULL, kIOUCScalarIStructO,
				1, sizeof( IODisplayModeInformation) },
/* 6 */  { NULL, NULL, kIOUCScalarIScalarO, 0, 1 },
/* 7 */  { NULL, NULL, kIOUCStructIStructO, 0, 0xffffffff },
/* 8 */  { NULL, NULL, kIOUCScalarIScalarO, 1, 1 },
/* 9 */  { NULL, NULL, kIOUCStructIStructO, sizeof( Bounds), 0 },
/* 10 */  { NULL, NULL, kIOUCScalarIScalarO, 3, 0 },
/* 11 */  { NULL, NULL, kIOUCScalarIStructI, 3, 0xffffffff },
/* 12 */  { NULL, NULL, kIOUCScalarIScalarO, 1, 0 },
/* 13 */  { NULL, NULL, kIOUCScalarIScalarO, 2, 0 },
/* 14 */  { NULL, NULL, kIOUCScalarIScalarO, 0, 0 },
/* 15 */  { NULL, NULL, kIOUCScalarIStructI, 1, 0xffffffff },
/* 16 */  { NULL, NULL, kIOUCScalarIStructI, 2, 0xffffffff },
/* 17 */  { NULL, NULL, kIOUCStructIStructO, 0xffffffff, 0xffffffff },

    };

    if( !super::start( _owner ))
	return( false);

    owner = (IOFramebuffer *) _owner;

    assert( sizeof( methodTemplate) == sizeof( externals));
    bcopy( methodTemplate, externals, sizeof( externals ));

    externals[0].object = owner;
    externals[0].func = (IOMethod) &IOFramebuffer::createSharedCursor;

    externals[1].object = owner;
    externals[1].func = (IOMethod) &IOFramebuffer::getPixelInformation;

    externals[2].object = owner;
    externals[2].func = (IOMethod) &IOFramebuffer::getCurrentDisplayMode;

    externals[3].object = owner;
    externals[3].func = (IOMethod) &IOFramebuffer::setStartupDisplayMode;

    externals[4].object = owner;
    externals[4].func = (IOMethod) &IOFramebuffer::extSetDisplayMode;

    externals[5].object = owner;
    externals[5].func = 
	(IOMethod) &IOFramebuffer::extGetInformationForDisplayMode;

    externals[6].object = owner;
    externals[6].func = (IOMethod) &IOFramebuffer::extGetDisplayModeCount;

    externals[7].object = owner;
    externals[7].func = (IOMethod) &IOFramebuffer::extGetDisplayModes;

    externals[8].object = owner;
    externals[8].func = (IOMethod) &IOFramebuffer::extGetVRAMMapOffset;

    externals[9].object = owner;
    externals[9].func = (IOMethod) &IOFramebuffer::extSetBounds;

    externals[10].object = owner;
    externals[10].func = (IOMethod) &IOFramebuffer::extSetNewCursor;

    externals[11].object = owner;
    externals[11].func = (IOMethod) &IOFramebuffer::setGammaTable;

    externals[12].object = owner;
    externals[12].func = (IOMethod) &IOFramebuffer::extSetCursorVisible;

    externals[13].object = owner;
    externals[13].func = (IOMethod) &IOFramebuffer::extSetCursorPosition;

    externals[14].object = this;
    externals[14].func = (IOMethod) &IOFramebufferUserClient::acknowledgeNotification;

    externals[15].object = owner;
    externals[15].func = (IOMethod) &IOFramebuffer::extSetColorConvertTable;

    externals[16].object = owner;
    externals[16].func = (IOMethod) &IOFramebuffer::extSetCLUTWithEntries;

    externals[17].object = owner;
    externals[17].func = (IOMethod) &IOFramebuffer::extValidateDetailedTiming;


    ackFrameBuffer = false;
    ackRoot = false;

    owner->serverConnect = this;

    // register interest in sleep and wake
    powerRootNotifier = registerSleepWakeInterest(myHandler, (void *) this);
    // register interest in frame buffer
    frameBufferNotifier = owner->registerInterest( gIOGeneralInterest, myHandler, this, 0 );
    return( true );
}


IOReturn
IOFramebufferUserClient::acknowledgeNotification( void )
{
    if( ackFrameBuffer ) {
        ackFrameBuffer = false;
        owner->allowPowerChange((unsigned long)PMrefcon);
    }
    if( ackRoot ) {
        ackRoot = false;
        owner->beginSystemSleep(PMrefcon);
    }

    return IOPMNoErr;
}


// We have registered for notification of power state changes in the framebuffer and the system in general.
// We are notified here of such a change.  "System" power changes refer to sleep/wake and power down/up.
// "Device" changes refer to the framebuffer.

static IOReturn
myHandler(void * us, void *, UInt32 messageType, IOService *, void * params, unsigned int)
{
    kern_return_t r;
    mach_msg_header_t *msgh;
    IOFramebufferUserClient * self = (IOFramebufferUserClient *)us;

    switch (messageType) {
        case kIOMessageSystemWillSleep:	
            if ( !(self->WSKnowsWeAreOff) ) {
                msgh = (mach_msg_header_t *)(self->notificationMsg);
                if( msgh && (self->WSnotificationPort) ) {
                    msgh->msgh_id = 0;
                    self->WSKnowsWeAreOff = true;
                    self->ackRoot = true;
                    r = mach_msg_send_from_kernel( msgh, msgh->msgh_size);
                    if( KERN_SUCCESS == r) {
                        // WS will ack within ten seconds
                        ((sleepWakeNote *)params)->returnValue = 10000000;
                        self->PMrefcon = ((sleepWakeNote *)params)->powerRef;
                        IOLockLock( gSleepFramebuffersLock );
                        gSleepFramebuffers->setObject(self);
                        IOLockUnlock( gSleepFramebuffersLock );
                        return kIOReturnSuccess;
                    }
                }
            }
            self->ackRoot = false;
            ((sleepWakeNote *)params)->returnValue = 0;
            return kIOReturnSuccess;

        case kIOMessageDeviceWillPowerOff:	
            if ( !self->WSKnowsWeAreOff ) {
                msgh = (mach_msg_header_t *)(self->notificationMsg);
                if( msgh && (self->WSnotificationPort) ) {
                    msgh->msgh_id = 0;
                    self->WSKnowsWeAreOff = true;
                    self->ackFrameBuffer = true;
                    r = mach_msg_send_from_kernel( msgh, msgh->msgh_size);
                    if( KERN_SUCCESS == r) {
                        // WS will ack within ten seconds
                        ((sleepWakeNote *)params)->returnValue = 10000000;
                        self->PMrefcon = ((sleepWakeNote *)params)->powerRef;
                        IOLockLock( gSleepFramebuffersLock );
                        gSleepFramebuffers->setObject(self);
                        IOLockUnlock( gSleepFramebuffersLock );
                        return kIOReturnSuccess;
                    }
                }
            }
            ((sleepWakeNote *)params)->returnValue = 0;
            self->ackFrameBuffer = false;
            return kIOReturnSuccess;

        case kIOMessageDeviceHasPoweredOn:

            IOLockLock( gSleepFramebuffersLock );
            gWakeCount++;
            if( gWakeCount == gSleepFramebuffers->getCount()) {
                while( (self = (IOFramebufferUserClient *) gSleepFramebuffers->getFirstObject())) {
                    if ( self->WSKnowsWeAreOff ) {
                        msgh = (mach_msg_header_t *)(self->notificationMsg);
                        if( msgh && (self->WSnotificationPort)) {
                            msgh->msgh_id = 1;
                            self->WSKnowsWeAreOff = false;
                            r = mach_msg_send_from_kernel( msgh, msgh->msgh_size);
                        }
                    }
                    gSleepFramebuffers->removeObject( self );
                }
                gWakeCount = 0;
            }
            IOLockUnlock( gSleepFramebuffersLock );
            return kIOReturnSuccess;
    }
    return kIOReturnUnsupported;
}

IOReturn IOFramebufferUserClient::registerNotificationPort(
                mach_port_t 	port,
                UInt32		type,
                UInt32		refCon )
{
    static mach_msg_header_t init_msg = {
        // mach_msg_bits_t	msgh_bits;
        MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,0),
        // mach_msg_size_t	msgh_size;
        sizeof (mach_msg_header_t),
        // mach_port_t	msgh_remote_port;
        MACH_PORT_NULL,
        // mach_port_t	msgh_local_port;
        MACH_PORT_NULL,
        // mach_msg_size_t 	msgh_reserved;
        0,
        // mach_msg_id_t	msgh_id;
        0
    };

    if ( notificationMsg == NULL )
        notificationMsg = IOMalloc( sizeof (mach_msg_header_t) );
    // Initialize the power state change notification message.
    *((mach_msg_header_t *)notificationMsg) = init_msg;

    ((mach_msg_header_t *)notificationMsg)->msgh_remote_port = port;
    
    WSnotificationPort = port;
    WSKnowsWeAreOff = false;
    return( kIOReturnSuccess);
}

IOReturn IOFramebufferUserClient::getNotificationSemaphore(
                            UInt32 interruptType, semaphore_t * semaphore )
{
    return( owner->getNotificationSemaphore(interruptType, semaphore) );
}

// The window server is going away.
// We disallow power down to prevent idle sleep while the console is running.
IOReturn IOFramebufferUserClient::clientClose( void )
{
    owner->close();
    if( owner->isConsoleDevice())
        getPlatform()->setConsoleInfo( 0, kPEAcquireScreen);

    if( powerRootNotifier) {
        powerRootNotifier->remove();
        powerRootNotifier = 0;
    }
    if( frameBufferNotifier) {
        frameBufferNotifier->remove();
        frameBufferNotifier = 0;
    }
    if( notificationMsg) {
	IOFree( notificationMsg, sizeof (mach_msg_header_t));
        notificationMsg = 0;
    }
    owner->serverConnect = 0;
    WSnotificationPort = NULL;
    detach( owner);

    return( kIOReturnSuccess);
}

IOService * IOFramebufferUserClient::getService( void )
{
    return( owner );
}

IOReturn IOFramebufferUserClient::clientMemoryForType( UInt32 type,
        IOOptionBits * flags, IOMemoryDescriptor ** memory )
{
    IOMemoryDescriptor *	mem;
    IOReturn		err;

    switch( type) {

	case kIOFBCursorMemory:
	    mem = owner->sharedCursor;
	    mem->retain();
	    break;

	case kIOFBVRAMMemory:
	    mem = owner->getVRAMRange();
	    break;

	default:
            mem = (IOMemoryDescriptor *) owner->userAccessRanges->getObject( type );
            mem->retain();
	    break;
    }

    *memory = mem;
    if( mem)
	err = kIOReturnSuccess;
    else
	err = kIOReturnBadArgument;

    return( err );
}

IOExternalMethod * IOFramebufferUserClient::getExternalMethodForIndex( UInt32 index )
{
    if( index < (sizeof( externals) / sizeof( externals[0])))
	return( externals + index);
    else
	return( NULL);
}

IOReturn IOFramebufferUserClient::setProperties( OSObject * properties )
{
    OSDictionary *	dict;
    OSArray *		array;
    IOReturn		kr = kIOReturnUnsupported;

    if( !(dict = OSDynamicCast( OSDictionary, properties)))
	return( kIOReturnBadArgument);

    if( (array = OSDynamicCast(OSArray,
		dict->getObject( kIOFBDetailedTimingsKey))))
        kr = owner->setDetailedTimings( array );
    else
        kr = kIOReturnBadArgument;

    return( kr );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSDefineMetaClassAndStructors(IOGraphicsEngineClient, IOUserClient)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOGraphicsEngineClient * IOGraphicsEngineClient::withTask( task_t owningTask )
{
    IOGraphicsEngineClient * inst;

    inst = new IOGraphicsEngineClient;

    if( inst && !inst->init()) {
	inst->release();
	inst = 0;
    }
    if( inst)
	inst->owningTask = owningTask;

    return( inst );
}

bool IOGraphicsEngineClient::start( IOService * _owner )
{

    static const IOExternalMethod methodTemplate[] = {
/* 0 */  { NULL, NULL, kIOUCScalarIScalarO, 3, 1 },
/* 1 */  { NULL, NULL, kIOUCScalarIScalarO, 2, 2 },
/* 2 */  { NULL, NULL, kIOUCScalarIScalarO, 3, 2 },
/* 3 */  { NULL, NULL, kIOUCScalarIScalarO, 1, 0 },
    };

    IOGraphicsEngineContext *	mem;
    IOByteCount			size;

    if( !super::start( _owner ))
	return( false);

    owner = (IOFramebuffer *) _owner;
    agpDev = OSDynamicCast( IOAGPDevice, owner->getProvider());
    descriptors = OSArray::withCapacity( 1 );

    bcopy( methodTemplate, externals, sizeof( methodTemplate ));

    externals[0].object = this;
    externals[0].func = (IOMethod) &IOGraphicsEngineClient::addUserRange;
    externals[1].object = this;
    externals[1].func = (IOMethod) &IOGraphicsEngineClient::createAGPSpace;
    externals[2].object = this;
    externals[2].func = (IOMethod) &IOGraphicsEngineClient::commitAGPMemory;
    externals[3].object = this;
    externals[3].func = (IOMethod) &IOGraphicsEngineClient::releaseAGPMemory;

    if( 0 == owner->engineContext) {

	size = round_page( sizeof( IOGraphicsEngineContext));
	owner->engineContext = IOBufferMemoryDescriptor::withCapacity(
					size, kIODirectionNone, false );
	if( !owner->engineContext)
	    return( kIOReturnNoMemory );
	owner->engineContext->setLength( size );

	mem = (IOGraphicsEngineContext *)
		owner->engineContext->getBytesNoCopy();
        memset((char *)mem, 0, size);
        mem->version = kIOGraphicsEngineContextVersion;
        mem->structSize = size;
    }

    return( true );
}

void IOGraphicsEngineClient::free()
{
    if( descriptors)
	descriptors->free();

    if( agpDev && haveAGP)
	agpDev->destroyAGPSpace();

    super::free();
}

IOReturn IOGraphicsEngineClient::clientClose( void )
{
    detach( owner );

    return( kIOReturnSuccess);
}

IOService * IOGraphicsEngineClient::getService( void )
{
    return( owner );
}

IOReturn IOGraphicsEngineClient::clientMemoryForType( UInt32 type,
			        IOOptionBits * options, IOMemoryDescriptor ** memory )
{
    IOMemoryDescriptor *	mem;

    switch( type) {
	case kIOGraphicsEngineContext:
	    mem = owner->engineContext;
	    break;
	default:
	    mem = (IOMemoryDescriptor *) owner->engineAccessRanges->getObject( type );
	    break;
    }

    if( mem) {
	mem->retain();
	*memory = mem;
	return( kIOReturnSuccess);
    } else
	return( kIOReturnBadArgument);
}

IOExternalMethod * IOGraphicsEngineClient::getExternalMethodForIndex( UInt32 index )
{
    if( index < (sizeof( externals) / sizeof( externals[0])))
	return( externals + index);
    else
	return( NULL);
}

IOReturn IOGraphicsEngineClient::addUserRange( vm_address_t start,
		vm_size_t length, UInt32 apertureIndex, IOPhysicalAddress * phys )
{
    IODeviceMemory *	mem;
    IOReturn		err = kIOReturnSuccess;
    OSArray *		ranges;
    int			i;
    IODeviceMemory *	aperture
        = owner->getProvider()->getDeviceMemoryWithIndex( apertureIndex );

    if( 0 == aperture)
	return( kIOReturnBadArgument );

    ranges = owner->engineAccessRanges;
    i = 0;
    while( (mem = (IODeviceMemory *) ranges->getObject( i++ ))) {
	if( (mem->getPhysicalAddress() ==
			(start + aperture->getPhysicalAddress()))
	    && (length <= mem->getLength()) )
		break;
    }

    if( 0 == mem) {
        mem = IODeviceMemory::withSubRange(
                    aperture, start, length );
        if( mem) {
            owner->engineAccessRanges->setObject( mem );
	    err = kIOReturnSuccess;
	} else
            err = kIOReturnNoResources;
    }

    if( kIOReturnSuccess == err)
	*phys = mem->getPhysicalAddress();

    return( err );
}

IOReturn IOGraphicsEngineClient::createAGPSpace( IOOptionBits options,
				    		 IOPhysicalLength length,
				    		 IOPhysicalAddress * address, 
				    		 IOPhysicalLength * lengthOut )
{
    IOReturn			err;

    if( !agpDev)
	return( kIOReturnUnsupported );

    *lengthOut = length;
    err = agpDev->createAGPSpace( options, address, lengthOut );
    haveAGP = (kIOReturnSuccess == err);

    return( err );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

class _IOGraphicsClientMemory : public OSObject {
    OSDeclareDefaultStructors(_IOGraphicsClientMemory)
public:
    IOMemoryDescriptor *	memory;
    IOAGPDevice *		agpDev;
    IOByteCount			agpOffset;

    virtual bool init();
    virtual void free();
};

OSDefineMetaClassAndStructors(_IOGraphicsClientMemory, OSObject)

bool _IOGraphicsClientMemory::init()
{
    return( OSObject::init());
}

void _IOGraphicsClientMemory::free()
{
    if( memory) {
	agpDev->getAGPRangeAllocator()->deallocate( agpOffset, 
						memory->getLength() );
	memory->complete();
	memory->release();
    }

    OSObject::free();
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOReturn IOGraphicsEngineClient::commitAGPMemory( vm_address_t start,
		vm_size_t length, IOOptionBits options,
		void ** ref, IOByteCount * offset )
{
    _IOGraphicsClientMemory *	graphicsMem;
    IORangeAllocator *		rangeAllocator;
    IOByteCount			agpOffset;
    IOReturn			err = kIOReturnNoMemory;
    bool			ok;

    if( !agpDev)
	return( kIOReturnUnsupported );
    if( (!start) || (!length))
	return( kIOReturnBadArgument );
    rangeAllocator = agpDev->getAGPRangeAllocator();
    if( !rangeAllocator)
	return( kIOReturnUnsupported );

    do {
	graphicsMem = new _IOGraphicsClientMemory;
	if( (!graphicsMem) || (!graphicsMem->init()))
	    continue;

	ok = rangeAllocator->allocate( length, (IORangeScalar *) &agpOffset );
	if( !ok) {
	    err = kIOReturnNoSpace;
	    continue;
	}

	graphicsMem->agpDev = agpDev;
	graphicsMem->agpOffset = agpOffset;

	graphicsMem->memory = IOMemoryDescriptor::withAddress( start, length,
		kIODirectionOut, owningTask );
	if( !graphicsMem->memory)
	    continue;

	err = graphicsMem->memory->prepare();
	if( err != kIOReturnSuccess)
	    continue;

	err = agpDev->commitAGPMemory( graphicsMem->memory, agpOffset );
	if( err != kIOReturnSuccess)
	    continue;

	*ref = (void *) descriptors->getCount();
	*offset = agpOffset;
	descriptors->setObject( graphicsMem );

    } while( false );

    if( graphicsMem)
	graphicsMem->release();

    if( (kIOReturnSuccess != err) && (!graphicsMem))
	rangeAllocator->deallocate( agpOffset, length );

    return( err );
}

IOReturn IOGraphicsEngineClient::releaseAGPMemory( void * ref )
{
    _IOGraphicsClientMemory *	graphicsMem;
    UInt32			index = (UInt32) ref;

    if( 0 == (graphicsMem = (_IOGraphicsClientMemory *)
		descriptors->getObject( index )))
	return( kIOReturnBadArgument );

    descriptors->removeObject( index );

    return( kIOReturnSuccess );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

OSDefineMetaClassAndStructors(IOFramebufferSharedUserClient, IOUserClient)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOFramebufferSharedUserClient * IOFramebufferSharedUserClient::withTask(
                                                                task_t owningTask )
{
    IOFramebufferSharedUserClient * inst;

    inst = new IOFramebufferSharedUserClient;

    if( inst && !inst->init()) {
	inst->release();
	inst = 0;
    }

    return( inst );
}

bool IOFramebufferSharedUserClient::start( IOService * _owner )
{

    static const IOExternalMethod methodTemplate[] = {
    };

    if( !super::start( _owner ))
	return( false);

    owner = (IOFramebuffer *) _owner;

    bcopy( methodTemplate, externals, sizeof( methodTemplate ));

    return( true );
}

void IOFramebufferSharedUserClient::free( void )
{
    retain(); retain();
    owner->sharedConnect = 0;
    detach( owner);
    super::free();
}

void IOFramebufferSharedUserClient::release() const
{
    super::release(2);
}

IOReturn IOFramebufferSharedUserClient::clientClose( void )
{
    return( kIOReturnSuccess);
}

IOService * IOFramebufferSharedUserClient::getService( void )
{
    return( owner );
}

IOReturn IOFramebufferSharedUserClient::clientMemoryForType( UInt32 type,
			        IOOptionBits * options, IOMemoryDescriptor ** memory )
{
    IOMemoryDescriptor *	mem = 0;
    IOReturn			err;

    switch( type) {

	case kIOFBCursorMemory:
	    mem = owner->sharedCursor;
	    mem->retain();
            *options = kIOMapReadOnly;
	    break;

	case kIOFBVRAMMemory:
	    mem = owner->getVRAMRange();
	    break;
    }

    *memory = mem;
    if( mem)
	err = kIOReturnSuccess;
    else
	err = kIOReturnBadArgument;

    return( err );
}

IOReturn IOFramebufferSharedUserClient::getNotificationSemaphore(
                            UInt32 interruptType, semaphore_t * semaphore )
{
    return( owner->getNotificationSemaphore(interruptType, semaphore) );
}

IOExternalMethod * IOFramebufferSharedUserClient::getExternalMethodForIndex( UInt32 index )
{
    if( index < (sizeof( externals) / sizeof( externals[0])))
	return( externals + index);
    else
	return( NULL);
}

