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
 */


#include <IOKit/IOLib.h>
#include <libkern/c++/OSContainers.h>

#include "IOHIDUserClient.h"


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOUserClient

OSDefineMetaClassAndStructors(IOHIDUserClient, IOUserClient)

OSDefineMetaClassAndStructors(IOHIDParamUserClient, IOUserClient)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool IOHIDUserClient::start( IOService * _owner )
{
    static const IOExternalMethod methodTemplate[] = {
/* 0 */  { NULL, NULL, kIOUCScalarIScalarO, 1, 0 },
/* 1 */  { NULL, NULL, kIOUCScalarIScalarO, 1, 0 },
/* 2 */  { NULL, NULL, kIOUCScalarIScalarO, 1, 0 },
/* 3 */  { NULL, NULL, kIOUCStructIStructO, sizeof(struct evioLLEvent), 0 },
/* 4 */  { NULL, NULL, kIOUCStructIStructO, sizeof(Point), 0 },
/* 5 */  { NULL, NULL, kIOUCScalarIScalarO, 1, 1 }
    };

    if( !super::start( _owner ))
	return( false);

    owner = (IOHIDSystem *) _owner;

    bcopy( methodTemplate, externals, sizeof( methodTemplate ));

    externals[0].object = owner;
    externals[0].func = (IOMethod) &IOHIDSystem::createShmem;

    externals[1].object = owner;
    externals[1].func = (IOMethod) &IOHIDSystem::setEventsEnable;

    externals[2].object = owner;
    externals[2].func = (IOMethod) &IOHIDSystem::setCursorEnable;

    externals[3].object = owner;
    externals[3].func = (IOMethod) &IOHIDSystem::extPostEvent;

    externals[4].object = owner;
    externals[4].func = (IOMethod) &IOHIDSystem::extSetMouseLocation;

    externals[5].object = owner;
    externals[5].func = (IOMethod) &IOHIDSystem::extGetButtonEventNum;

    return( true );
}

IOReturn IOHIDUserClient::clientClose( void )
{
    owner->evClose();
#ifdef DEBUG
    kprintf("%s: client token invalidated\n", getName());
#endif

    owner->serverConnect = 0;
    detach( owner);

    return( kIOReturnSuccess);
}

IOService * IOHIDUserClient::getService( void )
{
    return( owner );
}

IOReturn IOHIDUserClient::registerNotificationPort(
		mach_port_t 	port,
		UInt32		type,
		UInt32		refCon )
{
    if( type != kIOHIDEventNotification)
	return( kIOReturnUnsupported);

    owner->setEventPort(port);
    return( kIOReturnSuccess);
}

IOReturn IOHIDUserClient::connectClient( IOUserClient * client )
{
    Bounds * 		bounds;
    IOGraphicsDevice *	graphicsDevice;

    // yikes
    if( 0 == (graphicsDevice = OSDynamicCast(IOGraphicsDevice,
						client->getProvider())) )
	return( kIOReturnBadArgument );

    graphicsDevice->getBoundingRect(&bounds);

    owner->registerScreen(graphicsDevice, bounds);

    return( kIOReturnSuccess);
}

IOReturn IOHIDUserClient::clientMemoryForType( UInt32 type,
        UInt32 * flags, IOMemoryDescriptor ** memory )
{

    if( type != kIOHIDGlobalMemory)
	return( kIOReturnBadArgument);

    *flags = 0;
    owner->globalMemory->retain();
    *memory = owner->globalMemory;

    return( kIOReturnSuccess);
}

IOExternalMethod * IOHIDUserClient::getExternalMethodForIndex( UInt32 index )
{
    if( index < (sizeof( externals) / sizeof( externals[0])))
	return( externals + index);
    else
	return( NULL);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool IOHIDParamUserClient::start( IOService * _owner )
{
    static const IOExternalMethod methodTemplate[] = {
/* 0 */  { NULL, NULL, kIOUCScalarIScalarO, 1, 0 },
/* 1 */  { NULL, NULL, kIOUCScalarIScalarO, 1, 0 },
/* 2 */  { NULL, NULL, kIOUCScalarIScalarO, 1, 0 },
/* 3 */  { NULL, NULL, kIOUCStructIStructO, sizeof(struct evioLLEvent), 0 },
/* 4 */  { NULL, NULL, kIOUCStructIStructO, sizeof(Point), 0 },
    };

    if( !super::start( _owner ))
	return( false);

    owner = (IOHIDSystem *) _owner;

    bcopy( methodTemplate, externals, sizeof( methodTemplate ));

    externals[3].object = owner;
    externals[3].func = (IOMethod) &IOHIDSystem::extPostEvent;

    externals[4].object = owner;
    externals[4].func = (IOMethod) &IOHIDSystem::extSetMouseLocation;

    return( true );
}

void IOHIDParamUserClient::free( void )
{
    retain(); retain();
    owner->paramConnect = 0;
    detach( owner);
    super::free();
}

void IOHIDParamUserClient::release() const
{
    super::release(2);
}


IOReturn IOHIDParamUserClient::clientClose( void )
{
    return( kIOReturnSuccess);
}

IOService * IOHIDParamUserClient::getService( void )
{
    return( owner );
}

IOExternalMethod * IOHIDParamUserClient::getExternalMethodForIndex(
						UInt32 index )
{
    // get the same library function to work for param & server connects
    if( (index >= 3)
     && (index < (sizeof( externals) / sizeof( externals[0]))))
	return( externals + index);
    else
	return( NULL);
}

IOReturn IOHIDParamUserClient::setProperties( OSObject * properties )
{
    OSDictionary *	dict;
    OSIterator *	iter;
    IOHIDevice *	eventSrc;
    IOReturn		err = kIOReturnSuccess;
    IOReturn		ret;

    dict = OSDynamicCast( OSDictionary, properties );
    if( dict) {
        ret = owner->setParamProperties( dict );
        if( (ret != kIOReturnSuccess) && (ret != kIOReturnBadArgument))
            err = ret;
        iter = owner->getOpenProviderIterator();

        if( iter) {
            while( (eventSrc = (IOHIDevice *) iter->getNextObject())) {
                ret = eventSrc->setParamProperties( dict );
                if( (ret != kIOReturnSuccess) && (ret != kIOReturnBadArgument))
                    err = ret;
            }
            iter->release();
        }
    } else
	err = kIOReturnBadArgument;

    return( err );
}

