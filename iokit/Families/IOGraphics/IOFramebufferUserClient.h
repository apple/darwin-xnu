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
 * Copyright (c) 1997 Apple Computer, Inc.
 *
 *
 * HISTORY
 *
 */


#ifndef _IOKIT_IOFRAMEBUFFERUSERCLIENT_H
#define _IOKIT_IOFRAMEBUFFERUSERCLIENT_H

#include <IOKit/IOUserClient.h>
#include <IOKit/graphics/IOFramebuffer.h>
#include <IOKit/pci/IOAGPDevice.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

class IOFramebufferUserClient : public IOUserClient
{
    OSDeclareDefaultStructors(IOFramebufferUserClient)

private:

    IONotifier *	powerRootNotifier;
    IONotifier *	frameBufferNotifier;

    IOExternalMethod externals[ 18 ];

  

public:

    IOFramebuffer *	owner;
    mach_port_t 	WSnotificationPort;	// how we tell window server of power changes
    void *		notificationMsg;	// Msg to be sent to Window Server.
        
    bool	WSKnowsWeAreOff;		// true after informing WS that framebuffer is off
    bool	ackRoot;			// true if we must ack the root domain
    bool	ackFrameBuffer;			// true if we must ack the framebuffer
    void * 	PMrefcon;			// refcon to return to Power Management
    
    // IOUserClient methods
    virtual IOReturn clientClose( void );

    virtual IOService * getService( void );

    virtual IOReturn clientMemoryForType( UInt32 type,
        IOOptionBits * options, IOMemoryDescriptor ** memory );

    virtual IOExternalMethod * getExternalMethodForIndex( UInt32 index );

    virtual IOReturn registerNotificationPort( mach_port_t, UInt32, UInt32 );
    virtual IOReturn getNotificationSemaphore( UInt32 interruptType,
                                               semaphore_t * semaphore );

    // others

    static IOFramebufferUserClient * withTask( task_t owningTask );

    virtual bool start( IOService * provider );
    virtual IOReturn setProperties( OSObject * properties );
    
    virtual IOReturn acknowledgeNotification(void);

};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

class IOGraphicsEngineClient : public IOUserClient
{
    OSDeclareDefaultStructors(IOGraphicsEngineClient)

private:

    IOFramebuffer *	owner;
    task_t		owningTask;
    IOAGPDevice *	agpDev;
    bool		haveAGP;
    OSArray * 		descriptors;

    IOExternalMethod externals[ 4 ];

public:
    // IOUserClient methods
    virtual IOReturn clientClose( void );
    virtual void free();

    virtual IOService * getService( void );

    virtual IOReturn clientMemoryForType( UInt32 type,
        IOOptionBits * options, IOMemoryDescriptor ** memory );

    virtual IOExternalMethod * getExternalMethodForIndex( UInt32 index );

    // others

    static IOGraphicsEngineClient * withTask( task_t owningTask );
    virtual bool start( IOService * provider );

    virtual IOReturn addUserRange( vm_address_t start, vm_size_t length,
		UInt32 aperture, IOPhysicalAddress * phys );

    virtual IOReturn createAGPSpace( IOOptionBits options,
				    IOPhysicalLength	length,
				    IOPhysicalAddress * address, 
				    IOPhysicalLength * lengthOut );

    virtual IOReturn commitAGPMemory( vm_address_t start,
		vm_size_t length, IOOptionBits options,
		void ** ref, IOByteCount * offset );

    virtual IOReturn releaseAGPMemory( void * ref );

};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

class IOFramebufferSharedUserClient : public IOUserClient
{
    OSDeclareDefaultStructors(IOFramebufferSharedUserClient)

private:

    IOFramebuffer *	owner;

    IOExternalMethod externals[ 0 ];

public:
    virtual void free();
    virtual void release() const;

    // IOUserClient methods
    virtual IOReturn clientClose( void );

    virtual IOService * getService( void );

    virtual IOReturn clientMemoryForType( UInt32 type,
        IOOptionBits * options, IOMemoryDescriptor ** memory );

    virtual IOReturn getNotificationSemaphore( UInt32 notification_type,
                                    semaphore_t * semaphore );
    
    virtual IOExternalMethod * getExternalMethodForIndex( UInt32 index );

    // others
    static IOFramebufferSharedUserClient * withTask( task_t owningTask );
    virtual bool start( IOService * provider );
};


#endif /* ! _IOKIT_IOFRAMEBUFFERUSERCLIENT_H */
