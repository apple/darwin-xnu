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
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved. 
 *
 * IONetworkStack.h - An IOKit proxy for the BSD network stack.
 *
 * HISTORY
 *
 */

#ifndef _IONETWORKSTACK_H
#define _IONETWORKSTACK_H

// User-client keys
//
#define kIONetworkStackUserCommand     "IONetworkStackUserCommand"
enum {
	kIORegisterOne = 1,
	kIORegisterAll
};

#ifdef KERNEL

class IONetworkInterface;

class IONetworkStack : public IOService
{
    OSDeclareDefaultStructors( IONetworkStack )

protected:
    OSOrderedSet *   _ifSet;
    OSDictionary *   _ifDict;
    IONotifier *     _interfaceNotifier;
    bool             _registerPrimaryInterface;

    struct ExpansionData { };
    /*! @var reserved
        Reserved for future use.  (Internal use only)  */
    ExpansionData *_reserved;


    static bool interfacePublished( void *      target,
                                    void *      param,
                                    IOService * service );

    static void unregisterBSDInterface( IONetworkInterface * netif );

    static void registerBSDInterface( IONetworkInterface * netif );

    static SInt32 orderRegisteredInterfaces( const OSMetaClassBase * obj1,
                                             const OSMetaClassBase * obj2,
                                             void *     ref );

    static void completeRegistrationUsingArray( OSArray * array );

    static void completeRegistration( OSArray * array, bool isSync );

    virtual void free();

    virtual bool addInterface( IONetworkInterface * netif );

    virtual void removeInterface( IONetworkInterface * netif );

    virtual IONetworkInterface * getInterface( UInt32 index );

    virtual bool containsInterface( IONetworkInterface * netif );

    virtual bool addRegisteredInterface( IONetworkInterface * netif );

    virtual void removeRegisteredInterface( IONetworkInterface * netif );

    virtual IONetworkInterface * getRegisteredInterface( const char * name,
                                                         UInt32       unit );

    virtual IONetworkInterface * getLastRegisteredInterface(const char * name);

    virtual UInt32 getNextAvailableUnitNumber( const char * name,
                                               UInt32       startingUnit = 0 );

    virtual bool preRegisterInterface( IONetworkInterface * netif,
                                       const char *         name,
                                       UInt32               unit,
                                       OSArray *            array );

public:
    static IONetworkStack * getNetworkStack();

    static int bsdInterfaceWasUnregistered( struct ifnet * ifp );

    virtual bool init( OSDictionary * properties );

    virtual bool start( IOService * provider );

    virtual void stop( IOService * provider );

    virtual IOReturn registerAllInterfaces();
    
    virtual IOReturn registerPrimaryInterface( bool enable );

    virtual IOReturn registerInterface( IONetworkInterface * netif,
                                        const char *         name,
                                        UInt32               unit   = 0,
                                        bool                 isSync = true );

    virtual IOReturn message( UInt32      type,
                              IOService * provider,
                              void *      argument = 0 );

    virtual IOReturn newUserClient( task_t           owningTask,
                                    void *           security_id,
                                    UInt32           type,
                                    IOUserClient **  handler );

    // Virtual function padding
    OSMetaClassDeclareReservedUnused( IONetworkStack,  0);
    OSMetaClassDeclareReservedUnused( IONetworkStack,  1);
    OSMetaClassDeclareReservedUnused( IONetworkStack,  2);
    OSMetaClassDeclareReservedUnused( IONetworkStack,  3);

};

#endif /* KERNEL */

#endif /* !_IONETWORKSTACK_H */
