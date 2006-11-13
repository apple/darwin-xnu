/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 *
 */


#ifndef _IOKIT_IOSERVICEPRIVATE_H
#define _IOKIT_IOSERVICEPRIVATE_H

// options for getExistingServices()
enum {
    kIONotifyOnce		= 0x00000001,
    kIOServiceExistingSet	= 0x00000002
};

// masks for __state[1]
enum {
    kIOServiceBusyStateMask	= 0x000000ff,
    kIOServiceBusyMax		= 255,
    kIOServiceNeedConfigState	= 0x80000000,
    kIOServiceSynchronousState	= 0x40000000,
    kIOServiceModuleStallState	= 0x20000000,
    kIOServiceBusyWaiterState	= 0x10000000,

    kIOServiceSyncPubState	= 0x08000000,
    kIOServiceConfigState	= 0x04000000,
    kIOServiceTermPhase2State	= 0x01000000,
    kIOServiceTermPhase3State	= 0x00800000,
};

// options for terminate()
enum {
    kIOServiceRecursing		= 0x00100000,
};

// notify state
enum {
    kIOServiceNotifyEnable	= 0x00000001,
    kIOServiceNotifyWaiter	= 0x00000002
};

struct _IOServiceNotifierInvocation
{
    IOThread		thread;
    queue_chain_t	link;
};

class _IOServiceNotifier : public IONotifier
{
    friend class IOService;

    OSDeclareDefaultStructors(_IOServiceNotifier)

public:
    OSOrderedSet *			whence;

    OSDictionary *			matching;
    IOServiceNotificationHandler	handler;
    void *				target;
    void *				ref;
    SInt32				priority;
    queue_head_t			handlerInvocations;
    IOOptionBits			state;

    virtual void free();
    virtual void remove();
    virtual bool disable();
    virtual void enable( bool was );
    virtual void wait();
};

class _IOServiceInterestNotifier : public IONotifier
{
    friend class IOService;

    OSDeclareDefaultStructors(_IOServiceInterestNotifier)

public:
    queue_chain_t		chain;

    IOServiceInterestHandler	handler;
    void *			target;
    void *			ref;
    queue_head_t		handlerInvocations;
    IOOptionBits		state;

    virtual void free();
    virtual void remove();
    virtual bool disable();
    virtual void enable( bool was );
    virtual void wait();
};

class _IOConfigThread : public OSObject
{
    friend class IOService;

    OSDeclareDefaultStructors(_IOConfigThread)

public:
    virtual void free();

    static void configThread( void );
    static void main( _IOConfigThread * self );
};

enum {
#ifdef LESS_THREAD_CREATE
    kMaxConfigThreads	= 4,
#else
    kMaxConfigThreads	= 32,
#endif
};

enum {
    kMatchNubJob	= 10,
};

class _IOServiceJob : public OSObject
{
    friend class IOService;

    OSDeclareDefaultStructors(_IOServiceJob)

public:
    int			type;
    IOService *		nub;
    IOOptionBits	options;

    static _IOServiceJob * startJob( IOService * nub, int type,
                          IOOptionBits options = 0 );
    static void pingConfig( class _IOServiceJob * job );

};

class IOResources : public IOService
{
    friend class IOService;

    OSDeclareDefaultStructors(IOResources)

public:
    static IOService * resources( void );
    virtual IOWorkLoop * getWorkLoop( ) const;
    virtual bool matchPropertyTable( OSDictionary * table );
    virtual IOReturn setProperties( OSObject * properties );
};

class _IOOpenServiceIterator : public OSIterator
{
    friend class IOService;

    OSDeclareDefaultStructors(_IOOpenServiceIterator)

    OSIterator *	iter;
    const IOService *	client;
    const IOService *	provider;
    IOService *		last;

public:
    static OSIterator * iterator( OSIterator * _iter,
                                  const IOService * client,
                                  const IOService * provider );
    virtual void free();
    virtual void reset();
    virtual bool isValid();
    virtual OSObject * getNextObject();
};

extern const OSSymbol * gIOConsoleUsersKey;
extern const OSSymbol * gIOConsoleSessionUIDKey;

#endif /* ! _IOKIT_IOSERVICEPRIVATE_H */

