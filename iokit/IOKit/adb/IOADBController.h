/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * 18 June 1998 sdouglas   Start IOKit version.
 * 12 Nov  1998 suurballe  Port objc protocol to c++ abstract class.
 */
#ifndef _IOKIT_ADBCONTROLLER_H
#define _IOKIT_ADBCONTROLLER_H

#include <IOKit/IOService.h>
#include <IOKit/adb/adb.h>
#include <IOKit/adb/IOADBBus.h>

extern "C" {
#include <kern/thread_call.h>
}

// referenced in subclasses:
void autopollHandler ( IOService *, UInt8, IOByteCount, UInt8 * );

class IOADBDevice;

/*
 * Results
 */

#define ADB_RET_OK          		0   /* Successful */
#define ADB_RET_INUSE           	1   /* ADB Device in use */
#define ADB_RET_NOTPRESENT      	2   /* ADB Device not present */
#define ADB_RET_TIMEOUT         	3   /* ADB Timeout  */
#define ADB_RET_UNEXPECTED_RESULT	4   /* Unknown result */
#define ADB_RET_REQUEST_ERROR       	5   /* Packet Request Error */
#define ADB_RET_BUS_ERROR       	6   /* ADB Bus Error */

class IOPMrootDomain;

class IOADBController: public IOADBBus
{
OSDeclareAbstractStructors(IOADBController)

public:

    bool start ( IOService * nub );
    IOReturn setOwner ( void * device, IOService * client, ADB_callback_func handler );
    virtual IOReturn claimDevice ( unsigned long, IOService *, ADB_callback_func );
    virtual IOReturn releaseDevice ( unsigned long );
    virtual IOReturn readDeviceForUser(unsigned long, unsigned long, UInt8 *, IOByteCount *);
    virtual IOReturn writeDeviceForUser(unsigned long, unsigned long, UInt8 *, IOByteCount *);
    virtual IOReturn setAutoPollPeriod (int microseconds) = 0;
    virtual IOReturn getAutoPollPeriod (int * microseconds) = 0;
    virtual IOReturn setAutoPollList(UInt16 activeAddressMask) = 0;
    virtual IOReturn getAutoPollList(UInt16 * activeAddressMask) = 0;
    virtual IOReturn setAutoPollEnable(bool enable) = 0;
    virtual IOReturn resetBus(void) = 0;
    virtual IOReturn cancelAllIO(void) = 0;
    virtual IOReturn flushDevice(IOADBAddress address) = 0;
    virtual IOReturn readFromDevice(IOADBAddress address, IOADBRegister adbRegister,
                                    UInt8 * data, IOByteCount * length) = 0;
    virtual IOReturn writeToDevice(IOADBAddress address, IOADBRegister adbRegister,
                                   UInt8 * data, IOByteCount * length) = 0;
    void packet ( UInt8 * data, IOByteCount length, UInt8 adbCommand );

    IOReturn flush ( ADBDeviceControl * busRef );
    IOReturn readRegister ( ADBDeviceControl * busRef, IOADBRegister adbRegister,
                            UInt8 * data, IOByteCount * length );
    IOReturn writeRegister ( ADBDeviceControl * busRef, IOADBRegister adbRegister,
                             UInt8 * data, IOByteCount * length );
    IOADBAddress address ( ADBDeviceControl * busRef );
    IOADBAddress defaultAddress ( ADBDeviceControl * busRef );
    UInt8 handlerID ( ADBDeviceControl * busRef );
    UInt8 defaultHandlerID ( ADBDeviceControl * busRef );
    IOReturn setHandlerID ( ADBDeviceControl * busRef, UInt8 handlerID );
    bool matchNubWithPropertyTable( IOService * device, OSDictionary *  propertyTable );
    IOReturn newUserClient(  task_t,  void *, UInt32, IOUserClient ** );
    IOReturn powerStateWillChangeTo ( IOPMPowerFlags, unsigned long, IOService*);
    IOReturn powerStateDidChangeTo ( IOPMPowerFlags, unsigned long, IOService*);
    IOReturn probeBus ( void );

IOReturn clearOwner ( void * );

IOPMrootDomain * rootDomain;

private:
    
    bool 		claimed_devices[16];		// true if a device has been claimed by user

    bool probeAddress ( IOADBAddress addr );
    bool moveDeviceFrom ( IOADBAddress from, IOADBAddress to, bool check );
    unsigned int firstBit ( unsigned int mask );
    int getURLComponentUnit ( IOService * device, char * path, int maxLen );
    bool busProbed;
    thread_call_t probeThread;
};

#endif /* ! _IOKIT_ADBCONTROLLER_H */
