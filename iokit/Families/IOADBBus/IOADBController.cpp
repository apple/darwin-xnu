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
 * Copyright 1996 1995 by Open Software Foundation, Inc. 1997 1996 1995 1994 1993 1992 1991
 *              All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appears in all copies and
 * that both the copyright notice and this permission notice appear in
 * supporting documentation.
 *
 * OSF DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE.
 *
 * IN NO EVENT SHALL OSF BE LIABLE FOR ANY SPECIAL, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN ACTION OF CONTRACT,
 * NEGLIGENCE, OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */
/*
 * Copyright 1996 1995 by Apple Computer, Inc. 1997 1996 1995 1994 1993 1992 1991
 *              All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appears in all copies and
 * that both the copyright notice and this permission notice appear in
 * supporting documentation.
 *
 * APPLE COMPUTER DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE.
 *
 * IN NO EVENT SHALL APPLE COMPUTER BE LIABLE FOR ANY SPECIAL, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN ACTION OF CONTRACT,
 * NEGLIGENCE, OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/*
 * MKLINUX-1.0DR2
 */
/*
 * 18 June 1998 sdouglas  Start IOKit version.
 * 16 Nov  1998 suurballe Port to c++
 */


#include <mach/mach_types.h>

#include "IOADBControllerUserClient.h"
#include <IOKit/adb/IOADBController.h>
#include <IOKit/adb/IOADBDevice.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/c++/OSNumber.h>
#include <IOKit/IOLib.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include "IOADBBusPriv.h"

bool ADBhasRoot( OSObject *, void *, IOService * );
void doProbe ( thread_call_param_t, thread_call_param_t);

#define kTenSeconds 10000000

#define super IOADBBus

OSDefineMetaClass(IOADBController,IOADBBus)
OSDefineAbstractStructors(IOADBController,IOADBBus)


// **********************************************************************************
// start
//
// **********************************************************************************
bool IOADBController::start ( IOService * nub )
{
    if( !super::start(nub)) {
        return false;
    }
    probeBus();

    rootDomain = NULL;
    busProbed = true;
    
    // creates the probe thread for when we wake up:
    probeThread = thread_call_allocate((thread_call_func_t)doProbe, (thread_call_param_t)this);
    if (probeThread == NULL) {
        IOLog("IOADBController::start fails to call thread_call_allocate \n");
        return false;
    }

    addNotification( gIOPublishNotification,serviceMatching("IOPMrootDomain"),	// look for the Root Domain
                     (IOServiceNotificationHandler)ADBhasRoot, this, 0 );

    return true;
}





// **********************************************************************************
// ADBhasRoot
//
// The Root Power Domain has registered.
// Register as an interested driver so we find out when the system is
// going to sleep and waking up.
// **********************************************************************************
bool ADBhasRoot( OSObject * us, void *, IOService * yourDevice )
{
    if ( yourDevice != NULL ) {
        ((IOADBController *)us)->rootDomain = (IOPMrootDomain *)yourDevice;
        ((IOADBController *)us)->rootDomain->registerInterestedDriver((IOService *) us);
    }
    return true;
}


//*********************************************************************************
// powerStateWillChangeTo
//
// We are notified here of power changes in the root domain.
//
// If power is going down in the root domain, then the system is going to
// sleep, and we tear down the ADB stack.
//*********************************************************************************

IOReturn IOADBController::powerStateWillChangeTo ( IOPMPowerFlags theFlags, unsigned long, IOService*)
{
    int i;
    if ( ! (theFlags & kIOPMPowerOn) && ! (theFlags & kIOPMDoze) ) {
        busProbed = false;
        for ( i = 1; i < ADB_DEVICE_COUNT; i++ ) {
            if( adbDevices[ i ] != NULL ) {
                if ( adbDevices[ i ]->nub ) {
                    adbDevices[ i ]->nub->terminate(kIOServiceRequired | kIOServiceSynchronous);
                    adbDevices[ i ]->nub->release();
                }
                IOFree( adbDevices[ i ], sizeof (ADBDeviceControl));
                adbDevices[ i ] = NULL;
            }
        }
    }
    return IOPMAckImplied;
}

//*********************************************************************************
// powerStateDidChangeTo
//
// We are notified here of power changes in the root domain
//
// If power is has been brought up, then the system is waking from sleep.
// We re-probe the bus
//*********************************************************************************
IOReturn IOADBController::powerStateDidChangeTo ( IOPMPowerFlags theFlags, unsigned long, IOService*)
{
    if ( (theFlags & kIOPMPowerOn) || (theFlags & kIOPMDoze) ) {
        if ( ! busProbed ) {
            thread_call_enter(probeThread);
            busProbed = true;
            return kTenSeconds;
        }
    }
    return IOPMAckImplied;
}


void doProbe ( thread_call_param_t arg, thread_call_param_t)
{
    ((IOADBController *)arg)->probeBus();
    ((IOADBController *)arg)->rootDomain->acknowledgePowerChange((IOService *)arg);
}


// **********************************************************************************
// probeAddress
//
// **********************************************************************************
bool IOADBController::probeAddress ( IOADBAddress addr )
{
    IOReturn		err;
    ADBDeviceControl *	deviceInfo;
    UInt16		value;
    IOByteCount		length;

    length = 2;
    err = readFromDevice(addr,3,(UInt8 *)&value,&length);

    if (err == ADB_RET_OK) {
        if( NULL == (deviceInfo = adbDevices[ addr ])) {

            deviceInfo = (ADBDeviceControl *)IOMalloc(sizeof(ADBDeviceControl));
            bzero(deviceInfo, sizeof(ADBDeviceControl));

            adbDevices[ addr ] = deviceInfo;
            deviceInfo->defaultAddress = addr;
            deviceInfo->handlerID = deviceInfo->defaultHandlerID = (value & 0xff);
            }
        deviceInfo->address = addr;
    }
    return( (err == ADB_RET_OK));
}


// **********************************************************************************
// firstBit
//
// **********************************************************************************
unsigned int IOADBController::firstBit ( unsigned int mask )
{
    int bit = 15;

    while( 0 == (mask & (1 << bit))) {
        bit--;
    }
    return(bit);
}


// **********************************************************************************
// moveDeviceFrom
//
// **********************************************************************************
bool IOADBController::moveDeviceFrom ( IOADBAddress from, IOADBAddress to, bool check )
{
    IOReturn	err;
    UInt16		value;
    IOByteCount	length;
    bool		moved;

    length = 2;
    value = ((to << 8) | ADB_DEVCMD_CHANGE_ID);

    err = writeToDevice(from,3,(UInt8 *)&value,&length);

    adbDevices[ to ] = adbDevices[ from ];

    moved = probeAddress(to);

    if( moved || (!check)) {
        adbDevices[ from ] = NULL;
    }
    else {
        adbDevices[ to ] = NULL;
    }

    return moved;
}


// **********************************************************************************
// probeBus
//
// **********************************************************************************
IOReturn IOADBController::probeBus ( void )
{
    int 		i;
    UInt32		unresolvedAddrs;
    UInt32		freeAddrs;
    IOADBAddress	freeNum, devNum;
    IOADBDevice *	newDev;
    OSDictionary * 	newProps;
    char		nameStr[ 10 ];
    const OSNumber * object;
    const OSSymbol * key;

    /* Kill the auto poll until a new dev id's have been setup */
    setAutoPollEnable(false);
    
    /*
     * Send a ADB bus reset - reply is sent after bus has reset,
     * so there is no need to wait for the reset to complete.
     */
    
    resetBus();

    /*
     * Okay, now attempt reassign the
     * bus
     */

    unresolvedAddrs = 0;
    freeAddrs = 0xfffe;

    /* Skip 0 -- it's special! */
    for (i = 1; i < ADB_DEVICE_COUNT; i++) {
        if( probeAddress(i) ) {
            unresolvedAddrs |= ( 1 << i );
            freeAddrs &= ~( 1 << i );
            }
    }

/* Now attempt to reassign the addresses */
    while( unresolvedAddrs) {
        if( !freeAddrs) {
            panic("ADB: Cannot find a free ADB slot for reassignment!");
            }

        freeNum = firstBit(freeAddrs);
        devNum = firstBit(unresolvedAddrs);

        if( !moveDeviceFrom(devNum, freeNum, true) ) {

            /* It didn't move.. bad! */
            IOLog("WARNING : ADB DEVICE %d having problems "
                  "probing!\n", devNum);
        }
        else {
            if( probeAddress(devNum) ) {
                /* Found another device at the address, leave
                * the first device moved to one side and set up
                * newly found device for probing
                */
                freeAddrs &= ~( 1 << freeNum );

                devNum = 0;

            }
            else {
                /* no more at this address, good !*/
                /* Move it back.. */
                moveDeviceFrom(freeNum,devNum,false);
            }
            }
        if(devNum) {
            unresolvedAddrs &= ~( 1 << devNum );
            }
    }

    IOLog("ADB present:%lx\n", (freeAddrs ^ 0xfffe));

    setAutoPollList(freeAddrs ^ 0xfffe);

    setAutoPollPeriod(11111);

    setAutoPollEnable(true);
    
// publish the nubs
    for ( i = 1; i < ADB_DEVICE_COUNT; i++ ) {
        if( 0 == adbDevices[ i ] ) {
            continue;
        }
        newDev = new IOADBDevice;			// make a nub
        if ( newDev == NULL ) {
            continue;
        }
        adbDevices[ i ]->nub = newDev;			// keep a pointer to it
        
        newProps = OSDictionary::withCapacity( 10 );	// create a property table for it
        if ( newProps == NULL ) {
            newDev->free();
            continue;
        }

        key = OSSymbol::withCString(ADBaddressProperty);	// make key/object for address
        if ( key == NULL ) {
            newDev->free();
            newProps->free();
            continue;
        }
        
        object = OSNumber::withNumber((unsigned long long)adbDevices[i]->address,8);
        if ( object == NULL ) {
            key->release();
            newDev->free();
            newProps->free();
            continue;
        }
        newProps->setObject(key, (OSObject *)object); 		// put it in newProps
        key->release();
        object->release();

        key = OSSymbol::withCString(ADBhandlerIDProperty);	// make key/object for handlerID
        if ( key == NULL ) {
            newDev->free();
            newProps->free();
            continue;
        }
        object = OSNumber::withNumber((unsigned long long)adbDevices[i]->handlerID,8);
        if ( object == NULL ) {
            key->release();
            newDev->free();
            newProps->free();
            continue;
        }
        newProps->setObject(key, (OSObject *)object); 		// put it in newProps
        key->release();
        object->release();

        key = OSSymbol::withCString(ADBdefAddressProperty);	// make key/object for default addr
        if ( key == NULL ) {
            newDev->free();
            newProps->free();
            continue;
        }
        object = OSNumber::withNumber((unsigned long long)adbDevices[i]->defaultAddress,8);
        if ( object == NULL ) {
            key->release();
            newDev->free();
            newProps->free();
            continue;
        }
        newProps->setObject(key, (OSObject *)object); 		// put it in newProps
        key->release();
        object->release();

        key = OSSymbol::withCString(ADBdefHandlerProperty);	// make key/object for default h id
        if ( key == NULL ) {
            newDev->free();
            newProps->free();
            continue;
        }
        object = OSNumber::withNumber((unsigned long long)adbDevices[i]->defaultHandlerID,8);
        if ( object == NULL ) {
            key->release();
            newDev->free();
            newProps->free();
            continue;
        }
        newProps->setObject(key, (OSObject *)object);	 	// put it in newProps
        key->release();
        object->release();

        if ( ! newDev->init(newProps,adbDevices[i]) ) {		// give it to our new nub
            kprintf("adb nub init failed\n");
            newDev->release();
            continue;
        }

	sprintf(nameStr,"%x-%02x",adbDevices[i]->defaultAddress,adbDevices[i]->handlerID);
        newDev->setName(nameStr);
	sprintf(nameStr, "%x", adbDevices[i]->defaultAddress);
	newDev->setLocation(nameStr);

        newProps->release();				// we're done with it
        if ( !newDev->attach(this) ) {
            kprintf("adb nub attach failed\n");
            newDev->release();
            continue;
        }
        newDev->start(this);
        newDev->registerService();
        newDev->waitQuiet();
    }							// repeat loop
    return kIOReturnSuccess;
}


// **********************************************************************************
// autopollHandler
//
// **********************************************************************************
void autopollHandler ( IOService * us, UInt8 adbCommand, IOByteCount length, UInt8 * data )
{
    ((IOADBController *)us)->packet(data,length,adbCommand);
}


// **********************************************************************************
// packet
//
// **********************************************************************************
void IOADBController::packet ( UInt8 * data, IOByteCount length, UInt8 adbCommand )
{
    ADBDeviceControl * deviceInfo;

    deviceInfo = adbDevices[ adbCommand >> 4 ];
    if( deviceInfo != NULL ) {
        if( deviceInfo->owner != NULL ) {
            deviceInfo->handler(deviceInfo->owner, adbCommand, length, data);
            }
    }
    else {
        // new device arrival?
        // IOLog("IOADBBus: new device @%x\n", address);
    }
}


// **********************************************************************************
// matchDevice
//
// **********************************************************************************
bool IOADBController::matchNubWithPropertyTable( IOService * device, OSDictionary *  propTable )
{
    bool		matched = false;
    const char *	keys;
    ADBDeviceControl * deviceInfo = (ADBDeviceControl *)(((IOADBDevice *)device)->busRef());
    OSObject *	X;

    do {
        X = propTable->getObject("ADB Match");
        if( !X ) {
            break;
        }
        keys = ((OSString *)X)->getCStringNoCopy();
        if( *keys == '*' ) {
            keys++;
        }
        else {
            if( deviceInfo->defaultAddress != strtol(keys, &keys, 16)) {
                break;
            }
        }
        if( *keys++ == '-' ) {
            if( deviceInfo->defaultHandlerID != strtol(keys, &keys, 16)) {
                break;
            }
        }
        matched = true;

    } while ( false );
    return matched;
}


/////// nub -> bus

// **********************************************************************************
// setOwner
//
// **********************************************************************************
IOReturn IOADBController::setOwner ( void * device, IOService * client, ADB_callback_func handler )
{
   ADBDeviceControl * deviceInfo = (ADBDeviceControl *)device;

   deviceInfo->handler = handler;
   deviceInfo->owner = client;
   return kIOReturnSuccess;
}


// **********************************************************************************
// clearOwner
//
// **********************************************************************************
IOReturn IOADBController::clearOwner ( void * device )
{
   ADBDeviceControl * deviceInfo = (ADBDeviceControl *)device;
    kprintf("IOADBController::clearOwner\n");
    
   deviceInfo->owner = NULL;
   deviceInfo->handler = NULL;
   return kIOReturnSuccess;
}


// **********************************************************************************
// claimDevice
//
// Called by the user client
// **********************************************************************************
IOReturn IOADBController::claimDevice (unsigned long ADBaddress, IOService * client, ADB_callback_func handler )
{
   if ( claimed_devices[ADBaddress] == true ) {			// is this address already claimed by the user?
       return kIOReturnExclusiveAccess;			// yes
   }
   if ( adbDevices[ADBaddress] == NULL )  {			// no, is there a device at that address?
       return kIOReturnNoDevice;				// no
   }
   if (adbDevices[ADBaddress]->handler != NULL ) {		// yes, is it already owned by the kernel?
       return kIOReturnExclusiveAccess;			// yes
   }
   claimed_devices[ADBaddress] = true;			// no, user can have it
    return kIOReturnSuccess;
}


// **********************************************************************************
// releaseDevice
//
// Called by the user client
// **********************************************************************************
IOReturn IOADBController::releaseDevice (unsigned long ADBaddress )
{
   if ( claimed_devices[ADBaddress] == false ) {
       return kIOReturnBadArgument;
   }

   claimed_devices[ADBaddress] = false;

    return kIOReturnSuccess;
}


// **********************************************************************************
// readDeviceForUser
//
// Called by the user client
// **********************************************************************************
IOReturn IOADBController::readDeviceForUser  (unsigned long address, unsigned long adbRegister,
                      UInt8 * data, IOByteCount * length)
{
  if ( claimed_devices[address] == false ) {
      return kIOReturnBadArgument;
  }

   return (readFromDevice((IOADBAddress)address,(IOADBRegister)adbRegister,data,length));
}


// **********************************************************************************
// writeDeviceForUser
//
// Called by the user client
// **********************************************************************************
IOReturn IOADBController::writeDeviceForUser  (unsigned long address, unsigned long adbRegister,
                      UInt8 * data, IOByteCount * length)
{
  if ( claimed_devices[address] == false ) {
      return kIOReturnBadArgument;
  }

   return (writeToDevice((IOADBAddress)address,(IOADBRegister)adbRegister,data,length));
}


// **********************************************************************************
// address
//
// **********************************************************************************
IOADBAddress IOADBController::address ( ADBDeviceControl * busRef )
{
    return busRef->address;
}


// **********************************************************************************
// defaultAddress
//
// **********************************************************************************
IOADBAddress IOADBController::defaultAddress ( ADBDeviceControl * busRef )
{
    return busRef->defaultAddress;
}


// **********************************************************************************
// handlerID
//
// **********************************************************************************
UInt8 IOADBController::handlerID ( ADBDeviceControl * busRef )
{
    return busRef->handlerID;
}


// **********************************************************************************
// defaultHandlerID
//
// **********************************************************************************
UInt8 IOADBController::defaultHandlerID ( ADBDeviceControl * busRef )
{
    return busRef->defaultHandlerID;
}


// **********************************************************************************
// cancelAllIO
//
// **********************************************************************************
IOReturn IOADBController::cancelAllIO ( void )
{
    return kIOReturnSuccess;
}


// **********************************************************************************
// flush
//
// **********************************************************************************
IOReturn IOADBController::flush ( ADBDeviceControl * busRef )
{
    return(flushDevice(busRef->address));
}


// **********************************************************************************
// readRegister
//
// **********************************************************************************
IOReturn IOADBController::readRegister ( ADBDeviceControl * busRef, IOADBRegister adbRegister,
                                         UInt8 * data, IOByteCount * length )
{
    return readFromDevice(busRef->address,adbRegister,data,length);
}


// **********************************************************************************
// writeRegister
//
// **********************************************************************************
IOReturn IOADBController::writeRegister ( ADBDeviceControl * busRef, IOADBRegister adbRegister,
                                          UInt8 * data, IOByteCount * length )
{
    return writeToDevice(busRef->address,adbRegister,data,length);
}


// **********************************************************************************
// setHandlerID
//
// **********************************************************************************
IOReturn IOADBController::setHandlerID ( ADBDeviceControl * deviceInfo, UInt8 handlerID )
{
    IOReturn	err;
    UInt16		value;
    IOByteCount	        length;
    IOADBAddress	addr = deviceInfo->address;

    length = 2;
    err = readFromDevice(addr,3,(UInt8 *)&value,&length);

    if ( err ) {
        return err;
    }

    value = (value & 0xf000) | handlerID | (addr << 8);
    length = sizeof(value);
    err = writeToDevice(addr,3,(UInt8 *)&value,&length);

    length = sizeof(value);
    err = readFromDevice(addr,3,(UInt8 *)&value,&length);

    if ( err == kIOReturnSuccess ) {
        deviceInfo->handlerID = value & 0xff;
    }

    if ( deviceInfo->handlerID == handlerID ) {
        err = kIOReturnSuccess;
    }
    else {
        err = kIOReturnNoResources;
    }

    return err;
}


// **********************************************************************************
// getURLComponentUnit
//
// **********************************************************************************
int IOADBController::getURLComponentUnit ( IOService * device, char * path, int maxLen )
{
    ADBDeviceControl * deviceInfo = (ADBDeviceControl *)((IOADBDevice *)device)->busRef();

    if( maxLen > 1 ) {
        sprintf( path, "%x", deviceInfo->address );
        return(1);
    }
    else {
        return(0);
    }
}


// **********************************************************************************
// newUserClient
//
// **********************************************************************************
IOReturn IOADBController::newUserClient(  task_t owningTask,  void * /* security_id */, UInt32 type, IOUserClient ** handler )
{
    IOReturn		err = kIOReturnSuccess;
   IOADBControllerUserClient *	client;

  client = IOADBControllerUserClient::withTask(owningTask);

  if( !client || (false == client->attach( this )) ||
      (false == client->start( this )) ) {
      if(client) {
          client->detach( this );
          client->release();
          client = NULL;
      }
      err = kIOReturnNoMemory;
  }
  *handler = client;	
  return err;
}
