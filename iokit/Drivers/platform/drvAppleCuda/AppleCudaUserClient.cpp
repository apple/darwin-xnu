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
#include "AppleCudaUserClient.h"

#ifndef NULL
#define NULL	0
#endif

#define super	IOUserClient

OSDefineMetaClassAndStructors(AppleCudaUserClient, IOUserClient)

AppleCudaUserClient*
AppleCudaUserClient::withTask(task_t owningTask)
{
    AppleCudaUserClient *client;

    client = new AppleCudaUserClient;
    if (client != NULL) {
        if (client->init() == false) {
            client->release();
            client = NULL;
        }
    }
    if (client != NULL) {
        client->fTask = owningTask;
    }
    return (client);
}

bool
AppleCudaUserClient::start(IOService *provider)
{
    bool result = false;

    theInterface = OSDynamicCast(AppleCuda, provider);

    if (theInterface != NULL)
        result = super::start(provider);
    else
        result = false;

    if (result == false) {
        IOLog("AppleCudaUserClient: provider start failed\n");
    }

    return (result);
}

IOReturn
AppleCudaUserClient::clientClose(void)
{
    detach(theInterface);
    return (kIOReturnSuccess);
}

IOReturn
AppleCudaUserClient::clientDied(void)
{
    return (clientClose());
}

IOReturn
AppleCudaUserClient::connectClient(IOUserClient *client)
{
    return (kIOReturnSuccess);
}

IOReturn
AppleCudaUserClient::registerNotificationPort(mach_port_t port, UInt32 type)
{
    return (kIOReturnUnsupported);
}

// --------------------------------------------------------------------------
// Method: setProperties
//
// Purpose:
//       sets the property from the dictionary to the airport properties.

IOReturn
AppleCudaUserClient::setProperties( OSObject * properties )
{
    OSDictionary *	dict;

    dict = OSDynamicCast( OSDictionary, properties );
    if ((dict) && (theInterface != NULL)) {
        OSData *data;

        // Sets the wake on ring:
        if( (data = OSDynamicCast( OSData, dict->getObject("WakeOnRing")))) {
            UInt8 myBool = *((UInt8*)data->getBytesNoCopy());
            //theInterface->setWakeOnRing(myBool);

            IOLog("AppleCudaUserClient::setProperties WakeOnRing %d\n", myBool);
            
            // returns success:
            return kIOReturnSuccess;
        }

        // Sets the file-server mode:
        if( (data = OSDynamicCast( OSData, dict->getObject("FileServer")))) {
            UInt8 myBool = *((UInt8*)data->getBytesNoCopy());
            theInterface->setFileServerMode(myBool);

            IOLog("AppleCudaUserClient::setProperties FileServer %d\n", myBool != 0);
            
            // returns success:
            return kIOReturnSuccess;
        }

	//Demand sleep immediately:
        if( (data = OSDynamicCast( OSData, dict->getObject("SleepNow")))) {
            UInt8 myBool = *((UInt8*)data->getBytesNoCopy());
	    
	    if (myBool)
	    {
		theInterface->demandSleepNow();
		IOLog("AppleCudaUserClient::setProperties SleepNow\n");
	    }
	    return kIOReturnSuccess;
        }

        // Sets the self-wake time:
        if( (data = OSDynamicCast( OSData, dict->getObject("AutoWake")))) {
            UInt32 newTime;
            IOByteCount len = data->getLength();

            if (len == 4)
                newTime = *((UInt32*)data->getBytesNoCopy());
            else
                newTime = 0;
                
            theInterface->setWakeTime(newTime * 1000); //convert to milliseconds
            
            IOLog("AppleCudaUserClient::setProperties AutoWake 0x%08lx\n", newTime);   

            // returns success:
            return kIOReturnSuccess;
        }
        
        // Sets the self-poweron time:
        if( (data = OSDynamicCast( OSData, dict->getObject("AutoPower")))) {
            UInt32 newTime;
            IOByteCount len = data->getLength();

            if (len == 4)
                newTime = *((UInt32*)data->getBytesNoCopy());
            else
                newTime = 0;
                
            theInterface->setPowerOnTime(newTime);
            
            IOLog("AppleCudaUserClient::setProperties AutoPower 0x%08lx\n", newTime);   

            // returns success:
            return kIOReturnSuccess;
        }
        
    }

    return(kIOReturnBadArgument);
}
