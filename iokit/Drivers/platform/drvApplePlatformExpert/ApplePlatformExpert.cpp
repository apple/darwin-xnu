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
 * HISTORY
 * 
 */

#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IORangeAllocator.h>
#include <IOKit/nvram/IONVRAMController.h>

#include <IOKit/platform/ApplePlatformExpert.h>


const OSSymbol *gGetDefaultBusSpeedsKey;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super IODTPlatformExpert

OSDefineMetaClassAndAbstractStructors(ApplePlatformExpert, IODTPlatformExpert);

OSMetaClassDefineReservedUnused(ApplePlatformExpert,  0);
OSMetaClassDefineReservedUnused(ApplePlatformExpert,  1);
OSMetaClassDefineReservedUnused(ApplePlatformExpert,  2);
OSMetaClassDefineReservedUnused(ApplePlatformExpert,  3);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool ApplePlatformExpert::start( IOService * provider )
{
  UInt16 romVersion;
  
  gGetDefaultBusSpeedsKey = OSSymbol::withCString("GetDefaultBusSpeeds");
  
  if (provider->getProperty(gIODTNWInterruptMappingKey)) {
    // new world interrupt mapping => new world, for now
    setBootROMType(kBootROMTypeNewWorld); 
  } else {
    setBootROMType(kBootROMTypeOldWorld);
    
    // Get the Rom Minor Version from the 68k ROM.
    romVersion = ml_phys_read(0xffc00010) & 0x0000ffff;
    provider->setProperty("rom-version", &romVersion, sizeof(romVersion));
  }
  
  return super::start(provider);
}

bool ApplePlatformExpert::configure( IOService * provider )
{
  IORangeAllocator *	physicalRanges;

  if((physicalRanges = getPhysicalRangeAllocator())) {
    physicalRanges->allocateRange(0,0x80000000);		// RAM
    physicalRanges->allocateRange(0xff000000,0x01000000);	// ROM
  }
  return(super::configure(provider));
}

const char * ApplePlatformExpert::deleteList ( void )
{
    return( "('packages', 'psuedo-usb', 'psuedo-hid', 'multiboot', 'rtas')" );
}

const char * ApplePlatformExpert::excludeList( void )
{
    return( "('chosen', 'memory', 'openprom', 'AAPL,ROM', 'rom', 'options', 'aliases')");
}

void ApplePlatformExpert::registerNVRAMController( IONVRAMController * nvram )
{
  IOReturn err;
  enum {   kXPRAMTimeToGMTOffset = 0xEC };
  
  super::registerNVRAMController(nvram);
  
  // Here we are saving off the time zone info that's in PRAM.
  // This probably should be a separate call that the
  // ApplePlatformExpert does in it's initialization.  -ECH
  
  err = readXPRAM(kXPRAMTimeToGMTOffset, (UInt8 *)&_timeToGMT,
		  sizeof(_timeToGMT));
  if (err == kIOReturnSuccess) {
    // Convert from a SInt24 - sign extend from bit 23.
    if (_timeToGMT & (1 << 23))
      _timeToGMT |= 0xFF000000;
    else
      _timeToGMT &= 0x00FFFFFF; 
  }
}

#define	SECS_BETWEEN_1904_1970	2082844800

long ApplePlatformExpert::getGMTTimeOfDay(void)
{
   long localtime;

   // to avid to hang the kernel at boot
   // I set a limit of 15 seconds waiting
   // for the real time clock.
   mach_timespec_t  t;
   t.tv_sec = 30;
   t.tv_nsec = 0;
   if (waitForService(resourceMatching("IORTC"), &t ) != NULL) {
       if (PE_read_write_time_of_day(kPEReadTOD, &localtime) == 0)
           return (localtime - _timeToGMT - SECS_BETWEEN_1904_1970);
   }
   else
      IOLog("ApplePlatformExpert::getGMTTimeOfDay can not provide time of day RTC did not show up\n");

    return(0);
}

void ApplePlatformExpert::setGMTTimeOfDay(long secs)
{
   // to avid to hang the kernel at boot 
   // I set a limit of 15 seconds waiting
   // for the real time clock.
   mach_timespec_t  t;   
   t.tv_sec = 30;    
   t.tv_nsec = 0;  
   if (waitForService(resourceMatching("IORTC"), &t ) != NULL) { 
        secs += SECS_BETWEEN_1904_1970;
        secs += _timeToGMT;
        PE_read_write_time_of_day(kPEWriteTOD, &secs);
    }
    else
      IOLog("ApplePlatformExpert::setGMTTimeOfDay can not set time of day RTC did not show up\n"); 

}

bool ApplePlatformExpert::getMachineName(char *name, int maxLength)
{
  strncpy(name, "Power Macintosh", maxLength);
  
  return true;
}
