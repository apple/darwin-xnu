/*
 * Copyright (c) 1998-2014 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
 
#include <IOKit/IOCPU.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOKitDebug.h>
#include <IOKit/IOMapper.h>
#include <IOKit/IOMessage.h>
#include <IOKit/IONVRAM.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IORangeAllocator.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOTimeStamp.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOKitDiagnosticsUserClient.h>

#include <IOKit/system.h>
#include <sys/csr.h>

#include <libkern/c++/OSContainers.h>
#include <libkern/crypto/sha1.h>
#include <libkern/OSAtomic.h>

extern "C" {
#include <machine/machine_routines.h>
#include <pexpert/pexpert.h>
#include <uuid/uuid.h>
}

#if defined(__x86_64__)
/*
 * This will eventually be properly exported in
 * <rdar://problem/31181482> ER: Expose coprocessor version (T208/T290) in a kernel/kext header
 * although we'll always need to hardcode this here since we won't be able to include whatever
 * header this ends up in.
 */
#define kCoprocessorMinVersion 0x00020000
#endif

void printDictionaryKeys (OSDictionary * inDictionary, char * inMsg);
static void getCStringForObject(OSObject *inObj, char *outStr, size_t outStrLen);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super IOService

OSDefineMetaClassAndStructors(IOPlatformExpert, IOService)

OSMetaClassDefineReservedUsed(IOPlatformExpert,  0);
OSMetaClassDefineReservedUsed(IOPlatformExpert,  1);
OSMetaClassDefineReservedUsed(IOPlatformExpert,  2);
OSMetaClassDefineReservedUsed(IOPlatformExpert,  3);
OSMetaClassDefineReservedUsed(IOPlatformExpert,  4);

OSMetaClassDefineReservedUnused(IOPlatformExpert,  5);
OSMetaClassDefineReservedUnused(IOPlatformExpert,  6);
OSMetaClassDefineReservedUnused(IOPlatformExpert,  7);
OSMetaClassDefineReservedUnused(IOPlatformExpert,  8);
OSMetaClassDefineReservedUnused(IOPlatformExpert,  9);
OSMetaClassDefineReservedUnused(IOPlatformExpert, 10);
OSMetaClassDefineReservedUnused(IOPlatformExpert, 11);

static IOPlatformExpert * gIOPlatform;
static OSDictionary * gIOInterruptControllers;
static IOLock * gIOInterruptControllersLock;
static IODTNVRAM *gIOOptionsEntry;

OSSymbol * gPlatformInterruptControllerName;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool IOPlatformExpert::attach( IOService * provider )
{

    if( !super::attach( provider ))
	return( false);

    return( true);
}

bool IOPlatformExpert::start( IOService * provider )
{
    IORangeAllocator *	physicalRanges;
    OSData *		busFrequency;
    uint32_t		debugFlags;

#if defined(__x86_64__)
    IORegistryEntry	*platform_entry = NULL;
    OSData		*coprocessor_version_obj = NULL;
    uint64_t		coprocessor_version = 0;
#endif
    
    if (!super::start(provider))
      return false;
    
    // Override the mapper present flag is requested by boot arguments, if SIP disabled.
#if CONFIG_CSR
    if (csr_check(CSR_ALLOW_UNRESTRICTED_FS) == 0)
#endif /* CONFIG_CSR */
    {
	if (PE_parse_boot_argn("dart", &debugFlags, sizeof (debugFlags)) && (debugFlags == 0))
	    removeProperty(kIOPlatformMapperPresentKey);
#if DEBUG || DEVELOPMENT
	if (PE_parse_boot_argn("-x", &debugFlags, sizeof (debugFlags)))
	    removeProperty(kIOPlatformMapperPresentKey);
#endif /* DEBUG || DEVELOPMENT */
    }

    // Register the presence or lack thereof a system 
    // PCI address mapper with the IOMapper class
    IOMapper::setMapperRequired(0 != getProperty(kIOPlatformMapperPresentKey));
    
    gIOInterruptControllers = OSDictionary::withCapacity(1);
    gIOInterruptControllersLock = IOLockAlloc();
    
    // Correct the bus frequency in the device tree.
    busFrequency = OSData::withBytesNoCopy((void *)&gPEClockFrequencyInfo.bus_clock_rate_hz, 4);
    provider->setProperty("clock-frequency", busFrequency);
    busFrequency->release();
    
    gPlatformInterruptControllerName = (OSSymbol *)OSSymbol::withCStringNoCopy("IOPlatformInterruptController");
    
    physicalRanges = IORangeAllocator::withRange(0xffffffff, 1, 16,
						 IORangeAllocator::kLocking);
    assert(physicalRanges);
    setProperty("Platform Memory Ranges", physicalRanges);
    
    setPlatform( this );
    gIOPlatform = this;
    
    PMInstantiatePowerDomains();
    
    // Parse the serial-number data and publish a user-readable string
    OSData* mydata = (OSData*) (provider->getProperty("serial-number"));
    if (mydata != NULL) {
        OSString *serNoString = createSystemSerialNumberString(mydata);
        if (serNoString != NULL) {
            provider->setProperty(kIOPlatformSerialNumberKey, serNoString);
            serNoString->release();
        }
    }

#if defined(__x86_64__)
    platform_entry = IORegistryEntry::fromPath(kIODeviceTreePlane ":/efi/platform");
    if (platform_entry != NULL) {
        coprocessor_version_obj = OSDynamicCast(OSData, platform_entry->getProperty("apple-coprocessor-version"));
        if ((coprocessor_version_obj != NULL) && (coprocessor_version_obj->getLength() <= sizeof(coprocessor_version))) {
            memcpy(&coprocessor_version, coprocessor_version_obj->getBytesNoCopy(), coprocessor_version_obj->getLength());
            if (coprocessor_version >= kCoprocessorMinVersion) {
                coprocessor_paniclog_flush = TRUE;
            }
        }
        platform_entry->release();
    }
#endif /* defined(__x86_64__) */

    return( configure(provider) );
}

bool IOPlatformExpert::configure( IOService * provider )
{
    OSSet *		topLevel;
    OSDictionary *	dict;
    IOService * 	nub;

    topLevel = OSDynamicCast( OSSet, getProperty("top-level"));

    if( topLevel) {
        while( (dict = OSDynamicCast( OSDictionary,
				topLevel->getAnyObject()))) {
            dict->retain();
            topLevel->removeObject( dict );
            nub = createNub( dict );
            if( 0 == nub)
                continue;
            dict->release();
            nub->attach( this );
            nub->registerService();
        }
    }

    return( true );
}

IOService * IOPlatformExpert::createNub( OSDictionary * from )
{
    IOService *		nub;

    nub = new IOPlatformDevice;
    if(nub) {
	if( !nub->init( from )) {
	    nub->release();
	    nub = 0;
	}
    }
    return( nub);
}

bool IOPlatformExpert::compareNubName( const IOService * nub,
				OSString * name, OSString ** matched ) const
{
    return( nub->IORegistryEntry::compareName( name, matched ));
}

IOReturn IOPlatformExpert::getNubResources( IOService * nub )
{
    return( kIOReturnSuccess );
}

long IOPlatformExpert::getBootROMType(void)
{
  return _peBootROMType;
}

long IOPlatformExpert::getChipSetType(void)
{
  return _peChipSetType;
}

long IOPlatformExpert::getMachineType(void)
{
  return _peMachineType;
}

void IOPlatformExpert::setBootROMType(long peBootROMType)
{
  _peBootROMType = peBootROMType;
}

void IOPlatformExpert::setChipSetType(long peChipSetType)
{
  _peChipSetType = peChipSetType;
}

void IOPlatformExpert::setMachineType(long peMachineType)
{
  _peMachineType = peMachineType;
}

bool IOPlatformExpert::getMachineName( char * /*name*/, int /*maxLength*/)
{
    return( false );
}

bool IOPlatformExpert::getModelName( char * /*name*/, int /*maxLength*/)
{
    return( false );
}

OSString* IOPlatformExpert::createSystemSerialNumberString(OSData* myProperty)
{
    return NULL;
}

IORangeAllocator * IOPlatformExpert::getPhysicalRangeAllocator(void)
{
    return(OSDynamicCast(IORangeAllocator,
			getProperty("Platform Memory Ranges")));
}

int (*PE_halt_restart)(unsigned int type) = 0;

int IOPlatformExpert::haltRestart(unsigned int type)
{
  if (type == kPEPanicSync) return 0;

  if (type == kPEHangCPU) while (true) {}

  if (type == kPEUPSDelayHaltCPU) {
    // RestartOnPowerLoss feature was turned on, proceed with shutdown.
    type = kPEHaltCPU;
  }

#if !CONFIG_EMBEDDED
  // On ARM kPEPanicRestartCPU is supported in the drivers
  if (type == kPEPanicRestartCPU)
	  type = kPERestartCPU;
#endif

  if (PE_halt_restart) return (*PE_halt_restart)(type);
  else return -1;
}

void IOPlatformExpert::sleepKernel(void)
{
#if 0
  long cnt;
  boolean_t intState;
  
  intState = ml_set_interrupts_enabled(false);
  
  for (cnt = 0; cnt < 10000; cnt++) {
    IODelay(1000);
  }
  
  ml_set_interrupts_enabled(intState);
#else
//  PE_initialize_console(0, kPEDisableScreen);
  
  IOCPUSleepKernel();
  
//  PE_initialize_console(0, kPEEnableScreen);
#endif
}

long IOPlatformExpert::getGMTTimeOfDay(void)
{
    return(0);
}

void IOPlatformExpert::setGMTTimeOfDay(long secs)
{
}


IOReturn IOPlatformExpert::getConsoleInfo( PE_Video * consoleInfo )
{
    return( PE_current_console( consoleInfo));
}

IOReturn IOPlatformExpert::setConsoleInfo( PE_Video * consoleInfo,
						unsigned int op)
{
    return( PE_initialize_console( consoleInfo, op ));
}

IOReturn IOPlatformExpert::registerInterruptController(OSSymbol *name, IOInterruptController *interruptController)
{
  IOLockLock(gIOInterruptControllersLock);
  
  gIOInterruptControllers->setObject(name, interruptController);
  
  IOLockWakeup(gIOInterruptControllersLock,
		gIOInterruptControllers, /* one-thread */ false);

  IOLockUnlock(gIOInterruptControllersLock);
  
  return kIOReturnSuccess;
}

IOReturn IOPlatformExpert::deregisterInterruptController(OSSymbol *name)
{
  IOLockLock(gIOInterruptControllersLock);
  
  gIOInterruptControllers->removeObject(name);
  
  IOLockUnlock(gIOInterruptControllersLock);
  
  return kIOReturnSuccess;
}

IOInterruptController *IOPlatformExpert::lookUpInterruptController(OSSymbol *name)
{
  OSObject              *object;
  
  IOLockLock(gIOInterruptControllersLock);
  while (1) {
    
    object = gIOInterruptControllers->getObject(name);
    
    if (object != 0)
	break;
    
    IOLockSleep(gIOInterruptControllersLock,
		gIOInterruptControllers, THREAD_UNINT);
  }
  
  IOLockUnlock(gIOInterruptControllersLock);
  return OSDynamicCast(IOInterruptController, object);
}


void IOPlatformExpert::setCPUInterruptProperties(IOService *service)
{
  IOCPUInterruptController *controller;
  
  controller = OSDynamicCast(IOCPUInterruptController, waitForService(serviceMatching("IOCPUInterruptController")));
  if (controller) controller->setCPUInterruptProperties(service);
}

bool IOPlatformExpert::atInterruptLevel(void)
{
  return ml_at_interrupt_context();
}

bool IOPlatformExpert::platformAdjustService(IOService */*service*/)
{
  return true;
}

void IOPlatformExpert::getUTCTimeOfDay(clock_sec_t * secs, clock_nsec_t * nsecs)
{
  *secs = getGMTTimeOfDay();
  *nsecs = 0;
}

void IOPlatformExpert::setUTCTimeOfDay(clock_sec_t secs, __unused clock_nsec_t nsecs)
{
  setGMTTimeOfDay(secs);
}


//*********************************************************************************
// PMLog
//
//*********************************************************************************

void IOPlatformExpert::
PMLog(const char *who, unsigned long event,
      unsigned long param1, unsigned long param2)
{
	clock_sec_t nows;
	clock_usec_t nowus;
	clock_get_system_microtime(&nows, &nowus);
	nowus += (nows % 1000) * 1000000;

    kprintf("pm%u %p %.30s %d %lx %lx\n",
		nowus, OBFUSCATE(current_thread()), who,	// Identity
		(int) event, (long)OBFUSCATE(param1), (long)OBFUSCATE(param2));			// Args
}


//*********************************************************************************
// PMInstantiatePowerDomains
//
// In this vanilla implementation, a Root Power Domain is instantiated.
// All other objects which register will be children of this Root.
// Where this is inappropriate, PMInstantiatePowerDomains is overridden 
// in a platform-specific subclass.
//*********************************************************************************

void IOPlatformExpert::PMInstantiatePowerDomains ( void )
{
    root = new IOPMrootDomain;
    root->init();
    root->attach(this);
    root->start(this);
}


//*********************************************************************************
// PMRegisterDevice
//
// In this vanilla implementation, all callers are made children of the root power domain.
// Where this is inappropriate, PMRegisterDevice is overridden in a platform-specific subclass.
//*********************************************************************************

void IOPlatformExpert::PMRegisterDevice(IOService * theNub, IOService * theDevice)
{
    root->addPowerChild ( theDevice );
}

//*********************************************************************************
// hasPMFeature
//
//*********************************************************************************

bool IOPlatformExpert::hasPMFeature (unsigned long featureMask)
{
  return ((_pePMFeatures & featureMask) != 0);
}

//*********************************************************************************
// hasPrivPMFeature
//
//*********************************************************************************

bool IOPlatformExpert::hasPrivPMFeature (unsigned long privFeatureMask)
{
  return ((_pePrivPMFeatures & privFeatureMask) != 0);
}

//*********************************************************************************
// numBatteriesSupported
//
//*********************************************************************************

int IOPlatformExpert::numBatteriesSupported (void)
{
  return (_peNumBatteriesSupported);
}

//*********************************************************************************
// CheckSubTree
//
// This method is called by the instantiated sublass of the platform expert to
// determine how a device should be inserted into the Power Domain. The subclass
// provides an XML power tree description against which a device is matched based
// on class and provider. If a match is found this routine returns true in addition
// to flagging the description tree at the appropriate node that a device has been
// registered for the given service.
//*********************************************************************************

bool IOPlatformExpert::CheckSubTree (OSArray * inSubTree, IOService * theNub, IOService * theDevice, OSDictionary * theParent)
{
  unsigned int    i;
  unsigned int    numPowerTreeNodes;
  OSDictionary *  entry;
  OSDictionary *  matchingDictionary;
  OSDictionary *  providerDictionary;
  OSDictionary *  deviceDictionary;
  OSDictionary *  nubDictionary;
  OSArray *       children;
  bool            nodeFound            = false;
  bool            continueSearch       = false;
  bool            deviceMatch          = false;
  bool            providerMatch        = false;
  bool            multiParentMatch     = false;

  if ( (NULL == theDevice) || (NULL == inSubTree) )
    return false;

  numPowerTreeNodes = inSubTree->getCount ();

  // iterate through the power tree to find a home for this device

  for ( i = 0; i < numPowerTreeNodes; i++ ) {

    entry =  (OSDictionary *) inSubTree->getObject (i);

    matchingDictionary = (OSDictionary *) entry->getObject ("device");
    providerDictionary = (OSDictionary *) entry->getObject ("provider");

    deviceMatch = true; // if no matching dictionary, this is not a criteria and so must match
    if ( matchingDictionary ) {
      deviceMatch = false;
      if ( NULL != (deviceDictionary = theDevice->dictionaryWithProperties ())) {
        deviceMatch = deviceDictionary->isEqualTo ( matchingDictionary, matchingDictionary );
        deviceDictionary->release ();
      }
    }

    providerMatch = true; // we indicate a match if there is no nub or provider
    if ( theNub && providerDictionary ) {
      providerMatch = false;
      if ( NULL != (nubDictionary = theNub->dictionaryWithProperties ()) ) {
        providerMatch = nubDictionary->isEqualTo ( providerDictionary,  providerDictionary );
        nubDictionary->release ();
      }
    }

    multiParentMatch = true; // again we indicate a match if there is no multi-parent node
    if (deviceMatch && providerMatch) {
      if (NULL != multipleParentKeyValue) {
        OSNumber * aNumber = (OSNumber *) entry->getObject ("multiple-parent");
        multiParentMatch   = (NULL != aNumber) ? multipleParentKeyValue->isEqualTo (aNumber) : false;
      }
    }

    nodeFound = (deviceMatch && providerMatch && multiParentMatch);

    // if the power tree specifies a provider dictionary but theNub is
    // NULL then we cannot match with this entry.

    if ( theNub == NULL && providerDictionary != NULL )
      nodeFound = false;
  
    // if this node is THE ONE...then register the device

    if ( nodeFound ) {
      if (RegisterServiceInTree (theDevice, entry, theParent, theNub) ) {

        if ( kIOLogPower & gIOKitDebug)
          IOLog ("PMRegisterDevice/CheckSubTree - service registered!\n");

	numInstancesRegistered++;

	// determine if we need to search for additional nodes for this item
	multipleParentKeyValue = (OSNumber *) entry->getObject ("multiple-parent");
      }
      else
	nodeFound = false;
    }

    continueSearch = ( (false == nodeFound) || (NULL != multipleParentKeyValue) );

    if ( continueSearch && (NULL != (children = (OSArray *) entry->getObject ("children"))) ) {
      nodeFound = CheckSubTree ( children, theNub, theDevice, entry );
      continueSearch = ( (false == nodeFound) || (NULL != multipleParentKeyValue) );
    }

    if ( false == continueSearch )
      break;
  }

  return ( nodeFound );
}

//*********************************************************************************
// RegisterServiceInTree
//
// Register a device at the specified node of our power tree.
//*********************************************************************************

bool IOPlatformExpert::RegisterServiceInTree (IOService * theService, OSDictionary * theTreeNode, OSDictionary * theTreeParentNode, IOService * theProvider)
{
  IOService *    aService;
  bool           registered = false;
  OSArray *      children;
  unsigned int   numChildren;
  OSDictionary * child;

  // make sure someone is not already registered here

  if ( NULL == theTreeNode->getObject ("service") ) {

    if ( theTreeNode->setObject ("service", OSDynamicCast ( OSObject, theService)) ) {

      // 1. CHILDREN ------------------

      // we registered the node in the tree...now if the node has children
      // registered we must tell this service to add them.

      if ( NULL != (children = (OSArray *) theTreeNode->getObject ("children")) ) {
        numChildren = children->getCount ();
        for ( unsigned int i = 0; i < numChildren; i++ ) {
          if ( NULL != (child = (OSDictionary *) children->getObject (i)) ) {
            if ( NULL != (aService = (IOService *) child->getObject ("service")) )
              theService->addPowerChild (aService);
          }
        }
      }

      // 2. PARENT --------------------

      // also we must notify the parent of this node (if a registered service
      // exists there) of a new child.

      if ( theTreeParentNode ) {
        if ( NULL != (aService = (IOService *) theTreeParentNode->getObject ("service")) )
          if (aService != theProvider)
            aService->addPowerChild (theService);
      }

      registered = true;
    }
  }

  return registered;
}

//*********************************************************************************
// printDictionaryKeys
//
// Print the keys for the given dictionary and selected contents.
//*********************************************************************************
void printDictionaryKeys (OSDictionary * inDictionary, char * inMsg)
{
  OSCollectionIterator * mcoll = OSCollectionIterator::withCollection (inDictionary);
  OSSymbol * mkey;
  OSString * ioClass;
  unsigned int i = 0;
 
  mcoll->reset ();

  mkey = OSDynamicCast (OSSymbol, mcoll->getNextObject ());

  while (mkey) {

    // kprintf ("dictionary key #%d: %s\n", i, mkey->getCStringNoCopy () );

    // if this is the IOClass key, print it's contents

    if ( mkey->isEqualTo ("IOClass") ) {
      ioClass = (OSString *) inDictionary->getObject ("IOClass");
      if ( ioClass ) IOLog ("%s IOClass is %s\n", inMsg, ioClass->getCStringNoCopy () );
    }

    // if this is an IOProviderClass key print it

    if ( mkey->isEqualTo ("IOProviderClass") ) {
      ioClass = (OSString *) inDictionary->getObject ("IOProviderClass");
      if ( ioClass ) IOLog ("%s IOProviderClass is %s\n", inMsg, ioClass->getCStringNoCopy () );

    }

    // also print IONameMatch keys
    if ( mkey->isEqualTo ("IONameMatch") ) {
      ioClass = (OSString *) inDictionary->getObject ("IONameMatch");
      if ( ioClass ) IOLog ("%s IONameMatch is %s\n", inMsg, ioClass->getCStringNoCopy () );
    }

    // also print IONameMatched keys

    if ( mkey->isEqualTo ("IONameMatched") ) {
      ioClass = (OSString *) inDictionary->getObject ("IONameMatched");
      if ( ioClass ) IOLog ("%s IONameMatched is %s\n", inMsg, ioClass->getCStringNoCopy () );
    }

#if 0
    // print clock-id

    if ( mkey->isEqualTo ("AAPL,clock-id") ) {
      char * cstr;
      cstr = getCStringForObject (inDictionary->getObject ("AAPL,clock-id"));
      if (cstr)
        kprintf (" ===> AAPL,clock-id is %s\n", cstr );
    }
#endif

    // print name

    if ( mkey->isEqualTo ("name") ) {
      char nameStr[64];
      nameStr[0] = 0;
      getCStringForObject(inDictionary->getObject("name"), nameStr,
		      sizeof(nameStr));
      if (strlen(nameStr) > 0)
        IOLog ("%s name is %s\n", inMsg, nameStr);
    }

    mkey = (OSSymbol *) mcoll->getNextObject ();

    i++;
  }

  mcoll->release ();
}

static void
getCStringForObject(OSObject *inObj, char *outStr, size_t outStrLen)
{
   char * buffer;
   unsigned int    len, i;

   if ( (NULL == inObj) || (NULL == outStr))
     return;

   char * objString = (char *) (inObj->getMetaClass())->getClassName();

   if ((0 == strncmp(objString, "OSString", sizeof("OSString"))) ||
		   (0 == strncmp(objString, "OSSymbol", sizeof("OSSymbol"))))
     strlcpy(outStr, ((OSString *)inObj)->getCStringNoCopy(), outStrLen);

   else if (0 == strncmp(objString, "OSData", sizeof("OSData"))) {
     len = ((OSData *)inObj)->getLength();
     buffer = (char *)((OSData *)inObj)->getBytesNoCopy();
     if (buffer && (len > 0)) {
       for (i=0; i < len; i++) {
         outStr[i] = buffer[i];
       }
       outStr[len] = 0;
     }
   }
}

/* IOShutdownNotificationsTimedOut
 * - Called from a timer installed by PEHaltRestart
 */
static void IOShutdownNotificationsTimedOut(
    thread_call_param_t p0, 
    thread_call_param_t p1)
{
#ifdef CONFIG_EMBEDDED
    /* 30 seconds has elapsed - panic */
    panic("Halt/Restart Timed Out");

#else /* ! CONFIG_EMBEDDED */
    int type = (int)(long)p0;

    /* 30 seconds has elapsed - resume shutdown */
    if(gIOPlatform) gIOPlatform->haltRestart(type);
#endif /* CONFIG_EMBEDDED */
}


extern "C" {

/*
 * Callouts from BSD for machine name & model
 */ 

boolean_t PEGetMachineName( char * name, int maxLength )
{
    if( gIOPlatform)
	return( gIOPlatform->getMachineName( name, maxLength ));
    else
	return( false );
}

boolean_t PEGetModelName( char * name, int maxLength )
{
    if( gIOPlatform)
	return( gIOPlatform->getModelName( name, maxLength ));
    else
	return( false );
}

int PEGetPlatformEpoch(void)
{
    if( gIOPlatform)
	return( gIOPlatform->getBootROMType());
    else
	return( -1 );
}

int PEHaltRestart(unsigned int type)
{
  IOPMrootDomain    *pmRootDomain;
  AbsoluteTime      deadline;
  thread_call_t     shutdown_hang;
  IORegistryEntry   *node;
  OSData            *data;
  uint32_t          timeout = 30;
  static boolean_t  panic_begin_called = FALSE;
  
  if(type == kPEHaltCPU || type == kPERestartCPU || type == kPEUPSDelayHaltCPU)
  {
    pmRootDomain = IOService::getPMRootDomain();
    /* Notify IOKit PM clients of shutdown/restart
       Clients subscribe to this message with a call to
       IOService::registerInterest()
    */
    
    /* Spawn a thread that will panic in 30 seconds. 
       If all goes well the machine will be off by the time
       the timer expires. If the device wants a different
       timeout, use that value instead of 30 seconds.
     */
#if CONFIG_EMBEDDED
#define RESTART_NODE_PATH    "/defaults"
#else
#define RESTART_NODE_PATH    "/chosen"
#endif
    node = IORegistryEntry::fromPath( RESTART_NODE_PATH, gIODTPlane );
    if ( node ) {
      data = OSDynamicCast( OSData, node->getProperty( "halt-restart-timeout" ) );
      if ( data && data->getLength() == 4 )
        timeout = *((uint32_t *) data->getBytesNoCopy());
    }

    shutdown_hang = thread_call_allocate( &IOShutdownNotificationsTimedOut, 
                        (thread_call_param_t)(uintptr_t) type);
    clock_interval_to_deadline( timeout, kSecondScale, &deadline );
    thread_call_enter1_delayed( shutdown_hang, 0, deadline );

    pmRootDomain->handlePlatformHaltRestart(type); 
    /* This notification should have few clients who all do 
       their work synchronously.
             
       In this "shutdown notification" context we don't give
       drivers the option of working asynchronously and responding 
       later. PM internals make it very hard to wait for asynchronous
       replies.
     */
   }
   else if(type == kPEPanicRestartCPU || type == kPEPanicSync)
   {
       if (type == kPEPanicRestartCPU) {
           // Notify any listeners that we're done collecting
           // panic data before we call through to do the restart
           IOCPURunPlatformPanicActions(kPEPanicEnd);
       }

       // Do an initial sync to flush as much panic data as possible,
       // in case we have a problem in one of the platorm panic handlers.
       // After running the platform handlers, do a final sync w/
       // platform hardware quiesced for the panic.
       PE_sync_panic_buffers();
       IOCPURunPlatformPanicActions(type);
       PE_sync_panic_buffers();
   }
   else if (type == kPEPanicEnd) {
       IOCPURunPlatformPanicActions(type);
   } else if (type == kPEPanicBegin) {
       // Only call the kPEPanicBegin callout once
       if (!panic_begin_called) {
           panic_begin_called = TRUE;
           IOCPURunPlatformPanicActions(type);
       }
   }

  if (gIOPlatform) return gIOPlatform->haltRestart(type);
  else return -1;
}

UInt32 PESavePanicInfo(UInt8 *buffer, UInt32 length)
{
  if (gIOPlatform != 0) return gIOPlatform->savePanicInfo(buffer, length);
  else return 0;
}

void PESavePanicInfoAction(void *buffer, size_t length)
{
	IOCPURunPlatformPanicSyncAction(buffer, length);
	return;
}


inline static int init_gIOOptionsEntry(void)
{
    IORegistryEntry *entry;
    void *nvram_entry;
    volatile void **options;
    int ret = -1;

    if (gIOOptionsEntry) 
        return 0;

    entry = IORegistryEntry::fromPath( "/options", gIODTPlane );
    if (!entry)
        return -1;

    nvram_entry = (void *) OSDynamicCast(IODTNVRAM, entry);
    if (!nvram_entry) 
        goto release;

    options = (volatile void **) &gIOOptionsEntry;
    if (!OSCompareAndSwapPtr(NULL, nvram_entry, options)) {
        ret = 0;
        goto release;
    }

    return 0;

release:
    entry->release();
    return ret;

}

/* pass in a NULL value if you just want to figure out the len */
boolean_t PEReadNVRAMProperty(const char *symbol, void *value,
                              unsigned int *len)
{
    OSObject  *obj;
    OSData *data;
    unsigned int vlen;

    if (!symbol || !len)
        goto err;

    if (init_gIOOptionsEntry() < 0)
        goto err;

    vlen = *len;
    *len = 0;

    obj = gIOOptionsEntry->getProperty(symbol);
    if (!obj)
        goto err;

    /* convert to data */
    data = OSDynamicCast(OSData, obj);
    if (!data) 
        goto err;

    *len  = data->getLength();
    vlen  = min(vlen, *len);
    if (value && vlen)
        memcpy((void *) value, data->getBytesNoCopy(), vlen);

    return TRUE;

err:
    return FALSE;
}

boolean_t
PEWriteNVRAMBooleanProperty(const char *symbol, boolean_t value)
{
	const OSSymbol *sym = NULL;
	OSBoolean *data = NULL;
	bool ret = false;

	if (symbol == NULL) {
		goto exit;
	}

	if (init_gIOOptionsEntry() < 0) {
		goto exit;
	}

	if ((sym = OSSymbol::withCStringNoCopy(symbol)) == NULL) {
		goto exit;
	}

	data  = value ? kOSBooleanTrue : kOSBooleanFalse;
	ret = gIOOptionsEntry->setProperty(sym, data);

	sym->release();

	/* success, force the NVRAM to flush writes */
	if (ret == true) {
		gIOOptionsEntry->sync();
	}

exit:
	return ret;
}

boolean_t PEWriteNVRAMProperty(const char *symbol, const void *value, 
                               const unsigned int len)
{
    const OSSymbol *sym;
    OSData *data;
    bool ret = false;

    if (!symbol || !value || !len)
        goto err;

    if (init_gIOOptionsEntry() < 0)
        goto err;

    sym = OSSymbol::withCStringNoCopy(symbol);
    if (!sym)
        goto err;

    data = OSData::withBytes((void *) value, len);
    if (!data)
        goto sym_done;

    ret = gIOOptionsEntry->setProperty(sym, data);
    data->release();

sym_done:
    sym->release();

    if (ret == true) {
        gIOOptionsEntry->sync();
        return TRUE;
    }

err:
    return FALSE;
}


boolean_t PERemoveNVRAMProperty(const char *symbol)
{
    const OSSymbol *sym;

    if (!symbol)
        goto err;

    if (init_gIOOptionsEntry() < 0)
        goto err;

    sym = OSSymbol::withCStringNoCopy(symbol);
    if (!sym)
        goto err;

    gIOOptionsEntry->removeProperty(sym);

    sym->release();

    gIOOptionsEntry->sync();
    return TRUE;

err:
    return FALSE;

}

long PEGetGMTTimeOfDay(void)
{
    clock_sec_t     secs;
    clock_usec_t    usecs;

    PEGetUTCTimeOfDay(&secs, &usecs);
    return secs;
}

void PESetGMTTimeOfDay(long secs)
{
    PESetUTCTimeOfDay(secs, 0);
}

void PEGetUTCTimeOfDay(clock_sec_t * secs, clock_usec_t * usecs)
{
    clock_nsec_t    nsecs = 0;

    *secs = 0;
	if (gIOPlatform)
        gIOPlatform->getUTCTimeOfDay(secs, &nsecs);

    assert(nsecs < NSEC_PER_SEC);
    *usecs = nsecs / NSEC_PER_USEC;
}

void PESetUTCTimeOfDay(clock_sec_t secs, clock_usec_t usecs)
{
    assert(usecs < USEC_PER_SEC);
	if (gIOPlatform)
        gIOPlatform->setUTCTimeOfDay(secs, usecs * NSEC_PER_USEC);
}

} /* extern "C" */

void IOPlatformExpert::registerNVRAMController(IONVRAMController * caller)
{
    OSData *          data;
    IORegistryEntry * entry;
    OSString *        string = 0;
    uuid_string_t     uuid;

#if CONFIG_EMBEDDED
    entry = IORegistryEntry::fromPath( "/chosen", gIODTPlane );
    if ( entry )
    {
        OSData * data1;

        data1 = OSDynamicCast( OSData, entry->getProperty( "unique-chip-id" ) );
        if ( data1 && data1->getLength( ) == 8 )
        {
            OSData * data2;

            data2 = OSDynamicCast( OSData, entry->getProperty( "chip-id" ) );
            if ( data2 && data2->getLength( ) == 4 )
            {
                SHA1_CTX     context;
                uint8_t      digest[ SHA_DIGEST_LENGTH ];
                const uuid_t space = { 0xA6, 0xDD, 0x4C, 0xCB, 0xB5, 0xE8, 0x4A, 0xF5, 0xAC, 0xDD, 0xB6, 0xDC, 0x6A, 0x05, 0x42, 0xB8 };

                SHA1Init( &context );
                SHA1Update( &context, space, sizeof( space ) );
                SHA1Update( &context, data1->getBytesNoCopy( ), data1->getLength( ) );
                SHA1Update( &context, data2->getBytesNoCopy( ), data2->getLength( ) );
                SHA1Final( digest, &context );

                digest[ 6 ] = ( digest[ 6 ] & 0x0F ) | 0x50;
                digest[ 8 ] = ( digest[ 8 ] & 0x3F ) | 0x80;

                uuid_unparse( digest, uuid );
                string = OSString::withCString( uuid );
            }
        }

        entry->release( );
    }
#else /* !CONFIG_EMBEDDED */
    entry = IORegistryEntry::fromPath( "/efi/platform", gIODTPlane );
    if ( entry )
    {
        data = OSDynamicCast( OSData, entry->getProperty( "system-id" ) );
        if ( data && data->getLength( ) == 16 )
        {
            SHA1_CTX     context;
            uint8_t      digest[ SHA_DIGEST_LENGTH ];
            const uuid_t space = { 0x2A, 0x06, 0x19, 0x90, 0xD3, 0x8D, 0x44, 0x40, 0xA1, 0x39, 0xC4, 0x97, 0x70, 0x37, 0x65, 0xAC };

            SHA1Init( &context );
            SHA1Update( &context, space, sizeof( space ) );
            SHA1Update( &context, data->getBytesNoCopy( ), data->getLength( ) );
            SHA1Final( digest, &context );

            digest[ 6 ] = ( digest[ 6 ] & 0x0F ) | 0x50;
            digest[ 8 ] = ( digest[ 8 ] & 0x3F ) | 0x80;

            uuid_unparse( digest, uuid );
            string = OSString::withCString( uuid );
        }

        entry->release( );
    }
#endif /* !CONFIG_EMBEDDED */

    if ( string == 0 )
    {
        entry = IORegistryEntry::fromPath( "/options", gIODTPlane );
        if ( entry )
        {
            data = OSDynamicCast( OSData, entry->getProperty( "platform-uuid" ) );
            if ( data && data->getLength( ) == sizeof( uuid_t ) )
            {
                uuid_unparse( ( uint8_t * ) data->getBytesNoCopy( ), uuid );
                string = OSString::withCString( uuid );
            }

            entry->release( );
        }
    }

    if ( string )
    {
        getProvider( )->setProperty( kIOPlatformUUIDKey, string );
        publishResource( kIOPlatformUUIDKey, string );

        string->release( );
    }

    publishResource("IONVRAM");
}

IOReturn IOPlatformExpert::callPlatformFunction(const OSSymbol *functionName,
						bool waitForFunction,
						void *param1, void *param2,
						void *param3, void *param4)
{
  IOService *service, *_resources;
  
  if (waitForFunction) {
    _resources = waitForService(resourceMatching(functionName));
  } else {
    _resources = getResourceService();
  }
  if (_resources == 0) return kIOReturnUnsupported;
  
  service = OSDynamicCast(IOService, _resources->getProperty(functionName));
  if (service == 0) return kIOReturnUnsupported;
  
  return service->callPlatformFunction(functionName, waitForFunction,
				       param1, param2, param3, param4);
}

IOByteCount IOPlatformExpert::savePanicInfo(UInt8 *buffer, IOByteCount length)
{
  return 0;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOPlatformExpert

OSDefineMetaClassAndAbstractStructors( IODTPlatformExpert, IOPlatformExpert )

OSMetaClassDefineReservedUnused(IODTPlatformExpert,  0);
OSMetaClassDefineReservedUnused(IODTPlatformExpert,  1);
OSMetaClassDefineReservedUnused(IODTPlatformExpert,  2);
OSMetaClassDefineReservedUnused(IODTPlatformExpert,  3);
OSMetaClassDefineReservedUnused(IODTPlatformExpert,  4);
OSMetaClassDefineReservedUnused(IODTPlatformExpert,  5);
OSMetaClassDefineReservedUnused(IODTPlatformExpert,  6);
OSMetaClassDefineReservedUnused(IODTPlatformExpert,  7);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IOService * IODTPlatformExpert::probe( IOService * provider,
			       		SInt32 * score )
{
    if( !super::probe( provider, score))
	return( 0 );

    // check machine types
    if( !provider->compareNames( getProperty( gIONameMatchKey ) ))
        return( 0 );

    return( this);
}

bool IODTPlatformExpert::configure( IOService * provider )
{
    if( !super::configure( provider))
	return( false);

    processTopLevel( provider );

    return( true );
}

IOService * IODTPlatformExpert::createNub( IORegistryEntry * from )
{
    IOService *		nub;

    nub = new IOPlatformDevice;
    if( nub) {
	if( !nub->init( from, gIODTPlane )) {
	    nub->free();
	    nub = 0;
	}
    }
    return( nub);
}

bool IODTPlatformExpert::createNubs( IOService * parent, OSIterator * iter )
{
    IORegistryEntry *	next;
    IOService *		nub;
    bool		ok = true;

    if( iter) {
	while( (next = (IORegistryEntry *) iter->getNextObject())) {

            if( 0 == (nub = createNub( next )))
                continue;

            nub->attach( parent );
            nub->registerService();
        }
	iter->release();
    }

    return( ok );
}

void IODTPlatformExpert::processTopLevel( IORegistryEntry * rootEntry )
{
    OSIterator * 	kids;
    IORegistryEntry *	next;
    IORegistryEntry *	cpus;
    IORegistryEntry *	options;

    // infanticide
    kids = IODTFindMatchingEntries( rootEntry, 0, deleteList() );
    if( kids) {
	while( (next = (IORegistryEntry *)kids->getNextObject())) {
	    next->detachAll( gIODTPlane);
	}
	kids->release();
    }

    // Publish an IODTNVRAM class on /options.
    options = rootEntry->childFromPath("options", gIODTPlane);
    if (options) {
      dtNVRAM = new IODTNVRAM;
      if (dtNVRAM) {
        if (!dtNVRAM->init(options, gIODTPlane)) {
	  dtNVRAM->release();
	  dtNVRAM = 0;
        } else {
	  dtNVRAM->attach(this);
	  dtNVRAM->registerService();
	  options->release();
	}
      }
    }

    // Publish the cpus.
    cpus = rootEntry->childFromPath( "cpus", gIODTPlane);
    if ( cpus)
    {
      createNubs( this, IODTFindMatchingEntries( cpus, kIODTExclusive, 0));
      cpus->release();
    }

    // publish top level, minus excludeList
    createNubs( this, IODTFindMatchingEntries( rootEntry, kIODTExclusive, excludeList()));
}

IOReturn IODTPlatformExpert::getNubResources( IOService * nub )
{
  if( nub->getDeviceMemory())
    return( kIOReturnSuccess );

  IODTResolveAddressing( nub, "reg", 0);

  return( kIOReturnSuccess);
}

bool IODTPlatformExpert::compareNubName( const IOService * nub,
				OSString * name, OSString ** matched ) const
{
    return( IODTCompareNubName( nub, name, matched )
	  || super::compareNubName( nub, name, matched) );
}

bool IODTPlatformExpert::getModelName( char * name, int maxLength )
{
    OSData *		prop;
    const char *	str;
    int			len;
    char		c;
    bool		ok = false;

    maxLength--;

    prop = (OSData *) getProvider()->getProperty( gIODTCompatibleKey );
    if( prop ) {
	str = (const char *) prop->getBytesNoCopy();

	if( 0 == strncmp( str, "AAPL,", strlen( "AAPL," ) ))
	    str += strlen( "AAPL," );

	len = 0;
	while( (c = *str++)) {
	    if( (c == '/') || (c == ' '))
		c = '-';

	    name[ len++ ] = c;
	    if( len >= maxLength)
		break;
	}

	name[ len ] = 0;
	ok = true;
    }
    return( ok );
}

bool IODTPlatformExpert::getMachineName( char * name, int maxLength )
{
    OSData *		prop;
    bool		ok = false;

    maxLength--;
    prop = (OSData *) getProvider()->getProperty( gIODTModelKey );
    ok = (0 != prop);

    if( ok )
	strlcpy( name, (const char *) prop->getBytesNoCopy(), maxLength );

    return( ok );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void IODTPlatformExpert::registerNVRAMController( IONVRAMController * nvram )
{
  if (dtNVRAM) dtNVRAM->registerNVRAMController(nvram);
  
  super::registerNVRAMController(nvram);
}

int IODTPlatformExpert::haltRestart(unsigned int type)
{
  if (dtNVRAM) dtNVRAM->sync();
  
  return super::haltRestart(type);
}

IOReturn IODTPlatformExpert::readXPRAM(IOByteCount offset, UInt8 * buffer,
				       IOByteCount length)
{
  if (dtNVRAM) return dtNVRAM->readXPRAM(offset, buffer, length);
  else return kIOReturnNotReady;
}

IOReturn IODTPlatformExpert::writeXPRAM(IOByteCount offset, UInt8 * buffer,
					IOByteCount length)
{
  if (dtNVRAM) return dtNVRAM->writeXPRAM(offset, buffer, length);
  else return kIOReturnNotReady;
}

IOReturn IODTPlatformExpert::readNVRAMProperty(
	IORegistryEntry * entry,
	const OSSymbol ** name, OSData ** value )
{
  if (dtNVRAM) return dtNVRAM->readNVRAMProperty(entry, name, value);
  else return kIOReturnNotReady;
}

IOReturn IODTPlatformExpert::writeNVRAMProperty(
	IORegistryEntry * entry,
	const OSSymbol * name, OSData * value )
{
  if (dtNVRAM) return dtNVRAM->writeNVRAMProperty(entry, name, value);
  else return kIOReturnNotReady;
}

OSDictionary *IODTPlatformExpert::getNVRAMPartitions(void)
{
  if (dtNVRAM) return dtNVRAM->getNVRAMPartitions();
  else return 0;
}

IOReturn IODTPlatformExpert::readNVRAMPartition(const OSSymbol * partitionID,
						IOByteCount offset, UInt8 * buffer,
						IOByteCount length)
{
  if (dtNVRAM) return dtNVRAM->readNVRAMPartition(partitionID, offset,
						  buffer, length);
  else return kIOReturnNotReady;
}

IOReturn IODTPlatformExpert::writeNVRAMPartition(const OSSymbol * partitionID,
						 IOByteCount offset, UInt8 * buffer,
						 IOByteCount length)
{
  if (dtNVRAM) return dtNVRAM->writeNVRAMPartition(partitionID, offset,
						   buffer, length);
  else return kIOReturnNotReady;
}

IOByteCount IODTPlatformExpert::savePanicInfo(UInt8 *buffer, IOByteCount length)
{
  IOByteCount lengthSaved = 0;
  
  if (dtNVRAM) lengthSaved = dtNVRAM->savePanicInfo(buffer, length);
  
  if (lengthSaved == 0) lengthSaved = super::savePanicInfo(buffer, length);
  
  return lengthSaved;
}

OSString* IODTPlatformExpert::createSystemSerialNumberString(OSData* myProperty) {
    UInt8* serialNumber;
    unsigned int serialNumberSize;
    unsigned short pos = 0;
    char* temp;
    char SerialNo[30];
    
    if (myProperty != NULL) {
        serialNumberSize = myProperty->getLength();
        serialNumber = (UInt8*)(myProperty->getBytesNoCopy());
        temp = (char*)serialNumber;
        if (serialNumberSize > 0) {
            // check to see if this is a CTO serial number...
            while (pos < serialNumberSize && temp[pos] != '-') pos++;
            
            if (pos < serialNumberSize) { // there was a hyphen, so it's a CTO serial number
                memcpy(SerialNo, serialNumber + 12, 8);
                memcpy(&SerialNo[8], serialNumber, 3);
                SerialNo[11] = '-';
                memcpy(&SerialNo[12], serialNumber + 3, 8);
                SerialNo[20] = 0;
            } else { // just a normal serial number
                memcpy(SerialNo, serialNumber + 13, 8);
                memcpy(&SerialNo[8], serialNumber, 3);
                SerialNo[11] = 0;
            }
            return OSString::withCString(SerialNo);
        }
    }
    return NULL;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOService

OSDefineMetaClassAndStructors(IOPlatformExpertDevice, IOService)

OSMetaClassDefineReservedUnused(IOPlatformExpertDevice,  0);
OSMetaClassDefineReservedUnused(IOPlatformExpertDevice,  1);
OSMetaClassDefineReservedUnused(IOPlatformExpertDevice,  2);
OSMetaClassDefineReservedUnused(IOPlatformExpertDevice,  3);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool IOPlatformExpertDevice::compareName( OSString * name,
                                        OSString ** matched ) const
{
    return( IODTCompareNubName( this, name, matched ));
}

bool
IOPlatformExpertDevice::initWithArgs(
                            void * dtTop, void * p2, void * p3, void * p4 )
{
    IORegistryEntry * 	dt = 0;
    bool		ok;

    // dtTop may be zero on non- device tree systems
    if( dtTop && (dt = IODeviceTreeAlloc( dtTop )))
	ok = super::init( dt, gIODTPlane );
    else
	ok = super::init();

    if( !ok)
	return( false);

    reserved = NULL;
    workLoop = IOWorkLoop::workLoop();
    if (!workLoop)
        return false;

    return( true);
}

IOWorkLoop *IOPlatformExpertDevice::getWorkLoop() const
{
    return workLoop;
}

IOReturn IOPlatformExpertDevice::setProperties( OSObject * properties )
{
    OSDictionary * dictionary;
    OSObject *     object;
    IOReturn       status;

    status = super::setProperties( properties );
    if ( status != kIOReturnUnsupported ) return status;

    status = IOUserClient::clientHasPrivilege( current_task( ), kIOClientPrivilegeAdministrator );
    if ( status != kIOReturnSuccess ) return status;

    dictionary = OSDynamicCast( OSDictionary, properties );
    if ( dictionary == 0 ) return kIOReturnBadArgument;

    object = dictionary->getObject( kIOPlatformUUIDKey );
    if ( object )
    {
        IORegistryEntry * entry;
        OSString *        string;
        uuid_t            uuid;

        string = ( OSString * ) getProperty( kIOPlatformUUIDKey );
        if ( string ) return kIOReturnNotPermitted;

        string = OSDynamicCast( OSString, object );
        if ( string == 0 ) return kIOReturnBadArgument;

        status = uuid_parse( string->getCStringNoCopy( ), uuid );
        if ( status != 0 ) return kIOReturnBadArgument;

        entry = IORegistryEntry::fromPath( "/options", gIODTPlane );
        if ( entry )
        {
            entry->setProperty( "platform-uuid", uuid, sizeof( uuid_t ) );
            entry->release( );
        }

        setProperty( kIOPlatformUUIDKey, string );
        publishResource( kIOPlatformUUIDKey, string );

        return kIOReturnSuccess;
    }

    return kIOReturnUnsupported;
}

IOReturn IOPlatformExpertDevice::newUserClient( task_t owningTask, void * securityID,
                                    UInt32 type,  OSDictionary * properties,
                                    IOUserClient ** handler )
{
    IOReturn            err = kIOReturnSuccess;
    IOUserClient *      newConnect = 0;
    IOUserClient *      theConnect = 0;

    switch (type)
    {
        case kIOKitDiagnosticsClientType:
	    newConnect = IOKitDiagnosticsClient::withTask(owningTask);
	    if (!newConnect) err = kIOReturnNotPermitted;
            break;
        default:
            err = kIOReturnBadArgument;
    }

    if (newConnect)
    {
        if ((false == newConnect->attach(this))
                || (false == newConnect->start(this)))
        {
            newConnect->detach( this );
            newConnect->release();
            err = kIOReturnNotPermitted;
        }
        else
            theConnect = newConnect;
    }

    *handler = theConnect;
    return (err);
}

void IOPlatformExpertDevice::free()
{
    if (workLoop)
        workLoop->release();
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super IOService

OSDefineMetaClassAndStructors(IOPlatformDevice, IOService)

OSMetaClassDefineReservedUnused(IOPlatformDevice,  0);
OSMetaClassDefineReservedUnused(IOPlatformDevice,  1);
OSMetaClassDefineReservedUnused(IOPlatformDevice,  2);
OSMetaClassDefineReservedUnused(IOPlatformDevice,  3);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

bool IOPlatformDevice::compareName( OSString * name,
					OSString ** matched ) const
{
    return( ((IOPlatformExpert *)getProvider())->
		compareNubName( this, name, matched ));
}

IOService * IOPlatformDevice::matchLocation( IOService * /* client */ )
{
    return( this );
}

IOReturn IOPlatformDevice::getResources( void )
{
    return( ((IOPlatformExpert *)getProvider())->getNubResources( this ));
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*********************************************************************
* IOPanicPlatform class
*
* If no legitimate IOPlatformDevice matches, this one does and panics
* the kernel with a suitable message.
*********************************************************************/

class IOPanicPlatform : IOPlatformExpert {
    OSDeclareDefaultStructors(IOPanicPlatform);

public:
    bool start(IOService * provider) APPLE_KEXT_OVERRIDE;
};


OSDefineMetaClassAndStructors(IOPanicPlatform, IOPlatformExpert);


bool IOPanicPlatform::start(IOService * provider) {
    const char * platform_name = "(unknown platform name)";

    if (provider) platform_name = provider->getName();

    panic("Unable to find driver for this platform: \"%s\".\n",
        platform_name);

    return false;
}

