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
 * Copyright (c) 1998,1999 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 *
 */


#ifndef _IOKIT_IOSERVICE_H
#define _IOKIT_IOSERVICE_H

#include <IOKit/IORegistryEntry.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IONotifier.h>
#include <IOKit/IOLocks.h>

#include <IOKit/IOKitDebug.h>
#include <IOKit/IOInterrupts.h>

class IOPMinformee;
class IOPowerConnection;

#include <IOKit/pwr_mgt/IOPMpowerState.h>
#include <IOKit/IOServicePM.h>

extern "C" {
#include <kern/thread_call.h>
}

enum {
    kIODefaultProbeScore 	= 0
};

// masks for getState()
enum {
    kIOServiceInactiveState	= 0x00000001,
    kIOServiceRegisteredState	= 0x00000002,
    kIOServiceMatchedState	= 0x00000004,
    kIOServiceFirstPublishState	= 0x00000008,
    kIOServiceFirstMatchState	= 0x00000010
};

enum {
    // options for registerService()
    kIOServiceExclusive		= 0x00000001,

    // options for terminate()
    kIOServiceRequired		= 0x00000001,
    kIOServiceTerminate		= 0x00000004,

    // options for registerService() & terminate()
    kIOServiceSynchronous	= 0x00000002,
    // options for registerService()
    kIOServiceAsynchronous	= 0x00000008
};

// options for open()
enum {
    kIOServiceSeize		= 0x00000001,
    kIOServiceFamilyOpenOptions = 0xffff0000
};

// options for close()
enum {
    kIOServiceFamilyCloseOptions = 0xffff0000
};

typedef void * IONotificationRef;

extern const IORegistryPlane *	gIOServicePlane;
extern const IORegistryPlane *  gIOPowerPlane;

extern const OSSymbol *		gIOResourcesKey;
extern const OSSymbol *		gIOResourceMatchKey;
extern const OSSymbol *		gIOProviderClassKey;
extern const OSSymbol * 	gIONameMatchKey;
extern const OSSymbol *		gIONameMatchedKey;
extern const OSSymbol *		gIOPropertyMatchKey;
extern const OSSymbol *		gIOLocationMatchKey;
extern const OSSymbol *		gIOParentMatchKey;
extern const OSSymbol *		gIOPathMatchKey;
extern const OSSymbol *		gIOMatchCategoryKey;
extern const OSSymbol *		gIODefaultMatchCategoryKey;
extern const OSSymbol *		gIOMatchedServiceCountKey;

extern const OSSymbol *		gIOUserClientClassKey;
extern const OSSymbol *		gIOKitDebugKey;
extern const OSSymbol *		gIOServiceKey;

extern const OSSymbol *		gIOCommandPoolSizeKey;

extern const OSSymbol *		gIOPublishNotification;
extern const OSSymbol *		gIOFirstPublishNotification;
extern const OSSymbol *		gIOMatchedNotification;
extern const OSSymbol *		gIOFirstMatchNotification;
extern const OSSymbol *		gIOTerminatedNotification;

extern const OSSymbol *		gIOGeneralInterest;
extern const OSSymbol *		gIOBusyInterest;
extern const OSSymbol *		gIOOpenInterest;
extern const OSSymbol *		gIOAppPowerStateInterest;
extern const OSSymbol *		gIOPriorityPowerStateInterest;

extern const OSSymbol *		gIODeviceMemoryKey;
extern const OSSymbol *		gIOInterruptControllersKey;
extern const OSSymbol *		gIOInterruptSpecifiersKey;

extern SInt32 IOServiceOrdering( const OSMetaClassBase * inObj1, const OSMetaClassBase * inObj2, void * ref );

typedef void (*IOInterruptAction)( OSObject * target, void * refCon,
				   IOService * nub, int source );

/*! @typedef IOServiceNotificationHandler
    @param target Reference supplied when the notification was registered.
    @param refCon Reference constant supplied when the notification was registered.
    @param newService The IOService object the notification is delivering. It is retained for the duration of the handler's invocation and doesn't need to be released by the handler. */

typedef bool (*IOServiceNotificationHandler)( void * target, void * refCon,
                  IOService * newService );

/*! @typedef IOServiceInterestHandler
    @param target Reference supplied when the notification was registered.
    @param refCon Reference constant supplied when the notification was registered.
    @param messageType Type of the message - IOKit defined in IOKit/IOMessage.h or family specific.
    @param provider The IOService object who is delivering the notification. It is retained for the duration of the handler's invocation and doesn't need to be released by the handler.
    @param messageArgument An argument for message, dependent on its type.
    @param argSize Non zero if the argument represents a struct of that size, used when delivering messages outside the kernel. */

typedef IOReturn (*IOServiceInterestHandler)( void * target, void * refCon,
                                              UInt32 messageType, IOService * provider,
                                              void * messageArgument, vm_size_t argSize );

typedef void (*IOServiceApplierFunction)(IOService * service, void * context);
typedef void (*OSObjectApplierFunction)(OSObject * object, void * context);

class IOUserClient;
class IOPlatformExpert;

/*! @class IOService : public IORegistryEntry
    @abstract The base class for most families, devices and drivers.
    @discussion The IOService base class defines APIs used to publish services, instantiate other services based on the existance of a providing service (ie. driver stacking), destroy a service and its dependent stack, notify interested parties of service state changes, and general utility functions useful across all families. 

Types of service are specified with a matching dictionary that describes properties of the service. For example, a matching dictionary might describe any IOUSBDevice (or subclass), an IOUSBDevice with a certain class code, or a IOPCIDevice with a set of OpenFirmware matching names or device & vendor IDs. Since the matching dictionary is interpreted by the family which created the service, as well as generically by IOService, the list of properties considered for matching depends on the familiy.

Matching dictionaries are associated with IOService classes by the catalogue, as driver property tables, and also supplied by clients of the notification APIs.

IOService provides matching based on c++ class (via OSMetaClass dynamic casting), registry entry name, a registry path to the service (which includes OpenFirmware paths), a name assigned by BSD, or by its location (its point of attachment).

<br><br>Driver Instantiation by IOService<br><br>

Drivers are subclasses of IOService, and their availability is managed through the catalogue. They are instantiated based on the publication of an IOService they use (for example, an IOPCIDevice or IOUSBDevice), or when they are added to  the catalogue and the IOService(s) they use are already available.

When an IOService (the "provider") is published with the registerService() method, the matching and probing process begins, which is always single threaded per provider. A list of matching dictionaries from the catalog and installed publish notification requests, that successfully match the IOService, is constructed, with ordering supplied by kIOProbeScoreKey ("IOProbeScore") property in the dictionary, or supplied with the notification. 

Each entry in the list is then processed in order - for notifications, the notification is delivered, for driver property tables a lot more happens.

The driver class is instantiated and init() called with its property table. The new driver instance is then attached to the provider, and has its probe() method called with the provider as an argument. The default probe method does nothing but return success, but a driver may implement this method to interrogate the provider to make sure it can work with it. It may also modify its probe score at this time. After probe, the driver is detached and the next in the list is considered (ie. attached, probed, and detached).

When the probing phase is complete, the list consists of successfully probed drivers, in order of their probe score (after adjustment during the probe() call). The list is then divided into categories based on the kIOMatchCategoryKey property ("IOMatchCategory"); drivers without a match category are all considered in one default category. Match categories allow multiple clients of a provider to be attached and started, though the provider may also enforce open/close semantics to gain active access to it.

For each category, the highest scoring driver in that category is attached to the provider, and its start() method called. If start() is successful, the rest of the drivers in the same match category are discarded, otherwise the next highest scoring driver is started, and so one.

The driver should only consider itself in action when the start method is called, meaning it has been selected for use on the provider, and consuming that particular match category. It should also be prepared to be allocated, probed and freed even if the probe was sucessful.

After the drivers have all synchronously been started, the installed "matched" notifications that match the registered IOService are delivered.

<br><br>Properties used by IOService<br><br>

	kIOClassKey, extern const OSSymbol * gIOClassKey, "IOClass"
<br>
Class of the driver to instantiate on matching providers.
<br>
<br>
	kIOProviderClassKey, extern const OSSymbol * gIOProviderClassKey, "IOProviderClass"
<br>
Class of the provider(s) to be considered for matching, checked with OSDynamicCast so subclasses will also match.
<br>
<br>
	kIOProbeScoreKey, extern const OSSymbol * gIOProbeScoreKey, "IOProbeScore"
<br>
The probe score initially used to order multiple matching drivers.
<br>
<br>
	kIOMatchCategoryKey, extern const OSSymbol * gIOMatchCategoryKey, "IOMatchCategory"
<br>
A string defining the driver category for matching purposes. All drivers with no IOMatchCategory property are considered to be in the same default category. Only one driver in a category can be started on each provider.
<br>
<br>
	kIONameMatchKey, extern const OSSymbol * gIONameMatchKey, "IONameMatch"
<br>
A string or collection of strings that match the provider's name. The comparison is implemented with the IORegistryEntry::compareNames method, which supports a single string, or any collection (OSArray, OSSet, OSDictionary etc.) of strings. IOService objects with OpenFirmware device tree properties (eg. IOPCIDevice) will also be matched based on that standard's "compatible", "name", "device_type" properties. The matching name will be left in the driver's property table in the kIONameMatchedKey property.
<br>
Examples
<br>
      &ltkey&gtIONameMatch&lt/key&gt		<br>
	&ltstring&gtpci106b,7&ltstring&gt
<br>
For a list of possible matching names, a serialized array of strings should used, eg.
<br>
      &ltkey&gtIONameMatch&lt/key&gt		<br>
	&ltarray&gt				<br>
		&ltstring&gtAPPL,happy16&lt/string&gt	<br>
		&ltstring&gtpci106b,7&lt/string&gt	<br>
	&lt/array&gt
<br>
<br>
	kIONameMatchedKey, extern const OSSymbol * gIONameMatchedKey, "IONameMatched"
<br>
The name successfully matched name from the kIONameMatchKey property will be left in the driver's property table as the kIONameMatchedKey property.
<br>
<br>
	kIOPropertyMatchKey, extern const OSSymbol * gIOPropertyMatchKey, "IOPropertyMatch"
<br>
A dictionary of properties that each must exist in the matching IOService and compare sucessfully with the isEqualTo method.
      &ltkey&gtIOPropertyMatch&lt/key&gt		<br>
	&ltdictionary&gt				<br>
		&ltkey&gtname&lt/key&gt	<br>
		&ltstring&gtAPPL,meek8&lt/string&gt	<br>
	&lt/dictionary&gt
<br>
<br>
	kIOUserClientClassKey, extern const OSSymbol * gIOUserClientClassKey, "IOUserClientClass"
<br>
The class name that the service will attempt to allocate when a user client connection is requested.  First the device nub is queried, then the nub's provider is queried by default.
<br>
<br>
	kIOKitDebugKey, extern const OSSymbol * gIOKitDebugKey, "IOKitDebug"
<br>
Set some debug flags for logging the driver loading process. Flags are defined in IOKit/IOKitDebug.h, but 65535 works well.

*/
    
class IOService : public IORegistryEntry
{
    OSDeclareDefaultStructors(IOService)

protected:
/*! @struct ExpansionData
    @discussion This structure will be used to expand the capablilties of this class in the future.
    */    
    struct ExpansionData { };

/*! @var reserved
    Reserved for future use.  (Internal use only)  */
    ExpansionData * reserved;

private:
    IOService *		__provider;
    SInt32		__providerGeneration;
    IOService *		__owner;
    IOOptionBits	__state[2];
    IOOptionBits	__reserved[4];

    // pointer to private instance variables for power management
    IOPMpriv *		priv;

protected:
    // TRUE once PMinit has been called
        bool		initialized;
        
public:
    // pointer to protected instance variables for power management
    IOPMprot * 	 	pm_vars;

public:
    /* methods available in Mac OS X 10.1 or later */
/*! @function requestTerminate
    @abstract Passes a termination up the stack.
    @discussion When an IOService is made inactive the default behaviour is to also make any of its clients that have it as their only provider also inactive, in this way recursing the termination up the driver stack. This method allows an IOService object to override this behaviour. Returning true from this method when passed a just terminated provider will cause the client to also be terminated.
    @param provider The terminated provider of this object.
    @param options Options originally passed to terminate, plus kIOServiceRecursing.
    @result true if this object should be terminated now that its provider as been. */

    virtual bool requestTerminate( IOService * provider, IOOptionBits options );

/*! @function willTerminate
    @abstract Passes a termination up the stack.
    @discussion Notification that a provider has been terminated, sent before recursing up the stack, in root-to-leaf order.
    @param provider The terminated provider of this object.
    @param options Options originally passed to terminate.
    @result true return true. */

    virtual bool willTerminate( IOService * provider, IOOptionBits options );

/*! @function didTerminate
    @abstract Passes a termination up the stack.
    @discussion Notification that a provider has been terminated, sent after recursing up the stack, in leaf-to-root order.
    @param provider The terminated provider of this object.
    @param options Options originally passed to terminate.
    @param defer If there is pending I/O that requires this object to persist, and the provider is not opened by this object set defer to true and call the IOService::didTerminate() implementation when the I/O completes. Otherwise, leave defer set to its default value of false.
    @result true return true. */

    virtual bool didTerminate( IOService * provider, IOOptionBits options, bool * defer );

private:
    OSMetaClassDeclareReservedUsed(IOService, 0);
    OSMetaClassDeclareReservedUsed(IOService, 1);
    OSMetaClassDeclareReservedUsed(IOService, 2);

    OSMetaClassDeclareReservedUnused(IOService, 3);
    OSMetaClassDeclareReservedUnused(IOService, 4);
    OSMetaClassDeclareReservedUnused(IOService, 5);
    OSMetaClassDeclareReservedUnused(IOService, 6);
    OSMetaClassDeclareReservedUnused(IOService, 7);
    OSMetaClassDeclareReservedUnused(IOService, 8);
    OSMetaClassDeclareReservedUnused(IOService, 9);
    OSMetaClassDeclareReservedUnused(IOService, 10);
    OSMetaClassDeclareReservedUnused(IOService, 11);
    OSMetaClassDeclareReservedUnused(IOService, 12);
    OSMetaClassDeclareReservedUnused(IOService, 13);
    OSMetaClassDeclareReservedUnused(IOService, 14);
    OSMetaClassDeclareReservedUnused(IOService, 15);
    OSMetaClassDeclareReservedUnused(IOService, 16);
    OSMetaClassDeclareReservedUnused(IOService, 17);
    OSMetaClassDeclareReservedUnused(IOService, 18);
    OSMetaClassDeclareReservedUnused(IOService, 19);
    OSMetaClassDeclareReservedUnused(IOService, 20);
    OSMetaClassDeclareReservedUnused(IOService, 21);
    OSMetaClassDeclareReservedUnused(IOService, 22);
    OSMetaClassDeclareReservedUnused(IOService, 23);
    OSMetaClassDeclareReservedUnused(IOService, 24);
    OSMetaClassDeclareReservedUnused(IOService, 25);
    OSMetaClassDeclareReservedUnused(IOService, 26);
    OSMetaClassDeclareReservedUnused(IOService, 27);
    OSMetaClassDeclareReservedUnused(IOService, 28);
    OSMetaClassDeclareReservedUnused(IOService, 29);
    OSMetaClassDeclareReservedUnused(IOService, 30);
    OSMetaClassDeclareReservedUnused(IOService, 31);
    OSMetaClassDeclareReservedUnused(IOService, 32);
    OSMetaClassDeclareReservedUnused(IOService, 33);
    OSMetaClassDeclareReservedUnused(IOService, 34);
    OSMetaClassDeclareReservedUnused(IOService, 35);
    OSMetaClassDeclareReservedUnused(IOService, 36);
    OSMetaClassDeclareReservedUnused(IOService, 37);
    OSMetaClassDeclareReservedUnused(IOService, 38);
    OSMetaClassDeclareReservedUnused(IOService, 39);
    OSMetaClassDeclareReservedUnused(IOService, 40);
    OSMetaClassDeclareReservedUnused(IOService, 41);
    OSMetaClassDeclareReservedUnused(IOService, 42);
    OSMetaClassDeclareReservedUnused(IOService, 43);
    OSMetaClassDeclareReservedUnused(IOService, 44);
    OSMetaClassDeclareReservedUnused(IOService, 45);
    OSMetaClassDeclareReservedUnused(IOService, 46);
    OSMetaClassDeclareReservedUnused(IOService, 47);
    OSMetaClassDeclareReservedUnused(IOService, 48);
    OSMetaClassDeclareReservedUnused(IOService, 49);
    OSMetaClassDeclareReservedUnused(IOService, 50);
    OSMetaClassDeclareReservedUnused(IOService, 51);
    OSMetaClassDeclareReservedUnused(IOService, 52);
    OSMetaClassDeclareReservedUnused(IOService, 53);
    OSMetaClassDeclareReservedUnused(IOService, 54);
    OSMetaClassDeclareReservedUnused(IOService, 55);
    OSMetaClassDeclareReservedUnused(IOService, 56);
    OSMetaClassDeclareReservedUnused(IOService, 57);
    OSMetaClassDeclareReservedUnused(IOService, 58);
    OSMetaClassDeclareReservedUnused(IOService, 59);
    OSMetaClassDeclareReservedUnused(IOService, 60);
    OSMetaClassDeclareReservedUnused(IOService, 61);
    OSMetaClassDeclareReservedUnused(IOService, 62);
    OSMetaClassDeclareReservedUnused(IOService, 63);

public:
/*! @function getState
    @abstract Accessor for IOService state bits, not normally needed or used outside IOService.
    @result State bits for the IOService, eg. kIOServiceInactiveState, kIOServiceRegisteredState. */

    virtual IOOptionBits getState( void ) const;

/*! @function isInactive
    @abstract Check the IOService has been terminated, and is in the process of being destroyed.
    @discussion When an IOService is successfully terminated, it is immediately made inactive, which blocks further attach()es, matching or notifications occuring on the object. It remains inactive until the last client closes, and is then finalized and destroyed.
    @result Returns true if the IOService has been terminated. */

    bool isInactive( void ) const;

    /* Stack creation */

/*! @function registerService
    @abstract Start the registration process for a newly discovered IOService.
    @discussion This function allows an IOService subclass to be published and made available to possible clients, by starting the registration process and delivering notifications to registered clients. The object should be completely setup and ready to field requests from clients before registerService is called.
    @param options The default zero options mask is recommended & should be used in most cases. The registration process is usually asynchronous, with possible driver probing & notification occurring some time later. kIOServiceSynchronous may be passed to carry out the matching and notification process for currently registered clients before returning to the caller. */

    virtual void registerService( IOOptionBits options = 0 );

/*! @function probe
    @abstract During an IOService instantiation probe a matched service to see if it can be used.
    @discussion The registration process for an IOService (the provider) includes instantiating possible driver clients. The probe method is called in the client instance to check the matched service can be used before the driver is considered to be started. Since matching screens many possible providers, in many cases the probe method can be left unimplemented by IOService subclasses. The client is already attached to the provider when probe is called.
    @param provider The registered IOService which matches a driver personality's matching dictionary.
    @param score Pointer to the current driver's probe score, which is used to order multiple matching drivers in the same match category. It defaults to the value of the IOProbeScore property in the drivers property table, or kIODefaultProbeScore if none is specified. The probe method may alter the score to affect start order.
    @result Returns an IOService instance or zero when the probe is unsuccessful. In almost all cases the value of this is returned on success. If another IOService object is returned, the probed instance is detached and freed, and the returned instance is used in its stead for start. */
    
    virtual IOService * probe(	IOService * 	provider,
				SInt32 	  *	score );

/*! @function start
    @abstract During an IOService instantiation, the start method is called when the IOService has been selected to run on the provider.
    @discussion The registration process for an IOService (the provider) includes instantiating possible driver clients. The start method is called in the client instance when it has been selected (by its probe score and match category) to be the winning client. The client is already attached to the provider when start is called.
    @result Return true if the start was successful, false otherwise (which will cause the instance to be detached and usually freed). */
    
    virtual bool start( IOService * provider );
    
/*! @function stop
    @abstract During an IOService termination, the stop method is called in its clients before they are detached & it is destroyed.
    @discussion The termination process for an IOService (the provider) will call stop in each of its clients, after they have closed the provider if they had it open, or immediately on termination. */

    virtual void stop( IOService * provider );

    /* Open / Close */

/*! @function open
    @abstract Request active access to a provider.
    @discussion IOService provides generic open and close semantics to track clients of a provider that have established an active datapath. The use of open & close, and rules regarding ownership are family defined, and defined by the handleOpen / handleClose methods in the provider. Some families will limit access to a provider based on its open state.
    @param forClient Designates the client of the provider requesting the open.
    @param options Options for the open. The provider family may implement options for open; IOService defines only kIOServiceSeize to request the device be withdrawn from its current owner.
    @result Return true if the open was successful, false otherwise. */

    virtual bool open( 	 IOService *	   forClient,
                         IOOptionBits	   options = 0,
                         void *		   arg = 0 );

/*! @function close
    @abstract Release active access to a provider.
    @discussion IOService provides generic open and close semantics to track clients of a provider that have established an active datapath. The use of open & close, and rules regarding ownership are family defined, and defined by the handleOpen / handleClose methods in the provider.
    @param forClient Designates the client of the provider requesting the close.
    @param options Options available for the close. The provider family may implement options for close; IOService defines none.
    @param arg Family specific arguments, ignored by IOService. */
    
    virtual void close(  IOService *	   forClient,
                         IOOptionBits	   options = 0 );
                         
/*! @function isOpen
    @abstract Determine whether a specific, or any, client has an IOService open.
    @discussion Returns the open state of an IOService with respect to the specified client, or when it is open by any client.
    @param forClient If non-zero, isOpen returns the open state for that client. If zero is passed, isOpen returns the open state for all clients.
    @result Returns true if the specific, or any, client has the IOService open. */

    virtual bool isOpen( const IOService * forClient = 0 ) const;

/*! @function handleOpen
    @abstract Overrideable method to control the open / close behaviour of an IOService.
    @discussion IOService calls this method in its subclasses in response to the open method, so the subclass may implement the request. The default implementation provides single owner access to an IOService via open. The object is locked via lockForArbitration before handleOpen is called.
    @param forClient Designates the client of the provider requesting the open.
    @param options Options for the open, may be interpreted by the implementor of handleOpen.
    @result Return true if the open was successful, false otherwise. */

    virtual bool handleOpen( 	IOService *	  forClient,
                                IOOptionBits	  options,
                                void *		  arg );
                                
/*! @function handleClose
    @abstract Overrideable method to control the open / close behaviour of an IOService.
    @discussion IOService calls this method in its subclasses in response to the close method, so the subclass may implement the request. The default implementation provides single owner access to an IOService via open. The object is locked via lockForArbitration before handleClose is called.
    @param forClient Designates the client of the provider requesting the close.
    @param options Options for the close, may be interpreted by the implementor of handleOpen. */

    virtual void handleClose(   IOService *	  forClient,
                                IOOptionBits	  options );
                                
/*! @function handleIsOpen
    @abstract Overrideable method to control the open / close behaviour of an IOService.
    @discussion IOService calls this method in its subclasses in response to the open method, so the subclass may implement the request. The default implementation provides single owner access to an IOService via open. The object is locked via lockForArbitration before handleIsOpen is called.
    @param forClient If non-zero, isOpen returns the open state for that client. If zero is passed, isOpen returns the open state for all clients.
    @result Returns true if the specific, or any, client has the IOService open. */

    virtual bool handleIsOpen(  const IOService * forClient ) const;

    /* Stacking change */

/*! @function terminate
    @abstract Make an IOService inactive and begin its destruction.
    @discussion Registering an IOService informs possible clients of its existance and instantiates drivers that may be used with it; terminate involves the opposite process of informing clients that an IOService is no longer able to be used and will be destroyed. By default, if any client has the service open, terminate fails. If the kIOServiceRequired flag is passed however, terminate will be sucessful though further progress in the destruction of the IOService will not proceed until the last client has closed it. The service will be made inactive immediately upon successful termination, and all its clients will be notified via their message method with a message of type kIOMessageServiceIsTerminated. Both these actions take place on the callers thread. After the IOService is made inactive, further matching or attach calls will fail on it. Each client has its stop method called upon their close of an inactive IOService, or on its termination if they do not have it open. After stop, detach is called in each client. When all clients have been detached, the finalize method is called in the inactive service. The terminate process is inherently asynchronous since it will be deferred until all clients have chosen to close.
    @param options In most cases no options are needed. kIOServiceSynchronous may be passed to cause terminate to not return until the service is finalized. */

    virtual bool terminate( IOOptionBits options = 0 );

/*! @function finalize
    @abstract The last stage in an IOService destruction.
    @discussion The finalize method is called in an inactive (ie. terminated) IOService after the last client has detached. IOService's implementation will call stop, close, and detach on each provider. When finalize returns, the object's retain count will have no references generated by IOService's registration process.
    @param options The options passed to the terminate method of the IOService are passed on to finalize.
    @result Returns true. */
    
    virtual bool finalize( IOOptionBits options );

/*! @function free
    @discussion Free data structures that were allocated when power management was initialized on this service. */
    
    virtual void free( void );

/*! @function lockForArbitration
    @abstract Locks an IOService against changes in state or ownership.
    @discussion The registration, termination and open / close functions of IOService use lockForArbtration to single thread access to an IOService. lockForArbitration will grant recursive access to the same thread.
    @param isSuccessRequired If a request for access to an IOService should be denied if it is terminated, isSuccessRequired should passed as false, otherwise pass true. */
    
    virtual bool lockForArbitration( bool isSuccessRequired = true );
    
/*! @function unlockForArbitration
    @abstract Unlocks an IOService after a successful lockForArbitration.
    @discussion A thread granted exclusive access to an IOService should release it with unlockForArbitration. */
    
    virtual void unlockForArbitration( void );

/*! @function terminateClient
    @abstract Passes a termination up the stack.
    @discussion When an IOService is made inactive the default behaviour is to also make any of its clients that have it as their only provider also inactive, in this way recursing the termination up the driver stack. This method allows a terminated  IOService to override this behaviour. Note the client may also override this behaviour by overriding its terminate method.
    @param client The client of the of the terminated provider.
    @param options Options originally passed to terminate, plus kIOServiceRecursing.
    @result result of the terminate request on the client. */

    virtual bool terminateClient( IOService * client, IOOptionBits options );

    /* Busy state indicates discovery, matching or termination is in progress */

/*! @function getBusyState
    @abstract Returns the busyState of an IOService.
    @discussion Many activities in IOService are asynchronous. When registration, matching, or termination is in progress on an IOService, its busyState is increased by one. Change in busyState to or from zero also changes the IOService's provider's busyState by one, which means that an IOService is marked busy when any of the above activities is ocurring on it or any of its clients.
    @result The busyState. */

    virtual UInt32 getBusyState( void );
    
/*! @function adjustBusy
    @abstract Adjusts the busyState of an IOService.
    @discussion Applies a delta to an IOService's busyState. A change in the busyState to or from zero will change the IOService's provider's busyState by one (in the same direction). 
    @param delta The delta to be applied to the IOService busy state. */

    virtual void adjustBusy( SInt32 delta );

/*! @function waitQuiet
    @abstract Wait for an IOService's busyState to be zero.
    @discussion Blocks the caller until an IOService is non busy.
    @param timeout Specifies a maximum time to wait.
    @result Returns an error code if mach synchronization primitives fail, kIOReturnTimeout, or kIOReturnSuccess. */
    
    virtual IOReturn waitQuiet( mach_timespec_t * timeout = 0 );

    /* Matching */

/*! @function matchPropertyTable
    @abstract Allows a registered IOService to implement family specific matching.
    @discussion All matching on an IOService will call this method to allow a family writer to implement matching in addition to the generic methods provided by IOService. The implementer should examine the matching dictionary passed to see if it contains properties the family understands for matching, and use them to match with the IOService if so. Note that since matching is also carried out by other parts of IOKit, the matching dictionary may contain properties the family does not understand - these should not be considered matching failures.
    @param table The dictionary of properties to be matched against.
    @param score Pointer to the current driver's probe score, which is used to order multiple matching drivers in the same match category. It defaults to the value of the IOProbeScore property in the drivers property table, or kIODefaultProbeScore if none is specified.
    @result Returns false if the family considers the matching dictionary does not match in properties it understands, true otherwise. */

    virtual bool matchPropertyTable( OSDictionary *	table,
                                     SInt32       *	score );

    virtual bool matchPropertyTable( OSDictionary * table );

/*! @function matchLocation
    @abstract Allows a registered IOService to direct location matching.
    @discussion By default, a location matching property will be applied to an IOService's provider. This method allows that behaviour to be overridden by families.
    @param client The IOService at which matching is taking place.
    @result Returns the IOService instance to be used for location matching. */

    virtual IOService * matchLocation( IOService * client );

    /* Resource service */

/*! @function publishResource
    @abstract Use the resource service to publish a property.
    @discussion The resource service uses IOService's matching and notification to allow objects to be published and found by any IOKit client by a global name. publishResource makes an object available to anyone waiting for it or looking for it in the future.
    @param key An OSSymbol key that globally identifies the object.
    @param The object to be published. */

    static void publishResource( const OSSymbol * key, OSObject * value = 0 );

/*! @function publishResource
    @abstract Use the resource service to publish a property.
    @discussion The resource service uses IOService's matching and notification to allow objects to be published and found by any IOKit client by a global name. publishResource makes an object available to anyone waiting for it or looking for it in the future.
    @param key A C-string key that globally identifies the object.
    @param The object to be published. */

    static void publishResource( const char * key, OSObject * value = 0 );
    virtual bool addNeededResource( const char * key );

    /* Notifications */

/*! @function addNotification
    @abstract Add a persistant notification handler to be notified of IOService events.
    @discussion IOService will deliver notifications of changes in state of an IOService to registered clients. The type of notification is specified by a symbol, for example gIOMatchedNotification or gIOTerminatedNotification, and notifications will only include IOService's that match the supplied matching dictionary. Notifications are ordered by a priority set with addNotification. When the notification is installed, its handler will be called with each of any currently existing IOService's that are in the correct state (eg. registered) and match the supplied matching dictionary, avoiding races between finding preexisting and new IOService events. The notification request is identified by an instance of an IONotifier object, through which it can be enabled, disabled or removed. addNotification will consume a retain count on the matching dictionary when the notification is removed.
    @param type An OSSymbol identifying the type of notification and IOService state:
<br>	gIOPublishNotification Delivered when an IOService is registered.
<br>	gIOFirstPublishNotification Delivered when an IOService is registered, but only once per IOService instance. Some IOService's may be reregistered when their state is changed.
<br>	gIOMatchedNotification Delivered when an IOService has been matched with all client drivers, and they have been probed and started.
<br>	gIOFirstMatchNotification Delivered when an IOService has been matched with all client drivers, but only once per IOService instance. Some IOService's may be reregistered when their state is changed.
<br>	gIOTerminatedNotification Delivered after an IOService has been terminated, during its finalize stage.
    @param matching A matching dictionary to restrict notifications to only matching IOServices. The dictionary will be released when the notification is removed - consuming the passed in reference.
    @param handler A C-function callback to deliver notifications.
    @param target An instance reference for the callbacks use.
    @param ref A reference constant for the callbacks use
    @param priority A constant ordering all notifications of a each type.
    @result Returns an instance of an IONotifier object that can be used to control or destroy the notification request. */

    static IONotifier * addNotification(
                            const OSSymbol * type, OSDictionary * matching,
                            IOServiceNotificationHandler handler,
                            void * target, void * ref = 0,
                            SInt32 priority = 0 );

/*! @function waitForService
    @abstract Wait for a matching to service to be published.
    @discussion Provides a method of waiting for an IOService matching the supplied matching dictionary to be registered and fully matched. 
    @param matching The matching dictionary describing the desired IOService. waitForService will consume one reference of the matching dictionary.
    @param timeout The maximum time to wait.
    @result A published IOService matching the supplied dictionary. */

    static IOService * waitForService( OSDictionary * matching,
                            mach_timespec_t * timeout = 0);

/*! @function getMatchingServices
    @abstract Finds the set of current published IOServices matching a matching dictionary.
    @discussion Provides a method of finding the current set of published IOServices matching the supplied matching dictionary.   
    @param matching The matching dictionary describing the desired IOServices.
    @result An instance of an iterator over a set of IOServices. To be released by the caller. */

    static OSIterator * getMatchingServices( OSDictionary * matching );

/*! @function installNotification
    @abstract Add a persistant notification handler to be notified of IOService events.
    @discussion A lower level interface to addNotification that will install a handler and return the current set of IOServices that are in the specified state and match the matching dictionary.
    @param type See addNotification.
    @param matching See addNotification.
    @param handler See addNotification.
    @param self See addNotification.
    @param ref See addNotification.
    @param priority See addNotification.
    @param existing Returns an iterator over the set of IOServices that are currently in the specified state and match the matching dictionary.
    @result See addNotification.  */

    static IONotifier * installNotification(
			const OSSymbol * type, OSDictionary * matching,
			IOServiceNotificationHandler handler,
			void * target, void * ref,
			SInt32 priority, OSIterator ** existing );

    /* Helpers to make matching dictionaries for simple cases,
     * they add keys to an existing dictionary, or create one. */

/*! @function serviceMatching
    @abstract Create a matching dictionary, or add matching properties to an existing dictionary, that specify an IOService class match.
    @discussion A very common matching criteria for IOService is based on its class. serviceMatching will create a matching dictionary that specifies any IOService of a class, or its subclasses. The class is specified by name, and an existing dictionary may be passed in, in which case the matching properties will be added to that dictionary rather than creating a new one.
    @param className The class name, as a const C-string. Class matching is successful on IOService's of this class or any subclass.
    @param table If zero, serviceMatching will create a matching dictionary and return a reference to it, otherwise the matching properties are added to the specified dictionary.
    @result The matching dictionary created, or passed in, is returned on success, or zero on failure. */

    static OSDictionary * serviceMatching( const char * className,
			OSDictionary * table = 0 );

/*! @function serviceMatching
    @abstract Create a matching dictionary, or add matching properties to an existing dictionary, that specify an IOService class match.
    @discussion A very common matching criteria for IOService is based on its class. serviceMatching will create a matching dictionary that specifies any IOService of a class, or its subclasses. The class is specified by name, and an existing dictionary may be passed in, in which case the matching properties will be added to that dictionary rather than creating a new one.
    @param className The class name, as an OSString (which includes OSSymbol). Class matching is successful on IOService's of this class or any subclass.
    @param table If zero, serviceMatching will create a matching dictionary and return a reference to it, otherwise the matching properties are added to the specified dictionary.
    @result The matching dictionary created, or passed in, is returned on success, or zero on failure. */

    static OSDictionary * serviceMatching( const OSString * className,
			OSDictionary * table = 0 );

/*! @function nameMatching
    @abstract Create a matching dictionary, or add matching properties to an existing dictionary, that specify an IOService name match.
    @discussion A very common matching criteria for IOService is based on its name. nameMatching will create a matching dictionary that specifies any IOService which respond sucessfully to the IORegistryEntry method compareName. An existing dictionary may be passed in, in which case the matching properties will be added to that dictionary rather than creating a new one.
    @param name The service's name, as a const C-string. Name matching is successful on IOService's which respond sucessfully to the IORegistryEntry method compareName.
    @param table If zero, nameMatching will create a matching dictionary and return a reference to it, otherwise the matching properties are added to the specified dictionary.
    @result The matching dictionary created, or passed in, is returned on success, or zero on failure. */

    static OSDictionary * nameMatching( const char * name,
			OSDictionary * table = 0 );

/*! @function nameMatching
    @abstract Create a matching dictionary, or add matching properties to an existing dictionary, that specify an IOService name match.
    @discussion A very common matching criteria for IOService is based on its name. nameMatching will create a matching dictionary that specifies any IOService which respond sucessfully to the IORegistryEntry method compareName. An existing dictionary may be passed in, in which case the matching properties will be added to that dictionary rather than creating a new one.
    @param name The service's name, as an OSString (which includes OSSymbol). Name matching is successful on IOService's which respond sucessfully to the IORegistryEntry method compareName.
    @param table If zero, nameMatching will create a matching dictionary and return a reference to it, otherwise the matching properties are added to the specified dictionary.
    @result The matching dictionary created, or passed in, is returned on success, or zero on failure. */

    static OSDictionary * nameMatching( const OSString* name,
			OSDictionary * table = 0 );

/*! @function resourceMatching
    @abstract Create a matching dictionary, or add matching properties to an existing dictionary, that specify a resource service match.
    @discussion IOService maintains a resource service IOResources that allows objects to be published and found globally in IOKit based on a name, using the standard IOService matching and notification calls.
    @param name The resource name, as a const C-string. Resource matching is successful when an object by that name has been published with the publishResource method.
    @param table If zero, resourceMatching will create a matching dictionary and return a reference to it, otherwise the matching properties are added to the specified dictionary.
    @result The matching dictionary created, or passed in, is returned on success, or zero on failure. */

    static OSDictionary * resourceMatching( const char * name,
			OSDictionary * table = 0 );

/*! @function resourceMatching
    @abstract Create a matching dictionary, or add matching properties to an existing dictionary, that specify a resource service match.
    @discussion IOService maintains a resource service IOResources that allows objects to be published and found globally in IOKit based on a name, using the standard IOService matching and notification calls.
    @param name The resource name, as an OSString (which includes OSSymbol). Resource matching is successful when an object by that name has been published with the publishResource method.
    @param table If zero, resourceMatching will create a matching dictionary and return a reference to it, otherwise the matching properties are added to the specified dictionary.
    @result The matching dictionary created, or passed in, is returned on success, or zero on failure. */

    static OSDictionary * resourceMatching( const OSString * name,
			OSDictionary * table = 0 );

/*! @function addLocation
    @abstract Add a location matching property to an existing dictionary.
    @discussion This function creates matching properties that specify the location of a IOService, as an embedded matching dictionary. This matching will be successful on an IOService which attached to an IOService which matches this location matching dictionary.
    @param table The matching properties are added to the specified dictionary, which must be non-zero.
    @result The location matching dictionary created is returned on success, or zero on failure. */

    static OSDictionary * addLocation( OSDictionary * table );

    /* Helpers for matching dictionaries. */

/*! @function compareProperty
    @abstract Utility to compare a property in a matching dictionary with an IOService's property table.
    @discussion This is a helper function to aid in implementing matchPropertyTable. If the property specified by key exists in the matching dictionary, it is compared with a property of the same name in the IOService's property table. The comparison is performed with the isEqualTo method. If the property does not exist in the matching table, success is returned. If the property exists in the matching dictionary but not the IOService property table, failure is returned.
    @param matching The matching dictionary, which must be non-zero.
    @param key The dictionary key specifying the property to be compared, as a C-string.
    @result If the property does not exist in the matching table, true is returned. If the property exists in the matching dictionary but not the IOService property table, failure is returned. Otherwise the result of calling the property from the matching dictionary's isEqualTo method with the IOService property as an argument is returned. */

    virtual bool compareProperty(   OSDictionary   * matching,
                                    const char     * key );
/*! @function compareProperty
    @abstract Utility to compare a property in a matching dictionary with an IOService's property table.
    @discussion This is a helper function to aid in implementing matchPropertyTable. If the property specified by key exists in the matching dictionary, it is compared with a property of the same name in the IOService's property table. The comparison is performed with the isEqualTo method. If the property does not exist in the matching table, success is returned. If the property exists in the matching dictionary but not the IOService property table, failure is returned.
    @param matching The matching dictionary, which must be non-zero.
    @param key The dictionary key specifying the property to be compared, as an OSString (which includes OSSymbol).
    @result If the property does not exist in the matching table, true is returned. If the property exists in the matching dictionary but not the IOService property table, failure is returned. Otherwise the result of calling the property from the matching dictionary's isEqualTo method with the IOService property as an argument is returned. */

    virtual bool compareProperty(   OSDictionary   * matching,
                                    const OSString * key );

/*! @function compareProperties
    @abstract Utility to compare a set of properties in a matching dictionary with an IOService's property table.
    @discussion This is a helper function to aid in implementing matchPropertyTable. A collection of dictionary keys specifies properties in a matching dictionary to be compared, with compareProperty, with an IOService property table, if compareProperty returns true for each key, success is return else failure.
    @param matching The matching dictionary, which must be non-zero.
    @param keys A collection (eg. OSSet, OSArray, OSDictionary) which should contain OSStrings (or OSSymbols) that specify the property keys to be compared.
    @result if compareProperty returns true for each key in the collection, success is return else failure. */

    virtual bool compareProperties( OSDictionary   * matching,
                                    OSCollection   * keys );

    /* Client / provider accessors */

/*! @function attach
    @abstract Attaches an IOService client to a provider in the registry.
    @discussion This function called in an IOService client enters the client into the registry as a child of the provider in the service plane. The provider must be active or the attach will fail. Multiple attach calls to the same provider are no-ops and return success. A client may be attached to multiple providers. Entering an object into the registry will retain both the client and provider until they are detached.
    @param provider The IOService object which will serve as this objects provider.
    @result false if the provider is inactive or on a resource failure, otherwise true. */

    virtual bool attach( IOService * provider );
    
/*! @function detach
    @abstract Detaches an IOService client from a provider in the registry.
    @discussion This function called in an IOService client removes the client as a child of the provider in the service plane of the registry. If the provider is not a parent of the client this is a no-op, otherwise the registry will release both the client and provider.
    @param provider The IOService object to detach from. */

    virtual void detach( IOService * provider );

/*! @function getProvider
    @abstract Returns an IOService's primary provider.
    @discussion This function called in an IOService client will return the provider to which it was first attached. Since the majority of IOService objects have only one provider, this is a useful simplification and also supports caching of the provider when the registry is unchanged.
    @result Returns the first provider of the client, or zero if the IOService is not attached into the registry. The provider is retained while the client is attached, and should not be released by the caller. */

    virtual IOService * getProvider( void ) const;

/*! @function getWorkLoop
    @abstract Returns the current work loop or provider->getWorkLoop().
    @discussion This function returns a valid work loop that a client can use to add an IOCommandGate to.  The intention is that an IOService client has data that needs to be protected but doesn't want to pay the cost of an entire dedicated thread.  This data has to be accessed from a providers call out context as well.  So to achieve both of these goals the client creates an IOCommandGate to lock access to his data but he registers it with the providers work loop, i.e. the work loop which will make the completion call outs.  In one fell swoop we avoid a potentially nasty deadlock 'cause a work loop's gate is recursive.
    @result Always returns a work loop, either the current work loop or it walks up the $link getProvider() chain calling getWorkLoop.  Eventually it will reach a valid work loop based driver or the root of the io tree where it will return a system wide work loop.  Returns 0 if it fails to find (or create) */

    virtual IOWorkLoop * getWorkLoop() const;

/*! @function getProviderIterator
    @abstract Returns an iterator over an IOService's providers.
    @discussion For those few IOService objects that obtain service from multiple providers, this method supplies an iterator over a client's providers. 
    @result Returns an iterator over the providers of the client, or zero if there is a resource failure. The iterator must be released when the iteration is finished. All objects returned by the iteration are retained while the iterator is valid, though they may no longer be attached during the iteration. */

    virtual OSIterator * getProviderIterator( void ) const;

/*! @function getOpenProviderIterator
    @abstract Returns an iterator over an client's providers that are currently opened by the client.
    @discussion For those few IOService objects that obtain service from multiple providers, this method supplies an iterator over a client's providers, locking each in turn with lockForArbitration and returning those that have been opened by the client. 
    @result Returns an iterator over the providers the client has open, or zero if there is a resource failure. The iterator must be released when the iteration is finished. All objects returned by the iteration are retained while the iterator is valid, and the current entry in the iteration is locked with lockForArbitration, protecting it from state changes. */

    virtual OSIterator * getOpenProviderIterator( void ) const;

/*! @function getClient
    @abstract Returns an IOService's primary client.
    @discussion This function called in an IOService provider will return the first client to attach to it. For IOService objects which have only only one client, this may be a useful simplification.
    @result Returns the first client of the provider, or zero if the IOService is not attached into the registry. The client is retained while it is attached, and should not be released by the caller. */

    virtual IOService * getClient( void ) const;

/*! @function getClientIterator
    @abstract Returns an iterator over an IOService's clients.
    @discussion For IOService objects that may have multiple clients, this method supplies an iterator over a provider's clients. 
    @result Returns an iterator over the clients of the provider, or zero if there is a resource failure. The iterator must be released when the iteration is finished. All objects returned by the iteration are retained while the iterator is valid, though they may no longer be attached during the iteration. */

    virtual OSIterator * getClientIterator( void ) const;

/*! @function getOpenClientIterator
    @abstract Returns an iterator over an provider's clients that currently have opened the provider.
    @discussion For IOService objects that may have multiple clients, this method supplies an iterator over a provider's clients, locking each in turn with lockForArbitration and returning those that have opened the provider. 
    @result Returns an iterator over the clients which the provider open, or zero if there is a resource failure. The iterator must be released when the iteration is finished. All objects returned by the iteration are retained while the iterator is valid, and the current entry in the iteration is locked with lockForArbitration, protecting it from state changes. */

    virtual OSIterator * getOpenClientIterator( void ) const;

/*! @function callPlatformFunction
    @abstract Calls the platform function with the given name.
    @discussion The platform expert or other drivers may implement various functions to control hardware features.  callPlatformFunction allows any IOService object to access these functions.  Normally callPlatformFunction will be called on a service's provider.  The provider will service the request or pass it to it's provider.  The systems IOPlatformExpert subclass will catch functions it knows about and redirect them into other parts of the IOService plane.  If the IOPlatformExpert subclass can not execute the function, the base class will be called.  The IOPlatformExpert base class will attempt to find a service to execute the function by looking up the function name in a IOResources name space.  A service may publish a service using publishResource(functionName, this).  If no service can be found to execute the function an error will be returned.
    @param functionName name of the function to be called.  When functionName is a c-string, callPlatformFunction will convert the c-string to a OSSymbol and call other OSSymbol version of callPlatformFunction.  This process can block and should not be used from an interrupt context.
    @param waitForFunction if true callPlatformFunction will not return until the function has been called.
    @result Return an IOReturn code, kIOReturnSuccess if the function was successfully executed, kIOReturnUnsupported if a service to execute the function could not be found.  Other return codes may be returned by the function.*/

    virtual IOReturn callPlatformFunction( const OSSymbol * functionName,
					   bool waitForFunction,
					   void *param1, void *param2,
					   void *param3, void *param4 );

    virtual IOReturn callPlatformFunction( const char * functionName,
					   bool waitForFunction,
					   void *param1, void *param2,
					   void *param3, void *param4 );


    /* Some accessors */

/*! @function getPlatform
    @abstract Returns a pointer to the platform expert instance for the machine.
    @discussion This method provides an accessor to the platform expert instance for the machine. 
    @result A pointer to the IOPlatformExport instance. It should not be released by the caller. */

    static IOPlatformExpert * getPlatform( void );

/*! @function getPMRootDomain
    @abstract Returns a pointer to the power management root domain instance for the machine.
    @discussion This method provides an accessor to the power management root domain instance for the machine. 
    @result A pointer to the power management root domain instance. It should not be released by the caller. */

    static class IOPMrootDomain * getPMRootDomain( void );

/*! @function getServiceRoot
    @abstract Returns a pointer to the root of the service plane.
    @discussion This method provides an accessor to the root of the service plane for the machine. 
    @result A pointer to the IOService instance at the root of the service plane. It should not be released by the caller. */

    static IOService * getServiceRoot( void );

/*! @function getResourceService
    @abstract Returns a pointer to the IOResources service.
    @discussion IOService maintains a resource service IOResources that allows objects to be published and found globally in IOKit based on a name, using the standard IOService matching and notification calls.
    @result A pointer to the IOResources instance. It should not be released by the caller. */

    static IOService * getResourceService( void );

    /* Allocate resources for a matched service */

/*! @function getResources
    @abstract Allocate any needed resources for a published IOService before clients attach.
    @discussion This method is called during the registration process for an IOService object if there are success driver matches, before any clients attach. It allows for lazy allocation of resources to an IOService when a matching driver is found.
    @result Return an IOReturn code, kIOReturnSuccess is necessary for the IOService to be successfully used, otherwise the registration process for the object is halted. */
    
    virtual IOReturn getResources( void );

    /* Device memory accessors */

/*! @function getDeviceMemoryCount
    @abstract Returns a count of the physical memory ranges available for a device.
    @discussion This method will return the count of physical memory ranges, each represented by an IODeviceMemory instance, that have been allocated for a memory mapped device.
    @result An integer count of the number of ranges available. */

    virtual IOItemCount getDeviceMemoryCount( void );

/*! @function getDeviceMemoryWithIndex
    @abstract Returns an instance of IODeviceMemory representing one of a device's memory mapped  ranges.
    @discussion This method will return a pointer to an instance of IODeviceMemory for the physical memory range at the given index for a memory mapped device.
    @param index An index into the array of ranges assigned to the device.
    @result A pointer to an instance of IODeviceMemory, or zero if the index is beyond the count available. The IODeviceMemory is retained by the provider, so is valid while attached, or while any mappings to it exist. It should not be released by the caller. See also mapDeviceMemory() which will create a device memory mapping. */

    virtual IODeviceMemory * getDeviceMemoryWithIndex( unsigned int index );

/*! @function mapDeviceMemoryWithIndex
    @abstract Maps a physical range of a device.
    @discussion This method will create a mapping for the IODeviceMemory at the given index, with IODeviceMemory::map(options). The mapping is represented by the returned instance of IOMemoryMap, which should not be released until the mapping is no longer required.
    @param index An index into the array of ranges assigned to the device.
    @result An instance of IOMemoryMap, or zero if the index is beyond the count available. The mapping should be released only when access to it is no longer required. */

    virtual IOMemoryMap * mapDeviceMemoryWithIndex( unsigned int index,
						IOOptionBits options = 0 );

/*! @function getDeviceMemory
    @abstract Returns the array of IODeviceMemory objects representing a device's memory mapped ranges.
    @discussion This method will return an array of IODeviceMemory objects representing the physical memory ranges allocated to a memory mapped device.
    @result An OSArray of IODeviceMemory objects, or zero if none are available. The array is retained by the provider, so is valid while attached. */

    virtual OSArray * getDeviceMemory( void );

/*! @function setDeviceMemory
    @abstract Sets the array of IODeviceMemory objects representing a device's memory mapped ranges.
    @discussion This method will set an array of IODeviceMemory objects representing the physical memory ranges allocated to a memory mapped device.
    @param array An OSArray of IODeviceMemory objects, or zero if none are available. The array will be retained by the object. */

    virtual void setDeviceMemory( OSArray * array );

    /* Interrupt accessors */

/*! @function registerInterrupt
    @abstract Register a C-function interrupt handler for a device supplying interrupts.
    @discussion This method will install a C-function interrupt handler to be called at primary interrupt time for a device's interrupt. Only one handler may be installed per interrupt source. IOInterruptEventSource provides an IOWorkLoop based abstraction for interrupt delivery that may be more appropriate for work loop based drivers.
    @param source The index of the interrupt source in the device.
    @param target An object instance to be passed to the interrupt handler.
    @param handler The C-function to be to be called at primary interrupt time when the interrupt occurs. The handler should process the interrupt by clearing the interrupt, or by disabling the source.
    @param refCon A reference constant for the handler's use.
    @result An IOReturn code.<br>kIOReturnNoInterrupt is returned if the source is not valid.<br>kIOReturnNoResources is returned if the interrupt already has an installed handler. */

    virtual IOReturn registerInterrupt(int source, OSObject *target,
				       IOInterruptAction handler,
				       void *refCon = 0);
                                       
/*! @function unregisterInterrupt
    @abstract Remove a C-function interrupt handler for a device supplying hardware interrupts.
    @discussion This method will remove a C-function interrupt handler previously installed with registerInterrupt.
    @param source The index of the interrupt source in the device.
    @result An IOReturn code.<br>kIOReturnNoInterrupt is returned if the source is not valid. */

    virtual IOReturn unregisterInterrupt(int source);

/*! @function getInterruptType
    @abstract Return the type of interrupt used for a device supplying hardware interrupts.
    @discussion This method will return the type of interrupt used by the device.
    @param source The index of the interrupt source in the device.
    @param interruptType The interrupt type for the interrupt source will be stored here by getInterruptType.<br> kIOInterruptTypeEdge will be returned for edge trigggered sources.<br> kIOInterruptTypeLevel will be returned for level trigggered sources.
    @result An IOReturn code.<br>kIOReturnNoInterrupt is returned if the source is not valid. */

    virtual IOReturn getInterruptType(int source, int *interruptType);

/*! @function enableInterrupt
    @abstract Enable a device interrupt.
    @discussion Enable a device interrupt. It is the callers responsiblity to keep track of the enable state of the interrupt source.
    @param source The index of the interrupt source in the device.
    @result An IOReturn code.<br>kIOReturnNoInterrupt is returned if the source is not valid. */

    virtual IOReturn enableInterrupt(int source);

/*! @function disableInterrupt
    @abstract Disable a device interrupt.
    @discussion Disable a device interrupt. It is the callers responsiblity to keep track of the enable state of the interrupt source.
    @param source The index of the interrupt source in the device.
    @result An IOReturn code.<br>kIOReturnNoInterrupt is returned if the source is not valid. */

    virtual IOReturn disableInterrupt(int source);

/*! @function causeInterrupt
    @abstract Cause a device interrupt to occur.
    @discussion Emulate a hardware interrupt, to be called from task level.
    @param source The index of the interrupt source in the device.
    @result An IOReturn code.<br>kIOReturnNoInterrupt is returned if the source is not valid. */

    virtual IOReturn causeInterrupt(int source);

/*! @function requestProbe
    @abstract An external request that hardware be re-scanned for devices.
    @discussion For bus families that do not usually detect device addition or removal, this method represents an external request (eg. from a utility application) to rescan and publish or remove found devices.
    @param options Family defined options, not interpreted by IOService.
    @result An IOReturn code. */

    virtual IOReturn requestProbe( IOOptionBits options );

    /* Generic API for non-data-path upstream calls */

/*! @function message
    @abstract Receive a generic message delivered from an attached provider.
    @discussion A provider may deliver messages via the message method to its clients informing them of state changes, for example kIOMessageServiceIsTerminated or kIOMessageServiceIsSuspended. Certain messages are defined by IOKit in IOMessage.h while others may family dependent. This method is implemented in the client to receive messages.
    @param type A type defined in IOMessage.h or defined by the provider family.
    @param provider The provider from which the message originates.
    @param argument An argument defined by the provider family, not used by IOService.
    @result An IOReturn code defined by the message type. */

    virtual IOReturn message( UInt32 type, IOService * provider,
                              void * argument = 0 );
                                
/*! @function messageClient
    @abstract Send a generic message to an attached client.
    @discussion A provider may deliver messages via the message method to its clients informing them of state changes, for example kIOMessageServiceIsTerminated or kIOMessageServiceIsSuspended. Certain messages are defined by IOKit in IOMessage.h while others may family dependent. This method may be called in the provider to send a message to the specified client, which may be useful for overrides.
    @param type A type defined in IOMessage.h or defined by the provider family.
    @param client A client of the IOService to send the message.
    @param argument An argument defined by the provider family, not used by IOService.
    @result The return code from the client message call. */
    
    virtual IOReturn messageClient( UInt32 messageType, OSObject * client,
                                    void * messageArgument = 0, vm_size_t argSize = 0 );

/*! @function messageClients
    @abstract Send a generic message to all attached clients.
    @discussion A provider may deliver messages via the message method to its clients informing them of state changes, for example kIOMessageServiceIsTerminated or kIOMessageServiceIsSuspended. Certain messages are defined by IOKit in IOMessage.h while others may family dependent. This method may be called in the provider to send a message to all the attached clients, via the messageClient method.
    @param type A type defined in IOMessage.h or defined by the provider family.
    @param argument An argument defined by the provider family, not used by IOService.
    @result Any non-kIOReturnSuccess return codes returned by the clients, or kIOReturnSuccess if all return kIOReturnSuccess. */

    virtual IOReturn messageClients( UInt32 type,
                                     void * argument = 0, vm_size_t argSize = 0 );

    virtual IONotifier * registerInterest( const OSSymbol * typeOfInterest,
                                           IOServiceInterestHandler handler,
                                           void * target, void * ref = 0 );

    virtual void applyToProviders( IOServiceApplierFunction applier,
                                   void * context );

    virtual void applyToClients( IOServiceApplierFunction applier,
                                 void * context );

    virtual void applyToInterested( const OSSymbol * typeOfInterest,
                                    OSObjectApplierFunction applier,
                                    void * context );

    virtual IOReturn acknowledgeNotification( IONotificationRef notification,
                                              IOOptionBits response );

    /* User client create */

/*! @function newUserClient
    @abstract A request to create a connection for a non kernel client.
    @discussion A non kernel client may request a connection be opened via the IOServiceOpen() library function, which will call this method in an IOService. The rules & capabilities of user level clients are family dependent, and use the functions of the IOUserClient class for support. IOService's implementation returns kIOReturnUnsupported, so any family supporting user clients must implement this method.
    @param owningTask The mach task requesting the connection.
    @param securityID A token representing the access level for the task.
    @param type A constant specifying the type of connection to be created, specified by the caller of IOServiceOpen and interpreted only by the family.
    @param handler An instance of an IOUserClient object to represent the connection, which will be released when the connection is closed, or zero if the connection was not opened.    
    @param properties A dictionary of additional properties for the connection.
    @result A return code to be passed back to the caller of IOServiceOpen. */

    virtual IOReturn newUserClient( task_t owningTask, void * securityID,
                                    UInt32 type, OSDictionary * properties,
                                    IOUserClient ** handler );

    virtual IOReturn newUserClient( task_t owningTask, void * securityID,
                                    UInt32 type, IOUserClient ** handler );

    /* Return code utilities */

/*! @function stringFromReturn
    @abstract A utility to supply a programmer friendly string from an IOReturn code.
    @discussion Strings are available for the standard return codes in IOReturn.h in IOService, while subclasses may implement this method to interpret family dependent return codes.
    @param rtn The IOReturn code.
    @result A pointer to a constant string, or zero if the return code is unknown. */
    
    virtual const char * stringFromReturn( IOReturn rtn );

/*! @function errnoFromReturn
    @abstract A utility to translate an IOReturn code to a BSD errno.
    @discussion BSD defines its own return codes for its functions in sys/errno.h, and IOKit families may need to supply compliant results in BSD shims. Results are available for the standard return codes in IOReturn.h in IOService, while subclasses may implement this method to interpret family dependent return codes.
    @param rtn The IOReturn code.
    @result The BSD errno or EIO if unknown. */
    
    virtual int errnoFromReturn( IOReturn rtn );

    /* * * * * * * * * * * * * * * * * * * * * * * * * * * * */
    /* * * * * * * * * * * * Internals * * * * * * * * * * * */
    /* * * * * * * * * * * * * * * * * * * * * * * * * * * * */

public:
    int               _numInterruptSources;
    IOInterruptSource *_interruptSources;

    static void initialize( void );
    
    virtual bool serializeProperties( OSSerialize * s ) const;

    static void setPlatform( IOPlatformExpert * platform);
    static void setPMRootDomain( class IOPMrootDomain * rootDomain );

    static IOReturn catalogNewDrivers( OSOrderedSet * newTables );
    static IOReturn waitMatchIdle( UInt32 ms );

    static IOService * resources( void );
    virtual bool checkResources( void );
    virtual bool checkResource( OSObject * matching );

    virtual void probeCandidates( OSOrderedSet * matches );
    virtual bool startCandidate( IOService * candidate );
    virtual IOService * getClientWithCategory( const OSSymbol * category );

    virtual bool passiveMatch( OSDictionary * matching, bool changesOK = false);

    virtual void startMatching( IOOptionBits options = 0 );
    virtual void doServiceMatch( IOOptionBits options );
    virtual void doServiceTerminate( IOOptionBits options );

    static OSObject * getExistingServices( OSDictionary * matching,
		 IOOptionBits inState, IOOptionBits options = 0 );

    static IONotifier * setNotification(
			const OSSymbol * type, OSDictionary * matching,
                    	IOServiceNotificationHandler handler,
                        void * target, void * ref,
                        SInt32 priority = 0 );

    static IONotifier * doInstallNotification(
			const OSSymbol * type, OSDictionary * matching,
			IOServiceNotificationHandler handler,
			void * target, void * ref,
			SInt32 priority, OSIterator ** existing );

    static bool syncNotificationHandler( void * target, void * ref,
			IOService * newService );

    virtual void deliverNotification( const OSSymbol * type,
                            IOOptionBits orNewState, IOOptionBits andNewState );

    bool invokeNotifer( class _IOServiceNotifier * notify );

    virtual void unregisterAllInterest( void );

    virtual IOReturn waitForState( UInt32 mask, UInt32 value,
				 mach_timespec_t * timeout = 0 );

    UInt32 _adjustBusy( SInt32 delta );

    bool terminatePhase1( IOOptionBits options = 0 );
    void scheduleTerminatePhase2( IOOptionBits options = 0 );
    void scheduleStop( IOService * provider );
    void scheduleFinalize( void );
    static void terminateThread( void * arg );
    static void terminateWorker( IOOptionBits options );
    static void actionWillTerminate( IOService * victim, IOOptionBits options, 
                                        OSArray * doPhase2List );
    static void actionDidTerminate( IOService * victim, IOOptionBits options );
    static void actionFinalize( IOService * victim, IOOptionBits options );
    static void actionStop( IOService * client, IOService * provider );

    void PMfree( void );

    virtual IOReturn resolveInterrupt(IOService *nub, int source);
    virtual IOReturn lookupInterrupt(int source, bool resolve, IOInterruptController **interruptController);

    /* power management */
    
/*! @function PMinit
        A power managment policy-maker for a device calls itself here to initialize its power management.
        PMinit allocates and initializes the power management instance variables, and it should be called before any
        access to those variables or the power management methods. */
    virtual void PMinit (void );

/*! @function PMstop
        A power managment policy-maker for a device calls itself here when it resigns its responsibilities as
        policy-maker.  This typically happens when it is handing off the responsibility to another policy-maker,
        or when the device is removed from the system.  The power managment variables don't exist after
        this call,  and the power managment methods in the caller shouldn't be accessed.  */
    virtual void PMstop ( void );

/*! @function joinPMtree
        A policy-maker calls its nub here when initializing, to be attached into
        the power management hierarchy.  The default function is to call the
        platform expert, which knows how to do it.  This method is overridden
        by a nub subclass which may either know how to do it, or may need
        to take other action.

        This may be the only "power management" method used in a nub, meaning
        it may be called even if the nub is not initialized for power management.

        Before the nub returns from this method, the caller will probably be called
        at "setPowerParent" and "setAggressiveness" and possibly at "addPowerChild" as it is
        added to me hierarchy. */
    virtual void joinPMtree ( IOService * driver );

/*! @function registerPowerDriver
        A driver calls a policy-maker here to volunteer to control power to the device.
        If the policy-maker accepts the volunteer, it adds the volunteer to its list of
        interested drivers, and it will call the volunteer at appropriate times to switch
        the power state of the device.
        @param controllingDriver
        This points to the calling driver.
        @param powerStates
        This is an array of power states which the driver can deal with.  If this array
        is no less rich than one supplied by an earlier volunteer, then the policy-maker
        uses the calling driver as its power-controlling driver.
        @param numberOfStates
        The number of power states in the array.  Power states are defined in
        pwr_mgt/IOPMpowerState.h.
        @result
        IOPMNoErr is returned.  There are various error conditions possible which prevent
        the policy-maker from accepting the new power state array.  These conditions
        are logged in the power managment event log, but not returned to the caller. */
    virtual IOReturn registerPowerDriver ( IOService* controllingDriver, IOPMPowerState* powerStates, unsigned long numberOfStates );

/*! @function registerInterestedDriver
        Some IOService calls a policy-maker here to register interest in the changing
        power state of its device.
        @param theDriver
        The policy-maker adds this pointer to the calling IOService to its list of
        interested drivers.  It informs drivers on this list pre- and post-power change.
        @result
        The policy-maker returns flags describing the capability of the device in its
        current power state.  The policy-maker does not interpret these flags or
        understand them; they come from the power state array, and are understood
        only by interested drivers and perhaps the power-controlling driver.  If the
        current power state is not yet defined, zero is returned.  This is the case when
        the policy-maker is not yet in the power domain hierarchy or when it doesn't
        have a power-controlling driver yet. */
    virtual IOPMPowerFlags registerInterestedDriver ( IOService* theDriver );

/*! @function deRegisterInterestedDriver
        An IOService which has previously registered with a policy-maker as an interested
        driver calls the policy-maker here to withdraw its interest.  The policy-maker removes
        it from its list of interested drivers.
        @result
        These bits describe the capability of the device in its current power state.  They are
        not understood by the policy-maker; they come from the capabilityFlags field of the
        current power state in the power state array. */
    virtual IOReturn deRegisterInterestedDriver ( IOService * theDriver );

/*! @function acknowledgePowerChange
        When a device is changing power state, its policy-maker informs interested
        parties before and after the change.  Interested parties are those which
        have registered as interested drivers and also children of the policy-maker
        in the case that it is a power domain.
        When an object is so informed, it can return an indication that it is prepared
        for the change, or it can return an indication that it needs some time to
        prepare.  In this case it will call this method in the policy-maker when it has
        prepared.
        @param theDriver
        This points to the calling driver.  The policy-maker uses it to know if all
        interested parties have acknowledged the power state change.
        @result
        IOPMNoErr is returned. */
    virtual IOReturn acknowledgePowerChange ( IOService * whichDriver );

/*! @function acknowledgeSetPowerState
        When a policy-maker instructs its controlling driver to switch the state of
        the device, the driver can return an indication that the change is complete,
        or it can return an indication that it needs some time to make the change.
        In this case it will call this method in the policy-maker when it has made the
        power state change.
        @result
        IOPMNoErr is returned. */
    virtual IOReturn acknowledgeSetPowerState ( void );

/*! @function powerDomainWillChangeTo
        When a power domain changes state, it notifies its children, which
        are policy-makers, by calling them at this method.  It calls here
        before it makes the change, and a called policy-maker can return
        IOPMAckImplied to indicate that it is prepared for the change,
        or it can return a non-zero number to indicate that it is not prepared
        but will prepare and then call the parent at acknowledgePowerChange.

        To prepare for a lowering of the power domain, the policy-maker
        informs all its interested parties of any resulting change in its device,
        and when they have all acknowledged, it calls its controlling driver
        to switch the device to an appropriate power state for the imminent
        domain state.  If any interested driver or the controlling driver does
        not acknowledge immediately, then the policy-maker also will not.

        To prepare for a raising of the power domain, the policy-maker
        informs all its interested parties of any resulting change in its device.
        If any do not acknowledge immediately, then the policy-maker also will not.
        @param newPowerStateFlags
        These flags describe the character of power in the imminent domain state.
        They are not understood by the policy-maker.  It asks the controlling
        driver to translate them into a state number within the power state array.
        (The policy-maker for the domain also doesn't understand the bits; they
         come from a outputPowerCharacter field of the power state array for
         the power domain.)
        @param whichParent
        This pointer identifies the calling parent. */
    IOReturn powerDomainWillChangeTo ( IOPMPowerFlags newPowerStateFlags, IOPowerConnection * whichParent );

/*! @function powerDomainDidChangeTo
        When a power domain changes state, it notifies its children, which
        are policy-makers, by calling them at this method.  It calls here
        after the changed power of the power domain has settled at the
        new level.  A called policy-maker can return
        IOPMAckImplied to indicate that it is prepared for the change,
        or it can return a non-zero number to indicate that it is not prepared
        but will prepare and then call the parent at acknowledgePowerChange.

        To prepare for a lowered power domain, the policy-maker
        informs all its interested parties of the new power state of its device.
        If any do not acknowledge immediately, then the policy-maker also will not.

        To prepare for a raised power domain, the policy-maker calls its controlling
        driver to switch the device to the appropriate power state for the new
        domain state.  When that is accomplished, the policy-maker informs
        all its interested parties of the new power state.  If any interested driver
        or the controlling driver does not acknowledge immediately, then the
        policy-maker also will not.
        
        @param newPowerStateFlags
        These flags describe the character of power in the new domain state.
        They are not understood by the policy-maker.  It asks the controlling
        driver to translate them into a state number within the power state array.
        (The policy-maker for the domain also doesn't understand the bits; they
         come from a outputPowerCharacter field of the power state array for
         the power domain.)
        @param whichParent
        This pointer identifies the calling parent. */
    IOReturn powerDomainDidChangeTo ( IOPMPowerFlags newPowerStateFlags, IOPowerConnection * whichParent );

/*! @function requestPowerDomainState
        The child of a power domain calls it parent here to request power of a certain
        character.  It does this after lowering power in its own device which allows
        it to tolerate lower power in the domain, and it does this if it needs more
        power for its device than is currently available in the domain.
        @param desiredState
        These flags describe the power required for some state of the caller's device.
        They are not understood by either the child or the parent.  They come from
        the power state array of the child (in the inputPowerRequirement field), and
        the parent compares them to bits in the outputPowerCharacter fields of its
        power state array.
        @param whichChild
        This points to the caller, so the power domain can know which child is requesting.
        @param specificationFlags
        This value modifies the parent's choice of power state.
        If the parameter is IOPMNextHigherState, the parent will choose the lowest state
        which matches desiredState and which is higher than the current state.
        If the parameter is IOPMHighestState	, the parent will choose the highest state
        which matches desiredState.
        If the parameter is IOPMNextLowerState, the parent will choose the highest state
        which matches desiredState and which is lower than the current state.
        If the parameter is IOPMLowestState, the parent will choose the lowest state
        which matches desiredState.
        A state matches desiredState if all the bits set in desiredState are also set in the
        outputPowerCharacter field of that state in the parent's power state array.
        @result
        The power domain parent returns IOPMBadSpecification if specificationFlags
        not wellformed.  It returns IOPMNoSuchState if no state in its array satisfies
        the callers specification.  It returns IOPMNotYetInitialized if it has not power
        state array yet to compare with.  Otherwise it returns IOPMNoErr.  In the last
        case it will initiate its change to the new state if it has a parent in the hierarchy
        (or is the root power domain.)  */
    virtual IOReturn requestPowerDomainState ( IOPMPowerFlags desiredState, IOPowerConnection * whichChild, unsigned long specificationFlags );

/*! @function makeUsable
        Some client of a device is asking that it become usable.  Although
        this has not come from the policy-maker for the device, treat it exactly
        as if it had.  In this way, subsequent requests for lower power from
        the policy-maker will pre-empt this request.
        We treat this as policy-maker request to switch to the highest power state.
        @result
        The return code reflects the state of the policy-maker's internal queue of power
        changes and can be ignored by the caller.  */
    virtual IOReturn makeUsable ( void );

    /*! @function temporaryPowerClampOn
        A power domain calls this method to hold itself in the highest power state until it
        has children, and at that point the domain state is controlled by the childrens'
        requirements.
        @result
        The return code reflects the state of the policy-maker's internal queue of power
        changes and can be ignored by the caller.  */
    virtual IOReturn temporaryPowerClampOn ( void );
    
/*! @function changePowerStateTo
        The power-controlling driver calls the policy-maker here when it wants the device
        switched to a different power state.  This is mildly ironic in that it is the controlling
        driver which does the switching, but it must do it this way so that the policy-maker
        can make sure the power domain is correct and to notify interested parties
        pre-change.  When appropriate, the policy-maker will call the controlling driver and
        have it switch the device to the requested state in the usual way.
        This request by the controlling driver is sticky in that the policy-maker will not
        switch the device lower than this request, so if the driver needs power raised for
        some reason and then gets it and does what it needs, it should then rescind the
        request by requesting state zero.  This will allow the policy-maker to control the
        device as usual.
        @param ordinal
        This is the number, in the power state array, of the desired power state.
        @result
        The return code reflects the state of the policy-maker's internal queue of power
        changes and can be ignored by the caller. */
    virtual IOReturn changePowerStateTo ( unsigned long ordinal );

/*! @function currentCapability
        Some object calls a policy-maker here to find out the current capability of a device.
        The policy-maker returns a copy of the capabilityFlags field for the current power
        state in the power state array. */
   virtual  IOPMPowerFlags currentCapability ( void );

/*! @function currentPowerConsumption
        Some object calls a policy-maker here to find out the current power consumption of a device.
        The policy-maker returns a copy of the staticPower field for the current power state in the
        power state array. */
    virtual  unsigned long currentPowerConsumption ( void );

/*! @function activityTickle
        A principal function of a policy-maker is deciding when the device is idle and can be
        powered down.  To do this it needs to know when the device is being used.  In some
        cases it is in the data path to the device so it knows when it is being used.  In others
        it is not and must be told.  The activityTickle method is provided for objects in the
        system to tell a policy-maker that its device is being used.

        If the policy-maker is managing the idleness determination totally on its own, the
        paramter should be kIOPMSubclassPolicy, and the policy-maker should intercept
        the activityTickle call, because the superclass will do nothing with it.

        The IOService superclass can manage idleness determination, too, with the simple
        mechanism of an idle timer and this activityTickle call.  To start this up, the policy-
        maker calls its superclass at setIdleTimerPeriod.  This starts a timer for the time
        interval specified in the call.  When the timer expires, the superclass checks to see
        if there has been any activity since the last timer expiration. (It checks to see if
        activityTickle has been called).  If there has been activity, it restarts the timer, and
        this process continues.  When the timer expires, and there has been no device
        activity, the superclass lowers the device power state to the next lower state.
        This can continue until the device is in state zero.

        After the device has been powered down by at least one power state,
        a call to activityTickle will cause the device to be switched to a higher state
        required for the activity.

        activityTickle in the IOService superclass is meant to be called by sub-classed
        policy-makers, because only they understand the paramters.  They may implement
        an activityTickle for their clients and then call this activityTickle in the superclass.
        @param type
        activityTickle with parameter kIOPMSubclassPolicy is not handled in IOService
        and should be intercepted by the subclass policy-maker.
        activityTickle with parameter kIOPMSuperclassPolicy1 causes an activity flag to be set,
        and the device state checked.  If the device has been powered down, it is powered up again.
        @param stateNumber
        When the type parameter is kIOPMSuperclassPolicy1, the stateNumber contains
        the desired power state ordinal for the activity.  If the device is in a lower state,
        the superclass will switch it to this state.  This is for devices which can handle
        some accesses in lower power states than others; the device is powered up only
        as far as it needs to be for the activity.
        @result
        When the type parameter is kIOPMSuperclassPolicy1, the superclass returns true
        if the device is currently in the state specified by stateNumber.  If it is in a lower
        state and must be brought up, it returns false.  In this case the superclass will
        cause the device to be brought up. */
    virtual bool activityTickle ( unsigned long type, unsigned long stateNumber=0 );

/*! @function setAggressiveness
        The parent of a policy-maker calls it here while broadcasting an aggressiveness factor
        around the power management hierarchy.

        A policy-maker may want to intercept this call if it needs to do something with the
        new factor, like change its idle timeout, for example.  A policy-maker which does
        intercept should call setAggressiveness in its superclass, though.
        @param type
        There are several aggressiveness factors which can be broadcast.  One is a general
        aggressiveness factor, and the others are specific to parts of the system, like the
        hard drive or the display.  A policy-maker takes action only on a factor that applies
        to its policy.  These factor types (e.g. kPMSetGeneralAggressiveness) are defined
        in pwr_mgt/IOPM.h.
        @param newLevel
        This is the aggressiveness factor's new value.
        @result
        setAggressiveness returns IOPMNoErr. */
    virtual  IOReturn setAggressiveness ( unsigned long, unsigned long newLevel );

    /*! @function getAggressiveness
        Return the current aggressiveness value for the given type. 
     */
    virtual IOReturn getAggressiveness ( unsigned long, unsigned long * );

    /*! @function systemWake
        The parent of a policy-maker calls it here while broadcasting a system wake event.

        A policy-maker must intercept this call if its device can wake the system from sleep.
        It should check to see if its device did in fact wake the system, and if so, treat the
        waking action as activity:  it should request power from its parent to keep the system
        up until it idles again.

        A policy-maker which does  intercept should call systemWake in its superclass.
        @result
        systemWake returns IOPMNoErr. */
    virtual  IOReturn systemWake ( void );

    /*! @function temperatureCriticalForZone
        A policy-maker calls its parent power domain to alert it to critical temperature in
        some thermal zone.
        @param whichZone
        This is a pointer to the IOService policy-maker for the thermal zone which has
        reported critical temperature.
        @result
        temperatureCriticalForZone returns IOPMNoErr. */
    virtual  IOReturn temperatureCriticalForZone ( IOService * whichZone );

/*! @function youAreRoot
        The Platform Expert instantiates the root power domain IOService and
        calls it here to inform it that it is the root power domain.
        (The only difference between the root domain and any other power domain
         is that the root has no parent and therefore never calls it. */
    virtual IOReturn youAreRoot ( void );

/*! @function setPowerParent
        The Platform Expert or some other IOService calls a policy-maker here to
        inform it who its parent is in the power management hierarchy.  This is
        part of the process of attaching a policy-maker into the hierarchy.
        @param theParent
        This is a pointer to the parent IOService power domain.
        @param stateKnown
        This is true if the parent knows its power state. (It would not if it doesn't yet
        have a parent or a controlling driver)
        @param currentState
        If the stateKnown parameter is true, these flags describe the character of
        power in the power domain.  If the policy-maker has a controlling driver,
        the policy-maker asks the driver, given this power domain state,
        what state it would be in, and then it  tells the driver to assume that state. */
    virtual IOReturn setPowerParent ( IOPowerConnection * theParent, bool stateKnown, IOPMPowerFlags currentState );

/*! @function addPowerChild
        The Platform Expert or some other IOService calls a power domain policy-maker
        here to introduce it to a child of it, a member of the domain.
        @param theChild
        This is a pointer to the child IOService, which is another power domain policy-maker
        or a device policy-maker. */
    virtual IOReturn addPowerChild ( IOService * theChild );

/*! @function removePowerChild
        A power domain policy-maker is called here to tell it that one of its enclosed members
        is disappearing.  This happens when a device policy-maker hands off its responsibility
        to another policy-maker or when its device disappears. */
    virtual IOReturn removePowerChild ( IOPowerConnection * theChild );

/* @function command_received
            */
    virtual void command_received ( void *, void * , void * , void *);

/* @function start_PM_idle_timer
            */
    virtual void start_PM_idle_timer ( void );

/* @function PM_idle_timer_expiration
            */
    virtual void PM_idle_timer_expiration ( void );

/* @function PM_Clamp_Timer_Expired
            */
    virtual void PM_Clamp_Timer_Expired (void);

/*! @function setIdleTimerPeriod
        A policy-maker which uses the type 1 idleness determination provided by IOService
        calls its superclass here to set or change the idle timer period.

        See activityTickle for a description of this idleness determination.
        @param period
        This is the desired idle timer period in seconds.
        @result
        The normal return is IOPMNoErr, but it is possible to return kIOReturnError if there
        was difficulty creating the timer event or the command queue, for example (which is
        done only on the first call.) */
    virtual IOReturn  setIdleTimerPeriod ( unsigned long );

/*! @function getPMworkloop
            */
    virtual IOWorkLoop *getPMworkloop ( void );

/* @function ack_timer_ticked
            */
    void ack_timer_ticked ( void );

/* @function settleTimerExpired
            */
    void settleTimerExpired ( void );
    
    IOReturn serializedAllowPowerChange2 ( unsigned long );
    IOReturn serializedCancelPowerChange2 ( unsigned long );

// implemented by power-controlling driver...

/*! @function setPowerState
        A policy-maker (usually its superclass) calls its controlling driver here to change
        the power state of its device.
        @param powerStateOrdinal
        This is the number in the power state array of the state the driver is being
        instructed to switch to.
        @param whatDevice
        This is a pointer to the policy-maker.  It is useful when a single power-controlling
        driver controls multiple devices and needs to know for which device it is being
        called.
        @result
        The driver returns IOPMAckImplied if it has complied with the request when it
        returns.  If it has started the process of changing power state but not finished
        it, it should return a number of microseconds which is an upper limit of the time
        it will need to finish.  Then, when it has completed the power switch, it should
        call acknowledgeSetPowerState in the policy-maker. */
virtual IOReturn setPowerState ( unsigned long powerStateOrdinal, IOService* whatDevice );

/*! @function clampPowerOn
    This method sets the device to the highest power state and ensures it stays there
    until a timer of duration length expires.
 */
virtual void clampPowerOn (unsigned long duration);

/*! @function maxCapabilityForDomainState
    A policy-maker (usually its superclass) calls its controlling driver here to find out
    the highest power state possible for a given power domain state.  This happens
    when the power domain is changing state and the policy-maker wants to find
    out what states the device is capable of in the new domain state.
    @param domainState
    These flags describe the character of domain power in some domain power state.
    The flags are not understood by the calling policy-maker; they were passed to it
    by its power domain parent.  They come from the outputPowerCharacter field
    of a state in the power domain's power state array.

    This method is implemented in a simple way in IOService.  It scans the power state
    array looking for the highest state whose inputPowerRequirement field exactly
    matches the parameter.  If more intelligent determination is required, the
    power-controlling driver should implement the method and override the superclass.
    @result
    A state number is returned. */
virtual unsigned long maxCapabilityForDomainState ( IOPMPowerFlags domainState );

/*! @function initialPowerStateForDomainState
    A policy-maker (usually its superclass) calls its controlling driver here to find out
    which power state the device is in, given the current power domain state.  This
    happens once, when the policy-maker is initializing, and the controlling driver
    can use this to know what state the device is in initially.
    @param domainState
    These flags describe the character of domain power in the current state of the
    power domain.  The flags are not understood by the calling policy-maker; they
    were passed to it by its power domain parent.  They come from the
    outputPowerCharacter field of the current power state in the power domain's
    power state array.

    This method is implemented in a simple way in IOService.  It scans the power state
    array looking for the highest state whose inputPowerRequirement field exactly
    matches the parameter.  If more intelligent determination is required, the
    power-controlling driver should implement the method and override the superclass.
    @result
    A state number is returned. */
virtual unsigned long initialPowerStateForDomainState ( IOPMPowerFlags );

/*! @function powerStateForDomainState
    A policy-maker (usually its superclass) calls its controlling driver here to find out
    what power state the device would be in for a given power domain state.  This
    happens when the power domain is changing state and the policy-maker wants
    to find out the effect of the change.
    @param domainState
    These flags describe the character of domain power in some domain power state.
    The flags are not understood by the calling policy-maker; they were passed to it
    by its power domain parent.  They come from the outputPowerCharacter field
    of a state in the power domain's power state array.

    This method is implemented in a simple way in IOService.  It scans the power state
    array looking for the highest state whose inputPowerRequirement field exactly
    matches the parameter.  If more intelligent determination is required, the
    power-controlling driver should implement the method and override the superclass.
    @result
    A state number is returned. */
virtual unsigned long powerStateForDomainState ( IOPMPowerFlags domainState );

/*! @function powerStateWillChangeTo
    A policy-maker informs interested parties that its device is about to change to
    a different power state.  Interested parties are those that have registered for
    this notification via registerInterestedDriver and also the power-controlling
    driver which is registered as an interested driver automatically when it registers
    as the controlling driver.
    @param capabilities
    These flags describe the capability of the device in the new power state.  They
    are not understood by the policy-maker; they come from the capabilityFlags field
    of the new state in the power state array.
    @param stateNumber
    This is the number of the state in the state array that the device is switching to.
    @param whatDevice
    This points to the policy-maker, and it is used by a driver which is receiving power
    state change notifications for multiple devices.
    @result
    The driver returns IOPMAckImplied if it has prepared for the power change when it
     returns.  If it has started preparing but not finished, it should return a number of
    microseconds which is an upper limit of the time  it will need to finish preparing.
    Then, when it has completed its preparations, it should call acknowledgePowerChange
    in the policy-maker. */
virtual IOReturn powerStateWillChangeTo ( IOPMPowerFlags, unsigned long, IOService* );

/*! @function powerStateDidChangeTo
    A policy-maker informs interested parties that its device has changed to
    a different power state.  Interested parties are those that have registered for
    this notification via registerInterestedDriver and also the power-controlling
    driver which is registered as an interested driver automatically when it registers
    as the controlling driver.
    @param capabilities
    These flags describe the capability of the device in the new power state.  They
    are not understood by the policy-maker; they come from the capabilityFlags field
    of the new state in the power state array.
    @param stateNumber
    This is the number of the state in the state array that the device has switched to.
    @param whatDevice
    This points to the policy-maker, and it is used by a driver which is receiving power
    state change notifications for multiple devices.
    @result
    The driver returns IOPMAckImplied if it has prepared for the power change when it
     returns.  If it has started preparing but not finished, it should return a number of
    microseconds which is an upper limit of the time  it will need to finish preparing.
    Then, when it has completed its preparations, it should call acknowledgePowerChange
    in the policy-maker. */
virtual IOReturn powerStateDidChangeTo ( IOPMPowerFlags, unsigned long, IOService* );

/*! @function didYouWakeSystem
    A policy-maker calls its power driver here to ask if its device is the one
    which just woke the system from sleep.
    @result
    The driver returns true if it did wake the system and false if it didn't. */
virtual bool didYouWakeSystem  ( void );

/*! @function newTemperature
    A thermal-zone driver calls its policy-maker here to tell it that the temperature in
    the zone has changed.  The thermal-zone policy-maker uses this information to
    manage its thermal zone.
    @param currentTemp
    This is the new temperature in the thermal zone.
    @param whichZone
    This is a pointer to the controlling driver.
        */
virtual IOReturn newTemperature  ( long currentTemp, IOService * whichZone );

    virtual bool askChangeDown ( unsigned long );
    virtual bool tellChangeDown ( unsigned long );
    bool tellChangeDown1 ( unsigned long );
    bool tellChangeDown2 ( unsigned long );
    virtual void tellNoChangeDown ( unsigned long );
    virtual void tellChangeUp ( unsigned long );
    virtual IOReturn allowPowerChange ( unsigned long refcon );
    virtual IOReturn cancelPowerChange ( unsigned long refcon );

// ...implemented by power-controlling driver

    protected:
/*! @function changePowerStateToPriv
    A policy-maker calls its superclass here to change the power state of the device.
    The superclass takes care of making sure the power domain state is appropriate
    and informing interested parties.  It calls the controlling driver to make the change.
    @param ordinal
    This is the number, in the power state array, of the desired power state.
    @result
    The return code reflects the state of the policy-maker's internal queue of power
    changes and can be ignored by the caller.          
            */
    IOReturn changePowerStateToPriv ( unsigned long ordinal );

/*! @function powerOverrideOnPriv
    A policy-maker normally keeps its device at the highest state required by itself,
    its power-controlling driver, and its children (when the power domain state
    allows).  There may be times, however, when a policy-maker needs the power
    state lower than its driver or its children desire, and when this is the case, it
    calls powerOverrideOnPriv in its superclass to enable this override.  When the override
    is on, the superclass keeps the device in the state desired by the policy-maker
    (requested via changePowerStateToPriv), regardless of the children's or driver's desire.
    Turning on the override will initiate a power change if the policy-maker's desired
    power state is different from the maximum of the controlling driver's desire and
    the children's desires.
    @result
    The return code reflects the state of the policy-maker's internal queue of power
    changes and can be ignored by the caller.  */
    IOReturn powerOverrideOnPriv ( void );

/*! @function powerOverrideOffPriv
        When a policy-maker has enabled the override, it can disable it again by calling
        this method in its superclass.  This will allow the superclass to keep the device
         at the highest state required by itself, its power-controlling driver, and its
        children (when the power domain state allows).  Turning off the override
        will initiate a power change if the policy-maker's desired power state is different
        from the maximum of the controlling driver's desire and the children's desires.
        @result
        The return code reflects the state of the policy-maker's internal queue of power
        changes and can be ignored by the caller.  */
    IOReturn powerOverrideOffPriv ( void );

        /*! @function powerChangeDone
            A policy-maker calls itself here when a power change is completely done, when
        all interested parties have acknowledged the powerStateDidChangeTo call.
        The implementation here is null; the method is meant to be overridden by
        subclassed policy-makers, and that is how one finds out that a power change
        it initiated is complete
            @param stateNumber
            This is the number of the state in the state array that the device has switched from.  */
    virtual void powerChangeDone ( unsigned long );
    
    bool tellClientsWithResponse ( int messageType );
    void tellClients ( int messageType );

private:

    IOReturn enqueuePowerChange ( unsigned long, unsigned long, unsigned long, IOPowerConnection *, unsigned long );
    void setParentInfo ( IOPMPowerFlags, IOPowerConnection * );
    IOReturn notifyAll ( bool is_prechange );
    bool notifyChild ( IOPowerConnection * nextObject, bool is_prechange );
    bool inform ( IOPMinformee * nextObject, bool is_prechange );
    
    // Power Management state machine
    // power change initiated by driver
    void OurChangeTellClientsPowerDown ( void );
    void OurChangeTellPriorityClientsPowerDown ( void );
    void OurChangeNotifyInterestedDriversWillChange ( void );
    void OurChangeSetPowerState ( void );
    void OurChangeWaitForPowerSettle ( void );
    void OurChangeNotifyInterestedDriversDidChange ( void );
    void OurChangeFinish ( void );
    
    // downward power change initiated by a power parent
    IOReturn ParentDownTellPriorityClientsPowerDown_Immediate ( void );
    IOReturn ParentDownNotifyInterestedDriversWillChange_Immediate ( void );
    void ParentDownTellPriorityClientsPowerDown_Delayed ( void );
    void ParentDownNotifyInterestedDriversWillChange_Delayed ( void );
    IOReturn ParentDownSetPowerState_Immediate ( void );
    IOReturn ParentDownWaitForPowerSettleAndNotifyDidChange_Immediate ( void );
    void ParentDownNotifyDidChangeAndAcknowledgeChange_Delayed ( void );
    void ParentDownSetPowerState_Delayed ( void );
    void ParentDownWaitForPowerSettle_Delayed ( void );
    void ParentDownAcknowledgeChange_Delayed ( void );
    
    // upward power change initiated by a power parent
    void ParentUpSetPowerState_Delayed ( void );
    IOReturn ParentUpSetPowerState_Immediate ( void );
    IOReturn ParentUpWaitForSettleTime_Immediate ( void );
    IOReturn ParentUpNotifyInterestedDriversDidChange_Immediate ( void );
    void ParentUpWaitForSettleTime_Delayed ( void );
    void ParentUpNotifyInterestedDriversDidChange_Delayed ( void );
    void ParentUpAcknowledgePowerChange_Delayed ( void );
    
    void all_done ( void );
    void all_acked ( void );
    void driver_acked ( void );
    void start_ack_timer ( void );
    void stop_ack_timer ( void );
    unsigned long compute_settle_time ( void );
    IOReturn startSettleTimer ( unsigned long delay );
    IOReturn changeState ( void );
    IOReturn add_child_to_active_change ( IOPowerConnection * );
    IOReturn add_driver_to_active_change ( IOPMinformee * );
    IOReturn instruct_driver ( unsigned long newState );
    bool acquire_lock ( void );
    IOReturn start_parent_change ( unsigned long queue_head );
    void start_our_change ( unsigned long queue_head );
    IOReturn ask_parent ( unsigned long requestedState );
    bool checkForDone ( void );
    bool responseValid ( unsigned long x );
    IOReturn allowCancelCommon ( void );
    void computeDesiredState ( void );
    void rebuildChildClampBits ( void );
};

#endif /* ! _IOKIT_IOSERVICE_H */
