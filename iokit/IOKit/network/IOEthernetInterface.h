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
 * IOEthernetInterface.h
 *
 * HISTORY
 * 8-Jan-1999       Joe Liu (jliu) created.
 */

#ifndef _IOETHERNETINTERFACE_H
#define _IOETHERNETINTERFACE_H

/*! @defined kIOEthernetInterfaceClass
    @abstract kIOEthernetInterfaceClass is the name of the
        IOEthernetInterface class. */

#define kIOEthernetInterfaceClass     "IOEthernetInterface"

/*! @defined kIOActivePacketFilters
    @abstract kIOActivePacketFilters is a property of IOEthernetInterface
        objects. It has an OSDictionary value.
    @discussion The kIOActivePacketFilters property describes the current
        set of packet filters that have been successfully activated. Each
        entry in the dictionary is a key/value pair consisting of the filter
        group name, and an OSNumber describing the set of active filters for
        that group. Entries in this dictionary will mirror those in
        kIORequiredPacketFilters if the controller has reported success for
        all filter change requests from the IOEthernetInterface object. */

#define kIOActivePacketFilters        "IOActivePacketFilters"

/*! @defined kIORequiredPacketFilters
    @abstract kIORequiredPacketFilters is a property of IOEthernetInterface
        objects. It has an OSDictionary value.
    @discussion The kIORequiredPacketFilters property describes the current
        set of required packet filters. Each entry in the dictionary is a
        key/value pair consisting of the filter group name, and an OSNumber
        describing the set of required filters for that group. */

#define kIORequiredPacketFilters      "IORequiredPacketFilters"

/*! @defined kIOMulticastAddressList
    @abstract kIOMulticastAddressList is a property of IOEthernetInterface
        objects. It is an OSData object.
    @discussion The kIOMulticastAddressList property describes the
        list of multicast addresses that are being used by the
        controller to match against the destination address of an
        incoming frame. */

#define kIOMulticastAddressList       "IOMulticastAddressList"
#define kIOMulticastFilterData        kIOMulticastAddressList    

/*
 * Kernel
 */
#if defined(KERNEL) && defined(__cplusplus)

#include <IOKit/network/IONetworkInterface.h>
#include <IOKit/network/IOEthernetController.h>
#include <IOKit/network/IOEthernetStats.h>

/*! @class IOEthernetInterface : public IONetworkInterface
    @abstract The Ethernet interface object. An Ethernet controller driver,
    that is a subclass of IOEthernetController, will instantiate an object
    of this class when the driver calls the attachInterface() method.
    This interface object will then vend an Ethernet interface to DLIL,
    and manage the connection between the controller driver and the upper
    networking layers. Drivers will seldom need to subclass
    IOEthernetInterface. */

class IOEthernetInterface : public IONetworkInterface
{
    OSDeclareDefaultStructors( IOEthernetInterface )

private:
    struct arpcom *  _arpcom;               // Arpcom struct allocated
    UInt32           _mcAddrCount;          // # of multicast addresses
    bool             _ctrEnabled;           // Is controller enabled?
    OSDictionary *   _supportedFilters;     // Controller's supported filters
    OSDictionary *   _requiredFilters;      // The required filters
    OSDictionary *   _activeFilters;        // Currently active filters    
    bool             _controllerLostPower;  // true if controller is unusable

    struct ExpansionData { };
    /*! @var reserved
        Reserved for future use.  (Internal use only)  */
    ExpansionData *  _reserved;


    IOReturn enableController(IONetworkController * ctr);
    IOReturn setupMulticastFilter(IONetworkController * ctr);

    UInt32 getFilters(const OSDictionary * dict,
                      const OSSymbol *     group);

    bool setFilters(OSDictionary *   dict,
                    const OSSymbol * group,
                    UInt32           filters);
                                     
    IOReturn disableFilter(IONetworkController * ctr,
                           const OSSymbol *      group,
                           UInt32                filter,
                           IOOptionBits          options = 0);

    IOReturn enableFilter(IONetworkController * ctr,
                          const OSSymbol *      group,
                          UInt32                filter,
                          IOOptionBits          options = 0);

    int syncSIOCSIFFLAGS(IONetworkController * ctr);
    int syncSIOCSIFADDR(IONetworkController * ctr);
    int syncSIOCADDMULTI(IONetworkController * ctr);
    int syncSIOCDELMULTI(IONetworkController * ctr);

    static int performGatedCommand(void *, void *, void *, void *, void *);

public:

/*! @function init
    @abstract Initialize an IOEthernetInterface instance.
    @discussion Instance variables are initialized, and an arpcom
    structure is allocated.
    @param controller A network controller object that will service
    the interface object being initialized.
    @result true on success, false otherwise. */

    virtual bool init( IONetworkController * controller );

/*! @function getNamePrefix
    @abstract Return a string containing the prefix to use when
    creating a BSD name for this interface.
    @discussion The BSD name for each interface object is created by
    concatenating a string returned by this method, with an unique
    unit number assigned by IONetworkStack.
    @result A pointer to a constant C string "en". Therefore, Ethernet
    interfaces will be registered with BSD as en0, en1, etc. */

    virtual const char * getNamePrefix() const;

protected:

/*! @function free
    @abstract Free the IOEthernetInterface instance.
    @discussion The memory allocated for the arpcom structure is released,
    followed by a call to super::free(). */

    virtual void free();

/*! @function performCommand
    @abstract Handle an ioctl command sent to the Ethernet interface.
    @discussion This method handles socket ioctl commands sent to the Ethernet
    interface from DLIL. Commands recognized and processed by this method are
    SIOCSIFADDR, SIOCSIFFLAGS, SIOCADDMULTI, and SIOCDELMULTI. Other commands
    are passed to the superclass.
    @param controller The controller object.
    @param cmd  The ioctl command code.
    @param arg0 Command argument 0. Generally a pointer to an ifnet structure
        associated with the interface.
    @param arg1 Command argument 1.
    @result A BSD return value defined in bsd/sys/errno.h. */

    virtual SInt32 performCommand(IONetworkController * controller,
                                  UInt32                cmd,
                                  void *                arg0,
                                  void *                arg1);

/*! @function controllerDidOpen
    @abstract A notification that the interface has opened the network
    controller.
    @discussion This method will be called by IONetworkInterface after a
    network controller has accepted an open from this interface object.
    IOEthernetInterface will first call the implementation in its
    superclass, then inspect the controller through properties published
    in the registry. This method is called with the arbitration lock held.
    @param controller The controller object that was opened.
    @result true on success, false otherwise. Returning false will
    cause the controller to be closed, and any pending client opens to be
    rejected. */

    virtual bool controllerDidOpen(IONetworkController * controller);

/*! @function controllerWillClose
    @abstract A notification that the interface will close the network
    controller.
    @discussion This method will simply call super to propagate the method
    call. This method is called with the arbitration lock held.
    @param controller The controller that is about to be closed. */

    virtual void controllerWillClose(IONetworkController * controller);

/*! @function initIfnet
    @abstract Initialize the ifnet structure given.
    @discussion IOEthernetInterface will initialize this structure in a manner
    that is appropriate for Ethernet interfaces, then call super::initIfnet()
    to allow the superclass to perform generic interface initialization.
    @param ifp Pointer to an ifnet structure obtained earlier through
               the getIfnet() method call.
    @result true on success, false otherwise. */

    virtual bool initIfnet(struct ifnet * ifp);

/*! @function getIfnet
    @abstract Get the ifnet structure allocated by the interface object.
    @discussion This method returns a pointer to an ifnet structure
    that was allocated by a concrete subclass of IONetworkInterface.
    IOEthernetInterface will allocate an arpcom structure during init(),
    and returns a pointer to that structure when this method is called.
    @result Pointer to an ifnet structure. */

    virtual struct ifnet * getIfnet() const;

/*! @function controllerWillChangePowerState
    @abstract Handle a notification that the network controller which is
    servicing this interface object is about to transition to a new power state.
    @discussion If the controller is about to transition to an unusable state,
    and it is currently enabled, then the disable() method on the controller is
    called.
    @param controller The network controller object.
    @param flags Flags that describe the capability of the controller in the new
    power state.
    @param stateNumber An index to a state in the network controller's
    power state array that the controller is switching to.
    @param policyMaker A reference to the network controller's policy-maker,
    and is also the originator of this notification.
    @result The return value is always kIOReturnSuccess. */

    virtual IOReturn controllerWillChangePowerState(
                               IONetworkController * controller,
                               IOPMPowerFlags        flags,
                               UInt32                stateNumber,
                               IOService *           policyMaker);

/*! @function controllerDidChangePowerState
    @abstract Handle a notification that the network controller which is servicing
    this interface object has transitioned to a new power state.
    @discussion If the controller did transition to a usable state, and it was
    previously disabled due to a previous power change, then it is re-enabled.
    @param controller The network controller object.
    @param flags Flags that describe the capability of the controller in the new
    power state.
    @param stateNumber An index to a state in the network controller's
    power state array that the controller has switched to.
    @param policyMaker A reference to the network controller's policy-maker,
    and is also the originator of this notification.
    @result The return value is always kIOReturnSuccess. */

    virtual IOReturn controllerDidChangePowerState( 
                               IONetworkController * controller,
                               IOPMPowerFlags        flags,
                               UInt32                stateNumber,
                               IOService *           policyMaker);


    // Virtual function padding
    OSMetaClassDeclareReservedUnused( IOEthernetInterface,  0);
    OSMetaClassDeclareReservedUnused( IOEthernetInterface,  1);
    OSMetaClassDeclareReservedUnused( IOEthernetInterface,  2);
    OSMetaClassDeclareReservedUnused( IOEthernetInterface,  3);
    OSMetaClassDeclareReservedUnused( IOEthernetInterface,  4);
    OSMetaClassDeclareReservedUnused( IOEthernetInterface,  5);
    OSMetaClassDeclareReservedUnused( IOEthernetInterface,  6);
    OSMetaClassDeclareReservedUnused( IOEthernetInterface,  7);
    OSMetaClassDeclareReservedUnused( IOEthernetInterface,  8);
    OSMetaClassDeclareReservedUnused( IOEthernetInterface,  9);
    OSMetaClassDeclareReservedUnused( IOEthernetInterface, 10);
    OSMetaClassDeclareReservedUnused( IOEthernetInterface, 11);
    OSMetaClassDeclareReservedUnused( IOEthernetInterface, 12);
    OSMetaClassDeclareReservedUnused( IOEthernetInterface, 13);
    OSMetaClassDeclareReservedUnused( IOEthernetInterface, 14);
    OSMetaClassDeclareReservedUnused( IOEthernetInterface, 15);
};

#endif /* defined(KERNEL) && defined(__cplusplus) */

#endif /* !_IOETHERNETINTERFACE_H */
