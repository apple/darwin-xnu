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
 * IONetworkInterface.h
 *
 * HISTORY
 * 8-Jan-1999       Joe Liu (jliu) created.
 */

#ifndef _IONETWORKINTERFACE_H
#define _IONETWORKINTERFACE_H

/*! @defined kIONetworkInterfaceClass
    @abstract kIONetworkInterfaceClass is the name of the
        IONetworkInterface class. */

#define kIONetworkInterfaceClass     "IONetworkInterface"

/*! @defined kIONetworkData
    @abstract kIONetworkData is a property of IONetworkInterface
        objects. It has an OSDictionary value.
    @discussion The kIONetworkData property is a container for the
        set of IONetworkData objects managed by the interface.
        Each entry in the dictionary is a key/value pair consisting of
        the network data name, and an OSDictionary describing the
        contents of the network data. */

#define kIONetworkData            "IONetworkData"

/*! @defined kIOInterfaceType
    @abstract kIOInterfaceType is a property of IONetworkInterface objects.
        It has an OSNumber value.
    @discussion The kIOInterfaceType property specifies the type of
        network interface that this interface represents. The type
        constants are defined in bsd/net/if_types.h. */

#define kIOInterfaceType          "IOInterfaceType"

/*! @defined kIOMaxTransferUnit
    @abstract kIOMaxTransferUnit is a property of IONetworkInterface objects.
        It has an OSNumber value.
    @discussion The kIOMaxTransferUnit property specifies the maximum
        transfer unit for the interface in bytes. */

#define kIOMaxTransferUnit        "IOMaxTransferUnit"

/*! @defined kIOMediaAddressLength
    @abstract kIOMediaAddressLength is a property of IONetworkInterface objects.
        It has an OSNumber value.
    @discussion The kIOMediaAddressLength property specifies the size of the
        media address in bytes. */

#define kIOMediaAddressLength     "IOMediaAddressLength"

/*! @defined kIOMediaHeaderLength
    @abstract kIOMediaHeaderLength is a property of IONetworkInterface objects.
        It has an OSNumber value.
    @discussion The kIOMediaHeaderLength property specifies the size of the
        media header in bytes. */

#define kIOMediaHeaderLength      "IOMediaHeaderLength"

/*! @defined kIOInterfaceFlags
    @abstract kIOInterfaceFlags is a property of IONetworkInterface objects.
        It has an OSNumber value.
    @discussion The kIOInterfaceFlags property specifies the current value
        of the interface flags. The flag constants are defined in
        bsd/net/if.h. */

#define kIOInterfaceFlags         "IOInterfaceFlags"

/*! @defined kIOInterfaceExtraFlags
    @abstract kIOInterfaceExtraFlags is a property of IONetworkInterface
        objects. It has an OSNumber value.
    @discussion The kIOInterfaceExtraFlags property specifies the current
        value of the interface extra flags. The extra flag constants are
        defined in bsd/net/if.h. */

#define kIOInterfaceExtraFlags    "IOInterfaceExtraFlags"

/*! @defined kIOInterfaceUnit
    @abstract kIOInterfaceUnit is a property of IONetworkInterface
        objects. It has an OSNumber value.
    @discussion The kIOInterfaceUnit property describes the unit number
        assigned to the interface object. */

#define kIOInterfaceUnit          "IOInterfaceUnit"

/*! @defined kIOInterfaceState
    @abstract kIOInterfaceState is a property of IONetworkInterface
        objects. It has an OSNumber value.
    @discussion The kIOInterfaceState property describes the current state
        of the interface object. This property is not exported to BSD via
        the ifnet structure. */

#define kIOInterfaceState         "IOInterfaceState"

/*! @defined kIOInterfaceNamePrefix
    @abstract kIOInterfaceNamePrefix is a property of IONetworkInterface
        objects. It has an OSString value.
    @discussion The kIOInterfaceNamePrefix property describes the string
        prefix for the BSD name assigned to the interface. */

#define kIOInterfaceNamePrefix    "IOInterfaceNamePrefix"

/*! @defined kIOPrimaryInterface
    @abstract kIOPrimaryInterface is a property of IONetworkInterface
        objects. It has an OSBoolean value.
    @discussion The kIOInterfaceNamePrefix property describes whether the
        interface is the primary or the built-in network interface. */

#define kIOPrimaryInterface       "IOPrimaryInterface"

/*! @enum Interface state flags.
    @discussion An enumeration of the constants that are used to encode the
        state of the interface object.
    @constant kIONetworkInterfaceRegisteredState The interface object has
        registered with the data link layer.
    @constant kIONetworkInterfaceOpenedState One or more clients have an
        open on the interface object.
    @constant kIONetworkInterfaceDisabledState The interface is temporarily
        unable to service its clients. This will occur when the network
        controller that is servicing the interface has entered a low power
        state that renders it unusable. */

enum {
    kIONetworkInterfaceRegisteredState  = 0x1,
    kIONetworkInterfaceOpenedState      = 0x2,
    kIONetworkInterfaceDisabledState    = 0x4
};

/*
 * Kernel
 */
#if defined(KERNEL) && defined(__cplusplus)

#include <IOKit/IOService.h>
#include <IOKit/network/IONetworkData.h>
#include <IOKit/network/IONetworkStats.h>
#include <IOKit/network/IONetworkMedium.h>

struct mbuf;                // forward declarations.
struct ifnet;
class  IONetworkController;
class  IONetworkStack;
class  IOCommandGate;

/*! @typedef IOOutputAction
    @discussion Prototype for an output packet handler that will process
    all outbound packets sent to the interface from the data link layer.
    An output handler is registered with the interface by calling
    registerOutputHandler().
    @param m A packet mbuf.
    @param param A parameter for the output request. */

typedef UInt32 (OSObject::*IOOutputAction)(struct mbuf * m, void * param);

/*! @typedef BPF_FUNC
    @discussion Prototype for the BPF tap handler. This will disappear
    when the correct DLIL header file is included. */

typedef int (*BPF_FUNC)(struct ifnet *, struct mbuf *);

// Network event types recognized by inputEvent().
//
enum {
    /* DLIL defined event, argument must be a pointer to a
       kern_event_msg structure. */
    kIONetworkEventTypeDLIL      = 0xff000001,

    /* Link up event, no argument */
    kIONetworkEventTypeLinkUp    = 0xff000002,

    /* Link down event, no argument */
    kIONetworkEventTypeLinkDown  = 0xff000003
};

/*! @class IONetworkInterface : public IOService
    @abstract An IONetworkInterface object manages the connection between
    an IONetworkController and the data link interface layer (DLIL).
    All interactions between the controller and DLIL must go through an
    interface object. Any data structures that are required by DLIL for a
    particular interface type shall be allocated and mantained by the
    interface object. IONetworkInterface is an abstract class that must be
    extended by a concrete subclass to specialize for a particular network
    type.

    Although most drivers will allocate a single interface object.
    It is possible for multiple interfaces to be attached to a single
    controller. This controller driver will be responsible for arbitrating
    access among its multiple interface clients.
    
    IONetworkInterface also maintains a dictionary of IONetworkData
    objects containing statistics structures. Controller drivers can
    ask for a particular data object by name and update the
    statistics counters within directly. This dictionary is added to
    the interface's property table and is visible outside of the kernel. */

class IONetworkInterface : public IOService
{
    OSDeclareAbstractStructors( IONetworkInterface )

    friend class IONetworkStack;

private:
    IONetworkController *    _controller;
    struct ifnet *           _ifp;
    IORecursiveLock *        _ifLock;
    OSSet *                  _clientSet;
    OSNumber *               _stateBits;
    BPF_FUNC                 _inputFilterFunc;
    BPF_FUNC                 _outputFilterFunc;
    OSObject *               _outTarget;
    IOOutputAction           _outAction;
	UInt32                   _clientVar[4];
    OSDictionary *           _dataDict;
    struct mbuf *            _inputQHead;
    struct mbuf *            _inputQTail;
    UInt32                   _inputQCount;

    struct ExpansionData { };
    /*! @var reserved
        Reserved for future use.  (Internal use only)  */
    ExpansionData *          _reserved;

    bool _syncNetworkDataDict();
    bool _setInterfaceProperty(UInt32   value,
                               UInt32   mask,
                               UInt32   bytes,
                               void *   addr,
                               char *   name);

    SInt32 syncSIOCSIFMEDIA(IONetworkController * ctlr, struct ifreq * ifr);
    SInt32 syncSIOCGIFMEDIA(IONetworkController * ctlr, struct ifreq * ifr);
    SInt32 syncSIOCSIFMTU(IONetworkController * ctlr, struct ifreq * ifr);

    static int  performGatedCommand(void *, void *, void *, void *, void *);
    static int  ioctl_shim(struct ifnet * ifp, u_long cmd, caddr_t data);
    static int  set_bpf_tap_shim(struct ifnet * ifp, int mode, BPF_FUNC func);
    static int  free_shim(struct ifnet * ifp);
    static int  output_shim(struct ifnet * ifp, struct mbuf *m);
    static void null_shim(struct ifnet * ifp);

    static IOReturn sControllerWillChangePowerState( IONetworkInterface *,
                                                     void *, void *,
                                                     void *, void *);

    static IOReturn sControllerDidChangePowerState( IONetworkInterface *,
                                                    void *, void *,
                                                    void *, void *);

public:

/*! @function isPrimaryInterface
    @abstract Query whether the interface object provided represents
    the "primary" network interface for the system.
    @result true if the interface provided is the primary inteface,
    false otherwise. */

    virtual bool isPrimaryInterface() const;

/*! @function init
    @abstract Initialize an IONetworkInterface object.
    @discussion Initialize instance variables, and allocate resources.
    Call getIfnet() to get the ifnet structure allocated by a concrete
    subclass, then call initIfnet() to initialize this ifnet structure.
    @param controller A network controller object that will service
    the interface object being initialized.
    @result true on success, false otherwise. */

    virtual bool init( IONetworkController * controller );

/*! @function isRegistered
    @abstract Returns true if the interface has been registered with
    the data link layer.
    @discussion Once registered, the interface will be assigned a
    BSD name (such as en0), and a kIOBSDNameKey property is added to the
    property table containing this name. Calling this method performs
    the same function as checking for the kIONetworkInterfaceRegisteredState
    bit in the value returned by getInterfaceState().
    @result True if interface is registered. False if the data link layer
    has no references to this network interface, which implies that either the
    interface has yet to attach to the data link layer, or the interface has
    been detached. */

    virtual bool isRegistered() const;

/*! @function getInterfaceState
    @abstract Report the current state of the interface object by returning
    the interface state flags.
    @result Returns the interface state flags. */

    virtual UInt32 getInterfaceState() const;

/*! @function matchPropertyTable
    @abstract Override the implementation in IOService in order to
    implement family specific matching.
    @discussion When the gIOLocationMatchKey property is present in the
    dictionary provided, then fail the match unless the kIOBSDNameKey property
    is found. This is to prevent a premature match when hunting for a root
    device for BSD. The presence of the kIOBSDNameKey property indicates that
    the interface has registered with BSD, and is a valid candidate for
    matching against the gIOLocationMatchKey property. If the
    gIOLocationMatchKey property is absent, then this method will always
    return true.
    @param table The dictionary of properties to match against.
    @param score Pointer to the current driver's probe score, not used.
    @result Returns true for a positive match, false otherwise. */

    virtual bool matchPropertyTable( OSDictionary *	table,
                                     SInt32       *	score );

/*! @function getController
    @abstract Return the provider, an IONetworkController object, that
    is servicing this interface object.
    @discussion This is the same controller object that was supplied as
    an argument to the init() method.
    @result The IONetworkController object that is providing service to
    this interface object. */

    virtual IONetworkController * getController() const;

/*! @function inputPacket
    @abstract Called by the network controller to submit a single packet
    received from the network to the data link layer.
    @discussion The packet received by this method may be added to an input
    queue on the interface object, which the controller can use to postpone
    the packet handoff to the upper layers, until all received packets have
    been transferred to the input queue. A subsequent call to flushInputQueue(),
    will transfer the entire contents of the queue to the data link layer,
    by making a single call to dlil_input(). Other methods that can be used
    to manage the input queue are flushInputQueue() and clearInputQueue().
    This input queue is not protected by a lock. Access to the queue by the
    controller must be serialized, otherwise its use must be avoided.
    @param m The mbuf containing the received packet.
    @param length Specify the size of the received packet in the mbuf.
           The mbuf length fields are updated with this value. If zero,
           then the mbuf length fields are not updated.
    @param options Options defined by inputPacket() that the caller
           can use to specify this method call.
    @param param A parameter provided by the caller. Not used by
           IONetworkInterface.
    @result The number of packets that were submitted to the data link layer,
            or 0 if the packet was queued. */

    virtual UInt32 inputPacket(struct mbuf * m,
                               UInt32        length  = 0,
                               IOOptionBits  options = 0,
                               void *        param   = 0);

/*! @enum Options for the inputPacket() method.
    @discussion An enumeration of the option bits that can be specified
    in the options argument when calling inputPacket().
    @constant kInputOptionQueuePacket Keep the packet provided in the
    input packet queue. No packets are sent to the data link layers,
    and the caller's thread will not venture outside the interface
    object. Calls to inputPacket() must be serialized. */

    enum {
        kInputOptionQueuePacket = 0x1
    };

/*! @function flushInputQueue
    @abstract Send all packets held in the input queue to the data
    link layer.
    @discussion Remove all packets from the input queue and
    send them to the data link layer by calling dlil_input(). This
    method should be used in connection with the inputPacket() method,
    to flush the input queue after inputPacket() was used to queue up
    some number of received packets. See inputPacket() and clearInputQueue().
    @result The number of packets that were submitted to the data link layer.
            May be zero if the queue was empty. */

    virtual UInt32 flushInputQueue();

/*! @function clearInputQueue
    @abstract Remove and discard all packets in the input queue.
    @discussion Remove all packets from the input queue and
    release them back to the free mbuf pool. Also see flushInputQueue().
    @result The number of packets freed. */

    virtual UInt32 clearInputQueue();

/*! @function inputEvent
    @abstract Send an event to the data link layer.
    @discussion This method can be used by the network controller to
    send an event to the data link layer.
    @param type A constant describing the event type.
    @param data Data associated with the event.
    @result true if the event was delivered, false if the event type
    specified is invalid, or if the event delivery was unsuccesful. */

    virtual bool inputEvent(UInt32 type, void * data);

/*! @function registerOutputHandler
    @abstract Register a target/action to handle output packets.
    @discussion The interface object will forward all output packets,
    received from the data link layer, to the output handler registered
    through this method. The default target and action are set by the init()
    method to the controller, and the handler returned by the controller's
    getOutputHandler() method. Once the interface becomes registered with
    the data link layer, this method will return false and will reject any
    further changes.
    @param target Target object that implements the output handler.
    @param action The function that will process output packets.
    @result true if the target/action provided was accepted,
    false otherwise. */

    virtual bool registerOutputHandler(OSObject *      target,
                                       IOOutputAction  action);

/*! @function getNamePrefix
    @abstract Return a string containing the prefix to use when
    creating a BSD name for this interface.
    @discussion The BSD name for each interface object is generated by
    concatenating a string returned by this method, with an unique
    unit number assigned by IONetworkStack.
    A concrete subclass of IONetworkInterface must implement this method
    and enforce a consistent name for all of its instances.
    @result A pointer to a constant C string. */

    virtual const char * getNamePrefix() const = 0;

/*! @function getInterfaceType
    @abstract Get the interface type.
    @discussion Return the value in the if_type field in the ifnet structure.
    @result A constant defined in bsd/net/if_types.h header file
    that describes the interface type. */

    virtual UInt8  getInterfaceType() const;

/*! @function getMaxTransferUnit
    @abstract Get the maximum transfer unit for this interface.
    @discussion Return the value in the if_mtu field in the ifnet structure.
    @result The interface MTU size in bytes. */

    virtual UInt32 getMaxTransferUnit() const;

/*! @function getFlags
    @abstract Get the value of the interface flags.
    @discussion Return the value in the if_flags field in the ifnet structure.
    @result The value of the interface flags. */

    virtual UInt16 getFlags() const;

/*! @function getExtraFlags
    @abstract Get the value of the interface extra flags.
    @discussion Return the value in the if_eflags field in the ifnet structure.
    @result The value of the interface extra flags. */

    virtual UInt32 getExtraFlags() const;

/*! @function getMediaAddressLength
    @abstract Get the size of the media (MAC-layer) address.
    @discussion Return the value in the if_addrlen field in the ifnet structure.
    @result The size of the media address in bytes. */

    virtual UInt8  getMediaAddressLength() const;

/*! @function getMediaHeaderLength
    @abstract Get the size of the media header.
    @discussion Return the value in the if_hdrlen field in the ifnet structure.
    @result The size of the media header in bytes. */

    virtual UInt8  getMediaHeaderLength() const;

/*! @function getUnitNumber
    @abstract Get the unit number assigned to this interface object.
    @discussion Return the value in the if_unit field in the ifnet structure.
    @result The assigned interface unit number. */

    virtual UInt16 getUnitNumber() const;

/*! @function addNetworkData
    @abstract Add an IONetworkData object to a dictionary managed by
    the interface.
    @param aData An IONetworkData object to be added to a dictionary
    managed by the interface. This object is retained by the dictionary.
    @result true if the operation was successful, false otherwise. */

    virtual bool addNetworkData(IONetworkData * aData);

/*! @function removeNetworkData
    @abstract Remove an entry from the IONetworkData dictionary
    managed by the interface. The removed object is released.
    @param aKey A unique OSSymbol identifying the IONetworkData object
           to be removed from the dictionary.
    @result true if the operation was successful, false otherwise. */

    virtual bool removeNetworkData(const OSSymbol * aKey);

/*! @function removeNetworkData
    @abstract Remove an entry from the IONetworkData dictionary
    managed by the interface. The removed object is released.
    @param aKey A unique string identifying the IONetworkData object
           to be removed from the dictionary.
    @result true if the operation was successful, false otherwise. */

    virtual bool removeNetworkData(const char * aKey);

/*! @function getNetworkData
    @abstract Get an IONetworkData object from the interface that is
    associated with the given key.
    @param aKey The unique string identifying the IONetworkData object to be
    returned to caller.
    @result Returns a reference to the matching IONetworkData object,
    or 0 if no match was found. */

    virtual IONetworkData * getNetworkData(const char * aKey) const;

/*! @function getNetworkData
    @abstract Get an IONetworkData object from the interface that is
    associated with the given key.
    @param aKey The unique OSSymbol identifying the IONetworkData object to be
    returned to caller.
    @result Returns a reference to the matching IONetworkData object,
    or 0 if no match was found. */

    virtual IONetworkData * getNetworkData(const OSSymbol * aKey) const;

    // FIXME - Compatibility methods (to be removed)
    inline IONetworkData * getParameter(const char * aKey) const
    { return getNetworkData(aKey); }

    inline bool setExtendedFlags(UInt32 flags, UInt32 clear = 0)
    { return true; }

protected:

/*! @function setInterfaceType
    @abstract Set the interface type.
    @discussion Both the if_type field in the ifnet structure, and the
    kIOInterfaceType property are updated with the value provided.
    @param type A constant defined in bsd/net/if_types.h header file
    that describes the interface type.
    @result true if the update was successful, false otherwise. */

    virtual bool setInterfaceType(UInt8 type);

/*! @function setMaxTransferUnit
    @abstract Set the maximum transfer unit for this interface.
    @discussion Both the if_mtu field in the ifnet structure, and the
    kIOMaxTransferUnit property are updated with the value provided.
    @param mtu The interface MTU size in bytes.
    @result true if the update was successful, false otherwise. */

    virtual bool setMaxTransferUnit(UInt32 mtu);

/*! @function setFlags
    @abstract Perform a read-modify-write operation on the current
    interface flags value.
    @discussion See bsd/net/if.h header file for the definition of the
    flag constants. Both the if_flags field in the ifnet structure, and
    the kIOInterfaceFlags property are updated with the value provided.
    @param flags The bits that should be set.
    @param clear The bits that should be cleared. If 0, then non
    of the flags are cleared and the result is formed by OR'ing the
    original flags value with the new flags.
    @result true if the update was successful, false otherwise. */

    virtual bool setFlags(UInt16 flags, UInt16 clear = 0);

/*! @function setExtraFlags
    @abstract Perform a read-modify-write operation on the current
    interface extra flags value.
    @discussion See bsd/net/if.h header file for the definition of the
    extra flag constants. Both the if_eflags field in the ifnet structure,
    and the kIOInterfaceExtraFlags property are updated with the value
    provided.
    @param flags The bits that should be set.
    @param flags The bits that should be set.
    @param clear The bits that should be cleared. If 0, then non
    of the flags are cleared and the result is formed by OR'ing the
    original flags with the new flags.
    @result true if the update was successful, false otherwise. */

    virtual bool setExtraFlags(UInt32 flags, UInt32 clear = 0);

/*! @function setMediaAddressLength
    @abstract Set the size of the media (MAC-layer) address.
    @discussion Both the if_addrlen field in the ifnet structure, and the
    kIOMediaAddressLength property are updated with the value provided.
    @param length The size of the media address in bytes.
    @result true if the update was successful, false otherwise. */

    virtual bool setMediaAddressLength(UInt8 length);

/*! @function setMediaHeaderLength
    @abstract Set the size of the media header.
    @discussion Both the if_hdrlen field in the ifnet structure, and the
    kIOMediaHeaderLength property are updated with the value provided.
    @param length The size of the media header in bytes.
    @result true if the update was successful, false otherwise. */

    virtual bool setMediaHeaderLength(UInt8 length);

/*! @function setUnitNumber
    @abstract Assign an unique unit number to this interface.
    @discussion This method is called by IONetworkStack before the
    interface is registered with the data link layer, to assign an
    unique unit number to the interface object. Both the if_unit field
    in the ifnet structure, and the kIOInterfaceUnit property are updated
    with the value provided.
    @param unit The unit number assigned to this interface object.
    @result true if the update was successful, false otherwise. */

    virtual bool setUnitNumber(UInt16 unit);

/*! @function free
    @abstract Free the IONetworkInterface object.
    @discussion Resource allocated by init() are released, and
    clearInputQueue() is called to ensure that the input queue is empty. */

    virtual void free();

/*! @function handleOpen
    @abstract Handle a client open on the interface.
    @discussion This method is called by IOService::open() with the
    arbitration lock held, and must return true to accept the client open.
    This method will in turn call handleClientOpen() to qualify the client
    requesting the open. Since the controller is opened by the interface
    in a lazy fashion, the interface may also perform an open on the
    controller before this method returns. If the controller was opened,
    then controllerDidOpen() is called to notify interested subclasses.
    Subclasses should not override this method.
    @param client The client object that requested the open.
    @param options Options passed to IOService::open().
    @param argument Argument passed to IOService::open().
    @result true to accept the client open, false otherwise. */

    virtual bool handleOpen(IOService *  client,
                            IOOptionBits options,
                            void *       argument);

/*! @function handleClose
    @abstract Handle a client close on the interface.
    @discussion This method is called by IOService::close() with the
    arbitration lock held. This method will in turn call handleClientClose()
    to notify interested subclasses about the client close. If this represents
    the last close, then the interface will also close the controller before
    this method returns. The controllerWillClose() method will be called before
    closing the controller. Subclasses should not override this method.
    @param client The client object that requested the close.
    @param options Options passed to IOService::close(). */

    virtual void handleClose(IOService * client, IOOptionBits options);

/*! @function handleIsOpen
    @abstract Query whether a client has an open on the interface.
    @discussion This method is always called by IOService with the
    arbitration lock held. Subclasses should not override this method.
    @result true if the specified client, or any client if none (0) is
    specified, presently has an open on this object. */

    virtual bool handleIsOpen(const IOService * client) const;

/*! @function lock
    @abstract Take the network interface lock.
    @discussion Take the recursive lock that protects the interface
    state. All updates to the interface state and to the ifnet structure
    must be performed while holding this lock. This call must be balanced
    by a subsequent call to unlock(). */

    virtual void lock();

/*! @function unlock
    @abstract Release the network interface lock.
    @discussion Release the recursive lock that protects the interface
    state to balance a previous lock() call. */

    virtual void unlock();

/*! @function controllerDidOpen
    @abstract A notification that the interface has opened the network
    controller.
    @discussion Called by handleOpen() to notify subclasses that the
    controller has been opened. The open on the controller is done when
    the interface receives the initial open request from a client.
    Subclasses can override this method and inspect the controller before
    allowing the client open. The implementation in the subclass must first
    call the method in super and check the return value. This method is
    called with our arbitration lock held, hence issuing I/O to the
    controller must be avoided to eliminate the possibility of a
    deadlock.
    @param controller The controller that was opened.
    @result Must return true in order for handleOpen() to accept 
    the client open. If the return is false, then the controller will be
    closed and the client open will be refused. */

    virtual bool controllerDidOpen(IONetworkController * controller);

/*! @function controllerWillClose
    @abstract A notification that the interface will close the network
    controller.
    @discussion Called by handleClose() after receiving a close from the
    last client, and just before the controller is closed. Subclasses
    can override this method to perform any cleanup action before the 
    controller is closed. This method is called with our arbitration lock
    held, hence issuing I/O to the controller must be avoided to eliminate
    the possibility of a deadlock.
    @param controller The controller that is about to be closed. */

    virtual void controllerWillClose(IONetworkController * controller);

/*! @function performCommand
    @abstract Handle an ioctl command sent to the network interface.
    @discussion This method handles socket ioctl commands sent to the
    network interface from DLIL.
    IONetworkInterface handles commands that are common for all network
    interface types. A subclass of IONetworkInterface may override this
    method to override the command handling in IONetworkInterface, or
    to extend the command processing to handle additional commands,
    and then call super for any commands not handled in the subclass.
    The ioctl commands handled by IONetworkInterface are
        SIOCGIFMTU (Get interface MTU size),
        SIOCSIFMTU (Set interface MTU size),
        SIOCSIFMEDIA (Set media), and
        SIOCGIFMEDIA (Get media and link status).
    @param controller The controller object.
    @param cmd The ioctl command code.
    @param arg0 Command argument 0. Generally a pointer to an ifnet structure
        associated with the interface.
    @param arg1 Command argument 1.
    @result A BSD return value defined in bsd/sys/errno.h. */

    virtual SInt32 performCommand(IONetworkController * controller,
                                  UInt32                cmd,
                                  void *                arg0,
                                  void *                arg1);

/*! @function getIfnet
    @abstract Get the ifnet structure allocated by the interface object.
    @discussion Request an interface to reveal its ifnet structure.
    A concrete subclass must allocate an ifnet structure when the
    object is initialized, and return a pointer to the ifnet structure
    when this method is called.
    @result Pointer to an ifnet structure allocated by a concrete
    interface subclass. */

    virtual struct ifnet * getIfnet() const = 0;

/*! @function initIfnet
    @abstract Initialize the ifnet structure given.
    @discussion A concrete subclass must override this method and initialize
    the ifnet structure given. The implementation in the subclass must call
    super before it returns, to allow IONetworkInterface to complete the
    initialization, and to insert the BSD shim functions implemented in
    IONetworkInterface to the appropriate function pointer fields in the
    ifnet structure. IONetworkInterface will call this method during its
    init() method. Subclasses are encouraged to use the ifnet accessor
    methods to update the ifnet structure when possible, since this will
    ensure that properties in the registry will also be updated to reflect
    any changes made.
    @param ifp Pointer to an ifnet structure obtained earlier through
               the getIfnet() method call.
    @result true on success, false otherwise. */

    virtual bool initIfnet(struct ifnet * ifp);

/*! @function handleClientOpen
    @abstract Handle a client open on the interface.
    @discussion Called by handleOpen() to handle an open from a client object.
    Unlike handleOpen(), subclasses may override this method to catch an open
    request from a client. This method is called with the arbitration lock held.
    @param client The client object requesting the open.
    @param options Options passed to IONetworkInterface::handleOpen().
    @param argument Argument passed to IONetworkInterface::handleOpen().
    @result true to accept the client open, false to refuse it. */

    virtual bool handleClientOpen(IOService *  client,
                                  IOOptionBits options,
                                  void *       argument);

/*! @function handleClientClose
    @abstract Handle a client close on the interface.
    @discussion Called by handleClose() to handle a close from a client object.
    Unlike handleClose(), subclasses may override this method to catch a close
    reuqest from a client. This method is called with the arbitration lock held.
    @param client The client object requesting the close.
    @param options Options passed to IONetworkInterface::handleClose(). */

    virtual void handleClientClose(IOService *  client,
                                   IOOptionBits options);

/*! @function newUserClient
    @abstract A request to create a connection for a non kernel client.
    @discussion Create a new IOUserClient to service a connection to a
    non kernel client.
    @param owningTask The mach task requesting the connection.
    @param security_id A token representing the access level for the task.
    @param type A constant specifying the type of connection to be created.
    An IONetworkUserClient object is created if the type specified is
    kIONetworkUserClientTypeID.
    @param handler The IOUserClient object returned.
    @result kIOReturnSuccess if an IONetworkUserClient was created,
    kIOReturnNoMemory for a memory allocation error, or
    kIOReturnBadArgument if the type specified is unknown. */

    virtual IOReturn newUserClient(task_t           owningTask,
                                   void *           security_id,
                                   UInt32           type,
                                   IOUserClient **  handler);

/*! @function setInterfaceState
    @abstract Update the interface object state flags.
    @discussion The kIOInterfaceState property is updated with the value
    provided.
    @param flags The bits that should be set.
    @param clear The bits that should be cleared.
    @result The resulting interface state flags following any changes
    made by this method. */

    virtual UInt32 setInterfaceState( UInt32 set, UInt32 clear = 0 );

/*! @function powerStateWillChangeTo
    @abstract Handle a notification that the network controller which is servicing
    this interface object is about to transition to a new power state.
    @discussion This method will call the controllerWillChangePowerState() method
    on the controller's work loop context to prepare for the power state change.
    Subclasses should not override this method.
    @param flags Flags that describe the capability of the controller in the new
    power state.
    @param stateNumber An index to a state in the network controller's
    power state array that the controller is switching to.
    @param policyMaker A reference to the network controller's policy-maker,
    and is also the originator of this notification.
    @result The return will always be IOPMAckImplied to indicate that the
    preparation for the power change has already completed when this method
    returns. */

    virtual IOReturn powerStateWillChangeTo( IOPMPowerFlags  flags,
                                             UInt32          stateNumber,
                                             IOService *     policyMaker );

/*! @function powerStateDidChangeTo
    @abstract Handle a notification that the network controller which is servicing
    this interface object has transitioned to a new power state.
    @discussion This method will call the controllerDidChangePowerState() method
    on the controller's work loop context to prepare for the power state change.
    Subclasses should not override this method.
    @param flags Flags that describe the capability of the controller in the new
    power state.
    @param stateNumber An index to a state in the network controller's
    power state array that the controller has switched to.
    @param policyMaker A reference to the network controller's policy-maker,
    and is also the originator of this notification.
    @result The return will always be IOPMAckImplied to indicate that the
    preparation for the power change has already completed when this method
    returns. */

    virtual IOReturn powerStateDidChangeTo( IOPMPowerFlags  flags,
                                            UInt32          stateNumber,
                                            IOService *     policyMaker );

/*! @function controllerWillChangePowerState
    @abstract Handle a notification that the network controller which is servicing
    this interface object is about to transition to a new power state.
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
    OSMetaClassDeclareReservedUnused( IONetworkInterface,  0);
    OSMetaClassDeclareReservedUnused( IONetworkInterface,  1);
    OSMetaClassDeclareReservedUnused( IONetworkInterface,  2);
    OSMetaClassDeclareReservedUnused( IONetworkInterface,  3);
    OSMetaClassDeclareReservedUnused( IONetworkInterface,  4);
    OSMetaClassDeclareReservedUnused( IONetworkInterface,  5);
    OSMetaClassDeclareReservedUnused( IONetworkInterface,  6);
    OSMetaClassDeclareReservedUnused( IONetworkInterface,  7);
    OSMetaClassDeclareReservedUnused( IONetworkInterface,  8);
    OSMetaClassDeclareReservedUnused( IONetworkInterface,  9);
    OSMetaClassDeclareReservedUnused( IONetworkInterface, 10);
    OSMetaClassDeclareReservedUnused( IONetworkInterface, 11);
    OSMetaClassDeclareReservedUnused( IONetworkInterface, 12);
    OSMetaClassDeclareReservedUnused( IONetworkInterface, 13);
    OSMetaClassDeclareReservedUnused( IONetworkInterface, 14);
    OSMetaClassDeclareReservedUnused( IONetworkInterface, 15);
};

#endif /* defined(KERNEL) && defined(__cplusplus) */

#endif /* !_IONETWORKINTERFACE_H */
