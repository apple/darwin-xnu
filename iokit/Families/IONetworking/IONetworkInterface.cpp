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
 * IONetworkInterface.cpp
 *
 * HISTORY
 * 8-Jan-1999       Joe Liu (jliu) created.
 *
 */

#include <IOKit/assert.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOBSD.h>
#include <IOKit/network/IONetworkInterface.h>
#include <IOKit/network/IONetworkController.h>
#include <IOKit/network/IONetworkUserClient.h>
#include <IOKit/network/IONetworkStack.h>

extern "C" {
#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/bpf.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/if_media.h>
#include <net/dlil.h>
int copyout(void *kaddr, void *udaddr, size_t len);

#ifdef KEV_DL_LINK_ON
#include <sys/kern_event.h>
int dlil_event(struct ifnet *ifp, struct kern_event_msg *event);
#endif
}

//---------------------------------------------------------------------------

#define super IOService

OSDefineMetaClassAndAbstractStructors( IONetworkInterface, IOService )
OSMetaClassDefineReservedUnused( IONetworkInterface,  0);
OSMetaClassDefineReservedUnused( IONetworkInterface,  1);
OSMetaClassDefineReservedUnused( IONetworkInterface,  2);
OSMetaClassDefineReservedUnused( IONetworkInterface,  3);
OSMetaClassDefineReservedUnused( IONetworkInterface,  4);
OSMetaClassDefineReservedUnused( IONetworkInterface,  5);
OSMetaClassDefineReservedUnused( IONetworkInterface,  6);
OSMetaClassDefineReservedUnused( IONetworkInterface,  7);
OSMetaClassDefineReservedUnused( IONetworkInterface,  8);
OSMetaClassDefineReservedUnused( IONetworkInterface,  9);
OSMetaClassDefineReservedUnused( IONetworkInterface, 10);
OSMetaClassDefineReservedUnused( IONetworkInterface, 11);
OSMetaClassDefineReservedUnused( IONetworkInterface, 12);
OSMetaClassDefineReservedUnused( IONetworkInterface, 13);
OSMetaClassDefineReservedUnused( IONetworkInterface, 14);
OSMetaClassDefineReservedUnused( IONetworkInterface, 15);

//---------------------------------------------------------------------------
// Macros

#ifdef  DEBUG
#define DLOG(fmt, args...)  IOLog(fmt, ## args)
#else
#define DLOG(fmt, args...)
#endif

//---------------------------------------------------------------------------
// Initialize an IONetworkInterface instance.
//
// Returns true if initialized successfully, false otherwise.

bool IONetworkInterface::init(IONetworkController * controller)
{
    // Propagate the init() call to our superclass.

    if ( super::init() == false )
        return false;

    // The controller object provided must be valid.

    if ( OSDynamicCast(IONetworkController, controller) == 0 )
        return false;

    _controller = controller;

    // Create interface lock to serialize ifnet updates.

    _ifLock = IORecursiveLockAlloc();
    if ( _ifLock == 0 )
        return false;

    // Create an OSNumber to store interface state bits.

    _stateBits = OSNumber::withNumber((UInt64) 0, 32);
    if ( _stateBits == 0 )
        return false;
    setProperty( kIOInterfaceState, _stateBits );

    // Create an OSSet to store client objects. Initial capacity
    // (which can grow) is set at 2 clients.

    _clientSet = OSSet::withCapacity(2);
    if ( _clientSet == 0 )
        return false;

    // Get the ifnet structure of the network interface. Subclasses must
    // implement getIfnet() and expect this function to be called when
    // they call IONetworkInterface::init().

    _ifp = getIfnet();
    if ( _ifp == 0 )
    {
        DLOG("%s: getIfnet() returned NULL\n", getName());
        return false;
    }

    // Intialize the ifnet structure.

    if ( initIfnet(_ifp) == false )
        return false;

    // Create a data dictionary.

    if ( (_dataDict = OSDictionary::withCapacity(5)) == 0 )
        return false;

    IONetworkData * data = IONetworkData::withExternalBuffer(
                                    kIONetworkStatsKey,
                                    sizeof(IONetworkStats),
                                    (UInt8 *) &(_ifp->if_data.ifi_ipackets));
    if ( data )
    {
        addNetworkData(data);
        data->release();
    }

    // Register default output handler.

    if ( registerOutputHandler( controller,
                                controller->getOutputHandler() ) == false )
    {
        return false;
    }

    // Set the kIOInterfaceNamePrefix and kIOPrimaryInterface properties.
    // These may be used by an user space agent as hints when assigning a
    // BSD name for the interface.

    setProperty( kIOInterfaceNamePrefix, getNamePrefix() );
    setProperty( kIOPrimaryInterface, isPrimaryInterface() );

    return true;
}

//---------------------------------------------------------------------------
// Destroy the interface. Release all allocated resources.

void IONetworkInterface::free()
{
    DLOG("IONetworkInterface::free()\n");

    if ( _clientSet )
    {
        // Should not have any clients.
        assert(_clientSet->getCount() == 0);
        _clientSet->release();
        _clientSet = 0;
    }

    if ( _dataDict  ) { _dataDict->release();  _dataDict  = 0; }
    if ( _stateBits ) { _stateBits->release(); _stateBits = 0; }

    if ( _ifLock )
    {
        IORecursiveLockFree(_ifLock);
        _ifLock = 0;
    }

    clearInputQueue();

    super::free();
}

//---------------------------------------------------------------------------
// Returns true if the receiver of this method is the system's primary
// network interface.

bool IONetworkInterface::isPrimaryInterface() const
{
    IOService * provider  = getController();
    bool        isPrimary = false;

    if ( provider ) provider = provider->getProvider();

    // FIXME: Should rely on a single property, and the platform
    // expert should patch the device tree if necessary to make
    // it so.

    if ( provider &&
        ( provider->getProperty( "AAPL,slot-name" ) == 0 ) &&
        ( provider->getProperty( "built-in" )                 ||
          provider->getProperty( "AAPL,connector" )           ||    
          ( strcmp( provider->getName(), "ethernet" ) == 0 ) ) )
    {
        isPrimary = true;
    }

    return isPrimary;
}

//---------------------------------------------------------------------------
// Get the IONetworkCotroller object that is servicing this interface.

IONetworkController * IONetworkInterface::getController() const
{
    return _controller;
}

#ifdef HW_CSUM_SUPPORT
//---------------------------------------------------------------------------
// Get the value that should be set in the hwassist field in the ifnet
// structure. Currently, this field is solely used for advertising the
// hardware checksumming support.

static UInt32 getIfnetHardwareAssistValue( IONetworkController * ctr )
{
    UInt32  input;
    UInt32  output;
    UInt32  hwassist = 0;

    do {
        if ( ctr->getChecksumSupport(
                     &input,
                     IONetworkController::kChecksumFamilyTCPIP,
                     false ) != kIOReturnSuccess ) break;
        
        if ( ctr->getChecksumSupport(
                     &output,
                     IONetworkController::kChecksumFamilyTCPIP,
                     true ) != kIOReturnSuccess ) break;

        if ( input & output & IONetworkController::kChecksumIP )
        {
            hwassist |= CSUM_IP;
        }
        
        if ( ( input  & ( IONetworkController::kChecksumTCP |
                          IONetworkController::kChecksumTCPNoPseudoHeader ) )
        &&   ( output & ( IONetworkController::kChecksumTCP |
                          IONetworkController::kChecksumTCPSum16 ) ) )
        {
            hwassist |= CSUM_TCP;
        }
        
        if ( ( input  & ( IONetworkController::kChecksumUDP | 
                          IONetworkController::kChecksumUDPNoPseudoHeader ) )
        &&   ( output & ( IONetworkController::kChecksumUDP |
                          IONetworkController::kChecksumTCPSum16 ) ) )
        {
            hwassist |= CSUM_UDP;
        }
    }
    while ( false );
    
    return hwassist;
}
#endif HW_CSUM_SUPPORT

//---------------------------------------------------------------------------
// Initialize the ifnet structure.
    
bool IONetworkInterface::initIfnet(struct ifnet * ifp)
{
    lock();

    // Register our 'shim' functions. These function pointers
    // points to static member functions inside this class.

    ifp->if_output      = output_shim;
    ifp->if_ioctl       = ioctl_shim;
    ifp->if_set_bpf_tap = set_bpf_tap_shim;
    ifp->if_private     = this;
    ifp->if_free        = &IONetworkStack::bsdInterfaceWasUnregistered;
    ifp->if_name        = (char *) getNamePrefix();

    unlock();

    return true;
}

//---------------------------------------------------------------------------
// Implement family specific matching.

bool IONetworkInterface::matchPropertyTable(OSDictionary * table,
                                            SInt32       * score)
{ 
    return super::matchPropertyTable(table, score);
}

//---------------------------------------------------------------------------
// Take the interface lock.

void IONetworkInterface::lock()
{
    IORecursiveLockLock(_ifLock);
}

//---------------------------------------------------------------------------
// Release the interface lock.

void IONetworkInterface::unlock()
{
    IORecursiveLockUnlock(_ifLock);
}

//---------------------------------------------------------------------------
// Inspect the controller after it has been opened.

bool IONetworkInterface::controllerDidOpen(IONetworkController * controller)
{
    return true;   // by default, always accept the controller open.
}

//---------------------------------------------------------------------------
// Perform cleanup before the controller is closed.

void IONetworkInterface::controllerWillClose(IONetworkController * controller)
{
}

//---------------------------------------------------------------------------
// Handle a client open on the interface.

bool IONetworkInterface::handleOpen(IOService *  client,
                                    IOOptionBits options,
                                    void *       argument)
{
    bool  accept         = false;
    bool  controllerOpen = false;

    do {
        // Was this object already registered as our client?

        if ( _clientSet->containsObject(client) )
        {
            DLOG("%s: multiple opens from client %lx\n",
                 getName(), (UInt32) client);
            accept = true;
            break;
        }

        // If the interface has not received a client open, which also
        // implies that the interface has not yet opened the controller,
        // then open the controller upon receiving the first open from
        // a client. If the controller open fails, the client open will
        // be rejected.

        if ( ( getInterfaceState() & kIONetworkInterfaceOpenedState ) == 0 )
        {
            if ( ( (controllerOpen = _controller->open(this)) == false ) ||
                 ( controllerDidOpen(_controller) == false ) )
                break;
        }

        // Qualify the client.

        if ( handleClientOpen(client, options, argument) == false )
            break;

        // Add the new client object to our client set.

        if ( _clientSet->setObject(client) == false )
        {
            handleClientClose(client, 0);
            break;
        }

        accept = true;
    }
    while (false);

    // If provider was opened above, but an error has caused us to refuse
    // the client open, then close our provider.

    if ( controllerOpen )
    {
        if (accept)
        {
            setInterfaceState( kIONetworkInterfaceOpenedState );
            _controller->registerInterestedDriver( this );
        }
        else {
            controllerWillClose(_controller);
            _controller->close(this);
        }
    }

    return accept;
}

//---------------------------------------------------------------------------
// Handle a client close on the interface.

void IONetworkInterface::handleClose(IOService * client, IOOptionBits options)
{
    // Remove the object from the client OSSet.

    if ( _clientSet->containsObject(client) )
    {
        // Call handleClientClose() to handle the client close.

        handleClientClose( client, options );

        // If this is the last client, then close our provider.

        if ( _clientSet->getCount() == 1 )
        {
            _controller->deRegisterInterestedDriver( this );
            controllerWillClose( _controller );
            _controller->close( this );
            setInterfaceState( 0, kIONetworkInterfaceOpenedState );
        }

        // Remove the client from our OSSet.

        _clientSet->removeObject(client);
    }
}

//---------------------------------------------------------------------------
// Query whether a client has an open on the interface.

bool IONetworkInterface::handleIsOpen(const IOService * client) const
{
    if (client)
        return _clientSet->containsObject(client);
    else
        return (_clientSet->getCount() > 0);
}

//---------------------------------------------------------------------------
// Handle a client open on the interface.

bool IONetworkInterface::handleClientOpen(IOService *  client,
                                          IOOptionBits options,
                                          void *       argument)
{
    if ( OSDynamicCast(IONetworkStack, client) )
    {
        // Transition state to registered interface.

        setInterfaceState( kIONetworkInterfaceRegisteredState );
    }
    return true;
}

//---------------------------------------------------------------------------
// Handle a client close on the interface.

void IONetworkInterface::handleClientClose(IOService *  client,
                                           IOOptionBits options)
{
    if ( OSDynamicCast(IONetworkStack, client) )
    {
        // Transition state to unregistered interface.

        setInterfaceState( 0, kIONetworkInterfaceRegisteredState );
    }
}

//---------------------------------------------------------------------------
// Register the output packet handler.

bool IONetworkInterface::registerOutputHandler(OSObject *      target,
                                               IOOutputAction  action)
{
    lock();

    // Sanity check on the arguments.

    if ( (getInterfaceState() & kIONetworkInterfaceRegisteredState) ||
         !target || !action )
    {
        unlock();
        return false;
    }

    _outTarget = target;
    _outAction = action;

    unlock();

    return true;
}

//---------------------------------------------------------------------------
// Feed packets to the input/output BPF packet filter taps.

static inline void _feedPacketTap(struct ifnet * ifp,
                                  struct mbuf *  m,
                                  BPF_FUNC       func,
                                  int            mode)
{
    if (func) func(ifp, m);
}

//---------------------------------------------------------------------------
// Called by a network controller to submit a single packet received from
// the network to the data link layer.

#define IN_Q_ENQUEUE(m)                   \
{                                         \
    if (_inputQHead == 0) {               \
        _inputQHead = _inputQTail = (m);  \
    }                                     \
    else {                                \
        _inputQTail->m_nextpkt = (m) ;    \
        _inputQTail = (m);                \
    }                                     \
    _inputQCount++;                       \
}

#define DLIL_INPUT(m_head, m_tail)               \
{                                                \
    if ( m_head ) {                              \
        dlil_input(_ifp, (m_head), (m_tail));    \
    }                                            \
}

UInt32 IONetworkInterface::flushInputQueue()
{
    UInt32 count = _inputQCount;

    DLIL_INPUT(_inputQHead, _inputQTail);
    _inputQHead  = _inputQTail = 0;
    _inputQCount = 0;

    return count;
}

UInt32 IONetworkInterface::clearInputQueue()
{
    UInt32 count = _inputQCount;

    m_freem_list( _inputQHead );

    _inputQHead = _inputQTail = 0;
    _inputQCount = 0;

    return count;
}

UInt32 IONetworkInterface::inputPacket(struct mbuf * pkt,
                                       UInt32        length  = 0,
                                       IOOptionBits  options = 0,
                                       void *        param   = 0)
{
    UInt32 count;

    assert(pkt);

    // Set the source interface and length of the received frame.

    if ( length )
    {
        if ( pkt->m_next == 0 )
        {
            pkt->m_pkthdr.len = pkt->m_len = length;
        }
        else
        {
            struct mbuf * m   = pkt;
            pkt->m_pkthdr.len = length;
            do {
                if (length < (UInt32) m->m_len)
                    m->m_len = length;
                length -= m->m_len;
            } while (( m = m->m_next ));
            assert(length == 0);
        }
    }

	pkt->m_pkthdr.rcvif = _ifp;
    
    // Increment input byte count.

    _ifp->if_ibytes += pkt->m_pkthdr.len;

    // Feed BPF tap.

    _feedPacketTap(_ifp, pkt, _inputFilterFunc, BPF_TAP_INPUT);

    pkt->m_pkthdr.header = pkt->m_data;
    pkt->m_pkthdr.len -= sizeof(struct ether_header);
    pkt->m_len  -= sizeof(struct ether_header);
    pkt->m_data += sizeof(struct ether_header);

    if ( options & kInputOptionQueuePacket )
    {
        IN_Q_ENQUEUE(pkt);
        count = 0;
    }
    else
    {
        if ( _inputQHead )  // queue is not empty
        {
            IN_Q_ENQUEUE(pkt);

            count = _inputQCount;

            DLIL_INPUT(_inputQHead, _inputQTail);

            _inputQHead  = _inputQTail = 0;
            _inputQCount = 0;
        }
        else
        {
            DLIL_INPUT(pkt, pkt);
            count = 1;
        }
    }
    return count;
}

//---------------------------------------------------------------------------
// Deliver an event to the network layer.

bool IONetworkInterface::inputEvent(UInt32 type, void * data)
{
    bool   success = true;

#ifdef KEV_DL_LINK_ON
    struct {
        kern_event_msg  header;
        u_long          unit;
        char            if_name[IFNAMSIZ];
    } event;

    switch (type)
    {
        // Deliver an IOKit defined event.

        case kIONetworkEventTypeLinkUp:
        case kIONetworkEventTypeLinkDown:

            if ( ( _ifp->if_flags & IFF_UP ) == 0 )
            {
                break;
            }

            bzero((void *) &event, sizeof(event));

            event.header.total_size    = sizeof(event);
            event.header.vendor_code   = KEV_VENDOR_APPLE;
            event.header.kev_class     = KEV_NETWORK_CLASS;
            event.header.kev_subclass  = KEV_DL_SUBCLASS;
            event.header.event_code    = (type == kIONetworkEventTypeLinkUp) ?
                                         KEV_DL_LINK_ON : KEV_DL_LINK_OFF;
            event.header.event_data[0] = _ifp->if_family;
            event.unit                 = (u_long) _ifp->if_unit;
            strncpy(&event.if_name[0], _ifp->if_name, IFNAMSIZ);

            dlil_event(_ifp, &event.header);
            break;

        // Deliver a raw kernel event to DLIL.
        // The data argument must point to a kern_event_msg structure.

        case kIONetworkEventTypeDLIL:
            dlil_event(_ifp, (struct kern_event_msg *) data);
            break;

        default:
            IOLog("IONetworkInterface: unknown event type %lx\n", type);
            success = false;
            break;
    }
#endif

    return success;
}

//---------------------------------------------------------------------------
// SIOCSIFMTU (set interface MTU) ioctl handler.

SInt32 IONetworkInterface::syncSIOCSIFMTU(IONetworkController * ctr,
                                          struct ifreq *        ifr)
{   
    SInt32  error;
    UInt32  newMTU = ifr->ifr_mtu;

    // If change is not necessary, return success without getting the
    // controller involved.

    if ( getMaxTransferUnit() == newMTU )
        return 0;

    // Request the controller to switch MTU size.

    error = errnoFromReturn( ctr->setMaxPacketSize(newMTU) );

    if ( error == 0 )
    {
        // Controller reports success. Update the interface MTU size
        // property.

        setMaxTransferUnit(newMTU);
    }

    return error;
}

//---------------------------------------------------------------------------
// SIOCSIFMEDIA (SET interface media) ioctl handler.

SInt32 IONetworkInterface::syncSIOCSIFMEDIA(IONetworkController * ctr,
                                            struct ifreq *        ifr)
{
    OSDictionary *    mediumDict;
    IONetworkMedium * medium;
    SInt32            error;

    mediumDict = ctr->copyMediumDictionary();  // creates a copy
    if ( mediumDict == 0 )
    {
        // unable to allocate memory, or no medium dictionary.
        return EOPNOTSUPP;
    }

    medium = IONetworkMedium::getMediumWithType(mediumDict, ifr->ifr_media);
    if ( medium == 0 )
    {
        // Exact type was not found. Try a partial match.
        // ifconfig program sets the media type and media
        // options separately. This should not be allowed!

        medium = IONetworkMedium::getMediumWithType(mediumDict,
                                                    ifr->ifr_media,
                                                    ~(IFM_TMASK | IFM_NMASK));
        if ( medium == 0 )
        {
            mediumDict->release();
            return EINVAL;       // requested medium not found.
        }
    }

    // It may be possible for the controller to update the medium
    // dictionary and perhaps delete the medium entry that we have
    // selected from our copy of the stale dictionary. This is
    // harmless since IONetworkController will filter out invalid
    // selections before calling the driver.

    error = errnoFromReturn( ctr->selectMediumWithName(medium->getName()) );

    mediumDict->release();

    return error;
}

//---------------------------------------------------------------------------
// SIOCGIFMEDIA (GET interface media) ioctl handler.

SInt32 IONetworkInterface::syncSIOCGIFMEDIA(IONetworkController * ctr,
                                            struct ifreq *        ifr)
{
    OSDictionary *          mediumDict  = 0;
    UInt                    mediumCount = 0;
    UInt                    maxCount;
    OSCollectionIterator *  iter = 0;
    UInt32 *                typeList;
    UInt                    typeListSize;
    OSSymbol *              keyObject;
    SInt32                  error = 0;
    struct ifmediareq *     ifmr = (struct ifmediareq *) ifr;

    // Maximum number of medium types that the caller will accept.
    //
    maxCount = ifmr->ifm_count;

    do {
        mediumDict = ctr->copyMediumDictionary();  // creates a copy
        if (mediumDict == 0)
        {
            break;  // unable to allocate memory, or no medium dictionary.
        }

        if ((mediumCount = mediumDict->getCount()) == 0)
            break;  // no medium in the medium dictionary

        if (maxCount == 0)
            break;  //  caller is only probing for support and media count.

        if (maxCount < mediumCount)
        {
            // user buffer is too small to hold all medium entries.
            error = E2BIG;

            // Proceed with partial copy on E2BIG. This follows the
            // SIOCGIFMEDIA handling practice in bsd/net/if_media.c.
            //
            // break;
        }

        // Create an iterator to loop through the medium entries in the
        // dictionary.
        //
        iter = OSCollectionIterator::withCollection(mediumDict);
        if (!iter)
        {
            error = ENOMEM;
            break;
        }

        // Allocate memory for the copyout buffer.
        //
        typeListSize = maxCount * sizeof(UInt32);
        typeList = (UInt32 *) IOMalloc(typeListSize);
        if (!typeList)
        {
            error = ENOMEM;
            break;
        }
        bzero(typeList, typeListSize);

        // Iterate through the medium dictionary and copy the type of
        // each medium entry to typeList[].
        //
        mediumCount = 0;
        while ( (keyObject = (OSSymbol *) iter->getNextObject()) &&
                (mediumCount < maxCount) )
        {
            IONetworkMedium * medium = (IONetworkMedium *) 
                                       mediumDict->getObject(keyObject);
            if (!medium)
                continue;   // should not happen!

            typeList[mediumCount++] = medium->getType();
        }

        if (mediumCount)
        {
            error = copyout((caddr_t) typeList,
                            (caddr_t) ifmr->ifm_ulist,
                            typeListSize);
        }

        IOFree(typeList, typeListSize);
    }
    while (0);

    ifmr->ifm_active = ifmr->ifm_current = IFM_NONE;
    ifmr->ifm_status = 0;
    ifmr->ifm_count  = mediumCount;

    // Get a copy of the controller's property table and read the
    // link status, current, and active medium.

    OSDictionary * pTable = ctr->dictionaryWithProperties();
    if (pTable)
    {
        OSNumber * linkStatus = (OSNumber *) 
                                pTable->getObject(kIOLinkStatus);
        if (linkStatus)
            ifmr->ifm_status = linkStatus->unsigned32BitValue();
        
        if (mediumDict)
        {
            IONetworkMedium * medium;
            OSSymbol *        mediumName;

            if ((mediumName = (OSSymbol *) pTable->getObject(kIOSelectedMedium)) 
               && (medium = (IONetworkMedium *) 
                            mediumDict->getObject(mediumName)))
            {
                ifmr->ifm_current = medium->getType();
            }

            if ((mediumName = (OSSymbol *) pTable->getObject(kIOActiveMedium)) 
               && (medium = (IONetworkMedium *) 
                            mediumDict->getObject(mediumName)))
            {
                ifmr->ifm_active = medium->getType();
            }
        }
        pTable->release();
    }

    if (iter)
        iter->release();

    if (mediumDict)
        mediumDict->release();

    return error;
}

//---------------------------------------------------------------------------
// Handle ioctl commands sent to the network interface.

SInt32 IONetworkInterface::performCommand(IONetworkController * ctr,
                                          UInt32                cmd,
                                          void *                arg0,
                                          void *                arg1)
{
    struct ifreq *  ifr = (struct ifreq *) arg1;
    SInt32          ret = EOPNOTSUPP;

    if ( (ifr == 0) || (ctr == 0) )
        return EINVAL;

    switch ( cmd )
    {
        // Get interface MTU.

        case SIOCGIFMTU:
            ifr->ifr_mtu = getMaxTransferUnit();
            ret = 0;    // no error
            break;

        // Get interface media type and status.

        case SIOCGIFMEDIA:
            ret = syncSIOCGIFMEDIA(ctr, ifr);
            break;

        case SIOCSIFMTU:
        case SIOCSIFMEDIA:
            ret = (int) ctr->executeCommand(
                             this,            /* client */
                             (IONetworkController::Action)
                                &IONetworkInterface::performGatedCommand,
                             this,            /* target */
                             ctr,             /* param0 */
                             (void *) cmd,    /* param1 */
                             arg0,            /* param2 */
                             arg1 );          /* param3 */
            break;

        default:
            // DLOG(%s: command not handled (%08lx), getName(), cmd);
            break;
    }

    return ret;
}

//---------------------------------------------------------------------------
// Perform an ioctl command on the controller's workloop context.

int IONetworkInterface::performGatedCommand(void * target,
                                            void * arg1_ctr,
                                            void * arg2_cmd,
                                            void * arg3_0,
                                            void * arg4_1)
{
    IONetworkInterface *  self = (IONetworkInterface *)  target;
    IONetworkController * ctr  = (IONetworkController *) arg1_ctr;
    struct ifreq *        ifr  = (struct ifreq *) arg4_1;
    SInt32                ret  = EOPNOTSUPP;

    // Refuse to issue I/O to the controller if it is in a power state
    // that renders it "unusable".

    if ( self->getInterfaceState() & kIONetworkInterfaceDisabledState )
        return EPWROFF;

    switch ( (UInt32) arg2_cmd )
    {
        // Set interface MTU.

        case SIOCSIFMTU:
            ret = self->syncSIOCSIFMTU(ctr, ifr);
            break;

        // Set interface (controller) media type.

        case SIOCSIFMEDIA:
            ret = self->syncSIOCSIFMEDIA(ctr, ifr);
            break;
    }

    return ret;
}

//---------------------------------------------------------------------------
// if_ioctl() handler - Calls performCommand() when we receive an ioctl
// from DLIL.

int
IONetworkInterface::ioctl_shim(struct ifnet * ifp, u_long cmd, caddr_t data)
{
    assert(ifp && ifp->if_private);

    IONetworkInterface * self = (IONetworkInterface *) ifp->if_private;

    assert(ifp == self->_ifp);

    return self->performCommand( self->_controller,
                                 cmd,
                                 (void *) ifp,
                                 (void *) data );
}

//---------------------------------------------------------------------------
// if_output() handler.
//
// Handle a call from the network stack to transmit the given mbuf.
// For now, we can assume that the mbuf is singular, and never chained.

int IONetworkInterface::output_shim(struct ifnet * ifp, struct mbuf * m)
{
    assert(ifp && ifp->if_private);

    IONetworkInterface * self = (IONetworkInterface *) ifp->if_private;
    
    assert(ifp == self->_ifp);

    if ( m == 0 )
    {
        DLOG("IONetworkInterface: NULL output mbuf\n");
        return EINVAL;
    }

    if ( (m->m_flags & M_PKTHDR) == 0 )
    {
        DLOG("IONetworkInterface: M_PKTHDR bit not set\n");
        m_freem(m);
        return EINVAL;
    }

    // Increment output byte counter.

    ifp->if_obytes += m->m_pkthdr.len;

    // Feed the output filter tap.

    _feedPacketTap(ifp, m, self->_outputFilterFunc, BPF_TAP_OUTPUT);

    // Forward the packet to the registered output packet handler.

    return ((self->_outTarget)->*(self->_outAction))(m, 0);
}

//---------------------------------------------------------------------------
// if_set_bpf_tap() handler. Handles request from the DLIL to enable or
// disable the input/output filter taps.
//
// FIXME - locking may be needed.

int IONetworkInterface::set_bpf_tap_shim(struct ifnet * ifp,
                                         int            mode,
                                         BPF_FUNC       func)
{
    assert(ifp && ifp->if_private);

    IONetworkInterface * self = (IONetworkInterface *) ifp->if_private;

    assert(ifp == self->_ifp);

    self->lock();

    switch ( mode )
    {
        case BPF_TAP_DISABLE:
            self->_inputFilterFunc = self->_outputFilterFunc = 0;
            break;

        case BPF_TAP_INPUT:
            assert(func);
            self->_inputFilterFunc = func;
            break;

        case BPF_TAP_OUTPUT:
            assert(func);
            self->_outputFilterFunc = func;
            break;
        
        case BPF_TAP_INPUT_OUTPUT:
            assert(func);
            self->_inputFilterFunc = self->_outputFilterFunc = func;
            break;

        default:
            DLOG("IONetworkInterface: Unknown BPF tap mode %d\n", mode);
            break;
    }

    self->unlock();

    return 0;
}

//---------------------------------------------------------------------------
// As the name implies, this function does nothing. This will get called
// if the network layer tries to call the if_watchdog function pointer 
// in ifnet. This should not happen. IOKit does not use this watchdog
// timer facility.

void IONetworkInterface::null_shim(struct ifnet * /*ifp*/)
{
    IOLog("IONetworkInterface::null_shim called!\n");
}

//---------------------------------------------------------------------------
// ifnet field (and property table) getter/setter.

bool IONetworkInterface::_setInterfaceProperty(UInt32  value,
                                               UInt32  mask,
                                               UInt32  bytes,
                                               void *  addr,
                                               char *  key)
{
    bool       updateOk = false;
    UInt32     newValue;
    OSNumber * number;

    lock();

    // Update the property in ifnet.

    switch (bytes)
    {
        case 1:
            newValue = (*((UInt8 *) addr) & mask) | value;
            *((UInt8 *) addr) = (UInt8) newValue;
            break;
        case 2:
            newValue = (*((UInt16 *) addr) & mask) | value;
            *((UInt16 *) addr) = (UInt16) newValue;
            break;
        case 4:
            newValue = (*((UInt32 *) addr) & mask) | value;
            *((UInt32 *) addr) = (UInt32) newValue;
            break;
        default:
            goto abort;
    }

    // Update the OSNumber in the property table.

    if ( key )
    {
        if ( (number = (OSNumber *) getProperty(key)) )
        {
            number->setValue(newValue);
            updateOk = true;
        }
        else
        {
            updateOk = setProperty(key, newValue, bytes * 8);
        }
    }
abort:
    unlock();
    return updateOk;
}

#define IO_IFNET_GET(func, type, field)                        \
type IONetworkInterface:: ## func() const                      \
{                                                              \
    type ret;                                                  \
    ((IONetworkInterface *) this)->lock();                     \
    ret = _ifp ? _ifp-> ## field : 0;                          \
    ((IONetworkInterface *) this)->unlock();                   \
    return ret;                                                \
}

#define IO_IFNET_SET(func, type, field, propName)              \
bool IONetworkInterface:: ## func(type value)                  \
{                                                              \
    return _setInterfaceProperty(                              \
        (UInt32) value,                                        \
        0,                                                     \
        sizeof(type),                                          \
        (void *) &_ifp-> ## field,                             \
        propName);                                             \
}

#define IO_IFNET_RMW(func, type, field, propName)              \
bool IONetworkInterface:: ## func(type value, type clear = 0)  \
{                                                              \
    return _setInterfaceProperty(                              \
        (UInt32) value,                                        \
        (UInt32) ~clear,                                       \
        sizeof(type),                                          \
        (void *) &_ifp-> ## field,                             \
        propName);                                             \
}

//---------------------------------------------------------------------------
// Interface type accessors (ifp->if_type). The list of interface types is
// defined in <bsd/net/if_types.h>.

IO_IFNET_SET(setInterfaceType, UInt8, if_type, kIOInterfaceType)
IO_IFNET_GET(getInterfaceType, UInt8, if_type)

//---------------------------------------------------------------------------
// Mtu (MaxTransferUnit) accessors (ifp->if_mtu).

IO_IFNET_SET(setMaxTransferUnit, UInt32, if_mtu, kIOMaxTransferUnit)
IO_IFNET_GET(getMaxTransferUnit, UInt32, if_mtu)

//---------------------------------------------------------------------------
// Flags accessors (ifp->if_flags). This is a read-modify-write operation.

IO_IFNET_RMW(setFlags, UInt16, if_flags, kIOInterfaceFlags)
IO_IFNET_GET(getFlags, UInt16, if_flags)

//---------------------------------------------------------------------------
// EFlags accessors (ifp->if_eflags). This is a read-modify-write operation.

IO_IFNET_RMW(setExtraFlags, UInt32, if_eflags, kIOInterfaceExtraFlags)
IO_IFNET_GET(getExtraFlags, UInt32, if_eflags)

//---------------------------------------------------------------------------
// MediaAddressLength accessors (ifp->if_addrlen)

IO_IFNET_SET(setMediaAddressLength, UInt8, if_addrlen, kIOMediaAddressLength)
IO_IFNET_GET(getMediaAddressLength, UInt8, if_addrlen)

//---------------------------------------------------------------------------
// MediaHeaderLength accessors (ifp->if_hdrlen)

IO_IFNET_SET(setMediaHeaderLength, UInt8, if_hdrlen, kIOMediaHeaderLength)
IO_IFNET_GET(getMediaHeaderLength, UInt8, if_hdrlen)

//---------------------------------------------------------------------------
// Interface unit number. The unit number for the interface is assigned
// by our client.

IO_IFNET_SET(setUnitNumber, UInt16, if_unit, kIOInterfaceUnit)
IO_IFNET_GET(getUnitNumber, UInt16, if_unit)

//---------------------------------------------------------------------------
// Return true if the interface has been registered with the network layer,
// false otherwise.

bool IONetworkInterface::isRegistered() const
{
    return (bool)(getInterfaceState() & kIONetworkInterfaceRegisteredState);
}

//---------------------------------------------------------------------------
// Return the interface state flags.

UInt32 IONetworkInterface::getInterfaceState() const
{
    return _stateBits->unsigned32BitValue();
}

//---------------------------------------------------------------------------
// Set (or clear) the interface state flags.

UInt32 IONetworkInterface::setInterfaceState( UInt32 set,
                                              UInt32 clear )
{
    UInt32  val;

    assert( _stateBits );

    lock();

    val = ( _stateBits->unsigned32BitValue() | set ) & ~clear;
    _stateBits->setValue( val );

    unlock();

    return val;
}

//---------------------------------------------------------------------------
// Perform a lookup of the dictionary kept by the interface,
// and return an entry that matches the specified string key.
//
// key: Search for an IONetworkData entry with this key.
//
// Returns the matching entry, or 0 if no match was found.

IONetworkData * IONetworkInterface::getNetworkData(const OSSymbol * key) const
{
    return OSDynamicCast(IONetworkData, _dataDict->getObject(key));
}

IONetworkData * IONetworkInterface::getNetworkData(const char * key) const
{
    return OSDynamicCast(IONetworkData, _dataDict->getObject(key));
}

//---------------------------------------------------------------------------
// A private function to copy the data dictionary to the property table.

bool IONetworkInterface::_syncNetworkDataDict()
{
    OSDictionary * aCopy = OSDictionary::withDictionary(_dataDict);
    bool           ret   = false;

    if (aCopy) {
        ret = setProperty(kIONetworkData, aCopy);
        aCopy->release();
    }

    return ret;
}

//---------------------------------------------------------------------------
// Remove an entry from the IONetworkData dictionary managed by the interface.
// The removed object is released.

bool IONetworkInterface::removeNetworkData(const OSSymbol * aKey)
{
    bool ret = false;

    lock();

    do {
        if ( getInterfaceState() & kIONetworkInterfaceOpenedState )
            break;

        _dataDict->removeObject(aKey);
        ret = _syncNetworkDataDict();
    }
    while (0);

    unlock();

    return ret;
}

bool IONetworkInterface::removeNetworkData(const char * aKey)
{
    bool ret = false;

    lock();

    do {
        if ( getInterfaceState() & kIONetworkInterfaceOpenedState )
            break;

        _dataDict->removeObject(aKey);
        ret = _syncNetworkDataDict();
    }
    while (0);

    unlock();

    return ret;
}

//---------------------------------------------------------------------------
// Add an IONetworkData object to a dictionary managed by the interface.

bool IONetworkInterface::addNetworkData(IONetworkData * aData)
{
    bool ret = false;

    if (OSDynamicCast(IONetworkData, aData) == 0)
        return false;

    lock();

    if (( getInterfaceState() & kIONetworkInterfaceOpenedState ) == 0)
    {
        if ((ret = _dataDict->setObject(aData->getKey(), aData)))
            ret = _syncNetworkDataDict();
    }

    unlock();

    return ret;
}

//---------------------------------------------------------------------------
// Create a new IOUserClient to handle client requests. The default
// implementation will create an IONetworkUserClient instance if
// the type given is kIONUCType.

IOReturn IONetworkInterface::newUserClient(task_t           owningTask,
                                           void *         /*security_id*/,
                                           UInt32           type,
                                           IOUserClient **  handler)
{
    IOReturn              err = kIOReturnSuccess;
    IONetworkUserClient * client;

    if (type != kIONUCType)
        return kIOReturnBadArgument;

    client = IONetworkUserClient::withTask(owningTask);

    if (!client || !client->attach(this) || !client->start(this))
    {
        if (client)
        {
            client->detach(this);
            client->release();
            client = 0;
        }
        err = kIOReturnNoMemory;
    }

    *handler = client;

    return err;
}

//---------------------------------------------------------------------------
// Handle controller's power state transitions.

IOReturn
IONetworkInterface::controllerWillChangePowerState(
                              IONetworkController * controller,
                              IOPMPowerFlags        flags,
                              UInt32                stateNumber,
                              IOService *           policyMaker )
{
    if ( ( flags & IOPMDeviceUsable ) == 0 )
    {
        setInterfaceState( kIONetworkInterfaceDisabledState );
    }
    return kIOReturnSuccess;
}

IOReturn
IONetworkInterface::controllerDidChangePowerState(
                              IONetworkController * controller,
                              IOPMPowerFlags        flags,
                              UInt32                stateNumber,
                              IOService *           policyMaker )
{
    if ( flags & IOPMDeviceUsable )
    {
        setInterfaceState( 0, kIONetworkInterfaceDisabledState );
    }
    return kIOReturnSuccess;
}

//---------------------------------------------------------------------------
// Static member functions called by power-management notification handlers.
// Act as stub functions that will simply forward the call to virtual member
// functions.

IOReturn
IONetworkInterface::sControllerWillChangePowerState(
                               IONetworkInterface *   netif,
                               void *                 param0,
                               void *                 param1,
                               void *                 param2,
                               void *                 param3 )
{
    return netif->controllerWillChangePowerState(
                            (IONetworkController *) param0,
                            (IOPMPowerFlags)        param1,
                            (UInt32)                param2,
                            (IOService *)           param3 );
}

IOReturn
IONetworkInterface::sControllerDidChangePowerState(
                               IONetworkInterface *   netif,
                               void *                 param0,
                               void *                 param1,
                               void *                 param2,
                               void *                 param3 )
{
    return netif->controllerDidChangePowerState( 
                            (IONetworkController *) param0,
                            (IOPMPowerFlags)        param1,
                            (UInt32)                param2,
                            (IOService *)           param3 );
}

//---------------------------------------------------------------------------
// Handle notitifications triggered by controller's power state change.

IOReturn
IONetworkInterface::powerStateWillChangeTo( IOPMPowerFlags  flags,
                                            UInt32          stateNumber,
                                            IOService *     policyMaker )
{
    _controller->executeCommand(
                    this,                   /* client */
                    (IONetworkController::Action)
                    &IONetworkInterface::sControllerWillChangePowerState,
                    this,                   /* target */
                    (void *) _controller,   /* param0 */
                    (void *) flags,         /* param1 */
                    (void *) stateNumber,   /* param2 */
                    (void *) policyMaker);  /* param3 */

    return IOPMAckImplied;
}

IOReturn
IONetworkInterface::powerStateDidChangeTo( IOPMPowerFlags  flags,
                                           UInt32          stateNumber,
                                           IOService *     policyMaker )
{
    _controller->executeCommand(
                    this,                   /* client */
                    (IONetworkController::Action)
                    &IONetworkInterface::sControllerDidChangePowerState,
                    this,                   /* target */
                    (void *) _controller,   /* param0 */
                    (void *) flags,         /* param1 */
                    (void *) stateNumber,   /* param2 */
                    (void *) policyMaker);  /* param3 */

    return IOPMAckImplied;
}
