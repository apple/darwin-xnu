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
 * Copyright (c) 1996 NeXT Software, Inc.
 *
 * i82557.h
 *
 * HISTORY
 *
 * 4-Mar-96	Dieter Siegmund (dieter) at NeXT
 *		Created.
 */

#ifndef _I82557_H
#define _I82557_H

#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/network/IOEthernetController.h>
#include <IOKit/network/IOEthernetInterface.h>
#include <IOKit/network/IOGatedOutputQueue.h>
#include <IOKit/network/IOMbufMemoryCursor.h>
#include <IOKit/network/IOPacketQueue.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOFilterInterruptEventSource.h>

#include "i82557Inline.h"
#include "i82557eeprom.h"
#include "i82557PHY.h"
#include <IOKit/assert.h>

/*
 * Macro: VPRINT
 *
 * Purpose:
 *   Dump stuff to console log if the "Verbose" key is present in
 *   the device description.
 */
#define VPRINT(fmt, args...) \
	if (verbose) \
		IOLog(fmt, ## args);

#define NUM_RECEIVE_FRAMES		32
#define NUM_TRANSMIT_FRAMES		32

#define TRANSMIT_INT_DELAY		8
#define TRANSMIT_QUEUE_SIZE		256

#define MAX_BUF_SIZE			(ETHERMAXPACKET + ETHERCRC)

#define SPIN_TIMEOUT			50000
#define SPIN_COUNT				1

/*
 * Type: tcbQ_t
 *
 * Purpose:
 *   Hold transmit hardware queue variables.
 */
typedef struct {
    int			numTcbs;
	tcb_t *		activeHead_p;
	tcb_t *		activeTail_p;
	tcb_t *		freeHead_p;
    int			numFree;
} tcbQ_t;

/*
 * Type: overlay_t
 *
 * Purpose:
 *   Overlayable memory used during start-up.
 */
typedef union {
    cbHeader_t			nop;
    cb_configure_t		configure;
    cb_iasetup_t		iasetup;
    port_selftest_t 	selftest;
} overlay_t;

/*
 * Type: pageBlock_t
 *
 * Purpose:
 *   Track a page sized memory block.
 */
typedef struct {
    void *	memPtr;
    UInt	memSize;
    void *	memAllocPtr;
    UInt	memAvail;
} pageBlock_t;

/*
 * Adapter activation levels.
 */
enum {
	kActivationLevel0 = 0,
	kActivationLevel1,
	kActivationLevel2
};

class Intel82557 : public IOEthernetController
{
	OSDeclareDefaultStructors(Intel82557)

public:
    IOPhysicalAddress              memBasePhysical;
    int                            irq;
    IOEthernetAddress              myAddress;
    IOEthernetInterface	*          netif;
	IOKernelDebugger *             debugger;
    IOPCIDevice *                  pciNub;
    IOWorkLoop *                   workLoop;

	IOInterruptEventSource *       interruptSrc;
	IOOutputQueue *                transmitQueue;
	IOTimerEventSource *           timerSrc;
	IONetworkStats *               netStats;
	IOEthernetStats *              etherStats;
	IOMemoryMap *                  csrMap;
	OSDictionary *                 mediumDict;
	IONetworkMedium *              mediumTable[MEDIUM_TYPE_INVALID];

	IOMbufLittleMemoryCursor *     rxMbufCursor;
	IOMbufLittleMemoryCursor *     txMbufCursor;

    int                            txCount;
	UInt32                         currentLevel;
	bool                           enabledForNetif;
	bool                           enabledForDebugger;
    bool                           promiscuousEnabled;
    bool                           multicastEnabled;
    bool                           allMulticastEnabled;
	bool                           interruptEnabled;
    bool                           packetsReceived;
    bool                           packetsTransmitted;
    bool                           verbose;
	bool						   flowControl;
	mediumType_t                   currentMediumType;
    UInt8                          phyAddr;
	UInt32                         phyID;
    UInt16                         phyStatusPrev;

    /* descriptor and control block data structures */
	pageBlock_t                    shared;
	pageBlock_t                    rxRing;
	pageBlock_t                    txRing;
	
	CSR_t *                        CSR_p;
    overlay_t *                    overlay_p;
    IOPhysicalAddress              overlay_paddr;
    errorCounters_t *              errorCounters_p;
    IOPhysicalAddress              errorCounters_paddr;
    i82557eeprom *                 eeprom;

    /* transmit-related */
    tcbQ_t                         tcbQ;
	tcb_t *                        tcbList_p;
    int                            prevCUCommand;

    /* kernel debugger */
	tcb_t *                        KDB_tcb_p;
    void *                         KDB_buf_p;
    IOPhysicalAddress              KDB_buf_paddr;
    
    /* receive-related */
	rfd_t *                        rfdList_p;	
	rfd_t *                        headRfd;
	rfd_t *                        tailRfd;

	// --------------------------------------------------
	// IOService (or its superclass) methods.
	// --------------------------------------------------

	virtual bool start(IOService * provider);
	virtual void stop(IOService * provider);
	virtual void free();

	// --------------------------------------------------
	// IONetworkController methods.
	// --------------------------------------------------

	virtual IOReturn enable(IONetworkInterface * netif);
	virtual IOReturn disable(IONetworkInterface * netif);

	virtual IOReturn enable(IOKernelDebugger * debugger);
	virtual IOReturn disable(IOKernelDebugger * debugger);

	virtual void sendPacket(void * pkt, UInt32 pkt_len);
	virtual void receivePacket(void * pkt, UInt32 * pkt_len, UInt32 timeout);

	virtual UInt32 outputPacket(struct mbuf * m, void * param);

	virtual void getPacketBufferConstraints(
                 IOPacketBufferConstraints * constraints) const;

	virtual IOOutputQueue * createOutputQueue();

	virtual const OSString * newVendorString() const;
	virtual const OSString * newModelString() const;

	virtual IOReturn setMedium(const IONetworkMedium * medium);

	virtual bool configureInterface(IONetworkInterface * interface);

    virtual bool         createWorkLoop();
    virtual IOWorkLoop * getWorkLoop() const;

	// --------------------------------------------------
	// IOEthernetController methods.
	// --------------------------------------------------

	virtual IOReturn getHardwareAddress(IOEthernetAddress * addr);
	virtual IOReturn setPromiscuousMode(IOEnetPromiscuousMode mode);
	virtual IOReturn setMulticastMode(IOEnetMulticastMode mode);
	virtual IOReturn setMulticastList(IOEthernetAddress *addrs, UInt32 count);

	// --------------------------------------------------
	// Intel82557 driver specific methods.
	// --------------------------------------------------

	bool pciConfigInit(IOPCIDevice * provider);
	bool initDriver(IOService * provider);
	bool coldInit();
	bool enableAdapter(UInt32 level);
	bool disableAdapter(UInt32 level);
	bool setActivationLevel(UInt32 newLevel);
	bool config();
	void disableAdapterInterrupts();
	void enableAdapterInterrupts();
	bool hwInit();
	bool iaSetup();
	bool mcSetup(IOEthernetAddress * addrs, UInt count, bool fromData = false);
	bool nop();
	void sendPortCommand(port_command_t command, UInt arg);
	bool getDefaultSettings();
	void issueReset();

	bool _selfTest();
	bool _allocateMemPage(pageBlock_t * p);
	void _freeMemPage(pageBlock_t * p);
	void _updateStatistics();
	bool _dumpStatistics();
	bool _mdiWritePHY(UInt8 phyAddress, UInt8 regAddress, UInt16 data);
	bool _mdiReadPHY(UInt8 phyAddress, UInt8 regAddress, UInt16 * data_p);
	void * _memAllocFrom(pageBlock_t * p, UInt allocSize, UInt align);
	bool _polledCommand(cbHeader_t * hdr_p, IOPhysicalAddress paddr);
	bool _abortReceive();
	bool _startReceive();
	void _resetChip();

	bool _initTcbQ(bool enable = false);
	bool _initRfdList(bool enable = false);
	bool _resetRfdList();
	bool _initRingBuffers() {
	     return (_initTcbQ(true) && _initRfdList(true)); }	
	bool _clearRingBuffers() {
         return (_initTcbQ(false) && _initRfdList(false)); }

	bool _sendPacket(void * pkt, UInt len);
	bool _receivePacket(void * pkt, UInt * len, UInt timeout);

	bool updateRFDFromMbuf(rfd_t * rfd_p, struct mbuf * m);
	struct mbuf * updateTCBForMbuf(tcb_t * tcb_p, struct mbuf * m);

	void interruptOccurred(IOInterruptEventSource * src, int count);
	bool receiveInterruptOccurred();
	void transmitInterruptOccurred();
	void timeoutOccurred(IOTimerEventSource * timer);

	// --------------------------------------------------
	// PHY methods.
	// --------------------------------------------------

	bool   _phyReset();
	bool   _phyWaitAutoNegotiation();
	UInt32 _phyGetID();
	bool   _phySetMedium(mediumType_t medium);
	bool   _phyProbe();
	void   _phyPublishMedia();
	bool   _phyAddMediumType(UInt32 type, UInt32 speed, UInt32 code);
    void   _phyReportLinkStatus(bool firstPoll = false);
    mediumType_t      _phyGetActiveMedium();
	IONetworkMedium * _phyGetMediumWithType(UInt32 type);
	mediumType_t      _phyGetMediumTypeFromBits(bool rate100,
                                                bool fullDuplex,
                                                bool t4);
};

#endif /* !_I82557_H */
