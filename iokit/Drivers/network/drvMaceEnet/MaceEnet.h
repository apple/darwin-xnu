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
 * Copyright (c) 1995-1996 NeXT Software, Inc.
 *
 * Interface definition for the Mace Ethernet chip 
 *
 * HISTORY
 *
 * 16-Sept-97	 
 *	Created.
 */

#ifndef _MACEENET_H
#define _MACEENET_H

#include <IOKit/network/IOEthernetController.h>
#include <IOKit/network/IOEthernetInterface.h>
#include <IOKit/network/IOGatedOutputQueue.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/network/IOMbufMemoryCursor.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/ppc/IODBDMA.h>
#include <string.h>			/* bcopy */

#if 0
#include <kern/kdebug.h>				/* Performance tracepoints */
#else
#define KERNEL_DEBUG(x,a,b,c,d,e)
#endif

#include "MaceEnetRegisters.h"

extern "C" {
#include <sys/param.h>
#include <sys/mbuf.h>
}

#if 0
#define IOLog kprintf
#endif

typedef void  *		IOPPCAddress;

typedef struct enet_dma_cmd_t
{
    IODBDMADescriptor		desc_seg[2];
} enet_dma_cmd_t;

typedef struct enet_txdma_cmd_t
{
    IODBDMADescriptor		desc_seg[4];
} enet_txdma_cmd_t;

class MaceEnet : public IOEthernetController
{
	OSDeclareDefaultStructors(MaceEnet)

private:
    volatile IOPPCAddress       ioBaseEnet;
    volatile IOPPCAddress		ioBaseEnetROM;
    volatile IODBDMAChannelRegisters 	*ioBaseEnetRxDMA;	
    volatile IODBDMAChannelRegisters 	*ioBaseEnetTxDMA;

    u_int16_t				chipId;	

    IOEthernetAddress		myAddress;
    IOEthernetInterface *	networkInterface;
	IOGatedOutputQueue *    transmitQueue;
	IOPacketQueue *			debugQueue;
	IOKernelDebugger *      debugger;
    bool					isPromiscuous;
    bool					multicastEnabled;
	bool					ready;
	bool					netifClient;
	bool					debugClient;
	bool					debugTxPoll;

    IOWorkLoop *            workLoop;
	IOInterruptEventSource *rxIntSrc;
	IOInterruptEventSource *txIntSrc;
	IOMemoryMap *			maps[MEMORY_MAP_COUNT];
	IOMemoryMap *			romMap;
	IONetworkStats *		netStats;
	IOTimerEventSource *	timerSrc;
	IOMbufBigMemoryCursor *	mbufCursor;

    struct mbuf *			txMbuf[TX_RING_LENGTH];
    struct mbuf *			rxMbuf[RX_RING_LENGTH];
	struct mbuf *			txDebuggerPkt;

    unsigned int			txCommandHead; /* Transmit ring descriptor index */
    unsigned int			txCommandTail;
    unsigned int       		txMaxCommand;		
    unsigned int			rxCommandHead;	/* Receive ring descriptor index */
    unsigned int			rxCommandTail;
    unsigned int        	rxMaxCommand;		

	struct {
		void	*ptr;
		u_int	size;
		void	*ptrReal;
		u_int	sizeReal;
	} dmaMemory;

    unsigned char *			dmaCommands;
    enet_txdma_cmd_t *		txDMACommands;		/* TX descriptor ring ptr */
    unsigned int			txDMACommandsPhys;

    enet_dma_cmd_t *		rxDMACommands;		/* RX descriptor ring ptr */
    unsigned int			rxDMACommandsPhys;

    u_int32_t				txWDInterrupts;
    u_int32_t				txWDTimeouts;
    bool					txWDForceReset;

    void *					debuggerPkt;
    u_int32_t				debuggerPktSize;
   
    u_int16_t				hashTableUseCount[64];
    u_int8_t         		hashTableMask[8];

	bool _allocateMemory();
	bool _initTxRing();
	bool _initRxRing();
	bool _initChip();
	void _resetChip();
	void _disableAdapterInterrupts();
	void _enableAdapterInterrupts();
	void _startChip();
	void _restartChip();
	void _stopReceiveDMA();
	void _stopTransmitDMA();
	bool _transmitPacket(struct mbuf * packet);
	bool _transmitInterruptOccurred(bool fDebugger = false);
	bool _receiveInterruptOccurred();
	bool _receivePackets(bool fDebugger);
	void _packetToDebugger(struct mbuf * packet, u_int size);
	bool _updateDescriptorFromMbuf(struct mbuf * m,  enet_dma_cmd_t *desc,
			bool isReceive);
	void _resetHashTableMask();
	void _addToHashTableMask(u_int8_t *addr);
	void _removeFromHashTableMask(u_int8_t *addr);
	void _updateHashTableMask();
#ifdef DEBUG
	void _dumpRegisters();
	void _dumpDesc(void * addr, u_int32_t size);
#endif
	IOReturn _setPromiscuousMode(IOEnetPromiscuousMode mode);
	void MaceEnet::_sendTestPacket();

	/*
	 * Kernel Debugger
	 */
	void _sendPacket(void *pkt, unsigned int pkt_len);
	void _receivePacket(void *pkt, unsigned int *pkt_len, unsigned int 
		timeout);

	bool resetAndEnable(bool enable);	
	void interruptOccurredForSource(IOInterruptEventSource *src, int count);
	void timeoutOccurred(IOTimerEventSource *timer);

public:
	virtual MaceEnet * MaceEnet::probe(IOService * provider,
                           unsigned int * score,
                           unsigned int * specificity);
	virtual bool init(OSDictionary * properties = 0);
	virtual bool start(IOService * provider);
	virtual void free();
	
    virtual bool         createWorkLoop();
    virtual IOWorkLoop * getWorkLoop() const;

	virtual IOReturn enable(IONetworkInterface * netif);
	virtual IOReturn disable(IONetworkInterface * netif);

	virtual IOReturn enable(IOKernelDebugger * debugger);
	virtual IOReturn disable(IOKernelDebugger * debugger);

	virtual IOReturn getHardwareAddress(IOEthernetAddress *addr);

	virtual IOReturn setMulticastMode(IOEnetMulticastMode mode);
	virtual IOReturn setMulticastList(IOEthernetAddress *addrs, UInt32 count);

	virtual IOReturn setPromiscuousMode(IOEnetPromiscuousMode mode);
	
	virtual IOOutputQueue * createOutputQueue();

	virtual UInt32 outputPacket(struct mbuf * m, void * param);

	virtual void sendPacket(void *pkt, UInt32 pkt_len);
	virtual void receivePacket(void *pkt, UInt32 *pkt_len, UInt32 timeout);

	virtual const OSString * newVendorString() const;
	virtual const OSString * newModelString() const;
	virtual const OSString * newRevisionString() const;
};

#if 0	// no power management stuff in IOKit yet.
/*
 * Power management methods. 
 */
- (IOReturn)getPowerState:(PMPowerState *)state_p;
- (IOReturn)setPowerState:(PMPowerState)state;
- (IOReturn)getPowerManagement:(PMPowerManagementState *)state_p;
- (IOReturn)setPowerManagement:(PMPowerManagementState)state;
#endif

/*
 * Performance tracepoints
 *
 * DBG_MACE_RXIRQ     	- Receive  ISR run time
 * DBG_MACE_TXIRQ     	- Transmit ISR run time
 * DBG_MACE_TXQUEUE     - Transmit packet passed from network stack
 * DBG_MACE_TXCOMPLETE  - Transmit packet sent
 * DBG_MACE_RXCOMPLETE  - Receive packet passed to network stack
 */
#define DBG_MACE_ENET		0x0800
#define DBG_MACE_RXIRQ 		DRVDBG_CODE(DBG_DRVNETWORK,(DBG_MACE_ENET+1)) 	
#define DBG_MACE_TXIRQ	 	DRVDBG_CODE(DBG_DRVNETWORK,(DBG_MACE_ENET+2))	
#define DBG_MACE_TXQUEUE 	DRVDBG_CODE(DBG_DRVNETWORK,(DBG_MACE_ENET+3))	
#define DBG_MACE_TXCOMPLETE	DRVDBG_CODE(DBG_DRVNETWORK,(DBG_MACE_ENET+4))	
#define DBG_MACE_RXCOMPLETE	DRVDBG_CODE(DBG_DRVNETWORK,(DBG_MACE_ENET+5))	

#endif /* !_MACEENET_H */
