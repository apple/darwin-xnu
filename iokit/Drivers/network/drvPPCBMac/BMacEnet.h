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
 * Copyright (c) 1998-1999 by Apple Computer, Inc., All rights reserved.
 *
 * Interface definition for the BMac Ethernet Controller 
 *
 * HISTORY
 *
 * Dec 10, 1998        jliu
 *  Converted to IOKit/C++.
 */

#ifndef _BMACENET_H
#define _BMACENET_H

#include <IOKit/network/IOEthernetController.h>
#include <IOKit/network/IOEthernetInterface.h>
#include <IOKit/network/IOGatedOutputQueue.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/network/IOMbufMemoryCursor.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/ppc/IODBDMA.h>
#include <string.h>            /* bcopy */
#include "BMacEnetRegisters.h"

extern "C" {
#include <sys/param.h>
#include <sys/mbuf.h>
}

// No kernel tracing support at this time.
//
#define KERNEL_DEBUG(x,a,b,c,d,e)

// #define IOLog kprintf

typedef void  *        IOPPCAddress;

typedef struct enet_dma_cmd_t
{
    IODBDMADescriptor    desc_seg[2];
} enet_dma_cmd_t;

typedef struct enet_txdma_cmd_t
{
    IODBDMADescriptor    desc_seg[3];
} enet_txdma_cmd_t;

class BMacEnet : public IOEthernetController
{
    OSDeclareDefaultStructors( BMacEnet )

private:
    volatile IOPPCAddress              ioBaseEnet;
    volatile IOPPCAddress              ioBaseHeathrow;
    volatile IODBDMAChannelRegisters * ioBaseEnetRxDMA;    
    volatile IODBDMAChannelRegisters * ioBaseEnetTxDMA;
    
    IOEthernetAddress         myAddress;
    IOEthernetInterface *     networkInterface;
    IOGatedOutputQueue *      transmitQueue;
    IOPacketQueue *           debugQueue;
    IOKernelDebugger *        debugger;
    bool                      isPromiscuous;
    bool                      multicastEnabled;
    bool                      isFullDuplex;    
    
    IOWorkLoop *              workLoop;
    IOInterruptEventSource *  rxIntSrc;
    IOMemoryMap *             maps[MEMORY_MAP_COUNT];
    IONetworkStats *          netStats;
    IOTimerEventSource *      timerSrc;
    IOMbufBigMemoryCursor *   mbufCursor;

    bool                      ready;
    bool                      netifEnabled;
    bool                      debugEnabled;
    bool                      debugTxPoll;
    bool                      useUnicastFilter;
    unsigned int              enetAddressOffset;

    unsigned long             chipId;

    unsigned long             phyType;
    unsigned long             phyMIIDelay;

    unsigned char             phyId;
    unsigned char             sromAddressBits;

    unsigned short            phyStatusPrev;

    OSDictionary *            mediumDict;

    struct mbuf *             txMbuf[TX_RING_LENGTH];
    struct mbuf *             rxMbuf[RX_RING_LENGTH];
    struct mbuf *             txDebuggerPkt;
    
    unsigned int              txCommandHead;    // TX ring descriptor index
    unsigned int              txCommandTail;
    unsigned int              txMaxCommand;        
    unsigned int              rxCommandHead;    // RX ring descriptor index
    unsigned int              rxCommandTail;
    unsigned int              rxMaxCommand;        

    struct {
        void *   ptr;
        u_int    size;
        void *   ptrReal;
        u_int    sizeReal;
    } dmaMemory;

    unsigned char *           dmaCommands;
    enet_txdma_cmd_t *        txDMACommands;    // TX descriptor ring ptr
    unsigned int              txDMACommandsPhys;

    enet_dma_cmd_t *          rxDMACommands;    // RX descriptor ring ptr
    unsigned int              rxDMACommandsPhys;

    u_int32_t                 txWDInterrupts;
    u_int32_t                 txWDCount;

    void *                    debuggerPkt;
    u_int32_t                 debuggerPktSize;

    u_int16_t                 statReg;      // Current STAT register contents
   
    u_int16_t                 hashTableUseCount[64];
    u_int16_t                 hashTableMask[4];

    unsigned long             currentPowerState;

    bool _allocateMemory();
    bool _initTxRing();
    bool _initRxRing();
    bool _initChip();
    void _resetChip();
    void _disableAdapterInterrupts();
    void _enableAdapterInterrupts();
    void _setDuplexMode(bool duplexMode);
    void _startChip();
    bool _updateDescriptorFromMbuf(struct mbuf * m,  enet_dma_cmd_t * desc,
                                   bool isReceive);
    void _restartTransmitter();
    void _stopTransmitDMA();
    bool _transmitPacket(struct mbuf * packet);
    bool _transmitInterruptOccurred();
    bool _debugTransmitInterruptOccurred();
    bool _receiveInterruptOccurred();
    bool _rejectBadUnicastPacket(ether_header_t * etherHeader);
    bool _receivePackets(bool fDebugger);
    void _packetToDebugger(struct mbuf * packet, u_int size);
    void _restartReceiver();
    void _stopReceiveDMA();
    bool _resetAndEnable(bool enable);
    void _sendDummyPacket();
    void _resetHashTableMask();
    void _addToHashTableMask(u_int8_t * addr);
    void _removeFromHashTableMask(u_int8_t * addr);
    void _updateBMacHashTableMask();
    bool createMediumTables();

#ifdef DEBUG
    void _dumpRegisters();
    void _dumpDesc(void * addr, u_int32_t size);
    void _dump_srom();
#endif DEBUG

    void _sendPacket(void * pkt, unsigned int pkt_len);
    void _receivePacket(void * pkt, unsigned int * pkt_len,
                        unsigned int timeout);

    void sendPacket(void * pkt, UInt32 pkt_len);
    void receivePacket(void * pkt, UInt32 * pkt_len,
                       UInt32 timeout);

    bool miiReadWord(unsigned short * dataPtr, unsigned short reg,
                     unsigned char phy);
    bool miiWriteWord(unsigned short data, unsigned short reg,
                      unsigned char phy);
    void miiWrite(unsigned int miiData, unsigned int dataSize);
    int  miiReadBit();
    bool miiCheckZeroBit();
    void miiOutThreeState();
    bool miiResetPHY(unsigned char phy);
    bool miiWaitForLink(unsigned char phy);
    bool miiWaitForAutoNegotiation(unsigned char phy);
    void miiRestartAutoNegotiation(unsigned char phy);
    bool miiFindPHY(unsigned char * phy_num);
    bool miiInitializePHY(unsigned char phy);

    UInt32 outputPacket(struct mbuf * m, void * param);

    void interruptOccurredForSource(IOInterruptEventSource * src, int count);

    void timeoutOccurred(IOTimerEventSource * timer);

    void monitorLinkStatus( bool firstPoll = false );

public:
    virtual bool init(OSDictionary * properties = 0);
    virtual bool start(IOService * provider);
    virtual void free();
    
    virtual bool         createWorkLoop();
    virtual IOWorkLoop * getWorkLoop() const;
    
    virtual IOReturn enable(IONetworkInterface * netif);
    virtual IOReturn disable(IONetworkInterface * netif);

    virtual IOReturn getHardwareAddress(IOEthernetAddress * addr);

    virtual IOReturn setMulticastMode(IOEnetMulticastMode mode);
    virtual IOReturn setMulticastList(IOEthernetAddress * addrs, UInt32 count);

    virtual IOReturn setPromiscuousMode(IOEnetPromiscuousMode mode);
    
    virtual IOOutputQueue * createOutputQueue();
    
    virtual const OSString * newVendorString() const;
    virtual const OSString * newModelString() const;
    virtual const OSString * newRevisionString() const;

    virtual IOReturn enable(IOKernelDebugger * debugger);
    virtual IOReturn disable(IOKernelDebugger * debugger);

    virtual bool configureInterface(IONetworkInterface * netif);

    // Simple power managment support:
    virtual IOReturn   setPowerState( UInt32 powerStateOrdinal,
                                      IOService * whatDevice );

    virtual IOReturn registerWithPolicyMaker(IOService * policyMaker);
};

/*
 * Performance tracepoints
 *
 * DBG_BMAC_RXIRQ       - Receive  ISR run time
 * DBG_BMAC_TXIRQ       - Transmit ISR run time
 * DBG_BMAC_TXQUEUE     - Transmit packet passed from network stack
 * DBG_BMAC_TXCOMPLETE  - Transmit packet sent
 * DBG_BMAC_RXCOMPLETE  - Receive packet passed to network stack
 */
#define DBG_BMAC_ENET          0x0900
#define DBG_BMAC_RXIRQ         DRVDBG_CODE(DBG_DRVNETWORK,(DBG_BMAC_ENET+1))     
#define DBG_BMAC_TXIRQ         DRVDBG_CODE(DBG_DRVNETWORK,(DBG_BMAC_ENET+2))    
#define DBG_BMAC_TXQUEUE       DRVDBG_CODE(DBG_DRVNETWORK,(DBG_BMAC_ENET+3))    
#define DBG_BMAC_TXCOMPLETE    DRVDBG_CODE(DBG_DRVNETWORK,(DBG_BMAC_ENET+4))    
#define DBG_BMAC_RXCOMPLETE    DRVDBG_CODE(DBG_DRVNETWORK,(DBG_BMAC_ENET+5))    

#endif /* !_BMACENET_H */
