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
 * Copyright (c) 1998-1999 Apple Software, Inc.
 *
 * Interface definition for the UniN Ethernet Controller 
 *
 * HISTORY
 *
 */

#include <IOKit/network/IOEthernetController.h>
#include <IOKit/network/IOEthernetInterface.h>
#include <IOKit/network/IOGatedOutputQueue.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/network/IOMbufMemoryCursor.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOLib.h>            /* bcopy */

extern "C" 
{
    #include <sys/param.h>
    #include <sys/mbuf.h>
}

//#define IOLog kprintf

// No kernel tracing support at this time.
//
#define KERNEL_DEBUG(x,a,b,c,d,e)

#include "UniNEnetRegisters.h"



#define NETWORK_STAT_ADD(  x )	(fpNetStats->x++)
#define ETHERNET_STAT_ADD( x )	(fpEtherStats->x++)

#define READ_REGISTER(  REG )		OSReadLittleInt32(  (void*)&fpRegs->REG, 0 )
#define DBG_WRITE 0
#if DBG_WRITE
#define WRITE_REGISTER( REG, VAL )	writeRegister( &fpRegs->REG, VAL )
#else
#define WRITE_REGISTER( REG, VAL )	OSWriteLittleInt32( (void*)&fpRegs->REG, 0, VAL )
#endif // DBG_WRITE


typedef void  *         IOPPCAddress;

#define NUM_RX_DESC     1
typedef struct enet_dma_cmd_t
{
    GEMRxDescriptor     desc_seg[NUM_RX_DESC];
} enet_dma_cmd_t;

#define NUM_TX_DESC     1
typedef struct enet_txdma_cmd_t
{
    GEMTxDescriptor     desc_seg[NUM_TX_DESC];
} enet_txdma_cmd_t;


typedef struct TxQueueElement
{
    queue_chain_t   next;
    queue_head_t *  list;
    
    struct mbuf *   mbuf;
    UInt32          slot;
    UInt32          count;
} TxQueueElement;

enum LinkStatus
{
    kLinkStatusUnknown,
    kLinkStatusDown,
    kLinkStatusUp,
};

#define kMaxUniNEnetPowerState  1
#define kUniNsettle_time        500    //guess 500 microseconds for settling


class UniNEnet: public IOEthernetController
{
    OSDeclareDefaultStructors( UniNEnet )

private:
	volatile GMAC_Registers	*fpRegs;
    IOPCIDevice *             nub;
    IOMemoryMap *             ioMapEnet;
    volatile IOPPCAddress     ioBaseEnet;

    IOEthernetInterface *     networkInterface;
    IOBasicOutputQueue *      transmitQueue;
    IOPacketQueue *           debugQueue;
    IOKernelDebugger *        debugger;

    IOWorkLoop *              workLoop;
    IOInterruptEventSource *  interruptSource;
    IONetworkStats *          fpNetStats;
	IOEthernetStats *         fpEtherStats;
    IOTimerEventSource *      timerSource;
    IOMbufBigMemoryCursor *   mbufCursor;
	IOSimpleLock *            txQueueLock;

    bool                      ready;
    bool                      netifEnabled;
    bool                      debugEnabled;
    bool                      debugTxPoll;
        
    IOEthernetAddress         myAddress;
    bool                      isPromiscuous;
    bool                      multicastEnabled;
    bool                      isFullDuplex;

    UInt32                    phyType;
    UInt8                     phyId;

    UInt16                    phyStatusPrev;
    UInt32                    linkStatusPrev;

    UInt16                    phyBCMType;  // 5400 or 5201 for PM

    OSDictionary *            mediumDict;

    queue_head_t              txActiveQueue;
    queue_head_t              txFreeQueue;
    
    TxQueueElement *          txElementPtrs[TX_RING_LENGTH];
    struct mbuf *             rxMbuf[RX_RING_LENGTH];
    struct mbuf *             txDebuggerPkt;

    void *                    debuggerPkt;
    u_int32_t                 debuggerPktSize;
    
    UInt32                    txCommandHead;  // TX ring descriptor index
    UInt32                    txCommandTail;
    UInt32                    rxCommandHead;  // RX ring descriptor index
    UInt32                    rxCommandTail;

    UInt32                    dmaCommandsSize;
    UInt8 *                   dmaCommands;
    enet_txdma_cmd_t *        txDMACommands;  // TX descriptor ring ptr
    UInt32                    txDMACommandsPhys;
    UInt32                    txCommandsAvail;

    enet_dma_cmd_t *          rxDMACommands;  // RX descriptor ring ptr
    UInt32                    rxDMACommandsPhys;

    UInt32                    txIntCnt;
    UInt32                    txRingIndexLast;
    UInt32                    txWDInterrupts;
    UInt32                    txWDCount;
    
    UInt32                    rxWDInterrupts;
    UInt32                    rxWDCount;
    UInt32                    rxMacConfigReg;

    UInt16                    hashTableUseCount[256];
    UInt16                    hashTableMask[16];

    unsigned long             currentPowerState;  /* must be 0 or 1 */

    bool             allocateMemory();
    bool             initTxRing();
    bool             initRxRing();
    void             flushRings();
    bool             initChip();
    bool             resetChip();
    void             disableAdapterInterrupts();
    void             enableAdapterInterrupts();
    void             setDuplexMode(bool duplexMode);
    void             startChip();
    void             stopChip();
    bool             updateDescriptorFromMbuf(struct mbuf * m,
                                              enet_dma_cmd_t * desc,
                                              bool isReceive);
    void             monitorLinkStatus( bool firstPoll = false );
    void             restartTransmitter();
    void             stopTransmitDMA();
    bool             transmitPacket(struct mbuf * packet);
    bool             transmitInterruptOccurred();
    bool             debugTransmitInterruptOccurred();
    void             debugTransmitCleanup();
    bool             receiveInterruptOccurred();
    bool             receivePackets(bool fDebugger);
    void             packetToDebugger(struct mbuf * packet, u_int size);
    void             restartReceiver();
    void             stopReceiveDMA();
    bool             resetAndEnable(bool enable);
    void             sendDummyPacket();
    void             resetHashTableMask();
    void             addToHashTableMask(u_int8_t *addr);
    void             removeFromHashTableMask(u_int8_t *addr);
    void             updateHashTableMask();


    TxQueueElement * getTxElement();
    void             releaseTxElement(TxQueueElement * txElement);
    
#ifdef DEBUG
    void             dumpRegisters();
#endif DEBUG

    void             sendPacket(void * pkt, UInt32 pkt_len);
    void             receivePacket(void * pkt, UInt32 * pkt_len,
                                   UInt32 timeout);

    bool             miiReadWord(unsigned short * dataPtr,
                                 unsigned short reg, UInt8 phy);
    bool             miiWriteWord(unsigned short data,
                                  unsigned short reg, UInt8 phy);
    void             miiWrite(UInt32 miiData, UInt32 dataSize);
    bool             miiResetPHY(UInt8 phy);
    bool             miiWaitForLink(UInt8 phy);
    bool             miiWaitForAutoNegotiation(UInt8 phy);
    void             miiRestartAutoNegotiation(UInt8 phy);
    bool             miiFindPHY(UInt8 * phy_num);
    bool             miiInitializePHY(UInt8 phy);

    UInt32           outputPacket(struct mbuf * m, void * param);

    void             interruptOccurred(IOInterruptEventSource * src,
                                       int count);
    void             timeoutOccurred(IOTimerEventSource * timer);
    bool             createMediumTables();

	void	writeRegister( UInt32 *pReg, UInt32 data );

    void             stopPHYChip(bool  setupWOL); 
    void             startPHYChip();
    bool             resetPHYChip();

    // callPlatformFunction symbols
    const OSSymbol 	*keyLargo_resetUniNEthernetPhy;

    IOService                    *keyLargo;

public:
    virtual bool             init(OSDictionary * properties = 0);
    virtual bool             start(IOService * provider);
    virtual void             free();

    virtual bool             createWorkLoop();
    virtual IOWorkLoop *     getWorkLoop() const;

    virtual IOReturn         enable(IONetworkInterface * netif);
    virtual IOReturn         disable(IONetworkInterface * netif);

    virtual IOReturn         getHardwareAddress(IOEthernetAddress *addr);

    virtual IOReturn         setMulticastMode(IOEnetMulticastMode mode);
    virtual IOReturn         setMulticastList(IOEthernetAddress *addrs, UInt32 count);

    virtual IOReturn         setPromiscuousMode(IOEnetPromiscuousMode mode);
    
    virtual IOOutputQueue *  createOutputQueue();
    
    virtual const OSString * newVendorString() const;
    virtual const OSString * newModelString() const;
    virtual const OSString * newRevisionString() const;

    virtual IOReturn         enable(IOKernelDebugger * debugger);
    virtual IOReturn         disable(IOKernelDebugger * debugger);

    virtual bool             configureInterface(IONetworkInterface * netif);

    // Power management methods:
    virtual IOReturn   registerWithPolicyMaker(IOService * policyMaker);
    virtual UInt32     maxCapabilityForDomainState(IOPMPowerFlags state);
    virtual UInt32     initialPowerStateForDomainState(IOPMPowerFlags state);
    virtual UInt32     powerStateForDomainState(IOPMPowerFlags state);
    virtual IOReturn   setPowerState(UInt32 powerStateOrdinal,
                                     IOService * whatDevice);
};


/*
 * Performance tracepoints
 *
 * DBG_UniN_RXIRQ       - Receive  ISR run time
 * DBG_UniN_TXIRQ       - Transmit ISR run time
 * DBG_UniN_TXQUEUE     - Transmit packet passed from network stack
 * DBG_UniN_TXCOMPLETE  - Transmit packet sent
 * DBG_UniN_RXCOMPLETE  - Receive packet passed to network stack
 */
#define DBG_UniN_ENET          0x0900
#define DBG_UniN_RXIRQ         DRVDBG_CODE(DBG_DRVNETWORK,(DBG_UniN_ENET+1))
#define DBG_UniN_TXIRQ         DRVDBG_CODE(DBG_DRVNETWORK,(DBG_UniN_ENET+2))
#define DBG_UniN_TXQUEUE       DRVDBG_CODE(DBG_DRVNETWORK,(DBG_UniN_ENET+3))
#define DBG_UniN_TXCOMPLETE    DRVDBG_CODE(DBG_DRVNETWORK,(DBG_UniN_ENET+4)) 
#define DBG_UniN_RXCOMPLETE    DRVDBG_CODE(DBG_DRVNETWORK,(DBG_UniN_ENET+5)) 
