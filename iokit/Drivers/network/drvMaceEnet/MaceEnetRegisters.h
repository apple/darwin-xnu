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
 * Interface definition for the Mace Ethernet controller. 
 *
 * HISTORY
 *
 * 04-Nov-97	
 *	Created.
 */

#ifndef _MACEENETREGISTERS_H
#define _MACEENETREGISTERS_H

// ---------------------------------------------------------------------------------------------
//	Mace and GC I/O Addresses
// ---------------------------------------------------------------------------------------------
#define kTxDMABaseOffset		0x08200			// offset from I/O Space Base address
#define kRxDMABaseOffset		0x08300
#define kControllerBaseOffset		0x11000
#define kControllerROMOffset		0x19000	


// ---------------------------------------------------------------------------------------------
//	Mace Register Numbers & Bit Assignments
// ---------------------------------------------------------------------------------------------
/*
 * Chip Revisions..
 */

#define	kMaceRevisionB0		0x0940
#define	kMaceRevisionA2		0x0941

/* xmtfc */
#define kXmtFC			0x0020			/* Transmit Frame Control 		*/
#define kXmtFCDRtry		0X80			/* - Disable Retry			*/
#define kXmtFCDXmtFCS		0x08			/* - Disable Transmit FCS		*/
#define kXmtFCAPadXmt		0x01			/* - Auto PAD Transmit			*/

/* xmtfs */
#define kXmtFS			0x0030			/* Transmit Frame Status		*/
#define kXmtFSXmtSV  		0x80			/* - Transmit Status Valid		*/
#define kXmtFSUFlo  		0x40			/* - Transmit Underflow			*/
#define kXmtFSLCol	   	0x20			/* - Transmit late collision		*/
#define kXmtFSMore	   	0x10			/* - Transmit < 1 retry			*/
#define kXmtFSOne	    	0x08			/* - Transmit single retry		*/
#define kXmtFSDefer	  	0x04			/* - Transmit deferred			*/
#define kXmtFSLCar	   	0x02			/* - Transmit lost carrier		*/
#define kXmtFSRtry	   	0x01			/* - Transmit Unsuccessful		*/

/* xmtrc */
#define kXmtRC			0x0040			/* Transmit Retry Count			*/
#define kXmtRCExDef		0x80			/* - ?					*/
#define kXmtRCXmrRC		0x0F			/* - Transmit retry count		*/

/* rcvfc */
#define kRcvFC			0x0050			/* Receive Frame Control		*/
#define kRcvFCLLRcv	       	0x08			/* - ?					*/
#define kRcvFCMR	       	0x04			/* - Match/Reject (not implemented)	*/
#define kRcvFCAStrpRcv   	0x01			/* - Auto Strip Receive	Enable		*/

/* rcvfs */
#define kRcvFS0			0x0060			/* Receive Frame Status - Byte 0	*/
#define kRcvFS0RcvCnt		0xFF			/* - Receive Msg Byte Count (7:0)	*/

#define kRcvFS1			0x0060			/* Receive Frame Status - Byte 1	*/
#define kRcvFS1OFlo		0x80			/* - Receive Overflow			*/
#define kRcvFS1Clsn	   	0x40			/* - Receive Collision			*/
#define kRcvFS1Fram	   	0x20			/* - Receive Framming Error		*/
#define kRcvFS1FCS	   	0x10			/* - Receive Frame Check Error		*/
#define kRcvFS1RcvCnt	 	0x0f			/* - Receive Msg Byte Count (11:8)	*/


#define kRcvFS2			0x0060			/* Receive Frame Status - Byte 2 	*/
#define kRcvFS2RntPC		0xFF			/* - Runt Packet Count			*/

#define kRcvFS3			0x0060			/* Receive Frame Status - Byte 3	*/
#define kRcvFS3RcvCC		0xFF			/* Receive Collision Count		*/

/* fifofc */
#define kFifoFC			0x0070			/* FIFO Frame Count			*/
#define kFifoFCXFW		0xc0			/* - ?					*/
#define	kFifoFCXFW8		0x00 			/* - ?					*/
#define	kFifoFCXFW16		0x40 			/* - ?					*/
#define	kFifoFCXFW32		0x80			/* - ?					*/
 
#define kFifoFCRFW		0x30			/* - ?					*/
#define	kFifoFCRFW16		0x00 			/* - ?					*/
#define	kFifoFCRFW32		0x10 			/* - ?					*/
#define	kFifoFCRFW64		0x20 			/* - ?					*/
#define kFifoFCXFWU		0x08			/* - ?					*/	
#define kFifoFCRFWU		0x04			/* - ?					*/
#define kFifoFCXBRst		0x02			/* - ?					*/
#define kFifoFCRBRst		0x01			/* - ?					*/


/* ir */
#define kIntReg			0x0080			/* Interrupt Register			*/
#define kIntRegJab    		0x80			/* - Jabber Error			*/
#define kIntRegBabl	   	0x40			/* - Babble Error			*/
#define kIntRegCErr	   	0x20			/* - Collision Error			*/
#define kIntRegRcvCCO 		0x10			/* - Receive Collision Count Overflow	*/	
#define kIntRegRntPCO	 	0x08			/* - Runt Packet Count Overflow		*/
#define kIntRegMPCO   		0x04			/* - Missed Packet Count Overflow	*/
#define kIntRegRcvInt	 	0x02			/* - Receive Interrupt			*/
#define kIntRegXmtInt	 	0x01			/* - Transmit Interrupt			*/

/* imr */
#define kIntMask		0x0090			/* Interrupt Mask Register		*/
#define kIntMaskJab    		0x80			/* - Mask Jabber Error Int		*/
#define kIntMaskBabl   		0x40			/* - Mask Babble Error Int		*/
#define kIntMaskCErr	   	0x20			/* - Mask Collision Error Int		*/
#define kIntMaskRcvCCO	 	0x10			/* - Mask Rcv Coll Ctr Overflow Int	*/
#define kIntMaskRntPCO 		0x08			/* - Mask Runt Packet Ctr Overflow Int	*/
#define kIntMaskMPCO   		0x04			/* - Mask Missed Pkt Ctr Overflow Int	*/
#define kIntMaskRcvInt 		0x02			/* - Mask Receive Int			*/
#define kIntMaskXmtInt 		0x01			/* - Mask Transmit Int			*/

/* pr */
#define kPollReg		0x00A0			/* Poll Register			*/
#define kPollRegXmtSV  		0x80			/* - Transmit Status Valid		*/
#define kPollRegTDTReq	 	0x40			/* - Transmit Data Transfer Request	*/
#define kPollRegRDTReq	 	0x20			/* - Receive Data Transfer Request	*/

/* biucc */
#define kBIUCC			0x00B0			/* BUI Configuration Control		*/
#define kBIUCCBSwp	        0x40			/* - Byte Swap Enable			*/
#define kBIUCCXmtSP		0x30			/* - Transmit Start Point:		*/
#define kBIUCCXmtSP04	        0x00			/* - 00b = 4 Bytes			*/	
#define kBIUCCXmtSP16   	0x10			/* - 01b = 16 Bytes			*/
#define kBIUCCXmtSP64     	0x20			/* - 10b = 64 Bytes			*/
#define kBIUCCXmtSP112    	0x30			/* - 11b = 112 Bytes			*/
#define kBIUCCSWRst		0x01			/* Software Reset			*/

/* fifocc */
#define kFifoCC			0x00C0			/* FIFO Configuration Control		*/
#define kFifoCCXmtFW		0xC0			/* - Transmit FIFO Watermark:		*/
#define kFifoCCXmtFW08    	0x00			/* - 00b = 8 Write Cycles		*/
#define kFifoCCXmtFW16		0x40			/* - 01b = 16 Write Cycles		*/
#define kFifoCCXmtFW32		0x80			/* - 10b = 32 Write Cycles		*/

#define kFifoCCRcvFW		0x30			/* - Receive FIFO Watermark:		*/
#define kFifoCCRcvFW16     	0x00     		/* - 00b = 16 Bytes			*/
#define kFifoCCRcvFW32    	0x10			/* - 01b = 32 Bytes			*/
#define kFifoCCRcvFW64    	0x20			/* - 10b = 64 Bytes			*/

#define kFifoCCXmtFWRst     	0x08			/* - Transmit FIFO Watermark Reset	*/
#define kFifoCCRcvFWRst      	0x04			/* - Receive FIFO Watermark Reset	*/
#define kFifoCCXmtBRst		0x02			/* - Transmit Burst Enable		*/
#define kFifoCCRcvBRst	     	0x01			/* - Receive Burst Enable		*/

/* maccc */
#define kMacCC			0x00D0			/* MAC Configuration Control		*/
#define kMacCCProm        	0x80			/* - Promiscuous Mode Enable		*/
#define kMacCCDXmt2PD     	0x40			/* - Disable Transmit Two Part Deferral */
#define kMacCCEMBA        	0x20			/* - Enable Modified Backoff Algorithm	*/
#define kMacCCDRcvPA      	0x08			/* - ?					*/
#define kMacCCDRcvBC   		0x04			/* - ?					*/
#define kMacCCEnXmt     	0x02			/* - Transmit Enable			*/
#define kMacCCEnRcv	       	0x01			/* - Receive Enable			*/

/* plscc */
#define kPLSCC			0x00E0			/* PLS Configuration Control		*/
#define kPLSCCXmtSel      	0x08			/* - Transmit Mode Select		*/
#define kPLSCCPortSel		0x06			/* - Port Select:			*/
#define kPLSCCPortSelAUI       	0x00			/* - 00b = AUI				*/
#define kPLSCCPortSelTenBase   	0x02			/* - 01b = 10BaseT			*/
#define kPLSCCPortSelDAI        0x04			/* - 10b = DAI				*/
#define kPLSCCPortSelGPSI      	0x06			/* - 11b = GPSI				*/
#define kPLSCCEnSts    		0x01			/* - Enable Status			*/			

/* phycc */
#define kPHYCC			0x00F0			/* PHY Configuration Control		*/
#define kPHYCCLnkFL       	0x80			/* - ?					*/
#define kPHYCCDLnkTst     	0x40			/* - ?					*/
#define kPHYCCRcvPol		0x20			/* - ?					*/
#define kPHYCCDAPC        	0x10			/* - ?					*/
#define kPHYCCLRT         	0x08			/* - ?					*/
#define kPHYCCASel        	0x04			/* - ?					*/
#define kPHYCCRWake       	0x02			/* - ?					*/
#define kPHYCCAWake       	0x01			/* - ?					*/

#define kMaceChipId0		0x0100			/* MACE Chip ID Register (7:0)		*/
#define kMaceChipId1		0x0110			/* MACE Chip ID Register (15:8)		*/

/* iac */
#define kIAC			0x0120			/* Internal Address Configuration	*/
#define kIACAddrChg		0x80			/* - ?					*/
#define kIACPhyAddr     	0x04			/* - Physical Address Reset		*/
#define kIACLogAddr		0x02			/* - Logical Address Reset		*/


/* ladrf */
#define kLADRF			0x0140			/* Logical Address Filter - 8 Bytes	*/

/* padr */
#define kPADR			0x0150			/* Physical Address Filter - 6 Bytes	*/

/* kMPC */			
#define	kMPC			0x0180			/* Missed Packet Count			*/

/* utr */
#define kUTR			0x01D0			/* User Test Register			*/
#define kUTRRTRE        	0x80			/* - Reserved Test Register Enable	*/
#define kUTRRTRD        	0x40			/* - Reserved Test Register Disable	*/
#define kUTRRPA         	0x20			/* - Runt Packet Accept			*/
#define kUTRFColl       	0x10			/* - Force Collision			*/
#define kUTRRcvFCS     		0x08			/* - Receive FCS Enable			*/

#define kUTRLoop		0x06			/* - Loopback Control:			*/
#define kUTRLoopNone      	0x00			/* - 00b = None				*/
#define kUTRLoopExt		0x02			/* - 01b = External			*/
#define kUTRLoopInt      	0x04			/* - 10b = Internal (excludes MENDEC)	*/
#define kUTRLoopIntM    	0x06			/* - 11b = Internal (includes MENDEC)	*/


#define TX_RING_LENGTH		(32+1)
#define RX_RING_LENGTH		(32+1)

#define NETWORK_BUFSIZE		(ETHERMAXPACKET + ETHERCRC + 8)
#define TRANSMIT_QUEUE_SIZE		128

#define WATCHDOG_TIMER_MS	500
#define TX_KDB_TIMEOUT		1000

#define TRANSMIT_QUIESCE_uS	200
#define RECEIVE_QUIESCE_uS	1500

enum
{
    kIRQEnetDev   = 0,
    kIRQEnetTxDMA = 1,
    kIRQEnetRxDMA = 2
};

enum
{
	MEMORY_MAP_ENET_INDEX 	= 0,
	MEMORY_MAP_TXDMA_INDEX	= 1,
	MEMORY_MAP_RXDMA_INDEX	= 2,
	MEMORY_MAP_COUNT		= 3
};

#endif /* !_MACEENETREGISTERS_H */
