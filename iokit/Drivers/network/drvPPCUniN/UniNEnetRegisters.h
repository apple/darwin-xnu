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
 * Copyright (c) 1998-1999 Apple Computer
 *
 * Interface definition for the Sun GEM (UniN) Ethernet controller.
 *
 *
 */

/*
 *      Miscellaneous defines...
 */
#define CACHE_LINE_SIZE         32       /* Bytes */

#define RX_RING_LENGTH_FACTOR	1		// valid from 0 to 8
#define RX_RING_LENGTH			(32 * (1 << RX_RING_LENGTH_FACTOR))	// 128 pkt descs		/* Packet descriptors	*/
#define RX_RING_WRAP_MASK		(RX_RING_LENGTH -1)

#define TX_RING_LENGTH_FACTOR	2		// valid from 0 to 8
#define TX_RING_LENGTH			(32 * (1 << TX_RING_LENGTH_FACTOR))	// 128 pkt descs
#define TX_RING_WRAP_MASK		(TX_RING_LENGTH -1)

#define TX_MAX_MBUFS            (TX_RING_LENGTH / 2)

#define TX_DESC_PER_INT         32

#define NETWORK_BUFSIZE         (((ETHERMAXPACKET + ETHERCRC) + 7) & ~7)

#define TRANSMIT_QUEUE_SIZE     256

#define WATCHDOG_TIMER_MS       300
#define TX_KDB_TIMEOUT          1000

#define PCI_PERIOD_33MHz        30
#define PCI_PERIOD_66MHz        15
#define RX_INT_LATENCY_uS       250             


	struct GMAC_Registers
	{
			/* Global Resources:	*/								// 0x0000

		UInt32	SEB_State;		//	3 bits for diagnostics
		UInt32	Configuration;	//
		UInt32	filler1;
		UInt32	Status;

		UInt32	InterruptMask;										// 0x0010
		UInt32	InterruptAck;
		UInt32	filler2;
		UInt32	StatusAlias;

		UInt8	filler3[ 0x1000 - 0x20 ];

		UInt32	PCIErrorStatus;										// 0x1000
		UInt32	PCIErrorMask;
		UInt32	BIFConfiguration;
		UInt32	BIFDiagnostic;

		UInt32	SoftwareReset;										// 0x1010

		UInt8	filler4[ 0x2000 - 0x1014 ];

			/* Transmit DMA registers:	*/

		UInt32	TxKick;												// 0x2000
		UInt32	TxConfiguration;
		UInt32	TxDescriptorBaseLow;
		UInt32	TxDescriptorBaseHigh;

		UInt32	filler5;											// 0x2010
		UInt32	TxFIFOWritePointer;
		UInt32	TxFIFOShadowWritePointer;
		UInt32	TxFIFOReadPointer;

		UInt32	TxFIFOShadowReadPointer;							// 0x2020
		UInt32	TxFIFOPacketCounter;
		UInt32	TxStateMachine;
		UInt32	filler6;

		UInt32	TxDataPointerLow;									// 0x2030
		UInt32	TxDataPointerHigh;

		UInt8	filler7[ 0x2100 - 0x2038 ];

		UInt32	TxCompletion;										// 0x2100
		UInt32	TxFIFOAddress;
		UInt32	TxFIFOTag;
		UInt32	TxFIFODataLow;

		UInt32	TxFIFODataHighT1;									// 0x2110
		UInt32	TxFIFODataHighT0;
		UInt32	TxFIFOSize;

		UInt8	filler8[ 0x4000 - 0x211C ];

			/* Receive DMA registers: */

		UInt32	RxConfiguration;									// 0x4000
		UInt32	RxDescriptorBaseLow;
		UInt32	RxDescriptorBaseHigh;
		UInt32	RxFIFOWritePointer;

		UInt32	RxFIFOShadowWritePointer;							// 0x4010
		UInt32	RxFIFOReadPointer;
		UInt32	RxFIFOPacketCounter;
		UInt32	RxStateMachine;

		UInt32	PauseThresholds;									// 0x4020
		UInt32	RxDataPointerLow;
		UInt32	RxDataPointerHigh;

		UInt8	filler9[ 0x4100 - 0x402C ];

		UInt32	RxKick;												// 0x4100
		UInt32	RxCompletion;
		UInt32	RxBlanking;
		UInt32	RxFIFOAddress;

		UInt32	RxFIFOTag;											// 0x4110
		UInt32	RxFIFODataLow;
		UInt32	RxFIFODataHighT0;
		UInt32	RxFIFODataHighT1;

		UInt32	RxFIFOSize;											// 0x4120

		UInt8	filler10[ 0x6000 - 0x4124 ];

			/* MAC registers: */

		UInt32	TxMACSoftwareResetCommand;							// 0x6000
		UInt32	RxMACSoftwareResetCommand;
		UInt32	SendPauseCommand;
		UInt32	filler11;

		UInt32	TxMACStatus;										// 0x6010
		UInt32	RxMACStatus;
		UInt32	MACControlStatus;
		UInt32	filler12;

		UInt32	TxMACMask;											// 0x6020
		UInt32	RxMACMask;
		UInt32	MACControlMask;
		UInt32	filler13;

		UInt32	TxMACConfiguration;									// 0x6030
		UInt32	RxMACConfiguration;
		UInt32	MACControlConfiguration;
		UInt32	XIFConfiguration;

		UInt32	InterPacketGap0;									// 0x6040
		UInt32	InterPacketGap1;
		UInt32	InterPacketGap2;
		UInt32	SlotTime;

		UInt32	MinFrameSize;										// 0x6050
		UInt32	MaxFrameSize;
		UInt32	PASize;
		UInt32	JamSize;

		UInt32	AttemptLimit;										// 0x6060
		UInt32	MACControlType;
		UInt8	filler14[ 0x6080 - 0x6068 ];

		UInt32	MACAddress[ 9 ];									// 0x6080

		UInt32	AddressFilter[ 3 ];									// 0x60A4

		UInt32	AddressFilter2_1Mask;								// 0x60B0
		UInt32	AddressFilter0Mask;
		UInt32	filler15[ 2 ];

		UInt32	HashTable[ 16 ];									// 0x60C0

			/* Statistics registers:	*/

		UInt32	NormalCollisionCounter;								// 0x6100
		UInt32	FirstAttemptSuccessfulCollisionCounter;
		UInt32	ExcessiveCollisionCounter;
		UInt32	LateCollisionCounter;

		UInt32	DeferTimer;											// 0x6110
		UInt32	PeakAttempts;
		UInt32	ReceiveFrameCounter;
		UInt32	LengthErrorCounter;

		UInt32	AlignmentErrorCounter;								// 0x6120
		UInt32	FCSErrorCounter;
		UInt32	RxCodeViolationErrorCounter;
		UInt32	filler16;

			/* Miscellaneous registers:	*/

		UInt32	RandomNumberSeed;									// 0x6130
		UInt32	StateMachine;

		UInt8	filler17[ 0x6200 - 0x6138 ];

			/* MIF registers: */

		UInt32	MIFBitBangClock;									// 0x6200
		UInt32	MIFBitBangData;
		UInt32	MIFBitBangOutputEnable;
		UInt32	MIFBitBangFrame_Output;

		UInt32	MIFConfiguration;									// 0x6210
		UInt32	MIFMask;
		UInt32	MIFStatus;
		UInt32	MIFStateMachine;

		UInt8	filler18[ 0x9000 - 0x6220 ];

			/* PCS/Serialink registers:	*/

		UInt32	PCSMIIControl;										// 0x9000
		UInt32	PCSMIIStatus;
		UInt32	Advertisement;
		UInt32	PCSMIILinkPartnerAbility;

		UInt32	PCSConfiguration;									// 0x9010
		UInt32	PCSStateMachine;
		UInt32	PCSInterruptStatus;

		UInt8	filler19[ 0x9050 - 0x901C ];

		UInt32	DatapathMode;										// 0x9050
		UInt32	SerialinkControl;
		UInt32	SharedOutputSelect;
		UInt32	SerialinkState;
	};	/* end GMAC_Registers	*/


#define kConfiguration_Infinite_Burst	0x00000001
#define kConfiguration_TX_DMA_Limit		(0x1F << 1)
#define kConfiguration_RX_DMA_Limit		(0x1F << 6)

	/* The following bits are used in the								*/
	/* Status, InterruptMask, InterruptAck, and StatusAlias registers:	*/

#define kStatus_TX_INT_ME				0x00000001
#define kStatus_TX_ALL					0x00000002
#define kStatus_TX_DONE					0x00000004
#define kStatus_RX_DONE					0x00000010
#define kStatus_Rx_Buffer_Not_Available	0x00000020
#define kStatus_RX_TAG_ERROR			0x00000040
#define kStatus_PCS_INT					0x00002000
#define kStatus_TX_MAC_INT				0x00004000
#define kStatus_RX_MAC_INT				0x00008000
#define kStatus_MAC_CTRL_INT			0x00010000
#define kStatus_MIF_Interrupt			0x00020000
#define kStatus_PCI_ERROR_INT			0x00040000
#define kStatus_TxCompletion_Shift		19

#define kInterruptMask_None				0xFFFFFFFF

#define kBIFConfiguration_SLOWCLK	0x1
#define kBIFConfiguration_B64D_DIS	0x2
#define kBIFConfiguration_M66EN		0x8

#define kSoftwareReset_TX		0x1
#define kSoftwareReset_RX		0x2
#define kSoftwareReset_RSTOUT	0x4

		// register TxConfiguration 2004:
#define kTxConfiguration_Tx_DMA_Enable				0x00000001
#define kTxConfiguration_Tx_Desc_Ring_Size_Shift	1			// bits 1:4
#define kTxConfiguration_TxFIFO_Threshold			0x001FFC00	// obsolete

		// register RxConfiguration 4000:
#define kRxConfiguration_Rx_DMA_Enable				0x00000001
#define kRxConfiguration_Rx_Desc_Ring_Size_Shift	1			// bits 1:4
#define kRxConfiguration_Batch_Disable				0x00000020
#define kRxConfiguration_First_Byte_Offset_Mask		0x00001C00
#define kRxConfiguration_Checksum_Start_Offset_Mask	0x000FE000
#define kRxConfiguration_RX_DMA_Threshold			0x01000000	// 128 bytes

#define kPauseThresholds_Factor					64
#define kPauseThresholds_OFF_Threshold_Shift	0	// 9 bit field
#define kPauseThresholds_ON_Threshold_Shift		12

#define FACTOR33 ((RX_INT_LATENCY_uS * 1000) / (2048 * PCI_PERIOD_33MHz))
#define FACTOR66 ((RX_INT_LATENCY_uS * 1000) / (2048 * PCI_PERIOD_66MHz))

#define F33 (FACTOR33 << kPauseThresholds_ON_Threshold_Shift )
#define F66 (FACTOR66 << kPauseThresholds_ON_Threshold_Shift )

#define kRxBlanking_default_33	(F33 | 5)
#define kRxBlanking_default_66	(F66 | 5)

#define kTxMACSoftwareResetCommand_Reset	1	// 1 bit register
#define kRxMACSoftwareResetCommand_Reset	1

#define kSendPauseCommand_default	0x1BF0
														// 0x6010:
#define kTX_MAC_Status_Frame_Transmitted		0x001
#define kTX_MAC_Status_Tx_Underrun				0x002
#define kTX_MAC_Status_Max_Pkt_Err				0x004
#define kTX_MAC_Status_Normal_Coll_Cnt_Exp		0x008
#define kTX_MAC_Status_Excess_Coll_Cnt_Exp		0x010
#define kTX_MAC_Status_Late_Coll_Cnt_Exp		0x020
#define kTX_MAC_Status_First_Coll_Cnt_Exp		0x040
#define kTX_MAC_Status_Defer_Timer_Exp			0x080
#define kTX_MAC_Status_Peak_Attempts_Cnt_Exp	0x100
														// 0x6014:
#define kRX_MAC_Status_Frame_Received			0x01
#define kRX_MAC_Status_Rx_Overflow				0x02	// Rx FIFO overflow
#define kRX_MAC_Status_Frame_Cnt_Exp			0x04
#define kRX_MAC_Status_Align_Err_Cnt_Exp		0x08
#define kRX_MAC_Status_CRC_Err_Cnt_Exp			0x10
#define kRX_MAC_Status_Length_Err_Cnt_Exp		0x20
#define kRX_MAC_Status_Viol_Err_Cnt_Exp			0x40


#ifdef CRAP
#define kTxMACMask_default			0x1FF		// was 0xFFFF
#define kRxMACMask_default			0x7F		// was 0xFFFF
#define kMACControlMask_default		0X00000007	// was 0xFFFF
#else
#define kTxMACMask_default			1			// enable all but Frame_Transmitted
#define kRxMACMask_default			1			// enable all but Frame_Received
#define kMACControlMask_default		0xFFFFFFF8	// enable Paused stuff
#endif // CRAP

#define kTxMACConfiguration_TxMac_Enable			0x001
#define kTxMACConfiguration_Ignore_Carrier_Sense	0x002
#define kTxMACConfiguration_Ignore_Collisions		0x004
#define kTxMACConfiguration_Enable_IPG0				0x008
#define kTxMACConfiguration_Never_Give_Up			0x010
#define kTxMACConfiguration_Never_Give_Up_Limit		0x020
#define kTxMACConfiguration_No_Backoff				0x040
#define kTxMACConfiguration_Slow_Down				0x080
#define kTxMACConfiguration_No_FCS					0x100
#define kTxMACConfiguration_TX_Carrier_Extension	0x200

#define kRxMACConfiguration_Rx_Mac_Enable			0x001
#define kRxMACConfiguration_Strip_Pad				0x002
#define kRxMACConfiguration_Strip_FCS				0x004
#define kRxMACConfiguration_Promiscuous				0x008
#define kRxMACConfiguration_Promiscuous_Group		0x010
#define kRxMACConfiguration_Hash_Filter_Enable		0x020
#define kRxMACConfiguration_Address_Filter_Enable	0x040
#define kRxMACConfiguration_Disable_Discard_On_Err	0x080
#define kRxMACConfiguration_Rx_Carrier_Extension	0x100

#define kMACControlConfiguration_Send_Pause_Enable		0x1
#define kMACControlConfiguration_Receive_Pause_Enable	0x2
#define kMACControlConfiguration_Pass_MAC_Control		0x4

#define kXIFConfiguration_Tx_MII_OE			0x01	// output enable on the MII bus
#define kXIFConfiguration_MII_Int_Loopback	0x02
#define kXIFConfiguration_Disable_Echo		0x04
#define kXIFConfiguration_GMIIMODE			0x08
#define kXIFConfiguration_MII_Buffer_OE		0x10
#define kXIFConfiguration_LINKLED			0x20
#define kXIFConfiguration_FDPLXLED			0x40

#define kInterPacketGap0_default	0
#define kInterPacketGap1_default	8
#define kInterPacketGap2_default	4

#define kSlotTime_default		0x0040
#define kMinFrameSize_default	0x0040
#define kMaxFrameSize_default	0x05EE

#define kGEMMacMaxFrameSize_Aligned	((kMaxFrameSize_default + 7) & ~7)


#define kPASize_default			0x07
#define kJamSize_default		0x04
#define kAttemptLimit_default	0x10
#define kMACControlType_default	0x8808

#define kMACAddress_default_6	0x0001
#define kMACAddress_default_7	0xC200
#define kMACAddress_default_8	0x0180

#define kMIFBitBangFrame_Output_ST_default	0x40000000	// 2 bits: ST of frame
#define kMIFBitBangFrame_Output_OP_read		0x20000000	// OP code - 2 bits:
#define kMIFBitBangFrame_Output_OP_write	0x10000000	// Read=10; Write=01
#define kMIFBitBangFrame_Output_PHYAD_shift	23			// 5 bit PHY ADdress
#define kMIFBitBangFrame_Output_REGAD_shift	18			// 5 bit REGister ADdress
#define kMIFBitBangFrame_Output_TA_MSB		0x00020000	// Turn Around MSB
#define kMIFBitBangFrame_Output_TA_LSB		0x00010000	// Turn Around LSB

#define kMIFConfiguration_PHY_Select	0x01
#define kMIFConfiguration_Poll_Enable	0x02
#define kMIFConfiguration_BB_Mode		0x04
#define kMIFConfiguration_MDI_0			0x10
#define kMIFConfiguration_MDI_1			0x20

#define kPCSMIIControl_1000_Mbs_Speed_Select	0x0040
#define kPCSMIIControl_Collision_Test			0x0080
#define kPCSMIIControl_Duplex_Mode				0x0100
#define kPCSMIIControl_Restart_Auto_Negotiation	0x0200
#define kPCSMIIControl_Isolate					0x0400
#define kPCSMIIControl_Power_Down				0x0800
#define kPCSMIIControl_Auto_Negotiation_Enable	0x1000
#define kPCSMIIControl_Wrapback					0x4000
#define kPCSMIIControl_Reset					0x8000

#define kAdvertisement_Full_Duplex	0x0020
#define kAdvertisement_Half_Duplex	0x0040
#define kAdvertisement_PAUSE		0x0080	// symmetrical to link partner
#define kAdvertisement_ASM_DIR		0x0100	// pause asymmetrical to link partner
#define kAdvertisement_Ack			0x4000

#define kPCSConfiguration_Enable					0x01
#define kPCSConfiguration_Signal_Detect_Override	0x02
#define kPCSConfiguration_Signal_Detect_Active_Low	0x04
#define kPCSConfiguration_Jitter_Study				// 2 bit field			
#define kPCSConfiguration_10ms_Timer_Override		0x20

#define kDatapathMode_XMode				0x01
#define kDatapathMode_ExtSERDESMode		0x02
#define kDatapathMode_GMIIMode			0x04
#define kDatapathMode_GMIIOutputEnable	0x08

#define kSerialinkControl_DisableLoopback	0x01
#define kSerialinkControl_EnableSyncDet		0x02
#define kSerialinkControl_LockRefClk		0x04



	/* Descriptor definitions:								*/
	/* Note: Own is in the high bit of frameDataSize field:	*/

#define kGEMRxDescFrameSize_Mask	0x7FFF
#define kGEMRxDescFrameSize_Own		0x8000


	/* Rx flags field:	*/

#define kGEMRxDescFlags_HashValueBit	0x00001000
#define kGEMRxDescFlags_HashValueMask	0x0FFFF000
#define kGEMRxDescFlags_HashPass		0x10000000
#define kGEMRxDescFlags_AlternateAddr	0x20000000
#define kGEMRxDescFlags_BadCRC			0x40000000


#define kGEMTxDescFlags0_BufferSizeMask		0x00007FFF
//#define kGEMTxDescFlags0_BufferSizeBit		0x00000001
#define kGEMTxDescFlags0_ChecksumStartMask	0x00FF8000
#define kGEMTxDescFlags0_ChecksumStartBit	0x00008000
#define kGEMTxDescFlags0_ChecksumStuffMask	0x1F000000
#define kGEMTxDescFlags0_ChecksupStuffBit	0x01000000
#define kGEMTxDescFlags0_ChecksumEnable		0x20000000
#define kGEMTxDescFlags0_EndOfFrame			0x40000000
#define kGEMTxDescFlags0_StartOfFrame		0x80000000

#define kGEMTxDescFlags1_Int				0x00000001
#define kGEMTxDescFlags1_NoCRC				0x00000002


/*
 *      Receive/Transmit descriptor
 *
 */
typedef struct _GEMRxDescriptor
{
    u_int16_t           tcpPseudoChecksum;
    u_int16_t           frameDataSize;
    u_int32_t           flags;
    u_int32_t           bufferAddrLo;
    u_int32_t           bufferAddrHi;
} GEMRxDescriptor;

/*
 *    Note: Own is in the high bit of frameDataSize field
 */
#define kGEMRxDescFrameSize_Mask                0x7FFF
#define kGEMRxDescFrameSize_Own                 0x8000

/*
 * Rx flags field
 */
#define kGEMRxDescFlags_HashValueBit            0x00001000
#define kGEMRxDescFlags_HashValueMask           0x0FFFF000
#define kGEMRxDescFlags_HashPass                0x10000000
#define kGEMRxDescFlags_AlternateAddr           0x20000000
#define kGEMRxDescFlags_BadCRC                  0x40000000


typedef struct _GEMTxDescriptor
{
    u_int32_t           flags0;
    u_int32_t           flags1;
    u_int32_t           bufferAddrLo;
    u_int32_t           bufferAddrHi;
} GEMTxDescriptor;

/*
 * 
 */
#define kGEMTxDescFlags0_BufferSizeMask         0x00007FFF
#define kGEMTxDescFlags0_BufferSizeBit          0x00000001
#define kGEMTxDescFlags0_ChecksumStartMask      0x00FF8000
#define kGEMTxDescFlags0_ChecksumStartBit       0x00008000
#define kGEMTxDescFlags0_ChecksumStuffMask      0x1F000000
#define kGEMTxDescFlags0_ChecksupStuffBit       0x01000000
#define kGEMTxDescFlags0_ChecksumEnable         0x20000000
#define kGEMTxDescFlags0_EndOfFrame             0x40000000
#define kGEMTxDescFlags0_StartOfFrame           0x80000000

#define kGEMTxDescFlags1_Int                    0x00000001
#define kGEMTxDescFlags1_NoCRC                  0x00000002



#define kGEMBurstSize                           (CACHE_LINE_SIZE / 8)           
