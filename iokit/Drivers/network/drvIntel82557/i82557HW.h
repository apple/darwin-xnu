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
 * Copyright (c) 1996 NeXT Software, Inc.  All rights reserved. 
 *
 * i82557HW.h - Intel 82557/82558 chip-related definitions
 *
 * HISTORY
 * Jan 22, 1996	Dieter Siegmund at NeXT (dieter@next.com)
 *      Created.
 */

#ifndef _I82557HW_H
#define _I82557HW_H

#include <net/etherdefs.h>

//-------------------------------------------------------------------------
// Misc definitions.
//-------------------------------------------------------------------------

#define DWORD_ALIGNMENT				4
#define WORD_ALIGNMENT				2
#define PARAGRAPH_ALIGNMENT			16
#define CACHE_ALIGNMENT				32

#define C_NULL						(~0)

#define PCI_CFID_INTEL82557			0x12298086

typedef enum {
	MEDIUM_TYPE_10_HD = 0,
	MEDIUM_TYPE_10_FD,
	MEDIUM_TYPE_TX_HD,
	MEDIUM_TYPE_TX_FD,
	MEDIUM_TYPE_T4,
	MEDIUM_TYPE_AUTO,
	MEDIUM_TYPE_INVALID,
} mediumType_t;

//-------------------------------------------------------------------------
// SCB status word.
// Offset 0, 16-bit, RW.
//-------------------------------------------------------------------------
typedef UInt16 scb_status_t;
#define SCB_STATUS_CX				BIT(15)	// command block with 'I' bit set.
#define SCB_STATUS_FR				BIT(14)	// RU finished receiving a frame.
#define SCB_STATUS_CNA				BIT(13)	// CU active to suspended/idle.
#define SCB_STATUS_RNR				BIT(12)	// RU no longer in ready state.
#define SCB_STATUS_MDI				BIT(11)	// MDI read/write cycle is done.
#define SCB_STATUS_SWI				BIT(10)	// software interrupt.
#define SCB_STATUS_ER				BIT(9)	// early receive interrupt.
#define SCB_STATUS_FCP				BIT(8)	// flow control pause interrupt.
#define SCB_STATUS_INT_MASK			0xff00	// mask for all interrupt bits.

#define SCB_STATUS_CUS_SHIFT		6
#define SCB_STATUS_CUS_MASK			CSR_MASK(SCB_STATUS_CUS, 0x3)
#define SCB_CUS_IDLE				0
#define SCB_CUS_SUSPEND				1
#define SCB_CUS_ACTIVE				2

#define SCB_STATUS_RUS_SHIFT		2
#define SCB_STATUS_RUS_MASK			CSR_MASK(SCB_STATUS_RUS, 0xf)
#define SCB_RUS_IDLE				0
#define SCB_RUS_SUSPEND				1
#define SCB_RUS_NO_RESOURCES		2
#define SCB_RUS_READY				4
#define SCB_RUS_SUSPEND_NO_RBDS		9
#define SCB_RUS_NO_RBDS				10
#define SCB_RUS_READY_NO_RBDS		12

//-------------------------------------------------------------------------
// SCB interrupt control byte.
// Offset 3, 8-bit, RW.
//-------------------------------------------------------------------------
typedef UInt8 scb_interrupt_t;
#define SCB_INTERRUPT_CX			BIT(7)	// interrupt masks
#define SCB_INTERRUPT_FR			BIT(6)
#define SCB_INTERRUPT_CNA			BIT(5)
#define SCB_INTERRUPT_RNR			BIT(4)
#define SCB_INTERRUPT_ER			BIT(3)
#define SCB_INTERRUPT_FCP			BIT(2)
#define SCB_INTERRUPT_SI			BIT(1)
#define SCB_INTERRUPT_M				BIT(0)

//-------------------------------------------------------------------------
// SCB command byte.
// Offset 2, 8-bit, RW.
//-------------------------------------------------------------------------
typedef UInt8 scb_command_t;
#define SCB_COMMAND_CUC_SHIFT		4
#define SCB_COMMAND_CUC_MASK		CSR_MASK(SCB_COMMAND_CUC, 0xf)
#define SCB_CUC_NOP					0
#define SCB_CUC_START				1
#define SCB_CUC_RESUME				2
#define SCB_CUC_LOAD_DUMP_ADDR		4
#define SCB_CUC_DUMP_STAT			5
#define SCB_CUC_LOAD_BASE			6
#define SCB_CUC_DUMP_RESET_STAT		7
#define SCB_CUC_STATIC_RESUME		10

#define SCB_COMMAND_RUC_SHIFT		0
#define SCB_COMMAND_RUC_MASK		CSR_MASK(SCB_COMMAND_RUC, 0x7)
#define SCB_RUC_NOP					0
#define SCB_RUC_START				1
#define SCB_RUC_RESUME				2
#define SCB_RUC_DMA_REDIRECT		3
#define SCB_RUC_ABORT				4
#define SCB_RUC_LOAD_HDS			5
#define SCB_RUC_LOAD_BASE			6
#define SCB_RUC_RBD_RESUME			7

//-------------------------------------------------------------------------
// MDI control register.
// Offset 0x10, 32-bit, RW.
//-------------------------------------------------------------------------
typedef UInt32 mdi_control_t;
#define MDI_CONTROL_INT_ENABLE		BIT(29)	// interrupt enable.
#define MDI_CONTROL_READY			BIT(28)	// ready bit.
#define MDI_CONTROL_OPCODE_SHIFT	26
#define MDI_CONTROL_OPCODE_MASK		CSR_MASK(MDI_CONTROL_OPCODE, 0x3)
#define MDI_CONTROL_OP_WRITE		1
#define MDI_CONTROL_OP_READ			2
#define MDI_CONTROL_PHYADDR_SHIFT	21
#define MDI_CONTROL_PHYADDR_MASK	CSR_MASK(MDI_CONTROL_PHYADDR, 0x1f)
#define MDI_CONTROL_REGADDR_SHIFT	16
#define MDI_CONTROL_REGADDR_MASK	CSR_MASK(MDI_CONTROL_REGADDR, 0x1f)
#define MDI_CONTROL_DATA_SHIFT		0
#define MDI_CONTROL_DATA_MASK		CSR_MASK(MDI_CONTROL_DATA, 0xffff)

//-------------------------------------------------------------------------
// EEPROM control register.
// Offset 0xE, 16-bit, RW.
//-------------------------------------------------------------------------
typedef UInt16 eeprom_control_t;
#define EEPROM_CONTROL_EEDO			BIT(3)
#define EEPROM_CONTROL_EEDI			BIT(2)
#define EEPROM_CONTROL_EECS			BIT(1)
#define EEPROM_CONTROL_EESK			BIT(0)

//-------------------------------------------------------------------------
// Flow control threshold register.
// Offset 0x19, 8-bit, RW.
//-------------------------------------------------------------------------
#define FC_THRESHOLD_SHIFT			0
#define FC_THRESHOLD_MASK			CSR_MASK(FC_THRESHOLD, 0x7)
#define FC_THRESHOLD_512			0
#define FC_THRESHOLD_1024			1
#define FC_THRESHOLD_1280			2
#define FC_THRESHOLD_1536			3

//-------------------------------------------------------------------------
// Flow control command register.
// Offset 0x20, 8-bit, RW.
//-------------------------------------------------------------------------
#define FC_XON						BIT(0)
#define FC_XOFF						BIT(1)
#define FC_FULL						BIT(2)
#define FC_PAUSED					BIT(3)
#define FC_PAUSED_LOW				BIT(4)

//-------------------------------------------------------------------------
// Generic command block definition.
//-------------------------------------------------------------------------
#define CB_NOP                  	0
#define CB_IA_ADDRESS           	1
#define CB_CONFIGURE            	2
#define CB_MULTICAST            	3
#define CB_TRANSMIT             	4
#define CB_LOAD_MICROCODE       	5
#define CB_DUMP                 	6
#define CB_DIAGNOSE             	7

typedef UInt16 cb_status_t;
#define CB_STATUS_C					BIT(15)	// command complete.
#define CB_STATUS_OK				BIT(13)	// DMA OK.

typedef UInt16 cb_command_t;
#define CB_EL						BIT(15)	// end of list.
#define CB_S						BIT(14)	// suspend bit.
#define CB_I						BIT(13)	// interrupt bit.
#define CB_CMD_SHIFT				0
#define CB_CMD_MASK					CSR_MASK(CB_CMD, 0x7)

#define CB_CMD_NOP					0x0
#define CB_CMD_IASETUP				0x1
#define CB_CMD_CONFIGURE			0x2
#define CB_CMD_MCSETUP				0x3
#define CB_CMD_TRANSMIT				0x4

static __inline__ char *
CUCommandString(int cmd)
{
	char * s[] = {
		"nop",
		"iasetup",
		"configure",
		"mcsetup",
		"transmit"
    };
    return (s[cmd]);
}

typedef struct {
	volatile cb_status_t	status;
	volatile cb_command_t			command;
	IOPhysicalAddress		link;
} cbHeader_t;

//-------------------------------------------------------------------------
// Configure command.
//-------------------------------------------------------------------------
#define CB_CONFIG_BYTE_COUNT		22

#define CB_CB0_BYTE_COUNT_SHIFT		0
#define CB_CB0_BYTE_COUNT_MASK		CSR_MASK(CB_CB0_BYTE_COUNT, 0x3f)

#define CB_CB1_TX_FIFO_LIMIT_SHIFT	4
#define CB_CB1_TX_FIFO_LIMIT_MASK	CSR_MASK(CB_CB1_TX_FIFO_LIMIT, 0xf)
#define CB_CB1_RX_FIFO_LIMIT_SHIFT	0
#define CB_CB1_RX_FIFO_LIMIT_MASK	CSR_MASK(CB_CB1_RX_FIFO_LIMIT, 0xf)
#define CB_CB1_TX_FIFO_0			8	// 0  bytes
#define CB_CB1_RX_FIFO_64			8	// 64 bytes

#define CB_CB2_ADAPTIVE_IFS_SHIFT	0
#define CB_CB2_ADAPTIVE_IFS_MASK	CSR_MASK(CB_CB2_ADAPTIVE_IFS, 0xff)

#define CB_CB3_TERM_ON_CL       	BIT(3)
#define CB_CB3_READ_AL_ENABLE		BIT(2)
#define CB_CB3_TYPE_ENABLE       	BIT(1)
#define CB_CB3_MWI_ENABLE       	BIT(0)

#define CB_CB4_RX_MIN_SHIFT			0
#define CB_CB4_RX_MIN_MASK			CSR_MASK(CB_CB4_RX_MIN, 0x7f)

#define CB_CB5_DMBC_EN				BIT(7)
#define CB_CB5_TX_MAX_SHIFT			0
#define CB_CB5_TX_MAX_MASK			CSR_MASK(CB_CB4_TX_MAX, 0x7f)

#define CB_CB6_SAVE_BF				BIT(7)
#define CB_CB6_DISC_OVER			BIT(6)
#define CB_CB6_STD_STATS			BIT(5)
#define CB_CB6_STD_TCB				BIT(4)
#define CB_CB6_CI_INT				BIT(3)
#define CB_CB6_TNO_INT				BIT(2)
#define CB_CB6_NON_DIRECT_DMA		BIT(1)
#define CB_CB6_LATE_SCB				BIT(0)

#define CB_CB7_DYNAMIC_TBD			BIT(7)
#define CB_CB7_UNDERRUN_RETRY_SHIFT	1
#define CB_CB7_UNDERRUN_RETRY_MASK	CSR_MASK(CB_CB7_UNDERRUN_RETRY, 0x3)
#define CB_CB7_UNDERRUN_RETRY_1		1
#define CB_CB7_UNDERRUN_RETRY_2		2
#define CB_CB7_UNDERRUN_RETRY_3		3
#define CB_CB7_DISC_SHORT_FRAMES	BIT(0)

#define CB_CB8_CSMA_EN				BIT(0)

#define CB_CB10_LOOPBACK_SHIFT		6
#define CB_CB10_LOOPBACK_MASK		CSR_MASK(CB_CB10_LOOPBACK, 0x3)
#define CB_CB10_PREAMBLE_SHIFT		4
#define CB_CB10_PREAMBLE_MASK		CSR_MASK(CB_CB10_PREAMBLE, 0x3)
#define CB_CB10_PREAMBLE_1_BYTE		0
#define CB_CB10_PREAMBLE_3_BYTES	1
#define CB_CB10_PREAMBLE_7_BYTES	2
#define CB_CB10_PREAMBLE_15_BYTES	3
#define CB_CB10_NSAI				BIT(3)

#define CB_CB11_LIN_PRIORITY_SHIFT	0
#define CB_CB11_LIN_PRIORITY_MASK	CSR_MASK(CB_CB11_PRIORITY, 0x7)

#define CB_CB12_IFS_SHIFT			4
#define CB_CB12_IFS_MASK			CSR_MASK(CB_CB12_IFS, 0xf)
#define CB_CB12_IFS_96_BIT_TIMES	0x6
#define CB_CB12_LIN_PRIORITY		BIT(0)

#define CB_CB13_FC_TYPE_LSB_SHIFT	0
#define CB_CB13_FC_TYPE_LSB_MASK	CSR_MASK(CB_CB13_FC_TYPE_LSB, 0xff)
#define CB_CB13_FC_TYPE_LSB_DEF		0		// 82558 compatible

#define CB_CB14_FC_TYPE_MSB_SHIFT	0
#define CB_CB14_FC_TYPE_MSB_MASK	CSR_MASK(CB_CB14_FC_TYPE_MSB, 0xff)
#define CB_CB14_FC_TYPE_MSB_DEF		0xf2	// 82558 compatible

#define CB_CB15_CRS_CDT				BIT(7)
#define CB_CB15_BROADCAST_DISABLE	BIT(1)
#define CB_CB15_PROMISCUOUS			BIT(0)

#define CB_CB16_FC_DELAY_LSB_SHIFT	0
#define CB_CB16_FC_DELAY_LSB_MASK	CSR_MASK(CB_CB16_FC_DELAY_LSB, 0xff)
#define CB_CB16_FC_DELAY_LSB_DEF	0

#define CB_CB17_FC_DELAY_MSB_SHIFT	0
#define CB_CB17_FC_DELAY_MSB_MASK	CSR_MASK(CB_CB17_FC_DELAY_MSB, 0xff)
#define CB_CB17_FC_DELAY_MSB_DEF	0x40

#define CB_CB18_LONG_RX_OK			BIT(3)
#define CB_CB18_CRC_XFER			BIT(2)
#define CB_CB18_PADDING				BIT(1)
#define CB_CB18_STRIPPING			BIT(0)

#define CB_CB19_AUTO_FDX			BIT(7)
#define CB_CB19_FORCE_FDX			BIT(6)
#define CB_CB19_REJECT_FC			BIT(5)
#define CB_CB19_RX_FC_RESTART		BIT(4)
#define CB_CB19_RX_FC_RESTOP		BIT(3)
#define CB_CB19_TX_FC				BIT(2)
#define CB_CB19_MAGIC_PKT_WAKEUP	BIT(1)
#define CB_CB19_ADDRESS_WAKEUP		BIT(0)

#define CB_CB20_MULTI_IA			BIT(6)
#define CB_CB20_FC_ADDR_LSB_SHIFT	0
#define CB_CB20_FC_ADDR_LSB_MASK	CSR_MASK(CB_CB20_FC_ADDR_LSB, 0x1f)
#define CB_CB20_FC_ADDR_LSB_DEF		0x0f

#define CB_CB21_MULTICAST_ALL		BIT(3)

typedef struct cb_configure {
	cbHeader_t		header;
	UInt8			byte[24];
} cb_configure_t;

//-------------------------------------------------------------------------
// MC-Setup command.
//-------------------------------------------------------------------------
typedef struct cb_mcsetup {
	cbHeader_t		   header;
	UInt16			   count;
	IOEthernetAddress  addrs[0];
} cb_mcsetup_t;

//-------------------------------------------------------------------------
// IA-Setup command.
//-------------------------------------------------------------------------
typedef struct cb_iasetup {
	cbHeader_t		   header;
    IOEthernetAddress  addr;
} cb_iasetup_t;

//-------------------------------------------------------------------------
// Port Commands.
// Enumerated port command values.
//-------------------------------------------------------------------------
typedef enum {
    portReset_e = 0,
    portSelfTest_e = 1,
    portSelectiveReset_e = 2,
    portDump_e = 3,
} port_command_t;

#define PORT_ADDRESS_SHIFT			4
#define PORT_ADDRESS_MASK			CSR_MASK(PORT_FUNCTION, 0xfffffff)

#define PORT_FUNCTION_SHIFT			0
#define PORT_FUNCTION_MASK			CSR_MASK(PORT_FUNCTION, 0xf)

//-------------------------------------------------------------------------
// Port Self-Test
// Definition for self test area.
//-------------------------------------------------------------------------
#define PORT_SELFTEST_GENERAL		BIT(12)
#define PORT_SELFTEST_DIAGNOSE		BIT(5)
#define PORT_SELFTEST_REGISTER		BIT(3)
#define PORT_SELFTEST_ROM			BIT(2)

typedef struct port_selftest_t {
	UInt32			signature;
	UInt32			results;
} port_selftest_t;

/*
 * Typedef: CSR_t
 *
 * Purpose: Control Status Registers block
 *   Communication to the chip occurs via this set of
 *   memory-mapped (also io-mapped, which we don't use)
 *   registers.
 */
typedef struct csr {
    volatile scb_status_t			status;
    volatile scb_command_t 			command;
	volatile scb_interrupt_t		interrupt;
	volatile IOPhysicalAddress		pointer;
	volatile UInt32					port;
	volatile UInt16					flashControl;
	volatile eeprom_control_t		eepromControl;
	volatile mdi_control_t			mdiControl;
	volatile UInt32					rxDMAByteCount;
	volatile UInt8					earlyRxInterrupt;
	volatile UInt8					flowControlThreshold;
	volatile UInt8					flowControlCommand;
	volatile UInt8					powerManagement;
} CSR_t;

//-------------------------------------------------------------------------
// Structure containing error counters retrieved via:
//	Dump Statistics Counters command, or
//	Dump and Reset Statistics Counters command.
//
// NOTE: 82558 can return an extended set of statistics counters.
//-------------------------------------------------------------------------
typedef struct {
    UInt32		tx_good_frames;
    UInt32		tx_maxcol_errors;
    UInt32		tx_late_collision_errors;
    UInt32		tx_underrun_errors;
    UInt32		tx_lost_carrier_sense_errors;
    UInt32		tx_deferred;
    UInt32		tx_single_collisions;
    UInt32		tx_multiple_collisions;
    UInt32		tx_total_collisions;
    UInt32		rx_good_frames;
    UInt32		rx_crc_errors;
    UInt32		rx_alignment_errors;
    UInt32		rx_resource_errors;
    UInt32		rx_overrun_errors;
    UInt32		rx_collision_detect_errors;
    UInt32		rx_short_frame_errors;
    UInt32		_status;
#define DUMP_STATUS					0x0
#define DUMP_COMPLETE				0xa005
#define DUMP_AND_RESET_COMPLETE		0xa007
} errorCounters_t;

//-------------------------------------------------------------------------
// RBD count dword.
// Offset 0, 32-bit, RW.
//-------------------------------------------------------------------------
typedef UInt32 rbd_count_t;
#define RBD_COUNT_EOF				BIT(15)	// end-of-frame bit.
#define RBD_COUNT_F					BIT(14)	// buffer fetch bit.
#define RBD_COUNT_SHIFT				0
#define RBD_COUNT_MASK				CSR_MASK(RBD_COUNT, 0x3fff)

//-------------------------------------------------------------------------
// RBD size dword.
// Offset 0xC, 32-bit, RW.
//-------------------------------------------------------------------------
typedef UInt32 rbd_size_t;
#define RBD_SIZE_EL					BIT(15)	// EL bit.
#define RBD_SIZE_SHIFT				0
#define RBD_SIZE_MASK				CSR_MASK(RBD_SIZE, 0x3fff)

//-------------------------------------------------------------------------
// RBD - receive buffer descriptor definition.
//-------------------------------------------------------------------------
typedef struct rbd {
	volatile rbd_count_t			count;
	volatile IOPhysicalAddress		link;
	volatile IOPhysicalAddress		buffer;
	volatile rbd_size_t				size;
	
	/* driver private */
	
	struct rbd *					_next;
	IOPhysicalAddress				_paddr;
	struct mbuf *					_mbuf;
	UInt32							_pad;
} rbd_t;

//-------------------------------------------------------------------------
// RFD status word.
// Offset 0, 16-bit, RW.
//-------------------------------------------------------------------------
typedef UInt16 rfd_status_t;
#define RFD_STATUS_C				BIT(15)	// complete bit.
#define RFD_STATUS_OK				BIT(13)	// OK bit.
#define RFD_STATUS_CRC_ERROR		BIT(11)	// CRC error bit.
#define RFD_STATUS_ALIGNMENT_ERROR	BIT(10)	// alignment error.
#define RFD_STATUS_NO_RESOURCES		BIT(9)	// no buffer space.
#define RFD_STATUS_DMA_OVERRUN		BIT(8)	// receive DMA overrun.
#define RFD_STATUS_FRAME_TOO_SHORT	BIT(7)	// frame too short.
#define RFD_STATUS_TYPE_FRAME		BIT(5)	// type/length bit.
#define RFD_STATUS_RX_ERROR			BIT(4)	// RX_ERR pin on PHY was set.
#define RFD_STATUS_NO_ADDR_MATCH	BIT(2)	// no address match.
#define RFD_STATUS_IA_MATCH			BIT(1)	// IA address match.
#define RFD_STATUS_COLLISION		BIT(0)	// receive collision.

//-------------------------------------------------------------------------
// RFD command word.
// Offset 2, 16-bit, RW.
//-------------------------------------------------------------------------
typedef UInt16 rfd_command_t;
#define RFD_COMMAND_EL				BIT(15)	// EL bit.
#define RFD_COMMAND_S				BIT(14)	// suspend bit.
#define RFD_COMMAND_H				BIT(4)	// header RFD bit.
#define RFD_COMMAND_SF				BIT(3)	// flexible mode bit.

//-------------------------------------------------------------------------
// RFD misc dword.
// Offset 0xC, 32-bit, RW.
//-------------------------------------------------------------------------
typedef UInt32 rfd_misc_t;
#define RFD_MISC_EOF				BIT(15)	// end-of-frame bit.
#define RFD_MISC_F					BIT(14)	// buffer fetch bit.
#define RFD_MISC_ACT_COUNT_SHIFT	0
#define RFD_MISC_ACT_COUNT_MASK		CSR_MASK(RFD_MISC_ACT_COUNT,  0x3fff)
#define RFD_MISC_SIZE_SHIFT			16
#define RFD_MISC_SIZE_MASK			CSR_MASK(RFD_MISC_SIZE, 0x3fff)

//-------------------------------------------------------------------------
// RFD - receive frame descriptor definition.
//-------------------------------------------------------------------------
typedef struct rfd {
    volatile rfd_status_t			status;
    volatile rfd_command_t			command;
    volatile IOPhysicalAddress		link;
    volatile IOPhysicalAddress		rbdAddr;
	volatile rfd_misc_t				misc;		// 16 bytes

	UInt32							_pad[2];	// pad it to 64 bytes

	/* driver private */

	struct rfd *					_next;
	IOPhysicalAddress				_paddr;
	rbd_t							_rbd;		// 32 bytes
} rfd_t;

//-------------------------------------------------------------------------
// TBD - Transmit Buffer Descriptor.
//-------------------------------------------------------------------------
typedef UInt16	tbd_size_t;
#define TBD_SIZE_EL					BIT(15)	// end of list
#define TBD_SIZE_SHIFT				0
#define TBD_SIZE_MASK				CSR_MASK(TBD_SIZE, 0x3fff)

typedef struct tbd {
	volatile IOPhysicalAddress		addr;
	volatile tbd_size_t				size;
} tbd_t;

//-------------------------------------------------------------------------
// TxCB Status Word.
// Offset 0, 16-bit, RW.
//-------------------------------------------------------------------------
typedef UInt16 tcb_status_t;		
#define TCB_STATUS_C				BIT(15)	// complete bit
#define TCB_STATUS_OK				BIT(13)	// error free completion
#define TCB_STATUS_U				BIT(12)	// underrun bit

//-------------------------------------------------------------------------
// TxCB Command Word.
// Offset 2, 16-bit, RW.
//-------------------------------------------------------------------------
typedef UInt16 tcb_command_t;		
#define TCB_COMMAND_EL				BIT(15)	// end of list
#define TCB_COMMAND_S				BIT(14)	// suspend bit
#define TCB_COMMAND_I				BIT(13)	// interrupt bit
#define TCB_COMMAND_NC				BIT(4)	// CRC/Source Address control
#define TCB_COMMAND_SF				BIT(3)	// flexible mode bit
#define TCB_COMMAND_SHIFT			0
#define TCB_COMMAND_MASK			CSR_MASK(TCB_COMMAND, 0x7)

//-------------------------------------------------------------------------
// TxCB Count Word.
// Offset 0xC, 16-bit, RW.
//-------------------------------------------------------------------------
typedef UInt16 tcb_count_t;		
#define TCB_COUNT_EOF				BIT(15)	// whole frame in TCB
#define TCB_COUNT_SHIFT				0
#define TCB_COUNT_MASK				CSR_MASK(TCB_COUNT, 0x3fff)

//-------------------------------------------------------------------------
// TxCB - Transmit Command Block.
//-------------------------------------------------------------------------
#define TBDS_PER_TCB		12
#define TCB_TX_THRESHOLD	0xe0

typedef struct tcb {
	volatile tcb_status_t			status;
	volatile tcb_command_t			command;
    volatile IOPhysicalAddress		link;
    volatile IOPhysicalAddress		tbdAddr;
	volatile tcb_count_t			count;
	volatile UInt8					threshold;
	volatile UInt8					number;
	
    /* driver private */

	tbd_t				_tbds[TBDS_PER_TCB];
	struct tcb *		_next;
    IOPhysicalAddress	_paddr;
    struct mbuf *		_mbuf;
	unsigned			_pad;
} tcb_t;

#endif /* !_I82557HW_H */

