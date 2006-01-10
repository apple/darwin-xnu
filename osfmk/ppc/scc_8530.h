/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */
/*
 * @APPLE_FREE_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */
/*
 *	File: scc_8530.h
 * 	Author: Alessandro Forin, Carnegie Mellon University
 *	Date:	6/91
 *
 *	Definitions for the Zilog Z8530 SCC serial line chip
 */

#ifndef	_SCC_8530_H_
#define	_SCC_8530_H_

/*
 * Register map, needs definition of the alignment
 * used on the specific machine.
 * #define the 'scc_register_t' data type before
 * including this header file.  For restrictions on
 * access modes define the set/get_datum macros.
 * We provide defaults ifnot.
 */


#define	SCC_CHANNEL_A	1
#define	SCC_CHANNEL_B	0

#define	SCC_MODEM	SCC_CHANNEL_A
#define	SCC_PRINTER	SCC_CHANNEL_B

#define	SCC_DATA_OFFSET	4

typedef unsigned char *scc_regmap_t;

extern void	powermac_scc_set_datum(scc_regmap_t regs, unsigned int offset, unsigned char value);
extern unsigned char powermac_scc_get_datum(scc_regmap_t regs, unsigned int offset);

#define scc_set_datum(regs, d, v)	powermac_scc_set_datum(regs, (d), (v))
#define	scc_get_datum(regs, d,v)	(v)  = powermac_scc_get_datum(regs, (d));

#define	scc_init_reg(regs,chan)		{ \
		char tmp; \
		scc_get_datum(regs, ((chan)<<1),tmp); \
		scc_get_datum(regs, ((chan)<<1),tmp); \
	}

#define	scc_read_reg(regs,chan,reg,val)	{ \
		scc_set_datum(regs, ((chan)<<1),reg); \
		scc_get_datum(regs, ((chan)<<1),val); \
	}

#define	scc_read_reg_zero(regs,chan,val)	{ \
		scc_get_datum(regs, ((chan)<<1),val); \
	}

#define	scc_write_reg(regs,chan,reg,val)	{ \
		scc_set_datum(regs, ((chan)<<1),reg); \
		scc_set_datum(regs, ((chan)<<1),val); \
	}

#define	scc_write_reg_zero(regs,chan,val) { \
		scc_set_datum(regs, ((chan)<<1),val); \
	}

#define	scc_read_data(regs,chan,val)	{ \
		scc_get_datum(regs, ((chan)<<1)+SCC_DATA_OFFSET,val); \
	}

#define	scc_write_data(regs,chan,val) { \
		scc_set_datum(regs, ((chan)<<1)+SCC_DATA_OFFSET,val); \
	}


/*
 * Addressable registers
 */

#define	SCC_RR0		0	/* status register */
#define	SCC_RR1		1	/* special receive conditions */
#define	SCC_RR2		2	/* (modified) interrupt vector */
#define	SCC_RR3		3	/* interrupts pending (cha A only) */
#define	SCC_RR8		8	/* recv buffer (alias for data) */
#define	SCC_RR10	10	/* sdlc status */
#define	SCC_RR12	12	/* BRG constant, low part */
#define	SCC_RR13	13	/* BRG constant, high part */
#define	SCC_RR15	15	/* interrupts currently enabled */

#define	SCC_WR0		0	/* reg select, and commands */
#define	SCC_WR1		1	/* interrupt and DMA enables */
#define	SCC_WR2		2	/* interrupt vector */
#define	SCC_WR3		3	/* receiver params and enables */
#define	SCC_WR4		4	/* clock/char/parity params */
#define	SCC_WR5		5	/* xmit params and enables */
#define	SCC_WR6		6	/* synchr SYNCH/address */
#define	SCC_WR7		7	/* synchr SYNCH/flag */
#define	SCC_WR8		8	/* xmit buffer (alias for data) */
#define	SCC_WR9		9	/* vectoring and resets */
#define	SCC_WR10	10	/* synchr params */
#define	SCC_WR11	11	/* clocking definitions */
#define	SCC_WR12	12	/* BRG constant, low part */
#define	SCC_WR13	13	/* BRG constant, high part */
#define	SCC_WR14	14	/* BRG enables and commands */
#define	SCC_WR15	15	/* interrupt enables */

/*
 * Read registers defines
 */

#define	SCC_RR0_BREAK		0x80	/* break detected (rings twice), or */
#define	SCC_RR0_ABORT		0x80	/* abort (synchr) */
#define	SCC_RR0_TX_UNDERRUN	0x40	/* xmit buffer empty/end of message */
#define	SCC_RR0_CTS		0x20	/* clear-to-send pin active (sampled
					   only on intr and after RESI cmd */
#define	SCC_RR0_SYNCH		0x10	/* SYNCH found/still hunting */
#define	SCC_RR0_DCD		0x08	/* carrier-detect (same as CTS) */
#define	SCC_RR0_TX_EMPTY	0x04	/* xmit buffer empty */
#define	SCC_RR0_ZERO_COUNT	0x02	/* ? */
#define	SCC_RR0_RX_AVAIL	0x01	/* recv fifo not empty */

#define	SCC_RR1_EOF		0x80	/* end-of-frame, SDLC mode */
#define	SCC_RR1_CRC_ERR		0x40	/* incorrect CRC or.. */
#define	SCC_RR1_FRAME_ERR	0x40	/* ..bad frame */
#define	SCC_RR1_RX_OVERRUN	0x20	/* rcv fifo overflow */
#define	SCC_RR1_PARITY_ERR	0x10	/* incorrect parity in data */
#define	SCC_RR1_RESIDUE0	0x08
#define	SCC_RR1_RESIDUE1	0x04
#define	SCC_RR1_RESIDUE2	0x02
#define	SCC_RR1_ALL_SENT	0x01

/* RR2 contains the interrupt vector unmodified (channel A) or
   modified as follows (channel B, if vector-include-status) */

#define	SCC_RR2_STATUS(val)	((val)&0xe)	/* 11/7/95 used to be 0xf */

#define	SCC_RR2_B_XMIT_DONE	0x0
#define	SCC_RR2_B_EXT_STATUS	0x2
#define	SCC_RR2_B_RECV_DONE	0x4
#define	SCC_RR2_B_RECV_SPECIAL	0x6
#define	SCC_RR2_A_XMIT_DONE	0x8
#define	SCC_RR2_A_EXT_STATUS	0xa
#define	SCC_RR2_A_RECV_DONE	0xc
#define	SCC_RR2_A_RECV_SPECIAL	0xe

/* Interrupts pending, to be read from channel A only (B raz) */
#define	SCC_RR3_zero		0xc0
#define	SCC_RR3_RX_IP_A		0x20
#define	SCC_RR3_TX_IP_A		0x10
#define	SCC_RR3_EXT_IP_A	0x08
#define	SCC_RR3_RX_IP_B		0x04
#define	SCC_RR3_TX_IP_B		0x02
#define	SCC_RR3_EXT_IP_B	0x01

/* RR8 is the receive data buffer, a 3 deep FIFO */
#define	SCC_RECV_BUFFER		SCC_RR8
#define	SCC_RECV_FIFO_DEEP	3

#define	SCC_RR10_1CLKS		0x80
#define	SCC_RR10_2CLKS		0x40
#define	SCC_RR10_zero		0x2d
#define	SCC_RR10_LOOP_SND	0x10
#define	SCC_RR10_ON_LOOP	0x02

/* RR12/RR13 hold the timing base, upper byte in RR13 */

#define	scc_get_timing_base(scc,chan,val)	{ \
		register char	tmp;	\
		scc_read_reg(scc,chan,SCC_RR12,val);\
		scc_read_reg(scc,chan,SCC_RR13,tmp);\
		(val) = ((val)<<8)|(tmp&0xff);\
	}

#define	SCC_RR15_BREAK_IE	0x80
#define	SCC_RR15_TX_UNDERRUN_IE	0x40
#define	SCC_RR15_CTS_IE		0x20
#define	SCC_RR15_SYNCH_IE	0x10
#define	SCC_RR15_DCD_IE		0x08
#define	SCC_RR15_zero		0x05
#define	SCC_RR15_ZERO_COUNT_IE	0x02


/*
 * Write registers defines
 */

/* WR0 is used for commands too */
#define	SCC_RESET_TXURUN_LATCH	0xc0
#define	SCC_RESET_TX_CRC	0x80
#define	SCC_RESET_RX_CRC	0x40
#define	SCC_RESET_HIGHEST_IUS	0x38	/* channel A only */
#define	SCC_RESET_ERROR		0x30
#define	SCC_RESET_TX_IP		0x28
#define	SCC_IE_NEXT_CHAR	0x20
#define	SCC_SEND_SDLC_ABORT	0x18
#define	SCC_RESET_EXT_IP	0x10

#define	SCC_WR1_DMA_ENABLE	0x80	/* dma control */
#define	SCC_WR1_DMA_MODE	0x40	/* drive ~req for DMA controller */
#define	SCC_WR1_DMA_RECV_DATA	0x20	/* from wire to host memory */
					/* interrupt enable/conditions */
#define	SCC_WR1_RXI_SPECIAL_O	0x18	/* on special only */
#define	SCC_WR1_RXI_ALL_CHAR	0x10	/* on each char, or special */
#define	SCC_WR1_RXI_FIRST_CHAR	0x08	/* on first char, or special */
#define	SCC_WR1_RXI_DISABLE	0x00	/* never on recv */
#define	SCC_WR1_PARITY_IE	0x04	/* on parity errors */
#define	SCC_WR1_TX_IE		0x02
#define	SCC_WR1_EXT_IE		0x01

/* WR2 is common and contains the interrupt vector (high nibble) */

#define	SCC_WR3_RX_8_BITS	0xc0
#define	SCC_WR3_RX_6_BITS	0x80
#define	SCC_WR3_RX_7_BITS	0x40
#define	SCC_WR3_RX_5_BITS	0x00
#define	SCC_WR3_AUTO_ENABLE	0x20
#define	SCC_WR3_HUNT_MODE	0x10
#define	SCC_WR3_RX_CRC_ENABLE	0x08
#define	SCC_WR3_SDLC_SRCH	0x04
#define	SCC_WR3_INHIBIT_SYNCH	0x02
#define	SCC_WR3_RX_ENABLE	0x01

/* Should be re-written after reset */
#define	SCC_WR4_CLK_x64		0xc0	/* clock divide factor */
#define	SCC_WR4_CLK_x32		0x80
#define	SCC_WR4_CLK_x16		0x40
#define	SCC_WR4_CLK_x1		0x00
#define	SCC_WR4_EXT_SYNCH_MODE	0x30	/* synch modes */
#define	SCC_WR4_SDLC_MODE	0x20
#define	SCC_WR4_16BIT_SYNCH	0x10
#define	SCC_WR4_8BIT_SYNCH	0x00
#define	SCC_WR4_2_STOP		0x0c	/* asynch modes */
#define	SCC_WR4_1_5_STOP	0x08
#define	SCC_WR4_1_STOP		0x04
#define	SCC_WR4_SYNCH_MODE	0x00
#define	SCC_WR4_EVEN_PARITY	0x02
#define	SCC_WR4_PARITY_ENABLE	0x01

#define	SCC_WR5_DTR		0x80	/* drive DTR pin */
#define	SCC_WR5_TX_8_BITS	0x60
#define	SCC_WR5_TX_6_BITS	0x40
#define	SCC_WR5_TX_7_BITS	0x20
#define	SCC_WR5_TX_5_BITS	0x00
#define	SCC_WR5_SEND_BREAK	0x10
#define	SCC_WR5_TX_ENABLE	0x08
#define	SCC_WR5_CRC_16		0x04	/* CRC if non zero, .. */
#define	SCC_WR5_SDLC		0x00	/* ..SDLC otherwise  */
#define	SCC_WR5_RTS		0x02	/* drive RTS pin */
#define	SCC_WR5_TX_CRC_ENABLE	0x01

/* Registers WR6 and WR7 are for synch modes data, with among other things: */

#define	SCC_WR6_BISYNCH_12	0x0f
#define	SCC_WR6_SDLC_RANGE_MASK	0x0f
#define	SCC_WR7_SDLC_FLAG	0x7e

/* Register WR7' (prime) controls some ESCC features */
#define SCC_WR7P_RX_FIFO	0x08	/* Enable interrupt on FIFO 1/2 full */

/* WR8 is the transmit data buffer (no FIFO) */
#define	SCC_XMT_BUFFER		SCC_WR8

#define	SCC_WR9_HW_RESET	0xc0	/* force hardware reset */
#define	SCC_WR9_RESET_CHA_A	0x80
#define	SCC_WR9_RESET_CHA_B	0x40
#define	SCC_WR9_NON_VECTORED	0x20	/* mbz for Zilog chip */
#define	SCC_WR9_STATUS_HIGH	0x10
#define	SCC_WR9_MASTER_IE	0x08
#define	SCC_WR9_DLC		0x04	/* disable-lower-chain */
#define	SCC_WR9_NV		0x02	/* no vector */
#define	SCC_WR9_VIS		0x01	/* vector-includes-status */

#define	SCC_WR10_CRC_PRESET	0x80
#define	SCC_WR10_FM0		0x60
#define	SCC_WR10_FM1		0x40
#define	SCC_WR10_NRZI		0x20
#define	SCC_WR10_NRZ		0x00
#define	SCC_WR10_ACTIVE_ON_POLL	0x10
#define	SCC_WR10_MARK_IDLE	0x08	/* flag if zero */
#define	SCC_WR10_ABORT_ON_URUN	0x04	/* flag if zero */
#define	SCC_WR10_LOOP_MODE	0x02
#define	SCC_WR10_6BIT_SYNCH	0x01
#define	SCC_WR10_8BIT_SYNCH	0x00

#define	SCC_WR11_RTxC_XTAL	0x80	/* RTxC pin is input (ext oscill) */
#define	SCC_WR11_RCLK_DPLL	0x60	/* clock received data on dpll */
#define	SCC_WR11_RCLK_BAUDR	0x40	/* .. on BRG */
#define	SCC_WR11_RCLK_TRc_PIN	0x20	/* .. on TRxC pin */
#define	SCC_WR11_RCLK_RTc_PIN	0x00	/* .. on RTxC pin */
#define	SCC_WR11_XTLK_DPLL	0x18
#define	SCC_WR11_XTLK_BAUDR	0x10
#define	SCC_WR11_XTLK_TRc_PIN	0x08
#define	SCC_WR11_XTLK_RTc_PIN	0x00
#define	SCC_WR11_TRc_OUT	0x04	/* drive TRxC pin as output from..*/
#define	SCC_WR11_TRcOUT_DPLL	0x03	/* .. the dpll */
#define	SCC_WR11_TRcOUT_BAUDR	0x02	/* .. the BRG */
#define	SCC_WR11_TRcOUT_XMTCLK	0x01	/* .. the xmit clock */
#define	SCC_WR11_TRcOUT_XTAL	0x00	/* .. the external oscillator */

/* WR12/WR13 are for timing base preset */
#define	scc_set_timing_base(scc,chan,val)	{ \
		scc_write_reg(scc,chan,SCC_RR12,val);\
		scc_write_reg(scc,chan,SCC_RR13,(val)>>8);\
	}

/* More commands in this register */
#define	SCC_WR14_NRZI_MODE	0xe0	/* synch modulations */
#define	SCC_WR14_FM_MODE	0xc0
#define	SCC_WR14_RTc_SOURCE	0xa0	/* clock is from pin .. */
#define	SCC_WR14_BAUDR_SOURCE	0x80	/* .. or internal BRG */
#define	SCC_WR14_DISABLE_DPLL	0x60
#define	SCC_WR14_RESET_CLKMISS	0x40
#define	SCC_WR14_SEARCH_MODE	0x20
/* ..and more bitsy */
#define	SCC_WR14_LOCAL_LOOPB	0x10
#define	SCC_WR14_AUTO_ECHO	0x08
#define	SCC_WR14_DTR_REQUEST	0x04
#define	SCC_WR14_BAUDR_SRC	0x02
#define	SCC_WR14_BAUDR_ENABLE	0x01

#define	SCC_WR15_BREAK_IE	0x80
#define	SCC_WR15_TX_UNDERRUN_IE	0x40
#define	SCC_WR15_CTS_IE		0x20
#define	SCC_WR15_SYNCHUNT_IE	0x10
#define	SCC_WR15_DCD_IE		0x08
#define	SCC_WR15_zero		0x05
#define	SCC_WR15_ZERO_COUNT_IE	0x02
#define SCC_WR15_ENABLE_ESCC	0x01	/* Enable some ESCC registers */

#define	NSCC_LINE		2	/* How many lines are support per 8530 */
/*
 * Driver status
 */

#define	SCC_FLAGS_DMA_PAUSED	0x00001		/* DMA has been paused because of XON/XOFF */
#define	SCC_FLAGS_DMA_TX_BUSY	0x00002		/* On going DMA operation.. */

struct scc_softreg {
	unsigned char	wr1;
	unsigned char	wr4;
	unsigned char	wr5;
	unsigned char	wr14;

	unsigned long	speed;
	unsigned long	flags;
	unsigned long	dma_flags;
};


struct scc_softc {
	scc_regmap_t		regs;
	struct scc_dma_ops	*dma_ops;

	/* software copy of some write regs, for reg |= */
	struct scc_softreg softr[NSCC_LINE];

	int		flags;
	int		modem[NSCC_LINE]; /* Mach modem bits (TM_DTR etc). */
	int		dcd_timer[NSCC_LINE];
	int		dma_initted;

	char		polling_mode;
	char		probed_once;

	boolean_t		full_modem;
};

#define DCD_TIMEOUT 4

typedef struct scc_softc *scc_softc_t;
extern struct scc_softc		scc_softc[];

#endif	/*_SCC_8530_H_*/
