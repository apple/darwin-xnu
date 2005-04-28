/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 *	File: scc_8530_hdw.c
 * 	Author: Alessandro Forin, Carnegie Mellon University
 *	Date:	6/91
 *
 *	Hardware-level operations for the SCC Serial Line Driver
 */

#define	NSCC	1	/* Number of serial chips, two ports per chip. */
#if	NSCC > 0

#include <mach_kdb.h>
#include <platforms.h>
#include <kern/spl.h>
#include <mach/std_types.h>
#include <types.h>
#include <sys/syslog.h>
#include <kern/thread.h>
#include <ppc/misc_protos.h>
#include <ppc/proc_reg.h>
#include <ppc/exception.h>
#include <ppc/Firmware.h>
#include <ppc/serial_io.h>
#include <ppc/scc_8530.h>

#if	MACH_KDB
#include <machine/db_machdep.h>
#endif	/* MACH_KDB */

#define	kdebug_state()	(1)
#define	delay(x)	{ volatile int _d_; for (_d_ = 0; _d_ < (10000*x); _d_++) ; }

#define	NSCC_LINE	2	/* 2 ttys per chip */

#define	SCC_DMA_TRANSFERS	0
  
struct scc_tty scc_tty[NSCC_LINE];

#define scc_tty_for(chan)	(&scc_tty[chan])
/* #define scc_unit(dev_no)	(dev_no) */

#define scc_dev_no(chan) ((chan)^0x01)
#define scc_chan(dev_no) ((dev_no)^0x01)

extern unsigned int disableSerialOuput;

int	serial_initted = 0;
unsigned int scc_parm_done = 0;				/* (TEST/DEBUG) */

extern unsigned int serialmode;

static struct scc_byte {
	unsigned char	reg;
	unsigned char	val;
} scc_init_hw[] = {
	
	9, 0x80,
	4, 0x44,
	3, 0xC0,
	5, 0xE2,
	2, 0x00,
	10, 0x00,
	11, 0x50,
	12, 0x0A,
	13, 0x00,
	3, 0xC1,
	5, 0xEA,
	14, 0x01,
	15, 0x00,
	0, 0x10,
	0, 0x10,
#if 0
	1, 0x12,			/* int or Rx, Tx int enable */
#else
	1, 0x10,			/* int or Rx,  no Tx int enable */
#endif
	9, 0x0A
};

static int	scc_init_hw_count = sizeof(scc_init_hw)/sizeof(scc_init_hw[0]);

enum scc_error {SCC_ERR_NONE, SCC_ERR_PARITY, SCC_ERR_BREAK, SCC_ERR_OVERRUN};


/*
 * BRG formula is:
 *				ClockFrequency (115200 for Power Mac)
 *	BRGconstant = 	---------------------------  -  2
 *			      BaudRate
 */

#define SERIAL_CLOCK_FREQUENCY (115200*2) /* Power Mac value */
#define	convert_baud_rate(rate)	((((SERIAL_CLOCK_FREQUENCY) + (rate)) / (2 * (rate))) - 2)

#define DEFAULT_SPEED 57600
#define DEFAULT_PORT0_SPEED 1200
#define DEFAULT_FLAGS (TF_LITOUT|TF_ECHO)

int	scc_param(struct scc_tty *tp);


struct scc_softc	scc_softc[NSCC];
caddr_t	scc_std[NSCC] = { (caddr_t) 0};


#define SCC_RR1_ERRS (SCC_RR1_FRAME_ERR|SCC_RR1_RX_OVERRUN|SCC_RR1_PARITY_ERR)
#define SCC_RR3_ALL (SCC_RR3_RX_IP_A|SCC_RR3_TX_IP_A|SCC_RR3_EXT_IP_A|\
                     SCC_RR3_RX_IP_B|SCC_RR3_TX_IP_B|SCC_RR3_EXT_IP_B)

#define DEBUG_SCC
#undef  DEBUG_SCC

#ifdef DEBUG_SCC
static int total_chars, total_ints, total_overruns, total_errors, num_ints, max_chars;
static int chars_received[8];
static int __SCC_STATS = 0;
static int max_in_q = 0;
static int max_out_q = 0;
#endif

DECL_FUNNEL(, scc_funnel)	/* funnel to serialize the SCC driver */
boolean_t scc_funnel_initted = FALSE;
#define SCC_FUNNEL		scc_funnel
#define SCC_FUNNEL_INITTED	scc_funnel_initted


/*
 * Adapt/Probe/Attach functions
 */
boolean_t	scc_uses_modem_control = FALSE;/* patch this with adb */
decl_simple_lock_data(,scc_stomp)			/* (TEST/DEBUG) */

/* This is called VERY early on in the init and therefore has to have
 * hardcoded addresses of the serial hardware control registers. The
 * serial line may be needed for console and debugging output before
 * anything else takes place
 */

void
initialize_serial( caddr_t scc_phys_base, int32_t serial_baud )
{
	int i, chan, bits;
	scc_regmap_t	regs;
	DECL_FUNNEL_VARS

	assert( scc_phys_base );

	if (!SCC_FUNNEL_INITTED) {
		FUNNEL_INIT(&SCC_FUNNEL, master_processor);
		SCC_FUNNEL_INITTED = TRUE;
	}
	FUNNEL_ENTER(&SCC_FUNNEL);

	if (serial_initted) {
		FUNNEL_EXIT(&SCC_FUNNEL);
		return;
	}

	simple_lock_init(&scc_stomp, FALSE);				/* (TEST/DEBUG) */
	
	if (serial_baud == -1) serial_baud = DEFAULT_SPEED;
	
	scc_softc[0].full_modem = TRUE;

        scc_std[0] = scc_phys_base;

	regs = scc_softc[0].regs = (scc_regmap_t)scc_std[0];

	for (chan = 0; chan < NSCC_LINE; chan++) {
		if (chan == 1)
			scc_init_hw[0].val = 0x80;

		for (i = 0; i < scc_init_hw_count; i++) {
			scc_write_reg(regs, chan,
				      scc_init_hw[i].reg, scc_init_hw[i].val);
		}
	}

	/* Call probe so we are ready very early for remote gdb and for serial
	   console output if appropriate.  */
	if (scc_probe(serial_baud)) {
		for (i = 0; i < NSCC_LINE; i++) {
			scc_softc[0].softr[i].wr5 = SCC_WR5_DTR | SCC_WR5_RTS;
			scc_param(scc_tty_for(i));
	/* Enable SCC interrupts (how many interrupts are to this thing?!?) */
			scc_write_reg(regs,  i,  9, SCC_WR9_NV);

			scc_read_reg_zero(regs, 0, bits);/* Clear the status */
		}
                scc_parm_done = 1;			/* (TEST/DEBUG) */
	}

	serial_initted = TRUE;

	FUNNEL_EXIT(&SCC_FUNNEL);
	return;
}

int
scc_probe(int32_t serial_baud)
{
	scc_softc_t     scc;
	register int	val, i;
	register scc_regmap_t	regs;
	spl_t	s;
	DECL_FUNNEL_VARS

	if (!SCC_FUNNEL_INITTED) {
		FUNNEL_INIT(&SCC_FUNNEL, master_processor);
		SCC_FUNNEL_INITTED = TRUE;
	}
	FUNNEL_ENTER(&SCC_FUNNEL);

	/* Readjust the I/O address to handling 
	 * new memory mappings.
	 */

	regs = (scc_regmap_t)scc_std[0];

	if (regs == (scc_regmap_t) 0) {
		FUNNEL_EXIT(&SCC_FUNNEL);
		return 0;
	}

	scc = &scc_softc[0];
	scc->regs = regs;

	s = splhigh();

	for (i = 0; i < NSCC_LINE; i++) {
		register struct scc_tty	*tp;
		tp = scc_tty_for(i);
		tp->t_addr = (char*)(0x80000000L + (i&1));
		/* Set default values.  These will be overridden on
		   open but are needed if the port will be used
		   independently of the Mach interfaces, e.g., for
		   gdb or for a serial console.  */
		if (i == 0) {
		  tp->t_ispeed = DEFAULT_PORT0_SPEED;
		  tp->t_ospeed = DEFAULT_PORT0_SPEED;
		} else {
		  tp->t_ispeed = serial_baud;
		  tp->t_ospeed = serial_baud;
		}
		tp->t_flags = DEFAULT_FLAGS;
		scc->softr[i].speed = -1;

		/* do min buffering */
		tp->t_state |= TS_MIN;

		tp->t_dev = scc_dev_no(i);
	}

	splx(s);

	FUNNEL_EXIT(&SCC_FUNNEL);
	return 1;
}

/*
 * Get a char from a specific SCC line
 * [this is only used for console&screen purposes]
 * must be splhigh since it may be called from another routine under spl
 */

int
scc_getc(int unit, int line, boolean_t wait, boolean_t raw)
{
	register scc_regmap_t	regs;
	unsigned char   c, value;
	int             rcvalue, from_line;
	spl_t		s = splhigh();
	DECL_FUNNEL_VARS

	FUNNEL_ENTER(&SCC_FUNNEL);

	simple_lock(&scc_stomp);					/* (TEST/DEBUG) */
	regs = scc_softc[0].regs;

	/*
	 * wait till something available
	 *
	 */
again:
	rcvalue = 0;
	while (1) {
		scc_read_reg_zero(regs, line, value);

		if (value & SCC_RR0_RX_AVAIL)
			break;

		if (!wait) {
			simple_unlock(&scc_stomp);			/* (TEST/DEBUG) */
			splx(s);
			FUNNEL_EXIT(&SCC_FUNNEL);
			return -1;
		}
	}

	/*
	 * if nothing found return -1
	 */

	scc_read_reg(regs, line, SCC_RR1, value);
	scc_read_data(regs, line, c);

#if	MACH_KDB
	if (console_is_serial() &&
	    c == ('_' & 0x1f)) {
		/* Drop into the debugger */
		simple_unlock(&scc_stomp);				/* (TEST/DEBUG) */
		Debugger("Serial Line Request");
		simple_lock(&scc_stomp);				/* (TEST/DEBUG) */
		scc_write_reg(regs, line, SCC_RR0, SCC_RESET_HIGHEST_IUS);
		if (wait) {
			goto again;
		}
		simple_unlock(&scc_stomp);				/* (TEST/DEBUG) */
		splx(s);
		FUNNEL_EXIT(&SCC_FUNNEL);
		return -1;
	}
#endif	/* MACH_KDB */

	/*
	 * bad chars not ok
	 */
	if (value&(SCC_RR1_PARITY_ERR | SCC_RR1_RX_OVERRUN | SCC_RR1_FRAME_ERR)) {
		scc_write_reg(regs, line, SCC_RR0, SCC_RESET_ERROR);

		if (wait) {
			scc_write_reg(regs, line, SCC_RR0, SCC_RESET_HIGHEST_IUS);
			goto again;
		}
	}

	scc_write_reg(regs, line, SCC_RR0, SCC_RESET_HIGHEST_IUS);

	simple_unlock(&scc_stomp);					/* (TEST/DEBUG) */
	splx(s);

	FUNNEL_EXIT(&SCC_FUNNEL);
	return c;
}

/*
 * Put a char on a specific SCC line
 * use splhigh since we might be doing a printf in high spl'd code
 */

int
scc_putc(int unit, int line, int c)
{
	scc_regmap_t	regs;
	spl_t            s;
	unsigned char	 value;
	DECL_FUNNEL_VARS

	if (disableSerialOuput)
		return 0;

	s = splhigh();
	FUNNEL_ENTER(&SCC_FUNNEL);
	simple_lock(&scc_stomp);				/* (TEST/DEBUG) */

	regs = scc_softc[0].regs;

	do {
		scc_read_reg(regs, line, SCC_RR0, value);
		if (value & SCC_RR0_TX_EMPTY)
			break;
		delay(1);
	} while (1);

	scc_write_data(regs, line, c);
/* wait for it to swallow the char ? */

	do {
		scc_read_reg(regs, line, SCC_RR0, value);
		if (value & SCC_RR0_TX_EMPTY)
			break;
	} while (1);
	scc_write_reg(regs, line, SCC_RR0, SCC_RESET_HIGHEST_IUS);
	simple_unlock(&scc_stomp);				/* (TEST/DEBUG) */

	splx(s);

	FUNNEL_EXIT(&SCC_FUNNEL);
	return 0;
}


void
powermac_scc_set_datum(scc_regmap_t regs, unsigned int offset, unsigned char value)
{
	volatile unsigned char *address = (unsigned char *) regs + offset;
  
	assert(FUNNEL_IN_USE(&SCC_FUNNEL));

	*address = value;
	eieio();

	assert(FUNNEL_IN_USE(&SCC_FUNNEL));
}
  
unsigned char
powermac_scc_get_datum(scc_regmap_t regs, unsigned int offset)
{
	volatile unsigned char *address = (unsigned char *) regs + offset;
	unsigned char	value;
  
	assert(FUNNEL_IN_USE(&SCC_FUNNEL));

	value = *address; eieio();
	return value;

	assert(FUNNEL_IN_USE(&SCC_FUNNEL));
}

int
scc_param(struct scc_tty *tp)
{
	scc_regmap_t	regs;
	unsigned char	value;
	unsigned short	speed_value;
	int		bits, chan;
	spl_t		s;
	struct scc_softreg	*sr;
	scc_softc_t	scc;

	assert(FUNNEL_IN_USE(&SCC_FUNNEL));
	
	s = splhigh();
	simple_lock(&scc_stomp);				/* (TEST/DEBUG) */

	chan = scc_chan(tp->t_dev);
	scc = &scc_softc[0];
	regs = scc->regs;

	sr = &scc->softr[chan];
	
	/* Do a quick check to see if the hardware needs to change */
	if ((sr->flags & (TF_ODDP|TF_EVENP)) == (tp->t_flags & (TF_ODDP|TF_EVENP))
	    && sr->speed == tp->t_ispeed) {
		assert(FUNNEL_IN_USE(&SCC_FUNNEL));
		simple_unlock(&scc_stomp);					/* (TEST/DEBUG) */
		splx(s);											/* (TEST/DEBUG) */
		return 0;											/* (TEST/DEBUG) */
	}

	if(scc_parm_done) 	{								
		
		scc_write_reg(regs,  chan,  3, SCC_WR3_RX_8_BITS|SCC_WR3_RX_ENABLE);	/* (TEST/DEBUG) */
		sr->wr1 = SCC_WR1_RXI_FIRST_CHAR | SCC_WR1_EXT_IE;	/* (TEST/DEBUG) */
		scc_write_reg(regs,  chan,  1, sr->wr1);			/* (TEST/DEBUG) */
       	scc_write_reg(regs,  chan, 15, SCC_WR15_ENABLE_ESCC);	/* (TEST/DEBUG) */
		scc_write_reg(regs,  chan,  7, SCC_WR7P_RX_FIFO);	/* (TEST/DEBUG) */
		scc_write_reg(regs,  chan,  0, SCC_IE_NEXT_CHAR);	/* (TEST/DEBUG) */
		scc_write_reg(regs,  chan,  0, SCC_RESET_EXT_IP);	/* (TEST/DEBUG) */
		scc_write_reg(regs,  chan,  0, SCC_RESET_EXT_IP);	/* (TEST/DEBUG) */
		scc_write_reg(regs,  chan,  9, SCC_WR9_MASTER_IE|SCC_WR9_NV);	/* (TEST/DEBUG) */
		scc_read_reg_zero(regs, 0, bits);					/* (TEST/DEBUG) */
		sr->wr1 = SCC_WR1_RXI_FIRST_CHAR | SCC_WR1_EXT_IE;	/* (TEST/DEBUG) */
		scc_write_reg(regs,  chan,  1, sr->wr1);			/* (TEST/DEBUG) */
		scc_write_reg(regs,  chan,  0, SCC_IE_NEXT_CHAR);	/* (TEST/DEBUG) */
		simple_unlock(&scc_stomp);							/* (TEST/DEBUG) */
		splx(s);											/* (TEST/DEBUG) */
		return 0;											/* (TEST/DEBUG) */
	}
	
	sr->flags = tp->t_flags;
	sr->speed = tp->t_ispeed;


	if (tp->t_ispeed == 0) {
		sr->wr5 &= ~SCC_WR5_DTR;
		scc_write_reg(regs,  chan, 5, sr->wr5);
		simple_unlock(&scc_stomp);							/* (TEST/DEBUG) */
		splx(s);

		assert(FUNNEL_IN_USE(&SCC_FUNNEL));
		return 0;
	}
	

#if	SCC_DMA_TRANSFERS
	if (scc->dma_initted & (1<<chan)) 
		scc->dma_ops->scc_dma_reset_rx(chan);
#endif

	value = SCC_WR4_1_STOP;

	/* 
	 * For 115K the clocking divide changes to 64.. to 230K will
	 * start at the normal clock divide 16.
	 *
	 * However, both speeds will pull from a different clocking
	 * source
	 */

	if (tp->t_ispeed == 115200)
		value |= SCC_WR4_CLK_x32;
	else	
		value |= SCC_WR4_CLK_x16 ;

	/* .. and parity */
	if ((tp->t_flags & (TF_ODDP | TF_EVENP)) == TF_EVENP)
		value |= (SCC_WR4_EVEN_PARITY |  SCC_WR4_PARITY_ENABLE);
	else if ((tp->t_flags & (TF_ODDP | TF_EVENP)) == TF_ODDP)
		value |= SCC_WR4_PARITY_ENABLE;

	/* set it now, remember it must be first after reset */
	sr->wr4 = value;

	/* Program Parity, and Stop bits */
	scc_write_reg(regs,  chan, 4, sr->wr4);

	/* Setup for 8 bits */
	scc_write_reg(regs,  chan, 3, SCC_WR3_RX_8_BITS);

	// Set DTR, RTS, and transmitter bits/character.
	sr->wr5 = SCC_WR5_TX_8_BITS | SCC_WR5_RTS | SCC_WR5_DTR;

	scc_write_reg(regs,  chan, 5, sr->wr5);
	
	scc_write_reg(regs, chan, 14, 0);	/* Disable baud rate */

	/* Setup baud rate 57.6Kbps, 115K, 230K should all yeild
	 * a converted baud rate of zero
	 */
	speed_value = convert_baud_rate(tp->t_ispeed);

	if (speed_value == 0xffff)
		speed_value = 0;

	scc_set_timing_base(regs, chan, speed_value);
	
	if (tp->t_ispeed == 115200 || tp->t_ispeed == 230400) {
		/* Special case here.. change the clock source*/
		scc_write_reg(regs, chan, 11, 0);
		/* Baud rate generator is disabled.. */
	} else {
		scc_write_reg(regs, chan, 11, SCC_WR11_RCLK_BAUDR|SCC_WR11_XTLK_BAUDR);
		/* Enable the baud rate generator */
		scc_write_reg(regs,  chan, 14, SCC_WR14_BAUDR_ENABLE);
	}


	scc_write_reg(regs,  chan,  3, SCC_WR3_RX_8_BITS|SCC_WR3_RX_ENABLE);


	sr->wr1 = SCC_WR1_RXI_FIRST_CHAR | SCC_WR1_EXT_IE;
	scc_write_reg(regs,  chan,  1, sr->wr1);
       	scc_write_reg(regs,  chan, 15, SCC_WR15_ENABLE_ESCC);
	scc_write_reg(regs,  chan,  7, SCC_WR7P_RX_FIFO);
	scc_write_reg(regs,  chan,  0, SCC_IE_NEXT_CHAR);


	/* Clear out any pending external or status interrupts */
	scc_write_reg(regs,  chan,  0, SCC_RESET_EXT_IP);
	scc_write_reg(regs,  chan,  0, SCC_RESET_EXT_IP);
	//scc_write_reg(regs,  chan,  0, SCC_RESET_ERROR);

	/* Enable SCC interrupts (how many interrupts are to this thing?!?) */
	scc_write_reg(regs,  chan,  9, SCC_WR9_MASTER_IE|SCC_WR9_NV);

	scc_read_reg_zero(regs, 0, bits);/* Clear the status */

#if	SCC_DMA_TRANSFERS
	if (scc->dma_initted & (1<<chan))  {
		scc->dma_ops->scc_dma_start_rx(chan);
		scc->dma_ops->scc_dma_setup_8530(chan);
	} else
#endif
	{
		sr->wr1 = SCC_WR1_RXI_FIRST_CHAR | SCC_WR1_EXT_IE;
		scc_write_reg(regs, chan, 1, sr->wr1);
		scc_write_reg(regs, chan, 0, SCC_IE_NEXT_CHAR);
	}

	sr->wr5 |= SCC_WR5_TX_ENABLE;
	scc_write_reg(regs,  chan,  5, sr->wr5);

	simple_unlock(&scc_stomp);			/* (TEST/DEBUG) */
	splx(s);

	assert(FUNNEL_IN_USE(&SCC_FUNNEL));
	return 0;

}

/*
 *  This routine will start a thread that polls the serial port, listening for
 *  characters that have been typed.
 */

void
serial_keyboard_init(void)
{
	kern_return_t	result;
	thread_t		thread;

	if(!(serialmode & 2)) return;		/* Leave if we do not want a serial console */

	kprintf("Serial keyboard started\n");
	result = kernel_thread_start_priority((thread_continue_t)serial_keyboard_start, NULL, MAXPRI_KERNEL, &thread);
	if (result != KERN_SUCCESS)
		panic("serial_keyboard_init");

	thread_deallocate(thread);
}

void
serial_keyboard_start(void)
{
	serial_keyboard_poll();			/* Go see if there are any characters pending now */
	panic("serial_keyboard_start: we can't get back here\n");
}

void
serial_keyboard_poll(void)
{
	int chr;
	uint64_t next;
	extern void cons_cinput(char ch);	/* The BSD routine that gets characters */

	while(1) {				/* Do this for a while */
		chr = scc_getc(0, 1, 0, 1);	/* Get a character if there is one */
		if(chr < 0) break;		/* The serial buffer is empty */
		cons_cinput((char)chr);		/* Buffer up the character */
	}

	clock_interval_to_deadline(16, 1000000, &next);	/* Get time of pop */

	assert_wait_deadline((event_t)serial_keyboard_poll, THREAD_UNINT, next);	/* Show we are "waiting" */
	thread_block((thread_continue_t)serial_keyboard_poll);	/* Wait for it */
	panic("serial_keyboard_poll: Shouldn't never ever get here...\n");
}

#endif	/* NSCC > 0 */
