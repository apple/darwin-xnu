/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * HISTORY
 * 
 * Revision 1.1.1.1.12.1  1998/10/06 20:27:13  ehewitt
 * Updated for framebuffer support.  Added pexpert calls.
 *
 * Revision 1.1.1.1  1998/09/22 21:05:39  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:38  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.22.1  1996/11/29  16:56:42  stephen
 * 	nmklinux_1.0b3_shared into pmk1.1
 * 	Include mach/mach_ioctl.h instead of sys/ioctl.h and use the
 * 	"MACH"-prefixed ioctl definitions.
 * 	Include mach/time_value.h instead of sys/time.h and use the
 * 	new time types.
 * 	Replaced u_char, u_short and u_int types with real ones.
 * 	[96/09/18            barbou]
 *
 * Revision 1.1.18.1  1996/09/17  16:33:38  bruel
 * 	use standalone includes only
 * 	[1996/09/17  15:27:38  bruel]
 * 
 * Revision 1.1.6.5  1996/07/31  20:49:24  paire
 * 	Merged with changes from 1.1.6.4
 * 	[1996/07/31  20:38:47  paire]
 * 
 * 	Merged with changes from 1.1.6.4
 * 	[1996/07/31  14:58:21  paire]
 * 
 * Revision 1.1.6.4  1996/07/31  13:23:35  paire
 * 	Merged with nmk20b7_shared (1.1.11.1)
 * 	[96/06/07            paire]
 * 
 * Revision 1.1.11.1  1996/03/04  16:11:12  bernadat
 * 	Changed mouse_rawbuf struct to keep same kd_event struct size.
 * 	[96/02/22            bernadat]
 * 
 * Revision 1.1.6.2  1996/02/19  13:35:33  bernadat
 * 	Adapted to be exported to users (added some #ifdef MACH_KERNEL).
 * 	Modified kd_event structure to allow raw (unprocessed) mouse events.
 * 	[96/01/29            barbou]
 * 
 * Revision 1.1.6.1  1994/09/23  01:42:33  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:18:52  ezf]
 * 
 * Revision 1.1.2.4  1993/08/09  19:38:22  dswartz
 * 	Add ANSI prototypes - CR#9523
 * 	[1993/08/06  17:50:44  dswartz]
 * 
 * Revision 1.1.2.3  1993/08/03  18:29:12  gm
 * 	CR9596: Change KERNEL to MACH_KERNEL.
 * 	[1993/08/02  16:04:31  gm]
 * 
 * Revision 1.1.2.2  1993/06/02  23:20:30  jeffc
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:02:41  jeffc]
 * 
 * Revision 1.1  1992/09/30  02:27:08  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.7.9.1  92/02/18  18:55:07  jeffreyh
 * 	Added two defines to detect if a PC Keyboard is present
 * 	[91/06/25            bernadat]
 * 
 * Revision 2.7  91/05/14  16:26:55  mrt
 * 	Correcting copyright
 * 
 * Revision 2.6  91/03/16  14:46:53  rpd
 * 	Fixed ioctl definitions for ANSI C.
 * 	[91/02/20            rpd]
 * 
 * Revision 2.5  91/02/05  17:19:03  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  17:45:28  mrt]
 * 
 * Revision 2.4  90/11/26  14:50:27  rvb
 * 	jsb bet me to XMK34, sigh ...
 * 	[90/11/26            rvb]
 * 	Synched 2.5 & 3.0 at I386q (r1.5.1.5) & XMK35 (r2.4)
 * 	[90/11/15            rvb]
 * 
 * Revision 1.5.1.4  90/06/07  08:05:44  rvb
 * 	Move CURRENT_COLUMN here.
 * 	[90/06/06            rvb]
 * 
 * Revision 2.3  90/08/09  16:32:09  rpd
 * 	Added kdb/X support from rvb.
 * 	[90/08/09            rpd]
 * 
 * Revision 1.5.1.3  90/05/14  13:21:26  rvb
 * 	Support for entering kdb from X;
 * 	[90/04/30            rvb]
 * 
 * Revision 2.2  90/05/03  15:44:47  dbg
 * 	First checkin.
 * 
 * Revision 1.5.1.2  90/02/28  15:50:17  rvb
 * 	Fix numerous typo's in Olivetti disclaimer.
 * 	[90/02/28            rvb]
 * 
 * Revision 1.5.1.1  90/01/08  13:30:59  rvb
 * 	Add Olivetti copyright.
 * 	[90/01/08            rvb]
 * 
 * Revision 1.5  89/07/17  10:41:10  rvb
 * 	Olivetti Changes to X79 upto 5/9/89:
 * 	[89/07/11            rvb]
 * 
 * Revision 1.6  89/07/07  16:24:24  kupfer
 * X79 merge, 2nd attempt
 * 
 * Revision 1.4.1.1  89/04/27  12:20:58  kupfer
 * Merge X79 with our latest and greatest.
 * 
 * Revision 1.1.1.1  89/04/27  11:53:41  kupfer
 * X79 from CMU.
 * 
 * Revision 1.4  89/03/09  20:06:33  rpd
 * 	More cleanup.
 * 
 * Revision 1.3  89/02/26  12:37:13  gm0w
 * 	Changes for cleanup.
 * 
 */
/* CMU_ENDHIST */
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
 *  File:         kd.h
 *  Description:  definitions for AT keyboard/display driver
 *  Authors:       Eugene Kuerner, Adrienne Jardetzky, Mike Kupfer
 * 
 *  $ Header: $
 * 
 *  Copyright Ing. C. Olivetti & C. S.p.A. 1988, 1989.
 *  All rights reserved.
 * 
 *   Copyright 1988, 1989 by Olivetti Advanced Technology Center, Inc.,
 * Cupertino, California.
 * 
 * 		All Rights Reserved
 * 
 *   Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that the above copyright notice appears in all
 * copies and that both the copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Olivetti
 * not be used in advertising or publicity pertaining to distribution
 * of the software without specific, written prior permission.
 * 
 *   OLIVETTI DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS,
 * IN NO EVENT SHALL OLIVETTI BE LIABLE FOR ANY SPECIAL, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN ACTION OF CONTRACT,
 * NEGLIGENCE, OR OTHER TORTIOUS ACTION, ARISING OUR OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * This file contains defines and structures that implement hardware
 * keyboard mapping into ansi defined output codes.  Note that this
 * is structured so that "re-mapping" of actual keys is allowed at
 * anytime during execution of the console driver.  And each scan code
 * is potentially expanded into NUMKEYS characters.  Which is programmable
 * at runtime or whenever.
 *
 * 02 Nov 1988		orc!eugene
 *
 */

#ifndef	_MACHINE_KD_H_
#define _MACHINE_KD_H_

#include <mach/boolean.h>
#include <mach/time_value.h>


/*
 * Where memory for various graphics adapters starts.
 */
#define EGA_START	0x0b8000
#define CGA_START	0x0b8000
#define MONO_START	0x0b0000

/*
 * Common I/O ports.
 */
#define K_TMR0		0x40		/* timer 0, 1, or 2 value (r/w) */
#define K_TMR1		0x41
#define K_TMR2		0x42
#define K_TMRCTL	0x43		/* timer control (write-only) */
#define K_RDWR 		0x60		/* keyboard data & cmds (read/write) */
#define K_PORTB		0x61		/* r/w. speaker & status lines */
#define K_STATUS 	0x64		/* keybd status (read-only) */
#define K_CMD	 	0x64		/* keybd ctlr command (write-only) */

/*
 * I/O ports for various graphics adapters.
 */
#define EGA_IDX_REG	0x3d4
#define EGA_IO_REG	0x3d5
#define CGA_IDX_REG	0x3d4
#define CGA_IO_REG	0x3d5
#define MONO_IDX_REG	0x3b4
#define MONO_IO_REG	0x3b5

/*
 * Commands sent to graphics adapter.
 */
#define C_LOW 		0x0f		/* return low byte of cursor addr */
#define C_HIGH 		0x0e		/* high byte */

/*
 * Bit definitions for K_STATUS port.
 */
#define K_OBUF_FUL 	0x01		/* output (from keybd) buffer full */
#define K_IBUF_FUL 	0x02		/* input (to keybd) buffer full */
#define K_SYSFLAG	0x04		/* "System Flag" */
#define K_CMD_DATA	0x08		/* 1 = input buf has cmd, 0 = data */
#define K_KBD_INHBT	0x10		/* 0 if keyboard inhibited */
#define K_XMT_TIMEOUT	0x20		/* Transmit time out */
#define K_RCV_TIMEOUT	0x40		/* Receive time out */

/* 
 * Keyboard controller commands (sent to K_CMD port).
 */
#define KC_CMD_READ	0x20		/* read controller command byte */
#define KC_CMD_WRITE	0x60		/* write controller command byte */
#define KC_CMD_TEST	0xab		/* test interface */
#define KC_CMD_DUMP	0xac		/* diagnostic dump */
#define KC_CMD_DISBLE	0xad		/* disable keyboard */
#define KC_CMD_ENBLE	0xae		/* enable keyboard */
#define KC_CMD_RDKBD	0xc4		/* read keyboard ID */
#define KC_CMD_ECHO	0xee		/* used for diagnostic testing */

/* 
 * Keyboard commands (send to K_RDWR).
 */
#define K_CMD_LEDS	0xed		/* set status LEDs (caps lock, etc.) */

/* 
 * Bit definitions for controller command byte (sent following 
 * K_CMD_WRITE command).
 */
#define K_CB_ENBLIRQ	0x01		/* enable data-ready intrpt */
#define K_CB_SETSYSF	0x04		/* Set System Flag */
#define K_CB_INHBOVR	0x08		/* Inhibit Override */
#define K_CB_DISBLE	0x10		/* disable keyboard */

/* 
 * Bit definitions for "Indicator Status Byte" (sent after a 
 * K_CMD_LEDS command).  If the bit is on, the LED is on.  Undefined 
 * bit positions must be 0.
 */
#define K_LED_SCRLLK	0x1		/* scroll lock */
#define K_LED_NUMLK	0x2		/* num lock */
#define K_LED_CAPSLK	0x4		/* caps lock */

/* 
 * Bit definitions for "Miscellaneous port B" (K_PORTB).
 */
/* read/write */
#define K_ENABLETMR2	0x01		/* enable output from timer 2 */
#define K_SPKRDATA	0x02		/* direct input to speaker */
#define K_ENABLEPRTB	0x04		/* "enable" port B */
#define K_EIOPRTB	0x08		/* enable NMI on parity error */
/* read-only */
#define K_REFRESHB	0x10		/* refresh flag from INLTCONT PAL */
#define K_OUT2B		0x20		/* timer 2 output */
#define K_ICKB		0x40		/* I/O channel check (parity error) */

/* 
 * Bit definitions for timer control port (K_TMRCTL).
 */
/* select timer 0, 1, or 2. Don't mess with 0 or 1. */
#define K_SELTMRMASK	0xc0
#define K_SELTMR0	0x00
#define K_SELTMR1	0x40
#define K_SELTMR2	0x80

/* read/load control */
#define K_RDLDTMRMASK	0x30
#define K_HOLDTMR	0x00		/* freeze timer until read */
#define K_RDLDTLSB	0x10		/* read/load LSB */
#define K_RDLDTMSB	0x20		/* read/load MSB */
#define K_RDLDTWORD	0x30		/* read/load LSB then MSB */

/* mode control */
#define K_TMDCTLMASK	0x0e
#define K_TCOUNTINTR	0x00		/* "Term Count Intr" */
#define K_TONESHOT	0x02		/* "Progr One-Shot" */
#define K_TRATEGEN	0x04		/* "Rate Gen (/n)" */
#define K_TSQRWAVE	0x06		/* "Sqr Wave Gen" */
#define K_TSOFTSTRB	0x08		/* "Softw Trig Strob" */
#define K_THARDSTRB	0x0a		/* "Hardw Trig Strob" */

/* count mode */
#define K_TCNTMDMASK	0x01
#define K_TBINARY	0x00		/* 16-bit binary counter */
#define K_TBCD		0x01		/* 4-decade BCD counter */



/* 
 * Fun definitions for displayed characters and characters read from 
 * the keyboard.
 */

/*
 * Attributes for character sent to display.
 */
#define KA_NORMAL	0x07
#define KA_REVERSE	0x70

/*
 * For an EGA-like display, each character takes two bytes, one for the 
 * actual character, followed by one for its attributes.  
 * Be very careful if you change ONE_SPACE, as these constants are also used
 * to define the device-independent display implemented by kd.c.  
 * (See kdsoft.h for more details on the device-independent display.)
 */
#define ONE_SPACE	2		/* bytes in 1 char, EGA-like display */
#define ONE_LINE 	(kd_cols * ONE_SPACE)	/* 160 number of bytes in line */
#define ONE_PAGE 	(kd_lines * ONE_LINE)	/* 4000 number of bytes in page */
#define BOTTOM_LINE 	((kd_lines - 1) * ONE_LINE) /* 3840 1st byte in last line of display */

#define BEG_OF_LINE(pos)	((pos) - (pos)%ONE_LINE)
#define CURRENT_COLUMN(pos)	(((pos) % ONE_LINE) / ONE_SPACE)

#define NUMKEYS		89
#define NUMSTATES	5		/* NORMAL_STATE, ... */
#define NUMOUTPUT 	3		/* max size of byte seq from key */
#define WIDTH_KMAP	(NUMSTATES * NUMOUTPUT)

/*
 * Keyboard states.  Used for KDGKBENT, KDSKBENT ioctl's.  If you
 * change these values, you should also rearrange the entries in
 * key_map.
 */
/* "state indices" (for computing key_map index) */
#define NORM_STATE	0
#define SHIFT_STATE	1
#define CTRL_STATE	2
#define ALT_STATE	3
#define SHIFT_ALT	4
/* macro to convert from state index to actual key_map index */
#define CHARIDX(sidx)	((sidx) * NUMOUTPUT)
			/* where sidx is in [NORM_STATE ... SHIFT_ALT] */

/* "state bits" for kd_state vector */
#define KS_NORMAL	0x00
#define KS_SLKED	0x01
#define KS_NLKED	0x02
#define KS_CLKED	0x04
#define KS_ALTED	0x08
#define KS_SHIFTED	0x10
#define KS_CTLED	0x20


/*
 * Scancode values, not to be confused with Ascii values.
 */
typedef unsigned char Scancode;

/* special codes */
#define K_UP		0x80		/* OR'd in if key below is released */
#define K_EXTEND	0xe0		/* marker for "extended" sequence */
#define K_ACKSC		0xfa		/* ack for keyboard command */
#define K_RESEND	0xfe		/* request to resend keybd cmd */

/* modifier keys  */
#define K_CTLSC		0x1d		/* control down		*/
#define K_LSHSC		0x2a		/* left shift down	*/
#define K_RSHSC		0x36		/* right shift down	*/
#define K_ALTSC		0x38		/* alt key down		*/
#define K_CLCKSC	0x3a		/* caps lock 		*/
#define K_NLCKSC	0x45		/* num lock down	*/

/* "special keys" */
#define K_BSSC		0x0e		/* backspace */
#define K_TABSC		0x0f		/* tab */
#define K_RETSC		0x1c		/* return */
#define K_SPSC		0x39		/* space */
#define K_ESCSC		0x01		/* ESC */

/* alphabetic keys */
#define K_qSC		0x10
#define K_wSC		0x11
#define K_eSC		0x12
#define K_rSC		0x13
#define K_tSC		0x14
#define K_ySC		0x15
#define K_uSC		0x16
#define K_iSC		0x17
#define K_oSC		0x18
#define K_pSC		0x19

#define K_aSC		0x1e
#define K_sSC		0x1f
#define K_dSC		0x20
#define K_fSC		0x21
#define K_gSC		0x22
#define K_hSC		0x23
#define K_jSC		0x24
#define K_kSC		0x25
#define K_lSC		0x26

#define K_zSC		0x2c
#define K_xSC		0x2d
#define K_cSC		0x2e
#define K_vSC		0x2f
#define K_bSC		0x30
#define K_nSC		0x31
#define K_mSC		0x32

/* numbers and punctuation */
#define K_ONESC		0x02		/* 1	*/
#define K_TWOSC		0x03		/* 2	*/
#define K_THREESC	0x04		/* 3	*/
#define K_FOURSC	0x05		/* 4	*/
#define K_FIVESC	0x06		/* 5	*/
#define K_SIXSC		0x07		/* 6	*/
#define K_SEVENSC	0x08		/* 7	*/
#define K_EIGHTSC	0x09		/* 8	*/
#define K_NINESC	0x0a		/* 9	*/
#define K_ZEROSC	0x0b		/* 0	*/

#define K_MINUSSC	0x0c		/* -	*/
#define K_EQLSC		0x0d		/* =	*/
#define K_LBRKTSC	0x1a		/* [	*/
#define K_RBRKTSC	0x1b		/* ]	*/
#define K_SEMISC	0x27		/* ;	*/
#define K_SQUOTESC	0x28		/* '	*/
#define K_GRAVSC	0x29		/* `	*/
#define K_BSLSHSC	0x2b		/* \	*/
#define K_COMMASC	0x33		/* ,	*/
#define K_PERIODSC	0x34		/* .	*/
#define K_SLASHSC	0x35		/* /	*/

/* keypad keys */
#define K_HOMESC	0x47		/* scancode for home 	*/
#define K_DELSC		0x53		/* scancode for del	*/

/*
 * Ascii values and flag characters for key map.
 * A function key is represented by the 3-byte char sequence that it
 * corresponds to.
 * Other mappable non-Ascii keys (e.g., "ctrl") are represented by a
 * two-byte sequence: K_SCAN, followed by the key's scan code.
 */
#define K_DONE		0xff		/* must be same as NC */
#define NC		0xff		/* No character defined	*/

#define K_SCAN		0xfe		/* followed by scan code */

/* ascii char set */
#define K_NUL		0x00		/* Null character	*/
#define K_SOH		0x01
#define K_STX		0x02
#define K_ETX		0x03
#define K_EOT		0x04
#define K_ENQ		0x05
#define K_ACK		0x06
#define K_BEL		0x07		/* bell character	*/
#define K_BS		0x08		/* back space		*/
#define K_HT		0x09
#define K_LF		0x0a		/* line feed		*/
#define K_VT		0x0b
#define K_FF		0x0c
#define K_CR		0x0d		/* carriage return	*/
#define K_SO		0x0e
#define K_SI		0x0f
#define K_DLE		0x10
#define K_DC1		0x11
#define K_DC2		0x12
#define K_DC3		0x13
#define K_DC4		0x14
#define K_NAK		0x15
#define K_SYN		0x16
#define K_ETB		0x17
#define K_CAN		0x18
#define K_EM		0x19
#define K_SUB		0x1a
#define K_ESC		0x1b		/* escape character	*/
#define K_FS		0x1c
#define K_GS		0x1d
#define K_RS		0x1e
#define K_US		0x1f
#define K_SPACE		0x20		/* space character	*/
#define K_BANG		0x21		/* !			*/
#define K_DQUOTE	0x22		/* "			*/
#define K_POUND		0x23		/* #			*/ 
#define K_DOLLAR	0x24		/* $			*/ 
#define K_PERC		0x25		/* %			*/ 
#define K_AMPER		0x26		/* &			*/ 
#define K_SQUOTE	0x27		/* '			*/ 
#define K_LPAREN	0x28		/* (			*/ 
#define K_RPAREN	0x29		/* )			*/ 
#define K_ASTER		0x2a		/* *			*/ 
#define K_PLUS		0x2b		/* +			*/ 
#define K_COMMA		0x2c		/* ,			*/ 
#define K_MINUS		0x2d		/* -			*/ 
#define K_PERIOD	0x2e		/* .			*/ 
#define K_SLASH		0x2f		/* /			*/ 
#define K_ZERO		0x30		/* 0			*/ 
#define K_ONE		0x31		/* 1			*/
#define K_TWO		0x32		/* 2			*/
#define K_THREE		0x33		/* 3			*/
#define K_FOUR		0x34		/* 4			*/
#define K_FIVE		0x35		/* 5			*/
#define K_SIX		0x36		/* 6			*/
#define K_SEVEN		0x37		/* 7			*/
#define K_EIGHT		0x38		/* 8			*/
#define K_NINE		0x39		/* 9			*/
#define K_COLON		0x3a		/* :			*/
#define K_SEMI		0x3b		/* ;			*/
#define K_LTHN		0x3c		/* <			*/
#define K_EQL		0x3d		/* =			*/
#define K_GTHN		0x3e		/* >			*/
#define K_QUES		0x3f		/* ?			*/
#define K_ATSN		0x40		/* @			*/
#define K_A		0x41		/* A			*/
#define K_B		0x42		/* B			*/
#define K_C		0x43		/* C			*/
#define K_D		0x44		/* D			*/
#define K_E		0x45		/* E			*/
#define K_F		0x46		/* F			*/
#define K_G		0x47		/* G			*/
#define K_H		0x48		/* H			*/
#define K_I		0x49		/* I			*/
#define K_J		0x4a		/* J			*/
#define K_K		0x4b		/* K			*/
#define K_L		0x4c		/* L			*/
#define K_M		0x4d		/* M			*/
#define K_N		0x4e		/* N			*/
#define K_O		0x4f		/* O			*/
#define K_P		0x50		/* P			*/
#define K_Q		0x51		/* Q			*/
#define K_R		0x52		/* R			*/
#define K_S		0x53		/* S			*/
#define K_T		0x54		/* T			*/
#define K_U		0x55		/* U			*/
#define K_V		0x56		/* V			*/
#define K_W		0x57		/* W			*/
#define K_X		0x58		/* X			*/
#define K_Y		0x59		/* Y			*/
#define K_Z		0x5a		/* Z			*/
#define K_LBRKT		0x5b		/* [			*/
#define K_BSLSH		0x5c		/* \			*/
#define K_RBRKT		0x5d		/* ]			*/
#define K_CARET		0x5e		/* ^			*/
#define K_UNDSC		0x5f		/* _			*/
#define K_GRAV		0x60		/* `			*/
#define K_a		0x61		/* a			*/
#define K_b		0x62		/* b			*/
#define K_c		0x63		/* c			*/
#define K_d		0x64		/* d			*/
#define K_e		0x65		/* e			*/
#define K_f		0x66		/* f			*/
#define K_g		0x67		/* g			*/
#define K_h		0x68		/* h			*/
#define K_i		0x69		/* i			*/
#define K_j		0x6a		/* j			*/
#define K_k		0x6b		/* k			*/
#define K_l		0x6c		/* l			*/
#define K_m		0x6d		/* m			*/
#define K_n		0x6e		/* n			*/
#define K_o		0x6f		/* o			*/
#define K_p		0x70		/* p			*/
#define K_q		0x71		/* q			*/
#define K_r		0x72		/* r			*/
#define K_s		0x73		/* s			*/
#define K_t		0x74		/* t			*/
#define K_u		0x75		/* u			*/
#define K_v		0x76		/* v			*/
#define K_w		0x77		/* w			*/
#define K_x		0x78		/* x			*/
#define K_y		0x79		/* y			*/
#define K_z		0x7a		/* z			*/
#define K_LBRACE	0x7b		/* {			*/
#define K_PIPE		0x7c		/* |			*/
#define K_RBRACE	0x7d		/* }			*/
#define K_TILDE		0x7e		/* ~			*/
#define K_DEL		0x7f		/* delete		*/

/* Ascii sequences to be generated by the named key */
#define K_F1		0x1b,0x4f,0x50
#define K_F1S		0x1b,0x4f,0x70
#define K_F2		0x1b,0x4f,0x51
#define K_F2S		0x1b,0x4f,0x71
#define K_F3		0x1b,0x4f,0x52
#define K_F3S		0x1b,0x4f,0x72
#define K_F4		0x1b,0x4f,0x53
#define K_F4S		0x1b,0x4f,0x73
#define K_F5		0x1b,0x4f,0x54
#define K_F5S		0x1b,0x4f,0x74
#define K_F6		0x1b,0x4f,0x55
#define K_F6S		0x1b,0x4f,0x75
#define K_F7		0x1b,0x4f,0x56
#define K_F7S		0x1b,0x4f,0x76
#define K_F8		0x1b,0x4f,0x57
#define K_F8S		0x1b,0x4f,0x77
#define K_F9		0x1b,0x4f,0x58
#define K_F9S		0x1b,0x4f,0x78
#define K_F10		0x1b,0x4f,0x59
#define K_F10S		0x1b,0x4f,0x79
#define K_F11		0x1b,0x4f,0x5a
#define K_F11S		0x1b,0x4f,0x7a
#define K_F12		0x1b,0x4f,0x41
#define K_F12S		0x1b,0x4f,0x61

#define K_SCRL		0x1b,0x5b,0x4d
#define K_HOME		0x1b,0x5b,0x48
#define K_UA		0x1b,0x5b,0x41
#define K_PUP		0x1b,0x5b,0x56
#define K_LA		0x1b,0x5b,0x44
#define K_RA		0x1b,0x5b,0x43
#define K_END		0x1b,0x5b,0x59
#define K_DA		0x1b,0x5b,0x42
#define K_PDN		0x1b,0x5b,0x55
#define K_INS		0x1b,0x5b,0x40


/*
 * This array maps scancodes to Ascii characters (or character
 * sequences).
 * The first index is the scancode.  The first NUMOUTPUT characters
 * (accessed using the second index) correspond to the key's char
 * sequence for the Normal state.  The next NUMOUTPUT characters
 * are for the Shift state, then Ctrl, then Alt, then Shift/Alt.
 */
extern unsigned char	key_map[NUMKEYS][WIDTH_KMAP];



/*
 * These routines are declared here so that all the modules making
 * up the kd driver agree on how to do locking.
 */

#define SPLKD	spltty


/*
 * Ioctl's on /dev/console.
 */

/*
 * KDGKBENT, KDSKBENT - Get and set keyboard table entry.  Useful for 
 *                      remapping keys.
 *
 * KDGSTATE - Get the keyboard state variable, which flags the 
 *            modifier keys (shift, ctrl, etc.) that are down.  See 
 *            KS_NORMAL et al above.  Used for debugging.
 *
 * KDSETBELL - Turns the bell on or off.
 */

#define KDGKBENT	_MACH_IOWR('k', 1, struct kbentry) /* get keybd entry */

#define KDSKBENT	_MACH_IOW('k', 2, struct kbentry) /* set keybd entry */

#define KDGSTATE	_MACH_IOR('k', 3, int)	/* get keybd state */

#define KDSETBELL	_MACH_IOW('k', 4, int)	/* turn bell on or off */
#	define	KD_BELLON	1
#	define	KD_BELLOFF	0

/*
 * This struct is used for getting and setting key definitions.  The
 * values for kb_index are obtainable from the man page for
 * keyboard(7) (though they should really be defined here!).
 */
struct kbentry {
	unsigned char kb_state;		/* which state to use */
	unsigned char kb_index;		/* which keycode */
	unsigned char kb_value[NUMOUTPUT];	/* value to get/set */
};


/*
 * Ioctl's on /dev/kbd.
 */

/*
 * KDSKBDMODE - When the console is in "ascii" mode, keyboard events are
 * converted to Ascii characters that are readable from /dev/console.
 * When the console is in "event" mode, keyboard events are
 * timestamped and queued up on /dev/kbd as kd_events.  When the last
 * close is done on /dev/kbd, the console automatically reverts to ascii
 * mode.
 * When /dev/mouse is opened, mouse events are timestamped and queued
 * on /dev/mouse, again as kd_events.
 *
 * KDGKBDTYPE - Returns the type of keyboard installed.  Currently
 * there is only one type, KB_VANILLAKB, which is your standard PC-AT
 * keyboard.
 */

extern	int	kb_mode;

#define KDSKBDMODE	_MACH_IOW('K', 1, int)	/* set keyboard mode */
#define KB_EVENT	1
#define KB_ASCII	2

#define KDGKBDTYPE	_MACH_IOR('K', 2, int)	/* get keyboard type */
#define KB_VANILLAKB	0

struct X_kdb {
	unsigned int *ptr;
	unsigned int size;
};

#define K_X_KDB_ENTER	_MACH_IOW('K', 16, struct X_kdb)
#define K_X_KDB_EXIT	_MACH_IOW('K', 17, struct X_kdb)

#define K_X_IN		0x01000000
#define K_X_OUT		0x02000000
#define K_X_BYTE	0x00010000
#define K_X_WORD	0x00020000
#define K_X_LONG	0x00040000
#define K_X_TYPE	0x03070000
#define K_X_PORT	0x0000ffff


typedef unsigned short kev_type;		/* kd event type */

/* (used for event records) */
struct mouse_motion {		
	short mm_deltaX;		/* units? */
	short mm_deltaY;
};

#define MOUSEBUFSIZE	5	/* num bytes def'd by protocol */

struct mouse_rawbuf {
	unsigned char	mr_bufsize;
	unsigned char	mr_buf[1];
};

typedef struct {
	kev_type type;			/* see below */
	struct time_value time;		/* timestamp */
	union {				/* value associated with event */
		boolean_t up;		/* MOUSE_LEFT .. MOUSE_RIGHT */
		Scancode sc;		/* KEYBD_EVENT */
		struct mouse_motion mmotion;	/* MOUSE_MOTION */
		struct mouse_rawbuf mrawbuf;	/* MOUSE_RAW */
	} value;
} kd_event;

#define m_deltaX	mmotion.mm_deltaX
#define m_deltaY	mmotion.mm_deltaY
#define r_buf		mrawbuf.mr_buf
#define r_bufsize	mrawbuf.mr_bufsize

/* 
 * kd_event ID's.
 */
#define MOUSE_LEFT	1		/* mouse left button up/down */
#define MOUSE_MIDDLE	2
#define MOUSE_RIGHT	3
#define MOUSE_MOTION	4		/* mouse motion */
#define KEYBD_EVENT	5		/* key up/down */

/* CMOS Info */

#define CMOS_ADDR	0x70		/* port for CMOS ram address */
#define CMOS_DATA	0x71		/* port for CMOS ram data */


/* Addresses, related masks, and potential results */

#define CMOS_EB		0x14		/* read Equipment Byte */
#define CM_SCRMSK	0x30		/* mask for EB query to get screen */
#define CM_EGA_VGA	0x00		/* "not CGA or MONO" */
#define CM_CGA_40	0x10
#define CM_CGA_80	0x20
#define CM_MONO_80	0x30


#endif	/* _MACHINE_KD_H_ */
