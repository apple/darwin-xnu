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
 */
 
/* 
 *	Olivetti Mach Console driver v0.0
 *	Copyright Ing. C. Olivetti & C. S.p.A. 1988, 1989
 *	All rights reserved.
 *
 */ 
/*
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
 *
 * 
 *   Copyright 1988, 1989 by Intel Corporation, Santa Clara, California.
 * 
 * 		All Rights Reserved
 * 
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that the above copyright notice appears in all
 * copies and that both the copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Intel
 * not be used in advertising or publicity pertaining to distribution
 * of the software without specific, written prior permission.
 * 
 * INTEL DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS,
 * IN NO EVENT SHALL INTEL BE LIABLE FOR ANY SPECIAL, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN ACTION OF CONTRACT,
 * NEGLIGENCE, OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $ Header:  $ */

#include <string.h>
#include "kd.h"

#include	<mach/i386/vm_param.h>

#define at386_io_lock_state()	
#define at386_io_lock(op)	(TRUE)
#define at386_io_unlock()


typedef unsigned short i386_ioport_t;

/* read a byte */
extern unsigned char	inb(
				i386_ioport_t	port);
/* write a longword */
extern void		outb(
				i386_ioport_t	port,
				unsigned char	datum);

extern __inline__ unsigned char inb(
				i386_ioport_t port)
{
	unsigned char datum;
	__asm__ volatile("inb %1, %0" : "=a" (datum) : "d" (port));
	return(datum);
}

extern __inline__ void outb(
				i386_ioport_t port,
				unsigned char datum)
{
	__asm__ volatile("outb %0, %1" : : "a" (datum), "d" (port));
}

/* Forward */

extern void kd_sendcmd(unsigned char		ch);
extern void kdreboot(void);
extern int		kd_dogetc(int		wait);
extern void		kd_handle_ack(void);
extern void		kd_resend(void);
extern int		do_modifier(
				int			state,
				Scancode		c,
				int		up);
extern int	kdcheckmagic(
				Scancode		sc,
				int			* regs);
extern int		kdstate2idx(
				int			state,
				int		extended);
extern void		kdinit(void);
extern void		kd_belloff(void);
extern void		kd_bellon(void);
extern void		kd_senddata(unsigned char c);
extern unsigned char		kd_getdata(void);
extern unsigned char		kd_cmdreg_read(void);
extern void		set_kd_state(
				int			newstate);
extern unsigned char		state2leds(
				int			state);
extern void		kd_setleds1(
				unsigned char			val);
extern void		kd_setleds2(void);
extern void		cnsetleds(
				unsigned char			val);
extern int		kd_kbd_magic(
				int			scancode);

extern int		cngetc(void);
extern int		cnmaygetc(void);
extern void kdreboot(void);
extern int kd_dogetc(int	wait);

/* reboot on CTL-ALT-DEL ? */
extern int	rebootflag;
/* enter kernel debugger on CTR-ALT-d ? */
int		kbdkdbflag = 1;
/* allow keyboard mouse ? */
int		kbdmouseflag = 0;

/* 
 * kd_state shows the state of the modifier keys (ctrl, caps lock, 
 * etc.)  It should normally be changed by calling set_kd_state(), so
 * that the keyboard status LEDs are updated correctly.
 */
int  	kd_state	= KS_NORMAL;
int	kb_mode		= KB_ASCII;	/* event/ascii */

int kd_kbd_mouse = 0;
int kd_kbd_magic_scale = 6;
int kd_kbd_magic_button  = 0;

/* 
 * Some keyboard commands work by sending a command, waiting for an 
 * ack (handled by kdintr), then sending data, which generates a 
 * second ack.  If we are in the middle of such a sequence, kd_ack
 * shows what the ack is for.
 * 
 * When a byte is sent to the keyboard, it is kept around in last_sent 
 * in case it needs to be resent.
 * 
 * The rest of the variables here hold the data required to complete
 * the sequence.
 * 
 * XXX - the System V driver keeps a command queue, I guess in case we
 * want to start a command while another is in progress.  Is this
 * something we should worry about?
 */
enum why_ack {NOT_WAITING, SET_LEDS, DATA_ACK};
enum why_ack	kd_ack	= NOT_WAITING;

unsigned char last_sent = 0;

unsigned char	kd_nextled	= 0;

/*
 * We don't provide any mutex protection for this flag because we know
 * that this module will have been initialized by the time multiple
 * threads are running.
 */
int kd_initialized 	= FALSE;	/* driver initialized? */
int kd_extended	= FALSE;

/*
 * This array maps scancodes to Ascii characters (or character
 * sequences). 
 * Each row corresponds to one key.  There are NUMOUTPUT bytes per key
 * state.  The states are ordered: Normal, SHIFT, CTRL, ALT,
 * SHIFT/ALT.
 */
unsigned char	key_map[NUMKEYS][WIDTH_KMAP] = {
{NC,NC,NC,NC,NC,NC,NC,NC,NC,NC,NC,NC,NC,NC,NC},
{K_ESC,NC,NC, K_ESC,NC,NC, K_ESC,NC,NC, K_ESC,NC,NC, K_ESC,NC,NC},
{K_ONE,NC,NC, K_BANG,NC,NC, K_ONE,NC,NC, 0x1b,0x4e,0x31, 0x1b,0x4e,0x21},
{K_TWO,NC,NC, K_ATSN,NC,NC, K_NUL,NC,NC, 0x1b,0x4e,0x32, 0x1b,0x4e,0x40},
{K_THREE,NC,NC, K_POUND,NC,NC, K_THREE,NC,NC, 0x1b,0x4e,0x33, 0x1b,0x4e,0x23},
{K_FOUR,NC,NC, K_DOLLAR,NC,NC, K_FOUR,NC,NC, 0x1b,0x4e,0x34, 0x1b,0x4e,0x24},
{K_FIVE,NC,NC, K_PERC,NC,NC, K_FIVE,NC,NC, 0x1b,0x4e,0x35, 0x1b,0x4e,0x25},
{K_SIX,NC,NC, K_CARET,NC,NC, K_RS,NC,NC, 0x1b,0x4e,0x36, 0x1b,0x4e,0x5e},
{K_SEVEN,NC,NC, K_AMPER,NC,NC, K_SEVEN,NC,NC, 0x1b,0x4e,0x37, 0x1b,0x4e,0x26},
{K_EIGHT,NC,NC, K_ASTER,NC,NC, K_EIGHT,NC,NC, 0x1b,0x4e,0x38, 0x1b,0x4e,0x2a},
{K_NINE,NC,NC, K_LPAREN,NC,NC, K_NINE,NC,NC, 0x1b,0x4e,0x39,0x1b,0x4e,0x28},
{K_ZERO,NC,NC, K_RPAREN,NC,NC, K_ZERO,NC,NC, 0x1b,0x4e,0x30,0x1b,0x4e,0x29},
{K_MINUS,NC,NC, K_UNDSC,NC,NC, K_US,NC,NC, 0x1b,0x4e,0x2d, 0x1b,0x4e,0x5f},
{K_EQL,NC,NC, K_PLUS,NC,NC, K_EQL,NC,NC, 0x1b,0x4e,0x3d, 0x1b,0x4e,0x2b},
{K_BS,NC,NC, K_BS,NC,NC, K_BS,NC,NC, K_BS,NC,NC, K_BS,NC,NC},
{K_HT,NC,NC, K_GS,NC,NC, K_HT,NC,NC, K_HT,NC,NC, K_GS,NC,NC},
{K_q,NC,NC, K_Q,NC,NC, K_DC1,NC,NC, 0x1b,0x4e,0x71, 0x1b,0x4e,0x51},
{K_w,NC,NC, K_W,NC,NC, K_ETB,NC,NC, 0x1b,0x4e,0x77, 0x1b,0x4e,0x57},
{K_e,NC,NC, K_E,NC,NC, K_ENQ,NC,NC, 0x1b,0x4e,0x65, 0x1b,0x4e,0x45},
{K_r,NC,NC, K_R,NC,NC, K_DC2,NC,NC, 0x1b,0x4e,0x72, 0x1b,0x4e,0x52},
{K_t,NC,NC, K_T,NC,NC, K_DC4,NC,NC, 0x1b,0x4e,0x74, 0x1b,0x4e,0x54},
{K_y,NC,NC, K_Y,NC,NC, K_EM,NC,NC, 0x1b,0x4e,0x79, 0x1b,0x4e,0x59},
{K_u,NC,NC, K_U,NC,NC, K_NAK,NC,NC, 0x1b,0x4e,0x75, 0x1b,0x4e,0x55},
{K_i,NC,NC, K_I,NC,NC, K_HT,NC,NC, 0x1b,0x4e,0x69, 0x1b,0x4e,0x49},
{K_o,NC,NC, K_O,NC,NC, K_SI,NC,NC, 0x1b,0x4e,0x6f, 0x1b,0x4e,0x4f},
{K_p,NC,NC, K_P,NC,NC, K_DLE,NC,NC, 0x1b,0x4e,0x70, 0x1b,0x4e,0x50},
{K_LBRKT,NC,NC, K_LBRACE,NC,NC, K_ESC,NC,NC, 0x1b,0x4e,0x5b, 0x1b,0x4e,0x7b},
{K_RBRKT,NC,NC, K_RBRACE,NC,NC, K_GS,NC,NC, 0x1b,0x4e,0x5d, 0x1b,0x4e,0x7d},
{K_CR,NC,NC, K_CR,NC,NC, K_CR,NC,NC, K_CR,NC,NC, K_CR,NC,NC},
{K_SCAN,K_CTLSC,NC, K_SCAN,K_CTLSC,NC, K_SCAN,K_CTLSC,NC, K_SCAN,K_CTLSC,NC, 
	 K_SCAN,K_CTLSC,NC},
{K_a,NC,NC, K_A,NC,NC, K_SOH,NC,NC, 0x1b,0x4e,0x61, 0x1b,0x4e,0x41},
{K_s,NC,NC, K_S,NC,NC, K_DC3,NC,NC, 0x1b,0x4e,0x73, 0x1b,0x4e,0x53},
{K_d,NC,NC, K_D,NC,NC, K_EOT,NC,NC, 0x1b,0x4e,0x65, 0x1b,0x4e,0x45},
{K_f,NC,NC, K_F,NC,NC, K_ACK,NC,NC, 0x1b,0x4e,0x66, 0x1b,0x4e,0x46},
{K_g,NC,NC, K_G,NC,NC, K_BEL,NC,NC, 0x1b,0x4e,0x67, 0x1b,0x4e,0x47},
{K_h,NC,NC, K_H,NC,NC, K_BS,NC,NC, 0x1b,0x4e,0x68, 0x1b,0x4e,0x48},
{K_j,NC,NC, K_J,NC,NC, K_LF,NC,NC, 0x1b,0x4e,0x6a, 0x1b,0x4e,0x4a},
{K_k,NC,NC, K_K,NC,NC, K_VT,NC,NC, 0x1b,0x4e,0x6b, 0x1b,0x4e,0x4b},
{K_l,NC,NC, K_L,NC,NC, K_FF,NC,NC, 0x1b,0x4e,0x6c, 0x1b,0x4e,0x4c},
{K_SEMI,NC,NC, K_COLON,NC,NC, K_SEMI,NC,NC, 0x1b,0x4e,0x3b, 0x1b,0x4e,0x3a},
{K_SQUOTE,NC,NC,K_DQUOTE,NC,NC,K_SQUOTE,NC,NC,0x1b,0x4e,0x27,0x1b,0x4e,0x22},
{K_GRAV,NC,NC, K_TILDE,NC,NC, K_RS,NC,NC, 0x1b,0x4e,0x60, 0x1b,0x4e,0x7e},
{K_SCAN,K_LSHSC,NC, K_SCAN,K_LSHSC,NC, K_SCAN,K_LSHSC,NC, K_SCAN,K_LSHSC,NC,
	 K_SCAN,K_LSHSC,NC},
{K_BSLSH,NC,NC, K_PIPE,NC,NC, K_FS,NC,NC, 0x1b,0x4e,0x5c, 0x1b,0x4e,0x7c},
{K_z,NC,NC, K_Z,NC,NC, K_SUB,NC,NC, 0x1b,0x4e,0x7a, 0x1b,0x4e,0x5a},
{K_x,NC,NC, K_X,NC,NC, K_CAN,NC,NC, 0x1b,0x4e,0x78, 0x1b,0x4e,0x58},
{K_c,NC,NC, K_C,NC,NC, K_ETX,NC,NC, 0x1b,0x4e,0x63, 0x1b,0x4e,0x43},
{K_v,NC,NC, K_V,NC,NC, K_SYN,NC,NC, 0x1b,0x4e,0x76, 0x1b,0x4e,0x56},
{K_b,NC,NC, K_B,NC,NC, K_STX,NC,NC, 0x1b,0x4e,0x62, 0x1b,0x4e,0x42},
{K_n,NC,NC, K_N,NC,NC, K_SO,NC,NC, 0x1b,0x4e,0x6e, 0x1b,0x4e,0x4e},
{K_m,NC,NC, K_M,NC,NC, K_CR,NC,NC, 0x1b,0x4e,0x6d, 0x1b,0x4e,0x4d},
{K_COMMA,NC,NC, K_LTHN,NC,NC, K_COMMA,NC,NC, 0x1b,0x4e,0x2c, 0x1b,0x4e,0x3c},
{K_PERIOD,NC,NC, K_GTHN,NC,NC, K_PERIOD,NC,NC,0x1b,0x4e,0x2e,0x1b,0x4e,0x3e},
{K_SLASH,NC,NC, K_QUES,NC,NC, K_SLASH,NC,NC, 0x1b,0x4e,0x2f, 0x1b,0x4e,0x3f},
{K_SCAN,K_RSHSC,NC, K_SCAN,K_RSHSC,NC, K_SCAN,K_RSHSC,NC, K_SCAN,K_RSHSC,NC, 
	 K_SCAN,K_RSHSC,NC},
{K_ASTER,NC,NC, K_ASTER,NC,NC, K_ASTER,NC,NC, 0x1b,0x4e,0x2a,0x1b,0x4e,0x2a},
{K_SCAN,K_ALTSC,NC, K_SCAN,K_ALTSC,NC, K_SCAN,K_ALTSC,NC, K_SCAN,K_ALTSC,NC, 
	 K_SCAN,K_ALTSC,NC},
{K_SPACE,NC,NC, K_SPACE,NC,NC, K_NUL,NC,NC, K_SPACE,NC,NC, K_SPACE,NC,NC},
{K_SCAN,K_CLCKSC,NC, K_SCAN,K_CLCKSC,NC, K_SCAN,K_CLCKSC,NC, 
	 K_SCAN,K_CLCKSC,NC, K_SCAN,K_CLCKSC,NC},
{K_F1, K_F1S, K_F1, K_F1, K_F1S},
{K_F2, K_F2S, K_F2, K_F2, K_F2S},
{K_F3, K_F3S, K_F3, K_F3, K_F3S},
{K_F4, K_F4S, K_F4, K_F4, K_F4S},
{K_F5, K_F5S, K_F5, K_F5, K_F5S},
{K_F6, K_F6S, K_F6, K_F6, K_F6S},
{K_F7, K_F7S, K_F7, K_F7, K_F7S},
{K_F8, K_F8S, K_F8, K_F8, K_F8S},
{K_F9, K_F9S, K_F9, K_F9, K_F9S},
{K_F10, K_F10S, K_F10, K_F10, K_F10S},
{K_SCAN,K_NLCKSC,NC, K_SCAN,K_NLCKSC,NC, K_SCAN,K_NLCKSC,NC, 
	 K_SCAN,K_NLCKSC,NC, K_SCAN,K_NLCKSC,NC},
{K_SCRL, K_NUL,NC,NC, K_SCRL, K_SCRL, K_NUL,NC,NC},
{K_HOME, K_SEVEN,NC,NC, K_HOME, K_HOME, 0x1b,0x4e,0x37},
{K_UA, K_EIGHT,NC,NC, K_UA, K_UA, 0x1b,0x4e,0x38},
{K_PUP, K_NINE,NC,NC, K_PUP, K_PUP, 0x1b,0x4e,0x39},
{0x1b,0x5b,0x53, K_MINUS,NC,NC, 0x1b,0x5b,0x53,0x1b,0x5b,0x53,0x1b,0x4e,0x2d},
{K_LA, K_FOUR,NC,NC, K_LA, K_LA, 0x1b,0x4e,0x34},
{0x1b,0x5b,0x47,K_FIVE,NC,NC,0x1b,0x5b,0x47, 0x1b,0x5b,0x47, 0x1b,0x4e,0x35},
{K_RA, K_SIX,NC,NC, K_RA, K_RA, 0x1b,0x4e,0x36},
{0x1b,0x5b,0x54,K_PLUS,NC,NC, 0x1b,0x5b,0x54, 0x1b,0x5b,0x54, 0x1b,0x4e,0x2b},
{K_END, K_ONE,NC,NC, K_END, K_END, 0x1b,0x4e,0x31},
{K_DA, K_TWO,NC,NC, K_DA, K_DA, 0x1b,0x4e,0x32},
{K_PDN, K_THREE,NC,NC, K_PDN, K_PDN, 0x1b,0x4e,0x33},
{K_INS, K_ZERO,NC,NC, K_INS, K_INS, 0x1b,0x4e,0x30},
{K_DEL,NC,NC, K_PERIOD,NC,NC, K_DEL,NC,NC, K_DEL,NC,NC, 0x1b,0x4e,0x2e},
{NC,NC,NC,NC,NC,NC,NC,NC,NC,NC,NC,NC,NC,NC,NC},
{NC,NC,NC,NC,NC,NC,NC,NC,NC,NC,NC,NC,NC,NC,NC},
{NC,NC,NC,NC,NC,NC,NC,NC,NC,NC,NC,NC,NC,NC,NC},
{K_F11, K_F11S, K_F11, K_F11, K_F11S},
{K_F12, K_F12S, K_F12, K_F12, K_F12S}
};

extern void cnputc(unsigned char ch);

/*
 * Switch for poll vs. interrupt.
 */
int	kd_pollc = 0;

int (*cgetc)(
	int	wait) = kd_dogetc;
					/* get a char. from console	*/
void (*cputc)(
	char		ch) = cnputc;
					/* put a char. to console	*/

/* 
 * cngetc:
 * 
 *	Get one character using polling, rather than interrupts.  Used 
 *	by the kernel debugger.  Note that Caps Lock is ignored.
 *	Normally this routine is called with interrupts already 
 *	disabled, but there is code in place so that it will be more 
 *	likely to work even if interrupts are turned on.
 */

int
cngetc(void)
{
	int ret;

	ret = (*cgetc)(TRUE);

	return ret;
}

int
cnmaygetc(void)
{
	int ret;

	ret = (*cgetc)(FALSE);

	return ret;
}

int
kd_dogetc(
	int	wait)
{
	unsigned char	c;
	unsigned char	scancode;
	unsigned int	char_idx;
	int	up;

	kdinit();
	kd_extended = FALSE;

	for ( ; ; ) {
		while (!(inb(K_STATUS) & K_OBUF_FUL))
			if (!wait)
				return (-1);
		up = FALSE;
		/*
		 * We'd come here for mouse events in debugger, if
		 * the mouse were on.
		 */
		if ((inb(K_STATUS) & 0x20) == 0x20) {
			printf("M%xP", inb(K_RDWR));
			continue;
		}
		scancode = inb(K_RDWR);
		/*
		 * Handle extend modifier and
		 * ack/resend, otherwise we may never receive
		 * a key.
		 */
		if (scancode == K_EXTEND) {
			kd_extended = TRUE;
			continue;
		} else if (scancode == K_RESEND) {
/*  printf("kd_getc: resend");	*/
			kd_resend();
			continue;
		} else if (scancode == K_ACKSC) {
/*  printf("kd_getc: handle_ack");	*/
			kd_handle_ack();
			continue;
		}
		if (scancode & K_UP) {
			up = TRUE;
			scancode &= ~K_UP;
		}
		if (kd_kbd_mouse)
			kd_kbd_magic(scancode);
		if (scancode < NUMKEYS) {
			/* Lookup in map, then process. */
			char_idx = kdstate2idx(kd_state, kd_extended);
			c = key_map[scancode][char_idx];
			if (c == K_SCAN) {
				c = key_map[scancode][++char_idx];
				kd_state = do_modifier(kd_state, c, up);
#ifdef notdef
				cnsetleds(state2leds(kd_state));
#endif
			} else if (!up) {
				/* regular key-down */
				if (c == K_CR)
					c = K_LF;
#ifdef	notdef
				splx(o_pri);
#endif
				return(c & 0177);
			}
		}
	}
}


int		old_kb_mode;

#if	MACH_KDB
#define	poll_spl()	db_splhigh()	/* prevent race w/ kdintr() */
#define poll_splx(s)	db_splx(s)
#else	/* MACH_KDB */
#define	poll_spl()	SPLKD()
#define poll_splx(s)	splx(s)
#endif	/* MACH_KDB */


void
cnpollc(
	int	on)
{
	int	old_spl;		/* spl we're called at... */

    	if (cpu_number()) {
		return;
	}
	if (on) {
		old_spl = poll_spl();

		old_kb_mode = kb_mode;
		kb_mode = KB_ASCII;
		poll_splx(old_spl);

		kd_pollc++;
	} else {
		--kd_pollc;

		old_spl = poll_spl();
		kb_mode = old_kb_mode;
		poll_splx(old_spl);


	}
}

/* 
 * kd_handle_ack:
 * 
 *	For pending commands, complete the command.  For data bytes, 
 *	drop the ack on the floor.
 */

void
kd_handle_ack(void)
{
	switch (kd_ack) {
	case SET_LEDS:
		kd_setleds2();
		kd_ack = DATA_ACK;
		break;
	case DATA_ACK:
		kd_ack = NOT_WAITING;
		break;
	case NOT_WAITING:
		printf("unexpected ACK from keyboard\n");
		break;
	default:
		panic("bogus kd_ack\n");
		break;
	}
}

/* 
 * kd_resend:
 *
 *	Resend a missed keyboard command or data byte.
 */

void
kd_resend(void)
{
	if (kd_ack == NOT_WAITING) 
		printf("unexpected RESEND from keyboard\n");
	else
		kd_senddata(last_sent);
}


/*
 * do_modifier:
 *
 *	Change keyboard state according to which modifier key and
 *	whether it went down or up.
 *
 * input:	the current state, the key, and the key's direction.  
 *		The key can be any key, not just a modifier key.
 * 
 * output:	the new state
 */

int
do_modifier(
	int		state,
	Scancode	c,
	int	up)
{
	switch (c) {
	case (K_ALTSC):
		if (up)
			state &= ~KS_ALTED;
		else
			state |= KS_ALTED;
		kd_extended = FALSE;
		break;
#ifndef	ORC
	case (K_CLCKSC):
#endif	/* ORC */
	case (K_CTLSC):
		if (up)
			state &= ~KS_CTLED;
		else
			state |= KS_CTLED;
		kd_extended = FALSE;
		break;
#ifdef	ORC
	case (K_CLCKSC):
		if (!up)
			state ^= KS_CLKED;
		break;
#endif	/* ORC */
	case (K_NLCKSC):
		if (!up)
			state ^= KS_NLKED;
		break;
	case (K_LSHSC):
	case (K_RSHSC):
		if (up)
			state &= ~KS_SHIFTED;
		else
			state |= KS_SHIFTED;
		kd_extended = FALSE;
		break;
	}

	return(state);
}


/* 
 * kdcheckmagic:
 * 
 *	Check for magic keystrokes for invoking the debugger or 
 *	rebooting or ...
 *
 * input:	an unprocessed scancode
 * 
 * output:	TRUE if a magic key combination was recognized and 
 *		processed.  FALSE otherwise.
 *
 * side effects:	
 *		various actions possible, depending on which keys are
 *		pressed.  If the debugger is called, steps are taken 
 *		to ensure that the system doesn't think the magic keys 
 *		are still held down.
 */

int
kdcheckmagic(
	Scancode	scancode,
	int		*regs)
{
	static int magic_state = KS_NORMAL; /* like kd_state */
	int up = FALSE;
	extern	int	rebootflag;

	if (scancode == 0x46 && kbdmouseflag)	/* scroll lock */
	{
		kd_kbd_mouse = !kd_kbd_mouse;
		kd_kbd_magic_button = 0;
		return(TRUE);
	}
	if (scancode & K_UP) {
		up = TRUE;
		scancode &= ~K_UP;
	}
	magic_state = do_modifier(magic_state, scancode, up);

	if ((magic_state&(KS_CTLED|KS_ALTED)) == (KS_CTLED|KS_ALTED)) {
		switch (scancode) {
#if	MACH_KDB
		case K_dSC:		/*  ctl-alt-d */
			if (!kbdkdbflag)
				return(FALSE);

			kdb_kintr();	/* invoke debugger */

			/* Returned from debugger, so reset kbd state. */
			(void)SPLKD();
			magic_state = KS_NORMAL;
			if (kb_mode == KB_ASCII)
				kd_state = KS_NORMAL;
				/* setting leds kills kbd */

			return(TRUE);
			break;
#endif	/* MACH_KDB */
		case K_DELSC:		/* ctl-alt-del */
			/* if rebootflag is on, reboot the system */
			if (rebootflag)
				kdreboot();
			break;
		}
	}
	return(FALSE);
}


/*
 * kdstate2idx:
 *
 *	Return the value for the 2nd index into key_map that 
 *	corresponds to the given state.
 */

int
kdstate2idx(
	int		state,		/* bit vector, not a state index */
	int	extended)
{
	int state_idx = NORM_STATE;

	if ((!extended) && state != KS_NORMAL) {
		if ((state&(KS_SHIFTED|KS_ALTED)) == (KS_SHIFTED|KS_ALTED))
			state_idx = SHIFT_ALT;
		else if (state&KS_SHIFTED)
			state_idx = SHIFT_STATE;
		else if (state&KS_ALTED)
			state_idx = ALT_STATE;
		else if (state&KS_CTLED)
			state_idx = CTRL_STATE;
	}

	return (CHARIDX(state_idx));
}

/*
 * kdinit:
 *
 *	This code initializes the structures and sets up the port registers
 *	for the console driver.  
 *
 *	Each bitmap-based graphics card is likely to require a unique
 *	way to determine the card's presence.  The driver runs through
 *	each "special" card that it knows about and uses the first one
 *	that it finds.  If it doesn't find any, it assumes that an
 *	EGA-like card is installed.
 *
 * input	: None.	Interrupts are assumed to be disabled
 * output	: Driver is initialized
 *
 */

void
kdinit(void)
{
	unsigned char	k_comm;		/* keyboard command byte */
	unsigned char kd_stat;

	if (kd_initialized)
		return;
	kd_initialized = TRUE;

	/* get rid of any garbage in output buffer */
	if (inb(K_STATUS) & K_OBUF_FUL)
		(void)inb(K_RDWR);

	cnsetleds(kd_state = KS_NORMAL);

	kd_sendcmd(KC_CMD_READ);	/* ask for the ctlr command byte */
	k_comm = kd_getdata();
	k_comm &= ~K_CB_DISBLE;		/* clear keyboard disable bit */
	k_comm |= K_CB_ENBLIRQ;		/* enable interrupt */
	kd_sendcmd(KC_CMD_WRITE);	/* write new ctlr command byte */
	kd_senddata(k_comm);

/*	set_kd_state(KS_NORMAL);	does only HALF of set-leds sequence -
					leaves kbd dead */

	/* get rid of any garbage in output buffer */
	(void)inb(K_RDWR);
}

/*
 * kd_belloff:
 *
 *	This routine shuts the bell off, by sending the appropriate code
 *	to the speaker port.
 *
 * input	: None
 * output	: bell is turned off
 *
 */

void
kd_belloff(void)
{
	unsigned char status;

	status = (inb(K_PORTB) & ~(K_SPKRDATA | K_ENABLETMR2));
	outb(K_PORTB, status);
}


/*
 * kd_bellon:
 *
 *	This routine turns the bell on.
 *
 * input	: None
 * output	: bell is turned on
 *
 */

void
kd_bellon(void)
{
	unsigned char	status;

	/* program timer 2 */
	outb(K_TMRCTL, K_SELTMR2 | K_RDLDTWORD | K_TSQRWAVE | K_TBINARY);
	outb(K_TMR2, 1500 & 0xff);	/* LSB */
	outb(K_TMR2, (int)1500 >> 8);	/* MSB */

	/* start speaker - why must we turn on K_SPKRDATA? */
	status = (inb(K_PORTB)| K_ENABLETMR2 | K_SPKRDATA);
	outb(K_PORTB, status);
	return;
}

/*
 * kd_senddata:
 *
 *	This function sends a byte to the keyboard RDWR port, but
 *	first waits until the input/output data buffer is clear before
 *	sending the data.  Note that this byte can be either data or a
 *	keyboard command.
 *
 */

void
kd_senddata(
	unsigned char		ch)
{
	while (inb(K_STATUS) & K_IBUF_FUL);
	outb(K_RDWR, ch);
	last_sent = ch;
}

/*
 * kd_sendcmd:
 *
 *	This function sends a command byte to the keyboard command
 *	port, but first waits until the input/output data buffer is
 *	clear before sending the data.
 *
 */

void
kd_sendcmd(
	unsigned char		ch)
{
	while (inb(K_STATUS) & K_IBUF_FUL);
	outb(K_CMD, ch);
}


/* 
 * kd_getdata:
 * 
 *	This function returns a data byte from the keyboard RDWR port, 
 *	after waiting until the port is flagged as having something to 
 *	read. 
 */

unsigned char
kd_getdata(void)
{
	while ((inb(K_STATUS) & K_OBUF_FUL) == 0);
	return(inb(K_RDWR));
}

unsigned char
kd_cmdreg_read(void)
{
	int ch=KC_CMD_READ;

	while (inb(K_STATUS) & (K_IBUF_FUL | K_OBUF_FUL));
	outb(K_CMD, ch);

	while ((inb(K_STATUS) & K_OBUF_FUL) == 0);
	return(inb(K_RDWR));
}

void
kd_cmdreg_write(
	unsigned char		val)
{
	int ch=KC_CMD_WRITE;

	while (inb(K_STATUS) & K_IBUF_FUL);
	outb(K_CMD, ch);

	while (inb(K_STATUS) & K_IBUF_FUL);
	outb(K_RDWR, val);
}

int kd_mouse_write_no_ack = 0;

int
kd_mouse_write(
	unsigned char		val)
{
	int ch=0xd4;		/* output byte to aux device (i.e. mouse) */
	int ret = 0;

	while (inb(K_STATUS) & K_IBUF_FUL);
	outb(K_CMD, ch);

	while (inb(K_STATUS) & K_IBUF_FUL);
	outb(K_RDWR, val);

	if (kd_mouse_write_no_ack) goto done;

	while ((inb(K_STATUS) & K_OBUF_FUL) == 0);
	if ((inb(K_STATUS) & 0x20) == 0x20) {
		switch (ret = inb(K_RDWR)) {
		case 0xfa:
			break;
		case 0xfe:
		case 0xfc:
		default:
			printf("kd_mouse_write: saw %x for %x\n",
				ret, val);
		}
	} else	{		/* abort */
		printf("kd_mouse_write: sync error ??? on %x\n", val);
	}

done:	
	return ret;
}

void
kd_mouse_read(
	int		no,
	char		*buf)
{

	while (no-- > 0) {
		while ((inb(K_STATUS) & K_OBUF_FUL) == 0);
		/*
		 * We may have seen a mouse event.
		 */
		if ((inb(K_STATUS) & 0x20) == 0x20) {
			*buf++ = (unsigned char)inb(K_RDWR);
		} else {	/* abort */
			int	junk = inb(K_RDWR);
			printf("kd_mouse_read: sync error, received: 0x%x\n",
				junk);
			break;
		}
	}
}

void
kd_mouse_drain(void)
{
	int i;
	while(inb(K_STATUS) & K_IBUF_FUL);
	while((i = inb(K_STATUS)) & K_OBUF_FUL)
		printf("kbd: S = %x D = %x\n", i, inb(K_RDWR));
}

/* 
 * set_kd_state:
 * 
 *	Set kd_state and update the keyboard status LEDs.
 */

void
set_kd_state(
	int	newstate)
{
	kd_state = newstate;
	kd_setleds1(state2leds(newstate));
}

/* 
 * state2leds:
 * 
 *	Return a byte containing LED settings for the keyboard, given 
 *	a state vector.
 */

unsigned char
state2leds(
	int	state)
{
	unsigned char result = 0;

	if (state & KS_NLKED)
		result |= K_LED_NUMLK;
	if (state & KS_CLKED)
		result |= K_LED_CAPSLK;
	return(result);
}

/* 
 * kd_setleds[12]:
 * 
 *	Set the keyboard LEDs according to the given byte.  
 */

void
kd_setleds1(
	unsigned char		val)
{
	if (kd_ack != NOT_WAITING) {
		printf("kd_setleds1: unexpected state (%d)\n", kd_ack);
		return;
	}

	kd_ack = SET_LEDS;
	kd_nextled = val;
	kd_senddata(K_CMD_LEDS);
}

void
kd_setleds2(void)
{
	kd_senddata(kd_nextled);
}


/* 
 * cnsetleds:
 * 
 *	like kd_setleds[12], but not interrupt-based.
 *	Currently disabled because cngetc ignores caps lock and num 
 *	lock anyway.
 */

void
cnsetleds(
	unsigned char		val)
{
	kd_senddata(K_CMD_LEDS);
	(void)kd_getdata();		/* XXX - assume is ACK */
	kd_senddata(val);
	(void)kd_getdata();		/* XXX - assume is ACK */
}

void
kdreboot(void)
{
	kd_sendcmd(0xFE);		/* XXX - magic # */
        /*
         * DRAT.  We're still here.  Let's try a "CPU shutdown", which consists
         * of clearing the IDTR and causing an exception.  It's in locore.s
         */
        cpu_shutdown();
        /*NOTREACHED*/
}

int
kd_kbd_magic(
	int	scancode)
{
int new_button = 0;

	if (kd_kbd_mouse == 2)
		printf("sc = %x\n", scancode);

	switch (scancode) {
/* f1 f2 f3 */
	case 0x3d:
		new_button++;
	case 0x3c:
		new_button++;
	case 0x3b:
		new_button++;
		if (kd_kbd_magic_button && (new_button != kd_kbd_magic_button)) {
				/* down w/o up */
		}
				/* normal */
		if (kd_kbd_magic_button == new_button) {
			kd_kbd_magic_button = 0;
		} else {
			kd_kbd_magic_button = new_button;
		}
		break;
	default:
		return 0;
	}
	return 1;
}
