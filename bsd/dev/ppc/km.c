/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/* 	Copyright (c) 1992 NeXT Computer, Inc.  All rights reserved. 
 *
 * km.m - kernel keyboard/monitor module, procedural interface.
 *
 * HISTORY
 */

#include <sys/kernel.h>
#include <sys/tty.h>

#include <dev/ppc/cons.h>
#include <sys/conf.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/fcntl.h>		/* for kmopen */
#include <sys/errno.h>		
#include <sys/proc.h>		/* for kmopen */
#include <sys/msgbuf.h>
#include <sys/time.h>
#include <dev/kmreg_com.h>
#include <pexpert/pexpert.h>

/*
 * 'Global' variables, shared only by this file and conf.c.
 */
struct tty *km_tty[1] = { &cons };

/*
 * this works early on, after initialize_screen() but before autoconf (and thus
 * before we have a kmDevice).
 */
int disableConsoleOutput;

static int initialized = 0;

// Function prototypes
extern d_open_t         kmopen;
extern d_close_t        kmclose;
extern d_read_t         kmread;
extern d_write_t        kmwrite;
extern d_ioctl_t        kmioctl;
extern d_getc_t         kmgetc;
extern d_putc_t         kmputc;

extern void kminit(void);

// used by or implemented in the osfmk project
extern void cnputcusr(char);		// From osfmk
extern int  cngetc(void);		// From osfmk
extern void cons_cinput(char ch);	// Used by osfmk

static int kmoutput(struct tty *tp);
static void kmtimeout(struct tty *tp);
static void kmstart(struct tty *tp);

extern void KeyboardOpen(void);

void
kminit(void)
{
   	 cons.t_dev = makedev(12, 0);
	initialized = 1;
}
/*
 * cdevsw interface to km driver.
 */
int 
kmopen(dev_t dev, int flag, __unused int devtype, struct proc *pp)
{
	int unit;
	struct tty *tp;
	struct winsize *wp;
	int ret;
	
	unit = minor(dev);
	if(unit >= 1)
		return (ENXIO);

	tp = (struct tty *)&cons;
	tp->t_oproc = kmstart;
	tp->t_param = NULL;
	tp->t_dev = dev;
	
	if ( !(tp->t_state & TS_ISOPEN) ) {
		tp->t_iflag = TTYDEF_IFLAG;
		tp->t_oflag = TTYDEF_OFLAG;
		tp->t_cflag = (CREAD | CS8 | CLOCAL);
		tp->t_lflag = TTYDEF_LFLAG;
		tp->t_ispeed = tp->t_ospeed = TTYDEF_SPEED;
		termioschars(&tp->t_termios);
		ttsetwater(tp);
	} else if ((tp->t_state & TS_XCLUDE) && proc_suser(pp))
		return EBUSY;

	tp->t_state |= TS_CARR_ON; /* lie and say carrier exists and is on. */
	ret = ((*linesw[tp->t_line].l_open)(dev, tp));
	{
		PE_Video video;
		wp = &tp->t_winsize;
		/* Magic numbers.  These are CHARWIDTH and CHARHEIGHT
		 * from osfmk/ppc/POWERMAC/video_console.c
		 */
		wp->ws_xpixel = 8;
		wp->ws_ypixel = 16;

		if (flag & O_POPUP)
			PE_initialize_console(0, kPETextScreen);

		bzero(&video, sizeof(video));
		PE_current_console(&video);
		if( video.v_width != 0 && video.v_height != 0 ) {
			wp->ws_col = video.v_width / wp->ws_xpixel;
			wp->ws_row = video.v_height / wp->ws_ypixel;
		} else {
			wp->ws_col = 100;
			wp->ws_row = 36;
		}
	}
	return ret;
}

int 
kmclose(__unused dev_t dev, __unused int flag, __unused int mode,
	__unused struct proc *p)
{
	 
	struct tty *tp;

	tp = &cons;
	(*linesw[tp->t_line].l_close)(tp,flag);
	ttyclose(tp);
	return (0);
}

int 
kmread(__unused dev_t dev, struct uio *uio, int ioflag)
{
	register struct tty *tp;
 
	tp = &cons;
	return ((*linesw[tp->t_line].l_read)(tp, uio, ioflag));
}

int 
kmwrite(__unused dev_t dev, struct uio *uio, int ioflag)
{
	register struct tty *tp;
 
	tp = &cons;
	return ((*linesw[tp->t_line].l_write)(tp, uio, ioflag));
}

int 
kmioctl( __unused dev_t dev, u_long cmd, caddr_t data, int flag,
	struct proc *p)
{
	int error;
	struct tty *tp = &cons;
	struct winsize *wp;
	
	switch (cmd) {
		


	    case KMIOCSIZE:
		wp = (struct winsize *)data;
		*wp = tp->t_winsize;
		return 0;
		
	    case TIOCSWINSZ:
		/* Prevent changing of console size --
		 * this ensures that login doesn't revert to the
		 * termcap-defined size
		 */
		return EINVAL;

	    /* Bodge in the CLOCAL flag as the km device is always local */
	    case TIOCSETA:
	    case TIOCSETAW:
	    case TIOCSETAF: {
		register struct termios *t = (struct termios *)data;
		t->c_cflag |= CLOCAL;
		/* No Break */
	    }
	    default:		
		error = (*linesw[tp->t_line].l_ioctl)(tp, cmd, data, flag, p);
		if (ENOTTY != error)
			return error;
		return ttioctl (tp, cmd, data, flag, p);
	}
}

int 
kmputc(__unused dev_t dev, char c)
{

	if( disableConsoleOutput)
		return( 0);

	if(!initialized)
		return( 0);

	if(c == '\n')
		cnputcusr('\r');

	cnputcusr(c);

	return 0;
}

int 
kmgetc(__unused dev_t dev)
{
	int c;
	
	c= cngetc();

	if (c == '\r') {
		c = '\n';
	}
	cnputcusr(c);
	return c;
}

#if 0
int 
kmgetc_silent(
	__unused dev_t dev)
{
	int c;
	
	c= cngetc();
	if (c == '\r') {
		c = '\n';
	}
	return c;
}
#endif /* 0 */

/*
 * Callouts from linesw.
 */
 
#define KM_LOWAT_DELAY	((ns_time_t)1000)

static void 
kmstart(struct tty *tp)
{
	if (tp->t_state & (TS_TIMEOUT | TS_BUSY | TS_TTSTOP))
		goto out;
	if (tp->t_outq.c_cc == 0)
		goto out;
	tp->t_state |= TS_BUSY;
	kmoutput(tp);
	return;

out:
	(*linesw[tp->t_line].l_start)(tp);
	return;
}

static void
kmtimeout(struct tty *tp)
{
	boolean_t 	funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	kmoutput(tp);
	(void) thread_funnel_set(kernel_flock, funnel_state);


}
static int 
kmoutput(struct tty *tp)
{
	/*
	 * FIXME - to be grokked...copied from m68k km.c.
	 */
	char 		buf[80];
	char 		*cp;
	int 		cc = -1;

	while (tp->t_outq.c_cc > 0) {
		cc = ndqb(&tp->t_outq, 0);
		if (cc == 0)
			break;
		cc = min(cc, sizeof buf);
		(void) q_to_b(&tp->t_outq, buf, cc);
		for (cp = buf; cp < &buf[cc]; cp++)
		    kmputc(tp->t_dev, *cp & 0x7f);
	}
        if (tp->t_outq.c_cc > 0) {
		timeout((timeout_fcn_t)kmtimeout, tp, hz);
	}
	tp->t_state &= ~TS_BUSY;
	(*linesw[tp->t_line].l_start)(tp);

	return 0;
}

void cons_cinput(char ch)
{
	struct tty *tp = &cons;
	
	(*linesw[tp->t_line].l_rint) (ch, tp);
}

