/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
/* 	Copyright (c) 1992 NeXT Computer, Inc.  All rights reserved. 
 *
 * km.m - kernel keyboard/monitor module, procedural interface.
 *
 * HISTORY
 */

#include <sys/param.h>
#include <sys/tty.h>

#include <dev/i386/cons.h>
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
extern struct tty	cons;
struct tty *km_tty[1] = { &cons };

/*
 * this works early on, after initialize_screen() but before autoconf (and thus
 * before we have a kmDevice).
 */
int disableConsoleOutput;

/*
 * 'Global' variables, shared only by this file and kmDevice.m.
 */
int initialized = 0;

static int kmoutput(struct tty *tp);
static void kmstart(struct tty *tp);

extern void KeyboardOpen(void);

int kminit()
{
   	 cons.t_dev = makedev(12, 0);
	initialized = 1;
}
/*
 * cdevsw interface to km driver.
 */
int 
kmopen(
	dev_t dev, 
	int flag,
	int devtype, 
	struct proc *pp)
{
	int rtn;
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
	} else if ((tp->t_state & TS_XCLUDE) && pp->p_ucred->cr_uid != 0)
		return EBUSY;

	tp->t_state |= TS_CARR_ON; /* lie and say carrier exists and is on. */
	ret = ((*linesw[tp->t_line].l_open)(dev, tp));
	{
		PE_Video video;
		wp = &tp->t_winsize;
		/* Magic numbers.  These are CHARWIDTH and CHARHEIGHT
		 * from pexpert/i386/video_console.c
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
kmclose(
	dev_t dev, 
	int flag,
	int mode,
	struct proc *p)
{
	 
	struct tty *tp;

	tp = &cons;
	(*linesw[tp->t_line].l_close)(tp,flag);
	ttyclose(tp);
	return (0);
}

int 
kmread(
	dev_t dev, 
	struct uio *uio,
	int ioflag)
{
	register struct tty *tp;
 
	tp = &cons;
	return ((*linesw[tp->t_line].l_read)(tp, uio, ioflag));
}

int 
kmwrite(
	dev_t dev, 
	struct uio *uio,
	int ioflag)
{
	register struct tty *tp;
 
	tp = &cons;
	return ((*linesw[tp->t_line].l_write)(tp, uio, ioflag));
}

int 
kmioctl(
	dev_t dev, 
	int cmd, 
	caddr_t data, 
	int flag,
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
		if (error >= 0) {
			return error;
		}
		error = ttioctl (tp, cmd, data, flag, p);
		if (error >= 0) {
			return error;
		}
		else {
			return ENOTTY;
		}
	}
}

int 
kmputc(
	int c)
{

	if( disableConsoleOutput)
		return( 0);

	if(!initialized)
		return( 0);

	if(c == '\n')
		cnputc('\r');

	cnputc(c);

	return 0;
}

int 
kmgetc(
	dev_t dev)
{
	int c;
	
	c= cngetc();

	if (c == '\r') {
		c = '\n';
	}
	cnputc(c);
	return c;
}

int 
kmgetc_silent(
	dev_t dev)
{
	int c;
	
	c= cngetc();
	if (c == '\r') {
		c = '\n';
	}
	return c;
}

/*
 * Callouts from linesw.
 */
 
#define KM_LOWAT_DELAY	((ns_time_t)1000)

static void 
kmstart(
	struct tty *tp)
{
	extern int hz;
	if (tp->t_state & (TS_TIMEOUT | TS_BUSY | TS_TTSTOP))
		goto out;
	if (tp->t_outq.c_cc == 0)
		goto out;
	tp->t_state |= TS_BUSY;
	if (tp->t_outq.c_cc > tp->t_lowat) {
		/*
		 * Start immediately.
		 */
		kmoutput(tp);
	}
	else {
		/*
		 * Wait a bit...
		 */
#if 0
		/* FIXME */
		timeout(kmtimeout, tp, hz);
#else
		kmoutput(tp);
#endif
	}
out:
	ttwwakeup(tp);
}

static void
kmtimeout(void *arg)
{
	boolean_t 	funnel_state;
	struct tty	*tp = (struct tty *) arg;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	kmoutput(tp);
	(void) thread_funnel_set(kernel_flock, funnel_state);


}
static int 
kmoutput(
	struct tty *tp)
{
	/*
	 * FIXME - to be grokked...copied from m68k km.c.
	 */
	char 		buf[80];
	char 		*cp;
	int 		cc = -1;
	extern int hz;


	while (tp->t_outq.c_cc > 0) {
		cc = ndqb(&tp->t_outq, 0);
		if (cc == 0)
			break;
		cc = min(cc, sizeof buf);
		(void) q_to_b(&tp->t_outq, buf, cc);
		for (cp = buf; cp < &buf[cc]; cp++) {
		    kmputc(*cp & 0x7f);
		}
	}
        if (tp->t_outq.c_cc > 0) {
		timeout(kmtimeout, tp, hz);
	}
	tp->t_state &= ~TS_BUSY;
	ttwwakeup(tp);

	return 0;
}
cons_cinput(char ch)
{
	struct tty *tp = &cons;
	boolean_t 	funnel_state;

	
	(*linesw[tp->t_line].l_rint) (ch, tp);

}

