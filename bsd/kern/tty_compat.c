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
/* Copyright (c) 1997 Apple Computer, Inc. All Rights Reserved */
/*-
 * Copyright (c) 1982, 1986, 1991, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)tty_compat.c        8.1 (Berkeley) 6/10/93
 */

/*
 * mapping routines for old line discipline (yuck)
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ioctl.h>
#include <sys/proc.h>
#include <sys/tty.h>
#include <sys/termios.h>
#include <sys/file.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>

/* NeXT Move define down here cause COMPAT_43 not valid earlier */
#if COMPAT_43 || defined(COMPAT_SUNOS)

static int ttcompatgetflags	__P((struct tty	*tp));
static void ttcompatsetflags	__P((struct tty	*tp, struct termios *t));
static void ttcompatsetlflags	__P((struct tty	*tp, struct termios *t));
static int ttcompatspeedtab	__P((int speed, struct speedtab *table));


static int ttydebug = 0;

#ifndef NeXT
SYSCTL_INT(_debug, OID_AUTO, ttydebug, CTLFLAG_RW, &ttydebug, 0, "");
#endif

static struct speedtab compatspeeds[] = {
#define MAX_SPEED	17
	{ 115200, 17 },
	{ 57600, 16 },
	{ 38400, 15 },
	{ 19200, 14 },
	{ 9600,	13 },
	{ 4800,	12 },
	{ 2400,	11 },
	{ 1800,	10 },
	{ 1200,	9 },
	{ 600,	8 },
	{ 300,	7 },
	{ 200,	6 },
	{ 150,	5 },
	{ 134,	4 },
	{ 110,	3 },
	{ 75,	2 },
	{ 50,	1 },
	{ 0,	0 },
	{ -1,	-1 },
};
static int compatspcodes[] = {
	0, 50, 75, 110, 134, 150, 200, 300, 600, 1200,
	1800, 2400, 4800, 9600, 19200, 38400, 57600, 115200,
};

static int
ttcompatspeedtab(speed, table)
	int speed;
	register struct speedtab *table;
{
	if (speed == 0)
		return (0); /* hangup */
	for ( ; table->sp_speed > 0; table++)
		if (table->sp_speed <= speed) /* nearest one, rounded down */
			return (table->sp_code);
	return (1); /* 50, min and not hangup */
}

#ifndef NeXT
int
ttsetcompat(tp, com, data, term)
	register struct tty *tp;
	int *com;
	caddr_t data;
	struct termios *term;
#else
__private_extern__ int
ttsetcompat(tp, com, data, term)
	register struct tty *tp;
	u_long *com;
	caddr_t data;
	struct termios *term;
#endif /* !NeXT */
{
	switch (*com) {
	case TIOCSETP:
	case TIOCSETN: {
		register struct sgttyb *sg = (struct sgttyb *)data;
		int speed;

		if ((speed = sg->sg_ispeed) > MAX_SPEED || speed < 0)
			return(EINVAL);
		else if (speed != ttcompatspeedtab(tp->t_ispeed, compatspeeds))
			term->c_ispeed = compatspcodes[speed];
		else
			term->c_ispeed = tp->t_ispeed;
		if ((speed = sg->sg_ospeed) > MAX_SPEED || speed < 0)
			return(EINVAL);
		else if (speed != ttcompatspeedtab(tp->t_ospeed, compatspeeds))
			term->c_ospeed = compatspcodes[speed];
		else
			term->c_ospeed = tp->t_ospeed;
		term->c_cc[VERASE] = sg->sg_erase;
		term->c_cc[VKILL] = sg->sg_kill;
		tp->t_flags = (tp->t_flags&0xffff0000) | (sg->sg_flags&0xffff);
		ttcompatsetflags(tp, term);
		*com = (*com == TIOCSETP) ? TIOCSETAF : TIOCSETA;
		break;
	}
	case TIOCSETC: {
		struct tchars *tc = (struct tchars *)data;
		register cc_t *cc;

		cc = term->c_cc;
		cc[VINTR] = tc->t_intrc;
		cc[VQUIT] = tc->t_quitc;
		cc[VSTART] = tc->t_startc;
		cc[VSTOP] = tc->t_stopc;
		cc[VEOF] = tc->t_eofc;
		cc[VEOL] = tc->t_brkc;
		if (tc->t_brkc == -1)
			cc[VEOL2] = _POSIX_VDISABLE;
		*com = TIOCSETA;
		break;
	}
	case TIOCSLTC: {
		struct ltchars *ltc = (struct ltchars *)data;
		register cc_t *cc;

		cc = term->c_cc;
		cc[VSUSP] = ltc->t_suspc;
		cc[VDSUSP] = ltc->t_dsuspc;
		cc[VREPRINT] = ltc->t_rprntc;
		cc[VDISCARD] = ltc->t_flushc;
		cc[VWERASE] = ltc->t_werasc;
		cc[VLNEXT] = ltc->t_lnextc;
		*com = TIOCSETA;
		break;
	}
	case TIOCLBIS:
	case TIOCLBIC:
	case TIOCLSET:
		if (*com == TIOCLSET)
			tp->t_flags = (tp->t_flags&0xffff) | *(int *)data<<16;
		else {
			tp->t_flags =
			 (ttcompatgetflags(tp)&0xffff0000)|(tp->t_flags&0xffff);
			if (*com == TIOCLBIS)
				tp->t_flags |= *(int *)data<<16;
			else
				tp->t_flags &= ~(*(int *)data<<16);
		}
		ttcompatsetlflags(tp, term);
		*com = TIOCSETA;
		break;
	}
	return 0;
}

/*ARGSUSED*/
#ifndef NeXT
int
ttcompat(tp, com, data, flag)
	register struct tty *tp;
	int com;
	caddr_t data;
	int flag;
#else
__private_extern__ int
ttcompat(tp, com, data, flag, p)
	register struct tty *tp;
	u_long com;
	caddr_t data;
	int flag;
	struct proc *p;
#endif /* !NeXT */
{
	switch (com) {
	case TIOCSETP:
	case TIOCSETN:
	case TIOCSETC:
	case TIOCSLTC:
	case TIOCLBIS:
	case TIOCLBIC:
	case TIOCLSET: {
		struct termios term;
		int error;

		term = tp->t_termios;
		if ((error = ttsetcompat(tp, &com, data, &term)) != 0)
			return error;
#ifdef NeXT
		return ttioctl(tp, com, (caddr_t) &term, flag, p);
#else
		return ttioctl(tp, com, &term, flag);
#endif
	}
	case TIOCGETP: {
		register struct sgttyb *sg = (struct sgttyb *)data;
		register cc_t *cc = tp->t_cc;

		sg->sg_ospeed = ttcompatspeedtab(tp->t_ospeed, compatspeeds);
		if (tp->t_ispeed == 0)
			sg->sg_ispeed = sg->sg_ospeed;
		else
			sg->sg_ispeed = ttcompatspeedtab(tp->t_ispeed, compatspeeds);
		sg->sg_erase = cc[VERASE];
		sg->sg_kill = cc[VKILL];
		sg->sg_flags = tp->t_flags = ttcompatgetflags(tp);
		break;
	}
	case TIOCGETC: {
		struct tchars *tc = (struct tchars *)data;
		register cc_t *cc = tp->t_cc;

		tc->t_intrc = cc[VINTR];
		tc->t_quitc = cc[VQUIT];
		tc->t_startc = cc[VSTART];
		tc->t_stopc = cc[VSTOP];
		tc->t_eofc = cc[VEOF];
		tc->t_brkc = cc[VEOL];
		break;
	}
	case TIOCGLTC: {
		struct ltchars *ltc = (struct ltchars *)data;
		register cc_t *cc = tp->t_cc;

		ltc->t_suspc = cc[VSUSP];
		ltc->t_dsuspc = cc[VDSUSP];
		ltc->t_rprntc = cc[VREPRINT];
		ltc->t_flushc = cc[VDISCARD];
		ltc->t_werasc = cc[VWERASE];
		ltc->t_lnextc = cc[VLNEXT];
		break;
	}
	case TIOCLGET:
		tp->t_flags =
		 (ttcompatgetflags(tp) & 0xffff0000UL)
		   | (tp->t_flags & 0xffff);
		*(int *)data = tp->t_flags>>16;
#ifndef NeXT
		if (ttydebug)
			printf("CLGET: returning %x\n", *(int *)data);
#endif
		break;

	case OTIOCGETD:
		*(int *)data = tp->t_line ? tp->t_line : 2;
		break;

#ifndef NeXT
	case OTIOCSETD: {
		int ldisczero = 0;

		return (ttioctl(tp, TIOCSETD,
			*(int *)data == 2 ? (caddr_t)&ldisczero : data, flag));
	    }

	case OTIOCCONS:
		*(int *)data = 1;
		return (ttioctl(tp, TIOCCONS, data, flag));
#else
	case OTIOCSETD: {
		int ldisczero = 0;

		return (ttioctl(tp, TIOCSETD, 
		    *(int *)data == 2 ? (caddr_t)&ldisczero : data, flag, p));
	    }

	case OTIOCCONS:
		*(int *)data = 1;
		return (ttioctl(tp, TIOCCONS, data, flag, p));

	case TIOCGSID:
		if (tp->t_session == NULL)
			return ENOTTY;

		if (tp->t_session->s_leader == NULL)
			return ENOTTY;

		*(int *) data =  tp->t_session->s_leader->p_pid;
		break;
#endif /* NeXT */

	default:
		return (-1);
	}
	return (0);
}

static int
ttcompatgetflags(tp)
	register struct tty *tp;
{
	register tcflag_t iflag	= tp->t_iflag;
	register tcflag_t lflag	= tp->t_lflag;
	register tcflag_t oflag	= tp->t_oflag;
	register tcflag_t cflag	= tp->t_cflag;
	register flags = 0;

	if (iflag&IXOFF)
		flags |= TANDEM;
	if (iflag&ICRNL || oflag&ONLCR)
		flags |= CRMOD;
	if ((cflag&CSIZE) == CS8) {
		flags |= PASS8;
		if (iflag&ISTRIP)
			flags |= ANYP;
	}
	else if (cflag&PARENB) {
		if (iflag&INPCK) {
			if (cflag&PARODD)
				flags |= ODDP;
			else
				flags |= EVENP;
		} else
			flags |= EVENP | ODDP;
	}

	if ((lflag&ICANON) == 0) {
		/* fudge */
		if (iflag&(INPCK|ISTRIP|IXON) || lflag&(IEXTEN|ISIG)
		    || cflag&(CSIZE|PARENB) != CS8)
			flags |= CBREAK;
		else
			flags |= RAW;
	}
	if (!(flags&RAW) && !(oflag&OPOST) && cflag&(CSIZE|PARENB) == CS8)
		flags |= LITOUT;
	if (cflag&MDMBUF)
		flags |= MDMBUF;
	if ((cflag&HUPCL) == 0)
		flags |= NOHANG;
	if (oflag&OXTABS)
		flags |= XTABS;
	if (lflag&ECHOE)
		flags |= CRTERA|CRTBS;
	if (lflag&ECHOKE)
		flags |= CRTKIL|CRTBS;
	if (lflag&ECHOPRT)
		flags |= PRTERA;
	if (lflag&ECHOCTL)
		flags |= CTLECH;
	if ((iflag&IXANY) == 0)
		flags |= DECCTQ;
	flags |= lflag&(ECHO|TOSTOP|FLUSHO|PENDIN|NOFLSH);
#ifndef NeXT
	if (ttydebug)
		printf("getflags: %x\n", flags);
#endif
	return (flags);
}

static void
ttcompatsetflags(tp, t)
	register struct tty *tp;
	register struct termios *t;
{
	register flags = tp->t_flags;
	register tcflag_t iflag	= t->c_iflag;
	register tcflag_t oflag	= t->c_oflag;
	register tcflag_t lflag	= t->c_lflag;
	register tcflag_t cflag	= t->c_cflag;

	if (flags & RAW) {
		iflag = IGNBRK;
		lflag &= ~(ECHOCTL|ISIG|ICANON|IEXTEN);
	} else {
		iflag &= ~(PARMRK|IGNPAR|IGNCR|INLCR);
		iflag |= BRKINT|IXON|IMAXBEL;
		lflag |= ISIG|IEXTEN|ECHOCTL;	/* XXX was echoctl on ? */
		if (flags & XTABS)
			oflag |= OXTABS;
		else
			oflag &= ~OXTABS;
		if (flags & CBREAK)
			lflag &= ~ICANON;
		else
			lflag |= ICANON;
		if (flags&CRMOD) {
			iflag |= ICRNL;
			oflag |= ONLCR;
		} else {
			iflag &= ~ICRNL;
			oflag &= ~ONLCR;
		}
	}
	if (flags&ECHO)
		lflag |= ECHO;
	else
		lflag &= ~ECHO;

	cflag &= ~(CSIZE|PARENB);
	if (flags&(RAW|LITOUT|PASS8)) {
		cflag |= CS8;
		if (!(flags&(RAW|PASS8))
		    || (flags&(RAW|PASS8|ANYP)) == (PASS8|ANYP))
			iflag |= ISTRIP;
		else
			iflag &= ~ISTRIP;
		if (flags&(RAW|LITOUT))
			oflag &= ~OPOST;
		else
			oflag |= OPOST;
	} else {
		cflag |= CS7|PARENB;
		iflag |= ISTRIP;
		oflag |= OPOST;
	}
	/* XXX don't set INPCK if RAW or PASS8? */
	if ((flags&(EVENP|ODDP)) == EVENP) {
		iflag |= INPCK;
		cflag &= ~PARODD;
	} else if ((flags&(EVENP|ODDP)) == ODDP) {
		iflag |= INPCK;
		cflag |= PARODD;
	} else
		iflag &= ~INPCK;
	if (flags&TANDEM)
		iflag |= IXOFF;
	else
		iflag &= ~IXOFF;
	if ((flags&DECCTQ) == 0)
		iflag |= IXANY;
	else
		iflag &= ~IXANY;
	t->c_iflag = iflag;
	t->c_oflag = oflag;
	t->c_lflag = lflag;
	t->c_cflag = cflag;
}

static void
ttcompatsetlflags(tp, t)
	register struct tty *tp;
	register struct termios *t;
{
	register flags = tp->t_flags;
	register tcflag_t iflag	= t->c_iflag;
	register tcflag_t oflag	= t->c_oflag;
	register tcflag_t lflag	= t->c_lflag;
	register tcflag_t cflag	= t->c_cflag;

	iflag &= ~(PARMRK|IGNPAR|IGNCR|INLCR);
	if (flags&CRTERA)
		lflag |= ECHOE;
	else
		lflag &= ~ECHOE;
	if (flags&CRTKIL)
		lflag |= ECHOKE;
	else
		lflag &= ~ECHOKE;
	if (flags&PRTERA)
		lflag |= ECHOPRT;
	else
		lflag &= ~ECHOPRT;
	if (flags&CTLECH)
		lflag |= ECHOCTL;
	else
		lflag &= ~ECHOCTL;
	if (flags&TANDEM)
		iflag |= IXOFF;
	else
		iflag &= ~IXOFF;
	if ((flags&DECCTQ) == 0)
		iflag |= IXANY;
	else
		iflag &= ~IXANY;
	if (flags & MDMBUF)
		cflag |= MDMBUF;
	else
		cflag &= ~MDMBUF;
	if (flags&NOHANG)
		cflag &= ~HUPCL;
	else
		cflag |= HUPCL;
	lflag &= ~(TOSTOP|FLUSHO|PENDIN|NOFLSH);
	lflag |= flags&(TOSTOP|FLUSHO|PENDIN|NOFLSH);

	/*
	 * The next if-else statement is copied from above so don't bother
	 * checking it separately.  We could avoid fiddlling with the
	 * character size if the mode is already RAW or if neither the
	 * LITOUT bit or the PASS8 bit is being changed, but the delta of
	 * the change is not available here and skipping the RAW case would
	 * make the code different from above.
	 */
	cflag &= ~(CSIZE|PARENB);
	if (flags&(RAW|LITOUT|PASS8)) {
		cflag |= CS8;
		if (!(flags&(RAW|PASS8))
		    || (flags&(RAW|PASS8|ANYP)) == (PASS8|ANYP))
			iflag |= ISTRIP;
		else
			iflag &= ~ISTRIP;
		if (flags&(RAW|LITOUT))
			oflag &= ~OPOST;
		else
			oflag |= OPOST;
	} else {
		cflag |= CS7|PARENB;
		iflag |= ISTRIP;
		oflag |= OPOST;
	}
	t->c_iflag = iflag;
	t->c_oflag = oflag;
	t->c_lflag = lflag;
	t->c_cflag = cflag;
}
#endif	/* COMPAT_43 || COMPAT_SUNOS */
