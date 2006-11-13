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
/* Copyright (c) 1997 Apple Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1989, 1993
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
 *	@(#)tty_pty.c	8.4 (Berkeley) 2/20/95
 */

/*
 * Pseudo-teletype Driver
 * (Actually two drivers, requiring two entries in 'cdevsw')
 */
#include "pty.h"		/* XXX */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ioctl.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/tty.h>
#include <sys/conf.h>
#include <sys/file_internal.h>
#include <sys/uio.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/user.h>
#include <sys/signalvar.h>

#ifndef NeXT

#define FREE_BSDSTATIC	static
#else
#define FREE_BSDSTATIC __private_extern__
#define d_devtotty_t    struct tty **

#ifdef d_stop_t
#undef d_stop_t
#endif
typedef void d_stop_t(struct tty *tp, int rw);

#endif /* NeXT */

/* XXX function should be removed??? */
int pty_init(int n_ptys);

#ifdef notyet
static void ptyattach(int n);
#endif
static void ptsstart(struct tty *tp);
static void ptcwakeup(struct tty *tp, int flag);

FREE_BSDSTATIC	d_open_t	ptsopen;
FREE_BSDSTATIC	d_close_t	ptsclose;
FREE_BSDSTATIC	d_read_t	ptsread;
FREE_BSDSTATIC	d_write_t	ptswrite;
FREE_BSDSTATIC	d_ioctl_t	ptyioctl;
FREE_BSDSTATIC	d_stop_t	ptsstop;
FREE_BSDSTATIC	d_devtotty_t	ptydevtotty;
FREE_BSDSTATIC	d_open_t	ptcopen;
FREE_BSDSTATIC	d_close_t	ptcclose;
FREE_BSDSTATIC	d_read_t	ptcread;
FREE_BSDSTATIC	d_write_t	ptcwrite;
FREE_BSDSTATIC	d_select_t	ptcselect;

#ifndef NeXT
#define CDEV_MAJOR_S 5
#define CDEV_MAJOR_C 6
static struct cdevsw pts_cdevsw = 
	{ ptsopen,	ptsclose,	ptsread,	ptswrite,	/*5*/
	  ptyioctl,	ptsstop,	nullreset,	ptydevtotty,/* ttyp */
	  ttselect,	nommap,		NULL,	"pts",	NULL,	-1 };

static struct cdevsw ptc_cdevsw = 
	{ ptcopen,	ptcclose,	ptcread,	ptcwrite,	/*6*/
	  ptyioctl,	nullstop,	nullreset,	ptydevtotty,/* ptyp */
	  ptcselect,	nommap,		NULL,	"ptc",	NULL,	-1 };
#endif /* !NeXT */


#if NPTY == 1
#undef NPTY
#define	NPTY	32		/* crude XXX */
#warning	You have only one pty defined, redefining to 32.
#endif

#ifndef NeXT
#ifdef DEVFS
#define MAXUNITS (8 * 32)
static	void	*devfs_token_pts[MAXUNITS];
static	void	*devfs_token_ptc[MAXUNITS];
static  const	char jnames[] = "pqrsPQRS";
#if NPTY > MAXUNITS
#undef NPTY
#define NPTY MAXUNITS
#warning	Can't have more than 256 pty's with DEVFS defined.
#endif /* NPTY > MAXUNITS */
#endif /* DEVFS */
#endif /* !NeXT */

#define BUFSIZ 100		/* Chunk size iomoved to/from user */

/*
 * pts == /dev/tty[pqrsPQRS][0123456789abcdefghijklmnopqrstuv]
 * ptc == /dev/pty[pqrsPQRS][0123456789abcdefghijklmnopqrstuv]
 */
#ifndef NeXT
FREE_BSDSTATIC struct	tty pt_tty[NPTY];	/* XXX */
#else /* NeXT */
/* NeXT All references to have been changed to indirections in the file */
FREE_BSDSTATIC struct	tty *pt_tty[NPTY] = { NULL };
#endif /* ! NeXT */

static struct	pt_ioctl {
	int	pt_flags;
	struct	selinfo pt_selr, pt_selw;
	u_char	pt_send;
	u_char	pt_ucntl;
} pt_ioctl[NPTY];		/* XXX */
static int	npty = NPTY;		/* for pstat -t */

#define	PF_PKT		0x08		/* packet mode */
#define	PF_STOPPED	0x10		/* user told stopped */
#define	PF_REMOTE	0x20		/* remote and flow controlled input */
#define	PF_NOSTOP	0x40
#define PF_UCNTL	0x80		/* user control mode */

#ifdef notyet
/*
 * Establish n (or default if n is 1) ptys in the system.
 *
 * XXX cdevsw & pstat require the array `pty[]' to be an array
 */
FREEBSD_STATIC void
ptyattach(n)
	int n;
{
	char *mem;
	register u_long ntb;
#define	DEFAULT_NPTY	32

	/* maybe should allow 0 => none? */
	if (n <= 1)
		n = DEFAULT_NPTY;
	ntb = n * sizeof(struct tty);
#ifndef NeXT
	mem = malloc(ntb + ALIGNBYTES + n * sizeof(struct pt_ioctl),
	    M_DEVBUF, M_WAITOK);
#else
	MALLOC(mem, char *, ntb + ALIGNBYTES + n * sizeof(struct pt_ioctl),
			M_DEVBUF, M_WAITOK);
#endif /* !NeXT */
	pt_tty = (struct tty *)mem;
	mem = (char *)ALIGN(mem + ntb);
	pt_ioctl = (struct pt_ioctl *)mem;
	npty = n;
}
#endif

#ifndef DEVFS
int
pty_init(__unused int n_ptys)
{
    return 0;
}
#else
#include <miscfs/devfs/devfs.h>
#define START_CHAR	'p'
#define HEX_BASE	16
int
pty_init(int n_ptys)
{
    int 	i;
    int		j;

    /* create the pseudo tty device nodes */
    for (j = 0; j < 10; j++) {
	for (i = 0; i < HEX_BASE; i++) {
	    int m = j * HEX_BASE + i;
	    if (m == n_ptys)
		goto done;
	    (void)devfs_make_node(makedev(4, m), 
				  DEVFS_CHAR, UID_ROOT, GID_WHEEL, 0666, 
				  "tty%c%x", j + START_CHAR, i);
	    (void)devfs_make_node(makedev(5, m), 
				  DEVFS_CHAR, UID_ROOT, GID_WHEEL, 0666, 
				  "pty%c%x", j + START_CHAR, i);
	}
    }
 done:
    return (0);
}
#endif /* DEVFS */

/*ARGSUSED*/
FREE_BSDSTATIC int
ptsopen(dev_t dev, int flag, __unused int devtype, __unused struct proc *p)
{
	register struct tty *tp;
	int error;
	boolean_t   funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);
#ifndef NeXT
	tp = &pt_tty[minor(dev)];
#else
	/*
	 * You will see this sort of code coming up in diffs later both
	 * the ttymalloc and the tp indirection.
	 */
	if (minor(dev) >= npty) {
	        error = ENXIO;
		goto out;
	}
	if (!pt_tty[minor(dev)]) {
		tp = pt_tty[minor(dev)] = ttymalloc();
	} else
		tp = pt_tty[minor(dev)];
#endif
	if ((tp->t_state & TS_ISOPEN) == 0) {
		ttychars(tp);		/* Set up default chars */
		tp->t_iflag = TTYDEF_IFLAG;
		tp->t_oflag = TTYDEF_OFLAG;
		tp->t_lflag = TTYDEF_LFLAG;
		tp->t_cflag = TTYDEF_CFLAG;
		tp->t_ispeed = tp->t_ospeed = TTYDEF_SPEED;
		ttsetwater(tp);		/* would be done in xxparam() */
	} else if (tp->t_state&TS_XCLUDE && suser(kauth_cred_get(), NULL)) {
	        error = EBUSY;
		goto out;
	}
	if (tp->t_oproc)			/* Ctrlr still around. */
		(void)(*linesw[tp->t_line].l_modem)(tp, 1);
	while ((tp->t_state & TS_CARR_ON) == 0) {
		if (flag&FNONBLOCK)
			break;
		error = ttysleep(tp, TSA_CARR_ON(tp), TTIPRI | PCATCH,
				 "ptsopn", 0);
		if (error)
			goto out;
	}
	error = (*linesw[tp->t_line].l_open)(dev, tp);
	if (error == 0)
		ptcwakeup(tp, FREAD|FWRITE);
out:
	(void) thread_funnel_set(kernel_flock, funnel_state);
	return (error);
}

FREE_BSDSTATIC int
ptsclose(dev_t dev, int flag, __unused int mode, __unused proc_t p)
{
	register struct tty *tp;
	int err;
	boolean_t   funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	tp = pt_tty[minor(dev)];
	err = (*linesw[tp->t_line].l_close)(tp, flag);
	ptsstop(tp, FREAD|FWRITE);
	(void) ttyclose(tp);

	(void) thread_funnel_set(kernel_flock, funnel_state);
	return (err);
}

FREE_BSDSTATIC int
ptsread(dev, uio, flag)
	dev_t dev;
	struct uio *uio;
	int flag;
{
#ifndef NeXT
	struct proc *p = curproc;
#else
	struct proc *p = current_proc();
#endif /* NeXT */
	register struct tty *tp = pt_tty[minor(dev)];
	register struct pt_ioctl *pti = &pt_ioctl[minor(dev)];
	int error = 0;
	struct uthread *ut;
	boolean_t   funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);


	ut = (struct uthread *)get_bsdthread_info(current_thread());
again:
	if (pti->pt_flags & PF_REMOTE) {
		while (isbackground(p, tp)) {
			if ((p->p_sigignore & sigmask(SIGTTIN)) ||
			    (ut->uu_sigmask & sigmask(SIGTTIN)) ||
			    p->p_pgrp->pg_jobc == 0 ||
			    p->p_flag & P_PPWAIT) {
				error = EIO;
				goto out;
			}
			pgsignal(p->p_pgrp, SIGTTIN, 1);
			error = ttysleep(tp, &lbolt, TTIPRI | PCATCH | PTTYBLOCK, "ptsbg",
					 0);
			if (error)
			        goto out;
		}
		if (tp->t_canq.c_cc == 0) {
			if (flag & IO_NDELAY)
				return (EWOULDBLOCK);
			error = ttysleep(tp, TSA_PTS_READ(tp), TTIPRI | PCATCH,
					 "ptsin", 0);
			if (error)
			        goto out;
			goto again;
		}
		while (tp->t_canq.c_cc > 1 && uio_resid(uio) > 0) {
			int cc;
			char buf[BUFSIZ];

			cc = min(uio_resid(uio), BUFSIZ);
			// Don't copy the very last byte
			cc = min(cc, tp->t_canq.c_cc - 1);
			cc = q_to_b(&tp->t_canq, buf, cc);
			error = uiomove(buf, cc, uio);
			if (error)
				break;
		}
		if (tp->t_canq.c_cc == 1)
			(void) getc(&tp->t_canq);
		if (tp->t_canq.c_cc)
		        goto out;
	} else
		if (tp->t_oproc)
			error = (*linesw[tp->t_line].l_read)(tp, uio, flag);
	ptcwakeup(tp, FWRITE);
out:
	(void) thread_funnel_set(kernel_flock, funnel_state);
	return (error);
}

/*
 * Write to pseudo-tty.
 * Wakeups of controlling tty will happen
 * indirectly, when tty driver calls ptsstart.
 */
FREE_BSDSTATIC int
ptswrite(dev, uio, flag)
	dev_t dev;
	struct uio *uio;
	int flag;
{
	register struct tty *tp;
	int error;
	boolean_t   funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	tp = pt_tty[minor(dev)];
	if (tp->t_oproc == 0)
		error = EIO;
	else
	        error = (*linesw[tp->t_line].l_write)(tp, uio, flag);

	(void) thread_funnel_set(kernel_flock, funnel_state);
	return (error);
}

/*
 * Start output on pseudo-tty.
 * Wake up process selecting or sleeping for input from controlling tty.
 */
static void
ptsstart(tp)
	struct tty *tp;
{
	register struct pt_ioctl *pti = &pt_ioctl[minor(tp->t_dev)];
	boolean_t   funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	if (tp->t_state & TS_TTSTOP)
	        goto out;
	if (pti->pt_flags & PF_STOPPED) {
		pti->pt_flags &= ~PF_STOPPED;
		pti->pt_send = TIOCPKT_START;
	}
	ptcwakeup(tp, FREAD);
out:
	(void) thread_funnel_set(kernel_flock, funnel_state);
	return;
}

static void
ptcwakeup(tp, flag)
	struct tty *tp;
	int flag;
{
	struct pt_ioctl *pti = &pt_ioctl[minor(tp->t_dev)];
	boolean_t   funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	if (flag & FREAD) {
		selwakeup(&pti->pt_selr);
		wakeup(TSA_PTC_READ(tp));
	}
	if (flag & FWRITE) {
		selwakeup(&pti->pt_selw);
		wakeup(TSA_PTC_WRITE(tp));
	}
	(void) thread_funnel_set(kernel_flock, funnel_state);
}

FREE_BSDSTATIC int
ptcopen(dev_t dev, __unused int flag, __unused int devtype, __unused proc_t p)
{
	register struct tty *tp;
	struct pt_ioctl *pti;
	int error = 0;
	boolean_t   funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	if (minor(dev) >= npty) {
		error = ENXIO;
		goto out;
	}
	if(!pt_tty[minor(dev)]) {
		tp = pt_tty[minor(dev)] = ttymalloc();
	} else
		tp = pt_tty[minor(dev)];
	if (tp->t_oproc) {
		error = EIO;
		goto out;
	}
	tp->t_oproc = ptsstart;
	CLR(tp->t_state, TS_ZOMBIE);
#ifdef sun4c
	tp->t_stop = ptsstop;
#endif
	(void)(*linesw[tp->t_line].l_modem)(tp, 1);
	tp->t_lflag &= ~EXTPROC;
	pti = &pt_ioctl[minor(dev)];
	pti->pt_flags = 0;
	pti->pt_send = 0;
	pti->pt_ucntl = 0;
out:
	(void) thread_funnel_set(kernel_flock, funnel_state);
	return (error);
}

FREE_BSDSTATIC int
ptcclose(dev_t dev, __unused int flags, __unused int fmt, __unused proc_t p)
{
	register struct tty *tp;
	boolean_t   funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	tp = pt_tty[minor(dev)];
	(void)(*linesw[tp->t_line].l_modem)(tp, 0);

	/*
	 * XXX MDMBUF makes no sense for ptys but would inhibit the above
	 * l_modem().  CLOCAL makes sense but isn't supported.   Special
	 * l_modem()s that ignore carrier drop make no sense for ptys but
	 * may be in use because other parts of the line discipline make
	 * sense for ptys.  Recover by doing everything that a normal
	 * ttymodem() would have done except for sending a SIGHUP.
	 */
	if (tp->t_state & TS_ISOPEN) {
		tp->t_state &= ~(TS_CARR_ON | TS_CONNECTED);
		tp->t_state |= TS_ZOMBIE;
		ttyflush(tp, FREAD | FWRITE);
	}

	tp->t_oproc = 0;		/* mark closed */

	(void) thread_funnel_set(kernel_flock, funnel_state);
	return (0);
}

FREE_BSDSTATIC int
ptcread(dev, uio, flag)
	dev_t dev;
	struct uio *uio;
	int flag;
{
	register struct tty *tp = pt_tty[minor(dev)];
	struct pt_ioctl *pti = &pt_ioctl[minor(dev)];
	char buf[BUFSIZ];
	int error = 0, cc;
	boolean_t   funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	/*
	 * We want to block until the slave
	 * is open, and there's something to read;
	 * but if we lost the slave or we're NBIO,
	 * then return the appropriate error instead.
	 */
	for (;;) {
		if (tp->t_state&TS_ISOPEN) {
			if (pti->pt_flags&PF_PKT && pti->pt_send) {
				error = ureadc((int)pti->pt_send, uio);
				if (error)
					goto out;
				if (pti->pt_send & TIOCPKT_IOCTL) {
					cc = min(uio_resid(uio),
						sizeof(tp->t_termios));
					uiomove((caddr_t)&tp->t_termios, cc,
						uio);
				}
				pti->pt_send = 0;
				goto out;
			}
			if (pti->pt_flags&PF_UCNTL && pti->pt_ucntl) {
				error = ureadc((int)pti->pt_ucntl, uio);
				if (error)
					goto out;
				pti->pt_ucntl = 0;
				goto out;
			}
			if (tp->t_outq.c_cc && (tp->t_state&TS_TTSTOP) == 0)
				break;
		}
		if ((tp->t_state & TS_CONNECTED) == 0)
			goto out;	/* EOF */
		if (flag & IO_NDELAY) {
			error = EWOULDBLOCK;
			goto out;
		}
		error = tsleep(TSA_PTC_READ(tp), TTIPRI | PCATCH, "ptcin", 0);
		if (error)
		        goto out;
	}
	if (pti->pt_flags & (PF_PKT|PF_UCNTL))
		error = ureadc(0, uio);
	while (uio_resid(uio) > 0 && error == 0) {
		cc = q_to_b(&tp->t_outq, buf, min(uio_resid(uio), BUFSIZ));
		if (cc <= 0)
			break;
		error = uiomove(buf, cc, uio);
	}
	(*linesw[tp->t_line].l_start)(tp);

out:
	(void) thread_funnel_set(kernel_flock, funnel_state);
	return (error);
}

FREE_BSDSTATIC void
ptsstop(tp, flush)
	register struct tty *tp;
	int flush;
{
	struct pt_ioctl *pti = &pt_ioctl[minor(tp->t_dev)];
	int flag;
	boolean_t   funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	/* note: FLUSHREAD and FLUSHWRITE already ok */
	if (flush == 0) {
		flush = TIOCPKT_STOP;
		pti->pt_flags |= PF_STOPPED;
	} else
		pti->pt_flags &= ~PF_STOPPED;
	pti->pt_send |= flush;
	/* change of perspective */
	flag = 0;
	if (flush & FREAD)
		flag |= FWRITE;
	if (flush & FWRITE)
		flag |= FREAD;
	ptcwakeup(tp, flag);

	(void) thread_funnel_set(kernel_flock, funnel_state);
}

FREE_BSDSTATIC int
ptcselect(dev, rw, wql, p)
	dev_t dev;
	int rw;
	void * wql;
	struct proc *p;
{
	register struct tty *tp = pt_tty[minor(dev)];
	struct pt_ioctl *pti = &pt_ioctl[minor(dev)];
	int retval = 0;
	boolean_t   funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	if ((tp->t_state & TS_CONNECTED) == 0) {
		retval = 1;
		goto out;
	}
	switch (rw) {

	case FREAD:
		/*
		 * Need to block timeouts (ttrstart).
		 */
		if ((tp->t_state&TS_ISOPEN) &&
		     tp->t_outq.c_cc && (tp->t_state&TS_TTSTOP) == 0) {
			retval = 1;
			goto out;
		}
		/* FALLTHROUGH */

	case 0:					/* exceptional */
		if ((tp->t_state&TS_ISOPEN) &&
		    ((pti->pt_flags&PF_PKT && pti->pt_send) ||
		     (pti->pt_flags&PF_UCNTL && pti->pt_ucntl))) {
			retval = 1;
			goto out;
		}
		selrecord(p, &pti->pt_selr, wql);
		break;


	case FWRITE:
		if (tp->t_state&TS_ISOPEN) {
			if (pti->pt_flags & PF_REMOTE) {
			    if (tp->t_canq.c_cc == 0) {
				retval = 1;
				goto out;
			    }
			} else {
			    if (tp->t_rawq.c_cc + tp->t_canq.c_cc < TTYHOG-2) {
				    retval = 1;
				    goto out;
			    }
			    if (tp->t_canq.c_cc == 0 && (tp->t_iflag&ICANON)) {
				    retval = 1;
				    goto out;
			    }
			}
		}
		selrecord(p, &pti->pt_selw, wql);
		break;

	}
out:
	(void) thread_funnel_set(kernel_flock, funnel_state);
	return (retval);
}

FREE_BSDSTATIC int
ptcwrite(dev, uio, flag)
	dev_t dev;
	register struct uio *uio;
	int flag;
{
	register struct tty *tp = pt_tty[minor(dev)];
	register u_char *cp = NULL;
	register int cc = 0;
	u_char locbuf[BUFSIZ];
	int wcnt = 0;
	struct pt_ioctl *pti = &pt_ioctl[minor(dev)];
	int error = 0;
	boolean_t   funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

again:
	if ((tp->t_state&TS_ISOPEN) == 0)
		goto block;
	if (pti->pt_flags & PF_REMOTE) {
		if (tp->t_canq.c_cc)
			goto block;
		while ((uio_resid(uio) > 0 || cc > 0) &&
		       tp->t_canq.c_cc < TTYHOG - 1) {
			if (cc == 0) {
				cc = min(uio_resid(uio), BUFSIZ);
				cc = min(cc, TTYHOG - 1 - tp->t_canq.c_cc);
				cp = locbuf;
				error = uiomove((caddr_t)cp, cc, uio);
				if (error)
					goto out;
				/* check again for safety */
				if ((tp->t_state & TS_ISOPEN) == 0) {
					/* adjust as usual */
					uio_setresid(uio, (uio_resid(uio) + cc));
					error = EIO;
					goto out;
				}
			}
			if (cc > 0) {
				cc = b_to_q((char *)cp, cc, &tp->t_canq);
				/*
				 * XXX we don't guarantee that the canq size
				 * is >= TTYHOG, so the above b_to_q() may
				 * leave some bytes uncopied.  However, space
				 * is guaranteed for the null terminator if
				 * we don't fail here since (TTYHOG - 1) is
				 * not a multiple of CBSIZE.
				 */
				if (cc > 0)
					break;
			}
		}
		/* adjust for data copied in but not written */
		uio_setresid(uio, (uio_resid(uio) + cc));
		(void) putc(0, &tp->t_canq);
		ttwakeup(tp);
		wakeup(TSA_PTS_READ(tp));
		goto out;
	}
	while (uio_resid(uio) > 0 || cc > 0) {
		if (cc == 0) {
			cc = min(uio_resid(uio), BUFSIZ);
			cp = locbuf;
			error = uiomove((caddr_t)cp, cc, uio);
			if (error)
				goto out;
			/* check again for safety */
			if ((tp->t_state & TS_ISOPEN) == 0) {
				/* adjust for data copied in but not written */
				uio_setresid(uio, (uio_resid(uio) + cc));
				error = EIO;
				goto out;
			}
		}
		while (cc > 0) {
			if ((tp->t_rawq.c_cc + tp->t_canq.c_cc) >= TTYHOG - 2 &&
			   (tp->t_canq.c_cc > 0 || !(tp->t_iflag&ICANON))) {
				wakeup(TSA_HUP_OR_INPUT(tp));
				goto block;
			}
			(*linesw[tp->t_line].l_rint)(*cp++, tp);
			wcnt++;
			cc--;
		}
		cc = 0;
	}
out:
	(void) thread_funnel_set(kernel_flock, funnel_state);
	return (error);
block:
	/*
	 * Come here to wait for slave to open, for space
	 * in outq, or space in rawq, or an empty canq.
	 */
	if ((tp->t_state & TS_CONNECTED) == 0) {
		/* adjust for data copied in but not written */
		uio_setresid(uio, (uio_resid(uio) + cc));
		error = EIO;
		goto out;
	}
	if (flag & IO_NDELAY) {
		/* adjust for data copied in but not written */
		uio_setresid(uio, (uio_resid(uio) + cc));
		if (wcnt == 0)
			error = EWOULDBLOCK;
		goto out;
	}
	error = tsleep(TSA_PTC_WRITE(tp), TTOPRI | PCATCH, "ptcout", 0);
	if (error) {
		/* adjust for data copied in but not written */
		uio_setresid(uio, (uio_resid(uio) + cc));
		goto out;
	}
	goto again;
}

#ifndef NeXT
/* XXX we eventually want to go to this model,
 * but premier can't change the cdevsw */
static	struct tty *
ptydevtotty(dev)
	dev_t		dev;
{
	if (minor(dev) >= npty)
		return (NULL);

	return &pt_tty[minor(dev)];
}
#endif /* !NeXT */

/*ARGSUSED*/
FREE_BSDSTATIC int
#ifndef NeXT
ptyioctl(dev, cmd, data, flag)
	dev_t dev;
	int cmd;
	caddr_t data;
	int flag;
#else
ptyioctl(dev, cmd, data, flag, p)
	dev_t dev;
	u_long cmd;
	caddr_t data;
	int flag;
	struct proc *p;
#endif
{
	register struct tty *tp = pt_tty[minor(dev)];
	register struct pt_ioctl *pti = &pt_ioctl[minor(dev)];
	register u_char *cc = tp->t_cc;
	int stop, error = 0;
	boolean_t   funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	/*
	 * IF CONTROLLER STTY THEN MUST FLUSH TO PREVENT A HANG.
	 * ttywflush(tp) will hang if there are characters in the outq.
	 */
	if (cmd == TIOCEXT) {
		/*
		 * When the EXTPROC bit is being toggled, we need
		 * to send an TIOCPKT_IOCTL if the packet driver
		 * is turned on.
		 */
		if (*(int *)data) {
			if (pti->pt_flags & PF_PKT) {
				pti->pt_send |= TIOCPKT_IOCTL;
				ptcwakeup(tp, FREAD);
			}
			tp->t_lflag |= EXTPROC;
		} else {
			if ((tp->t_lflag & EXTPROC) &&
			    (pti->pt_flags & PF_PKT)) {
				pti->pt_send |= TIOCPKT_IOCTL;
				ptcwakeup(tp, FREAD);
			}
			tp->t_lflag &= ~EXTPROC;
		}
		goto out;
	} else
#ifndef NeXT
	if (cdevsw[major(dev)]->d_open == ptcopen)
#else
	if (cdevsw[major(dev)].d_open == ptcopen)
#endif
		switch (cmd) {

		case TIOCGPGRP:
			/*
			 * We aviod calling ttioctl on the controller since,
			 * in that case, tp must be the controlling terminal.
			 */
			*(int *)data = tp->t_pgrp ? tp->t_pgrp->pg_id : 0;
			goto out;

		case TIOCPKT:
			if (*(int *)data) {
			        if (pti->pt_flags & PF_UCNTL) {
					error = EINVAL;
					goto out;
				}
				pti->pt_flags |= PF_PKT;
			} else
				pti->pt_flags &= ~PF_PKT;
			goto out;

		case TIOCUCNTL:
			if (*(int *)data) {
			        if (pti->pt_flags & PF_PKT) {
					error = EINVAL;
					goto out;
				}
				pti->pt_flags |= PF_UCNTL;
			} else
				pti->pt_flags &= ~PF_UCNTL;
			goto out;

		case TIOCREMOTE:
			if (*(int *)data)
				pti->pt_flags |= PF_REMOTE;
			else
				pti->pt_flags &= ~PF_REMOTE;
			ttyflush(tp, FREAD|FWRITE);
			goto out;

#if COMPAT_43_TTY
		case TIOCSETP:
		case TIOCSETN:
#endif
		case TIOCSETD:
		case TIOCSETA:
		case TIOCSETAW:
		case TIOCSETAF:
			ndflush(&tp->t_outq, tp->t_outq.c_cc);
			break;

		case TIOCSIG:
			if (*(unsigned int *)data >= NSIG ||
			    *(unsigned int *)data == 0) {
				error = EINVAL;
				goto out;
			}
			if ((tp->t_lflag&NOFLSH) == 0)
				ttyflush(tp, FREAD|FWRITE);
			pgsignal(tp->t_pgrp, *(unsigned int *)data, 1);
			if ((*(unsigned int *)data == SIGINFO) &&
			    ((tp->t_lflag&NOKERNINFO) == 0))
				ttyinfo(tp);
			goto out;
		}
	error = (*linesw[tp->t_line].l_ioctl)(tp, cmd, data, flag, p);
	if (error == ENOTTY) {
		error = ttioctl(tp, cmd, data, flag, p);
		if (error == ENOTTY
		&&  pti->pt_flags & PF_UCNTL && (cmd & ~0xff) == UIOCCMD(0)) {
			/* Process the UIOCMD ioctl group */
			if (cmd & 0xff) {
				pti->pt_ucntl = (u_char)cmd;
				ptcwakeup(tp, FREAD);
			}
			error = 0;
			goto out;
		}
	}

	/*
	 * If external processing and packet mode send ioctl packet.
	 */
	if ((tp->t_lflag&EXTPROC) && (pti->pt_flags & PF_PKT)) {
		switch(cmd) {
		case TIOCSETA:
		case TIOCSETAW:
		case TIOCSETAF:
#if COMPAT_43_TTY
		case TIOCSETP:
		case TIOCSETN:
#endif
#if COMPAT_43_TTY || defined(COMPAT_SUNOS)
		case TIOCSETC:
		case TIOCSLTC:
		case TIOCLBIS:
		case TIOCLBIC:
		case TIOCLSET:
#endif
			pti->pt_send |= TIOCPKT_IOCTL;
			ptcwakeup(tp, FREAD);
		default:
			break;
		}
	}
	stop = (tp->t_iflag & IXON) && CCEQ(cc[VSTOP], CTRL('s'))
		&& CCEQ(cc[VSTART], CTRL('q'));
	if (pti->pt_flags & PF_NOSTOP) {
		if (stop) {
			pti->pt_send &= ~TIOCPKT_NOSTOP;
			pti->pt_send |= TIOCPKT_DOSTOP;
			pti->pt_flags &= ~PF_NOSTOP;
			ptcwakeup(tp, FREAD);
		}
	} else {
		if (!stop) {
			pti->pt_send &= ~TIOCPKT_DOSTOP;
			pti->pt_send |= TIOCPKT_NOSTOP;
			pti->pt_flags |= PF_NOSTOP;
			ptcwakeup(tp, FREAD);
		}
	}
out:
	(void) thread_funnel_set(kernel_flock, funnel_state);
	return (error);
}

#ifndef NeXT
static ptc_devsw_installed = 0;

static void
ptc_drvinit(void *unused)
{
#ifdef DEVFS
	int i,j,k;
#endif
	dev_t dev;

	if( ! ptc_devsw_installed ) {
		dev = makedev(CDEV_MAJOR_S, 0);
		cdevsw_add(&dev, &pts_cdevsw, NULL);
		dev = makedev(CDEV_MAJOR_C, 0);
		cdevsw_add(&dev, &ptc_cdevsw, NULL);
		ptc_devsw_installed = 1;
#ifdef DEVFS
		for ( i = 0 ; i<NPTY ; i++ ) {
			j = i / 32;
			k = i % 32;
			devfs_token_pts[i] = 
				devfs_add_devswf(&pts_cdevsw,i,
						DV_CHR,0,0,0666,
						"tty%c%n",jnames[j],k);
			devfs_token_ptc[i] =
				devfs_add_devswf(&ptc_cdevsw,i,
						DV_CHR,0,0,0666,
						"pty%c%n",jnames[j],k);
		}
#endif
    	}
}

SYSINIT(ptcdev,SI_SUB_DRIVERS,SI_ORDER_MIDDLE+CDEV_MAJOR_C,ptc_drvinit,NULL)
#endif /* !NeXT */
