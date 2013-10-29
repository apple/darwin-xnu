/*
 * Copyright (c) 1997-2006 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
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
#include <sys/uio_internal.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/user.h>
#include <sys/signalvar.h>

#define d_devtotty_t    struct tty **

#ifdef d_stop_t
#undef d_stop_t
#endif
typedef void d_stop_t(struct tty *tp, int rw);

/* XXX function should be removed??? */
int pty_init(int n_ptys);

/* XXX should be a devfs function */
int _devfs_setattr(void * handle, unsigned short mode, uid_t uid, gid_t gid);

static void ptsstart(struct tty *tp);
static void ptcwakeup(struct tty *tp, int flag);

__XNU_PRIVATE_EXTERN	d_open_t	ptsopen;
__XNU_PRIVATE_EXTERN	d_close_t	ptsclose;
__XNU_PRIVATE_EXTERN	d_read_t	ptsread;
__XNU_PRIVATE_EXTERN	d_write_t	ptswrite;
__XNU_PRIVATE_EXTERN	d_ioctl_t	ptyioctl;
__XNU_PRIVATE_EXTERN	d_stop_t	ptsstop;
__XNU_PRIVATE_EXTERN	d_devtotty_t	ptydevtotty;
__XNU_PRIVATE_EXTERN	d_open_t	ptcopen;
__XNU_PRIVATE_EXTERN	d_close_t	ptcclose;
__XNU_PRIVATE_EXTERN	d_read_t	ptcread;
__XNU_PRIVATE_EXTERN	d_write_t	ptcwrite;
__XNU_PRIVATE_EXTERN	d_select_t	ptcselect;

#if NPTY == 1
#undef NPTY
#define	NPTY	32		/* crude XXX */
#warning	You have only one pty defined, redefining to 32.
#endif

#define BUFSIZ 100		/* Chunk size iomoved to/from user */

/*
 * pts == /dev/tty[pqrsPQRS][0123456789abcdefghijklmnopqrstuv]
 * ptc == /dev/pty[pqrsPQRS][0123456789abcdefghijklmnopqrstuv]
 */
/* All references to have been changed to indirections in the file */
__private_extern__ struct	tty *pt_tty[NPTY] = { NULL };

static struct	pt_ioctl {
	int	pt_flags;
	struct	selinfo pt_selr, pt_selw;
	u_char	pt_send;
	u_char	pt_ucntl;
	void	*pt_devhandle;	/* slave device handle for grantpt() */
} pt_ioctl[NPTY];		/* XXX */
static int	npty = NPTY;		/* for pstat -t */

#define	PF_PKT		0x08		/* packet mode */
#define	PF_STOPPED	0x10		/* user told stopped */
#define	PF_REMOTE	0x20		/* remote and flow controlled input */
#define	PF_NOSTOP	0x40
#define PF_UCNTL	0x80		/* user control mode */

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
	    pt_ioctl[m].pt_devhandle = devfs_make_node(makedev(4, m), 
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

__private_extern__ int
ptsopen(dev_t dev, int flag, __unused int devtype, __unused struct proc *p)
{
	struct tty *tp;
	int error;

	/*
	 * You will see this sort of code coming up in diffs later both
	 * the ttymalloc and the tp indirection.
	 */
	if (minor(dev) >= npty) {
	        error = ENXIO;
		goto err;
	}
	if (!pt_tty[minor(dev)]) {
		/*
		 * If we can't allocate a new one, act as if we had run out
		 * of device nodes.
		 */
		if ((tp = pt_tty[minor(dev)] = ttymalloc()) == NULL) {
			error = ENXIO;
			goto err;
		}
	} else
		tp = pt_tty[minor(dev)];

	tty_lock(tp);

	if ((tp->t_state & TS_ISOPEN) == 0) {
		termioschars(&tp->t_termios);	/* Set up default chars */
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
	tty_unlock(tp);
err:
	return (error);
}

__private_extern__ int
ptsclose(dev_t dev, int flag, __unused int mode, __unused proc_t p)
{
	struct tty *tp;
	int err;

	/*
	 * This is temporary until the VSX conformance tests
	 * are fixed.  They are hanging with a deadlock
	 * where close(pts) will not complete without t_timeout set
	 */
#define	FIX_VSX_HANG	1
#ifdef	FIX_VSX_HANG
	int save_timeout;
#endif

	tp = pt_tty[minor(dev)];
	tty_lock(tp);
#ifdef	FIX_VSX_HANG
	save_timeout = tp->t_timeout;
	tp->t_timeout = 60;
#endif
	err = (*linesw[tp->t_line].l_close)(tp, flag);
	ptsstop(tp, FREAD|FWRITE);
	(void) ttyclose(tp);
#ifdef	FIX_VSX_HANG
	tp->t_timeout = save_timeout;
#endif
	tty_unlock(tp);
	return (err);
}

__private_extern__ int
ptsread(dev_t dev, struct uio *uio, int flag)
{
	struct proc *p = current_proc();
	struct tty *tp = pt_tty[minor(dev)];
	struct pt_ioctl *pti = &pt_ioctl[minor(dev)];
	int error = 0;
	struct uthread *ut;
	struct pgrp *pg;

	tty_lock(tp);

	ut = (struct uthread *)get_bsdthread_info(current_thread());
again:
	if (pti->pt_flags & PF_REMOTE) {
		while (isbackground(p, tp)) {
			if ((p->p_sigignore & sigmask(SIGTTIN)) ||
			    (ut->uu_sigmask & sigmask(SIGTTIN)) ||
			    p->p_lflag & P_LPPWAIT) {
				error = EIO;
				goto out;
			}


			pg = proc_pgrp(p);
			if (pg == PGRP_NULL) {
				error = EIO;
				goto out;
			}
			/*
			 * SAFE: We about to drop the lock ourselves by
			 * SAFE: erroring out or sleeping anyway.
			 */
			tty_unlock(tp);
			if (pg->pg_jobc == 0) {
				pg_rele(pg);
				tty_lock(tp);
				error = EIO;
				goto out;
			}
			pgsignal(pg, SIGTTIN, 1);
			pg_rele(pg);
			tty_lock(tp);

			error = ttysleep(tp, &ptsread, TTIPRI | PCATCH | PTTYBLOCK, "ptsbg",
					 hz);
			if (error)
			        goto out;
		}
		if (tp->t_canq.c_cc == 0) {
			if (flag & IO_NDELAY) {
				error = EWOULDBLOCK;
				goto out;
			}
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
			cc = q_to_b(&tp->t_canq, (u_char *)buf, cc);
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
	tty_unlock(tp);
	return (error);
}

/*
 * Write to pseudo-tty.
 * Wakeups of controlling tty will happen
 * indirectly, when tty driver calls ptsstart.
 */
__private_extern__ int
ptswrite(dev_t dev, struct uio *uio, int flag)
{
	struct tty *tp;
	int error;

	tp = pt_tty[minor(dev)];

	tty_lock(tp);

	if (tp->t_oproc == 0)
		error = EIO;
	else
	        error = (*linesw[tp->t_line].l_write)(tp, uio, flag);

	tty_unlock(tp);

	return (error);
}

/*
 * Start output on pseudo-tty.
 * Wake up process selecting or sleeping for input from controlling tty.
 *
 * t_oproc for this driver; called from within the line discipline
 *
 * Locks:	Assumes tp is locked on entry, remains locked on exit
 */
static void
ptsstart(struct tty *tp)
{
	struct pt_ioctl *pti = &pt_ioctl[minor(tp->t_dev)];

	if (tp->t_state & TS_TTSTOP)
	        goto out;
	if (pti->pt_flags & PF_STOPPED) {
		pti->pt_flags &= ~PF_STOPPED;
		pti->pt_send = TIOCPKT_START;
	}
	ptcwakeup(tp, FREAD);
out:
	return;
}

/*
 * Locks:	Assumes tty_lock() is held over this call.
 */
static void
ptcwakeup(struct tty *tp, int flag)
{
	struct pt_ioctl *pti = &pt_ioctl[minor(tp->t_dev)];

	if (flag & FREAD) {
		selwakeup(&pti->pt_selr);
		wakeup(TSA_PTC_READ(tp));
	}
	if (flag & FWRITE) {
		selwakeup(&pti->pt_selw);
		wakeup(TSA_PTC_WRITE(tp));
	}
}

__private_extern__ int
ptcopen(dev_t dev, __unused int flag, __unused int devtype, __unused proc_t p)
{
	struct tty *tp;
	struct pt_ioctl *pti;
	int error = 0;

	if (minor(dev) >= npty) {
		error = ENXIO;
		goto out;
	}
	if(!pt_tty[minor(dev)]) {
		tp = pt_tty[minor(dev)] = ttymalloc();
	} else
		tp = pt_tty[minor(dev)];

	tty_lock(tp);

	/* If master is open OR slave is still draining, pty is still busy */
	if (tp->t_oproc || (tp->t_state & TS_ISOPEN)) {
		error = EBUSY;
	} else {
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
	}

	tty_unlock(tp);

out:
	return (error);
}

__private_extern__ int
ptcclose(dev_t dev, __unused int flags, __unused int fmt, __unused proc_t p)
{
	struct tty *tp = pt_tty[minor(dev)];

	tty_lock(tp);

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

	tty_unlock(tp);

	return (0);
}

__private_extern__ int
ptcread(dev_t dev, struct uio *uio, int flag)
{
	struct tty *tp = pt_tty[minor(dev)];
	struct pt_ioctl *pti = &pt_ioctl[minor(dev)];
	char buf[BUFSIZ];
	int error = 0, cc;

	tty_lock(tp);

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
		error = ttysleep(tp, TSA_PTC_READ(tp), TTIPRI | PCATCH, "ptcin", 0);
		if (error)
		        goto out;
	}
	if (pti->pt_flags & (PF_PKT|PF_UCNTL))
		error = ureadc(0, uio);
	while (uio_resid(uio) > 0 && error == 0) {
		cc = q_to_b(&tp->t_outq, (u_char *)buf, min(uio_resid(uio), BUFSIZ));
		if (cc <= 0)
			break;
		error = uiomove(buf, cc, uio);
	}
	(*linesw[tp->t_line].l_start)(tp);

out:
	tty_unlock(tp);

	return (error);
}

/*
 * Line discipline callback
 *
 * Locks:	tty_lock() is assumed held on entry and exit.
 */
__private_extern__ void
ptsstop(struct tty *tp, int flush)
{
	struct pt_ioctl *pti;
	int flag;

	pti = &pt_ioctl[minor(tp->t_dev)];

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
}

__private_extern__ int
ptcselect(dev_t dev, int rw, void *wql, struct proc *p)
{
	struct tty *tp = pt_tty[minor(dev)];
	struct pt_ioctl *pti = &pt_ioctl[minor(dev)];
	int retval = 0;

	tty_lock(tp);

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
			    if (tp->t_canq.c_cc == 0 && (tp->t_lflag&ICANON)) {
				    retval = 1;
				    goto out;
			    }
			}
		}
		selrecord(p, &pti->pt_selw, wql);
		break;

	}
out:
	tty_unlock(tp);

	return (retval);
}

__private_extern__ int
ptcwrite(dev_t dev, struct uio *uio, int flag)
{
	struct tty *tp = pt_tty[minor(dev)];
	u_char *cp = NULL;
	int cc = 0;
	u_char locbuf[BUFSIZ];
	int wcnt = 0;
	struct pt_ioctl *pti = &pt_ioctl[minor(dev)];
	int error = 0;

	tty_lock(tp);

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
				cc = b_to_q((u_char *)cp, cc, &tp->t_canq);
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
			   (tp->t_canq.c_cc > 0 || !(tp->t_lflag&ICANON))) {
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
	tty_unlock(tp);

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
	error = ttysleep(tp, TSA_PTC_WRITE(tp), TTOPRI | PCATCH, "ptcout", 0);
	if (error) {
		/* adjust for data copied in but not written */
		uio_setresid(uio, (uio_resid(uio) + cc));
		goto out;
	}
	goto again;
}

__private_extern__ int
ptyioctl(dev_t dev, u_long cmd, caddr_t data, int flag, struct proc *p)
{
	struct tty *tp = pt_tty[minor(dev)];
	struct pt_ioctl *pti = &pt_ioctl[minor(dev)];
	u_char *cc = tp->t_cc;
	int stop, error = 0;

	tty_lock(tp);

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
	if (cdevsw[major(dev)].d_open == ptcopen)
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

		case TIOCSETP:
		case TIOCSETN:
		case TIOCSETD:
		case TIOCSETA_32:
		case TIOCSETAW_32:
		case TIOCSETAF_32:
		case TIOCSETA_64:
		case TIOCSETAW_64:
		case TIOCSETAF_64:
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
			if ((*(unsigned int *)data == SIGINFO) &&
			    ((tp->t_lflag&NOKERNINFO) == 0))
				ttyinfo_locked(tp);
			/*
			 * SAFE: All callers drop the lock on return and
			 * SAFE: the linesw[] will short circut this call
			 * SAFE: if the ioctl() is eaten before the lower
			 * SAFE: level code gets to see it.
			 */
			tty_unlock(tp);
			tty_pgsignal(tp, *(unsigned int *)data, 1);
			tty_lock(tp);
			goto out;

		case TIOCPTYGRANT:	/* grantpt(3) */
			/*
			 * Change the uid of the slave to that of the calling
			 * thread, change the gid of the slave to GID_TTY,
			 * change the mode to 0620 (rw--w----).
			 */
			{
				_devfs_setattr(pti->pt_devhandle, 0620, kauth_getuid(), GID_TTY);
				goto out;
			}

		case TIOCPTYGNAME:	/* ptsname(3) */
			/*
			 * Report the name of the slave device in *data
			 * (128 bytes max.).  Use the same derivation method
			 * used for calling devfs_make_node() to create it.
			 */
			snprintf(data, 128, "/dev/tty%c%x",
				START_CHAR + (minor(dev) / HEX_BASE),
				minor(dev) % HEX_BASE);
			error = 0;
			goto out;
		
		case TIOCPTYUNLK:	/* unlockpt(3) */
			/*
			 * Unlock the slave device so that it can be opened.
			 */
			error = 0;
			goto out;
		}
	error = (*linesw[tp->t_line].l_ioctl)(tp, cmd, data, flag, p);
	if (error == ENOTTY) {
		error = ttioctl_locked(tp, cmd, data, flag, p);
		if (error == ENOTTY) {
			if (pti->pt_flags & PF_UCNTL && (cmd & ~0xff) == UIOCCMD(0)) {
				/* Process the UIOCMD ioctl group */
				if (cmd & 0xff) {
					pti->pt_ucntl = (u_char)cmd;
					ptcwakeup(tp, FREAD);
				}
				error = 0;
				goto out;
			} else if (cmd == TIOCSBRK || cmd == TIOCCBRK) {
				/*
				 * POSIX conformance; rdar://3936338
				 *
				 * Clear ENOTTY in the case of setting or
				 * clearing a break failing because pty's
				 * don't support break like real serial
				 * ports.
				 */
				error = 0;
				goto out;
			}
		}
	}

	/*
	 * If external processing and packet mode send ioctl packet.
	 */
	if ((tp->t_lflag&EXTPROC) && (pti->pt_flags & PF_PKT)) {
		switch(cmd) {
		case TIOCSETA_32:
		case TIOCSETAW_32:
		case TIOCSETAF_32:
		case TIOCSETA_64:
		case TIOCSETAW_64:
		case TIOCSETAF_64:
		case TIOCSETP:
		case TIOCSETN:
		case TIOCSETC:
		case TIOCSLTC:
		case TIOCLBIS:
		case TIOCLBIC:
		case TIOCLSET:
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
	tty_unlock(tp);

	return (error);
}
