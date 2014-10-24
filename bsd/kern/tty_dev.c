/*
 * Copyright (c) 1997-2013 Apple Inc. All rights reserved.
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

/* Common callbacks for the pseudo-teletype driver (pty/tty)
 * and cloning pseudo-teletype driver (ptmx/pts).
 */

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
#include <sys/vnode_internal.h>		/* _devfs_setattr() */
#include <sys/stat.h>			/* _devfs_setattr() */
#include <sys/user.h>
#include <sys/signalvar.h>
#include <sys/sysctl.h>
#include <miscfs/devfs/devfs.h>
#include <miscfs/devfs/devfsdefs.h>	/* DEVFS_LOCK()/DEVFS_UNLOCK() */

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

#include "tty_dev.h"

/* XXX belongs in devfs somewhere - LATER */
static int _devfs_setattr(void *, unsigned short, uid_t, gid_t);

/*
 * Forward declarations
 */
static void ptcwakeup(struct tty *tp, int flag);
__XNU_PRIVATE_EXTERN	d_open_t	ptsopen;
__XNU_PRIVATE_EXTERN	d_close_t	ptsclose;
__XNU_PRIVATE_EXTERN	d_read_t	ptsread;
__XNU_PRIVATE_EXTERN	d_write_t	ptswrite;
__XNU_PRIVATE_EXTERN	d_ioctl_t	ptyioctl;	/* common ioctl */
__XNU_PRIVATE_EXTERN	d_stop_t	ptsstop;
__XNU_PRIVATE_EXTERN	d_reset_t	ptsreset;
__XNU_PRIVATE_EXTERN	d_select_t	ptsselect;
__XNU_PRIVATE_EXTERN	d_open_t	ptcopen;
__XNU_PRIVATE_EXTERN	d_close_t	ptcclose;
__XNU_PRIVATE_EXTERN	d_read_t	ptcread;
__XNU_PRIVATE_EXTERN	d_write_t	ptcwrite;
__XNU_PRIVATE_EXTERN	d_stop_t	ptcstop;	/* NO-OP */
__XNU_PRIVATE_EXTERN	d_reset_t	ptcreset;
__XNU_PRIVATE_EXTERN	d_select_t	ptcselect;

/*
 * XXX Should be devfs function... and use VATTR mechanisms, per
 * XXX vnode_setattr2(); only we maybe can't really get back to the
 * XXX vnode here for cloning devices (but it works for *cloned* devices
 * XXX that are not themselves cloning).
 *
 * Returns:	0			Success
 *	namei:???
 *	vnode_setattr:???
 */
static int
_devfs_setattr(void * handle, unsigned short mode, uid_t uid, gid_t gid)
{
	devdirent_t		*direntp = (devdirent_t *)handle;
	devnode_t		*devnodep;
	int			error = EACCES;
	vfs_context_t		ctx = vfs_context_current();;
	struct vnode_attr	va;

	VATTR_INIT(&va);
	VATTR_SET(&va, va_uid, uid);
	VATTR_SET(&va, va_gid, gid);
	VATTR_SET(&va, va_mode, mode & ALLPERMS);

	/*
	 * If the TIOCPTYGRANT loses the race with the clone operation because
	 * this function is not part of devfs, and therefore can't take the
	 * devfs lock to protect the direntp update, then force user space to
	 * redrive the grant request.
	 */
	if (direntp == NULL || (devnodep = direntp->de_dnp) == NULL) {
		error = ERESTART;
		goto out;
	}

	/*
	 * Only do this if we are operating on device that doesn't clone
	 * each time it's referenced.  We perform a lookup on the device
	 * to insure we get the right instance.  We can't just use the call
	 * to devfs_dntovn() to get the vp for the operation, because
	 * dn_dvm may not have been initialized.
	 */
	if (devnodep->dn_clone == NULL) {
		struct nameidata nd;
		char name[128];

		snprintf(name, sizeof(name), "/dev/%s", direntp->de_name);
		NDINIT(&nd, LOOKUP, OP_SETATTR, FOLLOW, UIO_SYSSPACE, CAST_USER_ADDR_T(name), ctx);
		error = namei(&nd);
		if (error)
			goto out;
		error = vnode_setattr(nd.ni_vp, &va, ctx);
		vnode_put(nd.ni_vp);
		nameidone(&nd);
		goto out;
	}

out:
	return(error);
}

#define BUFSIZ 100		/* Chunk size iomoved to/from user */

static struct tty_dev_t *tty_dev_head;

__private_extern__ void
tty_dev_register(struct tty_dev_t *driver)
{
	if (driver) {
		driver->next = tty_dev_head;
		tty_dev_head = driver;
	}
}

/*
 * Given a minor number, return the corresponding structure for that minor
 * number.  If there isn't one, and the create flag is specified, we create
 * one if possible.
 *
 * Parameters:	minor			Minor number of ptmx device
 *		open_flag		PF_OPEN_M	First open of master
 *					PF_OPEN_S	First open of slave
 *					0		Just want ioctl struct
 *
 * Returns:	NULL			Did not exist/could not create
 *		!NULL			structure corresponding minor number
 *
 * Locks:	tty_lock() on ptmx_ioctl->pt_tty NOT held on entry or exit.
 */

static struct tty_dev_t *
pty_get_driver(dev_t dev)
{
	int major = major(dev);
	struct tty_dev_t *driver;
	for (driver = tty_dev_head; driver != NULL; driver = driver->next) {
		if ((driver->master == major || driver->slave == major)) {
			break;
		}
	}
	return driver;
}

static struct ptmx_ioctl *
pty_get_ioctl(dev_t dev, int open_flag, struct tty_dev_t **out_driver)
{
	struct tty_dev_t *driver = pty_get_driver(dev);
	if (out_driver) {
		*out_driver = driver;
	}
	if (driver && driver->open) {
		return driver->open(minor(dev), open_flag);
	}
	return NULL;
}

/*
 * Locks:	tty_lock() of old_ptmx_ioctl->pt_tty NOT held for this call.
 */
static int
pty_free_ioctl(dev_t dev, int open_flag)
{
	struct tty_dev_t *driver = pty_get_driver(dev);
	if (driver && driver->free) {
		return driver->free(minor(dev), open_flag);
	}
	return 0;
}

static int
pty_get_name(dev_t dev, char *buffer, size_t size)
{
	struct tty_dev_t *driver = pty_get_driver(dev);
	if (driver && driver->name) {
		return driver->name(minor(dev), buffer, size);
	}
	return 0;
}

__private_extern__ int
ptsopen(dev_t dev, int flag, __unused int devtype, __unused struct proc *p)
{
	int error;
	struct tty_dev_t *driver;
	struct ptmx_ioctl *pti = pty_get_ioctl(dev, PF_OPEN_S, &driver);
	if (pti == NULL) {
		return ENXIO;
	}
	if (!(pti->pt_flags & PF_UNLOCKED)) {
		return EAGAIN;
	}

	struct tty *tp = pti->pt_tty;
	tty_lock(tp);

	if ((tp->t_state & TS_ISOPEN) == 0) {
		termioschars(&tp->t_termios);	/* Set up default chars */
		tp->t_iflag = TTYDEF_IFLAG;
		tp->t_oflag = TTYDEF_OFLAG;
		tp->t_lflag = TTYDEF_LFLAG;
		tp->t_cflag = TTYDEF_CFLAG;
		tp->t_ispeed = tp->t_ospeed = TTYDEF_SPEED;
		ttsetwater(tp);		/* would be done in xxparam() */
	} else if ((tp->t_state & TS_XCLUDE) && kauth_cred_issuser(kauth_cred_get())) {
	        error = EBUSY;
		goto out;
	}
	if (tp->t_oproc)			/* Ctrlr still around. */
		(void)(*linesw[tp->t_line].l_modem)(tp, 1);
	while ((tp->t_state & TS_CARR_ON) == 0) {
		if (flag&FNONBLOCK)
			break;
		error = ttysleep(tp, TSA_CARR_ON(tp), TTIPRI | PCATCH, __FUNCTION__, 0);
		if (error)
			goto out;
	}
	error = (*linesw[tp->t_line].l_open)(dev, tp);
	/* Successful open; mark as open by the slave */

	pti->pt_flags |= PF_OPEN_S;
	CLR(tp->t_state, TS_IOCTL_NOT_OK);
	if (error == 0)
		ptcwakeup(tp, FREAD|FWRITE);

out:
	tty_unlock(tp);
	return (error);
}

__private_extern__ int
ptsclose(dev_t dev, int flag, __unused int mode, __unused proc_t p)
{
	int err;

	/*
	 * This is temporary until the VSX conformance tests
	 * are fixed.  They are hanging with a deadlock
	 * where close() will not complete without t_timeout set
	 */
#define	FIX_VSX_HANG	1
#ifdef	FIX_VSX_HANG
	int save_timeout;
#endif
	struct tty_dev_t *driver;
	struct ptmx_ioctl *pti = pty_get_ioctl(dev, 0, &driver);
	struct tty *tp;
	
	if (pti == NULL)
		return (ENXIO);

	tp = pti->pt_tty;
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

	if ((flag & IO_REVOKE) == IO_REVOKE && driver->revoke) {
		driver->revoke(minor(dev), tp);
	}
	/* unconditional, just like ttyclose() */
	pty_free_ioctl(dev, PF_OPEN_S);

	return (err);
}

__private_extern__ int
ptsread(dev_t dev, struct uio *uio, int flag)
{
	proc_t p = current_proc();
	struct ptmx_ioctl *pti = pty_get_ioctl(dev, 0, NULL);
	struct tty *tp;
	int error = 0;
	struct uthread *ut;
	struct pgrp *pg;

	if (pti == NULL)
		return (ENXIO);
	tp = pti->pt_tty;
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

			error = ttysleep(tp, &ptsread, TTIPRI | PCATCH | PTTYBLOCK, __FUNCTION__, hz);
			if (error)
			        goto out;
		}
		if (tp->t_canq.c_cc == 0) {
			if (flag & IO_NDELAY) {
				error = EWOULDBLOCK;
				goto out;
			}
			error = ttysleep(tp, TSA_PTS_READ(tp), TTIPRI | PCATCH, __FUNCTION__, 0);
			if (error)
			        goto out;
			goto again;
		}
		while (tp->t_canq.c_cc > 1 && uio_resid(uio) > 0) {
			int cc;
			char buf[BUFSIZ];

			cc = MIN((int)uio_resid(uio), BUFSIZ);
			// Don't copy the very last byte
			cc = MIN(cc, tp->t_canq.c_cc - 1);
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
	struct ptmx_ioctl *pti = pty_get_ioctl(dev, 0, NULL);
	struct tty *tp;
	int error;

	if (pti == NULL)
		return (ENXIO);
	tp = pti->pt_tty;
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
	struct ptmx_ioctl *pti = pty_get_ioctl(tp->t_dev, 0, NULL);
	if (pti == NULL)
		goto out;
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
	struct ptmx_ioctl *pti = pty_get_ioctl(tp->t_dev, 0, NULL);
	if (pti == NULL)
		return;

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
	struct tty_dev_t *driver;
	struct ptmx_ioctl *pti = pty_get_ioctl(dev, PF_OPEN_M, &driver);
	if (pti == NULL) {
	        return (ENXIO);
	} else if (pti == (struct ptmx_ioctl*)-1) {
		return (EREDRIVEOPEN);
	}

	struct tty *tp = pti->pt_tty;
	tty_lock(tp);

	/* If master is open OR slave is still draining, pty is still busy */
	if (tp->t_oproc || (tp->t_state & TS_ISOPEN)) {
		tty_unlock(tp);
		/*
		 * If master is closed, we are the only reference, so we
		 * need to clear the master open bit
		 */
		if (!tp->t_oproc) {
			pty_free_ioctl(dev, PF_OPEN_M);
		}
		return EBUSY;
	}
	tp->t_oproc = ptsstart;
	CLR(tp->t_state, TS_ZOMBIE);
	SET(tp->t_state, TS_IOCTL_NOT_OK);
#ifdef sun4c
	tp->t_stop = ptsstop;
#endif
	(void)(*linesw[tp->t_line].l_modem)(tp, 1);
	tp->t_lflag &= ~EXTPROC;

	if (driver->open_reset) {
		pti->pt_flags = PF_UNLOCKED;
		pti->pt_send = 0;
		pti->pt_ucntl = 0;
	}

	tty_unlock(tp);
	return 0;
}

__private_extern__ int
ptcclose(dev_t dev, __unused int flags, __unused int fmt, __unused proc_t p)
{
	struct tty_dev_t *driver;
	struct ptmx_ioctl *pti = pty_get_ioctl(dev, 0, &driver);
	struct tty *tp;

	if (pti == NULL)
		return (ENXIO);
	tp = pti->pt_tty;
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

	pty_free_ioctl(dev, PF_OPEN_M);
#if CONFIG_MACF
	if (driver->mac_notify) {
		mac_pty_notify_close(p, tp, dev, NULL);
	}
#endif

	return (0);
}

__private_extern__ int
ptcread(dev_t dev, struct uio *uio, int flag)
{
	struct ptmx_ioctl *pti = pty_get_ioctl(dev, 0, NULL);
	struct tty *tp;
	char buf[BUFSIZ];
	int error = 0, cc;

	if (pti == NULL)
		return (ENXIO);
	tp = pti->pt_tty;
	tty_lock(tp);

	/*
	 * We want to block until the slave
	 * is open, and there's something to read;
	 * but if we lost the slave or we're NBIO,
	 * then return the appropriate error instead.
	 */
	for (;;) {
		if (tp->t_state & TS_ISOPEN) {
			if (pti->pt_flags & PF_PKT && pti->pt_send) {
				error = ureadc((int)pti->pt_send, uio);
				if (error)
					goto out;
				if (pti->pt_send & TIOCPKT_IOCTL) {
					cc = MIN((int)uio_resid(uio),
						(int)sizeof(tp->t_termios));
					uiomove((caddr_t)&tp->t_termios, cc,
						uio);
				}
				pti->pt_send = 0;
				goto out;
			}
			if (pti->pt_flags & PF_UCNTL && pti->pt_ucntl) {
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
		error = ttysleep(tp, TSA_PTC_READ(tp), TTIPRI | PCATCH, __FUNCTION__, 0);
		if (error)
		        goto out;
	}
	if (pti->pt_flags & (PF_PKT|PF_UCNTL))
		error = ureadc(0, uio);
	while (uio_resid(uio) > 0 && error == 0) {
		cc = q_to_b(&tp->t_outq, (u_char *)buf, MIN((int)uio_resid(uio), BUFSIZ));
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
__private_extern__ int
ptsstop(struct tty* tp, int flush)
{
	struct ptmx_ioctl *pti = pty_get_ioctl(tp->t_dev, 0, NULL);
	int flag;

	if (pti == NULL)
		return (ENXIO);

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
	return 0;
}

__private_extern__ int
ptsreset(__unused int uban)
{
	return (0);
}

int
ptsselect(dev_t dev, int rw, void *wql, proc_t p)
{
	struct ptmx_ioctl *pti = pty_get_ioctl(dev, 0, NULL);
	struct tty *tp;
	int retval = 0;

	if (pti == NULL)
		return (ENXIO);
	tp = pti->pt_tty;
	if (tp == NULL)
		return (ENXIO);

	tty_lock(tp);

	switch (rw) {
	case FREAD:
		if (ISSET(tp->t_state, TS_ZOMBIE)) {
			retval = 1;
			break;
		}

		retval = ttnread(tp);
		if (retval > 0) {
			break;
		}

		selrecord(p, &tp->t_rsel, wql);
		break;
	case FWRITE:
		if (ISSET(tp->t_state, TS_ZOMBIE)) {
			retval = 1;
			break;
		}

		if ((tp->t_outq.c_cc <= tp->t_lowat) &&
				ISSET(tp->t_state, TS_CONNECTED)) {
			retval = tp->t_hiwat - tp->t_outq.c_cc;
			break;
		}

		selrecord(p, &tp->t_wsel, wql);
		break;
	}

	tty_unlock(tp);
	return (retval);
}

__private_extern__ int
ptcselect(dev_t dev, int rw, void *wql, proc_t p)
{
	struct tty_dev_t *driver;
	struct ptmx_ioctl *pti = pty_get_ioctl(dev, 0, &driver);
	struct tty *tp;
	int retval = 0;

	if (pti == NULL)
		return (ENXIO);
	tp = pti->pt_tty;
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
			retval = (driver->fix_7828447) ? tp->t_outq.c_cc : 1;
			break;
		}
		/* FALLTHROUGH */

	case 0:					/* exceptional */
		if ((tp->t_state&TS_ISOPEN) &&
		    ((pti->pt_flags & PF_PKT && pti->pt_send) ||
		     (pti->pt_flags & PF_UCNTL && pti->pt_ucntl))) {
			retval = 1;
			break;
		}
		selrecord(p, &pti->pt_selr, wql);
		break;


	case FWRITE:
		if (tp->t_state&TS_ISOPEN) {
			if (pti->pt_flags & PF_REMOTE) {
			    if (tp->t_canq.c_cc == 0) {
				retval = (driver->fix_7828447) ? (TTYHOG - 1) : 1;
				break;
			    }
			} else {
			    retval = (TTYHOG - 2) - (tp->t_rawq.c_cc + tp->t_canq.c_cc);
			    if (retval > 0) {
				    retval = (driver->fix_7828447) ? retval : 1;
				    break;
			    }
			    if (tp->t_canq.c_cc == 0 && (tp->t_lflag&ICANON)) {
				    retval = 1;
				    break;
			    }
			    retval = 0;
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
ptcstop(__unused struct tty *tp, __unused int flush)
{
	return (0);
}

__private_extern__ int
ptcreset(__unused int uban)
{
	return (0);
}

__private_extern__ int
ptcwrite(dev_t dev, struct uio *uio, int flag)
{
	struct ptmx_ioctl *pti = pty_get_ioctl(dev, 0, NULL);
	struct tty *tp;
	u_char *cp = NULL;
	int cc = 0;
	u_char locbuf[BUFSIZ];
	int wcnt = 0;
	int error = 0;

	if (pti == NULL)
		return (ENXIO);
	tp = pti->pt_tty;
	tty_lock(tp);

again:
	if ((tp->t_state & TS_ISOPEN) == 0)
		goto block;
	if (pti->pt_flags & PF_REMOTE) {
		if (tp->t_canq.c_cc)
			goto block;
		while ((uio_resid(uio) > 0 || cc > 0) &&
		       tp->t_canq.c_cc < TTYHOG - 1) {
			if (cc == 0) {
				cc = MIN((int)uio_resid(uio), BUFSIZ);
				cc = MIN(cc, TTYHOG - 1 - tp->t_canq.c_cc);
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
			cc = MIN((int)uio_resid(uio), BUFSIZ);
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
	error = ttysleep(tp, TSA_PTC_WRITE(tp), TTOPRI | PCATCH, __FUNCTION__, 0);
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
	struct tty_dev_t *driver;
	struct ptmx_ioctl *pti = pty_get_ioctl(dev, 0, &driver);
	struct tty *tp;
	int stop, error = 0;
	int allow_ext_ioctl = 1;

	if (pti == NULL)
		return (ENXIO);
	tp = pti->pt_tty;
	tty_lock(tp);

	u_char *cc = tp->t_cc;

	/*
	 * Do not permit extended ioctls on the master side of the pty unless
	 * the slave side has been successfully opened and initialized.
	 */
	if (major(dev) == driver->master &&
	    driver->fix_7070978 &&
	    ISSET(tp->t_state, TS_IOCTL_NOT_OK)) {
		allow_ext_ioctl = 0;
	}

	/*
	 * IF CONTROLLER STTY THEN MUST FLUSH TO PREVENT A HANG.
	 * ttywflush(tp) will hang if there are characters in the outq.
	 */
	if (cmd == TIOCEXT && allow_ext_ioctl) {
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
	if (cdevsw[major(dev)].d_open == ptcopen) {
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
				error = _devfs_setattr(pti->pt_devhandle, 0620, kauth_getuid(), GID_TTY);
				if (major(dev) == driver->master) {
					if (driver->mac_notify) {
#if CONFIG_MACF
						if (!error) {
							tty_unlock(tp);
							mac_pty_notify_grant(p, tp, dev, NULL);
							tty_lock(tp);
						}
#endif
					} else {
						error = 0;
					}
				}
				goto out;
			}

		case TIOCPTYGNAME:	/* ptsname(3) */
			/*
			 * Report the name of the slave device in *data
			 * (128 bytes max.).  Use the same template string
			 * used for calling devfs_make_node() to create it.
			 */
			pty_get_name(dev, data, 128);
			error = 0;
			goto out;
		
		case TIOCPTYUNLK:	/* unlockpt(3) */
			/*
			 * Unlock the slave device so that it can be opened.
			 */
			if (major(dev) == driver->master) {
				pti->pt_flags |= PF_UNLOCKED;
			}
			error = 0;
			goto out;
		}

		/*
		 * Fail all other calls; pty masters are not serial devices;
		 * we only pretend they are when the slave side of the pty is
		 * already open.
		 */
		if (!allow_ext_ioctl) {
			error = ENOTTY;
			goto out;
		}
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
