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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
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
 *	@(#)subr_log.c	8.3 (Berkeley) 2/14/95
 */

/*
 * Error log buffer for kernel printf's.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/ioctl.h>
#include <sys/msgbuf.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/select.h>
#include <kern/thread.h>

#define LOG_RDPRI	(PZERO + 1)

#define LOG_NBIO	0x02
#define LOG_ASYNC	0x04
#define LOG_RDWAIT	0x08

struct logsoftc {
	int	sc_state;		/* see above for possibilities */
	struct	selinfo sc_selp;	/* thread waiting for select */
	int	sc_pgid;		/* process/group for async I/O */
} logsoftc;

int	log_open;			/* also used in log() */
struct msgbuf temp_msgbuf;
struct msgbuf *msgbufp;
static int _logentrypend = 0;

/*
 * Serialize log access.  Note that the log can be written at interrupt level,
 * so any log manipulations that can be done from, or affect, another processor
 * at interrupt level must be guarded with a spin lock.
 */
decl_simple_lock_data(,log_lock);	/* stop races dead in their tracks */
#define	LOG_LOCK()	simple_lock(&log_lock)
#define	LOG_UNLOCK()	simple_unlock(&log_lock)
#define	LOG_LOCK_INIT()	simple_lock_init(&log_lock)

/*ARGSUSED*/
logopen(dev, flags, mode, p)
	dev_t dev;
	int flags, mode;
	struct proc *p;
{
	LOG_LOCK();
	if (log_open) {
		LOG_UNLOCK();
		return (EBUSY);
	}
	log_open = 1;
	logsoftc.sc_pgid = p->p_pid;		/* signal process only */
	/*
	 * Potential race here with putchar() but since putchar should be
	 * called by autoconf, msg_magic should be initialized by the time
	 * we get here.
	 */
	if (msgbufp->msg_magic != MSG_MAGIC) {
		register int i;

		msgbufp->msg_magic = MSG_MAGIC;
		msgbufp->msg_bufx = msgbufp->msg_bufr = 0;
		for (i=0; i < MSG_BSIZE; i++)
			msgbufp->msg_bufc[i] = 0;
	}
	LOG_UNLOCK();

	return (0);
}

/*ARGSUSED*/
int
logclose(dev, flag)
	dev_t dev;
{
	int oldpri;
	LOG_LOCK();
	log_open = 0;
	selwakeup(&logsoftc.sc_selp);
	oldpri = splhigh();
	selthreadclear(&logsoftc.sc_selp);
	splx(oldpri);
	LOG_UNLOCK();
	return (0);
}

/*ARGSUSED*/
int
logread(dev, uio, flag)
	dev_t dev;
	struct uio *uio;
	int flag;
{
	register long l;
	register int s;
	int error = 0;

	s = splhigh();
	while (msgbufp->msg_bufr == msgbufp->msg_bufx) {
		if (flag & IO_NDELAY) {
			splx(s);
			return (EWOULDBLOCK);
		}
		if (logsoftc.sc_state & LOG_NBIO) {
			splx(s);
			return (EWOULDBLOCK);
		}
		logsoftc.sc_state |= LOG_RDWAIT;
		if (error = tsleep((caddr_t)msgbufp, LOG_RDPRI | PCATCH,
				"klog", 0)) {
			splx(s);
			return (error);
		}
	}
	splx(s);
	logsoftc.sc_state &= ~LOG_RDWAIT;

	while (uio->uio_resid > 0) {
		l = msgbufp->msg_bufx - msgbufp->msg_bufr;
		if (l < 0)
			l = MSG_BSIZE - msgbufp->msg_bufr;
		l = min(l, uio->uio_resid);
		if (l == 0)
			break;
		error = uiomove((caddr_t)&msgbufp->msg_bufc[msgbufp->msg_bufr],
			(int)l, uio);
		if (error)
			break;
		msgbufp->msg_bufr += l;
		if (msgbufp->msg_bufr < 0 || msgbufp->msg_bufr >= MSG_BSIZE)
			msgbufp->msg_bufr = 0;
	}
	return (error);
}

/*ARGSUSED*/
int
logselect(dev, rw, wql, p)
	dev_t dev;
	int rw;
	void * wql;
	struct proc *p;
{
	int s = splhigh();

	switch (rw) {

	case FREAD:
		if (msgbufp->msg_bufr != msgbufp->msg_bufx) {
			splx(s);
			return (1);
		}
		selrecord(p, &logsoftc.sc_selp, wql);
		break;
	}
	splx(s);
	return (0);
}

void
logwakeup()
{
	struct proc *p;
	int pgid;
	boolean_t funnel_state;

	if (!log_open)
		return;
	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	selwakeup(&logsoftc.sc_selp);
	if (logsoftc.sc_state & LOG_ASYNC) {
		LOG_LOCK();
		pgid = logsoftc.sc_pgid;
		LOG_UNLOCK();
		if (pgid < 0)
			gsignal(-pgid, SIGIO); 
		else if (p = pfind(pgid))
			psignal(p, SIGIO);
	}
	if (logsoftc.sc_state & LOG_RDWAIT) {
		wakeup((caddr_t)msgbufp);
		logsoftc.sc_state &= ~LOG_RDWAIT;
	}
	(void) thread_funnel_set(kernel_flock, funnel_state);
}

void
klogwakeup()
{

	if (_logentrypend) {
		_logentrypend = 0;
		logwakeup();
	}
}

/*ARGSUSED*/
int
logioctl(com, data, flag)
	caddr_t data;
{
	long l;
	int s;

	switch (com) {

	/* return number of characters immediately available */
	case FIONREAD:
		s = splhigh();
		l = msgbufp->msg_bufx - msgbufp->msg_bufr;
		splx(s);
		if (l < 0)
			l += MSG_BSIZE;
		*(off_t *)data = l;
		break;

	case FIONBIO:
		if (*(int *)data)
			logsoftc.sc_state |= LOG_NBIO;
		else
			logsoftc.sc_state &= ~LOG_NBIO;
		break;

	case FIOASYNC:
		if (*(int *)data)
			logsoftc.sc_state |= LOG_ASYNC;
		else
			logsoftc.sc_state &= ~LOG_ASYNC;
		break;

	case TIOCSPGRP:
		LOG_LOCK();
		logsoftc.sc_pgid = *(int *)data;
		LOG_UNLOCK();
		break;

	case TIOCGPGRP:
		LOG_LOCK();
		*(int *)data = logsoftc.sc_pgid;
		LOG_UNLOCK();
		break;

	default:
		return (-1);
	}
	return (0);
}

void
log_init()
{
	msgbufp = &temp_msgbuf;
	LOG_LOCK_INIT();
}

void
log_putc(char c)
{
	register struct msgbuf *mbp;

	if (msgbufp == NULL)
		msgbufp =&temp_msgbuf;

	mbp = msgbufp; 
	if (mbp-> msg_magic != MSG_MAGIC) { 
		register int i;

		mbp->msg_magic = MSG_MAGIC;
		mbp->msg_bufx = mbp->msg_bufr = 0;
		for (i=0; i < MSG_BSIZE; i++)
			mbp->msg_bufc[i] = 0;
	}
	mbp->msg_bufc[mbp->msg_bufx++] = c;
	_logentrypend = 1;
	if (mbp->msg_bufx < 0 || mbp->msg_bufx >= MSG_BSIZE)
		mbp->msg_bufx = 0;
}
