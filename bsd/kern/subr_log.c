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
#include <sys/proc_internal.h>
#include <sys/vnode.h>
#include <sys/ioctl.h>
#include <sys/msgbuf.h>
#include <sys/file_internal.h>
#include <sys/errno.h>
#include <sys/select.h>
#include <sys/kernel.h>
#include <kern/thread.h>
#include <sys/lock.h>

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
static int log_inited = 0;
void bsd_log_lock(void);
/* the following two are implemented in osfmk/kern/printf.c  */
extern void bsd_log_unlock(void);
extern void bsd_log_init(void);

/*
 * Serialize log access.  Note that the log can be written at interrupt level,
 * so any log manipulations that can be done from, or affect, another processor
 * at interrupt level must be guarded with a spin lock.
 */

#define	LOG_LOCK() bsd_log_lock()
#define	LOG_UNLOCK() bsd_log_unlock()


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
	selthreadclear(&logsoftc.sc_selp);
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
	char localbuff[MSG_BSIZE];
	int copybytes;

	LOG_LOCK();
	while (msgbufp->msg_bufr == msgbufp->msg_bufx) {
		if (flag & IO_NDELAY) {
			error = EWOULDBLOCK;
			goto out;
		}
		if (logsoftc.sc_state & LOG_NBIO) {
			error = EWOULDBLOCK;
			goto out;
		}
		logsoftc.sc_state |= LOG_RDWAIT;
		LOG_UNLOCK();
		/*
		 * If the wakeup is missed the ligtening bolt will wake this up 
		 * if there are any new characters. If that doesn't do it
		 * then wait for 5 sec and reevaluate 
		 */
		if (error = tsleep((caddr_t)msgbufp, LOG_RDPRI | PCATCH,
				"klog", 5 * hz)) {
			/* if it times out; ignore */
			if (error != EWOULDBLOCK)
				return (error);
		}
		LOG_LOCK();
	}
	logsoftc.sc_state &= ~LOG_RDWAIT;


	while (uio_resid(uio) > 0) {
		l = msgbufp->msg_bufx - msgbufp->msg_bufr;
		if (l < 0)
			l = MSG_BSIZE - msgbufp->msg_bufr;
		l = min(l, uio_resid(uio));
		if (l == 0)
			break;
		bcopy(&msgbufp->msg_bufc[msgbufp->msg_bufr], &localbuff[0], l);
		LOG_UNLOCK();
		error = uiomove((caddr_t)&localbuff[0],
			(int)l, uio);
		LOG_LOCK();
		if (error)
			break;
		msgbufp->msg_bufr += l;
		if (msgbufp->msg_bufr < 0 || msgbufp->msg_bufr >= MSG_BSIZE)
			msgbufp->msg_bufr = 0;
	}
out:
	LOG_UNLOCK();
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

	switch (rw) {

	case FREAD:
		LOG_LOCK();	
		if (msgbufp->msg_bufr != msgbufp->msg_bufx) {
			LOG_UNLOCK();
			return (1);
		}
		selrecord(p, &logsoftc.sc_selp, wql);
		LOG_UNLOCK();
		break;
	}
	return (0);
}

void
logwakeup()
{
	struct proc *p;
	int pgid;
	boolean_t funnel_state;

	LOG_LOCK();	
	if (!log_open) {
		LOG_UNLOCK();
		return;
	}
	selwakeup(&logsoftc.sc_selp);
	if (logsoftc.sc_state & LOG_ASYNC) {
		pgid = logsoftc.sc_pgid;
		LOG_UNLOCK();
		if (pgid < 0)
			gsignal(-pgid, SIGIO); 
		else if (p = pfind(pgid))
			psignal(p, SIGIO);
		LOG_LOCK();
	}
	if (logsoftc.sc_state & LOG_RDWAIT) {
		wakeup((caddr_t)msgbufp);
		logsoftc.sc_state &= ~LOG_RDWAIT;
	}
	LOG_UNLOCK();
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
logioctl(dev, com, data, flag)
	caddr_t data;
{
	long l;
	int s;

	LOG_LOCK();	
	switch (com) {

	/* return number of characters immediately available */
	case FIONREAD:
		l = msgbufp->msg_bufx - msgbufp->msg_bufr;
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
		logsoftc.sc_pgid = *(int *)data;
		break;

	case TIOCGPGRP:
		*(int *)data = logsoftc.sc_pgid;
		break;

	default:
		LOG_UNLOCK();
		return (-1);
	}
	LOG_UNLOCK();
	return (0);
}

void
bsd_log_init()
{
	if (!log_inited) { 
		msgbufp = &temp_msgbuf;
		log_inited = 1;
	}
}

void
log_putc(char c)
{
	register struct msgbuf *mbp;

	if (!log_inited) {
		panic("bsd log is not inited");
	}
	LOG_LOCK();

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
	LOG_UNLOCK();
}

