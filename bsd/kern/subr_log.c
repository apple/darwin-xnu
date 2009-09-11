/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
#include <sys/signalvar.h>
#include <sys/conf.h>
#include <sys/sysctl.h>
#include <kern/kalloc.h>

/* XXX should be in a common header somewhere */
extern void klogwakeup(void);
extern void logwakeup(void);

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
char smsg_bufc[MSG_BSIZE]; /* static buffer */
struct msgbuf temp_msgbuf = {0,MSG_BSIZE,0,0,smsg_bufc};
struct msgbuf *msgbufp;
static int _logentrypend = 0;
static int log_inited = 0;
/* the following are implemented in osfmk/kern/printf.c  */
extern void bsd_log_lock(void);
extern void bsd_log_unlock(void);
extern void bsd_log_init(void);

/* XXX wants a linker set so these can be static */
extern d_open_t         logopen;
extern d_close_t        logclose;
extern d_read_t         logread;
extern d_ioctl_t        logioctl;
extern d_select_t       logselect;

/*
 * Serialize log access.  Note that the log can be written at interrupt level,
 * so any log manipulations that can be done from, or affect, another processor
 * at interrupt level must be guarded with a spin lock.
 */

#define	LOG_LOCK() bsd_log_lock()
#define	LOG_UNLOCK() bsd_log_unlock()


/*ARGSUSED*/
int
logopen(__unused dev_t dev, __unused int flags, __unused int mode, struct proc *p)
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
logclose(__unused dev_t dev, __unused int flag, __unused int devtype, __unused struct proc *p)
{
	LOG_LOCK();
	log_open = 0;
	selwakeup(&logsoftc.sc_selp);
	selthreadclear(&logsoftc.sc_selp);
	LOG_UNLOCK();
	return (0);
}

/*ARGSUSED*/
int
logread(__unused dev_t dev, struct uio *uio, int flag)
{
	register long l;
	int error = 0;

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
		if ((error = tsleep((caddr_t)msgbufp, LOG_RDPRI | PCATCH,
				"klog", 5 * hz)) != 0) {
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
			l = msgbufp->msg_size - msgbufp->msg_bufr;
		l = min(l, uio_resid(uio));
		if (l == 0)
			break;
		LOG_UNLOCK();
		error = uiomove((caddr_t)&msgbufp->msg_bufc[msgbufp->msg_bufr],
			(int)l, uio);
		LOG_LOCK();
		if (error)
			break;
		msgbufp->msg_bufr += l;
		if (msgbufp->msg_bufr < 0 || msgbufp->msg_bufr >= msgbufp->msg_size)
			msgbufp->msg_bufr = 0;
	}
out:
	LOG_UNLOCK();
	return (error);
}

/*ARGSUSED*/
int
logselect(__unused dev_t dev, int rw, void * wql, struct proc *p)
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
logwakeup(void)
{
	int pgid;

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
		else 
			proc_signal(pgid, SIGIO);
		LOG_LOCK();
	}
	if (logsoftc.sc_state & LOG_RDWAIT) {
		wakeup((caddr_t)msgbufp);
		logsoftc.sc_state &= ~LOG_RDWAIT;
	}
	LOG_UNLOCK();
}

void
klogwakeup(void)
{
	if (_logentrypend) {
		_logentrypend = 0;
		logwakeup();
	}
}

/*ARGSUSED*/
int
logioctl(__unused dev_t dev, u_long com, caddr_t data, __unused int flag, __unused struct proc *p)
{
	long l;

	LOG_LOCK();
	switch (com) {

	/* return number of characters immediately available */
	case FIONREAD:
		l = msgbufp->msg_bufx - msgbufp->msg_bufr;
		if (l < 0)
			l += msgbufp->msg_size;
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
bsd_log_init(void)
{
	if (!log_inited) { 
		msgbufp = &temp_msgbuf;
		log_inited = 1;
	}
}


/*
 * log_putc_locked
 *
 * Decription:	Output a character to the log; assumes the LOG_LOCK() is held
 *		by the caller.
 *
 * Parameters:	c				Character to output
 *
 * Returns:	(void)
 *
 * Notes:	This functions is used for multibyte output to the log; it
 *		should be used preferrentially where possible to ensure that
 *		log entries do not end up interspersed due to preemption or
 *		SMP reentrancy.
 */
void
log_putc_locked(char c)
{
	register struct msgbuf *mbp;

	if (!log_inited) {
		panic("bsd log is not inited");
	}

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
	if (mbp->msg_bufx < 0 || mbp->msg_bufx >= msgbufp->msg_size)
		mbp->msg_bufx = 0;
}


/*
 * log_putc
 *
 * Decription:	Output a character to the log; assumes the LOG_LOCK() is NOT
 *		held by the caller.
 *
 * Parameters:	c				Character to output
 *
 * Returns:	(void)
 *
 * Notes:	This function is used for syingle byte output to the log.  It
 *		primarily exists to maintain binary backward compatibility.
 */
void
log_putc(char c)
{
	if (!log_inited) {
		panic("bsd log is not inited");
	}
	LOG_LOCK();
	log_putc_locked(c);
	LOG_UNLOCK();
}


/*
 * it is possible to increase the kernel log buffer size by adding
 *   msgbuf=n
 * to the kernel command line, and to read the current size using
 *   sysctl kern.msgbuf
 * If there is no parameter on the kernel command line, the buffer is
 * allocated statically and is MSG_BSIZE characters in size, otherwise
 * memory is dynamically allocated.
 * This function may only be called once, during kernel initialization.
 * Memory management must already be up. The buffer must not have
 * overflown yet.
 */
void
log_setsize(long size) {
	char *new_logdata;
	if (msgbufp->msg_size!=MSG_BSIZE) {
		printf("log_setsize: attempt to change size more than once\n");
		return;
	}
	if (size==MSG_BSIZE)
		return;
	if (size<MSG_BSIZE) { /* we don't support reducing the log size */
		printf("log_setsize: can't decrease log size\n");
		return;
	}
	if (!(new_logdata = (char*)kalloc(size))) {
		printf("log_setsize: unable to allocate memory\n");
		return;
	}
	LOG_LOCK();
	bcopy(smsg_bufc, new_logdata, MSG_BSIZE);
	bzero(new_logdata+MSG_BSIZE, size - MSG_BSIZE);
	/* this memory is now dead - clear it so that it compresses better
	   in case of suspend to disk etc. */
	bzero(smsg_bufc, MSG_BSIZE);
	msgbufp->msg_size = size;
	msgbufp->msg_bufc = new_logdata;
	LOG_UNLOCK();
	printf("set system log size to %ld bytes\n", msgbufp->msg_size);
}

SYSCTL_LONG(_kern, OID_AUTO, msgbuf, CTLFLAG_RD, &temp_msgbuf.msg_size, "");

/*
 * This should be called by single user mode /sbin/dmesg only.
 * It returns as much data still in the buffer as possible.
 */
int
log_dmesg(user_addr_t buffer, uint32_t buffersize, int32_t * retval) {
	uint32_t i;
	uint32_t localbuff_size = (msgbufp->msg_size + 2);
	int error = 0, newl, skip;
	char *localbuff, *p, *copystart, ch;
	long copysize;	

	if (!(localbuff = (char *)kalloc(localbuff_size))) {
		printf("log_dmesg: unable to allocate memory\n");
		return (ENOMEM);
	}
	/* in between here, the log could become bigger, but that's fine */
	LOG_LOCK();

	/*
	 * The message buffer is circular; start at the write pointer, and
	 * make one loop up to write pointer - 1.
	 */
	p = msgbufp->msg_bufc + msgbufp->msg_bufx;
	for (i = newl = skip = 0; p != msgbufp->msg_bufc + msgbufp->msg_bufx - 1; ++p) {
		if (p >= msgbufp->msg_bufc + msgbufp->msg_size)
			p = msgbufp->msg_bufc;
		ch = *p;
		/* Skip "\n<.*>" syslog sequences. */
		if (skip) {
			if (ch == '>')
				newl = skip = 0;
			continue;
		}
		if (newl && ch == '<') {
			skip = 1;
			continue;
		}
		if (ch == '\0')
			continue;
		newl = ch == '\n';
		localbuff[i++] = ch;
		/* The original version of this routine contained a buffer
		 * overflow. At the time, a "small" targeted fix was desired
		 * so the change below to check the buffer bounds was made.
		 * TODO: rewrite this needlessly convoluted routine.
		 */
		if (i == (localbuff_size - 2))
			break;
	}
	if (!newl)
		localbuff[i++] = '\n';
	localbuff[i++] = 0;

	if (buffersize >= i) {
		copystart = localbuff;
		copysize = i;
	} else {
		copystart = localbuff + i - buffersize;
		copysize = buffersize;
	}

	LOG_UNLOCK();

	error = copyout(copystart, buffer, copysize);
	if (!error)
		*retval = copysize;

	kfree(localbuff, localbuff_size);
	return (error);
}
