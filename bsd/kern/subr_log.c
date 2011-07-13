/*
 * Copyright (c) 2000-2010 Apple, Inc. All rights reserved.
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
#include <pexpert/pexpert.h>

/* XXX should be in a common header somewhere */
extern void klogwakeup(void);
extern void logwakeup(void);

#define LOG_RDPRI	(PZERO + 1)

#define LOG_NBIO	0x02
#define LOG_ASYNC	0x04
#define LOG_RDWAIT	0x08

/* All globals should be accessed under LOG_LOCK() */

/* logsoftc only valid while log_open=1 */
struct logsoftc {
	int	sc_state;		/* see above for possibilities */
	struct	selinfo sc_selp;	/* thread waiting for select */
	int	sc_pgid;		/* process/group for async I/O */
} logsoftc;

int	log_open;			/* also used in log() */
char smsg_bufc[CONFIG_MSG_BSIZE]; /* static buffer */
struct msgbuf msgbuf = {MSG_MAGIC,sizeof(smsg_bufc),0,0,smsg_bufc};
struct msgbuf *msgbufp = &msgbuf;
static int logentrypend = 0;

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

#if DEBUG
#define LOG_SETSIZE_DEBUG(x...) kprintf(x)
#else
#define LOG_SETSIZE_DEBUG(x...) do { } while(0)
#endif

static int sysctl_kern_msgbuf(struct sysctl_oid *oidp,
				void *arg1,
				int arg2,
				struct sysctl_req *req);

/*ARGSUSED*/
int
logopen(__unused dev_t dev, __unused int flags, __unused int mode, struct proc *p)
{
	LOG_LOCK();
	if (log_open) {
		LOG_UNLOCK();
		return (EBUSY);
	}
	logsoftc.sc_pgid = p->p_pid;		/* signal process only */
	log_open = 1;

	LOG_UNLOCK();

	return (0);
}

/*ARGSUSED*/
int
logclose(__unused dev_t dev, __unused int flag, __unused int devtype, __unused struct proc *p)
{
	LOG_LOCK();
	selwakeup(&logsoftc.sc_selp);
	selthreadclear(&logsoftc.sc_selp);
	log_open = 0;
	LOG_UNLOCK();
	return (0);
}

/*ARGSUSED*/
int
logread(__unused dev_t dev, struct uio *uio, int flag)
{
	int l;
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
		int readpos;

		l = msgbufp->msg_bufx - msgbufp->msg_bufr;
		if (l < 0)
			l = msgbufp->msg_size - msgbufp->msg_bufr;
		l = min(l, uio_resid(uio));
		if (l == 0)
			break;

		readpos = msgbufp->msg_bufr;
		LOG_UNLOCK();
		error = uiomove((caddr_t)&msgbufp->msg_bufc[readpos],
			l, uio);
		LOG_LOCK();
		if (error)
			break;
		msgbufp->msg_bufr = readpos + l;
		if (msgbufp->msg_bufr >= msgbufp->msg_size)
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
	LOG_LOCK();
	if (logentrypend && log_open) {
		logentrypend = 0; /* only reset if someone will be reading */
		LOG_UNLOCK();
		logwakeup();
	} else {
		LOG_UNLOCK();
	}
}

/*ARGSUSED*/
int
logioctl(__unused dev_t dev, u_long com, caddr_t data, __unused int flag, __unused struct proc *p)
{
	int l;

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
	/* After this point, we must be ready to accept characters */
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
	struct msgbuf *mbp;

	mbp = msgbufp; 
	mbp->msg_bufc[mbp->msg_bufx++] = c;
	logentrypend = 1;
	if (mbp->msg_bufx >= msgbufp->msg_size)
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
 * allocated statically and is CONFIG_MSG_BSIZE characters in size, otherwise
 * memory is dynamically allocated. Memory management must already be up.
 */
int
log_setsize(int size) {
	char *new_logdata;
	int new_logsize, new_bufr, new_bufx;
	char *old_logdata;
	int old_logsize, old_bufr, old_bufx;
	int i, count;
	char *p, ch;

	if (size > MAX_MSG_BSIZE)
		return (EINVAL);

	if (size <= 0)
		return (EINVAL);

	new_logsize = size;
	if (!(new_logdata = (char*)kalloc(size))) {
		printf("log_setsize: unable to allocate memory\n");
		return (ENOMEM);
	}
	bzero(new_logdata, new_logsize);

	LOG_LOCK();

	old_logsize = msgbufp->msg_size;
	old_logdata = msgbufp->msg_bufc;
	old_bufr = msgbufp->msg_bufr;
	old_bufx = msgbufp->msg_bufx;

	LOG_SETSIZE_DEBUG("log_setsize(%d): old_logdata %p old_logsize %d old_bufr %d old_bufx %d\n",
					  size, old_logdata, old_logsize, old_bufr, old_bufx);

	/* start "new_logsize" bytes before the write pointer */
	if (new_logsize <= old_bufx) {
		count = new_logsize;
		p = old_logdata + old_bufx - count;
	} else {
		/*
		 * if new buffer is bigger, copy what we have and let the
		 * bzero above handle the difference
		 */
		count = MIN(new_logsize, old_logsize);
		p = old_logdata + old_logsize - (count - old_bufx);
	}
	for (i = 0; i < count; i++) {
		if (p >= old_logdata + old_logsize)
			p = old_logdata;

		ch = *p++;
		new_logdata[i] = ch;
	}

	new_bufx = i;
	if (new_bufx >= new_logsize)
		new_bufx = 0;
	msgbufp->msg_bufx = new_bufx;

	new_bufr = old_bufx - old_bufr; /* how much were we trailing bufx by? */
	if (new_bufr < 0)
		new_bufr += old_logsize;
	new_bufr = new_bufx - new_bufr; /* now relative to oldest data in new buffer */
	if (new_bufr < 0)
		new_bufr += new_logsize;
	msgbufp->msg_bufr = new_bufr;

	msgbufp->msg_size = new_logsize;
	msgbufp->msg_bufc = new_logdata;

	LOG_SETSIZE_DEBUG("log_setsize(%d): new_logdata %p new_logsize %d new_bufr %d new_bufx %d\n",
					  size, new_logdata, new_logsize, new_bufr, new_bufx);

	LOG_UNLOCK();

	/* this memory is now dead - clear it so that it compresses better
	   in case of suspend to disk etc. */
	bzero(old_logdata, old_logsize);
	if (old_logdata != smsg_bufc) {
		/* dynamic memory that must be freed */
		kfree(old_logdata, old_logsize);
	}

	printf("set system log size to %d bytes\n", new_logsize);

	return 0;
}

SYSCTL_PROC(_kern, OID_AUTO, msgbuf, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, 0, 0, sysctl_kern_msgbuf, "I", "");

static int sysctl_kern_msgbuf(struct sysctl_oid *oidp __unused,
							  void *arg1 __unused,
							  int arg2 __unused,
							  struct sysctl_req *req)
{
	int old_bufsize, bufsize;
	int error;

	LOG_LOCK();
	old_bufsize = bufsize = msgbufp->msg_size;
	LOG_UNLOCK();

	error = sysctl_io_number(req, bufsize, sizeof(bufsize), &bufsize, NULL);
	if (error)
		return (error);

	if (bufsize != old_bufsize) {
		error = log_setsize(bufsize);
	}

	return (error);
}


/*
 * This should be called by /sbin/dmesg only via libproc.
 * It returns as much data still in the buffer as possible.
 */
int
log_dmesg(user_addr_t buffer, uint32_t buffersize, int32_t * retval) {
	uint32_t i;
	uint32_t localbuff_size;
	int error = 0, newl, skip;
	char *localbuff, *p, *copystart, ch;
	size_t copysize;

	LOG_LOCK();
	localbuff_size = (msgbufp->msg_size + 2); /* + '\n' + '\0' */
	LOG_UNLOCK();

	/* Allocate a temporary non-circular buffer for copyout */
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
		newl = (ch == '\n');
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
