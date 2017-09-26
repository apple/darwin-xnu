/*
 * Copyright (c) 2000-2016 Apple, Inc. All rights reserved.
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
#include <stdbool.h>
#include <firehose/tracepoint_private.h>
#include <firehose/chunk_private.h>
#include <firehose/ioctl_private.h>
#include <os/firehose_buffer_private.h>

#include <os/log_private.h>
#include <sys/ioctl.h>
#include <sys/msgbuf.h>
#include <sys/file_internal.h>
#include <sys/errno.h>
#include <sys/select.h>
#include <sys/kernel.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/simple_lock.h>
#include <sys/lock.h>
#include <sys/signalvar.h>
#include <sys/conf.h>
#include <sys/sysctl.h>
#include <sys/queue.h>
#include <kern/kalloc.h>
#include <pexpert/pexpert.h>
#include <mach/mach_port.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <vm/vm_kern.h>
#include <kern/task.h>
#include <kern/locks.h>

/* XXX should be in a common header somewhere */
extern void logwakeup(void);
extern void oslogwakeup(void);
extern void oslog_streamwakeup(void);
static void oslog_streamwakeup_locked(void);
vm_offset_t kernel_firehose_addr = 0;

/* log message counters for streaming mode */
uint32_t oslog_s_streamed_msgcount = 0;
uint32_t oslog_s_dropped_msgcount  = 0;
extern uint32_t oslog_s_error_count;

#define LOG_RDPRI	(PZERO + 1)

#define LOG_NBIO	0x02
#define LOG_ASYNC	0x04
#define LOG_RDWAIT	0x08

#define MAX_UNREAD_CHARS (CONFIG_MSG_BSIZE/2)
/* All globals should be accessed under LOG_LOCK() */

/* logsoftc only valid while log_open=1 */
struct logsoftc {
	int	sc_state;		/* see above for possibilities */
	struct	selinfo sc_selp;	/* thread waiting for select */
	int	sc_pgid;		/* process/group for async I/O */
} logsoftc;

int	log_open;			/* also used in log() */
char smsg_bufc[CONFIG_MSG_BSIZE]; /* static buffer */
char oslog_stream_bufc[FIREHOSE_CHUNK_SIZE]; /* static buffer */
struct firehose_chunk_s oslog_boot_buf = {
	.fc_pos = {
		.fcp_next_entry_offs = offsetof(struct firehose_chunk_s, fc_data),
		.fcp_private_offs = FIREHOSE_CHUNK_SIZE,
		.fcp_refcnt = 1, // indicate that there is a writer to this chunk
		.fcp_stream = firehose_stream_persist,
		.fcp_flag_io = 1, // for now, lets assume this is coming from the io bank
	},
}; /* static buffer */
firehose_chunk_t firehose_boot_chunk = &oslog_boot_buf;
struct msgbuf msgbuf = {MSG_MAGIC,sizeof(smsg_bufc),0,0,smsg_bufc};
struct msgbuf oslog_stream_buf = {MSG_MAGIC,0,0,0,NULL};
struct msgbuf *msgbufp __attribute__((used)) = &msgbuf;
struct msgbuf *oslog_streambufp __attribute__((used)) = &oslog_stream_buf;

// List entries for keeping track of the streaming buffer
static oslog_stream_buf_entry_t oslog_stream_buf_entries;

#define OSLOG_NUM_STREAM_ENTRIES	64
#define OSLOG_STREAM_BUF_SIZE		4096

int	oslog_open = 0;
int	os_log_wakeup = 0;
int	oslog_stream_open = 0;
int	oslog_stream_buf_size = OSLOG_STREAM_BUF_SIZE;
int	oslog_stream_num_entries = OSLOG_NUM_STREAM_ENTRIES;

/* oslogsoftc only valid while oslog_open=1 */
struct oslogsoftc {
	int	sc_state;		/* see above for possibilities */
	struct	selinfo sc_selp;	/* thread waiting for select */
	int	sc_pgid;		/* process/group for async I/O */
} oslogsoftc;

struct oslog_streamsoftc {
	int	sc_state;		/* see above for possibilities */
	struct	selinfo sc_selp;	/* thread waiting for select */
	int	sc_pgid;		/* process/group for async I/O */
}oslog_streamsoftc;

STAILQ_HEAD(, oslog_stream_buf_entry_s) oslog_stream_free_head =
		STAILQ_HEAD_INITIALIZER(oslog_stream_free_head);
STAILQ_HEAD(, oslog_stream_buf_entry_s) oslog_stream_buf_head =
		STAILQ_HEAD_INITIALIZER(oslog_stream_buf_head);

/* defined in osfmk/kern/printf.c  */
extern void oslog_lock_init(void);
extern void bsd_log_lock(void);
extern void bsd_log_unlock(void);

/* defined for osfmk/kern/printf.c */
void bsd_log_init(void);

/*
 * Ideally this file would define this lock, but bsd doesn't have the definition
 * for lock groups.
 */
decl_lck_spin_data(extern, oslog_stream_lock)

/* XXX wants a linker set so these can be static */
extern d_open_t         logopen;
extern d_close_t        logclose;
extern d_read_t         logread;
extern d_ioctl_t        logioctl;
extern d_select_t       logselect;

/* XXX wants a linker set so these can be static */
extern d_open_t         oslogopen;
extern d_close_t        oslogclose;
extern d_select_t       oslogselect;
extern d_ioctl_t        oslogioctl;

/* XXX wants a linker set so these can be static */
extern d_open_t         oslog_streamopen;
extern d_close_t        oslog_streamclose;
extern d_read_t         oslog_streamread;
extern d_ioctl_t        oslog_streamioctl;
extern d_select_t       oslog_streamselect;

void oslog_init(void);
void oslog_setsize(int size);
void oslog_streamwrite_locked(firehose_tracepoint_id_u ftid,
		uint64_t stamp, const void *pubdata, size_t publen);
void oslog_streamwrite_metadata_locked(oslog_stream_buf_entry_t m_entry);
static oslog_stream_buf_entry_t oslog_stream_find_free_buf_entry_locked(void);
static void oslog_streamwrite_append_bytes(const char *buffer, int buflen);

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
	logsoftc.sc_state &= ~(LOG_NBIO | LOG_ASYNC);
	selwakeup(&logsoftc.sc_selp);
	selthreadclear(&logsoftc.sc_selp);
	log_open = 0;
	LOG_UNLOCK();
	return (0);
}


int
oslogopen(__unused dev_t dev, __unused int flags, __unused int mode, struct proc *p)
{
	LOG_LOCK();
	if (oslog_open) {
		LOG_UNLOCK();
		return(EBUSY);
	}
	oslogsoftc.sc_pgid = p->p_pid;		/* signal process only */
	oslog_open = 1;

	LOG_UNLOCK();
	return (0);
}

int
oslogclose(__unused dev_t dev, __unused int flag, __unused int devtype, __unused struct proc *p)
{
	LOG_LOCK();
	oslogsoftc.sc_state &= ~(LOG_NBIO | LOG_ASYNC);
	selwakeup(&oslogsoftc.sc_selp);
	selthreadclear(&oslogsoftc.sc_selp);
	oslog_open = 0;
	LOG_UNLOCK();
	return (0);
}

int
oslog_streamopen(__unused dev_t dev, __unused int flags, __unused int mode, struct proc *p)
{
	char *oslog_stream_msg_bufc = NULL;
	oslog_stream_buf_entry_t entries = NULL;

	lck_spin_lock(&oslog_stream_lock);
	if (oslog_stream_open) {
		lck_spin_unlock(&oslog_stream_lock);
		return EBUSY;
	}
	lck_spin_unlock(&oslog_stream_lock);

	// Allocate the stream buffer
	oslog_stream_msg_bufc = kalloc(oslog_stream_buf_size);
	if (!oslog_stream_msg_bufc) {
		return ENOMEM;
	}

	/* entries to support kernel logging in stream mode */
	entries = kalloc(oslog_stream_num_entries * sizeof(struct oslog_stream_buf_entry_s));
	if (!entries) {
		kfree(oslog_stream_msg_bufc, oslog_stream_buf_size);
		return ENOMEM;
	}

	lck_spin_lock(&oslog_stream_lock);
	if (oslog_stream_open) {
		lck_spin_unlock(&oslog_stream_lock);
		kfree(oslog_stream_msg_bufc, oslog_stream_buf_size);
		kfree(entries, oslog_stream_num_entries * sizeof(struct oslog_stream_buf_entry_s));
		return EBUSY;
	}

	assert(oslog_streambufp->msg_bufc == NULL);
	oslog_streambufp->msg_bufc = oslog_stream_msg_bufc;
	oslog_streambufp->msg_size = oslog_stream_buf_size;

	oslog_stream_buf_entries = entries;

	STAILQ_INIT(&oslog_stream_free_head);
	STAILQ_INIT(&oslog_stream_buf_head);

	for (int i = 0; i < oslog_stream_num_entries; i++) {
		oslog_stream_buf_entries[i].type = oslog_stream_link_type_log;
		oslog_stream_buf_entries[i].offset = 0;
		oslog_stream_buf_entries[i].size = 0;
		oslog_stream_buf_entries[i].timestamp = 0;
		STAILQ_INSERT_TAIL(&oslog_stream_free_head, &oslog_stream_buf_entries[i], buf_entries);
	}

	/* there should be no pending entries in the stream */
	assert(STAILQ_EMPTY(&oslog_stream_buf_head));
	assert(oslog_streambufp->msg_bufx == 0);
	assert(oslog_streambufp->msg_bufr == 0);

	oslog_streambufp->msg_bufx = 0;
	oslog_streambufp->msg_bufr = 0;
	oslog_streamsoftc.sc_pgid = p->p_pid; /* signal process only */
	oslog_stream_open = 1;
	lck_spin_unlock(&oslog_stream_lock);

	return 0;
}

int
oslog_streamclose(__unused dev_t dev, __unused int flag, __unused int devtype, __unused struct proc *p)
{
	oslog_stream_buf_entry_t next_entry = NULL;
	char *oslog_stream_msg_bufc = NULL;
	oslog_stream_buf_entry_t entries = NULL;

	lck_spin_lock(&oslog_stream_lock);

	if (oslog_stream_open == 0) {
		lck_spin_unlock(&oslog_stream_lock);
		return EBADF;
	}

	// Consume all log lines
	while (!STAILQ_EMPTY(&oslog_stream_buf_head)) {
		next_entry = STAILQ_FIRST(&oslog_stream_buf_head);
		STAILQ_REMOVE_HEAD(&oslog_stream_buf_head, buf_entries);
	}
	oslog_streamwakeup_locked();
	oslog_streamsoftc.sc_state &= ~(LOG_NBIO | LOG_ASYNC);
	selwakeup(&oslog_streamsoftc.sc_selp);
	selthreadclear(&oslog_streamsoftc.sc_selp);
	oslog_stream_open = 0;
	oslog_streambufp->msg_bufr = 0;
	oslog_streambufp->msg_bufx = 0;
	oslog_stream_msg_bufc = oslog_streambufp->msg_bufc;
	oslog_streambufp->msg_bufc = NULL;
	entries = oslog_stream_buf_entries;
	oslog_stream_buf_entries = NULL;
	oslog_streambufp->msg_size = 0;

	lck_spin_unlock(&oslog_stream_lock);

	// Free the stream buffer
	kfree(oslog_stream_msg_bufc, oslog_stream_buf_size);
	// Free the list entries
	kfree(entries, oslog_stream_num_entries * sizeof(struct oslog_stream_buf_entry_s));

	return 0;
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
		 * If the wakeup is missed 
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
oslog_streamread(__unused dev_t dev, struct uio *uio, int flag)
{
	int error = 0;
	int copy_size = 0;
	static char logline[FIREHOSE_CHUNK_SIZE];

	lck_spin_lock(&oslog_stream_lock);

	if (!oslog_stream_open) {
		lck_spin_unlock(&oslog_stream_lock);
		return EBADF;
	}

	while (STAILQ_EMPTY(&oslog_stream_buf_head)) {
		if (flag & IO_NDELAY || oslog_streamsoftc.sc_state & LOG_NBIO) {
			lck_spin_unlock(&oslog_stream_lock);
			return EWOULDBLOCK;
		}

		oslog_streamsoftc.sc_state |= LOG_RDWAIT;
		wait_result_t wr = assert_wait((event_t)oslog_streambufp,
			THREAD_INTERRUPTIBLE);
		if (wr == THREAD_WAITING) {
			lck_spin_unlock(&oslog_stream_lock);
			wr = thread_block(THREAD_CONTINUE_NULL);
			lck_spin_lock(&oslog_stream_lock);
		}

		switch (wr) {
			case THREAD_AWAKENED:
			case THREAD_TIMED_OUT:
				break;
			default:
				lck_spin_unlock(&oslog_stream_lock);
				return EINTR;
		}
	}

	if (!oslog_stream_open) {
		lck_spin_unlock(&oslog_stream_lock);
		return EBADF;
	}

	int logpos = 0;
	oslog_stream_buf_entry_t read_entry = NULL;
	uint16_t rec_length;

	read_entry = STAILQ_FIRST(&oslog_stream_buf_head);
	assert(read_entry != NULL);
	STAILQ_REMOVE_HEAD(&oslog_stream_buf_head, buf_entries);

	// Copy the timestamp first
	memcpy(logline + logpos, &read_entry->timestamp, sizeof(uint64_t));
	logpos += sizeof(uint64_t);

	switch (read_entry->type) {
		/* Handle metadata messages */
		case oslog_stream_link_type_metadata:
		{
			memcpy(logline + logpos,
				(read_entry->metadata), read_entry->size);
			logpos += read_entry->size;

			lck_spin_unlock(&oslog_stream_lock);

			// Free the list entry
			kfree(read_entry, (sizeof(struct oslog_stream_buf_entry_s) + read_entry->size));
			break;
		}
		/* Handle log messages */
		case oslog_stream_link_type_log:
		{
			/* ensure that the correct read entry was dequeued */
			assert(read_entry->offset == oslog_streambufp->msg_bufr);
			rec_length = read_entry->size;

			// If the next log line is contiguous in the buffer, copy it out.
			if(read_entry->offset + rec_length <= oslog_streambufp->msg_size) {
				memcpy(logline + logpos,
					oslog_streambufp->msg_bufc + read_entry->offset, rec_length);

				oslog_streambufp->msg_bufr += rec_length;
				if (oslog_streambufp->msg_bufr == oslog_streambufp->msg_size) {
					oslog_streambufp->msg_bufr = 0;
				}
				logpos += rec_length;
			} else {
				// Otherwise, copy until the end of the buffer, and
				// copy the remaining bytes starting at index 0.
				int bytes_left = oslog_streambufp->msg_size - read_entry->offset;
				memcpy(logline + logpos,
					oslog_streambufp->msg_bufc + read_entry->offset, bytes_left);
				logpos += bytes_left;
				rec_length -= bytes_left;

				memcpy(logline + logpos, (const void *)oslog_streambufp->msg_bufc,
					rec_length);
				oslog_streambufp->msg_bufr = rec_length;
				logpos += rec_length;
			}
			assert(oslog_streambufp->msg_bufr < oslog_streambufp->msg_size);
			STAILQ_INSERT_TAIL(&oslog_stream_free_head, read_entry, buf_entries);

			lck_spin_unlock(&oslog_stream_lock);
			break;
		}
		default:
		{
			panic("Got unexpected log entry type: %hhu\n", read_entry->type);
		}
	}

	copy_size = min(logpos, uio_resid(uio));
	if (copy_size != 0) {
		error = uiomove((caddr_t)logline, copy_size, uio);
	}
	(void)hw_atomic_add(&oslog_s_streamed_msgcount, 1);

	return error;
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

int
oslogselect(__unused dev_t dev, int rw, void * wql, struct proc *p)
{
	switch (rw) {

	case FREAD:
		LOG_LOCK();
		if (os_log_wakeup) {
			LOG_UNLOCK();
			return (1);
		}
		selrecord(p, &oslogsoftc.sc_selp, wql);
		LOG_UNLOCK();
		break;
	}
	return (0);
}

int
oslog_streamselect(__unused dev_t dev, int rw, void * wql, struct proc *p)
{
	int ret = 0;

	lck_spin_lock(&oslog_stream_lock);

	switch (rw) {
	case FREAD:
		if (STAILQ_EMPTY(&oslog_stream_buf_head)) {
			selrecord(p, &oslog_streamsoftc.sc_selp, wql);
		} else {
			ret = 1;
		}
		break;
	}

	lck_spin_unlock(&oslog_stream_lock);
	return ret;
}

void
logwakeup(void)
{
	int pgid;

	/* cf. r24974766 & r25201228*/
	if (oslog_is_safe() == FALSE) {
		return;
	}

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
oslogwakeup(void)
{
	LOG_LOCK();
	if (!oslog_open) {
		LOG_UNLOCK();
		return;
	}
	selwakeup(&oslogsoftc.sc_selp);
	os_log_wakeup = 1;
	LOG_UNLOCK();
}

static void
oslog_streamwakeup_locked(void)
{
	LCK_SPIN_ASSERT(&oslog_stream_lock, LCK_ASSERT_OWNED);
	if (!oslog_stream_open) {
		return;
	}
	selwakeup(&oslog_streamsoftc.sc_selp);
	if (oslog_streamsoftc.sc_state & LOG_RDWAIT) {
		wakeup((caddr_t)oslog_streambufp);
		oslog_streamsoftc.sc_state &= ~LOG_RDWAIT;
	}
}

void
oslog_streamwakeup(void)
{
	/* cf. r24974766 & r25201228*/
	if (oslog_is_safe() == FALSE) {
		return;
	}

	lck_spin_lock(&oslog_stream_lock);
	oslog_streamwakeup_locked();
	lck_spin_unlock(&oslog_stream_lock);
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

/*ARGSUSED*/
int
oslogioctl(__unused dev_t dev, u_long com, caddr_t data, __unused int flag, __unused struct proc *p)
{
	int ret = 0;
	mach_vm_size_t buffer_size = (FIREHOSE_BUFFER_KERNEL_CHUNK_COUNT * FIREHOSE_CHUNK_SIZE);
	firehose_buffer_map_info_t map_info = {0, 0};
	firehose_buffer_t kernel_firehose_buffer = NULL;
	mach_vm_address_t user_addr = 0;
	mach_port_t mem_entry_ptr = MACH_PORT_NULL;

	switch (com) {

	/* return number of characters immediately available */

	case LOGBUFFERMAP:
		kernel_firehose_buffer = (firehose_buffer_t)kernel_firehose_addr;

		ret = mach_make_memory_entry_64(kernel_map,
						&buffer_size,
						(mach_vm_offset_t) kernel_firehose_buffer,
						( MAP_MEM_VM_SHARE | VM_PROT_READ ),
						&mem_entry_ptr,
						MACH_PORT_NULL);
		if (ret == KERN_SUCCESS) {
			ret = mach_vm_map_kernel(get_task_map(current_task()),
					  &user_addr,
					  buffer_size,
					  0, /*  mask */
					  VM_FLAGS_ANYWHERE,
					  VM_KERN_MEMORY_NONE,
					  mem_entry_ptr,
					  0, /* offset */
					  FALSE, /* copy */
					  VM_PROT_READ,
					  VM_PROT_READ,
					  VM_INHERIT_SHARE);
		}

		if (ret == KERN_SUCCESS) {
			map_info.fbmi_addr = (uint64_t) (user_addr);
			map_info.fbmi_size = buffer_size;
			bcopy(&map_info, data, sizeof(firehose_buffer_map_info_t));
		}
		break;
	case LOGFLUSHED:
		LOG_LOCK();
		os_log_wakeup = 0;
		LOG_UNLOCK();
		__firehose_merge_updates(*(firehose_push_reply_t *)(data));
		break;
	default:
		return (-1);
	}
	return (0);
}

/*ARGSUSED*/
int
oslog_streamioctl(__unused dev_t dev, u_long com, caddr_t data, __unused int flag, __unused struct proc *p)
{
	int err = 0;

	lck_spin_lock(&oslog_stream_lock);

	switch (com) {
	case FIONBIO:
		if (data && *(int *)data)
			oslog_streamsoftc.sc_state |= LOG_NBIO;
		else
			oslog_streamsoftc.sc_state &= ~LOG_NBIO;
		break;
	case FIOASYNC:
		if (data && *(int *)data)
			oslog_streamsoftc.sc_state |= LOG_ASYNC;
		else
			oslog_streamsoftc.sc_state &= ~LOG_ASYNC;
		break;
	default:
		err = -1;
		break;
	}

	lck_spin_unlock(&oslog_stream_lock);
	return err;
}

void
bsd_log_init(void)
{
	/* After this point, we must be ready to accept characters */
}

void
oslog_init(void)
{
	kern_return_t kr;
	vm_size_t size = FIREHOSE_BUFFER_KERNEL_CHUNK_COUNT * FIREHOSE_CHUNK_SIZE;

	oslog_lock_init();

	kr = kmem_alloc_flags(kernel_map, &kernel_firehose_addr,
		size + (2 * PAGE_SIZE), VM_KERN_MEMORY_LOG,
		KMA_GUARD_FIRST | KMA_GUARD_LAST);
	if (kr != KERN_SUCCESS) {
		panic("Failed to allocate memory for firehose logging buffer");
	}
	kernel_firehose_addr += PAGE_SIZE;
	bzero((void *)kernel_firehose_addr, size);
	/* register buffer with firehose */
	kernel_firehose_addr = (vm_offset_t)__firehose_buffer_create((size_t *) &size);

	kprintf("oslog_init completed\n");
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
	if (mbp->msg_bufx >= msgbufp->msg_size)
		mbp->msg_bufx = 0;
}

static oslog_stream_buf_entry_t
oslog_stream_find_free_buf_entry_locked(void)
{
	struct msgbuf *mbp;
	oslog_stream_buf_entry_t buf_entry = NULL;

	LCK_SPIN_ASSERT(&oslog_stream_lock, LCK_ASSERT_OWNED);

	mbp = oslog_streambufp;

	buf_entry = STAILQ_FIRST(&oslog_stream_free_head);
	if (buf_entry) {
		STAILQ_REMOVE_HEAD(&oslog_stream_free_head, buf_entries);
	}
	else {
		// If no list elements are available in the free-list,
		// consume the next log line so we can free up its list element
		oslog_stream_buf_entry_t prev_entry = NULL;

		buf_entry = STAILQ_FIRST(&oslog_stream_buf_head);
		while (buf_entry->type == oslog_stream_link_type_metadata) {
			prev_entry = buf_entry;
			buf_entry = STAILQ_NEXT(buf_entry, buf_entries);
		}

		if (prev_entry == NULL) {
			STAILQ_REMOVE_HEAD(&oslog_stream_buf_head, buf_entries);
		}
		else {
			STAILQ_REMOVE_AFTER(&oslog_stream_buf_head, prev_entry, buf_entries);
		}

		mbp->msg_bufr += buf_entry->size;
		oslog_s_dropped_msgcount++;
		if (mbp->msg_bufr >= mbp->msg_size) {
			mbp->msg_bufr = (mbp->msg_bufr % mbp->msg_size);
		}
	}

	return buf_entry;
}

void
oslog_streamwrite_metadata_locked(oslog_stream_buf_entry_t m_entry)
{
	LCK_SPIN_ASSERT(&oslog_stream_lock, LCK_ASSERT_OWNED);
	STAILQ_INSERT_TAIL(&oslog_stream_buf_head, m_entry, buf_entries);

	return;
}

static void oslog_streamwrite_append_bytes(const char *buffer, int buflen)
{
	struct msgbuf *mbp;

	LCK_SPIN_ASSERT(&oslog_stream_lock, LCK_ASSERT_OWNED);

	mbp = oslog_streambufp;
	// Check if we have enough space in the stream buffer to write the data
	if (mbp->msg_bufx + buflen <= mbp->msg_size) {
		memcpy((void *)(mbp->msg_bufc + mbp->msg_bufx), buffer, buflen);

		mbp->msg_bufx += buflen;
		if (mbp->msg_bufx == mbp->msg_size) {
			mbp->msg_bufx = 0;
		}
	} else {
		// Copy part of the data until the end of the stream
		int bytes_left = mbp->msg_size - mbp->msg_bufx;
		memcpy((void *)(mbp->msg_bufc + mbp->msg_bufx), buffer, bytes_left);

		buflen -= bytes_left;
		buffer += bytes_left;

		// Copy the remainder of the data from the beginning of stream
		memcpy((void *)mbp->msg_bufc, buffer, buflen);
		mbp->msg_bufx = buflen;
	}
	return;
}


void
oslog_streamwrite_locked(firehose_tracepoint_id_u ftid,
		uint64_t stamp, const void *pubdata, size_t publen)
{
	struct msgbuf *mbp;
	int available_space = 0;
	oslog_stream_buf_entry_t buf_entry = NULL;
	oslog_stream_buf_entry_t next_entry = NULL;

	uint16_t ft_size = offsetof(struct firehose_tracepoint_s, ft_data);
	int ft_length = ft_size + publen;

	LCK_SPIN_ASSERT(&oslog_stream_lock, LCK_ASSERT_OWNED);

	mbp = oslog_streambufp;
	if (ft_length > mbp->msg_size) {
		(void)hw_atomic_add(&oslog_s_error_count, 1);
		return;
	}

	// Ensure that we have a list element for this record
	buf_entry = oslog_stream_find_free_buf_entry_locked();

	assert(buf_entry != NULL);

	// Ensure that we have space in the ring buffer for the current logline
	if (mbp->msg_bufr > mbp->msg_bufx) {
		available_space = mbp->msg_bufr - mbp->msg_bufx;
	} else {
		available_space = mbp->msg_size - mbp->msg_bufx + mbp->msg_bufr;
	}
	while(ft_length > available_space) {
		oslog_stream_buf_entry_t prev_entry = NULL;

		next_entry = STAILQ_FIRST(&oslog_stream_buf_head);
		assert(next_entry != NULL);
		while (next_entry->type == oslog_stream_link_type_metadata) {
			prev_entry = next_entry;
			next_entry = STAILQ_NEXT(next_entry, buf_entries);
		}

		if (prev_entry == NULL) {
			STAILQ_REMOVE_HEAD(&oslog_stream_buf_head, buf_entries);
		}
		else {
			STAILQ_REMOVE_AFTER(&oslog_stream_buf_head, prev_entry, buf_entries);
		}

		mbp->msg_bufr += next_entry->size;
		if (mbp->msg_bufr >= mbp->msg_size) {
			mbp->msg_bufr = (mbp->msg_bufr % mbp->msg_size);
		}

		oslog_s_dropped_msgcount++;
		available_space += next_entry->size;

		STAILQ_INSERT_TAIL(&oslog_stream_free_head, next_entry, buf_entries);
	}

	assert(ft_length <= available_space);

	// Write the log line and update the list entry for this record
	buf_entry->offset = mbp->msg_bufx;
	buf_entry->size = ft_length;
	buf_entry->timestamp = stamp;
	buf_entry->type = oslog_stream_link_type_log;

	// Construct a tracepoint
	struct firehose_tracepoint_s fs = {
		.ft_thread = thread_tid(current_thread()),
		.ft_id.ftid_value = ftid.ftid_value,
		.ft_length = publen
	};

	oslog_streamwrite_append_bytes((char *)&fs, sizeof(fs));
	oslog_streamwrite_append_bytes(pubdata, publen);

	assert(mbp->msg_bufr < mbp->msg_size);
	// Insert the element to the buffer data list
	STAILQ_INSERT_TAIL(&oslog_stream_buf_head, buf_entry, buf_entries);

	return;
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
	int unread_count = 0;
	LOG_LOCK();
	log_putc_locked(c);
	unread_count = msgbufp->msg_bufx - msgbufp->msg_bufr;
	LOG_UNLOCK();

	if (unread_count < 0)
		unread_count = 0 - unread_count;
	if (c == '\n' || unread_count >= MAX_UNREAD_CHARS)
		logwakeup();
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

void oslog_setsize(int size)
{
	uint16_t scale = 0;
	// If the size is less than the default stream buffer
	// do nothing
	if (size <= OSLOG_STREAM_BUF_SIZE) {
		return;
	}

	scale = (uint16_t) (size / OSLOG_STREAM_BUF_SIZE);

	oslog_stream_buf_size = size;
	oslog_stream_num_entries = scale * OSLOG_NUM_STREAM_ENTRIES;
	printf("oslog_setsize: new buffer size = %d, new num entries= %d\n", oslog_stream_buf_size, oslog_stream_num_entries);
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

