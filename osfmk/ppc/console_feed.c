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
/*
 * @OSF_FREE_COPYRIGHT@
 * 
 */

/* Intercept mach console output and supply it to a user application */

#include <mach_kdb.h>

#include <types.h>
#include <device/buf.h>
#include <device/conf.h>
#include <device/errno.h>
#include <device/misc_protos.h>
#include <device/ds_routines.h>
#include <device/cirbuf.h>
#include <ppc/console_feed_entries.h>
#include <ppc/serial_io.h>

#if	MACH_KDB
#include <ppc/db_machdep.h>
#endif	/* MACH_KDB */

static struct cirbuf cons_feed_cb;
static int cons_feed_count = 0;
io_req_t   cons_feed_queued = 0;

/* console feed lock should be taken at splhigh */
decl_simple_lock_data(,cons_feed_lock)

boolean_t cons_feed_read_done(io_req_t ior);

io_return_t
console_feed_open(
	dev_t		dev,
	dev_mode_t	flag,
	io_req_t	ior)
{
	spl_t	s;

        simple_lock_init(&cons_feed_lock, ETAP_IO_TTY);
#if	MACH_KDB
	if (console_is_serial()) {
		return D_DEVICE_DOWN;
	}
#endif	/* MACH_KDB */
	cb_alloc(&cons_feed_cb, CONSOLE_FEED_BUFSIZE);
	s = splhigh();
	simple_lock(&cons_feed_lock);
	cons_feed_count++;
	simple_unlock(&cons_feed_lock);
	splx(s);
	return D_SUCCESS;
}

void
console_feed_close(
	dev_t		dev)
{
	spl_t	s;

	s = splhigh();
	simple_lock(&cons_feed_lock);
	cons_feed_count--;
	simple_unlock(&cons_feed_lock);
	splx(s);

	console_feed_cancel_and_flush();
	cb_free(&cons_feed_cb);

	return;
}

/* A routine that can be called from a panic or other problem
 * situation. It switches off the console feed and dumps any
 * remaining buffered information to the original console
 * (usually the screen). It doesn't free up the buffer, since
 * it tries to be as minimal as possible 
 */

void console_feed_cancel_and_flush(void)
{
	int	c;
	spl_t	s;
	
#if	NCONSFEED > 0
#if	MACH_KDB
	if (console_is_serial()) {
		return;
	}
#endif	/* MACH_KDB */

	s = splhigh();
	simple_lock(&cons_feed_lock);
	if (cons_feed_count == 0) {
		simple_unlock(&cons_feed_lock);
		splx(s);
		return;
	}
	cons_feed_count = 0;
	simple_unlock(&cons_feed_lock);
	splx(s);

	do {
		c = getc(&cons_feed_cb);
		if (c == -1)
			break;
		cnputc(c);
	} while (1);
#endif /* NCONSFEED > 0 */
}

io_return_t
console_feed_read(
	dev_t		dev,
	io_req_t 	ior)
{
	spl_t		s;
	kern_return_t	rc;
	int		count;

	rc = device_read_alloc(ior, (vm_size_t) ior->io_count);
	if (rc != KERN_SUCCESS)
		return rc;

	s = splhigh();
	simple_lock(&cons_feed_lock);

	ior->io_residual = ior->io_count;

	count = q_to_b(&cons_feed_cb, (char *) ior->io_data, ior->io_count);
	if (count == 0) {
		if (ior->io_mode & D_NOWAIT) {
			rc = D_WOULD_BLOCK;
		}
		if (cons_feed_queued == NULL) {
			ior->io_done = cons_feed_read_done;
			cons_feed_queued = ior;
			rc = D_IO_QUEUED;
		} else {
			/* Can't queue multiple read requests yet */
			rc = D_INVALID_OPERATION;
		}
		simple_unlock(&cons_feed_lock);
		splx(s);
		return rc;
	}

	simple_unlock(&cons_feed_lock);
	splx(s);

	ior->io_residual -= count;

	iodone(ior);

	if (ior->io_op & IO_SYNC) {
		iowait(ior);
	}

	return D_SUCCESS;
}

/* Called when data is ready and there's a queued-up read waiting */
boolean_t cons_feed_read_done(io_req_t ior)
{
	spl_t	s;
	int	count;

	s = splhigh();
	simple_lock(&cons_feed_lock);

	count = q_to_b(&cons_feed_cb, (char *) ior->io_data, ior->io_count);
	if (count == 0) {
		if (cons_feed_queued == NULL) {
			ior->io_done = cons_feed_read_done;
			cons_feed_queued = ior;
		}
		simple_unlock(&cons_feed_lock);
		splx(s);
		return FALSE;
	}

	simple_unlock(&cons_feed_lock);
	splx(s);

	ior->io_residual -= count;
	ds_read_done(ior);

	return TRUE;
}

/* This routine is called from putc() - it should return TRUE if
 * the character should be passed on to a physical console, FALSE
 * if the feed has intercepted the character. It may be called from
 * under interrupt (even splhigh)
 */

boolean_t console_feed_putc(char c)
{
	spl_t 		s;
	io_req_t	ior;
	boolean_t	retval;

#if	MACH_KDB
	if (db_active) {
		return TRUE;
	}
#endif	/* MACH_KDB */

	retval=TRUE;	/* TRUE : character should be displayed now */
	if (!cons_feed_count) {
		return TRUE;
	}
	s = splhigh();
	simple_lock(&cons_feed_lock);
	if (!cons_feed_count) {
		simple_unlock(&cons_feed_lock);
		splx(s);
		return TRUE;
	}
	/* queue up the data if we can */
	if (!putc(c, &cons_feed_cb)) {
		/* able to stock the character */
		retval = FALSE;
	}
	if (cons_feed_queued != NULL) {
		/* Queued up request - service it */
		ior = cons_feed_queued;
		cons_feed_queued = NULL;
		simple_unlock(&cons_feed_lock);
		splx(s);
		iodone(ior);
		retval=FALSE;
	} else {
		simple_unlock(&cons_feed_lock);
		splx(s);
	}
	return retval;
}
