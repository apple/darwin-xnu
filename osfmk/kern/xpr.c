/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
#include <mach_kdb.h>
/*
 * xpr silent tracing circular buffer.
 */

#include <mach/machine/vm_types.h>
#include <kern/xpr.h>
#include <kern/lock.h>
#include <kern/spl.h>
#include <kern/cpu_number.h>
#include <kern/misc_protos.h>
#include <kern/thread.h>
#include <vm/vm_kern.h>
#include <string.h>

/*
 *	After a spontaneous reboot, it is desirable to look
 *	at the old xpr buffer.  Assuming xprbootstrap allocates
 *	the buffer in the same place in physical memory and
 *	the reboot doesn't clear memory, this should work.
 *	xprptr will be reset, but the saved value should be OK.
 *	Just set xprenable false so the buffer isn't overwritten.
 */

decl_simple_lock_data(,xprlock)
boolean_t xprenable = TRUE;	/* Enable xpr tracing */
int nxprbufs = 0;	/* Number of contiguous xprbufs allocated */
int xprflags = 0;	/* Bit mask of xpr flags enabled */
struct xprbuf *xprbase;	/* Pointer to circular buffer nxprbufs*sizeof(xprbuf)*/
struct xprbuf *xprptr;	/* Currently allocated xprbuf */
struct xprbuf *xprlast;	/* Pointer to end of circular buffer */

void
xpr(
	const char	*msg,
	long		arg1,
	long		arg2,
	long		arg3,
	long		arg4,
	long		arg5)
{
	spl_t s;
	register struct xprbuf *x;

	/* If we aren't initialized, ignore trace request */
	if (!xprenable || (xprptr == 0))
		return;
	/* Guard against all interrupts and allocate next buffer. */

	s = splhigh();
	simple_lock(&xprlock);
	x = xprptr++;
	if (xprptr >= xprlast) {
		/* wrap around */
		xprptr = xprbase;
	}
	/* Save xprptr in allocated memory. */
	*(struct xprbuf **)xprlast = xprptr;
	simple_unlock(&xprlock);
	x->timestamp = XPR_TIMESTAMP;
	splx(s);
	x->msg = msg;
	x->arg1 = arg1;
	x->arg2 = arg2;
	x->arg3 = arg3;
	x->arg4 = arg4;
	x->arg5 = arg5;
	mp_disable_preemption();
	x->cpuinfo = cpu_number();
	mp_enable_preemption();
}

void 
xprbootstrap(void)
{
	vm_offset_t	addr;
	vm_size_t	size;
	kern_return_t	kr;

	simple_lock_init(&xprlock, 0);
	if (nxprbufs == 0)
		return;	/* assume XPR support not desired */

	/* leave room at the end for a saved copy of xprptr */
	size = nxprbufs * sizeof(struct xprbuf) + sizeof xprptr;

	kr = kmem_alloc_wired(kernel_map, &addr, size);
	if (kr != KERN_SUCCESS)
		panic("xprbootstrap");

	if (xprenable) {
		/*
		 *	If xprenable is set (the default) then we zero
		 *	the buffer so xpr_dump doesn't encounter bad pointers.
		 *	If xprenable isn't set, then we preserve
		 *	the original contents of the buffer.  This is useful
		 *	if memory survives reboots, so xpr_dump can show
		 *	the previous buffer contents.
		 */

		(void) memset((void *) addr, 0, size);
	}

	xprbase = (struct xprbuf *) addr;
	xprlast = &xprbase[nxprbufs];
	xprptr = xprbase;	/* setting xprptr enables tracing */
}

int		xprinitial = 0;

void
xprinit(void)
{
	xprflags |= xprinitial;
}

#if	MACH_KDB
#include <ddb/db_output.h>

/*
 * Prototypes for functions called from the debugger
 */
void
xpr_dump(
	struct xprbuf	*base,
	int		nbufs);

void
xpr_search(
	int	arg_index,
	int	value);

extern jmp_buf_t *db_recover;

/*
 *	Print current content of xpr buffers (KDB's sake)
 *	Use stack order to make it understandable.
 *
 *	Called as "!xpr_dump" this dumps the kernel's xpr buffer.
 *	Called with arguments, it can dump xpr buffers in user tasks,
 *	assuming they use the same format as the kernel.
 */
void
xpr_dump(
	struct xprbuf	*base,
	int		nbufs)
{
	jmp_buf_t db_jmpbuf;
	jmp_buf_t *prev;
	struct xprbuf *last, *ptr;
	register struct xprbuf *x;
	int i;
	spl_t s;

	if (base == 0) {
		base = xprbase;
		nbufs = nxprbufs;
	}

	if (nbufs == 0)
		return;

	if (base == xprbase) {
		s = splhigh();
		simple_lock(&xprlock);
	}

	last = base + nbufs;
	ptr = * (struct xprbuf **) last;

	prev = db_recover;
	if (_setjmp(db_recover = &db_jmpbuf) == 0)
	    for (x = ptr, i = 0; i < nbufs; i++) {
		if (--x < base)
			x = last - 1;

		if (x->msg == 0)
			break;

		db_printf("<%d:%x:%x> ", x - base, x->cpuinfo, x->timestamp);
		db_printf(x->msg, x->arg1,x->arg2,x->arg3,x->arg4,x->arg5);
	    }
	db_recover = prev;

	if (base == xprbase) {
		simple_unlock(&xprlock);
		splx(s);
	}
}

/*
 * dump xpr table with a selection criteria.
 * argument number "arg_index" must equal "value"
 */

void
xpr_search(
	int	arg_index,
	int	value)
{
	jmp_buf_t db_jmpbuf;
	jmp_buf_t *prev;
	register struct xprbuf *x;
	spl_t s;
	int n;

	if (!nxprbufs)
		return;

	n = nxprbufs;

	s = splhigh();
	simple_lock(&xprlock);

	prev = db_recover;
	if (_setjmp(db_recover = &db_jmpbuf) == 0)
  	    for (x = *(struct xprbuf **)xprlast ; n--; ) {
		if (--x < xprbase)
			x = xprlast - 1;

		if (x->msg == 0) {
			break;
		}

		if (*((&x->arg1)+arg_index) != value)
			continue;

		db_printf("<%d:%d:%x> ", x - xprbase,
			  x->cpuinfo, x->timestamp);
		db_printf(x->msg, x->arg1,x->arg2,x->arg3,x->arg4,x->arg5);
	    }
	db_recover = prev;

	simple_unlock(&xprlock);
	splx(s);
}
#endif	/* MACH_KDB */
