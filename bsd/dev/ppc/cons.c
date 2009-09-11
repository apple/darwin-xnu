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
/* 
 * Copyright (c) 1987, 1988 NeXT, Inc.
 *
 * HISTORY
 *  7-Jan-93  Mac Gillon (mgillon) at NeXT
 *	Integrated POSIX support
 *
 * 12-Aug-87  John Seamons (jks) at NeXT
 *	Ported to NeXT.
 */ 

/*
 * Indirect driver for console.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <machine/cons.h>

struct tty	*constty;	/* current console device */

/*
 * The km driver supplied the default console device for the systems
 * (usually a raw frame buffer driver, but potentially a serial driver).
 */
extern struct tty *km_tty[1];

static dev_t
cndev(void)
{
        if (constty)
                return constty->t_dev;
        else
                return km_tty[0]->t_dev;
}

/*ARGSUSED*/
int
consopen(__unused dev_t dev, int flag, int devtype, struct proc *pp)
{
	dev = cndev();
	return ((*cdevsw[major(dev)].d_open)(dev, flag, devtype, pp));
}


/*ARGSUSED*/
int
consclose(__unused dev_t dev, int flag, int mode, struct proc *pp)
{
	dev = cndev();
	return ((*cdevsw[major(dev)].d_close)(dev, flag, mode, pp));
}


/*ARGSUSED*/
int
consread(__unused dev_t dev, struct uio *uio, int ioflag)
{
	dev = cndev();
	return ((*cdevsw[major(dev)].d_read)(dev, uio, ioflag));
}


/*ARGSUSED*/
int
conswrite(__unused dev_t dev, struct uio *uio, int ioflag)
{
	dev = cndev();
	return ((*cdevsw[major(dev)].d_write)(dev, uio, ioflag));
}


/*ARGSUSED*/
int
consioctl(__unused dev_t dev, u_long cmd, caddr_t addr, int flag, struct proc *p)
{
	dev = cndev();
#if 0
	/*
	 * Superuser can always use this to wrest control of console
	 * output from the "virtual" console.
	 *
	 * XXX Unfortunately, this code doesn't do what the author thougt
	 * XXX it did; use of the console device, a TIOCCONS would always
	 * XXX disassociate the console from a virtual terminal and send
	 * XXX it back to the fake tty.
	 */
	if ((unsigned) cmd == TIOCCONS && constty) {
		int error = proc_suser(p);
		if (!error) {
			constty = NULL;
		}
		return(error);
	}
#endif	/* 0 */

	return ((*cdevsw[major(dev)].d_ioctl)(dev, cmd, addr, flag, p));
}


/*ARGSUSED*/
/* called with funnel held */
int
consselect(__unused dev_t dev, int flag, void *wql, struct proc *p)
{
	dev = cndev();
	return ((*cdevsw[major(dev)].d_select)(dev, flag, wql, p));
}
