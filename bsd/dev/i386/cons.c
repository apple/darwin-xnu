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

struct tty	cons;
struct tty	*constty;		/* current console device */

/*ARGSUSED*/
int
cnopen(dev, flag, devtype, pp)
	dev_t dev;
	int flag, devtype;
	struct proc *pp;
{
	dev_t device;

	if (constty)
	    device = constty->t_dev;
	else
	    device = cons.t_dev;
	return ((*cdevsw[major(device)].d_open)(device, flag, devtype, pp));
}

/*ARGSUSED*/
int
cnclose(dev, flag, mode, pp)
	dev_t dev;
	int flag, mode;
	struct proc *pp;
{
	dev_t device;

	if (constty)
	    device = constty->t_dev;
	else
	    device = cons.t_dev;
	return ((*cdevsw[major(device)].d_close)(device, flag, mode, pp));
}

/*ARGSUSED*/
int
cnread(dev, uio, ioflag)
	dev_t dev;
	struct uio *uio;
	int ioflag;
{
	dev_t device;

	if (constty)
	    device = constty->t_dev;
	else
	    device = cons.t_dev;
	return ((*cdevsw[major(device)].d_read)(device, uio, ioflag));
}

/*ARGSUSED*/
int
cnwrite(dev, uio, ioflag)
	dev_t dev;
	struct uio *uio;
	int ioflag;
{
    dev_t device;

	if (constty)
	    device = constty->t_dev;
	else
	    device = cons.t_dev;
    return ((*cdevsw[major(device)].d_write)(device, uio, ioflag));
}

/*ARGSUSED*/
int
cnioctl(dev, cmd, addr, flag, p)
	dev_t dev;
	int cmd;
	caddr_t addr;
	int flag;
	struct proc *p;
{
	dev_t device;

	if (constty)
	    device = constty->t_dev;
	else
	    device = cons.t_dev;
	/*
	 * Superuser can always use this to wrest control of console
	 * output from the "virtual" console.
	 */
	if (cmd == TIOCCONS && constty) {
		int error = suser(p->p_ucred, (u_short *) NULL);
		if (error)
			return (error);
		constty = NULL;
		return (0);
	}
	return ((*cdevsw[major(device)].d_ioctl)(device, cmd, addr, flag, p));
}

/*ARGSUSED*/
int
cnselect(dev, flag, wql, p)
	dev_t dev;
	int flag;
	void * wql;
	struct proc *p;
{
	dev_t device;

	if (constty)
	    device = constty->t_dev;
	else
	    device = cons.t_dev;
	return ((*cdevsw[major(device)].d_select)(device, flag, wql, p));
}

#if 0	/* FIXME  - using OSFMK console driver for the moment */
int
cngetc()
{
	dev_t device;

	if (constty)
	    device = constty->t_dev;
	else
	    device = cons.t_dev;
	return ((*cdevsw[major(device)].d_getc)(device));
}

/*ARGSUSED*/
int
cnputc(c)
	char c;
{
	dev_t device;

	if (constty)
	    device = constty->t_dev;
	else
	    device = cons.t_dev;
	return ((*cdevsw[major(device)].d_putc)(device, c));
}
#endif

#if	NCPUS > 1
slave_cnenable()
{
	/* FIXME: what to do here? */
}
#endif	NCPUS > 1

#if 0
void
kprintf( const char *format, ...)
{
        /* on PPC this outputs to the serial line */
        /* nop on intel ... umeshv@apple.com */

}
#endif

/*
 * Write message to console; create an alert panel if no text-type window
 * currently exists. Caller must call alert_done() when finished.
 * The height and width arguments are not used; they are provided for 
 * compatibility with the 68k version of alert().
 */
int 
alert(
	int width, 
	int height, 
	const char *title, 
	const char *msg, 
	int p1, 
	int p2, 
	int p3, 
	int p4, 
	int p5, 
	int p6, 
	int p7, 
	int p8)
{
	char smsg[200];
	
	sprintf(smsg, msg,  p1, p2, p3, p4, p5, p6, p7, p8);
#if FIXME  /* [ */
	/* DoAlert(title, smsg); */
#else
	printf("%s\n",smsg);
#endif  /* FIXME ] */

	return 0;
}

int 
alert_done()
{
	/* DoRestore(); */
	return 0;
}

