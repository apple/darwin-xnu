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
/* Copyright (c) 1997 Apple Computer, Inc. All Rights Reserved */
/*-
 * Copyright (c) 1982, 1986, 1991, 1993
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
 *	@(#)tty_tty.c	8.2 (Berkeley) 9/23/93
 */

/*
 * Indirect driver for controlling tty.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/ioctl.h>
#include <sys/proc.h>
#include <sys/tty.h>
#include <sys/vnode.h>
#include <sys/file.h>
#ifndef NeXT
#include <sys/kernel.h>
#ifdef DEVFS
#include <sys/devfsext.h>
#endif /*DEVFS*/

static	d_open_t	cttyopen;
static	d_read_t	cttyread;
static	d_write_t	cttywrite;
static	d_ioctl_t	cttyioctl;
static	d_select_t	cttyselect;

#define CDEV_MAJOR 1
/* Don't make static, fdesc_vnops uses this. */
struct cdevsw ctty_cdevsw = 
	{ cttyopen,	nullclose,	cttyread,	cttywrite,	/*1*/
	  cttyioctl,	nullstop,	nullreset,	nodevtotty,/* tty */
	  cttyselect,	nommap,		NULL,	"ctty",	NULL,	-1 };

#endif /* !NeXT */

#define cttyvp(p) ((p)->p_flag & P_CONTROLT ? (p)->p_session->s_ttyvp : NULL)

/*ARGSUSED*/
int
cttyopen(dev, flag, mode, p)
	dev_t dev;
	int flag, mode;
	struct proc *p;
{
	struct vnode *ttyvp = cttyvp(p);
	int error;

	if (ttyvp == NULL)
		return (ENXIO);
#ifndef NeXT
	VOP_LOCK(ttyvp);
#else
	/*
	 * This is the only place that NeXT Guarding has been used for
	 * VOP_.*LOCK style calls.  Note all of the other diffs should
	 * use the three paramater lock/unlock.
	 */
	vn_lock(ttyvp, LK_EXCLUSIVE | LK_RETRY, p);
#endif

#ifdef PARANOID
	/*
	 * Since group is tty and mode is 620 on most terminal lines
	 * and since sessions protect terminals from processes outside
	 * your session, this check is probably no longer necessary.
	 * Since it inhibits setuid root programs that later switch
	 * to another user from accessing /dev/tty, we have decided
	 * to delete this test. (mckusick 5/93)
	 */
	error = VOP_ACCESS(ttyvp,
	  (flag&FREAD ? VREAD : 0) | (flag&FWRITE ? VWRITE : 0), p->p_ucred, p);
	if (!error)
#endif /* PARANOID */
		error = VOP_OPEN(ttyvp, flag, NOCRED, p);
	VOP_UNLOCK(ttyvp, 0, p);
	return (error);
}

/*ARGSUSED*/
int
cttyread(dev, uio, flag)
	dev_t dev;
	struct uio *uio;
	int flag;
{
	struct proc *p = uio->uio_procp;
	register struct vnode *ttyvp = cttyvp(uio->uio_procp);
	int error;

	if (ttyvp == NULL)
		return (EIO);
	vn_lock(ttyvp, LK_EXCLUSIVE | LK_RETRY, p);
	error = VOP_READ(ttyvp, uio, flag, NOCRED);
	VOP_UNLOCK(ttyvp, 0, p);
	return (error);
}

/*ARGSUSED*/
int
cttywrite(dev, uio, flag)
	dev_t dev;
	struct uio *uio;
	int flag;
{
	struct proc *p = uio->uio_procp;
	register struct vnode *ttyvp = cttyvp(uio->uio_procp);
	int error;

	if (ttyvp == NULL)
		return (EIO);
	vn_lock(ttyvp, LK_EXCLUSIVE | LK_RETRY, p);
	error = VOP_WRITE(ttyvp, uio, flag, NOCRED);
	VOP_UNLOCK(ttyvp, 0, p);
	return (error);
}

/*ARGSUSED*/
#ifndef NeXT
static	int
cttyioctl(dev, cmd, addr, flag, p)
	dev_t dev;
	int cmd;
	caddr_t addr;
	int flag;
	struct proc *p;
#else
int
cttyioctl(dev, cmd, addr, flag, p)
	dev_t dev;
	u_long cmd;
	caddr_t addr;
	int flag;
	struct proc *p;
#endif /* !NeXT */
{
	struct vnode *ttyvp = cttyvp(p);

	if (ttyvp == NULL)
		return (EIO);
	if (cmd == TIOCSCTTY)  /* don't allow controlling tty to be set    */
		return EINVAL; /* to controlling tty -- infinite recursion */
	if (cmd == TIOCNOTTY) {
		if (!SESS_LEADER(p)) {
			p->p_flag &= ~P_CONTROLT;
			return (0);
		} else
			return (EINVAL);
	}
	return (VOP_IOCTL(ttyvp, cmd, addr, flag, NOCRED, p));
}

/*ARGSUSED*/
int
cttyselect(dev, flag, wql, p)
	dev_t dev;
	int flag;
	void * wql;
	struct proc *p;
{
	struct vnode *ttyvp = cttyvp(p);

	if (ttyvp == NULL)
		return (1);	/* try operation to get EOF/failure */
	return (VOP_SELECT(ttyvp, flag, FREAD|FWRITE, NOCRED, wql, p));
}

#ifndef NeXT
static ctty_devsw_installed = 0;
#ifdef DEVFS
static 	void	*ctty_devfs_token;
#endif

static void
ctty_drvinit(void *unused)
{
	dev_t dev;

	if( ! ctty_devsw_installed ) {
		dev = makedev(CDEV_MAJOR,0);
		cdevsw_add(&dev,&ctty_cdevsw,NULL);
		ctty_devsw_installed = 1;
#ifdef DEVFS
		ctty_devfs_token = 
			devfs_add_devswf(&ctty_cdevsw, 0, DV_CHR, 0, 0, 
					0666, "tty");
#endif
    	}
}

SYSINIT(cttydev,SI_SUB_DRIVERS,SI_ORDER_MIDDLE+CDEV_MAJOR,ctty_drvinit,NULL)


#endif /* !NeXT */
