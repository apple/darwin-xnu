/*
 * Copyright (c) 1997-2013 Apple Computer, Inc. All rights reserved.
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
#include <sys/proc_internal.h>
#include <sys/tty.h>
#include <sys/vnode_internal.h>
#include <sys/file_internal.h>
#include <sys/kauth.h>

/* Forward declarations for cdevsw[] entry */
/* XXX we should consider making these static */
int cttyopen(dev_t dev, int flag, int mode, proc_t p);
int cttyread(dev_t dev, struct uio *uio, int flag);
int cttywrite(dev_t dev, struct uio *uio, int flag);
int cttyioctl(dev_t dev, u_long cmd, caddr_t addr, int flag, proc_t p);
int cttyselect(dev_t dev, int flag, void* wql, proc_t p);
static vnode_t cttyvp(proc_t p);

int
cttyopen(dev_t dev, int flag, __unused int mode, proc_t p)
{
	vnode_t ttyvp = cttyvp(p);
	struct vfs_context context;
	int error = 0;
	int cttyflag, doclose = 0;
	struct session *sessp;

	if (ttyvp == NULL) {
		return ENXIO;
	}

	context.vc_thread = current_thread();
	context.vc_ucred = kauth_cred_proc_ref(p);

	sessp = proc_session(p);
	session_lock(sessp);
	cttyflag = sessp->s_flags & S_CTTYREF;
	session_unlock(sessp);

	/*
	 * A little hack--this device, used by many processes,
	 * happens to do an open on another device, which can
	 * cause unhappiness if the second-level open blocks indefinitely
	 * (as could be the case if the master side has hung up).  Since
	 * we know that this driver doesn't care about the serializing
	 * opens and closes, we can drop the lock. To avoid opencount leak,
	 * open the vnode only for the first time.
	 */
	if (cttyflag == 0) {
		devsw_unlock(dev, S_IFCHR);
		error = VNOP_OPEN(ttyvp, flag, &context);
		devsw_lock(dev, S_IFCHR);

		if (error) {
			goto out;
		}

		/*
		 * If S_CTTYREF is set, some other thread did an open
		 * and was able to set the flag, now perform a close, else
		 * set the flag.
		 */
		session_lock(sessp);
		if (cttyflag == (sessp->s_flags & S_CTTYREF)) {
			sessp->s_flags |= S_CTTYREF;
		} else {
			doclose = 1;
		}
		session_unlock(sessp);

		/*
		 * We have to take a reference here to make sure a close
		 * gets called during revoke. Note that once a controlling
		 * tty gets opened by this driver, the only way close will
		 * get called is when the session leader , whose controlling
		 * tty is ttyvp, exits and vnode is revoked. We cannot
		 * redirect close from this driver because underlying controlling
		 * terminal might change and close may get redirected to a
		 * wrong vnode causing panic.
		 */
		if (doclose) {
			devsw_unlock(dev, S_IFCHR);
			VNOP_CLOSE(ttyvp, flag, &context);
			devsw_lock(dev, S_IFCHR);
		} else {
			error = vnode_ref(ttyvp);
		}
	}
out:
	session_rele(sessp);

	vnode_put(ttyvp);
	kauth_cred_unref(&context.vc_ucred);

	return error;
}

int
cttyread(__unused dev_t dev, struct uio *uio, int flag)
{
	vnode_t ttyvp = cttyvp(current_proc());
	struct vfs_context context;
	int error;

	if (ttyvp == NULL) {
		return EIO;
	}

	context.vc_thread = current_thread();
	context.vc_ucred = NOCRED;

	error = VNOP_READ(ttyvp, uio, flag, &context);
	vnode_put(ttyvp);

	return error;
}

int
cttywrite(__unused dev_t dev, struct uio *uio, int flag)
{
	vnode_t ttyvp = cttyvp(current_proc());
	struct vfs_context context;
	int error;

	if (ttyvp == NULL) {
		return EIO;
	}

	context.vc_thread = current_thread();
	context.vc_ucred = NOCRED;

	error = VNOP_WRITE(ttyvp, uio, flag, &context);
	vnode_put(ttyvp);

	return error;
}

int
cttyioctl(__unused dev_t dev, u_long cmd, caddr_t addr, int flag, proc_t p)
{
	vnode_t ttyvp = cttyvp(current_proc());
	struct vfs_context context;
	struct session *sessp;
	int error = 0;

	if (ttyvp == NULL) {
		return EIO;
	}
	if (cmd == TIOCSCTTY) {  /* don't allow controlling tty to be set    */
		error = EINVAL; /* to controlling tty -- infinite recursion */
		goto out;
	}
	if (cmd == TIOCNOTTY) {
		sessp = proc_session(p);
		if (!SESS_LEADER(p, sessp)) {
			OSBitAndAtomic(~((uint32_t)P_CONTROLT), &p->p_flag);
			if (sessp != SESSION_NULL) {
				session_rele(sessp);
			}
			error = 0;
			goto out;
		} else {
			if (sessp != SESSION_NULL) {
				session_rele(sessp);
			}
			error = EINVAL;
			goto out;
		}
	}
	context.vc_thread = current_thread();
	context.vc_ucred = NOCRED;

	error = VNOP_IOCTL(ttyvp, cmd, addr, flag, &context);
out:
	vnode_put(ttyvp);
	return error;
}

int
cttyselect(__unused dev_t dev, int flag, void* wql, __unused proc_t p)
{
	vnode_t ttyvp = cttyvp(current_proc());
	struct vfs_context context;
	int error;

	context.vc_thread = current_thread();
	context.vc_ucred = NOCRED;

	if (ttyvp == NULL) {
		return 1;     /* try operation to get EOF/failure */
	}
	error = VNOP_SELECT(ttyvp, flag, FREAD | FWRITE, wql, &context);
	vnode_put(ttyvp);
	return error;
}

/* This returns vnode with ioref */
static vnode_t
cttyvp(proc_t p)
{
	vnode_t vp;
	int vid;
	struct session *sessp;

	sessp = proc_session(p);

	session_lock(sessp);
	vp = (p->p_flag & P_CONTROLT ? sessp->s_ttyvp : NULLVP);
	vid = sessp->s_ttyvid;
	session_unlock(sessp);

	session_rele(sessp);

	if (vp != NULLVP) {
		/* cannot get an IO reference, return NULLVP */
		if (vnode_getwithvid(vp, vid) != 0) {
			vp = NULLVP;
		}
	}
	return vp;
}
