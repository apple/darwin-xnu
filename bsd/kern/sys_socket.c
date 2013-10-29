/*
 * Copyright (c) 2000-2013 Apple Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1990, 1993
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
 *	@(#)sys_socket.c	8.1 (Berkeley) 6/10/93
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/file_internal.h>
#include <sys/event.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/filio.h>			/* XXX */
#include <sys/sockio.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/filedesc.h>
#include <sys/kauth.h>
#include <sys/signalvar.h>
#include <sys/vnode.h>

#include <net/if.h>
#include <net/route.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

/*
 * File operations on sockets.
 */
static int soo_read(struct fileproc *, struct uio *, int, vfs_context_t ctx);
static int soo_write(struct fileproc *, struct uio *, int, vfs_context_t ctx);
static int soo_close(struct fileglob *, vfs_context_t ctx);
static int soo_drain(struct fileproc *, vfs_context_t ctx);

const struct fileops socketops = {
	DTYPE_SOCKET,
	soo_read,
	soo_write,
	soo_ioctl,
	soo_select,
	soo_close,
	soo_kqfilter,
	soo_drain
};

/* ARGSUSED */
static int
soo_read(struct fileproc *fp, struct uio *uio, __unused int flags,
#if !CONFIG_MACF_SOCKET
	__unused
#endif
	vfs_context_t ctx)
{
	struct socket *so;
	int stat;
#if CONFIG_MACF_SOCKET
	int error;
#endif

	int (*fsoreceive)(struct socket *so2, struct sockaddr **paddr,
	    struct uio *uio2, struct mbuf **mp0, struct mbuf **controlp,
	    int *flagsp);

	if ((so = (struct socket *)fp->f_fglob->fg_data) == NULL) {
		/* This is not a valid open file descriptor */
		return (EBADF);
	}

#if CONFIG_MACF_SOCKET
	error = mac_socket_check_receive(vfs_context_ucred(ctx), so);
	if (error)
		return (error);
#endif /* CONFIG_MACF_SOCKET */

	fsoreceive = so->so_proto->pr_usrreqs->pru_soreceive;

	stat = (*fsoreceive)(so, 0, uio, 0, 0, 0);
	return (stat);
}

/* ARGSUSED */
static int
soo_write(struct fileproc *fp, struct uio *uio, __unused int flags,
	vfs_context_t ctx)
{
	struct socket *so;
	int stat;
	int (*fsosend)(struct socket *so2, struct sockaddr *addr,
	    struct uio *uio2, struct mbuf *top, struct mbuf *control,
	    int flags2);
	proc_t procp;

#if CONFIG_MACF_SOCKET
	int error;
#endif

	if ((so = (struct socket *)fp->f_fglob->fg_data) == NULL) {
		/* This is not a valid open file descriptor */
		return (EBADF);
	}

#if CONFIG_MACF_SOCKET
	/* JMM - have to fetch the socket's remote addr */
	error = mac_socket_check_send(vfs_context_ucred(ctx), so, NULL);
	if (error)
		return (error);
#endif /* CONFIG_MACF_SOCKET */

	fsosend = so->so_proto->pr_usrreqs->pru_sosend;

	stat = (*fsosend)(so, 0, uio, 0, 0, 0);

	/* Generation of SIGPIPE can be controlled per socket */
	procp = vfs_context_proc(ctx);
	if (stat == EPIPE && !(so->so_flags & SOF_NOSIGPIPE))
		psignal(procp, SIGPIPE);

	return (stat);
}

__private_extern__ int
soioctl(struct socket *so, u_long cmd, caddr_t data, struct proc *p)
{
	int error = 0;
	int int_arg;

	socket_lock(so, 1);

	/* call the socket filter's ioctl handler anything but ours */
	if (IOCGROUP(cmd) != 'i' && IOCGROUP(cmd) != 'r') {
		switch (cmd) {
		case SIOCGASSOCIDS32:
		case SIOCGASSOCIDS64:
		case SIOCGCONNIDS32:
		case SIOCGCONNIDS64:
		case SIOCGCONNINFO32:
		case SIOCGCONNINFO64:
		case SIOCSCONNORDER:
		case SIOCGCONNORDER:
			/* don't pass to filter */
			break;

		default:
			error = sflt_ioctl(so, cmd, data);
			if (error != 0)
				goto out;
			break;
		}
	}

	switch (cmd) {
	case FIONBIO:			/* int */
		bcopy(data, &int_arg, sizeof (int_arg));
		if (int_arg)
			so->so_state |= SS_NBIO;
		else
			so->so_state &= ~SS_NBIO;

		goto out;

	case FIOASYNC:			/* int */
		bcopy(data, &int_arg, sizeof (int_arg));
		if (int_arg) {
			so->so_state |= SS_ASYNC;
			so->so_rcv.sb_flags |= SB_ASYNC;
			so->so_snd.sb_flags |= SB_ASYNC;
		} else {
			so->so_state &= ~SS_ASYNC;
			so->so_rcv.sb_flags &= ~SB_ASYNC;
			so->so_snd.sb_flags &= ~SB_ASYNC;
		}
		goto out;

	case FIONREAD:			/* int */
		bcopy(&so->so_rcv.sb_cc, data, sizeof (u_int32_t));
		goto out;

	case SIOCSPGRP:			/* int */
		bcopy(data, &so->so_pgid, sizeof (pid_t));
		goto out;

	case SIOCGPGRP:			/* int */
		bcopy(&so->so_pgid, data, sizeof (pid_t));
		goto out;

	case SIOCATMARK:		/* int */
		int_arg = (so->so_state & SS_RCVATMARK) != 0;
		bcopy(&int_arg, data, sizeof (int_arg));
		goto out;

	case SIOCSETOT:			/* int; deprecated */
		error = EOPNOTSUPP;
		goto out;

	case SIOCGASSOCIDS32:		/* so_aidreq32 */
	case SIOCGASSOCIDS64:		/* so_aidreq64 */
	case SIOCGCONNIDS32:		/* so_cidreq32 */
	case SIOCGCONNIDS64:		/* so_cidreq64 */
	case SIOCGCONNINFO32:		/* so_cinforeq32 */
	case SIOCGCONNINFO64:		/* so_cinforeq64 */
	case SIOCSCONNORDER:		/* so_cordreq */
	case SIOCGCONNORDER:		/* so_cordreq */
		error = (*so->so_proto->pr_usrreqs->pru_control)(so,
		    cmd, data, NULL, p);
		goto out;
	}

	/*
	 * Interface/routing/protocol specific ioctls:
	 * interface and routing ioctls should have a
	 * different entry since a socket's unnecessary
	 */
	if (IOCGROUP(cmd) == 'i') {
		error = ifioctllocked(so, cmd, data, p);
	} else {
		if (IOCGROUP(cmd) == 'r')
			error = rtioctl(cmd, data, p);
		else
			error = (*so->so_proto->pr_usrreqs->pru_control)(so,
			    cmd, data, NULL, p);
	}

out:
	socket_unlock(so, 1);

	if (error == EJUSTRETURN)
		error = 0;

	return (error);
}

int
soo_ioctl(struct fileproc *fp, u_long cmd, caddr_t data, vfs_context_t ctx)
{
	struct socket *so;
	proc_t procp = vfs_context_proc(ctx);

	if ((so = (struct socket *)fp->f_fglob->fg_data) == NULL) {
		/* This is not a valid open file descriptor */
		return (EBADF);
	}

	return (soioctl(so, cmd, data, procp));
}

int
soo_select(struct fileproc *fp, int which, void *wql, vfs_context_t ctx)
{
	struct socket *so = (struct socket *)fp->f_fglob->fg_data;
	int retnum = 0;
	proc_t procp;

	if (so == NULL || so == (struct socket *)-1)
		return (0);

	procp = vfs_context_proc(ctx);

#if CONFIG_MACF_SOCKET
	if (mac_socket_check_select(vfs_context_ucred(ctx), so, which) != 0)
		return (0);
#endif /* CONFIG_MACF_SOCKET */


	socket_lock(so, 1);
	switch (which) {

	case FREAD:
		so->so_rcv.sb_flags |= SB_SEL;
		if (soreadable(so)) {
			retnum = 1;
			so->so_rcv.sb_flags &= ~SB_SEL;
			goto done;
		}
		selrecord(procp, &so->so_rcv.sb_sel, wql);
		break;

	case FWRITE:
		so->so_snd.sb_flags |= SB_SEL;
		if (sowriteable(so)) {
			retnum = 1;
			so->so_snd.sb_flags &= ~SB_SEL;
			goto done;
		}
		selrecord(procp, &so->so_snd.sb_sel, wql);
		break;

	case 0:
		so->so_rcv.sb_flags |= SB_SEL;
		if (so->so_oobmark || (so->so_state & SS_RCVATMARK)) {
			retnum = 1;
			so->so_rcv.sb_flags &= ~SB_SEL;
			goto done;
		}
		selrecord(procp, &so->so_rcv.sb_sel, wql);
		break;
	}

done:
	socket_unlock(so, 1);
	return (retnum);
}

int
soo_stat(struct socket *so, void *ub, int isstat64)
{
	int ret;
	/* warning avoidance ; protected by isstat64 */
	struct stat *sb = (struct stat *)0;
	/* warning avoidance ; protected by isstat64 */
	struct stat64 *sb64 = (struct stat64 *)0;

#if CONFIG_MACF_SOCKET
	ret = mac_socket_check_stat(kauth_cred_get(), so);
	if (ret)
		return (ret);
#endif

	if (isstat64 != 0) {
		sb64 = (struct stat64 *)ub;
		bzero((caddr_t)sb64, sizeof (*sb64));
	} else {
		sb = (struct stat *)ub;
		bzero((caddr_t)sb, sizeof (*sb));
	}

	socket_lock(so, 1);
	if (isstat64 != 0) {
		sb64->st_mode = S_IFSOCK;
		if ((so->so_state & SS_CANTRCVMORE) == 0 ||
		    so->so_rcv.sb_cc != 0)
			sb64->st_mode |= S_IRUSR | S_IRGRP | S_IROTH;
		if ((so->so_state & SS_CANTSENDMORE) == 0)
			sb64->st_mode |= S_IWUSR | S_IWGRP | S_IWOTH;
		sb64->st_size = so->so_rcv.sb_cc - so->so_rcv.sb_ctl;
		sb64->st_uid = kauth_cred_getuid(so->so_cred);
		sb64->st_gid = kauth_cred_getgid(so->so_cred);
	} else {
		sb->st_mode = S_IFSOCK;
		if ((so->so_state & SS_CANTRCVMORE) == 0 ||
		    so->so_rcv.sb_cc != 0)
			sb->st_mode |= S_IRUSR | S_IRGRP | S_IROTH;
		if ((so->so_state & SS_CANTSENDMORE) == 0)
			sb->st_mode |= S_IWUSR | S_IWGRP | S_IWOTH;
		sb->st_size = so->so_rcv.sb_cc - so->so_rcv.sb_ctl;
		sb->st_uid = kauth_cred_getuid(so->so_cred);
		sb->st_gid = kauth_cred_getgid(so->so_cred);
	}

	ret = (*so->so_proto->pr_usrreqs->pru_sense)(so, ub, isstat64);
	socket_unlock(so, 1);
	return (ret);
}

/* ARGSUSED */
static int
soo_close(struct fileglob *fg, __unused vfs_context_t ctx)
{
	int error = 0;
	struct socket *sp;

	sp = (struct socket *)fg->fg_data;
	fg->fg_data = NULL;

	if (sp)
		error = soclose(sp);

	return (error);
}

static int
soo_drain(struct fileproc *fp, __unused vfs_context_t ctx)
{
	int error = 0;
	struct socket *so = (struct socket *)fp->f_fglob->fg_data;

	if (so) {
		socket_lock(so, 1);
		so->so_state |= SS_DRAINING;

		wakeup((caddr_t)&so->so_timeo);
		sorwakeup(so);
		sowwakeup(so);
		soevent(so, SO_FILT_HINT_LOCKED);

		socket_unlock(so, 1);
	}

	return (error);
}

/*
 * 's' group ioctls.
 *
 * The switch statement below does nothing at runtime, as it serves as a
 * compile time check to ensure that all of the socket 's' ioctls (those
 * in the 's' group going thru soo_ioctl) that are made available by the
 * networking stack is unique.  This works as long as this routine gets
 * updated each time a new interface ioctl gets added.
 *
 * Any failures at compile time indicates duplicated ioctl values.
 */
static __attribute__((unused)) void
soioctl_cassert(void)
{
	/*
	 * This is equivalent to _CASSERT() and the compiler wouldn't
	 * generate any instructions, thus for compile time only.
	 */
	switch ((u_long)0) {
	case 0:

	/* bsd/sys/sockio.h */
	case SIOCSHIWAT:
	case SIOCGHIWAT:
	case SIOCSLOWAT:
	case SIOCGLOWAT:
	case SIOCATMARK:
	case SIOCSPGRP:
	case SIOCGPGRP:
	case SIOCSETOT:
	case SIOCGASSOCIDS32:
	case SIOCGASSOCIDS64:
	case SIOCGCONNIDS32:
	case SIOCGCONNIDS64:
	case SIOCGCONNINFO32:
	case SIOCGCONNINFO64:
	case SIOCSCONNORDER:
	case SIOCGCONNORDER:
		;
	}
}
