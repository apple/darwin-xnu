/*
 * Copyright (c) 2000-2011 Apple Inc. All rights reserved.
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

/* TODO: these should be in header file */
extern int soo_ioctl(struct fileproc *, u_long, caddr_t, vfs_context_t ctx);
extern int soo_stat(struct socket *, void *, int);
extern int soo_select(struct fileproc *, int, void *, vfs_context_t ctx);
extern int soo_kqfilter(struct fileproc *, struct knote *, vfs_context_t ctx);

struct fileops socketops = {
	soo_read, soo_write, soo_ioctl, soo_select, soo_close,
	soo_kqfilter, soo_drain
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

//###LD will have to change
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
	int dropsockref = -1;

	socket_lock(so, 1);

	/* Call the socket filter's ioctl handler for most ioctls */
	if (IOCGROUP(cmd) != 'i' && IOCGROUP(cmd) != 'r') {
		error = sflt_ioctl(so, cmd, data);
		if (error != 0)
			goto out;
	}

	switch (cmd) {

	case FIONBIO:
		if (*(int *)data)
			so->so_state |= SS_NBIO;
		else
			so->so_state &= ~SS_NBIO;

		goto out;

	case FIOASYNC:
		if (*(int *)data) {
			so->so_state |= SS_ASYNC;
			so->so_rcv.sb_flags |= SB_ASYNC;
			so->so_snd.sb_flags |= SB_ASYNC;
		} else {
			so->so_state &= ~SS_ASYNC;
			so->so_rcv.sb_flags &= ~SB_ASYNC;
			so->so_snd.sb_flags &= ~SB_ASYNC;
		}
		goto out;

	case FIONREAD:
		*(int *)data = so->so_rcv.sb_cc;
		goto out;

	case SIOCSPGRP:
		so->so_pgid = *(int *)data;
		goto out;

	case SIOCGPGRP:
		*(int *)data = so->so_pgid;
		goto out;

	case SIOCATMARK:
		*(int *)data = (so->so_state&SS_RCVATMARK) != 0;
		goto out;

	case SIOCSETOT: {
		/*
		 * Set socket level options here and then call protocol
		 * specific routine.
		 */
		struct socket *cloned_so = NULL;
		int cloned_fd = *(int *)data;

		/* let's make sure it's either -1 or a valid file descriptor */
		if (cloned_fd != -1) {
			error = file_socket(cloned_fd, &cloned_so);
			if (error) {
				goto out;
			}
			dropsockref = cloned_fd;
		}

		/* Always set socket non-blocking for OT */
		so->so_state |= SS_NBIO;
		so->so_options |= SO_DONTTRUNC | SO_WANTMORE;
		so->so_flags |= SOF_NOSIGPIPE | SOF_NPX_SETOPTSHUT;

		if (cloned_so && so != cloned_so) {
			/* Flags options */
			so->so_options |=
			    cloned_so->so_options & ~SO_ACCEPTCONN;

			/* SO_LINGER */
			if (so->so_options & SO_LINGER)
				so->so_linger = cloned_so->so_linger;

			/* SO_SNDBUF, SO_RCVBUF */
			if (cloned_so->so_snd.sb_hiwat > 0) {
				if (sbreserve(&so->so_snd,
				    cloned_so->so_snd.sb_hiwat) == 0) {
					error = ENOBUFS;
					goto out;
				}
			}
			if (cloned_so->so_rcv.sb_hiwat > 0) {
				if (sbreserve(&so->so_rcv,
				    cloned_so->so_rcv.sb_hiwat) == 0) {
					error = ENOBUFS;
					goto out;
				}
			}

			/* SO_SNDLOWAT, SO_RCVLOWAT */
			so->so_snd.sb_lowat =
			    (cloned_so->so_snd.sb_lowat > so->so_snd.sb_hiwat) ?
			    so->so_snd.sb_hiwat : cloned_so->so_snd.sb_lowat;
			so->so_rcv.sb_lowat =
			    (cloned_so->so_rcv.sb_lowat > so->so_rcv.sb_hiwat) ?
			    so->so_rcv.sb_hiwat : cloned_so->so_rcv.sb_lowat;

			/* SO_SNDTIMEO, SO_RCVTIMEO */
			so->so_snd.sb_timeo = cloned_so->so_snd.sb_timeo;
			so->so_rcv.sb_timeo = cloned_so->so_rcv.sb_timeo;
		}

		error = (*so->so_proto->pr_usrreqs->pru_control)(so, cmd,
		    data, 0, p);
		/* Just ignore protocols that do not understand it */
		if (error == EOPNOTSUPP)
			error = 0;

		goto out;
	}
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
			    cmd, data, 0, p);
	}

out:
	if (dropsockref != -1)
		file_drop(dropsockref);
	socket_unlock(so, 1);

	if (error == EJUSTRETURN)
		error = 0;

	return (error);
}

int
soo_ioctl(struct fileproc *fp, u_long cmd, caddr_t data, vfs_context_t ctx)
{
	struct socket *so;
	int error;
	proc_t procp = vfs_context_proc(ctx);

	if ((so = (struct socket *)fp->f_fglob->fg_data) == NULL) {
		/* This is not a valid open file descriptor */
		return (EBADF);
	}

	error = soioctl(so, cmd, data, procp);

	if (error == 0 && cmd == SIOCSETOT)
		fp->f_fglob->fg_flag |= FNONBLOCK;

	return (error);
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
	if (mac_socket_check_select(vfs_context_ucred(ctx), so, which) != 0);
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
		sb64->st_uid = so->so_uid;
		sb64->st_gid = so->so_gid;
	} else {
		sb->st_mode = S_IFSOCK;
		if ((so->so_state & SS_CANTRCVMORE) == 0 ||
		    so->so_rcv.sb_cc != 0)
			sb->st_mode |= S_IRUSR | S_IRGRP | S_IROTH;
		if ((so->so_state & SS_CANTSENDMORE) == 0)
			sb->st_mode |= S_IWUSR | S_IWGRP | S_IWOTH;
		sb->st_size = so->so_rcv.sb_cc - so->so_rcv.sb_ctl;
		sb->st_uid = so->so_uid;
		sb->st_gid = so->so_gid;
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

		socket_unlock(so, 1);
	}

	return (error);
}
