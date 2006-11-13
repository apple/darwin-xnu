/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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

#include <net/if.h>
#include <net/route.h>

/*
 * File operations on sockets.
 */
int	soo_read(struct fileproc *fp, struct uio *uio, kauth_cred_t cred,
		int flags, struct proc *p);
int	soo_write(struct fileproc *fp, struct uio *uio, kauth_cred_t cred,
		int flags, struct proc *p);
int soo_close(struct fileglob *fp, struct proc *p);
int	soo_ioctl(struct fileproc *fp, u_long cmd, caddr_t data, struct proc *p);
int	soo_stat(struct socket *so, struct stat *ub);
int	soo_select(struct fileproc *fp, int which, void * wql, struct proc *p);
int     soo_kqfilter(struct fileproc *fp, struct knote *kn, struct proc *p);
int	soo_drain(struct fileproc *fp, struct proc *p);

struct	fileops socketops =
    { soo_read, soo_write, soo_ioctl, soo_select, soo_close, soo_kqfilter, soo_drain };

/* ARGSUSED */
int
soo_read(
	struct fileproc *fp,
	struct uio *uio,
	__unused kauth_cred_t cred,
	__unused int flags,
	__unused struct proc *p)
{
	struct socket *so;
	int stat;
	int (*fsoreceive)(struct socket *so2, 
			       struct sockaddr **paddr,
			       struct uio *uio2, struct mbuf **mp0,
			       struct mbuf **controlp, int *flagsp);



        if ((so = (struct socket *)fp->f_fglob->fg_data) == NULL) {
                /* This is not a valid open file descriptor */
		return(EBADF);
        }
//###LD will have to change
	fsoreceive = so->so_proto->pr_usrreqs->pru_soreceive;
	
	stat = (*fsoreceive)(so, 0, uio, 0, 0, 0);
	return stat;
}

/* ARGSUSED */
int
soo_write(
	struct fileproc *fp,
	struct uio *uio,
	__unused kauth_cred_t cred,
	__unused int flags,
	struct proc *procp)
{
	struct socket *so;
	int	(*fsosend)(struct socket *so2, struct sockaddr *addr,
				struct uio *uio2, struct mbuf *top,
				struct mbuf *control, int flags2);
	int           stat;

	if ((so = (struct socket *)fp->f_fglob->fg_data) == NULL) {
		/* This is not a valid open file descriptor */
		return (EBADF);
	}

	fsosend = so->so_proto->pr_usrreqs->pru_sosend;

	stat = (*fsosend)(so, 0, uio, 0, 0, 0);

	/* Generation of SIGPIPE can be controlled per socket */
	if (stat == EPIPE && procp && !(so->so_flags & SOF_NOSIGPIPE))
		psignal(procp, SIGPIPE);

	return stat;
}

__private_extern__ int
soioctl(
	struct socket *so,
	u_long cmd,
	caddr_t data,
	struct proc *p)
{
	struct sockopt sopt;
	int    error = 0;
	int dropsockref = -1;


	socket_lock(so, 1);

	sopt.sopt_level = cmd;
	sopt.sopt_name = (int)data;
	sopt.sopt_p = p;

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
	     struct socket	*cloned_so = NULL;
	     int				cloned_fd = *(int *)data;

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
          so->so_flags |= SOF_NOSIGPIPE;

	     if (cloned_so && so != cloned_so) {
		  /* Flags options */
		  so->so_options |= cloned_so->so_options & ~SO_ACCEPTCONN;

            /* SO_LINGER */
            if (so->so_options & SO_LINGER)
                so->so_linger = cloned_so->so_linger;

            /* SO_SNDBUF, SO_RCVBUF */
		  if (cloned_so->so_snd.sb_hiwat > 0) {
		       if (sbreserve(&so->so_snd, cloned_so->so_snd.sb_hiwat) == 0) {
			    error = ENOBUFS;
			    goto out;
		       }
		  }
		  if (cloned_so->so_rcv.sb_hiwat > 0) {
		       if (sbreserve(&so->so_rcv, cloned_so->so_rcv.sb_hiwat) == 0) {
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

	     error = (*so->so_proto->pr_usrreqs->pru_control)(so, cmd, data, 0, p);
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
	if (IOCGROUP(cmd) == 'i')
	     error = ifioctllocked(so, cmd, data, p);
	else 
	     if (IOCGROUP(cmd) == 'r')
		  error = rtioctl(cmd, data, p);
	     else
		  error = (*so->so_proto->pr_usrreqs->pru_control)(so, cmd, data, 0, p);

out:
	if (dropsockref != -1)
		file_drop(dropsockref);
	socket_unlock(so, 1);

	return error;
}

int
soo_ioctl(fp, cmd, data, p)
	struct fileproc *fp;
	u_long cmd;
	register caddr_t data;
	struct proc *p;
{
	register struct socket *so;
	int error;


	if ((so = (struct socket *)fp->f_fglob->fg_data) == NULL) {
		/* This is not a valid open file descriptor */
		return (EBADF);
	}
	
	error = soioctl(so, cmd, data, p);
	
	if (error == 0 && cmd == SIOCSETOT)
		fp->f_fglob->fg_flag |= FNONBLOCK;

	return error;
}

int
soo_select(fp, which, wql, p)
	struct fileproc *fp;
	int which;
	void * wql;
	struct proc *p;
{
	register struct socket *so = (struct socket *)fp->f_fglob->fg_data;
	int retnum=0;

	if (so == NULL || so == (struct socket*)-1)
		return (0);

	socket_lock(so, 1);
	switch (which) {

	case FREAD:
		so->so_rcv.sb_flags |= SB_SEL;
		if (soreadable(so)) {
			retnum = 1;
			so->so_rcv.sb_flags &= ~SB_SEL;
			goto done;
		}
		selrecord(p, &so->so_rcv.sb_sel, wql);
		break;

	case FWRITE:
		so->so_snd.sb_flags |= SB_SEL;
		if (sowriteable(so)) {
			retnum = 1;
			so->so_snd.sb_flags &= ~SB_SEL;
			goto done;
		}
		selrecord(p, &so->so_snd.sb_sel, wql);
		break;

	case 0:
		so->so_rcv.sb_flags |= SB_SEL;
		if (so->so_oobmark || (so->so_state & SS_RCVATMARK)) {
			retnum = 1;
			so->so_rcv.sb_flags &= ~SB_SEL;
			goto done;
		}
		selrecord(p, &so->so_rcv.sb_sel, wql);
		break;
	}
	
done:
	socket_unlock(so, 1);
	return (retnum);
}


int
soo_stat(so, ub)
	register struct socket *so;
	register struct stat *ub;
{
	int stat;

	bzero((caddr_t)ub, sizeof (*ub));
	socket_lock(so, 1);
	ub->st_mode = S_IFSOCK;
	stat = (*so->so_proto->pr_usrreqs->pru_sense)(so, ub);
	socket_unlock(so, 1);
	return stat;
}

/* ARGSUSED */
int
soo_close(struct fileglob *fg, __unused proc_t p)
{
	int error = 0;
	struct socket *sp;

	sp = (struct socket *)fg->fg_data;
	fg->fg_data = NULL;


	if (sp)
	     error = soclose(sp);


	return (error);
}

int
soo_drain(struct fileproc *fp, __unused struct proc *p)
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

	return error;
}

