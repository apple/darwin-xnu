/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 *	Copyright (c) 1998 Apple Computer, Inc. 
 */

/*	at_proto.c
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/mbuf.h>

#include <sys/sysctl.h>

#include <net/if.h>

#include <netat/appletalk.h>
#include <netat/at_var.h>
#include <netat/ddp.h>

struct domain atalkdomain;

extern int	ddp_pru_abort(struct socket *so);

extern int	ddp_pru_attach(struct socket *so, int proto,
			       struct proc *p);
extern int	ddp_pru_bind(struct socket *so, struct sockaddr *nam,
			     struct proc *p);
extern int	ddp_pru_connect(struct socket *so, struct sockaddr *nam,
				struct proc *p);

extern int	ddp_pru_control(struct socket *so, u_long cmd, caddr_t data,
				struct ifnet *ifp, struct proc *p);
extern int	ddp_pru_detach(struct socket *so);
extern int	ddp_pru_disconnect(struct socket *so);

extern int	ddp_pru_peeraddr(struct socket *so, 
				 struct sockaddr **nam);

extern int	ddp_pru_send(struct socket *so, int flags, struct mbuf *m, 
				 struct sockaddr *addr, struct mbuf *control,
				 struct proc *p);

extern int	ddp_pru_shutdown(struct socket *so);
extern int	ddp_pru_sockaddr(struct socket *so, 
				 struct sockaddr **nam);

/*
 * Dummy usrreqs struct created by Ted for FreeBSD 3.x integration. 
 * Fill in supported functions as appropriate.
 */
struct pr_usrreqs ddp_usrreqs = {
	ddp_pru_abort,  pru_accept_notsupp, ddp_pru_attach, ddp_pru_bind,
	ddp_pru_connect, pru_connect2_notsupp, ddp_pru_control, ddp_pru_detach,
	ddp_pru_disconnect, pru_listen_notsupp, ddp_pru_peeraddr, pru_rcvd_notsupp,
	pru_rcvoob_notsupp, ddp_pru_send, pru_sense_null, ddp_pru_shutdown,
	ddp_pru_sockaddr, sosend, soreceive, sopoll
};

struct protosw atalksw[] = {
  { SOCK_RAW,	&atalkdomain,	/*protocol*/ 0,	PR_ATOMIC|PR_ADDR,
    /*input*/ 0, /*output*/ 0, /*clinput*/ 0, ddp_ctloutput,
    /*ousrreq*/ 0, 
    ddp_init, /*fastto*/ 0, /*slowto*/ 0, /*drain*/ 0, 
    /*sysctl*/ 0, &ddp_usrreqs
  }
};

struct domain atalkdomain =
{ AF_APPLETALK, "appletalk", 0, 0, 0, 
  atalksw, 0,
  0, 0, 0,
  DDP_X_HDR_SIZE, 0
};

SYSCTL_NODE(_net, PF_APPLETALK, appletalk, CTLFLAG_RW, 0, "AppleTalk Family");

