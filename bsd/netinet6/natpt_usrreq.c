/*	$KAME: natpt_usrreq.c,v 1.9 2000/03/25 07:23:57 sumikawa Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
/*	FreeBSD330 compiler complain that do not #include ioctl.h in the kernel,	*/
/*	Include xxxio.h instead								*/
/*	#include <sys/ioctl.h>	*/
#include <sys/ioccom.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3 || defined (__APPLE__)
#include <sys/proc.h>
#endif
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include <net/if.h>
#include <net/raw_cb.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>

#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_log.h>
#include <netinet6/natpt_soctl.h>
#include <netinet6/natpt_var.h>


/*
 *
 */

#define	NATPTSNDQ		(8192)
#define	NATPTRCVQ		(8192)

u_long	natpt_sendspace = NATPTSNDQ;
u_long	natpt_recvspace = NATPTRCVQ;

#if defined(__bsdi__) || defined(__FreeBSD__) && __FreeBSD__ <= 2
static struct rawcb		ptrcb;
#else
LIST_HEAD(, rawcb)		ptrcb;
#endif

static struct sockaddr	natpt_dst = {2, PF_INET};
#ifdef notused
static struct sockaddr	natpt_src = {2, PF_INET};
#endif

#if	0
int	natpt_sosetopt	__P((struct socket *, int, struct mbuf *));
int	natpt_sogetopt	__P((struct socket *, int, struct mbuf *));
#endif

static	int	_natptSetIf	__P((caddr_t));
static	int	_natptGetIf	__P((caddr_t));
static	int	_natptSetValue	__P((caddr_t));
static	int	_natptTestLog	__P((caddr_t));

void	natpt_init	__P((void));

#ifdef __bsdi__
int	natpt_usrreq	__P((struct socket *, int,
			     struct mbuf *, struct mbuf *, struct mbuf *));
#elif defined(__NetBSD__)
int	natpt_usrreq	__P((struct socket *, int,
			     struct mbuf *, struct mbuf *, struct mbuf *, struct proc *));
#endif	/* defined(__bsdi__) || defined(__NetBSD__)	*/


#if defined(__FreeBSD__) && __FreeBSD__ >= 3 || defined (__APPLE__)
int	natpt_uabort	__P((struct socket *));
int	natpt_uattach	__P((struct socket *, int, struct proc *));
int	natpt_ubind	__P((struct socket *, struct sockaddr *, struct proc *));
int	natpt_uconnect	__P((struct socket *, struct sockaddr *, struct proc *));
int	natpt_udetach	__P((struct socket *));
int	natpt_ucontrol	__P((struct socket *, u_long, caddr_t, struct ifnet *, struct proc *));
#endif	/* defined(__FreeBSD__) && __FreeBSD__ >= 3	*/

int	natpt_attach	 __P((struct socket *, int));
int	natpt_control	 __P((struct socket *, int, caddr_t, struct ifnet *));
int	natpt_detach	 __P((struct socket *));
int	natpt_disconnect __P((struct socket *));


#ifdef __FreeBSD__
#if __FreeBSD__ >= 3
struct pr_usrreqs natpt_usrreqs =
{
    natpt_uabort,	NULL,		natpt_uattach,	natpt_ubind,
    natpt_uconnect,	NULL,		natpt_ucontrol,	natpt_udetach,
    natpt_disconnect,	NULL,		NULL,		NULL,
    NULL,		NULL,		NULL,		NULL,
    NULL,		sosend,		soreceive,	sopoll
};
#else
struct pr_usrreqs natpt_usrreqs =
{
    NULL,		NULL,		natpt_attach,	NULL,
    NULL,		NULL,		natpt_control,	natpt_detach,
    natpt_disconnect,	NULL,		NULL,		NULL,
    NULL,		NULL,		NULL,		NULL,
    NULL
};
#endif	/* __FreeBSD__ >= 3 */
#endif	/* __FreeBSD__      */


/*
 *
 */

void
natpt_init()
{
    natpt_initialized = 0;
    ip6_protocol_tr = 0;

    init_tslot();

#if defined(__bsdi__) || defined(__FreeBSD__) && __FreeBSD__ <= 2
    ptrcb.rcb_next = ptrcb.rcb_prev = &ptrcb;
#else
    LIST_INIT(&ptrcb);
#endif

    printf("NATPT: initialized.\n");
}


void
natpt_input(struct mbuf *m0, struct sockproto *proto,
	 struct sockaddr *src, struct sockaddr *dst)
{
    struct rawcb	*rp;
    struct mbuf		*m = m0;
    struct socket	*last;
    int	sockets;

    last = 0;
#if defined(__bsdi__) || defined(__FreeBSD__) && __FreeBSD__ <= 2
    for (rp = ptrcb.rcb_next; rp != &ptrcb; rp = rp->rcb_next)
#else
    for (rp = ptrcb.lh_first; rp != 0; rp = rp->rcb_list.le_next)
#endif
    {
	if (rp->rcb_proto.sp_family != proto->sp_family)
	    continue;
	if (rp->rcb_proto.sp_protocol
	    && (rp->rcb_proto.sp_protocol != proto->sp_protocol))
	    continue;

#define	equal(a1, a2)	(bcmp((caddr_t)(a1), (caddr_t)(a2), a1->sa_len) == 0)

	if (rp->rcb_laddr && !equal(rp->rcb_laddr, dst))
	    continue;
	if (rp->rcb_faddr && !equal(rp->rcb_faddr, src))
	    continue;

	if (last)
	{
	    struct mbuf *n;

	    if ((n = m_copy(m, 0, (int)M_COPYALL)) != NULL)
	    {
		if (sbappendaddr(&last->so_rcv, src, n, (struct mbuf *)NULL) == 0)
		    m_freem(n);		/* should notify about lost packet */
		else
		{
		    sorwakeup(last);
		    sockets++;
		}
	    }
	}
	last = rp->rcb_socket;
    }

    if (last)
    {
	if (sbappendaddr(&last->so_rcv, src, m, (struct mbuf *)NULL) == 0)
	    m_freem(m);
	else
	{
	    sorwakeup(last);
	    sockets++;
	}
    }
    else
	m_freem(m);
}


#if defined(__bsdi__) || defined(__NetBSD__)
int
natpt_usrreq(struct socket *so, int req,
	     struct mbuf *m, struct mbuf *nam, struct mbuf *control
#ifdef __NetBSD__
	     ,struct proc *p
#endif
	     )
{
    struct rawcb	*rp = sotorawcb(so);
    int			 error = 0;

    if ((rp == NULL) && (req != PRU_ATTACH))
    {
	m_freem(m);
	return (EINVAL);
    }

    switch (req)
    {
      case PRU_ATTACH:
	error = natpt_attach(so, (int)nam);
	break;

      case PRU_DETACH:
	error = natpt_detach(so);
	break;

      case PRU_DISCONNECT:
	if (rp->rcb_faddr == NULL)
	{
	    error = ENOTCONN;
	    break;
	}
	rp->rcb_faddr = NULL;
	raw_disconnect(rp);
	soisdisconnected(so);
	break;

      case PRU_SEND:
      case PRU_BIND:
      case PRU_LISTEN:
      case PRU_CONNECT:
      case PRU_ACCEPT:
      case PRU_SHUTDOWN:
      case PRU_RCVD:
      case PRU_ABORT:
	error = EOPNOTSUPP;
	break;

      case PRU_CONTROL:
	error = natpt_control(so, (int)m, (caddr_t)nam, (struct ifnet *)NULL);
	return (error);
	break;

      case PRU_SENSE:
      case PRU_RCVOOB:
      case PRU_SENDOOB:
      case PRU_SOCKADDR:
      case PRU_PEERADDR:
      case PRU_CONNECT2:
      case PRU_FASTTIMO:
      case PRU_SLOWTIMO:
      case PRU_PROTORCV:
      case PRU_PROTOSEND:
	error = EOPNOTSUPP;
	break;

      default:
	panic("raw_usrreq");
    }

    if (m != NULL)
	m_freem(m);

    return (error);
}
#endif	/* defined(__bsdi__) || defined(__NetBSD__)	*/


#if defined(__FreeBSD__) && __FreeBSD__ >= 3 || defined (__APPLE__)
int
natpt_uabort(struct socket *so)
{
    struct rawcb *rp = sotorawcb(so);

    if (rp == 0)
	return (EINVAL);

    raw_disconnect(rp);
    sofree(so);
    soisdisconnected(so);

    return (0);
}


int
natpt_uattach(struct socket *so, int proto, struct proc *p)
{
    int		error;

#if ISFB31
    if (p && (error = suser(p->p_ucred, &p->p_acflag)) != 0)
	return (error);
#else
	if ((so->so_state & SS_PRIV) != 0)
		return (EPERM);
#endif

    return (natpt_attach(so, proto));
}


int
natpt_ubind(struct socket *so, struct sockaddr *nam, struct proc *p)
{
    return (EINVAL);
}


int
natpt_uconnect(struct socket *so, struct sockaddr *nam, struct proc *p)
{
    return (EINVAL);
}


int
natpt_ucontrol(struct socket *so, u_long cmd, caddr_t data, struct ifnet *ifp,
	       struct proc *p)
{
    return (natpt_control(so, cmd, data, ifp));
}


int
natpt_udetach(struct socket *so)
{
    struct rawcb *rp = sotorawcb(so);

    if (rp == 0)
	return (EINVAL);

    return (natpt_detach(so));
}

#endif	/* defined(__FreeBSD__) && __FreeBSD__ >= 3	*/


int
natpt_attach(struct socket *so, int proto)
{
    struct rawcb *rp;
    int	error;

    if (so->so_pcb == NULL)
    {
	MALLOC(rp, struct rawcb *, sizeof(*rp), M_PCB, M_WAITOK);
	so->so_pcb = (caddr_t)rp;
	bzero(rp, sizeof(*rp));
    }

    if ((rp = sotorawcb(so)) == NULL)
	return (ENOBUFS);
    if ((error = soreserve(so, natpt_sendspace, natpt_recvspace)))
	return (error);

    rp->rcb_socket = so;
    rp->rcb_proto.sp_family = so->so_proto->pr_domain->dom_family;
    rp->rcb_proto.sp_protocol = proto;
#if defined(__bsdi__) || defined(__FreeBSD__) && __FreeBSD__ <= 2
    insque(rp, &ptrcb);
#else
    LIST_INSERT_HEAD(&ptrcb, rp, rcb_list);
#endif

    /* The socket is always "connected" because
	  we always know "where" to send the packet */
    rp->rcb_faddr = &natpt_dst;
    soisconnected(so);

    return (0);
}


int
natpt_detach(struct socket *so)
{
    struct rawcb	*rp = sotorawcb(so);

    if (rp == NULL)
	return (ENOTCONN);

    so->so_pcb = NULL;
    sofree(so);

#if defined(__bsdi__) || defined(__FreeBSD__) && __FreeBSD__ <= 2
    remque(rp);
#else
    LIST_REMOVE(rp, rcb_list);
#endif
    if (rp->rcb_laddr)
	m_freem(dtom(rp->rcb_laddr));
    if (rp->rcb_faddr)
	m_freem(dtom(rp->rcb_faddr));
    FREE(rp, M_PCB);

    return (0);
}


int
natpt_disconnect(struct socket *so)
{
    struct rawcb	*rp = sotorawcb(so);

    if (rp == NULL)
	return (EINVAL);

    if (rp->rcb_faddr == NULL)
	return (ENOTCONN);

    rp->rcb_faddr = NULL;
    raw_disconnect(rp);
    soisdisconnected(so);

    return (0);
}


int
natpt_control(struct socket *so, int cmd, caddr_t data, struct ifnet *ifp)
{
    if (natpt_initialized == 0)
	natpt_initialize();

    switch (cmd)
    {
      case SIOCSETIF:		return (_natptSetIf(data));
      case SIOCGETIF:		return (_natptGetIf(data));
      case SIOCENBTRANS:	return (_natptEnableTrans(data));
      case SIOCDSBTRANS:	return (_natptDisableTrans(data));
      case SIOCSETRULE:		return (_natptSetRule(data));
      case SIOCFLUSHRULE:	return (_natptFlushRule(data));
      case SIOCSETPREFIX:	return (_natptSetPrefix(data));
      case SIOCSETVALUE:	return (_natptSetValue(data));

      case SIOCTESTLOG:		return (_natptTestLog(data));

      case SIOCBREAK:		return (_natptBreak());
    }

    return (EINVAL);
}


/*
 *
 */

static int
_natptSetIf(caddr_t addr)
{
    struct natpt_msgBox	*mbx = (struct natpt_msgBox *)addr;
    struct ifBox	*ifb;

    if (((ifb = natpt_asIfBox(mbx->m_ifName)) == NULL)
      && ((ifb = natpt_setIfBox(mbx->m_ifName)) == NULL))
     return (ENXIO);

    if (ifb->side != noSide)
    {
	char	WoW[LBFSZ];

	sprintf(WoW, "[natpt]: interface `%s\' already configured.", mbx->m_ifName);
	natpt_logMsg(LOG_WARNING, WoW, strlen(WoW));
	return (EALREADY);
    }

    {
	char	 WoW[LBFSZ];
	char	*s;

	natpt_ip6src = ifb->ifnet;
	if (mbx->flags == IF_EXTERNAL)
	    ifb->side = outSide, s = "outside";
	else
	    ifb->side = inSide,	 s = "inside";

	sprintf(WoW, "[natpt]: interface `%s\' set as %s.", mbx->m_ifName, s);
	natpt_logMsg(LOG_INFO, WoW, strlen(WoW));
    }

    return (0);
}


static int
_natptGetIf(caddr_t addr)
{
    struct natpt_msgBox	*mbx = (struct natpt_msgBox *)addr;
    struct ifBox	*ifb;

    if (((ifb = natpt_asIfBox(mbx->m_ifName)) == NULL)
      && ((ifb = natpt_setIfBox(mbx->m_ifName)) == NULL))
     return (ENXIO);

    {
	switch (ifb->side)
	{
	  case outSide:	mbx->flags |= IF_EXTERNAL;	break;
	  case inSide:	mbx->flags |= IF_INTERNAL;	break;
	  default:	mbx->flags  = -1;		break;
	}
    }

    return (0);
}


static int
_natptSetValue(caddr_t addr)
{
    struct natpt_msgBox	*mbx = (struct natpt_msgBox *)addr;

    switch (mbx->flags)
    {
      case NATPT_DEBUG:
	natpt_debug = *((u_int *)mbx->m_aux);
	break;

      case NATPT_DUMP:
	natpt_dump = *((u_int *)mbx->m_aux);
	break;
    }

    return (0);
}


static int
_natptTestLog(caddr_t addr)
{
    char		*fragile;
    struct natpt_msgBox	*mbox = (struct natpt_msgBox *)addr;

    MALLOC(fragile, char *, mbox->size, M_TEMP, M_WAITOK);
    copyin(mbox->freight, fragile, mbox->size);

    natpt_logMsg(LOG_DEBUG, fragile, mbox->size);

    FREE(fragile, M_TEMP);
    return (0);
}

