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

/*	ddp_usrreq.c
 */

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <machine/spl.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/mbuf.h>
#include <sys/ioctl.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>

#include <net/if.h>

#include <netat/appletalk.h>
#include <netat/at_var.h>
#include <netat/sysglue.h>
#include <netat/ddp.h>
#include <netat/ep.h>
#include <netat/rtmp.h>
#include <netat/zip.h>
#include <netat/at_pcb.h>
#include <netat/routing_tables.h>
#include <netat/nbp.h>

extern int at_control(), at_memzone_init();
extern void  nbp_input(), ep_input(), zip_router_input(), 
  sip_input(), add_ddp_handler(), init_ddp_handler(), 
  ddp_start(), ddp_input(), appletalk_hack_start();
extern u_short ddp_checksum();
extern at_ifaddr_t *forUs();
extern struct mbuf *m_dup(struct mbuf *, int);

extern at_ifaddr_t *ifID_home;
extern int xpatcnt;

struct atpcb ddp_head;
u_long ddp_sendspace = 600,	/* *** what should this value be? *** */
  ddp_recvspace = 50 * (600 + sizeof(struct sockaddr_at));

int ddp_pru_control(struct socket *so, u_long cmd, caddr_t data,
		struct ifnet *ifp, struct proc *p)
{
	return(at_control(so, cmd, data, ifp));
}


int	ddp_pru_attach(struct socket *so, int proto,
		   struct proc *p)
{
	int s, error = 0;
	at_ddp_t *ddp = NULL;
	struct atpcb *pcb = (struct atpcb *)((so)->so_pcb);

	s = splnet();
	error = at_pcballoc(so, &ddp_head);
	splx(s);
	if (error)
		return error;
	error = soreserve(so, ddp_sendspace, ddp_recvspace);
	pcb = (struct atpcb *)((so)->so_pcb);
	pcb->pid = current_proc()->p_pid;
	pcb->ddptype = (u_char) proto;    /* set in socreate() */
	pcb->proto = ATPROTO_DDP;

	return error;
}


int  ddp_pru_disconnect(struct socket *so)
{

	int s, error = 0;
	at_ddp_t *ddp = NULL;
	struct atpcb *pcb = (struct atpcb *)((so)->so_pcb);

	if (pcb == NULL) 
		return (EINVAL);

	if ((so->so_state & SS_ISCONNECTED) == 0) 
		return ENOTCONN;

	soisdisconnected(so);
	s = splnet();
	at_pcbdetach(pcb);
	splx(s);

	return error;
}


int  ddp_pru_abort(struct socket *so)
{
	int s;
	struct atpcb *pcb = (struct atpcb *)((so)->so_pcb);

	if (pcb == NULL) 
		return (EINVAL);

	soisdisconnected(so);
	s = splnet();
	at_pcbdetach(pcb);
	splx(s);

	return 0;
}

int  ddp_pru_detach(struct socket *so)
{
	int s;
	struct atpcb *pcb = (struct atpcb *)((so)->so_pcb);

	if (pcb == NULL) 
		return (EINVAL);

	s = splnet();
	at_pcbdetach(pcb);
	splx(s);
	return 0;
}
					  
int	ddp_pru_shutdown(struct socket *so)
{
	struct atpcb *pcb = (struct atpcb *)((so)->so_pcb);

	if (pcb == NULL) 
		return (EINVAL);

	socantsendmore(so);
	return 0;
}
					  

int    ddp_pru_bind(struct socket *so, struct sockaddr *nam,
		struct proc *p)
{
	struct atpcb *pcb = (struct atpcb *)((so)->so_pcb);

	if (pcb == NULL) 
		return (EINVAL);

	return (at_pcbbind(pcb, nam));
}


int	ddp_pru_send(struct socket *so, int flags, struct mbuf *m, 
		     struct sockaddr *addr, struct mbuf *control,
		     struct proc *p)
{
	at_ddp_t *ddp = NULL;
	struct atpcb *pcb = (struct atpcb *)((so)->so_pcb);

	if (pcb == NULL)
		return (EINVAL);
		
	/*
	 * Set type to MSG_DATA.  Otherwise looped back packet is not
	 * recognized by atp_input() and possibly other protocols.
	 */
	 
	MCHTYPE(m, MSG_DATA);
	
	if (!(pcb->ddp_flags & DDPFLG_HDRINCL)) {
		/* prepend a DDP header */
		M_PREPEND(m, DDP_X_HDR_SIZE, M_WAIT);
		ddp = mtod(m, at_ddp_t *);
	}

	if (so->so_state & SS_ISCONNECTED) {
		if (addr) 
		        return EISCONN;

		if (ddp) {
			NET_ASSIGN(ddp->dst_net, pcb->raddr.s_net);
			ddp->dst_node = pcb->raddr.s_node;
			ddp->dst_socket = pcb->rport;
		}
	} else {
		if (addr == NULL) 
			return ENOTCONN;

		if (ddp) {
			struct sockaddr_at *dst =
				(struct sockaddr_at *) addr;
			NET_ASSIGN(ddp->dst_net, dst->sat_addr.s_net);
			ddp->dst_node = dst->sat_addr.s_node;
			ddp->dst_socket = dst->sat_port;
		}
	}
	if (ddp) {
		ddp->length = m->m_pkthdr.len;
		UAS_ASSIGN(ddp->checksum, 
			   (pcb->ddp_flags & DDPFLG_CHKSUM)? 1: 0);
		ddp->type = (pcb->ddptype)? pcb->ddptype: DEFAULT_OT_DDPTYPE;
#ifdef NOT_YET
		NET_ASSIGN(ddp->src_net, pcb->laddr.s_net);
		ddp->src_node = pcb->laddr.s_node;
		ddp->src_socket = pcb->lport;
#endif
	} else {
		ddp = mtod(m, at_ddp_t *);
	}
	if (NET_VALUE(ddp->dst_net) == ATADDR_ANYNET && 
	    ddp->dst_node == ATADDR_BCASTNODE &&
	    (pcb->ddp_flags & DDPFLG_SLFSND)) {
		struct mbuf *n;

		if ((n = m_dup(m, M_DONTWAIT))) {
			at_ifaddr_t 
			  *ifID = ifID_home, 
			  *ifIDTmp = (at_ifaddr_t *)NULL;

			/* as in ddp_output() loop processing, fill in the 
			   rest of the header */
			ddp = mtod(n, at_ddp_t *);
			if (MULTIHOME_MODE && (ifIDTmp = forUs(ddp)))
				ifID = ifIDTmp;
			NET_ASSIGN(ddp->src_net, ifID->ifThisNode.s_net);
			ddp->src_node = ifID->ifThisNode.s_node;
			ddp->src_socket = pcb->lport;
			if (UAS_VALUE(ddp->checksum))
				UAS_ASSIGN(ddp->checksum, ddp_checksum(m, 4));
			ddp_input(n, ifID);
		}
	}
	return(ddp_output(&m, pcb->lport, FALSE));
} /* ddp_pru_send */

int   ddp_pru_sockaddr(struct socket *so, 
		   struct sockaddr **nam)
{
        int s;
	struct atpcb *pcb;
	struct sockaddr_at *sat;

	MALLOC(sat, struct sockaddr_at *, sizeof *sat, M_SONAME, M_WAITOK);
	if (sat == NULL)
		return(ENOMEM);
	bzero((caddr_t)sat, sizeof(*sat));

	s = splnet();
	if ((pcb = sotoatpcb(so)) == NULL) {
		splx(s);
		FREE(sat, M_SONAME);
		return(EINVAL);
	}

	sat->sat_family = AF_APPLETALK;
	sat->sat_len = sizeof(*sat);
	sat->sat_port = pcb->lport;
	sat->sat_addr = pcb->laddr;
	splx(s);

	*nam = (struct sockaddr *)sat;
	return(0);
}


int  ddp_pru_peeraddr(struct socket *so, 
		  struct sockaddr **nam)
{
        int s;
	struct atpcb *pcb;
	struct sockaddr_at *sat;

	MALLOC(sat, struct sockaddr_at *, sizeof *sat, M_SONAME, M_WAITOK);
	if (sat == NULL)
		return (ENOMEM);
	bzero((caddr_t)sat, sizeof(*sat));

	s = splnet();
	if ((pcb = sotoatpcb(so)) == NULL) {
		splx(s);
		FREE(sat, M_SONAME);
		return(EINVAL);
	}

	sat->sat_family = AF_APPLETALK;
	sat->sat_len = sizeof(*sat);
	sat->sat_port = pcb->rport;
	sat->sat_addr = pcb->raddr;
	splx(s);

	*nam = (struct sockaddr *)sat;
	return(0);
}


int    ddp_pru_connect(struct socket *so, struct sockaddr *nam,
		   struct proc *p)
{
	struct atpcb *pcb = (struct atpcb *)((so)->so_pcb);
	struct sockaddr_at *faddr = (struct sockaddr_at *) nam;

	if (pcb != NULL) 
		return (EINVAL);

	if (xpatcnt == 0) 
		return (EADDRNOTAVAIL);

	if (faddr->sat_family != AF_APPLETALK) 
		return (EAFNOSUPPORT);

	pcb->raddr = faddr->sat_addr;
	soisconnected(so);
	return 0;
}



/*
 * One-time AppleTalk initialization
 */
void ddp_init()
{
	at_memzone_init();
	ddp_head.atpcb_next = ddp_head.atpcb_prev = &ddp_head;
	init_ddp_handler();

    /* Initialize protocols implemented in the kernel */
	add_ddp_handler(EP_SOCKET, ep_input);
	add_ddp_handler(ZIP_SOCKET, zip_router_input);
	add_ddp_handler(NBP_SOCKET, nbp_input);
	add_ddp_handler(DDP_SOCKET_1st_DYNAMIC, sip_input);

	ddp_start();

	appletalk_hack_start();
} /* ddp_init */

