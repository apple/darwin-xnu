/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 *	Copyright (c) 1996 Apple Computer, Inc. 
 *
 *		Created April 25, 1996, by Justin C. Walker
 *   Modified, March 17, 1997 by Tuyen Nguyen for MacOSX.
 *
 *	File: aurpd.c
 */

/*
 * Kernel process to implement the AURP daemon:
 *  manage tunnels to remote AURP servers across IP networks
 */
#ifdef AURP_SUPPORT

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <machine/spl.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/uio_internal.h>
#include <kern/locks.h>
#include <netinet/in.h>
#include <net/if.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/at_var.h>
#include <netat/routing_tables.h>
#include <netat/at_pcb.h>
#include <netat/aurp.h>
#include <netat/debug.h>

#define M_RCVBUF (64 * 1024)
#define M_SNDBUF (64 * 1024)

extern lck_mtx_t * atalk_mutex;

static int ip_to_atalk(struct sockaddr_in *fp, register gbuf_t *p_mbuf);
static int aurp_bindrp(struct socket *so);

struct aurp_global_t aurp_global;

/*
 * Initialize the aurp pipe -
 * -Create, initialize, and start the aurpd kernel process; we need
 *  a process to permit queueing between the socket and the stream,
 *  which is necessary for orderly access to the socket structure.
 * -The user process (aurpd) is there to 'build' the AURP
 *  stream, act as a 'logging agent' (:-}), and hold open the stream
 *  during its use.
 * -Data and AURP packets from the DDP stream will be fed into the
 *  UDP tunnel (AURPsend())
 * -Data and AURP packets from the UDP tunnel will be fed into the
 *  DDP stream (ip_to_atalk(), via the kernel process).
 */
int
aurpd_start()
{
	register int error;
	register struct socket *so;
	struct mbuf *m;
	int maxbuf;
	struct sockopt sopt;

	if (suser(kauth_cred_get(), 0) != 0 )
		return(EPERM);

	/*
	 * Set up state prior to starting kernel process so we can back out
	 *  (error return) if something goes wrong.
	 */
	bzero((char *)&aurp_global.tunnel, sizeof(aurp_global.tunnel));
	/*lock_alloc(&aurp_global.glock, LOCK_ALLOC_PIN, AURP_EVNT_LOCK, -1);*/
	ATEVENTINIT(aurp_global.event_anchor);

	/* open udp socket */
	if (aurp_global.udp_port == 0)
		aurp_global.udp_port = AURP_SOCKNUM;
	error = socreate(AF_INET, &aurp_global.tunnel, SOCK_DGRAM,
			 IPPROTO_UDP);
	if (error)
	{	dPrintf(D_M_AURP, D_L_FATAL, ("AURP: Can't get socket (%d)\n",
			error));
		return(error);
	}

	so = aurp_global.tunnel;

	if ((error = aurp_bindrp(so)) != 0)
	{	dPrintf(D_M_AURP, D_L_FATAL,
			("AURP: Can't bind to port %d (error %d)\n",
			aurp_global.udp_port, error));
		soclose(so);
		return(error);
	}

	sblock(&so->so_rcv, M_WAIT);
	sblock(&so->so_snd, M_WAIT);

	/*
	 * Set socket Receive buffer size
	 */
	m = m_get(M_WAIT, MT_SOOPTS);
	if (m == NULL) {
		error = ENOBUFS;
		goto out;
	} else {
		maxbuf = M_RCVBUF;
		sopt.sopt_val     = CAST_USER_ADDR_T(&maxbuf);
		sopt.sopt_valsize = sizeof(maxbuf);
		sopt.sopt_level   = SOL_SOCKET;
		sopt.sopt_name    = SO_RCVBUF;
		sopt.sopt_dir     = SOPT_SET;
		sopt.sopt_p		  = NULL;
		if ((error = sosetopt(so, &sopt)) != 0)
			goto out;
	}

	/*
	 * Set socket Send buffer size
	 */
	m = m_get(M_WAIT, MT_SOOPTS);
	if (m == NULL) {
		error = ENOBUFS;
		goto out;
	} else {

		maxbuf = M_SNDBUF;
		sopt.sopt_val     = CAST_USER_ADDR_T(&maxbuf);
		sopt.sopt_valsize = sizeof(maxbuf);
		sopt.sopt_level   = SOL_SOCKET;
		sopt.sopt_name    = SO_SNDBUF;
		sopt.sopt_dir     = SOPT_SET;
		sopt.sopt_p		  = NULL;
		if ((error = sosetopt(so, &sopt)) != 0)
			goto out;
	}

	so->so_upcall = aurp_wakeup;
	so->so_upcallarg = (caddr_t)AE_UDPIP; /* Yuck */
	so->so_state |= SS_NBIO;
	so->so_rcv.sb_flags |=(SB_SEL|SB_NOINTR);
	so->so_snd.sb_flags |=(SB_SEL|SB_NOINTR);

out:
	sbunlock(&so->so_snd, 0);
	sbunlock(&so->so_rcv, 0);

	return(error);
}

int
AURPgetmsg(err)
	int *err;
{	register struct socket *so;
	register int events;

	so = aurp_global.tunnel;
	*err = 0;

	for (;;)
	{	gbuf_t *from, *p_mbuf;
		int flags = MSG_DONTWAIT;
		uio_t auio;
		char uio_buf[ UIO_SIZEOF(0) ];

		/*
		 * Wait for a package to arrive.  This will be from the
		 * IP side - sowakeup() calls aurp_wakeup()
		 *	     when a packet arrives
		 */

		events = aurp_global.event;
		if (((*err == 0) || (*err == EWOULDBLOCK)) && events == 0)
		  {
			lck_mtx_assert(atalk_mutex, LCK_MTX_ASSERT_OWNED);
		    *err = msleep(&aurp_global.event_anchor, atalk_mutex, PSOCK | PCATCH, "AURPgetmsg", 0);
		    events = aurp_global.event;
		    aurp_global.event = 0;
		  }	

		/*
		 * Shut down if we have the AE_SHUTDOWN event or if we got
		 * a system error other than EWOULDBLOCK, such as EINTR.
		 */
		if (((*err != EWOULDBLOCK) && (*err != 0)) || events & AE_SHUTDOWN)
		  {	
		    dPrintf(D_M_AURP, D_L_SHUTDN_INFO,
			("AURPgetmsg: AE_SHUTDOWN detected--starting shutdown sequence\n"));
		    aurp_global.shutdown = 1;
		    while (aurp_global.running)
			;
		    /*lock_free(&aurp_global.glock);*/
		    aurp_global.tunnel = 0;
		    aurp_global.event = 0;
		    aurp_global.shutdown = 0;
		    soclose(so);
		    if (*err == 0)
		    *err = ESHUTDOWN;
		    dPrintf(D_M_AURP, D_L_SHUTDN_INFO,
			("AURPgetmsg: shutdown completed\n"));
		    return -1;
		  }



		/*
		 * Set up the nominal uio structure -
		 *  give it no iov's, point off to non-existant user space,
		 *  but make sure the 'resid' count means somehting.
		 */
		auio = uio_createwithbuffer(0, 0, UIO_SYSSPACE, UIO_READ, 
								  &uio_buf[0], sizeof(uio_buf));

		/* Keep up an even flow... */
		for (;;)
		{
/*
 * This should be large enough to encompass a full DDP packet plus
 *  domain header.
 */
#define A_LARGE_SIZE 700

			flags = MSG_DONTWAIT;
			uio_setresid(auio, A_LARGE_SIZE);
			*err = soreceive(so, (struct sockaddr **)&from, auio, &p_mbuf, 0, &flags);
			dPrintf(D_M_AURP, D_L_VERBOSE,
				("AURPgetmsg: soreceive returned %d, aurp_global.event==0x%x\n", *err, events));
			/* soreceive() sets *mp to zero! at start */
			if (p_mbuf)
			        ip_to_atalk((struct sockaddr_in *)from, p_mbuf);
			if (*err || (p_mbuf == NULL)) {
				/*
				 * An error occurred in soreceive(),
				 * so clear the data input event flag
				 * and break out of this inner loop.
				 *
				 * XXX Note that clearing AE_UDPIP here could
				 * cause us to lose an AE_UDPIP event that
				 * was posted in aurp_global.event between
				 * the soreceive() above and the code here.
				 * The protocol should recover from this
				 * lost event, though, since the next
				 * request (a tickle, for example) from
				 * the other end of the tunnel will cause
				 * another AE_UDPIP event to be posted,
				 * which will wake us from the sleep at
				 * the top of the outer loop.
				 */
				aurp_global.event &= ~AE_UDPIP;
				dPrintf(D_M_AURP, D_L_WARNING, ("AURPgetmsg: spurious soreceive, err==%d, p_mbuf==0x%x\n", *err, (unsigned int) p_mbuf));
			  break;
		}
	}
	}
	return -1;
}

/*
 * Wakeup the sleeping giant - we've put a message on his queue(s).
 * The arg indicates what queue has been updated.
 *
 * This conforms to the so_upcall function pointer member of struct sockbuf.
 */
void aurp_wakeup(__unused struct socket *so, register caddr_t p, __unused int state)
{
	register int bit;

	bit = (int) p;
	aurp_global.event |= bit;

	dPrintf(D_M_AURP, D_L_STATE_CHG,
		("aurp_wakeup: bit 0x%x, aurp_global.event now 0x%x\n",
		bit, aurp_global.event));

	wakeup(&aurp_global.event_anchor);
}

/*
 * Try to bind to the specified reserved port.
 * Sort of like sobind(), but no suser() check.
 */
static int
aurp_bindrp(struct socket *so)
{
	struct sockaddr_in sin;
	struct proc *p = current_proc();
	int error;


	bzero(&sin, sizeof(sin));
	sin.sin_family      = AF_INET;
	sin.sin_addr.s_addr = htons(aurp_global.src_addr);
	sin.sin_port        = htons(aurp_global.udp_port);
	sin.sin_len         = sizeof(struct sockaddr_in);

	sblock(&so->so_rcv, M_WAIT);
	sblock(&so->so_snd, M_WAIT);
	so->so_state |= SS_PRIV;
	error = (*so->so_proto->pr_usrreqs->pru_bind)(so, (struct sockaddr *) &sin, p);
	sbunlock(&so->so_snd, 0);
	sbunlock(&so->so_rcv, 0);

	return (error);
}

/*
 * receive from UDP
 * fp is the 'source address' mbuf; p_mbuf is the data mbuf.
 * Use the source address to find the 'node number' (index of the address),
 *  and pass that to the next stage.
 */
int ip_to_atalk(register struct sockaddr_in *rem_addr, register gbuf_t *p_mbuf)
{	
	register aurp_domain_t *domain;
	unsigned char node;


	/* determine the node where the packet came from */
	for (node=1; node <= dst_addr_cnt; node++) {
		if (aurp_global.dst_addr[node] == *(long *)&rem_addr->sin_addr)
			break;
	}
	if (node > dst_addr_cnt) {
		dPrintf(D_M_AURP, D_L_WARNING,
			("AURPrecv: invalid node, %d.%lx\n",
			rem_addr->sin_port,
			rem_addr->sin_addr.s_addr));
		
		gbuf_freem(p_mbuf);
		FREE(rem_addr, M_SONAME);
		return -1;
	}

	/* validate the domain */
	domain = (aurp_domain_t *)gbuf_rptr(p_mbuf);
	if ( (domain->dst_length != IP_LENGTH) ||
	    (domain->dst_authority != IP_AUTHORITY) ||
	    (domain->version != AUD_Version) ||
	    ((domain->type != AUD_Atalk) && (domain->type != AUD_AURP)) ) {
		dPrintf(D_M_AURP, D_L_WARNING,
			("AURPrecv: invalid domain, %d.%lx\n",
			rem_addr->sin_port,
			rem_addr->sin_addr.s_addr));
		
		gbuf_freem(p_mbuf);
		FREE(rem_addr, M_SONAME);
		return -1;
	}

	/* Remove domain header */
	p_mbuf->m_pkthdr.len -= IP_DOMAINSIZE;
	gbuf_rinc(p_mbuf,IP_DOMAINSIZE);
	gbuf_set_type(p_mbuf, MSG_DATA);

	/* forward the packet to the local AppleTalk stack */

	at_insert(p_mbuf, domain->type, node);
	FREE(rem_addr, M_SONAME);
	return 0;
}

/*
 * send to UDP
 * The real work has been done already.	 Here, we just cobble together
 *  a sockaddr for the destination and call sosend().
 */
void
atalk_to_ip(register gbuf_t *m)
{	register aurp_domain_t *domain;
	int error;
	int flags = MSG_DONTWAIT;
	struct sockaddr_in rem_addr;

	m->m_type = MT_HEADER;
	m->m_pkthdr.len = gbuf_msgsize(m);
	m->m_pkthdr.rcvif = 0;

	bzero((char *) &rem_addr, sizeof(rem_addr));
	rem_addr.sin_family = PF_INET;
	rem_addr.sin_port = aurp_global.udp_port;
	rem_addr.sin_len  = sizeof (struct sockaddr_in);
	domain = (aurp_domain_t *)gbuf_rptr(m);
	*(long *) &rem_addr.sin_addr = domain->dst_address;

	aurp_global.running++;
	if (aurp_global.shutdown) {
		gbuf_freem(m);
		aurp_global.running--;
		dPrintf(D_M_AURP, D_L_SHUTDN_INFO,
			("atalk_to_ip: detected aurp_global.shutdown state\n"));
		return;
	}
	dPrintf(D_M_AURP, D_L_VERBOSE, ("atalk_to_ip: calling sosend\n"));
	error = sosend(aurp_global.tunnel, (struct sockaddr *) &rem_addr, NULL, m, NULL, flags);
	if (error)
	{	/*log error*/
	  dPrintf(D_M_AURP, D_L_ERROR, ("AURP: sosend error (%d)\n",
		  error));
	}

	aurp_global.running--;
	return;
}

#endif  /* AURP_SUPPORT */
