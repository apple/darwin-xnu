/*
 * Copyright (c) 1997-2014 Apple Inc. All rights reserved.
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
 *	@(#)ndrv.c	1.1 (MacOSX) 6/10/43
 * Justin Walker, 970604
 *   AF_NDRV support
 * 980130 - Cleanup, reorg, performance improvemements
 * 000816 - Removal of Y adapter cruft
 */

/*
 * PF_NDRV allows raw access to a specified network device, directly
 *  with a socket.  Expected use involves a socket option to request
 *  protocol packets.  This lets ndrv_output() call ifnet_output(), and
 *  lets DLIL find the proper recipient for incoming packets.
 *  The purpose here is for user-mode protocol implementation.
 * Note that "pure raw access" will still be accomplished with BPF.
 *
 * In addition to the former use, when combined with socket NKEs,
 * PF_NDRV permits a fairly flexible mechanism for implementing
 * strange protocol support.
 */
#include <mach/mach_types.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/errno.h>
#include <sys/syslog.h>
#include <sys/proc.h>

#include <kern/queue.h>

#include <net/ndrv.h>
#include <net/route.h>
#include <net/if_llc.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/ndrv_var.h>
#include <net/dlil.h>

#if INET
#include <netinet/in.h>
#include <netinet/in_var.h>
#endif
#include <netinet/if_ether.h>

#include <machine/spl.h>

static unsigned int ndrv_multi_max_count = NDRV_DMUX_MAX_DESCR;
SYSCTL_UINT(_net, OID_AUTO, ndrv_multi_max_count, CTLFLAG_RW | CTLFLAG_LOCKED,
        &ndrv_multi_max_count, 0, "Number of allowed multicast addresses per NRDV socket");

static int ndrv_do_detach(struct ndrv_cb *);
static int ndrv_do_disconnect(struct ndrv_cb *);
static struct ndrv_cb *ndrv_find_inbound(struct ifnet *ifp, u_int32_t protocol_family);
static int ndrv_setspec(struct ndrv_cb *np, struct sockopt *sopt);
static int ndrv_delspec(struct ndrv_cb *);
static int ndrv_to_ifnet_demux(struct ndrv_demux_desc* ndrv, struct ifnet_demux_desc* ifdemux);
static void ndrv_handle_ifp_detach(u_int32_t family, short unit);
static int ndrv_do_add_multicast(struct ndrv_cb *np, struct sockopt *sopt);
static int ndrv_do_remove_multicast(struct ndrv_cb *np, struct sockopt *sopt);
static struct ndrv_multiaddr* ndrv_have_multicast(struct ndrv_cb *np, struct sockaddr* addr);
static void ndrv_remove_all_multicast(struct ndrv_cb *np);
static void ndrv_dominit(struct domain *);

u_int32_t  ndrv_sendspace = NDRVSNDQ;
u_int32_t  ndrv_recvspace = NDRVRCVQ;
TAILQ_HEAD(, ndrv_cb)	ndrvl = TAILQ_HEAD_INITIALIZER(ndrvl);

static struct domain *ndrvdomain = NULL;
extern struct domain ndrvdomain_s;

#define NDRV_PROTODEMUX_COUNT	10

/*
 * Verify these values match.
 * To keep clients from including dlil.h, we define
 * these values independently in ndrv.h. They must
 * match or a conversion function must be written.
 */
#if NDRV_DEMUXTYPE_ETHERTYPE != DLIL_DESC_ETYPE2
#error NDRV_DEMUXTYPE_ETHERTYPE must match DLIL_DESC_ETYPE2
#endif
#if NDRV_DEMUXTYPE_SAP != DLIL_DESC_SAP
#error NDRV_DEMUXTYPE_SAP must match DLIL_DESC_SAP
#endif
#if NDRV_DEMUXTYPE_SNAP != DLIL_DESC_SNAP
#error NDRV_DEMUXTYPE_SNAP must match DLIL_DESC_SNAP
#endif

/*
 * Protocol output - Called to output a raw network packet directly
 *  to the driver.
 */
static int
ndrv_output(struct mbuf *m, struct socket *so)
{
    struct ndrv_cb *np = sotondrvcb(so);
	struct ifnet *ifp = np->nd_if;
    int	result = 0;

#if NDRV_DEBUG
	kprintf("NDRV output: %x, %x, %x\n", m, so, np);
#endif

	/*
	 * No header is a format error
	 */
	if ((m->m_flags&M_PKTHDR) == 0)
		return(EINVAL);

	/* Unlock before calling ifnet_output */
	socket_unlock(so, 0);
	
	/*
     * Call DLIL if we can. DLIL is much safer than calling the
     * ifp directly.
     */
	result = ifnet_output_raw(ifp, np->nd_proto_family, m);
	
	socket_lock(so, 0);
	
	return (result);
}

/* Our input routine called from DLIL */
static errno_t
ndrv_input(
	ifnet_t				ifp,
	protocol_family_t	proto_family,
	mbuf_t				m,
	char				*frame_header)
{
	struct socket *so;
	struct sockaddr_dl ndrvsrc;
	struct ndrv_cb *np;
	int error = 0;

    ndrvsrc.sdl_len = sizeof (struct sockaddr_dl);
    ndrvsrc.sdl_family = AF_NDRV;
    ndrvsrc.sdl_index = 0;

    /* move packet from if queue to socket */
	/* Should be media-independent */
    ndrvsrc.sdl_type = IFT_ETHER;
    ndrvsrc.sdl_nlen = 0;
    ndrvsrc.sdl_alen = 6;
    ndrvsrc.sdl_slen = 0;
    bcopy(frame_header, &ndrvsrc.sdl_data, 6);

	np = ndrv_find_inbound(ifp, proto_family);
	if (np == NULL)
	{
		return(ENOENT);
	}
	so = np->nd_socket;
    /* prepend the frame header */
    m = m_prepend(m, ifnet_hdrlen(ifp), M_NOWAIT);
    if (m == NULL)
        return EJUSTRETURN;
    bcopy(frame_header, m->m_data, ifnet_hdrlen(ifp));

	lck_mtx_assert(ndrvdomain->dom_mtx, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(ndrvdomain->dom_mtx);
	if (sbappendaddr(&(so->so_rcv), (struct sockaddr *)&ndrvsrc,
			 		 m, (struct mbuf *)0, &error) != 0) {
		sorwakeup(so);
	}
	lck_mtx_unlock(ndrvdomain->dom_mtx);
	return 0; /* radar 4030377 - always return 0 */
}

/*
 * Allocate an ndrv control block and some buffer space for the socket
 */
static int
ndrv_attach(struct socket *so, int proto, __unused struct proc *p)
{
    int error;
	struct ndrv_cb *np = sotondrvcb(so);

	if ((so->so_state & SS_PRIV) == 0)
		return(EPERM);

#if NDRV_DEBUG
	kprintf("NDRV attach: %x, %x, %x\n", so, proto, np);
#endif

        if ((error = soreserve(so, ndrv_sendspace, ndrv_recvspace)))
                return(error);

	MALLOC(np, struct ndrv_cb *, sizeof(*np), M_PCB, M_WAITOK);
	if (np == NULL)
		return (ENOMEM);
    so->so_pcb = (caddr_t)np;
    bzero(np, sizeof(*np));
#if NDRV_DEBUG
	kprintf("NDRV attach: %x, %x, %x\n", so, proto, np);
#endif
	TAILQ_INIT(&np->nd_dlist);
	np->nd_signature = NDRV_SIGNATURE;
	np->nd_socket = so;
	np->nd_proto.sp_family = SOCK_DOM(so);
	np->nd_proto.sp_protocol = proto;
    np->nd_if = NULL;
    np->nd_proto_family = 0;
    np->nd_family = 0;
    np->nd_unit = 0;
    TAILQ_INSERT_TAIL(&ndrvl, np, nd_next);
	return(0);
}

/*
 * Destroy state just before socket deallocation.
 * Flush data or not depending on the options.
 */

static int
ndrv_detach(struct socket *so)
{
	struct ndrv_cb *np = sotondrvcb(so);

	if (np == 0)
		return EINVAL;
	return ndrv_do_detach(np);
}


/*
 * If a socket isn't bound to a single address,
 * the ndrv input routine will hand it anything
 * within that protocol family (assuming there's
 * nothing else around it should go to).
 *
 * Don't expect this to be used.
 */

static int
ndrv_connect(struct socket *so, struct sockaddr *nam, __unused struct proc *p)
{
	struct ndrv_cb *np = sotondrvcb(so);

	if (np == 0)
		return EINVAL;

	if (np->nd_faddr)
		return EISCONN;
    
	/* Allocate memory to store the remote address */
	MALLOC(np->nd_faddr, struct sockaddr_ndrv*,
                nam->sa_len, M_IFADDR, M_WAITOK);
	if (np->nd_faddr == NULL)
		return ENOMEM;
    
	bcopy((caddr_t) nam, (caddr_t) np->nd_faddr, nam->sa_len);
	soisconnected(so);
	return 0;
}

static void
ndrv_event(struct ifnet *ifp, __unused protocol_family_t protocol,
		   const struct kev_msg *event)
{
	if (event->vendor_code == KEV_VENDOR_APPLE &&
		event->kev_class == KEV_NETWORK_CLASS &&
		event->kev_subclass == KEV_DL_SUBCLASS &&
		event->event_code == KEV_DL_IF_DETACHING) {
		lck_mtx_assert(ndrvdomain->dom_mtx, LCK_MTX_ASSERT_NOTOWNED);
		lck_mtx_lock(ndrvdomain->dom_mtx);
		ndrv_handle_ifp_detach(ifnet_family(ifp), ifnet_unit(ifp));
		lck_mtx_unlock(ndrvdomain->dom_mtx);
	}
}

static int name_cmp(struct ifnet *, char *);

/*
 * This is the "driver open" hook - we 'bind' to the
 *  named driver.
 * Here's where we latch onto the driver.
 */
static int
ndrv_bind(struct socket *so, struct sockaddr *nam, __unused struct proc *p)
{
    struct sockaddr_ndrv *sa = (struct sockaddr_ndrv *) nam;
	char *dname;
	struct ndrv_cb *np;
	struct ifnet *ifp;
    int	result;

	if TAILQ_EMPTY(&ifnet_head)
		return(EADDRNOTAVAIL); /* Quick sanity check */
	np = sotondrvcb(so);
	if (np == 0)
		return EINVAL;

	if (np->nd_laddr)
		return EINVAL;			/* XXX */

	/* I think we just latch onto a copy here; the caller frees */
	np->nd_laddr = _MALLOC(sizeof(struct sockaddr_ndrv), M_IFADDR, M_WAITOK);
	if (np->nd_laddr == NULL)
		return(ENOMEM);
	bcopy((caddr_t) sa, (caddr_t) np->nd_laddr, sizeof(struct sockaddr_ndrv));
	dname = (char *) sa->snd_name;
	if (*dname == '\0')
		return(EINVAL);
#if NDRV_DEBUG
	kprintf("NDRV bind: %x, %x, %s\n", so, np, dname);
#endif
	/* Track down the driver and its ifnet structure.
	 * There's no internal call for this so we have to dup the code
	 *  in if.c/ifconf()
	 */
	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_link) {
		if (name_cmp(ifp, dname) == 0)
			break;
	}
	ifnet_head_done();

	if (ifp == NULL)
		return(EADDRNOTAVAIL);
	
	// PPP doesn't support PF_NDRV.
	if (ifnet_family(ifp) != APPLE_IF_FAM_PPP)
	{
		/* NDRV on this interface */
		struct ifnet_attach_proto_param	ndrv_proto;
		result = 0;
		bzero(&ndrv_proto, sizeof(ndrv_proto));
		ndrv_proto.event = ndrv_event;
		
		/* We aren't worried about double attaching, that should just return an error */
		socket_unlock(so, 0);
		result = ifnet_attach_protocol(ifp, PF_NDRV, &ndrv_proto);
		socket_lock(so, 0);
		if (result && result != EEXIST) {
			return result;
		}
		np->nd_proto_family = PF_NDRV;
	}
	else {
		np->nd_proto_family = 0;
	}
    
	np->nd_if = ifp;
    np->nd_family = ifnet_family(ifp);
    np->nd_unit = ifnet_unit(ifp);
    
	return(0);
}

static int
ndrv_disconnect(struct socket *so)
{
	struct ndrv_cb *np = sotondrvcb(so);

	if (np == 0)
		return EINVAL;

	if (np->nd_faddr == 0)
		return ENOTCONN;

	ndrv_do_disconnect(np);
	return 0;
}

/*
 * Mark the connection as being incapable of further input.
 */
static int
ndrv_shutdown(struct socket *so)
{
	lck_mtx_assert(ndrvdomain->dom_mtx, LCK_MTX_ASSERT_OWNED);
	socantsendmore(so);
	return 0;
}

/*
 * Ship a packet out.  The ndrv output will pass it
 *  to the appropriate driver.  The really tricky part
 *  is the destination address...
 */
static int
ndrv_send(struct socket *so, __unused int flags, struct mbuf *m,
	  __unused struct sockaddr *addr, struct mbuf *control,
	  __unused struct proc *p)
{
	int error;

	if (control)
		return EOPNOTSUPP;

	error = ndrv_output(m, so);
	m = NULL;
	return error;
}


static int
ndrv_abort(struct socket *so)
{
	struct ndrv_cb *np = sotondrvcb(so);

	if (np == 0)
		return EINVAL;

	ndrv_do_disconnect(np);
	return 0;
}

static int
ndrv_sockaddr(struct socket *so, struct sockaddr **nam)
{
	struct ndrv_cb *np = sotondrvcb(so);
	int len;

	if (np == 0)
		return EINVAL;

	if (np->nd_laddr == 0)
		return EINVAL;

	len = np->nd_laddr->snd_len;
	MALLOC(*nam, struct sockaddr *, len, M_SONAME, M_WAITOK);
	if (*nam == NULL)
		return ENOMEM;
	bcopy((caddr_t)np->nd_laddr, *nam,
	      (unsigned)len);
	return 0;
}


static int
ndrv_peeraddr(struct socket *so, struct sockaddr **nam)
{
	struct ndrv_cb *np = sotondrvcb(so);
	int len;

	if (np == 0)
		return EINVAL;

	if (np->nd_faddr == 0)
		return ENOTCONN;

	len = np->nd_faddr->snd_len;
	MALLOC(*nam, struct sockaddr *, len, M_SONAME, M_WAITOK);
	if (*nam == NULL)
		return ENOMEM;
	bcopy((caddr_t)np->nd_faddr, *nam,
	      (unsigned)len);
	return 0;
}


/* Control output */

static int
ndrv_ctloutput(struct socket *so, struct sockopt *sopt)
{
    struct ndrv_cb *np = sotondrvcb(so);
	int error = 0;
    
    switch(sopt->sopt_name)
    {
        case NDRV_DELDMXSPEC: /* Delete current spec */
            /* Verify no parameter was passed */
            if (sopt->sopt_val != 0 || sopt->sopt_valsize != 0) {
                /*
                 * We don't support deleting a specific demux, it's
                 * all or nothing.
                 */
                return EINVAL;
            }
            error = ndrv_delspec(np);
            break;
        case NDRV_SETDMXSPEC: /* Set protocol spec */
            error = ndrv_setspec(np, sopt);
            break;
        case NDRV_ADDMULTICAST:
            error = ndrv_do_add_multicast(np, sopt);
            break;
        case NDRV_DELMULTICAST:
            error = ndrv_do_remove_multicast(np, sopt);
            break;
        default:
            error = ENOTSUP;
    }
#ifdef NDRV_DEBUG
	log(LOG_WARNING, "NDRV CTLOUT: %x returns %d\n", sopt->sopt_name,
	    error);
#endif
	return(error);
}

static int
ndrv_do_detach(struct ndrv_cb *np)
{
    struct ndrv_cb*	cur_np = NULL;
    struct socket *so = np->nd_socket;
    int error = 0;
    struct ifnet * ifp;

#if NDRV_DEBUG
	kprintf("NDRV detach: %x, %x\n", so, np);
#endif
    ndrv_remove_all_multicast(np);

    ifp = np->nd_if;
    /* Remove from the linked list of control blocks */
    TAILQ_REMOVE(&ndrvl, np, nd_next);
    if (ifp != NULL) {
		u_int32_t proto_family = np->nd_proto_family;

		if (proto_family != PF_NDRV && proto_family != 0) {
			socket_unlock(so, 0);
			ifnet_detach_protocol(ifp, proto_family);
			socket_lock(so, 0);
		}
		
		/* Check if this is the last socket attached to this interface */
		TAILQ_FOREACH(cur_np, &ndrvl, nd_next) {
			if (cur_np->nd_family == np->nd_family &&
				cur_np->nd_unit == np->nd_unit) {
				break;
			}
		}
		
		/* If there are no other interfaces, detach PF_NDRV from the interface */
		if (cur_np == NULL) {
			socket_unlock(so, 0);
			ifnet_detach_protocol(ifp, PF_NDRV);
			socket_lock(so, 0);
		}
	}
    	if (np->nd_laddr != NULL) {
		FREE((caddr_t)np->nd_laddr, M_IFADDR);
		np->nd_laddr = NULL;
	}
	FREE((caddr_t)np, M_PCB);
	so->so_pcb = 0;
	so->so_flags |= SOF_PCBCLEARING;
	sofree(so);
	return error;
}

static int
ndrv_do_disconnect(struct ndrv_cb *np)
{
	struct socket * so = np->nd_socket;
#if NDRV_DEBUG
	kprintf("NDRV disconnect: %x\n", np);
#endif
	if (np->nd_faddr)
	{
        FREE(np->nd_faddr, M_IFADDR);
		np->nd_faddr = 0;
	}
	/*
	 * A multipath subflow socket would have its SS_NOFDREF set by default,
	 * so check for SOF_MP_SUBFLOW socket flag before detaching the PCB;
	 * when the socket is closed for real, SOF_MP_SUBFLOW would be cleared.
	 */
	if (!(so->so_flags & SOF_MP_SUBFLOW) && (so->so_state & SS_NOFDREF))
		ndrv_do_detach(np);
	soisdisconnected(so);
	return(0);
}

/* Hackery - return a string version of a decimal number */
static void
sprint_d(u_int n, char *buf, int buflen)
{	char dbuf[IFNAMSIZ];
	char *cp = dbuf+IFNAMSIZ-1;

        *cp = 0;
        do {	buflen--;
		cp--;
                *cp = "0123456789"[n % 10];
                n /= 10;
        } while (n != 0 && buflen > 0);
	strlcpy(buf, cp, IFNAMSIZ-buflen);
        return;
}

/*
 * Try to compare a device name (q) with one of the funky ifnet
 *  device names (ifp).
 */
static int name_cmp(struct ifnet *ifp, char *q)
{	char *r;
	int len;
	char buf[IFNAMSIZ];

	r = buf;
	len = strlen(ifnet_name(ifp));
	strlcpy(r, ifnet_name(ifp), IFNAMSIZ);
	r += len;
	sprint_d(ifnet_unit(ifp), r, IFNAMSIZ-(r-buf));
#if NDRV_DEBUG
	kprintf("Comparing %s, %s\n", buf, q);
#endif
	return(strncmp(buf, q, IFNAMSIZ));
}

#if 0
//### Not used
/*
 * When closing, dump any enqueued mbufs.
 */
void
ndrv_flushq(struct ifqueue *q)
{
    struct mbuf *m;
	for (;;)
	{
		IF_DEQUEUE(q, m);
		if (m == NULL)
			break;
		IF_DROP(q);
		if (m)
			m_freem(m);
	}
}
#endif 

int
ndrv_setspec(struct ndrv_cb *np, struct sockopt *sopt)
{
	struct ifnet_attach_proto_param	proto_param;
	struct ndrv_protocol_desc	ndrvSpec;
	struct ndrv_demux_desc*		ndrvDemux = NULL;
	int							error = 0;
	struct socket *				so = np->nd_socket; 
	user_addr_t					user_addr;
	
	/* Sanity checking */
	if (np->nd_proto_family != PF_NDRV)
		return EBUSY;
	if (np->nd_if == NULL)
		return EINVAL;

	/* Copy the ndrvSpec */
	if (proc_is64bit(sopt->sopt_p)) {
		struct ndrv_protocol_desc64	ndrvSpec64;

		if (sopt->sopt_valsize != sizeof(ndrvSpec64))
			return EINVAL;
	
		error = sooptcopyin(sopt, &ndrvSpec64, sizeof(ndrvSpec64), sizeof(ndrvSpec64));
		if (error != 0)
			return error;

		ndrvSpec.version         = ndrvSpec64.version;
		ndrvSpec.protocol_family = ndrvSpec64.protocol_family;
		ndrvSpec.demux_count     = ndrvSpec64.demux_count;

		user_addr = ndrvSpec64.demux_list;
	}
	else {
		struct ndrv_protocol_desc32	ndrvSpec32;

		if (sopt->sopt_valsize != sizeof(ndrvSpec32))
			return EINVAL;
	
		error = sooptcopyin(sopt, &ndrvSpec32, sizeof(ndrvSpec32), sizeof(ndrvSpec32));
		if (error != 0)
			return error;

		ndrvSpec.version         = ndrvSpec32.version;
		ndrvSpec.protocol_family = ndrvSpec32.protocol_family;
		ndrvSpec.demux_count     = ndrvSpec32.demux_count;

		user_addr = CAST_USER_ADDR_T(ndrvSpec32.demux_list);
	}
	
	/* Verify the parameter */
	if (ndrvSpec.version > NDRV_PROTOCOL_DESC_VERS)
		return ENOTSUP; // version is too new!
	else if (ndrvSpec.version < 1)
		return EINVAL; // version is not valid
	else if (ndrvSpec.demux_count > NDRV_PROTODEMUX_COUNT || ndrvSpec.demux_count == 0)
		return EINVAL; // demux_count is not valid
	
	bzero(&proto_param, sizeof(proto_param));
	proto_param.demux_count = ndrvSpec.demux_count;
	
	/* Allocate storage for demux array */
	MALLOC(ndrvDemux, struct ndrv_demux_desc*, proto_param.demux_count *
		   sizeof(struct ndrv_demux_desc), M_TEMP, M_WAITOK);
	if (ndrvDemux == NULL)
		return ENOMEM;
	
	/* Allocate enough ifnet_demux_descs */
	MALLOC(proto_param.demux_array, struct ifnet_demux_desc*,
		   sizeof(*proto_param.demux_array) * ndrvSpec.demux_count,
		   M_TEMP, M_WAITOK);
	if (proto_param.demux_array == NULL)
		error = ENOMEM;
	
	if (error == 0)
	{
		/* Copy the ndrv demux array from userland */
		error = copyin(user_addr, ndrvDemux,
					   ndrvSpec.demux_count * sizeof(struct ndrv_demux_desc));
		ndrvSpec.demux_list = ndrvDemux;
	}
	
	if (error == 0)
	{
		/* At this point, we've at least got enough bytes to start looking around */
		u_int32_t	demuxOn = 0;
		
		proto_param.demux_count = ndrvSpec.demux_count;
		proto_param.input = ndrv_input;
		proto_param.event = ndrv_event;
		
		for (demuxOn = 0; demuxOn < ndrvSpec.demux_count; demuxOn++)
		{
			/* Convert an ndrv_demux_desc to a ifnet_demux_desc */
			error = ndrv_to_ifnet_demux(&ndrvSpec.demux_list[demuxOn],
										&proto_param.demux_array[demuxOn]);
			if (error)
				break;
		}
	}
	
	if (error == 0)
	{
		/* We've got all our ducks lined up...lets attach! */
		socket_unlock(so, 0);
		error = ifnet_attach_protocol(np->nd_if, ndrvSpec.protocol_family,
									  &proto_param);
		socket_lock(so, 0);
		if (error == 0)
			np->nd_proto_family = ndrvSpec.protocol_family;
	}
	
	/* Free any memory we've allocated */
	if (proto_param.demux_array)
		FREE(proto_param.demux_array, M_TEMP);
	if (ndrvDemux)
		FREE(ndrvDemux, M_TEMP);
	
	return error;
}


int
ndrv_to_ifnet_demux(struct ndrv_demux_desc* ndrv, struct ifnet_demux_desc* ifdemux)
{
    bzero(ifdemux, sizeof(*ifdemux));
    
    if (ndrv->type < DLIL_DESC_ETYPE2)
    {
        /* using old "type", not supported */
        return ENOTSUP;
    }
    
    if (ndrv->length > 28)
    {
        return EINVAL;
    }
    
    ifdemux->type = ndrv->type;
    ifdemux->data = ndrv->data.other;
    ifdemux->datalen = ndrv->length;
    
    return 0;
}

int
ndrv_delspec(struct ndrv_cb *np)
{
    int result = 0;
    
    if (np->nd_proto_family == PF_NDRV ||
    	np->nd_proto_family == 0)
        return EINVAL;
    
    /* Detach the protocol */
    result = ifnet_detach_protocol(np->nd_if, np->nd_proto_family);
    np->nd_proto_family = PF_NDRV;
    
	return result;
}

struct ndrv_cb *
ndrv_find_inbound(struct ifnet *ifp, u_int32_t protocol)
{
    struct ndrv_cb* np;
	
	if (protocol == PF_NDRV) return NULL;
    
    TAILQ_FOREACH(np, &ndrvl, nd_next) {
        if (np->nd_proto_family == protocol &&
        	np->nd_if == ifp) {
            return np;
        }
    }
    
	return NULL;
}

static void
ndrv_handle_ifp_detach(u_int32_t family, short unit)
{
    struct ndrv_cb* np;
    struct ifnet	*ifp = NULL;
    struct socket *so;
    
    /* Find all sockets using this interface. */
    TAILQ_FOREACH(np, &ndrvl, nd_next) {
        if (np->nd_family == family &&
            np->nd_unit == unit)
        {
            /* This cb is using the detaching interface, but not for long. */
            /* Let the protocol go */
            ifp = np->nd_if;
            if (np->nd_proto_family != 0)
                ndrv_delspec(np);
            
            /* Delete the multicasts first */
            ndrv_remove_all_multicast(np);
            
            /* Disavow all knowledge of the ifp */
            np->nd_if = NULL;
            np->nd_unit = 0;
            np->nd_family = 0;
           
		  so = np->nd_socket; 
            /* Make sure sending returns an error */
		lck_mtx_assert(ndrvdomain->dom_mtx, LCK_MTX_ASSERT_OWNED);
            socantsendmore(so);
            socantrcvmore(so);
        }
    }
    
    /* Unregister our protocol */
    if (ifp) {
        ifnet_detach_protocol(ifp, PF_NDRV);
    }
}

static int
ndrv_do_add_multicast(struct ndrv_cb *np, struct sockopt *sopt)
{
    struct ndrv_multiaddr*	ndrv_multi;
    int						result;
    
    if (sopt->sopt_val == 0 || sopt->sopt_valsize < 2 ||
        sopt->sopt_level != SOL_NDRVPROTO || sopt->sopt_valsize > SOCK_MAXADDRLEN)
        return EINVAL;
    if (np->nd_if == NULL)
        return ENXIO;
	if (!(np->nd_dlist_cnt < ndrv_multi_max_count))
		return EPERM;
    
    // Allocate storage
    MALLOC(ndrv_multi, struct ndrv_multiaddr*, sizeof(struct ndrv_multiaddr) -
        sizeof(struct sockaddr) + sopt->sopt_valsize, M_IFADDR, M_WAITOK);
    if (ndrv_multi == NULL)
        return ENOMEM;
    
    // Copy in the address
    result = copyin(sopt->sopt_val, &ndrv_multi->addr, sopt->sopt_valsize);
    
    // Validate the sockaddr
    if (result == 0 && sopt->sopt_valsize != ndrv_multi->addr.sa_len)
        result = EINVAL;
    
    if (result == 0 && ndrv_have_multicast(np, &ndrv_multi->addr))
        result = EEXIST;
    
    if (result == 0)
    {
        // Try adding the multicast
        result = ifnet_add_multicast(np->nd_if, &ndrv_multi->addr,
        							 &ndrv_multi->ifma);
    }
    
    if (result == 0)
    {
        // Add to our linked list
        ndrv_multi->next = np->nd_multiaddrs;
        np->nd_multiaddrs = ndrv_multi;
		np->nd_dlist_cnt++;
    }
    else
    {
        // Free up the memory, something went wrong
        FREE(ndrv_multi, M_IFADDR);
    }
    
    return result;
}

static int
ndrv_do_remove_multicast(struct ndrv_cb *np, struct sockopt *sopt)
{
    struct sockaddr*		multi_addr;
    struct ndrv_multiaddr*	ndrv_entry = NULL;
    int					result;
    
    if (sopt->sopt_val == 0 || sopt->sopt_valsize < 2 ||
        sopt->sopt_level != SOL_NDRVPROTO)
        return EINVAL;
    if (np->nd_if == NULL || np->nd_dlist_cnt == 0)
        return ENXIO;
    
    // Allocate storage
    MALLOC(multi_addr, struct sockaddr*, sopt->sopt_valsize,
            M_TEMP, M_WAITOK);
    if (multi_addr == NULL)
        return ENOMEM;
    
    // Copy in the address
    result = copyin(sopt->sopt_val, multi_addr, sopt->sopt_valsize);
    
    // Validate the sockaddr
    if (result == 0 && sopt->sopt_valsize != multi_addr->sa_len)
        result = EINVAL;
    
    if (result == 0)
    {
        /* Find the old entry */
        ndrv_entry = ndrv_have_multicast(np, multi_addr);
        
        if (ndrv_entry == NULL)
            result = ENOENT;
    }
    
    if (result == 0)
    {
        // Try deleting the multicast
        result = ifnet_remove_multicast(ndrv_entry->ifma);
    }
    
    if (result == 0)
    {
        // Remove from our linked list
        struct ndrv_multiaddr*	cur = np->nd_multiaddrs;
        
        ifmaddr_release(ndrv_entry->ifma);
        
        if (cur == ndrv_entry)
        {
            np->nd_multiaddrs = cur->next;
        }
        else
        {
            for (cur = cur->next; cur != NULL; cur = cur->next)
            {
                if (cur->next == ndrv_entry)
                {
                    cur->next = cur->next->next;
                    break;
                }
            }
        }
        
		np->nd_dlist_cnt--;
		
        // Free the memory
        FREE(ndrv_entry, M_IFADDR);
    }
    FREE(multi_addr, M_TEMP);
    
    return result;
}

static struct ndrv_multiaddr*
ndrv_have_multicast(struct ndrv_cb *np, struct sockaddr* inAddr)
{
    struct ndrv_multiaddr*	cur;
    for (cur = np->nd_multiaddrs; cur != NULL; cur = cur->next)
    {
        
        if ((inAddr->sa_len == cur->addr.sa_len) &&
            (bcmp(&cur->addr, inAddr, inAddr->sa_len) == 0))
        {
            // Found a match
            return cur;
        }
    }
    
    return NULL;
}

static void
ndrv_remove_all_multicast(struct ndrv_cb* np)
{
    struct ndrv_multiaddr*	cur;
    
    if (np->nd_if != NULL)
    {
        while (np->nd_multiaddrs != NULL)
        {
            cur = np->nd_multiaddrs;
            np->nd_multiaddrs = cur->next;
            
            ifnet_remove_multicast(cur->ifma);
            ifmaddr_release(cur->ifma);
            FREE(cur, M_IFADDR);
        }
    }
}

static struct pr_usrreqs ndrv_usrreqs = {
	.pru_abort =		ndrv_abort,
	.pru_attach =		ndrv_attach,
	.pru_bind =		ndrv_bind,
	.pru_connect =		ndrv_connect,
	.pru_detach =		ndrv_detach,
	.pru_disconnect =	ndrv_disconnect,
	.pru_peeraddr =		ndrv_peeraddr,
	.pru_send =		ndrv_send,
	.pru_shutdown =		ndrv_shutdown,
	.pru_sockaddr =		ndrv_sockaddr,
	.pru_sosend =		sosend,
	.pru_soreceive =	soreceive,
};

static struct protosw ndrvsw[] = {
{
	.pr_type =		SOCK_RAW,
	.pr_protocol =		NDRVPROTO_NDRV,
	.pr_flags =		PR_ATOMIC|PR_ADDR,
	.pr_output =		ndrv_output,
	.pr_ctloutput =		ndrv_ctloutput,
	.pr_usrreqs =		&ndrv_usrreqs,
}
};

static int ndrv_proto_count = (sizeof (ndrvsw) / sizeof (struct protosw));

struct domain ndrvdomain_s = {
	.dom_family =		PF_NDRV,
	.dom_name =		"NetDriver",
	.dom_init =		ndrv_dominit,
};

static void
ndrv_dominit(struct domain *dp)
{
	struct protosw *pr;
	int i;

	VERIFY(!(dp->dom_flags & DOM_INITIALIZED));
	VERIFY(ndrvdomain == NULL);

	ndrvdomain = dp;

	for (i = 0, pr = &ndrvsw[0]; i < ndrv_proto_count; i++, pr++)
		net_add_proto(pr, dp, 1);
}
