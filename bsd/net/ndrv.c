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
/* Copyright (c) 1997, 1998 Apple Computer, Inc. All Rights Reserved */
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
 *  protocol packets.  This lets ndrv_output() call dlil_output(), and
 *  lets DLIL find the proper recipient for incoming packets.
 *  The purpose here is for user-mode protocol implementation.
 * Note that "pure raw access" will still be accomplished with BPF.
 *
 * In addition to the former use, when combined with socket NKEs,
 * PF_NDRV permits a fairly flexible mechanism for implementing
 * strange protocol support.  One of the main ones will be the
 * BlueBox/Classic Shared IP Address support.
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
#include <sys/errno.h>
#include <sys/syslog.h>
#include <sys/proc.h>

#include <kern/queue.h>

#include <net/ndrv.h>
#include <net/netisr.h>
#include <net/route.h>
#include <net/if_llc.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/ndrv_var.h>

#if INET
#include <netinet/in.h>
#include <netinet/in_var.h>
#endif
#include <netinet/if_ether.h>

#include <machine/spl.h>

int ndrv_do_detach(struct ndrv_cb *);
int ndrv_do_disconnect(struct ndrv_cb *);
struct ndrv_cb *ndrv_find_tag(unsigned int);
void ndrv_read_event(struct socket* inSo, caddr_t ref, int waitf);
int ndrv_setspec(struct ndrv_cb *np, struct sockopt *sopt);
int ndrv_delspec(struct ndrv_cb *);
int ndrv_to_dlil_demux(struct ndrv_demux_desc* ndrv, struct dlil_demux_desc* dlil);
void ndrv_handle_ifp_detach(u_long family, short unit);
static int ndrv_do_add_multicast(struct ndrv_cb *np, struct sockopt *sopt);
static int ndrv_do_remove_multicast(struct ndrv_cb *np, struct sockopt *sopt);
static struct ndrv_multiaddr* ndrv_have_multicast(struct ndrv_cb *np, struct sockaddr* addr);
static void ndrv_remove_all_multicast(struct ndrv_cb *np);

unsigned long  ndrv_sendspace = NDRVSNDQ;
unsigned long  ndrv_recvspace = NDRVRCVQ;
struct ndrv_cb ndrvl;		/* Head of controlblock list */

struct domain ndrvdomain;
struct protosw ndrvsw;
static struct socket* ndrv_so;


/*
 * Protocol init function for NDRV protocol
 * Init the control block list.
 */
void
ndrv_init()
{
    int retval;
    struct kev_request kev_request;
    
	ndrvl.nd_next = ndrvl.nd_prev = &ndrvl;
    
    /* Create a PF_SYSTEM socket so we can listen for events */
    retval = socreate(PF_SYSTEM, &ndrv_so, SOCK_RAW, SYSPROTO_EVENT);
    if (retval != 0 || ndrv_so == NULL)
        retval = KERN_FAILURE;
    
    /* Install a callback function for the socket */
    ndrv_so->so_rcv.sb_flags |= SB_NOTIFY|SB_UPCALL;
    ndrv_so->so_upcall = ndrv_read_event;
    ndrv_so->so_upcallarg = NULL;
    
    /* Configure the socket to receive the events we're interested in */
    kev_request.vendor_code = KEV_VENDOR_APPLE;
    kev_request.kev_class = KEV_NETWORK_CLASS;
    kev_request.kev_subclass = KEV_DL_SUBCLASS;
    retval = ndrv_so->so_proto->pr_usrreqs->pru_control(ndrv_so, SIOCSKEVFILT, (caddr_t)&kev_request, 0, 0);
    if (retval != 0)
    {
        /*
         * We will not get attaching or detaching events in this case.
         * We should probably prevent any sockets from binding so we won't
         * panic later if the interface goes away.
         */
        log(LOG_WARNING, "PF_NDRV: ndrv_init - failed to set event filter (%d)",
            retval);
    }
}

/*
 * Protocol output - Called to output a raw network packet directly
 *  to the driver.
 */
int
ndrv_output(register struct mbuf *m, register struct socket *so)
{
    register struct ndrv_cb *np = sotondrvcb(so);
	register struct ifnet *ifp = np->nd_if;
	extern void kprintf(const char *, ...);
    int	result = 0;

#if NDRV_DEBUG
	kprintf("NDRV output: %x, %x, %x\n", m, so, np);
#endif

	/*
	 * No header is a format error
	 */
	if ((m->m_flags&M_PKTHDR) == 0)
		return(EINVAL);

	/*
     * Call DLIL if we can. DLIL is much safer than calling the
     * ifp directly.
     */
    if (np->nd_tag != 0)
        result = dlil_output(np->nd_tag, m, (caddr_t)NULL,
                            (struct sockaddr*)NULL, 1);
    else if (np->nd_send_tag != 0)
        result = dlil_output(np->nd_send_tag, m, (caddr_t)NULL,
                            (struct sockaddr*)NULL, 1);
    else
        result = ENXIO;
	return (result);
}

/* Our input routine called from DLIL */
int
ndrv_input(struct mbuf *m,
	   char *frame_header,
	   struct ifnet *ifp,
	   u_long  dl_tag,
	   int sync_ok)
{
	struct socket *so;
	struct sockaddr_dl ndrvsrc = {sizeof (struct sockaddr_dl), AF_NDRV};
	register struct ndrv_cb *np;


    /* move packet from if queue to socket */
	/* Should be media-independent */
    ndrvsrc.sdl_type = IFT_ETHER;
    ndrvsrc.sdl_nlen = 0;
    ndrvsrc.sdl_alen = 6;
    ndrvsrc.sdl_slen = 0;
    bcopy(frame_header, &ndrvsrc.sdl_data, 6);

	np = ndrv_find_tag(dl_tag);
	if (np == NULL)
	{
		return(ENOENT);
	}
	so = np->nd_socket;
    /* prepend the frame header */
    m = m_prepend(m, ifp->if_data.ifi_hdrlen, M_NOWAIT);
    if (m == NULL)
        return EJUSTRETURN;
    bcopy(frame_header, m->m_data, ifp->if_data.ifi_hdrlen);
	if (sbappendaddr(&(so->so_rcv), (struct sockaddr *)&ndrvsrc,
			 m, (struct mbuf *)0) == 0)
	{
        /* yes, sbappendaddr returns zero if the sockbuff is full... */
        /* caller will free m */
		return(ENOMEM);
	} else
		sorwakeup(so);
	return(0);
}

int
ndrv_control(struct socket *so, u_long cmd, caddr_t data,
		  struct ifnet *ifp, struct proc *p)
{
	return (0);
}

/*
 * Allocate an ndrv control block and some buffer space for the socket
 */
int
ndrv_attach(struct socket *so, int proto, struct proc *p)
{
    int error;
	register struct ndrv_cb *np = sotondrvcb(so);

	if ((so->so_state & SS_PRIV) == 0)
		return(EPERM);

#if NDRV_DEBUG
	kprintf("NDRV attach: %x, %x, %x\n", so, proto, np);
#endif
	MALLOC(np, struct ndrv_cb *, sizeof(*np), M_PCB, M_WAITOK);
	if (np == NULL)
		return (ENOMEM);
    so->so_pcb = (caddr_t)np;
    bzero(np, sizeof(*np));
#if NDRV_DEBUG
	kprintf("NDRV attach: %x, %x, %x\n", so, proto, np);
#endif
	if ((error = soreserve(so, ndrv_sendspace, ndrv_recvspace)))
		return(error);
	TAILQ_INIT(&np->nd_dlist);
	np->nd_signature = NDRV_SIGNATURE;
	np->nd_socket = so;
	np->nd_proto.sp_family = so->so_proto->pr_domain->dom_family;
	np->nd_proto.sp_protocol = proto;
    np->nd_if = NULL;
    np->nd_tag = 0;
    np->nd_family = 0;
    np->nd_unit = 0;
	insque((queue_t)np, (queue_t)&ndrvl);
	return(0);
}

/*
 * Destroy state just before socket deallocation.
 * Flush data or not depending on the options.
 */

int
ndrv_detach(struct socket *so)
{
	register struct ndrv_cb *np = sotondrvcb(so);

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

int ndrv_connect(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	register struct ndrv_cb *np = sotondrvcb(so);
    int	result = 0;

	if (np == 0)
		return EINVAL;

	if (np->nd_faddr)
		return EISCONN;
    
    /* Allocate memory to store the remote address */
    MALLOC(np->nd_faddr, struct sockaddr_ndrv*,
                nam->sa_len, M_IFADDR, M_WAITOK);
    if (result != 0)
        return result;
    if (np->nd_faddr == NULL)
        return ENOMEM;
    
	bcopy((caddr_t) nam, (caddr_t) np->nd_faddr, nam->sa_len);
	soisconnected(so);
	return 0;
}

/*
 * This is the "driver open" hook - we 'bind' to the
 *  named driver.
 * Here's where we latch onto the driver.
 */
int
ndrv_bind(struct socket *so, struct sockaddr *nam, struct proc *p)
{
    register struct sockaddr_ndrv *sa = (struct sockaddr_ndrv *) nam;
	register char *dname;
	register struct ndrv_cb *np;
	register struct ifnet *ifp;
	extern int name_cmp(struct ifnet *, char *);
    int	result;

	if TAILQ_EMPTY(&ifnet)
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
	dname = sa->snd_name;
	if (*dname == '\0')
		return(EINVAL);
#if NDRV_DEBUG
	kprintf("NDRV bind: %x, %x, %s\n", so, np, dname);
#endif
	/* Track down the driver and its ifnet structure.
	 * There's no internal call for this so we have to dup the code
	 *  in if.c/ifconf()
	 */
	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		if (name_cmp(ifp, dname) == 0)
			break;
	}

	if (ifp == NULL)
		return(EADDRNOTAVAIL);
    
    /* 
     * Loopback demuxing doesn't work with PF_NDRV.
     * The first 4 bytes of the packet must be the
     * protocol ptr. Can't get that from userland.
     */
    if (ifp->if_family == APPLE_IF_FAM_LOOPBACK)
        return (ENOTSUP);
    
    if ((dlil_find_dltag(ifp->if_family, ifp->if_unit,
                         PF_NDRV, &np->nd_send_tag) != 0) &&
        (ifp->if_family != APPLE_IF_FAM_PPP)) {
        /* NDRV isn't registered on this interface, lets change that */
        struct dlil_proto_reg_str	ndrv_proto;
        int	result = 0;
        bzero(&ndrv_proto, sizeof(ndrv_proto));
        TAILQ_INIT(&ndrv_proto.demux_desc_head);
        
        ndrv_proto.interface_family = ifp->if_family;
        ndrv_proto.protocol_family = PF_NDRV;
        ndrv_proto.unit_number = ifp->if_unit;
        
        result = dlil_attach_protocol(&ndrv_proto, &np->nd_send_tag);
        
        /*
         * If the interface does not allow PF_NDRV to attach, we will
         * respect it's wishes. Sending will be disabled. No error is
         * returned because the client may later attach a real protocol
         * that the interface may accept.
         */
        if (result != 0)
            np->nd_send_tag = 0;
    }
    
	np->nd_if = ifp;
    np->nd_family = ifp->if_family;
    np->nd_unit = ifp->if_unit;
    
	return(0);
}

int
ndrv_disconnect(struct socket *so)
{
	register struct ndrv_cb *np = sotondrvcb(so);

	if (np == 0)
		return EINVAL;

	if (np->nd_faddr == 0)
		return ENOTCONN;

	ndrv_do_disconnect(np);
	return 0;
}

/*
 * Accessor function
 */
struct ifnet*
ndrv_get_ifp(caddr_t ndrv_pcb)
{
    struct ndrv_cb*	np = (struct ndrv_cb*)ndrv_pcb;
    
#if DEBUG
    {
        struct ndrv_cb* temp = ndrvl.nd_next;
        /* Verify existence of pcb */
        for (temp = ndrvl.nd_next; temp != &ndrvl; temp = temp->nd_next)
        {
            if (temp == np)
                break;
        }
        
        if (temp != np)
        {
            log(LOG_WARNING, "PF_NDRV: ndrv_get_ifp called with invalid ndrv_cb!");
            return NULL;
        }
    }
#endif
    
    return np->nd_if;
}

/*
 * Mark the connection as being incapable of further input.
 */
int
ndrv_shutdown(struct socket *so)
{
	socantsendmore(so);
	return 0;
}

/*
 * Ship a packet out.  The ndrv output will pass it
 *  to the appropriate driver.  The really tricky part
 *  is the destination address...
 */
int
ndrv_send(struct socket *so, int flags, struct mbuf *m,
	  struct sockaddr *addr, struct mbuf *control,
	  struct proc *p)
{
	int error;

	if (control)
		return EOPNOTSUPP;

	error = ndrv_output(m, so);
	m = NULL;
	return error;
}


int
ndrv_abort(struct socket *so)
{
	register struct ndrv_cb *np = sotondrvcb(so);

	if (np == 0)
		return EINVAL;

	ndrv_do_disconnect(np);
	return 0;
}

int
ndrv_sense(struct socket *so, struct stat *sb)
{
	/*
	 * stat: don't bother with a blocksize.
	 */
	return (0);
}

int
ndrv_sockaddr(struct socket *so, struct sockaddr **nam)
{
	register struct ndrv_cb *np = sotondrvcb(so);
	int len;

	if (np == 0)
		return EINVAL;

	if (np->nd_laddr == 0)
		return EINVAL;

	len = np->nd_laddr->snd_len;
	bcopy((caddr_t)np->nd_laddr, *nam,
	      (unsigned)len);
	return 0;
}


int
ndrv_peeraddr(struct socket *so, struct sockaddr **nam)
{
	register struct ndrv_cb *np = sotondrvcb(so);
	int len;

	if (np == 0)
		return EINVAL;

	if (np->nd_faddr == 0)
		return ENOTCONN;

	len = np->nd_faddr->snd_len;
	bcopy((caddr_t)np->nd_faddr, *nam,
	      (unsigned)len);
	return 0;
}


/* Control input */

void
ndrv_ctlinput(int dummy1, struct sockaddr *dummy2, void *dummy3)
{
}

/* Control output */

int
ndrv_ctloutput(struct socket *so, struct sockopt *sopt)
{
    register struct ndrv_cb *np = sotondrvcb(so);
	int error = 0;
    
    switch(sopt->sopt_name)
    {
        case NDRV_DELDMXSPEC: /* Delete current spec */
            /* Verify no parameter was passed */
            if (sopt->sopt_val != NULL || sopt->sopt_valsize != 0) {
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

/* Drain the queues */
void
ndrv_drain()
{
}

/* Sysctl hook for NDRV */
int
ndrv_sysctl()
{
	return(0);
}

int
ndrv_do_detach(register struct ndrv_cb *np)
{
    struct ndrv_cb*	cur_np = NULL;
    struct socket *so = np->nd_socket;
    struct ndrv_multicast*	next;
    int error;

#if NDRV_DEBUG
	kprintf("NDRV detach: %x, %x\n", so, np);
#endif
    ndrv_remove_all_multicast(np);
    
    if (np->nd_tag != 0)
    {
        error = dlil_detach_protocol(np->nd_tag);
        if (error)
        {
            log(LOG_WARNING, "NDRV ndrv_do_detach: error %d removing dl_tag %d",
                error, np->nd_tag);
            return error;
        }
    }
    
    /* Remove from the linked list of control blocks */
	remque((queue_t)np);
    
    if (np->nd_send_tag != 0)
    {
        /* Check if this is the last socket attached to this interface */
        for (cur_np = ndrvl.nd_next; cur_np != &ndrvl; cur_np = cur_np->nd_next)
        {
            if (cur_np->nd_family == np->nd_family &&
                cur_np->nd_unit == np->nd_unit)
            {
                break;
            }
        }
        
        /* If there are no other interfaces, detach PF_NDRV from the interface */
        if (cur_np == &ndrvl)
        {
            dlil_detach_protocol(np->nd_send_tag);
        }
    }
    
	FREE((caddr_t)np, M_PCB);
	so->so_pcb = 0;
	sofree(so);
	return error;
}

int
ndrv_do_disconnect(register struct ndrv_cb *np)
{
#if NDRV_DEBUG
	kprintf("NDRV disconnect: %x\n", np);
#endif
	if (np->nd_faddr)
	{
        FREE(np->nd_faddr, M_IFADDR);
		np->nd_faddr = 0;
	}
	if (np->nd_socket->so_state & SS_NOFDREF)
		ndrv_do_detach(np);
	soisdisconnected(np->nd_socket);
	return(0);
}

/*
 * Try to compare a device name (q) with one of the funky ifnet
 *  device names (ifp).
 */
int name_cmp(register struct ifnet *ifp, register char *q)
{	register char *r;
	register int len;
	char buf[IFNAMSIZ];
	static char *sprint_d();

	r = buf;
	len = strlen(ifp->if_name);
	strncpy(r, ifp->if_name, IFNAMSIZ);
	r += len;
	(void)sprint_d(ifp->if_unit, r, IFNAMSIZ-(r-buf));
#if NDRV_DEBUG
	kprintf("Comparing %s, %s\n", buf, q);
#endif
	return(strncmp(buf, q, IFNAMSIZ));
}

/* Hackery - return a string version of a decimal number */
static char *
sprint_d(n, buf, buflen)
        u_int n;
        char *buf;
        int buflen;
{	char dbuf[IFNAMSIZ];
	register char *cp = dbuf+IFNAMSIZ-1;

        *cp = 0;
        do {	buflen--;
		cp--;
                *cp = "0123456789"[n % 10];
                n /= 10;
        } while (n != 0 && buflen > 0);
	strncpy(buf, cp, IFNAMSIZ-buflen);
        return (cp);
}

/*
 * When closing, dump any enqueued mbufs.
 */
void
ndrv_flushq(register struct ifqueue *q)
{
    register struct mbuf *m;
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

int
ndrv_setspec(struct ndrv_cb *np, struct sockopt *sopt)
{
    struct dlil_proto_reg_str	dlilSpec;
    struct ndrv_protocol_desc	ndrvSpec;
    struct dlil_demux_desc*		dlilDemux = NULL;
    struct ndrv_demux_desc*		ndrvDemux = NULL;
    int							error = 0;
    
    /* Sanity checking */
    if (np->nd_tag)
        return EBUSY;
    if (np->nd_if == NULL)
        return EINVAL;
    if (sopt->sopt_valsize != sizeof(struct ndrv_protocol_desc))
        return EINVAL;
    
    /* Copy the ndrvSpec */
    error = sooptcopyin(sopt, &ndrvSpec, sizeof(struct ndrv_protocol_desc),
                        sizeof(struct ndrv_protocol_desc));
    if (error != 0)
        return error;
    
    /* Verify the parameter */
    if (ndrvSpec.version > NDRV_PROTOCOL_DESC_VERS)
        return ENOTSUP; // version is too new!
    else if (ndrvSpec.version < 1)
        return EINVAL; // version is not valid
    
    /* Allocate storage for demux array */
    MALLOC(ndrvDemux, struct ndrv_demux_desc*,
            ndrvSpec.demux_count * sizeof(struct ndrv_demux_desc), M_TEMP, M_WAITOK);
    if (ndrvDemux == NULL)
        return ENOMEM;
    
    /* Allocate enough dlil_demux_descs */
    MALLOC(dlilDemux, struct dlil_demux_desc*,
            sizeof(*dlilDemux) * ndrvSpec.demux_count, M_TEMP, M_WAITOK);
    if (dlilDemux == NULL)
        error = ENOMEM;
    
    if (error == 0)
    {
        /* Copy the ndrv demux array from userland */
        error = copyin(ndrvSpec.demux_list, ndrvDemux,
                    ndrvSpec.demux_count * sizeof(struct ndrv_demux_desc));
        ndrvSpec.demux_list = ndrvDemux;
    }
    
    if (error == 0)
    {
        /* At this point, we've at least got enough bytes to start looking around */
        u_long	demuxOn = 0;
        
        bzero(&dlilSpec, sizeof(dlilSpec));
        TAILQ_INIT(&dlilSpec.demux_desc_head);
        dlilSpec.interface_family = np->nd_family;
        dlilSpec.unit_number = np->nd_unit;
        dlilSpec.input = ndrv_input;
        dlilSpec.protocol_family = ndrvSpec.protocol_family;
        
        for (demuxOn = 0; demuxOn < ndrvSpec.demux_count; demuxOn++)
        {
            /* Convert an ndrv_demux_desc to a dlil_demux_desc */
            error = ndrv_to_dlil_demux(&ndrvSpec.demux_list[demuxOn], &dlilDemux[demuxOn]);
            if (error)
                break;
            
            /* Add the dlil_demux_desc to the list */
            TAILQ_INSERT_TAIL(&dlilSpec.demux_desc_head, &dlilDemux[demuxOn], next);
        }
    }
    
    if (error == 0)
    {
        /* We've got all our ducks lined up...lets attach! */
        error = dlil_attach_protocol(&dlilSpec, &np->nd_tag);
    }
    
    /* Free any memory we've allocated */
    if (dlilDemux)
        FREE(dlilDemux, M_TEMP);
    if (ndrvDemux)
        FREE(ndrvDemux, M_TEMP);
    
    return error;
}


int
ndrv_to_dlil_demux(struct ndrv_demux_desc* ndrv, struct dlil_demux_desc* dlil)
{
    bzero(dlil, sizeof(*dlil));
    
    if (ndrv->type < DLIL_DESC_ETYPE2)
    {
        /* using old "type", not supported */
        return ENOTSUP;
    }
    
    if (ndrv->length > 28)
    {
        return EINVAL;
    }
    
    dlil->type = ndrv->type;
    dlil->native_type = ndrv->data.other;
    dlil->variants.native_type_length = ndrv->length;
    
    return 0;
}

int
ndrv_delspec(struct ndrv_cb *np)
{
    int result = 0;
    
    if (np->nd_tag == 0)
        return EINVAL;
    
    /* Detach the protocol */
    result = dlil_detach_protocol(np->nd_tag);
    if (result == 0)
    {
        np->nd_tag = 0;
    }
    
	return result;
}

struct ndrv_cb *
ndrv_find_tag(unsigned int tag)
{
    struct ndrv_cb* np;
	int i;
    
    if (tag == 0)
        return NULL;
    
    for (np = ndrvl.nd_next; np != NULL; np = np->nd_next)
    {
        if (np->nd_tag == tag)
        {
            return np;
        }
    }
    
	return NULL;
}

void ndrv_dominit()
{
        static int ndrv_dominited = 0;

        if (ndrv_dominited == 0 &&
            net_add_proto(&ndrvsw, &ndrvdomain) == 0)
                ndrv_dominited = 1;
}

void
ndrv_read_event(struct socket* so, caddr_t ref, int waitf)
{
    // Read an event
    struct mbuf *m = NULL;
    struct kern_event_msg *msg;
    struct uio auio = {0};
    int	result = 0;
    int flags = 0;
    
    // Get the data
    auio.uio_resid = 1000000; // large number to get all of the data
    flags = MSG_DONTWAIT;
    result = soreceive(so, (struct sockaddr**)NULL, &auio, &m,
        (struct mbuf**)NULL, &flags);
    if (result != 0 || m == NULL)
        return;
    
    // cast the mbuf to a kern_event_msg
    // this is dangerous, doesn't handle linked mbufs
    msg = mtod(m, struct kern_event_msg*);
    
    // check for detaches, assume even filtering is working
    if (msg->event_code == KEV_DL_IF_DETACHING ||
        msg->event_code == KEV_DL_IF_DETACHED)
    {
        struct net_event_data *ev_data;
        ev_data = (struct net_event_data*)msg->event_data;
        ndrv_handle_ifp_detach(ev_data->if_family, ev_data->if_unit);
    }
    
    m_free(m);
}

void
ndrv_handle_ifp_detach(u_long family, short unit)
{
    struct ndrv_cb* np;
    u_long			dl_tag;
    
    /* Find all sockets using this interface. */
    for (np = ndrvl.nd_next; np != &ndrvl; np = np->nd_next)
    {
        if (np->nd_family == family &&
            np->nd_unit == unit)
        {
            /* This cb is using the detaching interface, but not for long. */
            /* Let the protocol go */
            if (np->nd_tag != 0)
                ndrv_delspec(np);
            
            /* Delete the multicasts first */
            ndrv_remove_all_multicast(np);
            
            /* Disavow all knowledge of the ifp */
            np->nd_if = NULL;
            np->nd_unit = 0;
            np->nd_family = 0;
            np->nd_send_tag = 0;
            
            /* Make sure sending returns an error */
            /* Is this safe? Will we drop the funnel? */
            socantsendmore(np->nd_socket);
            socantrcvmore(np->nd_socket);
        }
    }
    
    /* Unregister our protocol */
    if (dlil_find_dltag(family, unit, PF_NDRV, &dl_tag) == 0) {
        dlil_detach_protocol(dl_tag);
    }
}

static int
ndrv_do_add_multicast(struct ndrv_cb *np, struct sockopt *sopt)
{
    struct ndrv_multiaddr*	ndrv_multi;
    int						result;
    
    if (sopt->sopt_val == NULL || sopt->sopt_valsize < 2 ||
        sopt->sopt_level != SOL_NDRVPROTO)
        return EINVAL;
    if (np->nd_if == NULL)
        return ENXIO;
    
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
        result = if_addmulti(np->nd_if, &ndrv_multi->addr, NULL);
    }
    
    if (result == 0)
    {
        // Add to our linked list
        ndrv_multi->next = np->nd_multiaddrs;
        np->nd_multiaddrs = ndrv_multi;
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
    
    if (sopt->sopt_val == NULL || sopt->sopt_valsize < 2 ||
        sopt->sopt_level != SOL_NDRVPROTO)
        return EINVAL;
    if (np->nd_if == NULL)
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
        result = if_delmulti(np->nd_if, &ndrv_entry->addr);
    }
    
    if (result == 0)
    {
        // Remove from our linked list
        struct ndrv_multiaddr*	cur = np->nd_multiaddrs;
        
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
            
            if_delmulti(np->nd_if, &cur->addr);
            FREE(cur, M_IFADDR);
        }
    }
}

struct pr_usrreqs ndrv_usrreqs = {
	ndrv_abort, pru_accept_notsupp, ndrv_attach, ndrv_bind,
	ndrv_connect, pru_connect2_notsupp, ndrv_control, ndrv_detach,
	ndrv_disconnect, pru_listen_notsupp, ndrv_peeraddr, pru_rcvd_notsupp,
	pru_rcvoob_notsupp, ndrv_send, ndrv_sense, ndrv_shutdown,
	ndrv_sockaddr, sosend, soreceive, sopoll
};

struct protosw ndrvsw =
{	SOCK_RAW, &ndrvdomain, NDRVPROTO_NDRV, PR_ATOMIC|PR_ADDR,
    0, ndrv_output, ndrv_ctlinput, ndrv_ctloutput,
    0, ndrv_init, 0, 0,
    ndrv_drain, ndrv_sysctl, &ndrv_usrreqs
};

struct domain ndrvdomain =
{	AF_NDRV, "NetDriver", ndrv_dominit, NULL, NULL,
	NULL,
	NULL, NULL, 0, 0, 0, 0
};
