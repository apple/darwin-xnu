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

#include <net/if.h>
#include <net/netisr.h>
#include <net/route.h>
#include <net/if_llc.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/dlil.h>
#include "ndrv.h"

#if INET
#include <netinet/in.h>
#include <netinet/in_var.h>
#endif
#include <netinet/if_ether.h>

#if NS
#include <netns/ns.h>
#include <netns/ns_if.h>
#endif

#if ISO
#include <netiso/argo_debug.h>
#include <netiso/iso.h>
#include <netiso/iso_var.h>
#include <netiso/iso_snpac.h>
#endif

#if LLC
#include <netccitt/dll.h>
#include <netccitt/llc_var.h>
#endif

#include <machine/spl.h>

int ndrv_do_detach(struct ndrv_cb *);
int ndrv_do_disconnect(struct ndrv_cb *);

unsigned long  ndrv_sendspace = NDRVSNDQ;
unsigned long  ndrv_recvspace = NDRVRCVQ;
struct ndrv_cb ndrvl;		/* Head of controlblock list */

/* To handle input, need to map tag to ndrv_cb */
struct ndrv_tag_map
{	unsigned int tm_tag;		/* Tag in use */
	struct ndrv_cb *tm_np;		/* Owning device */
	struct dlil_demux_desc *tm_dm;	/* Our local copy */
};

struct ndrv_tag_map *ndrv_tags;
#define TAG_MAP_COUNT 10
int tag_map_count;

struct domain ndrvdomain;
extern struct protosw ndrvsw[];


/*
 * Protocol init function for NDRV protocol
 * Init the control block list.
 */
void
ndrv_init()
{
	ndrvl.nd_next = ndrvl.nd_prev = &ndrvl;
}

/*
 * Protocol output - Called to output a raw network packet directly
 *  to the driver.
 */
int
ndrv_output(register struct mbuf *m, register struct socket *so)
{	register struct ndrv_cb *np = sotondrvcb(so);
	register struct ifnet *ifp = np->nd_if;
	int s, error;
	extern void kprintf(const char *, ...);

#if NDRV_DEBUG
	kprintf("NDRV output: %x, %x, %x\n", m, so, np);
#endif

	/*
	 * No header is a format error
	 */
	if ((m->m_flags&M_PKTHDR) == 0)
		return(EINVAL);

	/*
	 * Can't do multicast accounting because we don't know
	 *  (a) if our interface does multicast; and
	 *  (b) what a multicast address looks like
	 */
	s = splimp();

	/*
	 * Can't call DLIL to do the job - we don't have a tag
	 *  and we aren't really a protocol
	 */

        (*ifp->if_output)(ifp, m);
	splx(s);
	return (0);
}

int
ndrv_input(struct mbuf *m,
	   char *frame_header,
	   struct ifnet *ifp,
	   u_long  dl_tag,
	   int sync_ok)
{	int s;
	struct socket *so;
	struct sockaddr_dl ndrvsrc = {sizeof (struct sockaddr_dl), AF_NDRV};
	register struct ndrv_cb *np;
	extern struct ndrv_cb *ndrv_find_tag(unsigned int);


        /* move packet from if queue to socket */
	/* Should be media-independent */
        ndrvsrc.sdl_type = IFT_ETHER;
        ndrvsrc.sdl_nlen = 0;
        ndrvsrc.sdl_alen = 6;
        ndrvsrc.sdl_slen = 0;
        bcopy(frame_header, &ndrvsrc.sdl_data, 6);

	s = splnet();
	np = ndrv_find_tag(dl_tag);
	if (np == NULL)
	{	splx(s);
		return(ENOENT);
	}
	so = np->nd_socket;
	if (sbappendaddr(&(so->so_rcv), (struct sockaddr *)&ndrvsrc,
			 m, (struct mbuf *)0) == 0)
	{	/* yes, sbappendaddr returns zero if the sockbuff is full... */
		splx(s);
		return(ENOMEM);
	} else
		sorwakeup(so);
	splx(s);
	return(0);
}

int
ndrv_ioctl(unsigned long dl_tag,
	   struct ifnet *ifp,
	   unsigned long command,
	   caddr_t data)
{
	if (ifp)
		return((*ifp->if_ioctl)(ifp, command, data));
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
{	int error;
	register struct ndrv_cb *np = sotondrvcb(so);

	if ((so->so_state & SS_PRIV) == 0)
		return(EPERM);

#if NDRV_DEBUG
	kprintf("NDRV attach: %x, %x, %x\n", so, proto, np);
#endif
	MALLOC(np, struct ndrv_cb *, sizeof(*np), M_PCB, M_WAITOK);
	if (np == NULL)
		return (ENOMEM);
#if NDRV_DEBUG
	kprintf("NDRV attach: %x, %x, %x\n", so, proto, np);
#endif
	if ((so->so_pcb = (caddr_t)np))
		bzero(np, sizeof(*np));
	else
		return(ENOBUFS);
	if ((error = soreserve(so, ndrv_sendspace, ndrv_recvspace)))
		return(error);
	TAILQ_INIT(&np->nd_dlist);
	np->nd_signature = NDRV_SIGNATURE;
	np->nd_socket = so;
	np->nd_proto.sp_family = so->so_proto->pr_domain->dom_family;
	np->nd_proto.sp_protocol = proto;
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

	if (np == 0)
		return EINVAL;

	if (np->nd_faddr)
		return EISCONN;

	bcopy((caddr_t) nam, (caddr_t) np->nd_faddr, sizeof(struct sockaddr_ndrv));
	soisconnected(so);
	return 0;
}

/*
 * This is the "driver open" hook - we 'bind' to the
 *  named driver.
 * Here's where we latch onto the driver and make it ours.
 */
int
ndrv_bind(struct socket *so, struct sockaddr *nam, struct proc *p)
{	register struct sockaddr_ndrv *sa = (struct sockaddr_ndrv *) nam;
	register char *dname;
	register struct ndrv_cb *np;
	register struct ifnet *ifp;
	extern int name_cmp(struct ifnet *, char *);

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
	np->nd_if = ifp;
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
{	register struct ndrv_cb *np = sotondrvcb(so);
	struct ndrv_descr nd;
	int count = 0, error = 0;
	int ndrv_getspec(struct ndrv_cb *,
			 struct sockopt *,
			 struct ndrv_descr *);
	int ndrv_setspec(struct ndrv_cb *, struct ndrv_descr *);
	int ndrv_delspec(struct ndrv_cb *, struct ndrv_descr *);

	if (sopt->sopt_name != NDRV_DMXSPECCNT)
		error = sooptcopyin(sopt, &nd, sizeof nd, sizeof nd);
	if (error == 0)
	{	switch(sopt->sopt_name)
		{	case NDRV_DMXSPEC: /* Get/Set(Add) spec list */
				if (sopt->sopt_dir == SOPT_GET)
					error = ndrv_getspec(np, sopt, &nd);
				else
					error = ndrv_setspec(np, &nd);
				break;
			case NDRV_DELDMXSPEC: /* Delete specified specs */
				error = ndrv_delspec(np, &nd);
				break;
			case NDRV_DMXSPECCNT: /* How many are in the list */
				count = np->nd_descrcnt;
				error = sooptcopyout(sopt, &count, sizeof count);
				break;
		}
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
{	register struct socket *so = np->nd_socket;
	int ndrv_dump_descr(struct ndrv_cb *);

#if NDRV_DEBUG
	kprintf("NDRV detach: %x, %x\n", so, np);
#endif
	if (!TAILQ_EMPTY(&np->nd_dlist))
		ndrv_dump_descr(np);

	remque((queue_t)np);
	FREE((caddr_t)np, M_PCB);
	so->so_pcb = 0;
	sofree(so);
	return(0);
}

int
ndrv_do_disconnect(register struct ndrv_cb *np)
{
#if NDRV_DEBUG
	kprintf("NDRV disconnect: %x\n", np);
#endif
	if (np->nd_faddr)
	{	m_freem(dtom(np->nd_faddr));
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
{	register struct mbuf *m;
	register int s;
	for (;;)
	{	s = splimp();
		IF_DEQUEUE(q, m);
		if (m == NULL)
			break;
		IF_DROP(q);
		splx(s);
		if (m)
			m_freem(m);
	}
	splx(s);
}

int
ndrv_getspec(struct ndrv_cb *np,
	     struct sockopt *sopt,
	     struct ndrv_descr *nd)
{	struct dlil_demux_desc *mp, *mp1;
	int i, k, error = 0;

	/* Compute # structs to copy */
	i = k = min(np->nd_descrcnt,
		    (nd->nd_len / sizeof (struct dlil_demux_desc)));
	mp = (struct dlil_demux_desc *)nd->nd_buf;
	TAILQ_FOREACH(mp1, &np->nd_dlist, next)
	{	if (k-- == 0)
			break;
		error = copyout(mp1, mp++, sizeof (struct dlil_demux_desc));
		if (error)
			break;
	}
	if (error == 0)
	{	nd->nd_len = i * (sizeof (struct dlil_demux_desc));
		error = sooptcopyout(sopt, nd, sizeof (*nd));
	}
	return(error);
}

/* 
 * Install a protocol descriptor, making us a protocol handler.
 *  We expect the client to handle all output tasks (we get fully
 *  formed frames from the client and hand them to the driver
 *  directly).  The reason we register is to get those incoming
 *  frames.  We do it as a protocol handler because the network layer
 *  already knows how find the ones we want, so there's no need to
 *  duplicate effort.
 * Since this mechanism is mostly for user mode, most of the procedures
 *  to be registered will be null.
 * Note that we jam the pair (PF_XXX, native_type) into the native_type
 *  field of the demux descriptor.  Yeah, it's a hack.
 */
int
ndrv_setspec(struct ndrv_cb *np, struct ndrv_descr *nd)
{	struct dlil_demux_desc *mp, *mp1;
	int i = 0, error = 0, j;
	unsigned long value;
	int *native_values;
	struct dlil_proto_reg_str proto_spec;
	int ndrv_add_descr(struct ndrv_cb *, struct dlil_proto_reg_str *);

	bzero((caddr_t)&proto_spec, sizeof (proto_spec));
	i = nd->nd_len / (sizeof (struct dlil_demux_desc)); /* # elts */
	MALLOC(native_values,int *, i * sizeof (int), M_TEMP, M_WAITOK);
	if (native_values == NULL)
		return (ENOMEM);
	mp = (struct dlil_demux_desc *)nd->nd_buf;
	for (j = 0; j++ < i;)
	{	MALLOC(mp1, struct dlil_demux_desc *,
		       sizeof (struct dlil_demux_desc), M_PCB, M_WAITOK);
		if (mp1 == NULL)
		{	error = ENOBUFS;
			break;
		}
		error = copyin(mp++, mp1, sizeof (struct dlil_demux_desc));
		if (error)
			break;
		TAILQ_INSERT_TAIL(&np->nd_dlist, mp1, next);
		value = (unsigned long)mp1->native_type;
		native_values[j] = (unsigned short)value;
		mp1->native_type = (char *)&native_values[j];
		proto_spec.protocol_family  = (unsigned char)(value>>16); /* Oy! */
		proto_spec.interface_family = np->nd_if->if_family;
		proto_spec.unit_number      = np->nd_if->if_unit;
		/* Our input */
		proto_spec.input            = ndrv_input;
		proto_spec.pre_output       = NULL;
		/* No event/offer functionality needed */
		proto_spec.event            = NULL;
		proto_spec.offer            = NULL;
		proto_spec.ioctl            = ndrv_ioctl; /* ??? */
		/* What exactly does this do again? */
		proto_spec.default_proto    = 0;

		np->nd_descrcnt++;
	}
	if (error)
	{	struct dlil_demux_desc *mp2;

                while ((mp2 = TAILQ_FIRST(&np->nd_dlist))) {
                        TAILQ_REMOVE(&np->nd_dlist, mp2, next);
			FREE(mp2, M_PCB);
                }
	} else
		error = ndrv_add_descr(np, &proto_spec);
#ifdef NDRV_DEBUG
	log(LOG_WARNING, "NDRV ADDSPEC: got error %d\n", error);
#endif
	FREE(native_values, M_TEMP);
	return(error);
}

int
ndrv_delspec(struct ndrv_cb *np, struct ndrv_descr *nd)
{	struct dlil_demux_desc *mp;

	return(EINVAL);
}

struct ndrv_cb *
ndrv_find_tag(unsigned int tag)
{	struct ndrv_tag_map *tmp;
	int i;

	tmp = ndrv_tags;
	for (i=0; i++ < tag_map_count; tmp++)
		if (tmp->tm_tag == tag)
			return(tmp->tm_np);
	return(NULL);
}

int
ndrv_add_tag(struct ndrv_cb *np, unsigned int tag,
	     struct dlil_demux_desc *mp)
{	struct ndrv_tag_map *tmp;
	int i;

	tmp = ndrv_tags;
	for (i=0; i++ < tag_map_count; tmp++)
		if (tmp->tm_tag == 0)
		{	tmp->tm_tag = tag;
			tmp->tm_np = np;
#ifdef NDRV_DEBUG
			log(LOG_WARNING, "NDRV ADDING TAG %d\n", tag);
#endif
			return(0);
		}

	/* Oops - ran out of space.  Realloc */
	i = tag_map_count + TAG_MAP_COUNT;
	MALLOC(tmp, struct ndrv_tag_map *, i * sizeof (struct ndrv_tag_map),
	       M_PCB, M_WAITOK);
	if (tmp == NULL)
		return(ENOMEM);
	/* Clear tail of new table, except for the slot we are creating ... */
	bzero((caddr_t)&tmp[tag_map_count+1],
	      (TAG_MAP_COUNT-1) * sizeof (struct ndrv_tag_map));
	/* ...and then copy in the original piece */
	if (tag_map_count)
		bcopy(ndrv_tags, tmp,
		      tag_map_count * sizeof (struct ndrv_tag_map));
	/* ...and then install the new tag... */
	tmp[tag_map_count].tm_tag = tag;
	tmp[tag_map_count].tm_np = np;
	tag_map_count = i;
	if (tag_map_count)
		FREE(ndrv_tags, M_PCB);
	ndrv_tags = tmp;
#ifdef NDRV_DEBUG
	log(LOG_WARNING, "NDRV ADDING TAG %d (new chunk)\n", tag);
#endif
	return(0);
}

/*
 * Attach the proto spec list, and record the tags.
 */
int
ndrv_add_descr(struct ndrv_cb *np, struct dlil_proto_reg_str *proto_spec)
{	unsigned long dl_tag;
	int error;
	struct dlil_demux_desc *mp;

	/* Attach to our device to get requested packets */
	TAILQ_INIT(&proto_spec->demux_desc_head);
        error = dlil_attach_protocol(proto_spec, &dl_tag);

	if (error == 0)
		error = ndrv_add_tag(np, dl_tag, mp);

	return(error);
}

int
ndrv_dump_descr(struct ndrv_cb *np)
{	struct dlil_demux_desc *dm1, *dm2;
	struct ndrv_tag_map *tmp;
	int i, error = 0;

	if (dm1 = TAILQ_FIRST(&np->nd_dlist))
	{	for (i = 0, tmp = &ndrv_tags[0]; i++ < tag_map_count; tmp++)
			if (tmp->tm_np == np)
			{	error = dlil_detach_protocol(tmp->tm_tag);
				while (dm1)
				{	dm2 = TAILQ_NEXT(dm1, next);
					FREE(dm1, M_PCB);
					dm1 = dm2;
				}
				log(LOG_WARNING,
				    "Detached tag %d (error %d)\n",
				    tmp->tm_tag, error);
				tmp->tm_np = 0;
				tmp->tm_tag = 0;
			}
	}
	return(0);
}

void ndrv_dominit()
{
        static int ndrv_dominited = 0;

        if (ndrv_dominited == 0) {
                net_add_proto(&ndrvsw[0], &ndrvdomain);

                ndrv_dominited = 1;
        }
}

struct pr_usrreqs ndrv_usrreqs = {
	ndrv_abort, pru_accept_notsupp, ndrv_attach, ndrv_bind,
	ndrv_connect, pru_connect2_notsupp, ndrv_control, ndrv_detach,
	ndrv_disconnect, pru_listen_notsupp, ndrv_peeraddr, pru_rcvd_notsupp,
	pru_rcvoob_notsupp, ndrv_send, ndrv_sense, ndrv_shutdown,
	ndrv_sockaddr, sosend, soreceive, sopoll
};

struct protosw ndrvsw[] =
{	{	SOCK_RAW, &ndrvdomain, 0, PR_ATOMIC|PR_ADDR,
		0, ndrv_output, ndrv_ctlinput, ndrv_ctloutput,
		0, ndrv_init, 0, 0,
		ndrv_drain, ndrv_sysctl, &ndrv_usrreqs
	}
};

struct domain ndrvdomain =
{	AF_NDRV, "NetDriver", ndrv_dominit, NULL, NULL,
	NULL,
	NULL, NULL, 0, 0, 0, 0
};
