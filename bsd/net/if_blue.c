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
 *	@(#)if_blue.c	1.1 (MacOSX) 6/10/43
 * Justin Walker, 9970520
 *  First wave - splitter and notification support for the Blue Box
 * 980130 - Second wave -  Performance improvements, reorg and cleanup
 */

#include <sys/kdebug.h>
#if KDEBUG

#define DBG_SPLT_BFCHK	DRVDBG_CODE(DBG_DRVSPLT, 0)
#define DBG_SPLT_APPND	DRVDBG_CODE(DBG_DRVSPLT, 1)
#define DBG_SPLT_MBUF	DRVDBG_CODE(DBG_DRVSPLT, 2)
#define DBG_SPLT_DUP	DRVDBG_CODE(DBG_DRVSPLT, 3)
#define DBG_SPLT_PAD	DRVDBG_CODE(DBG_DRVSPLT, 4)

#endif


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/syslog.h>
#include <sys/proc.h>
#include <sys/vm.h>

#include <kern/cpu_number.h>

#include <net/if.h>
#include <net/netisr.h>
#include <net/route.h>
#include <net/if_llc.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include "if_blue.h"
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

#include <sys/systm.h>
#include <machine/spl.h>
#include <kern/thread.h>
#include <kern/queue.h>

/* Dummy IFs to differentiate source of looped packets */
struct ifnet rhap_if_s;
struct ifnet *rhap_if = &rhap_if_s;
struct ifnet_blue *blue_if;
struct sockaddr_dl ndrvsrc = {sizeof (struct sockaddr_dl), AF_NDRV};

struct ifqueue blueq;

extern int if_register(register struct BlueFilter *f
#ifdef BF_if
	    ,
	    register struct ifnet *ifp
#endif
	    );

/*
 * Blue Box support:
 * 1st cut: the Y splitter
 * A process turns on the splitter by opening the "raw" device
 *  (socket() for AF_NDRV) and issuing an SIOCSSPLITTER ioctl.
 * Incoming packets are routed into MacOSX as well as to the requesting
 *  interface.
 * Outbound packets are sent, and are examined to see if they should go
 *  back up (loopback, sort of).  Packets that are looped back include:
 *	broadcast
 *	multicast
 */
int
new_splitter(register struct socket *so)
{	register struct ifnet_blue *ifb;
	register struct ndrv_cb *np;
	register struct ifnet *ifp;
	struct BlueFilter filter;
	int retval;

	if ((ifb = _MALLOC(sizeof (struct ifnet_blue), M_PCB, M_WAITOK))
	    == NULL)
	{
#if BLUE_DEBUG
		kprintf("Can't create new splitter\n");
#endif
		return(ENOBUFS);
	}
	bzero(ifb, sizeof(struct ifnet_blue));
	np = (struct ndrv_cb *)so->so_pcb;
#if BLUE_DEBUG
	kprintf("NEW SPLT: %x, %x\n", so, np);
	if (np)
		printf("SIG: %x, ifp: %x\n", np->nd_signature, np->nd_if);
#endif
	if (np == NULL)
		return(EINVAL);	/* XXX */
	if (np->nd_signature != NDRV_SIGNATURE)
		return(EINVAL);	/* XXX */
	if ((ifp = np->nd_if) == NULL)
		return(EINVAL);	/* XXX */
	if (ifp->if_flags & IFF_SPLITTER)
		return(EBUSY);
	if ((ifp->if_flags&IFF_UP) == 0)
		return(ENXIO);
	/*
	 * Bump the receive sockbuf size - need a big buffer
	 *  to offset the scheduling latencies of the system
	 * Try to get something if our grandiose design fails.
	 */
	if (sbreserve(&so->so_rcv, 131072) == 0)
	{	if (sbreserve(&so->so_rcv, 65536) == 0 &&
		    sbreserve(&so->so_rcv, 32768) == 0 &&
		    sbreserve(&so->so_rcv, 16384) == 0)
			return(ENOBUFS);
	}
	ifp->if_flags |= IFF_SPLITTER;
	/*
	 * Register each IP address associated with this ifnet
	 * This takes care of addresses registered prior to startup
	 *  of the BlueBox.
	 * TODO: Appletalk sockaddrs
	 */
#define IFA2IN(ifa) \
	((struct in_addr) \
	   ((struct sockaddr_in *)(ifa->ifa_addr))->sin_addr).s_addr
		{	struct ifaddr *ifa;

	TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link)
		{	if (ifa->ifa_addr->sa_family == AF_INET)
			{	filter.BF_flags = (BF_ALLOC|BF_IP);
				filter.BF_address = IFA2IN(ifa);
#if BLUE_DEBUG
				kprintf("[1] IP registering [%x] %x\n",
					filter.BF_flags,
					(unsigned int)filter.BF_address);
#endif
				retval = if_register(&filter);
#if BLUE_DEBUG
				if (retval)
					kprintf("if_register(IP) returns %d\n",
						retval);
#endif
			}
		}
	}

	blue_if = (struct ifnet_blue *)ifb;
	ifb->blue_pid = ((struct proc *)current_proc())->p_pid;
	ifb->ifb_so = so;
	ifp->if_Y = (void *)ifb;
	return(0);
}

/*
 * Determine if destined for BlueBox or not.  Called from ether_output()
 *  and ether_input().
 * Returns NULL if we ate the packet, otherwise, the mbuf to continue with.
 */
struct mbuf *
splitter_input(register struct mbuf *m, register struct ifnet *ifp)
{	register struct ifnet_blue *ifb;
#if 0
	register int s, flags;
#else
	register int flags;
#endif
	int rv;
	register struct mbuf *m0 = NULL;
	struct mbuf *m1;
	extern struct mbuf *m_dup(struct mbuf *, int);
	extern int BlueFilter_check(struct mbuf **, struct ifnet_blue *);
	extern void blue_notify(struct mbuf *);
	extern int blue_notify1(struct mbuf *);

	if ((ifb = (struct ifnet_blue *)ifp->if_Y) == NULL)
	{	ifp->if_flags &= ~IFF_SPLITTER;
		return(m);
	}
	flags = m->m_flags;
	m1 = m;
	/* Check filters */
	if ((rv = BlueFilter_check(&m1, ifb)) == -1)
		return(m1);	/* Not for BB, MacOSX will want to see it. */
	m = m1;
	if (rv == 0)		/* It's for both - dup the packet */
	{	m0 = m_dup(m, M_DONTWAIT);
		if (m0 == NULL)
		{	blue_if->no_bufs1++;
			return(m); /* Give it to MacOSX */
		}
	} else
	{	/* Oy, veh!  The depths to which we stoop! */
		/* We'll just assume M_PKTHDR is set */
		if (m->m_next == 0 && (m->m_flags & M_EXT)
		    && m->m_pkthdr.len <= MHLEN)
		{	m0 = m_dup(m, M_DONTWAIT);
			if (m0)
			{	m_freem(m);
				m = NULL;
			} else
				m0 = m;
		} else
			m0 = m;
	}
	if (flags & 0x10)
		blue_if->pkts_looped_r2b++;

#if 0
	schednetisr(NETISR_BLUE);
	s = splimp();
	if (IF_QFULL(&blueq)) {
		IF_DROP(&blueq);
		m_freem(m0);
	} else
		IF_ENQUEUE(&blueq, m0);
	splx(s);
#else
	blue_notify1(m0);
	sorwakeup(blue_if->ifb_so);
	blue_if->sig_sent++;
#endif
	/* If we eat the packet (rv==1) return NULL */
	return(rv == 0 ? m : NULL);
}

void
blue_notify()
{	register int do_notify = 0;
	register int s;
	register struct mbuf *m;
	extern int blue_notify1(struct mbuf *);

	/*
	 * Move the packets from the blue queue to the indicated socket
	 * If we haven't told anyone yet, send a signal.
	 */
	for (;;)
	{	s = splimp();
		IF_DEQUEUE(&blueq, m);
		splx(s);
		if (m == 0)
			break;

		do_notify = blue_notify1(m);
	}
	if (do_notify)
		sorwakeup(blue_if->ifb_so);	/* Start by using SIGIO */
}

int
blue_notify1(register struct mbuf *m)
{	register int rv;

	/* move packet from if queue to socket */
	/* !!!Fix this to work generically!!! */
	ndrvsrc.sdl_type = IFT_ETHER;
	ndrvsrc.sdl_nlen = 0;
	ndrvsrc.sdl_alen = 6;
	ndrvsrc.sdl_slen = 0;
	bcopy(m->m_data+6, &ndrvsrc.sdl_data, 6);

	if (sbappendaddr(&(blue_if->ifb_so->so_rcv),
			 (struct sockaddr *)&ndrvsrc, m,
			 (struct mbuf *)0) == 0)
	{	register struct mbuf *n;
	
		KERNEL_DEBUG(DBG_SPLT_APPND | DBG_FUNC_NONE,
			     blue_if->ifb_so->so_rcv.sb_cc,
			     blue_if->ifb_so->so_rcv.sb_hiwat,
			     blue_if->ifb_so->so_rcv.sb_mbcnt,
			     blue_if->ifb_so->so_rcv.sb_mbmax,
			     blue_if->ifb_so->so_rcv.sb_lowat );
		if (m->m_flags & M_PKTHDR)
			KERNEL_DEBUG(DBG_SPLT_MBUF, 0, m->m_pkthdr.len,
				     m->m_flags, 0, 0);
		for (n = m; n; n = n->m_next)
			KERNEL_DEBUG(DBG_SPLT_MBUF, 1,
				     (int)n, (int)n->m_next, n->m_len,
				     n->m_flags);
		m_freem(m);
		blue_if->full_sockbuf++;
		rv = 1;
	} else
	{	register struct mbuf *n;
	
		KERNEL_DEBUG(DBG_SPLT_APPND | DBG_FUNC_NONE,
			     blue_if->ifb_so->so_rcv.sb_cc,
			     blue_if->ifb_so->so_rcv.sb_hiwat,
			     blue_if->ifb_so->so_rcv.sb_mbcnt,
			     blue_if->ifb_so->so_rcv.sb_mbmax,
			     blue_if->ifb_so->so_rcv.sb_lowat );
		if (m->m_flags & M_PKTHDR)
			KERNEL_DEBUG(DBG_SPLT_MBUF, 2, m->m_pkthdr.len,
				     m->m_flags, 0, 0);
		for (n = m; n; n = n->m_next)
			KERNEL_DEBUG(DBG_SPLT_MBUF, 3,
				     (int)n, (int)n->m_next, n->m_len,
				     n->m_flags);
		blue_if->pkts_up++;
		rv = 0;
	}
	return(rv);
}

/*
 * Check the incoming packet against the registered filters
 * Rules (the rules are subtly different for input to the
 *  y-adapter customer and the "real" stacks):
 *  For BB: return 1
 *  For Both: return 0
 *  Not For BB: return -1
 *  Multicast/Broadcast => For Both
 *  Hack:
 *   if no registered filters, For Both
 *  Atalk filter registered
 *   filter matches => For BB else Not For BB
 *  IP filter registered
 *   filter matches => For BB else Not For BB
 *  Not For BB
 * WARNING: this is a big-endian routine.
 * WARNING 2: m_pullup can give you a new mbuf!
 */
int
BlueFilter_check(struct mbuf **m0, register struct ifnet_blue *ifb)
{	register struct BlueFilter *bf;
	register unsigned char *p;
	register unsigned short *s;
	register unsigned long *l;
	int total, flags;
	register struct mbuf *m;
	extern struct mbuf *m_pullup(struct mbuf *, int);
#define FILTER_LEN 32

	KERNEL_DEBUG(DBG_SPLT_BFCHK | DBG_FUNC_START, 0, 0, 0, 0, 0 );

	m = *m0;
	if (FILTER_LEN > m->m_pkthdr.len)
	{	KERNEL_DEBUG(DBG_SPLT_BFCHK | DBG_FUNC_END, 0, 0, 0, 0, 0 );
		return(-1);
	}
	flags = m->m_flags;
	while ((FILTER_LEN > m->m_len) && m->m_next) {
		total = m->m_len + (m->m_next)->m_len;
		if ((m = m_pullup(m, min(FILTER_LEN, total))) == 0)
		{	KERNEL_DEBUG(DBG_SPLT_BFCHK | DBG_FUNC_END, 1, flags, total, 0, 0);
			return(-1);
		}
	}
	*m0 = m;	/* Update, just in case */

	p = mtod(m, unsigned char *);	/* Point to destination media addr */
	if (p[0] & 0x01)	/* Multicast/broadcast */
	{	KERNEL_DEBUG(DBG_SPLT_BFCHK | DBG_FUNC_END, 2, 0, 0, 0, 0 );
		return(0);
	}
	s = (unsigned short *)p;
	bf = &ifb->filter[BFS_ATALK];
	if (!bf->BF_flags && !bf[1].BF_flags) /* Hack for Developer Release Blue Box */
	{	KERNEL_DEBUG(DBG_SPLT_BFCHK | DBG_FUNC_END, 3, 0, 0, 0, 0 );
		return(0);
	}
#if BLUE_DEBUG
	kprintf("PKT: %x, %x, %x\n", s[6], s[7], s[8]);
#endif
	if (bf->BF_flags)	/* Filtering Appletalk */
	{	l = (unsigned long *)&s[8];
#if BLUE_DEBUG
		kprintf("AT: %x, %x, %x, %x, %x, %x\n", s[6], s[7],
			*l, s[10], s[13], p[30]);
#endif
		if (s[6] <= ETHERMTU)
		{	if (s[7] == 0xaaaa) /* Could be Atalk */
			{	/* Verify SNAP header */
				if (*l == 0x03080007 && s[10] == 0x809b)
				{	if ((bf->BF_flags&BF_VALID) == 0 ||
					    (s[13] == bf->BF_address &&
					     p[30] == bf->BF_node))
					{	KERNEL_DEBUG(DBG_SPLT_BFCHK | DBG_FUNC_END, 4,
							     s[13], p[30], 0, 0 );
						return(1);
					}
				} else if (*l == 0x03000000 && s[10] == 0x80f3)
					/* AARP pkts aren't net-addressed */
				{	KERNEL_DEBUG(DBG_SPLT_BFCHK | DBG_FUNC_END, 5, 0, 0, 0, 0 );
					return(0);
				}
				/* Not for us */
				KERNEL_DEBUG(DBG_SPLT_BFCHK | DBG_FUNC_END, 6, s[13], p[30], 0, 0 );
				return(-1);
			} else /* Not for us? */
			{	KERNEL_DEBUG(DBG_SPLT_BFCHK | DBG_FUNC_END, 7, s[7], 0, 0, 0 );
				return(-1);
			}
		} /* Fall through */
	} /* Fall through */
	bf++;			/* Look for IP next */
	if (bf->BF_flags)	/* Filtering IP */
	{
		l = (unsigned long *)&s[15];
#if BLUE_DEBUG
		kprintf("IP: %x, %x\n", s[6], *l);
#endif
		if (s[6] > ETHERMTU)
		{	if (s[6] == 0x800)	/* Is IP */
			{	/* Verify IP address */
				if ((bf->BF_flags&BF_VALID) == 0 ||
				    *l == bf->BF_address)
				{	KERNEL_DEBUG(DBG_SPLT_BFCHK | DBG_FUNC_END, 8, *l, 0, 0, 0 );
					return(1);
				} else	/* Not for us */
				{	KERNEL_DEBUG(DBG_SPLT_BFCHK | DBG_FUNC_END, 9, *l, 0, 0, 0 );
					return(-1);
				}
			} else if (s[6] == 0x806)
			{	/* ARP pkts aren't net-addressed */
				KERNEL_DEBUG(DBG_SPLT_BFCHK | DBG_FUNC_END, 10, 0, 0, 0, 0 );
				return(0);
			}
		}
	}
	KERNEL_DEBUG(DBG_SPLT_BFCHK | DBG_FUNC_END, 11, s[6], 0, 0, 0 );
	return(-1);
}

int
splitter_ctl(register struct socket *so, register int cmd,
	     register caddr_t data, register struct ifnet *ifp)
{	register struct ndrv_cb *np = sotondrvcb(so);
	register struct ifnet_blue *ifb;
	register struct BlueFilter *bf = (struct BlueFilter *)data, *bf1;
	u_long at_dl_tag;


	if ((ifb = np->nd_if->if_Y) == NULL)
		return(ENXIO);

	if (cmd == SIOCSSPLTFILT)
	{
#if BLUE_DEBUG
kprintf("Filter: %s, %x, %x, %x\n", bf->ifr_name, bf->BF_flags, bf->BF_address,
       bf->BF_node);
#endif
		if (bf->BF_flags & BF_ATALK)
			bf1 = &ifb->filter[BFS_ATALK];
		else if (bf->BF_flags & BF_IP)
			bf1 = &ifb->filter[BFS_IP];
		else
			return(EINVAL);
		if (bf->BF_flags&BF_ALLOC)
		{	if ((bf1->BF_flags&(BF_ALLOC|BF_VALID)) ==
			    (BF_ALLOC|BF_VALID))
				return(EBUSY);
			*bf1 = *bf;
			bf1->BF_flags |= BF_VALID;
		} else if (bf->BF_flags&BF_DEALLOC)
		{	if (bf1->BF_flags&BF_ALLOC)
				bf1->BF_flags = 0;
			else
				return(EINVAL);
		}
                /* Register AppleTalk Tags if not registered */

		ether_attach_at(ifp, &at_dl_tag,
				&at_dl_tag);


	} else if (cmd == SIOCZSPLTSTAT)
	{	ifb->pkts_up = 0;
		ifb->pkts_out = 0;
		ifb->pkts_looped_r2b = 0;
		ifb->pkts_looped_b2r = 0;
		ifb->no_bufs1 = 0;
		ifb->no_bufs2 = 0;
		ifb->full_sockbuf = 0;
	} else if (cmd == SIOCGSPLTSTAT)
	{	register struct Ystats *ys = (struct Ystats *)data;
		ys->YS_blue_pid = ifb->blue_pid;
		ys->YS_filter[BFS_ATALK] = ifb->filter[BFS_ATALK];
		ys->YS_filter[BFS_IP] = ifb->filter[BFS_IP];
		ys->YS_pkts_up = ifb->pkts_up;
		ys->YS_pkts_out = ifb->pkts_out;
		ys->YS_pkts_looped_b2r = ifb->pkts_looped_b2r;
		ys->YS_pkts_looped_r2b = ifb->pkts_looped_r2b;
		ys->YS_no_bufs1 = ifb->no_bufs1;
		ys->YS_no_bufs2 = ifb->no_bufs2;
		ys->YS_full_sockbuf = ifb->full_sockbuf;
	} else
		return(EINVAL);
	return(0);
}

void
splitter_close(register struct ndrv_cb *np)
{	extern struct ifnet_blue *blue_if;
	extern void ndrv_flushq(struct ifqueue *);

	if (blue_if)
	{	/* If we're the guy holding the Y-adapter, clean it up */
		if (blue_if->blue_pid == 
			((struct proc *)current_proc())->p_pid)
		{	if (np->nd_if)
			{	np->nd_if->if_flags &= ~IFF_SPLITTER;
				np->nd_if->if_Y = 0;
			}

			BFIx = 0;
			/* Clean out the filter supply */
			bzero(RhapFilter,
			      sizeof(struct BlueFilter) * BFCount);
			blue_if->ifb_so = 0;
			blue_if->filter[0].BF_flags = 0;
			blue_if->filter[1].BF_flags = 0;
			ndrv_flushq(&blueq);
			if (np->nd_laddr)
			{	FREE((caddr_t) np->nd_laddr, M_IFADDR);
				np->nd_laddr = 0;
			}
		}
	}
	remque((queue_t)np);
	FREE((caddr_t)np, M_PCB);
}

/*
 * Dup the mbuf chain passed in.  The whole thing.  No cute additional cruft.
 * And really copy the thing.  That way, we don't "precompute" checksums
 *  for unsuspecting consumers.
 * Assumption: m->m_nextpkt == 0.
 * Trick: for small packets, don't dup into a cluster.  That way received
 *  packets don't take up too much room in the sockbuf (cf. sbspace()).
 */
int MDFail;

struct mbuf *
m_dup(register struct mbuf *m, int how)
{	register struct mbuf *n, **np;
	struct mbuf *top;
	int copyhdr = 0;

	KERNEL_DEBUG(DBG_SPLT_DUP | DBG_FUNC_START, m->m_flags, m->m_len,
		     m->m_pkthdr.len, 0, 0 );
	np = &top;
	top = 0;
	if (m->m_flags & M_PKTHDR)
		copyhdr = 1;

	/*
	 * Quick check: if we have one mbuf and its data fits in an
	 *  mbuf with packet header, just copy and go.
	 */
	if (m->m_next == NULL)
	{	/* Then just move the data into an mbuf and be done... */
		if (copyhdr)
		{	if (m->m_pkthdr.len <= MHLEN)
			{	if ((n = m_gethdr(how, m->m_type)) == NULL)
					return(NULL);
				bcopy(m->m_data, n->m_data, m->m_pkthdr.len);
				n->m_pkthdr.len = m->m_pkthdr.len;
				n->m_len = m->m_len;
				KERNEL_DEBUG(DBG_SPLT_DUP | DBG_FUNC_END, 2,
					     m->m_pkthdr.len, m->m_flags,
					     n->m_flags, 0 );
				return(n);
			}
		} else if (m->m_len <= MLEN)
		{	if ((n = m_get(how, m->m_type)) == NULL)
				return(NULL);
			bcopy(m->m_data, n->m_data, m->m_len);
			n->m_len = m->m_len;
			KERNEL_DEBUG(DBG_SPLT_DUP | DBG_FUNC_END, 3, m->m_len,
				     m->m_flags, n->m_flags, 0 );
			return(n);
		}
	}
	while (m)
	{
#if BLUE_DEBUG
		kprintf("<%x: %x, %x, %x\n", m, m->m_flags, m->m_len,
			m->m_data);
#endif
		if (copyhdr)
			n = m_gethdr(how, m->m_type);
		else
			n = m_get(how, m->m_type);
		if (n == 0)
			goto nospace;
		if (m->m_flags & M_EXT)
		{	MCLGET(n, how);
			if ((n->m_flags & M_EXT) == 0)
				goto nospace;
		}
		*np = n;
		if (copyhdr)
		{	/* Don't use M_COPY_PKTHDR: preserve m_data */
			n->m_pkthdr = m->m_pkthdr;
                	n->m_pkthdr.aux = (struct mbuf *)NULL; /*###LD080800 Avoid problems with IPsec */

			n->m_flags |= (m->m_flags & M_COPYFLAGS);
			copyhdr = 0;
			if ((n->m_flags & M_EXT) == 0)
				n->m_data = n->m_pktdat;
		}
		n->m_len = m->m_len;
		/*
		 * Get the dup on the same bdry as the original
		 * Assume that the two mbufs have the same offset to data area
		 *  (up to word bdries)
		 */
		bcopy(mtod(m, caddr_t), mtod(n, caddr_t), (unsigned)n->m_len);
		m = m->m_next;
		np = &n->m_next;
#if BLUE_DEBUG
		kprintf(">%x: %x, %x, %x\n", n, n->m_flags, n->m_len,
			n->m_data);
#endif
	}

	if (top == 0)
		MDFail++;
	KERNEL_DEBUG(DBG_SPLT_DUP | DBG_FUNC_END, 0, (int)top, 0, 0, 0 );
	return (top);
 nospace:
	m_freem(top);
	MDFail++;
	KERNEL_DEBUG(DBG_SPLT_DUP | DBG_FUNC_END, 1, 0, 0, 0, 0 );
	return (0);
}
