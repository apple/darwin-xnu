/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * Copyright 1998 Massachusetts Institute of Technology
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that both the above copyright notice and this
 * permission notice appear in all copies, that both the above
 * copyright notice and this permission notice appear in all
 * supporting documentation, and that the name of M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  M.I.T. makes
 * no representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 * 
 * THIS SOFTWARE IS PROVIDED BY M.I.T. ``AS IS''.  M.I.T. DISCLAIMS
 * ALL EXPRESS OR IMPLIED WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT
 * SHALL M.I.T. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/*
 * if_vlan.c - pseudo-device driver for IEEE 802.1Q virtual LANs.
 * Might be extended some day to also handle IEEE 802.1p priority
 * tagging.  This is sort of sneaky in the implementation, since
 * we need to pretend to be enough of an Ethernet implementation
 * to make arp work.  The way we do this is by telling everyone
 * that we are an Ethernet, and then catch the packets that
 * ether_output() left on our output queue queue when it calls
 * if_start(), rewrite them for use by the real outgoing interface,
 * and ask it to send them.
 *
 *
 * XXX It's incorrect to assume that we must always kludge up
 * headers on the physical device's behalf: some devices support
 * VLAN tag insersion and extraction in firmware. For these cases,
 * one can change the behavior of the vlan interface by setting
 * the LINK0 flag on it (that is setting the vlan interface's LINK0
 * flag, _not_ the parent's LINK0 flag; we try to leave the parent
 * alone). If the interface as the LINK0 flag set, then it will
 * not modify the ethernet header on output because the parent
 * can do that for itself. On input, the parent can call vlan_input_tag()
 * directly in order to supply us with an incoming mbuf and the vlan
 * tag value that goes with it.
 */

#include "vlan.h"
#if NVLAN > 0
#include "opt_inet.h"
#include "bpfilter.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#if NBPFILTER > 0
#include <net/bpf.h>
#endif
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_vlan_var.h>

#if INET
#include <netinet/in.h>
#include <netinet/if_ether.h>
#endif

SYSCTL_DECL(_net_link);
SYSCTL_NODE(_net_link, IFT_8021_VLAN, vlan, CTLFLAG_RW, 0, "IEEE 802.1Q VLAN");
SYSCTL_NODE(_net_link_vlan, PF_LINK, link, CTLFLAG_RW, 0, "for consistency");

u_int	vlan_proto = ETHERTYPE_VLAN;
SYSCTL_INT(_net_link_vlan_link, VLANCTL_PROTO, proto, CTLFLAG_RW, &vlan_proto,
	   0, "Ethernet protocol used for VLAN encapsulation");

static	struct ifvlan ifv_softc[NVLAN];

static	void vlan_start(struct ifnet *ifp);
static	void vlan_ifinit(void *foo);
static	int vlan_ioctl(struct ifnet *ifp, u_long cmd, caddr_t addr);
static	int vlan_setmulti(struct ifnet *ifp);
static	int vlan_unconfig(struct ifnet *ifp);
static	int vlan_config(struct ifvlan *ifv, struct ifnet *p);

/*
 * Program our multicast filter. What we're actually doing is
 * programming the multicast filter of the parent. This has the
 * side effect of causing the parent interface to receive multicast
 * traffic that it doesn't really want, which ends up being discarded
 * later by the upper protocol layers. Unfortunately, there's no way
 * to avoid this: there really is only one physical interface.
 */
static int vlan_setmulti(struct ifnet *ifp)
{
	struct ifnet		*ifp_p;
	struct ifmultiaddr	*ifma, *rifma = NULL;
	struct ifvlan		*sc;
	struct vlan_mc_entry	*mc = NULL;
	struct sockaddr_dl	sdl;
	int			error;

	/* Find the parent. */
	sc = ifp->if_softc;
	ifp_p = sc->ifv_p;

	sdl.sdl_len = ETHER_ADDR_LEN;
	sdl.sdl_family = AF_LINK;

	/* First, remove any existing filter entries. */
	while(sc->vlan_mc_listhead.slh_first != NULL) {
		mc = sc->vlan_mc_listhead.slh_first;
		bcopy((char *)&mc->mc_addr, LLADDR(&sdl), ETHER_ADDR_LEN);
		error = if_delmulti(ifp_p, (struct sockaddr *)&sdl);
		if (error)
			return(error);
		SLIST_REMOVE_HEAD(&sc->vlan_mc_listhead, mc_entries);
		FREE(mc, M_DEVBUF);
	}

	/* Now program new ones. */
	for (ifma = ifp->if_multiaddrs.lh_first;
	    ifma != NULL;ifma = ifma->ifma_link.le_next) {
		if (ifma->ifma_addr->sa_family != AF_LINK)
			continue;
		mc = _MALLOC(sizeof(struct vlan_mc_entry), M_DEVBUF, M_WAITOK);
		if (mc == NULL)
			return (ENOMEM);
		bcopy(LLADDR((struct sockaddr_dl *)ifma->ifma_addr),
		    (char *)&mc->mc_addr, ETHER_ADDR_LEN);
		SLIST_INSERT_HEAD(&sc->vlan_mc_listhead, mc, mc_entries);
		error = if_addmulti(ifp_p, (struct sockaddr *)&sdl, &rifma);
		if (error)
			return(error);
	}

	return(0);
}

static void
vlaninit(void *dummy)
{
	int i;

	for (i = 0; i < NVLAN; i++) {
		struct ifnet *ifp = &ifv_softc[i].ifv_if;

		ifp->if_softc = &ifv_softc[i];
		ifp->if_name = "vlan";
		ifp->if_family = APPLE_IF_FAM_VLAN;
		ifp->if_unit = i;
		/* NB: flags are not set here */
		ifp->if_linkmib = &ifv_softc[i].ifv_mib;
		ifp->if_linkmiblen = sizeof ifv_softc[i].ifv_mib;
		/* NB: mtu is not set here */

		ifp->if_init = vlan_ifinit;
		ifp->if_start = vlan_start;
		ifp->if_ioctl = vlan_ioctl;
		ifp->if_output = ether_output;
		ifp->if_snd.ifq_maxlen = ifqmaxlen;
		if_attach(ifp);
		ether_ifattach(ifp);
#if NBPFILTER > 0
		bpfattach(ifp, DLT_EN10MB, sizeof(struct ether_header));
#endif
		/* Now undo some of the damage... */
		ifp->if_data.ifi_type = IFT_8021_VLAN;
		ifp->if_data.ifi_hdrlen = EVL_ENCAPLEN;
		ifp->if_resolvemulti = 0;
	}
}
PSEUDO_SET(vlaninit, if_vlan);

static void
vlan_ifinit(void *foo)
{
	return;
}

static void
vlan_start(struct ifnet *ifp)
{
	struct ifvlan *ifv;
	struct ifnet *p;
	struct ether_vlan_header *evl;
	struct mbuf *m;

	ifv = ifp->if_softc;
	p = ifv->ifv_p;

	ifp->if_flags |= IFF_OACTIVE;
	for (;;) {
		IF_DEQUEUE(&ifp->if_snd, m);
		if (m == 0)
			break;
#if NBPFILTER > 0
		if (ifp->if_bpf)
			bpf_mtap(ifp, m);
#endif /* NBPFILTER > 0 */

		/*
		 * If the LINK0 flag is set, it means the underlying interface
		 * can do VLAN tag insertion itself and doesn't require us to
	 	 * create a special header for it. In this case, we just pass
		 * the packet along. However, we need some way to tell the
		 * interface where the packet came from so that it knows how
		 * to find the VLAN tag to use, so we set the rcvif in the
		 * mbuf header to our ifnet.
		 *
		 * Note: we also set the M_PROTO1 flag in the mbuf to let
		 * the parent driver know that the rcvif pointer is really
		 * valid. We need to do this because sometimes mbufs will
		 * be allocated by other parts of the system that contain
		 * garbage in the rcvif pointer. Using the M_PROTO1 flag
		 * lets the driver perform a proper sanity check and avoid
		 * following potentially bogus rcvif pointers off into
		 * never-never land.
		 */
		if (ifp->if_flags & IFF_LINK0) {
			m->m_pkthdr.rcvif = ifp;
			m->m_flags |= M_PROTO1;
		} else {
			M_PREPEND(m, EVL_ENCAPLEN, M_DONTWAIT);
			if (m == 0)
				continue;
			/* M_PREPEND takes care of m_len, m_pkthdr.len for us */

			/*
			 * Transform the Ethernet header into an Ethernet header
			 * with 802.1Q encapsulation.
			 */
			bcopy(mtod(m, char *) + EVL_ENCAPLEN, mtod(m, char *),
			      sizeof(struct ether_header));
			evl = mtod(m, struct ether_vlan_header *);
			evl->evl_proto = evl->evl_encap_proto;
			evl->evl_encap_proto = htons(vlan_proto);
			evl->evl_tag = htons(ifv->ifv_tag);
#ifdef DEBUG
			printf("vlan_start: %*D\n", sizeof *evl,
			    (char *)evl, ":");
#endif
		}

		/*
		 * Send it, precisely as ether_output() would have.
		 * We are already running at splimp.
		 */
		if (IF_QFULL(&p->if_snd)) {
			IF_DROP(&p->if_snd);
				/* XXX stats */
			ifp->if_oerrors++;
			m_freem(m);
			continue;
		}
		IF_ENQUEUE(&p->if_snd, m);
		if ((p->if_flags & IFF_OACTIVE) == 0) {
			p->if_start(p);
			ifp->if_opackets++;
		}
	}
	ifp->if_flags &= ~IFF_OACTIVE;

	return;
}

void
vlan_input_tag(struct ether_header *eh, struct mbuf *m, u_int16_t t)
{
	int i;
	struct ifvlan *ifv;

	for (i = 0; i < NVLAN; i++) {
		ifv = &ifv_softc[i];
		if (ifv->ifv_tag == t)
			break;
	}

	if (i >= NVLAN || (ifv->ifv_if.if_flags & IFF_UP) == 0) {
		m_freem(m);
		ifv->ifv_p->if_data.ifi_noproto++;
		return;
	}

	/*
	 * Having found a valid vlan interface corresponding to
	 * the given source interface and vlan tag, run the
	 * the real packet through ethert_input().
	 */
	m->m_pkthdr.rcvif = &ifv->ifv_if;

#if NBPFILTER > 0
	if (ifv->ifv_if.if_bpf) {
		/*
		 * Do the usual BPF fakery.  Note that we don't support
		 * promiscuous mode here, since it would require the
		 * drivers to know about VLANs and we're not ready for
		 * that yet.
		 */
		struct mbuf m0;
		m0.m_next = m;
		m0.m_len = sizeof(struct ether_header);
		m0.m_data = (char *)eh;
		bpf_mtap(&ifv->ifv_if, &m0);
	}
#endif
	ifv->ifv_if.if_ipackets++;
	ether_input(&ifv->ifv_if, eh, m);
	return;
}

int
vlan_input(struct ether_header *eh, struct mbuf *m)
{
	int i;
	struct ifvlan *ifv;

	for (i = 0; i < NVLAN; i++) {
		ifv = &ifv_softc[i];
		if (m->m_pkthdr.rcvif == ifv->ifv_p
		    && (EVL_VLANOFTAG(ntohs(*mtod(m, u_int16_t *)))
			== ifv->ifv_tag))
			break;
	}

	if (i >= NVLAN || (ifv->ifv_if.if_flags & IFF_UP) == 0) {
		m_freem(m);
		return -1;	/* so ether_input can take note */
	}

	/*
	 * Having found a valid vlan interface corresponding to
	 * the given source interface and vlan tag, remove the
	 * encapsulation, and run the real packet through
	 * ether_input() a second time (it had better be
	 * reentrant!).
	 */
	m->m_pkthdr.rcvif = &ifv->ifv_if;
	eh->ether_type = mtod(m, u_int16_t *)[1];
	m->m_data += EVL_ENCAPLEN;
	m->m_len -= EVL_ENCAPLEN;
	m->m_pkthdr.len -= EVL_ENCAPLEN;

#if NBPFILTER > 0
	if (ifv->ifv_if.if_bpf) {
		/*
		 * Do the usual BPF fakery.  Note that we don't support
		 * promiscuous mode here, since it would require the
		 * drivers to know about VLANs and we're not ready for
		 * that yet.
		 */
		struct mbuf m0;
		m0.m_next = m;
		m0.m_len = sizeof(struct ether_header);
		m0.m_data = (char *)eh;
		bpf_mtap(&ifv->ifv_if, &m0);
	}
#endif
	ifv->ifv_if.if_ipackets++;
	ether_input(&ifv->ifv_if, eh, m);
	return 0;
}

static int
vlan_config(struct ifvlan *ifv, struct ifnet *p)
{
	struct ifaddr *ifa1, *ifa2;
	struct sockaddr_dl *sdl1, *sdl2;

	if (p->if_data.ifi_type != IFT_ETHER)
		return EPROTONOSUPPORT;
	if (ifv->ifv_p)
		return EBUSY;
	ifv->ifv_p = p;
	if (p->if_data.ifi_hdrlen == sizeof(struct ether_vlan_header))
		ifv->ifv_if.if_mtu = p->if_mtu;
	else
		ifv->ifv_if.if_mtu = p->if_data.ifi_mtu - EVL_ENCAPLEN;

	/*
	 * Preserve the state of the LINK0 flag for ourselves.
	 */
	ifv->ifv_if.if_flags = (p->if_flags & ~(IFF_LINK0));

	/*
	 * Set up our ``Ethernet address'' to reflect the underlying
	 * physical interface's.
	 */
	ifa1 = ifnet_addrs[ifv->ifv_if.if_index - 1];
	ifa2 = ifnet_addrs[p->if_index - 1];
	sdl1 = (struct sockaddr_dl *)ifa1->ifa_addr;
	sdl2 = (struct sockaddr_dl *)ifa2->ifa_addr;
	sdl1->sdl_type = IFT_ETHER;
	sdl1->sdl_alen = ETHER_ADDR_LEN;
	bcopy(LLADDR(sdl2), LLADDR(sdl1), ETHER_ADDR_LEN);
	bcopy(LLADDR(sdl2), ifv->ifv_ac.ac_enaddr, ETHER_ADDR_LEN);
	return 0;
}

static int
vlan_unconfig(struct ifnet *ifp)
{
	struct ifaddr *ifa;
	struct sockaddr_dl *sdl;
	struct vlan_mc_entry *mc;
	struct ifvlan *ifv;
	struct ifnet *p;
	int error;

	ifv = ifp->if_softc;
	p = ifv->ifv_p;

	/*
 	 * Since the interface is being unconfigured, we need to
	 * empty the list of multicast groups that we may have joined
	 * while we were alive and remove them from the parent's list
	 * as well.
	 */
	while(ifv->vlan_mc_listhead.slh_first != NULL) {
		struct sockaddr_dl	sdl;

		sdl.sdl_len = ETHER_ADDR_LEN;
		sdl.sdl_family = AF_LINK;
		mc = ifv->vlan_mc_listhead.slh_first;
		bcopy((char *)&mc->mc_addr, LLADDR(&sdl), ETHER_ADDR_LEN);
		error = if_delmulti(p, (struct sockaddr *)&sdl);
		error = if_delmulti(ifp, (struct sockaddr *)&sdl);
		if (error)
			return(error);
		SLIST_REMOVE_HEAD(&ifv->vlan_mc_listhead, mc_entries);
		FREE(mc, M_DEVBUF);
	}

	/* Disconnect from parent. */
	ifv->ifv_p = NULL;
	ifv->ifv_if.if_mtu = ETHERMTU;

	/* Clear our MAC address. */
	ifa = ifnet_addrs[ifv->ifv_if.if_index - 1];
	sdl = (struct sockaddr_dl *)ifa->ifa_addr;
	sdl->sdl_type = IFT_ETHER;
	sdl->sdl_alen = ETHER_ADDR_LEN;
	bzero(LLADDR(sdl), ETHER_ADDR_LEN);
	bzero(ifv->ifv_ac.ac_enaddr, ETHER_ADDR_LEN);

	return 0;
}

static int
vlan_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct ifaddr *ifa;
	struct ifnet *p;
	struct ifreq *ifr;
	struct ifvlan *ifv;
	struct vlanreq vlr;
	int error = 0;

	ifr = (struct ifreq *)data;
	ifa = (struct ifaddr *)data;
	ifv = ifp->if_softc;

	switch (cmd) {
	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP;

		switch (ifa->ifa_addr->sa_family) {
#if INET
		case AF_INET:
			arp_ifinit(&ifv->ifv_ac, ifa);
			break;
#endif
		default:
			break;
		}
		break;

	case SIOCGIFADDR:
		{
			struct sockaddr *sa;

			sa = (struct sockaddr *) &ifr->ifr_data;
			bcopy(((struct arpcom *)ifp->if_softc)->ac_enaddr,
			      (caddr_t) sa->sa_data, ETHER_ADDR_LEN);
		}
		break;

	case SIOCSIFMTU:
		/*
		 * Set the interface MTU.
		 * This is bogus. The underlying interface might support
	 	 * jumbo frames.
		 */
		if (ifr->ifr_mtu > ETHERMTU) {
			error = EINVAL;
		} else {
			ifp->if_mtu = ifr->ifr_mtu;
		}
		break;

	case SIOCSETVLAN:
		error = copyin(ifr->ifr_data, &vlr, sizeof vlr);
		if (error)
			break;
		if (vlr.vlr_parent[0] == '\0') {
			vlan_unconfig(ifp);
			if_down(ifp);
			ifp->if_flags = 0;
			break;
		}
		p = ifunit(vlr.vlr_parent);
		if (p == 0) {
			error = ENOENT;
			break;
		}
		error = vlan_config(ifv, p);
		if (error)
			break;
		ifv->ifv_tag = vlr.vlr_tag;
		break;
		
	case SIOCGETVLAN:
		bzero(&vlr, sizeof vlr);
		if (ifv->ifv_p) {
			snprintf(vlr.vlr_parent, sizeof(vlr.vlr_parent),
			    "%s%d", ifv->ifv_p->if_name, ifv->ifv_p->if_unit);
			vlr.vlr_tag = ifv->ifv_tag;
		}
		error = copyout(&vlr, ifr->ifr_data, sizeof vlr);
		break;
		
	case SIOCSIFFLAGS:
		/*
		 * We don't support promiscuous mode
		 * right now because it would require help from the
		 * underlying drivers, which hasn't been implemented.
		 */
		if (ifr->ifr_flags & (IFF_PROMISC)) {
			ifp->if_flags &= ~(IFF_PROMISC);
			error = EINVAL;
		}
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		error = vlan_setmulti(ifp);
		break;
	default:
		error = EINVAL;
	}
	return error;
}

#endif /* NVLAN > 0 */
