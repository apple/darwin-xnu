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
 * Copyright (c) 1982, 1989, 1993
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
 */



#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/netisr.h>
#include <net/route.h>
#include <net/if_llc.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/ndrv.h>
#include <netinet/if_ether.h>

#include <sys/socketvar.h>

#include <net/dlil.h>
#include <netat/at_pat.h>
#if NETAT
extern struct ifqueue atalkintrq;
#endif


#if BRIDGE
#include <net/bridge.h>
#endif

/* #include "vlan.h" */
#if NVLAN > 0
#include <net/if_vlan_var.h>
#endif /* NVLAN > 0 */

static
u_char	etherbroadcastaddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

#define IFP2AC(IFP) ((struct arpcom *)IFP)


struct dl_es_at_entry 
{
     struct ifnet *ifp;
     u_long	  dl_tag;
     int    ref_count;
};


/*
 * Temp static for protocol registration XXX
 */

#define MAX_EN_COUNT 30

static struct dl_es_at_entry en_at_array[MAX_EN_COUNT];

/*
 * Process a received Ethernet packet;
 * the packet is in the mbuf chain m without
 * the ether header, which is provided separately.
 */
int
at_ether_input(m, frame_header, ifp, dl_tag, sync_ok)
    struct mbuf  *m;
    char         *frame_header;
    struct ifnet *ifp;
    u_long	     dl_tag;
    int          sync_ok;

{
    register struct ether_header *eh = (struct ether_header *) frame_header;
    register struct ifqueue *inq=0;
    u_short ether_type;
    int s;
    u_int16_t ptype = -1;
    unsigned char buf[18];

#if NETAT
    register struct llc *l;
#endif

    if ((ifp->if_flags & IFF_UP) == 0) {
	m_freem(m);
	return EJUSTRETURN;
    }

    ifp->if_lastchange = time;

    if (eh->ether_dhost[0] & 1) {
	if (bcmp((caddr_t)etherbroadcastaddr, (caddr_t)eh->ether_dhost,
		 sizeof(etherbroadcastaddr)) == 0)
	    m->m_flags |= M_BCAST;
	else
	    m->m_flags |= M_MCAST;
    }
    if (m->m_flags & (M_BCAST|M_MCAST))
	ifp->if_imcasts++;

    ether_type = ntohs(eh->ether_type);

#if NVLAN > 0
	if (ether_type == vlan_proto) {
		if (vlan_input(eh, m) < 0)
			ifp->if_data.ifi_noproto++;
		return EJUSTRETURN;
	}
#endif /* NVLAN > 0 */

	if (ether_type > ETHERMTU)
	     return ENOENT;

#if NETAT
	l = mtod(m, struct llc *);

	switch (l->llc_dsap) {
	case LLC_SNAP_LSAP:

	     /* Temporary hack: check for AppleTalk and AARP packets */
	     /* WARNING we're checking only on the "ether_type" (the 2 bytes
	      * of the SNAP header. This shouldn't be a big deal, 
	      * AppleTalk pat_input is making sure we have the right packets
	      * because it needs to discrimante AARP from EtherTalk packets.
	      */

	     if (l->llc_ssap == LLC_SNAP_LSAP &&
		 l->llc_un.type_snap.control == 0x03) {

#ifdef APPLETALK_DEBUG
		  printf("new_ether_input: SNAP Cntrol type=0x%x Src=%s\n",
			 l->llc_un.type_snap.ether_type,
			 ether_sprintf(buf, &eh->ether_shost));
		  printf("                                     Dst=%s\n",
			 ether_sprintf(buf, &eh->ether_dhost));
#endif /* APPLETALK_DEBUG */

		  if ((l->llc_un.type_snap.ether_type == 0x809B) ||
		      (l->llc_un.type_snap.ether_type == 0x80F3)) {


		       /*
			* note: for AppleTalk we need to pass the enet header of the
			* packet up stack. To do so, we made sure in that the FULL packet
			* is copied in the mbuf by the mace driver, and only the m_data and
			* length have been shifted to make IP and the other guys happy.
			*/

		       m->m_data -= sizeof(*eh);
		       m->m_len += sizeof(*eh);
		       m->m_pkthdr.len += sizeof(*eh);	
#ifdef APPLETALK_DEBUG
		       l == (struct llc *)(eh+1);
		       if (l->llc_un.type_snap.ether_type == 0x80F3) {
			    kprintf("new_ether_input: RCV AppleTalk type=0x%x Src=%s\n",
				    l->llc_un.type_snap.ether_type,
				    ether_sprintf(buf, &eh->ether_shost));
			    kprintf("                                     Dst=%s\n",
				    ether_sprintf(buf, &eh->ether_dhost));
		       }
#endif /* APPLETALK_DEBUG */
		       schednetisr(NETISR_APPLETALK);
		       inq = &atalkintrq ;
		    
		       break;
		  }
	     }
	    
	     break;
	    
	    
	default:
	     return ENOENT;
	}


	if (inq == 0)
	     return ENOENT;

	s = splimp();
	if (IF_QFULL(inq)) {
		IF_DROP(inq);
		m_freem(m);
		splx(s);
		return EJUSTRETURN;
	} else
		IF_ENQUEUE(inq, m);
	splx(s);
	return 0;
#else
	return ENOENT;
#endif  /* NETAT */
}



int
ether_pre_output(ifp, m0, dst_netaddr, route, type, edst, dl_tag )
    struct ifnet    *ifp;
    struct mbuf     **m0;
    struct sockaddr *dst_netaddr;
    caddr_t	    route;
    char	    *type;
    char            *edst;
    u_long	    dl_tag;
{
    int s;
    register struct mbuf *m = *m0;
    register struct rtentry *rt;
    register struct ether_header *eh;
    int off, len = m->m_pkthdr.len;
    int hlen;	/* link layer header lenght */
    struct arpcom *ac = IFP2AC(ifp);



    if ((ifp->if_flags & (IFF_UP|IFF_RUNNING)) != (IFF_UP|IFF_RUNNING)) 
	return ENETDOWN;

    hlen = ETHER_HDR_LEN;

    /*
     * Tell ether_frameout it's ok to loop packet unless negated below.
     */
    m->m_flags |= M_LOOP;

    switch (dst_netaddr->sa_family) {
    case AF_UNSPEC:
	m->m_flags &= ~M_LOOP;
	eh = (struct ether_header *)dst_netaddr->sa_data;
	(void)memcpy(edst, eh->ether_dhost, 6);
	*(u_short *)type = eh->ether_type;
	break;
	

    case AF_APPLETALK:
    {
	eh = (struct ether_header *)dst_netaddr->sa_data;
	bcopy((caddr_t)eh->ether_dhost, (caddr_t)edst, 6);
		
	*(u_short *)type = m->m_pkthdr.len;
    }
    break;


    default:
	kprintf("%s%d: can't handle af%d\n", ifp->if_name, ifp->if_unit,
	       dst_netaddr->sa_family);

        return EAFNOSUPPORT;
    }

    return (0);
}





int
ether_prmod_ioctl(dl_tag, ifp, command, data)
    u_long       dl_tag;
    struct ifnet *ifp;
    int          command;
    caddr_t      data;
{
    struct ifaddr *ifa = (struct ifaddr *) data;
    struct ifreq *ifr = (struct ifreq *) data;
    int error = 0;
    boolean_t funnel_state;
    struct arpcom *ac = (struct arpcom *) ifp;
    struct sockaddr_dl *sdl;
    struct sockaddr_in *sin;
    u_char *e_addr;


    funnel_state = thread_funnel_set(network_flock, TRUE);

    switch (command) {

    case SIOCSIFADDR:
	 if ((ifp->if_flags & IFF_RUNNING) == 0) {
	      ifp->if_flags |= IFF_UP;
	      dlil_ioctl(0, ifp, SIOCSIFFLAGS, (caddr_t) 0);
	 }

	break;

    case SIOCGIFADDR:
    {
	struct sockaddr *sa;

	sa = (struct sockaddr *) & ifr->ifr_data;
	bcopy(IFP2AC(ifp)->ac_enaddr,
	      (caddr_t) sa->sa_data, ETHER_ADDR_LEN);
    }
    break;

    case SIOCSIFMTU:
	/*
	 * Set the interface MTU.
	 */
	if (ifr->ifr_mtu > ETHERMTU) {
	    error = EINVAL;
	} else {
	    ifp->if_mtu = ifr->ifr_mtu;
	}
	break;

    default:
	 return EOPNOTSUPP;
    }

    (void) thread_funnel_set(network_flock, funnel_state);

    return (error);
}



void
ether_attach_at(struct ifnet *ifp, u_long *at_dl_tag, u_long *aarp_dl_tag)
{
    struct dlil_proto_reg_str   reg;
    struct dlil_demux_desc      desc;
    struct dlil_demux_desc      desc2;
    u_short native = 0;           /* 802.2 frames use a length here */
    int   stat;
    int   first_empty;
    int   i;


    first_empty = MAX_EN_COUNT;
    for (i=0; i < MAX_EN_COUNT; i++) {
	 if (en_at_array[i].ifp == 0)
	      first_empty = i;

	 if (en_at_array[i].ifp == ifp) {
	      en_at_array[i].ref_count++;
	      *at_dl_tag = *aarp_dl_tag = en_at_array[i].dl_tag;
	      return;
	}
    }
    
    if (first_empty == MAX_EN_COUNT)
	 return;

    TAILQ_INIT(&reg.demux_desc_head);
    desc.type = DLIL_DESC_802_2_SNAP;
    desc.variants.desc_802_2_SNAP.dsap = LLC_SNAP_LSAP;
    desc.variants.desc_802_2_SNAP.ssap = LLC_SNAP_LSAP;
    desc.variants.desc_802_2_SNAP.control_code = 0x03;
    desc.variants.desc_802_2_SNAP.org[0] = 0x08;
    desc.variants.desc_802_2_SNAP.org[1] = 0x00;
    desc.variants.desc_802_2_SNAP.org[2] = 0x07;
    desc.variants.desc_802_2_SNAP.protocol_type = 0x809B;
    desc.native_type = (char *) &native;
    TAILQ_INSERT_TAIL(&reg.demux_desc_head, &desc, next);
    reg.interface_family = ifp->if_family;
    reg.unit_number      = ifp->if_unit;
    reg.input            = at_ether_input;
    reg.pre_output       = ether_pre_output;
    reg.event            = 0;
    reg.offer            = 0;
    reg.ioctl            = ether_prmod_ioctl;
    reg.default_proto    = 0;
    reg.protocol_family  = PF_APPLETALK;

    desc2 = desc;
    desc2.variants.desc_802_2_SNAP.protocol_type = 0x80F3;
    desc2.variants.desc_802_2_SNAP.org[0] = 0;
    desc2.variants.desc_802_2_SNAP.org[1] = 0;
    desc2.variants.desc_802_2_SNAP.org[2] = 0;

    TAILQ_INSERT_TAIL(&reg.demux_desc_head, &desc2, next); 

    stat = dlil_attach_protocol(&reg, at_dl_tag);
    if (stat) {
	printf("WARNING: ether_attach_at can't attach at to interface\n");
	return;
    }

    *aarp_dl_tag = *at_dl_tag;

    en_at_array[first_empty].ifp = ifp;
    en_at_array[first_empty].dl_tag = *at_dl_tag;
    en_at_array[first_empty].ref_count = 1;

} /* ether_attach_at */


void
ether_detach_at(struct ifnet *ifp)
{
     int i;
     
     for (i=0; i < MAX_EN_COUNT; i++) {
	  if (en_at_array[i].ifp == ifp)
	       break;
     }

     if (i < MAX_EN_COUNT) {
	  if (en_at_array[i].ref_count > 1) 
	       en_at_array[i].ref_count--;
	  else {
	       if (en_at_array[i].ref_count == 1) {
		    dlil_detach_protocol(en_at_array[i].dl_tag);
		    en_at_array[i].ifp = 0;
	       }
	  }
     }
}
