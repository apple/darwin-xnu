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

#if INET
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#endif
#if INET6
#include <netinet6/nd6.h>
#include <netinet6/in6_ifattach.h>
#endif


#include <sys/socketvar.h>
#include <net/if_blue.h>

#include <net/dlil.h>


#if LLC && CCITT
extern struct ifqueue pkintrq;
#endif

/* General stuff from if_ethersubr.c - may not need some of it */

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


extern struct ifnet_blue *blue_if;
extern struct mbuf *splitter_input(struct mbuf *, struct ifnet *);

static u_long lo_dlt = 0;
static ivedonethis = 0;
static	int ether_resolvemulti __P((struct ifnet *, struct sockaddr **, 
				    struct sockaddr *));
u_char	etherbroadcastaddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

#define IFP2AC(IFP) ((struct arpcom *)IFP)

/* This stuff is new */

#define DB_HEADER_SIZE 20
struct en_desc {
    short           total_len;
    u_short         ethertype;
    u_long	    dl_tag;
    struct ifnet    *ifp;
    struct if_proto *proto;
    u_long          proto_id_length;
    u_long           proto_id_data[8]; /* probably less - proto-id and bitmasks */
};
    
#define LITMUS_SIZE 16
#define ETHER_DESC_BLK_SIZE 50
#define MAX_INTERFACES 50

/*
 * Statics for demux module
 */

struct ether_desc_blk_str {
    u_long   n_blocks;
    u_long   *block_ptr;
};

struct dl_es_at_entry 
{
     struct ifnet *ifp;
     u_long	  dl_tag;
     int    ref_count;
};


static struct ether_desc_blk_str ether_desc_blk[MAX_INTERFACES];
static u_long  litmus_mask[LITMUS_SIZE];
static u_long  litmus_length = 0;


/*
 * Temp static for protocol registration XXX
 */

#define MAX_EN_COUNT 30

static struct dl_es_at_entry en_at_array[MAX_EN_COUNT];

/*
 * This could be done below in-line with heavy casting, but the pointer arithmetic is 
 * prone to error.
 */

static
int  desc_in_bounds(block, current_ptr, offset_length)
    u_int  block;
    char   *current_ptr;
    u_long offset_length;
{
    u_long end_of_block;
    u_long current_ptr_tmp;

    current_ptr_tmp = (u_long) current_ptr;
    end_of_block = (u_long) ether_desc_blk[block].block_ptr;
    end_of_block += (ETHER_DESC_BLK_SIZE * ether_desc_blk[block].n_blocks);
    if ((current_ptr_tmp + offset_length) < end_of_block)
	return 1;
    else
	return 0;
}


/*
 * Release all descriptor entries owned by this dl_tag (there may be several).
 * Setting the dl_tag to 0 releases the entry. Eventually we should compact-out
 * the unused entries.
 */
static
int  ether_del_proto(struct if_proto *proto, u_long dl_tag)
{
    char *current_ptr = (char *) ether_desc_blk[proto->ifp->family_cookie].block_ptr;
    struct en_desc	   *ed;
    int i;
    int found = 0;

    ed = (struct en_desc *) current_ptr;

    while(ed->total_len) {
	if (ed->dl_tag == dl_tag) {
	    found = 1;
	    ed->dl_tag = 0;
	}

	current_ptr += ed->total_len;
	ed = (struct en_desc *) current_ptr;
    }
 }



static
int  ether_add_proto(struct ddesc_head_str *desc_head, struct if_proto *proto, u_long dl_tag)
{
   char *current_ptr;
   struct dlil_demux_desc  *desc;
   u_long		   id_length; /* IN LONGWORDS!!! */
   struct en_desc	   *ed;
   u_long		   *bitmask;
   u_long		   *proto_id;
   int			   i;
   short		   total_length;
   u_long		   block_count;
   u_long                  *tmp;


   TAILQ_FOREACH(desc, desc_head, next) {
       switch (desc->type) 
       {
       case DLIL_DESC_RAW:
	   id_length   = desc->variants.bitmask.proto_id_length;
	   break;
	   
       case DLIL_DESC_802_2:
	   id_length = 1; 
	   break;
	   
       case DLIL_DESC_802_2_SNAP:
	   id_length = 2;
	   break;
	   
       default:
	   return EINVAL;
       }

restart:
       block_count = ether_desc_blk[proto->ifp->family_cookie].n_blocks;
       current_ptr =  (char *) ether_desc_blk[proto->ifp->family_cookie].block_ptr;
       ed = (struct en_desc *) current_ptr;
       total_length = ((id_length << 2) * 2) + DB_HEADER_SIZE;

       while ((ed->total_len) && (desc_in_bounds(proto->ifp->family_cookie, 
			      current_ptr, total_length))) {
	   if ((ed->dl_tag == 0) && (total_length <= ed->total_len)) 
	       break;
	   else
	       current_ptr += *(short *)current_ptr;
	   
	   ed = (struct en_desc *) current_ptr;
       }

       if (!desc_in_bounds(proto->ifp->family_cookie, current_ptr, total_length)) {

	   tmp = _MALLOC((ETHER_DESC_BLK_SIZE * (block_count + 1)), 
			 M_IFADDR, M_WAITOK);
	   if (tmp  == 0) {
	       /*
	   	* Remove any previous descriptors set in the call.
	   	*/
	       ether_del_proto(proto, dl_tag);
	       return ENOMEM;
	   }

	   bzero(tmp, ETHER_DESC_BLK_SIZE * (block_count + 1));
	   bcopy(ether_desc_blk[proto->ifp->family_cookie].block_ptr, 
		 tmp, (ETHER_DESC_BLK_SIZE * block_count));
	   FREE(ether_desc_blk[proto->ifp->family_cookie].block_ptr, M_IFADDR);
	   ether_desc_blk[proto->ifp->family_cookie].n_blocks = block_count + 1;
	   ether_desc_blk[proto->ifp->family_cookie].block_ptr = tmp;
	   goto restart;
       }

       if (ed->total_len == 0)
	   ed->total_len = total_length;
       ed->ethertype = *((u_short *) desc->native_type);

       ed->dl_tag    = dl_tag;
       ed->proto     = proto;
       ed->proto_id_length = id_length;
       ed->ifp       = proto->ifp;

       switch (desc->type)
       {
       case DLIL_DESC_RAW:
	   bcopy(desc->variants.bitmask.proto_id, &ed->proto_id_data[0], (id_length << 2) );
	   bcopy(desc->variants.bitmask.proto_id_mask, &ed->proto_id_data[id_length],
		 (id_length << 2));
	   break;

       case DLIL_DESC_802_2:
	   ed->proto_id_data[0] = 0;
	   bcopy(&desc->variants.desc_802_2, &ed->proto_id_data[0], 3);
	   ed->proto_id_data[1] = 0xffffff00;
	   break;

       case DLIL_DESC_802_2_SNAP:
	   /* XXX Add verification of fixed values here */

	   ed->proto_id_data[0] = 0;
	   ed->proto_id_data[1] = 0;
	   bcopy(&desc->variants.desc_802_2_SNAP, &ed->proto_id_data[0], 8);
	   ed->proto_id_data[2] = 0xffffffff;
	   ed->proto_id_data[3] = 0xffffffff;;
	   break;  
       }
       
       if (id_length) {
	   proto_id = (u_long *) &ed->proto_id_data[0];
	   bitmask  = (u_long *) &ed->proto_id_data[id_length];
	   for (i=0; i < (id_length); i++) {
	       litmus_mask[i] &= bitmask[i];
	       litmus_mask[i] &= proto_id[i];
	   }
	   if (id_length > litmus_length)
	       litmus_length = id_length;
       }
   }	

   return 0;
} 


static
int  ether_shutdown()
{
    return 0;
}




/*
 * Process a received Ethernet packet;
 * the packet is in the mbuf chain m without
 * the ether header, which is provided separately.
 */
int
new_ether_input(m, frame_header, ifp, dl_tag, sync_ok)
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

#if ISO || LLC || NETAT
    register struct llc *l;
#endif


#if DLIL_BLUEBOX

    /*
     * Y-adapter input processing:
     *  - Don't split if coming from a dummy if
     *  - If coming from a real if, if splitting enabled,
     *    then filter the incoming packet
     */
    if (ifp != (struct ifnet *)blue_if)
    {	/* Is splitter turned on? */
	if (ifp->if_flags&IFF_SPLITTER)
	{	m->m_data -= sizeof(struct ether_header);
	m->m_len += sizeof (struct ether_header);
	m->m_pkthdr.len += sizeof(struct ether_header);
	/*
	 * Check to see if destined for BlueBox or Rhapsody
	 * If NULL return, mbuf's been consumed by the BlueBox.
	 * Otherwise, send on to Rhapsody
	 */
	if ((m = splitter_input(m, ifp)) == NULL)
	    return EJUSTRETURN;
	m->m_data += sizeof(struct ether_header);
	m->m_len -= sizeof (struct ether_header);
	m->m_pkthdr.len -= sizeof(struct ether_header);
	}
    } else
    {	/* Get the "real" IF */
	ifp = ((struct ndrv_cb *)(blue_if->ifb_so->so_pcb))->nd_if;
	m->m_pkthdr.rcvif = ifp;
	blue_if->pkts_looped_b2r++;
    }

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

    switch (ether_type) {
#if INET
    case ETHERTYPE_IP:
	if (ipflow_fastforward(m))
	    return EJUSTRETURN;
	ptype = mtod(m, struct ip *)->ip_p;
	if ((sync_ok == 0) || 
	    (ptype != IPPROTO_TCP && ptype != IPPROTO_UDP)) {
	    schednetisr(NETISR_IP); 
	}

	inq = &ipintrq;
	break;

    case ETHERTYPE_ARP:
	schednetisr(NETISR_ARP);
	inq = &arpintrq;
	break;
#endif
#if INET6                       
    case ETHERTYPE_IPV6:
        schednetisr(NETISR_IPV6);
        inq = &ip6intrq;
        break;
#endif  


    default: {
#if NETAT
	if (ether_type > ETHERMTU)
	    return ENOENT;
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

#else /*NETAT*/
	return ENOENT;
#endif /* NETAT */

	}
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

    if ((sync_ok) && 
	(ptype == IPPROTO_TCP || ptype == IPPROTO_UDP)) {
	extern void ipintr(void);

	s = splnet();
	ipintr();
	splx(s);
    }

    return 0;
}




int ether_demux(ifp, m, frame_header, proto)
    struct ifnet *ifp;
    struct mbuf  *m;
    char         *frame_header;
    struct if_proto **proto;

{
    register struct ether_header *eh = (struct ether_header *)frame_header;
    u_short ether_type;
    char *current_ptr = (char *) ether_desc_blk[ifp->family_cookie].block_ptr;
    struct dlil_demux_desc  *desc;
    register u_long          temp;
    u_long		    *data;
    register struct if_proto *ifproto;
    u_long		     i;
    struct en_desc	     *ed;


    if (eh->ether_dhost[0] & 1) {
	if (bcmp((caddr_t)etherbroadcastaddr, (caddr_t)eh->ether_dhost,
		 sizeof(etherbroadcastaddr)) == 0)
	    m->m_flags |= M_BCAST;
	else
	    m->m_flags |= M_MCAST;
    }

    ether_type = ntohs(eh->ether_type);

    /* 
     * Search through the connected protocols for a match. 
     */


    data = mtod(m, u_long *);
    ed = (struct en_desc *) current_ptr;
    while (desc_in_bounds(ifp->family_cookie, current_ptr, DB_HEADER_SIZE)) {
	if (ed->total_len == 0)
	    break;

	if ((ed->dl_tag !=  0) && (ed->ifp == ifp) && 
	    ((ed->ethertype == ntohs(eh->ether_type)) || (ed->ethertype == 0))) {
	    if (ed->proto_id_length) {
		for (i=0; i < (ed->proto_id_length); i++) {
		    temp = ntohs(data[i]) & ed->proto_id_data[ed->proto_id_length + i];
		    if ((temp ^ ed->proto_id_data[i]))
			break;
		}

		if (i >= (ed->proto_id_length)) {
		    *proto = ed->proto;
		    return 0;
		}
	    }
	    else {
		*proto = ed->proto;
		return 0;
	    }
	}
	current_ptr += ed->total_len;
	ed = (struct en_desc *) current_ptr;
    }

/*
    kprintf("ether_demux - No match for <%x><%x><%x><%x><%x><%x><%x<%x>\n",
	    eh->ether_type,data[0], data[1], data[2], data[3], data[4],data[5],data[6]);
*/

    return ENOENT;
}			



/*
 * Ethernet output routine.
 * Encapsulate a packet of type family for the local net.
 * Use trailer local net encapsulation if enough data in first
 * packet leaves a multiple of 512 bytes of data in remainder.
 * Assumes that ifp is actually pointer to arpcom structure.
 */
int
ether_frameout(ifp, m, ndest, edst, ether_type)
	register struct ifnet	*ifp;
	struct mbuf		**m;
	struct sockaddr		*ndest;
	char			*edst;
	char			*ether_type;
{
	register struct ether_header *eh;
	int hlen;	/* link layer header lenght */
	struct arpcom *ac = IFP2AC(ifp);


	hlen = ETHER_HDR_LEN;

	/*
	 * If a simplex interface, and the packet is being sent to our
	 * Ethernet address or a broadcast address, loopback a copy.
	 * XXX To make a simplex device behave exactly like a duplex
	 * device, we should copy in the case of sending to our own
	 * ethernet address (thus letting the original actually appear
	 * on the wire). However, we don't do that here for security
	 * reasons and compatibility with the original behavior.
	 */
	if ((ifp->if_flags & IFF_SIMPLEX) &&
	    ((*m)->m_flags & M_LOOP)) {
	    if (lo_dlt == 0) 
		dlil_find_dltag(APPLE_IF_FAM_LOOPBACK, 0, PF_INET, &lo_dlt);

	    if (lo_dlt) {
		if ((*m)->m_flags & M_BCAST) {
		    struct mbuf *n = m_copy(*m, 0, (int)M_COPYALL);
		    dlil_output(lo_dlt, n, 0, ndest, 0);
		} 
		else 
		{
		    if (bcmp(edst,  ac->ac_enaddr, ETHER_ADDR_LEN) == 0) {
			dlil_output(lo_dlt, *m, 0, ndest, 0);
			return EJUSTRETURN;
		    }
		}
	    }
	}


	/*
	 * Add local net header.  If no space in first mbuf,
	 * allocate another.
	 */
	M_PREPEND(*m, sizeof (struct ether_header), M_DONTWAIT);
	if (*m == 0) {
	    return (EJUSTRETURN);
	}


	eh = mtod(*m, struct ether_header *);
	(void)memcpy(&eh->ether_type, ether_type,
		sizeof(eh->ether_type));
 	(void)memcpy(eh->ether_dhost, edst, 6);
 	(void)memcpy(eh->ether_shost, ac->ac_enaddr,
	    sizeof(eh->ether_shost));

#if DLIL_BLUEBOX
	/*
	 * We're already to send.  Let's check for the blue box...
	 */
	if (ifp->if_flags&IFF_SPLITTER)
	{	
	    (*m)->m_flags |= 0x10;
	    if ((*m = splitter_input(*m, ifp)) == NULL) 
		return EJUSTRETURN;
	    else
		return (0);
	}
	else
#endif
	    return 0;
}


static
int  ether_add_if(struct ifnet *ifp)
{
    u_long  i;

    ifp->if_framer = ether_frameout;
    ifp->if_demux  = ether_demux;

    for (i=0; i < MAX_INTERFACES; i++)
	if (ether_desc_blk[i].n_blocks == 0)
	    break;

    if (i == MAX_INTERFACES)
	return EOVERFLOW;

    ether_desc_blk[i].block_ptr = _MALLOC(ETHER_DESC_BLK_SIZE, M_IFADDR, M_WAITOK);
    if (ether_desc_blk[i].block_ptr == 0)
	return ENOMEM;

    ether_desc_blk[i].n_blocks = 1;
    bzero(ether_desc_blk[i].block_ptr, ETHER_DESC_BLK_SIZE);

    ifp->family_cookie = i;
    
    return 0;
}

static
int  ether_del_if(struct ifnet *ifp)
{
    if ((ifp->family_cookie < MAX_INTERFACES) &&
	(ether_desc_blk[ifp->family_cookie].n_blocks)) {
	FREE(ether_desc_blk[ifp->family_cookie].block_ptr, M_IFADDR);
	ether_desc_blk[ifp->family_cookie].n_blocks = 0;
	return 0;
    }
    else
	return ENOENT;
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
    struct rtentry  *rt0 = (struct rtentry *) route;
    int s;
    register struct mbuf *m = *m0;
    register struct rtentry *rt;
    register struct ether_header *eh;
    int off, len = m->m_pkthdr.len;
    int hlen;	/* link layer header lenght */
    struct arpcom *ac = IFP2AC(ifp);



    if ((ifp->if_flags & (IFF_UP|IFF_RUNNING)) != (IFF_UP|IFF_RUNNING)) 
	return ENETDOWN;

    rt = rt0;
    if (rt) {
	if ((rt->rt_flags & RTF_UP) == 0) {
	    rt0 = rt = rtalloc1(dst_netaddr, 1, 0UL);
	    if (rt0)
		rt->rt_refcnt--;
	    else
		return EHOSTUNREACH;
	}

	if (rt->rt_flags & RTF_GATEWAY) {
	    if (rt->rt_gwroute == 0)
		goto lookup;
	    if (((rt = rt->rt_gwroute)->rt_flags & RTF_UP) == 0) {
		rtfree(rt); rt = rt0;
	    lookup: rt->rt_gwroute = rtalloc1(rt->rt_gateway, 1,
					      0UL);
		if ((rt = rt->rt_gwroute) == 0)
		    return (EHOSTUNREACH);
	    }
	}

	
	if (rt->rt_flags & RTF_REJECT)
	    if (rt->rt_rmx.rmx_expire == 0 ||
		time_second < rt->rt_rmx.rmx_expire)
		return (rt == rt0 ? EHOSTDOWN : EHOSTUNREACH);
    }

    hlen = ETHER_HDR_LEN;

    /*
     * Tell ether_frameout it's ok to loop packet unless negated below.
     */
    m->m_flags |= M_LOOP;

    switch (dst_netaddr->sa_family) {

#if INET
    case AF_INET:
	if (!arpresolve(ac, rt, m, dst_netaddr, edst, rt0))
	    return (EJUSTRETURN);	/* if not yet resolved */
	off = m->m_pkthdr.len - m->m_len;
	*(u_short *)type = htons(ETHERTYPE_IP);
	break;
#endif

#if INET6       
    case AF_INET6:
        if (!nd6_storelladdr(&ac->ac_if, rt, m, dst_netaddr, (u_char *)edst)) {
             /* this must be impossible, so we bark */
             kprintf("nd6_storelladdr failed\n");
             return(0);
                }
       off = m->m_pkthdr.len - m->m_len;
       *(u_short *)type = htons(ETHERTYPE_IPV6);
       break;
#endif  


    case AF_UNSPEC:
	m->m_flags &= ~M_LOOP;
	eh = (struct ether_header *)dst_netaddr->sa_data;
	(void)memcpy(edst, eh->ether_dhost, 6);
	*(u_short *)type = eh->ether_type;
	break;
	
#if NETAT
    case AF_APPLETALK:
    {
	eh = (struct ether_header *)dst_netaddr->sa_data;
	bcopy((caddr_t)eh->ether_dhost, (caddr_t)edst, 6);
		
	*(u_short *)type = m->m_pkthdr.len;
    }
    break;

#endif /* NETAT */

    default:
	kprintf("%s%d: can't handle af%d\n", ifp->if_name, ifp->if_unit,
	       dst_netaddr->sa_family);

        return EAFNOSUPPORT;
    }

    return (0);
}





int
ether_ioctl(dl_tag, ifp, command, data)
    u_long       dl_tag;
    struct ifnet *ifp;
    int          command;
    caddr_t      data;
{
    struct ifaddr *ifa = (struct ifaddr *) data;
    struct ifreq *ifr = (struct ifreq *) data;
    int error = 0;
    boolean_t funnel_state;

    funnel_state = thread_funnel_set(TRUE);

    switch (command) {
    case SIOCSIFADDR:
	ifp->if_flags |= IFF_UP;

	switch (ifa->ifa_addr->sa_family) {

	case AF_INET:

	    if (ifp->if_init)
		ifp->if_init(ifp->if_softc);	/* before arpwhohas */


	    arp_ifinit(IFP2AC(ifp), ifa);

	    break;

	default:
	    break;
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
    }

    (void) thread_funnel_set(funnel_state);

    return (error);
}




/*
 * Y-adapter filter check
 * The rules here:
 *  For Rhap: return 1
 *  For Both: return 0
 *  Not for Rhap: return -1
 *  Multicast/Broadcast => For Both
 *  Atalk address registered
 *   filter matches => For Rhap else Not For Rhap
 *  IP address registered
 *   filter matches => For Rhap else Not For Rhap
 *  For Rhap
 * Note this is *not* a general filter mechanism in that we know
 *  what we *could* be looking for.
 * WARNING: this is a big-endian routine.
 * Note: ARP and AARP packets are implicitly accepted for "both"
 */
int
Filter_check(struct mbuf **m0)
{	register struct BlueFilter *bf;
	register unsigned char *p;
	register unsigned short *s;
	register unsigned long *l;
	int total, flags;
	struct mbuf *m;
	extern struct mbuf *m_pullup(struct mbuf *, int);
	extern void kprintf( const char *, ...);
#define FILTER_LEN 32

	m = *m0;
	flags = m->m_flags;
	if (FILTER_LEN > m->m_pkthdr.len)
		return(1);
	while ((FILTER_LEN > m->m_len) && m->m_next) {
		total = m->m_len + (m->m_next)->m_len;
		if ((m = m_pullup(m, min(FILTER_LEN, total))) == 0)
			return(-1);
	}	 
	*m0 = m;

	p = mtod(m, unsigned char *);	/* Point to destination media addr */
	if (p[0] & 0x01)	/* Multicast/broadcast */
		return(0);
	s = (unsigned short *)p;
	bf = &RhapFilter[BFS_ATALK];
#if 0
	kprintf("!PKT: %x, %x, %x\n", s[6], s[7],	s[8]);
#endif

	if (bf->BF_flags)	/* Filtering Appletalk */
	{
		l = (unsigned long *)&s[8];
#if 0
		kprintf("!AT: %x, %x, %x, %x, %x, %x\n", s[6], s[7],
			*l, s[10], s[13], p[30]);
#endif
		if (s[6] <= ETHERMTU)
		{	if (s[7] == 0xaaaa) /* Could be Atalk */
			{	/* Verify SNAP header */
				if (*l == 0x03080007 && s[10] == 0x809b)
				{	if (s[13] == bf->BF_address &&
					     p[30] == bf->BF_node)
						return(1);
				} else if (*l == 0x03000000 && s[10] == 0x80f3)
					/* AARP pkts aren't net-addressed */
					return(0);
				return(0);
			} else /* Not for us? */
				return(0);
		} /* Fall through */
	} /* Fall through */
	bf++;			/* Look for IP next */
	if (bf->BF_flags)	/* Filtering IP */
	{
		l = (unsigned long *)&s[15];
#if 0
		kprintf("!IP: %x, %x\n", s[6], *l);
#endif
		if (s[6] > ETHERMTU)
		{	if (s[6] == 0x800)	/* Is IP */
			{	/* Verify IP address */
				if (*l == bf->BF_address)
					return(1);
				else	/* Not for us */
					return(0);
			} else if (s[6] == 0x806)
				/* ARP pkts aren't net-addressed */
				return(0);
		}
	}
	return(0);		/* No filters => Accept */
}



int ether_family_init()
{

    int  i;

    if (ivedonethis)
	return 0;

    ivedonethis = 1;


    if (dlil_reg_if_modules(APPLE_IF_FAM_ETHERNET, ether_add_if, ether_del_if,
			ether_add_proto, ether_del_proto,
			    ether_shutdown)) {
	printf("WARNING: ether_family_init -- Can't register if family modules\n");
	return EIO;
    }

    for (i=0; i < (LITMUS_SIZE/4); i++)
	litmus_mask[i] = 0xffffffff;

    for (i=0; i < MAX_INTERFACES; i++)
	ether_desc_blk[i].n_blocks = 0;

    for (i=0; i < MAX_EN_COUNT; i++)
	 en_at_array[i].ifp = 0;

    return 0;
}



u_long  ether_attach_inet(struct ifnet *ifp)
{
    struct dlil_proto_reg_str   reg;
    struct dlil_demux_desc      desc;
    struct dlil_demux_desc      desc2;
#if INET6
    struct dlil_demux_desc      desc3;
#endif
    u_long			ip_dl_tag=0;
    u_short en_native=ETHERTYPE_IP;
    u_short arp_native=ETHERTYPE_ARP;
#if INET6
    u_short en_6native=ETHERTYPE_IPV6;
#endif
    int   stat;
    int i;


    stat = dlil_find_dltag(ifp->if_family, ifp->if_unit, PF_INET, &ip_dl_tag);
    if (stat == 0)
	 return ip_dl_tag;

    TAILQ_INIT(&reg.demux_desc_head);
    desc.type = DLIL_DESC_RAW;
    desc.variants.bitmask.proto_id_length = 0;
    desc.variants.bitmask.proto_id = 0;
    desc.variants.bitmask.proto_id_mask = 0;
    desc.native_type = (char *) &en_native;
    TAILQ_INSERT_TAIL(&reg.demux_desc_head, &desc, next);
    reg.interface_family = ifp->if_family;
    reg.unit_number      = ifp->if_unit;
    reg.input            = new_ether_input;
    reg.pre_output       = ether_pre_output;
    reg.event            = 0;
    reg.offer            = 0;
    reg.ioctl            = ether_ioctl;
    reg.default_proto    = 1;
    reg.protocol_family  = PF_INET;

    desc2 = desc;
    desc2.native_type = (char *) &arp_native;
    TAILQ_INSERT_TAIL(&reg.demux_desc_head, &desc2, next);

#if INET6
    desc3 = desc;
    desc3.native_type = (char *) &en_6native;
    TAILQ_INSERT_TAIL(&reg.demux_desc_head, &desc3, next);
#endif

    stat = dlil_attach_protocol(&reg, &ip_dl_tag);
    if (stat) {
	printf("WARNING: ether_attach_inet can't attach ip to interface\n");
	return stat;
    }

    return ip_dl_tag;
}

void ether_attach_at(struct ifnet *ifp, u_long *at_dl_tag, u_long *aarp_dl_tag)
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
    reg.input            = new_ether_input;
    reg.pre_output       = ether_pre_output;
    reg.event            = 0;
    reg.offer            = 0;
    reg.ioctl            = ether_ioctl;
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


void ether_detach_at(struct ifnet *ifp)
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
