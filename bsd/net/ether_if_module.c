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
#include <netinet/if_ether.h>
#include <netinet/in.h>	/* For M_LOOP */

/*
#if INET
#include <netinet/in.h>
#include <netinet/in_var.h>

#include <netinet/in_systm.h>
#include <netinet/ip.h>
#endif
*/

#include <sys/socketvar.h>
#include <net/if_vlan_var.h>

#include <net/dlil.h>

extern int  vlan_demux(struct ifnet * ifp, struct mbuf *, 
		       char * frame_header, struct if_proto * * proto);

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

static u_long lo_dlt = 0;

#define IFP2AC(IFP) ((struct arpcom *)IFP)

struct en_desc {
    u_int16_t		type;		/* Type of protocol stored in data */
    struct if_proto *proto;		/* Protocol structure */
    u_long			data[2];	/* Protocol data */
};

#define ETHER_DESC_BLK_SIZE (10)
#define MAX_INTERFACES 50

/*
 * Statics for demux module
 */

struct ether_desc_blk_str {
    u_long  n_max_used;
    u_long	n_count;
    struct en_desc  *block_ptr;
};


static struct ether_desc_blk_str ether_desc_blk[MAX_INTERFACES];


/* from if_ethersubr.c */
int ether_resolvemulti __P((struct ifnet *, struct sockaddr **,
                                    struct sockaddr *));

/*
 * Release all descriptor entries owned by this dl_tag (there may be several).
 * Setting the type to 0 releases the entry. Eventually we should compact-out
 * the unused entries.
 */
__private_extern__ int
ether_del_proto(struct if_proto *proto, u_long dl_tag)
{
    struct en_desc*	ed = ether_desc_blk[proto->ifp->family_cookie].block_ptr;
    u_long	current = 0;
    int found = 0;
    
    for (current = ether_desc_blk[proto->ifp->family_cookie].n_max_used;
            current > 0; current--) {
        if (ed[current - 1].proto == proto) {
            found = 1;
            ed[current - 1].type = 0;
            
            if (current == ether_desc_blk[proto->ifp->family_cookie].n_max_used) {
                ether_desc_blk[proto->ifp->family_cookie].n_max_used--;
            }
        }
    }
    
    return found;
 }




__private_extern__ int
ether_add_proto(struct ddesc_head_str *desc_head, struct if_proto *proto, u_long dl_tag)
{
   char *current_ptr;
   struct dlil_demux_desc  *desc;
   struct en_desc	   *ed;
   struct en_desc *last;
   u_long		   *bitmask;
   u_long		   *proto_id;
   u_long		   i;
   short		   total_length;
   u_long		   block_count;
   u_long                  *tmp;


    TAILQ_FOREACH(desc, desc_head, next) {
        switch (desc->type) {
            /* These types are supported */
            /* Top three are preferred */
            case DLIL_DESC_ETYPE2:
                if (desc->variants.native_type_length != 2)
                    return EINVAL;
                break;
                
            case DLIL_DESC_SAP:
                if (desc->variants.native_type_length != 3)
                    return EINVAL;
                break;
                
            case DLIL_DESC_SNAP:
                if (desc->variants.native_type_length != 5)
                    return EINVAL;
                break;
                
            case DLIL_DESC_802_2:
            case DLIL_DESC_802_2_SNAP:
                break;
            
            case DLIL_DESC_RAW:
                if (desc->variants.bitmask.proto_id_length == 0)
                    break;
                /* else fall through, bitmask variant not supported */
            
            default:
                ether_del_proto(proto, dl_tag);
                return EINVAL;
        }
    
        ed = ether_desc_blk[proto->ifp->family_cookie].block_ptr;
        
        /* Find a free entry */
        for (i = 0; i < ether_desc_blk[proto->ifp->family_cookie].n_count; i++) {
            if (ed[i].type == 0) {
                break;
            }
        }
        
        if (i >= ether_desc_blk[proto->ifp->family_cookie].n_count) {
            u_long	new_count = ETHER_DESC_BLK_SIZE +
                        ether_desc_blk[proto->ifp->family_cookie].n_count;
            tmp = _MALLOC((new_count * (sizeof(*ed))), M_IFADDR, M_WAITOK);
            if (tmp  == 0) {
                /*
                * Remove any previous descriptors set in the call.
                */
                ether_del_proto(proto, dl_tag);
                return ENOMEM;
            }
            
            bzero(tmp, new_count * sizeof(*ed));
            bcopy(ether_desc_blk[proto->ifp->family_cookie].block_ptr, 
                tmp, ether_desc_blk[proto->ifp->family_cookie].n_count * sizeof(*ed));
            FREE(ether_desc_blk[proto->ifp->family_cookie].block_ptr, M_IFADDR);
            ether_desc_blk[proto->ifp->family_cookie].n_count = new_count;
            ether_desc_blk[proto->ifp->family_cookie].block_ptr = (struct en_desc*)tmp;
	    ed = ether_desc_blk[proto->ifp->family_cookie].block_ptr;
        }
        
        /* Bump n_max_used if appropriate */
        if (i + 1 > ether_desc_blk[proto->ifp->family_cookie].n_max_used) {
            ether_desc_blk[proto->ifp->family_cookie].n_max_used = i + 1;
        }
        
        ed[i].proto	= proto;
        ed[i].data[0] = 0;
        ed[i].data[1] = 0;
        
        switch (desc->type) {
            case DLIL_DESC_RAW:
                /* 2 byte ethernet raw protocol type is at native_type */
                /* protocol is not in network byte order */
                ed[i].type = DLIL_DESC_ETYPE2;
                ed[i].data[0] = htons(*(u_int16_t*)desc->native_type);
                break;
                
            case DLIL_DESC_ETYPE2:
                /* 2 byte ethernet raw protocol type is at native_type */
                /* prtocol must be in network byte order */
                ed[i].type = DLIL_DESC_ETYPE2;
                ed[i].data[0] = *(u_int16_t*)desc->native_type;
                break;
            
            case DLIL_DESC_802_2:
                ed[i].type = DLIL_DESC_SAP;
                ed[i].data[0] = *(u_int32_t*)&desc->variants.desc_802_2;
                ed[i].data[0] &= htonl(0xFFFFFF00);
                break;
            
            case DLIL_DESC_SAP:
                ed[i].type = DLIL_DESC_SAP;
                bcopy(desc->native_type, &ed[i].data[0], 3);
                break;
    
            case DLIL_DESC_802_2_SNAP:
                ed[i].type = DLIL_DESC_SNAP;
                desc->variants.desc_802_2_SNAP.protocol_type =
                    htons(desc->variants.desc_802_2_SNAP.protocol_type);
                bcopy(&desc->variants.desc_802_2_SNAP, &ed[i].data[0], 8);
                ed[i].data[0] &= htonl(0x000000FF);
                desc->variants.desc_802_2_SNAP.protocol_type =
                    ntohs(desc->variants.desc_802_2_SNAP.protocol_type);
                break;
            
            case DLIL_DESC_SNAP: {
                u_int8_t*	pDest = ((u_int8_t*)&ed[i].data[0]) + 3;
                ed[i].type = DLIL_DESC_SNAP;
                bcopy(desc->native_type, pDest, 5);
            }
            break;
        }
    }
    
    return 0;
} 


static
int  ether_shutdown()
{
    return 0;
}


int ether_demux(ifp, m, frame_header, proto)
    struct ifnet *ifp;
    struct mbuf  *m;
    char         *frame_header;
    struct if_proto **proto;

{
    register struct ether_header *eh = (struct ether_header *)frame_header;
    u_short			ether_type = eh->ether_type;
    u_short			ether_type_host;
    u_int16_t		type;
    u_int8_t		*data;
    u_long			i = 0;
    u_long			max = ether_desc_blk[ifp->family_cookie].n_max_used;
    struct en_desc	*ed = ether_desc_blk[ifp->family_cookie].block_ptr;
    u_int32_t		extProto1 = 0;
    u_int32_t		extProto2 = 0;
    
    if (eh->ether_dhost[0] & 1) {
        /* Check for broadcast */
        if (*(u_int32_t*)eh->ether_dhost == 0xFFFFFFFF &&
            *(u_int16_t*)(eh->ether_dhost + sizeof(u_int32_t)) == 0xFFFF)
            m->m_flags |= M_BCAST;
        else
            m->m_flags |= M_MCAST;
    } else {
        /*
         * When the driver is put into promiscuous mode we may receive unicast
         * frames that are not intended for our interfaces.  They are filtered
         * here to keep them from traveling further up the stack to code that
         * is not expecting them or prepared to deal with them.  In the near
         * future, the filtering done here will be moved even further down the
         * stack into the IONetworkingFamily, preventing even interface
         * filter NKE's from receiving promiscuous packets.  Please use BPF.
         */
        #define ETHER_CMP(x, y) ( ((u_int16_t *) x)[0] != ((u_int16_t *) y)[0] || \
                                  ((u_int16_t *) x)[1] != ((u_int16_t *) y)[1] || \
                                  ((u_int16_t *) x)[2] != ((u_int16_t *) y)[2] )
    
        if (ETHER_CMP(eh->ether_dhost, ((struct arpcom *) ifp)->ac_enaddr)) {
            m_freem(m);
            return EJUSTRETURN;
        }
    }
    ether_type_host = ntohs(ether_type);
    if ((m->m_pkthdr.csum_flags & CSUM_VLAN_TAG_VALID)
	|| ether_type_host == ETHERTYPE_VLAN) {
	return (vlan_demux(ifp, m, frame_header, proto));
    }
    data = mtod(m, u_int8_t*);

    /*
     * Determine the packet's protocol type and stuff the protocol into
     * longs for quick compares.
     */
    if (ether_type_host <= 1500) {
        extProto1 = *(u_int32_t*)data;
        
        // SAP or SNAP
        if ((extProto1 & htonl(0xFFFFFF00)) == htonl(0xAAAA0300)) {
            // SNAP
            type = DLIL_DESC_SNAP;
            extProto2 = *(u_int32_t*)(data + sizeof(u_int32_t));
            extProto1 &= htonl(0x000000FF);
        } else {
            type = DLIL_DESC_SAP;
            extProto1 &= htonl(0xFFFFFF00);
        }
    } else {
        type = DLIL_DESC_ETYPE2;
    }
    
    /* 
     * Search through the connected protocols for a match. 
     */
    
    switch (type) {
        case DLIL_DESC_ETYPE2:
            for (i = 0; i < max; i++) {
                if ((ed[i].type == type) && (ed[i].data[0] == ether_type)) {
                    *proto = ed[i].proto;
                    return 0;
                }
            }
            break;
        
        case DLIL_DESC_SAP:
            for (i = 0; i < max; i++) {
                if ((ed[i].type == type) && (ed[i].data[0] == extProto1)) {
                    *proto = ed[i].proto;
                    return 0;
                }
            }
            break;
        
        case DLIL_DESC_SNAP:
            for (i = 0; i < max; i++) {
                if ((ed[i].type == type) && (ed[i].data[0] == extProto1) &&
                    (ed[i].data[1] == extProto2)) {
                    *proto = ed[i].proto;
                    return 0;
                }
            }
            break;
    }
    
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
	int hlen;	/* link layer header length */
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
                if (n != NULL)
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

	return 0;
}



__private_extern__ int
ether_add_if(struct ifnet *ifp)
{
    u_long  i;

    ifp->if_framer = ether_frameout;
    ifp->if_demux  = ether_demux;
    ifp->if_event  = 0;
    ifp->if_resolvemulti = ether_resolvemulti;
    ifp->if_nvlans = 0;

    for (i=0; i < MAX_INTERFACES; i++)
        if (ether_desc_blk[i].n_count == 0)
            break;

    if (i == MAX_INTERFACES)
        return ENOMEM;

    ether_desc_blk[i].block_ptr = _MALLOC(ETHER_DESC_BLK_SIZE * sizeof(struct en_desc),
                                            M_IFADDR, M_WAITOK);
    if (ether_desc_blk[i].block_ptr == 0)
        return ENOMEM;

    ether_desc_blk[i].n_count = ETHER_DESC_BLK_SIZE;
    bzero(ether_desc_blk[i].block_ptr, ETHER_DESC_BLK_SIZE * sizeof(struct en_desc));

    ifp->family_cookie = i;
    
    return 0;
}

__private_extern__ int
ether_del_if(struct ifnet *ifp)
{
    if ((ifp->family_cookie < MAX_INTERFACES) &&
        (ether_desc_blk[ifp->family_cookie].n_count))
    {
        FREE(ether_desc_blk[ifp->family_cookie].block_ptr, M_IFADDR);
        ether_desc_blk[ifp->family_cookie].block_ptr = NULL;
        ether_desc_blk[ifp->family_cookie].n_count = 0;
        ether_desc_blk[ifp->family_cookie].n_max_used = 0;
        return 0;
    }
    else
        return ENOENT;
}

__private_extern__ int
ether_init_if(struct ifnet *ifp)
{
    register struct ifaddr *ifa;
    register struct sockaddr_dl *sdl;

    ifa = ifnet_addrs[ifp->if_index - 1];
    if (ifa == 0) {
            printf("ether_ifattach: no lladdr!\n");
            return (EINVAL);
    }
    sdl = (struct sockaddr_dl *)ifa->ifa_addr;
    sdl->sdl_type = IFT_ETHER;
    sdl->sdl_alen = ifp->if_addrlen;
    bcopy((IFP2AC(ifp))->ac_enaddr, LLADDR(sdl), ifp->if_addrlen);

    return 0;
}


int
ether_ifmod_ioctl(ifp, command, data)
    struct ifnet *ifp;
    u_long       command;
    caddr_t      data;
{
    struct rslvmulti_req *rsreq = (struct rslvmulti_req *) data;
    int error = 0;
    struct sockaddr_dl *sdl;
    struct sockaddr_in *sin;
    u_char *e_addr;


    switch (command) {
        case SIOCRSLVMULTI: 
        switch(rsreq->sa->sa_family) {
            case AF_UNSPEC:
                /* AppleTalk uses AF_UNSPEC for multicast registration.
                 * No mapping needed. Just check that it's a valid MC address.
                 */
                e_addr = &rsreq->sa->sa_data[0];
                if ((e_addr[0] & 1) != 1)
                    return EADDRNOTAVAIL;
                *rsreq->llsa = 0;
                return EJUSTRETURN;
            
            
            case AF_LINK:
                /* 
                 * No mapping needed. Just check that it's a valid MC address.
                 */
                sdl = (struct sockaddr_dl *)rsreq->sa;
                e_addr = LLADDR(sdl);
                if ((e_addr[0] & 1) != 1)
                    return EADDRNOTAVAIL;
                *rsreq->llsa = 0;
                return EJUSTRETURN;
                
            default:
                return EAFNOSUPPORT;
        }
        
        default:
            return EOPNOTSUPP;
    }
}


extern int ether_attach_inet(struct ifnet *ifp, u_long *dl_tag);
extern int ether_detach_inet(struct ifnet *ifp, u_long dl_tag);
extern int ether_attach_inet6(struct ifnet *ifp, u_long *dl_tag);
extern int ether_detach_inet6(struct ifnet *ifp, u_long dl_tag);
int ether_family_init()
{
    int  i, error=0;
    struct dlil_ifmod_reg_str  ifmod_reg;
    struct dlil_protomod_reg_str enet_protoreg;
    extern int vlan_family_init(void);

    /* ethernet family is built-in, called from bsd_init */
    thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);

    bzero(&ifmod_reg, sizeof(ifmod_reg));
    ifmod_reg.add_if = ether_add_if;
    ifmod_reg.del_if = ether_del_if;
    ifmod_reg.init_if = ether_init_if;
    ifmod_reg.add_proto = ether_add_proto;
    ifmod_reg.del_proto = ether_del_proto;
    ifmod_reg.ifmod_ioctl = ether_ifmod_ioctl;
    ifmod_reg.shutdown    = ether_shutdown;

    if (dlil_reg_if_modules(APPLE_IF_FAM_ETHERNET, &ifmod_reg)) {
        printf("WARNING: ether_family_init -- Can't register if family modules\n");
        error = EIO;
	goto done;
    }


    /* Register protocol registration functions */
    
    bzero(&enet_protoreg, sizeof(enet_protoreg));
    enet_protoreg.attach_proto = ether_attach_inet;
    enet_protoreg.detach_proto = ether_detach_inet;
    
    if (error = dlil_reg_proto_module(PF_INET, APPLE_IF_FAM_ETHERNET, &enet_protoreg) != 0) {
	printf("ether_family_init: dlil_reg_proto_module failed for AF_INET error=%d\n", error);
	goto done;
    }
    
    enet_protoreg.attach_proto = ether_attach_inet6;
    enet_protoreg.detach_proto = ether_detach_inet6;
    
    if (error = dlil_reg_proto_module(PF_INET6, APPLE_IF_FAM_ETHERNET, &enet_protoreg) != 0) {
	printf("ether_family_init: dlil_reg_proto_module failed for AF_INET6 error=%d\n", error);
	goto done;
    }
    vlan_family_init();

 done:
    thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);

    return (error);
}
