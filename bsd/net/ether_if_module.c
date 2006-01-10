/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
#include <net/route.h>
#include <net/if_llc.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_ether.h>
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
#include <net/if_bond_var.h>

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

#define memcpy(x,y,z)	bcopy(y, x, z)


SYSCTL_DECL(_net_link);
SYSCTL_NODE(_net_link, IFT_ETHER, ether, CTLFLAG_RW, 0, "Ethernet");

struct en_desc {
	u_int16_t	type;			/* Type of protocol stored in data */
	u_long 		protocol_family;	/* Protocol family */
	u_long		data[2];		/* Protocol data */
};
/* descriptors are allocated in blocks of ETHER_DESC_BLK_SIZE */
#define ETHER_DESC_BLK_SIZE (10) 

/*
 * Header for the demux list, hangs off of IFP at family_cookie
 */

struct ether_desc_blk_str {
	u_long  n_max_used;
	u_long	n_count;
	u_long	n_used;
	struct en_desc  block_ptr[1];
};
/* Size of the above struct before the array of struct en_desc */
#define ETHER_DESC_HEADER_SIZE	((size_t)&(((struct ether_desc_blk_str*)0)->block_ptr[0]))
__private_extern__ u_char	etherbroadcastaddr[ETHER_ADDR_LEN] =
								{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

int ether_add_proto_old(struct ifnet *ifp, u_long protocol_family, struct ddesc_head_str *desc_head);
int ether_add_if(struct ifnet *ifp);
int ether_del_if(struct ifnet *ifp);
int ether_init_if(struct ifnet *ifp);
int ether_family_init(void);

/*
 * Release all descriptor entries owned by this protocol (there may be several).
 * Setting the type to 0 releases the entry. Eventually we should compact-out
 * the unused entries.
 */
int
ether_del_proto(
	ifnet_t ifp,
	protocol_family_t protocol_family)
{
	struct ether_desc_blk_str *desc_blk = (struct ether_desc_blk_str *)ifp->family_cookie;
	u_long	current = 0;
	int found = 0;
	
	if (desc_blk == NULL)
		return 0;
	
	for (current = desc_blk->n_max_used; current > 0; current--) {
		if (desc_blk->block_ptr[current - 1].protocol_family == protocol_family) {
			found = 1;
			desc_blk->block_ptr[current - 1].type = 0;
			desc_blk->n_used--;
		}
	}
	
	if (desc_blk->n_used == 0) {
		FREE(ifp->family_cookie, M_IFADDR);
		ifp->family_cookie = 0;
	}
	else {
		/* Decrement n_max_used */
		for (; desc_blk->n_max_used > 0 && desc_blk->block_ptr[desc_blk->n_max_used - 1].type == 0; desc_blk->n_max_used--)
			;
	}
	
	return 0;
 }


static int
ether_add_proto_internal(
	struct ifnet					*ifp,
	protocol_family_t				protocol,
	const struct ifnet_demux_desc	*demux)
{
	struct en_desc *ed;
	struct ether_desc_blk_str *desc_blk = (struct ether_desc_blk_str *)ifp->family_cookie;
	u_int32_t i;
	
	switch (demux->type) {
		/* These types are supported */
		/* Top three are preferred */
		case DLIL_DESC_ETYPE2:
			if (demux->datalen != 2) {
				return EINVAL;
			}
			break;
		
		case DLIL_DESC_SAP:
			if (demux->datalen != 3) {
				return EINVAL;
			}
			break;
		
		case DLIL_DESC_SNAP:
			if (demux->datalen != 5) {
				return EINVAL;
			}
			break;
			
		default:
			return ENOTSUP;
	}
	
	// Verify a matching descriptor does not exist.
	if (desc_blk != NULL) {
		switch (demux->type) {
			case DLIL_DESC_ETYPE2:
				for (i = 0; i < desc_blk->n_max_used; i++) {
					if (desc_blk->block_ptr[i].type == DLIL_DESC_ETYPE2 &&
						desc_blk->block_ptr[i].data[0] ==
						*(u_int16_t*)demux->data) {
						return EADDRINUSE;
					}
				}
				break;
			case DLIL_DESC_SAP:
			case DLIL_DESC_SNAP:
				for (i = 0; i < desc_blk->n_max_used; i++) {
					if (desc_blk->block_ptr[i].type == demux->type &&
						bcmp(desc_blk->block_ptr[i].data, demux->data,
							 demux->datalen) == 0) {
						return EADDRINUSE;
					}
				}
				break;
		}
	}
	
	// Check for case where all of the descriptor blocks are in use
	if (desc_blk == NULL || desc_blk->n_used == desc_blk->n_count) {
		struct ether_desc_blk_str *tmp;
		u_long	new_count = ETHER_DESC_BLK_SIZE;
		u_long	new_size;
		u_long	old_size = 0;
		
		i = 0;
		
		if (desc_blk) {
			new_count += desc_blk->n_count;
			old_size = desc_blk->n_count * sizeof(struct en_desc) + ETHER_DESC_HEADER_SIZE;
			i = desc_blk->n_used;
		}
		
		new_size = new_count * sizeof(struct en_desc) + ETHER_DESC_HEADER_SIZE;
		
		tmp = _MALLOC(new_size, M_IFADDR, M_WAITOK);
		if (tmp  == 0) {
			/*
			 * Remove any previous descriptors set in the call.
			 */
			return ENOMEM;
		}
		
		bzero(tmp + old_size, new_size - old_size);
		if (desc_blk) {
			bcopy(desc_blk, tmp, old_size);
			FREE(desc_blk, M_IFADDR);
		}
		desc_blk = tmp;
		ifp->family_cookie = (u_long)desc_blk;
		desc_blk->n_count = new_count;
	}
	else {
		/* Find a free entry */
		for (i = 0; i < desc_blk->n_count; i++) {
			if (desc_blk->block_ptr[i].type == 0) {
				break;
			}
		}
	}
	
	/* Bump n_max_used if appropriate */
	if (i + 1 > desc_blk->n_max_used) {
		desc_blk->n_max_used = i + 1;
	}
	
	ed = &desc_blk->block_ptr[i];
	ed->protocol_family = protocol;
	ed->data[0] = 0;
	ed->data[1] = 0;
	
	switch (demux->type) {
		case DLIL_DESC_ETYPE2:
			/* 2 byte ethernet raw protocol type is at native_type */
			/* prtocol must be in network byte order */
			ed->type = DLIL_DESC_ETYPE2;
			ed->data[0] = *(u_int16_t*)demux->data;
			break;
		
		case DLIL_DESC_SAP:
			ed->type = DLIL_DESC_SAP;
			bcopy(demux->data, &ed->data[0], 3);
			break;
		
		case DLIL_DESC_SNAP: {
			u_int8_t*	pDest = ((u_int8_t*)&ed->data[0]) + 3;
			ed->type = DLIL_DESC_SNAP;
			bcopy(demux->data, pDest, 5);
			}
			break;
	}
	
	desc_blk->n_used++;
	
	return 0;
}

int
ether_add_proto(
	ifnet_t				ifp,
	protocol_family_t	protocol,
	const struct ifnet_demux_desc *demux_list,
	u_int32_t			demux_count)
{
	int			error = 0;
	u_int32_t	i;
	
	for (i = 0; i < demux_count; i++) {
		error = ether_add_proto_internal(ifp, protocol, &demux_list[i]);
		if (error) {
			ether_del_proto(ifp, protocol);
			break;
		}
	}
	
	return error;
}

__private_extern__ int
ether_add_proto_old(
	struct ifnet *ifp,
	u_long protocol_family,
	struct ddesc_head_str *desc_head)
{
	struct dlil_demux_desc  *desc;
	int error = 0;
	
	TAILQ_FOREACH(desc, desc_head, next) {
		struct ifnet_demux_desc dmx;
		int swapped = 0;
		
		// Convert dlil_demux_desc to ifnet_demux_desc
		dmx.type = desc->type;
		dmx.datalen = desc->variants.native_type_length;
		dmx.data = desc->native_type;
		
#ifdef DLIL_DESC_RAW
		if (dmx.type == DLIL_DESC_RAW) {
			swapped = 1;
			dmx.type = DLIL_DESC_ETYPE2;
			dmx.datalen = 2;
			*(u_int16_t*)dmx.data = htons(*(u_int16_t*)dmx.data);
		}
#endif
		
		error = ether_add_proto_internal(ifp, protocol_family, &dmx);
		if (swapped) {
			*(u_int16_t*)dmx.data = ntohs(*(u_int16_t*)dmx.data);
			swapped = 0;
		}
		if (error) {
			ether_del_proto(ifp, protocol_family);
			break;
		}
	}
	
	return error;
} 


static int
ether_shutdown(void)
{
    return 0;
}


int
ether_demux(
	ifnet_t				ifp,
	mbuf_t				m,
	char				*frame_header,
	protocol_family_t	*protocol_family)
{
	struct ether_header *eh = (struct ether_header *)frame_header;
	u_short			ether_type = eh->ether_type;
	u_int16_t		type;
	u_int8_t		*data;
	u_long			i = 0;
	struct ether_desc_blk_str *desc_blk = (struct ether_desc_blk_str *)ifp->family_cookie;
	u_long			maxd = desc_blk ? desc_blk->n_max_used : 0;
	struct en_desc	*ed = desc_blk ? desc_blk->block_ptr : NULL;
	u_int32_t		extProto1 = 0;
	u_int32_t		extProto2 = 0;

	if (eh->ether_dhost[0] & 1) {
		/* Check for broadcast */
		if (*(u_int32_t*)eh->ether_dhost == 0xFFFFFFFF &&
			*(u_int16_t*)(eh->ether_dhost + sizeof(u_int32_t)) == 0xFFFF)
			m->m_flags |= M_BCAST;
		else
			m->m_flags |= M_MCAST;
	}

	if (ifp->if_eflags & IFEF_BOND) {
		/* if we're bonded, bond "protocol" gets all the packets */
		*protocol_family = PF_BOND;
		return (0);
	}

	if ((eh->ether_dhost[0] & 1) == 0) {
		/*
 		* When the driver is put into promiscuous mode we may receive unicast
		* frames that are not intended for our interfaces.  They are marked here
		* as being promiscuous so the caller may dispose of them after passing
		* the packets to any interface filters.
		*/
		#define ETHER_CMP(x, y) ( ((u_int16_t *) x)[0] != ((u_int16_t *) y)[0] || \
								  ((u_int16_t *) x)[1] != ((u_int16_t *) y)[1] || \
								  ((u_int16_t *) x)[2] != ((u_int16_t *) y)[2] )
		
		if (ETHER_CMP(eh->ether_dhost, ifnet_lladdr(ifp))) {
			m->m_flags |= M_PROMISC;
		}
	}
	
	/* Quick check for VLAN */
	if ((m->m_pkthdr.csum_flags & CSUM_VLAN_TAG_VALID) != 0 ||
		ether_type == htons(ETHERTYPE_VLAN)) {
		*protocol_family = PF_VLAN;
		return 0;
	}
	
	data = mtod(m, u_int8_t*);
	
	/*
	* Determine the packet's protocol type and stuff the protocol into
	* longs for quick compares.
	*/
	
	if (ntohs(ether_type) <= 1500) {
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
			for (i = 0; i < maxd; i++) {
				if ((ed[i].type == type) && (ed[i].data[0] == ether_type)) {
					*protocol_family = ed[i].protocol_family;
					return 0;
				}
			}
			break;
		
		case DLIL_DESC_SAP:
			for (i = 0; i < maxd; i++) {
				if ((ed[i].type == type) && (ed[i].data[0] == extProto1)) {
					*protocol_family = ed[i].protocol_family;
					return 0;
				}
			}
			break;
		
		case DLIL_DESC_SNAP:
			for (i = 0; i < maxd; i++) {
				if ((ed[i].type == type) && (ed[i].data[0] == extProto1) &&
					(ed[i].data[1] == extProto2)) {
					*protocol_family = ed[i].protocol_family;
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
 */
int
ether_frameout(
	struct ifnet			*ifp,
	struct mbuf				**m,
	const struct sockaddr	*ndest,
	const char				*edst,
	const char				*ether_type)
{
	struct ether_header *eh;
	int hlen;	/* link layer header length */

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
	    if (lo_ifp) {
            if ((*m)->m_flags & M_BCAST) {
                struct mbuf *n = m_copy(*m, 0, (int)M_COPYALL);
                if (n != NULL)
                    dlil_output(lo_ifp, ndest->sa_family, n, 0, ndest, 0);
            }
            else {
                if (bcmp(edst, ifnet_lladdr(ifp), ETHER_ADDR_LEN) == 0) {
                    dlil_output(lo_ifp, ndest->sa_family, *m, 0, ndest, 0);
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
 	ifnet_lladdr_copy_bytes(ifp, eh->ether_shost, ETHER_ADDR_LEN);

	return 0;
}


__private_extern__ int
ether_add_if(struct ifnet *ifp)
{
	ifp->if_framer = ether_frameout;
	ifp->if_demux = ether_demux;
    
    return 0;
}

__private_extern__ int
ether_del_if(struct ifnet *ifp)
{
	if (ifp->family_cookie) {
		FREE(ifp->family_cookie, M_IFADDR);
		return 0;
	}
	else
		return ENOENT;
}

__private_extern__ int
ether_init_if(struct ifnet *ifp)
{
	/*
	 * Copy ethernet address out of old style arpcom. New
	 * interfaces created using the KPIs will not have an
	 * interface family. Those interfaces will have the
	 * lladdr passed in when the interface is created.
	 */
	u_char *enaddr = ((u_char*)ifp) + sizeof(struct ifnet);
	ifnet_set_lladdr(ifp, enaddr, 6);
	bzero(enaddr, 6);
	
    return 0;
}


errno_t
ether_check_multi(
	ifnet_t					ifp,
	const struct sockaddr	*proto_addr)
{
	errno_t	result = EAFNOSUPPORT;
	const u_char *e_addr;
	
	/*
	 * AF_SPEC and AF_LINK don't require translation. We do
	 * want to verify that they specify a valid multicast.
	 */
	switch(proto_addr->sa_family) {
		case AF_UNSPEC:
			e_addr = (const u_char*)&proto_addr->sa_data[0];
			if ((e_addr[0] & 0x01) != 0x01)
				result = EADDRNOTAVAIL;
			else
				result = 0;
			break;
		
		case AF_LINK:
			e_addr = CONST_LLADDR((const struct sockaddr_dl*)proto_addr); 
			if ((e_addr[0] & 0x01) != 0x01)
				result = EADDRNOTAVAIL;
			else
				result = 0;
			break;
	}
	
	return result;
}

int
ether_ioctl(
    __unused ifnet_t	ifp,
    __unused u_int32_t	command,
    __unused void*		data)
{
	return EOPNOTSUPP;
}


extern int ether_attach_inet(struct ifnet *ifp, u_long proto_family);
extern int ether_detach_inet(struct ifnet *ifp, u_long proto_family);
extern int ether_attach_inet6(struct ifnet *ifp, u_long proto_family);
extern int ether_detach_inet6(struct ifnet *ifp, u_long proto_family);

extern void kprintf(const char *, ...);

int ether_family_init(void)
{
    int  error=0;
    struct dlil_ifmod_reg_str  ifmod_reg;

    /* ethernet family is built-in, called from bsd_init */

    bzero(&ifmod_reg, sizeof(ifmod_reg));
    ifmod_reg.add_if = ether_add_if;
    ifmod_reg.del_if = ether_del_if;
    ifmod_reg.init_if = ether_init_if;
    ifmod_reg.add_proto = ether_add_proto_old;
    ifmod_reg.del_proto = ether_del_proto;
    ifmod_reg.ifmod_ioctl = ether_ioctl;
    ifmod_reg.shutdown    = ether_shutdown;

    if (dlil_reg_if_modules(APPLE_IF_FAM_ETHERNET, &ifmod_reg)) {
        printf("WARNING: ether_family_init -- Can't register if family modules\n");
        error = EIO;
	goto done;
    }

	/* Register protocol registration functions */

	if ((error = dlil_reg_proto_module(PF_INET, APPLE_IF_FAM_ETHERNET,
									  ether_attach_inet, ether_detach_inet)) != 0) {
		kprintf("dlil_reg_proto_module failed for AF_INET6 error=%d\n", error);
		goto done;
	}


	if ((error = dlil_reg_proto_module(PF_INET6, APPLE_IF_FAM_ETHERNET,
									  ether_attach_inet6, ether_detach_inet6)) != 0) {
		kprintf("dlil_reg_proto_module failed for AF_INET6 error=%d\n", error);
		goto done;
	}
	vlan_family_init();
	bond_family_init();

 done:

    return (error);
}
