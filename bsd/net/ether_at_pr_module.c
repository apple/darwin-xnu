/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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

struct dl_es_at_entry 
{
	struct ifnet *ifp;
	int    ref_count;
};

/* Local fuction declerations */
int at_ether_input(struct mbuf *m, char *frame_header, struct ifnet *ifp,
				   u_long protocol_family, int sync_ok);
int ether_pre_output(struct ifnet *ifp, u_long protocol_family, struct mbuf **m0,
					 const struct sockaddr *dst_netaddr, caddr_t route, char *type, char *edst);
int ether_prmod_ioctl(u_long protocol_family, struct ifnet *ifp, u_long command,
					  caddr_t data);
int ether_attach_at(struct ifnet *ifp);
void ether_detach_at(struct ifnet *ifp);


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
at_ether_input(
	struct mbuf				*m,
	__unused char			*frame_header,
	__unused struct ifnet	*ifp,
	__unused u_long			protocol_family,
	__unused int			sync_ok)

{
   /*
	* note: for AppleTalk we need to pass the enet header of the
	* packet up stack. To do so, we made sure in that the FULL packet
	* is copied in the mbuf by the mace driver, and only the m_data and
	* length have been shifted to make IP and the other guys happy.
	*/

	m->m_data -= sizeof(struct ether_header);
	m->m_len += sizeof(struct ether_header);
	m->m_pkthdr.len += sizeof(struct ether_header);
	proto_input(PF_APPLETALK, m);

	return 0;
}



int
ether_pre_output(
	struct ifnet			*ifp,
	__unused u_long			protocol_family,
	struct mbuf				**m0,
	const struct sockaddr	*dst_netaddr,
	__unused caddr_t		route,
	char					*type,
	char					*edst)
{
    register struct mbuf *m = *m0;
    register struct ether_header *eh;
    int hlen;	/* link layer header lenght */



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
		
	*(u_short *)type = htons(m->m_pkthdr.len);
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
ether_prmod_ioctl(
    __unused u_long	protocol_family,
    struct ifnet	*ifp,
    u_long			command,
    caddr_t			data)
{
    struct ifreq *ifr = (struct ifreq *) data;
    int error = 0;

    switch (command) {

    case SIOCSIFADDR:
	 if ((ifp->if_flags & IFF_RUNNING) == 0) {
	      ifnet_set_flags(ifp, IFF_UP, IFF_UP);
	      dlil_ioctl(0, ifp, SIOCSIFFLAGS, (caddr_t) 0);
	 }

	break;

    case SIOCGIFADDR:
	ifnet_lladdr_copy_bytes(ifp, ifr->ifr_addr.sa_data, ETHER_ADDR_LEN);
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


    return (error);
}



int
ether_attach_at(
	struct ifnet *ifp)
{
    struct dlil_proto_reg_str   reg;
    struct dlil_demux_desc      desc;
    struct dlil_demux_desc      desc2;
    int   stat;
    int   first_empty;
    int   i;
    u_int8_t	atalk_snap[5] = {0x08, 0x00, 0x07, 0x80, 0x9b};
    u_int8_t	aarp_snap[5] = {0x00, 0x00, 0x00, 0x80, 0xf3};

    first_empty = MAX_EN_COUNT;
	for (i=0; i < MAX_EN_COUNT; i++) {
		if (en_at_array[i].ifp == 0)
			first_empty = i;
		
		if (en_at_array[i].ifp == ifp) {
			en_at_array[i].ref_count++;
			return 0;
		}
    }
    
	if (first_empty == MAX_EN_COUNT)
		return ENOMEM;
	
	bzero(&reg, sizeof(reg));
	bzero(&desc, sizeof(desc));
	bzero(&desc2, sizeof(desc2));
	
	TAILQ_INIT(&reg.demux_desc_head);
	reg.interface_family = ifp->if_family;
	reg.unit_number      = ifp->if_unit;
	reg.input            = at_ether_input;
	reg.pre_output       = ether_pre_output;
	reg.ioctl            = ether_prmod_ioctl;
	reg.protocol_family  = PF_APPLETALK;

	desc.type = DLIL_DESC_SNAP;
	desc.native_type = atalk_snap;
	desc.variants.native_type_length = sizeof(atalk_snap);
	TAILQ_INSERT_TAIL(&reg.demux_desc_head, &desc, next);
	
	desc2.type = DLIL_DESC_SNAP;
	desc2.native_type = aarp_snap;
	desc2.variants.native_type_length = sizeof(aarp_snap);
	TAILQ_INSERT_TAIL(&reg.demux_desc_head, &desc2, next);
	
    stat = dlil_attach_protocol(&reg);
	if (stat) {
		printf("WARNING: ether_attach_at can't attach at to interface\n");
		return stat;
	}

	en_at_array[first_empty].ifp = ifp;
	en_at_array[first_empty].ref_count = 1;
	
	return 0;
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
				dlil_detach_protocol(ifp, PF_APPLETALK);
				en_at_array[i].ifp = 0;
			}
		}
	}
}
