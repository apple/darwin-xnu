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

/*
#if INET
#include <netinet/in.h>
#include <netinet/in_var.h>

#include <netinet/in_systm.h>
#include <netinet/ip.h>
#endif
*/

#include <sys/socketvar.h>

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

static u_long lo_dlt = 0;
static ivedonethis = 0;

#define IFP2AC(IFP) ((struct arpcom *)IFP)

u_char	etherbroadcastaddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };


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


static
int  ether_add_if(struct ifnet *ifp)
{
    u_long  i;

    ifp->if_framer = ether_frameout;
    ifp->if_demux  = ether_demux;
    ifp->if_event  = 0;

    for (i=0; i < MAX_INTERFACES; i++)
	if (ether_desc_blk[i].n_blocks == 0)
	    break;

    if (i == MAX_INTERFACES)
	return ENOMEM;

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


    switch (command) 
    {
    case SIOCRSLVMULTI: 
	 switch(rsreq->sa->sa_family) 
	 {
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


int ether_family_init()
{
    int  i;
    struct dlil_ifmod_reg_str  ifmod_reg;

    if (ivedonethis)
	return 0;

    ivedonethis = 1;

    ifmod_reg.add_if = ether_add_if;
    ifmod_reg.del_if = ether_del_if;
    ifmod_reg.add_proto = ether_add_proto;
    ifmod_reg.del_proto = ether_del_proto;
    ifmod_reg.ifmod_ioctl = ether_ifmod_ioctl;
    ifmod_reg.shutdown    = ether_shutdown;

    if (dlil_reg_if_modules(APPLE_IF_FAM_ETHERNET, &ifmod_reg)) {
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
