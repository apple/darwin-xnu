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
 * Copyright 1994 Apple Computer, Inc.
 * All Rights Reserved.
 *
 * Tuyen A. Nguyen. (December 5, 1994)
 *   Modified, March 17, 1997 by Tuyen Nguyen for MacOSX.
 */

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <machine/spl.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/mbuf.h>
#include <sys/ioctl.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/ethernet.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/at_pcb.h>
#include <netat/at_var.h>
#include <netat/ddp.h>
#include <netat/at_aarp.h>
#include <netat/at_pat.h>
#include <netat/debug.h>

#define DSAP_SNAP 0xaa

extern void gref_init(), atp_init(), atp_link(), atp_unlink();

extern int adspInited;

static llc_header_t	snap_hdr_at = SNAP_HDR_AT;
static llc_header_t	snap_hdr_aarp = SNAP_HDR_AARP;
static unsigned char snap_proto_ddp[5] = SNAP_PROTO_AT;
static unsigned char snap_proto_aarp[5] = SNAP_PROTO_AARP;

int pktsIn, pktsOut;

struct ifqueue atalkintrq; 	/* appletalk and aarp packet input queue */

short appletalk_inited = 0;

extern atlock_t 
	ddpall_lock, ddpinp_lock, arpinp_lock, refall_lock, nve_lock,
  	aspall_lock, asptmo_lock, atpall_lock, atptmo_lock, atpgen_lock;

extern int (*sys_ATsocket )(), (*sys_ATgetmsg)(), (*sys_ATputmsg)();
extern int (*sys_ATPsndreq)(), (*sys_ATPsndrsp)();
extern int (*sys_ATPgetreq)(), (*sys_ATPgetrsp)();

void atalk_load()
{
	extern int _ATsocket(), _ATgetmsg(), _ATputmsg();
	extern int _ATPsndreq(), _ATPsndrsp(), _ATPgetreq(), _ATPgetrsp();

	sys_ATsocket  = _ATsocket;
	sys_ATgetmsg  = _ATgetmsg;
	sys_ATputmsg  = _ATputmsg;
	sys_ATPsndreq = _ATPsndreq;
	sys_ATPsndrsp = _ATPsndrsp;
	sys_ATPgetreq = _ATPgetreq;
	sys_ATPgetrsp = _ATPgetrsp;

	ATLOCKINIT(ddpall_lock);
	ATLOCKINIT(ddpinp_lock);
	ATLOCKINIT(arpinp_lock);
	ATLOCKINIT(refall_lock);
	ATLOCKINIT(aspall_lock);
	ATLOCKINIT(asptmo_lock);
	ATLOCKINIT(atpall_lock);
	ATLOCKINIT(atptmo_lock);
	ATLOCKINIT(atpgen_lock);
	ATLOCKINIT(nve_lock);

	atp_init();
	atp_link();
	adspInited = 0;

/*	adsp_init(); 
		for 2225395
		this happens in adsp_open and is undone on ADSP_UNLINK 
*/
} /* atalk_load */

/* Undo everything atalk_load() did. */
void atalk_unload()  /* not currently used */
{
	extern gbuf_t *scb_resource_m;
	extern gbuf_t *atp_resource_m;

	sys_ATsocket  = 0;
	sys_ATgetmsg  = 0;
	sys_ATputmsg  = 0;
	sys_ATPsndreq = 0;
	sys_ATPsndrsp = 0;
	sys_ATPgetreq = 0;
	sys_ATPgetrsp = 0;

	atp_unlink();

#ifdef NOT_YET
	if (scb_resource_m) { 
		gbuf_freem(scb_resource_m);
		scb_resource_m = 0;
		scb_free_list = 0;
	}
	/* allocated in atp_trans_alloc() */
	if (atp_resource_m) {
		gbuf_freem(atp_resource_m);
		atp_resource_m = 0;
		atp_trans_free_list = 0;
	}
#endif

	appletalk_inited = 0;
} /* atalk_unload */

void appletalk_hack_start()
{
	if (!appletalk_inited) {
		atalk_load();
		atalkintrq.ifq_maxlen = IFQ_MAXLEN; 
		appletalk_inited = 1;
	}
} /* appletalk_hack_start */

int pat_output(patp, mlist, dst_addr, type)
	at_ifaddr_t *patp;
	struct mbuf *mlist;			/* packet chain */
	unsigned char *dst_addr;
	int 	type;
{
	struct mbuf *m, *m1;
	llc_header_t *llc_header;
	struct sockaddr dst;

	if (! patp->aa_ifp) {
		for (m = mlist; m; m = mlist) {
			mlist = m->m_nextpkt;
			m->m_nextpkt = 0;
			m_freem(m);
		}
		return ENOTREADY;
	}

	/* this is for ether_output */
	dst.sa_family = AF_APPLETALK;
	dst.sa_len = 2 + sizeof(struct etalk_addr);
	bcopy (dst_addr, &dst.sa_data[0], sizeof(struct etalk_addr)); 

	/* packet chains are used on output and can be tested using aufs */
	for (m = mlist; m; m = mlist) {
		mlist = m->m_nextpkt;
		m->m_nextpkt = 0;

		M_PREPEND(m, sizeof(llc_header_t), M_DONTWAIT);
		if (m == 0) {
			continue;
		}

		llc_header = mtod(m, llc_header_t *);
		*llc_header = 
		  (type == AARP_AT_TYPE) ? snap_hdr_aarp : snap_hdr_at;

		for (m->m_pkthdr.len = 0, m1 = m; m1; m1 = m1->m_next)
			m->m_pkthdr.len += m1->m_len;
		m->m_pkthdr.rcvif = 0;

		/* *** Note: AT is sending out mbufs of type MSG_DATA,
		   not MT_DATA.  *** */
#ifdef APPLETALK_DEBUG
		if (m->m_next && 
		    !((m->m_next)->m_flags & M_EXT))
			kprintf("po: mlen= %d, m2len= %d\n", m->m_len, 
				(m->m_next)->m_len);
#endif
		dlil_output(patp->at_dl_tag, m, NULL, &dst, 0);

		pktsOut++;
	}

	return 0;
} /* pat_output */

void atalkintr()
{
	struct mbuf *m, *m1, *mlist = NULL;
	struct ifnet *ifp;
	int s;
	llc_header_t *llc_header;
	at_ifaddr_t *ifID;
	char src[6];
	enet_header_t *enet_header;
		
next:
	s = splimp();
	IF_DEQUEUE(&atalkintrq, m);
	splx(s);	

	if (m == 0) 
		return;	

	for ( ; m ; m = mlist) {
	  mlist = m->m_nextpkt;
#ifdef APPLETALK_DEBUG
	  /* packet chains are not yet in use on input */
	  if (mlist) kprintf("atalkintr: packet chain\n");
#endif
	  m->m_nextpkt = 0;

	  if (!appletalk_inited) {
		m_freem(m);
		continue;
	  }

	  if ((m->m_flags & M_PKTHDR) == 0) {
#ifdef APPLETALK_DEBUG
                kprintf("atalkintr: no HDR on packet received");
#endif
		m_freem(m);
		continue;
	  }

	  /* make sure the interface this packet was received on is configured
	     for AppleTalk */
	  ifp = m->m_pkthdr.rcvif;
	  TAILQ_FOREACH(ifID, &at_ifQueueHd, aa_link) {
		if (ifID->aa_ifp && (ifID->aa_ifp == ifp)) 
			break;
	  }
	  /* if we didn't find a matching interface */
	  if (!ifID) {
		m_freem(m);
		continue; /* was EAFNOSUPPORT */
	  }

	  /* make sure the entire packet header is in the current mbuf */
	  if (m->m_len < ENET_LLC_SIZE &&
	      (m = m_pullup(m, ENET_LLC_SIZE)) == 0) {
#ifdef APPLETALK_DEBUG
		kprintf("atalkintr: packet too small\n");
#endif
		m_freem(m);
		continue;
	  }
	  enet_header = mtod(m, enet_header_t *);

	  /* Ignore multicast packets from local station */
	  /* *** Note: code for IFTYPE_TOKENTALK may be needed here. *** */
	  if (ifID->aa_ifp->if_type == IFT_ETHER) {
		bcopy((char *)enet_header->src, src, sizeof(src));

#ifdef COMMENT  /* In order to receive packets from the Blue Box, we cannot 
		   reject packets whose source address matches our local address.
		*/
		if ((enet_header->dst[0] & 1) && 
		    (bcmp(src, ifID->xaddr, sizeof(src)) == 0)) {
		  /* Packet rejected: think it's a local mcast. */
		  m_freem(m);
		  continue; /* was EAFNOSUPPORT */
		}
#endif /* COMMENT */

		llc_header = (llc_header_t *)(enet_header+1);

		/* advance the mbuf pointers past the ethernet header */
		m->m_data += ENET_LLC_SIZE;
		m->m_len -= ENET_LLC_SIZE;

		pktsIn++;

		if (LLC_PROTO_EQUAL(llc_header->protocol,snap_proto_aarp)) {
	       		(void)aarp_rcv_pkt(mtod(m, aarp_pkt_t *), ifID);
			m_freem(m);
		} 
		else if (LLC_PROTO_EQUAL(llc_header->protocol, snap_proto_ddp)) {
			/* if we're a router take all pkts */
			if (!ROUTING_MODE) {
			  if (aarp_chk_addr(mtod(m, at_ddp_t  *), ifID)
			      == AARP_ERR_NOT_OURS) {
#ifdef APPLETALK_DEBUG
			    kprintf("pat_input: Packet Rejected: not for us? dest=%x.%x.%x.%x.%x.%x LLC_PROTO= %02x%02x\n",
				    enet_header->dst[0], enet_header->dst[1], 
				    enet_header->dst[2], enet_header->dst[3], 
				    enet_header->dst[4], enet_header->dst[5], 
				    llc_header->protocol[3],
				    llc_header->protocol[4]);
#endif
			    m_freem(m);
			    continue; /* was EAFNOSUPPORT */
			  }
			}
			MCHTYPE(m, MSG_DATA); /* set the mbuf type */

			ifID->stats.rcv_packets++;
			for (m1 = m; m1; m1 = m1->m_next)
				ifID->stats.rcv_bytes += m1->m_len;

			if (!MULTIPORT_MODE)
				ddp_glean(m, ifID, src);

			ddp_input(m, ifID);
		} else {
#ifdef APPLETALK_DEBUG
		  	kprintf("pat_input: Packet Rejected: wrong LLC_PROTO = %02x%02x\n",
				llc_header->protocol[3],
				llc_header->protocol[4]);
#endif
			m_freem(m);
		}
	      }
	}
	goto next;
} /* atalkintr */
