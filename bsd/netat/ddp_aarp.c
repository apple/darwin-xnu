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
/*	Copyright (c) 1988, 1989, 1997, 1998 Apple Computer, Inc. 
 *
 *    Modified for MP, 1996 by Tuyen Nguyen
 *   Modified, March 17, 1997 by Tuyen Nguyen for MacOSX.
 */

/* at_aarp.c: 2.0, 1.17; 10/4/93; Apple Computer, Inc. */;

/* This file is at_aarp.c and it contains all the routines used by AARP. This
 * is part of the LAP layer.
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

#include <net/if.h>
#include <net/if_types.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/ddp.h>
#include <netat/at_snmp.h>
#include <netat/at_pcb.h>
#include <netat/at_var.h>
#include <netat/at_aarp.h>
#include <netat/debug.h>

#include <sys/kern_event.h>

static int	probing;
/* Following two variables are used to keep track of how many dynamic addresses
 * we have tried out at startup.
 */
int	no_of_nodes_tried;	/* no of node addresses we've tried 
				 * so far, within a network number
				 */
int	no_of_nets_tried;	/* no. of network numbers tried
				 */

struct	etalk_addr	et_zeroaddr = {
	{0, 0, 0, 0, 0, 0}};

aarp_amt_t		probe_cb;
aarp_amt_array *aarp_table[IF_TOTAL_MAX];

int aarp_init1(), aarp_init2();
int aarp_send_data();
int aarp_sched_probe();

StaticProc int aarp_req_cmd_in();
StaticProc int aarp_resp_cmd_in();
StaticProc int aarp_probe_cmd_in();
StaticProc int aarp_send_resp();
StaticProc int aarp_send_req();
StaticProc int aarp_send_probe();
StaticProc aarp_amt_t *aarp_lru_entry();
StaticProc int aarp_glean_info();
StaticProc int aarp_delete_amt_info();
StaticProc void aarp_build_pkt();
StaticProc int aarp_sched_req();
StaticProc int aarp_get_rand_node();
StaticProc int aarp_get_next_node();
StaticProc int aarp_get_rand_net();
atlock_t arpinp_lock;

extern void AARPwakeup(aarp_amt_t *);
extern int pat_output(at_ifaddr_t *, gbuf_t *, unsigned char *, int);

/****************************************************************************
 * aarp_init()
 *
 ****************************************************************************/

int aarp_init1(elapp)
     register at_ifaddr_t	*elapp;
{
	elapp->ifThisNode.s_net = 0;
	elapp->ifThisNode.s_node = 0;

	if (probing != PROBE_TENTATIVE)	/* How do I set the initial probe */
		probing = PROBE_IDLE;	/* state ???*/
	else {
		dPrintf(D_M_AARP,D_L_ERROR, 
			("aarp_init: error :probing == PROBE_TENTATIVE\n"));
		return(-1);
	}

	/* pick a random addr or start with what we have from initial_node addr */
	if (elapp->initial_addr.s_net == 0 && elapp->initial_addr.s_node == 0) {
		dPrintf(D_M_AARP, D_L_INFO, 
			("aarp_init: pick up a new node number\n"));
		aarp_get_rand_node(elapp);
		aarp_get_rand_net(elapp);
	}
	probe_cb.elapp = elapp;
	probe_cb.no_of_retries = 0;
	probe_cb.error = 0;

	no_of_nodes_tried = 0; /* haven't tried any addresses yet */
	no_of_nets_tried = 0;

	if (aarp_send_probe() == -1) {
		probing = PROBE_IDLE;	/* not probing any more */
		dPrintf(D_M_AARP, D_L_ERROR, 
			("aarp_init: aarp_send_probe returns error\n"));
		return(-1);
	}
	return(ENOTREADY);
}

int aarp_init2(elapp)
     register at_ifaddr_t	*elapp;
{
	if (probe_cb.error != 0) {
		probing = PROBE_IDLE;	/* not probing any more */
		dPrintf(D_M_AARP, D_L_ERROR,
			("aarp_init: probe_cb.error creates error =%d\n", 
			 probe_cb.error));
		return(-1);
	}

	if (aarp_table[elapp->ifPort])
		bzero ((caddr_t)&aarp_table[elapp->ifPort]->et_aarp_amt[0], 
		       sizeof(aarp_amt_array));
	else
		return(-1);

	elapp->ifThisNode = elapp->initial_addr;
	probing = PROBE_DONE;
	
	/* AppleTalk was successfully started up. Send event with node and net. */
	atalk_post_msg(elapp->aa_ifp, KEV_ATALK_ENABLED, &(elapp->ifThisNode), 0);
	
	/* Set global flag */
	at_state.flags |= AT_ST_STARTED;
	
	return(0);
}

/****************************************************************************
 * aarp_rcv_pkt()
 *
 * remarks :
 *	(1) The caller must take care of freeing the real storage (gbuf)
 *	(2) The incoming packet is of the form {802.3, 802.2, aarp}.
 *
 ****************************************************************************/
int aarp_rcv_pkt(pkt, elapp)
     aarp_pkt_t *pkt;
     at_ifaddr_t *elapp;
{
	switch (pkt->aarp_cmd) {
	case AARP_REQ_CMD:
		return (aarp_req_cmd_in (pkt, elapp));
	case AARP_RESP_CMD:
		return (aarp_resp_cmd_in (pkt, elapp));
	case AARP_PROBE_CMD:
		return (aarp_probe_cmd_in (pkt, elapp));
	default:
		return (-1);
	}/* end of switch*/
}

/****************************************************************************
 *  aarp_req_cmd_in()
 *
 ****************************************************************************/
StaticProc   int	aarp_req_cmd_in (pkt, elapp)
aarp_pkt_t		*pkt;
at_ifaddr_t	*elapp;
{
/*
	kprintf("aarp_req_cmd_in: ifThisNode=%d:%d srcNode=%d:%d dstNode=%d:%d\n",
			elapp->ifThisNode.s_net,
			elapp->ifThisNode.s_node,
			NET_VALUE(pkt->src_at_addr.atalk_net),
			pkt->src_at_addr.atalk_node,
			NET_VALUE(pkt->dest_at_addr.atalk_net),
			pkt->dest_at_addr.atalk_node);
*/
	if ((probing == PROBE_DONE) && 
	    (NET_VALUE(pkt->dest_at_addr.atalk_net) == elapp->ifThisNode.s_net) &&
	    (pkt->dest_at_addr.atalk_node == elapp->ifThisNode.s_node)) {
		if (aarp_send_resp(elapp, pkt) == -1)
			return(-1);
	}
	/* now to glean some info */
	aarp_glean_info(pkt, elapp);
	return (0);
}



/****************************************************************************
 *  aarp_resp_cmd_in()
 *
 ****************************************************************************/
StaticProc int aarp_resp_cmd_in (pkt, elapp)
     aarp_pkt_t		*pkt;
     at_ifaddr_t	*elapp;
{
	register aarp_amt_t	*amt_ptr;
	gbuf_t		        *m;

	switch (probing) {
	case PROBE_TENTATIVE :
		if ((NET_VALUE(pkt->src_at_addr.atalk_net) == 
		     probe_cb.elapp->initial_addr.s_net) &&
		    (pkt->src_at_addr.atalk_node == 
		     probe_cb.elapp->initial_addr.s_node)) {

			/* this is a response to AARP_PROBE_CMD.  There's
			 * someone out there with the address we desire
			 * for ourselves.
			 */
			untimeout(aarp_sched_probe, 0);
			probe_cb.no_of_retries = 0;
			aarp_get_next_node(probe_cb.elapp);
			no_of_nodes_tried++;

			if (no_of_nodes_tried == AARP_MAX_NODES_TRIED) {
				aarp_get_rand_net(probe_cb.elapp);
				aarp_get_rand_node(probe_cb.elapp);
				no_of_nodes_tried = 0;
				no_of_nets_tried++;
			}
			if (no_of_nets_tried == AARP_MAX_NETS_TRIED) {
				/* We have tried enough nodes and nets, give up.
				 */
				probe_cb.error = EADDRNOTAVAIL;
				AARPwakeup(&probe_cb);
				return(0);
			}
			if (aarp_send_probe() == -1) {
				/* expecting aarp_send_probe to fill in 
				 * probe_cb.error
				 */
				AARPwakeup(&probe_cb);
				return(-1);
			}
		} else {
			/* hmmmm! got a response packet while still probing
			 * for AT address and the AT dest address doesn't
			 * match!!
			 * What should I do here??  kkkkkkkkk
			 */
			 return(-1);
		}
		break;

	case PROBE_DONE :
		AMT_LOOK(amt_ptr, pkt->src_at_addr, elapp);
		if (amt_ptr == NULL)
			return(-1);
		if (amt_ptr->tmo) {
		  	untimeout(aarp_sched_req, amt_ptr);
			amt_ptr->tmo = 0;
		}

		if (amt_ptr->m == NULL) {
			/* this may be because of a belated response to 
			 * aarp reaquest.  Based on an earlier response, we
			 * might have already sent the packet out, so 
			 * there's nothing to send now.  This is okay, no 
			 * error.
			 */
			return(0);
		}
		amt_ptr->dest_addr = pkt->src_addr;
		if (FDDI_OR_TOKENRING(elapp->aa_ifp->if_type))
			ddp_bit_reverse(&amt_ptr->dest_addr);
		m = amt_ptr->m;
		amt_ptr->m = NULL;
		pat_output(amt_ptr->elapp, m,
			   (unsigned char *)&amt_ptr->dest_addr, 0);
		break;
	default :
		/* probing in a weird state?? */
		return(-1);
	}
	return(0);
}



/****************************************************************************
 *  aarp_probe_cmd_in()
 *
 ****************************************************************************/
StaticProc   int	aarp_probe_cmd_in (pkt, elapp)
register aarp_pkt_t	*pkt;
at_ifaddr_t	*elapp;
{
	register aarp_amt_t	*amt_ptr;

	switch (probing) {
	case PROBE_TENTATIVE :
		if ((elapp == probe_cb.elapp) &&
		    (NET_VALUE(pkt->src_at_addr.atalk_net) == 
		     probe_cb.elapp->initial_addr.s_net) &&
		    (pkt->src_at_addr.atalk_node == 
		     probe_cb.elapp->initial_addr.s_node)) {
			/* some bozo is probing for address I want... and I 
			 * can't tell him to shove off!
			 */
			untimeout(aarp_sched_probe, 0);
			probe_cb.no_of_retries = 0;
			aarp_get_next_node(probe_cb.elapp);
			no_of_nodes_tried++;

			if (no_of_nodes_tried == AARP_MAX_NODES_TRIED) {
				aarp_get_rand_net(probe_cb.elapp);
				aarp_get_rand_node(probe_cb.elapp);
				no_of_nodes_tried = 0;
				no_of_nets_tried++;
			}
			if (no_of_nets_tried == AARP_MAX_NETS_TRIED) {
				/* We have tried enough nodes and nets, give up.
				 */
				probe_cb.error = EADDRNOTAVAIL;
				AARPwakeup(&probe_cb);
				return(0);
			}
			if (aarp_send_probe() == -1) {
				/* expecting aarp_send_probe to fill in 
				 * probe_cb.error
				 */
				AARPwakeup(&probe_cb);
				return(-1);
			}
		} else {
			/* somebody's probing... none of my business yet, so
			 * just ignore the packet
			 */
			return (0);
		}
		break;

	case PROBE_DONE :
		if ((NET_VALUE(pkt->src_at_addr.atalk_net) == elapp->ifThisNode.s_net) &&
		    (pkt->src_at_addr.atalk_node == elapp->ifThisNode.s_node)) {
			if (aarp_send_resp(elapp, pkt) == -1)
				return (-1);
			return (0);
		}
		AMT_LOOK(amt_ptr, pkt->src_at_addr, elapp);

		if (amt_ptr)
		        aarp_delete_amt_info(amt_ptr);
		break;
	default :
		/* probing in a weird state?? */
		return (-1);
	}
	return (0);
}



/****************************************************************************
 *  aarp_chk_addr()
 ****************************************************************************/
int aarp_chk_addr(ddp_hdrp, elapp)
     at_ddp_t  *ddp_hdrp;
     at_ifaddr_t *elapp;
{
	if ((ddp_hdrp->dst_node == elapp->ifThisNode.s_node) &&
	    (NET_VALUE(ddp_hdrp->dst_net) == elapp->ifThisNode.s_net)) {
	        return(0);	    /* exact match in address */
		}

	if (AARP_BROADCAST(ddp_hdrp, elapp)) {
	        return(0);          /* some kind of broadcast address */
	}
	return (AARP_ERR_NOT_OURS); /* not for us */
}



/****************************************************************************
 *  aarp_send_data()
 *
 * remarks :
 *	1. The message coming in would be of the form {802.3, 802.2, ddp,...} 
 *
 *	2. The message coming in would be freed here if transmission goes 
 *	through okay. If an error is returned by aarp_send_data, the caller 
 *	can assume that	the message is not freed.  The exception to 
 *	this scenario is the prepended atalk_addr field.  This field
 * 	will ALWAYS be removed.  If the message is dropped,
 *	it's not an "error".
 *
 ****************************************************************************/

int	aarp_send_data(m, elapp, dest_at_addr, loop)
     register gbuf_t	*m;
     register at_ifaddr_t  *elapp;
     struct  atalk_addr	   *dest_at_addr;
     int		loop;			/* if true, loopback broadcasts */
{
	register aarp_amt_t	*amt_ptr;
	register at_ddp_t	*ddp_hdrp;
	int			error;
	int s;

	if (gbuf_len(m) <= 0)
		ddp_hdrp = (at_ddp_t *)gbuf_rptr(gbuf_cont(m));
	else
		ddp_hdrp = (at_ddp_t *)gbuf_rptr(m);

	if ((ddp_hdrp->dst_node == ddp_hdrp->src_node) &&
	    (NET_VALUE(ddp_hdrp->dst_net)  == NET_VALUE(ddp_hdrp->src_net))) {
	        /*
		 * we're sending to ourselves
		 * so loop it back upstream
		 */
		ddp_input(m, elapp);
		return(0);
	}
	ATDISABLE(s, arpinp_lock);
	AMT_LOOK(amt_ptr, *dest_at_addr, elapp);


	if (amt_ptr) {
	        if (amt_ptr->m) {
		        /*
			 * there's already a packet awaiting transmission, so
			 * drop this one and let the upper layer retransmit
			 * later.
			 */
			ATENABLE(s, arpinp_lock);
		        gbuf_freel(m);
			return (0);
		}
		ATENABLE(s, arpinp_lock);
		return (pat_output(elapp, m,
				   (unsigned char *)&amt_ptr->dest_addr, 0));
        }
	/*
	 * either this is a packet to be broadcasted, or the address
	 * resolution needs to be done
	 */
	if (AARP_BROADCAST(ddp_hdrp, elapp)) {
	        gbuf_t	             *newm = 0;
		struct	etalk_addr   *dest_addr;

		ATENABLE(s, arpinp_lock);
		dest_addr =  &elapp->cable_multicast_addr;
		if (loop)
			newm = (gbuf_t *)gbuf_dupm(m);

		if ( !(error = pat_output(elapp, m,
					  (unsigned char *)dest_addr, 0))) { 
			/*
			 * The message transmitted successfully;
			 * Also loop a copy back up since this
			 * is a broadcast message.
			 */
			if (loop) {
				if (newm == NULL)
				        return (error);
				ddp_input(newm, elapp);
			} /* endif loop */
		} else {
		        if (newm)
			        gbuf_freem(newm);
		}
		return (error);
	}
	NEW_AMT(amt_ptr, *dest_at_addr,elapp);

        if (amt_ptr->m) {
	        /*
		 * no non-busy slots available in the cache, so
		 * drop this one and let the upper layer retransmit
		 * later.
		 */
		ATENABLE(s, arpinp_lock);
	        gbuf_freel(m);
		return (0);
	}
	amt_ptr->dest_at_addr = *dest_at_addr;
	amt_ptr->dest_at_addr.atalk_unused = 0;

	amt_ptr->last_time = time.tv_sec;
	amt_ptr->m = m;
	amt_ptr->elapp = elapp;
	amt_ptr->no_of_retries = 0;
	ATENABLE(s, arpinp_lock);

	if ((error = aarp_send_req(amt_ptr))) {
		aarp_delete_amt_info(amt_ptr);
		return(error);
	}
	return(0);
}



/****************************************************************************
 * aarp_send_resp()
 *
 * remarks :
 *	The pkt being passed here is only to "look at".  It should neither
 *	be used for transmission, nor freed.  Its contents also must not be
 *	altered.
 *
 ****************************************************************************/
StaticProc   int	aarp_send_resp(elapp, pkt)
     register at_ifaddr_t   *elapp;
     aarp_pkt_t		    *pkt;
{
	register aarp_pkt_t	*new_pkt;
	register gbuf_t		*m;

	if ((m = gbuf_alloc(AT_WR_OFFSET+sizeof(aarp_pkt_t), PRI_MED)) == NULL) {
		return (-1);
	}
	gbuf_rinc(m,AT_WR_OFFSET);
	gbuf_wset(m,0);

	new_pkt = (aarp_pkt_t *)gbuf_rptr(m);
	aarp_build_pkt(new_pkt, elapp);

	new_pkt->aarp_cmd = AARP_RESP_CMD;
	new_pkt->dest_addr =  pkt->src_addr;

	new_pkt->dest_at_addr = pkt->src_at_addr;
	new_pkt->dest_at_addr.atalk_unused = 0;

	ATALK_ASSIGN(new_pkt->src_at_addr, elapp->ifThisNode.s_net,
		     elapp->ifThisNode.s_node, 0);

	gbuf_winc(m,sizeof(aarp_pkt_t));
	if (FDDI_OR_TOKENRING(elapp->aa_ifp->if_type))
		ddp_bit_reverse(&new_pkt->dest_addr);

	if (pat_output(elapp, m, (unsigned char *)&new_pkt->dest_addr,
		       AARP_AT_TYPE))
	        return(-1);
	return(0);
}



/****************************************************************************
 * aarp_send_req()
 *
 ****************************************************************************/

StaticProc   int	aarp_send_req (amt_ptr)
register aarp_amt_t 	*amt_ptr;
{
	register aarp_pkt_t  *pkt;
	register gbuf_t	     *m;
	int	             error;

	if ((m = gbuf_alloc(AT_WR_OFFSET+sizeof(aarp_pkt_t), PRI_MED)) == NULL) {
		return (ENOBUFS);
	}
	gbuf_rinc(m,AT_WR_OFFSET);
	gbuf_wset(m,0);

	pkt = (aarp_pkt_t *)gbuf_rptr(m);
	aarp_build_pkt(pkt, amt_ptr->elapp);

	pkt->aarp_cmd = AARP_REQ_CMD;
	pkt->dest_addr = et_zeroaddr;
	pkt->dest_at_addr = amt_ptr->dest_at_addr;
	pkt->dest_at_addr.atalk_unused = 0;
	ATALK_ASSIGN(pkt->src_at_addr, amt_ptr->elapp->ifThisNode.s_net,
		     amt_ptr->elapp->ifThisNode.s_node, 0);
	gbuf_winc(m,sizeof(aarp_pkt_t));
	
	amt_ptr->no_of_retries++;
	timeout(aarp_sched_req, amt_ptr, AARP_REQ_TIMER_INT);
	amt_ptr->tmo = 1;
	error = pat_output(amt_ptr->elapp, m,
			   (unsigned char *)&amt_ptr->elapp->cable_multicast_addr, AARP_AT_TYPE);
	if (error)
	{
		untimeout(aarp_sched_req, amt_ptr);
		amt_ptr->tmo = 0;
		return(error);
	}

	return(0);
}



/****************************************************************************
 * aarp_send_probe()
 *
 ****************************************************************************/
StaticProc  int	aarp_send_probe()
{
	register aarp_pkt_t  *pkt;
	register gbuf_t	     *m;

	if ((m = gbuf_alloc(AT_WR_OFFSET+sizeof(aarp_pkt_t), PRI_MED)) == NULL) {
		probe_cb.error = ENOBUFS;
		return (-1);
	}
	gbuf_rinc(m,AT_WR_OFFSET);
	gbuf_wset(m,0);
	pkt = (aarp_pkt_t *)gbuf_rptr(m);
	aarp_build_pkt(pkt, probe_cb.elapp);

	pkt->aarp_cmd = AARP_PROBE_CMD;
	pkt->dest_addr = et_zeroaddr;

	ATALK_ASSIGN(pkt->src_at_addr, probe_cb.elapp->initial_addr.s_net,
		     probe_cb.elapp->initial_addr.s_node, 0);

	ATALK_ASSIGN(pkt->dest_at_addr, probe_cb.elapp->initial_addr.s_net,
		     probe_cb.elapp->initial_addr.s_node, 0);

	gbuf_winc(m,sizeof(aarp_pkt_t));

	probe_cb.error = pat_output(probe_cb.elapp, m,
		(unsigned char *)&probe_cb.elapp->cable_multicast_addr, AARP_AT_TYPE);
	if (probe_cb.error) {
		return(-1);
	}

	probing = PROBE_TENTATIVE;
	probe_cb.no_of_retries++;
	timeout(aarp_sched_probe, 0, AARP_PROBE_TIMER_INT);

	return(0);
}



/****************************************************************************
 * aarp_lru_entry()
 *
 ****************************************************************************/

StaticProc   aarp_amt_t	*aarp_lru_entry(at)
register aarp_amt_t	*at;
{
	register aarp_amt_t  *at_ret;
	register int	     i;

	at_ret = at;

	for (i = 1, at++; i < AMT_BSIZ; i++, at++) {
		if (at->last_time < at_ret->last_time && (at->m == NULL))
			at_ret = at;
	}
        return(at_ret);
}



/****************************************************************************
 * aarp_glean_info()
 *
 ****************************************************************************/

StaticProc   int	aarp_glean_info(pkt, elapp)
register aarp_pkt_t	*pkt;
at_ifaddr_t	*elapp;
{
    register aarp_amt_t   *amt_ptr;
	int s;

	ATDISABLE(s, arpinp_lock);
	AMT_LOOK(amt_ptr, pkt->src_at_addr, elapp);

	if (amt_ptr == NULL) {
	        /*
		 * amt entry for this address doesn't exist, add it to the cache
	         */
		NEW_AMT(amt_ptr, pkt->src_at_addr,elapp); 

		if (amt_ptr->m)
		{
		ATENABLE(s, arpinp_lock);
		        return(0);     /* no non-busy slots available in the cache */
		}
		amt_ptr->dest_at_addr = pkt->src_at_addr;
		amt_ptr->dest_at_addr.atalk_unused = 0;

		amt_ptr->last_time = (int)random();
	}
	/*
	 * update the ethernet address
	 * in either case
	 */
	amt_ptr->dest_addr = pkt->src_addr;
	if (FDDI_OR_TOKENRING(elapp->aa_ifp->if_type))
		ddp_bit_reverse(&amt_ptr->dest_addr);
	ATENABLE(s, arpinp_lock);
	return(1);
}


/****************************************************************************
 * aarp_delete_amt_info()
 *
 ****************************************************************************/

StaticProc   int	aarp_delete_amt_info(amt_ptr)
register aarp_amt_t	*amt_ptr;
{
	register s;
	register gbuf_t		*m;
	ATDISABLE(s, arpinp_lock);
	amt_ptr->last_time = 0;
	ATALK_ASSIGN(amt_ptr->dest_at_addr, 0, 0, 0);
	amt_ptr->no_of_retries = 0;

	if (amt_ptr->m) {
	    m = amt_ptr->m;
	    amt_ptr->m = NULL;    
 	    ATENABLE(s, arpinp_lock);
	    gbuf_freel(m);
        }
	else
		ATENABLE(s, arpinp_lock);
	return(0);
}



/****************************************************************************
 * aarp_sched_probe()
 *
 ****************************************************************************/

int  aarp_sched_probe()
{
	boolean_t 	funnel_state;

	funnel_state = thread_funnel_set(network_flock, TRUE);

	if (probe_cb.no_of_retries != AARP_MAX_PROBE_RETRIES) {
		if (aarp_send_probe() == -1)
			AARPwakeup(&probe_cb);
	} else {
		probe_cb.error = 0;
		AARPwakeup(&probe_cb);
	}

	(void) thread_funnel_set(network_flock, FALSE);
	return(0);
}



/****************************************************************************
 * aarp_build_pkt()
 *
 ****************************************************************************/

StaticProc void aarp_build_pkt(pkt, elapp)
     register aarp_pkt_t *pkt;
     at_ifaddr_t *elapp;
{
	pkt->hardware_type = AARP_ETHER_HW_TYPE;
	pkt->stack_type = AARP_AT_PROTO;
	pkt->hw_addr_len = ETHERNET_ADDR_LEN;
	pkt->stack_addr_len = AARP_AT_ADDR_LEN;
	bcopy(elapp->xaddr, pkt->src_addr.etalk_addr_octet, sizeof(elapp->xaddr));
	if (FDDI_OR_TOKENRING(elapp->aa_ifp->if_type))
		ddp_bit_reverse(pkt->src_addr.etalk_addr_octet);
}

/****************************************************************************
 * aarp_sched_req()
 *
 ****************************************************************************/

StaticProc int	aarp_sched_req(amt_ptr)
     register aarp_amt_t *amt_ptr;
{
	int s, i;
	boolean_t 	funnel_state;

	funnel_state = thread_funnel_set(network_flock, TRUE);

	/*
	 * make sure pointer still valid in case interface removed
	 * while trying to acquire the funnel. make sure it points
	 * into one of the amt arrays.
	 */
	for (i = 0; i < IF_TOTAL_MAX; i++) {
	    if (aarp_table[i] == NULL || amt_ptr < aarp_table[i] || amt_ptr >= (aarp_table[i] + 1))
	        continue;  /* no match - try next entry */
		
	    /*
	     * found match - pointer is valid
	     */
	    ATDISABLE(s, arpinp_lock);
	    if (amt_ptr->tmo == 0) {
	        ATENABLE(s, arpinp_lock);
	        (void) thread_funnel_set(network_flock, FALSE);
	        return(0);
	    }
	    if (amt_ptr->no_of_retries < AARP_MAX_REQ_RETRIES) {
	        ATENABLE(s, arpinp_lock);
	        if (aarp_send_req(amt_ptr) == 0) {
	            (void) thread_funnel_set(network_flock, FALSE);
	            return(0);
	        }
	        ATDISABLE(s, arpinp_lock);
	    }
	    ATENABLE(s, arpinp_lock);
	    aarp_delete_amt_info(amt_ptr);
	    break;
	}	
	(void) thread_funnel_set(network_flock, FALSE);

	return(0);
}



/****************************************************************************
 * aarp_get_rand_node()
 *
 ****************************************************************************/
StaticProc   int	aarp_get_rand_node(elapp)
at_ifaddr_t	*elapp;
{
	register u_char	node;

	/*
	 * generate a starting node number in the range 1 thru 0xfd.
	 * we use this as the starting probe point for a given net
	 * To generate a different node number each time we call
         * aarp_get_next_node
	 */
	node = ((u_char)(random() & 0xff)) % 0xfd + 2;
	
	elapp->initial_addr.s_node = node;
	return(0);
}



StaticProc   int	aarp_get_next_node(elapp)
at_ifaddr_t	*elapp;
{
	register u_char	node = elapp->initial_addr.s_node;

	/*
	 * return the next node number in the range 1 thru 0xfd.
	 */
	node = (node == 0xfd) ? (1) : (node+1);

	elapp->initial_addr.s_node = node;
	return(0);
}





/****************************************************************************
 * aarp_get_rand_net()
 *
 ****************************************************************************/
StaticProc   int	aarp_get_rand_net(elapp)
register at_ifaddr_t	*elapp;
{
	register at_net_al	 last_net, new_net;

	if (elapp->ifThisCableStart) {
		last_net = elapp->initial_addr.s_net;
		/*
		 * the range of network numbers valid for this
		 * cable is known.  Try to choose a number from
		 * this range only.  
		 */
		new_net= ((at_net_al)random() & 0xffff);
		/* two-byte random number generated... now fit it in 
		 * the prescribed range 
		 */
		new_net = new_net % (unsigned) (elapp->ifThisCableEnd - 
				     elapp->ifThisCableStart + 1)
			  + elapp->ifThisCableStart;

		if (new_net == last_net) {
		        if (new_net == elapp->ifThisCableEnd)
			        new_net = elapp->ifThisCableStart;
			else
			        new_net++;
		}
		elapp->initial_addr.s_net = new_net;
	} else {
		/* The range of valid network numbers for this cable
		 * is not known... choose a network number from
		 * startup range.
		 */
		last_net = (elapp->initial_addr.s_net & 0x00ff);
		new_net = (at_net_al)random() & 0x00ff;

		if (new_net == last_net)
		        new_net++;
		if (new_net == 0xff)
		        new_net = 0;
		elapp->initial_addr.s_net = (DDP_STARTUP_LOW | new_net);
	}
	return(0);
}


int getAarpTableSize(elapId)
     int	elapId;			/* elap_specifics array index (should be
					 * changed when we add a non-ethernet type
					 * of I/F to the mix. Unused for now.
					 */
{
	return(AMTSIZE);
}

int getPhysAddrSize(elapId)
     int	elapId;			/* elap_specifics array index (should be
					 * changed when we add a non-ethernet type
					 * of I/F to the mix. Unused for now.
					 */
{
	return(ETHERNET_ADDR_LEN);
}

#define ENTRY_SIZE 	sizeof(struct atalk_addr) + sizeof(struct etalk_addr)

snmpAarpEnt_t *getAarp(elapId)
     int		*elapId;		/* I/F table to retrieve & table
					   size entries on return */

/* gets aarp table for specified interface and builds
   a table in SNMP expected format. Returns pointer to said
   table and sets elapId to byte size of used portion of table
*/
{
	int i, cnt=0;
	aarp_amt_t *amtp;
	static snmpAarpEnt_t  snmp[AMTSIZE];
	snmpAarpEnt_t  *snmpp;


	if (*elapId <0 || *elapId >= IF_TOTAL_MAX)
		return NULL;
	
	
	for (i=0, amtp = &(aarp_table[*elapId]->et_aarp_amt[0]), snmpp = snmp;
		 i < AMTSIZE; i++,amtp++)	{

		/* last_time will be 0 if entry was never used */
		if (amtp->last_time) {
				/* copy just network & mac address.
				 * For speed, we assume that the atalk_addr
				 * & etalk_addr positions in the aarp_amt_t struct
				 * has not changed and copy both at once
				 */
			bcopy(&amtp->dest_at_addr, &snmpp->ap_ddpAddr, ENTRY_SIZE);
			snmpp++;
			cnt++;
			
		}
	}
	*elapId = cnt;
	return(snmp);
}
/*#endif *//*  COMMENTED_OUT */

