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
 *	Copyright (c) 1987, 1988, 1989 Apple Computer, Inc. 
 *
 *
 *    Modified for MP, 1996 by Tuyen Nguyen
 *    Added AURP support, April 8, 1996 by Tuyen Nguyen
 *   Modified, March 17, 1997 by Tuyen Nguyen for MacOSX.
 */

#define RESOLVE_DBG			/* define debug globals in debug.h */

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
#include <sys/protosw.h>

#include <net/if.h>
#include <net/dlil.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/at_var.h>
#include <netat/ddp.h>
#include <netat/ep.h>
#include <netat/nbp.h>
#include <netat/rtmp.h>
#include <netat/zip.h>
#include <netat/at_pcb.h>
#include <netat/routing_tables.h>
#include <netat/at_snmp.h>
#include <netat/aurp.h>
#include <netat/debug.h>
#include <netat/at_ddp_brt.h>
#include <netat/at_aarp.h>
#include <netat/adsp.h>
#include <netat/adsp_internal.h>

/* globals */

/* Queue of LAP interfaces which have registered themselves with DDP */
struct at_ifQueueHd at_ifQueueHd;

extern at_state_t at_state;
extern TAILQ_HEAD(name_registry, _nve_) name_registry;

snmpStats_t snmpStats;		/* snmp ddp & echo stats */

extern at_ddp_stats_t at_ddp_stats;	/* DDP statistics */
extern struct atpcb ddp_head;
extern at_ifaddr_t *ifID_home, *ifID_table[];
extern aarp_amt_array *aarp_table[];
extern at_ifaddr_t at_interfaces[];

/* routing mode special */
void (*ddp_AURPsendx)();
at_ifaddr_t *aurp_ifID = 0;
extern pktsIn,pktsOut;
int pktsDropped,pktsHome;
atlock_t ddpall_lock;
atlock_t ddpinp_lock;

extern int *atp_pidM;
extern int *adsp_pidM;
extern struct atpcb *atp_inputQ[];
extern CCB *adsp_inputQ[];

at_ifaddr_t *forUs(at_ddp_t *);

void ddp_input(), ddp_notify_nbp();

extern void routing_needed();
extern void ddp_brt_sweep();

struct {
	void (*func)();
} ddp_handler[256];

void init_ddp_handler()
{
	bzero(ddp_handler, sizeof(ddp_handler));
}

void add_ddp_handler(ddp_socket, input_func)
     u_char ddp_socket;
     void (*input_func)();
{
	ddp_handler[ddp_socket].func = input_func;
}

void
ddp_slowtimo()
{
	ddp_brt_sweep();
}

/*
 * Raw DDP socket option processing.
 */
int ddp_ctloutput(so, sopt)
     struct socket *so;
     struct sockopt *sopt;
{
	struct atpcb *at_pcb = sotoatpcb(so);
	int optval, error = 0;

	if (sopt->sopt_level != ATPROTO_NONE)
		return (EINVAL);

	switch (sopt->sopt_dir) {

	case SOPT_GET:
		switch (sopt->sopt_name) {
		case DDP_HDRINCL:
			optval = at_pcb->ddp_flags & DDPFLG_HDRINCL;
			error = sooptcopyout(sopt, &optval, sizeof optval);
			break;
		case DDP_CHKSUM_ON:
			optval = at_pcb->ddp_flags & DDPFLG_CHKSUM;
			error = sooptcopyout(sopt, &optval, sizeof optval);
			break;
		case DDP_STRIPHDR:
			optval = at_pcb->ddp_flags & DDPFLG_STRIPHDR;
			error = sooptcopyout(sopt, &optval, sizeof optval);
			break;
		case DDP_SLFSND_ON:
			optval = at_pcb->ddp_flags & DDPFLG_SLFSND;
			error = sooptcopyout(sopt, &optval, sizeof optval);
			break;
		case DDP_GETSOCKNAME:
		  {
		  	ddp_addr_t addr;
			addr.inet.net = at_pcb->laddr.s_net;
			addr.inet.node = at_pcb->laddr.s_node;
			addr.inet.socket = at_pcb->lport;
			addr.ddptype = at_pcb->ddptype;
			error = sooptcopyout(sopt, &addr, sizeof addr);
		  }
			break;
                default:
			error = ENOPROTOOPT;
			break;
		}
		break;
	case SOPT_SET:
		switch (sopt->sopt_name) {
		case DDP_HDRINCL:
			error = sooptcopyin(sopt, &optval, sizeof optval,
					    sizeof optval);
			if (error)
				break;
			if (optval)
				at_pcb->ddp_flags |= DDPFLG_HDRINCL;
			else
				at_pcb->ddp_flags &= ~DDPFLG_HDRINCL;
			break;
		case DDP_CHKSUM_ON:
			error = sooptcopyin(sopt, &optval, sizeof optval,
					    sizeof optval);
			if (error)
				break;
			if (optval)
				at_pcb->ddp_flags |= DDPFLG_CHKSUM;
			else
				at_pcb->ddp_flags &= ~DDPFLG_CHKSUM;
			break;
		case DDP_STRIPHDR:
			error = sooptcopyin(sopt, &optval, sizeof optval,
					    sizeof optval);
			if (error)
				break;
			if (optval)
				at_pcb->ddp_flags |= DDPFLG_STRIPHDR;
			else
				at_pcb->ddp_flags &= ~DDPFLG_STRIPHDR;
			break;
		case DDP_SLFSND_ON:
			error = sooptcopyin(sopt, &optval, sizeof optval,
					    sizeof optval);
			if (error)
				break;
			if (optval)
				at_pcb->ddp_flags |= DDPFLG_SLFSND;
			else
				at_pcb->ddp_flags &= ~DDPFLG_SLFSND;
			break;
                default:
			error = ENOPROTOOPT;
			break;
		}
		break;
	}

	return(error);
} /* ddp_cloutput */

/****************************************************************/
/*								*/
/*								*/
/*			Support Routines			*/
/*								*/
/*								*/
/****************************************************************/

/*
 * Name:
 * 	ddp_checksum
 *
 * Description:
 *	This procedure determines the checksum of an extended DDP datagram.
 *      Add the unsigned bytes into an unsigned 16-bit accumulator.
 *      After each add, rotate the sign bit into the low order bit of
 *      the accumulator. When done, if the checksum is 0, changed into 0xFFFF.
 *
 * Calling sequence:
 *	checksum = ddp_checksum(mp, offset)
 *
 * Parameters:
 *	mp		pointer to the datagram gbuf_t
 *	offset		offset to start at in first gbuf_t block
 *
 * Return value:
 *	The DDP checksum.
 *
 */

u_short ddp_checksum(mp, offset)
     register gbuf_t	*mp;
     register int	offset;
{
	register u_char	*data;
	register int   	 length;
	register u_short checksum;

	checksum = 0;

	do {
		if (offset >= gbuf_len(mp))
			offset -= gbuf_len(mp);
		else {
			data = ((unsigned char *) gbuf_rptr(mp)) + offset;
			length = gbuf_len(mp) - offset;
			offset = 0;
			/* Portable checksum from 3.0 */
		   	while (length--) {
				checksum += *data++;
				checksum = (checksum & 0x8000) ?
					((checksum << 1) | 1) : (checksum << 1);
			}
		}
	} while ( (mp = gbuf_cont(mp)) );

	if (checksum == 0)
		checksum = 0xffff;

	return(checksum);
}

/*
 * ddp_add_if()
 *
 * Description:
 *	This procedure is called by each LAP interface when it wants to place
 *	itself online.  The LAP interfaces passes in a pointer to its at_if
 *	struct, which is added to DDP's list of active interfaces (at_ifQueueHd).
 *	When DDP wants to transmit a packet, it searches this list for the 
 *	interface to use.
 *	
 *	If AT_IFF_DEFAULT is set, then this interface is to be brought online
 *	as the interface DDP socket addresses are tied to.  Of course there can
 *	be only one default interface; we return an error if it's already set. 
 *
 * Calling Sequence:
 *	ret_status = ddp_add_if(ifID)
 *
 * Formal Parameters:
 *	ifID		pointer to LAP interface's at_if struct.
 *
 * Completion Status:
 *	0		Procedure successfully completed.
 *	EALREADY	This interface is already online, or there is
 *			already a default interface.
 *	ENOBUFS		Cannot allocate input queue
 *
 */
int ddp_add_if(ifID)
register at_ifaddr_t	*ifID;
{
	int port = -1;

	dPrintf(D_M_DDP, D_L_STARTUP, 
		("ddp_add_if: called, ifID:0x%x\n", (u_int) ifID));

	if (ifID->ifFlags & AT_IFF_DEFAULT) {
		if (ifID_home)
			return(EEXIST);    /* home port already set */ 
		else {
			port = IFID_HOME;
			ifID_home = ifID;
		}
	} else {
		for (port=IFID_HOME+1; port<IF_TOTAL_MAX; port++)
			if (!ifID_table[port]) {
				break;
		}
		if (port == IF_TOTAL_MAX)	/* no space left */
			return(ENOMEM);
	}

	/* allocate an et_aarp_amt structure */
	if ((aarp_table[port] = 
	     (aarp_amt_array *)_MALLOC(sizeof(aarp_amt_array),
				       M_RTABLE, M_WAITOK)) == NULL)
		return(ENOMEM);

	dPrintf(D_M_DDP, D_L_STARTUP, ("ddp:adding ifID_table[%d]\n", port));
		
	/* add i/f to port list */
	ifID_table[port] = ifID;
	ifID->ifPort = port;	/* set ddp port # in ifID */

	/* Add this interface to the list of online interfaces */
	TAILQ_INSERT_TAIL(&at_ifQueueHd, ifID, aa_link);
	
	return (0);
} /* ddp_add_if */

/*
 * ddp_rem_if()
 *
 * Description:
 *	This procedure is called by each LAP interface when it wants to take
 *	itself offline.  The LAP interfaces passes in a pointer to its at_if
 *	struct; DDP's list of active interfaces (at_ifQueueHd) is searched and
 *	this interface is removed from the list.  DDP can still transmit 
 *	packets as long as this interface is not the default interface; the
 *	sender will just get ENETUNREACH errors when it tries to send to an
 *	interface that went offline.  However, if the default interface is
 *	taken offline, we no longer have a node ID to use as a source address
 * 	and DDP must return ENETDOWN when a caller tries to send a packet.
 *	
 * Formal Parameters:
 *	ifID		pointer to LAP interface's at_if struct.
 */

void  ddp_rem_if(ifID)
     register at_ifaddr_t	*ifID;
{
	struct ifaddr *ifa = &ifID->aa_ifa;

	/* un-do processing done in SIOCSIFADDR */
	if (ifa->ifa_addr) {
		int s = splnet();
		TAILQ_REMOVE(&ifID->aa_ifp->if_addrhead, ifa, ifa_link);
		ifa->ifa_addr = NULL;
		splx(s);
	}
	if (ifID->at_dl_tag) {
/*		dlil_detach_protocol(ifID->at_dl_tag); */
		ether_detach_at(ifID->aa_ifp);
		ifID->at_dl_tag = 0;
	}

	/* un-do processing done in ddp_add_if() */
	if (ifID->ifPort) {
		if (aarp_table[ifID->ifPort]) {
			FREE(aarp_table[ifID->ifPort], M_RTABLE);
			aarp_table[ifID->ifPort] = NULL;
		}

		at_state.flags |= AT_ST_IF_CHANGED;
		ifID->aa_ifp = NULL;

		trackrouter_rem_if(ifID);
		TAILQ_REMOVE(&at_ifQueueHd, ifID, aa_link);
		ifID_table[ifID->ifPort] = NULL;
		ifID->ifName[0] = '\0';
		ifID->ifPort = 0;
	}

	/* *** deallocate ifID, eventually *** */
} /* ddp_rem_if */

/*
 * The user may have registered an NVE with the NBP on a socket.  When the
 * socket is closed, the NVE should be deleted from NBP's name table.  The
 * user should delete the NVE before the socket is shut down, but there
 * may be circumstances when he can't.  So, whenever a DDP socket is closed,
 * this routine is used to notify NBP of the socket closure.  This would
 * help NBP get rid of all NVE's registered on the socket.
 */

/* *** Do we still need to do this? *** */
int ot_ddp_check_socket(socket, pid)
     unsigned char socket;
     int pid;
{
	int cnt = 0;
	gref_t *gref;

	dPrintf(D_M_DDP, D_L_INFO, ("ot_ddp_check_socket: %d\n", socket));
	for (gref = ddp_head.atpcb_next; gref != &ddp_head; gref = gref->atpcb_next)
		if (gref->lport == socket && gref->pid == pid)
		     cnt++;
	if ((atp_inputQ[socket] != NULL) && (atp_inputQ[socket] != (gref_t *)1)
	    && (atp_pidM[socket] == pid))
		cnt++;
	if ((adsp_inputQ[socket] != NULL) && (adsp_pidM[socket] == pid))
		cnt++;

	return(cnt);
}

void ddp_notify_nbp(socket, pid, ddptype)
     unsigned char socket;
     int pid;
     unsigned char ddptype; /* not used */
{
	extern int nve_lock;
	nve_entry_t *nve_entry;

	if (at_state.flags & AT_ST_STARTED) {
		/* *** NBP_CLOSE_NOTE processing (from ddp_nbp.c) *** */
   		ATDISABLE(nve_lock, NVE_LOCK);
		TAILQ_FOREACH(nve_entry, &name_registry, nve_link) {
			if ((at_socket)socket == nve_entry->address.socket &&
			    /* *** check complete address and ddptype here *** */
			    pid == nve_entry->pid &&
			    ot_ddp_check_socket(nve_entry->address.socket,
						nve_entry->pid) < 2) {
				nbp_delete_entry(nve_entry);
			}
		}
		ATENABLE(nve_lock, NVE_LOCK);
	}
} /* ddp_notify_nbp */

static void fillin_pkt_chain(m)
     gbuf_t *m;
{
	gbuf_t *tmp_m = m;
	register at_ddp_t 
	  *ddp = (at_ddp_t *)gbuf_rptr(m),
	  *tmp_ddp;
	u_short tmp;

	if (UAS_VALUE(ddp->checksum)) {
		tmp = ddp_checksum(m, 4);
		UAS_ASSIGN(ddp->checksum, tmp);
	}

	for (tmp_m=gbuf_next(tmp_m); tmp_m; tmp_m=gbuf_next(tmp_m)) {
		tmp_ddp = (at_ddp_t *)gbuf_rptr(tmp_m);
		tmp_ddp->length = gbuf_msgsize(tmp_m);
		tmp_ddp->hopcount = 
		  tmp_ddp->unused = 0;
		NET_NET(tmp_ddp->src_net, ddp->src_net);
		tmp_ddp->src_node = ddp->src_node;
		tmp_ddp->src_socket = ddp->src_socket;
		if (UAS_VALUE(tmp_ddp->checksum)) {
			tmp = ddp_checksum(tmp_m, 4);
			UAS_ASSIGN(tmp_ddp->checksum, tmp);
		}
	}
}

/* There are various ways a packet may go out.... it may be sent out
 * directly to destination node, or sent to a random router or sent
 * to a router whose entry exists in Best Router Cache.  Following are 
 * constants used WITHIN this routine to keep track of choice of destination
 */
#define DIRECT_ADDR	1
#define	BRT_ENTRY	2
#define	BRIDGE_ADDR	3

/* 
 * ddp_output()
 *
 * Remarks : 
 *	Called to queue a atp/ddp data packet on the network interface.
 *	It returns 0 normally, and an errno in case of error.
 *	The mbuf chain pointed to by *mp is consumed on success, and
 *		freed in case of error.
 *
 */
int ddp_output(mp, src_socket, src_addr_included)
     register gbuf_t	**mp;
     at_socket	src_socket;
     int src_addr_included;
{
	register at_ifaddr_t	*ifID = ifID_home, *ifIDTmp = NULL;
	register at_ddp_t	*ddp;
	register ddp_brt_t	*brt;
	register at_net_al	dst_net;
	register int 		len;
	struct	 atalk_addr	at_dest;
	at_ifaddr_t		*ARouterIf = NULL;
	int loop = 0;
	int error = 0;
	int addr_type;
	u_char	addr_flag;
	char	*addr = NULL;
	register gbuf_t	*m;

	KERNEL_DEBUG(DBG_AT_DDP_OUTPUT | DBG_FUNC_START, 0,
		     0,0,0,0);

	snmpStats.dd_outReq++;

	m = *mp;
	ddp = (at_ddp_t *)gbuf_rptr(m);

	if ((ddp->dst_socket > (unsigned) (DDP_SOCKET_LAST + 1)) || 
	    (ddp->dst_socket < DDP_SOCKET_1st_RESERVED)) {
		dPrintf(D_M_DDP, D_L_ERROR,
			("Illegal destination socket on outgoing packet (0x%x)",
			 ddp->dst_socket));
		at_ddp_stats.xmit_bad_addr++;
		error = ENOTSOCK;
		gbuf_freel(*mp);
		goto exit_ddp_output;
	}
	if ((len = gbuf_msgsize(*mp)) > DDP_DATAGRAM_SIZE) {
	        /* the packet is too large */
	        dPrintf(D_M_DDP, D_L_ERROR,
			("Outgoing packet too long (len=%d bytes)", len));
		at_ddp_stats.xmit_bad_length++;
		error = EMSGSIZE;
		gbuf_freel(*mp);
		goto exit_ddp_output;
	}
	at_ddp_stats.xmit_bytes += len;
	at_ddp_stats.xmit_packets++;

	ddp->length = len;
	ddp->hopcount = 
	  ddp->unused = 0;

	/* If this packet is for the same node, loop it back
	 * up...  Note that for LocalTalk, dst_net zero means "THIS_NET", so
	 * address 0.nn is eligible for loopback.  For Extended EtherTalk,
	 * dst_net 0 can be used only for cable-wide or zone-wide 
	 * broadcasts (0.ff) and as such, address of the form 0.nn is NOT
	 * eligible for loopback.
	 */
	dst_net = NET_VALUE(ddp->dst_net);

	/* If our packet is destined for the 'virtual' bridge
	 * address of NODE==0xFE, replace that address with a
	 * real bridge address.
	 */
	if ((ddp->dst_node == 0xfe) && 
	    ((dst_net == ATADDR_ANYNET) ||
	     (dst_net >= ifID_home->ifThisCableStart &&
	      dst_net <= ifID_home->ifThisCableEnd))) {
		/* if there's a router that's not us, it's in ifID_home */
		NET_ASSIGN(ddp->dst_net, ifID_home->ifARouter.s_net);
		dst_net = ifID_home->ifARouter.s_net;
		ddp->dst_node = ifID_home->ifARouter.s_node;
	}

	if (MULTIHOME_MODE && (ifIDTmp = forUs(ddp))) {
		ifID = ifIDTmp;
		loop = TRUE;
		dPrintf(D_M_DDP_LOW, D_L_USR1,
			("ddp_out: for us if:%s\n", ifIDTmp->ifName));
	}

	if (!loop)
		loop = ((ddp->dst_node == ifID->ifThisNode.s_node) &&
			(dst_net == ifID->ifThisNode.s_net)
			);
	if (loop) {
		gbuf_t *mdata, *mdata_next;

		if (!MULTIHOME_MODE || !src_addr_included) {
			NET_ASSIGN(ddp->src_net, ifID->ifThisNode.s_net);
			ddp->src_node = ifID->ifThisNode.s_node;
		}
		ddp->src_socket = src_socket;

		dPrintf(D_M_DDP_LOW, D_L_OUTPUT,
			("ddp_output: loop to %d:%d port=%d\n",
			  NET_VALUE(ddp->dst_net),
			  ddp->dst_node,
			  ifID->ifPort));
		
		fillin_pkt_chain(*mp);

		dPrintf(D_M_DDP, D_L_VERBOSE,
			("Looping back packet from skt 0x%x to skt 0x%x\n",
			ddp->src_socket, ddp->dst_socket));

		for (mdata = *mp; mdata; mdata = mdata_next) {
			mdata_next = gbuf_next(mdata);
			gbuf_next(mdata) = 0;
			ddp_input(mdata, ifID);
		}
		goto exit_ddp_output;
	}
        if ((ddp->dst_socket == ZIP_SOCKET) &&
	    (zip_type_packet(*mp) == ZIP_GETMYZONE)) {
	        ddp->src_socket = src_socket;
	        error = zip_handle_getmyzone(ifID, *mp);
		gbuf_freel(*mp);
		goto exit_ddp_output;
	}
	/*
	 * find out the interface on which the packet should go out
	 */
	TAILQ_FOREACH(ifID, &at_ifQueueHd, aa_link) {
		if ((ifID->ifThisNode.s_net == dst_net) || (dst_net == 0))
			/* the message is either going out (i) on the same 
			 * NETWORK in case of LocalTalk, or (ii) on the same
			 * CABLE in case of Extended AppleTalk (EtherTalk).
			 */
			break;

		if ((ifID->ifThisCableStart <= dst_net) &&
		    (ifID->ifThisCableEnd   >= dst_net)
		   )
			/* We're on EtherTalk and the message is going out to 
			 * some other network on the same cable.
			 */
			break;
		
		if (ARouterIf == NULL && ATALK_VALUE(ifID->ifARouter))
			ARouterIf = ifID;
	}
	dPrintf(D_M_DDP_LOW, D_L_USR1,
			("ddp_output: after search ifid:0x%x %s ifID_home:0x%x\n",
			(u_int)ifID, ifID ? ifID->ifName : "",
			(u_int)ifID_home));

	if (ifID) {
		/* located the interface where the packet should
		 * go.... the "first-hop" destination address
		 * must be the same as real destination address.
		 */
		addr_type = DIRECT_ADDR;
	} else {
		/* no, the destination network number does
		 * not match known network numbers.  If we have
		 * heard from this network recently, BRT table
		 * may have address of a router we could use!
		 */
		if (!MULTIPORT_MODE) {
			BRT_LOOK (brt, dst_net);
			if (brt) {
				/* Bingo... BRT has an entry for this network. 
				 * Use the link address as is.
				 */
				dPrintf(D_M_DDP, D_L_VERBOSE,
					("Found BRT entry to send to net 0x%x", dst_net));
				at_ddp_stats.xmit_BRT_used++;
				addr_type = BRT_ENTRY;
				ifID = brt->ifID;
			} else {
				/* No BRT entry available for dest network... do we 
				 * know of any router at all??
				 */
				if ((ifID = ARouterIf) != NULL)
					addr_type = BRIDGE_ADDR;
				else {
		 		dPrintf(D_M_DDP, D_L_WARNING,
						("Found no interface to send pkt"));
					at_ddp_stats.xmit_bad_addr++;
					error = ENETUNREACH;
					gbuf_freel(*mp);
					goto exit_ddp_output;
				}
			}
		}
		else { /* We are in multiport mode,  so we can bypass all the rest 
			* and directly ask for the routing of the packet
			*/ 
			at_ddp_stats.xmit_BRT_used++;

			ifID = ifID_home;
			if (!src_addr_included) {
			  ddp->src_node = ifID->ifThisNode.s_node;
			  NET_ASSIGN(ddp->src_net, ifID->ifThisNode.s_net); 
			}
			ddp->src_socket = src_socket;
			routing_needed(*mp, ifID, TRUE);

			goto exit_ddp_output;
		}
	}
	/* by the time we land here, we know the interface on 
	 * which this packet is going out....  ifID.  
	 */
	if (ifID->ifState == LAP_OFFLINE) {
		gbuf_freel(*mp);
		goto exit_ddp_output;
	} 		
	
	switch (addr_type) {
		case DIRECT_ADDR :
/*
			at_dest.atalk_unused = 0;
*/
			NET_ASSIGN(at_dest.atalk_net, dst_net);
			at_dest.atalk_node = ddp->dst_node;
			addr_flag = AT_ADDR;
			addr = (char *)&at_dest;
			break;
		case BRT_ENTRY :
			addr_flag = ET_ADDR;
			addr = (char *)&brt->et_addr;
			break;
		case BRIDGE_ADDR :
			NET_ASSIGN(at_dest.atalk_net, ifID->ifARouter.s_net);
			at_dest.atalk_node = ifID->ifARouter.s_node;
			addr_flag = AT_ADDR;
			addr = (char *)&at_dest;
			break;

	}
	/* Irrespective of the interface on which 
	 * the packet is going out, we always put the 
	 * same source address on the packet (unless multihoming mode).
	 */
	if (MULTIHOME_MODE) {
		if (!src_addr_included) {
			ddp->src_node = ifID->ifThisNode.s_node;
			NET_ASSIGN(ddp->src_net, ifID->ifThisNode.s_net); 
		}
	}
	else {
		ddp->src_node = ifID_home->ifThisNode.s_node;
		NET_ASSIGN(ddp->src_net, ifID_home->ifThisNode.s_net);
	}
	ddp->src_socket = src_socket;

	dPrintf(D_M_DDP_LOW, D_L_OUTPUT,
		("ddp_output: going out to %d:%d skt%d on %s\n",
		dst_net, ddp->dst_node, ddp->dst_socket, ifID->ifName));

	fillin_pkt_chain(*mp);

	{ /* begin block */
	struct	etalk_addr	dest_addr;
	struct	atalk_addr	dest_at_addr;
	int		loop = TRUE;		/* flag to aarp to loopback (default) */

	m = *mp;

	/* the incoming frame is of the form {flag, address, ddp...}
	 * where "flag" indicates whether the address is an 802.3
	 * (link) address, or an appletalk address.  If it's an
	 * 802.3 address, the packet can just go out to the network
	 * through PAT, if it's an appletalk address, AT->802.3 address
	 * resolution needs to be done.
	 * If 802.3 address is known, strip off the flag and 802.3
	 * address, and prepend 802.2 and 802.3 headers.
	 */
	
	if (addr == NULL) {
		addr_flag = *(u_char *)gbuf_rptr(m);
		gbuf_rinc(m,1);
	}
	
	switch (addr_flag) {
	case AT_ADDR_NO_LOOP :
		loop = FALSE;
		/* pass thru */
	case AT_ADDR :
		if (addr == NULL) {
		    dest_at_addr = *(struct atalk_addr *)gbuf_rptr(m);
		    gbuf_rinc(m,sizeof(struct atalk_addr));
		} else
		    dest_at_addr = *(struct atalk_addr *)addr;
		break;
	case ET_ADDR :
		if (addr == NULL) {
		  dest_addr = *(struct etalk_addr *)gbuf_rptr(m);
		  gbuf_rinc(m,sizeof(struct etalk_addr));
		} else
		  dest_addr = *(struct etalk_addr *)addr;
		break;
	default :
		dPrintf(D_M_DDP_LOW,D_L_ERROR,
		    ("ddp_output: Unknown addr_flag = 0x%x\n", addr_flag));
		gbuf_freel(m);		/* unknown address type, chuck it */
		goto exit_ddp_output;
        }

	m = gbuf_strip(m);

	/* At this point, rptr points to ddp header for sure */
	if (ifID->ifState == LAP_ONLINE_FOR_ZIP) {
		/* see if this is a ZIP packet that we need
		 * to let through even though network is
		 * not yet alive!!
		 */
		if (zip_type_packet(m) == 0) {
			gbuf_freel(m);
			goto exit_ddp_output;
		}
	}
	
	ifID->stats.xmit_packets++;
	ifID->stats.xmit_bytes += gbuf_msgsize(m);
	snmpStats.dd_outLong++;
	
	switch (addr_flag) {
	case AT_ADDR_NO_LOOP :
	case AT_ADDR :
	    /*
	     * we don't want elap to be looking into ddp header, so
	     * it doesn't know net#, consequently can't do 
	     * AMT_LOOKUP.  That task left to aarp now.
	     */
	    aarp_send_data(m,ifID,&dest_at_addr, loop);
	    break;
	case ET_ADDR :
	    pat_output(ifID, m, &dest_addr, 0);
	    break;
        }
	} /* end block */
 exit_ddp_output:
	KERNEL_DEBUG(DBG_AT_DDP_OUTPUT | DBG_FUNC_END, 0,
		     error, 0, 0, 0);
	return(error);
} /* ddp_output */

void ddp_input(mp, ifID)
     register gbuf_t   *mp;
     register at_ifaddr_t *ifID;
{
	register at_ddp_t *ddp;		/* DDP header */
	register int       msgsize;
	register at_socket socket;
	register int	   len;
	register at_net_al dst_net;

	KERNEL_DEBUG(DBG_AT_DDP_INPUT | DBG_FUNC_START, 0,
		     ifID, mp, gbuf_len(mp),0);

	/* Makes sure we know the default interface before starting to
	 * accept incomming packets. If we don't we may end up with a
	 * null ifID_table[0] and have impredicable results (specially
	 * in router mode. This is a transitory state (because we can
	 * begin to receive packet while we're not completly set up yet.
	 */

	if (ifID_home == (at_ifaddr_t *)NULL) {
		dPrintf(D_M_DDP, D_L_ERROR,
			("dropped incoming packet ifID_home not set yet\n"));
		gbuf_freem(mp);
		goto out; /* return */
	}

	/*
	 * if a DDP packet has been broadcast, we're going to get a copy of
	 * it here; if it originated at user level via a write on a DDP 
	 * socket; when it gets here, the first block in the chain will be
	 * empty since it only contained the lap level header which will be
	 * stripped in the lap level immediately below ddp
	 */

	if ((mp = (gbuf_t *)ddp_compress_msg(mp)) == NULL) {
		dPrintf(D_M_DDP, D_L_ERROR,
			("dropped short incoming ET packet (len %d)", 0));
		snmpStats.dd_inTotal++;
		at_ddp_stats.rcv_bad_length++;
		goto out; /* return; */
	}
	msgsize = gbuf_msgsize(mp);

	at_ddp_stats.rcv_bytes += msgsize;
	at_ddp_stats.rcv_packets++;

	/* if the interface pointer is 0, the packet has been 
	 * looped back by 'write' half of DDP.  It is of the
	 * form {extended ddp,...}.  The packet is meant to go
	 * up to some socket on the same node.
	 */
	if (!ifID)			/* if loop back is specified */
		ifID = ifID_home;	/* that means the home port */

	/* the incoming datagram has extended DDP header and is of 
	 * the form {ddp,...}.
	 */
	if (msgsize < DDP_X_HDR_SIZE) {
		dPrintf(D_M_DDP, D_L_ERROR,
			("dropped short incoming ET packet (len %d)", msgsize));
		at_ddp_stats.rcv_bad_length++;
		gbuf_freem(mp);
		goto out; /* return; */
	}
	/*
	 * At this point, the message is always of the form
	 * {extended ddp, ... }.
	 */
	ddp = (at_ddp_t *)gbuf_rptr(mp);
	len = ddp->length;

	if (msgsize != len) {
	        if ((unsigned) msgsize > len) {
		        if (len < DDP_X_HDR_SIZE) {
			        dPrintf(D_M_DDP, D_L_ERROR,
				       ("Length problems, ddp length %d, buffer length %d",
				       len, msgsize));
				snmpStats.dd_tooLong++;
				at_ddp_stats.rcv_bad_length++;
				gbuf_freem(mp);
				goto out; /* return; */
			}
		        /*
			 * shave off the extra bytes from the end of message
		         */
		        mp = ddp_adjmsg(mp, -(msgsize - len)) ? mp : 0;
		        if (mp == 0)
				goto out; /* return; */
		} else {
		        dPrintf(D_M_DDP, D_L_ERROR,
				("Length problems, ddp length %d, buffer length %d",
				len, msgsize));
				snmpStats.dd_tooShort++;
			at_ddp_stats.rcv_bad_length++;
			gbuf_freem(mp);
			goto out; /* return; */
		}
	}
	socket = ddp->dst_socket;

	/*
	 * We want everything in router mode, specially socket 254 for nbp so we need
	 * to bypass this test when we are a router.
	 */

	if (!MULTIPORT_MODE && (socket > DDP_SOCKET_LAST ||
			 socket < DDP_SOCKET_1st_RESERVED)) {
		dPrintf(D_M_DDP, D_L_WARNING,
			("Bad dst socket on incoming packet (0x%x)",
			ddp->dst_socket));
		at_ddp_stats.rcv_bad_socket++;
		gbuf_freem(mp);
		goto out; /* return; */
	}
	/*
	 * if the checksum is true, then upstream wants us to calc
	 */
	if (UAS_VALUE(ddp->checksum) && 
           (UAS_VALUE(ddp->checksum) != ddp_checksum(mp, 4))) {
		dPrintf(D_M_DDP, D_L_WARNING,
			("Checksum error on incoming pkt, calc 0x%x, exp 0x%x",
			ddp_checksum(mp, 4), UAS_VALUE(ddp->checksum)));
		snmpStats.dd_checkSum++;
		at_ddp_stats.rcv_bad_checksum++;
		gbuf_freem(mp);
		goto out; /* return; */
	}

/*############### routing input checking */

/* Router mode special: we send "up-stack" packets for this node or coming from any
 * other ports, but for the reserved atalk sockets (RTMP, ZIP, NBP [and EP])
 * BTW, the way we know it's for the router and not the home port is that the
 * MAC (ethernet) address is always the one of the interface we're on, but
 * the AppleTalk address must be the one of the home port. If it's a multicast
 * or another AppleTalk address, this is the router job's to figure out where it's
 * going to go.
 */
	/* *** a duplicate should be sent to any other client that is listening
	   for packets of this type on a raw DDP socket *** */
	if (ddp_handler[socket].func) {
		dPrintf(D_M_DDP,D_L_INPUT,
			("ddp_input: skt %d hdnlr:0x%x\n",
			 (u_int) socket, ddp_handler[socket].func));
		pktsHome++;
		snmpStats.dd_inLocal++;

		(*ddp_handler[socket].func)(mp, ifID);
		goto out; /* return; */
	}
	dst_net = NET_VALUE(ddp->dst_net);
	if (
	    /* exact match */
	    forUs(ddp) ||
	    /* any node, wildcard or matching net */
	    ((ddp->dst_node == 255) && 
	     (((dst_net >= ifID_home->ifThisCableStart) &&
	       (dst_net <= ifID_home->ifThisCableEnd)) || 
	      dst_net == 0)) ||
	    /* this node is not online yet(?) */
	    (ifID->ifRoutingState < PORT_ONLINE)
	    ) { 
		gref_t   *gref;
		pktsHome++;
		snmpStats.dd_inLocal++;

		if (ddp->type == DDP_ATP) {
		  if (atp_inputQ[socket] && (atp_inputQ[socket] != (gref_t *)1)) {
			/* if there's an ATP pcb */
			atp_input(mp);
			goto out; /* return; */
		  }
		} else if (ddp->type == DDP_ADSP) {
		  if (adsp_inputQ[socket]) {
		        /* if there's an ADSP pcb */
			adsp_input(mp);
			goto out; /* return; */
		  }
		}

		/* otherwise look for a DDP pcb;
		   ATP / raw-DDP and ADSP / raw-DDP are possible */
		for (gref = ddp_head.atpcb_next; gref != &ddp_head; 
		       gref = gref->atpcb_next)
		    if (gref->lport == socket) {
			dPrintf(D_M_DDP, D_L_INPUT, 
				("ddp_input: streamq, skt %d\n", socket));
			if (gref->atpcb_socket) {
				struct sockaddr_at ddp_in;
				ddp_in.sat_len = sizeof(ddp_in);
				ddp_in.sat_family = AF_APPLETALK;
				ddp_in.sat_addr.s_net = NET_VALUE(ddp->src_net);
				ddp_in.sat_addr.s_node = ddp->src_node;
				ddp_in.sat_port = ddp->src_socket;

				/* strip off DDP header if so indicated by
				   sockopt */
				if (gref->ddp_flags & DDPFLG_STRIPHDR) {
					mp = m_pullup((struct mbuf *)mp,
                                                           DDP_X_HDR_SIZE);
					if (mp) {
						gbuf_rinc(mp, DDP_X_HDR_SIZE);
					} else { 
					  /* this should never happen because 
					     msgsize was checked earlier */
						at_ddp_stats.rcv_bad_length++;
					 	goto out; /* return */
					}
				}

				if (sbappendaddr(&((gref->atpcb_socket)->so_rcv), 
						 (struct sockaddr *)&ddp_in,
						 mp, 0) == 0)
					gbuf_freem(mp);
				else
				 	sorwakeup(gref->atpcb_socket);
			} else {
				atalk_putnext(gref, mp);
			}
			goto out; /* return */
		    } 

		at_ddp_stats.rcv_bad_socket++;
		gbuf_freem(mp);
		snmpStats.dd_noHandler++;
		dPrintf(D_M_DDP, D_L_WARNING, 
			("ddp_input: dropped pkt for socket %d\n", socket));
	} else { 
		dPrintf(D_M_DDP, D_L_ROUTING, 
			("ddp_input: routing_needed from  port=%d sock=%d\n",
			 ifID->ifPort, ddp->dst_socket));

		snmpStats.dd_fwdReq++;
		if (((pktsIn-pktsHome+200) >= RouterMix) && ((++pktsDropped % 5) == 0)) {
			at_ddp_stats.rcv_dropped_nobuf++;
			gbuf_freem(mp);
		}
		else {
			routing_needed(mp, ifID, FALSE);
		}
	}
out:
	KERNEL_DEBUG(DBG_AT_DDP_INPUT | DBG_FUNC_END, 0,0,0,0,0);
} /* ddp_input */


/* 
 * ddp_router_output()
 *
 * Remarks : 
 *	This is a modified version of ddp_output for router use.
 *	The main difference is that the interface on which the packet needs
 *	to be sent is specified and a *destination* AppleTalk address is passed
 *	as an argument, this address may or may not be the same as the destination
 *	address found in the ddp packet... This is the trick about routing, the
 *	AppleTalk destination of the packet may not be the same as the Enet address
 *	we send the packet too (ie, we may pass the baby to another router).	
 *
 */
int ddp_router_output(mp, ifID, addr_type, router_net, router_node, enet_addr)
     gbuf_t	*mp;
     at_ifaddr_t *ifID;
     int addr_type;
     at_net_al router_net;
     at_node router_node;
     etalk_addr_t *enet_addr;
{
	register at_ddp_t	*ddp;
	struct	 atalk_addr	at_dest;
	int		addr_flag;
	char	*addr = NULL;
	register gbuf_t	*m;

	if (!ifID) {
		dPrintf(D_M_DDP, D_L_WARNING, ("BAD BAD ifID\n"));
		gbuf_freel(mp);
		return(EPROTOTYPE);
	}
	ddp = (at_ddp_t *)gbuf_rptr(mp);

	if (ifID->ifFlags & AT_IFF_AURP) { /* AURP link? */
		if (ddp_AURPsendx) {
			fillin_pkt_chain(mp);
			if (router_node == 255)
				router_node = 0;
			ddp_AURPsendx(AURPCODE_DATAPKT, mp, router_node);
			return 0;
		} else {
			gbuf_freel(mp);
			return EPROTOTYPE;
		}
	}

	/* keep some of the tests for now ####### */

	if (gbuf_msgsize(mp) > DDP_DATAGRAM_SIZE) {
	        /* the packet is too large */
		dPrintf(D_M_DDP, D_L_WARNING,
			("ddp_router_output: Packet too large size=%d\n",
			 gbuf_msgsize(mp)));
		gbuf_freel(mp);
		return (EMSGSIZE);
	}

	switch (addr_type) {

		case AT_ADDR :

			/*
			 * Check for packet destined to the home stack
			 */

		  if	((ddp->dst_node == ifID->ifThisNode.s_node) &&
			 (NET_VALUE(ddp->dst_net) == ifID->ifThisNode.s_net)) {
		  	dPrintf(D_M_DDP_LOW, D_L_ROUTING, 
				("ddp_r_output: sending back home from port=%d socket=%d\n",
				 ifID->ifPort, ddp->dst_socket));
			
			UAS_ASSIGN(ddp->checksum, 0);
			ddp_input(mp, ifID);	
			return(0);
		  }

		  NET_ASSIGN(at_dest.atalk_net, router_net);
		  at_dest.atalk_node = router_node;

		  addr_flag = AT_ADDR_NO_LOOP;
		  addr = (char *)&at_dest;
		  dPrintf(D_M_DDP_LOW, D_L_ROUTING_AT,
			  ("ddp_r_output: AT_ADDR out port=%d net %d:%d via rte %d:%d",
			   ifID->ifPort, NET_VALUE(ddp->dst_net), ddp->dst_node, router_net,
			   router_node));
		  break;

		case ET_ADDR :
		  addr_flag = ET_ADDR;
		  addr = (char *)enet_addr;
		  dPrintf(D_M_DDP_LOW, D_L_ROUTING,
			  ("ddp_r_output: ET_ADDR out port=%d net %d:%d\n",
			   ifID->ifPort, NET_VALUE(ddp->dst_net), ddp->dst_node));
		  break;
		}

	if (ifID->ifState == LAP_OFFLINE) {
	      gbuf_freel(mp);
	      return 0;
	}
	
	fillin_pkt_chain(mp);

	{ /* begin block */
	    struct	etalk_addr	dest_addr;
	    struct	atalk_addr	dest_at_addr;
	    int	loop = TRUE;		/* flag to aarp to loopback (default) */

	    m = mp;

	    /* the incoming frame is of the form {flag, address, ddp...}
	     * where "flag" indicates whether the address is an 802.3
	     * (link) address, or an appletalk address.  If it's an
	     * 802.3 address, the packet can just go out to the network
	     * through PAT, if it's an appletalk address, AT->802.3 address
	     * resolution needs to be done.
	     * If 802.3 address is known, strip off the flag and 802.3
	     * address, and prepend 802.2 and 802.3 headers.
	     */
	
	    if (addr == NULL) {
	    	addr_flag = *(u_char *)gbuf_rptr(m);
		gbuf_rinc(m,1);
	    }
	
	    switch (addr_flag) {
	    case AT_ADDR_NO_LOOP :
	      loop = FALSE;
	      /* pass thru */
	    case AT_ADDR :
	      if (addr == NULL) {
		dest_at_addr = *(struct atalk_addr *)gbuf_rptr(m);
		gbuf_rinc(m,sizeof(struct atalk_addr));
	      } else
		dest_at_addr = *(struct atalk_addr *)addr;
	      break;
	    case ET_ADDR :
	      if (addr == NULL) {
		dest_addr = *(struct etalk_addr *)gbuf_rptr(m);
		gbuf_rinc(m,sizeof(struct etalk_addr));
	      } else
		dest_addr = *(struct etalk_addr *)addr;
	      break;
	    default :
	      dPrintf(D_M_DDP_LOW,D_L_ERROR,
		      ("ddp_router_output: Unknown addr_flag = 0x%x\n", addr_flag));

	      gbuf_freel(m);		/* unknown address type, chuck it */
	      return 0;
	    }

	    m = gbuf_strip(m);

	    /* At this point, rptr points to ddp header for sure */
	    if (ifID->ifState == LAP_ONLINE_FOR_ZIP) {
		      /* see if this is a ZIP packet that we need
		       * to let through even though network is
		       * not yet alive!!
		       */
		      if (zip_type_packet(m) == 0) {
			gbuf_freel(m);
			return 0;
		      }
	    }
	
	    ifID->stats.xmit_packets++;
	    ifID->stats.xmit_bytes += gbuf_msgsize(m);
	    snmpStats.dd_outLong++;
	    
	    switch (addr_flag) {
	    case AT_ADDR_NO_LOOP :
	    case AT_ADDR :
	      /*
	       * we don't want elap to be looking into ddp header, so
	       * it doesn't know net#, consequently can't do 
	       * AMT_LOOKUP.  That task left to aarp now.
	       */
	      aarp_send_data(m,ifID,&dest_at_addr, loop);
	      break;
	    case ET_ADDR :
	      pat_output(ifID, m, &dest_addr, 0);
	      break;
	    }
	} /* end block */

	return(0);
} /* ddp_router_output */

/*****************************************/

void rt_delete(NetStop, NetStart)
	unsigned short NetStop;
	unsigned short NetStart;
{
	RT_entry *found;
	int s;

	ATDISABLE(s, ddpinp_lock);
	if ((found = rt_bdelete(NetStop, NetStart)) != 0) {
		bzero(found, sizeof(RT_entry));
		found->right = RT_table_freelist;
		RT_table_freelist = found;
	}
	ATENABLE(s, ddpinp_lock);
}

int ddp_AURPfuncx(code, param, node)
	int code;
	void *param;
	unsigned char node;
{
	extern void rtmp_timeout();
	extern void rtmp_send_port();
	at_ifaddr_t *ifID;
	int k;

	switch (code) {
	case AURPCODE_DATAPKT: /* data packet */
		if (aurp_ifID) {
			dPrintf(D_M_DDP, D_L_TRACE, ("ddp_AURPfuncx: data, 0x%x, %d\n",
				(u_int) aurp_ifID, node));

			ddp_input((gbuf_t *)param, aurp_ifID);
		} else
			gbuf_freem((gbuf_t *)param);
		break;

	case AURPCODE_REG: /* register/deregister */
		if (!ROUTING_MODE)
			return -1;
		ddp_AURPsendx = (void(*)())param;

		if (param) {
			/* register AURP callback function */
			if (aurp_ifID)
				return 0;
			for (k=(IFID_HOME+1); k < IF_TOTAL_MAX; k++) {
				if (ifID_table[k] == 0) {
					aurp_ifID = &at_interfaces[k];
					aurp_ifID->ifFlags = RTR_XNET_PORT;
					ddp_add_if(aurp_ifID);
					aurp_ifID->ifState = LAP_ONLINE;
					aurp_ifID->ifRoutingState = PORT_ONLINE;
					dPrintf(D_M_DDP, D_L_TRACE,
						("ddp_AURPfuncx: on, 0x%x\n",
						(u_int) aurp_ifID));

					ddp_AURPsendx(AURPCODE_DEBUGINFO,
							&dbgBits, aurp_ifID->ifPort);
					return 0;
				}
			}
			return -1;

		} else {
			/* deregister AURP callback function */
			if (aurp_ifID) {
				rtmp_purge(aurp_ifID);
				ddp_rem_if(aurp_ifID);
				aurp_ifID->ifState = LAP_OFFLINE;
				aurp_ifID->ifRoutingState = PORT_OFFLINE;
				dPrintf(D_M_DDP, D_L_TRACE,
					("ddp_AURPfuncx: off, 0x%x\n", (u_int) aurp_ifID));
				aurp_ifID = 0;
			}
		}
		break;

	case AURPCODE_AURPPROTO: /* proto type - AURP */
		if (aurp_ifID) {
			aurp_ifID->ifFlags |= AT_IFF_AURP;
		}
		break;
	}

	return 0;
}


/* checks to see if address of packet is for one of our interfaces
   returns *ifID if it's for us, NULL if not
*/
at_ifaddr_t *forUs(ddp)
     register at_ddp_t *ddp;
{
	at_ifaddr_t *ifID;

	TAILQ_FOREACH(ifID, &at_ifQueueHd, aa_link) {
		if ((ddp->dst_node == ifID->ifThisNode.s_node) &&
		    (NET_VALUE(ddp->dst_net) ==  ifID->ifThisNode.s_net)
		   ) {
			dPrintf(D_M_DDP_LOW, D_L_ROUTING,
				("pkt was for port %d\n", ifID->ifPort));

			return(ifID);
		}
	}

	return((at_ifaddr_t *)NULL);
} /* forUs */
