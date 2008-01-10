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
 *	Copyright (c) 1988-1998 Apple Computer, Inc. 
 */
/*
 *   0.01 05/12/94	Laurent Dumont		Creation
 *
 *   Modified, March 17, 1997 by Tuyen Nguyen for MacOSX.
 */
/*
 *
 * Router ZIP protocol functions:
 *
 * This file contains Routing specifics to handle ZIP requests and responses
 * sent and received by a router node.
 *
 * The entry point for the zip input in ddp is valid only when we're
 * running in router mode. 
 *
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
#include <netat/at_var.h>
#include <netat/ddp.h>
#include <netat/nbp.h>
#include <netat/zip.h>
#include <netat/at_pcb.h>
#include <netat/atp.h>
#include <netat/routing_tables.h>
#include <netat/debug.h>

#include <sys/kern_event.h>

static void zip_reply_to_getmyzone();
extern int at_reg_mcast(), at_unreg_mcast();

/* globals */
extern at_ifaddr_t *ifID_table[], *ifID_home;
extern short	ErrorZIPoverflow;

/**********************************************************************
 * Remarks : 
 *	ZIP is implemented as a "peer" of DDP, so the packets coming in 
 *	to ZIP have the same headers as those coming in to DDP {ddp...}.
 *	Same applies to outgoing packets. Also, unlike DDP, ZIP assumes
 *	that an incoming packet is in a contiguous gbuf_t.
 *
 **********************************************************************/

static	int	netinfo_reply_pending;
static	void	zip_netinfo_reply(at_x_zip_t *, at_ifaddr_t *);
static	void	zip_getnetinfo(at_ifaddr_t *);
static	void	zip_getnetinfo_locked(void *);
static	void	send_phony_reply(void *);

/*
 * zip_send_getnetinfo_reply: we received a GetNetInfo packet, we need to reply
 *		   with the right information for the port.
 */
static void zip_send_getnetinfo_reply(m, ifID)
     register gbuf_t	*m;
     register at_ifaddr_t	*ifID;
{
	at_nvestr_t	*zname;
	gbuf_t *m_sent;
	at_ddp_t	*ddp, *ddp_sent;
	short ZoneNameProvided = FALSE;
	short RequestIsBroadcasted = FALSE;
	u_short znumber, len, packet_length, size, status;
	RT_entry *Entry;
	char GNIReply[128];

	ddp = (at_ddp_t *)gbuf_rptr(m);

	/* access the Zone Name info part of the GetNetInfo Request */

	zname = (at_nvestr_t *)(gbuf_rptr(m) + DDP_X_HDR_SIZE + 6);

	if (zname->len > ZIP_MAX_ZONE_LENGTH) {
		dPrintf(D_M_ZIP, D_L_WARNING, 
			("zip_s_gni_r: zone len too long l=%d ddplen=%d\n",
			 zname->len, DDPLEN_VALUE(ddp)));
		return;
	}


	if (zname->len)
		ZoneNameProvided = TRUE;

	GNIReply[0] = ZIP_NETINFO_REPLY;
	GNIReply[1] = ZIP_ZONENAME_INVALID;

	/* check if we are the originator is in the cable range for this interface */

	if ((NET_VALUE(ddp->src_net) < CableStart || NET_VALUE(ddp->src_net) > CableStop) &&
		(NET_VALUE(ddp->dst_net) == 0 && ddp->dst_node == 0xff)) {
			RequestIsBroadcasted = TRUE;
	}
	Entry = rt_blookup(CableStop);

	if (Entry != NULL && RT_ALL_ZONES_KNOWN(Entry)) { /* this net is well known... */

		GNIReply[2] = (Entry->NetStart & 0xFF00) >> 8;
		GNIReply[3] = (Entry->NetStart & 0x00FF);
		GNIReply[4] = (Entry->NetStop & 0xFF00) >> 8;
		GNIReply[5] = (Entry->NetStop & 0x00FF);
		
		/* copy the zone name found in the request */

		GNIReply[6] = zname->len;
		bcopy(&zname->str, &GNIReply[7], zname->len);


		if (znumber = zt_find_zname(zname)) {

			if (ZT_ISIN_ZMAP((znumber), Entry->ZoneBitMap)) {

			  GNIReply[1] = 0; /* Zone Valid */

			  if (len = zt_get_zmcast(ifID, zname, &GNIReply[8+zname->len]))
				GNIReply[7+zname->len] = len;
			  else {
				GNIReply[1] |= ZIP_USE_BROADCAST;
				GNIReply[7+zname->len] = 0; /* multicast address length */
			  }
			  packet_length = 8 + zname->len + len;
		    }
		}

	}

	else {	/* should not happen, we are supposed to know our net */
	  dPrintf(D_M_ZIP, D_L_WARNING, ("zip_s_gni_r: Don't know about our zone infos!!!\n"));
		return;
	}

	if (zt_ent_zcount(Entry) == 1)
		GNIReply[1] |= ZIP_ONE_ZONE;

	if (GNIReply[1] & ZIP_ZONENAME_INVALID) {

		short Index = ifID->ifDefZone;

		if (Index <= 0 || Index >= ZT_MAXEDOUT) {
	  		dPrintf(D_M_ZIP, D_L_WARNING,
			  ("zip_s_gni_r: Invalid starting index =%d port%d\n",
				 Index, ifID->ifPort));
			return;
		}


		Index--;

		if (len = zt_get_zmcast(ifID, &ZT_table[Index].Zone, &GNIReply[8+zname->len]))
			GNIReply[7+zname->len] = len;
		else {
			GNIReply[1] |= ZIP_USE_BROADCAST;
			GNIReply[7+zname->len] = 0; /* multicast address length */
		}

		packet_length = 7 + zname->len + len;

		/* in the case the zone name asked for in the request was invalid, we need
		 * to copy the good default zone for this net
		 */

		GNIReply[packet_length + 1] = ZT_table[Index].Zone.len;
		bcopy(&ZT_table[Index].Zone.str, &GNIReply[packet_length + 2],
				ZT_table[Index].Zone.len);
		packet_length = packet_length +2 + ZT_table[Index].Zone.len;
	}


	/* 
	 * we're finally ready to send out the GetNetInfo Reply
	 *
	 */


	size =  DDP_X_HDR_SIZE + packet_length;
	if ((m_sent = gbuf_alloc(AT_WR_OFFSET+size, PRI_HI)) == NULL) {
	  return; /* was return(ENOBUFS); */
	}

	gbuf_rinc(m_sent,AT_WR_OFFSET);
	gbuf_wset(m_sent,size);
	ddp_sent = (at_ddp_t *)(gbuf_rptr(m_sent));

	/* Prepare the DDP header */

	ddp_sent->unused = ddp_sent->hopcount = 0;
	UAS_ASSIGN(ddp->checksum, 0);
	DDPLEN_ASSIGN(ddp_sent, size);
	NET_ASSIGN(ddp_sent->src_net, ifID->ifThisNode.s_net);
	ddp_sent->src_node = ifID->ifThisNode.s_node;
	ddp_sent->src_socket = ZIP_SOCKET;
	ddp_sent->dst_socket = ddp->src_socket;

	if (RequestIsBroadcasted) { /* if this was a broadcast, must respond from that */

		NET_ASSIGN(ddp_sent->dst_net, 0);
		ddp_sent->dst_node = 0xFF;
	}
	else {

	  NET_NET(ddp_sent->dst_net, ddp->src_net);
	  ddp_sent->dst_node = ddp->src_node;
	}
	ddp_sent->type = DDP_ZIP;

	bcopy(&GNIReply, &ddp_sent->data, packet_length);

	dPrintf(D_M_ZIP_LOW, D_L_ROUTING, 
		("zip_s_gni_r: send to %d:%d port#%d pack_len=%d\n",
		 NET_VALUE(ddp_sent->dst_net), ddp_sent->dst_node,
		 ifID->ifPort, packet_length));
	if ((status = 
	     ddp_router_output(m_sent, ifID, AT_ADDR,
			      NET_VALUE(ddp_sent->dst_net), ddp_sent->dst_node, 0))) {
	  dPrintf(D_M_ZIP, D_L_ERROR, 
		  ("zip_s_gni_r: ddp_router_output returns =%d\n", status));
	  return; /* was return(status); */
	}
} /* zip_send_getnetinfo_reply */


/*
 * build_ZIP_reply_packet: is used to create and send a DDP packet and use the
 * provided buffer as a ZIP reply. This is used by zip_send_ext_reply_to_query
 * and zip_send_reply_to_query for sending their replies to ZIP queries.
 */
gbuf_t *prep_ZIP_reply_packet(m, ifID)
     register gbuf_t *m;		/* this is the original zip query */
     register at_ifaddr_t *ifID;
{
	register gbuf_t *m_sent;
	register at_ddp_t	*ddp, *src_ddp;

	/* access the source Net and Node informations */

	src_ddp = (at_ddp_t *)gbuf_rptr(m);

	if ((m_sent = gbuf_alloc (AT_WR_OFFSET+1024, PRI_HI)) == NULL) {
		return((gbuf_t *)NULL);
	}
	gbuf_rinc(m_sent,AT_WR_OFFSET);
	gbuf_wset(m_sent,DDP_X_HDR_SIZE);
	ddp = (at_ddp_t *)(gbuf_rptr(m_sent));

	/* Prepare the DDP header */

	ddp->unused = ddp->hopcount = 0;
	UAS_ASSIGN(ddp->checksum, 0);

	NET_ASSIGN(ddp->src_net, ifID->ifThisNode.s_net);
	ddp->src_node = ifID->ifThisNode.s_node;
	ddp->src_socket = ZIP_SOCKET;

	ddp->dst_socket = src_ddp->src_socket;
	NET_NET(ddp->dst_net, src_ddp->src_net);
	ddp->dst_node = src_ddp->src_node;

	ddp->type = DDP_ZIP;
	
	return(m_sent);
}
/*
 * zip_send_ext_reply_to_query: this function deals with ZIP Queries for extended nets.
 *  When we recognize an extended net (that might have several zone name associated with
 *  it), we send A SEPARATE ZIP reply for that network. This is called from the
 *  regular zip_send_reply_to_query, that just deals with non-ext nets.
 */ 

static void zip_send_ext_reply_to_query(mreceived, ifID, Entry, NetAsked)
     register gbuf_t	*mreceived;
     register at_ifaddr_t	*ifID;
     RT_entry *Entry;		/* info about the network we're looking for */
     u_short NetAsked;
{
	register gbuf_t	*m;
	register at_ddp_t	*ddp;
	short i, j, reply_length, Index, zone_count, status;
	u_char	*zmap;
	char *ReplyBuff, *ZonesInPacket;

	zone_count = zt_ent_zcount(Entry);
	zmap = Entry->ZoneBitMap;
	i = ZT_BYTES -1;

	
newPacket:

	if (!(m = prep_ZIP_reply_packet (mreceived, ifID))) {
	  return; /* was return(ENOBUFS); */
	}

	ddp = (at_ddp_t *)(gbuf_rptr(m));
	ReplyBuff = (char *)(ddp->data);


	*ReplyBuff++ = 8;	/* ZIP function = 8 [extended reply] */

	ZonesInPacket= ReplyBuff;
	*ZonesInPacket= 0;	
	ReplyBuff ++;
	reply_length = 2;	/* 1st byte is ZIP reply code, 2nd is network count */
	j= 0;

	/* For all zones, we check if they belong to the map for that Network */

	for (;  i >= 0; i--) {

		/* find the zones defined in this entry bitmap */
		
		if (zmap[i]) {
			for (; j < 8 ; j++)
				if (zmap[i] << j & 0x80) { /* bingo */

					Index = i*8 + j; /* zone index in zone table */

					if (reply_length + 3 + ZT_table[Index].Zone.len  > DDP_DATA_SIZE) {
 
					/* we need to send the packet before, this won't fit... */

						zone_count -= *ZonesInPacket;

						DDPLEN_ASSIGN(ddp, reply_length + DDP_X_HDR_SIZE);
						gbuf_winc(m,reply_length);
						if ((status = 
						     ddp_router_output(m, ifID, AT_ADDR,
								       NET_VALUE(ddp->dst_net), ddp->dst_node, 0))) {
						  dPrintf(D_M_ZIP, D_L_ERROR,
							  ("zip_s_ext_repl: ddp_router_output returns =%d\n",
							   status));
						  return; /* was return (status); */
						}
			
						goto newPacket;

					}
					/* this should fit in this packet, build the NetNumber, ZoneLen,
				 	* ZoneName triple 
				 	*/

					if (ZT_table[Index].Zone.len) {
						*ZonesInPacket += 1; /* bump NetCount field */
						*ReplyBuff++ = (NetAsked & 0xFF00) >> 8;
						*ReplyBuff++ = (NetAsked & 0x00FF) ;
						*ReplyBuff++ = ZT_table[Index].Zone.len;

						bcopy(&ZT_table[Index].Zone.str, ReplyBuff,
								ZT_table[Index].Zone.len);

						ReplyBuff += ZT_table[Index].Zone.len;
						reply_length += ZT_table[Index].Zone.len +3;
					}

				}
			}
			j= 0;	/* reset the bit count */
	}

	/* if we have some zone info in a half-empty packet, send it now.
	 * Remember, for extended nets we send *at least* one Reply
	 */

	if (zone_count) {
			DDPLEN_ASSIGN(ddp, reply_length + DDP_X_HDR_SIZE);
			gbuf_winc(m,reply_length);
			if ((status = 
			     ddp_router_output(m, ifID, AT_ADDR,
					       NET_VALUE(ddp->dst_net), ddp->dst_node, 0))) {
			  dPrintf(D_M_ZIP, D_L_ERROR,
				  ("zip_s_ext_reply: ddp_router_output returns =%d\n", status));
			  return; /* was return (status); */
			}
	}
	else  /* free the buffer not used */

		gbuf_freem(m);
} /* zip_send_ext_reply_to_query */

/*
 * zip_send_reply_to_query: we received a ZIPQuery packet, we need to reply
 *	with the right information for the nets requested (if we have
 *	the right information.
 */
static void zip_send_reply_to_query(mreceived, ifID)
     register gbuf_t	*mreceived;
     register at_ifaddr_t	*ifID;
{
	register gbuf_t	*m;
	register at_ddp_t	*ddp, *ddp_received;
	RT_entry *Entry;
	short i, reply_length, Index, status;
	u_char	network_count;
	u_short *NetAsked;
	char *ReplyBuff, *ZonesInPacket;

	ddp_received = (at_ddp_t *)gbuf_rptr(mreceived);

	/* access the number of nets requested in the Query */
	network_count  = *((char *)(ddp_received->data) + 1);
	NetAsked = (u_short *)(ddp_received->data + 2);

	/* check the validity of the Query packet */

	if (DDPLEN_VALUE(ddp_received) != 
	    (2 + network_count * 2 + DDP_X_HDR_SIZE)) {

	  	dPrintf(D_M_ZIP, D_L_WARNING, 
			("zip_s_reply_to_q: bad length netcount=%d len=%d\n",
			 network_count, DDPLEN_VALUE(ddp)));
		return; /* was return(1); */
	} 

	/* walk the Query Network list */
	/* we want to build a response with the network number followed by the zone name
     * length and the zone name. If there is more than one zone per network asked,
	 * we repeat the network number and stick the zone length and zone name.
	 * We need to be carefull with the max DDP size for data. If we see that a new
     * NetNum, ZoneLen, ZoneName sequence won't fit, we send the previous packet and
     * begin to build a new one.
	 */

newPacket:

	if (!(m = prep_ZIP_reply_packet (mreceived, ifID))) {
	  return; /* was return(ENOBUFS); */
	}

	ddp = (at_ddp_t *)(gbuf_rptr(m));
	ReplyBuff = (char *)(ddp->data);

	*ReplyBuff++ = 2;	/* ZIP function = 2 [Non extended reply] */
	ZonesInPacket = ReplyBuff;
	*ZonesInPacket = 0;
	ReplyBuff++;
	reply_length = 2;	/* 1st byte is ZIP reply code, 2nd is network count */

	for (i = 0 ; i < network_count ; i ++, NetAsked++) {
	  Entry = rt_blookup(ntohs(*NetAsked));

	  if (Entry != NULL && ((Entry->EntryState & 0x0F) >= RTE_STATE_SUSPECT) &&
	      RT_ALL_ZONES_KNOWN(Entry)) { /* this net is well known... */

	    if (Entry->NetStart == 0) { /* asking for a NON EXTENDED network */
	
	      if ( (Index = zt_ent_zindex(Entry->ZoneBitMap)) == 0)
		continue;
	      
	      Index--;

	      if (reply_length + 3 + ZT_table[Index].Zone.len  > DDP_DATA_SIZE) {

			/* we need to send the packet before, this won't fit... */
		
			DDPLEN_ASSIGN(ddp, reply_length + DDP_X_HDR_SIZE);
			gbuf_winc(m,reply_length);

			if ((status = 
			     ddp_router_output(m, ifID, AT_ADDR,
					       NET_VALUE(ddp->dst_net), 
					       ddp->dst_node, 0))) {
			  dPrintf(D_M_ZIP, D_L_ERROR,
				  ("zip_s_reply: ddp_router_output returns =%d\n",
				   status));
			  return; /* was return (status); */
			}

			/* this is not nice, I know, but we reenter the loop with
			 * a packet is sent with the next network field in the Query
			 */
			
			network_count -= i;
			goto newPacket;

	      }
	      
	      /* this should fit in this packet, build the NetNumber, ZoneLen,
	       * ZoneName triple 
	       */

	      if (ZT_table[Index].Zone.len) {
	      		ZonesInPacket += 1; /* bump NetCount field */
			*ReplyBuff++	= (*NetAsked & 0xFF00) >> 8;
			*ReplyBuff++ 	= (*NetAsked & 0x00FF) ;
			*ReplyBuff++ 	= ZT_table[Index].Zone.len;
			bcopy(&ZT_table[Index].Zone.str, ReplyBuff,
			      ZT_table[Index].Zone.len);
					
			ReplyBuff += ZT_table[Index].Zone.len;

			reply_length += ZT_table[Index].Zone.len + 3;


	      }
					
				
	    }
	    else {	/* extended network, check for multiple zone name attached
			 * and build a separate packet for each extended network requested
			 */

	    	zip_send_ext_reply_to_query(mreceived, ifID, Entry, ntohs(*NetAsked));

	    }
	  }
	}				

	/* If we have a non extended packet (code 2) with some stuff in it,
	 * we need to send it now
	 */

	if ( reply_length > 2)  {
		DDPLEN_ASSIGN(ddp, reply_length + DDP_X_HDR_SIZE);
		gbuf_winc(m,reply_length);
		if ((status = 
		     ddp_router_output(m, ifID, AT_ADDR,
				       NET_VALUE(ddp->dst_net), 
				       ddp->dst_node, 0))) {
			dPrintf(D_M_ZIP, D_L_ERROR,
			 	("zip_send_reply: ddp_router_output returns =%d\n", status));
			return; /* was return (status); */
		}
	}
	else  /* free the buffer not used */
		gbuf_freem(m);
} /* zip_send_reply_to_query */

/***********************************************************************
 * zip_router_input()
 * 
 **********************************************************************/

void zip_router_input (m, ifID)
     register gbuf_t	*m;
     register at_ifaddr_t	*ifID;
{
	register at_ddp_t	*ddp;
	register at_atp_t	*atp;
	register at_zip_t	*zip;
	u_char	 user_bytes[4];
	register u_short user_byte;
	
	/* variables for ZipNotify processing */
	register char	old_zone_len;
	register char	new_zone_len;
	register char	*old_zone;
	char		*new_zone;
	void		zip_sched_getnetinfo(); /* forward reference */

	if (gbuf_type(m) != MSG_DATA) {
		/* If this is a M_ERROR message, DDP is shutting down, 
		 * nothing to do here...If it's something else, we don't 
		 * understand what it is
		 */
	  	dPrintf(D_M_ZIP, D_L_WARNING, ("zip_router_input: not an M_DATA message\n"));
		gbuf_freem(m);
		return;
	}

	if (!ifID) {
	  	dPrintf(D_M_ZIP, D_L_WARNING, ("zip_router_input: BAD ifID\n"));
		gbuf_freem(m);
		return;
	}

	/*
	 * The ZIP listener receives two types of requests:
	 *
	 * ATP requests: GetZoneList, GetLocalZone, or GetMyZone
	 * ZIP requests: Netinfo, Query, Reply, takedown, bringup
	 */

	ddp = (at_ddp_t *)gbuf_rptr(m);

	if (ddp->type == DDP_ZIP) {
		zip = (at_zip_t *)(gbuf_rptr(m) + DDP_X_HDR_SIZE);
		dPrintf(D_M_ZIP_LOW, D_L_INPUT, 
			("zip_input: received a ZIP_DDP command=%d\n", 
			 zip->command));
		switch (zip->command) {
		    case ZIP_QUERY : /* we received a Zip Query request */
			dPrintf(D_M_ZIP, D_L_INPUT, 
				("zip_input: Received a Zip Query in from %d.%d\n",
				 NET_VALUE(ddp->src_net), ddp->src_node));

			if (!RT_LOOKUP_OKAY(ifID, ddp)) {
				dPrintf(D_M_ZIP, D_L_INPUT, 
					("zip_input:: refused ZIP_QUERY from %d:%d\n",
					NET_VALUE(ddp->src_net), ddp->src_node));
			}
			else
				zip_send_reply_to_query(m, ifID);
			gbuf_freem(m);
			break;

		case ZIP_REPLY : /* we received a Zip Query Reply packet */
		case ZIP_EXTENDED_REPLY:
			if (ifID->ifRoutingState == PORT_OFFLINE) {
				dPrintf(D_M_ZIP, D_L_INPUT, 
					("zip_input: Received a Zip Reply in user mode\n"));
			}
			else
				zip_reply_received(m, ifID, zip->command);
			gbuf_freem(m);
			break;

		case ZIP_TAKEDOWN :
			/* we received a Zip Takedown packet */
			dPrintf(D_M_ZIP, D_L_WARNING, ("zip_input: Received a Zip takedown!!!\n"));
			gbuf_freem(m);
			break;

		case ZIP_BRINGUP :
			/* we received a Zip BringUp packet */
			dPrintf(D_M_ZIP, D_L_WARNING, ("zip_input: Received a Zip BringUp!!!\n"));
			gbuf_freem(m);
			break;

		case ZIP_GETNETINFO: /* we received a GetNetInfo request */
			dPrintf(D_M_ZIP, D_L_INPUT,
				("zip_input: Received a GetNetInfo Req in from %d.%d\n",
				NET_VALUE(ddp->src_net), ddp->src_node));
			if (RT_LOOKUP_OKAY(ifID, ddp)) {
				dPrintf(D_M_ZIP, D_L_OUTPUT,
					("zip_input: we, as node %d:%d send GNI reply to %d:%d\n",
					 ifID->ifThisNode.s_net, ifID->ifThisNode.s_node,
					 NET_VALUE(ddp->src_net), ddp->src_node));
			      	zip_send_getnetinfo_reply(m, ifID);
			}
			gbuf_freem(m);
			break;


		case ZIP_NETINFO_REPLY :
	
			/* If we are not waiting for a GetNetInfo reply
			 * to arrive, this must be a broadcast
			 * message for someone else on the zone, so
			 * no need to even look at it!
			 */
			if (!ROUTING_MODE && 
			    ((NET_VALUE(ddp->src_net) != ifID->ifThisNode.s_net) ||
			     (ddp->src_node != ifID->ifThisNode.s_node)) && netinfo_reply_pending)
			{
				extern void trackrouter();
				dPrintf(D_M_ZIP, D_L_INPUT,
					("zip_input: Received a GetNetInfo Reply from %d.%d\n",
					NET_VALUE(ddp->src_net), ddp->src_node));
				trackrouter(ifID, NET_VALUE(ddp->src_net), ddp->src_node);
				zip_netinfo_reply((at_x_zip_t *)zip, ifID);
			}

			gbuf_freem(m);
			break;

		case ZIP_NOTIFY :
			/* processing of ZipNotify message : first, change
			 * our zone name, then if NIS is open, let NBP demon
				  process know of this change...(just forward the
			 * Notify packet
			 */
			/* First, check if this is really a packet for us */
			old_zone = &zip->data[4];
			if (!zonename_equal(&ifID->ifZoneName, 
					    (at_nvestr_t *)old_zone)) {
				/* the old zone name in the packet is not the
				 * same as ours, so this packet couldn't be
				 * for us.
				 */
				gbuf_freem(m);
				break;

			}
			old_zone_len = *old_zone;
			new_zone_len = zip->data[4 + old_zone_len + 1];
			new_zone = old_zone + old_zone_len;

			/* Reset the zone multicast address */
			(void)at_unreg_mcast(ifID, (caddr_t)&ifID->ZoneMcastAddr);
			bzero((caddr_t)&ifID->ZoneMcastAddr, ETHERNET_ADDR_LEN);
		
			/* change the zone name - copy both the length and the string */
			bcopy((caddr_t)new_zone, (caddr_t)&ifID->ifZoneName, 
			      new_zone_len+1);

			/* Send network zone change event and new zone for this interface. */
			atalk_post_msg(ifID->aa_ifp, KEV_ATALK_ZONEUPDATED, 0, &(ifID->ifZoneName));
			atalk_post_msg(ifID->aa_ifp, KEV_ATALK_ZONELISTCHANGED, 0, 0);
			
			/* add the new zone to the list of local zones */
			if (!MULTIPORT_MODE && !DEFAULT_ZONE(&ifID->ifZoneName))
				(void)setLocalZones(&ifID->ifZoneName, 
						    (ifID->ifZoneName.len+1));

			/* Before trying to request our new multicast address,
			 * wait a while... someone might have alredy requested
			 * it, so we may see some broadcast messages flying 
			 * by...  Set up the structures so that it appears that
			 * we have already requested the NetInfo.
			 */
			ifID->ifNumRetries = ZIP_NETINFO_RETRIES;
			netinfo_reply_pending = 1;
			ifID->ifGNIScheduled = 1;
			timeout(zip_sched_getnetinfo, (caddr_t) ifID, 
				 2*ZIP_TIMER_INT);
	
			gbuf_freem(m);
			break;
		default :
			routing_needed(m, ifID, TRUE);
			break;
		}
	}
	else if (ddp->type == DDP_ATP && 
		 RT_LOOKUP_OKAY(ifID, ddp)) {
		if (gbuf_len(m) > DDP_X_HDR_SIZE)
			atp = (at_atp_t *)(gbuf_rptr(m)+DDP_X_HDR_SIZE);
		else
			atp = (at_atp_t *)(gbuf_rptr(gbuf_cont(m)));

		/* Get the user bytes in network order */

		*((u_long*)user_bytes) = UAL_VALUE(atp->user_bytes);
		user_byte = user_bytes[0]; /* Get the zeroth byte */

		dPrintf(D_M_ZIP, D_L_INPUT,
			("zip_input: received a ZIP_ATP command=%d\n", user_byte));

		switch (user_byte) {
			case ZIP_GETMYZONE:
				zip_reply_to_getmyzone(ifID, m);
				gbuf_freem(m);
				break;
		
			case ZIP_GETZONELIST:
				zip_reply_to_getzonelist(ifID, m);
				gbuf_freem(m);
				break;
		
			case ZIP_GETLOCALZONES:
				zip_reply_to_getlocalzones(ifID, m);
				gbuf_freem(m);
				break;

			default:
				dPrintf(D_M_ZIP, D_L_WARNING,
					("zip_input: received unknown ZIP_ATP command=%d\n", user_byte));
				routing_needed(m, ifID, TRUE);
				break;
		}
	} else {
		gbuf_freem(m);
	}
	return;
} /* zip_router_input */

/***********************************************************************
 * zonename_equal()
 * 
 * Remarks :
 *
 **********************************************************************/
int zonename_equal (zone1, zone2)
     register at_nvestr_t	*zone1, *zone2;
{
	register char c1, c2;
	char	upshift8();
	register int	i;

	if (zone1->len != zone2->len)
		return(0);

	for (i=0; i< (int) zone1->len; i++) {
		c1 = zone1->str[i];
		c2 = zone2->str[i];
		if (c1 >= 'a' && c1 <= 'z')
			c1 += 'A' - 'a';
		if (c2 >= 'a' && c2 <= 'z')
			c2 += 'A' - 'a';
		if (c1 & 0x80)
			c1 = upshift8(c1);
		if (c2 & 0x80)
			c2 = upshift8(c2);
		if (c1 != c2)
			return(0);
	}
	return(1);
}


char	upshift8 (ch)
     register char	ch;
{
	register int	i;

	static	unsigned char	lower_case[] =
		{0x8a, 0x8c, 0x8d, 0x8e, 0x96, 0x9a, 0x9f, 0xbe,
		 0xbf, 0xcf, 0x9b, 0x8b, 0x88, 0};
	static	unsigned char	upper_case[] = 
		{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0xae,
		 0xaf, 0xce, 0xcd, 0xcc, 0xcb, 0};
	
	for (i=0; lower_case[i]; i++)
		if (ch == lower_case[i])
			return (upper_case[i]);

	return(ch);
}


/***********************************************************************
 * zip_netinfo_reply ()
 * 
 * Remarks :
 *
 **********************************************************************/
static void zip_netinfo_reply (netinfo, ifID)
     register at_x_zip_t	*netinfo;
     register at_ifaddr_t	*ifID;
{
	u_char	mcast_len;
	void	zip_sched_getnetinfo(); /* forward reference */
	register at_net_al	this_net;
	char	*default_zone;
	register u_char	zone_name_len;
	
	/* There may be multiple zones on the cable.... we need to
	 * worry about whether or not this packet is addressed
	 * to us.
	 */
	/* *** Do we really need to check this? *** */
	if (!zonename_equal((at_nvestr_t *)netinfo->data, &ifID->ifZoneName)) {
		dPrintf(D_M_ZIP, D_L_INFO, ("zip_netinfo_reply, !zonename_equal!!!"));
		return;
	}

	ifID->ifThisCableStart = NET_VALUE(netinfo->cable_range_start);
	ifID->ifThisCableEnd = NET_VALUE(netinfo->cable_range_end);
	dPrintf(D_M_ZIP, D_L_OUTPUT, ("Zip_netinfo_reply: Set cable to %d-%d\n",
		 ifID->ifThisCableStart, ifID->ifThisCableEnd));

	/* The packet is in response to our request */
	ifID->ifGNIScheduled = 0;
	untimeout (zip_sched_getnetinfo, (caddr_t) ifID);
	netinfo_reply_pending = 0;
	zone_name_len = netinfo->data[0];
	mcast_len = netinfo->data[zone_name_len + 1];

	if (netinfo->flags & ZIP_ZONENAME_INVALID) {
		/* copy out the default zone name from packet */
		default_zone = (char *)&netinfo->data[zone_name_len+1+mcast_len+1];
		bcopy((caddr_t)default_zone, (caddr_t)&ifID->ifZoneName, 
		      *default_zone + 1);
	} 

	/* add the new zone to the list of local zones */
	if (!MULTIPORT_MODE && !DEFAULT_ZONE(&ifID->ifZoneName))
		(void)setLocalZones(&ifID->ifZoneName, (ifID->ifZoneName.len+1));

	/* get the multicast address out of the GetNetInfo reply, if there is one */
	if (!(netinfo->flags & ZIP_USE_BROADCAST)) {
		/* If ZIP_USE_BROADCAST is set, we will use the cable 
		   broadcast address as the multicast address, however
		   the cable multicast address has already been registered.
		 */
		/* This packet contains a multicast address, so
		 * send to elap to register it.
		 */
	  	if (FDDI_OR_TOKENRING(ifID->aa_ifp->if_type))
			ddp_bit_reverse(&netinfo->data[zone_name_len + 2]);

		bcopy((caddr_t)&netinfo->data[zone_name_len + 2], 
		      (caddr_t)&ifID->ZoneMcastAddr, ETHERNET_ADDR_LEN);
		(void)at_reg_mcast(ifID, (caddr_t)&ifID->ZoneMcastAddr);
	}

	this_net = ifID->ifThisNode.s_net;
	if ((this_net >= ifID->ifThisCableStart) &&
	    (this_net <= ifID->ifThisCableEnd)) {
		/* ThisNet is in the range of valid network numbers
		 * for the cable. Do nothing.
		 */
	} else {
		/* ThisNet is not in the range of valid network 
		 * numbers for the cable. This may be either because
		 * the chosen number was from start-up range, or
		 * because the user has a misconception of where the
		 * machine is!!  Since ThisCableRange is set up, next
		 * time aarp is invoked, it would select address in
		 * the right range.
		 */

		/* to reset initial_net and initial_node to zero, so
		 * that aarp is forced to choose new values
		 */
		ifID->initial_addr.s_net = 0;
		ifID->initial_addr.s_node = 0;

		/* Wake up elap_online sleeping on this interface. */
		ZIPwakeup(ifID, ZIP_RE_AARP);
		return;
	}
	
	if (!ifID->startup_inprogress) {
		/* Send event with zone info. This covers case where we get zone info
			after startup. During startup this event is sent from ZIPwakeup. */
		atalk_post_msg(ifID->aa_ifp, KEV_ATALK_ZONEUPDATED, 0, &(ifID->ifZoneName));
	}

	ZIPwakeup(ifID, 0); /* no error */
	return;
} /* zip_netinfo_reply */


/**********************************************************************
 * zip_control()
 *
 **********************************************************************/
int zip_control (ifID, control)
     register at_ifaddr_t	*ifID;
     int	control;
{
	dPrintf(D_M_ZIP, D_L_INFO, ("zip_control called port=%d control=%d\n",
			 ifID->ifPort, control));
	switch (control) {
	case ZIP_ONLINE :
	case ZIP_LATE_ROUTER :
		if (!ifID->ifGNIScheduled) {
			ifID->ifNumRetries = 0;
			/* Get the desired zone name from elap and put it in
		 	* ifID for zip_getnetinfo() to use.
		 	*/
			if (ifID->startup_zone.len)
				ifID->ifZoneName = ifID->startup_zone;
			zip_getnetinfo(ifID);
		}
		break;
	case ZIP_NO_ROUTER :
		ifID->ifZoneName.len = 1;
		ifID->ifZoneName.str[0] = '*';
		ifID->ifZoneName.str[1] = '\0';

		/* Send event with zone info. */
		atalk_post_msg(ifID->aa_ifp, KEV_ATALK_ZONEUPDATED, 0, &(ifID->ifZoneName));

		break;
	default :
		break;
	}
	return (0);
}

/* locked version of zip_getnetinfo */
static void zip_getnetinfo_locked(arg)
     void       *arg;
{
	at_ifaddr_t       *ifID;
	
	atalk_lock();
	if (ifID != NULL) {		// make sure it hasn't been closed
		ifID = (at_ifaddr_t *)arg;
		ifID->ifGNIScheduled = 0;
		zip_getnetinfo(ifID);
	}
	atalk_unlock();
}


/**********************************************************************
 * zip_getnetinfo()
 *
 **********************************************************************/
static void zip_getnetinfo (ifID)
     register at_ifaddr_t       *ifID;
{
	register at_x_zip_t	*zip;
	gbuf_t			*m;
	register at_ddp_t	*ddp;
	void			zip_sched_getnetinfo();
	register struct	atalk_addr	*at_dest;
	register int		size;
	

	size =  DDP_X_HDR_SIZE + ZIP_X_HDR_SIZE + ifID->ifZoneName.len + 1
		+ sizeof(struct atalk_addr) + 1;
	if ((m = gbuf_alloc (AT_WR_OFFSET+size, PRI_HI)) == NULL) {
		/* This time, we're unable to allocate buffer to 
		 * send a packet out, so schedule to send a packet 
		 * out later, and exit.
		 */
		dPrintf(D_M_ZIP, D_L_WARNING, ("zip_getnetinfo: no buffer, call later port=%d\n",
			ifID->ifPort));
		ifID->ifGNIScheduled = 1;
		timeout (zip_getnetinfo_locked, (caddr_t) ifID, ZIP_TIMER_INT/10);
		return;
	}

	gbuf_rinc(m,AT_WR_OFFSET);
	gbuf_wset(m,0);
	*(u_char *)gbuf_rptr(m) = AT_ADDR;
	at_dest = (struct atalk_addr *)(gbuf_rptr(m) + 1);
	ddp = (at_ddp_t *)(gbuf_rptr(m) + sizeof(struct atalk_addr) + 1);
	zip = (at_x_zip_t *)ddp->data;
	gbuf_winc(m,size);

	zip->command = ZIP_GETNETINFO;
	zip->flags = 0;
	NET_ASSIGN(zip->cable_range_start, 0);
	NET_ASSIGN(zip->cable_range_end, 0);
	if (ifID->ifZoneName.len)	/* has to match reply exactly */
		bcopy((caddr_t)&ifID->ifZoneName, (caddr_t)zip->data, 
		      ifID->ifZoneName.len + 1);
	else 
		zip->data[0] = 0; /* No zone name is availbale */

	/* let the lap fields be uninitialized, 'cause it doesn't 
	 * matter.
	 */
	DDPLEN_ASSIGN(ddp, size - (sizeof(struct atalk_addr) + 1));
	UAS_ASSIGN(ddp->checksum, 0);
	ddp->hopcount = ddp->unused = 0;
	NET_ASSIGN(ddp->dst_net, 0); /* cable-wide broadcast */
	NET_ASSIGN(ddp->src_net, ifID->ifThisNode.s_net);
		/* By this time, AARP is done */

	ddp->dst_node = 0xff;
	ddp->src_node = ifID->ifThisNode.s_node;
	ddp->dst_socket = ZIP_SOCKET;
	ddp->src_socket = ZIP_SOCKET;
	ddp->type = DDP_ZIP;

	at_dest->atalk_unused = 0;
	NET_NET(at_dest->atalk_net, ddp->dst_net);
	at_dest->atalk_node = ddp->dst_node;

	dPrintf(D_M_ZIP, D_L_INPUT, ("zip_getnetinfo: called for port=%d\n",
		 ifID->ifPort));

	if (elap_dataput(m, ifID, 0, NULL)) {
	 dPrintf(D_M_ZIP, D_L_ERROR, 
		 ("zip_getnetinfo: error sending zip_getnetinfo\n"));
		return;
	}

	ifID->ifNumRetries++;
	netinfo_reply_pending = 1;
	ifID->ifGNIScheduled = 1;
	timeout (zip_sched_getnetinfo, (caddr_t) ifID, ZIP_TIMER_INT);
} /* zip_getnetinfo */

 
/**********************************************************************
 * zip_sched_getnetinfo()
 *
 **********************************************************************/

void	zip_sched_getnetinfo (ifID)
     register at_ifaddr_t	     *ifID;
{

	atalk_lock();
	
	ifID->ifGNIScheduled = 0;

	if (ifID->ifNumRetries >= ZIP_NETINFO_RETRIES) {
		/* enough packets sent.... give up! */
		/* we didn't get any response from the net, so
		 * assume there's no router around and the given
		 * zone name, if any, is not valid.  Change the
		 * zone name to "*".
		 */
		ifID->ifZoneName.len = 1;
		ifID->ifZoneName.str[0] = '*';
		ifID->ifZoneName.str[1] = '\0';
		/* Should NBP be notified of this "new" zone name?? */
		netinfo_reply_pending = 0;

		ifID->ifRouterState = NO_ROUTER;
		ifID->ifARouter.s_net = 0;
		ifID->ifARouter.s_node = 0;

		dPrintf(D_M_ZIP, D_L_INFO, ("zip_sched_getnetinfo: Reset Cable Range\n"));

		ifID->ifThisCableStart = DDP_MIN_NETWORK;
		ifID->ifThisCableEnd = DDP_MAX_NETWORK;

		if (ifID->ifState == LAP_ONLINE_FOR_ZIP)
			ZIPwakeup (ifID, 0); /* no error */
	} else
		zip_getnetinfo(ifID);

	atalk_unlock();
}


/**********************************************************************
 * zip_type_packet()
 *
 * Remarks:
 *	This routine checks whether or not the packet contained in "m"
 *	is an (outgoing) ZIP packet.  If not, it returns 0.  If it is a
 *	ZIP packet, it returns the ZIP packet type (ZIP command). "m"
 *	points to a packet with extended DDP header.  The rest of the
 *	DDP data may or may not be in the first gbuf.
 *
 **********************************************************************/
int zip_type_packet (m)
     register gbuf_t	*m;
{
	register at_atp_t	*atp;
	register at_ddp_t	*ddp;
	register at_zip_t	*zip;
	u_char	user_bytes[4];
	register int	user_byte;

	ddp = (at_ddp_t *)gbuf_rptr(m);
	if (ddp->dst_socket == ZIP_SOCKET) {
		switch (ddp->type) {
		case DDP_ZIP :
			if (gbuf_len(m) > DDP_X_HDR_SIZE)
				zip = (at_zip_t *)(gbuf_rptr(m) 
					+ DDP_X_HDR_SIZE);
			else
				zip=(at_zip_t *)(gbuf_rptr(gbuf_cont(m)));
			return ((int)zip->command);
		case DDP_ATP :
			if (gbuf_len(m) > DDP_X_HDR_SIZE)
				atp = (at_atp_t *)(gbuf_rptr(m)+DDP_X_HDR_SIZE);
			else
				atp = (at_atp_t *)(gbuf_rptr(gbuf_cont(m)));
			/* Get the user bytes in network order */
			*((u_long*)user_bytes) = UAL_VALUE(atp->user_bytes);
			user_byte = user_bytes[0]; /* Get the zeroth byte */
			if ((user_byte == ZIP_GETMYZONE) ||
			    (user_byte == ZIP_GETZONELIST) ||
			    (user_byte == ZIP_GETLOCALZONES))
				return (user_byte);
			else
				return (0);
		default :
			return (0);
		}
	} else
		return (0);
}

/**********************************************************************
 * zip_handle_getmyzone()
 *
 * Remarks:
 *	Routine to handle ZIP GetMyZone request locally.  It generates
 *	a phony response to the outgoing ATP request and sends it up.
 *
 * 07/12/94 : remark2 only called from ddp.c / ddp_output
 *            should only be called from the home port, but
 *		      when we are a router we should know the infos for all
 *			  anyway, so reply locally with what we have in stock... 
 *
 **********************************************************************/

int zip_handle_getmyzone(ifID, m)
     register at_ifaddr_t   *ifID;
     register gbuf_t      *m;
{
        at_atp_t            *atp;
        register at_ddp_t   *ddp;
        register at_ddp_t *r_ddp;
        register at_atp_t *r_atp;
        gbuf_t          *rm; /* reply message */
        register int    size;
        u_long  ulongtmp;

	dPrintf(D_M_ZIP, D_L_INFO, 
		("zip_handle_getmyzone: local reply for port=%d\n",
		 ifID->ifPort));

        size = DDP_X_HDR_SIZE + ATP_HDR_SIZE + 1 + ifID->ifZoneName.len;
        /* space for two headers and the zone name */
        if ((rm = gbuf_alloc(AT_WR_OFFSET+size, PRI_HI)) == NULL) {
		dPrintf(D_M_ZIP, D_L_WARNING, 
			("zip_handle_getmyzone: no buffer, port=%d\n",
			 ifID->ifPort));
		return (ENOBUFS);
	}

        gbuf_rinc(rm,AT_WR_OFFSET);
        gbuf_wset(rm,0);
        r_ddp = (at_ddp_t *)(gbuf_rptr(rm));
        r_atp = (at_atp_t *)r_ddp->data;
        gbuf_winc(rm,size);

        ddp = (at_ddp_t *)gbuf_rptr(m);
        if (gbuf_len(m) > DDP_X_HDR_SIZE)
                atp = (at_atp_t *)(gbuf_rptr(m) + DDP_X_HDR_SIZE);
        else
                atp = (at_atp_t *)(gbuf_rptr(gbuf_cont(m)));

        /* fill up the ddp header for reply */
        DDPLEN_ASSIGN(r_ddp, size);
        r_ddp->hopcount = r_ddp->unused = 0;
        UAS_ASSIGN(r_ddp->checksum, 0);
        NET_ASSIGN(r_ddp->dst_net, ifID->ifThisNode.s_net);
        NET_NET(r_ddp->src_net, ddp->dst_net);
        r_ddp->dst_node = ifID->ifThisNode.s_node;
        r_ddp->src_node = ddp->dst_node;
        r_ddp->dst_socket = ddp->src_socket;
        r_ddp->src_socket = ZIP_SOCKET;
        r_ddp->type = DDP_ATP;

        /* fill up the atp header */
        r_atp->cmd = ATP_CMD_TRESP;
        r_atp->xo = 0;
        r_atp->eom = 1;
        r_atp->sts = 0;
        r_atp->xo_relt = 0;
        r_atp->bitmap = 0;
        UAS_UAS(r_atp->tid, atp->tid);
        ulongtmp = 1;
		UAL_ASSIGN_HTON(r_atp->user_bytes, ulongtmp); /* no of zones */

        /* fill up atp data part */
        bcopy((caddr_t) &ifID->ifZoneName, (caddr_t) r_atp->data, ifID->ifZoneName.len+1);

        /* all set to send the packet back up */

        timeout(send_phony_reply, (caddr_t) rm, HZ/20);
        return (0);
}

static	void
send_phony_reply(arg)
	void	*arg;
{
	gbuf_t  *rm = (gbuf_t *)arg;

	atalk_lock();
	ddp_input(rm, ifID_home);
	atalk_unlock();
        
	return;
}


/*
 * zip_prep_query_packet:  build the actual ddp packet for the zip query
 */

gbuf_t *zip_prep_query_packet(ifID, RouterNet, RouterNode)
     at_ifaddr_t *ifID;
     at_net_al	RouterNet; /* we want to send the Zip Query to that router */
     at_node	RouterNode;
{

	register gbuf_t *m;
	register at_ddp_t	*ddp;

	if ((m = gbuf_alloc (AT_WR_OFFSET+1024, PRI_HI)) == NULL) {
		dPrintf(D_M_ZIP, D_L_WARNING, 
			("zip_send_query_packet: no buffer, port=%d\n",
			 ifID->ifPort));
		return((gbuf_t *)NULL);
	}
	gbuf_rinc(m,AT_WR_OFFSET);
	gbuf_wset(m,0);

	ddp = (at_ddp_t *)(gbuf_rptr(m));

	/* Prepare the DDP header */

	ddp->unused = ddp->hopcount = 0;
	UAS_ASSIGN(ddp->checksum, 0);
	NET_ASSIGN(ddp->src_net, ifID->ifThisNode.s_net);
	ddp->src_node = ifID->ifThisNode.s_node;
	ddp->src_socket = ZIP_SOCKET;

	ddp->dst_socket = ZIP_SOCKET;
	NET_ASSIGN(ddp->dst_net, RouterNet);
	ddp->dst_node = RouterNode;

	ddp->type = DDP_ZIP;

	return (m);
} /* zip_prep_query_packet */


/*
 * zip_send_queries: this function send queries for the routing table entries that
 *     need to know their zones. It scans the routing table for entries with unknown
 *     zones and build Query packets accordingly.
 *     Note: this is called on a per port basis.
 */

void zip_send_queries(ifID, RouterNet, RouterNode)
     register at_ifaddr_t	*ifID;
     at_net_al	RouterNet;		/* we want to send the Zip Query to that router */
     at_node		RouterNode;
{
	RT_entry *Entry = &RT_table[0];
	register gbuf_t *m;
	register at_ddp_t	*ddp;
	int status;
	short Query_index, EntryNumber = 0 ;
	register u_char port = ifID->ifPort;
	char *QueryBuff, *ZoneCount;
	short zip_sent = FALSE;

newPacket:

	if (!(m = zip_prep_query_packet(ifID, RouterNet, RouterNode))) {
		return; /* was return (ENOBUFS); */
	}

	ddp = (at_ddp_t *)(gbuf_rptr(m));
	QueryBuff = (char *)ddp->data;
	
	*QueryBuff++ = ZIP_QUERY;
	ZoneCount = QueryBuff;	/* network count */
	*ZoneCount = 0;
	QueryBuff++;
	Query_index = 2;	
	

	while (EntryNumber < RT_maxentry) {

		/* scan the table, and build the packet with the right entries:
		 *  - entry in use and on the right Port
		 *  - with unknwon zones and in an active state
		 *	- talking to the right router
		 */

		if ((Query_index) > 2*254 +2) {
	
			/* we need to send the packet now, but we can't have more than 256
			 * requests for networks: the Netcount field is a 8bit in the zip query
			 * packet format as defined in Inside Atalk
			 */

			dPrintf(D_M_ZIP_LOW, D_L_OUTPUT,
				("zip_send_query: FULL query for %d nets on port#%d.(len=%d)\n",
				 *ZoneCount, port, Query_index));
			zip_sent = TRUE;

			gbuf_winc(m,DDP_X_HDR_SIZE + Query_index);
			DDPLEN_ASSIGN(ddp, DDP_X_HDR_SIZE + Query_index);

			if ((status = 
			     ddp_router_output(m, ifID, AT_ADDR,
					       RouterNet, RouterNode, 0))) { 
				dPrintf(D_M_ZIP, D_L_ERROR,
					("zip_send_query: ddp_router_output returns =%d\n", status));
				return; /* was return (status); */
			}

			goto newPacket;
		}


		if (((Entry->EntryState & 0x0F) >= RTE_STATE_SUSPECT) &&
			(Entry->NetStop) && (Entry->NetPort == port) &&
			(!RT_ALL_ZONES_KNOWN(Entry))){

			/* we're ready to had that to our list of stuff to send */

			if (Entry->NetStart) { /* extended net*/

				*QueryBuff++ = (Entry->NetStart & 0xFF00) >> 8;
				*QueryBuff++ = (Entry->NetStart & 0x00FF);

			}
			else {
				*QueryBuff++ = (Entry->NetStop & 0xFF00) >> 8;
				*QueryBuff++ = (Entry->NetStop & 0x00FF);
			}

			Query_index += 2;
			*ZoneCount += 1;/* bump the number of network requested */
			
		}

		Entry++;
		EntryNumber++;

	}

	dPrintf(D_M_ZIP_LOW, D_L_OUTPUT,
	 ("zip_send_query: query for %d nets on port#%d.(len=%d)\n",
	 *ZoneCount, port, Query_index));

	if (*ZoneCount) { 	/* non-full Query needs to be sent */
		zip_sent = TRUE;
		gbuf_winc(m,DDP_X_HDR_SIZE + Query_index);
		DDPLEN_ASSIGN(ddp, DDP_X_HDR_SIZE + Query_index);

		if ((status = 
		     ddp_router_output(m, ifID, AT_ADDR,
				       RouterNet, RouterNode, 0))) { 
			dPrintf(D_M_ZIP, D_L_ERROR, 
				("zip_send_query: ddp_router_output returns =%d\n",
				 status));
			return; /* was return (status); */
		}
	}
	else
		gbuf_freem(m);

	if (!zip_sent) /* we didn't need to send anything for that port */
		ifID->ifZipNeedQueries = 0;
} /* zip_send_queries */

/* zip_reply_received: we recieved the reply to one of our query, update the
 *                     zone bitmap and stuffs with was we received.
 *		we receive two types of replies: non extended and extended.
 *	    For extended replies, the network count is the Total of zones for that net.
 */

zip_reply_received(m, ifID, reply_type)
     register gbuf_t	*m;
     register at_ifaddr_t	*ifID;
     int	reply_type;
{
	register at_nvestr_t	*zname;
	RT_entry *Entry = &RT_table[0];
	register at_ddp_t	*ddp;
	at_net_al Network;
	u_short payload_len, result;
	u_char network_count;
	char *PacketPtr;

	ddp = (at_ddp_t *)gbuf_rptr(m);

	/* access the number of nets provided in the ZIP Reply */

	network_count  = ntohs(*(u_char *)(gbuf_rptr(m) + DDP_X_HDR_SIZE + 1));

	PacketPtr = (char *)(gbuf_rptr(m) + DDP_X_HDR_SIZE + 2);

	payload_len = DDPLEN_VALUE(ddp) - (DDP_X_HDR_SIZE + 2);

	dPrintf(D_M_ZIP_LOW, D_L_INPUT, ("zip_reply_received from %d:%d type=%d netcount=%d\n",
			NET_VALUE(ddp->src_net), ddp->src_node, reply_type, network_count));


	while (payload_len > 0 && network_count >0) {

		Network = ntohs(*(at_net_al *)PacketPtr);
		PacketPtr += 2;
		zname = (at_nvestr_t *)PacketPtr;
		if (payload_len)
			payload_len = payload_len -(zname->len + 3);
		
		if (zname->len <= 0) { /* not valid, we got a problem here... */
			dPrintf(D_M_ZIP, D_L_WARNING,
			 ("zip_reply_received: Problem zlen=0 for net=%d from %d:%d type=%d netcnt=%d\n",
			 Network, NET_VALUE(ddp->src_net), ddp->src_node, reply_type, network_count));
			payload_len =0;
			continue;
		}

			
		Entry = rt_blookup(Network);

		if (Entry != NULL) { 
	
			if (Entry->EntryState >= RTE_STATE_SUSPECT)  { 

				result = zt_add_zonename(zname);

				if (result == ZT_MAXEDOUT) {

					dPrintf(D_M_ZIP, D_L_ERROR,
						("zip_reply_received: ZTable full from %d:%d on zone '%s'\n",
						 NET_VALUE(ddp->src_net), ddp->src_node, zname->str));
					ErrorZIPoverflow = 1;
					return(1);
				}	
				
				zt_set_zmap(result, Entry->ZoneBitMap);

				RT_SET_ZONE_KNOWN(Entry);

			}
			else {
				dPrintf(D_M_ZIP, D_L_INPUT,
					("zip_reply_received: entry %d-%d not updated, cause state=%d\n",
					 Entry->NetStart, Entry->NetStop, Entry->EntryState));
			}
		}
		else {
			dPrintf(D_M_ZIP, D_L_WARNING,
				("zip_reply_received: network %d not found in RT\n", Network));
		}

		
		/* now bump the PacketPtr pointer */
		PacketPtr += zname->len + 1;
		network_count--;
	}

	if ((reply_type == ZIP_REPLY) && network_count > 0) {
		if (Entry)
			dPrintf(D_M_ZIP, D_L_WARNING,
			("zip_reply_received: Problem decoding zone (after net:%d-%d)\n",
			Entry->NetStart, Entry->NetStop));
		ifID->ifZipNeedQueries = 1;
	}
	else {
		ifID->ifZipNeedQueries = 0;
		if (Entry)
			dPrintf(D_M_ZIP_LOW, D_L_INFO,
			("zip_reply_received: entry %d-%d all zones known\n",
			Entry->NetStart, Entry->NetStop));
	}
}

/*
 * zip_reply_to_getmyzone: replies to ZIP GetMyZone received from the Net
 */

static void zip_reply_to_getmyzone (ifID, m)
     register at_ifaddr_t   *ifID;
     register gbuf_t      *m;
{
        at_atp_t            *atp;
        register at_ddp_t   *ddp;
        register at_ddp_t *r_ddp;
        register at_atp_t *r_atp;
        register gbuf_t          *rm; /* reply message */
        register int    size, Index, status;
		char *data_ptr;
		RT_entry *Entry;
        u_long  ulongtmp;

        size = DDP_X_HDR_SIZE + ATP_HDR_SIZE + 1 + ifID->ifZoneName.len;
        /* space for two headers and the zone name */
        if ((rm = gbuf_alloc(AT_WR_OFFSET+size, PRI_HI)) == NULL) {
		dPrintf(D_M_ZIP, D_L_WARNING,
			("zip_reply_to_getmyzone: no buffer, port=%d\n", ifID->ifPort));
                return; /* was return (ENOBUFS); */
		}
        gbuf_rinc(rm,AT_WR_OFFSET);
        gbuf_wset(rm,size);
        r_ddp = (at_ddp_t *)(gbuf_rptr(rm));
        r_atp = (at_atp_t *)r_ddp->data;

        ddp = (at_ddp_t *)gbuf_rptr(m);
        if (gbuf_len(m) > DDP_X_HDR_SIZE)
                atp = (at_atp_t *)(gbuf_rptr(m) + DDP_X_HDR_SIZE);
        else
                atp = (at_atp_t *)(gbuf_rptr(gbuf_cont(m)));

        /* fill up the ddp header for reply */
        DDPLEN_ASSIGN(r_ddp, size);
        r_ddp->hopcount = r_ddp->unused = 0;
        UAS_ASSIGN(r_ddp->checksum, 0);

        NET_ASSIGN(r_ddp->src_net, ifID->ifThisNode.s_net);
        NET_NET(r_ddp->dst_net, ddp->src_net);

        r_ddp->src_node = ifID->ifThisNode.s_node;
        r_ddp->dst_node = ddp->src_node;

        r_ddp->dst_socket = ddp->src_socket;
        r_ddp->src_socket = ZIP_SOCKET;
        r_ddp->type = DDP_ATP;

        /* fill up the atp header */
        r_atp->cmd = ATP_CMD_TRESP;
        r_atp->xo = 0;
        r_atp->eom = 1;
        r_atp->sts = 0;
        r_atp->xo_relt = 0;
        r_atp->bitmap = 0;
        UAS_UAS(r_atp->tid, atp->tid);
        ulongtmp = 1;
		UAL_ASSIGN_HTON(r_atp->user_bytes, ulongtmp); /* no of zones */

	data_ptr = (char *)r_atp->data;

        /*
	 * fill up atp data part  with the zone name if we can find it...
         */

	Entry = rt_blookup(NET_VALUE(ddp->src_net));
	if (Entry != NULL && ((Entry->EntryState & 0x0F) >= RTE_STATE_SUSPECT) &&
	    RT_ALL_ZONES_KNOWN(Entry)) { /* this net is well known... */
	
		Index = zt_ent_zindex(Entry->ZoneBitMap) -1;
			
		*data_ptr = ZT_table[Index].Zone.len;	
		bcopy((caddr_t) &ZT_table[Index].Zone.str, (caddr_t) ++data_ptr,
		      ZT_table[Index].Zone.len); 

		/* all set to send the packet back up */
		dPrintf(D_M_ZIP_LOW, D_L_OUTPUT,
			("zip_reply_to_GMZ: ddp_router_output to %d:%d port %d\n", 
			 NET_VALUE(r_ddp->dst_net), r_ddp->dst_node, ifID->ifPort));

		if ((status = 
		     ddp_router_output(rm, ifID, AT_ADDR,
				       NET_VALUE(r_ddp->dst_net), r_ddp->dst_node, 0))) {
		  dPrintf(D_M_ZIP, D_L_ERROR,
			  ("zip_reply_to_GMZ: ddp_r_output returns =%d\n", status));
		  return; /* was return (status); */
		}
	}
	else 
		gbuf_freem(rm);
}

/*
 * zip_reply_to_getzonelist: replies to ZIP GetZoneList requested from the Net
 */

zip_reply_to_getzonelist (ifID, m)
     register at_ifaddr_t   *ifID;
     register gbuf_t      *m;
{
        at_atp_t            *atp;
        register at_ddp_t   *ddp;
        register at_ddp_t *r_ddp;
        register at_atp_t *r_atp;
        register gbuf_t          *rm; /* reply message */
        register int    size, status;
		register short	Index=0, StartPoint, ZLength, PacketLen=0;
        u_long  ulongtmp= 0;
		char *Reply;

        ddp = (at_ddp_t *)gbuf_rptr(m);
        if (gbuf_len(m) > DDP_X_HDR_SIZE)
                atp = (at_atp_t *)(gbuf_rptr(m) + DDP_X_HDR_SIZE);
        else
                atp = (at_atp_t *)(gbuf_rptr(gbuf_cont(m)));


        /* space for two headers and the zone name */

        if ((rm = gbuf_alloc(AT_WR_OFFSET+1024, PRI_HI)) == NULL) {
                return (ENOBUFS);
		}

        gbuf_rinc(rm,AT_WR_OFFSET);
        gbuf_wset(rm,0);
        r_ddp = (at_ddp_t *)(gbuf_rptr(rm));
        r_atp = (at_atp_t *)r_ddp->data;

        /* fill up the ddp header for reply */

        r_ddp->hopcount = r_ddp->unused = 0;
        UAS_ASSIGN(r_ddp->checksum, 0);
        NET_ASSIGN(r_ddp->src_net, ifID->ifThisNode.s_net);
        NET_NET(r_ddp->dst_net, ddp->src_net);
        r_ddp->src_node = ifID->ifThisNode.s_node;
        r_ddp->dst_node = ddp->src_node;
        r_ddp->dst_socket = ddp->src_socket;
        r_ddp->src_socket = ZIP_SOCKET;
        r_ddp->type = DDP_ATP;

        /* fill up the atp header */

        r_atp->cmd = ATP_CMD_TRESP;
        r_atp->xo = 0;
        r_atp->eom = 1;
        r_atp->sts = 0;
        r_atp->xo_relt = 0;
        r_atp->bitmap = 0;
        UAS_UAS(r_atp->tid, atp->tid);

		Reply = (char *)r_atp->data;

			/* get the start index from the ATP request */

		StartPoint = (UAL_VALUE_NTOH(atp->user_bytes) & 0xffff) -1;

		/* find the next zone to send */

		while ((Index < ZT_maxentry) && StartPoint > 0) {
			if (ZT_table[Index].Zone.len)
				StartPoint--;
			Index++;
		}


		dPrintf(D_M_ZIP_LOW, D_L_OUTPUT, ("zip_reply_to_GZL: Index=%d\n", Index));
        /*
		 * fill up atp data part  with the zone name if we can find it...
         */

		while (Index < ZT_maxentry) {

			ZLength = ZT_table[Index].Zone.len;

			if (ZT_table[Index].ZoneCount && ZLength) {
		

				if (PacketLen + 8 + ZLength+1 > DDP_DATA_SIZE) /* packet full */
					break;

				*Reply++ = ZLength;
				bcopy((caddr_t) &ZT_table[Index].Zone.str, 
				      Reply, ZLength);
				Reply += ZLength;
				PacketLen += ZLength + 1;
				ulongtmp++;
			}
			Index++;
		}

		if (Index >= ZT_maxentry) /* this is the end of the list */

				ulongtmp += 0x01000000;

        
		UAL_ASSIGN_HTON(r_atp->user_bytes, ulongtmp); /* # of zones and flag*/

        size = DDP_X_HDR_SIZE + ATP_HDR_SIZE + PacketLen;
        gbuf_winc(rm,size);
        DDPLEN_ASSIGN(r_ddp, size);

        /* all set to send the packet back up */

		dPrintf(D_M_ZIP_LOW, D_L_OUTPUT,
			("zip_r_GZL: send packet to %d:%d port %d atp_len =%d\n",
			NET_VALUE(r_ddp->dst_net), r_ddp->dst_node, ifID->ifPort, PacketLen));


		if (status= ddp_router_output(rm, ifID, AT_ADDR,
				 NET_VALUE(r_ddp->dst_net), r_ddp->dst_node, 0)) {
			dPrintf(D_M_ZIP, D_L_ERROR, ("zip_reply_to_GZL: ddp_router_output returns=%d\n",
				 status));
			return (status);
		}
        return (0);
			
}

/*
 * zip_reply_to_getlocalzones: replies to ZIP GetLocalZones requested from the Net
 */

int zip_reply_to_getlocalzones (ifID, m)
     register at_ifaddr_t   *ifID;
     register gbuf_t      *m;
{
        at_atp_t            *atp;
        register at_ddp_t   *ddp;
        register at_ddp_t *r_ddp;
        register at_atp_t *r_atp;
        register gbuf_t          *rm; /* reply message */
        int    size, status;
		short	Index, Index_wanted, ZLength;
		short i,j, packet_len;
		short  zCount, ZoneCount, ZonesInPacket;
		char *zmap, last_flag = 0;
		RT_entry *Entry;
		char *Reply;

        u_long  ulongtmp = 0;

		Index = Index_wanted = ZLength = i = j = packet_len = zCount = ZoneCount =
		ZonesInPacket = 0;
        
        ddp = (at_ddp_t *)gbuf_rptr(m);
        if (gbuf_len(m) > DDP_X_HDR_SIZE)
                atp = (at_atp_t *)(gbuf_rptr(m) + DDP_X_HDR_SIZE);
        else
                atp = (at_atp_t *)(gbuf_rptr(gbuf_cont(m)));

        /* space for two headers and the zone name */

        if ((rm = gbuf_alloc(AT_WR_OFFSET+1024, PRI_HI)) == NULL) {
                return (ENOBUFS);
		}

        gbuf_rinc(rm,AT_WR_OFFSET);
        gbuf_wset(rm,0);
        r_ddp = (at_ddp_t *)(gbuf_rptr(rm));
        r_atp = (at_atp_t *)r_ddp->data;

	Reply = (char *)r_atp->data;


	/* get the start index from the ATP request */

	Index_wanted = (UAL_VALUE_NTOH(atp->user_bytes) & 0xffff) -1;

	dPrintf(D_M_ZIP_LOW, D_L_INFO, 
		("zip_r_GLZ: for station %d:%d Index_wanted = %d\n",
		 NET_VALUE(ddp->src_net), ddp->src_node, Index_wanted));

	Entry = rt_blookup(NET_VALUE(ddp->src_net));

	if (Entry != NULL && ((Entry->EntryState & 0x0F) >= RTE_STATE_SUSPECT) &&
		 RT_ALL_ZONES_KNOWN(Entry)) { /* this net is well known... */
	
		ZoneCount = zt_ent_zcount(Entry) ;

		dPrintf(D_M_ZIP_LOW, D_L_INFO, 
			("zip_reply_GLZ: for %d:%d ZoneCount=%d\n",
			 NET_VALUE(ddp->src_net), ddp->src_node, ZoneCount));

		zmap = &Entry->ZoneBitMap[0];

		/*
		 * first of all, we want to find the "first next zone" in the bitmap,
		 * to do so, we need to scan the bitmap and add the number of valid
		 * zones we find until we reach the next zone to be sent in the reply
		 */

		if (ZoneCount > Index_wanted) {

			ZoneCount -= Index_wanted;

			/* find the starting point in the bitmap according to index */

			for (i = 0; Index_wanted >= 0 && i < ZT_BYTES; i++) 
				if (zmap[i]) {
					if (Index_wanted < 8) {	
						/* how many zones in the bitmap byte */
						for (j = 0, zCount =0; j < 8 ; j++)
							if ((zmap[i] << j) & 0x80)
								zCount++;
						if (Index_wanted < zCount) {
						  for (j = 0 ; Index_wanted > 0 && j < 8 ; j++)
						  	if ((zmap[i] << j) & 0x80)
							  Index_wanted--;
						  break;
						}
						else
						  Index_wanted -= zCount;
						}
					else 
						for (j = 0 ; j < 8 ; j++)
							if ((zmap[i] << j) & 0x80)
								Index_wanted--;
				}
						
			/*
			 * now, we point to the begining of our next zones in the bitmap
			 */

			while (i < ZT_BYTES) {

				if (zmap[i]) {
					for (; j < 8 ; j++)
						if ((zmap[i] << j) & 0x80) {
						  Index = i*8 + j;	/* get the index in ZT */
						  
						  ZLength = ZT_table[Index].Zone.len;

						  if (ZT_table[Index].ZoneCount && ZLength) {
						    if (packet_len + ATP_HDR_SIZE + ZLength + 1 >
							DDP_DATA_SIZE)
						      goto FullPacket;

						    *Reply++ = ZLength;
						    bcopy((caddr_t) &ZT_table[Index].Zone.str,
							  Reply, ZLength);
						    Reply += ZLength;
						    packet_len += ZLength + 1;
						    ZonesInPacket ++;
						    dPrintf(D_M_ZIP_LOW, D_L_INFO,
							    ("zip_reply_GLZ: add z#%d to packet (l=%d)\n",
							     Index, packet_len));
						  }
						  else {
						    dPrintf(D_M_ZIP, D_L_WARNING,
							    ("zip_reply_GLZ: no len for index=%d\n",
							     Index));
						  }
						}
				}
				i++;
				j = 0;
			}
		}
		else /* set the "last flag" bit  in the reply */
			last_flag = 1;
	}
	else /* set the "last flag" bit  in the reply */
		last_flag = 1;

FullPacket:

	if (ZonesInPacket == ZoneCount)
			last_flag = 1;


        /* fill up the ddp header for reply */

        r_ddp->hopcount = r_ddp->unused = 0;
        UAS_ASSIGN(r_ddp->checksum, 0);

        NET_ASSIGN(r_ddp->src_net, ifID->ifThisNode.s_net);
        NET_NET(r_ddp->dst_net, ddp->src_net);

        r_ddp->src_node = ifID->ifThisNode.s_node;
        r_ddp->dst_node = ddp->src_node;

        r_ddp->dst_socket = ddp->src_socket;
        r_ddp->src_socket = ZIP_SOCKET;
        r_ddp->type = DDP_ATP;

        /* fill up the atp header */
        r_atp->cmd = ATP_CMD_TRESP;
        r_atp->xo = 0;
        r_atp->eom = 1;
        r_atp->sts = 0;
        r_atp->xo_relt = 0;
        r_atp->bitmap = 0;
        UAS_UAS(r_atp->tid, atp->tid);
        ulongtmp =  ((last_flag << 24) & 0xFF000000) + ZonesInPacket; /* # of zones and flag*/
		UAL_ASSIGN_HTON(r_atp->user_bytes, ulongtmp);
        size = DDP_X_HDR_SIZE + ATP_HDR_SIZE + packet_len;
        gbuf_winc(rm,size);
        DDPLEN_ASSIGN(r_ddp, size);

        /* all set to send the packet back up */

	dPrintf(D_M_ZIP_LOW, D_L_OUTPUT,
		("zip_r_GLZ: send packet to %d:%d port %d atp_len =%d\n",
		 NET_VALUE(r_ddp->dst_net), r_ddp->dst_node, ifID->ifPort, packet_len));

	if (status= ddp_router_output(rm, ifID, AT_ADDR,
				      NET_VALUE(r_ddp->dst_net), r_ddp->dst_node, 0)) {
		dPrintf(D_M_ZIP, D_L_ERROR, 
			("zip_reply_to_GLZ: ddp_router_output returns =%d\n",
			 status));
		return (status);
	}
        return (0);
} /* zip_reply_to_getlocalzones */

int regDefaultZone(ifID)
     at_ifaddr_t *ifID;
{
	int i;
	char data[ETHERNET_ADDR_LEN];

	if (!ifID)
		return(-1);

	zt_get_zmcast(ifID, &ifID->ifZoneName, data); 
	if (FDDI_OR_TOKENRING(ifID->aa_ifp->if_type))
		ddp_bit_reverse(data);
	bcopy((caddr_t)data, (caddr_t)&ifID->ZoneMcastAddr, ETHERNET_ADDR_LEN);
	(void)at_reg_mcast(ifID, (caddr_t)&ifID->ZoneMcastAddr);
	return(0);
}
