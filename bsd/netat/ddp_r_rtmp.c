/*
 * Copyright (c) 1994, 1996-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*--------------------------------------------------------------------------
 * Router RTMP protocol functions: 
 *
 * This file contains Routing specifics to handle RTMP packets and
 * the maintenance of the routing table through....
 *
 * The entry point for the rtmp input in ddp is valid only when we're
 * running in router mode. 
 *
 *
 * 0.01 03/22/94	Laurent Dumont		Creation
 *    Modified for MP, 1996 by Tuyen Nguyen
 *    Added AURP support, April 8, 1996 by Tuyen Nguyen
 *   Modified, March 17, 1997 by Tuyen Nguyen for MacOSX.
 *
 *-------------------------------------------------------------------------
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
#include <kern/locks.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <net/if.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/at_var.h>
#include <netat/ddp.h>
#include <netat/rtmp.h>
#include <netat/at_pcb.h>
#include <netat/zip.h>
#include <netat/routing_tables.h>
#include <netat/aurp.h>
#include <netat/debug.h>

#include <sys/kern_event.h>

extern void (*ddp_AURPsendx)();
extern at_ifaddr_t *aurp_ifID;
extern at_ifaddr_t *ifID_table[];
extern at_ifaddr_t *ifID_home;

/*DEBUG ONLY */
static int dump_counter =0;
/*DEBUG ONLY */

static at_kern_err_t ke; 
			/* Used to record error discovered in rtmp_update() */
gbuf_t *rtmp_prep_new_packet();

void rtmp_timeout();
void rtmp_send_port();
void rtmp_send_port_locked();
void rtmp_dropper(void *);
void rtmp_shutdown();
static void rtmp_update();
static void rtmp_request();
extern int elap_online3();

extern pktsIn, pktsOut, pktsDropped, pktsHome;
extern short ErrorRTMPoverflow, ErrorZIPoverflow;
extern lck_mtx_t * atalk_mutex;

/*
 * rtmp_router_input: function called by DDP (in router mode) to handle
 *                    all incoming RTMP packets. Listen to the RTMP socket
 *                    for all the connected ports.
 *					  Switch to the relevant rtmp functions.
 */

void rtmp_router_input(mp, ifID)
     register gbuf_t  *mp;
     register at_ifaddr_t        *ifID;
{
        register at_ddp_t *ddp = (at_ddp_t *)gbuf_rptr(mp);
                          /* NOTE: there is an assumption here that the
			   * DATA follows the header. */

	register at_net_al OurNet;
	register at_node OurNode;
	register at_net_al DstNet;
	register at_node DstNode;
	short tuples;
	RT_entry *Entry;

    	if (!ifID || (ifID->ifRoutingState < PORT_ACTIVATING)) {
                gbuf_freem(mp);
                return;
        }


	OurNet = ifID->ifThisNode.s_net;
	OurNode = ifID->ifThisNode.s_node;


        if (gbuf_type(mp) != MSG_DATA) {

                /* If this is a M_ERROR message, DDP is shutting down,
                 * nothing to do here...If it's something else, we don't
                 * understand what it is
                 */
		dPrintf(D_M_RTMP, D_L_WARNING, 
			("rtmp_router_input: Not an M_DATA type\n"));
                gbuf_freem(mp);
                return;
        }

	DstNet = NET_VALUE(ddp->dst_net);
	DstNode = ddp->dst_node;

	/* check the kind of RTMP packet we received */

	switch (ddp->type) {

	case DDP_RTMP:
				
		tuples = gbuf_len(mp) - DDP_X_HDR_SIZE - RTMP_IDLENGTH;
		/*
		 * we need to make sure that the size of 'tuples' is
		 * not less than or equal to 0 due to a bad packet
		 */
		if (tuples <= 0) {
			gbuf_freem(mp);
			break;
		}

		if (tuples % 3)	{/* not a valid RTMP data packet */
			gbuf_freem(mp);
			dPrintf(D_M_RTMP, D_L_WARNING,
				("rtmp_input: bad number of tuple in RTMP packet\n"));
			return;
		}

		tuples = tuples / 3;
		
		rtmp_update(ifID, (at_rtmp *)ddp->data, tuples);
		gbuf_freem(mp);
					
		break;

	case DDP_RTMP_REQ:

		/* we should treat requests a bit differently.
		 * - if the request if not for the port, route it and also respond
		 *   for this port if not locally connected.
		 * - if the request for this port, then just respond to it.
		 */

		if (!ROUTING_MODE) {
			gbuf_freem(mp);
			return;
		}
		if (DstNode == 255) {
			if (((DstNet >= CableStart) && (DstNet <= CableStop)) ||
			    DstNet == 0) {
				rtmp_request(ifID, ddp);
				gbuf_freem(mp);
				return;
			}
			else {
				/* check if directly connected port */
				if ((Entry = rt_blookup(DstNet)) &&
				    (Entry->NetDist == 0)) {
				  dPrintf(D_M_RTMP, D_L_WARNING, 
					  ("rtmp_router_input: request for %d.%d, port %d\n",
					   DstNet, DstNode, Entry->NetPort));
				  rtmp_request(ifID_table[Entry->NetPort], ddp);
				  gbuf_freem(mp);
				  return;
				}
				else {
				  dPrintf(D_M_RTMP, D_L_WARNING,
					  ("rtmp_router_input: RTMP packet received for %d.%d, also forward\n",
					   NET_VALUE(ddp->dst_net),ddp->dst_node));
				  routing_needed(mp, ifID, TRUE);
				  return;
				}
			}
		}
		else {

			if ((DstNode == OurNode) && (DstNet == OurNet)) {
				rtmp_request(ifID, ddp);
				gbuf_freem(mp);
				return;
			}
			else  {
			  dPrintf(D_M_RTMP, D_L_WARNING,
				  ("rtmp_router_input: RTMP packet received for %d.%d, forward\n",
				   NET_VALUE(ddp->dst_net), ddp->dst_node));
			  routing_needed(mp, ifID, TRUE);
			}
		}

		break;

	default:

		dPrintf(D_M_RTMP, D_L_WARNING,
			("rtmp_input: RTMP packet type=%d, route it\n", ddp->type));
		routing_needed(mp, ifID, TRUE);
		break;

	}	
} /* rtmp_router_input */

/*
 * rtmp_update:
 *
 */

static void rtmp_update(ifID, rtmp, tuple_nb)
     register at_ifaddr_t 	*ifID;
     register at_rtmp 	*rtmp;
     register short	tuple_nb;
{
	register int PortFlags = ifID->ifFlags;
	register at_rtmp_tuple *FirstTuple =  (at_rtmp_tuple *)&rtmp->at_rtmp_id[1];
	register at_rtmp_tuple *SecondTuple = (at_rtmp_tuple *)&rtmp->at_rtmp_id[4];
	RT_entry NewRoute, *CurrentRoute;

	register u_char SenderNodeID = rtmp->at_rtmp_id[0];
	char *TuplePtr;
	short state;


	/* Make sure this an AppleTalk node sending us the RTMP packet */

	if (rtmp->at_rtmp_id_length  != 8) {
		dPrintf(D_M_RTMP, D_L_WARNING,
			("rtmp_update : RTMP ID not as expected Net=%d L=x%x\n", 
			 NET_VALUE(rtmp->at_rtmp_this_net), rtmp->at_rtmp_id_length));
		return;
	}

	/*
	 * If the port is activating, only take the Network range from the
         * the RTMP packet received.
	 * Check if there is a conflict with our seed infos.
         */

	if (ifID->ifRoutingState == PORT_ACTIVATING) {
		if (PortFlags & RTR_XNET_PORT) {
			if ((PortFlags & RTR_SEED_PORT) &&
			    ((CableStart != TUPLENET(FirstTuple)) ||
			     (CableStop != TUPLENET(SecondTuple)))) {
				ifID->ifRoutingState = PORT_ERR_SEED;
				ke.error 	= KE_CONF_SEED_RNG;
				ke.port1 	= ifID->ifPort;
				strlcpy(ke.name1, ifID->ifName, sizeof(ke.name1));
				ke.net 		=  NET_VALUE(rtmp->at_rtmp_this_net);
				ke.node     = SenderNodeID;
				ke.netr1b 	= TUPLENET(FirstTuple);
				ke.netr1e 	= TUPLENET(SecondTuple);
				ke.netr2b 	= CableStart;
				ke.netr2e	= CableStop;
				RouterError(ifID->ifPort, ERTR_SEED_CONFLICT);
				return;
			}
			CableStart = TUPLENET(FirstTuple);
			CableStop  = TUPLENET(SecondTuple); 
/*
			dPrintf(D_M_RTMP, D_L_INFO,
				("rtmp_update: Port #%d activating, set Cable %d-%d\n",
				ifID->ifPort, CableStart, CableStop));
*/
		}
		else { /* non extended cable */
			if ((PortFlags & RTR_SEED_PORT) &&
			    (ifID->ifThisCableEnd != NET_VALUE(rtmp->at_rtmp_this_net))) {
				ke.error 	= KE_CONF_SEED1;
				ke.port1 	= ifID->ifPort;
				strlcpy(ke.name1, ifID->ifName,sizeof(ke.name1));
				ke.net 		=  NET_VALUE(rtmp->at_rtmp_this_net);
				ke.node     = SenderNodeID;
				ke.netr1e 	= ifID->ifThisCableEnd;
				ifID->ifRoutingState = PORT_ERR_SEED;
				RouterError(ifID->ifPort, ERTR_SEED_CONFLICT);
				return;
			}
			CableStop =  NET_VALUE(rtmp->at_rtmp_this_net);
			CableStart = 0;
			dPrintf(D_M_RTMP, D_L_INFO,
				("rtmp_update: Port #%d NONX activating, set Cable %d-%d\n",
				 ifID->ifPort, CableStart, CableStop));
		}
	}
	
	/*
	 * Perform a few sanity checks on the received RTMP data packet
         */

	if ((PortFlags & RTR_XNET_PORT) && (tuple_nb >= 2)) {

		/* The first tuple must be extended */

		if (! TUPLERANGE(FirstTuple)) {
			dPrintf(D_M_RTMP, D_L_WARNING,
				("rtmp_update: bad range value in 1st tuple =%d\n",
				 TUPLERANGE(FirstTuple)));
			return;
		}

		if (PortFlags & RTR_SEED_PORT)
			if ((TUPLENET(FirstTuple) != CableStart) ||
			    (TUPLENET(SecondTuple) != CableStop)) {
				dPrintf(D_M_RTMP, D_L_WARNING, ("rtmp_update: conflict on Seed Port\n"));
				ifID->ifRoutingState = PORT_ERR_CABLER;
				ke.error 	= KE_CONF_SEED_NODE;
				ke.port1 	= ifID->ifPort;
				strlcpy(ke.name1, ifID->ifName,sizeof(ke.name1));
				ke.net 		=  NET_VALUE(rtmp->at_rtmp_this_net);
				ke.node     = SenderNodeID;
				ke.netr1b 	= TUPLENET(FirstTuple);
				ke.netr1e 	= TUPLENET(SecondTuple);
				ke.netr2b 	= CableStart;
				ke.netr2e	= CableStop;
				RouterError(ifID->ifPort, ERTR_CABLE_CONFLICT);	
				return;
			}

		/* check that the tuple matches the range */

		if ((TUPLENET(SecondTuple) < TUPLENET(FirstTuple)) ||
		    (TUPLENET(FirstTuple) == 0) ||
		    (TUPLENET(FirstTuple) >= DDP_STARTUP_LOW) ||
		    (TUPLENET(SecondTuple) == 0) ||
		    (TUPLENET(SecondTuple) >= DDP_STARTUP_LOW)) {
					
			/*
			 * IS THIS NON-FATAL?????
			 */
			dPrintf(D_M_RTMP, D_L_WARNING,
				("rtmp_update: STARTUP RANGE!!! 1st %d-%d\n",
				 TUPLENET(FirstTuple), TUPLENET(SecondTuple)));
			ifID->ifRoutingState = PORT_ERR_STARTUP;
			ke.error 	= KE_SEED_STARTUP;
			ke.port1 	= ifID->ifPort;
			strlcpy(ke.name1, ifID->ifName,sizeof(ke.name1));
			ke.net 		=  NET_VALUE(rtmp->at_rtmp_this_net);
			ke.node     = SenderNodeID;
			RouterError(ifID->ifPort, ERTR_CABLE_STARTUP);
			return;
		}

		if (TUPLEDIST(FirstTuple) != 0) {
			dPrintf(D_M_RTMP, D_L_WARNING,
				("rtmp_update: Invalid distance in 1st tuple\n"));
			return;
		}

		if (rtmp->at_rtmp_id[6] != RTMP_VERSION_NUMBER) {
			dPrintf(D_M_RTMP, D_L_WARNING,
				("rtmp_update: Invalid RTMP version = x%x\n",
				 rtmp->at_rtmp_id[6]));
			return;
		}

	}
	else {	/* non extended interface or problem in tuple*/
		
		if (PortFlags & RTR_XNET_PORT) {
			dPrintf(D_M_RTMP, D_L_WARNING,
				("rtmp_update: invalid number of tuple for X-net\n"));
			return;
		}

		if (TUPLENET(FirstTuple) == 0) { /* non extended RTMP data */

			if (rtmp->at_rtmp_id[3] > RTMP_VERSION_NUMBER) {
				dPrintf(D_M_RTMP, D_L_WARNING,
					("rtmp_update: Invalid non extended RTMP version\n"));
				return;
			}

		}
		else {
			dPrintf(D_M_RTMP, D_L_WARNING,
				("rtmp_update: version 1.0 non Xtended net not supported\n"));
			ifID->ifRoutingState = PORT_ERR_BADRTMP;
			ke.error 	= KE_BAD_VER;
			ke.rtmp_id = rtmp->at_rtmp_id[6];
			ke.net 		=  NET_VALUE(rtmp->at_rtmp_this_net);
			ke.node     = SenderNodeID;
			RouterError(ifID->ifPort, ERTR_RTMP_BAD_VERSION);
			return;
		}			
	}

	NewRoute.NextIRNet  = NET_VALUE(rtmp->at_rtmp_this_net);
	NewRoute.NextIRNode = SenderNodeID;
	NewRoute.NetPort	= ifID->ifPort;

	/* 
	 * Process the case where a non-seed port needs to acquire the right
	 * information.
         */

	if (!(PortFlags & RTR_SEED_PORT) && (ifID->ifRoutingState == PORT_ACTIVATING)) {
		dPrintf(D_M_RTMP_LOW, D_L_INFO,
			("rtmp_update: Port# %d, set non seed cable %d-%d\n",
			 ifID->ifPort, TUPLENET(FirstTuple), TUPLENET(SecondTuple)));

		if (PortFlags & RTR_XNET_PORT) {
			NewRoute.NetStart = TUPLENET(FirstTuple);
			NewRoute.NetStop = TUPLENET(SecondTuple);
			ifID->ifThisCableStart = TUPLENET(FirstTuple);
			ifID->ifThisCableEnd  = TUPLENET(SecondTuple);
				
		}
		else {
		  
			NewRoute.NetStart = 0;
			NewRoute.NetStop  = NET_VALUE(rtmp->at_rtmp_this_net);
			ifID->ifThisCableStart = NET_VALUE(rtmp->at_rtmp_this_net);
			ifID->ifThisCableEnd  = NET_VALUE(rtmp->at_rtmp_this_net);
		}
		/*
		 * Now, check if we already know this route, or we need to add it
		 * (or modify it in the table accordingly)
		 */

		if ((CurrentRoute = rt_blookup(NewRoute.NetStop)) &&
		    (CurrentRoute->NetStop  == NewRoute.NetStop) &&
		    (CurrentRoute->NetStart == NewRoute.NetStart)) {
/*LD 7/31/95 tempo########*/
			if (NewRoute.NetPort != CurrentRoute->NetPort) {
				dPrintf(D_M_RTMP, D_L_WARNING,
					("rtmp_update: port# %d, not the port we waited for %d\n",
					 ifID->ifPort, CurrentRoute->NetPort));
				/* propose to age the entry we know... */
					
				state = CurrentRoute->EntryState & 0x0F;
				/* if entry has been updated recently, just clear the UPDATED 
				   bit. if bit not set, then we can age the entry */
				if (state)
					if (CurrentRoute->EntryState & RTE_STATE_UPDATED) {
						CurrentRoute->EntryState &= ~RTE_STATE_UPDATED; 
					}
					else {
						state  = state >> 1 ;	/* decrement state */
					}

				CurrentRoute->EntryState = (CurrentRoute->EntryState & 0xF0) | state;
			}
		}

		else { /* add the new route */

			dPrintf(D_M_RTMP, D_L_INFO,
				("rtmp_update: P# %d, 1st tuple route not known, add %d-%d\n",
				 ifID->ifPort, NewRoute.NetStart, NewRoute.NetStop));

			NewRoute.EntryState = RTE_STATE_GOOD|RTE_STATE_UPDATED;
			NewRoute.NetDist	= 0;
			
			if (rt_insert(NewRoute.NetStop, NewRoute.NetStart, 0, 
				      0, NewRoute.NetDist, NewRoute.NetPort,
				      NewRoute.EntryState) == (RT_entry *)NULL)
 
				ErrorRTMPoverflow = 1;
		}	

	}

	if (ifID->ifRoutingState == PORT_ACTIVATING) {
		dPrintf(D_M_RTMP, D_L_INFO,
	  		("rtmp_update: port activating, ignoring remaining tuples\n"));
		return;
	}

	/*
	 * Process all the tuples against our routing table
	 */

	TuplePtr = (char *)FirstTuple;

	while (tuple_nb-- > 0) {

		if (TUPLEDIST(TuplePtr) == NOTIFY_N_DIST) {
			dPrintf(D_M_RTMP, D_L_INFO,
				("rtmp_update: Port# %d, Tuple with Notify Neighbour\n",
				 ifID->ifPort));
			NewRoute.NetDist = NOTIFY_N_DIST;
			NewRoute.EntryState = RTE_STATE_BAD;
		}
		else {
			NewRoute.NetDist = TUPLEDIST(TuplePtr) + 1;
			NewRoute.EntryState = RTE_STATE_GOOD;
			NewRoute.EntryState = RTE_STATE_GOOD|RTE_STATE_UPDATED;
		}


		if (TUPLERANGE(TuplePtr)) {	/* Extended Tuple */


			NewRoute.NetStart = TUPLENET(TuplePtr);
			TuplePtr += 3;
			NewRoute.NetStop  = TUPLENET((TuplePtr));
			TuplePtr += 3;
			tuple_nb--;

			if ((NewRoute.NetDist  == 0) ||
			    (NewRoute.NetStart == 0) ||
			    (NewRoute.NetStop  == 0) ||
			    (NewRoute.NetStop  < NewRoute.NetStart) ||
			    (NewRoute.NetStart >= DDP_STARTUP_LOW) ||
			    (NewRoute.NetStop  >= DDP_STARTUP_LOW)) {
					
			  dPrintf(D_M_RTMP, D_L_WARNING,
				  ("rtmp_update: P# %d, non valid xtuple received [%d-%d]\n",
				   ifID->ifPort, NewRoute.NetStart, NewRoute.NetStop));
			  
						continue;
			}
	
		}
		else {		/* Non Extended Tuple */

			NewRoute.NetStart = 0;
			NewRoute.NetStop  = TUPLENET(TuplePtr);
				
			TuplePtr += 3;
			
			if ((NewRoute.NetDist  == 0) ||
			    (NewRoute.NetStop  == 0) ||
			    (NewRoute.NetStop  >= DDP_STARTUP_LOW)) {

			  dPrintf(D_M_RTMP, D_L_WARNING,
				  ("rtmp_update: P# %d, non valid tuple received [%d]\n",
				   ifID->ifPort, NewRoute.NetStop));

			  continue;
			}
		}

		if ((CurrentRoute = rt_blookup(NewRoute.NetStop))) { 
			/* found something... */

			if (NewRoute.NetDist < 16 || 
			    NewRoute.NetDist == NOTIFY_N_DIST ) {

				/*
				 * Check if the definition of the route changed
				 */

				if (NewRoute.NetStop != CurrentRoute->NetStop ||
				    NewRoute.NetStart != CurrentRoute->NetStart) {
						
				  if (NewRoute.NetStop == CurrentRoute->NetStop &&
				      NewRoute.NetStop == CurrentRoute->NetStart &&
				      NewRoute.NetStart == 0)
				
				  	NewRoute.NetStart = NewRoute.NetStop;

				  else if (NewRoute.NetStop == CurrentRoute->NetStop &&
					   NewRoute.NetStart == NewRoute.NetStop &&
					   CurrentRoute->NetStart == 0) {
						dPrintf(D_M_RTMP, D_L_WARNING,
							("rtmp_update: Range %d-%d has changed to %d-%d Dist=%d\n",
							 CurrentRoute->NetStart, CurrentRoute->NetStop,
							 NewRoute.NetStart, NewRoute.NetStop, NewRoute.NetDist));
						NewRoute.NetStart = 0;
				  }

				  else {
					dPrintf(D_M_RTMP, D_L_WARNING,
						("rtmp_update: Net Conflict Cur=%d, New=%d\n", 
						 CurrentRoute->NetStop, NewRoute.NetStop));
					CurrentRoute->EntryState = 
					  (CurrentRoute->EntryState & 0xF0) | RTE_STATE_BAD; 
					continue;

				  }
				}

				/*
				 * If we don't know the associated zones
				 */

				if (!RT_ALL_ZONES_KNOWN(CurrentRoute)) {

					dPrintf(D_M_RTMP_LOW, D_L_INFO,
						("rtmp_update: Zone unknown for %d-%d state=0x%x\n",
						 CurrentRoute->NetStart, CurrentRoute->NetStop,
						 CurrentRoute->EntryState));
					
					/* set the flag in the ifID structure telling
					 * that a scheduling of Zip Query is needed.
					 */

					ifID->ifZipNeedQueries = 1;
					continue;
				}

				if (((CurrentRoute->EntryState & 0x0F) <= RTE_STATE_SUSPECT) &&
				    NewRoute.NetDist != NOTIFY_N_DIST) {
				  
					dPrintf(D_M_RTMP, D_L_INFO,
						("rtmp_update: update suspect entry %d-%d State=%d\n",
						 NewRoute.NetStart, NewRoute.NetStop,
						 (CurrentRoute->EntryState & 0x0F)));

					if (NewRoute.NetDist <= CurrentRoute->NetDist) {
					  CurrentRoute->NetDist 	 = NewRoute.NetDist;
					  CurrentRoute->NetPort 	 = NewRoute.NetPort;
					  CurrentRoute->NextIRNode = NewRoute.NextIRNode;
					  CurrentRoute->NextIRNet  = NewRoute.NextIRNet;
					  CurrentRoute->EntryState = 
					    (CurrentRoute->EntryState & 0xF0) | 
					    (RTE_STATE_GOOD|RTE_STATE_UPDATED); 
					}
					continue;
				}
				else {

					if (NewRoute.NetDist == NOTIFY_N_DIST) {
	
						CurrentRoute->EntryState = 
						  (CurrentRoute->EntryState & 0xF0) | RTE_STATE_SUSPECT; 
						CurrentRoute->NetDist = NOTIFY_N_DIST;
						continue;
					}
				}

			}
			

			if ((NewRoute.NetDist <= CurrentRoute->NetDist) && (NewRoute.NetDist <16)) { 

				 /* Found a shorter or more recent Route,
				  * Replace with the New entryi
				  */

				CurrentRoute->NetDist    = NewRoute.NetDist;
				CurrentRoute->NetPort    = NewRoute.NetPort;
				CurrentRoute->NextIRNode = NewRoute.NextIRNode;
				CurrentRoute->NextIRNet  = NewRoute.NextIRNet;
				CurrentRoute->EntryState |= RTE_STATE_UPDATED; 

				/* Can we consider now that the entry is updated? */	
				dPrintf(D_M_RTMP_LOW, D_L_INFO,
					("rtmp_update: Shorter route found %d-%d, update\n",
					 NewRoute.NetStart, NewRoute.NetStop));

#ifdef AURP_SUPPORT
			if (ddp_AURPsendx && (aurp_ifID->ifFlags & AT_IFF_AURP))
				ddp_AURPsendx(AURPCODE_RTUPDATE,
					      (void *)&NewRoute, AURPEV_NetDistChange);
#endif
			}
		}
		else { /* no entry found */

			if (NewRoute.NetDist < 16 && NewRoute.NetDist != NOTIFY_N_DIST &&
			    NewRoute.NextIRNet >= ifID->ifThisCableStart &&
			    NewRoute.NextIRNet <= ifID->ifThisCableEnd) {
				
				NewRoute.EntryState = (RTE_STATE_GOOD|RTE_STATE_UPDATED);

				dPrintf(D_M_RTMP_LOW, D_L_INFO,
					("rtmp_update: NewRoute %d-%d Tuple #%d\n",
					 NewRoute.NetStart, NewRoute.NetStop, tuple_nb));

				ifID->ifZipNeedQueries = 1;

				if (rt_insert(NewRoute.NetStop, NewRoute.NetStart, NewRoute.NextIRNet, 
					      NewRoute.NextIRNode, NewRoute.NetDist, NewRoute.NetPort,
					      NewRoute.EntryState) == (RT_entry *)NULL)
					ErrorRTMPoverflow = 1;
#ifdef AURP_SUPPORT
				else if (ddp_AURPsendx && (aurp_ifID->ifFlags & AT_IFF_AURP))
					ddp_AURPsendx(AURPCODE_RTUPDATE,
						      (void *)&NewRoute, AURPEV_NetAdded);
#endif
			}		
		}

	} /* end of main while */			
	ifID->ifRouterState = ROUTER_UPDATED;
	if (ifID->ifZipNeedQueries) 
		zip_send_queries(ifID, 0, 0xFF);
	
/*
	timeout(rtmp_timeout, (caddr_t) ifID, 20*SYS_HZ);
*/
} /* rtmp_update */

/* The RTMP validity timer expired, we need to update the
 * state of each routing entry in the table
 * because there is only one validity timer and it is always running,
 * we can't just age all the entries automatically, as we might be
 * aging entries that were just updated. So, when an entry is updated,
 * the RTE_STATE_UPDATED bit is set and when the aging routine is called
 * it just resets this bit if it is set, only if it is not set will the
 * route actually be aged.
 * Note there are 4 states for an entry, the state is decremented until
 * it reaches the bad state. At this point, the entry is removed
 *
 *      RTE_STATE_GOOD   :  The entry was valid (will be SUSPECT)
 *      RTE_STATE_SUSPECT:  The entry was suspect (can still be used for routing)
 *      RTE_STATE_BAD    : 	The entry was bad and is now deleted 
 *      RTE_STATE_UNUSED :  Unused or removed entry in the table
 */

void rtmp_timeout(ifID)
register at_ifaddr_t        *ifID;
{
		register u_char state;
		short i;
		RT_entry *en = &RT_table[0];

		atalk_lock();

		if (ifID->ifRoutingState < PORT_ONLINE) {
			atalk_unlock();
			return;
                }

		/* for multihoming mode, we use ifRouterState to tell if there
           is a router out there, so we know when to use cable multicast */
		if (ifID->ifRouterState > NO_ROUTER)
			ifID->ifRouterState--;

		for (i = 0 ; i < RT_maxentry; i++,en++) {

			/* we want to age "learned" nets, not directly connected ones */
			state  = en->EntryState & 0x0F;


			if (state > RTE_STATE_UNUSED && 
			   !(en->EntryState & RTE_STATE_PERMANENT) && en->NetStop && 
			   en->NetDist && en->NetPort == ifID->ifPort) {

					/* if entry has been updated recently, just clear the UPDATED 
					   bit. if bit not set, then we can age the entry */
				if (en->EntryState & RTE_STATE_UPDATED) {
					en->EntryState &= ~RTE_STATE_UPDATED;
					continue;
				}
				else
					state  = state >> 1 ;	/* decrement state */

				if (state == RTE_STATE_UNUSED)	{/* was BAD, needs to delete */
					dPrintf(D_M_RTMP, D_L_INFO,
						("rtmp_timeout: Bad State for %d-%d (e#%d): remove\n",
							en->NetStart, en->NetStop, i));
#ifdef AURP_SUPPORT
				if (ddp_AURPsendx && (aurp_ifID->ifFlags & AT_IFF_AURP))
					ddp_AURPsendx(AURPCODE_RTUPDATE,
						(void *)en, AURPEV_NetDeleted);
#endif
	
					/* then clear the bit in the table concerning this entry.
					If the zone Count reaches zero, remove the entry */

					zt_remove_zones(en->ZoneBitMap);
					
					RT_DELETE(en->NetStop, en->NetStart);
				}
				else {
					en->EntryState = (en->EntryState & 0xF0) | state;
					dPrintf(D_M_RTMP, D_L_INFO, ("Change State for %d-%d to %d (e#%d)\n",
							en->NetStart, en->NetStop, state, i));
				}
			}
		}
		timeout(rtmp_timeout, (caddr_t) ifID, 20*SYS_HZ);
		
		atalk_unlock();
}
			 
/*
 * rtmp_prep_new_packet: allocate a ddp packet for RTMP use (reply to a RTMP request or
 *                  Route Data Request, or generation of RTMP data packets.
 *		    The ddp header is filled with relevant information, as well as
 *                  the beginning of the rtmp packet with the following info:
 *						Router's net number  (2bytes)
 *						ID Length = 8		 (1byte)
 *						Router's node ID	 (1byte)
 *						Extended Range Start (2bytes)
 *						Range + dist (0x80)  (1byte)
 *						Extended Range End   (2bytes)
 *						Rtmp version (0x82)  (1byte)
 *
 */				
		
gbuf_t *rtmp_prep_new_packet (ifID, DstNet, DstNode, socket)
register at_ifaddr_t        *ifID;
register at_net DstNet;
register u_char DstNode;
register char socket;

{
	gbuf_t		*m;
	register at_ddp_t	*ddp;
	register char * rtmp_data;
	
	if ((m = gbuf_alloc(AT_WR_OFFSET+1024, PRI_HI)) == NULL) {
		dPrintf(D_M_RTMP, D_L_WARNING, ("rtmp_new_packet: Can't allocate mblock\n"));
		return ((gbuf_t *)NULL);
	}

	gbuf_rinc(m,AT_WR_OFFSET); 
	gbuf_wset(m,DDP_X_HDR_SIZE + 10); 
	ddp = (at_ddp_t *)(gbuf_rptr(m));

	/*
	 * Prepare the DDP header of the new packet 
	 */


	ddp->unused = ddp->hopcount = 0;

	UAS_ASSIGN(ddp->checksum, 0);

	NET_NET(ddp->dst_net, DstNet);
	ddp->dst_node =  DstNode;
	ddp->dst_socket = socket;

	NET_ASSIGN(ddp->src_net, ifID->ifThisNode.s_net);
	ddp->src_node = ifID->ifThisNode.s_node;
	ddp->src_socket = RTMP_SOCKET;
	ddp->type = DDP_RTMP;

	/*
	 * Prepare the RTMP header (Router Net, ID, Node and Net Tuple
	 * (this works only if we are on an extended net)
	 */

	rtmp_data = ddp->data;
	
	*rtmp_data++ = (ifID->ifThisNode.s_net & 0xff00) >> 8;
	*rtmp_data++ = ifID->ifThisNode.s_net & 0x00ff ;
	*rtmp_data++ = 8;	
	*rtmp_data++ = (u_char)ifID->ifThisNode.s_node;
	*rtmp_data++ = (CableStart & 0xff00) >> 8;
	*rtmp_data++ = CableStart & 0x00ff ;
	*rtmp_data++ = 0x80;	/* first tuple, so distance is always zero */
	*rtmp_data++ = (CableStop & 0xff00) >> 8;
	*rtmp_data++ = CableStop & 0x00ff ;
	*rtmp_data++ = RTMP_VERSION_NUMBER;

	return (m);


}
int rtmp_r_find_bridge(ifID, orig_ddp)
register at_ifaddr_t    *ifID;
register at_ddp_t 	*orig_ddp;

{
	gbuf_t		*m;
	register int		size, status;
	register at_ddp_t	*ddp;
	register char * rtmp_data;
	RT_entry *Entry;


	/* find the bridge for the querried net */

	Entry = rt_blookup(NET_VALUE(orig_ddp->dst_net));

	if (Entry == NULL) {
		dPrintf(D_M_RTMP, D_L_WARNING, ("rtmp_r_find_bridge: no info for net %d\n",
			 NET_VALUE(orig_ddp->dst_net)));
		return (1);
	}

	
	size = DDP_X_HDR_SIZE + 10 ;
	if ((m = gbuf_alloc(AT_WR_OFFSET+size, PRI_HI)) == NULL) {
		dPrintf(D_M_RTMP, D_L_WARNING, 
			("rtmp_r_find_bridge: Can't allocate mblock\n"));
		return (ENOBUFS);
	}

	gbuf_rinc(m,AT_WR_OFFSET);
	gbuf_wset(m,size);
	ddp = (at_ddp_t *)(gbuf_rptr(m));

	/*
	 * Prepare the DDP header of the new packet 
	 */

	ddp->unused = ddp->hopcount = 0;

	DDPLEN_ASSIGN(ddp, size);
	UAS_ASSIGN(ddp->checksum, 0);

	NET_NET(ddp->dst_net, orig_ddp->src_net);
	ddp->dst_node =  orig_ddp->src_node;
	ddp->dst_socket = orig_ddp->src_socket;

	NET_ASSIGN(ddp->src_net, Entry->NextIRNet);
	ddp->src_node = Entry->NextIRNode;
	ddp->src_socket = RTMP_SOCKET;
	ddp->type = DDP_RTMP;

	/*
	 * Prepare the RTMP header (Router Net, ID, Node and Net Tuple
	 * (this works only if we are on an extended net)
	 */

	rtmp_data = ddp->data;
	
	*rtmp_data++ = (Entry->NextIRNet & 0xff00) >> 8;
	*rtmp_data++ = Entry->NextIRNet & 0x00ff ;
	*rtmp_data++ = 8;	
	*rtmp_data++ = (u_char)Entry->NextIRNode;
	*rtmp_data++ = (Entry->NetStart & 0xff00) >> 8;
	*rtmp_data++ = Entry->NetStart & 0x00ff ;
	*rtmp_data++ = 0x80;	/* first tuple, so distance is always zero */
	*rtmp_data++ = (Entry->NetStop & 0xff00) >> 8;
	*rtmp_data++ = Entry->NetStop & 0x00ff ;
	*rtmp_data++ = RTMP_VERSION_NUMBER;


	dPrintf(D_M_RTMP, D_L_INFO, ("rtmp_r_find_bridge: for net %d send back router %d.%d\n",
				NET_VALUE(orig_ddp->dst_net), Entry->NextIRNet, Entry->NextIRNode));
	if (status = ddp_router_output(m, ifID, AT_ADDR, NET_VALUE(orig_ddp->src_net),
			orig_ddp->src_node, 0)){
		dPrintf(D_M_RTMP, D_L_WARNING,
			("rtmp_r_find_bridge: ddp_router_output failed status=%d\n", status));
				return (status);
	}
	return (0);
}

/*
 * rtmp_send_table: 
 *	Send the routing table entries in RTMP data packets.
 *	Use split horizon if specified. The Data packets are sent
 *	as full DDP packets, if the last packet is full an empty
 *	packet is sent to tell the recipients that this is the end of
 *	the table...
 *
 */
static int rtmp_send_table(ifID, DestNet, DestNode, split_hz, socket, 
			   n_neighbors)
     register at_ifaddr_t *ifID;	/* interface/port params */
     register at_net 	DestNet;	/* net where to send the table */
     register u_char 	DestNode;	/* node where to send to table */
     short 		split_hz;	/* use split horizon */
     char		socket;		/* the destination socket to send to */
     short 		n_neighbors;	/* used to send packets telling we are going down */
{

	RT_entry *Entry;
	char *Buff_ptr;
	u_char NewDist;
	gbuf_t *m;
	short size,status ;
	register at_ddp_t	*ddp;
	register short EntNb = 0, sent_tuple = 0;

	if (ifID->ifRoutingState < PORT_ONLINE) {
		dPrintf(D_M_RTMP, D_L_INFO,
			("rtmp_send_table: port %d activating, we don't send anything!\n",
			 ifID->ifPort));
		return (0);
	}

	/* prerare tuples and packets for DDP*/
	/* if split horizon, do not send tuples we can reach on the port we
	 * want to send too
	 */

	Entry = &RT_table[0];
	size = 0;
	if (!(m = rtmp_prep_new_packet(ifID, DestNet, DestNode, socket))) {
		dPrintf(D_M_RTMP, D_L_WARNING,
			("rtmp_send_table: rtmp_prep_new_packet failed\n"));
		return(ENOBUFS);
	}

	ddp = (at_ddp_t *)(gbuf_rptr(m));
	Buff_ptr = (char *)((char *)ddp + DDP_X_HDR_SIZE + 10); 

	while (EntNb < RT_maxentry) {

		if (Entry->NetStop && ((Entry->EntryState & 0x0F) >= RTE_STATE_SUSPECT)) {
			if (!(split_hz && ifID->ifPort == Entry->NetPort)) {
				sent_tuple++;

				if (((Entry->EntryState & 0x0F) < RTE_STATE_SUSPECT) || n_neighbors)
					NewDist = NOTIFY_N_DIST;
				else
					NewDist = Entry->NetDist & 0x1F;

				if (Entry->NetStart) {	/* Extended */
					*Buff_ptr++ = (Entry->NetStart & 0xFF00) >> 8;
					*Buff_ptr++ = (Entry->NetStart & 0x00FF);
					*Buff_ptr++ = 0x80 | NewDist;
					*Buff_ptr++ = (Entry->NetStop & 0xFF00) >> 8;
					*Buff_ptr++ = (Entry->NetStop & 0x00FF);
					*Buff_ptr++ = RTMP_VERSION_NUMBER;
					size += 6;
				}
				else {	/* non extended tuple */
					*Buff_ptr++ = (Entry->NetStop & 0xFF00) >> 8;
					*Buff_ptr++ = (Entry->NetStop & 0x00FF);
					*Buff_ptr++ = NewDist;
					size += 3;
				}
			}
		}

		if (size > (DDP_DATA_SIZE-20)) {
			DDPLEN_ASSIGN(ddp, size + DDP_X_HDR_SIZE + 10);
			gbuf_winc(m,size);
			if (status = ddp_router_output(m, ifID, AT_ADDR,
				NET_VALUE(DestNet),DestNode, 0)){
			  dPrintf(D_M_RTMP, D_L_WARNING,
				  ("rtmp_send_table: ddp_router_output failed status=%d\n",
				   status));
			  return (status);
			}
			if ((m = rtmp_prep_new_packet (ifID, DestNet, DestNode, socket)) == NULL){
				dPrintf(D_M_RTMP, D_L_WARNING,
					("rtmp_send_table: rtmp_prep_new_poacket failed status=%d\n",
					 status));
				return (ENOBUFS);
			}
			ddp = (at_ddp_t *)(gbuf_rptr(m));
			Buff_ptr = (char *)((char *)ddp + DDP_X_HDR_SIZE + 10); 
			
			dPrintf(D_M_RTMP_LOW, D_L_OUTPUT,
				("rtmp_s_tble: Send %d tuples on port %d\n",
				 sent_tuple, ifID->ifPort));
			sent_tuple = 0;
			size = 0;
		}

		Entry++;
		EntNb++;
	}

	/*
	 * If we have some remaining entries to send, send them now.
         * otherwise, the last packet we sent was full, we need to send an empty one
         */

	DDPLEN_ASSIGN(ddp, size + DDP_X_HDR_SIZE + 10);
	gbuf_winc(m,size);
	if ((status = 
	     ddp_router_output(m, ifID, AT_ADDR, NET_VALUE(DestNet),DestNode, 0))){
		dPrintf(D_M_RTMP, D_L_WARNING,
		("rtmp_send_table: ddp_router_output failed status=%d\n", status));
		return (status);
	}
	dPrintf(D_M_RTMP_LOW, D_L_OUTPUT,
		("rtmp_s_tble: LAST Packet split=%d with %d tuples sent on port %d\n",
		split_hz, sent_tuple, ifID->ifPort));
			
	return (0);
}

/*
 * rtmp_request: respond to the 3 types of RTMP requests RTMP may receive
 *      RTMP func =1 : respond with an RTMP Reponse Packet
 *	RTMP func =2 : respond with the routing table RTMP packet with split horizon
 *	RTMP func =3 : respond with the routing table RTMP packet no split horizon	
 *
 * see Inside AppleTalk around page 5-18 for "details"
 */

static void rtmp_request(ifID, ddp)
     register at_ifaddr_t *ifID;
     register at_ddp_t *ddp;
{

	short split_horizon = FALSE;
	short code;
	short error;

	/* We ignore the request if we're activating on that port */

	if (ifID->ifRoutingState <  PORT_ONLINE) 
			return;

	/* check RTMP function code */

	code = ddp->data[0];

	switch (code) {

		case RTMP_REQ_FUNC1:	/* RTMP Find Bridge */

			/* RTMP Request Packet: we send a response with the next IRrange */
			dPrintf(D_M_RTMP, D_L_INPUT,
				( "rtmp_request: find bridge for net %d port %d node %d.%d\n",
				  NET_VALUE(ddp->dst_net), ifID->ifPort,
				  NET_VALUE(ddp->src_net), ddp->src_node));

			if ((error = rtmp_r_find_bridge (ifID, ddp))) {
				dPrintf(D_M_RTMP, D_L_WARNING,
					("rtmp_request: Code 1 ddp_r_output failed error=%d\n",
					 error));
				return;
			}

			break;

		case RTMP_REQ_FUNC2:

			split_horizon = TRUE;	

		case RTMP_REQ_FUNC3:

			/* RTMP Route Request Packet */

			dPrintf(D_M_RTMP, D_L_INPUT,
				("rtmp_request:  received code=%d from %d.%d for %d.%d\n", 
				 code, NET_VALUE(ddp->src_net), ddp->src_node,
				 NET_VALUE(ddp->dst_net), ddp->dst_node));

			rtmp_send_table(ifID, ddp->src_net, ddp->src_node,
					split_horizon, ddp->src_socket, 0);

			break;

		default:

			/* unknown type of request */
		  dPrintf(D_M_RTMP, D_L_WARNING,
			  ("rtmp_request : invalid type of request =%d\n",
			   code));
		  break;
	}			

}

/* locked version of rtmp_send_port */
void rtmp_send_port_locked(ifID)
     register at_ifaddr_t *ifID;
{
	atalk_lock();
	rtmp_send_port(ifID);
	atalk_unlock();
}


/*
 * rtmp_send_all_ports : send the routing table on all connected ports
 *                       check for the port status and if ok, send the
 *                       rtmp tuples to the broadcast address for the port
 *                       usually called on timeout every 10 seconds.
 */

void rtmp_send_port(ifID)
     register at_ifaddr_t *ifID;
{
	at_net 	DestNet;	

	NET_ASSIGN(DestNet, 0);

	if (ifID && ifID->ifRoutingState == PORT_ONLINE) {
		dPrintf(D_M_RTMP_LOW, D_L_OUTPUT,
			("rtmp_send_port: do stuff for port=%d\n",
			 ifID->ifPort));
		if (ifID->ifZipNeedQueries) 
			zip_send_queries(ifID, 0, 0xFF);
		if (!ROUTING_MODE) {
			return;
                }
		rtmp_send_table(ifID, DestNet, 0xFF, 1, RTMP_SOCKET, 0);
	}

	if (ifID == ifID_home)
		dPrintf(D_M_RTMP_LOW, D_L_VERBOSE,
			("I:%5d O:%5d H:%5d dropped:%d\n",
			 pktsIn, pktsOut, pktsHome, pktsDropped));

	dPrintf(D_M_RTMP_LOW, D_L_TRACE,
		("rtmp_send_port: func=0x%x, ifID=0x%x\n", 
		 (u_int) rtmp_send_port, (u_int) ifID));
	timeout (rtmp_send_port_locked, (caddr_t)ifID, 10 * SYS_HZ);

}

/* rtmp_dropper: check the number of packet received every x secondes.
 *               the actual packet dropping is done in ddp_input
 */

void rtmp_dropper(void *arg)
{

	atalk_lock();

	pktsIn = pktsOut = pktsHome = pktsDropped = 0;
	timeout(rtmp_dropper, NULL, 2*SYS_HZ);

	atalk_unlock();
}
	
/*
 * rtmp_router_start: perform the sanity checks before declaring the router up
 *	 and running. This function looks for discrepency between the net infos
 *	 for the different ports and seed problems.
 *	 If everything is fine, the state of each port is brought to PORT_ONLINE.\
 *   ### LD 01/09/95 Changed to correct Zone problem on non seed ports.
 */
     
int rtmp_router_start(keP)
     at_kern_err_t *keP; /* used to report errors (if any) */
{
	int err = 0;
	register at_ifaddr_t *ifID, *ifID2;
	register short Index, router_starting_timer = 0;
	register RT_entry *Entry;
	register at_net_al netStart, netStop;
	struct timespec ts;


	/* clear the static structure used to record routing errors */
	bzero(&ke, sizeof(ke));

	TAILQ_FOREACH(ifID, &at_ifQueueHd, aa_link) {

		/* if non seed, need to acquire the right node address */

		if ((ifID->ifFlags & RTR_SEED_PORT) == 0)  {
			if ((ifID->ifThisCableStart == 0 && ifID->ifThisCableEnd == 0) ||
				(ifID->ifThisCableStart >= DDP_STARTUP_LOW && 
				ifID->ifThisCableEnd <= DDP_STARTUP_HIGH))  {

				if (ifID->ifThisCableEnd == 0)  {
					keP->error 	= KE_NO_SEED;
					keP->port1 	= ifID->ifPort;
					strlcpy(keP->name1, ifID->ifName,sizeof(keP->name1));
				}
				else {
					keP->error 	= KE_INVAL_RANGE;
					keP->port1 	= ifID->ifPort;
					strlcpy(keP->name1, ifID->ifName,sizeof(keP->name1));
					keP->netr1b 	= ifID->ifThisCableStart;
					keP->netr1e 	= ifID->ifThisCableEnd;
				}
				ifID->ifRoutingState = PORT_ERR_STARTUP;
				RouterError(ifID->ifPort, ERTR_CABLE_STARTUP);

				goto error;
			}
			
			/* we are non seed, so try to acquire the zones for that guy */
			ifID->ifZipNeedQueries = 1;

			dPrintf(D_M_RTMP, D_L_STARTUP,
				("rtmp_router_start: call elap_online for Non Seed port #%d cable =%d-%d\n",
					ifID->ifPort, CableStart, CableStop));
			if ((err = elap_online3(ifID)))
				goto error;
		}
	}

	/* Check if we have a problem with the routing table size */

	if (ErrorRTMPoverflow) {
		keP->error = KE_RTMP_OVERFLOW;	
		goto error;
	}


	/* Now, check that we don't have a conflict in between our interfaces */
	TAILQ_FOREACH(ifID, &at_ifQueueHd, aa_link) {

		/* check if the RoutingState != PORT_ONERROR */
		if (ifID->ifRoutingState < PORT_ACTIVATING) {
			goto error;
		}

		if ((ifID->ifThisCableStart == 0 && ifID->ifThisCableEnd == 0) ||
			(ifID->ifThisCableStart >= DDP_STARTUP_LOW && 
			ifID->ifThisCableEnd <= DDP_STARTUP_HIGH))  {

			if (ifID->ifThisCableEnd == 0)  {
				keP->error 	= KE_NO_SEED;
				keP->port1 	= ifID->ifPort;
				strlcpy(keP->name1, ifID->ifName,sizeof(keP->name1));
			}
			else {
				keP->error 	= KE_INVAL_RANGE;
				keP->port1 	= ifID->ifPort;
				strlcpy(keP->name1, ifID->ifName,sizeof(keP->name1));
				keP->netr1b 	= ifID->ifThisCableStart;
				keP->netr1e 	= ifID->ifThisCableEnd;
			}
			
			ifID->ifRoutingState = PORT_ERR_STARTUP;
			RouterError(ifID->ifPort, ERTR_CABLE_STARTUP);

			goto error;
		}

			/* check the interface address against all other ifs */

		netStart = ifID->ifThisCableStart;
		netStop = ifID->ifThisCableEnd;

		for (ifID2 = TAILQ_NEXT(ifID, aa_link); ifID2; 
		     ifID2 = TAILQ_NEXT(ifID2, aa_link)) {

			if (((netStart >= ifID2->ifThisCableStart) && 
				(netStart <= ifID2->ifThisCableEnd)) ||
			    ((netStop >= ifID2->ifThisCableStart) && 
				(netStop <= ifID2->ifThisCableEnd)) ||
				((ifID2->ifThisCableStart >= netStart) &&
				(ifID2->ifThisCableStart <= netStop)) ||
				((ifID2->ifThisCableEnd >= netStart) &&
				(ifID2->ifThisCableEnd <= netStop)) ) {

					keP->error 	= KE_CONF_RANGE;
					keP->port1 	= ifID->ifPort;
					strlcpy(keP->name1, ifID->ifName,sizeof(keP->name1));
					keP->port2 	= ifID2->ifPort;
					strlcpy(keP->name2, ifID2->ifName,sizeof(keP->name2));
					keP->netr1b 	= ifID->ifThisCableStart;
					keP->netr1e 	= ifID->ifThisCableEnd;
					ifID->ifRoutingState = PORT_ERR_CABLER;
					RouterError(ifID->ifPort, ERTR_CABLE_CONFLICT);
					goto error;
			}

		}

		/* ### LD 01/04/94: We need to fill in the next IR info in the routing table */
		Entry = rt_blookup(ifID->ifThisCableEnd);

		if (Entry == NULL) {
			dPrintf(D_M_RTMP, D_L_ERROR,
				("rtmp_router_start: we don't know our cable range port=%d\n",
			ifID->ifPort));

			goto error;
		}

		/*
		 * Note: At this point, non seed ports may not be aware of their Default zone
		 */

		if (!(ifID->ifFlags & RTR_SEED_PORT)) {
			ifID->ifDefZone = 0;
			Entry->EntryState |= (RTE_STATE_GOOD|RTE_STATE_UPDATED);
		}
			
		ifID->ifRoutingState = PORT_ONLINE;
		ifID->ifState = LAP_ONLINE;

		/* set the right net and node for each port */
		Entry->NextIRNet = ifID->ifThisNode.s_net;
		Entry->NextIRNode= ifID->ifThisNode.s_node;
		
		dPrintf(D_M_RTMP, D_L_STARTUP,
			("rtmp_router_start: bring port=%d [%d.%d]... on line\n",
			 ifID->ifPort, ifID->ifThisNode.s_net,
			 ifID->ifThisNode.s_node));

	}

	/*
	 * Everything is fine, we can begin to babble on the net...
	 */

	TAILQ_FOREACH(ifID, &at_ifQueueHd, aa_link) {
		if (ifID->ifRoutingState == PORT_ONLINE)  {
			rtmp_send_port(ifID);
			timeout(rtmp_timeout, (caddr_t)ifID, (50+ifID->ifPort) * SYS_HZ);
			if (ifID->ifRoutingState  < PORT_ACTIVATING) {
				goto error;
			}
		}
	}

	/* Check if we have a problem with the routing or zip table size */

	if (ErrorRTMPoverflow) {
		keP->error = KE_RTMP_OVERFLOW;	
		goto error;
	}
	if (ErrorZIPoverflow) {
		keP->error = KE_ZIP_OVERFLOW;	
		goto error;
	}

	/* sleep for 11 seconds */
	ts.tv_sec = 11;
	ts.tv_nsec = 0;
	if ((err = 
	     /* *** eventually this will be the ifID for the interface
		being brought up in router mode *** */
	     /* *** router sends rtmp packets every 10 seconds *** */
		msleep(&ifID_home->startup_inprogress, atalk_mutex,
		    PSOCK | PCATCH, "router_start1", &ts))
	    != EWOULDBLOCK) {
		goto error;
	}
	
	/* Is the stack still up ? */
	if (!(at_state.flags & AT_ST_STARTED) || !ifID_home) {
		err = ECONNABORTED;
		goto error;
	}

startZoneInfo:
	err = 0;
	TAILQ_FOREACH(ifID, &at_ifQueueHd, aa_link) {

		if (ifID->ifRoutingState < PORT_ACTIVATING) {
			goto error;
		}

		if ((ifID->ifZipNeedQueries) 
		 && (ifID->ifFlags & RTR_SEED_PORT) == 0)  {
			dPrintf(D_M_RTMP, D_L_STARTUP,
				("rtmp_router_start: send Zip Queries for Port %d\n",
					ifID->ifPort));
			zip_send_queries(ifID, 0, 0xFF);

			if (router_starting_timer >= 10) {
				dPrintf(D_M_RTMP, D_L_WARNING,
					("rtmp_router_start: no received response to ZipNeedQueries\n"));
				keP->error 	= KE_NO_ZONES_FOUND;
				keP->port1 	= ifID->ifPort;
				strlcpy(keP->name1, ifID->ifName,sizeof(keP->name1));
				keP->netr1b 	= ifID->ifThisCableStart;
				keP->netr1e 	= ifID->ifThisCableEnd;
				ifID->ifRoutingState = PORT_ERR_CABLER;
				RouterError(ifID->ifPort, ERTR_CABLE_CONFLICT);
				goto error;
			}

			dPrintf(D_M_RTMP, D_L_STARTUP,
				("rtmp_router_start: waiting for zone info to complete\n"));
			/* sleep for 10 seconds */
			ts.tv_sec = 10;
			ts.tv_nsec = 0;
			if ((err = 
			     /* *** eventually this will be the ifID for the 
				    interface being brought up in router mode *** */
				msleep(&ifID_home->startup_inprogress, atalk_mutex,
				    PSOCK | PCATCH, "router_start2", &ts))
			    != EWOULDBLOCK) {
				goto error;
			}
			
			/* Is the stack still up ? */
			if (!(at_state.flags & AT_ST_STARTED) || !ifID_home) {
				err = ECONNABORTED;
				goto error;
			}

			err = 0;
			router_starting_timer++;
			goto startZoneInfo;
		}

	}

	/* At This Point, check if we know the default zones for non seed port */

	TAILQ_FOREACH(ifID, &at_ifQueueHd, aa_link) {

		if (ifID->ifRoutingState < PORT_ACTIVATING)
			goto error;

		if (!(ifID->ifFlags & RTR_SEED_PORT)) { 
			Entry = rt_blookup(ifID->ifThisCableEnd);

			if (Entry == NULL) {
				dPrintf(D_M_RTMP, D_L_ERROR,
					("rtmp_router_start: (2)we don't know our cable range port=%d\n",
					ifID->ifPort));
				goto error;
			}
			
			dPrintf(D_M_RTMP, D_L_STARTUP,
				("rtmp_router_start: if %s set to permanent\n", 
				 ifID->ifName));
			Entry->NetDist = 0; 	/* added 4-29-96 jjs, prevent direct
						   nets from showing non-zero 
						   distance */
			/* upgrade the non seed ports. */
			Entry->EntryState |= RTE_STATE_PERMANENT;

			Index = zt_ent_zindex(Entry->ZoneBitMap);
			if (Index <= 0) {
				dPrintf(D_M_RTMP, D_L_ERROR,
					 ("rtmp_router_start: still don't know default zone for port %d\n",
					ifID->ifPort));
			} else {
				ifID->ifDefZone = Index;
				if ((ifID == ifID_home) || MULTIHOME_MODE) {
					ifID->ifZoneName = ZT_table[Index-1].Zone;
					(void)regDefaultZone(ifID);

					/* Send zone change event */
					atalk_post_msg(ifID->aa_ifp, KEV_ATALK_ZONEUPDATED, 0, &(ifID->ifZoneName));
				}
			}
		}
	}

	/* Check if we have a problem with the routing or zip table size */

	if (ErrorRTMPoverflow) {
		keP->error = KE_RTMP_OVERFLOW;	
		goto error;
	}
	if (ErrorZIPoverflow) {
		keP->error = KE_ZIP_OVERFLOW;	
		goto error;
	}

	/*
	 * Handle the Home Port specifics
	 */

	/* set the router address as being us no matter what*/
	ifID_home->ifARouter = ifID_home->ifThisNode;
	ifID_home->ifRouterState = ROUTER_UPDATED;

	/* prepare the packet dropper timer */
	timeout (rtmp_dropper, NULL, 1*SYS_HZ);

	return(0);

error:
	dPrintf(D_M_RTMP,D_L_ERROR, 
		("rtmp_router_start: error type=%d occurred on port %d\n",
		ifID->ifRoutingState, ifID->ifPort));

	/* if there's no keP->error, copy the local ke structure,
	   since the error occurred asyncronously */
	if ((!keP->error) && ke.error)
		bcopy(&ke, keP, sizeof(ke));
	rtmp_shutdown();

	/* to return the error in keP, the ioctl has to return 0 */
        
	return((keP->error)? 0: err);
} /* rtmp_router_start */


void rtmp_shutdown()
{
	register at_ifaddr_t *ifID;
	register short i;
	at_net DestNet;	

	NET_ASSIGN(DestNet, 0);

	dPrintf(D_M_RTMP, D_L_SHUTDN,
		("rtmp_shutdown:stop sending to all ports\n"));

	untimeout(rtmp_dropper, (caddr_t)0);
	untimeout(rtmp_router_start, 1); /* added for 2225395 */
	untimeout(rtmp_router_start, 3); /* added for 2225395 */
	
	TAILQ_FOREACH(ifID, &at_ifQueueHd, aa_link) {
		if (ifID->ifRoutingState > PORT_OFFLINE ) {
			if (ifID->ifRoutingState == PORT_ONLINE)  {
				untimeout(rtmp_send_port_locked, (caddr_t)ifID);
				untimeout(rtmp_timeout, (caddr_t) ifID); 
			}
			/* 
			 * it's better to notify the neighbour routers that we are going down
			 */
			if (ROUTING_MODE)
				rtmp_send_table(ifID, DestNet, 0xFF, TRUE, 
						RTMP_SOCKET, TRUE);

			ifID->ifRoutingState = PORT_OFFLINE;

			dPrintf(D_M_RTMP, D_L_SHUTDN,
				("rtmp_shutdown: routing on port=%d... off line\nStats:\n",
				 ifID->ifPort));
			dPrintf(D_M_RTMP, D_L_SHUTDN,
			 ("fwdBytes     : %ld\nfwdPackets   : %ld\ndroppedBytes : %ld\ndroppedPkts  : %ld\n",
			ifID->ifStatistics.fwdBytes, ifID->ifStatistics.fwdPkts,
			ifID->ifStatistics.droppedBytes, ifID->ifStatistics.droppedPkts));
 
		}
	}

}

/*
 * Remove all entries associated with the specified port.
 */
void rtmp_purge(ifID)
	at_ifaddr_t *ifID;
{
	u_char state;
	int i;
	RT_entry *en = &RT_table[0];

	for (i=0; i < RT_maxentry; i++) {
		state = en->EntryState & 0x0F;
		if ((state > RTE_STATE_UNUSED) && (state != RTE_STATE_PERMANENT)
			&& en->NetStop && en->NetDist && (en->NetPort == ifID->ifPort)) {
			zt_remove_zones(en->ZoneBitMap);		
			RT_DELETE(en->NetStop, en->NetStart);
		}
		en++;
	}
}
