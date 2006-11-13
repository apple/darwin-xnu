/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
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
 *	Copyright (c) 1993-1998 Apple Computer, Inc.
 *	All Rights Reserved.
 */

/*
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

#include <net/if.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/at_var.h>
#include <netat/ddp.h>
#include <netat/rtmp.h>
#include <netat/zip.h>
#include <netat/routing_tables.h>
#include <netat/debug.h>
#include <netat/at_pcb.h>

#include <sys/kern_event.h>

extern void rtmp_router_input();

/****************************************************************/
/*								*/
/*								*/
/*			RTMP Protocol				*/
/*								*/
/*								*/
/****************************************************************/


/* rtmp.c: , 1.6; 2/26/93; Apple Computer, Inc." */


#define	NROUTERS2TRAK	8
#define	FIFTYSECS	10
#define NODE(r)		((r)->ifARouter.s_node)
#define NET(r)		((r)->ifARouter.s_net)
#define	INUSE(r)	(NODE(r))

void ddp_age_router();

static struct routerinfo {
	struct at_addr ifARouter;
	at_ifaddr_t	  *ifID;
	void		  *tmo;
} trackedrouters[NROUTERS2TRAK];

void trackrouter_rem_if(ifID)
     register at_ifaddr_t *ifID;
{
	register i;
	register struct routerinfo *router;

	for (i = NROUTERS2TRAK; --i >= 0;) {
		router = &trackedrouters[i];
		if (trackedrouters[i].ifID == ifID) {
			untimeout(ddp_age_router, (caddr_t)router);
			break;
		}
	}
}


void routershutdown()
{
	register i;

	for (i = NROUTERS2TRAK; --i >= 0;) {
		register struct routerinfo *router;

		router = &trackedrouters[i];
		if (INUSE(router)) {
			untimeout(ddp_age_router, (caddr_t) router);
			bzero((caddr_t) router, sizeof(struct routerinfo));
		}
	}
}

int router_added  = 0;
int router_killed = 0;



void trackrouter(ifID, net, node)
     register at_ifaddr_t *ifID;
     register unsigned short	net;
     register unsigned char	node;
{
	register struct routerinfo *unused = NULL;
	register i;

	for (i = NROUTERS2TRAK; --i >= 0;) {
		register struct routerinfo *router;

		router = &trackedrouters[(i + node) & (NROUTERS2TRAK-1)];
		if ((NODE(router) == node) && (NET(router) == net)) {
			untimeout(ddp_age_router, (caddr_t) router);
			timeout(ddp_age_router, (caddr_t) router, 50*SYS_HZ);
			unused = NULL;
			break;
		}
		else if (!INUSE(router) && !unused)
			unused = router;
	}
	if (unused) {
		router_added++;

		if (ifID->ifARouter.s_net == 0) {
			/* Send event that this interface just got a router. This does not
				discriminate on whether this router is valid or not. If it is not
				valid rtmp_input will send a KEV_ATALK_ROUTERUP_INVALID event. */
			atalk_post_msg(ifID->aa_ifp, KEV_ATALK_ROUTERUP, 0, 0);
		}
		
		unused->ifID = ifID;
		NET(unused) =  net;
		NODE(unused) = node;
		ifID->ifRouterState = ROUTER_AROUND;
		timeout(ddp_age_router, (caddr_t) unused, 50*SYS_HZ);
		
		if (NET(ifID) == 0 && NODE(ifID) == 0) {
			NET(ifID) = net;
			NODE(ifID) = node;
		}
	}
}

/*
 * This is the timeout function that is called after 50 seconds, 
 * if no router packets come in. That way we won't send extended 
 * frames to something that is not there. Untimeout is called if 
 * an RTMP packet comes in so this routine will not be called.
 */
void ddp_age_router(deadrouter)
     register struct routerinfo *deadrouter;
{
	register at_ifaddr_t *ourrouter;

	atalk_lock();
			
	ourrouter = deadrouter->ifID;
	if (ourrouter == NULL) {
		atalk_unlock();
		return;
	}
        
	dPrintf(D_M_RTMP, D_L_INFO, 
		("ddp_age_router called deadrouter=%d:%d\n", NODE(deadrouter), NET(deadrouter)));

	router_killed++;

	if (NODE(ourrouter) == NODE(deadrouter) && 
	    NET(ourrouter) == NET(deadrouter)) {
		register unsigned long	atrandom = random();
		register struct routerinfo *newrouter;
		register i;

		bzero((caddr_t) deadrouter, sizeof(struct routerinfo));
		for (i = NROUTERS2TRAK; --i >= 0;) {
			newrouter = &trackedrouters[(i + atrandom) & (NROUTERS2TRAK-1)];
			if (INUSE(newrouter))
				break;
			else
				newrouter = NULL;
		}
		if (newrouter) {
			/* Set our router to another on the list and go on with life */
			NET(ourrouter) = NET(newrouter);
			NODE(ourrouter) = NODE(newrouter);
		}
		else {
			/* from gorouterless() */
			/* We have no other routers. */
			ATTRACE(AT_MID_DDP, AT_SID_TIMERS, AT_LV_WARNING, FALSE,
				"ddp_age_router entry : ARouter = 0x%x, RouterState = 0x%x",
				ATALK_VALUE(ourrouter->ifARouter), ourrouter->ifRouterState, 0);

			switch (ourrouter->ifRouterState) {
			case ROUTER_AROUND :
				/* This is where we lose our cable.
					Reset router fields and state accordingly. */
				ourrouter->ifARouter.s_net = 0;
				ourrouter->ifARouter.s_node = 0;
				ourrouter->ifThisCableStart = DDP_MIN_NETWORK;
				ourrouter->ifThisCableEnd = DDP_MAX_NETWORK;
				ourrouter->ifRouterState = NO_ROUTER;

				/* Send event to indicate that we've lost our seed router. */
				atalk_post_msg(ourrouter->aa_ifp, KEV_ATALK_ROUTERDOWN, 0, 0);

				zip_control(ourrouter, ZIP_NO_ROUTER);
				break;
			case ROUTER_WARNING :
				/* there was a router that we were ignoring...
				 * now, even that's gone.  But we want to tackle the
				 * case where another router may come up after all
				 * of them have died...
				 */
				ourrouter->ifRouterState = NO_ROUTER;
				break;
			}
		}
	} else
	        bzero((caddr_t) deadrouter, sizeof(struct routerinfo));

	atalk_unlock();
        
} /* ddp_age_router */

void rtmp_input (mp, ifID)
     register gbuf_t *mp;
     register at_ifaddr_t *ifID;
{
	register at_net_al	this_net;
	register at_net_al	range_start, range_end;
	register at_ddp_t	*ddp = (at_ddp_t *)gbuf_rptr(mp);
				/* NOTE: there is an assumption here that the 
				 * DATA follows the header. */
	register at_rtmp	*rtmp = (at_rtmp *)ddp->data;

	if (gbuf_type(mp) != MSG_DATA) {
		/* If this is a M_ERROR message, DDP is shutting down, 
		 * nothing to do here...If it's something else, we don't 
		 * understand what it is
		 */
		gbuf_freem(mp);
		return;
	}

	if (!ifID) {
		gbuf_freem(mp);
		return;
	}
	if (gbuf_len(mp) < (DDP_X_HDR_SIZE + sizeof(at_rtmp))) {
		gbuf_freem(mp);
		return;
	}
	this_net = ifID->ifThisNode.s_net;
	if (rtmp->at_rtmp_id_length  != 8) {
		gbuf_freem(mp);
		return;
	}

	{
		at_rtmp_tuple *tp;
		tp = ((at_rtmp_tuple *)&rtmp->at_rtmp_id[1]);
		range_start = NET_VALUE(tp->at_rtmp_net);
		tp = ((at_rtmp_tuple *)&rtmp->at_rtmp_id[4]);
		range_end = NET_VALUE(tp->at_rtmp_net);

		if (ifID->ifRouterState == ROUTER_AROUND) {
			if ((ifID->ifThisCableStart == range_start) &&
			    (ifID->ifThisCableEnd == range_end)) {
				trackrouter(ifID,
					    NET_VALUE(rtmp->at_rtmp_this_net),
					    rtmp->at_rtmp_id[0]
					    );
			}
		} else {
			/* There was no router around earlier, one
			 * probably just came up.
			 */
			if ((this_net >= DDP_STARTUP_LOW) && 
			    (this_net <= DDP_STARTUP_HIGH)) {
				/* we're operating in the startup range,
				 * ignore the presence of router
				 */
				if (ifID->ifRouterState == NO_ROUTER) {
					dPrintf(D_M_RTMP, D_L_INFO, ("rtmp_input: new router came up, INVALID: net \
						in startup range.\n"));
					/* trackrouter sends a KEV_ATALK_ROUTERUP event to note that
						a new router has come up when we had none before. */
					trackrouter(ifID,
						    NET_VALUE(rtmp->at_rtmp_this_net),
						    rtmp->at_rtmp_id[0]
						    );
					ifID->ifRouterState = ROUTER_WARNING;
					
					/* This router is invalid. Send event. */
					atalk_post_msg(ifID->aa_ifp, KEV_ATALK_ROUTERUP_INVALID, 0, 0);
				}
			} else {
				/* our address
				 * is not in startup range; Is our
				 * address good for the cable??
				 */
				if ((this_net >= range_start) &&
				    (this_net <= range_end)) {
					/* Our address is in the range
					 * valid for this cable... Note
					 * the router address and then
					 * get ZIP rolling to get the
					 * zone info.
					 */
					ifID->ifThisCableStart = range_start;
					ifID->ifThisCableEnd = range_end;

					/* A seed router that gives us back our cable range came up.
						It's a valid router and gives us our network back. */
					atalk_post_msg(ifID->aa_ifp, KEV_ATALK_ROUTERUP, 0, 0);

					trackrouter(ifID,
						    NET_VALUE(rtmp->at_rtmp_this_net),
						    rtmp->at_rtmp_id[0]
						    );
					zip_control(ifID, ZIP_LATE_ROUTER);
				} else {
					/* Our address is not in the
					 * range valid for this cable..
					 * ignore presence of the 
					 * router
					 */
					if (ifID->ifRouterState == NO_ROUTER) {
						/* trackrouter sends a KEV_ATALK_ROUTERUP event to note that
							a new router has come up when we had none before. */
						trackrouter(ifID,
							    NET_VALUE(rtmp->at_rtmp_this_net),
							    rtmp->at_rtmp_id[0]
							    );
						ifID->ifRouterState = ROUTER_WARNING;

						/* A new seed router came up, but the cable range is different
							than what we had before. */
						atalk_post_msg(ifID->aa_ifp, KEV_ATALK_ROUTERUP_INVALID, 0, 0);
					}
				}
			}
		}
	}

	gbuf_freem(mp);
	return;
}


void rtmp_init()
{
  bzero((caddr_t)trackedrouters, sizeof(struct routerinfo)*NROUTERS2TRAK);
}


