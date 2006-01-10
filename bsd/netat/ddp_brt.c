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
 *	Copyright (c) 1988, 1989 Apple Computer, Inc. 
 *
 *   Modified, March 17, 1997 by Tuyen Nguyen for MacOSX.
 */

#ifndef lint
/* static char sccsid[] = "@(#)ddp_brt.c: 2.0, 1.7; 10/4/93; Copyright 1988-89, Apple Computer, Inc."; */
#endif  /* lint */

/*
 * Title:	ddp_brt.c
 *
 * Facility:	Best Router Caching.
 *
 * Author:	Kumar Vora, Creation Date: June-15-1989
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
#include <sys/protosw.h>

#include <net/if.h>

#include <netat/appletalk.h>
#include <netat/sysglue.h>
#include <netat/ddp.h>
#include <netat/at_pcb.h>
#include <netat/at_var.h>
#include <netat/at_ddp_brt.h>
#include <netat/debug.h>

/* Best Router Cache */
ddp_brt_t at_ddp_brt[BRTSIZE];
int ddp_brt_sweep_timer;

void ddp_brt_sweep();

void ddp_glean(mp, ifID, src_addr)
     register gbuf_t	  *mp;
     register at_ifaddr_t  *ifID;
     struct etalk_addr  *src_addr;
{
	register at_net_al	     src_net;

	/* NOT assuming that the incoming packet is in one contiguous
	 * buffer.
	 */

	{
		/* The interface is ethertalk, so the message is
		 * of the form {802.3, 802.2, ddp.... }. Extract the
		 * 802.3 source address if necessary.  Assuming, 
		 * however, that 802.3 and 802.2 headers are in
		 * one contiguous piece.
		 */
		{       register at_ddp_t    *dgp;

			dgp = (at_ddp_t *)(gbuf_rptr(mp));
			src_net = NET_VALUE(dgp->src_net);
		}
		if (src_net >= ifID->ifThisCableStart && src_net <= ifID->ifThisCableEnd) 
			/* the packet has come from a net on this cable,
			 * no need to glean router info.
			 */
			return;

		if (src_addr != NULL)
		{	register ddp_brt_t   *brt;

			BRT_LOOK (brt, src_net);
			if (brt == NULL) {
			        /* There's no BRT entry corresponding to this 
				 * net. Allocate a new entry.
				 */
			        NEW_BRT(brt, src_net);
				if (brt == NULL)
				        /* No space available in the BRT; 
					 * can't glean info.
					 */
				        return;
				brt->net = src_net;
		        }
			/*
			 * update the router info in either case
			 */
			brt->et_addr = *src_addr;
			brt->age_flag = BRT_VALID;
			brt->ifID = ifID;
		}
	}
}

void ddp_brt_init()
{
	bzero(at_ddp_brt, sizeof(at_ddp_brt));
	ddp_brt_sweep_timer = 1;
#ifdef NOT_USED
	timeout(ddp_brt_sweep_locked, (long)0, BRT_SWEEP_INT * SYS_HZ);
#endif
}

void ddp_brt_shutdown()
{
#ifdef NOT_USED
	bzero(at_ddp_brt, sizeof(at_ddp_brt));
	if (ddp_brt_sweep_timer)
		untimeout(ddp_brt_sweep_locked, 0);
#endif
	ddp_brt_sweep_timer = 0;
}

/* locked version */
void ddp_brt_sweep_locked()
{
	atalk_lock();
	ddp_brt_sweep();
	atalk_unlock();
}

void ddp_brt_sweep()
{
        register ddp_brt_t      *brt;
	register int		i;

	if (ddp_brt_sweep_timer)
	  if (++ddp_brt_sweep_timer > BRT_SWEEP_INT) {
	    ddp_brt_sweep_timer = 1;

	    brt = at_ddp_brt;
	    for (i = 0; i < BRTSIZE; i++, brt++) {
		switch (brt->age_flag) {
		case BRT_EMPTY :
			break;
		case BRT_VALID :
			brt->age_flag = BRT_GETTING_OLD;
			break;
		case BRT_GETTING_OLD :
			bzero(brt, sizeof(ddp_brt_t));
			break;
		default :
			ATTRACE(AT_MID_DDP,AT_SID_RESOURCE, AT_LV_ERROR, FALSE,
				"ddp_brt_sweep : corrupt age flag %d", 
				brt->age_flag, 0,0);
			break;
		}
	    }
	  }
#ifdef NOT_USED
	/* set up the next sweep... */
	timeout(ddp_brt_sweep_locked, (long)0, BRT_SWEEP_INT * SYS_HZ);
#endif

}


