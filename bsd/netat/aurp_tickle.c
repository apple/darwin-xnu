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
 *	Copyright (c) 1996 Apple Computer, Inc. 
 *
 *		Created April 8, 1996 by Tuyen Nguyen
 *   Modified, March 17, 1997 by Tuyen Nguyen for MacOSX.
 *
 *	File: tickle.c
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
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <net/if.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/at_var.h>
#include <netat/routing_tables.h>
#include <netat/at_pcb.h>
#include <netat/aurp.h>
#include <netat/debug.h>

/* */
void AURPsndTickle(state)
	aurp_state_t *state;
{
	int msize;
	gbuf_t *m;
	aurp_hdr_t *hdrp;
	boolean_t 	funnel_state;

	funnel_state = thread_funnel_set(network_flock, TRUE);

	if (state->rcv_state == AURPSTATE_Unconnected) {
                (void) thread_funnel_set(network_flock, FALSE);
		return;
        }
	/* stop trying if the retry count exceeds the maximum retry value */
	if (++state->tickle_retry > AURP_MaxTickleRetry) {
		dPrintf(D_M_AURP, D_L_WARNING,
			("AURPsndTickle: no response, %d\n", state->rem_node));
		/*
		 * the tunnel peer seems to have disappeared, update state info
		 */
		state->snd_state = AURPSTATE_Unconnected;
		state->rcv_state = AURPSTATE_Unconnected;
		state->tickle_retry = 0;
		AURPcleanup(state);

		/* purge all routes associated with the tunnel peer */
		AURPpurgeri(state->rem_node);
                (void) thread_funnel_set(network_flock, FALSE);
		return;
	}

  if (state->tickle_retry > 1) {
	msize = sizeof(aurp_hdr_t);
	if ((m = (gbuf_t *)gbuf_alloc(msize, PRI_MED)) != 0) {
		gbuf_wset(m,msize);

		/* construct the tickle packet */
		hdrp = (aurp_hdr_t *)gbuf_rptr(m);
		hdrp->connection_id = state->rcv_connection_id;
		hdrp->sequence_number = 0;
		hdrp->command_code = AURPCMD_Tickle;
		hdrp->flags = 0;

		/* send the packet */
		AURPsend(m, AUD_AURP, state->rem_node);
	}
  }

	/* start the retry timer */
	timeout(AURPsndTickle, state, AURP_TickleRetryInterval*HZ);

	(void) thread_funnel_set(network_flock, FALSE);
}

/* */
void AURPrcvTickle(state, m)
	aurp_state_t *state;
	gbuf_t *m;
{
	aurp_hdr_t *hdrp = (aurp_hdr_t *)gbuf_rptr(m);

	/* make sure we're in a valid state to accept it */
	if (state->snd_state == AURPSTATE_Unconnected) {
		dPrintf(D_M_AURP, D_L_WARNING,
			("AURPrcvTickle: unexpected request\n"));
		gbuf_freem(m);
		return;
	}

	/* construct the tickle ack packet */
	gbuf_wset(m,sizeof(aurp_hdr_t));
	hdrp->command_code = AURPCMD_TickleAck;
	hdrp->flags = 0;

	/* send the packet */
	AURPsend(m, AUD_AURP, state->rem_node);
}

/* */
void AURPrcvTickleAck(state, m)
	aurp_state_t *state;
	gbuf_t *m;
{
	aurp_hdr_t *hdrp = (aurp_hdr_t *)gbuf_rptr(m);

	/* make sure we're in a valid state to accept it */
	if (state->rcv_state == AURPSTATE_Unconnected) {
		dPrintf(D_M_AURP, D_L_WARNING,
			("AURPrcvTickleAck: unexpected response\n"));
		gbuf_freem(m);
		return;
	}

	/* check for the correct connection id */
	if (hdrp->connection_id != state->rcv_connection_id) {
		dPrintf(D_M_AURP, D_L_WARNING,
			("AURPrcvTickleAck: invalid connection id, r=%d, m=%d\n",
			hdrp->connection_id, state->rcv_connection_id));
		gbuf_freem(m);
		return;
	}
	gbuf_freem(m);

	/* update state info */
	state->tickle_retry = 0;
}
