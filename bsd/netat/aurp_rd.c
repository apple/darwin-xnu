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
 *	Copyright (c) 1996 Apple Computer, Inc. 
 *
 *		Created April 8, 1996 by Tuyen Nguyen
 *   Modified, March 17, 1997 by Tuyen Nguyen for MacOSX.
 *
 *	File: rd.c
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

/* */
void AURPsndRDReq(state)
	aurp_state_t *state;
{
	int msize;
	gbuf_t *m;
	aurp_hdr_t *hdrp;

	if ((state->rcv_state == AURPSTATE_Unconnected) ||
			(state->snd_state == AURPSTATE_Unconnected))
		return;

	/* update state info */
	state->rcv_state = AURPSTATE_Unconnected;
	state->snd_state = AURPSTATE_Unconnected;

	/* notify tunnel peer of router going-down for the data receiver side */
	msize = sizeof(aurp_hdr_t) + sizeof(short);
	if ((m = (gbuf_t *)gbuf_alloc(msize, PRI_MED)) != 0) {
		gbuf_wset(m,msize);

		/* construct the router down packet */
		hdrp = (aurp_hdr_t *)gbuf_rptr(m);
		hdrp->connection_id = state->rcv_connection_id;
		hdrp->sequence_number = 0;
		hdrp->command_code = AURPCMD_RDReq;
		hdrp->flags = 0;
		*(short *)(hdrp+1) = AURPERR_NormalConnectionClose;

		/* send the packet */
		AURPsend(m, AUD_AURP, state->rem_node);
	}

	/* notify tunnel peer of router going-down for the data sender side */
	msize = sizeof(aurp_hdr_t) + sizeof(short);
	if ((m = (gbuf_t *)gbuf_alloc(msize, PRI_MED)) != 0) {
		gbuf_wset(m,msize);

		/* construct the router down packet */
		hdrp = (aurp_hdr_t *)gbuf_rptr(m);
		hdrp->connection_id = state->snd_connection_id;
		hdrp->sequence_number = state->snd_sequence_number;
		hdrp->command_code = AURPCMD_RDReq;
		hdrp->flags = 0;
		*(short *)(hdrp+1) = AURPERR_NormalConnectionClose;

		/* send the packet */
		AURPsend(m, AUD_AURP, state->rem_node);
	}
}

/* */
void AURPrcvRDReq(state, m)
	aurp_state_t *state;
	gbuf_t *m;
{
	/* update state info */
	state->rcv_state = AURPSTATE_Unconnected;
	state->snd_state = AURPSTATE_Unconnected;
	AURPcleanup(state);

	/* purge all routes associated with the tunnel peer going-down */
	AURPpurgeri(state->rem_node);

	/* respond to the going-down peer with an RI Ack packet */
	AURPsndRIAck(state, m, 0);
}
