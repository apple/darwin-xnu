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
 *	File: ri.c
 */
 
#ifdef AURP_SUPPORT

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
#include <netat/rtmp.h>
#include <netat/routing_tables.h>
#include <netat/at_pcb.h>
#include <netat/aurp.h>
#include <netat/debug.h>


static void AURPsndRIRsp(aurp_state_t *);

/* */
void AURPsndRIAck(state, m, flags)
	aurp_state_t *state;
	gbuf_t *m;
	unsigned short flags;
{
	unsigned short sequence_number;
	aurp_hdr_t *hdrp;
	int msize = sizeof(aurp_hdr_t);

	if (m) {
		sequence_number = ((aurp_hdr_t *)gbuf_rptr(m))->sequence_number;
		gbuf_wset(m,sizeof(aurp_hdr_t));
	} else {
		sequence_number = state->rcv_sequence_number;
		if ((m = (gbuf_t *)gbuf_alloc(msize, PRI_MED)) == 0)
			return;
		gbuf_wset(m,msize);
	}

	/* construct the RI Ack packet */
	hdrp = (aurp_hdr_t *)gbuf_rptr(m);
	hdrp->connection_id = state->rcv_connection_id;
	hdrp->sequence_number = sequence_number;
	hdrp->command_code = AURPCMD_RIAck;
	hdrp->flags = flags;

	/* send the packet */
	dPrintf(D_M_AURP, D_L_INFO, ("AURPsndRIAck: node=%d\n",
		state->rem_node));
	AURPsend(m, AUD_AURP, state->rem_node);
}

/* locked version of AURPsndRIReq */
void AURPsndRIReq_locked(state)
	aurp_state_t *state;
{
	atalk_lock();
	AURPsndRIReq(state);
	atalk_unlock();
}

/* */
void AURPsndRIReq(state)
	aurp_state_t *state;
{
	int msize;
	gbuf_t *m;
	aurp_hdr_t *hdrp;


	if (state->rcv_state == AURPSTATE_Unconnected) {
		return;
        }
	if (state->rcv_tmo && (state->rcv_state != AURPSTATE_WaitingForRIRsp)) {
		return;
        }

	msize = sizeof(aurp_hdr_t);
	if ((m = (gbuf_t *)gbuf_alloc(msize, PRI_MED)) != 0) {
		gbuf_wset(m,msize);

		/* construct the RI request packet */
		hdrp = (aurp_hdr_t *)gbuf_rptr(m);
		hdrp->connection_id = state->rcv_connection_id;
		hdrp->sequence_number = 0;
		hdrp->command_code = AURPCMD_RIReq;
		hdrp->flags = 0;

		/* update state info */
		state->rcv_state = AURPSTATE_WaitingForRIRsp;

		/* send the packet */
		dPrintf(D_M_AURP, D_L_INFO, ("AURPsndRIReq: node=%d\n",
			state->rem_node));
		AURPsend(m, AUD_AURP, state->rem_node);
	}

	/* start the retry timer */
	timeout(AURPsndRIReq_locked, state, AURP_RetryInterval*HZ);
	state->rcv_tmo = 1;
}

/* locked version of AURPsndRIRsp */
void AURPsndRIRsp_locked(state)
	aurp_state_t *state;
{
	atalk_lock();
	AURPsndRIRsp(state);
	atalk_unlock();
}

/* */
void AURPsndRIRsp(state)
	aurp_state_t *state;
{
	gbuf_t *m;
	aurp_hdr_t *hdrp;
	short len = 0;
	int msize = 0;


	/* make sure we're in a valid state to send RI response */
	if ((state->snd_state == AURPSTATE_Unconnected) ||
		(state->snd_state == AURPSTATE_WaitingForRIAck2)) {
		return;
	}

	/* update state info */
	state->snd_state = AURPSTATE_WaitingForRIAck1;

	if (state->rsp_m == 0) {
		msize = sizeof(aurp_hdr_t);
		if ((m = (gbuf_t *)gbuf_alloc(msize+AURP_MaxPktSize, PRI_MED)) == 0) {
			timeout(AURPsndRIRsp_locked, state, AURP_RetryInterval*HZ);
			state->snd_tmo = 1;
			return;
		}
		gbuf_wset(m,msize);
		state->rsp_m = m;

		/* construct the RI response packet */
		hdrp = (aurp_hdr_t *)gbuf_rptr(m);
		hdrp->connection_id = state->snd_connection_id;
		hdrp->sequence_number = state->snd_sequence_number;
		hdrp->command_code = AURPCMD_RIRsp;
		hdrp->flags = 0;

		/* get routing info of the local networks */
		state->snd_next_entry = AURPgetri(
			state->snd_next_entry, gbuf_wptr(m), &len);
		gbuf_winc(m,len);

		/* set the last flag if this is the last response packet */
		if (!state->snd_next_entry)
			hdrp->flags = AURPFLG_LAST;
	}

	/* keep a copy of the packet for retry */
	m = (gbuf_t *)gbuf_dupb(state->rsp_m);

	/* start the retry timer */
	timeout(AURPsndRIRsp_locked, state, AURP_RetryInterval*HZ);
	state->snd_tmo = 1;


	/* send the packet */
	if (m) {
		dPrintf(D_M_AURP, D_L_INFO, ("AURPsndRIRsp: len=%d\n", len));
		AURPsend(m, AUD_AURP, state->rem_node);
	}
        
}

void AURPsndRIUpd_locked(state)
	aurp_state_t *state;
{
	atalk_lock();
	AURPsndRIUpd(state);
	atalk_unlock();
}

/* */
void AURPsndRIUpd(state)
	aurp_state_t *state;
{
	gbuf_t *m;
	aurp_hdr_t *hdrp;
	short len = 0;
	int s, msize = 0;


	/* make sure we're in a valid state to send update */
	if (state->snd_next_entry || (state->upd_m == 0) ||
		(state->snd_state == AURPSTATE_Unconnected) ||
			(state->snd_state == AURPSTATE_WaitingForRIAck1)) {
		return;
	}

	/* update state info */
	state->snd_state = AURPSTATE_WaitingForRIAck2;

	if (state->snd_tmo == 0) {
		msize = sizeof(aurp_hdr_t);
		m = state->upd_m;
		len = gbuf_len(m);
		gbuf_rdec(m,msize);

		/* construct the RI update packet */
		hdrp = (aurp_hdr_t *)gbuf_rptr(m);
		hdrp->connection_id = state->snd_connection_id;
		hdrp->sequence_number = state->snd_sequence_number;
		hdrp->command_code = AURPCMD_RIUpd;
		hdrp->flags = 0;
	}

	/* keep a copy of the packet for retry */
	m = (gbuf_t *)gbuf_dupb(state->upd_m);

	/* start the retry timer */
	timeout(AURPsndRIUpd_locked, state, AURP_RetryInterval*HZ);
	state->snd_tmo = 1;


	/* send the packet */
	if (m) {
		dPrintf(D_M_AURP, D_L_INFO, ("AURPsndRIUpd: len=%d\n", len));
		AURPsend(m, AUD_AURP, state->rem_node);
	}
        
}

/* */
void AURPrcvRIReq(state, m)
	aurp_state_t *state;
	gbuf_t *m;
{
	aurp_hdr_t *hdrp = (aurp_hdr_t *)gbuf_rptr(m);
	int s;


	/* make sure we're in a valid state to accept it */
	if ((state->snd_state == AURPSTATE_Unconnected) ||
			(state->snd_state == AURPSTATE_WaitingForRIAck2)) {
		dPrintf(D_M_AURP, D_L_WARNING, ("AURPrcvRIReq: unexpected request\n"));
		gbuf_freem(m);
		return;
	}

	/* check for the correct connection id */
	if (hdrp->connection_id != state->snd_connection_id) {
		dPrintf(D_M_AURP, D_L_WARNING,
			("AURPrcvRIReq: invalid connection id, r=%d, m=%d\n",
			hdrp->connection_id, state->snd_connection_id));
		gbuf_freem(m);
		return;
	}

	if (state->snd_state != AURPSTATE_WaitingForRIAck1) {
		state->snd_next_entry = 0;
		if (state->rsp_m) {
			gbuf_freem(state->rsp_m);
			state->rsp_m = 0;
		}
		AURPsndRIRsp(state);
	} 

	gbuf_freem(m);
}

/* */
void AURPrcvRIRsp(state, m)
	aurp_state_t *state;
	gbuf_t *m;
{
	aurp_hdr_t *hdrp = (aurp_hdr_t *)gbuf_rptr(m);


	/* make sure we're in a valid state to accept it */
	if (state->rcv_state != AURPSTATE_WaitingForRIRsp) {
		dPrintf(D_M_AURP, D_L_WARNING, ("AURPrcvRIRsp: unexpected response\n"));
		gbuf_freem(m);
		return;
	}

	/* check for the correct connection id */
	if (hdrp->connection_id != state->rcv_connection_id) {
		dPrintf(D_M_AURP, D_L_WARNING,
			("AURPrcvRIRsp: invalid connection id, r=%d, m=%d\n",
			hdrp->connection_id, state->rcv_connection_id));
		gbuf_freem(m);
		return;
	}

	/* check for the correct sequence number */
	if (hdrp->sequence_number != state->rcv_sequence_number) {
		if ( ((state->rcv_sequence_number == AURP_FirstSeqNum) &&
			(hdrp->sequence_number == AURP_LastSeqNum)) ||
		(hdrp->sequence_number == (state->rcv_sequence_number-1)) ) {
			AURPsndRIAck(state, m, AURPFLG_SZI);
		} else {
			dPrintf(D_M_AURP, D_L_WARNING,
				("AURPrcvRIRsp: invalid sequence number, r=%d, m=%d\n",
				hdrp->sequence_number, state->rcv_sequence_number));
			gbuf_freem(m);
		}
		return;
	}
	gbuf_rinc(m,sizeof(*hdrp));
	if (hdrp->flags & AURPFLG_LAST)
		state->rcv_state = AURPSTATE_Connected;

	dPrintf(D_M_AURP, D_L_INFO, ("AURPrcvRIRsp: len=%ld\n", gbuf_len(m)));

	/* cancel the retry timer */
	untimeout(AURPsndRIReq_locked, state);
	state->rcv_tmo = 0;

	/* send RI ack */
	AURPsndRIAck(state, 0, AURPFLG_SZI);

	/* update state info */
	if (++state->rcv_sequence_number == 0)
		state->rcv_sequence_number = AURP_FirstSeqNum;

	/* process routing info of the tunnel peer */
	if (AURPsetri(state->rem_node, m)) {
		dPrintf(D_M_AURP, D_L_ERROR, ("AURPrcvRIRsp: AURPsetri() error\n"));
	}
	gbuf_freem(m);

	/* set the get zone flag to get zone info later if required */ 
	if (state->rcv_state == AURPSTATE_Connected)
		state->get_zi = 1;
}

/* */
void AURPrcvRIUpd(state, m)
	aurp_state_t *state;
	gbuf_t *m;
{
	aurp_hdr_t *hdrp = (aurp_hdr_t *)gbuf_rptr(m);

	/* make sure we're in a valid state to accept it */
	if (state->rcv_state == AURPSTATE_Unconnected) {
		dPrintf(D_M_AURP, D_L_WARNING, ("AURPrcvRIUpd: unexpected response\n"));
		gbuf_freem(m);
		return;
	}

	/* check for the correct connection id */
	if (hdrp->connection_id != state->rcv_connection_id) {
		dPrintf(D_M_AURP, D_L_WARNING,
			("AURPrcvRIUpd: invalid connection id, r=%d, m=%d\n",
			hdrp->connection_id, state->rcv_connection_id));
		gbuf_freem(m);
		return;
	}

	/* check for the correct sequence number */
	if (hdrp->sequence_number != state->rcv_sequence_number) {
		if ( ((state->rcv_sequence_number == AURP_FirstSeqNum) &&
			(hdrp->sequence_number == AURP_LastSeqNum)) ||
		(hdrp->sequence_number == (state->rcv_sequence_number-1)) ) {
			AURPsndRIAck(state, m, AURPFLG_SZI);
		} else {
			dPrintf(D_M_AURP, D_L_WARNING,
				("AURPrcvRIUpd: invalid sequence number, r=%d, m=%d\n",
				hdrp->sequence_number, state->rcv_sequence_number));
			gbuf_freem(m);
		}
		return;
	}
	gbuf_rinc(m,sizeof(*hdrp));

	dPrintf(D_M_AURP, D_L_INFO, ("AURPrcvRIUpd: len=%ld\n", gbuf_len(m)));

	/* send RI ack */
	AURPsndRIAck(state, 0, AURPFLG_SZI);

	/* update state info */
	if (++state->rcv_sequence_number == 0)
		state->rcv_sequence_number = AURP_FirstSeqNum;

	/* process update routing info of the tunnel peer */
	if (AURPupdateri(state->rem_node, m)) {
		dPrintf(D_M_AURP, D_L_ERROR, ("AURPrcvRIUpd: AURPupdateri() error\n"));
	}

	/* set the get zone flag to get zone info later if required */ 
	state->get_zi = 1;

	gbuf_freem(m);
}

/* */
void AURPrcvRIAck(state, m)
	aurp_state_t *state;
	gbuf_t *m;
{
	gbuf_t *dat_m;
	aurp_hdr_t *hdrp = (aurp_hdr_t *)gbuf_rptr(m);
	unsigned char snd_state;
	int flag;

	dPrintf(D_M_AURP, D_L_INFO, ("AURPrcvRIAck: state=%d\n",
		state->snd_state));

	/* make sure we're in a valid state to accept it */
	snd_state = state->snd_state;
	if (((snd_state == AURPSTATE_WaitingForRIAck1) ||
		(snd_state == AURPSTATE_WaitingForRIAck2)) &&
			(hdrp->sequence_number == state->snd_sequence_number)) {

		if (snd_state == AURPSTATE_WaitingForRIAck1) {
			/* ack from the tunnel peer to our RI response */
			untimeout(AURPsndRIRsp_locked, state);
			dat_m = state->rsp_m;
			state->rsp_m = 0;
			flag = 1;
		} else {
			/* ack from the tunnel peer to our RI update */
			untimeout(AURPsndRIUpd_locked, state);
			dat_m = state->upd_m;
			state->upd_m = 0;
			flag = 2;
		}
		state->snd_tmo = 0;
		gbuf_rinc(dat_m,sizeof(aurp_hdr_t));

		/* increment the sequence number */
		if (++state->snd_sequence_number == 0)
			state->snd_sequence_number = AURP_FirstSeqNum;

		/* update state info */
		state->snd_state = AURPSTATE_Connected;

		if (state->snd_next_entry) /* more RI responses to send? */
			AURPsndRIRsp(state);

		/* check to see if we need to send ZI responses */
		if (hdrp->flags & AURPFLG_SZI)
			AURPsndZRsp(state, dat_m, flag);
		else if (dat_m)
			gbuf_freem(dat_m);
	} 

	gbuf_freem(m);
}

/* */
int AURPgetri(next_entry, buf, len)
	short next_entry;
	unsigned char *buf;
	short *len;
{
	short entry_num = next_entry;
	RT_entry *entry = (RT_entry *)&RT_table[next_entry];

	for (*len=0; entry_num < RT_maxentry; entry_num++,entry++) {
		if ((net_port != entry->NetPort) &&
				!(entry->AURPFlag & AURP_NetHiden)) {
			if ((entry->EntryState & 0x0F) >= RTE_STATE_SUSPECT) {
			  if (entry->NetStart) {
				/* route info for extended network */
				*(short *)buf = entry->NetStart;
				buf += sizeof(short);
				*buf++ = 0x80 | (entry->NetDist & 0x1F);
				*(short *)buf = entry->NetStop;
				buf += sizeof(short);
				*buf++ = 0;
				*len += 6;
			  } else {
				/* route info for non-extended network */
				*(short *)buf = entry->NetStop;
				buf += sizeof(short);
				*buf++ = (entry->NetDist & 0x1F);
				*len += 3;
			  }
			}
		}
		if (*len > AURP_MaxPktSize)
			break;
	}

	return (entry_num == RT_maxentry) ? 0 : entry_num;
}

/* */
int AURPsetri(node, m)
	unsigned char node;
	gbuf_t *m;
{
	int tuples_cnt;
	unsigned char *tuples_ptr;
	RT_entry new_rt, *curr_rt;

	new_rt.NextIRNet  = 0;
	new_rt.NextIRNode = node;
	new_rt.NetPort	  = net_port;

	/*
	 * Process all the tuples against our routing table
	 */
	tuples_ptr = (char *)gbuf_rptr(m);
	tuples_cnt = (gbuf_len(m))/3;

	while (tuples_cnt--) {
		new_rt.NetDist = TUPLEDIST(tuples_ptr) + 1;
		new_rt.EntryState = RTE_STATE_GOOD;
		new_rt.NetStart = TUPLENET(tuples_ptr);
		tuples_ptr += 3;
		if (tuples_ptr[-1] & 0x80) {
			new_rt.NetStop  = TUPLENET((tuples_ptr));
			tuples_ptr += 3;
			tuples_cnt--;
		} else {
			new_rt.NetStop = new_rt.NetStart;
			new_rt.NetStart = 0;
		}
		if ((new_rt.NetStop == 0) || (new_rt.NetStop < new_rt.NetStart)) {
			dPrintf(D_M_AURP, D_L_WARNING,
			("AURPsetri: %d, invalid tuple received [%d-%d]\n",
				net_port, new_rt.NetStart, new_rt.NetStop));
			continue;
		}
	
		if ((curr_rt = rt_blookup(new_rt.NetStop)) != 0) { /* found? */
			/* ignore loop if present */
			if (curr_rt->NetPort != net_port)
				continue;

			if (new_rt.NetDist < 16) {
				/*
				 * check if the definition of the route has changed
				 */
				if ((new_rt.NetStop != curr_rt->NetStop) ||
						(new_rt.NetStart != curr_rt->NetStart)) {
					if ((new_rt.NetStop == curr_rt->NetStop) &&
						(new_rt.NetStop == curr_rt->NetStart) &&
							(new_rt.NetStart == 0)) {
						new_rt.NetStart = new_rt.NetStop;
					} else if ((new_rt.NetStop == curr_rt->NetStop) &&
						(new_rt.NetStart == new_rt.NetStop) &&
							(curr_rt->NetStart == 0)) {
						dPrintf(D_M_AURP, D_L_WARNING,
					("AURPsetri: [%d-%d] has changed to [%d-%d], Dist=%d\n",
						curr_rt->NetStart, curr_rt->NetStop,
					new_rt.NetStart, new_rt.NetStop, new_rt.NetDist));
						new_rt.NetStart = 0;
					} else {
						dPrintf(D_M_AURP, D_L_WARNING,
					("AURPsetri: Net Conflict, Curr=[%d-%d], New=[%d-%d]\n",
							curr_rt->NetStart,curr_rt->NetStop,
							new_rt.NetStart,new_rt.NetStop));
						zt_remove_zones(curr_rt->ZoneBitMap);
						rt_delete(curr_rt->NetStop, curr_rt->NetStart);
						continue;
					}
				}
			}

			if ((new_rt.NetDist <= curr_rt->NetDist) &&
					(new_rt.NetDist < 16)) { 
				/*
				 * found a shorter or more recent route,
				 * replace with the new entry
				 */
				curr_rt->NetDist    = new_rt.NetDist;
				curr_rt->NextIRNode = new_rt.NextIRNode;
				dPrintf(D_M_AURP_LOW,D_L_INFO,
					("AURPsetri: shorter route found [%d-%d], update\n",
					new_rt.NetStart,new_rt.NetStop));
			}

		} else { /* no entry found */
			if (new_rt.NetDist < 16) {
				new_rt.EntryState = RTE_STATE_GOOD;
				dPrintf(D_M_AURP, D_L_INFO,
				("AURPsetri: new_rt [%d-%d], tuple #%d\n",
					new_rt.NetStart, new_rt.NetStop, tuples_cnt));
				if (rt_insert(new_rt.NetStop, new_rt.NetStart,
					new_rt.NextIRNet, new_rt.NextIRNode,
					new_rt.NetDist, new_rt.NetPort,
						new_rt.EntryState) == (RT_entry *)0) {
				dPrintf(D_M_AURP,D_L_ERROR,
					("AURPsetri: RTMP table full [%d-%d]\n",
					new_rt.NetStart,new_rt.NetStop));
					return -1;
				}
			}
		}
	} /* end of main while */			

	return 0;
}

/* */
int AURPupdateri(node, m)
	unsigned char node;
	gbuf_t *m;
{
	char ev, ev_len;
	RT_entry new_rt, *old_rt;

	while (gbuf_len(m) > 0) {
		ev = *gbuf_rptr(m); /* event code */
		gbuf_rinc(m,1);
		if (gbuf_rptr(m)[2] & 0x80) {
			/* event tuple for extended network */
			new_rt.NetStart = *(unsigned short *)gbuf_rptr(m);
			new_rt.NetStop  = *(unsigned short *)&gbuf_rptr(m)[3];
			new_rt.NetDist  = gbuf_rptr(m)[2] & 0x7f;
			ev_len = 5;
		} else {
			/* event tuple for non-extended network */
			new_rt.NetStart = 0;
			new_rt.NetStop  = *(unsigned short *)gbuf_rptr(m);
			new_rt.NetDist  = gbuf_rptr(m)[2];
			ev_len = 3;
		}

	  switch (ev) {
	  case AURPEV_Null:
		break;

	  case AURPEV_NetAdded:
		gbuf_rinc(m,ev_len);
		new_rt.NextIRNet  = 0;
		new_rt.NextIRNode = node;
		new_rt.NetPort    = net_port;
		if ((new_rt.NetDist == 0) || (new_rt.NetStop == 0) ||
				(new_rt.NetStop < new_rt.NetStart)) {
			dPrintf(D_M_AURP,D_L_WARNING,
			("AURPupdateri: %d, invalid NetAdded received [%d-%d]\n",
				net_port, new_rt.NetStart, new_rt.NetStop));
			break;
		}
	
		if ((old_rt = rt_blookup(new_rt.NetStop)) != 0) { /* found? */
			if (old_rt->NetPort == net_port) {
				/*
				 * process this event as if it was an NDC event;
				 * update the route's distance
				 */
				old_rt->NetDist = new_rt.NetDist;
			}
		} else {
l_add:		if ((new_rt.NetDist < 16) && (new_rt.NetDist != NOTIFY_N_DIST)) {
				new_rt.EntryState = RTE_STATE_GOOD;
				dPrintf(D_M_AURP, D_L_INFO,
				("AURPupdateri: NetAdded [%d-%d]\n",
					new_rt.NetStart, new_rt.NetStop));
				if (rt_insert(new_rt.NetStop, new_rt.NetStart,
					new_rt.NextIRNet, new_rt.NextIRNode,
					new_rt.NetDist, new_rt.NetPort,
						new_rt.EntryState) == (RT_entry *)0) {
				dPrintf(D_M_AURP, D_L_WARNING,
					("AURPupdateri: RTMP table full [%d-%d]\n",
					new_rt.NetStart,new_rt.NetStop));
					return 0;
				}
			}
		}
		break;

	  case AURPEV_NetDeleted:
	  case AURPEV_NetRouteChange:
		gbuf_rinc(m,ev_len);
l_delete:	if ((old_rt = rt_blookup(new_rt.NetStop)) != 0) { /* found? */
			if (old_rt->NetPort == net_port) {
				zt_remove_zones(old_rt->ZoneBitMap);
				rt_delete(old_rt->NetStop, old_rt->NetStart);
			}
		}
		break;

	  case AURPEV_NetDistChange:
		gbuf_rinc(m,ev_len);
		if (new_rt.NetDist == 15)
			goto l_delete; /* process this event as if was an ND event */
		if ((old_rt = rt_blookup(new_rt.NetStop)) != 0) { /* found? */
			if (old_rt->NetPort == net_port) {
				/*
				 * update the route's distance
				 */
				old_rt->NetDist = new_rt.NetDist;
			}
		} else
			goto l_add; /* process this event as if was an NA event */
		break;

	  case AURPEV_NetZoneChange:
		break;
	  }
	}

	return 0;
}

/* */
void AURPpurgeri(node)
	unsigned char node;
{
	short entry_num;
	RT_entry *entry = (RT_entry *)RT_table;

	/*
	 * purge all routes associated with the tunnel peer
	 */
	for (entry_num=0; entry_num < RT_maxentry; entry_num++,entry++) {
		if ((net_port == entry->NetPort) && (node == entry->NextIRNode)) {
			zt_remove_zones(entry->ZoneBitMap);
			rt_delete(entry->NetStop, entry->NetStart);
		}
	}
}

/* */
void AURPrtupdate(entry, ev)
	RT_entry *entry;
	unsigned char ev;
{
	unsigned char i, node, ev_len, ev_tuple[6];
	gbuf_t *m;
	aurp_state_t *state = (aurp_state_t *)&aurp_state[1];
	int s, msize = sizeof(aurp_hdr_t);

	dPrintf(D_M_AURP, D_L_TRACE, ("AURPrtupdate: event=%d, net=[%d-%d]\n",
		ev, entry->NetStart, entry->NetStop));

	/*
	 * check that the network can be exported; if not,
	 * we must not make it visible beyond the local networks
	 */
	if (net_export) {
		for (i=0; i < net_access_cnt; i++) {
			if ((net_access[i] == entry->NetStart) ||
					(net_access[i] == entry->NetStop))
				break;
		}
		if (i == net_access_cnt)
			return;
	} else {
		for (i=0; i < net_access_cnt; i++) {
			if ((net_access[i] == entry->NetStart) ||
					(net_access[i] == entry->NetStop))
				return;
		}
	}

	/*
	 * create the update event tuple
	 */
	ev_tuple[0] = ev; /* event code */
	if (entry->NetStart) {
		*(unsigned short *)&ev_tuple[1] = entry->NetStart;
		ev_tuple[3] = 0x80 | (entry->NetDist & 0x1F);
		*(unsigned short *)&ev_tuple[4] = entry->NetStop;
		ev_len = 6;
	} else {
		*(unsigned short *)&ev_tuple[1] = entry->NetStop;
		ev_tuple[3] = (entry->NetDist & 0x1F);
		ev_len = 4;
	}

	for (node=1; node <= dst_addr_cnt; node++, state++) {
		if ((ev == AURPEV_NetAdded) &&
				(!(state->snd_sui & AURPFLG_NA))) continue;
		if ((ev == AURPEV_NetDeleted) &&
				(!(state->snd_sui & AURPFLG_ND))) continue;
		if ((ev == AURPEV_NetDistChange) &&
				(!(state->snd_sui & AURPFLG_NDC))) continue;
	  if ((state->snd_state != AURPSTATE_Unconnected) &&
			(state->snd_state != AURPSTATE_WaitingForRIAck2)) {
		if ((m = state->upd_m) == 0) {
			/*
			 * we don't have the RI update buffer yet, allocate one
			 */
			if ((m = (gbuf_t *)gbuf_alloc(msize+AURP_MaxPktSize, PRI_HI)) == 0)
				continue;
			state->upd_m = m;
			gbuf_rinc(m,msize);
			gbuf_wset(m,0);
		}

		/*
		 * add the update event tuple to the RI update buffer;
		 * the RI update buffer will be sent when the periodic update
		 * timer expires
		 */
		bcopy(ev_tuple, gbuf_wptr(m), ev_len);
		gbuf_winc(m,ev_len);

		/*
		 * if the RI update buffer is full, send the RI update now
		 */
		if (gbuf_len(m) > (AURP_MaxPktSize-6)) {
			AURPsndRIUpd(state);
			continue;
		}
	  }
	}
}

