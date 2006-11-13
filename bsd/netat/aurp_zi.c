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
 *	Copyright (c) 1996 Apple Computer, Inc. 
 *
 *		Created April 8, 1996 by Tuyen Nguyen
 *   Modified, March 17, 1997 by Tuyen Nguyen for MacOSX.
 *
 *	File: zi.c
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
#include <kern/assert.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/at_var.h>
#include <netat/routing_tables.h>
#include <netat/at_pcb.h>
#include <netat/aurp.h>
#include <netat/debug.h>

static int AURPgetzi(int, unsigned char *, short *, gbuf_t *, int);
static void AURPsetzi(unsigned char, gbuf_t *, short, short);

/* */
void AURPsndZReq(state)
	aurp_state_t *state;
{
	gbuf_t *m;
	int msize;
	aurp_hdr_t *hdrp;
	short *net, nets_cnt, net_sent=0, entry_num=0;
	RT_entry *entry = RT_table;

	if (!state->get_zi || (state->rcv_state == AURPSTATE_Unconnected))
		return;

l_more:
	msize = sizeof(aurp_hdr_t);
	if ((m = (gbuf_t *)gbuf_alloc(msize+AURP_MaxPktSize, PRI_MED)) == 0) {
		dPrintf(D_M_AURP, D_L_WARNING, ("AURPsndZReq: node=%d, out of mblk\n",
			state->rem_node));
		return;
	}
	gbuf_wset(m,msize);

	/* construct the ZI request packet */
	hdrp = (aurp_hdr_t *)gbuf_rptr(m);
	hdrp->connection_id = state->rcv_connection_id;
	hdrp->sequence_number = 0;
	hdrp->command_code = AURPCMD_ZReq;
	hdrp->flags = 0;
	*(short *)(hdrp+1) = AURPSUBCODE_ZoneInfo1;
	gbuf_winc(m,sizeof(short));

	net = (short *)gbuf_wptr(m);
	nets_cnt = 0;

	while (entry_num < RT_maxentry) {
		/*
		 * scan the router table, and build the ZI request packet
		 * with the right entries, i.e.,
		 *  - entry in use and not of the net_port
		 *  - with no zones and in an active state
		 *  - talking to the right router
		 */
		if ( (entry->NetPort == net_port) && entry->NetStop &&
			((entry->EntryState & 0x0F) >= RTE_STATE_SUSPECT) &&
				(!RT_ALL_ZONES_KNOWN(entry)) ) {
			*net++ = (entry->NetStart) ? entry->NetStart : entry->NetStop;
			nets_cnt++;
		}

		if (nets_cnt >= 640) {
			/* query only 640 networks per packet */
			dPrintf(D_M_AURP, D_L_INFO, ("AURPsndZReq: node=%d\n",
				state->rem_node));
			gbuf_winc(m,(nets_cnt * sizeof(short)));
			AURPsend(m, AUD_AURP, state->rem_node);
			net_sent = 1;
			goto l_more;
		}

		entry_num++;
		entry++;
	}

	if (nets_cnt) {
		dPrintf(D_M_AURP, D_L_INFO, ("AURPsndZReq: node=%d\n",
			state->rem_node));
		gbuf_winc(m,(nets_cnt * sizeof(short)));
		AURPsend(m, AUD_AURP, state->rem_node);
		net_sent = 1;
	} else
		gbuf_freeb(m);

	if (!net_sent)
		state->get_zi = 0;
}

/* */
void AURPsndZRsp(state, dat_m, flag)
	aurp_state_t *state;
	gbuf_t *dat_m;
	int flag;
{
	short len;
	int msize, next_entry = 0;
	gbuf_t *m;
	aurp_hdr_t *hdrp;

	if ((state->snd_state == AURPSTATE_Unconnected) || (dat_m == 0))
		return;
	msize = sizeof(aurp_hdr_t);

  do {
	if ((m = (gbuf_t *)gbuf_alloc(msize+AURP_MaxPktSize, PRI_MED)) == 0) {
		dPrintf(D_M_AURP, D_L_WARNING, ("AURPsndZRsp: node=%d, out of mblk\n",
			state->rem_node));
		return;
	}
	gbuf_wset(m,msize);

	/* construct the ZI response packet */
	hdrp = (aurp_hdr_t *)gbuf_rptr(m);
	hdrp->connection_id = state->snd_connection_id;
	hdrp->sequence_number = 0;
	hdrp->command_code = AURPCMD_ZRsp;
	hdrp->flags = 0;

	/* get zone info of the local networks */
	next_entry = AURPgetzi(next_entry, gbuf_wptr(m), &len, dat_m, flag);
	gbuf_winc(m,len);

	/* send the packet */
	dPrintf(D_M_AURP, D_L_INFO, ("AURPsndZRsp: len=%d\n", len));
	AURPsend(m, AUD_AURP, state->rem_node);

  } while (next_entry);

	gbuf_freem(dat_m);
}

/* */
void AURPsndGZN(state, dat_m)
	aurp_state_t *state;
	gbuf_t *dat_m;
{
	short zname_len;
	int msize;
	gbuf_t *m;
	aurp_hdr_t *hdrp;

	if (state->snd_state == AURPSTATE_Unconnected)
		return;

	msize = sizeof(aurp_hdr_t);
	if ((m = (gbuf_t *)gbuf_alloc(msize+AURP_MaxPktSize, PRI_MED)) == 0) {
		dPrintf(D_M_AURP, D_L_WARNING, ("AURPsndGZN: node=%d, out of mblk\n",
			state->rem_node));
		return;
	}
	gbuf_wset(m,msize);

	/* construct the GZN response packet */
	hdrp = (aurp_hdr_t *)gbuf_rptr(m);
	hdrp->connection_id = state->snd_connection_id;
	hdrp->sequence_number = 0;
	hdrp->command_code = AURPCMD_ZRsp;
	hdrp->flags = 0;
	*(short *)(gbuf_wptr(m)) = AURPSUBCODE_GetZoneNets;
	gbuf_winc(m,sizeof(short));
	zname_len = gbuf_len(dat_m);
	bcopy(gbuf_rptr(dat_m), gbuf_wptr(m), zname_len);
	gbuf_winc(m,zname_len);
	*(short *)(gbuf_wptr(m)) = -1; /* number of tuples - proto not supported */
	gbuf_winc(m,sizeof(short));

	/* send the packet */
	dPrintf(D_M_AURP, D_L_INFO, ("AURPsndGZN: count=%d\n", -1));
	AURPsend(m, AUD_AURP, state->rem_node);
}

/* */
void AURPsndGDZL(state, dat_m)
	aurp_state_t *state;
	gbuf_t *dat_m;
{
	int msize;
	gbuf_t *m;
	aurp_hdr_t *hdrp;

	if (state->snd_state == AURPSTATE_Unconnected)
		return;

	msize = sizeof(aurp_hdr_t);
	if ((m = (gbuf_t *)gbuf_alloc(msize+AURP_MaxPktSize, PRI_MED)) == 0) {
		dPrintf(D_M_AURP, D_L_WARNING, ("AURPsndGDZL: node=%d, out of mblk\n",
			state->rem_node));
		return;
	}
	gbuf_wset(m,msize);

	/* construct the GDZL response packet */
	hdrp = (aurp_hdr_t *)gbuf_rptr(m);
	hdrp->connection_id = state->snd_connection_id;
	hdrp->sequence_number = 0;
	hdrp->command_code = AURPCMD_ZRsp;
	hdrp->flags = 0;
	*(short *)(gbuf_wptr(m)) = AURPSUBCODE_GetDomainZoneList;
	gbuf_winc(m,sizeof(short));
	*(short *)(gbuf_wptr(m)) = -1; /* start index - proto not supported */
	gbuf_winc(m,sizeof(short));

	/* send the packet */
	dPrintf(D_M_AURP, D_L_INFO, ("AURPsndGDZL: index=%d\n", -1));
	AURPsend(m, AUD_AURP, state->rem_node);
}

/* */
void AURPrcvZReq(state, m)
	aurp_state_t *state;
	gbuf_t *m;
{
	short sub_code;
	aurp_hdr_t *hdrp = (aurp_hdr_t *)gbuf_rptr(m);

	/* make sure we're in a valid state to accept it */
	if (state->snd_state == AURPSTATE_Unconnected) {
		dPrintf(D_M_AURP, D_L_WARNING, ("AURPrcvZReq: unexpected response\n"));
		gbuf_freem(m);
		return;
	}

	/* check for the correct connection id */
	if (hdrp->connection_id != state->snd_connection_id) {
		dPrintf(D_M_AURP, D_L_WARNING,
			("AURPrcvZReq: invalid connection id, r=%d, m=%d\n",
			hdrp->connection_id, state->snd_connection_id));
		gbuf_freem(m);
		return;
	}

	gbuf_rinc(m,sizeof(*hdrp));
	sub_code = *(short *)gbuf_rptr(m);
	gbuf_rinc(m,sizeof(short));

	dPrintf(D_M_AURP, D_L_INFO, ("AURPrcvZReq: len=%ld\n", gbuf_len(m)));

	switch (sub_code) {
	case AURPSUBCODE_ZoneInfo1:
		AURPsndZRsp(state, m, 0);
		return;

	case AURPSUBCODE_GetZoneNets:
		AURPsndGZN(state, m);
		break;

	case AURPSUBCODE_GetDomainZoneList:
		AURPsndGDZL(state, m);
		break;
	}

	gbuf_freem(m);
}

/* */
void AURPrcvZRsp(state, m)
	aurp_state_t *state;
	gbuf_t *m;
{
	short sub_code, tuples_cnt;
	aurp_hdr_t *hdrp = (aurp_hdr_t *)gbuf_rptr(m);

	/* make sure we're in a valid state to accept it */
	if (state->rcv_state == AURPSTATE_Unconnected) {
		dPrintf(D_M_AURP, D_L_WARNING, ("AURPrcvZRsp: unexpected response\n"));
		gbuf_freem(m);
		return;
	}

	/* check for the correct connection id */
	if (hdrp->connection_id != state->rcv_connection_id) {
		dPrintf(D_M_AURP, D_L_WARNING,
			("AURPrcvZRsp: invalid connection id, r=%d, m=%d\n",
			hdrp->connection_id, state->rcv_connection_id));
		gbuf_freem(m);
		return;
	}

	gbuf_rinc(m,sizeof(*hdrp));
	sub_code = *(short *)gbuf_rptr(m);
	gbuf_rinc(m,sizeof(short));

	dPrintf(D_M_AURP, D_L_INFO, ("AURPrcvZRsp: len=%ld\n", gbuf_len(m)));

	switch (sub_code) {
	case AURPSUBCODE_ZoneInfo1:
	case AURPSUBCODE_ZoneInfo2:
		tuples_cnt = *(short *)gbuf_rptr(m);
		gbuf_rinc(m,sizeof(short));
		AURPsetzi(state->rem_node, m, sub_code, tuples_cnt);
		break;

	case AURPSUBCODE_GetZoneNets:
		break;

	case AURPSUBCODE_GetDomainZoneList:
		break;
	}

	gbuf_freem(m);
}

/* */
static int
AURPgetzi(next_entry, buf, len, dat_m, flag)
	int next_entry;
	unsigned char *buf;
	short *len;
	gbuf_t *dat_m;
	int flag;
{
	static int i_sav=ZT_BYTES-1, j_sav=0, idx_sav=-1;
	unsigned char ev, zname_len, *zmap, *zname_base, *zname_sav, *tuples_ptr;
	unsigned short net_num, *net, zname_offset;
	short *sub_codep, *tuples_cntp, tuples_cnt, dat_len;
	int i, j, idx, nets_cnt;
	RT_entry *entry;

	/*
	 * XXX CHS June-98: The compiler complains that some of these
	 * XXX variables may be used before they're set. I don't think
	 * XXX that's actually the case, but to check, I'll assign them
	 * XXX with some test value, and add asserts to check them at
	 * XXX run-time. The asserts won't be compiled in for production.
	 */
	zname_sav = tuples_ptr = (unsigned char *) 0xdeadbeef;	/* XXX */
	net = (unsigned short *) 0xdeadbeef;			/* XXX */
	net_num = 0xdead;					/* XXX */
	nets_cnt = 0xfeedface;					/* XXX */

	sub_codep = (short *)buf;
	buf += sizeof(short);
	tuples_cntp = (short *)buf;
	buf += sizeof(short);
	*len = sizeof(short) + sizeof(short);
	zname_base = buf + sizeof(short);
	dat_len = 0;

	/* set the subcode in the ZI response packet */
	*sub_codep = next_entry ? AURPSUBCODE_ZoneInfo2 : AURPSUBCODE_ZoneInfo1;

	switch (flag) {
	case 0: /* zone info in response to ZI request */
		net = (unsigned short *)gbuf_rptr(dat_m);
		nets_cnt = (gbuf_len(dat_m))/2;
		break;
	case 1: /* zone info in response to Ack of RI response */
		tuples_ptr = gbuf_rptr(dat_m);
		nets_cnt = (gbuf_len(dat_m))/3;
		next_entry = 0;
		break;
	case 2: /* zone info in response to Ack of RI update */
		tuples_ptr = gbuf_rptr(dat_m);
		nets_cnt = (gbuf_len(dat_m))/4;
		next_entry = 0;
		break;
	}

	/*
	 * for each network, find all the zones that it belongs to
	 */
	assert(nets_cnt != 0xfeedface);				/* XXX */
	for (tuples_cnt=0; next_entry < nets_cnt; next_entry++) {
		switch(flag) {
		case 0:
			assert(net != 0xdeadbeef);		/* XXX */
			net_num = net[next_entry];
			break;
		case 1:
			assert(tuples_ptr != 0xdeadbeef);	/* XXX */
			net_num = *(unsigned short *)tuples_ptr; 
			tuples_ptr += 3;
			gbuf_rinc(dat_m,3);
			if (tuples_ptr[-1] & 0x80) {
				tuples_ptr += 3;
				gbuf_rinc(dat_m,3);
				next_entry++;
			}
			break;
		case 2:
			if (gbuf_len(dat_m) <= 0) {
				next_entry = nets_cnt;
				goto l_done;
			}
			assert(tuples_ptr != 0xdeadbeef);	/* XXX */
			ev = *tuples_ptr++;
			net_num = *(unsigned short *)tuples_ptr; 
			tuples_ptr += 3;
			gbuf_rinc(dat_m,4);
			if (tuples_ptr[-1] & 0x80) {
				tuples_ptr += 2;
				gbuf_rinc(dat_m,2);
			}
			if (ev != AURPEV_NetAdded)
				continue;
			break;
		}

		/*
		 * find the RT entry associated with the network
		 */
		assert(net_num != 0xdead);			/* XXX */
		if ((entry = rt_blookup(net_num)) == 0) {
			dPrintf(D_M_AURP, D_L_WARNING, ("AURPgetzi: invalid net, %d\n",
				net_num));
			continue;
		}
		if ( ((entry->EntryState & 0x0F) < RTE_STATE_SUSPECT) ||
				!RT_ALL_ZONES_KNOWN(entry) ||
				(entry->AURPFlag & AURP_NetHiden) ) {
			dPrintf(D_M_AURP_LOW, D_L_INFO, ("AURPgetzi: zombie net, net=%d\n",
				net_num));
			continue;
		}

	  if (entry->NetStart == 0) {
		if ((idx = zt_ent_zindex(entry->ZoneBitMap)) == 0)
			continue;
		idx--; /* index in the zone table */
		zname_len = ZT_table[idx].Zone.len;
		if (zname_len) {
			assert(net_num != 0xdead);		/* XXX */
			*(unsigned short *)buf = net_num;
			buf += sizeof(short);
		  if (idx == idx_sav) {
			/* use the optimized format */
			assert(zname_sav != 0xdeadbeef);	/* XXX */
			zname_offset = zname_sav - zname_base;
			*(unsigned short *)buf = (0x8000 | zname_offset);
			buf += sizeof(short);
			dat_len += 4;
		  } else {
			/* use the long format */
			zname_sav = buf; 
			*buf++ = zname_len;
			bcopy(ZT_table[idx].Zone.str, buf, zname_len);
			buf += zname_len;
			dat_len += (3 + zname_len);
		  }
			tuples_cnt++;
			idx_sav = idx;
		}

	  } else {
		zmap = entry->ZoneBitMap;
		for (i=i_sav; i >=0; i--) {
			if (!zmap[i])
				continue;

			for (j=j_sav; j < 8; j++) {
				if (!((zmap[i] << j) & 0x80))
					continue;

				idx = i*8 + j; /* index in the zone table */
				zname_len = ZT_table[idx].Zone.len;
				if (zname_len) {
					if ((dat_len+3+zname_len) > AURP_MaxPktSize) {
						i_sav = i;
						j_sav = j;
						goto l_done;
					}

					assert(net_num != 0xdead); /* XXX */
					*(unsigned short *)buf = net_num;
					buf += sizeof(short);
				  if (idx == idx_sav) {
					/* use the optimized format */
					assert(zname_sav != 0xdeadbeef);/*XXX*/
					zname_offset = zname_sav - zname_base;
					*(unsigned short *)buf = (0x8000 | zname_offset);
					buf += sizeof(short);
					dat_len += 4;
				  } else {
					/* use the long format */
					zname_sav = buf; 
					*buf++ = zname_len;
					bcopy(ZT_table[idx].Zone.str, buf, zname_len);
					buf += zname_len;
					dat_len += (3 + zname_len);
				  }
					tuples_cnt++;
					idx_sav = idx;
				}
			}
		}
	  }
		if ((dat_len+3+32) > AURP_MaxPktSize) {
			next_entry++;
			break;
		}
	}
	i_sav = ZT_BYTES-1;
	j_sav = 0;

l_done:
	*len += dat_len;
	if (next_entry == nets_cnt)
		next_entry = 0;

	/* set the subcode in the ZI response packet */
	if (next_entry)
		*sub_codep = AURPSUBCODE_ZoneInfo2;

	/* set the tuples count in the ZI response packet */
	*tuples_cntp = tuples_cnt;

	idx_sav = -1;
	return next_entry;
}

/* */
static void
AURPsetzi(node, m, sub_code, tuples_cnt)
	unsigned char node;
	gbuf_t *m;
	short sub_code;
	short tuples_cnt;
{
	int rc, tuple_fmt;
	unsigned short net_num, zname_offset;
	unsigned char *buf = gbuf_rptr(m), *zname_base;
	RT_entry *entry;
	at_nvestr_t *zname;

	/* compute the base of the zone names of the optimized tuples */
	zname_base = buf + sizeof(short);

	/* process all tuples */
	while (tuples_cnt-- > 0) {
		net_num = *(unsigned short *)buf;
		buf += sizeof(short);
		if (*buf & 0x80) {
			/* optimized-format tuple */
			zname_offset = (*(unsigned short *)buf) & 0x7fff;
			buf += sizeof(short);
			zname = (at_nvestr_t *)(zname_base + zname_offset);
			tuple_fmt = 0;
			dPrintf(D_M_AURP_LOW, D_L_INFO,
				("AURPsetzi: optimized fmt, net=%d. zlen=%d, zoffset=%d\n ",
					net_num, zname->len, zname_offset));
		} else {
			/* long-format tuple */
			zname = (at_nvestr_t *)buf;
			tuple_fmt = 1;
			dPrintf(D_M_AURP_LOW, D_L_INFO,
				("AURPsetzi: long fmt, net=%d, zlen=%d\n ",
					net_num, zname->len));
		}

		/*
		 * find the RT entry associated with the specified network
		 */
		if ((entry = rt_blookup(net_num)) == 0) {
			dPrintf(D_M_AURP, D_L_WARNING,
				("AURPsetzi: invalid net, net=%d\n", net_num));
		} else { /* entry found */
			if (entry->EntryState >= RTE_STATE_SUSPECT)  {
				if ((rc = zt_add_zonename(zname)) == ZT_MAXEDOUT) {
					dPrintf(D_M_AURP, D_L_WARNING,
						("AURPsetzi: ZT_table full\n"));
				} else {
					zt_set_zmap(rc, entry->ZoneBitMap);
					RT_SET_ZONE_KNOWN(entry);
				}
			}
		}
		if (tuple_fmt)
			buf += zname->len+1;
	}
}
