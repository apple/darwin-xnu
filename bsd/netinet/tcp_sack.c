/*
 * Copyright (c) 2004-2016 Apple Inc. All rights reserved.
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
/*
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#define	_IP_VHL


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <kern/zalloc.h>

#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#if INET6
#include <netinet6/in6_pcb.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#endif
#include <netinet/tcp.h>
//#define	TCPOUTFLAGS
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_cache.h>
#if TCPDEBUG
#include <netinet/tcp_debug.h>
#endif
#include <sys/kdebug.h>

#if IPSEC
#include <netinet6/ipsec.h>
#endif /*IPSEC*/

#include <libkern/OSAtomic.h>

SYSCTL_SKMEM_TCP_INT(OID_AUTO, sack, CTLFLAG_RW | CTLFLAG_LOCKED,
	int, tcp_do_sack, 1, "Enable/Disable TCP SACK support");
SYSCTL_SKMEM_TCP_INT(OID_AUTO, sack_maxholes, CTLFLAG_RW | CTLFLAG_LOCKED,
	static int, tcp_sack_maxholes, 128,
    "Maximum number of TCP SACK holes allowed per connection");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, sack_globalmaxholes,
	CTLFLAG_RW | CTLFLAG_LOCKED, static int, tcp_sack_globalmaxholes, 65536,
    "Global maximum number of TCP SACK holes");

static SInt32 tcp_sack_globalholes = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, sack_globalholes, CTLFLAG_RD | CTLFLAG_LOCKED,
    &tcp_sack_globalholes, 0,
    "Global number of TCP SACK holes currently allocated");

static int tcp_detect_reordering = 1;
static int tcp_dsack_ignore_hw_duplicates = 0;

#if (DEVELOPMENT || DEBUG)
SYSCTL_INT(_net_inet_tcp, OID_AUTO, detect_reordering,
    CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_detect_reordering, 0, "");

SYSCTL_INT(_net_inet_tcp, OID_AUTO, ignore_hw_duplicates,
    CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_dsack_ignore_hw_duplicates, 0, "");
#endif /* (DEVELOPMENT || DEBUG) */

extern struct zone *sack_hole_zone;

#define	TCP_VALIDATE_SACK_SEQ_NUMBERS(_tp_, _sb_, _ack_) \
    (SEQ_GT((_sb_)->end, (_sb_)->start) && \
    SEQ_GT((_sb_)->start, (_tp_)->snd_una) && \
    SEQ_GT((_sb_)->start, (_ack_)) && \
    SEQ_LT((_sb_)->start, (_tp_)->snd_max) && \
    SEQ_GT((_sb_)->end, (_tp_)->snd_una) && \
    SEQ_LEQ((_sb_)->end, (_tp_)->snd_max))

/*
 * This function is called upon receipt of new valid data (while not in header
 * prediction mode), and it updates the ordered list of sacks.
 */
void
tcp_update_sack_list(struct tcpcb *tp, tcp_seq rcv_start, tcp_seq rcv_end)
{
	/*
	 * First reported block MUST be the most recent one.  Subsequent
	 * blocks SHOULD be in the order in which they arrived at the
	 * receiver.  These two conditions make the implementation fully
	 * compliant with RFC 2018.
	 */
	struct sackblk head_blk, saved_blks[MAX_SACK_BLKS];
	int num_head, num_saved, i;

	/* SACK block for the received segment. */
	head_blk.start = rcv_start;
	head_blk.end = rcv_end;

	/*
	 * Merge updated SACK blocks into head_blk, and
	 * save unchanged SACK blocks into saved_blks[].
	 * num_saved will have the number of the saved SACK blocks.
	 */
	num_saved = 0;
	for (i = 0; i < tp->rcv_numsacks; i++) {
		tcp_seq start = tp->sackblks[i].start;
		tcp_seq end = tp->sackblks[i].end;
		if (SEQ_GEQ(start, end) || SEQ_LEQ(start, tp->rcv_nxt)) {
			/*
			 * Discard this SACK block.
			 */
		} else if (SEQ_LEQ(head_blk.start, end) &&
			   SEQ_GEQ(head_blk.end, start)) {
			/*
			 * Merge this SACK block into head_blk.
			 * This SACK block itself will be discarded.
			 */
			if (SEQ_GT(head_blk.start, start))
				head_blk.start = start;
			if (SEQ_LT(head_blk.end, end))
				head_blk.end = end;
		} else {
			/*
			 * Save this SACK block.
			 */
			saved_blks[num_saved].start = start;
			saved_blks[num_saved].end = end;
			num_saved++;
		}
	}

	/*
	 * Update SACK list in tp->sackblks[].
	 */
	num_head = 0;
	if (SEQ_GT(head_blk.start, tp->rcv_nxt)) {
		/*
		 * The received data segment is an out-of-order segment.
		 * Put head_blk at the top of SACK list.
		 */
		tp->sackblks[0] = head_blk;
		num_head = 1;
		/*
		 * If the number of saved SACK blocks exceeds its limit,
		 * discard the last SACK block.
		 */
		if (num_saved >= MAX_SACK_BLKS)
			num_saved--;
	}
	if (num_saved > 0) {
		/*
		 * Copy the saved SACK blocks back.
		 */
		bcopy(saved_blks, &tp->sackblks[num_head],
		      sizeof(struct sackblk) * num_saved);
	}

	/* Save the number of SACK blocks. */
	tp->rcv_numsacks = num_head + num_saved;

	/* If we are requesting SACK recovery, reset the stretch-ack state
	 * so that connection will generate more acks after recovery and
	 * sender's cwnd will open.
	 */
	if ((tp->t_flags & TF_STRETCHACK) != 0 && tp->rcv_numsacks > 0)
		tcp_reset_stretch_ack(tp);

#if TRAFFIC_MGT
	if (tp->acc_iaj > 0 && tp->rcv_numsacks > 0) 
		reset_acc_iaj(tp);
#endif /* TRAFFIC_MGT */
}

/*
 * Delete all receiver-side SACK information.
 */
void
tcp_clean_sackreport( struct tcpcb *tp)
{

	tp->rcv_numsacks = 0;
	bzero(&tp->sackblks[0], sizeof (struct sackblk) * MAX_SACK_BLKS);
}

/*
 * Allocate struct sackhole.
 */
static struct sackhole *
tcp_sackhole_alloc(struct tcpcb *tp, tcp_seq start, tcp_seq end)
{
	struct sackhole *hole;

	if (tp->snd_numholes >= tcp_sack_maxholes ||
	    tcp_sack_globalholes >= tcp_sack_globalmaxholes) {
		tcpstat.tcps_sack_sboverflow++;
		return NULL;
	}

	hole = (struct sackhole *)zalloc(sack_hole_zone);
	if (hole == NULL)
		return NULL;

	hole->start = start;
	hole->end = end;
	hole->rxmit = start;

	tp->snd_numholes++;
	OSIncrementAtomic(&tcp_sack_globalholes);

	return hole;
}

/*
 * Free struct sackhole.
 */
static void
tcp_sackhole_free(struct tcpcb *tp, struct sackhole *hole)
{
	zfree(sack_hole_zone, hole);

	tp->snd_numholes--;
	OSDecrementAtomic(&tcp_sack_globalholes);
}

/*
 * Insert new SACK hole into scoreboard.
 */
static struct sackhole *
tcp_sackhole_insert(struct tcpcb *tp, tcp_seq start, tcp_seq end,
		    struct sackhole *after)
{
	struct sackhole *hole;

	/* Allocate a new SACK hole. */
	hole = tcp_sackhole_alloc(tp, start, end);
	if (hole == NULL)
		return NULL;
	hole->rxmit_start = tcp_now;
	/* Insert the new SACK hole into scoreboard */
	if (after != NULL)
		TAILQ_INSERT_AFTER(&tp->snd_holes, after, hole, scblink);
	else
		TAILQ_INSERT_TAIL(&tp->snd_holes, hole, scblink);

	/* Update SACK hint. */
	if (tp->sackhint.nexthole == NULL)
		tp->sackhint.nexthole = hole;

	return(hole);
}

/*
 * Remove SACK hole from scoreboard.
 */
static void
tcp_sackhole_remove(struct tcpcb *tp, struct sackhole *hole)
{
	/* Update SACK hint. */
	if (tp->sackhint.nexthole == hole)
		tp->sackhint.nexthole = TAILQ_NEXT(hole, scblink);

	/* Remove this SACK hole. */
	TAILQ_REMOVE(&tp->snd_holes, hole, scblink);

	/* Free this SACK hole. */
	tcp_sackhole_free(tp, hole);
}
/*
 * When a new ack with SACK is received, check if it indicates packet
 * reordering. If there is packet reordering, the socket is marked and
 * the late time offset by which the packet was reordered with
 * respect to its closest neighboring packets is computed.
 */
static void
tcp_sack_detect_reordering(struct tcpcb *tp, struct sackhole *s,
    tcp_seq sacked_seq, tcp_seq snd_fack)
{
	int32_t rext = 0, reordered = 0;

	/*
	 * If the SACK hole is past snd_fack, this is from new SACK
	 * information, so we can ignore it.
	 */
	if (SEQ_GT(s->end, snd_fack))
		return;
	/*
	 * If there has been a retransmit timeout, then the timestamp on 
	 * the SACK segment will be newer. This might lead to a
	 * false-positive. Avoid re-ordering detection in this case.
	 */
	if (tp->t_rxtshift > 0)
		return;

	/*
	 * Detect reordering from SACK information by checking
	 * if recently sacked data was never retransmitted from this hole.
	 */
	if (SEQ_LT(s->rxmit, sacked_seq)) {
		reordered = 1;
		tcpstat.tcps_avoid_rxmt++;
	}

	if (reordered) {
		if (tcp_detect_reordering == 1 &&
		    !(tp->t_flagsext & TF_PKTS_REORDERED)) {
			tp->t_flagsext |= TF_PKTS_REORDERED;
			tcpstat.tcps_detect_reordering++;
		}

		tcpstat.tcps_reordered_pkts++;
		tp->t_reordered_pkts++;

		/*
		 * If reordering is seen on a connection wth ECN enabled,
		 * increment the heuristic
		 */
		if (TCP_ECN_ENABLED(tp)) {
			INP_INC_IFNET_STAT(tp->t_inpcb, ecn_fallback_reorder);
			tcpstat.tcps_ecn_fallback_reorder++;
			tcp_heuristic_ecn_aggressive(tp);
		}

		VERIFY(SEQ_GEQ(snd_fack, s->rxmit));

		if (s->rxmit_start > 0) {
			rext = timer_diff(tcp_now, 0, s->rxmit_start, 0);
			if (rext < 0)
				return;

			/*
			 * We take the maximum reorder window to schedule
			 * DELAYFR timer as that will take care of jitter
			 * on the network path.
			 *
			 * Computing average and standard deviation seems
			 * to cause unnecessary retransmissions when there
			 * is high jitter.
			 *
			 * We set a maximum of SRTT/2 and a minimum of
			 * 10 ms on the reorder window.
			 */
			tp->t_reorderwin = max(tp->t_reorderwin, rext);
			tp->t_reorderwin = min(tp->t_reorderwin,
			    (tp->t_srtt >> (TCP_RTT_SHIFT - 1)));
			tp->t_reorderwin = max(tp->t_reorderwin, 10);
		}
	}
}

/*
 * Process cumulative ACK and the TCP SACK option to update the scoreboard.
 * tp->snd_holes is an ordered list of holes (oldest to newest, in terms of
 * the sequence space).
 */
void
tcp_sack_doack(struct tcpcb *tp, struct tcpopt *to, struct tcphdr *th, 
	u_int32_t *newbytes_acked)
{
	struct sackhole *cur, *temp;
	struct sackblk sack, sack_blocks[TCP_MAX_SACK + 1], *sblkp;
	int i, j, num_sack_blks;
	tcp_seq old_snd_fack = 0, th_ack = th->th_ack;

	num_sack_blks = 0;
	/*
	 * If SND.UNA will be advanced by SEG.ACK, and if SACK holes exist,
	 * treat [SND.UNA, SEG.ACK) as if it is a SACK block.
	 */
	if (SEQ_LT(tp->snd_una, th_ack) && !TAILQ_EMPTY(&tp->snd_holes)) {
		sack_blocks[num_sack_blks].start = tp->snd_una;
		sack_blocks[num_sack_blks++].end = th_ack;
	}
	/*
	 * Append received valid SACK blocks to sack_blocks[].
	 * Check that the SACK block range is valid.
	 */
	for (i = 0; i < to->to_nsacks; i++) {
		bcopy((to->to_sacks + i * TCPOLEN_SACK),
		    &sack, sizeof(sack));
		sack.start = ntohl(sack.start);
		sack.end = ntohl(sack.end);
		if (TCP_VALIDATE_SACK_SEQ_NUMBERS(tp, &sack, th_ack))
			sack_blocks[num_sack_blks++] = sack;
	}

	/*
	 * Return if SND.UNA is not advanced and no valid SACK block
	 * is received.
	 */
	if (num_sack_blks == 0)
		return;

	VERIFY(num_sack_blks <= (TCP_MAX_SACK + 1));
	/*
	 * Sort the SACK blocks so we can update the scoreboard
	 * with just one pass. The overhead of sorting upto 4+1 elements
	 * is less than making upto 4+1 passes over the scoreboard.
	 */
	for (i = 0; i < num_sack_blks; i++) {
		for (j = i + 1; j < num_sack_blks; j++) {
			if (SEQ_GT(sack_blocks[i].end, sack_blocks[j].end)) {
				sack = sack_blocks[i];
				sack_blocks[i] = sack_blocks[j];
				sack_blocks[j] = sack;
			}
		}
	}
	if (TAILQ_EMPTY(&tp->snd_holes)) {
		/*
		 * Empty scoreboard. Need to initialize snd_fack (it may be
		 * uninitialized or have a bogus value). Scoreboard holes
		 * (from the sack blocks received) are created later below (in
		 * the logic that adds holes to the tail of the scoreboard).
		 */
		tp->snd_fack = SEQ_MAX(tp->snd_una, th_ack);
		*newbytes_acked += (tp->snd_fack - tp->snd_una);
	}

	old_snd_fack = tp->snd_fack;
	/*
	 * In the while-loop below, incoming SACK blocks (sack_blocks[])
	 * and SACK holes (snd_holes) are traversed from their tails with
	 * just one pass in order to reduce the number of compares especially
	 * when the bandwidth-delay product is large.
	 * Note: Typically, in the first RTT of SACK recovery, the highest
	 * three or four SACK blocks with the same ack number are received.
	 * In the second RTT, if retransmitted data segments are not lost,
	 * the highest three or four SACK blocks with ack number advancing
	 * are received.
	 */
	sblkp = &sack_blocks[num_sack_blks - 1];	/* Last SACK block */
	if (SEQ_LT(tp->snd_fack, sblkp->start)) {
		/*
		 * The highest SACK block is beyond fack.
		 * Append new SACK hole at the tail.
		 * If the second or later highest SACK blocks are also
		 * beyond the current fack, they will be inserted by
		 * way of hole splitting in the while-loop below.
		 */
		temp = tcp_sackhole_insert(tp, tp->snd_fack,sblkp->start,NULL);
		if (temp != NULL) {
			tp->snd_fack = sblkp->end;
			*newbytes_acked += (sblkp->end - sblkp->start);

			/* Go to the previous sack block. */
			sblkp--;
		} else {
			/* 
			 * We failed to add a new hole based on the current 
			 * sack block.  Skip over all the sack blocks that 
			 * fall completely to the right of snd_fack and proceed
			 * to trim the scoreboard based on the remaining sack
			 * blocks. This also trims the scoreboard for th_ack 
			 * (which is sack_blocks[0]).
			 */
			while (sblkp >= sack_blocks && 
			       SEQ_LT(tp->snd_fack, sblkp->start))
				sblkp--;
			if (sblkp >= sack_blocks && 
			    SEQ_LT(tp->snd_fack, sblkp->end)) {
				*newbytes_acked += (sblkp->end - tp->snd_fack);
				tp->snd_fack = sblkp->end;
			}
		}
	} else if (SEQ_LT(tp->snd_fack, sblkp->end)) {
		/* fack is advanced. */
		*newbytes_acked += (sblkp->end - tp->snd_fack);
		tp->snd_fack = sblkp->end;
	}
	/* We must have at least one SACK hole in scoreboard */
	cur = TAILQ_LAST(&tp->snd_holes, sackhole_head); /* Last SACK hole */
	/*
	 * Since the incoming sack blocks are sorted, we can process them
	 * making one sweep of the scoreboard.
	 */
	while (sblkp >= sack_blocks  && cur != NULL) {
		if (SEQ_GEQ(sblkp->start, cur->end)) {
			/*
			 * SACKs data beyond the current hole.
			 * Go to the previous sack block.
			 */
			sblkp--;
			continue;
		}
		if (SEQ_LEQ(sblkp->end, cur->start)) {
			/*
			 * SACKs data before the current hole.
			 * Go to the previous hole.
			 */
			cur = TAILQ_PREV(cur, sackhole_head, scblink);
			continue;
		}
		tp->sackhint.sack_bytes_rexmit -= (cur->rxmit - cur->start);
		if (SEQ_LEQ(sblkp->start, cur->start)) {
			/* Data acks at least the beginning of hole */
			if (SEQ_GEQ(sblkp->end, cur->end)) {
				/* Acks entire hole, so delete hole */
				*newbytes_acked += (cur->end - cur->start);

				tcp_sack_detect_reordering(tp, cur,
				    cur->end, old_snd_fack);
				temp = cur;
				cur = TAILQ_PREV(cur, sackhole_head, scblink);
				tcp_sackhole_remove(tp, temp);
				/*
				 * The sack block may ack all or part of the next
				 * hole too, so continue onto the next hole.
				 */
				continue;
			} else {
				/* Move start of hole forward */
				*newbytes_acked += (sblkp->end - cur->start);
				tcp_sack_detect_reordering(tp, cur,
				    sblkp->end, old_snd_fack);
				cur->start = sblkp->end;
				cur->rxmit = SEQ_MAX(cur->rxmit, cur->start);
			}
		} else {
			/* Data acks at least the end of hole */
			if (SEQ_GEQ(sblkp->end, cur->end)) {
				/* Move end of hole backward */
				*newbytes_acked += (cur->end - sblkp->start);
				tcp_sack_detect_reordering(tp, cur,
				    cur->end, old_snd_fack);
				cur->end = sblkp->start;
				cur->rxmit = SEQ_MIN(cur->rxmit, cur->end);
			} else {
				/*
				 * ACKs some data in the middle of a hole;
				 * need to split current hole
				 */
				*newbytes_acked += (sblkp->end - sblkp->start);
				tcp_sack_detect_reordering(tp, cur,
				    sblkp->end, old_snd_fack);
				temp = tcp_sackhole_insert(tp, sblkp->end,
				    cur->end, cur);
				if (temp != NULL) {
					if (SEQ_GT(cur->rxmit, temp->rxmit)) {
						temp->rxmit = cur->rxmit;
						tp->sackhint.sack_bytes_rexmit
							+= (temp->rxmit
							    - temp->start);
					}
					cur->end = sblkp->start;
					cur->rxmit = SEQ_MIN(cur->rxmit,
							     cur->end);
					/*
					 * Reset the rxmit_start to that of
					 * the current hole as that will
					 * help to compute the reorder
					 * window correctly
					 */
					temp->rxmit_start = cur->rxmit_start;
				}
			}
		}
		tp->sackhint.sack_bytes_rexmit += (cur->rxmit - cur->start);
		/*
		 * Testing sblkp->start against cur->start tells us whether
		 * we're done with the sack block or the sack hole.
		 * Accordingly, we advance one or the other.
		 */
		if (SEQ_LEQ(sblkp->start, cur->start))
			cur = TAILQ_PREV(cur, sackhole_head, scblink);
		else
			sblkp--;
	}
}

/*
 * Free all SACK holes to clear the scoreboard.
 */
void
tcp_free_sackholes(struct tcpcb *tp)
{
	struct sackhole *q;

	while ((q = TAILQ_FIRST(&tp->snd_holes)) != NULL)
		tcp_sackhole_remove(tp, q);
	tp->sackhint.sack_bytes_rexmit = 0;
	tp->sackhint.nexthole = NULL;
	tp->sack_newdata = 0;

}

/*
 * Partial ack handling within a sack recovery episode. 
 * Keeping this very simple for now. When a partial ack
 * is received, force snd_cwnd to a value that will allow
 * the sender to transmit no more than 2 segments.
 * If necessary, a better scheme can be adopted at a 
 * later point, but for now, the goal is to prevent the
 * sender from bursting a large amount of data in the midst
 * of sack recovery.
 */
void
tcp_sack_partialack(struct tcpcb *tp, struct tcphdr *th)
{
	int num_segs = 1;

	tp->t_timer[TCPT_REXMT] = 0;
	tp->t_rtttime = 0;
	/* send one or 2 segments based on how much new data was acked */
	if (((BYTES_ACKED(th, tp)) / tp->t_maxseg) > 2)
		num_segs = 2;
	tp->snd_cwnd = (tp->sackhint.sack_bytes_rexmit +
		(tp->snd_nxt - tp->sack_newdata) +
		num_segs * tp->t_maxseg);
	if (tp->snd_cwnd > tp->snd_ssthresh)
		tp->snd_cwnd = tp->snd_ssthresh;
	if (SEQ_LT(tp->snd_fack, tp->snd_recover) &&
	    tp->snd_fack == th->th_ack && TAILQ_EMPTY(&tp->snd_holes)) {
		struct sackhole *temp;
		/*
		 * we received a partial ack but there is no sack_hole
		 * that will cover the remaining seq space. In this case,
		 * create a hole from snd_fack to snd_recover so that
		 * the sack recovery will continue.
		 */
		temp = tcp_sackhole_insert(tp, tp->snd_fack,
		    tp->snd_recover, NULL);
		if (temp != NULL)
			tp->snd_fack = tp->snd_recover;
	}
	(void) tcp_output(tp);
}

/*
 * Debug version of tcp_sack_output() that walks the scoreboard. Used for
 * now to sanity check the hint.
 */
static struct sackhole *
tcp_sack_output_debug(struct tcpcb *tp, int *sack_bytes_rexmt)
{
	struct sackhole *p;

	*sack_bytes_rexmt = 0;
	TAILQ_FOREACH(p, &tp->snd_holes, scblink) {
		if (SEQ_LT(p->rxmit, p->end)) {
			if (SEQ_LT(p->rxmit, tp->snd_una)) {/* old SACK hole */
				continue;
			}
			*sack_bytes_rexmt += (p->rxmit - p->start);
			break;
		}
		*sack_bytes_rexmt += (p->rxmit - p->start);
	}
	return (p);
}

/*
 * Returns the next hole to retransmit and the number of retransmitted bytes
 * from the scoreboard. We store both the next hole and the number of
 * retransmitted bytes as hints (and recompute these on the fly upon SACK/ACK
 * reception). This avoids scoreboard traversals completely.
 *
 * The loop here will traverse *at most* one link. Here's the argument.
 * For the loop to traverse more than 1 link before finding the next hole to
 * retransmit, we would need to have at least 1 node following the current hint
 * with (rxmit == end). But, for all holes following the current hint,
 * (start == rxmit), since we have not yet retransmitted from them. Therefore,
 * in order to traverse more 1 link in the loop below, we need to have at least
 * one node following the current hint with (start == rxmit == end).
 * But that can't happen, (start == end) means that all the data in that hole
 * has been sacked, in which case, the hole would have been removed from the
 * scoreboard.
 */
struct sackhole *
tcp_sack_output(struct tcpcb *tp, int *sack_bytes_rexmt)
{
	struct sackhole *hole = NULL, *dbg_hole = NULL;
	int dbg_bytes_rexmt;

	dbg_hole = tcp_sack_output_debug(tp, &dbg_bytes_rexmt);
	*sack_bytes_rexmt = tp->sackhint.sack_bytes_rexmit;
	hole = tp->sackhint.nexthole;
	if (hole == NULL || SEQ_LT(hole->rxmit, hole->end))
		goto out;
	while ((hole = TAILQ_NEXT(hole, scblink)) != NULL) {
		if (SEQ_LT(hole->rxmit, hole->end)) {
			tp->sackhint.nexthole = hole;
			break;
		}
	}
out:
	if (dbg_hole != hole) {
		printf("%s: Computed sack hole not the same as cached value\n", __func__);
		hole = dbg_hole;
	}
	if (*sack_bytes_rexmt != dbg_bytes_rexmt) {
		printf("%s: Computed sack_bytes_retransmitted (%d) not "
		       "the same as cached value (%d)\n",
		       __func__, dbg_bytes_rexmt, *sack_bytes_rexmt);
		*sack_bytes_rexmt = dbg_bytes_rexmt;
	}
	return (hole);
}

/*
 * After a timeout, the SACK list may be rebuilt.  This SACK information
 * should be used to avoid retransmitting SACKed data.  This function
 * traverses the SACK list to see if snd_nxt should be moved forward.
 */
void
tcp_sack_adjust(struct tcpcb *tp)
{
	struct sackhole *p, *cur = TAILQ_FIRST(&tp->snd_holes);

	if (cur == NULL)
		return; /* No holes */
	if (SEQ_GEQ(tp->snd_nxt, tp->snd_fack))
		return; /* We're already beyond any SACKed blocks */
	/*
	 * Two cases for which we want to advance snd_nxt:
	 * i) snd_nxt lies between end of one hole and beginning of another
	 * ii) snd_nxt lies between end of last hole and snd_fack
	 */
	while ((p = TAILQ_NEXT(cur, scblink)) != NULL) {
		if (SEQ_LT(tp->snd_nxt, cur->end))
			return;
		if (SEQ_GEQ(tp->snd_nxt, p->start))
			cur = p;
		else {
			tp->snd_nxt = p->start;
			return;
		}
	}
	if (SEQ_LT(tp->snd_nxt, cur->end))
		return;
	tp->snd_nxt = tp->snd_fack;
	return;
}

/*
 * This function returns TRUE if more than (tcprexmtthresh - 1) * SMSS
 * bytes with sequence numbers greater than snd_una have been SACKed. 
 */
boolean_t
tcp_sack_byte_islost(struct tcpcb *tp)
{
	u_int32_t unacked_bytes, sndhole_bytes = 0;
	struct sackhole *sndhole;
	if (!SACK_ENABLED(tp) || IN_FASTRECOVERY(tp) ||
	    TAILQ_EMPTY(&tp->snd_holes) ||
	    (tp->t_flagsext & TF_PKTS_REORDERED))
		return (FALSE);

	unacked_bytes = tp->snd_max - tp->snd_una;

	TAILQ_FOREACH(sndhole, &tp->snd_holes, scblink) {
		sndhole_bytes += (sndhole->end - sndhole->start);
	}

	VERIFY(unacked_bytes >= sndhole_bytes);
	return ((unacked_bytes - sndhole_bytes) >
	    ((tcprexmtthresh - 1) * tp->t_maxseg));
}

/*
 * Process any DSACK options that might be present on an input packet
 */

boolean_t
tcp_sack_process_dsack(struct tcpcb *tp, struct tcpopt *to,
    struct tcphdr *th)
{
	struct sackblk first_sack, second_sack;
	struct tcp_rxt_seg *rxseg;

	bcopy(to->to_sacks, &first_sack, sizeof(first_sack));
	first_sack.start = ntohl(first_sack.start);
	first_sack.end = ntohl(first_sack.end);

	if (to->to_nsacks > 1) {
		bcopy((to->to_sacks + TCPOLEN_SACK), &second_sack,
		    sizeof(second_sack));
		second_sack.start = ntohl(second_sack.start);
		second_sack.end = ntohl(second_sack.end);
	}

	if (SEQ_LT(first_sack.start, th->th_ack) &&
	    SEQ_LEQ(first_sack.end, th->th_ack)) {
		/*
		 * There is a dsack option reporting a duplicate segment
		 * also covered by cumulative acknowledgement.
		 *
		 * Validate the sequence numbers before looking at dsack
		 * option. The duplicate notification can come after
		 * snd_una moves forward. In order to set a window of valid
		 * sequence numbers to look for, we set a maximum send
		 * window within which the DSACK option will be processed.
		 */
		if (!(TCP_DSACK_SEQ_IN_WINDOW(tp, first_sack.start, th->th_ack) &&
		    TCP_DSACK_SEQ_IN_WINDOW(tp, first_sack.end, th->th_ack))) {
			to->to_nsacks--;
			to->to_sacks += TCPOLEN_SACK;
			tcpstat.tcps_dsack_recvd_old++;

			/*
			 * returning true here so that the ack will not be
			 * treated as duplicate ack.
			 */
			return (TRUE);
		}
	} else if (to->to_nsacks > 1 &&
	    SEQ_LEQ(second_sack.start, first_sack.start) &&
	    SEQ_GEQ(second_sack.end, first_sack.end)) {
		/*
		 * there is a dsack option in the first block not
		 * covered by the cumulative acknowledgement but covered
		 * by the second sack block.
		 *
		 * verify the sequence numbes on the second sack block
		 * before processing the DSACK option. Returning false
		 * here will treat the ack as a duplicate ack.
		 */
		if (!TCP_VALIDATE_SACK_SEQ_NUMBERS(tp, &second_sack,
		    th->th_ack)) {
			to->to_nsacks--;
			to->to_sacks += TCPOLEN_SACK;
			tcpstat.tcps_dsack_recvd_old++;
			return (TRUE);
		}
	} else {
		/* no dsack options, proceed with processing the sack */
		return (FALSE);
	}

	/* Update the tcpopt pointer to exclude dsack block */
	to->to_nsacks--;
	to->to_sacks += TCPOLEN_SACK;
	tcpstat.tcps_dsack_recvd++;
	tp->t_dsack_recvd++;

	/* ignore DSACK option, if DSACK is disabled */
	if (tp->t_flagsext & TF_DISABLE_DSACK)
		return (TRUE);

	/* If the DSACK is for TLP mark it as such */
	if ((tp->t_flagsext & TF_SENT_TLPROBE) &&
	    first_sack.end == tp->t_tlphighrxt) {
		if ((rxseg = tcp_rxtseg_find(tp, first_sack.start,
		    (first_sack.end - 1))) != NULL)
			rxseg->rx_flags |= TCP_RXT_DSACK_FOR_TLP;
	}
	/* Update the sender's retransmit segment state */
	if (((tp->t_rxtshift == 1 && first_sack.start == tp->snd_una) ||
	    ((tp->t_flagsext & TF_SENT_TLPROBE) &&
	    first_sack.end == tp->t_tlphighrxt)) &&
	    TAILQ_EMPTY(&tp->snd_holes) &&
	    SEQ_GT(th->th_ack, tp->snd_una)) {
		/*
		 * If the dsack is for a retransmitted packet and one of
		 * the two cases is true, it indicates ack loss:
		 * - retransmit timeout and first_sack.start == snd_una
		 * - TLP probe and first_sack.end == tlphighrxt
		 *
		 * Ignore dsack and do not update state when there is
		 * ack loss
		 */
		tcpstat.tcps_dsack_ackloss++;

		return (TRUE);
	} else if ((rxseg = tcp_rxtseg_find(tp, first_sack.start,
	    (first_sack.end - 1))) == NULL) {
		/*
		 * Duplicate notification was not triggered by a
		 * retransmission. This might be due to network duplication,
		 * disable further DSACK processing.
		 */
		if (!tcp_dsack_ignore_hw_duplicates) {
			tp->t_flagsext |= TF_DISABLE_DSACK;
			tcpstat.tcps_dsack_disable++;
		}
	} else {
		/*
		 * If the segment was retransmitted only once, mark it as
		 * spurious. Otherwise ignore the duplicate notification.
		 */
		if (rxseg->rx_count == 1)
			rxseg->rx_flags |= TCP_RXT_SPURIOUS;
		else
			rxseg->rx_flags &= ~TCP_RXT_SPURIOUS;
	}
	return (TRUE);
}
