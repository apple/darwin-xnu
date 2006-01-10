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
 * Copyright (c) 1988 Stephen Deering.
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Stephen Deering of Stanford University.
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
 *	@(#)igmp.c	8.1 (Berkeley) 7/19/93
 */

/*
 * Internet Group Management Protocol (IGMP) routines.
 *
 * Written by Steve Deering, Stanford, May 1988.
 * Modified by Rosen Sharma, Stanford, Aug 1994.
 * Modified by Bill Fenner, Xerox PARC, Feb 1995.
 * Modified to fully comply to IGMPv2 by Bill Fenner, Oct 1995.
 *
 * MULTICAST Revision: 3.5.1.4
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/igmp.h>
#include <netinet/igmp_var.h>

#ifndef __APPLE__
static MALLOC_DEFINE(M_IGMP, "igmp", "igmp state");
#endif

static struct router_info *
		find_rti(struct ifnet *ifp);

static struct igmpstat igmpstat;

SYSCTL_STRUCT(_net_inet_igmp, IGMPCTL_STATS, stats, CTLFLAG_RD,
	&igmpstat, igmpstat, "");

static int igmp_timers_are_running;
static u_long igmp_all_hosts_group;
static u_long igmp_all_rtrs_group;
static struct mbuf *router_alert;
static struct router_info *Head;

static void igmp_sendpkt(struct in_multi *, int, unsigned long);

void
igmp_init()
{
	struct ipoption *ra;

	/*
	 * To avoid byte-swapping the same value over and over again.
	 */
	igmp_all_hosts_group = htonl(INADDR_ALLHOSTS_GROUP);
	igmp_all_rtrs_group = htonl(INADDR_ALLRTRS_GROUP);

	igmp_timers_are_running = 0;

	/*
	 * Construct a Router Alert option to use in outgoing packets
	 */
	MGET(router_alert, M_DONTWAIT, MT_DATA);
	ra = mtod(router_alert, struct ipoption *);
	ra->ipopt_dst.s_addr = 0;
	ra->ipopt_list[0] = IPOPT_RA;	/* Router Alert Option */
	ra->ipopt_list[1] = 0x04;	/* 4 bytes long */
	ra->ipopt_list[2] = 0x00;
	ra->ipopt_list[3] = 0x00;
	router_alert->m_len = sizeof(ra->ipopt_dst) + ra->ipopt_list[1];

	Head = (struct router_info *) 0;
}

static struct router_info *
find_rti(
	struct ifnet *ifp)
{
	struct router_info *rti = Head;
	
	
#if IGMP_DEBUG
	printf("[igmp.c, _find_rti] --> entering \n");
#endif
	while (rti) {
		if (rti->rti_ifp == ifp) {
#if IGMP_DEBUG
			printf("[igmp.c, _find_rti] --> found old entry \n");
#endif
			return rti;
		}
		rti = rti->rti_next;
	}
	
	MALLOC(rti, struct router_info *, sizeof *rti, M_IGMP, M_NOWAIT);
	if (rti != NULL)
	{
		rti->rti_ifp = ifp;
		rti->rti_type = IGMP_V2_ROUTER;
		rti->rti_time = 0;
		rti->rti_next = Head;
		Head = rti;
	}
#if IGMP_DEBUG
	if (rti) printf("[igmp.c, _find_rti] --> created an entry \n");
#endif
	return rti;
}

void
igmp_input(
	struct mbuf *m,
	int iphlen)
{
	struct igmp *igmp;
	struct ip *ip;
	int igmplen;
	struct ifnet *ifp = m->m_pkthdr.rcvif;
	int minlen;
	struct in_multi *inm;
	struct in_ifaddr *ia;
	struct in_multistep step;
	struct router_info *rti;
	
	int timer; /** timer value in the igmp query header **/

	++igmpstat.igps_rcv_total;

	ip = mtod(m, struct ip *);
	igmplen = ip->ip_len;

	/*
	 * Validate lengths
	 */
	if (igmplen < IGMP_MINLEN) {
		++igmpstat.igps_rcv_tooshort;
		m_freem(m);
		return;
	}
	minlen = iphlen + IGMP_MINLEN;
	if ((m->m_flags & M_EXT || m->m_len < minlen) &&
	    (m = m_pullup(m, minlen)) == 0) {
		++igmpstat.igps_rcv_tooshort;
		return;
	}

	/*
	 * Validate checksum
	 */
	m->m_data += iphlen;
	m->m_len -= iphlen;
	igmp = mtod(m, struct igmp *);
	if (in_cksum(m, igmplen)) {
		++igmpstat.igps_rcv_badsum;
		m_freem(m);
		return;
	}
	m->m_data -= iphlen;
	m->m_len += iphlen;

	ip = mtod(m, struct ip *);
	timer = igmp->igmp_code * PR_FASTHZ / IGMP_TIMER_SCALE;
	if (timer == 0)
		timer = 1;
	rti = find_rti(ifp);
	if (rti == NULL) {
		m_freem(m);
		return;
	}

	/*
	 * In the IGMPv2 specification, there are 3 states and a flag.
	 *
	 * In Non-Member state, we simply don't have a membership record.
	 * In Delaying Member state, our timer is running (inm->inm_timer)
	 * In Idle Member state, our timer is not running (inm->inm_timer==0)
	 *
	 * The flag is inm->inm_state, it is set to IGMP_OTHERMEMBER if
	 * we have heard a report from another member, or IGMP_IREPORTEDLAST
	 * if I sent the last report.
	 */
	switch (igmp->igmp_type) {

	case IGMP_MEMBERSHIP_QUERY:
		++igmpstat.igps_rcv_queries;

		if (ifp->if_flags & IFF_LOOPBACK)
			break;

		if (igmp->igmp_code == 0) {
			/*
			 * Old router.  Remember that the querier on this
			 * interface is old, and set the timer to the
			 * value in RFC 1112.
			 */

			rti->rti_type = IGMP_V1_ROUTER;
			rti->rti_time = 0;

			timer = IGMP_MAX_HOST_REPORT_DELAY * PR_FASTHZ;

			if (ip->ip_dst.s_addr != igmp_all_hosts_group ||
			    igmp->igmp_group.s_addr != 0) {
				++igmpstat.igps_rcv_badqueries;
				m_freem(m);
				return;
			}
		} else {
			/*
			 * New router.  Simply do the new validity check.
			 */
			
			if (igmp->igmp_group.s_addr != 0 &&
			    !IN_MULTICAST(ntohl(igmp->igmp_group.s_addr))) {
				++igmpstat.igps_rcv_badqueries;
				m_freem(m);
				return;
			}
		}

		/*
		 * - Start the timers in all of our membership records
		 *   that the query applies to for the interface on
		 *   which the query arrived excl. those that belong
		 *   to the "all-hosts" group (224.0.0.1).
		 * - Restart any timer that is already running but has
		 *   a value longer than the requested timeout.
		 * - Use the value specified in the query message as
		 *   the maximum timeout.
		 */
		lck_mtx_lock(rt_mtx);
		IN_FIRST_MULTI(step, inm);
		while (inm != NULL) {
			if (inm->inm_ifp == ifp &&
			    inm->inm_addr.s_addr != igmp_all_hosts_group &&
			    (igmp->igmp_group.s_addr == 0 ||
			     igmp->igmp_group.s_addr == inm->inm_addr.s_addr)) {
				if (inm->inm_timer == 0 ||
				    inm->inm_timer > timer) {
					inm->inm_timer =
						IGMP_RANDOM_DELAY(timer);
					igmp_timers_are_running = 1;
				}
			}
			IN_NEXT_MULTI(step, inm);
		}
		lck_mtx_unlock(rt_mtx);

		break;

	case IGMP_V1_MEMBERSHIP_REPORT:
	case IGMP_V2_MEMBERSHIP_REPORT:
		/*
		 * For fast leave to work, we have to know that we are the
		 * last person to send a report for this group.  Reports
		 * can potentially get looped back if we are a multicast
		 * router, so discard reports sourced by me.
		 */
		IFP_TO_IA(ifp, ia);
		if (ia && ip->ip_src.s_addr == IA_SIN(ia)->sin_addr.s_addr)
			break;

		++igmpstat.igps_rcv_reports;

		if (ifp->if_flags & IFF_LOOPBACK)
			break;

		if (!IN_MULTICAST(ntohl(igmp->igmp_group.s_addr))) {
			++igmpstat.igps_rcv_badreports;
			m_freem(m);
			return;
		}

		/*
		 * KLUDGE: if the IP source address of the report has an
		 * unspecified (i.e., zero) subnet number, as is allowed for
		 * a booting host, replace it with the correct subnet number
		 * so that a process-level multicast routing demon can
		 * determine which subnet it arrived from.  This is necessary
		 * to compensate for the lack of any way for a process to
		 * determine the arrival interface of an incoming packet.
		 */
		if ((ntohl(ip->ip_src.s_addr) & IN_CLASSA_NET) == 0)
			if (ia) ip->ip_src.s_addr = htonl(ia->ia_subnet);

		/*
		 * If we belong to the group being reported, stop
		 * our timer for that group.
		 */
		ifnet_lock_shared(ifp);
		IN_LOOKUP_MULTI(igmp->igmp_group, ifp, inm);
		ifnet_lock_done(ifp);

		if (inm != NULL) {
			inm->inm_timer = 0;
			++igmpstat.igps_rcv_ourreports;

			inm->inm_state = IGMP_OTHERMEMBER;
		}

		break;
	}

	/*
	 * Pass all valid IGMP packets up to any process(es) listening
	 * on a raw IGMP socket.
	 */
	rip_input(m, iphlen);
}

int
igmp_joingroup(inm)
	struct in_multi *inm;
{

	if (inm->inm_addr.s_addr == igmp_all_hosts_group
	    || inm->inm_ifp->if_flags & IFF_LOOPBACK) {
		inm->inm_timer = 0;
		inm->inm_state = IGMP_OTHERMEMBER;
	} else {
		inm->inm_rti = find_rti(inm->inm_ifp);
		if (inm->inm_rti == NULL) return ENOMEM;
		igmp_sendpkt(inm, inm->inm_rti->rti_type, 0);
		inm->inm_timer = IGMP_RANDOM_DELAY(
					IGMP_MAX_HOST_REPORT_DELAY*PR_FASTHZ);
		inm->inm_state = IGMP_IREPORTEDLAST;
		igmp_timers_are_running = 1;
	}
	return 0;
}

void
igmp_leavegroup(inm)
	struct in_multi *inm;
{
	if (inm->inm_state == IGMP_IREPORTEDLAST &&
	    inm->inm_addr.s_addr != igmp_all_hosts_group &&
	    !(inm->inm_ifp->if_flags & IFF_LOOPBACK) &&
	    inm->inm_rti->rti_type != IGMP_V1_ROUTER)
		igmp_sendpkt(inm, IGMP_V2_LEAVE_GROUP, igmp_all_rtrs_group);
}

void
igmp_fasttimo()
{
	struct in_multi *inm;
	struct in_multistep step;

	/*
	 * Quick check to see if any work needs to be done, in order
	 * to minimize the overhead of fasttimo processing.
	 */

	if (!igmp_timers_are_running)
		return;

	igmp_timers_are_running = 0;
	IN_FIRST_MULTI(step, inm);
	while (inm != NULL) {
		if (inm->inm_timer == 0) {
			/* do nothing */
		} else if (--inm->inm_timer == 0) {
			igmp_sendpkt(inm, inm->inm_rti->rti_type, 0);
			inm->inm_state = IGMP_IREPORTEDLAST;
		} else {
			igmp_timers_are_running = 1;
		}
		IN_NEXT_MULTI(step, inm);
	}
}

void
igmp_slowtimo()
{
	struct router_info *rti =  Head;

#if IGMP_DEBUG
	printf("[igmp.c,_slowtimo] -- > entering \n");
#endif
	while (rti) {
	    if (rti->rti_type == IGMP_V1_ROUTER) {
		rti->rti_time++;
		if (rti->rti_time >= IGMP_AGE_THRESHOLD) {
			rti->rti_type = IGMP_V2_ROUTER;
		}
	    }
	    rti = rti->rti_next;
	}
#if IGMP_DEBUG	
	printf("[igmp.c,_slowtimo] -- > exiting \n");
#endif
}

static struct route igmprt;

static void
igmp_sendpkt(inm, type, addr)
	struct in_multi *inm;
	int type;
	unsigned long addr;
{
        struct mbuf *m;
        struct igmp *igmp;
        struct ip *ip;
        struct ip_moptions imo;

        MGETHDR(m, M_DONTWAIT, MT_HEADER);
        if (m == NULL)
                return;

	m->m_pkthdr.rcvif = loif;
	m->m_pkthdr.len = sizeof(struct ip) + IGMP_MINLEN;
	MH_ALIGN(m, IGMP_MINLEN + sizeof(struct ip));
	m->m_data += sizeof(struct ip);
        m->m_len = IGMP_MINLEN;
	m->m_pkthdr.csum_flags = 0;
	m->m_pkthdr.csum_data = 0;
        igmp = mtod(m, struct igmp *);
        igmp->igmp_type   = type;
        igmp->igmp_code   = 0;
        igmp->igmp_group  = inm->inm_addr;
        igmp->igmp_cksum  = 0;
        igmp->igmp_cksum  = in_cksum(m, IGMP_MINLEN);

        m->m_data -= sizeof(struct ip);
        m->m_len += sizeof(struct ip);
        ip = mtod(m, struct ip *);
        ip->ip_tos        = 0;
        ip->ip_len        = sizeof(struct ip) + IGMP_MINLEN;
        ip->ip_off        = 0;
        ip->ip_p          = IPPROTO_IGMP;
        ip->ip_src.s_addr = INADDR_ANY;
        ip->ip_dst.s_addr = addr ? addr : igmp->igmp_group.s_addr;

        imo.imo_multicast_ifp  = inm->inm_ifp;
        imo.imo_multicast_ttl  = 1;
	imo.imo_multicast_vif  = -1;
        /*
         * Request loopback of the report if we are acting as a multicast
         * router, so that the process-level routing demon can hear it.
         */
        imo.imo_multicast_loop = (ip_mrouter != NULL);

	/*
	 * XXX
	 * Do we have to worry about reentrancy here?  Don't think so.
	 */
        ip_output(m, router_alert, &igmprt, 0, &imo);

        ++igmpstat.igps_snd_reports;
}
