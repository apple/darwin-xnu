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
 * Copyright (C) 1995-1997 by Darren Reed.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and due credit is given
 * to the original author and the contributors.
 */
#if !defined(lint)
/* static const char sccsid[] = "@(#)ip_state.c	1.8 6/5/96 (C) 1993-1995 Darren Reed"; */
#endif

#include "opt_ipfilter.h"
#if defined(KERNEL) && !defined(_KERNEL)
#define _KERNEL
#endif
#define __FreeBSD_version 300000        /* it's a hack, but close enough */

#if !defined(_KERNEL) && !defined(KERNEL) && !defined(__KERNEL__)
# include <stdlib.h>
# include <string.h>
#else
# ifdef linux
#  include <linux/kernel.h>
#  include <linux/module.h>
# endif
#endif
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/file.h>
#if defined(KERNEL) && (__FreeBSD_version >= 220000)
# include <sys/filio.h>
# include <sys/fcntl.h>
# include <sys/malloc.h>
#else
# include <sys/ioctl.h>
#endif
#include <sys/time.h>
#include <sys/uio.h>
#ifndef linux
#include <sys/protosw.h>
#endif
#include <sys/socket.h>
#if defined(_KERNEL) && !defined(linux)
# include <sys/systm.h>
#endif
#if !defined(__SVR4) && !defined(__svr4__)
# ifndef linux
#  include <sys/mbuf.h>
# endif
#else
# include <sys/filio.h>
# include <sys/byteorder.h>
# include <sys/dditypes.h>
# include <sys/stream.h>
# include <sys/kmem.h>
#endif

#include <net/if.h>
#if sun
#include <net/af.h>
#endif
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#ifndef linux
# include <netinet/ip_var.h>
# include <netinet/tcp_fsm.h>
#endif
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "netinet/ip_compat.h"
#include <netinet/tcpip.h>
#include "netinet/ip_fil.h"
#include "netinet/ip_nat.h"
#include "netinet/ip_frag.h"
#include "netinet/ip_proxy.h"
#include "netinet/ip_state.h"
#ifndef	MIN
#define	MIN(a,b)	(((a)<(b))?(a):(b))
#endif

#define	TCP_CLOSE	(TH_FIN|TH_RST)

static ipstate_t *ips_table[IPSTATE_SIZE];
static int	ips_num = 0;
static ips_stat_t ips_stats;
#if	(SOLARIS || defined(__sgi)) && defined(_KERNEL)
extern	kmutex_t	ipf_state;
#endif

static int fr_matchsrcdst __P((ipstate_t *, struct in_addr, struct in_addr,
			       fr_info_t *, void *, u_short, u_short));
static int fr_state_flush __P((int));
static ips_stat_t *fr_statetstats __P((void));


#define	FIVE_DAYS	(2 * 5 * 86400)	/* 5 days: half closed session */

u_long	fr_tcpidletimeout = FIVE_DAYS,
	fr_tcpclosewait = 60,
	fr_tcplastack = 20,
	fr_tcptimeout = 120,
	fr_tcpclosed = 1,
	fr_udptimeout = 120,
	fr_icmptimeout = 120;


static ips_stat_t *fr_statetstats()
{
	ips_stats.iss_active = ips_num;
	ips_stats.iss_table = ips_table;
	return &ips_stats;
}


/*
 * flush state tables.  two actions currently defined:
 * which == 0 : flush all state table entries
 * which == 1 : flush TCP connections which have started to close but are
 *              stuck for some reason.
 */
static int fr_state_flush(which)
int which;
{
	register int i;
	register ipstate_t *is, **isp;
#if defined(_KERNEL) && !SOLARIS
	int s;
#endif
	int delete, removed = 0;

	SPL_NET(s);
	MUTEX_ENTER(&ipf_state);
	for (i = 0; i < IPSTATE_SIZE; i++)
		for (isp = &ips_table[i]; (is = *isp); ) {
			delete = 0;

			switch (which)
			{
			case 0 :
				delete = 1;
				break;
			case 1 :
				if ((is->is_p == IPPROTO_TCP) &&
				    (((is->is_state[0] <= TCPS_ESTABLISHED) &&
				      (is->is_state[1] > TCPS_ESTABLISHED)) ||
				     ((is->is_state[1] <= TCPS_ESTABLISHED) &&
				      (is->is_state[0] > TCPS_ESTABLISHED))))
					delete = 1;
				break;
			}

			if (delete) {
				*isp = is->is_next;
				if (is->is_p == IPPROTO_TCP)
					ips_stats.iss_fin++;
				else
					ips_stats.iss_expire++;
#if	IPFILTER_LOG
				ipstate_log(is, ISL_FLUSH);
#endif
				KFREE(is);
				ips_num--;
				removed++;
			} else
				isp = &is->is_next;
		}
	MUTEX_EXIT(&ipf_state);
	SPL_X(s);
	return removed;
}


int fr_state_ioctl(data, cmd, mode)
caddr_t data;
#if defined(__NetBSD__) || defined(__OpenBSD__)
u_long cmd;
#else
int cmd;
#endif
int mode;
{
	int	arg, ret, error = 0;

	switch (cmd)
	{
	case SIOCIPFFL :
		IRCOPY(data, (caddr_t)&arg, sizeof(arg));
		if (arg == 0 || arg == 1) {
			ret = fr_state_flush(arg);
			IWCOPY((caddr_t)&ret, data, sizeof(ret));
		} else
			error = EINVAL;
		break;
	case SIOCGIPST :
		IWCOPY((caddr_t)fr_statetstats(), data, sizeof(ips_stat_t));
		break;
	case FIONREAD :
#if	IPFILTER_LOG
		IWCOPY((caddr_t)&iplused[IPL_LOGSTATE], (caddr_t)data,
		       sizeof(iplused[IPL_LOGSTATE]));
#endif
		break;
	default :
		return EINVAL;
	}
	return error;
}


/*
 * Create a new ipstate structure and hang it off the hash table.
 */
int fr_addstate(ip, fin, pass)
ip_t *ip;
fr_info_t *fin;
u_int pass;
{
	ipstate_t ips;
	register ipstate_t *is = &ips;
	register u_int hv;

	if ((ip->ip_off & 0x1fff) || (fin->fin_fi.fi_fl & FI_SHORT))
		return -1;
	if (ips_num == IPSTATE_MAX) {
		ips_stats.iss_max++;
		return -1;
	}
	ips.is_age = 1;
	ips.is_state[0] = 0;
	ips.is_state[1] = 0;
	/*
	 * Copy and calculate...
	 */
	hv = (is->is_p = ip->ip_p);
	hv += (is->is_src.s_addr = ip->ip_src.s_addr);
	hv += (is->is_dst.s_addr = ip->ip_dst.s_addr);

	switch (ip->ip_p)
	{
	case IPPROTO_ICMP :
	    {
		struct icmp *ic = (struct icmp *)fin->fin_dp;

		switch (ic->icmp_type)
		{
		case ICMP_ECHO :
			is->is_icmp.ics_type = ICMP_ECHOREPLY;	/* XXX */
			hv += (is->is_icmp.ics_id = ic->icmp_id);
			hv += (is->is_icmp.ics_seq = ic->icmp_seq);
			break;
		case ICMP_TSTAMP :
		case ICMP_IREQ :
		case ICMP_MASKREQ :
			is->is_icmp.ics_type = ic->icmp_type + 1;
			break;
		default :
			return -1;
		}
		ips_stats.iss_icmp++;
		is->is_age = fr_icmptimeout;
		break;
	    }
	case IPPROTO_TCP :
	    {
		register tcphdr_t *tcp = (tcphdr_t *)fin->fin_dp;

		/*
		 * The endian of the ports doesn't matter, but the ack and
		 * sequence numbers do as we do mathematics on them later.
		 */
		hv += (is->is_dport = tcp->th_dport);
		hv += (is->is_sport = tcp->th_sport);
		is->is_seq = ntohl(tcp->th_seq);
		is->is_ack = ntohl(tcp->th_ack);
		is->is_swin = ntohs(tcp->th_win);
		is->is_dwin = is->is_swin;	/* start them the same */
		ips_stats.iss_tcp++;
		/*
		 * If we're creating state for a starting connection, start the
		 * timer on it as we'll never see an error if it fails to
		 * connect.
		 */
		if ((tcp->th_flags & (TH_SYN|TH_ACK)) == TH_SYN)
			is->is_ack = 0;	/* Trumpet WinSock 'ism */
		fr_tcp_age(&is->is_age, is->is_state, ip, fin,
			   tcp->th_sport == is->is_sport);
		break;
	    }
	case IPPROTO_UDP :
	    {
		register tcphdr_t *tcp = (tcphdr_t *)fin->fin_dp;

		hv += (is->is_dport = tcp->th_dport);
		hv += (is->is_sport = tcp->th_sport);
		ips_stats.iss_udp++;
		is->is_age = fr_udptimeout;
		break;
	    }
	default :
		return -1;
	}

	KMALLOC(is, ipstate_t *, sizeof(*is));
	if (is == NULL) {
		ips_stats.iss_nomem++;
		return -1;
	}
	bcopy((char *)&ips, (char *)is, sizeof(*is));
	hv %= IPSTATE_SIZE;
	MUTEX_ENTER(&ipf_state);

	is->is_pass = pass;
	is->is_pkts = 1;
	is->is_bytes = ip->ip_len;
	/*
	 * Copy these from the rule itself.
	 */
	is->is_opt = fin->fin_fr->fr_ip.fi_optmsk;
	is->is_optmsk = fin->fin_fr->fr_mip.fi_optmsk;
	is->is_sec = fin->fin_fr->fr_ip.fi_secmsk;
	is->is_secmsk = fin->fin_fr->fr_mip.fi_secmsk;
	is->is_auth = fin->fin_fr->fr_ip.fi_auth;
	is->is_authmsk = fin->fin_fr->fr_mip.fi_auth;
	is->is_flags = fin->fin_fr->fr_ip.fi_fl;
	is->is_flags |= fin->fin_fr->fr_mip.fi_fl << 4;
	/*
	 * add into table.
	 */
	is->is_next = ips_table[hv];
	ips_table[hv] = is;
	if (fin->fin_out) {
		is->is_ifpin = NULL;
		is->is_ifpout = fin->fin_ifp;
	} else {
		is->is_ifpin = fin->fin_ifp;
		is->is_ifpout = NULL;
	}
	if (pass & FR_LOGFIRST)
		is->is_pass &= ~(FR_LOGFIRST|FR_LOG);
	ips_num++;
#if	IPFILTER_LOG
	ipstate_log(is, ISL_NEW);
#endif
	MUTEX_EXIT(&ipf_state);
	if (fin->fin_fi.fi_fl & FI_FRAG)
		ipfr_newfrag(ip, fin, pass ^ FR_KEEPSTATE);
	return 0;
}


/*
 * check to see if a packet with TCP headers fits within the TCP window.
 * change timeout depending on whether new packet is a SYN-ACK returning for a
 * SYN or a RST or FIN which indicate time to close up shop.
 */
int fr_tcpstate(is, fin, ip, tcp)
register ipstate_t *is;
fr_info_t *fin;
ip_t *ip;
tcphdr_t *tcp;
{
	register int seqskew, ackskew;
	register u_short swin, dwin;
	register tcp_seq seq, ack;
	int source;

	/*
	 * Find difference between last checked packet and this packet.
	 */
	seq = ntohl(tcp->th_seq);
	ack = ntohl(tcp->th_ack);
	source = (ip->ip_src.s_addr == is->is_src.s_addr);

	if (!(tcp->th_flags & TH_ACK))  /* Pretend an ack was sent */
		ack = source ? is->is_ack : is->is_seq;

	if (source) {
		if (!is->is_seq)
			/*
			 * Must be an outgoing SYN-ACK in reply to a SYN.
			 */
			is->is_seq = seq;
		seqskew = seq - is->is_seq;
		ackskew = ack - is->is_ack;
	} else {
		if (!is->is_ack)
			/*
			 * Must be a SYN-ACK in reply to a SYN.
			 */
			is->is_ack = seq;
		ackskew = seq - is->is_ack;
		seqskew = ack - is->is_seq;
	}

	/*
	 * Make skew values absolute
	 */
	if (seqskew < 0)
		seqskew = -seqskew;
	if (ackskew < 0)
		ackskew = -ackskew;

	/*
	 * If the difference in sequence and ack numbers is within the
	 * window size of the connection, store these values and match
	 * the packet.
	 */
	if (source) {
		swin = is->is_swin;
		dwin = is->is_dwin;
	} else {
		dwin = is->is_swin;
		swin = is->is_dwin;
	}

	if ((seqskew <= dwin) && (ackskew <= swin)) {
		if (source) {
			is->is_seq = seq;
			is->is_ack = ack;
			is->is_swin = ntohs(tcp->th_win);
		} else {
			is->is_seq = ack;
			is->is_ack = seq;
			is->is_dwin = ntohs(tcp->th_win);
		}
		ips_stats.iss_hits++;
		is->is_pkts++;
		is->is_bytes += ip->ip_len;
		/*
		 * Nearing end of connection, start timeout.
		 */
		fr_tcp_age(&is->is_age, is->is_state, ip, fin, source);
		return 1;
	}
	return 0;
}


static int fr_matchsrcdst(is, src, dst, fin, tcp, sp, dp)
ipstate_t *is;
struct in_addr src, dst;
fr_info_t *fin;
void *tcp;
u_short sp, dp;
{
	int ret = 0, rev, out;
	void *ifp;

	rev = (is->is_dst.s_addr != dst.s_addr);
	ifp = fin->fin_ifp;
	out = fin->fin_out;

	if (!rev) {
		if (out) {
			if (!is->is_ifpout)
				is->is_ifpout = ifp;
		} else {
			if (!is->is_ifpin)
				is->is_ifpin = ifp;
		}
	} else {
		if (out) {
			if (!is->is_ifpin)
				is->is_ifpin = ifp;
		} else {
			if (!is->is_ifpout)
				is->is_ifpout = ifp;
		}
	}

	if (!rev) {
		if (((out && is->is_ifpout == ifp) ||
		     (!out && is->is_ifpin == ifp)) &&
		    (is->is_dst.s_addr == dst.s_addr) &&
		    (is->is_src.s_addr == src.s_addr) &&
		    (!tcp || (sp == is->is_sport) &&
		     (dp == is->is_dport))) {
			ret = 1;
		}
	} else {
		if (((out && is->is_ifpin == ifp) ||
		     (!out && is->is_ifpout == ifp)) &&
		    (is->is_dst.s_addr == src.s_addr) &&
		    (is->is_src.s_addr == dst.s_addr) &&
		    (!tcp || (sp == is->is_dport) &&
		     (dp == is->is_sport))) {
			ret = 1;
		}
	}

	/*
	 * Whether or not this should be here, is questionable, but the aim
	 * is to get this out of the main line.
	 */
	if (ret) {
		if (((fin->fin_fi.fi_optmsk & is->is_optmsk) != is->is_opt) ||
		    ((fin->fin_fi.fi_secmsk & is->is_secmsk) != is->is_sec) ||
		    ((fin->fin_fi.fi_auth & is->is_authmsk) != is->is_auth) ||
		    ((fin->fin_fi.fi_fl & (is->is_flags >> 4)) !=
		     (is->is_flags & 0xf)))
			ret = 0;
	}
	return ret;
}


/*
 * Check if a packet has a registered state.
 */
int fr_checkstate(ip, fin)
ip_t *ip;
fr_info_t *fin;
{
	register struct in_addr dst, src;
	register ipstate_t *is, **isp;
	register u_char pr;
	struct icmp *ic;
	tcphdr_t *tcp;
	u_int hv, hlen, pass;

	if ((ip->ip_off & 0x1fff) || (fin->fin_fi.fi_fl & FI_SHORT))
		return 0;

	hlen = fin->fin_hlen;
	tcp = (tcphdr_t *)((char *)ip + hlen);
	ic = (struct icmp *)tcp;
	hv = (pr = ip->ip_p);
	hv += (src.s_addr = ip->ip_src.s_addr);
	hv += (dst.s_addr = ip->ip_dst.s_addr);

	/*
	 * Search the hash table for matching packet header info.
	 */
	switch (ip->ip_p)
	{
	case IPPROTO_ICMP :
		hv += ic->icmp_id;
		hv += ic->icmp_seq;
		hv %= IPSTATE_SIZE;
		MUTEX_ENTER(&ipf_state);
		for (isp = &ips_table[hv]; (is = *isp); isp = &is->is_next)
			if ((is->is_p == pr) &&
			    (ic->icmp_id == is->is_icmp.ics_id) &&
			    (ic->icmp_seq == is->is_icmp.ics_seq) &&
			    fr_matchsrcdst(is, src, dst, fin, NULL, 0, 0)) {
				if (is->is_icmp.ics_type != ic->icmp_type)
					continue;
				is->is_age = fr_icmptimeout;
				is->is_pkts++;
				is->is_bytes += ip->ip_len;
				ips_stats.iss_hits++;
				pass = is->is_pass;
				MUTEX_EXIT(&ipf_state);
				return pass;
			}
		MUTEX_EXIT(&ipf_state);
		break;
	case IPPROTO_TCP :
	    {
		register u_short dport = tcp->th_dport, sport = tcp->th_sport;

		hv += dport;
		hv += sport;
		hv %= IPSTATE_SIZE;
		MUTEX_ENTER(&ipf_state);
		for (isp = &ips_table[hv]; (is = *isp); isp = &is->is_next)
			if ((is->is_p == pr) &&
			    fr_matchsrcdst(is, src, dst, fin, tcp,
					   sport, dport)) {
				if (fr_tcpstate(is, fin, ip, tcp)) {
					pass = is->is_pass;
#ifdef	_KERNEL
					MUTEX_EXIT(&ipf_state);
#else

					if (tcp->th_flags & TCP_CLOSE) {
						*isp = is->is_next;
						isp = &ips_table[hv];
						KFREE(is);
					}
#endif
					return pass;
				}
			}
		MUTEX_EXIT(&ipf_state);
		break;
	    }
	case IPPROTO_UDP :
	    {
		register u_short dport = tcp->th_dport, sport = tcp->th_sport;

		hv += dport;
		hv += sport;
		hv %= IPSTATE_SIZE;
		/*
		 * Nothing else to match on but ports. and IP#'s
		 */
		MUTEX_ENTER(&ipf_state);
		for (is = ips_table[hv]; is; is = is->is_next)
			if ((is->is_p == pr) &&
			    fr_matchsrcdst(is, src, dst, fin,
					   tcp, sport, dport)) {
				ips_stats.iss_hits++;
				is->is_pkts++;
				is->is_bytes += ip->ip_len;
				is->is_age = fr_udptimeout;
				pass = is->is_pass;
				MUTEX_EXIT(&ipf_state);
				return pass;
			}
		MUTEX_EXIT(&ipf_state);
		break;
	    }
	default :
		break;
	}
	ips_stats.iss_miss++;
	return 0;
}


/*
 * Free memory in use by all state info. kept.
 */
void fr_stateunload()
{
	register int i;
	register ipstate_t *is, **isp;

	MUTEX_ENTER(&ipf_state);
	for (i = 0; i < IPSTATE_SIZE; i++)
		for (isp = &ips_table[i]; (is = *isp); ) {
			*isp = is->is_next;
			KFREE(is);
		}
	MUTEX_EXIT(&ipf_state);
}


/*
 * Slowly expire held state for thingslike UDP and ICMP.  Timeouts are set
 * in expectation of this being called twice per second.
 */
void fr_timeoutstate()
{
	register int i;
	register ipstate_t *is, **isp;
#if defined(_KERNEL) && !SOLARIS
	int s;
#endif

	SPL_NET(s);
	MUTEX_ENTER(&ipf_state);
	for (i = 0; i < IPSTATE_SIZE; i++)
		for (isp = &ips_table[i]; (is = *isp); )
			if (is->is_age && !--is->is_age) {
				*isp = is->is_next;
				if (is->is_p == IPPROTO_TCP)
					ips_stats.iss_fin++;
				else
					ips_stats.iss_expire++;
#if	IPFILTER_LOG
				ipstate_log(is, ISL_EXPIRE);
#endif
				KFREE(is);
				ips_num--;
			} else
				isp = &is->is_next;
	MUTEX_EXIT(&ipf_state);
	SPL_X(s);
}


/*
 * Original idea freom Pradeep Krishnan for use primarily with NAT code.
 * (pkrishna@netcom.com)
 */
void fr_tcp_age(age, state, ip, fin, dir)
u_long *age;
u_char *state;
ip_t *ip;
fr_info_t *fin;
int dir;
{
	tcphdr_t *tcp = (tcphdr_t *)fin->fin_dp;
	u_char flags = tcp->th_flags;
	int dlen, ostate;

	ostate = state[1 - dir];

	dlen = ip->ip_len - fin->fin_hlen - (tcp->th_off << 2);

	if (flags & TH_RST) {
		if (!(tcp->th_flags & TH_PUSH) && !dlen) {
			*age = fr_tcpclosed;
			state[dir] = TCPS_CLOSED;
		} else {
			*age = fr_tcpclosewait;
			state[dir] = TCPS_CLOSE_WAIT;
		}
		return;
	}

	*age = fr_tcptimeout; /* 1 min */

	switch(state[dir])
	{
	case TCPS_FIN_WAIT_2:
	case TCPS_CLOSED:
		if ((flags & TH_OPENING) == TH_OPENING)
			state[dir] = TCPS_SYN_RECEIVED;
		else if (flags & TH_SYN)
			state[dir] = TCPS_SYN_SENT;
		break;
	case TCPS_SYN_RECEIVED:
		if ((flags & (TH_FIN|TH_ACK)) == TH_ACK) {
			state[dir] = TCPS_ESTABLISHED;
			current_active_connections++;
			*age = fr_tcpidletimeout;
		}
		break;
	case TCPS_SYN_SENT:
		if ((flags & (TH_FIN|TH_ACK)) == TH_ACK) {
			state[dir] = TCPS_ESTABLISHED;
			current_active_connections++;
			*age = fr_tcpidletimeout;
		}
		break;
	case TCPS_ESTABLISHED:
		if (flags & TH_FIN) {
			state[dir] = TCPS_CLOSE_WAIT;
			if (!(flags & TH_PUSH) && !dlen &&
			    ostate > TCPS_ESTABLISHED)
				*age  = fr_tcplastack;
			else
				*age  = fr_tcpclosewait;
		} else
			*age = fr_tcpidletimeout;
		break;
	case TCPS_CLOSE_WAIT:
		if ((flags & TH_FIN) && !(flags & TH_PUSH) && !dlen &&
		    ostate > TCPS_ESTABLISHED) {
			*age  = fr_tcplastack;
			state[dir] = TCPS_LAST_ACK;
		} else
			*age  = fr_tcpclosewait;
		break;
	case TCPS_LAST_ACK:
		if (flags & TH_ACK) {
			state[dir] = TCPS_FIN_WAIT_2;
			if (!(flags & TH_PUSH) && !dlen &&
			    ostate > TCPS_ESTABLISHED)
				*age  = fr_tcplastack;
			else {
				*age  = fr_tcpclosewait;
				state[dir] = TCPS_CLOSE_WAIT;
			}
		}
		break;
	}
}


#if	IPFILTER_LOG
void ipstate_log(is, type)
struct ipstate *is;
u_short type;
{
	struct	ipslog	ipsl;
	void *items[1];
	size_t sizes[1];
	int types[1];

	ipsl.isl_pkts = is->is_pkts;
	ipsl.isl_bytes = is->is_bytes;
	ipsl.isl_src = is->is_src;
	ipsl.isl_dst = is->is_dst;
	ipsl.isl_p = is->is_p;
	ipsl.isl_flags = is->is_flags;
	ipsl.isl_type = type;
	if (ipsl.isl_p == IPPROTO_TCP || ipsl.isl_p == IPPROTO_UDP) {
		ipsl.isl_sport = is->is_sport;
		ipsl.isl_dport = is->is_dport;
	} else if (ipsl.isl_p == IPPROTO_ICMP)
		ipsl.isl_itype = is->is_icmp.ics_type;
	else {
		ipsl.isl_ps.isl_filler[0] = 0;
		ipsl.isl_ps.isl_filler[1] = 0;
	}
	items[0] = &ipsl;
	sizes[0] = sizeof(ipsl);
	types[0] = 0;

	(void) ipllog(IPL_LOGSTATE, 0, items, sizes, types, 1);
}
#endif
