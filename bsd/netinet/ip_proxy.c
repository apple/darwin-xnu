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
 * Copyright (C) 1997 by Darren Reed.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and due credit is given
 * to the original author and the contributors.
 */
#if !defined(lint)
#endif

#if defined(__FreeBSD__) && defined(KERNEL) && !defined(_KERNEL)
# define	_KERNEL
#endif

#if !defined(_KERNEL) && !defined(KERNEL)
# include <stdio.h>
# include <string.h>
# include <stdlib.h>
#endif
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/file.h>
#if !defined(__FreeBSD__)
# include <sys/ioctl.h>
#endif
#include <sys/fcntl.h>
#include <sys/uio.h>
#ifndef	linux
# include <sys/protosw.h>
#endif
#include <sys/socket.h>
#if defined(_KERNEL)
# if !defined(linux)
#  include <sys/systm.h>
# else
#  include <linux/string.h>
# endif
#endif
#if !defined(__SVR4) && !defined(__svr4__)
# ifndef linux
#  include <sys/mbuf.h>
# endif
#else
# include <sys/byteorder.h>
# include <sys/dditypes.h>
# include <sys/stream.h>
# include <sys/kmem.h>
#endif
#if __FreeBSD__ > 2
# include <sys/queue.h>
# include <sys/malloc.h>
#endif
#include <net/if.h>
#ifdef sun
# include <net/af.h>
#endif
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#ifndef linux
# include <netinet/ip_var.h>
#endif
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "netinet/ip_compat.h"
#include <netinet/tcpip.h>
#include "netinet/ip_fil.h"
#include "netinet/ip_proxy.h"
#include "netinet/ip_nat.h"
#include "netinet/ip_state.h"

#ifndef MIN
#define MIN(a,b)        (((a)<(b))?(a):(b))
#endif

static ap_session_t *ap_find __P((ip_t *, tcphdr_t *));
static ap_session_t *ap_new_session __P((aproxy_t *, ip_t *, tcphdr_t *,
					 fr_info_t *, nat_t *));

static int ap_matchsrcdst __P((ap_session_t *aps, struct in_addr src,
			       struct in_addr dst, void *tcp, u_short sport,
			       u_short dport));

#define	AP_SESS_SIZE	53

#if defined(_KERNEL) && !defined(linux)
#include "netinet/ip_ftp_pxy.c"
#endif

ap_session_t	*ap_sess_tab[AP_SESS_SIZE];
aproxy_t	ap_proxies[] = {
#if	IPF_FTP_PROXY
	{ "ftp", (char)IPPROTO_TCP, 0, 0, ippr_ftp_init, ippr_ftp_in, ippr_ftp_out },
#endif
	{ "", '\0', 0, 0, NULL, NULL }
};


int ap_ok(ip, tcp, nat)
ip_t *ip;
tcphdr_t *tcp;
ipnat_t *nat;
{
	aproxy_t *apr = nat->in_apr;
	u_short dport = nat->in_dport;

	if (!apr || (apr && (apr->apr_flags & APR_DELETE)) ||
	    (ip->ip_p != apr->apr_p))
		return 0;
	if ((tcp && (tcp->th_dport != dport)) || (!tcp && dport))
		return 0;
	return 1;
}


static int
ap_matchsrcdst(aps, src, dst, tcp, sport, dport)
ap_session_t *aps;
struct in_addr src, dst;
void *tcp;
u_short sport, dport;
{
	if (aps->aps_dst.s_addr == dst.s_addr) {
		if ((aps->aps_src.s_addr == src.s_addr) &&
		    (!tcp || (sport == aps->aps_sport) &&
		     (dport == aps->aps_dport)))
			return 1;
	} else if (aps->aps_dst.s_addr == src.s_addr) {
		if ((aps->aps_src.s_addr == dst.s_addr) &&
		    (!tcp || (sport == aps->aps_dport) &&
		     (dport == aps->aps_sport)))
			return 1;
	}
	return 0;
}


static ap_session_t *ap_find(ip, tcp)
ip_t *ip;
tcphdr_t *tcp;
{
	register u_char p = ip->ip_p;
	register ap_session_t *aps;
	register u_short sp, dp;
	register u_long hv;
	struct in_addr src, dst;

	src = ip->ip_src, dst = ip->ip_dst;
	sp = dp = 0;			/* XXX gcc -Wunitialized */

	hv = ip->ip_src.s_addr ^ ip->ip_dst.s_addr;
	hv *= 651733;
	if (tcp) {
		sp = tcp->th_sport;
		dp = tcp->th_dport;
		hv ^= (sp + dp);
		hv *= 5;
	}
	hv %= AP_SESS_SIZE;

	for (aps = ap_sess_tab[hv]; aps; aps = aps->aps_next)
		if ((aps->aps_p == p) &&
		    ap_matchsrcdst(aps, src, dst, tcp, sp, dp))
			break;
	return aps;
}


/*
 * Allocate a new application proxy structure and fill it in with the
 * relevant details.  call the init function once complete, prior to
 * returning.
 */
static ap_session_t *ap_new_session(apr, ip, tcp, fin, nat)
aproxy_t *apr;
ip_t *ip;
tcphdr_t *tcp;
fr_info_t *fin;
nat_t *nat;
{
	register ap_session_t *aps;
	u_short dport;
	u_long hv;

	if (!apr || (apr && (apr->apr_flags & APR_DELETE)) ||
	    (ip->ip_p != apr->apr_p))
		return NULL;
	dport = nat->nat_ptr->in_dport;
	if ((tcp && (tcp->th_dport != dport)) || (!tcp && dport))
		return NULL;

	hv = ip->ip_src.s_addr ^ ip->ip_dst.s_addr;
	hv *= 651733;
	if (tcp) {
		hv ^= (tcp->th_sport + tcp->th_dport);
		hv *= 5;
	}
	hv %= AP_SESS_SIZE;

	KMALLOC(aps, ap_session_t *, sizeof(*aps));
	if (!aps)
		return NULL;
	bzero((char *)aps, sizeof(*aps));
	aps->aps_apr = apr;
	aps->aps_src = ip->ip_src;
	aps->aps_dst = ip->ip_dst;
	aps->aps_p = ip->ip_p;
	aps->aps_tout = 1200;	/* XXX */
	if (tcp) {
		aps->aps_sport = tcp->th_sport;
		aps->aps_dport = tcp->th_dport;
	}
	aps->aps_data = NULL;
	aps->aps_psiz = 0;
	aps->aps_next = ap_sess_tab[hv];
	ap_sess_tab[hv] = aps;
	(void) (*apr->apr_init)(fin, ip, tcp, aps, nat);
	return aps;
}


/*
 * check to see if a packet should be passed through an active proxy routine
 * if one has been setup for it.
 */
int ap_check(ip, tcp, fin, nat)
ip_t *ip;
tcphdr_t *tcp;
fr_info_t *fin;
nat_t *nat;
{
	ap_session_t *aps;
	aproxy_t *apr;
	int err;

	if (!(fin->fin_fi.fi_fl & FI_TCPUDP))
		tcp = NULL;

	if ((aps = ap_find(ip, tcp)) ||
	    (aps = ap_new_session(nat->nat_ptr->in_apr, ip, tcp, fin, nat))) {
		if (ip->ip_p == IPPROTO_TCP) {
			/*
			 * verify that the checksum is correct.  If not, then
			 * don't do anything with this packet.
			 */
			if (tcp->th_sum != fr_tcpsum(*(mb_t **)fin->fin_mp,
						     ip, tcp, ip->ip_len)) {
				frstats[fin->fin_out].fr_tcpbad++;
				return -1;
			}
			fr_tcp_age(&aps->aps_tout, aps->aps_state, ip, fin,
				   tcp->th_sport == aps->aps_sport);
		}

		apr = aps->aps_apr;
		err = 0;
		if (fin->fin_out) {
			if (apr->apr_outpkt)
				err = (*apr->apr_outpkt)(fin, ip, tcp,
							 aps, nat);
		} else {
			if (apr->apr_inpkt)
				err = (*apr->apr_inpkt)(fin, ip, tcp,
							aps, nat);
		}
		if (err == 2) {
			tcp->th_sum = fr_tcpsum(*(mb_t **)fin->fin_mp, ip,
						tcp, ip->ip_len);
			err = 0;
		}
		return err;
	}
	return -1;
}


aproxy_t *ap_match(pr, name)
u_char pr;
char *name;
{
	aproxy_t *ap;

	for (ap = ap_proxies; ap->apr_p; ap++)
		if ((ap->apr_p == pr) &&
		    !strncmp(name, ap->apr_label, sizeof(ap->apr_label))) {
			ap->apr_ref++;
			return ap;
		}
	return NULL;
}


void ap_free(ap)
aproxy_t *ap;
{
	ap->apr_ref--;
}


void aps_free(aps)
ap_session_t *aps;
{
	if (aps->aps_data && aps->aps_psiz)
		KFREES(aps->aps_data, aps->aps_psiz);
	KFREE(aps);
}


void ap_unload()
{
	ap_session_t *aps;
	int i;

	for (i = 0; i < AP_SESS_SIZE; i++)
		while ((aps = ap_sess_tab[i])) {
			ap_sess_tab[i] = aps->aps_next;
			aps_free(aps);
		}
}


void ap_expire()
{
	ap_session_t *aps, **apsp;
	int i;

	for (i = 0; i < AP_SESS_SIZE; i++)
		for (apsp = &ap_sess_tab[i]; (aps = *apsp); ) {
			aps->aps_tout--;
			if (!aps->aps_tout) {
				ap_sess_tab[i] = aps->aps_next;
				aps_free(aps);
				*apsp = aps->aps_next;
			} else
				apsp = &aps->aps_next;
		}
}
