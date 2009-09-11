/*
 * Copyright (C) 1995, 1996, 1997, 1998 and 1999 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <sys/appleapiopts.h>

#include <sys/callout.h>

#ifdef KERNEL_PRIVATE
struct rr_prefix {
	struct ifprefix	rp_ifpr;
	LIST_ENTRY(rr_prefix) rp_entry;
	LIST_HEAD(rp_addrhead, rp_addr) rp_addrhead;
	struct sockaddr_in6 rp_prefix;	/* prefix */
	u_int32_t rp_vltime;	/* advertised valid lifetime */
	u_int32_t rp_pltime;	/* advertised preferred lifetime */
	time_t rp_expire;	/* expiration time of the prefix */
	time_t rp_preferred;	/* preferred time of the prefix */
	struct in6_prflags rp_flags;
	u_char	rp_origin; /* from where this prefix info is obtained */
	struct	rp_stateflags {
		/* if some prefix should be added to this prefix */
		u_char addmark : 1;
		u_char delmark : 1; /* if this prefix will be deleted */
	} rp_stateflags;
};

#define rp_type		rp_ifpr.ifpr_type
#define rp_ifp		rp_ifpr.ifpr_ifp
#define rp_plen		rp_ifpr.ifpr_plen

#define rp_raf		rp_flags.prf_ra
#define rp_raf_onlink		rp_flags.prf_ra.onlink
#define rp_raf_auto		rp_flags.prf_ra.autonomous

#define rp_statef_addmark	rp_stateflags.addmark
#define rp_statef_delmark	rp_stateflags.delmark

#define rp_rrf		rp_flags.prf_rr
#define rp_rrf_decrvalid	rp_flags.prf_rr.decrvalid
#define rp_rrf_decrprefd	rp_flags.prf_rr.decrprefd

struct rp_addr {
	LIST_ENTRY(rp_addr)	ra_entry;
	struct in6_addr		ra_ifid;
	struct in6_ifaddr	*ra_addr;
	struct ra_flags {
		u_char anycast : 1;
	} ra_flags;
};

#define ifpr2rp(ifpr)	((struct rr_prefix *)(ifpr))
#define rp2ifpr(rp)	((struct ifprefix *)(rp))

#define RP_IN6(rp)	(&(rp)->rp_prefix.sin6_addr)

#define RR_INFINITE_LIFETIME		0xffffffff


LIST_HEAD(rr_prhead, rr_prefix);

extern struct rr_prhead rr_prefix;

void in6_rr_timer(void *);
int delete_each_prefix (struct rr_prefix *rpp, u_char origin);

#endif /* KERNEL_PRIVATE */
