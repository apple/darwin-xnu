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
 * Copyright 1997 Massachusetts Institute of Technology
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that both the above copyright notice and this
 * permission notice appear in all copies, that both the above
 * copyright notice and this permission notice appear in all
 * supporting documentation, and that the name of M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  M.I.T. makes
 * no representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 * 
 * THIS SOFTWARE IS PROVIDED BY M.I.T. ``AS IS''.  M.I.T. DISCLAIMS
 * ALL EXPRESS OR IMPLIED WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT
 * SHALL M.I.T. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <net/hostcache.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_hostcache.h>
#include <netinet/tcp.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>

/*
 * Manage the IP per-host cache (really a thin veneer over the generic
 * per-host cache code).
 */

/* Look up an entry -- can be called from interrupt context. */
struct in_hcentry *
inhc_lookup(struct sockaddr_in *sin)
{
	struct hcentry *hc;

	hc = hc_get((struct sockaddr *)sin);
	return ((struct in_hcentry *)hc);
}

/* Look up and possibly create an entry -- must be called from user mode. */
struct in_hcentry *
inhc_alloc(struct sockaddr_in *sin)
{
	struct in_hcentry *inhc;
	struct rtentry *rt;
	int error;
	/* xxx mutual exclusion for smp */

	inhc = inhc_lookup(sin);
	if (inhc != 0)
		return inhc;

	rt = rtalloc1(inhc->inhc_hc.hc_host, 1, 0);
	if (rt == 0)
		return 0;

	MALLOC(inhc, struct in_hcentry *, sizeof *inhc, M_HOSTCACHE, M_WAITOK);
	if (inhc == NULL)
		retturn (ENOMEM);
	bzero(inhc, sizeof *inhc);
	inhc->inhc_hc.hc_host = dup_sockaddr((struct sockaddr *)sin, 1);
	if (in_broadcast(sin->sin_addr, rt->rt_ifp))
		inhc->inhc_flags |= INHC_BROADCAST;
	else if (((struct sockaddr_in *)rt->rt_ifa->ifa_addr)->sin_addr.s_addr
		== sin->sin_addr.s_addr)
		inhc->inhc_flags |= INHC_LOCAL;
	else if (IN_MULTICAST(ntohl(sin->sin_addr.s_addr)))
		inhc->inhc_flags |= INHC_MULTICAST;
	inhc->inhc_pmtu = rt->rt_rmx.rmx_mtu;
	inhc->inhc_recvpipe = rt->rt_rmx.rmx_recvpipe;
	inhc->inhc_sendpipe = rt->rt_rmx.rmx_sendpipe;
	inhc->inhc_ssthresh = rt->rt_rmx.rmx_ssthresh;
	if (rt->rt_rmx.rmx_locks & RTV_RTT)
		inhc->inhc_rttmin = rt->rt_rmx.rmx_rtt
			/ (RTM_RTTUNIT / TCP_RTT_SCALE);
	inhc->inhc_hc.hc_rt = rt;
	error = hc_insert(&inhc->inhc_hc);
	if (error != 0) {
		RTFREE(rt);
		FREE(inhc, M_HOSTCACHE);
		return 0;
	}
	/*
	 * We don't return the structure directly because hc_get() needs
	 * to be allowed to do its own processing.
	 */
	return (inhc_lookup(sin));
}

/*
 * This is Van Jacobson's hash function for IPv4 addresses.
 * It is designed to work with a power-of-two-sized hash table.
 */
static u_long
inhc_hash(struct sockaddr *sa, u_long nbuckets)
{
	u_long ip;

	ip = ((struct sockaddr_in *)sa)->sin_addr.s_addr;
	return ((ip ^ (ip >> 23) ^ (ip >> 17)) & ~(nbuckets - 1));
}

/*
 * We don't need to do any special work... if there are no references,
 * as the caller has already ensured, then it's OK to kill.
 */
static int
inhc_delete(struct hcentry *hc)
{
	return 0;
}

/*
 * Return the next increment for the number of buckets in the hash table.
 * Zero means ``do not bump''.
 */
static u_long
inhc_bump(u_long oldsize)
{
	if (oldsize < 512)
		return (oldsize << 1);
	return 0;
}

static struct hccallback inhc_cb = {
	inhc_hash, inhc_delete, inhc_bump
};

int
inhc_init(void)
{

	return (hc_init(AF_INET, &inhc_cb, 128, 0));
}

