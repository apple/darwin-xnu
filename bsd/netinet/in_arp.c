/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1982, 1989, 1993
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

#include <kern/debug.h>
#include <netinet/in_arp.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/kernel_types.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/sysctl.h>
#include <string.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/dlil.h>
#include <net/route.h>
#include <netinet/if_ether.h>
#include <netinet/in_var.h>

#define SIN(s) ((struct sockaddr_in *)s)
#define CONST_LLADDR(s) ((const u_char*)((s)->sdl_data + (s)->sdl_nlen))
#define	rt_expire rt_rmx.rmx_expire

static const size_t MAX_HW_LEN = 10;

SYSCTL_DECL(_net_link_ether);
SYSCTL_NODE(_net_link_ether, PF_INET, inet, CTLFLAG_RW, 0, "");

/* timer values */
static int arpt_prune = (5*60*1); /* walk list every 5 minutes */
static int arpt_keep = (20*60); /* once resolved, good for 20 more minutes */
static int arpt_down = 20;	/* once declared down, don't send for 20 sec */

/* Apple Hardware SUM16 checksuming */
int apple_hwcksum_tx = 1;
int apple_hwcksum_rx = 1;

SYSCTL_INT(_net_link_ether_inet, OID_AUTO, prune_intvl, CTLFLAG_RW,
	   &arpt_prune, 0, "");
SYSCTL_INT(_net_link_ether_inet, OID_AUTO, max_age, CTLFLAG_RW, 
	   &arpt_keep, 0, "");
SYSCTL_INT(_net_link_ether_inet, OID_AUTO, host_down_time, CTLFLAG_RW,
	   &arpt_down, 0, "");
SYSCTL_INT(_net_link_ether_inet, OID_AUTO, apple_hwcksum_tx, CTLFLAG_RW,
	   &apple_hwcksum_tx, 0, "");
SYSCTL_INT(_net_link_ether_inet, OID_AUTO, apple_hwcksum_rx, CTLFLAG_RW,
	   &apple_hwcksum_rx, 0, "");

struct llinfo_arp {
	LIST_ENTRY(llinfo_arp) la_le;
	struct	rtentry *la_rt;
	struct	mbuf *la_hold;		/* last packet until resolved/timeout */
	long	la_asked;		/* last time we QUERIED for this addr */
};

static LIST_HEAD(, llinfo_arp) llinfo_arp;

static int	arp_inuse, arp_allocated;

static int	arp_maxtries = 5;
static int	useloopback = 1; /* use loopback interface for local traffic */
static int	arp_proxyall = 0;

SYSCTL_INT(_net_link_ether_inet, OID_AUTO, maxtries, CTLFLAG_RW,
	   &arp_maxtries, 0, "");
SYSCTL_INT(_net_link_ether_inet, OID_AUTO, useloopback, CTLFLAG_RW,
	   &useloopback, 0, "");
SYSCTL_INT(_net_link_ether_inet, OID_AUTO, proxyall, CTLFLAG_RW,
	   &arp_proxyall, 0, "");

static int log_arp_warnings = 0;

SYSCTL_INT(_net_link_ether_inet, OID_AUTO, log_arp_warnings, CTLFLAG_RW,
	&log_arp_warnings, 0,
	"log arp warning messages");

extern u_int32_t	ipv4_ll_arp_aware;

/*
 * Free an arp entry.
 */
static void
arptfree(
	struct llinfo_arp *la)
{
	struct rtentry *rt = la->la_rt;
	struct sockaddr_dl *sdl;
	lck_mtx_assert(rt_mtx, LCK_MTX_ASSERT_OWNED);
	if (rt == 0)
		panic("arptfree");
	if (rt->rt_refcnt > 0 && (sdl = SDL(rt->rt_gateway)) &&
	    sdl->sdl_family == AF_LINK) {
		sdl->sdl_alen = 0;
		la->la_asked = 0;
		rt->rt_flags &= ~RTF_REJECT;
		return;
	}
	rtrequest_locked(RTM_DELETE, rt_key(rt), (struct sockaddr *)0, rt_mask(rt),
			0, (struct rtentry **)0);
}

/*
 * Timeout routine.  Age arp_tab entries periodically.
 */
/* ARGSUSED */
static void
arptimer(
	__unused void *ignored_arg)
{
	struct llinfo_arp *la = llinfo_arp.lh_first;
	struct llinfo_arp *ola;
	struct timeval timenow;

	lck_mtx_lock(rt_mtx);
	getmicrotime(&timenow);
	while ((ola = la) != 0) {
		struct rtentry *rt = la->la_rt;
		la = la->la_le.le_next;
		if (rt->rt_expire && rt->rt_expire <= timenow.tv_sec)
			arptfree(ola); /* timer has expired, clear */
	}
	lck_mtx_unlock(rt_mtx);
	timeout(arptimer, (caddr_t)0, arpt_prune * hz);
}

/*
 * Parallel to llc_rtrequest.
 */
static void
arp_rtrequest(
	int req,
	struct rtentry *rt,
	__unused struct sockaddr *sa)
{
	struct sockaddr *gate = rt->rt_gateway;
	struct llinfo_arp *la = (struct llinfo_arp *)rt->rt_llinfo;
	static struct sockaddr_dl null_sdl = {sizeof(null_sdl), AF_LINK, 0, 0, 0, 0, 0, {0}};
	static int arpinit_done;
	struct timeval timenow;

	if (!arpinit_done) {
		arpinit_done = 1;
		LIST_INIT(&llinfo_arp);
		timeout(arptimer, (caddr_t)0, hz);
	}
	lck_mtx_assert(rt_mtx, LCK_MTX_ASSERT_OWNED);

	if (rt->rt_flags & RTF_GATEWAY)
		return;
	getmicrotime(&timenow);
	switch (req) {

	case RTM_ADD:
		/*
		 * XXX: If this is a manually added route to interface
		 * such as older version of routed or gated might provide,
		 * restore cloning bit.
		 */
		if ((rt->rt_flags & RTF_HOST) == 0 &&
		    SIN(rt_mask(rt))->sin_addr.s_addr != 0xffffffff)
			rt->rt_flags |= RTF_CLONING;
		if (rt->rt_flags & RTF_CLONING) {
			/*
			 * Case 1: This route should come from a route to iface.
			 */
			rt_setgate(rt, rt_key(rt),
					(struct sockaddr *)&null_sdl);
			gate = rt->rt_gateway;
			SDL(gate)->sdl_type = rt->rt_ifp->if_type;
			SDL(gate)->sdl_index = rt->rt_ifp->if_index;
			rt->rt_expire = timenow.tv_sec;
			break;
		}
		/* Announce a new entry if requested. */
		if (rt->rt_flags & RTF_ANNOUNCE)
			dlil_send_arp(rt->rt_ifp, ARPOP_REQUEST, SDL(gate), rt_key(rt), (struct sockaddr_dl *)rt_key(rt), NULL);
		/*FALLTHROUGH*/
	case RTM_RESOLVE:
		if (gate->sa_family != AF_LINK ||
		    gate->sa_len < sizeof(null_sdl)) {
		        if (log_arp_warnings) 
				log(LOG_DEBUG, "arp_rtrequest: bad gateway value\n");
			break;
		}
		SDL(gate)->sdl_type = rt->rt_ifp->if_type;
		SDL(gate)->sdl_index = rt->rt_ifp->if_index;
		if (la != 0)
			break; /* This happens on a route change */
		/*
		 * Case 2:  This route may come from cloning, or a manual route
		 * add with a LL address.
		 */
		R_Malloc(la, struct llinfo_arp *, sizeof(*la));
		rt->rt_llinfo = (caddr_t)la;
		if (la == 0) {
		       	if ( log_arp_warnings) 
				log(LOG_DEBUG, "arp_rtrequest: malloc failed\n");
			break;
		}
		arp_inuse++, arp_allocated++;
		Bzero(la, sizeof(*la));
		la->la_rt = rt;
		rt->rt_flags |= RTF_LLINFO;
		LIST_INSERT_HEAD(&llinfo_arp, la, la_le);

#if INET
		/*
		 * This keeps the multicast addresses from showing up
		 * in `arp -a' listings as unresolved.  It's not actually
		 * functional.  Then the same for broadcast.
		 */
		if (IN_MULTICAST(ntohl(SIN(rt_key(rt))->sin_addr.s_addr))) {
			dlil_resolve_multi(rt->rt_ifp, rt_key(rt), gate, sizeof(struct sockaddr_dl));
			rt->rt_expire = 0;
		}
		else if (in_broadcast(SIN(rt_key(rt))->sin_addr, rt->rt_ifp)) {
			struct sockaddr_dl	*gate_ll = SDL(gate);
			size_t	broadcast_len;
			ifnet_llbroadcast_copy_bytes(rt->rt_ifp, LLADDR(gate_ll),
										 sizeof(gate_ll->sdl_data),
										 &broadcast_len);
			gate_ll->sdl_alen = broadcast_len;
			gate_ll->sdl_family = AF_LINK;
			gate_ll->sdl_len = sizeof(struct sockaddr_dl);
			rt->rt_expire = timenow.tv_sec;
		}
#endif

		if (SIN(rt_key(rt))->sin_addr.s_addr ==
		    (IA_SIN(rt->rt_ifa))->sin_addr.s_addr) {
		    /*
		     * This test used to be
		     *	if (loif.if_flags & IFF_UP)
		     * It allowed local traffic to be forced
		     * through the hardware by configuring the loopback down.
		     * However, it causes problems during network configuration
		     * for boards that can't receive packets they send.
		     * It is now necessary to clear "useloopback" and remove
		     * the route to force traffic out to the hardware.
		     */
			rt->rt_expire = 0;
			ifnet_lladdr_copy_bytes(rt->rt_ifp, LLADDR(SDL(gate)), SDL(gate)->sdl_alen = 6);
			if (useloopback)
				rt->rt_ifp = loif;

		}
		break;

	case RTM_DELETE:
		if (la == 0)
			break;
		arp_inuse--;
		LIST_REMOVE(la, la_le);
		rt->rt_llinfo = 0;
		rt->rt_flags &= ~RTF_LLINFO;
		if (la->la_hold) {
			m_freem(la->la_hold);
		}
		la->la_hold = NULL;
		R_Free((caddr_t)la);
	}
}

/*
 * convert hardware address to hex string for logging errors.
 */
static const char *
sdl_addr_to_hex(const struct sockaddr_dl *sdl, char * orig_buf, int buflen)
{
	char *		buf = orig_buf;
	int 		i;
	const u_char *	lladdr = sdl->sdl_data;
	int			maxbytes = buflen / 3;
	
	if (maxbytes > sdl->sdl_alen) {
		maxbytes = sdl->sdl_alen;
	}	
	*buf = '\0';
	for (i = 0; i < maxbytes; i++) {
		snprintf(buf, 3, "%02x", lladdr[i]);
		buf += 2;
		*buf = (i == maxbytes - 1) ? '\0' : ':';
		buf++;
	}
	return (orig_buf);
}

/*
 * arp_lookup_route will lookup the route for a given address.
 *
 * The routing lock must be held. The address must be for a
 * host on a local network on this interface.
 */
static errno_t
arp_lookup_route(
	const struct in_addr *addr,
	int	create,
	int proxy,
	route_t *route)
{
	struct sockaddr_inarp sin = {sizeof(sin), AF_INET, 0, {0}, {0}, 0, 0};
	const char *why = 0;
	errno_t	error = 0;
	
	// Caller is responsible for taking the routing lock
	lck_mtx_assert(rt_mtx, LCK_MTX_ASSERT_OWNED);

	sin.sin_addr.s_addr = addr->s_addr;
	sin.sin_other = proxy ? SIN_PROXY : 0;
	
	*route = rtalloc1_locked((const struct sockaddr*)&sin, create, 0);
	if (*route == NULL)
		return ENETUNREACH;
	
	rtunref(*route);
	
	if ((*route)->rt_flags & RTF_GATEWAY) {
		why = "host is not on local network";
		
		/* If there are no references to this route, purge it */
		if ((*route)->rt_refcnt <= 0 && ((*route)->rt_flags & RTF_WASCLONED) != 0) {
			rtrequest_locked(RTM_DELETE,
					(struct sockaddr *)rt_key(*route),
					(*route)->rt_gateway, rt_mask(*route),
					(*route)->rt_flags, 0);
		}
		*route = NULL;
		error = ENETUNREACH;
	}
	else if (((*route)->rt_flags & RTF_LLINFO) == 0) {
		why = "could not allocate llinfo";
		*route = NULL;
		error = ENOMEM;
	}
	else if ((*route)->rt_gateway->sa_family != AF_LINK) {
		why = "gateway route is not ours";
		*route = NULL;
		error = EPROTONOSUPPORT;
	}
	
	if (why && create && log_arp_warnings) {
		char	tmp[MAX_IPv4_STR_LEN];
		log(LOG_DEBUG, "arplookup %s failed: %s\n",
			inet_ntop(AF_INET, addr, tmp, sizeof(tmp)), why);
	}
	
	return error;
}


__private_extern__ errno_t
arp_route_to_gateway_route(
	const struct sockaddr *net_dest,
	route_t	hint,
	route_t *out_route);
/*
 * arp_route_to_gateway_route will find the gateway route for a given route.
 *
 * If the route is down, look the route up again.
 * If the route goes through a gateway, get the route to the gateway.
 * If the gateway route is down, look it up again.
 * If the route is set to reject, verify it hasn't expired.
 */
__private_extern__ errno_t
arp_route_to_gateway_route(
	const struct sockaddr *net_dest,
	route_t	hint,
	route_t *out_route)
{
	route_t route = hint;
	*out_route = NULL;
	struct timeval timenow;
	
	/* If we got a hint from the higher layers, check it out */
	if (route) {
		lck_mtx_lock(rt_mtx);
		
		if ((route->rt_flags & RTF_UP) == 0) {
			/* route is down, find a new one */
			hint = route = rtalloc1_locked(net_dest, 1, 0);
			if (hint) {
				rtunref(hint);
			}
			else {
				/* No route to host */
				lck_mtx_unlock(rt_mtx);
				return EHOSTUNREACH;
			}
		}
		
		if (route->rt_flags & RTF_GATEWAY) {
			/*
			 * We need the gateway route. If it is NULL or down,
			 * look it up.
			 */
			if (route->rt_gwroute == 0 ||
				(route->rt_gwroute->rt_flags & RTF_UP) == 0) {
				if (route->rt_gwroute != 0)
					rtfree_locked(route->rt_gwroute);
				
				route->rt_gwroute = rtalloc1_locked(route->rt_gateway, 1, 0);
				if (route->rt_gwroute == 0) {
					lck_mtx_unlock(rt_mtx);
					return EHOSTUNREACH;
				}
			}
			
			route = route->rt_gwroute;
		}
		
		if (route->rt_flags & RTF_REJECT) {
			getmicrotime(&timenow);
			if (route->rt_rmx.rmx_expire == 0 ||
				timenow.tv_sec < route->rt_rmx.rmx_expire) {
				lck_mtx_unlock(rt_mtx);
				return route == hint ? EHOSTDOWN : EHOSTUNREACH;
			}
		}
		
		lck_mtx_unlock(rt_mtx);
	}
	
	*out_route = route;
	return 0;
}

errno_t
arp_lookup_ip(
	ifnet_t ifp,
	const struct sockaddr_in *net_dest,
	struct sockaddr_dl *ll_dest,
	size_t	ll_dest_len,
	route_t	hint,
	mbuf_t packet)
{
	route_t	route = NULL;
	errno_t	result = 0;
	struct sockaddr_dl	*gateway;
	struct llinfo_arp	*llinfo;
	struct timeval timenow;
	
	if (net_dest->sin_family != AF_INET)
		return EAFNOSUPPORT;
	
	if ((ifp->if_flags & (IFF_UP|IFF_RUNNING)) != (IFF_UP|IFF_RUNNING))
		return ENETDOWN;
	
	/*
	 * If we were given a route, verify the route and grab the gateway
	 */
	if (hint) {
		result = arp_route_to_gateway_route((const struct sockaddr*)net_dest,
											hint, &route);
		if (result != 0)
			return result;
	}
	
	if (packet->m_flags & M_BCAST) {
		u_long	broadcast_len;
		bzero(ll_dest, ll_dest_len);
		result = ifnet_llbroadcast_copy_bytes(ifp, LLADDR(ll_dest), ll_dest_len
											  - offsetof(struct sockaddr_dl,
											  sdl_data), &broadcast_len);
		if (result != 0) {
			return result;
		}
		
		ll_dest->sdl_alen = broadcast_len;
		ll_dest->sdl_family = AF_LINK;
		ll_dest->sdl_len = sizeof(struct sockaddr_dl);
		
		return 0;
	}
	if (packet->m_flags & M_MCAST) {
		return dlil_resolve_multi(ifp, (const struct sockaddr*)net_dest,
								   (struct sockaddr*)ll_dest, ll_dest_len);
	}
	
	lck_mtx_lock(rt_mtx);
	
	/*
	 * If we didn't find a route, or the route doesn't have
	 * link layer information, trigger the creation of the
	 * route and link layer information.
	 */
	if (route == NULL || route->rt_llinfo == NULL)
		result = arp_lookup_route(&net_dest->sin_addr, 1, 0, &route);
	
	if (result || route == NULL || route->rt_llinfo == NULL) {
		char	tmp[MAX_IPv4_STR_LEN];
		lck_mtx_unlock(rt_mtx);
		if (log_arp_warnings)
			log(LOG_DEBUG, "arpresolve: can't allocate llinfo for %s\n",
				inet_ntop(AF_INET, &net_dest->sin_addr, tmp, sizeof(tmp)));
		return result;
	}
	
	/*
	 * Now that we have the right route, is it filled in?
	 */
	gateway = SDL(route->rt_gateway);
	getmicrotime(&timenow);
	if ((route->rt_rmx.rmx_expire == 0 || route->rt_rmx.rmx_expire > timenow.tv_sec) &&
		gateway != NULL && gateway->sdl_family == AF_LINK && gateway->sdl_alen != 0) {
		bcopy(gateway, ll_dest, MIN(gateway->sdl_len, ll_dest_len));
		lck_mtx_unlock(rt_mtx);
		return 0;
	}
	
	/*
	 * Route wasn't complete/valid. We need to arp.
	 */
	if (ifp->if_flags & IFF_NOARP) {
		lck_mtx_unlock(rt_mtx);
		return ENOTSUP;
	}
	
	llinfo = (struct llinfo_arp*)route->rt_llinfo;
	if (packet) {
		if (llinfo->la_hold) {
			m_freem(llinfo->la_hold);
		}
		llinfo->la_hold = packet;
	}
	
	if (route->rt_rmx.rmx_expire) {
		route->rt_flags &= ~RTF_REJECT;
		if (llinfo->la_asked == 0 || route->rt_rmx.rmx_expire != timenow.tv_sec) {
			route->rt_rmx.rmx_expire = timenow.tv_sec;
			if (llinfo->la_asked++ < arp_maxtries) {
				lck_mtx_unlock(rt_mtx);
				dlil_send_arp(ifp, ARPOP_REQUEST, NULL, route->rt_ifa->ifa_addr,
							  NULL, (const struct sockaddr*)net_dest);
				return EJUSTRETURN;
			}
			else {
				route->rt_flags |= RTF_REJECT;
				route->rt_rmx.rmx_expire += arpt_down;
				llinfo->la_asked = 0;
				llinfo->la_hold = 0;
				lck_mtx_unlock(rt_mtx);
				return EHOSTUNREACH;
			}
		}
	}
	lck_mtx_unlock(rt_mtx);
	
	return EJUSTRETURN;
}

errno_t
arp_ip_handle_input(
	ifnet_t		ifp,
	u_short		arpop,
	const struct sockaddr_dl *sender_hw,
	const struct sockaddr_in *sender_ip,
	const struct sockaddr_in *target_ip)
{
	char	ipv4str[MAX_IPv4_STR_LEN];
	struct sockaddr_dl *gateway;
	struct in_ifaddr *ia;
	struct in_ifaddr *best_ia = NULL;
	route_t	route = NULL;
	char buf[3 * MAX_HW_LEN]; // enough for MAX_HW_LEN byte hw address
	struct llinfo_arp *llinfo;
	struct timeval timenow;
	errno_t	error;
	
	/* Do not respond to requests for 0.0.0.0 */
	if (target_ip->sin_addr.s_addr == 0 && arpop == ARPOP_REQUEST) {
		return 0;
	}
	
	/*
	 * Determine if this ARP is for us
	 */
	lck_mtx_lock(rt_mtx);
	for (ia = in_ifaddrhead.tqh_first; ia; ia = ia->ia_link.tqe_next) {
		/* do_bridge should be tested here for bridging */
		if (ia->ia_ifp == ifp) {
			best_ia = ia;
			if (target_ip->sin_addr.s_addr == ia->ia_addr.sin_addr.s_addr ||
				sender_ip->sin_addr.s_addr == ia->ia_addr.sin_addr.s_addr) {
				break;
			}
		}
	}
	
	/* If we don't have an IP address on this interface, ignore the packet */
	if (best_ia == 0) {
		lck_mtx_unlock(rt_mtx);
		return 0;
	}
	
	/* If the packet is from this interface, ignore the packet */
	if (!bcmp(CONST_LLADDR(sender_hw), ifnet_lladdr(ifp), sender_hw->sdl_len)) {
		lck_mtx_unlock(rt_mtx);
		return 0;
	}
	
	/* Check for a conflict */
	if (sender_ip->sin_addr.s_addr == best_ia->ia_addr.sin_addr.s_addr) {
		struct kev_msg        ev_msg;
		struct kev_in_collision	*in_collision;
		u_char	storage[sizeof(struct kev_in_collision) + MAX_HW_LEN];
		in_collision = (struct kev_in_collision*)storage;
		log(LOG_ERR, "%s%d duplicate IP address %s sent from address %s\n",
			ifp->if_name, ifp->if_unit,
			inet_ntop(AF_INET, &sender_ip->sin_addr, ipv4str, sizeof(ipv4str)),
			sdl_addr_to_hex(sender_hw, buf, sizeof(buf)));
		
		/* Send a kernel event so anyone can learn of the conflict */
		in_collision->link_data.if_family = ifp->if_family;
		in_collision->link_data.if_unit = ifp->if_unit;
		strncpy(&in_collision->link_data.if_name[0], ifp->if_name, IFNAMSIZ);
		in_collision->ia_ipaddr = sender_ip->sin_addr;
		in_collision->hw_len = sender_hw->sdl_alen < MAX_HW_LEN ? sender_hw->sdl_alen : MAX_HW_LEN;
		bcopy(CONST_LLADDR(sender_hw), (caddr_t)in_collision->hw_addr, in_collision->hw_len);
		ev_msg.vendor_code = KEV_VENDOR_APPLE;
		ev_msg.kev_class = KEV_NETWORK_CLASS;
		ev_msg.kev_subclass = KEV_INET_SUBCLASS;
		ev_msg.event_code = KEV_INET_ARPCOLLISION;
		ev_msg.dv[0].data_ptr = in_collision;
		ev_msg.dv[0].data_length = sizeof(struct kev_in_collision) + in_collision->hw_len;
		ev_msg.dv[1].data_length = 0;
		kev_post_msg(&ev_msg);
		
		goto respond;
	}
	
	/*
	 * Look up the routing entry. If it doesn't exist and we are the
	 * target, go ahead and create one.
	 */
	error = arp_lookup_route(&sender_ip->sin_addr, (target_ip->sin_addr.s_addr ==
				best_ia->ia_addr.sin_addr.s_addr), 0, &route);
	
	if (error || route == 0 || route->rt_gateway == 0) {
		if (ipv4_ll_arp_aware != 0 && IN_LINKLOCAL(target_ip->sin_addr.s_addr)
			&& arpop == ARPOP_REQUEST && sender_ip->sin_addr.s_addr == 0) {
			/*
			 * Verify this ARP probe doesn't conflict with an IPv4LL we know of
			 * on another interface.
			 */
			error = arp_lookup_route(&target_ip->sin_addr, 0, 0, &route);
			if (error == 0 && route && route->rt_gateway) {
				gateway = SDL(route->rt_gateway);
				if (route->rt_ifp != ifp &&
					(gateway->sdl_alen != sender_hw->sdl_alen ||
			 		 bcmp(CONST_LLADDR(gateway), CONST_LLADDR(sender_hw),
			 		 gateway->sdl_alen) != 0)) {
					/*
					 * A node is probing for an IPv4LL we know exists on a
					 * different interface. We respond with a conflicting probe
					 * to force the new device to pick a different IPv4LL
					 * address.
					 */
					log(LOG_INFO,
						"arp: %s on %s%d sent probe for %s, already on %s%d\n",
						sdl_addr_to_hex(sender_hw, buf, sizeof(buf)),
						ifp->if_name, ifp->if_unit,
						inet_ntop(AF_INET, &target_ip->sin_addr, ipv4str,
								  sizeof(ipv4str)),
						route->rt_ifp->if_name, route->rt_ifp->if_unit);
					log(LOG_INFO,
						"arp: sending conflicting probe to %s on %s%d\n",
						sdl_addr_to_hex(sender_hw, buf, sizeof(buf)),
						ifp->if_name, ifp->if_unit);
					
					/*
					 * Send a conservative unicast "ARP probe".
					 * This should force the other device to pick a new number.
					 * This will not force the device to pick a new number if the device
					 * has already assigned that number.
					 * This will not imply to the device that we own that address.
					 */
					dlil_send_arp_internal(ifp, ARPOP_REQUEST,
						(struct sockaddr_dl*)TAILQ_FIRST(&ifp->if_addrhead)->ifa_addr,
						(const struct sockaddr*)sender_ip, sender_hw,
						(const struct sockaddr*)target_ip);
			 	}
			}
		}
		
		goto respond;
	}
	
	gateway = SDL(route->rt_gateway);
	if (route->rt_ifp != ifp) {
		if (!IN_LINKLOCAL(sender_ip->sin_addr.s_addr) || (ifp->if_eflags & IFEF_ARPLL) == 0) {
			if (log_arp_warnings)
				log(LOG_ERR, "arp: %s is on %s%d but got reply from %s on %s%d\n",
					inet_ntop(AF_INET, &sender_ip->sin_addr, ipv4str,
							  sizeof(ipv4str)),
					route->rt_ifp->if_name,
					route->rt_ifp->if_unit,
					sdl_addr_to_hex(sender_hw, buf, sizeof(buf)),
					ifp->if_name, ifp->if_unit);
			goto respond;
		}
		else {
			/* Don't change a permanent address */
			if (route->rt_rmx.rmx_expire == 0) {
				goto respond;
			}
			
			/*
			 * Don't change the cloned route away from the parent's interface
			 * if the address did resolve.
			 */
			if (gateway->sdl_alen != 0 && route->rt_parent &&
				route->rt_parent->rt_ifp == route->rt_ifp) {
				goto respond;
			}
			
			/* Change the interface when the existing route is on */
			route->rt_ifp = ifp;
			rtsetifa(route, &best_ia->ia_ifa);
			gateway->sdl_index = ifp->if_index;
		}
	}
	
	if (gateway->sdl_alen && bcmp(LLADDR(gateway), CONST_LLADDR(sender_hw), gateway->sdl_alen)) {
		if (route->rt_rmx.rmx_expire) {
			char buf2[3 * MAX_HW_LEN];
			log(LOG_INFO, "arp: %s moved from %s to %s on %s%d\n",
				inet_ntop(AF_INET, &sender_ip->sin_addr, ipv4str,
						  sizeof(ipv4str)),
				sdl_addr_to_hex(gateway, buf, sizeof(buf)),
				sdl_addr_to_hex(sender_hw, buf2, sizeof(buf2)), ifp->if_name,
				ifp->if_unit);
		}
		else {
			log(LOG_ERR,
				"arp: %s attempts to modify permanent entry for %s on %s%d\n",
				sdl_addr_to_hex(sender_hw, buf, sizeof(buf)),
				inet_ntop(AF_INET, &sender_ip->sin_addr, ipv4str,
						  sizeof(ipv4str)),
				ifp->if_name, ifp->if_unit);
			goto respond;
		}
	}
	
	/* Copy the sender hardware address in to the route's gateway address */
	gateway->sdl_alen = sender_hw->sdl_alen;
	bcopy(CONST_LLADDR(sender_hw), LLADDR(gateway), gateway->sdl_alen);
	
	/* Update the expire time for the route and clear the reject flag */
	getmicrotime(&timenow);
	if (route->rt_rmx.rmx_expire)
		route->rt_rmx.rmx_expire = timenow.tv_sec + arpt_keep;
	route->rt_flags &= ~RTF_REJECT;
	
	/* update the llinfo, send a queued packet if there is one */
	llinfo = (struct llinfo_arp*)route->rt_llinfo;
	llinfo->la_asked = 0;
	if (llinfo->la_hold) {
		struct mbuf *m0;
		m0 = llinfo->la_hold;
		llinfo->la_hold = 0;
		
		/* Should we a reference on the route first? */
		lck_mtx_unlock(rt_mtx);
		dlil_output(ifp, PF_INET, m0, (caddr_t)route, rt_key(route), 0);
		lck_mtx_lock(rt_mtx);
	}
	
respond:
	if (arpop != ARPOP_REQUEST) {
		lck_mtx_unlock(rt_mtx);
		return 0;
	}
	
	/* If we are not the target, check if we should proxy */
	if (target_ip->sin_addr.s_addr != best_ia->ia_addr.sin_addr.s_addr) {
	
		/* Find a proxy route */
		error = arp_lookup_route(&target_ip->sin_addr, 0, SIN_PROXY, &route);
		if (error || route == NULL) {
			
			/* We don't have a route entry indicating we should use proxy */
			/* If we aren't supposed to proxy all, we are done */
			if (!arp_proxyall) {
				lck_mtx_unlock(rt_mtx);
				return 0;
			}
			
			/* See if we have a route to the target ip before we proxy it */
			route = rtalloc1_locked((const struct sockaddr*)target_ip, 0, 0);
			if (!route) {
				lck_mtx_unlock(rt_mtx);
				return 0;
			}
			
			/*
			 * Don't proxy for hosts already on the same interface.
			 */
			if (route->rt_ifp == ifp) {
				rtfree_locked(route);
				lck_mtx_unlock(rt_mtx);
				return 0;
			}
		}
	}
	lck_mtx_unlock(rt_mtx);
	
	dlil_send_arp(ifp, ARPOP_REPLY, NULL, (const struct sockaddr*)target_ip,
		sender_hw, (const struct sockaddr*)sender_ip);
	
	return 0;
}

void
arp_ifinit(
	struct ifnet *ifp,
	struct ifaddr *ifa)
{
	ifa->ifa_rtrequest = arp_rtrequest;
	ifa->ifa_flags |= RTF_CLONING;
	dlil_send_arp(ifp, ARPOP_REQUEST, NULL, ifa->ifa_addr, NULL, ifa->ifa_addr);
}
