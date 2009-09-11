/*
 * Copyright (c) 2003-2008 Apple Inc. All rights reserved.
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
/*	$FreeBSD: src/sys/netinet6/in6_ifattach.c,v 1.8 2002/04/19 04:46:22 suz Exp $	*/
/*	$KAME: in6_ifattach.c,v 1.118 2001/05/24 07:44:00 itojun Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <libkern/crypto/md5.h>
#include <libkern/OSAtomic.h>
#include <kern/lock.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/kpi_protocol.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#include <netinet/in_pcb.h>

#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_var.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/in6_ifattach.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet6/scope6_var.h>

#include <net/net_osdep.h>

struct in6_ifstat **in6_ifstat = NULL;
struct icmp6_ifstat **icmp6_ifstat = NULL;
size_t in6_ifstatmax = 0;
size_t icmp6_ifstatmax = 0;
u_int32_t in6_maxmtu = 0;
extern lck_mtx_t *nd6_mutex;
extern lck_mtx_t *inet6_domain_mutex;

#if IP6_AUTO_LINKLOCAL
int ip6_auto_linklocal = IP6_AUTO_LINKLOCAL;
#else
int ip6_auto_linklocal = 1;	/* enable by default */
#endif

extern struct inpcbinfo udbinfo;
extern struct inpcbinfo ripcbinfo;
extern lck_mtx_t *ip6_mutex;

static int get_rand_ifid(struct ifnet *, struct in6_addr *);
static int generate_tmp_ifid(u_int8_t *, const u_int8_t *, u_int8_t *);
static int get_hw_ifid(struct ifnet *, struct in6_addr *);
static int get_ifid(struct ifnet *, struct ifnet *, struct in6_addr *);
static int in6_ifattach_linklocal(struct ifnet *, struct ifnet *, struct in6_aliasreq *);
static int in6_ifattach_loopback(struct ifnet *);

#define EUI64_GBIT	0x01
#define EUI64_UBIT	0x02
#define EUI64_TO_IFID(in6)	do {(in6)->s6_addr[8] ^= EUI64_UBIT; } while (0)
#define EUI64_GROUP(in6)	((in6)->s6_addr[8] & EUI64_GBIT)
#define EUI64_INDIVIDUAL(in6)	(!EUI64_GROUP(in6))
#define EUI64_LOCAL(in6)	((in6)->s6_addr[8] & EUI64_UBIT)
#define EUI64_UNIVERSAL(in6)	(!EUI64_LOCAL(in6))

#define IFID_LOCAL(in6)		(!EUI64_LOCAL(in6))
#define IFID_UNIVERSAL(in6)	(!EUI64_UNIVERSAL(in6))

/*
 * Generate a last-resort interface identifier, when the machine has no
 * IEEE802/EUI64 address sources.
 * The goal here is to get an interface identifier that is
 * (1) random enough and (2) does not change across reboot.
 * We currently use MD5(hostname) for it.
 */
static int
get_rand_ifid(
	__unused struct ifnet *ifp,
	struct in6_addr *in6)	/* upper 64bits are preserved */
{
	MD5_CTX ctxt;
	u_int8_t digest[16];
	int len	= strlen(hostname);

#if 0
	/* we need at least several letters as seed for ifid */
	if (len < 3)
		return -1;
#endif

	/* generate 8 bytes of pseudo-random value. */
	bzero(&ctxt, sizeof(ctxt));
	MD5Init(&ctxt);
	MD5Update(&ctxt, hostname, len);
	MD5Final(digest, &ctxt);

	/* assumes sizeof(digest) > sizeof(ifid) */
	bcopy(digest, &in6->s6_addr[8], 8);

	/* make sure to set "u" bit to local, and "g" bit to individual. */
	in6->s6_addr[8] &= ~EUI64_GBIT;	/* g bit to "individual" */
	in6->s6_addr[8] |= EUI64_UBIT;	/* u bit to "local" */

	/* convert EUI64 into IPv6 interface identifier */
	EUI64_TO_IFID(in6);

	return 0;
}

static int
generate_tmp_ifid(
	u_int8_t *seed0,
	const u_int8_t *seed1,
	u_int8_t *ret)
{
	MD5_CTX ctxt;
	u_int8_t seed[16], digest[16], nullbuf[8];
	u_int32_t val32;
	struct timeval tv;

	/* If there's no hisotry, start with a random seed. */
	bzero(nullbuf, sizeof(nullbuf));
	if (bcmp(nullbuf, seed0, sizeof(nullbuf)) == 0) {
		int i;

		for (i = 0; i < 2; i++) {
			microtime(&tv);
			val32 = random() ^ tv.tv_usec;
			bcopy(&val32, seed + sizeof(val32) * i, sizeof(val32));
		}
	} else {
		bcopy(seed0, seed, 8);
	}

	/* copy the right-most 64-bits of the given address */
	/* XXX assumption on the size of IFID */
	bcopy(seed1, &seed[8], 8);

	if (0) {		/* for debugging purposes only */
		int i;

		printf("generate_tmp_ifid: new randomized ID from: ");
		for (i = 0; i < 16; i++)
			printf("%02x", seed[i]);
		printf(" ");
	}

	/* generate 16 bytes of pseudo-random value. */
	bzero(&ctxt, sizeof(ctxt));
	MD5Init(&ctxt);
	MD5Update(&ctxt, seed, sizeof(seed));
	MD5Final(digest, &ctxt);

	/*
	 * RFC 3041 3.2.1. (3)
	 * Take the left-most 64-bits of the MD5 digest and set bit 6 (the
	 * left-most bit is numbered 0) to zero.
	 */
	bcopy(digest, ret, 8);
	ret[0] &= ~EUI64_UBIT;

	/*
	 * XXX: we'd like to ensure that the generated value is not zero
	 * for simplicity.  If the caclculated digest happens to be zero,
	 * use a random non-zero value as the last resort.
	 */
	if (bcmp(nullbuf, ret, sizeof(nullbuf)) == 0) {
		log(LOG_INFO,
		    "generate_tmp_ifid: computed MD5 value is zero.\n");

		microtime(&tv);
		val32 = random() ^ tv.tv_usec;
		val32 = 1 + (val32 % (0xffffffff - 1));
	}

	/*
	 * RFC 3041 3.2.1. (4)
	 * Take the rightmost 64-bits of the MD5 digest and save them in
	 * stable storage as the history value to be used in the next
	 * iteration of the algorithm. 
	 */
	bcopy(&digest[8], seed0, 8);

	if (0) {		/* for debugging purposes only */
		int i;

		printf("to: ");
		for (i = 0; i < 16; i++)
			printf("%02x", digest[i]);
		printf("\n");
	}

	return 0;
}

/*
 * Get interface identifier for the specified interface.
 * XXX assumes single sockaddr_dl (AF_LINK address) per an interface
 */
static int
get_hw_ifid(
	struct ifnet *ifp,
	struct in6_addr *in6)	/* upper 64bits are preserved */
{
	struct ifaddr *ifa;
	struct sockaddr_dl *sdl;
	u_int8_t *addr;
	size_t addrlen;
	static u_int8_t allzero[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	static u_int8_t allone[8] =
		{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	/* Why doesn't this code use ifnet_addrs? */
	ifnet_lock_shared(ifp);
	for (ifa = ifp->if_addrlist.tqh_first;
	     ifa;
	     ifa = ifa->ifa_list.tqe_next)
	{
		if (ifa->ifa_addr->sa_family != AF_LINK)
			continue;
		sdl = (struct sockaddr_dl *)ifa->ifa_addr;
		if (sdl == NULL)
			continue;
		if (sdl->sdl_alen == 0)
			continue;

		goto found;
	}
	ifnet_lock_done(ifp);

	return -1;

found:
	ifnet_lock_done(ifp);
	addr = (u_int8_t *) LLADDR(sdl);
	addrlen = sdl->sdl_alen;

	/* get EUI64 */
	switch (ifp->if_type) {
	case IFT_ETHER:
	case IFT_FDDI:
	case IFT_ATM:
	case IFT_IEEE1394:
	case IFT_L2VLAN:
	case IFT_IEEE8023ADLAG:
#if IFT_IEEE80211
	case IFT_IEEE80211:
#endif
		/* IEEE802/EUI64 cases - what others? */
		/* IEEE1394 uses 16byte length address starting with EUI64 */
		if (addrlen > 8)
			addrlen = 8;

		/* look at IEEE802/EUI64 only */
		if (addrlen != 8 && addrlen != 6)
			return -1;

		/*
		 * check for invalid MAC address - on bsdi, we see it a lot
		 * since wildboar configures all-zero MAC on pccard before
		 * card insertion.
		 */
		if (bcmp(addr, allzero, addrlen) == 0)
			return -1;
		if (bcmp(addr, allone, addrlen) == 0)
			return -1;

		/* make EUI64 address */
		if (addrlen == 8)
			bcopy(addr, &in6->s6_addr[8], 8);
		else if (addrlen == 6) {
			in6->s6_addr[8] = addr[0];
			in6->s6_addr[9] = addr[1];
			in6->s6_addr[10] = addr[2];
			in6->s6_addr[11] = 0xff;
			in6->s6_addr[12] = 0xfe;
			in6->s6_addr[13] = addr[3];
			in6->s6_addr[14] = addr[4];
			in6->s6_addr[15] = addr[5];
		}
		break;

	case IFT_ARCNET:
		if (addrlen != 1)
			return -1;
		if (!addr[0])
			return -1;

		bzero(&in6->s6_addr[8], 8);
		in6->s6_addr[15] = addr[0];

		/*
		 * due to insufficient bitwidth, we mark it local.
		 */
		in6->s6_addr[8] &= ~EUI64_GBIT;	/* g bit to "individual" */
		in6->s6_addr[8] |= EUI64_UBIT;	/* u bit to "local" */
		break;

	case IFT_GIF:
#if IFT_STF
	case IFT_STF:
#endif
		/*
		 * RFC2893 says: "SHOULD use IPv4 address as ifid source".
		 * however, IPv4 address is not very suitable as unique
		 * identifier source (can be renumbered).
		 * we don't do this.
		 */
		return -1;

	default:
		return -1;
	}

	/* sanity check: g bit must not indicate "group" */
	if (EUI64_GROUP(in6))
		return -1;

	/* convert EUI64 into IPv6 interface identifier */
	EUI64_TO_IFID(in6);

	/*
	 * sanity check: ifid must not be all zero, avoid conflict with
	 * subnet router anycast
	 */
	if ((in6->s6_addr[8] & ~(EUI64_GBIT | EUI64_UBIT)) == 0x00 &&
	    bcmp(&in6->s6_addr[9], allzero, 7) == 0) {
		return -1;
	}

	return 0;
}

/*
 * Get interface identifier for the specified interface.  If it is not
 * available on ifp0, borrow interface identifier from other information
 * sources.
 */
static int
get_ifid(
	struct ifnet *ifp0,
	struct ifnet *altifp,	/* secondary EUI64 source */
	struct in6_addr *in6)
{
	struct ifnet *ifp;

	/* first, try to get it from the interface itself */
	if (get_hw_ifid(ifp0, in6) == 0) {
		nd6log((LOG_DEBUG, "%s: got interface identifier from itself\n",
		    if_name(ifp0)));
		goto success;
	}

	/* try secondary EUI64 source. this basically is for ATM PVC */
	if (altifp && get_hw_ifid(altifp, in6) == 0) {
		nd6log((LOG_DEBUG, "%s: got interface identifier from %s\n",
		    if_name(ifp0), if_name(altifp)));
		goto success;
	}

	/* next, try to get it from some other hardware interface */
	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_list) {
		if (ifp == ifp0)
			continue;
		if (get_hw_ifid(ifp, in6) != 0)
			continue;

		/*
		 * to borrow ifid from other interface, ifid needs to be
		 * globally unique
		 */
		if (IFID_UNIVERSAL(in6)) {
			nd6log((LOG_DEBUG,
			    "%s: borrow interface identifier from %s\n",
			    if_name(ifp0), if_name(ifp)));
			ifnet_head_done();
			goto success;
		}
	}
	ifnet_head_done();

	/* last resort: get from random number source */
	if (get_rand_ifid(ifp, in6) == 0) {
		nd6log((LOG_DEBUG,
		    "%s: interface identifier generated by random number\n",
		    if_name(ifp0)));
		goto success;
	}

	printf("%s: failed to get interface identifier\n", if_name(ifp0));
	return -1;

success:
	nd6log((LOG_INFO, "%s: ifid: "
		"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
		if_name(ifp0),
		in6->s6_addr[8], in6->s6_addr[9],
		in6->s6_addr[10], in6->s6_addr[11],
		in6->s6_addr[12], in6->s6_addr[13],
		in6->s6_addr[14], in6->s6_addr[15]));
	return 0;
}

static int
in6_ifattach_linklocal(
	struct ifnet *ifp,
	struct ifnet *altifp,	/* secondary EUI64 source */
	struct in6_aliasreq *ifra_passed)
{
	struct in6_ifaddr *ia;
	struct in6_aliasreq ifra;
	struct nd_prefix pr0, *pr;
	int i, error;

	/*
	 * configure link-local address.
	 */
	bzero(&ifra, sizeof(ifra));

	proto_plumb(PF_INET6, ifp);

	/*
	 * in6_update_ifa() does not use ifra_name, but we accurately set it
	 * for safety.
	 */
	strncpy(ifra.ifra_name, if_name(ifp), sizeof(ifra.ifra_name));

	if (((ifp->if_type == IFT_PPP) ||  ((ifp->if_eflags & IFEF_NOAUTOIPV6LL) != 0)) &&
			 ifra_passed != NULL)  /* PPP provided both addresses for us */
		bcopy(&ifra_passed->ifra_addr, &(ifra.ifra_addr), sizeof(struct sockaddr_in6));
	else {
		ifra.ifra_addr.sin6_family = AF_INET6;
		ifra.ifra_addr.sin6_len = sizeof(struct sockaddr_in6);
		ifra.ifra_addr.sin6_addr.s6_addr16[0] = htons(0xfe80);
#if SCOPEDROUTING
		ifra.ifra_addr.sin6_addr.s6_addr16[1] = 0
#else
		ifra.ifra_addr.sin6_addr.s6_addr16[1] = htons(ifp->if_index); /* XXX */
#endif
		ifra.ifra_addr.sin6_addr.s6_addr32[1] = 0;
		if ((ifp->if_flags & IFF_LOOPBACK) != 0) {
			ifra.ifra_addr.sin6_addr.s6_addr32[2] = 0;
			ifra.ifra_addr.sin6_addr.s6_addr32[3] = htonl(1);
		} else {
			if (get_ifid(ifp, altifp, &ifra.ifra_addr.sin6_addr) != 0) {
				nd6log((LOG_ERR,
			    "	%s: no ifid available\n", if_name(ifp)));
				return -1;
			}
		}
#if SCOPEDROUTING
		ifra.ifra_addr.sin6_scope_id =
			in6_addr2scopeid(ifp,  &ifra.ifra_addr.sin6_addr);
#endif
	}
	ifra.ifra_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
	ifra.ifra_prefixmask.sin6_family = AF_INET6;
	ifra.ifra_prefixmask.sin6_addr = in6mask64;
#if SCOPEDROUTING
	/* take into accound the sin6_scope_id field for routing */
	ifra.ifra_prefixmask.sin6_scope_id = 0xffffffff;
#endif
	/* link-local addresses should NEVER expire. */
	ifra.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
	ifra.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

	/*
	 * Do not let in6_update_ifa() do DAD, since we need a random delay
	 * before sending an NS at the first time the interface becomes up.
	 * Instead, in6_if_up() will start DAD with a proper random delay.
	 */
	ifra.ifra_flags |= IN6_IFF_NODAD;

	/*
	 * Now call in6_update_ifa() to do a bunch of procedures to configure
	 * a link-local address. We can set NULL to the 3rd argument, because
	 * we know there's no other link-local address on the interface
	 * and therefore we are adding one (instead of updating one).
	 */
	if ((error = in6_update_ifa(ifp, &ifra, NULL, M_WAITOK)) != 0) {
		/*
		 * XXX: When the interface does not support IPv6, this call
		 * would fail in the SIOCSIFADDR ioctl.  I believe the
		 * notification is rather confusing in this case, so just
		 * supress it.  (jinmei@kame.net 20010130)
		 */
		if (error != EAFNOSUPPORT)
			log(LOG_NOTICE, "in6_ifattach_linklocal: failed to "
			    "configure a link-local address on %s "
			    "(errno=%d)\n",
			    if_name(ifp), error);
		return(-1);
	}

	/*
	 * Adjust ia6_flags so that in6_if_up will perform DAD.
	 * XXX: Some P2P interfaces seem not to send packets just after
	 * becoming up, so we skip p2p interfaces for safety.
	 */
	ia = in6ifa_ifpforlinklocal(ifp, 0); /* ia must not be NULL */
#if DIAGNOSTIC
	if (!ia) {
		panic("ia == NULL in in6_ifattach_linklocal");
		/*NOTREACHED*/
	}
#endif
	if (in6if_do_dad(ifp) && (ifp->if_flags & IFF_POINTOPOINT) == 0) {
		ia->ia6_flags &= ~IN6_IFF_NODAD;
		ia->ia6_flags |= IN6_IFF_TENTATIVE;
	}

	/*
	 * Make the link-local prefix (fe80::/64%link) as on-link.
	 * Since we'd like to manage prefixes separately from addresses,
	 * we make an ND6 prefix structure for the link-local prefix,
	 * and add it to the prefix list as a never-expire prefix.
	 * XXX: this change might affect some existing code base...
	 */
	bzero(&pr0, sizeof(pr0));
	pr0.ndpr_ifp = ifp;
	/* this should be 64 at this moment. */
	pr0.ndpr_plen = in6_mask2len(&ifra.ifra_prefixmask.sin6_addr, NULL);
	pr0.ndpr_mask = ifra.ifra_prefixmask.sin6_addr;
	pr0.ndpr_prefix = ifra.ifra_addr;
	/* apply the mask for safety. (nd6_prelist_add will apply it again) */
	for (i = 0; i < 4; i++) {
		pr0.ndpr_prefix.sin6_addr.s6_addr32[i] &=
			in6mask64.s6_addr32[i];
	}
	/*
	 * Initialize parameters.  The link-local prefix must always be
	 * on-link, and its lifetimes never expire.
	 */
	pr0.ndpr_raf_onlink = 1;
	pr0.ndpr_raf_auto = 1;	/* probably meaningless */
	pr0.ndpr_vltime = ND6_INFINITE_LIFETIME;
	pr0.ndpr_pltime = ND6_INFINITE_LIFETIME;
	/*
	 * Since there is no other link-local addresses, nd6_prefix_lookup()
	 * probably returns NULL.  However, we cannot always expect the result.
	 * For example, if we first remove the (only) existing link-local
	 * address, and then reconfigure another one, the prefix is still
	 * valid with referring to the old link-local address.
	 */
	if ((pr = nd6_prefix_lookup(&pr0)) == NULL) {
		if ((error = nd6_prelist_add(&pr0, NULL, &pr)) != 0) {
			printf("in6_ifattach_linklocal: nd6_prelist_add failed %d\n", error);
			ifafree(&ia->ia_ifa);
			return(error);
		}
	}

	if (ia != NULL) {
		in6_post_msg(ifp, KEV_INET6_NEW_LL_ADDR, ia);
		ifafree(&ia->ia_ifa);
	}

	/* Drop use count held above during lookup/add */
	if (pr != NULL)
		ndpr_rele(pr, FALSE);

	return 0;
}

static int
in6_ifattach_loopback(
	struct ifnet *ifp)	/* must be IFT_LOOP */
{
	struct in6_aliasreq ifra;
	int error;

	bzero(&ifra, sizeof(ifra));

	/*
	 * in6_update_ifa() does not use ifra_name, but we accurately set it
	 * for safety.
	 */
	strncpy(ifra.ifra_name, if_name(ifp), sizeof(ifra.ifra_name));

	ifra.ifra_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
	ifra.ifra_prefixmask.sin6_family = AF_INET6;
	ifra.ifra_prefixmask.sin6_addr = in6mask128;

	/*
	 * Always initialize ia_dstaddr (= broadcast address) to loopback
	 * address.  Follows IPv4 practice - see in_ifinit().
	 */
	ifra.ifra_dstaddr.sin6_len = sizeof(struct sockaddr_in6);
	ifra.ifra_dstaddr.sin6_family = AF_INET6;
	ifra.ifra_dstaddr.sin6_addr = in6addr_loopback;

	ifra.ifra_addr.sin6_len = sizeof(struct sockaddr_in6);
	ifra.ifra_addr.sin6_family = AF_INET6;
	ifra.ifra_addr.sin6_addr = in6addr_loopback;

	/* the loopback  address should NEVER expire. */
	ifra.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
	ifra.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

	/* we don't need to perform DAD on loopback interfaces. */
	ifra.ifra_flags |= IN6_IFF_NODAD;

	/* skip registration to the prefix list. XXX should be temporary. */
	ifra.ifra_flags |= IN6_IFF_NOPFX;

	/*
	 * We are sure that this is a newly assigned address, so we can set
	 * NULL to the 3rd arg.
	 */
	if ((error = in6_update_ifa(ifp, &ifra, NULL, M_WAITOK)) != 0) {
		log(LOG_ERR, "in6_ifattach_loopback: failed to configure "
		    "the loopback address on %s (errno=%d)\n",
		    if_name(ifp), error);
		return(-1);
	}

	return 0;
}

/*
 * compute NI group address, based on the current hostname setting.
 * see draft-ietf-ipngwg-icmp-name-lookup-* (04 and later).
 *
 * when ifp == NULL, the caller is responsible for filling scopeid.
 */
int
in6_nigroup(
	struct ifnet *ifp,
	const char *name,
	int namelen,
	struct in6_addr *in6)
{
	const char *p;
	u_char *q;
	MD5_CTX ctxt;
	u_int8_t digest[16];
	char l;
	char n[64];	/* a single label must not exceed 63 chars */

	if (!namelen || !name)
		return -1;

	p = name;
	while (p && *p && *p != '.' && p - name < namelen)
		p++;
	if (p - name > sizeof(n) - 1)
		return -1;	/* label too long */
	l = p - name;
	strncpy(n, name, l);
	n[(int)l] = '\0';
	for (q = (u_char *) n; *q; q++) {
		if ('A' <= *q && *q <= 'Z')
			*q = *q - 'A' + 'a';
	}

	/* generate 8 bytes of pseudo-random value. */
	bzero(&ctxt, sizeof(ctxt));
	MD5Init(&ctxt);
	MD5Update(&ctxt, &l, sizeof(l));
	MD5Update(&ctxt, n, l);
	MD5Final(digest, &ctxt);

	bzero(in6, sizeof(*in6));
	in6->s6_addr16[0] = htons(0xff02);
	if (ifp)
		in6->s6_addr16[1] = htons(ifp->if_index);
	in6->s6_addr8[11] = 2;
	bcopy(digest, &in6->s6_addr32[3], sizeof(in6->s6_addr32[3]));

	return 0;
}

void
in6_nigroup_attach(
	const char *name,
	int namelen)
{
	struct ifnet *ifp;
	struct sockaddr_in6 mltaddr;
	struct in6_multi *in6m;
	int error;

	bzero(&mltaddr, sizeof(mltaddr));
	mltaddr.sin6_family = AF_INET6;
	mltaddr.sin6_len = sizeof(struct sockaddr_in6);
	if (in6_nigroup(NULL, name, namelen, &mltaddr.sin6_addr) != 0)
		return;

	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_list) {
		mltaddr.sin6_addr.s6_addr16[1] = htons(ifp->if_index);
		ifnet_lock_shared(ifp);
		IN6_LOOKUP_MULTI(mltaddr.sin6_addr, ifp, in6m);
		ifnet_lock_done(ifp);
		if (!in6m) {
			if (!in6_addmulti(&mltaddr.sin6_addr, ifp, &error, 0)) {
				nd6log((LOG_ERR, "%s: failed to join %s "
				    "(errno=%d)\n", if_name(ifp),
				    ip6_sprintf(&mltaddr.sin6_addr), 
				    error));
			}
		}
	}
	ifnet_head_done();
}

void
in6_nigroup_detach(
	const char *name,
	int namelen)
{
	struct ifnet *ifp;
	struct sockaddr_in6 mltaddr;
	struct in6_multi *in6m;

	bzero(&mltaddr, sizeof(mltaddr));
	mltaddr.sin6_family = AF_INET6;
	mltaddr.sin6_len = sizeof(struct sockaddr_in6);
	if (in6_nigroup(NULL, name, namelen, &mltaddr.sin6_addr) != 0)
		return;

	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_list) {
		mltaddr.sin6_addr.s6_addr16[1] = htons(ifp->if_index);
		ifnet_lock_shared(ifp);
		IN6_LOOKUP_MULTI(mltaddr.sin6_addr, ifp, in6m);
		ifnet_lock_done(ifp);
		if (in6m)
			in6_delmulti(in6m, 0);
	}
	ifnet_head_done();
}

/*
 * XXX multiple loopback interface needs more care.  for instance,
 * nodelocal address needs to be configured onto only one of them.
 * XXX multiple link-local address case
 */
int
in6_ifattach(
	struct ifnet *ifp,
	struct ifnet *altifp,	/* secondary EUI64 source */
	struct	in6_aliasreq *ifra)
{
	static size_t if_indexlim = 8;
	struct in6_ifaddr *ia;
	int error;

	/*
	 * We have some arrays that should be indexed by if_index.
	 * since if_index will grow dynamically, they should grow too.
	 *	struct in6_ifstat **in6_ifstat
	 *	struct icmp6_ifstat **icmp6_ifstat
	 */
	if (in6_ifstat == NULL || icmp6_ifstat == NULL ||
	    if_index >= if_indexlim) {
		while (if_index >= if_indexlim)
			if_indexlim <<= 1;
	}
    
	lck_mtx_lock(ip6_mutex);
	/* grow in6_ifstat */
	if (in6_ifstatmax < if_indexlim) {
		size_t n;
		caddr_t q;
        
		n = if_indexlim * sizeof(struct in6_ifstat *);
		q = (caddr_t)_MALLOC(n, M_IFADDR, M_WAITOK);
		if (q == NULL) {
			lck_mtx_unlock(ip6_mutex);
			return ENOBUFS;
		}
		bzero(q, n);
		if (in6_ifstat) {
			bcopy((caddr_t)in6_ifstat, q,
				in6_ifstatmax * sizeof(struct in6_ifstat *));
			FREE((caddr_t)in6_ifstat, M_IFADDR);
		}
		in6_ifstat = (struct in6_ifstat **)q;
		in6_ifstatmax = if_indexlim;
	}
    
	if (in6_ifstat[ifp->if_index] == NULL) {
		in6_ifstat[ifp->if_index] = (struct in6_ifstat *)
			_MALLOC(sizeof(struct in6_ifstat), M_IFADDR, M_WAITOK);
		if (in6_ifstat[ifp->if_index] == NULL) {
			lck_mtx_unlock(ip6_mutex);
			return ENOBUFS;
		}
		bzero(in6_ifstat[ifp->if_index], sizeof(struct in6_ifstat));
	}
	lck_mtx_unlock(ip6_mutex);

	/* grow icmp6_ifstat, use inet6_domain_mutex as that is used in 
         * icmp6 routines 
         */
	lck_mtx_lock(inet6_domain_mutex);
	if (icmp6_ifstatmax < if_indexlim) {
		size_t n;
		caddr_t q;
        
		n = if_indexlim * sizeof(struct icmp6_ifstat *);
		q = (caddr_t)_MALLOC(n, M_IFADDR, M_WAITOK);
		if (q == NULL) {
			lck_mtx_unlock(inet6_domain_mutex);
			return ENOBUFS;
		}
		bzero(q, n);
		if (icmp6_ifstat) {
			bcopy((caddr_t)icmp6_ifstat, q,
				icmp6_ifstatmax * sizeof(struct icmp6_ifstat *));
			FREE((caddr_t)icmp6_ifstat, M_IFADDR);
		}
		icmp6_ifstat = (struct icmp6_ifstat **)q;
		icmp6_ifstatmax = if_indexlim;
	}

	if (icmp6_ifstat[ifp->if_index] == NULL) {
		icmp6_ifstat[ifp->if_index] = (struct icmp6_ifstat *)
			_MALLOC(sizeof(struct icmp6_ifstat), M_IFADDR, M_WAITOK);
		if (icmp6_ifstat[ifp->if_index] == NULL) {
			lck_mtx_unlock(inet6_domain_mutex);
			return ENOBUFS;
		}
		bzero(icmp6_ifstat[ifp->if_index], sizeof(struct icmp6_ifstat));
	}
	lck_mtx_unlock(inet6_domain_mutex);

	/* initialize NDP variables */
	if ((error = nd6_ifattach(ifp)) != 0)
		return error;

	/* initialize scope identifiers */
	if ((error = scope6_ifattach(ifp)) != 0)
		return error;

	/*
	 * quirks based on interface type
	 */
	switch (ifp->if_type) {
#if IFT_STF
	case IFT_STF:
		/*
		 * 6to4 interface is a very special kind of beast.
		 * no multicast, no linklocal.  RFC2529 specifies how to make
		 * linklocals for 6to4 interface, but there's no use and
		 * it is rather harmful to have one.
		 */
		goto statinit;
#endif
	default:
		break;
	}

	/*
	 * usually, we require multicast capability to the interface
	 */
	if ((ifp->if_flags & IFF_MULTICAST) == 0) {
		log(LOG_INFO, "in6_ifattach: "
		    "%s is not multicast capable, IPv6 not enabled\n",
		    if_name(ifp));
		return EINVAL;
	}

	/*
	 * assign loopback address for loopback interface.
	 * XXX multiple loopback interface case.
	 */
	if ((ifp->if_flags & IFF_LOOPBACK) != 0) {
		if (in6_ifattach_loopback(ifp) != 0)
			printf("in6_ifattach: in6_ifattach_loopback failed\n");
	}

	/*
	 * assign a link-local address, if there's none. 
	 */
	if (ip6_auto_linklocal) {
		ia = in6ifa_ifpforlinklocal(ifp, 0);
		if (ia == NULL) {
			if (in6_ifattach_linklocal(ifp, altifp, ifra) == 0) {
				/* linklocal address assigned */
			} else {
				log(LOG_INFO, "in6_ifattach: %s failed to "
				    "attach a linklocal address.\n",
				    if_name(ifp));
				/* failed to assign linklocal address. bark? */
			}
		} else {
			ifafree(&ia->ia_ifa);
		}
	}

#if IFT_STF			/* XXX */
statinit:	
#endif

	/* update dynamically. */
	if (in6_maxmtu < ifp->if_mtu)
		in6_maxmtu = ifp->if_mtu;

    return 0;
}

/*
 * NOTE: in6_ifdetach() does not support loopback if at this moment.
 * We don't need this function in bsdi, because interfaces are never removed
 * from the ifnet list in bsdi.
 */
void
in6_ifdetach(
	struct ifnet *ifp)
{
	struct in6_ifaddr *ia, *oia, *nia;
	struct ifaddr *ifa, *next;
	struct rtentry *rt;
	struct sockaddr_in6 sin6;

	/* nuke prefix list.  this may try to remove some of ifaddrs as well */
	in6_purgeprefix(ifp);

	/* remove neighbor management table */
	nd6_purge(ifp);

	/* nuke any of IPv6 addresses we have */
	
	lck_mtx_lock(nd6_mutex);
	for (ia = in6_ifaddrs; ia != NULL; ia = nia) {
		nia = ia->ia_next;
		if (ia->ia_ifa.ifa_ifp != ifp)
			continue;
		in6_purgeaddr(&ia->ia_ifa, 1);
	}
	lck_mtx_unlock(nd6_mutex);

	ifnet_lock_exclusive(ifp);

	/* undo everything done by in6_ifattach(), just in case */
	for (ifa = ifp->if_addrlist.tqh_first; ifa; ifa = next)
	{
		next = ifa->ifa_list.tqe_next;


		if (ifa->ifa_addr->sa_family != AF_INET6
		 || !IN6_IS_ADDR_LINKLOCAL(&satosin6(&ifa->ifa_addr)->sin6_addr)) {
			continue;
		}

		ia = (struct in6_ifaddr *)ifa;

		/* remove from the routing table */
		if ((ia->ia_flags & IFA_ROUTE) &&
		    (rt = rtalloc1((struct sockaddr *)&ia->ia_addr, 0, 0))) {
			(void) rtrequest(RTM_DELETE,
				(struct sockaddr *)&ia->ia_addr,
				(struct sockaddr *)&ia->ia_addr,
				(struct sockaddr *)&ia->ia_prefixmask,
				rt->rt_flags, (struct rtentry **)0);
			rtfree(rt);
		}

		/* remove from the linked list */
		if_detach_ifa(ifp, &ia->ia_ifa);

		/* also remove from the IPv6 address chain(itojun&jinmei) */
		oia = ia;
		lck_mtx_lock(nd6_mutex);
		if (oia == (ia = in6_ifaddrs))
			in6_ifaddrs = ia->ia_next;
		else {
			while (ia->ia_next && (ia->ia_next != oia))
				ia = ia->ia_next;
			if (ia->ia_next)
				ia->ia_next = oia->ia_next;
			else {
				nd6log((LOG_ERR, 
				    "%s: didn't unlink in6ifaddr from "
				    "list\n", if_name(ifp)));
			}
		}
		lck_mtx_unlock(nd6_mutex);

		ifafree(&oia->ia_ifa);
	}
	ifnet_lock_done(ifp);

	/*
	 * remove neighbor management table.  we call it twice just to make
	 * sure we nuke everything.  maybe we need just one call.
	 * XXX: since the first call did not release addresses, some prefixes
	 * might remain.  We should call nd6_purge() again to release the
	 * prefixes after removing all addresses above.
	 * (Or can we just delay calling nd6_purge until at this point?)
	 */
	nd6_purge(ifp);

	/* remove route to link-local allnodes multicast (ff02::1) */
	bzero(&sin6, sizeof(sin6));
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = in6addr_linklocal_allnodes;
	sin6.sin6_addr.s6_addr16[1] = htons(ifp->if_index);
	rt = rtalloc1((struct sockaddr *)&sin6, 0, 0);
	if (rt != NULL) {
		RT_LOCK(rt);
	        if (rt->rt_ifp == ifp) {
			/*
			 * Prevent another thread from modifying rt_key,
			 * rt_gateway via rt_setgate() after the rt_lock
			 * is dropped by marking the route as defunct.
			 */
			rt->rt_flags |= RTF_CONDEMNED;
			RT_UNLOCK(rt);
			(void) rtrequest(RTM_DELETE, rt_key(rt), rt->rt_gateway,
			    rt_mask(rt), rt->rt_flags, 0);
		} else {
			RT_UNLOCK(rt);
		}
		rtfree(rt);
	}
}

void
in6_get_tmpifid(
	struct ifnet *ifp,
	u_int8_t *retbuf,
	const u_int8_t *baseid,
	int generate)
{
	u_int8_t nullbuf[8];
	struct nd_ifinfo *ndi;

	lck_rw_lock_shared(nd_if_rwlock);
	ndi = &nd_ifinfo[ifp->if_index];
	bzero(nullbuf, sizeof(nullbuf));
	if (bcmp(ndi->randomid, nullbuf, sizeof(nullbuf)) == 0) {
		/* we've never created a random ID.  Create a new one. */
		generate = 1;
	}

	if (generate) {
		bcopy(baseid, ndi->randomseed1, sizeof(ndi->randomseed1));

		/* generate_tmp_ifid will update seedn and buf */
		(void)generate_tmp_ifid(ndi->randomseed0, ndi->randomseed1,
					ndi->randomid);
	}
	bcopy(ndi->randomid, retbuf, 8);
	lck_rw_done(nd_if_rwlock);
}

void
in6_tmpaddrtimer(
	__unused void *ignored_arg)
{
	int i;
	struct nd_ifinfo *ndi;
	u_int8_t nullbuf[8];

	timeout(in6_tmpaddrtimer, (caddr_t)0,
		      (ip6_temp_preferred_lifetime - ip6_desync_factor -
		       ip6_temp_regen_advance) * hz);

	if (ip6_use_tempaddr) {
		lck_rw_lock_shared(nd_if_rwlock);
		bzero(nullbuf, sizeof(nullbuf));
		for (i = 1; i < nd_ifinfo_indexlim + 1; i++) {
			ndi = &nd_ifinfo[i];
			if (ndi->flags != ND6_IFF_PERFORMNUD)
				continue;
			if (bcmp(ndi->randomid, nullbuf, sizeof(nullbuf)) != 0) {
				/*
				 * We've been generating a random ID on this interface.
				 * Create a new one.
				 */
				(void)generate_tmp_ifid(ndi->randomseed0,
							ndi->randomseed1,
							ndi->randomid);
			}
		}
		lck_rw_done(nd_if_rwlock);
	}
}
