/*
 * Copyright (c) 2003-2014 Apple Inc. All rights reserved.
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
#include <libkern/crypto/sha1.h>
#include <libkern/OSAtomic.h>
#include <kern/locks.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/kpi_protocol.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#include <netinet/in_pcb.h>
#include <netinet/icmp6.h>

#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_var.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/in6_ifattach.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet6/scope6_var.h>

#include <net/net_osdep.h>
#include <dev/random/randomdev.h>

u_int32_t in6_maxmtu = 0;
extern lck_mtx_t *nd6_mutex;

#if IP6_AUTO_LINKLOCAL
int ip6_auto_linklocal = IP6_AUTO_LINKLOCAL;
#else
int ip6_auto_linklocal = 1;	/* enable by default */
#endif

extern struct inpcbinfo udbinfo;
extern struct inpcbinfo ripcbinfo;

static const unsigned int in6_extra_size = sizeof(struct in6_ifextra);
static const unsigned int in6_extra_bufsize = in6_extra_size + 
    sizeof(void *) + sizeof(uint64_t);

static int get_rand_iid(struct ifnet *, struct in6_addr *);
static int in6_generate_tmp_iid(u_int8_t *, const u_int8_t *, u_int8_t *);
static int in6_select_iid_from_all_hw(struct ifnet *, struct ifnet *,
    struct in6_addr *);
static int in6_ifattach_linklocal(struct ifnet *, struct in6_aliasreq *);
static int in6_ifattach_loopback(struct ifnet *);

/*
 * Generate a last-resort interface identifier, when the machine has no
 * IEEE802/EUI64 address sources.
 * The goal here is to get an interface identifier that is
 * (1) random enough and (2) does not change across reboot.
 * We currently use SHA1(hostname) for it.
 *
 * in6 - upper 64bits are preserved
 */
static int
get_rand_iid(
	__unused struct ifnet *ifp,
	struct in6_addr *in6)	/* upper 64bits are preserved */
{
	SHA1_CTX ctxt;
	u_int8_t digest[SHA1_RESULTLEN];
	int hostnlen	= strlen(hostname);

	/* generate 8 bytes of pseudo-random value. */
	bzero(&ctxt, sizeof (ctxt));
	SHA1Init(&ctxt);
	SHA1Update(&ctxt, hostname, hostnlen);
	SHA1Final(digest, &ctxt);

	/* assumes sizeof (digest) > sizeof (iid) */
	bcopy(digest, &in6->s6_addr[8], 8);

	/* make sure to set "u" bit to local, and "g" bit to individual. */
	in6->s6_addr[8] &= ~ND6_EUI64_GBIT;	/* g bit to "individual" */
	in6->s6_addr[8] |= ND6_EUI64_UBIT;	/* u bit to "local" */

	/* convert EUI64 into IPv6 interface identifier */
	ND6_EUI64_TO_IFID(in6);

	return (0);
}

static int
in6_generate_tmp_iid(
	u_int8_t *seed0,
	const u_int8_t *seed1,
	u_int8_t *ret)
{
	SHA1_CTX ctxt;
	u_int8_t seed[16], nullbuf[8], digest[SHA1_RESULTLEN];
	u_int32_t val32;
	struct timeval tv;

	/* If there's no history, start with a random seed. */
	bzero(nullbuf, sizeof (nullbuf));
	if (bcmp(nullbuf, seed0, sizeof (nullbuf)) == 0) {
		int i;

		for (i = 0; i < 2; i++) {
			getmicrotime(&tv);
			val32 = RandomULong() ^ tv.tv_usec;
			bcopy(&val32, seed + sizeof (val32) * i,
			    sizeof (val32));
		}
	} else {
		bcopy(seed0, seed, 8);
	}

	/* copy the right-most 64-bits of the given address */
	/* XXX assumption on the size of IFID */
	bcopy(seed1, &seed[8], 8);

	if ((0)) {		/* for debugging purposes only */
		int i;

		printf("%s: new randomized ID from: ", __func__);
		for (i = 0; i < 16; i++)
			printf("%02x", seed[i]);
		printf(" ");
	}

	/* generate 16 bytes of pseudo-random value. */
	bzero(&ctxt, sizeof (ctxt));
	SHA1Init(&ctxt);
	SHA1Update(&ctxt, seed, sizeof (seed));
	SHA1Final(digest, &ctxt);

	/*
	 * RFC 4941 3.2.1. (3)
	 * Take the left-most 64-bits of the SHA1 digest and set bit 6 (the
	 * left-most bit is numbered 0) to zero.
	 */
	bcopy(digest, ret, 8);
	ret[0] &= ~ND6_EUI64_UBIT;

	/*
	 * XXX: we'd like to ensure that the generated value is not zero
	 * for simplicity.  If the caclculated digest happens to be zero,
	 * use a random non-zero value as the last resort.
	 */
	if (bcmp(nullbuf, ret, sizeof (nullbuf)) == 0) {
		nd6log((LOG_INFO,
		    "%s: computed SHA1 value is zero.\n", __func__));

		getmicrotime(&tv);
		val32 = random() ^ tv.tv_usec;
		val32 = 1 + (val32 % (0xffffffff - 1));
	}

	/*
	 * RFC 4941 3.2.1. (4)
	 * Take the next 64-bits of the SHA1 digest and save them in
	 * stable storage as the history value to be used in the next
	 * iteration of the algorithm.
	 */
	bcopy(&digest[8], seed0, 8);

	if ((0)) {		/* for debugging purposes only */
		int i;

		printf("to: ");
		for (i = 0; i < 16; i++)
			printf("%02x", digest[i]);
		printf("\n");
	}

	return (0);
}

/*
 * Get interface identifier for the specified interface using the method in
 * Appendix A of RFC 4291.
 *
 * XXX assumes single sockaddr_dl (AF_LINK address) per an interface
 *
 * in6 - upper 64bits are preserved
 */
int
in6_iid_from_hw(struct ifnet *ifp, struct in6_addr *in6)
{
	struct ifaddr *ifa = NULL;
	struct sockaddr_dl *sdl;
	u_int8_t *addr;
	size_t addrlen;
	static u_int8_t allzero[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	static u_int8_t allone[8] =
		{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	int err = -1;

	/* Why doesn't this code use ifnet_addrs? */
	ifnet_lock_shared(ifp);
	ifa = ifp->if_lladdr;
	sdl = (struct sockaddr_dl *)(void *)ifa->ifa_addr;
	if (sdl->sdl_alen == 0) {
		ifnet_lock_done(ifp);
		return (-1);
	}
	IFA_ADDREF(ifa);	/* for this routine */
	ifnet_lock_done(ifp);

	IFA_LOCK(ifa);
	addr = (u_int8_t *) LLADDR(sdl);
	addrlen = sdl->sdl_alen;

	/* get EUI64 */
	switch (ifp->if_type) {
	case IFT_ETHER:
	case IFT_FDDI:
	case IFT_ISO88025:
	case IFT_ATM:
	case IFT_IEEE1394:
	case IFT_L2VLAN:
	case IFT_IEEE8023ADLAG:
#if IFT_IEEE80211
	case IFT_IEEE80211:
#endif
	case IFT_BRIDGE:
		/* IEEE802/EUI64 cases - what others? */
		/* IEEE1394 uses 16byte length address starting with EUI64 */
		if (addrlen > 8)
			addrlen = 8;

		/* look at IEEE802/EUI64 only */
		if (addrlen != 8 && addrlen != 6)
			goto done;

		/*
		 * check for invalid MAC address - on bsdi, we see it a lot
		 * since wildboar configures all-zero MAC on pccard before
		 * card insertion.
		 */
		if (bcmp(addr, allzero, addrlen) == 0)
			goto done;
		if (bcmp(addr, allone, addrlen) == 0)
			goto done;

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
			goto done;
		if (!addr[0])
			goto done;

		bzero(&in6->s6_addr[8], 8);
		in6->s6_addr[15] = addr[0];

		/*
		 * due to insufficient bitwidth, we mark it local.
		 */
		in6->s6_addr[8] &= ~ND6_EUI64_GBIT;	/* g to "individual" */
		in6->s6_addr[8] |= ND6_EUI64_UBIT;	/* u to "local" */
		break;

	case IFT_GIF:
#if IFT_STF
	case IFT_STF:
#endif
		/*
		 * RFC2893 says: "SHOULD use IPv4 address as IID source".
		 * however, IPv4 address is not very suitable as unique
		 * identifier source (can be renumbered).
		 * we don't do this.
		 */
		goto done;

	case IFT_CELLULAR:
		goto done;

	default:
		goto done;
	}

	/* sanity check: g bit must not indicate "group" */
	if (ND6_EUI64_GROUP(in6))
		goto done;

	/* convert EUI64 into IPv6 interface identifier */
	ND6_EUI64_TO_IFID(in6);

	/*
	 * sanity check: iid must not be all zero, avoid conflict with
	 * subnet router anycast
	 */
	if ((in6->s6_addr[8] & ~(ND6_EUI64_GBIT | ND6_EUI64_UBIT)) == 0x00 &&
	    bcmp(&in6->s6_addr[9], allzero, 7) == 0) {
		goto done;
	}

	err = 0;	/* found */

done:
	/* This must not be the last reference to the lladdr */
	if (IFA_REMREF_LOCKED(ifa) == NULL) {
		panic("%s: unexpected (missing) refcnt ifa=%p", __func__, ifa);
		/* NOTREACHED */
	}
	IFA_UNLOCK(ifa);
	return (err);
}

/*
 * Get interface identifier for the specified interface using the method in
 * Appendix A of RFC 4291.  If it is not available on ifp0, borrow interface
 * identifier from other information sources.
 *
 * ifp     - primary EUI64 source
 * altifp  - secondary EUI64 source
 * in6     - IPv6 address to output IID
 */
static int
in6_select_iid_from_all_hw(
	struct ifnet *ifp0,
	struct ifnet *altifp,	/* secondary EUI64 source */
	struct in6_addr *in6)
{
	struct ifnet *ifp;

	/* first, try to get it from the interface itself */
	if (in6_iid_from_hw(ifp0, in6) == 0) {
		nd6log((LOG_DEBUG, "%s: IID derived from HW interface.\n",
		    if_name(ifp0)));
		goto success;
	}

	/* try secondary EUI64 source. this basically is for ATM PVC */
	if (altifp && in6_iid_from_hw(altifp, in6) == 0) {
		nd6log((LOG_DEBUG, "%s: IID from alterate HW interface %s.\n",
		    if_name(ifp0), if_name(altifp)));
		goto success;
	}

	/* next, try to get it from some other hardware interface */
	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_list) {
		if (ifp == ifp0)
			continue;
		if (in6_iid_from_hw(ifp, in6) != 0)
			continue;

		/*
		 * to borrow IID from other interface, IID needs to be
		 * globally unique
		 */
		if (ND6_IFID_UNIVERSAL(in6)) {
			nd6log((LOG_DEBUG, "%s: borrowed IID from %s\n",
			    if_name(ifp0), if_name(ifp)));
			ifnet_head_done();
			goto success;
		}
	}
	ifnet_head_done();

	/* last resort: get from random number source */
	if (get_rand_iid(ifp, in6) == 0) {
		nd6log((LOG_DEBUG, "%s: IID from PRNG.\n", if_name(ifp0)));
		goto success;
	}

	printf("%s: failed to get interface identifier\n", if_name(ifp0));
	return (-1);

success:
	nd6log((LOG_INFO, "%s: IID: "
		"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
		if_name(ifp0),
		in6->s6_addr[8], in6->s6_addr[9],
		in6->s6_addr[10], in6->s6_addr[11],
		in6->s6_addr[12], in6->s6_addr[13],
		in6->s6_addr[14], in6->s6_addr[15]));
	return (0);
}

static int
in6_ifattach_linklocal(struct ifnet *ifp, struct in6_aliasreq *ifra)
{
	struct in6_ifaddr *ia;
	struct nd_prefix pr0, *pr;
	int i, error;

	VERIFY(ifra != NULL);

	proto_plumb(PF_INET6, ifp);

	error = in6_update_ifa(ifp, ifra, IN6_IFAUPDATE_DADDELAY, &ia);
	if (error != 0) {
		/*
		 * XXX: When the interface does not support IPv6, this call
		 * would fail in the SIOCSIFADDR ioctl.  I believe the
		 * notification is rather confusing in this case, so just
		 * suppress it.  (jinmei@kame.net 20010130)
		 */
		if (error != EAFNOSUPPORT)
			nd6log((LOG_NOTICE, "%s: failed to "
			    "configure a link-local address on %s "
			    "(errno=%d)\n",
			    __func__, if_name(ifp), error));
		return (EADDRNOTAVAIL);
	}
	VERIFY(ia != NULL);

	/*
	 * Make the link-local prefix (fe80::%link/64) as on-link.
	 * Since we'd like to manage prefixes separately from addresses,
	 * we make an ND6 prefix structure for the link-local prefix,
	 * and add it to the prefix list as a never-expire prefix.
	 * XXX: this change might affect some existing code base...
	 */
	bzero(&pr0, sizeof (pr0));
	lck_mtx_init(&pr0.ndpr_lock, ifa_mtx_grp, ifa_mtx_attr);
	pr0.ndpr_ifp = ifp;
	/* this should be 64 at this moment. */
	pr0.ndpr_plen = in6_mask2len(&ifra->ifra_prefixmask.sin6_addr, NULL);
	pr0.ndpr_mask = ifra->ifra_prefixmask.sin6_addr;
	pr0.ndpr_prefix = ifra->ifra_addr;
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
	pr0.ndpr_stateflags |= NDPRF_STATIC;
	/*
	 * Since there is no other link-local addresses, nd6_prefix_lookup()
	 * probably returns NULL.  However, we cannot always expect the result.
	 * For example, if we first remove the (only) existing link-local
	 * address, and then reconfigure another one, the prefix is still
	 * valid with referring to the old link-local address.
	 */
	if ((pr = nd6_prefix_lookup(&pr0)) == NULL) {
		if ((error = nd6_prelist_add(&pr0, NULL, &pr, TRUE)) != 0) {
			IFA_REMREF(&ia->ia_ifa);
			lck_mtx_destroy(&pr0.ndpr_lock, ifa_mtx_grp);
			return (error);
		}
	}

	in6_post_msg(ifp, KEV_INET6_NEW_LL_ADDR, ia, NULL);
	IFA_REMREF(&ia->ia_ifa);

	/* Drop use count held above during lookup/add */
	if (pr != NULL)
		NDPR_REMREF(pr);

	lck_mtx_destroy(&pr0.ndpr_lock, ifa_mtx_grp);
	return (0);
}

static int
in6_ifattach_loopback(
	struct ifnet *ifp)	/* must be IFT_LOOP */
{
	struct in6_aliasreq ifra;
	struct in6_ifaddr *ia;
	int error;

	bzero(&ifra, sizeof (ifra));

	/*
	 * in6_update_ifa() does not use ifra_name, but we accurately set it
	 * for safety.
	 */
	strlcpy(ifra.ifra_name, if_name(ifp), sizeof (ifra.ifra_name));

	ifra.ifra_prefixmask.sin6_len = sizeof (struct sockaddr_in6);
	ifra.ifra_prefixmask.sin6_family = AF_INET6;
	ifra.ifra_prefixmask.sin6_addr = in6mask128;

	/*
	 * Always initialize ia_dstaddr (= broadcast address) to loopback
	 * address.  Follows IPv4 practice - see in_ifinit().
	 */
	ifra.ifra_dstaddr.sin6_len = sizeof (struct sockaddr_in6);
	ifra.ifra_dstaddr.sin6_family = AF_INET6;
	ifra.ifra_dstaddr.sin6_addr = in6addr_loopback;

	ifra.ifra_addr.sin6_len = sizeof (struct sockaddr_in6);
	ifra.ifra_addr.sin6_family = AF_INET6;
	ifra.ifra_addr.sin6_addr = in6addr_loopback;

	/* the loopback  address should NEVER expire. */
	ifra.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
	ifra.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

	/* we don't need to perform DAD on loopback interfaces. */
	ifra.ifra_flags |= IN6_IFF_NODAD;

	/* add the new interface address */
	error = in6_update_ifa(ifp, &ifra, 0, &ia);
	if (error != 0) {
		nd6log((LOG_ERR,
		    "%s: failed to configure loopback address %s (error=%d)\n",
		    __func__, if_name(ifp), error));
		VERIFY(ia == NULL);
		return (EADDRNOTAVAIL);
	}

	VERIFY(ia != NULL);
	IFA_REMREF(&ia->ia_ifa);
	return (0);
}

/*
 * compute NI group address, based on the current hostname setting.
 * see RFC 4620.
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
	SHA1_CTX ctxt;
	u_int8_t digest[SHA1_RESULTLEN];
	char l;
	char n[64];	/* a single label must not exceed 63 chars */

	if (!namelen || !name)
		return (-1);

	p = name;
	while (p && *p && *p != '.' && p - name < namelen)
		p++;
	if (p - name > sizeof (n) - 1)
		return (-1);	/* label too long */
	l = p - name;
	strlcpy(n, name, l);
	n[(int)l] = '\0';
	for (q = (u_char *) n; *q; q++) {
		if ('A' <= *q && *q <= 'Z')
			*q = *q - 'A' + 'a';
	}

	/* generate 16 bytes of pseudo-random value. */
	bzero(&ctxt, sizeof (ctxt));
	SHA1Init(&ctxt);
	SHA1Update(&ctxt, &l, sizeof (l));
	SHA1Update(&ctxt, n, l);
	SHA1Final(digest, &ctxt);

	bzero(in6, sizeof (*in6));
	in6->s6_addr16[0] = IPV6_ADDR_INT16_MLL;
	in6->s6_addr8[11] = 2;
	in6->s6_addr8[12] = 0xff;
	/* copy first 3 bytes of prefix into address */
	bcopy(digest, &in6->s6_addr8[13], 3);
	if (in6_setscope(in6, ifp, NULL))
		return (-1); /* XXX: should not fail */

	return (0);
}

int
in6_domifattach(struct ifnet *ifp)
{
	int error;

	VERIFY(ifp != NULL);

	error = proto_plumb(PF_INET6, ifp);
	if (error != 0) {
		if (error != EEXIST)
			log(LOG_ERR, "%s: proto_plumb returned %d if=%s\n",
			    __func__, error, if_name(ifp));
	} else {
		error = in6_ifattach_prelim(ifp);
		if (error != 0) {
			int errorx;

			log(LOG_ERR,
			    "%s: in6_ifattach_prelim returned %d if=%s%d\n",
			    __func__, error, ifp->if_name, ifp->if_unit);

			errorx = proto_unplumb(PF_INET6, ifp);
			if (errorx != 0) /* XXX should not fail */
				log(LOG_ERR,
				    "%s: proto_unplumb returned %d if=%s%d\n",
				    __func__, errorx, ifp->if_name,
				    ifp->if_unit);
		}
	}

	return (error);
}

int
in6_ifattach_prelim(struct ifnet *ifp)
{
	struct in6_ifextra *ext;
	void **pbuf, *base;
	int error = 0;

	VERIFY(ifp != NULL);

	/* quirks based on interface type */
	switch (ifp->if_type) {
#if IFT_STF
	case IFT_STF:
		/*
		 * 6to4 interface is a very special kind of beast.
		 * no multicast, no linklocal.  RFC2529 specifies how to make
		 * linklocals for 6to4 interface, but there's no use and
		 * it is rather harmful to have one.
		 */
		goto skipmcast;
#endif
	default:
		break;
	}

	/*
	 * IPv6 requires multicast capability at the interface.
	 *   (previously, this was a silent error.)
	 */
	if ((ifp->if_flags & IFF_MULTICAST) == 0) {
		nd6log((LOG_INFO, "in6_ifattach: ",
		    "%s is not multicast capable, IPv6 not enabled\n",
		    if_name(ifp)));
		return (EINVAL);
	}

#if IFT_STF
skipmcast:
#endif

	if (ifp->if_inet6data == NULL) {
		ext = (struct in6_ifextra *)_MALLOC(in6_extra_size, M_IFADDR,
		    M_WAITOK|M_ZERO);
		if (!ext)
			return (ENOMEM);
		base = (void *)P2ROUNDUP((intptr_t)ext + sizeof(uint64_t),
		    sizeof(uint64_t));
		VERIFY(((intptr_t)base + in6_extra_size) <= 
		    ((intptr_t)ext + in6_extra_bufsize));
		pbuf = (void **)((intptr_t)base - sizeof(void *));
		*pbuf = ext;
		ifp->if_inet6data = base;
		VERIFY(IS_P2ALIGNED(ifp->if_inet6data, sizeof(uint64_t)));
	} else {
		/*
		 * Since the structure is never freed, we need to zero out 
		 * some of its members. We avoid zeroing out the scope6
		 * structure on purpose because other threads might be
		 * using its contents.
		 */
		bzero(&IN6_IFEXTRA(ifp)->icmp6_ifstat,
		    sizeof(IN6_IFEXTRA(ifp)->icmp6_ifstat));
		bzero(&IN6_IFEXTRA(ifp)->in6_ifstat,
		    sizeof(IN6_IFEXTRA(ifp)->in6_ifstat));
	}

	/* initialize NDP variables */
	if ((error = nd6_ifattach(ifp)) != 0)
		return (error);

	scope6_ifattach(ifp);

	/* initialize loopback interface address */
	if ((ifp->if_flags & IFF_LOOPBACK) != 0) {
		error = in6_ifattach_loopback(ifp);
		if (error != 0) {
			log(LOG_ERR, "%s: in6_ifattach_loopback returned %d\n",
			    __func__, error, ifp->if_name,
			    ifp->if_unit);
			return (error);
		}
	}

	/* update dynamically. */
	if (in6_maxmtu < ifp->if_mtu)
		in6_maxmtu = ifp->if_mtu;

	VERIFY(error == 0);
	return (0);
}

int
in6_ifattach_aliasreq(struct ifnet *ifp, struct ifnet *altifp,
    struct in6_aliasreq *ifra0)
{
	int error;
	struct in6_ifaddr *ia6;
	struct in6_aliasreq ifra;

	error = in6_ifattach_prelim(ifp);
	if (error != 0)
		return (error);

	if (!ip6_auto_linklocal)
		return (0);

	/* assign a link-local address, only if there isn't one here already. */
	ia6 = in6ifa_ifpforlinklocal(ifp, 0);
	if (ia6 != NULL) {
		IFA_REMREF(&ia6->ia_ifa);
		return (0);
	}

	bzero(&ifra, sizeof (ifra));

	/*
	 * in6_update_ifa() does not use ifra_name, but we accurately set it
	 * for safety.
	 */
	strlcpy(ifra.ifra_name, if_name(ifp), sizeof (ifra.ifra_name));

	/* Initialize the IPv6 interface address in our in6_aliasreq block */
	if ((ifp->if_eflags & IFEF_NOAUTOIPV6LL) != 0 && ifra0 != NULL) {
		/* interface provided both addresses for us */
		struct sockaddr_in6 *sin6 = &ifra.ifra_addr;
		struct in6_addr *in6 = &sin6->sin6_addr;
		boolean_t ok = TRUE;

		bcopy(&ifra0->ifra_addr, sin6, sizeof (struct sockaddr_in6));

		if (sin6->sin6_family != AF_INET6 || sin6->sin6_port != 0)
			ok = FALSE;
		if (ok && (in6->s6_addr16[0] != htons(0xfe80)))
			ok = FALSE;
		if (ok) {
			if (sin6->sin6_scope_id == 0 && in6->s6_addr16[1] == 0)
				in6->s6_addr16[1] = htons(ifp->if_index);
			else if (sin6->sin6_scope_id != 0 &&
			    sin6->sin6_scope_id != ifp->if_index)
				ok = FALSE;
			else if (in6->s6_addr16[1] != 0 &&
			    ntohs(in6->s6_addr16[1]) != ifp->if_index)
				ok = FALSE;
		}
		if (ok && (in6->s6_addr32[1] != 0))
			ok = FALSE;
		if (!ok)
			return (EINVAL);
	} else {
		ifra.ifra_addr.sin6_family = AF_INET6;
		ifra.ifra_addr.sin6_len = sizeof (struct sockaddr_in6);
		ifra.ifra_addr.sin6_addr.s6_addr16[0] = htons(0xfe80);
		ifra.ifra_addr.sin6_addr.s6_addr16[1] = htons(ifp->if_index);
		ifra.ifra_addr.sin6_addr.s6_addr32[1] = 0;
		if ((ifp->if_flags & IFF_LOOPBACK) != 0) {
			ifra.ifra_addr.sin6_addr.s6_addr32[2] = 0;
			ifra.ifra_addr.sin6_addr.s6_addr32[3] = htonl(1);
		} else {
			if (in6_select_iid_from_all_hw(ifp, altifp,
			    &ifra.ifra_addr.sin6_addr) != 0) {
				nd6log((LOG_ERR, "%s: no IID available\n",
				    if_name(ifp)));
				return (EADDRNOTAVAIL);
			}
		}
	}

	if (in6_setscope(&ifra.ifra_addr.sin6_addr, ifp, NULL))
		return (EADDRNOTAVAIL);

	/* Set the prefix mask */
	ifra.ifra_prefixmask.sin6_len = sizeof (struct sockaddr_in6);
	ifra.ifra_prefixmask.sin6_family = AF_INET6;
	ifra.ifra_prefixmask.sin6_addr = in6mask64;

	/* link-local addresses should NEVER expire. */
	ifra.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
	ifra.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

	/* Attach the link-local address */
	if (in6_ifattach_linklocal(ifp, &ifra) != 0) {
		nd6log((LOG_INFO,
		    "%s: %s could not attach link-local address.\n",
		    __func__, if_name(ifp)));
		/* NB: not an error */
	}

	return (0);
}

int
in6_ifattach_llstartreq(struct ifnet *ifp, struct in6_llstartreq *llsr)
{
	struct in6_aliasreq ifra;
	struct in6_ifaddr *ia6;
	struct nd_ifinfo *ndi;
	int error;

	VERIFY(llsr != NULL);

	error = in6_ifattach_prelim(ifp);
	if (error != 0)
		return (error);

	if (!ip6_auto_linklocal || (ifp->if_eflags & IFEF_NOAUTOIPV6LL) != 0)
		return (0);

	if (nd6_send_opstate == ND6_SEND_OPMODE_DISABLED)
		return (ENXIO);

	lck_rw_lock_shared(nd_if_rwlock);
	ndi = ND_IFINFO(ifp);
	VERIFY(ndi != NULL && ndi->initialized);
	if ((ndi->flags & ND6_IFF_INSECURE) != 0) {
		lck_rw_done(nd_if_rwlock);
		return (ENXIO);
	}
	lck_rw_done(nd_if_rwlock);

	/* assign a link-local address, only if there isn't one here already. */
	ia6 = in6ifa_ifpforlinklocal(ifp, 0);
	if (ia6 != NULL) {
		IFA_REMREF(&ia6->ia_ifa);
		return (0);
	}

	bzero(&ifra, sizeof (ifra));
	strlcpy(ifra.ifra_name, if_name(ifp), sizeof (ifra.ifra_name));

	ifra.ifra_addr.sin6_family = AF_INET6;
	ifra.ifra_addr.sin6_len = sizeof (struct sockaddr_in6);
	ifra.ifra_addr.sin6_addr.s6_addr16[0] = htons(0xfe80);
	ifra.ifra_addr.sin6_addr.s6_addr16[1] = htons(ifp->if_index);
	ifra.ifra_addr.sin6_addr.s6_addr32[1] = 0;
	ifra.ifra_flags = IN6_IFF_SECURED;

	in6_cga_node_lock();
	if (in6_cga_generate(&llsr->llsr_cgaprep, 0,
	    &ifra.ifra_addr.sin6_addr)) {
		in6_cga_node_unlock();
		return (EADDRNOTAVAIL);
	}
	in6_cga_node_unlock();

	if (in6_setscope(&ifra.ifra_addr.sin6_addr, ifp, NULL))
		return (EADDRNOTAVAIL);

	/* Set the prefix mask */
	ifra.ifra_prefixmask.sin6_len = sizeof (struct sockaddr_in6);
	ifra.ifra_prefixmask.sin6_family = AF_INET6;
	ifra.ifra_prefixmask.sin6_addr = in6mask64;

	/*
	 * link-local addresses should NEVER expire, but cryptographic
	 * ones may have finite preferred lifetime [if it's important to
	 * keep them from being used by applications as persistent device
	 * identifiers].
	 */
	ifra.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
	ifra.ifra_lifetime.ia6t_pltime = llsr->llsr_lifetime.ia6t_pltime;

	/* Attach the link-local address */
	if (in6_ifattach_linklocal(ifp, &ifra) != 0) {
		/* NB: not an error */
		nd6log((LOG_INFO,
		    "%s: %s could not attach link-local address.\n",
		    __func__, if_name(ifp)));
	}

	VERIFY(error == 0);
	return (error);
}

/*
 * NOTE: in6_ifdetach() does not support loopback if at this moment.
 */
void
in6_ifdetach(struct ifnet *ifp)
{
	struct in6_ifaddr *ia, *oia;
	struct ifaddr *ifa;
	struct rtentry *rt;
	struct sockaddr_in6 sin6;
	struct in6_multi_mship *imm;
	int unlinked;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_NOTOWNED);

	/* remove neighbor management table */
	nd6_purge(ifp);

	/* nuke any of IPv6 addresses we have */
	lck_rw_lock_exclusive(&in6_ifaddr_rwlock);
	ia = in6_ifaddrs;
	while (ia != NULL) {
		if (ia->ia_ifa.ifa_ifp != ifp) {
			ia = ia->ia_next;
			continue;
		}
		IFA_ADDREF(&ia->ia_ifa);	/* for us */
		lck_rw_done(&in6_ifaddr_rwlock);
		in6_purgeaddr(&ia->ia_ifa);
		IFA_REMREF(&ia->ia_ifa);	/* for us */
		lck_rw_lock_exclusive(&in6_ifaddr_rwlock);
		/*
		 * Purging the address caused in6_ifaddr_rwlock
		 * to be dropped and reacquired;
		 * therefore search again from the beginning
		 * of in6_ifaddrs list.
		 */
		ia = in6_ifaddrs;
	}
	lck_rw_done(&in6_ifaddr_rwlock);

	ifnet_lock_exclusive(ifp);

	/* undo everything done by in6_ifattach(), just in case */
	ifa = TAILQ_FIRST(&ifp->if_addrlist);
	while (ifa != NULL) {
		IFA_LOCK(ifa);
		if (ifa->ifa_addr->sa_family != AF_INET6 ||
		    !IN6_IS_ADDR_LINKLOCAL(&satosin6(&ifa->ifa_addr)->
		    sin6_addr)) {
			IFA_UNLOCK(ifa);
			ifa = TAILQ_NEXT(ifa, ifa_list);
			continue;
		}

		ia = (struct in6_ifaddr *)ifa;

		/* hold a reference for this routine */
		IFA_ADDREF_LOCKED(ifa);
		/* remove from the linked list */
		if_detach_ifa(ifp, ifa);
		IFA_UNLOCK(ifa);

		/*
		 * Leaving the multicast group(s) may involve freeing the
		 * link address multicast structure(s) for the interface,
		 * which is protected by ifnet lock.  To avoid violating
		 * lock ordering, we must drop ifnet lock before doing so.
		 * The ifa won't go away since we held a refcnt above.
		 */
		ifnet_lock_done(ifp);

		/*
		 * We have to do this work manually here instead of calling
		 * in6_purgeaddr() since in6_purgeaddr() uses the RTM_HOST flag.
		 */

		/*
		 * leave from multicast groups we have joined for the interface
		 */
		IFA_LOCK(ifa);
		while ((imm = ia->ia6_memberships.lh_first) != NULL) {
			LIST_REMOVE(imm, i6mm_chain);
			IFA_UNLOCK(ifa);
			in6_leavegroup(imm);
			IFA_LOCK(ifa);
		}

		/* remove from the routing table */
		if (ia->ia_flags & IFA_ROUTE) {
			IFA_UNLOCK(ifa);
			rt = rtalloc1((struct sockaddr *)&ia->ia_addr, 0, 0);
			if (rt != NULL) {
				(void) rtrequest(RTM_DELETE,
					(struct sockaddr *)&ia->ia_addr,
					(struct sockaddr *)&ia->ia_addr,
					(struct sockaddr *)&ia->ia_prefixmask,
					rt->rt_flags, (struct rtentry **)0);
				rtfree(rt);
			}
		} else {
			IFA_UNLOCK(ifa);
		}

		/* also remove from the IPv6 address chain(itojun&jinmei) */
		unlinked = 1;
		oia = ia;
		lck_rw_lock_exclusive(&in6_ifaddr_rwlock);
		if (oia == (ia = in6_ifaddrs)) {
			in6_ifaddrs = ia->ia_next;
		} else {
			while (ia->ia_next && (ia->ia_next != oia))
				ia = ia->ia_next;
			if (ia->ia_next) {
				ia->ia_next = oia->ia_next;
			} else {
				nd6log((LOG_ERR,
				    "%s: didn't unlink in6ifaddr from "
				    "list\n", if_name(ifp)));
				unlinked = 0;
			}
		}
		lck_rw_done(&in6_ifaddr_rwlock);

		ifa = &oia->ia_ifa;
		/*
		 * release another refcnt for the link from in6_ifaddrs.
		 * Do this only if it's not already unlinked in the event
		 * that we lost the race, since in6_ifaddr_rwlock was
		 * momentarily dropped above.
		 */
		if (unlinked)
			IFA_REMREF(ifa);
		/* release reference held for this routine */
		IFA_REMREF(ifa);

		/*
		 * This is suboptimal, but since we dropped ifnet lock above
		 * the list might have changed.  Repeat the search from the
		 * beginning until we find the first eligible IPv6 address.
		 */
		ifnet_lock_exclusive(ifp);
		ifa = TAILQ_FIRST(&ifp->if_addrlist);
	}
	ifnet_lock_done(ifp);

	/* invalidate route caches */
	routegenid_inet6_update();

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
	bzero(&sin6, sizeof (sin6));
	sin6.sin6_len = sizeof (struct sockaddr_in6);
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
in6_iid_mktmp(struct ifnet *ifp, u_int8_t *retbuf, const u_int8_t *baseid,
    int generate)
{
	u_int8_t nullbuf[8];
	struct nd_ifinfo *ndi;

	lck_rw_lock_shared(nd_if_rwlock);
	ndi = ND_IFINFO(ifp);
	VERIFY(ndi != NULL && ndi->initialized);
	lck_mtx_lock(&ndi->lock);
	bzero(nullbuf, sizeof (nullbuf));
	if (bcmp(ndi->randomid, nullbuf, sizeof (nullbuf)) == 0) {
		/* we've never created a random ID.  Create a new one. */
		generate = 1;
	}

	if (generate) {
		bcopy(baseid, ndi->randomseed1, sizeof (ndi->randomseed1));

		/* in6_generate_tmp_iid will update seedn and buf */
		(void) in6_generate_tmp_iid(ndi->randomseed0, ndi->randomseed1,
		    ndi->randomid);
	}

	bcopy(ndi->randomid, retbuf, 8);
	lck_mtx_unlock(&ndi->lock);
	lck_rw_done(nd_if_rwlock);
}

void
in6_tmpaddrtimer(void *arg)
{
#pragma unused(arg)
	int i;
	struct nd_ifinfo *ndi;
	u_int8_t nullbuf[8];

	timeout(in6_tmpaddrtimer, (caddr_t)0, (ip6_temp_preferred_lifetime -
	    ip6_desync_factor - ip6_temp_regen_advance) * hz);

	lck_rw_lock_shared(nd_if_rwlock);
	bzero(nullbuf, sizeof (nullbuf));
	for (i = 1; i < if_index + 1; i++) {
		if (!nd_ifinfo || i >= nd_ifinfo_indexlim)
			break;
		ndi = &nd_ifinfo[i];
		if (!ndi->initialized)
			continue;
		lck_mtx_lock(&ndi->lock);
		if (bcmp(ndi->randomid, nullbuf, sizeof (nullbuf)) != 0) {
			/*
			 * We've been generating a random ID on this interface.
			 * Create a new one.
			 */
			(void) in6_generate_tmp_iid(ndi->randomseed0,
			    ndi->randomseed1, ndi->randomid);
		}
		lck_mtx_unlock(&ndi->lock);
	}
	lck_rw_done(nd_if_rwlock);
}
