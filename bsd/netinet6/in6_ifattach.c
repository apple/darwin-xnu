/*	$KAME: in6_ifattach.c,v 1.41 2000/03/16 07:05:34 jinmei Exp $	*/

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
#include <sys/sockio.h>
#include <sys/kernel.h>
#ifdef __bsdi__
#include <crypto/md5.h>
#elif defined(__OpenBSD__)
#include <sys/md5k.h>
#else
#include <sys/md5.h>
#endif

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#ifndef __NetBSD__
#include <netinet/if_ether.h>
#endif

#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_ifattach.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>

#include <net/net_osdep.h>

static	struct in6_addr llsol;

struct in6_ifstat **in6_ifstat = NULL;
struct icmp6_ifstat **icmp6_ifstat = NULL;
size_t in6_ifstatmax = 0;
size_t icmp6_ifstatmax = 0;
unsigned long in6_maxmtu = 0;

int found_first_ifid = 0;
#define IFID_LEN 8
static u_int8_t first_ifid[IFID_LEN];

static int laddr_to_eui64 __P((u_int8_t *, u_int8_t *, size_t));
static int gen_rand_eui64 __P((u_int8_t *));

#define DEBUG 1

static int
laddr_to_eui64(dst, src, len)
	u_int8_t *dst;
	u_int8_t *src;
	size_t len;
{
	static u_int8_t zero[8];

	bzero(zero, sizeof(zero));

	switch (len) {
	case 6:
		if (bcmp(zero, src, 6) == 0)
			return EINVAL;
		dst[0] = src[0];
		dst[1] = src[1];
		dst[2] = src[2];
		dst[3] = 0xff;
		dst[4] = 0xfe;
		dst[5] = src[3];
		dst[6] = src[4];
		dst[7] = src[5];
		break;
	case 8:
		if (bcmp(zero, src, 8) == 0)
			return EINVAL;
		bcopy(src, dst, len);
		break;
	default:
		return EINVAL;
	}

	return 0;
}

/*
 * Generate a last-resort interface identifier, when the machine has no
 * IEEE802/EUI64 address sources.
 * The address should be random, and should not change across reboot.
 */
static int
gen_rand_eui64(dst)
	u_int8_t *dst;
{
	MD5_CTX ctxt;
	u_int8_t digest[16];
#if defined(__FreeBSD__) || defined (__APPLE__)
	int hostnamelen	= strlen(hostname);
#endif

	/* generate 8bytes of pseudo-random value. */
	bzero(&ctxt, sizeof(ctxt));
	MD5Init(&ctxt);
	MD5Update(&ctxt, hostname, hostnamelen);
	MD5Final(digest, &ctxt);

	/* assumes sizeof(digest) > sizeof(first_ifid) */
	bcopy(digest, dst, 8);

	/* make sure to set "u" bit to local, and "g" bit to individual. */
	dst[0] &= 0xfe;
	dst[0] |= 0x02;		/* EUI64 "local" */

	return 0;
}

/*
 * Find first ifid on list of interfaces.
 * This is assumed that ifp0's interface token (for example, IEEE802 MAC)
 * is globally unique.  We may need to have a flag parameter in the future.
 */
int
in6_ifattach_getifid(ifp0)
	struct ifnet *ifp0;
{
	struct ifnet *ifp;
	struct ifaddr *ifa;
	u_int8_t *addr = NULL;
	int addrlen = 0;
	struct sockaddr_dl *sdl;

	if (found_first_ifid)
		return 0;

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	for (ifp = ifnet; ifp; ifp = ifp->if_next)
#else
	for (ifp = ifnet.tqh_first; ifp; ifp = ifp->if_list.tqe_next)
#endif
	{
		if (ifp0 != NULL && ifp0 != ifp)
			continue;
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
		for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
#else
		for (ifa = ifp->if_addrlist.tqh_first;
		     ifa;
		     ifa = ifa->ifa_list.tqe_next)
#endif
		{
			if (ifa->ifa_addr->sa_family != AF_LINK)
				continue;
			sdl = (struct sockaddr_dl *)ifa->ifa_addr;
			if (sdl == NULL)
				continue;
			if (sdl->sdl_alen == 0)
				continue;
			switch (ifp->if_type) {
			case IFT_ETHER:
			case IFT_FDDI:
			case IFT_ATM:
				/* IEEE802/EUI64 cases - what others? */
				addr = LLADDR(sdl);
				addrlen = sdl->sdl_alen;
				/*
				 * to copy ifid from IEEE802/EUI64 interface,
				 * u bit of the source needs to be 0.
				 */
				if ((addr[0] & 0x02) != 0)
					break;
				goto found;
			case IFT_ARCNET:
				/*
				 * ARCnet interface token cannot be used as
				 * globally unique identifier due to its
				 * small bitwidth.
				 */
				break;
			default:
				break;
			}
		}
	}
#if DEBUG
	printf("in6_ifattach_getifid: failed to get EUI64");
#endif
	return EADDRNOTAVAIL;

found:
	if (laddr_to_eui64(first_ifid, addr, addrlen) == 0)
		found_first_ifid = 1;

	if (found_first_ifid) {
		printf("%s: supplying EUI64: "
			"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
			if_name(ifp),
			first_ifid[0] & 0xff, first_ifid[1] & 0xff,
			first_ifid[2] & 0xff, first_ifid[3] & 0xff,
			first_ifid[4] & 0xff, first_ifid[5] & 0xff,
			first_ifid[6] & 0xff, first_ifid[7] & 0xff);

		/* invert u bit to convert EUI64 to RFC2373 interface ID. */
		first_ifid[0] ^= 0x02;

		return 0;
	} else {
#if DEBUG
		printf("in6_ifattach_getifid: failed to get EUI64");
#endif
		return EADDRNOTAVAIL;
	}
}

/*
 * XXX multiple loopback interface needs more care.  for instance,
 * nodelocal address needs to be configured onto only one of them.
 */
void
in6_ifattach(ifp, type, laddr, noloop)
	struct ifnet *ifp;
	u_int type;
	caddr_t laddr;
	/* size_t laddrlen; */
	int noloop;
{
	static size_t if_indexlim = 8;
	struct sockaddr_in6 mltaddr;
	struct sockaddr_in6 mltmask;
	struct sockaddr_in6 gate;
	struct sockaddr_in6 mask;
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	struct ifaddr **ifap;
#endif

	struct in6_ifaddr *ia, *ib, *oia;
	struct ifaddr *ifa;
	int rtflag = 0;
	int s;
	int error;

	if (type == IN6_IFT_P2P && found_first_ifid == 0) {
		printf("%s: no ifid available for IPv6 link-local address\n",
			if_name(ifp));
#if 0
		return;
#else
		/* last resort */
		if (gen_rand_eui64(first_ifid) == 0) {
			printf("%s: using random value as EUI64: "
				"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
				if_name(ifp),
				first_ifid[0] & 0xff, first_ifid[1] & 0xff,
				first_ifid[2] & 0xff, first_ifid[3] & 0xff,
				first_ifid[4] & 0xff, first_ifid[5] & 0xff,
				first_ifid[6] & 0xff, first_ifid[7] & 0xff);
			/*
			 * invert u bit to convert EUI64 to RFC2373 interface
			 * ID.
			 */
			first_ifid[0] ^= 0x02;

			found_first_ifid = 1;
		}
#endif
	}

	if ((ifp->if_flags & IFF_MULTICAST) == 0) {
		printf("%s: not multicast capable, IPv6 not enabled\n",
			if_name(ifp));
		return;
	}

	/*
	 * We have some arrays that should be indexed by if_index.
	 * since if_index will grow dynamically, they should grow too.
	 *	struct in6_ifstat **in6_ifstat
	 *	struct icmp6_ifstat **icmp6_ifstat
	 */
	if (in6_ifstat == NULL || icmp6_ifstat == NULL
	 || if_index >= if_indexlim) {
		size_t n;
		caddr_t q;
		size_t olim;

		olim = if_indexlim;
		while (if_index >= if_indexlim)
			if_indexlim <<= 1;

		/* grow in6_ifstat */
		n = if_indexlim * sizeof(struct in6_ifstat *);
		q = (caddr_t)_MALLOC(n, M_IFADDR, M_WAITOK);
		bzero(q, n);
		if (in6_ifstat) {
			bcopy((caddr_t)in6_ifstat, q,
				olim * sizeof(struct in6_ifstat *));
			_FREE((caddr_t)in6_ifstat, M_IFADDR);
		}
		in6_ifstat = (struct in6_ifstat **)q;
		in6_ifstatmax = if_indexlim;

		/* grow icmp6_ifstat */
		n = if_indexlim * sizeof(struct icmp6_ifstat *);
		q = (caddr_t)_MALLOC(n, M_IFADDR, M_WAITOK);
		bzero(q, n);
		if (icmp6_ifstat) {
			bcopy((caddr_t)icmp6_ifstat, q,
				olim * sizeof(struct icmp6_ifstat *));
			_FREE((caddr_t)icmp6_ifstat, M_IFADDR);
		}
		icmp6_ifstat = (struct icmp6_ifstat **)q;
		icmp6_ifstatmax = if_indexlim;
	}

	/*
	 * To prevent to assign link-local address to PnP network
	 * cards multiple times.
	 * This is lengthy for P2P and LOOP but works.
	 */
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	ifa = ifp->if_addrlist;
	if (ifa != NULL) {
		for ( ; ifa; ifa = ifa->ifa_next) {
			ifap = &ifa->ifa_next;
			if (ifa->ifa_addr->sa_family != AF_INET6)
				continue;
			if (IN6_IS_ADDR_LINKLOCAL(&satosin6(ifa->ifa_addr)->sin6_addr))
				return;
		}
	} else
		ifap = &ifp->if_addrlist;
#else
	ifa = TAILQ_FIRST(&ifp->if_addrlist);
	if (ifa != NULL) {
		for ( ; ifa; ifa = TAILQ_NEXT(ifa, ifa_list)) {
			if (ifa->ifa_addr->sa_family != AF_INET6)
				continue;
			if (IN6_IS_ADDR_LINKLOCAL(&satosin6(ifa->ifa_addr)->sin6_addr))
				return;
		}
	} else {
		TAILQ_INIT(&ifp->if_addrlist);
	}
#endif

	/*
	 * link-local address
	 */
	ia = (struct in6_ifaddr *)_MALLOC(sizeof(*ia), M_IFADDR, M_WAITOK);
	bzero((caddr_t)ia, sizeof(*ia));
	ia->ia_ifa.ifa_addr =    (struct sockaddr *)&ia->ia_addr;
	if (ifp->if_flags & IFF_POINTOPOINT)
		ia->ia_ifa.ifa_dstaddr = (struct sockaddr *)&ia->ia_dstaddr;
	else
		ia->ia_ifa.ifa_dstaddr = NULL;
	ia->ia_ifa.ifa_netmask = (struct sockaddr *)&ia->ia_prefixmask;
	ia->ia_ifp = ifp;
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	*ifap = (struct ifaddr *)ia;
#else
	TAILQ_INSERT_TAIL(&ifp->if_addrlist, (struct ifaddr *)ia, ifa_list);
#endif
	ia->ia_ifa.ifa_refcnt++;

	/*
	 * Also link into the IPv6 address chain beginning with in6_ifaddr.
	 * kazu opposed it, but itojun & jinmei wanted.
	 */
	if ((oia = in6_ifaddr) != NULL) {
		for (; oia->ia_next; oia = oia->ia_next)
			continue;
		oia->ia_next = ia;
	} else
		in6_ifaddr = ia;
	ia->ia_ifa.ifa_refcnt++;

	ia->ia_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
	ia->ia_prefixmask.sin6_family = AF_INET6;
	ia->ia_prefixmask.sin6_addr = in6mask64;

	bzero(&ia->ia_addr, sizeof(struct sockaddr_in6));
	ia->ia_addr.sin6_len = sizeof(struct sockaddr_in6);
	ia->ia_addr.sin6_family = AF_INET6;
	ia->ia_addr.sin6_addr.s6_addr16[0] = htons(0xfe80);
	ia->ia_addr.sin6_addr.s6_addr16[1] = htons(ifp->if_index);
	ia->ia_addr.sin6_addr.s6_addr32[1] = 0;

	switch (type) {
	case IN6_IFT_LOOP:
		ia->ia_addr.sin6_addr.s6_addr32[2] = 0;
		ia->ia_addr.sin6_addr.s6_addr32[3] = htonl(1);
                if (strcmp(ifp->if_name, "lo") == 0) {
                        ia->ia_ifa.ifa_dlt = lo_attach_inet(ifp);
	           	printf("in6_ifattach: IFT_LOOP setting initial ifp=%s%d initial ia=%x ifa_dlt=%x\n",
			 ifp->if_name, ifp->if_unit, ia, ia->ia_ifa.ifa_dlt);
		}
		break;
	case IN6_IFT_802:
		ia->ia_ifa.ifa_rtrequest = nd6_rtrequest;
		ia->ia_ifa.ifa_flags |= RTF_CLONING;
		rtflag = RTF_CLONING;
                 if (strcmp(ifp->if_name, "en") == 0) {
                   	ia->ia_ifa.ifa_dlt = ether_attach_inet6(ifp);
	           	printf("in6_ifattach: IFT_802 setting initial ifp=%s%d initial ia=%x ifa_dlt=%x\n",
				 ifp->if_name, ifp->if_unit, ia, ia->ia_ifa.ifa_dlt);
		 }

		/* fall through */
	case IN6_IFT_P2P802:
		ia->ia_ifa.ifa_rtrequest = nd6_rtrequest;
		ia->ia_ifa.ifa_flags |= RTF_CLONING;
		rtflag = RTF_CLONING;
		if (laddr == NULL)
			break;
		/* XXX use laddrlen */
		if (laddr_to_eui64(&ia->ia_addr.sin6_addr.s6_addr8[8],
				laddr, 6) != 0) {
			break;
		}
		/* invert u bit to convert EUI64 to RFC2373 interface ID. */
		ia->ia_addr.sin6_addr.s6_addr8[8] ^= 0x02;
		if (found_first_ifid == 0)
			in6_ifattach_getifid(ifp);
		bzero(&ia->ia_dstaddr, sizeof(struct sockaddr_in6));
		ia->ia_dstaddr.sin6_len = sizeof(struct sockaddr_in6);
		ia->ia_dstaddr.sin6_family = AF_INET6;

		if (ia->ia_ifa.ifa_dlt == 0) {
                	ia->ia_ifa.ifa_dlt = ifp;
#if DEBUG
	         	printf("in6_ifattach: IFT_P2P802 setting initial ifp=%s%d initial ia=%x ifa_dlt=%x\n",
				 ifp->if_name, ifp->if_unit, ia, ia->ia_ifa.ifa_dlt);
#endif
		}
		break;
	case IN6_IFT_P2P:
		ia->ia_ifa.ifa_rtrequest = nd6_rtrequest;
		ia->ia_ifa.ifa_flags |= RTF_CLONING;
		rtflag = RTF_CLONING;
		bcopy((caddr_t)first_ifid,
		      (caddr_t)&ia->ia_addr.sin6_addr.s6_addr8[8],
		      IFID_LEN);
		bzero(&ia->ia_dstaddr, sizeof(struct sockaddr_in6));
		ia->ia_dstaddr.sin6_len = sizeof(struct sockaddr_in6);
		ia->ia_dstaddr.sin6_family = AF_INET6;
#if NGIF > 0
                 if (strcmp(ifp->if_name, "gif") == 0) {
                   	ia->ia_ifa.ifa_dlt = gif_attach_inet(ifp);
#if DEBUG
	           	printf("in6_ifattach: IFT_P2P setting initial ifp=%s%d initial ia=%x ifa_dlt=%x\n",
				 ifp->if_name, ifp->if_unit, ia, ia->ia_ifa.ifa_dlt);
#endif
		 }
#endif
		break;
	case IN6_IFT_ARCNET:
		ia->ia_ifa.ifa_rtrequest = nd6_rtrequest;
		ia->ia_ifa.ifa_flags |= RTF_CLONING;
		rtflag = RTF_CLONING;
		if (laddr == NULL)
			break;

		/* make non-global IF id out of link-level address */
		bzero(&ia->ia_addr.sin6_addr.s6_addr8[8], 7);
		ia->ia_addr.sin6_addr.s6_addr8[15] = *laddr;
                ia->ia_ifa.ifa_dlt = ifp;
#if DEBUG
	        printf("in6_ifattach: IFT_ARCNET setting initial ifp=%s%d initial ia=%x ifa_dlt=%x\n",
			 ifp->if_name, ifp->if_unit, ia, ia->ia_ifa.ifa_dlt);
#endif
	}

	ia->ia_ifa.ifa_metric = ifp->if_metric;


	/*
	 * give the interface a chance to initialize, in case this
	 * is the first address to be added.
	 */
	s = splimp();
#ifdef __APPLE__
	error = dlil_ioctl(0, ifp, SIOCSIFADDR, (caddr_t)ia);
#else
	error = (*ifp->if_ioctl)(ifp, SIOCSIFADDR, (caddr_t)ia);
#endif
	splx(s);
#if DEBUG
	printf("in6_ifattach: Calling SIOCSIFADDR for if=%s%d ia=%x error=%x\n", ifp->if_name, ifp->if_unit, ia, error);
#endif
	if (error == EOPNOTSUPP)
		error = 0;

	if (error) {
		switch (error) {
		case EAFNOSUPPORT:
			printf("%s: IPv6 not supported\n",
				if_name(ifp));
			break;
		default:
			printf("%s: SIOCSIFADDR error %d\n",
				if_name(ifp), error);
			break;
		}

		/* undo changes */
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
		*ifap = NULL;
#else
		TAILQ_REMOVE(&ifp->if_addrlist, (struct ifaddr *)ia, ifa_list);
#endif
		IFAFREE(&ia->ia_ifa);
		if (oia)
			oia->ia_next = ia->ia_next;
		else
			in6_ifaddr = ia->ia_next;
		IFAFREE(&ia->ia_ifa);
		return;
	}

	/* add route to the interface. */
	rtrequest(RTM_ADD,
		  (struct sockaddr *)&ia->ia_addr,
		  (struct sockaddr *)&ia->ia_addr,
		  (struct sockaddr *)&ia->ia_prefixmask,
		  RTF_UP|rtflag,
		  (struct rtentry **)0);
	ia->ia_flags |= IFA_ROUTE;

	if (type == IN6_IFT_P2P || type == IN6_IFT_P2P802) {
		/*
		 * route local address to loopback
		 */
		bzero(&gate, sizeof(gate));
		gate.sin6_len = sizeof(struct sockaddr_in6);
		gate.sin6_family = AF_INET6;
		gate.sin6_addr = in6addr_loopback;
		bzero(&mask, sizeof(mask));
		mask.sin6_len = sizeof(struct sockaddr_in6);
		mask.sin6_family = AF_INET6;
		mask.sin6_addr = in6mask64;
		rtrequest(RTM_ADD,
			  (struct sockaddr *)&ia->ia_addr,
			  (struct sockaddr *)&gate,
			  (struct sockaddr *)&mask,
			  RTF_UP|RTF_HOST,
			  (struct rtentry **)0);
	}

	/*
	 * loopback address
	 */
	ib = (struct in6_ifaddr *)NULL;
	if (type == IN6_IFT_LOOP) {
		ib = (struct in6_ifaddr *)
			_MALLOC(sizeof(*ib), M_IFADDR, M_WAITOK);
		bzero((caddr_t)ib, sizeof(*ib));
		ib->ia_ifa.ifa_addr = (struct sockaddr *)&ib->ia_addr;
		ib->ia_ifa.ifa_dstaddr = (struct sockaddr *)&ib->ia_dstaddr;
		ib->ia_ifa.ifa_netmask = (struct sockaddr *)&ib->ia_prefixmask;
		ib->ia_ifa.ifa_dlt = lo_attach_inet(ifp);
		ib->ia_ifp = ifp;

		ia->ia_next = ib;
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
		ia->ia_ifa.ifa_next = (struct ifaddr *)ib;
#else
		TAILQ_INSERT_TAIL(&ifp->if_addrlist, (struct ifaddr *)ib,
			ifa_list);
#endif
		ib->ia_ifa.ifa_refcnt++;

		ib->ia_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
		ib->ia_prefixmask.sin6_family = AF_INET6;
		ib->ia_prefixmask.sin6_addr = in6mask128;
		ib->ia_addr.sin6_len = sizeof(struct sockaddr_in6);
		ib->ia_addr.sin6_family = AF_INET6;
		ib->ia_addr.sin6_addr = in6addr_loopback;

		/*
		 * Always initialize ia_dstaddr (= broadcast address)
		 * to loopback address, to make getifaddr happier.
		 *
		 * For BSDI, it is mandatory.  The BSDI version of
		 * ifa_ifwithroute() rejects to add a route to the loopback
		 * interface.  Even for other systems, loopback looks somewhat
		 * special.
		 */
		ib->ia_dstaddr.sin6_len = sizeof(struct sockaddr_in6);
		ib->ia_dstaddr.sin6_family = AF_INET6;
		ib->ia_dstaddr.sin6_addr = in6addr_loopback;

		ib->ia_ifa.ifa_metric = ifp->if_metric;

		rtrequest(RTM_ADD,
			  (struct sockaddr *)&ib->ia_addr,
			  (struct sockaddr *)&ib->ia_addr,
			  (struct sockaddr *)&ib->ia_prefixmask,
			  RTF_UP|RTF_HOST,
			  (struct rtentry **)0);

		ib->ia_flags |= IFA_ROUTE;
	}

	/*
	 * join multicast
	 */
	if (ifp->if_flags & IFF_MULTICAST) {
		int error;	/* not used */

#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3) && !defined (__APPLE__)
		/* Restore saved multicast addresses(if any). */
		in6_restoremkludge(ia, ifp);
#endif

		bzero(&mltmask, sizeof(mltmask));
		mltmask.sin6_len = sizeof(struct sockaddr_in6);
		mltmask.sin6_family = AF_INET6;
		mltmask.sin6_addr = in6mask32;

		/*
		 * join link-local all-nodes address
		 */
		bzero(&mltaddr, sizeof(mltaddr));
		mltaddr.sin6_len = sizeof(struct sockaddr_in6);
		mltaddr.sin6_family = AF_INET6;
		mltaddr.sin6_addr = in6addr_linklocal_allnodes;
		mltaddr.sin6_addr.s6_addr16[1] = htons(ifp->if_index);
		rtrequest(RTM_ADD,
			  (struct sockaddr *)&mltaddr,
			  (struct sockaddr *)&ia->ia_addr,
			  (struct sockaddr *)&mltmask,
			  RTF_UP|RTF_CLONING,  /* xxx */
			  (struct rtentry **)0);
		(void)in6_addmulti(&mltaddr.sin6_addr, ifp, &error);

		if (type == IN6_IFT_LOOP) {
			/*
			 * join node-local all-nodes address
			 */
			mltaddr.sin6_addr = in6addr_nodelocal_allnodes;
			rtrequest(RTM_ADD,
				  (struct sockaddr *)&mltaddr,
				  (struct sockaddr *)&ib->ia_addr,
				  (struct sockaddr *)&mltmask,
				  RTF_UP,
				  (struct rtentry **)0);
			(void)in6_addmulti(&mltaddr.sin6_addr, ifp, &error);
		} else {
			/*
			 * join solicited multicast address
			 */
			bzero(&llsol, sizeof(llsol));
			llsol.s6_addr16[0] = htons(0xff02);
			llsol.s6_addr16[1] = htons(ifp->if_index);
			llsol.s6_addr32[1] = 0;
			llsol.s6_addr32[2] = htonl(1);
			llsol.s6_addr32[3] = ia->ia_addr.sin6_addr.s6_addr32[3];
			llsol.s6_addr8[12] = 0xff;
			(void)in6_addmulti(&llsol, ifp, &error);
		}
	}

	/* update dynamically. */
	if (in6_maxmtu < ifp->if_mtu)
		in6_maxmtu = ifp->if_mtu;

	if (in6_ifstat[ifp->if_index] == NULL) {
		in6_ifstat[ifp->if_index] = (struct in6_ifstat *)
			_MALLOC(sizeof(struct in6_ifstat), M_IFADDR, M_WAITOK);
		bzero(in6_ifstat[ifp->if_index], sizeof(struct in6_ifstat));
	}
	if (icmp6_ifstat[ifp->if_index] == NULL) {
		icmp6_ifstat[ifp->if_index] = (struct icmp6_ifstat *)
			_MALLOC(sizeof(struct icmp6_ifstat), M_IFADDR, M_WAITOK);
		bzero(icmp6_ifstat[ifp->if_index], sizeof(struct icmp6_ifstat));
	}

	/* initialize NDP variables */
	nd6_ifattach(ifp);

	/* mark the address TENTATIVE, if needed. */
	switch (ifp->if_type) {
	case IFT_ARCNET:
	case IFT_ETHER:
	case IFT_FDDI:
#if 0
	case IFT_ATM:
	case IFT_SLIP:
	case IFT_PPP:
#endif
		ia->ia6_flags |= IN6_IFF_TENTATIVE;
		/* nd6_dad_start() will be called in in6_if_up */
		break;
	case IFT_DUMMY:
	case IFT_GIF:	/*XXX*/
	case IFT_LOOP:
	case IFT_FAITH:
	default:
		break;
	}

	return;
}

/*
 * NOTE: in6_ifdetach() does not support loopback if at this moment.
 */
void
in6_ifdetach(ifp)
	struct ifnet *ifp;
{
	struct in6_ifaddr *ia, *oia;
	struct ifaddr *ifa;
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	struct ifaddr *ifaprev = NULL;
#endif
	struct rtentry *rt;
	short rtflags;
	struct sockaddr_in6 sin6;
	struct in6_multi *in6m;
#if (defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined (__APPLE__)
	struct in6_multi *in6m_next;
#endif

	/* nuke prefix list.  this may try to remove some of ifaddrs as well */
	in6_purgeprefix(ifp);

	/* remove neighbor management table */
	nd6_purge(ifp);

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
#else
	for (ifa = ifp->if_addrlist.tqh_first; ifa; ifa = ifa->ifa_list.tqe_next)
#endif
	{
		if (ifa->ifa_addr->sa_family != AF_INET6
		 || !IN6_IS_ADDR_LINKLOCAL(&satosin6(&ifa->ifa_addr)->sin6_addr)) {
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
			ifaprev = ifa;
#endif
			continue;
		}

		ia = (struct in6_ifaddr *)ifa;

#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3) && !defined (__APPLE__)
		/* leave from all multicast groups joined */
		while ((in6m = LIST_FIRST(&oia->ia6_multiaddrs)) != NULL)
			in6_delmulti(in6m);
#endif

		/* remove from the routing table */
		if ((ia->ia_flags & IFA_ROUTE)
		 && (rt = rtalloc1((struct sockaddr *)&ia->ia_addr, 0
#if defined (__FreeBSD__) || defined (__APPLE__)
				, 0UL
#endif
				))) {
			rtflags = rt->rt_flags;
			rtfree(rt);
			rtrequest(RTM_DELETE,
				(struct sockaddr *)&ia->ia_addr,
				(struct sockaddr *)&ia->ia_addr,
				(struct sockaddr *)&ia->ia_prefixmask,
				rtflags, (struct rtentry **)0);
		}

		/* remove from the linked list */
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
		if (ifaprev)
			ifaprev->ifa_next = ifa->ifa_next;
		else
			ifp->if_addrlist = ifa->ifa_next;
#else
		TAILQ_REMOVE(&ifp->if_addrlist, (struct ifaddr *)ia, ifa_list);
#endif

		/* also remove from the IPv6 address chain(itojun&jinmei) */
		oia = ia;
		if (oia == (ia = in6_ifaddr))
			in6_ifaddr = ia->ia_next;
		else {
			while (ia->ia_next && (ia->ia_next != oia))
				ia = ia->ia_next;
			if (ia->ia_next)
				ia->ia_next = oia->ia_next;
#if DEBUG
			else
				printf("%s: didn't unlink in6ifaddr from "
				    "list\n", if_name(ifp));
#endif
		}

		_FREE(ia, M_IFADDR);
	}

#if (defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined (__APPLE__)
	/* leave from all multicast groups joined */
	for (in6m = LIST_FIRST(&in6_multihead); in6m; in6m = in6m_next) {
		in6m_next = LIST_NEXT(in6m, in6m_entry);
		if (in6m->in6m_ifp != ifp)
			continue;
		in6_delmulti(in6m);
		in6m = NULL;
	}
#endif

#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3) && !defined(__APPLE__)
	/* cleanup multicast address kludge table, if there is any */
	in6_purgemkludge(ifp);
#endif

	/* remove neighbor management table */
	nd6_purge(ifp);

	/* remove route to link-local allnodes multicast (ff02::1) */
	bzero(&sin6, sizeof(sin6));
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = in6addr_linklocal_allnodes;
	sin6.sin6_addr.s6_addr16[1] = htons(ifp->if_index);
#if !defined(__FreeBSD__) && !defined (__APPLE__)
	if ((rt = rtalloc1((struct sockaddr *)&sin6, 0)) != NULL)
#else
	if ((rt = rtalloc1((struct sockaddr *)&sin6, 0, 0UL)) != NULL)
#endif
	{
		rtrequest(RTM_DELETE, (struct sockaddr *)rt_key(rt),
			rt->rt_gateway, rt_mask(rt), rt->rt_flags, 0);
		rtfree(rt);
	}
}
