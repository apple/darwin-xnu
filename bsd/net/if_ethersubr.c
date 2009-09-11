/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 *	@(#)if_ethersubr.c	8.1 (Berkeley) 6/10/93
 * $FreeBSD: src/sys/net/if_ethersubr.c,v 1.70.2.17 2001/08/01 00:47:49 fenner Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/route.h>
#include <net/if_llc.h>
#include <net/if_dl.h>
#include <net/if_types.h>

#if INET || INET6
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#endif

#if IPX
#include <netipx/ipx.h>
#include <netipx/ipx_if.h>
#endif

#include <sys/socketvar.h>

#if LLC && CCITT
extern struct ifqueue pkintrq;
#endif

#if BRIDGE
#include <net/bridge.h>
#endif

/* #include "vlan.h" */
#if NVLAN > 0
#include <net/if_vlan_var.h>
#endif /* NVLAN > 0 */

extern u_char	etherbroadcastaddr[];
#define senderr(e) do { error = (e); goto bad;} while (0)

/*
 * Perform common duties while attaching to interface list
 */

int
ether_resolvemulti(
	struct ifnet *ifp,
	struct sockaddr **llsa,
	struct sockaddr *sa)
{
	struct sockaddr_dl *sdl;
	struct sockaddr_in *sin;
	u_char *e_addr;
#if INET6
        struct sockaddr_in6 *sin6;
#endif


	switch(sa->sa_family) {
	case AF_UNSPEC:
		/* AppleTalk uses AF_UNSPEC for multicast registration.
		 * No mapping needed. Just check that it's a valid MC address.
		 */
		e_addr = &sa->sa_data[0];
		if ((e_addr[0] & 1) != 1)
			return EADDRNOTAVAIL;
		*llsa = 0;
		return 0;

	case AF_LINK:
		/* 
		 * No mapping needed. Just check that it's a valid MC address.
		 */
		sdl = (struct sockaddr_dl *)sa;
		e_addr = LLADDR(sdl);
		if ((e_addr[0] & 1) != 1)
			return EADDRNOTAVAIL;
		*llsa = 0;
		return 0;

#if INET
	case AF_INET:
		sin = (struct sockaddr_in *)sa;
		if (!IN_MULTICAST(ntohl(sin->sin_addr.s_addr)))
			return EADDRNOTAVAIL;
		MALLOC(sdl, struct sockaddr_dl *, sizeof *sdl, M_IFMADDR,
		       M_WAITOK);
		if (sdl == NULL)
			return ENOBUFS;
		sdl->sdl_len = sizeof *sdl;
		sdl->sdl_family = AF_LINK;
		sdl->sdl_index = ifp->if_index;
		sdl->sdl_type = IFT_ETHER;
		sdl->sdl_nlen = 0;
		sdl->sdl_alen = ETHER_ADDR_LEN;
		sdl->sdl_slen = 0;
		e_addr = LLADDR(sdl);
		ETHER_MAP_IP_MULTICAST(&sin->sin_addr, e_addr);
		*llsa = (struct sockaddr *)sdl;
		return 0;
#endif
#if INET6
        case AF_INET6:
                sin6 = (struct sockaddr_in6 *)sa;
                if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
                        /*
                         * An IP6 address of 0 means listen to all
                         * of the Ethernet multicast address used for IP6.
                         * (This is used for multicast routers.)
                         */
                        ifp->if_flags |= IFF_ALLMULTI;
                        *llsa = 0;
                        return 0;
                }
                MALLOC(sdl, struct sockaddr_dl *, sizeof *sdl, M_IFMADDR,
                       M_WAITOK);
		if (sdl == NULL)
			return ENOBUFS;
                sdl->sdl_len = sizeof *sdl;
                sdl->sdl_family = AF_LINK;
                sdl->sdl_index = ifp->if_index;
                sdl->sdl_type = IFT_ETHER;
                sdl->sdl_nlen = 0;
                sdl->sdl_alen = ETHER_ADDR_LEN;
                sdl->sdl_slen = 0;
                e_addr = LLADDR(sdl);
                ETHER_MAP_IPV6_MULTICAST(&sin6->sin6_addr, e_addr);
#if 0
                printf("ether_resolvemulti Adding %x:%x:%x:%x:%x:%x\n",
                                e_addr[0], e_addr[1], e_addr[2], e_addr[3], e_addr[4], e_addr[5]);
#endif
                *llsa = (struct sockaddr *)sdl;
                return 0;
#endif

	default:
		/* 
		 * Well, the text isn't quite right, but it's the name
		 * that counts...
		 */
		return EAFNOSUPPORT;
	}
}


/*
 * Convert Ethernet address to printable (loggable) representation.
 */
static u_char digits[] = "0123456789abcdef";
char *
ether_sprintf(p, ap)
	register u_char *p;
        register u_char *ap;
{	register char *cp;
        register i;

        for (cp = p, i = 0; i < 6; i++) {
                *cp++ = digits[*ap >> 4];
                *cp++ = digits[*ap++ & 0xf];
                *cp++ = ':';
        }
        *--cp = 0;
        return (p);
}
