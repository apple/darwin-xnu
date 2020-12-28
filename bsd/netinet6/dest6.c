/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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
/*	$FreeBSD: src/sys/netinet6/dest6.c,v 1.1.2.3 2001/07/03 11:01:49 ume Exp $	*/
/*	$KAME: dest6.c,v 1.27 2001/03/29 05:34:30 itojun Exp $	*/

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
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>

/*
 * Destination options header processing.
 */
int
dest6_input(struct mbuf **mp, int *offp, int proto)
{
#pragma unused(proto)
	struct mbuf *m = *mp;
	int off = *offp, dstoptlen = 0, optlen = 0;
	struct ip6_dest *dstopts = NULL;
	u_int8_t *opt = NULL;

	/* validation of the length of the header */
	IP6_EXTHDR_CHECK(m, off, sizeof(*dstopts), return IPPROTO_DONE);
	dstopts = (struct ip6_dest *)(mtod(m, caddr_t) + off);
	dstoptlen = (dstopts->ip6d_len + 1) << 3;

	IP6_EXTHDR_CHECK(m, off, dstoptlen, return IPPROTO_DONE);
	dstopts = (struct ip6_dest *)(mtod(m, caddr_t) + off);
	off += dstoptlen;
	dstoptlen -= sizeof(struct ip6_dest);
	opt = (u_int8_t *)dstopts + sizeof(struct ip6_dest);

	/* search header for all options. */
	for (optlen = 0; dstoptlen > 0; dstoptlen -= optlen, opt += optlen) {
		if (*opt != IP6OPT_PAD1 &&
		    (dstoptlen < IP6OPT_MINLEN || *(opt + 1) + 2 > dstoptlen)) {
			ip6stat.ip6s_toosmall++;
			goto bad;
		}

		switch (*opt) {
		case IP6OPT_PAD1:
			optlen = 1;
			break;
		case IP6OPT_PADN:
			optlen = *(opt + 1) + 2;
			break;

		default:                /* unknown option */
			optlen = ip6_unknown_opt(opt, m,
			    opt - mtod(m, u_int8_t *));
			if (optlen == -1) {
				return IPPROTO_DONE;
			}
			optlen += 2;
			break;
		}
	}
	*mp = m;
	*offp = off;
	return dstopts->ip6d_nxt;

bad:
	*mp = NULL;
	m_freem(m);
	return IPPROTO_DONE;
}
