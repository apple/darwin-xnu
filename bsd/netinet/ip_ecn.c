/*
 * Copyright (c) 2000, 2007, 2015 Apple Inc. All rights reserved.
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
 * Copyright (C) 1999 WIDE Project.
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
 *
 */
/*
 * ECN consideration on tunnel ingress/egress operation.
 * http://www.aciri.org/floyd/papers/draft-ipsec-ecn-00.txt
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/errno.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#if INET6
#include <netinet/ip6.h>
#endif

#include <netinet/ip_ecn.h>
#if INET6
#include <netinet6/ip6_ecn.h>
#endif

/*
 * modify outer ECN (TOS) field on ingress operation (tunnel encapsulation).
 */
void
ip_ecn_ingress(mode, outer, inner)
	int mode;
	u_int8_t *outer;
	const u_int8_t *inner;
{
	if (!outer || !inner)
		panic("NULL pointer passed to ip_ecn_ingress");

	*outer = *inner;
	switch (mode) {
	case ECN_NORMAL:		/* ECN normal mode, copy flags */
		break;
	case ECN_COMPATIBILITY:		/* ECN compatibility mode */
		*outer &= ~IPTOS_ECN_MASK;
		break;
	case ECN_NOCARE:	/* no consideration to ECN */
		break;
	}
}

/*
 * modify inner ECN (TOS) field on egress operation (tunnel decapsulation).
 */
int
ip_ecn_egress(mode, outer, inner)
	int mode;
	const u_int8_t *outer;
	u_int8_t *inner;
{
	if (!outer || !inner)
		panic("NULL pointer passed to ip_ecn_egress");

	switch (mode) {
	/* Process ECN for both normal and compatibility modes */
	case ECN_NORMAL:
	case ECN_COMPATIBILITY:
		if ((*outer & IPTOS_ECN_MASK) == IPTOS_ECN_CE) {
			if ((*inner & IPTOS_ECN_MASK) == IPTOS_ECN_NOTECT) {
				/* Drop */
				return (0);
			} else {
				*inner |= IPTOS_ECN_CE;
			}
		} else if ((*outer & IPTOS_ECN_MASK) == IPTOS_ECN_ECT1 &&
				   (*inner & IPTOS_ECN_MASK) == IPTOS_ECN_ECT0) {
			*inner = *outer;
		}
		break;
	case ECN_NOCARE:	/* no consideration to ECN */
		break;
	}
	return (1);
}

#if INET6
void
ip6_ecn_ingress(mode, outer, inner)
	int mode;
	u_int32_t *outer;
	const u_int32_t *inner;
{
	u_int8_t outer8, inner8;

	if (!outer || !inner)
		panic("NULL pointer passed to ip6_ecn_ingress");

	inner8 = (ntohl(*inner) >> 20) & 0xff;
	ip_ecn_ingress(mode, &outer8, &inner8);
	*outer &= ~htonl(0xff << 20);
	*outer |= htonl((u_int32_t)outer8 << 20);
}

int
ip6_ecn_egress(mode, outer, inner)
	int mode;
	const u_int32_t *outer;
	u_int32_t *inner;
{
	u_int8_t outer8, inner8;

	if (!outer || !inner)
		panic("NULL pointer passed to ip6_ecn_egress");

	outer8 = (ntohl(*outer) >> 20) & 0xff;
	inner8 = (ntohl(*inner) >> 20) & 0xff;
	if (ip_ecn_egress(mode, &outer8, &inner8) == 0) {
		return (0);
	}
	*inner &= ~htonl(0xff << 20);
	*inner |= htonl((u_int32_t)inner8 << 20);
	return (1);
}

/*
 * Modify outer IPv6 ECN (Traffic Class) field according to inner IPv4 TOS field
 * on ingress operation (tunnel encapsulation).
 */
void
ip46_ecn_ingress(mode, outer, tos)
	int mode;
	u_int32_t *outer;
	const u_int8_t *tos;
{
	u_int8_t outer8;

	if (!outer || !tos)
		panic("NULL pointer passed to ip46_ecn_ingress");

	ip_ecn_ingress(mode, &outer8, tos);
	*outer &= ~htonl(0xff << 20);
	*outer |= htonl((u_int32_t)outer8 << 20);
}

/*
 * Modify inner IPv4 ECN (TOS) field according to output IPv6 ECN (Traffic Class)
 * on egress operation (tunnel decapsulation).
 */
int
ip46_ecn_egress(mode, outer, tos)
	int mode;
	const u_int32_t *outer;
	u_int8_t *tos;
{
	u_int8_t outer8;

	if (!outer || !tos)
		panic("NULL pointer passed to ip46_ecn_egress");

	outer8 = (ntohl(*outer) >> 20) & 0xff;
	return ip_ecn_egress(mode, &outer8, tos);
}

/*
 * Modify outer IPv4 TOS field according to inner IPv6 ECN (Traffic Class)
 * on ingress operation (tunnel encapsulation).
 */
void
ip64_ecn_ingress(mode, outer, inner)
	int mode;
	u_int8_t *outer;
	const u_int32_t *inner;
{
	u_int8_t inner8;

	if (!outer || ! inner)
		panic("NULL pointer passed to ip64_ecn_ingress");

	inner8 = (ntohl(*inner) >> 20) & 0xff;
	ip_ecn_ingress(mode, outer, &inner8);
}

/*
 * Modify inner IPv6 ECN (Traffic Class) according to outer IPv4 TOS field
 * on egress operation (tunnel decapsulation).
 */
int
ip64_ecn_egress(mode, outer, inner)
	int mode;
	const u_int8_t *outer;
	u_int32_t *inner;
{
	u_int8_t inner8;

	if (!outer || !inner)
		panic("NULL pointer passed to ip64_ecn_egress");

	inner8 = (ntohl(*inner) >> 20) & 0xff;
	if (ip_ecn_egress(mode, outer, &inner8) == 0) {
		return (0);
	}

	*inner &= ~htonl(0xff << 20);
	*inner |= htonl((u_int32_t)inner8 << 20);
	return (1);
}

#endif
