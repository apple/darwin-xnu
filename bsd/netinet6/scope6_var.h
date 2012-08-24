/*
 * Copyright (c) 2009-2010 Apple Inc. All rights reserved.
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

/*	$FreeBSD: src/sys/netinet6/scope6_var.h,v 1.1.2.1 2000/07/15 07:14:38 kris Exp $	*/
/*	$KAME: scope6_var.h,v 1.4 2000/05/18 15:03:27 jinmei Exp $	*/

/*
 * Copyright (C) 2000 WIDE Project.
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

#ifndef _NETINET6_SCOPE6_VAR_H_
#define _NETINET6_SCOPE6_VAR_H_
#include <sys/appleapiopts.h>

#ifdef KERNEL_PRIVATE

struct scope6_id {
	/*
	 * 16 is correspondent to 4bit multicast scope field.
	 * i.e. from node-local to global with some reserved/unassigned types.
	 */
	u_int32_t s6id_list[16];
};

void	scope6_init (void);
int	scope6_ifattach(struct ifnet *);
void scope6_ifdetach (struct scope6_id *);
int	scope6_set(struct ifnet *, u_int32_t *);
int	scope6_get(struct ifnet *, u_int32_t *);
void	scope6_setdefault(struct ifnet *);
int	scope6_get_default(u_int32_t *);
u_int32_t scope6_in6_addrscope(struct in6_addr *);
u_int32_t scope6_addr2default(struct in6_addr *);
int	sa6_embedscope (struct sockaddr_in6 *, int);
int	sa6_recoverscope (struct sockaddr_in6 *, boolean_t);
int	in6_setscope (struct in6_addr *, struct ifnet *, u_int32_t *);
int	in6_clearscope (struct in6_addr *);
extern void rtkey_to_sa6(struct rtentry *, struct sockaddr_in6 *);
extern void rtgw_to_sa6(struct rtentry *, struct sockaddr_in6 *);

#endif /* KERNEL_PRIVATE */

#endif /* _NETINET6_SCOPE6_VAR_H_ */
