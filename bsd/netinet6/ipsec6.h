/*	$FreeBSD: src/sys/netinet6/ipsec6.h,v 1.3.2.2 2001/07/03 11:01:54 ume Exp $	*/
/*	$KAME: ipsec.h,v 1.44 2001/03/23 08:08:47 itojun Exp $	*/

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

/*
 * IPsec controller part.
 */

#ifndef _NETINET6_IPSEC6_H_
#define _NETINET6_IPSEC6_H_
#include <sys/appleapiopts.h>

#include <net/pfkeyv2.h>
#include <netkey/keydb.h>

#ifdef KERNEL
#ifdef __APPLE_API_PRIVATE
extern struct ipsecstat ipsec6stat;
extern struct secpolicy ip6_def_policy;
extern int ip6_esp_trans_deflev;
extern int ip6_esp_net_deflev;
extern int ip6_ah_trans_deflev;
extern int ip6_ah_net_deflev;
extern int ip6_ipsec_ecn;
extern int ip6_esp_randpad;

extern struct secpolicy *ipsec6_getpolicybysock
	__P((struct mbuf *, u_int, struct socket *, int *));
extern struct secpolicy *ipsec6_getpolicybyaddr
	__P((struct mbuf *, u_int, int, int *));

struct inpcb;

extern int ipsec6_in_reject_so __P((struct mbuf *, struct socket *));
extern int ipsec6_delete_pcbpolicy __P((struct inpcb *));
extern int ipsec6_set_policy __P((struct inpcb *inp, int optname,
	caddr_t request, size_t len, int priv));
extern int ipsec6_get_policy
	__P((struct inpcb *inp, caddr_t request, size_t len, struct mbuf **mp));
extern int ipsec6_in_reject __P((struct mbuf *, struct inpcb *));

struct tcp6cb;

extern size_t ipsec6_hdrsiz __P((struct mbuf *, u_int, struct inpcb *));

struct ip6_hdr;
extern const char *ipsec6_logpacketstr __P((struct ip6_hdr *, u_int32_t));

extern int ipsec6_output_trans __P((struct ipsec_output_state *, u_char *,
	struct mbuf *, struct secpolicy *, int, int *));
extern int ipsec6_output_tunnel __P((struct ipsec_output_state *,
	struct secpolicy *, int));
extern int ipsec6_tunnel_validate __P((struct mbuf *, int, u_int,
	struct secasvar *));
#endif /* __APPLE_API_PRIVATE */
#endif /*KERNEL*/

#endif /*_NETINET6_IPSEC6_H_*/
