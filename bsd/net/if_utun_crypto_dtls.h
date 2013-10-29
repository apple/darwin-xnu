/*
 * Copyright (c) 2012 Apple Inc. All rights reserved.
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

#ifndef	_NET_IF_UTUN_CRYPTO_DTLS_H_
#define	_NET_IF_UTUN_CRYPTO_DTLS_H_

#define UTUN_CRYPTO_DTLS_HANDLE_INVALID -1

#ifdef KERNEL_PRIVATE

#include <sys/systm.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_types.h>
#include <sys/mbuf.h>
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet6/in6_var.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_var.h>
#include <net/if_utun.h>
#include <net/if_utun_crypto.h>
#include <sys/kernel_types.h>
#include <net/kpi_interface.h>

#define utun_cleanup_all_crypto_dtls(pcb) utun_ctl_disable_crypto_dtls(pcb)

/*
 * Summary: initializes global vars needed for any utun crypto based on dtls
 */
void
utun_ctl_init_crypto_dtls(void);

errno_t
utun_ctl_register_dtls (utun_crypto_kpi_reg_t *reg);

/*
 * Summary: disables all crypto DTLS in one shot
 */
void
utun_cleanup_all_crypto_dtls (struct utun_pcb   *pcb);

/*
 * Summary: enables dtls crypto info for the specified utun. dtls ref is passed into args.
 */
void
utun_ctl_enable_crypto_dtls(struct utun_pcb   *pcb, utun_crypto_args_t *args);

/*
 * Summary: disables ipsec crypto info for the specified utun.
 */
void
utun_ctl_disable_crypto_dtls(struct utun_pcb   *pcb);

int
utun_ctl_config_crypto_dtls_framer(utun_crypto_ctx_t *crypto_ctx, utun_crypto_framer_args_t *args);

int
utun_ctl_unconfig_crypto_dtls_framer(utun_crypto_ctx_t *crypto_ctx, utun_crypto_framer_args_t *args);

/*
 * Summary: enables handling of data traffic
 */
void
utun_ctl_start_datatraffic_crypto_dtls(struct utun_pcb   *pcb);

/*
 * Summary: disables handling of data traffic
 */
void
utun_ctl_stop_datatraffic_crypto_dtls(struct utun_pcb   *pcb);

int
utun_pkt_dtls_output(struct utun_pcb *pcb, mbuf_t *pkt);

int
utun_pkt_dtls_input(struct utun_pcb *pcb, mbuf_t *pkt, protocol_family_t family);

static inline protocol_family_t
utun_crypto_framer_inner_type_to_protocol_family (utun_crypto_framer_inner_type_t type)
{
	if (type == UTUN_CRYPTO_INNER_TYPE_IPv4) {
		return PF_INET;
	} else {
		return PF_INET6;
	}
}

static inline utun_crypto_framer_inner_type_t
utun_crypto_framer_protocol_family_to_inner_type (protocol_family_t family)
{
	if (family == PF_INET) {
		return UTUN_CRYPTO_INNER_TYPE_IPv4;
	} else {
		return UTUN_CRYPTO_INNER_TYPE_IPv6;
	}
}

#endif // KERNEL_PRIVATE

#endif // _NET_IF_UTUN_CRYPTO_DTLS_H_
