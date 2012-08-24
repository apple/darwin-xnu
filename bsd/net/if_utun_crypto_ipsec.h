/*
 * Copyright (c) 2011 Apple Inc. All rights reserved.
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

#ifndef	_NET_IF_UTUN_CRYPTO_IPSEC_H_
#define	_NET_IF_UTUN_CRYPTO_IPSEC_H_

#ifdef KERNEL_PRIVATE

struct utun_pcb;

#define UTUN_CRYPTO_DIR_TO_IPSEC_DIR(dir)       (dir == UTUN_CRYPTO_DIR_IN)? IPSEC_DIR_INBOUND : IPSEC_DIR_OUTBOUND
#define IF_UTUN_GET_TX_CRYPTO_KEYS(pcb)         LIST_FIRST(&pcb->utun_crypto_ctx[UTUN_CRYPTO_DIR_TO_IDX(UTUN_CRYPTO_DIR_OUT)].keys_listhead)
#define IF_UTUN_GET_CRYPTO_KEYS_IPSEC_SAH(keys) keys->state.u.ipsec.sah
#define IF_UTUN_GET_CRYPTO_KEYS_IPSEC_SAV(keys) keys->state.u.ipsec.sav

/*
 * Summary: cleans up all crypto info for the specified utun.
 */
void
utun_cleanup_all_crypto_ipsec(struct utun_pcb   *pcb);

/*
 * Summary: enables ipsec crypto info for the specified utun.
 */
void
utun_ctl_enable_crypto_ipsec(struct utun_pcb   *pcb, utun_crypto_args_t *args);

/*
 * Summary: disables ipsec crypto info for the specified utun.
 */
void
utun_ctl_disable_crypto_ipsec(struct utun_pcb   *pcb);

/*
 * Summary: configures an ipsec crypto context for the specified utun, with keying material
 *          (needed for traffic encrypt/decrypt).
 * Args:
 *		pcb - the specified utun state info
 *      args - the ipsec crypto context keying arguments as passed down from userland.
 *      crypto_ctx_mat - the ipsec crypto context's keying material to be filled.
 * Returns: 0 if successful, otherwise returns an appropriate errno.
 */
errno_t
utun_ctl_config_crypto_keys_ipsec(struct utun_pcb         *pcb,
				  utun_crypto_keys_args_t *args,
				  utun_crypto_keys_t      *crypto_ctx_mat);

/*
 * Summary: unconfigures the keying material in an ipsec crypto context for the specified utun.
 * Args:
 *      args - the ipsec crypto context keying arguments as passed down from userland.
 *      crypto_ctx_mat - the ipsec crypto context's keying material to be filled.
 * Returns: 0 if successful, otherwise returns an appropriate errno.
 */
errno_t
utun_ctl_unconfig_crypto_keys_ipsec(utun_crypto_keys_args_t *args,
				    utun_crypto_keys_t      *crypto_ctx_mat);

/*
 * Summary: generates an SPI/index to be using by keying material in an ipsec crypto context 
 *          for the specified utun.
 * Args:
 *      args - the ipsec crypto context key index arguments as passed down from userland.
 * Returns: 0 if successful, otherwise returns an appropriate errno.
 */
errno_t
utun_ctl_generate_crypto_keys_idx_ipsec(utun_crypto_keys_idx_args_t *args);

int
utun_pkt_ipsec_output(struct utun_pcb *pcb, mbuf_t *pkt);

int
utun_pkt_is_ipsec_keepalive(struct utun_pcb *pcb, mbuf_t *pkt, u_int16_t nxt, u_int32_t flags, size_t off);

int
utun_pkt_ipsec_input(struct utun_pcb *pcb, mbuf_t *pkt, protocol_family_t family);

#endif // KERNEL_PRIVATE

#endif // _NET_IF_UTUN_CRYPTO_IPSEC_H_
