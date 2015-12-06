/*
 * Copyright (c) 2012-2013 Apple Inc. All rights reserved.
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

#include <sys/systm.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_utun.h>
#include <sys/mbuf.h>
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet6/in6_var.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_var.h>
#include <net/if_utun.h>
#include <net/if_utun_crypto_dtls.h>
#include <net/bpf.h>

extern errno_t utun_pkt_input (struct utun_pcb *pcb, mbuf_t m);

static UInt32                               dtls_kpi_callbacks_inited = FALSE;
static unsigned int                         dtls_kpi_flags = 0;
static utun_crypto_kpi_connect_func         dtls_kpi_connect = (__typeof__(dtls_kpi_connect))NULL;
static utun_crypto_kpi_send_func            dtls_kpi_send = (__typeof__(dtls_kpi_send))NULL;

// convert this mutex to shared lock
static UInt32             dtls_ctl_mutex_inited = FALSE;
static lck_grp_t         *dtls_ctl_mutex_grp = NULL;
static lck_grp_attr_t    *dtls_ctl_mutex_grp_attr = NULL;
static lck_attr_t        *dtls_ctl_mutex_attr = NULL;
static lck_mtx_t          dtls_ctl_mutex;

#define utun_ctl_get_first_framer(ctx, inner_type) (utun_crypto_framer_t *)LIST_FIRST(&ctx->framer_listheads[UTUN_CRYPTO_INNER_TYPE_TO_IDX(inner_type)])
#define utun_get_framer_listhead(ctx, inner_type) &ctx->framer_listheads[UTUN_CRYPTO_INNER_TYPE_TO_IDX(inner_type)]

static void
utun_ctl_clr_dtls_framer (utun_crypto_framer_t *rem_framer)
{
	if (!rem_framer) return;

	// TOFIX: switch to BPF
	LIST_REMOVE(rem_framer, framer_chain); // unchain the framer
	if (rem_framer->dir == UTUN_CRYPTO_DIR_IN) {
		if (utun_crypto_framer_state_dtls_in(rem_framer).in_pattern) {
			utun_free(utun_crypto_framer_state_dtls_in(rem_framer).in_pattern);
		}
		if (utun_crypto_framer_state_dtls_in(rem_framer).in_pattern_mask) {
			utun_free(utun_crypto_framer_state_dtls_in(rem_framer).in_pattern_mask);
		}
		if (utun_crypto_framer_state_dtls_in(rem_framer).in_pattern_masked) {
			utun_free(utun_crypto_framer_state_dtls_in(rem_framer).in_pattern_masked);
		}
	} else {
		if (utun_crypto_framer_state_dtls_out(rem_framer).out_pattern) {
			utun_free(utun_crypto_framer_state_dtls_out(rem_framer).out_pattern);
		}
	}
	utun_free(rem_framer);
	
	return;
}

static void
utun_ctl_clr_dtls_framers (utun_crypto_framer_t *first_framer)
{
	utun_crypto_framer_t *cur_framer, *nxt_framer;
	
	// check framer->state.u.dtls.u.in.listhead for duplicates;
	for (cur_framer = first_framer;
		 cur_framer != NULL;
		 cur_framer = nxt_framer) {
		nxt_framer = (__typeof__(nxt_framer))LIST_NEXT(cur_framer, framer_chain);
		utun_ctl_clr_dtls_framer(cur_framer);
	}
	
	return;
}

static void
utun_ctl_clr_dtls_all_framers (utun_crypto_ctx_t *crypto_ctx)
{
	utun_ctl_clr_dtls_framers(utun_ctl_get_first_framer(crypto_ctx, UTUN_CRYPTO_INNER_TYPE_IPv4));
	utun_ctl_clr_dtls_framers(utun_ctl_get_first_framer(crypto_ctx, UTUN_CRYPTO_INNER_TYPE_IPv6));
	crypto_ctx->num_framers = 0;
}

static void
utun_ctl_restart_dtls_framers (utun_crypto_framer_t *first_framer)
{
	utun_crypto_framer_t *cur_framer;
	
	// check framer->state.u.dtls.u.in.listhead for duplicates;
	for (cur_framer = first_framer;
		 cur_framer != NULL;
		 cur_framer = (__typeof__(cur_framer))LIST_NEXT(cur_framer, framer_chain)) {
		utun_crypto_framer_state_dtls_out(cur_framer).sequence_field = utun_crypto_framer_state_dtls_out(cur_framer).sequence_field_initval;
	}
	
	return;
}

static void
utun_ctl_restart_dtls_all_framers (utun_crypto_ctx_t *crypto_ctx)
{
	utun_ctl_restart_dtls_framers(utun_ctl_get_first_framer(crypto_ctx, UTUN_CRYPTO_INNER_TYPE_IPv4));
	utun_ctl_restart_dtls_framers(utun_ctl_get_first_framer(crypto_ctx, UTUN_CRYPTO_INNER_TYPE_IPv6));
}

static int
is_pattern_all_zeroes (u_int8_t *pattern,
					   int       pattern_len)
{
	int i;

	if (!pattern || !pattern_len) return FALSE; // false if args are NULL

	for (i = 0; i < pattern_len; i++) {
		if (pattern[i] != 0) return FALSE;
	}
	return TRUE;
}

static int
is_pattern_masked_all_zeroes (u_int8_t *pattern,
							  u_int8_t *pattern_mask,
							  int       pattern_len)
{
	int i;

	if (!pattern || !pattern_mask || !pattern_len) return FALSE; // false if args are NULL

	for (i = 0; i < pattern_len; i++) {
		if ((pattern[i] & pattern_mask[i])) return FALSE;
	}
	return TRUE;
}

static void
utun_ctl_calc_dtls_framer_pattern_and_mask (u_int8_t *pattern_masked, u_int8_t *pattern, u_int8_t *mask, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		pattern_masked[i] = (pattern[i] & mask[i]);
	}
}

static Boolean
utun_ctl_did_dtls_framer_pattern_match (u_int8_t *input, u_int8_t *pattern_masked, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		if ((input[i] & pattern_masked[i]) != pattern_masked[i]) return FALSE;
	}
	return TRUE;
}

static Boolean
utun_pkt_dtls_input_frame_is_data(utun_crypto_ctx_t *crypto_ctx,
				  mbuf_t            *pkt,
				  protocol_family_t  family,
				  int               *striplen)
{
	u_int8_t *p;
	utun_crypto_framer_t *cur_framer;

	p = mtod(*pkt, __typeof__(p));
	for (cur_framer = utun_ctl_get_first_framer(crypto_ctx, utun_crypto_framer_protocol_family_to_inner_type(family));
	     cur_framer != NULL;
	     cur_framer = (__typeof__(cur_framer))LIST_NEXT(cur_framer, framer_chain)) {
		if (m_pktlen(*pkt) < utun_crypto_framer_state_dtls_in(cur_framer).in_pattern_len) {
			continue;
		}
		if ((*pkt)->m_len < utun_crypto_framer_state_dtls_in(cur_framer).in_pattern_len) {
		  *pkt = m_pullup(*pkt, utun_crypto_framer_state_dtls_in(cur_framer).in_pattern_len);
			if (!*pkt ||
			    (*pkt)->m_len < utun_crypto_framer_state_dtls_in(cur_framer).in_pattern_len) {
				return FALSE;
			}
			p = mtod(*pkt, __typeof__(p));
		}
		// TOFIX: switch to BPF
		if (utun_ctl_did_dtls_framer_pattern_match(p,
							   utun_crypto_framer_state_dtls_in(cur_framer).in_pattern_masked,
							   utun_crypto_framer_state_dtls_in(cur_framer).in_pattern_len)) {
			*striplen = utun_crypto_framer_state_dtls_in(cur_framer).in_data_offset;
			return TRUE;
		}
	}
	return FALSE;
}

#define GETLONG(l, cp) {               \
	(l) = *(cp)++ << 8;	       \
	(l) |= *(cp)++; (l) <<= 8;     \
	(l) |= *(cp)++; (l) <<= 8;     \
	(l) |= *(cp)++;		       \
  }
#define PUTLONG(l, cp) {                \
	*(cp)++ = (u_char) ((l) >> 24); \
	*(cp)++ = (u_char) ((l) >> 16); \
	*(cp)++ = (u_char) ((l) >> 8);	\
	*(cp)++ = (u_char) (l);		\
  }

static int
utun_pkt_dtls_output_frame_encapsulate (utun_crypto_ctx_t *crypto_ctx,
					mbuf_t            *pkt,
					protocol_family_t  proto)
{
	u_int8_t *p;
	utun_crypto_framer_t *cur_framer;
	u_int32_t pkt_len;

	// TOFIX: switch to BPF

	if (!crypto_ctx->num_framers) {
		return 0;
	}
	if (proto != AF_INET && proto != AF_INET6) {
		printf("%s: unsupported proto %d\n", __FUNCTION__, proto);
		return EINVAL;
	}

	for (cur_framer = utun_ctl_get_first_framer(crypto_ctx, utun_crypto_framer_protocol_family_to_inner_type(proto));
	     cur_framer != NULL && !utun_crypto_framer_state_dtls_out(cur_framer).out_pattern;
	     cur_framer = (__typeof__(cur_framer))LIST_NEXT(cur_framer, framer_chain));
	if (!cur_framer ||
	    !utun_crypto_framer_state_dtls_out(cur_framer).out_pattern_len) {
		return 0;
	}

	pkt_len = m_pktlen(*pkt);

	// prepend/encapsulate the output pattern
	if (mbuf_prepend(pkt, utun_crypto_framer_state_dtls_out(cur_framer).out_pattern_len, MBUF_DONTWAIT) != 0) {
		printf("%s - ifnet_output prepend failed\n", __FUNCTION__);
		return ENOBUFS;
	}

	p = mtod(*pkt, __typeof__(p));
	memcpy(p,
	       utun_crypto_framer_state_dtls_out(cur_framer).out_pattern,
	       utun_crypto_framer_state_dtls_out(cur_framer).out_pattern_len);
	// fill a "length" field... if configured
	if (utun_crypto_framer_state_dtls_out(cur_framer).len_field_mask) {
		u_int32_t  tmp;
		u_int8_t  *q = p + utun_crypto_framer_state_dtls_out(cur_framer).len_field_offset;
		GETLONG(tmp, q);
		tmp &= ((pkt_len + utun_crypto_framer_state_dtls_out(cur_framer).len_field_extra) & utun_crypto_framer_state_dtls_out(cur_framer).len_field_mask);
		q = p + utun_crypto_framer_state_dtls_out(cur_framer).len_field_offset;
		PUTLONG(tmp, q);
	}
	// fill a "sequence" field... if configured
	if (utun_crypto_framer_state_dtls_out(cur_framer).sequence_field_mask) {
		u_int32_t  tmp = (utun_crypto_framer_state_dtls_out(cur_framer).sequence_field & utun_crypto_framer_state_dtls_out(cur_framer).sequence_field_mask);
		u_int8_t  *q = p + utun_crypto_framer_state_dtls_out(cur_framer).sequence_field_offset;
		GETLONG(tmp, q);
		tmp &= (utun_crypto_framer_state_dtls_out(cur_framer).sequence_field & utun_crypto_framer_state_dtls_out(cur_framer).sequence_field_mask);
		q = p + utun_crypto_framer_state_dtls_out(cur_framer).sequence_field_offset;
		PUTLONG(tmp, q);
		utun_crypto_framer_state_dtls_out(cur_framer).sequence_field++;
	}
	return 0;
}

void
utun_ctl_init_crypto_dtls (void)
{
	if (OSCompareAndSwap(FALSE, TRUE, &dtls_ctl_mutex_inited)) {
		if (!dtls_ctl_mutex_grp_attr)
			dtls_ctl_mutex_grp_attr = lck_grp_attr_alloc_init();
		if (!dtls_ctl_mutex_grp)
			dtls_ctl_mutex_grp = lck_grp_alloc_init("utun-crypto", dtls_ctl_mutex_grp_attr);
		if (!dtls_ctl_mutex_attr)
			dtls_ctl_mutex_attr = lck_attr_alloc_init();

		lck_mtx_init(&dtls_ctl_mutex, dtls_ctl_mutex_grp, dtls_ctl_mutex_attr);
	}
}

/*
 * Summary: registers the DTLS Kext routines with UTUN... so that UTUN can make calls into DTLS
 */
errno_t
utun_ctl_register_dtls (utun_crypto_kpi_reg_t *reg)
{
	//printf("%s: entering\n", __FUNCTION__);
	if (!reg) return EINVAL;

	//printf("%s: type %d\n", __FUNCTION__, reg->crypto_kpi_type);
	if (reg->crypto_kpi_type != UTUN_CRYPTO_TYPE_DTLS) {
		return EINVAL;
	}

	if (!reg->crypto_kpi_connect) {
		return EINVAL;
	}

	if (!reg->crypto_kpi_send) {
		return EINVAL;
	}

	//	printf("%s: pre-value of dtls_kpi_callbacks_inited %lu\n", __FUNCTION__,
	//       dtls_kpi_callbacks_inited);
	if (OSCompareAndSwap(FALSE, TRUE, &dtls_kpi_callbacks_inited)) {
		dtls_kpi_flags = reg->crypto_kpi_flags;
		dtls_kpi_connect = reg->crypto_kpi_connect;
		dtls_kpi_send = reg->crypto_kpi_send;
	}
	//printf("%s: post-value of dtls_kpi_callbacks_inited %lu\n", __FUNCTION__,
	//       dtls_kpi_callbacks_inited);
	return 0;
}

/*
 * Summary: enables dtls crypto info for the specified utun. dtls ref is passed into args.
 */
void
utun_ctl_enable_crypto_dtls(struct utun_pcb   *pcb, utun_crypto_args_t *args)
{
	utun_crypto_ctx_t *crypto_ctx;

	lck_mtx_lock(&dtls_ctl_mutex);

	//printf("%s: entering, flags %x, kpi-handle %x, kpi-ref %p, kpi-refcnt %d\n", __FUNCTION__, pcb->utun_flags, crypto_ctx->kpi_handle, crypto_ctx->kpi_ref, crypto_ctx->kpi_refcnt);
	
	crypto_ctx = &pcb->utun_crypto_ctx[UTUN_CRYPTO_DIR_TO_IDX(UTUN_CRYPTO_DIR_IN)];
	if (crypto_ctx->valid) {
		printf("%s: dtls already enabled (prev %u, now %u)\n", __FUNCTION__,
		       crypto_ctx->kpi_handle, args->u.dtls_v1.kpi_handle);
		lck_mtx_unlock(&dtls_ctl_mutex);
		return;
	}

	crypto_ctx = &pcb->utun_crypto_ctx[UTUN_CRYPTO_DIR_TO_IDX(UTUN_CRYPTO_DIR_OUT)];
	if (!crypto_ctx->valid) {
		crypto_ctx->kpi_handle = args->u.dtls_v1.kpi_handle;
	} else {
		printf("%s: dtls already enabled for egress (prev %u, now %u)\n", __FUNCTION__,
		       crypto_ctx->kpi_handle, args->u.dtls_v1.kpi_handle);
		lck_mtx_unlock(&dtls_ctl_mutex);
		return;
	}
	// crypto_ctx->valid will be set in utun_ctl_enable_crypto
	lck_mtx_unlock(&dtls_ctl_mutex);
	return;
}

/*
 * Summary: disables dtls crypto info for the specified utun.
 */
void
utun_ctl_disable_crypto_dtls(struct utun_pcb   *pcb)
{
	utun_crypto_ctx_t *crypto_ctx;

	lck_mtx_lock(&dtls_ctl_mutex);

	//printf("%s: entering, flags %x, kpi-handle %d, kpi-ref %p, kpi-refcnt %d\n", __FUNCTION__, pcb->utun_flags, crypto_ctx->kpi_handle, crypto_ctx->kpi_ref, crypto_ctx->kpi_refcnt);
	
	crypto_ctx = &pcb->utun_crypto_ctx[UTUN_CRYPTO_DIR_TO_IDX(UTUN_CRYPTO_DIR_IN)];
	if (crypto_ctx->valid &&
	    crypto_ctx->type == UTUN_CRYPTO_TYPE_DTLS) {
		utun_ctl_clr_dtls_all_framers(crypto_ctx);
	}

	crypto_ctx = &pcb->utun_crypto_ctx[UTUN_CRYPTO_DIR_TO_IDX(UTUN_CRYPTO_DIR_OUT)];
	if (!crypto_ctx->valid ||
	    crypto_ctx->type != UTUN_CRYPTO_TYPE_DTLS) {
		lck_mtx_unlock(&dtls_ctl_mutex);
		return;
	}
	if (crypto_ctx->kpi_ref) {
		if (dtls_kpi_connect) {
			(void)dtls_kpi_connect(crypto_ctx->kpi_handle, NULL);
			if (--crypto_ctx->kpi_refcnt == 0) {
				crypto_ctx->kpi_ref = (__typeof__(crypto_ctx->kpi_ref))NULL;
				crypto_ctx->kpi_handle = UTUN_CRYPTO_DTLS_HANDLE_INVALID;
			} else {
			  //				printf("%s: ### dtls_kpi_refcnt %d not yet zero\n",
			  //				       __FUNCTION__, crypto_ctx->kpi_refcnt);
			}
		} else {
			printf("%s: ### dtls_ctl_connect unavailable\n", __FUNCTION__);
			lck_mtx_unlock(&dtls_ctl_mutex);
			return;
		}
	} else {
		if (crypto_ctx->kpi_handle < 0) {
			printf("%s: dtls already disabled\n", __FUNCTION__);
			lck_mtx_unlock(&dtls_ctl_mutex);
			return;
		}
		crypto_ctx->kpi_handle = UTUN_CRYPTO_DTLS_HANDLE_INVALID;
	}
	utun_ctl_clr_dtls_all_framers(crypto_ctx);
	lck_mtx_unlock(&dtls_ctl_mutex);
	return;
}

static utun_crypto_framer_t *
utun_ctl_get_dtls_in_framer (utun_crypto_framer_t            *first_framer,
			     u_int8_t                        *in_pattern,
			     int                              in_pattern_len,
			     u_int8_t                        *in_pattern_mask,
			     int                              in_pattern_mask_len)
{
	utun_crypto_framer_t *cur_framer;

	// check framer->u.listhead for duplicates;
	for (cur_framer = first_framer;
	     cur_framer != NULL;
	     cur_framer = (__typeof__(cur_framer))LIST_NEXT(cur_framer, framer_chain)) {
		// TOFIX: use in_pattern_masked
		if (utun_crypto_framer_state_dtls_in(cur_framer).in_pattern_len == in_pattern_len &&
		    memcmp(utun_crypto_framer_state_dtls_in(cur_framer).in_pattern,
			   in_pattern,
			   in_pattern_len) == 0 &&
		    utun_crypto_framer_state_dtls_in(cur_framer).in_pattern_len == in_pattern_mask_len &&
		    memcmp(utun_crypto_framer_state_dtls_in(cur_framer).in_pattern_mask,
			   in_pattern_mask,
			   in_pattern_mask_len) == 0) {
			// found
			return cur_framer;
		}
	}

	return NULL;
}

errno_t
utun_ctl_config_crypto_dtls_framer (utun_crypto_ctx_t         *crypto_ctx,
				    utun_crypto_framer_args_t *args)
{
	utun_crypto_framer_t *framer, *new_framer = NULL, *dup_framer;

	if (args->ver != UTUN_CRYPTO_DTLS_VER_1) {
		return EINVAL;
	}
	if (!args->type || args->type >= UTUN_CRYPTO_INNER_TYPE_MAX) {
		return EINVAL;
	}

	lck_mtx_lock(&dtls_ctl_mutex);

	if (args->dir == UTUN_CRYPTO_DIR_IN) {
		// Input framer (for tunnel hdr detection and decapsulation). there can be several pattern that identify data (vs. control) packets.

		// First, the args need to be verified for errors/inconsistencies
		// pattern and mask have to be configured
		if (!utun_crypto_framer_args_dtls_in(args).in_pattern_len ||
		    !utun_crypto_framer_args_dtls_in(args).in_pattern_mask_len) {
			lck_mtx_unlock(&dtls_ctl_mutex);
			printf("%s: invalid dtls in-pattern %d mask %d\n", __FUNCTION__, 
			       utun_crypto_framer_args_dtls_in(args).in_pattern_len,
			       utun_crypto_framer_args_dtls_in(args).in_pattern_mask_len);
			return EINVAL;
		}
		// pattern and mask lengths have to match
		if (utun_crypto_framer_args_dtls_in(args).in_pattern_len != utun_crypto_framer_args_dtls_in(args).in_pattern_mask_len) {
			lck_mtx_unlock(&dtls_ctl_mutex);
			printf("%s: inconsistent dtls in-pattern %d mask %d\n",__FUNCTION__, 
			       utun_crypto_framer_args_dtls_in(args).in_pattern_len,
			       utun_crypto_framer_args_dtls_in(args).in_pattern_mask_len);
			return EINVAL;
		}
		// check for len inconsistencies
		if ((u_int32_t)utun_crypto_framer_args_dtls_in(args).in_pattern_len + (u_int32_t)utun_crypto_framer_args_dtls_in(args).in_pattern_mask_len != args->varargs_buflen) {
			lck_mtx_unlock(&dtls_ctl_mutex);
			printf("%s: inconsistent dtls in-pattern %d mask %d, total %d\n",__FUNCTION__, 
			       utun_crypto_framer_args_dtls_in(args).in_pattern_len,
			       utun_crypto_framer_args_dtls_in(args).in_pattern_mask_len,
			       args->varargs_buflen);
			return EINVAL;
		}
		// utun_crypto_framer_args_dtls_in(args).in_pattern should not be all zeros
		if (is_pattern_all_zeroes(&args->varargs_buf[0],
					  utun_crypto_framer_args_dtls_in(args).in_pattern_len)) {
			lck_mtx_unlock(&dtls_ctl_mutex);
			printf("%s: in-pattern is all zeros, len %d\n",__FUNCTION__, 
			       utun_crypto_framer_args_dtls_in(args).in_pattern_len);
			return EINVAL;
		}
		// utun_crypto_framer_args_dtls_in(args).in_pattern_mask should not be all zeros
		if (is_pattern_all_zeroes(&args->varargs_buf[utun_crypto_framer_args_dtls_in(args).in_pattern_len],
					  utun_crypto_framer_args_dtls_in(args).in_pattern_mask_len)) {
			lck_mtx_unlock(&dtls_ctl_mutex);
			printf("%s: in-pattern-mask is all zeros, len %d\n",__FUNCTION__, 
			       utun_crypto_framer_args_dtls_in(args).in_pattern_mask_len);
			return EINVAL;
		}
		// utun_crypto_framer_args_dtls_in(args).in_pattern & utun_crypto_framer_args_dtls_in(args).in_pattern_mask should not be zeros
		if (is_pattern_masked_all_zeroes(&args->varargs_buf[0],
						 &args->varargs_buf[utun_crypto_framer_args_dtls_in(args).in_pattern_len],
						 utun_crypto_framer_args_dtls_in(args).in_pattern_len)) {
			lck_mtx_unlock(&dtls_ctl_mutex);
			printf("%s: in-pattern-masked is all zeros, len %d\n",__FUNCTION__, 
			       utun_crypto_framer_args_dtls_in(args).in_pattern_mask_len);
			return EINVAL;
		}

		// Secondly, we need to be careful about existing framer configs
		if (!(framer = utun_ctl_get_first_framer(crypto_ctx, args->inner_type))) {
			// no framers configured
			if (!(framer = utun_alloc(sizeof(*framer)))) {
				lck_mtx_unlock(&dtls_ctl_mutex);
				return ENOBUFS;
			}
			bzero(framer, sizeof(*framer));
			// fall through to fill-in the 1st framer
		} else {
			// at least one framer configured... check framer->u.listhead for duplicates;
			if ((dup_framer = utun_ctl_get_dtls_in_framer(framer /* could be a list */,
								      &args->varargs_buf[0],
								      utun_crypto_framer_args_dtls_in(args).in_pattern_len,
								      &args->varargs_buf[utun_crypto_framer_args_dtls_in(args).in_pattern_len],
								      utun_crypto_framer_args_dtls_in(args).in_pattern_mask_len))) {
				// duplicate
				lck_mtx_unlock(&dtls_ctl_mutex);
				printf("%s: ignoring duplicate framer for type %d\n",__FUNCTION__, 
				       args->inner_type);
				return 0;
			}

			if (!(new_framer = utun_alloc(sizeof(*new_framer)))) {
				lck_mtx_unlock(&dtls_ctl_mutex);
				return ENOBUFS;
			}
			bzero(new_framer, sizeof(*new_framer));
			framer = new_framer;
			// fall through to fill-in additional framer
		}
		LIST_INSERT_HEAD(utun_get_framer_listhead(crypto_ctx, args->inner_type),
						 new_framer,
						 framer_chain);

		framer->inner_type = args->inner_type;
		framer->inner_protocol_family = utun_crypto_framer_inner_type_to_protocol_family(args->inner_type);
		// allocate and fill the pattern
		if (!(utun_crypto_framer_state_dtls_in(framer).in_pattern = utun_alloc(utun_crypto_framer_args_dtls_in(args).in_pattern_len))) {
			utun_ctl_clr_dtls_framer(framer);
			lck_mtx_unlock(&dtls_ctl_mutex);
			return ENOBUFS;
		}
		memcpy(utun_crypto_framer_state_dtls_in(framer).in_pattern,
		       &args->varargs_buf[0],
		       utun_crypto_framer_args_dtls_in(args).in_pattern_len);
		utun_crypto_framer_state_dtls_in(framer).in_pattern_len = utun_crypto_framer_args_dtls_in(args).in_pattern_len;

		// allocate and fill the pattern-mask
		if (!(utun_crypto_framer_state_dtls_in(framer).in_pattern_mask = utun_alloc(utun_crypto_framer_args_dtls_in(args).in_pattern_mask_len))) {
			utun_ctl_clr_dtls_framer(framer);
			lck_mtx_unlock(&dtls_ctl_mutex);
			return ENOBUFS;
		}
		memcpy(utun_crypto_framer_state_dtls_in(framer).in_pattern_mask,
		       &args->varargs_buf[utun_crypto_framer_args_dtls_in(args).in_pattern_len],
		       utun_crypto_framer_args_dtls_in(args).in_pattern_mask_len);
		utun_crypto_framer_state_dtls_in(framer).in_data_offset = utun_crypto_framer_args_dtls_in(args).in_data_offset;

		if (!(utun_crypto_framer_state_dtls_in(framer).in_pattern_masked = utun_alloc(utun_crypto_framer_args_dtls_in(args).in_pattern_len))) {
			utun_ctl_clr_dtls_framer(framer);
			lck_mtx_unlock(&dtls_ctl_mutex);
			return ENOBUFS;
		}
		utun_ctl_calc_dtls_framer_pattern_and_mask(utun_crypto_framer_state_dtls_in(framer).in_pattern_masked,
							   utun_crypto_framer_state_dtls_in(framer).in_pattern,
							   utun_crypto_framer_state_dtls_in(framer).in_pattern_mask,
							   utun_crypto_framer_state_dtls_in(framer).in_pattern_len);
		// TOFIX: switch to BPF
		crypto_ctx->num_framers++;
	} else {
		// Output Framer (for tunnel hdr encapsulation)... there can only be one for each type of traffic (see caller of this function)

		// pattern and mask have to be configured
		if (!utun_crypto_framer_args_dtls_out(args).out_pattern_len) {
			lck_mtx_unlock(&dtls_ctl_mutex);
			printf("%s: invalid output framer, len %d\n",__FUNCTION__, 
			       utun_crypto_framer_args_dtls_out(args).out_pattern_len);
			return EINVAL;
		}
		// utun_crypto_framer_args_dtls_out(args).out_pattern should not be all zeros;
		if (is_pattern_all_zeroes(&args->varargs_buf[0],
					  utun_crypto_framer_args_dtls_out(args).out_pattern_len)) {
			lck_mtx_unlock(&dtls_ctl_mutex);
			printf("%s: zeroed output framer, len %d\n",__FUNCTION__, 
			       utun_crypto_framer_args_dtls_out(args).out_pattern_len);
			return EINVAL;
		}

		// can't have the offset/extra configured while the mask is cleared
		if ((utun_crypto_framer_args_dtls_out(args).len_field_offset || utun_crypto_framer_args_dtls_out(args).len_field_extra) && !utun_crypto_framer_args_dtls_out(args).len_field_mask) {
			lck_mtx_unlock(&dtls_ctl_mutex);
			printf("%s: output framer has invalid length-field %d,%d,%x\n",__FUNCTION__, 
			       (int)utun_crypto_framer_args_dtls_out(args).len_field_offset,
			       (int)utun_crypto_framer_args_dtls_out(args).len_field_extra,
			       utun_crypto_framer_args_dtls_out(args).len_field_mask);
			return EINVAL;
		}
		// any length field should be within the bounds of the out-pattern
		if (utun_crypto_framer_args_dtls_out(args).len_field_offset >= utun_crypto_framer_args_dtls_out(args).out_pattern_len) {
			lck_mtx_unlock(&dtls_ctl_mutex);
			return EINVAL;
		}

		// can't have the offset configured while the mask is cleared
		if ((utun_crypto_framer_args_dtls_out(args).sequence_field || utun_crypto_framer_args_dtls_out(args).sequence_field_offset) && !utun_crypto_framer_args_dtls_out(args).sequence_field_mask) {
			lck_mtx_unlock(&dtls_ctl_mutex);
			printf("%s: output framer has invalid sequence-field %d,%d,%x\n",__FUNCTION__, 
			       (int)utun_crypto_framer_args_dtls_out(args).sequence_field,
			       (int)utun_crypto_framer_args_dtls_out(args).sequence_field_offset,
			       utun_crypto_framer_args_dtls_out(args).sequence_field_mask);
			return EINVAL;
		}
		// any sequence field should be within the bounds of the out-pattern
		if (utun_crypto_framer_args_dtls_out(args).sequence_field_offset >= utun_crypto_framer_args_dtls_out(args).out_pattern_len) {
			lck_mtx_unlock(&dtls_ctl_mutex);
			return EINVAL;
		}

		// check for len inconsistencies
		if ((u_int32_t)utun_crypto_framer_args_dtls_out(args).out_pattern_len != args->varargs_buflen) {
			lck_mtx_unlock(&dtls_ctl_mutex);
			return EINVAL;
		}

		if (!(framer = utun_ctl_get_first_framer(crypto_ctx, args->inner_type))) {
			if (!(framer = utun_alloc(sizeof(*framer)))) {
				lck_mtx_unlock(&dtls_ctl_mutex);
				return ENOBUFS;
			}
			bzero(framer, sizeof(*framer));
			LIST_INSERT_HEAD(utun_get_framer_listhead(crypto_ctx, args->inner_type),
							 new_framer,
							 framer_chain);
			// fall through to fill-in 1st framer
		} else {
			// only one outbound framer may be configured.. is it a dup?
			if (framer->inner_type == args->inner_type &&
			    utun_crypto_framer_state_dtls_out(framer).out_pattern_len == utun_crypto_framer_args_dtls_out(args).out_pattern_len &&
			    utun_crypto_framer_state_dtls_out(framer).out_pattern &&
			    memcmp(utun_crypto_framer_state_dtls_out(framer).out_pattern,
				   &args->varargs_buf[0],
				   utun_crypto_framer_args_dtls_out(args).out_pattern_len) == 0) {
				// found
				lck_mtx_unlock(&dtls_ctl_mutex);
				return 0;
			}

			// overwrite the previous one
			if (utun_crypto_framer_state_dtls_out(framer).out_pattern) {
				utun_free(utun_crypto_framer_state_dtls_out(framer).out_pattern);
			}
			// fall through to fill-in additional framer
		}

		framer->inner_type = args->inner_type;
		framer->inner_protocol_family = utun_crypto_framer_inner_type_to_protocol_family(args->inner_type);

		// alloc and fill in the out-pattern
		if (!(utun_crypto_framer_state_dtls_out(framer).out_pattern = utun_alloc(utun_crypto_framer_args_dtls_out(args).out_pattern_len))) {
			utun_ctl_clr_dtls_framer(framer);
			lck_mtx_unlock(&dtls_ctl_mutex);
			return ENOBUFS;
		}
		memcpy(utun_crypto_framer_state_dtls_out(framer).out_pattern,
		       &args->varargs_buf[0],
		       utun_crypto_framer_args_dtls_out(args).out_pattern_len);
		utun_crypto_framer_state_dtls_out(framer).out_pattern_len = utun_crypto_framer_args_dtls_out(args).out_pattern_len;

		utun_crypto_framer_state_dtls_out(framer).len_field_mask = utun_crypto_framer_args_dtls_out(args).len_field_mask;
		utun_crypto_framer_state_dtls_out(framer).len_field_offset = utun_crypto_framer_args_dtls_out(args).len_field_offset;
		utun_crypto_framer_state_dtls_out(framer).len_field_extra = utun_crypto_framer_args_dtls_out(args).len_field_extra;
		utun_crypto_framer_state_dtls_out(framer).sequence_field_initval = utun_crypto_framer_args_dtls_out(args).sequence_field;
		utun_crypto_framer_state_dtls_out(framer).sequence_field_mask = utun_crypto_framer_args_dtls_out(args).sequence_field_mask;
		utun_crypto_framer_state_dtls_out(framer).sequence_field_offset = utun_crypto_framer_args_dtls_out(args).sequence_field_offset;
		crypto_ctx->num_framers = 1;
	}
	framer->type = args->type;
	framer->dir = args->dir;
	framer->valid = 1;

	lck_mtx_unlock(&dtls_ctl_mutex);
	return 0;
}

int
utun_ctl_unconfig_crypto_dtls_framer (utun_crypto_ctx_t         *crypto_ctx,
				      utun_crypto_framer_args_t *args)
{
	utun_crypto_framer_t *framer, *rem_framer;

	if (args->ver != UTUN_CRYPTO_DTLS_VER_1) {
		return EINVAL;
	}
	if (!args->type || args->type >= UTUN_CRYPTO_INNER_TYPE_MAX) {
		return EINVAL;
	}

	lck_mtx_lock(&dtls_ctl_mutex);

	if (args->dir == UTUN_CRYPTO_DIR_IN) {
		if (!utun_crypto_framer_args_dtls_in(args).in_pattern_len) {
			// no pattern means... clear all
			utun_ctl_clr_dtls_framers(utun_ctl_get_first_framer(crypto_ctx, args->inner_type));
			lck_mtx_unlock(&dtls_ctl_mutex);
			return 0;
		}

		// when both specified, pattern and mask lengths have to match
		if (utun_crypto_framer_args_dtls_in(args).in_pattern_mask_len &&
		    utun_crypto_framer_args_dtls_in(args).in_pattern_len != utun_crypto_framer_args_dtls_in(args).in_pattern_mask_len) {
			lck_mtx_unlock(&dtls_ctl_mutex);
			return EINVAL;
		}
		// check for len inconsistencies
		if ((u_int32_t)utun_crypto_framer_args_dtls_in(args).in_pattern_len + (u_int32_t)utun_crypto_framer_args_dtls_in(args).in_pattern_mask_len != args->varargs_buflen) {
			lck_mtx_unlock(&dtls_ctl_mutex);
			return EINVAL;
		}
		// utun_crypto_framer_args_dtls_in(args).in_pattern should not be all zeros
		if (is_pattern_all_zeroes(&args->varargs_buf[0],
					  utun_crypto_framer_args_dtls_in(args).in_pattern_len)) {
			lck_mtx_unlock(&dtls_ctl_mutex);
			return EINVAL;
		}
		// when specified, utun_crypto_framer_args_dtls_in(args).in_pattern_mask should not be all zeros
		if (utun_crypto_framer_args_dtls_in(args).in_pattern_mask_len &&
		    is_pattern_all_zeroes(&args->varargs_buf[utun_crypto_framer_args_dtls_in(args).in_pattern_len],
					  utun_crypto_framer_args_dtls_in(args).in_pattern_mask_len)) {
			lck_mtx_unlock(&dtls_ctl_mutex);
			return EINVAL;
		}
		// utun_crypto_framer_args_dtls_in(args).in_pattern & utun_crypto_framer_args_dtls_in(args).in_pattern_mask should not be zeros
		if (is_pattern_masked_all_zeroes(&args->varargs_buf[0],
						 &args->varargs_buf[utun_crypto_framer_args_dtls_in(args).in_pattern_len],
						 utun_crypto_framer_args_dtls_in(args).in_pattern_len)) {
			lck_mtx_unlock(&dtls_ctl_mutex);
			return EINVAL;
		}

		if ((u_int32_t)utun_crypto_framer_args_dtls_in(args).in_pattern_len + (u_int32_t)utun_crypto_framer_args_dtls_in(args).in_pattern_mask_len != args->varargs_buflen) {
			lck_mtx_unlock(&dtls_ctl_mutex);
			return EINVAL;
		}

		if (!(framer = utun_ctl_get_first_framer(crypto_ctx, args->inner_type))) {
			// no framers
			printf("%s: no framers configured\n", __FUNCTION__);
			lck_mtx_unlock(&dtls_ctl_mutex);
			return 0;
		} else {
			if ((rem_framer = utun_ctl_get_dtls_in_framer(framer,
								      &args->varargs_buf[0],
								      utun_crypto_framer_args_dtls_in(args).in_pattern_len,
								      &args->varargs_buf[utun_crypto_framer_args_dtls_in(args).in_pattern_len],
								      utun_crypto_framer_args_dtls_in(args).in_pattern_mask_len))) {
				utun_ctl_clr_dtls_framer(rem_framer);
				if (crypto_ctx->num_framers) crypto_ctx->num_framers--;
			} else {
				printf("%s: no matching ingress framer\n", __FUNCTION__);
			}
			lck_mtx_unlock(&dtls_ctl_mutex);
			return 0;
		}
	} else {
		framer = utun_ctl_get_first_framer(crypto_ctx, args->inner_type);
		// overwrite the previous one
		if (framer) {
			if (framer->inner_type != args->inner_type ||
				(utun_crypto_framer_args_dtls_out(args).out_pattern_len &&
				 utun_crypto_framer_state_dtls_out(framer).out_pattern_len != utun_crypto_framer_args_dtls_out(args).out_pattern_len) ||
				(utun_crypto_framer_args_dtls_out(args).out_pattern_len &&
				 memcmp(utun_crypto_framer_state_dtls_out(framer).out_pattern,
						&args->varargs_buf[0],
						utun_crypto_framer_args_dtls_out(args).out_pattern_len))) {
					printf("%s: no matching egress framer\n", __FUNCTION__);
					lck_mtx_unlock(&dtls_ctl_mutex);
					return EBADF;
			}
			utun_ctl_clr_dtls_framer(framer);
			if (crypto_ctx->num_framers) crypto_ctx->num_framers--;
		}
	}

	lck_mtx_unlock(&dtls_ctl_mutex);
	return 0;
}

/*
 * Summary: enables handling of data traffic
 */
void
utun_ctl_start_datatraffic_crypto_dtls(struct utun_pcb   *pcb)
{
	utun_crypto_ctx_t *crypto_ctx;

	lck_mtx_lock(&dtls_ctl_mutex);

	//printf("%s: entering, flags %x, kpi-handle %d, kpi-ref %p, kpi-refcnt %d\n", __FUNCTION__, pcb->utun_flags, crypto_ctx->kpi_handle, crypto_ctx->kpi_ref, crypto_ctx->kpi_refcnt);
	
	crypto_ctx = &pcb->utun_crypto_ctx[UTUN_CRYPTO_DIR_TO_IDX(UTUN_CRYPTO_DIR_OUT)];

	if (crypto_ctx->kpi_handle < 0) {
		printf("%s: dtls disabled\n", __FUNCTION__);
		lck_mtx_unlock(&dtls_ctl_mutex);
		return;
	}

	if (!crypto_ctx->kpi_ref) {
		if (dtls_kpi_connect) {
			crypto_ctx->kpi_ref = dtls_kpi_connect(crypto_ctx->kpi_handle, pcb);
			if (!crypto_ctx->kpi_ref) {
				printf("%s: ### dtls_kpi_connect failed\n", __FUNCTION__);
				lck_mtx_unlock(&dtls_ctl_mutex);
				return;
			}
			crypto_ctx->kpi_refcnt++;
		} else {
			printf("%s: ### dtls_kpi_connect unavailable\n", __FUNCTION__);
			lck_mtx_unlock(&dtls_ctl_mutex);
			return;
		}
	} else {
		printf("%s: dtls already stitched\n", __FUNCTION__);
		lck_mtx_unlock(&dtls_ctl_mutex);
		return;
	}
	utun_ctl_restart_dtls_all_framers(crypto_ctx); // for dynamic egress hdrs

	//printf("%s: leaving, flags %x, kpi-handle %d, kpi-ref %p, kpi-refcnt %d\n", __FUNCTION__, pcb->utun_flags, crypto_ctx->kpi_handle, crypto_ctx->kpi_ref, crypto_ctx->kpi_refcnt);
	lck_mtx_unlock(&dtls_ctl_mutex);
	return;
}

/*
 * Summary: disables handling of data traffic
 */
void
utun_ctl_stop_datatraffic_crypto_dtls(struct utun_pcb   *pcb)
{
	utun_crypto_ctx_t *crypto_ctx;

	lck_mtx_lock(&dtls_ctl_mutex);

	//printf("%s: entering, flags %x, kpi-ref %p, kpi-refcnt %d\n", __FUNCTION__, pcb->utun_flags, crypto_ctx->kpi_ref, crypto_ctx->kpi_refcnt);
	
	crypto_ctx = &pcb->utun_crypto_ctx[UTUN_CRYPTO_DIR_TO_IDX(UTUN_CRYPTO_DIR_OUT)];

	if (crypto_ctx->kpi_ref) {
		if (dtls_kpi_connect) {
			(void)dtls_kpi_connect(crypto_ctx->kpi_handle, NULL);
			if (--crypto_ctx->kpi_refcnt == 0) {
				crypto_ctx->kpi_ref = (__typeof__(crypto_ctx->kpi_ref))NULL;
				crypto_ctx->kpi_handle = UTUN_CRYPTO_DTLS_HANDLE_INVALID;
			} else {
			  //				printf("%s: ### dtls_kpi_refcnt %d not yet zero\n",
			  //				       __FUNCTION__, crypto_ctx->kpi_refcnt);
			}
		} else {
			printf("%s: dtls_kpi_connect unavailable\n", __FUNCTION__);
			lck_mtx_unlock(&dtls_ctl_mutex);
			return;
		}
	} else {
		printf("%s: dtls already not-stitched\n", __FUNCTION__);
		lck_mtx_unlock(&dtls_ctl_mutex);
		return;
	}
	lck_mtx_unlock(&dtls_ctl_mutex);
	return;
}

#define utun_pkt_dtls_prepend_proto(pkt, pf) do {                               \
		if (mbuf_prepend(pkt, sizeof(protocol_family_t), MBUF_DONTWAIT) != 0) { \
			printf("%s - ifnet_output prepend failed\n", __FUNCTION__);         \
			lck_mtx_unlock(&dtls_ctl_mutex);                                    \
			return EBADF;                                                       \
		}                                                                       \
		*(protocol_family_t *)mbuf_data(*pkt) = pf;                             \
	} while(0);

#define utun_pkt_dtls_puntup(pcb, pkt, errstr, rc) do {                                                 \
		*(protocol_family_t *)mbuf_data(*pkt) = htonl(*(protocol_family_t *)mbuf_data(*pkt));           \
		rc = ctl_enqueuembuf(pcb->utun_ctlref, pcb->utun_unit, *pkt, CTL_DATA_EOR);                     \
		if (rc != 0) {                                                                                  \
			printf("%s: - ctl_enqueuembuf failed (rc %d) for %s:\n", __FUNCTION__, rc, errstr); \
			mbuf_freem(*pkt);                                                                           \
			ifnet_stat_increment_out(pcb->utun_ifp, 0, 0, 1);                                           \
			lck_mtx_unlock(&dtls_ctl_mutex);                                                            \
			return 0;                                                                                   \
		}                                                                                               \
		*pkt = NULL;                                                                                    \
	} while(0);

int
utun_pkt_dtls_output(struct utun_pcb *pcb, mbuf_t *pkt)
{
	errno_t            rc = ENETUNREACH;
	int                len;
	utun_crypto_ctx_t *crypto_ctx;
	protocol_family_t  proto;

	//printf("%s: entering, flags %x, ifp %p\n", __FUNCTION__, pcb->utun_flags, pcb->utun_ifp);

	if (!(pcb->utun_flags & UTUN_FLAGS_CRYPTO)) {
		printf("%s - crypto disabled\n", __FUNCTION__);
		return EINVAL;
	}

	if (!pcb->utun_ifp) {
		printf("%s - utun ifp cleared\n", __FUNCTION__);
		return EINVAL;
	}

	proto = *(mtod(*pkt, protocol_family_t *));

	lck_mtx_lock(&dtls_ctl_mutex);

	len = mbuf_pkthdr_len(*pkt);

	crypto_ctx = &pcb->utun_crypto_ctx[UTUN_CRYPTO_DIR_TO_IDX(UTUN_CRYPTO_DIR_OUT)];

	//printf("%s: entering, kpi-handle %d, kpi-ref %p, kpi-refcnt %d\n", __FUNCTION__, crypto_ctx->kpi_handle, crypto_ctx->kpi_ref, crypto_ctx->kpi_refcnt);

	if (dtls_kpi_send && (crypto_ctx->kpi_handle >= 0) && crypto_ctx->kpi_ref) {
		m_adj(*pkt, sizeof(protocol_family_t));

		if (!(rc = utun_pkt_dtls_output_frame_encapsulate(crypto_ctx, pkt, proto))) {
			rc = dtls_kpi_send(crypto_ctx->kpi_ref, pkt);
			if (rc) {
				printf("%s: DTLS failed to send pkt %d\n", __FUNCTION__, rc);
				// <rdar://problem/11385397> 
				// dtls_kpi_send (by way of so_inject_data_out) frees mbuf during certain error cases, 
				ifnet_stat_increment_out(pcb->utun_ifp, 0, 0, 1); // increment errors
				lck_mtx_unlock(&dtls_ctl_mutex);
				return 0; // and drop packet
			}
		} else if (rc == EINVAL) {
			// unsupported proto... fall through and punt (but 1st undo the protocol strip)
			utun_pkt_dtls_prepend_proto(pkt, proto);
			utun_pkt_dtls_puntup(pcb, pkt, "unsupported proto", rc);
		} else {
			// mbuf_prepend failure... mbuf will be already freed
			printf("%s: failed to encrypsulate and send pkt %d\n", __FUNCTION__,rc);
			ifnet_stat_increment_out(pcb->utun_ifp, 0, 0, 1); // increment errors
			lck_mtx_unlock(&dtls_ctl_mutex);
			return 0; // and drop packet
		}
	} else {
		utun_pkt_dtls_puntup(pcb, pkt, "slowpath", rc);
	}

	if (!rc)
		ifnet_stat_increment_out(pcb->utun_ifp, 1, len, 0);

	lck_mtx_unlock(&dtls_ctl_mutex);
	return rc;
}

int
utun_pkt_dtls_input(struct utun_pcb *pcb, mbuf_t *pkt, __unused protocol_family_t family)
{
	utun_crypto_ctx_t *crypto_ctx;
	int                striplen = 0;

	//printf("%s: got pkt %d\n", __FUNCTION__,family);
	if (!(pcb->utun_flags & UTUN_FLAGS_CRYPTO)) {
		printf("%s - crypto disabled\n", __FUNCTION__);
		return EINVAL;
	}

	if (!pcb->utun_ifp) {
		printf("%s - utun ifp cleared\n", __FUNCTION__);
		return EINVAL;
	}

	lck_mtx_lock(&dtls_ctl_mutex);

	/*
	 * make sure that family matches what the UTUN was configured for (punt those that don't... along with all that fail to match the data pattern.
	 */
	crypto_ctx = &pcb->utun_crypto_ctx[UTUN_CRYPTO_DIR_TO_IDX(UTUN_CRYPTO_DIR_IN)];
	if (crypto_ctx->num_framers &&
	    !utun_pkt_dtls_input_frame_is_data(crypto_ctx, pkt, AF_INET, &striplen) &&
	    !utun_pkt_dtls_input_frame_is_data(crypto_ctx, pkt, AF_INET6, &striplen)) {
		// control or unknown traffic, so punt up to the plugin
		errno_t rc;

		utun_pkt_dtls_prepend_proto(pkt, family);
		*(protocol_family_t *)mbuf_data(*pkt) = htonl(*(protocol_family_t *)mbuf_data(*pkt));
		rc = ctl_enqueuembuf(pcb->utun_ctlref, pcb->utun_unit, *pkt, CTL_DATA_EOR);
		if (rc != 0) {
			// drop packet
	  		printf("%s: - ctl_enqueuembuf failed: %d\n", __FUNCTION__, rc);
			mbuf_freem(*pkt);
			lck_mtx_unlock(&dtls_ctl_mutex);
			return rc;
		}
		printf("%s: - ctl_enqueuembuf punted a packet up to UTUN ctrl sock: %d\n", __FUNCTION__, rc);
		ifnet_stat_increment_in(pcb->utun_ifp, 1, mbuf_pkthdr_len(*pkt), 0);

		*pkt = NULL;
		lck_mtx_unlock(&dtls_ctl_mutex);
		return 0;
	}
	if (striplen) {
		//printf("%s: - about to strip tunneled hdr of len %d\n", __FUNCTION__, striplen);
		m_adj(*pkt, striplen);
	}

	utun_pkt_dtls_prepend_proto(pkt, family);

	ifnet_stat_increment_in(pcb->utun_ifp, 1, mbuf_pkthdr_len(*pkt), 0);

	(void)utun_pkt_input(pcb, *pkt);
	lck_mtx_unlock(&dtls_ctl_mutex);
	return 0;
}
