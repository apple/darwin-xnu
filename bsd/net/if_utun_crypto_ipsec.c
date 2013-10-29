/*
 * Copyright (c) 2011-2013 Apple Inc. All rights reserved.
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

#if IPSEC

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
#include <net/if_utun_crypto_ipsec.h>
#include <netinet6/esp.h>
#include <netinet6/esp6.h>
#include <netinet6/ipsec.h>
#include <net/bpf.h>

extern lck_mtx_t *sadb_mutex;
extern int        esp_udp_encap_port; // udp encap listening port
extern int        ipsec_policy_count;
extern int        ipsec_bypass;
extern int        natt_keepalive_interval;

static int        utun_punt_rx_keepalive = 0; // optional global control

extern errno_t utun_pkt_input (struct utun_pcb *pcb, mbuf_t m);

static u_int8_t
utun_ipsec_mode_to_sadb_mode (if_utun_crypto_ipsec_mode_t mode)
{
	switch (mode) {
	case IF_UTUN_CRYPTO_IPSEC_MODE_TRANSPORT:
		return IPSEC_MODE_TRANSPORT;
	case IF_UTUN_CRYPTO_IPSEC_MODE_TUNNEL:
		return IPSEC_MODE_TUNNEL;
	default:
		return 0;
	}
}

static u_int16_t
utun_ipsec_proto_to_sadb_proto (if_utun_crypto_ipsec_proto_t proto)
{
	switch (proto) {
		case IF_UTUN_CRYPTO_IPSEC_PROTO_ESP:
			return IPPROTO_ESP;
		case IF_UTUN_CRYPTO_IPSEC_PROTO_AH:
			return IPPROTO_AH;
		default:
			return 0;
    }
}

static u_int8_t
utun_ipsec_proto_to_sadb_satype (if_utun_crypto_ipsec_proto_t proto)
{
	switch (proto) {
	case IF_UTUN_CRYPTO_IPSEC_PROTO_ESP:
		return SADB_SATYPE_ESP;
	case IF_UTUN_CRYPTO_IPSEC_PROTO_AH:
		return SADB_SATYPE_AH;
	default:
		return 0;
    }
}

static u_int8_t
utun_ipsec_auth_to_sadb_aalg (if_utun_crypto_ipsec_auth_t auth)
{
	switch (auth) {
	case IF_UTUN_CRYPTO_IPSEC_AUTH_MD5:
		return SADB_AALG_MD5HMAC;
	case IF_UTUN_CRYPTO_IPSEC_AUTH_SHA1:
		return SADB_AALG_SHA1HMAC;
	case IF_UTUN_CRYPTO_IPSEC_AUTH_SHA256:
		return SADB_X_AALG_SHA2_256;
	case IF_UTUN_CRYPTO_IPSEC_AUTH_SHA384:
		return SADB_X_AALG_SHA2_384;
	case IF_UTUN_CRYPTO_IPSEC_AUTH_SHA512:
		return SADB_X_AALG_SHA2_512;
	default:
		return 0;
	}
}

static u_int8_t
utun_ipsec_enc_to_sadb_ealg (if_utun_crypto_ipsec_enc_t enc)
{
	switch (enc) {
	case IF_UTUN_CRYPTO_IPSEC_ENC_DES:
		return SADB_EALG_DESCBC;
	case IF_UTUN_CRYPTO_IPSEC_ENC_3DES:
		return SADB_EALG_3DESCBC;
	case IF_UTUN_CRYPTO_IPSEC_ENC_AES128:
	case IF_UTUN_CRYPTO_IPSEC_ENC_AES256:
		return SADB_X_EALG_AESCBC;
	default:
		return 0;
	}
}

static u_int32_t
utun_ipsec_keepalive_and_nat_info_to_sadb_flags (if_utun_crypto_ipsec_keepalive_t keepalive,
						 int                              punt_rx_keepalive,
						 if_utun_crypto_ipsec_natd_t      natd,
						 u_int16_t                        natt_port)
{
	u_int32_t flags = 0;

	if (natt_port && natt_port != 500) {
		flags |= SADB_X_EXT_NATT;

		switch (keepalive) {
		case IF_UTUN_CRYPTO_IPSEC_KEEPALIVE_NATT:
			flags |= SADB_X_EXT_NATT_KEEPALIVE; // normal keepalive packet
			break;
		case IF_UTUN_CRYPTO_IPSEC_KEEPALIVE_ESP:
			flags |= (SADB_X_EXT_ESP_KEEPALIVE | SADB_X_EXT_PUNT_RX_KEEPALIVE); // use an EMPTY ESP as a keepalive 
			break;
		default:
			break;
		}

		switch (natd) {
		case IF_UTUN_CRYPTO_IPSEC_NATD_PEER:
			flags |= SADB_X_EXT_NATT_DETECTED_PEER;
			break;
		default:
			break;
		}
	}

	if (punt_rx_keepalive) {
		flags |= SADB_X_EXT_PUNT_RX_KEEPALIVE;
	}

	return flags;
}

static errno_t
utun_ipsec_set_sah (struct secashead        **sah,
		    u_int8_t                  dir,
		    u_int16_t                 proto,
		    u_int8_t                  mode,
		    u_int32_t                 reqid,
		    struct sockaddr_storage  *src_addr,
		    struct sockaddr_storage  *dst_addr)
{
	struct secasindex saidx;

	// currently only support tunnel mode and ESP
	if (proto != IPPROTO_ESP ||
	    mode != IPSEC_MODE_TUNNEL) {
		return EINVAL;
	}
	if ((((struct sockaddr *)src_addr)->sa_family != AF_INET &&
	     ((struct sockaddr *)src_addr)->sa_family != AF_INET6) ||
	    (((struct sockaddr *)dst_addr)->sa_family != AF_INET &&
	     ((struct sockaddr *)dst_addr)->sa_family != AF_INET6)) {
		return EINVAL;
	}

	bzero(&saidx, sizeof(saidx));
	saidx.proto = proto;
	saidx.mode = mode;
	saidx.reqid = reqid;
	bcopy(src_addr, &saidx.src, sizeof(saidx.src)); 
	bcopy(dst_addr, &saidx.dst, sizeof(saidx.dst)); 

	lck_mtx_lock(sadb_mutex);
	// TODO: add sah and policy (collision) check and prevention. ensure that there is no conflicting policy.
	// TDDO: ensure that key_spdaddxxx doesn't add a policy that's conflicting with any of our sahs.
	*sah = key_newsah2(&saidx, dir);
	lck_mtx_unlock(sadb_mutex);
	return 0;
}

static int
utun_ipsec_clr_sahs (struct secashead **sah)
{
	struct secasvar *sav;
	struct secasvar *nextsav;
	u_int            state;

	lck_mtx_lock(sadb_mutex);
	for (state = 0; state < SADB_SASTATE_MAX; state++) {
		for (sav = LIST_FIRST(&(*sah)->savtree[state]);
		     sav != NULL;
		     sav = nextsav) {
			nextsav = LIST_NEXT(sav, chain);
			if (sav->state == SADB_SASTATE_LARVAL ||
				sav->state == SADB_SASTATE_DEAD) {
				continue;
			}

			if (sav->utun_pcb) {
				sav->utun_pcb = NULL;
				sav->utun_is_keepalive_fn = NULL;
				sav->utun_in_fn = NULL;
				sav->refcnt--; // unlinked from pcb
			} else {
				printf("%s: SAV inconsistency\n", __FUNCTION__);
			}

			key_sa_chgstate(sav, SADB_SASTATE_DEAD);
			key_freesav(sav, KEY_SADB_LOCKED);
		}
	}

	// clear the rest of the SAs
	key_delsah(*sah);
	lck_mtx_unlock(sadb_mutex);
	return 0;
}

static void
utun_ipsec_set_udp_encap_listen_port (utun_crypto_dir_t dir,
				      u_int16_t         natt_port)
{
	if (dir == UTUN_CRYPTO_DIR_IN) {
		if (natt_port && natt_port != 500) {
			esp_udp_encap_port = natt_port;
		}
	}	
}

static void
utun_set_lifetime (struct sadb_lifetime *lfh,
		   int                   type,
		   u_int64_t             l_time)
{
	lfh->sadb_lifetime_len = (sizeof(*lfh) >> 3); // convert to words
	lfh->sadb_lifetime_exttype = type;
	lfh->sadb_lifetime_allocations = 0;
	lfh->sadb_lifetime_bytes = 0;
	lfh->sadb_lifetime_addtime = l_time;
	lfh->sadb_lifetime_usetime = l_time;
}

static struct sadb_key *
utun_ipsec_set_keybuf (u_int16_t  type,
		       u_int8_t  *key,
		       u_int16_t  key_len)
{
	struct sadb_key *new;
	int len = sizeof(*new) + BITSTOBYTES(key_len);

	lck_mtx_lock(sadb_mutex);
	new = utun_alloc(len);
	if (new == NULL) {
		return NULL;
	}
	lck_mtx_unlock(sadb_mutex);
	bzero(new, len);
	new->sadb_key_len = BITSTOBYTES(key_len);
	new->sadb_key_exttype = type;
	new->sadb_key_bits = key_len;
	bcopy(key, &new[1], new->sadb_key_len);
	return new;
}

static errno_t
utun_ipsec_alloc_sav (struct secashead                *sah,
		      struct secasvar                **sav,
		      struct utun_pcb                 *pcb,
		      u_int8_t                         satype,
		      u_int8_t                         alg_auth,
		      u_int8_t                         alg_enc,
		      u_int32_t                        flags,
		      u_int8_t                         replay,
		      u_int8_t                        *key_auth,
		      u_int16_t                        key_auth_len,
		      u_int8_t                        *key_enc,
		      u_int16_t                        key_enc_len,
		      u_int16_t                        natt_port,
		      u_int32_t                        seq,
		      u_int32_t                        spi,
		      u_int32_t                        pid,
		      u_int64_t                        lifetime_hard,
		      u_int64_t                        lifetime_soft)
{
	struct sadb_key      *keye, *keya;
	struct sadb_lifetime  lfh, lfs;

	if (*sav) {
		return EINVAL;
	}

	bzero(&lfh, sizeof(lfh));
	utun_set_lifetime(&lfh, SADB_EXT_LIFETIME_HARD, lifetime_hard);
	bzero(&lfs, sizeof(lfs));
	utun_set_lifetime(&lfs, SADB_EXT_LIFETIME_SOFT, lifetime_soft);

	if ((keya = utun_ipsec_set_keybuf(SADB_EXT_KEY_AUTH, key_auth, key_auth_len)) == NULL) {
		return ENOBUFS;
	}
	if ((keye = utun_ipsec_set_keybuf(SADB_EXT_KEY_ENCRYPT, key_enc, key_enc_len)) == NULL) {
		utun_free(keya);
		return ENOBUFS;
	}

	lck_mtx_lock(sadb_mutex);
	if ((*sav = key_newsav2(sah,
				satype,
				alg_auth,
				alg_enc,
				flags,
				replay,
				keya,
				key_auth_len,
				keye,
				key_enc_len,
				natt_port,
				seq,
				spi,
				pid,
				&lfh,
				&lfs)) == NULL) {
		lck_mtx_unlock(sadb_mutex);
		utun_free(keya);
		utun_free(keye);
		return ENOBUFS;
	}
	(*sav)->utun_pcb = (__typeof__((*sav)->utun_pcb))pcb;
	(*sav)->utun_is_keepalive_fn = (__typeof__((*sav)->utun_is_keepalive_fn))utun_pkt_is_ipsec_keepalive;
	(*sav)->utun_in_fn = (__typeof__((*sav)->utun_in_fn))utun_pkt_ipsec_input;
	(*sav)->refcnt++; // for the pcb
	lck_mtx_unlock(sadb_mutex);
	utun_free(keya);
	utun_free(keye);
	return 0;
}

static int
utun_ipsec_free_sav (struct secasvar  **sav)
{
	lck_mtx_lock(sadb_mutex);
	if ((*sav)->utun_pcb) {
		(*sav)->utun_pcb = NULL;
		(*sav)->utun_is_keepalive_fn = NULL;
		(*sav)->utun_in_fn = NULL;
	}
	(*sav)->refcnt--; // unlinked from pcb
	key_sa_chgstate(*sav, SADB_SASTATE_DEAD);
	key_freesav(*sav, KEY_SADB_LOCKED);
	lck_mtx_unlock(sadb_mutex);
	*sav = NULL;
	return 0;
}

static int
utun_ipsec_num_savs (struct secashead **sah)
{
	struct secasvar *sav;
	struct secasvar *nextsav;
	u_int            state;
	int              n = 0;

	lck_mtx_lock(sadb_mutex);
	for (state = 0; state < SADB_SASTATE_MAX; state++) {
		for (sav = LIST_FIRST(&(*sah)->savtree[state]);
		     sav != NULL;
		     sav = nextsav) {
			nextsav = LIST_NEXT(sav, chain);
			if (sav->state == SADB_SASTATE_LARVAL ||
			    sav->state == SADB_SASTATE_DYING ||
			    sav->state == SADB_SASTATE_DEAD) {
				continue;
			}

			if (sav->utun_pcb) {
				n++;
			} else {
				printf("%s: SAV inconsistency\n", __FUNCTION__);
			}
		}
	}
	lck_mtx_unlock(sadb_mutex);

	return n;
}

static errno_t
utun_ctl_config_crypto_keys_ipsec_v1 (struct utun_pcb         *pcb,
				      utun_crypto_keys_args_t *args,
				      utun_crypto_keys_t      *crypto_keys)
{
	utun_crypto_keys_ipsec_args_v1_t *args_ipsec_v1 = &args->u.ipsec_v1;
	u_int8_t                         *varargs_buf = UTUN_CRYPTO_KEYS_ARGS_VARARGS_BUF(args);
	errno_t                           err;
	struct secashead                 *sah;
	u_int16_t                         proto;
	u_int8_t                          mode;
	u_int8_t                          satype, aalg, ealg;
	u_int32_t                         flags;
	
	if (args_ipsec_v1->key_auth_len > MAX_KEY_AUTH_LEN_BITS) {
		printf("%s: invalid auth key len %d, max %d\n", __FUNCTION__,
		       args_ipsec_v1->key_auth_len, MAX_KEY_AUTH_LEN_BITS);
		return EINVAL;
	}
	if (args_ipsec_v1->key_enc_len > MAX_KEY_ENC_LEN_BITS) {
		printf("%s: invalid enc key len %d, max %d\n", __FUNCTION__,
		       args_ipsec_v1->key_enc_len, MAX_KEY_ENC_LEN_BITS);
		return EINVAL;
	}
	if (args->varargs_buflen != (__typeof__(args->varargs_buflen))((BITSTOBYTES(args_ipsec_v1->key_auth_len) + 
									BITSTOBYTES(args_ipsec_v1->key_enc_len)))) {
		printf("%s: len check failed (%d,%d, %d)\n", __FUNCTION__,
		       args->varargs_buflen, args_ipsec_v1->key_auth_len, args_ipsec_v1->key_enc_len);
		return EINVAL;
	}
	sah = IF_UTUN_GET_CRYPTO_KEYS_IPSEC_SAH(crypto_keys);
	if (!sah) {
		// TODO: make sure we pass through this once
		proto = utun_ipsec_proto_to_sadb_proto(args_ipsec_v1->proto);
		mode = utun_ipsec_mode_to_sadb_mode(args_ipsec_v1->mode);

		if ((err = utun_ipsec_set_sah(&IF_UTUN_GET_CRYPTO_KEYS_IPSEC_SAH(crypto_keys),
					      UTUN_CRYPTO_DIR_TO_IPSEC_DIR(args->dir),
					      proto,
					      mode,
					      args_ipsec_v1->reqid,
					      &args_ipsec_v1->src_addr,
					      &args_ipsec_v1->dst_addr))) {
			return err;
		}
		sah = IF_UTUN_GET_CRYPTO_KEYS_IPSEC_SAH(crypto_keys);
		if (!sah) {
			return EBADF;
		}
	}

	satype = utun_ipsec_proto_to_sadb_satype(args_ipsec_v1->proto);
	aalg = utun_ipsec_auth_to_sadb_aalg(args_ipsec_v1->alg_auth);
	ealg = utun_ipsec_enc_to_sadb_ealg(args_ipsec_v1->alg_enc);
	flags = utun_ipsec_keepalive_and_nat_info_to_sadb_flags(args_ipsec_v1->keepalive,
								args_ipsec_v1->punt_rx_keepalive,
								args_ipsec_v1->natd,
								args_ipsec_v1->natt_port);

	if ((err = utun_ipsec_alloc_sav(sah,
					&IF_UTUN_GET_CRYPTO_KEYS_IPSEC_SAV(crypto_keys),
					pcb,
					satype,
					aalg,
					ealg,
					flags,
					args_ipsec_v1->replay,
					varargs_buf,
					args_ipsec_v1->key_auth_len,
					(varargs_buf + BITSTOBYTES(args_ipsec_v1->key_auth_len)),
					args_ipsec_v1->key_enc_len,
					args_ipsec_v1->natt_port,
					args_ipsec_v1->seq,
					args_ipsec_v1->spi,
					args_ipsec_v1->pid,
					args_ipsec_v1->lifetime_hard,
					args_ipsec_v1->lifetime_soft))) {
		return err;
	}
	crypto_keys->state.u.ipsec.proto = sah->saidx.proto;
	crypto_keys->state.u.ipsec.mode = sah->saidx.mode;
	if (((struct sockaddr *)&sah->saidx.src)->sa_family == AF_INET) {
		crypto_keys->state.u.ipsec.ifamily = IPPROTO_IPV4;
	} else {
		crypto_keys->state.u.ipsec.ifamily = IPPROTO_IPV6;
	}
	crypto_keys->state.u.ipsec.spi = args_ipsec_v1->spi;
	utun_ipsec_set_udp_encap_listen_port(args->dir, args_ipsec_v1->natt_port);
	return 0;
}

static errno_t
utun_ctl_unconfig_crypto_keys_ipsec_v1 (utun_crypto_keys_t *crypto_keys)
{
	if (!IF_UTUN_GET_CRYPTO_KEYS_IPSEC_SAH(crypto_keys)) {
		return EBADF;
	}
	if (!IF_UTUN_GET_CRYPTO_KEYS_IPSEC_SAV(crypto_keys)) {
		return EBADF;
	}
	if (utun_ipsec_free_sav(&IF_UTUN_GET_CRYPTO_KEYS_IPSEC_SAV(crypto_keys))) {
		return EADDRNOTAVAIL;
	}
	if (!utun_ipsec_num_savs(&IF_UTUN_GET_CRYPTO_KEYS_IPSEC_SAH(crypto_keys))) {
		(void)utun_ipsec_clr_sahs(&IF_UTUN_GET_CRYPTO_KEYS_IPSEC_SAH(crypto_keys));

		// release sah
		IF_UTUN_GET_CRYPTO_KEYS_IPSEC_SAH(crypto_keys) = NULL;
	}

	return 0;
}

static void
utun_set_spirange (struct sadb_spirange *spirange,
		   u_int32_t             spirange_min,
		   u_int32_t             spirange_max)
{
	spirange->sadb_spirange_min = spirange_min;
	spirange->sadb_spirange_max = spirange_max;
}

static u_int32_t
utun_ipsec_get_spi (struct sockaddr_storage  *src_addr,
		    struct sockaddr_storage  *dst_addr,
		    u_int16_t                 proto,
		    u_int8_t                  mode,
		    u_int32_t                 reqid,
		    u_int32_t         spirange_min,
		    u_int32_t         spirange_max)
{
	struct sadb_spirange spirange;
	utun_set_spirange(&spirange, spirange_min, spirange_max);
	// TODO: should this allocate an SAH?
	return key_getspi2((struct sockaddr *)src_addr,
			   (struct sockaddr *)dst_addr,
			   proto,
			   mode,
			   reqid,
			   &spirange);
}

static errno_t
utun_ctl_generate_crypto_keys_idx_ipsec_v1 (utun_crypto_keys_idx_args_t *args)
{
	utun_crypto_keys_idx_ipsec_args_v1_t *args_ipsec_v1 = &args->u.ipsec_v1;
	u_int16_t                             proto;
	u_int8_t                              mode;

	proto = utun_ipsec_proto_to_sadb_proto(args_ipsec_v1->proto);
	mode = utun_ipsec_mode_to_sadb_mode(args_ipsec_v1->mode);

	args_ipsec_v1->spi = 0;
	if ((args_ipsec_v1->spi = utun_ipsec_get_spi(&args_ipsec_v1->src_addr,
						     &args_ipsec_v1->dst_addr,
						     proto,
						     mode,
						     args_ipsec_v1->reqid,
						     args_ipsec_v1->spirange_min,
						     args_ipsec_v1->spirange_max)) == 0) {
		return ENOBUFS;
	}
	return 0;
}

void
utun_cleanup_all_crypto_ipsec (struct utun_pcb   *pcb)
{
	int                 idx;
	utun_crypto_ctx_t  *crypto_ctx;
	utun_crypto_keys_t *cur_crypto_keys, *nxt_crypto_keys;

	for (idx = 0; idx < UTUN_CRYPTO_DIR_TO_IDX(UTUN_CRYPTO_DIR_MAX); idx++) {
		crypto_ctx = &pcb->utun_crypto_ctx[idx];
		if (!crypto_ctx->valid ||
		    crypto_ctx->type != UTUN_CRYPTO_TYPE_IPSEC) {
			continue;
		}

		// flush all crypto materials
		for (cur_crypto_keys = (__typeof__(cur_crypto_keys))LIST_FIRST(&crypto_ctx->keys_listhead);
		     cur_crypto_keys != NULL;
		     cur_crypto_keys = nxt_crypto_keys) {
			nxt_crypto_keys = (__typeof__(nxt_crypto_keys))LIST_NEXT(cur_crypto_keys, chain);

			if (!cur_crypto_keys->valid) {
				continue;
			}

			if (IF_UTUN_GET_CRYPTO_KEYS_IPSEC_SAV(cur_crypto_keys)) {
				(void)utun_ipsec_free_sav(&IF_UTUN_GET_CRYPTO_KEYS_IPSEC_SAV(cur_crypto_keys));
			}

			if (IF_UTUN_GET_CRYPTO_KEYS_IPSEC_SAH(cur_crypto_keys)) {		
				(void)utun_ipsec_clr_sahs(&IF_UTUN_GET_CRYPTO_KEYS_IPSEC_SAH(cur_crypto_keys));
			}
			
			LIST_REMOVE(cur_crypto_keys, chain);
			bzero(cur_crypto_keys, sizeof(*cur_crypto_keys));
			utun_free(cur_crypto_keys);
		}

		bzero(crypto_ctx, sizeof(*crypto_ctx));
	}
}

static errno_t
utun_ctl_enable_crypto_ipsec_v1 (__unused utun_crypto_args_t *args)
{
	return 0;
}

/*
 * Summary: enables ipsec crypto info for the specified utun.
 */
void
utun_ctl_enable_crypto_ipsec(__unused struct utun_pcb    *pcb,
			     utun_crypto_args_t *args)
{
	lck_mtx_lock(sadb_mutex);
	/* Turn off the ipsec bypass, if already on */
	if (ipsec_bypass) {
		ipsec_bypass = 0;
	}
	if (args->ver == UTUN_CRYPTO_KEYS_IPSEC_VER_1) {
		(void)utun_ctl_enable_crypto_ipsec_v1(args);
	}
	lck_mtx_unlock(sadb_mutex);
}

/*
 * Summary: disables ipsec crypto info for the specified utun.
 */
void
utun_ctl_disable_crypto_ipsec(__unused struct utun_pcb   *pcb)
{
	utun_cleanup_all_crypto_ipsec(pcb);
	lck_mtx_lock(sadb_mutex);
	/* Turn on the ipsec bypass, if there are no other policies */
	if (!ipsec_policy_count && !ipsec_bypass) // TODO: ipsec_policy_count may be 1 by default
		ipsec_bypass = 1;
	utun_punt_rx_keepalive = 0;
	lck_mtx_unlock(sadb_mutex);
}

errno_t
utun_ctl_config_crypto_keys_ipsec (struct utun_pcb         *pcb,
				   utun_crypto_keys_args_t *args,
				   utun_crypto_keys_t      *crypto_keys)
{
	if (args->ver == UTUN_CRYPTO_KEYS_IPSEC_VER_1) {
		return(utun_ctl_config_crypto_keys_ipsec_v1(pcb, args, crypto_keys));			   
	} else {
		printf("%s: ver unsupported (%d, %d)\n", __FUNCTION__, args->ver, UTUN_CRYPTO_KEYS_IPSEC_VER_1);
		return EINVAL;
	}
}

errno_t
utun_ctl_unconfig_crypto_keys_ipsec (utun_crypto_keys_args_t *args,
				     utun_crypto_keys_t      *crypto_keys)
{
	if (args->ver == UTUN_CRYPTO_KEYS_IPSEC_VER_1) {
		return(utun_ctl_unconfig_crypto_keys_ipsec_v1(crypto_keys));			   
	} else {
		printf("%s: ver unsupported (%d, %d)\n", __FUNCTION__, args->ver, UTUN_CRYPTO_KEYS_IPSEC_VER_1);
		return EINVAL;
	}
}

errno_t
utun_ctl_generate_crypto_keys_idx_ipsec (utun_crypto_keys_idx_args_t *args)
{
	if (args->ver == UTUN_CRYPTO_KEYS_IPSEC_VER_1) {
		return(utun_ctl_generate_crypto_keys_idx_ipsec_v1(args));			   
	} else {
		printf("%s: ver unsupported (%d, %d)\n", __FUNCTION__, args->ver, UTUN_CRYPTO_KEYS_IPSEC_VER_1);
		return EINVAL;
	}
}

int
utun_pkt_ipsec_output (struct utun_pcb *pcb, mbuf_t *pkt)
{
	utun_crypto_keys_t *crypto_keys = IF_UTUN_GET_TX_CRYPTO_KEYS(pcb);
	struct secasvar    *sav;
	protocol_family_t   proto;
	mbuf_t              new;
	int                 err;
	struct route       *ro = NULL;
	struct route        ro_copy;
	struct ip_out_args  ipoa =
	    { IFSCOPE_NONE, { 0 }, IPOAF_SELECT_SRCIF, 0 };

	if (crypto_keys &&
	    crypto_keys->state.u.ipsec.proto == IPPROTO_ESP &&
	    (sav = IF_UTUN_GET_CRYPTO_KEYS_IPSEC_SAV(crypto_keys)) &&
	    sav->state == SADB_SASTATE_MATURE) {
		// TODO: update stats to increment outgoing packets
		// TODO: allow empty packets thru

		proto = *(mtod(*pkt, protocol_family_t *));
		m_adj(*pkt, sizeof(protocol_family_t));

		bzero(&ro_copy, sizeof(ro_copy));

		if ((proto == AF_UTUN || proto == AF_INET) && crypto_keys->state.u.ipsec.ifamily == IPPROTO_IPV4) {
			struct ip          *ip;
			struct sockaddr_in *dst4;

			if (proto == AF_INET) {
				if ((*pkt)->m_len < (__typeof__((*pkt)->m_len))sizeof(*ip)) {
					if (!(*pkt = m_pullup(*pkt, sizeof(*ip)))) {
						printf("%s: m_pullup failed\n", __FUNCTION__);
						return 0;
					}
				}

				// split the mbuf chain to put the ip header and payloads in separate mbufs
				new = ipsec4_splithdr(*pkt);
				if (!new) {
					printf("%s: ipsec4_splithdr(1) failed\n", __FUNCTION__);
					ROUTE_RELEASE(&ro_copy);
					*pkt = NULL;
					return 0;
				}
				*pkt = new;

				// encapsulate with the outer header
				if ((err = ipsec4_encapsulate(new, sav))) {
					printf("%s: ipsec4_encapsulate failed (%d)\n", __FUNCTION__, err);
					*pkt = NULL;
					return 0;
				}

			} else {
				// otherwise it's AF_UTUN which will be a keepalive packet to be encapsulated, encrypted and sent
				// encapsulate with the outer header
				if ((err = ipsec4_encapsulate_utun_esp_keepalive(pkt, sav))) {
					printf("%s: ipsec4_encapsulate failed (%d)\n", __FUNCTION__, err);
					return 0;
				}
				new = *pkt;
			}

			ip = mtod(new, __typeof__(ip));
			// grab sadb_mutex, to update sah's route cache and get a local copy of it
			lck_mtx_lock(sadb_mutex);
			ro = &sav->sah->sa_route;
			dst4 = (struct sockaddr_in *)(void *)&ro->ro_dst;
			if (ro->ro_rt) {
				RT_LOCK(ro->ro_rt);
			}
			if (ROUTE_UNUSABLE(ro) ||
			    dst4->sin_addr.s_addr != ip->ip_dst.s_addr) {
				if (ro->ro_rt != NULL)
					RT_UNLOCK(ro->ro_rt);
				ROUTE_RELEASE(ro);
			}
			if (ro->ro_rt == NULL) {
				dst4->sin_family = AF_INET;
				dst4->sin_len = sizeof(*dst4);
				dst4->sin_addr = ip->ip_dst;
				rtalloc(ro);
				if (ro->ro_rt) {
					RT_LOCK(ro->ro_rt);
				} else {
					printf("%s: rtalloc(1) failed\n", __FUNCTION__);
					mbuf_freem(new);
					*pkt = NULL;
					return 0;
				}
			}
			if (ro->ro_rt->rt_flags & RTF_GATEWAY) {
				dst4 = (struct sockaddr_in *)(void *)ro->ro_rt->rt_gateway;
			}
			RT_UNLOCK(ro->ro_rt);
			route_copyout(&ro_copy, ro, sizeof(ro_copy));
			// release sadb_mutex, after updating sah's route cache and getting a local copy
			lck_mtx_unlock(sadb_mutex);

			// split the mbuf chain to put the ip header and payloads in separate mbufs
			new = ipsec4_splithdr(*pkt);
			if (!new) {
				printf("%s: ipsec4_splithdr(2) failed\n", __FUNCTION__);
				ROUTE_RELEASE(&ro_copy);
				*pkt = NULL;
				return 0;
			}
			*pkt = new;

			if ((err = esp4_output(new, sav))) {
				printf("%s: esp4_output failed (%d)\n", __FUNCTION__, err);
				ROUTE_RELEASE(&ro_copy);
				*pkt = NULL;
				return 0; // drop
			}

			ip = mtod(new, __typeof__(ip));
			ip->ip_len = ntohs(ip->ip_len);  /* flip len field before calling ip_output */
		} else if ((proto == AF_UTUN || proto == AF_INET6) && crypto_keys->state.u.ipsec.ifamily == IPPROTO_IPV6) {
			int                  plen;
			struct ip6_hdr      *ip6;
			struct sockaddr_in6 *dst6;

			if (proto == AF_INET6) {
				// split the mbuf chain to put the ip header and payloads in separate mbufs
				new = ipsec6_splithdr(*pkt);
				if (!new) {
					printf("%s: ipsec6_splithdr(1) failed\n", __FUNCTION__);
					ROUTE_RELEASE(&ro_copy);
					*pkt = NULL;
					return 0;
				}
				*pkt = new;

				// encapsulate with the outer header
				if ((err = ipsec6_encapsulate(new, sav))) {
					printf("%s: ipsec6_encapsulate failed (%d)\n", __FUNCTION__, err);
					*pkt = NULL;
					return 0;
				}

			} else {
				// otherwise it's AF_UTUN which will be a keepalive packet to be encapsulated, encrypted and sent
				// encapsulate with the outer header
				if ((err = ipsec6_encapsulate_utun_esp_keepalive(pkt, sav))) {
					printf("%s: ipsec6_encapsulate failed (%d)\n", __FUNCTION__, err);
					return 0;
				}
				new = *pkt;
			}

			ip6 = mtod(new, __typeof__(ip6));
			// grab sadb_mutex, before updating sah's route cache
			lck_mtx_lock(sadb_mutex);
			ro = &sav->sah->sa_route;
			dst6 = (struct sockaddr_in6 *)(void *)&ro->ro_dst;
			if (ro->ro_rt) {
				RT_LOCK(ro->ro_rt);
			}
			if (ROUTE_UNUSABLE(ro) ||
			    !IN6_ARE_ADDR_EQUAL(&dst6->sin6_addr, &ip6->ip6_dst)) {
				if (ro->ro_rt != NULL)
					RT_UNLOCK(ro->ro_rt);
				ROUTE_RELEASE(ro);
			}
			if (ro->ro_rt == NULL) {
				bzero(dst6, sizeof(*dst6));
				dst6->sin6_family = AF_INET6;
				dst6->sin6_len = sizeof(*dst6);
				dst6->sin6_addr = ip6->ip6_dst;
				rtalloc(ro);
				if (ro->ro_rt) {
					RT_LOCK(ro->ro_rt);
				} else {
					printf("%s: rtalloc(2) failed\n", __FUNCTION__);
					mbuf_freem(new);
					*pkt = NULL;
					return 0;
				}
			}
			if (ro->ro_rt->rt_flags & RTF_GATEWAY) {
				dst6 = (struct sockaddr_in6 *)(void *)ro->ro_rt->rt_gateway;
			}
			RT_UNLOCK(ro->ro_rt);
			route_copyout(&ro_copy, ro, sizeof(ro_copy));
			// release sadb_mutex, after updating sah's route cache and getting a local copy
			lck_mtx_unlock(sadb_mutex);

			// split the mbuf chain to put the ip header and payloads in separate mbufs
			new = ipsec6_splithdr(*pkt);
			if (!new) {
				printf("%s: ipsec6_splithdr failed\n", __FUNCTION__);
				ROUTE_RELEASE(&ro_copy);
				*pkt = NULL;
				return 0;
			}
			*pkt = new;
			
			if ((err = esp6_output(new, mtod(new, u_char *), new->m_next, sav))) {
				printf("%s: esp6_output failed (%d)\n", __FUNCTION__, err);
				ROUTE_RELEASE(&ro_copy);
				*pkt = NULL;
				return 0; // drop
			}

			plen = new->m_pkthdr.len - sizeof(struct ip6_hdr);
			if (plen > IPV6_MAXPACKET) {
				printf("%s: esp6_output failed due to invalid len (%d)\n", __FUNCTION__, plen);
				ROUTE_RELEASE(&ro_copy);
				mbuf_freem(new);
				*pkt = NULL;
				return 0;
			}
			ip6 = mtod(new, __typeof__(ip6));
			ip6->ip6_plen = ntohs(ip6->ip6_plen);  /* flip len field before calling ip_output */
		} else {
			printf("%s: packet's proto (%d) mismatched the context's proto (%d)\n", __FUNCTION__,
				   proto, crypto_keys->state.u.ipsec.ifamily);
			mbuf_freem(*pkt);
			*pkt = NULL;
			return 0;
		}

		if (pcb->utun_ifp) {
			ifnet_stat_increment_out(pcb->utun_ifp, 1, mbuf_pkthdr_len(new), 0);
		}

		if ((err = ip_output(new, NULL, &ro_copy,
		    (IP_OUTARGS | IP_NOIPSEC), NULL, &ipoa))) {
			printf("%s: ip_output failed (%d)\n", __FUNCTION__, err);
		}
		lck_mtx_lock(sadb_mutex);
		route_copyin(&ro_copy, ro, sizeof(*ro));
		lck_mtx_unlock(sadb_mutex);
		return 0;
	} else {
		printf("%s: no suitable crypto-mat\n", __FUNCTION__);
	}
	return -1;
}

// returns 0 if false, 1 if true, and -1 if there was a failure
int
utun_pkt_is_ipsec_keepalive (struct utun_pcb *pcb, mbuf_t *pkt, u_int16_t nxt, u_int32_t flags, size_t offs)
{
	int result;
	u_int8_t *data;
	int size_diff;

	if (!pcb->utun_ctlref) {
		printf("%s - utun ctlref cleared\n", __FUNCTION__);
		return 0;
	}

	if (!(pcb->utun_flags & UTUN_FLAGS_CRYPTO)) {
		printf("%s - crypto disabled\n", __FUNCTION__);
		return 0;
	}

	if ((*pkt)->m_pkthdr.len < 0) {
		printf("%s - invalid hdr len, len %d, offs %lu\n", __FUNCTION__, (*pkt)->m_pkthdr.len, offs);
		return 0;
	}

	if ((size_t)(*pkt)->m_pkthdr.len <= offs) {
		printf("%s - invalid offset, len %d, offs %lu\n", __FUNCTION__, (*pkt)->m_pkthdr.len, offs);
		return 0;
	}

	if ((*pkt)->m_len < 0) {
		printf("%s - invalid len, len %d, offs %lu\n", __FUNCTION__, (*pkt)->m_len, offs);
		return 0;
	}

	// pullup offs + 1 bytes
	if ((size_t)(*pkt)->m_len < (offs + 1)) {
		if ((*pkt = m_pullup(*pkt, (offs + 1))) == NULL) {
			printf("%s: m_pullup failed\n", __FUNCTION__);
			return -1;
		}
	}

	if (pcb->utun_ifp) {
		ifnet_stat_increment_in(pcb->utun_ifp, 1, mbuf_pkthdr_len(*pkt), 0);
	}

	size_diff = (*pkt)->m_pkthdr.len - offs;
	data = mtod(*pkt, __typeof(data));
	data += offs;

	// ESP keepalive meets all these conditions: ESP trailer's next proto indicates IP, the decrypted packet only has one zero'd byte in it.
	if (flags & SADB_X_EXT_ESP_KEEPALIVE &&
	    nxt == IPPROTO_IPV4 &&
	    size_diff == 1 &&
	    *data == 0) {
		// TODO: update stats to increment keepalives and current timestamp
		if (utun_punt_rx_keepalive ||
			flags & SADB_X_EXT_PUNT_RX_KEEPALIVE) {

			// strip all headers
			if ((size_t)(*pkt)->m_len >= (offs + size_diff)) {
				ovbcopy((caddr_t)data, (data + offs), size_diff);
				(*pkt)->m_data += offs;
				(*pkt)->m_len -= offs;
				(*pkt)->m_pkthdr.len -= offs;
			} else {
				struct mbuf *n;

				n = m_split(*pkt, offs, M_DONTWAIT);
				if (n == NULL) {
					/* *pkt is retained by m_split */
					mbuf_freem(*pkt);
					*pkt = NULL;
					return -1;
				}
				m_adj(n, offs);
				mbuf_freem(*pkt);
				*pkt = n;
			}

			// keepalive is being punted up to the control socket, prepend with a special packet type (PF_UTUN)
			if (mbuf_prepend(pkt, sizeof(protocol_family_t), MBUF_DONTWAIT) != 0) {
				printf("%s - ifnet_output prepend failed\n", __FUNCTION__);
				return -1;
			}
			if ((size_t)(*pkt)->m_len < (sizeof(protocol_family_t) + size_diff)) {
				if ((*pkt = m_pullup(*pkt, (sizeof(protocol_family_t) + size_diff))) == NULL) {
					printf("%s: m_pullup failed\n", __FUNCTION__);
					return -1;
				}
			}

			// mark UTUN/Keepalive packet
			*(protocol_family_t *)mbuf_data(*pkt) = htonl(PF_UTUN);

			result = ctl_enqueuembuf(pcb->utun_ctlref, pcb->utun_unit, *pkt, CTL_DATA_EOR);
			if (result != 0) {
				printf("%s: - ctl_enqueuembuf failed: %d\n", __FUNCTION__, result);
				mbuf_freem(*pkt);
				return -1;
			}
			*pkt = NULL;
		}
		return 1;
	}
	return 0;
}

int
utun_pkt_ipsec_input (struct utun_pcb *pcb, mbuf_t *pkt, protocol_family_t family)
{
	if (!m_tag_locate(*pkt, KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_IPSEC, NULL)) {
		return EINVAL;
	}

	if (!(pcb->utun_flags & UTUN_FLAGS_CRYPTO)) {
		printf("%s - crypto disabled\n", __FUNCTION__);
		return EINVAL;
	}

	if (!pcb->utun_ifp) {
		printf("%s - utun ifp cleared\n", __FUNCTION__);
		return EINVAL;
	}

	// place protocol number at the beginning of the mbuf
	if (mbuf_prepend(pkt, sizeof(protocol_family_t), MBUF_DONTWAIT) != 0) {
		printf("%s - ifnet_output prepend failed\n", __FUNCTION__);
		return ENOBUFS;
	}
	*(protocol_family_t *)mbuf_data(*pkt) = family;

	(void)utun_pkt_input(pcb, *pkt);
	return 0;
}

#endif /* IPSEC */
