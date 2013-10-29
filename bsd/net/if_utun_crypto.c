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



#include <sys/systm.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_utun.h>
#include <sys/mbuf.h> 
#include <net/if_utun_crypto.h>
#include <net/if_utun_crypto_ipsec.h>
#include <net/if_utun_crypto_dtls.h>

void
utun_ctl_init_crypto (void)
{
	utun_ctl_init_crypto_dtls();
}

void
utun_cleanup_crypto (struct utun_pcb *pcb)
{
#if IPSEC
	utun_cleanup_all_crypto_ipsec(pcb);
#endif
	utun_cleanup_all_crypto_dtls(pcb);
	pcb->utun_flags &= ~UTUN_FLAGS_CRYPTO;
}

errno_t
utun_ctl_enable_crypto (__unused kern_ctl_ref  kctlref,
			__unused u_int32_t     unit, 
			__unused void         *unitinfo,
			__unused int           opt, 
			void                  *data, 
			size_t                 len)
{
	struct utun_pcb	*pcb = unitinfo;

	/*
	 * - verify the crypto context args passed from user-land.
	 *    - check the size of the argument buffer.
	 *    - check the direction (IN or OUT)
	 *    - check the type (IPSec or DTLS)
	 * - ensure that the crypto context is *not* already valid (don't recreate already valid context).
	 *    - we have only one context per direction and type.
	 * - any error should be equivalent to noop.
	 */
	if (len < UTUN_CRYPTO_ARGS_HDR_SIZE) {
		return EMSGSIZE;
	} else {
		int                 idx;
		utun_crypto_args_t *crypto_args = (__typeof__(crypto_args))data;
		utun_crypto_ctx_t  *crypto_ctx;

		if (crypto_args->ver == 0 || crypto_args->ver >= UTUN_CRYPTO_ARGS_VER_MAX) {
			printf("%s: ver check failed %d\n", __FUNCTION__, crypto_args->ver);
			return EINVAL;
		}
		if (crypto_args->type == 0 || crypto_args->type >= UTUN_CRYPTO_TYPE_MAX) {
			printf("%s: type check failed %d\n", __FUNCTION__, crypto_args->type);
			return EINVAL;
		}
		if (len < UTUN_CRYPTO_ARGS_TOTAL_SIZE(crypto_args)) {
			printf("%s: vlen check failed (%d,%d)\n", __FUNCTION__,
				   (int)len, (int)UTUN_CRYPTO_ARGS_TOTAL_SIZE(crypto_args));
			return EINVAL;
		}
		if (crypto_args->args_ulen != sizeof(crypto_args->u)) {
			printf("%s: compatibility mode\n", __FUNCTION__);
		}

#if IPSEC
		if (crypto_args->type == UTUN_CRYPTO_TYPE_IPSEC) {
			utun_ctl_enable_crypto_ipsec(pcb, crypto_args);
		} else
#endif
		if (crypto_args->type == UTUN_CRYPTO_TYPE_DTLS) {
			utun_ctl_enable_crypto_dtls(pcb, crypto_args);
		} else {
			// unsupported
			return EPROTONOSUPPORT;
		}
		for (idx = 0; idx < UTUN_CRYPTO_DIR_TO_IDX(UTUN_CRYPTO_DIR_MAX); idx++) {
			crypto_ctx = &pcb->utun_crypto_ctx[idx];
			if (crypto_ctx->valid) {
				return EBADF;
			}

			crypto_ctx->type = crypto_args->type;
			LIST_INIT(&crypto_ctx->keys_listhead);
			LIST_INIT(&crypto_ctx->framer_listheads[UTUN_CRYPTO_INNER_TYPE_TO_IDX(UTUN_CRYPTO_INNER_TYPE_IPv4)]);
			LIST_INIT(&crypto_ctx->framer_listheads[UTUN_CRYPTO_INNER_TYPE_TO_IDX(UTUN_CRYPTO_INNER_TYPE_IPv6)]);
			crypto_ctx->valid = 1;
			printf("%s: initialized framer lists\n", __FUNCTION__);
		}
		// data traffic is stopped by default
		pcb->utun_flags |= (UTUN_FLAGS_CRYPTO | UTUN_FLAGS_CRYPTO_STOP_DATA_TRAFFIC);
		return 0;
	}
}

errno_t
utun_ctl_disable_crypto (__unused kern_ctl_ref  kctlref,
			 __unused u_int32_t     unit, 
			 __unused void         *unitinfo,
			 __unused int           opt, 
			 void                  *data, 
			 size_t                 len)
{
	struct utun_pcb	*pcb = unitinfo;

	/*
	 * - verify the crypto context args passed from user-land.
	 *    - check the size of the argument buffer.
	 *    - check the direction (IN or OUT)
	 *    - check the type (IPSec or DTLS)
	 * - ensure that the crypto context *is* already valid (don't release invalid context).
	 *    - we have only one context per direction and type.
	 * - ensure that the crypto context has no crypto material.
	 * - any error should be equivalent to noop.
	 */
	if (len < UTUN_CRYPTO_ARGS_HDR_SIZE) {
		return EMSGSIZE;
	} else {
		utun_crypto_args_t *crypto_args = (__typeof__(crypto_args))data;

		if (crypto_args->ver == 0 || crypto_args->ver >= UTUN_CRYPTO_ARGS_VER_MAX) {
			printf("%s: ver check failed %d\n", __FUNCTION__, crypto_args->ver);
			return EINVAL;
		}
		if (crypto_args->type == 0 || crypto_args->type >= UTUN_CRYPTO_TYPE_MAX) {
			printf("%s: type check failed %d\n", __FUNCTION__, crypto_args->type);
			return EINVAL;
		}
		if (len < UTUN_CRYPTO_ARGS_TOTAL_SIZE(crypto_args)) {
			printf("%s: vlen check failed (%d,%d)\n", __FUNCTION__,
				   (int)len, (int)UTUN_CRYPTO_ARGS_TOTAL_SIZE(crypto_args));
			return EINVAL;
		}
		if (crypto_args->args_ulen != sizeof(crypto_args->u)) {
			printf("%s: compatibility mode\n", __FUNCTION__);
		}

#if IPSEC
		if (crypto_args->type == UTUN_CRYPTO_TYPE_IPSEC) {
			utun_ctl_disable_crypto_ipsec(pcb);
		} else 
#endif
		if (crypto_args->type == UTUN_CRYPTO_TYPE_DTLS) {
			utun_ctl_disable_crypto_dtls(pcb);
		} else {
			// unsupported
			return EPROTONOSUPPORT;
		}
	}
	pcb->utun_flags &= ~(UTUN_FLAGS_CRYPTO | UTUN_FLAGS_CRYPTO_STOP_DATA_TRAFFIC);
	return 0;
}

errno_t
utun_ctl_config_crypto_keys (__unused kern_ctl_ref  kctlref,
			     __unused u_int32_t     unit, 
			     __unused void         *unitinfo,
			     __unused int           opt, 
			     void                  *data, 
			     size_t                 len)
{
	struct utun_pcb *pcb = unitinfo;

	/*
	 * - verify the crypto material args passed from user-land.
	 *    - check the size of the argument buffer.
	 *    - check the direction (IN or OUT)
	 *    - check the type (IPSec only)
	 *    - crypto material direction and type must match the associated crypto context's.
	 *        - we can have a list of crypto materials per context.
	 * - ensure that the crypto context is already valid (don't add crypto material to invalid context).
	 * - any error should be equivalent to noop.
	 */
	if (len < UTUN_CRYPTO_KEYS_ARGS_HDR_SIZE) {
		return EMSGSIZE;
	} else {
		int                      idx;
		utun_crypto_keys_args_t *crypto_keys_args = (__typeof__(crypto_keys_args))data;
		utun_crypto_ctx_t       *crypto_ctx;
		utun_crypto_keys_t      *crypto_keys = NULL;

		if (crypto_keys_args->ver == 0 || crypto_keys_args->ver >= UTUN_CRYPTO_KEYS_ARGS_VER_MAX) {
			printf("%s: ver check failed %d\n", __FUNCTION__, crypto_keys_args->ver);
			return EINVAL;
		}
		if (crypto_keys_args->dir == 0 || crypto_keys_args->dir >= UTUN_CRYPTO_DIR_MAX) {
			printf("%s: dir check failed %d\n", __FUNCTION__, crypto_keys_args->dir);
			return EINVAL;
		}
		if (crypto_keys_args->type == 0 || crypto_keys_args->type >= UTUN_CRYPTO_TYPE_MAX) {
			printf("%s: type check failed %d\n", __FUNCTION__, crypto_keys_args->type);
			return EINVAL;
		}
		if (len < UTUN_CRYPTO_KEYS_ARGS_TOTAL_SIZE(crypto_keys_args)) {
			printf("%s: vlen check failed (%d,%d)\n", __FUNCTION__,
				   (int)len, (int)UTUN_CRYPTO_KEYS_ARGS_TOTAL_SIZE(crypto_keys_args));
			return EINVAL;
		}
		idx = UTUN_CRYPTO_DIR_TO_IDX(crypto_keys_args->dir);
		crypto_ctx = &pcb->utun_crypto_ctx[idx];
		if (!crypto_ctx->valid) {
			return EBADF;
		}
		if (crypto_keys_args->type != crypto_ctx->type) {
			// can't add keymat to context with different crypto type
			return ENOENT;
		}
		crypto_keys = utun_alloc(sizeof(*crypto_keys));
		if (!crypto_keys) {
			return ENOBUFS;
		}
		bzero(crypto_keys, sizeof(*crypto_keys));
		if (crypto_keys_args->args_ulen != sizeof(crypto_keys_args->u)) {
			printf("%s: compatibility mode\n", __FUNCTION__);
		}

		// branch-off for ipsec vs. dtls
#if IPSEC
		if (crypto_keys_args->type == UTUN_CRYPTO_TYPE_IPSEC) {
			errno_t err;
			if ((err = utun_ctl_config_crypto_keys_ipsec(pcb, crypto_keys_args, crypto_keys))) {
				utun_free(crypto_keys);
				return err;
			}
		} else 
#endif
		{
			// unsupported
			utun_free(crypto_keys);
			return EPROTONOSUPPORT;
		}
		crypto_keys->type = crypto_keys_args->type;
		LIST_INSERT_HEAD(&crypto_ctx->keys_listhead, crypto_keys, chain);
		crypto_keys->valid = 1;
	}

	return 0;
}

errno_t
utun_ctl_unconfig_crypto_keys (__unused kern_ctl_ref  kctlref,
			       __unused u_int32_t     unit, 
			       __unused void         *unitinfo,
			       __unused int           opt, 
			       void                  *data, 
			       size_t                 len)
{
	struct utun_pcb *pcb = unitinfo;

	/*
	 * - verify the crypto material args passed from user-land.
	 *    - check the size of the argument buffer.
	 *    - check the direction (IN or OUT)
	 *    - check the type (IPSec only)
	 *    - crypto material direction and type must match the associated crypto context's.
	 *        - we can have a list of crypto materials per context.
	 * - ensure that the crypto context is already valid (don't add crypto material to invalid context).
	 * - any error should be equivalent to noop.
	 */
	if (len < UTUN_CRYPTO_KEYS_ARGS_HDR_SIZE) {
		return EMSGSIZE;
	} else {
		int                      idx;
		utun_crypto_keys_args_t *crypto_keys_args = (__typeof__(crypto_keys_args))data;
		utun_crypto_ctx_t       *crypto_ctx;
		utun_crypto_keys_t      *cur_crypto_keys, *nxt_crypto_keys;

		if (crypto_keys_args->ver == 0 || crypto_keys_args->ver >= UTUN_CRYPTO_KEYS_ARGS_VER_MAX) {
			printf("%s: ver check failed %d\n", __FUNCTION__, crypto_keys_args->ver);
			return EINVAL;
		}
		if (crypto_keys_args->dir == 0 || crypto_keys_args->dir >= UTUN_CRYPTO_DIR_MAX) {
			printf("%s: dir check failed %d\n", __FUNCTION__, crypto_keys_args->dir);
			return EINVAL;
		}
		if (crypto_keys_args->type == 0 || crypto_keys_args->type >= UTUN_CRYPTO_TYPE_MAX) {
			printf("%s: type check failed %d\n", __FUNCTION__, crypto_keys_args->type);
			return EINVAL;
		}
		if (len < UTUN_CRYPTO_KEYS_ARGS_TOTAL_SIZE(crypto_keys_args)) {
			printf("%s: vlen check failed (%d,%d)\n", __FUNCTION__,
				   (int)len, (int)UTUN_CRYPTO_KEYS_ARGS_TOTAL_SIZE(crypto_keys_args));
			return EINVAL;
		}
		idx = UTUN_CRYPTO_DIR_TO_IDX(crypto_keys_args->dir);
		crypto_ctx = &pcb->utun_crypto_ctx[idx];
		if (!crypto_ctx->valid) {
			return EBADF;
		}
		if (crypto_keys_args->type != crypto_ctx->type) {
			// can't add keymat to context with different crypto type
			return ENOENT;
		}
		if (crypto_keys_args->args_ulen != sizeof(crypto_keys_args->u)) {
 			printf("%s: compatibility mode\n", __FUNCTION__);
		}

		// traverse crypto materials looking for the right one
		for (cur_crypto_keys = (__typeof__(cur_crypto_keys))LIST_FIRST(&crypto_ctx->keys_listhead);
			 cur_crypto_keys != NULL;
			 cur_crypto_keys = nxt_crypto_keys) {
			nxt_crypto_keys = (__typeof__(nxt_crypto_keys))LIST_NEXT(cur_crypto_keys, chain);
			// branch-off for ipsec vs. dtls
#if IPSEC
			if (crypto_keys_args->type == UTUN_CRYPTO_TYPE_IPSEC) {
				if (crypto_keys_args->u.ipsec_v1.spi == cur_crypto_keys->state.u.ipsec.spi) {
					errno_t err;
					if ((err = utun_ctl_unconfig_crypto_keys_ipsec(crypto_keys_args, cur_crypto_keys))) {
						return err;
					}
					LIST_REMOVE(cur_crypto_keys, chain);
					bzero(cur_crypto_keys, sizeof(*cur_crypto_keys));
					utun_free(cur_crypto_keys);
					return 0;
				}
			} else 
#endif
			{
				// unsupported
				return EPROTONOSUPPORT;
			}
		}
		// TODO: if there is no SA left, ensure utun can't decrypt/encrypt packets directly. it should rely on the vpnplugin for that.
	}

	return 0;
}

errno_t
utun_ctl_config_crypto_framer (__unused kern_ctl_ref  kctlref,
			       __unused u_int32_t     unit, 
			       __unused void         *unitinfo,
			       __unused int           opt, 
			       void                  *data, 
			       size_t                 len)
{
	struct utun_pcb *pcb = unitinfo;

	/*
	 * - verify the crypto material args passed from user-land.
	 *    - check the size of the argument buffer.
	 *    - check the direction (IN or OUT)
	 *    - check the type (DTLS only)
	 *    - crypto material direction and type must match the associated crypto context's.
	 *        - we can have a list of crypto materials per context.
	 * - ensure that the crypto context is already valid (don't add crypto material to invalid context).
	 * - any error should be equivalent to noop.
	 */
	if (len < UTUN_CRYPTO_FRAMER_ARGS_HDR_SIZE) {
		return EMSGSIZE;
	} else {
		int                        idx;
		utun_crypto_framer_args_t *framer_args = (__typeof__(framer_args))data;
		utun_crypto_ctx_t         *crypto_ctx;

		if (framer_args->ver == 0 || framer_args->ver >= UTUN_CRYPTO_FRAMER_ARGS_VER_MAX) {
			printf("%s: ver check failed %d\n", __FUNCTION__, (int)framer_args->ver);
			return EINVAL;
		}
		if (framer_args->dir == 0 || framer_args->dir >= UTUN_CRYPTO_DIR_MAX) {
			printf("%s: dir check failed %d\n", __FUNCTION__, (int)framer_args->dir);
			return EINVAL;
		}
		if (framer_args->type == 0 || framer_args->type >= UTUN_CRYPTO_TYPE_MAX) {
			printf("%s: type check failed %d\n", __FUNCTION__, (int)framer_args->type);
			return EINVAL;
		}
		if (len < UTUN_CRYPTO_FRAMER_ARGS_TOTAL_SIZE(framer_args)) {
			printf("%s: vlen check failed (%d,%d)\n", __FUNCTION__,
			       (int)len, (int)UTUN_CRYPTO_FRAMER_ARGS_TOTAL_SIZE(framer_args));
			return EINVAL;
		}
		idx = UTUN_CRYPTO_DIR_TO_IDX(framer_args->dir);
		crypto_ctx = &pcb->utun_crypto_ctx[idx];
		if (!crypto_ctx->valid) {
			return EBADF;
		}
		if (framer_args->type != crypto_ctx->type) {
			// can't add keymat to context with different crypto type
			return ENOENT;
		}
		if (framer_args->args_ulen != sizeof(framer_args->u)) {
			printf("%s: compatibility mode\n", __FUNCTION__);
			// TODO:
		}

		// branch-off for ipsec vs. dtls
		if (framer_args->type == UTUN_CRYPTO_TYPE_DTLS) {
			errno_t err;
			if ((err = utun_ctl_config_crypto_dtls_framer(crypto_ctx, framer_args))) {
				return err;
			}
		} else {
			// unsupported
			return EPROTONOSUPPORT;
		}
	}

	return 0;
}

errno_t
utun_ctl_unconfig_crypto_framer (__unused kern_ctl_ref  kctlref,
				 __unused u_int32_t     unit, 
				 __unused void         *unitinfo,
				 __unused int           opt, 
				 void                  *data, 
				 size_t                 len)
{
	struct utun_pcb *pcb = unitinfo;

	/*
	 * - verify the crypto material args passed from user-land.
	 *    - check the size of the argument buffer.
	 *    - check the direction (IN or OUT)
	 *    - check the type (DTLS only)
	 *    - crypto material direction and type must match the associated crypto context's.
	 *        - we can have a list of crypto materials per context.
	 * - ensure that the crypto context is already valid (don't add crypto material to invalid context).
	 * - any error should be equivalent to noop.
	 */
	if (len < UTUN_CRYPTO_FRAMER_ARGS_HDR_SIZE) {
		return EMSGSIZE;
	} else {
		int                        idx;
		utun_crypto_framer_args_t *framer_args = (__typeof__(framer_args))data;
		utun_crypto_ctx_t         *crypto_ctx;

		if (framer_args->ver == 0 || framer_args->ver >= UTUN_CRYPTO_FRAMER_ARGS_VER_MAX) {
			printf("%s: ver check failed %d\n", __FUNCTION__, (int)framer_args->ver);
			return EINVAL;
		}
		if (framer_args->dir == 0 || framer_args->dir >= UTUN_CRYPTO_DIR_MAX) {
			printf("%s: dir check failed %d\n", __FUNCTION__, (int)framer_args->dir);
			return EINVAL;
		}
		if (framer_args->type == 0 || framer_args->type >= UTUN_CRYPTO_TYPE_MAX) {
			printf("%s: type check failed %d\n", __FUNCTION__, (int)framer_args->type);
			return EINVAL;
		}
		if (len < UTUN_CRYPTO_FRAMER_ARGS_TOTAL_SIZE(framer_args)) {
		  	printf("%s: vlen check failed (%d,%d)\n", __FUNCTION__,
		  		   (int)len, (int)UTUN_CRYPTO_FRAMER_ARGS_TOTAL_SIZE(framer_args));
			return EINVAL;
		}
		idx = UTUN_CRYPTO_DIR_TO_IDX(framer_args->dir);
		crypto_ctx = &pcb->utun_crypto_ctx[idx];
		if (!crypto_ctx->valid) {
			return EBADF;
		}
		if (framer_args->type != crypto_ctx->type) {
			// can't add keymat to context with different crypto type
			return ENOENT;
		}
		if (framer_args->args_ulen != sizeof(framer_args->u)) {
			printf("%s: compatibility mode\n", __FUNCTION__);
		}

		// branch-off for ipsec vs. dtls
		if (framer_args->type == UTUN_CRYPTO_TYPE_DTLS) {
			errno_t err;
			if ((err = utun_ctl_unconfig_crypto_dtls_framer(crypto_ctx, framer_args))) {
				return err;
			}
		} else {
			// unsupported
			return EPROTONOSUPPORT;
		}
	}

	return 0;
}

errno_t
utun_ctl_generate_crypto_keys_idx (__unused kern_ctl_ref   kctlref,
				   __unused u_int32_t      unit, 
				   __unused void          *unitinfo,
				   __unused int            opt, 
				   void                   *data, 
				   size_t                 *len)
{
	struct utun_pcb	*pcb = unitinfo;

	/*
	 * - verify the crypto material index args passed from user-land.
	 *    - check the size of the argument buffer.
	 *    - check the direction (IN or OUT)
	 *    - check the type (IPSec only)
	 *    - crypto material direction and type must match the associated crypto context's.
	 *        - we can have a list of crypto materials per context.
	 * - any error should be equivalent to noop.
	 */
	if (*len < UTUN_CRYPTO_KEYS_IDX_ARGS_HDR_SIZE) {
		return EMSGSIZE;
	} else {
		int                          idx;
		utun_crypto_keys_idx_args_t *crypto_keys_idx_args = (__typeof__(crypto_keys_idx_args))data;
		utun_crypto_ctx_t           *crypto_ctx;

		if (crypto_keys_idx_args->ver == 0 || crypto_keys_idx_args->ver >= UTUN_CRYPTO_KEYS_ARGS_VER_MAX) {
			printf("%s: ver check failed %d\n", __FUNCTION__, crypto_keys_idx_args->ver);
			return EINVAL;
		}
		if (crypto_keys_idx_args->dir == 0 || crypto_keys_idx_args->dir >= UTUN_CRYPTO_DIR_MAX) {
			printf("%s: dir check failed %d\n", __FUNCTION__, crypto_keys_idx_args->dir);
			return EINVAL;
		}
		if (crypto_keys_idx_args->type == 0 || crypto_keys_idx_args->type >= UTUN_CRYPTO_TYPE_MAX) {
			printf("%s: type check failed %d\n", __FUNCTION__, crypto_keys_idx_args->type);
			return EINVAL;
		}
		if (*len < UTUN_CRYPTO_KEYS_IDX_ARGS_TOTAL_SIZE(crypto_keys_idx_args)) {
			printf("%s: vlen check failed (%d,%d)\n", __FUNCTION__,
				   (int)*len, (int)UTUN_CRYPTO_KEYS_IDX_ARGS_TOTAL_SIZE(crypto_keys_idx_args));
			return EINVAL;
		}
		idx = UTUN_CRYPTO_DIR_TO_IDX(crypto_keys_idx_args->dir);
		crypto_ctx = &pcb->utun_crypto_ctx[idx];
		if (!crypto_ctx->valid) {
			return EBADF;
		}
		if (crypto_keys_idx_args->type != crypto_ctx->type) {
			// can't add keymat to context with different crypto type
			return ENOENT;
		}
		if (crypto_keys_idx_args->args_ulen != sizeof(crypto_keys_idx_args->u)) {
			printf("%s: compatibility mode\n", __FUNCTION__);
		}

		// traverse crypto materials looking for the right one
		// branch-off for ipsec vs. dtls
#if IPSEC
		if (crypto_keys_idx_args->type == UTUN_CRYPTO_TYPE_IPSEC) {
			errno_t err;
			if ((err = utun_ctl_generate_crypto_keys_idx_ipsec(crypto_keys_idx_args))) {
				return err;
			}
		} else 
#endif
		{
			// unsupported
			return EPROTONOSUPPORT;
		}
	}

	return 0;
}

errno_t
utun_ctl_stop_crypto_data_traffic (__unused kern_ctl_ref  kctlref,
				   __unused u_int32_t     unit, 
				   __unused void         *unitinfo,
				   __unused int           opt, 
				   void                  *data, 
				   size_t                 len)
{
	struct utun_pcb	*pcb = unitinfo;

	/*
	 * - verify the crypto context args passed from user-land.
	 *    - check the size of the argument buffer.
	 *    - check the direction (IN or OUT)
	 *    - check the type (IPSec or DTLS)
	 * - ensure that the crypto context *is* already valid (don't release invalid context).
	 *    - we have only one context per direction and type.
	 * - ensure that the crypto context has no crypto material.
	 * - any error should be equivalent to noop.
	 */
	if (len < UTUN_CRYPTO_ARGS_HDR_SIZE) {
		return EMSGSIZE;
	} else {
		utun_crypto_args_t *crypto_args = (__typeof__(crypto_args))data;

		if (crypto_args->ver == 0 || crypto_args->ver >= UTUN_CRYPTO_ARGS_VER_MAX) {
			printf("%s: ver check failed %d\n", __FUNCTION__, crypto_args->ver);
			return EINVAL;
		}
		if (crypto_args->type == 0 || crypto_args->type >= UTUN_CRYPTO_TYPE_MAX) {
			printf("%s: type check failed %d\n", __FUNCTION__, crypto_args->type);
			return EINVAL;
		}
		if (len < UTUN_CRYPTO_ARGS_TOTAL_SIZE(crypto_args)) {
			printf("%s: vlen check failed (%d,%d)\n", __FUNCTION__,
				   (int)len, (int)UTUN_CRYPTO_ARGS_TOTAL_SIZE(crypto_args));
			return EINVAL;
		}
		if (crypto_args->args_ulen != sizeof(crypto_args->u)) {
			printf("%s: compatibility mode\n", __FUNCTION__);
		}

		if ((pcb->utun_flags & UTUN_FLAGS_CRYPTO) == 0) {
			printf("%s: crypto is already disabled\n", __FUNCTION__);
			return EINVAL;
		}

		if (crypto_args->type == UTUN_CRYPTO_TYPE_IPSEC) {
			// nothing
		} else if (crypto_args->type == UTUN_CRYPTO_TYPE_DTLS) {
			utun_ctl_stop_datatraffic_crypto_dtls(pcb);
		} else {
			// unsupported
			return EPROTONOSUPPORT;
		}
	}
	pcb->utun_flags |= UTUN_FLAGS_CRYPTO_STOP_DATA_TRAFFIC;
	return 0;
}

errno_t
utun_ctl_start_crypto_data_traffic (__unused kern_ctl_ref  kctlref,
				    __unused u_int32_t     unit, 
				    __unused void         *unitinfo,
				    __unused int           opt, 
				    void                  *data, 
				    size_t                 len)
{
	struct utun_pcb	*pcb = unitinfo;

	/*
	 * - verify the crypto context args passed from user-land.
	 *    - check the size of the argument buffer.
	 *    - check the direction (IN or OUT)
	 *    - check the type (IPSec or DTLS)
	 * - ensure that the crypto context *is* already valid (don't release invalid context).
	 *    - we have only one context per direction and type.
	 * - ensure that the crypto context has no crypto material.
	 * - any error should be equivalent to noop.
	 */
	if (len < UTUN_CRYPTO_ARGS_HDR_SIZE) {
		return EMSGSIZE;
	} else {
		utun_crypto_args_t *crypto_args = (__typeof__(crypto_args))data;

		if (crypto_args->ver == 0 || crypto_args->ver >= UTUN_CRYPTO_ARGS_VER_MAX) {
			printf("%s: ver check failed %d\n", __FUNCTION__, crypto_args->ver);
			return EINVAL;
		}
		if (crypto_args->type == 0 || crypto_args->type >= UTUN_CRYPTO_TYPE_MAX) {
			printf("%s: type check failed %d\n", __FUNCTION__, crypto_args->type);
			return EINVAL;
		}
		if (len < UTUN_CRYPTO_ARGS_TOTAL_SIZE(crypto_args)) {
			printf("%s: vlen check failed (%d,%d)\n", __FUNCTION__,
				   (int)len, (int)UTUN_CRYPTO_ARGS_TOTAL_SIZE(crypto_args));
			return EINVAL;
		}
		if (crypto_args->args_ulen != sizeof(crypto_args->u)) {
			printf("%s: compatibility mode\n", __FUNCTION__);
		}

		if ((pcb->utun_flags & UTUN_FLAGS_CRYPTO) == 0) {
			printf("%s: crypto is already disabled\n", __FUNCTION__);
			return EINVAL;
		}

		if (crypto_args->type == UTUN_CRYPTO_TYPE_IPSEC) {
			// nothing
		} else if (crypto_args->type == UTUN_CRYPTO_TYPE_DTLS) {
			utun_ctl_start_datatraffic_crypto_dtls(pcb);
		} else {
			// unsupported
			return EPROTONOSUPPORT;
		}
	}
	pcb->utun_flags &= ~UTUN_FLAGS_CRYPTO_STOP_DATA_TRAFFIC;
	return 0;
}

int
utun_pkt_crypto_output (struct utun_pcb *pcb, mbuf_t *m)
{
	int idx = UTUN_CRYPTO_DIR_TO_IDX(UTUN_CRYPTO_DIR_OUT);
	if (!pcb->utun_crypto_ctx[idx].valid) {
		printf("%s: context is invalid %d\n", __FUNCTION__, pcb->utun_crypto_ctx[idx].valid);
		return -1;
	}
#if IPSEC
	if (pcb->utun_crypto_ctx[idx].type ==  UTUN_CRYPTO_TYPE_IPSEC) {
		return(utun_pkt_ipsec_output(pcb, m));
	} else 
#endif
	if (pcb->utun_crypto_ctx[idx].type ==  UTUN_CRYPTO_TYPE_DTLS) {
		return(utun_pkt_dtls_output(pcb, m));
	} else {
		// unsupported
		printf("%s: type is invalid %d\n", __FUNCTION__, pcb->utun_crypto_ctx[idx].type);
	}
	return -1;
}
