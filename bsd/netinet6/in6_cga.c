/*
 * Copyright (c) 2013-2016 Apple Inc. All rights reserved.
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

#include <sys/types.h>
#include <sys/malloc.h>

#include <kern/locks.h>

#include <libkern/crypto/sha1.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>

#define IN6_CGA_HASH1_LENGTH    8
#define IN6_CGA_HASH2_LENGTH    14
#define IN6_CGA_PREPARE_ZEROES  9

struct in6_cga_hash1 {
	u_int8_t octets[IN6_CGA_HASH1_LENGTH];
};

struct in6_cga_hash2 {
	u_int8_t octets[IN6_CGA_HASH2_LENGTH];
};

struct in6_cga_singleton {
	boolean_t cga_initialized;
	decl_lck_mtx_data(, cga_mutex);
	struct in6_cga_prepare cga_prepare;
	struct iovec cga_pubkey;
	struct iovec cga_privkey;
};

static struct in6_cga_singleton in6_cga = {
	.cga_initialized = FALSE,
	.cga_mutex = {},
	.cga_prepare = {
		.cga_modifier = {},
		.cga_security_level = 0,
	},
	.cga_pubkey = {
		.iov_base = NULL,
		.iov_len = 0,
	},
	.cga_privkey = {
		.iov_base = NULL,
		.iov_len = 0,
	},
};

static void
in6_cga_node_lock_assert(int owned)
{
#if !MACH_ASSERT
#pragma unused(owned)
#endif
	VERIFY(in6_cga.cga_initialized);
	LCK_MTX_ASSERT(&in6_cga.cga_mutex, owned);
}

static boolean_t
in6_cga_is_prepare_valid(const struct in6_cga_prepare *prepare,
    const struct iovec *pubkey)
{
	static const u_int8_t zeroes[IN6_CGA_PREPARE_ZEROES] = { };
	SHA1_CTX ctx;
	u_int8_t sha1[SHA1_RESULTLEN];
	u_int i, n;

	VERIFY(prepare != NULL);
	VERIFY(pubkey != NULL && pubkey->iov_base != NULL);

	if (prepare->cga_security_level == 0) {
		return TRUE;
	}

	if (prepare->cga_security_level > 7) {
		return FALSE;
	}

	SHA1Init(&ctx);
	SHA1Update(&ctx, &prepare->cga_modifier.octets,
	    IN6_CGA_MODIFIER_LENGTH);
	SHA1Update(&ctx, &zeroes, IN6_CGA_PREPARE_ZEROES);
	SHA1Update(&ctx, pubkey->iov_base, pubkey->iov_len);
	/* FUTURE: extension fields */
	SHA1Final(sha1, &ctx);

	n = 2 * (u_int) prepare->cga_security_level;
	VERIFY(n < SHA1_RESULTLEN);
	for (i = 0; i < n; ++i) {
		if (sha1[i] != 0) {
			return FALSE;
		}
	}

	return TRUE;
}

/*
 * @brief Generate interface identifier for CGA
 *      XXX You may notice that following does not really
 *      mirror what is decribed in:
 *      https://tools.ietf.org/html/rfc3972#section-4
 *      By design kernel here will assume that that
 *      modifier has been converged on by userspace
 *      for first part of the algorithm for the given
 *      security level.
 *      We are not doing that yet but that's how the code
 *      below is written. So really we are starting
 *      from bullet 4 of the algorithm.
 *
 * @param prepare Pointer to object containing modifier,
 *      security level & externsion to be used.
 * @param pubkey Public key used for IID generation
 * @param collisions Collission count on DAD failure
 *      XXX We are not really re-generating IID on DAD
 *      failures for now.
 * @param in6 Pointer to the address containing
 *      the prefix.
 *
 * @return void
 */
static void
in6_cga_generate_iid(const struct in6_cga_prepare *prepare,
    const struct iovec *pubkey, u_int8_t collisions, struct in6_addr *in6)
{
	SHA1_CTX ctx;
	u_int8_t sha1[SHA1_RESULTLEN];

	VERIFY(prepare != NULL);
	VERIFY(prepare->cga_security_level < 8);
	VERIFY(pubkey != NULL && pubkey->iov_base != NULL);
	VERIFY(in6 != NULL);

	SHA1Init(&ctx);
	SHA1Update(&ctx, &prepare->cga_modifier.octets, 16);
	SHA1Update(&ctx, in6->s6_addr, 8);
	SHA1Update(&ctx, &collisions, 1);
	SHA1Update(&ctx, pubkey->iov_base, pubkey->iov_len);
	/* FUTURE: extension fields */
	SHA1Final(sha1, &ctx);

	in6->s6_addr8[8] =
	    (prepare->cga_security_level << 5) | (sha1[0] & 0x1c);
	in6->s6_addr8[9] = sha1[1];
	in6->s6_addr8[10] = sha1[2];
	in6->s6_addr8[11] = sha1[3];
	in6->s6_addr8[12] = sha1[4];
	in6->s6_addr8[13] = sha1[5];
	in6->s6_addr8[14] = sha1[6];
	in6->s6_addr8[15] = sha1[7];
}

void
in6_cga_init(void)
{
	lck_mtx_init(&in6_cga.cga_mutex, ifa_mtx_grp, ifa_mtx_attr);
	in6_cga.cga_initialized = TRUE;
}

void
in6_cga_node_lock(void)
{
	VERIFY(in6_cga.cga_initialized);
	lck_mtx_lock(&in6_cga.cga_mutex);
}

void
in6_cga_node_unlock(void)
{
	VERIFY(in6_cga.cga_initialized);
	lck_mtx_unlock(&in6_cga.cga_mutex);
}

void
in6_cga_query(struct in6_cga_nodecfg *cfg)
{
	VERIFY(cfg != NULL);
	in6_cga_node_lock_assert(LCK_MTX_ASSERT_OWNED);

	cfg->cga_pubkey = in6_cga.cga_pubkey;
	cfg->cga_prepare = in6_cga.cga_prepare;
}

int
in6_cga_start(const struct in6_cga_nodecfg *cfg)
{
	struct iovec privkey, pubkey;
	const struct in6_cga_prepare *prepare;
	caddr_t pubkeycopy, privkeycopy;

	VERIFY(cfg != NULL);
	in6_cga_node_lock_assert(LCK_MTX_ASSERT_OWNED);

	privkey = cfg->cga_privkey;
	if (privkey.iov_base == NULL || privkey.iov_len == 0 ||
	    privkey.iov_len >= IN6_CGA_KEY_MAXSIZE) {
		return EINVAL;
	}
	pubkey = cfg->cga_pubkey;
	if (pubkey.iov_base == NULL || pubkey.iov_len == 0 ||
	    pubkey.iov_len >= IN6_CGA_KEY_MAXSIZE) {
		return EINVAL;
	}
	prepare = &cfg->cga_prepare;

	if (!in6_cga_is_prepare_valid(prepare, &pubkey)) {
		return EINVAL;
	}

	in6_cga.cga_prepare = *prepare;

	MALLOC(privkeycopy, caddr_t, privkey.iov_len, M_IP6CGA, M_WAITOK);
	if (privkeycopy == NULL) {
		return ENOMEM;
	}

	MALLOC(pubkeycopy, caddr_t, pubkey.iov_len, M_IP6CGA, M_WAITOK);
	if (pubkeycopy == NULL) {
		if (privkeycopy != NULL) {
			FREE(privkeycopy, M_IP6CGA);
		}
		return ENOMEM;
	}

	bcopy(privkey.iov_base, privkeycopy, privkey.iov_len);
	privkey.iov_base = privkeycopy;
	if (in6_cga.cga_privkey.iov_base != NULL) {
		FREE(in6_cga.cga_privkey.iov_base, M_IP6CGA);
	}
	in6_cga.cga_privkey = privkey;

	bcopy(pubkey.iov_base, pubkeycopy, pubkey.iov_len);
	pubkey.iov_base = pubkeycopy;
	if (in6_cga.cga_pubkey.iov_base != NULL) {
		FREE(in6_cga.cga_pubkey.iov_base, M_IP6CGA);
	}
	in6_cga.cga_pubkey = pubkey;

	return 0;
}

int
in6_cga_stop(void)
{
	in6_cga_node_lock_assert(LCK_MTX_ASSERT_OWNED);

	if (in6_cga.cga_privkey.iov_base != NULL) {
		FREE(in6_cga.cga_privkey.iov_base, M_IP6CGA);
		in6_cga.cga_privkey.iov_base = NULL;
		in6_cga.cga_privkey.iov_len = 0;
	}

	if (in6_cga.cga_pubkey.iov_base != NULL) {
		FREE(in6_cga.cga_pubkey.iov_base, M_IP6CGA);
		in6_cga.cga_pubkey.iov_base = NULL;
		in6_cga.cga_pubkey.iov_len = 0;
	}

	return 0;
}

ssize_t
in6_cga_parameters_prepare(void *output, size_t max,
    const struct in6_addr *prefix, u_int8_t collisions,
    const struct in6_cga_modifier *modifier)
{
	caddr_t cursor;

	in6_cga_node_lock_assert(LCK_MTX_ASSERT_OWNED);

	if (in6_cga.cga_pubkey.iov_len == 0) {
		/* No public key */
		return EINVAL;
	}

	if (output == NULL ||
	    max < in6_cga.cga_pubkey.iov_len + sizeof(modifier->octets) + 9) {
		/* Output buffer error */
		return EINVAL;
	}

	cursor = output;
	if (modifier == NULL) {
		modifier = &in6_cga.cga_prepare.cga_modifier;
	}
	if (prefix == NULL) {
		static const struct in6_addr llprefix = {{{ 0xfe, 0x80 }}};
		prefix = &llprefix;
	}

	bcopy(&modifier->octets, cursor, sizeof(modifier->octets));
	cursor += sizeof(modifier->octets);

	*cursor++ = (char) collisions;

	bcopy(&prefix->s6_addr[0], cursor, 8);
	cursor += 8;

	bcopy(in6_cga.cga_pubkey.iov_base, cursor, in6_cga.cga_pubkey.iov_len);
	cursor += in6_cga.cga_pubkey.iov_len;

	/* FUTURE: Extension fields */

	return (ssize_t)(cursor - (caddr_t)output);
}

int
in6_cga_generate(struct in6_cga_prepare *prepare, u_int8_t collisions,
    struct in6_addr *in6)
{
	int error;
	const struct iovec *pubkey;

	in6_cga_node_lock_assert(LCK_MTX_ASSERT_OWNED);
	VERIFY(in6 != NULL);

	if (prepare == NULL) {
		prepare = &in6_cga.cga_prepare;
	} else {
		prepare->cga_security_level =
		    in6_cga.cga_prepare.cga_security_level;
	}

	pubkey = &in6_cga.cga_pubkey;

	if (pubkey->iov_base != NULL) {
		in6_cga_generate_iid(prepare, pubkey, collisions, in6);
		error = 0;
	} else {
		error = EADDRNOTAVAIL;
	}

	return error;
}

/* End of file */
