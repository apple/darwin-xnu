/*	$KAME: key_var.h,v 1.5 2000/02/22 14:06:41 itojun Exp $	*/

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

#ifndef _NETKEY_KEY_VAR_H_
#define _NETKEY_KEY_VAR_H_

#ifdef __NetBSD__
#if defined(_KERNEL) && !defined(_LKM)
#include "opt_inet.h"
#endif
#endif

/* sysctl */
#define KEYCTL_DEBUG_LEVEL		1
#define KEYCTL_SPI_TRY			2
#define KEYCTL_SPI_MIN_VALUE		3
#define KEYCTL_SPI_MAX_VALUE		4
#define KEYCTL_RANDOM_INT		5
#define KEYCTL_LARVAL_LIFETIME		6
#define KEYCTL_BLOCKACQ_COUNT		7
#define KEYCTL_BLOCKACQ_LIFETIME	8
#define KEYCTL_MAXID			9

#define KEYCTL_NAMES { \
	{ 0, 0 }, \
	{ "debug", CTLTYPE_INT }, \
	{ "spi_try", CTLTYPE_INT }, \
	{ "spi_min_value", CTLTYPE_INT }, \
	{ "spi_max_value", CTLTYPE_INT }, \
	{ "random_int", CTLTYPE_INT }, \
	{ "larval_lifetime", CTLTYPE_INT }, \
	{ "blockacq_count", CTLTYPE_INT }, \
	{ "blockacq_lifetime", CTLTYPE_INT }, \
}

//#if IPSEC_DEBUG
#define KEYCTL_VARS { \
	0, \
	&key_debug_level, \
	&key_spi_trycnt, \
	&key_spi_minval, \
	&key_spi_maxval, \
	&key_int_random, \
	&key_larval_lifetime, \
	&key_blockacq_count, \
	&key_blockacq_lifetime, \
}
//#else
//#define KEYCTL_VARS { \
//	0, \
//	0, \
//	&key_spi_trycnt, \
//	&key_spi_minval, \
//	&key_spi_maxval, \
//	&key_int_random, \
//	&key_larval_lifetime, \
//	&key_blockacq_count, \
//	&key_blockacq_lifetime, \
//}
//#endif

#define _ARRAYLEN(p) (sizeof(p)/sizeof(p[0]))
#define _KEYLEN(key) ((u_int)((key)->sadb_key_bits >> 3))
#define _KEYBITS(key) ((u_int)((key)->sadb_key_bits))
#define _KEYBUF(key) ((caddr_t)((caddr_t)(key) + sizeof(struct sadb_key)))

#define _INADDR(in) ((struct sockaddr_in *)(in))

#if defined(INET6)
#define _IN6ADDR(in6) ((struct sockaddr_in6 *)(in6))
#define _SALENBYAF(family) \
	(((family) == AF_INET) ? \
		(u_int)sizeof(struct sockaddr_in) : \
		(u_int)sizeof(struct sockaddr_in6))
#define _INALENBYAF(family) \
	(((family) == AF_INET) ? \
		(u_int)sizeof(struct in_addr) : \
		(u_int)sizeof(struct in6_addr))
#define _INADDRBYSA(saddr) \
	((((struct sockaddr *)(saddr))->sa_family == AF_INET) ? \
		(caddr_t)&((struct sockaddr_in *)(saddr))->sin_addr : \
		(caddr_t)&((struct sockaddr_in6 *)(saddr))->sin6_addr)
#define _INPORTBYSA(saddr) \
	((((struct sockaddr *)(saddr))->sa_family == AF_INET) ? \
		((struct sockaddr_in *)(saddr))->sin_port : \
		((struct sockaddr_in6 *)(saddr))->sin6_port)
#if 0
#define _SADDRBYSA(saddr) \
	((((struct sockaddr *)(saddr))->sa_family == AF_INET) ? \
		(caddr_t)&((struct sockaddr_in *)(saddr))->sin_addr.s_addr : \
		(caddr_t)&((struct sockaddr_in6 *)(saddr))->sin6_addr.s6_addr)
#endif
#else
#define _IN6ADDR(in6) "#error"
#define _SALENBYAF(family) sizeof(struct sockaddr_in)
#define _INALENBYAF(family) sizeof(struct in_addr)
#define _INADDRBYSA(saddr) ((caddr_t)&((struct sockaddr_in *)(saddr))->sin_addr)
#define _INPORTBYSA(saddr) (((struct sockaddr_in *)(saddr))->sin_port)
#if 0
#define _SADDRBYSA(saddr) \
	((caddr_t)&((struct sockaddr_in *)(saddr))->sin_addr.s_addr)
#endif
#endif /* defined(INET6) */

#endif /* _NETKEY_KEY_VAR_H_ */
