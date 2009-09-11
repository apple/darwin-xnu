/*
 * Copyright (c) 2008 Apple Inc. All rights reserved.
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

/*	$FreeBSD: src/sys/netkey/key.c,v 1.16.2.13 2002/07/24 18:17:40 ume Exp $	*/
/*	$KAME: key.c,v 1.191 2001/06/27 10:46:49 sakane Exp $	*/

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
 * This code is referd to RFC 2367
 */

#include <machine/endian.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/syslog.h>

#include <kern/locks.h>

#include <net/if.h>
#include <net/route.h>
#include <net/raw_cb.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_var.h>

#if INET6
#include <netinet/ip6.h>
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#endif /* INET6 */

#if INET
#include <netinet/in_pcb.h>
#endif
#if INET6
#include <netinet6/in6_pcb.h>
#endif /* INET6 */

#include <net/pfkeyv2.h>
#include <netkey/keydb.h>
#include <netkey/key.h>
#include <netkey/keysock.h>
#include <netkey/key_debug.h>
#include <stdarg.h>


#include <netinet6/ipsec.h>
#if INET6
#include <netinet6/ipsec6.h>
#endif
#include <netinet6/ah.h>
#if INET6
#include <netinet6/ah6.h>
#endif
#if IPSEC_ESP
#include <netinet6/esp.h>
#if INET6
#include <netinet6/esp6.h>
#endif
#endif
#include <netinet6/ipcomp.h>
#if INET6
#include <netinet6/ipcomp6.h>
#endif


/* randomness */
#include <sys/random.h>

#include <net/net_osdep.h>

#ifndef satosin
#define satosin(s) ((struct sockaddr_in *)s)
#endif

#define FULLMASK	0xff

lck_grp_t         *sadb_mutex_grp;
lck_grp_attr_t    *sadb_mutex_grp_attr;
lck_attr_t        *sadb_mutex_attr;
lck_mtx_t         *sadb_mutex;

lck_grp_t         *pfkey_stat_mutex_grp;
lck_grp_attr_t    *pfkey_stat_mutex_grp_attr;
lck_attr_t        *pfkey_stat_mutex_attr;
lck_mtx_t         *pfkey_stat_mutex;


extern lck_mtx_t  *nd6_mutex;

/*
 * Note on SA reference counting:
 * - SAs that are not in DEAD state will have (total external reference + 1)
 *   following value in reference count field.  they cannot be freed and are
 *   referenced from SA header.
 * - SAs that are in DEAD state will have (total external reference)
 *   in reference count field.  they are ready to be freed.  reference from
 *   SA header will be removed in key_delsav(), when the reference count
 *   field hits 0 (= no external reference other than from SA header.
 */

u_int32_t key_debug_level = 0; //### our sysctl is not dynamic
static u_int key_spi_trycnt = 1000;
static u_int32_t key_spi_minval = 0x100;
static u_int32_t key_spi_maxval = 0x0fffffff;	/* XXX */
static u_int32_t policy_id = 0;
static u_int key_int_random = 60;	/*interval to initialize randseed,1(m)*/
static u_int key_larval_lifetime = 30;	/* interval to expire acquiring, 30(s)*/
static int key_blockacq_count = 10;	/* counter for blocking SADB_ACQUIRE.*/
static int key_blockacq_lifetime = 20;	/* lifetime for blocking SADB_ACQUIRE.*/
static int key_preferred_oldsa = 0;	/* preferred old sa rather than new sa.*/
__private_extern__ int natt_keepalive_interval = 20;	/* interval between natt keepalives.*/
static int ipsec_policy_count = 0;
static int ipsec_sav_count = 0;

static u_int32_t acq_seq = 0;
static int key_tick_init_random = 0;
__private_extern__ u_int32_t natt_now = 0;

static LIST_HEAD(_sptree, secpolicy) sptree[IPSEC_DIR_MAX];	/* SPD */
static LIST_HEAD(_sahtree, secashead) sahtree;			/* SAD */
static LIST_HEAD(_regtree, secreg) regtree[SADB_SATYPE_MAX + 1];
							/* registed list */
							
#define SPIHASHSIZE	128
#define	SPIHASH(x)	(((x) ^ ((x) >> 16)) % SPIHASHSIZE)
static LIST_HEAD(_spihash, secasvar) spihash[SPIHASHSIZE];

#ifndef IPSEC_NONBLOCK_ACQUIRE
static LIST_HEAD(_acqtree, secacq) acqtree;		/* acquiring list */
#endif
static LIST_HEAD(_spacqtree, secspacq) spacqtree;	/* SP acquiring list */

struct key_cb key_cb;

/* search order for SAs */
static const u_int saorder_state_valid_prefer_old[] = {
	SADB_SASTATE_DYING, SADB_SASTATE_MATURE,
};
static const u_int saorder_state_valid_prefer_new[] = {
	SADB_SASTATE_MATURE, SADB_SASTATE_DYING,
};
static const u_int saorder_state_alive[] = {
	/* except DEAD */
	SADB_SASTATE_MATURE, SADB_SASTATE_DYING, SADB_SASTATE_LARVAL
};
static const u_int saorder_state_any[] = {
	SADB_SASTATE_MATURE, SADB_SASTATE_DYING,
	SADB_SASTATE_LARVAL, SADB_SASTATE_DEAD
};

static const int minsize[] = {
	sizeof(struct sadb_msg),	/* SADB_EXT_RESERVED */
	sizeof(struct sadb_sa),		/* SADB_EXT_SA */
	sizeof(struct sadb_lifetime),	/* SADB_EXT_LIFETIME_CURRENT */
	sizeof(struct sadb_lifetime),	/* SADB_EXT_LIFETIME_HARD */
	sizeof(struct sadb_lifetime),	/* SADB_EXT_LIFETIME_SOFT */
	sizeof(struct sadb_address),	/* SADB_EXT_ADDRESS_SRC */
	sizeof(struct sadb_address),	/* SADB_EXT_ADDRESS_DST */
	sizeof(struct sadb_address),	/* SADB_EXT_ADDRESS_PROXY */
	sizeof(struct sadb_key),	/* SADB_EXT_KEY_AUTH */
	sizeof(struct sadb_key),	/* SADB_EXT_KEY_ENCRYPT */
	sizeof(struct sadb_ident),	/* SADB_EXT_IDENTITY_SRC */
	sizeof(struct sadb_ident),	/* SADB_EXT_IDENTITY_DST */
	sizeof(struct sadb_sens),	/* SADB_EXT_SENSITIVITY */
	sizeof(struct sadb_prop),	/* SADB_EXT_PROPOSAL */
	sizeof(struct sadb_supported),	/* SADB_EXT_SUPPORTED_AUTH */
	sizeof(struct sadb_supported),	/* SADB_EXT_SUPPORTED_ENCRYPT */
	sizeof(struct sadb_spirange),	/* SADB_EXT_SPIRANGE */
	0,				/* SADB_X_EXT_KMPRIVATE */
	sizeof(struct sadb_x_policy),	/* SADB_X_EXT_POLICY */
	sizeof(struct sadb_x_sa2),	/* SADB_X_SA2 */
	sizeof(struct sadb_session_id), /* SADB_EXT_SESSION_ID */
	sizeof(struct sadb_sastat),     /* SADB_EXT_SASTAT */
};
static const int maxsize[] = {
	sizeof(struct sadb_msg),	/* SADB_EXT_RESERVED */
	sizeof(struct sadb_sa_2),		/* SADB_EXT_SA */
	sizeof(struct sadb_lifetime),	/* SADB_EXT_LIFETIME_CURRENT */
	sizeof(struct sadb_lifetime),	/* SADB_EXT_LIFETIME_HARD */
	sizeof(struct sadb_lifetime),	/* SADB_EXT_LIFETIME_SOFT */
	0,				/* SADB_EXT_ADDRESS_SRC */
	0,				/* SADB_EXT_ADDRESS_DST */
	0,				/* SADB_EXT_ADDRESS_PROXY */
	0,				/* SADB_EXT_KEY_AUTH */
	0,				/* SADB_EXT_KEY_ENCRYPT */
	0,				/* SADB_EXT_IDENTITY_SRC */
	0,				/* SADB_EXT_IDENTITY_DST */
	0,				/* SADB_EXT_SENSITIVITY */
	0,				/* SADB_EXT_PROPOSAL */
	0,				/* SADB_EXT_SUPPORTED_AUTH */
	0,				/* SADB_EXT_SUPPORTED_ENCRYPT */
	sizeof(struct sadb_spirange),	/* SADB_EXT_SPIRANGE */
	0,				/* SADB_X_EXT_KMPRIVATE */
	0,				/* SADB_X_EXT_POLICY */
	sizeof(struct sadb_x_sa2),	/* SADB_X_SA2 */
	0,                              /* SADB_EXT_SESSION_ID */
	0,                              /* SADB_EXT_SASTAT */
};

static int ipsec_esp_keymin = 256;
static int ipsec_esp_auth = 0;
static int ipsec_ah_keymin = 128;

SYSCTL_DECL(_net_key);

SYSCTL_INT(_net_key, KEYCTL_DEBUG_LEVEL,	debug,	CTLFLAG_RW, \
	&key_debug_level,	0,	"");


/* max count of trial for the decision of spi value */
SYSCTL_INT(_net_key, KEYCTL_SPI_TRY,		spi_trycnt,	CTLFLAG_RW, \
	&key_spi_trycnt,	0,	"");

/* minimum spi value to allocate automatically. */
SYSCTL_INT(_net_key, KEYCTL_SPI_MIN_VALUE,	spi_minval,	CTLFLAG_RW, \
	&key_spi_minval,	0,	"");

/* maximun spi value to allocate automatically. */
SYSCTL_INT(_net_key, KEYCTL_SPI_MAX_VALUE,	spi_maxval,	CTLFLAG_RW, \
	&key_spi_maxval,	0,	"");

/* interval to initialize randseed */
SYSCTL_INT(_net_key, KEYCTL_RANDOM_INT,	int_random,	CTLFLAG_RW, \
	&key_int_random,	0,	"");

/* lifetime for larval SA */
SYSCTL_INT(_net_key, KEYCTL_LARVAL_LIFETIME,	larval_lifetime, CTLFLAG_RW, \
	&key_larval_lifetime,	0,	"");

/* counter for blocking to send SADB_ACQUIRE to IKEd */
SYSCTL_INT(_net_key, KEYCTL_BLOCKACQ_COUNT,	blockacq_count,	CTLFLAG_RW, \
	&key_blockacq_count,	0,	"");

/* lifetime for blocking to send SADB_ACQUIRE to IKEd */
SYSCTL_INT(_net_key, KEYCTL_BLOCKACQ_LIFETIME,	blockacq_lifetime, CTLFLAG_RW, \
	&key_blockacq_lifetime,	0,	"");

/* ESP auth */
SYSCTL_INT(_net_key, KEYCTL_ESP_AUTH,	esp_auth, CTLFLAG_RW, \
	&ipsec_esp_auth,	0,	"");

/* minimum ESP key length */
SYSCTL_INT(_net_key, KEYCTL_ESP_KEYMIN,	esp_keymin, CTLFLAG_RW, \
	&ipsec_esp_keymin,	0,	"");

/* minimum AH key length */
SYSCTL_INT(_net_key, KEYCTL_AH_KEYMIN,	ah_keymin, CTLFLAG_RW, \
	&ipsec_ah_keymin,	0,	"");

/* perfered old SA rather than new SA */
SYSCTL_INT(_net_key, KEYCTL_PREFERED_OLDSA,	prefered_oldsa, CTLFLAG_RW,\
	&key_preferred_oldsa,	0,	"");

/* time between NATT keepalives in seconds, 0 disabled  */
SYSCTL_INT(_net_key, KEYCTL_NATT_KEEPALIVE_INTERVAL, natt_keepalive_interval, CTLFLAG_RW,\
	&natt_keepalive_interval,	0,	"");

/* PF_KEY statistics */
SYSCTL_STRUCT(_net_key, KEYCTL_PFKEYSTAT, pfkeystat, CTLFLAG_RD,\
	&pfkeystat, pfkeystat, "");

#ifndef LIST_FOREACH
#define LIST_FOREACH(elm, head, field)                                     \
	for (elm = LIST_FIRST(head); elm; elm = LIST_NEXT(elm, field))
#endif
#define __LIST_CHAINED(elm) \
	(!((elm)->chain.le_next == NULL && (elm)->chain.le_prev == NULL))
#define LIST_INSERT_TAIL(head, elm, type, field) \
do {\
	struct type *curelm = LIST_FIRST(head); \
	if (curelm == NULL) {\
		LIST_INSERT_HEAD(head, elm, field); \
	} else { \
		while (LIST_NEXT(curelm, field)) \
			curelm = LIST_NEXT(curelm, field);\
		LIST_INSERT_AFTER(curelm, elm, field);\
	}\
} while (0)

#define KEY_CHKSASTATE(head, sav, name) \
do { \
	if ((head) != (sav)) {						\
		ipseclog((LOG_DEBUG, "%s: state mismatched (TREE=%d SA=%d)\n", \
			(name), (head), (sav)));			\
		continue;						\
	}								\
} while (0)

#define KEY_CHKSPDIR(head, sp, name) \
do { \
	if ((head) != (sp)) {						\
		ipseclog((LOG_DEBUG, "%s: direction mismatched (TREE=%d SP=%d), " \
			"anyway continue.\n",				\
			(name), (head), (sp)));				\
	}								\
} while (0)

#if 1
#define KMALLOC_WAIT(p, t, n)                                                     \
	((p) = (t) _MALLOC((u_int32_t)(n), M_SECA, M_WAITOK))
#define KMALLOC_NOWAIT(p, t, n)                                              \
	((p) = (t) _MALLOC((u_int32_t)(n), M_SECA, M_NOWAIT))
#define KFREE(p)                                                             \
	_FREE((caddr_t)(p), M_SECA);
#else
#define KMALLOC_WAIT(p, t, n) \
do { \
	((p) = (t)_MALLOC((u_int32_t)(n), M_SECA, M_WAITOK));             \
	printf("%s %d: %p <- KMALLOC_WAIT(%s, %d)\n",                             \
		__FILE__, __LINE__, (p), #t, n);                             \
} while (0)
#define KMALLOC_NOWAIT(p, t, n) \
	do { \
		((p) = (t)_MALLOC((u_int32_t)(n), M_SECA, M_NOWAIT));             \
		printf("%s %d: %p <- KMALLOC_NOWAIT(%s, %d)\n",                             \
		       __FILE__, __LINE__, (p), #t, n);                             \
	} while (0)

#define KFREE(p)                                                             \
	do {                                                                 \
		printf("%s %d: %p -> KFREE()\n", __FILE__, __LINE__, (p));   \
		_FREE((caddr_t)(p), M_SECA);                                  \
	} while (0)
#endif

/*
 * set parameters into secpolicyindex buffer.
 * Must allocate secpolicyindex buffer passed to this function.
 */
#define KEY_SETSECSPIDX(_dir, s, d, ps, pd, ulp, idx) \
do { \
	bzero((idx), sizeof(struct secpolicyindex));                             \
	(idx)->dir = (_dir);                                                 \
	(idx)->prefs = (ps);                                                 \
	(idx)->prefd = (pd);                                                 \
	(idx)->ul_proto = (ulp);                                             \
	bcopy((s), &(idx)->src, ((struct sockaddr *)(s))->sa_len);           \
	bcopy((d), &(idx)->dst, ((struct sockaddr *)(d))->sa_len);           \
} while (0)

/*
 * set parameters into secasindex buffer.
 * Must allocate secasindex buffer before calling this function.
 */
#define KEY_SETSECASIDX(p, m, r, s, d, idx) \
do { \
	bzero((idx), sizeof(struct secasindex));                             \
	(idx)->proto = (p);                                                  \
	(idx)->mode = (m);                                                   \
	(idx)->reqid = (r);                                                  \
	bcopy((s), &(idx)->src, ((const struct sockaddr *)(s))->sa_len);           \
	bcopy((d), &(idx)->dst, ((const struct sockaddr *)(d))->sa_len);           \
} while (0)

/* key statistics */
struct _keystat {
	u_int32_t getspi_count; /* the avarage of count to try to get new SPI */
} keystat;

struct sadb_msghdr {
	struct sadb_msg *msg;
	struct sadb_ext *ext[SADB_EXT_MAX + 1];
	int extoff[SADB_EXT_MAX + 1];
	int extlen[SADB_EXT_MAX + 1];
};

static struct secasvar *key_do_allocsa_policy(struct secashead *, u_int, u_int16_t);
static int key_do_get_translated_port(struct secashead *, struct secasvar *, u_int);
static void key_delsp(struct secpolicy *);
static struct secpolicy *key_getsp(struct secpolicyindex *);
static struct secpolicy *key_getspbyid(u_int32_t);
static u_int32_t key_newreqid(void);
static struct mbuf *key_gather_mbuf(struct mbuf *,
	const struct sadb_msghdr *, int, int, int *);
static int key_spdadd(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static u_int32_t key_getnewspid(void);
static int key_spddelete(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static int key_spddelete2(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static int key_spdget(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static int key_spdflush(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static int key_spddump(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static struct mbuf *key_setdumpsp(struct secpolicy *,
	u_int8_t, u_int32_t, u_int32_t);
static u_int key_getspreqmsglen(struct secpolicy *);
static int key_spdexpire(struct secpolicy *);
static struct secashead *key_newsah(struct secasindex *, u_int8_t);
static void key_delsah(struct secashead *);
static struct secasvar *key_newsav(struct mbuf *,
	const struct sadb_msghdr *, struct secashead *, int *);
static void key_delsav(struct secasvar *);
static struct secashead *key_getsah(struct secasindex *);
static struct secasvar *key_checkspidup(struct secasindex *, u_int32_t);
static void key_setspi __P((struct secasvar *, u_int32_t));
static struct secasvar *key_getsavbyspi(struct secashead *, u_int32_t);
static int key_setsaval(struct secasvar *, struct mbuf *,
	const struct sadb_msghdr *);
static int key_mature(struct secasvar *);
static struct mbuf *key_setdumpsa(struct secasvar *, u_int8_t,
	u_int8_t, u_int32_t, u_int32_t);
static struct mbuf *key_setsadbmsg(u_int8_t, u_int16_t, u_int8_t,
	u_int32_t, pid_t, u_int16_t);
static struct mbuf *key_setsadbsa(struct secasvar *);
static struct mbuf *key_setsadbaddr(u_int16_t,
	struct sockaddr *, u_int8_t, u_int16_t);
#if 0
static struct mbuf *key_setsadbident(u_int16_t, u_int16_t, caddr_t,
	int, u_int64_t);
#endif
static struct mbuf *key_setsadbxsa2(u_int8_t, u_int32_t, u_int32_t);
static struct mbuf *key_setsadbxpolicy(u_int16_t, u_int8_t,
	u_int32_t);
static void *key_newbuf(const void *, u_int);
#if INET6
static int key_ismyaddr6(struct sockaddr_in6 *);
#endif
static void key_update_natt_keepalive_timestamp(struct secasvar *, struct secasvar *);

/* flags for key_cmpsaidx() */
#define CMP_HEAD	0x1	/* protocol, addresses. */
#define CMP_PORT	0x2	/* additionally HEAD, reqid, mode. */
#define CMP_REQID	0x4	/* additionally HEAD, reqid. */
#define CMP_MODE        0x8       /* additionally mode. */
#define CMP_EXACTLY	0xF	/* all elements. */
static int key_cmpsaidx(struct secasindex *, struct secasindex *, int);

static int key_cmpspidx_exactly(struct secpolicyindex *,
					struct secpolicyindex *);
static int key_cmpspidx_withmask(struct secpolicyindex *,
					struct secpolicyindex *);
static int key_sockaddrcmp(struct sockaddr *, struct sockaddr *, int);
static int key_bbcmp(caddr_t, caddr_t, u_int);
static void key_srandom(void);
static u_int16_t key_satype2proto(u_int8_t);
static u_int8_t key_proto2satype(u_int16_t);

static int key_getspi(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static u_int32_t key_do_getnewspi(struct sadb_spirange *, struct secasindex *);
static int key_update(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
#if IPSEC_DOSEQCHECK
static struct secasvar *key_getsavbyseq(struct secashead *, u_int32_t);
#endif
static int key_add(struct socket *, struct mbuf *, const struct sadb_msghdr *);
static int key_setident(struct secashead *, struct mbuf *,
	const struct sadb_msghdr *);
static struct mbuf *key_getmsgbuf_x1(struct mbuf *, const struct sadb_msghdr *);
static int key_delete(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static int key_get(struct socket *, struct mbuf *, const struct sadb_msghdr *);

static void key_getcomb_setlifetime(struct sadb_comb *);
#if IPSEC_ESP
static struct mbuf *key_getcomb_esp(void);
#endif
static struct mbuf *key_getcomb_ah(void);
static struct mbuf *key_getcomb_ipcomp(void);
static struct mbuf *key_getprop(const struct secasindex *);

static int key_acquire(struct secasindex *, struct secpolicy *);
#ifndef IPSEC_NONBLOCK_ACQUIRE
static struct secacq *key_newacq(struct secasindex *);
static struct secacq *key_getacq(struct secasindex *);
static struct secacq *key_getacqbyseq(u_int32_t);
#endif
static struct secspacq *key_newspacq(struct secpolicyindex *);
static struct secspacq *key_getspacq(struct secpolicyindex *);
static int key_acquire2(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static int key_register(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static int key_expire(struct secasvar *);
static int key_flush(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static int key_dump(struct socket *, struct mbuf *, const struct sadb_msghdr *);
static int key_promisc(struct socket *, struct mbuf *,
	const struct sadb_msghdr *);
static int key_senderror(struct socket *, struct mbuf *, int);
static int key_validate_ext(const struct sadb_ext *, int);
static int key_align(struct mbuf *, struct sadb_msghdr *);
static void key_sa_chgstate(struct secasvar *, u_int8_t);
static struct mbuf *key_alloc_mbuf(int);
static int key_getsastat (struct socket *, struct mbuf *, const struct sadb_msghdr *);

extern int ipsec_bypass;
extern int esp_udp_encap_port;
int ipsec_send_natt_keepalive(struct secasvar *sav);

void key_init(void);



/*
 * PF_KEY init
 * setup locks and call raw_init()
 *
 */
void
key_init(void)
{

	int i;
	
	sadb_mutex_grp_attr = lck_grp_attr_alloc_init();
	sadb_mutex_grp = lck_grp_alloc_init("sadb", sadb_mutex_grp_attr);
	sadb_mutex_attr = lck_attr_alloc_init();

	if ((sadb_mutex = lck_mtx_alloc_init(sadb_mutex_grp, sadb_mutex_attr)) == NULL) {
		printf("key_init: can't alloc sadb_mutex\n");
		return;
	}
	
	pfkey_stat_mutex_grp_attr = lck_grp_attr_alloc_init();
	pfkey_stat_mutex_grp = lck_grp_alloc_init("pfkey_stat", pfkey_stat_mutex_grp_attr);
	pfkey_stat_mutex_attr = lck_attr_alloc_init();

	if ((pfkey_stat_mutex = lck_mtx_alloc_init(pfkey_stat_mutex_grp, pfkey_stat_mutex_attr)) == NULL) {
		printf("key_init: can't alloc pfkey_stat_mutex\n");
		return;
	}

	for (i = 0; i < SPIHASHSIZE; i++)
		LIST_INIT(&spihash[i]);

	raw_init();
	
}


/* %%% IPsec policy management */
/*
 * allocating a SP for OUTBOUND or INBOUND packet.
 * Must call key_freesp() later.
 * OUT:	NULL:	not found
 *	others:	found and return the pointer.
 */
struct secpolicy *
key_allocsp(spidx, dir)
	struct secpolicyindex *spidx;
	u_int dir;
{
	struct secpolicy *sp;
	struct timeval tv;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	/* sanity check */
	if (spidx == NULL)
		panic("key_allocsp: NULL pointer is passed.\n");

	/* check direction */
	switch (dir) {
	case IPSEC_DIR_INBOUND:
	case IPSEC_DIR_OUTBOUND:
		break;
	default:
		panic("key_allocsp: Invalid direction is passed.\n");
	}

	/* get a SP entry */
	KEYDEBUG(KEYDEBUG_IPSEC_DATA,
		printf("*** objects\n");
		kdebug_secpolicyindex(spidx));

	lck_mtx_lock(sadb_mutex);
	LIST_FOREACH(sp, &sptree[dir], chain) {
		KEYDEBUG(KEYDEBUG_IPSEC_DATA,
			printf("*** in SPD\n");
			kdebug_secpolicyindex(&sp->spidx));

		if (sp->state == IPSEC_SPSTATE_DEAD)
			continue;
		if (key_cmpspidx_withmask(&sp->spidx, spidx))
			goto found;
	}
	lck_mtx_unlock(sadb_mutex);
	return NULL;

found:

	/* found a SPD entry */
	microtime(&tv);
	sp->lastused = tv.tv_sec;
	sp->refcnt++;
	lck_mtx_unlock(sadb_mutex);
	
	/* sanity check */
	KEY_CHKSPDIR(sp->spidx.dir, dir, "key_allocsp");
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		printf("DP key_allocsp cause refcnt++:%d SP:%p\n",
			sp->refcnt, sp));
	return sp;
}

/*
 * return a policy that matches this particular inbound packet.
 * XXX slow
 */
struct secpolicy *
key_gettunnel(osrc, odst, isrc, idst)
	struct sockaddr *osrc, *odst, *isrc, *idst;
{
	struct secpolicy *sp;
	const int dir = IPSEC_DIR_INBOUND;
	struct timeval tv;
	struct ipsecrequest *r1, *r2, *p;
	struct sockaddr *os, *od, *is, *id;
	struct secpolicyindex spidx;

	if (isrc->sa_family != idst->sa_family) {
		ipseclog((LOG_ERR, "protocol family mismatched %d != %d\n.",
			isrc->sa_family, idst->sa_family));
		return NULL;
	}

	lck_mtx_lock(sadb_mutex);
	LIST_FOREACH(sp, &sptree[dir], chain) {
		if (sp->state == IPSEC_SPSTATE_DEAD)
			continue;

		r1 = r2 = NULL;
		for (p = sp->req; p; p = p->next) {
			if (p->saidx.mode != IPSEC_MODE_TUNNEL)
				continue;

			r1 = r2;
			r2 = p;

			if (!r1) {
				/* here we look at address matches only */
				spidx = sp->spidx;
				if (isrc->sa_len > sizeof(spidx.src) ||
				    idst->sa_len > sizeof(spidx.dst))
					continue;
				bcopy(isrc, &spidx.src, isrc->sa_len);
				bcopy(idst, &spidx.dst, idst->sa_len);
				if (!key_cmpspidx_withmask(&sp->spidx, &spidx))
				  continue;
			} else {
				is = (struct sockaddr *)&r1->saidx.src;
				id = (struct sockaddr *)&r1->saidx.dst;
				if (key_sockaddrcmp(is, isrc, 0) ||
				    key_sockaddrcmp(id, idst, 0))
					continue;
			}

			os = (struct sockaddr *)&r2->saidx.src;
			od = (struct sockaddr *)&r2->saidx.dst;
			if (key_sockaddrcmp(os, osrc, 0) ||
			    key_sockaddrcmp(od, odst, 0))
				continue;

			goto found;
		}
	}
	lck_mtx_unlock(sadb_mutex);
	return NULL;

found:
	microtime(&tv);
	sp->lastused = tv.tv_sec;
	sp->refcnt++;
	lck_mtx_unlock(sadb_mutex);
	return sp;
}

/*
 * allocating an SA entry for an *OUTBOUND* packet.
 * checking each request entries in SP, and acquire an SA if need.
 * OUT:	0: there are valid requests.
 *	ENOENT: policy may be valid, but SA with REQUIRE is on acquiring.
 */
int
key_checkrequest(isr, saidx, sav)
	struct ipsecrequest *isr;
	struct secasindex *saidx;	
	struct secasvar **sav;
{
	u_int level;
	int error;
	struct sockaddr_in *sin;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	*sav = NULL;
	
	/* sanity check */
	if (isr == NULL || saidx == NULL)
		panic("key_checkrequest: NULL pointer is passed.\n");

	/* check mode */
	switch (saidx->mode) {
	case IPSEC_MODE_TRANSPORT:
	case IPSEC_MODE_TUNNEL:
		break;
	case IPSEC_MODE_ANY:
	default:
		panic("key_checkrequest: Invalid policy defined.\n");
	}

	/* get current level */
	level = ipsec_get_reqlevel(isr);


	/*
	 * key_allocsa_policy should allocate the oldest SA available.
	 * See key_do_allocsa_policy(), and draft-jenkins-ipsec-rekeying-03.txt.
	 */
	if (*sav == NULL)
		*sav = key_allocsa_policy(saidx);

	/* When there is SA. */
	if (*sav != NULL)
		return 0;

	/* There is no SA.
	 *
	 * Remove dst port - used for special natt support - don't call
	 * key_acquire with it.
	 */
	if (saidx->mode == IPSEC_MODE_TRANSPORT) {
		sin = (struct sockaddr_in *)&saidx->dst;
		sin->sin_port = IPSEC_PORT_ANY;
	}
	if ((error = key_acquire(saidx, isr->sp)) != 0) {
		/* XXX What should I do ? */
		ipseclog((LOG_DEBUG, "key_checkrequest: error %d returned "
			"from key_acquire.\n", error));
		return error;
	}

	return level == IPSEC_LEVEL_REQUIRE ? ENOENT : 0;
}

/*
 * allocating a SA for policy entry from SAD.
 * NOTE: searching SAD of aliving state.
 * OUT:	NULL:	not found.
 *	others:	found and return the pointer.
 */
u_int32_t sah_search_calls = 0;
u_int32_t sah_search_count = 0;
struct secasvar *
key_allocsa_policy(saidx)
	struct secasindex *saidx;
{
	struct secashead *sah;
	struct secasvar *sav;
	u_int stateidx, state;
	const u_int *saorder_state_valid;
	int arraysize;
	struct sockaddr_in *sin;
	u_int16_t	dstport;
	
	lck_mtx_lock(sadb_mutex);
	sah_search_calls++;
	LIST_FOREACH(sah, &sahtree, chain) {
	        sah_search_count++;
		if (sah->state == SADB_SASTATE_DEAD)
			continue;
		if (key_cmpsaidx(&sah->saidx, saidx, CMP_MODE | CMP_REQID))
			goto found;
	}
	lck_mtx_unlock(sadb_mutex);
	return NULL;

    found:

	/*
	 * search a valid state list for outbound packet.
	 * This search order is important.
	 */
	if (key_preferred_oldsa) {
		saorder_state_valid = saorder_state_valid_prefer_old;
		arraysize = _ARRAYLEN(saorder_state_valid_prefer_old);
	} else {
		saorder_state_valid = saorder_state_valid_prefer_new;
		arraysize = _ARRAYLEN(saorder_state_valid_prefer_new);
	}


	sin = (struct sockaddr_in *)&saidx->dst;
	dstport = sin->sin_port;
	if (saidx->mode == IPSEC_MODE_TRANSPORT)
		sin->sin_port = IPSEC_PORT_ANY;

	for (stateidx = 0; stateidx < arraysize; stateidx++) {

		state = saorder_state_valid[stateidx];

		sav = key_do_allocsa_policy(sah, state, dstport);
		if (sav != NULL) {
			lck_mtx_unlock(sadb_mutex);
			return sav;
		}
	}
	lck_mtx_unlock(sadb_mutex);
	return NULL;
}

/*
 * searching SAD with direction, protocol, mode and state.
 * called by key_allocsa_policy().
 * OUT:
 *	NULL	: not found
 *	others	: found, pointer to a SA.
 */
static struct secasvar *
key_do_allocsa_policy(sah, state, dstport)
	struct secashead *sah;
	u_int state;
	u_int16_t dstport;
{
	struct secasvar *sav, *nextsav, *candidate, *natt_candidate, *no_natt_candidate, *d;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);

	/* initialize */
	candidate = NULL;
	natt_candidate = NULL;
	no_natt_candidate = NULL;

	for (sav = LIST_FIRST(&sah->savtree[state]);
	     sav != NULL;
	     sav = nextsav) {

		nextsav = LIST_NEXT(sav, chain);

		/* sanity check */
		KEY_CHKSASTATE(sav->state, state, "key_do_allocsa_policy");

		if (sah->saidx.mode == IPSEC_MODE_TUNNEL && dstport &&
		    ((sav->flags & SADB_X_EXT_NATT) != 0) &&
		    ntohs(dstport) != sav->remote_ike_port)
			continue;
		    
		if (sah->saidx.mode == IPSEC_MODE_TRANSPORT &&
		    ((sav->flags & SADB_X_EXT_NATT_MULTIPLEUSERS) != 0) &&
		    ntohs(dstport) != sav->remote_ike_port)
			continue;	/* skip this one - not a match - or not UDP */
							
		if ((sah->saidx.mode == IPSEC_MODE_TUNNEL &&
		     ((sav->flags & SADB_X_EXT_NATT) != 0)) ||
		    (sah->saidx.mode == IPSEC_MODE_TRANSPORT &&
		     ((sav->flags & SADB_X_EXT_NATT_MULTIPLEUSERS) != 0))) {
			if (natt_candidate == NULL) {
				natt_candidate = sav;
				continue;
			} else
				candidate = natt_candidate;
		} else {
			if (no_natt_candidate == NULL) {
				no_natt_candidate = sav;
				continue;
			} else
				candidate = no_natt_candidate;
		}			

		/* Which SA is the better ? */

		/* sanity check 2 */
		if (candidate->lft_c == NULL || sav->lft_c == NULL)
			panic("key_do_allocsa_policy: "
				"lifetime_current is NULL.\n");

		/* What the best method is to compare ? */
		if (key_preferred_oldsa) {
			if (candidate->lft_c->sadb_lifetime_addtime >
					sav->lft_c->sadb_lifetime_addtime) {
				if ((sav->flags & SADB_X_EXT_NATT_MULTIPLEUSERS) != 0)
					natt_candidate = sav;
				else
					no_natt_candidate = sav;
				}
			continue;
			/*NOTREACHED*/
		}

		/* prefered new sa rather than old sa */
		if (candidate->lft_c->sadb_lifetime_addtime <
				sav->lft_c->sadb_lifetime_addtime) {
			d = candidate;
			if ((sav->flags & SADB_X_EXT_NATT_MULTIPLEUSERS) != 0)
				natt_candidate = sav;
			else
				no_natt_candidate = sav;
		} else
			d = sav;

		/*
		 * prepared to delete the SA when there is more
		 * suitable candidate and the lifetime of the SA is not
		 * permanent.
		 */
		if (d->lft_c->sadb_lifetime_addtime != 0) {
			struct mbuf *m, *result;

			key_sa_chgstate(d, SADB_SASTATE_DEAD);

			m = key_setsadbmsg(SADB_DELETE, 0,
			    d->sah->saidx.proto, 0, 0, d->refcnt - 1);
			if (!m)
				goto msgfail;
			result = m;

			/* set sadb_address for saidx's. */
			m = key_setsadbaddr(SADB_EXT_ADDRESS_SRC,
				(struct sockaddr *)&d->sah->saidx.src,
				d->sah->saidx.src.ss_len << 3,
				IPSEC_ULPROTO_ANY);
			if (!m)
				goto msgfail;
			m_cat(result, m);

			/* set sadb_address for saidx's. */
			m = key_setsadbaddr(SADB_EXT_ADDRESS_DST,
				(struct sockaddr *)&d->sah->saidx.src,
				d->sah->saidx.src.ss_len << 3,
				IPSEC_ULPROTO_ANY);
			if (!m)
				goto msgfail;
			m_cat(result, m);

			/* create SA extension */
			m = key_setsadbsa(d);
			if (!m)
				goto msgfail;
			m_cat(result, m);

			if (result->m_len < sizeof(struct sadb_msg)) {
				result = m_pullup(result,
						sizeof(struct sadb_msg));
				if (result == NULL)
					goto msgfail;
			}

			result->m_pkthdr.len = 0;
			for (m = result; m; m = m->m_next)
				result->m_pkthdr.len += m->m_len;
			mtod(result, struct sadb_msg *)->sadb_msg_len =
				PFKEY_UNIT64(result->m_pkthdr.len);

			if (key_sendup_mbuf(NULL, result,
					KEY_SENDUP_REGISTERED))
				goto msgfail;
		 msgfail:
			key_freesav(d, KEY_SADB_LOCKED);
		}
	}

	/* choose latest if both types present */
	if (natt_candidate == NULL)
		candidate = no_natt_candidate;
	else if (no_natt_candidate == NULL)
		candidate = natt_candidate;
	else if (sah->saidx.mode == IPSEC_MODE_TUNNEL && dstport)
		candidate = natt_candidate;
	else if (natt_candidate->lft_c->sadb_lifetime_addtime >
			no_natt_candidate->lft_c->sadb_lifetime_addtime)
		candidate = natt_candidate;
	else
		candidate = no_natt_candidate;

	if (candidate) {
		candidate->refcnt++;
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
			printf("DP allocsa_policy cause "
				"refcnt++:%d SA:%p\n",
				candidate->refcnt, candidate));
	}
	return candidate;
}

/*
 * allocating a SA entry for a *INBOUND* packet.
 * Must call key_freesav() later.
 * OUT: positive:	pointer to a sav.
 *	NULL:		not found, or error occurred.
 *
 * In the comparison, source address will be ignored for RFC2401 conformance.
 * To quote, from section 4.1:
 *	A security association is uniquely identified by a triple consisting
 *	of a Security Parameter Index (SPI), an IP Destination Address, and a
 *	security protocol (AH or ESP) identifier.
 * Note that, however, we do need to keep source address in IPsec SA.
 * IKE specification and PF_KEY specification do assume that we
 * keep source address in IPsec SA.  We see a tricky situation here.
 */
struct secasvar *
key_allocsa(family, src, dst, proto, spi)
	u_int family, proto;
	caddr_t src, dst;
	u_int32_t spi;
{
	struct secasvar *sav, *match;
	u_int stateidx, state, tmpidx, matchidx;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	const u_int *saorder_state_valid;
	int arraysize;
	
	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);

	/* sanity check */
	if (src == NULL || dst == NULL)
		panic("key_allocsa: NULL pointer is passed.\n");

	/*
	 * when both systems employ similar strategy to use a SA.
	 * the search order is important even in the inbound case.
	 */
	if (key_preferred_oldsa) {
		saorder_state_valid = saorder_state_valid_prefer_old;
		arraysize = _ARRAYLEN(saorder_state_valid_prefer_old);
	} else {
		saorder_state_valid = saorder_state_valid_prefer_new;
		arraysize = _ARRAYLEN(saorder_state_valid_prefer_new);
	}

	/*
	 * searching SAD.
	 * XXX: to be checked internal IP header somewhere.  Also when
	 * IPsec tunnel packet is received.  But ESP tunnel mode is
	 * encrypted so we can't check internal IP header.
	 */
	/*
	 * search a valid state list for inbound packet.
	 * the search order is not important.
	 */
	match = NULL;
	matchidx = arraysize;
	lck_mtx_lock(sadb_mutex);
	LIST_FOREACH(sav, &spihash[SPIHASH(spi)], spihash) {
		if (sav->spi != spi)
			continue;
		if (proto != sav->sah->saidx.proto)
			continue;
		if (family != sav->sah->saidx.src.ss_family ||
		    family != sav->sah->saidx.dst.ss_family)
			continue;
		tmpidx = arraysize;
		for (stateidx = 0; stateidx < matchidx; stateidx++) {
			state = saorder_state_valid[stateidx];
			if (sav->state == state) {
				tmpidx = stateidx;
				break;
			}
		}
		if (tmpidx >= matchidx)
			continue;

#if 0	/* don't check src */
		/* check src address */
		switch (family) {
		case AF_INET:
			bzero(&sin, sizeof(sin));
			sin.sin_family = AF_INET;
			sin.sin_len = sizeof(sin);
			bcopy(src, &sin.sin_addr,
			    sizeof(sin.sin_addr));
			if (key_sockaddrcmp((struct sockaddr*)&sin,
			    (struct sockaddr *)&sav->sah->saidx.src, 0) != 0)
				continue;
			break;
		case AF_INET6:
		   bzero(&sin6, sizeof(sin6));
		   sin6.sin6_family = AF_INET6;
		   sin6.sin6_len = sizeof(sin6);
		   bcopy(src, &sin6.sin6_addr,
			   sizeof(sin6.sin6_addr));
		   if (IN6_IS_SCOPE_LINKLOCAL(&sin6.sin6_addr)) {
				   /* kame fake scopeid */
				   sin6.sin6_scope_id =
					   ntohs(sin6.sin6_addr.s6_addr16[1]);
				   sin6.sin6_addr.s6_addr16[1] = 0;
		   }
		   if (key_sockaddrcmp((struct sockaddr*)&sin6,
			    (struct sockaddr *)&sav->sah->saidx.src, 0) != 0)
				continue;
			break;
		default:
			ipseclog((LOG_DEBUG, "key_allocsa: "
			    "unknown address family=%d.\n",
			    family));
			continue;
		}

#endif
		/* check dst address */
		switch (family) {
		case AF_INET:
			bzero(&sin, sizeof(sin));
			sin.sin_family = AF_INET;
			sin.sin_len = sizeof(sin);
			bcopy(dst, &sin.sin_addr,
			    sizeof(sin.sin_addr));
			if (key_sockaddrcmp((struct sockaddr*)&sin,
			    (struct sockaddr *)&sav->sah->saidx.dst, 0) != 0)
				continue;

			break;
		case AF_INET6:
		   bzero(&sin6, sizeof(sin6));
		   sin6.sin6_family = AF_INET6;
		   sin6.sin6_len = sizeof(sin6);
		   bcopy(dst, &sin6.sin6_addr,
			   sizeof(sin6.sin6_addr));
		   if (IN6_IS_SCOPE_LINKLOCAL(&sin6.sin6_addr)) {
				   /* kame fake scopeid */
				   sin6.sin6_scope_id =
					   ntohs(sin6.sin6_addr.s6_addr16[1]);
				   sin6.sin6_addr.s6_addr16[1] = 0;
		   }
		   if (key_sockaddrcmp((struct sockaddr*)&sin6,
			    (struct sockaddr *)&sav->sah->saidx.dst, 0) != 0)
				continue;
			break;
		default:
			ipseclog((LOG_DEBUG, "key_allocsa: "
			    "unknown address family=%d.\n", family));
			continue;
		}

		match = sav;
		matchidx = tmpidx;
	}
	if (match)
		goto found;

	/* not found */
	lck_mtx_unlock(sadb_mutex);
	return NULL;

found:
	match->refcnt++;
	lck_mtx_unlock(sadb_mutex);
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		printf("DP allocsa cause refcnt++:%d SA:%p\n",
			match->refcnt, match));
	return match;
}

u_int16_t
key_natt_get_translated_port(outsav)
	struct secasvar *outsav;
{

	struct secasindex saidx;
	struct secashead *sah;
	u_int stateidx, state;
	const u_int *saorder_state_valid;
	int arraysize;
	
	/* get sa for incoming */
	saidx.mode = outsav->sah->saidx.mode;
	saidx.reqid = 0;
	saidx.proto = outsav->sah->saidx.proto;
	bcopy(&outsav->sah->saidx.src, &saidx.dst, sizeof(struct sockaddr_in));
	bcopy(&outsav->sah->saidx.dst, &saidx.src, sizeof(struct sockaddr_in));
	
	lck_mtx_lock(sadb_mutex);
	LIST_FOREACH(sah, &sahtree, chain) {
		if (sah->state == SADB_SASTATE_DEAD)
			continue;
		if (key_cmpsaidx(&sah->saidx, &saidx, CMP_MODE))
			goto found;
	}
	lck_mtx_unlock(sadb_mutex);
	return 0;

found:
	/* 
	 * Found sah - now go thru list of SAs and find
	 * matching remote ike port.  If found - set
	 * sav->natt_encapsulated_src_port and return the port.
	 */
	/*
	 * search a valid state list for outbound packet.
	 * This search order is important.
	 */
	if (key_preferred_oldsa) {
		saorder_state_valid = saorder_state_valid_prefer_old;
		arraysize = _ARRAYLEN(saorder_state_valid_prefer_old);
	} else {
		saorder_state_valid = saorder_state_valid_prefer_new;
		arraysize = _ARRAYLEN(saorder_state_valid_prefer_new);
	}

	for (stateidx = 0; stateidx < arraysize; stateidx++) {
		state = saorder_state_valid[stateidx];
		if (key_do_get_translated_port(sah, outsav, state)) {
			lck_mtx_unlock(sadb_mutex);
			return outsav->natt_encapsulated_src_port;
		}
	}
	lck_mtx_unlock(sadb_mutex);
	return 0;
}

static int
key_do_get_translated_port(sah, outsav, state)
	struct secashead *sah;
	struct secasvar *outsav; 
	u_int state;
{
	struct secasvar *currsav, *nextsav, *candidate;


	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);
	
	/* initilize */
	candidate = NULL;

	for (currsav = LIST_FIRST(&sah->savtree[state]);
	     currsav != NULL;
	     currsav = nextsav) {

		nextsav = LIST_NEXT(currsav, chain);

		/* sanity check */
		KEY_CHKSASTATE(currsav->state, state, "key_do_get_translated_port");
		
		if ((currsav->flags & SADB_X_EXT_NATT_MULTIPLEUSERS) == 0 ||
			currsav->remote_ike_port != outsav->remote_ike_port)
			continue;

		if (candidate == NULL) {
			candidate = currsav;
			continue;
		}
		
		/* Which SA is the better ? */

		/* sanity check 2 */
		if (candidate->lft_c == NULL || currsav->lft_c == NULL)
			panic("key_do_get_translated_port: "
				"lifetime_current is NULL.\n");

		/* What the best method is to compare ? */
		if (key_preferred_oldsa) {
			if (candidate->lft_c->sadb_lifetime_addtime >
					currsav->lft_c->sadb_lifetime_addtime) {
				candidate = currsav;
			}
			continue;
			/*NOTREACHED*/
		}

		/* prefered new sa rather than old sa */
		if (candidate->lft_c->sadb_lifetime_addtime <
				currsav->lft_c->sadb_lifetime_addtime) 
			candidate = currsav;
	}

	if (candidate) { 
		outsav->natt_encapsulated_src_port = candidate->natt_encapsulated_src_port;
		return 1;
	}

	return 0;
}

/*
 * Must be called after calling key_allocsp().
 * For both the packet without socket and key_freeso().
 */
void
key_freesp(sp, locked)
	struct secpolicy *sp;
	int locked;
{

	/* sanity check */
	if (sp == NULL)
		panic("key_freesp: NULL pointer is passed.\n");
	
	if (!locked)
		lck_mtx_lock(sadb_mutex);
	else
		lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);
	sp->refcnt--;
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		printf("DP freesp cause refcnt--:%d SP:%p\n",
			sp->refcnt, sp));

	if (sp->refcnt == 0)
		key_delsp(sp);
	if (!locked)
		lck_mtx_unlock(sadb_mutex);
	return;
}

#if 0
static void key_freesp_so(struct secpolicy **);

/*
 * Must be called after calling key_allocsp().
 * For the packet with socket.
 */
void
key_freeso(so)
	struct socket *so;
{
	
	/* sanity check */
	if (so == NULL)
		panic("key_freeso: NULL pointer is passed.\n");

	lck_mtx_lock(sadb_mutex);
	switch (so->so_proto->pr_domain->dom_family) {
#if INET
	case PF_INET:
	    {
		struct inpcb *pcb = sotoinpcb(so);

		/* Does it have a PCB ? */
		if (pcb == NULL || pcb->inp_sp == NULL)
			goto done;
		key_freesp_so(&pcb->inp_sp->sp_in);
		key_freesp_so(&pcb->inp_sp->sp_out);
	    }
		break;
#endif
#if INET6
	case PF_INET6:
	    {
#if HAVE_NRL_INPCB
		struct inpcb *pcb  = sotoinpcb(so);

		/* Does it have a PCB ? */
		if (pcb == NULL || pcb->inp_sp == NULL)
			goto done;
		key_freesp_so(&pcb->inp_sp->sp_in);
		key_freesp_so(&pcb->inp_sp->sp_out);
#else
		struct in6pcb *pcb  = sotoin6pcb(so);

		/* Does it have a PCB ? */
		if (pcb == NULL || pcb->in6p_sp == NULL)
			goto done;
		key_freesp_so(&pcb->in6p_sp->sp_in);
		key_freesp_so(&pcb->in6p_sp->sp_out);
#endif
	    }
		break;
#endif /* INET6 */
	default:
		ipseclog((LOG_DEBUG, "key_freeso: unknown address family=%d.\n",
		    so->so_proto->pr_domain->dom_family));
		break;
	}
done:
	lck_mtx_unlock(sadb_mutex);
	
	return;
}

static void
key_freesp_so(sp)
	struct secpolicy **sp;
{

	/* sanity check */
	if (sp == NULL || *sp == NULL)
		panic("key_freesp_so: sp == NULL\n");

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);
	
	switch ((*sp)->policy) {
	case IPSEC_POLICY_IPSEC:
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
			printf("DP freeso calls free SP:%p\n", *sp));
		key_freesp(*sp, KEY_SADB_LOCKED);
		*sp = NULL;
		break;
	case IPSEC_POLICY_ENTRUST:
	case IPSEC_POLICY_BYPASS:
		return;
	default:
		panic("key_freesp_so: Invalid policy found %d", (*sp)->policy);
	}

	return;
}

#endif

/*
 * Must be called after calling key_allocsa().
 * This function is called by key_freesp() to free some SA allocated
 * for a policy.
 */
void
key_freesav(sav, locked)
	struct secasvar *sav;
	int locked;
{

	/* sanity check */
	if (sav == NULL)
		panic("key_freesav: NULL pointer is passed.\n");

	if (!locked)
		lck_mtx_lock(sadb_mutex);
	else
		lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);
	sav->refcnt--;
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		printf("DP freesav cause refcnt--:%d SA:%p SPI %u\n",
			sav->refcnt, sav, (u_int32_t)ntohl(sav->spi)));

	if (sav->refcnt == 0)
		key_delsav(sav);
	if (!locked)
		lck_mtx_unlock(sadb_mutex);
	return;
}

/* %%% SPD management */
/*
 * free security policy entry.
 */
static void
key_delsp(sp)
	struct secpolicy *sp;
{

	/* sanity check */
	if (sp == NULL)
		panic("key_delsp: NULL pointer is passed.\n");
		
	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);
	sp->state = IPSEC_SPSTATE_DEAD;

	if (sp->refcnt > 0)
		return; /* can't free */

	/* remove from SP index */
	if (__LIST_CHAINED(sp)) {
		LIST_REMOVE(sp, chain);
		ipsec_policy_count--;
	}

    {
		struct ipsecrequest *isr = sp->req, *nextisr;

		while (isr != NULL) {
			nextisr = isr->next;
			KFREE(isr);
			isr = nextisr;
    	}
	}
	keydb_delsecpolicy(sp);

	return;
}

/*
 * search SPD
 * OUT:	NULL	: not found
 *	others	: found, pointer to a SP.
 */
static struct secpolicy *
key_getsp(spidx)
	struct secpolicyindex *spidx;
{
	struct secpolicy *sp;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);

	/* sanity check */
	if (spidx == NULL)
		panic("key_getsp: NULL pointer is passed.\n");

	LIST_FOREACH(sp, &sptree[spidx->dir], chain) {
		if (sp->state == IPSEC_SPSTATE_DEAD)
			continue;
		if (key_cmpspidx_exactly(spidx, &sp->spidx)) {
			sp->refcnt++;
			return sp;
		}
	}

	return NULL;
}

/*
 * get SP by index.
 * OUT:	NULL	: not found
 *	others	: found, pointer to a SP.
 */
static struct secpolicy *
key_getspbyid(id)
	u_int32_t id;
{
	struct secpolicy *sp;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);

	LIST_FOREACH(sp, &sptree[IPSEC_DIR_INBOUND], chain) {
		if (sp->state == IPSEC_SPSTATE_DEAD)
			continue;
		if (sp->id == id) {
			sp->refcnt++;
			return sp;
		}
	}

	LIST_FOREACH(sp, &sptree[IPSEC_DIR_OUTBOUND], chain) {
		if (sp->state == IPSEC_SPSTATE_DEAD)
			continue;
		if (sp->id == id) {
			sp->refcnt++;
			return sp;
		}
	}

	return NULL;
}

struct secpolicy *
key_newsp()
{
	struct secpolicy *newsp = NULL;
	
	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	newsp = keydb_newsecpolicy();
	if (!newsp)
		return newsp;

	newsp->refcnt = 1;
	newsp->req = NULL;

	return newsp;
}

/*
 * create secpolicy structure from sadb_x_policy structure.
 * NOTE: `state', `secpolicyindex' in secpolicy structure are not set,
 * so must be set properly later.
 */
struct secpolicy *
key_msg2sp(xpl0, len, error)
	struct sadb_x_policy *xpl0;
	size_t len;
	int *error;
{
	struct secpolicy *newsp;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	/* sanity check */
	if (xpl0 == NULL)
		panic("key_msg2sp: NULL pointer was passed.\n");
	if (len < sizeof(*xpl0))
		panic("key_msg2sp: invalid length.\n");
	if (len != PFKEY_EXTLEN(xpl0)) {
		ipseclog((LOG_DEBUG, "key_msg2sp: Invalid msg length.\n"));
		*error = EINVAL;
		return NULL;
	}

	if ((newsp = key_newsp()) == NULL) {
		*error = ENOBUFS;
		return NULL;
	}

	newsp->spidx.dir = xpl0->sadb_x_policy_dir;
	newsp->policy = xpl0->sadb_x_policy_type;

	/* check policy */
	switch (xpl0->sadb_x_policy_type) {
	case IPSEC_POLICY_DISCARD:
        case IPSEC_POLICY_GENERATE:
	case IPSEC_POLICY_NONE:
	case IPSEC_POLICY_ENTRUST:
	case IPSEC_POLICY_BYPASS:
		newsp->req = NULL;
		break;

	case IPSEC_POLICY_IPSEC:
	    {
		int tlen;
		struct sadb_x_ipsecrequest *xisr;
		struct ipsecrequest **p_isr = &newsp->req;

		/* validity check */
		if (PFKEY_EXTLEN(xpl0) < sizeof(*xpl0)) {
			ipseclog((LOG_DEBUG,
			    "key_msg2sp: Invalid msg length.\n"));
			key_freesp(newsp, KEY_SADB_UNLOCKED);
			*error = EINVAL;
			return NULL;
		}

		tlen = PFKEY_EXTLEN(xpl0) - sizeof(*xpl0);
		xisr = (struct sadb_x_ipsecrequest *)(xpl0 + 1);

		while (tlen > 0) {

			/* length check */
			if (xisr->sadb_x_ipsecrequest_len < sizeof(*xisr)) {
				ipseclog((LOG_DEBUG, "key_msg2sp: "
					"invalid ipsecrequest length.\n"));
				key_freesp(newsp, KEY_SADB_UNLOCKED);
				*error = EINVAL;
				return NULL;
			}

			/* allocate request buffer */
			KMALLOC_WAIT(*p_isr, struct ipsecrequest *, sizeof(**p_isr));
			if ((*p_isr) == NULL) {
				ipseclog((LOG_DEBUG,
				    "key_msg2sp: No more memory.\n"));
				key_freesp(newsp, KEY_SADB_UNLOCKED);
				*error = ENOBUFS;
				return NULL;
			}
			bzero(*p_isr, sizeof(**p_isr));

			/* set values */
			(*p_isr)->next = NULL;

			switch (xisr->sadb_x_ipsecrequest_proto) {
			case IPPROTO_ESP:
			case IPPROTO_AH:
			case IPPROTO_IPCOMP:
				break;
			default:
				ipseclog((LOG_DEBUG,
				    "key_msg2sp: invalid proto type=%u\n",
				    xisr->sadb_x_ipsecrequest_proto));
				key_freesp(newsp, KEY_SADB_UNLOCKED);
				*error = EPROTONOSUPPORT;
				return NULL;
			}
			(*p_isr)->saidx.proto = xisr->sadb_x_ipsecrequest_proto;

			switch (xisr->sadb_x_ipsecrequest_mode) {
			case IPSEC_MODE_TRANSPORT:
			case IPSEC_MODE_TUNNEL:
				break;
			case IPSEC_MODE_ANY:
			default:
				ipseclog((LOG_DEBUG,
				    "key_msg2sp: invalid mode=%u\n",
				    xisr->sadb_x_ipsecrequest_mode));
				key_freesp(newsp, KEY_SADB_UNLOCKED);
				*error = EINVAL;
				return NULL;
			}
			(*p_isr)->saidx.mode = xisr->sadb_x_ipsecrequest_mode;

			switch (xisr->sadb_x_ipsecrequest_level) {
			case IPSEC_LEVEL_DEFAULT:
			case IPSEC_LEVEL_USE:
			case IPSEC_LEVEL_REQUIRE:
				break;
			case IPSEC_LEVEL_UNIQUE:
				/* validity check */
				/*
				 * If range violation of reqid, kernel will
				 * update it, don't refuse it.
				 */
				if (xisr->sadb_x_ipsecrequest_reqid
						> IPSEC_MANUAL_REQID_MAX) {
					ipseclog((LOG_DEBUG,
					    "key_msg2sp: reqid=%d range "
					    "violation, updated by kernel.\n",
					    xisr->sadb_x_ipsecrequest_reqid));
					xisr->sadb_x_ipsecrequest_reqid = 0;
				}

				/* allocate new reqid id if reqid is zero. */
				if (xisr->sadb_x_ipsecrequest_reqid == 0) {
					u_int32_t reqid;
					if ((reqid = key_newreqid()) == 0) {
						key_freesp(newsp, KEY_SADB_UNLOCKED);
						*error = ENOBUFS;
						return NULL;
					}
					(*p_isr)->saidx.reqid = reqid;
					xisr->sadb_x_ipsecrequest_reqid = reqid;
				} else {
				/* set it for manual keying. */
					(*p_isr)->saidx.reqid =
						xisr->sadb_x_ipsecrequest_reqid;
				}
				break;

			default:
				ipseclog((LOG_DEBUG, "key_msg2sp: invalid level=%u\n",
					xisr->sadb_x_ipsecrequest_level));
				key_freesp(newsp, KEY_SADB_UNLOCKED);
				*error = EINVAL;
				return NULL;
			}
			(*p_isr)->level = xisr->sadb_x_ipsecrequest_level;

			/* set IP addresses if there */
			if (xisr->sadb_x_ipsecrequest_len > sizeof(*xisr)) {
				struct sockaddr *paddr;

				paddr = (struct sockaddr *)(xisr + 1);

				/* validity check */
				if (paddr->sa_len
				    > sizeof((*p_isr)->saidx.src)) {
					ipseclog((LOG_DEBUG, "key_msg2sp: invalid request "
						"address length.\n"));
					key_freesp(newsp, KEY_SADB_UNLOCKED);
					*error = EINVAL;
					return NULL;
				}
				bcopy(paddr, &(*p_isr)->saidx.src,
					paddr->sa_len);

				paddr = (struct sockaddr *)((caddr_t)paddr
							+ paddr->sa_len);

				/* validity check */
				if (paddr->sa_len
				    > sizeof((*p_isr)->saidx.dst)) {
					ipseclog((LOG_DEBUG, "key_msg2sp: invalid request "
						"address length.\n"));
					key_freesp(newsp, KEY_SADB_UNLOCKED);
					*error = EINVAL;
					return NULL;
				}
				bcopy(paddr, &(*p_isr)->saidx.dst,
					paddr->sa_len);
			}

			(*p_isr)->sp = newsp;

			/* initialization for the next. */
			p_isr = &(*p_isr)->next;
			tlen -= xisr->sadb_x_ipsecrequest_len;

			/* validity check */
			if (tlen < 0) {
				ipseclog((LOG_DEBUG, "key_msg2sp: becoming tlen < 0.\n"));
				key_freesp(newsp, KEY_SADB_UNLOCKED);
				*error = EINVAL;
				return NULL;
			}

			xisr = (struct sadb_x_ipsecrequest *)((caddr_t)xisr
			                 + xisr->sadb_x_ipsecrequest_len);
		}
	    }
		break;
	default:
		ipseclog((LOG_DEBUG, "key_msg2sp: invalid policy type.\n"));
		key_freesp(newsp, KEY_SADB_UNLOCKED);
		*error = EINVAL;
		return NULL;
	}

	*error = 0;
	return newsp;
}

static u_int32_t
key_newreqid()
{
	lck_mtx_lock(sadb_mutex);
	static u_int32_t auto_reqid = IPSEC_MANUAL_REQID_MAX + 1;

	auto_reqid = (auto_reqid == ~0
			? IPSEC_MANUAL_REQID_MAX + 1 : auto_reqid + 1);
	lck_mtx_unlock(sadb_mutex);

	/* XXX should be unique check */

	return auto_reqid;
}

/*
 * copy secpolicy struct to sadb_x_policy structure indicated.
 */
struct mbuf *
key_sp2msg(sp)
	struct secpolicy *sp;
{
	struct sadb_x_policy *xpl;
	int tlen;
	caddr_t p;
	struct mbuf *m;

	/* sanity check. */
	if (sp == NULL)
		panic("key_sp2msg: NULL pointer was passed.\n");

	tlen = key_getspreqmsglen(sp);

	m = key_alloc_mbuf(tlen);
	if (!m || m->m_next) {	/*XXX*/
		if (m)
			m_freem(m);
		return NULL;
	}

	m->m_len = tlen;
	m->m_next = NULL;
	xpl = mtod(m, struct sadb_x_policy *);
	bzero(xpl, tlen);

	xpl->sadb_x_policy_len = PFKEY_UNIT64(tlen);
	xpl->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	xpl->sadb_x_policy_type = sp->policy;
	xpl->sadb_x_policy_dir = sp->spidx.dir;
	xpl->sadb_x_policy_id = sp->id;
	p = (caddr_t)xpl + sizeof(*xpl);

	/* if is the policy for ipsec ? */
	if (sp->policy == IPSEC_POLICY_IPSEC) {
		struct sadb_x_ipsecrequest *xisr;
		struct ipsecrequest *isr;

		for (isr = sp->req; isr != NULL; isr = isr->next) {

			xisr = (struct sadb_x_ipsecrequest *)p;

			xisr->sadb_x_ipsecrequest_proto = isr->saidx.proto;
			xisr->sadb_x_ipsecrequest_mode = isr->saidx.mode;
			xisr->sadb_x_ipsecrequest_level = isr->level;
			xisr->sadb_x_ipsecrequest_reqid = isr->saidx.reqid;

			p += sizeof(*xisr);
			bcopy(&isr->saidx.src, p, isr->saidx.src.ss_len);
			p += isr->saidx.src.ss_len;
			bcopy(&isr->saidx.dst, p, isr->saidx.dst.ss_len);
			p += isr->saidx.src.ss_len;

			xisr->sadb_x_ipsecrequest_len =
				PFKEY_ALIGN8(sizeof(*xisr)
					+ isr->saidx.src.ss_len
					+ isr->saidx.dst.ss_len);
		}
	}

	return m;
}

/* m will not be freed nor modified */
static struct mbuf *
key_gather_mbuf(struct mbuf *m, const struct sadb_msghdr *mhp,
	int ndeep, int nitem, int *items)
{
	int idx;
	int i;
	struct mbuf *result = NULL, *n;
	int len;

	if (m == NULL || mhp == NULL)
		panic("null pointer passed to key_gather");

	for (i = 0; i < nitem; i++) {
		idx = items[i];
		if (idx < 0 || idx > SADB_EXT_MAX)
			goto fail;
		/* don't attempt to pull empty extension */
		if (idx == SADB_EXT_RESERVED && mhp->msg == NULL)
			continue;
		if (idx != SADB_EXT_RESERVED  &&
		    (mhp->ext[idx] == NULL || mhp->extlen[idx] == 0))
			continue;

		if (idx == SADB_EXT_RESERVED) {
			len = PFKEY_ALIGN8(sizeof(struct sadb_msg));
#if DIAGNOSTIC
			if (len > MHLEN)
				panic("assumption failed");
#endif
			MGETHDR(n, M_DONTWAIT, MT_DATA);
			if (!n)
				goto fail;
			n->m_len = len;
			n->m_next = NULL;
			m_copydata(m, 0, sizeof(struct sadb_msg),
			    mtod(n, caddr_t));
		} else if (i < ndeep) {
			len = mhp->extlen[idx];
			n = key_alloc_mbuf(len);
			if (!n || n->m_next) {	/*XXX*/
				if (n)
					m_freem(n);
				goto fail;
			}
			m_copydata(m, mhp->extoff[idx], mhp->extlen[idx],
			    mtod(n, caddr_t));
		} else {
			n = m_copym(m, mhp->extoff[idx], mhp->extlen[idx],
			    M_DONTWAIT);
		}
		if (n == NULL)
			goto fail;

		if (result)
			m_cat(result, n);
		else
			result = n;
	}

	if ((result->m_flags & M_PKTHDR) != 0) {
		result->m_pkthdr.len = 0;
		for (n = result; n; n = n->m_next)
			result->m_pkthdr.len += n->m_len;
	}

	return result;

fail:
	m_freem(result);
	return NULL;
}

/*
 * SADB_X_SPDADD, SADB_X_SPDSETIDX or SADB_X_SPDUPDATE processing
 * add a entry to SP database, when received
 *   <base, address(SD), (lifetime(H),) policy>
 * from the user(?).
 * Adding to SP database,
 * and send
 *   <base, address(SD), (lifetime(H),) policy>
 * to the socket which was send.
 *
 * SPDADD set a unique policy entry.
 * SPDSETIDX like SPDADD without a part of policy requests.
 * SPDUPDATE replace a unique policy entry.
 *
 * m will always be freed.
 */
static int
key_spdadd(so, m, mhp)
	struct socket *so;
	struct mbuf *m;
	const struct sadb_msghdr *mhp;
{
	struct sadb_address *src0, *dst0;
	struct sadb_x_policy *xpl0, *xpl;
	struct sadb_lifetime *lft = NULL;
	struct secpolicyindex spidx;
	struct secpolicy *newsp;
	struct timeval tv;
	int error;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_spdadd: NULL pointer is passed.\n");

	if (mhp->ext[SADB_EXT_ADDRESS_SRC] == NULL ||
	    mhp->ext[SADB_EXT_ADDRESS_DST] == NULL ||
	    mhp->ext[SADB_X_EXT_POLICY] == NULL) {
		ipseclog((LOG_DEBUG, "key_spdadd: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}
	if (mhp->extlen[SADB_EXT_ADDRESS_SRC] < sizeof(struct sadb_address) ||
	    mhp->extlen[SADB_EXT_ADDRESS_DST] < sizeof(struct sadb_address) ||
	    mhp->extlen[SADB_X_EXT_POLICY] < sizeof(struct sadb_x_policy)) {
		ipseclog((LOG_DEBUG, "key_spdadd: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}
	if (mhp->ext[SADB_EXT_LIFETIME_HARD] != NULL) {
		if (mhp->extlen[SADB_EXT_LIFETIME_HARD]
			< sizeof(struct sadb_lifetime)) {
			ipseclog((LOG_DEBUG, "key_spdadd: invalid message is passed.\n"));
			return key_senderror(so, m, EINVAL);
		}
		lft = (struct sadb_lifetime *)mhp->ext[SADB_EXT_LIFETIME_HARD];
	}

	src0 = (struct sadb_address *)mhp->ext[SADB_EXT_ADDRESS_SRC];
	dst0 = (struct sadb_address *)mhp->ext[SADB_EXT_ADDRESS_DST];
	xpl0 = (struct sadb_x_policy *)mhp->ext[SADB_X_EXT_POLICY];

	/* make secindex */
	/* XXX boundary check against sa_len */
	KEY_SETSECSPIDX(xpl0->sadb_x_policy_dir,
	                src0 + 1,
	                dst0 + 1,
	                src0->sadb_address_prefixlen,
	                dst0->sadb_address_prefixlen,
	                src0->sadb_address_proto,
	                &spidx);

	/* checking the direciton. */
	switch (xpl0->sadb_x_policy_dir) {
	case IPSEC_DIR_INBOUND:
	case IPSEC_DIR_OUTBOUND:
		break;
	default:
		ipseclog((LOG_DEBUG, "key_spdadd: Invalid SP direction.\n"));
		mhp->msg->sadb_msg_errno = EINVAL;
		return 0;
	}

	/* check policy */
	/* key_spdadd() accepts DISCARD, NONE and IPSEC. */
	if (xpl0->sadb_x_policy_type == IPSEC_POLICY_ENTRUST
	 || xpl0->sadb_x_policy_type == IPSEC_POLICY_BYPASS) {
		ipseclog((LOG_DEBUG, "key_spdadd: Invalid policy type.\n"));
		return key_senderror(so, m, EINVAL);
	}

	/* policy requests are mandatory when action is ipsec. */
     if (mhp->msg->sadb_msg_type != SADB_X_SPDSETIDX
	 && xpl0->sadb_x_policy_type == IPSEC_POLICY_IPSEC
	 && mhp->extlen[SADB_X_EXT_POLICY] <= sizeof(*xpl0)) {
		ipseclog((LOG_DEBUG, "key_spdadd: some policy requests part required.\n"));
		return key_senderror(so, m, EINVAL);
	}

	/*
	 * checking there is SP already or not.
	 * SPDUPDATE doesn't depend on whether there is a SP or not.
	 * If the type is either SPDADD or SPDSETIDX AND a SP is found,
	 * then error.
	 */
	lck_mtx_lock(sadb_mutex);
	newsp = key_getsp(&spidx);
	if (mhp->msg->sadb_msg_type == SADB_X_SPDUPDATE) {
		if (newsp) {
			newsp->state = IPSEC_SPSTATE_DEAD;
			key_freesp(newsp, KEY_SADB_LOCKED);
		}
	} else {
		if (newsp != NULL) {
			key_freesp(newsp, KEY_SADB_LOCKED);
			ipseclog((LOG_DEBUG, "key_spdadd: a SP entry exists already.\n"));
			lck_mtx_unlock(sadb_mutex);
			return key_senderror(so, m, EEXIST);
		}
	}
	lck_mtx_unlock(sadb_mutex);
	/* allocation new SP entry */
	if ((newsp = key_msg2sp(xpl0, PFKEY_EXTLEN(xpl0), &error)) == NULL) {
		return key_senderror(so, m, error);
	}

	if ((newsp->id = key_getnewspid()) == 0) {
		keydb_delsecpolicy(newsp);
		return key_senderror(so, m, ENOBUFS);
	}

	/* XXX boundary check against sa_len */
	KEY_SETSECSPIDX(xpl0->sadb_x_policy_dir,
	                src0 + 1,
	                dst0 + 1,
	                src0->sadb_address_prefixlen,
	                dst0->sadb_address_prefixlen,
	                src0->sadb_address_proto,
	                &newsp->spidx);

	/* sanity check on addr pair */
	if (((struct sockaddr *)(src0 + 1))->sa_family !=
			((struct sockaddr *)(dst0+ 1))->sa_family) {
		keydb_delsecpolicy(newsp);
		return key_senderror(so, m, EINVAL);
	}
	if (((struct sockaddr *)(src0 + 1))->sa_len !=
			((struct sockaddr *)(dst0+ 1))->sa_len) {
		keydb_delsecpolicy(newsp);
		return key_senderror(so, m, EINVAL);
	}
#if 1
	/* 
	 * allow IPv6 over IPv4 tunnels using ESP - 
	 * otherwise reject if inner and outer address families not equal 
	 */
	if (newsp->req && newsp->req->saidx.src.ss_family) {
		struct sockaddr *sa;
		sa = (struct sockaddr *)(src0 + 1);
		if (sa->sa_family != newsp->req->saidx.src.ss_family) {
			if (newsp->req->saidx.mode != IPSEC_MODE_TUNNEL || newsp->req->saidx.proto != IPPROTO_ESP
			    || sa->sa_family != AF_INET6 || newsp->req->saidx.src.ss_family != AF_INET) {
				keydb_delsecpolicy(newsp);
				return key_senderror(so, m, EINVAL);
			}
		}
	}
	if (newsp->req && newsp->req->saidx.dst.ss_family) {
		struct sockaddr *sa;
		sa = (struct sockaddr *)(dst0 + 1);
		if (sa->sa_family != newsp->req->saidx.dst.ss_family) {
			if (newsp->req->saidx.mode != IPSEC_MODE_TUNNEL || newsp->req->saidx.proto != IPPROTO_ESP
			    || sa->sa_family != AF_INET6 || newsp->req->saidx.dst.ss_family != AF_INET) {
				keydb_delsecpolicy(newsp);
				return key_senderror(so, m, EINVAL);
			}
		}
	}
#endif

	microtime(&tv);
	newsp->created = tv.tv_sec;
	newsp->lastused = tv.tv_sec;
	newsp->lifetime = lft ? lft->sadb_lifetime_addtime : 0;
	newsp->validtime = lft ? lft->sadb_lifetime_usetime : 0;

	newsp->refcnt = 1;	/* do not reclaim until I say I do */
	newsp->state = IPSEC_SPSTATE_ALIVE;
	lck_mtx_lock(sadb_mutex);
	/*
	 * policies of type generate should be at the end of the SPD
	 * because they function as default discard policies
       	 */
	if (newsp->policy == IPSEC_POLICY_GENERATE)
		LIST_INSERT_TAIL(&sptree[newsp->spidx.dir], newsp, secpolicy, chain);
	else {  /* XXX until we have policy ordering in the kernel */
		struct secpolicy *tmpsp;

		LIST_FOREACH(tmpsp, &sptree[newsp->spidx.dir], chain)
			if (tmpsp->policy == IPSEC_POLICY_GENERATE)
				break;
		if (tmpsp)
			LIST_INSERT_BEFORE(tmpsp, newsp, chain);
		else
			LIST_INSERT_TAIL(&sptree[newsp->spidx.dir], newsp, secpolicy, chain);
	}

	ipsec_policy_count++;
	/* Turn off the ipsec bypass */
	if (ipsec_bypass != 0)
		ipsec_bypass = 0;

	/* delete the entry in spacqtree */
	if (mhp->msg->sadb_msg_type == SADB_X_SPDUPDATE) {
		struct secspacq *spacq;
		if ((spacq = key_getspacq(&spidx)) != NULL) {
			/* reset counter in order to deletion by timehandler. */
			microtime(&tv);
			spacq->created = tv.tv_sec;
			spacq->count = 0;
		}
    }
	lck_mtx_unlock(sadb_mutex);

    {
	struct mbuf *n, *mpolicy;
	struct sadb_msg *newmsg;
	int off;

	/* create new sadb_msg to reply. */
	if (lft) {
		int	mbufItems[] = {SADB_EXT_RESERVED, SADB_X_EXT_POLICY,
					   SADB_EXT_LIFETIME_HARD, SADB_EXT_ADDRESS_SRC,
					   SADB_EXT_ADDRESS_DST};
		n = key_gather_mbuf(m, mhp, 2, sizeof(mbufItems)/sizeof(int), mbufItems);
	} else {
		int	mbufItems[] = {SADB_EXT_RESERVED, SADB_X_EXT_POLICY,
					   SADB_EXT_ADDRESS_SRC, SADB_EXT_ADDRESS_DST};
		n = key_gather_mbuf(m, mhp, 2, sizeof(mbufItems)/sizeof(int), mbufItems);
	}
	if (!n)
		return key_senderror(so, m, ENOBUFS);

	if (n->m_len < sizeof(*newmsg)) {
		n = m_pullup(n, sizeof(*newmsg));
		if (!n)
			return key_senderror(so, m, ENOBUFS);
	}
	newmsg = mtod(n, struct sadb_msg *);
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(n->m_pkthdr.len);

	off = 0;
	mpolicy = m_pulldown(n, PFKEY_ALIGN8(sizeof(struct sadb_msg)),
	    sizeof(*xpl), &off);
	if (mpolicy == NULL) {
		/* n is already freed */
		return key_senderror(so, m, ENOBUFS);
	}
	xpl = (struct sadb_x_policy *)(mtod(mpolicy, caddr_t) + off);
	if (xpl->sadb_x_policy_exttype != SADB_X_EXT_POLICY) {
		m_freem(n);
		return key_senderror(so, m, EINVAL);
	}
	xpl->sadb_x_policy_id = newsp->id;

	m_freem(m);
	return key_sendup_mbuf(so, n, KEY_SENDUP_ALL);
    }
}

/*
 * get new policy id.
 * OUT:
 *	0:	failure.
 *	others: success.
 */
static u_int32_t
key_getnewspid()
{
	u_int32_t newid = 0;
	int count = key_spi_trycnt;	/* XXX */
	struct secpolicy *sp;
	
	/* when requesting to allocate spi ranged */
	lck_mtx_lock(sadb_mutex);
	while (count--) {
		newid = (policy_id = (policy_id == ~0 ? 1 : policy_id + 1));

		if ((sp = key_getspbyid(newid)) == NULL)
			break;

		key_freesp(sp, KEY_SADB_LOCKED);
	}
	lck_mtx_unlock(sadb_mutex);
	if (count == 0 || newid == 0) {
		ipseclog((LOG_DEBUG, "key_getnewspid: to allocate policy id is failed.\n"));
		return 0;
	}

	return newid;
}

/*
 * SADB_SPDDELETE processing
 * receive
 *   <base, address(SD), policy(*)>
 * from the user(?), and set SADB_SASTATE_DEAD,
 * and send,
 *   <base, address(SD), policy(*)>
 * to the ikmpd.
 * policy(*) including direction of policy.
 *
 * m will always be freed.
 */
static int
key_spddelete(so, m, mhp)
	struct socket *so;
	struct mbuf *m;
	const struct sadb_msghdr *mhp;
{
	struct sadb_address *src0, *dst0;
	struct sadb_x_policy *xpl0;
	struct secpolicyindex spidx;
	struct secpolicy *sp;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_spddelete: NULL pointer is passed.\n");

	if (mhp->ext[SADB_EXT_ADDRESS_SRC] == NULL ||
	    mhp->ext[SADB_EXT_ADDRESS_DST] == NULL ||
	    mhp->ext[SADB_X_EXT_POLICY] == NULL) {
		ipseclog((LOG_DEBUG, "key_spddelete: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}
	if (mhp->extlen[SADB_EXT_ADDRESS_SRC] < sizeof(struct sadb_address) ||
	    mhp->extlen[SADB_EXT_ADDRESS_DST] < sizeof(struct sadb_address) ||
	    mhp->extlen[SADB_X_EXT_POLICY] < sizeof(struct sadb_x_policy)) {
		ipseclog((LOG_DEBUG, "key_spddelete: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	src0 = (struct sadb_address *)mhp->ext[SADB_EXT_ADDRESS_SRC];
	dst0 = (struct sadb_address *)mhp->ext[SADB_EXT_ADDRESS_DST];
	xpl0 = (struct sadb_x_policy *)mhp->ext[SADB_X_EXT_POLICY];

	/* make secindex */
	/* XXX boundary check against sa_len */
	KEY_SETSECSPIDX(xpl0->sadb_x_policy_dir,
	                src0 + 1,
	                dst0 + 1,
	                src0->sadb_address_prefixlen,
	                dst0->sadb_address_prefixlen,
	                src0->sadb_address_proto,
	                &spidx);

	/* checking the direciton. */
	switch (xpl0->sadb_x_policy_dir) {
	case IPSEC_DIR_INBOUND:
	case IPSEC_DIR_OUTBOUND:
		break;
	default:
		ipseclog((LOG_DEBUG, "key_spddelete: Invalid SP direction.\n"));
		return key_senderror(so, m, EINVAL);
	}

	/* Is there SP in SPD ? */
	lck_mtx_lock(sadb_mutex);
	if ((sp = key_getsp(&spidx)) == NULL) {
		ipseclog((LOG_DEBUG, "key_spddelete: no SP found.\n"));
		lck_mtx_unlock(sadb_mutex);
		return key_senderror(so, m, EINVAL);
	}

	/* save policy id to buffer to be returned. */
	xpl0->sadb_x_policy_id = sp->id;

	sp->state = IPSEC_SPSTATE_DEAD;
	key_freesp(sp, KEY_SADB_LOCKED);
	lck_mtx_unlock(sadb_mutex);


    {
	struct mbuf *n;
	struct sadb_msg *newmsg;
	int	mbufItems[] = {SADB_EXT_RESERVED, SADB_X_EXT_POLICY,
					SADB_EXT_ADDRESS_SRC, SADB_EXT_ADDRESS_DST};

	/* create new sadb_msg to reply. */
	n = key_gather_mbuf(m, mhp, 1, sizeof(mbufItems)/sizeof(int), mbufItems);
	if (!n)
		return key_senderror(so, m, ENOBUFS);

	newmsg = mtod(n, struct sadb_msg *);
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(n->m_pkthdr.len);

	m_freem(m);
	return key_sendup_mbuf(so, n, KEY_SENDUP_ALL);
    }
}

/*
 * SADB_SPDDELETE2 processing
 * receive
 *   <base, policy(*)>
 * from the user(?), and set SADB_SASTATE_DEAD,
 * and send,
 *   <base, policy(*)>
 * to the ikmpd.
 * policy(*) including direction of policy.
 *
 * m will always be freed.
 */
static int
key_spddelete2(so, m, mhp)
	struct socket *so;
	struct mbuf *m;
	const struct sadb_msghdr *mhp;
{
	u_int32_t id;
	struct secpolicy *sp;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_spddelete2: NULL pointer is passed.\n");

	if (mhp->ext[SADB_X_EXT_POLICY] == NULL ||
	    mhp->extlen[SADB_X_EXT_POLICY] < sizeof(struct sadb_x_policy)) {
		ipseclog((LOG_DEBUG, "key_spddelete2: invalid message is passed.\n"));
		key_senderror(so, m, EINVAL);
		return 0;
	}

	id = ((struct sadb_x_policy *)mhp->ext[SADB_X_EXT_POLICY])->sadb_x_policy_id;

	/* Is there SP in SPD ? */
	lck_mtx_lock(sadb_mutex);
	if ((sp = key_getspbyid(id)) == NULL) {
		lck_mtx_unlock(sadb_mutex);
		ipseclog((LOG_DEBUG, "key_spddelete2: no SP found id:%u.\n", id));
		return key_senderror(so, m, EINVAL);
	}

	sp->state = IPSEC_SPSTATE_DEAD;
	key_freesp(sp, KEY_SADB_LOCKED);
	lck_mtx_unlock(sadb_mutex);

    {
	struct mbuf *n, *nn;
	struct sadb_msg *newmsg;
	int off, len;

	/* create new sadb_msg to reply. */
	len = PFKEY_ALIGN8(sizeof(struct sadb_msg));

	if (len > MCLBYTES)
		return key_senderror(so, m, ENOBUFS);
	MGETHDR(n, M_DONTWAIT, MT_DATA);
	if (n && len > MHLEN) {
		MCLGET(n, M_DONTWAIT);
		if ((n->m_flags & M_EXT) == 0) {
			m_freem(n);
			n = NULL;
		}
	}
	if (!n)
		return key_senderror(so, m, ENOBUFS);

	n->m_len = len;
	n->m_next = NULL;
	off = 0;

	m_copydata(m, 0, sizeof(struct sadb_msg), mtod(n, caddr_t) + off);
	off += PFKEY_ALIGN8(sizeof(struct sadb_msg));

#if DIAGNOSTIC
	if (off != len)
		panic("length inconsistency in key_spddelete2");
#endif

	n->m_next = m_copym(m, mhp->extoff[SADB_X_EXT_POLICY],
	    mhp->extlen[SADB_X_EXT_POLICY], M_DONTWAIT);
	if (!n->m_next) {
		m_freem(n);
		return key_senderror(so, m, ENOBUFS);
	}

	n->m_pkthdr.len = 0;
	for (nn = n; nn; nn = nn->m_next)
		n->m_pkthdr.len += nn->m_len;

	newmsg = mtod(n, struct sadb_msg *);
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(n->m_pkthdr.len);

	m_freem(m);
	return key_sendup_mbuf(so, n, KEY_SENDUP_ALL);
    }
}

/*
 * SADB_X_GET processing
 * receive
 *   <base, policy(*)>
 * from the user(?),
 * and send,
 *   <base, address(SD), policy>
 * to the ikmpd.
 * policy(*) including direction of policy.
 *
 * m will always be freed.
 */
static int
key_spdget(so, m, mhp)
	struct socket *so;
	struct mbuf *m;
	const struct sadb_msghdr *mhp;
{
	u_int32_t id;
	struct secpolicy *sp;
	struct mbuf *n;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_spdget: NULL pointer is passed.\n");

	if (mhp->ext[SADB_X_EXT_POLICY] == NULL ||
	    mhp->extlen[SADB_X_EXT_POLICY] < sizeof(struct sadb_x_policy)) {
		ipseclog((LOG_DEBUG, "key_spdget: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	id = ((struct sadb_x_policy *)mhp->ext[SADB_X_EXT_POLICY])->sadb_x_policy_id;

	/* Is there SP in SPD ? */
	lck_mtx_lock(sadb_mutex);
	if ((sp = key_getspbyid(id)) == NULL) {
		ipseclog((LOG_DEBUG, "key_spdget: no SP found id:%u.\n", id));
		lck_mtx_unlock(sadb_mutex);
		return key_senderror(so, m, ENOENT);
	}
	lck_mtx_unlock(sadb_mutex);
	n = key_setdumpsp(sp, SADB_X_SPDGET, 0, mhp->msg->sadb_msg_pid);
	if (n != NULL) {
		m_freem(m);
		return key_sendup_mbuf(so, n, KEY_SENDUP_ONE);
	} else
		return key_senderror(so, m, ENOBUFS);
}

/*
 * SADB_X_SPDACQUIRE processing.
 * Acquire policy and SA(s) for a *OUTBOUND* packet.
 * send
 *   <base, policy(*)>
 * to KMD, and expect to receive
 *   <base> with SADB_X_SPDACQUIRE if error occurred,
 * or
 *   <base, policy>
 * with SADB_X_SPDUPDATE from KMD by PF_KEY.
 * policy(*) is without policy requests.
 *
 *    0     : succeed
 *    others: error number
 */
int
key_spdacquire(sp)
	struct secpolicy *sp;
{
	struct mbuf *result = NULL, *m;
	struct secspacq *newspacq;
	int error;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	/* sanity check */
	if (sp == NULL)
		panic("key_spdacquire: NULL pointer is passed.\n");
	if (sp->req != NULL)
		panic("key_spdacquire: called but there is request.\n");
	if (sp->policy != IPSEC_POLICY_IPSEC)
		panic("key_spdacquire: policy mismathed. IPsec is expected.\n");

	/* get a entry to check whether sent message or not. */
	lck_mtx_lock(sadb_mutex);
	if ((newspacq = key_getspacq(&sp->spidx)) != NULL) {
		if (key_blockacq_count < newspacq->count) {
			/* reset counter and do send message. */
			newspacq->count = 0;
		} else {
			/* increment counter and do nothing. */
			newspacq->count++;
			lck_mtx_unlock(sadb_mutex);
			return 0;
		}
	} else {
		/* make new entry for blocking to send SADB_ACQUIRE. */
		if ((newspacq = key_newspacq(&sp->spidx)) == NULL) {
			lck_mtx_unlock(sadb_mutex);
			return ENOBUFS;
		}
		/* add to acqtree */
		LIST_INSERT_HEAD(&spacqtree, newspacq, chain);
	}
	lck_mtx_unlock(sadb_mutex);
	/* create new sadb_msg to reply. */
	m = key_setsadbmsg(SADB_X_SPDACQUIRE, 0, 0, 0, 0, 0);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	result = m;

	result->m_pkthdr.len = 0;
	for (m = result; m; m = m->m_next)
		result->m_pkthdr.len += m->m_len;

	mtod(result, struct sadb_msg *)->sadb_msg_len =
	    PFKEY_UNIT64(result->m_pkthdr.len);

	return key_sendup_mbuf(NULL, m, KEY_SENDUP_REGISTERED);

fail:
	if (result)
		m_freem(result);
	return error;
}

/*
 * SADB_SPDFLUSH processing
 * receive
 *   <base>
 * from the user, and free all entries in secpctree.
 * and send,
 *   <base>
 * to the user.
 * NOTE: what to do is only marking SADB_SASTATE_DEAD.
 *
 * m will always be freed.
 */
static int
key_spdflush(so, m, mhp)
	struct socket *so;
	struct mbuf *m;
	const struct sadb_msghdr *mhp;
{
	struct sadb_msg *newmsg;
	struct secpolicy *sp;
	u_int dir;
	
	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_spdflush: NULL pointer is passed.\n");

	if (m->m_len != PFKEY_ALIGN8(sizeof(struct sadb_msg)))
		return key_senderror(so, m, EINVAL);

	lck_mtx_lock(sadb_mutex);
	for (dir = 0; dir < IPSEC_DIR_MAX; dir++) {
		LIST_FOREACH(sp, &sptree[dir], chain) {
			sp->state = IPSEC_SPSTATE_DEAD;
		}
	}
	lck_mtx_unlock(sadb_mutex);
	
	if (sizeof(struct sadb_msg) > m->m_len + M_TRAILINGSPACE(m)) {
		ipseclog((LOG_DEBUG, "key_spdflush: No more memory.\n"));
		return key_senderror(so, m, ENOBUFS);
	}

	if (m->m_next)
		m_freem(m->m_next);
	m->m_next = NULL;
	m->m_pkthdr.len = m->m_len = PFKEY_ALIGN8(sizeof(struct sadb_msg));
	newmsg = mtod(m, struct sadb_msg *);
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(m->m_pkthdr.len);

	return key_sendup_mbuf(so, m, KEY_SENDUP_ALL);
}

/*
 * SADB_SPDDUMP processing
 * receive
 *   <base>
 * from the user, and dump all SP leaves
 * and send,
 *   <base> .....
 * to the ikmpd.
 *
 * m will always be freed.
 */
 	
static int
key_spddump(so, m, mhp)
	struct socket *so;
	struct mbuf *m;
	const struct sadb_msghdr *mhp;
{
	struct secpolicy *sp, **spbuf = NULL, **sp_ptr;
	int cnt = 0, bufcount;
	u_int dir;
	struct mbuf *n;
	int error = 0;
	
	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_spddump: NULL pointer is passed.\n");

	if ((bufcount = ipsec_policy_count) == 0) {
		error = ENOENT;
		goto end;
	}
	bufcount += 256;	/* extra */
	KMALLOC_WAIT(spbuf, struct secpolicy**, bufcount * sizeof(struct secpolicy*));
	if (spbuf == NULL) {
		ipseclog((LOG_DEBUG, "key_spddump: No more memory.\n"));
		error = ENOMEM;
		goto end;
	}
	lck_mtx_lock(sadb_mutex);
	/* search SPD entry, make list. */
	sp_ptr = spbuf;
	for (dir = 0; dir < IPSEC_DIR_MAX; dir++) {
		LIST_FOREACH(sp, &sptree[dir], chain) {
			if (cnt == bufcount)	
				break;		/* buffer full */
			*sp_ptr++ = sp;
			sp->refcnt++;
			cnt++;
		}
	}
	lck_mtx_unlock(sadb_mutex);

	if (cnt == 0) {
		error = ENOENT;
		goto end;
	}
	
	sp_ptr = spbuf;
	while (cnt) {
		--cnt;
		n = key_setdumpsp(*sp_ptr++, SADB_X_SPDDUMP, cnt,
			mhp->msg->sadb_msg_pid);

		if (n)
			key_sendup_mbuf(so, n, KEY_SENDUP_ONE);
	}
	
	lck_mtx_lock(sadb_mutex);
	while (sp_ptr > spbuf)
		key_freesp(*(--sp_ptr), KEY_SADB_LOCKED);
	lck_mtx_unlock(sadb_mutex);
	
end:	
	if (spbuf)
		KFREE(spbuf);
	if (error)
		return key_senderror(so, m, error);

	m_freem(m);
	return 0;

}

static struct mbuf *
key_setdumpsp(sp, type, seq, pid)
	struct secpolicy *sp;
	u_int8_t type;
	u_int32_t seq, pid;
{
	struct mbuf *result = NULL, *m;

	m = key_setsadbmsg(type, 0, SADB_SATYPE_UNSPEC, seq, pid, sp->refcnt);
	if (!m)
		goto fail;
	result = m;

	m = key_setsadbaddr(SADB_EXT_ADDRESS_SRC,
	    (struct sockaddr *)&sp->spidx.src, sp->spidx.prefs,
	    sp->spidx.ul_proto);
	if (!m)
		goto fail;
	m_cat(result, m);

	m = key_setsadbaddr(SADB_EXT_ADDRESS_DST,
	    (struct sockaddr *)&sp->spidx.dst, sp->spidx.prefd,
	    sp->spidx.ul_proto);
	if (!m)
		goto fail;
	m_cat(result, m);

	m = key_sp2msg(sp);
	if (!m)
		goto fail;
	m_cat(result, m);

	if ((result->m_flags & M_PKTHDR) == 0)
		goto fail;

	if (result->m_len < sizeof(struct sadb_msg)) {
		result = m_pullup(result, sizeof(struct sadb_msg));
		if (result == NULL)
			goto fail;
	}

	result->m_pkthdr.len = 0;
	for (m = result; m; m = m->m_next)
		result->m_pkthdr.len += m->m_len;

	mtod(result, struct sadb_msg *)->sadb_msg_len =
	    PFKEY_UNIT64(result->m_pkthdr.len);

	return result;

fail:
	m_freem(result);
	return NULL;
}

/*
 * get PFKEY message length for security policy and request.
 */
static u_int
key_getspreqmsglen(sp)
	struct secpolicy *sp;
{
	u_int tlen;

	tlen = sizeof(struct sadb_x_policy);

	/* if is the policy for ipsec ? */
	if (sp->policy != IPSEC_POLICY_IPSEC)
		return tlen;

	/* get length of ipsec requests */
    {
	struct ipsecrequest *isr;
	int len;

	for (isr = sp->req; isr != NULL; isr = isr->next) {
		len = sizeof(struct sadb_x_ipsecrequest)
			+ isr->saidx.src.ss_len
			+ isr->saidx.dst.ss_len;

		tlen += PFKEY_ALIGN8(len);
	}
    }

	return tlen;
}

/*
 * SADB_SPDEXPIRE processing
 * send
 *   <base, address(SD), lifetime(CH), policy>
 * to KMD by PF_KEY.
 *
 * OUT:	0	: succeed
 *	others	: error number
 */
static int
key_spdexpire(sp)
	struct secpolicy *sp;
{
	struct mbuf *result = NULL, *m;
	int len;
	int error = -1;
	struct sadb_lifetime *lt;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	/* sanity check */
	if (sp == NULL)
		panic("key_spdexpire: NULL pointer is passed.\n");

	/* set msg header */
	m = key_setsadbmsg(SADB_X_SPDEXPIRE, 0, 0, 0, 0, 0);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	result = m;

	/* create lifetime extension (current and hard) */
	len = PFKEY_ALIGN8(sizeof(*lt)) * 2;
	m = key_alloc_mbuf(len);
	if (!m || m->m_next) {	/*XXX*/
		if (m)
			m_freem(m);
		error = ENOBUFS;
		goto fail;
	}
	bzero(mtod(m, caddr_t), len);
	lt = mtod(m, struct sadb_lifetime *);
	lt->sadb_lifetime_len = PFKEY_UNIT64(sizeof(struct sadb_lifetime));
	lt->sadb_lifetime_exttype = SADB_EXT_LIFETIME_CURRENT;
	lt->sadb_lifetime_allocations = 0;
	lt->sadb_lifetime_bytes = 0;
	lt->sadb_lifetime_addtime = sp->created;
	lt->sadb_lifetime_usetime = sp->lastused;
	lt = (struct sadb_lifetime *)(mtod(m, caddr_t) + len / 2);
	lt->sadb_lifetime_len = PFKEY_UNIT64(sizeof(struct sadb_lifetime));
	lt->sadb_lifetime_exttype = SADB_EXT_LIFETIME_HARD;
	lt->sadb_lifetime_allocations = 0;
	lt->sadb_lifetime_bytes = 0;
	lt->sadb_lifetime_addtime = sp->lifetime;
	lt->sadb_lifetime_usetime = sp->validtime;
	m_cat(result, m);

	/* set sadb_address for source */
	m = key_setsadbaddr(SADB_EXT_ADDRESS_SRC,
	    (struct sockaddr *)&sp->spidx.src,
	    sp->spidx.prefs, sp->spidx.ul_proto);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	m_cat(result, m);

	/* set sadb_address for destination */
	m = key_setsadbaddr(SADB_EXT_ADDRESS_DST,
	    (struct sockaddr *)&sp->spidx.dst,
	    sp->spidx.prefd, sp->spidx.ul_proto);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	m_cat(result, m);

	/* set secpolicy */
	m = key_sp2msg(sp);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	m_cat(result, m);

	if ((result->m_flags & M_PKTHDR) == 0) {
		error = EINVAL;
		goto fail;
	}

	if (result->m_len < sizeof(struct sadb_msg)) {
		result = m_pullup(result, sizeof(struct sadb_msg));
		if (result == NULL) {
			error = ENOBUFS;
			goto fail;
		}
	}

	result->m_pkthdr.len = 0;
	for (m = result; m; m = m->m_next)
		result->m_pkthdr.len += m->m_len;

	mtod(result, struct sadb_msg *)->sadb_msg_len =
	    PFKEY_UNIT64(result->m_pkthdr.len);

	return key_sendup_mbuf(NULL, result, KEY_SENDUP_REGISTERED);

 fail:
	if (result)
		m_freem(result);
	return error;
}

/* %%% SAD management */
/*
 * allocating a memory for new SA head, and copy from the values of mhp.
 * OUT:	NULL	: failure due to the lack of memory.
 *	others	: pointer to new SA head.
 */
static struct secashead *
key_newsah(saidx, dir)
	struct secasindex *saidx;
	u_int8_t           dir;
{
	struct secashead *newsah;

	/* sanity check */
	if (saidx == NULL)
		panic("key_newsaidx: NULL pointer is passed.\n");

	newsah = keydb_newsecashead();
	if (newsah == NULL)
		return NULL;

	bcopy(saidx, &newsah->saidx, sizeof(newsah->saidx));
	
	/* remove the ports */
	switch (saidx->src.ss_family) {
	        case AF_INET:
			((struct sockaddr_in *)(&newsah->saidx.src))->sin_port = IPSEC_PORT_ANY;
			break;
        	case AF_INET6:
		        ((struct sockaddr_in6 *)(&newsah->saidx.src))->sin6_port = IPSEC_PORT_ANY;
			break;
	        default:
			break;
	}
	switch (saidx->dst.ss_family) {
        	case AF_INET:
		  ((struct sockaddr_in *)(&newsah->saidx.dst))->sin_port = IPSEC_PORT_ANY;
			break;
        	case AF_INET6:
			((struct sockaddr_in6 *)(&newsah->saidx.dst))->sin6_port = IPSEC_PORT_ANY;
			break;
        	default:
			break;
        }

	newsah->dir = dir;
	/* add to saidxtree */
	newsah->state = SADB_SASTATE_MATURE;
	LIST_INSERT_HEAD(&sahtree, newsah, chain);

	return(newsah);
}

/*
 * delete SA index and all SA registerd.
 */
static void
key_delsah(sah)
	struct secashead *sah;
{
	struct secasvar *sav, *nextsav;
	u_int stateidx, state;
	int zombie = 0;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);

	/* sanity check */
	if (sah == NULL)
		panic("key_delsah: NULL pointer is passed.\n");

	/* searching all SA registerd in the secindex. */
	for (stateidx = 0;
	     stateidx < _ARRAYLEN(saorder_state_any);
	     stateidx++) {

		state = saorder_state_any[stateidx];
		for (sav = (struct secasvar *)LIST_FIRST(&sah->savtree[state]);
		     sav != NULL;
		     sav = nextsav) {

			nextsav = LIST_NEXT(sav, chain);

			if (sav->refcnt > 0) {
				/* give up to delete this sa */
				zombie++;
				continue;
			}

			/* sanity check */
			KEY_CHKSASTATE(state, sav->state, "key_delsah");

			key_freesav(sav, KEY_SADB_LOCKED);

			/* remove back pointer */
			sav->sah = NULL;
			sav = NULL;
		}
	}

	/* don't delete sah only if there are savs. */
	if (zombie)
		return;

	if (sah->sa_route.ro_rt) {
		rtfree(sah->sa_route.ro_rt);
		sah->sa_route.ro_rt = (struct rtentry *)NULL;
	}

	/* remove from tree of SA index */
	if (__LIST_CHAINED(sah))
		LIST_REMOVE(sah, chain);

	KFREE(sah);

	return;
}

/*
 * allocating a new SA with LARVAL state.  key_add() and key_getspi() call,
 * and copy the values of mhp into new buffer.
 * When SAD message type is GETSPI:
 *	to set sequence number from acq_seq++,
 *	to set zero to SPI.
 *	not to call key_setsava().
 * OUT:	NULL	: fail
 *	others	: pointer to new secasvar.
 *
 * does not modify mbuf.  does not free mbuf on error.
 */
static struct secasvar *
key_newsav(m, mhp, sah, errp)
	struct mbuf *m;
	const struct sadb_msghdr *mhp;
	struct secashead *sah;
	int *errp;
{
	struct secasvar *newsav;
	const struct sadb_sa *xsa;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);

	/* sanity check */
	if (m == NULL || mhp == NULL || mhp->msg == NULL || sah == NULL)
		panic("key_newsa: NULL pointer is passed.\n");

	KMALLOC_NOWAIT(newsav, struct secasvar *, sizeof(struct secasvar));
	if (newsav == NULL) {
		lck_mtx_unlock(sadb_mutex);
		KMALLOC_WAIT(newsav, struct secasvar *, sizeof(struct secasvar));
		lck_mtx_lock(sadb_mutex);
		if (newsav == NULL) {
			ipseclog((LOG_DEBUG, "key_newsa: No more memory.\n"));
			*errp = ENOBUFS;
			return NULL;
		}
	}
	bzero((caddr_t)newsav, sizeof(struct secasvar));

	switch (mhp->msg->sadb_msg_type) {
	case SADB_GETSPI:
		key_setspi(newsav, 0);

#if IPSEC_DOSEQCHECK
		/* sync sequence number */
		if (mhp->msg->sadb_msg_seq == 0)
			newsav->seq =
				(acq_seq = (acq_seq == ~0 ? 1 : ++acq_seq));
		else
#endif
			newsav->seq = mhp->msg->sadb_msg_seq;
		break;

	case SADB_ADD:
		/* sanity check */
		if (mhp->ext[SADB_EXT_SA] == NULL) {
			KFREE(newsav);
			ipseclog((LOG_DEBUG, "key_newsa: invalid message is passed.\n"));
			*errp = EINVAL;
			return NULL;
		}
		xsa = (const struct sadb_sa *)mhp->ext[SADB_EXT_SA];
		key_setspi(newsav, xsa->sadb_sa_spi);
		newsav->seq = mhp->msg->sadb_msg_seq;
		break;
	default:
		KFREE(newsav);
		*errp = EINVAL;
		return NULL;
	}

	/* copy sav values */
	if (mhp->msg->sadb_msg_type != SADB_GETSPI) {
		*errp = key_setsaval(newsav, m, mhp);
		if (*errp) {
			if (newsav->spihash.le_prev || newsav->spihash.le_next)
				LIST_REMOVE(newsav, spihash);
			KFREE(newsav);
			return NULL;
		}
	}

	/* reset created */
    {
	struct timeval tv;
	microtime(&tv);
	newsav->created = tv.tv_sec;
    }

	newsav->pid = mhp->msg->sadb_msg_pid;

	/* add to satree */
	newsav->sah = sah;
	newsav->refcnt = 1;
	newsav->state = SADB_SASTATE_LARVAL;
	LIST_INSERT_TAIL(&sah->savtree[SADB_SASTATE_LARVAL], newsav,
			secasvar, chain);
	ipsec_sav_count++;

	return newsav;
}

/*
 * free() SA variable entry.
 */
static void
key_delsav(sav)
	struct secasvar *sav;
{

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);
	
	/* sanity check */
	if (sav == NULL)
		panic("key_delsav: NULL pointer is passed.\n");

	if (sav->refcnt > 0)
		return;		/* can't free */
	
	/* remove from SA header */
	if (__LIST_CHAINED(sav))
		LIST_REMOVE(sav, chain);
	ipsec_sav_count--;
		
	if (sav->spihash.le_prev || sav->spihash.le_next)
		LIST_REMOVE(sav, spihash);

	if (sav->key_auth != NULL) {
		bzero(_KEYBUF(sav->key_auth), _KEYLEN(sav->key_auth));
		KFREE(sav->key_auth);
		sav->key_auth = NULL;
	}
	if (sav->key_enc != NULL) {
		bzero(_KEYBUF(sav->key_enc), _KEYLEN(sav->key_enc));
		KFREE(sav->key_enc);
		sav->key_enc = NULL;
	}
	if (sav->sched) {
		bzero(sav->sched, sav->schedlen);
		KFREE(sav->sched);
		sav->sched = NULL;
	}
	if (sav->replay != NULL) {
		keydb_delsecreplay(sav->replay);
		sav->replay = NULL;
	}
	if (sav->lft_c != NULL) {
		KFREE(sav->lft_c);
		sav->lft_c = NULL;
	}
	if (sav->lft_h != NULL) {
		KFREE(sav->lft_h);
		sav->lft_h = NULL;
	}
	if (sav->lft_s != NULL) {
		KFREE(sav->lft_s);
		sav->lft_s = NULL;
	}
	if (sav->iv != NULL) {
		KFREE(sav->iv);
		sav->iv = NULL;
	}

	KFREE(sav);

	return;
}

/*
 * search SAD.
 * OUT:
 *	NULL	: not found
 *	others	: found, pointer to a SA.
 */
static struct secashead *
key_getsah(saidx)
	struct secasindex *saidx;
{
	struct secashead *sah;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);

	LIST_FOREACH(sah, &sahtree, chain) {
		if (sah->state == SADB_SASTATE_DEAD)
			continue;
		if (key_cmpsaidx(&sah->saidx, saidx, CMP_REQID))
			return sah;
	}

	return NULL;
}

/*
 * check not to be duplicated SPI.
 * NOTE: this function is too slow due to searching all SAD.
 * OUT:
 *	NULL	: not found
 *	others	: found, pointer to a SA.
 */
static struct secasvar *
key_checkspidup(saidx, spi)
	struct secasindex *saidx;
	u_int32_t spi;
{
	struct secasvar *sav;
	u_int stateidx, state;
	
	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);

	/* check address family */
	if (saidx->src.ss_family != saidx->dst.ss_family) {
		ipseclog((LOG_DEBUG, "key_checkspidup: address family mismatched.\n"));
		return NULL;
	}

	/* check all SAD */
	LIST_FOREACH(sav, &spihash[SPIHASH(spi)], spihash) {
		if (sav->spi != spi)
			continue;
		for (stateidx = 0;
		     stateidx < _ARRAYLEN(saorder_state_alive);
		     stateidx++) {
			state = saorder_state_alive[stateidx];
			if (sav->state == state &&
			    key_ismyaddr((struct sockaddr *)&sav->sah->saidx.dst))
				return sav;
		}
	}

	return NULL;
}

static void
key_setspi(sav, spi)
	struct secasvar *sav;
	u_int32_t spi;
{
	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);
	sav->spi = spi;
	if (sav->spihash.le_prev || sav->spihash.le_next)
		LIST_REMOVE(sav, spihash);
	LIST_INSERT_HEAD(&spihash[SPIHASH(spi)], sav, spihash);
}


/*
 * search SAD litmited alive SA, protocol, SPI.
 * OUT:
 *	NULL	: not found
 *	others	: found, pointer to a SA.
 */
static struct secasvar *
key_getsavbyspi(sah, spi)
	struct secashead *sah;
	u_int32_t spi;
{
	struct secasvar *sav, *match;
	u_int stateidx, state, matchidx;
			
	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);
	match = NULL;
	matchidx = _ARRAYLEN(saorder_state_alive);
	LIST_FOREACH(sav, &spihash[SPIHASH(spi)], spihash) {
		if (sav->spi != spi)
			continue;
		if (sav->sah != sah)
			continue;
		for (stateidx = 0; stateidx < matchidx; stateidx++) {
			state = saorder_state_alive[stateidx];
			if (sav->state == state) {
				match = sav;
				matchidx = stateidx;
				break;
			}
		}
	}

	return match;
}

/*
 * copy SA values from PF_KEY message except *SPI, SEQ, PID, STATE and TYPE*.
 * You must update these if need.
 * OUT:	0:	success.
 *	!0:	failure.
 *
 * does not modify mbuf.  does not free mbuf on error.
 */
static int
key_setsaval(sav, m, mhp)
	struct secasvar *sav;
	struct mbuf *m;
	const struct sadb_msghdr *mhp;
{
#if IPSEC_ESP
	const struct esp_algorithm *algo;
#endif
	int error = 0;
	struct timeval tv;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);

	/* sanity check */
	if (m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_setsaval: NULL pointer is passed.\n");

	/* initialization */
	sav->replay = NULL;
	sav->key_auth = NULL;
	sav->key_enc = NULL;
	sav->sched = NULL;
	sav->schedlen = 0;
	sav->iv = NULL;
	sav->lft_c = NULL;
	sav->lft_h = NULL;
	sav->lft_s = NULL;
	sav->remote_ike_port = 0;
	sav->natt_last_activity = natt_now;
	sav->natt_encapsulated_src_port = 0;

	/* SA */
	if (mhp->ext[SADB_EXT_SA] != NULL) {
		const struct sadb_sa *sa0;

		sa0 = (const struct sadb_sa *)mhp->ext[SADB_EXT_SA];
		if (mhp->extlen[SADB_EXT_SA] < sizeof(*sa0)) {
			ipseclog((LOG_DEBUG, "key_setsaval: invalid message size.\n"));
			error = EINVAL;
			goto fail;
		}

		sav->alg_auth = sa0->sadb_sa_auth;
		sav->alg_enc = sa0->sadb_sa_encrypt;
		sav->flags = sa0->sadb_sa_flags;
		
		/*
		 * Verify that a nat-traversal port was specified if
		 * the nat-traversal flag is set.
		 */
		if ((sav->flags & SADB_X_EXT_NATT) != 0) {
			if (mhp->extlen[SADB_EXT_SA] < sizeof(struct sadb_sa_2) ||
				 ((const struct sadb_sa_2*)(sa0))->sadb_sa_natt_port == 0) {
				ipseclog((LOG_DEBUG, "key_setsaval: natt port not set.\n"));
				error = EINVAL;
				goto fail;
			}
			sav->remote_ike_port = ((const struct sadb_sa_2*)(sa0))->sadb_sa_natt_port;
		}
		
		/*
		 * Verify if SADB_X_EXT_NATT_MULTIPLEUSERS flag is set that
		 * SADB_X_EXT_NATT is set and SADB_X_EXT_NATT_KEEPALIVE is not 
		 * set (we're not behind nat) - otherwise clear it.
		 */
		if ((sav->flags & SADB_X_EXT_NATT_MULTIPLEUSERS) != 0)
			if ((sav->flags & SADB_X_EXT_NATT) == 0 ||
				(sav->flags & SADB_X_EXT_NATT_KEEPALIVE) != 0)
				sav->flags &= ~SADB_X_EXT_NATT_MULTIPLEUSERS;

		/* replay window */
		if ((sa0->sadb_sa_flags & SADB_X_EXT_OLD) == 0) {
			sav->replay = keydb_newsecreplay(sa0->sadb_sa_replay);
			if (sav->replay == NULL) {
				ipseclog((LOG_DEBUG, "key_setsaval: No more memory.\n"));
				error = ENOBUFS;
				goto fail;
			}
		}
	}

	/* Authentication keys */
	if (mhp->ext[SADB_EXT_KEY_AUTH] != NULL) {
		const struct sadb_key *key0;
		int len;

		key0 = (const struct sadb_key *)mhp->ext[SADB_EXT_KEY_AUTH];
		len = mhp->extlen[SADB_EXT_KEY_AUTH];

		error = 0;
		if (len < sizeof(*key0)) {
			ipseclog((LOG_DEBUG, "key_setsaval: invalid auth key ext len. len = %d\n", len));
			error = EINVAL;
			goto fail;
		}
		switch (mhp->msg->sadb_msg_satype) {
		case SADB_SATYPE_AH:
		case SADB_SATYPE_ESP:
			if (len == PFKEY_ALIGN8(sizeof(struct sadb_key)) &&
			    sav->alg_auth != SADB_X_AALG_NULL)
				error = EINVAL;
			break;
		case SADB_X_SATYPE_IPCOMP:
		default:
			error = EINVAL;
			break;
		}
		if (error) {
			ipseclog((LOG_DEBUG, "key_setsaval: invalid key_auth values.\n"));
			goto fail;
		}

		sav->key_auth = (struct sadb_key *)key_newbuf(key0, len);
		if (sav->key_auth == NULL) {
			ipseclog((LOG_DEBUG, "key_setsaval: No more memory.\n"));
			error = ENOBUFS;
			goto fail;
		}
	}

	/* Encryption key */
	if (mhp->ext[SADB_EXT_KEY_ENCRYPT] != NULL) {
		const struct sadb_key *key0;
		int len;

		key0 = (const struct sadb_key *)mhp->ext[SADB_EXT_KEY_ENCRYPT];
		len = mhp->extlen[SADB_EXT_KEY_ENCRYPT];

		error = 0;
		if (len < sizeof(*key0)) {
			ipseclog((LOG_DEBUG, "key_setsaval: invalid encryption key ext len. len = %d\n", len));
			error = EINVAL;
			goto fail;
		}
		switch (mhp->msg->sadb_msg_satype) {
		case SADB_SATYPE_ESP:
			if (len == PFKEY_ALIGN8(sizeof(struct sadb_key)) &&
			    sav->alg_enc != SADB_EALG_NULL) {
			    ipseclog((LOG_DEBUG, "key_setsaval: invalid ESP algorithm.\n"));
				error = EINVAL;
				break;
			}
			sav->key_enc = (struct sadb_key *)key_newbuf(key0, len);
			if (sav->key_enc == NULL) {
				ipseclog((LOG_DEBUG, "key_setsaval: No more memory.\n"));
				error = ENOBUFS;
				goto fail;
			}
			break;
		case SADB_X_SATYPE_IPCOMP:
			if (len != PFKEY_ALIGN8(sizeof(struct sadb_key)))
				error = EINVAL;
			sav->key_enc = NULL;	/*just in case*/
			break;
		case SADB_SATYPE_AH:
		default:
			error = EINVAL;
			break;
		}
		if (error) {
			ipseclog((LOG_DEBUG, "key_setsaval: invalid key_enc value.\n"));
			goto fail;
		}
	}

	/* set iv */
	sav->ivlen = 0;

	switch (mhp->msg->sadb_msg_satype) {
	case SADB_SATYPE_ESP:
#if IPSEC_ESP
		algo = esp_algorithm_lookup(sav->alg_enc);
		if (algo && algo->ivlen)
			sav->ivlen = (*algo->ivlen)(algo, sav);
		if (sav->ivlen == 0)
			break;
		KMALLOC_NOWAIT(sav->iv, caddr_t, sav->ivlen);
		if (sav->iv == 0) {
			lck_mtx_unlock(sadb_mutex);
			KMALLOC_WAIT(sav->iv, caddr_t, sav->ivlen);
			lck_mtx_lock(sadb_mutex);
			if (sav->iv == 0) {
				ipseclog((LOG_DEBUG, "key_setsaval: No more memory.\n"));
				error = ENOBUFS;
				goto fail;
			}
		}

		/* initialize */
		key_randomfill(sav->iv, sav->ivlen);
#endif
		break;
	case SADB_SATYPE_AH:
	case SADB_X_SATYPE_IPCOMP:
		break;
	default:
		ipseclog((LOG_DEBUG, "key_setsaval: invalid SA type.\n"));
		error = EINVAL;
		goto fail;
	}

	/* reset created */
	microtime(&tv);
	sav->created = tv.tv_sec;

	/* make lifetime for CURRENT */
	KMALLOC_NOWAIT(sav->lft_c, struct sadb_lifetime *,
	    sizeof(struct sadb_lifetime));
	if (sav->lft_c == NULL) {
		lck_mtx_unlock(sadb_mutex);
		KMALLOC_WAIT(sav->lft_c, struct sadb_lifetime *,
	    	sizeof(struct sadb_lifetime));
	    lck_mtx_lock(sadb_mutex);
		if (sav->lft_c == NULL) {
			ipseclog((LOG_DEBUG, "key_setsaval: No more memory.\n"));
			error = ENOBUFS;
			goto fail;
		}
	}

	microtime(&tv);

	sav->lft_c->sadb_lifetime_len =
	    PFKEY_UNIT64(sizeof(struct sadb_lifetime));
	sav->lft_c->sadb_lifetime_exttype = SADB_EXT_LIFETIME_CURRENT;
	sav->lft_c->sadb_lifetime_allocations = 0;
	sav->lft_c->sadb_lifetime_bytes = 0;
	sav->lft_c->sadb_lifetime_addtime = tv.tv_sec;
	sav->lft_c->sadb_lifetime_usetime = 0;

	/* lifetimes for HARD and SOFT */
    {
	const struct sadb_lifetime *lft0;

	lft0 = (struct sadb_lifetime *)mhp->ext[SADB_EXT_LIFETIME_HARD];
	if (lft0 != NULL) {
		if (mhp->extlen[SADB_EXT_LIFETIME_HARD] < sizeof(*lft0)) {
			ipseclog((LOG_DEBUG, "key_setsaval: invalid hard lifetime ext len.\n"));
			error = EINVAL;
			goto fail;
		}
		sav->lft_h = (struct sadb_lifetime *)key_newbuf(lft0,
		    sizeof(*lft0));
		if (sav->lft_h == NULL) {
			ipseclog((LOG_DEBUG, "key_setsaval: No more memory.\n"));
			error = ENOBUFS;
			goto fail;
		}
		/* to be initialize ? */
	}

	lft0 = (struct sadb_lifetime *)mhp->ext[SADB_EXT_LIFETIME_SOFT];
	if (lft0 != NULL) {
		if (mhp->extlen[SADB_EXT_LIFETIME_SOFT] < sizeof(*lft0)) {
			ipseclog((LOG_DEBUG, "key_setsaval: invalid soft lifetime ext len.\n"));
			error = EINVAL;
			goto fail;
		}
		sav->lft_s = (struct sadb_lifetime *)key_newbuf(lft0,
		    sizeof(*lft0));
		if (sav->lft_s == NULL) {
			ipseclog((LOG_DEBUG, "key_setsaval: No more memory.\n"));
			error = ENOBUFS;
			goto fail;
		}
		/* to be initialize ? */
	}
    }

	return 0;

 fail:
	/* initialization */
	if (sav->replay != NULL) {
		keydb_delsecreplay(sav->replay);
		sav->replay = NULL;
	}
	if (sav->key_auth != NULL) {
		bzero(_KEYBUF(sav->key_auth), _KEYLEN(sav->key_auth));
		KFREE(sav->key_auth);
		sav->key_auth = NULL;
	}
	if (sav->key_enc != NULL) {
		bzero(_KEYBUF(sav->key_enc), _KEYLEN(sav->key_enc));
		KFREE(sav->key_enc);
		sav->key_enc = NULL;
	}
	if (sav->sched) {
		bzero(sav->sched, sav->schedlen);
		KFREE(sav->sched);
		sav->sched = NULL;
	}
	if (sav->iv != NULL) {
		KFREE(sav->iv);
		sav->iv = NULL;
	}
	if (sav->lft_c != NULL) {
		KFREE(sav->lft_c);
		sav->lft_c = NULL;
	}
	if (sav->lft_h != NULL) {
		KFREE(sav->lft_h);
		sav->lft_h = NULL;
	}
	if (sav->lft_s != NULL) {
		KFREE(sav->lft_s);
		sav->lft_s = NULL;
	}

	return error;
}

/*
 * validation with a secasvar entry, and set SADB_SATYPE_MATURE.
 * OUT:	0:	valid
 *	other:	errno
 */
static int
key_mature(sav)
	struct secasvar *sav;
{
	int mature;
	int checkmask = 0;	/* 2^0: ealg  2^1: aalg  2^2: calg */
	int mustmask = 0;	/* 2^0: ealg  2^1: aalg  2^2: calg */

	mature = 0;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);

	/* check SPI value */
	switch (sav->sah->saidx.proto) {
	case IPPROTO_ESP:
	case IPPROTO_AH:

		/* No reason to test if this is >= 0, because ntohl(sav->spi) is unsigned. */
		if (ntohl(sav->spi) <= 255) {
			ipseclog((LOG_DEBUG,
			    "key_mature: illegal range of SPI %u.\n",
			    (u_int32_t)ntohl(sav->spi)));
			return EINVAL;
		}
		break;
	}

	/* check satype */
	switch (sav->sah->saidx.proto) {
	case IPPROTO_ESP:
		/* check flags */
		if ((sav->flags & SADB_X_EXT_OLD)
		 && (sav->flags & SADB_X_EXT_DERIV)) {
			ipseclog((LOG_DEBUG, "key_mature: "
			    "invalid flag (derived) given to old-esp.\n"));
			return EINVAL;
		}
		if (sav->alg_auth == SADB_AALG_NONE)
			checkmask = 1;
		else
			checkmask = 3;
		mustmask = 1;
		break;
	case IPPROTO_AH:
		/* check flags */
		if (sav->flags & SADB_X_EXT_DERIV) {
			ipseclog((LOG_DEBUG, "key_mature: "
			    "invalid flag (derived) given to AH SA.\n"));
			return EINVAL;
		}
		if (sav->alg_enc != SADB_EALG_NONE) {
			ipseclog((LOG_DEBUG, "key_mature: "
			    "protocol and algorithm mismated.\n"));
			return(EINVAL);
		}
		checkmask = 2;
		mustmask = 2;
		break;
	case IPPROTO_IPCOMP:
		if (sav->alg_auth != SADB_AALG_NONE) {
			ipseclog((LOG_DEBUG, "key_mature: "
				"protocol and algorithm mismated.\n"));
			return(EINVAL);
		}
		if ((sav->flags & SADB_X_EXT_RAWCPI) == 0
		 && ntohl(sav->spi) >= 0x10000) {
			ipseclog((LOG_DEBUG, "key_mature: invalid cpi for IPComp.\n"));
			return(EINVAL);
		}
		checkmask = 4;
		mustmask = 4;
		break;
	default:
		ipseclog((LOG_DEBUG, "key_mature: Invalid satype.\n"));
		return EPROTONOSUPPORT;
	}

	/* check authentication algorithm */
	if ((checkmask & 2) != 0) {
		const struct ah_algorithm *algo;
		int keylen;

		algo = ah_algorithm_lookup(sav->alg_auth);
		if (!algo) {
			ipseclog((LOG_DEBUG,"key_mature: "
			    "unknown authentication algorithm.\n"));
			return EINVAL;
		}

		/* algorithm-dependent check */
		if (sav->key_auth)
			keylen = sav->key_auth->sadb_key_bits;
		else
			keylen = 0;
		if (keylen < algo->keymin || algo->keymax < keylen) {
			ipseclog((LOG_DEBUG,
			    "key_mature: invalid AH key length %d "
			    "(%d-%d allowed)\n",
			    keylen, algo->keymin, algo->keymax));
			return EINVAL;
		}

		if (algo->mature) {
			if ((*algo->mature)(sav)) {
				/* message generated in per-algorithm function*/
				return EINVAL;
			} else
				mature = SADB_SATYPE_AH;
		}

		if ((mustmask & 2) != 0 &&  mature != SADB_SATYPE_AH) {
			ipseclog((LOG_DEBUG, "key_mature: no satisfy algorithm for AH\n"));
			return EINVAL;
		}
	}

	/* check encryption algorithm */
	if ((checkmask & 1) != 0) {
#if IPSEC_ESP
		const struct esp_algorithm *algo;
		int keylen;

		algo = esp_algorithm_lookup(sav->alg_enc);
		if (!algo) {
			ipseclog((LOG_DEBUG, "key_mature: unknown encryption algorithm.\n"));
			return EINVAL;
		}

		/* algorithm-dependent check */
		if (sav->key_enc)
			keylen = sav->key_enc->sadb_key_bits;
		else
			keylen = 0;
		if (keylen < algo->keymin || algo->keymax < keylen) {
			ipseclog((LOG_DEBUG,
			    "key_mature: invalid ESP key length %d "
			    "(%d-%d allowed)\n",
			    keylen, algo->keymin, algo->keymax));
			return EINVAL;
		}

		if (algo->mature) {
			if ((*algo->mature)(sav)) {
				/* message generated in per-algorithm function*/
				return EINVAL;
			} else
				mature = SADB_SATYPE_ESP;
		}

		if ((mustmask & 1) != 0 &&  mature != SADB_SATYPE_ESP) {
			ipseclog((LOG_DEBUG, "key_mature: no satisfy algorithm for ESP\n"));
			return EINVAL;
		}
#else /*IPSEC_ESP*/
		ipseclog((LOG_DEBUG, "key_mature: ESP not supported in this configuration\n"));
		return EINVAL;
#endif
	}

	/* check compression algorithm */
	if ((checkmask & 4) != 0) {
		const struct ipcomp_algorithm *algo;

		/* algorithm-dependent check */
		algo = ipcomp_algorithm_lookup(sav->alg_enc);
		if (!algo) {
			ipseclog((LOG_DEBUG, "key_mature: unknown compression algorithm.\n"));
			return EINVAL;
		}
	}

	key_sa_chgstate(sav, SADB_SASTATE_MATURE);

	return 0;
}

/*
 * subroutine for SADB_GET and SADB_DUMP.
 */
static struct mbuf *
key_setdumpsa(sav, type, satype, seq, pid)
	struct secasvar *sav;
	u_int8_t type, satype;
	u_int32_t seq, pid;
{
	struct mbuf *result = NULL, *tres = NULL, *m;
	int l = 0;
	int i;
	void *p;
	int dumporder[] = {
		SADB_EXT_SA, SADB_X_EXT_SA2,
		SADB_EXT_LIFETIME_HARD, SADB_EXT_LIFETIME_SOFT,
		SADB_EXT_LIFETIME_CURRENT, SADB_EXT_ADDRESS_SRC,
		SADB_EXT_ADDRESS_DST, SADB_EXT_ADDRESS_PROXY, SADB_EXT_KEY_AUTH,
		SADB_EXT_KEY_ENCRYPT, SADB_EXT_IDENTITY_SRC,
		SADB_EXT_IDENTITY_DST, SADB_EXT_SENSITIVITY,
	};
	
	m = key_setsadbmsg(type, 0, satype, seq, pid, sav->refcnt);
	if (m == NULL)
		goto fail;
	result = m;

	for (i = sizeof(dumporder)/sizeof(dumporder[0]) - 1; i >= 0; i--) {
		m = NULL;
		p = NULL;
		switch (dumporder[i]) {
		case SADB_EXT_SA:
			m = key_setsadbsa(sav);
			if (!m)
				goto fail;
			break;

		case SADB_X_EXT_SA2:
			m = key_setsadbxsa2(sav->sah->saidx.mode,
					sav->replay ? sav->replay->count : 0,
					sav->sah->saidx.reqid);
			if (!m)
				goto fail;
			break;

		case SADB_EXT_ADDRESS_SRC:
			m = key_setsadbaddr(SADB_EXT_ADDRESS_SRC,
			    (struct sockaddr *)&sav->sah->saidx.src,
			    FULLMASK, IPSEC_ULPROTO_ANY);
			if (!m)
				goto fail;
			break;

		case SADB_EXT_ADDRESS_DST:
			m = key_setsadbaddr(SADB_EXT_ADDRESS_DST,
			    (struct sockaddr *)&sav->sah->saidx.dst,
			    FULLMASK, IPSEC_ULPROTO_ANY);
			if (!m)
				goto fail;
			break;

		case SADB_EXT_KEY_AUTH:
			if (!sav->key_auth)
				continue;
			l = PFKEY_UNUNIT64(sav->key_auth->sadb_key_len);
			p = sav->key_auth;
			break;

		case SADB_EXT_KEY_ENCRYPT:
			if (!sav->key_enc)
				continue;
			l = PFKEY_UNUNIT64(sav->key_enc->sadb_key_len);
			p = sav->key_enc;
			break;

		case SADB_EXT_LIFETIME_CURRENT:
			if (!sav->lft_c)
				continue;
			l = PFKEY_UNUNIT64(((struct sadb_ext *)sav->lft_c)->sadb_ext_len);
			p = sav->lft_c;
			break;

		case SADB_EXT_LIFETIME_HARD:
			if (!sav->lft_h)
				continue;
			l = PFKEY_UNUNIT64(((struct sadb_ext *)sav->lft_h)->sadb_ext_len);
			p = sav->lft_h;
			break;

		case SADB_EXT_LIFETIME_SOFT:
			if (!sav->lft_s)
				continue;
			l = PFKEY_UNUNIT64(((struct sadb_ext *)sav->lft_s)->sadb_ext_len);
			p = sav->lft_s;
			break;

		case SADB_EXT_ADDRESS_PROXY:
		case SADB_EXT_IDENTITY_SRC:
		case SADB_EXT_IDENTITY_DST:
			/* XXX: should we brought from SPD ? */
		case SADB_EXT_SENSITIVITY:
		default:
			continue;
		}

		if ((!m && !p) || (m && p))
			goto fail;
		if (p && tres) {
			M_PREPEND(tres, l, M_DONTWAIT);
			if (!tres)
				goto fail;
			bcopy(p, mtod(tres, caddr_t), l);
			continue;
		}
		if (p) {
			m = key_alloc_mbuf(l);
			if (!m)
				goto fail;
			m_copyback(m, 0, l, p);
		}

		if (tres)
			m_cat(m, tres);
		tres = m;
	}

	m_cat(result, tres);

	if (result->m_len < sizeof(struct sadb_msg)) {
		result = m_pullup(result, sizeof(struct sadb_msg));
		if (result == NULL)
			goto fail;
	}

	result->m_pkthdr.len = 0;
	for (m = result; m; m = m->m_next)
		result->m_pkthdr.len += m->m_len;

	mtod(result, struct sadb_msg *)->sadb_msg_len =
	    PFKEY_UNIT64(result->m_pkthdr.len);

	return result;

fail:
	m_freem(result);
	m_freem(tres);
	return NULL;
}

/*
 * set data into sadb_msg.
 */
static struct mbuf *
key_setsadbmsg(type, tlen, satype, seq, pid, reserved)
	u_int8_t type, satype;
	u_int16_t tlen;
	u_int32_t seq;
	pid_t pid;
	u_int16_t reserved;
{
	struct mbuf *m;
	struct sadb_msg *p;
	int len;

	len = PFKEY_ALIGN8(sizeof(struct sadb_msg));
	if (len > MCLBYTES)
		return NULL;
	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (m && len > MHLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_freem(m);
			m = NULL;
		}
	}
	if (!m)
		return NULL;
	m->m_pkthdr.len = m->m_len = len;
	m->m_next = NULL;

	p = mtod(m, struct sadb_msg *);

	bzero(p, len);
	p->sadb_msg_version = PF_KEY_V2;
	p->sadb_msg_type = type;
	p->sadb_msg_errno = 0;
	p->sadb_msg_satype = satype;
	p->sadb_msg_len = PFKEY_UNIT64(tlen);
	p->sadb_msg_reserved = reserved;
	p->sadb_msg_seq = seq;
	p->sadb_msg_pid = (u_int32_t)pid;

	return m;
}

/*
 * copy secasvar data into sadb_address.
 */
static struct mbuf *
key_setsadbsa(sav)
	struct secasvar *sav;
{
	struct mbuf *m;
	struct sadb_sa *p;
	int len;

	len = PFKEY_ALIGN8(sizeof(struct sadb_sa));
	m = key_alloc_mbuf(len);
	if (!m || m->m_next) {	/*XXX*/
		if (m)
			m_freem(m);
		return NULL;
	}

	p = mtod(m, struct sadb_sa *);

	bzero(p, len);
	p->sadb_sa_len = PFKEY_UNIT64(len);
	p->sadb_sa_exttype = SADB_EXT_SA;
	p->sadb_sa_spi = sav->spi;
	p->sadb_sa_replay = (sav->replay != NULL ? sav->replay->wsize : 0);
	p->sadb_sa_state = sav->state;
	p->sadb_sa_auth = sav->alg_auth;
	p->sadb_sa_encrypt = sav->alg_enc;
	p->sadb_sa_flags = sav->flags;

	return m;
}

/*
 * set data into sadb_address.
 */
static struct mbuf *
key_setsadbaddr(exttype, saddr, prefixlen, ul_proto)
	u_int16_t exttype;
	struct sockaddr *saddr;
	u_int8_t prefixlen;
	u_int16_t ul_proto;
{
	struct mbuf *m;
	struct sadb_address *p;
	size_t len;

	len = PFKEY_ALIGN8(sizeof(struct sadb_address)) +
	    PFKEY_ALIGN8(saddr->sa_len);
	m = key_alloc_mbuf(len);
	if (!m || m->m_next) {	/*XXX*/
		if (m)
			m_freem(m);
		return NULL;
	}

	p = mtod(m, struct sadb_address *);

	bzero(p, len);
	p->sadb_address_len = PFKEY_UNIT64(len);
	p->sadb_address_exttype = exttype;
	p->sadb_address_proto = ul_proto;
	if (prefixlen == FULLMASK) {
		switch (saddr->sa_family) {
		case AF_INET:
			prefixlen = sizeof(struct in_addr) << 3;
			break;
		case AF_INET6:
			prefixlen = sizeof(struct in6_addr) << 3;
			break;
		default:
			; /*XXX*/
		}
	}
	p->sadb_address_prefixlen = prefixlen;
	p->sadb_address_reserved = 0;

	bcopy(saddr,
	    mtod(m, caddr_t) + PFKEY_ALIGN8(sizeof(struct sadb_address)),
	    saddr->sa_len);

	return m;
}

/*
 * set data into sadb_session_id
 */
static struct mbuf *
key_setsadbsession_id (u_int64_t session_ids[])
{
	struct mbuf *m;
	struct sadb_session_id *p;
	size_t len;

	len = PFKEY_ALIGN8(sizeof(*p));
	m = key_alloc_mbuf(len);
	if (!m || m->m_next) {	/*XXX*/
		if (m)
			m_freem(m);
		return NULL;
	}

	p = mtod(m, __typeof__(p));

	bzero(p, len);
	p->sadb_session_id_len = PFKEY_UNIT64(len);
	p->sadb_session_id_exttype = SADB_EXT_SESSION_ID;
	p->sadb_session_id_v[0] = session_ids[0];
	p->sadb_session_id_v[1] = session_ids[1];

	return m;
}

/*
 * copy stats data into sadb_sastat type.
 */
static struct mbuf *
key_setsadbsastat (u_int32_t      dir,
		   struct sastat *stats,
		   u_int32_t      max_stats)
{
	struct mbuf        *m;
	struct sadb_sastat *p;
	int                 list_len, len;

	if (!stats) {
	        return NULL;
	}

	list_len = sizeof(*stats) * max_stats;
	len = PFKEY_ALIGN8(sizeof(*p)) + PFKEY_ALIGN8(list_len);
	m = key_alloc_mbuf(len);
	if (!m || m->m_next) {	/*XXX*/
		if (m)
			m_freem(m);
		return NULL;
	}

	p = mtod(m, __typeof__(p));

	bzero(p, len);
	p->sadb_sastat_len      = PFKEY_UNIT64(len);
	p->sadb_sastat_exttype  = SADB_EXT_SASTAT;
	p->sadb_sastat_dir      = dir;
	p->sadb_sastat_list_len = max_stats;
	if (list_len) {
	        bcopy(stats,
		      mtod(m, caddr_t) + PFKEY_ALIGN8(sizeof(*p)),
		      list_len);
	}

	return m;
}

#if 0
/*
 * set data into sadb_ident.
 */
static struct mbuf *
key_setsadbident(exttype, idtype, string, stringlen, id)
	u_int16_t exttype, idtype;
	caddr_t string;
	int stringlen;
	u_int64_t id;
{
	struct mbuf *m;
	struct sadb_ident *p;
	size_t len;

	len = PFKEY_ALIGN8(sizeof(struct sadb_ident)) + PFKEY_ALIGN8(stringlen);
	m = key_alloc_mbuf(len);
	if (!m || m->m_next) {	/*XXX*/
		if (m)
			m_freem(m);
		return NULL;
	}

	p = mtod(m, struct sadb_ident *);

	bzero(p, len);
	p->sadb_ident_len = PFKEY_UNIT64(len);
	p->sadb_ident_exttype = exttype;
	p->sadb_ident_type = idtype;
	p->sadb_ident_reserved = 0;
	p->sadb_ident_id = id;

	bcopy(string,
	    mtod(m, caddr_t) + PFKEY_ALIGN8(sizeof(struct sadb_ident)),
	    stringlen);

	return m;
}
#endif

/*
 * set data into sadb_x_sa2.
 */
static struct mbuf *
key_setsadbxsa2(mode, seq, reqid)
	u_int8_t mode;
	u_int32_t seq, reqid;
{
	struct mbuf *m;
	struct sadb_x_sa2 *p;
	size_t len;

	len = PFKEY_ALIGN8(sizeof(struct sadb_x_sa2));
	m = key_alloc_mbuf(len);
	if (!m || m->m_next) {	/*XXX*/
		if (m)
			m_freem(m);
		return NULL;
	}

	p = mtod(m, struct sadb_x_sa2 *);

	bzero(p, len);
	p->sadb_x_sa2_len = PFKEY_UNIT64(len);
	p->sadb_x_sa2_exttype = SADB_X_EXT_SA2;
	p->sadb_x_sa2_mode = mode;
	p->sadb_x_sa2_reserved1 = 0;
	p->sadb_x_sa2_reserved2 = 0;
	p->sadb_x_sa2_sequence = seq;
	p->sadb_x_sa2_reqid = reqid;

	return m;
}

/*
 * set data into sadb_x_policy
 */
static struct mbuf *
key_setsadbxpolicy(type, dir, id)
	u_int16_t type;
	u_int8_t dir;
	u_int32_t id;
{
	struct mbuf *m;
	struct sadb_x_policy *p;
	size_t len;

	len = PFKEY_ALIGN8(sizeof(struct sadb_x_policy));
	m = key_alloc_mbuf(len);
	if (!m || m->m_next) {	/*XXX*/
		if (m)
			m_freem(m);
		return NULL;
	}

	p = mtod(m, struct sadb_x_policy *);

	bzero(p, len);
	p->sadb_x_policy_len = PFKEY_UNIT64(len);
	p->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	p->sadb_x_policy_type = type;
	p->sadb_x_policy_dir = dir;
	p->sadb_x_policy_id = id;

	return m;
}

/* %%% utilities */
/*
 * copy a buffer into the new buffer allocated.
 */
static void *
key_newbuf(src, len)
	const void *src;
	u_int len;
{
	caddr_t new;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);
	KMALLOC_NOWAIT(new, caddr_t, len);
	if (new == NULL) {
		lck_mtx_unlock(sadb_mutex);
		KMALLOC_WAIT(new, caddr_t, len);
		lck_mtx_lock(sadb_mutex);
		if (new == NULL) {
			ipseclog((LOG_DEBUG, "key_newbuf: No more memory.\n"));
			return NULL;
		}
	}
	bcopy(src, new, len);

	return new;
}

/* compare my own address
 * OUT:	1: true, i.e. my address.
 *	0: false
 */
int
key_ismyaddr(sa)
	struct sockaddr *sa;
{
#if INET
	struct sockaddr_in *sin;
	struct in_ifaddr *ia;
#endif

	/* sanity check */
	if (sa == NULL)
		panic("key_ismyaddr: NULL pointer is passed.\n");

	switch (sa->sa_family) {
#if INET
	case AF_INET:
		lck_rw_lock_shared(in_ifaddr_rwlock);
		sin = (struct sockaddr_in *)sa;
		for (ia = in_ifaddrhead.tqh_first; ia;
		     ia = ia->ia_link.tqe_next)
		{
			if (sin->sin_family == ia->ia_addr.sin_family &&
			    sin->sin_len == ia->ia_addr.sin_len &&
			    sin->sin_addr.s_addr == ia->ia_addr.sin_addr.s_addr)
			{
				lck_rw_done(in_ifaddr_rwlock);
				return 1;
			}
		}
		lck_rw_done(in_ifaddr_rwlock);
		break;
#endif
#if INET6
	case AF_INET6:
		return key_ismyaddr6((struct sockaddr_in6 *)sa);
#endif
	}

	return 0;
}

#if INET6
/*
 * compare my own address for IPv6.
 * 1: ours
 * 0: other
 * NOTE: derived ip6_input() in KAME. This is necessary to modify more.
 */
#include <netinet6/in6_var.h>

static int
key_ismyaddr6(sin6)
	struct sockaddr_in6 *sin6;
{
	struct in6_ifaddr *ia;
	struct in6_multi *in6m;

	lck_mtx_lock(nd6_mutex);
	for (ia = in6_ifaddrs; ia; ia = ia->ia_next) {
		if (key_sockaddrcmp((struct sockaddr *)&sin6,
		    (struct sockaddr *)&ia->ia_addr, 0) == 0) {
			lck_mtx_unlock(nd6_mutex);
			return 1;
		}

		/*
		 * XXX Multicast
		 * XXX why do we care about multlicast here while we don't care
		 * about IPv4 multicast??
		 * XXX scope
		 */
		in6m = NULL;
		ifnet_lock_shared(ia->ia_ifp);
		IN6_LOOKUP_MULTI(sin6->sin6_addr, ia->ia_ifp, in6m);
		ifnet_lock_done(ia->ia_ifp);
		if (in6m) {
			lck_mtx_unlock(nd6_mutex);
			return 1;
		}
	}
	lck_mtx_unlock(nd6_mutex);

	/* loopback, just for safety */
	if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr))
		return 1;

	return 0;
}
#endif /*INET6*/

/*
 * compare two secasindex structure.
 * flag can specify to compare 2 saidxes.
 * compare two secasindex structure without both mode and reqid.
 * don't compare port.
 * IN:  
 *      saidx0: source, it can be in SAD.
 *      saidx1: object.
 * OUT: 
 *      1 : equal
 *      0 : not equal
 */
static int
key_cmpsaidx(saidx0, saidx1, flag)
	struct secasindex *saidx0, *saidx1;
	int flag;
{
	/* sanity */
	if (saidx0 == NULL && saidx1 == NULL)
		return 1;

	if (saidx0 == NULL || saidx1 == NULL)
		return 0;

	if (saidx0->proto != saidx1->proto)
		return 0;

	if (flag == CMP_EXACTLY) {
		if (saidx0->mode != saidx1->mode)
			return 0;
		if (saidx0->reqid != saidx1->reqid)
			return 0;
		if (bcmp(&saidx0->src, &saidx1->src, saidx0->src.ss_len) != 0 ||
		    bcmp(&saidx0->dst, &saidx1->dst, saidx0->dst.ss_len) != 0)
			return 0;
	} else {

		/* CMP_MODE_REQID, CMP_REQID, CMP_HEAD */
		if (flag & CMP_REQID) {
			/*
			 * If reqid of SPD is non-zero, unique SA is required.
			 * The result must be of same reqid in this case.
			 */
			if (saidx1->reqid != 0 && saidx0->reqid != saidx1->reqid)
				return 0;
		}

		if (flag & CMP_MODE) {
			if (saidx0->mode != IPSEC_MODE_ANY
			 && saidx0->mode != saidx1->mode)
				return 0;
		}

		if (key_sockaddrcmp((struct sockaddr *)&saidx0->src,
				    (struct sockaddr *)&saidx1->src, flag & CMP_PORT ? 1 : 0) != 0) {
			return 0;
		}
		if (key_sockaddrcmp((struct sockaddr *)&saidx0->dst,
				    (struct sockaddr *)&saidx1->dst, flag & CMP_PORT ? 1 : 0) != 0) {
			return 0;
		}
	}

	return 1;
}

/*
 * compare two secindex structure exactly.
 * IN:
 *	spidx0: source, it is often in SPD.
 *	spidx1: object, it is often from PFKEY message.
 * OUT:
 *	1 : equal
 *	0 : not equal
 */
static int
key_cmpspidx_exactly(spidx0, spidx1)
	struct secpolicyindex *spidx0, *spidx1;
{
	/* sanity */
	if (spidx0 == NULL && spidx1 == NULL)
		return 1;

	if (spidx0 == NULL || spidx1 == NULL)
		return 0;

	if (spidx0->prefs != spidx1->prefs
	 || spidx0->prefd != spidx1->prefd
	 || spidx0->ul_proto != spidx1->ul_proto)
		return 0;

	if (key_sockaddrcmp((struct sockaddr *)&spidx0->src,
	    (struct sockaddr *)&spidx1->src, 1) != 0) {
		return 0;
	}
	if (key_sockaddrcmp((struct sockaddr *)&spidx0->dst,
	    (struct sockaddr *)&spidx1->dst, 1) != 0) {
		return 0;
	}

	return 1;
}

/*
 * compare two secindex structure with mask.
 * IN:
 *	spidx0: source, it is often in SPD.
 *	spidx1: object, it is often from IP header.
 * OUT:
 *	1 : equal
 *	0 : not equal
 */
static int
key_cmpspidx_withmask(spidx0, spidx1)
	struct secpolicyindex *spidx0, *spidx1;
{
	/* sanity */
	if (spidx0 == NULL && spidx1 == NULL)
		return 1;

	if (spidx0 == NULL || spidx1 == NULL)
		return 0;

	if (spidx0->src.ss_family != spidx1->src.ss_family ||
	    spidx0->dst.ss_family != spidx1->dst.ss_family ||
	    spidx0->src.ss_len != spidx1->src.ss_len ||
	    spidx0->dst.ss_len != spidx1->dst.ss_len)
		return 0;

	/* if spidx.ul_proto == IPSEC_ULPROTO_ANY, ignore. */
	if (spidx0->ul_proto != (u_int16_t)IPSEC_ULPROTO_ANY
	 && spidx0->ul_proto != spidx1->ul_proto)
		return 0;

	switch (spidx0->src.ss_family) {
	case AF_INET:
		if (satosin(&spidx0->src)->sin_port != IPSEC_PORT_ANY
		 && satosin(&spidx0->src)->sin_port !=
		    satosin(&spidx1->src)->sin_port)
			return 0;
		if (!key_bbcmp((caddr_t)&satosin(&spidx0->src)->sin_addr,
		    (caddr_t)&satosin(&spidx1->src)->sin_addr, spidx0->prefs))
			return 0;
		break;
	case AF_INET6:
		if (satosin6(&spidx0->src)->sin6_port != IPSEC_PORT_ANY
		 && satosin6(&spidx0->src)->sin6_port !=
		    satosin6(&spidx1->src)->sin6_port)
			return 0;
		/*
		 * scope_id check. if sin6_scope_id is 0, we regard it
		 * as a wildcard scope, which matches any scope zone ID. 
		 */
		if (satosin6(&spidx0->src)->sin6_scope_id &&
		    satosin6(&spidx1->src)->sin6_scope_id &&
		    satosin6(&spidx0->src)->sin6_scope_id !=
		    satosin6(&spidx1->src)->sin6_scope_id)
			return 0;
		if (!key_bbcmp((caddr_t)&satosin6(&spidx0->src)->sin6_addr,
		    (caddr_t)&satosin6(&spidx1->src)->sin6_addr, spidx0->prefs))
			return 0;
		break;
	default:
		/* XXX */
		if (bcmp(&spidx0->src, &spidx1->src, spidx0->src.ss_len) != 0)
			return 0;
		break;
	}

	switch (spidx0->dst.ss_family) {
	case AF_INET:
		if (satosin(&spidx0->dst)->sin_port != IPSEC_PORT_ANY
		 && satosin(&spidx0->dst)->sin_port !=
		    satosin(&spidx1->dst)->sin_port)
			return 0;
		if (!key_bbcmp((caddr_t)&satosin(&spidx0->dst)->sin_addr,
		    (caddr_t)&satosin(&spidx1->dst)->sin_addr, spidx0->prefd))
			return 0;
		break;
	case AF_INET6:
		if (satosin6(&spidx0->dst)->sin6_port != IPSEC_PORT_ANY
		 && satosin6(&spidx0->dst)->sin6_port !=
		    satosin6(&spidx1->dst)->sin6_port)
			return 0;
		/*
		 * scope_id check. if sin6_scope_id is 0, we regard it
		 * as a wildcard scope, which matches any scope zone ID. 
		 */
		if (satosin6(&spidx0->src)->sin6_scope_id &&
		    satosin6(&spidx1->src)->sin6_scope_id &&
		    satosin6(&spidx0->dst)->sin6_scope_id !=
		    satosin6(&spidx1->dst)->sin6_scope_id)
			return 0;
		if (!key_bbcmp((caddr_t)&satosin6(&spidx0->dst)->sin6_addr,
		    (caddr_t)&satosin6(&spidx1->dst)->sin6_addr, spidx0->prefd))
			return 0;
		break;
	default:
		/* XXX */
		if (bcmp(&spidx0->dst, &spidx1->dst, spidx0->dst.ss_len) != 0)
			return 0;
		break;
	}

	/* XXX Do we check other field ?  e.g. flowinfo */

	return 1;
}

/* returns 0 on match */
static int
key_sockaddrcmp(sa1, sa2, port)
	struct sockaddr *sa1;
	struct sockaddr *sa2;
	int port;
{
	if (sa1->sa_family != sa2->sa_family || sa1->sa_len != sa2->sa_len)
		return 1;

	switch (sa1->sa_family) {
	case AF_INET:
		if (sa1->sa_len != sizeof(struct sockaddr_in))
			return 1;
		if (satosin(sa1)->sin_addr.s_addr !=
		    satosin(sa2)->sin_addr.s_addr) {
			return 1;
		}
		if (port && satosin(sa1)->sin_port != satosin(sa2)->sin_port)
			return 1;
		break;
	case AF_INET6:
		if (sa1->sa_len != sizeof(struct sockaddr_in6))
			return 1;	/*EINVAL*/
		if (satosin6(sa1)->sin6_scope_id !=
		    satosin6(sa2)->sin6_scope_id) {
			return 1;
		}
		if (!IN6_ARE_ADDR_EQUAL(&satosin6(sa1)->sin6_addr,
		    &satosin6(sa2)->sin6_addr)) {
			return 1;
		}
		if (port &&
		    satosin6(sa1)->sin6_port != satosin6(sa2)->sin6_port) {
			return 1;
		}
		break;
	default:
		if (bcmp(sa1, sa2, sa1->sa_len) != 0)
			return 1;
		break;
	}

	return 0;
}

/*
 * compare two buffers with mask.
 * IN:
 *	addr1: source
 *	addr2: object
 *	bits:  Number of bits to compare
 * OUT:
 *	1 : equal
 *	0 : not equal
 */
static int
key_bbcmp(p1, p2, bits)
	caddr_t p1, p2;
	u_int bits;
{
	u_int8_t mask;

	/* XXX: This could be considerably faster if we compare a word
	 * at a time, but it is complicated on LSB Endian machines */

	/* Handle null pointers */
	if (p1 == NULL || p2 == NULL)
		return (p1 == p2);

	while (bits >= 8) {
		if (*p1++ != *p2++)
			return 0;
		bits -= 8;
	}

	if (bits > 0) {
		mask = ~((1<<(8-bits))-1);
		if ((*p1 & mask) != (*p2 & mask))
			return 0;
	}
	return 1;	/* Match! */
}

/*
 * time handler.
 * scanning SPD and SAD to check status for each entries,
 * and do to remove or to expire.
 * XXX: year 2038 problem may remain.
 */
int key_timehandler_debug = 0;
u_int32_t spd_count = 0, sah_count = 0, dead_sah_count = 0, empty_sah_count = 0, larval_sav_count = 0, mature_sav_count = 0, dying_sav_count = 0, dead_sav_count = 0;
u_int64_t total_sav_count = 0;
void
key_timehandler(void)
{
	u_int dir;
	struct timeval tv;
	struct secpolicy **spbuf = NULL, **spptr = NULL;
	struct secasvar **savexbuf = NULL, **savexptr = NULL;
	struct secasvar **savkabuf = NULL, **savkaptr = NULL;
	int spbufcount = 0, savbufcount = 0, spcount = 0, savexcount = 0, savkacount = 0, cnt;
	
	microtime(&tv);

	/* pre-allocate buffers before taking the lock */
	/* if allocation failures occur - portions of the processing will be skipped */
	if ((spbufcount = ipsec_policy_count) != 0) {
		spbufcount += 256;
		KMALLOC_WAIT(spbuf, struct secpolicy **, spbufcount * sizeof(struct secpolicy *));
		if (spbuf)
			spptr = spbuf;
	}
	if ((savbufcount = ipsec_sav_count) != 0) {
		savbufcount += 512;
		KMALLOC_WAIT(savexbuf, struct secasvar **, savbufcount * sizeof(struct secasvar *));
		if (savexbuf)
			savexptr = savexbuf;
		KMALLOC_WAIT(savkabuf, struct secasvar **, savbufcount * sizeof(struct secasvar *));
		if (savkabuf)
			savkaptr = savkabuf;
	}
	lck_mtx_lock(sadb_mutex);
	/* SPD */
	if (spbuf) {

		struct secpolicy *sp, *nextsp;

		for (dir = 0; dir < IPSEC_DIR_MAX; dir++) {
			for (sp = LIST_FIRST(&sptree[dir]);
			     sp != NULL;
			     sp = nextsp) {

			        spd_count++;
				nextsp = LIST_NEXT(sp, chain);

				if (sp->state == IPSEC_SPSTATE_DEAD) {
					key_freesp(sp, KEY_SADB_LOCKED);
					continue;
				}

				if (sp->lifetime == 0 && sp->validtime == 0)
					continue;
				if (spbuf && spcount < spbufcount) {
					/* the deletion will occur next time */
					if ((sp->lifetime
					     && tv.tv_sec - sp->created > sp->lifetime)
					    || (sp->validtime
						&& tv.tv_sec - sp->lastused > sp->validtime)) {
						//key_spdexpire(sp);
						sp->state = IPSEC_SPSTATE_DEAD;
						sp->refcnt++;
						*spptr++ = sp;
						spcount++;
					}
				}
			}
		}
	}

	/* SAD */
	if (savbufcount != 0) {
		struct secashead *sah, *nextsah;
		struct secasvar *sav, *nextsav;
	
		for (sah = LIST_FIRST(&sahtree);
			 sah != NULL;
			 sah = nextsah) {
	
		        sah_count++;
			nextsah = LIST_NEXT(sah, chain);
	
			/* if sah has been dead, then delete it and process next sah. */
			if (sah->state == SADB_SASTATE_DEAD) {
				key_delsah(sah);
				dead_sah_count++;
				continue;
			}

			if (LIST_FIRST(&sah->savtree[SADB_SASTATE_LARVAL]) == NULL &&
			    LIST_FIRST(&sah->savtree[SADB_SASTATE_MATURE]) == NULL && 
			    LIST_FIRST(&sah->savtree[SADB_SASTATE_DYING]) == NULL && 
			    LIST_FIRST(&sah->savtree[SADB_SASTATE_DEAD]) == NULL) {
			        key_delsah(sah);
				empty_sah_count++;
				continue;
			}

			/* if LARVAL entry doesn't become MATURE, delete it. */
			for (sav = LIST_FIRST(&sah->savtree[SADB_SASTATE_LARVAL]);
				 sav != NULL;
				 sav = nextsav) {
	
			        larval_sav_count++;
				total_sav_count++;
				nextsav = LIST_NEXT(sav, chain);
	
				if (tv.tv_sec - sav->created > key_larval_lifetime) {
					key_freesav(sav, KEY_SADB_LOCKED);
				}
			}
			
			/*
			 * If this is a NAT traversal SA with no activity,
			 * we need to send a keep alive.
			 *
			 * Performed outside of the loop before so we will
			 * only ever send one keepalive. The first SA on
			 * the list is the one that will be used for sending
			 * traffic, so this is the one we use for determining
			 * when to send the keepalive.
			 */
			if (savkabuf && savkacount < savbufcount) {
				sav = LIST_FIRST(&sah->savtree[SADB_SASTATE_MATURE]);	//%%% should we check dying list if this is empty???
				if (natt_keepalive_interval && sav && (sav->flags & SADB_X_EXT_NATT_KEEPALIVE) != 0) {
					sav->refcnt++;
					*savkaptr++ = sav;
					savkacount++;
				}
			}
			
			/*
			 * check MATURE entry to start to send expire message
			 * whether or not.
			 */
			for (sav = LIST_FIRST(&sah->savtree[SADB_SASTATE_MATURE]);
				 sav != NULL;
				 sav = nextsav) {
	
			        mature_sav_count++;
				total_sav_count++;
				nextsav = LIST_NEXT(sav, chain);
	
				/* we don't need to check. */
				if (sav->lft_s == NULL)
					continue;
	
				/* sanity check */
				if (sav->lft_c == NULL) {
					ipseclog((LOG_DEBUG,"key_timehandler: "
						"There is no CURRENT time, why?\n"));
					continue;
				}
	
				/* check SOFT lifetime */
				if (sav->lft_s->sadb_lifetime_addtime != 0
				 && tv.tv_sec - sav->created > sav->lft_s->sadb_lifetime_addtime) {
					/*
					 * check the SA if it has been used.
					 * when it hasn't been used, delete it.
					 * i don't think such SA will be used.
					 */
					if (sav->lft_c->sadb_lifetime_usetime == 0) {
						key_sa_chgstate(sav, SADB_SASTATE_DEAD);
						key_freesav(sav, KEY_SADB_LOCKED);
						sav = NULL;
					} else if (savexbuf && savexcount < savbufcount) {
						key_sa_chgstate(sav, SADB_SASTATE_DYING);	
						sav->refcnt++;
						*savexptr++ = sav;
						savexcount++;
					}
				}
	
				/* check SOFT lifetime by bytes */
				/*
				 * XXX I don't know the way to delete this SA
				 * when new SA is installed.  Caution when it's
				 * installed too big lifetime by time.
				 */
				else if (savexbuf && savexcount < savbufcount
					  && sav->lft_s->sadb_lifetime_bytes != 0
					  && sav->lft_s->sadb_lifetime_bytes < sav->lft_c->sadb_lifetime_bytes) {
	
					/*
					 * XXX If we keep to send expire
					 * message in the status of
					 * DYING. Do remove below code.
					 */
					//key_expire(sav);
					key_sa_chgstate(sav, SADB_SASTATE_DYING);
					sav->refcnt++;
					*savexptr++ = sav;
					savexcount++;
				}
			}

			/* check DYING entry to change status to DEAD. */
			for (sav = LIST_FIRST(&sah->savtree[SADB_SASTATE_DYING]);
				 sav != NULL;
				 sav = nextsav) {
	
			        dying_sav_count++;
				total_sav_count++;
				nextsav = LIST_NEXT(sav, chain);
	
				/* we don't need to check. */
				if (sav->lft_h == NULL)
					continue;
	
				/* sanity check */
				if (sav->lft_c == NULL) {
					ipseclog((LOG_DEBUG, "key_timehandler: "
						"There is no CURRENT time, why?\n"));
					continue;
				}
	
				if (sav->lft_h->sadb_lifetime_addtime != 0
				 && tv.tv_sec - sav->created > sav->lft_h->sadb_lifetime_addtime) {
					key_sa_chgstate(sav, SADB_SASTATE_DEAD);
					key_freesav(sav, KEY_SADB_LOCKED);
					sav = NULL;
				}
#if 0	/* XXX Should we keep to send expire message until HARD lifetime ? */
				else if (savbuf && savexcount < savbufcount
					  && sav->lft_s != NULL
					  && sav->lft_s->sadb_lifetime_addtime != 0
					  && tv.tv_sec - sav->created > sav->lft_s->sadb_lifetime_addtime) {
					/*
					 * XXX: should be checked to be
					 * installed the valid SA.
					 */
	
					/*
					 * If there is no SA then sending
					 * expire message.
					 */
					//key_expire(sav);
					sav->refcnt++;
					*savexptr++ = sav;
					savexcount++;
				}
#endif
				/* check HARD lifetime by bytes */
				else if (sav->lft_h->sadb_lifetime_bytes != 0
					  && sav->lft_h->sadb_lifetime_bytes < sav->lft_c->sadb_lifetime_bytes) {
					key_sa_chgstate(sav, SADB_SASTATE_DEAD);
					key_freesav(sav, KEY_SADB_LOCKED);
					sav = NULL;
				}
			}
	
			/* delete entry in DEAD */
			for (sav = LIST_FIRST(&sah->savtree[SADB_SASTATE_DEAD]);
				 sav != NULL;
				 sav = nextsav) {
	
			        dead_sav_count++;
				total_sav_count++;
				nextsav = LIST_NEXT(sav, chain);
	
				/* sanity check */
				if (sav->state != SADB_SASTATE_DEAD) {
					ipseclog((LOG_DEBUG, "key_timehandler: "
						"invalid sav->state "
						"(queue: %d SA: %d): "
						"kill it anyway\n",
						SADB_SASTATE_DEAD, sav->state));
				}
	
				/*
				 * do not call key_freesav() here.
				 * sav should already be freed, and sav->refcnt
				 * shows other references to sav
				 * (such as from SPD).
				 */
			}
		}
   }

         if (++key_timehandler_debug >= 300) {
	          if (key_debug_level) {
		           printf("%s: total stats for %u calls\n", __FUNCTION__, key_timehandler_debug);
		           printf("%s: walked %u SPDs\n", __FUNCTION__, spd_count);
			   printf("%s: walked %llu SAs: LARVAL SAs %u, MATURE SAs %u, DYING SAs %u, DEAD SAs %u\n", __FUNCTION__,
				  total_sav_count, larval_sav_count, mature_sav_count, dying_sav_count, dead_sav_count);
			   printf("%s: walked %u SAHs: DEAD SAHs %u, EMPTY SAHs %u\n", __FUNCTION__,
				  sah_count, dead_sah_count, empty_sah_count);
			   if (sah_search_calls) {
			           printf("%s: SAH search cost %d iters per call\n", __FUNCTION__,
					  (sah_search_count/sah_search_calls));
			   }
		  }
		  spd_count = 0;
		  sah_count = 0;
		  dead_sah_count = 0;
		  empty_sah_count = 0;
		  larval_sav_count = 0;
		  mature_sav_count = 0;
		  dying_sav_count = 0;
		  dead_sav_count = 0;
		  total_sav_count = 0;
		  sah_search_count = 0;
		  sah_search_calls = 0;
		  key_timehandler_debug = 0;
	 }
#ifndef IPSEC_NONBLOCK_ACQUIRE
	/* ACQ tree */
    {
	struct secacq *acq, *nextacq;

	for (acq = LIST_FIRST(&acqtree);
	     acq != NULL;
	     acq = nextacq) {

		nextacq = LIST_NEXT(acq, chain);

		if (tv.tv_sec - acq->created > key_blockacq_lifetime
		 && __LIST_CHAINED(acq)) {
			LIST_REMOVE(acq, chain);
			KFREE(acq);
		}
	}
    }
#endif

	/* SP ACQ tree */
    {
	struct secspacq *acq, *nextacq;

	for (acq = LIST_FIRST(&spacqtree);
	     acq != NULL;
	     acq = nextacq) {

		nextacq = LIST_NEXT(acq, chain);

		if (tv.tv_sec - acq->created > key_blockacq_lifetime
		 && __LIST_CHAINED(acq)) {
			LIST_REMOVE(acq, chain);
			KFREE(acq);
		}
	}
    }

	/* initialize random seed */
	if (key_tick_init_random++ > key_int_random) {
		key_tick_init_random = 0;
		key_srandom();
	}
	
	natt_now++;

	lck_mtx_unlock(sadb_mutex);

	/* send messages outside of sadb_mutex */
	if (spbuf && spcount > 0) {
		cnt = spcount;
		while (cnt--)
			key_spdexpire(*(--spptr));
	}
	if (savkabuf && savkacount > 0) {
		struct secasvar **savkaptr_sav = savkaptr;
		int               cnt_send = savkacount;

		while (cnt_send--) {
			if (ipsec_send_natt_keepalive(*(--savkaptr))) {
				// <rdar://6768487> iterate (all over again) and update timestamps
				struct secasvar **savkaptr_update = savkaptr_sav;
				int               cnt_update = savkacount;
				while (cnt_update--) {
					key_update_natt_keepalive_timestamp(*savkaptr,
									    *(--savkaptr_update));
				}
			}
		}
	}
	if (savexbuf && savexcount > 0) {
		cnt = savexcount;
		while (cnt--)
			key_expire(*(--savexptr));
	}
	
	/* decrement ref counts and free buffers */
	lck_mtx_lock(sadb_mutex);
	if (spbuf) {
		while (spcount--)
			key_freesp(*spptr++, KEY_SADB_LOCKED);
		KFREE(spbuf);
	}
	if (savkabuf) {
		while (savkacount--)
			key_freesav(*savkaptr++, KEY_SADB_LOCKED);
		KFREE(savkabuf);
	}
	if (savexbuf) {
		while (savexcount--)
			key_freesav(*savexptr++, KEY_SADB_LOCKED);
		KFREE(savexbuf);
	}
	lck_mtx_unlock(sadb_mutex);

	
#ifndef IPSEC_DEBUG2
	/* do exchange to tick time !! */
	(void)timeout((void *)key_timehandler, (void *)0, hz);
#endif /* IPSEC_DEBUG2 */

	return;
}

/*
 * to initialize a seed for random()
 */
static void
key_srandom()
{
#ifdef __APPLE__
	/* Our PRNG is based on Yarrow and doesn't need to be seeded */
	random();
#else
	struct timeval tv;

	microtime(&tv);

	srandom(tv.tv_usec);
#endif

	return;
}

u_int32_t
key_random()
{
	u_int32_t value;

	key_randomfill(&value, sizeof(value));
	return value;
}

void
key_randomfill(p, l)
	void *p;
	size_t l;
{
#ifdef __APPLE__

	read_random(p, (u_int)l);
#else
	size_t n;
	u_int32_t v;
	static int warn = 1;

	n = 0;
	n = (size_t)read_random(p, (u_int)l);
	/* last resort */
	while (n < l) {
		v = random();
		bcopy(&v, (u_int8_t *)p + n,
		    l - n < sizeof(v) ? l - n : sizeof(v));
		n += sizeof(v);

		if (warn) {
			printf("WARNING: pseudo-random number generator "
			    "used for IPsec processing\n");
			warn = 0;
		}
	}
#endif
}

/*
 * map SADB_SATYPE_* to IPPROTO_*.
 * if satype == SADB_SATYPE then satype is mapped to ~0.
 * OUT:
 *	0: invalid satype.
 */
static u_int16_t
key_satype2proto(satype)
	u_int8_t satype;
{
	switch (satype) {
	case SADB_SATYPE_UNSPEC:
		return IPSEC_PROTO_ANY;
	case SADB_SATYPE_AH:
		return IPPROTO_AH;
	case SADB_SATYPE_ESP:
		return IPPROTO_ESP;
	case SADB_X_SATYPE_IPCOMP:
		return IPPROTO_IPCOMP;
		break;
	default:
		return 0;
	}
	/* NOTREACHED */
}

/*
 * map IPPROTO_* to SADB_SATYPE_*
 * OUT:
 *	0: invalid protocol type.
 */
static u_int8_t
key_proto2satype(proto)
	u_int16_t proto;
{
	switch (proto) {
	case IPPROTO_AH:
		return SADB_SATYPE_AH;
	case IPPROTO_ESP:
		return SADB_SATYPE_ESP;
	case IPPROTO_IPCOMP:
		return SADB_X_SATYPE_IPCOMP;
		break;
	default:
		return 0;
	}
	/* NOTREACHED */
}

/* %%% PF_KEY */
/*
 * SADB_GETSPI processing is to receive
 *	<base, (SA2), src address, dst address, (SPI range)>
 * from the IKMPd, to assign a unique spi value, to hang on the INBOUND
 * tree with the status of LARVAL, and send
 *	<base, SA(*), address(SD)>
 * to the IKMPd.
 *
 * IN:	mhp: pointer to the pointer to each header.
 * OUT:	NULL if fail.
 *	other if success, return pointer to the message to send.
 */
static int
key_getspi(so, m, mhp)
	struct socket *so;
	struct mbuf *m;
	const struct sadb_msghdr *mhp;
{
	struct sadb_address *src0, *dst0;
	struct secasindex saidx;
	struct secashead *newsah;
	struct secasvar *newsav;
	u_int8_t proto;
	u_int32_t spi;
	u_int8_t mode;
	u_int32_t reqid;
	int error;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_getspi: NULL pointer is passed.\n");

	if (mhp->ext[SADB_EXT_ADDRESS_SRC] == NULL ||
	    mhp->ext[SADB_EXT_ADDRESS_DST] == NULL) {
		ipseclog((LOG_DEBUG, "key_getspi: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}
	if (mhp->extlen[SADB_EXT_ADDRESS_SRC] < sizeof(struct sadb_address) ||
	    mhp->extlen[SADB_EXT_ADDRESS_DST] < sizeof(struct sadb_address)) {
		ipseclog((LOG_DEBUG, "key_getspi: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}
	if (mhp->ext[SADB_X_EXT_SA2] != NULL) {
		mode = ((struct sadb_x_sa2 *)mhp->ext[SADB_X_EXT_SA2])->sadb_x_sa2_mode;
		reqid = ((struct sadb_x_sa2 *)mhp->ext[SADB_X_EXT_SA2])->sadb_x_sa2_reqid;
	} else {
		mode = IPSEC_MODE_ANY;
		reqid = 0;
	}

	src0 = (struct sadb_address *)(mhp->ext[SADB_EXT_ADDRESS_SRC]);
	dst0 = (struct sadb_address *)(mhp->ext[SADB_EXT_ADDRESS_DST]);

	/* map satype to proto */
	if ((proto = key_satype2proto(mhp->msg->sadb_msg_satype)) == 0) {
		ipseclog((LOG_DEBUG, "key_getspi: invalid satype is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	/* make sure if port number is zero. */
	switch (((struct sockaddr *)(src0 + 1))->sa_family) {
	case AF_INET:
		if (((struct sockaddr *)(src0 + 1))->sa_len !=
		    sizeof(struct sockaddr_in))
			return key_senderror(so, m, EINVAL);
		((struct sockaddr_in *)(src0 + 1))->sin_port = 0;
		break;
	case AF_INET6:
		if (((struct sockaddr *)(src0 + 1))->sa_len !=
		    sizeof(struct sockaddr_in6))
			return key_senderror(so, m, EINVAL);
		((struct sockaddr_in6 *)(src0 + 1))->sin6_port = 0;
		break;
	default:
		; /*???*/
	}
	switch (((struct sockaddr *)(dst0 + 1))->sa_family) {
	case AF_INET:
		if (((struct sockaddr *)(dst0 + 1))->sa_len !=
		    sizeof(struct sockaddr_in))
			return key_senderror(so, m, EINVAL);
		((struct sockaddr_in *)(dst0 + 1))->sin_port = 0;
		break;
	case AF_INET6:
		if (((struct sockaddr *)(dst0 + 1))->sa_len !=
		    sizeof(struct sockaddr_in6))
			return key_senderror(so, m, EINVAL);
		((struct sockaddr_in6 *)(dst0 + 1))->sin6_port = 0;
		break;
	default:
		; /*???*/
	}

	/* XXX boundary check against sa_len */
	KEY_SETSECASIDX(proto, mode, reqid, src0 + 1, dst0 + 1, &saidx);

	lck_mtx_lock(sadb_mutex);
	
	/* SPI allocation */
	spi = key_do_getnewspi((struct sadb_spirange *)mhp->ext[SADB_EXT_SPIRANGE],
	                       &saidx);
	if (spi == 0) {
		lck_mtx_unlock(sadb_mutex);
		return key_senderror(so, m, EINVAL);
	}

	/* get a SA index */
	if ((newsah = key_getsah(&saidx)) == NULL) {
		/* create a new SA index: key_addspi is always used for inbound spi */
		if ((newsah = key_newsah(&saidx, IPSEC_DIR_INBOUND)) == NULL) {
			lck_mtx_unlock(sadb_mutex);
			ipseclog((LOG_DEBUG, "key_getspi: No more memory.\n"));
			return key_senderror(so, m, ENOBUFS);
		}
	}

	/* get a new SA */
	/* XXX rewrite */
	newsav = key_newsav(m, mhp, newsah, &error);
	if (newsav == NULL) {
		/* XXX don't free new SA index allocated in above. */
		lck_mtx_unlock(sadb_mutex);
		return key_senderror(so, m, error);
	}

	/* set spi */
	key_setspi(newsav, htonl(spi));

#ifndef IPSEC_NONBLOCK_ACQUIRE
	/* delete the entry in acqtree */
	if (mhp->msg->sadb_msg_seq != 0) {
		struct secacq *acq;
		if ((acq = key_getacqbyseq(mhp->msg->sadb_msg_seq)) != NULL) {
			/* reset counter in order to deletion by timehandler. */
			struct timeval tv;
			microtime(&tv);
			acq->created = tv.tv_sec;
			acq->count = 0;
		}
    	}
#endif

	lck_mtx_unlock(sadb_mutex);
	
    {
	struct mbuf *n, *nn;
	struct sadb_sa *m_sa;
	struct sadb_msg *newmsg;
	int off, len;

	/* create new sadb_msg to reply. */
	len = PFKEY_ALIGN8(sizeof(struct sadb_msg)) +
	    PFKEY_ALIGN8(sizeof(struct sadb_sa));
	if (len > MCLBYTES)
		return key_senderror(so, m, ENOBUFS);

	MGETHDR(n, M_DONTWAIT, MT_DATA);
	if (len > MHLEN) {
		MCLGET(n, M_DONTWAIT);
		if ((n->m_flags & M_EXT) == 0) {
			m_freem(n);
			n = NULL;
		}
	}
	if (!n)
		return key_senderror(so, m, ENOBUFS);

	n->m_len = len;
	n->m_next = NULL;
	off = 0;

	m_copydata(m, 0, sizeof(struct sadb_msg), mtod(n, caddr_t) + off);
	off += PFKEY_ALIGN8(sizeof(struct sadb_msg));

	m_sa = (struct sadb_sa *)(mtod(n, caddr_t) + off);
	m_sa->sadb_sa_len = PFKEY_UNIT64(sizeof(struct sadb_sa));
	m_sa->sadb_sa_exttype = SADB_EXT_SA;
	m_sa->sadb_sa_spi = htonl(spi);
	off += PFKEY_ALIGN8(sizeof(struct sadb_sa));

#if DIAGNOSTIC
	if (off != len)
		panic("length inconsistency in key_getspi");
#endif
	{
	int mbufItems[] = {SADB_EXT_ADDRESS_SRC, SADB_EXT_ADDRESS_DST};
	n->m_next = key_gather_mbuf(m, mhp, 0, sizeof(mbufItems)/sizeof(int), mbufItems);
	if (!n->m_next) {
		m_freem(n);
		return key_senderror(so, m, ENOBUFS);
	}
	}

	if (n->m_len < sizeof(struct sadb_msg)) {
		n = m_pullup(n, sizeof(struct sadb_msg));
		if (n == NULL)
			return key_sendup_mbuf(so, m, KEY_SENDUP_ONE);
	}

	n->m_pkthdr.len = 0;
	for (nn = n; nn; nn = nn->m_next)
		n->m_pkthdr.len += nn->m_len;

	newmsg = mtod(n, struct sadb_msg *);
	newmsg->sadb_msg_seq = newsav->seq;
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(n->m_pkthdr.len);

	m_freem(m);
	return key_sendup_mbuf(so, n, KEY_SENDUP_ONE);
    }
}

/*
 * allocating new SPI
 * called by key_getspi().
 * OUT:
 *	0:	failure.
 *	others: success.
 */
static u_int32_t
key_do_getnewspi(spirange, saidx)
	struct sadb_spirange *spirange;
	struct secasindex *saidx;
{
	u_int32_t newspi;
	u_int32_t keymin, keymax;
	int count = key_spi_trycnt;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);

	/* set spi range to allocate */
	if (spirange != NULL) {
		keymin = spirange->sadb_spirange_min;
		keymax = spirange->sadb_spirange_max;
	} else {
		keymin = key_spi_minval;
		keymax = key_spi_maxval;
	}
	/* IPCOMP needs 2-byte SPI */
	if (saidx->proto == IPPROTO_IPCOMP) {
		u_int32_t t;
		if (keymin >= 0x10000)
			keymin = 0xffff;
		if (keymax >= 0x10000)
			keymax = 0xffff;
		if (keymin > keymax) {
			t = keymin; keymin = keymax; keymax = t;
		}
	}

	if (keymin == keymax) {
		if (key_checkspidup(saidx, keymin) != NULL) {
			ipseclog((LOG_DEBUG, "key_do_getnewspi: SPI %u exists already.\n", keymin));
			return 0;
		}

		count--; /* taking one cost. */
		newspi = keymin;

	} else {
	
		u_int32_t range = keymax - keymin + 1;  /* overflow value of zero means full range */

		/* init SPI */
		newspi = 0;

		/* when requesting to allocate spi ranged */
		while (count--) {
			u_int32_t rand_val = key_random();
			
			/* generate pseudo-random SPI value ranged. */
			newspi = (range == 0 ? rand_val : keymin + (rand_val % range));

			if (key_checkspidup(saidx, newspi) == NULL)
				break;
		}

		if (count == 0 || newspi == 0) {
			ipseclog((LOG_DEBUG, "key_do_getnewspi: to allocate spi is failed.\n"));
			return 0;
		}
	}

	/* statistics */
	keystat.getspi_count =
		(keystat.getspi_count + key_spi_trycnt - count) / 2;

	return newspi;
}

/*
 * SADB_UPDATE processing
 * receive
 *   <base, SA, (SA2), (lifetime(HSC),) address(SD), (address(P),)
 *       key(AE), (identity(SD),) (sensitivity)>
 * from the ikmpd, and update a secasvar entry whose status is SADB_SASTATE_LARVAL.
 * and send
 *   <base, SA, (SA2), (lifetime(HSC),) address(SD), (address(P),)
 *       (identity(SD),) (sensitivity)>
 * to the ikmpd.
 *
 * m will always be freed.
 */
static int
key_update(so, m, mhp)
	struct socket *so;
	struct mbuf *m;
	const struct sadb_msghdr *mhp;
{
	struct sadb_sa *sa0;
	struct sadb_address *src0, *dst0;
	struct secasindex saidx;
	struct secashead *sah;
	struct secasvar *sav;
	u_int16_t proto;
	u_int8_t mode;
	u_int32_t reqid;
	int error;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_update: NULL pointer is passed.\n");

	/* map satype to proto */
	if ((proto = key_satype2proto(mhp->msg->sadb_msg_satype)) == 0) {
		ipseclog((LOG_DEBUG, "key_update: invalid satype is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	if (mhp->ext[SADB_EXT_SA] == NULL ||
	    mhp->ext[SADB_EXT_ADDRESS_SRC] == NULL ||
	    mhp->ext[SADB_EXT_ADDRESS_DST] == NULL ||
	    (mhp->msg->sadb_msg_satype == SADB_SATYPE_ESP &&
	     mhp->ext[SADB_EXT_KEY_ENCRYPT] == NULL) ||
	    (mhp->msg->sadb_msg_satype == SADB_SATYPE_AH &&
	     mhp->ext[SADB_EXT_KEY_AUTH] == NULL) ||
	    (mhp->ext[SADB_EXT_LIFETIME_HARD] != NULL &&
	     mhp->ext[SADB_EXT_LIFETIME_SOFT] == NULL) ||
	    (mhp->ext[SADB_EXT_LIFETIME_HARD] == NULL &&
	     mhp->ext[SADB_EXT_LIFETIME_SOFT] != NULL)) {
		ipseclog((LOG_DEBUG, "key_update: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}
	if (mhp->extlen[SADB_EXT_SA] < sizeof(struct sadb_sa) ||
	    mhp->extlen[SADB_EXT_ADDRESS_SRC] < sizeof(struct sadb_address) ||
	    mhp->extlen[SADB_EXT_ADDRESS_DST] < sizeof(struct sadb_address)) {
		ipseclog((LOG_DEBUG, "key_update: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}
	if (mhp->ext[SADB_X_EXT_SA2] != NULL) {
		mode = ((struct sadb_x_sa2 *)mhp->ext[SADB_X_EXT_SA2])->sadb_x_sa2_mode;
		reqid = ((struct sadb_x_sa2 *)mhp->ext[SADB_X_EXT_SA2])->sadb_x_sa2_reqid;
	} else {
		mode = IPSEC_MODE_ANY;
		reqid = 0;
	}
	/* XXX boundary checking for other extensions */

	sa0 = (struct sadb_sa *)mhp->ext[SADB_EXT_SA];
	src0 = (struct sadb_address *)(mhp->ext[SADB_EXT_ADDRESS_SRC]);
	dst0 = (struct sadb_address *)(mhp->ext[SADB_EXT_ADDRESS_DST]);

	/* XXX boundary check against sa_len */
	KEY_SETSECASIDX(proto, mode, reqid, src0 + 1, dst0 + 1, &saidx);

	lck_mtx_lock(sadb_mutex);
	
	/* get a SA header */
	if ((sah = key_getsah(&saidx)) == NULL) {
		lck_mtx_unlock(sadb_mutex);
		ipseclog((LOG_DEBUG, "key_update: no SA index found.\n"));
		return key_senderror(so, m, ENOENT);
	}

	/* set spidx if there */
	/* XXX rewrite */
	error = key_setident(sah, m, mhp);
	if (error) {
		lck_mtx_unlock(sadb_mutex);
		return key_senderror(so, m, error);
	}

	/* find a SA with sequence number. */
#if IPSEC_DOSEQCHECK
	if (mhp->msg->sadb_msg_seq != 0
	 && (sav = key_getsavbyseq(sah, mhp->msg->sadb_msg_seq)) == NULL) {
	 	lck_mtx_unlock(sadb_mutex);
		ipseclog((LOG_DEBUG,
		    "key_update: no larval SA with sequence %u exists.\n",
		    mhp->msg->sadb_msg_seq));
		return key_senderror(so, m, ENOENT);
	}
#else
	if ((sav = key_getsavbyspi(sah, sa0->sadb_sa_spi)) == NULL) {
		lck_mtx_unlock(sadb_mutex);
		ipseclog((LOG_DEBUG,
		    "key_update: no such a SA found (spi:%u)\n",
		    (u_int32_t)ntohl(sa0->sadb_sa_spi)));
		return key_senderror(so, m, EINVAL);
	}
#endif

	/* validity check */
	if (sav->sah->saidx.proto != proto) {
		lck_mtx_unlock(sadb_mutex);
		ipseclog((LOG_DEBUG,
		    "key_update: protocol mismatched (DB=%u param=%u)\n",
		    sav->sah->saidx.proto, proto));
		return key_senderror(so, m, EINVAL);
	}
#if IPSEC_DOSEQCHECK
	if (sav->spi != sa0->sadb_sa_spi) {
		lck_mtx_unlock(sadb_mutex);
		ipseclog((LOG_DEBUG,
		    "key_update: SPI mismatched (DB:%u param:%u)\n",
		    (u_int32_t)ntohl(sav->spi),
		    (u_int32_t)ntohl(sa0->sadb_sa_spi)));
		return key_senderror(so, m, EINVAL);
	}
#endif
	if (sav->pid != mhp->msg->sadb_msg_pid) {
		lck_mtx_unlock(sadb_mutex);
		ipseclog((LOG_DEBUG,
		    "key_update: pid mismatched (DB:%u param:%u)\n",
		    sav->pid, mhp->msg->sadb_msg_pid));
		return key_senderror(so, m, EINVAL);
	}

	/* copy sav values */
	error = key_setsaval(sav, m, mhp);
	if (error) {
		key_freesav(sav, KEY_SADB_LOCKED);
		lck_mtx_unlock(sadb_mutex);
		return key_senderror(so, m, error);
	}
	
	/*
	 * Verify if SADB_X_EXT_NATT_MULTIPLEUSERS flag is set that
	 * this SA is for transport mode - otherwise clear it.
	 */
	if ((sav->flags & SADB_X_EXT_NATT_MULTIPLEUSERS) != 0 &&
		(sav->sah->saidx.mode != IPSEC_MODE_TRANSPORT ||
		sav->sah->saidx.src.ss_family != AF_INET))
		sav->flags &= ~SADB_X_EXT_NATT_MULTIPLEUSERS;

	/* check SA values to be mature. */
	if ((error = key_mature(sav)) != 0) {
		key_freesav(sav, KEY_SADB_LOCKED);
		lck_mtx_unlock(sadb_mutex);
		return key_senderror(so, m, error);
	}
	
	lck_mtx_unlock(sadb_mutex);
	
    {
	struct mbuf *n;

	/* set msg buf from mhp */
	n = key_getmsgbuf_x1(m, mhp);
	if (n == NULL) {
		ipseclog((LOG_DEBUG, "key_update: No more memory.\n"));
		return key_senderror(so, m, ENOBUFS);
	}

	m_freem(m);
	return key_sendup_mbuf(so, n, KEY_SENDUP_ALL);
    }
}

/*
 * search SAD with sequence for a SA which state is SADB_SASTATE_LARVAL.
 * only called by key_update().
 * OUT:
 *	NULL	: not found
 *	others	: found, pointer to a SA.
 */
#if IPSEC_DOSEQCHECK
static struct secasvar *
key_getsavbyseq(sah, seq)
	struct secashead *sah;
	u_int32_t seq;
{
	struct secasvar *sav;
	u_int state;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);

	state = SADB_SASTATE_LARVAL;

	/* search SAD with sequence number ? */
	LIST_FOREACH(sav, &sah->savtree[state], chain) {

		KEY_CHKSASTATE(state, sav->state, "key_getsabyseq");

		if (sav->seq == seq) {
			sav->refcnt++;
			KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
				printf("DP key_getsavbyseq cause "
					"refcnt++:%d SA:%p\n",
					sav->refcnt, sav));
			return sav;
		}
	}

	return NULL;
}
#endif

/*
 * SADB_ADD processing
 * add a entry to SA database, when received
 *   <base, SA, (SA2), (lifetime(HSC),) address(SD), (address(P),)
 *       key(AE), (identity(SD),) (sensitivity)>
 * from the ikmpd,
 * and send
 *   <base, SA, (SA2), (lifetime(HSC),) address(SD), (address(P),)
 *       (identity(SD),) (sensitivity)>
 * to the ikmpd.
 *
 * IGNORE identity and sensitivity messages.
 *
 * m will always be freed.
 */
static int
key_add(so, m, mhp)
	struct socket *so;
	struct mbuf *m;
	const struct sadb_msghdr *mhp;
{
	struct sadb_sa *sa0;
	struct sadb_address *src0, *dst0;
	struct secasindex saidx;
	struct secashead *newsah;
	struct secasvar *newsav;
	u_int16_t proto;
	u_int8_t mode;
	u_int32_t reqid;
	int error;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_add: NULL pointer is passed.\n");

	/* map satype to proto */
	if ((proto = key_satype2proto(mhp->msg->sadb_msg_satype)) == 0) {
		ipseclog((LOG_DEBUG, "key_add: invalid satype is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	if (mhp->ext[SADB_EXT_SA] == NULL ||
	    mhp->ext[SADB_EXT_ADDRESS_SRC] == NULL ||
	    mhp->ext[SADB_EXT_ADDRESS_DST] == NULL ||
	    (mhp->msg->sadb_msg_satype == SADB_SATYPE_ESP &&
	     mhp->ext[SADB_EXT_KEY_ENCRYPT] == NULL) ||
	    (mhp->msg->sadb_msg_satype == SADB_SATYPE_AH &&
	     mhp->ext[SADB_EXT_KEY_AUTH] == NULL) ||
	    (mhp->ext[SADB_EXT_LIFETIME_HARD] != NULL &&
	     mhp->ext[SADB_EXT_LIFETIME_SOFT] == NULL) ||
	    (mhp->ext[SADB_EXT_LIFETIME_HARD] == NULL &&
	     mhp->ext[SADB_EXT_LIFETIME_SOFT] != NULL)) {
		ipseclog((LOG_DEBUG, "key_add: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}
	if (mhp->extlen[SADB_EXT_SA] < sizeof(struct sadb_sa) ||
	    mhp->extlen[SADB_EXT_ADDRESS_SRC] < sizeof(struct sadb_address) ||
	    mhp->extlen[SADB_EXT_ADDRESS_DST] < sizeof(struct sadb_address)) {
		/* XXX need more */
		ipseclog((LOG_DEBUG, "key_add: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}
	if (mhp->ext[SADB_X_EXT_SA2] != NULL) {
		mode = ((struct sadb_x_sa2 *)mhp->ext[SADB_X_EXT_SA2])->sadb_x_sa2_mode;
		reqid = ((struct sadb_x_sa2 *)mhp->ext[SADB_X_EXT_SA2])->sadb_x_sa2_reqid;
	} else {
		mode = IPSEC_MODE_ANY;
		reqid = 0;
	}

	sa0 = (struct sadb_sa *)mhp->ext[SADB_EXT_SA];
	src0 = (struct sadb_address *)mhp->ext[SADB_EXT_ADDRESS_SRC];
	dst0 = (struct sadb_address *)mhp->ext[SADB_EXT_ADDRESS_DST];

	/* XXX boundary check against sa_len */
	KEY_SETSECASIDX(proto, mode, reqid, src0 + 1, dst0 + 1, &saidx);

	lck_mtx_lock(sadb_mutex);
	
	/* get a SA header */
	if ((newsah = key_getsah(&saidx)) == NULL) {
		/* create a new SA header: key_addspi is always used for outbound spi */
		if ((newsah = key_newsah(&saidx, IPSEC_DIR_OUTBOUND)) == NULL) {
			lck_mtx_unlock(sadb_mutex);
			ipseclog((LOG_DEBUG, "key_add: No more memory.\n"));
			return key_senderror(so, m, ENOBUFS);
		}
	}

	/* set spidx if there */
	/* XXX rewrite */
	error = key_setident(newsah, m, mhp);
	if (error) {
		lck_mtx_unlock(sadb_mutex);
		return key_senderror(so, m, error);
	}

	/* create new SA entry. */
	/* We can create new SA only if SPI is different. */
	if (key_getsavbyspi(newsah, sa0->sadb_sa_spi)) {
		lck_mtx_unlock(sadb_mutex);
		ipseclog((LOG_DEBUG, "key_add: SA already exists.\n"));
		return key_senderror(so, m, EEXIST);
	}
	newsav = key_newsav(m, mhp, newsah, &error);
	if (newsav == NULL) {
		lck_mtx_unlock(sadb_mutex);
		return key_senderror(so, m, error);
	}

	/*
	 * Verify if SADB_X_EXT_NATT_MULTIPLEUSERS flag is set that
	 * this SA is for transport mode - otherwise clear it.
	 */
	if ((newsav->flags & SADB_X_EXT_NATT_MULTIPLEUSERS) != 0 &&
		(newsah->saidx.mode != IPSEC_MODE_TRANSPORT ||
		newsah->saidx.dst.ss_family != AF_INET))
		newsav->flags &= ~SADB_X_EXT_NATT_MULTIPLEUSERS;

	/* check SA values to be mature. */
	if ((error = key_mature(newsav)) != 0) {
		key_freesav(newsav, KEY_SADB_LOCKED);
		lck_mtx_unlock(sadb_mutex);
		return key_senderror(so, m, error);
	}

	lck_mtx_unlock(sadb_mutex);
	
	/*
	 * don't call key_freesav() here, as we would like to keep the SA
	 * in the database on success.
	 */

    {
	struct mbuf *n;

	/* set msg buf from mhp */
	n = key_getmsgbuf_x1(m, mhp);
	if (n == NULL) {
		ipseclog((LOG_DEBUG, "key_update: No more memory.\n"));
		return key_senderror(so, m, ENOBUFS);
	}

	m_freem(m);
	return key_sendup_mbuf(so, n, KEY_SENDUP_ALL);
    }
}

/* m is retained */
static int
key_setident(sah, m, mhp)
	struct secashead *sah;
	struct mbuf *m;
	const struct sadb_msghdr *mhp;
{
	const struct sadb_ident *idsrc, *iddst;
	int idsrclen, iddstlen;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);

	/* sanity check */
	if (sah == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_setident: NULL pointer is passed.\n");

	/* don't make buffer if not there */
	if (mhp->ext[SADB_EXT_IDENTITY_SRC] == NULL &&
	    mhp->ext[SADB_EXT_IDENTITY_DST] == NULL) {
		sah->idents = NULL;
		sah->identd = NULL;
		return 0;
	}
	
	if (mhp->ext[SADB_EXT_IDENTITY_SRC] == NULL ||
	    mhp->ext[SADB_EXT_IDENTITY_DST] == NULL) {
		ipseclog((LOG_DEBUG, "key_setident: invalid identity.\n"));
		return EINVAL;
	}

	idsrc = (const struct sadb_ident *)mhp->ext[SADB_EXT_IDENTITY_SRC];
	iddst = (const struct sadb_ident *)mhp->ext[SADB_EXT_IDENTITY_DST];
	idsrclen = mhp->extlen[SADB_EXT_IDENTITY_SRC];
	iddstlen = mhp->extlen[SADB_EXT_IDENTITY_DST];

	/* validity check */
	if (idsrc->sadb_ident_type != iddst->sadb_ident_type) {
		ipseclog((LOG_DEBUG, "key_setident: ident type mismatch.\n"));
		return EINVAL;
	}

	switch (idsrc->sadb_ident_type) {
	case SADB_IDENTTYPE_PREFIX:
	case SADB_IDENTTYPE_FQDN:
	case SADB_IDENTTYPE_USERFQDN:
	default:
		/* XXX do nothing */
		sah->idents = NULL;
		sah->identd = NULL;
	 	return 0;
	}

	/* make structure */
	KMALLOC_NOWAIT(sah->idents, struct sadb_ident *, idsrclen);
	if (sah->idents == NULL) {
		lck_mtx_unlock(sadb_mutex);
		KMALLOC_WAIT(sah->idents, struct sadb_ident *, idsrclen);
		lck_mtx_lock(sadb_mutex);
		if (sah->idents == NULL) {
			ipseclog((LOG_DEBUG, "key_setident: No more memory.\n"));
			return ENOBUFS;
		}
	}
	KMALLOC_NOWAIT(sah->identd, struct sadb_ident *, iddstlen);
	if (sah->identd == NULL) {
		lck_mtx_unlock(sadb_mutex);
		KMALLOC_WAIT(sah->identd, struct sadb_ident *, iddstlen);
		lck_mtx_lock(sadb_mutex);
		if (sah->identd == NULL) {
			KFREE(sah->idents);
			sah->idents = NULL;
			ipseclog((LOG_DEBUG, "key_setident: No more memory.\n"));
			return ENOBUFS;
		}
	}
	bcopy(idsrc, sah->idents, idsrclen);
	bcopy(iddst, sah->identd, iddstlen);

	return 0;
}

/*
 * m will not be freed on return.
 * it is caller's responsibility to free the result. 
 */
static struct mbuf *
key_getmsgbuf_x1(m, mhp)
	struct mbuf *m;
	const struct sadb_msghdr *mhp;
{
	struct mbuf *n;
	int mbufItems[] = {SADB_EXT_RESERVED, SADB_EXT_SA,
					SADB_X_EXT_SA2, SADB_EXT_ADDRESS_SRC,
					SADB_EXT_ADDRESS_DST, SADB_EXT_LIFETIME_HARD,
					SADB_EXT_LIFETIME_SOFT, SADB_EXT_IDENTITY_SRC,
					SADB_EXT_IDENTITY_DST};

	/* sanity check */
	if (m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_getmsgbuf_x1: NULL pointer is passed.\n");

	/* create new sadb_msg to reply. */
	n = key_gather_mbuf(m, mhp, 1, sizeof(mbufItems)/sizeof(int), mbufItems);
	if (!n)
		return NULL;

	if (n->m_len < sizeof(struct sadb_msg)) {
		n = m_pullup(n, sizeof(struct sadb_msg));
		if (n == NULL)
			return NULL;
	}
	mtod(n, struct sadb_msg *)->sadb_msg_errno = 0;
	mtod(n, struct sadb_msg *)->sadb_msg_len =
	    PFKEY_UNIT64(n->m_pkthdr.len);

	return n;
}

static int key_delete_all(struct socket *, struct mbuf *,
	const struct sadb_msghdr *, u_int16_t);

/*
 * SADB_DELETE processing
 * receive
 *   <base, SA(*), address(SD)>
 * from the ikmpd, and set SADB_SASTATE_DEAD,
 * and send,
 *   <base, SA(*), address(SD)>
 * to the ikmpd.
 *
 * m will always be freed.
 */
static int
key_delete(so, m, mhp)
	struct socket *so;
	struct mbuf *m;
	const struct sadb_msghdr *mhp;
{
	struct sadb_sa *sa0;
	struct sadb_address *src0, *dst0;
	struct secasindex saidx;
	struct secashead *sah;
	struct secasvar *sav = NULL;
	u_int16_t proto;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_delete: NULL pointer is passed.\n");

	/* map satype to proto */
	if ((proto = key_satype2proto(mhp->msg->sadb_msg_satype)) == 0) {
		ipseclog((LOG_DEBUG, "key_delete: invalid satype is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	if (mhp->ext[SADB_EXT_ADDRESS_SRC] == NULL ||
	    mhp->ext[SADB_EXT_ADDRESS_DST] == NULL) {
		ipseclog((LOG_DEBUG, "key_delete: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	if (mhp->extlen[SADB_EXT_ADDRESS_SRC] < sizeof(struct sadb_address) ||
	    mhp->extlen[SADB_EXT_ADDRESS_DST] < sizeof(struct sadb_address)) {
		ipseclog((LOG_DEBUG, "key_delete: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	lck_mtx_lock(sadb_mutex);
	
	if (mhp->ext[SADB_EXT_SA] == NULL) {
		/*
		 * Caller wants us to delete all non-LARVAL SAs
		 * that match the src/dst.  This is used during
		 * IKE INITIAL-CONTACT.
		 */
		ipseclog((LOG_DEBUG, "key_delete: doing delete all.\n"));
		/* key_delete_all will unlock sadb_mutex  */
		return key_delete_all(so, m, mhp, proto);	
	} else if (mhp->extlen[SADB_EXT_SA] < sizeof(struct sadb_sa)) {
		lck_mtx_unlock(sadb_mutex);
		ipseclog((LOG_DEBUG, "key_delete: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	sa0 = (struct sadb_sa *)mhp->ext[SADB_EXT_SA];
	src0 = (struct sadb_address *)(mhp->ext[SADB_EXT_ADDRESS_SRC]);
	dst0 = (struct sadb_address *)(mhp->ext[SADB_EXT_ADDRESS_DST]);

	/* XXX boundary check against sa_len */
	KEY_SETSECASIDX(proto, IPSEC_MODE_ANY, 0, src0 + 1, dst0 + 1, &saidx);

	/* get a SA header */
	LIST_FOREACH(sah, &sahtree, chain) {
		if (sah->state == SADB_SASTATE_DEAD)
			continue;
		if (key_cmpsaidx(&sah->saidx, &saidx, CMP_HEAD) == 0)
			continue;

		/* get a SA with SPI. */
		sav = key_getsavbyspi(sah, sa0->sadb_sa_spi);
		if (sav)
			break;
	}
	if (sah == NULL) {
		lck_mtx_unlock(sadb_mutex);
		ipseclog((LOG_DEBUG, "key_delete: no SA found.\n"));
		return key_senderror(so, m, ENOENT);
	}

	key_sa_chgstate(sav, SADB_SASTATE_DEAD);
	key_freesav(sav, KEY_SADB_LOCKED);
	
	lck_mtx_unlock(sadb_mutex);
	sav = NULL;

    {
	struct mbuf *n;
	struct sadb_msg *newmsg;
	int mbufItems[] = {SADB_EXT_RESERVED, SADB_EXT_SA,
						SADB_EXT_ADDRESS_SRC, SADB_EXT_ADDRESS_DST};

	/* create new sadb_msg to reply. */
	n = key_gather_mbuf(m, mhp, 1, sizeof(mbufItems)/sizeof(int), mbufItems);
	if (!n)
		return key_senderror(so, m, ENOBUFS);

	if (n->m_len < sizeof(struct sadb_msg)) {
		n = m_pullup(n, sizeof(struct sadb_msg));
		if (n == NULL)
			return key_senderror(so, m, ENOBUFS);
	}
	newmsg = mtod(n, struct sadb_msg *);
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(n->m_pkthdr.len);

	m_freem(m);
	return key_sendup_mbuf(so, n, KEY_SENDUP_ALL);
    }
}

/*
 * delete all SAs for src/dst.  Called from key_delete().
 */
static int
key_delete_all(so, m, mhp, proto)
	struct socket *so;
	struct mbuf *m;
	const struct sadb_msghdr *mhp;
	u_int16_t proto;
{
	struct sadb_address *src0, *dst0;
	struct secasindex saidx;
	struct secashead *sah;
	struct secasvar *sav, *nextsav;
	u_int stateidx, state;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);

	src0 = (struct sadb_address *)(mhp->ext[SADB_EXT_ADDRESS_SRC]);
	dst0 = (struct sadb_address *)(mhp->ext[SADB_EXT_ADDRESS_DST]);

	/* XXX boundary check against sa_len */
	KEY_SETSECASIDX(proto, IPSEC_MODE_ANY, 0, src0 + 1, dst0 + 1, &saidx);

	LIST_FOREACH(sah, &sahtree, chain) {
		if (sah->state == SADB_SASTATE_DEAD)
			continue;
		if (key_cmpsaidx(&sah->saidx, &saidx, CMP_HEAD) == 0)
			continue;

		/* Delete all non-LARVAL SAs. */
		for (stateidx = 0;
		     stateidx < _ARRAYLEN(saorder_state_alive);
		     stateidx++) {
			state = saorder_state_alive[stateidx];
			if (state == SADB_SASTATE_LARVAL)
				continue;
			for (sav = LIST_FIRST(&sah->savtree[state]);
			     sav != NULL; sav = nextsav) {
				nextsav = LIST_NEXT(sav, chain);
				/* sanity check */
				if (sav->state != state) {
					ipseclog((LOG_DEBUG, "key_delete_all: "
					       "invalid sav->state "
					       "(queue: %d SA: %d)\n",
					       state, sav->state));
					continue;
				}
				
				key_sa_chgstate(sav, SADB_SASTATE_DEAD);
				key_freesav(sav, KEY_SADB_LOCKED);
			}
		}
	}
	lck_mtx_unlock(sadb_mutex);
	
    {
	struct mbuf *n;
	struct sadb_msg *newmsg;
	int mbufItems[] = {SADB_EXT_RESERVED, SADB_EXT_ADDRESS_SRC,
						SADB_EXT_ADDRESS_DST};

	/* create new sadb_msg to reply. */
	n = key_gather_mbuf(m, mhp, 1, sizeof(mbufItems)/sizeof(int), mbufItems);
	if (!n)
		return key_senderror(so, m, ENOBUFS);

	if (n->m_len < sizeof(struct sadb_msg)) {
		n = m_pullup(n, sizeof(struct sadb_msg));
		if (n == NULL)
			return key_senderror(so, m, ENOBUFS);
	}
	newmsg = mtod(n, struct sadb_msg *);
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(n->m_pkthdr.len);

	m_freem(m);
	return key_sendup_mbuf(so, n, KEY_SENDUP_ALL);
    }
}

/*
 * SADB_GET processing
 * receive
 *   <base, SA(*), address(SD)>
 * from the ikmpd, and get a SP and a SA to respond,
 * and send,
 *   <base, SA, (lifetime(HSC),) address(SD), (address(P),) key(AE),
 *       (identity(SD),) (sensitivity)>
 * to the ikmpd.
 *
 * m will always be freed.
 */
static int
key_get(so, m, mhp)
	struct socket *so;
	struct mbuf *m;
	const struct sadb_msghdr *mhp;
{
	struct sadb_sa *sa0;
	struct sadb_address *src0, *dst0;
	struct secasindex saidx;
	struct secashead *sah;
	struct secasvar *sav = NULL;
	u_int16_t proto;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_get: NULL pointer is passed.\n");

	/* map satype to proto */
	if ((proto = key_satype2proto(mhp->msg->sadb_msg_satype)) == 0) {
		ipseclog((LOG_DEBUG, "key_get: invalid satype is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	if (mhp->ext[SADB_EXT_SA] == NULL ||
	    mhp->ext[SADB_EXT_ADDRESS_SRC] == NULL ||
	    mhp->ext[SADB_EXT_ADDRESS_DST] == NULL) {
		ipseclog((LOG_DEBUG, "key_get: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}
	if (mhp->extlen[SADB_EXT_SA] < sizeof(struct sadb_sa) ||
	    mhp->extlen[SADB_EXT_ADDRESS_SRC] < sizeof(struct sadb_address) ||
	    mhp->extlen[SADB_EXT_ADDRESS_DST] < sizeof(struct sadb_address)) {
		ipseclog((LOG_DEBUG, "key_get: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	sa0 = (struct sadb_sa *)mhp->ext[SADB_EXT_SA];
	src0 = (struct sadb_address *)mhp->ext[SADB_EXT_ADDRESS_SRC];
	dst0 = (struct sadb_address *)mhp->ext[SADB_EXT_ADDRESS_DST];

	/* XXX boundary check against sa_len */
	KEY_SETSECASIDX(proto, IPSEC_MODE_ANY, 0, src0 + 1, dst0 + 1, &saidx);

	lck_mtx_lock(sadb_mutex);
	
	/* get a SA header */
	LIST_FOREACH(sah, &sahtree, chain) {
		if (sah->state == SADB_SASTATE_DEAD)
			continue;
		if (key_cmpsaidx(&sah->saidx, &saidx, CMP_HEAD) == 0)
			continue;

		/* get a SA with SPI. */
		sav = key_getsavbyspi(sah, sa0->sadb_sa_spi);
		if (sav)
			break;
	}
	if (sah == NULL) {
		lck_mtx_unlock(sadb_mutex);
		ipseclog((LOG_DEBUG, "key_get: no SA found.\n"));
		return key_senderror(so, m, ENOENT);
	}

    {
	struct mbuf *n;
	u_int8_t satype;

	/* map proto to satype */
	if ((satype = key_proto2satype(sah->saidx.proto)) == 0) {
		lck_mtx_unlock(sadb_mutex);
		ipseclog((LOG_DEBUG, "key_get: there was invalid proto in SAD.\n"));
		return key_senderror(so, m, EINVAL);
	}
	lck_mtx_unlock(sadb_mutex);

	/* create new sadb_msg to reply. */
	n = key_setdumpsa(sav, SADB_GET, satype, mhp->msg->sadb_msg_seq,
	    mhp->msg->sadb_msg_pid);
	   
	
	
	if (!n)
		return key_senderror(so, m, ENOBUFS);

	m_freem(m);
	return key_sendup_mbuf(so, n, KEY_SENDUP_ONE);
    }
}

/*
 * get SA stats by spi.
 * OUT:	-1	: not found
 *	0	: found, arg pointer to a SA stats is updated.
 */
static int
key_getsastatbyspi_one (u_int32_t      spi,
			struct sastat *stat)
{
	struct secashead *sah;
	struct secasvar  *sav = NULL;

	if ((void *)stat == NULL) {
	        return -1;
	}

	lck_mtx_lock(sadb_mutex);
	
	/* get a SA header */
	LIST_FOREACH(sah, &sahtree, chain) {
		if (sah->state == SADB_SASTATE_DEAD)
			continue;

		/* get a SA with SPI. */
		sav = key_getsavbyspi(sah, spi);
		if (sav) {
		        stat->spi = sav->spi;
			stat->created = sav->created;
			if (sav->lft_c) {
			        bcopy(sav->lft_c,&stat->lft_c, sizeof(stat->lft_c));
			} else {
			        bzero(&stat->lft_c, sizeof(stat->lft_c));
			}
			lck_mtx_unlock(sadb_mutex);
			return 0;
		}
	}

	lck_mtx_unlock(sadb_mutex);

	return -1;
}

/*
 * get SA stats collection by indices.
 * OUT:	-1	: not found
 *	0	: found, arg pointers to a SA stats and 'maximum stats' are updated.
 */
static int
key_getsastatbyspi (struct sastat *stat_arg,
		    u_int32_t      max_stat_arg,
		    struct sastat *stat_res,
		    u_int32_t     *max_stat_res)
{
        int cur, found = 0;

	if (stat_arg == NULL ||
	    stat_res == NULL || 
	    max_stat_res == NULL) {
	        return -1;
	}

	for (cur = 0; cur < max_stat_arg; cur++) {
	        if (key_getsastatbyspi_one(stat_arg[cur].spi,
					   &stat_res[found]) == 0) {
		        found++;
		}
	}
	*max_stat_res = found;

	if (found) {
	        return 0;
	}
	return -1;
}

/* XXX make it sysctl-configurable? */
static void
key_getcomb_setlifetime(comb)
	struct sadb_comb *comb;
{

	comb->sadb_comb_soft_allocations = 1;
	comb->sadb_comb_hard_allocations = 1;
	comb->sadb_comb_soft_bytes = 0;
	comb->sadb_comb_hard_bytes = 0;
	comb->sadb_comb_hard_addtime = 86400;	/* 1 day */
	comb->sadb_comb_soft_addtime = comb->sadb_comb_soft_addtime * 80 / 100;
	comb->sadb_comb_soft_usetime = 28800;	/* 8 hours */
	comb->sadb_comb_hard_usetime = comb->sadb_comb_hard_usetime * 80 / 100;
}

#if IPSEC_ESP
/*
 * XXX reorder combinations by preference
 * XXX no idea if the user wants ESP authentication or not
 */
static struct mbuf *
key_getcomb_esp()
{
	struct sadb_comb *comb;
	const struct esp_algorithm *algo;
	struct mbuf *result = NULL, *m, *n;
	int encmin;
	int i, off, o;
	int totlen;
	const int l = PFKEY_ALIGN8(sizeof(struct sadb_comb));

	m = NULL;
	for (i = 1; i <= SADB_EALG_MAX; i++) {
		algo = esp_algorithm_lookup(i);
		if (!algo)
			continue;

		if (algo->keymax < ipsec_esp_keymin)
			continue;
		if (algo->keymin < ipsec_esp_keymin)
			encmin = ipsec_esp_keymin;
		else
			encmin = algo->keymin;

		if (ipsec_esp_auth)
			m = key_getcomb_ah();
		else {
#if DIAGNOSTIC
			if (l > MLEN)
				panic("assumption failed in key_getcomb_esp");
#endif
			MGET(m, M_DONTWAIT, MT_DATA);
			if (m) {
				M_ALIGN(m, l);
				m->m_len = l;
				m->m_next = NULL;
				bzero(mtod(m, caddr_t), m->m_len);
			}
		}
		if (!m)
			goto fail;

		totlen = 0;
		for (n = m; n; n = n->m_next)
			totlen += n->m_len;
#if DIAGNOSTIC
		if (totlen % l)
			panic("assumption failed in key_getcomb_esp");
#endif

		for (off = 0; off < totlen; off += l) {
			n = m_pulldown(m, off, l, &o);
			if (!n) {
				/* m is already freed */
				goto fail;
			}
			comb = (struct sadb_comb *)(mtod(n, caddr_t) + o);
			bzero(comb, sizeof(*comb));
			key_getcomb_setlifetime(comb);
			comb->sadb_comb_encrypt = i;
			comb->sadb_comb_encrypt_minbits = encmin;
			comb->sadb_comb_encrypt_maxbits = algo->keymax;
		}

		if (!result)
			result = m;
		else
			m_cat(result, m);
	}

	return result;

 fail:
	if (result)
		m_freem(result);
	return NULL;
}
#endif

/*
 * XXX reorder combinations by preference
 */
static struct mbuf *
key_getcomb_ah()
{
	struct sadb_comb *comb;
	const struct ah_algorithm *algo;
	struct mbuf *m;
	int keymin;
	int i;
	const int l = PFKEY_ALIGN8(sizeof(struct sadb_comb));

	m = NULL;
	for (i = 1; i <= SADB_AALG_MAX; i++) {
#if 1
		/* we prefer HMAC algorithms, not old algorithms */
		if (i != SADB_AALG_SHA1HMAC && i != SADB_AALG_MD5HMAC)
			continue;
#endif
		algo = ah_algorithm_lookup(i);
		if (!algo)
			continue;

		if (algo->keymax < ipsec_ah_keymin)
			continue;
		if (algo->keymin < ipsec_ah_keymin)
			keymin = ipsec_ah_keymin;
		else
			keymin = algo->keymin;

		if (!m) {
#if DIAGNOSTIC
			if (l > MLEN)
				panic("assumption failed in key_getcomb_ah");
#endif
			MGET(m, M_DONTWAIT, MT_DATA);
			if (m) {
				M_ALIGN(m, l);
				m->m_len = l;
				m->m_next = NULL;
			}
		} else
			M_PREPEND(m, l, M_DONTWAIT);
		if (!m)
			return NULL;

		comb = mtod(m, struct sadb_comb *);
		bzero(comb, sizeof(*comb));
		key_getcomb_setlifetime(comb);
		comb->sadb_comb_auth = i;
		comb->sadb_comb_auth_minbits = keymin;
		comb->sadb_comb_auth_maxbits = algo->keymax;
	}

	return m;
}

/*
 * not really an official behavior.  discussed in pf_key@inner.net in Sep2000.
 * XXX reorder combinations by preference
 */
static struct mbuf *
key_getcomb_ipcomp()
{
	struct sadb_comb *comb;
	const struct ipcomp_algorithm *algo;
	struct mbuf *m;
	int i;
	const int l = PFKEY_ALIGN8(sizeof(struct sadb_comb));

	m = NULL;
	for (i = 1; i <= SADB_X_CALG_MAX; i++) {
		algo = ipcomp_algorithm_lookup(i);
		if (!algo)
			continue;

		if (!m) {
#if DIAGNOSTIC
			if (l > MLEN)
				panic("assumption failed in key_getcomb_ipcomp");
#endif
			MGET(m, M_DONTWAIT, MT_DATA);
			if (m) {
				M_ALIGN(m, l);
				m->m_len = l;
				m->m_next = NULL;
			}
		} else
			M_PREPEND(m, l, M_DONTWAIT);
		if (!m)
			return NULL;

		comb = mtod(m, struct sadb_comb *);
		bzero(comb, sizeof(*comb));
		key_getcomb_setlifetime(comb);
		comb->sadb_comb_encrypt = i;
		/* what should we set into sadb_comb_*_{min,max}bits? */
	}

	return m;
}

/*
 * XXX no way to pass mode (transport/tunnel) to userland
 * XXX replay checking?
 * XXX sysctl interface to ipsec_{ah,esp}_keymin
 */
static struct mbuf *
key_getprop(saidx)
	const struct secasindex *saidx;
{
	struct sadb_prop *prop;
	struct mbuf *m, *n;
	const int l = PFKEY_ALIGN8(sizeof(struct sadb_prop));
	int totlen;

	switch (saidx->proto)  {
#if IPSEC_ESP
	case IPPROTO_ESP:
		m = key_getcomb_esp();
		break;
#endif
	case IPPROTO_AH:
		m = key_getcomb_ah();
		break;
	case IPPROTO_IPCOMP:
		m = key_getcomb_ipcomp();
		break;
	default:
		return NULL;
	}

	if (!m)
		return NULL;
	M_PREPEND(m, l, M_DONTWAIT);
	if (!m)
		return NULL;

	totlen = 0;
	for (n = m; n; n = n->m_next)
		totlen += n->m_len;

	prop = mtod(m, struct sadb_prop *);
	bzero(prop, sizeof(*prop));
	prop->sadb_prop_len = PFKEY_UNIT64(totlen);
	prop->sadb_prop_exttype = SADB_EXT_PROPOSAL;
	prop->sadb_prop_replay = 32;	/* XXX */

	return m;
}

/*
 * SADB_ACQUIRE processing called by key_checkrequest() and key_acquire2().
 * send
 *   <base, SA, address(SD), (address(P)), x_policy,
 *       (identity(SD),) (sensitivity,) proposal>
 * to KMD, and expect to receive
 *   <base> with SADB_ACQUIRE if error occurred,
 * or
 *   <base, src address, dst address, (SPI range)> with SADB_GETSPI
 * from KMD by PF_KEY.
 *
 * XXX x_policy is outside of RFC2367 (KAME extension).
 * XXX sensitivity is not supported.
 * XXX for ipcomp, RFC2367 does not define how to fill in proposal.
 * see comment for key_getcomb_ipcomp().
 *
 * OUT:
 *    0     : succeed
 *    others: error number
 */
static int
key_acquire(saidx, sp)
	struct secasindex *saidx;
	struct secpolicy *sp;
{
	struct mbuf *result = NULL, *m;
#ifndef IPSEC_NONBLOCK_ACQUIRE
	struct secacq *newacq;
#endif
	u_int8_t satype;
	int error = -1;
	u_int32_t seq;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	/* sanity check */
	if (saidx == NULL)
		panic("key_acquire: NULL pointer is passed.\n");
	if ((satype = key_proto2satype(saidx->proto)) == 0)
		panic("key_acquire: invalid proto is passed.\n");

#ifndef IPSEC_NONBLOCK_ACQUIRE
	/*
	 * We never do anything about acquirng SA.  There is anather
	 * solution that kernel blocks to send SADB_ACQUIRE message until
	 * getting something message from IKEd.  In later case, to be
	 * managed with ACQUIRING list.
	 */
	/* get a entry to check whether sending message or not. */
	lck_mtx_lock(sadb_mutex);
	if ((newacq = key_getacq(saidx)) != NULL) {
		if (key_blockacq_count < newacq->count) {
			/* reset counter and do send message. */
			newacq->count = 0;
		} else {
			/* increment counter and do nothing. */
			newacq->count++;
			lck_mtx_unlock(sadb_mutex);
			return 0;
		}
	} else {
		/* make new entry for blocking to send SADB_ACQUIRE. */
		if ((newacq = key_newacq(saidx)) == NULL) {
			lck_mtx_unlock(sadb_mutex);
			return ENOBUFS;
		}

		/* add to acqtree */
		LIST_INSERT_HEAD(&acqtree, newacq, chain);
	}
	seq = newacq->seq;
	lck_mtx_unlock(sadb_mutex);

#else
	seq = (acq_seq = (acq_seq == ~0 ? 1 : ++acq_seq));
#endif
	m = key_setsadbmsg(SADB_ACQUIRE, 0, satype, seq, 0, 0);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	result = m;

	/* set sadb_address for saidx's. */
	m = key_setsadbaddr(SADB_EXT_ADDRESS_SRC,
	    (struct sockaddr *)&saidx->src, FULLMASK, IPSEC_ULPROTO_ANY);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	m_cat(result, m);

	m = key_setsadbaddr(SADB_EXT_ADDRESS_DST,
	    (struct sockaddr *)&saidx->dst, FULLMASK, IPSEC_ULPROTO_ANY);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	m_cat(result, m);

	/* XXX proxy address (optional) */

	/* set sadb_x_policy */
	if (sp) {
		m = key_setsadbxpolicy(sp->policy, sp->spidx.dir, sp->id);
		if (!m) {
			error = ENOBUFS;
			goto fail;
		}
		m_cat(result, m);
	}

	/* XXX identity (optional) */
#if 0
	if (idexttype && fqdn) {
		/* create identity extension (FQDN) */
		struct sadb_ident *id;
		int fqdnlen;

		fqdnlen = strlen(fqdn) + 1;	/* +1 for terminating-NUL */
		id = (struct sadb_ident *)p;
		bzero(id, sizeof(*id) + PFKEY_ALIGN8(fqdnlen));
		id->sadb_ident_len = PFKEY_UNIT64(sizeof(*id) + PFKEY_ALIGN8(fqdnlen));
		id->sadb_ident_exttype = idexttype;
		id->sadb_ident_type = SADB_IDENTTYPE_FQDN;
		bcopy(fqdn, id + 1, fqdnlen);
		p += sizeof(struct sadb_ident) + PFKEY_ALIGN8(fqdnlen);
	}

	if (idexttype) {
		/* create identity extension (USERFQDN) */
		struct sadb_ident *id;
		int userfqdnlen;

		if (userfqdn) {
			/* +1 for terminating-NUL */
			userfqdnlen = strlen(userfqdn) + 1;
		} else
			userfqdnlen = 0;
		id = (struct sadb_ident *)p;
		bzero(id, sizeof(*id) + PFKEY_ALIGN8(userfqdnlen));
		id->sadb_ident_len = PFKEY_UNIT64(sizeof(*id) + PFKEY_ALIGN8(userfqdnlen));
		id->sadb_ident_exttype = idexttype;
		id->sadb_ident_type = SADB_IDENTTYPE_USERFQDN;
		/* XXX is it correct? */
		if (curproc && curproc->p_cred)
			id->sadb_ident_id = curproc->p_cred->p_ruid;
		if (userfqdn && userfqdnlen)
			bcopy(userfqdn, id + 1, userfqdnlen);
		p += sizeof(struct sadb_ident) + PFKEY_ALIGN8(userfqdnlen);
	}
#endif

	/* XXX sensitivity (optional) */

	/* create proposal/combination extension */
	m = key_getprop(saidx);
#if 0
	/*
	 * spec conformant: always attach proposal/combination extension,
	 * the problem is that we have no way to attach it for ipcomp,
	 * due to the way sadb_comb is declared in RFC2367.
	 */
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	m_cat(result, m);
#else
	/*
	 * outside of spec; make proposal/combination extension optional.
	 */
	if (m)
		m_cat(result, m);
#endif

	if ((result->m_flags & M_PKTHDR) == 0) {
		error = EINVAL;
		goto fail;
	}

	if (result->m_len < sizeof(struct sadb_msg)) {
		result = m_pullup(result, sizeof(struct sadb_msg));
		if (result == NULL) {
			error = ENOBUFS;
			goto fail;
		}
	}

	result->m_pkthdr.len = 0;
	for (m = result; m; m = m->m_next)
		result->m_pkthdr.len += m->m_len;

	mtod(result, struct sadb_msg *)->sadb_msg_len =
	    PFKEY_UNIT64(result->m_pkthdr.len);

	return key_sendup_mbuf(NULL, result, KEY_SENDUP_REGISTERED);

 fail:
	if (result)
		m_freem(result);
	return error;
}

#ifndef IPSEC_NONBLOCK_ACQUIRE
static struct secacq *
key_newacq(saidx)
	struct secasindex *saidx;
{
	struct secacq *newacq;
	struct timeval tv;

	/* get new entry */
	KMALLOC_NOWAIT(newacq, struct secacq *, sizeof(struct secacq));
	if (newacq == NULL) {
		lck_mtx_unlock(sadb_mutex);
		KMALLOC_WAIT(newacq, struct secacq *, sizeof(struct secacq));
		lck_mtx_lock(sadb_mutex);
			if (newacq == NULL) {
			ipseclog((LOG_DEBUG, "key_newacq: No more memory.\n"));
			return NULL;
		}
	}
	bzero(newacq, sizeof(*newacq));

	/* copy secindex */
	bcopy(saidx, &newacq->saidx, sizeof(newacq->saidx));
	newacq->seq = (acq_seq == ~0 ? 1 : ++acq_seq);
	microtime(&tv);
	newacq->created = tv.tv_sec;
	newacq->count = 0;

	return newacq;
}

static struct secacq *
key_getacq(saidx)
	struct secasindex *saidx;
{
	struct secacq *acq;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);

	LIST_FOREACH(acq, &acqtree, chain) {
		if (key_cmpsaidx(saidx, &acq->saidx, CMP_EXACTLY))
			return acq;
	}

	return NULL;
}

static struct secacq *
key_getacqbyseq(seq)
	u_int32_t seq;
{
	struct secacq *acq;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);

	LIST_FOREACH(acq, &acqtree, chain) {
		if (acq->seq == seq)
			return acq;
	}

	return NULL;
}
#endif

static struct secspacq *
key_newspacq(spidx)
	struct secpolicyindex *spidx;
{
	struct secspacq *acq;
	struct timeval tv;

	/* get new entry */
	KMALLOC_NOWAIT(acq, struct secspacq *, sizeof(struct secspacq));
	if (acq == NULL) {
		lck_mtx_unlock(sadb_mutex);
		KMALLOC_WAIT(acq, struct secspacq *, sizeof(struct secspacq));
		lck_mtx_lock(sadb_mutex);
		if (acq == NULL) {
			ipseclog((LOG_DEBUG, "key_newspacq: No more memory.\n"));
			return NULL;
		}
	}
	bzero(acq, sizeof(*acq));

	/* copy secindex */
	bcopy(spidx, &acq->spidx, sizeof(acq->spidx));
	microtime(&tv);
	acq->created = tv.tv_sec;
	acq->count = 0;

	return acq;
}

static struct secspacq *
key_getspacq(spidx)
	struct secpolicyindex *spidx;
{
	struct secspacq *acq;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);

	LIST_FOREACH(acq, &spacqtree, chain) {
		if (key_cmpspidx_exactly(spidx, &acq->spidx))
			return acq;
	}

	return NULL;
}

/*
 * SADB_ACQUIRE processing,
 * in first situation, is receiving
 *   <base>
 * from the ikmpd, and clear sequence of its secasvar entry.
 *
 * In second situation, is receiving
 *   <base, address(SD), (address(P),) (identity(SD),) (sensitivity,) proposal>
 * from a user land process, and return
 *   <base, address(SD), (address(P),) (identity(SD),) (sensitivity,) proposal>
 * to the socket.
 *
 * m will always be freed.
 */
static int
key_acquire2(so, m, mhp)
	struct socket *so;
	struct mbuf *m;
	const struct sadb_msghdr *mhp;
{
	const struct sadb_address *src0, *dst0;
	struct secasindex saidx;
	struct secashead *sah;
	u_int16_t proto;
	int error;


	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_acquire2: NULL pointer is passed.\n");

	/*
	 * Error message from KMd.
	 * We assume that if error was occurred in IKEd, the length of PFKEY
	 * message is equal to the size of sadb_msg structure.
	 * We do not raise error even if error occurred in this function.
	 */
	 lck_mtx_lock(sadb_mutex);

	if (mhp->msg->sadb_msg_len == PFKEY_UNIT64(sizeof(struct sadb_msg))) {
#ifndef IPSEC_NONBLOCK_ACQUIRE
		struct secacq *acq;
		struct timeval tv;

		/* check sequence number */
		if (mhp->msg->sadb_msg_seq == 0) {
			lck_mtx_unlock(sadb_mutex);
			ipseclog((LOG_DEBUG, "key_acquire2: must specify sequence number.\n"));
			m_freem(m);
			return 0;
		}

		if ((acq = key_getacqbyseq(mhp->msg->sadb_msg_seq)) == NULL) {
			/*
			 * the specified larval SA is already gone, or we got
			 * a bogus sequence number.  we can silently ignore it.
			 */
			lck_mtx_unlock(sadb_mutex);
			m_freem(m);
			return 0;
		}

		/* reset acq counter in order to deletion by timehander. */
		microtime(&tv);
		acq->created = tv.tv_sec;
		acq->count = 0;
#endif
		lck_mtx_unlock(sadb_mutex);
		m_freem(m);
		return 0;
	}

	/*
	 * This message is from user land.
	 */

	/* map satype to proto */
	if ((proto = key_satype2proto(mhp->msg->sadb_msg_satype)) == 0) {
		lck_mtx_unlock(sadb_mutex);
		ipseclog((LOG_DEBUG, "key_acquire2: invalid satype is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	if (mhp->ext[SADB_EXT_ADDRESS_SRC] == NULL ||
	    mhp->ext[SADB_EXT_ADDRESS_DST] == NULL ||
	    mhp->ext[SADB_EXT_PROPOSAL] == NULL) {
		/* error */
		lck_mtx_unlock(sadb_mutex);
		ipseclog((LOG_DEBUG, "key_acquire2: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}
	if (mhp->extlen[SADB_EXT_ADDRESS_SRC] < sizeof(struct sadb_address) ||
	    mhp->extlen[SADB_EXT_ADDRESS_DST] < sizeof(struct sadb_address) ||
	    mhp->extlen[SADB_EXT_PROPOSAL] < sizeof(struct sadb_prop)) {
		/* error */
		lck_mtx_unlock(sadb_mutex);
		ipseclog((LOG_DEBUG, "key_acquire2: invalid message is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	src0 = (const struct sadb_address *)mhp->ext[SADB_EXT_ADDRESS_SRC];
	dst0 = (const struct sadb_address *)mhp->ext[SADB_EXT_ADDRESS_DST];

	/* XXX boundary check against sa_len */
	/* cast warnings */
	KEY_SETSECASIDX(proto, IPSEC_MODE_ANY, 0, src0 + 1, dst0 + 1, &saidx);

	/* get a SA index */
	LIST_FOREACH(sah, &sahtree, chain) {
		if (sah->state == SADB_SASTATE_DEAD)
			continue;
		if (key_cmpsaidx(&sah->saidx, &saidx, CMP_MODE | CMP_REQID))
			break;
	}
	if (sah != NULL) {
		lck_mtx_unlock(sadb_mutex);
		ipseclog((LOG_DEBUG, "key_acquire2: a SA exists already.\n"));
		return key_senderror(so, m, EEXIST);
	}
	lck_mtx_unlock(sadb_mutex);
	error = key_acquire(&saidx, NULL);
	if (error != 0) {
		ipseclog((LOG_DEBUG, "key_acquire2: error %d returned "
			"from key_acquire.\n", mhp->msg->sadb_msg_errno));
		return key_senderror(so, m, error);
	}

	return key_sendup_mbuf(so, m, KEY_SENDUP_REGISTERED);
}

/*
 * SADB_REGISTER processing.
 * If SATYPE_UNSPEC has been passed as satype, only return sadb_supported.
 * receive
 *   <base>
 * from the ikmpd, and register a socket to send PF_KEY messages,
 * and send
 *   <base, supported>
 * to KMD by PF_KEY.
 * If socket is detached, must free from regnode.
 *
 * m will always be freed.
 */
static int
key_register(so, m, mhp)
	struct socket *so;
	struct mbuf *m;
	const struct sadb_msghdr *mhp;
{
	struct secreg *reg, *newreg = 0;
	
	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_register: NULL pointer is passed.\n");

	/* check for invalid register message */
	if (mhp->msg->sadb_msg_satype >= sizeof(regtree)/sizeof(regtree[0]))
		return key_senderror(so, m, EINVAL);

	/* When SATYPE_UNSPEC is specified, only return sadb_supported. */
	if (mhp->msg->sadb_msg_satype == SADB_SATYPE_UNSPEC)
		goto setmsg;

	/* create regnode */
	KMALLOC_WAIT(newreg, struct secreg *, sizeof(*newreg));
        if (newreg == NULL) {
	  ipseclog((LOG_DEBUG, "key_register: No more memory.\n"));
	  return key_senderror(so, m, ENOBUFS);
        }
        bzero((caddr_t)newreg, sizeof(*newreg));

	lck_mtx_lock(sadb_mutex);
	/* check whether existing or not */
	LIST_FOREACH(reg, &regtree[mhp->msg->sadb_msg_satype], chain) {
		if (reg->so == so) {
			lck_mtx_unlock(sadb_mutex);
			ipseclog((LOG_DEBUG, "key_register: socket exists already.\n"));
			KFREE(newreg);
			return key_senderror(so, m, EEXIST);
		}
	}

	socket_lock(so, 1);
	newreg->so = so;
	((struct keycb *)sotorawcb(so))->kp_registered++;
	socket_unlock(so, 1);

	/* add regnode to regtree. */
	LIST_INSERT_HEAD(&regtree[mhp->msg->sadb_msg_satype], newreg, chain);
	lck_mtx_unlock(sadb_mutex);
  setmsg:
    {
	struct mbuf *n;
	struct sadb_msg *newmsg;
	struct sadb_supported *sup;
	u_int len, alen, elen;
	int off;
	int i;
	struct sadb_alg *alg;

	/* create new sadb_msg to reply. */
	alen = 0;
	for (i = 1; i <= SADB_AALG_MAX; i++) {
		if (ah_algorithm_lookup(i))
			alen += sizeof(struct sadb_alg);
	}
	if (alen)
		alen += sizeof(struct sadb_supported);
	elen = 0;
#if IPSEC_ESP
	for (i = 1; i <= SADB_EALG_MAX; i++) {
		if (esp_algorithm_lookup(i))
			elen += sizeof(struct sadb_alg);
	}
	if (elen)
		elen += sizeof(struct sadb_supported);
#endif

	len = sizeof(struct sadb_msg) + alen + elen;

	if (len > MCLBYTES)
		return key_senderror(so, m, ENOBUFS);

	MGETHDR(n, M_DONTWAIT, MT_DATA);
	if (len > MHLEN) {
		MCLGET(n, M_DONTWAIT);
		if ((n->m_flags & M_EXT) == 0) {
			m_freem(n);
			n = NULL;
		}
	}
	if (!n)
		return key_senderror(so, m, ENOBUFS);

	n->m_pkthdr.len = n->m_len = len;
	n->m_next = NULL;
	off = 0;

	m_copydata(m, 0, sizeof(struct sadb_msg), mtod(n, caddr_t) + off);
	newmsg = mtod(n, struct sadb_msg *);
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(len);
	off += PFKEY_ALIGN8(sizeof(struct sadb_msg));

	/* for authentication algorithm */
	if (alen) {
		sup = (struct sadb_supported *)(mtod(n, caddr_t) + off);
		sup->sadb_supported_len = PFKEY_UNIT64(alen);
		sup->sadb_supported_exttype = SADB_EXT_SUPPORTED_AUTH;
		off += PFKEY_ALIGN8(sizeof(*sup));

		for (i = 1; i <= SADB_AALG_MAX; i++) {
			const struct ah_algorithm *aalgo;

			aalgo = ah_algorithm_lookup(i);
			if (!aalgo)
				continue;
			alg = (struct sadb_alg *)(mtod(n, caddr_t) + off);
			alg->sadb_alg_id = i;
			alg->sadb_alg_ivlen = 0;
			alg->sadb_alg_minbits = aalgo->keymin;
			alg->sadb_alg_maxbits = aalgo->keymax;
			off += PFKEY_ALIGN8(sizeof(*alg));
		}
	}

#if IPSEC_ESP
	/* for encryption algorithm */
	if (elen) {
		sup = (struct sadb_supported *)(mtod(n, caddr_t) + off);
		sup->sadb_supported_len = PFKEY_UNIT64(elen);
		sup->sadb_supported_exttype = SADB_EXT_SUPPORTED_ENCRYPT;
		off += PFKEY_ALIGN8(sizeof(*sup));

		for (i = 1; i <= SADB_EALG_MAX; i++) {
			const struct esp_algorithm *ealgo;

			ealgo = esp_algorithm_lookup(i);
			if (!ealgo)
				continue;
			alg = (struct sadb_alg *)(mtod(n, caddr_t) + off);
			alg->sadb_alg_id = i;
			if (ealgo && ealgo->ivlen) {
				/*
				 * give NULL to get the value preferred by
				 * algorithm XXX SADB_X_EXT_DERIV ?
				 */
				alg->sadb_alg_ivlen =
				    (*ealgo->ivlen)(ealgo, NULL);
			} else
				alg->sadb_alg_ivlen = 0;
			alg->sadb_alg_minbits = ealgo->keymin;
			alg->sadb_alg_maxbits = ealgo->keymax;
			off += PFKEY_ALIGN8(sizeof(struct sadb_alg));
		}
	}
#endif

#if DIGAGNOSTIC
	if (off != len)
		panic("length assumption failed in key_register");
#endif

	m_freem(m);
	return key_sendup_mbuf(so, n, KEY_SENDUP_REGISTERED);
    }
}

/*
 * free secreg entry registered.
 * XXX: I want to do free a socket marked done SADB_RESIGER to socket.
 */
void
key_freereg(so)
	struct socket *so;
{
	struct secreg *reg;
	int i;
	
	/* sanity check */
	if (so == NULL)
		panic("key_freereg: NULL pointer is passed.\n");

	/*
	 * check whether existing or not.
	 * check all type of SA, because there is a potential that
	 * one socket is registered to multiple type of SA.
	 */
	lck_mtx_lock(sadb_mutex);
	for (i = 0; i <= SADB_SATYPE_MAX; i++) {
		LIST_FOREACH(reg, &regtree[i], chain) {
			if (reg->so == so
			 && __LIST_CHAINED(reg)) {
				LIST_REMOVE(reg, chain);
				KFREE(reg);
				break;
			}
		}
	}
	lck_mtx_unlock(sadb_mutex);
	return;
}

/*
 * SADB_EXPIRE processing
 * send
 *   <base, SA, SA2, lifetime(C and one of HS), address(SD)>
 * to KMD by PF_KEY.
 * NOTE: We send only soft lifetime extension.
 *
 * OUT:	0	: succeed
 *	others	: error number
 */
static int
key_expire(sav)
	struct secasvar *sav;
{
	int satype;
	struct mbuf *result = NULL, *m;
	int len;
	int error = -1;
	struct sadb_lifetime *lt;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	/* sanity check */
	if (sav == NULL)
		panic("key_expire: NULL pointer is passed.\n");
	if (sav->sah == NULL)
		panic("key_expire: Why was SA index in SA NULL.\n");
	if ((satype = key_proto2satype(sav->sah->saidx.proto)) == 0)
		panic("key_expire: invalid proto is passed.\n");

	/* set msg header */
	m = key_setsadbmsg(SADB_EXPIRE, 0, satype, sav->seq, 0, sav->refcnt);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	result = m;

	/* create SA extension */
	m = key_setsadbsa(sav);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	m_cat(result, m);

	/* create SA extension */
	m = key_setsadbxsa2(sav->sah->saidx.mode,
			sav->replay ? sav->replay->count : 0,
			sav->sah->saidx.reqid);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	m_cat(result, m);

	/* create lifetime extension (current and soft) */
	len = PFKEY_ALIGN8(sizeof(*lt)) * 2;
	m = key_alloc_mbuf(len);
	if (!m || m->m_next) {	/*XXX*/
		if (m)
			m_freem(m);
		error = ENOBUFS;
		goto fail;
	}
	bzero(mtod(m, caddr_t), len);
	lt = mtod(m, struct sadb_lifetime *);
	lt->sadb_lifetime_len = PFKEY_UNIT64(sizeof(struct sadb_lifetime));
	lt->sadb_lifetime_exttype = SADB_EXT_LIFETIME_CURRENT;
	lt->sadb_lifetime_allocations = sav->lft_c->sadb_lifetime_allocations;
	lt->sadb_lifetime_bytes = sav->lft_c->sadb_lifetime_bytes;
	lt->sadb_lifetime_addtime = sav->lft_c->sadb_lifetime_addtime;
	lt->sadb_lifetime_usetime = sav->lft_c->sadb_lifetime_usetime;
	lt = (struct sadb_lifetime *)(mtod(m, caddr_t) + len / 2);
	bcopy(sav->lft_s, lt, sizeof(*lt));
	m_cat(result, m);

	/* set sadb_address for source */
	m = key_setsadbaddr(SADB_EXT_ADDRESS_SRC,
	    (struct sockaddr *)&sav->sah->saidx.src,
	    FULLMASK, IPSEC_ULPROTO_ANY);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	m_cat(result, m);

	/* set sadb_address for destination */
	m = key_setsadbaddr(SADB_EXT_ADDRESS_DST,
	    (struct sockaddr *)&sav->sah->saidx.dst,
	    FULLMASK, IPSEC_ULPROTO_ANY);
	if (!m) {
		error = ENOBUFS;
		goto fail;
	}
	m_cat(result, m);

	if ((result->m_flags & M_PKTHDR) == 0) {
		error = EINVAL;
		goto fail;
	}

	if (result->m_len < sizeof(struct sadb_msg)) {
		result = m_pullup(result, sizeof(struct sadb_msg));
		if (result == NULL) {
			error = ENOBUFS;
			goto fail;
		}
	}

	result->m_pkthdr.len = 0;
	for (m = result; m; m = m->m_next)
		result->m_pkthdr.len += m->m_len;

	mtod(result, struct sadb_msg *)->sadb_msg_len =
	    PFKEY_UNIT64(result->m_pkthdr.len);

	return key_sendup_mbuf(NULL, result, KEY_SENDUP_REGISTERED);

 fail:
	if (result)
		m_freem(result);
	return error;
}

/*
 * SADB_FLUSH processing
 * receive
 *   <base>
 * from the ikmpd, and free all entries in secastree.
 * and send,
 *   <base>
 * to the ikmpd.
 * NOTE: to do is only marking SADB_SASTATE_DEAD.
 *
 * m will always be freed.
 */
static int
key_flush(so, m, mhp)
	struct socket *so;
	struct mbuf *m;
	const struct sadb_msghdr *mhp;
{
	struct sadb_msg *newmsg;
	struct secashead *sah, *nextsah;
	struct secasvar *sav, *nextsav;
	u_int16_t proto;
	u_int8_t state;
	u_int stateidx;
	
	/* sanity check */
	if (so == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_flush: NULL pointer is passed.\n");

	/* map satype to proto */
	if ((proto = key_satype2proto(mhp->msg->sadb_msg_satype)) == 0) {
		ipseclog((LOG_DEBUG, "key_flush: invalid satype is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	lck_mtx_lock(sadb_mutex);
	
	/* no SATYPE specified, i.e. flushing all SA. */
	for (sah = LIST_FIRST(&sahtree);
	     sah != NULL;
	     sah = nextsah) {
		nextsah = LIST_NEXT(sah, chain);

		if (mhp->msg->sadb_msg_satype != SADB_SATYPE_UNSPEC
		 && proto != sah->saidx.proto)
			continue;

		for (stateidx = 0;
		     stateidx < _ARRAYLEN(saorder_state_alive);
		     stateidx++) {
			state = saorder_state_any[stateidx];
			for (sav = LIST_FIRST(&sah->savtree[state]);
			     sav != NULL;
			     sav = nextsav) {

				nextsav = LIST_NEXT(sav, chain);

				key_sa_chgstate(sav, SADB_SASTATE_DEAD);
				key_freesav(sav, KEY_SADB_LOCKED);
			}
		}

		sah->state = SADB_SASTATE_DEAD;
	}
	lck_mtx_unlock(sadb_mutex);
	
	if (m->m_len < sizeof(struct sadb_msg) ||
	    sizeof(struct sadb_msg) > m->m_len + M_TRAILINGSPACE(m)) {
		ipseclog((LOG_DEBUG, "key_flush: No more memory.\n"));
		return key_senderror(so, m, ENOBUFS);
	}

	if (m->m_next)
		m_freem(m->m_next);
	m->m_next = NULL;
	m->m_pkthdr.len = m->m_len = sizeof(struct sadb_msg);
	newmsg = mtod(m, struct sadb_msg *);
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(m->m_pkthdr.len);

	return key_sendup_mbuf(so, m, KEY_SENDUP_ALL);
}

/*
 * SADB_DUMP processing
 * dump all entries including status of DEAD in SAD.
 * receive
 *   <base>
 * from the ikmpd, and dump all secasvar leaves
 * and send,
 *   <base> .....
 * to the ikmpd.
 *
 * m will always be freed.
 */
 
struct sav_dump_elem {
	struct secasvar *sav;
	u_int8_t satype;
};

static int
key_dump(so, m, mhp)
	struct socket *so;
	struct mbuf *m;
	const struct sadb_msghdr *mhp;
{
	struct secashead *sah;
	struct secasvar *sav;
	struct sav_dump_elem *savbuf = NULL, *elem_ptr;
	u_int16_t proto;
	u_int stateidx;
	u_int8_t satype;
	u_int8_t state;
	int cnt = 0, cnt2, bufcount;
	struct mbuf *n;
	int error = 0;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_dump: NULL pointer is passed.\n");

	/* map satype to proto */
	if ((proto = key_satype2proto(mhp->msg->sadb_msg_satype)) == 0) {
		ipseclog((LOG_DEBUG, "key_dump: invalid satype is passed.\n"));
		return key_senderror(so, m, EINVAL);
	}

	if ((bufcount = ipsec_sav_count) <= 0) {
		error = ENOENT;
		goto end;
	}
	bufcount += 512;	/* extra */
	KMALLOC_WAIT(savbuf, struct sav_dump_elem*, bufcount * sizeof(struct sav_dump_elem));
	if (savbuf == NULL) {
		ipseclog((LOG_DEBUG, "key_dump: No more memory.\n"));
		error = ENOMEM;
		goto end;
	}

	/* count sav entries to be sent to the userland. */
	lck_mtx_lock(sadb_mutex);
	elem_ptr = savbuf;
	LIST_FOREACH(sah, &sahtree, chain) {
		if (mhp->msg->sadb_msg_satype != SADB_SATYPE_UNSPEC
		 && proto != sah->saidx.proto)
			continue;
		
		/* map proto to satype */
		if ((satype = key_proto2satype(sah->saidx.proto)) == 0) {
			lck_mtx_unlock(sadb_mutex);
			ipseclog((LOG_DEBUG, "key_dump: there was invalid proto in SAD.\n"));
			error = EINVAL;
			goto end;
		}

		for (stateidx = 0;
		     stateidx < _ARRAYLEN(saorder_state_any);
		     stateidx++) {
			state = saorder_state_any[stateidx];
			LIST_FOREACH(sav, &sah->savtree[state], chain) {
				if (cnt == bufcount)
					break;		/* out of buffer space */
				elem_ptr->sav = sav;
				elem_ptr->satype = satype;
				sav->refcnt++;
				elem_ptr++;
				cnt++;				
			}
		}
	}
	lck_mtx_unlock(sadb_mutex);

	if (cnt == 0) {
		error = ENOENT;
		goto end;
	}

	/* send this to the userland, one at a time. */
	elem_ptr = savbuf;
	cnt2 = cnt;
	while (cnt2) {
		n = key_setdumpsa(elem_ptr->sav, SADB_DUMP, elem_ptr->satype,
			--cnt2, mhp->msg->sadb_msg_pid);
		
		if (!n) {
			error = ENOBUFS;
			goto end;
		}

		key_sendup_mbuf(so, n, KEY_SENDUP_ONE);
		elem_ptr++;
	}

end:
	if (savbuf) {
		if (cnt) {
			elem_ptr = savbuf;
			lck_mtx_lock(sadb_mutex);
			while (cnt--)
				key_freesav((elem_ptr++)->sav, KEY_SADB_LOCKED);
			lck_mtx_unlock(sadb_mutex);
		}
		KFREE(savbuf);
	}

	if (error)
		return key_senderror(so, m, error);

	m_freem(m);
	return 0;
}

/*
 * SADB_X_PROMISC processing
 *
 * m will always be freed.
 */
static int
key_promisc(so, m, mhp)
	struct socket *so;
	struct mbuf *m;
	const struct sadb_msghdr *mhp;
{
	int olen;
	
	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
		panic("key_promisc: NULL pointer is passed.\n");

	olen = PFKEY_UNUNIT64(mhp->msg->sadb_msg_len);

	if (olen < sizeof(struct sadb_msg)) {
#if 1
		return key_senderror(so, m, EINVAL);
#else
		m_freem(m);
		return 0;
#endif
	} else if (olen == sizeof(struct sadb_msg)) {
		/* enable/disable promisc mode */
		struct keycb *kp;
		
		socket_lock(so, 1);
		if ((kp = (struct keycb *)sotorawcb(so)) == NULL)
			return key_senderror(so, m, EINVAL);
		mhp->msg->sadb_msg_errno = 0;
		switch (mhp->msg->sadb_msg_satype) {
		case 0:
		case 1:
			kp->kp_promisc = mhp->msg->sadb_msg_satype;
			break;
		default:
			socket_unlock(so, 1);
			return key_senderror(so, m, EINVAL);
		}
		socket_unlock(so, 1);

		/* send the original message back to everyone */
		mhp->msg->sadb_msg_errno = 0;
		return key_sendup_mbuf(so, m, KEY_SENDUP_ALL);
	} else {
		/* send packet as is */

		m_adj(m, PFKEY_ALIGN8(sizeof(struct sadb_msg)));

		/* TODO: if sadb_msg_seq is specified, send to specific pid */
		return key_sendup_mbuf(so, m, KEY_SENDUP_ALL);
	}
}

static int (*key_typesw[])(struct socket *, struct mbuf *,
		const struct sadb_msghdr *) = {
	NULL,		/* SADB_RESERVED */
	key_getspi,	/* SADB_GETSPI */
	key_update,	/* SADB_UPDATE */
	key_add,	/* SADB_ADD */
	key_delete,	/* SADB_DELETE */
	key_get,	/* SADB_GET */
	key_acquire2,	/* SADB_ACQUIRE */
	key_register,	/* SADB_REGISTER */
	NULL,		/* SADB_EXPIRE */
	key_flush,	/* SADB_FLUSH */
	key_dump,	/* SADB_DUMP */
	key_promisc,	/* SADB_X_PROMISC */
	NULL,		/* SADB_X_PCHANGE */
	key_spdadd,	/* SADB_X_SPDUPDATE */
	key_spdadd,	/* SADB_X_SPDADD */
	key_spddelete,	/* SADB_X_SPDDELETE */
	key_spdget,	/* SADB_X_SPDGET */
	NULL,		/* SADB_X_SPDACQUIRE */
	key_spddump,	/* SADB_X_SPDDUMP */
	key_spdflush,	/* SADB_X_SPDFLUSH */
	key_spdadd,	/* SADB_X_SPDSETIDX */
	NULL,		/* SADB_X_SPDEXPIRE */
	key_spddelete2,	/* SADB_X_SPDDELETE2 */
	key_getsastat,   /* SADB_GETSASTAT */
};

/*
 * parse sadb_msg buffer to process PFKEYv2,
 * and create a data to response if needed.
 * I think to be dealed with mbuf directly.
 * IN:
 *     msgp  : pointer to pointer to a received buffer pulluped.
 *             This is rewrited to response.
 *     so    : pointer to socket.
 * OUT:
 *    length for buffer to send to user process.
 */
int
key_parse(m, so)
	struct mbuf *m;
	struct socket *so;
{
	struct sadb_msg *msg;
	struct sadb_msghdr mh;
	u_int orglen;
	int error;
	int target;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	/* sanity check */
	if (m == NULL || so == NULL)
		panic("key_parse: NULL pointer is passed.\n");

#if 0	/*kdebug_sadb assumes msg in linear buffer*/
	KEYDEBUG(KEYDEBUG_KEY_DUMP,
		ipseclog((LOG_DEBUG, "key_parse: passed sadb_msg\n"));
		kdebug_sadb(msg));
#endif

	if (m->m_len < sizeof(struct sadb_msg)) {
		m = m_pullup(m, sizeof(struct sadb_msg));
		if (!m)
			return ENOBUFS;
	}
	msg = mtod(m, struct sadb_msg *);
	orglen = PFKEY_UNUNIT64(msg->sadb_msg_len);
	target = KEY_SENDUP_ONE;

	if ((m->m_flags & M_PKTHDR) == 0 ||
	    m->m_pkthdr.len != m->m_pkthdr.len) {
		ipseclog((LOG_DEBUG, "key_parse: invalid message length.\n"));
		PFKEY_STAT_INCREMENT(pfkeystat.out_invlen);
		error = EINVAL;
		goto senderror;
	}

	if (msg->sadb_msg_version != PF_KEY_V2) {
		ipseclog((LOG_DEBUG,
		    "key_parse: PF_KEY version %u is mismatched.\n",
		    msg->sadb_msg_version));
		PFKEY_STAT_INCREMENT(pfkeystat.out_invver);
		error = EINVAL;
		goto senderror;
	}

	if (msg->sadb_msg_type > SADB_MAX) {
		ipseclog((LOG_DEBUG, "key_parse: invalid type %u is passed.\n",
		    msg->sadb_msg_type));
		PFKEY_STAT_INCREMENT(pfkeystat.out_invmsgtype);
		error = EINVAL;
		goto senderror;
	}

	/* for old-fashioned code - should be nuked */
	if (m->m_pkthdr.len > MCLBYTES) {
		m_freem(m);
		return ENOBUFS;
	}
	if (m->m_next) {
		struct mbuf *n;

		MGETHDR(n, M_DONTWAIT, MT_DATA);
		if (n && m->m_pkthdr.len > MHLEN) {
			MCLGET(n, M_DONTWAIT);
			if ((n->m_flags & M_EXT) == 0) {
				m_free(n);
				n = NULL;
			}
		}
		if (!n) {
			m_freem(m);
			return ENOBUFS;
		}
		m_copydata(m, 0, m->m_pkthdr.len, mtod(n, caddr_t));
		n->m_pkthdr.len = n->m_len = m->m_pkthdr.len;
		n->m_next = NULL;
		m_freem(m);
		m = n;
	}

	/* align the mbuf chain so that extensions are in contiguous region. */
	error = key_align(m, &mh);
	if (error)
		return error;

	if (m->m_next) {	/*XXX*/
		m_freem(m);
		return ENOBUFS;
	}

	msg = mh.msg;

	/* check SA type */
	switch (msg->sadb_msg_satype) {
	case SADB_SATYPE_UNSPEC:
		switch (msg->sadb_msg_type) {
		case SADB_GETSPI:
		case SADB_UPDATE:
		case SADB_ADD:
		case SADB_DELETE:
		case SADB_GET:
		case SADB_ACQUIRE:
		case SADB_EXPIRE:
			ipseclog((LOG_DEBUG, "key_parse: must specify satype "
			    "when msg type=%u.\n", msg->sadb_msg_type));
			PFKEY_STAT_INCREMENT(pfkeystat.out_invsatype);
			error = EINVAL;
			goto senderror;
		}
		break;
	case SADB_SATYPE_AH:
	case SADB_SATYPE_ESP:
	case SADB_X_SATYPE_IPCOMP:
		switch (msg->sadb_msg_type) {
		case SADB_X_SPDADD:
		case SADB_X_SPDDELETE:
		case SADB_X_SPDGET:
		case SADB_X_SPDDUMP:
		case SADB_X_SPDFLUSH:
		case SADB_X_SPDSETIDX:
		case SADB_X_SPDUPDATE:
		case SADB_X_SPDDELETE2:
			ipseclog((LOG_DEBUG, "key_parse: illegal satype=%u\n",
			    msg->sadb_msg_type));
			PFKEY_STAT_INCREMENT(pfkeystat.out_invsatype);
			error = EINVAL;
			goto senderror;
		}
		break;
	case SADB_SATYPE_RSVP:
	case SADB_SATYPE_OSPFV2:
	case SADB_SATYPE_RIPV2:
	case SADB_SATYPE_MIP:
		ipseclog((LOG_DEBUG, "key_parse: type %u isn't supported.\n",
		    msg->sadb_msg_satype));
		PFKEY_STAT_INCREMENT(pfkeystat.out_invsatype);
		error = EOPNOTSUPP;
		goto senderror;
	case 1:	/* XXX: What does it do? */
		if (msg->sadb_msg_type == SADB_X_PROMISC)
			break;
		/*FALLTHROUGH*/
	default:
		ipseclog((LOG_DEBUG, "key_parse: invalid type %u is passed.\n",
		    msg->sadb_msg_satype));
		PFKEY_STAT_INCREMENT(pfkeystat.out_invsatype);
		error = EINVAL;
		goto senderror;
	}

	/* check field of upper layer protocol and address family */
	if (mh.ext[SADB_EXT_ADDRESS_SRC] != NULL
	 && mh.ext[SADB_EXT_ADDRESS_DST] != NULL) {
		struct sadb_address *src0, *dst0;
		u_int plen;

		src0 = (struct sadb_address *)(mh.ext[SADB_EXT_ADDRESS_SRC]);
		dst0 = (struct sadb_address *)(mh.ext[SADB_EXT_ADDRESS_DST]);

		/* check upper layer protocol */
		if (src0->sadb_address_proto != dst0->sadb_address_proto) {
			ipseclog((LOG_DEBUG, "key_parse: upper layer protocol mismatched.\n"));
			PFKEY_STAT_INCREMENT(pfkeystat.out_invaddr);
			error = EINVAL;
			goto senderror;
		}

		/* check family */
		if (PFKEY_ADDR_SADDR(src0)->sa_family !=
		    PFKEY_ADDR_SADDR(dst0)->sa_family) {
			ipseclog((LOG_DEBUG, "key_parse: address family mismatched.\n"));
			PFKEY_STAT_INCREMENT(pfkeystat.out_invaddr);
			error = EINVAL;
			goto senderror;
		}
		if (PFKEY_ADDR_SADDR(src0)->sa_len !=
		    PFKEY_ADDR_SADDR(dst0)->sa_len) {
			ipseclog((LOG_DEBUG,
			    "key_parse: address struct size mismatched.\n"));
			PFKEY_STAT_INCREMENT(pfkeystat.out_invaddr);
			error = EINVAL;
			goto senderror;
		}

		switch (PFKEY_ADDR_SADDR(src0)->sa_family) {
		case AF_INET:
			if (PFKEY_ADDR_SADDR(src0)->sa_len !=
			    sizeof(struct sockaddr_in)) {
				PFKEY_STAT_INCREMENT(pfkeystat.out_invaddr);
				error = EINVAL;
				goto senderror;
			}
			break;
		case AF_INET6:
			if (PFKEY_ADDR_SADDR(src0)->sa_len !=
			    sizeof(struct sockaddr_in6)) {
				PFKEY_STAT_INCREMENT(pfkeystat.out_invaddr);
				error = EINVAL;
				goto senderror;
			}
			break;
		default:
			ipseclog((LOG_DEBUG,
			    "key_parse: unsupported address family.\n"));
			PFKEY_STAT_INCREMENT(pfkeystat.out_invaddr);
			error = EAFNOSUPPORT;
			goto senderror;
		}

		switch (PFKEY_ADDR_SADDR(src0)->sa_family) {
		case AF_INET:
			plen = sizeof(struct in_addr) << 3;
			break;
		case AF_INET6:
			plen = sizeof(struct in6_addr) << 3;
			break;
		default:
			plen = 0;	/*fool gcc*/
			break;
		}

		/* check max prefix length */
		if (src0->sadb_address_prefixlen > plen ||
		    dst0->sadb_address_prefixlen > plen) {
			ipseclog((LOG_DEBUG,
			    "key_parse: illegal prefixlen.\n"));
			PFKEY_STAT_INCREMENT(pfkeystat.out_invaddr);
			error = EINVAL;
			goto senderror;
		}

		/*
		 * prefixlen == 0 is valid because there can be a case when
		 * all addresses are matched.
		 */
	}

	if (msg->sadb_msg_type >= sizeof(key_typesw)/sizeof(key_typesw[0]) ||
	    key_typesw[msg->sadb_msg_type] == NULL) {
		PFKEY_STAT_INCREMENT(pfkeystat.out_invmsgtype);
		error = EINVAL;
		goto senderror;
	}

	return (*key_typesw[msg->sadb_msg_type])(so, m, &mh);

senderror:
	msg->sadb_msg_errno = error;
	return key_sendup_mbuf(so, m, target);
}

static int
key_senderror(so, m, code)
	struct socket *so;
	struct mbuf *m;
	int code;
{
	struct sadb_msg *msg;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);
	
	if (m->m_len < sizeof(struct sadb_msg))
		panic("invalid mbuf passed to key_senderror");

	msg = mtod(m, struct sadb_msg *);
	msg->sadb_msg_errno = code;
	return key_sendup_mbuf(so, m, KEY_SENDUP_ONE);
}

/*
 * set the pointer to each header into message buffer.
 * m will be freed on error.
 * XXX larger-than-MCLBYTES extension?
 */
static int
key_align(m, mhp)
	struct mbuf *m;
	struct sadb_msghdr *mhp;
{
	struct mbuf *n;
	struct sadb_ext *ext;
	size_t off, end;
	int extlen;
	int toff;

	/* sanity check */
	if (m == NULL || mhp == NULL)
		panic("key_align: NULL pointer is passed.\n");
	if (m->m_len < sizeof(struct sadb_msg))
		panic("invalid mbuf passed to key_align");

	/* initialize */
	bzero(mhp, sizeof(*mhp));

	mhp->msg = mtod(m, struct sadb_msg *);
	mhp->ext[0] = (struct sadb_ext *)mhp->msg;	/*XXX backward compat */

	end = PFKEY_UNUNIT64(mhp->msg->sadb_msg_len);
	extlen = end;	/*just in case extlen is not updated*/
	for (off = sizeof(struct sadb_msg); off < end; off += extlen) {
		n = m_pulldown(m, off, sizeof(struct sadb_ext), &toff);
		if (!n) {
			/* m is already freed */
			return ENOBUFS;
		}
		ext = (struct sadb_ext *)(mtod(n, caddr_t) + toff);

		/* set pointer */
		switch (ext->sadb_ext_type) {
		case SADB_EXT_SA:
		case SADB_EXT_ADDRESS_SRC:
		case SADB_EXT_ADDRESS_DST:
		case SADB_EXT_ADDRESS_PROXY:
		case SADB_EXT_LIFETIME_CURRENT:
		case SADB_EXT_LIFETIME_HARD:
		case SADB_EXT_LIFETIME_SOFT:
		case SADB_EXT_KEY_AUTH:
		case SADB_EXT_KEY_ENCRYPT:
		case SADB_EXT_IDENTITY_SRC:
		case SADB_EXT_IDENTITY_DST:
		case SADB_EXT_SENSITIVITY:
		case SADB_EXT_PROPOSAL:
		case SADB_EXT_SUPPORTED_AUTH:
		case SADB_EXT_SUPPORTED_ENCRYPT:
		case SADB_EXT_SPIRANGE:
		case SADB_X_EXT_POLICY:
		case SADB_X_EXT_SA2:
		case SADB_EXT_SESSION_ID:
		case SADB_EXT_SASTAT:
			/* duplicate check */
			/*
			 * XXX Are there duplication payloads of either
			 * KEY_AUTH or KEY_ENCRYPT ?
			 */
			if (mhp->ext[ext->sadb_ext_type] != NULL) {
				ipseclog((LOG_DEBUG,
				    "key_align: duplicate ext_type %u "
				    "is passed.\n", ext->sadb_ext_type));
				m_freem(m);
				PFKEY_STAT_INCREMENT(pfkeystat.out_dupext);
				return EINVAL;
			}
			break;
		default:
			ipseclog((LOG_DEBUG,
			    "key_align: invalid ext_type %u is passed.\n",
			    ext->sadb_ext_type));
			m_freem(m);
			PFKEY_STAT_INCREMENT(pfkeystat.out_invexttype);
			return EINVAL;
		}

		extlen = PFKEY_UNUNIT64(ext->sadb_ext_len);

		if (key_validate_ext(ext, extlen)) {
			m_freem(m);
			PFKEY_STAT_INCREMENT(pfkeystat.out_invlen);
			return EINVAL;
		}

		n = m_pulldown(m, off, extlen, &toff);
		if (!n) {
			/* m is already freed */
			return ENOBUFS;
		}
		ext = (struct sadb_ext *)(mtod(n, caddr_t) + toff);

		mhp->ext[ext->sadb_ext_type] = ext;
		mhp->extoff[ext->sadb_ext_type] = off;
		mhp->extlen[ext->sadb_ext_type] = extlen;
	}

	if (off != end) {
		m_freem(m);
		PFKEY_STAT_INCREMENT(pfkeystat.out_invlen);
		return EINVAL;
	}

	return 0;
}

static int
key_validate_ext(ext, len)
	const struct sadb_ext *ext;
	int len;
{
	struct sockaddr *sa;
	enum { NONE, ADDR } checktype = NONE;
	int baselen;
	const int sal = offsetof(struct sockaddr, sa_len) + sizeof(sa->sa_len);

	if (len != PFKEY_UNUNIT64(ext->sadb_ext_len))
		return EINVAL;

	/* if it does not match minimum/maximum length, bail */
	if (ext->sadb_ext_type >= sizeof(minsize) / sizeof(minsize[0]) ||
	    ext->sadb_ext_type >= sizeof(maxsize) / sizeof(maxsize[0]))
		return EINVAL;
	if (!minsize[ext->sadb_ext_type] || len < minsize[ext->sadb_ext_type])
		return EINVAL;
	if (maxsize[ext->sadb_ext_type] && len > maxsize[ext->sadb_ext_type])
		return EINVAL;

	/* more checks based on sadb_ext_type XXX need more */
	switch (ext->sadb_ext_type) {
	case SADB_EXT_ADDRESS_SRC:
	case SADB_EXT_ADDRESS_DST:
	case SADB_EXT_ADDRESS_PROXY:
		baselen = PFKEY_ALIGN8(sizeof(struct sadb_address));
		checktype = ADDR;
		break;
	case SADB_EXT_IDENTITY_SRC:
	case SADB_EXT_IDENTITY_DST:
		if (((const struct sadb_ident *)ext)->sadb_ident_type ==
		    SADB_X_IDENTTYPE_ADDR) {
			baselen = PFKEY_ALIGN8(sizeof(struct sadb_ident));
			checktype = ADDR;
		} else
			checktype = NONE;
		break;
	default:
		checktype = NONE;
		break;
	}

	switch (checktype) {
	case NONE:
		break;
	case ADDR:
		sa = (struct sockaddr *)((caddr_t)(uintptr_t)ext + baselen);		
		
		if (len < baselen + sal)
			return EINVAL;
		if (baselen + PFKEY_ALIGN8(sa->sa_len) != len)
			return EINVAL;
		break;
	}

	return 0;
}

void
key_domain_init()
{
	int i;

	bzero((caddr_t)&key_cb, sizeof(key_cb));
	
	for (i = 0; i < IPSEC_DIR_MAX; i++) {
		LIST_INIT(&sptree[i]);
	}
	ipsec_policy_count = 0;

	LIST_INIT(&sahtree);

	for (i = 0; i <= SADB_SATYPE_MAX; i++) {
		LIST_INIT(&regtree[i]);
	}
	ipsec_sav_count = 0;

#ifndef IPSEC_NONBLOCK_ACQUIRE
	LIST_INIT(&acqtree);
#endif
	LIST_INIT(&spacqtree);

	/* system default */
#if INET
	ip4_def_policy.policy = IPSEC_POLICY_NONE;
	ip4_def_policy.refcnt++;	/*never reclaim this*/
#endif
#if INET6
	ip6_def_policy.policy = IPSEC_POLICY_NONE;
	ip6_def_policy.refcnt++;	/*never reclaim this*/
#endif

#ifndef IPSEC_DEBUG2
	timeout((void *)key_timehandler, (void *)0, hz);
#endif /*IPSEC_DEBUG2*/

	/* initialize key statistics */
	keystat.getspi_count = 1;

#ifndef __APPLE__
	printf("IPsec: Initialized Security Association Processing.\n");
#endif

	return;
}

/*
 * XXX: maybe This function is called after INBOUND IPsec processing.
 *
 * Special check for tunnel-mode packets.
 * We must make some checks for consistency between inner and outer IP header.
 *
 * xxx more checks to be provided
 */
int
key_checktunnelsanity(
	struct secasvar *sav,
	__unused u_int family,
	__unused caddr_t src,
	__unused caddr_t dst)
{

	/* sanity check */
	if (sav->sah == NULL)
		panic("sav->sah == NULL at key_checktunnelsanity");

	/* XXX: check inner IP header */

	return 1;
}

/* record data transfer on SA, and update timestamps */
void
key_sa_recordxfer(sav, m)
	struct secasvar *sav;
	struct mbuf *m;
{

	
	if (!sav)
		panic("key_sa_recordxfer called with sav == NULL");
	if (!m)
		panic("key_sa_recordxfer called with m == NULL");
	if (!sav->lft_c)
		return;

	lck_mtx_lock(sadb_mutex);
	/*
	 * XXX Currently, there is a difference of bytes size
	 * between inbound and outbound processing.
	 */
	sav->lft_c->sadb_lifetime_bytes += m->m_pkthdr.len;
	/* to check bytes lifetime is done in key_timehandler(). */

	/*
	 * We use the number of packets as the unit of
	 * sadb_lifetime_allocations.  We increment the variable
	 * whenever {esp,ah}_{in,out}put is called.
	 */
	sav->lft_c->sadb_lifetime_allocations++;
	/* XXX check for expires? */

	/*
	 * NOTE: We record CURRENT sadb_lifetime_usetime by using wall clock,
	 * in seconds.  HARD and SOFT lifetime are measured by the time
	 * difference (again in seconds) from sadb_lifetime_usetime.
	 *
	 *	usetime
	 *	v     expire   expire
	 * -----+-----+--------+---> t
	 *	<--------------> HARD
	 *	<-----> SOFT
	 */
    {
	struct timeval tv;
	microtime(&tv);
	sav->lft_c->sadb_lifetime_usetime = tv.tv_sec;
	/* XXX check for expires? */
    }
	lck_mtx_unlock(sadb_mutex);
	
	return;
}

/* dumb version */
void
key_sa_routechange(dst)
	struct sockaddr *dst;
{
	struct secashead *sah;
	struct route *ro;
	
	lck_mtx_lock(sadb_mutex);
	LIST_FOREACH(sah, &sahtree, chain) {
		ro = &sah->sa_route;
		if (ro->ro_rt && dst->sa_len == ro->ro_dst.sa_len
		 && bcmp(dst, &ro->ro_dst, dst->sa_len) == 0) {
			rtfree(ro->ro_rt);
			ro->ro_rt = (struct rtentry *)NULL;
		}
	}
	lck_mtx_unlock(sadb_mutex);

	return;
}

static void
key_sa_chgstate(sav, state)
	struct secasvar *sav;
	u_int8_t state;
{

	if (sav == NULL)
		panic("key_sa_chgstate called with sav == NULL");

	if (sav->state == state)
		return;

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_OWNED);
		
	if (__LIST_CHAINED(sav))
		LIST_REMOVE(sav, chain);

	sav->state = state;
	LIST_INSERT_HEAD(&sav->sah->savtree[state], sav, chain);
	
}

void
key_sa_stir_iv(sav)
	struct secasvar *sav;
{
	lck_mtx_lock(sadb_mutex);
	if (!sav->iv)
		panic("key_sa_stir_iv called with sav == NULL");
	key_randomfill(sav->iv, sav->ivlen);
	lck_mtx_unlock(sadb_mutex);
}

/* XXX too much? */
static struct mbuf *
key_alloc_mbuf(l)
	int l;
{
	struct mbuf *m = NULL, *n;
	int len, t;

	len = l;
	while (len > 0) {
		MGET(n, M_DONTWAIT, MT_DATA);
		if (n && len > MLEN)
			MCLGET(n, M_DONTWAIT);
		if (!n) {
			m_freem(m);
			return NULL;
		}

		n->m_next = NULL;
		n->m_len = 0;
		n->m_len = M_TRAILINGSPACE(n);
		/* use the bottom of mbuf, hoping we can prepend afterwards */
		if (n->m_len > len) {
			t = (n->m_len - len) & ~(sizeof(long) - 1);
			n->m_data += t;
			n->m_len = len;
		}

		len -= n->m_len;

		if (m)
			m_cat(m, n);
		else
			m = n;
	}

	return m;
}

static struct mbuf *
key_setdumpsastats (u_int32_t      dir,
		    struct sastat *stats,
		    u_int32_t      max_stats,
		    u_int64_t      session_ids[],
		    u_int32_t      seq,
		    u_int32_t      pid)
{
        struct mbuf *result = NULL, *m = NULL;

        m = key_setsadbmsg(SADB_GETSASTAT, 0, 0, seq, pid, 0);
        if (!m) {
	        goto fail;
	}
        result = m;

	m = key_setsadbsession_id(session_ids);
	if (!m) {
	        goto fail;
	}
        m_cat(result, m);

	m = key_setsadbsastat(dir,
			      stats,
			      max_stats);
	if (!m) {
	        goto fail;
	}
        m_cat(result, m);

        if ((result->m_flags & M_PKTHDR) == 0) {
		goto fail;
        }

        if (result->m_len < sizeof(struct sadb_msg)) {
	        result = m_pullup(result, sizeof(struct sadb_msg));
		if (result == NULL) {
			goto fail;
		}
        }

        result->m_pkthdr.len = 0;
        for (m = result; m; m = m->m_next) {
	        result->m_pkthdr.len += m->m_len;
	}

        mtod(result, struct sadb_msg *)->sadb_msg_len =
	  PFKEY_UNIT64(result->m_pkthdr.len);

        return result;

 fail:
	if (result) {
	        m_freem(result);
	}
        return NULL;
}

/*
 * SADB_GETSASTAT processing
 * dump all stats for matching entries in SAD.
 *
 * m will always be freed.
 */
 
static int
key_getsastat (struct socket *so,
	       struct mbuf *m,
	       const struct sadb_msghdr *mhp)
{
	struct sadb_session_id *session_id;
	u_int32_t               bufsize, arg_count, res_count;
	struct sadb_sastat     *sa_stats_arg;
	struct sastat          *sa_stats_sav = NULL;
	struct mbuf            *n;
	int                     error = 0;

	/* sanity check */
	if (so == NULL || m == NULL || mhp == NULL || mhp->msg == NULL)
	        panic("%s: NULL pointer is passed.\n", __FUNCTION__);

        if (mhp->ext[SADB_EXT_SESSION_ID] == NULL) {
	        printf("%s: invalid message is passed. missing session-id.\n", __FUNCTION__);
		return key_senderror(so, m, EINVAL);
        }
	if (mhp->extlen[SADB_EXT_SESSION_ID] < sizeof(struct sadb_session_id)) {
	        printf("%s: invalid message is passed. short session-id.\n", __FUNCTION__);
		return key_senderror(so, m, EINVAL);
        }
	if (mhp->ext[SADB_EXT_SASTAT] == NULL) {
	        printf("%s: invalid message is passed. missing stat args.\n", __FUNCTION__);
		return key_senderror(so, m, EINVAL);
        }
        if (mhp->extlen[SADB_EXT_SASTAT] < sizeof(*sa_stats_arg)) {
	        printf("%s: invalid message is passed. short stat args.\n", __FUNCTION__);
		return key_senderror(so, m, EINVAL);
        }

	lck_mtx_assert(sadb_mutex, LCK_MTX_ASSERT_NOTOWNED);

	// exit early if there are no active SAs
	if (ipsec_sav_count <= 0) {
	        printf("%s: No active SAs.\n", __FUNCTION__);
		error = ENOENT;
		goto end;
	}
	bufsize = (ipsec_sav_count + 1) * sizeof(*sa_stats_sav);

	KMALLOC_WAIT(sa_stats_sav, __typeof__(sa_stats_sav), bufsize);
	if (sa_stats_sav == NULL) {
	        printf("%s: No more memory.\n", __FUNCTION__);
		error = ENOMEM;
		goto end;
	}
	bzero(sa_stats_sav, bufsize);

       sa_stats_arg = (__typeof__(sa_stats_arg))mhp->ext[SADB_EXT_SASTAT];
	arg_count = sa_stats_arg->sadb_sastat_list_len;
	// exit early if there are no requested SAs
	if (arg_count == 0) {
	        printf("%s: No SAs requested.\n", __FUNCTION__);
		error = ENOENT;
		goto end;
	}
	res_count = 0;

	if (key_getsastatbyspi((struct sastat *)(sa_stats_arg + 1),
			       arg_count,
			       sa_stats_sav,
			       &res_count)) {
	        printf("%s: Error finding SAs.\n", __FUNCTION__);
		error = ENOENT;
		goto end;
	}
	if (!res_count) {
	        printf("%s: No SAs found.\n", __FUNCTION__);
		error = ENOENT;
		goto end;
	}

	session_id = (__typeof__(session_id))mhp->ext[SADB_EXT_SESSION_ID];

	/* send this to the userland. */
	n = key_setdumpsastats(sa_stats_arg->sadb_sastat_dir,
			       sa_stats_sav,
			       res_count,
			       session_id->sadb_session_id_v,
			       mhp->msg->sadb_msg_seq,
			       mhp->msg->sadb_msg_pid);
        if (!n) {
	        printf("%s: No bufs to dump stats.\n", __FUNCTION__);
		error = ENOBUFS;
		goto end;
	}

       key_sendup_mbuf(so, n, KEY_SENDUP_ALL);
end:
	if (sa_stats_sav) {
		KFREE(sa_stats_sav);
	}

	if (error)
		return key_senderror(so, m, error);

	m_freem(m);
	return 0;
}

static void
key_update_natt_keepalive_timestamp (struct secasvar *sav_sent,
				     struct secasvar *sav_update)
{
	struct secasindex saidx_swap_sent_addr;

	// exit early if two SAs are identical, or if sav_update is current
	if (sav_sent == sav_update ||
	    sav_update->natt_last_activity == natt_now) {
		return;
	}

	// assuming that (sav_update->remote_ike_port != 0 && (esp_udp_encap_port & 0xFFFF) != 0)

	bzero(&saidx_swap_sent_addr, sizeof(saidx_swap_sent_addr));
	memcpy(&saidx_swap_sent_addr.src, &sav_sent->sah->saidx.dst, sizeof(saidx_swap_sent_addr.src));
	memcpy(&saidx_swap_sent_addr.dst, &sav_sent->sah->saidx.src, sizeof(saidx_swap_sent_addr.dst));
	saidx_swap_sent_addr.proto = sav_sent->sah->saidx.proto;
	saidx_swap_sent_addr.mode = sav_sent->sah->saidx.mode;
	// we ignore reqid for split-tunnel setups

	if (key_cmpsaidx(&sav_sent->sah->saidx, &sav_update->sah->saidx, CMP_MODE | CMP_PORT) ||
	    key_cmpsaidx(&saidx_swap_sent_addr, &sav_update->sah->saidx, CMP_MODE | CMP_PORT)) {
		sav_update->natt_last_activity = natt_now;
	}
}
