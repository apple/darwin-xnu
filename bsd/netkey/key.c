/*	$KAME: key.c,v 1.76 2000/03/27 05:11:04 sumikawa Exp $	*/

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

#if (defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined(__NetBSD__)
#include "opt_inet.h"
#ifdef __NetBSD__
#include "opt_ipsec.h"
#endif
#endif

/* this is for backward compatibility. we should not touch those. */
#define ss_len		__ss_len
#define ss_family	__ss_family

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
#if defined(__FreeBSD__) || defined (__APPLE__)
#include <sys/sysctl.h>
#endif
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/queue.h>

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
#if !(defined(__bsdi__) && _BSDI_VERSION >= 199802)
#include <netinet6/in6_pcb.h>
#endif
#endif /* INET6 */

#include <net/pfkeyv2.h>
#include <netkey/keydb.h>
#include <netkey/key.h>
#include <netkey/keysock.h>
#include <netkey/key_debug.h>

#include <netinet6/ipsec.h>
#include <netinet6/ah.h>
#if IPSEC_ESP
#include <netinet6/esp.h>
#endif
#include <netinet6/ipcomp.h>

#include <net/net_osdep.h>

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

static u_int32_t acq_seq = 0;
static int key_tick_init_random = 0;

static LIST_HEAD(_sptree, secpolicy) sptree[IPSEC_DIR_MAX];	/* SPD */
static LIST_HEAD(_sahtree, secashead) sahtree;			/* SAD */
static LIST_HEAD(_regtree, secreg) regtree[SADB_SATYPE_MAX + 1];
							/* registed list */
#ifndef IPSEC_NONBLOCK_ACQUIRE
static LIST_HEAD(_acqtree, secacq) acqtree;		/* acquiring list */
#endif
static LIST_HEAD(_spacqtree, secspacq) spacqtree;	/* SP acquiring list */

struct key_cb key_cb;

/* search order for SAs */
static u_int saorder_state_valid[] = {
	SADB_SASTATE_DYING, SADB_SASTATE_MATURE,
	/*
	 * This order is important because we must select a oldest SA
	 * for outbound processing.  For inbound, This is not important.
	 */
};
static u_int saorder_state_alive[] = {
	/* except DEAD */
	SADB_SASTATE_MATURE, SADB_SASTATE_DYING, SADB_SASTATE_LARVAL
};
static u_int saorder_state_any[] = {
	SADB_SASTATE_MATURE, SADB_SASTATE_DYING,
	SADB_SASTATE_LARVAL, SADB_SASTATE_DEAD
};

#if defined(__FreeBSD__) || defined (__APPLE__)
SYSCTL_DECL(_net_key);
//#if defined(IPSEC_DEBUG)
SYSCTL_INT(_net_key, KEYCTL_DEBUG_LEVEL,	debug,	CTLFLAG_RW, \
	&key_debug_level,	0,	"");
//#endif /* defined(IPSEC_DEBUG) */

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

#endif /* __FreeBSD__ */

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
	if ((head) != (sav)) {                                               \
		printf("%s: state mismatched (TREE=%d SA=%d)\n",             \
			(name), (head), (sav));                              \
		continue;                                                    \
	}                                                                    \
} while (0)

#define KEY_CHKSPDIR(head, sp, name) \
do { \
	if ((head) != (sp)) {                                                \
		printf("%s: direction mismatched (TREE=%d SP=%d), "          \
			"anyway continue.\n",                                \
			(name), (head), (sp));                               \
	}                                                                    \
} while (0)

#if 1
#define KMALLOC(p, t, n)                                                     \
	((p) = (t) _MALLOC((unsigned long)(n), M_SECA, M_NOWAIT))
#define KFREE(p)                                                             \
	_FREE((caddr_t)(p), M_SECA);
#else
#define KMALLOC(p, t, n) \
do { \
	((p) = (t)_MALLOC((unsigned long)(n), M_SECA, M_NOWAIT));             \
	printf("%s %d: %p <- KMALLOC(%s, %d)\n",                             \
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
#define KEY_SETSECASIDX(p, m, s, d, idx) \
do { \
	bzero((idx), sizeof(struct secasindex));                             \
	(idx)->proto = (p);                                                  \
	(idx)->mode = (m)->sadb_msg_mode;                                    \
	(idx)->reqid = (m)->sadb_msg_reqid;                                  \
	bcopy((s), &(idx)->src, ((struct sockaddr *)(s))->sa_len);           \
	bcopy((d), &(idx)->dst, ((struct sockaddr *)(d))->sa_len);           \
} while (0)

/* key statistics */
struct _keystat {
	u_long getspi_count; /* the avarage of count to try to get new SPI */
} keystat;

static struct secasvar *key_allocsa_policy __P((struct secasindex *saidx));
static void key_freesp_so __P((struct secpolicy **sp));
static struct secasvar *key_do_allocsa_policy __P((struct secashead *sah,
						u_int state));
static void key_delsp __P((struct secpolicy *sp));
static struct secpolicy *key_getsp __P((struct secpolicyindex *spidx));
static struct secpolicy *key_getspbyid __P((u_int32_t id));
static u_int32_t key_newreqid __P((void));
static struct sadb_msg *key_spdadd __P((caddr_t *mhp));
static u_int32_t key_getnewspid __P((void));
static struct sadb_msg *key_spddelete __P((caddr_t *mhp));
static struct sadb_msg *key_spddelete2 __P((caddr_t *mhp));
static int key_spdget __P((caddr_t *mhp, struct socket *so, int target));
static struct sadb_msg *key_spdflush __P((caddr_t *mhp));
static int key_spddump __P((caddr_t *mhp, struct socket *so, int target));
static struct mbuf *key_setdumpsp __P((struct secpolicy *sp,
				u_int8_t type, u_int32_t seq, u_int32_t pid));
static u_int key_getspmsglen __P((struct secpolicy *sp));
static u_int key_getspreqmsglen __P((struct secpolicy *sp));
static struct secashead *key_newsah __P((struct secasindex *saidx));
static void key_delsah __P((struct secashead *sah));
static struct secasvar *key_newsav __P((caddr_t *mhp, struct secashead *sah));
static void key_delsav __P((struct secasvar *sav));
static struct secashead *key_getsah __P((struct secasindex *saidx));
static struct secasvar *key_checkspidup __P((struct secasindex *saidx,
						u_int32_t spi));
static struct secasvar *key_getsavbyspi __P((struct secashead *sah,
						u_int32_t spi));
static int key_setsaval __P((struct secasvar *sav, caddr_t *mhp));
static u_int key_getmsglen __P((struct secasvar *sav));
static int key_mature __P((struct secasvar *sav));
static u_int key_setdumpsa __P((struct sadb_msg *newmsg, struct secasvar *sav,
				u_int8_t type, u_int8_t satype,
				u_int32_t seq, u_int32_t pid));
#if 1
static int key_setsadbmsg_m __P((struct mbuf *, u_int8_t type, int tlen,
				u_int8_t satype, u_int32_t seq, pid_t pid,
				u_int8_t mode, u_int32_t reqid,
				u_int8_t reserved1, u_int32_t reserved2));
#endif
static caddr_t key_setsadbmsg __P((caddr_t buf, u_int8_t type, int tlen,
				u_int8_t satype, u_int32_t seq, pid_t pid,
				u_int8_t mode, u_int32_t reqid,
				u_int8_t reserved1, u_int32_t reserved2));
static caddr_t key_setsadbsa __P((caddr_t buf, struct secasvar *sav));
#if 1
static int key_setsadbaddr_m __P((struct mbuf *m, u_int16_t exttype,
	struct sockaddr *saddr, u_int8_t prefixlen, u_int16_t ul_proto));
#endif
static caddr_t key_setsadbaddr __P((caddr_t buf, u_int16_t exttype,
	struct sockaddr *saddr, u_int8_t prefixlen, u_int16_t ul_proto));
static caddr_t key_setsadbident
	__P((caddr_t buf, u_int16_t exttype, u_int16_t idtype,
		caddr_t string, int stringlen, u_int64_t id));
static caddr_t key_setsadbxpolicy
	__P((caddr_t buf, u_int16_t type, u_int8_t dir, u_int32_t id));
static caddr_t key_setsadbext __P((caddr_t p, caddr_t ext));
static void *key_newbuf __P((void *src, u_int len));
#if INET6
static int key_ismyaddr6 __P((caddr_t addr));
#endif
#if 0
static int key_isloopback __P((u_int family, caddr_t addr));
#endif
static int key_cmpsaidx_exactly
	__P((struct secasindex *saidx0, struct secasindex *saidx1));
static int key_cmpsaidx_withmode
	__P((struct secasindex *saidx0, struct secasindex *saidx1));
static int key_cmpspidx_exactly
	__P((struct secpolicyindex *spidx0, struct secpolicyindex *spidx1));
static int key_cmpspidx_withmask
	__P((struct secpolicyindex *spidx0, struct secpolicyindex *spidx1));
static int key_bbcmp __P((caddr_t p1, caddr_t p2, u_int bits));
static u_int16_t key_satype2proto __P((u_int8_t satype));
static u_int8_t key_proto2satype __P((u_int16_t proto));

static struct sadb_msg *key_getspi __P((caddr_t *mhp));
static u_int32_t key_do_getnewspi __P((struct sadb_spirange *spirange,
					struct secasindex *saidx));
static struct sadb_msg *key_update __P((caddr_t *mhp));
#ifdef IPSEC_DOSEQCHECK
static struct secasvar *key_getsavbyseq __P((struct secashead *sah,
						u_int32_t seq));
#endif
static struct sadb_msg *key_add __P((caddr_t *mhp));
static int key_setident __P((struct secashead *sah, caddr_t *mhp));
static struct sadb_msg *key_getmsgbuf_x1 __P((caddr_t *mhp));
static struct sadb_msg *key_delete __P((caddr_t *mhp));
static struct sadb_msg *key_get __P((caddr_t *mhp));
static int key_acquire __P((struct secasindex *, struct secpolicy *));
static struct secacq *key_newacq __P((struct secasindex *saidx));
static struct secacq *key_getacq __P((struct secasindex *saidx));
static struct secacq *key_getacqbyseq __P((u_int32_t seq));
static struct secspacq *key_newspacq __P((struct secpolicyindex *spidx));
static struct secspacq *key_getspacq __P((struct secpolicyindex *spidx));
static struct sadb_msg *key_acquire2 __P((caddr_t *mhp));
static struct sadb_msg *key_register __P((caddr_t *mhp, struct socket *so));
static int key_expire __P((struct secasvar *sav));
static struct sadb_msg *key_flush __P((caddr_t *mhp));
static int key_dump __P((caddr_t *mhp, struct socket *so, int target));
static void key_promisc __P((caddr_t *mhp, struct socket *so));
static int key_sendall __P((struct sadb_msg *msg, u_int len));
static int key_align __P((struct sadb_msg *msg, caddr_t *mhp));
#if 0
static const char *key_getfqdn __P((void));
static const char *key_getuserfqdn __P((void));
#endif
static void key_sa_chgstate __P((struct secasvar *sav, u_int8_t state));
static caddr_t key_appendmbuf __P((struct mbuf *, int));

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
	int s;

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
#ifdef __NetBSD__
	s = splsoftnet();	/*called from softclock()*/
#else
	s = splnet();	/*called from softclock()*/
#endif
	KEYDEBUG(KEYDEBUG_IPSEC_DATA,
		printf("*** objects\n");
		kdebug_secpolicyindex(spidx));

	LIST_FOREACH(sp, &sptree[dir], chain) {
		KEYDEBUG(KEYDEBUG_IPSEC_DATA,
			printf("*** in SPD\n");
			kdebug_secpolicyindex(&sp->spidx));

		if (sp->state == IPSEC_SPSTATE_DEAD)
			continue;
		if (key_cmpspidx_withmask(&sp->spidx, spidx))
			goto found;
	}

	splx(s);
	return NULL;

found:
	/* sanity check */
	KEY_CHKSPDIR(sp->spidx.dir, dir, "key_allocsp");

	/* found a SPD entry */
	sp->refcnt++;
	splx(s);
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		printf("DP key_allocsp cause refcnt++:%d SP:%p\n",
			sp->refcnt, sp));

	return sp;
}

/*
 * allocating a SA entry for a *OUTBOUND* packet.
 * checking each request entries in SP, and acquire SA if need.
 * OUT:	0: there are valid requests.
 *	ENOENT: policy may be valid, but SA with REQUIRE is on acquiring.
 */
int
key_checkrequest(isr, saidx)
	struct ipsecrequest *isr;
	struct secasindex *saidx;
{
	u_int level;
	int error;

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

#if 0
	/*
	 * We do allocate new SA only if the state of SA in the holder is
	 * SADB_SASTATE_DEAD.  The SA for outbound must be the oldest.
	 */
	if (isr->sav != NULL) {
		if (isr->sav->sah == NULL)
			panic("key_checkrequest: sah is null.\n");
		if (isr->sav == (struct secasvar *)LIST_FIRST(
			    &isr->sav->sah->savtree[SADB_SASTATE_DEAD])) {
			KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
				printf("DP checkrequest calls free SA:%p\n",
					isr->sav));
			key_freesav(isr->sav);
			isr->sav = NULL;
		}
	}
#else
	/*
	 * we free any SA stashed in the IPsec request because a different
	 * SA may be involved each time this request is checked, either
	 * because new SAs are being configured, or this request is
	 * associated with an unconnected datagram socket, or this request
	 * is associated with a system default policy.
	 *
	 * The operation may have negative impact to performance.  We may
	 * want to check cached SA carefully, rather than picking new SA
	 * every time.
	 */
	if (isr->sav != NULL) {
		key_freesav(isr->sav);
		isr->sav = NULL;
	}
#endif

	/*
	 * new SA allocation if no SA found.
	 * key_allocsa_policy should allocate the oldest SA available.
	 * See key_do_allocsa_policy(), and draft-jenkins-ipsec-rekeying-03.txt.
	 */
	if (isr->sav == NULL)
		isr->sav = key_allocsa_policy(saidx);

	/* When there is SA. */
	if (isr->sav != NULL)
		return 0;

	/* there is no SA */
	if ((error = key_acquire(saidx, isr->sp)) != 0) {
		/* XXX What I do ? */
#ifdef IPSEC_DEBUG
		printf("key_checkrequest: error %d returned "
			"from key_acquire.\n", error);
#endif
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
static struct secasvar *
key_allocsa_policy(saidx)
	struct secasindex *saidx;
{
	struct secashead *sah;
	struct secasvar *sav;
	u_int stateidx, state;

	LIST_FOREACH(sah, &sahtree, chain) {
		if (sah->state == SADB_SASTATE_DEAD)
			continue;
		if (key_cmpsaidx_withmode(&sah->saidx, saidx))
			goto found;
	}

	return NULL;

    found:

	/* search valid state */
	for (stateidx = 0;
	     stateidx < _ARRAYLEN(saorder_state_valid);
	     stateidx++) {

		state = saorder_state_valid[stateidx];

		sav = key_do_allocsa_policy(sah, state);
		if (sav != NULL)
			return sav;
	}

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
key_do_allocsa_policy(sah, state)
	struct secashead *sah;
	u_int state;
{
	struct secasvar *sav, *candidate;

	/* initilize */
	candidate = NULL;

	LIST_FOREACH(sav, &sah->savtree[state], chain) {

		/* sanity check */
		KEY_CHKSASTATE(sav->state, state, "key_do_allocsa_policy");

		/* initialize */
		if (candidate == NULL) {
			candidate = sav;
			continue;
		}

		/* Which SA is the better ? */

		/* sanity check 2 */
		if (candidate->lft_c == NULL || sav->lft_c == NULL)
			panic("key_do_allocsa_policy: "
				"lifetime_current is NULL.\n");

		/* XXX What the best method is to compare ? */
		if (candidate->lft_c->sadb_lifetime_addtime >
				sav->lft_c->sadb_lifetime_addtime) {
			candidate = sav;
			continue;
		}
	}

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
 *	NULL:		not found, or error occured.
 *
 * In the comparison, source address will be ignored for RFC2401 conformance.
 * To quote, from section 4.1:
 *	A security association is uniquely identified by a triple consisting
 *	of a Security Parameter Index (SPI), an IP Destination Address, and a
 *	security protocol (AH or ESP) identifier.
 * Note that, however, we do need to keep source address in IPsec SA.
 * IPsec SA.  IKE specification and PF_KEY specification do assume that we
 * keep source address in IPsec SA.  We see a tricky situation here.
 */
struct secasvar *
key_allocsa(family, src, dst, proto, spi)
	u_int family, proto;
	caddr_t src, dst;
	u_int32_t spi;
{
	struct secashead *sah;
	struct secasvar *sav;
	u_int stateidx, state;
	int s;

	/* sanity check */
	if (src == NULL || dst == NULL)
		panic("key_allocsa: NULL pointer is passed.\n");

	/*
	 * searching SAD.
	 * XXX: to be checked internal IP header somewhere.  Also when
	 * IPsec tunnel packet is received.  But ESP tunnel mode is
	 * encrypted so we can't check internal IP header.
	 */
#ifdef __NetBSD__
	s = splsoftnet();	/*called from softclock()*/
#else
	s = splnet();	/*called from softclock()*/
#endif
	LIST_FOREACH(sah, &sahtree, chain) {

		/* search valid state */
		for (stateidx = 0;
		     stateidx < _ARRAYLEN(saorder_state_valid);
		     stateidx++) {

			state = saorder_state_valid[stateidx];
			LIST_FOREACH(sav, &sah->savtree[state], chain) {

				/* sanity check */
				KEY_CHKSASTATE(sav->state, state, "key_allocsav");
				if (proto != sav->sah->saidx.proto)
					continue;
				if (spi != sav->spi)
					continue;

#if 0	/* don't check src */
				if (!key_bbcmp(src,
				     _INADDRBYSA(&sav->sah->saidx.src),
				     _INALENBYAF(sav->sah->saidx.src.ss_family) << 3))
					continue;
#endif
				if (!key_bbcmp(dst,
				     _INADDRBYSA(&sav->sah->saidx.dst),
				     _INALENBYAF(sav->sah->saidx.dst.ss_family) << 3))
					continue;

				goto found;
			}
		}
	}

	/* not found */
	splx(s);
	return NULL;

found:
	sav->refcnt++;
	splx(s);
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		printf("DP allocsa cause refcnt++:%d SA:%p\n",
			sav->refcnt, sav));
	return sav;
}

/*
 * Must be called after calling key_allocsp().
 * For both the packet without socket and key_freeso().
 */
void
key_freesp(sp)
	struct secpolicy *sp;
{
	/* sanity check */
	if (sp == NULL)
		panic("key_freesp: NULL pointer is passed.\n");

	sp->refcnt--;
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		printf("DP freesp cause refcnt--:%d SP:%p\n",
			sp->refcnt, sp));

	if (sp->refcnt == 0)
		key_delsp(sp);

	return;
}

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

	switch (so->so_proto->pr_domain->dom_family) {
#if INET
	case PF_INET:
	    {
		struct inpcb *pcb = sotoinpcb(so);

		/* Does it have a PCB ? */
		if (pcb == NULL)
			return;
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
		if (pcb == NULL)
			return;
		key_freesp_so(&pcb->inp_sp->sp_in);
		key_freesp_so(&pcb->inp_sp->sp_out);
#else
		struct in6pcb *pcb  = sotoin6pcb(so);

		/* Does it have a PCB ? */
		if (pcb == NULL)
			return;
		key_freesp_so(&pcb->in6p_sp->sp_in);
		key_freesp_so(&pcb->in6p_sp->sp_out);
#endif
	    }
		break;
#endif /* INET6 */
	default:
#if IPSEC_DEBUG
		printf("key_freeso: unknown address family=%d.\n",
			so->so_proto->pr_domain->dom_family);
#endif
		return;
	}

	return;
}

static void
key_freesp_so(sp)
	struct secpolicy **sp;
{
	/* sanity check */
	if (sp == NULL || *sp == NULL)
		panic("key_freesp_so: sp == NULL\n");

	switch ((*sp)->policy) {
	case IPSEC_POLICY_IPSEC:
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
			printf("DP freeso calls free SP:%p\n", *sp));
		key_freesp(*sp);
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

/*
 * Must be called after calling key_allocsa().
 * This function is called by key_freesp() to free some SA allocated
 * for a policy.
 */
void
key_freesav(sav)
	struct secasvar *sav;
{
	/* sanity check */
	if (sav == NULL)
		panic("key_freesav: NULL pointer is passed.\n");

	sav->refcnt--;
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		printf("DP freesav cause refcnt--:%d SA:%p SPI %d\n",
			sav->refcnt, sav, (u_int32_t)ntohl(sav->spi)));

	if (sav->refcnt == 0)
		key_delsav(sav);

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
	int s;

	/* sanity check */
	if (sp == NULL)
		panic("key_delsp: NULL pointer is passed.\n");

	sp->state = IPSEC_SPSTATE_DEAD;

	if (sp->refcnt > 0)
		return; /* can't free */

#if __NetBSD__
	s = splsoftnet();	/*called from softclock()*/
#else
	s = splnet();	/*called from softclock()*/
#endif
	/* remove from SP index */
	if (__LIST_CHAINED(sp))
		LIST_REMOVE(sp, chain);

    {
	struct ipsecrequest *isr = sp->req, *nextisr;

	while (isr != NULL) {
		if (isr->sav != NULL) {
			KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
				printf("DP delsp calls free SA:%p\n",
					isr->sav));
			key_freesav(isr->sav);
			isr->sav = NULL;
		}

		nextisr = isr->next;
		KFREE(isr);
		isr = nextisr;
	}
    }

	keydb_delsecpolicy(sp);

	splx(s);

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

	/* sanity check */
	if (xpl0 == NULL)
		panic("key_msg2sp: NULL pointer was passed.\n");
	if (len < sizeof(*xpl0))
		panic("key_msg2sp: invalid length.\n");
	if (len != PFKEY_EXTLEN(xpl0)) {
#if IPSEC_DEBUG
		printf("key_msg2sp: Invalid msg length.\n");
#endif
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
#if IPSEC_DEBUG
			printf("key_msg2sp: Invalid msg length.\n");
#endif
			key_freesp(newsp);
			*error = EINVAL;
			return NULL;
		}

		tlen = PFKEY_EXTLEN(xpl0) - sizeof(*xpl0);
		xisr = (struct sadb_x_ipsecrequest *)(xpl0 + 1);

		while (tlen > 0) {

			/* length check */
			if (xisr->sadb_x_ipsecrequest_len < sizeof(*xisr)) {
#if IPSEC_DEBUG
				printf("key_msg2sp: "
					"invalid ipsecrequest length.\n");
#endif
				key_freesp(newsp);
				*error = EINVAL;
				return NULL;
			}

			/* allocate request buffer */
			KMALLOC(*p_isr, struct ipsecrequest *, sizeof(**p_isr));
			if ((*p_isr) == NULL) {
#if IPSEC_DEBUG
				printf("key_msg2sp: No more memory.\n");
#endif
				key_freesp(newsp);
				*error = ENOBUFS;
				return NULL;
			}
			bzero(*p_isr, sizeof(**p_isr));

			/* set values */
			(*p_isr)->next = NULL;

			switch (xisr->sadb_x_ipsecrequest_proto) {
			case IPPROTO_ESP:
			case IPPROTO_AH:
#if 1	/*nonstandard*/
			case IPPROTO_IPCOMP:
#endif
				break;
			default:
#if IPSEC_DEBUG
				printf("key_msg2sp: invalid proto type=%u\n",
					xisr->sadb_x_ipsecrequest_proto);
#endif
				key_freesp(newsp);
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
#if IPSEC_DEBUG
				printf("key_msg2sp: invalid mode=%u\n",
					xisr->sadb_x_ipsecrequest_mode);
#endif
				key_freesp(newsp);
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
#if IPSEC_DEBUG
					printf("key_msg2sp: reqid=%d "
						"range violation, "
						"updated by kernel.\n",
						xisr->sadb_x_ipsecrequest_reqid);
#endif
					xisr->sadb_x_ipsecrequest_reqid = 0;
				}

				/* allocate new reqid id if reqid is zero. */
				if (xisr->sadb_x_ipsecrequest_reqid == 0) {
					u_int32_t reqid;
					if ((reqid = key_newreqid()) == 0) {
						key_freesp(newsp);
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
#if IPSEC_DEBUG
				printf("key_msg2sp: invalid level=%u\n",
					xisr->sadb_x_ipsecrequest_level);
#endif
				key_freesp(newsp);
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
#if IPSEC_DEBUG
					printf("key_msg2sp: invalid request "
						"address length.\n");
#endif
					key_freesp(newsp);
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
#if IPSEC_DEBUG
					printf("key_msg2sp: invalid request "
						"address length.\n");
#endif
					key_freesp(newsp);
					*error = EINVAL;
					return NULL;
				}
				bcopy(paddr, &(*p_isr)->saidx.dst,
					paddr->sa_len);
			}

			(*p_isr)->sav = NULL;
			(*p_isr)->sp = newsp;

			/* initialization for the next. */
			p_isr = &(*p_isr)->next;
			tlen -= xisr->sadb_x_ipsecrequest_len;

			/* validity check */
			if (tlen < 0) {
#if IPSEC_DEBUG
				printf("key_msg2sp: becoming tlen < 0.\n");
#endif
				key_freesp(newsp);
				*error = EINVAL;
				return NULL;
			}

			xisr = (struct sadb_x_ipsecrequest *)((caddr_t)xisr
			                 + xisr->sadb_x_ipsecrequest_len);
		}
	    }
		break;
	default:
#if IPSEC_DEBUG
		printf("key_msg2sp: invalid policy type.\n");
#endif
		key_freesp(newsp);
		*error = EINVAL;
		return NULL;
	}

	*error = 0;
	return newsp;
}

static u_int32_t
key_newreqid()
{
	static u_int32_t auto_reqid = IPSEC_MANUAL_REQID_MAX + 1;

	auto_reqid = (auto_reqid == ~0
			? IPSEC_MANUAL_REQID_MAX + 1 : auto_reqid + 1);

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

	MGET(m, M_DONTWAIT, MT_DATA);
	if (m && MLEN < tlen) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			m = NULL;
		}
	}
	m->m_len = 0;
	if (!m || M_TRAILINGSPACE(m) < tlen) {
#if IPSEC_DEBUG
		printf("key_sp2msg: No more memory.\n");
#endif
		if (m)
			m_free(m);
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

/*
 * SADB_X_SPDADD, SADB_X_SPDSETIDX or SADB_X_SPDUPDATE processing
 * add a entry to SP database, when received
 *   <base, address(SD), policy>
 * from the user(?).
 * Adding to SP database,
 * and send
 *   <base, address(SD), policy>
 * to the socket which was send.
 *
 * SPDADD set a unique policy entry.
 * SPDSETIDX like SPDADD without a part of policy requests.
 * SPDUPDATE replace a unique policy entry.
 *
 * IN:	mhp: pointer to the pointer to each header.
 * OUT:	NULL if fail.
 *	other if success, return pointer to the message to send.
 *
 */
static struct sadb_msg *
key_spdadd(mhp)
	caddr_t *mhp;
{
	struct sadb_msg *msg0;
	struct sadb_address *src0, *dst0;
	struct sadb_x_policy *xpl0;
	struct secpolicyindex spidx;
	struct secpolicy *newsp;
	int error;

	/* sanity check */
	if (mhp == NULL || mhp[0] == NULL)
		panic("key_spdadd: NULL pointer is passed.\n");

	msg0 = (struct sadb_msg *)mhp[0];

	if (mhp[SADB_EXT_ADDRESS_SRC] == NULL
	 || mhp[SADB_EXT_ADDRESS_DST] == NULL
	 || mhp[SADB_X_EXT_POLICY] == NULL) {
#if IPSEC_DEBUG
		printf("key_spdadd: invalid message is passed.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}

	src0 = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_SRC];
	dst0 = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_DST];
	xpl0 = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];

	/* make secindex */
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
#if IPSEC_DEBUG
		printf("key_spdadd: Invalid SP direction.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}

	/* check policy */
	/* key_spdadd() accepts DISCARD, NONE and IPSEC. */
	if (xpl0->sadb_x_policy_type == IPSEC_POLICY_ENTRUST
	 || xpl0->sadb_x_policy_type == IPSEC_POLICY_BYPASS) {
#if IPSEC_DEBUG
		printf("key_spdadd: Invalid policy type.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}

	/* policy requests are mandatory when action is ipsec. */
        if (msg0->sadb_msg_type != SADB_X_SPDSETIDX
	 && xpl0->sadb_x_policy_type == IPSEC_POLICY_IPSEC
	 && PFKEY_EXTLEN(xpl0) <= sizeof(*xpl0)) {
#if IPSEC_DEBUG
		printf("key_spdadd: some policy requests part required.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}

	/*
	 * checking there is SP already or not.
	 * If type is SPDUPDATE and no SP found, then error.
	 * If type is either SPDADD or SPDSETIDX and SP found, then error.
	 */
	newsp = key_getsp(&spidx);
	if (msg0->sadb_msg_type == SADB_X_SPDUPDATE) {
		if (newsp == NULL) {
#if IPSEC_DEBUG
			printf("key_spdadd: no SP found.\n");
#endif
			msg0->sadb_msg_errno = ENOENT;
			return NULL;
		}

		newsp->state = IPSEC_SPSTATE_DEAD;
		key_freesp(newsp);
	} else {
		if (newsp != NULL) {
			key_freesp(newsp);
#if IPSEC_DEBUG
			printf("key_spdadd: a SP entry exists already.\n");
#endif
			msg0->sadb_msg_errno = EEXIST;
			return NULL;
		}
	}

	/* allocation new SP entry */
	if ((newsp = key_msg2sp(xpl0, PFKEY_EXTLEN(xpl0), &error)) == NULL) {
		msg0->sadb_msg_errno = error;
		return NULL;
	}

	if ((newsp->id = key_getnewspid()) == 0) {
		msg0->sadb_msg_errno = ENOBUFS;
		keydb_delsecpolicy(newsp);
		return NULL;
	}

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
		msg0->sadb_msg_errno = EINVAL;
		keydb_delsecpolicy(newsp);
		return NULL;
	}
#if 1
	if (newsp->req && newsp->req->saidx.src.ss_family) {
		struct sockaddr *sa;
		sa = (struct sockaddr *)(src0 + 1);
		if (sa->sa_family != newsp->req->saidx.src.ss_family) {
			msg0->sadb_msg_errno = EINVAL;
			keydb_delsecpolicy(newsp);
			return NULL;
		}
	}
	if (newsp->req && newsp->req->saidx.dst.ss_family) {
		struct sockaddr *sa;
		sa = (struct sockaddr *)(dst0 + 1);
		if (sa->sa_family != newsp->req->saidx.dst.ss_family) {
			msg0->sadb_msg_errno = EINVAL;
			keydb_delsecpolicy(newsp);
			return NULL;
		}
	}
#endif

	newsp->refcnt = 1;	/* do not reclaim until I say I do */
	newsp->state = IPSEC_SPSTATE_ALIVE;
	LIST_INSERT_HEAD(&sptree[newsp->spidx.dir], newsp, chain);

	/* delete the entry in spacqtree */
	if (msg0->sadb_msg_type == SADB_X_SPDUPDATE) {
		struct secspacq *spacq;
		if ((spacq = key_getspacq(&spidx)) != NULL) {
			/* reset counter in order to deletion by timehander. */
			spacq->tick = key_blockacq_lifetime;
			spacq->count = 0;
		}
    	}

    {
	struct sadb_msg *newmsg;
	u_int len;
	caddr_t p;

	/* create new sadb_msg to reply. */
	len = sizeof(struct sadb_msg)
	    + PFKEY_EXTLEN(mhp[SADB_X_EXT_POLICY])
	    + PFKEY_EXTLEN(mhp[SADB_EXT_ADDRESS_SRC])
	    + PFKEY_EXTLEN(mhp[SADB_EXT_ADDRESS_DST]);

	KMALLOC(newmsg, struct sadb_msg *, len);
	if (newmsg == NULL) {
#if IPSEC_DEBUG
		printf("key_spdadd: No more memory.\n");
#endif
		/* newsp persists in the kernel */
		msg0->sadb_msg_errno = ENOBUFS;
		return NULL;
	}
	bzero((caddr_t)newmsg, len);

	bcopy((caddr_t)msg0, (caddr_t)newmsg, sizeof(*msg0));
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(len);
	p = (caddr_t)newmsg + sizeof(*msg0);

	/*
	 * reqid may had been updated at key_msg2sp() if reqid's
	 * range violation.
	 */
	((struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY])->sadb_x_policy_id = newsp->id;
	p = key_setsadbext(p, mhp[SADB_X_EXT_POLICY]);

	p = key_setsadbext(p, mhp[SADB_EXT_ADDRESS_SRC]);
	p = key_setsadbext(p, mhp[SADB_EXT_ADDRESS_DST]);

	return newmsg;
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
	while (count--) {
		newid = (policy_id = (policy_id == ~0 ? 1 : ++policy_id));

		if ((sp = key_getspbyid(newid)) == NULL)
			break;

		key_freesp(sp);
	}

	if (count == 0 || newid == 0) {
#if IPSEC_DEBUG
		printf("key_getnewspid: to allocate policy id is failed.\n");
#endif
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
 * IN:	mhp: pointer to the pointer to each header.
 * OUT:	other if success, return pointer to the message to send.
 *	0 if fail.
 */
static struct sadb_msg *
key_spddelete(mhp)
	caddr_t *mhp;
{
	struct sadb_msg *msg0;
	struct sadb_address *src0, *dst0;
	struct sadb_x_policy *xpl0;
	struct secpolicyindex spidx;
	struct secpolicy *sp;

	/* sanity check */
	if (mhp == NULL || mhp[0] == NULL)
		panic("key_spddelete: NULL pointer is passed.\n");

	msg0 = (struct sadb_msg *)mhp[0];

	if (mhp[SADB_EXT_ADDRESS_SRC] == NULL
	 || mhp[SADB_EXT_ADDRESS_DST] == NULL
	 || mhp[SADB_X_EXT_POLICY] == NULL) {
#if IPSEC_DEBUG
		printf("key_spddelete: invalid message is passed.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}

	src0 = (struct sadb_address *)(mhp[SADB_EXT_ADDRESS_SRC]);
	dst0 = (struct sadb_address *)(mhp[SADB_EXT_ADDRESS_DST]);
	xpl0 = (struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY];

	/* make secindex */
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
#if IPSEC_DEBUG
		printf("key_spddelete: Invalid SP direction.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}

	/* Is there SP in SPD ? */
	if ((sp = key_getsp(&spidx)) == NULL) {
#if IPSEC_DEBUG
		printf("key_spddelete: no SP found.\n");
#endif
		msg0->sadb_msg_errno = ENOENT;
		return NULL;
	}

	/* save policy id to buffer to be returned. */
	xpl0->sadb_x_policy_id = sp->id;

	sp->state = IPSEC_SPSTATE_DEAD;
	key_freesp(sp);

    {
	struct sadb_msg *newmsg;
	u_int len;
	caddr_t p;

	/* create new sadb_msg to reply. */
	len = sizeof(struct sadb_msg)
	    + PFKEY_EXTLEN(mhp[SADB_X_EXT_POLICY])
	    + PFKEY_EXTLEN(mhp[SADB_EXT_ADDRESS_SRC])
	    + PFKEY_EXTLEN(mhp[SADB_EXT_ADDRESS_DST]);

	KMALLOC(newmsg, struct sadb_msg *, len);
	if (newmsg == NULL) {
#if IPSEC_DEBUG
		printf("key_spddelete: No more memory.\n");
#endif
		msg0->sadb_msg_errno = ENOBUFS;
		return NULL;
	}
	bzero((caddr_t)newmsg, len);

	bcopy((caddr_t)mhp[0], (caddr_t)newmsg, sizeof(*msg0));
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(len);
	p = (caddr_t)newmsg + sizeof(*msg0);

	p = key_setsadbext(p, mhp[SADB_X_EXT_POLICY]);
	p = key_setsadbext(p, mhp[SADB_EXT_ADDRESS_SRC]);
	p = key_setsadbext(p, mhp[SADB_EXT_ADDRESS_DST]);

	return newmsg;
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
 * IN:	mhp: pointer to the pointer to each header.
 * OUT:	other if success, return pointer to the message to send.
 *	0 if fail.
 */
static struct sadb_msg *
key_spddelete2(mhp)
	caddr_t *mhp;
{
	struct sadb_msg *msg0;
	u_int32_t id;
	struct secpolicy *sp;

	/* sanity check */
	if (mhp == NULL || mhp[0] == NULL)
		panic("key_spddelete2: NULL pointer is passed.\n");

	msg0 = (struct sadb_msg *)mhp[0];

	if (mhp[SADB_X_EXT_POLICY] == NULL) {
#if IPSEC_DEBUG
		printf("key_spddelete2: invalid message is passed.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}

	id = ((struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY])->sadb_x_policy_id;

	/* Is there SP in SPD ? */
	if ((sp = key_getspbyid(id)) == NULL) {
#if IPSEC_DEBUG
		printf("key_spddelete2: no SP found id:%u.\n", id);
#endif
		msg0->sadb_msg_errno = ENOENT;
		return NULL;
	}

	sp->state = IPSEC_SPSTATE_DEAD;
	key_freesp(sp);

    {
	struct sadb_msg *newmsg;
	u_int len;
	caddr_t p;

	/* create new sadb_msg to reply. */
	len = sizeof(struct sadb_msg)
	    + PFKEY_EXTLEN(mhp[SADB_X_EXT_POLICY]);

	KMALLOC(newmsg, struct sadb_msg *, len);
	if (newmsg == NULL) {
#if IPSEC_DEBUG
		printf("key_spddelete2: No more memory.\n");
#endif
		msg0->sadb_msg_errno = ENOBUFS;
		return NULL;
	}
	bzero((caddr_t)newmsg, len);

	bcopy((caddr_t)mhp[0], (caddr_t)newmsg, sizeof(*msg0));
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(len);
	p = (caddr_t)newmsg + sizeof(*msg0);

	p = key_setsadbext(p, mhp[SADB_X_EXT_POLICY]);

	return newmsg;
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
 * IN:	mhp: pointer to the pointer to each header.
 * OUT:	other if success, return pointer to the message to send.
 *	0 if fail.
 */
static int
key_spdget(mhp, so, target)
	caddr_t *mhp;
	struct socket *so;
	int target;
{
	struct sadb_msg *msg0;
	u_int32_t id;
	struct secpolicy *sp;
	struct mbuf *m;

	/* sanity check */
	if (mhp == NULL || mhp[0] == NULL)
		panic("key_spdget: NULL pointer is passed.\n");

	msg0 = (struct sadb_msg *)mhp[0];

	if (mhp[SADB_X_EXT_POLICY] == NULL) {
#if IPSEC_DEBUG
		printf("key_spdget: invalid message is passed.\n");
#endif
		return EINVAL;
	}

	id = ((struct sadb_x_policy *)mhp[SADB_X_EXT_POLICY])->sadb_x_policy_id;

	/* Is there SP in SPD ? */
	if ((sp = key_getspbyid(id)) == NULL) {
#if IPSEC_DEBUG
		printf("key_spdget: no SP found id:%u.\n", id);
#endif
		return ENOENT;
	}

	m = key_setdumpsp(sp, SADB_X_SPDGET, 0, msg0->sadb_msg_pid);
	if (m != NULL)
		key_sendup_mbuf(so, m, target);

	return 0;
}

/*
 * SADB_X_SPDACQUIRE processing.
 * Acquire policy and SA(s) for a *OUTBOUND* packet.
 * send
 *   <base, policy(*)>
 * to KMD, and expect to receive
 *   <base> with SADB_X_SPDACQUIRE if error occured,
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
	struct secspacq *newspacq;
	int error;

	/* sanity check */
	if (sp == NULL)
		panic("key_spdacquire: NULL pointer is passed.\n");
	if (sp->req != NULL)
		panic("key_spdacquire: called but there is request.\n");
	if (sp->policy != IPSEC_POLICY_IPSEC)
		panic("key_spdacquire: policy mismathed. IPsec is expected.\n");

	/* get a entry to check whether sent message or not. */
	if ((newspacq = key_getspacq(&sp->spidx)) != NULL) {
		if (key_blockacq_count < newspacq->count) {
			/* reset counter and do send message. */
			newspacq->count = 0;
		} else {
			/* increment counter and do nothing. */
			newspacq->count++;
			return 0;
		}
	} else {
		/* make new entry for blocking to send SADB_ACQUIRE. */
		if ((newspacq = key_newspacq(&sp->spidx)) == NULL)
			return ENOBUFS;

		/* add to acqtree */
		LIST_INSERT_HEAD(&spacqtree, newspacq, chain);
	}

    {
	struct sadb_msg *newmsg = NULL;
	union sadb_x_ident_id id;
	u_int len;
	caddr_t p;

	/* create new sadb_msg to reply. */
	len = sizeof(struct sadb_msg)
		+ sizeof(struct sadb_ident)
		+ PFKEY_ALIGN8(sp->spidx.src.ss_len)
		+ sizeof(struct sadb_ident)
		+ PFKEY_ALIGN8(sp->spidx.dst.ss_len);

	KMALLOC(newmsg, struct sadb_msg *, len);
	if (newmsg == 0) {
#if IPSEC_DEBUG
		printf("key_spdacquire: No more memory.\n");
#endif
		return ENOBUFS;
	}
	bzero((caddr_t)newmsg, len);

	newmsg->sadb_msg_version = PF_KEY_V2;
	newmsg->sadb_msg_type = SADB_X_SPDACQUIRE;
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_satype = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(len);
	newmsg->sadb_msg_mode = 0;
	newmsg->sadb_msg_reqid = 0;
	newmsg->sadb_msg_seq = 0;
	newmsg->sadb_msg_pid = 0;
	p = (caddr_t)newmsg + sizeof(struct sadb_msg);

	/* set sadb_address for spidx's. */
	bzero(&id, sizeof(id));
	id.sadb_x_ident_id_addr.prefix = sp->spidx.prefs;
	id.sadb_x_ident_id_addr.ul_proto = sp->spidx.ul_proto;
	p = key_setsadbident(p,
	                    SADB_EXT_IDENTITY_SRC,
			    SADB_X_IDENTTYPE_ADDR,
	                    (caddr_t)&sp->spidx.src,
			    sp->spidx.src.ss_len,
			    *(u_int64_t *)&id);

	bzero(&id, sizeof(id));
	id.sadb_x_ident_id_addr.prefix = sp->spidx.prefd;
	id.sadb_x_ident_id_addr.ul_proto = sp->spidx.ul_proto;
	p = key_setsadbident(p,
	                    SADB_EXT_IDENTITY_DST,
			    SADB_X_IDENTTYPE_ADDR,
	                    (caddr_t)&sp->spidx.dst,
			    sp->spidx.dst.ss_len,
			    *(u_int64_t *)&id);

	error = key_sendall(newmsg, len);
#if IPSEC_DEBUG
	if (error != 0)
		printf("key_spdacquire: key_sendall returned %d\n", error);
#endif
	return error;
    }

	return 0;
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
 * IN:	mhp: pointer to the pointer to each header.
 * OUT:	other if success, return pointer to the message to send.
 *	0 if fail.
 */
static struct sadb_msg *
key_spdflush(mhp)
	caddr_t *mhp;
{
	struct sadb_msg *msg0;
	struct secpolicy *sp;
	u_int dir;

	/* sanity check */
	if (mhp == NULL || mhp[0] == NULL)
		panic("key_spdflush: NULL pointer is passed.\n");

	msg0 = (struct sadb_msg *)mhp[0];

	for (dir = 0; dir < IPSEC_DIR_MAX; dir++) {
		LIST_FOREACH(sp, &sptree[dir], chain) {
			sp->state = IPSEC_SPSTATE_DEAD;
		}
	}

    {
	struct sadb_msg *newmsg;
	u_int len;

	/* create new sadb_msg to reply. */
	len = sizeof(struct sadb_msg);

	KMALLOC(newmsg, struct sadb_msg *, len);
	if (newmsg == NULL) {
#if IPSEC_DEBUG
		printf("key_spdflush: No more memory.\n");
#endif
		msg0->sadb_msg_errno = ENOBUFS;
		return NULL;
	}
	bzero((caddr_t)newmsg, len);

	bcopy((caddr_t)mhp[0], (caddr_t)newmsg, sizeof(*msg0));
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(len);

	return(newmsg);
    }
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
 * IN:	mhp: pointer to the pointer to each header.
 * OUT:	other if success, return pointer to the message to send.
 *	0 if fail.
 */
static int
key_spddump(mhp, so, target)
	caddr_t *mhp;
	struct socket *so;
	int target;
{
	struct sadb_msg *msg0;
	struct secpolicy *sp;
	int cnt;
	u_int dir;
	struct mbuf *m;

	/* sanity check */
	if (mhp == NULL || mhp[0] == NULL)
		panic("key_spddump: NULL pointer is passed.\n");

	msg0 = (struct sadb_msg *)mhp[0];

	/* search SPD entry and get buffer size. */
	cnt = 0;
	for (dir = 0; dir < IPSEC_DIR_MAX; dir++) {
		LIST_FOREACH(sp, &sptree[dir], chain) {
			cnt++;
		}
	}

	if (cnt == 0)
		return ENOENT;

	for (dir = 0; dir < IPSEC_DIR_MAX; dir++) {
		LIST_FOREACH(sp, &sptree[dir], chain) {
			--cnt;
			m = key_setdumpsp(sp, SADB_X_SPDDUMP,
			                    cnt, msg0->sadb_msg_pid);

			if (m)
				key_sendup_mbuf(so, m, target);
		}
	}

	return 0;
}

static struct mbuf *
key_setdumpsp(sp, type, seq, pid)
	struct secpolicy *sp;
	u_int8_t type;
	u_int32_t seq, pid;
{
	struct mbuf *m;
	u_int tlen;

	/* XXX it would be better to avoid pre-computing length */
	tlen = key_getspmsglen(sp);

	/* XXX maybe it's a wrong idea to insist on cluster? */
	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (m != NULL) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_freem(m);
			m = NULL;
		}
	}
	if (m == NULL)
		return NULL;	/*ENOBUFS*/

	m->m_pkthdr.len = m->m_len = 0;
	m->m_next = NULL;

	/* sadb_msg->sadb_msg_len must be filled afterwards */
	if (key_setsadbmsg_m(m, type, 0, SADB_SATYPE_UNSPEC, seq, pid,
		    IPSEC_MODE_ANY, 0, 0, sp->refcnt) != 0) {
		m_freem(m);
		return NULL;
	}

	if (key_setsadbaddr_m(m, SADB_EXT_ADDRESS_SRC,
		    (struct sockaddr *)&sp->spidx.src, sp->spidx.prefs,
		    sp->spidx.ul_proto) != 0) {
		m_freem(m);
		return NULL;
	}

	if (key_setsadbaddr_m(m, SADB_EXT_ADDRESS_DST,
		    (struct sockaddr *)&sp->spidx.dst, sp->spidx.prefd,
		    sp->spidx.ul_proto) != 0) {
		m_freem(m);
		return NULL;
	}

    {
	struct mbuf *n;
	struct sadb_x_policy *tmp;

	n = key_sp2msg(sp);
	if (!n || n->m_len < sizeof(*tmp)) {
#if IPSEC_DEBUG
		printf("key_setdumpsp: No more memory.\n");
#endif
		m_freem(m);
		if (n)
			m_freem(n);
		return NULL;
	}

	tmp = mtod(n, struct sadb_x_policy *);

	/* validity check */
	if (key_getspreqmsglen(sp) != PFKEY_UNUNIT64(tmp->sadb_x_policy_len)
	 || n->m_len != PFKEY_UNUNIT64(tmp->sadb_x_policy_len))
		panic("key_setdumpsp: length mismatch."
		      "sp:%d msg:%d\n",
			key_getspreqmsglen(sp),
			PFKEY_UNUNIT64(tmp->sadb_x_policy_len));
	
	m_cat(m, n);
	m->m_pkthdr.len += n->m_len;
    }

	if (m->m_len < sizeof(struct sadb_msg)) {
		m = m_pullup(m, sizeof(struct sadb_msg));
		if (m == NULL)
			return NULL;
	}
	mtod(m, struct sadb_msg *)->sadb_msg_len =
	    PFKEY_UNIT64(m->m_pkthdr.len);

	return m;
}

/* get sadb message length for a SP. */
static u_int
key_getspmsglen(sp)
	struct secpolicy *sp;
{
	u_int tlen;

	/* sanity check */
	if (sp == NULL)
		panic("key_getspmsglen: NULL pointer is passed.\n");

	tlen = (sizeof(struct sadb_msg)
		+ sizeof(struct sadb_address)
		+ PFKEY_ALIGN8(_SALENBYAF(sp->spidx.src.ss_family))
		+ sizeof(struct sadb_address)
		+ PFKEY_ALIGN8(_SALENBYAF(sp->spidx.dst.ss_family)));

	tlen += key_getspreqmsglen(sp);

	return tlen;
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

/* %%% SAD management */
/*
 * allocating a memory for new SA head, and copy from the values of mhp.
 * OUT:	NULL	: failure due to the lack of memory.
 *	others	: pointer to new SA head.
 */
static struct secashead *
key_newsah(saidx)
	struct secasindex *saidx;
{
	struct secashead *newsah;

	/* sanity check */
	if (saidx == NULL)
		panic("key_newsaidx: NULL pointer is passed.\n");

	newsah = keydb_newsecashead();
	if (newsah == NULL)
		return NULL;

	bcopy(saidx, &newsah->saidx, sizeof(newsah->saidx));

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
	int s;
	int zombie = 0;

	/* sanity check */
	if (sah == NULL)
		panic("key_delsah: NULL pointer is passed.\n");

#ifdef __NetBSD__
	s = splsoftnet();	/*called from softclock()*/
#else
	s = splnet();	/*called from softclock()*/
#endif

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

			key_freesav(sav);

			/* remove back pointer */
			sav->sah = NULL;
			sav = NULL;
		}
	}

	/* don't delete sah only if there are savs. */
	if (zombie) {
		splx(s);
		return;
	}

	if (sah->sa_route.ro_rt) {
		RTFREE(sah->sa_route.ro_rt);
		sah->sa_route.ro_rt = (struct rtentry *)NULL;
	}

	/* remove from tree of SA index */
	if (__LIST_CHAINED(sah))
		LIST_REMOVE(sah, chain);

	KFREE(sah);

	splx(s);
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
 */
static struct secasvar *
key_newsav(mhp, sah)
	caddr_t *mhp;
	struct secashead *sah;
{
	struct secasvar *newsav;
	struct sadb_msg *msg0;

	/* sanity check */
	if (mhp == NULL || mhp[0] == NULL || sah == NULL)
		panic("key_newsa: NULL pointer is passed.\n");

	msg0 = (struct sadb_msg *)mhp[0];

	KMALLOC(newsav, struct secasvar *, sizeof(struct secasvar));
	if (newsav == NULL) {
#if IPSEC_DEBUG
		printf("key_newsa: No more memory.\n");
#endif
		msg0->sadb_msg_errno = ENOBUFS;
		return NULL;
	}
	bzero((caddr_t)newsav, sizeof(struct secasvar));

	switch (msg0->sadb_msg_type) {
	case SADB_GETSPI:
		newsav->spi = 0;

#if IPSEC_DOSEQCHECK
		/* sync sequence number */
		if (msg0->sadb_msg_seq == 0)
			newsav->seq =
				(acq_seq = (acq_seq == ~0 ? 1 : ++acq_seq));
		else
#endif
			newsav->seq = msg0->sadb_msg_seq;
		break;

	case SADB_ADD:
		/* sanity check */
		if (mhp[SADB_EXT_SA] == NULL) {
			KFREE(newsav);
#if IPSEC_DEBUG
			printf("key_newsa: invalid message is passed.\n");
#endif
			msg0->sadb_msg_errno = EINVAL;
			return NULL;
		}
		newsav->spi = ((struct sadb_sa *)mhp[SADB_EXT_SA])->sadb_sa_spi;
		newsav->seq = msg0->sadb_msg_seq;
		break;
	default:
		KFREE(newsav);
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}

	/* copy sav values */
	if (msg0->sadb_msg_type != SADB_GETSPI && key_setsaval(newsav, mhp)) {
		KFREE(newsav);
		/* msg0->sadb_msg_errno is set at key_setsaval. */
		return NULL;
	}

	/* reset tick */
	newsav->tick = 0;

	newsav->pid = msg0->sadb_msg_pid;

	/* add to satree */
	newsav->sah = sah;
	newsav->refcnt = 1;
	newsav->state = SADB_SASTATE_LARVAL;
	LIST_INSERT_TAIL(&sah->savtree[SADB_SASTATE_LARVAL], newsav,
			secasvar, chain);

	return newsav;
}

/*
 * free() SA variable entry.
 */
static void
key_delsav(sav)
	struct secasvar *sav;
{
	/* sanity check */
	if (sav == NULL)
		panic("key_delsav: NULL pointer is passed.\n");

	if (sav->refcnt > 0)
		return;		/* can't free */

	/* remove from SA header */
	if (__LIST_CHAINED(sav))
		LIST_REMOVE(sav, chain);

	if (sav->key_auth != NULL)
		KFREE(sav->key_auth);
	if (sav->key_enc != NULL)
		KFREE(sav->key_enc);
	if (sav->replay != NULL)
		keydb_delsecreplay(sav->replay);
	if (sav->lft_c != NULL)
		KFREE(sav->lft_c);
	if (sav->lft_h != NULL)
		KFREE(sav->lft_h);
	if (sav->lft_s != NULL)
		KFREE(sav->lft_s);
	if (sav->iv != NULL)
		KFREE(sav->iv);
#if notyet
	if (sav->misc1 != NULL)
		KFREE(sav->misc1);
	if (sav->misc2 != NULL)
		KFREE(sav->misc2);
	if (sav->misc3 != NULL)
		KFREE(sav->misc3);
#endif

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

	LIST_FOREACH(sah, &sahtree, chain) {
		if (sah->state == SADB_SASTATE_DEAD)
			continue;
		if (key_cmpsaidx_exactly(&sah->saidx, saidx))
			return(sah);
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
	struct secashead *sah;
	struct secasvar *sav;

	/* check address family */
	if (saidx->src.ss_family != saidx->dst.ss_family) {
#if IPSEC_DEBUG
		printf("key_checkspidup: address family mismatched.\n");
#endif
		return NULL;
	}

	/* check all SAD */
	LIST_FOREACH(sah, &sahtree, chain) {
		if (!key_ismyaddr(sah->saidx.dst.ss_family,
		                  _INADDRBYSA(&sah->saidx.dst)))
			continue;
		sav = key_getsavbyspi(sah, spi);
		if (sav != NULL)
			return sav;
	}

	return NULL;
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
	struct secasvar *sav;
	u_int stateidx, state;

	/* search all status */
	for (stateidx = 0;
	     stateidx < _ARRAYLEN(saorder_state_alive);
	     stateidx++) {

		state = saorder_state_alive[stateidx];
		LIST_FOREACH(sav, &sah->savtree[state], chain) {

			/* sanity check */
			if (sav->state != state) {
#if IPSEC_DEBUG
				printf("key_getsavbyspi: "
					"invalid sav->state "
					"(queue: %d SA: %d)\n",
					state, sav->state);
#endif
				continue;
			}

			if (sav->spi == spi)
				return sav;
		}
	}

	return NULL;
}

/*
 * copy SA values from PF_KEY message except *SPI, SEQ, PID, STATE and TYPE*.
 * You must update these if need.
 * OUT:	0:	success.
 *	1:	failure. set errno to (mhp[0])->sadb_msg_errno.
 */
static int
key_setsaval(sav, mhp)
	struct secasvar *sav;
	caddr_t *mhp;
{
	struct sadb_msg *msg0;
	int error = 0;

	/* sanity check */
	if (mhp == NULL || mhp[0] == NULL)
		panic("key_setsaval: NULL pointer is passed.\n");

	msg0 = (struct sadb_msg *)mhp[0];

	/* initialization */
	sav->replay = NULL;
	sav->key_auth = NULL;
	sav->key_enc = NULL;
	sav->iv = NULL;
	sav->lft_c = NULL;
	sav->lft_h = NULL;
	sav->lft_s = NULL;
#if notyet
	sav->misc1 = NULL;
	sav->misc2 = NULL;
	sav->misc3 = NULL;
#endif

	/* SA */
	if (mhp[SADB_EXT_SA] != NULL) {
		struct sadb_sa *sa0 = (struct sadb_sa *)mhp[SADB_EXT_SA];

		sav->alg_auth = sa0->sadb_sa_auth;
		sav->alg_enc = sa0->sadb_sa_encrypt;
		sav->flags = sa0->sadb_sa_flags;

		/* replay window */
		if ((sa0->sadb_sa_flags & SADB_X_EXT_OLD) == 0) {
			sav->replay = keydb_newsecreplay(sa0->sadb_sa_replay);
			if (sav->replay == NULL) {
#if IPSEC_DEBUG
				printf("key_setsaval: No more memory.\n");
#endif
				error = ENOBUFS;
				goto err;
			}
		}
	}

	/* Authentication keys */
	if (mhp[SADB_EXT_KEY_AUTH] != NULL) {
		struct sadb_key *key0;
		u_int len;

		key0 = (struct sadb_key *)mhp[SADB_EXT_KEY_AUTH];
		len = PFKEY_UNUNIT64(key0->sadb_key_len);

		error = 0;
		if (len < sizeof(struct sadb_key))
			error = EINVAL;
		switch (msg0->sadb_msg_satype) {
		case SADB_SATYPE_AH:
		case SADB_SATYPE_ESP:
			if (len == sizeof(struct sadb_key)
			 && sav->alg_auth != SADB_AALG_NULL) {
				error = EINVAL;
			}
			break;
		case SADB_X_SATYPE_IPCOMP:
			error = EINVAL;
			break;
		default:
			error = EINVAL;
			break;
		}
		if (error) {
#if IPSEC_DEBUG
			printf("key_setsaval: invalid key_auth values.\n");
#endif
			goto err;
		}

		sav->key_auth = (struct sadb_key *)key_newbuf(key0, len);
		if (sav->key_auth == NULL) {
#if IPSEC_DEBUG
			printf("key_setsaval: No more memory.\n");
#endif
			error = ENOBUFS;
			goto err;
		}

		/* make length shift up for kernel*/
		sav->key_auth->sadb_key_len = len;
	}

	/* Encryption key */
	if (mhp[SADB_EXT_KEY_ENCRYPT] != NULL) {
		struct sadb_key *key0;
		u_int len;

		key0 = (struct sadb_key *)mhp[SADB_EXT_KEY_ENCRYPT];
		len = PFKEY_UNUNIT64(key0->sadb_key_len);

		error = 0;
		if (len < sizeof(struct sadb_key))
			error = EINVAL;
		switch (msg0->sadb_msg_satype) {
		case SADB_SATYPE_ESP:
			if (len == sizeof(struct sadb_key)
			 && sav->alg_enc != SADB_EALG_NULL) {
				error = EINVAL;
			}
			break;
		case SADB_SATYPE_AH:
			error = EINVAL;
			break;
		case SADB_X_SATYPE_IPCOMP:
			break;
		default:
			error = EINVAL;
			break;
		}
		if (error) {
#if IPSEC_DEBUG
			printf("key_setsatval: invalid key_enc value.\n");
#endif
			goto err;
		}

		sav->key_enc = (struct sadb_key *)key_newbuf(key0, len);
		if (sav->key_enc == NULL) {
#if IPSEC_DEBUG
			printf("key_setsaval: No more memory.\n");
#endif
			error = ENOBUFS;
			goto err;
		}

		/* make length shift up for kernel*/
		sav->key_enc->sadb_key_len = len;
	}

	/* set iv */
	sav->ivlen = 0;

	switch (msg0->sadb_msg_satype) {
	case SADB_SATYPE_ESP:
#if IPSEC_ESP
	    {
		struct esp_algorithm *algo;

		algo = &esp_algorithms[sav->alg_enc];
		if (algo && algo->ivlen)
			sav->ivlen = (*algo->ivlen)(sav);
		KMALLOC(sav->iv, caddr_t, sav->ivlen);
		if (sav->iv == 0) {
#if IPSEC_DEBUG
			printf("key_setsaval: No more memory.\n");
#endif
			error = ENOBUFS;
			goto err;
		}
		/* initialize ? */
		break;
	    }
#else
		break;
#endif
	case SADB_SATYPE_AH:
#if 1	/*nonstandard*/
	case SADB_X_SATYPE_IPCOMP:
#endif
		break;
	default:
#if IPSEC_DEBUG
		printf("key_setsaval: invalid SA type.\n");
#endif
		error = EINVAL;
		goto err;
	}

	/* reset tick */
	sav->tick = 0;

	/* make lifetime for CURRENT */
    {
	struct timeval tv;

	KMALLOC(sav->lft_c, struct sadb_lifetime *,
		sizeof(struct sadb_lifetime));
	if (sav->lft_c == NULL) {
#if IPSEC_DEBUG
		printf("key_setsaval: No more memory.\n");
#endif
		error = ENOBUFS;
		goto err;
	}

	microtime(&tv);

	sav->lft_c->sadb_lifetime_len =
		PFKEY_UNIT64(sizeof(struct sadb_lifetime));
	sav->lft_c->sadb_lifetime_exttype = SADB_EXT_LIFETIME_CURRENT;
	sav->lft_c->sadb_lifetime_allocations = 0;
	sav->lft_c->sadb_lifetime_bytes = 0;
	sav->lft_c->sadb_lifetime_addtime = tv.tv_sec;
	sav->lft_c->sadb_lifetime_usetime = 0;
    }

	/* lifetimes for HARD and SOFT */
    {
	struct sadb_lifetime *lft0;

	lft0 = (struct sadb_lifetime *)mhp[SADB_EXT_LIFETIME_HARD];
	if (lft0 != NULL) {
		sav->lft_h = (struct sadb_lifetime *)key_newbuf(lft0,
				sizeof(*lft0));
		if (sav->lft_h == NULL) {
#if IPSEC_DEBUG
			printf("key_setsaval: No more memory.\n");
#endif
			error = ENOBUFS;
			goto err;
		}
		/* to be initialize ? */
	}

	lft0 = (struct sadb_lifetime *)mhp[SADB_EXT_LIFETIME_SOFT];
	if (lft0 != NULL) {
		sav->lft_s = (struct sadb_lifetime *)key_newbuf(lft0,
				sizeof(*lft0));
		if (sav->lft_s == NULL) {
#if IPSEC_DEBUG
			printf("key_setsaval: No more memory.\n");
#endif
			error = ENOBUFS;
			goto err;
		}
		/* to be initialize ? */
	}
    }

#if notyet
	/* pre-processing for DES */
	switch (sav->alg_enc) {
	case SADB_EALG_DESCBC:
        	if (des_key_sched((C_Block *)_KEYBUF(sav->key_enc),
		                  (des_key_schedule)sav->misc1) != 0) {
#if IPSEC_DEBUG
			printf("key_setsaval: error des_key_sched.\n");
#endif
			sav->misc1 = NULL;
			/* THROUGH */
		}
		break;
	case SADB_EALG_3DESCBC:
        	if (des_key_sched((C_Block *)_KEYBUF(sav->key_enc),
		                  (des_key_schedule)sav->misc1) != 0
        	 || des_key_sched((C_Block *)(_KEYBUF(sav->key_enc) + 8),
		                  (des_key_schedule)sav->misc2) != 0
        	 || des_key_sched((C_Block *)(_KEYBUF(sav->key_enc) + 16),
		                  (des_key_schedule)sav->misc3) != 0) {
#if IPSEC_DEBUG
			printf("key_setsaval: error des_key_sched.\n");
#endif
			sav->misc1 = NULL;
			sav->misc2 = NULL;
			sav->misc3 = NULL;
			/* THROUGH */
		}
	}
#endif

	msg0->sadb_msg_errno = 0;
	return 0;

    err:
	/* initialization */
	if (sav->replay != NULL)
		keydb_delsecreplay(sav->replay);
	if (sav->key_auth != NULL)
		KFREE(sav->key_auth);
	if (sav->key_enc != NULL)
		KFREE(sav->key_enc);
	if (sav->iv != NULL)
		KFREE(sav->iv);
	if (sav->lft_c != NULL)
		KFREE(sav->lft_c);
	if (sav->lft_h != NULL)
		KFREE(sav->lft_h);
	if (sav->lft_s != NULL)
		KFREE(sav->lft_s);
#if notyet
	if (sav->misc1 != NULL)
		KFREE(sav->misc1);
	if (sav->misc2 != NULL)
		KFREE(sav->misc2);
	if (sav->misc3 != NULL)
		KFREE(sav->misc3);
#endif

	msg0->sadb_msg_errno = error;
	return 1;
}

/*
 * get message buffer length.
 */
static u_int
key_getmsglen(sav)
	struct secasvar *sav;
{
	int len = sizeof(struct sadb_msg);

	len += sizeof(struct sadb_sa);
	len += (sizeof(struct sadb_address)
		+ PFKEY_ALIGN8(_SALENBYAF(sav->sah->saidx.src.ss_family)));
	len += (sizeof(struct sadb_address)
		+ PFKEY_ALIGN8(_SALENBYAF(sav->sah->saidx.dst.ss_family)));

	if (sav->key_auth != NULL)
		len += sav->key_auth->sadb_key_len;
	if (sav->key_enc != NULL)
		len += sav->key_enc->sadb_key_len;

	if (sav->lft_c != NULL)
		len += sizeof(struct sadb_lifetime);
	if (sav->lft_h != NULL)
		len += sizeof(struct sadb_lifetime);
	if (sav->lft_s != NULL)
		len += sizeof(struct sadb_lifetime);

	return len;
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

	/* check SPI value */
	if (ntohl(sav->spi) >= 0 && ntohl(sav->spi) <= 255) {
#if IPSEC_DEBUG
		printf("key_mature: illegal range of SPI %d.\n", sav->spi);
#endif
		return EINVAL;
	}

	/* check satype */
	switch (sav->sah->saidx.proto) {
	case IPPROTO_ESP:
		/* check flags */
		if ((sav->flags & SADB_X_EXT_OLD)
		 && (sav->flags & SADB_X_EXT_DERIV)) {
#if IPSEC_DEBUG
			printf("key_mature: "
				"invalid flag (derived) given to old-esp.\n");
#endif
			return EINVAL;
		}
		checkmask = 3;
		mustmask = 1;
		break;
	case IPPROTO_AH:
		/* check flags */
		if (sav->flags & SADB_X_EXT_DERIV) {
#if IPSEC_DEBUG
			printf("key_mature: "
				"invalid flag (derived) given to AH SA.\n");
#endif
			return EINVAL;
		}
		if (sav->alg_enc != SADB_EALG_NONE) {
#if IPSEC_DEBUG
			printf("key_mature: "
				"protocol and algorithm mismated.\n");
#endif
			return(EINVAL);
		}
		checkmask = 2;
		mustmask = 2;
		break;
#if 1	/*nonstandard*/
	case IPPROTO_IPCOMP:
		if (sav->alg_auth != SADB_AALG_NONE) {
#if IPSEC_DEBUG
			printf("key_mature: "
				"protocol and algorithm mismated.\n");
#endif
			return(EINVAL);
		}
		if ((sav->flags & SADB_X_EXT_RAWCPI) == 0
		 && ntohl(sav->spi) >= 0x10000) {
#if IPSEC_DEBUG
			printf("key_mature: invalid cpi for IPComp.\n");
#endif
			return(EINVAL);
		}
		checkmask = 4;
		mustmask = 4;
		break;
#endif
	default:
#if IPSEC_DEBUG
		printf("key_mature: Invalid satype.\n");
#endif
		return EPROTONOSUPPORT;
	}

	/* check authentication algorithm */
	if ((checkmask & 2) != 0) {
		struct ah_algorithm *algo;
		int keylen;

		/* XXX: should use algorithm map to check. */
		switch (sav->alg_auth) {
		case SADB_AALG_NONE:
		case SADB_AALG_MD5HMAC:
		case SADB_AALG_SHA1HMAC:
		case SADB_AALG_MD5:
		case SADB_AALG_SHA:
		case SADB_AALG_NULL:
			break;
		default:
#if IPSEC_DEBUG
			printf("key_mature: "
				"unknown authentication algorithm.\n");
#endif
			return EINVAL;
		}

		/* algorithm-dependent check */
		algo = &ah_algorithms[sav->alg_auth];

		if (sav->key_auth)
			keylen = sav->key_auth->sadb_key_bits;
		else
			keylen = 0;
		if (keylen < algo->keymin || algo->keymax < keylen) {
#if IPSEC_DEBUG
			printf("key_mature: invalid AH key length %d "
				"(%d-%d allowed)\n", keylen,
				algo->keymin, algo->keymax);
#endif
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
#if IPSEC_DEBUG
			printf("key_mature: no satisfy algorithm for AH\n");
#endif
			return EINVAL;
		}
	}

	/* check encryption algorithm */
	if ((checkmask & 1) != 0) {
#if IPSEC_ESP
		struct esp_algorithm *algo;
		int keylen;

		switch (sav->alg_enc) {
		case SADB_EALG_NONE:
		case SADB_EALG_DESCBC:
		case SADB_EALG_3DESCBC:
		case SADB_EALG_NULL:
		case SADB_EALG_BLOWFISHCBC:
		case SADB_EALG_CAST128CBC:
		case SADB_EALG_RC5CBC:
			break;
		default:
#if IPSEC_DEBUG
			printf("key_mature: unknown encryption algorithm.\n");
#endif
			return EINVAL;
		}

		/* algorithm-dependent check */
		algo = &esp_algorithms[sav->alg_enc];

		if (sav->key_enc)
			keylen = sav->key_enc->sadb_key_bits;
		else
			keylen = 0;
		if (keylen < algo->keymin || algo->keymax < keylen) {
#if IPSEC_DEBUG
			printf("key_mature: invalid ESP key length %d "
				"(%d-%d allowed)\n", keylen,
				algo->keymin, algo->keymax);
#endif
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
#if IPSEC_DEBUG
			printf("key_mature: no satisfy algorithm for ESP\n");
#endif
			return EINVAL;
		}
#else /*IPSEC_ESP*/
#if IPSEC_DEBUG
		printf("key_mature: ESP not supported in this configuration\n");
#endif
		return EINVAL;
#endif
	}

	/* check compression algorithm */
	if ((checkmask & 4) != 0) {
		struct ipcomp_algorithm *algo;

		switch (sav->alg_enc) {
		case SADB_X_CALG_NONE:
		case SADB_X_CALG_OUI:
		case SADB_X_CALG_DEFLATE:
		case SADB_X_CALG_LZS:
			break;
		default:
#if IPSEC_DEBUG
			printf("key_mature: unknown compression algorithm.\n");
#endif
			return EINVAL;
		}

		/* algorithm-dependent check */
		algo = &ipcomp_algorithms[sav->alg_enc];

		if (!(algo->compress && algo->decompress)) {
#if IPSEC_DEBUG
			printf("key_mature: "
				"unsupported compression algorithm.\n");
#endif
			return EINVAL;
		}
	}

	key_sa_chgstate(sav, SADB_SASTATE_MATURE);

	return 0;
}

/*
 * subroutine for SADB_GET and SADB_DUMP.
 * the buf must be allocated sufficent space.
 */
static u_int
key_setdumpsa(newmsg, sav, type, satype, seq, pid)
	struct sadb_msg *newmsg;
	struct secasvar *sav;
	u_int8_t type, satype;
	u_int32_t seq, pid;
{
	u_int tlen;
	caddr_t p;
	int i;

	tlen = key_getmsglen(sav);

	p = key_setsadbmsg((caddr_t)newmsg, type, tlen,
	                   satype, seq, pid,
	                   sav->sah->saidx.mode, sav->sah->saidx.reqid,
			   0, sav->refcnt);

	for (i = 1; i <= SADB_EXT_MAX; i++) {
		switch (i) {
		case SADB_EXT_SA:
			p = key_setsadbsa(p, sav);
			break;

		case SADB_EXT_ADDRESS_SRC:
			p = key_setsadbaddr(p,
			      SADB_EXT_ADDRESS_SRC,
			      (struct sockaddr *)&sav->sah->saidx.src,
			      _INALENBYAF(sav->sah->saidx.src.ss_family) << 3,
			      IPSEC_ULPROTO_ANY);
			break;

		case SADB_EXT_ADDRESS_DST:
			p = key_setsadbaddr(p,
			      SADB_EXT_ADDRESS_DST,
			      (struct sockaddr *)&sav->sah->saidx.dst,
			      _INALENBYAF(sav->sah->saidx.dst.ss_family) << 3,
			      IPSEC_ULPROTO_ANY);
			break;

		case SADB_EXT_KEY_AUTH:
		    {
			u_int len;
			if (sav->key_auth == NULL) break;
			len = sav->key_auth->sadb_key_len; /* real length */
			bcopy((caddr_t)sav->key_auth, p, len);
			((struct sadb_ext *)p)->sadb_ext_len = PFKEY_UNIT64(len);
			p += len;
		    }
			break;

		case SADB_EXT_KEY_ENCRYPT:
		    {
			u_int len;
			if (sav->key_enc == NULL) break;
			len = sav->key_enc->sadb_key_len; /* real length */
			bcopy((caddr_t)sav->key_enc, p, len);
			((struct sadb_ext *)p)->sadb_ext_len = PFKEY_UNIT64(len);
			p += len;
		    }
			break;;

		case SADB_EXT_LIFETIME_CURRENT:
			if (sav->lft_c == NULL) break;
			p = key_setsadbext(p, (caddr_t)sav->lft_c);
			break;

		case SADB_EXT_LIFETIME_HARD:
			if (sav->lft_h == NULL) break;
			p = key_setsadbext(p, (caddr_t)sav->lft_h);
			break;

		case SADB_EXT_LIFETIME_SOFT:
			if (sav->lft_s == NULL) break;
			p = key_setsadbext(p, (caddr_t)sav->lft_s);
			break;

		case SADB_EXT_IDENTITY_SRC:
		case SADB_EXT_IDENTITY_DST:
			/* XXX: should we brought from SPD ? */
		case SADB_EXT_SENSITIVITY:
		default:
			break;
		}
	}

	return tlen;
}

#if 1
static int
key_setsadbmsg_m(m, type, tlen, satype, seq, pid, mode, reqid,
		reserved1, reserved2)
	struct mbuf *m;
	u_int8_t type, satype;
	u_int16_t tlen;
	u_int32_t seq;
	pid_t pid;
	u_int8_t mode;
	u_int32_t reqid;
	u_int8_t reserved1;
	u_int32_t reserved2;
{
	caddr_t p;
	const size_t len = sizeof(struct sadb_msg);

	p = key_appendmbuf(m, len);
	if (p == NULL)
		return ENOBUFS;

	if (key_setsadbmsg(p, type, tlen, satype, seq, pid, mode, reqid,
			reserved1, reserved2))
		return 0;
	else
		return EINVAL;
}
#endif

/*
 * set data into sadb_msg.
 * `buf' must has been allocated sufficiently.
 */
static caddr_t
key_setsadbmsg(buf, type, tlen, satype, seq, pid, mode, reqid,
		reserved1, reserved2)
	caddr_t buf;
	u_int8_t type, satype;
	u_int16_t tlen;
	u_int32_t seq;
	pid_t pid;
	u_int8_t mode;
	u_int32_t reqid;
	u_int8_t reserved1;
	u_int32_t reserved2;
{
	struct sadb_msg *p;
	u_int len;

	p = (struct sadb_msg *)buf;
	len = sizeof(struct sadb_msg);

	bzero(p, len);
	p->sadb_msg_version = PF_KEY_V2;
	p->sadb_msg_type = type;
	p->sadb_msg_errno = 0;
	p->sadb_msg_satype = satype;
	p->sadb_msg_len = PFKEY_UNIT64(tlen);
	p->sadb_msg_mode = mode;
	p->sadb_msg_reserved1 = reserved1;
	p->sadb_msg_seq = seq;
	p->sadb_msg_pid = (u_int32_t)pid;
	p->sadb_msg_reqid = reqid;
	p->sadb_msg_reserved2 = reserved2;

	return(buf + len);
}

/*
 * copy secasvar data into sadb_address.
 * `buf' must has been allocated sufficiently.
 */
static caddr_t
key_setsadbsa(buf, sav)
	caddr_t buf;
	struct secasvar *sav;
{
	struct sadb_sa *p;
	u_int len;

	p = (struct sadb_sa *)buf;
	len = sizeof(struct sadb_sa);

	bzero(p, len);
	p->sadb_sa_len = PFKEY_UNIT64(len);
	p->sadb_sa_exttype = SADB_EXT_SA;
	p->sadb_sa_spi = sav->spi;
	p->sadb_sa_replay = (sav->replay != NULL ? sav->replay->wsize : 0);
	p->sadb_sa_state = sav->state;
	p->sadb_sa_auth = sav->alg_auth;
	p->sadb_sa_encrypt = sav->alg_enc;
	p->sadb_sa_flags = sav->flags;

	return(buf + len);
}

#if 1
static int
key_setsadbaddr_m(m, exttype, saddr, prefixlen, ul_proto)
	struct mbuf *m;
	u_int16_t exttype;
	struct sockaddr *saddr;
	u_int8_t prefixlen;
	u_int16_t ul_proto;
{
	caddr_t p;
	const size_t len =
	    sizeof(struct sadb_address) + PFKEY_ALIGN8(saddr->sa_len);

	p = key_appendmbuf(m, len);
	if (p == NULL)
		return ENOBUFS;

	if (key_setsadbaddr(p, exttype, saddr, prefixlen, ul_proto))
		return 0;
	else
		return EINVAL;
}
#endif

/*
 * set data into sadb_address.
 * `buf' must has been allocated sufficiently.
 */
static caddr_t
key_setsadbaddr(buf, exttype, saddr, prefixlen, ul_proto)
	caddr_t buf;
	u_int16_t exttype;
	struct sockaddr *saddr;
	u_int8_t prefixlen;
	u_int16_t ul_proto;
{
	struct sadb_address *p;
	size_t len;

	p = (struct sadb_address *)buf;
	len = sizeof(struct sadb_address) + PFKEY_ALIGN8(saddr->sa_len);

	bzero(p, len);
	p->sadb_address_len = PFKEY_UNIT64(len);
	p->sadb_address_exttype = exttype;
	p->sadb_address_proto = ul_proto;
	p->sadb_address_prefixlen = prefixlen;
	p->sadb_address_reserved = 0;

	bcopy(saddr, p + 1, saddr->sa_len);

	return(buf + len);
}

/*
 * set data into sadb_ident.
 * `buf' must has been allocated sufficiently.
 */
static caddr_t
key_setsadbident(buf, exttype, idtype, string, stringlen, id)
	caddr_t buf;
	u_int16_t exttype, idtype;
	caddr_t string;
	int stringlen;
	u_int64_t id;
{
	struct sadb_ident *p;
	u_int len;

	p = (struct sadb_ident *)buf;
	len = sizeof(struct sadb_ident) + PFKEY_ALIGN8(stringlen);

	bzero(p, len);
	p->sadb_ident_len = PFKEY_UNIT64(len);
	p->sadb_ident_exttype = exttype;
	p->sadb_ident_type = idtype;
	p->sadb_ident_reserved = 0;
	p->sadb_ident_id = id;

	bcopy(string, p + 1, stringlen);

	return(buf + len);
}

/*
 * set data into sadb_x_policy
 * `buf' must has been allocated sufficiently.
 */
static caddr_t
key_setsadbxpolicy(buf, type, dir, id)
	caddr_t buf;
	u_int16_t type;
	u_int8_t dir;
	u_int32_t id;
{
	struct sadb_x_policy *p;
	u_int len;

	p = (struct sadb_x_policy *)buf;
	len = sizeof(struct sadb_x_policy);

	bzero(p, len);
	p->sadb_x_policy_len = PFKEY_UNIT64(len);
	p->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	p->sadb_x_policy_type = type;
	p->sadb_x_policy_dir = dir;
	p->sadb_x_policy_id = id;

	return(buf + len);
}

/*
 * copy buffer of any sadb extension type into sadb_ext.
 * assume that sadb_ext_len shifted down >> 3.
 * i.e. shift length up when setting length of extension.
 */
static caddr_t
key_setsadbext(p, ext)
	caddr_t p, ext;
{
	u_int len;

	len = PFKEY_UNUNIT64(((struct sadb_ext *)ext)->sadb_ext_len);

	bcopy(ext, p, len);

	return(p + len);
}

/* %%% utilities */
/*
 * copy a buffer into the new buffer allocated.
 */
static void *
key_newbuf(src, len)
	void *src;
	u_int len;
{
	caddr_t new;

	KMALLOC(new, caddr_t, len);
	if (new == NULL) {
#if IPSEC_DEBUG
		printf("key_newbuf: No more memory.\n");
#endif
		return NULL;
	}
	bcopy((caddr_t)src, new, len);

	return new;
}

/* compare my own address
 * OUT:	1: true, i.e. my address.
 *	0: false
 */
int
key_ismyaddr(family, addr)
	u_int family;
	caddr_t addr;
{
	/* sanity check */
	if (addr == NULL)
		panic("key_ismyaddr: NULL pointer is passed.\n");

	switch (family) {
	case AF_INET:
	{
		struct in_ifaddr *ia;

#ifdef __NetBSD__
		for (ia = in_ifaddr.tqh_first; ia; ia = ia->ia_list.tqe_next)
#elif defined(__FreeBSD__) && __FreeBSD__ >= 3 || defined (__APPLE__)
		for (ia = in_ifaddrhead.tqh_first; ia;
		     ia = ia->ia_link.tqe_next)
#else
		for (ia = in_ifaddr; ia; ia = ia->ia_next)
#endif
			if (bcmp(addr,
			        (caddr_t)&ia->ia_addr.sin_addr,
			        _INALENBYAF(family)) == 0)
				return 1;
	}
		break;
#if INET6
	case AF_INET6:
		return key_ismyaddr6(addr);
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
key_ismyaddr6(addr)
	caddr_t addr;
{
	struct in6_addr *a = (struct in6_addr *)addr;
	struct in6_ifaddr *ia;

	for (ia = in6_ifaddr; ia; ia = ia->ia_next) {
		if (bcmp(addr, (caddr_t)&ia->ia_addr.sin6_addr,
				_INALENBYAF(AF_INET6)) == 0) {
			return 1;
		}

		/* XXX Multicast */
	    {
	  	struct	in6_multi *in6m = 0;

#if defined(__FreeBSD__) && __FreeBSD__ >= 3 || defined (__APPLE__)
		IN6_LOOKUP_MULTI(*(struct in6_addr *)addr, ia->ia_ifp, in6m);
#else
		for ((in6m) = ia->ia6_multiaddrs.lh_first;
		     (in6m) != NULL &&
		     !IN6_ARE_ADDR_EQUAL(&(in6m)->in6m_addr, a);
		     (in6m) = in6m->in6m_entry.le_next)
			continue;
#endif
		if (in6m)
			return 1;
	    }
	}

	/* loopback, just for safety */
	if (IN6_IS_ADDR_LOOPBACK(a))
		return 1;

#if 0
	/* FAITH */
	if (ip6_keepfaith &&
	    (a->s6_addr32[0] == ip6_faith_prefix.s6_addr32[0] &&
	     a->s6_addr32[1] == ip6_faith_prefix.s6_addr32[1] &&
	     a->s6_addr32[2] == ip6_faith_prefix.s6_addr32[2]))
		return 1;
#endif

	/* XXX anycast */

	return 0;
}
#endif /*INET6*/

#if 0
/* checking address is whether loopback or not.
 * OUT:	1:	true
 *	0:	false
 */
static int
key_isloopback(family, addr)
	u_int family;
	caddr_t addr;
{
	switch (family) {
	case PF_INET:
		if (((caddr_t)addr)[0] == IN_LOOPBACKNET)
			return 1;
		break;
#if INET6
	case PF_INET6:
		if (IN6_IS_ADDR_LOOPBACK((struct in6_addr *)addr))
			return 1;
		break;
#endif /* INET6 */
	default:
#if IPSEC_DEBUG
		printf("key_isloopback: unknown address family=%d.\n", family);
#endif
		return 0;
	}

	return 0;
}
#endif

/*
 * compare two secasindex structure exactly.
 * IN:
 *	saidx0: source, it can be in SAD.
 *	saidx1: object.
 * OUT:
 *	1 : equal
 *	0 : not equal
 */
static int
key_cmpsaidx_exactly(saidx0, saidx1)
	struct secasindex *saidx0, *saidx1;
{
	/* sanity */
	if (saidx0 == NULL && saidx1 == NULL)
		return 1;

	if (saidx0 == NULL || saidx1 == NULL)
		return 0;

	if (saidx0->proto != saidx1->proto
	 || saidx0->mode != saidx1->mode
	 || saidx0->reqid != saidx1->reqid)
		return 0;

	if (bcmp(&saidx0->src, &saidx1->src, saidx0->src.ss_len) != 0
	 || bcmp(&saidx0->dst, &saidx1->dst, saidx0->dst.ss_len) != 0)
		return 0;

	return 1;
}

/*
 * compare two secasindex structure with consideration mode.
 * don't compare port.
 * IN:
 *	saidx0: source, it is often in SAD.
 *	saidx1: object, it is often from SPD.
 * OUT:
 *	1 : equal
 *	0 : not equal
 */
static int
key_cmpsaidx_withmode(saidx0, saidx1)
	struct secasindex *saidx0, *saidx1;
{
	/* sanity */
	if (saidx0 == NULL && saidx1 == NULL)
		return 1;

	if (saidx0 == NULL || saidx1 == NULL)
		return 0;

	if (saidx0->proto != saidx1->proto
	 || saidx0->src.ss_family != saidx1->src.ss_family
	 || saidx0->dst.ss_family != saidx1->dst.ss_family)
		return 0;

	/*
	 * If reqid of SPD is non-zero, unique SA is required.
	 * The result must be of same reqid in this case.
	 */
	if (saidx1->reqid != 0
	 && saidx0->reqid != saidx1->reqid)
		return 0;

	if (saidx0->mode != IPSEC_MODE_ANY
	 && saidx0->mode != saidx1->mode)
		return 0;

    {
	int sa_len = _INALENBYAF(saidx0->src.ss_family);

	if (bcmp(_INADDRBYSA(&saidx0->src), _INADDRBYSA(&saidx1->src), sa_len)
	 || bcmp(_INADDRBYSA(&saidx0->dst), _INADDRBYSA(&saidx1->dst), sa_len))
		return 0;
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

	if (bcmp(&spidx0->src, &spidx1->src, spidx0->src.ss_len) != 0
	 || bcmp(&spidx0->dst, &spidx1->dst, spidx0->dst.ss_len) != 0)
		return 0;

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

	if (spidx0->src.ss_family != spidx1->src.ss_family
	 || spidx0->dst.ss_family != spidx1->dst.ss_family)
		return 0;

	/* if spidx.ul_proto == IPSEC_ULPROTO_ANY, ignore. */
	if (spidx0->ul_proto != (u_int16_t)IPSEC_ULPROTO_ANY
	 && spidx0->ul_proto != spidx1->ul_proto)
		return 0;

	if (_INPORTBYSA(&spidx0->src) != IPSEC_PORT_ANY
	 && _INPORTBYSA(&spidx0->src) != _INPORTBYSA(&spidx1->src))
		return 0;

	if (_INPORTBYSA(&spidx0->dst) != IPSEC_PORT_ANY
	 && _INPORTBYSA(&spidx0->dst) != _INPORTBYSA(&spidx1->dst))
		return 0;

	if (!key_bbcmp(_INADDRBYSA(&spidx0->src),
	               _INADDRBYSA(&spidx1->src),
	               spidx0->prefs))
		return 0;

	if (!key_bbcmp(_INADDRBYSA(&spidx0->dst),
	               _INADDRBYSA(&spidx1->dst),
	               spidx0->prefd))
		return 0;

	/* XXX Do we check other field ?  e.g. flowinfo, scope_id. */

	return 1;
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
	register caddr_t p1, p2;
	register u_int bits;
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
 */
void
key_timehandler(void)
{
	u_int dir;
	int s;

	thread_funnel_set(network_flock, TRUE);
#if __NetBSD__
	s = splsoftnet();	/*called from softclock()*/
#else
	s = splnet();	/*called from softclock()*/
#endif

	/* SPD */
    {
	struct secpolicy *sp, *nextsp;

	for (dir = 0; dir < IPSEC_DIR_MAX; dir++) {
		for (sp = LIST_FIRST(&sptree[dir]);
		     sp != NULL;
		     sp = nextsp) {

			nextsp = LIST_NEXT(sp, chain);

			if (sp->state == IPSEC_SPSTATE_DEAD)
				key_freesp(sp);
		}
	}
    }

	/* SAD */
    {
	struct secashead *sah, *nextsah;
	struct secasvar *sav, *nextsav;

	for (sah = LIST_FIRST(&sahtree);
	     sah != NULL;
	     sah = nextsah) {

		nextsah = LIST_NEXT(sah, chain);

		/* if sah has been dead, then delete it and process next sah. */
		if (sah->state == SADB_SASTATE_DEAD) {
			key_delsah(sah);
			continue;
		}

		/* if LARVAL entry doesn't become MATURE, delete it. */
		for (sav = LIST_FIRST(&sah->savtree[SADB_SASTATE_LARVAL]);
		     sav != NULL;
		     sav = nextsav) {

			nextsav = LIST_NEXT(sav, chain);

			sav->tick++;

			if (key_larval_lifetime < sav->tick) {
				key_freesav(sav);
			}
		}

		/*
		 * check MATURE entry to start to send expire message
		 * whether or not.
		 */
		for (sav = LIST_FIRST(&sah->savtree[SADB_SASTATE_MATURE]);
		     sav != NULL;
		     sav = nextsav) {

			nextsav = LIST_NEXT(sav, chain);

			sav->tick++;

			/* we don't need to check. */
			if (sav->lft_s == NULL)
				continue;

			/* sanity check */
			if (sav->lft_c == NULL) {
#if IPSEC_DEBUG
				printf("key_timehandler: "
					"There is no CURRENT time, why?\n");
#endif
				continue;
			}

			/* compare SOFT lifetime and tick */
			if (sav->lft_s->sadb_lifetime_addtime != 0
			 && sav->lft_s->sadb_lifetime_addtime < sav->tick) {
				/*
				 * check SA to be used whether or not.
				 * when SA hasn't been used, delete it.
				 */
				if (sav->lft_c->sadb_lifetime_usetime == 0) {
					key_sa_chgstate(sav, SADB_SASTATE_DEAD);
					key_freesav(sav);
					sav = NULL;
				} else {
					key_sa_chgstate(sav, SADB_SASTATE_DYING);
					/*
					 * XXX If we keep to send expire
					 * message in the status of
					 * DYING. Do remove below code.
					 */
					key_expire(sav);
				}
			}
			/* check SOFT lifetime by bytes */
			/*
			 * XXX I don't know the way to delete this SA
			 * when new SA is installed.  Caution when it's
			 * installed too big lifetime by time.
			 */
			else if (sav->lft_s->sadb_lifetime_bytes != 0
			      && sav->lft_s->sadb_lifetime_bytes < sav->lft_c->sadb_lifetime_bytes) {

				key_sa_chgstate(sav, SADB_SASTATE_DYING);
				/*
				 * XXX If we keep to send expire
				 * message in the status of
				 * DYING. Do remove below code.
				 */
				key_expire(sav);
			}
		}

		/* check DYING entry to change status to DEAD. */
		for (sav = LIST_FIRST(&sah->savtree[SADB_SASTATE_DYING]);
		     sav != NULL;
		     sav = nextsav) {

			nextsav = LIST_NEXT(sav, chain);

			sav->tick++;

			/* we don't need to check. */
			if (sav->lft_h == NULL)
				continue;

			/* sanity check */
			if (sav->lft_c == NULL) {
#if IPSEC_DEBUG
				printf("key_timehandler: "
					"There is no CURRENT time, why?\n");
#endif
				continue;
			}

			/* compare HARD lifetime and tick */
			if (sav->lft_h->sadb_lifetime_addtime != 0
			 && sav->lft_h->sadb_lifetime_addtime < sav->tick) {
				key_sa_chgstate(sav, SADB_SASTATE_DEAD);
				key_freesav(sav);
				sav = NULL;
			}
#if 0	/* XXX Should we keep to send expire message until HARD lifetime ? */
			else if (sav->lft_s != NULL
			      && sav->lft_s->sadb_lifetime_addtime != 0
			      && sav->lft_s->sadb_lifetime_addtime < sav->tick) {
				/*
				 * XXX: should be checked to be
				 * installed the valid SA.
				 */

				/*
				 * If there is no SA then sending
				 * expire message.
				 */
				key_expire(sav);
			}
#endif
			/* check HARD lifetime by bytes */
			else if (sav->lft_h->sadb_lifetime_bytes != 0
			      && sav->lft_h->sadb_lifetime_bytes < sav->lft_c->sadb_lifetime_bytes) {
				key_sa_chgstate(sav, SADB_SASTATE_DEAD);
				key_freesav(sav);
				sav = NULL;
			}
		}

		/* delete entry in DEAD */
		for (sav = LIST_FIRST(&sah->savtree[SADB_SASTATE_DEAD]);
		     sav != NULL;
		     sav = nextsav) {

			nextsav = LIST_NEXT(sav, chain);

			/* sanity check */
			if (sav->state != SADB_SASTATE_DEAD) {
#if IPSEC_DEBUG
				printf("key_timehandler: "
					"invalid sav->state "
					"(queue: %d SA: %d): "
					"kill it anyway\n",
					SADB_SASTATE_DEAD, sav->state);
#endif
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

#ifndef IPSEC_NONBLOCK_ACQUIRE
	/* ACQ tree */
    {
	struct secacq *acq, *nextacq;

	for (acq = LIST_FIRST(&acqtree);
	     acq != NULL;
	     acq = nextacq) {

		nextacq = LIST_NEXT(acq, chain);

		acq->tick++;

		if (key_blockacq_lifetime < acq->tick && __LIST_CHAINED(acq)) {
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

		acq->tick++;

		if (key_blockacq_lifetime < acq->tick && __LIST_CHAINED(acq)) {
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

#ifndef IPSEC_DEBUG2
	/* do exchange to tick time !! */
	(void)timeout((void *)key_timehandler, (void *)0, 100);
#endif /* IPSEC_DEBUG2 */

	splx(s);
	thread_funnel_set(network_funnel, FALSE);
	return;
}

/*
 * to initialize a seed for random()
 */
void
key_srandom()
{
	struct timeval tv;
#ifdef __bsdi__
	extern long randseed; /* it's defined at i386/i386/random.s */
#endif /* __bsdi__ */

	microtime(&tv);

#if defined(__FreeBSD__)
	srandom(tv.tv_usec);
#endif /* __FreeBSD__ */
#if defined(__APPLE__)
	random();
#endif
#ifdef __bsdi__
	randseed = tv.tv_usec;
#endif /* __bsdi__ */

	return;
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
#if 1	/*nonstandard*/
	case SADB_X_SATYPE_IPCOMP:
		return IPPROTO_IPCOMP;
		break;
#endif
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
#if 1	/*nonstandard*/
	case IPPROTO_IPCOMP:
		return SADB_X_SATYPE_IPCOMP;
		break;
#endif
	default:
		return 0;
	}
	/* NOTREACHED */
}

/* %%% PF_KEY */
/*
 * SADB_GETSPI processing is to receive
 *	<base, src address, dst address, (SPI range)>
 * from the IKMPd, to assign a unique spi value, to hang on the INBOUND
 * tree with the status of LARVAL, and send
 *	<base, SA(*), address(SD)>
 * to the IKMPd.
 *
 * IN:	mhp: pointer to the pointer to each header.
 * OUT:	NULL if fail.
 *	other if success, return pointer to the message to send.
 */
static struct sadb_msg *
key_getspi(mhp)
	caddr_t *mhp;
{
	struct sadb_msg *msg0;
	struct sadb_address *src0, *dst0;
	struct secasindex saidx;
	struct secashead *newsah;
	struct secasvar *newsav;
	u_int8_t proto;
	u_int32_t spi;

	/* sanity check */
	if (mhp == NULL || mhp[0] == NULL)
		panic("key_getspi: NULL pointer is passed.\n");

	msg0 = (struct sadb_msg *)mhp[0];

	if (mhp[SADB_EXT_ADDRESS_SRC] == NULL
	 || mhp[SADB_EXT_ADDRESS_DST] == NULL) {
#if IPSEC_DEBUG
		printf("key_getspi: invalid message is passed.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}

	src0 = (struct sadb_address *)(mhp[SADB_EXT_ADDRESS_SRC]);
	dst0 = (struct sadb_address *)(mhp[SADB_EXT_ADDRESS_DST]);

	/* map satype to proto */
	if ((proto = key_satype2proto(msg0->sadb_msg_satype)) == 0) {
#if IPSEC_DEBUG
		printf("key_getspi: invalid satype is passed.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}

	KEY_SETSECASIDX(proto, msg0, src0+1, dst0+1, &saidx);

	/* SPI allocation */
	spi = key_do_getnewspi((struct sadb_spirange *)mhp[SADB_EXT_SPIRANGE],
	                       &saidx);
	if (spi == 0) {
		msg0->sadb_msg_errno = EEXIST;
		return NULL;
	}

	/* get a SA index */
	if ((newsah = key_getsah(&saidx)) == NULL) {

		/* create a new SA index */
		if ((newsah = key_newsah(&saidx)) == NULL) {
#if IPSEC_DEBUG
			printf("key_getspi: No more memory.\n");
#endif
			msg0->sadb_msg_errno = ENOBUFS;
			return NULL;
		}
	}

	/* get a new SA */
	if ((newsav = key_newsav(mhp, newsah)) == NULL) {
		msg0->sadb_msg_errno = ENOBUFS;
		/* XXX don't free new SA index allocated in above. */
		return NULL;
	}

	/* set spi */
	newsav->spi = htonl(spi);

#ifndef IPSEC_NONBLOCK_ACQUIRE
	/* delete the entry in acqtree */
	if (msg0->sadb_msg_seq != 0) {
		struct secacq *acq;
		if ((acq = key_getacqbyseq(msg0->sadb_msg_seq)) != NULL) {
			/* reset counter in order to deletion by timehander. */
			acq->tick = key_blockacq_lifetime;
			acq->count = 0;
		}
    	}
#endif

    {
	struct sadb_msg *newmsg;
	u_int len;
	caddr_t p;

	/* create new sadb_msg to reply. */
	len = sizeof(struct sadb_msg)
	    + sizeof(struct sadb_sa)
	    + PFKEY_EXTLEN(mhp[SADB_EXT_ADDRESS_SRC])
	    + PFKEY_EXTLEN(mhp[SADB_EXT_ADDRESS_DST]);

	KMALLOC(newmsg, struct sadb_msg *, len);
	if (newmsg == NULL) {
#if IPSEC_DEBUG
		printf("key_getspi: No more memory.\n");
#endif
		msg0->sadb_msg_errno = ENOBUFS;
		return NULL;
	}
	bzero((caddr_t)newmsg, len);

	bcopy((caddr_t)mhp[0], (caddr_t)newmsg, sizeof(*msg0));
	newmsg->sadb_msg_seq = newsav->seq;
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(len);
	p = (caddr_t)newmsg + sizeof(*msg0);

      {
	struct sadb_sa *m_sa;
	m_sa = (struct sadb_sa *)p;
	m_sa->sadb_sa_len = PFKEY_UNIT64(sizeof(struct sadb_sa));
	m_sa->sadb_sa_exttype = SADB_EXT_SA;
	m_sa->sadb_sa_spi = htonl(spi);
	p += sizeof(struct sadb_sa);
      }

	p = key_setsadbext(p, mhp[SADB_EXT_ADDRESS_SRC]);
	p = key_setsadbext(p, mhp[SADB_EXT_ADDRESS_DST]);

	return newmsg;
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
	u_int32_t min, max;
	int count = key_spi_trycnt;

	/* set spi range to allocate */
	if (spirange != NULL) {
		min = spirange->sadb_spirange_min;
		max = spirange->sadb_spirange_max;
	} else {
		min = key_spi_minval;
		max = key_spi_maxval;
	}
	/* IPCOMP needs 2-byte SPI */
	if (saidx->proto == IPPROTO_IPCOMP) {
		u_int32_t t;
		if (min >= 0x10000)
			min = 0xffff;
		if (max >= 0x10000)
			max = 0xffff;
		if (min > max) {
			t = min; min = max; max = t;
		}
	}

	if (min == max) {
		if (key_checkspidup(saidx, min) != NULL) {
#if IPSEC_DEBUG
			printf("key_do_getnewspi: SPI %u exists already.\n", min);
#endif
			return 0;
		}

		count--; /* taking one cost. */
		newspi = min;

	} else {

		/* init SPI */
		newspi = 0;

		/* when requesting to allocate spi ranged */
		while (count--) {
			/* generate pseudo-random SPI value ranged. */
			newspi = min + (random() % ( max - min + 1 ));

			if (key_checkspidup(saidx, newspi) == NULL)
				break;
		}

		if (count == 0 || newspi == 0) {
#if IPSEC_DEBUG
			printf("key_do_getnewspi: to allocate spi is failed.\n");
#endif
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
 *   <base, SA, (lifetime(HSC),) address(SD), (address(P),)
 *       key(AE), (identity(SD),) (sensitivity)>
 * from the ikmpd, and update a secasvar entry whose status is SADB_SASTATE_LARVAL.
 * and send
 *   <base, SA, (lifetime(HSC),) address(SD), (address(P),)
 *       (identity(SD),) (sensitivity)>
 * to the ikmpd.
 *
 * IN:	mhp: pointer to the pointer to each header.
 * OUT:	NULL if fail.
 *	other if success, return pointer to the message to send.
 */
static struct sadb_msg *
key_update(mhp)
	caddr_t *mhp;
{
	struct sadb_msg *msg0;
	struct sadb_sa *sa0;
	struct sadb_address *src0, *dst0;
	struct secasindex saidx;
	struct secashead *sah;
	struct secasvar *sav;
	u_int16_t proto;

	/* sanity check */
	if (mhp == NULL || mhp[0] == NULL)
		panic("key_update: NULL pointer is passed.\n");

	msg0 = (struct sadb_msg *)mhp[0];

	/* map satype to proto */
	if ((proto = key_satype2proto(msg0->sadb_msg_satype)) == 0) {
#if IPSEC_DEBUG
		printf("key_update: invalid satype is passed.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}

	if (mhp[SADB_EXT_SA] == NULL
	 || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	 || mhp[SADB_EXT_ADDRESS_DST] == NULL
	 || (msg0->sadb_msg_satype == SADB_SATYPE_ESP
	  && mhp[SADB_EXT_KEY_ENCRYPT] == NULL)
	 || (msg0->sadb_msg_satype == SADB_SATYPE_AH
	  && mhp[SADB_EXT_KEY_AUTH] == NULL)
	 || (mhp[SADB_EXT_LIFETIME_HARD] != NULL
	  && mhp[SADB_EXT_LIFETIME_SOFT] == NULL)
	 || (mhp[SADB_EXT_LIFETIME_HARD] == NULL
	  && mhp[SADB_EXT_LIFETIME_SOFT] != NULL)) {
#if IPSEC_DEBUG
		printf("key_update: invalid message is passed.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}

	sa0 = (struct sadb_sa *)mhp[SADB_EXT_SA];
	src0 = (struct sadb_address *)(mhp[SADB_EXT_ADDRESS_SRC]);
	dst0 = (struct sadb_address *)(mhp[SADB_EXT_ADDRESS_DST]);

	KEY_SETSECASIDX(proto, msg0, src0+1, dst0+1, &saidx);

	/* get a SA header */
	if ((sah = key_getsah(&saidx)) == NULL) {
#if IPSEC_DEBUG
		printf("key_update: no SA index found.\n");
#endif
		msg0->sadb_msg_errno = ENOENT;
		return NULL;
	}

	/* set spidx if there */
	if (key_setident(sah, mhp) < 0)
		return NULL;

	/* find a SA with sequence number. */
#if IPSEC_DOSEQCHECK
	if (msg0->sadb_msg_seq != 0
	 && (sav = key_getsavbyseq(sah, msg0->sadb_msg_seq)) == NULL) {
#if IPSEC_DEBUG
		printf("key_update: no larval SA with sequence %u exists.\n",
			msg0->sadb_msg_seq);
#endif
		msg0->sadb_msg_errno = ENOENT;
		return NULL;
	}
#else
	if ((sav = key_getsavbyspi(sah, sa0->sadb_sa_spi)) == NULL) {
#if IPSEC_DEBUG
		printf("key_update: no such a SA found (spi:%u)\n",
			(u_int32_t)ntohl(sa0->sadb_sa_spi));
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}
#endif

	/* validity check */
	if (sav->sah->saidx.proto != proto) {
#if IPSEC_DEBUG
		printf("key_update: protocol mismatched (DB=%u param=%u)\n",
			sav->sah->saidx.proto, proto);
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}
#if IPSEC_DOSEQCHECK
	if (sav->spi != sa0->sadb_sa_spi) {
#if IPSEC_DEBUG
		printf("key_update: SPI mismatched (DB:%u param:%u)\n",
			(u_int32_t)ntohl(sav->spi),
			(u_int32_t)ntohl(sa0->sadb_sa_spi));
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}
#endif
	if (sav->pid != msg0->sadb_msg_pid) {
#if IPSEC_DEBUG
		printf("key_update: pid mismatched (DB:%u param:%u)\n",
			sav->pid, msg0->sadb_msg_pid);
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}

	/* copy sav values */
	if (key_setsaval(sav, mhp)) {
		key_freesav(sav);
		return NULL;
	}

	/* check SA values to be mature. */
	if ((msg0->sadb_msg_errno = key_mature(sav)) != 0) {
		key_freesav(sav);
		return NULL;
	}

    {
	struct sadb_msg *newmsg;

	/* set msg buf from mhp */
	if ((newmsg = key_getmsgbuf_x1(mhp)) == NULL) {
#if IPSEC_DEBUG
		printf("key_update: No more memory.\n");
#endif
		msg0->sadb_msg_errno = ENOBUFS;
		return NULL;
	}
	return newmsg;
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
 *   <base, SA, (lifetime(HSC),) address(SD), (address(P),)
 *       key(AE), (identity(SD),) (sensitivity)>
 * from the ikmpd,
 * and send
 *   <base, SA, (lifetime(HSC),) address(SD), (address(P),)
 *       (identity(SD),) (sensitivity)>
 * to the ikmpd.
 *
 * IGNORE identity and sensitivity messages.
 *
 * IN:	mhp: pointer to the pointer to each header.
 * OUT:	NULL if fail.
 *	other if success, return pointer to the message to send.
 */
static struct sadb_msg *
key_add(mhp)
	caddr_t *mhp;
{
	struct sadb_msg *msg0;
	struct sadb_sa *sa0;
	struct sadb_address *src0, *dst0;
	struct secasindex saidx;
	struct secashead *newsah;
	struct secasvar *newsav;
	u_int16_t proto;

	/* sanity check */
	if (mhp == NULL || mhp[0] == NULL)
		panic("key_add: NULL pointer is passed.\n");

	msg0 = (struct sadb_msg *)mhp[0];

	/* map satype to proto */
	if ((proto = key_satype2proto(msg0->sadb_msg_satype)) == 0) {
#if IPSEC_DEBUG
		printf("key_add: invalid satype is passed.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}

	if (mhp[SADB_EXT_SA] == NULL
	 || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	 || mhp[SADB_EXT_ADDRESS_DST] == NULL
	 || (msg0->sadb_msg_satype == SADB_SATYPE_ESP
	  && mhp[SADB_EXT_KEY_ENCRYPT] == NULL)
	 || (msg0->sadb_msg_satype == SADB_SATYPE_AH
	  && mhp[SADB_EXT_KEY_AUTH] == NULL)
	 || (mhp[SADB_EXT_LIFETIME_HARD] != NULL
	  && mhp[SADB_EXT_LIFETIME_SOFT] == NULL)
	 || (mhp[SADB_EXT_LIFETIME_HARD] == NULL
	  && mhp[SADB_EXT_LIFETIME_SOFT] != NULL)) {
#if IPSEC_DEBUG
		printf("key_add: invalid message is passed.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}

	sa0 = (struct sadb_sa *)mhp[SADB_EXT_SA];
	src0 = (struct sadb_address *)(mhp[SADB_EXT_ADDRESS_SRC]);
	dst0 = (struct sadb_address *)(mhp[SADB_EXT_ADDRESS_DST]);

	KEY_SETSECASIDX(proto, msg0, src0+1, dst0+1, &saidx);

	/* get a SA header */
	if ((newsah = key_getsah(&saidx)) == NULL) {

		/* create a new SA header */
		if ((newsah = key_newsah(&saidx)) == NULL) {
#if IPSEC_DEBUG
			printf("key_add: No more memory.\n");
#endif
			msg0->sadb_msg_errno = ENOBUFS;
			return NULL;
		}
	}

	/* set spidx if there */
	if (key_setident(newsah, mhp) < 0)
		return NULL;

	/* create new SA entry. */
	/* We can create new SA only if SPI is differenct. */
	if (key_getsavbyspi(newsah, sa0->sadb_sa_spi)) {
#if IPSEC_DEBUG
		printf("key_add: SA already exists.\n");
#endif
		msg0->sadb_msg_errno = EEXIST;
		return NULL;
	}
	if ((newsav = key_newsav(mhp, newsah)) == NULL)
		return NULL;

	/* check SA values to be mature. */
	if ((msg0->sadb_msg_errno = key_mature(newsav)) != NULL) {
		key_freesav(newsav);
		return NULL;
	}

	/*
	 * don't call key_freesav() here, as we would like to keep the SA
	 * in the database on success.
	 */

    {
	struct sadb_msg *newmsg;

	/* set msg buf from mhp */
	if ((newmsg = key_getmsgbuf_x1(mhp)) == NULL) {
#if IPSEC_DEBUG
		printf("key_add: No more memory.\n");
#endif
		msg0->sadb_msg_errno = ENOBUFS;
		return NULL;
	}

	return newmsg;
    }
}

static int
key_setident(sah, mhp)
	struct secashead *sah;
	caddr_t *mhp;
{
	struct sadb_msg *msg0;
	struct sadb_ident *idsrc, *iddst;
	int idsrclen, iddstlen;

	/* sanity check */
	if (sah == NULL || mhp == NULL || mhp[0] == NULL)
		panic("key_setident: NULL pointer is passed.\n");

	msg0 = (struct sadb_msg *)mhp[0];

	/* don't make buffer if not there */
	if (mhp[SADB_EXT_IDENTITY_SRC] == NULL
	 && mhp[SADB_EXT_IDENTITY_DST] == NULL) {
		sah->idents = NULL;
		sah->identd = NULL;
		return 0;
	}
	
	if (mhp[SADB_EXT_IDENTITY_SRC] == NULL
	 || mhp[SADB_EXT_IDENTITY_DST] == NULL) {
#if IPSEC_DEBUG
		printf("key_setident: invalid identity.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return -1;
	}

	idsrc = (struct sadb_ident *)mhp[SADB_EXT_IDENTITY_SRC];
	iddst = (struct sadb_ident *)mhp[SADB_EXT_IDENTITY_DST];
	idsrclen = PFKEY_UNUNIT64(idsrc->sadb_ident_len);
	iddstlen = PFKEY_UNUNIT64(idsrc->sadb_ident_len);

	/* validity check */
	if (idsrc->sadb_ident_type != iddst->sadb_ident_type) {
#if IPSEC_DEBUG
		printf("key_setident: ident type mismatch.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return -1;
	}

	switch (idsrc->sadb_ident_type) {
	case SADB_X_IDENTTYPE_ADDR:
		if (idsrclen !=
		    sizeof(*idsrc) + ((struct sockaddr *)(idsrc + 1))->sa_len
		 || iddstlen !=
		    sizeof(*iddst) + ((struct sockaddr *)(iddst + 1))->sa_len) {
#if IPSEC_DEBUG
			printf("key_setident: invalid length is passed.\n");
#endif
			msg0->sadb_msg_errno = EINVAL;
			return -1;
		}
		if (((struct sockaddr *)(idsrc + 1))->sa_len >
				sizeof(struct sockaddr_storage)
		 || ((struct sockaddr *)(iddst + 1))->sa_len >
				sizeof(struct sockaddr_storage)) {
#if IPSEC_DEBUG
			printf("key_setident: invalid sa_len is passed.\n");
#endif
			msg0->sadb_msg_errno = EINVAL;
			return -1;
		}
#define __IDENTXID(a) ((union sadb_x_ident_id *)&(a)->sadb_ident_id)
		if (__IDENTXID(idsrc)->sadb_x_ident_id_addr.ul_proto
		 != __IDENTXID(iddst)->sadb_x_ident_id_addr.ul_proto) {
#if IPSEC_DEBUG
			printf("key_setident: ul_proto mismatch.\n");
#endif
			msg0->sadb_msg_errno = EINVAL;
			return -1;
		}
#undef __IDENTXID(a)
		break;
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
	KMALLOC(sah->idents, struct sadb_ident *, idsrclen);
	if (sah->idents == NULL) {
#if IPSEC_DEBUG
		printf("key_setident: No more memory.\n");
#endif
		msg0->sadb_msg_errno = ENOBUFS;
		return -1;
	}
	KMALLOC(sah->identd, struct sadb_ident *, iddstlen);
	if (sah->identd == NULL) {
		KFREE(sah->idents);
#if IPSEC_DEBUG
		printf("key_setident: No more memory.\n");
#endif
		msg0->sadb_msg_errno = ENOBUFS;
		return -1;
	}
	bcopy(idsrc, sah->idents, idsrclen);
	bcopy(iddst, sah->identd, iddstlen);

	return 0;
}

static struct sadb_msg *
key_getmsgbuf_x1(mhp)
	caddr_t *mhp;
{
	struct sadb_msg *msg0;
	struct sadb_msg *newmsg;
	u_int len;
	caddr_t p;

	/* sanity check */
	if (mhp == NULL || mhp[0] == NULL)
		panic("key_getmsgbuf_x1: NULL pointer is passed.\n");

	msg0 = (struct sadb_msg *)mhp[0];

	/* create new sadb_msg to reply. */
	len = sizeof(struct sadb_msg)
	    + sizeof(struct sadb_sa)
	    + PFKEY_EXTLEN(mhp[SADB_EXT_ADDRESS_SRC])
	    + PFKEY_EXTLEN(mhp[SADB_EXT_ADDRESS_DST])
	    + (mhp[SADB_EXT_LIFETIME_HARD] == NULL
		? 0 : sizeof(struct sadb_lifetime))
	    + (mhp[SADB_EXT_LIFETIME_SOFT] == NULL
		? 0 : sizeof(struct sadb_lifetime))
	    + (mhp[SADB_EXT_IDENTITY_SRC] == NULL
		? 0 : PFKEY_EXTLEN(mhp[SADB_EXT_IDENTITY_SRC]))
	    + (mhp[SADB_EXT_IDENTITY_DST] == NULL
		? 0 : PFKEY_EXTLEN(mhp[SADB_EXT_IDENTITY_DST]));

	KMALLOC(newmsg, struct sadb_msg *, len);
	if (newmsg == NULL)
		return NULL;
	bzero((caddr_t)newmsg, len);

	bcopy((caddr_t)mhp[0], (caddr_t)newmsg, sizeof(*msg0));
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(len);
	p = (caddr_t)newmsg + sizeof(*msg0);

	p = key_setsadbext(p, mhp[SADB_EXT_SA]);
	p = key_setsadbext(p, mhp[SADB_EXT_ADDRESS_SRC]);
	p = key_setsadbext(p, mhp[SADB_EXT_ADDRESS_DST]);

	if (mhp[SADB_EXT_LIFETIME_HARD] != NULL)
		p = key_setsadbext(p, mhp[SADB_EXT_LIFETIME_HARD]);

	if (mhp[SADB_EXT_LIFETIME_SOFT] != NULL)
		p = key_setsadbext(p, mhp[SADB_EXT_LIFETIME_SOFT]);

	if (mhp[SADB_EXT_IDENTITY_SRC] != NULL)
		p = key_setsadbext(p, mhp[SADB_EXT_IDENTITY_SRC]);
	if (mhp[SADB_EXT_IDENTITY_DST] != NULL)
		p = key_setsadbext(p, mhp[SADB_EXT_IDENTITY_DST]);

	return newmsg;
}

/*
 * SADB_DELETE processing
 * receive
 *   <base, SA(*), address(SD)>
 * from the ikmpd, and set SADB_SASTATE_DEAD,
 * and send,
 *   <base, SA(*), address(SD)>
 * to the ikmpd.
 *
 * IN:	mhp: pointer to the pointer to each header.
 * OUT:	NULL if fail.
 *	other if success, return pointer to the message to send.
 */
static struct sadb_msg *
key_delete(mhp)
	caddr_t *mhp;
{
	struct sadb_msg *msg0;
	struct sadb_sa *sa0;
	struct sadb_address *src0, *dst0;
	struct secasindex saidx;
	struct secashead *sah;
	struct secasvar *sav;
	u_int16_t proto;

	/* sanity check */
	if (mhp == NULL || mhp[0] == NULL)
		panic("key_delete: NULL pointer is passed.\n");

	msg0 = (struct sadb_msg *)mhp[0];

	/* map satype to proto */
	if ((proto = key_satype2proto(msg0->sadb_msg_satype)) == 0) {
#if IPSEC_DEBUG
		printf("key_delete: invalid satype is passed.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}

	if (mhp[SADB_EXT_SA] == NULL
	 || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	 || mhp[SADB_EXT_ADDRESS_DST] == NULL) {
#if IPSEC_DEBUG
		printf("key_delete: invalid message is passed.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}
	sa0 = (struct sadb_sa *)mhp[SADB_EXT_SA];
	src0 = (struct sadb_address *)(mhp[SADB_EXT_ADDRESS_SRC]);
	dst0 = (struct sadb_address *)(mhp[SADB_EXT_ADDRESS_DST]);

	KEY_SETSECASIDX(proto, msg0, src0+1, dst0+1, &saidx);

	/* get a SA header */
	if ((sah = key_getsah(&saidx)) == NULL) {
#if IPSEC_DEBUG
		printf("key_delete: no SA found.\n");
#endif
		msg0->sadb_msg_errno = ENOENT;
		return NULL;
	}

	/* get a SA with SPI. */
	sav = key_getsavbyspi(sah, sa0->sadb_sa_spi);
	if (sav == NULL) {
#if IPSEC_DEBUG
		printf("key_delete: no alive SA found.\n");
#endif
		msg0->sadb_msg_errno = ENOENT;
		return NULL;
	}

	key_sa_chgstate(sav, SADB_SASTATE_DEAD);
	key_freesav(sav);
	sav = NULL;

    {
	struct sadb_msg *newmsg;
	u_int len;
	caddr_t p;

	/* create new sadb_msg to reply. */
	len = sizeof(struct sadb_msg)
	    + sizeof(struct sadb_sa)
	    + PFKEY_EXTLEN(mhp[SADB_EXT_ADDRESS_SRC])
	    + PFKEY_EXTLEN(mhp[SADB_EXT_ADDRESS_DST]);

	KMALLOC(newmsg, struct sadb_msg *, len);
	if (newmsg == NULL) {
#if IPSEC_DEBUG
		printf("key_delete: No more memory.\n");
#endif
		msg0->sadb_msg_errno = ENOBUFS;
		return NULL;
	}
	bzero((caddr_t)newmsg, len);

	bcopy((caddr_t)mhp[0], (caddr_t)newmsg, sizeof(*msg0));
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(len);
	p = (caddr_t)newmsg + sizeof(*msg0);

	p = key_setsadbext(p, mhp[SADB_EXT_SA]);
	p = key_setsadbext(p, mhp[SADB_EXT_ADDRESS_SRC]);
	p = key_setsadbext(p, mhp[SADB_EXT_ADDRESS_DST]);

	return newmsg;
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
 * IN:	mhp: pointer to the pointer to each header.
 * OUT:	NULL if fail.
 *	other if success, return pointer to the message to send.
 */
static struct sadb_msg *
key_get(mhp)
	caddr_t *mhp;
{
	struct sadb_msg *msg0;
	struct sadb_sa *sa0;
	struct sadb_address *src0, *dst0;
	struct secasindex saidx;
	struct secashead *sah;
	struct secasvar *sav;
	u_int16_t proto;

	/* sanity check */
	if (mhp == NULL || mhp[0] == NULL)
		panic("key_get: NULL pointer is passed.\n");

	msg0 = (struct sadb_msg *)mhp[0];

	/* map satype to proto */
	if ((proto = key_satype2proto(msg0->sadb_msg_satype)) == 0) {
#if IPSEC_DEBUG
		printf("key_get: invalid satype is passed.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}

	if (mhp[SADB_EXT_SA] == NULL
	 || mhp[SADB_EXT_ADDRESS_SRC] == NULL
	 || mhp[SADB_EXT_ADDRESS_DST] == NULL) {
#if IPSEC_DEBUG
		printf("key_get: invalid message is passed.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}
	sa0 = (struct sadb_sa *)mhp[SADB_EXT_SA];
	src0 = (struct sadb_address *)(mhp[SADB_EXT_ADDRESS_SRC]);
	dst0 = (struct sadb_address *)(mhp[SADB_EXT_ADDRESS_DST]);

	KEY_SETSECASIDX(proto, msg0, src0+1, dst0+1, &saidx);

	/* get a SA header */
	if ((sah = key_getsah(&saidx)) == NULL) {
#if IPSEC_DEBUG
		printf("key_get: no SA found.\n");
#endif
		msg0->sadb_msg_errno = ENOENT;
		return NULL;
	}

	/* get a SA with SPI. */
	sav = key_getsavbyspi(sah, sa0->sadb_sa_spi);
	if (sav == NULL) {
#if IPSEC_DEBUG
		printf("key_get: no SA with state of mature found.\n");
#endif
		msg0->sadb_msg_errno = ENOENT;
		return NULL;
	}

    {
	struct sadb_msg *newmsg;
	u_int len;
	u_int8_t satype;

	/* map proto to satype */
	if ((satype = key_proto2satype(sah->saidx.proto)) == 0) {
#if IPSEC_DEBUG
		printf("key_get: there was invalid proto in SAD.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}

	/* calculate a length of message buffer */
	len = key_getmsglen(sav);

	KMALLOC(newmsg, struct sadb_msg *, len);
	if (newmsg == NULL) {
#if IPSEC_DEBUG
		printf("key_get: No more memory.\n");
#endif
		msg0->sadb_msg_errno = ENOBUFS;
		return NULL;
	}

	/* create new sadb_msg to reply. */
	(void)key_setdumpsa(newmsg, sav, SADB_GET,
	                    satype, msg0->sadb_msg_seq, msg0->sadb_msg_pid);

	return newmsg;
    }
}

/*
 * SADB_ACQUIRE processing called by key_checkrequest() and key_acquire2().
 * send
 *   <base, SA, address(SD), (address(P)),
 *       (identity(SD),) (sensitivity,) proposal>
 * to KMD, and expect to receive
 *   <base> with SADB_ACQUIRE if error occured,
 * or
 *   <base, src address, dst address, (SPI range)> with SADB_GETSPI
 * from KMD by PF_KEY.
 *
 * sensitivity is not supported.
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
#ifndef IPSEC_NONBLOCK_ACQUIRE
	struct secacq *newacq;
#endif
	struct secpolicyindex *spidx = NULL;
	u_int8_t satype;
	int error;

	/* sanity check */
	if (saidx == NULL || sp == NULL)
		panic("key_acquire: NULL pointer is passed.\n");
	if ((satype = key_proto2satype(saidx->proto)) == 0)
		panic("key_acquire: invalid proto is passed.\n");

	spidx = &sp->spidx;

#ifndef IPSEC_NONBLOCK_ACQUIRE
	/*
	 * We never do anything about acquirng SA.  There is anather
	 * solution that kernel blocks to send SADB_ACQUIRE message until
	 * getting something message from IKEd.  In later case, to be
	 * managed with ACQUIRING list.
	 */
	/* get a entry to check whether sending message or not. */
	if ((newacq = key_getacq(saidx)) != NULL) {
		if (key_blockacq_count < newacq->count) {
			/* reset counter and do send message. */
			newacq->count = 0;
		} else {
			/* increment counter and do nothing. */
			newacq->count++;
			return 0;
		}
	} else {
		/* make new entry for blocking to send SADB_ACQUIRE. */
		if ((newacq = key_newacq(saidx)) == NULL)
			return ENOBUFS;

		/* add to acqtree */
		LIST_INSERT_HEAD(&acqtree, newacq, chain);
	}
#endif

    {
	struct sadb_msg *newmsg = NULL;
	union sadb_x_ident_id id;
	u_int len;
	caddr_t p;

	/* create new sadb_msg to reply. */
	len = sizeof(struct sadb_msg)
		+ sizeof(struct sadb_address)
		+ PFKEY_ALIGN8(saidx->src.ss_len)
		+ sizeof(struct sadb_address)
		+ PFKEY_ALIGN8(saidx->dst.ss_len)
		+ sizeof(struct sadb_x_policy)
		+ sizeof(struct sadb_ident)
		+ PFKEY_ALIGN8(spidx->src.ss_len)
		+ sizeof(struct sadb_ident)
		+ PFKEY_ALIGN8(spidx->dst.ss_len)
		+ sizeof(struct sadb_prop)
		+ sizeof(struct sadb_comb); /* XXX to be multiple */

	KMALLOC(newmsg, struct sadb_msg *, len);
	if (newmsg == 0) {
#if IPSEC_DEBUG
		printf("key_acquire: No more memory.\n");
#endif
		return ENOBUFS;
	}
	bzero((caddr_t)newmsg, len);

	newmsg->sadb_msg_version = PF_KEY_V2;
	newmsg->sadb_msg_type = SADB_ACQUIRE;
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_satype = satype;
	newmsg->sadb_msg_len = PFKEY_UNIT64(len);
	newmsg->sadb_msg_mode = saidx->mode;
	newmsg->sadb_msg_reqid = saidx->reqid;

#ifndef IPSEC_NONBLOCK_ACQUIRE
	newmsg->sadb_msg_seq = newacq->seq;
#else
	newmsg->sadb_msg_seq = (acq_seq = (acq_seq == ~0 ? 1 : ++acq_seq));
#endif

	newmsg->sadb_msg_pid = 0;

	p = (caddr_t)newmsg + sizeof(struct sadb_msg);

	/* set sadb_address for saidx's. */
	p = key_setsadbaddr(p,
	                    SADB_EXT_ADDRESS_SRC,
	                    (struct sockaddr *)&saidx->src,
	                    _INALENBYAF(saidx->src.ss_family) << 3,
	                    IPSEC_ULPROTO_ANY);
	p = key_setsadbaddr(p,
	                    SADB_EXT_ADDRESS_DST,
	                    (struct sockaddr *)&saidx->dst,
	                    _INALENBYAF(saidx->dst.ss_family) << 3,
	                    IPSEC_ULPROTO_ANY);

	/* set sadb_x_policy */
	p = key_setsadbxpolicy(p, sp->policy, sp->spidx.dir, sp->id);

	/* set sadb_address for spidx's. */
	bzero(&id, sizeof(id));
	id.sadb_x_ident_id_addr.prefix = spidx->prefs;
	id.sadb_x_ident_id_addr.ul_proto = spidx->ul_proto;
	p = key_setsadbident(p,
	                    SADB_EXT_IDENTITY_SRC,
			    SADB_X_IDENTTYPE_ADDR,
	                    (caddr_t)&spidx->src,
			    spidx->src.ss_len,
			    *(u_int64_t *)&id);

	bzero(&id, sizeof(id));
	id.sadb_x_ident_id_addr.prefix = spidx->prefd;
	id.sadb_x_ident_id_addr.ul_proto = spidx->ul_proto;
	p = key_setsadbident(p,
	                    SADB_EXT_IDENTITY_DST,
			    SADB_X_IDENTTYPE_ADDR,
	                    (caddr_t)&spidx->dst,
			    spidx->dst.ss_len,
			    *(u_int64_t *)&id);

	/* create proposal extension */
	/* set combination extension */
	/* XXX: to be defined by proposal database */
    {
	struct sadb_prop *prop;
	struct sadb_comb *comb;

	prop = (struct sadb_prop *)p;
	prop->sadb_prop_len = PFKEY_UNIT64(sizeof(*prop) + sizeof(*comb));
		/* XXX to be multiple */
	prop->sadb_prop_exttype = SADB_EXT_PROPOSAL;
	prop->sadb_prop_replay = 32;	/* XXX be variable ? */
	p += sizeof(struct sadb_prop);

	comb = (struct sadb_comb *)p;
	comb->sadb_comb_auth = SADB_AALG_SHA1HMAC; /* XXX ??? */
	comb->sadb_comb_encrypt = SADB_EALG_DESCBC; /* XXX ??? */
	comb->sadb_comb_flags = 0;
	comb->sadb_comb_auth_minbits = 8; /* XXX */
	comb->sadb_comb_auth_maxbits = 1024; /* XXX */
	comb->sadb_comb_encrypt_minbits = 64; /* XXX */
	comb->sadb_comb_encrypt_maxbits = 64; /* XXX */
	comb->sadb_comb_soft_allocations = 0;
	comb->sadb_comb_hard_allocations = 0;
	comb->sadb_comb_soft_bytes = 0;
	comb->sadb_comb_hard_bytes = 0;
	comb->sadb_comb_soft_addtime = 0;
	comb->sadb_comb_hard_addtime = 0;
	comb->sadb_comb_soft_usetime = 0;
	comb->sadb_comb_hard_usetime = 0;

	p += sizeof(*comb);
    }

#if 0 /* XXX Do it ?*/
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

	error = key_sendall(newmsg, len);
#if IPSEC_DEBUG
	if (error != 0)
		printf("key_acquire: key_sendall returned %d\n", error);
#endif
	return error;
    }

	return 0;
}

#ifndef IPSEC_NONBLOCK_ACQUIRE
static struct secacq *
key_newacq(saidx)
	struct secasindex *saidx;
{
	struct secacq *newacq;

	/* get new entry */
	KMALLOC(newacq, struct secacq *, sizeof(struct secacq));
	if (newacq == NULL) {
#if IPSEC_DEBUG
		printf("key_newacq: No more memory.\n");
#endif
		return NULL;
	}
	bzero(newacq, sizeof(*newacq));

	/* copy secindex */
	bcopy(saidx, &newacq->saidx, sizeof(newacq->saidx));
	newacq->seq = (acq_seq == ~0 ? 1 : ++acq_seq);
	newacq->tick = 0;
	newacq->count = 0;

	return newacq;
}

static struct secacq *
key_getacq(saidx)
	struct secasindex *saidx;
{
	struct secacq *acq;

	LIST_FOREACH(acq, &acqtree, chain) {
		if (key_cmpsaidx_exactly(saidx, &acq->saidx))
			return acq;
	}

	return NULL;
}

static struct secacq *
key_getacqbyseq(seq)
	u_int32_t seq;
{
	struct secacq *acq;

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

	/* get new entry */
	KMALLOC(acq, struct secspacq *, sizeof(struct secspacq));
	if (acq == NULL) {
#if IPSEC_DEBUG
		printf("key_newspacq: No more memory.\n");
#endif
		return NULL;
	}
	bzero(acq, sizeof(*acq));

	/* copy secindex */
	bcopy(spidx, &acq->spidx, sizeof(acq->spidx));
	acq->tick = 0;
	acq->count = 0;

	return acq;
}

static struct secspacq *
key_getspacq(spidx)
	struct secpolicyindex *spidx;
{
	struct secspacq *acq;

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
 * IN:	mhp: pointer to the pointer to each header.
 * OUT:	NULL if fail.
 *	other if success, return pointer to the message to send.
 */
static struct sadb_msg *
key_acquire2(mhp)
	caddr_t *mhp;
{
	struct sadb_msg *msg0;
	struct sadb_address *src0, *dst0;
	struct secasindex saidx;
	struct secashead *sah;
	u_int16_t proto;

	/* sanity check */
	if (mhp == NULL || mhp[0] == NULL)
		panic("key_acquire2: NULL pointer is passed.\n");

	msg0 = (struct sadb_msg *)mhp[0];

	/*
	 * Error message from KMd.
	 * We assume that if error was occured in IKEd, the length of PFKEY
	 * message is equal to the size of sadb_msg structure.
	 * We return ~0 even if error occured in this function.
	 */
	if (msg0->sadb_msg_len == PFKEY_UNIT64(sizeof(struct sadb_msg))) {

#ifndef IPSEC_NONBLOCK_ACQUIRE
		struct secacq *acq;

		/* check sequence number */
		if (msg0->sadb_msg_seq == 0) {
#if IPSEC_DEBUG
			printf("key_acquire2: must specify sequence number.\n");
#endif
			return (struct sadb_msg *)~0;
		}

		if ((acq = key_getacqbyseq(msg0->sadb_msg_seq)) == NULL) {
#if IPSEC_DEBUG
			printf("key_acquire2: "
				"invalid sequence number is passed.\n");
#endif
			return (struct sadb_msg *)~0;
		}

		/* reset acq counter in order to deletion by timehander. */
		acq->tick = key_blockacq_lifetime;
		acq->count = 0;
#endif
		return (struct sadb_msg *)~0;
		/* NOTREACHED */
	}

	/*
	 * This message is from user land.
	 */

	/* map satype to proto */
	if ((proto = key_satype2proto(msg0->sadb_msg_satype)) == 0) {
#if IPSEC_DEBUG
		printf("key_acquire2: invalid satype is passed.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}

	if (mhp[SADB_EXT_ADDRESS_SRC] == NULL
	 || mhp[SADB_EXT_ADDRESS_DST] == NULL
	 || mhp[SADB_EXT_PROPOSAL] == NULL) {
		/* error */
#if IPSEC_DEBUG
		printf("key_acquire2: invalid message is passed.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}
	src0 = (struct sadb_address *)(mhp[SADB_EXT_ADDRESS_SRC]);
	dst0 = (struct sadb_address *)(mhp[SADB_EXT_ADDRESS_DST]);

	KEY_SETSECASIDX(proto, msg0, src0+1, dst0+1, &saidx);

	/* get a SA index */
	if ((sah = key_getsah(&saidx)) != NULL) {
#if IPSEC_DEBUG
		printf("key_acquire2: a SA exists already.\n");
#endif
		msg0->sadb_msg_errno = EEXIST;
		return NULL;
	}

	msg0->sadb_msg_errno = key_acquire(&saidx, NULL);
	if (msg0->sadb_msg_errno != 0) {
#if IPSEC_DEBUG
		printf("key_acquire2: error %d returned "
			"from key_acquire.\n", msg0->sadb_msg_errno);
#endif
		return NULL;
	}

    {
	struct sadb_msg *newmsg;
	u_int len;

	/* create new sadb_msg to reply. */
	len = PFKEY_UNUNIT64(msg0->sadb_msg_len);

	KMALLOC(newmsg, struct sadb_msg *, len);
	if (newmsg == NULL) {
#if IPSEC_DEBUG
		printf("key_acquire2: No more memory.\n");
#endif
		msg0->sadb_msg_errno = ENOBUFS;
		return NULL;
	}
	bzero((caddr_t)newmsg, len);

	bcopy(mhp[0], (caddr_t)newmsg, len);

	return newmsg;
    }
}

/*
 * SADB_REGISTER processing.
 * If SATYPE_UNSPEC has been passed as satype, only return sabd_supported.
 * receive
 *   <base>
 * from the ikmpd, and register a socket to send PF_KEY messages,
 * and send
 *   <base, supported>
 * to KMD by PF_KEY.
 * If socket is detached, must free from regnode.
 * OUT:
 *    0     : succeed
 *    others: error number
 */
static struct sadb_msg *
key_register(mhp, so)
	caddr_t *mhp;
	struct socket *so;
{
	struct sadb_msg *msg0;
	struct secreg *reg, *newreg = 0;

	/* sanity check */
	if (mhp == NULL || so == NULL || mhp[0] == NULL)
		panic("key_register: NULL pointer is passed.\n");

	msg0 = (struct sadb_msg *)mhp[0];

	/* check for invalid register message */
	if (msg0->sadb_msg_satype >= sizeof(regtree)/sizeof(regtree[0])) {
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}

	/* When SATYPE_UNSPEC is specified, only return sabd_supported. */
	if (msg0->sadb_msg_satype == SADB_SATYPE_UNSPEC)
		goto setmsg;

	/* check whether existing or not */
	LIST_FOREACH(reg, &regtree[msg0->sadb_msg_satype], chain) {
		if (reg->so == so) {
#if IPSEC_DEBUG
			printf("key_register: socket exists already.\n");
#endif
			msg0->sadb_msg_errno = EEXIST;
			return NULL;
		}
	}

	/* create regnode */
	KMALLOC(newreg, struct secreg *, sizeof(struct secreg));
	if (newreg == NULL) {
#if IPSEC_DEBUG
		printf("key_register: No more memory.\n");
#endif
		msg0->sadb_msg_errno = ENOBUFS;
		return NULL;
	}
	bzero((caddr_t)newreg, sizeof(struct secreg));

	newreg->so = so;
	((struct keycb *)sotorawcb(so))->kp_registered++;

	/* add regnode to regtree. */
	LIST_INSERT_HEAD(&regtree[msg0->sadb_msg_satype], newreg, chain);

  setmsg:
  {
	struct sadb_msg *newmsg;
	struct sadb_supported *sup;
	u_int len, alen, elen;
	caddr_t p;

	/* create new sadb_msg to reply. */
	alen = sizeof(struct sadb_supported)
		+ ((SADB_AALG_MAX - 1) * sizeof(struct sadb_alg));

#if IPSEC_ESP
	elen = sizeof(struct sadb_supported)
		+ ((SADB_EALG_MAX - 1) * sizeof(struct sadb_alg));
#else
	elen = 0;
#endif

	len = sizeof(struct sadb_msg)
		+ alen
		+ elen;

	KMALLOC(newmsg, struct sadb_msg *, len);
	if (newmsg == NULL) {
#if IPSEC_DEBUG
		printf("key_register: No more memory.\n");
#endif
		msg0->sadb_msg_errno = ENOBUFS;
		return NULL;
	}
	bzero((caddr_t)newmsg, len);

	bcopy((caddr_t)mhp[0], (caddr_t)newmsg, sizeof(*msg0));
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(len);
	p = (caddr_t)newmsg + sizeof(*msg0);

	/* for authentication algorithm */
	sup = (struct sadb_supported *)p;
	sup->sadb_supported_len = PFKEY_UNIT64(alen);
	sup->sadb_supported_exttype = SADB_EXT_SUPPORTED_AUTH;
	p += sizeof(*sup);

    {
	int i;
	struct sadb_alg *alg;
	struct ah_algorithm *algo;

	for (i = 1; i < SADB_AALG_MAX; i++) {
		algo = &ah_algorithms[i];
		alg = (struct sadb_alg *)p;
		alg->sadb_alg_id = i;
		alg->sadb_alg_ivlen = 0;
		alg->sadb_alg_minbits = algo->keymin;
		alg->sadb_alg_maxbits = algo->keymax;
		p += sizeof(struct sadb_alg);
	}
    }

#if IPSEC_ESP
	/* for encryption algorithm */
	sup = (struct sadb_supported *)p;
	sup->sadb_supported_len = PFKEY_UNIT64(elen);
	sup->sadb_supported_exttype = SADB_EXT_SUPPORTED_ENCRYPT;
	p += sizeof(*sup);

    {
	int i;
	struct sadb_alg *alg;
	struct esp_algorithm *algo;

	for (i = 1; i < SADB_EALG_MAX; i++) {
		algo = &esp_algorithms[i];

		alg = (struct sadb_alg *)p;
		alg->sadb_alg_id = i;
		if (algo && algo->ivlen) {
			/*
			 * give NULL to get the value preferred by algorithm
			 * XXX SADB_X_EXT_DERIV ?
			 */
			alg->sadb_alg_ivlen = (*algo->ivlen)(NULL);
		} else
			alg->sadb_alg_ivlen = 0;
		alg->sadb_alg_minbits = algo->keymin;
		alg->sadb_alg_maxbits = algo->keymax;
		p += sizeof(struct sadb_alg);
	}
    }
#endif

	return newmsg;
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
	
	return;
}

/*
 * SADB_EXPIRE processing
 * send
 *   <base, SA, lifetime(C and one of HS), address(SD)>
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
	int s;
	int satype;

	/* XXX: Why do we lock ? */
#ifdef __NetBSD__
	s = splsoftnet();	/*called from softclock()*/
#else
	s = splnet();	/*called from softclock()*/
#endif

	/* sanity check */
	if (sav == NULL)
		panic("key_expire: NULL pointer is passed.\n");
	if (sav->sah == NULL)
		panic("key_expire: Why was SA index in SA NULL.\n");
	if ((satype = key_proto2satype(sav->sah->saidx.proto)) == 0)
		panic("key_expire: invalid proto is passed.\n");

    {
	struct sadb_msg *newmsg = NULL;
	u_int len;
	caddr_t p;
	int error;

	/* create new sadb_msg to reply. */
	len = sizeof(struct sadb_msg)
		+ sizeof(struct sadb_sa)
		+ sizeof(struct sadb_lifetime)
		+ sizeof(struct sadb_lifetime)
		+ sizeof(struct sadb_address)
		+ PFKEY_ALIGN8(sav->sah->saidx.src.ss_len)
		+ sizeof(struct sadb_address)
		+ PFKEY_ALIGN8(sav->sah->saidx.dst.ss_len);

	KMALLOC(newmsg, struct sadb_msg *, len);
	if (newmsg == NULL) {
#if IPSEC_DEBUG
		printf("key_expire: No more memory.\n");
#endif
		splx(s);
		return ENOBUFS;
	}
	bzero((caddr_t)newmsg, len);

	/* set msg header */
	p = key_setsadbmsg((caddr_t)newmsg, SADB_EXPIRE, len,
	                   satype, sav->seq, 0,
	                   sav->sah->saidx.mode, sav->sah->saidx.reqid,
			   0, sav->refcnt);

	/* create SA extension */
	p = key_setsadbsa(p, sav);

	/* create lifetime extension */
    {
	struct sadb_lifetime *m_lt = (struct sadb_lifetime *)p;

	m_lt->sadb_lifetime_len = PFKEY_UNIT64(sizeof(struct sadb_lifetime));
	m_lt->sadb_lifetime_exttype = SADB_EXT_LIFETIME_CURRENT;
	m_lt->sadb_lifetime_allocations = sav->lft_c->sadb_lifetime_allocations;
	m_lt->sadb_lifetime_bytes = sav->lft_c->sadb_lifetime_bytes;
	m_lt->sadb_lifetime_addtime = sav->lft_c->sadb_lifetime_addtime;
	m_lt->sadb_lifetime_usetime = sav->lft_c->sadb_lifetime_usetime;
	p += sizeof(struct sadb_lifetime);

	/* copy SOFT lifetime extension. */
	bcopy(sav->lft_s, p, sizeof(struct sadb_lifetime));
	p += sizeof(struct sadb_lifetime);
    }

	/* set sadb_address for source */
	p = key_setsadbaddr(p,
	                    SADB_EXT_ADDRESS_SRC,
	                    (struct sockaddr *)&sav->sah->saidx.src,
	                    _INALENBYAF(sav->sah->saidx.src.ss_family) << 3,
	                    IPSEC_ULPROTO_ANY);

	/* set sadb_address for destination */
	p = key_setsadbaddr(p,
	                    SADB_EXT_ADDRESS_DST,
	                    (struct sockaddr *)&sav->sah->saidx.dst,
	                    _INALENBYAF(sav->sah->saidx.dst.ss_family) << 3,
	                    IPSEC_ULPROTO_ANY);

	error = key_sendall(newmsg, len);
	splx(s);
	return error;
    }
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
 * IN:	mhp: pointer to the pointer to each header.
 * OUT:	NULL if fail.
 *	other if success, return pointer to the message to send.
 */
static struct sadb_msg *
key_flush(mhp)
	caddr_t *mhp;
{
	struct sadb_msg *msg0;
	struct secashead *sah, *nextsah;
	struct secasvar *sav, *nextsav;
	u_int16_t proto;
	u_int8_t state;
	u_int stateidx;

	/* sanity check */
	if (mhp == NULL || mhp[0] == NULL)
		panic("key_flush: NULL pointer is passed.\n");

	msg0 = (struct sadb_msg *)mhp[0];

	/* map satype to proto */
	if ((proto = key_satype2proto(msg0->sadb_msg_satype)) == 0) {
#if IPSEC_DEBUG
		printf("key_flush: invalid satype is passed.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}

	/* no SATYPE specified, i.e. flushing all SA. */
	for (sah = LIST_FIRST(&sahtree);
	     sah != NULL;
	     sah = nextsah) {

		nextsah = LIST_NEXT(sah, chain);

		if (msg0->sadb_msg_satype != SADB_SATYPE_UNSPEC
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
				key_freesav(sav);
			}
		}

		sah->state = SADB_SASTATE_DEAD;
	}

    {
	struct sadb_msg *newmsg;
	u_int len;

	/* create new sadb_msg to reply. */
	len = sizeof(struct sadb_msg);

	KMALLOC(newmsg, struct sadb_msg *, len);
	if (newmsg == NULL) {
#if IPSEC_DEBUG
		printf("key_flush: No more memory.\n");
#endif
		msg0->sadb_msg_errno = ENOBUFS;
		return NULL;
	}
	bzero((caddr_t)newmsg, len);

	bcopy((caddr_t)mhp[0], (caddr_t)newmsg, sizeof(*msg0));
	newmsg->sadb_msg_errno = 0;
	newmsg->sadb_msg_len = PFKEY_UNIT64(len);

	return newmsg;
    }
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
 * IN:	mhp: pointer to the pointer to each header.
 * OUT:	error code.  0 on success.
 */
static int
key_dump(mhp, so, target)
	caddr_t *mhp;
	struct socket *so;
	int target;
{
	struct sadb_msg *msg0;
	struct secashead *sah;
	struct secasvar *sav;
	u_int16_t proto;
	u_int stateidx;
	u_int8_t satype;
	u_int8_t state;
	int len, cnt;
	struct sadb_msg *newmsg;

	/* sanity check */
	if (mhp == NULL || mhp[0] == NULL)
		panic("key_dump: NULL pointer is passed.\n");

	msg0 = (struct sadb_msg *)mhp[0];

	/* map satype to proto */
	if ((proto = key_satype2proto(msg0->sadb_msg_satype)) == 0) {
#if IPSEC_DEBUG
		printf("key_dump: invalid satype is passed.\n");
#endif
		msg0->sadb_msg_errno = EINVAL;
		return NULL;
	}

	/* count sav entries to be sent to the userland. */
	cnt = 0;
	LIST_FOREACH(sah, &sahtree, chain) {

		if (msg0->sadb_msg_satype != SADB_SATYPE_UNSPEC
		 && proto != sah->saidx.proto)
			continue;

		for (stateidx = 0;
		     stateidx < _ARRAYLEN(saorder_state_any);
		     stateidx++) {

			state = saorder_state_any[stateidx];
			LIST_FOREACH(sav, &sah->savtree[state], chain) {
				cnt++;
			}
		}
	}

	if (cnt == 0)
		return ENOENT;

	/* send this to the userland, one at a time. */
	newmsg = NULL;
	LIST_FOREACH(sah, &sahtree, chain) {

		if (msg0->sadb_msg_satype != SADB_SATYPE_UNSPEC
		 && proto != sah->saidx.proto)
			continue;

		/* map proto to satype */
		if ((satype = key_proto2satype(sah->saidx.proto)) == 0) {
#if IPSEC_DEBUG
			printf("key_dump: there was invalid proto in SAD.\n");
#endif
			msg0->sadb_msg_errno = EINVAL;
			return NULL;
		}

		for (stateidx = 0;
		     stateidx < _ARRAYLEN(saorder_state_any);
		     stateidx++) {

			state = saorder_state_any[stateidx];
			LIST_FOREACH(sav, &sah->savtree[state], chain) {

				len = key_getmsglen(sav);
				KMALLOC(newmsg, struct sadb_msg *, len);
				if (newmsg == NULL) {
#if IPSEC_DEBUG
					printf("key_dump: No more memory.\n");
#endif
					return ENOBUFS;
				}
				bzero((caddr_t)newmsg, len);

				--cnt;
				(void)key_setdumpsa(newmsg, sav, SADB_DUMP,
				               satype, cnt, msg0->sadb_msg_pid);

				key_sendup(so, newmsg, len, target);
				KFREE(newmsg);
				newmsg = NULL;
			}
		}
	}

	return 0;
}

/*
 * SADB_X_PROMISC processing
 */
static void
key_promisc(mhp, so)
	caddr_t *mhp;
	struct socket *so;
{
	struct sadb_msg *msg0;
	int olen;

	/* sanity check */
	if (mhp == NULL || mhp[0] == NULL)
		panic("key_promisc: NULL pointer is passed.\n");

	msg0 = (struct sadb_msg *)mhp[0];
	olen = PFKEY_UNUNIT64(msg0->sadb_msg_len);

	if (olen < sizeof(struct sadb_msg)) {
		return;
	} else if (olen == sizeof(struct sadb_msg)) {
		/* enable/disable promisc mode */
		struct keycb *kp;
		int target = 0;

		target = KEY_SENDUP_ONE;

		if (so == NULL) {
			return;
		}
		if ((kp = (struct keycb *)sotorawcb(so)) == NULL) {
			msg0->sadb_msg_errno = EINVAL;
			goto sendorig;
		}
		msg0->sadb_msg_errno = 0;
		if (msg0->sadb_msg_satype == 1 || msg0->sadb_msg_satype == 0) {
			kp->kp_promisc = msg0->sadb_msg_satype;
		} else {
			msg0->sadb_msg_errno = EINVAL;
			goto sendorig;
		}

		/* send the original message back to everyone */
		msg0->sadb_msg_errno = 0;
		target = KEY_SENDUP_ALL;
sendorig:
		key_sendup(so, msg0, PFKEY_UNUNIT64(msg0->sadb_msg_len), target);
	} else {
		/* send packet as is */
		struct sadb_msg *msg;
		int len;

		len = olen - sizeof(struct sadb_msg);
		KMALLOC(msg, struct sadb_msg *, len);
		if (msg == NULL) {
			msg0->sadb_msg_errno = ENOBUFS;
			key_sendup(so, msg0, PFKEY_UNUNIT64(msg0->sadb_msg_len),
				KEY_SENDUP_ONE);	/*XXX*/
		}

		/* XXX if sadb_msg_seq is specified, send to specific pid */
		key_sendup(so, msg, len, KEY_SENDUP_ALL);
		KFREE(msg);
	}
}

/*
 * send message to the socket.
 * OUT:
 *	0	: success
 *	others	: fail
 */
static int
key_sendall(msg, len)
	struct sadb_msg *msg;
	u_int len;
{
	struct secreg *reg;
	int error = 0;

	/* sanity check */
	if (msg == NULL)
		panic("key_sendall: NULL pointer is passed.\n");

	/* search table registerd socket to send a message. */
	LIST_FOREACH(reg, &regtree[msg->sadb_msg_satype], chain) {
		error = key_sendup(reg->so, msg, len, KEY_SENDUP_ONE);
		if (error != 0) {
#if IPSEC_DEBUG
			if (error == ENOBUFS)
				printf("key_sendall: No more memory.\n");
			else {
				printf("key_sendall: key_sendup returned %d\n",
					error);
			}
#endif
			KFREE(msg);
			return error;
		}
	}

	KFREE(msg);
	return 0;
}

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
key_parse(msgp, so, targetp)
	struct sadb_msg **msgp;
	struct socket *so;
	int *targetp;
{
	struct sadb_msg *msg = *msgp, *newmsg = NULL;
	caddr_t mhp[SADB_EXT_MAX + 1];
	u_int orglen;
	int error;

	/* sanity check */
	if (msg == NULL || so == NULL)
		panic("key_parse: NULL pointer is passed.\n");

	KEYDEBUG(KEYDEBUG_KEY_DUMP,
		printf("key_parse: passed sadb_msg\n");
		kdebug_sadb(msg));

	orglen = PFKEY_UNUNIT64(msg->sadb_msg_len);

	if (targetp)
		*targetp = KEY_SENDUP_ONE;

	/* check version */
	if (msg->sadb_msg_version != PF_KEY_V2) {
#if IPSEC_DEBUG
		printf("key_parse: PF_KEY version %u is mismatched.\n",
		    msg->sadb_msg_version);
#endif
		pfkeystat.out_invver++;
		msg->sadb_msg_errno = EINVAL;
		return orglen;
	}

	/* check type */
	if (msg->sadb_msg_type > SADB_MAX) {
#if IPSEC_DEBUG
		printf("key_parse: invalid type %u is passed.\n",
		    msg->sadb_msg_type);
#endif
		msg->sadb_msg_errno = EINVAL;
		pfkeystat.out_invmsgtype++;
		return orglen;
	}

	/* align message. */
	if (key_align(msg, mhp) != 0) {
		msg->sadb_msg_errno = EINVAL;
		return orglen;
	}

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
#if IPSEC_DEBUG
			printf("key_parse: must specify satype "
				"when msg type=%u.\n",
				msg->sadb_msg_type);
#endif
			msg->sadb_msg_errno = EINVAL;
			pfkeystat.out_invsatype++;
			return orglen;
		}
		break;
	case SADB_SATYPE_AH:
	case SADB_SATYPE_ESP:
#if 1 /*nonstandard*/
	case SADB_X_SATYPE_IPCOMP:
#endif
		switch (msg->sadb_msg_type) {
		case SADB_X_SPDADD:
		case SADB_X_SPDDELETE:
		case SADB_X_SPDGET:
		case SADB_X_SPDDUMP:
		case SADB_X_SPDFLUSH:
		case SADB_X_SPDSETIDX:
		case SADB_X_SPDUPDATE:
		case SADB_X_SPDDELETE2:
#if IPSEC_DEBUG
			printf("key_parse: illegal satype=%u\n",
			    msg->sadb_msg_type);
#endif
			msg->sadb_msg_errno = EINVAL;
			pfkeystat.out_invsatype++;
			return orglen;
		}
		break;
	case SADB_SATYPE_RSVP:
	case SADB_SATYPE_OSPFV2:
	case SADB_SATYPE_RIPV2:
	case SADB_SATYPE_MIP:
#if IPSEC_DEBUG
		printf("key_parse: type %u isn't supported.\n",
		    msg->sadb_msg_satype);
#endif
		msg->sadb_msg_errno = EOPNOTSUPP;
		pfkeystat.out_invsatype++;
		return orglen;
	case 1:	/* XXX: What does it do ? */
		if (msg->sadb_msg_type == SADB_X_PROMISC)
			break;
		/*FALLTHROUGH*/
	default:
#if IPSEC_DEBUG
		printf("key_parse: invalid type %u is passed.\n",
		    msg->sadb_msg_satype);
#endif
		msg->sadb_msg_errno = EINVAL;
		pfkeystat.out_invsatype++;
		return orglen;
	}

	/* check field of upper layer protocol and address family */
	if (mhp[SADB_EXT_ADDRESS_SRC] != NULL
	 && mhp[SADB_EXT_ADDRESS_DST] != NULL) {
		struct sadb_address *src0, *dst0;
		u_int prefix;

		src0 = (struct sadb_address *)(mhp[SADB_EXT_ADDRESS_SRC]);
		dst0 = (struct sadb_address *)(mhp[SADB_EXT_ADDRESS_DST]);

		/* check upper layer protocol */
		if (src0->sadb_address_proto != dst0->sadb_address_proto) {
#if IPSEC_DEBUG
			printf("key_parse: upper layer protocol mismatched.\n");
#endif
			msg->sadb_msg_errno = EINVAL;
			pfkeystat.out_invaddr++;
			return orglen;
		}

		/* check family */
		if (PFKEY_ADDR_SADDR(src0)->sa_family
		 != PFKEY_ADDR_SADDR(dst0)->sa_family) {
#if IPSEC_DEBUG
			printf("key_parse: address family mismatched.\n");
#endif
			msg->sadb_msg_errno = EINVAL;
			pfkeystat.out_invaddr++;
			return orglen;
		}

		prefix = _INALENBYAF(PFKEY_ADDR_SADDR(src0)->sa_family) << 3;

		/* check max prefixlen */
		if (prefix < src0->sadb_address_prefixlen
		 || prefix < dst0->sadb_address_prefixlen) {
#if IPSEC_DEBUG
			printf("key_parse: illegal prefixlen.\n");
#endif
			msg->sadb_msg_errno = EINVAL;
			pfkeystat.out_invaddr++;
			return orglen;
		}

		switch (PFKEY_ADDR_SADDR(src0)->sa_family) {
		case AF_INET:
		case AF_INET6:
			break;
		default:
#if IPSEC_DEBUG
			printf("key_parse: invalid address family.\n");
#endif
			msg->sadb_msg_errno = EINVAL;
			pfkeystat.out_invaddr++;
			return orglen;
		}

		/*
		 * prefixlen == 0 is valid because there can be a case when
		 * all addresses are matched.
		 */
	}

	switch (msg->sadb_msg_type) {
	case SADB_GETSPI:
		if ((newmsg = key_getspi(mhp)) == NULL)
			return orglen;
		if (targetp)
			*targetp = KEY_SENDUP_ALL;
		break;

	case SADB_UPDATE:
		if ((newmsg = key_update(mhp)) == NULL)
			return orglen;
		if (targetp)
			*targetp = KEY_SENDUP_ALL;
		break;

	case SADB_ADD:
		if ((newmsg = key_add(mhp)) == NULL)
			return orglen;
		if (targetp)
			*targetp = KEY_SENDUP_ALL;
		break;

	case SADB_DELETE:
		if ((newmsg = key_delete(mhp)) == NULL)
			return orglen;
		if (targetp)
			*targetp = KEY_SENDUP_ALL;
		break;

	case SADB_GET:
		if ((newmsg = key_get(mhp)) == NULL)
			return orglen;
		break;

	case SADB_ACQUIRE:
		if ((newmsg = key_acquire2(mhp)) == NULL)
			return orglen;

		if (newmsg == (struct sadb_msg *)~0) {
			/*
			 * It's not need to reply because of the message
			 * that was reporting an error occured from the KMd.
			 */
			KFREE(msg);
			return 0;
		}
		break;

	case SADB_REGISTER:
		if ((newmsg = key_register(mhp, so)) == NULL)
			return orglen;
#if 1
		if (targetp)
			*targetp = KEY_SENDUP_REGISTERED;
#else
		/* send result to all registered sockets */
		KFREE(msg);
		key_sendall(newmsg, PFKEY_UNUNIT64(newmsg->sadb_msg_len));
		return 0;
#endif
		break;

	case SADB_EXPIRE:
#if IPSEC_DEBUG
		printf("key_parse: why is SADB_EXPIRE received ?\n");
#endif
		msg->sadb_msg_errno = EINVAL;
		if (targetp)
			*targetp = KEY_SENDUP_ALL;
		pfkeystat.out_invmsgtype++;
		return orglen;

	case SADB_FLUSH:
		if ((newmsg = key_flush(mhp)) == NULL)
			return orglen;
		if (targetp)
			*targetp = KEY_SENDUP_ALL;
		break;

	case SADB_DUMP:
		/* key_dump will call key_sendup() on her own */
		error = key_dump(mhp, so, KEY_SENDUP_ONE);
		if (error) {
			msg->sadb_msg_errno = error;
			return orglen;
		} else {
			KFREE(msg);
			return 0;
		}
	        break;

	case SADB_X_PROMISC:
		/* everything is handled in key_promisc() */
		key_promisc(mhp, so);
		KFREE(msg);
		return 0;	/*nothing to reply*/

	case SADB_X_PCHANGE:
#if IPSEC_DEBUG
		printf("key_parse: SADB_X_PCHANGE isn't supported.\n");
#endif
		msg->sadb_msg_errno = EINVAL;
		pfkeystat.out_invmsgtype++;
		return orglen;
#if 0
		if (targetp)
			*targetp = KEY_SENDUP_REGISTERED;
#endif

	case SADB_X_SPDADD:
	case SADB_X_SPDSETIDX:
	case SADB_X_SPDUPDATE:
		if ((newmsg = key_spdadd(mhp)) == NULL)
			return orglen;
		if (targetp)
			*targetp = KEY_SENDUP_ALL;
	        break;

	case SADB_X_SPDDELETE:
		if ((newmsg = key_spddelete(mhp)) == NULL)
			return orglen;
		if (targetp)
			*targetp = KEY_SENDUP_ALL;
	        break;

	case SADB_X_SPDDELETE2:
		if ((newmsg = key_spddelete2(mhp)) == NULL)
			return orglen;
		if (targetp)
			*targetp = KEY_SENDUP_ALL;
	        break;

	case SADB_X_SPDGET:
		/* key_spdget will call key_sendup() on her own */
		error = key_spdget(mhp, so, KEY_SENDUP_ONE);
		if (error) {
			msg->sadb_msg_errno = error;
			return orglen;
		} else {
			KFREE(msg);
			return 0;
		}
	        break;

	case SADB_X_SPDDUMP:
		/* key_spddump will call key_sendup() on her own */
		error = key_spddump(mhp, so, KEY_SENDUP_ONE);
		if (error) {
			msg->sadb_msg_errno = error;
			return orglen;
		} else {
			KFREE(msg);
			return 0;
		}
	        break;

	case SADB_X_SPDFLUSH:
		if ((newmsg = key_spdflush(mhp)) == NULL)
			return orglen;
		if (targetp)
			*targetp = KEY_SENDUP_ALL;
	        break;

	default:
		msg->sadb_msg_errno = EOPNOTSUPP;
		return orglen;
	}

	/* switch from old sadb_msg to new one if success. */
	KFREE(msg);
	*msgp = newmsg;

	return PFKEY_UNUNIT64((*msgp)->sadb_msg_len);
}

/*
 * set the pointer to each header into message buffer.
 * IN:	msg: pointer to message buffer.
 *	mhp: pointer to the buffer allocated like below:
 *		caddr_t mhp[SADB_EXT_MAX + 1];
 * OUT: 0:
 *      EINVAL:
 */
static int
key_align(msg, mhp)
	struct sadb_msg *msg;
	caddr_t *mhp;
{
	struct sadb_ext *ext;
	int tlen, extlen;
	int i;

	/* sanity check */
	if (msg == NULL || mhp == NULL)
		panic("key_align: NULL pointer is passed.\n");

	/* initialize */
	for (i = 0; i < SADB_EXT_MAX + 1; i++)
		mhp[i] = NULL;

	mhp[0] = (caddr_t)msg;

	tlen = PFKEY_UNUNIT64(msg->sadb_msg_len) - sizeof(struct sadb_msg);
	ext = (struct sadb_ext *)((caddr_t)msg + sizeof(struct sadb_msg));

	while (tlen > 0) {
		/* set pointer */
		switch (ext->sadb_ext_type) {
		case SADB_EXT_SA:
		case SADB_EXT_LIFETIME_CURRENT:
		case SADB_EXT_LIFETIME_HARD:
		case SADB_EXT_LIFETIME_SOFT:
		case SADB_EXT_ADDRESS_SRC:
		case SADB_EXT_ADDRESS_DST:
		case SADB_EXT_ADDRESS_PROXY:
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
			/* duplicate check */
			/*
			 * XXX Are there duplication payloads of either
			 * KEY_AUTH or KEY_ENCRYPT ?
			 */
			if (mhp[ext->sadb_ext_type] != NULL) {
#if IPSEC_DEBUG
				printf("key_align: duplicate ext_type %u "
					"is passed.\n",
					ext->sadb_ext_type);
#endif
				pfkeystat.out_dupext++;
				return EINVAL;
			}
			mhp[ext->sadb_ext_type] = (caddr_t)ext;
			break;
		default:
#if IPSEC_DEBUG
			printf("key_align: invalid ext_type %u is passed.\n",
				ext->sadb_ext_type);
#endif
			pfkeystat.out_invexttype++;
			return EINVAL;
		}

		extlen = PFKEY_UNUNIT64(ext->sadb_ext_len);
		tlen -= extlen;
		ext = (struct sadb_ext *)((caddr_t)ext + extlen);
	}

	return 0;
}

void
key_init()
{
	int i;

	bzero((caddr_t)&key_cb, sizeof(key_cb));

	for (i = 0; i < IPSEC_DIR_MAX; i++) {
		LIST_INIT(&sptree[i]);
	}

	LIST_INIT(&sahtree);

	for (i = 0; i <= SADB_SATYPE_MAX; i++) {
		LIST_INIT(&regtree[i]);
	}

#ifndef IPSEC_NONBLOCK_ACQUIRE
	LIST_INIT(&acqtree);
#endif
	LIST_INIT(&spacqtree);

	/* system default */
	ip4_def_policy.policy = IPSEC_POLICY_NONE;
	ip4_def_policy.refcnt++;	/*never reclaim this*/
#if INET6
	ip6_def_policy.policy = IPSEC_POLICY_NONE;
	ip6_def_policy.refcnt++;	/*never reclaim this*/
#endif

#ifndef IPSEC_DEBUG2
	timeout((void *)key_timehandler, (void *)0, hz);
#endif /*IPSEC_DEBUG2*/

	/* initialize key statistics */
	keystat.getspi_count = 1;

	printf("IPsec: Initialized Security Association Processing.\n");

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
key_checktunnelsanity(sav, family, src, dst)
	struct secasvar *sav;
	u_int family;
	caddr_t src;
	caddr_t dst;
{
	/* sanity check */
	if (sav->sah == NULL)
		panic("sav->sah == NULL at key_checktunnelsanity");

	/* XXX: check inner IP header */

	return 1;
}

#if 0
#ifdef __FreeBSD__
#define hostnamelen	strlen(hostname)
#endif

/*
 * Get FQDN for the host.
 * If the administrator configured hostname (by hostname(1)) without
 * domain name, returns nothing.
 */
static const char *
key_getfqdn()
{
	int i;
	int hasdot;
	static char fqdn[MAXHOSTNAMELEN + 1];

	if (!hostnamelen)
		return NULL;

	/* check if it comes with domain name. */
	hasdot = 0;
	for (i = 0; i < hostnamelen; i++) {
		if (hostname[i] == '.')
			hasdot++;
	}
	if (!hasdot)
		return NULL;

	/* NOTE: hostname may not be NUL-terminated. */
	bzero(fqdn, sizeof(fqdn));
	bcopy(hostname, fqdn, hostnamelen);
	fqdn[hostnamelen] = '\0';
	return fqdn;
}

/*
 * get username@FQDN for the host/user.
 */
static const char *
key_getuserfqdn()
{
	const char *host;
	static char userfqdn[MAXHOSTNAMELEN + MAXLOGNAME + 2];
	struct proc *p = curproc;
	char *q;

	if (!p || !p->p_pgrp || !p->p_pgrp->pg_session)
		return NULL;
	if (!(host = key_getfqdn()))
		return NULL;

	/* NOTE: s_login may not be-NUL terminated. */
	bzero(userfqdn, sizeof(userfqdn));
	bcopy(p->p_pgrp->pg_session->s_login, userfqdn, MAXLOGNAME);
	userfqdn[MAXLOGNAME] = '\0';	/* safeguard */
	q = userfqdn + strlen(userfqdn);
	*q++ = '@';
	bcopy(host, q, strlen(host));
	q += strlen(host);
	*q++ = '\0';

	return userfqdn;
}
#endif

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

	return;
}

/* dumb version */
void
key_sa_routechange(dst)
	struct sockaddr *dst;
{
	struct secashead *sah;
	struct route *ro;

	LIST_FOREACH(sah, &sahtree, chain) {
		ro = &sah->sa_route;
		if (ro->ro_rt && dst->sa_len == ro->ro_dst.sa_len
		 && bcmp(dst, &ro->ro_dst, dst->sa_len) == 0) {
			RTFREE(ro->ro_rt);
			ro->ro_rt = (struct rtentry *)NULL;
		}
	}

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

	if (__LIST_CHAINED(sav))
		LIST_REMOVE(sav, chain);

	sav->state = state;
	LIST_INSERT_HEAD(&sav->sah->savtree[state], sav, chain);
}

/* returns NULL on error, m0 will be left unchanged */
static caddr_t
key_appendmbuf(m0, len)
	struct mbuf *m0;
	int len;
{
	caddr_t p;
	struct mbuf *m;
	struct mbuf *n;

	if (!m0 || (m0->m_flags & M_PKTHDR) == 0)
		return NULL;	/*EINVAL*/
	if (len > MCLBYTES)
		return NULL;	/*EINVAL*/

	for (m = m0; m && m->m_next; m = m->m_next)
		;
	if (len <= M_TRAILINGSPACE(m)) {
		p = mtod(m, caddr_t) + m->m_len;
		m->m_len += len;
		m0->m_pkthdr.len += len;

		return p;
	}
	MGET(n, M_DONTWAIT, m->m_type);
	if (n != NULL) {
		MCLGET(n, M_DONTWAIT);
		if ((n->m_flags & M_EXT) == 0) {
			m_freem(n);
			n = NULL;
		}
	}
	if (n == NULL)
		return NULL;	/*ENOBUFS*/
	n->m_next = NULL;
	m->m_next = n;
	n->m_len = len;
	m0->m_pkthdr.len += len;

	return mtod(n, caddr_t);
}

#ifdef __bsdi__
#include <sys/user.h>
#include <sys/sysctl.h>

int *key_sysvars[] = KEYCTL_VARS;

int
key_sysctl(name, namelen, oldp, oldlenp, newp, newlen)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
{
	if (name[0] >= KEYCTL_MAXID)
		return EOPNOTSUPP;
	switch (name[0]) {
	default:
		return sysctl_int_arr(key_sysvars, name, namelen,
			oldp, oldlenp, newp, newlen);
	}
}
#endif /*__bsdi__*/

#ifdef __NetBSD__
#include <vm/vm.h>
#include <sys/sysctl.h>

static int *key_sysvars[] = KEYCTL_VARS;

int
key_sysctl(name, namelen, oldp, oldlenp, newp, newlen)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
{
	if (name[0] >= KEYCTL_MAXID)
		return EOPNOTSUPP;
	if (!key_sysvars[name[0]])
		return EOPNOTSUPP;
	switch (name[0]) {
	default:
		return sysctl_int(oldp, oldlenp, newp, newlen,
			key_sysvars[name[0]]);
	}
}
#endif /*__NetBSD__*/
