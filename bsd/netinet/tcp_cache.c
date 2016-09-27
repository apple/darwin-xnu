/*
 * Copyright (c) 2015-2016 Apple Inc. All rights reserved.
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

/* TCP-cache to store and retrieve TCP-related information */

#include <net/flowhash.h>
#include <net/route.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp_cache.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_var.h>
#include <kern/locks.h>
#include <sys/queue.h>
#include <dev/random/randomdev.h>

struct tcp_heuristic_key {
	union {
		uint8_t thk_net_signature[IFNET_SIGNATURELEN];
		union {
			struct in_addr addr;
			struct in6_addr addr6;
		} thk_ip;
	};
	sa_family_t	thk_family;
};

struct tcp_heuristic {
	SLIST_ENTRY(tcp_heuristic) list;

	u_int32_t	th_last_access;

	struct tcp_heuristic_key	th_key;

	char		th_val_start[0]; /* Marker for memsetting to 0 */

	u_int8_t	th_tfo_cookie_loss; /* The number of times a SYN+cookie has been lost */
	u_int8_t	th_mptcp_loss; /* The number of times a SYN+MP_CAPABLE has been lost */
	u_int8_t	th_ecn_loss; /* The number of times a SYN+ecn has been lost */
	u_int8_t	th_ecn_aggressive; /* The number of times we did an aggressive fallback */
	u_int8_t	th_ecn_droprst; /* The number of times ECN connections received a RST after first data pkt */
	u_int8_t	th_ecn_droprxmt; /* The number of times ECN connection is dropped after multiple retransmits */
	u_int32_t	th_tfo_fallback_trials; /* Number of times we did not try out TFO due to SYN-loss */
	u_int32_t	th_tfo_cookie_backoff; /* Time until when we should not try out TFO */
	u_int32_t	th_mptcp_backoff; /* Time until when we should not try out MPTCP */
	u_int32_t	th_ecn_backoff; /* Time until when we should not try out ECN */

	u_int8_t	th_tfo_in_backoff:1, /* Are we avoiding TFO due to the backoff timer? */
			th_tfo_aggressive_fallback:1, /* Aggressive fallback due to nasty middlebox */
			th_tfo_snd_middlebox_supp:1, /* We are sure that the network supports TFO in upstream direction */
			th_tfo_rcv_middlebox_supp:1, /* We are sure that the network supports TFO in downstream direction*/
			th_mptcp_in_backoff:1; /* Are we avoiding MPTCP due to the backoff timer? */

	char		th_val_end[0]; /* Marker for memsetting to 0 */
};

struct tcp_heuristics_head {
	SLIST_HEAD(tcp_heur_bucket, tcp_heuristic) tcp_heuristics;

	/* Per-hashbucket lock to avoid lock-contention */
	lck_mtx_t	thh_mtx;
};

struct tcp_cache_key {
	sa_family_t	tck_family;

	struct tcp_heuristic_key tck_src;
	union {
		struct in_addr addr;
		struct in6_addr addr6;
	} tck_dst;
};

struct tcp_cache {
	SLIST_ENTRY(tcp_cache) list;

	u_int32_t	tc_last_access;

	struct tcp_cache_key tc_key;

	u_int8_t	tc_tfo_cookie[TFO_COOKIE_LEN_MAX];
	u_int8_t	tc_tfo_cookie_len;
};

struct tcp_cache_head {
	SLIST_HEAD(tcp_cache_bucket, tcp_cache) tcp_caches;

	/* Per-hashbucket lock to avoid lock-contention */
	lck_mtx_t	tch_mtx;
};

static u_int32_t tcp_cache_hash_seed;

size_t tcp_cache_size;

/*
 * The maximum depth of the hash-bucket. This way we limit the tcp_cache to
 * TCP_CACHE_BUCKET_SIZE * tcp_cache_size and have "natural" garbage collection
 */
#define	TCP_CACHE_BUCKET_SIZE 5

static struct tcp_cache_head *tcp_cache;

decl_lck_mtx_data(, tcp_cache_mtx);

static lck_attr_t	*tcp_cache_mtx_attr;
static lck_grp_t	*tcp_cache_mtx_grp;
static lck_grp_attr_t	*tcp_cache_mtx_grp_attr;

static struct tcp_heuristics_head *tcp_heuristics;

decl_lck_mtx_data(, tcp_heuristics_mtx);

static lck_attr_t	*tcp_heuristic_mtx_attr;
static lck_grp_t	*tcp_heuristic_mtx_grp;
static lck_grp_attr_t	*tcp_heuristic_mtx_grp_attr;

static int tcp_ecn_timeout = 60;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, ecn_timeout, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_ecn_timeout, 0, "Initial minutes to wait before re-trying ECN");

static int disable_tcp_heuristics = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, disable_tcp_heuristics, CTLFLAG_RW | CTLFLAG_LOCKED,
    &disable_tcp_heuristics, 0, "Set to 1, to disable all TCP heuristics (TFO, ECN, MPTCP)");

/*
 * This number is coupled with tcp_ecn_timeout, because we want to prevent
 * integer overflow. Need to find an unexpensive way to prevent integer overflow
 * while still allowing a dynamic sysctl.
 */
#define	TCP_CACHE_OVERFLOW_PROTECT	9

/* Number of SYN-losses we accept */
#define	TFO_MAX_COOKIE_LOSS	2
#define	ECN_MAX_SYN_LOSS	2
#define	MPTCP_MAX_SYN_LOSS	2
#define	ECN_MAX_DROPRST		2
#define	ECN_MAX_DROPRXMT	4

/* Flags for setting/unsetting loss-heuristics, limited to 1 byte */
#define	TCPCACHE_F_TFO		0x01
#define	TCPCACHE_F_ECN		0x02
#define	TCPCACHE_F_MPTCP	0x04
#define	TCPCACHE_F_ECN_DROPRST	0x08
#define	TCPCACHE_F_ECN_DROPRXMT	0x10

/* Always retry ECN after backing off to this level for some heuristics */
#define	ECN_RETRY_LIMIT	9

/*
 * Round up to next higher power-of 2.  See "Bit Twiddling Hacks".
 *
 * Might be worth moving this to a library so that others
 * (e.g., scale_to_powerof2()) can use this as well instead of a while-loop.
 */
static u_int32_t tcp_cache_roundup2(u_int32_t a)
{
	a--;
	a |= a >> 1;
	a |= a >> 2;
	a |= a >> 4;
	a |= a >> 8;
	a |= a >> 16;
	a++;

	return a;
}

static void tcp_cache_hash_src(struct inpcb *inp, struct tcp_heuristic_key *key)
{
	struct ifnet *ifn = inp->inp_last_outifp;
	uint8_t len = sizeof(key->thk_net_signature);
	uint16_t flags;

	if (inp->inp_vflag & INP_IPV6) {
		int ret;

		key->thk_family = AF_INET6;
		ret = ifnet_get_netsignature(ifn, AF_INET6, &len, &flags,
		    key->thk_net_signature);

		/*
		 * ifnet_get_netsignature only returns EINVAL if ifn is NULL
		 * (we made sure that in the other cases it does not). So,
		 * in this case we should take the connection's address.
		 */
		if (ret == ENOENT || ret == EINVAL)
			memcpy(&key->thk_ip.addr6, &inp->in6p_laddr, sizeof(struct in6_addr));
	} else {
		int ret;

		key->thk_family = AF_INET;
		ret = ifnet_get_netsignature(ifn, AF_INET, &len, &flags,
		    key->thk_net_signature);

		/*
		 * ifnet_get_netsignature only returns EINVAL if ifn is NULL
		 * (we made sure that in the other cases it does not). So,
		 * in this case we should take the connection's address.
		 */
		if (ret == ENOENT || ret == EINVAL)
			memcpy(&key->thk_ip.addr, &inp->inp_laddr, sizeof(struct in_addr));
	}
}

static u_int16_t tcp_cache_hash(struct inpcb *inp, struct tcp_cache_key *key)
{
	u_int32_t hash;

	bzero(key, sizeof(struct tcp_cache_key));

	tcp_cache_hash_src(inp, &key->tck_src);

	if (inp->inp_vflag & INP_IPV6) {
		key->tck_family = AF_INET6;
		memcpy(&key->tck_dst.addr6, &inp->in6p_faddr,
		    sizeof(struct in6_addr));
	} else {
		key->tck_family = AF_INET;
		memcpy(&key->tck_dst.addr, &inp->inp_faddr,
		    sizeof(struct in_addr));
	}

	hash = net_flowhash(key, sizeof(struct tcp_cache_key),
	    tcp_cache_hash_seed);

	return (hash & (tcp_cache_size - 1));
}

static void tcp_cache_unlock(struct tcp_cache_head *head)
{
	lck_mtx_unlock(&head->tch_mtx);
}

/*
 * Make sure that everything that happens after tcp_getcache_with_lock()
 * is short enough to justify that you hold the per-bucket lock!!!
 *
 * Otherwise, better build another lookup-function that does not hold the
 * lock and you copy out the bits and bytes.
 *
 * That's why we provide the head as a "return"-pointer so that the caller
 * can give it back to use for tcp_cache_unlock().
 */
static struct tcp_cache *tcp_getcache_with_lock(struct tcpcb *tp, int create,
    struct tcp_cache_head **headarg)
{
	struct inpcb *inp = tp->t_inpcb;
	struct tcp_cache *tpcache = NULL;
	struct tcp_cache_head *head;
	struct tcp_cache_key key;
	u_int16_t hash;
	int i = 0;

	hash = tcp_cache_hash(inp, &key);
	head = &tcp_cache[hash];

	lck_mtx_lock(&head->tch_mtx);

	/*** First step: Look for the tcp_cache in our bucket ***/
	SLIST_FOREACH(tpcache, &head->tcp_caches, list) {
		if (memcmp(&tpcache->tc_key, &key, sizeof(key)) == 0)
			break;

		i++;
	}

	/*** Second step: If it's not there, create/recycle it ***/
	if ((tpcache == NULL) && create) {
		if (i >= TCP_CACHE_BUCKET_SIZE) {
			struct tcp_cache *oldest_cache = NULL;
			u_int32_t max_age = 0;

			/* Look for the oldest tcp_cache in the bucket */
			SLIST_FOREACH(tpcache, &head->tcp_caches, list) {
				u_int32_t age = tcp_now - tpcache->tc_last_access;
				if (age > max_age) {
					max_age = age;
					oldest_cache = tpcache;
				}
			}
			VERIFY(oldest_cache != NULL);

			tpcache = oldest_cache;

			/* We recycle, thus let's indicate that there is no cookie */
			tpcache->tc_tfo_cookie_len = 0;
		} else {
			/* Create a new cache and add it to the list */
			tpcache = _MALLOC(sizeof(struct tcp_cache), M_TEMP,
			    M_NOWAIT | M_ZERO);
			if (tpcache == NULL)
				goto out_null;

			SLIST_INSERT_HEAD(&head->tcp_caches, tpcache, list);
		}

		memcpy(&tpcache->tc_key, &key, sizeof(key));
	}

	if (tpcache == NULL)
		goto out_null;

	/* Update timestamp for garbage collection purposes */
	tpcache->tc_last_access = tcp_now;
	*headarg = head;

	return (tpcache);

out_null:
	tcp_cache_unlock(head);
	return (NULL);
}

void tcp_cache_set_cookie(struct tcpcb *tp, u_char *cookie, u_int8_t len)
{
	struct tcp_cache_head *head;
	struct tcp_cache *tpcache;

	/* Call lookup/create function */
	tpcache = tcp_getcache_with_lock(tp, 1, &head);
	if (tpcache == NULL)
		return;

	tpcache->tc_tfo_cookie_len = len;
	memcpy(tpcache->tc_tfo_cookie, cookie, len);

	tcp_cache_unlock(head);
}

/*
 * Get the cookie related to 'tp', and copy it into 'cookie', provided that len
 * is big enough (len designates the available memory.
 * Upon return, 'len' is set to the cookie's length.
 *
 * Returns 0 if we should request a cookie.
 * Returns 1 if the cookie has been found and written.
 */
int tcp_cache_get_cookie(struct tcpcb *tp, u_char *cookie, u_int8_t *len)
{
	struct tcp_cache_head *head;
	struct tcp_cache *tpcache;

	/* Call lookup/create function */
	tpcache = tcp_getcache_with_lock(tp, 1, &head);
	if (tpcache == NULL)
		return (0);

	if (tpcache->tc_tfo_cookie_len == 0) {
		tcp_cache_unlock(head);
		return (0);
	}

	/*
	 * Not enough space - this should never happen as it has been checked
	 * in tcp_tfo_check. So, fail here!
	 */
	VERIFY(tpcache->tc_tfo_cookie_len <= *len);

	memcpy(cookie, tpcache->tc_tfo_cookie, tpcache->tc_tfo_cookie_len);
	*len = tpcache->tc_tfo_cookie_len;

	tcp_cache_unlock(head);

	return (1);
}

unsigned int tcp_cache_get_cookie_len(struct tcpcb *tp)
{
	struct tcp_cache_head *head;
	struct tcp_cache *tpcache;
	unsigned int cookie_len;

	/* Call lookup/create function */
	tpcache = tcp_getcache_with_lock(tp, 1, &head);
	if (tpcache == NULL)
		return (0);

	cookie_len = tpcache->tc_tfo_cookie_len;

	tcp_cache_unlock(head);

	return cookie_len;
}

static u_int16_t tcp_heuristics_hash(struct inpcb *inp,
				     struct tcp_heuristic_key *key)
{
	u_int32_t hash;

	bzero(key, sizeof(struct tcp_heuristic_key));

	tcp_cache_hash_src(inp, key);

	hash = net_flowhash(key, sizeof(struct tcp_heuristic_key),
	    tcp_cache_hash_seed);

	return (hash & (tcp_cache_size - 1));
}

static void tcp_heuristic_unlock(struct tcp_heuristics_head *head)
{
	lck_mtx_unlock(&head->thh_mtx);
}

/*
 * Make sure that everything that happens after tcp_getheuristic_with_lock()
 * is short enough to justify that you hold the per-bucket lock!!!
 *
 * Otherwise, better build another lookup-function that does not hold the
 * lock and you copy out the bits and bytes.
 *
 * That's why we provide the head as a "return"-pointer so that the caller
 * can give it back to use for tcp_heur_unlock().
 *
 *
 * ToDo - way too much code-duplication. We should create an interface to handle
 * bucketized hashtables with recycling of the oldest element.
 */
static struct tcp_heuristic *tcp_getheuristic_with_lock(struct tcpcb *tp,
    int create, struct tcp_heuristics_head **headarg)
{
	struct inpcb *inp = tp->t_inpcb;
	struct tcp_heuristic *tpheur = NULL;
	struct tcp_heuristics_head *head;
	struct tcp_heuristic_key key;
	u_int16_t hash;
	int i = 0;

	hash = tcp_heuristics_hash(inp, &key);
	head = &tcp_heuristics[hash];

	lck_mtx_lock(&head->thh_mtx);

	/*** First step: Look for the tcp_heur in our bucket ***/
	SLIST_FOREACH(tpheur, &head->tcp_heuristics, list) {
		if (memcmp(&tpheur->th_key, &key, sizeof(key)) == 0)
			break;

		i++;
	}

	/*** Second step: If it's not there, create/recycle it ***/
	if ((tpheur == NULL) && create) {
		if (i >= TCP_CACHE_BUCKET_SIZE) {
			struct tcp_heuristic *oldest_heur = NULL;
			u_int32_t max_age = 0;

			/* Look for the oldest tcp_heur in the bucket */
			SLIST_FOREACH(tpheur, &head->tcp_heuristics, list) {
				u_int32_t age = tcp_now - tpheur->th_last_access;
				if (age > max_age) {
					max_age = age;
					oldest_heur = tpheur;
				}
			}
			VERIFY(oldest_heur != NULL);

			tpheur = oldest_heur;

			/* We recycle - set everything to 0 */
			bzero(tpheur->th_val_start,
			      tpheur->th_val_end - tpheur->th_val_start);
		} else {
			/* Create a new heuristic and add it to the list */
			tpheur = _MALLOC(sizeof(struct tcp_heuristic), M_TEMP,
			    M_NOWAIT | M_ZERO);
			if (tpheur == NULL)
				goto out_null;

			SLIST_INSERT_HEAD(&head->tcp_heuristics, tpheur, list);
		}

		/*
		 * Set to tcp_now, to make sure it won't be > than tcp_now in the
		 * near future.
		 */
		tpheur->th_ecn_backoff = tcp_now;
		tpheur->th_tfo_cookie_backoff = tcp_now;
		tpheur->th_mptcp_backoff = tcp_now;

		memcpy(&tpheur->th_key, &key, sizeof(key));
	}

	if (tpheur == NULL)
		goto out_null;

	/* Update timestamp for garbage collection purposes */
	tpheur->th_last_access = tcp_now;
	*headarg = head;

	return (tpheur);

out_null:
	tcp_heuristic_unlock(head);
	return (NULL);
}

static void tcp_heuristic_reset_loss(struct tcpcb *tp, u_int8_t flags)
{
	struct tcp_heuristics_head *head;
	struct tcp_heuristic *tpheur;

	/*
	 * Don't attempt to create it! Keep the heuristics clean if the
	 * server does not support TFO. This reduces the lookup-cost on
	 * our side.
	 */
	tpheur = tcp_getheuristic_with_lock(tp, 0, &head);
	if (tpheur == NULL)
		return;

	if (flags & TCPCACHE_F_TFO)
		tpheur->th_tfo_cookie_loss = 0;

	if (flags & TCPCACHE_F_ECN)
		tpheur->th_ecn_loss = 0;

	if (flags & TCPCACHE_F_MPTCP)
		tpheur->th_mptcp_loss = 0;

	tcp_heuristic_unlock(head);
}

void tcp_heuristic_tfo_success(struct tcpcb *tp)
{
	tcp_heuristic_reset_loss(tp, TCPCACHE_F_TFO);
}

void tcp_heuristic_mptcp_success(struct tcpcb *tp)
{
	tcp_heuristic_reset_loss(tp, TCPCACHE_F_MPTCP);
}

void tcp_heuristic_ecn_success(struct tcpcb *tp)
{
	tcp_heuristic_reset_loss(tp, TCPCACHE_F_ECN);
}

void tcp_heuristic_tfo_rcv_good(struct tcpcb *tp)
{
	struct tcp_heuristics_head *head;

	struct tcp_heuristic *tpheur = tcp_getheuristic_with_lock(tp, 1, &head);
	if (tpheur == NULL)
		return;

	tpheur->th_tfo_rcv_middlebox_supp = 1;

	tcp_heuristic_unlock(head);

	tp->t_tfo_flags |= TFO_F_NO_RCVPROBING;
}

void tcp_heuristic_tfo_snd_good(struct tcpcb *tp)
{
	struct tcp_heuristics_head *head;

	struct tcp_heuristic *tpheur = tcp_getheuristic_with_lock(tp, 1, &head);
	if (tpheur == NULL)
		return;

	tpheur->th_tfo_snd_middlebox_supp = 1;

	tcp_heuristic_unlock(head);

	tp->t_tfo_flags |= TFO_F_NO_SNDPROBING;
}

static void tcp_heuristic_inc_loss(struct tcpcb *tp, u_int8_t flags)
{
	struct tcp_heuristics_head *head;
	struct tcp_heuristic *tpheur;

	tpheur = tcp_getheuristic_with_lock(tp, 1, &head);
	if (tpheur == NULL)
		return;

	/* Limit to prevent integer-overflow during exponential backoff */
	if ((flags & TCPCACHE_F_TFO) && tpheur->th_tfo_cookie_loss < TCP_CACHE_OVERFLOW_PROTECT)
		tpheur->th_tfo_cookie_loss++;

	if ((flags & TCPCACHE_F_ECN) && tpheur->th_ecn_loss < TCP_CACHE_OVERFLOW_PROTECT) {
		tpheur->th_ecn_loss++;
		if (tpheur->th_ecn_loss >= ECN_MAX_SYN_LOSS) {
			tcpstat.tcps_ecn_fallback_synloss++;
			INP_INC_IFNET_STAT(tp->t_inpcb, ecn_fallback_synloss);
			tpheur->th_ecn_backoff = tcp_now +
			    ((tcp_ecn_timeout * 60 * TCP_RETRANSHZ) <<
			    (tpheur->th_ecn_loss - ECN_MAX_SYN_LOSS));
		}
	}

	if ((flags & TCPCACHE_F_MPTCP) &&
	    tpheur->th_mptcp_loss < TCP_CACHE_OVERFLOW_PROTECT) {
		tpheur->th_mptcp_loss++;
		if (tpheur->th_mptcp_loss >= MPTCP_MAX_SYN_LOSS) {
			/*
			 * Yes, we take tcp_ecn_timeout, to avoid adding yet
			 * another sysctl that is just used for testing.
			 */
			tpheur->th_mptcp_backoff = tcp_now +
			    ((tcp_ecn_timeout * 60 * TCP_RETRANSHZ) <<
			    (tpheur->th_mptcp_loss - MPTCP_MAX_SYN_LOSS));
		}
	}

	if ((flags & TCPCACHE_F_ECN_DROPRST) &&
	    tpheur->th_ecn_droprst < TCP_CACHE_OVERFLOW_PROTECT) {
		tpheur->th_ecn_droprst++;
		if (tpheur->th_ecn_droprst >= ECN_MAX_DROPRST) {
			tcpstat.tcps_ecn_fallback_droprst++;
			INP_INC_IFNET_STAT(tp->t_inpcb, ecn_fallback_droprst);
			tpheur->th_ecn_backoff = tcp_now +
			    ((tcp_ecn_timeout * 60 * TCP_RETRANSHZ) <<
			    (tpheur->th_ecn_droprst - ECN_MAX_DROPRST));

		}
	}

	if ((flags & TCPCACHE_F_ECN_DROPRXMT) &&
	    tpheur->th_ecn_droprst < TCP_CACHE_OVERFLOW_PROTECT) {
		tpheur->th_ecn_droprxmt++;
		if (tpheur->th_ecn_droprxmt >= ECN_MAX_DROPRXMT) {
			tcpstat.tcps_ecn_fallback_droprxmt++;
			INP_INC_IFNET_STAT(tp->t_inpcb, ecn_fallback_droprxmt);
			tpheur->th_ecn_backoff = tcp_now +
			    ((tcp_ecn_timeout * 60 * TCP_RETRANSHZ) <<
			    (tpheur->th_ecn_droprxmt - ECN_MAX_DROPRXMT));
		}
	}
	tcp_heuristic_unlock(head);
}

void tcp_heuristic_tfo_loss(struct tcpcb *tp)
{
	tcp_heuristic_inc_loss(tp, TCPCACHE_F_TFO);
}

void tcp_heuristic_mptcp_loss(struct tcpcb *tp)
{
	tcp_heuristic_inc_loss(tp, TCPCACHE_F_MPTCP);
}

void tcp_heuristic_ecn_loss(struct tcpcb *tp)
{
	tcp_heuristic_inc_loss(tp, TCPCACHE_F_ECN);
}

void tcp_heuristic_ecn_droprst(struct tcpcb *tp)
{
	tcp_heuristic_inc_loss(tp, TCPCACHE_F_ECN_DROPRST);
}

void tcp_heuristic_ecn_droprxmt(struct tcpcb *tp)
{
	tcp_heuristic_inc_loss(tp, TCPCACHE_F_ECN_DROPRXMT);
}

void tcp_heuristic_tfo_middlebox(struct tcpcb *tp)
{
	struct tcp_heuristics_head *head;
	struct tcp_heuristic *tpheur;

	tpheur = tcp_getheuristic_with_lock(tp, 1, &head);
	if (tpheur == NULL)
		return;

	tpheur->th_tfo_aggressive_fallback = 1;

	tcp_heuristic_unlock(head);
}

void tcp_heuristic_ecn_aggressive(struct tcpcb *tp)
{
	struct tcp_heuristics_head *head;
	struct tcp_heuristic *tpheur;

	tpheur = tcp_getheuristic_with_lock(tp, 1, &head);
	if (tpheur == NULL)
		return;

	/* Must be done before, otherwise we will start off with expo-backoff */
	tpheur->th_ecn_backoff = tcp_now +
	    ((tcp_ecn_timeout * 60 * TCP_RETRANSHZ) << (tpheur->th_ecn_aggressive));

	/*
	 * Ugly way to prevent integer overflow... limit to prevent in
	 * overflow during exp. backoff.
	 */
	if (tpheur->th_ecn_aggressive < TCP_CACHE_OVERFLOW_PROTECT)
		tpheur->th_ecn_aggressive++;

	tcp_heuristic_unlock(head);
}

boolean_t tcp_heuristic_do_tfo(struct tcpcb *tp)
{
	struct tcp_heuristics_head *head;
	struct tcp_heuristic *tpheur;

	if (disable_tcp_heuristics)
		return (TRUE);

	/* Get the tcp-heuristic. */
	tpheur = tcp_getheuristic_with_lock(tp, 0, &head);
	if (tpheur == NULL)
		return (TRUE);

	if (tpheur->th_tfo_aggressive_fallback) {
		/* Aggressive fallback - don't do TFO anymore... :'( */
		tcp_heuristic_unlock(head);
		return (FALSE);
	}

	if (tpheur->th_tfo_cookie_loss >= TFO_MAX_COOKIE_LOSS &&
	    (tpheur->th_tfo_fallback_trials < tcp_tfo_fallback_min ||
	     TSTMP_GT(tpheur->th_tfo_cookie_backoff, tcp_now))) {
		/*
		 * So, when we are in SYN-loss mode we try to stop using TFO
		 * for the next 'tcp_tfo_fallback_min' connections. That way,
		 * we are sure that never more than 1 out of tcp_tfo_fallback_min
		 * connections will suffer from our nice little middelbox.
		 *
		 * After that we first wait for 2 minutes. If we fail again,
		 * we wait for yet another 60 minutes.
		 */
		tpheur->th_tfo_fallback_trials++;
		if (tpheur->th_tfo_fallback_trials >= tcp_tfo_fallback_min &&
		    !tpheur->th_tfo_in_backoff) {
			if (tpheur->th_tfo_cookie_loss == TFO_MAX_COOKIE_LOSS)
				/* Backoff for 2 minutes */
				tpheur->th_tfo_cookie_backoff = tcp_now + (60 * 2 * TCP_RETRANSHZ);
			else
				/* Backoff for 60 minutes */
				tpheur->th_tfo_cookie_backoff = tcp_now + (60 * 60 * TCP_RETRANSHZ);

			tpheur->th_tfo_in_backoff = 1;
		}

		tcp_heuristic_unlock(head);
		return (FALSE);
	}

	/*
	 * We give it a new shot, set trials back to 0. This allows to
	 * start counting again from zero in case we get yet another SYN-loss
	 */
	tpheur->th_tfo_fallback_trials = 0;
	tpheur->th_tfo_in_backoff = 0;

	if (tpheur->th_tfo_rcv_middlebox_supp)
		tp->t_tfo_flags |= TFO_F_NO_RCVPROBING;
	if (tpheur->th_tfo_snd_middlebox_supp)
		tp->t_tfo_flags |= TFO_F_NO_SNDPROBING;

	tcp_heuristic_unlock(head);

	return (TRUE);
}

boolean_t tcp_heuristic_do_mptcp(struct tcpcb *tp)
{
	struct tcp_heuristics_head *head;
	struct tcp_heuristic *tpheur;
	boolean_t ret = TRUE;

	if (disable_tcp_heuristics)
		return (TRUE);

	/* Get the tcp-heuristic. */
	tpheur = tcp_getheuristic_with_lock(tp, 0, &head);
	if (tpheur == NULL)
		return ret;

	if (TSTMP_GT(tpheur->th_mptcp_backoff, tcp_now))
		ret = FALSE;

	tcp_heuristic_unlock(head);

	return (ret);
}

boolean_t tcp_heuristic_do_ecn(struct tcpcb *tp)
{
	struct tcp_heuristics_head *head;
	struct tcp_heuristic *tpheur;
	boolean_t ret = TRUE;

	if (disable_tcp_heuristics)
		return (TRUE);

	/* Get the tcp-heuristic. */
	tpheur = tcp_getheuristic_with_lock(tp, 0, &head);
	if (tpheur == NULL)
		return ret;

	if (TSTMP_GT(tpheur->th_ecn_backoff, tcp_now)) {
		ret = FALSE;
	} else {
		/* Reset the following counters to start re-evaluating */
		if (tpheur->th_ecn_droprst >= ECN_RETRY_LIMIT)
			tpheur->th_ecn_droprst = 0;
		if (tpheur->th_ecn_droprxmt >= ECN_RETRY_LIMIT)
			tpheur->th_ecn_droprxmt = 0;
	}

	tcp_heuristic_unlock(head);

	return (ret);
}

static void sysctl_cleartfocache(void)
{
	int i;

	for (i = 0; i < tcp_cache_size; i++) {
		struct tcp_cache_head *head = &tcp_cache[i];
		struct tcp_cache *tpcache, *tmp;
		struct tcp_heuristics_head *hhead = &tcp_heuristics[i];
		struct tcp_heuristic *tpheur, *htmp;

		lck_mtx_lock(&head->tch_mtx);
		SLIST_FOREACH_SAFE(tpcache, &head->tcp_caches, list, tmp) {
			SLIST_REMOVE(&head->tcp_caches, tpcache, tcp_cache, list);
			_FREE(tpcache, M_TEMP);
		}
		lck_mtx_unlock(&head->tch_mtx);

		lck_mtx_lock(&hhead->thh_mtx);
		SLIST_FOREACH_SAFE(tpheur, &hhead->tcp_heuristics, list, htmp) {
			SLIST_REMOVE(&hhead->tcp_heuristics, tpheur, tcp_heuristic, list);
			_FREE(tpheur, M_TEMP);
		}
		lck_mtx_unlock(&hhead->thh_mtx);
	}
}

/* This sysctl is useful for testing purposes only */
static int tcpcleartfo = 0;

static int sysctl_cleartfo SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error = 0, val, oldval = tcpcleartfo;

	val = oldval;
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || !req->newptr)
		return (error);

	/*
	 * The actual value does not matter. If the value is set, it triggers
	 * the clearing of the TFO cache. If a future implementation does not
	 * use the route entry to hold the TFO cache, replace the route sysctl.
	 */

	if (val != oldval)
		sysctl_cleartfocache();

	tcpcleartfo = val;

	return (error);
}

SYSCTL_PROC(_net_inet_tcp, OID_AUTO, clear_tfocache, CTLTYPE_INT | CTLFLAG_RW |
	CTLFLAG_LOCKED, &tcpcleartfo, 0, &sysctl_cleartfo, "I",
	"Toggle to clear the TFO destination based heuristic cache");

void tcp_cache_init(void)
{
	uint64_t sane_size_meg = sane_size / 1024 / 1024;
	int i;

	/*
	 * On machines with <100MB of memory this will result in a (full) cache-size
	 * of 32 entries, thus 32 * 5 * 64bytes = 10KB. (about 0.01 %)
	 * On machines with > 4GB of memory, we have a cache-size of 1024 entries,
	 * thus about 327KB.
	 *
	 * Side-note: we convert to u_int32_t. If sane_size is more than
	 * 16000 TB, we loose precision. But, who cares? :)
	 */
	tcp_cache_size = tcp_cache_roundup2((u_int32_t)(sane_size_meg >> 2));
	if (tcp_cache_size < 32)
		tcp_cache_size = 32;
	else if (tcp_cache_size > 1024)
		tcp_cache_size = 1024;

	tcp_cache = _MALLOC(sizeof(struct tcp_cache_head) * tcp_cache_size,
	    M_TEMP, M_ZERO);
	if (tcp_cache == NULL)
		panic("Allocating tcp_cache failed at boot-time!");

	tcp_cache_mtx_grp_attr = lck_grp_attr_alloc_init();
	tcp_cache_mtx_grp = lck_grp_alloc_init("tcpcache", tcp_cache_mtx_grp_attr);
	tcp_cache_mtx_attr = lck_attr_alloc_init();

	tcp_heuristics = _MALLOC(sizeof(struct tcp_heuristics_head) * tcp_cache_size,
	    M_TEMP, M_ZERO);
	if (tcp_heuristics == NULL)
		panic("Allocating tcp_heuristic failed at boot-time!");

	tcp_heuristic_mtx_grp_attr = lck_grp_attr_alloc_init();
	tcp_heuristic_mtx_grp = lck_grp_alloc_init("tcpheuristic", tcp_heuristic_mtx_grp_attr);
	tcp_heuristic_mtx_attr = lck_attr_alloc_init();

	for (i = 0; i < tcp_cache_size; i++) {
		lck_mtx_init(&tcp_cache[i].tch_mtx, tcp_cache_mtx_grp,
		    tcp_cache_mtx_attr);
		SLIST_INIT(&tcp_cache[i].tcp_caches);

		lck_mtx_init(&tcp_heuristics[i].thh_mtx, tcp_heuristic_mtx_grp,
		    tcp_heuristic_mtx_attr);
		SLIST_INIT(&tcp_heuristics[i].tcp_heuristics);
	}

	tcp_cache_hash_seed = RandomULong();
}
