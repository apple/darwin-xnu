/*
 * Copyright (c) 2015-2017 Apple Inc. All rights reserved.
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
#include <net/necp.h>
#include <netinet/in_pcb.h>
#include <netinet/mptcp_var.h>
#include <netinet/tcp_cache.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_var.h>
#include <kern/locks.h>
#include <sys/queue.h>
#include <dev/random/randomdev.h>

typedef union {
	struct in_addr addr;
	struct in6_addr addr6;
} in_4_6_addr;

struct tcp_heuristic_key {
	union {
		uint8_t thk_net_signature[IFNET_SIGNATURELEN];
		in_4_6_addr thk_ip;
	};
	sa_family_t     thk_family;
};

struct tcp_heuristic {
	SLIST_ENTRY(tcp_heuristic) list;

	uint32_t        th_last_access;

	struct tcp_heuristic_key        th_key;

	char            th_val_start[0]; /* Marker for memsetting to 0 */

	uint8_t         th_tfo_data_loss; /* The number of times a SYN+data has been lost */
	uint8_t         th_tfo_req_loss; /* The number of times a SYN+cookie-req has been lost */
	uint8_t         th_tfo_data_rst; /* The number of times a SYN+data has received a RST */
	uint8_t         th_tfo_req_rst; /* The number of times a SYN+cookie-req has received a RST */
	uint8_t         th_mptcp_loss; /* The number of times a SYN+MP_CAPABLE has been lost */
	uint8_t         th_mptcp_success; /* The number of times MPTCP-negotiation has been successful */
	uint8_t         th_ecn_loss; /* The number of times a SYN+ecn has been lost */
	uint8_t         th_ecn_aggressive; /* The number of times we did an aggressive fallback */
	uint8_t         th_ecn_droprst; /* The number of times ECN connections received a RST after first data pkt */
	uint8_t         th_ecn_droprxmt; /* The number of times ECN connection is dropped after multiple retransmits */
	uint8_t         th_ecn_synrst;  /* number of times RST was received in response to an ECN enabled SYN */
	uint32_t        th_tfo_enabled_time; /* The moment when we reenabled TFO after backing off */
	uint32_t        th_tfo_backoff_until; /* Time until when we should not try out TFO */
	uint32_t        th_tfo_backoff; /* Current backoff timer */
	uint32_t        th_mptcp_backoff; /* Time until when we should not try out MPTCP */
	uint32_t        th_ecn_backoff; /* Time until when we should not try out ECN */

	uint8_t         th_tfo_in_backoff:1, /* Are we avoiding TFO due to the backoff timer? */
	    th_mptcp_in_backoff:1,             /* Are we avoiding MPTCP due to the backoff timer? */
	    th_mptcp_heuristic_disabled:1;             /* Are heuristics disabled? */

	char            th_val_end[0]; /* Marker for memsetting to 0 */
};

struct tcp_heuristics_head {
	SLIST_HEAD(tcp_heur_bucket, tcp_heuristic) tcp_heuristics;

	/* Per-hashbucket lock to avoid lock-contention */
	lck_mtx_t       thh_mtx;
};

struct tcp_cache_key {
	sa_family_t     tck_family;

	struct tcp_heuristic_key tck_src;
	in_4_6_addr tck_dst;
};

struct tcp_cache {
	SLIST_ENTRY(tcp_cache) list;

	uint32_t       tc_last_access;

	struct tcp_cache_key tc_key;

	uint8_t        tc_tfo_cookie[TFO_COOKIE_LEN_MAX];
	uint8_t        tc_tfo_cookie_len;
};

struct tcp_cache_head {
	SLIST_HEAD(tcp_cache_bucket, tcp_cache) tcp_caches;

	/* Per-hashbucket lock to avoid lock-contention */
	lck_mtx_t       tch_mtx;
};

struct tcp_cache_key_src {
	struct ifnet *ifp;
	in_4_6_addr laddr;
	in_4_6_addr faddr;
	int af;
};

static uint32_t tcp_cache_hash_seed;

size_t tcp_cache_size;

/*
 * The maximum depth of the hash-bucket. This way we limit the tcp_cache to
 * TCP_CACHE_BUCKET_SIZE * tcp_cache_size and have "natural" garbage collection
 */
#define TCP_CACHE_BUCKET_SIZE 5

static struct tcp_cache_head *tcp_cache;

decl_lck_mtx_data(, tcp_cache_mtx);

static lck_attr_t       *tcp_cache_mtx_attr;
static lck_grp_t        *tcp_cache_mtx_grp;
static lck_grp_attr_t   *tcp_cache_mtx_grp_attr;

static struct tcp_heuristics_head *tcp_heuristics;

decl_lck_mtx_data(, tcp_heuristics_mtx);

static lck_attr_t       *tcp_heuristic_mtx_attr;
static lck_grp_t        *tcp_heuristic_mtx_grp;
static lck_grp_attr_t   *tcp_heuristic_mtx_grp_attr;

static uint32_t tcp_backoff_maximum = 65536;

SYSCTL_UINT(_net_inet_tcp, OID_AUTO, backoff_maximum, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_backoff_maximum, 0, "Maximum time for which we won't try TFO");

static uint32_t tcp_ecn_timeout = 60;

SYSCTL_UINT(_net_inet_tcp, OID_AUTO, ecn_timeout, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_ecn_timeout, 60, "Initial minutes to wait before re-trying ECN");

static int disable_tcp_heuristics = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, disable_tcp_heuristics, CTLFLAG_RW | CTLFLAG_LOCKED,
    &disable_tcp_heuristics, 0, "Set to 1, to disable all TCP heuristics (TFO, ECN, MPTCP)");

static uint32_t
tcp_min_to_hz(uint32_t minutes)
{
	if (minutes > 65536) {
		return (uint32_t)65536 * 60 * TCP_RETRANSHZ;
	}

	return minutes * 60 * TCP_RETRANSHZ;
}

/*
 * This number is coupled with tcp_ecn_timeout, because we want to prevent
 * integer overflow. Need to find an unexpensive way to prevent integer overflow
 * while still allowing a dynamic sysctl.
 */
#define TCP_CACHE_OVERFLOW_PROTECT      9

/* Number of SYN-losses we accept */
#define TFO_MAX_COOKIE_LOSS     2
#define ECN_MAX_SYN_LOSS        2
#define MPTCP_MAX_SYN_LOSS      2
#define MPTCP_SUCCESS_TRIGGER   10
#define ECN_MAX_DROPRST         1
#define ECN_MAX_DROPRXMT        4
#define ECN_MAX_SYNRST          4

/* Flags for setting/unsetting loss-heuristics, limited to 4 bytes */
#define TCPCACHE_F_TFO_REQ      0x01
#define TCPCACHE_F_TFO_DATA     0x02
#define TCPCACHE_F_ECN          0x04
#define TCPCACHE_F_MPTCP        0x08
#define TCPCACHE_F_ECN_DROPRST  0x10
#define TCPCACHE_F_ECN_DROPRXMT 0x20
#define TCPCACHE_F_TFO_REQ_RST  0x40
#define TCPCACHE_F_TFO_DATA_RST 0x80
#define TCPCACHE_F_ECN_SYNRST   0x100

/* Always retry ECN after backing off to this level for some heuristics */
#define ECN_RETRY_LIMIT 9

#define TCP_CACHE_INC_IFNET_STAT(_ifp_, _af_, _stat_) { \
	if ((_ifp_) != NULL) { \
	        if ((_af_) == AF_INET6) { \
	                (_ifp_)->if_ipv6_stat->_stat_++;\
	        } else { \
	                (_ifp_)->if_ipv4_stat->_stat_++;\
	        }\
	}\
}

/*
 * Round up to next higher power-of 2.  See "Bit Twiddling Hacks".
 *
 * Might be worth moving this to a library so that others
 * (e.g., scale_to_powerof2()) can use this as well instead of a while-loop.
 */
static uint32_t
tcp_cache_roundup2(uint32_t a)
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

static void
tcp_cache_hash_src(struct tcp_cache_key_src *tcks, struct tcp_heuristic_key *key)
{
	struct ifnet *ifp = tcks->ifp;
	uint8_t len = sizeof(key->thk_net_signature);
	uint16_t flags;

	if (tcks->af == AF_INET6) {
		int ret;

		key->thk_family = AF_INET6;
		ret = ifnet_get_netsignature(ifp, AF_INET6, &len, &flags,
		    key->thk_net_signature);

		/*
		 * ifnet_get_netsignature only returns EINVAL if ifn is NULL
		 * (we made sure that in the other cases it does not). So,
		 * in this case we should take the connection's address.
		 */
		if (ret == ENOENT || ret == EINVAL) {
			memcpy(&key->thk_ip.addr6, &tcks->laddr.addr6, sizeof(struct in6_addr));
		}
	} else {
		int ret;

		key->thk_family = AF_INET;
		ret = ifnet_get_netsignature(ifp, AF_INET, &len, &flags,
		    key->thk_net_signature);

		/*
		 * ifnet_get_netsignature only returns EINVAL if ifn is NULL
		 * (we made sure that in the other cases it does not). So,
		 * in this case we should take the connection's address.
		 */
		if (ret == ENOENT || ret == EINVAL) {
			memcpy(&key->thk_ip.addr, &tcks->laddr.addr, sizeof(struct in_addr));
		}
	}
}

static uint16_t
tcp_cache_hash(struct tcp_cache_key_src *tcks, struct tcp_cache_key *key)
{
	uint32_t hash;

	bzero(key, sizeof(struct tcp_cache_key));

	tcp_cache_hash_src(tcks, &key->tck_src);

	if (tcks->af == AF_INET6) {
		key->tck_family = AF_INET6;
		memcpy(&key->tck_dst.addr6, &tcks->faddr.addr6,
		    sizeof(struct in6_addr));
	} else {
		key->tck_family = AF_INET;
		memcpy(&key->tck_dst.addr, &tcks->faddr.addr,
		    sizeof(struct in_addr));
	}

	hash = net_flowhash(key, sizeof(struct tcp_cache_key),
	    tcp_cache_hash_seed);

	return (uint16_t)(hash & (tcp_cache_size - 1));
}

static void
tcp_cache_unlock(struct tcp_cache_head *head)
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
static struct tcp_cache *
tcp_getcache_with_lock(struct tcp_cache_key_src *tcks,
    int create, struct tcp_cache_head **headarg)
{
	struct tcp_cache *tpcache = NULL;
	struct tcp_cache_head *head;
	struct tcp_cache_key key;
	uint16_t hash;
	int i = 0;

	hash = tcp_cache_hash(tcks, &key);
	head = &tcp_cache[hash];

	lck_mtx_lock(&head->tch_mtx);

	/*** First step: Look for the tcp_cache in our bucket ***/
	SLIST_FOREACH(tpcache, &head->tcp_caches, list) {
		if (memcmp(&tpcache->tc_key, &key, sizeof(key)) == 0) {
			break;
		}

		i++;
	}

	/*** Second step: If it's not there, create/recycle it ***/
	if ((tpcache == NULL) && create) {
		if (i >= TCP_CACHE_BUCKET_SIZE) {
			struct tcp_cache *oldest_cache = NULL;
			uint32_t max_age = 0;

			/* Look for the oldest tcp_cache in the bucket */
			SLIST_FOREACH(tpcache, &head->tcp_caches, list) {
				uint32_t age = tcp_now - tpcache->tc_last_access;
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
			if (tpcache == NULL) {
				os_log_error(OS_LOG_DEFAULT, "%s could not allocate cache", __func__);
				goto out_null;
			}

			SLIST_INSERT_HEAD(&head->tcp_caches, tpcache, list);
		}

		memcpy(&tpcache->tc_key, &key, sizeof(key));
	}

	if (tpcache == NULL) {
		goto out_null;
	}

	/* Update timestamp for garbage collection purposes */
	tpcache->tc_last_access = tcp_now;
	*headarg = head;

	return tpcache;

out_null:
	tcp_cache_unlock(head);
	return NULL;
}

static void
tcp_cache_key_src_create(struct tcpcb *tp, struct tcp_cache_key_src *tcks)
{
	struct inpcb *inp = tp->t_inpcb;
	memset(tcks, 0, sizeof(*tcks));

	tcks->ifp = inp->inp_last_outifp;

	if (inp->inp_vflag & INP_IPV6) {
		memcpy(&tcks->laddr.addr6, &inp->in6p_laddr, sizeof(struct in6_addr));
		memcpy(&tcks->faddr.addr6, &inp->in6p_faddr, sizeof(struct in6_addr));
		tcks->af = AF_INET6;
	} else {
		memcpy(&tcks->laddr.addr, &inp->inp_laddr, sizeof(struct in_addr));
		memcpy(&tcks->faddr.addr, &inp->inp_faddr, sizeof(struct in_addr));
		tcks->af = AF_INET;
	}

	return;
}

static void
tcp_cache_set_cookie_common(struct tcp_cache_key_src *tcks, u_char *cookie, uint8_t len)
{
	struct tcp_cache_head *head;
	struct tcp_cache *tpcache;

	/* Call lookup/create function */
	tpcache = tcp_getcache_with_lock(tcks, 1, &head);
	if (tpcache == NULL) {
		return;
	}

	tpcache->tc_tfo_cookie_len = len > TFO_COOKIE_LEN_MAX ?
	    TFO_COOKIE_LEN_MAX : len;
	memcpy(tpcache->tc_tfo_cookie, cookie, tpcache->tc_tfo_cookie_len);

	tcp_cache_unlock(head);
}

void
tcp_cache_set_cookie(struct tcpcb *tp, u_char *cookie, uint8_t len)
{
	struct tcp_cache_key_src tcks;

	tcp_cache_key_src_create(tp, &tcks);
	tcp_cache_set_cookie_common(&tcks, cookie, len);
}

static int
tcp_cache_get_cookie_common(struct tcp_cache_key_src *tcks, u_char *cookie, uint8_t *len)
{
	struct tcp_cache_head *head;
	struct tcp_cache *tpcache;

	/* Call lookup/create function */
	tpcache = tcp_getcache_with_lock(tcks, 1, &head);
	if (tpcache == NULL) {
		return 0;
	}

	if (tpcache->tc_tfo_cookie_len == 0) {
		tcp_cache_unlock(head);
		return 0;
	}

	/*
	 * Not enough space - this should never happen as it has been checked
	 * in tcp_tfo_check. So, fail here!
	 */
	VERIFY(tpcache->tc_tfo_cookie_len <= *len);

	memcpy(cookie, tpcache->tc_tfo_cookie, tpcache->tc_tfo_cookie_len);
	*len = tpcache->tc_tfo_cookie_len;

	tcp_cache_unlock(head);

	return 1;
}

/*
 * Get the cookie related to 'tp', and copy it into 'cookie', provided that len
 * is big enough (len designates the available memory.
 * Upon return, 'len' is set to the cookie's length.
 *
 * Returns 0 if we should request a cookie.
 * Returns 1 if the cookie has been found and written.
 */
int
tcp_cache_get_cookie(struct tcpcb *tp, u_char *cookie, uint8_t *len)
{
	struct tcp_cache_key_src tcks;

	tcp_cache_key_src_create(tp, &tcks);
	return tcp_cache_get_cookie_common(&tcks, cookie, len);
}

static unsigned int
tcp_cache_get_cookie_len_common(struct tcp_cache_key_src *tcks)
{
	struct tcp_cache_head *head;
	struct tcp_cache *tpcache;
	unsigned int cookie_len;

	/* Call lookup/create function */
	tpcache = tcp_getcache_with_lock(tcks, 1, &head);
	if (tpcache == NULL) {
		return 0;
	}

	cookie_len = tpcache->tc_tfo_cookie_len;

	tcp_cache_unlock(head);

	return cookie_len;
}

unsigned int
tcp_cache_get_cookie_len(struct tcpcb *tp)
{
	struct tcp_cache_key_src tcks;

	tcp_cache_key_src_create(tp, &tcks);
	return tcp_cache_get_cookie_len_common(&tcks);
}

static uint16_t
tcp_heuristics_hash(struct tcp_cache_key_src *tcks, struct tcp_heuristic_key *key)
{
	uint32_t hash;

	bzero(key, sizeof(struct tcp_heuristic_key));

	tcp_cache_hash_src(tcks, key);

	hash = net_flowhash(key, sizeof(struct tcp_heuristic_key),
	    tcp_cache_hash_seed);

	return (uint16_t)(hash & (tcp_cache_size - 1));
}

static void
tcp_heuristic_unlock(struct tcp_heuristics_head *head)
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
static struct tcp_heuristic *
tcp_getheuristic_with_lock(struct tcp_cache_key_src *tcks,
    int create, struct tcp_heuristics_head **headarg)
{
	struct tcp_heuristic *tpheur = NULL;
	struct tcp_heuristics_head *head;
	struct tcp_heuristic_key key;
	uint16_t hash;
	int i = 0;

	hash = tcp_heuristics_hash(tcks, &key);
	head = &tcp_heuristics[hash];

	lck_mtx_lock(&head->thh_mtx);

	/*** First step: Look for the tcp_heur in our bucket ***/
	SLIST_FOREACH(tpheur, &head->tcp_heuristics, list) {
		if (memcmp(&tpheur->th_key, &key, sizeof(key)) == 0) {
			break;
		}

		i++;
	}

	/*** Second step: If it's not there, create/recycle it ***/
	if ((tpheur == NULL) && create) {
		if (i >= TCP_CACHE_BUCKET_SIZE) {
			struct tcp_heuristic *oldest_heur = NULL;
			uint32_t max_age = 0;

			/* Look for the oldest tcp_heur in the bucket */
			SLIST_FOREACH(tpheur, &head->tcp_heuristics, list) {
				uint32_t age = tcp_now - tpheur->th_last_access;
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
			if (tpheur == NULL) {
				os_log_error(OS_LOG_DEFAULT, "%s could not allocate cache", __func__);
				goto out_null;
			}

			SLIST_INSERT_HEAD(&head->tcp_heuristics, tpheur, list);
		}

		/*
		 * Set to tcp_now, to make sure it won't be > than tcp_now in the
		 * near future.
		 */
		tpheur->th_ecn_backoff = tcp_now;
		tpheur->th_tfo_backoff_until = tcp_now;
		tpheur->th_mptcp_backoff = tcp_now;
		tpheur->th_tfo_backoff = tcp_min_to_hz(tcp_ecn_timeout);

		memcpy(&tpheur->th_key, &key, sizeof(key));
	}

	if (tpheur == NULL) {
		goto out_null;
	}

	/* Update timestamp for garbage collection purposes */
	tpheur->th_last_access = tcp_now;
	*headarg = head;

	return tpheur;

out_null:
	tcp_heuristic_unlock(head);
	return NULL;
}

static void
tcp_heuristic_reset_counters(struct tcp_cache_key_src *tcks, uint8_t flags)
{
	struct tcp_heuristics_head *head;
	struct tcp_heuristic *tpheur;

	/*
	 * Always create heuristics here because MPTCP needs to write success
	 * into it. Thus, we always end up creating them.
	 */
	tpheur = tcp_getheuristic_with_lock(tcks, 1, &head);
	if (tpheur == NULL) {
		return;
	}

	if (flags & TCPCACHE_F_TFO_DATA) {
		if (tpheur->th_tfo_data_loss >= TFO_MAX_COOKIE_LOSS) {
			os_log(OS_LOG_DEFAULT, "%s: Resetting TFO-data loss to 0 from %u on heur %lx\n",
			    __func__, tpheur->th_tfo_data_loss, (unsigned long)VM_KERNEL_ADDRPERM(tpheur));
		}
		tpheur->th_tfo_data_loss = 0;
	}

	if (flags & TCPCACHE_F_TFO_REQ) {
		if (tpheur->th_tfo_req_loss >= TFO_MAX_COOKIE_LOSS) {
			os_log(OS_LOG_DEFAULT, "%s: Resetting TFO-req loss to 0 from %u on heur %lx\n",
			    __func__, tpheur->th_tfo_req_loss, (unsigned long)VM_KERNEL_ADDRPERM(tpheur));
		}
		tpheur->th_tfo_req_loss = 0;
	}

	if (flags & TCPCACHE_F_TFO_DATA_RST) {
		if (tpheur->th_tfo_data_rst >= TFO_MAX_COOKIE_LOSS) {
			os_log(OS_LOG_DEFAULT, "%s: Resetting TFO-data RST to 0 from %u on heur %lx\n",
			    __func__, tpheur->th_tfo_data_rst, (unsigned long)VM_KERNEL_ADDRPERM(tpheur));
		}
		tpheur->th_tfo_data_rst = 0;
	}

	if (flags & TCPCACHE_F_TFO_REQ_RST) {
		if (tpheur->th_tfo_req_rst >= TFO_MAX_COOKIE_LOSS) {
			os_log(OS_LOG_DEFAULT, "%s: Resetting TFO-req RST to 0 from %u on heur %lx\n",
			    __func__, tpheur->th_tfo_req_rst, (unsigned long)VM_KERNEL_ADDRPERM(tpheur));
		}
		tpheur->th_tfo_req_rst = 0;
	}

	if (flags & TCPCACHE_F_ECN) {
		if (tpheur->th_ecn_loss >= ECN_MAX_SYN_LOSS || tpheur->th_ecn_synrst >= ECN_MAX_SYNRST) {
			os_log(OS_LOG_DEFAULT, "%s: Resetting ECN-loss to 0 from %u and synrst from %u on heur %lx\n",
			    __func__, tpheur->th_ecn_loss, tpheur->th_ecn_synrst, (unsigned long)VM_KERNEL_ADDRPERM(tpheur));
		}
		tpheur->th_ecn_loss = 0;
		tpheur->th_ecn_synrst = 0;
	}

	if (flags & TCPCACHE_F_MPTCP) {
		tpheur->th_mptcp_loss = 0;
		if (tpheur->th_mptcp_success < MPTCP_SUCCESS_TRIGGER) {
			tpheur->th_mptcp_success++;

			if (tpheur->th_mptcp_success == MPTCP_SUCCESS_TRIGGER) {
				os_log(mptcp_log_handle, "%s disabling heuristics for 12 hours", __func__);
				tpheur->th_mptcp_heuristic_disabled = 1;
				/* Disable heuristics for 12 hours */
				tpheur->th_mptcp_backoff = tcp_now + tcp_min_to_hz(tcp_ecn_timeout * 12);
			}
		}
	}

	tcp_heuristic_unlock(head);
}

void
tcp_heuristic_tfo_success(struct tcpcb *tp)
{
	struct tcp_cache_key_src tcks;
	uint8_t flag = 0;

	tcp_cache_key_src_create(tp, &tcks);

	if (tp->t_tfo_stats & TFO_S_SYN_DATA_SENT) {
		flag = (TCPCACHE_F_TFO_DATA | TCPCACHE_F_TFO_REQ |
		    TCPCACHE_F_TFO_DATA_RST | TCPCACHE_F_TFO_REQ_RST);
	}
	if (tp->t_tfo_stats & TFO_S_COOKIE_REQ) {
		flag = (TCPCACHE_F_TFO_REQ | TCPCACHE_F_TFO_REQ_RST);
	}

	tcp_heuristic_reset_counters(&tcks, flag);
}

void
tcp_heuristic_mptcp_success(struct tcpcb *tp)
{
	struct tcp_cache_key_src tcks;

	tcp_cache_key_src_create(tp, &tcks);
	tcp_heuristic_reset_counters(&tcks, TCPCACHE_F_MPTCP);
}

void
tcp_heuristic_ecn_success(struct tcpcb *tp)
{
	struct tcp_cache_key_src tcks;

	tcp_cache_key_src_create(tp, &tcks);
	tcp_heuristic_reset_counters(&tcks, TCPCACHE_F_ECN);
}

static void
__tcp_heuristic_tfo_middlebox_common(struct tcp_heuristic *tpheur)
{
	if (tpheur->th_tfo_in_backoff) {
		return;
	}

	tpheur->th_tfo_in_backoff = 1;

	if (tpheur->th_tfo_enabled_time) {
		uint32_t old_backoff = tpheur->th_tfo_backoff;

		tpheur->th_tfo_backoff -= (tcp_now - tpheur->th_tfo_enabled_time);
		if (tpheur->th_tfo_backoff > old_backoff) {
			tpheur->th_tfo_backoff = tcp_min_to_hz(tcp_ecn_timeout);
		}
	}

	tpheur->th_tfo_backoff_until = tcp_now + tpheur->th_tfo_backoff;

	/* Then, increase the backoff time */
	tpheur->th_tfo_backoff *= 2;

	if (tpheur->th_tfo_backoff > tcp_min_to_hz(tcp_backoff_maximum)) {
		tpheur->th_tfo_backoff = tcp_min_to_hz(tcp_ecn_timeout);
	}

	os_log(OS_LOG_DEFAULT, "%s disable TFO until %u now %u on %lx\n", __func__,
	    tpheur->th_tfo_backoff_until, tcp_now, (unsigned long)VM_KERNEL_ADDRPERM(tpheur));
}

static void
tcp_heuristic_tfo_middlebox_common(struct tcp_cache_key_src *tcks)
{
	struct tcp_heuristics_head *head;
	struct tcp_heuristic *tpheur;

	tpheur = tcp_getheuristic_with_lock(tcks, 1, &head);
	if (tpheur == NULL) {
		return;
	}

	__tcp_heuristic_tfo_middlebox_common(tpheur);

	tcp_heuristic_unlock(head);
}

static void
tcp_heuristic_inc_counters(struct tcp_cache_key_src *tcks,
    uint32_t flags)
{
	struct tcp_heuristics_head *head;
	struct tcp_heuristic *tpheur;

	tpheur = tcp_getheuristic_with_lock(tcks, 1, &head);
	if (tpheur == NULL) {
		return;
	}

	/* Limit to prevent integer-overflow during exponential backoff */
	if ((flags & TCPCACHE_F_TFO_DATA) && tpheur->th_tfo_data_loss < TCP_CACHE_OVERFLOW_PROTECT) {
		tpheur->th_tfo_data_loss++;

		if (tpheur->th_tfo_data_loss >= TFO_MAX_COOKIE_LOSS) {
			__tcp_heuristic_tfo_middlebox_common(tpheur);
		}
	}

	if ((flags & TCPCACHE_F_TFO_REQ) && tpheur->th_tfo_req_loss < TCP_CACHE_OVERFLOW_PROTECT) {
		tpheur->th_tfo_req_loss++;

		if (tpheur->th_tfo_req_loss >= TFO_MAX_COOKIE_LOSS) {
			__tcp_heuristic_tfo_middlebox_common(tpheur);
		}
	}

	if ((flags & TCPCACHE_F_TFO_DATA_RST) && tpheur->th_tfo_data_rst < TCP_CACHE_OVERFLOW_PROTECT) {
		tpheur->th_tfo_data_rst++;

		if (tpheur->th_tfo_data_rst >= TFO_MAX_COOKIE_LOSS) {
			__tcp_heuristic_tfo_middlebox_common(tpheur);
		}
	}

	if ((flags & TCPCACHE_F_TFO_REQ_RST) && tpheur->th_tfo_req_rst < TCP_CACHE_OVERFLOW_PROTECT) {
		tpheur->th_tfo_req_rst++;

		if (tpheur->th_tfo_req_rst >= TFO_MAX_COOKIE_LOSS) {
			__tcp_heuristic_tfo_middlebox_common(tpheur);
		}
	}

	if ((flags & TCPCACHE_F_ECN) &&
	    tpheur->th_ecn_loss < TCP_CACHE_OVERFLOW_PROTECT &&
	    TSTMP_LEQ(tpheur->th_ecn_backoff, tcp_now)) {
		tpheur->th_ecn_loss++;
		if (tpheur->th_ecn_loss >= ECN_MAX_SYN_LOSS) {
			tcpstat.tcps_ecn_fallback_synloss++;
			TCP_CACHE_INC_IFNET_STAT(tcks->ifp, tcks->af, ecn_fallback_synloss);
			tpheur->th_ecn_backoff = tcp_now +
			    (tcp_min_to_hz(tcp_ecn_timeout) <<
			    (tpheur->th_ecn_loss - ECN_MAX_SYN_LOSS));

			os_log(OS_LOG_DEFAULT, "%s disable ECN until %u now %u on %lx for SYN-loss\n",
			    __func__, tpheur->th_ecn_backoff, tcp_now,
			    (unsigned long)VM_KERNEL_ADDRPERM(tpheur));
		}
	}

	if ((flags & TCPCACHE_F_MPTCP) &&
	    tpheur->th_mptcp_loss < TCP_CACHE_OVERFLOW_PROTECT &&
	    tpheur->th_mptcp_heuristic_disabled == 0) {
		tpheur->th_mptcp_loss++;
		if (tpheur->th_mptcp_loss >= MPTCP_MAX_SYN_LOSS) {
			/*
			 * Yes, we take tcp_ecn_timeout, to avoid adding yet
			 * another sysctl that is just used for testing.
			 */
			tpheur->th_mptcp_backoff = tcp_now +
			    (tcp_min_to_hz(tcp_ecn_timeout) <<
			    (tpheur->th_mptcp_loss - MPTCP_MAX_SYN_LOSS));
			tpheur->th_mptcp_in_backoff = 1;

			os_log(OS_LOG_DEFAULT, "%s disable MPTCP until %u now %u on %lx\n",
			    __func__, tpheur->th_mptcp_backoff, tcp_now,
			    (unsigned long)VM_KERNEL_ADDRPERM(tpheur));
		}
	}

	if ((flags & TCPCACHE_F_ECN_DROPRST) &&
	    tpheur->th_ecn_droprst < TCP_CACHE_OVERFLOW_PROTECT &&
	    TSTMP_LEQ(tpheur->th_ecn_backoff, tcp_now)) {
		tpheur->th_ecn_droprst++;
		if (tpheur->th_ecn_droprst >= ECN_MAX_DROPRST) {
			tcpstat.tcps_ecn_fallback_droprst++;
			TCP_CACHE_INC_IFNET_STAT(tcks->ifp, tcks->af,
			    ecn_fallback_droprst);
			tpheur->th_ecn_backoff = tcp_now +
			    (tcp_min_to_hz(tcp_ecn_timeout) <<
			    (tpheur->th_ecn_droprst - ECN_MAX_DROPRST));

			os_log(OS_LOG_DEFAULT, "%s disable ECN until %u now %u on %lx for drop-RST\n",
			    __func__, tpheur->th_ecn_backoff, tcp_now,
			    (unsigned long)VM_KERNEL_ADDRPERM(tpheur));
		}
	}

	if ((flags & TCPCACHE_F_ECN_DROPRXMT) &&
	    tpheur->th_ecn_droprxmt < TCP_CACHE_OVERFLOW_PROTECT &&
	    TSTMP_LEQ(tpheur->th_ecn_backoff, tcp_now)) {
		tpheur->th_ecn_droprxmt++;
		if (tpheur->th_ecn_droprxmt >= ECN_MAX_DROPRXMT) {
			tcpstat.tcps_ecn_fallback_droprxmt++;
			TCP_CACHE_INC_IFNET_STAT(tcks->ifp, tcks->af,
			    ecn_fallback_droprxmt);
			tpheur->th_ecn_backoff = tcp_now +
			    (tcp_min_to_hz(tcp_ecn_timeout) <<
			    (tpheur->th_ecn_droprxmt - ECN_MAX_DROPRXMT));

			os_log(OS_LOG_DEFAULT, "%s disable ECN until %u now %u on %lx for drop-Rxmit\n",
			    __func__, tpheur->th_ecn_backoff, tcp_now,
			    (unsigned long)VM_KERNEL_ADDRPERM(tpheur));
		}
	}
	if ((flags & TCPCACHE_F_ECN_SYNRST) &&
	    tpheur->th_ecn_synrst < TCP_CACHE_OVERFLOW_PROTECT) {
		tpheur->th_ecn_synrst++;
		if (tpheur->th_ecn_synrst >= ECN_MAX_SYNRST) {
			tcpstat.tcps_ecn_fallback_synrst++;
			TCP_CACHE_INC_IFNET_STAT(tcks->ifp, tcks->af,
			    ecn_fallback_synrst);
			tpheur->th_ecn_backoff = tcp_now +
			    (tcp_min_to_hz(tcp_ecn_timeout) <<
			    (tpheur->th_ecn_synrst - ECN_MAX_SYNRST));

			os_log(OS_LOG_DEFAULT, "%s disable ECN until %u now %u on %lx for SYN-RST\n",
			    __func__, tpheur->th_ecn_backoff, tcp_now,
			    (unsigned long)VM_KERNEL_ADDRPERM(tpheur));
		}
	}
	tcp_heuristic_unlock(head);
}

void
tcp_heuristic_tfo_loss(struct tcpcb *tp)
{
	struct tcp_cache_key_src tcks;
	uint32_t flag = 0;

	if (symptoms_is_wifi_lossy() &&
	    IFNET_IS_WIFI(tp->t_inpcb->inp_last_outifp)) {
		return;
	}

	tcp_cache_key_src_create(tp, &tcks);

	if (tp->t_tfo_stats & TFO_S_SYN_DATA_SENT) {
		flag = (TCPCACHE_F_TFO_DATA | TCPCACHE_F_TFO_REQ);
	}
	if (tp->t_tfo_stats & TFO_S_COOKIE_REQ) {
		flag = TCPCACHE_F_TFO_REQ;
	}

	tcp_heuristic_inc_counters(&tcks, flag);
}

void
tcp_heuristic_tfo_rst(struct tcpcb *tp)
{
	struct tcp_cache_key_src tcks;
	uint32_t flag = 0;

	tcp_cache_key_src_create(tp, &tcks);

	if (tp->t_tfo_stats & TFO_S_SYN_DATA_SENT) {
		flag = (TCPCACHE_F_TFO_DATA_RST | TCPCACHE_F_TFO_REQ_RST);
	}
	if (tp->t_tfo_stats & TFO_S_COOKIE_REQ) {
		flag = TCPCACHE_F_TFO_REQ_RST;
	}

	tcp_heuristic_inc_counters(&tcks, flag);
}

void
tcp_heuristic_mptcp_loss(struct tcpcb *tp)
{
	struct tcp_cache_key_src tcks;

	if (symptoms_is_wifi_lossy() &&
	    IFNET_IS_WIFI(tp->t_inpcb->inp_last_outifp)) {
		return;
	}

	tcp_cache_key_src_create(tp, &tcks);

	tcp_heuristic_inc_counters(&tcks, TCPCACHE_F_MPTCP);
}

void
tcp_heuristic_ecn_loss(struct tcpcb *tp)
{
	struct tcp_cache_key_src tcks;

	if (symptoms_is_wifi_lossy() &&
	    IFNET_IS_WIFI(tp->t_inpcb->inp_last_outifp)) {
		return;
	}

	tcp_cache_key_src_create(tp, &tcks);

	tcp_heuristic_inc_counters(&tcks, TCPCACHE_F_ECN);
}

void
tcp_heuristic_ecn_droprst(struct tcpcb *tp)
{
	struct tcp_cache_key_src tcks;

	tcp_cache_key_src_create(tp, &tcks);

	tcp_heuristic_inc_counters(&tcks, TCPCACHE_F_ECN_DROPRST);
}

void
tcp_heuristic_ecn_droprxmt(struct tcpcb *tp)
{
	struct tcp_cache_key_src tcks;

	tcp_cache_key_src_create(tp, &tcks);

	tcp_heuristic_inc_counters(&tcks, TCPCACHE_F_ECN_DROPRXMT);
}

void
tcp_heuristic_ecn_synrst(struct tcpcb *tp)
{
	struct tcp_cache_key_src tcks;

	tcp_cache_key_src_create(tp, &tcks);

	tcp_heuristic_inc_counters(&tcks, TCPCACHE_F_ECN_SYNRST);
}

void
tcp_heuristic_tfo_middlebox(struct tcpcb *tp)
{
	struct tcp_cache_key_src tcks;

	tp->t_tfo_flags |= TFO_F_HEURISTIC_DONE;

	tcp_cache_key_src_create(tp, &tcks);
	tcp_heuristic_tfo_middlebox_common(&tcks);
}

static void
tcp_heuristic_ecn_aggressive_common(struct tcp_cache_key_src *tcks)
{
	struct tcp_heuristics_head *head;
	struct tcp_heuristic *tpheur;

	tpheur = tcp_getheuristic_with_lock(tcks, 1, &head);
	if (tpheur == NULL) {
		return;
	}

	if (TSTMP_GT(tpheur->th_ecn_backoff, tcp_now)) {
		/* We are already in aggressive mode */
		tcp_heuristic_unlock(head);
		return;
	}

	/* Must be done before, otherwise we will start off with expo-backoff */
	tpheur->th_ecn_backoff = tcp_now +
	    (tcp_min_to_hz(tcp_ecn_timeout) << (tpheur->th_ecn_aggressive));

	/*
	 * Ugly way to prevent integer overflow... limit to prevent in
	 * overflow during exp. backoff.
	 */
	if (tpheur->th_ecn_aggressive < TCP_CACHE_OVERFLOW_PROTECT) {
		tpheur->th_ecn_aggressive++;
	}

	tcp_heuristic_unlock(head);

	os_log(OS_LOG_DEFAULT, "%s disable ECN until %u now %u on %lx\n", __func__,
	    tpheur->th_ecn_backoff, tcp_now, (unsigned long)VM_KERNEL_ADDRPERM(tpheur));
}

void
tcp_heuristic_ecn_aggressive(struct tcpcb *tp)
{
	struct tcp_cache_key_src tcks;

	tcp_cache_key_src_create(tp, &tcks);
	tcp_heuristic_ecn_aggressive_common(&tcks);
}

static boolean_t
tcp_heuristic_do_tfo_common(struct tcp_cache_key_src *tcks)
{
	struct tcp_heuristics_head *head;
	struct tcp_heuristic *tpheur;

	if (disable_tcp_heuristics) {
		return TRUE;
	}

	/* Get the tcp-heuristic. */
	tpheur = tcp_getheuristic_with_lock(tcks, 0, &head);
	if (tpheur == NULL) {
		return TRUE;
	}

	if (tpheur->th_tfo_in_backoff == 0) {
		goto tfo_ok;
	}

	if (TSTMP_GT(tcp_now, tpheur->th_tfo_backoff_until)) {
		tpheur->th_tfo_in_backoff = 0;
		tpheur->th_tfo_enabled_time = tcp_now;

		goto tfo_ok;
	}

	tcp_heuristic_unlock(head);
	return FALSE;

tfo_ok:
	tcp_heuristic_unlock(head);
	return TRUE;
}

boolean_t
tcp_heuristic_do_tfo(struct tcpcb *tp)
{
	struct tcp_cache_key_src tcks;

	tcp_cache_key_src_create(tp, &tcks);
	if (tcp_heuristic_do_tfo_common(&tcks)) {
		return TRUE;
	}

	return FALSE;
}
/*
 * @return:
 *         0	Enable MPTCP (we are still discovering middleboxes)
 *         -1	Enable MPTCP (heuristics have been temporarily disabled)
 *         1	Disable MPTCP
 */
int
tcp_heuristic_do_mptcp(struct tcpcb *tp)
{
	struct tcp_cache_key_src tcks;
	struct tcp_heuristics_head *head = NULL;
	struct tcp_heuristic *tpheur;
	int ret = 0;

	if (disable_tcp_heuristics ||
	    (tptomptp(tp)->mpt_mpte->mpte_flags & MPTE_FORCE_ENABLE)) {
		return 0;
	}

	tcp_cache_key_src_create(tp, &tcks);

	/* Get the tcp-heuristic. */
	tpheur = tcp_getheuristic_with_lock(&tcks, 0, &head);
	if (tpheur == NULL) {
		return 0;
	}

	if (tpheur->th_mptcp_in_backoff == 0 ||
	    tpheur->th_mptcp_heuristic_disabled == 1) {
		goto mptcp_ok;
	}

	if (TSTMP_GT(tpheur->th_mptcp_backoff, tcp_now)) {
		goto fallback;
	}

	tpheur->th_mptcp_in_backoff = 0;

mptcp_ok:
	if (tpheur->th_mptcp_heuristic_disabled) {
		ret = -1;

		if (TSTMP_GT(tcp_now, tpheur->th_mptcp_backoff)) {
			tpheur->th_mptcp_heuristic_disabled = 0;
			tpheur->th_mptcp_success = 0;
		}
	}

	tcp_heuristic_unlock(head);
	return ret;

fallback:
	if (head) {
		tcp_heuristic_unlock(head);
	}

	if (tptomptp(tp)->mpt_mpte->mpte_flags & MPTE_FIRSTPARTY) {
		tcpstat.tcps_mptcp_fp_heuristic_fallback++;
	} else {
		tcpstat.tcps_mptcp_heuristic_fallback++;
	}

	return 1;
}

static boolean_t
tcp_heuristic_do_ecn_common(struct tcp_cache_key_src *tcks)
{
	struct tcp_heuristics_head *head;
	struct tcp_heuristic *tpheur;
	boolean_t ret = TRUE;

	if (disable_tcp_heuristics) {
		return TRUE;
	}

	/* Get the tcp-heuristic. */
	tpheur = tcp_getheuristic_with_lock(tcks, 0, &head);
	if (tpheur == NULL) {
		return ret;
	}

	if (TSTMP_GT(tpheur->th_ecn_backoff, tcp_now)) {
		ret = FALSE;
	} else {
		/* Reset the following counters to start re-evaluating */
		if (tpheur->th_ecn_droprst >= ECN_RETRY_LIMIT) {
			tpheur->th_ecn_droprst = 0;
		}
		if (tpheur->th_ecn_droprxmt >= ECN_RETRY_LIMIT) {
			tpheur->th_ecn_droprxmt = 0;
		}
		if (tpheur->th_ecn_synrst >= ECN_RETRY_LIMIT) {
			tpheur->th_ecn_synrst = 0;
		}

		/* Make sure it follows along */
		tpheur->th_ecn_backoff = tcp_now;
	}

	tcp_heuristic_unlock(head);

	return ret;
}

boolean_t
tcp_heuristic_do_ecn(struct tcpcb *tp)
{
	struct tcp_cache_key_src tcks;

	tcp_cache_key_src_create(tp, &tcks);
	return tcp_heuristic_do_ecn_common(&tcks);
}

boolean_t
tcp_heuristic_do_ecn_with_address(struct ifnet *ifp,
    union sockaddr_in_4_6 *local_address)
{
	struct tcp_cache_key_src tcks;

	memset(&tcks, 0, sizeof(tcks));
	tcks.ifp = ifp;

	calculate_tcp_clock();

	if (local_address->sa.sa_family == AF_INET6) {
		memcpy(&tcks.laddr.addr6, &local_address->sin6.sin6_addr, sizeof(struct in6_addr));
		tcks.af = AF_INET6;
	} else if (local_address->sa.sa_family == AF_INET) {
		memcpy(&tcks.laddr.addr, &local_address->sin.sin_addr, sizeof(struct in_addr));
		tcks.af = AF_INET;
	}

	return tcp_heuristic_do_ecn_common(&tcks);
}

void
tcp_heuristics_ecn_update(struct necp_tcp_ecn_cache *necp_buffer,
    struct ifnet *ifp, union sockaddr_in_4_6 *local_address)
{
	struct tcp_cache_key_src tcks;

	memset(&tcks, 0, sizeof(tcks));
	tcks.ifp = ifp;

	calculate_tcp_clock();

	if (local_address->sa.sa_family == AF_INET6) {
		memcpy(&tcks.laddr.addr6, &local_address->sin6.sin6_addr, sizeof(struct in6_addr));
		tcks.af = AF_INET6;
	} else if (local_address->sa.sa_family == AF_INET) {
		memcpy(&tcks.laddr.addr, &local_address->sin.sin_addr, sizeof(struct in_addr));
		tcks.af = AF_INET;
	}

	if (necp_buffer->necp_tcp_ecn_heuristics_success) {
		tcp_heuristic_reset_counters(&tcks, TCPCACHE_F_ECN);
	} else if (necp_buffer->necp_tcp_ecn_heuristics_loss) {
		tcp_heuristic_inc_counters(&tcks, TCPCACHE_F_ECN);
	} else if (necp_buffer->necp_tcp_ecn_heuristics_drop_rst) {
		tcp_heuristic_inc_counters(&tcks, TCPCACHE_F_ECN_DROPRST);
	} else if (necp_buffer->necp_tcp_ecn_heuristics_drop_rxmt) {
		tcp_heuristic_inc_counters(&tcks, TCPCACHE_F_ECN_DROPRXMT);
	} else if (necp_buffer->necp_tcp_ecn_heuristics_syn_rst) {
		tcp_heuristic_inc_counters(&tcks, TCPCACHE_F_ECN_SYNRST);
	} else if (necp_buffer->necp_tcp_ecn_heuristics_aggressive) {
		tcp_heuristic_ecn_aggressive_common(&tcks);
	}

	return;
}

boolean_t
tcp_heuristic_do_tfo_with_address(struct ifnet *ifp,
    union sockaddr_in_4_6 *local_address, union sockaddr_in_4_6 *remote_address,
    uint8_t *cookie, uint8_t *cookie_len)
{
	struct tcp_cache_key_src tcks;

	memset(&tcks, 0, sizeof(tcks));
	tcks.ifp = ifp;

	calculate_tcp_clock();

	if (remote_address->sa.sa_family == AF_INET6) {
		memcpy(&tcks.laddr.addr6, &local_address->sin6.sin6_addr, sizeof(struct in6_addr));
		memcpy(&tcks.faddr.addr6, &remote_address->sin6.sin6_addr, sizeof(struct in6_addr));
		tcks.af = AF_INET6;
	} else if (remote_address->sa.sa_family == AF_INET) {
		memcpy(&tcks.laddr.addr, &local_address->sin.sin_addr, sizeof(struct in_addr));
		memcpy(&tcks.faddr.addr, &remote_address->sin.sin_addr, sizeof(struct in_addr));
		tcks.af = AF_INET;
	}

	if (tcp_heuristic_do_tfo_common(&tcks)) {
		if (!tcp_cache_get_cookie_common(&tcks, cookie, cookie_len)) {
			*cookie_len = 0;
		}
		return TRUE;
	}

	return FALSE;
}

void
tcp_heuristics_tfo_update(struct necp_tcp_tfo_cache *necp_buffer,
    struct ifnet *ifp, union sockaddr_in_4_6 *local_address,
    union sockaddr_in_4_6 *remote_address)
{
	struct tcp_cache_key_src tcks;

	memset(&tcks, 0, sizeof(tcks));
	tcks.ifp = ifp;

	calculate_tcp_clock();

	if (remote_address->sa.sa_family == AF_INET6) {
		memcpy(&tcks.laddr.addr6, &local_address->sin6.sin6_addr, sizeof(struct in6_addr));
		memcpy(&tcks.faddr.addr6, &remote_address->sin6.sin6_addr, sizeof(struct in6_addr));
		tcks.af = AF_INET6;
	} else if (remote_address->sa.sa_family == AF_INET) {
		memcpy(&tcks.laddr.addr, &local_address->sin.sin_addr, sizeof(struct in_addr));
		memcpy(&tcks.faddr.addr, &remote_address->sin.sin_addr, sizeof(struct in_addr));
		tcks.af = AF_INET;
	}

	if (necp_buffer->necp_tcp_tfo_heuristics_success) {
		tcp_heuristic_reset_counters(&tcks, TCPCACHE_F_TFO_REQ | TCPCACHE_F_TFO_DATA |
		    TCPCACHE_F_TFO_REQ_RST | TCPCACHE_F_TFO_DATA_RST);
	}

	if (necp_buffer->necp_tcp_tfo_heuristics_success_req) {
		tcp_heuristic_reset_counters(&tcks, TCPCACHE_F_TFO_REQ | TCPCACHE_F_TFO_REQ_RST);
	}

	if (necp_buffer->necp_tcp_tfo_heuristics_loss) {
		tcp_heuristic_inc_counters(&tcks, TCPCACHE_F_TFO_REQ | TCPCACHE_F_TFO_DATA);
	}

	if (necp_buffer->necp_tcp_tfo_heuristics_loss_req) {
		tcp_heuristic_inc_counters(&tcks, TCPCACHE_F_TFO_REQ);
	}

	if (necp_buffer->necp_tcp_tfo_heuristics_rst_data) {
		tcp_heuristic_inc_counters(&tcks, TCPCACHE_F_TFO_REQ_RST | TCPCACHE_F_TFO_DATA_RST);
	}

	if (necp_buffer->necp_tcp_tfo_heuristics_rst_req) {
		tcp_heuristic_inc_counters(&tcks, TCPCACHE_F_TFO_REQ_RST);
	}

	if (necp_buffer->necp_tcp_tfo_heuristics_middlebox) {
		tcp_heuristic_tfo_middlebox_common(&tcks);
	}

	if (necp_buffer->necp_tcp_tfo_cookie_len != 0) {
		tcp_cache_set_cookie_common(&tcks,
		    necp_buffer->necp_tcp_tfo_cookie, necp_buffer->necp_tcp_tfo_cookie_len);
	}

	return;
}

static void
sysctl_cleartfocache(void)
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
	if (error || !req->newptr) {
		if (error) {
			os_log_error(OS_LOG_DEFAULT, "%s could not parse int: %d", __func__, error);
		}
		return error;
	}

	/*
	 * The actual value does not matter. If the value is set, it triggers
	 * the clearing of the TFO cache. If a future implementation does not
	 * use the route entry to hold the TFO cache, replace the route sysctl.
	 */

	if (val != oldval) {
		sysctl_cleartfocache();
	}

	tcpcleartfo = val;

	return error;
}

SYSCTL_PROC(_net_inet_tcp, OID_AUTO, clear_tfocache, CTLTYPE_INT | CTLFLAG_RW |
    CTLFLAG_LOCKED, &tcpcleartfo, 0, &sysctl_cleartfo, "I",
    "Toggle to clear the TFO destination based heuristic cache");

void
tcp_cache_init(void)
{
	uint64_t sane_size_meg = sane_size / 1024 / 1024;
	int i;

	/*
	 * On machines with <100MB of memory this will result in a (full) cache-size
	 * of 32 entries, thus 32 * 5 * 64bytes = 10KB. (about 0.01 %)
	 * On machines with > 4GB of memory, we have a cache-size of 1024 entries,
	 * thus about 327KB.
	 *
	 * Side-note: we convert to uint32_t. If sane_size is more than
	 * 16000 TB, we loose precision. But, who cares? :)
	 */
	tcp_cache_size = tcp_cache_roundup2((uint32_t)(sane_size_meg >> 2));
	if (tcp_cache_size < 32) {
		tcp_cache_size = 32;
	} else if (tcp_cache_size > 1024) {
		tcp_cache_size = 1024;
	}

	tcp_cache = _MALLOC(sizeof(struct tcp_cache_head) * tcp_cache_size,
	    M_TEMP, M_ZERO);
	if (tcp_cache == NULL) {
		panic("Allocating tcp_cache failed at boot-time!");
	}

	tcp_cache_mtx_grp_attr = lck_grp_attr_alloc_init();
	tcp_cache_mtx_grp = lck_grp_alloc_init("tcpcache", tcp_cache_mtx_grp_attr);
	tcp_cache_mtx_attr = lck_attr_alloc_init();

	tcp_heuristics = _MALLOC(sizeof(struct tcp_heuristics_head) * tcp_cache_size,
	    M_TEMP, M_ZERO);
	if (tcp_heuristics == NULL) {
		panic("Allocating tcp_heuristic failed at boot-time!");
	}

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
