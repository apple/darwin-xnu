/*
 * Copyright (c) 2007-2015 Apple Inc. All rights reserved.
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

/*	$apfw: git commit b6bf13f8321283cd7ee82b1795e86506084b1b95 $ */
/*	$OpenBSD: pf_ioctl.c,v 1.175 2007/02/26 22:47:43 deraadt Exp $ */

/*
 * Copyright (c) 2001 Daniel Hartmeier
 * Copyright (c) 2002,2003 Henning Brauer
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Effort sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F30602-01-2-0537.
 *
 */

#include <machine/endian.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/filio.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/kernel.h>
#include <sys/time.h>
#include <sys/proc_internal.h>
#include <sys/malloc.h>
#include <sys/kauth.h>
#include <sys/conf.h>
#include <sys/mcache.h>
#include <sys/queue.h>

#include <mach/vm_param.h>

#include <net/dlil.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/net_api_stats.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>

#if DUMMYNET
#include <netinet/ip_dummynet.h>
#else
struct ip_fw_args;
#endif /* DUMMYNET */

#include <libkern/crypto/md5.h>

#include <machine/machine_routines.h>

#include <miscfs/devfs/devfs.h>

#include <net/pfvar.h>

#if NPFSYNC
#include <net/if_pfsync.h>
#endif /* NPFSYNC */

#if PFLOG
#include <net/if_pflog.h>
#endif /* PFLOG */

#if INET6
#include <netinet/ip6.h>
#include <netinet/in_pcb.h>
#endif /* INET6 */

#include <dev/random/randomdev.h>

#if 0
static void pfdetach(void);
#endif
static int pfopen(dev_t, int, int, struct proc *);
static int pfclose(dev_t, int, int, struct proc *);
static int pfioctl(dev_t, u_long, caddr_t, int, struct proc *);
static int pfioctl_ioc_table(u_long, struct pfioc_table_32 *,
    struct pfioc_table_64 *, struct proc *);
static int pfioctl_ioc_tokens(u_long, struct pfioc_tokens_32 *,
    struct pfioc_tokens_64 *, struct proc *);
static int pfioctl_ioc_rule(u_long, int, struct pfioc_rule *, struct proc *);
static int pfioctl_ioc_state_kill(u_long, struct pfioc_state_kill *,
    struct proc *);
static int pfioctl_ioc_state(u_long, struct pfioc_state *, struct proc *);
static int pfioctl_ioc_states(u_long, struct pfioc_states_32 *,
    struct pfioc_states_64 *, struct proc *);
static int pfioctl_ioc_natlook(u_long, struct pfioc_natlook *, struct proc *);
static int pfioctl_ioc_tm(u_long, struct pfioc_tm *, struct proc *);
static int pfioctl_ioc_limit(u_long, struct pfioc_limit *, struct proc *);
static int pfioctl_ioc_pooladdr(u_long, struct pfioc_pooladdr *, struct proc *);
static int pfioctl_ioc_ruleset(u_long, struct pfioc_ruleset *, struct proc *);
static int pfioctl_ioc_trans(u_long, struct pfioc_trans_32 *,
    struct pfioc_trans_64 *, struct proc *);
static int pfioctl_ioc_src_nodes(u_long, struct pfioc_src_nodes_32 *,
    struct pfioc_src_nodes_64 *, struct proc *);
static int pfioctl_ioc_src_node_kill(u_long, struct pfioc_src_node_kill *,
    struct proc *);
static int pfioctl_ioc_iface(u_long, struct pfioc_iface_32 *,
    struct pfioc_iface_64 *, struct proc *);
static struct pf_pool *pf_get_pool(char *, u_int32_t, u_int8_t, u_int32_t,
    u_int8_t, u_int8_t, u_int8_t);
static void pf_mv_pool(struct pf_palist *, struct pf_palist *);
static void pf_empty_pool(struct pf_palist *);
static int pf_begin_rules(u_int32_t *, int, const char *);
static int pf_rollback_rules(u_int32_t, int, char *);
static int pf_setup_pfsync_matching(struct pf_ruleset *);
static void pf_hash_rule(MD5_CTX *, struct pf_rule *);
static void pf_hash_rule_addr(MD5_CTX *, struct pf_rule_addr *, u_int8_t);
static int pf_commit_rules(u_int32_t, int, char *);
static void pf_rule_copyin(struct pf_rule *, struct pf_rule *, struct proc *,
    int);
static void pf_rule_copyout(struct pf_rule *, struct pf_rule *);
static void pf_state_export(struct pfsync_state *, struct pf_state_key *,
    struct pf_state *);
static void pf_state_import(struct pfsync_state *, struct pf_state_key *,
    struct pf_state *);
static void pf_pooladdr_copyin(struct pf_pooladdr *, struct pf_pooladdr *);
static void pf_pooladdr_copyout(struct pf_pooladdr *, struct pf_pooladdr *);
static void pf_expire_states_and_src_nodes(struct pf_rule *);
static void pf_delete_rule_from_ruleset(struct pf_ruleset *,
    int, struct pf_rule *);
static void pf_addrwrap_setup(struct pf_addr_wrap *);
static int pf_rule_setup(struct pfioc_rule *, struct pf_rule *,
    struct pf_ruleset *);
static void pf_delete_rule_by_owner(char *, u_int32_t);
static int pf_delete_rule_by_ticket(struct pfioc_rule *, u_int32_t);
static void pf_ruleset_cleanup(struct pf_ruleset *, int);
static void pf_deleterule_anchor_step_out(struct pf_ruleset **,
    int, struct pf_rule **);

#define	PF_CDEV_MAJOR	(-1)

static struct cdevsw pf_cdevsw = {
	/* open */	pfopen,
	/* close */	pfclose,
	/* read */	eno_rdwrt,
	/* write */	eno_rdwrt,
	/* ioctl */	pfioctl,
	/* stop */	eno_stop,
	/* reset */	eno_reset,
	/* tty */	NULL,
	/* select */	eno_select,
	/* mmap */	eno_mmap,
	/* strategy */	eno_strat,
	/* getc */	eno_getc,
	/* putc */	eno_putc,
	/* type */	0
};

static void pf_attach_hooks(void);
#if 0
/* currently unused along with pfdetach() */
static void pf_detach_hooks(void);
#endif

/*
 * This is set during DIOCSTART/DIOCSTOP with pf_perim_lock held as writer,
 * and used in pf_af_hook() for performance optimization, such that packets
 * will enter pf_test() or pf_test6() only when PF is running.
 */
int pf_is_enabled = 0;

u_int32_t pf_hash_seed;
int16_t pf_nat64_configured = 0;

/*
 * These are the pf enabled reference counting variables
 */
static u_int64_t pf_enabled_ref_count;
static u_int32_t nr_tokens = 0;
static u_int64_t pffwrules;
static u_int32_t pfdevcnt;

SLIST_HEAD(list_head, pfioc_kernel_token);
static struct list_head token_list_head;

struct pf_rule		 pf_default_rule;

#define	TAGID_MAX	 50000
static TAILQ_HEAD(pf_tags, pf_tagname)	pf_tags =
    TAILQ_HEAD_INITIALIZER(pf_tags);

#if (PF_QNAME_SIZE != PF_TAG_NAME_SIZE)
#error PF_QNAME_SIZE must be equal to PF_TAG_NAME_SIZE
#endif
static u_int16_t	 tagname2tag(struct pf_tags *, char *);
static void		 tag2tagname(struct pf_tags *, u_int16_t, char *);
static void		 tag_unref(struct pf_tags *, u_int16_t);
static int		 pf_rtlabel_add(struct pf_addr_wrap *);
static void		 pf_rtlabel_remove(struct pf_addr_wrap *);
static void		 pf_rtlabel_copyout(struct pf_addr_wrap *);

#if INET
static int pf_inet_hook(struct ifnet *, struct mbuf **, int,
    struct ip_fw_args *);
#endif /* INET */
#if INET6
static int pf_inet6_hook(struct ifnet *, struct mbuf **, int,
    struct ip_fw_args *);
#endif /* INET6 */

#define	DPFPRINTF(n, x) if (pf_status.debug >= (n)) printf x

/*
 * Helper macros for ioctl structures which vary in size (32-bit vs. 64-bit)
 */
#define	PFIOCX_STRUCT_DECL(s)						\
struct {								\
	union {								\
		struct s##_32	_s##_32;				\
		struct s##_64	_s##_64;				\
	} _u;								\
} *s##_un = NULL							\

#define	PFIOCX_STRUCT_BEGIN(a, s, _action) {				\
	VERIFY(s##_un == NULL);						\
	s##_un = _MALLOC(sizeof (*s##_un), M_TEMP, M_WAITOK|M_ZERO);	\
	if (s##_un == NULL) {						\
		_action							\
	} else {							\
		if (p64)						\
			bcopy(a, &s##_un->_u._s##_64,			\
			    sizeof (struct s##_64));			\
		else							\
			bcopy(a, &s##_un->_u._s##_32,			\
			    sizeof (struct s##_32));			\
	}								\
}

#define	PFIOCX_STRUCT_END(s, a) {					\
	VERIFY(s##_un != NULL);						\
	if (p64)							\
		bcopy(&s##_un->_u._s##_64, a, sizeof (struct s##_64));	\
	else								\
		bcopy(&s##_un->_u._s##_32, a, sizeof (struct s##_32));	\
	_FREE(s##_un, M_TEMP);						\
	s##_un = NULL;							\
}

#define	PFIOCX_STRUCT_ADDR32(s)		(&s##_un->_u._s##_32)
#define	PFIOCX_STRUCT_ADDR64(s)		(&s##_un->_u._s##_64)

/*
 * Helper macros for regular ioctl structures.
 */
#define	PFIOC_STRUCT_BEGIN(a, v, _action) {				\
	VERIFY((v) == NULL);						\
	(v) = _MALLOC(sizeof (*(v)), M_TEMP, M_WAITOK|M_ZERO);		\
	if ((v) == NULL) {						\
		_action							\
	} else {							\
		bcopy(a, v, sizeof (*(v)));				\
	}								\
}

#define	PFIOC_STRUCT_END(v, a) {					\
	VERIFY((v) != NULL);						\
	bcopy(v, a, sizeof (*(v)));					\
	_FREE(v, M_TEMP);						\
	(v) = NULL;							\
}

#define	PFIOC_STRUCT_ADDR32(s)		(&s##_un->_u._s##_32)
#define	PFIOC_STRUCT_ADDR64(s)		(&s##_un->_u._s##_64)

static lck_attr_t *pf_perim_lock_attr;
static lck_grp_t *pf_perim_lock_grp;
static lck_grp_attr_t *pf_perim_lock_grp_attr;

static lck_attr_t *pf_lock_attr;
static lck_grp_t *pf_lock_grp;
static lck_grp_attr_t *pf_lock_grp_attr;

struct thread *pf_purge_thread;

extern void pfi_kifaddr_update(void *);

/* pf enable ref-counting helper functions */
static u_int64_t		generate_token(struct proc *);
static int			remove_token(struct pfioc_remove_token *);
static void			invalidate_all_tokens(void);

static u_int64_t
generate_token(struct proc *p)
{
	u_int64_t token_value;
	struct pfioc_kernel_token *new_token;

	new_token = _MALLOC(sizeof (struct pfioc_kernel_token), M_TEMP,
	    M_WAITOK|M_ZERO);

	LCK_MTX_ASSERT(pf_lock, LCK_MTX_ASSERT_OWNED);

	if (new_token == NULL) {
		/* malloc failed! bail! */
		printf("%s: unable to allocate pf token structure!", __func__);
		return (0);
	}

	token_value = VM_KERNEL_ADDRPERM((u_int64_t)(uintptr_t)new_token);

	new_token->token.token_value = token_value;
	new_token->token.pid = proc_pid(p);
	proc_name(new_token->token.pid, new_token->token.proc_name,
	    sizeof (new_token->token.proc_name));
	new_token->token.timestamp = pf_calendar_time_second();

	SLIST_INSERT_HEAD(&token_list_head, new_token, next);
	nr_tokens++;

	return (token_value);
}

static int
remove_token(struct pfioc_remove_token *tok)
{
	struct pfioc_kernel_token *entry, *tmp;

	LCK_MTX_ASSERT(pf_lock, LCK_MTX_ASSERT_OWNED);

	SLIST_FOREACH_SAFE(entry, &token_list_head, next, tmp) {
		if (tok->token_value == entry->token.token_value) {
			SLIST_REMOVE(&token_list_head, entry,
			    pfioc_kernel_token, next);
			_FREE(entry, M_TEMP);
			nr_tokens--;
			return (0);    /* success */
		}
	}

	printf("pf : remove failure\n");
	return (ESRCH);    /* failure */
}

static void
invalidate_all_tokens(void)
{
	struct pfioc_kernel_token *entry, *tmp;

	LCK_MTX_ASSERT(pf_lock, LCK_MTX_ASSERT_OWNED);

	SLIST_FOREACH_SAFE(entry, &token_list_head, next, tmp) {
		SLIST_REMOVE(&token_list_head, entry, pfioc_kernel_token, next);
		_FREE(entry, M_TEMP);
	}

	nr_tokens = 0;
}

void
pfinit(void)
{
	u_int32_t *t = pf_default_rule.timeout;
	int maj;

	pf_perim_lock_grp_attr = lck_grp_attr_alloc_init();
	pf_perim_lock_grp = lck_grp_alloc_init("pf_perim",
	    pf_perim_lock_grp_attr);
	pf_perim_lock_attr = lck_attr_alloc_init();
	lck_rw_init(pf_perim_lock, pf_perim_lock_grp, pf_perim_lock_attr);

	pf_lock_grp_attr = lck_grp_attr_alloc_init();
	pf_lock_grp = lck_grp_alloc_init("pf", pf_lock_grp_attr);
	pf_lock_attr = lck_attr_alloc_init();
	lck_mtx_init(pf_lock, pf_lock_grp, pf_lock_attr);

	pool_init(&pf_rule_pl, sizeof (struct pf_rule), 0, 0, 0, "pfrulepl",
	    NULL);
	pool_init(&pf_src_tree_pl, sizeof (struct pf_src_node), 0, 0, 0,
	    "pfsrctrpl", NULL);
	pool_init(&pf_state_pl, sizeof (struct pf_state), 0, 0, 0, "pfstatepl",
	    NULL);
	pool_init(&pf_state_key_pl, sizeof (struct pf_state_key), 0, 0, 0,
	    "pfstatekeypl", NULL);
	pool_init(&pf_app_state_pl, sizeof (struct pf_app_state), 0, 0, 0,
	    "pfappstatepl", NULL);
	pool_init(&pf_pooladdr_pl, sizeof (struct pf_pooladdr), 0, 0, 0,
	    "pfpooladdrpl", NULL);
	pfr_initialize();
	pfi_initialize();
	pf_osfp_initialize();

	pool_sethardlimit(pf_pool_limits[PF_LIMIT_STATES].pp,
	    pf_pool_limits[PF_LIMIT_STATES].limit, NULL, 0);

	if (max_mem <= 256*1024*1024)
		pf_pool_limits[PF_LIMIT_TABLE_ENTRIES].limit =
		    PFR_KENTRY_HIWAT_SMALL;

	RB_INIT(&tree_src_tracking);
	RB_INIT(&pf_anchors);
	pf_init_ruleset(&pf_main_ruleset);
	TAILQ_INIT(&pf_pabuf);
	TAILQ_INIT(&state_list);

	_CASSERT((SC_BE & SCIDX_MASK) == SCIDX_BE);
	_CASSERT((SC_BK_SYS & SCIDX_MASK) == SCIDX_BK_SYS);
	_CASSERT((SC_BK & SCIDX_MASK) == SCIDX_BK);
	_CASSERT((SC_RD & SCIDX_MASK) == SCIDX_RD);
	_CASSERT((SC_OAM & SCIDX_MASK) == SCIDX_OAM);
	_CASSERT((SC_AV & SCIDX_MASK) == SCIDX_AV);
	_CASSERT((SC_RV & SCIDX_MASK) == SCIDX_RV);
	_CASSERT((SC_VI & SCIDX_MASK) == SCIDX_VI);
	_CASSERT((SC_VO & SCIDX_MASK) == SCIDX_VO);
	_CASSERT((SC_CTL & SCIDX_MASK) == SCIDX_CTL);

	/* default rule should never be garbage collected */
	pf_default_rule.entries.tqe_prev = &pf_default_rule.entries.tqe_next;
	pf_default_rule.action = PF_PASS;
	pf_default_rule.nr = -1;
	pf_default_rule.rtableid = IFSCOPE_NONE;

	/* initialize default timeouts */
	t[PFTM_TCP_FIRST_PACKET] = PFTM_TCP_FIRST_PACKET_VAL;
	t[PFTM_TCP_OPENING] = PFTM_TCP_OPENING_VAL;
	t[PFTM_TCP_ESTABLISHED] = PFTM_TCP_ESTABLISHED_VAL;
	t[PFTM_TCP_CLOSING] = PFTM_TCP_CLOSING_VAL;
	t[PFTM_TCP_FIN_WAIT] = PFTM_TCP_FIN_WAIT_VAL;
	t[PFTM_TCP_CLOSED] = PFTM_TCP_CLOSED_VAL;
	t[PFTM_UDP_FIRST_PACKET] = PFTM_UDP_FIRST_PACKET_VAL;
	t[PFTM_UDP_SINGLE] = PFTM_UDP_SINGLE_VAL;
	t[PFTM_UDP_MULTIPLE] = PFTM_UDP_MULTIPLE_VAL;
	t[PFTM_ICMP_FIRST_PACKET] = PFTM_ICMP_FIRST_PACKET_VAL;
	t[PFTM_ICMP_ERROR_REPLY] = PFTM_ICMP_ERROR_REPLY_VAL;
	t[PFTM_GREv1_FIRST_PACKET] = PFTM_GREv1_FIRST_PACKET_VAL;
	t[PFTM_GREv1_INITIATING] = PFTM_GREv1_INITIATING_VAL;
	t[PFTM_GREv1_ESTABLISHED] = PFTM_GREv1_ESTABLISHED_VAL;
	t[PFTM_ESP_FIRST_PACKET] = PFTM_ESP_FIRST_PACKET_VAL;
	t[PFTM_ESP_INITIATING] = PFTM_ESP_INITIATING_VAL;
	t[PFTM_ESP_ESTABLISHED] = PFTM_ESP_ESTABLISHED_VAL;
	t[PFTM_OTHER_FIRST_PACKET] = PFTM_OTHER_FIRST_PACKET_VAL;
	t[PFTM_OTHER_SINGLE] = PFTM_OTHER_SINGLE_VAL;
	t[PFTM_OTHER_MULTIPLE] = PFTM_OTHER_MULTIPLE_VAL;
	t[PFTM_FRAG] = PFTM_FRAG_VAL;
	t[PFTM_INTERVAL] = PFTM_INTERVAL_VAL;
	t[PFTM_SRC_NODE] = PFTM_SRC_NODE_VAL;
	t[PFTM_TS_DIFF] = PFTM_TS_DIFF_VAL;
	t[PFTM_ADAPTIVE_START] = PFSTATE_ADAPT_START;
	t[PFTM_ADAPTIVE_END] = PFSTATE_ADAPT_END;

	pf_normalize_init();
	bzero(&pf_status, sizeof (pf_status));
	pf_status.debug = PF_DEBUG_URGENT;
	pf_hash_seed = RandomULong();

	/* XXX do our best to avoid a conflict */
	pf_status.hostid = random();

	if (kernel_thread_start(pf_purge_thread_fn, NULL,
	    &pf_purge_thread) != 0) {
		printf("%s: unable to start purge thread!", __func__);
		return;
	}

	maj = cdevsw_add(PF_CDEV_MAJOR, &pf_cdevsw);
	if (maj == -1) {
		printf("%s: failed to allocate major number!\n", __func__);
		return;
	}
	(void) devfs_make_node(makedev(maj, PFDEV_PF), DEVFS_CHAR,
	    UID_ROOT, GID_WHEEL, 0600, "pf", 0);

	(void) devfs_make_node(makedev(maj, PFDEV_PFM), DEVFS_CHAR,
	    UID_ROOT, GID_WHEEL, 0600, "pfm", 0);

	pf_attach_hooks();
#if DUMMYNET
	dummynet_init();
#endif
}

#if 0
static void
pfdetach(void)
{
	struct pf_anchor	*anchor;
	struct pf_state		*state;
	struct pf_src_node	*node;
	struct pfioc_table	pt;
	u_int32_t		ticket;
	int			i;
	char			r = '\0';

	pf_detach_hooks();

	pf_status.running = 0;
	wakeup(pf_purge_thread_fn);

	/* clear the rulesets */
	for (i = 0; i < PF_RULESET_MAX; i++)
		if (pf_begin_rules(&ticket, i, &r) == 0)
				pf_commit_rules(ticket, i, &r);

	/* clear states */
	RB_FOREACH(state, pf_state_tree_id, &tree_id) {
		state->timeout = PFTM_PURGE;
#if NPFSYNC
		state->sync_flags = PFSTATE_NOSYNC;
#endif
	}
	pf_purge_expired_states(pf_status.states);

#if NPFSYNC
	pfsync_clear_states(pf_status.hostid, NULL);
#endif

	/* clear source nodes */
	RB_FOREACH(state, pf_state_tree_id, &tree_id) {
		state->src_node = NULL;
		state->nat_src_node = NULL;
	}
	RB_FOREACH(node, pf_src_tree, &tree_src_tracking) {
		node->expire = 1;
		node->states = 0;
	}
	pf_purge_expired_src_nodes();

	/* clear tables */
	memset(&pt, '\0', sizeof (pt));
	pfr_clr_tables(&pt.pfrio_table, &pt.pfrio_ndel, pt.pfrio_flags);

	/* destroy anchors */
	while ((anchor = RB_MIN(pf_anchor_global, &pf_anchors)) != NULL) {
		for (i = 0; i < PF_RULESET_MAX; i++)
			if (pf_begin_rules(&ticket, i, anchor->name) == 0)
				pf_commit_rules(ticket, i, anchor->name);
	}

	/* destroy main ruleset */
	pf_remove_if_empty_ruleset(&pf_main_ruleset);

	/* destroy the pools */
	pool_destroy(&pf_pooladdr_pl);
	pool_destroy(&pf_state_pl);
	pool_destroy(&pf_rule_pl);
	pool_destroy(&pf_src_tree_pl);

	/* destroy subsystems */
	pf_normalize_destroy();
	pf_osfp_destroy();
	pfr_destroy();
	pfi_destroy();
}
#endif

static int
pfopen(dev_t dev, int flags, int fmt, struct proc *p)
{
#pragma unused(flags, fmt, p)
	if (minor(dev) >= PFDEV_MAX)
		return (ENXIO);

	if (minor(dev) == PFDEV_PFM) {
		lck_mtx_lock(pf_lock);
		if (pfdevcnt != 0) {
			lck_mtx_unlock(pf_lock);
			return (EBUSY);
		}
		pfdevcnt++;
		lck_mtx_unlock(pf_lock);
	}
	return (0);
}

static int
pfclose(dev_t dev, int flags, int fmt, struct proc *p)
{
#pragma unused(flags, fmt, p)
	if (minor(dev) >= PFDEV_MAX)
		return (ENXIO);

	if (minor(dev) == PFDEV_PFM) {
		lck_mtx_lock(pf_lock);
		VERIFY(pfdevcnt > 0);
		pfdevcnt--;
		lck_mtx_unlock(pf_lock);
	}
	return (0);
}

static struct pf_pool *
pf_get_pool(char *anchor, u_int32_t ticket, u_int8_t rule_action,
    u_int32_t rule_number, u_int8_t r_last, u_int8_t active,
    u_int8_t check_ticket)
{
	struct pf_ruleset	*ruleset;
	struct pf_rule		*rule;
	int			 rs_num;

	ruleset = pf_find_ruleset(anchor);
	if (ruleset == NULL)
		return (NULL);
	rs_num = pf_get_ruleset_number(rule_action);
	if (rs_num >= PF_RULESET_MAX)
		return (NULL);
	if (active) {
		if (check_ticket && ticket !=
		    ruleset->rules[rs_num].active.ticket)
			return (NULL);
		if (r_last)
			rule = TAILQ_LAST(ruleset->rules[rs_num].active.ptr,
			    pf_rulequeue);
		else
			rule = TAILQ_FIRST(ruleset->rules[rs_num].active.ptr);
	} else {
		if (check_ticket && ticket !=
		    ruleset->rules[rs_num].inactive.ticket)
			return (NULL);
		if (r_last)
			rule = TAILQ_LAST(ruleset->rules[rs_num].inactive.ptr,
			    pf_rulequeue);
		else
			rule = TAILQ_FIRST(ruleset->rules[rs_num].inactive.ptr);
	}
	if (!r_last) {
		while ((rule != NULL) && (rule->nr != rule_number))
			rule = TAILQ_NEXT(rule, entries);
	}
	if (rule == NULL)
		return (NULL);

	return (&rule->rpool);
}

static void
pf_mv_pool(struct pf_palist *poola, struct pf_palist *poolb)
{
	struct pf_pooladdr	*mv_pool_pa;

	while ((mv_pool_pa = TAILQ_FIRST(poola)) != NULL) {
		TAILQ_REMOVE(poola, mv_pool_pa, entries);
		TAILQ_INSERT_TAIL(poolb, mv_pool_pa, entries);
	}
}

static void
pf_empty_pool(struct pf_palist *poola)
{
	struct pf_pooladdr	*empty_pool_pa;

	while ((empty_pool_pa = TAILQ_FIRST(poola)) != NULL) {
		pfi_dynaddr_remove(&empty_pool_pa->addr);
		pf_tbladdr_remove(&empty_pool_pa->addr);
		pfi_kif_unref(empty_pool_pa->kif, PFI_KIF_REF_RULE);
		TAILQ_REMOVE(poola, empty_pool_pa, entries);
		pool_put(&pf_pooladdr_pl, empty_pool_pa);
	}
}

void
pf_rm_rule(struct pf_rulequeue *rulequeue, struct pf_rule *rule)
{
	if (rulequeue != NULL) {
		if (rule->states <= 0) {
			/*
			 * XXX - we need to remove the table *before* detaching
			 * the rule to make sure the table code does not delete
			 * the anchor under our feet.
			 */
			pf_tbladdr_remove(&rule->src.addr);
			pf_tbladdr_remove(&rule->dst.addr);
			if (rule->overload_tbl)
				pfr_detach_table(rule->overload_tbl);
		}
		TAILQ_REMOVE(rulequeue, rule, entries);
		rule->entries.tqe_prev = NULL;
		rule->nr = -1;
	}

	if (rule->states > 0 || rule->src_nodes > 0 ||
	    rule->entries.tqe_prev != NULL)
		return;
	pf_tag_unref(rule->tag);
	pf_tag_unref(rule->match_tag);
	pf_rtlabel_remove(&rule->src.addr);
	pf_rtlabel_remove(&rule->dst.addr);
	pfi_dynaddr_remove(&rule->src.addr);
	pfi_dynaddr_remove(&rule->dst.addr);
	if (rulequeue == NULL) {
		pf_tbladdr_remove(&rule->src.addr);
		pf_tbladdr_remove(&rule->dst.addr);
		if (rule->overload_tbl)
			pfr_detach_table(rule->overload_tbl);
	}
	pfi_kif_unref(rule->kif, PFI_KIF_REF_RULE);
	pf_anchor_remove(rule);
	pf_empty_pool(&rule->rpool.list);
	pool_put(&pf_rule_pl, rule);
}

static u_int16_t
tagname2tag(struct pf_tags *head, char *tagname)
{
	struct pf_tagname	*tag, *p = NULL;
	u_int16_t		 new_tagid = 1;

	TAILQ_FOREACH(tag, head, entries)
		if (strcmp(tagname, tag->name) == 0) {
			tag->ref++;
			return (tag->tag);
		}

	/*
	 * to avoid fragmentation, we do a linear search from the beginning
	 * and take the first free slot we find. if there is none or the list
	 * is empty, append a new entry at the end.
	 */

	/* new entry */
	if (!TAILQ_EMPTY(head))
		for (p = TAILQ_FIRST(head); p != NULL &&
		    p->tag == new_tagid; p = TAILQ_NEXT(p, entries))
			new_tagid = p->tag + 1;

	if (new_tagid > TAGID_MAX)
		return (0);

	/* allocate and fill new struct pf_tagname */
	tag = _MALLOC(sizeof (*tag), M_TEMP, M_WAITOK|M_ZERO);
	if (tag == NULL)
		return (0);
	strlcpy(tag->name, tagname, sizeof (tag->name));
	tag->tag = new_tagid;
	tag->ref++;

	if (p != NULL)	/* insert new entry before p */
		TAILQ_INSERT_BEFORE(p, tag, entries);
	else	/* either list empty or no free slot in between */
		TAILQ_INSERT_TAIL(head, tag, entries);

	return (tag->tag);
}

static void
tag2tagname(struct pf_tags *head, u_int16_t tagid, char *p)
{
	struct pf_tagname	*tag;

	TAILQ_FOREACH(tag, head, entries)
		if (tag->tag == tagid) {
			strlcpy(p, tag->name, PF_TAG_NAME_SIZE);
			return;
		}
}

static void
tag_unref(struct pf_tags *head, u_int16_t tag)
{
	struct pf_tagname	*p, *next;

	if (tag == 0)
		return;

	for (p = TAILQ_FIRST(head); p != NULL; p = next) {
		next = TAILQ_NEXT(p, entries);
		if (tag == p->tag) {
			if (--p->ref == 0) {
				TAILQ_REMOVE(head, p, entries);
				_FREE(p, M_TEMP);
			}
			break;
		}
	}
}

u_int16_t
pf_tagname2tag(char *tagname)
{
	return (tagname2tag(&pf_tags, tagname));
}

void
pf_tag2tagname(u_int16_t tagid, char *p)
{
	tag2tagname(&pf_tags, tagid, p);
}

void
pf_tag_ref(u_int16_t tag)
{
	struct pf_tagname *t;

	TAILQ_FOREACH(t, &pf_tags, entries)
		if (t->tag == tag)
			break;
	if (t != NULL)
		t->ref++;
}

void
pf_tag_unref(u_int16_t tag)
{
	tag_unref(&pf_tags, tag);
}

static int
pf_rtlabel_add(struct pf_addr_wrap *a)
{
#pragma unused(a)
	return (0);
}

static void
pf_rtlabel_remove(struct pf_addr_wrap *a)
{
#pragma unused(a)
}

static void
pf_rtlabel_copyout(struct pf_addr_wrap *a)
{
#pragma unused(a)
}

static int
pf_begin_rules(u_int32_t *ticket, int rs_num, const char *anchor)
{
	struct pf_ruleset	*rs;
	struct pf_rule		*rule;

	if (rs_num < 0 || rs_num >= PF_RULESET_MAX)
		return (EINVAL);
	rs = pf_find_or_create_ruleset(anchor);
	if (rs == NULL)
		return (EINVAL);
	while ((rule = TAILQ_FIRST(rs->rules[rs_num].inactive.ptr)) != NULL) {
		pf_rm_rule(rs->rules[rs_num].inactive.ptr, rule);
		rs->rules[rs_num].inactive.rcount--;
	}
	*ticket = ++rs->rules[rs_num].inactive.ticket;
	rs->rules[rs_num].inactive.open = 1;
	return (0);
}

static int
pf_rollback_rules(u_int32_t ticket, int rs_num, char *anchor)
{
	struct pf_ruleset	*rs;
	struct pf_rule		*rule;

	if (rs_num < 0 || rs_num >= PF_RULESET_MAX)
		return (EINVAL);
	rs = pf_find_ruleset(anchor);
	if (rs == NULL || !rs->rules[rs_num].inactive.open ||
	    rs->rules[rs_num].inactive.ticket != ticket)
		return (0);
	while ((rule = TAILQ_FIRST(rs->rules[rs_num].inactive.ptr)) != NULL) {
		pf_rm_rule(rs->rules[rs_num].inactive.ptr, rule);
		rs->rules[rs_num].inactive.rcount--;
	}
	rs->rules[rs_num].inactive.open = 0;
	return (0);
}

#define	PF_MD5_UPD(st, elm)						\
	MD5Update(ctx, (u_int8_t *)&(st)->elm, sizeof ((st)->elm))

#define	PF_MD5_UPD_STR(st, elm)						\
	MD5Update(ctx, (u_int8_t *)(st)->elm, strlen((st)->elm))

#define	PF_MD5_UPD_HTONL(st, elm, stor) do {				\
	(stor) = htonl((st)->elm);					\
	MD5Update(ctx, (u_int8_t *)&(stor), sizeof (u_int32_t));	\
} while (0)

#define	PF_MD5_UPD_HTONS(st, elm, stor) do {				\
	(stor) = htons((st)->elm);					\
	MD5Update(ctx, (u_int8_t *)&(stor), sizeof (u_int16_t));	\
} while (0)

static void
pf_hash_rule_addr(MD5_CTX *ctx, struct pf_rule_addr *pfr, u_int8_t proto)
{
	PF_MD5_UPD(pfr, addr.type);
	switch (pfr->addr.type) {
	case PF_ADDR_DYNIFTL:
		PF_MD5_UPD(pfr, addr.v.ifname);
		PF_MD5_UPD(pfr, addr.iflags);
		break;
	case PF_ADDR_TABLE:
		PF_MD5_UPD(pfr, addr.v.tblname);
		break;
	case PF_ADDR_ADDRMASK:
		/* XXX ignore af? */
		PF_MD5_UPD(pfr, addr.v.a.addr.addr32);
		PF_MD5_UPD(pfr, addr.v.a.mask.addr32);
		break;
	case PF_ADDR_RTLABEL:
		PF_MD5_UPD(pfr, addr.v.rtlabelname);
		break;
	}

	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		PF_MD5_UPD(pfr, xport.range.port[0]);
		PF_MD5_UPD(pfr, xport.range.port[1]);
		PF_MD5_UPD(pfr, xport.range.op);
		break;

	default:
		break;
	}

	PF_MD5_UPD(pfr, neg);
}

static void
pf_hash_rule(MD5_CTX *ctx, struct pf_rule *rule)
{
	u_int16_t x;
	u_int32_t y;

	pf_hash_rule_addr(ctx, &rule->src, rule->proto);
	pf_hash_rule_addr(ctx, &rule->dst, rule->proto);
	PF_MD5_UPD_STR(rule, label);
	PF_MD5_UPD_STR(rule, ifname);
	PF_MD5_UPD_STR(rule, match_tagname);
	PF_MD5_UPD_HTONS(rule, match_tag, x); /* dup? */
	PF_MD5_UPD_HTONL(rule, os_fingerprint, y);
	PF_MD5_UPD_HTONL(rule, prob, y);
	PF_MD5_UPD_HTONL(rule, uid.uid[0], y);
	PF_MD5_UPD_HTONL(rule, uid.uid[1], y);
	PF_MD5_UPD(rule, uid.op);
	PF_MD5_UPD_HTONL(rule, gid.gid[0], y);
	PF_MD5_UPD_HTONL(rule, gid.gid[1], y);
	PF_MD5_UPD(rule, gid.op);
	PF_MD5_UPD_HTONL(rule, rule_flag, y);
	PF_MD5_UPD(rule, action);
	PF_MD5_UPD(rule, direction);
	PF_MD5_UPD(rule, af);
	PF_MD5_UPD(rule, quick);
	PF_MD5_UPD(rule, ifnot);
	PF_MD5_UPD(rule, match_tag_not);
	PF_MD5_UPD(rule, natpass);
	PF_MD5_UPD(rule, keep_state);
	PF_MD5_UPD(rule, proto);
	PF_MD5_UPD(rule, type);
	PF_MD5_UPD(rule, code);
	PF_MD5_UPD(rule, flags);
	PF_MD5_UPD(rule, flagset);
	PF_MD5_UPD(rule, allow_opts);
	PF_MD5_UPD(rule, rt);
	PF_MD5_UPD(rule, tos);
}

static int
pf_commit_rules(u_int32_t ticket, int rs_num, char *anchor)
{
	struct pf_ruleset	*rs;
	struct pf_rule		*rule, **old_array, *r;
	struct pf_rulequeue	*old_rules;
	int			 error;
	u_int32_t		 old_rcount;

	LCK_MTX_ASSERT(pf_lock, LCK_MTX_ASSERT_OWNED);

	if (rs_num < 0 || rs_num >= PF_RULESET_MAX)
		return (EINVAL);
	rs = pf_find_ruleset(anchor);
	if (rs == NULL || !rs->rules[rs_num].inactive.open ||
	    ticket != rs->rules[rs_num].inactive.ticket)
		return (EBUSY);

	/* Calculate checksum for the main ruleset */
	if (rs == &pf_main_ruleset) {
		error = pf_setup_pfsync_matching(rs);
		if (error != 0)
			return (error);
	}

	/* Swap rules, keep the old. */
	old_rules = rs->rules[rs_num].active.ptr;
	old_rcount = rs->rules[rs_num].active.rcount;
	old_array = rs->rules[rs_num].active.ptr_array;

	if(old_rcount != 0) {
		r = TAILQ_FIRST(rs->rules[rs_num].active.ptr);
		while (r) {
			if (r->rule_flag & PFRULE_PFM)
				pffwrules--;
			r = TAILQ_NEXT(r, entries);
		}
	}


	rs->rules[rs_num].active.ptr =
	    rs->rules[rs_num].inactive.ptr;
	rs->rules[rs_num].active.ptr_array =
	    rs->rules[rs_num].inactive.ptr_array;
	rs->rules[rs_num].active.rcount =
	    rs->rules[rs_num].inactive.rcount;
	rs->rules[rs_num].inactive.ptr = old_rules;
	rs->rules[rs_num].inactive.ptr_array = old_array;
	rs->rules[rs_num].inactive.rcount = old_rcount;

	rs->rules[rs_num].active.ticket =
	    rs->rules[rs_num].inactive.ticket;
	pf_calc_skip_steps(rs->rules[rs_num].active.ptr);


	/* Purge the old rule list. */
	while ((rule = TAILQ_FIRST(old_rules)) != NULL)
		pf_rm_rule(old_rules, rule);
	if (rs->rules[rs_num].inactive.ptr_array)
		_FREE(rs->rules[rs_num].inactive.ptr_array, M_TEMP);
	rs->rules[rs_num].inactive.ptr_array = NULL;
	rs->rules[rs_num].inactive.rcount = 0;
	rs->rules[rs_num].inactive.open = 0;
	pf_remove_if_empty_ruleset(rs);
	return (0);
}

static void
pf_rule_copyin(struct pf_rule *src, struct pf_rule *dst, struct proc *p,
    int minordev)
{
	bcopy(src, dst, sizeof (struct pf_rule));

	dst->label[sizeof (dst->label) - 1] = '\0';
	dst->ifname[sizeof (dst->ifname) - 1] = '\0';
	dst->qname[sizeof (dst->qname) - 1] = '\0';
	dst->pqname[sizeof (dst->pqname) - 1] = '\0';
	dst->tagname[sizeof (dst->tagname) - 1] = '\0';
	dst->match_tagname[sizeof (dst->match_tagname) - 1] = '\0';
	dst->overload_tblname[sizeof (dst->overload_tblname) - 1] = '\0';

	dst->cuid = kauth_cred_getuid(p->p_ucred);
	dst->cpid = p->p_pid;

	dst->anchor = NULL;
	dst->kif = NULL;
	dst->overload_tbl = NULL;

	TAILQ_INIT(&dst->rpool.list);
	dst->rpool.cur = NULL;

	/* initialize refcounting */
	dst->states = 0;
	dst->src_nodes = 0;

	dst->entries.tqe_prev = NULL;
	dst->entries.tqe_next = NULL;
	if ((uint8_t)minordev == PFDEV_PFM)
		dst->rule_flag |= PFRULE_PFM;
}

static void
pf_rule_copyout(struct pf_rule *src, struct pf_rule *dst)
{
	bcopy(src, dst, sizeof (struct pf_rule));

	dst->anchor = NULL;
	dst->kif = NULL;
	dst->overload_tbl = NULL;

	TAILQ_INIT(&dst->rpool.list);
	dst->rpool.cur = NULL;

	dst->entries.tqe_prev = NULL;
	dst->entries.tqe_next = NULL;
}

static void
pf_state_export(struct pfsync_state *sp, struct pf_state_key *sk,
    struct pf_state *s)
{
	uint64_t secs = pf_time_second();
	bzero(sp, sizeof (struct pfsync_state));

	/* copy from state key */
	sp->lan.addr = sk->lan.addr;
	sp->lan.xport = sk->lan.xport;
	sp->gwy.addr = sk->gwy.addr;
	sp->gwy.xport = sk->gwy.xport;
	sp->ext_lan.addr = sk->ext_lan.addr;
	sp->ext_lan.xport = sk->ext_lan.xport;
	sp->ext_gwy.addr = sk->ext_gwy.addr;
	sp->ext_gwy.xport = sk->ext_gwy.xport;
	sp->proto_variant = sk->proto_variant;
	sp->tag = s->tag;
	sp->proto = sk->proto;
	sp->af_lan = sk->af_lan;
	sp->af_gwy = sk->af_gwy;
	sp->direction = sk->direction;
	sp->flowhash = sk->flowhash;

	/* copy from state */
	memcpy(&sp->id, &s->id, sizeof (sp->id));
	sp->creatorid = s->creatorid;
	strlcpy(sp->ifname, s->kif->pfik_name, sizeof (sp->ifname));
	pf_state_peer_to_pfsync(&s->src, &sp->src);
	pf_state_peer_to_pfsync(&s->dst, &sp->dst);

	sp->rule = s->rule.ptr->nr;
	sp->nat_rule = (s->nat_rule.ptr == NULL) ?
	    (unsigned)-1 : s->nat_rule.ptr->nr;
	sp->anchor = (s->anchor.ptr == NULL) ?
	    (unsigned)-1 : s->anchor.ptr->nr;

	pf_state_counter_to_pfsync(s->bytes[0], sp->bytes[0]);
	pf_state_counter_to_pfsync(s->bytes[1], sp->bytes[1]);
	pf_state_counter_to_pfsync(s->packets[0], sp->packets[0]);
	pf_state_counter_to_pfsync(s->packets[1], sp->packets[1]);
	sp->creation = secs - s->creation;
	sp->expire = pf_state_expires(s);
	sp->log = s->log;
	sp->allow_opts = s->allow_opts;
	sp->timeout = s->timeout;

	if (s->src_node)
		sp->sync_flags |= PFSYNC_FLAG_SRCNODE;
	if (s->nat_src_node)
		sp->sync_flags |= PFSYNC_FLAG_NATSRCNODE;

	if (sp->expire > secs)
		sp->expire -= secs;
	else
		sp->expire = 0;

}

static void
pf_state_import(struct pfsync_state *sp, struct pf_state_key *sk,
    struct pf_state *s)
{
	/* copy to state key */
	sk->lan.addr = sp->lan.addr;
	sk->lan.xport = sp->lan.xport;
	sk->gwy.addr = sp->gwy.addr;
	sk->gwy.xport = sp->gwy.xport;
	sk->ext_lan.addr = sp->ext_lan.addr;
	sk->ext_lan.xport = sp->ext_lan.xport;
	sk->ext_gwy.addr = sp->ext_gwy.addr;
	sk->ext_gwy.xport = sp->ext_gwy.xport;
	sk->proto_variant = sp->proto_variant;
	s->tag = sp->tag;
	sk->proto = sp->proto;
	sk->af_lan = sp->af_lan;
	sk->af_gwy = sp->af_gwy;
	sk->direction = sp->direction;
	sk->flowhash = pf_calc_state_key_flowhash(sk);

	/* copy to state */
	memcpy(&s->id, &sp->id, sizeof (sp->id));
	s->creatorid = sp->creatorid;
	pf_state_peer_from_pfsync(&sp->src, &s->src);
	pf_state_peer_from_pfsync(&sp->dst, &s->dst);

	s->rule.ptr = &pf_default_rule;
	s->nat_rule.ptr = NULL;
	s->anchor.ptr = NULL;
	s->rt_kif = NULL;
	s->creation = pf_time_second();
	s->expire = pf_time_second();
	if (sp->expire > 0)
		s->expire -= pf_default_rule.timeout[sp->timeout] - sp->expire;
	s->pfsync_time = 0;
	s->packets[0] = s->packets[1] = 0;
	s->bytes[0] = s->bytes[1] = 0;
}

static void
pf_pooladdr_copyin(struct pf_pooladdr *src, struct pf_pooladdr *dst)
{
	bcopy(src, dst, sizeof (struct pf_pooladdr));

	dst->entries.tqe_prev = NULL;
	dst->entries.tqe_next = NULL;
	dst->ifname[sizeof (dst->ifname) - 1] = '\0';
	dst->kif = NULL;
}

static void
pf_pooladdr_copyout(struct pf_pooladdr *src, struct pf_pooladdr *dst)
{
	bcopy(src, dst, sizeof (struct pf_pooladdr));

	dst->entries.tqe_prev = NULL;
	dst->entries.tqe_next = NULL;
	dst->kif = NULL;
}

static int
pf_setup_pfsync_matching(struct pf_ruleset *rs)
{
	MD5_CTX			 ctx;
	struct pf_rule		*rule;
	int			 rs_cnt;
	u_int8_t		 digest[PF_MD5_DIGEST_LENGTH];

	MD5Init(&ctx);
	for (rs_cnt = 0; rs_cnt < PF_RULESET_MAX; rs_cnt++) {
		/* XXX PF_RULESET_SCRUB as well? */
		if (rs_cnt == PF_RULESET_SCRUB)
			continue;

		if (rs->rules[rs_cnt].inactive.ptr_array)
			_FREE(rs->rules[rs_cnt].inactive.ptr_array, M_TEMP);
		rs->rules[rs_cnt].inactive.ptr_array = NULL;

		if (rs->rules[rs_cnt].inactive.rcount) {
			rs->rules[rs_cnt].inactive.ptr_array =
			    _MALLOC(sizeof (caddr_t) *
			    rs->rules[rs_cnt].inactive.rcount,
			    M_TEMP, M_WAITOK);

			if (!rs->rules[rs_cnt].inactive.ptr_array)
				return (ENOMEM);
		}

		TAILQ_FOREACH(rule, rs->rules[rs_cnt].inactive.ptr,
		    entries) {
			pf_hash_rule(&ctx, rule);
			(rs->rules[rs_cnt].inactive.ptr_array)[rule->nr] = rule;
		}
	}

	MD5Final(digest, &ctx);
	memcpy(pf_status.pf_chksum, digest, sizeof (pf_status.pf_chksum));
	return (0);
}

static void
pf_start(void)
{
	LCK_MTX_ASSERT(pf_lock, LCK_MTX_ASSERT_OWNED);

	VERIFY(pf_is_enabled == 0);

	pf_is_enabled = 1;
	pf_status.running = 1;
	pf_status.since = pf_calendar_time_second();
	if (pf_status.stateid == 0) {
		pf_status.stateid = pf_time_second();
		pf_status.stateid = pf_status.stateid << 32;
	}
	wakeup(pf_purge_thread_fn);
	DPFPRINTF(PF_DEBUG_MISC, ("pf: started\n"));
}

static void
pf_stop(void)
{
	LCK_MTX_ASSERT(pf_lock, LCK_MTX_ASSERT_OWNED);

	VERIFY(pf_is_enabled);

	pf_status.running = 0;
	pf_is_enabled = 0;
	pf_status.since = pf_calendar_time_second();
	wakeup(pf_purge_thread_fn);
	DPFPRINTF(PF_DEBUG_MISC, ("pf: stopped\n"));
}

static int
pfioctl(dev_t dev, u_long cmd, caddr_t addr, int flags, struct proc *p)
{
#pragma unused(dev)
	int p64 = proc_is64bit(p);
	int error = 0;
	int minordev = minor(dev);

	if (kauth_cred_issuser(kauth_cred_get()) == 0)
		return (EPERM);

	/* XXX keep in sync with switch() below */
	if (securelevel > 1)
		switch (cmd) {
		case DIOCGETRULES:
		case DIOCGETRULE:
		case DIOCGETADDRS:
		case DIOCGETADDR:
		case DIOCGETSTATE:
		case DIOCSETSTATUSIF:
		case DIOCGETSTATUS:
		case DIOCCLRSTATUS:
		case DIOCNATLOOK:
		case DIOCSETDEBUG:
		case DIOCGETSTATES:
		case DIOCINSERTRULE:
		case DIOCDELETERULE:
		case DIOCGETTIMEOUT:
		case DIOCCLRRULECTRS:
		case DIOCGETLIMIT:
		case DIOCGETALTQS:
		case DIOCGETALTQ:
		case DIOCGETQSTATS:
		case DIOCGETRULESETS:
		case DIOCGETRULESET:
		case DIOCRGETTABLES:
		case DIOCRGETTSTATS:
		case DIOCRCLRTSTATS:
		case DIOCRCLRADDRS:
		case DIOCRADDADDRS:
		case DIOCRDELADDRS:
		case DIOCRSETADDRS:
		case DIOCRGETADDRS:
		case DIOCRGETASTATS:
		case DIOCRCLRASTATS:
		case DIOCRTSTADDRS:
		case DIOCOSFPGET:
		case DIOCGETSRCNODES:
		case DIOCCLRSRCNODES:
		case DIOCIGETIFACES:
		case DIOCGIFSPEED:
		case DIOCSETIFFLAG:
		case DIOCCLRIFFLAG:
			break;
		case DIOCRCLRTABLES:
		case DIOCRADDTABLES:
		case DIOCRDELTABLES:
		case DIOCRSETTFLAGS: {
			int pfrio_flags;

			bcopy(&((struct pfioc_table *)(void *)addr)->
			    pfrio_flags, &pfrio_flags, sizeof (pfrio_flags));

			if (pfrio_flags & PFR_FLAG_DUMMY)
				break; /* dummy operation ok */
			return (EPERM);
		}
		default:
			return (EPERM);
		}

	if (!(flags & FWRITE))
		switch (cmd) {
		case DIOCSTART:
		case DIOCSTARTREF:
		case DIOCSTOP:
		case DIOCSTOPREF:
		case DIOCGETSTARTERS:
		case DIOCGETRULES:
		case DIOCGETADDRS:
		case DIOCGETADDR:
		case DIOCGETSTATE:
		case DIOCGETSTATUS:
		case DIOCGETSTATES:
		case DIOCINSERTRULE:
		case DIOCDELETERULE:
		case DIOCGETTIMEOUT:
		case DIOCGETLIMIT:
		case DIOCGETALTQS:
		case DIOCGETALTQ:
		case DIOCGETQSTATS:
		case DIOCGETRULESETS:
		case DIOCGETRULESET:
		case DIOCNATLOOK:
		case DIOCRGETTABLES:
		case DIOCRGETTSTATS:
		case DIOCRGETADDRS:
		case DIOCRGETASTATS:
		case DIOCRTSTADDRS:
		case DIOCOSFPGET:
		case DIOCGETSRCNODES:
		case DIOCIGETIFACES:
		case DIOCGIFSPEED:
			break;
		case DIOCRCLRTABLES:
		case DIOCRADDTABLES:
		case DIOCRDELTABLES:
		case DIOCRCLRTSTATS:
		case DIOCRCLRADDRS:
		case DIOCRADDADDRS:
		case DIOCRDELADDRS:
		case DIOCRSETADDRS:
		case DIOCRSETTFLAGS: {
			int pfrio_flags;

			bcopy(&((struct pfioc_table *)(void *)addr)->
			    pfrio_flags, &pfrio_flags, sizeof (pfrio_flags));

			if (pfrio_flags & PFR_FLAG_DUMMY) {
				flags |= FWRITE; /* need write lock for dummy */
				break; /* dummy operation ok */
			}
			return (EACCES);
		}
		case DIOCGETRULE: {
			u_int32_t action;

			bcopy(&((struct pfioc_rule *)(void *)addr)->action,
			    &action, sizeof (action));

			if (action == PF_GET_CLR_CNTR)
				return (EACCES);
			break;
		}
		default:
			return (EACCES);
		}

	if (flags & FWRITE)
		lck_rw_lock_exclusive(pf_perim_lock);
	else
		lck_rw_lock_shared(pf_perim_lock);

	lck_mtx_lock(pf_lock);

	switch (cmd) {

	case DIOCSTART:
		if (pf_status.running) {
			/*
			 * Increment the reference for a simple -e enable, so
			 * that even if other processes drop their references,
			 * pf will still be available to processes that turned
			 * it on without taking a reference
			 */
			if (nr_tokens == pf_enabled_ref_count) {
				pf_enabled_ref_count++;
				VERIFY(pf_enabled_ref_count != 0);
			}
			error = EEXIST;
		} else if (pf_purge_thread == NULL) {
			error = ENOMEM;
		} else {
			pf_start();
			pf_enabled_ref_count++;
			VERIFY(pf_enabled_ref_count != 0);
		}
		break;

	case DIOCSTARTREF:		/* u_int64_t */
		if (pf_purge_thread == NULL) {
			error = ENOMEM;
		} else {
			u_int64_t token;

			/* small enough to be on stack */
			if ((token = generate_token(p)) != 0) {
				if (pf_is_enabled == 0) {
					pf_start();
				}
				pf_enabled_ref_count++;
				VERIFY(pf_enabled_ref_count != 0);
			} else {
				error = ENOMEM;
				DPFPRINTF(PF_DEBUG_URGENT,
				    ("pf: unable to generate token\n"));
			}
			bcopy(&token, addr, sizeof (token));
		}
		break;

	case DIOCSTOP:
		if (!pf_status.running) {
			error = ENOENT;
		} else {
			pf_stop();
			pf_enabled_ref_count = 0;
			invalidate_all_tokens();
		}
		break;

	case DIOCSTOPREF:		/* struct pfioc_remove_token */
		if (!pf_status.running) {
			error = ENOENT;
		} else {
			struct pfioc_remove_token pfrt;

			/* small enough to be on stack */
			bcopy(addr, &pfrt, sizeof (pfrt));
			if ((error = remove_token(&pfrt)) == 0) {
				VERIFY(pf_enabled_ref_count != 0);
				pf_enabled_ref_count--;
				/* return currently held references */
				pfrt.refcount = pf_enabled_ref_count;
				DPFPRINTF(PF_DEBUG_MISC,
				    ("pf: enabled refcount decremented\n"));
			} else {
				error = EINVAL;
				DPFPRINTF(PF_DEBUG_URGENT,
				    ("pf: token mismatch\n"));
			}
			bcopy(&pfrt, addr, sizeof (pfrt));

			if (error == 0 && pf_enabled_ref_count == 0)
				pf_stop();
		}
		break;

	case DIOCGETSTARTERS: {		/* struct pfioc_tokens */
		PFIOCX_STRUCT_DECL(pfioc_tokens);

		PFIOCX_STRUCT_BEGIN(addr, pfioc_tokens, error = ENOMEM; break;);
		error = pfioctl_ioc_tokens(cmd,
		    PFIOCX_STRUCT_ADDR32(pfioc_tokens),
		    PFIOCX_STRUCT_ADDR64(pfioc_tokens), p);
		PFIOCX_STRUCT_END(pfioc_tokens, addr);
		break;
	}

	case DIOCADDRULE:		/* struct pfioc_rule */
	case DIOCGETRULES:		/* struct pfioc_rule */
	case DIOCGETRULE:		/* struct pfioc_rule */
	case DIOCCHANGERULE:		/* struct pfioc_rule */
	case DIOCINSERTRULE:		/* struct pfioc_rule */
	case DIOCDELETERULE: {		/* struct pfioc_rule */
		struct pfioc_rule *pr = NULL;

		PFIOC_STRUCT_BEGIN(addr, pr, error = ENOMEM; break;);
		error = pfioctl_ioc_rule(cmd, minordev, pr, p);
		PFIOC_STRUCT_END(pr, addr);
		break;
	}

	case DIOCCLRSTATES:		/* struct pfioc_state_kill */
	case DIOCKILLSTATES: {		/* struct pfioc_state_kill */
		struct pfioc_state_kill *psk = NULL;

		PFIOC_STRUCT_BEGIN(addr, psk, error = ENOMEM; break;);
		error = pfioctl_ioc_state_kill(cmd, psk, p);
		PFIOC_STRUCT_END(psk, addr);
		break;
	}

	case DIOCADDSTATE:		/* struct pfioc_state */
	case DIOCGETSTATE: {		/* struct pfioc_state */
		struct pfioc_state *ps = NULL;

		PFIOC_STRUCT_BEGIN(addr, ps, error = ENOMEM; break;);
		error = pfioctl_ioc_state(cmd, ps, p);
		PFIOC_STRUCT_END(ps, addr);
		break;
	}

	case DIOCGETSTATES: {		/* struct pfioc_states */
		PFIOCX_STRUCT_DECL(pfioc_states);

		PFIOCX_STRUCT_BEGIN(addr, pfioc_states, error = ENOMEM; break;);
		error = pfioctl_ioc_states(cmd,
		    PFIOCX_STRUCT_ADDR32(pfioc_states),
		    PFIOCX_STRUCT_ADDR64(pfioc_states), p);
		PFIOCX_STRUCT_END(pfioc_states, addr);
		break;
	}

	case DIOCGETSTATUS: {		/* struct pf_status */
		struct pf_status *s = NULL;

		PFIOC_STRUCT_BEGIN(&pf_status, s, error = ENOMEM; break;);
		pfi_update_status(s->ifname, s);
		PFIOC_STRUCT_END(s, addr);
		break;
	}

	case DIOCSETSTATUSIF: {		/* struct pfioc_if */
		struct pfioc_if	*pi = (struct pfioc_if *)(void *)addr;

		/* OK for unaligned accesses */
		if (pi->ifname[0] == 0) {
			bzero(pf_status.ifname, IFNAMSIZ);
			break;
		}
		strlcpy(pf_status.ifname, pi->ifname, IFNAMSIZ);
		break;
	}

	case DIOCCLRSTATUS: {
		bzero(pf_status.counters, sizeof (pf_status.counters));
		bzero(pf_status.fcounters, sizeof (pf_status.fcounters));
		bzero(pf_status.scounters, sizeof (pf_status.scounters));
		pf_status.since = pf_calendar_time_second();
		if (*pf_status.ifname)
			pfi_update_status(pf_status.ifname, NULL);
		break;
	}

	case DIOCNATLOOK: {		/* struct pfioc_natlook */
		struct pfioc_natlook *pnl = NULL;

		PFIOC_STRUCT_BEGIN(addr, pnl, error = ENOMEM; break;);
		error = pfioctl_ioc_natlook(cmd, pnl, p);
		PFIOC_STRUCT_END(pnl, addr);
		break;
	}

	case DIOCSETTIMEOUT:		/* struct pfioc_tm */
	case DIOCGETTIMEOUT: {		/* struct pfioc_tm */
		struct pfioc_tm	pt;

		/* small enough to be on stack */
		bcopy(addr, &pt, sizeof (pt));
		error = pfioctl_ioc_tm(cmd, &pt, p);
		bcopy(&pt, addr, sizeof (pt));
		break;
	}

	case DIOCGETLIMIT:		/* struct pfioc_limit */
	case DIOCSETLIMIT: {		/* struct pfioc_limit */
		struct pfioc_limit pl;

		/* small enough to be on stack */
		bcopy(addr, &pl, sizeof (pl));
		error = pfioctl_ioc_limit(cmd, &pl, p);
		bcopy(&pl, addr, sizeof (pl));
		break;
	}

	case DIOCSETDEBUG: {		/* u_int32_t */
		bcopy(addr, &pf_status.debug, sizeof (u_int32_t));
		break;
	}

	case DIOCCLRRULECTRS: {
		/* obsoleted by DIOCGETRULE with action=PF_GET_CLR_CNTR */
		struct pf_ruleset	*ruleset = &pf_main_ruleset;
		struct pf_rule		*rule;

		TAILQ_FOREACH(rule,
		    ruleset->rules[PF_RULESET_FILTER].active.ptr, entries) {
			rule->evaluations = 0;
			rule->packets[0] = rule->packets[1] = 0;
			rule->bytes[0] = rule->bytes[1] = 0;
		}
		break;
	}

	case DIOCGIFSPEED: {
		struct pf_ifspeed *psp = (struct pf_ifspeed *)(void *)addr;
		struct pf_ifspeed ps;
		struct ifnet *ifp;
		u_int64_t baudrate;

		if (psp->ifname[0] != '\0') {
			/* Can we completely trust user-land? */
			strlcpy(ps.ifname, psp->ifname, IFNAMSIZ);
			ps.ifname[IFNAMSIZ - 1] = '\0';
			ifp = ifunit(ps.ifname);
			if (ifp != NULL) {
				baudrate = ifp->if_output_bw.max_bw;
				bcopy(&baudrate, &psp->baudrate,
				    sizeof (baudrate));
			} else {
				error = EINVAL;
			}
		} else {
			error = EINVAL;
		}
		break;
	}

	case DIOCBEGINADDRS:		/* struct pfioc_pooladdr */
	case DIOCADDADDR:		/* struct pfioc_pooladdr */
	case DIOCGETADDRS:		/* struct pfioc_pooladdr */
	case DIOCGETADDR:		/* struct pfioc_pooladdr */
	case DIOCCHANGEADDR: {		/* struct pfioc_pooladdr */
		struct pfioc_pooladdr *pp = NULL;

		PFIOC_STRUCT_BEGIN(addr, pp, error = ENOMEM; break;)
		error = pfioctl_ioc_pooladdr(cmd, pp, p);
		PFIOC_STRUCT_END(pp, addr);
		break;
	}

	case DIOCGETRULESETS:		/* struct pfioc_ruleset */
	case DIOCGETRULESET: {		/* struct pfioc_ruleset */
		struct pfioc_ruleset *pr = NULL;

		PFIOC_STRUCT_BEGIN(addr, pr, error = ENOMEM; break;);
		error = pfioctl_ioc_ruleset(cmd, pr, p);
		PFIOC_STRUCT_END(pr, addr);
		break;
	}

	case DIOCRCLRTABLES:		/* struct pfioc_table */
	case DIOCRADDTABLES:		/* struct pfioc_table */
	case DIOCRDELTABLES:		/* struct pfioc_table */
	case DIOCRGETTABLES:		/* struct pfioc_table */
	case DIOCRGETTSTATS:		/* struct pfioc_table */
	case DIOCRCLRTSTATS:		/* struct pfioc_table */
	case DIOCRSETTFLAGS:		/* struct pfioc_table */
	case DIOCRCLRADDRS:		/* struct pfioc_table */
	case DIOCRADDADDRS:		/* struct pfioc_table */
	case DIOCRDELADDRS:		/* struct pfioc_table */
	case DIOCRSETADDRS:		/* struct pfioc_table */
	case DIOCRGETADDRS:		/* struct pfioc_table */
	case DIOCRGETASTATS:		/* struct pfioc_table */
	case DIOCRCLRASTATS:		/* struct pfioc_table */
	case DIOCRTSTADDRS:		/* struct pfioc_table */
	case DIOCRINADEFINE: {		/* struct pfioc_table */
		PFIOCX_STRUCT_DECL(pfioc_table);

		PFIOCX_STRUCT_BEGIN(addr, pfioc_table, error = ENOMEM; break;);
		error = pfioctl_ioc_table(cmd,
		    PFIOCX_STRUCT_ADDR32(pfioc_table),
		    PFIOCX_STRUCT_ADDR64(pfioc_table), p);
		PFIOCX_STRUCT_END(pfioc_table, addr);
		break;
	}

	case DIOCOSFPADD:		/* struct pf_osfp_ioctl */
	case DIOCOSFPGET: {		/* struct pf_osfp_ioctl */
		struct pf_osfp_ioctl *io = NULL;

		PFIOC_STRUCT_BEGIN(addr, io, error = ENOMEM; break;);
		if (cmd == DIOCOSFPADD) {
			error = pf_osfp_add(io);
		} else {
			VERIFY(cmd == DIOCOSFPGET);
			error = pf_osfp_get(io);
		}
		PFIOC_STRUCT_END(io, addr);
		break;
	}

	case DIOCXBEGIN:		/* struct pfioc_trans */
	case DIOCXROLLBACK:		/* struct pfioc_trans */
	case DIOCXCOMMIT: {		/* struct pfioc_trans */
		PFIOCX_STRUCT_DECL(pfioc_trans);

		PFIOCX_STRUCT_BEGIN(addr, pfioc_trans, error = ENOMEM; break;);
		error = pfioctl_ioc_trans(cmd,
		    PFIOCX_STRUCT_ADDR32(pfioc_trans),
		    PFIOCX_STRUCT_ADDR64(pfioc_trans), p);
		PFIOCX_STRUCT_END(pfioc_trans, addr);
		break;
	}

	case DIOCGETSRCNODES: {		/* struct pfioc_src_nodes */
		PFIOCX_STRUCT_DECL(pfioc_src_nodes);

		PFIOCX_STRUCT_BEGIN(addr, pfioc_src_nodes,
		    error = ENOMEM; break;);
		error = pfioctl_ioc_src_nodes(cmd,
		    PFIOCX_STRUCT_ADDR32(pfioc_src_nodes),
		    PFIOCX_STRUCT_ADDR64(pfioc_src_nodes), p);
		PFIOCX_STRUCT_END(pfioc_src_nodes, addr);
		break;
	}

	case DIOCCLRSRCNODES: {
		struct pf_src_node	*n;
		struct pf_state		*state;

		RB_FOREACH(state, pf_state_tree_id, &tree_id) {
			state->src_node = NULL;
			state->nat_src_node = NULL;
		}
		RB_FOREACH(n, pf_src_tree, &tree_src_tracking) {
			n->expire = 1;
			n->states = 0;
		}
		pf_purge_expired_src_nodes();
		pf_status.src_nodes = 0;
		break;
	}

	case DIOCKILLSRCNODES: {	/* struct pfioc_src_node_kill */
		struct pfioc_src_node_kill *psnk = NULL;

		PFIOC_STRUCT_BEGIN(addr, psnk, error = ENOMEM; break;);
		error = pfioctl_ioc_src_node_kill(cmd, psnk, p);
		PFIOC_STRUCT_END(psnk, addr);
		break;
	}

	case DIOCSETHOSTID: {		/* u_int32_t */
		u_int32_t hid;

		/* small enough to be on stack */
		bcopy(addr, &hid, sizeof (hid));
		if (hid == 0)
			pf_status.hostid = random();
		else
			pf_status.hostid = hid;
		break;
	}

	case DIOCOSFPFLUSH:
		pf_osfp_flush();
		break;

	case DIOCIGETIFACES:		/* struct pfioc_iface */
	case DIOCSETIFFLAG:		/* struct pfioc_iface */
	case DIOCCLRIFFLAG: {		/* struct pfioc_iface */
		PFIOCX_STRUCT_DECL(pfioc_iface);

		PFIOCX_STRUCT_BEGIN(addr, pfioc_iface, error = ENOMEM; break;);
		error = pfioctl_ioc_iface(cmd,
		    PFIOCX_STRUCT_ADDR32(pfioc_iface),
		    PFIOCX_STRUCT_ADDR64(pfioc_iface), p);
		PFIOCX_STRUCT_END(pfioc_iface, addr);
		break;
	}

	default:
		error = ENODEV;
		break;
	}

	lck_mtx_unlock(pf_lock);
	lck_rw_done(pf_perim_lock);

	return (error);
}

static int
pfioctl_ioc_table(u_long cmd, struct pfioc_table_32 *io32,
    struct pfioc_table_64 *io64, struct proc *p)
{
	int p64 = proc_is64bit(p);
	int error = 0;

	if (!p64)
		goto struct32;

	/*
	 * 64-bit structure processing
	 */
	switch (cmd) {
	case DIOCRCLRTABLES:
		if (io64->pfrio_esize != 0) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io64->pfrio_table);
		error = pfr_clr_tables(&io64->pfrio_table, &io64->pfrio_ndel,
		    io64->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;

	case DIOCRADDTABLES:
		if (io64->pfrio_esize != sizeof (struct pfr_table)) {
			error = ENODEV;
			break;
		}
		error = pfr_add_tables(io64->pfrio_buffer, io64->pfrio_size,
		    &io64->pfrio_nadd, io64->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;

	case DIOCRDELTABLES:
		if (io64->pfrio_esize != sizeof (struct pfr_table)) {
			error = ENODEV;
			break;
		}
		error = pfr_del_tables(io64->pfrio_buffer, io64->pfrio_size,
		    &io64->pfrio_ndel, io64->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;

	case DIOCRGETTABLES:
		if (io64->pfrio_esize != sizeof (struct pfr_table)) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io64->pfrio_table);
		error = pfr_get_tables(&io64->pfrio_table, io64->pfrio_buffer,
		    &io64->pfrio_size, io64->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;

	case DIOCRGETTSTATS:
		if (io64->pfrio_esize != sizeof (struct pfr_tstats)) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io64->pfrio_table);
		error = pfr_get_tstats(&io64->pfrio_table, io64->pfrio_buffer,
		    &io64->pfrio_size, io64->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;

	case DIOCRCLRTSTATS:
		if (io64->pfrio_esize != sizeof (struct pfr_table)) {
			error = ENODEV;
			break;
		}
		error = pfr_clr_tstats(io64->pfrio_buffer, io64->pfrio_size,
		    &io64->pfrio_nzero, io64->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;

	case DIOCRSETTFLAGS:
		if (io64->pfrio_esize != sizeof (struct pfr_table)) {
			error = ENODEV;
			break;
		}
		error = pfr_set_tflags(io64->pfrio_buffer, io64->pfrio_size,
		    io64->pfrio_setflag, io64->pfrio_clrflag,
		    &io64->pfrio_nchange, &io64->pfrio_ndel,
		    io64->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;

	case DIOCRCLRADDRS:
		if (io64->pfrio_esize != 0) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io64->pfrio_table);
		error = pfr_clr_addrs(&io64->pfrio_table, &io64->pfrio_ndel,
		    io64->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;

	case DIOCRADDADDRS:
		if (io64->pfrio_esize != sizeof (struct pfr_addr)) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io64->pfrio_table);
		error = pfr_add_addrs(&io64->pfrio_table, io64->pfrio_buffer,
		    io64->pfrio_size, &io64->pfrio_nadd, io64->pfrio_flags |
		    PFR_FLAG_USERIOCTL);
		break;

	case DIOCRDELADDRS:
		if (io64->pfrio_esize != sizeof (struct pfr_addr)) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io64->pfrio_table);
		error = pfr_del_addrs(&io64->pfrio_table, io64->pfrio_buffer,
		    io64->pfrio_size, &io64->pfrio_ndel, io64->pfrio_flags |
		    PFR_FLAG_USERIOCTL);
		break;

	case DIOCRSETADDRS:
		if (io64->pfrio_esize != sizeof (struct pfr_addr)) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io64->pfrio_table);
		error = pfr_set_addrs(&io64->pfrio_table, io64->pfrio_buffer,
		    io64->pfrio_size, &io64->pfrio_size2, &io64->pfrio_nadd,
		    &io64->pfrio_ndel, &io64->pfrio_nchange, io64->pfrio_flags |
		    PFR_FLAG_USERIOCTL, 0);
		break;

	case DIOCRGETADDRS:
		if (io64->pfrio_esize != sizeof (struct pfr_addr)) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io64->pfrio_table);
		error = pfr_get_addrs(&io64->pfrio_table, io64->pfrio_buffer,
		    &io64->pfrio_size, io64->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;

	case DIOCRGETASTATS:
		if (io64->pfrio_esize != sizeof (struct pfr_astats)) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io64->pfrio_table);
		error = pfr_get_astats(&io64->pfrio_table, io64->pfrio_buffer,
		    &io64->pfrio_size, io64->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;

	case DIOCRCLRASTATS:
		if (io64->pfrio_esize != sizeof (struct pfr_addr)) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io64->pfrio_table);
		error = pfr_clr_astats(&io64->pfrio_table, io64->pfrio_buffer,
		    io64->pfrio_size, &io64->pfrio_nzero, io64->pfrio_flags |
		    PFR_FLAG_USERIOCTL);
		break;

	case DIOCRTSTADDRS:
		if (io64->pfrio_esize != sizeof (struct pfr_addr)) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io64->pfrio_table);
		error = pfr_tst_addrs(&io64->pfrio_table, io64->pfrio_buffer,
		    io64->pfrio_size, &io64->pfrio_nmatch, io64->pfrio_flags |
		    PFR_FLAG_USERIOCTL);
		break;

	case DIOCRINADEFINE:
		if (io64->pfrio_esize != sizeof (struct pfr_addr)) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io64->pfrio_table);
		error = pfr_ina_define(&io64->pfrio_table, io64->pfrio_buffer,
		    io64->pfrio_size, &io64->pfrio_nadd, &io64->pfrio_naddr,
		    io64->pfrio_ticket, io64->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
	}
	goto done;

struct32:
	/*
	 * 32-bit structure processing
	 */
	switch (cmd) {
	case DIOCRCLRTABLES:
		if (io32->pfrio_esize != 0) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io32->pfrio_table);
		error = pfr_clr_tables(&io32->pfrio_table, &io32->pfrio_ndel,
		    io32->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;

	case DIOCRADDTABLES:
		if (io32->pfrio_esize != sizeof (struct pfr_table)) {
			error = ENODEV;
			break;
		}
		error = pfr_add_tables(io32->pfrio_buffer, io32->pfrio_size,
		    &io32->pfrio_nadd, io32->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;

	case DIOCRDELTABLES:
		if (io32->pfrio_esize != sizeof (struct pfr_table)) {
			error = ENODEV;
			break;
		}
		error = pfr_del_tables(io32->pfrio_buffer, io32->pfrio_size,
		    &io32->pfrio_ndel, io32->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;

	case DIOCRGETTABLES:
		if (io32->pfrio_esize != sizeof (struct pfr_table)) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io32->pfrio_table);
		error = pfr_get_tables(&io32->pfrio_table, io32->pfrio_buffer,
		    &io32->pfrio_size, io32->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;

	case DIOCRGETTSTATS:
		if (io32->pfrio_esize != sizeof (struct pfr_tstats)) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io32->pfrio_table);
		error = pfr_get_tstats(&io32->pfrio_table, io32->pfrio_buffer,
		    &io32->pfrio_size, io32->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;

	case DIOCRCLRTSTATS:
		if (io32->pfrio_esize != sizeof (struct pfr_table)) {
			error = ENODEV;
			break;
		}
		error = pfr_clr_tstats(io32->pfrio_buffer, io32->pfrio_size,
		    &io32->pfrio_nzero, io32->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;

	case DIOCRSETTFLAGS:
		if (io32->pfrio_esize != sizeof (struct pfr_table)) {
			error = ENODEV;
			break;
		}
		error = pfr_set_tflags(io32->pfrio_buffer, io32->pfrio_size,
		    io32->pfrio_setflag, io32->pfrio_clrflag,
		    &io32->pfrio_nchange, &io32->pfrio_ndel,
		    io32->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;

	case DIOCRCLRADDRS:
		if (io32->pfrio_esize != 0) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io32->pfrio_table);
		error = pfr_clr_addrs(&io32->pfrio_table, &io32->pfrio_ndel,
		    io32->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;

	case DIOCRADDADDRS:
		if (io32->pfrio_esize != sizeof (struct pfr_addr)) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io32->pfrio_table);
		error = pfr_add_addrs(&io32->pfrio_table, io32->pfrio_buffer,
		    io32->pfrio_size, &io32->pfrio_nadd, io32->pfrio_flags |
		    PFR_FLAG_USERIOCTL);
		break;

	case DIOCRDELADDRS:
		if (io32->pfrio_esize != sizeof (struct pfr_addr)) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io32->pfrio_table);
		error = pfr_del_addrs(&io32->pfrio_table, io32->pfrio_buffer,
		    io32->pfrio_size, &io32->pfrio_ndel, io32->pfrio_flags |
		    PFR_FLAG_USERIOCTL);
		break;

	case DIOCRSETADDRS:
		if (io32->pfrio_esize != sizeof (struct pfr_addr)) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io32->pfrio_table);
		error = pfr_set_addrs(&io32->pfrio_table, io32->pfrio_buffer,
		    io32->pfrio_size, &io32->pfrio_size2, &io32->pfrio_nadd,
		    &io32->pfrio_ndel, &io32->pfrio_nchange, io32->pfrio_flags |
		    PFR_FLAG_USERIOCTL, 0);
		break;

	case DIOCRGETADDRS:
		if (io32->pfrio_esize != sizeof (struct pfr_addr)) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io32->pfrio_table);
		error = pfr_get_addrs(&io32->pfrio_table, io32->pfrio_buffer,
		    &io32->pfrio_size, io32->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;

	case DIOCRGETASTATS:
		if (io32->pfrio_esize != sizeof (struct pfr_astats)) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io32->pfrio_table);
		error = pfr_get_astats(&io32->pfrio_table, io32->pfrio_buffer,
		    &io32->pfrio_size, io32->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;

	case DIOCRCLRASTATS:
		if (io32->pfrio_esize != sizeof (struct pfr_addr)) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io32->pfrio_table);
		error = pfr_clr_astats(&io32->pfrio_table, io32->pfrio_buffer,
		    io32->pfrio_size, &io32->pfrio_nzero, io32->pfrio_flags |
		    PFR_FLAG_USERIOCTL);
		break;

	case DIOCRTSTADDRS:
		if (io32->pfrio_esize != sizeof (struct pfr_addr)) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io32->pfrio_table);
		error = pfr_tst_addrs(&io32->pfrio_table, io32->pfrio_buffer,
		    io32->pfrio_size, &io32->pfrio_nmatch, io32->pfrio_flags |
		    PFR_FLAG_USERIOCTL);
		break;

	case DIOCRINADEFINE:
		if (io32->pfrio_esize != sizeof (struct pfr_addr)) {
			error = ENODEV;
			break;
		}
		pfr_table_copyin_cleanup(&io32->pfrio_table);
		error = pfr_ina_define(&io32->pfrio_table, io32->pfrio_buffer,
		    io32->pfrio_size, &io32->pfrio_nadd, &io32->pfrio_naddr,
		    io32->pfrio_ticket, io32->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

done:
	return (error);
}

static int
pfioctl_ioc_tokens(u_long cmd, struct pfioc_tokens_32 *tok32,
    struct pfioc_tokens_64 *tok64, struct proc *p)
{
	struct pfioc_token *tokens;
	struct pfioc_kernel_token *entry, *tmp;
	user_addr_t token_buf;
	int ocnt, cnt, error = 0, p64 = proc_is64bit(p);
	char *ptr;

	switch (cmd) {
	case DIOCGETSTARTERS: {
		int size;

		if (nr_tokens == 0) {
			error = ENOENT;
			break;
		}

		size = sizeof (struct pfioc_token) * nr_tokens;
		ocnt = cnt = (p64 ? tok64->size : tok32->size);
		if (cnt == 0) {
			if (p64)
				tok64->size = size;
			else
				tok32->size = size;
			break;
		}

		token_buf = (p64 ? tok64->pgt_buf : tok32->pgt_buf);
		tokens = _MALLOC(size, M_TEMP, M_WAITOK|M_ZERO);
		if (tokens == NULL) {
			error = ENOMEM;
			break;
		}

		ptr = (void *)tokens;
		SLIST_FOREACH_SAFE(entry, &token_list_head, next, tmp) {
			struct pfioc_token *t;

			if ((unsigned)cnt < sizeof (*tokens))
				break;    /* no more buffer space left */

			t = (struct pfioc_token *)(void *)ptr;
			t->token_value	= entry->token.token_value;
			t->timestamp	= entry->token.timestamp;
			t->pid		= entry->token.pid;
			bcopy(entry->token.proc_name, t->proc_name,
			    PFTOK_PROCNAME_LEN);
			ptr += sizeof (struct pfioc_token);

			cnt -= sizeof (struct pfioc_token);
		}

		if (cnt < ocnt)
			error = copyout(tokens, token_buf, ocnt - cnt);

		if (p64)
			tok64->size = ocnt - cnt;
		else
			tok32->size = ocnt - cnt;

		_FREE(tokens, M_TEMP);
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

static void
pf_expire_states_and_src_nodes(struct pf_rule *rule)
{
	struct pf_state		*state;
	struct pf_src_node	*sn;
	int			 killed = 0;

	/* expire the states */
	state = TAILQ_FIRST(&state_list);
	while (state) {
		if (state->rule.ptr == rule)
			state->timeout = PFTM_PURGE;
		state = TAILQ_NEXT(state, entry_list);
	}
	pf_purge_expired_states(pf_status.states);

	/* expire the src_nodes */
	RB_FOREACH(sn, pf_src_tree, &tree_src_tracking) {
		if (sn->rule.ptr != rule)
			continue;
		if (sn->states != 0) {
			RB_FOREACH(state, pf_state_tree_id,
			    &tree_id) {
				if (state->src_node == sn)
					state->src_node = NULL;
				if (state->nat_src_node == sn)
					state->nat_src_node = NULL;
			}
			sn->states = 0;
		}
		sn->expire = 1;
		killed++;
	}
	if (killed)
		pf_purge_expired_src_nodes();
}

static void
pf_delete_rule_from_ruleset(struct pf_ruleset *ruleset, int rs_num,
    struct pf_rule *rule)
{
	struct pf_rule *r;
	int nr = 0;

	pf_expire_states_and_src_nodes(rule);

	pf_rm_rule(ruleset->rules[rs_num].active.ptr, rule);
	if (ruleset->rules[rs_num].active.rcount-- == 0)
		panic("%s: rcount value broken!", __func__);
	r = TAILQ_FIRST(ruleset->rules[rs_num].active.ptr);

	while (r) {
		r->nr = nr++;
		r = TAILQ_NEXT(r, entries);
	}
}


static void
pf_ruleset_cleanup(struct pf_ruleset *ruleset, int rs)
{
	pf_calc_skip_steps(ruleset->rules[rs].active.ptr);
	ruleset->rules[rs].active.ticket =
	    ++ruleset->rules[rs].inactive.ticket;
}

/*
 * req_dev encodes the PF interface. Currently, possible values are
 * 0 or PFRULE_PFM
 */
static int
pf_delete_rule_by_ticket(struct pfioc_rule *pr, u_int32_t req_dev)
{
	struct pf_ruleset	*ruleset;
	struct pf_rule		*rule = NULL;
	int			 is_anchor;
	int			 error;
	int			 i;

	is_anchor = (pr->anchor_call[0] != '\0');
	if ((ruleset = pf_find_ruleset_with_owner(pr->anchor,
	    pr->rule.owner, is_anchor, &error)) == NULL)
		return (error);

	for (i = 0; i < PF_RULESET_MAX && rule == NULL; i++) {
		rule = TAILQ_FIRST(ruleset->rules[i].active.ptr);
		while (rule && (rule->ticket != pr->rule.ticket))
			rule = TAILQ_NEXT(rule, entries);
	}
	if (rule == NULL)
		return (ENOENT);
	else
		i--;

	if (strcmp(rule->owner, pr->rule.owner))
		return (EACCES);

delete_rule:
	if (rule->anchor && (ruleset != &pf_main_ruleset) &&
	    ((strcmp(ruleset->anchor->owner, "")) == 0) &&
	    ((ruleset->rules[i].active.rcount - 1) == 0)) {
		/* set rule & ruleset to parent and repeat */
		struct pf_rule *delete_rule = rule;
		struct pf_ruleset *delete_ruleset = ruleset;

#define	parent_ruleset		ruleset->anchor->parent->ruleset
		if (ruleset->anchor->parent == NULL)
			ruleset = &pf_main_ruleset;
		else
			ruleset = &parent_ruleset;

		rule = TAILQ_FIRST(ruleset->rules[i].active.ptr);
		while (rule &&
		    (rule->anchor != delete_ruleset->anchor))
			rule = TAILQ_NEXT(rule, entries);
		if (rule == NULL)
			panic("%s: rule not found!", __func__);

		/*
		 * if reqest device != rule's device, bail :
		 * with error if ticket matches;
		 * without error if ticket doesn't match (i.e. its just cleanup)
		 */
		if ((rule->rule_flag & PFRULE_PFM) ^ req_dev) {
			if (rule->ticket != pr->rule.ticket) {
				return (0);
			} else {
				return EACCES;
			}
		}

		if (delete_rule->rule_flag & PFRULE_PFM) {
			pffwrules--;
		}

		pf_delete_rule_from_ruleset(delete_ruleset,
		    i, delete_rule);
		delete_ruleset->rules[i].active.ticket =
		    ++delete_ruleset->rules[i].inactive.ticket;
		goto delete_rule;
	} else {
		/*
		 * process deleting rule only if device that added the
		 * rule matches device that issued the request
		 */
		if ((rule->rule_flag & PFRULE_PFM) ^ req_dev)
			return EACCES;
		if (rule->rule_flag & PFRULE_PFM)
			pffwrules--;
		pf_delete_rule_from_ruleset(ruleset, i,
		    rule);
		pf_ruleset_cleanup(ruleset, i);
	}

	return (0);
}

/*
 * req_dev encodes the PF interface. Currently, possible values are
 * 0 or PFRULE_PFM
 */
static void
pf_delete_rule_by_owner(char *owner, u_int32_t req_dev)
{
	struct pf_ruleset	*ruleset;
	struct pf_rule		*rule, *next;
	int			 deleted = 0;

	for (int rs = 0; rs < PF_RULESET_MAX; rs++) {
		rule = TAILQ_FIRST(pf_main_ruleset.rules[rs].active.ptr);
		ruleset = &pf_main_ruleset;
		while (rule) {
			next = TAILQ_NEXT(rule, entries);
			/*
			 * process deleting rule only if device that added the
			 * rule matches device that issued the request
			 */
			if ((rule->rule_flag & PFRULE_PFM) ^ req_dev) {
				rule = next;
				continue;
			}
			if (rule->anchor) {
				if (((strcmp(rule->owner, owner)) == 0) ||
				    ((strcmp(rule->owner, "")) == 0)) {
					if (rule->anchor->ruleset.rules[rs].active.rcount > 0) {
						if (deleted) {
							pf_ruleset_cleanup(ruleset, rs);
							deleted = 0;
						}
						/* step into anchor */
						ruleset =
						    &rule->anchor->ruleset;
						rule = TAILQ_FIRST(ruleset->rules[rs].active.ptr);
						continue;
					} else {
						if (rule->rule_flag &
						    PFRULE_PFM)
							pffwrules--;
						pf_delete_rule_from_ruleset(ruleset, rs, rule);
						deleted = 1;
						rule = next;
					}
				} else
					rule = next;
			} else {
				if (((strcmp(rule->owner, owner)) == 0)) {
					/* delete rule */
					if (rule->rule_flag & PFRULE_PFM)
						pffwrules--;
					pf_delete_rule_from_ruleset(ruleset,
					    rs, rule);
					deleted = 1;
				}
				rule = next;
			}
			if (rule == NULL) {
				if (deleted) {
					pf_ruleset_cleanup(ruleset, rs);
					deleted = 0;
				}
				if (ruleset != &pf_main_ruleset)
					pf_deleterule_anchor_step_out(&ruleset,
					    rs, &rule);
			}
		}
	}
}

static void
pf_deleterule_anchor_step_out(struct pf_ruleset **ruleset_ptr,
    int rs, struct pf_rule **rule_ptr)
{
	struct pf_ruleset *ruleset = *ruleset_ptr;
	struct pf_rule *rule = *rule_ptr;

	/* step out of anchor */
	struct pf_ruleset *rs_copy = ruleset;
	ruleset = ruleset->anchor->parent?
	    &ruleset->anchor->parent->ruleset:&pf_main_ruleset;

	rule = TAILQ_FIRST(ruleset->rules[rs].active.ptr);
	while (rule && (rule->anchor != rs_copy->anchor))
		rule = TAILQ_NEXT(rule, entries);
	if (rule == NULL)
		panic("%s: parent rule of anchor not found!", __func__);
	if (rule->anchor->ruleset.rules[rs].active.rcount > 0)
		rule = TAILQ_NEXT(rule, entries);

	*ruleset_ptr = ruleset;
	*rule_ptr = rule;
}

static void
pf_addrwrap_setup(struct pf_addr_wrap *aw)
{
	VERIFY(aw);
	bzero(&aw->p, sizeof aw->p);
}

static int
pf_rule_setup(struct pfioc_rule *pr, struct pf_rule *rule,
    struct pf_ruleset *ruleset) {
	struct pf_pooladdr 	*apa;
	int			 error = 0;

	if (rule->ifname[0]) {
		rule->kif = pfi_kif_get(rule->ifname);
		if (rule->kif == NULL) {
			pool_put(&pf_rule_pl, rule);
			return (EINVAL);
		}
		pfi_kif_ref(rule->kif, PFI_KIF_REF_RULE);
	}
	if (rule->tagname[0])
		if ((rule->tag = pf_tagname2tag(rule->tagname)) == 0)
			error = EBUSY;
	if (rule->match_tagname[0])
		if ((rule->match_tag =
		    pf_tagname2tag(rule->match_tagname)) == 0)
			error = EBUSY;
	if (rule->rt && !rule->direction)
		error = EINVAL;
#if PFLOG
	if (!rule->log)
		rule->logif = 0;
	if (rule->logif >= PFLOGIFS_MAX)
		error = EINVAL;
#endif /* PFLOG */
	pf_addrwrap_setup(&rule->src.addr);
	pf_addrwrap_setup(&rule->dst.addr);
	if (pf_rtlabel_add(&rule->src.addr) ||
	    pf_rtlabel_add(&rule->dst.addr))
		error = EBUSY;
	if (pfi_dynaddr_setup(&rule->src.addr, rule->af))
		error = EINVAL;
	if (pfi_dynaddr_setup(&rule->dst.addr, rule->af))
		error = EINVAL;
	if (pf_tbladdr_setup(ruleset, &rule->src.addr))
		error = EINVAL;
	if (pf_tbladdr_setup(ruleset, &rule->dst.addr))
		error = EINVAL;
	if (pf_anchor_setup(rule, ruleset, pr->anchor_call))
		error = EINVAL;
	TAILQ_FOREACH(apa, &pf_pabuf, entries)
		if (pf_tbladdr_setup(ruleset, &apa->addr))
			error = EINVAL;

	if (rule->overload_tblname[0]) {
		if ((rule->overload_tbl = pfr_attach_table(ruleset,
		    rule->overload_tblname)) == NULL)
			error = EINVAL;
		else
			rule->overload_tbl->pfrkt_flags |=
			    PFR_TFLAG_ACTIVE;
	}

	pf_mv_pool(&pf_pabuf, &rule->rpool.list);

	if (((((rule->action == PF_NAT) || (rule->action == PF_RDR) ||
	    (rule->action == PF_BINAT) || (rule->action == PF_NAT64)) &&
	    rule->anchor == NULL) ||
	    (rule->rt > PF_FASTROUTE)) &&
	    (TAILQ_FIRST(&rule->rpool.list) == NULL))
		error = EINVAL;

	if (error) {
		pf_rm_rule(NULL, rule);
		return (error);
	}
	/* For a NAT64 rule the rule's address family is AF_INET6 whereas
	 * the address pool's family will be AF_INET
	 */
	rule->rpool.af = (rule->action == PF_NAT64) ? AF_INET: rule->af;
	rule->rpool.cur = TAILQ_FIRST(&rule->rpool.list);
	rule->evaluations = rule->packets[0] = rule->packets[1] =
	    rule->bytes[0] = rule->bytes[1] = 0;

	return (0);
}

static int
pfioctl_ioc_rule(u_long cmd, int minordev, struct pfioc_rule *pr, struct proc *p)
{
	int error = 0;
	u_int32_t req_dev = 0;

	switch (cmd) {
	case DIOCADDRULE: {
		struct pf_ruleset	*ruleset;
		struct pf_rule		*rule, *tail;
		int			rs_num;

		pr->anchor[sizeof (pr->anchor) - 1] = '\0';
		pr->anchor_call[sizeof (pr->anchor_call) - 1] = '\0';
		ruleset = pf_find_ruleset(pr->anchor);
		if (ruleset == NULL) {
			error = EINVAL;
			break;
		}
		rs_num = pf_get_ruleset_number(pr->rule.action);
		if (rs_num >= PF_RULESET_MAX) {
			error = EINVAL;
			break;
		}
		if (pr->rule.return_icmp >> 8 > ICMP_MAXTYPE) {
			error = EINVAL;
			break;
		}
		if (pr->ticket != ruleset->rules[rs_num].inactive.ticket) {
			error = EBUSY;
			break;
		}
		if (pr->pool_ticket != ticket_pabuf) {
			error = EBUSY;
			break;
		}
		rule = pool_get(&pf_rule_pl, PR_WAITOK);
		if (rule == NULL) {
			error = ENOMEM;
			break;
		}
		pf_rule_copyin(&pr->rule, rule, p, minordev);
#if !INET
		if (rule->af == AF_INET) {
			pool_put(&pf_rule_pl, rule);
			error = EAFNOSUPPORT;
			break;
		}
#endif /* INET */
#if !INET6
		if (rule->af == AF_INET6) {
			pool_put(&pf_rule_pl, rule);
			error = EAFNOSUPPORT;
			break;
		}
#endif /* INET6 */
		tail = TAILQ_LAST(ruleset->rules[rs_num].inactive.ptr,
		    pf_rulequeue);
		if (tail)
			rule->nr = tail->nr + 1;
		else
			rule->nr = 0;

		if ((error = pf_rule_setup(pr, rule, ruleset)))
			break;

		TAILQ_INSERT_TAIL(ruleset->rules[rs_num].inactive.ptr,
		    rule, entries);
		ruleset->rules[rs_num].inactive.rcount++;
		if (rule->rule_flag & PFRULE_PFM)
			pffwrules++;

		if (rule->action == PF_NAT64)
			atomic_add_16(&pf_nat64_configured, 1);

		if (pr->anchor_call[0] == '\0') {
			INC_ATOMIC_INT64_LIM(net_api_stats.nas_pf_addrule_total);
			if (rule->rule_flag & PFRULE_PFM) {
				INC_ATOMIC_INT64_LIM(net_api_stats.nas_pf_addrule_os);
			}
		}

#if DUMMYNET
		if (rule->action == PF_DUMMYNET) {
			struct dummynet_event dn_event;
			uint32_t direction = DN_INOUT;;
			bzero(&dn_event, sizeof(dn_event));

			dn_event.dn_event_code = DUMMYNET_RULE_CONFIG;

			if (rule->direction == PF_IN)
				direction = DN_IN;
			else if (rule->direction == PF_OUT)
				direction = DN_OUT;

			dn_event.dn_event_rule_config.dir = direction;
			dn_event.dn_event_rule_config.af = rule->af;
			dn_event.dn_event_rule_config.proto = rule->proto;
			dn_event.dn_event_rule_config.src_port = rule->src.xport.range.port[0];
			dn_event.dn_event_rule_config.dst_port = rule->dst.xport.range.port[0];
			strlcpy(dn_event.dn_event_rule_config.ifname, rule->ifname,
			    sizeof(dn_event.dn_event_rule_config.ifname));

			dummynet_event_enqueue_nwk_wq_entry(&dn_event);
		}
#endif
		break;
	}

	case DIOCGETRULES: {
		struct pf_ruleset	*ruleset;
		struct pf_rule		*tail;
		int			 rs_num;

		pr->anchor[sizeof (pr->anchor) - 1] = '\0';
		pr->anchor_call[sizeof (pr->anchor_call) - 1] = '\0';
		ruleset = pf_find_ruleset(pr->anchor);
		if (ruleset == NULL) {
			error = EINVAL;
			break;
		}
		rs_num = pf_get_ruleset_number(pr->rule.action);
		if (rs_num >= PF_RULESET_MAX) {
			error = EINVAL;
			break;
		}
		tail = TAILQ_LAST(ruleset->rules[rs_num].active.ptr,
		    pf_rulequeue);
		if (tail)
			pr->nr = tail->nr + 1;
		else
			pr->nr = 0;
		pr->ticket = ruleset->rules[rs_num].active.ticket;
		break;
	}

	case DIOCGETRULE: {
		struct pf_ruleset	*ruleset;
		struct pf_rule		*rule;
		int			 rs_num, i;

		pr->anchor[sizeof (pr->anchor) - 1] = '\0';
		pr->anchor_call[sizeof (pr->anchor_call) - 1] = '\0';
		ruleset = pf_find_ruleset(pr->anchor);
		if (ruleset == NULL) {
			error = EINVAL;
			break;
		}
		rs_num = pf_get_ruleset_number(pr->rule.action);
		if (rs_num >= PF_RULESET_MAX) {
			error = EINVAL;
			break;
		}
		if (pr->ticket != ruleset->rules[rs_num].active.ticket) {
			error = EBUSY;
			break;
		}
		rule = TAILQ_FIRST(ruleset->rules[rs_num].active.ptr);
		while ((rule != NULL) && (rule->nr != pr->nr))
			rule = TAILQ_NEXT(rule, entries);
		if (rule == NULL) {
			error = EBUSY;
			break;
		}
		pf_rule_copyout(rule, &pr->rule);
		if (pf_anchor_copyout(ruleset, rule, pr)) {
			error = EBUSY;
			break;
		}
		pfi_dynaddr_copyout(&pr->rule.src.addr);
		pfi_dynaddr_copyout(&pr->rule.dst.addr);
		pf_tbladdr_copyout(&pr->rule.src.addr);
		pf_tbladdr_copyout(&pr->rule.dst.addr);
		pf_rtlabel_copyout(&pr->rule.src.addr);
		pf_rtlabel_copyout(&pr->rule.dst.addr);
		for (i = 0; i < PF_SKIP_COUNT; ++i)
			if (rule->skip[i].ptr == NULL)
				pr->rule.skip[i].nr = -1;
			else
				pr->rule.skip[i].nr =
				    rule->skip[i].ptr->nr;

		if (pr->action == PF_GET_CLR_CNTR) {
			rule->evaluations = 0;
			rule->packets[0] = rule->packets[1] = 0;
			rule->bytes[0] = rule->bytes[1] = 0;
		}
		break;
	}

	case DIOCCHANGERULE: {
		struct pfioc_rule	*pcr = pr;
		struct pf_ruleset	*ruleset;
		struct pf_rule		*oldrule = NULL, *newrule = NULL;
		struct pf_pooladdr	*pa;
		u_int32_t		 nr = 0;
		int			 rs_num;

		if (!(pcr->action == PF_CHANGE_REMOVE ||
		    pcr->action == PF_CHANGE_GET_TICKET) &&
		    pcr->pool_ticket != ticket_pabuf) {
			error = EBUSY;
			break;
		}

		if (pcr->action < PF_CHANGE_ADD_HEAD ||
		    pcr->action > PF_CHANGE_GET_TICKET) {
			error = EINVAL;
			break;
		}
		pcr->anchor[sizeof (pcr->anchor) - 1] = '\0';
		pcr->anchor_call[sizeof (pcr->anchor_call) - 1] = '\0';
		ruleset = pf_find_ruleset(pcr->anchor);
		if (ruleset == NULL) {
			error = EINVAL;
			break;
		}
		rs_num = pf_get_ruleset_number(pcr->rule.action);
		if (rs_num >= PF_RULESET_MAX) {
			error = EINVAL;
			break;
		}

		if (pcr->action == PF_CHANGE_GET_TICKET) {
			pcr->ticket = ++ruleset->rules[rs_num].active.ticket;
			break;
		} else {
			if (pcr->ticket !=
			    ruleset->rules[rs_num].active.ticket) {
				error = EINVAL;
				break;
			}
			if (pcr->rule.return_icmp >> 8 > ICMP_MAXTYPE) {
				error = EINVAL;
				break;
			}
		}

		if (pcr->action != PF_CHANGE_REMOVE) {
			newrule = pool_get(&pf_rule_pl, PR_WAITOK);
			if (newrule == NULL) {
				error = ENOMEM;
				break;
			}
			pf_rule_copyin(&pcr->rule, newrule, p, minordev);
#if !INET
			if (newrule->af == AF_INET) {
				pool_put(&pf_rule_pl, newrule);
				error = EAFNOSUPPORT;
				break;
			}
#endif /* INET */
#if !INET6
			if (newrule->af == AF_INET6) {
				pool_put(&pf_rule_pl, newrule);
				error = EAFNOSUPPORT;
				break;
			}
#endif /* INET6 */
			if (newrule->ifname[0]) {
				newrule->kif = pfi_kif_get(newrule->ifname);
				if (newrule->kif == NULL) {
					pool_put(&pf_rule_pl, newrule);
					error = EINVAL;
					break;
				}
				pfi_kif_ref(newrule->kif, PFI_KIF_REF_RULE);
			} else
				newrule->kif = NULL;

			if (newrule->tagname[0])
				if ((newrule->tag =
				    pf_tagname2tag(newrule->tagname)) == 0)
					error = EBUSY;
			if (newrule->match_tagname[0])
				if ((newrule->match_tag = pf_tagname2tag(
				    newrule->match_tagname)) == 0)
					error = EBUSY;
			if (newrule->rt && !newrule->direction)
				error = EINVAL;
#if PFLOG
			if (!newrule->log)
				newrule->logif = 0;
			if (newrule->logif >= PFLOGIFS_MAX)
				error = EINVAL;
#endif /* PFLOG */
			pf_addrwrap_setup(&newrule->src.addr);
			pf_addrwrap_setup(&newrule->dst.addr);
			if (pf_rtlabel_add(&newrule->src.addr) ||
			    pf_rtlabel_add(&newrule->dst.addr))
				error = EBUSY;
			if (pfi_dynaddr_setup(&newrule->src.addr, newrule->af))
				error = EINVAL;
			if (pfi_dynaddr_setup(&newrule->dst.addr, newrule->af))
				error = EINVAL;
			if (pf_tbladdr_setup(ruleset, &newrule->src.addr))
				error = EINVAL;
			if (pf_tbladdr_setup(ruleset, &newrule->dst.addr))
				error = EINVAL;
			if (pf_anchor_setup(newrule, ruleset, pcr->anchor_call))
				error = EINVAL;
			TAILQ_FOREACH(pa, &pf_pabuf, entries)
				if (pf_tbladdr_setup(ruleset, &pa->addr))
					error = EINVAL;

			if (newrule->overload_tblname[0]) {
				if ((newrule->overload_tbl = pfr_attach_table(
				    ruleset, newrule->overload_tblname)) ==
				    NULL)
					error = EINVAL;
				else
					newrule->overload_tbl->pfrkt_flags |=
					    PFR_TFLAG_ACTIVE;
			}

			pf_mv_pool(&pf_pabuf, &newrule->rpool.list);
			if (((((newrule->action == PF_NAT) ||
			    (newrule->action == PF_RDR) ||
			    (newrule->action == PF_BINAT) ||
			    (newrule->rt > PF_FASTROUTE)) &&
			    !newrule->anchor)) &&
			    (TAILQ_FIRST(&newrule->rpool.list) == NULL))
				error = EINVAL;

			if (error) {
				pf_rm_rule(NULL, newrule);
				break;
			}
			newrule->rpool.cur = TAILQ_FIRST(&newrule->rpool.list);
			newrule->evaluations = 0;
			newrule->packets[0] = newrule->packets[1] = 0;
			newrule->bytes[0] = newrule->bytes[1] = 0;
		}
		pf_empty_pool(&pf_pabuf);

		if (pcr->action == PF_CHANGE_ADD_HEAD)
			oldrule = TAILQ_FIRST(
			    ruleset->rules[rs_num].active.ptr);
		else if (pcr->action == PF_CHANGE_ADD_TAIL)
			oldrule = TAILQ_LAST(
			    ruleset->rules[rs_num].active.ptr, pf_rulequeue);
		else {
			oldrule = TAILQ_FIRST(
			    ruleset->rules[rs_num].active.ptr);
			while ((oldrule != NULL) && (oldrule->nr != pcr->nr))
				oldrule = TAILQ_NEXT(oldrule, entries);
			if (oldrule == NULL) {
				if (newrule != NULL)
					pf_rm_rule(NULL, newrule);
				error = EINVAL;
				break;
			}
		}

		if (pcr->action == PF_CHANGE_REMOVE) {
			pf_rm_rule(ruleset->rules[rs_num].active.ptr, oldrule);
			ruleset->rules[rs_num].active.rcount--;
		} else {
			if (oldrule == NULL)
				TAILQ_INSERT_TAIL(
				    ruleset->rules[rs_num].active.ptr,
				    newrule, entries);
			else if (pcr->action == PF_CHANGE_ADD_HEAD ||
			    pcr->action == PF_CHANGE_ADD_BEFORE)
				TAILQ_INSERT_BEFORE(oldrule, newrule, entries);
			else
				TAILQ_INSERT_AFTER(
				    ruleset->rules[rs_num].active.ptr,
				    oldrule, newrule, entries);
			ruleset->rules[rs_num].active.rcount++;
		}

		nr = 0;
		TAILQ_FOREACH(oldrule,
		    ruleset->rules[rs_num].active.ptr, entries)
			oldrule->nr = nr++;

		ruleset->rules[rs_num].active.ticket++;

		pf_calc_skip_steps(ruleset->rules[rs_num].active.ptr);
		pf_remove_if_empty_ruleset(ruleset);

		break;
	}

	case DIOCINSERTRULE: {
		struct pf_ruleset	*ruleset;
		struct pf_rule		*rule, *tail, *r;
		int			rs_num;
		int			is_anchor;

		pr->anchor[sizeof (pr->anchor) - 1] = '\0';
		pr->anchor_call[sizeof (pr->anchor_call) - 1] = '\0';
		is_anchor = (pr->anchor_call[0] != '\0');

		if ((ruleset = pf_find_ruleset_with_owner(pr->anchor,
		    pr->rule.owner, is_anchor, &error)) == NULL)
			break;

		rs_num = pf_get_ruleset_number(pr->rule.action);
		if (rs_num >= PF_RULESET_MAX) {
			error = EINVAL;
			break;
		}
		if (pr->rule.return_icmp >> 8 > ICMP_MAXTYPE) {
			error = EINVAL;
			break;
		}

		/* make sure this anchor rule doesn't exist already */
		if (is_anchor) {
			r = TAILQ_FIRST(ruleset->rules[rs_num].active.ptr);
			while (r) {
				if (r->anchor &&
				    ((strcmp(r->anchor->name,
				    pr->anchor_call)) == 0)) {
					if (((strcmp(pr->rule.owner,
					    r->owner)) == 0) ||
					    ((strcmp(r->owner, "")) == 0))
						error = EEXIST;
					else
						error = EPERM;
					break;
				}
				r = TAILQ_NEXT(r, entries);
			}
			if (error != 0)
				return (error);
		}

		rule = pool_get(&pf_rule_pl, PR_WAITOK);
		if (rule == NULL) {
			error = ENOMEM;
			break;
		}
		pf_rule_copyin(&pr->rule, rule, p, minordev);
#if !INET
		if (rule->af == AF_INET) {
			pool_put(&pf_rule_pl, rule);
			error = EAFNOSUPPORT;
			break;
		}
#endif /* INET */
#if !INET6
		if (rule->af == AF_INET6) {
			pool_put(&pf_rule_pl, rule);
			error = EAFNOSUPPORT;
			break;
		}

#endif /* INET6 */
		r = TAILQ_FIRST(ruleset->rules[rs_num].active.ptr);
		while ((r != NULL) && (rule->priority >= (unsigned)r->priority))
			r = TAILQ_NEXT(r, entries);
		if (r == NULL) {
			if ((tail =
			    TAILQ_LAST(ruleset->rules[rs_num].active.ptr,
			    pf_rulequeue)) != NULL)
				rule->nr = tail->nr + 1;
			else
				rule->nr = 0;
		} else {
			rule->nr = r->nr;
		}

		if ((error = pf_rule_setup(pr, rule, ruleset)))
			break;

		if (rule->anchor != NULL)
			strlcpy(rule->anchor->owner, rule->owner,
			    PF_OWNER_NAME_SIZE);

		if (r) {
			TAILQ_INSERT_BEFORE(r, rule, entries);
			while (r && ++r->nr)
				r = TAILQ_NEXT(r, entries);
		} else
			TAILQ_INSERT_TAIL(ruleset->rules[rs_num].active.ptr,
			    rule, entries);
		ruleset->rules[rs_num].active.rcount++;

		/* Calculate checksum for the main ruleset */
		if (ruleset == &pf_main_ruleset)
			error = pf_setup_pfsync_matching(ruleset);

		pf_ruleset_cleanup(ruleset, rs_num);
		rule->ticket = VM_KERNEL_ADDRPERM((u_int64_t)(uintptr_t)rule);

		pr->rule.ticket = rule->ticket;
		pf_rule_copyout(rule, &pr->rule);
		if (rule->rule_flag & PFRULE_PFM)
			pffwrules++;
		if (rule->action == PF_NAT64)
			atomic_add_16(&pf_nat64_configured, 1);

		if (pr->anchor_call[0] == '\0') {
			INC_ATOMIC_INT64_LIM(net_api_stats.nas_pf_addrule_total);
			if (rule->rule_flag & PFRULE_PFM) {
				INC_ATOMIC_INT64_LIM(net_api_stats.nas_pf_addrule_os);
			}
		}
		break;
	}

	case DIOCDELETERULE: {
		pr->anchor[sizeof (pr->anchor) - 1] = '\0';
		pr->anchor_call[sizeof (pr->anchor_call) - 1] = '\0';

		if (pr->rule.return_icmp >> 8 > ICMP_MAXTYPE) {
			error = EINVAL;
			break;
		}

		/* get device through which request is made */
		if ((uint8_t)minordev == PFDEV_PFM)
			req_dev |= PFRULE_PFM;

		if (pr->rule.ticket) {
			if ((error = pf_delete_rule_by_ticket(pr, req_dev)))
				break;
		} else
			pf_delete_rule_by_owner(pr->rule.owner, req_dev);
		pr->nr = pffwrules;
		if (pr->rule.action == PF_NAT64)
			atomic_add_16(&pf_nat64_configured, -1);
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

static int
pfioctl_ioc_state_kill(u_long cmd, struct pfioc_state_kill *psk, struct proc *p)
{
#pragma unused(p)
	int error = 0;

	psk->psk_ifname[sizeof (psk->psk_ifname) - 1] = '\0';
	psk->psk_ownername[sizeof(psk->psk_ownername) - 1] = '\0';

	bool ifname_matched = true;
	bool owner_matched = true;

	switch (cmd) {
	case DIOCCLRSTATES: {
		struct pf_state		*s, *nexts;
		int			 killed = 0;

		for (s = RB_MIN(pf_state_tree_id, &tree_id); s; s = nexts) {
			nexts = RB_NEXT(pf_state_tree_id, &tree_id, s);
			/*
			 * Purge all states only when neither ifname
			 * or owner is provided. If any of these are provided
			 * we purge only the states with meta data that match
			 */
			bool unlink_state = false;
			ifname_matched = true;
			owner_matched = true;

			if (psk->psk_ifname[0] &&
			    strcmp(psk->psk_ifname, s->kif->pfik_name)) {
				ifname_matched = false;
			}

			if (psk->psk_ownername[0] &&
			    ((NULL == s->rule.ptr) ||
			     strcmp(psk->psk_ownername, s->rule.ptr->owner))) {
				owner_matched = false;
			}

			unlink_state = ifname_matched && owner_matched;

			if (unlink_state) {
#if NPFSYNC
				/* don't send out individual delete messages */
				s->sync_flags = PFSTATE_NOSYNC;
#endif
				pf_unlink_state(s);
				killed++;
			}
		}
		psk->psk_af = killed;
#if NPFSYNC
		pfsync_clear_states(pf_status.hostid, psk->psk_ifname);
#endif
		break;
	}

	case DIOCKILLSTATES: {
		struct pf_state		*s, *nexts;
		struct pf_state_key	*sk;
		struct pf_state_host	*src, *dst;
		int			 killed = 0;

		for (s = RB_MIN(pf_state_tree_id, &tree_id); s;
		    s = nexts) {
			nexts = RB_NEXT(pf_state_tree_id, &tree_id, s);
			sk = s->state_key;
			ifname_matched = true;
			owner_matched = true;

			if (psk->psk_ifname[0] &&
			    strcmp(psk->psk_ifname, s->kif->pfik_name)) {
				ifname_matched = false;
			}

			if (psk->psk_ownername[0] &&
			    ((NULL == s->rule.ptr) ||
			     strcmp(psk->psk_ownername, s->rule.ptr->owner))) {
				owner_matched = false;
			}

			if (sk->direction == PF_OUT) {
				src = &sk->lan;
				dst = &sk->ext_lan;
			} else {
				src = &sk->ext_lan;
				dst = &sk->lan;
			}
			if ((!psk->psk_af || sk->af_lan == psk->psk_af) &&
			    (!psk->psk_proto || psk->psk_proto == sk->proto) &&
			    PF_MATCHA(psk->psk_src.neg,
			    &psk->psk_src.addr.v.a.addr,
			    &psk->psk_src.addr.v.a.mask,
			    &src->addr, sk->af_lan) &&
			    PF_MATCHA(psk->psk_dst.neg,
			    &psk->psk_dst.addr.v.a.addr,
			    &psk->psk_dst.addr.v.a.mask,
			    &dst->addr, sk->af_lan) &&
			    (pf_match_xport(psk->psk_proto,
			    psk->psk_proto_variant, &psk->psk_src.xport,
			    &src->xport)) &&
			    (pf_match_xport(psk->psk_proto,
			    psk->psk_proto_variant, &psk->psk_dst.xport,
			    &dst->xport)) &&
			    ifname_matched &&
			    owner_matched) {
#if NPFSYNC
				/* send immediate delete of state */
				pfsync_delete_state(s);
				s->sync_flags |= PFSTATE_NOSYNC;
#endif
				pf_unlink_state(s);
				killed++;
			}
		}
		psk->psk_af = killed;
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

static int
pfioctl_ioc_state(u_long cmd, struct pfioc_state *ps, struct proc *p)
{
#pragma unused(p)
	int error = 0;

	switch (cmd) {
	case DIOCADDSTATE: {
		struct pfsync_state	*sp = &ps->state;
		struct pf_state		*s;
		struct pf_state_key	*sk;
		struct pfi_kif		*kif;

		if (sp->timeout >= PFTM_MAX) {
			error = EINVAL;
			break;
		}
		s = pool_get(&pf_state_pl, PR_WAITOK);
		if (s == NULL) {
			error = ENOMEM;
			break;
		}
		bzero(s, sizeof (struct pf_state));
		if ((sk = pf_alloc_state_key(s, NULL)) == NULL) {
			pool_put(&pf_state_pl, s);
			error = ENOMEM;
			break;
		}
		pf_state_import(sp, sk, s);
		kif = pfi_kif_get(sp->ifname);
		if (kif == NULL) {
			pool_put(&pf_state_pl, s);
			pool_put(&pf_state_key_pl, sk);
			error = ENOENT;
			break;
		}
		TAILQ_INIT(&s->unlink_hooks);
		s->state_key->app_state = 0;
		if (pf_insert_state(kif, s)) {
			pfi_kif_unref(kif, PFI_KIF_REF_NONE);
			pool_put(&pf_state_pl, s);
			error = EEXIST;
			break;
		}
		pf_default_rule.states++;
		VERIFY(pf_default_rule.states != 0);
		break;
	}

	case DIOCGETSTATE: {
		struct pf_state		*s;
		struct pf_state_cmp	 id_key;

		bcopy(ps->state.id, &id_key.id, sizeof (id_key.id));
		id_key.creatorid = ps->state.creatorid;

		s = pf_find_state_byid(&id_key);
		if (s == NULL) {
			error = ENOENT;
			break;
		}

		pf_state_export(&ps->state, s->state_key, s);
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

static int
pfioctl_ioc_states(u_long cmd, struct pfioc_states_32 *ps32,
    struct pfioc_states_64 *ps64, struct proc *p)
{
	int p64 = proc_is64bit(p);
	int error = 0;

	switch (cmd) {
	case DIOCGETSTATES: {		/* struct pfioc_states */
		struct pf_state		*state;
		struct pfsync_state	*pstore;
		user_addr_t		 buf;
		u_int32_t		 nr = 0;
		int			 len, size;

		len = (p64 ? ps64->ps_len : ps32->ps_len);
		if (len == 0) {
			size = sizeof (struct pfsync_state) * pf_status.states;
			if (p64)
				ps64->ps_len = size;
			else
				ps32->ps_len = size;
			break;
		}

		pstore = _MALLOC(sizeof (*pstore), M_TEMP, M_WAITOK | M_ZERO);
		if (pstore == NULL) {
			error = ENOMEM;
			break;
		}
		buf = (p64 ? ps64->ps_buf : ps32->ps_buf);

		state = TAILQ_FIRST(&state_list);
		while (state) {
			if (state->timeout != PFTM_UNLINKED) {
				if ((nr + 1) * sizeof (*pstore) > (unsigned)len)
					break;

				pf_state_export(pstore,
				    state->state_key, state);
				error = copyout(pstore, buf, sizeof (*pstore));
				if (error) {
					_FREE(pstore, M_TEMP);
					goto fail;
				}
				buf += sizeof (*pstore);
				nr++;
			}
			state = TAILQ_NEXT(state, entry_list);
		}

		size = sizeof (struct pfsync_state) * nr;
		if (p64)
			ps64->ps_len = size;
		else
			ps32->ps_len = size;

		_FREE(pstore, M_TEMP);
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}
fail:
	return (error);
}

static int
pfioctl_ioc_natlook(u_long cmd, struct pfioc_natlook *pnl, struct proc *p)
{
#pragma unused(p)
	int error = 0;

	switch (cmd) {
	case DIOCNATLOOK: {
		struct pf_state_key	*sk;
		struct pf_state		*state;
		struct pf_state_key_cmp	 key;
		int			 m = 0, direction = pnl->direction;

		key.proto = pnl->proto;
		key.proto_variant = pnl->proto_variant;

		if (!pnl->proto ||
		    PF_AZERO(&pnl->saddr, pnl->af) ||
		    PF_AZERO(&pnl->daddr, pnl->af) ||
		    ((pnl->proto == IPPROTO_TCP ||
		    pnl->proto == IPPROTO_UDP) &&
		    (!pnl->dxport.port || !pnl->sxport.port)))
			error = EINVAL;
		else {
			/*
			 * userland gives us source and dest of connection,
			 * reverse the lookup so we ask for what happens with
			 * the return traffic, enabling us to find it in the
			 * state tree.
			 */
			if (direction == PF_IN) {
				key.af_gwy = pnl->af;
				PF_ACPY(&key.ext_gwy.addr, &pnl->daddr,
					pnl->af);
				memcpy(&key.ext_gwy.xport, &pnl->dxport,
				    sizeof (key.ext_gwy.xport));
				PF_ACPY(&key.gwy.addr, &pnl->saddr, pnl->af);
				memcpy(&key.gwy.xport, &pnl->sxport,
				    sizeof (key.gwy.xport));
				state = pf_find_state_all(&key, PF_IN, &m);
			} else {
				key.af_lan = pnl->af;
				PF_ACPY(&key.lan.addr, &pnl->daddr, pnl->af);
				memcpy(&key.lan.xport, &pnl->dxport,
				    sizeof (key.lan.xport));
				PF_ACPY(&key.ext_lan.addr, &pnl->saddr,
					pnl->af);
				memcpy(&key.ext_lan.xport, &pnl->sxport,
				    sizeof (key.ext_lan.xport));
				state = pf_find_state_all(&key, PF_OUT, &m);
			}
			if (m > 1)
				error = E2BIG;	/* more than one state */
			else if (state != NULL) {
				sk = state->state_key;
				if (direction == PF_IN) {
					PF_ACPY(&pnl->rsaddr, &sk->lan.addr,
					    sk->af_lan);
					memcpy(&pnl->rsxport, &sk->lan.xport,
					    sizeof (pnl->rsxport));
					PF_ACPY(&pnl->rdaddr, &pnl->daddr,
					    pnl->af);
					memcpy(&pnl->rdxport, &pnl->dxport,
					    sizeof (pnl->rdxport));
				} else {
					PF_ACPY(&pnl->rdaddr, &sk->gwy.addr,
					    sk->af_gwy);
					memcpy(&pnl->rdxport, &sk->gwy.xport,
					    sizeof (pnl->rdxport));
					PF_ACPY(&pnl->rsaddr, &pnl->saddr,
					    pnl->af);
					memcpy(&pnl->rsxport, &pnl->sxport,
					    sizeof (pnl->rsxport));
				}
			} else
				error = ENOENT;
		}
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

static int
pfioctl_ioc_tm(u_long cmd, struct pfioc_tm *pt, struct proc *p)
{
#pragma unused(p)
	int error = 0;

	switch (cmd) {
	case DIOCSETTIMEOUT: {
		int old;

		if (pt->timeout < 0 || pt->timeout >= PFTM_MAX ||
		    pt->seconds < 0) {
			error = EINVAL;
			goto fail;
		}
		old = pf_default_rule.timeout[pt->timeout];
		if (pt->timeout == PFTM_INTERVAL && pt->seconds == 0)
			pt->seconds = 1;
		pf_default_rule.timeout[pt->timeout] = pt->seconds;
		if (pt->timeout == PFTM_INTERVAL && pt->seconds < old)
			wakeup(pf_purge_thread_fn);
		pt->seconds = old;
		break;
	}

	case DIOCGETTIMEOUT: {
		if (pt->timeout < 0 || pt->timeout >= PFTM_MAX) {
			error = EINVAL;
			goto fail;
		}
		pt->seconds = pf_default_rule.timeout[pt->timeout];
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}
fail:
	return (error);
}

static int
pfioctl_ioc_limit(u_long cmd, struct pfioc_limit *pl, struct proc *p)
{
#pragma unused(p)
	int error = 0;

	switch (cmd) {
	case DIOCGETLIMIT: {

		if (pl->index < 0 || pl->index >= PF_LIMIT_MAX) {
			error = EINVAL;
			goto fail;
		}
		pl->limit = pf_pool_limits[pl->index].limit;
		break;
	}

	case DIOCSETLIMIT: {
		int old_limit;

		if (pl->index < 0 || pl->index >= PF_LIMIT_MAX ||
		    pf_pool_limits[pl->index].pp == NULL) {
			error = EINVAL;
			goto fail;
		}
		pool_sethardlimit(pf_pool_limits[pl->index].pp,
		    pl->limit, NULL, 0);
		old_limit = pf_pool_limits[pl->index].limit;
		pf_pool_limits[pl->index].limit = pl->limit;
		pl->limit = old_limit;
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}
fail:
	return (error);
}

static int
pfioctl_ioc_pooladdr(u_long cmd, struct pfioc_pooladdr *pp, struct proc *p)
{
#pragma unused(p)
	struct pf_pooladdr *pa = NULL;
	struct pf_pool *pool = NULL;
	int error = 0;

	switch (cmd) {
	case DIOCBEGINADDRS: {
		pf_empty_pool(&pf_pabuf);
		pp->ticket = ++ticket_pabuf;
		break;
	}

	case DIOCADDADDR: {
		pp->anchor[sizeof (pp->anchor) - 1] = '\0';
		if (pp->ticket != ticket_pabuf) {
			error = EBUSY;
			break;
		}
#if !INET
		if (pp->af == AF_INET) {
			error = EAFNOSUPPORT;
			break;
		}
#endif /* INET */
#if !INET6
		if (pp->af == AF_INET6) {
			error = EAFNOSUPPORT;
			break;
		}
#endif /* INET6 */
		if (pp->addr.addr.type != PF_ADDR_ADDRMASK &&
		    pp->addr.addr.type != PF_ADDR_DYNIFTL &&
		    pp->addr.addr.type != PF_ADDR_TABLE) {
			error = EINVAL;
			break;
		}
		pa = pool_get(&pf_pooladdr_pl, PR_WAITOK);
		if (pa == NULL) {
			error = ENOMEM;
			break;
		}
		pf_pooladdr_copyin(&pp->addr, pa);
		if (pa->ifname[0]) {
			pa->kif = pfi_kif_get(pa->ifname);
			if (pa->kif == NULL) {
				pool_put(&pf_pooladdr_pl, pa);
				error = EINVAL;
				break;
			}
			pfi_kif_ref(pa->kif, PFI_KIF_REF_RULE);
		}
		pf_addrwrap_setup(&pa->addr);
		if (pfi_dynaddr_setup(&pa->addr, pp->af)) {
			pfi_dynaddr_remove(&pa->addr);
			pfi_kif_unref(pa->kif, PFI_KIF_REF_RULE);
			pool_put(&pf_pooladdr_pl, pa);
			error = EINVAL;
			break;
		}
		TAILQ_INSERT_TAIL(&pf_pabuf, pa, entries);
		break;
	}

	case DIOCGETADDRS: {
		pp->nr = 0;
		pp->anchor[sizeof (pp->anchor) - 1] = '\0';
		pool = pf_get_pool(pp->anchor, pp->ticket, pp->r_action,
		    pp->r_num, 0, 1, 0);
		if (pool == NULL) {
			error = EBUSY;
			break;
		}
		TAILQ_FOREACH(pa, &pool->list, entries)
			pp->nr++;
		break;
	}

	case DIOCGETADDR: {
		u_int32_t		 nr = 0;

		pp->anchor[sizeof (pp->anchor) - 1] = '\0';
		pool = pf_get_pool(pp->anchor, pp->ticket, pp->r_action,
		    pp->r_num, 0, 1, 1);
		if (pool == NULL) {
			error = EBUSY;
			break;
		}
		pa = TAILQ_FIRST(&pool->list);
		while ((pa != NULL) && (nr < pp->nr)) {
			pa = TAILQ_NEXT(pa, entries);
			nr++;
		}
		if (pa == NULL) {
			error = EBUSY;
			break;
		}
		pf_pooladdr_copyout(pa, &pp->addr);
		pfi_dynaddr_copyout(&pp->addr.addr);
		pf_tbladdr_copyout(&pp->addr.addr);
		pf_rtlabel_copyout(&pp->addr.addr);
		break;
	}

	case DIOCCHANGEADDR: {
		struct pfioc_pooladdr	*pca = pp;
		struct pf_pooladdr	*oldpa = NULL, *newpa = NULL;
		struct pf_ruleset	*ruleset;

		if (pca->action < PF_CHANGE_ADD_HEAD ||
		    pca->action > PF_CHANGE_REMOVE) {
			error = EINVAL;
			break;
		}
		if (pca->addr.addr.type != PF_ADDR_ADDRMASK &&
		    pca->addr.addr.type != PF_ADDR_DYNIFTL &&
		    pca->addr.addr.type != PF_ADDR_TABLE) {
			error = EINVAL;
			break;
		}

		pca->anchor[sizeof (pca->anchor) - 1] = '\0';
		ruleset = pf_find_ruleset(pca->anchor);
		if (ruleset == NULL) {
			error = EBUSY;
			break;
		}
		pool = pf_get_pool(pca->anchor, pca->ticket, pca->r_action,
		    pca->r_num, pca->r_last, 1, 1);
		if (pool == NULL) {
			error = EBUSY;
			break;
		}
		if (pca->action != PF_CHANGE_REMOVE) {
			newpa = pool_get(&pf_pooladdr_pl, PR_WAITOK);
			if (newpa == NULL) {
				error = ENOMEM;
				break;
			}
			pf_pooladdr_copyin(&pca->addr, newpa);
#if !INET
			if (pca->af == AF_INET) {
				pool_put(&pf_pooladdr_pl, newpa);
				error = EAFNOSUPPORT;
				break;
			}
#endif /* INET */
#if !INET6
			if (pca->af == AF_INET6) {
				pool_put(&pf_pooladdr_pl, newpa);
				error = EAFNOSUPPORT;
				break;
			}
#endif /* INET6 */
			if (newpa->ifname[0]) {
				newpa->kif = pfi_kif_get(newpa->ifname);
				if (newpa->kif == NULL) {
					pool_put(&pf_pooladdr_pl, newpa);
					error = EINVAL;
					break;
				}
				pfi_kif_ref(newpa->kif, PFI_KIF_REF_RULE);
			} else
				newpa->kif = NULL;
			pf_addrwrap_setup(&newpa->addr);
			if (pfi_dynaddr_setup(&newpa->addr, pca->af) ||
			    pf_tbladdr_setup(ruleset, &newpa->addr)) {
				pfi_dynaddr_remove(&newpa->addr);
				pfi_kif_unref(newpa->kif, PFI_KIF_REF_RULE);
				pool_put(&pf_pooladdr_pl, newpa);
				error = EINVAL;
				break;
			}
		}

		if (pca->action == PF_CHANGE_ADD_HEAD)
			oldpa = TAILQ_FIRST(&pool->list);
		else if (pca->action == PF_CHANGE_ADD_TAIL)
			oldpa = TAILQ_LAST(&pool->list, pf_palist);
		else {
			int	i = 0;

			oldpa = TAILQ_FIRST(&pool->list);
			while ((oldpa != NULL) && (i < (int)pca->nr)) {
				oldpa = TAILQ_NEXT(oldpa, entries);
				i++;
			}
			if (oldpa == NULL) {
				error = EINVAL;
				break;
			}
		}

		if (pca->action == PF_CHANGE_REMOVE) {
			TAILQ_REMOVE(&pool->list, oldpa, entries);
			pfi_dynaddr_remove(&oldpa->addr);
			pf_tbladdr_remove(&oldpa->addr);
			pfi_kif_unref(oldpa->kif, PFI_KIF_REF_RULE);
			pool_put(&pf_pooladdr_pl, oldpa);
		} else {
			if (oldpa == NULL)
				TAILQ_INSERT_TAIL(&pool->list, newpa, entries);
			else if (pca->action == PF_CHANGE_ADD_HEAD ||
			    pca->action == PF_CHANGE_ADD_BEFORE)
				TAILQ_INSERT_BEFORE(oldpa, newpa, entries);
			else
				TAILQ_INSERT_AFTER(&pool->list, oldpa,
				    newpa, entries);
		}

		pool->cur = TAILQ_FIRST(&pool->list);
		PF_ACPY(&pool->counter, &pool->cur->addr.v.a.addr,
		    pca->af);
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

static int
pfioctl_ioc_ruleset(u_long cmd, struct pfioc_ruleset *pr, struct proc *p)
{
#pragma unused(p)
	int error = 0;

	switch (cmd) {
	case DIOCGETRULESETS: {
		struct pf_ruleset	*ruleset;
		struct pf_anchor	*anchor;

		pr->path[sizeof (pr->path) - 1] = '\0';
		pr->name[sizeof (pr->name) - 1] = '\0';
		if ((ruleset = pf_find_ruleset(pr->path)) == NULL) {
			error = EINVAL;
			break;
		}
		pr->nr = 0;
		if (ruleset->anchor == NULL) {
			/* XXX kludge for pf_main_ruleset */
			RB_FOREACH(anchor, pf_anchor_global, &pf_anchors)
				if (anchor->parent == NULL)
					pr->nr++;
		} else {
			RB_FOREACH(anchor, pf_anchor_node,
			    &ruleset->anchor->children)
				pr->nr++;
		}
		break;
	}

	case DIOCGETRULESET: {
		struct pf_ruleset	*ruleset;
		struct pf_anchor	*anchor;
		u_int32_t		 nr = 0;

		pr->path[sizeof (pr->path) - 1] = '\0';
		if ((ruleset = pf_find_ruleset(pr->path)) == NULL) {
			error = EINVAL;
			break;
		}
		pr->name[0] = 0;
		if (ruleset->anchor == NULL) {
			/* XXX kludge for pf_main_ruleset */
			RB_FOREACH(anchor, pf_anchor_global, &pf_anchors)
				if (anchor->parent == NULL && nr++ == pr->nr) {
					strlcpy(pr->name, anchor->name,
					    sizeof (pr->name));
					break;
				}
		} else {
			RB_FOREACH(anchor, pf_anchor_node,
			    &ruleset->anchor->children)
				if (nr++ == pr->nr) {
					strlcpy(pr->name, anchor->name,
					    sizeof (pr->name));
					break;
				}
		}
		if (!pr->name[0])
			error = EBUSY;
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

static int
pfioctl_ioc_trans(u_long cmd, struct pfioc_trans_32 *io32,
    struct pfioc_trans_64 *io64, struct proc *p)
{
	int p64 = proc_is64bit(p);
	int error = 0, esize, size;
	user_addr_t buf;

	esize = (p64 ? io64->esize : io32->esize);
	size = (p64 ? io64->size : io32->size);
	buf = (p64 ? io64->array : io32->array);

	switch (cmd) {
	case DIOCXBEGIN: {
		struct pfioc_trans_e	*ioe;
		struct pfr_table	*table;
		int			 i;

		if (esize != sizeof (*ioe)) {
			error = ENODEV;
			goto fail;
		}
		ioe = _MALLOC(sizeof (*ioe), M_TEMP, M_WAITOK);
		table = _MALLOC(sizeof (*table), M_TEMP, M_WAITOK);
		for (i = 0; i < size; i++, buf += sizeof (*ioe)) {
			if (copyin(buf, ioe, sizeof (*ioe))) {
				_FREE(table, M_TEMP);
				_FREE(ioe, M_TEMP);
				error = EFAULT;
				goto fail;
			}
			ioe->anchor[sizeof (ioe->anchor) - 1] = '\0';
			switch (ioe->rs_num) {
			case PF_RULESET_ALTQ:
				break;
			case PF_RULESET_TABLE:
				bzero(table, sizeof (*table));
				strlcpy(table->pfrt_anchor, ioe->anchor,
				    sizeof (table->pfrt_anchor));
				if ((error = pfr_ina_begin(table,
				    &ioe->ticket, NULL, 0))) {
					_FREE(table, M_TEMP);
					_FREE(ioe, M_TEMP);
					goto fail;
				}
				break;
			default:
				if ((error = pf_begin_rules(&ioe->ticket,
				    ioe->rs_num, ioe->anchor))) {
					_FREE(table, M_TEMP);
					_FREE(ioe, M_TEMP);
					goto fail;
				}
				break;
			}
			if (copyout(ioe, buf, sizeof (*ioe))) {
				_FREE(table, M_TEMP);
				_FREE(ioe, M_TEMP);
				error = EFAULT;
				goto fail;
			}
		}
		_FREE(table, M_TEMP);
		_FREE(ioe, M_TEMP);
		break;
	}

	case DIOCXROLLBACK: {
		struct pfioc_trans_e	*ioe;
		struct pfr_table	*table;
		int			 i;

		if (esize != sizeof (*ioe)) {
			error = ENODEV;
			goto fail;
		}
		ioe = _MALLOC(sizeof (*ioe), M_TEMP, M_WAITOK);
		table = _MALLOC(sizeof (*table), M_TEMP, M_WAITOK);
		for (i = 0; i < size; i++, buf += sizeof (*ioe)) {
			if (copyin(buf, ioe, sizeof (*ioe))) {
				_FREE(table, M_TEMP);
				_FREE(ioe, M_TEMP);
				error = EFAULT;
				goto fail;
			}
			ioe->anchor[sizeof (ioe->anchor) - 1] = '\0';
			switch (ioe->rs_num) {
			case PF_RULESET_ALTQ:
				break;
			case PF_RULESET_TABLE:
				bzero(table, sizeof (*table));
				strlcpy(table->pfrt_anchor, ioe->anchor,
				    sizeof (table->pfrt_anchor));
				if ((error = pfr_ina_rollback(table,
				    ioe->ticket, NULL, 0))) {
					_FREE(table, M_TEMP);
					_FREE(ioe, M_TEMP);
					goto fail; /* really bad */
				}
				break;
			default:
				if ((error = pf_rollback_rules(ioe->ticket,
				    ioe->rs_num, ioe->anchor))) {
					_FREE(table, M_TEMP);
					_FREE(ioe, M_TEMP);
					goto fail; /* really bad */
				}
				break;
			}
		}
		_FREE(table, M_TEMP);
		_FREE(ioe, M_TEMP);
		break;
	}

	case DIOCXCOMMIT: {
		struct pfioc_trans_e	*ioe;
		struct pfr_table	*table;
		struct pf_ruleset	*rs;
		user_addr_t		 _buf = buf;
		int			 i;

		if (esize != sizeof (*ioe)) {
			error = ENODEV;
			goto fail;
		}
		ioe = _MALLOC(sizeof (*ioe), M_TEMP, M_WAITOK);
		table = _MALLOC(sizeof (*table), M_TEMP, M_WAITOK);
		/* first makes sure everything will succeed */
		for (i = 0; i < size; i++, buf += sizeof (*ioe)) {
			if (copyin(buf, ioe, sizeof (*ioe))) {
				_FREE(table, M_TEMP);
				_FREE(ioe, M_TEMP);
				error = EFAULT;
				goto fail;
			}
			ioe->anchor[sizeof (ioe->anchor) - 1] = '\0';
			switch (ioe->rs_num) {
			case PF_RULESET_ALTQ:
				break;
			case PF_RULESET_TABLE:
				rs = pf_find_ruleset(ioe->anchor);
				if (rs == NULL || !rs->topen || ioe->ticket !=
				    rs->tticket) {
					_FREE(table, M_TEMP);
					_FREE(ioe, M_TEMP);
					error = EBUSY;
					goto fail;
				}
				break;
			default:
				if (ioe->rs_num < 0 || ioe->rs_num >=
				    PF_RULESET_MAX) {
					_FREE(table, M_TEMP);
					_FREE(ioe, M_TEMP);
					error = EINVAL;
					goto fail;
				}
				rs = pf_find_ruleset(ioe->anchor);
				if (rs == NULL ||
				    !rs->rules[ioe->rs_num].inactive.open ||
				    rs->rules[ioe->rs_num].inactive.ticket !=
				    ioe->ticket) {
					_FREE(table, M_TEMP);
					_FREE(ioe, M_TEMP);
					error = EBUSY;
					goto fail;
				}
				break;
			}
		}
		buf = _buf;
		/* now do the commit - no errors should happen here */
		for (i = 0; i < size; i++, buf += sizeof (*ioe)) {
			if (copyin(buf, ioe, sizeof (*ioe))) {
				_FREE(table, M_TEMP);
				_FREE(ioe, M_TEMP);
				error = EFAULT;
				goto fail;
			}
			ioe->anchor[sizeof (ioe->anchor) - 1] = '\0';
			switch (ioe->rs_num) {
			case PF_RULESET_ALTQ:
				break;
			case PF_RULESET_TABLE:
				bzero(table, sizeof (*table));
				strlcpy(table->pfrt_anchor, ioe->anchor,
				    sizeof (table->pfrt_anchor));
				if ((error = pfr_ina_commit(table, ioe->ticket,
				    NULL, NULL, 0))) {
					_FREE(table, M_TEMP);
					_FREE(ioe, M_TEMP);
					goto fail; /* really bad */
				}
				break;
			default:
				if ((error = pf_commit_rules(ioe->ticket,
				    ioe->rs_num, ioe->anchor))) {
					_FREE(table, M_TEMP);
					_FREE(ioe, M_TEMP);
					goto fail; /* really bad */
				}
				break;
			}
		}
		_FREE(table, M_TEMP);
		_FREE(ioe, M_TEMP);
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}
fail:
	return (error);
}

static int
pfioctl_ioc_src_nodes(u_long cmd, struct pfioc_src_nodes_32 *psn32,
    struct pfioc_src_nodes_64 *psn64, struct proc *p)
{
	int p64 = proc_is64bit(p);
	int error = 0;

	switch (cmd) {
	case DIOCGETSRCNODES: {
		struct pf_src_node	*n, *pstore;
		user_addr_t		 buf;
		u_int32_t		 nr = 0;
		int			 space, size;

		space = (p64 ? psn64->psn_len : psn32->psn_len);
		if (space == 0) {
			RB_FOREACH(n, pf_src_tree, &tree_src_tracking)
				nr++;

			size = sizeof (struct pf_src_node) * nr;
			if (p64)
				psn64->psn_len = size;
			else
				psn32->psn_len = size;
			break;
		}

		pstore = _MALLOC(sizeof (*pstore), M_TEMP, M_WAITOK);
		if (pstore == NULL) {
			error = ENOMEM;
			break;
		}
		buf = (p64 ? psn64->psn_buf : psn32->psn_buf);

		RB_FOREACH(n, pf_src_tree, &tree_src_tracking) {
			uint64_t secs = pf_time_second(), diff;

			if ((nr + 1) * sizeof (*pstore) > (unsigned)space)
				break;

			bcopy(n, pstore, sizeof (*pstore));
			if (n->rule.ptr != NULL)
				pstore->rule.nr = n->rule.ptr->nr;
			pstore->creation = secs - pstore->creation;
			if (pstore->expire > secs)
				pstore->expire -= secs;
			else
				pstore->expire = 0;

			/* adjust the connection rate estimate */
			diff = secs - n->conn_rate.last;
			if (diff >= n->conn_rate.seconds)
				pstore->conn_rate.count = 0;
			else
				pstore->conn_rate.count -=
				    n->conn_rate.count * diff /
				    n->conn_rate.seconds;

			_RB_PARENT(pstore, entry) = NULL;
			RB_LEFT(pstore, entry) = RB_RIGHT(pstore, entry) = NULL;
			pstore->kif = NULL;

			error = copyout(pstore, buf, sizeof (*pstore));
			if (error) {
				_FREE(pstore, M_TEMP);
				goto fail;
			}
			buf += sizeof (*pstore);
			nr++;
		}

		size = sizeof (struct pf_src_node) * nr;
		if (p64)
			psn64->psn_len = size;
		else
			psn32->psn_len = size;

		_FREE(pstore, M_TEMP);
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}
fail:
	return (error);

}

static int
pfioctl_ioc_src_node_kill(u_long cmd, struct pfioc_src_node_kill *psnk,
    struct proc *p)
{
#pragma unused(p)
	int error = 0;

	switch (cmd) {
	case DIOCKILLSRCNODES: {
		struct pf_src_node	*sn;
		struct pf_state		*s;
		int			killed = 0;

		RB_FOREACH(sn, pf_src_tree, &tree_src_tracking) {
			if (PF_MATCHA(psnk->psnk_src.neg,
			    &psnk->psnk_src.addr.v.a.addr,
			    &psnk->psnk_src.addr.v.a.mask,
			    &sn->addr, sn->af) &&
			    PF_MATCHA(psnk->psnk_dst.neg,
			    &psnk->psnk_dst.addr.v.a.addr,
			    &psnk->psnk_dst.addr.v.a.mask,
			    &sn->raddr, sn->af)) {
				/* Handle state to src_node linkage */
				if (sn->states != 0) {
					RB_FOREACH(s, pf_state_tree_id,
					    &tree_id) {
						if (s->src_node == sn)
							s->src_node = NULL;
						if (s->nat_src_node == sn)
							s->nat_src_node = NULL;
					}
					sn->states = 0;
				}
				sn->expire = 1;
				killed++;
			}
		}

		if (killed > 0)
			pf_purge_expired_src_nodes();

		psnk->psnk_af = killed;
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

static int
pfioctl_ioc_iface(u_long cmd, struct pfioc_iface_32 *io32,
    struct pfioc_iface_64 *io64, struct proc *p)
{
	int p64 = proc_is64bit(p);
	int error = 0;

	switch (cmd) {
	case DIOCIGETIFACES: {
		user_addr_t buf;
		int esize;

		buf = (p64 ? io64->pfiio_buffer : io32->pfiio_buffer);
		esize = (p64 ? io64->pfiio_esize : io32->pfiio_esize);

		/* esize must be that of the user space version of pfi_kif */
		if (esize != sizeof (struct pfi_uif)) {
			error = ENODEV;
			break;
		}
		if (p64)
			io64->pfiio_name[sizeof (io64->pfiio_name) - 1] = '\0';
		else
			io32->pfiio_name[sizeof (io32->pfiio_name) - 1] = '\0';
		error = pfi_get_ifaces(
		    p64 ? io64->pfiio_name : io32->pfiio_name, buf,
		    p64 ? &io64->pfiio_size : &io32->pfiio_size);
		break;
	}

	case DIOCSETIFFLAG: {
		if (p64)
			io64->pfiio_name[sizeof (io64->pfiio_name) - 1] = '\0';
		else
			io32->pfiio_name[sizeof (io32->pfiio_name) - 1] = '\0';

		error = pfi_set_flags(
		    p64 ? io64->pfiio_name : io32->pfiio_name,
		    p64 ? io64->pfiio_flags : io32->pfiio_flags);
		break;
	}

	case DIOCCLRIFFLAG: {
		if (p64)
			io64->pfiio_name[sizeof (io64->pfiio_name) - 1] = '\0';
		else
			io32->pfiio_name[sizeof (io32->pfiio_name) - 1] = '\0';

		error = pfi_clear_flags(
		    p64 ? io64->pfiio_name : io32->pfiio_name,
		    p64 ? io64->pfiio_flags : io32->pfiio_flags);
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

int
pf_af_hook(struct ifnet *ifp, struct mbuf **mppn, struct mbuf **mp,
    unsigned int af, int input, struct ip_fw_args *fwa)
{
	int error = 0;
	struct mbuf *nextpkt;
	net_thread_marks_t marks;
	struct ifnet * pf_ifp = ifp;

	/* Always allow traffic on co-processor interfaces. */
	if (!intcoproc_unrestricted && ifp && IFNET_IS_INTCOPROC(ifp))
		return (0);

	marks = net_thread_marks_push(NET_THREAD_HELD_PF);

	if (marks != net_thread_marks_none) {
		lck_rw_lock_shared(pf_perim_lock);
		if (!pf_is_enabled)
			goto done;
		lck_mtx_lock(pf_lock);
	}

	if (mppn != NULL && *mppn != NULL)
		VERIFY(*mppn == *mp);
	if ((nextpkt = (*mp)->m_nextpkt) != NULL)
		(*mp)->m_nextpkt = NULL;

        /*
         * For packets destined to locally hosted IP address
         * ip_output_list sets Mbuf's pkt header's rcvif to
         * the interface hosting the IP address.
         * While on the output path ifp passed to pf_af_hook
         * to such local communication is the loopback interface,
         * the input path derives ifp from mbuf packet header's
         * rcvif.
         * This asymmetry caues issues with PF.
         * To handle that case, we have a limited change here to
         * pass interface as loopback if packets are looped in.
         */
	if (input && ((*mp)->m_pkthdr.pkt_flags & PKTF_LOOP)) {
		pf_ifp = lo_ifp;
	}

	switch (af) {
#if INET
	case AF_INET: {
		error = pf_inet_hook(pf_ifp, mp, input, fwa);
		break;
	}
#endif /* INET */
#if INET6
	case AF_INET6:
		error = pf_inet6_hook(pf_ifp, mp, input, fwa);
		break;
#endif /* INET6 */
	default:
		break;
	}

	/* When packet valid, link to the next packet */
	if (*mp != NULL && nextpkt != NULL) {
		struct mbuf *m = *mp;
		while (m->m_nextpkt != NULL)
			m = m->m_nextpkt;
		m->m_nextpkt = nextpkt;
	}
	/* Fix up linkage of previous packet in the chain */
	if (mppn != NULL) {
		if (*mp != NULL)
			*mppn = *mp;
		else
			*mppn = nextpkt;
	}

	if (marks != net_thread_marks_none)
		lck_mtx_unlock(pf_lock);

done:
	if (marks != net_thread_marks_none)
		lck_rw_done(pf_perim_lock);

	net_thread_marks_pop(marks);
	return (error);
}


#if INET
static int
pf_inet_hook(struct ifnet *ifp, struct mbuf **mp, int input,
    struct ip_fw_args *fwa)
{
	struct mbuf *m = *mp;
#if BYTE_ORDER != BIG_ENDIAN
	struct ip *ip = mtod(m, struct ip *);
#endif
	int error = 0;

	/*
	 * If the packet is outbound, is originated locally, is flagged for
	 * delayed UDP/TCP checksum calculation, and is about to be processed
	 * for an interface that doesn't support the appropriate checksum
	 * offloading, then calculated the checksum here so that PF can adjust
	 * it properly.
	 */
	if (!input && m->m_pkthdr.rcvif == NULL) {
		static const int mask = CSUM_DELAY_DATA;
		const int flags = m->m_pkthdr.csum_flags &
		    ~IF_HWASSIST_CSUM_FLAGS(ifp->if_hwassist);

		if (flags & mask) {
			in_delayed_cksum(m);
			m->m_pkthdr.csum_flags &= ~mask;
		}
	}

#if BYTE_ORDER != BIG_ENDIAN
	HTONS(ip->ip_len);
	HTONS(ip->ip_off);
#endif
	if (pf_test_mbuf(input ? PF_IN : PF_OUT, ifp, mp, NULL, fwa) != PF_PASS) {
		if (*mp != NULL) {
			m_freem(*mp);
			*mp = NULL;
			error = EHOSTUNREACH;
		} else {
			error = ENOBUFS;
		}
	}
#if BYTE_ORDER != BIG_ENDIAN
	else {
		if (*mp != NULL) {
			ip = mtod(*mp, struct ip *);
			NTOHS(ip->ip_len);
			NTOHS(ip->ip_off);
		}
	}
#endif
	return (error);
}
#endif /* INET */

#if INET6
int
pf_inet6_hook(struct ifnet *ifp, struct mbuf **mp, int input,
    struct ip_fw_args *fwa)
{
	int error = 0;

	/*
	 * If the packet is outbound, is originated locally, is flagged for
	 * delayed UDP/TCP checksum calculation, and is about to be processed
	 * for an interface that doesn't support the appropriate checksum
	 * offloading, then calculated the checksum here so that PF can adjust
	 * it properly.
	 */
	if (!input && (*mp)->m_pkthdr.rcvif == NULL) {
		static const int mask = CSUM_DELAY_IPV6_DATA;
		const int flags = (*mp)->m_pkthdr.csum_flags &
		    ~IF_HWASSIST_CSUM_FLAGS(ifp->if_hwassist);

		if (flags & mask) {
			/*
			 * Checksum offload should not have been enabled
			 * when extension headers exist, thus 0 for optlen.
			 */
			in6_delayed_cksum(*mp);
			(*mp)->m_pkthdr.csum_flags &= ~mask;
		}
	}

	if (pf_test6_mbuf(input ? PF_IN : PF_OUT, ifp, mp, NULL, fwa) != PF_PASS) {
		if (*mp != NULL) {
			m_freem(*mp);
			*mp = NULL;
			error = EHOSTUNREACH;
		} else {
			error = ENOBUFS;
		}
	}
	return (error);
}
#endif /* INET6 */

int
pf_ifaddr_hook(struct ifnet *ifp)
{
	struct pfi_kif *kif = ifp->if_pf_kif;

	if (kif != NULL) {
		lck_rw_lock_shared(pf_perim_lock);
		lck_mtx_lock(pf_lock);

		pfi_kifaddr_update(kif);

		lck_mtx_unlock(pf_lock);
		lck_rw_done(pf_perim_lock);
	}
	return (0);
}

/*
 * Caller acquires dlil lock as writer (exclusive)
 */
void
pf_ifnet_hook(struct ifnet *ifp, int attach)
{
	lck_rw_lock_shared(pf_perim_lock);
	lck_mtx_lock(pf_lock);
	if (attach)
		pfi_attach_ifnet(ifp);
	else
		pfi_detach_ifnet(ifp);
	lck_mtx_unlock(pf_lock);
	lck_rw_done(pf_perim_lock);
}

static void
pf_attach_hooks(void)
{
	ifnet_head_lock_shared();
	/*
	 * Check against ifnet_addrs[] before proceeding, in case this
	 * is called very early on, e.g. during dlil_init() before any
	 * network interface is attached.
	 */
	if (ifnet_addrs != NULL) {
		int i;

		for (i = 0; i <= if_index; i++) {
			struct ifnet *ifp = ifindex2ifnet[i];
			if (ifp != NULL) {
				pfi_attach_ifnet(ifp);
			}
		}
	}
	ifnet_head_done();
}

#if 0
/* currently unused along with pfdetach() */
static void
pf_detach_hooks(void)
{
	ifnet_head_lock_shared();
	if (ifnet_addrs != NULL) {
		for (i = 0; i <= if_index; i++) {
			int i;

			struct ifnet *ifp = ifindex2ifnet[i];
			if (ifp != NULL && ifp->if_pf_kif != NULL) {
				pfi_detach_ifnet(ifp);
			}
		}
	}
	ifnet_head_done();
}
#endif

/*
 * 'D' group ioctls.
 *
 * The switch statement below does nothing at runtime, as it serves as a
 * compile time check to ensure that all of the socket 'D' ioctls (those
 * in the 'D' group going thru soo_ioctl) that are made available by the
 * networking stack is unique.  This works as long as this routine gets
 * updated each time a new interface ioctl gets added.
 *
 * Any failures at compile time indicates duplicated ioctl values.
 */
static __attribute__((unused)) void
pfioctl_cassert(void)
{
	/*
	 * This is equivalent to _CASSERT() and the compiler wouldn't
	 * generate any instructions, thus for compile time only.
	 */
	switch ((u_long)0) {
	case 0:

	/* bsd/net/pfvar.h */
	case DIOCSTART:
	case DIOCSTOP:
	case DIOCADDRULE:
	case DIOCGETSTARTERS:
	case DIOCGETRULES:
	case DIOCGETRULE:
	case DIOCSTARTREF:
	case DIOCSTOPREF:
	case DIOCCLRSTATES:
	case DIOCGETSTATE:
	case DIOCSETSTATUSIF:
	case DIOCGETSTATUS:
	case DIOCCLRSTATUS:
	case DIOCNATLOOK:
	case DIOCSETDEBUG:
	case DIOCGETSTATES:
	case DIOCCHANGERULE:
	case DIOCINSERTRULE:
	case DIOCDELETERULE:
	case DIOCSETTIMEOUT:
	case DIOCGETTIMEOUT:
	case DIOCADDSTATE:
	case DIOCCLRRULECTRS:
	case DIOCGETLIMIT:
	case DIOCSETLIMIT:
	case DIOCKILLSTATES:
	case DIOCSTARTALTQ:
	case DIOCSTOPALTQ:
	case DIOCADDALTQ:
	case DIOCGETALTQS:
	case DIOCGETALTQ:
	case DIOCCHANGEALTQ:
	case DIOCGETQSTATS:
	case DIOCBEGINADDRS:
	case DIOCADDADDR:
	case DIOCGETADDRS:
	case DIOCGETADDR:
	case DIOCCHANGEADDR:
	case DIOCGETRULESETS:
	case DIOCGETRULESET:
	case DIOCRCLRTABLES:
	case DIOCRADDTABLES:
	case DIOCRDELTABLES:
	case DIOCRGETTABLES:
	case DIOCRGETTSTATS:
	case DIOCRCLRTSTATS:
	case DIOCRCLRADDRS:
	case DIOCRADDADDRS:
	case DIOCRDELADDRS:
	case DIOCRSETADDRS:
	case DIOCRGETADDRS:
	case DIOCRGETASTATS:
	case DIOCRCLRASTATS:
	case DIOCRTSTADDRS:
	case DIOCRSETTFLAGS:
	case DIOCRINADEFINE:
	case DIOCOSFPFLUSH:
	case DIOCOSFPADD:
	case DIOCOSFPGET:
	case DIOCXBEGIN:
	case DIOCXCOMMIT:
	case DIOCXROLLBACK:
	case DIOCGETSRCNODES:
	case DIOCCLRSRCNODES:
	case DIOCSETHOSTID:
	case DIOCIGETIFACES:
	case DIOCSETIFFLAG:
	case DIOCCLRIFFLAG:
	case DIOCKILLSRCNODES:
	case DIOCGIFSPEED:
		;
	}
}
