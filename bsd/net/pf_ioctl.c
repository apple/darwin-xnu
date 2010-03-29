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

/*	$apfw: pf_ioctl.c,v 1.16 2008/08/27 00:01:32 jhw Exp $ */
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

#include <mach/vm_param.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>

#include <libkern/crypto/md5.h>

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

#if ALTQ
#include <altq/altq.h>
#endif /* ALTQ */

#if 0
static void pfdetach(void);
#endif
static int pfopen(dev_t, int, int, struct proc *);
static int pfclose(dev_t, int, int, struct proc *);
static int pfioctl(dev_t, u_long, caddr_t, int, struct proc *);
static struct pf_pool *pf_get_pool(char *, u_int32_t, u_int8_t, u_int32_t,
    u_int8_t, u_int8_t, u_int8_t);

static void pf_mv_pool(struct pf_palist *, struct pf_palist *);
static void pf_empty_pool(struct pf_palist *);
#if ALTQ
static int pf_begin_altq(u_int32_t *);
static int pf_rollback_altq(u_int32_t);
static int pf_commit_altq(u_int32_t);
static int pf_enable_altq(struct pf_altq *);
static int pf_disable_altq(struct pf_altq *);
#endif /* ALTQ */
static int pf_begin_rules(u_int32_t *, int, const char *);
static int pf_rollback_rules(u_int32_t, int, char *);
static int pf_setup_pfsync_matching(struct pf_ruleset *);
static void pf_hash_rule(MD5_CTX *, struct pf_rule *);
#ifndef NO_APPLE_EXTENSIONS
static void pf_hash_rule_addr(MD5_CTX *, struct pf_rule_addr *, u_int8_t);
#else
static void pf_hash_rule_addr(MD5_CTX *, struct pf_rule_addr *);
#endif
static int pf_commit_rules(u_int32_t, int, char *);
static void pf_state_export(struct pfsync_state *, struct pf_state_key *,
    struct pf_state *);
static void pf_state_import(struct pfsync_state *, struct pf_state_key *,
    struct pf_state *);

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
static void pf_detach_hooks(void);
static int pf_hooks_attached = 0;

struct pf_rule		 pf_default_rule;
#if ALTQ
static int		 pf_altq_running;
#endif /* ALTQ */

#define	TAGID_MAX	 50000
static TAILQ_HEAD(pf_tags, pf_tagname)	pf_tags =
    TAILQ_HEAD_INITIALIZER(pf_tags);
#if ALTQ
static TAILQ_HEAD(pf_tags, pf_tagname)	pf_qids =
    TAILQ_HEAD_INITIALIZER(pf_qids);
#endif /* ALTQ */

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
static int pf_inet_hook(struct ifnet *, struct mbuf **, int);
#endif /* INET */
#if INET6
static int pf_inet6_hook(struct ifnet *, struct mbuf **, int);
#endif /* INET6 */

#define DPFPRINTF(n, x) if (pf_status.debug >= (n)) printf x

static lck_attr_t *pf_perim_lock_attr;
static lck_grp_t *pf_perim_lock_grp;
static lck_grp_attr_t *pf_perim_lock_grp_attr;

static lck_attr_t *pf_lock_attr;
static lck_grp_t *pf_lock_grp;
static lck_grp_attr_t *pf_lock_grp_attr;

struct thread *pf_purge_thread;

extern void pfi_kifaddr_update(void *);

void
pfinit(void)
{
	u_int32_t *t = pf_default_rule.timeout;
	int maj;

	pf_perim_lock_grp_attr = lck_grp_attr_alloc_init();
	pf_perim_lock_grp = lck_grp_alloc_init("pf_perim",
	    pf_perim_lock_grp_attr);
	pf_perim_lock_attr = lck_attr_alloc_init();
	pf_perim_lock = lck_rw_alloc_init(pf_perim_lock_grp,
	    pf_perim_lock_attr);

	pf_lock_grp_attr = lck_grp_attr_alloc_init();
	pf_lock_grp = lck_grp_alloc_init("pf", pf_lock_grp_attr);
	pf_lock_attr = lck_attr_alloc_init();
	pf_lock = lck_mtx_alloc_init(pf_lock_grp, pf_lock_attr);

	pool_init(&pf_rule_pl, sizeof (struct pf_rule), 0, 0, 0, "pfrulepl",
	    NULL);
	pool_init(&pf_src_tree_pl, sizeof (struct pf_src_node), 0, 0, 0,
	    "pfsrctrpl", NULL);
	pool_init(&pf_state_pl, sizeof (struct pf_state), 0, 0, 0, "pfstatepl",
	    NULL);
	pool_init(&pf_state_key_pl, sizeof (struct pf_state_key), 0, 0, 0,
	    "pfstatekeypl", NULL);
#ifndef NO_APPLE_EXTENSIONS
	pool_init(&pf_app_state_pl, sizeof (struct pf_app_state), 0, 0, 0,
	    "pfappstatepl", NULL);
#endif
#if ALTQ
	pool_init(&pf_altq_pl, sizeof (struct pf_altq), 0, 0, 0, "pfaltqpl",
	    NULL);
#endif /* ALTQ */
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
#if ALTQ
	TAILQ_INIT(&pf_altqs[0]);
	TAILQ_INIT(&pf_altqs[1]);
	pf_altqs_active = &pf_altqs[0];
	pf_altqs_inactive = &pf_altqs[1];
#endif /* ALTQ */

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
#ifndef NO_APPLE_EXTENSIONS
	t[PFTM_GREv1_FIRST_PACKET] = PFTM_GREv1_FIRST_PACKET_VAL;
	t[PFTM_GREv1_INITIATING] = PFTM_GREv1_INITIATING_VAL;
	t[PFTM_GREv1_ESTABLISHED] = PFTM_GREv1_ESTABLISHED_VAL;
	t[PFTM_ESP_FIRST_PACKET] = PFTM_ESP_FIRST_PACKET_VAL;
	t[PFTM_ESP_INITIATING] = PFTM_ESP_INITIATING_VAL;
	t[PFTM_ESP_ESTABLISHED] = PFTM_ESP_ESTABLISHED_VAL;
#endif
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
	(void) devfs_make_node(makedev(maj, 0), DEVFS_CHAR,
	    UID_ROOT, GID_WHEEL, 0600, "pf", 0);
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

	pf_status.running = 0;
	wakeup(pf_purge_thread_fn);

	/* clear the rulesets */
	for (i = 0; i < PF_RULESET_MAX; i++)
		if (pf_begin_rules(&ticket, i, &r) == 0)
				pf_commit_rules(ticket, i, &r);
#if ALTQ
	if (pf_begin_altq(&ticket) == 0)
		pf_commit_altq(ticket);
#endif /* ALTQ */

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
#if ALTQ
	pool_destroy(&pf_altq_pl);
#endif /* ALTQ */
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
	if (minor(dev) >= 1)
		return (ENXIO);
	return (0);
}

static int
pfclose(dev_t dev, int flags, int fmt, struct proc *p)
{
#pragma unused(flags, fmt, p)
	if (minor(dev) >= 1)
		return (ENXIO);
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
#if ALTQ
	if (rule->pqid != rule->qid)
		pf_qid_unref(rule->pqid);
	pf_qid_unref(rule->qid);
#endif /* ALTQ */
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

#if ALTQ
u_int32_t
pf_qname2qid(char *qname)
{
	return ((u_int32_t)tagname2tag(&pf_qids, qname));
}

void
pf_qid2qname(u_int32_t qid, char *p)
{
	tag2tagname(&pf_qids, (u_int16_t)qid, p);
}

void
pf_qid_unref(u_int32_t qid)
{
	tag_unref(&pf_qids, (u_int16_t)qid);
}

static int
pf_begin_altq(u_int32_t *ticket)
{
	struct pf_altq	*altq;
	int		 error = 0;

	/* Purge the old altq list */
	while ((altq = TAILQ_FIRST(pf_altqs_inactive)) != NULL) {
		TAILQ_REMOVE(pf_altqs_inactive, altq, entries);
		if (altq->qname[0] == 0) {
			/* detach and destroy the discipline */
			error = altq_remove(altq);
		} else
			pf_qid_unref(altq->qid);
		pool_put(&pf_altq_pl, altq);
	}
	if (error)
		return (error);
	*ticket = ++ticket_altqs_inactive;
	altqs_inactive_open = 1;
	return (0);
}

static int
pf_rollback_altq(u_int32_t ticket)
{
	struct pf_altq	*altq;
	int		 error = 0;

	if (!altqs_inactive_open || ticket != ticket_altqs_inactive)
		return (0);
	/* Purge the old altq list */
	while ((altq = TAILQ_FIRST(pf_altqs_inactive)) != NULL) {
		TAILQ_REMOVE(pf_altqs_inactive, altq, entries);
		if (altq->qname[0] == 0) {
			/* detach and destroy the discipline */
			error = altq_remove(altq);
		} else
			pf_qid_unref(altq->qid);
		pool_put(&pf_altq_pl, altq);
	}
	altqs_inactive_open = 0;
	return (error);
}

static int
pf_commit_altq(u_int32_t ticket)
{
	struct pf_altqqueue	*old_altqs;
	struct pf_altq		*altq;
	int			 s, err, error = 0;

	if (!altqs_inactive_open || ticket != ticket_altqs_inactive)
		return (EBUSY);

	/* swap altqs, keep the old. */
	s = splnet();
	old_altqs = pf_altqs_active;
	pf_altqs_active = pf_altqs_inactive;
	pf_altqs_inactive = old_altqs;
	ticket_altqs_active = ticket_altqs_inactive;

	/* Attach new disciplines */
	TAILQ_FOREACH(altq, pf_altqs_active, entries) {
		if (altq->qname[0] == 0) {
			/* attach the discipline */
			error = altq_pfattach(altq);
			if (error == 0 && pf_altq_running)
				error = pf_enable_altq(altq);
			if (error != 0) {
				splx(s);
				return (error);
			}
		}
	}

	/* Purge the old altq list */
	while ((altq = TAILQ_FIRST(pf_altqs_inactive)) != NULL) {
		TAILQ_REMOVE(pf_altqs_inactive, altq, entries);
		if (altq->qname[0] == 0) {
			/* detach and destroy the discipline */
			if (pf_altq_running)
				error = pf_disable_altq(altq);
			err = altq_pfdetach(altq);
			if (err != 0 && error == 0)
				error = err;
			err = altq_remove(altq);
			if (err != 0 && error == 0)
				error = err;
		} else
			pf_qid_unref(altq->qid);
		pool_put(&pf_altq_pl, altq);
	}
	splx(s);

	altqs_inactive_open = 0;
	return (error);
}

static int
pf_enable_altq(struct pf_altq *altq)
{
	struct ifnet		*ifp;
	struct tb_profile	 tb;
	int			 s, error = 0;

	if ((ifp = ifunit(altq->ifname)) == NULL)
		return (EINVAL);

	if (ifp->if_snd.altq_type != ALTQT_NONE)
		error = altq_enable(&ifp->if_snd);

	/* set tokenbucket regulator */
	if (error == 0 && ifp != NULL && ALTQ_IS_ENABLED(&ifp->if_snd)) {
		tb.rate = altq->ifbandwidth;
		tb.depth = altq->tbrsize;
		s = splnet();
		error = tbr_set(&ifp->if_snd, &tb);
		splx(s);
	}

	return (error);
}

static int
pf_disable_altq(struct pf_altq *altq)
{
	struct ifnet		*ifp;
	struct tb_profile	 tb;
	int			 s, error;

	if ((ifp = ifunit(altq->ifname)) == NULL)
		return (EINVAL);

	/*
	 * when the discipline is no longer referenced, it was overridden
	 * by a new one.  if so, just return.
	 */
	if (altq->altq_disc != ifp->if_snd.altq_disc)
		return (0);

	error = altq_disable(&ifp->if_snd);

	if (error == 0) {
		/* clear tokenbucket regulator */
		tb.rate = 0;
		s = splnet();
		error = tbr_set(&ifp->if_snd, &tb);
		splx(s);
	}

	return (error);
}
#endif /* ALTQ */

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

#define PF_MD5_UPD(st, elm)						\
	MD5Update(ctx, (u_int8_t *)&(st)->elm, sizeof ((st)->elm))

#define PF_MD5_UPD_STR(st, elm)						\
	MD5Update(ctx, (u_int8_t *)(st)->elm, strlen((st)->elm))

#define PF_MD5_UPD_HTONL(st, elm, stor) do {				\
	(stor) = htonl((st)->elm);					\
	MD5Update(ctx, (u_int8_t *)&(stor), sizeof (u_int32_t));	\
} while (0)

#define PF_MD5_UPD_HTONS(st, elm, stor) do {				\
	(stor) = htons((st)->elm);					\
	MD5Update(ctx, (u_int8_t *)&(stor), sizeof (u_int16_t));	\
} while (0)

#ifndef NO_APPLE_EXTENSIONS
static void
pf_hash_rule_addr(MD5_CTX *ctx, struct pf_rule_addr *pfr, u_int8_t proto)
#else
static void
pf_hash_rule_addr(MD5_CTX *ctx, struct pf_rule_addr *pfr)
#endif
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

#ifndef NO_APPLE_EXTENSIONS
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
#else
	PF_MD5_UPD(pfr, port[0]);
	PF_MD5_UPD(pfr, port[1]);
	PF_MD5_UPD(pfr, neg);
	PF_MD5_UPD(pfr, port_op);
#endif
}

static void
pf_hash_rule(MD5_CTX *ctx, struct pf_rule *rule)
{
	u_int16_t x;
	u_int32_t y;

#ifndef NO_APPLE_EXTENSIONS
	pf_hash_rule_addr(ctx, &rule->src, rule->proto);
	pf_hash_rule_addr(ctx, &rule->dst, rule->proto);
#else
	pf_hash_rule_addr(ctx, &rule->src);
	pf_hash_rule_addr(ctx, &rule->dst);
#endif
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
	struct pf_rule		*rule, **old_array;
	struct pf_rulequeue	*old_rules;
	int			 error;
	u_int32_t		 old_rcount;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

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
pf_state_export(struct pfsync_state *sp, struct pf_state_key *sk,
    struct pf_state *s)
{
	uint64_t secs = pf_time_second();
	bzero(sp, sizeof (struct pfsync_state));

	/* copy from state key */
#ifndef NO_APPLE_EXTENSIONS
	sp->lan.addr = sk->lan.addr;
	sp->lan.xport = sk->lan.xport;
	sp->gwy.addr = sk->gwy.addr;
	sp->gwy.xport = sk->gwy.xport;
	sp->ext.addr = sk->ext.addr;
	sp->ext.xport = sk->ext.xport;
	sp->proto_variant = sk->proto_variant;
	sp->tag = s->tag;
#else
	sp->lan.addr = sk->lan.addr;
	sp->lan.port = sk->lan.port;
	sp->gwy.addr = sk->gwy.addr;
	sp->gwy.port = sk->gwy.port;
	sp->ext.addr = sk->ext.addr;
	sp->ext.port = sk->ext.port;
#endif
	sp->proto = sk->proto;
	sp->af = sk->af;
	sp->direction = sk->direction;

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
#ifndef NO_APPLE_EXTENSIONS
	sk->lan.addr = sp->lan.addr;
	sk->lan.xport = sp->lan.xport;
	sk->gwy.addr = sp->gwy.addr;
	sk->gwy.xport = sp->gwy.xport;
	sk->ext.addr = sp->ext.addr;
	sk->ext.xport = sp->ext.xport;
	sk->proto_variant = sp->proto_variant;
	s->tag = sp->tag;
#else
	sk->lan.addr = sp->lan.addr;
	sk->lan.port = sp->lan.port;
	sk->gwy.addr = sp->gwy.addr;
	sk->gwy.port = sp->gwy.port;
	sk->ext.addr = sp->ext.addr;
	sk->ext.port = sp->ext.port;
#endif
	sk->proto = sp->proto;
	sk->af = sp->af;
	sk->direction = sp->direction;

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

static int
pfioctl(dev_t dev, u_long cmd, caddr_t addr, int flags, struct proc *p)
{
#pragma unused(dev)
	struct pf_pooladdr	*pa = NULL;
	struct pf_pool		*pool = NULL;
	int			 error = 0;

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
		case DIOCSETIFFLAG:
		case DIOCCLRIFFLAG:
			break;
		case DIOCRCLRTABLES:
		case DIOCRADDTABLES:
		case DIOCRDELTABLES:
		case DIOCRSETTFLAGS:
			if (((struct pfioc_table *)addr)->pfrio_flags &
			    PFR_FLAG_DUMMY)
				break; /* dummy operation ok */
			return (EPERM);
		default:
			return (EPERM);
		}

	if (!(flags & FWRITE))
		switch (cmd) {
		case DIOCSTART:
		case DIOCSTOP:
		case DIOCGETRULES:
		case DIOCGETADDRS:
		case DIOCGETADDR:
		case DIOCGETSTATE:
		case DIOCGETSTATUS:
		case DIOCGETSTATES:
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
			break;
		case DIOCRCLRTABLES:
		case DIOCRADDTABLES:
		case DIOCRDELTABLES:
		case DIOCRCLRTSTATS:
		case DIOCRCLRADDRS:
		case DIOCRADDADDRS:
		case DIOCRDELADDRS:
		case DIOCRSETADDRS:
		case DIOCRSETTFLAGS:
			if (((struct pfioc_table *)addr)->pfrio_flags &
			    PFR_FLAG_DUMMY) {
				flags |= FWRITE; /* need write lock for dummy */
				break; /* dummy operation ok */
			}
			return (EACCES);
		case DIOCGETRULE:
			if (((struct pfioc_rule *)addr)->action ==
			    PF_GET_CLR_CNTR)
				return (EACCES);
			break;
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
			error = EEXIST;
		} else if (pf_purge_thread == NULL) {
			error = ENOMEM;
		} else {
			pf_status.running = 1;
			pf_status.since = pf_calendar_time_second();
			if (pf_status.stateid == 0) {
				pf_status.stateid = pf_time_second();
				pf_status.stateid = pf_status.stateid << 32;
			}
			mbuf_growth_aggressive();
			pf_attach_hooks();
			wakeup(pf_purge_thread_fn);
			DPFPRINTF(PF_DEBUG_MISC, ("pf: started\n"));
		}
		break;

	case DIOCSTOP:
		if (!pf_status.running) {
			error = ENOENT;
		} else {
			mbuf_growth_normal();
			pf_detach_hooks();
			pf_status.running = 0;
			pf_status.since = pf_calendar_time_second();
			wakeup(pf_purge_thread_fn);
			DPFPRINTF(PF_DEBUG_MISC, ("pf: stopped\n"));
		}
		break;

	case DIOCADDRULE: {
		struct pfioc_rule	*pr = (struct pfioc_rule *)addr;
		struct pf_ruleset	*ruleset;
		struct pf_rule		*rule, *tail;
		struct pf_pooladdr	*apa;
		int			 rs_num;

		pr->anchor[sizeof (pr->anchor) - 1] = 0;
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
		bcopy(&pr->rule, rule, sizeof (struct pf_rule));
		rule->cuid = kauth_cred_getuid(p->p_ucred);
		rule->cpid = p->p_pid;
		rule->anchor = NULL;
		rule->kif = NULL;
		TAILQ_INIT(&rule->rpool.list);
		/* initialize refcounting */
		rule->states = 0;
		rule->src_nodes = 0;
		rule->entries.tqe_prev = NULL;
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
		if (rule->ifname[0]) {
			rule->kif = pfi_kif_get(rule->ifname);
			if (rule->kif == NULL) {
				pool_put(&pf_rule_pl, rule);
				error = EINVAL;
				break;
			}
			pfi_kif_ref(rule->kif, PFI_KIF_REF_RULE);
		}

#if ALTQ
		/* set queue IDs */
		if (rule->qname[0] != 0) {
			if ((rule->qid = pf_qname2qid(rule->qname)) == 0)
				error = EBUSY;
			else if (rule->pqname[0] != 0) {
				if ((rule->pqid =
				    pf_qname2qid(rule->pqname)) == 0)
					error = EBUSY;
			} else
				rule->pqid = rule->qid;
		}
#endif /* ALTQ */
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
		    (rule->action == PF_BINAT)) && rule->anchor == NULL) ||
		    (rule->rt > PF_FASTROUTE)) &&
		    (TAILQ_FIRST(&rule->rpool.list) == NULL))
			error = EINVAL;

		if (error) {
			pf_rm_rule(NULL, rule);
			break;
		}
		rule->rpool.cur = TAILQ_FIRST(&rule->rpool.list);
		rule->evaluations = rule->packets[0] = rule->packets[1] =
		    rule->bytes[0] = rule->bytes[1] = 0;
		TAILQ_INSERT_TAIL(ruleset->rules[rs_num].inactive.ptr,
		    rule, entries);
		ruleset->rules[rs_num].inactive.rcount++;
		break;
	}

	case DIOCGETRULES: {
		struct pfioc_rule	*pr = (struct pfioc_rule *)addr;
		struct pf_ruleset	*ruleset;
		struct pf_rule		*tail;
		int			 rs_num;

		pr->anchor[sizeof (pr->anchor) - 1] = 0;
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
		struct pfioc_rule	*pr = (struct pfioc_rule *)addr;
		struct pf_ruleset	*ruleset;
		struct pf_rule		*rule;
		int			 rs_num, i;

		pr->anchor[sizeof (pr->anchor) - 1] = 0;
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
		bcopy(rule, &pr->rule, sizeof (struct pf_rule));
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
		struct pfioc_rule	*pcr = (struct pfioc_rule *)addr;
		struct pf_ruleset	*ruleset;
		struct pf_rule		*oldrule = NULL, *newrule = NULL;
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
			bcopy(&pcr->rule, newrule, sizeof (struct pf_rule));
			newrule->cuid = kauth_cred_getuid(p->p_ucred);
			newrule->cpid = p->p_pid;
			TAILQ_INIT(&newrule->rpool.list);
			/* initialize refcounting */
			newrule->states = 0;
			newrule->entries.tqe_prev = NULL;
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

#if ALTQ
			/* set queue IDs */
			if (newrule->qname[0] != 0) {
				if ((newrule->qid =
				    pf_qname2qid(newrule->qname)) == 0)
					error = EBUSY;
				else if (newrule->pqname[0] != 0) {
					if ((newrule->pqid =
					    pf_qname2qid(newrule->pqname)) == 0)
						error = EBUSY;
				} else
					newrule->pqid = newrule->qid;
			}
#endif /* ALTQ */
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

	case DIOCCLRSTATES: {
		struct pf_state		*s, *nexts;
		struct pfioc_state_kill *psk = (struct pfioc_state_kill *)addr;
		int			 killed = 0;

		for (s = RB_MIN(pf_state_tree_id, &tree_id); s; s = nexts) {
			nexts = RB_NEXT(pf_state_tree_id, &tree_id, s);

			if (!psk->psk_ifname[0] || strcmp(psk->psk_ifname,
			    s->kif->pfik_name) == 0) {
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
		struct pfioc_state_kill	*psk = (struct pfioc_state_kill *)addr;
		int			 killed = 0;

		for (s = RB_MIN(pf_state_tree_id, &tree_id); s;
		    s = nexts) {
			nexts = RB_NEXT(pf_state_tree_id, &tree_id, s);
			sk = s->state_key;

			if (sk->direction == PF_OUT) {
				src = &sk->lan;
				dst = &sk->ext;
			} else {
				src = &sk->ext;
				dst = &sk->lan;
			}
			if ((!psk->psk_af || sk->af == psk->psk_af) &&
			    (!psk->psk_proto || psk->psk_proto == sk->proto) &&
			    PF_MATCHA(psk->psk_src.neg,
			    &psk->psk_src.addr.v.a.addr,
			    &psk->psk_src.addr.v.a.mask,
			    &src->addr, sk->af) &&
			    PF_MATCHA(psk->psk_dst.neg,
			    &psk->psk_dst.addr.v.a.addr,
			    &psk->psk_dst.addr.v.a.mask,
			    &dst->addr, sk->af) &&
#ifndef NO_APPLE_EXTENSIONS
			    (pf_match_xport(psk->psk_proto,
			    psk->psk_proto_variant, &psk->psk_src.xport,
			    &src->xport)) &&
			    (pf_match_xport(psk->psk_proto,
			    psk->psk_proto_variant, &psk->psk_dst.xport,
			    &dst->xport)) &&
#else
			    (psk->psk_src.port_op == 0 ||
			    pf_match_port(psk->psk_src.port_op,
			    psk->psk_src.port[0], psk->psk_src.port[1],
			    src->port)) &&
			    (psk->psk_dst.port_op == 0 ||
			    pf_match_port(psk->psk_dst.port_op,
			    psk->psk_dst.port[0], psk->psk_dst.port[1],
			    dst->port)) &&
#endif
			    (!psk->psk_ifname[0] || strcmp(psk->psk_ifname,
			    s->kif->pfik_name) == 0)) {
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

	case DIOCADDSTATE: {
		struct pfioc_state	*ps = (struct pfioc_state *)addr;
		struct pfsync_state 	*sp = &ps->state;
		struct pf_state		*s;
		struct pf_state_key	*sk;
		struct pfi_kif		*kif;

		if (sp->timeout >= PFTM_MAX &&
		    sp->timeout != PFTM_UNTIL_PACKET) {
			error = EINVAL;
			break;
		}
		s = pool_get(&pf_state_pl, PR_WAITOK);
		if (s == NULL) {
			error = ENOMEM;
			break;
		}
		bzero(s, sizeof (struct pf_state));
		if ((sk = pf_alloc_state_key(s)) == NULL) {
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
#ifndef NO_APPLE_EXTENSIONS
		TAILQ_INIT(&s->unlink_hooks);
		s->state_key->app_state = 0;
#endif
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
		struct pfioc_state	*ps = (struct pfioc_state *)addr;
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

	case DIOCGETSTATES: {
		struct pfioc_states	*ps = (struct pfioc_states *)addr;
		struct pf_state		*state;
		struct pfsync_state	*y, *pstore;
		u_int32_t		 nr = 0;

		if (ps->ps_len == 0) {
			nr = pf_status.states;
			ps->ps_len = sizeof (struct pfsync_state) * nr;
			break;
		}

		pstore = _MALLOC(sizeof (*pstore), M_TEMP, M_WAITOK);

		y = ps->ps_states;

		state = TAILQ_FIRST(&state_list);
		while (state) {
			if (state->timeout != PFTM_UNLINKED) {
				if ((nr+1) * sizeof (*y) > (unsigned)ps->ps_len)
					break;

				pf_state_export(pstore,
				    state->state_key, state);
				error = copyout(pstore, CAST_USER_ADDR_T(y),
				    sizeof (*y));
				if (error) {
					_FREE(pstore, M_TEMP);
					goto fail;
				}
				y++;
				nr++;
			}
			state = TAILQ_NEXT(state, entry_list);
		}

		ps->ps_len = sizeof (struct pfsync_state) * nr;

		_FREE(pstore, M_TEMP);
		break;
	}

	case DIOCGETSTATUS: {
		struct pf_status *s = (struct pf_status *)addr;
		bcopy(&pf_status, s, sizeof (struct pf_status));
		pfi_update_status(s->ifname, s);
		break;
	}

	case DIOCSETSTATUSIF: {
		struct pfioc_if	*pi = (struct pfioc_if *)addr;

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

	case DIOCNATLOOK: {
		struct pfioc_natlook	*pnl = (struct pfioc_natlook *)addr;
		struct pf_state_key	*sk;
		struct pf_state		*state;
		struct pf_state_key_cmp	 key;
		int			 m = 0, direction = pnl->direction;

		key.af = pnl->af;
		key.proto = pnl->proto;

#ifndef NO_APPLE_EXTENSIONS
		key.proto_variant = pnl->proto_variant;
#endif

		if (!pnl->proto ||
		    PF_AZERO(&pnl->saddr, pnl->af) ||
		    PF_AZERO(&pnl->daddr, pnl->af) ||
		    ((pnl->proto == IPPROTO_TCP ||
		    pnl->proto == IPPROTO_UDP) &&
#ifndef NO_APPLE_EXTENSIONS
		    (!pnl->dxport.port || !pnl->sxport.port)))
#else
		    (!pnl->dport || !pnl->sport)))
#endif
			error = EINVAL;
		else {
			/*
			 * userland gives us source and dest of connection,
			 * reverse the lookup so we ask for what happens with
			 * the return traffic, enabling us to find it in the
			 * state tree.
			 */
			if (direction == PF_IN) {
				PF_ACPY(&key.ext.addr, &pnl->daddr, pnl->af);
#ifndef NO_APPLE_EXTENSIONS
				memcpy(&key.ext.xport, &pnl->dxport,
				    sizeof (key.ext.xport));
#else
				key.ext.port = pnl->dport;
#endif
				PF_ACPY(&key.gwy.addr, &pnl->saddr, pnl->af);
#ifndef NO_APPLE_EXTENSIONS
				memcpy(&key.gwy.xport, &pnl->sxport,
				    sizeof (key.gwy.xport));
#else
				key.gwy.port = pnl->sport;
#endif
				state = pf_find_state_all(&key, PF_IN, &m);
			} else {
				PF_ACPY(&key.lan.addr, &pnl->daddr, pnl->af);
#ifndef NO_APPLE_EXTENSIONS
				memcpy(&key.lan.xport, &pnl->dxport,
				    sizeof (key.lan.xport));
#else
				key.lan.port = pnl->dport;
#endif
				PF_ACPY(&key.ext.addr, &pnl->saddr, pnl->af);
#ifndef NO_APPLE_EXTENSIONS
				memcpy(&key.ext.xport, &pnl->sxport,
				    sizeof (key.ext.xport));
#else
				key.ext.port = pnl->sport;
#endif
				state = pf_find_state_all(&key, PF_OUT, &m);
			}
			if (m > 1)
				error = E2BIG;	/* more than one state */
			else if (state != NULL) {
				sk = state->state_key;
				if (direction == PF_IN) {
					PF_ACPY(&pnl->rsaddr, &sk->lan.addr,
					    sk->af);
#ifndef NO_APPLE_EXTENSIONS
					memcpy(&pnl->rsxport, &sk->lan.xport,
					    sizeof (pnl->rsxport));
#else
					pnl->rsport = sk->lan.port;
#endif
					PF_ACPY(&pnl->rdaddr, &pnl->daddr,
					    pnl->af);
#ifndef NO_APPLE_EXTENSIONS
					memcpy(&pnl->rdxport, &pnl->dxport,
					    sizeof (pnl->rdxport));
#else
					pnl->rdport = pnl->dport;
#endif
				} else {
					PF_ACPY(&pnl->rdaddr, &sk->gwy.addr,
					    sk->af);
#ifndef NO_APPLE_EXTENSIONS
					memcpy(&pnl->rdxport, &sk->gwy.xport,
					    sizeof (pnl->rdxport));
#else
					pnl->rdport = sk->gwy.port;
#endif
					PF_ACPY(&pnl->rsaddr, &pnl->saddr,
					    pnl->af);
#ifndef NO_APPLE_EXTENSIONS
					memcpy(&pnl->rsxport, &pnl->sxport,
					    sizeof (pnl->rsxport));
#else
					pnl->rsport = pnl->sport;
#endif
				}
			} else
				error = ENOENT;
		}
		break;
	}

	case DIOCSETTIMEOUT: {
		struct pfioc_tm	*pt = (struct pfioc_tm *)addr;
		int		 old;

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
		struct pfioc_tm	*pt = (struct pfioc_tm *)addr;

		if (pt->timeout < 0 || pt->timeout >= PFTM_MAX) {
			error = EINVAL;
			goto fail;
		}
		pt->seconds = pf_default_rule.timeout[pt->timeout];
		break;
	}

	case DIOCGETLIMIT: {
		struct pfioc_limit	*pl = (struct pfioc_limit *)addr;

		if (pl->index < 0 || pl->index >= PF_LIMIT_MAX) {
			error = EINVAL;
			goto fail;
		}
		pl->limit = pf_pool_limits[pl->index].limit;
		break;
	}

	case DIOCSETLIMIT: {
		struct pfioc_limit	*pl = (struct pfioc_limit *)addr;
		int			 old_limit;

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

	case DIOCSETDEBUG: {
		u_int32_t	*level = (u_int32_t *)addr;

		pf_status.debug = *level;
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

#if ALTQ
	case DIOCSTARTALTQ: {
		struct pf_altq		*altq;

		/* enable all altq interfaces on active list */
		TAILQ_FOREACH(altq, pf_altqs_active, entries) {
			if (altq->qname[0] == 0) {
				error = pf_enable_altq(altq);
				if (error != 0)
					break;
			}
		}
		if (error == 0)
			pf_altq_running = 1;
		DPFPRINTF(PF_DEBUG_MISC, ("altq: started\n"));
		break;
	}

	case DIOCSTOPALTQ: {
		struct pf_altq		*altq;

		/* disable all altq interfaces on active list */
		TAILQ_FOREACH(altq, pf_altqs_active, entries) {
			if (altq->qname[0] == 0) {
				error = pf_disable_altq(altq);
				if (error != 0)
					break;
			}
		}
		if (error == 0)
			pf_altq_running = 0;
		DPFPRINTF(PF_DEBUG_MISC, ("altq: stopped\n"));
		break;
	}

	case DIOCADDALTQ: {
		struct pfioc_altq	*pa = (struct pfioc_altq *)addr;
		struct pf_altq		*altq, *a;

		if (pa->ticket != ticket_altqs_inactive) {
			error = EBUSY;
			break;
		}
		altq = pool_get(&pf_altq_pl, PR_WAITOK);
		if (altq == NULL) {
			error = ENOMEM;
			break;
		}
		bcopy(&pa->altq, altq, sizeof (struct pf_altq));

		/*
		 * if this is for a queue, find the discipline and
		 * copy the necessary fields
		 */
		if (altq->qname[0] != 0) {
			if ((altq->qid = pf_qname2qid(altq->qname)) == 0) {
				error = EBUSY;
				pool_put(&pf_altq_pl, altq);
				break;
			}
			altq->altq_disc = NULL;
			TAILQ_FOREACH(a, pf_altqs_inactive, entries) {
				if (strncmp(a->ifname, altq->ifname,
				    IFNAMSIZ) == 0 && a->qname[0] == 0) {
					altq->altq_disc = a->altq_disc;
					break;
				}
			}
		}

		error = altq_add(altq);
		if (error) {
			pool_put(&pf_altq_pl, altq);
			break;
		}

		TAILQ_INSERT_TAIL(pf_altqs_inactive, altq, entries);
		bcopy(altq, &pa->altq, sizeof (struct pf_altq));
		break;
	}

	case DIOCGETALTQS: {
		struct pfioc_altq	*pa = (struct pfioc_altq *)addr;
		struct pf_altq		*altq;

		pa->nr = 0;
		TAILQ_FOREACH(altq, pf_altqs_active, entries)
			pa->nr++;
		pa->ticket = ticket_altqs_active;
		break;
	}

	case DIOCGETALTQ: {
		struct pfioc_altq	*pa = (struct pfioc_altq *)addr;
		struct pf_altq		*altq;
		u_int32_t		 nr;

		if (pa->ticket != ticket_altqs_active) {
			error = EBUSY;
			break;
		}
		nr = 0;
		altq = TAILQ_FIRST(pf_altqs_active);
		while ((altq != NULL) && (nr < pa->nr)) {
			altq = TAILQ_NEXT(altq, entries);
			nr++;
		}
		if (altq == NULL) {
			error = EBUSY;
			break;
		}
		bcopy(altq, &pa->altq, sizeof (struct pf_altq));
		break;
	}

	case DIOCCHANGEALTQ:
		/* CHANGEALTQ not supported yet! */
		error = ENODEV;
		break;

	case DIOCGETQSTATS: {
		struct pfioc_qstats	*pq = (struct pfioc_qstats *)addr;
		struct pf_altq		*altq;
		u_int32_t		 nr;
		int			 nbytes;

		if (pq->ticket != ticket_altqs_active) {
			error = EBUSY;
			break;
		}
		nbytes = pq->nbytes;
		nr = 0;
		altq = TAILQ_FIRST(pf_altqs_active);
		while ((altq != NULL) && (nr < pq->nr)) {
			altq = TAILQ_NEXT(altq, entries);
			nr++;
		}
		if (altq == NULL) {
			error = EBUSY;
			break;
		}
		error = altq_getqstats(altq, pq->buf, &nbytes);
		if (error == 0) {
			pq->scheduler = altq->scheduler;
			pq->nbytes = nbytes;
		}
		break;
	}
#endif /* ALTQ */

	case DIOCBEGINADDRS: {
		struct pfioc_pooladdr	*pp = (struct pfioc_pooladdr *)addr;

		pf_empty_pool(&pf_pabuf);
		pp->ticket = ++ticket_pabuf;
		break;
	}

	case DIOCADDADDR: {
		struct pfioc_pooladdr	*pp = (struct pfioc_pooladdr *)addr;

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
		bcopy(&pp->addr, pa, sizeof (struct pf_pooladdr));
		if (pa->ifname[0]) {
			pa->kif = pfi_kif_get(pa->ifname);
			if (pa->kif == NULL) {
				pool_put(&pf_pooladdr_pl, pa);
				error = EINVAL;
				break;
			}
			pfi_kif_ref(pa->kif, PFI_KIF_REF_RULE);
		}
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
		struct pfioc_pooladdr	*pp = (struct pfioc_pooladdr *)addr;

		pp->nr = 0;
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
		struct pfioc_pooladdr	*pp = (struct pfioc_pooladdr *)addr;
		u_int32_t		 nr = 0;

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
		bcopy(pa, &pp->addr, sizeof (struct pf_pooladdr));
		pfi_dynaddr_copyout(&pp->addr.addr);
		pf_tbladdr_copyout(&pp->addr.addr);
		pf_rtlabel_copyout(&pp->addr.addr);
		break;
	}

	case DIOCCHANGEADDR: {
		struct pfioc_pooladdr	*pca = (struct pfioc_pooladdr *)addr;
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
			bcopy(&pca->addr, newpa, sizeof (struct pf_pooladdr));
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

	case DIOCGETRULESETS: {
		struct pfioc_ruleset	*pr = (struct pfioc_ruleset *)addr;
		struct pf_ruleset	*ruleset;
		struct pf_anchor	*anchor;

		pr->path[sizeof (pr->path) - 1] = 0;
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
		struct pfioc_ruleset	*pr = (struct pfioc_ruleset *)addr;
		struct pf_ruleset	*ruleset;
		struct pf_anchor	*anchor;
		u_int32_t		 nr = 0;

		pr->path[sizeof (pr->path) - 1] = 0;
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

	case DIOCRCLRTABLES: {
		struct pfioc_table *io = (struct pfioc_table *)addr;

		if (io->pfrio_esize != 0) {
			error = ENODEV;
			break;
		}
		error = pfr_clr_tables(&io->pfrio_table, &io->pfrio_ndel,
		    io->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;
	}

	case DIOCRADDTABLES: {
		struct pfioc_table *io = (struct pfioc_table *)addr;

		if (io->pfrio_esize != sizeof (struct pfr_table)) {
			error = ENODEV;
			break;
		}
		error = pfr_add_tables(io->pfrio_buffer, io->pfrio_size,
		    &io->pfrio_nadd, io->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;
	}

	case DIOCRDELTABLES: {
		struct pfioc_table *io = (struct pfioc_table *)addr;

		if (io->pfrio_esize != sizeof (struct pfr_table)) {
			error = ENODEV;
			break;
		}
		error = pfr_del_tables(io->pfrio_buffer, io->pfrio_size,
		    &io->pfrio_ndel, io->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;
	}

	case DIOCRGETTABLES: {
		struct pfioc_table *io = (struct pfioc_table *)addr;

		if (io->pfrio_esize != sizeof (struct pfr_table)) {
			error = ENODEV;
			break;
		}
		error = pfr_get_tables(&io->pfrio_table, io->pfrio_buffer,
		    &io->pfrio_size, io->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;
	}

	case DIOCRGETTSTATS: {
		struct pfioc_table *io = (struct pfioc_table *)addr;

		if (io->pfrio_esize != sizeof (struct pfr_tstats)) {
			error = ENODEV;
			break;
		}
		error = pfr_get_tstats(&io->pfrio_table, io->pfrio_buffer,
		    &io->pfrio_size, io->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;
	}

	case DIOCRCLRTSTATS: {
		struct pfioc_table *io = (struct pfioc_table *)addr;

		if (io->pfrio_esize != sizeof (struct pfr_table)) {
			error = ENODEV;
			break;
		}
		error = pfr_clr_tstats(io->pfrio_buffer, io->pfrio_size,
		    &io->pfrio_nzero, io->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;
	}

	case DIOCRSETTFLAGS: {
		struct pfioc_table *io = (struct pfioc_table *)addr;

		if (io->pfrio_esize != sizeof (struct pfr_table)) {
			error = ENODEV;
			break;
		}
		error = pfr_set_tflags(io->pfrio_buffer, io->pfrio_size,
		    io->pfrio_setflag, io->pfrio_clrflag, &io->pfrio_nchange,
		    &io->pfrio_ndel, io->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;
	}

	case DIOCRCLRADDRS: {
		struct pfioc_table *io = (struct pfioc_table *)addr;

		if (io->pfrio_esize != 0) {
			error = ENODEV;
			break;
		}
		error = pfr_clr_addrs(&io->pfrio_table, &io->pfrio_ndel,
		    io->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;
	}

	case DIOCRADDADDRS: {
		struct pfioc_table *io = (struct pfioc_table *)addr;

		if (io->pfrio_esize != sizeof (struct pfr_addr)) {
			error = ENODEV;
			break;
		}
		error = pfr_add_addrs(&io->pfrio_table, io->pfrio_buffer,
		    io->pfrio_size, &io->pfrio_nadd, io->pfrio_flags |
		    PFR_FLAG_USERIOCTL);
		break;
	}

	case DIOCRDELADDRS: {
		struct pfioc_table *io = (struct pfioc_table *)addr;

		if (io->pfrio_esize != sizeof (struct pfr_addr)) {
			error = ENODEV;
			break;
		}
		error = pfr_del_addrs(&io->pfrio_table, io->pfrio_buffer,
		    io->pfrio_size, &io->pfrio_ndel, io->pfrio_flags |
		    PFR_FLAG_USERIOCTL);
		break;
	}

	case DIOCRSETADDRS: {
		struct pfioc_table *io = (struct pfioc_table *)addr;

		if (io->pfrio_esize != sizeof (struct pfr_addr)) {
			error = ENODEV;
			break;
		}
		error = pfr_set_addrs(&io->pfrio_table, io->pfrio_buffer,
		    io->pfrio_size, &io->pfrio_size2, &io->pfrio_nadd,
		    &io->pfrio_ndel, &io->pfrio_nchange, io->pfrio_flags |
		    PFR_FLAG_USERIOCTL, 0);
		break;
	}

	case DIOCRGETADDRS: {
		struct pfioc_table *io = (struct pfioc_table *)addr;

		if (io->pfrio_esize != sizeof (struct pfr_addr)) {
			error = ENODEV;
			break;
		}
		error = pfr_get_addrs(&io->pfrio_table, io->pfrio_buffer,
		    &io->pfrio_size, io->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;
	}

	case DIOCRGETASTATS: {
		struct pfioc_table *io = (struct pfioc_table *)addr;

		if (io->pfrio_esize != sizeof (struct pfr_astats)) {
			error = ENODEV;
			break;
		}
		error = pfr_get_astats(&io->pfrio_table, io->pfrio_buffer,
		    &io->pfrio_size, io->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;
	}

	case DIOCRCLRASTATS: {
		struct pfioc_table *io = (struct pfioc_table *)addr;

		if (io->pfrio_esize != sizeof (struct pfr_addr)) {
			error = ENODEV;
			break;
		}
		error = pfr_clr_astats(&io->pfrio_table, io->pfrio_buffer,
		    io->pfrio_size, &io->pfrio_nzero, io->pfrio_flags |
		    PFR_FLAG_USERIOCTL);
		break;
	}

	case DIOCRTSTADDRS: {
		struct pfioc_table *io = (struct pfioc_table *)addr;

		if (io->pfrio_esize != sizeof (struct pfr_addr)) {
			error = ENODEV;
			break;
		}
		error = pfr_tst_addrs(&io->pfrio_table, io->pfrio_buffer,
		    io->pfrio_size, &io->pfrio_nmatch, io->pfrio_flags |
		    PFR_FLAG_USERIOCTL);
		break;
	}

	case DIOCRINADEFINE: {
		struct pfioc_table *io = (struct pfioc_table *)addr;

		if (io->pfrio_esize != sizeof (struct pfr_addr)) {
			error = ENODEV;
			break;
		}
		error = pfr_ina_define(&io->pfrio_table, io->pfrio_buffer,
		    io->pfrio_size, &io->pfrio_nadd, &io->pfrio_naddr,
		    io->pfrio_ticket, io->pfrio_flags | PFR_FLAG_USERIOCTL);
		break;
	}

	case DIOCOSFPADD: {
		struct pf_osfp_ioctl *io = (struct pf_osfp_ioctl *)addr;
		error = pf_osfp_add(io);
		break;
	}

	case DIOCOSFPGET: {
		struct pf_osfp_ioctl *io = (struct pf_osfp_ioctl *)addr;
		error = pf_osfp_get(io);
		break;
	}

	case DIOCXBEGIN: {
		struct pfioc_trans	*io = (struct pfioc_trans *)addr;
		struct pfioc_trans_e	*ioe;
		struct pfr_table	*table;
		int			 i;

		if (io->esize != sizeof (*ioe)) {
			error = ENODEV;
			goto fail;
		}
		ioe = _MALLOC(sizeof (*ioe), M_TEMP, M_WAITOK);
		table = _MALLOC(sizeof (*table), M_TEMP, M_WAITOK);
		for (i = 0; i < io->size; i++) {
			if (copyin(CAST_USER_ADDR_T(io->array+i), ioe,
			    sizeof (*ioe))) {
				_FREE(table, M_TEMP);
				_FREE(ioe, M_TEMP);
				error = EFAULT;
				goto fail;
			}
			switch (ioe->rs_num) {
			case PF_RULESET_ALTQ:
#if ALTQ
				if (ioe->anchor[0]) {
					_FREE(table, M_TEMP);
					_FREE(ioe, M_TEMP);
					error = EINVAL;
					goto fail;
				}
				if ((error = pf_begin_altq(&ioe->ticket))) {
					_FREE(table, M_TEMP);
					_FREE(ioe, M_TEMP);
					goto fail;
				}
#endif /* ALTQ */
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
			if (copyout(ioe, CAST_USER_ADDR_T(io->array+i),
			    sizeof (io->array[i]))) {
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
		struct pfioc_trans	*io = (struct pfioc_trans *)addr;
		struct pfioc_trans_e	*ioe;
		struct pfr_table	*table;
		int			 i;

		if (io->esize != sizeof (*ioe)) {
			error = ENODEV;
			goto fail;
		}
		ioe = _MALLOC(sizeof (*ioe), M_TEMP, M_WAITOK);
		table = _MALLOC(sizeof (*table), M_TEMP, M_WAITOK);
		for (i = 0; i < io->size; i++) {
			if (copyin(CAST_USER_ADDR_T(io->array+i), ioe,
			    sizeof (*ioe))) {
				_FREE(table, M_TEMP);
				_FREE(ioe, M_TEMP);
				error = EFAULT;
				goto fail;
			}
			switch (ioe->rs_num) {
			case PF_RULESET_ALTQ:
#if ALTQ
				if (ioe->anchor[0]) {
					_FREE(table, M_TEMP);
					_FREE(ioe, M_TEMP);
					error = EINVAL;
					goto fail;
				}
				if ((error = pf_rollback_altq(ioe->ticket))) {
					_FREE(table, M_TEMP);
					_FREE(ioe, M_TEMP);
					goto fail; /* really bad */
				}
#endif /* ALTQ */
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
		struct pfioc_trans	*io = (struct pfioc_trans *)addr;
		struct pfioc_trans_e	*ioe;
		struct pfr_table	*table;
		struct pf_ruleset	*rs;
		int			 i;

		if (io->esize != sizeof (*ioe)) {
			error = ENODEV;
			goto fail;
		}
		ioe = _MALLOC(sizeof (*ioe), M_TEMP, M_WAITOK);
		table = _MALLOC(sizeof (*table), M_TEMP, M_WAITOK);
		/* first makes sure everything will succeed */
		for (i = 0; i < io->size; i++) {
			if (copyin(CAST_USER_ADDR_T(io->array+i), ioe,
			    sizeof (*ioe))) {
				_FREE(table, M_TEMP);
				_FREE(ioe, M_TEMP);
				error = EFAULT;
				goto fail;
			}
			switch (ioe->rs_num) {
			case PF_RULESET_ALTQ:
#if ALTQ
				if (ioe->anchor[0]) {
					_FREE(table, M_TEMP);
					_FREE(ioe, M_TEMP);
					error = EINVAL;
					goto fail;
				}
				if (!altqs_inactive_open || ioe->ticket !=
				    ticket_altqs_inactive) {
					_FREE(table, M_TEMP);
					_FREE(ioe, M_TEMP);
					error = EBUSY;
					goto fail;
				}
#endif /* ALTQ */
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
		/* now do the commit - no errors should happen here */
		for (i = 0; i < io->size; i++) {
			if (copyin(CAST_USER_ADDR_T(io->array+i), ioe,
			    sizeof (*ioe))) {
				_FREE(table, M_TEMP);
				_FREE(ioe, M_TEMP);
				error = EFAULT;
				goto fail;
			}
			switch (ioe->rs_num) {
			case PF_RULESET_ALTQ:
#if ALTQ
				if ((error = pf_commit_altq(ioe->ticket))) {
					_FREE(table, M_TEMP);
					_FREE(ioe, M_TEMP);
					goto fail; /* really bad */
				}
#endif /* ALTQ */
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

	case DIOCGETSRCNODES: {
		struct pfioc_src_nodes	*psn = (struct pfioc_src_nodes *)addr;
		struct pf_src_node	*n, *sn, *pstore;
		u_int32_t		 nr = 0;
		int			 space = psn->psn_len;

		if (space == 0) {
			RB_FOREACH(n, pf_src_tree, &tree_src_tracking)
				nr++;
			psn->psn_len = sizeof (struct pf_src_node) * nr;
			break;
		}

		pstore = _MALLOC(sizeof (*pstore), M_TEMP, M_WAITOK);

		sn = psn->psn_src_nodes;
		RB_FOREACH(n, pf_src_tree, &tree_src_tracking) {
			uint64_t secs = pf_time_second(), diff;

			if ((nr + 1) * sizeof (*sn) > (unsigned)psn->psn_len)
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

			error = copyout(pstore, CAST_USER_ADDR_T(sn),
			    sizeof (*sn));
			if (error) {
				_FREE(pstore, M_TEMP);
				goto fail;
			}
			sn++;
			nr++;
		}
		psn->psn_len = sizeof (struct pf_src_node) * nr;

		_FREE(pstore, M_TEMP);
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

	case DIOCKILLSRCNODES: {
		struct pf_src_node	*sn;
		struct pf_state		*s;
		struct pfioc_src_node_kill *psnk =
		    (struct pfioc_src_node_kill *)addr;
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

	case DIOCSETHOSTID: {
		u_int32_t	*hid = (u_int32_t *)addr;

		if (*hid == 0)
			pf_status.hostid = random();
		else
			pf_status.hostid = *hid;
		break;
	}

	case DIOCOSFPFLUSH:
		pf_osfp_flush();
		break;

	case DIOCIGETIFACES: {
		struct pfioc_iface *io = (struct pfioc_iface *)addr;

		if (io->pfiio_esize != sizeof (struct pfi_kif)) {
			error = ENODEV;
			break;
		}
		error = pfi_get_ifaces(io->pfiio_name, io->pfiio_buffer,
		    &io->pfiio_size);
		break;
	}

	case DIOCSETIFFLAG: {
		struct pfioc_iface *io = (struct pfioc_iface *)addr;

		error = pfi_set_flags(io->pfiio_name, io->pfiio_flags);
		break;
	}

	case DIOCCLRIFFLAG: {
		struct pfioc_iface *io = (struct pfioc_iface *)addr;

		error = pfi_clear_flags(io->pfiio_name, io->pfiio_flags);
		break;
	}

	default:
		error = ENODEV;
		break;
	}
fail:
	lck_mtx_unlock(pf_lock);
	lck_rw_done(pf_perim_lock);

	return (error);
}

int
pf_af_hook(struct ifnet *ifp, struct mbuf **mppn, struct mbuf **mp,
    unsigned int af, int input)
{
	int error = 0, reentry;
	struct thread *curthread = current_thread();
	struct mbuf *nextpkt;

	reentry = (ifp->if_pf_curthread == curthread);
	if (!reentry) {
		lck_rw_lock_shared(pf_perim_lock);
		if (!pf_hooks_attached)
			goto done;

		lck_mtx_lock(pf_lock);
		ifp->if_pf_curthread = curthread;
	}

	if (mppn != NULL && *mppn != NULL)
		VERIFY(*mppn == *mp);
	if ((nextpkt = (*mp)->m_nextpkt) != NULL)
		(*mp)->m_nextpkt = NULL;

	switch (af) {
#if INET
	case AF_INET: {
		error = pf_inet_hook(ifp, mp, input);
		break;
	}
#endif /* INET */
#if INET6
	case AF_INET6:
		error = pf_inet6_hook(ifp, mp, input);
		break;
#endif /* INET6 */
	default:
		break;
	}

	if (nextpkt != NULL) {
		if (*mp != NULL) {
			struct mbuf *m = *mp;
			while (m->m_nextpkt != NULL)
				m = m->m_nextpkt;
			m->m_nextpkt = nextpkt;
		} else {
			*mp = nextpkt;
		}
	}
	if (mppn != NULL && *mppn != NULL)
		*mppn = *mp;

	if (!reentry) {
		ifp->if_pf_curthread = NULL;
		lck_mtx_unlock(pf_lock);
	}
done:
	if (!reentry)
		lck_rw_done(pf_perim_lock);

	return (error);
}


#if INET
static int
pf_inet_hook(struct ifnet *ifp, struct mbuf **mp, int input)
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
	if (pf_test(input ? PF_IN : PF_OUT, ifp, mp, NULL) != PF_PASS) {
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
		ip = mtod(*mp, struct ip *);
		NTOHS(ip->ip_len);
		NTOHS(ip->ip_off);
	}
#endif
	return (error);
}
#endif /* INET */

#if INET6
int
pf_inet6_hook(struct ifnet *ifp, struct mbuf **mp, int input)
{
	int error = 0;

#if 0
	/*
	 * TODO: once we support IPv6 hardware checksum offload
	 */
	/*
	 * If the packet is outbound, is originated locally, is flagged for
	 * delayed UDP/TCP checksum calculation, and is about to be processed
	 * for an interface that doesn't support the appropriate checksum
	 * offloading, then calculated the checksum here so that PF can adjust
	 * it properly.
	 */
	if (!input && (*mp)->m_pkthdr.rcvif == NULL) {
		static const int mask = CSUM_DELAY_DATA;
		const int flags = (*mp)->m_pkthdr.csum_flags &
		    ~IF_HWASSIST_CSUM_FLAGS(ifp->if_hwassist);

		if (flags & mask) {
			in6_delayed_cksum(*mp);
			(*mp)->m_pkthdr.csum_flags &= ~mask;
		}
	}
#endif

	if (pf_test6(input ? PF_IN : PF_OUT, ifp, mp, NULL) != PF_PASS) {
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
pf_ifaddr_hook(struct ifnet *ifp, unsigned long cmd)
{
	lck_rw_lock_shared(pf_perim_lock);
	if (!pf_hooks_attached)
		goto done;

	lck_mtx_lock(pf_lock);

	switch (cmd) {
	case SIOCSIFADDR:
	case SIOCAIFADDR:
	case SIOCDIFADDR:
#if INET6
	case SIOCAIFADDR_IN6:
	case SIOCDIFADDR_IN6:
#endif /* INET6 */
		if (ifp->if_pf_kif != NULL)
			pfi_kifaddr_update(ifp->if_pf_kif);
		break;
	default:
		panic("%s: unexpected ioctl %lu", __func__, cmd);
		/* NOTREACHED */
	}

	lck_mtx_unlock(pf_lock);
done:
	lck_rw_done(pf_perim_lock);
	return (0);
}

/*
 * Caller acquires dlil lock as writer (exclusive)
 */
void
pf_ifnet_hook(struct ifnet *ifp, int attach)
{
	lck_rw_lock_shared(pf_perim_lock);
	if (!pf_hooks_attached)
		goto done;

	lck_mtx_lock(pf_lock);
	if (attach)
		pfi_attach_ifnet(ifp);
	else
		pfi_detach_ifnet(ifp);
	lck_mtx_unlock(pf_lock);
done:
	lck_rw_done(pf_perim_lock);
}

static void
pf_attach_hooks(void)
{
	int i;

	if (pf_hooks_attached)
		return;

	ifnet_head_lock_shared();
	for (i = 0; i <= if_index; i++) {
		struct ifnet *ifp = ifindex2ifnet[i];
		if (ifp != NULL) {
			pfi_attach_ifnet(ifp);
		}
	}
	ifnet_head_done();
	pf_hooks_attached = 1;
}

static void
pf_detach_hooks(void)
{
	int i;

	if (!pf_hooks_attached)
		return;

	ifnet_head_lock_shared();
	for (i = 0; i <= if_index; i++) {
		struct ifnet *ifp = ifindex2ifnet[i];
		if (ifp != NULL && ifp->if_pf_kif != NULL) {
			pfi_detach_ifnet(ifp);
		}
	}
	ifnet_head_done();
	pf_hooks_attached = 0;
}
