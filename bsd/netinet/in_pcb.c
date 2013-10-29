/*
 * Copyright (c) 2000-2013 Apple Inc. All rights reserved.
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
/*
 * Copyright (c) 1982, 1986, 1991, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)in_pcb.c	8.4 (Berkeley) 5/24/95
 * $FreeBSD: src/sys/netinet/in_pcb.c,v 1.59.2.17 2001/08/13 16:26:17 ume Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/mcache.h>
#include <sys/kauth.h>
#include <sys/priv.h>
#include <sys/proc_uuid_policy.h>
#include <sys/syslog.h>

#include <libkern/OSAtomic.h>
#include <kern/locks.h>

#include <machine/limits.h>

#include <kern/zalloc.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/flowhash.h>
#include <net/flowadv.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#if INET6
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#endif /* INET6 */

#if IPSEC
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#endif /* IPSEC */

#include <sys/kdebug.h>
#include <sys/random.h>

#include <dev/random/randomdev.h>
#include <mach/boolean.h>

#if FLOW_DIVERT
#include <netinet/flow_divert.h>
#endif

static lck_grp_t	*inpcb_lock_grp;
static lck_attr_t	*inpcb_lock_attr;
static lck_grp_attr_t	*inpcb_lock_grp_attr;
decl_lck_mtx_data(static, inpcb_lock);		/* global INPCB lock */
decl_lck_mtx_data(static, inpcb_timeout_lock);

static TAILQ_HEAD(, inpcbinfo) inpcb_head = TAILQ_HEAD_INITIALIZER(inpcb_head);

static u_int16_t inpcb_timeout_run = 0;	/* INPCB timer is scheduled to run */
static boolean_t inpcb_garbage_collecting = FALSE; /* gc timer is scheduled */
static boolean_t inpcb_ticking = FALSE;		/* "slow" timer is scheduled */
static boolean_t inpcb_fast_timer_on = FALSE;
static void inpcb_sched_timeout(struct timeval *);
static void inpcb_timeout(void *);
int inpcb_timeout_lazy = 10;	/* 10 seconds leeway for lazy timers */
extern int tvtohz(struct timeval *);

#if CONFIG_PROC_UUID_POLICY
static void inp_update_cellular_policy(struct inpcb *, boolean_t);
#if FLOW_DIVERT
static void inp_update_flow_divert_policy(struct inpcb *, boolean_t);
#endif /* FLOW_DIVERT */
#endif /* !CONFIG_PROC_UUID_POLICY */

#if IPSEC
extern int ipsec_bypass;
#endif /* IPSEC */

#define	DBG_FNC_PCB_LOOKUP	NETDBG_CODE(DBG_NETTCP, (6 << 8))
#define	DBG_FNC_PCB_HLOOKUP	NETDBG_CODE(DBG_NETTCP, ((6 << 8) | 1))

/*
 * These configure the range of local port addresses assigned to
 * "unspecified" outgoing connections/packets/whatever.
 */
int	ipport_lowfirstauto  = IPPORT_RESERVED - 1;	/* 1023 */
int	ipport_lowlastauto = IPPORT_RESERVEDSTART;	/* 600 */
int	ipport_firstauto = IPPORT_HIFIRSTAUTO;		/* 49152 */
int	ipport_lastauto  = IPPORT_HILASTAUTO;		/* 65535 */
int	ipport_hifirstauto = IPPORT_HIFIRSTAUTO;	/* 49152 */
int	ipport_hilastauto  = IPPORT_HILASTAUTO;		/* 65535 */

#define	RANGECHK(var, min, max) \
	if ((var) < (min)) { (var) = (min); } \
	else if ((var) > (max)) { (var) = (max); }

static int
sysctl_net_ipport_check SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error;

	error = sysctl_handle_int(oidp, oidp->oid_arg1, oidp->oid_arg2, req);
	if (!error) {
		RANGECHK(ipport_lowfirstauto, 1, IPPORT_RESERVED - 1);
		RANGECHK(ipport_lowlastauto, 1, IPPORT_RESERVED - 1);
		RANGECHK(ipport_firstauto, IPPORT_RESERVED, USHRT_MAX);
		RANGECHK(ipport_lastauto, IPPORT_RESERVED, USHRT_MAX);
		RANGECHK(ipport_hifirstauto, IPPORT_RESERVED, USHRT_MAX);
		RANGECHK(ipport_hilastauto, IPPORT_RESERVED, USHRT_MAX);
	}
	return (error);
}

#undef RANGECHK

SYSCTL_NODE(_net_inet_ip, IPPROTO_IP, portrange,
	CTLFLAG_RW|CTLFLAG_LOCKED, 0, "IP Ports");

SYSCTL_PROC(_net_inet_ip_portrange, OID_AUTO, lowfirst,
	CTLTYPE_INT|CTLFLAG_RW | CTLFLAG_LOCKED,
	&ipport_lowfirstauto, 0, &sysctl_net_ipport_check, "I", "");
SYSCTL_PROC(_net_inet_ip_portrange, OID_AUTO, lowlast,
	CTLTYPE_INT|CTLFLAG_RW | CTLFLAG_LOCKED,
	&ipport_lowlastauto, 0, &sysctl_net_ipport_check, "I", "");
SYSCTL_PROC(_net_inet_ip_portrange, OID_AUTO, first,
	CTLTYPE_INT|CTLFLAG_RW | CTLFLAG_LOCKED,
	&ipport_firstauto, 0, &sysctl_net_ipport_check, "I", "");
SYSCTL_PROC(_net_inet_ip_portrange, OID_AUTO, last,
	CTLTYPE_INT|CTLFLAG_RW | CTLFLAG_LOCKED,
	&ipport_lastauto, 0, &sysctl_net_ipport_check, "I", "");
SYSCTL_PROC(_net_inet_ip_portrange, OID_AUTO, hifirst,
	CTLTYPE_INT|CTLFLAG_RW | CTLFLAG_LOCKED,
	&ipport_hifirstauto, 0, &sysctl_net_ipport_check, "I", "");
SYSCTL_PROC(_net_inet_ip_portrange, OID_AUTO, hilast,
	CTLTYPE_INT|CTLFLAG_RW | CTLFLAG_LOCKED,
	&ipport_hilastauto, 0, &sysctl_net_ipport_check, "I", "");

extern int	udp_use_randomport;
extern int	tcp_use_randomport;

/* Structs used for flowhash computation */
struct inp_flowhash_key_addr {
	union {
		struct in_addr	v4;
		struct in6_addr v6;
		u_int8_t	addr8[16];
		u_int16_t	addr16[8];
		u_int32_t	addr32[4];
	} infha;
};

struct inp_flowhash_key {
	struct inp_flowhash_key_addr	infh_laddr;
	struct inp_flowhash_key_addr	infh_faddr;
	u_int32_t			infh_lport;
	u_int32_t			infh_fport;
	u_int32_t			infh_af;
	u_int32_t			infh_proto;
	u_int32_t			infh_rand1;
	u_int32_t			infh_rand2;
};

static u_int32_t inp_hash_seed = 0;

static int infc_cmp(const struct inpcb *, const struct inpcb *);

/* Flags used by inp_fc_getinp */
#define	INPFC_SOLOCKED	0x1
#define	INPFC_REMOVE	0x2
static struct inpcb *inp_fc_getinp(u_int32_t, u_int32_t);

static void inp_fc_feedback(struct inpcb *);
extern void tcp_remove_from_time_wait(struct inpcb *inp);

decl_lck_mtx_data(static, inp_fc_lck);

RB_HEAD(inp_fc_tree, inpcb) inp_fc_tree;
RB_PROTOTYPE(inp_fc_tree, inpcb, infc_link, infc_cmp);
RB_GENERATE(inp_fc_tree, inpcb, infc_link, infc_cmp);

/*
 * Use this inp as a key to find an inp in the flowhash tree.
 * Accesses to it are protected by inp_fc_lck.
 */
struct inpcb key_inp;

/*
 * in_pcb.c: manage the Protocol Control Blocks.
 */

void
in_pcbinit(void)
{
	static int inpcb_initialized = 0;

	VERIFY(!inpcb_initialized);
	inpcb_initialized = 1;

	inpcb_lock_grp_attr = lck_grp_attr_alloc_init();
	inpcb_lock_grp = lck_grp_alloc_init("inpcb", inpcb_lock_grp_attr);
	inpcb_lock_attr = lck_attr_alloc_init();
	lck_mtx_init(&inpcb_lock, inpcb_lock_grp, inpcb_lock_attr);
	lck_mtx_init(&inpcb_timeout_lock, inpcb_lock_grp, inpcb_lock_attr);

	/*
	 * Initialize data structures required to deliver
	 * flow advisories.
	 */
	lck_mtx_init(&inp_fc_lck, inpcb_lock_grp, inpcb_lock_attr);
	lck_mtx_lock(&inp_fc_lck);
	RB_INIT(&inp_fc_tree);
	bzero(&key_inp, sizeof(key_inp));
	lck_mtx_unlock(&inp_fc_lck);
}

#define	INPCB_HAVE_TIMER_REQ(req)	(((req).intimer_lazy > 0) || \
	((req).intimer_fast > 0) || ((req).intimer_nodelay > 0))
static void
inpcb_timeout(void *arg)
{
#pragma unused(arg)
	struct inpcbinfo *ipi;
	boolean_t t, gc;
	struct intimercount gccnt, tmcnt;
	struct timeval leeway;

	/*
	 * Update coarse-grained networking timestamp (in sec.); the idea
	 * is to piggy-back on the timeout callout to update the counter
	 * returnable via net_uptime().
	 */
	net_update_uptime();

	lck_mtx_lock_spin(&inpcb_timeout_lock);
	gc = inpcb_garbage_collecting;
	inpcb_garbage_collecting = FALSE;
	bzero(&gccnt, sizeof(gccnt));
	bzero(&tmcnt, sizeof(tmcnt));

	t = inpcb_ticking;
	inpcb_ticking = FALSE;

	if (gc || t) {
		lck_mtx_unlock(&inpcb_timeout_lock);

		lck_mtx_lock(&inpcb_lock);
		TAILQ_FOREACH(ipi, &inpcb_head, ipi_entry) {
			if (INPCB_HAVE_TIMER_REQ(ipi->ipi_gc_req)) {
				bzero(&ipi->ipi_gc_req,
					sizeof(ipi->ipi_gc_req));
				if (gc && ipi->ipi_gc != NULL) {
					ipi->ipi_gc(ipi);
					gccnt.intimer_lazy +=
					    ipi->ipi_gc_req.intimer_lazy;
					gccnt.intimer_fast +=
					    ipi->ipi_gc_req.intimer_fast;
					gccnt.intimer_nodelay +=
					    ipi->ipi_gc_req.intimer_nodelay;
				}
			}
			if (INPCB_HAVE_TIMER_REQ(ipi->ipi_timer_req)) {
				bzero(&ipi->ipi_timer_req,
					sizeof(ipi->ipi_timer_req));
				if (t && ipi->ipi_timer != NULL) {
					ipi->ipi_timer(ipi);
					tmcnt.intimer_lazy +=
					    ipi->ipi_timer_req.intimer_lazy;
					tmcnt.intimer_lazy +=
					    ipi->ipi_timer_req.intimer_fast;
					tmcnt.intimer_nodelay +=
					    ipi->ipi_timer_req.intimer_nodelay;
				}
			}
		}
		lck_mtx_unlock(&inpcb_lock);
		lck_mtx_lock_spin(&inpcb_timeout_lock);
	}

	/* lock was dropped above, so check first before overriding */
	if (!inpcb_garbage_collecting)
		inpcb_garbage_collecting = INPCB_HAVE_TIMER_REQ(gccnt);
	if (!inpcb_ticking)
		inpcb_ticking = INPCB_HAVE_TIMER_REQ(tmcnt);

	/* re-arm the timer if there's work to do */
	inpcb_timeout_run--;
	VERIFY(inpcb_timeout_run >= 0 && inpcb_timeout_run < 2);

	bzero(&leeway, sizeof(leeway));
	leeway.tv_sec = inpcb_timeout_lazy;
	if (gccnt.intimer_nodelay > 0 || tmcnt.intimer_nodelay > 0)
		inpcb_sched_timeout(NULL);
	else if ((gccnt.intimer_fast + tmcnt.intimer_fast) <= 5)
		/* be lazy when idle with little activity */
		inpcb_sched_timeout(&leeway);
	else
		inpcb_sched_timeout(NULL);

	lck_mtx_unlock(&inpcb_timeout_lock);
}

static void
inpcb_sched_timeout(struct timeval *leeway)
{
	lck_mtx_assert(&inpcb_timeout_lock, LCK_MTX_ASSERT_OWNED);

	if (inpcb_timeout_run == 0 &&
		(inpcb_garbage_collecting || inpcb_ticking)) {
		lck_mtx_convert_spin(&inpcb_timeout_lock);
		inpcb_timeout_run++;
		if (leeway == NULL) {
			inpcb_fast_timer_on = TRUE;
			timeout(inpcb_timeout, NULL, hz);
		} else {
			inpcb_fast_timer_on = FALSE;
			timeout_with_leeway(inpcb_timeout, NULL, hz,
				tvtohz(leeway));
		}
	} else if (inpcb_timeout_run == 1 &&
		leeway == NULL && !inpcb_fast_timer_on) {
		/*
		 * Since the request was for a fast timer but the
		 * scheduled timer is a lazy timer, try to schedule
		 * another instance of fast timer also
		 */
		lck_mtx_convert_spin(&inpcb_timeout_lock);
		inpcb_timeout_run++;
		inpcb_fast_timer_on = TRUE;
		timeout(inpcb_timeout, NULL, hz);
	}
}

void
inpcb_gc_sched(struct inpcbinfo *ipi, u_int32_t type)
{
	struct timeval leeway;
	lck_mtx_lock_spin(&inpcb_timeout_lock);
	inpcb_garbage_collecting = TRUE;
	switch (type) {
	case INPCB_TIMER_NODELAY:
		atomic_add_32(&ipi->ipi_gc_req.intimer_nodelay, 1);
		inpcb_sched_timeout(NULL);
		break;
	case INPCB_TIMER_FAST:
		atomic_add_32(&ipi->ipi_gc_req.intimer_fast, 1);
		inpcb_sched_timeout(NULL);
		break;
	default:
		atomic_add_32(&ipi->ipi_gc_req.intimer_lazy, 1);
		leeway.tv_sec = inpcb_timeout_lazy;
		leeway.tv_usec = 0;
		inpcb_sched_timeout(&leeway);
		break;
	}
	lck_mtx_unlock(&inpcb_timeout_lock);
}

void
inpcb_timer_sched(struct inpcbinfo *ipi, u_int32_t type)
{
	struct timeval leeway;
	lck_mtx_lock_spin(&inpcb_timeout_lock);
	inpcb_ticking = TRUE;
	switch (type) {
	case INPCB_TIMER_NODELAY:
		atomic_add_32(&ipi->ipi_timer_req.intimer_nodelay, 1);
		inpcb_sched_timeout(NULL);
		break;
	case INPCB_TIMER_FAST:
		atomic_add_32(&ipi->ipi_timer_req.intimer_fast, 1);
		inpcb_sched_timeout(NULL);
		break;
	default:
		atomic_add_32(&ipi->ipi_timer_req.intimer_lazy, 1);
		leeway.tv_sec = inpcb_timeout_lazy;
		leeway.tv_usec = 0;
		inpcb_sched_timeout(&leeway);
		break;
	}
	lck_mtx_unlock(&inpcb_timeout_lock);
}

void
in_pcbinfo_attach(struct inpcbinfo *ipi)
{
	struct inpcbinfo *ipi0;

	lck_mtx_lock(&inpcb_lock);
	TAILQ_FOREACH(ipi0, &inpcb_head, ipi_entry) {
		if (ipi0 == ipi) {
			panic("%s: ipi %p already in the list\n",
			    __func__, ipi);
			/* NOTREACHED */
		}
	}
	TAILQ_INSERT_TAIL(&inpcb_head, ipi, ipi_entry);
	lck_mtx_unlock(&inpcb_lock);
}

int
in_pcbinfo_detach(struct inpcbinfo *ipi)
{
	struct inpcbinfo *ipi0;
	int error = 0;

	lck_mtx_lock(&inpcb_lock);
	TAILQ_FOREACH(ipi0, &inpcb_head, ipi_entry) {
		if (ipi0 == ipi)
			break;
	}
	if (ipi0 != NULL)
		TAILQ_REMOVE(&inpcb_head, ipi0, ipi_entry);
	else
		error = ENXIO;
	lck_mtx_unlock(&inpcb_lock);

	return (error);
}

/*
 * Allocate a PCB and associate it with the socket.
 *
 * Returns:	0			Success
 *		ENOBUFS
 *		ENOMEM
 *	ipsec_init_policy:???		[IPSEC]
 */
int
in_pcballoc(struct socket *so, struct inpcbinfo *pcbinfo, struct proc *p)
{
#pragma unused(p)
	struct inpcb *inp;
	caddr_t	temp;
#if CONFIG_MACF_NET
	int mac_error;
#endif /* CONFIG_MACF_NET */

	if (!so->cached_in_sock_layer) {
		inp = (struct inpcb *)zalloc(pcbinfo->ipi_zone);
		if (inp == NULL)
			return (ENOBUFS);
		bzero((caddr_t)inp, sizeof (*inp));
	} else {
		inp = (struct inpcb *)(void *)so->so_saved_pcb;
		temp = inp->inp_saved_ppcb;
		bzero((caddr_t)inp, sizeof (*inp));
		inp->inp_saved_ppcb = temp;
	}

	inp->inp_gencnt = ++pcbinfo->ipi_gencnt;
	inp->inp_pcbinfo = pcbinfo;
	inp->inp_socket = so;
#if CONFIG_MACF_NET
	mac_error = mac_inpcb_label_init(inp, M_WAITOK);
	if (mac_error != 0) {
		if (!so->cached_in_sock_layer)
			zfree(pcbinfo->ipi_zone, inp);
		return (mac_error);
	}
	mac_inpcb_label_associate(so, inp);
#endif /* CONFIG_MACF_NET */
	/* make sure inp_stat is always 64-bit aligned */
	inp->inp_stat = (struct inp_stat *)P2ROUNDUP(inp->inp_stat_store,
	    sizeof (u_int64_t));
	if (((uintptr_t)inp->inp_stat - (uintptr_t)inp->inp_stat_store) +
	    sizeof (*inp->inp_stat) > sizeof (inp->inp_stat_store)) {
		panic("%s: insufficient space to align inp_stat", __func__);
		/* NOTREACHED */
	}

	/* make sure inp_cstat is always 64-bit aligned */
	inp->inp_cstat = (struct inp_stat *)P2ROUNDUP(inp->inp_cstat_store,
	    sizeof (u_int64_t));
	if (((uintptr_t)inp->inp_cstat - (uintptr_t)inp->inp_cstat_store) +
	    sizeof (*inp->inp_cstat) > sizeof (inp->inp_cstat_store)) {
		panic("%s: insufficient space to align inp_cstat", __func__);
		/* NOTREACHED */
	}

	/* make sure inp_wstat is always 64-bit aligned */
	inp->inp_wstat = (struct inp_stat *)P2ROUNDUP(inp->inp_wstat_store,
	    sizeof (u_int64_t));
	if (((uintptr_t)inp->inp_wstat - (uintptr_t)inp->inp_wstat_store) +
	    sizeof (*inp->inp_wstat) > sizeof (inp->inp_wstat_store)) {
		panic("%s: insufficient space to align inp_wstat", __func__);
		/* NOTREACHED */
	}

	so->so_pcb = (caddr_t)inp;

	if (so->so_proto->pr_flags & PR_PCBLOCK) {
		lck_mtx_init(&inp->inpcb_mtx, pcbinfo->ipi_lock_grp,
		    pcbinfo->ipi_lock_attr);
	}


#if INET6
	if (SOCK_DOM(so) == PF_INET6 && !ip6_mapped_addr_on)
		inp->inp_flags |= IN6P_IPV6_V6ONLY;

	if (ip6_auto_flowlabel)
		inp->inp_flags |= IN6P_AUTOFLOWLABEL;
#endif /* INET6 */

	(void) inp_update_policy(inp);

	lck_rw_lock_exclusive(pcbinfo->ipi_lock);
	inp->inp_gencnt = ++pcbinfo->ipi_gencnt;
	LIST_INSERT_HEAD(pcbinfo->ipi_listhead, inp, inp_list);
	pcbinfo->ipi_count++;
	lck_rw_done(pcbinfo->ipi_lock);
	return (0);
}

/*
 * in_pcblookup_local_and_cleanup does everything
 * in_pcblookup_local does but it checks for a socket
 * that's going away. Since we know that the lock is
 * held read+write when this funciton is called, we
 * can safely dispose of this socket like the slow
 * timer would usually do and return NULL. This is
 * great for bind.
 */
struct inpcb *
in_pcblookup_local_and_cleanup(struct inpcbinfo *pcbinfo, struct in_addr laddr,
    u_int lport_arg, int wild_okay)
{
	struct inpcb *inp;

	/* Perform normal lookup */
	inp = in_pcblookup_local(pcbinfo, laddr, lport_arg, wild_okay);

	/* Check if we found a match but it's waiting to be disposed */
	if (inp != NULL && inp->inp_wantcnt == WNT_STOPUSING) {
		struct socket *so = inp->inp_socket;

		lck_mtx_lock(&inp->inpcb_mtx);

		if (so->so_usecount == 0) {
			if (inp->inp_state != INPCB_STATE_DEAD)
				in_pcbdetach(inp);
			in_pcbdispose(inp);	/* will unlock & destroy */
			inp = NULL;
		} else {
			lck_mtx_unlock(&inp->inpcb_mtx);
		}
	}

	return (inp);
}

static void
in_pcb_conflict_post_msg(u_int16_t port)
{
	/*
	 * Radar 5523020 send a kernel event notification if a
	 * non-participating socket tries to bind the port a socket
	 * who has set SOF_NOTIFYCONFLICT owns.
	 */
	struct kev_msg ev_msg;
	struct kev_in_portinuse	in_portinuse;

	bzero(&in_portinuse, sizeof (struct kev_in_portinuse));
	bzero(&ev_msg, sizeof (struct kev_msg));
	in_portinuse.port = ntohs(port);	/* port in host order */
	in_portinuse.req_pid = proc_selfpid();
	ev_msg.vendor_code = KEV_VENDOR_APPLE;
	ev_msg.kev_class = KEV_NETWORK_CLASS;
	ev_msg.kev_subclass = KEV_INET_SUBCLASS;
	ev_msg.event_code = KEV_INET_PORTINUSE;
	ev_msg.dv[0].data_ptr = &in_portinuse;
	ev_msg.dv[0].data_length = sizeof (struct kev_in_portinuse);
	ev_msg.dv[1].data_length = 0;
	kev_post_msg(&ev_msg);
}

/*
 * Bind an INPCB to an address and/or port.  This routine should not alter
 * the caller-supplied local address "nam".
 *
 * Returns:	0			Success
 *		EADDRNOTAVAIL		Address not available.
 *		EINVAL			Invalid argument
 *		EAFNOSUPPORT		Address family not supported [notdef]
 *		EACCES			Permission denied
 *		EADDRINUSE		Address in use
 *		EAGAIN			Resource unavailable, try again
 *		priv_check_cred:EPERM	Operation not permitted
 */
int
in_pcbbind(struct inpcb *inp, struct sockaddr *nam, struct proc *p)
{
	struct socket *so = inp->inp_socket;
	unsigned short *lastport;
	struct inpcbinfo *pcbinfo = inp->inp_pcbinfo;
	u_short lport = 0, rand_port = 0;
	int wild = 0, reuseport = (so->so_options & SO_REUSEPORT);
	int error, randomport, conflict = 0;
	kauth_cred_t cred;

	if (TAILQ_EMPTY(&in_ifaddrhead)) /* XXX broken! */
		return (EADDRNOTAVAIL);
	if (inp->inp_lport != 0 || inp->inp_laddr.s_addr != INADDR_ANY)
		return (EINVAL);
	if (!(so->so_options & (SO_REUSEADDR|SO_REUSEPORT)))
		wild = 1;
	socket_unlock(so, 0); /* keep reference on socket */
	lck_rw_lock_exclusive(pcbinfo->ipi_lock);
	if (nam != NULL) {
		struct ifnet *outif = NULL;

		if (nam->sa_len != sizeof (struct sockaddr_in)) {
			lck_rw_done(pcbinfo->ipi_lock);
			socket_lock(so, 0);
			return (EINVAL);
		}
#if 0
		/*
		 * We should check the family, but old programs
		 * incorrectly fail to initialize it.
		 */
		if (nam->sa_family != AF_INET) {
			lck_rw_done(pcbinfo->ipi_lock);
			socket_lock(so, 0);
			return (EAFNOSUPPORT);
		}
#endif /* 0 */
		lport = SIN(nam)->sin_port;

		if (IN_MULTICAST(ntohl(SIN(nam)->sin_addr.s_addr))) {
			/*
			 * Treat SO_REUSEADDR as SO_REUSEPORT for multicast;
			 * allow complete duplication of binding if
			 * SO_REUSEPORT is set, or if SO_REUSEADDR is set
			 * and a multicast address is bound on both
			 * new and duplicated sockets.
			 */
			if (so->so_options & SO_REUSEADDR)
				reuseport = SO_REUSEADDR|SO_REUSEPORT;
		} else if (SIN(nam)->sin_addr.s_addr != INADDR_ANY) {
			struct sockaddr_in sin;
			struct ifaddr *ifa;

			/* Sanitized for interface address searches */
			bzero(&sin, sizeof (sin));
			sin.sin_family = AF_INET;
			sin.sin_len = sizeof (struct sockaddr_in);
			sin.sin_addr.s_addr = SIN(nam)->sin_addr.s_addr;

			ifa = ifa_ifwithaddr(SA(&sin));
			if (ifa == NULL) {
				lck_rw_done(pcbinfo->ipi_lock);
				socket_lock(so, 0);
				return (EADDRNOTAVAIL);
			} else {
				/*
				 * Opportunistically determine the outbound
				 * interface that may be used; this may not
				 * hold true if we end up using a route
				 * going over a different interface, e.g.
				 * when sending to a local address.  This
				 * will get updated again after sending.
				 */
				IFA_LOCK(ifa);
				outif = ifa->ifa_ifp;
				IFA_UNLOCK(ifa);
				IFA_REMREF(ifa);
			}
		}
		if (lport != 0) {
			struct inpcb *t;
			uid_t u;

			/* GROSS */
			if (ntohs(lport) < IPPORT_RESERVED) {
				cred = kauth_cred_proc_ref(p);
				error = priv_check_cred(cred,
				    PRIV_NETINET_RESERVEDPORT, 0);
				kauth_cred_unref(&cred);
				if (error != 0) {
					lck_rw_done(pcbinfo->ipi_lock);
					socket_lock(so, 0);
					return (EACCES);
				}
			}
			if (!IN_MULTICAST(ntohl(SIN(nam)->sin_addr.s_addr)) &&
			    (u = kauth_cred_getuid(so->so_cred)) != 0 &&
			    (t = in_pcblookup_local_and_cleanup(
			    inp->inp_pcbinfo, SIN(nam)->sin_addr, lport,
			    INPLOOKUP_WILDCARD)) != NULL &&
			    (SIN(nam)->sin_addr.s_addr != INADDR_ANY ||
			    t->inp_laddr.s_addr != INADDR_ANY ||
			    !(t->inp_socket->so_options & SO_REUSEPORT)) &&
			    (u != kauth_cred_getuid(t->inp_socket->so_cred)) &&
			    !(t->inp_socket->so_flags & SOF_REUSESHAREUID) &&
			    (SIN(nam)->sin_addr.s_addr != INADDR_ANY ||
			    t->inp_laddr.s_addr != INADDR_ANY)) {
				if ((t->inp_socket->so_flags &
				    SOF_NOTIFYCONFLICT) &&
				    !(so->so_flags & SOF_NOTIFYCONFLICT))
					conflict = 1;

				lck_rw_done(pcbinfo->ipi_lock);

				if (conflict)
					in_pcb_conflict_post_msg(lport);

				socket_lock(so, 0);
				return (EADDRINUSE);
			}
			t = in_pcblookup_local_and_cleanup(pcbinfo,
			    SIN(nam)->sin_addr, lport, wild);
			if (t != NULL &&
			    (reuseport & t->inp_socket->so_options) == 0) {
#if INET6
				if (SIN(nam)->sin_addr.s_addr != INADDR_ANY ||
				    t->inp_laddr.s_addr != INADDR_ANY ||
				    SOCK_DOM(so) != PF_INET6 ||
				    SOCK_DOM(t->inp_socket) != PF_INET6)
#endif /* INET6 */
				{

					if ((t->inp_socket->so_flags &
					    SOF_NOTIFYCONFLICT) &&
					    !(so->so_flags & SOF_NOTIFYCONFLICT))
						conflict = 1;

					lck_rw_done(pcbinfo->ipi_lock);

					if (conflict)
						in_pcb_conflict_post_msg(lport);
					socket_lock(so, 0);
					return (EADDRINUSE);
				}
			}
		}
		inp->inp_laddr = SIN(nam)->sin_addr;
		inp->inp_last_outifp = outif;
	}
	if (lport == 0) {
		u_short first, last;
		int count;

		randomport = (so->so_flags & SOF_BINDRANDOMPORT) ||
		    (so->so_type == SOCK_STREAM ? tcp_use_randomport :
		    udp_use_randomport);

		/*
		 * TODO:
		 *
		 * The following should be moved into its own routine and
		 * thus can be shared with in6_pcbsetport(); the latter
		 * currently duplicates the logic.
		 */

		inp->inp_flags |= INP_ANONPORT;

		if (inp->inp_flags & INP_HIGHPORT) {
			first = ipport_hifirstauto;	/* sysctl */
			last  = ipport_hilastauto;
			lastport = &pcbinfo->ipi_lasthi;
		} else if (inp->inp_flags & INP_LOWPORT) {
			cred = kauth_cred_proc_ref(p);
			error = priv_check_cred(cred,
			    PRIV_NETINET_RESERVEDPORT, 0);
			kauth_cred_unref(&cred);
			if (error != 0) {
				lck_rw_done(pcbinfo->ipi_lock);
				socket_lock(so, 0);
				return (error);
			}
			first = ipport_lowfirstauto;	/* 1023 */
			last  = ipport_lowlastauto;	/* 600 */
			lastport = &pcbinfo->ipi_lastlow;
		} else {
			first = ipport_firstauto;	/* sysctl */
			last  = ipport_lastauto;
			lastport = &pcbinfo->ipi_lastport;
		}
		/* No point in randomizing if only one port is available */

		if (first == last)
			randomport = 0;
		/*
		 * Simple check to ensure all ports are not used up causing
		 * a deadlock here.
		 *
		 * We split the two cases (up and down) so that the direction
		 * is not being tested on each round of the loop.
		 */
		if (first > last) {
			/*
			 * counting down
			 */
			if (randomport) {
				read_random(&rand_port, sizeof (rand_port));
				*lastport =
				    first - (rand_port % (first - last));
			}
			count = first - last;

			do {
				if (count-- < 0) {	/* completely used? */
					lck_rw_done(pcbinfo->ipi_lock);
					socket_lock(so, 0);
					inp->inp_laddr.s_addr = INADDR_ANY;
					inp->inp_last_outifp = NULL;
					return (EADDRNOTAVAIL);
				}
				--*lastport;
				if (*lastport > first || *lastport < last)
					*lastport = first;
				lport = htons(*lastport);
			} while (in_pcblookup_local_and_cleanup(pcbinfo,
			    inp->inp_laddr, lport, wild));
		} else {
			/*
			 * counting up
			 */
			if (randomport) {
				read_random(&rand_port, sizeof (rand_port));
				*lastport =
				    first + (rand_port % (first - last));
			}
			count = last - first;

			do {
				if (count-- < 0) {	/* completely used? */
					lck_rw_done(pcbinfo->ipi_lock);
					socket_lock(so, 0);
					inp->inp_laddr.s_addr = INADDR_ANY;
					inp->inp_last_outifp = NULL;
					return (EADDRNOTAVAIL);
				}
				++*lastport;
				if (*lastport < first || *lastport > last)
					*lastport = first;
				lport = htons(*lastport);
			} while (in_pcblookup_local_and_cleanup(pcbinfo,
			    inp->inp_laddr, lport, wild));
		}
	}
	socket_lock(so, 0);
	inp->inp_lport = lport;
	if (in_pcbinshash(inp, 1) != 0) {
		inp->inp_laddr.s_addr = INADDR_ANY;
		inp->inp_lport = 0;
		inp->inp_last_outifp = NULL;
		lck_rw_done(pcbinfo->ipi_lock);
		return (EAGAIN);
	}
	lck_rw_done(pcbinfo->ipi_lock);
	sflt_notify(so, sock_evt_bound, NULL);
	return (0);
}

/*
 * Transform old in_pcbconnect() into an inner subroutine for new
 * in_pcbconnect(); do some validity-checking on the remote address
 * (in "nam") and then determine local host address (i.e., which
 * interface) to use to access that remote host.
 *
 * This routine may alter the caller-supplied remote address "nam".
 *
 * The caller may override the bound-to-interface setting of the socket
 * by specifying the ifscope parameter (e.g. from IP_PKTINFO.)
 *
 * This routine might return an ifp with a reference held if the caller
 * provides a non-NULL outif, even in the error case.  The caller is
 * responsible for releasing its reference.
 *
 * Returns:	0			Success
 *		EINVAL			Invalid argument
 *		EAFNOSUPPORT		Address family not supported
 *		EADDRNOTAVAIL		Address not available
 */
int
in_pcbladdr(struct inpcb *inp, struct sockaddr *nam, struct in_addr *laddr,
    unsigned int ifscope, struct ifnet **outif)
{
	boolean_t nocell = (inp->inp_flags & INP_NO_IFT_CELLULAR);
	struct route *ro = &inp->inp_route;
	struct in_ifaddr *ia = NULL;
	struct sockaddr_in sin;
	int error = 0;

	if (outif != NULL)
		*outif = NULL;
	if (nam->sa_len != sizeof (struct sockaddr_in))
		return (EINVAL);
	if (SIN(nam)->sin_family != AF_INET)
		return (EAFNOSUPPORT);
	if (SIN(nam)->sin_port == 0)
		return (EADDRNOTAVAIL);

	/*
	 * If the destination address is INADDR_ANY,
	 * use the primary local address.
	 * If the supplied address is INADDR_BROADCAST,
	 * and the primary interface supports broadcast,
	 * choose the broadcast address for that interface.
	 */
	if (SIN(nam)->sin_addr.s_addr == INADDR_ANY ||
	    SIN(nam)->sin_addr.s_addr == (u_int32_t)INADDR_BROADCAST) {
		lck_rw_lock_shared(in_ifaddr_rwlock);
		if (!TAILQ_EMPTY(&in_ifaddrhead)) {
			ia = TAILQ_FIRST(&in_ifaddrhead);
			IFA_LOCK_SPIN(&ia->ia_ifa);
			if (SIN(nam)->sin_addr.s_addr == INADDR_ANY) {
				SIN(nam)->sin_addr = IA_SIN(ia)->sin_addr;
			} else if (ia->ia_ifp->if_flags & IFF_BROADCAST) {
				SIN(nam)->sin_addr =
				    SIN(&ia->ia_broadaddr)->sin_addr;
			}
			IFA_UNLOCK(&ia->ia_ifa);
			ia = NULL;
		}
		lck_rw_done(in_ifaddr_rwlock);
	}
	/*
	 * Otherwise, if the socket has already bound the source, just use it.
	 */
	if (inp->inp_laddr.s_addr != INADDR_ANY) {
		VERIFY(ia == NULL);
		*laddr = inp->inp_laddr;
		return (0);
	}

	/*
	 * If the ifscope is specified by the caller (e.g. IP_PKTINFO)
	 * then it overrides the sticky ifscope set for the socket.
	 */
	if (ifscope == IFSCOPE_NONE && (inp->inp_flags & INP_BOUND_IF))
		ifscope = inp->inp_boundifp->if_index;

	/*
	 * If route is known or can be allocated now,
	 * our src addr is taken from the i/f, else punt.
	 * Note that we should check the address family of the cached
	 * destination, in case of sharing the cache with IPv6.
	 */
	if (ro->ro_rt != NULL)
		RT_LOCK_SPIN(ro->ro_rt);
	if (ROUTE_UNUSABLE(ro) || ro->ro_dst.sa_family != AF_INET ||
	    SIN(&ro->ro_dst)->sin_addr.s_addr != SIN(nam)->sin_addr.s_addr ||
	    (inp->inp_socket->so_options & SO_DONTROUTE)) {
		if (ro->ro_rt != NULL)
			RT_UNLOCK(ro->ro_rt);
		ROUTE_RELEASE(ro);
	}
	if (!(inp->inp_socket->so_options & SO_DONTROUTE) &&
	    (ro->ro_rt == NULL || ro->ro_rt->rt_ifp == NULL)) {
		if (ro->ro_rt != NULL)
			RT_UNLOCK(ro->ro_rt);
		ROUTE_RELEASE(ro);
		/* No route yet, so try to acquire one */
		bzero(&ro->ro_dst, sizeof (struct sockaddr_in));
		ro->ro_dst.sa_family = AF_INET;
		ro->ro_dst.sa_len = sizeof (struct sockaddr_in);
		SIN(&ro->ro_dst)->sin_addr = SIN(nam)->sin_addr;
		rtalloc_scoped(ro, ifscope);
		if (ro->ro_rt != NULL)
			RT_LOCK_SPIN(ro->ro_rt);
	}
	/* Sanitized local copy for interface address searches */
	bzero(&sin, sizeof (sin));
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof (struct sockaddr_in);
	sin.sin_addr.s_addr = SIN(nam)->sin_addr.s_addr;
	/*
	 * If we did not find (or use) a route, assume dest is reachable
	 * on a directly connected network and try to find a corresponding
	 * interface to take the source address from.
	 */
	if (ro->ro_rt == NULL) {
		VERIFY(ia == NULL);
		ia = ifatoia(ifa_ifwithdstaddr(SA(&sin)));
		if (ia == NULL)
			ia = ifatoia(ifa_ifwithnet_scoped(SA(&sin), ifscope));
		error = ((ia == NULL) ? ENETUNREACH : 0);
		goto done;
	}
	RT_LOCK_ASSERT_HELD(ro->ro_rt);
	/*
	 * If the outgoing interface on the route found is not
	 * a loopback interface, use the address from that interface.
	 */
	if (!(ro->ro_rt->rt_ifp->if_flags & IFF_LOOPBACK)) {
		VERIFY(ia == NULL);
		/*
		 * If the route points to a cellular interface and the
		 * caller forbids our using interfaces of such type,
		 * pretend that there is no route.
		 */
		if (nocell && IFNET_IS_CELLULAR(ro->ro_rt->rt_ifp)) {
			RT_UNLOCK(ro->ro_rt);
			ROUTE_RELEASE(ro);
			error = EHOSTUNREACH;
		} else {
			/* Become a regular mutex */
			RT_CONVERT_LOCK(ro->ro_rt);
			ia = ifatoia(ro->ro_rt->rt_ifa);
			IFA_ADDREF(&ia->ia_ifa);
			RT_UNLOCK(ro->ro_rt);
			error = 0;
		}
		goto done;
	}
	VERIFY(ro->ro_rt->rt_ifp->if_flags & IFF_LOOPBACK);
	RT_UNLOCK(ro->ro_rt);
	/*
	 * The outgoing interface is marked with 'loopback net', so a route
	 * to ourselves is here.
	 * Try to find the interface of the destination address and then
	 * take the address from there. That interface is not necessarily
	 * a loopback interface.
	 */
	VERIFY(ia == NULL);
	ia = ifatoia(ifa_ifwithdstaddr(SA(&sin)));
	if (ia == NULL)
		ia = ifatoia(ifa_ifwithaddr_scoped(SA(&sin), ifscope));
	if (ia == NULL)
		ia = ifatoia(ifa_ifwithnet_scoped(SA(&sin), ifscope));
	if (ia == NULL) {
		RT_LOCK(ro->ro_rt);
		ia = ifatoia(ro->ro_rt->rt_ifa);
		if (ia != NULL)
			IFA_ADDREF(&ia->ia_ifa);
		RT_UNLOCK(ro->ro_rt);
	}
	error = ((ia == NULL) ? ENETUNREACH : 0);

done:
	/*
	 * If the destination address is multicast and an outgoing
	 * interface has been set as a multicast option, use the
	 * address of that interface as our source address.
	 */
	if (error == 0 && IN_MULTICAST(ntohl(SIN(nam)->sin_addr.s_addr)) &&
	    inp->inp_moptions != NULL) {
		struct ip_moptions *imo;
		struct ifnet *ifp;

		imo = inp->inp_moptions;
		IMO_LOCK(imo);
		if (imo->imo_multicast_ifp != NULL && (ia == NULL ||
		    ia->ia_ifp != imo->imo_multicast_ifp)) {
			ifp = imo->imo_multicast_ifp;
			if (ia != NULL)
				IFA_REMREF(&ia->ia_ifa);
			lck_rw_lock_shared(in_ifaddr_rwlock);
			TAILQ_FOREACH(ia, &in_ifaddrhead, ia_link) {
				if (ia->ia_ifp == ifp)
					break;
			}
			if (ia != NULL)
				IFA_ADDREF(&ia->ia_ifa);
			lck_rw_done(in_ifaddr_rwlock);
			if (ia == NULL)
				error = EADDRNOTAVAIL;
		}
		IMO_UNLOCK(imo);
	}
	/*
	 * Don't do pcblookup call here; return interface in laddr
	 * and exit to caller, that will do the lookup.
	 */
	if (ia != NULL) {
		/*
		 * If the source address belongs to a cellular interface
		 * and the socket forbids our using interfaces of such
		 * type, pretend that there is no source address.
		 */
		IFA_LOCK_SPIN(&ia->ia_ifa);
		if (nocell && IFNET_IS_CELLULAR(ia->ia_ifa.ifa_ifp)) {
			IFA_UNLOCK(&ia->ia_ifa);
			error = EHOSTUNREACH;
		} else if (error == 0) {
			*laddr = ia->ia_addr.sin_addr;
			if (outif != NULL) {
				struct ifnet *ifp;

				if (ro->ro_rt != NULL)
					ifp = ro->ro_rt->rt_ifp;
				else
					ifp = ia->ia_ifp;

				VERIFY(ifp != NULL);
				IFA_CONVERT_LOCK(&ia->ia_ifa);
				ifnet_reference(ifp);	/* for caller */
				if (*outif != NULL)
					ifnet_release(*outif);
				*outif = ifp;
			}
			IFA_UNLOCK(&ia->ia_ifa);
		} else {
			IFA_UNLOCK(&ia->ia_ifa);
		}
		IFA_REMREF(&ia->ia_ifa);
		ia = NULL;
	}

	if (nocell && error == EHOSTUNREACH) {
		soevent(inp->inp_socket, (SO_FILT_HINT_LOCKED |
		    SO_FILT_HINT_IFDENIED));
	}

	return (error);
}

/*
 * Outer subroutine:
 * Connect from a socket to a specified address.
 * Both address and port must be specified in argument sin.
 * If don't have a local address for this socket yet,
 * then pick one.
 *
 * The caller may override the bound-to-interface setting of the socket
 * by specifying the ifscope parameter (e.g. from IP_PKTINFO.)
 */
int
in_pcbconnect(struct inpcb *inp, struct sockaddr *nam, struct proc *p,
    unsigned int ifscope, struct ifnet **outif)
{
	struct in_addr laddr;
	struct sockaddr_in *sin = (struct sockaddr_in *)(void *)nam;
	struct inpcb *pcb;
	int error;

	/*
	 *   Call inner routine, to assign local interface address.
	 */
	if ((error = in_pcbladdr(inp, nam, &laddr, ifscope, outif)) != 0)
		return (error);

	socket_unlock(inp->inp_socket, 0);
	pcb = in_pcblookup_hash(inp->inp_pcbinfo, sin->sin_addr, sin->sin_port,
	    inp->inp_laddr.s_addr ? inp->inp_laddr : laddr,
	    inp->inp_lport, 0, NULL);
	socket_lock(inp->inp_socket, 0);

	/*
	 * Check if the socket is still in a valid state. When we unlock this
	 * embryonic socket, it can get aborted if another thread is closing
	 * the listener (radar 7947600).
	 */
	if ((inp->inp_socket->so_flags & SOF_ABORTED) != 0)
		return (ECONNREFUSED);

	if (pcb != NULL) {
		in_pcb_checkstate(pcb, WNT_RELEASE, pcb == inp ? 1 : 0);
		return (EADDRINUSE);
	}
	if (inp->inp_laddr.s_addr == INADDR_ANY) {
		if (inp->inp_lport == 0) {
			error = in_pcbbind(inp, NULL, p);
			if (error)
				return (error);
		}
		if (!lck_rw_try_lock_exclusive(inp->inp_pcbinfo->ipi_lock)) {
			/*
			 * Lock inversion issue, mostly with udp
			 * multicast packets.
			 */
			socket_unlock(inp->inp_socket, 0);
			lck_rw_lock_exclusive(inp->inp_pcbinfo->ipi_lock);
			socket_lock(inp->inp_socket, 0);
		}
		inp->inp_laddr = laddr;
		/* no reference needed */
		inp->inp_last_outifp = (outif != NULL) ? *outif : NULL;
		inp->inp_flags |= INP_INADDR_ANY;
	} else {
		if (!lck_rw_try_lock_exclusive(inp->inp_pcbinfo->ipi_lock)) {
			/*
			 * Lock inversion issue, mostly with udp
			 * multicast packets.
			 */
			socket_unlock(inp->inp_socket, 0);
			lck_rw_lock_exclusive(inp->inp_pcbinfo->ipi_lock);
			socket_lock(inp->inp_socket, 0);
		}
	}
	inp->inp_faddr = sin->sin_addr;
	inp->inp_fport = sin->sin_port;
	in_pcbrehash(inp);
	lck_rw_done(inp->inp_pcbinfo->ipi_lock);
	return (0);
}

void
in_pcbdisconnect(struct inpcb *inp)
{
	struct socket *so = inp->inp_socket;

	inp->inp_faddr.s_addr = INADDR_ANY;
	inp->inp_fport = 0;

	if (!lck_rw_try_lock_exclusive(inp->inp_pcbinfo->ipi_lock)) {
		/* lock inversion issue, mostly with udp multicast packets */
		socket_unlock(so, 0);
		lck_rw_lock_exclusive(inp->inp_pcbinfo->ipi_lock);
		socket_lock(so, 0);
	}

	in_pcbrehash(inp);
	lck_rw_done(inp->inp_pcbinfo->ipi_lock);
	/*
	 * A multipath subflow socket would have its SS_NOFDREF set by default,
	 * so check for SOF_MP_SUBFLOW socket flag before detaching the PCB;
	 * when the socket is closed for real, SOF_MP_SUBFLOW would be cleared.
	 */
	if (!(so->so_flags & SOF_MP_SUBFLOW) && (so->so_state & SS_NOFDREF))
		in_pcbdetach(inp);
}

void
in_pcbdetach(struct inpcb *inp)
{
	struct socket *so = inp->inp_socket;

	if (so->so_pcb == NULL) {
		/* PCB has been disposed */
		panic("%s: inp=%p so=%p proto=%d so_pcb is null!\n", __func__,
		    inp, so, SOCK_PROTO(so));
		/* NOTREACHED */
	}

#if IPSEC
	if (inp->inp_sp != NULL) {
		(void) ipsec4_delete_pcbpolicy(inp);
	}
#endif /* IPSEC */

	/* mark socket state as dead */
	if (in_pcb_checkstate(inp, WNT_STOPUSING, 1) != WNT_STOPUSING) {
		panic("%s: so=%p proto=%d couldn't set to STOPUSING\n",
		    __func__, so, SOCK_PROTO(so));
		/* NOTREACHED */
	}

	if (!(so->so_flags & SOF_PCBCLEARING)) {
		struct ip_moptions *imo;

		inp->inp_vflag = 0;
		if (inp->inp_options != NULL) {
			(void) m_free(inp->inp_options);
			inp->inp_options = NULL;
		}
		ROUTE_RELEASE(&inp->inp_route);
		imo = inp->inp_moptions;
		inp->inp_moptions = NULL;
		if (imo != NULL)
			IMO_REMREF(imo);
		sofreelastref(so, 0);
		inp->inp_state = INPCB_STATE_DEAD;
		/* makes sure we're not called twice from so_close */
		so->so_flags |= SOF_PCBCLEARING;

		inpcb_gc_sched(inp->inp_pcbinfo, INPCB_TIMER_FAST);
	}
}


void
in_pcbdispose(struct inpcb *inp)
{
	struct socket *so = inp->inp_socket;
	struct inpcbinfo *ipi = inp->inp_pcbinfo;

	if (so != NULL && so->so_usecount != 0) {
		panic("%s: so %p [%d,%d] usecount %d lockhistory %s\n",
		    __func__, so, SOCK_DOM(so), SOCK_TYPE(so), so->so_usecount,
		    solockhistory_nr(so));
		/* NOTREACHED */
	} else if (inp->inp_wantcnt != WNT_STOPUSING) {
		if (so != NULL) {
			panic_plain("%s: inp %p invalid wantcnt %d, so %p "
			    "[%d,%d] usecount %d retaincnt %d state 0x%x "
			    "flags 0x%x lockhistory %s\n", __func__, inp,
			    inp->inp_wantcnt, so, SOCK_DOM(so), SOCK_TYPE(so),
			    so->so_usecount, so->so_retaincnt, so->so_state,
			    so->so_flags, solockhistory_nr(so));
			/* NOTREACHED */
		} else {
			panic("%s: inp %p invalid wantcnt %d no socket\n",
			    __func__, inp, inp->inp_wantcnt);
			/* NOTREACHED */
		}
	}

	lck_rw_assert(ipi->ipi_lock, LCK_RW_ASSERT_EXCLUSIVE);

	inp->inp_gencnt = ++ipi->ipi_gencnt;
	/* access ipi in in_pcbremlists */
	in_pcbremlists(inp);

	if (so != NULL) {
		if (so->so_proto->pr_flags & PR_PCBLOCK) {
			sofreelastref(so, 0);
			if (so->so_rcv.sb_cc > 0 || so->so_snd.sb_cc > 0) {
				/*
				 * selthreadclear() already called
				 * during sofreelastref() above.
				 */
				sbrelease(&so->so_rcv);
				sbrelease(&so->so_snd);
			}
			if (so->so_head != NULL) {
				panic("%s: so=%p head still exist\n",
				    __func__, so);
				/* NOTREACHED */
			}
			lck_mtx_unlock(&inp->inpcb_mtx);
			lck_mtx_destroy(&inp->inpcb_mtx, ipi->ipi_lock_grp);
		}
		/* makes sure we're not called twice from so_close */
		so->so_flags |= SOF_PCBCLEARING;
		so->so_saved_pcb = (caddr_t)inp;
		so->so_pcb = NULL;
		inp->inp_socket = NULL;
#if CONFIG_MACF_NET
		mac_inpcb_label_destroy(inp);
#endif /* CONFIG_MACF_NET */
		/*
		 * In case there a route cached after a detach (possible
		 * in the tcp case), make sure that it is freed before
		 * we deallocate the structure.
		 */
		ROUTE_RELEASE(&inp->inp_route);
		if (!so->cached_in_sock_layer) {
			zfree(ipi->ipi_zone, inp);
		}
		sodealloc(so);
	}
}

/*
 * The calling convention of in_getsockaddr() and in_getpeeraddr() was
 * modified to match the pru_sockaddr() and pru_peeraddr() entry points
 * in struct pr_usrreqs, so that protocols can just reference then directly
 * without the need for a wrapper function.
 */
int
in_getsockaddr(struct socket *so, struct sockaddr **nam)
{
	struct inpcb *inp;
	struct sockaddr_in *sin;

	/*
	 * Do the malloc first in case it blocks.
	 */
	MALLOC(sin, struct sockaddr_in *, sizeof (*sin), M_SONAME, M_WAITOK);
	if (sin == NULL)
		return (ENOBUFS);
	bzero(sin, sizeof (*sin));
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof (*sin);

	if ((inp = sotoinpcb(so)) == NULL) {
		FREE(sin, M_SONAME);
		return (EINVAL);
	}
	sin->sin_port = inp->inp_lport;
	sin->sin_addr = inp->inp_laddr;

	*nam = (struct sockaddr *)sin;
	return (0);
}

int
in_getsockaddr_s(struct socket *so, struct sockaddr_storage *ss)
{
	struct sockaddr_in *sin = SIN(ss);
	struct inpcb *inp;

	VERIFY(ss != NULL);
	bzero(ss, sizeof (*ss));

	sin->sin_family = AF_INET;
	sin->sin_len = sizeof (*sin);

	if ((inp = sotoinpcb(so)) == NULL ||
	    (inp->inp_flags2 & INP2_WANT_FLOW_DIVERT))
		return (inp == NULL ? EINVAL : EPROTOTYPE);

	sin->sin_port = inp->inp_lport;
	sin->sin_addr = inp->inp_laddr;
	return (0);
}

int
in_getpeeraddr(struct socket *so, struct sockaddr **nam)
{
	struct inpcb *inp;
	struct sockaddr_in *sin;

	/*
	 * Do the malloc first in case it blocks.
	 */
	MALLOC(sin, struct sockaddr_in *, sizeof (*sin), M_SONAME, M_WAITOK);
	if (sin == NULL)
		return (ENOBUFS);
	bzero((caddr_t)sin, sizeof (*sin));
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof (*sin);

	if ((inp = sotoinpcb(so)) == NULL) {
		FREE(sin, M_SONAME);
		return (EINVAL);
	}
	sin->sin_port = inp->inp_fport;
	sin->sin_addr = inp->inp_faddr;

	*nam = (struct sockaddr *)sin;
	return (0);
}

int
in_getpeeraddr_s(struct socket *so, struct sockaddr_storage *ss)
{
	struct sockaddr_in *sin = SIN(ss);
	struct inpcb *inp;

	VERIFY(ss != NULL);
	bzero(ss, sizeof (*ss));

	sin->sin_family = AF_INET;
	sin->sin_len = sizeof (*sin);

	if ((inp = sotoinpcb(so)) == NULL ||
	    (inp->inp_flags2 & INP2_WANT_FLOW_DIVERT)) {
		return (inp == NULL ? EINVAL : EPROTOTYPE);
	}

	sin->sin_port = inp->inp_fport;
	sin->sin_addr = inp->inp_faddr;
	return (0);
}

void
in_pcbnotifyall(struct inpcbinfo *pcbinfo, struct in_addr faddr,
    int errno, void (*notify)(struct inpcb *, int))
{
	struct inpcb *inp;

	lck_rw_lock_shared(pcbinfo->ipi_lock);

	LIST_FOREACH(inp, pcbinfo->ipi_listhead, inp_list) {
#if INET6
		if (!(inp->inp_vflag & INP_IPV4))
			continue;
#endif /* INET6 */
		if (inp->inp_faddr.s_addr != faddr.s_addr ||
		    inp->inp_socket == NULL)
			continue;
		if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) == WNT_STOPUSING)
			continue;
		socket_lock(inp->inp_socket, 1);
		(*notify)(inp, errno);
		(void) in_pcb_checkstate(inp, WNT_RELEASE, 1);
		socket_unlock(inp->inp_socket, 1);
	}
	lck_rw_done(pcbinfo->ipi_lock);
}

/*
 * Check for alternatives when higher level complains
 * about service problems.  For now, invalidate cached
 * routing information.  If the route was created dynamically
 * (by a redirect), time to try a default gateway again.
 */
void
in_losing(struct inpcb *inp)
{
	boolean_t release = FALSE;
	struct rtentry *rt;
	struct rt_addrinfo info;

	if ((rt = inp->inp_route.ro_rt) != NULL) {
		struct in_ifaddr *ia = NULL;

		bzero((caddr_t)&info, sizeof (info));
		RT_LOCK(rt);
		info.rti_info[RTAX_DST] =
		    (struct sockaddr *)&inp->inp_route.ro_dst;
		info.rti_info[RTAX_GATEWAY] = rt->rt_gateway;
		info.rti_info[RTAX_NETMASK] = rt_mask(rt);
		rt_missmsg(RTM_LOSING, &info, rt->rt_flags, 0);
		if (rt->rt_flags & RTF_DYNAMIC) {
			/*
			 * Prevent another thread from modifying rt_key,
			 * rt_gateway via rt_setgate() after rt_lock is
			 * dropped by marking the route as defunct.
			 */
			rt->rt_flags |= RTF_CONDEMNED;
			RT_UNLOCK(rt);
			(void) rtrequest(RTM_DELETE, rt_key(rt),
			    rt->rt_gateway, rt_mask(rt), rt->rt_flags, NULL);
		} else {
			RT_UNLOCK(rt);
		}
		/* if the address is gone keep the old route in the pcb */
		if (inp->inp_laddr.s_addr != INADDR_ANY &&
		    (ia = ifa_foraddr(inp->inp_laddr.s_addr)) != NULL) {
			/*
			 * Address is around; ditch the route.  A new route
			 * can be allocated the next time output is attempted.
			 */
			release = TRUE;
		}
		if (ia != NULL)
			IFA_REMREF(&ia->ia_ifa);
	}
	if (rt == NULL || release)
		ROUTE_RELEASE(&inp->inp_route);
}

/*
 * After a routing change, flush old routing
 * and allocate a (hopefully) better one.
 */
void
in_rtchange(struct inpcb *inp, int errno)
{
#pragma unused(errno)
	boolean_t release = FALSE;
	struct rtentry *rt;

	if ((rt = inp->inp_route.ro_rt) != NULL) {
		struct in_ifaddr *ia = NULL;

		/* if address is gone, keep the old route */
		if (inp->inp_laddr.s_addr != INADDR_ANY &&
		    (ia = ifa_foraddr(inp->inp_laddr.s_addr)) != NULL) {
			/*
			 * Address is around; ditch the route.  A new route
			 * can be allocated the next time output is attempted.
			 */
			release = TRUE;
		}
		if (ia != NULL)
			IFA_REMREF(&ia->ia_ifa);
	}
	if (rt == NULL || release)
		ROUTE_RELEASE(&inp->inp_route);
}

/*
 * Lookup a PCB based on the local address and port.
 */
struct inpcb *
in_pcblookup_local(struct inpcbinfo *pcbinfo, struct in_addr laddr,
    unsigned int lport_arg, int wild_okay)
{
	struct inpcb *inp;
	int matchwild = 3, wildcard;
	u_short lport = lport_arg;

	KERNEL_DEBUG(DBG_FNC_PCB_LOOKUP | DBG_FUNC_START, 0, 0, 0, 0, 0);

	if (!wild_okay) {
		struct inpcbhead *head;
		/*
		 * Look for an unconnected (wildcard foreign addr) PCB that
		 * matches the local address and port we're looking for.
		 */
		head = &pcbinfo->ipi_hashbase[INP_PCBHASH(INADDR_ANY, lport, 0,
		    pcbinfo->ipi_hashmask)];
		LIST_FOREACH(inp, head, inp_hash) {
#if INET6
			if (!(inp->inp_vflag & INP_IPV4))
				continue;
#endif /* INET6 */
			if (inp->inp_faddr.s_addr == INADDR_ANY &&
			    inp->inp_laddr.s_addr == laddr.s_addr &&
			    inp->inp_lport == lport) {
				/*
				 * Found.
				 */
				return (inp);
			}
		}
		/*
		 * Not found.
		 */
		KERNEL_DEBUG(DBG_FNC_PCB_LOOKUP | DBG_FUNC_END, 0, 0, 0, 0, 0);
		return (NULL);
	} else {
		struct inpcbporthead *porthash;
		struct inpcbport *phd;
		struct inpcb *match = NULL;
		/*
		 * Best fit PCB lookup.
		 *
		 * First see if this local port is in use by looking on the
		 * port hash list.
		 */
		porthash = &pcbinfo->ipi_porthashbase[INP_PCBPORTHASH(lport,
		    pcbinfo->ipi_porthashmask)];
		LIST_FOREACH(phd, porthash, phd_hash) {
			if (phd->phd_port == lport)
				break;
		}
		if (phd != NULL) {
			/*
			 * Port is in use by one or more PCBs. Look for best
			 * fit.
			 */
			LIST_FOREACH(inp, &phd->phd_pcblist, inp_portlist) {
				wildcard = 0;
#if INET6
				if (!(inp->inp_vflag & INP_IPV4))
					continue;
#endif /* INET6 */
				if (inp->inp_faddr.s_addr != INADDR_ANY)
					wildcard++;
				if (inp->inp_laddr.s_addr != INADDR_ANY) {
					if (laddr.s_addr == INADDR_ANY)
						wildcard++;
					else if (inp->inp_laddr.s_addr !=
					    laddr.s_addr)
						continue;
				} else {
					if (laddr.s_addr != INADDR_ANY)
						wildcard++;
				}
				if (wildcard < matchwild) {
					match = inp;
					matchwild = wildcard;
					if (matchwild == 0) {
						break;
					}
				}
			}
		}
		KERNEL_DEBUG(DBG_FNC_PCB_LOOKUP | DBG_FUNC_END, match,
		    0, 0, 0, 0);
		return (match);
	}
}

/*
 * Check if PCB exists in hash list.
 */
int
in_pcblookup_hash_exists(struct inpcbinfo *pcbinfo, struct in_addr faddr,
    u_int fport_arg, struct in_addr laddr, u_int lport_arg, int wildcard,
    uid_t *uid, gid_t *gid, struct ifnet *ifp)
{
	struct inpcbhead *head;
	struct inpcb *inp;
	u_short fport = fport_arg, lport = lport_arg;
	int found = 0;
	struct inpcb *local_wild = NULL;
#if INET6
	struct inpcb *local_wild_mapped = NULL;
#endif /* INET6 */

	*uid = UID_MAX;
	*gid = GID_MAX;

	/*
	 * We may have found the pcb in the last lookup - check this first.
	 */

	lck_rw_lock_shared(pcbinfo->ipi_lock);

	/*
	 * First look for an exact match.
	 */
	head = &pcbinfo->ipi_hashbase[INP_PCBHASH(faddr.s_addr, lport, fport,
	    pcbinfo->ipi_hashmask)];
	LIST_FOREACH(inp, head, inp_hash) {
#if INET6
		if (!(inp->inp_vflag & INP_IPV4))
			continue;
#endif /* INET6 */
		if (inp_restricted(inp, ifp))
			continue;

		if (ifp != NULL && IFNET_IS_CELLULAR(ifp) &&
		    (inp->inp_flags & INP_NO_IFT_CELLULAR))
			continue;

		if (inp->inp_faddr.s_addr == faddr.s_addr &&
		    inp->inp_laddr.s_addr == laddr.s_addr &&
		    inp->inp_fport == fport &&
		    inp->inp_lport == lport) {
			if ((found = (inp->inp_socket != NULL))) {
				/*
				 * Found.
				 */
				*uid = kauth_cred_getuid(
				    inp->inp_socket->so_cred);
				*gid = kauth_cred_getgid(
				    inp->inp_socket->so_cred);
			}
			lck_rw_done(pcbinfo->ipi_lock);
			return (found);
		}
	}

	if (!wildcard) {
		/*
		 * Not found.
		 */
		lck_rw_done(pcbinfo->ipi_lock);
		return (0);
	}

	head = &pcbinfo->ipi_hashbase[INP_PCBHASH(INADDR_ANY, lport, 0,
	    pcbinfo->ipi_hashmask)];
	LIST_FOREACH(inp, head, inp_hash) {
#if INET6
		if (!(inp->inp_vflag & INP_IPV4))
			continue;
#endif /* INET6 */
		if (inp_restricted(inp, ifp))
			continue;

		if (ifp != NULL && IFNET_IS_CELLULAR(ifp) &&
		    (inp->inp_flags & INP_NO_IFT_CELLULAR))
			continue;

		if (inp->inp_faddr.s_addr == INADDR_ANY &&
		    inp->inp_lport == lport) {
			if (inp->inp_laddr.s_addr == laddr.s_addr) {
				if ((found = (inp->inp_socket != NULL))) {
					*uid = kauth_cred_getuid(
					    inp->inp_socket->so_cred);
					*gid = kauth_cred_getgid(
					    inp->inp_socket->so_cred);
				}
				lck_rw_done(pcbinfo->ipi_lock);
				return (found);
			} else if (inp->inp_laddr.s_addr == INADDR_ANY) {
#if INET6
				if (inp->inp_socket &&
				    SOCK_CHECK_DOM(inp->inp_socket, PF_INET6))
					local_wild_mapped = inp;
				else
#endif /* INET6 */
					local_wild = inp;
			}
		}
	}
	if (local_wild == NULL) {
#if INET6
		if (local_wild_mapped != NULL) {
			if ((found = (local_wild_mapped->inp_socket != NULL))) {
				*uid = kauth_cred_getuid(
				    local_wild_mapped->inp_socket->so_cred);
				*gid = kauth_cred_getgid(
				    local_wild_mapped->inp_socket->so_cred);
			}
			lck_rw_done(pcbinfo->ipi_lock);
			return (found);
		}
#endif /* INET6 */
		lck_rw_done(pcbinfo->ipi_lock);
		return (0);
	}
	if ((found = (local_wild->inp_socket != NULL))) {
		*uid = kauth_cred_getuid(
		    local_wild->inp_socket->so_cred);
		*gid = kauth_cred_getgid(
		    local_wild->inp_socket->so_cred);
	}
	lck_rw_done(pcbinfo->ipi_lock);
	return (found);
}

/*
 * Lookup PCB in hash list.
 */
struct inpcb *
in_pcblookup_hash(struct inpcbinfo *pcbinfo, struct in_addr faddr,
    u_int fport_arg, struct in_addr laddr, u_int lport_arg, int wildcard,
    struct ifnet *ifp)
{
	struct inpcbhead *head;
	struct inpcb *inp;
	u_short fport = fport_arg, lport = lport_arg;
	struct inpcb *local_wild = NULL;
#if INET6
	struct inpcb *local_wild_mapped = NULL;
#endif /* INET6 */

	/*
	 * We may have found the pcb in the last lookup - check this first.
	 */

	lck_rw_lock_shared(pcbinfo->ipi_lock);

	/*
	 * First look for an exact match.
	 */
	head = &pcbinfo->ipi_hashbase[INP_PCBHASH(faddr.s_addr, lport, fport,
	    pcbinfo->ipi_hashmask)];
	LIST_FOREACH(inp, head, inp_hash) {
#if INET6
		if (!(inp->inp_vflag & INP_IPV4))
			continue;
#endif /* INET6 */
		if (inp_restricted(inp, ifp))
			continue;

		if (ifp != NULL && IFNET_IS_CELLULAR(ifp) &&
		    (inp->inp_flags & INP_NO_IFT_CELLULAR))
			continue;

		if (inp->inp_faddr.s_addr == faddr.s_addr &&
		    inp->inp_laddr.s_addr == laddr.s_addr &&
		    inp->inp_fport == fport &&
		    inp->inp_lport == lport) {
			/*
			 * Found.
			 */
			if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) !=
			    WNT_STOPUSING) {
				lck_rw_done(pcbinfo->ipi_lock);
				return (inp);
			} else {
				/* it's there but dead, say it isn't found */
				lck_rw_done(pcbinfo->ipi_lock);
				return (NULL);
			}
		}
	}

	if (!wildcard) {
		/*
		 * Not found.
		 */
		lck_rw_done(pcbinfo->ipi_lock);
		return (NULL);
	}

	head = &pcbinfo->ipi_hashbase[INP_PCBHASH(INADDR_ANY, lport, 0,
	    pcbinfo->ipi_hashmask)];
	LIST_FOREACH(inp, head, inp_hash) {
#if INET6
		if (!(inp->inp_vflag & INP_IPV4))
			continue;
#endif /* INET6 */
		if (inp_restricted(inp, ifp))
			continue;

		if (ifp != NULL && IFNET_IS_CELLULAR(ifp) &&
		    (inp->inp_flags & INP_NO_IFT_CELLULAR))
			continue;

		if (inp->inp_faddr.s_addr == INADDR_ANY &&
		    inp->inp_lport == lport) {
			if (inp->inp_laddr.s_addr == laddr.s_addr) {
				if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) !=
				    WNT_STOPUSING) {
					lck_rw_done(pcbinfo->ipi_lock);
					return (inp);
				} else {
					/* it's dead; say it isn't found */
					lck_rw_done(pcbinfo->ipi_lock);
					return (NULL);
				}
			} else if (inp->inp_laddr.s_addr == INADDR_ANY) {
#if INET6
				if (SOCK_CHECK_DOM(inp->inp_socket, PF_INET6))
					local_wild_mapped = inp;
				else
#endif /* INET6 */
					local_wild = inp;
			}
		}
	}
	if (local_wild == NULL) {
#if INET6
		if (local_wild_mapped != NULL) {
			if (in_pcb_checkstate(local_wild_mapped,
			    WNT_ACQUIRE, 0) != WNT_STOPUSING) {
				lck_rw_done(pcbinfo->ipi_lock);
				return (local_wild_mapped);
			} else {
				/* it's dead; say it isn't found */
				lck_rw_done(pcbinfo->ipi_lock);
				return (NULL);
			}
		}
#endif /* INET6 */
		lck_rw_done(pcbinfo->ipi_lock);
		return (NULL);
	}
	if (in_pcb_checkstate(local_wild, WNT_ACQUIRE, 0) != WNT_STOPUSING) {
		lck_rw_done(pcbinfo->ipi_lock);
		return (local_wild);
	}
	/*
	 * It's either not found or is already dead.
	 */
	lck_rw_done(pcbinfo->ipi_lock);
	return (NULL);
}

/*
 * Insert PCB onto various hash lists.
 */
int
in_pcbinshash(struct inpcb *inp, int locked)
{
	struct inpcbhead *pcbhash;
	struct inpcbporthead *pcbporthash;
	struct inpcbinfo *pcbinfo = inp->inp_pcbinfo;
	struct inpcbport *phd;
	u_int32_t hashkey_faddr;

	if (!locked) {
		if (!lck_rw_try_lock_exclusive(pcbinfo->ipi_lock)) {
			/*
			 * Lock inversion issue, mostly with udp
			 * multicast packets
			 */
			socket_unlock(inp->inp_socket, 0);
			lck_rw_lock_exclusive(pcbinfo->ipi_lock);
			socket_lock(inp->inp_socket, 0);
			if (inp->inp_state == INPCB_STATE_DEAD) {
				/*
				 * The socket got dropped when
				 * it was unlocked
				 */
				lck_rw_done(pcbinfo->ipi_lock);
				return (ECONNABORTED);
			}
		}
	}

#if INET6
	if (inp->inp_vflag & INP_IPV6)
		hashkey_faddr = inp->in6p_faddr.s6_addr32[3] /* XXX */;
	else
#endif /* INET6 */
		hashkey_faddr = inp->inp_faddr.s_addr;

	inp->inp_hash_element = INP_PCBHASH(hashkey_faddr, inp->inp_lport,
	    inp->inp_fport, pcbinfo->ipi_hashmask);

	pcbhash = &pcbinfo->ipi_hashbase[inp->inp_hash_element];

	pcbporthash = &pcbinfo->ipi_porthashbase[INP_PCBPORTHASH(inp->inp_lport,
	    pcbinfo->ipi_porthashmask)];

	/*
	 * Go through port list and look for a head for this lport.
	 */
	LIST_FOREACH(phd, pcbporthash, phd_hash) {
		if (phd->phd_port == inp->inp_lport)
			break;
	}

	VERIFY(inp->inp_state != INPCB_STATE_DEAD);

	/*
	 * If none exists, malloc one and tack it on.
	 */
	if (phd == NULL) {
		MALLOC(phd, struct inpcbport *, sizeof (struct inpcbport),
		    M_PCB, M_WAITOK);
		if (phd == NULL) {
			if (!locked)
				lck_rw_done(pcbinfo->ipi_lock);
			return (ENOBUFS); /* XXX */
		}
		phd->phd_port = inp->inp_lport;
		LIST_INIT(&phd->phd_pcblist);
		LIST_INSERT_HEAD(pcbporthash, phd, phd_hash);
	}
	inp->inp_phd = phd;
	LIST_INSERT_HEAD(&phd->phd_pcblist, inp, inp_portlist);
	LIST_INSERT_HEAD(pcbhash, inp, inp_hash);
	if (!locked)
		lck_rw_done(pcbinfo->ipi_lock);
	return (0);
}

/*
 * Move PCB to the proper hash bucket when { faddr, fport } have  been
 * changed. NOTE: This does not handle the case of the lport changing (the
 * hashed port list would have to be updated as well), so the lport must
 * not change after in_pcbinshash() has been called.
 */
void
in_pcbrehash(struct inpcb *inp)
{
	struct inpcbhead *head;
	u_int32_t hashkey_faddr;

#if INET6
	if (inp->inp_vflag & INP_IPV6)
		hashkey_faddr = inp->in6p_faddr.s6_addr32[3] /* XXX */;
	else
#endif /* INET6 */
		hashkey_faddr = inp->inp_faddr.s_addr;

	inp->inp_hash_element = INP_PCBHASH(hashkey_faddr, inp->inp_lport,
	    inp->inp_fport, inp->inp_pcbinfo->ipi_hashmask);
	head = &inp->inp_pcbinfo->ipi_hashbase[inp->inp_hash_element];

	LIST_REMOVE(inp, inp_hash);
	LIST_INSERT_HEAD(head, inp, inp_hash);
}

/*
 * Remove PCB from various lists.
 * Must be called pcbinfo lock is held in exclusive mode.
 */
void
in_pcbremlists(struct inpcb *inp)
{
	inp->inp_gencnt = ++inp->inp_pcbinfo->ipi_gencnt;

	if (inp->inp_lport) {
		struct inpcbport *phd = inp->inp_phd;

		LIST_REMOVE(inp, inp_hash);
		LIST_REMOVE(inp, inp_portlist);
		if (phd != NULL && (LIST_FIRST(&phd->phd_pcblist) == NULL)) {
			LIST_REMOVE(phd, phd_hash);
			FREE(phd, M_PCB);
		}
	}

	if (inp->inp_flags2 & INP2_TIMEWAIT) {
		/* Remove from time-wait queue */
		tcp_remove_from_time_wait(inp);
		inp->inp_flags2 &= ~INP2_TIMEWAIT;
		VERIFY(inp->inp_pcbinfo->ipi_twcount != 0);
		inp->inp_pcbinfo->ipi_twcount--;
	} else {
		/* Remove from global inp list if it is not time-wait */
		LIST_REMOVE(inp, inp_list);
	}

	if (inp->inp_flags2 & INP2_IN_FCTREE) {
		inp_fc_getinp(inp->inp_flowhash, (INPFC_SOLOCKED|INPFC_REMOVE));
		VERIFY(!(inp->inp_flags2 & INP2_IN_FCTREE));
	}

	inp->inp_pcbinfo->ipi_count--;
}

/*
 * Mechanism used to defer the memory release of PCBs
 * The pcb list will contain the pcb until the reaper can clean it up if
 * the following conditions are met:
 *	1) state "DEAD",
 *	2) wantcnt is STOPUSING
 *	3) usecount is 0
 * This function will be called to either mark the pcb as
 */
int
in_pcb_checkstate(struct inpcb *pcb, int mode, int locked)
{
	volatile UInt32 *wantcnt = (volatile UInt32 *)&pcb->inp_wantcnt;
	UInt32 origwant;
	UInt32 newwant;

	switch (mode) {
	case WNT_STOPUSING:
		/*
		 * Try to mark the pcb as ready for recycling.  CAS with
		 * STOPUSING, if success we're good, if it's in use, will
		 * be marked later
		 */
		if (locked == 0)
			socket_lock(pcb->inp_socket, 1);
		pcb->inp_state = INPCB_STATE_DEAD;

stopusing:
		if (pcb->inp_socket->so_usecount < 0) {
			panic("%s: pcb=%p so=%p usecount is negative\n",
			    __func__, pcb, pcb->inp_socket);
			/* NOTREACHED */
		}
		if (locked == 0)
			socket_unlock(pcb->inp_socket, 1);

		inpcb_gc_sched(pcb->inp_pcbinfo, INPCB_TIMER_FAST);

		origwant = *wantcnt;
		if ((UInt16) origwant == 0xffff) /* should stop using */
			return (WNT_STOPUSING);
		newwant = 0xffff;
		if ((UInt16) origwant == 0) {
			/* try to mark it as unsuable now */
			OSCompareAndSwap(origwant, newwant, wantcnt);
		}
		return (WNT_STOPUSING);
		break;

	case WNT_ACQUIRE:
		/*
		 * Try to increase reference to pcb.  If WNT_STOPUSING
		 * should bail out.  If socket state DEAD, try to set count
		 * to STOPUSING, return failed otherwise increase cnt.
		 */
		do {
			origwant = *wantcnt;
			if ((UInt16) origwant == 0xffff) {
				/* should stop using */
				return (WNT_STOPUSING);
			}
			newwant = origwant + 1;
		} while (!OSCompareAndSwap(origwant, newwant, wantcnt));
		return (WNT_ACQUIRE);
		break;

	case WNT_RELEASE:
		/*
		 * Release reference.  If result is null and pcb state
		 * is DEAD, set wanted bit to STOPUSING
		 */
		if (locked == 0)
			socket_lock(pcb->inp_socket, 1);

		do {
			origwant = *wantcnt;
			if ((UInt16) origwant == 0x0) {
				panic("%s: pcb=%p release with zero count",
				    __func__, pcb);
				/* NOTREACHED */
			}
			if ((UInt16) origwant == 0xffff) {
				/* should stop using */
				if (locked == 0)
					socket_unlock(pcb->inp_socket, 1);
				return (WNT_STOPUSING);
			}
			newwant = origwant - 1;
		} while (!OSCompareAndSwap(origwant, newwant, wantcnt));

		if (pcb->inp_state == INPCB_STATE_DEAD)
			goto stopusing;
		if (pcb->inp_socket->so_usecount < 0) {
			panic("%s: RELEASE pcb=%p so=%p usecount is negative\n",
			    __func__, pcb, pcb->inp_socket);
			/* NOTREACHED */
		}

		if (locked == 0)
			socket_unlock(pcb->inp_socket, 1);
		return (WNT_RELEASE);
		break;

	default:
		panic("%s: so=%p not a valid state =%x\n", __func__,
		    pcb->inp_socket, mode);
		/* NOTREACHED */
	}

	/* NOTREACHED */
	return (mode);
}

/*
 * inpcb_to_compat copies specific bits of an inpcb to a inpcb_compat.
 * The inpcb_compat data structure is passed to user space and must
 * not change. We intentionally avoid copying pointers.
 */
void
inpcb_to_compat(struct inpcb *inp, struct inpcb_compat *inp_compat)
{
	bzero(inp_compat, sizeof (*inp_compat));
	inp_compat->inp_fport = inp->inp_fport;
	inp_compat->inp_lport = inp->inp_lport;
	inp_compat->nat_owner = 0;
	inp_compat->nat_cookie = 0;
	inp_compat->inp_gencnt = inp->inp_gencnt;
	inp_compat->inp_flags = inp->inp_flags;
	inp_compat->inp_flow = inp->inp_flow;
	inp_compat->inp_vflag = inp->inp_vflag;
	inp_compat->inp_ip_ttl = inp->inp_ip_ttl;
	inp_compat->inp_ip_p = inp->inp_ip_p;
	inp_compat->inp_dependfaddr.inp6_foreign =
	    inp->inp_dependfaddr.inp6_foreign;
	inp_compat->inp_dependladdr.inp6_local =
	    inp->inp_dependladdr.inp6_local;
	inp_compat->inp_depend4.inp4_ip_tos = inp->inp_depend4.inp4_ip_tos;
	inp_compat->inp_depend6.inp6_hlim = 0;
	inp_compat->inp_depend6.inp6_cksum = inp->inp_depend6.inp6_cksum;
	inp_compat->inp_depend6.inp6_ifindex = 0;
	inp_compat->inp_depend6.inp6_hops = inp->inp_depend6.inp6_hops;
}

void
inpcb_to_xinpcb64(struct inpcb *inp, struct xinpcb64 *xinp)
{
	xinp->inp_fport = inp->inp_fport;
	xinp->inp_lport = inp->inp_lport;
	xinp->inp_gencnt = inp->inp_gencnt;
	xinp->inp_flags = inp->inp_flags;
	xinp->inp_flow = inp->inp_flow;
	xinp->inp_vflag = inp->inp_vflag;
	xinp->inp_ip_ttl = inp->inp_ip_ttl;
	xinp->inp_ip_p = inp->inp_ip_p;
	xinp->inp_dependfaddr.inp6_foreign = inp->inp_dependfaddr.inp6_foreign;
	xinp->inp_dependladdr.inp6_local = inp->inp_dependladdr.inp6_local;
	xinp->inp_depend4.inp4_ip_tos = inp->inp_depend4.inp4_ip_tos;
	xinp->inp_depend6.inp6_hlim = 0;
	xinp->inp_depend6.inp6_cksum = inp->inp_depend6.inp6_cksum;
	xinp->inp_depend6.inp6_ifindex = 0;
	xinp->inp_depend6.inp6_hops = inp->inp_depend6.inp6_hops;
}

/*
 * The following routines implement this scheme:
 *
 * Callers of ip_output() that intend to cache the route in the inpcb pass
 * a local copy of the struct route to ip_output().  Using a local copy of
 * the cached route significantly simplifies things as IP no longer has to
 * worry about having exclusive access to the passed in struct route, since
 * it's defined in the caller's stack; in essence, this allows for a lock-
 * less operation when updating the struct route at the IP level and below,
 * whenever necessary. The scheme works as follows:
 *
 * Prior to dropping the socket's lock and calling ip_output(), the caller
 * copies the struct route from the inpcb into its stack, and adds a reference
 * to the cached route entry, if there was any.  The socket's lock is then
 * dropped and ip_output() is called with a pointer to the copy of struct
 * route defined on the stack (not to the one in the inpcb.)
 *
 * Upon returning from ip_output(), the caller then acquires the socket's
 * lock and synchronizes the cache; if there is no route cached in the inpcb,
 * it copies the local copy of struct route (which may or may not contain any
 * route) back into the cache; otherwise, if the inpcb has a route cached in
 * it, the one in the local copy will be freed, if there's any.  Trashing the
 * cached route in the inpcb can be avoided because ip_output() is single-
 * threaded per-PCB (i.e. multiple transmits on a PCB are always serialized
 * by the socket/transport layer.)
 */
void
inp_route_copyout(struct inpcb *inp, struct route *dst)
{
	struct route *src = &inp->inp_route;

	lck_mtx_assert(&inp->inpcb_mtx, LCK_MTX_ASSERT_OWNED);

	/*
	 * If the route in the PCB is stale or not for IPv4, blow it away;
	 * this is possible in the case of IPv4-mapped address case.
	 */
	if (ROUTE_UNUSABLE(src) || rt_key(src->ro_rt)->sa_family != AF_INET)
		ROUTE_RELEASE(src);

	route_copyout(dst, src, sizeof (*dst));
}

void
inp_route_copyin(struct inpcb *inp, struct route *src)
{
	struct route *dst = &inp->inp_route;

	lck_mtx_assert(&inp->inpcb_mtx, LCK_MTX_ASSERT_OWNED);

	/* Minor sanity check */
	if (src->ro_rt != NULL && rt_key(src->ro_rt)->sa_family != AF_INET)
		panic("%s: wrong or corrupted route: %p", __func__, src);

	route_copyin(src, dst, sizeof (*src));
}

/*
 * Handler for setting IP_FORCE_OUT_IFP/IP_BOUND_IF/IPV6_BOUND_IF socket option.
 */
int
inp_bindif(struct inpcb *inp, unsigned int ifscope, struct ifnet **pifp)
{
	struct ifnet *ifp = NULL;

	ifnet_head_lock_shared();
	if ((ifscope > (unsigned)if_index) || (ifscope != IFSCOPE_NONE &&
	    (ifp = ifindex2ifnet[ifscope]) == NULL)) {
		ifnet_head_done();
		return (ENXIO);
	}
	ifnet_head_done();

	VERIFY(ifp != NULL || ifscope == IFSCOPE_NONE);

	/*
	 * A zero interface scope value indicates an "unbind".
	 * Otherwise, take in whatever value the app desires;
	 * the app may already know the scope (or force itself
	 * to such a scope) ahead of time before the interface
	 * gets attached.  It doesn't matter either way; any
	 * route lookup from this point on will require an
	 * exact match for the embedded interface scope.
	 */
	inp->inp_boundifp = ifp;
	if (inp->inp_boundifp == NULL)
		inp->inp_flags &= ~INP_BOUND_IF;
	else
		inp->inp_flags |= INP_BOUND_IF;

	/* Blow away any cached route in the PCB */
	ROUTE_RELEASE(&inp->inp_route);

	if (pifp != NULL)
		*pifp = ifp;

	return (0);
}

/*
 * Handler for setting IP_NO_IFT_CELLULAR/IPV6_NO_IFT_CELLULAR socket option,
 * as well as for setting PROC_UUID_NO_CELLULAR policy.
 */
void
inp_set_nocellular(struct inpcb *inp)
{
	inp->inp_flags |= INP_NO_IFT_CELLULAR;

	/* Blow away any cached route in the PCB */
	ROUTE_RELEASE(&inp->inp_route);
}

/*
 * Handler for clearing IP_NO_IFT_CELLULAR/IPV6_NO_IFT_CELLULAR socket option,
 * as well as for clearing PROC_UUID_NO_CELLULAR policy.
 */
void
inp_clear_nocellular(struct inpcb *inp)
{
	struct socket *so = inp->inp_socket;

	/*
	 * SO_RESTRICT_DENY_CELLULAR socket restriction issued on the socket
	 * has a higher precendence than INP_NO_IFT_CELLULAR.  Clear the flag
	 * if and only if the socket is unrestricted.
	 */
	if (so != NULL && !(so->so_restrictions & SO_RESTRICT_DENY_CELLULAR)) {
		inp->inp_flags &= ~INP_NO_IFT_CELLULAR;

		/* Blow away any cached route in the PCB */
		ROUTE_RELEASE(&inp->inp_route);
	}
}

#if FLOW_DIVERT
/*
 * Called when PROC_UUID_FLOW_DIVERT is set.
 */
void
inp_set_flow_divert(struct inpcb *inp)
{
	inp->inp_flags2 |= INP2_WANT_FLOW_DIVERT;
}

/*
 * Called when PROC_UUID_FLOW_DIVERT is cleared.
 */
void
inp_clear_flow_divert(struct inpcb *inp)
{
	inp->inp_flags2 &= ~INP2_WANT_FLOW_DIVERT;
}
#endif /* FLOW_DIVERT */

/*
 * Calculate flow hash for an inp, used by an interface to identify a
 * flow. When an interface provides flow control advisory, this flow
 * hash is used as an identifier.
 */
u_int32_t
inp_calc_flowhash(struct inpcb *inp)
{
	struct inp_flowhash_key fh __attribute__((aligned(8)));
	u_int32_t flowhash = 0;
	struct inpcb *tmp_inp = NULL;

	if (inp_hash_seed == 0)
		inp_hash_seed = RandomULong();

	bzero(&fh, sizeof (fh));

	bcopy(&inp->inp_dependladdr, &fh.infh_laddr, sizeof (fh.infh_laddr));
	bcopy(&inp->inp_dependfaddr, &fh.infh_faddr, sizeof (fh.infh_faddr));

	fh.infh_lport = inp->inp_lport;
	fh.infh_fport = inp->inp_fport;
	fh.infh_af = (inp->inp_vflag & INP_IPV6) ? AF_INET6 : AF_INET;
	fh.infh_proto = inp->inp_ip_p;
	fh.infh_rand1 = RandomULong();
	fh.infh_rand2 = RandomULong();

try_again:
	flowhash = net_flowhash(&fh, sizeof (fh), inp_hash_seed);
	if (flowhash == 0) {
		/* try to get a non-zero flowhash */
		inp_hash_seed = RandomULong();
		goto try_again;
	}

	inp->inp_flowhash = flowhash;

	/* Insert the inp into inp_fc_tree */
	lck_mtx_lock_spin(&inp_fc_lck);
	tmp_inp = RB_FIND(inp_fc_tree, &inp_fc_tree, inp);
	if (tmp_inp != NULL) {
		/*
		 * There is a different inp with the same flowhash.
		 * There can be a collision on flow hash but the
		 * probability is low.  Let's recompute the
		 * flowhash.
		 */
		lck_mtx_unlock(&inp_fc_lck);
		/* recompute hash seed */
		inp_hash_seed = RandomULong();
		goto try_again;
	}

	RB_INSERT(inp_fc_tree, &inp_fc_tree, inp);
	inp->inp_flags2 |= INP2_IN_FCTREE;
	lck_mtx_unlock(&inp_fc_lck);

	return (flowhash);
}

void
inp_flowadv(uint32_t flowhash)
{
	struct inpcb *inp;

	inp = inp_fc_getinp(flowhash, 0);

	if (inp == NULL)
		return;
	inp_fc_feedback(inp);
}

/*
 * Function to compare inp_fc_entries in inp flow control tree
 */
static inline int
infc_cmp(const struct inpcb *inp1, const struct inpcb *inp2)
{
	return (memcmp(&(inp1->inp_flowhash), &(inp2->inp_flowhash),
	    sizeof(inp1->inp_flowhash)));
}

static struct inpcb *
inp_fc_getinp(u_int32_t flowhash, u_int32_t flags)
{
	struct inpcb *inp = NULL;
	int locked = (flags & INPFC_SOLOCKED) ? 1 : 0;

	lck_mtx_lock_spin(&inp_fc_lck);
	key_inp.inp_flowhash = flowhash;
	inp = RB_FIND(inp_fc_tree, &inp_fc_tree, &key_inp);
	if (inp == NULL) {
		/* inp is not present, return */
		lck_mtx_unlock(&inp_fc_lck);
		return (NULL);
	}

	if (flags & INPFC_REMOVE) {
		RB_REMOVE(inp_fc_tree, &inp_fc_tree, inp);
		lck_mtx_unlock(&inp_fc_lck);

		bzero(&(inp->infc_link), sizeof (inp->infc_link));
		inp->inp_flags2 &= ~INP2_IN_FCTREE;
		return (NULL);
	}

	if (in_pcb_checkstate(inp, WNT_ACQUIRE, locked) == WNT_STOPUSING)
		inp = NULL;
	lck_mtx_unlock(&inp_fc_lck);

	return (inp);
}

static void
inp_fc_feedback(struct inpcb *inp)
{
	struct socket *so = inp->inp_socket;

	/* we already hold a want_cnt on this inp, socket can't be null */
	VERIFY(so != NULL);
	socket_lock(so, 1);

	if (in_pcb_checkstate(inp, WNT_RELEASE, 1) == WNT_STOPUSING) {
		socket_unlock(so, 1);
		return;
	}

	/*
	 * Return if the connection is not in flow-controlled state.
	 * This can happen if the connection experienced
	 * loss while it was in flow controlled state
	 */
	if (!INP_WAIT_FOR_IF_FEEDBACK(inp)) {
		socket_unlock(so, 1);
		return;
	}
	inp_reset_fc_state(inp);

	if (SOCK_TYPE(so) == SOCK_STREAM)
		inp_fc_unthrottle_tcp(inp);

	socket_unlock(so, 1);
}

void
inp_reset_fc_state(struct inpcb *inp)
{
	struct socket *so = inp->inp_socket;
	int suspended = (INP_IS_FLOW_SUSPENDED(inp)) ? 1 : 0;
	int needwakeup = (INP_WAIT_FOR_IF_FEEDBACK(inp)) ? 1 : 0;

	inp->inp_flags &= ~(INP_FLOW_CONTROLLED | INP_FLOW_SUSPENDED);

	if (suspended) {
		so->so_flags &= ~(SOF_SUSPENDED);
		soevent(so, (SO_FILT_HINT_LOCKED | SO_FILT_HINT_RESUME));
	}

	if (inp->inp_sndinprog_cnt > 0)
		inp->inp_flags |= INP_FC_FEEDBACK;

	/* Give a write wakeup to unblock the socket */
	if (needwakeup)
		sowwakeup(so);
}

int
inp_set_fc_state(struct inpcb *inp, int advcode)
{
	struct inpcb *tmp_inp = NULL;
	/*
	 * If there was a feedback from the interface when
	 * send operation was in progress, we should ignore
	 * this flow advisory to avoid a race between setting
	 * flow controlled state and receiving feedback from
	 * the interface
	 */
	if (inp->inp_flags & INP_FC_FEEDBACK)
		return (0);

	inp->inp_flags &= ~(INP_FLOW_CONTROLLED | INP_FLOW_SUSPENDED);
	if ((tmp_inp = inp_fc_getinp(inp->inp_flowhash,
	    INPFC_SOLOCKED)) != NULL) {
		if (in_pcb_checkstate(tmp_inp, WNT_RELEASE, 1) == WNT_STOPUSING)
			return (0);
		VERIFY(tmp_inp == inp);
		switch (advcode) {
		case FADV_FLOW_CONTROLLED:
			inp->inp_flags |= INP_FLOW_CONTROLLED;
			break;
		case FADV_SUSPENDED:
			inp->inp_flags |= INP_FLOW_SUSPENDED;
			soevent(inp->inp_socket,
			    (SO_FILT_HINT_LOCKED | SO_FILT_HINT_SUSPEND));

			/* Record the fact that suspend event was sent */
			inp->inp_socket->so_flags |= SOF_SUSPENDED;
			break;
		}
		return (1);
	}
	return (0);
}

/*
 * Handler for SO_FLUSH socket option.
 */
int
inp_flush(struct inpcb *inp, int optval)
{
	u_int32_t flowhash = inp->inp_flowhash;
	struct ifnet *rtifp, *oifp;

	/* Either all classes or one of the valid ones */
	if (optval != SO_TC_ALL && !SO_VALID_TC(optval))
		return (EINVAL);

	/* We need a flow hash for identification */
	if (flowhash == 0)
		return (0);

	/* Grab the interfaces from the route and pcb */
	rtifp = ((inp->inp_route.ro_rt != NULL) ?
	    inp->inp_route.ro_rt->rt_ifp : NULL);
	oifp = inp->inp_last_outifp;

	if (rtifp != NULL)
		if_qflush_sc(rtifp, so_tc2msc(optval), flowhash, NULL, NULL, 0);
	if (oifp != NULL && oifp != rtifp)
		if_qflush_sc(oifp, so_tc2msc(optval), flowhash, NULL, NULL, 0);

	return (0);
}

/*
 * Clear the INP_INADDR_ANY flag (special case for PPP only)
 */
void
inp_clear_INP_INADDR_ANY(struct socket *so)
{
	struct inpcb *inp = NULL;

	socket_lock(so, 1);
	inp = sotoinpcb(so);
	if (inp) {
		inp->inp_flags &= ~INP_INADDR_ANY;
	}
	socket_unlock(so, 1);
}

void
inp_get_soprocinfo(struct inpcb *inp, struct so_procinfo *soprocinfo)
{
	struct socket *so = inp->inp_socket;

	soprocinfo->spi_pid = so->last_pid;
	/*
	 * When not delegated, the effective pid is the same as the real pid
	 */
	if (so->so_flags & SOF_DELEGATED)
		soprocinfo->spi_epid = so->e_pid;
	else
		soprocinfo->spi_epid = so->last_pid;
}

int
inp_findinpcb_procinfo(struct inpcbinfo *pcbinfo, uint32_t flowhash,
    struct so_procinfo *soprocinfo)
{
	struct inpcb *inp = NULL;
	int found = 0;

	bzero(soprocinfo, sizeof (struct so_procinfo));

	if (!flowhash)
		return (-1);

	lck_rw_lock_shared(pcbinfo->ipi_lock);
	LIST_FOREACH(inp, pcbinfo->ipi_listhead, inp_list) {
		if (inp->inp_state != INPCB_STATE_DEAD &&
		    inp->inp_socket != NULL &&
		    inp->inp_flowhash == flowhash) {
			found = 1;
			inp_get_soprocinfo(inp, soprocinfo);
			break;
		}
	}
	lck_rw_done(pcbinfo->ipi_lock);

	return (found);
}

#if CONFIG_PROC_UUID_POLICY
static void
inp_update_cellular_policy(struct inpcb *inp, boolean_t set)
{
	struct socket *so = inp->inp_socket;
	int before, after;

	VERIFY(so != NULL);
	VERIFY(inp->inp_state != INPCB_STATE_DEAD);

	before = (inp->inp_flags & INP_NO_IFT_CELLULAR);
	if (set) {
		inp_set_nocellular(inp);
	} else {
		inp_clear_nocellular(inp);
	}
	after = (inp->inp_flags & INP_NO_IFT_CELLULAR);
	if (net_io_policy_log && (before != after)) {
		static const char *ok = "OK";
		static const char *nok = "NOACCESS";
		uuid_string_t euuid_buf;
		pid_t epid;

		if (so->so_flags & SOF_DELEGATED) {
			uuid_unparse(so->e_uuid, euuid_buf);
			epid = so->e_pid;
		} else {
			uuid_unparse(so->last_uuid, euuid_buf);
			epid = so->last_pid;
		}

		/* allow this socket to generate another notification event */
		so->so_ifdenied_notifies = 0;

		log(LOG_DEBUG, "%s: so 0x%llx [%d,%d] epid %d "
		    "euuid %s%s %s->%s\n", __func__,
		    (uint64_t)VM_KERNEL_ADDRPERM(so), SOCK_DOM(so),
		    SOCK_TYPE(so), epid, euuid_buf,
		    (so->so_flags & SOF_DELEGATED) ?
		    " [delegated]" : "",
		    ((before < after) ? ok : nok),
		    ((before < after) ? nok : ok));
	}
}

#if FLOW_DIVERT
static void
inp_update_flow_divert_policy(struct inpcb *inp, boolean_t set)
{
	struct socket *so = inp->inp_socket;
	int before, after;

	VERIFY(so != NULL);
	VERIFY(inp->inp_state != INPCB_STATE_DEAD);

	if (set && !(inp->inp_flags2 & INP2_WANT_FLOW_DIVERT)) {
		set = !flow_divert_is_dns_service(so);
	}

	before = (inp->inp_flags2 & INP2_WANT_FLOW_DIVERT);
	if (set) {
		inp_set_flow_divert(inp);
	} else {
		inp_clear_flow_divert(inp);
	}
	after = (inp->inp_flags2 & INP2_WANT_FLOW_DIVERT);
	if (net_io_policy_log && (before != after)) {
		static const char *wanted = "WANTED";
		static const char *unwanted = "UNWANTED";
		uuid_string_t euuid_buf;
		pid_t epid;

		if (so->so_flags & SOF_DELEGATED) {
			uuid_unparse(so->e_uuid, euuid_buf);
			epid = so->e_pid;
		} else {
			uuid_unparse(so->last_uuid, euuid_buf);
			epid = so->last_pid;
		}

		log(LOG_DEBUG, "%s: so 0x%llx [%d,%d] epid %d "
		    "euuid %s%s %s->%s\n", __func__,
		    (uint64_t)VM_KERNEL_ADDRPERM(so), SOCK_DOM(so),
		    SOCK_TYPE(so), epid, euuid_buf,
		    (so->so_flags & SOF_DELEGATED) ?
		    " [delegated]" : "",
		    ((before < after) ? unwanted : wanted),
		    ((before < after) ? wanted : unwanted));
	}
}
#endif /* FLOW_DIVERT */
#endif /* !CONFIG_PROC_UUID_POLICY */

int
inp_update_policy(struct inpcb *inp)
{
#if CONFIG_PROC_UUID_POLICY
	struct socket *so = inp->inp_socket;
	uint32_t pflags = 0;
	int32_t ogencnt;
	int err = 0;

	if (!net_io_policy_uuid ||
	    so == NULL || inp->inp_state == INPCB_STATE_DEAD)
		return (0);

	/*
	 * Kernel-created sockets that aren't delegating other sockets
	 * are currently exempted from UUID policy checks.
	 */
	if (so->last_pid == 0 && !(so->so_flags & SOF_DELEGATED))
		return (0);

	ogencnt = so->so_policy_gencnt;
	err = proc_uuid_policy_lookup(((so->so_flags & SOF_DELEGATED) ?
	    so->e_uuid : so->last_uuid), &pflags, &so->so_policy_gencnt);

	/*
	 * Discard cached generation count if the entry is gone (ENOENT),
	 * so that we go thru the checks below.
	 */
	if (err == ENOENT && ogencnt != 0)
		so->so_policy_gencnt = 0;

	/*
	 * If the generation count has changed, inspect the policy flags
	 * and act accordingly.  If a policy flag was previously set and
	 * the UUID is no longer present in the table (ENOENT), treat it
	 * as if the flag has been cleared.
	 */
	if ((err == 0 || err == ENOENT) && ogencnt != so->so_policy_gencnt) {
		/* update cellular policy for this socket */
		if (err == 0 && (pflags & PROC_UUID_NO_CELLULAR)) {
			inp_update_cellular_policy(inp, TRUE);
		} else if (!(pflags & PROC_UUID_NO_CELLULAR)) {
			inp_update_cellular_policy(inp, FALSE);
		}
#if FLOW_DIVERT
		/* update flow divert policy for this socket */
		if (err == 0 && (pflags & PROC_UUID_FLOW_DIVERT)) {
			inp_update_flow_divert_policy(inp, TRUE);
		} else if (!(pflags & PROC_UUID_FLOW_DIVERT)) {
			inp_update_flow_divert_policy(inp, FALSE);
		}
#endif /* FLOW_DIVERT */
	}

	return ((err == ENOENT) ? 0 : err);
#else /* !CONFIG_PROC_UUID_POLICY */
#pragma unused(inp)
	return (0);
#endif /* !CONFIG_PROC_UUID_POLICY */
}

boolean_t
inp_restricted(struct inpcb *inp, struct ifnet *ifp)
{
	VERIFY(inp != NULL);

	if (!sorestrictrecv)
		return (FALSE);

	if (ifp == NULL || !(ifp->if_eflags & IFEF_RESTRICTED_RECV))
		return (FALSE);

	if (inp->inp_flags & INP_RECV_ANYIF)
		return (FALSE);

	if ((inp->inp_flags & INP_BOUND_IF) && inp->inp_boundifp == ifp)
		return (FALSE);

	return (TRUE);
}
