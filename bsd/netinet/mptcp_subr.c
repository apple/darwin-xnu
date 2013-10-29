/*
 * Copyright (c) 2012-2013 Apple Inc. All rights reserved.
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

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/mcache.h>
#include <sys/resourcevar.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/syslog.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/sysctl.h>

#include <kern/zalloc.h>
#include <kern/locks.h>

#include <mach/thread_act.h>
#include <mach/sdt.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_var.h>
#include <netinet/mptcp_var.h>
#include <netinet/mptcp.h>
#include <netinet/mptcp_seq.h>
#include <netinet/mptcp_timer.h>
#include <libkern/crypto/sha1.h>
#if INET6
#include <netinet6/in6_pcb.h>
#include <netinet6/ip6protosw.h>
#endif /* INET6 */
#include <dev/random/randomdev.h>

/*
 * Notes on MPTCP implementation.
 *
 * MPTCP is implemented as <SOCK_STREAM,IPPROTO_TCP> protocol in PF_MULTIPATH
 * communication domain.  The structure mtcbinfo describes the MPTCP instance
 * of a Multipath protocol in that domain.  It is used to keep track of all
 * MPTCP PCB instances in the system, and is protected by the global lock
 * mppi_lock.
 *
 * An MPTCP socket is opened by calling socket(PF_MULTIPATH, SOCK_STREAM,
 * IPPROTO_TCP).  Upon success, a Multipath PCB gets allocated and along with
 * it comes an MPTCP Session and an MPTCP PCB.  All three structures are
 * allocated from the same memory block, and each structure has a pointer
 * to the adjacent ones.  The layout is defined by the mpp_mtp structure.
 * The socket lock (mpp_lock) is used to protect accesses to the Multipath
 * PCB (mppcb) as well as the MPTCP Session (mptses).
 *
 * The MPTCP Session is an MPTCP-specific extension to the Multipath PCB;
 * in particular, the list of subflows as well as the MPTCP thread.
 *
 * A functioning MPTCP Session consists of one or more subflow sockets.  Each
 * subflow socket is essentially a regular PF_INET/PF_INET6 TCP socket, and is
 * represented by the mptsub structure.  Because each subflow requires access
 * to the MPTCP Session, the MPTCP socket's so_usecount is bumped up for each
 * subflow.  This gets decremented prior to the subflow's destruction.  The
 * subflow lock (mpts_lock) is used to protect accesses to the subflow.
 *
 * To handle events (read, write, control) from the subflows, an MPTCP thread
 * is created; currently, there is one thread per MPTCP Session.  In order to
 * prevent the MPTCP socket from being destroyed while being accessed by the
 * MPTCP thread, we bump up the MPTCP socket's so_usecount for the thread,
 * which will be decremented prior to the thread's termination.  The thread
 * lock (mpte_thread_lock) is used to synchronize its signalling.
 *
 * Lock ordering is defined as follows:
 *
 *	mtcbinfo (mppi_lock)
 *		mp_so (mpp_lock)
 *			mpts (mpts_lock)
 *				so (inpcb_mtx)
 *					mptcb (mpt_lock)
 *
 * It is not a requirement that all of the above locks need to be acquired
 * in succession, but the correct lock ordering must be followed when there
 * are more than one locks that need to be held.  The MPTCP thread lock is
 * is not constrained by this arrangement, because none of the other locks
 * is ever acquired while holding mpte_thread_lock; therefore it may be called
 * at any moment to signal the thread.
 *
 * An MPTCP socket will be destroyed when its so_usecount drops to zero; this
 * work is done by the MPTCP garbage collector which is invoked on demand by
 * the PF_MULTIPATH garbage collector.  This process will take place once all
 * of the subflows have been destroyed, and the MPTCP thread be instructed to
 * self-terminate.
 */

static void mptcp_sesdestroy(struct mptses *);
static void mptcp_thread_signal_locked(struct mptses *);
static void mptcp_thread_terminate_signal(struct mptses *);
static void mptcp_thread_dowork(struct mptses *);
static void mptcp_thread_func(void *, wait_result_t);
static void mptcp_thread_destroy(struct mptses *);
static void mptcp_key_pool_init(void);
static void mptcp_attach_to_subf(struct socket *, struct mptcb *, connid_t);
static void mptcp_detach_mptcb_from_subf(struct mptcb *, struct socket *);
static void mptcp_conn_properties(struct mptcb *);
static void mptcp_init_statevars(struct mptcb *);

static uint32_t mptcp_gc(struct mppcbinfo *);
static int mptcp_subflow_socreate(struct mptses *, struct mptsub *,
    int, struct proc *, struct socket **);
static int mptcp_subflow_soclose(struct mptsub *, struct socket *);
static int mptcp_subflow_soconnectx(struct mptses *, struct mptsub *);
static int mptcp_subflow_soreceive(struct socket *, struct sockaddr **,
    struct uio *, struct mbuf **, struct mbuf **, int *);
static void mptcp_subflow_rupcall(struct socket *, void *, int);
static void mptcp_subflow_input(struct mptses *, struct mptsub *);
static void mptcp_subflow_wupcall(struct socket *, void *, int);
static void mptcp_subflow_eupcall(struct socket *, void *, uint32_t);
static void mptcp_update_last_owner(struct mptsub *, struct socket *);

/*
 * Possible return values for subflow event handlers.  Note that success
 * values must be greater or equal than MPTS_EVRET_OK.  Values less than that
 * indicate errors or actions which require immediate attention; they will
 * prevent the rest of the handlers from processing their respective events
 * until the next round of events processing.
 */
typedef enum {
	MPTS_EVRET_DELETE		= 1,	/* delete this subflow */
	MPTS_EVRET_OK			= 2,	/* OK */
	MPTS_EVRET_CONNECT_PENDING	= 3,	/* resume pended connects */
	MPTS_EVRET_DISCONNECT_FALLBACK	= 4,	/* abort all but preferred */
	MPTS_EVRET_OK_UPDATE		= 5,	/* OK with conninfo update */
} ev_ret_t;

static ev_ret_t mptcp_subflow_events(struct mptses *, struct mptsub *);
static ev_ret_t mptcp_subflow_connreset_ev(struct mptses *, struct mptsub *);
static ev_ret_t mptcp_subflow_cantrcvmore_ev(struct mptses *, struct mptsub *);
static ev_ret_t mptcp_subflow_cantsendmore_ev(struct mptses *, struct mptsub *);
static ev_ret_t mptcp_subflow_timeout_ev(struct mptses *, struct mptsub *);
static ev_ret_t mptcp_subflow_nosrcaddr_ev(struct mptses *, struct mptsub *);
static ev_ret_t mptcp_subflow_failover_ev(struct mptses *, struct mptsub *);
static ev_ret_t mptcp_subflow_ifdenied_ev(struct mptses *, struct mptsub *);
static ev_ret_t mptcp_subflow_suspend_ev(struct mptses *, struct mptsub *);
static ev_ret_t mptcp_subflow_resume_ev(struct mptses *, struct mptsub *);
static ev_ret_t mptcp_subflow_connected_ev(struct mptses *, struct mptsub *);
static ev_ret_t mptcp_subflow_disconnected_ev(struct mptses *, struct mptsub *);
static ev_ret_t mptcp_subflow_mpstatus_ev(struct mptses *, struct mptsub *);
static ev_ret_t mptcp_subflow_mustrst_ev(struct mptses *, struct mptsub *);
static const char *mptcp_evret2str(ev_ret_t);

static mptcp_key_t *mptcp_reserve_key(void);
static int mptcp_do_sha1(mptcp_key_t *, char *, int);
static int mptcp_init_authparms(struct mptcb *);
static int mptcp_delete_ok(struct mptses *mpte, struct mptsub *mpts);

static unsigned int mptsub_zone_size;		/* size of mptsub */
static struct zone *mptsub_zone;		/* zone for mptsub */

static unsigned int mptopt_zone_size;		/* size of mptopt */
static struct zone *mptopt_zone;		/* zone for mptopt */

static unsigned int mpt_subauth_entry_size;	/* size of subf auth entry */
static struct zone *mpt_subauth_zone;		/* zone of subf auth entry */

struct mppcbinfo mtcbinfo;

static struct mptcp_keys_pool_head mptcp_keys_pool;

#define	MPTCP_SUBFLOW_WRITELEN	(8 * 1024)	/* bytes to write each time */
#define	MPTCP_SUBFLOW_READLEN	(8 * 1024)	/* bytes to read each time */

SYSCTL_DECL(_net_inet);

SYSCTL_NODE(_net_inet, OID_AUTO, mptcp, CTLFLAG_RW|CTLFLAG_LOCKED, 0, "MPTCP");

uint32_t mptcp_verbose = 0;		/* more noise if greater than 1 */
SYSCTL_UINT(_net_inet_mptcp, OID_AUTO, verbose, CTLFLAG_RW|CTLFLAG_LOCKED,
	&mptcp_verbose, 0, "MPTCP verbosity level");

SYSCTL_UINT(_net_inet_mptcp, OID_AUTO, pcbcount, CTLFLAG_RD|CTLFLAG_LOCKED,
	&mtcbinfo.mppi_count, 0, "Number of active PCBs");

/*
 * Since there is one kernel thread per mptcp socket, imposing an artificial
 * limit on number of allowed mptcp sockets.
 */
uint32_t mptcp_socket_limit = MPPCB_LIMIT;
SYSCTL_UINT(_net_inet_mptcp, OID_AUTO, sk_lim, CTLFLAG_RW|CTLFLAG_LOCKED,
	&mptcp_socket_limit, 0, "MPTCP socket limit");

static struct protosw mptcp_subflow_protosw;
static struct pr_usrreqs mptcp_subflow_usrreqs;
#if INET6
static struct ip6protosw mptcp_subflow_protosw6;
static struct pr_usrreqs mptcp_subflow_usrreqs6;
#endif /* INET6 */

/*
 * Protocol pr_init callback.
 */
void
mptcp_init(struct protosw *pp, struct domain *dp)
{
#pragma unused(dp)
	static int mptcp_initialized = 0;
	struct protosw *prp;
#if INET6
	struct ip6protosw *prp6;
#endif /* INET6 */

	VERIFY((pp->pr_flags & (PR_INITIALIZED|PR_ATTACHED)) == PR_ATTACHED);

	/* do this only once */
	if (mptcp_initialized)
		return;
	mptcp_initialized = 1;

	/*
	 * Since PF_MULTIPATH gets initialized after PF_INET/INET6,
	 * we must be able to find IPPROTO_TCP entries for both.
	 */
	prp = pffindproto_locked(PF_INET, IPPROTO_TCP, SOCK_STREAM);
	VERIFY(prp != NULL);
	bcopy(prp, &mptcp_subflow_protosw, sizeof (*prp));
	bcopy(prp->pr_usrreqs, &mptcp_subflow_usrreqs,
	    sizeof (mptcp_subflow_usrreqs));
	mptcp_subflow_protosw.pr_entry.tqe_next = NULL;
	mptcp_subflow_protosw.pr_entry.tqe_prev = NULL;
	mptcp_subflow_protosw.pr_usrreqs = &mptcp_subflow_usrreqs;
	mptcp_subflow_usrreqs.pru_soreceive = mptcp_subflow_soreceive;
	mptcp_subflow_usrreqs.pru_rcvoob = pru_rcvoob_notsupp;
	/*
	 * Socket filters shouldn't attach/detach to/from this protosw
	 * since pr_protosw is to be used instead, which points to the
	 * real protocol; if they do, it is a bug and we should panic.
	 */
	mptcp_subflow_protosw.pr_filter_head.tqh_first =
	    (struct socket_filter *)(uintptr_t)0xdeadbeefdeadbeef;
	mptcp_subflow_protosw.pr_filter_head.tqh_last =
	    (struct socket_filter **)(uintptr_t)0xdeadbeefdeadbeef;

#if INET6
	prp6 = (struct ip6protosw *)pffindproto_locked(PF_INET6,
	    IPPROTO_TCP, SOCK_STREAM);
	VERIFY(prp6 != NULL);
	bcopy(prp6, &mptcp_subflow_protosw6, sizeof (*prp6));
	bcopy(prp6->pr_usrreqs, &mptcp_subflow_usrreqs6,
	    sizeof (mptcp_subflow_usrreqs6));
	mptcp_subflow_protosw6.pr_entry.tqe_next = NULL;
	mptcp_subflow_protosw6.pr_entry.tqe_prev = NULL;
	mptcp_subflow_protosw6.pr_usrreqs = &mptcp_subflow_usrreqs6;
	mptcp_subflow_usrreqs6.pru_soreceive = mptcp_subflow_soreceive;
	mptcp_subflow_usrreqs6.pru_rcvoob = pru_rcvoob_notsupp;
	/*
	 * Socket filters shouldn't attach/detach to/from this protosw
	 * since pr_protosw is to be used instead, which points to the
	 * real protocol; if they do, it is a bug and we should panic.
	 */
	mptcp_subflow_protosw6.pr_filter_head.tqh_first =
	    (struct socket_filter *)(uintptr_t)0xdeadbeefdeadbeef;
	mptcp_subflow_protosw6.pr_filter_head.tqh_last =
	    (struct socket_filter **)(uintptr_t)0xdeadbeefdeadbeef;
#endif /* INET6 */

	bzero(&mtcbinfo, sizeof (mtcbinfo));
	TAILQ_INIT(&mtcbinfo.mppi_pcbs);
	mtcbinfo.mppi_size = sizeof (struct mpp_mtp);
	if ((mtcbinfo.mppi_zone = zinit(mtcbinfo.mppi_size,
	    1024 * mtcbinfo.mppi_size, 8192, "mptcb")) == NULL) {
		panic("%s: unable to allocate MPTCP PCB zone\n", __func__);
		/* NOTREACHED */
	}
	zone_change(mtcbinfo.mppi_zone, Z_CALLERACCT, FALSE);
	zone_change(mtcbinfo.mppi_zone, Z_EXPAND, TRUE);

	mtcbinfo.mppi_lock_grp_attr = lck_grp_attr_alloc_init();
	mtcbinfo.mppi_lock_grp = lck_grp_alloc_init("mppcb",
	    mtcbinfo.mppi_lock_grp_attr);
	mtcbinfo.mppi_lock_attr = lck_attr_alloc_init();
	lck_mtx_init(&mtcbinfo.mppi_lock, mtcbinfo.mppi_lock_grp,
	    mtcbinfo.mppi_lock_attr);
	mtcbinfo.mppi_gc = mptcp_gc;

	mtcbinfo.mppi_timer = mptcp_timer;

	/* attach to MP domain for garbage collection to take place */
	mp_pcbinfo_attach(&mtcbinfo);

	mptsub_zone_size = sizeof (struct mptsub);
	if ((mptsub_zone = zinit(mptsub_zone_size, 1024 * mptsub_zone_size,
	    8192, "mptsub")) == NULL) {
		panic("%s: unable to allocate MPTCP subflow zone\n", __func__);
		/* NOTREACHED */
	}
	zone_change(mptsub_zone, Z_CALLERACCT, FALSE);
	zone_change(mptsub_zone, Z_EXPAND, TRUE);

	mptopt_zone_size = sizeof (struct mptopt);
	if ((mptopt_zone = zinit(mptopt_zone_size, 128 * mptopt_zone_size,
	    1024, "mptopt")) == NULL) {
		panic("%s: unable to allocate MPTCP option zone\n", __func__);
		/* NOTREACHED */
	}
	zone_change(mptopt_zone, Z_CALLERACCT, FALSE);
	zone_change(mptopt_zone, Z_EXPAND, TRUE);

	mpt_subauth_entry_size = sizeof (struct mptcp_subf_auth_entry);
	if ((mpt_subauth_zone = zinit(mpt_subauth_entry_size,
	    1024 * mpt_subauth_entry_size, 8192, "mptauth")) == NULL) {
		panic("%s: unable to allocate MPTCP address auth zone \n",
		    __func__);
		/* NOTREACHED */
	}
	zone_change(mpt_subauth_zone, Z_CALLERACCT, FALSE);
	zone_change(mpt_subauth_zone, Z_EXPAND, TRUE);

	/* Set up a list of unique keys */
	mptcp_key_pool_init();

}

/*
 * Create an MPTCP session, called as a result of opening a MPTCP socket.
 */
struct mptses *
mptcp_sescreate(struct socket *mp_so, struct mppcb *mpp)
{
	struct mppcbinfo *mppi;
	struct mptses *mpte;
	struct mptcb *mp_tp;
	int error = 0;

	VERIFY(mpp != NULL);
	mppi = mpp->mpp_pcbinfo;
	VERIFY(mppi != NULL);

	mpte = &((struct mpp_mtp *)mpp)->mpp_ses;
	mp_tp = &((struct mpp_mtp *)mpp)->mtcb;

	/* MPTCP Multipath PCB Extension */
	bzero(mpte, sizeof (*mpte));
	VERIFY(mpp->mpp_pcbe == NULL);
	mpp->mpp_pcbe = mpte;
	mpte->mpte_mppcb = mpp;
	mpte->mpte_mptcb = mp_tp;

	TAILQ_INIT(&mpte->mpte_sopts);
	TAILQ_INIT(&mpte->mpte_subflows);
	mpte->mpte_associd = ASSOCID_ANY;
	mpte->mpte_connid_last = CONNID_ANY;

	lck_mtx_init(&mpte->mpte_thread_lock, mppi->mppi_lock_grp,
	    mppi->mppi_lock_attr);

	/*
	 * XXX: adi@apple.com
	 *
	 * This can be rather expensive if we have lots of MPTCP sockets,
	 * but we need a kernel thread for this model to work.  Perhaps we
	 * could amortize the costs by having one worker thread per a group
	 * of MPTCP sockets.
	 */
	if (kernel_thread_start(mptcp_thread_func, mpte,
	    &mpte->mpte_thread) != KERN_SUCCESS) {
		error = ENOBUFS;
		goto out;
	}
	mp_so->so_usecount++;		/* for thread */

	/* MPTCP Protocol Control Block */
	bzero(mp_tp, sizeof (*mp_tp));
	lck_mtx_init(&mp_tp->mpt_lock, mppi->mppi_lock_grp,
	    mppi->mppi_lock_attr);
	mp_tp->mpt_mpte = mpte;

out:
	if (error != 0)
		lck_mtx_destroy(&mpte->mpte_thread_lock, mppi->mppi_lock_grp);
	DTRACE_MPTCP5(session__create, struct socket *, mp_so,
	    struct sockbuf *, &mp_so->so_rcv,
	    struct sockbuf *, &mp_so->so_snd,
	    struct mppcb *, mpp, int, error);

	return ((error != 0) ? NULL : mpte);
}

/*
 * Destroy an MPTCP session.
 */
static void
mptcp_sesdestroy(struct mptses *mpte)
{
	struct mptcb *mp_tp;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */

	mp_tp = mpte->mpte_mptcb;
	VERIFY(mp_tp != NULL);

	/*
	 * MPTCP Multipath PCB Extension section
	 */
	mptcp_flush_sopts(mpte);
	VERIFY(TAILQ_EMPTY(&mpte->mpte_subflows) && mpte->mpte_numflows == 0);

	lck_mtx_destroy(&mpte->mpte_thread_lock,
	    mpte->mpte_mppcb->mpp_pcbinfo->mppi_lock_grp);

	/*
	 * MPTCP Protocol Control Block section
	 */
	lck_mtx_destroy(&mp_tp->mpt_lock,
	    mpte->mpte_mppcb->mpp_pcbinfo->mppi_lock_grp);

	DTRACE_MPTCP2(session__destroy, struct mptses *, mpte,
	    struct mptcb *, mp_tp);
}

/*
 * Allocate an MPTCP socket option structure.
 */
struct mptopt *
mptcp_sopt_alloc(int how)
{
	struct mptopt *mpo;

	mpo = (how == M_WAITOK) ? zalloc(mptopt_zone) :
	    zalloc_noblock(mptopt_zone);
	if (mpo != NULL) {
		bzero(mpo, mptopt_zone_size);
	}

	return (mpo);
}

/*
 * Free an MPTCP socket option structure.
 */
void
mptcp_sopt_free(struct mptopt *mpo)
{
	VERIFY(!(mpo->mpo_flags & MPOF_ATTACHED));

	zfree(mptopt_zone, mpo);
}

/*
 * Add a socket option to the MPTCP socket option list.
 */
void
mptcp_sopt_insert(struct mptses *mpte, struct mptopt *mpo)
{
	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	VERIFY(!(mpo->mpo_flags & MPOF_ATTACHED));
	mpo->mpo_flags |= MPOF_ATTACHED;
	TAILQ_INSERT_TAIL(&mpte->mpte_sopts, mpo, mpo_entry);
}

/*
 * Remove a socket option from the MPTCP socket option list.
 */
void
mptcp_sopt_remove(struct mptses *mpte, struct mptopt *mpo)
{
	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	VERIFY(mpo->mpo_flags & MPOF_ATTACHED);
	mpo->mpo_flags &= ~MPOF_ATTACHED;
	TAILQ_REMOVE(&mpte->mpte_sopts, mpo, mpo_entry);
}

/*
 * Search for an existing <sopt_level,sopt_name> socket option.
 */
struct mptopt *
mptcp_sopt_find(struct mptses *mpte, struct sockopt *sopt)
{
	struct mptopt *mpo;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */

	TAILQ_FOREACH(mpo, &mpte->mpte_sopts, mpo_entry) {
		if (mpo->mpo_level == sopt->sopt_level &&
		    mpo->mpo_name == sopt->sopt_name)
			break;
	}
	VERIFY(mpo == NULL || sopt->sopt_valsize == sizeof (int));

	return (mpo);
}

/*
 * Flushes all recorded socket options from an MP socket.
 */
void
mptcp_flush_sopts(struct mptses *mpte)
{
	struct mptopt *mpo, *tmpo;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */

	TAILQ_FOREACH_SAFE(mpo, &mpte->mpte_sopts, mpo_entry, tmpo) {
		mptcp_sopt_remove(mpte, mpo);
		mptcp_sopt_free(mpo);
	}
	VERIFY(TAILQ_EMPTY(&mpte->mpte_sopts));
}

/*
 * Allocate a MPTCP subflow structure.
 */
struct mptsub *
mptcp_subflow_alloc(int how)
{
	struct mptsub *mpts;

	mpts = (how == M_WAITOK) ? zalloc(mptsub_zone) :
	    zalloc_noblock(mptsub_zone);
	if (mpts != NULL) {
		bzero(mpts, mptsub_zone_size);
		lck_mtx_init(&mpts->mpts_lock, mtcbinfo.mppi_lock_grp,
		    mtcbinfo.mppi_lock_attr);
	}

	return (mpts);
}

/*
 * Deallocate a subflow structure, called when all of the references held
 * on it have been released.  This implies that the subflow has been deleted.
 */
void
mptcp_subflow_free(struct mptsub *mpts)
{
	MPTS_LOCK_ASSERT_HELD(mpts);

	VERIFY(mpts->mpts_refcnt == 0);
	VERIFY(!(mpts->mpts_flags & MPTSF_ATTACHED));
	VERIFY(mpts->mpts_mpte == NULL);
	VERIFY(mpts->mpts_socket == NULL);

	if (mpts->mpts_src_sl != NULL) {
		sockaddrlist_free(mpts->mpts_src_sl);
		mpts->mpts_src_sl = NULL;
	}
	if (mpts->mpts_dst_sl != NULL) {
		sockaddrlist_free(mpts->mpts_dst_sl);
		mpts->mpts_dst_sl = NULL;
	}
	MPTS_UNLOCK(mpts);
	lck_mtx_destroy(&mpts->mpts_lock, mtcbinfo.mppi_lock_grp);

	zfree(mptsub_zone, mpts);
}

/*
 * Create an MPTCP subflow socket.
 */
static int
mptcp_subflow_socreate(struct mptses *mpte, struct mptsub *mpts, int dom,
    struct proc *p, struct socket **so)
{
	struct mptopt smpo, *mpo, *tmpo;
	struct socket *mp_so;
	int error;

	*so = NULL;
	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	mp_so = mpte->mpte_mppcb->mpp_socket;

	/*
	 * Create the subflow socket (multipath subflow, non-blocking.)
	 *
	 * This will cause SOF_MP_SUBFLOW socket flag to be set on the subflow
	 * socket; it will be cleared when the socket is peeled off or closed.
	 * It also indicates to the underlying TCP to handle MPTCP options.
	 * A multipath subflow socket implies SS_NOFDREF state.
	 */
	if ((error = socreate_internal(dom, so, SOCK_STREAM,
	    IPPROTO_TCP, p, SOCF_ASYNC | SOCF_MP_SUBFLOW, PROC_NULL)) != 0) {
		mptcplog((LOG_ERR, "MPTCP ERROR %s: mp_so 0x%llx unable to "
		    "create subflow socket error %d\n", __func__,
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so), error));
		return (error);
	}

	socket_lock(*so, 0);
	VERIFY((*so)->so_flags & SOF_MP_SUBFLOW);
	VERIFY(((*so)->so_state & (SS_NBIO|SS_NOFDREF)) ==
	    (SS_NBIO|SS_NOFDREF));

	/* prevent the socket buffers from being compressed */
	(*so)->so_rcv.sb_flags |= SB_NOCOMPRESS;
	(*so)->so_snd.sb_flags |= SB_NOCOMPRESS;

	bzero(&smpo, sizeof (smpo));
	smpo.mpo_flags |= MPOF_SUBFLOW_OK;
	smpo.mpo_level = SOL_SOCKET;
	smpo.mpo_intval = 1;

	/* disable SIGPIPE */
	smpo.mpo_name = SO_NOSIGPIPE;
	if ((error = mptcp_subflow_sosetopt(mpte, *so, &smpo)) != 0)
		goto out;

	/* find out if the subflow's source address goes away */
	smpo.mpo_name = SO_NOADDRERR;
	if ((error = mptcp_subflow_sosetopt(mpte, *so, &smpo)) != 0)
		goto out;

	/* enable keepalive */
	smpo.mpo_name = SO_KEEPALIVE;
	if ((error = mptcp_subflow_sosetopt(mpte, *so, &smpo)) != 0)
		goto out;

	/*
	 * Limit the receive socket buffer size to 64k.
	 *
	 * We need to take into consideration the window scale option
	 * which could be negotiated in one subflow but disabled in
	 * another subflow.
	 * XXX This can be improved in the future.
	 */
	smpo.mpo_name = SO_RCVBUF;
	smpo.mpo_intval = MPTCP_RWIN_MAX;
	if ((error = mptcp_subflow_sosetopt(mpte, *so, &smpo)) != 0)
		goto out;

	/* N.B.: set by sosetopt */
	VERIFY(!((*so)->so_rcv.sb_flags & SB_AUTOSIZE));
	/* Prevent automatic socket buffer sizing. */
	(*so)->so_snd.sb_flags &= ~SB_AUTOSIZE;

	smpo.mpo_level = IPPROTO_TCP;
	smpo.mpo_intval = mptcp_subflow_keeptime;
	smpo.mpo_name = TCP_KEEPALIVE;
	if ((error = mptcp_subflow_sosetopt(mpte, *so, &smpo)) != 0)
		goto out;

	/* replay setsockopt(2) on the subflow sockets for eligible options */
	TAILQ_FOREACH_SAFE(mpo, &mpte->mpte_sopts, mpo_entry, tmpo) {
		int interim;

		if (!(mpo->mpo_flags & MPOF_SUBFLOW_OK))
			continue;

		/*
		 * Skip those that are handled internally; these options
		 * should not have been recorded and marked with the
		 * MPOF_SUBFLOW_OK by mptcp_setopt(), but just in case.
		 */
		if (mpo->mpo_level == SOL_SOCKET &&
		    (mpo->mpo_name == SO_NOSIGPIPE ||
		    mpo->mpo_name == SO_NOADDRERR ||
		    mpo->mpo_name == SO_KEEPALIVE))
			continue;

		interim = (mpo->mpo_flags & MPOF_INTERIM);
		if (mptcp_subflow_sosetopt(mpte, *so, mpo) != 0 && interim) {
			char buf[32];
			mptcplog((LOG_ERR, "%s: mp_so 0x%llx sopt %s val %d "
			    "interim record removed\n", __func__,
			    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
			    mptcp_sopt2str(mpo->mpo_level, mpo->mpo_name,
			    buf, sizeof (buf)), mpo->mpo_intval));
			mptcp_sopt_remove(mpte, mpo);
			mptcp_sopt_free(mpo);
			continue;
		}
	}

	/*
	 * We need to receive everything that the subflow socket has,
	 * so use a customized socket receive function.  We will undo
	 * this when the socket is peeled off or closed.
	 */
	mpts->mpts_oprotosw = (*so)->so_proto;
	switch (dom) {
	case PF_INET:
		(*so)->so_proto = &mptcp_subflow_protosw;
		break;
#if INET6
	case PF_INET6:
		(*so)->so_proto = (struct protosw *)&mptcp_subflow_protosw6;
		break;
#endif /* INET6 */
	default:
		VERIFY(0);
		/* NOTREACHED */
	}

out:
	socket_unlock(*so, 0);

	DTRACE_MPTCP4(subflow__create, struct mptses *, mpte,
	    struct mptsub *, mpts, int, dom, int, error);

	return (error);
}

/*
 * Close an MPTCP subflow socket.
 *
 * Note that this may be called on an embryonic subflow, and the only
 * thing that is guaranteed valid is the protocol-user request.
 */
static int
mptcp_subflow_soclose(struct mptsub *mpts, struct socket *so)
{
	MPTS_LOCK_ASSERT_HELD(mpts);

	socket_lock(so, 0);
	VERIFY(so->so_flags & SOF_MP_SUBFLOW);
	VERIFY((so->so_state & (SS_NBIO|SS_NOFDREF)) == (SS_NBIO|SS_NOFDREF));

	/* restore protocol-user requests */
	VERIFY(mpts->mpts_oprotosw != NULL);
	so->so_proto = mpts->mpts_oprotosw;
	socket_unlock(so, 0);

	mpts->mpts_socket = NULL;	/* may already be NULL */

	DTRACE_MPTCP5(subflow__close, struct mptsub *, mpts,
	    struct socket *, so,
	    struct sockbuf *, &so->so_rcv,
	    struct sockbuf *, &so->so_snd,
	    struct mptses *, mpts->mpts_mpte);

	return (soclose(so));
}

/*
 * Connect an MPTCP subflow socket.
 *
 * This may be called inline as part of adding a subflow, or asynchronously
 * by the thread (upon progressing to MPTCPF_JOIN_READY).  Note that in the
 * pending connect case, the subflow socket may have been bound to an interface
 * and/or a source IP address which may no longer be around by the time this
 * routine is called; in that case the connect attempt will most likely fail.
 */
static int
mptcp_subflow_soconnectx(struct mptses *mpte, struct mptsub *mpts)
{
	struct socket *so;
	int af, error;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);

	VERIFY((mpts->mpts_flags & (MPTSF_CONNECTING|MPTSF_CONNECTED)) ==
	    MPTSF_CONNECTING);
	VERIFY(mpts->mpts_socket != NULL);
	so = mpts->mpts_socket;
	af = mpts->mpts_family;

	if (af == AF_INET || af == AF_INET6) {
		struct sockaddr_entry *dst_se;
		char dbuf[MAX_IPv6_STR_LEN];

		dst_se = TAILQ_FIRST(&mpts->mpts_dst_sl->sl_head);
		VERIFY(dst_se != NULL);

		mptcplog((LOG_DEBUG, "%s: mp_so 0x%llx dst %s[%d] cid %d "
		    "[pended %s]\n", __func__,
		    (u_int64_t)VM_KERNEL_ADDRPERM(mpte->mpte_mppcb->mpp_socket),
		    inet_ntop(af, ((af == AF_INET) ?
		    (void *)&SIN(dst_se->se_addr)->sin_addr.s_addr :
		    (void *)&SIN6(dst_se->se_addr)->sin6_addr),
		    dbuf, sizeof (dbuf)), ((af == AF_INET) ?
		    ntohs(SIN(dst_se->se_addr)->sin_port) :
		    ntohs(SIN6(dst_se->se_addr)->sin6_port)),
		    mpts->mpts_connid,
		    ((mpts->mpts_flags & MPTSF_CONNECT_PENDING) ?
		    "YES" : "NO")));
	}

	mpts->mpts_flags &= ~MPTSF_CONNECT_PENDING;

	socket_lock(so, 0);
	mptcp_attach_to_subf(so, mpte->mpte_mptcb, mpts->mpts_connid);
	/* connect the subflow socket */
	error = soconnectxlocked(so, &mpts->mpts_src_sl, &mpts->mpts_dst_sl,
	    mpts->mpts_mpcr.mpcr_proc, mpts->mpts_mpcr.mpcr_ifscope,
	    mpte->mpte_associd, NULL, TCP_CONNREQF_MPTCP,
	    &mpts->mpts_mpcr, sizeof (mpts->mpts_mpcr));
	socket_unlock(so, 0);

	DTRACE_MPTCP3(subflow__connect, struct mptses *, mpte,
	    struct mptsub *, mpts, int, error);

	return (error);
}

/*
 * MPTCP subflow socket receive routine, derived from soreceive().
 */
static int
mptcp_subflow_soreceive(struct socket *so, struct sockaddr **psa,
    struct uio *uio, struct mbuf **mp0, struct mbuf **controlp, int *flagsp)
{
#pragma unused(uio)
	int flags, error = 0;
	struct proc *p = current_proc();
	struct mbuf *m, **mp = mp0;
	struct mbuf *nextrecord;

	socket_lock(so, 1);
	VERIFY(so->so_proto->pr_flags & PR_CONNREQUIRED);

#ifdef MORE_LOCKING_DEBUG
	if (so->so_usecount == 1) {
		panic("%s: so=%x no other reference on socket\n", __func__, so);
		/* NOTREACHED */
	}
#endif
	/*
	 * We return all that is there in the subflow's socket receive buffer
	 * to the MPTCP layer, so we require that the caller passes in the
	 * expected parameters.
	 */
	if (mp == NULL || controlp != NULL) {
		socket_unlock(so, 1);
		return (EINVAL);
	}
	*mp = NULL;
	if (psa != NULL)
		*psa = NULL;
	if (flagsp != NULL)
		flags = *flagsp &~ MSG_EOR;
	else
		flags = 0;

	if (flags & (MSG_PEEK|MSG_OOB|MSG_NEEDSA|MSG_WAITALL|MSG_WAITSTREAM)) {
		socket_unlock(so, 1);
		return (EOPNOTSUPP);
	}
	flags |= (MSG_DONTWAIT|MSG_NBIO);

	/*
	 * If a recv attempt is made on a previously-accepted socket
	 * that has been marked as inactive (disconnected), reject
	 * the request.
	 */
	if (so->so_flags & SOF_DEFUNCT) {
		struct sockbuf *sb = &so->so_rcv;

		error = ENOTCONN;
		SODEFUNCTLOG(("%s[%d]: defunct so 0x%llx [%d,%d] (%d)\n",
		    __func__, proc_pid(p), (uint64_t)VM_KERNEL_ADDRPERM(so),
		    SOCK_DOM(so), SOCK_TYPE(so), error));
		/*
		 * This socket should have been disconnected and flushed
		 * prior to being returned from sodefunct(); there should
		 * be no data on its receive list, so panic otherwise.
		 */
		if (so->so_state & SS_DEFUNCT)
			sb_empty_assert(sb, __func__);
		socket_unlock(so, 1);
		return (error);
	}

	/*
	 * See if the socket has been closed (SS_NOFDREF|SS_CANTRCVMORE)
	 * and if so just return to the caller.  This could happen when
	 * soreceive() is called by a socket upcall function during the
	 * time the socket is freed.  The socket buffer would have been
	 * locked across the upcall, therefore we cannot put this thread
	 * to sleep (else we will deadlock) or return EWOULDBLOCK (else
	 * we may livelock), because the lock on the socket buffer will
	 * only be released when the upcall routine returns to its caller.
	 * Because the socket has been officially closed, there can be
	 * no further read on it.
	 *
	 * A multipath subflow socket would have its SS_NOFDREF set by
	 * default, so check for SOF_MP_SUBFLOW socket flag; when the
	 * socket is closed for real, SOF_MP_SUBFLOW would be cleared.
	 */
	if ((so->so_state & (SS_NOFDREF | SS_CANTRCVMORE)) ==
	    (SS_NOFDREF | SS_CANTRCVMORE) && !(so->so_flags & SOF_MP_SUBFLOW)) {
		socket_unlock(so, 1);
		return (0);
	}

	/*
	 * For consistency with soreceive() semantics, we need to obey
	 * SB_LOCK in case some other code path has locked the buffer.
	 */
	error = sblock(&so->so_rcv, 0);
	if (error != 0) {
		socket_unlock(so, 1);
		return (error);
	}

	m = so->so_rcv.sb_mb;
	if (m == NULL) {
		/*
		 * Panic if we notice inconsistencies in the socket's
		 * receive list; both sb_mb and sb_cc should correctly
		 * reflect the contents of the list, otherwise we may
		 * end up with false positives during select() or poll()
		 * which could put the application in a bad state.
		 */
		SB_MB_CHECK(&so->so_rcv);

		if (so->so_error != 0) {
			error = so->so_error;
			so->so_error = 0;
			goto release;
		}

		if (so->so_state & SS_CANTRCVMORE) {
			goto release;
		}

		if (!(so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING))) {
			error = ENOTCONN;
			goto release;
		}

		/*
		 * MSG_DONTWAIT is implicitly defined and this routine will
		 * never block, so return EWOULDBLOCK when there is nothing.
		 */
		error = EWOULDBLOCK;
		goto release;
	}

	OSIncrementAtomicLong(&p->p_stats->p_ru.ru_msgrcv);
	SBLASTRECORDCHK(&so->so_rcv, "mptcp_subflow_soreceive 1");
	SBLASTMBUFCHK(&so->so_rcv, "mptcp_subflow_soreceive 1");

	while (m != NULL) {
		nextrecord = m->m_nextpkt;
		sbfree(&so->so_rcv, m);

		if (mp != NULL) {
			*mp = m;
			mp = &m->m_next;
			so->so_rcv.sb_mb = m = m->m_next;
			*mp = NULL;
		}

		if (m != NULL) {
			m->m_nextpkt = nextrecord;
			if (nextrecord == NULL)
				so->so_rcv.sb_lastrecord = m;
		} else {
			m = so->so_rcv.sb_mb = nextrecord;
			SB_EMPTY_FIXUP(&so->so_rcv);
		}
		SBLASTRECORDCHK(&so->so_rcv, "mptcp_subflow_soreceive 2");
		SBLASTMBUFCHK(&so->so_rcv, "mptcp_subflow_soreceive 2");
	}

	DTRACE_MPTCP3(subflow__receive, struct socket *, so,
	    struct sockbuf *, &so->so_rcv, struct sockbuf *, &so->so_snd);
	/* notify protocol that we drained all the data */
	if ((so->so_proto->pr_flags & PR_WANTRCVD) && so->so_pcb != NULL)
		(*so->so_proto->pr_usrreqs->pru_rcvd)(so, flags);

	if (flagsp != NULL)
		*flagsp |= flags;

release:
	sbunlock(&so->so_rcv, FALSE);	/* will unlock socket */
	return (error);

}


/*
 * Prepare an MPTCP subflow socket for peeloff(2); basically undo
 * the work done earlier when the subflow socket was created.
 */
void
mptcp_subflow_sopeeloff(struct mptses *mpte, struct mptsub *mpts,
    struct socket *so)
{
	struct mptopt smpo;
	struct socket *mp_so;
	int p, c;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	mp_so = mpte->mpte_mppcb->mpp_socket;
	MPTS_LOCK_ASSERT_HELD(mpts);

	socket_lock(so, 0);
	VERIFY(so->so_flags & SOF_MP_SUBFLOW);
	VERIFY((so->so_state & (SS_NBIO|SS_NOFDREF)) == (SS_NBIO|SS_NOFDREF));

	/* inherit MPTCP socket states */
	if (!(mp_so->so_state & SS_NBIO))
		so->so_state &= ~SS_NBIO;

	/*
	 * At this point, the socket is not yet closed, as there is at least
	 * one outstanding usecount previously held by mpts_socket from
	 * socreate().  Atomically clear SOF_MP_SUBFLOW and SS_NOFDREF here.
	 */
	so->so_flags &= ~SOF_MP_SUBFLOW;
	so->so_state &= ~SS_NOFDREF;
	so->so_state &= ~SOF_MPTCP_TRUE;

	/* allow socket buffers to be compressed */
	so->so_rcv.sb_flags &= ~SB_NOCOMPRESS;
	so->so_snd.sb_flags &= ~SB_NOCOMPRESS;

	/*
	 * Allow socket buffer auto sizing.
	 *
	 * This will increase the current 64k buffer size to whatever is best.
	 */
	so->so_rcv.sb_flags |= SB_AUTOSIZE;
	so->so_snd.sb_flags |= SB_AUTOSIZE;

	/* restore protocol-user requests */
	VERIFY(mpts->mpts_oprotosw != NULL);
	so->so_proto = mpts->mpts_oprotosw;

	bzero(&smpo, sizeof (smpo));
	smpo.mpo_flags |= MPOF_SUBFLOW_OK;
	smpo.mpo_level = SOL_SOCKET;

	/* inherit SOF_NOSIGPIPE from parent MP socket */
	p = (mp_so->so_flags & SOF_NOSIGPIPE);
	c = (so->so_flags & SOF_NOSIGPIPE);
	smpo.mpo_intval = ((p - c) > 0) ? 1 : 0;
	smpo.mpo_name = SO_NOSIGPIPE;
	if ((p - c) != 0)
		(void) mptcp_subflow_sosetopt(mpte, so, &smpo);

	/* inherit SOF_NOADDRAVAIL from parent MP socket */
	p = (mp_so->so_flags & SOF_NOADDRAVAIL);
	c = (so->so_flags & SOF_NOADDRAVAIL);
	smpo.mpo_intval = ((p - c) > 0) ? 1 : 0;
	smpo.mpo_name = SO_NOADDRERR;
	if ((p - c) != 0)
		(void) mptcp_subflow_sosetopt(mpte, so, &smpo);

	/* inherit SO_KEEPALIVE from parent MP socket */
	p = (mp_so->so_options & SO_KEEPALIVE);
	c = (so->so_options & SO_KEEPALIVE);
	smpo.mpo_intval = ((p - c) > 0) ? 1 : 0;
	smpo.mpo_name = SO_KEEPALIVE;
	if ((p - c) != 0)
		(void) mptcp_subflow_sosetopt(mpte, so, &smpo);

	/* unset TCP level default keepalive option */
	p = (intotcpcb(sotoinpcb(mp_so)))->t_keepidle;
	c = (intotcpcb(sotoinpcb(so)))->t_keepidle;
	smpo.mpo_level = IPPROTO_TCP;
	smpo.mpo_intval = 0;
	smpo.mpo_name = TCP_KEEPALIVE;
	if ((p - c) != 0)
		(void) mptcp_subflow_sosetopt(mpte, so, &smpo);
	socket_unlock(so, 0);

	DTRACE_MPTCP5(subflow__peeloff, struct mptses *, mpte,
	    struct mptsub *, mpts, struct socket *, so,
	    struct sockbuf *, &so->so_rcv, struct sockbuf *, &so->so_snd);
}

/*
 * Establish an initial MPTCP connection (if first subflow and not yet
 * connected), or add a subflow to an existing MPTCP connection.
 */
int
mptcp_subflow_add(struct mptses *mpte, struct mptsub *mpts,
    struct proc *p, uint32_t ifscope)
{
	struct sockaddr_entry *se, *src_se = NULL, *dst_se = NULL;
	struct socket *mp_so, *so = NULL;
	struct mptsub_connreq mpcr;
	struct mptcb *mp_tp;
	int af, error = 0;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	mp_so = mpte->mpte_mppcb->mpp_socket;
	mp_tp = mpte->mpte_mptcb;

	MPTS_LOCK(mpts);
	VERIFY(!(mpts->mpts_flags & (MPTSF_CONNECTING|MPTSF_CONNECTED)));
	VERIFY(mpts->mpts_mpte == NULL);
	VERIFY(mpts->mpts_socket == NULL);
	VERIFY(mpts->mpts_dst_sl != NULL);
	VERIFY(mpts->mpts_connid == CONNID_ANY);

	/* select source (if specified) and destination addresses */
	if ((error = in_selectaddrs(AF_UNSPEC, &mpts->mpts_src_sl, &src_se,
	    &mpts->mpts_dst_sl, &dst_se)) != 0)
		goto out;

	VERIFY(mpts->mpts_dst_sl != NULL && dst_se != NULL);
	VERIFY(src_se == NULL || mpts->mpts_src_sl != NULL);
	af = mpts->mpts_family = dst_se->se_addr->sa_family;
	VERIFY(src_se == NULL || src_se->se_addr->sa_family == af);
	VERIFY(af == AF_INET || af == AF_INET6);

	/*
	 * If the source address is not specified, allocate a storage for
	 * it, so that later on we can fill it in with the actual source
	 * IP address chosen by the underlying layer for the subflow after
	 * it is connected.
	 */
	if (mpts->mpts_src_sl == NULL) {
		mpts->mpts_src_sl =
		    sockaddrlist_dup(mpts->mpts_dst_sl, M_WAITOK);
		if (mpts->mpts_src_sl == NULL) {
			error = ENOBUFS;
			goto out;
		}
		se = TAILQ_FIRST(&mpts->mpts_src_sl->sl_head);
		VERIFY(se != NULL && se->se_addr != NULL &&
		    se->se_addr->sa_len == dst_se->se_addr->sa_len);
		bzero(se->se_addr, se->se_addr->sa_len);
		se->se_addr->sa_len = dst_se->se_addr->sa_len;
		se->se_addr->sa_family = dst_se->se_addr->sa_family;
	}

	/* create the subflow socket */
	if ((error = mptcp_subflow_socreate(mpte, mpts, af, p, &so)) != 0)
		goto out;

	/*
	 * XXX: adi@apple.com
	 *
	 * This probably needs to be made smarter, but for now simply
	 * increment the counter, while avoiding 0 (CONNID_ANY) and
	 * -1 (CONNID_ALL).  Assume that an MPTCP connection will not
	 * live too long with (2^32)-2 subflow connection attempts.
	 */
	mpte->mpte_connid_last++;
	if (mpte->mpte_connid_last == CONNID_ALL ||
	    mpte->mpte_connid_last == CONNID_ANY)
		mpte->mpte_connid_last++;

	mpts->mpts_connid = mpte->mpte_connid_last;
	VERIFY(mpts->mpts_connid != CONNID_ANY &&
	    mpts->mpts_connid != CONNID_ALL);

	/* bind subflow socket to the specified interface */
	if (ifscope != IFSCOPE_NONE) {
		socket_lock(so, 0);
		error = inp_bindif(sotoinpcb(so), ifscope, &mpts->mpts_outif);
		if (error != 0) {
			socket_unlock(so, 0);
			(void) mptcp_subflow_soclose(mpts, so);
			goto out;
		}
		VERIFY(mpts->mpts_outif != NULL);
		mpts->mpts_flags |= MPTSF_BOUND_IF;

		mptcplog((LOG_DEBUG, "%s: mp_so 0x%llx bindif %s[%d] "
		    "cid %d\n", __func__,
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
		    mpts->mpts_outif->if_xname,
		    ifscope, mpts->mpts_connid));
		socket_unlock(so, 0);
	}

	/* if source address and/or port is specified, bind to it */
	if (src_se != NULL) {
		struct sockaddr *sa = src_se->se_addr;
		uint32_t mpts_flags = 0;
		in_port_t lport;

		switch (af) {
		case AF_INET:
			if (SIN(sa)->sin_addr.s_addr != INADDR_ANY)
				mpts_flags |= MPTSF_BOUND_IP;
			if ((lport = SIN(sa)->sin_port) != 0)
				mpts_flags |= MPTSF_BOUND_PORT;
			break;
#if INET6
		case AF_INET6:
			VERIFY(af == AF_INET6);
			if (!IN6_IS_ADDR_UNSPECIFIED(&SIN6(sa)->sin6_addr))
				mpts_flags |= MPTSF_BOUND_IP;
			if ((lport = SIN6(sa)->sin6_port) != 0)
				mpts_flags |= MPTSF_BOUND_PORT;
			break;
#endif /* INET6 */
		}

		error = sobindlock(so, sa, 1);	/* will lock/unlock socket */
		if (error != 0) {
			(void) mptcp_subflow_soclose(mpts, so);
			goto out;
		}
		mpts->mpts_flags |= mpts_flags;

		if (af == AF_INET || af == AF_INET6) {
			char sbuf[MAX_IPv6_STR_LEN];

			mptcplog((LOG_DEBUG, "%s: mp_so 0x%llx bindip %s[%d] "
			    "cid %d\n", __func__,
			    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
			    inet_ntop(af, ((af == AF_INET) ?
			    (void *)&SIN(sa)->sin_addr.s_addr :
			    (void *)&SIN6(sa)->sin6_addr), sbuf, sizeof (sbuf)),
			    ntohs(lport), mpts->mpts_connid));
		}
	}

	/*
	 * Insert the subflow into the list, and associate the MPTCP PCB
	 * as well as the the subflow socket.  From this point on, removing
	 * the subflow needs to be done via mptcp_subflow_del().
	 */
	TAILQ_INSERT_TAIL(&mpte->mpte_subflows, mpts, mpts_entry);
	mpte->mpte_numflows++;

	atomic_bitset_32(&mpts->mpts_flags, MPTSF_ATTACHED);
	mpts->mpts_mpte = mpte;
	mpts->mpts_socket = so;
	MPTS_ADDREF_LOCKED(mpts);	/* for being in MPTCP subflow list */
	MPTS_ADDREF_LOCKED(mpts);	/* for subflow socket */
	mp_so->so_usecount++;		/* for subflow socket */

	/* register for subflow socket read/write events */
	(void) sock_setupcalls(so, mptcp_subflow_rupcall, mpts,
	    mptcp_subflow_wupcall, mpts);

	/*
	 * Register for subflow socket control events; ignore
	 * SO_FILT_HINT_CONNINFO_UPDATED from below since we
	 * will generate it here.
	 */
	(void) sock_catchevents(so, mptcp_subflow_eupcall, mpts,
	    SO_FILT_HINT_CONNRESET | SO_FILT_HINT_CANTRCVMORE |
	    SO_FILT_HINT_CANTSENDMORE | SO_FILT_HINT_TIMEOUT |
	    SO_FILT_HINT_NOSRCADDR | SO_FILT_HINT_IFDENIED |
	    SO_FILT_HINT_SUSPEND | SO_FILT_HINT_RESUME |
	    SO_FILT_HINT_CONNECTED | SO_FILT_HINT_DISCONNECTED |
	    SO_FILT_HINT_MPFAILOVER | SO_FILT_HINT_MPSTATUS |
	    SO_FILT_HINT_MUSTRST);

	/* sanity check */
	VERIFY(!(mpts->mpts_flags &
	    (MPTSF_CONNECTING|MPTSF_CONNECTED|MPTSF_CONNECT_PENDING)));

	bzero(&mpcr, sizeof (mpcr));
	mpcr.mpcr_proc = p;
	mpcr.mpcr_ifscope = ifscope;
	/*
	 * Indicate to the TCP subflow whether or not it should establish
	 * the initial MPTCP connection, or join an existing one.  Fill
	 * in the connection request structure with additional info needed
	 * by the underlying TCP (to be used in the TCP options, etc.)
	 */
	MPT_LOCK(mp_tp);
	if (mp_tp->mpt_state < MPTCPS_ESTABLISHED && mpte->mpte_numflows == 1) {
		if (mp_tp->mpt_state == MPTCPS_CLOSED) {
			mp_tp->mpt_localkey = mptcp_reserve_key();
			mptcp_conn_properties(mp_tp);
		}
		MPT_UNLOCK(mp_tp);
		soisconnecting(mp_so);
		mpcr.mpcr_type = MPTSUB_CONNREQ_MP_ENABLE;
	} else {
		if (!(mp_tp->mpt_flags & MPTCPF_JOIN_READY))
			mpts->mpts_flags |= MPTSF_CONNECT_PENDING;
		MPT_UNLOCK(mp_tp);
		mpcr.mpcr_type = MPTSUB_CONNREQ_MP_ADD;
	}

	mpts->mpts_mpcr = mpcr;
	mpts->mpts_flags |= MPTSF_CONNECTING;

	if (af == AF_INET || af == AF_INET6) {
		char dbuf[MAX_IPv6_STR_LEN];

		mptcplog((LOG_DEBUG, "%s: mp_so 0x%llx dst %s[%d] cid %d "
		    "[pending %s]\n", __func__,
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
		    inet_ntop(af, ((af == AF_INET) ?
		    (void *)&SIN(dst_se->se_addr)->sin_addr.s_addr :
		    (void *)&SIN6(dst_se->se_addr)->sin6_addr),
		    dbuf, sizeof (dbuf)), ((af == AF_INET) ?
		    ntohs(SIN(dst_se->se_addr)->sin_port) :
		    ntohs(SIN6(dst_se->se_addr)->sin6_port)),
		    mpts->mpts_connid,
		    ((mpts->mpts_flags & MPTSF_CONNECT_PENDING) ?
		    "YES" : "NO")));
	}

	/* connect right away if first attempt, or if join can be done now */
	if (!(mpts->mpts_flags & MPTSF_CONNECT_PENDING))
		error = mptcp_subflow_soconnectx(mpte, mpts);

out:
	MPTS_UNLOCK(mpts);
	if (error == 0) {
		soevent(mp_so, SO_FILT_HINT_LOCKED |
		    SO_FILT_HINT_CONNINFO_UPDATED);
	}
	return (error);
}

static int
mptcp_delete_ok(struct mptses *mpte, struct mptsub *mpts)
{
	int ret = 1;
	struct mptcb *mp_tp = NULL;

	MPTE_LOCK_ASSERT_HELD(mpte);
	mp_tp = mpte->mpte_mptcb;
	VERIFY(mp_tp != NULL);
	MPTS_LOCK(mpts);
	MPT_LOCK(mp_tp);
	if ((mpts->mpts_soerror == 0) &&
	    (mpts->mpts_flags & MPTSF_ACTIVE) &&
	    (mp_tp->mpt_state != MPTCPS_CLOSED) &&
	    (mp_tp->mpt_state <= MPTCPS_TIME_WAIT))
		ret = 0;
	MPT_UNLOCK(mp_tp);
	MPTS_UNLOCK(mpts);
	return (ret);
}

/*
 * Delete/remove a subflow from an MPTCP.  The underlying subflow socket
 * will no longer be accessible after a subflow is deleted, thus this
 * should occur only after the subflow socket has been disconnected.
 * If peeloff(2) is called, leave the socket open.
 */
void
mptcp_subflow_del(struct mptses *mpte, struct mptsub *mpts, boolean_t close)
{
	struct socket *mp_so, *so;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	mp_so = mpte->mpte_mppcb->mpp_socket;

	MPTS_LOCK(mpts);
	so = mpts->mpts_socket;
	VERIFY(so != NULL);

	mptcplog((LOG_DEBUG, "%s: mp_so 0x%llx [u=%d,r=%d] cid %d "
	    "[close %s] %d %x\n", __func__,
	    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
	    mp_so->so_usecount,
	    mp_so->so_retaincnt, mpts->mpts_connid,
	    (close ? "YES" : "NO"), mpts->mpts_soerror,
	    mpts->mpts_flags));

	VERIFY(mpts->mpts_mpte == mpte);
	VERIFY(mpts->mpts_connid != CONNID_ANY &&
	    mpts->mpts_connid != CONNID_ALL);

	VERIFY(mpts->mpts_flags & MPTSF_ATTACHED);
	atomic_bitclear_32(&mpts->mpts_flags, MPTSF_ATTACHED);
	TAILQ_REMOVE(&mpte->mpte_subflows, mpts, mpts_entry);
	VERIFY(mpte->mpte_numflows != 0);
	mpte->mpte_numflows--;

	/*
	 * Drop references held by this subflow socket; there
	 * will be no further upcalls made from this point.
	 */
	(void) sock_setupcalls(so, NULL, NULL, NULL, NULL);
	(void) sock_catchevents(so, NULL, NULL, 0);
	mptcp_detach_mptcb_from_subf(mpte->mpte_mptcb, so);
	if (close)
		(void) mptcp_subflow_soclose(mpts, so);

	VERIFY(mp_so->so_usecount != 0);
	mp_so->so_usecount--;		/* for subflow socket */
	mpts->mpts_mpte = NULL;
	mpts->mpts_socket = NULL;
	MPTS_UNLOCK(mpts);

	MPTS_REMREF(mpts);		/* for MPTCP subflow list */
	MPTS_REMREF(mpts);		/* for subflow socket */

	soevent(mp_so, SO_FILT_HINT_LOCKED | SO_FILT_HINT_CONNINFO_UPDATED);
}

/*
 * Disconnect a subflow socket.
 */
void
mptcp_subflow_disconnect(struct mptses *mpte, struct mptsub *mpts,
    boolean_t deleteok)
{
	struct socket *so;
	struct mptcb *mp_tp;
	int send_dfin = 0;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);

	VERIFY(mpts->mpts_mpte == mpte);
	VERIFY(mpts->mpts_socket != NULL);
	VERIFY(mpts->mpts_connid != CONNID_ANY &&
	    mpts->mpts_connid != CONNID_ALL);

	if (mpts->mpts_flags & (MPTSF_DISCONNECTING|MPTSF_DISCONNECTED))
		return;

	mpts->mpts_flags |= MPTSF_DISCONNECTING;

	/*
	 * If this is coming from disconnectx(2) or issued as part of
	 * closing the MPTCP socket, the subflow shouldn't stick around.
	 * Otherwise let it linger around in case the upper layers need
	 * to retrieve its conninfo.
	 */
	if (deleteok)
		mpts->mpts_flags |= MPTSF_DELETEOK;

	so = mpts->mpts_socket;
	mp_tp = mpte->mpte_mptcb;
	MPT_LOCK(mp_tp);
	if (mp_tp->mpt_state > MPTCPS_ESTABLISHED)
		send_dfin = 1;
	MPT_UNLOCK(mp_tp);

	socket_lock(so, 0);
	if (!(so->so_state & (SS_ISDISCONNECTING | SS_ISDISCONNECTED)) &&
	    (so->so_state & SS_ISCONNECTED)) {
		mptcplog((LOG_DEBUG, "%s: cid %d fin %d [linger %s]\n",
		    __func__, mpts->mpts_connid, send_dfin,
		    (deleteok ? "NO" : "YES")));

		if (send_dfin)
			mptcp_send_dfin(so);
		(void) soshutdownlock(so, SHUT_RD);
		(void) soshutdownlock(so, SHUT_WR);
		(void) sodisconnectlocked(so);
	}
	socket_unlock(so, 0);
	/*
	 * Generate a disconnect event for this subflow socket, in case
	 * the lower layer doesn't do it; this is needed because the
	 * subflow socket deletion relies on it.  This will also end up
	 * generating SO_FILT_HINT_CONNINFO_UPDATED on the MPTCP socket;
	 * we cannot do that here because subflow lock is currently held.
	 */
	mptcp_subflow_eupcall(so, mpts, SO_FILT_HINT_DISCONNECTED);
}

/*
 * Subflow socket read upcall.
 *
 * Called when the associated subflow socket posted a read event.  The subflow
 * socket lock has been released prior to invoking the callback.  Note that the
 * upcall may occur synchronously as a result of MPTCP performing an action on
 * it, or asynchronously as a result of an event happening at the subflow layer.
 * Therefore, to maintain lock ordering, the only lock that can be acquired
 * here is the thread lock, for signalling purposes.
 */
static void
mptcp_subflow_rupcall(struct socket *so, void *arg, int waitf)
{
#pragma unused(so, waitf)
	struct mptsub *mpts = arg;
	struct mptses *mpte = mpts->mpts_mpte;

	VERIFY(mpte != NULL);

	lck_mtx_lock(&mpte->mpte_thread_lock);
	mptcp_thread_signal_locked(mpte);
	lck_mtx_unlock(&mpte->mpte_thread_lock);
}

/*
 * Subflow socket input.
 *
 * Called in the context of the MPTCP thread, for reading data from the
 * underlying subflow socket and delivering it to MPTCP.
 */
static void
mptcp_subflow_input(struct mptses *mpte, struct mptsub *mpts)
{
	struct mbuf *m = NULL;
	struct socket *so;
	int error;
	struct mptsub *mpts_alt = NULL;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);

	DTRACE_MPTCP2(subflow__input, struct mptses *, mpte, 
	    struct mptsub *, mpts);

	if (!(mpts->mpts_flags & MPTSF_CONNECTED))
		return;

	so = mpts->mpts_socket;

	error = sock_receive_internal(so, NULL, &m, 0, NULL);
	if (error != 0 && error != EWOULDBLOCK) {
		mptcplog((LOG_ERR, "%s: cid %d error %d\n",
		    __func__, mpts->mpts_connid, error));
		MPTS_UNLOCK(mpts);
		mpts_alt = mptcp_get_subflow(mpte, mpts);
		if (mpts_alt == NULL) {
			mptcplog((LOG_ERR, "%s: no alt path cid %d\n",
			    __func__, mpts->mpts_connid));
			mpte->mpte_mppcb->mpp_socket->so_error = error;
		}
		MPTS_LOCK(mpts);
	} else if (error == 0) {
		mptcplog3((LOG_DEBUG, "%s: cid %d \n",
		    __func__, mpts->mpts_connid));
	}

	/* In fallback, make sure to accept data on all but one subflow */
	if ((mpts->mpts_flags & MPTSF_MP_DEGRADED) &&
	    (!(mpts->mpts_flags & MPTSF_ACTIVE))) {
		m_freem(m);
		return;
	}

	if (m != NULL) {
		/*
		 * Release subflow lock since this may trigger MPTCP to send,
		 * possibly on a different subflow.  An extra reference has
		 * been held on the subflow by the MPTCP thread before coming
		 * here, so we can be sure that it won't go away, in the event
		 * the MP socket lock gets released.
		 */
		MPTS_UNLOCK(mpts);
		mptcp_input(mpte, m);
		MPTS_LOCK(mpts);
	}
}

/*
 * Subflow socket write upcall.
 *
 * Called when the associated subflow socket posted a read event.  The subflow
 * socket lock has been released prior to invoking the callback.  Note that the
 * upcall may occur synchronously as a result of MPTCP performing an action on
 * it, or asynchronously as a result of an event happening at the subflow layer.
 * Therefore, to maintain lock ordering, the only lock that can be acquired
 * here is the thread lock, for signalling purposes.
 */
static void
mptcp_subflow_wupcall(struct socket *so, void *arg, int waitf)
{
#pragma unused(so, waitf)
	struct mptsub *mpts = arg;
	struct mptses *mpte = mpts->mpts_mpte;

	VERIFY(mpte != NULL);

	lck_mtx_lock(&mpte->mpte_thread_lock);
	mptcp_thread_signal_locked(mpte);
	lck_mtx_unlock(&mpte->mpte_thread_lock);
}

/*
 * Subflow socket output.
 *
 * Called for sending data from MPTCP to the underlying subflow socket.
 */
int
mptcp_subflow_output(struct mptses *mpte, struct mptsub *mpts)
{
	struct socket *mp_so, *so;
	size_t sb_cc = 0, tot_sent = 0;
	struct mbuf *sb_mb;
	int error = 0;
	u_int64_t mpt_dsn = 0;
	struct mptcb *mp_tp = mpte->mpte_mptcb;
	struct mbuf *mpt_mbuf = NULL;
	unsigned int off = 0;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);
	mp_so = mpte->mpte_mppcb->mpp_socket;
	so = mpts->mpts_socket;

	DTRACE_MPTCP2(subflow__output, struct mptses *, mpte, 
	    struct mptsub *, mpts);

	/* subflow socket is suspended? */
	if (mpts->mpts_flags & MPTSF_SUSPENDED) {
		mptcplog((LOG_ERR, "%s: mp_so 0x%llx cid %d is flow "
		    "controlled\n", __func__,
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so), mpts->mpts_connid));
		goto out;
	}

	/* subflow socket is not MPTCP capable? */
	if (!(mpts->mpts_flags & MPTSF_MP_CAPABLE) &&
	    !(mpts->mpts_flags & MPTSF_MP_DEGRADED)) {
		mptcplog((LOG_ERR, "%s: mp_so 0x%llx cid %d not "
		    "MPTCP capable\n", __func__,
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so), mpts->mpts_connid));
		goto out;
	}

	/* Remove Addr Option is not sent reliably as per I-D */
	if (mpte->mpte_flags & MPTE_SND_REM_ADDR) {
		struct tcpcb *tp = intotcpcb(sotoinpcb(so));
		tp->t_rem_aid = mpte->mpte_lost_aid;
		if (mptcp_remaddr_enable)
			tp->t_mpflags |= TMPF_SND_REM_ADDR;
		mpte->mpte_flags &= ~MPTE_SND_REM_ADDR;
	}

	/*
	 * The mbuf chains containing the metadata (as well as pointing to
	 * the user data sitting at the MPTCP output queue) would then be
	 * sent down to the subflow socket.
	 *
	 * Some notes on data sequencing:
	 *
	 *   a. Each mbuf must be a M_PKTHDR.
	 *   b. MPTCP metadata is stored in the mptcp_pktinfo structure
	 *	in the mbuf pkthdr structure.
	 *   c. Each mbuf containing the MPTCP metadata must have its
	 *	pkt_flags marked with the PKTF_MPTCP flag.
	 */

	/* First, drop acknowledged data */
	sb_mb = mp_so->so_snd.sb_mb;
	if (sb_mb == NULL) {
		goto out;
	}

	VERIFY(sb_mb->m_pkthdr.pkt_flags & PKTF_MPTCP);

	mpt_mbuf = sb_mb;
	while (mpt_mbuf && mpt_mbuf->m_pkthdr.mp_rlen == 0) {
		mpt_mbuf = mpt_mbuf->m_next;
	}
	if (mpt_mbuf && (mpt_mbuf->m_pkthdr.pkt_flags & PKTF_MPTCP)) {
		mpt_dsn = mpt_mbuf->m_pkthdr.mp_dsn;
	} else {
		goto out;
	}

	MPT_LOCK(mp_tp);
	if (MPTCP_SEQ_LT(mpt_dsn, mp_tp->mpt_snduna)) {
		int len = 0;
		len = mp_tp->mpt_snduna - mpt_dsn;
		sbdrop(&mp_so->so_snd, len);

	}

	/*
	 * In degraded mode, we don't receive data acks, so force free
	 * mbufs less than snd_nxt
	 */
	mpt_dsn = mp_so->so_snd.sb_mb->m_pkthdr.mp_dsn;
	if ((mpts->mpts_flags & MPTSF_MP_DEGRADED) &&
	    MPTCP_SEQ_LT(mpt_dsn, mp_tp->mpt_sndnxt)) {
		int len = 0;
		len = mp_tp->mpt_sndnxt - mpt_dsn;
		sbdrop(&mp_so->so_snd, len);
		mp_tp->mpt_snduna = mp_tp->mpt_sndnxt;
	}

	/*
	 * Adjust the subflow's notion of next byte to send based on
	 * the last unacknowledged byte
	 */
	if (MPTCP_SEQ_LT(mpts->mpts_sndnxt, mp_tp->mpt_snduna)) {
		mpts->mpts_sndnxt = mp_tp->mpt_snduna;
	}

	/*
	 * Adjust the top level notion of next byte used for retransmissions
	 * and sending FINs.
	 */
	if (MPTCP_SEQ_LT(mp_tp->mpt_sndnxt, mp_tp->mpt_snduna)) {
		mp_tp->mpt_sndnxt = mp_tp->mpt_snduna;
	}


	/* Now determine the offset from which to start transmitting data */
	sb_mb = mp_so->so_snd.sb_mb;
	sb_cc = mp_so->so_snd.sb_cc;
	if (sb_mb == NULL) {
		MPT_UNLOCK(mp_tp);
		goto out;
	}
	if (MPTCP_SEQ_LT(mpts->mpts_sndnxt, mp_tp->mpt_sndmax)) {
		off = mpts->mpts_sndnxt - mp_tp->mpt_snduna;
		sb_cc -= off;
	} else {
		MPT_UNLOCK(mp_tp);
		goto out;
	}
	MPT_UNLOCK(mp_tp);

	mpt_mbuf = sb_mb;
	mpt_dsn = mpt_mbuf->m_pkthdr.mp_dsn;

	while (mpt_mbuf && ((mpt_mbuf->m_pkthdr.mp_rlen == 0) ||
	    (mpt_mbuf->m_pkthdr.mp_rlen <= off))) {
		off -= mpt_mbuf->m_pkthdr.mp_rlen;
		mpt_mbuf = mpt_mbuf->m_next;
		mpt_dsn = mpt_mbuf->m_pkthdr.mp_dsn;
	}
	if ((mpts->mpts_connid == 2) || (mpts->mpts_flags & MPTSF_MP_DEGRADED))
		mptcplog((LOG_INFO, "%s: snduna = %llu off = %d id = %d"
		    " %llu \n",
		    __func__,
		    mp_tp->mpt_snduna, off, mpts->mpts_connid,
		    mpts->mpts_sndnxt));

	VERIFY(mpt_mbuf && (mpt_mbuf->m_pkthdr.pkt_flags & PKTF_MPTCP));

	while (tot_sent < sb_cc) {
		struct mbuf *m;
		size_t mlen, len = 0;

		mlen = mpt_mbuf->m_pkthdr.mp_rlen;
		mlen -= off;
		if (mlen == 0)
			goto out;

		if (mlen > sb_cc) {
			panic("%s: unexpected %lu %lu \n", __func__,
			    mlen, sb_cc);
		}

		m = m_copym_mode(mpt_mbuf, off, mlen, M_DONTWAIT,
		    M_COPYM_COPY_HDR);
		if (m == NULL) {
			error = ENOBUFS;
			break;
		}

		/* Create a DSN mapping for the data (m_copym does it) */
		mpt_dsn = mpt_mbuf->m_pkthdr.mp_dsn;
		m->m_pkthdr.pkt_flags |= PKTF_MPTCP;
		m->m_pkthdr.pkt_flags &= ~PKTF_MPSO;
		m->m_pkthdr.mp_dsn = mpt_dsn + off;
		m->m_pkthdr.mp_rseq = mpts->mpts_rel_seq;
		m->m_pkthdr.mp_rlen = mlen;
		mpts->mpts_rel_seq += mlen;
		m->m_pkthdr.len = mlen;

		/* last contiguous mapping is stored for error cases */
		if (mpts->mpts_lastmap.mptsl_dsn +
		    mpts->mpts_lastmap.mptsl_len == mpt_dsn) {
			mpts->mpts_lastmap.mptsl_len += tot_sent;
		} else if (MPTCP_SEQ_LT((mpts->mpts_lastmap.mptsl_dsn +
		    mpts->mpts_lastmap.mptsl_len), mpt_dsn)) {
			if (m->m_pkthdr.mp_dsn == 0)
				panic("%s %llu", __func__, mpt_dsn);
			mpts->mpts_lastmap.mptsl_dsn = m->m_pkthdr.mp_dsn;
			mpts->mpts_lastmap.mptsl_sseq = m->m_pkthdr.mp_rseq;
			mpts->mpts_lastmap.mptsl_len = m->m_pkthdr.mp_rlen;
		}

		error = sock_sendmbuf(so, NULL, m, 0, &len);
		DTRACE_MPTCP7(send, struct mbuf *, m, struct socket *, so, 
		    struct sockbuf *, &so->so_rcv,
		    struct sockbuf *, &so->so_snd,
		    struct mptses *, mpte, struct mptsub *, mpts,
		    size_t, mlen);
		if (error != 0) {
			mptcplog((LOG_ERR, "%s: len = %zd error = %d \n",
			    __func__, len, error));
			break;
		}
		mpts->mpts_sndnxt += mlen;
		MPT_LOCK(mp_tp);
		if (MPTCP_SEQ_LT(mp_tp->mpt_sndnxt, mpts->mpts_sndnxt)) {
			if (MPTCP_DATASEQ_HIGH32(mpts->mpts_sndnxt) >
			    MPTCP_DATASEQ_HIGH32(mp_tp->mpt_sndnxt))
				mp_tp->mpt_flags |= MPTCPF_SND_64BITDSN;
			mp_tp->mpt_sndnxt = mpts->mpts_sndnxt;
		}
		MPT_UNLOCK(mp_tp);
		if (len != mlen) {
			mptcplog((LOG_ERR, "%s: cid %d wrote %d "
			    "(expected %d)\n", __func__,
			    mpts->mpts_connid, len, mlen));
		}
		tot_sent += mlen;
		off = 0;
		mpt_mbuf = mpt_mbuf->m_next;
	}

	if (error != 0 && error != EWOULDBLOCK) {
		mptcplog((LOG_ERR, "MPTCP ERROR %s: cid %d error %d\n",
		    __func__, mpts->mpts_connid, error));
	} if (error == 0) {
		if ((mpts->mpts_connid == 2) ||
		    (mpts->mpts_flags & MPTSF_MP_DEGRADED))
			mptcplog((LOG_DEBUG, "%s: cid %d wrote %d %d\n",
			    __func__, mpts->mpts_connid, tot_sent,
			    sb_cc));
		MPT_LOCK(mp_tp);
		mptcp_cancel_timer(mp_tp, MPTT_REXMT);
		MPT_UNLOCK(mp_tp);
	}
out:
	return (error);
}

/*
 * Subflow socket control event upcall.
 *
 * Called when the associated subflow socket posted one or more control events.
 * The subflow socket lock has been released prior to invoking the callback.
 * Note that the upcall may occur synchronously as a result of MPTCP performing
 * an action on it, or asynchronously as a result of an event happening at the
 * subflow layer.  Therefore, to maintain lock ordering, the only lock that can
 * be acquired here is the thread lock, for signalling purposes.
 */
static void
mptcp_subflow_eupcall(struct socket *so, void *arg, uint32_t events)
{
#pragma unused(so)
	struct mptsub *mpts = arg;
	struct mptses *mpte = mpts->mpts_mpte;

	VERIFY(mpte != NULL);

	lck_mtx_lock(&mpte->mpte_thread_lock);
	atomic_bitset_32(&mpts->mpts_evctl, events);
	mptcp_thread_signal_locked(mpte);
	lck_mtx_unlock(&mpte->mpte_thread_lock);
}

/*
 * Subflow socket control events.
 *
 * Called for handling events related to the underlying subflow socket.
 */
static ev_ret_t
mptcp_subflow_events(struct mptses *mpte, struct mptsub *mpts)
{
	uint32_t events;
	ev_ret_t ret = MPTS_EVRET_OK;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);

	/* bail if there's nothing to process */
	if ((events = mpts->mpts_evctl) == 0)
		return (ret);

	if (events & (SO_FILT_HINT_CONNRESET|SO_FILT_HINT_MUSTRST|
	    SO_FILT_HINT_CANTRCVMORE|SO_FILT_HINT_CANTSENDMORE|
	    SO_FILT_HINT_TIMEOUT|SO_FILT_HINT_NOSRCADDR|
	    SO_FILT_HINT_IFDENIED|SO_FILT_HINT_SUSPEND|
	    SO_FILT_HINT_DISCONNECTED)) {
		events |= SO_FILT_HINT_MPFAILOVER;
	}

	DTRACE_MPTCP3(subflow__events, struct mptses *, mpte,
	    struct mptsub *, mpts, uint32_t, events);

	mptcplog2((LOG_DEBUG, "%s: cid %d events=%b\n", __func__,
	    mpts->mpts_connid, events, SO_FILT_HINT_BITS));

	if ((events & SO_FILT_HINT_MPFAILOVER) && (ret >= MPTS_EVRET_OK)) {
		ev_ret_t error = mptcp_subflow_failover_ev(mpte, mpts);
		events &= ~SO_FILT_HINT_MPFAILOVER;
		ret = ((error >= MPTS_EVRET_OK) ? MAX(error, ret) : error);
	}
	if ((events & SO_FILT_HINT_CONNRESET) && (ret >= MPTS_EVRET_OK)) {
		ev_ret_t error = mptcp_subflow_connreset_ev(mpte, mpts);
		events &= ~SO_FILT_HINT_CONNRESET;
		ret = ((error >= MPTS_EVRET_OK) ? MAX(error, ret) : error);
	}
	if ((events & SO_FILT_HINT_MUSTRST) && (ret >= MPTS_EVRET_OK)) {
		ev_ret_t error = mptcp_subflow_mustrst_ev(mpte, mpts);
		events &= ~SO_FILT_HINT_MUSTRST;
		ret = ((error >= MPTS_EVRET_OK) ? MAX(error, ret) : error);
	}
	if ((events & SO_FILT_HINT_CANTRCVMORE) && (ret >= MPTS_EVRET_OK)) {
		ev_ret_t error = mptcp_subflow_cantrcvmore_ev(mpte, mpts);
		events &= ~SO_FILT_HINT_CANTRCVMORE;
		ret = ((error >= MPTS_EVRET_OK) ? MAX(error, ret) : error);
	}
	if ((events & SO_FILT_HINT_CANTSENDMORE) && (ret >= MPTS_EVRET_OK)) {
		ev_ret_t error = mptcp_subflow_cantsendmore_ev(mpte, mpts);
		events &= ~SO_FILT_HINT_CANTSENDMORE;
		ret = ((error >= MPTS_EVRET_OK) ? MAX(error, ret) : error);
	}
	if ((events & SO_FILT_HINT_TIMEOUT) && (ret >= MPTS_EVRET_OK)) {
		ev_ret_t error = mptcp_subflow_timeout_ev(mpte, mpts);
		events &= ~SO_FILT_HINT_TIMEOUT;
		ret = ((error >= MPTS_EVRET_OK) ? MAX(error, ret) : error);
	}
	if ((events & SO_FILT_HINT_NOSRCADDR) && (ret >= MPTS_EVRET_OK)) {
		ev_ret_t error = mptcp_subflow_nosrcaddr_ev(mpte, mpts);
		events &= ~SO_FILT_HINT_NOSRCADDR;
		ret = ((error >= MPTS_EVRET_OK) ? MAX(error, ret) : error);
	}
	if ((events & SO_FILT_HINT_IFDENIED) && (ret >= MPTS_EVRET_OK)) {
		ev_ret_t error = mptcp_subflow_ifdenied_ev(mpte, mpts);
		events &= ~SO_FILT_HINT_IFDENIED;
		ret = ((error >= MPTS_EVRET_OK) ? MAX(error, ret) : error);
	}
	if ((events & SO_FILT_HINT_SUSPEND) && (ret >= MPTS_EVRET_OK)) {
		ev_ret_t error = mptcp_subflow_suspend_ev(mpte, mpts);
		events &= ~SO_FILT_HINT_SUSPEND;
		ret = ((error >= MPTS_EVRET_OK) ? MAX(error, ret) : error);
	}
	if ((events & SO_FILT_HINT_RESUME) && (ret >= MPTS_EVRET_OK)) {
		ev_ret_t error = mptcp_subflow_resume_ev(mpte, mpts);
		events &= ~SO_FILT_HINT_RESUME;
		ret = ((error >= MPTS_EVRET_OK) ? MAX(error, ret) : error);
	}
	if ((events & SO_FILT_HINT_CONNECTED) && (ret >= MPTS_EVRET_OK)) {
		ev_ret_t error = mptcp_subflow_connected_ev(mpte, mpts);
		events &= ~SO_FILT_HINT_CONNECTED;
		ret = ((error >= MPTS_EVRET_OK) ? MAX(error, ret) : error);
	}
	if ((events & SO_FILT_HINT_MPSTATUS) && (ret >= MPTS_EVRET_OK)) {
		ev_ret_t error = mptcp_subflow_mpstatus_ev(mpte, mpts);
		events &= ~SO_FILT_HINT_MPSTATUS;
		ret = ((error >= MPTS_EVRET_OK) ? MAX(error, ret) : error);
	}
	if ((events & SO_FILT_HINT_DISCONNECTED) && (ret >= MPTS_EVRET_OK)) {
		ev_ret_t error = mptcp_subflow_disconnected_ev(mpte, mpts);
		events &= ~SO_FILT_HINT_DISCONNECTED;
		ret = ((error >= MPTS_EVRET_OK) ? MAX(error, ret) : error);
	}
	/*
	 * We should be getting only events specified via sock_catchevents(),
	 * so loudly complain if we have any unprocessed one(s).
	 */
	if (events != 0 || ret < MPTS_EVRET_OK) {
		mptcplog((LOG_ERR, "%s%s: cid %d evret %s (%d)"
		    " unhandled events=%b\n",
		    (events != 0) ? "MPTCP_ERROR " : "", 
		    __func__, mpts->mpts_connid,
		    mptcp_evret2str(ret), ret, events, SO_FILT_HINT_BITS));
	}

	/* clear the ones we've processed */
	atomic_bitclear_32(&mpts->mpts_evctl, ~events);

	return (ret);
}

/*
 * Handle SO_FILT_HINT_CONNRESET subflow socket event.
 */
static ev_ret_t
mptcp_subflow_connreset_ev(struct mptses *mpte, struct mptsub *mpts)
{
	struct socket *mp_so, *so;
	struct mptcb *mp_tp;
	boolean_t linger;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);
	VERIFY(mpte->mpte_mppcb != NULL);
	mp_so = mpte->mpte_mppcb->mpp_socket;
	mp_tp = mpte->mpte_mptcb;
	so = mpts->mpts_socket;

	linger = (!(mpts->mpts_flags & MPTSF_DELETEOK) &&
	    !(mp_so->so_flags & SOF_PCBCLEARING));

	mptcplog((LOG_DEBUG, "%s: cid %d [linger %s]\n", __func__,
	    mpts->mpts_connid, (linger ? "YES" : "NO")));

	if (mpts->mpts_soerror == 0)
		mpts->mpts_soerror = ECONNREFUSED;

	/*
	 * We got a TCP RST for this subflow connection.
	 *
	 * Right now, we simply propagate ECONNREFUSED to the MPTCP socket
	 * client if the MPTCP connection has not been established. Otherwise
	 * we close the socket.
	 */
	mptcp_subflow_disconnect(mpte, mpts, !linger);

	MPT_LOCK(mp_tp);
	if (mp_tp->mpt_state < MPTCPS_ESTABLISHED) {
		mp_so->so_error = ECONNREFUSED;
	}
	MPT_UNLOCK(mp_tp);

	/*
	 * Keep the subflow socket around, unless the MPTCP socket has
	 * been detached or the subflow has been disconnected explicitly,
	 * in which case it should be deleted right away.
	 */
	return (linger ? MPTS_EVRET_OK : MPTS_EVRET_DELETE);
}

/*
 * Handle SO_FILT_HINT_CANTRCVMORE subflow socket event.
 */
static ev_ret_t
mptcp_subflow_cantrcvmore_ev(struct mptses *mpte, struct mptsub *mpts)
{
	struct socket *so;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);

	so = mpts->mpts_socket;

	mptcplog((LOG_DEBUG, "%s: cid %d\n", __func__, mpts->mpts_connid));

	/*
	 * We got a FIN for this subflow connection.  This subflow socket
	 * is no longer available for receiving data;
	 * The FIN may arrive with data. The data is handed up to the
	 * mptcp socket and the subflow is disconnected.
	 */

	return (MPTS_EVRET_OK);	/* keep the subflow socket around */
}

/*
 * Handle SO_FILT_HINT_CANTSENDMORE subflow socket event.
 */
static ev_ret_t
mptcp_subflow_cantsendmore_ev(struct mptses *mpte, struct mptsub *mpts)
{
	struct socket *so;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);

	so = mpts->mpts_socket;

	mptcplog((LOG_DEBUG, "%s: cid %d\n", __func__, mpts->mpts_connid));
	return (MPTS_EVRET_OK);	/* keep the subflow socket around */
}

/*
 * Handle SO_FILT_HINT_TIMEOUT subflow socket event.
 */
static ev_ret_t
mptcp_subflow_timeout_ev(struct mptses *mpte, struct mptsub *mpts)
{
	struct socket *mp_so, *so;
	struct mptcb *mp_tp;
	boolean_t linger;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);
	VERIFY(mpte->mpte_mppcb != NULL);
	mp_so = mpte->mpte_mppcb->mpp_socket;
	mp_tp = mpte->mpte_mptcb;
	so = mpts->mpts_socket;

	linger = (!(mpts->mpts_flags & MPTSF_DELETEOK) &&
	    !(mp_so->so_flags & SOF_PCBCLEARING));

	mptcplog((LOG_NOTICE, "%s: cid %d [linger %s]\n", __func__,
	    mpts->mpts_connid, (linger ? "YES" : "NO")));

	if (mpts->mpts_soerror == 0)
		mpts->mpts_soerror = ETIMEDOUT;

	/*
	 * The subflow connection has timed out.
	 *
	 * Right now, we simply propagate ETIMEDOUT to the MPTCP socket
	 * client if the MPTCP connection has not been established. Otherwise
	 * drop it.
	 */
	mptcp_subflow_disconnect(mpte, mpts, !linger);

	MPT_LOCK(mp_tp);
	if (mp_tp->mpt_state < MPTCPS_ESTABLISHED) {
		mp_so->so_error = ETIMEDOUT;
	}
	MPT_UNLOCK(mp_tp);

	/*
	 * Keep the subflow socket around, unless the MPTCP socket has
	 * been detached or the subflow has been disconnected explicitly,
	 * in which case it should be deleted right away.
	 */
	return (linger ? MPTS_EVRET_OK : MPTS_EVRET_DELETE);
}

/*
 * Handle SO_FILT_HINT_NOSRCADDR subflow socket event.
 */
static ev_ret_t
mptcp_subflow_nosrcaddr_ev(struct mptses *mpte, struct mptsub *mpts)
{
	struct socket *mp_so, *so;
	struct mptcb *mp_tp;
	boolean_t linger;
	struct tcpcb *tp = NULL;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);

	VERIFY(mpte->mpte_mppcb != NULL);
	mp_so = mpte->mpte_mppcb->mpp_socket;
	mp_tp = mpte->mpte_mptcb;
	so = mpts->mpts_socket;

	/* Not grabbing socket lock as t_local_aid is write once only */
	tp = intotcpcb(sotoinpcb(so));
	/*
	 * This overwrites any previous mpte_lost_aid to avoid storing
	 * too much state when the typical case has only two subflows.
	 */
	mpte->mpte_flags |= MPTE_SND_REM_ADDR;
	mpte->mpte_lost_aid = tp->t_local_aid;

	linger = (!(mpts->mpts_flags & MPTSF_DELETEOK) &&
	    !(mp_so->so_flags & SOF_PCBCLEARING));

	mptcplog((LOG_DEBUG, "%s: cid %d [linger %s]\n", __func__,
	    mpts->mpts_connid, (linger ? "YES" : "NO")));

	if (mpts->mpts_soerror == 0)
		mpts->mpts_soerror = EADDRNOTAVAIL;

	/*
	 * The subflow connection has lost its source address.
	 *
	 * Right now, we simply propagate EADDRNOTAVAIL to the MPTCP socket
	 * client if the MPTCP connection has not been established.  If it
	 * has been established with one subflow , we keep the MPTCP
	 * connection valid without any subflows till closed by application.
	 * This lets tcp connection manager decide whether to close this or
	 * not as it reacts to reachability changes too.
	 */
	mptcp_subflow_disconnect(mpte, mpts, !linger);

	MPT_LOCK(mp_tp);
	if ((mp_tp->mpt_state < MPTCPS_ESTABLISHED) &&
	    (mp_so->so_flags & SOF_NOADDRAVAIL)) {
		mp_so->so_error = EADDRNOTAVAIL;
	}
	MPT_UNLOCK(mp_tp);

	/*
	 * Keep the subflow socket around, unless the MPTCP socket has
	 * been detached or the subflow has been disconnected explicitly,
	 * in which case it should be deleted right away.
	 */
	return (linger ? MPTS_EVRET_OK : MPTS_EVRET_DELETE);
}

/*
 * Handle SO_FILT_HINT_MPFAILOVER subflow socket event
 */
static ev_ret_t
mptcp_subflow_failover_ev(struct mptses *mpte, struct mptsub *mpts)
{
	struct mptsub *mpts_alt = NULL;
	struct socket *so = NULL;
	struct socket *mp_so;
	int altpath_exists = 0;

	MPTE_LOCK_ASSERT_HELD(mpte);    /* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);
	mp_so = mpte->mpte_mppcb->mpp_socket;
	mptcplog2((LOG_NOTICE, "%s: mp_so 0x%llx\n", __func__,
	    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so)));

	MPTS_UNLOCK(mpts);
	mpts_alt = mptcp_get_subflow(mpte, mpts);

	/*
	 * If there is no alternate eligible subflow, ignore the
	 * failover hint.
	 */
	if (mpts_alt == NULL) {
		mptcplog2((LOG_WARNING, "%s: no alternate path\n", __func__));
		MPTS_LOCK(mpts);
		goto done;
	}
	MPTS_LOCK(mpts_alt);
	altpath_exists = 1;
	so = mpts_alt->mpts_socket;
	if (mpts_alt->mpts_flags & MPTSF_FAILINGOVER) {
		socket_lock(so, 1);
		/* All data acknowledged */
		if (so->so_snd.sb_cc == 0) {
			so->so_flags &= ~SOF_MP_TRYFAILOVER;
			mpts_alt->mpts_flags &= ~MPTSF_FAILINGOVER;
		} else {
			/* no alternate path available */
			altpath_exists = 0;
		}
		socket_unlock(so, 1);
	}
	if (altpath_exists) {
		mpts_alt->mpts_flags |= MPTSF_ACTIVE;
		struct mptcb *mp_tp = mpte->mpte_mptcb;
		/* Bring the subflow's notion of snd_nxt into the send window */
		MPT_LOCK(mp_tp);
		mpts_alt->mpts_sndnxt = mp_tp->mpt_snduna;
		MPT_UNLOCK(mp_tp);
		mpte->mpte_active_sub = mpts_alt;
		socket_lock(so, 1);
		sowwakeup(so);
		socket_unlock(so, 1);
	}
	MPTS_UNLOCK(mpts_alt);

	if (altpath_exists) {
		soevent(mp_so,
		    SO_FILT_HINT_LOCKED | SO_FILT_HINT_CONNINFO_UPDATED);
		mptcplog((LOG_NOTICE, "%s: mp_so 0x%llx switched from "
		    "%d to %d\n", __func__,
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
		    mpts->mpts_connid, mpts_alt->mpts_connid));
		tcpstat.tcps_mp_switches++;
	}

	MPTS_LOCK(mpts);
	if (altpath_exists) {
		mpts->mpts_flags |= MPTSF_FAILINGOVER;
		mpts->mpts_flags &= ~MPTSF_ACTIVE;
	} else {
		so = mpts->mpts_socket;
		socket_lock(so, 1);
		so->so_flags &= ~SOF_MP_TRYFAILOVER;
		socket_unlock(so, 1);
	}
done:
	MPTS_LOCK_ASSERT_HELD(mpts);
	return (MPTS_EVRET_OK);
}

/*
 * Handle SO_FILT_HINT_IFDENIED subflow socket event.
 */
static ev_ret_t
mptcp_subflow_ifdenied_ev(struct mptses *mpte, struct mptsub *mpts)
{
	struct socket *mp_so, *so;
	struct mptcb *mp_tp;
	boolean_t linger;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);
	VERIFY(mpte->mpte_mppcb != NULL);
	mp_so = mpte->mpte_mppcb->mpp_socket;
	mp_tp = mpte->mpte_mptcb;
	so = mpts->mpts_socket;

	linger = (!(mpts->mpts_flags & MPTSF_DELETEOK) &&
	    !(mp_so->so_flags & SOF_PCBCLEARING));

	mptcplog((LOG_DEBUG, "%s: cid %d [linger %s]\n", __func__,
	    mpts->mpts_connid, (linger ? "YES" : "NO")));

	if (mpts->mpts_soerror == 0)
		mpts->mpts_soerror = EHOSTUNREACH;

	/*
	 * The subflow connection cannot use the outgoing interface.
	 *
	 * Right now, we simply propagate EHOSTUNREACH to the MPTCP socket
	 * client if the MPTCP connection has not been established.  If it
	 * has been established, let the upper layer call disconnectx.
	 */
	mptcp_subflow_disconnect(mpte, mpts, !linger);
	MPTS_UNLOCK(mpts);

	soevent(mp_so, SO_FILT_HINT_LOCKED | SO_FILT_HINT_IFDENIED);

	MPT_LOCK(mp_tp);
	if (mp_tp->mpt_state < MPTCPS_ESTABLISHED) {
		mp_so->so_error = EHOSTUNREACH;
	}
	MPT_UNLOCK(mp_tp);

	MPTS_LOCK(mpts);
	/*
	 * Keep the subflow socket around, unless the MPTCP socket has
	 * been detached or the subflow has been disconnected explicitly,
	 * in which case it should be deleted right away.
	 */
	return (linger ? MPTS_EVRET_OK : MPTS_EVRET_DELETE);
}

/*
 * Handle SO_FILT_HINT_SUSPEND subflow socket event.
 */
static ev_ret_t
mptcp_subflow_suspend_ev(struct mptses *mpte, struct mptsub *mpts)
{
	struct socket *so;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);

	so = mpts->mpts_socket;

	/* the subflow connection is being flow controlled */
	mpts->mpts_flags |= MPTSF_SUSPENDED;

	mptcplog((LOG_DEBUG, "%s: cid %d\n", __func__,
	    mpts->mpts_connid));

	return (MPTS_EVRET_OK);	/* keep the subflow socket around */
}

/*
 * Handle SO_FILT_HINT_RESUME subflow socket event.
 */
static ev_ret_t
mptcp_subflow_resume_ev(struct mptses *mpte, struct mptsub *mpts)
{
	struct socket *so;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);

	so = mpts->mpts_socket;

	/* the subflow connection is no longer flow controlled */
	mpts->mpts_flags &= ~MPTSF_SUSPENDED;

	mptcplog((LOG_DEBUG, "%s: cid %d\n", __func__, mpts->mpts_connid));

	return (MPTS_EVRET_OK);	/* keep the subflow socket around */
}

/*
 * Handle SO_FILT_HINT_CONNECTED subflow socket event.
 */
static ev_ret_t
mptcp_subflow_connected_ev(struct mptses *mpte, struct mptsub *mpts)
{
	char buf0[MAX_IPv6_STR_LEN], buf1[MAX_IPv6_STR_LEN];
	struct sockaddr_entry *src_se, *dst_se;
	struct sockaddr_storage src;
	struct socket *mp_so, *so;
	struct mptcb *mp_tp;
	struct ifnet *outifp;
	int af, error = 0;
	boolean_t mpok = FALSE;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	VERIFY(mpte->mpte_mppcb != NULL);
	mp_so = mpte->mpte_mppcb->mpp_socket;
	mp_tp = mpte->mpte_mptcb;

	MPTS_LOCK_ASSERT_HELD(mpts);
	so = mpts->mpts_socket;
	af = mpts->mpts_family;

	if (mpts->mpts_flags & MPTSF_CONNECTED)
		return (MPTS_EVRET_OK);

	if ((mpts->mpts_flags & MPTSF_DISCONNECTED) ||
	    (mpts->mpts_flags & MPTSF_DISCONNECTING)) {
		return (MPTS_EVRET_OK);
	}

	/*
	 * The subflow connection has been connected.  Find out whether it
	 * is connected as a regular TCP or as a MPTCP subflow.  The idea is:
	 *
	 *   a. If MPTCP connection is not yet established, then this must be
	 *	the first subflow connection.  If MPTCP failed to negotiate,
	 *	indicate to the MPTCP socket client via EPROTO, that the
	 *	underlying TCP connection may be peeled off via peeloff(2).
	 *	Otherwise, mark the MPTCP socket as connected.
	 *
	 *   b. If MPTCP connection has been established, then this must be
	 *	one of the subsequent subflow connections. If MPTCP failed
	 *	to negotiate, disconnect the connection since peeloff(2)
	 *	is no longer possible.
	 *
	 * Right now, we simply unblock any waiters at the MPTCP socket layer
	 * if the MPTCP connection has not been established.
	 */
	socket_lock(so, 0);

	if (so->so_state & SS_ISDISCONNECTED) {
		/*
		 * With MPTCP joins, a connection is connected at the subflow
		 * level, but the 4th ACK from the server elevates the MPTCP
		 * subflow to connected state. So there is a small window 
		 * where the subflow could get disconnected before the 
		 * connected event is processed.
		 */
		socket_unlock(so, 0);
		return (MPTS_EVRET_OK);
	}

	mpts->mpts_soerror = 0;
	mpts->mpts_flags &= ~MPTSF_CONNECTING;
	mpts->mpts_flags |= MPTSF_CONNECTED;
	if (sototcpcb(so)->t_mpflags & TMPF_MPTCP_TRUE)
		mpts->mpts_flags |= MPTSF_MP_CAPABLE;

	VERIFY(mpts->mpts_dst_sl != NULL);
	dst_se = TAILQ_FIRST(&mpts->mpts_dst_sl->sl_head);
	VERIFY(dst_se != NULL && dst_se->se_addr != NULL &&
	    dst_se->se_addr->sa_family == af);

	VERIFY(mpts->mpts_src_sl != NULL);
	src_se = TAILQ_FIRST(&mpts->mpts_src_sl->sl_head);
	VERIFY(src_se != NULL && src_se->se_addr != NULL &&
	    src_se->se_addr->sa_family == af);

	/* get/check source IP address */
	switch (af) {
	case AF_INET: {
		error = in_getsockaddr_s(so, &src);
		if (error == 0) {
			struct sockaddr_in *ms = SIN(src_se->se_addr);
			struct sockaddr_in *s = SIN(&src);

			VERIFY(s->sin_len == ms->sin_len);
			VERIFY(ms->sin_family == AF_INET);

			if ((mpts->mpts_flags & MPTSF_BOUND_IP) &&
			    bcmp(&ms->sin_addr, &s->sin_addr,
			    sizeof (ms->sin_addr)) != 0) {
				mptcplog((LOG_ERR, "%s: cid %d local "
				    "address %s (expected %s)\n", __func__,
				    mpts->mpts_connid, inet_ntop(AF_INET,
				    (void *)&s->sin_addr.s_addr, buf0,
				    sizeof (buf0)), inet_ntop(AF_INET,
				    (void *)&ms->sin_addr.s_addr, buf1,
				    sizeof (buf1))));
			}
			bcopy(s, ms, sizeof (*s));
		}
		break;
	}
#if INET6
	case AF_INET6: {
		error = in6_getsockaddr_s(so, &src);
		if (error == 0) {
			struct sockaddr_in6 *ms = SIN6(src_se->se_addr);
			struct sockaddr_in6 *s = SIN6(&src);

			VERIFY(s->sin6_len == ms->sin6_len);
			VERIFY(ms->sin6_family == AF_INET6);

			if ((mpts->mpts_flags & MPTSF_BOUND_IP) &&
			    bcmp(&ms->sin6_addr, &s->sin6_addr,
			    sizeof (ms->sin6_addr)) != 0) {
				mptcplog((LOG_ERR, "%s: cid %d local "
				    "address %s (expected %s)\n", __func__,
				    mpts->mpts_connid, inet_ntop(AF_INET6,
				    (void *)&s->sin6_addr, buf0,
				    sizeof (buf0)), inet_ntop(AF_INET6,
				    (void *)&ms->sin6_addr, buf1,
				    sizeof (buf1))));
			}
			bcopy(s, ms, sizeof (*s));
		}
		break;
	}
#endif /* INET6 */
	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	if (error != 0) {
		mptcplog((LOG_ERR, "%s: cid %d getsockaddr failed (%d)\n",
		    __func__, mpts->mpts_connid, error));
	}

	/* get/verify the outbound interface */
	outifp = sotoinpcb(so)->inp_last_outifp;	/* could be NULL */
	if (mpts->mpts_flags & MPTSF_BOUND_IF) {
		VERIFY(mpts->mpts_outif != NULL);
		if (mpts->mpts_outif != outifp) {
			mptcplog((LOG_ERR, "%s: cid %d outif %s "
			    "(expected %s)\n", __func__, mpts->mpts_connid,
			    ((outifp != NULL) ? outifp->if_xname : "NULL"),
			    mpts->mpts_outif->if_xname));
			if (outifp == NULL)
				outifp = mpts->mpts_outif;
		}
	} else {
		mpts->mpts_outif = outifp;
	}

	socket_unlock(so, 0);

	mptcplog((LOG_DEBUG, "%s: cid %d outif %s %s[%d] -> %s[%d] "
	    "is %s\n", __func__, mpts->mpts_connid, ((outifp != NULL) ?
	    outifp->if_xname : "NULL"), inet_ntop(af, (af == AF_INET) ?
	    (void *)&SIN(src_se->se_addr)->sin_addr.s_addr :
	    (void *)&SIN6(src_se->se_addr)->sin6_addr, buf0, sizeof (buf0)),
	    ((af == AF_INET) ? ntohs(SIN(src_se->se_addr)->sin_port) :
	    ntohs(SIN6(src_se->se_addr)->sin6_port)),
	    inet_ntop(af, ((af == AF_INET) ?
	    (void *)&SIN(dst_se->se_addr)->sin_addr.s_addr :
	    (void *)&SIN6(dst_se->se_addr)->sin6_addr), buf1, sizeof (buf1)),
	    ((af == AF_INET) ? ntohs(SIN(dst_se->se_addr)->sin_port) :
	    ntohs(SIN6(dst_se->se_addr)->sin6_port)),
	    ((mpts->mpts_flags & MPTSF_MP_CAPABLE) ?
	    "MPTCP capable" : "a regular TCP")));

	mpok = (mpts->mpts_flags & MPTSF_MP_CAPABLE);
	MPTS_UNLOCK(mpts);

	soevent(mp_so, SO_FILT_HINT_LOCKED | SO_FILT_HINT_CONNINFO_UPDATED);

	MPT_LOCK(mp_tp);
	if (mp_tp->mpt_state < MPTCPS_ESTABLISHED) {
		/* case (a) above */
		if (!mpok) {
			mp_tp->mpt_flags |= MPTCPF_PEEL_OFF;
			(void) mptcp_drop(mpte, mp_tp, EPROTO);
			MPT_UNLOCK(mp_tp);
		} else {
			if (mptcp_init_authparms(mp_tp) != 0) {
				mp_tp->mpt_flags |= MPTCPF_PEEL_OFF;
				(void) mptcp_drop(mpte, mp_tp, EPROTO);
				MPT_UNLOCK(mp_tp);
				mpok = FALSE;
			} else {
				mp_tp->mpt_state = MPTCPS_ESTABLISHED;
				mpte->mpte_associd = mpts->mpts_connid;
				DTRACE_MPTCP2(state__change, 
				    struct mptcb *, mp_tp, 
				    uint32_t, 0 /* event */);
				mptcp_init_statevars(mp_tp);
				MPT_UNLOCK(mp_tp);

				(void) mptcp_setconnorder(mpte,
				    mpts->mpts_connid, 1);
				soisconnected(mp_so);
			}
		}
		MPTS_LOCK(mpts);
		if (mpok) {
			/* Initialize the relative sequence number */
			mpts->mpts_rel_seq = 1;
			mpts->mpts_flags |= MPTSF_MPCAP_CTRSET;
			mpte->mpte_nummpcapflows++;
			MPT_LOCK_SPIN(mp_tp);
			mpts->mpts_sndnxt = mp_tp->mpt_snduna;
			MPT_UNLOCK(mp_tp);
		}
	} else if (mpok) {
		MPT_UNLOCK(mp_tp);
		/*
		 * case (b) above
		 * In case of additional flows, the MPTCP socket is not
		 * MPTSF_MP_CAPABLE until an ACK is received from server
		 * for 3-way handshake.  TCP would have guaranteed that this
		 * is an MPTCP subflow.
		 */
		MPTS_LOCK(mpts);
		mpts->mpts_flags |= MPTSF_MPCAP_CTRSET;
		mpte->mpte_nummpcapflows++;
		mpts->mpts_rel_seq = 1;
		MPT_LOCK_SPIN(mp_tp);
		mpts->mpts_sndnxt = mp_tp->mpt_snduna;
		MPT_UNLOCK(mp_tp);
	}
	MPTS_LOCK_ASSERT_HELD(mpts);

	return (MPTS_EVRET_OK);	/* keep the subflow socket around */
}

/*
 * Handle SO_FILT_HINT_DISCONNECTED subflow socket event.
 */
static ev_ret_t
mptcp_subflow_disconnected_ev(struct mptses *mpte, struct mptsub *mpts)
{
	struct socket *mp_so, *so;
	struct mptcb *mp_tp;
	boolean_t linger;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);
	VERIFY(mpte->mpte_mppcb != NULL);
	mp_so = mpte->mpte_mppcb->mpp_socket;
	mp_tp = mpte->mpte_mptcb;
	so = mpts->mpts_socket;

	linger = (!(mpts->mpts_flags & MPTSF_DELETEOK) &&
	    !(mp_so->so_flags & SOF_PCBCLEARING));

	mptcplog2((LOG_DEBUG, "%s: cid %d [linger %s]\n", __func__,
	    mpts->mpts_connid, (linger ? "YES" : "NO")));

	if (mpts->mpts_flags & MPTSF_DISCONNECTED)
		return (linger ? MPTS_EVRET_OK : MPTS_EVRET_DELETE);

	/*
	 * Clear flags that are used by getconninfo to return state.
	 * Retain like MPTSF_DELETEOK, MPTSF_ACTIVE for internal purposes.
	 */
	mpts->mpts_flags &= ~(MPTSF_CONNECTING|MPTSF_CONNECT_PENDING|
	    MPTSF_CONNECTED|MPTSF_DISCONNECTING|MPTSF_PREFERRED|
	    MPTSF_MP_CAPABLE|MPTSF_MP_READY|MPTSF_MP_DEGRADED|
	    MPTSF_SUSPENDED|MPTSF_ACTIVE);
	mpts->mpts_flags |= MPTSF_DISCONNECTED;

	/*
	 * The subflow connection has been disconnected.
	 *
	 * Right now, we simply unblock any waiters at the MPTCP socket layer
	 * if the MPTCP connection has not been established.
	 */
	MPTS_UNLOCK(mpts);

	soevent(mp_so, SO_FILT_HINT_LOCKED | SO_FILT_HINT_CONNINFO_UPDATED);

	if (mpts->mpts_flags & MPTSF_MPCAP_CTRSET) {
		mpte->mpte_nummpcapflows--;
		mpts->mpts_flags &= ~MPTSF_MPCAP_CTRSET;
	}

	MPT_LOCK(mp_tp);
	if (mp_tp->mpt_state < MPTCPS_ESTABLISHED) {
		MPT_UNLOCK(mp_tp);
		soisdisconnected(mp_so);
	} else {
		MPT_UNLOCK(mp_tp);
	}

	MPTS_LOCK(mpts);
	/*
	 * The underlying subflow socket has been disconnected;
	 * it is no longer useful to us.  Keep the subflow socket
	 * around, unless the MPTCP socket has been detached or
	 * the subflow has been disconnected explicitly, in which
	 * case it should be deleted right away.
	 */
	return (linger ? MPTS_EVRET_OK : MPTS_EVRET_DELETE);
}

/*
 * Handle SO_FILT_HINT_MPSTATUS subflow socket event
 */
static ev_ret_t
mptcp_subflow_mpstatus_ev(struct mptses *mpte, struct mptsub *mpts)
{
	struct socket *mp_so, *so;
	struct mptcb *mp_tp;
	ev_ret_t ret = MPTS_EVRET_OK_UPDATE;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	VERIFY(mpte->mpte_mppcb != NULL);
	mp_so = mpte->mpte_mppcb->mpp_socket;
	mp_tp = mpte->mpte_mptcb;

	MPTS_LOCK_ASSERT_HELD(mpts);
	so = mpts->mpts_socket;

	socket_lock(so, 0);
	MPT_LOCK(mp_tp);

	if (sototcpcb(so)->t_mpflags & TMPF_MPTCP_TRUE)
		mpts->mpts_flags |= MPTSF_MP_CAPABLE;
	else
		mpts->mpts_flags &= ~MPTSF_MP_CAPABLE;

	if (sototcpcb(so)->t_mpflags & TMPF_TCP_FALLBACK) {
		if (mpts->mpts_flags & MPTSF_MP_DEGRADED)
			goto done;
		mpts->mpts_flags |= MPTSF_MP_DEGRADED;
	}
	else
		mpts->mpts_flags &= ~MPTSF_MP_DEGRADED;

	if (sototcpcb(so)->t_mpflags & TMPF_MPTCP_READY)
		mpts->mpts_flags |= MPTSF_MP_READY;
	else
		mpts->mpts_flags &= ~MPTSF_MP_READY;

	if (mpts->mpts_flags & MPTSF_MP_DEGRADED) {
		mp_tp->mpt_flags |= MPTCPF_FALLBACK_TO_TCP;
		mp_tp->mpt_flags &= ~MPTCPF_JOIN_READY;
	}

	if (mp_tp->mpt_flags & MPTCPF_FALLBACK_TO_TCP) {
		VERIFY(!(mp_tp->mpt_flags & MPTCPF_JOIN_READY));
		ret = MPTS_EVRET_DISCONNECT_FALLBACK;
	} else if (mpts->mpts_flags & MPTSF_MP_READY) {
		mp_tp->mpt_flags |= MPTCPF_JOIN_READY;
		ret = MPTS_EVRET_CONNECT_PENDING;
	}

	mptcplog2((LOG_DEBUG, "%s: mp_so 0x%llx mpt_flags=%b cid %d "
	    "mptsf=%b\n", __func__,
	    (u_int64_t)VM_KERNEL_ADDRPERM(mpte->mpte_mppcb->mpp_socket),
	    mp_tp->mpt_flags, MPTCPF_BITS, mpts->mpts_connid,
	    mpts->mpts_flags, MPTSF_BITS));
done:
	MPT_UNLOCK(mp_tp);
	socket_unlock(so, 0);

	return (ret);
}

/*
 * Handle SO_FILT_HINT_MUSTRST subflow socket event
 */
static ev_ret_t
mptcp_subflow_mustrst_ev(struct mptses *mpte, struct mptsub *mpts)
{
	struct socket *mp_so, *so;
	struct mptcb *mp_tp;
	boolean_t linger;


	MPTE_LOCK_ASSERT_HELD(mpte);    /* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);
	VERIFY(mpte->mpte_mppcb != NULL);
	mp_so = mpte->mpte_mppcb->mpp_socket;
	mp_tp = mpte->mpte_mptcb;
	so = mpts->mpts_socket;

	linger = (!(mpts->mpts_flags & MPTSF_DELETEOK) &&
	    !(mp_so->so_flags & SOF_PCBCLEARING));

	if (mpts->mpts_soerror == 0)
		mpts->mpts_soerror = ECONNABORTED;

	so->so_error = ECONNABORTED;

	/* We got an invalid option or a fast close */
	socket_lock(so, 0);
	struct tcptemp *t_template;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp = NULL;

	tp = intotcpcb(inp);

	t_template = tcp_maketemplate(tp);
	if (t_template) {
		unsigned int ifscope, nocell = 0;

		if (inp->inp_flags & INP_BOUND_IF)
			ifscope = inp->inp_boundifp->if_index;
		else
			ifscope = IFSCOPE_NONE;

		if (inp->inp_flags & INP_NO_IFT_CELLULAR)
			nocell = 1;

		tcp_respond(tp, t_template->tt_ipgen,
		    &t_template->tt_t, (struct mbuf *)NULL,
		    tp->rcv_nxt, tp->snd_una, TH_RST, ifscope, nocell);
		(void) m_free(dtom(t_template));
		mptcplog((LOG_DEBUG, "%s: mp_so 0x%llx cid %d \n",
		    __func__, (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
		    so, mpts->mpts_connid));
	}
	socket_unlock(so, 0);
	mptcp_subflow_disconnect(mpte, mpts, !linger);
	MPTS_UNLOCK(mpts);

	soevent(mp_so, SO_FILT_HINT_LOCKED | SO_FILT_HINT_CONNINFO_UPDATED);

	MPT_LOCK(mp_tp);
	if (mp_tp->mpt_state < MPTCPS_ESTABLISHED) {
		mp_so->so_error = ECONNABORTED;
	}
	MPT_UNLOCK(mp_tp);

	MPTS_LOCK(mpts);
	/*
	 * Keep the subflow socket around unless the subflow has been
	 * disconnected explicitly.
	 */
	return (linger ? MPTS_EVRET_OK : MPTS_EVRET_DELETE);
}

static const char *
mptcp_evret2str(ev_ret_t ret)
{
	const char *c = "UNKNOWN";

	switch (ret) {
	case MPTS_EVRET_DELETE:
		c = "MPTS_EVRET_DELETE";
		break;
	case MPTS_EVRET_CONNECT_PENDING:
		c = "MPTS_EVRET_CONNECT_PENDING";
		break;
	case MPTS_EVRET_DISCONNECT_FALLBACK:
		c = "MPTS_EVRET_DISCONNECT_FALLBACK";
		break;
	case MPTS_EVRET_OK:
		c = "MPTS_EVRET_OK";
		break;
	case MPTS_EVRET_OK_UPDATE:
		c = "MPTS_EVRET_OK_UPDATE";
		break;
	}
	return (c);
}

/*
 * Add a reference to a subflow structure; used by MPTS_ADDREF().
 */
void
mptcp_subflow_addref(struct mptsub *mpts, int locked)
{
	if (!locked)
		MPTS_LOCK(mpts);
	else
		MPTS_LOCK_ASSERT_HELD(mpts);

	if (++mpts->mpts_refcnt == 0) {
		panic("%s: mpts %p wraparound refcnt\n", __func__, mpts);
		/* NOTREACHED */
	}
	if (!locked)
		MPTS_UNLOCK(mpts);
}

/*
 * Remove a reference held on a subflow structure; used by MPTS_REMREF();
 */
void
mptcp_subflow_remref(struct mptsub *mpts)
{
	MPTS_LOCK(mpts);
	if (mpts->mpts_refcnt == 0) {
		panic("%s: mpts %p negative refcnt\n", __func__, mpts);
		/* NOTREACHED */
	}
	if (--mpts->mpts_refcnt > 0) {
		MPTS_UNLOCK(mpts);
		return;
	}
	/* callee will unlock and destroy lock */
	mptcp_subflow_free(mpts);
}

/*
 * Issues SOPT_SET on an MPTCP subflow socket; socket must already be locked,
 * caller must ensure that the option can be issued on subflow sockets, via
 * MPOF_SUBFLOW_OK flag.
 */
int
mptcp_subflow_sosetopt(struct mptses *mpte, struct socket *so,
    struct mptopt *mpo)
{
	struct socket *mp_so;
	struct sockopt sopt;
	char buf[32];
	int error;

	VERIFY(mpo->mpo_flags & MPOF_SUBFLOW_OK);
	mpo->mpo_flags &= ~MPOF_INTERIM;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	mp_so = mpte->mpte_mppcb->mpp_socket;

	bzero(&sopt, sizeof (sopt));
	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_level = mpo->mpo_level;
	sopt.sopt_name = mpo->mpo_name;
	sopt.sopt_val = CAST_USER_ADDR_T(&mpo->mpo_intval);
	sopt.sopt_valsize = sizeof (int);
	sopt.sopt_p = kernproc;

	error = sosetoptlock(so, &sopt, 0);	/* already locked */
	if (error == 0) {
		mptcplog2((LOG_DEBUG, "%s: mp_so 0x%llx sopt %s "
		    "val %d set successful\n", __func__,
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
		    mptcp_sopt2str(mpo->mpo_level, mpo->mpo_name,
		    buf, sizeof (buf)), mpo->mpo_intval));
	} else {
		mptcplog((LOG_ERR, "%s: mp_so 0x%llx sopt %s "
		    "val %d set error %d\n", __func__,
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
		    mptcp_sopt2str(mpo->mpo_level, mpo->mpo_name,
		    buf, sizeof (buf)), mpo->mpo_intval, error));
	}
	return (error);
}

/*
 * Issues SOPT_GET on an MPTCP subflow socket; socket must already be locked,
 * caller must ensure that the option can be issued on subflow sockets, via
 * MPOF_SUBFLOW_OK flag.
 */
int
mptcp_subflow_sogetopt(struct mptses *mpte, struct socket *so,
    struct mptopt *mpo)
{
	struct socket *mp_so;
	struct sockopt sopt;
	char buf[32];
	int error;

	VERIFY(mpo->mpo_flags & MPOF_SUBFLOW_OK);
	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	mp_so = mpte->mpte_mppcb->mpp_socket;

	bzero(&sopt, sizeof (sopt));
	sopt.sopt_dir = SOPT_GET;
	sopt.sopt_level = mpo->mpo_level;
	sopt.sopt_name = mpo->mpo_name;
	sopt.sopt_val = CAST_USER_ADDR_T(&mpo->mpo_intval);
	sopt.sopt_valsize = sizeof (int);
	sopt.sopt_p = kernproc;

	error = sogetoptlock(so, &sopt, 0);	/* already locked */
	if (error == 0) {
		mptcplog2((LOG_DEBUG, "%s: mp_so 0x%llx sopt %s "
		    "val %d get successful\n", __func__,
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
		    mptcp_sopt2str(mpo->mpo_level, mpo->mpo_name,
		    buf, sizeof (buf)), mpo->mpo_intval));
	} else {
		mptcplog((LOG_ERR, "%s: mp_so 0x%llx sopt %s get error %d\n",
		    __func__, (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
		    mptcp_sopt2str(mpo->mpo_level,
		    mpo->mpo_name, buf, sizeof (buf)), error));
	}
	return (error);
}


/*
 * MPTCP garbage collector.
 *
 * This routine is called by the MP domain on-demand, periodic callout,
 * which is triggered when a MPTCP socket is closed.  The callout will
 * repeat as long as this routine returns a non-zero value.
 */
static uint32_t
mptcp_gc(struct mppcbinfo *mppi)
{
	struct mppcb *mpp, *tmpp;
	uint32_t active = 0;

	lck_mtx_assert(&mppi->mppi_lock, LCK_MTX_ASSERT_OWNED);

	mptcplog3((LOG_DEBUG, "%s: running\n", __func__));

	TAILQ_FOREACH_SAFE(mpp, &mppi->mppi_pcbs, mpp_entry, tmpp) {
		struct socket *mp_so;
		struct mptses *mpte;
		struct mptcb *mp_tp;

		VERIFY(mpp->mpp_flags & MPP_ATTACHED);
		mp_so = mpp->mpp_socket;
		VERIFY(mp_so != NULL);
		mpte = mptompte(mpp);
		VERIFY(mpte != NULL);
		mp_tp = mpte->mpte_mptcb;
		VERIFY(mp_tp != NULL);

		mptcplog3((LOG_DEBUG, "%s: mp_so 0x%llx found "
		    "(u=%d,r=%d,s=%d)\n", __func__,
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so), mp_so->so_usecount,
		    mp_so->so_retaincnt, mpp->mpp_state));

		if (!lck_mtx_try_lock(&mpp->mpp_lock)) {
			mptcplog3((LOG_DEBUG, "%s: mp_so 0x%llx skipped "
			    "(u=%d,r=%d)\n", __func__,
			    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
			    mp_so->so_usecount, mp_so->so_retaincnt));
			active++;
			continue;
		}

		/* check again under the lock */
		if (mp_so->so_usecount > 1) {
			boolean_t wakeup = FALSE;
			struct mptsub *mpts, *tmpts;

			mptcplog3((LOG_DEBUG, "%s: mp_so 0x%llx skipped "
			    "[u=%d,r=%d] %d %d\n", __func__,
			    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
			    mp_so->so_usecount, mp_so->so_retaincnt,
			    mp_tp->mpt_gc_ticks,
			    mp_tp->mpt_state));
			MPT_LOCK(mp_tp);
			if (mp_tp->mpt_state >= MPTCPS_FIN_WAIT_1) {
				if (mp_tp->mpt_gc_ticks > 0)
					mp_tp->mpt_gc_ticks--;
				if (mp_tp->mpt_gc_ticks == 0) {
					wakeup = TRUE;
					if (mp_tp->mpt_localkey != NULL) {
						mptcp_free_key(
						    mp_tp->mpt_localkey);
						mp_tp->mpt_localkey = NULL;
					}
				}
			}
			MPT_UNLOCK(mp_tp);
			if (wakeup) {
				TAILQ_FOREACH_SAFE(mpts,
				    &mpte->mpte_subflows, mpts_entry, tmpts) {
					MPTS_LOCK(mpts);
					mpts->mpts_flags |= MPTSF_DELETEOK;
					if (mpts->mpts_soerror == 0)
						mpts->mpts_soerror = ETIMEDOUT;
					mptcp_subflow_eupcall(mpts->mpts_socket,
					    mpts, SO_FILT_HINT_DISCONNECTED);
					MPTS_UNLOCK(mpts);
				}
			}
			lck_mtx_unlock(&mpp->mpp_lock);
			active++;
			continue;
		}

		if (mpp->mpp_state != MPPCB_STATE_DEAD) {
			mptcplog3((LOG_DEBUG, "%s: mp_so 0x%llx skipped "
			    "[u=%d,r=%d,s=%d]\n", __func__,
			    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
			    mp_so->so_usecount, mp_so->so_retaincnt,
			    mpp->mpp_state));
			lck_mtx_unlock(&mpp->mpp_lock);
			active++;
			continue;
		}

		/*
		 * The PCB has been detached, and there is exactly 1 refnct
		 * held by the MPTCP thread.  Signal that thread to terminate,
		 * after which the last refcnt will be released.  That will
		 * allow it to be destroyed below during the next round.
		 */
		if (mp_so->so_usecount == 1) {
			mptcplog2((LOG_DEBUG, "%s: mp_so 0x%llx scheduled for "
			    "termination [u=%d,r=%d]\n", __func__,
			    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
			    mp_so->so_usecount, mp_so->so_retaincnt));
			/* signal MPTCP thread to terminate */
			mptcp_thread_terminate_signal(mpte);
			lck_mtx_unlock(&mpp->mpp_lock);
			active++;
			continue;
		}

		mptcplog((LOG_DEBUG, "%s: mp_so 0x%llx destroyed [u=%d,r=%d]\n",
		    __func__, (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
		    mp_so->so_usecount, mp_so->so_retaincnt));
		DTRACE_MPTCP4(dispose, struct socket *, mp_so, 
		    struct sockbuf *, &mp_so->so_rcv,
		    struct sockbuf *, &mp_so->so_snd,
		    struct mppcb *, mpp);

		mp_pcbdispose(mpp);
	}

	return (active);
}

/*
 * Drop a MPTCP connection, reporting the specified error.
 */
struct mptses *
mptcp_drop(struct mptses *mpte, struct mptcb *mp_tp, int errno)
{
	struct socket *mp_so;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	MPT_LOCK_ASSERT_HELD(mp_tp);
	VERIFY(mpte->mpte_mptcb == mp_tp);
	mp_so = mpte->mpte_mppcb->mpp_socket;

	mp_tp->mpt_state = MPTCPS_CLOSED;
	DTRACE_MPTCP2(state__change, struct mptcb *, mp_tp, 
	    uint32_t, 0 /* event */);

	if (errno == ETIMEDOUT && mp_tp->mpt_softerror != 0)
		errno = mp_tp->mpt_softerror;
	mp_so->so_error = errno;

	return (mptcp_close(mpte, mp_tp));
}

/*
 * Close a MPTCP control block.
 */
struct mptses *
mptcp_close(struct mptses *mpte, struct mptcb *mp_tp)
{
	struct socket *mp_so;
	struct mptsub *mpts, *tmpts;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	MPT_LOCK_ASSERT_HELD(mp_tp);
	VERIFY(mpte->mpte_mptcb == mp_tp);
	mp_so = mpte->mpte_mppcb->mpp_socket;
	if (mp_tp->mpt_localkey != NULL) {
		mptcp_free_key(mp_tp->mpt_localkey);
		mp_tp->mpt_localkey = NULL;
	}

	MPT_UNLOCK(mp_tp);
	soisdisconnected(mp_so);

	MPT_LOCK(mp_tp);
	if (mp_tp->mpt_flags & MPTCPF_PEEL_OFF) {
		return (NULL);
	}
	MPT_UNLOCK(mp_tp);

	/* Clean up all subflows */
	TAILQ_FOREACH_SAFE(mpts, &mpte->mpte_subflows, mpts_entry, tmpts) {
		MPTS_LOCK(mpts);
		mptcp_subflow_disconnect(mpte, mpts, TRUE);
		MPTS_UNLOCK(mpts);
		mptcp_subflow_del(mpte, mpts, TRUE);
	}
	MPT_LOCK(mp_tp);

	return (NULL);
}

void
mptcp_notify_close(struct socket *so)
{
	soevent(so, (SO_FILT_HINT_LOCKED | SO_FILT_HINT_DISCONNECTED));
}

/*
 * Signal MPTCP thread to wake up.
 */
void
mptcp_thread_signal(struct mptses *mpte)
{
	lck_mtx_lock(&mpte->mpte_thread_lock);
	mptcp_thread_signal_locked(mpte);
	lck_mtx_unlock(&mpte->mpte_thread_lock);
}

/*
 * Signal MPTCP thread to wake up (locked version)
 */
static void
mptcp_thread_signal_locked(struct mptses *mpte)
{
	lck_mtx_assert(&mpte->mpte_thread_lock, LCK_MTX_ASSERT_OWNED);

	mpte->mpte_thread_reqs++;
	if (!mpte->mpte_thread_active && mpte->mpte_thread != THREAD_NULL)
		wakeup_one((caddr_t)&mpte->mpte_thread);
}

/*
 * Signal MPTCP thread to terminate.
 */
static void
mptcp_thread_terminate_signal(struct mptses *mpte)
{
	lck_mtx_lock(&mpte->mpte_thread_lock);
	if (mpte->mpte_thread != THREAD_NULL) {
		mpte->mpte_thread = THREAD_NULL;
		mpte->mpte_thread_reqs++;
		if (!mpte->mpte_thread_active)
			wakeup_one((caddr_t)&mpte->mpte_thread);
	}
	lck_mtx_unlock(&mpte->mpte_thread_lock);
}

/*
 * MPTCP thread workloop.
 */
static void
mptcp_thread_dowork(struct mptses *mpte)
{
	struct socket *mp_so;
	struct mptsub *mpts, *tmpts;
	boolean_t connect_pending = FALSE, disconnect_fallback = FALSE;
	boolean_t conninfo_update = FALSE;

	MPTE_LOCK(mpte);		/* same as MP socket lock */
	VERIFY(mpte->mpte_mppcb != NULL);
	mp_so = mpte->mpte_mppcb->mpp_socket;
	VERIFY(mp_so != NULL);

	TAILQ_FOREACH_SAFE(mpts, &mpte->mpte_subflows, mpts_entry, tmpts) {
		ev_ret_t ret;

		MPTS_LOCK(mpts);
		MPTS_ADDREF_LOCKED(mpts);	/* for us */
		
		/* Update process ownership based on parent mptcp socket */
		mptcp_update_last_owner(mpts, mp_so);
		
		mptcp_subflow_input(mpte, mpts);
		ret = mptcp_subflow_events(mpte, mpts);

		if (mpts->mpts_flags & MPTSF_ACTIVE) {
			mptcplog3((LOG_INFO, "%s: cid %d \n", __func__,
			    mpts->mpts_connid));
			(void) mptcp_subflow_output(mpte, mpts);
		}

		/*
		 * If MPTCP socket is closed, disconnect all subflows.
		 * This will generate a disconnect event which will
		 * be handled during the next iteration, causing a
		 * non-zero error to be returned above.
		 */
		if (mp_so->so_flags & SOF_PCBCLEARING)
			mptcp_subflow_disconnect(mpte, mpts, FALSE);
		MPTS_UNLOCK(mpts);

		switch (ret) {
		case MPTS_EVRET_OK_UPDATE:
			conninfo_update = TRUE;
			break;
		case MPTS_EVRET_OK:
			/* nothing to do */
			break;
		case MPTS_EVRET_DELETE:
			if (mptcp_delete_ok(mpte, mpts)) {
				mptcp_subflow_del(mpte, mpts, TRUE);
			}
			break;
		case MPTS_EVRET_CONNECT_PENDING:
			connect_pending = TRUE;
			break;
		case MPTS_EVRET_DISCONNECT_FALLBACK:
			disconnect_fallback = TRUE;
			break;
		}
		MPTS_REMREF(mpts);		/* ours */
	}

	if (conninfo_update) {
		soevent(mp_so, SO_FILT_HINT_LOCKED |
		    SO_FILT_HINT_CONNINFO_UPDATED);
	}

	if (!connect_pending && !disconnect_fallback) {
		MPTE_UNLOCK(mpte);
		return;
	}

	TAILQ_FOREACH_SAFE(mpts, &mpte->mpte_subflows, mpts_entry, tmpts) {
		MPTS_LOCK(mpts);
		if (disconnect_fallback) {
			struct socket *so = NULL;
			struct inpcb *inp = NULL;
			struct tcpcb *tp = NULL;

			if (mpts->mpts_flags & MPTSF_MP_DEGRADED) {
				MPTS_UNLOCK(mpts);
				continue;
			}

			mpts->mpts_flags |= MPTSF_MP_DEGRADED;

			if (mpts->mpts_flags & (MPTSF_DISCONNECTING|
			    MPTSF_DISCONNECTED)) {
				MPTS_UNLOCK(mpts);
				continue;
			}
			so = mpts->mpts_socket;

			/*
			 * The MPTCP connection has degraded to a fallback
			 * mode, so there is no point in keeping this subflow
			 * regardless of its MPTCP-readiness state, unless it
			 * is the primary one which we use for fallback.  This
			 * assumes that the subflow used for fallback is the
			 * ACTIVE one.
			 */

			socket_lock(so, 1);
			inp = sotoinpcb(so);
			tp = intotcpcb(inp);
			tp->t_mpflags &=
			    ~(TMPF_MPTCP_READY|TMPF_MPTCP_TRUE);
			tp->t_mpflags |= TMPF_TCP_FALLBACK;
			if (mpts->mpts_flags & MPTSF_ACTIVE) {
				socket_unlock(so, 1);
				MPTS_UNLOCK(mpts);
				continue;
			}
			tp->t_mpflags |= TMPF_RESET;
			soevent(so, SO_FILT_HINT_LOCKED | SO_FILT_HINT_MUSTRST);
			socket_unlock(so, 1);

		} else if (connect_pending) {
			/*
			 * The MPTCP connection has progressed to a state
			 * where it supports full multipath semantics; allow
			 * additional joins to be attempted for all subflows
			 * that are in the PENDING state.
			 */
			if (mpts->mpts_flags & MPTSF_CONNECT_PENDING) {
				(void) mptcp_subflow_soconnectx(mpte, mpts);
			}
		}
		MPTS_UNLOCK(mpts);
	}

	MPTE_UNLOCK(mpte);
}

/*
 * MPTCP thread.
 */
static void
mptcp_thread_func(void *v, wait_result_t w)
{
#pragma unused(w)
	struct mptses *mpte = v;
	struct timespec *ts = NULL;

	VERIFY(mpte != NULL);

	lck_mtx_lock_spin(&mpte->mpte_thread_lock);

	for (;;) {
		lck_mtx_assert(&mpte->mpte_thread_lock, LCK_MTX_ASSERT_OWNED);

		if (mpte->mpte_thread != THREAD_NULL) {
			(void) msleep(&mpte->mpte_thread,
			    &mpte->mpte_thread_lock, (PZERO - 1) | PSPIN,
			    __func__, ts);
		}

		/* MPTCP socket is closed? */
		if (mpte->mpte_thread == THREAD_NULL) {
			lck_mtx_unlock(&mpte->mpte_thread_lock);
			/* callee will destroy thread lock */
			mptcp_thread_destroy(mpte);
			/* NOTREACHED */
			return;
		}

		mpte->mpte_thread_active = 1;
		for (;;) {
			uint32_t reqs = mpte->mpte_thread_reqs;

			lck_mtx_unlock(&mpte->mpte_thread_lock);
			mptcp_thread_dowork(mpte);
			lck_mtx_lock_spin(&mpte->mpte_thread_lock);

			/* if there's no pending request, we're done */
			if (reqs == mpte->mpte_thread_reqs ||
			    mpte->mpte_thread == THREAD_NULL)
				break;
		}
		mpte->mpte_thread_reqs = 0;
		mpte->mpte_thread_active = 0;
	}
}

/*
 * Destroy a MTCP thread, to be called in the MPTCP thread context
 * upon receiving an indication to self-terminate.  This routine
 * will not return, as the current thread is terminated at the end.
 */
static void
mptcp_thread_destroy(struct mptses *mpte)
{
	struct socket *mp_so;

	MPTE_LOCK(mpte);		/* same as MP socket lock */
	VERIFY(mpte->mpte_thread == THREAD_NULL);
	VERIFY(mpte->mpte_mppcb != NULL);

	mptcp_sesdestroy(mpte);

	mp_so = mpte->mpte_mppcb->mpp_socket;
	VERIFY(mp_so != NULL);
	VERIFY(mp_so->so_usecount != 0);
	mp_so->so_usecount--;		/* for thread */
	mpte->mpte_mppcb->mpp_flags |= MPP_DEFUNCT;
	MPTE_UNLOCK(mpte);

	/* for the extra refcnt from kernel_thread_start() */
	thread_deallocate(current_thread());
	/* this is the end */
	thread_terminate(current_thread());
	/* NOTREACHED */
}

/*
 * Protocol pr_lock callback.
 */
int
mptcp_lock(struct socket *mp_so, int refcount, void *lr)
{
	struct mppcb *mpp = sotomppcb(mp_so);
	void *lr_saved;

	if (lr == NULL)
		lr_saved = __builtin_return_address(0);
	else
		lr_saved = lr;

	if (mpp == NULL) {
		panic("%s: so=%p NO PCB! lr=%p lrh= %s\n", __func__,
		    mp_so, lr_saved, solockhistory_nr(mp_so));
		/* NOTREACHED */
	}
	lck_mtx_lock(&mpp->mpp_lock);

	if (mp_so->so_usecount < 0) {
		panic("%s: so=%p so_pcb=%p lr=%p ref=%x lrh= %s\n", __func__,
		    mp_so, mp_so->so_pcb, lr_saved, mp_so->so_usecount,
		    solockhistory_nr(mp_so));
		/* NOTREACHED */
	}
	if (refcount != 0)
		mp_so->so_usecount++;
	mp_so->lock_lr[mp_so->next_lock_lr] = lr_saved;
	mp_so->next_lock_lr = (mp_so->next_lock_lr + 1) % SO_LCKDBG_MAX;

	return (0);
}

/*
 * Protocol pr_unlock callback.
 */
int
mptcp_unlock(struct socket *mp_so, int refcount, void *lr)
{
	struct mppcb *mpp = sotomppcb(mp_so);
	void *lr_saved;

	if (lr == NULL)
		lr_saved = __builtin_return_address(0);
	else
		lr_saved = lr;

	if (mpp == NULL) {
		panic("%s: so=%p NO PCB usecount=%x lr=%p lrh= %s\n", __func__,
		    mp_so, mp_so->so_usecount, lr_saved,
		    solockhistory_nr(mp_so));
		/* NOTREACHED */
	}
	lck_mtx_assert(&mpp->mpp_lock, LCK_MTX_ASSERT_OWNED);

	if (refcount != 0)
		mp_so->so_usecount--;

	if (mp_so->so_usecount < 0) {
		panic("%s: so=%p usecount=%x lrh= %s\n", __func__,
		    mp_so, mp_so->so_usecount, solockhistory_nr(mp_so));
		/* NOTREACHED */
	}
	mp_so->unlock_lr[mp_so->next_unlock_lr] = lr_saved;
	mp_so->next_unlock_lr = (mp_so->next_unlock_lr + 1) % SO_LCKDBG_MAX;
	lck_mtx_unlock(&mpp->mpp_lock);

	return (0);
}

/*
 * Protocol pr_getlock callback.
 */
lck_mtx_t *
mptcp_getlock(struct socket *mp_so, int locktype)
{
#pragma unused(locktype)
	struct mppcb *mpp = sotomppcb(mp_so);

	if (mpp == NULL) {
		panic("%s: so=%p NULL so_pcb %s\n", __func__, mp_so,
		    solockhistory_nr(mp_so));
		/* NOTREACHED */
	}
	if (mp_so->so_usecount < 0) {
		panic("%s: so=%p usecount=%x lrh= %s\n", __func__,
		    mp_so, mp_so->so_usecount, solockhistory_nr(mp_so));
		/* NOTREACHED */
	}
	return (&mpp->mpp_lock);
}

/*
 * Key generation functions
 */
static void
mptcp_generate_unique_key(struct mptcp_key_entry *key_entry)
{
	struct mptcp_key_entry *key_elm;
try_again:
	read_random(&key_entry->mkey_value, sizeof (key_entry->mkey_value));
	if (key_entry->mkey_value == 0)
		goto try_again;
	mptcp_do_sha1(&key_entry->mkey_value, key_entry->mkey_digest,
	    sizeof (key_entry->mkey_digest));

	LIST_FOREACH(key_elm, &mptcp_keys_pool, mkey_next) {
		if (key_elm->mkey_value == key_entry->mkey_value) {
			goto try_again;
		}
		if (bcmp(key_elm->mkey_digest, key_entry->mkey_digest, 4) ==
		    0) {
			goto try_again;
		}
	}
}

static mptcp_key_t *
mptcp_reserve_key(void)
{
	struct mptcp_key_entry *key_elm;
	struct mptcp_key_entry *found_elm = NULL;

	lck_mtx_lock(&mptcp_keys_pool.mkph_lock);
	LIST_FOREACH(key_elm, &mptcp_keys_pool, mkey_next) {
		if (key_elm->mkey_flags == MKEYF_FREE) {
			key_elm->mkey_flags = MKEYF_INUSE;
			found_elm = key_elm;
			break;
		}
	}
	lck_mtx_unlock(&mptcp_keys_pool.mkph_lock);

	if (found_elm) {
		return (&found_elm->mkey_value);
	}

	key_elm = (struct mptcp_key_entry *)
	    zalloc(mptcp_keys_pool.mkph_key_entry_zone);
	key_elm->mkey_flags = MKEYF_INUSE;

	lck_mtx_lock(&mptcp_keys_pool.mkph_lock);
	mptcp_generate_unique_key(key_elm);
	LIST_INSERT_HEAD(&mptcp_keys_pool, key_elm, mkey_next);
	mptcp_keys_pool.mkph_count += 1;
	lck_mtx_unlock(&mptcp_keys_pool.mkph_lock);
	return (&key_elm->mkey_value);
}

static caddr_t
mptcp_get_stored_digest(mptcp_key_t *key)
{
	struct mptcp_key_entry *key_holder;
	caddr_t digest = NULL;

	lck_mtx_lock(&mptcp_keys_pool.mkph_lock);
	key_holder = (struct mptcp_key_entry *)(void *)((caddr_t)key -
	    offsetof(struct mptcp_key_entry, mkey_value));
	if (key_holder->mkey_flags != MKEYF_INUSE)
		panic_plain("%s", __func__);
	digest = &key_holder->mkey_digest[0];
	lck_mtx_unlock(&mptcp_keys_pool.mkph_lock);
	return (digest);
}

void
mptcp_free_key(mptcp_key_t *key)
{
	struct mptcp_key_entry *key_holder;
	struct mptcp_key_entry *key_elm;
	int pt = RandomULong();

	mptcplog((LOG_INFO, "%s\n", __func__));

	lck_mtx_lock(&mptcp_keys_pool.mkph_lock);
	key_holder = (struct mptcp_key_entry *)(void*)((caddr_t)key -
	    offsetof(struct mptcp_key_entry, mkey_value));
	key_holder->mkey_flags = MKEYF_FREE;

	LIST_REMOVE(key_holder, mkey_next);
	mptcp_keys_pool.mkph_count -= 1;

	/* Free half the time */
	if (pt & 0x01) {
		zfree(mptcp_keys_pool.mkph_key_entry_zone, key_holder);
	} else {
		/* Insert it at random point to avoid early reuse */
		int i = 0;
		if (mptcp_keys_pool.mkph_count > 1) {
			pt = pt % (mptcp_keys_pool.mkph_count - 1);
			LIST_FOREACH(key_elm, &mptcp_keys_pool, mkey_next) {
				if (++i >= pt) {
					LIST_INSERT_AFTER(key_elm, key_holder,
					    mkey_next);
					break;
				}
			}
			if (i < pt)
				panic("missed insertion");
		} else {
			LIST_INSERT_HEAD(&mptcp_keys_pool, key_holder,
			    mkey_next);
		}
		mptcp_keys_pool.mkph_count += 1;
	}
	lck_mtx_unlock(&mptcp_keys_pool.mkph_lock);
}

static void
mptcp_key_pool_init(void)
{
	int i;
	struct mptcp_key_entry *key_entry;

	LIST_INIT(&mptcp_keys_pool);
	mptcp_keys_pool.mkph_count = 0;

	mptcp_keys_pool.mkph_key_elm_sz = (vm_size_t)
	    (sizeof (struct mptcp_key_entry));
	mptcp_keys_pool.mkph_key_entry_zone = zinit(
	    mptcp_keys_pool.mkph_key_elm_sz,
	    MPTCP_MX_KEY_ALLOCS * mptcp_keys_pool.mkph_key_elm_sz,
	    MPTCP_MX_PREALLOC_ZONE_SZ, "mptkeys");
	if (mptcp_keys_pool.mkph_key_entry_zone == NULL) {
		panic("%s: unable to allocate MPTCP keys zone \n", __func__);
		/* NOTREACHED */
	}
	zone_change(mptcp_keys_pool.mkph_key_entry_zone, Z_CALLERACCT, FALSE);
	zone_change(mptcp_keys_pool.mkph_key_entry_zone, Z_EXPAND, TRUE);

	for (i = 0; i < MPTCP_KEY_PREALLOCS_MX; i++) {
		key_entry = (struct mptcp_key_entry *)
		    zalloc(mptcp_keys_pool.mkph_key_entry_zone);
		key_entry->mkey_flags = MKEYF_FREE;
		mptcp_generate_unique_key(key_entry);
		LIST_INSERT_HEAD(&mptcp_keys_pool, key_entry, mkey_next);
		mptcp_keys_pool.mkph_count += 1;
	}
	lck_mtx_init(&mptcp_keys_pool.mkph_lock, mtcbinfo.mppi_lock_grp,
	    mtcbinfo.mppi_lock_attr);
}

/*
 * MPTCP Join support
 */

static void
mptcp_attach_to_subf(struct socket *so, struct mptcb *mp_tp,
    connid_t conn_id)
{
	struct tcpcb *tp = sototcpcb(so);
	struct mptcp_subf_auth_entry *sauth_entry;
	MPT_LOCK_ASSERT_NOTHELD(mp_tp);

	MPT_LOCK_SPIN(mp_tp);
	tp->t_mptcb = mp_tp;
	MPT_UNLOCK(mp_tp);
	/*
	 * As long as the mpts_connid is unique it can be used as the
	 * address ID for additional subflows.
	 * The address ID of the first flow is implicitly 0.
	 */
	if (mp_tp->mpt_state == MPTCPS_CLOSED) {
		tp->t_local_aid = 0;
	} else {
		tp->t_local_aid = conn_id;
		tp->t_mpflags |= (TMPF_PREESTABLISHED | TMPF_JOINED_FLOW);
		so->so_flags |= SOF_MP_SEC_SUBFLOW;
	}
	sauth_entry = zalloc(mpt_subauth_zone);
	sauth_entry->msae_laddr_id = tp->t_local_aid;
	sauth_entry->msae_raddr_id = 0;
	sauth_entry->msae_raddr_rand = 0;
try_again:
	sauth_entry->msae_laddr_rand = RandomULong();
	if (sauth_entry->msae_laddr_rand == 0)
		goto try_again;
	LIST_INSERT_HEAD(&mp_tp->mpt_subauth_list, sauth_entry, msae_next);
}

static void
mptcp_detach_mptcb_from_subf(struct mptcb *mp_tp, struct socket *so)
{
	struct mptcp_subf_auth_entry *sauth_entry;
	struct tcpcb *tp = sototcpcb(so);
	int found = 0;

	if (tp == NULL)
		return;

	MPT_LOCK(mp_tp);
	LIST_FOREACH(sauth_entry, &mp_tp->mpt_subauth_list, msae_next) {
		if (sauth_entry->msae_laddr_id == tp->t_local_aid) {
			found = 1;
			break;
		}
	}
	if (found) {
		LIST_REMOVE(sauth_entry, msae_next);
		zfree(mpt_subauth_zone, sauth_entry);
	}
	tp->t_mptcb = NULL;
	MPT_UNLOCK(mp_tp);
}

void
mptcp_get_rands(mptcp_addr_id addr_id, struct mptcb *mp_tp, u_int32_t *lrand,
    u_int32_t *rrand)
{
	struct mptcp_subf_auth_entry *sauth_entry;
	MPT_LOCK_ASSERT_NOTHELD(mp_tp);

	MPT_LOCK(mp_tp);
	LIST_FOREACH(sauth_entry, &mp_tp->mpt_subauth_list, msae_next) {
		if (sauth_entry->msae_laddr_id == addr_id) {
			if (lrand)
				*lrand = sauth_entry->msae_laddr_rand;
			if (rrand)
				*rrand = sauth_entry->msae_raddr_rand;
			break;
		}
	}
	MPT_UNLOCK(mp_tp);
}

void
mptcp_set_raddr_rand(mptcp_addr_id laddr_id, struct mptcb *mp_tp,
    mptcp_addr_id raddr_id, u_int32_t raddr_rand)
{
	struct mptcp_subf_auth_entry *sauth_entry;
	MPT_LOCK_ASSERT_NOTHELD(mp_tp);

	MPT_LOCK(mp_tp);
	LIST_FOREACH(sauth_entry, &mp_tp->mpt_subauth_list, msae_next) {
		if (sauth_entry->msae_laddr_id == laddr_id) {
			if ((sauth_entry->msae_raddr_id != 0) &&
			    (sauth_entry->msae_raddr_id != raddr_id)) {
				mptcplog((LOG_ERR, "MPTCP ERROR %s: mismatched"
				    " address ids %d %d \n", __func__, raddr_id,
				    sauth_entry->msae_raddr_id));
				MPT_UNLOCK(mp_tp);
				return;
			}
			sauth_entry->msae_raddr_id = raddr_id;
			if ((sauth_entry->msae_raddr_rand != 0) &&
			    (sauth_entry->msae_raddr_rand != raddr_rand)) {
				mptcplog((LOG_ERR, "%s: dup SYN_ACK %d %d \n",
				    __func__, raddr_rand,
				    sauth_entry->msae_raddr_rand));
				MPT_UNLOCK(mp_tp);
				return;
			}
			sauth_entry->msae_raddr_rand = raddr_rand;
			MPT_UNLOCK(mp_tp);
			return;
		}
	}
	MPT_UNLOCK(mp_tp);
}

/*
 * SHA1 support for MPTCP
 */
static int
mptcp_do_sha1(mptcp_key_t *key, char *sha_digest, int digest_len)
{
	SHA1_CTX sha1ctxt;
	const unsigned char *sha1_base;
	int sha1_size;

	if (digest_len != SHA1_RESULTLEN) {
		return (FALSE);
	}

	sha1_base = (const unsigned char *) key;
	sha1_size = sizeof (mptcp_key_t);
	SHA1Init(&sha1ctxt);
	SHA1Update(&sha1ctxt, sha1_base, sha1_size);
	SHA1Final(sha_digest, &sha1ctxt);
	return (TRUE);
}

void
mptcp_hmac_sha1(mptcp_key_t key1, mptcp_key_t key2,
	u_int32_t rand1, u_int32_t rand2, u_char *digest, int digest_len)
{
	SHA1_CTX  sha1ctxt;
	mptcp_key_t key_ipad[8] = {0}; /* key XOR'd with inner pad */
	mptcp_key_t key_opad[8] = {0}; /* key XOR'd with outer pad */
	u_int32_t data[2];
	int i;

	bzero(digest, digest_len);

	/* Set up the Key for HMAC */
	key_ipad[0] = key1;
	key_ipad[1] = key2;

	key_opad[0] = key1;
	key_opad[1] = key2;

	/* Set up the message for HMAC */
	data[0] = rand1;
	data[1] = rand2;

	/* Key is 512 block length, so no need to compute hash */

	/* Compute SHA1(Key XOR opad, SHA1(Key XOR ipad, data)) */

	for (i = 0; i < 8; i++) {
		key_ipad[i] ^= 0x3636363636363636;
		key_opad[i] ^= 0x5c5c5c5c5c5c5c5c;
	}

	/* Perform inner SHA1 */
	SHA1Init(&sha1ctxt);
	SHA1Update(&sha1ctxt, (unsigned char *)key_ipad, sizeof (key_ipad));
	SHA1Update(&sha1ctxt, (unsigned char *)data, sizeof (data));
	SHA1Final(digest, &sha1ctxt);

	/* Perform outer SHA1 */
	SHA1Init(&sha1ctxt);
	SHA1Update(&sha1ctxt, (unsigned char *)key_opad, sizeof (key_opad));
	SHA1Update(&sha1ctxt, (unsigned char *)digest, SHA1_RESULTLEN);
	SHA1Final(digest, &sha1ctxt);
}

/*
 * corresponds to MAC-B = MAC (Key=(Key-B+Key-A), Msg=(R-B+R-A))
 * corresponds to MAC-A = MAC (Key=(Key-A+Key-B), Msg=(R-A+R-B))
 */
void
mptcp_get_hmac(mptcp_addr_id aid, struct mptcb *mp_tp, u_char *digest,
    int digest_len)
{
	uint32_t lrand, rrand;
	mptcp_key_t localkey, remotekey;
	MPT_LOCK_ASSERT_NOTHELD(mp_tp);

	if (digest_len != SHA1_RESULTLEN)
		return;

	lrand = rrand = 0;
	mptcp_get_rands(aid, mp_tp, &lrand, &rrand);
	MPT_LOCK_SPIN(mp_tp);
	localkey = *mp_tp->mpt_localkey;
	remotekey = mp_tp->mpt_remotekey;
	MPT_UNLOCK(mp_tp);
	mptcp_hmac_sha1(localkey, remotekey, lrand, rrand, digest,
	    digest_len);
}

u_int64_t
mptcp_get_trunced_hmac(mptcp_addr_id aid, struct mptcb *mp_tp)
{
	u_char digest[SHA1_RESULTLEN];
	u_int64_t trunced_digest;

	mptcp_get_hmac(aid, mp_tp, &digest[0], sizeof (digest));
	bcopy(digest, &trunced_digest, 8);
	return (trunced_digest);
}

/*
 * Authentication data generation
 */
int
mptcp_generate_token(char *sha_digest, int sha_digest_len, caddr_t token,
    int token_len)
{
	VERIFY(token_len == sizeof (u_int32_t));
	VERIFY(sha_digest_len == SHA1_RESULTLEN);

	/* Most significant 32 bits of the SHA1 hash */
	bcopy(sha_digest, token, sizeof (u_int32_t));
	return (TRUE);
}

int
mptcp_generate_idsn(char *sha_digest, int sha_digest_len, caddr_t idsn,
    int idsn_len)
{
	VERIFY(idsn_len == sizeof (u_int64_t));
	VERIFY(sha_digest_len == SHA1_RESULTLEN);

	/*
	 * Least significant 64 bits of the SHA1 hash
	 */

	idsn[7] = sha_digest[12];
	idsn[6] = sha_digest[13];
	idsn[5] = sha_digest[14];
	idsn[4] = sha_digest[15];
	idsn[3] = sha_digest[16];
	idsn[2] = sha_digest[17];
	idsn[1] = sha_digest[18];
	idsn[0] = sha_digest[19];
	return (TRUE);
}

static int
mptcp_init_authparms(struct mptcb *mp_tp)
{
	caddr_t local_digest = NULL;
	char remote_digest[MPTCP_SHA1_RESULTLEN];
	MPT_LOCK_ASSERT_HELD(mp_tp);

	/* Only Version 0 is supported for auth purposes */
	if (mp_tp->mpt_version != MP_DRAFT_VERSION_12)
		return (-1);

	/* Setup local and remote tokens and Initial DSNs */
	local_digest = mptcp_get_stored_digest(mp_tp->mpt_localkey);
	mptcp_generate_token(local_digest, SHA1_RESULTLEN,
	    (caddr_t)&mp_tp->mpt_localtoken, sizeof (mp_tp->mpt_localtoken));
	mptcp_generate_idsn(local_digest, SHA1_RESULTLEN,
	    (caddr_t)&mp_tp->mpt_local_idsn, sizeof (u_int64_t));

	if (!mptcp_do_sha1(&mp_tp->mpt_remotekey, remote_digest,
	    SHA1_RESULTLEN)) {
		mptcplog((LOG_ERR, "MPTCP ERROR %s: unexpected failure",
		    __func__));
		return (-1);
	}
	mptcp_generate_token(remote_digest, SHA1_RESULTLEN,
	    (caddr_t)&mp_tp->mpt_remotetoken, sizeof (mp_tp->mpt_localtoken));
	mptcp_generate_idsn(remote_digest, SHA1_RESULTLEN,
	    (caddr_t)&mp_tp->mpt_remote_idsn, sizeof (u_int64_t));
	return (0);
}

static void
mptcp_init_statevars(struct mptcb *mp_tp)
{
	MPT_LOCK_ASSERT_HELD(mp_tp);

	/* The subflow SYN is also first MPTCP byte */
	mp_tp->mpt_snduna = mp_tp->mpt_sndmax = mp_tp->mpt_local_idsn + 1;
	mp_tp->mpt_sndnxt = mp_tp->mpt_snduna;

	mp_tp->mpt_rcvatmark = mp_tp->mpt_rcvnxt = mp_tp->mpt_remote_idsn + 1;
}

static void
mptcp_conn_properties(struct mptcb *mp_tp)
{
	/* There is only Version 0 at this time */
	mp_tp->mpt_version = MP_DRAFT_VERSION_12;

	/* Set DSS checksum flag */
	if (mptcp_dss_csum)
		mp_tp->mpt_flags |= MPTCPF_CHECKSUM;

	/* Set up receive window */
	mp_tp->mpt_rcvwnd = mptcp_sbspace(mp_tp);

	/* Set up gc ticks */
	mp_tp->mpt_gc_ticks = MPT_GC_TICKS;
}

/*
 * Helper Functions
 */
mptcp_token_t
mptcp_get_localtoken(void* mptcb_arg)
{
	struct mptcb *mp_tp = (struct mptcb *)mptcb_arg;
	return (mp_tp->mpt_localtoken);
}

mptcp_token_t
mptcp_get_remotetoken(void* mptcb_arg)
{
	struct mptcb *mp_tp = (struct mptcb *)mptcb_arg;
	return (mp_tp->mpt_remotetoken);
}

u_int64_t
mptcp_get_localkey(void* mptcb_arg)
{
	struct mptcb *mp_tp = (struct mptcb *)mptcb_arg;
	if (mp_tp->mpt_localkey != NULL)
		return (*mp_tp->mpt_localkey);
	else
		return (0);
}

u_int64_t
mptcp_get_remotekey(void* mptcb_arg)
{
	struct mptcb *mp_tp = (struct mptcb *)mptcb_arg;
	return (mp_tp->mpt_remotekey);
}

void
mptcp_send_dfin(struct socket *so)
{
	struct tcpcb *tp = NULL;
	struct inpcb *inp = NULL;

	inp = sotoinpcb(so);
	if (!inp)
		return;

	tp = intotcpcb(inp);
	if (!tp)
		return;

	if (!(tp->t_mpflags & TMPF_RESET))
		tp->t_mpflags |= TMPF_SEND_DFIN;
}

/*
 * Data Sequence Mapping routines
 */
void
mptcp_insert_dsn(struct mppcb *mpp, struct mbuf *m)
{
	struct mptcb *mp_tp;

	if (m == NULL)
		return;

	mp_tp = &((struct mpp_mtp *)mpp)->mtcb;
	MPT_LOCK(mp_tp);
	if (mp_tp->mpt_state < MPTCPS_ESTABLISHED) {
		MPT_UNLOCK(mp_tp);
		panic("%s: data write before establishment.",
		    __func__);
		return;
	}

	while (m) {
		VERIFY(m->m_flags & M_PKTHDR);
		m->m_pkthdr.pkt_flags |= (PKTF_MPTCP | PKTF_MPSO);
		m->m_pkthdr.mp_dsn = mp_tp->mpt_sndmax;
		m->m_pkthdr.mp_rlen = m_pktlen(m);
		mp_tp->mpt_sndmax += m_pktlen(m);
		m = m->m_next;
	}
	MPT_UNLOCK(mp_tp);
}

void
mptcp_preproc_sbdrop(struct mbuf *m, unsigned int len)
{
	u_int32_t sub_len = 0;

	while (m) {
		VERIFY(m->m_flags & M_PKTHDR);

		if (m->m_pkthdr.pkt_flags & PKTF_MPTCP) {
			sub_len = m->m_pkthdr.mp_rlen;

			if (sub_len < len) {
				m->m_pkthdr.mp_dsn += sub_len;
				if (!(m->m_pkthdr.pkt_flags & PKTF_MPSO)) {
					m->m_pkthdr.mp_rseq += sub_len;
				}
				m->m_pkthdr.mp_rlen = 0;
				len -= sub_len;
			} else {
				/* sub_len >= len */
				m->m_pkthdr.mp_dsn += len;
				if (!(m->m_pkthdr.pkt_flags & PKTF_MPSO)) {
					m->m_pkthdr.mp_rseq += len;
				}
				mptcplog3((LOG_INFO,
				    "%s: %llu %u %d %d\n", __func__,
				    m->m_pkthdr.mp_dsn, m->m_pkthdr.mp_rseq,
				    m->m_pkthdr.mp_rlen, len));
				m->m_pkthdr.mp_rlen -= len;
				return;
			}
		} else {
			panic("%s: MPTCP tag not set", __func__);
			/* NOTREACHED */
		}
		m = m->m_next;
	}
}

/* Obtain the DSN mapping stored in the mbuf */
void
mptcp_output_getm_dsnmap32(struct socket *so, int off, uint32_t datalen,
    u_int32_t *dsn, u_int32_t *relseq, u_int16_t *data_len, u_int64_t *dsn64p)
{
	u_int64_t dsn64;

	mptcp_output_getm_dsnmap64(so, off, datalen, &dsn64, relseq, data_len);
	*dsn = (u_int32_t)MPTCP_DATASEQ_LOW32(dsn64);
	*dsn64p = dsn64;
}

void
mptcp_output_getm_dsnmap64(struct socket *so, int off, uint32_t datalen,
    u_int64_t *dsn, u_int32_t *relseq, u_int16_t *data_len)
{
	struct mbuf *m = so->so_snd.sb_mb;
	struct mbuf *mnext = NULL;
	uint32_t runlen = 0;
	u_int64_t dsn64;
	uint32_t contig_len = 0;

	if (m == NULL)
		return;

	if (off < 0)
		return;
	/*
	 * In the subflow socket, the DSN sequencing can be discontiguous,
	 * but the subflow sequence mapping is contiguous. Use the subflow
	 * sequence property to find the right mbuf and corresponding dsn
	 * mapping.
	 */

	while (m) {
		VERIFY(m->m_pkthdr.pkt_flags & PKTF_MPTCP);
		VERIFY(m->m_flags & M_PKTHDR);

		if ((unsigned int)off >= m->m_pkthdr.mp_rlen) {
			off -= m->m_pkthdr.mp_rlen;
			m = m->m_next;
		} else {
			break;
		}
	}

	if (m == NULL) {
		panic("%s: bad offset", __func__);
		/* NOTREACHED */
	}

	dsn64 = m->m_pkthdr.mp_dsn + off;
	*dsn = dsn64;
	*relseq = m->m_pkthdr.mp_rseq + off;

	/*
	 * Now find the last contiguous byte and its length from
	 * start.
	 */
	runlen = m->m_pkthdr.mp_rlen - off;
	contig_len = runlen;

	/* If datalen does not span multiple mbufs, return */
	if (datalen <= runlen) {
		*data_len = min(datalen, UINT16_MAX);
		return;
	}

	mnext = m->m_next;
	while (datalen > runlen) {
		if (mnext == NULL) {
			panic("%s: bad datalen = %d, %d %d", __func__, datalen,
			    runlen, off);
			/* NOTREACHED */
		}
		VERIFY(mnext->m_flags & M_PKTHDR);
		VERIFY(mnext->m_pkthdr.pkt_flags & PKTF_MPTCP);

		/*
		 * case A. contiguous DSN stream
		 * case B. discontiguous DSN stream
		 */
		if (mnext->m_pkthdr.mp_dsn == (dsn64 + runlen)) {
			/* case A */
			runlen += mnext->m_pkthdr.mp_rlen;
			contig_len += mnext->m_pkthdr.mp_rlen;
			mptcplog3((LOG_INFO, "%s: contig \n",
			    __func__));
		} else {
			/* case B */
			mptcplog((LOG_INFO, "%s: discontig %d %d \n",
			    __func__, datalen, contig_len));
			break;
		}
		mnext = mnext->m_next;
	}
	datalen = min(datalen, UINT16_MAX);
	*data_len = min(datalen, contig_len);
	mptcplog3((LOG_INFO, "%s: %llu %u %d %d \n", __func__,
	    *dsn, *relseq, *data_len, off));
}

/*
 * MPTCP's notion of the next insequence Data Sequence number is adjusted
 * here. It must be called from mptcp_adj_rmap() which is called only after
 * reassembly of out of order data. The rcvnxt variable must
 * be updated only when atleast some insequence new data is received.
 */
static void
mptcp_adj_rcvnxt(struct tcpcb *tp, struct mbuf *m)
{
	struct mptcb *mp_tp = tptomptp(tp);

	if (mp_tp == NULL)
		return;
	MPT_LOCK(mp_tp);
	if ((MPTCP_SEQ_GEQ(mp_tp->mpt_rcvnxt, m->m_pkthdr.mp_dsn)) &&
	    (MPTCP_SEQ_LEQ(mp_tp->mpt_rcvnxt, (m->m_pkthdr.mp_dsn +
	    m->m_pkthdr.mp_rlen)))) {
		mp_tp->mpt_rcvnxt = m->m_pkthdr.mp_dsn + m->m_pkthdr.mp_rlen;
	}
	MPT_UNLOCK(mp_tp);
}

/*
 * Note that this is called only from tcp_input() which may trim data
 * after the dsn mapping is inserted into the mbuf. When it trims data
 * tcp_input calls m_adj() which does not remove the m_pkthdr even if the
 * m_len becomes 0 as a result of trimming the mbuf. The dsn map insertion
 * cannot be delayed after trim, because data can be in the reassembly
 * queue for a while and the DSN option info in tp will be overwritten for
 * every new packet received.
 * The dsn map will be adjusted just prior to appending to subflow sockbuf
 * with mptcp_adj_rmap()
 */
void
mptcp_insert_rmap(struct tcpcb *tp, struct mbuf *m)
{
	VERIFY(!(m->m_pkthdr.pkt_flags & PKTF_MPTCP));

	if (tp->t_mpflags & TMPF_EMBED_DSN) {
		VERIFY(m->m_flags & M_PKTHDR);
		m->m_pkthdr.mp_dsn = tp->t_rcv_map.mpt_dsn;
		m->m_pkthdr.mp_rseq = tp->t_rcv_map.mpt_sseq;
		m->m_pkthdr.mp_rlen = tp->t_rcv_map.mpt_len;
		m->m_pkthdr.pkt_flags |= PKTF_MPTCP;
		tp->t_mpflags &= ~TMPF_EMBED_DSN;
		tp->t_mpflags |= TMPF_MPTCP_ACKNOW;
	}
}

void
mptcp_adj_rmap(struct socket *so, struct mbuf *m)
{
	u_int64_t dsn;
	u_int32_t sseq, datalen;
	struct tcpcb *tp = intotcpcb(sotoinpcb(so));
	u_int32_t old_rcvnxt = 0;

	if (m_pktlen(m) == 0)
		return;

	if (m->m_pkthdr.pkt_flags & PKTF_MPTCP) {
		VERIFY(m->m_flags & M_PKTHDR);

		dsn = m->m_pkthdr.mp_dsn;
		sseq = m->m_pkthdr.mp_rseq + tp->irs;
		datalen = m->m_pkthdr.mp_rlen;
	} else {
		/* data arrived without an DSS option mapping */
		mptcp_notify_mpfail(so);
		return;
	}

	/* In the common case, data is in window and in sequence */
	if (m->m_pkthdr.len == (int)datalen) {
		mptcp_adj_rcvnxt(tp, m);
		return;
	}

	if (m->m_pkthdr.len > (int)datalen) {
		panic("%s: mbuf len = %d expected = %d", __func__,
		    m->m_pkthdr.len, datalen);
	}

	old_rcvnxt = tp->rcv_nxt - m->m_pkthdr.len;
	if (SEQ_GT(old_rcvnxt, sseq)) {
		/* data trimmed from the left */
		int off = old_rcvnxt - sseq;
		m->m_pkthdr.mp_dsn += off;
		m->m_pkthdr.mp_rseq += off;
		m->m_pkthdr.mp_rlen -= off;
	} else if (old_rcvnxt == sseq) {
		/*
		 * Data was trimmed from the right
		 */
		m->m_pkthdr.mp_rlen = m->m_pkthdr.len;
	} else {
		/* XXX handle gracefully with reass or fallback in January */
		panic("%s: partial map %u %u", __func__, old_rcvnxt, sseq);
		/* NOTREACHED */
	}
	mptcp_adj_rcvnxt(tp, m);

}

/*
 * Following routines help with failure detection and failover of data
 * transfer from one subflow to another.
 */
void
mptcp_act_on_txfail(struct socket *so)
{
	struct tcpcb *tp = NULL;
	struct inpcb *inp = sotoinpcb(so);

	if (inp == NULL)
		return;

	tp = intotcpcb(inp);
	if (tp == NULL)
		return;

	if (tp->t_state != TCPS_ESTABLISHED)
		mptcplog((LOG_INFO, "%s: state = %d \n", __func__,
		    tp->t_state));

	if (so->so_flags & SOF_MP_TRYFAILOVER) {
		return;
	}

	so->so_flags |= SOF_MP_TRYFAILOVER;
	soevent(so, (SO_FILT_HINT_LOCKED | SO_FILT_HINT_MPFAILOVER));
}

/*
 * Support for MP_FAIL option
 */
int
mptcp_get_map_for_dsn(struct socket *so, u_int64_t dsn_fail, u_int32_t *tcp_seq)
{
	struct mbuf *m = so->so_snd.sb_mb;
	u_int64_t dsn;
	int off = 0;
	u_int32_t datalen;

	if (m == NULL)
		return (-1);

	while (m != NULL) {
		VERIFY(m->m_pkthdr.pkt_flags & PKTF_MPTCP);
		VERIFY(m->m_flags & M_PKTHDR);
		dsn = m->m_pkthdr.mp_dsn;
		datalen = m->m_pkthdr.mp_rlen;
		if (MPTCP_SEQ_LEQ(dsn, dsn_fail) &&
		    (MPTCP_SEQ_GEQ(dsn + datalen, dsn_fail))) {
			off = dsn_fail - dsn;
			*tcp_seq = m->m_pkthdr.mp_rseq + off;
			return (0);
		}

		m = m->m_next;
	}

	/*
	 * If there was no mbuf data and a fallback to TCP occurred, there's
	 * not much else to do.
	 */

	mptcplog((LOG_ERR, "%s: %llu not found \n", __func__, dsn_fail));
	return (-1);
}

/*
 * Support for sending contiguous MPTCP bytes in subflow
 */
int32_t
mptcp_adj_sendlen(struct socket *so, int32_t off, int32_t len)
{
	u_int64_t	mdss_dsn = 0;
	u_int32_t	mdss_subflow_seq = 0;
	u_int16_t	mdss_data_len = 0;

	if (len == 0)
		return (len);

	mptcp_output_getm_dsnmap64(so, off, (u_int32_t)len,
	    &mdss_dsn, &mdss_subflow_seq, &mdss_data_len);

	return (mdss_data_len);
}

int32_t
mptcp_sbspace(struct mptcb *mpt)
{
	struct sockbuf *sb;
	uint32_t rcvbuf;
	int32_t space;

	MPT_LOCK_ASSERT_HELD(mpt);
	MPTE_LOCK_ASSERT_HELD(mpt->mpt_mpte);

	sb = &mpt->mpt_mpte->mpte_mppcb->mpp_socket->so_rcv;
	rcvbuf = sb->sb_hiwat;
	space = ((int32_t)imin((rcvbuf - sb->sb_cc),
	    (sb->sb_mbmax - sb->sb_mbcnt)));
	if (space < 0)
		space = 0;
	/* XXX check if it's too small? */

	return (space);
}

/*
 * Support Fallback to Regular TCP
 */
void
mptcp_notify_mpready(struct socket *so)
{
	struct tcpcb *tp = NULL;

	if (so == NULL)
		return;

	tp = intotcpcb(sotoinpcb(so));

	if (tp == NULL)
		return;

	DTRACE_MPTCP4(multipath__ready, struct socket *, so,
	    struct sockbuf *, &so->so_rcv, struct sockbuf *, &so->so_snd,
	    struct tcpcb *, tp);

	if (!(tp->t_mpflags & TMPF_MPTCP_TRUE))
		return;

	if (tp->t_mpflags & TMPF_MPTCP_READY)
		return;

	tp->t_mpflags &= ~TMPF_TCP_FALLBACK;
	tp->t_mpflags |= TMPF_MPTCP_READY;

	soevent(so, (SO_FILT_HINT_LOCKED | SO_FILT_HINT_MPSTATUS));
}

void
mptcp_notify_mpfail(struct socket *so)
{
	struct tcpcb *tp = NULL;

	if (so == NULL)
		return;

	tp = intotcpcb(sotoinpcb(so));

	if (tp == NULL)
		return;

	DTRACE_MPTCP4(multipath__failed, struct socket *, so,
	    struct sockbuf *, &so->so_rcv, struct sockbuf *, &so->so_snd,
	    struct tcpcb *, tp);

	if (tp->t_mpflags & TMPF_TCP_FALLBACK)
		return;

	tp->t_mpflags &= ~(TMPF_MPTCP_READY|TMPF_MPTCP_TRUE);
	tp->t_mpflags |= TMPF_TCP_FALLBACK;

	soevent(so, (SO_FILT_HINT_LOCKED | SO_FILT_HINT_MPSTATUS));
}

/*
 * Keepalive helper function
 */
boolean_t
mptcp_ok_to_keepalive(struct mptcb *mp_tp)
{
	boolean_t ret = 1;
	VERIFY(mp_tp != NULL);
	MPT_LOCK(mp_tp);
	if (mp_tp->mpt_state >= MPTCPS_CLOSE_WAIT) {
		ret = 0;
	}
	MPT_UNLOCK(mp_tp);
	return (ret);
}

/*
 * MPTCP t_maxseg adjustment function
 */
int
mptcp_adj_mss(struct tcpcb *tp, boolean_t mtudisc)
{
	int mss_lower = 0;
	struct mptcb *mp_tp = tptomptp(tp);

#define	MPTCP_COMPUTE_LEN {				\
	mss_lower = sizeof (struct mptcp_dss_ack_opt);	\
	MPT_LOCK(mp_tp);				\
	if (mp_tp->mpt_flags & MPTCPF_CHECKSUM)		\
		mss_lower += 2;				\
	else						\
		/* adjust to 32-bit boundary + EOL */	\
		mss_lower += 2;				\
	MPT_UNLOCK(mp_tp);				\
}
	if (mp_tp == NULL)
		return (0);

	/*
	 * For the first subflow and subsequent subflows, adjust mss for
	 * most common MPTCP option size, for case where tcp_mss is called
	 * during option processing and MTU discovery.
	 */
	if ((tp->t_mpflags & TMPF_PREESTABLISHED) &&
	    (!(tp->t_mpflags & TMPF_JOINED_FLOW))) {
		MPTCP_COMPUTE_LEN;
	}

	if ((tp->t_mpflags & TMPF_PREESTABLISHED) &&
	    (tp->t_mpflags & TMPF_SENT_JOIN)) {
		MPTCP_COMPUTE_LEN;
	}

	if ((mtudisc) && (tp->t_mpflags & TMPF_MPTCP_TRUE)) {
		MPTCP_COMPUTE_LEN;
	}

	return (mss_lower);
}

/*
 * Update the pid, upid, uuid of the subflow so, based on parent so
 */
void
mptcp_update_last_owner(struct mptsub *mpts, struct socket *parent_mpso)
{
	struct socket *subflow_so = mpts->mpts_socket;
	
	MPTS_LOCK_ASSERT_HELD(mpts);

	socket_lock(subflow_so, 0);
	if ((subflow_so->last_pid != parent_mpso->last_pid) ||
		(subflow_so->last_upid != parent_mpso->last_upid)) {
		subflow_so->last_upid = parent_mpso->last_upid;
		subflow_so->last_pid = parent_mpso->last_pid;
		uuid_copy(subflow_so->last_uuid, parent_mpso->last_uuid);
	}
	so_update_policy(subflow_so);
	socket_unlock(subflow_so, 0);
}

static void
fill_mptcp_subflow(struct socket *so, mptcp_flow_t *flow, struct mptsub *mpts)
{
	struct inpcb *inp;

	tcp_getconninfo(so, &flow->flow_ci);
	inp = sotoinpcb(so);
#if INET6
	if ((inp->inp_vflag & INP_IPV6) != 0) {
		flow->flow_src.ss_family = AF_INET6;
		flow->flow_dst.ss_family = AF_INET6;
		flow->flow_src.ss_len = sizeof(struct sockaddr_in6);
		flow->flow_dst.ss_len = sizeof(struct sockaddr_in6);
		SIN6(&flow->flow_src)->sin6_port = inp->in6p_lport;
		SIN6(&flow->flow_dst)->sin6_port = inp->in6p_fport;
		SIN6(&flow->flow_src)->sin6_addr = inp->in6p_laddr;
		SIN6(&flow->flow_dst)->sin6_addr = inp->in6p_faddr;
	} else 
#endif
	{
		flow->flow_src.ss_family = AF_INET;
		flow->flow_dst.ss_family = AF_INET;
		flow->flow_src.ss_len = sizeof(struct sockaddr_in);
		flow->flow_dst.ss_len = sizeof(struct sockaddr_in);
		SIN(&flow->flow_src)->sin_port = inp->inp_lport;
		SIN(&flow->flow_dst)->sin_port = inp->inp_fport;
		SIN(&flow->flow_src)->sin_addr = inp->inp_laddr;
		SIN(&flow->flow_dst)->sin_addr = inp->inp_faddr;
	}
	flow->flow_flags = mpts->mpts_flags;
	flow->flow_cid = mpts->mpts_connid;
}

static int
mptcp_pcblist SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error = 0, f;
	size_t n, len;
	struct mppcb *mpp;
	struct mptses *mpte;
	struct mptcb *mp_tp;
	struct mptsub *mpts;
	struct socket *so;
	conninfo_mptcp_t mptcpci;
	mptcp_flow_t *flows;

	if (req->newptr != USER_ADDR_NULL)
		return (EPERM);

	lck_mtx_lock(&mtcbinfo.mppi_lock);
	n = mtcbinfo.mppi_count;
	if (req->oldptr == USER_ADDR_NULL) {
		lck_mtx_unlock(&mtcbinfo.mppi_lock);
		req->oldidx = (n + n/8) * sizeof(conninfo_mptcp_t) + 
		    4 * (n + n/8)  * sizeof(mptcp_flow_t);
		return (0);
	}
	TAILQ_FOREACH(mpp, &mtcbinfo.mppi_pcbs, mpp_entry) {
		bzero(&mptcpci, sizeof(mptcpci));
		lck_mtx_lock(&mpp->mpp_lock);
		VERIFY(mpp->mpp_flags & MPP_ATTACHED);
		mpte = mptompte(mpp);
		VERIFY(mpte != NULL);
		mp_tp = mpte->mpte_mptcb;
		VERIFY(mp_tp != NULL);
		len = sizeof(*flows) * mpte->mpte_numflows;
		flows = _MALLOC(len, M_TEMP, M_WAITOK | M_ZERO);
		if (flows == NULL) {
			lck_mtx_unlock(&mpp->mpp_lock);
			break;
		}
		/* N.B. we don't take the mpt_lock just for the state. */
		mptcpci.mptcpci_state = mp_tp->mpt_state;
		mptcpci.mptcpci_nflows = mpte->mpte_numflows;
		mptcpci.mptcpci_len = sizeof(mptcpci) +
		    sizeof(*flows) * (mptcpci.mptcpci_nflows - 1);
		error = SYSCTL_OUT(req, &mptcpci, 
		    sizeof(mptcpci) - sizeof(*flows));
		if (error) {
			lck_mtx_unlock(&mpp->mpp_lock);
			FREE(flows, M_TEMP);
			break;
		}
		f = 0;
		TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
			MPTS_LOCK(mpts);
			so = mpts->mpts_socket;
			socket_lock(so, 0);
			fill_mptcp_subflow(so, &flows[f], mpts);
			socket_unlock(so, 0);
			MPTS_UNLOCK(mpts);
			f++;
		}
		lck_mtx_unlock(&mpp->mpp_lock);
		error = SYSCTL_OUT(req, flows, len);
		FREE(flows, M_TEMP);
		if (error)
			break;
	}
	lck_mtx_unlock(&mtcbinfo.mppi_lock);

	return (error);
}

SYSCTL_PROC(_net_inet_mptcp, OID_AUTO, pcblist, CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, mptcp_pcblist, "S,conninfo_mptcp_t", 
    "List of active MPTCP connections");
