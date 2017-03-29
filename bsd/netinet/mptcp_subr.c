/*
 * Copyright (c) 2012-2016 Apple Inc. All rights reserved.
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
#include <net/if_var.h>
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

extern char *proc_best_name(proc_t);

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
static void mptcp_attach_to_subf(struct socket *, struct mptcb *, uint8_t);
static void mptcp_detach_mptcb_from_subf(struct mptcb *, struct socket *);

static uint32_t mptcp_gc(struct mppcbinfo *);
static int mptcp_subflow_soclose(struct mptsub *, struct socket *);
static int mptcp_subflow_soconnectx(struct mptses *, struct mptsub *);
static int mptcp_subflow_soreceive(struct socket *, struct sockaddr **,
    struct uio *, struct mbuf **, struct mbuf **, int *);
static void mptcp_subflow_rupcall(struct socket *, void *, int);
static void mptcp_subflow_input(struct mptses *, struct mptsub *);
static void mptcp_subflow_wupcall(struct socket *, void *, int);
static void mptcp_subflow_eupcall(struct socket *, void *, uint32_t);
static void mptcp_update_last_owner(struct mptsub *, struct socket *);
static void mptcp_output_needed(struct mptses *mpte, struct mptsub *to_mpts);
static void mptcp_get_rtt_measurement(struct mptsub *, struct mptses *);
static void mptcp_drop_tfo_data(struct mptses *, struct mptsub *, int *);

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
} ev_ret_t;

static ev_ret_t mptcp_subflow_events(struct mptses *, struct mptsub *, uint64_t *);
static ev_ret_t mptcp_subflow_connreset_ev(struct mptses *, struct mptsub *, uint64_t *);
static ev_ret_t mptcp_subflow_cantrcvmore_ev(struct mptses *, struct mptsub *, uint64_t *);
static ev_ret_t mptcp_subflow_cantsendmore_ev(struct mptses *, struct mptsub *, uint64_t *);
static ev_ret_t mptcp_subflow_timeout_ev(struct mptses *, struct mptsub *, uint64_t *);
static ev_ret_t mptcp_subflow_nosrcaddr_ev(struct mptses *, struct mptsub *, uint64_t *);
static ev_ret_t mptcp_subflow_failover_ev(struct mptses *, struct mptsub *, uint64_t *);
static ev_ret_t mptcp_subflow_ifdenied_ev(struct mptses *, struct mptsub *, uint64_t *);
static ev_ret_t mptcp_subflow_suspend_ev(struct mptses *, struct mptsub *, uint64_t *);
static ev_ret_t mptcp_subflow_resume_ev(struct mptses *, struct mptsub *, uint64_t *);
static ev_ret_t mptcp_subflow_connected_ev(struct mptses *, struct mptsub *, uint64_t *);
static ev_ret_t mptcp_subflow_disconnected_ev(struct mptses *, struct mptsub *, uint64_t *);
static ev_ret_t mptcp_subflow_mpstatus_ev(struct mptses *, struct mptsub *, uint64_t *);
static ev_ret_t mptcp_subflow_mustrst_ev(struct mptses *, struct mptsub *, uint64_t *);
static ev_ret_t mptcp_fastjoin_ev(struct mptses *, struct mptsub *, uint64_t *);
static ev_ret_t mptcp_deleteok_ev(struct mptses *, struct mptsub *, uint64_t *);
static ev_ret_t mptcp_subflow_mpcantrcvmore_ev(struct mptses *, struct mptsub *, uint64_t *);

static const char *mptcp_evret2str(ev_ret_t);

static mptcp_key_t *mptcp_reserve_key(void);
static int mptcp_do_sha1(mptcp_key_t *, char *, int);
static void mptcp_init_local_parms(struct mptcb *);

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

uint32_t mptcp_dbg_area = 0;		/* more noise if greater than 1 */
SYSCTL_UINT(_net_inet_mptcp, OID_AUTO, dbg_area, CTLFLAG_RW|CTLFLAG_LOCKED,
	&mptcp_dbg_area, 0, "MPTCP debug area");

uint32_t mptcp_dbg_level = 0;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, dbg_level, CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_dbg_level, 0, "MPTCP debug level");


SYSCTL_UINT(_net_inet_mptcp, OID_AUTO, pcbcount, CTLFLAG_RD|CTLFLAG_LOCKED,
	&mtcbinfo.mppi_count, 0, "Number of active PCBs");

/*
 * Since there is one kernel thread per mptcp socket, imposing an artificial
 * limit on number of allowed mptcp sockets.
 */
uint32_t mptcp_socket_limit = MPPCB_LIMIT;
SYSCTL_UINT(_net_inet_mptcp, OID_AUTO, sk_lim, CTLFLAG_RW|CTLFLAG_LOCKED,
	&mptcp_socket_limit, 0, "MPTCP socket limit");

/*
 * SYSCTL to turn on delayed cellular subflow start.
 */
uint32_t mptcp_delayed_subf_start = 0;
SYSCTL_UINT(_net_inet_mptcp, OID_AUTO, delayed, CTLFLAG_RW|CTLFLAG_LOCKED,
	&mptcp_delayed_subf_start, 0, "MPTCP Delayed Subflow start");

/*
 * sysctl to use network status hints from symptomsd
 */
uint32_t mptcp_use_symptomsd = 1;
SYSCTL_UINT(_net_inet_mptcp, OID_AUTO, usesymptoms, CTLFLAG_RW|CTLFLAG_LOCKED,
	&mptcp_use_symptomsd, 0, "MPTCP Use SymptomsD");

static struct protosw mptcp_subflow_protosw;
static struct pr_usrreqs mptcp_subflow_usrreqs;
#if INET6
static struct ip6protosw mptcp_subflow_protosw6;
static struct pr_usrreqs mptcp_subflow_usrreqs6;
#endif /* INET6 */

typedef struct mptcp_subflow_event_entry {
	uint64_t        sofilt_hint_mask;
	ev_ret_t        (*sofilt_hint_ev_hdlr)(
			    struct mptses *mpte,
			    struct mptsub *mpts,
			    uint64_t *p_mpsofilt_hint);
} mptsub_ev_entry_t;

/*
 * XXX The order of the event handlers below is really
 * really important.
 * SO_FILT_HINT_DELETEOK event has to be handled first,
 * else we may end up missing on this event.
 * Please read radar://24043716 for more details.
 */
static mptsub_ev_entry_t mpsub_ev_entry_tbl [] = {
	{
		.sofilt_hint_mask = SO_FILT_HINT_DELETEOK,
		.sofilt_hint_ev_hdlr = mptcp_deleteok_ev,
	},
	{
		.sofilt_hint_mask = SO_FILT_HINT_MPCANTRCVMORE,
		.sofilt_hint_ev_hdlr =	mptcp_subflow_mpcantrcvmore_ev,
	},
	{
		.sofilt_hint_mask = SO_FILT_HINT_MPFAILOVER,
		.sofilt_hint_ev_hdlr = mptcp_subflow_failover_ev,
	},
	{
		.sofilt_hint_mask = SO_FILT_HINT_CONNRESET,
		.sofilt_hint_ev_hdlr = mptcp_subflow_connreset_ev,
	},
	{
		.sofilt_hint_mask = SO_FILT_HINT_MUSTRST,
		.sofilt_hint_ev_hdlr = mptcp_subflow_mustrst_ev,
	},
	{
		.sofilt_hint_mask = SO_FILT_HINT_CANTRCVMORE,
		.sofilt_hint_ev_hdlr = mptcp_subflow_cantrcvmore_ev,
	},
	{	.sofilt_hint_mask = SO_FILT_HINT_CANTSENDMORE,
		.sofilt_hint_ev_hdlr = mptcp_subflow_cantsendmore_ev,
	},
	{
		.sofilt_hint_mask = SO_FILT_HINT_TIMEOUT,
		.sofilt_hint_ev_hdlr = mptcp_subflow_timeout_ev,
	},
	{
		.sofilt_hint_mask = SO_FILT_HINT_NOSRCADDR,
		.sofilt_hint_ev_hdlr = mptcp_subflow_nosrcaddr_ev,
	},
	{
		.sofilt_hint_mask = SO_FILT_HINT_IFDENIED,
		.sofilt_hint_ev_hdlr = mptcp_subflow_ifdenied_ev,
	},
	{
		.sofilt_hint_mask = SO_FILT_HINT_SUSPEND,
		.sofilt_hint_ev_hdlr = mptcp_subflow_suspend_ev,
	},
	{
		.sofilt_hint_mask = SO_FILT_HINT_RESUME,
		.sofilt_hint_ev_hdlr = mptcp_subflow_resume_ev,
	},
	{
		.sofilt_hint_mask = SO_FILT_HINT_CONNECTED,
		.sofilt_hint_ev_hdlr = mptcp_subflow_connected_ev,
	},
	{
		.sofilt_hint_mask = SO_FILT_HINT_MPSTATUS,
		.sofilt_hint_ev_hdlr = mptcp_subflow_mpstatus_ev,
	},
	{
		.sofilt_hint_mask = SO_FILT_HINT_DISCONNECTED,
		.sofilt_hint_ev_hdlr = mptcp_subflow_disconnected_ev,
	},
	{
		.sofilt_hint_mask = SO_FILT_HINT_MPFASTJ,
		.sofilt_hint_ev_hdlr = mptcp_fastjoin_ev,
	}
};

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
	mtcbinfo.mppi_pcbe_create = mptcp_sescreate;

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
void *
mptcp_sescreate(struct socket *mp_so, struct mppcb *mpp)
{
	struct mppcbinfo *mppi;
	struct mptses *mpte;
	struct mptcb *mp_tp;
	int error = 0;

	VERIFY(mpp != NULL);
	mppi = mpp->mpp_pcbinfo;
	VERIFY(mppi != NULL);

	__IGNORE_WCASTALIGN(mpte = &((struct mpp_mtp *)mpp)->mpp_ses);
	__IGNORE_WCASTALIGN(mp_tp = &((struct mpp_mtp *)mpp)->mtcb);

	/* MPTCP Multipath PCB Extension */
	bzero(mpte, sizeof (*mpte));
	VERIFY(mpp->mpp_pcbe == NULL);
	mpp->mpp_pcbe = mpte;
	mpte->mpte_mppcb = mpp;
	mpte->mpte_mptcb = mp_tp;

	TAILQ_INIT(&mpte->mpte_sopts);
	TAILQ_INIT(&mpte->mpte_subflows);
	mpte->mpte_associd = SAE_ASSOCID_ANY;
	mpte->mpte_connid_last = SAE_CONNID_ANY;

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
	mp_tp->mpt_state = MPTCPS_CLOSED;
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

	if (mpts->mpts_src != NULL) {
		FREE(mpts->mpts_src, M_SONAME);
		mpts->mpts_src = NULL;
	}
	if (mpts->mpts_dst != NULL) {
		FREE(mpts->mpts_dst, M_SONAME);
		mpts->mpts_dst = NULL;
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
		mptcplog((LOG_ERR, "MPTCP Socket: subflow socreate mp_so 0x%llx"
		    " unable to create subflow socket error %d\n",
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so), error),
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
		return (error);
	}

	socket_lock(*so, 0);
	VERIFY((*so)->so_flags & SOF_MP_SUBFLOW);
	VERIFY(((*so)->so_state & (SS_NBIO|SS_NOFDREF)) ==
	    (SS_NBIO|SS_NOFDREF));

	/* prevent the socket buffers from being compressed */
	(*so)->so_rcv.sb_flags |= SB_NOCOMPRESS;
	(*so)->so_snd.sb_flags |= SB_NOCOMPRESS;

	/* Inherit preconnect and TFO data flags */
	if (mp_so->so_flags1 & SOF1_PRECONNECT_DATA)
		(*so)->so_flags1 |= SOF1_PRECONNECT_DATA;

	if (mp_so->so_flags1 & SOF1_DATA_IDEMPOTENT)
		(*so)->so_flags1 |= SOF1_DATA_IDEMPOTENT;

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
			mptcplog((LOG_ERR, "MPTCP Socket: subflow socreate"
			    " mp_so 0x%llx"
			    " sopt %s val %d interim record removed\n",
			    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
			    mptcp_sopt2str(mpo->mpo_level, mpo->mpo_name,
			    buf, sizeof (buf)), mpo->mpo_intval),
			    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
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
		struct sockaddr *dst;
		char dbuf[MAX_IPv6_STR_LEN];

		dst = mpts->mpts_dst;

		mptcplog((LOG_DEBUG, "MPTCP Socket: connectx mp_so 0x%llx "
		    "dst %s[%d] cid %d [pended %s]\n",
		    (u_int64_t)VM_KERNEL_ADDRPERM(mpte->mpte_mppcb->mpp_socket),
		    inet_ntop(af, ((af == AF_INET) ?
		    (void *)&SIN(dst)->sin_addr.s_addr :
		    (void *)&SIN6(dst)->sin6_addr),
		    dbuf, sizeof (dbuf)), ((af == AF_INET) ?
		    ntohs(SIN(dst)->sin_port) :
		    ntohs(SIN6(dst)->sin6_port)),
		    mpts->mpts_connid,
		    ((mpts->mpts_flags & MPTSF_CONNECT_PENDING) ?
		    "YES" : "NO")),
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_LOG);
	}

	mpts->mpts_flags &= ~MPTSF_CONNECT_PENDING;

	socket_lock(so, 0);
	mptcp_attach_to_subf(so, mpte->mpte_mptcb, mpte->mpte_addrid_last);

	/* connect the subflow socket */
	error = soconnectxlocked(so, mpts->mpts_src, mpts->mpts_dst,
	    mpts->mpts_mpcr.mpcr_proc, mpts->mpts_mpcr.mpcr_ifscope,
	    mpte->mpte_associd, NULL, CONNREQF_MPTCP,
	    &mpts->mpts_mpcr, sizeof (mpts->mpts_mpcr), NULL, NULL);
	socket_unlock(so, 0);

	/* Allocate a unique address id per subflow */
	mpte->mpte_addrid_last++;
	if (mpte->mpte_addrid_last == 0)
		mpte->mpte_addrid_last++;

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
		SODEFUNCTLOG("%s[%d, %s]: defunct so 0x%llx [%d,%d] (%d)\n",
		    __func__, proc_pid(p), proc_best_name(p),
		    (uint64_t)VM_KERNEL_ADDRPERM(so),
		    SOCK_DOM(so), SOCK_TYPE(so), error);
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
	so->so_flags &= ~SOF_MPTCP_TRUE;

	/* allow socket buffers to be compressed */
	so->so_rcv.sb_flags &= ~SB_NOCOMPRESS;
	so->so_snd.sb_flags &= ~SB_NOCOMPRESS;

	/*
	 * Allow socket buffer auto sizing.
	 *
	 * This will increase the current 64k buffer size to whatever is best.
	 */
	if (!(so->so_rcv.sb_flags & SB_USRSIZE))
		so->so_rcv.sb_flags |= SB_AUTOSIZE;
	if (!(so->so_snd.sb_flags & SB_USRSIZE))
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
	struct socket *mp_so, *so = NULL;
	struct mptsub_connreq mpcr;
	struct mptcb *mp_tp;
	int af, error = 0;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	mp_so = mpte->mpte_mppcb->mpp_socket;
	mp_tp = mpte->mpte_mptcb;

	MPT_LOCK(mp_tp);
	if (mp_tp->mpt_state >= MPTCPS_CLOSE_WAIT) {
		/* If the remote end sends Data FIN, refuse subflow adds */
		error = ENOTCONN;
		MPT_UNLOCK(mp_tp);
		return (error);
	}
	MPT_UNLOCK(mp_tp);

	MPTS_LOCK(mpts);
	VERIFY(!(mpts->mpts_flags & (MPTSF_CONNECTING|MPTSF_CONNECTED)));
	VERIFY(mpts->mpts_mpte == NULL);
	VERIFY(mpts->mpts_socket == NULL);
	VERIFY(mpts->mpts_dst != NULL);
	VERIFY(mpts->mpts_connid == SAE_CONNID_ANY);

	af = mpts->mpts_family = mpts->mpts_dst->sa_family;

	/*
	 * If the source address is not specified, allocate a storage for
	 * it, so that later on we can fill it in with the actual source
	 * IP address chosen by the underlying layer for the subflow after
	 * it is connected.
	 */
	if (mpts->mpts_src == NULL) {
		int len = mpts->mpts_dst->sa_len;

		MALLOC(mpts->mpts_src, struct sockaddr *, len, M_SONAME,
		    M_WAITOK | M_ZERO);
		if (mpts->mpts_src == NULL) {
			error = ENOBUFS;
			goto out;
		}
		bzero(mpts->mpts_src, len);
		mpts->mpts_src->sa_len = len;
		mpts->mpts_src->sa_family = mpts->mpts_dst->sa_family;
	}

	/* create the subflow socket */
	if ((error = mptcp_subflow_socreate(mpte, mpts, af, p, &so)) != 0)
		goto out;

	/*
	 * Increment the counter, while avoiding 0 (SAE_CONNID_ANY) and
	 * -1 (SAE_CONNID_ALL).
	 */
	mpte->mpte_connid_last++;
	if (mpte->mpte_connid_last == SAE_CONNID_ALL ||
	    mpte->mpte_connid_last == SAE_CONNID_ANY)
		mpte->mpte_connid_last++;

	mpts->mpts_connid = mpte->mpte_connid_last;
	VERIFY(mpts->mpts_connid != SAE_CONNID_ANY &&
	    mpts->mpts_connid != SAE_CONNID_ALL);

	mpts->mpts_rel_seq = 1;

	/* Allocate a unique address id per subflow */
	mpte->mpte_addrid_last++;
	if (mpte->mpte_addrid_last == 0)
		mpte->mpte_addrid_last++;

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

		if (IFNET_IS_EXPENSIVE(mpts->mpts_outif)) {
			sototcpcb(so)->t_mpflags |= TMPF_BACKUP_PATH;
		} else {
			mpts->mpts_flags |= MPTSF_PREFERRED;
		}

		mptcplog((LOG_DEBUG, "MPTCP Socket: subflow_add mp_so 0x%llx "
		    "bindif %s[%d] cid %d expensive %d\n",
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
		    mpts->mpts_outif->if_xname,
		    ifscope, mpts->mpts_connid,
		    IFNET_IS_EXPENSIVE(mpts->mpts_outif)),
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_VERBOSE);
		socket_unlock(so, 0);
	}

	/* if source address and/or port is specified, bind to it */
	if (mpts->mpts_src != NULL) {
		struct sockaddr *sa = mpts->mpts_src;
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

			mptcplog((LOG_DEBUG, "MPTCP Socket: subflow_add "
			    "mp_so 0x%llx bindip %s[%d] cid %d\n",
			    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
			    inet_ntop(af, ((af == AF_INET) ?
			    (void *)&SIN(sa)->sin_addr.s_addr :
			    (void *)&SIN6(sa)->sin6_addr), sbuf, sizeof (sbuf)),
			    ntohs(lport), mpts->mpts_connid),
			    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_LOG);
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
	    SO_FILT_HINT_MUSTRST | SO_FILT_HINT_MPFASTJ |
	    SO_FILT_HINT_DELETEOK | SO_FILT_HINT_MPCANTRCVMORE);

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
			mptcp_init_local_parms(mp_tp);
		}
		MPT_UNLOCK(mp_tp);
		soisconnecting(mp_so);
		mpcr.mpcr_type = MPTSUB_CONNREQ_MP_ENABLE;
	} else {
		if (!(mp_tp->mpt_flags & MPTCPF_JOIN_READY))
			mpts->mpts_flags |= MPTSF_CONNECT_PENDING;

		/* avoid starting up cellular subflow unless required */
		if ((mptcp_delayed_subf_start) &&
		    (IFNET_IS_CELLULAR(mpts->mpts_outif))) {
		    	mpts->mpts_flags |= MPTSF_CONNECT_PENDING;
		}
		MPT_UNLOCK(mp_tp);
		mpcr.mpcr_type = MPTSUB_CONNREQ_MP_ADD;
	}

	/* If fastjoin or fastopen is requested, set state in mpts */
	if (mpte->mpte_nummpcapflows == 0) {
		if (so->so_flags1 & SOF1_PRECONNECT_DATA) {
			MPT_LOCK(mp_tp);
			if (mp_tp->mpt_state < MPTCPS_ESTABLISHED) {
				mpts->mpts_flags |= MPTSF_TFO_REQD;
				mpts->mpts_sndnxt = mp_tp->mpt_snduna;
			}
			MPT_UNLOCK(mp_tp);
		}

		if (so->so_flags & SOF_MPTCP_FASTJOIN) {
			MPT_LOCK(mp_tp);
			if (mp_tp->mpt_state == MPTCPS_ESTABLISHED) {
				mpts->mpts_flags |= MPTSF_FASTJ_REQD;
				mpts->mpts_sndnxt = mp_tp->mpt_snduna;
			}
			MPT_UNLOCK(mp_tp);
		}
	}

	mpts->mpts_mpcr = mpcr;
	mpts->mpts_flags |= MPTSF_CONNECTING;

	if (af == AF_INET || af == AF_INET6) {
		char dbuf[MAX_IPv6_STR_LEN];

		mptcplog((LOG_DEBUG, "MPTCP Socket: %s "
		    "mp_so 0x%llx dst %s[%d] cid %d "
		    "[pending %s]\n", __func__,
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
		    inet_ntop(af, ((af == AF_INET) ?
		    (void *)&SIN(mpts->mpts_dst)->sin_addr.s_addr :
		    (void *)&SIN6(mpts->mpts_dst)->sin6_addr),
		    dbuf, sizeof (dbuf)), ((af == AF_INET) ?
		    ntohs(SIN(mpts->mpts_dst)->sin_port) :
		    ntohs(SIN6(mpts->mpts_dst)->sin6_port)),
		    mpts->mpts_connid,
		    ((mpts->mpts_flags & MPTSF_CONNECT_PENDING) ?
		    "YES" : "NO")),
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_LOG);
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

	if (close && !((mpts->mpts_flags & MPTSF_DELETEOK) &&
	    (mpts->mpts_flags & MPTSF_USER_DISCONNECT))) {
		MPTS_UNLOCK(mpts);
		mptcplog((LOG_DEBUG, "MPTCP Socket: subflow_del returning"
		    " mp_so 0x%llx flags %x\n",
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so), mpts->mpts_flags),
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_LOG);
		return;
	}

	mptcplog((LOG_DEBUG, "MPTCP Socket: subflow_del mp_so 0x%llx "
	    "[u=%d,r=%d] cid %d [close %s] %d %x error %d\n",
	    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
	    mp_so->so_usecount,
	    mp_so->so_retaincnt, mpts->mpts_connid,
	    (close ? "YES" : "NO"), mpts->mpts_soerror,
	    mpts->mpts_flags,
	    mp_so->so_error),
	    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_LOG);

	VERIFY(mpts->mpts_mpte == mpte);
	VERIFY(mpts->mpts_connid != SAE_CONNID_ANY &&
	    mpts->mpts_connid != SAE_CONNID_ALL);

	VERIFY(mpts->mpts_flags & MPTSF_ATTACHED);
	atomic_bitclear_32(&mpts->mpts_flags, MPTSF_ATTACHED);
	TAILQ_REMOVE(&mpte->mpte_subflows, mpts, mpts_entry);
	VERIFY(mpte->mpte_numflows != 0);
	mpte->mpte_numflows--;
	if (mpte->mpte_active_sub == mpts)
		mpte->mpte_active_sub = NULL;

	/*
	 * Drop references held by this subflow socket; there
	 * will be no further upcalls made from this point.
	 */
	(void) sock_setupcalls(so, NULL, NULL, NULL, NULL);
	(void) sock_catchevents(so, NULL, NULL, 0);

	mptcp_detach_mptcb_from_subf(mpte->mpte_mptcb, so);

	if (close)
		(void) mptcp_subflow_soclose(mpts, so);

	VERIFY(mp_so->so_usecount > 0);
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
	VERIFY(mpts->mpts_connid != SAE_CONNID_ANY &&
	    mpts->mpts_connid != SAE_CONNID_ALL);

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
		mptcplog((LOG_DEBUG, "MPTCP Socket %s: cid %d fin %d "
		    "[linger %s]\n", __func__, mpts->mpts_connid, send_dfin,
		    (deleteok ? "NO" : "YES")),
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_LOG);

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

	/*
	 * mpte should never be NULL, except in a race with
	 * mptcp_subflow_del
	 */
	if (mpte == NULL)
		return;

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
		mptcplog((LOG_ERR, "MPTCP Receiver: %s cid %d error %d\n",
		    __func__, mpts->mpts_connid, error),
		    MPTCP_RECEIVER_DBG, MPTCP_LOGLVL_ERR);
		MPTS_UNLOCK(mpts);
		mpts_alt = mptcp_get_subflow(mpte, mpts, NULL);
		if (mpts_alt == NULL) {
			if (mptcp_delayed_subf_start) {
				mpts_alt = mptcp_get_pending_subflow(mpte,
				    mpts);
				if (mpts_alt) {
					mptcplog((LOG_DEBUG,"MPTCP Receiver:"
					" %s: pending %d\n",
					__func__, mpts_alt->mpts_connid),
					MPTCP_RECEIVER_DBG, MPTCP_LOGLVL_ERR);
				} else {
					mptcplog((LOG_ERR, "MPTCP Receiver:"
					    " %s: no pending flow for cid %d",
					    __func__, mpts->mpts_connid),
					    MPTCP_RECEIVER_DBG, MPTCP_LOGLVL_ERR);
				}
			} else {
				mptcplog((LOG_ERR, "MPTCP Receiver: %s: no alt"
				    " path for cid %d\n", __func__,
				    mpts->mpts_connid),
				    MPTCP_RECEIVER_DBG, MPTCP_LOGLVL_ERR);
			}
			if (error == ENODATA) {
				/*
				 * Don't ignore ENODATA so as to discover
				 * nasty middleboxes.
				 */
				struct socket *mp_so =
				    mpte->mpte_mppcb->mpp_socket;
				mp_so->so_error = ENODATA;
				sorwakeup(mp_so);
			}
		}
		MPTS_LOCK(mpts);
	} else if (error == 0) {
		mptcplog((LOG_DEBUG, "MPTCP Receiver: %s: cid %d \n",
		    __func__, mpts->mpts_connid),
		    MPTCP_RECEIVER_DBG, MPTCP_LOGLVL_VERBOSE);
	}

	/* In fallback, make sure to accept data on all but one subflow */
	if ((mpts->mpts_flags & MPTSF_MP_DEGRADED) &&
	    (!(mpts->mpts_flags & MPTSF_ACTIVE))) {
		m_freem(m);
		return;
	}

	if (m != NULL) {

		/* Did we receive data on the backup subflow? */
		if (!(mpts->mpts_flags & MPTSF_ACTIVE))
			mpts->mpts_peerswitch++;
		else
			mpts->mpts_peerswitch = 0;

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

	/*
	 * mpte should never be NULL except in a race with
	 * mptcp_subflow_del which doesn't hold socket lock across critical
	 * section. This upcall is made after releasing the socket lock.
	 * Interleaving of socket operations becomes possible therefore.
	 */
	if (mpte == NULL)
		return;

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
	int error = 0, wakeup = 0;
	u_int64_t mpt_dsn = 0;
	struct mptcb *mp_tp = mpte->mpte_mptcb;
	struct mbuf *mpt_mbuf = NULL;
	u_int64_t off = 0;
	struct mbuf *head, *tail;
	int tcp_zero_len_write = 0;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);
	mp_so = mpte->mpte_mppcb->mpp_socket;
	so = mpts->mpts_socket;

	DTRACE_MPTCP2(subflow__output, struct mptses *, mpte,
	    struct mptsub *, mpts);

	/* subflow socket is suspended? */
	if (mpts->mpts_flags & MPTSF_SUSPENDED) {
		mptcplog((LOG_ERR, "MPTCP Sender: %s mp_so 0x%llx cid %d is "
		    "flow controlled\n", __func__,
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so), mpts->mpts_connid),
		    MPTCP_SENDER_DBG, MPTCP_LOGLVL_ERR);
		goto out;
	}

	/* subflow socket is not MPTCP capable? */
	if (!(mpts->mpts_flags & MPTSF_MP_CAPABLE) &&
	    !(mpts->mpts_flags & MPTSF_MP_DEGRADED) &&
	    !(mpts->mpts_flags & MPTSF_FASTJ_SEND) &&
	    !(mpts->mpts_flags & MPTSF_TFO_REQD)) {
		mptcplog((LOG_ERR, "MPTCP Sender: %s mp_so 0x%llx cid %d not "
		    "MPTCP capable\n", __func__,
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so), mpts->mpts_connid),
		    MPTCP_SENDER_DBG, MPTCP_LOGLVL_ERR);
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

	if (mpts->mpts_flags & MPTSF_TFO_REQD) {
		mptcp_drop_tfo_data(mpte, mpts, &wakeup);
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
		if (((so->so_state & SS_ISCONNECTED) == 0) &&
		    (mpt_mbuf->m_next == NULL) &&
		    (so->so_flags1 & SOF1_PRECONNECT_DATA)) {
			/*
			 * If TFO, allow connection establishment with zero
			 * length write.
			 */
			tcp_zero_len_write = 1;
			goto zero_len_write;
		}
		mpt_mbuf = mpt_mbuf->m_next;
	}
	if (mpt_mbuf && (mpt_mbuf->m_pkthdr.pkt_flags & PKTF_MPTCP)) {
		mpt_dsn = mpt_mbuf->m_pkthdr.mp_dsn;
	} else {
		goto out;
	}

	MPT_LOCK(mp_tp);
	if (MPTCP_SEQ_LT(mpt_dsn, mp_tp->mpt_snduna)) {
		u_int64_t len = 0;
		len = mp_tp->mpt_snduna - mpt_dsn;
		MPT_UNLOCK(mp_tp);
		sbdrop(&mp_so->so_snd, (int)len);
		wakeup = 1;
		MPT_LOCK(mp_tp);
	}

	/*
	 * In degraded mode, we don't receive data acks, so force free
	 * mbufs less than snd_nxt
	 */
	if (mp_so->so_snd.sb_mb == NULL) {
		MPT_UNLOCK(mp_tp);
		goto out;
	}

	mpt_dsn = mp_so->so_snd.sb_mb->m_pkthdr.mp_dsn;
	if ((mpts->mpts_flags & MPTSF_MP_DEGRADED) &&
	    (mp_tp->mpt_flags & MPTCPF_POST_FALLBACK_SYNC) &&
	    MPTCP_SEQ_LT(mpt_dsn, mp_tp->mpt_sndnxt)) {
		u_int64_t len = 0;
		len = mp_tp->mpt_sndnxt - mpt_dsn;
		sbdrop(&mp_so->so_snd, (int)len);
		wakeup = 1;
		mp_tp->mpt_snduna = mp_tp->mpt_sndnxt;
	}

	if ((mpts->mpts_flags & MPTSF_MP_DEGRADED) &&
	    !(mp_tp->mpt_flags & MPTCPF_POST_FALLBACK_SYNC)) {
		mp_tp->mpt_flags |= MPTCPF_POST_FALLBACK_SYNC;
		so->so_flags1 |= SOF1_POST_FALLBACK_SYNC;
		if (mp_tp->mpt_flags & MPTCPF_RECVD_MPFAIL)
			mpts->mpts_sndnxt = mp_tp->mpt_dsn_at_csum_fail;
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
		sb_cc -= (size_t)off;
	} else {
		MPT_UNLOCK(mp_tp);
		goto out;
	}
	MPT_UNLOCK(mp_tp);

	mpt_mbuf = sb_mb;

	while (mpt_mbuf && ((mpt_mbuf->m_pkthdr.mp_rlen == 0) ||
	    (mpt_mbuf->m_pkthdr.mp_rlen <= (u_int32_t)off))) {
		off -= mpt_mbuf->m_pkthdr.mp_rlen;
		mpt_mbuf = mpt_mbuf->m_next;
	}
	if (mpts->mpts_flags & MPTSF_MP_DEGRADED)
		mptcplog((LOG_DEBUG, "MPTCP Sender: %s cid = %d "
		    "snduna = %llu sndnxt = %llu probe %d\n",
		    __func__, mpts->mpts_connid,
		    mp_tp->mpt_snduna, mpts->mpts_sndnxt,
		    mpts->mpts_probecnt),
		    MPTCP_SENDER_DBG, MPTCP_LOGLVL_LOG);

	VERIFY((mpt_mbuf == NULL) || (mpt_mbuf->m_pkthdr.pkt_flags & PKTF_MPTCP));

	head = tail = NULL;

	while (tot_sent < sb_cc) {
		struct mbuf *m;
		size_t mlen;

		mlen = mpt_mbuf->m_pkthdr.mp_rlen;
		mlen -= off;
		if (mlen == 0)
			goto out;

		if (mlen > sb_cc) {
			panic("%s: unexpected %lu %lu \n", __func__,
			    mlen, sb_cc);
		}

		m = m_copym_mode(mpt_mbuf, (int)off, mlen, M_DONTWAIT,
		    M_COPYM_MUST_COPY_HDR);
		if (m == NULL) {
			error = ENOBUFS;
			break;
		}

		/* Create a DSN mapping for the data (m_copym does it) */
		mpt_dsn = mpt_mbuf->m_pkthdr.mp_dsn;
		VERIFY(m->m_flags & M_PKTHDR);
		m->m_pkthdr.pkt_flags |= PKTF_MPTCP;
		m->m_pkthdr.pkt_flags &= ~PKTF_MPSO;
		m->m_pkthdr.mp_dsn = mpt_dsn + off;
		m->m_pkthdr.mp_rseq = mpts->mpts_rel_seq;
		m->m_pkthdr.mp_rlen = mlen;
		mpts->mpts_rel_seq += mlen;
		m->m_pkthdr.len = mlen;

		if (head == NULL) {
			 head = tail = m;
		} else {
			tail->m_next = m;
			tail = m;
		}

		tot_sent += mlen;
		off = 0;
		mpt_mbuf = mpt_mbuf->m_next;
	}

	if (head != NULL) {
		struct tcpcb *tp = intotcpcb(sotoinpcb(so));

		if ((mpts->mpts_flags & MPTSF_TFO_REQD) &&
		    (tp->t_tfo_stats == 0)) {
			tp->t_mpflags |= TMPF_TFO_REQUEST;
		} else if (mpts->mpts_flags & MPTSF_FASTJ_SEND) {
			tp->t_mpflags |= TMPF_FASTJOIN_SEND;
		}

		error = sock_sendmbuf(so, NULL, head, 0, NULL);

		DTRACE_MPTCP7(send, struct mbuf *, head, struct socket *, so,
		    struct sockbuf *, &so->so_rcv,
		    struct sockbuf *, &so->so_snd,
		    struct mptses *, mpte, struct mptsub *, mpts,
		    size_t, tot_sent);
	} else if (tcp_zero_len_write == 1) {
zero_len_write:
		socket_lock(so, 1);
		/* Opting to call pru_send as no mbuf at subflow level */
		error = (*so->so_proto->pr_usrreqs->pru_send)
		    (so, 0, NULL, NULL, NULL, current_proc());
		socket_unlock(so, 1);
	}

	if ((error == 0) || (error == EWOULDBLOCK)) {
		mpts->mpts_sndnxt += tot_sent;

		if (mpts->mpts_probesoon && mpts->mpts_maxseg && tot_sent) {
			tcpstat.tcps_mp_num_probes++;
			if (tot_sent < mpts->mpts_maxseg)
				mpts->mpts_probecnt += 1;
			else
				mpts->mpts_probecnt +=
				    tot_sent/mpts->mpts_maxseg;
		}

		MPT_LOCK(mp_tp);

		if (MPTCP_SEQ_LT(mp_tp->mpt_sndnxt, mpts->mpts_sndnxt)) {
			if (MPTCP_DATASEQ_HIGH32(mpts->mpts_sndnxt) >
			    MPTCP_DATASEQ_HIGH32(mp_tp->mpt_sndnxt))
				mp_tp->mpt_flags |= MPTCPF_SND_64BITDSN;
			mp_tp->mpt_sndnxt = mpts->mpts_sndnxt;
		}
		mptcp_cancel_timer(mp_tp, MPTT_REXMT);
		MPT_UNLOCK(mp_tp);

		if (so->so_flags1 & SOF1_PRECONNECT_DATA)
			so->so_flags1 &= ~SOF1_PRECONNECT_DATA;

		/* Send once in SYN_SENT state to avoid sending SYN spam */
		if (mpts->mpts_flags & MPTSF_FASTJ_SEND) {
			so->so_flags &= ~SOF_MPTCP_FASTJOIN;
			mpts->mpts_flags &= ~MPTSF_FASTJ_SEND;
		}

		if ((mpts->mpts_flags & MPTSF_MP_DEGRADED) ||
		    (mpts->mpts_probesoon != 0))
			mptcplog((LOG_DEBUG, "MPTCP Sender: %s cid %d "
			    "wrote %d %d probe %d probedelta %d\n",
			    __func__, mpts->mpts_connid, (int)tot_sent,
			    (int) sb_cc, mpts->mpts_probecnt,
			    (tcp_now - mpts->mpts_probesoon)),
			    MPTCP_SENDER_DBG, MPTCP_LOGLVL_LOG);
	} else {
		mptcplog((LOG_ERR, "MPTCP Sender: %s cid %d error %d len %zd\n",
		    __func__, mpts->mpts_connid, error, tot_sent),
		    MPTCP_SENDER_DBG, MPTCP_LOGLVL_ERR);
	}
out:
	if (wakeup)
		sowwakeup(mp_so);

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
mptcp_subflow_events(struct mptses *mpte, struct mptsub *mpts,
	uint64_t *p_mpsofilt_hint)
{
	uint32_t events, save_events;
	ev_ret_t ret = MPTS_EVRET_OK;
	int i = 0;
	int mpsub_ev_entry_count = sizeof(mpsub_ev_entry_tbl)/
		sizeof(mpsub_ev_entry_tbl[0]);
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

	save_events = events;

	DTRACE_MPTCP3(subflow__events, struct mptses *, mpte,
	    struct mptsub *, mpts, uint32_t, events);

	mptcplog((LOG_DEBUG, "MPTCP Events: %s cid %d events=%b\n", __func__,
	    mpts->mpts_connid, events, SO_FILT_HINT_BITS),
	    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_VERBOSE);

	/*
	 * Process all the socket filter hints and reset the hint
	 * once it is handled
	 */
	for (i = 0; (i < mpsub_ev_entry_count) && events; i++) {
		/*
		 * Always execute the DISCONNECTED event, because it will wakeup
		 * the app.
		 */
		if ((events & mpsub_ev_entry_tbl[i].sofilt_hint_mask) &&
		    (ret >= MPTS_EVRET_OK ||
		     mpsub_ev_entry_tbl[i].sofilt_hint_mask == SO_FILT_HINT_DISCONNECTED)) {
			ev_ret_t error =
				mpsub_ev_entry_tbl[i].sofilt_hint_ev_hdlr(mpte, mpts, p_mpsofilt_hint);
			events &= ~mpsub_ev_entry_tbl[i].sofilt_hint_mask;
			ret = ((error >= MPTS_EVRET_OK) ? MAX(error, ret) : error);
		}
	}

	/*
	 * We should be getting only events specified via sock_catchevents(),
	 * so loudly complain if we have any unprocessed one(s).
	 */
	if (events != 0 || ret < MPTS_EVRET_OK) {
		mptcplog((LOG_ERR, "MPTCP Events %s%s: cid %d evret %s (%d)"
		    " unhandled events=%b\n",
		    (events != 0) && (ret == MPTS_EVRET_OK) ? "MPTCP_ERROR " : "",
		    __func__, mpts->mpts_connid,
		    mptcp_evret2str(ret), ret, events, SO_FILT_HINT_BITS),
		    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_ERR);
	}

	/* clear the ones we've processed */
	atomic_bitclear_32(&mpts->mpts_evctl, save_events);
	return (ret);
}

/*
 * Handle SO_FILT_HINT_CONNRESET subflow socket event.
 */
static ev_ret_t
mptcp_subflow_connreset_ev(struct mptses *mpte, struct mptsub *mpts,
	uint64_t *p_mpsofilt_hint)
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

	mptcplog((LOG_DEBUG, "MPTCP Events: "
	    "%s: cid %d [linger %s]\n", __func__,
	    mpts->mpts_connid, (linger ? "YES" : "NO")),
	    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_LOG);

	/*
	 * We got a TCP RST for this subflow connection.
	 *
	 * Right now, we simply propagate ECONNREFUSED to the MPTCP socket
	 * client if the MPTCP connection has not been established or
	 * if the connection has only one subflow and is a connection being
	 * resumed. Otherwise we close the socket.
	 */
	mptcp_subflow_disconnect(mpte, mpts, !linger);

	MPT_LOCK(mp_tp);
	if (mp_tp->mpt_state < MPTCPS_ESTABLISHED) {
		mpts->mpts_soerror = mp_so->so_error = ECONNREFUSED;
	} else if (mpte->mpte_nummpcapflows < 1 ||
		   ((mp_tp->mpt_flags & MPTCPF_FALLBACK_TO_TCP) &&
		    (mpts->mpts_flags & MPTSF_ACTIVE))) {
		mpts->mpts_soerror = mp_so->so_error = ECONNRESET;
		*p_mpsofilt_hint |= SO_FILT_HINT_LOCKED | SO_FILT_HINT_CONNRESET;
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
mptcp_subflow_cantrcvmore_ev(struct mptses *mpte, struct mptsub *mpts,
	uint64_t *p_mpsofilt_hint)
{
	struct mptcb *mp_tp;
	struct socket *so;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);

	mp_tp = mpte->mpte_mptcb;
	so = mpts->mpts_socket;

	mptcplog((LOG_DEBUG, "MPTCP Events: "
	    "%s: cid %d\n", __func__, mpts->mpts_connid),
	    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_LOG);

	/*
	* A FIN on a fallen back MPTCP-connection should be treated like a
	* DATA_FIN.
	*/
	MPT_LOCK(mp_tp);
	if ((mp_tp->mpt_flags & MPTCPF_FALLBACK_TO_TCP) &&
	    (mpts->mpts_flags & MPTSF_ACTIVE)) {
		mptcp_close_fsm(mp_tp, MPCE_RECV_DATA_FIN);
		if (mp_tp->mpt_state == MPTCPS_CLOSE_WAIT) {
			*p_mpsofilt_hint |= SO_FILT_HINT_LOCKED | SO_FILT_HINT_CANTRCVMORE;
		}
	}
	MPT_UNLOCK(mp_tp);

	return (MPTS_EVRET_OK);	/* keep the subflow socket around */
}

/*
 * Handle SO_FILT_HINT_CANTSENDMORE subflow socket event.
 */
static ev_ret_t
mptcp_subflow_cantsendmore_ev(struct mptses *mpte, struct mptsub *mpts,
	uint64_t *p_mpsofilt_hint)
{
#pragma unused(p_mpsofilt_hint)
	struct socket *so;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);

	so = mpts->mpts_socket;

	mptcplog((LOG_DEBUG, "MPTCP Events: "
	    "%s: cid %d\n", __func__, mpts->mpts_connid),
	    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_LOG);

	return (MPTS_EVRET_OK);	/* keep the subflow socket around */
}

/*
 * Handle SO_FILT_HINT_TIMEOUT subflow socket event.
 */
static ev_ret_t
mptcp_subflow_timeout_ev(struct mptses *mpte, struct mptsub *mpts,
	uint64_t *p_mpsofilt_hint)
{
#pragma unused(p_mpsofilt_hint)
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

	mptcplog((LOG_NOTICE, "MPTCP Events: "
	    "%s: cid %d [linger %s]\n", __func__,
	    mpts->mpts_connid, (linger ? "YES" : "NO")),
	    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_LOG);

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
mptcp_subflow_nosrcaddr_ev(struct mptses *mpte, struct mptsub *mpts,
	uint64_t *p_mpsofilt_hint)
{
#pragma unused(p_mpsofilt_hint)
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

	mptcplog((LOG_DEBUG, "MPTCP Events: "
	    "%s cid %d [linger %s]\n", __func__,
	    mpts->mpts_connid, (linger ? "YES" : "NO")),
	    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_LOG);

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
 * Handle SO_FILT_HINT_MPCANTRCVMORE subflow socket event that
 * indicates that the remote side sent a Data FIN
 */
static ev_ret_t
mptcp_subflow_mpcantrcvmore_ev(struct mptses *mpte, struct mptsub *mpts,
	uint64_t *p_mpsofilt_hint)
{
	struct socket *so, *mp_so;
	struct mptcb *mp_tp;

	MPTE_LOCK_ASSERT_HELD(mpte);    /* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);
	mp_so = mpte->mpte_mppcb->mpp_socket;
	so = mpts->mpts_socket;
	mp_tp = mpte->mpte_mptcb;

	mptcplog((LOG_DEBUG, "MPTCP Events: "
	    "%s: cid %d\n", __func__, mpts->mpts_connid),
	    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_LOG);

	/*
	* We got a Data FIN for the MPTCP connection.
	* The FIN may arrive with data. The data is handed up to the
	* mptcp socket and the user is notified so that it may close
	* the socket if needed.
	*/
	MPT_LOCK(mp_tp);
	if (mp_tp->mpt_state == MPTCPS_CLOSE_WAIT)
		*p_mpsofilt_hint |= SO_FILT_HINT_LOCKED | SO_FILT_HINT_CANTRCVMORE;

	MPT_UNLOCK(mp_tp);
	return (MPTS_EVRET_OK); /* keep the subflow socket around */
}

/*
 * Handle SO_FILT_HINT_MPFAILOVER subflow socket event
 */
static ev_ret_t
mptcp_subflow_failover_ev(struct mptses *mpte, struct mptsub *mpts,
	uint64_t *p_mpsofilt_hint)
{
	struct mptsub *mpts_alt = NULL;
	struct socket *so = NULL;
	struct socket *mp_so;
	int altpath_exists = 0;

	MPTE_LOCK_ASSERT_HELD(mpte);    /* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);
	mp_so = mpte->mpte_mppcb->mpp_socket;
	mptcplog((LOG_NOTICE, "MPTCP Events: "
	    "%s: mp_so 0x%llx\n", __func__,
	    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so)),
	    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_LOG);

	MPTS_UNLOCK(mpts);
	mpts_alt = mptcp_get_subflow(mpte, mpts, NULL);

	/*
	 * If there is no alternate eligible subflow, ignore the
	 * failover hint.
	 */
	if (mpts_alt == NULL) {
		mptcplog((LOG_WARNING, "MPTCP Events: "
		    "%s: no alternate path\n", __func__),
		    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_ERR);

		if (mptcp_delayed_subf_start) {
			mpts_alt = mptcp_get_pending_subflow(mpte, mpts);
			if (mpts_alt != NULL) {
				MPTS_LOCK(mpts_alt);
				(void) mptcp_subflow_soconnectx(mpte,
				    mpts_alt);
				MPTS_UNLOCK(mpts_alt);
			}
		}
		MPTS_LOCK(mpts);
		goto done;
	}
	MPTS_LOCK(mpts_alt);
	altpath_exists = 1;
	so = mpts_alt->mpts_socket;
	if (mpts_alt->mpts_flags & MPTSF_FAILINGOVER) {
		socket_lock(so, 1);
		/* All data acknowledged and no RTT spike */
		if ((so->so_snd.sb_cc == 0) &&
		    (mptcp_no_rto_spike(so))) {
			so->so_flags &= ~SOF_MP_TRYFAILOVER;
			mpts_alt->mpts_flags &= ~MPTSF_FAILINGOVER;
		} else {
			/* no alternate path available */
			altpath_exists = 0;
		}
		socket_unlock(so, 1);
	}
	if (altpath_exists) {
		mptcplog((LOG_INFO, "MPTCP Events: "
		    "%s: cid = %d\n",
		    __func__, mpts_alt->mpts_connid),
		    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_LOG);
		mpts_alt->mpts_flags |= MPTSF_ACTIVE;
		mpts_alt->mpts_peerswitch = 0;
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
		*p_mpsofilt_hint |= SO_FILT_HINT_LOCKED | SO_FILT_HINT_CONNINFO_UPDATED;
		mptcplog((LOG_NOTICE, "MPTCP Events: "
		    "%s: mp_so 0x%llx switched from "
		    "%d to %d\n", __func__,
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
		    mpts->mpts_connid, mpts_alt->mpts_connid),
		    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_LOG);
		tcpstat.tcps_mp_switches++;
	}

	MPTS_LOCK(mpts);
	if (altpath_exists) {
		mpts->mpts_flags |= MPTSF_FAILINGOVER;
		mpts->mpts_flags &= ~MPTSF_ACTIVE;
	} else {
		mptcplog((LOG_DEBUG, "MPTCP Events %s: no alt cid = %d\n",
		    __func__, mpts->mpts_connid),
		    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_LOG);
done:
		so = mpts->mpts_socket;
		socket_lock(so, 1);
		so->so_flags &= ~SOF_MP_TRYFAILOVER;
		socket_unlock(so, 1);
	}
	MPTS_LOCK_ASSERT_HELD(mpts);
	return (MPTS_EVRET_OK);
}

/*
 * Handle SO_FILT_HINT_IFDENIED subflow socket event.
 */
static ev_ret_t
mptcp_subflow_ifdenied_ev(struct mptses *mpte, struct mptsub *mpts,
	uint64_t *p_mpsofilt_hint)
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

	mptcplog((LOG_DEBUG, "MPTCP Events: "
	    "%s: cid %d [linger %s]\n", __func__,
	    mpts->mpts_connid, (linger ? "YES" : "NO")),
	    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_LOG);

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
	*p_mpsofilt_hint |= SO_FILT_HINT_LOCKED | SO_FILT_HINT_IFDENIED;

	MPT_LOCK(mp_tp);
	if (mp_tp->mpt_state < MPTCPS_ESTABLISHED) {
		mp_so->so_error = EHOSTUNREACH;
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
 * Handle SO_FILT_HINT_SUSPEND subflow socket event.
 */
static ev_ret_t
mptcp_subflow_suspend_ev(struct mptses *mpte, struct mptsub *mpts,
	uint64_t *p_mpsofilt_hint)
{
#pragma unused(p_mpsofilt_hint)
	struct socket *so;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);

	so = mpts->mpts_socket;

	/* the subflow connection is being flow controlled */
	mpts->mpts_flags |= MPTSF_SUSPENDED;

	mptcplog((LOG_DEBUG, "MPTCP Events: "
	    "%s: cid %d\n", __func__,
	    mpts->mpts_connid), MPTCP_EVENTS_DBG, MPTCP_LOGLVL_LOG);

	return (MPTS_EVRET_OK);	/* keep the subflow socket around */
}

/*
 * Handle SO_FILT_HINT_RESUME subflow socket event.
 */
static ev_ret_t
mptcp_subflow_resume_ev(struct mptses *mpte, struct mptsub *mpts,
	uint64_t *p_mpsofilt_hint)
{
#pragma unused(p_mpsofilt_hint)
	struct socket *so;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);

	so = mpts->mpts_socket;

	/* the subflow connection is no longer flow controlled */
	mpts->mpts_flags &= ~MPTSF_SUSPENDED;

	mptcplog((LOG_DEBUG, "MPTCP Events: "
	    "%s: cid %d\n", __func__, mpts->mpts_connid),
	    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_LOG);

	return (MPTS_EVRET_OK);	/* keep the subflow socket around */
}

/*
 * Handle SO_FILT_HINT_CONNECTED subflow socket event.
 */
static ev_ret_t
mptcp_subflow_connected_ev(struct mptses *mpte, struct mptsub *mpts,
	uint64_t *p_mpsofilt_hint)
{
	char buf0[MAX_IPv6_STR_LEN], buf1[MAX_IPv6_STR_LEN];
	struct sockaddr_storage src;
	struct socket *mp_so, *so;
	struct mptcb *mp_tp;
	struct ifnet *outifp;
	int af, error = 0;
	boolean_t mpok = FALSE;
	boolean_t cell = FALSE;
	boolean_t wifi = FALSE;
	boolean_t wired = FALSE;

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
		socket_lock(so, 0);
		if (!(so->so_state & (SS_ISDISCONNECTING | SS_ISDISCONNECTED)) &&
		    (so->so_state & SS_ISCONNECTED)) {
		    mptcplog((LOG_DEBUG, "MPTCP Events: "
		        "%s: cid %d disconnect before tcp connect\n",
		        __func__, mpts->mpts_connid),
			MPTCP_EVENTS_DBG, MPTCP_LOGLVL_LOG);
			(void) soshutdownlock(so, SHUT_RD);
			(void) soshutdownlock(so, SHUT_WR);
			(void) sodisconnectlocked(so);
		}
		socket_unlock(so, 0);
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

	if (!(so->so_flags1 & SOF1_DATA_IDEMPOTENT))
		mpts->mpts_flags &= ~MPTSF_TFO_REQD;

	struct tcpcb *tp = sototcpcb(so);
	if (tp->t_mpflags & TMPF_MPTCP_TRUE)
		mpts->mpts_flags |= MPTSF_MP_CAPABLE;

	tp->t_mpflags &= ~TMPF_TFO_REQUEST;

	VERIFY(mpts->mpts_dst != NULL);

	VERIFY(mpts->mpts_src != NULL);

	/* get/check source IP address */
	switch (af) {
	case AF_INET: {
		error = in_getsockaddr_s(so, &src);
		if (error == 0) {
			struct sockaddr_in *ms = SIN(mpts->mpts_src);
			struct sockaddr_in *s = SIN(&src);

			VERIFY(s->sin_len == ms->sin_len);
			VERIFY(ms->sin_family == AF_INET);

			if ((mpts->mpts_flags & MPTSF_BOUND_IP) &&
			    bcmp(&ms->sin_addr, &s->sin_addr,
			    sizeof (ms->sin_addr)) != 0) {
				mptcplog((LOG_ERR, "MPTCP Events: "
				    "%s: cid %d local "
				    "address %s (expected %s)\n", __func__,
				    mpts->mpts_connid, inet_ntop(AF_INET,
				    (void *)&s->sin_addr.s_addr, buf0,
				    sizeof (buf0)), inet_ntop(AF_INET,
				    (void *)&ms->sin_addr.s_addr, buf1,
				    sizeof (buf1))),
				    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_ERR);
			}
			bcopy(s, ms, sizeof (*s));
		}
		break;
	}
#if INET6
	case AF_INET6: {
		error = in6_getsockaddr_s(so, &src);
		if (error == 0) {
			struct sockaddr_in6 *ms = SIN6(mpts->mpts_src);
			struct sockaddr_in6 *s = SIN6(&src);

			VERIFY(s->sin6_len == ms->sin6_len);
			VERIFY(ms->sin6_family == AF_INET6);

			if ((mpts->mpts_flags & MPTSF_BOUND_IP) &&
			    bcmp(&ms->sin6_addr, &s->sin6_addr,
			    sizeof (ms->sin6_addr)) != 0) {
				mptcplog((LOG_ERR, "MPTCP Events: "
				    "%s: cid %d local "
				    "address %s (expected %s)\n", __func__,
				    mpts->mpts_connid, inet_ntop(AF_INET6,
				    (void *)&s->sin6_addr, buf0,
				    sizeof (buf0)), inet_ntop(AF_INET6,
				    (void *)&ms->sin6_addr, buf1,
				    sizeof (buf1))),
				    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_ERR);
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
		mptcplog((LOG_ERR, "MPTCP Events "
		    "%s: cid %d getsockaddr failed (%d)\n",
		    __func__, mpts->mpts_connid, error),
		    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_ERR);
	}

	/* get/verify the outbound interface */
	outifp = sotoinpcb(so)->inp_last_outifp;	/* could be NULL */
	if (mpts->mpts_flags & MPTSF_BOUND_IF) {
		VERIFY(mpts->mpts_outif != NULL);
		if (mpts->mpts_outif != outifp) {
			mptcplog((LOG_ERR, "MPTCP Events: %s: cid %d outif %s "
			    "(expected %s)\n", __func__, mpts->mpts_connid,
			    ((outifp != NULL) ? outifp->if_xname : "NULL"),
			    mpts->mpts_outif->if_xname),
			    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_ERR);

			if (outifp == NULL)
				outifp = mpts->mpts_outif;
		}
	} else {
		mpts->mpts_outif = outifp;
	}

	mpts->mpts_srtt = (intotcpcb(sotoinpcb(so)))->t_srtt;
	mpts->mpts_rxtcur = (intotcpcb(sotoinpcb(so)))->t_rxtcur;
	mpts->mpts_maxseg = (intotcpcb(sotoinpcb(so)))->t_maxseg;

	cell = IFNET_IS_CELLULAR(mpts->mpts_outif);
	wifi = (!cell && IFNET_IS_WIFI(mpts->mpts_outif));
	wired = (!wifi && IFNET_IS_WIRED(mpts->mpts_outif));

	if (cell)
		mpts->mpts_linktype |= MPTSL_CELL;
	else if (wifi)
		mpts->mpts_linktype |= MPTSL_WIFI;
	else if (wired)
		mpts->mpts_linktype |= MPTSL_WIRED;

	socket_unlock(so, 0);

	mptcplog((LOG_DEBUG, "MPTCP Sender: %s: cid %d "
	    "establishment srtt %d \n", __func__,
	    mpts->mpts_connid, (mpts->mpts_srtt >> 5)),
	    MPTCP_SENDER_DBG, MPTCP_LOGLVL_LOG);


	mptcplog((LOG_DEBUG, "MPTCP Socket: "
	    "%s: cid %d outif %s %s[%d] -> %s[%d] "
	    "is %s\n", __func__, mpts->mpts_connid, ((outifp != NULL) ?
	    outifp->if_xname : "NULL"), inet_ntop(af, (af == AF_INET) ?
	    (void *)&SIN(mpts->mpts_src)->sin_addr.s_addr :
	    (void *)&SIN6(mpts->mpts_src)->sin6_addr, buf0, sizeof (buf0)),
	    ((af == AF_INET) ? ntohs(SIN(mpts->mpts_src)->sin_port) :
	    ntohs(SIN6(mpts->mpts_src)->sin6_port)),
	    inet_ntop(af, ((af == AF_INET) ?
	    (void *)&SIN(mpts->mpts_dst)->sin_addr.s_addr :
	    (void *)&SIN6(mpts->mpts_dst)->sin6_addr), buf1, sizeof (buf1)),
	    ((af == AF_INET) ? ntohs(SIN(mpts->mpts_dst)->sin_port) :
	    ntohs(SIN6(mpts->mpts_dst)->sin6_port)),
	    ((mpts->mpts_flags & MPTSF_MP_CAPABLE) ?
	    "MPTCP capable" : "a regular TCP")),
	    (MPTCP_SOCKET_DBG | MPTCP_EVENTS_DBG), MPTCP_LOGLVL_LOG);

	mpok = (mpts->mpts_flags & MPTSF_MP_CAPABLE);
	MPTS_UNLOCK(mpts);

	*p_mpsofilt_hint |= SO_FILT_HINT_LOCKED | SO_FILT_HINT_CONNINFO_UPDATED;

	MPT_LOCK(mp_tp);
	if (mp_tp->mpt_state < MPTCPS_ESTABLISHED) {
		/* case (a) above */
		if (!mpok) {
			mp_tp->mpt_flags |= MPTCPF_PEEL_OFF;
			(void) mptcp_drop(mpte, mp_tp, EPROTO);
			MPT_UNLOCK(mp_tp);
		} else {
			MPT_UNLOCK(mp_tp);
			mptcplog((LOG_DEBUG, "MPTCP State: "
			    "MPTCPS_ESTABLISHED for mp_so 0x%llx \n",
			    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so)),
			    MPTCP_STATE_DBG, MPTCP_LOGLVL_LOG);
			mp_tp->mpt_state = MPTCPS_ESTABLISHED;
			mpte->mpte_associd = mpts->mpts_connid;
			DTRACE_MPTCP2(state__change,
			    struct mptcb *, mp_tp,
			    uint32_t, 0 /* event */);

			if (mpts->mpts_outif &&
			    IFNET_IS_EXPENSIVE(mpts->mpts_outif)) {
				sototcpcb(so)->t_mpflags |= (TMPF_BACKUP_PATH | TMPF_SND_MPPRIO);
			} else {
				mpts->mpts_flags |= MPTSF_PREFERRED;
			}
			mpts->mpts_flags |= MPTSF_ACTIVE;
			soisconnected(mp_so);
		}
		MPTS_LOCK(mpts);
		if (mpok) {
			mpts->mpts_flags |= MPTSF_MPCAP_CTRSET;
			mpte->mpte_nummpcapflows++;
			MPT_LOCK_SPIN(mp_tp);
			/* With TFO, sndnxt may be initialized earlier */
			if (mpts->mpts_sndnxt == 0)
				mpts->mpts_sndnxt = mp_tp->mpt_snduna;
			MPT_UNLOCK(mp_tp);
		}
	} else if (mpok) {
		MPT_UNLOCK(mp_tp);
		if (mptcp_rwnotify && (mpte->mpte_nummpcapflows == 0)) {
			/* Experimental code, disabled by default. */
			sorwakeup(mp_so);
			sowwakeup(mp_so);
		}
		/*
		 * case (b) above
		 * In case of additional flows, the MPTCP socket is not
		 * MPTSF_MP_CAPABLE until an ACK is received from server
		 * for 3-way handshake.  TCP would have guaranteed that this
		 * is an MPTCP subflow.
		 */
		MPTS_LOCK(mpts);
		mpts->mpts_flags |= MPTSF_MPCAP_CTRSET;
		mpts->mpts_flags &= ~MPTSF_FASTJ_REQD;
		mpte->mpte_nummpcapflows++;
		MPT_LOCK_SPIN(mp_tp);
		/* With Fastjoin, sndnxt is updated before connected_ev */
		if (mpts->mpts_sndnxt == 0) {
			mpts->mpts_sndnxt = mp_tp->mpt_snduna;
			mpts->mpts_rel_seq = 1;
		}
		MPT_UNLOCK(mp_tp);
		mptcp_output_needed(mpte, mpts);
	} else {
		MPT_UNLOCK(mp_tp);
		MPTS_LOCK(mpts);
	}

	MPTS_LOCK_ASSERT_HELD(mpts);

	return (MPTS_EVRET_OK);	/* keep the subflow socket around */
}

/*
 * Handle SO_FILT_HINT_DISCONNECTED subflow socket event.
 */
static ev_ret_t
mptcp_subflow_disconnected_ev(struct mptses *mpte, struct mptsub *mpts,
	uint64_t *p_mpsofilt_hint)
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

	mptcplog((LOG_DEBUG, "MPTCP Events: "
	    "%s: cid %d [linger %s]\n", __func__,
	    mpts->mpts_connid, (linger ? "YES" : "NO")),
	    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_LOG);

	if (mpts->mpts_flags & MPTSF_DISCONNECTED)
		return (linger ? MPTS_EVRET_OK : MPTS_EVRET_DELETE);

	/*
	 * Clear flags that are used by getconninfo to return state.
	 * Retain like MPTSF_DELETEOK for internal purposes.
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
	*p_mpsofilt_hint |= SO_FILT_HINT_LOCKED | SO_FILT_HINT_CONNINFO_UPDATED;

	if (mpts->mpts_flags & MPTSF_MPCAP_CTRSET) {
		mpte->mpte_nummpcapflows--;
		if (mpte->mpte_active_sub == mpts) {
			mpte->mpte_active_sub = NULL;
			mptcplog((LOG_DEBUG, "MPTCP Events: "
			    "%s: resetting active subflow \n",
			    __func__), MPTCP_EVENTS_DBG, MPTCP_LOGLVL_LOG);
		}
		mpts->mpts_flags &= ~MPTSF_MPCAP_CTRSET;
	}

	MPT_LOCK(mp_tp);
	if (mp_tp->mpt_state < MPTCPS_ESTABLISHED) {
		MPT_UNLOCK(mp_tp);
		MPTS_UNLOCK(mpts);
		soisdisconnected(mp_so);
		MPTS_LOCK(mpts);
	} else {
		MPT_UNLOCK(mp_tp);
	}

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
mptcp_subflow_mpstatus_ev(struct mptses *mpte, struct mptsub *mpts,
		uint64_t *p_mpsofilt_hint)
{
	struct socket *mp_so, *so;
	struct mptcb *mp_tp;
	ev_ret_t ret = MPTS_EVRET_OK;

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
		*p_mpsofilt_hint |= SO_FILT_HINT_LOCKED |
			SO_FILT_HINT_CONNINFO_UPDATED;
	} else if (mpts->mpts_flags & MPTSF_MP_READY) {
		mp_tp->mpt_flags |= MPTCPF_JOIN_READY;
		ret = MPTS_EVRET_CONNECT_PENDING;
	} else {
		*p_mpsofilt_hint |= SO_FILT_HINT_LOCKED |
			SO_FILT_HINT_CONNINFO_UPDATED;
	}

	mptcplog((LOG_DEBUG, "MPTCP Events: "
	    "%s: mp_so 0x%llx mpt_flags=%b cid %d "
	    "mptsf=%b\n", __func__,
	    (u_int64_t)VM_KERNEL_ADDRPERM(mpte->mpte_mppcb->mpp_socket),
	    mp_tp->mpt_flags, MPTCPF_BITS, mpts->mpts_connid,
	    mpts->mpts_flags, MPTSF_BITS),
	    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_LOG);

done:
	MPT_UNLOCK(mp_tp);
	socket_unlock(so, 0);
	return (ret);
}

/*
 * Handle SO_FILT_HINT_MUSTRST subflow socket event
 */
static ev_ret_t
mptcp_subflow_mustrst_ev(struct mptses *mpte, struct mptsub *mpts,
	uint64_t *p_mpsofilt_hint)
{
	struct socket *mp_so, *so;
	struct mptcb *mp_tp;
	boolean_t linger, is_fastclose;


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

	/* We got an invalid option or a fast close */
	socket_lock(so, 0);
	struct tcptemp *t_template;
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp = NULL;

	tp = intotcpcb(inp);
	so->so_error = ECONNABORTED;

	is_fastclose = !!(tp->t_mpflags & TMPF_FASTCLOSERCV);

	t_template = tcp_maketemplate(tp);
	if (t_template) {
		struct tcp_respond_args tra;

		bzero(&tra, sizeof(tra));
		if (inp->inp_flags & INP_BOUND_IF)
			tra.ifscope = inp->inp_boundifp->if_index;
		else
			tra.ifscope = IFSCOPE_NONE;
		tra.awdl_unrestricted = 1;

		tcp_respond(tp, t_template->tt_ipgen,
		    &t_template->tt_t, (struct mbuf *)NULL,
		    tp->rcv_nxt, tp->snd_una, TH_RST, &tra);
		(void) m_free(dtom(t_template));
		mptcplog((LOG_DEBUG, "MPTCP Events: "
		    "%s: mp_so 0x%llx cid %d \n",
		    __func__, (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
		    so, mpts->mpts_connid),
		    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_LOG);
	}
	socket_unlock(so, 0);
	mptcp_subflow_disconnect(mpte, mpts, !linger);

	*p_mpsofilt_hint |=  (SO_FILT_HINT_LOCKED | SO_FILT_HINT_CONNINFO_UPDATED);

	MPT_LOCK(mp_tp);

	if (!(mp_tp->mpt_flags & MPTCPF_FALLBACK_TO_TCP) && is_fastclose) {
		*p_mpsofilt_hint |= SO_FILT_HINT_CONNRESET;

		if (mp_tp->mpt_state < MPTCPS_ESTABLISHED)
			mp_so->so_error = ECONNABORTED;
		else
			mp_so->so_error = ECONNRESET;

		/*
		 * mptcp_drop is being called after processing the events, to fully
		 * close the MPTCP connection
		 */
	}

	if (mp_tp->mpt_gc_ticks == MPT_GC_TICKS)
		mp_tp->mpt_gc_ticks = MPT_GC_TICKS_FAST;
	MPT_UNLOCK(mp_tp);

	/*
	 * Keep the subflow socket around unless the subflow has been
	 * disconnected explicitly.
	 */
	return (linger ? MPTS_EVRET_OK : MPTS_EVRET_DELETE);
}

static ev_ret_t
mptcp_fastjoin_ev(struct mptses *mpte, struct mptsub *mpts,
	uint64_t *p_mpsofilt_hint)
{
#pragma unused(p_mpsofilt_hint)
	MPTE_LOCK_ASSERT_HELD(mpte);    /* same as MP socket lock */
	MPTS_LOCK_ASSERT_HELD(mpts);
	VERIFY(mpte->mpte_mppcb != NULL);

	if (mpte->mpte_nummpcapflows == 0) {
		struct mptcb *mp_tp = mpte->mpte_mptcb;
		mptcplog((LOG_DEBUG,"MPTCP Events: %s: %llx %llx \n",
		    __func__, mp_tp->mpt_snduna, mpts->mpts_sndnxt),
		    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_LOG);

		mpte->mpte_active_sub = mpts;
		mpts->mpts_flags |= (MPTSF_FASTJ_SEND | MPTSF_ACTIVE);
		MPT_LOCK(mp_tp);
		/*
		 * If mptcp_subflow_output is called before fastjoin_ev
		 * then mpts->mpts_sndnxt is initialized to mp_tp->mpt_snduna
		 * and further mpts->mpts_sndnxt is incremented by len copied.
		 */
		if (mpts->mpts_sndnxt == 0) {
			mpts->mpts_sndnxt = mp_tp->mpt_snduna;
		}
		MPT_UNLOCK(mp_tp);
	}

	return (MPTS_EVRET_OK);
}

static ev_ret_t
mptcp_deleteok_ev(struct mptses *mpte, struct mptsub *mpts,
	uint64_t *p_mpsofilt_hint)
{
#pragma unused(p_mpsofilt_hint)
	MPTE_LOCK_ASSERT_HELD(mpte);
	MPTS_LOCK_ASSERT_HELD(mpts);
	VERIFY(mpte->mpte_mppcb != NULL);

	mptcplog((LOG_DEBUG, "MPTCP Events: "
	    "%s cid %d\n", __func__, mpts->mpts_connid),
	    MPTCP_EVENTS_DBG, MPTCP_LOGLVL_LOG);

	mpts->mpts_flags |= MPTSF_DELETEOK;
	if (mpts->mpts_flags & MPTSF_DISCONNECTED)
		return (MPTS_EVRET_DELETE);
	else
		return (MPTS_EVRET_OK);
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
	default:
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
		mptcplog((LOG_DEBUG, "MPTCP Socket: "
		    "%s: mp_so 0x%llx sopt %s "
		    "val %d set successful\n", __func__,
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
		    mptcp_sopt2str(mpo->mpo_level, mpo->mpo_name,
		    buf, sizeof (buf)), mpo->mpo_intval),
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_VERBOSE);
	} else {
		mptcplog((LOG_ERR, "MPTCP Socket: "
		    "%s: mp_so 0x%llx sopt %s "
		    "val %d set error %d\n", __func__,
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
		    mptcp_sopt2str(mpo->mpo_level, mpo->mpo_name,
		    buf, sizeof (buf)), mpo->mpo_intval, error),
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_VERBOSE);
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
		mptcplog((LOG_DEBUG, "MPTCP Socket: "
		    "%s: mp_so 0x%llx sopt %s "
		    "val %d get successful\n", __func__,
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
		    mptcp_sopt2str(mpo->mpo_level, mpo->mpo_name,
		    buf, sizeof (buf)), mpo->mpo_intval),
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_VERBOSE);
	} else {
		mptcplog((LOG_ERR, "MPTCP Socket: "
		    "%s: mp_so 0x%llx sopt %s get error %d\n",
		    __func__, (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
		    mptcp_sopt2str(mpo->mpo_level,
		    mpo->mpo_name, buf, sizeof (buf)), error),
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
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

		mptcplog((LOG_DEBUG, "MPTCP Socket: "
		    "%s: mp_so 0x%llx found "
		    "(u=%d,r=%d,s=%d)\n", __func__,
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so), mp_so->so_usecount,
		    mp_so->so_retaincnt, mpp->mpp_state),
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_VERBOSE);

		if (!lck_mtx_try_lock(&mpp->mpp_lock)) {
			mptcplog((LOG_DEBUG, "MPTCP Socket: "
			    "%s: mp_so 0x%llx skipped "
			    "(u=%d,r=%d)\n", __func__,
			    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
			    mp_so->so_usecount, mp_so->so_retaincnt),
			    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_VERBOSE);
			active++;
			continue;
		}

		/* check again under the lock */
		if (mp_so->so_usecount > 1) {
			boolean_t wakeup = FALSE;
			struct mptsub *mpts, *tmpts;

			mptcplog((LOG_DEBUG, "MPTCP Socket: "
			    "%s: mp_so 0x%llx skipped "
			    "[u=%d,r=%d] %d %d\n", __func__,
			    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
			    mp_so->so_usecount, mp_so->so_retaincnt,
			    mp_tp->mpt_gc_ticks,
			    mp_tp->mpt_state),
			    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_VERBOSE);

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
			mptcplog((LOG_DEBUG, "MPTCP Socket: "
			    "%s: mp_so 0x%llx skipped "
			    "[u=%d,r=%d,s=%d]\n", __func__,
			    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
			    mp_so->so_usecount, mp_so->so_retaincnt,
			    mpp->mpp_state),
			    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_VERBOSE);
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
			mptcplog((LOG_DEBUG, "MPTCP Socket: "
			    "%s: mp_so 0x%llx scheduled for "
			    "termination [u=%d,r=%d]\n", __func__,
			    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
			    mp_so->so_usecount, mp_so->so_retaincnt),
			    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_VERBOSE);

			/* signal MPTCP thread to terminate */
			mptcp_thread_terminate_signal(mpte);
			lck_mtx_unlock(&mpp->mpp_lock);
			active++;
			continue;
		}

		mptcplog((LOG_DEBUG, "MPTCP Socket: "
		    "%s: mp_so 0x%llx destroyed [u=%d,r=%d]\n",
		    __func__, (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
		    mp_so->so_usecount, mp_so->so_retaincnt),
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_VERBOSE);

		DTRACE_MPTCP4(dispose, struct socket *, mp_so,
		    struct sockbuf *, &mp_so->so_rcv,
		    struct sockbuf *, &mp_so->so_snd,
		    struct mppcb *, mpp);

		mp_pcbdispose(mpp);
		sodealloc(mp_so);
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

	mp_tp->mpt_state = MPTCPS_TERMINATE;
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
	struct socket *mp_so = NULL;
	struct mptsub *mpts = NULL, *tmpts = NULL;

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
		mpts->mpts_flags |= MPTSF_USER_DISCONNECT;
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
	uint64_t mpsofilt_hint_mask = 0;

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

		mptcp_get_rtt_measurement(mpts, mpte);

		ret = mptcp_subflow_events(mpte, mpts, &mpsofilt_hint_mask);

		if (mpts->mpts_flags & MPTSF_ACTIVE) {
			mptcplog((LOG_DEBUG, "MPTCP Socket: "
			    "%s: cid %d \n", __func__,
			    mpts->mpts_connid),
			    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_VERBOSE);
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
		case MPTS_EVRET_OK:
			/* nothing to do */
			break;
		case MPTS_EVRET_DELETE:
			mptcp_subflow_del(mpte, mpts, TRUE);
			break;
		case MPTS_EVRET_CONNECT_PENDING:
			connect_pending = TRUE;
			break;
		case MPTS_EVRET_DISCONNECT_FALLBACK:
			disconnect_fallback = TRUE;
			break;
		default:
			mptcplog((LOG_DEBUG,
			    "MPTCP Socket: %s: mptcp_subflow_events "
			    "returned invalid value: %d\n",  __func__,
			    ret),
			    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_VERBOSE);
			break;
		}
		MPTS_REMREF(mpts);		/* ours */
	}

	if (mpsofilt_hint_mask) {
		if (mpsofilt_hint_mask & SO_FILT_HINT_CANTRCVMORE) {
			socantrcvmore(mp_so);
			mpsofilt_hint_mask &= ~SO_FILT_HINT_CANTRCVMORE;
		}

		if (mpsofilt_hint_mask & SO_FILT_HINT_CONNRESET) {
			struct mptcb *mp_tp = mpte->mpte_mptcb;

			MPT_LOCK(mp_tp);
			mptcp_drop(mpte, mp_tp, ECONNRESET);
			MPT_UNLOCK(mp_tp);
		}

		soevent(mp_so, mpsofilt_hint_mask);
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
			    MPTSF_DISCONNECTED|MPTSF_CONNECT_PENDING)) {
				MPTS_UNLOCK(mpts);
				continue;
			}

			if (mpts->mpts_flags & MPTSF_TFO_REQD)
				mptcp_drop_tfo_data(mpte, mpts, NULL);

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
			 * If delayed subflow start is set and cellular,
			 * delay the connect till a retransmission timeout
			 */

			if ((mptcp_delayed_subf_start) &&
			    (IFNET_IS_CELLULAR(mpts->mpts_outif))) {
				MPTS_UNLOCK(mpts);
				continue;
			}

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
	VERIFY(mp_so->so_usecount > 0);
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
    uint8_t addr_id)
{
	struct tcpcb *tp = sototcpcb(so);
	struct mptcp_subf_auth_entry *sauth_entry;
	MPT_LOCK_ASSERT_NOTHELD(mp_tp);

	MPT_LOCK_SPIN(mp_tp);
	tp->t_mptcb = mp_tp;
	/*
	 * The address ID of the first flow is implicitly 0.
	 */
	if (mp_tp->mpt_state == MPTCPS_CLOSED) {
		tp->t_local_aid = 0;
	} else {
		tp->t_local_aid = addr_id;
		tp->t_mpflags |= (TMPF_PREESTABLISHED | TMPF_JOINED_FLOW);
		so->so_flags |= SOF_MP_SEC_SUBFLOW;
	}
	MPT_UNLOCK(mp_tp);
	sauth_entry = zalloc(mpt_subauth_zone);
	sauth_entry->msae_laddr_id = tp->t_local_aid;
	sauth_entry->msae_raddr_id = 0;
	sauth_entry->msae_raddr_rand = 0;
try_again:
	sauth_entry->msae_laddr_rand = RandomULong();
	if (sauth_entry->msae_laddr_rand == 0)
		goto try_again;
	MPT_LOCK_SPIN(mp_tp);
	LIST_INSERT_HEAD(&mp_tp->mpt_subauth_list, sauth_entry, msae_next);
	MPT_UNLOCK(mp_tp);
}

static void
mptcp_detach_mptcb_from_subf(struct mptcb *mp_tp, struct socket *so)
{
	struct mptcp_subf_auth_entry *sauth_entry;
	struct tcpcb *tp = NULL;
	int found = 0;

	socket_lock(so, 0);
	tp = sototcpcb(so);
	if (tp == NULL) {
		socket_unlock(so, 0);
		return;
	}

	MPT_LOCK(mp_tp);
	LIST_FOREACH(sauth_entry, &mp_tp->mpt_subauth_list, msae_next) {
		if (sauth_entry->msae_laddr_id == tp->t_local_aid) {
			found = 1;
			break;
		}
	}
	if (found) {
		LIST_REMOVE(sauth_entry, msae_next);
	}
	MPT_UNLOCK(mp_tp);

	if (found)
		zfree(mpt_subauth_zone, sauth_entry);

	tp->t_mptcb = NULL;
	socket_unlock(so, 0);
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
				mptcplog((LOG_ERR, "MPTCP Socket: %s mismatched"
				    " address ids %d %d \n", __func__, raddr_id,
				    sauth_entry->msae_raddr_id),
				    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_LOG);
				MPT_UNLOCK(mp_tp);
				return;
			}
			sauth_entry->msae_raddr_id = raddr_id;
			if ((sauth_entry->msae_raddr_rand != 0) &&
			    (sauth_entry->msae_raddr_rand != raddr_rand)) {
				mptcplog((LOG_ERR, "MPTCP Socket: "
				    "%s: dup SYN_ACK %d %d \n",
				    __func__, raddr_rand,
				    sauth_entry->msae_raddr_rand),
				    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_LOG);
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
void
mptcp_generate_token(char *sha_digest, int sha_digest_len, caddr_t token,
    int token_len)
{
	VERIFY(token_len == sizeof (u_int32_t));
	VERIFY(sha_digest_len == SHA1_RESULTLEN);

	/* Most significant 32 bits of the SHA1 hash */
	bcopy(sha_digest, token, sizeof (u_int32_t));
	return;
}

void
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
	return;
}

static void
mptcp_conn_properties(struct mptcb *mp_tp)
{
	/* There is only Version 0 at this time */
	mp_tp->mpt_version = MPTCP_STD_VERSION_0;

	/* Set DSS checksum flag */
	if (mptcp_dss_csum)
		mp_tp->mpt_flags |= MPTCPF_CHECKSUM;

	/* Set up receive window */
	mp_tp->mpt_rcvwnd = mptcp_sbspace(mp_tp);

	/* Set up gc ticks */
	mp_tp->mpt_gc_ticks = MPT_GC_TICKS;
}

static void
mptcp_init_local_parms(struct mptcb *mp_tp)
{
	caddr_t local_digest = NULL;

	mp_tp->mpt_localkey = mptcp_reserve_key();
	local_digest = mptcp_get_stored_digest(mp_tp->mpt_localkey);
	mptcp_generate_token(local_digest, SHA1_RESULTLEN,
	    (caddr_t)&mp_tp->mpt_localtoken, sizeof (mp_tp->mpt_localtoken));
	mptcp_generate_idsn(local_digest, SHA1_RESULTLEN,
	    (caddr_t)&mp_tp->mpt_local_idsn, sizeof (u_int64_t));

	/* The subflow SYN is also first MPTCP byte */
	mp_tp->mpt_snduna = mp_tp->mpt_sndmax = mp_tp->mpt_local_idsn + 1;
	mp_tp->mpt_sndnxt = mp_tp->mpt_snduna;

	mptcp_conn_properties(mp_tp);
}

int
mptcp_init_remote_parms(struct mptcb *mp_tp)
{
	char remote_digest[MPTCP_SHA1_RESULTLEN];
	MPT_LOCK_ASSERT_HELD(mp_tp);

	/* Only Version 0 is supported for auth purposes */
	if (mp_tp->mpt_version != MPTCP_STD_VERSION_0)
		return (-1);

	/* Setup local and remote tokens and Initial DSNs */

	if (!mptcp_do_sha1(&mp_tp->mpt_remotekey, remote_digest,
	    SHA1_RESULTLEN)) {
		mptcplog((LOG_ERR, "MPTCP Socket: %s: unexpected failure",
		    __func__), MPTCP_SOCKET_DBG, MPTCP_LOGLVL_LOG);
		return (-1);
	}
	mptcp_generate_token(remote_digest, SHA1_RESULTLEN,
	    (caddr_t)&mp_tp->mpt_remotetoken, sizeof (mp_tp->mpt_remotetoken));
	mptcp_generate_idsn(remote_digest, SHA1_RESULTLEN,
	    (caddr_t)&mp_tp->mpt_remote_idsn, sizeof (u_int64_t));
	mp_tp->mpt_rcvatmark = mp_tp->mpt_rcvnxt = mp_tp->mpt_remote_idsn + 1;

	return (0);
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

	__IGNORE_WCASTALIGN(mp_tp = &((struct mpp_mtp *)mpp)->mtcb);
	MPT_LOCK(mp_tp);
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
mptcp_preproc_sbdrop(struct socket *so, struct mbuf *m, unsigned int len)
{
	u_int32_t sub_len = 0;
	int rewinding = 0;

	if (so->so_flags1 & SOF1_DATA_IDEMPOTENT) {
		/* TFO makes things complicated. */
		if (so->so_flags1 & SOF1_TFO_REWIND) {
			rewinding = 1;
			so->so_flags1 &= ~SOF1_TFO_REWIND;
		}
	}

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
				if (rewinding == 0)
					m->m_pkthdr.mp_dsn += len;
				if (!(m->m_pkthdr.pkt_flags & PKTF_MPSO)) {
					if (rewinding == 0)
						m->m_pkthdr.mp_rseq += len;
				}
				mptcplog((LOG_DEBUG, "MPTCP Sender: "
				    "%s: dsn 0x%llx ssn %u len %d %d\n",
				    __func__,
				    m->m_pkthdr.mp_dsn, m->m_pkthdr.mp_rseq,
				    m->m_pkthdr.mp_rlen, len),
				    MPTCP_SENDER_DBG, MPTCP_LOGLVL_VERBOSE);
				m->m_pkthdr.mp_rlen -= len;
				break;
			}
		} else {
			panic("%s: MPTCP tag not set", __func__);
			/* NOTREACHED */
		}
		m = m->m_next;
	}

	if (so->so_flags & SOF_MP_SUBFLOW &&
	    !(sototcpcb(so)->t_mpflags & TMPF_TFO_REQUEST) &&
	    !(sototcpcb(so)->t_mpflags & TMPF_RCVD_DACK)) {
		/*
		 * Received an ack without receiving a DATA_ACK.
		 * Need to fallback to regular TCP (or destroy this subflow).
		 */
		mptcp_notify_mpfail(so);
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
			mptcplog((LOG_DEBUG, "MPTCP Sender: %s: contig \n",
			    __func__), MPTCP_SENDER_DBG, MPTCP_LOGLVL_VERBOSE);
		} else {
			/* case B */
			mptcplog((LOG_DEBUG, "MPTCP Sender: "
			    "%s: discontig datalen %d contig_len %d cc %d \n",
			    __func__, datalen, contig_len, so->so_snd.sb_cc),
			    MPTCP_SENDER_DBG, MPTCP_LOGLVL_VERBOSE);
			break;
		}
		mnext = mnext->m_next;
	}
	datalen = min(datalen, UINT16_MAX);
	*data_len = min(datalen, contig_len);
	mptcplog((LOG_DEBUG, "MPTCP Sender: "
	    "%s: %llu %u %d %d \n", __func__,
	    *dsn, *relseq, *data_len, off),
	    MPTCP_SENDER_DBG, MPTCP_LOGLVL_VERBOSE);
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
 * Note that this is called only from tcp_input() via mptcp_input_preproc()
 * tcp_input() may trim data after the dsn mapping is inserted into the mbuf.
 * When it trims data tcp_input calls m_adj() which does not remove the
 * m_pkthdr even if the m_len becomes 0 as a result of trimming the mbuf.
 * The dsn map insertion cannot be delayed after trim, because data can be in
 * the reassembly queue for a while and the DSN option info in tp will be
 * overwritten for every new packet received.
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

int
mptcp_adj_rmap(struct socket *so, struct mbuf *m)
{
	u_int64_t dsn;
	u_int32_t sseq, datalen;
	struct tcpcb *tp = intotcpcb(sotoinpcb(so));
	u_int32_t old_rcvnxt = 0;

	if (m_pktlen(m) == 0)
		return 0;

	if (m->m_pkthdr.pkt_flags & PKTF_MPTCP) {
		VERIFY(m->m_flags & M_PKTHDR);

		dsn = m->m_pkthdr.mp_dsn;
		sseq = m->m_pkthdr.mp_rseq + tp->irs;
		datalen = m->m_pkthdr.mp_rlen;
	} else {
		/* data arrived without an DSS option mapping */

		/* initial subflow can fallback right after SYN handshake */
		mptcp_notify_mpfail(so);
		return 0;
	}

	/* In the common case, data is in window and in sequence */
	if (m->m_pkthdr.len == (int)datalen) {
		mptcp_adj_rcvnxt(tp, m);
		return 0;
	}

	old_rcvnxt = tp->rcv_nxt - m->m_pkthdr.len;
	if (SEQ_GT(old_rcvnxt, sseq)) {
		/* data trimmed from the left */
		int off = old_rcvnxt - sseq;
		m->m_pkthdr.mp_dsn += off;
		m->m_pkthdr.mp_rseq += off;
		m->m_pkthdr.mp_rlen = m->m_pkthdr.len;
	} else if (old_rcvnxt == sseq) {
		/*
		 * data was trimmed from the right
		 */
		m->m_pkthdr.mp_rlen = m->m_pkthdr.len;
	} else {
		mptcp_notify_mpfail(so);
		return (-1);
	}
	mptcp_adj_rcvnxt(tp, m);
	return 0;
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
			mptcplog((LOG_DEBUG, "MPTCP Sender: %s: %llu %llu \n",
			    __func__, dsn, dsn_fail),
			    MPTCP_SENDER_DBG, MPTCP_LOGLVL_LOG);
			return (0);
		}

		m = m->m_next;
	}

	/*
	 * If there was no mbuf data and a fallback to TCP occurred, there's
	 * not much else to do.
	 */

	mptcplog((LOG_ERR, "MPTCP Sender: "
	    "%s: %llu not found \n", __func__, dsn_fail),
	    MPTCP_SENDER_DBG, MPTCP_LOGLVL_LOG);
	return (-1);
}

/*
 * Support for sending contiguous MPTCP bytes in subflow
 * Also for preventing sending data with ACK in 3-way handshake
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

	/*
	 * Special case handling for Fast Join. We want to send data right
	 * after ACK of the 3-way handshake, but not piggyback the data
	 * with the 3rd ACK of the 3WHS. TMPF_FASTJOINBY2_SEND and
	 * mdss_data_len control this.
	 */
	struct tcpcb *tp = NULL;
	tp = intotcpcb(sotoinpcb(so));
	if ((tp->t_mpflags & TMPF_JOINED_FLOW) &&
            (tp->t_mpflags & TMPF_PREESTABLISHED) &&
	    (!(tp->t_mpflags & TMPF_RECVD_JOIN)) &&
	    (tp->t_mpflags & TMPF_SENT_JOIN) &&
	    (!(tp->t_mpflags & TMPF_MPTCP_TRUE)) &&
	    (!(tp->t_mpflags & TMPF_FASTJOINBY2_SEND))) {
		mdss_data_len = 0;
		tp->t_mpflags |= TMPF_FASTJOINBY2_SEND;
	}

	if ((tp->t_state > TCPS_SYN_SENT) &&
	    (tp->t_mpflags & TMPF_TFO_REQUEST)) {
		mdss_data_len = 0;
		tp->t_mpflags &= ~TMPF_TFO_REQUEST;
	}
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
	if ((inp->inp_vflag & INP_IPV4) != 0) {
		flow->flow_src.ss_family = AF_INET;
		flow->flow_dst.ss_family = AF_INET;
		flow->flow_src.ss_len = sizeof(struct sockaddr_in);
		flow->flow_dst.ss_len = sizeof(struct sockaddr_in);
		SIN(&flow->flow_src)->sin_port = inp->inp_lport;
		SIN(&flow->flow_dst)->sin_port = inp->inp_fport;
		SIN(&flow->flow_src)->sin_addr = inp->inp_laddr;
		SIN(&flow->flow_dst)->sin_addr = inp->inp_faddr;
	}
	flow->flow_len = sizeof(*flow);
	flow->flow_tcpci_offset = offsetof(mptcp_flow_t, flow_ci);
	flow->flow_flags = mpts->mpts_flags;
	flow->flow_cid = mpts->mpts_connid;
	flow->flow_sndnxt = mpts->mpts_sndnxt;
	flow->flow_relseq = mpts->mpts_rel_seq;
	flow->flow_soerror = mpts->mpts_soerror;
	flow->flow_probecnt = mpts->mpts_probecnt;
	flow->flow_peerswitch = mpts->mpts_peerswitch;
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
	mptcp_flow_t *flows = NULL;

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
		flows = NULL;
		lck_mtx_lock(&mpp->mpp_lock);
		VERIFY(mpp->mpp_flags & MPP_ATTACHED);
		if (mpp->mpp_flags & MPP_DEFUNCT) {
			lck_mtx_unlock(&mpp->mpp_lock);
			continue;
		}
		mpte = mptompte(mpp);
		VERIFY(mpte != NULL);
		mp_tp = mpte->mpte_mptcb;
		VERIFY(mp_tp != NULL);

		bzero(&mptcpci, sizeof(mptcpci));
		MPT_LOCK(mp_tp);
		mptcpci.mptcpci_state = mp_tp->mpt_state;
		mptcpci.mptcpci_flags = mp_tp->mpt_flags;
		mptcpci.mptcpci_ltoken = mp_tp->mpt_localtoken;
		mptcpci.mptcpci_rtoken = mp_tp->mpt_remotetoken;
		mptcpci.mptcpci_notsent_lowat = mp_tp->mpt_notsent_lowat;
		mptcpci.mptcpci_snduna = mp_tp->mpt_snduna;
		mptcpci.mptcpci_sndnxt = mp_tp->mpt_sndnxt;
		mptcpci.mptcpci_sndmax = mp_tp->mpt_sndmax;
		mptcpci.mptcpci_lidsn = mp_tp->mpt_local_idsn;
		mptcpci.mptcpci_sndwnd = mp_tp->mpt_sndwnd;
		mptcpci.mptcpci_rcvnxt = mp_tp->mpt_rcvnxt;
		mptcpci.mptcpci_rcvatmark = mp_tp->mpt_rcvatmark;
		mptcpci.mptcpci_ridsn = mp_tp->mpt_remote_idsn;
		mptcpci.mptcpci_rcvwnd = mp_tp->mpt_rcvwnd;
		MPT_UNLOCK(mp_tp);

		mptcpci.mptcpci_nflows = mpte->mpte_numflows;
		mptcpci.mptcpci_mpte_flags = mpte->mpte_flags;
		mptcpci.mptcpci_mpte_addrid = mpte->mpte_addrid_last;
		mptcpci.mptcpci_flow_offset =
		    offsetof(conninfo_mptcp_t, mptcpci_flows);

		len = sizeof(*flows) * mpte->mpte_numflows;
		if (mpte->mpte_numflows != 0) {
			flows = _MALLOC(len, M_TEMP, M_WAITOK | M_ZERO);
			if (flows == NULL) {
				lck_mtx_unlock(&mpp->mpp_lock);
				break;
			}
			mptcpci.mptcpci_len = sizeof(mptcpci) +
			    sizeof(*flows) * (mptcpci.mptcpci_nflows - 1);
			error = SYSCTL_OUT(req, &mptcpci,
			    sizeof(mptcpci) - sizeof(mptcp_flow_t));
		} else {
			mptcpci.mptcpci_len = sizeof(mptcpci);
			error = SYSCTL_OUT(req, &mptcpci, sizeof(mptcpci));
		}
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
		if (flows) {
			error = SYSCTL_OUT(req, flows, len);
			FREE(flows, M_TEMP);
			if (error)
				break;
		}
	}
	lck_mtx_unlock(&mtcbinfo.mppi_lock);

	return (error);
}

SYSCTL_PROC(_net_inet_mptcp, OID_AUTO, pcblist, CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, mptcp_pcblist, "S,conninfo_mptcp_t",
    "List of active MPTCP connections");

/*
 * Check the health of the other subflows and do an mptcp_output if
 * there is no other active or functional subflow at the time of
 * call of this function.
 */
static void
mptcp_output_needed(struct mptses *mpte, struct mptsub *to_mpts)
{
	struct mptsub *from_mpts = NULL;

	MPTE_LOCK_ASSERT_HELD(mpte);

	MPTS_UNLOCK(to_mpts);

	from_mpts = mpte->mpte_active_sub;

	if (from_mpts == NULL)
		goto output_needed;

	MPTS_LOCK(from_mpts);

	if ((from_mpts->mpts_flags & MPTSF_DISCONNECTED) ||
	    (from_mpts->mpts_flags & MPTSF_DISCONNECTING)) {
		MPTS_UNLOCK(from_mpts);
		goto output_needed;
	}

	MPTS_UNLOCK(from_mpts);
	MPTS_LOCK(to_mpts);
	return;

output_needed:
	mptcp_output(mpte);
	MPTS_LOCK(to_mpts);
}

/*
 * Set notsent lowat mark on the MPTCB
 */
int
mptcp_set_notsent_lowat(struct mptses *mpte, int optval)
{
	struct mptcb *mp_tp = NULL;
	int error = 0;

	if (mpte->mpte_mppcb->mpp_flags & MPP_ATTACHED)
		mp_tp = mpte->mpte_mptcb;

	if (mp_tp)
		mp_tp->mpt_notsent_lowat = optval;
	else
		error = EINVAL;

	return error;
}

u_int32_t
mptcp_get_notsent_lowat(struct mptses *mpte)
{
	struct mptcb *mp_tp = NULL;

	if (mpte->mpte_mppcb->mpp_flags & MPP_ATTACHED)
		mp_tp = mpte->mpte_mptcb;

	if (mp_tp)
		return mp_tp->mpt_notsent_lowat;
	else
		return 0;
}

int
mptcp_notsent_lowat_check(struct socket *so) {
	struct mptses *mpte;
	struct mppcb *mpp;
	struct mptcb *mp_tp;
	struct mptsub *mpts;

	int notsent = 0;

	mpp = sotomppcb(so);
	if (mpp == NULL || mpp->mpp_state == MPPCB_STATE_DEAD) {
		return (0);
	}

	mpte = mptompte(mpp);
	mp_tp = mpte->mpte_mptcb;

	MPT_LOCK(mp_tp);
	notsent = so->so_snd.sb_cc;

	if ((notsent == 0) ||
	    ((notsent - (mp_tp->mpt_sndnxt - mp_tp->mpt_snduna)) <=
	    mp_tp->mpt_notsent_lowat)) {
		mptcplog((LOG_DEBUG, "MPTCP Sender: "
		    "lowat %d notsent %d actual %d \n",
		    mp_tp->mpt_notsent_lowat, notsent,
		    notsent - (mp_tp->mpt_sndnxt - mp_tp->mpt_snduna)),
		    MPTCP_SENDER_DBG , MPTCP_LOGLVL_VERBOSE);
		MPT_UNLOCK(mp_tp);
		return (1);
	}
	MPT_UNLOCK(mp_tp);

	/* When Nagle's algorithm is not disabled, it is better
	 * to wakeup the client even before there is atleast one
	 * maxseg of data to write.
	 */
	TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
		int retval = 0;
		MPTS_LOCK(mpts);
		if (mpts->mpts_flags & MPTSF_ACTIVE) {
			struct socket *subf_so = mpts->mpts_socket;
			socket_lock(subf_so, 0);
			struct tcpcb *tp = intotcpcb(sotoinpcb(subf_so));

			notsent = so->so_snd.sb_cc -
			   (tp->snd_nxt - tp->snd_una);

			if ((tp->t_flags & TF_NODELAY) == 0 &&
			    notsent > 0 && (notsent <= (int)tp->t_maxseg)) {
				retval = 1;
			}
			mptcplog((LOG_DEBUG, "MPTCP Sender: lowat %d notsent %d"
			    " nodelay false \n",
			    mp_tp->mpt_notsent_lowat, notsent),
			    MPTCP_SENDER_DBG , MPTCP_LOGLVL_VERBOSE);
			socket_unlock(subf_so, 0);
			MPTS_UNLOCK(mpts);
			return (retval);
		}
		MPTS_UNLOCK(mpts);
	}
	return (0);
}

static void
mptcp_get_rtt_measurement(struct mptsub *mpts, struct mptses *mpte)
{
	MPTE_LOCK_ASSERT_HELD(mpte);
	MPTS_LOCK_ASSERT_HELD(mpts);

	struct socket *subflow_so = mpts->mpts_socket;
	socket_lock(subflow_so, 0);
	mpts->mpts_srtt = (intotcpcb(sotoinpcb(subflow_so)))->t_srtt;
	mpts->mpts_rxtcur = (intotcpcb(sotoinpcb(subflow_so)))->t_rxtcur;
	socket_unlock(subflow_so, 0);
}

/* Using Symptoms Advisory to detect poor WiFi or poor Cell */
static kern_ctl_ref mptcp_kern_ctrl_ref = NULL;
static uint32_t mptcp_kern_skt_inuse = 0;
symptoms_advisory_t mptcp_advisory;

static errno_t
mptcp_symptoms_ctl_connect(kern_ctl_ref kctlref, struct sockaddr_ctl *sac,
	void **unitinfo)
{
#pragma unused(kctlref, sac, unitinfo)
	/*
	 * We don't need to do anything here. But we can atleast ensure
	 * only one user opens the MPTCP_KERN_CTL_NAME control socket.
	 */
	if (OSCompareAndSwap(0, 1, &mptcp_kern_skt_inuse))
		return (0);
	else
		return (EALREADY);
}

static errno_t
mptcp_symptoms_ctl_disconnect(kern_ctl_ref kctlref, u_int32_t kcunit,
	void *unitinfo)
{
#pragma unused(kctlref, kcunit, unitinfo)
	if (OSCompareAndSwap(1, 0, &mptcp_kern_skt_inuse)) {
		/* TBD needs to be locked if the size grows more than an int */
		bzero(&mptcp_advisory, sizeof(mptcp_advisory));
		return (0);
	}
	else {
		return (EINVAL);
	}
}

static errno_t
mptcp_symptoms_ctl_send(kern_ctl_ref kctlref, u_int32_t kcunit, void *unitinfo,
       mbuf_t m, int flags)
{
#pragma unused(kctlref, kcunit, unitinfo, flags)
	symptoms_advisory_t     *sa = NULL;

	if (mbuf_pkthdr_len(m) < sizeof(*sa)) {
		mbuf_freem(m);
		return (EINVAL);
	}

	if (mbuf_len(m) >= sizeof(*sa))
		sa = mbuf_data(m);
	else
		return (EINVAL);

	if (mptcp_advisory.sa_nwk_status_int != sa->sa_nwk_status_int) {
		/*
		 * we could use this notification to notify all mptcp pcbs
		 * of the change in network status. But its difficult to
		 * define if sending REMOVE_ADDR or MP_PRIO is appropriate
		 * given that these are only soft indicators of the network
		 * state. Leaving this as TBD for now.
		 */
	}

	if (sa->sa_nwk_status != SYMPTOMS_ADVISORY_NOCOMMENT) {
		mptcplog((LOG_DEBUG, "MPTCP Events: %s wifi %d,%d cell %d,%d\n",
		    __func__, sa->sa_wifi_status, mptcp_advisory.sa_wifi_status,
		    sa->sa_cell_status, mptcp_advisory.sa_cell_status),
		    MPTCP_SOCKET_DBG | MPTCP_EVENTS_DBG,
		    MPTCP_LOGLVL_LOG);

		if ((sa->sa_wifi_status &
		    (SYMPTOMS_ADVISORY_WIFI_BAD | SYMPTOMS_ADVISORY_WIFI_OK)) !=
		    (SYMPTOMS_ADVISORY_WIFI_BAD | SYMPTOMS_ADVISORY_WIFI_OK)) {
			mptcp_advisory.sa_wifi_status = sa->sa_wifi_status;
		}

		if ((sa->sa_cell_status &
		    (SYMPTOMS_ADVISORY_CELL_BAD | SYMPTOMS_ADVISORY_CELL_OK)) !=
		    (SYMPTOMS_ADVISORY_CELL_BAD | SYMPTOMS_ADVISORY_CELL_OK)) {
			mptcp_advisory.sa_cell_status = sa->sa_cell_status;
		}
	} else {
		mptcplog((LOG_DEBUG, "MPTCP Events: %s NOCOMMENT "
		    "wifi %d cell %d\n", __func__,
		    mptcp_advisory.sa_wifi_status,
		    mptcp_advisory.sa_cell_status),
		    MPTCP_SOCKET_DBG | MPTCP_EVENTS_DBG, MPTCP_LOGLVL_LOG);
	}
	return (0);
}

void
mptcp_control_register(void)
{
	/* Set up the advisory control socket */
	struct kern_ctl_reg mptcp_kern_ctl;

	bzero(&mptcp_kern_ctl, sizeof(mptcp_kern_ctl));
	strlcpy(mptcp_kern_ctl.ctl_name, MPTCP_KERN_CTL_NAME,
	    sizeof(mptcp_kern_ctl.ctl_name));
	mptcp_kern_ctl.ctl_connect = mptcp_symptoms_ctl_connect;
	mptcp_kern_ctl.ctl_disconnect = mptcp_symptoms_ctl_disconnect;
	mptcp_kern_ctl.ctl_send = mptcp_symptoms_ctl_send;
	mptcp_kern_ctl.ctl_flags = CTL_FLAG_PRIVILEGED;

	(void)ctl_register(&mptcp_kern_ctl, &mptcp_kern_ctrl_ref);
}

int
mptcp_is_wifi_unusable(void)
{
	/* a false return val indicates there is no info or wifi is ok */
	return (mptcp_advisory.sa_wifi_status & SYMPTOMS_ADVISORY_WIFI_BAD);
}

int
mptcp_is_cell_unusable(void)
{
	/* a false return val indicates there is no info or cell is ok */
	return (mptcp_advisory.sa_cell_status & SYMPTOMS_ADVISORY_CELL_BAD);
}

struct mptsub*
mptcp_use_symptoms_hints(struct mptsub* best, struct mptsub *second_best)
{
	struct mptsub *cellsub = NULL;
	struct mptsub *wifisub = NULL;
	struct mptsub *wiredsub = NULL;

	VERIFY ((best != NULL) && (second_best != NULL));

	if (!mptcp_use_symptomsd)
		return (NULL);

	if (!mptcp_kern_skt_inuse)
		return (NULL);

	/*
	 * There could be devices with more than one wifi interface or
	 * more than one wired or cell interfaces.
	 * TBD: SymptomsD is unavailable on such platforms as of now.
	 * Try to prefer best when possible in general.
	 * Also, SymptomsD sends notifications about wifi only when it
	 * is primary.
	 */
	if (best->mpts_linktype & MPTSL_WIFI)
		wifisub = best;
	else if (best->mpts_linktype & MPTSL_CELL)
		cellsub = best;
	else if (best->mpts_linktype & MPTSL_WIRED)
		wiredsub = best;

	/*
	 * On platforms with wired paths, don't use hints about wifi or cell.
	 * Currently, SymptomsD is not available on platforms with wired paths.
	 */
	if (wiredsub)
		return (NULL);

	if ((wifisub == NULL) && (second_best->mpts_linktype & MPTSL_WIFI))
		wifisub = second_best;

	if ((cellsub == NULL) && (second_best->mpts_linktype & MPTSL_CELL))
		cellsub = second_best;

	if ((wiredsub == NULL) && (second_best->mpts_linktype & MPTSL_WIRED))
		wiredsub = second_best;

	if ((wifisub == best) && mptcp_is_wifi_unusable()) {
		tcpstat.tcps_mp_sel_symtomsd++;
		if (mptcp_is_cell_unusable()) {
			mptcplog((LOG_DEBUG, "MPTCP Sender: SymptomsD hint"
			    " suggests both Wifi and Cell are bad. Wired %s.",
			    (wiredsub == NULL) ? "none" : "present"),
			    MPTCP_SENDER_DBG, MPTCP_LOGLVL_LOG);
			return (wiredsub);
		} else {
			mptcplog((LOG_DEBUG, "MPTCP Sender: SymptomsD hint"
			    " suggests Wifi bad, Cell good. Wired %s.",
			    (wiredsub == NULL) ? "none" : "present"),
			    MPTCP_SENDER_DBG, MPTCP_LOGLVL_LOG);
			return ((wiredsub != NULL) ? wiredsub : cellsub);
		}
	}

	if ((cellsub == best) && (mptcp_is_cell_unusable())) {
		tcpstat.tcps_mp_sel_symtomsd++;
		if (mptcp_is_wifi_unusable()) {
			mptcplog((LOG_DEBUG, "MPTCP Sender: SymptomsD hint"
			    " suggests both Cell and Wifi are bad. Wired %s.",
			    (wiredsub == NULL) ? "none" : "present"),
			    MPTCP_SENDER_DBG, MPTCP_LOGLVL_LOG);
			return (wiredsub);
		} else {
			mptcplog((LOG_DEBUG, "MPTCP Sender: SymptomsD hint"
			    " suggests Cell bad, Wifi good. Wired %s.",
			    (wiredsub == NULL) ? "none" : "present"),
			    MPTCP_SENDER_DBG, MPTCP_LOGLVL_LOG);
			return ((wiredsub != NULL) ? wiredsub : wifisub);
		}
	}

	/* little is known about the state of the network or wifi is good */
	return (NULL);
}

/* If TFO data is succesfully acked, it must be dropped from the mptcp so */
static void
mptcp_drop_tfo_data(struct mptses *mpte, struct mptsub *mpts, int *wakeup)
{
	struct socket *mp_so = mpte->mpte_mppcb->mpp_socket;
	struct socket *so = mpts->mpts_socket;
	struct tcpcb *tp = intotcpcb(sotoinpcb(so));
	struct mptcb *mp_tp = mpte->mpte_mptcb;

	/* If data was sent with SYN, rewind state */
	if (tp->t_tfo_stats & TFO_S_SYN_DATA_ACKED) {
		mpts->mpts_flags &= ~MPTSF_TFO_REQD;
		tp->t_mpflags &= ~TMPF_TFO_REQUEST;
		MPT_LOCK(mp_tp);
		u_int64_t mp_droplen = mpts->mpts_sndnxt - mp_tp->mpt_snduna;
		unsigned int tcp_droplen = tp->snd_una - tp->iss - 1;
		VERIFY(mp_droplen <= (UINT_MAX));
		VERIFY(mp_droplen >= tcp_droplen);

		if (mp_droplen > tcp_droplen) {
			/* handle partial TCP ack */
			mp_so->so_flags1 |= SOF1_TFO_REWIND;
			mp_tp->mpt_sndnxt = mp_tp->mpt_snduna + (mp_droplen - tcp_droplen);
			mpts->mpts_sndnxt = mp_tp->mpt_sndnxt;
			mp_droplen = tcp_droplen;
		} else {
			/* all data on SYN was acked */
			mpts->mpts_rel_seq = 1;
			mp_tp->mpt_sndnxt = mp_tp->mpt_snduna;
			mpts->mpts_sndnxt = mp_tp->mpt_snduna;
		}
		mp_tp->mpt_sndmax -= tcp_droplen;

		MPT_UNLOCK(mp_tp);
		if (mp_droplen != 0) {
			VERIFY(mp_so->so_snd.sb_mb != NULL);
			sbdrop(&mp_so->so_snd, (int)mp_droplen);
			if (wakeup)
				*wakeup = 1;
		}
		mptcplog((LOG_ERR, "MPTCP Sender: %s mp_so 0x%llx cid %d "
		    "TFO tcp len %d mptcp len %d\n", __func__,
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so), mpts->mpts_connid,
		    tcp_droplen, mp_droplen),
		    MPTCP_SENDER_DBG, MPTCP_LOGLVL_LOG);
	}
}
