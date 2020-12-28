/*
 * Copyright (c) 1999-2020 Apple Inc. All rights reserved.
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
 * Kernel Control domain - allows control connections to
 *  and to read/write data.
 *
 * Vincent Lubet, 040506
 * Christophe Allie, 010928
 * Justin C. Walker, 990319
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/syslog.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/sys_domain.h>
#include <sys/kern_event.h>
#include <sys/kern_control.h>
#include <sys/kauth.h>
#include <sys/sysctl.h>
#include <sys/proc_info.h>
#include <net/if_var.h>

#include <mach/vm_types.h>

#include <kern/thread.h>

struct kctl {
	TAILQ_ENTRY(kctl)       next;           /* controller chain */
	kern_ctl_ref            kctlref;

	/* controller information provided when registering */
	char                    name[MAX_KCTL_NAME];    /* unique identifier */
	u_int32_t               id;
	u_int32_t               reg_unit;

	/* misc communication information */
	u_int32_t               flags;          /* support flags */
	u_int32_t               recvbufsize;    /* request more than the default buffer size */
	u_int32_t               sendbufsize;    /* request more than the default buffer size */

	/* Dispatch functions */
	ctl_bind_func           bind;           /* Prepare contact */
	ctl_connect_func        connect;        /* Make contact */
	ctl_disconnect_func     disconnect;     /* Break contact */
	ctl_send_func           send;           /* Send data to nke */
	ctl_send_list_func      send_list;      /* Send list of packets */
	ctl_setopt_func         setopt;         /* set kctl configuration */
	ctl_getopt_func         getopt;         /* get kctl configuration */
	ctl_rcvd_func           rcvd;           /* Notify nke when client reads data */

	TAILQ_HEAD(, ctl_cb)    kcb_head;
	u_int32_t               lastunit;
};

#if DEVELOPMENT || DEBUG
enum ctl_status {
	KCTL_DISCONNECTED = 0,
	KCTL_CONNECTING = 1,
	KCTL_CONNECTED = 2
};
#endif /* DEVELOPMENT || DEBUG */

struct ctl_cb {
	TAILQ_ENTRY(ctl_cb)     next;           /* controller chain */
	lck_mtx_t               *mtx;
	struct socket           *so;            /* controlling socket */
	struct kctl             *kctl;          /* back pointer to controller */
	void                    *userdata;
	struct sockaddr_ctl     sac;
	u_int32_t               usecount;
	u_int32_t               kcb_usecount;
	u_int32_t               require_clearing_count;
#if DEVELOPMENT || DEBUG
	enum ctl_status         status;
#endif /* DEVELOPMENT || DEBUG */
};

#ifndef ROUNDUP64
#define ROUNDUP64(x) P2ROUNDUP((x), sizeof (u_int64_t))
#endif

#ifndef ADVANCE64
#define ADVANCE64(p, n) (void*)((char *)(p) + ROUNDUP64(n))
#endif

/*
 * Definitions and vars for we support
 */

#define CTL_SENDSIZE    (2 * 1024)      /* default buffer size */
#define CTL_RECVSIZE    (8 * 1024)      /* default buffer size */

/*
 * Definitions and vars for we support
 */

static u_int32_t        ctl_maxunit = 65536;
static lck_grp_attr_t   *ctl_lck_grp_attr = 0;
static lck_attr_t       *ctl_lck_attr = 0;
static lck_grp_t        *ctl_lck_grp = 0;
static lck_mtx_t        *ctl_mtx;

/* all the controllers are chained */
TAILQ_HEAD(kctl_list, kctl)     ctl_head;

static int ctl_attach(struct socket *, int, struct proc *);
static int ctl_detach(struct socket *);
static int ctl_sofreelastref(struct socket *so);
static int ctl_bind(struct socket *, struct sockaddr *, struct proc *);
static int ctl_connect(struct socket *, struct sockaddr *, struct proc *);
static int ctl_disconnect(struct socket *);
static int ctl_ioctl(struct socket *so, u_long cmd, caddr_t data,
    struct ifnet *ifp, struct proc *p);
static int ctl_send(struct socket *, int, struct mbuf *,
    struct sockaddr *, struct mbuf *, struct proc *);
static int ctl_send_list(struct socket *, int, struct mbuf *,
    struct sockaddr *, struct mbuf *, struct proc *);
static int ctl_ctloutput(struct socket *, struct sockopt *);
static int ctl_peeraddr(struct socket *so, struct sockaddr **nam);
static int ctl_usr_rcvd(struct socket *so, int flags);

static struct kctl *ctl_find_by_name(const char *);
static struct kctl *ctl_find_by_id_unit(u_int32_t id, u_int32_t unit);

static struct socket *kcb_find_socket(kern_ctl_ref kctlref, u_int32_t unit,
    u_int32_t *);
static struct ctl_cb *kcb_find(struct kctl *, u_int32_t unit);
static void ctl_post_msg(u_int32_t event_code, u_int32_t id);

static int ctl_lock(struct socket *, int, void *);
static int ctl_unlock(struct socket *, int, void *);
static lck_mtx_t * ctl_getlock(struct socket *, int);

static struct pr_usrreqs ctl_usrreqs = {
	.pru_attach =           ctl_attach,
	.pru_bind =             ctl_bind,
	.pru_connect =          ctl_connect,
	.pru_control =          ctl_ioctl,
	.pru_detach =           ctl_detach,
	.pru_disconnect =       ctl_disconnect,
	.pru_peeraddr =         ctl_peeraddr,
	.pru_rcvd =             ctl_usr_rcvd,
	.pru_send =             ctl_send,
	.pru_send_list =        ctl_send_list,
	.pru_sosend =           sosend,
	.pru_sosend_list =      sosend_list,
	.pru_soreceive =        soreceive,
	.pru_soreceive_list =   soreceive_list,
};

static struct protosw kctlsw[] = {
	{
		.pr_type =      SOCK_DGRAM,
		.pr_protocol =  SYSPROTO_CONTROL,
		.pr_flags =     PR_ATOMIC | PR_CONNREQUIRED | PR_PCBLOCK | PR_WANTRCVD,
		.pr_ctloutput = ctl_ctloutput,
		.pr_usrreqs =   &ctl_usrreqs,
		.pr_lock =      ctl_lock,
		.pr_unlock =    ctl_unlock,
		.pr_getlock =   ctl_getlock,
	},
	{
		.pr_type =      SOCK_STREAM,
		.pr_protocol =  SYSPROTO_CONTROL,
		.pr_flags =     PR_CONNREQUIRED | PR_PCBLOCK | PR_WANTRCVD,
		.pr_ctloutput = ctl_ctloutput,
		.pr_usrreqs =   &ctl_usrreqs,
		.pr_lock =      ctl_lock,
		.pr_unlock =    ctl_unlock,
		.pr_getlock =   ctl_getlock,
	}
};

__private_extern__ int kctl_reg_list SYSCTL_HANDLER_ARGS;
__private_extern__ int kctl_pcblist SYSCTL_HANDLER_ARGS;
__private_extern__ int kctl_getstat SYSCTL_HANDLER_ARGS;


SYSCTL_NODE(_net_systm, OID_AUTO, kctl,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "Kernel control family");

struct kctlstat kctlstat;
SYSCTL_PROC(_net_systm_kctl, OID_AUTO, stats,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0,
    kctl_getstat, "S,kctlstat", "");

SYSCTL_PROC(_net_systm_kctl, OID_AUTO, reg_list,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0,
    kctl_reg_list, "S,xkctl_reg", "");

SYSCTL_PROC(_net_systm_kctl, OID_AUTO, pcblist,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0,
    kctl_pcblist, "S,xkctlpcb", "");

u_int32_t ctl_autorcvbuf_max = 256 * 1024;
SYSCTL_INT(_net_systm_kctl, OID_AUTO, autorcvbufmax,
    CTLFLAG_RW | CTLFLAG_LOCKED, &ctl_autorcvbuf_max, 0, "");

u_int32_t ctl_autorcvbuf_high = 0;
SYSCTL_INT(_net_systm_kctl, OID_AUTO, autorcvbufhigh,
    CTLFLAG_RD | CTLFLAG_LOCKED, &ctl_autorcvbuf_high, 0, "");

u_int32_t ctl_debug = 0;
SYSCTL_INT(_net_systm_kctl, OID_AUTO, debug,
    CTLFLAG_RW | CTLFLAG_LOCKED, &ctl_debug, 0, "");

#if DEVELOPMENT || DEBUG
u_int32_t ctl_panic_debug = 0;
SYSCTL_INT(_net_systm_kctl, OID_AUTO, panicdebug,
    CTLFLAG_RW | CTLFLAG_LOCKED, &ctl_panic_debug, 0, "");
#endif /* DEVELOPMENT || DEBUG */

#define KCTL_TBL_INC 16

static uintptr_t kctl_tbl_size = 0;
static u_int32_t kctl_tbl_growing = 0;
static u_int32_t kctl_tbl_growing_waiting = 0;
static uintptr_t kctl_tbl_count = 0;
static struct kctl **kctl_table = NULL;
static uintptr_t kctl_ref_gencnt = 0;

static void kctl_tbl_grow(void);
static kern_ctl_ref kctl_make_ref(struct kctl *kctl);
static void kctl_delete_ref(kern_ctl_ref);
static struct kctl *kctl_from_ref(kern_ctl_ref);

/*
 * Install the protosw's for the Kernel Control manager.
 */
__private_extern__ void
kern_control_init(struct domain *dp)
{
	struct protosw *pr;
	int i;
	int kctl_proto_count = (sizeof(kctlsw) / sizeof(struct protosw));

	VERIFY(!(dp->dom_flags & DOM_INITIALIZED));
	VERIFY(dp == systemdomain);

	ctl_lck_grp_attr = lck_grp_attr_alloc_init();
	if (ctl_lck_grp_attr == NULL) {
		panic("%s: lck_grp_attr_alloc_init failed\n", __func__);
		/* NOTREACHED */
	}

	ctl_lck_grp = lck_grp_alloc_init("Kernel Control Protocol",
	    ctl_lck_grp_attr);
	if (ctl_lck_grp == NULL) {
		panic("%s: lck_grp_alloc_init failed\n", __func__);
		/* NOTREACHED */
	}

	ctl_lck_attr = lck_attr_alloc_init();
	if (ctl_lck_attr == NULL) {
		panic("%s: lck_attr_alloc_init failed\n", __func__);
		/* NOTREACHED */
	}

	ctl_mtx = lck_mtx_alloc_init(ctl_lck_grp, ctl_lck_attr);
	if (ctl_mtx == NULL) {
		panic("%s: lck_mtx_alloc_init failed\n", __func__);
		/* NOTREACHED */
	}
	TAILQ_INIT(&ctl_head);

	for (i = 0, pr = &kctlsw[0]; i < kctl_proto_count; i++, pr++) {
		net_add_proto(pr, dp, 1);
	}
}

static void
kcb_delete(struct ctl_cb *kcb)
{
	if (kcb != 0) {
		if (kcb->mtx != 0) {
			lck_mtx_free(kcb->mtx, ctl_lck_grp);
		}
		FREE(kcb, M_TEMP);
	}
}

/*
 * Kernel Controller user-request functions
 * attach function must exist and succeed
 * detach not necessary
 * we need a pcb for the per socket mutex
 */
static int
ctl_attach(struct socket *so, int proto, struct proc *p)
{
#pragma unused(proto, p)
	int error = 0;
	struct ctl_cb                   *kcb = 0;

	MALLOC(kcb, struct ctl_cb *, sizeof(struct ctl_cb), M_TEMP, M_WAITOK);
	if (kcb == NULL) {
		error = ENOMEM;
		goto quit;
	}
	bzero(kcb, sizeof(struct ctl_cb));

	kcb->mtx = lck_mtx_alloc_init(ctl_lck_grp, ctl_lck_attr);
	if (kcb->mtx == NULL) {
		error = ENOMEM;
		goto quit;
	}
	kcb->so = so;
	so->so_pcb = (caddr_t)kcb;

quit:
	if (error != 0) {
		kcb_delete(kcb);
		kcb = 0;
	}
	return error;
}

static int
ctl_sofreelastref(struct socket *so)
{
	struct ctl_cb   *kcb = (struct ctl_cb *)so->so_pcb;

	so->so_pcb = 0;

	if (kcb != 0) {
		struct kctl             *kctl;
		if ((kctl = kcb->kctl) != 0) {
			lck_mtx_lock(ctl_mtx);
			TAILQ_REMOVE(&kctl->kcb_head, kcb, next);
			kctlstat.kcs_pcbcount--;
			kctlstat.kcs_gencnt++;
			lck_mtx_unlock(ctl_mtx);
		}
		kcb_delete(kcb);
	}
	sofreelastref(so, 1);
	return 0;
}

/*
 * Use this function and ctl_kcb_require_clearing to serialize
 * critical calls into the kctl subsystem
 */
static void
ctl_kcb_increment_use_count(struct ctl_cb *kcb, lck_mtx_t *mutex_held)
{
	LCK_MTX_ASSERT(mutex_held, LCK_MTX_ASSERT_OWNED);
	while (kcb->require_clearing_count > 0) {
		msleep(&kcb->require_clearing_count, mutex_held, PSOCK | PCATCH, "kcb_require_clearing", NULL);
	}
	kcb->kcb_usecount++;
}

static void
ctl_kcb_require_clearing(struct ctl_cb *kcb, lck_mtx_t *mutex_held)
{
	assert(kcb->kcb_usecount != 0);
	kcb->require_clearing_count++;
	kcb->kcb_usecount--;
	while (kcb->kcb_usecount > 0) { // we need to wait until no one else is running
		msleep(&kcb->kcb_usecount, mutex_held, PSOCK | PCATCH, "kcb_usecount", NULL);
	}
	kcb->kcb_usecount++;
}

static void
ctl_kcb_done_clearing(struct ctl_cb *kcb)
{
	assert(kcb->require_clearing_count != 0);
	kcb->require_clearing_count--;
	wakeup((caddr_t)&kcb->require_clearing_count);
}

static void
ctl_kcb_decrement_use_count(struct ctl_cb *kcb)
{
	assert(kcb->kcb_usecount != 0);
	kcb->kcb_usecount--;
	wakeup((caddr_t)&kcb->kcb_usecount);
}

static int
ctl_detach(struct socket *so)
{
	struct ctl_cb   *kcb = (struct ctl_cb *)so->so_pcb;

	if (kcb == 0) {
		return 0;
	}

	lck_mtx_t *mtx_held = socket_getlock(so, PR_F_WILLUNLOCK);
	ctl_kcb_increment_use_count(kcb, mtx_held);
	ctl_kcb_require_clearing(kcb, mtx_held);

	if (kcb->kctl != NULL && kcb->kctl->bind != NULL &&
	    kcb->userdata != NULL && !(so->so_state & SS_ISCONNECTED)) {
		// The unit was bound, but not connected
		// Invoke the disconnected call to cleanup
		if (kcb->kctl->disconnect != NULL) {
			socket_unlock(so, 0);
			(*kcb->kctl->disconnect)(kcb->kctl->kctlref,
			    kcb->sac.sc_unit, kcb->userdata);
			socket_lock(so, 0);
		}
	}

	soisdisconnected(so);
#if DEVELOPMENT || DEBUG
	kcb->status = KCTL_DISCONNECTED;
#endif /* DEVELOPMENT || DEBUG */
	so->so_flags |= SOF_PCBCLEARING;
	ctl_kcb_done_clearing(kcb);
	ctl_kcb_decrement_use_count(kcb);
	return 0;
}

static int
ctl_setup_kctl(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	struct kctl *kctl = NULL;
	int error = 0;
	struct sockaddr_ctl     sa;
	struct ctl_cb *kcb = (struct ctl_cb *)so->so_pcb;
	struct ctl_cb *kcb_next = NULL;
	u_quad_t sbmaxsize;
	u_int32_t recvbufsize, sendbufsize;

	if (kcb == 0) {
		panic("ctl_setup_kctl so_pcb null\n");
	}

	if (kcb->kctl != NULL) {
		// Already set up, skip
		return 0;
	}

	if (nam->sa_len != sizeof(struct sockaddr_ctl)) {
		return EINVAL;
	}

	bcopy(nam, &sa, sizeof(struct sockaddr_ctl));

	lck_mtx_lock(ctl_mtx);
	kctl = ctl_find_by_id_unit(sa.sc_id, sa.sc_unit);
	if (kctl == NULL) {
		lck_mtx_unlock(ctl_mtx);
		return ENOENT;
	}

	if (((kctl->flags & CTL_FLAG_REG_SOCK_STREAM) &&
	    (so->so_type != SOCK_STREAM)) ||
	    (!(kctl->flags & CTL_FLAG_REG_SOCK_STREAM) &&
	    (so->so_type != SOCK_DGRAM))) {
		lck_mtx_unlock(ctl_mtx);
		return EPROTOTYPE;
	}

	if (kctl->flags & CTL_FLAG_PRIVILEGED) {
		if (p == 0) {
			lck_mtx_unlock(ctl_mtx);
			return EINVAL;
		}
		if (kauth_cred_issuser(kauth_cred_get()) == 0) {
			lck_mtx_unlock(ctl_mtx);
			return EPERM;
		}
	}

	if ((kctl->flags & CTL_FLAG_REG_ID_UNIT) || sa.sc_unit != 0) {
		if (kcb_find(kctl, sa.sc_unit) != NULL) {
			lck_mtx_unlock(ctl_mtx);
			return EBUSY;
		}
	} else {
		/* Find an unused ID, assumes control IDs are in order */
		u_int32_t unit = 1;

		TAILQ_FOREACH(kcb_next, &kctl->kcb_head, next) {
			if (kcb_next->sac.sc_unit > unit) {
				/* Found a gap, lets fill it in */
				break;
			}
			unit = kcb_next->sac.sc_unit + 1;
			if (unit == ctl_maxunit) {
				break;
			}
		}

		if (unit == ctl_maxunit) {
			lck_mtx_unlock(ctl_mtx);
			return EBUSY;
		}

		sa.sc_unit = unit;
	}

	bcopy(&sa, &kcb->sac, sizeof(struct sockaddr_ctl));
	kcb->kctl = kctl;
	if (kcb_next != NULL) {
		TAILQ_INSERT_BEFORE(kcb_next, kcb, next);
	} else {
		TAILQ_INSERT_TAIL(&kctl->kcb_head, kcb, next);
	}
	kctlstat.kcs_pcbcount++;
	kctlstat.kcs_gencnt++;
	kctlstat.kcs_connections++;
	lck_mtx_unlock(ctl_mtx);

	/*
	 * rdar://15526688: Limit the send and receive sizes to sb_max
	 * by using the same scaling as sbreserve()
	 */
	sbmaxsize = (u_quad_t)sb_max * MCLBYTES / (MSIZE + MCLBYTES);

	if (kctl->sendbufsize > sbmaxsize) {
		sendbufsize = sbmaxsize;
	} else {
		sendbufsize = kctl->sendbufsize;
	}

	if (kctl->recvbufsize > sbmaxsize) {
		recvbufsize = sbmaxsize;
	} else {
		recvbufsize = kctl->recvbufsize;
	}

	error = soreserve(so, sendbufsize, recvbufsize);
	if (error) {
		if (ctl_debug) {
			printf("%s - soreserve(%llx, %u, %u) error %d\n",
			    __func__, (uint64_t)VM_KERNEL_ADDRPERM(so),
			    sendbufsize, recvbufsize, error);
		}
		goto done;
	}

done:
	if (error) {
		soisdisconnected(so);
#if DEVELOPMENT || DEBUG
		kcb->status = KCTL_DISCONNECTED;
#endif /* DEVELOPMENT || DEBUG */
		lck_mtx_lock(ctl_mtx);
		TAILQ_REMOVE(&kctl->kcb_head, kcb, next);
		kcb->kctl = NULL;
		kcb->sac.sc_unit = 0;
		kctlstat.kcs_pcbcount--;
		kctlstat.kcs_gencnt++;
		kctlstat.kcs_conn_fail++;
		lck_mtx_unlock(ctl_mtx);
	}
	return error;
}

static int
ctl_bind(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	int error = 0;
	struct ctl_cb *kcb = (struct ctl_cb *)so->so_pcb;

	if (kcb == NULL) {
		panic("ctl_bind so_pcb null\n");
	}

	lck_mtx_t *mtx_held = socket_getlock(so, PR_F_WILLUNLOCK);
	ctl_kcb_increment_use_count(kcb, mtx_held);
	ctl_kcb_require_clearing(kcb, mtx_held);

	error = ctl_setup_kctl(so, nam, p);
	if (error) {
		goto out;
	}

	if (kcb->kctl == NULL) {
		panic("ctl_bind kctl null\n");
	}

	if (kcb->kctl->bind == NULL) {
		error = EINVAL;
		goto out;
	}

	socket_unlock(so, 0);
	error = (*kcb->kctl->bind)(kcb->kctl->kctlref, &kcb->sac, &kcb->userdata);
	socket_lock(so, 0);

out:
	ctl_kcb_done_clearing(kcb);
	ctl_kcb_decrement_use_count(kcb);
	return error;
}

static int
ctl_connect(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	int error = 0;
	struct ctl_cb *kcb = (struct ctl_cb *)so->so_pcb;

	if (kcb == NULL) {
		panic("ctl_connect so_pcb null\n");
	}

	lck_mtx_t *mtx_held = socket_getlock(so, PR_F_WILLUNLOCK);
	ctl_kcb_increment_use_count(kcb, mtx_held);
	ctl_kcb_require_clearing(kcb, mtx_held);

#if DEVELOPMENT || DEBUG
	if (kcb->status != KCTL_DISCONNECTED && ctl_panic_debug) {
		panic("kctl already connecting/connected");
	}
	kcb->status = KCTL_CONNECTING;
#endif /* DEVELOPMENT || DEBUG */

	error = ctl_setup_kctl(so, nam, p);
	if (error) {
		goto out;
	}

	if (kcb->kctl == NULL) {
		panic("ctl_connect kctl null\n");
	}

	soisconnecting(so);
	socket_unlock(so, 0);
	error = (*kcb->kctl->connect)(kcb->kctl->kctlref, &kcb->sac, &kcb->userdata);
	socket_lock(so, 0);
	if (error) {
		goto end;
	}
	soisconnected(so);
#if DEVELOPMENT || DEBUG
	kcb->status = KCTL_CONNECTED;
#endif /* DEVELOPMENT || DEBUG */

end:
	if (error && kcb->kctl->disconnect) {
		/*
		 * XXX Make sure we Don't check the return value
		 * of disconnect here.
		 * ipsec/utun_ctl_disconnect will return error when
		 * disconnect gets called after connect failure.
		 * However if we decide to check for disconnect return
		 * value here. Please make sure to revisit
		 * ipsec/utun_ctl_disconnect.
		 */
		socket_unlock(so, 0);
		(*kcb->kctl->disconnect)(kcb->kctl->kctlref, kcb->sac.sc_unit, kcb->userdata);
		socket_lock(so, 0);
	}
	if (error) {
		soisdisconnected(so);
#if DEVELOPMENT || DEBUG
		kcb->status = KCTL_DISCONNECTED;
#endif /* DEVELOPMENT || DEBUG */
		lck_mtx_lock(ctl_mtx);
		TAILQ_REMOVE(&kcb->kctl->kcb_head, kcb, next);
		kcb->kctl = NULL;
		kcb->sac.sc_unit = 0;
		kctlstat.kcs_pcbcount--;
		kctlstat.kcs_gencnt++;
		kctlstat.kcs_conn_fail++;
		lck_mtx_unlock(ctl_mtx);
	}
out:
	ctl_kcb_done_clearing(kcb);
	ctl_kcb_decrement_use_count(kcb);
	return error;
}

static int
ctl_disconnect(struct socket *so)
{
	struct ctl_cb   *kcb = (struct ctl_cb *)so->so_pcb;

	if ((kcb = (struct ctl_cb *)so->so_pcb)) {
		lck_mtx_t *mtx_held = socket_getlock(so, PR_F_WILLUNLOCK);
		ctl_kcb_increment_use_count(kcb, mtx_held);
		ctl_kcb_require_clearing(kcb, mtx_held);
		struct kctl             *kctl = kcb->kctl;

		if (kctl && kctl->disconnect) {
			socket_unlock(so, 0);
			(*kctl->disconnect)(kctl->kctlref, kcb->sac.sc_unit,
			    kcb->userdata);
			socket_lock(so, 0);
		}

		soisdisconnected(so);
#if DEVELOPMENT || DEBUG
		kcb->status = KCTL_DISCONNECTED;
#endif /* DEVELOPMENT || DEBUG */

		socket_unlock(so, 0);
		lck_mtx_lock(ctl_mtx);
		kcb->kctl = 0;
		kcb->sac.sc_unit = 0;
		while (kcb->usecount != 0) {
			msleep(&kcb->usecount, ctl_mtx, 0, "kcb->usecount", 0);
		}
		TAILQ_REMOVE(&kctl->kcb_head, kcb, next);
		kctlstat.kcs_pcbcount--;
		kctlstat.kcs_gencnt++;
		lck_mtx_unlock(ctl_mtx);
		socket_lock(so, 0);
		ctl_kcb_done_clearing(kcb);
		ctl_kcb_decrement_use_count(kcb);
	}
	return 0;
}

static int
ctl_peeraddr(struct socket *so, struct sockaddr **nam)
{
	struct ctl_cb           *kcb = (struct ctl_cb *)so->so_pcb;
	struct kctl                     *kctl;
	struct sockaddr_ctl     sc;

	if (kcb == NULL) {      /* sanity check */
		return ENOTCONN;
	}

	if ((kctl = kcb->kctl) == NULL) {
		return EINVAL;
	}

	bzero(&sc, sizeof(struct sockaddr_ctl));
	sc.sc_len = sizeof(struct sockaddr_ctl);
	sc.sc_family = AF_SYSTEM;
	sc.ss_sysaddr = AF_SYS_CONTROL;
	sc.sc_id =  kctl->id;
	sc.sc_unit = kcb->sac.sc_unit;

	*nam = dup_sockaddr((struct sockaddr *)&sc, 1);

	return 0;
}

static void
ctl_sbrcv_trim(struct socket *so)
{
	struct sockbuf *sb = &so->so_rcv;

	if (sb->sb_hiwat > sb->sb_idealsize) {
		u_int32_t diff;
		int32_t trim;

		/*
		 * The difference between the ideal size and the
		 * current size is the upper bound of the trimage
		 */
		diff = sb->sb_hiwat - sb->sb_idealsize;
		/*
		 * We cannot trim below the outstanding data
		 */
		trim = sb->sb_hiwat - sb->sb_cc;

		trim = imin(trim, (int32_t)diff);

		if (trim > 0) {
			sbreserve(sb, (sb->sb_hiwat - trim));

			if (ctl_debug) {
				printf("%s - shrunk to %d\n",
				    __func__, sb->sb_hiwat);
			}
		}
	}
}

static int
ctl_usr_rcvd(struct socket *so, int flags)
{
	int                     error = 0;
	struct ctl_cb           *kcb = (struct ctl_cb *)so->so_pcb;
	struct kctl                     *kctl;

	if (kcb == NULL) {
		return ENOTCONN;
	}

	lck_mtx_t *mtx_held = socket_getlock(so, PR_F_WILLUNLOCK);
	ctl_kcb_increment_use_count(kcb, mtx_held);

	if ((kctl = kcb->kctl) == NULL) {
		error = EINVAL;
		goto out;
	}

	if (kctl->rcvd) {
		socket_unlock(so, 0);
		(*kctl->rcvd)(kctl->kctlref, kcb->sac.sc_unit, kcb->userdata, flags);
		socket_lock(so, 0);
	}

	ctl_sbrcv_trim(so);

out:
	ctl_kcb_decrement_use_count(kcb);
	return error;
}

static int
ctl_send(struct socket *so, int flags, struct mbuf *m,
    struct sockaddr *addr, struct mbuf *control,
    struct proc *p)
{
#pragma unused(addr, p)
	int             error = 0;
	struct ctl_cb   *kcb = (struct ctl_cb *)so->so_pcb;
	struct kctl     *kctl;

	if (control) {
		m_freem(control);
	}

	if (kcb == NULL) {      /* sanity check */
		error = ENOTCONN;
	}

	lck_mtx_t *mtx_held = socket_getlock(so, PR_F_WILLUNLOCK);
	ctl_kcb_increment_use_count(kcb, mtx_held);

	if (error == 0 && (kctl = kcb->kctl) == NULL) {
		error = EINVAL;
	}

	if (error == 0 && kctl->send) {
		so_tc_update_stats(m, so, m_get_service_class(m));
		socket_unlock(so, 0);
		error = (*kctl->send)(kctl->kctlref, kcb->sac.sc_unit, kcb->userdata,
		    m, flags);
		socket_lock(so, 0);
	} else {
		m_freem(m);
		if (error == 0) {
			error = ENOTSUP;
		}
	}
	if (error != 0) {
		OSIncrementAtomic64((SInt64 *)&kctlstat.kcs_send_fail);
	}
	ctl_kcb_decrement_use_count(kcb);

	return error;
}

static int
ctl_send_list(struct socket *so, int flags, struct mbuf *m,
    __unused struct sockaddr *addr, struct mbuf *control,
    __unused struct proc *p)
{
	int             error = 0;
	struct ctl_cb   *kcb = (struct ctl_cb *)so->so_pcb;
	struct kctl     *kctl;

	if (control) {
		m_freem_list(control);
	}

	if (kcb == NULL) {      /* sanity check */
		error = ENOTCONN;
	}

	lck_mtx_t *mtx_held = socket_getlock(so, PR_F_WILLUNLOCK);
	ctl_kcb_increment_use_count(kcb, mtx_held);

	if (error == 0 && (kctl = kcb->kctl) == NULL) {
		error = EINVAL;
	}

	if (error == 0 && kctl->send_list) {
		struct mbuf *nxt;

		for (nxt = m; nxt != NULL; nxt = nxt->m_nextpkt) {
			so_tc_update_stats(nxt, so, m_get_service_class(nxt));
		}

		socket_unlock(so, 0);
		error = (*kctl->send_list)(kctl->kctlref, kcb->sac.sc_unit,
		    kcb->userdata, m, flags);
		socket_lock(so, 0);
	} else if (error == 0 && kctl->send) {
		while (m != NULL && error == 0) {
			struct mbuf *nextpkt = m->m_nextpkt;

			m->m_nextpkt = NULL;
			so_tc_update_stats(m, so, m_get_service_class(m));
			socket_unlock(so, 0);
			error = (*kctl->send)(kctl->kctlref, kcb->sac.sc_unit,
			    kcb->userdata, m, flags);
			socket_lock(so, 0);
			m = nextpkt;
		}
		if (m != NULL) {
			m_freem_list(m);
		}
	} else {
		m_freem_list(m);
		if (error == 0) {
			error = ENOTSUP;
		}
	}
	if (error != 0) {
		OSIncrementAtomic64((SInt64 *)&kctlstat.kcs_send_list_fail);
	}
	ctl_kcb_decrement_use_count(kcb);

	return error;
}

static errno_t
ctl_rcvbspace(struct socket *so, u_int32_t datasize,
    u_int32_t kctlflags, u_int32_t flags)
{
	struct sockbuf *sb = &so->so_rcv;
	u_int32_t space = sbspace(sb);
	errno_t error;

	if ((kctlflags & CTL_FLAG_REG_CRIT) == 0) {
		if ((u_int32_t) space >= datasize) {
			error = 0;
		} else {
			error = ENOBUFS;
		}
	} else if ((flags & CTL_DATA_CRIT) == 0) {
		/*
		 * Reserve 25% for critical messages
		 */
		if (space < (sb->sb_hiwat >> 2) ||
		    space < datasize) {
			error = ENOBUFS;
		} else {
			error = 0;
		}
	} else {
		u_int32_t autorcvbuf_max;

		/*
		 * Allow overcommit of 25%
		 */
		autorcvbuf_max = min(sb->sb_idealsize + (sb->sb_idealsize >> 2),
		    ctl_autorcvbuf_max);

		if ((u_int32_t) space >= datasize) {
			error = 0;
		} else if (tcp_cansbgrow(sb) &&
		    sb->sb_hiwat < autorcvbuf_max) {
			/*
			 * Grow with a little bit of leeway
			 */
			u_int32_t grow = datasize - space + MSIZE;

			if (sbreserve(sb,
			    min((sb->sb_hiwat + grow), autorcvbuf_max)) == 1) {
				if (sb->sb_hiwat > ctl_autorcvbuf_high) {
					ctl_autorcvbuf_high = sb->sb_hiwat;
				}

				/*
				 * A final check
				 */
				if ((u_int32_t) sbspace(sb) >= datasize) {
					error = 0;
				} else {
					error = ENOBUFS;
				}

				if (ctl_debug) {
					printf("%s - grown to %d error %d\n",
					    __func__, sb->sb_hiwat, error);
				}
			} else {
				error = ENOBUFS;
			}
		} else {
			error = ENOBUFS;
		}
	}
	return error;
}

errno_t
ctl_enqueuembuf(kern_ctl_ref kctlref, u_int32_t unit, struct mbuf *m,
    u_int32_t flags)
{
	struct socket   *so;
	errno_t         error = 0;
	int             len = m->m_pkthdr.len;
	u_int32_t       kctlflags;

	so = kcb_find_socket(kctlref, unit, &kctlflags);
	if (so == NULL) {
		return EINVAL;
	}

	if (ctl_rcvbspace(so, len, kctlflags, flags) != 0) {
		error = ENOBUFS;
		OSIncrementAtomic64((SInt64 *)&kctlstat.kcs_enqueue_fullsock);
		goto bye;
	}
	if ((flags & CTL_DATA_EOR)) {
		m->m_flags |= M_EOR;
	}

	so_recv_data_stat(so, m, 0);
	if (sbappend_nodrop(&so->so_rcv, m) != 0) {
		if ((flags & CTL_DATA_NOWAKEUP) == 0) {
			sorwakeup(so);
		}
	} else {
		error = ENOBUFS;
		OSIncrementAtomic64((SInt64 *)&kctlstat.kcs_enqueue_fullsock);
	}
bye:
	if (ctl_debug && error != 0 && (flags & CTL_DATA_CRIT)) {
		printf("%s - crit data err %d len %d hiwat %d cc: %d\n",
		    __func__, error, len,
		    so->so_rcv.sb_hiwat, so->so_rcv.sb_cc);
	}

	socket_unlock(so, 1);
	if (error != 0) {
		OSIncrementAtomic64((SInt64 *)&kctlstat.kcs_enqueue_fail);
	}

	return error;
}

/*
 * Compute space occupied by mbuf like sbappendrecord
 */
static int
m_space(struct mbuf *m)
{
	int space = 0;
	struct mbuf *nxt;

	for (nxt = m; nxt != NULL; nxt = nxt->m_next) {
		space += nxt->m_len;
	}

	return space;
}

errno_t
ctl_enqueuembuf_list(void *kctlref, u_int32_t unit, struct mbuf *m_list,
    u_int32_t flags, struct mbuf **m_remain)
{
	struct socket *so = NULL;
	errno_t error = 0;
	struct mbuf *m, *nextpkt;
	int needwakeup = 0;
	int len = 0;
	u_int32_t kctlflags;

	/*
	 * Need to point the beginning of the list in case of early exit
	 */
	m = m_list;

	/*
	 * kcb_find_socket takes the socket lock with a reference
	 */
	so = kcb_find_socket(kctlref, unit, &kctlflags);
	if (so == NULL) {
		error = EINVAL;
		goto done;
	}

	if (kctlflags & CTL_FLAG_REG_SOCK_STREAM) {
		error = EOPNOTSUPP;
		goto done;
	}
	if (flags & CTL_DATA_EOR) {
		error = EINVAL;
		goto done;
	}

	for (m = m_list; m != NULL; m = nextpkt) {
		nextpkt = m->m_nextpkt;

		if (m->m_pkthdr.len == 0 && ctl_debug) {
			printf("%s: %llx m_pkthdr.len is 0",
			    __func__, (uint64_t)VM_KERNEL_ADDRPERM(m));
		}

		/*
		 * The mbuf is either appended or freed by sbappendrecord()
		 * so it's not reliable from a data standpoint
		 */
		len = m_space(m);
		if (ctl_rcvbspace(so, len, kctlflags, flags) != 0) {
			error = ENOBUFS;
			OSIncrementAtomic64(
				(SInt64 *)&kctlstat.kcs_enqueue_fullsock);
			break;
		} else {
			/*
			 * Unlink from the list, m is on its own
			 */
			m->m_nextpkt = NULL;
			so_recv_data_stat(so, m, 0);
			if (sbappendrecord_nodrop(&so->so_rcv, m) != 0) {
				needwakeup = 1;
			} else {
				/*
				 * We free or return the remaining
				 * mbufs in the list
				 */
				m = nextpkt;
				error = ENOBUFS;
				OSIncrementAtomic64(
					(SInt64 *)&kctlstat.kcs_enqueue_fullsock);
				break;
			}
		}
	}
	if (needwakeup && (flags & CTL_DATA_NOWAKEUP) == 0) {
		sorwakeup(so);
	}

done:
	if (so != NULL) {
		if (ctl_debug && error != 0 && (flags & CTL_DATA_CRIT)) {
			printf("%s - crit data err %d len %d hiwat %d cc: %d\n",
			    __func__, error, len,
			    so->so_rcv.sb_hiwat, so->so_rcv.sb_cc);
		}

		socket_unlock(so, 1);
	}
	if (m_remain) {
		*m_remain = m;

		if (m != NULL && socket_debug && so != NULL &&
		    (so->so_options & SO_DEBUG)) {
			struct mbuf *n;

			printf("%s m_list %llx\n", __func__,
			    (uint64_t) VM_KERNEL_ADDRPERM(m_list));
			for (n = m; n != NULL; n = n->m_nextpkt) {
				printf(" remain %llx m_next %llx\n",
				    (uint64_t) VM_KERNEL_ADDRPERM(n),
				    (uint64_t) VM_KERNEL_ADDRPERM(n->m_next));
			}
		}
	} else {
		if (m != NULL) {
			m_freem_list(m);
		}
	}
	if (error != 0) {
		OSIncrementAtomic64((SInt64 *)&kctlstat.kcs_enqueue_fail);
	}
	return error;
}

errno_t
ctl_enqueuedata(void *kctlref, u_int32_t unit, void *data, size_t len,
    u_int32_t flags)
{
	struct socket   *so;
	struct mbuf     *m;
	errno_t         error = 0;
	unsigned int    num_needed;
	struct mbuf     *n;
	size_t          curlen = 0;
	u_int32_t       kctlflags;

	so = kcb_find_socket(kctlref, unit, &kctlflags);
	if (so == NULL) {
		return EINVAL;
	}

	if (ctl_rcvbspace(so, len, kctlflags, flags) != 0) {
		error = ENOBUFS;
		OSIncrementAtomic64((SInt64 *)&kctlstat.kcs_enqueue_fullsock);
		goto bye;
	}

	num_needed = 1;
	m = m_allocpacket_internal(&num_needed, len, NULL, M_NOWAIT, 1, 0);
	if (m == NULL) {
		kctlstat.kcs_enqdata_mb_alloc_fail++;
		if (ctl_debug) {
			printf("%s: m_allocpacket_internal(%lu) failed\n",
			    __func__, len);
		}
		error = ENOMEM;
		goto bye;
	}

	for (n = m; n != NULL; n = n->m_next) {
		size_t mlen = mbuf_maxlen(n);

		if (mlen + curlen > len) {
			mlen = len - curlen;
		}
		n->m_len = mlen;
		bcopy((char *)data + curlen, n->m_data, mlen);
		curlen += mlen;
	}
	mbuf_pkthdr_setlen(m, curlen);

	if ((flags & CTL_DATA_EOR)) {
		m->m_flags |= M_EOR;
	}
	so_recv_data_stat(so, m, 0);
	/*
	 * No need to call the "nodrop" variant of sbappend
	 * because the mbuf is local to the scope of the function
	 */
	if (sbappend(&so->so_rcv, m) != 0) {
		if ((flags & CTL_DATA_NOWAKEUP) == 0) {
			sorwakeup(so);
		}
	} else {
		kctlstat.kcs_enqdata_sbappend_fail++;
		error = ENOBUFS;
		OSIncrementAtomic64((SInt64 *)&kctlstat.kcs_enqueue_fullsock);
	}

bye:
	if (ctl_debug && error != 0 && (flags & CTL_DATA_CRIT)) {
		printf("%s - crit data err %d len %d hiwat %d cc: %d\n",
		    __func__, error, (int)len,
		    so->so_rcv.sb_hiwat, so->so_rcv.sb_cc);
	}

	socket_unlock(so, 1);
	if (error != 0) {
		OSIncrementAtomic64((SInt64 *)&kctlstat.kcs_enqueue_fail);
	}
	return error;
}

errno_t
ctl_getenqueuepacketcount(kern_ctl_ref kctlref, u_int32_t unit, u_int32_t *pcnt)
{
	struct socket   *so;
	u_int32_t cnt;
	struct mbuf *m1;

	if (pcnt == NULL) {
		return EINVAL;
	}

	so = kcb_find_socket(kctlref, unit, NULL);
	if (so == NULL) {
		return EINVAL;
	}

	cnt = 0;
	m1 = so->so_rcv.sb_mb;
	while (m1 != NULL) {
		if (m1->m_type == MT_DATA ||
		    m1->m_type == MT_HEADER ||
		    m1->m_type == MT_OOBDATA) {
			cnt += 1;
		}
		m1 = m1->m_nextpkt;
	}
	*pcnt = cnt;

	socket_unlock(so, 1);

	return 0;
}

errno_t
ctl_getenqueuespace(kern_ctl_ref kctlref, u_int32_t unit, size_t *space)
{
	struct socket   *so;
	long avail;

	if (space == NULL) {
		return EINVAL;
	}

	so = kcb_find_socket(kctlref, unit, NULL);
	if (so == NULL) {
		return EINVAL;
	}

	avail = sbspace(&so->so_rcv);
	*space = (avail < 0) ? 0 : avail;
	socket_unlock(so, 1);

	return 0;
}

errno_t
ctl_getenqueuereadable(kern_ctl_ref kctlref, u_int32_t unit,
    u_int32_t *difference)
{
	struct socket   *so;

	if (difference == NULL) {
		return EINVAL;
	}

	so = kcb_find_socket(kctlref, unit, NULL);
	if (so == NULL) {
		return EINVAL;
	}

	if (so->so_rcv.sb_cc >= so->so_rcv.sb_lowat) {
		*difference = 0;
	} else {
		*difference = (so->so_rcv.sb_lowat - so->so_rcv.sb_cc);
	}
	socket_unlock(so, 1);

	return 0;
}

static int
ctl_ctloutput(struct socket *so, struct sockopt *sopt)
{
	struct ctl_cb   *kcb = (struct ctl_cb *)so->so_pcb;
	struct kctl     *kctl;
	int     error = 0;
	void    *data = NULL;
	size_t  len;

	if (sopt->sopt_level != SYSPROTO_CONTROL) {
		return EINVAL;
	}

	if (kcb == NULL) {      /* sanity check */
		return ENOTCONN;
	}

	if ((kctl = kcb->kctl) == NULL) {
		return EINVAL;
	}

	lck_mtx_t *mtx_held = socket_getlock(so, PR_F_WILLUNLOCK);
	ctl_kcb_increment_use_count(kcb, mtx_held);

	switch (sopt->sopt_dir) {
	case SOPT_SET:
		if (kctl->setopt == NULL) {
			error = ENOTSUP;
			goto out;
		}
		if (sopt->sopt_valsize != 0) {
			MALLOC(data, void *, sopt->sopt_valsize, M_TEMP,
			    M_WAITOK | M_ZERO);
			if (data == NULL) {
				error = ENOMEM;
				goto out;
			}
			error = sooptcopyin(sopt, data,
			    sopt->sopt_valsize, sopt->sopt_valsize);
		}
		if (error == 0) {
			socket_unlock(so, 0);
			error = (*kctl->setopt)(kctl->kctlref,
			    kcb->sac.sc_unit, kcb->userdata, sopt->sopt_name,
			    data, sopt->sopt_valsize);
			socket_lock(so, 0);
		}

		if (data != NULL) {
			FREE(data, M_TEMP);
		}
		break;

	case SOPT_GET:
		if (kctl->getopt == NULL) {
			error = ENOTSUP;
			goto out;
		}

		if (sopt->sopt_valsize && sopt->sopt_val) {
			MALLOC(data, void *, sopt->sopt_valsize, M_TEMP,
			    M_WAITOK | M_ZERO);
			if (data == NULL) {
				error = ENOMEM;
				goto out;
			}
			/*
			 * 4108337 - copy user data in case the
			 * kernel control needs it
			 */
			error = sooptcopyin(sopt, data,
			    sopt->sopt_valsize, sopt->sopt_valsize);
		}

		if (error == 0) {
			len = sopt->sopt_valsize;
			socket_unlock(so, 0);
			error = (*kctl->getopt)(kctl->kctlref, kcb->sac.sc_unit,
			    kcb->userdata, sopt->sopt_name,
			    data, &len);
			if (data != NULL && len > sopt->sopt_valsize) {
				panic_plain("ctl_ctloutput: ctl %s returned "
				    "len (%lu) > sopt_valsize (%lu)\n",
				    kcb->kctl->name, len,
				    sopt->sopt_valsize);
			}
			socket_lock(so, 0);
			if (error == 0) {
				if (data != NULL) {
					error = sooptcopyout(sopt, data, len);
				} else {
					sopt->sopt_valsize = len;
				}
			}
		}
		if (data != NULL) {
			FREE(data, M_TEMP);
		}
		break;
	}

out:
	ctl_kcb_decrement_use_count(kcb);
	return error;
}

static int
ctl_ioctl(struct socket *so, u_long cmd, caddr_t data,
    struct ifnet *ifp, struct proc *p)
{
#pragma unused(so, ifp, p)
	int     error = ENOTSUP;

	switch (cmd) {
	/* get the number of controllers */
	case CTLIOCGCOUNT: {
		struct kctl     *kctl;
		u_int32_t n = 0;

		lck_mtx_lock(ctl_mtx);
		TAILQ_FOREACH(kctl, &ctl_head, next)
		n++;
		lck_mtx_unlock(ctl_mtx);

		bcopy(&n, data, sizeof(n));
		error = 0;
		break;
	}
	case CTLIOCGINFO: {
		struct ctl_info ctl_info;
		struct kctl     *kctl = 0;
		size_t name_len;

		bcopy(data, &ctl_info, sizeof(ctl_info));
		name_len = strnlen(ctl_info.ctl_name, MAX_KCTL_NAME);

		if (name_len == 0 || name_len + 1 > MAX_KCTL_NAME) {
			error = EINVAL;
			break;
		}
		lck_mtx_lock(ctl_mtx);
		kctl = ctl_find_by_name(ctl_info.ctl_name);
		lck_mtx_unlock(ctl_mtx);
		if (kctl == 0) {
			error = ENOENT;
			break;
		}
		ctl_info.ctl_id = kctl->id;
		bcopy(&ctl_info, data, sizeof(ctl_info));
		error = 0;
		break;
	}

		/* add controls to get list of NKEs */
	}

	return error;
}

static void
kctl_tbl_grow()
{
	struct kctl **new_table;
	uintptr_t new_size;

	lck_mtx_assert(ctl_mtx, LCK_MTX_ASSERT_OWNED);

	if (kctl_tbl_growing) {
		/* Another thread is allocating */
		kctl_tbl_growing_waiting++;

		do {
			(void) msleep((caddr_t) &kctl_tbl_growing, ctl_mtx,
			    PSOCK | PCATCH, "kctl_tbl_growing", 0);
		} while (kctl_tbl_growing);
		kctl_tbl_growing_waiting--;
	}
	/* Another thread grew the table */
	if (kctl_table != NULL && kctl_tbl_count < kctl_tbl_size) {
		return;
	}

	/* Verify we have a sane size */
	if (kctl_tbl_size + KCTL_TBL_INC >= UINT16_MAX) {
		kctlstat.kcs_tbl_size_too_big++;
		if (ctl_debug) {
			printf("%s kctl_tbl_size %lu too big\n",
			    __func__, kctl_tbl_size);
		}
		return;
	}
	kctl_tbl_growing = 1;

	new_size = kctl_tbl_size + KCTL_TBL_INC;

	lck_mtx_unlock(ctl_mtx);
	new_table = _MALLOC(sizeof(struct kctl *) * new_size,
	    M_TEMP, M_WAIT | M_ZERO);
	lck_mtx_lock(ctl_mtx);

	if (new_table != NULL) {
		if (kctl_table != NULL) {
			bcopy(kctl_table, new_table,
			    kctl_tbl_size * sizeof(struct kctl *));

			_FREE(kctl_table, M_TEMP);
		}
		kctl_table = new_table;
		kctl_tbl_size = new_size;
	}

	kctl_tbl_growing = 0;

	if (kctl_tbl_growing_waiting) {
		wakeup(&kctl_tbl_growing);
	}
}

#define KCTLREF_INDEX_MASK 0x0000FFFF
#define KCTLREF_GENCNT_MASK 0xFFFF0000
#define KCTLREF_GENCNT_SHIFT 16

static kern_ctl_ref
kctl_make_ref(struct kctl *kctl)
{
	uintptr_t i;

	lck_mtx_assert(ctl_mtx, LCK_MTX_ASSERT_OWNED);

	if (kctl_tbl_count >= kctl_tbl_size) {
		kctl_tbl_grow();
	}

	kctl->kctlref = NULL;
	for (i = 0; i < kctl_tbl_size; i++) {
		if (kctl_table[i] == NULL) {
			uintptr_t ref;

			/*
			 * Reference is index plus one
			 */
			kctl_ref_gencnt += 1;

			/*
			 * Add generation count as salt to reference to prevent
			 * use after deregister
			 */
			ref = ((kctl_ref_gencnt << KCTLREF_GENCNT_SHIFT) &
			    KCTLREF_GENCNT_MASK) +
			    ((i + 1) & KCTLREF_INDEX_MASK);

			kctl->kctlref = (void *)(ref);
			kctl_table[i] = kctl;
			kctl_tbl_count++;
			break;
		}
	}

	if (kctl->kctlref == NULL) {
		panic("%s no space in table", __func__);
	}

	if (ctl_debug > 0) {
		printf("%s %p for %p\n",
		    __func__, kctl->kctlref, kctl);
	}

	return kctl->kctlref;
}

static void
kctl_delete_ref(kern_ctl_ref kctlref)
{
	/*
	 * Reference is index plus one
	 */
	uintptr_t i = (((uintptr_t)kctlref) & KCTLREF_INDEX_MASK) - 1;

	lck_mtx_assert(ctl_mtx, LCK_MTX_ASSERT_OWNED);

	if (i < kctl_tbl_size) {
		struct kctl *kctl = kctl_table[i];

		if (kctl->kctlref == kctlref) {
			kctl_table[i] = NULL;
			kctl_tbl_count--;
		} else {
			kctlstat.kcs_bad_kctlref++;
		}
	} else {
		kctlstat.kcs_bad_kctlref++;
	}
}

static struct kctl *
kctl_from_ref(kern_ctl_ref kctlref)
{
	/*
	 * Reference is index plus one
	 */
	uintptr_t i = (((uintptr_t)kctlref) & KCTLREF_INDEX_MASK) - 1;
	struct kctl *kctl = NULL;

	lck_mtx_assert(ctl_mtx, LCK_MTX_ASSERT_OWNED);

	if (i >= kctl_tbl_size) {
		kctlstat.kcs_bad_kctlref++;
		return NULL;
	}
	kctl = kctl_table[i];
	if (kctl->kctlref != kctlref) {
		kctlstat.kcs_bad_kctlref++;
		return NULL;
	}
	return kctl;
}

/*
 * Register/unregister a NKE
 */
errno_t
ctl_register(struct kern_ctl_reg *userkctl, kern_ctl_ref *kctlref)
{
	struct kctl     *kctl = NULL;
	struct kctl     *kctl_next = NULL;
	u_int32_t       id = 1;
	size_t          name_len;
	int             is_extended = 0;

	if (userkctl == NULL) { /* sanity check */
		return EINVAL;
	}
	if (userkctl->ctl_connect == NULL) {
		return EINVAL;
	}
	name_len = strlen(userkctl->ctl_name);
	if (name_len == 0 || name_len + 1 > MAX_KCTL_NAME) {
		return EINVAL;
	}

	MALLOC(kctl, struct kctl *, sizeof(*kctl), M_TEMP, M_WAITOK);
	if (kctl == NULL) {
		return ENOMEM;
	}
	bzero((char *)kctl, sizeof(*kctl));

	lck_mtx_lock(ctl_mtx);

	if (kctl_make_ref(kctl) == NULL) {
		lck_mtx_unlock(ctl_mtx);
		FREE(kctl, M_TEMP);
		return ENOMEM;
	}

	/*
	 * Kernel Control IDs
	 *
	 * CTL_FLAG_REG_ID_UNIT indicates the control ID and unit number are
	 * static. If they do not exist, add them to the list in order. If the
	 * flag is not set, we must find a new unique value. We assume the
	 * list is in order. We find the last item in the list and add one. If
	 * this leads to wrapping the id around, we start at the front of the
	 * list and look for a gap.
	 */

	if ((userkctl->ctl_flags & CTL_FLAG_REG_ID_UNIT) == 0) {
		/* Must dynamically assign an unused ID */

		/* Verify the same name isn't already registered */
		if (ctl_find_by_name(userkctl->ctl_name) != NULL) {
			kctl_delete_ref(kctl->kctlref);
			lck_mtx_unlock(ctl_mtx);
			FREE(kctl, M_TEMP);
			return EEXIST;
		}

		/* Start with 1 in case the list is empty */
		id = 1;
		kctl_next = TAILQ_LAST(&ctl_head, kctl_list);

		if (kctl_next != NULL) {
			/* List was not empty, add one to the last item */
			id = kctl_next->id + 1;
			kctl_next = NULL;

			/*
			 * If this wrapped the id number, start looking at
			 * the front of the list for an unused id.
			 */
			if (id == 0) {
				/* Find the next unused ID */
				id = 1;

				TAILQ_FOREACH(kctl_next, &ctl_head, next) {
					if (kctl_next->id > id) {
						/* We found a gap */
						break;
					}

					id = kctl_next->id + 1;
				}
			}
		}

		userkctl->ctl_id = id;
		kctl->id = id;
		kctl->reg_unit = -1;
	} else {
		TAILQ_FOREACH(kctl_next, &ctl_head, next) {
			if (kctl_next->id > userkctl->ctl_id) {
				break;
			}
		}

		if (ctl_find_by_id_unit(userkctl->ctl_id, userkctl->ctl_unit)) {
			kctl_delete_ref(kctl->kctlref);
			lck_mtx_unlock(ctl_mtx);
			FREE(kctl, M_TEMP);
			return EEXIST;
		}
		kctl->id = userkctl->ctl_id;
		kctl->reg_unit = userkctl->ctl_unit;
	}

	is_extended = (userkctl->ctl_flags & CTL_FLAG_REG_EXTENDED);

	strlcpy(kctl->name, userkctl->ctl_name, MAX_KCTL_NAME);
	kctl->flags = userkctl->ctl_flags;

	/*
	 * Let the caller know the default send and receive sizes
	 */
	if (userkctl->ctl_sendsize == 0) {
		kctl->sendbufsize = CTL_SENDSIZE;
		userkctl->ctl_sendsize = kctl->sendbufsize;
	} else {
		kctl->sendbufsize = userkctl->ctl_sendsize;
	}
	if (userkctl->ctl_recvsize == 0) {
		kctl->recvbufsize = CTL_RECVSIZE;
		userkctl->ctl_recvsize = kctl->recvbufsize;
	} else {
		kctl->recvbufsize = userkctl->ctl_recvsize;
	}

	kctl->bind = userkctl->ctl_bind;
	kctl->connect = userkctl->ctl_connect;
	kctl->disconnect = userkctl->ctl_disconnect;
	kctl->send = userkctl->ctl_send;
	kctl->setopt = userkctl->ctl_setopt;
	kctl->getopt = userkctl->ctl_getopt;
	if (is_extended) {
		kctl->rcvd = userkctl->ctl_rcvd;
		kctl->send_list = userkctl->ctl_send_list;
	}

	TAILQ_INIT(&kctl->kcb_head);

	if (kctl_next) {
		TAILQ_INSERT_BEFORE(kctl_next, kctl, next);
	} else {
		TAILQ_INSERT_TAIL(&ctl_head, kctl, next);
	}

	kctlstat.kcs_reg_count++;
	kctlstat.kcs_gencnt++;

	lck_mtx_unlock(ctl_mtx);

	*kctlref = kctl->kctlref;

	ctl_post_msg(KEV_CTL_REGISTERED, kctl->id);
	return 0;
}

errno_t
ctl_deregister(void *kctlref)
{
	struct kctl             *kctl;

	lck_mtx_lock(ctl_mtx);
	if ((kctl = kctl_from_ref(kctlref)) == NULL) {
		kctlstat.kcs_bad_kctlref++;
		lck_mtx_unlock(ctl_mtx);
		if (ctl_debug != 0) {
			printf("%s invalid kctlref %p\n",
			    __func__, kctlref);
		}
		return EINVAL;
	}

	if (!TAILQ_EMPTY(&kctl->kcb_head)) {
		lck_mtx_unlock(ctl_mtx);
		return EBUSY;
	}

	TAILQ_REMOVE(&ctl_head, kctl, next);

	kctlstat.kcs_reg_count--;
	kctlstat.kcs_gencnt++;

	kctl_delete_ref(kctl->kctlref);
	lck_mtx_unlock(ctl_mtx);

	ctl_post_msg(KEV_CTL_DEREGISTERED, kctl->id);
	FREE(kctl, M_TEMP);
	return 0;
}

/*
 * Must be called with global ctl_mtx lock taked
 */
static struct kctl *
ctl_find_by_name(const char *name)
{
	struct kctl     *kctl;

	lck_mtx_assert(ctl_mtx, LCK_MTX_ASSERT_OWNED);

	TAILQ_FOREACH(kctl, &ctl_head, next)
	if (strncmp(kctl->name, name, sizeof(kctl->name)) == 0) {
		return kctl;
	}

	return NULL;
}

u_int32_t
ctl_id_by_name(const char *name)
{
	u_int32_t       ctl_id = 0;
	struct kctl     *kctl;

	lck_mtx_lock(ctl_mtx);
	kctl = ctl_find_by_name(name);
	if (kctl) {
		ctl_id = kctl->id;
	}
	lck_mtx_unlock(ctl_mtx);

	return ctl_id;
}

errno_t
ctl_name_by_id(u_int32_t id, char *out_name, size_t maxsize)
{
	int             found = 0;
	struct kctl *kctl;

	lck_mtx_lock(ctl_mtx);
	TAILQ_FOREACH(kctl, &ctl_head, next) {
		if (kctl->id == id) {
			break;
		}
	}

	if (kctl) {
		if (maxsize > MAX_KCTL_NAME) {
			maxsize = MAX_KCTL_NAME;
		}
		strlcpy(out_name, kctl->name, maxsize);
		found = 1;
	}
	lck_mtx_unlock(ctl_mtx);

	return found ? 0 : ENOENT;
}

/*
 * Must be called with global ctl_mtx lock taked
 *
 */
static struct kctl *
ctl_find_by_id_unit(u_int32_t id, u_int32_t unit)
{
	struct kctl     *kctl;

	lck_mtx_assert(ctl_mtx, LCK_MTX_ASSERT_OWNED);

	TAILQ_FOREACH(kctl, &ctl_head, next) {
		if (kctl->id == id && (kctl->flags & CTL_FLAG_REG_ID_UNIT) == 0) {
			return kctl;
		} else if (kctl->id == id && kctl->reg_unit == unit) {
			return kctl;
		}
	}
	return NULL;
}

/*
 * Must be called with kernel controller lock taken
 */
static struct ctl_cb *
kcb_find(struct kctl *kctl, u_int32_t unit)
{
	struct ctl_cb   *kcb;

	lck_mtx_assert(ctl_mtx, LCK_MTX_ASSERT_OWNED);

	TAILQ_FOREACH(kcb, &kctl->kcb_head, next)
	if (kcb->sac.sc_unit == unit) {
		return kcb;
	}

	return NULL;
}

static struct socket *
kcb_find_socket(kern_ctl_ref kctlref, u_int32_t unit, u_int32_t *kctlflags)
{
	struct socket *so = NULL;
	struct ctl_cb   *kcb;
	void *lr_saved;
	struct kctl *kctl;
	int i;

	lr_saved = __builtin_return_address(0);

	lck_mtx_lock(ctl_mtx);
	/*
	 * First validate the kctlref
	 */
	if ((kctl = kctl_from_ref(kctlref)) == NULL) {
		kctlstat.kcs_bad_kctlref++;
		lck_mtx_unlock(ctl_mtx);
		if (ctl_debug != 0) {
			printf("%s invalid kctlref %p\n",
			    __func__, kctlref);
		}
		return NULL;
	}

	kcb = kcb_find(kctl, unit);
	if (kcb == NULL || kcb->kctl != kctl || (so = kcb->so) == NULL) {
		lck_mtx_unlock(ctl_mtx);
		return NULL;
	}
	/*
	 * This prevents the socket from being closed
	 */
	kcb->usecount++;
	/*
	 * Respect lock ordering: socket before ctl_mtx
	 */
	lck_mtx_unlock(ctl_mtx);

	socket_lock(so, 1);
	/*
	 * The socket lock history is more useful if we store
	 * the address of the caller.
	 */
	i = (so->next_lock_lr + SO_LCKDBG_MAX - 1) % SO_LCKDBG_MAX;
	so->lock_lr[i] = lr_saved;

	lck_mtx_lock(ctl_mtx);

	if ((kctl = kctl_from_ref(kctlref)) == NULL || kcb->kctl == NULL) {
		lck_mtx_unlock(ctl_mtx);
		socket_unlock(so, 1);
		so = NULL;
		lck_mtx_lock(ctl_mtx);
	} else if (kctlflags != NULL) {
		*kctlflags = kctl->flags;
	}

	kcb->usecount--;
	if (kcb->usecount == 0) {
		wakeup((event_t)&kcb->usecount);
	}

	lck_mtx_unlock(ctl_mtx);

	return so;
}

static void
ctl_post_msg(u_int32_t event_code, u_int32_t id)
{
	struct ctl_event_data   ctl_ev_data;
	struct kev_msg                  ev_msg;

	lck_mtx_assert(ctl_mtx, LCK_MTX_ASSERT_NOTOWNED);

	bzero(&ev_msg, sizeof(struct kev_msg));
	ev_msg.vendor_code = KEV_VENDOR_APPLE;

	ev_msg.kev_class = KEV_SYSTEM_CLASS;
	ev_msg.kev_subclass = KEV_CTL_SUBCLASS;
	ev_msg.event_code = event_code;

	/* common nke subclass data */
	bzero(&ctl_ev_data, sizeof(ctl_ev_data));
	ctl_ev_data.ctl_id = id;
	ev_msg.dv[0].data_ptr = &ctl_ev_data;
	ev_msg.dv[0].data_length = sizeof(ctl_ev_data);

	ev_msg.dv[1].data_length = 0;

	kev_post_msg(&ev_msg);
}

static int
ctl_lock(struct socket *so, int refcount, void *lr)
{
	void *lr_saved;

	if (lr == NULL) {
		lr_saved = __builtin_return_address(0);
	} else {
		lr_saved = lr;
	}

	if (so->so_pcb != NULL) {
		lck_mtx_lock(((struct ctl_cb *)so->so_pcb)->mtx);
	} else {
		panic("ctl_lock: so=%p NO PCB! lr=%p lrh= %s\n",
		    so, lr_saved, solockhistory_nr(so));
		/* NOTREACHED */
	}

	if (so->so_usecount < 0) {
		panic("ctl_lock: so=%p so_pcb=%p lr=%p ref=%x lrh= %s\n",
		    so, so->so_pcb, lr_saved, so->so_usecount,
		    solockhistory_nr(so));
		/* NOTREACHED */
	}

	if (refcount) {
		so->so_usecount++;
	}

	so->lock_lr[so->next_lock_lr] = lr_saved;
	so->next_lock_lr = (so->next_lock_lr + 1) % SO_LCKDBG_MAX;
	return 0;
}

static int
ctl_unlock(struct socket *so, int refcount, void *lr)
{
	void *lr_saved;
	lck_mtx_t *mutex_held;

	if (lr == NULL) {
		lr_saved = __builtin_return_address(0);
	} else {
		lr_saved = lr;
	}

#if (MORE_KCTLLOCK_DEBUG && (DEVELOPMENT || DEBUG))
	printf("ctl_unlock: so=%llx sopcb=%x lock=%llx ref=%u lr=%llx\n",
	    (uint64_t)VM_KERNEL_ADDRPERM(so),
	    (uint64_t)VM_KERNEL_ADDRPERM(so->so_pcb,
	    (uint64_t)VM_KERNEL_ADDRPERM(((struct ctl_cb *)so->so_pcb)->mtx),
	    so->so_usecount, (uint64_t)VM_KERNEL_ADDRPERM(lr_saved));
#endif /* (MORE_KCTLLOCK_DEBUG && (DEVELOPMENT || DEBUG)) */
	if (refcount) {
		so->so_usecount--;
	}

	if (so->so_usecount < 0) {
		panic("ctl_unlock: so=%p usecount=%x lrh= %s\n",
		    so, so->so_usecount, solockhistory_nr(so));
		/* NOTREACHED */
	}
	if (so->so_pcb == NULL) {
		panic("ctl_unlock: so=%p NO PCB usecount=%x lr=%p lrh= %s\n",
		    so, so->so_usecount, (void *)lr_saved,
		    solockhistory_nr(so));
		/* NOTREACHED */
	}
	mutex_held = ((struct ctl_cb *)so->so_pcb)->mtx;

	    lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);
	    so->unlock_lr[so->next_unlock_lr] = lr_saved;
	    so->next_unlock_lr = (so->next_unlock_lr + 1) % SO_LCKDBG_MAX;
	    lck_mtx_unlock(mutex_held);

	    if (so->so_usecount == 0) {
		ctl_sofreelastref(so);
	}

	    return 0;
}

static lck_mtx_t *
ctl_getlock(struct socket *so, int flags)
{
#pragma unused(flags)
        struct ctl_cb *kcb = (struct ctl_cb *)so->so_pcb;

        if (so->so_pcb) {
                if (so->so_usecount < 0) {
                        panic("ctl_getlock: so=%p usecount=%x lrh= %s\n",
                            so, so->so_usecount, solockhistory_nr(so));
		}
                return kcb->mtx;
	} else {
                panic("ctl_getlock: so=%p NULL NO so_pcb %s\n",
                    so, solockhistory_nr(so));
                return so->so_proto->pr_domain->dom_mtx;
	}
}

__private_extern__ int
kctl_reg_list SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
        int error = 0;
        int n, i;
        struct xsystmgen xsg;
        void *buf = NULL;
        struct kctl *kctl;
        size_t item_size = ROUNDUP64(sizeof(struct xkctl_reg));

        buf = _MALLOC(item_size, M_TEMP, M_WAITOK | M_ZERO);
        if (buf == NULL) {
                return ENOMEM;
	}

        lck_mtx_lock(ctl_mtx);

        n = kctlstat.kcs_reg_count;

        if (req->oldptr == USER_ADDR_NULL) {
                req->oldidx = (n + n / 8) * sizeof(struct xkctl_reg);
                goto done;
	}
        if (req->newptr != USER_ADDR_NULL) {
                error = EPERM;
                goto done;
	}
        bzero(&xsg, sizeof(xsg));
        xsg.xg_len = sizeof(xsg);
        xsg.xg_count = n;
        xsg.xg_gen = kctlstat.kcs_gencnt;
        xsg.xg_sogen = so_gencnt;
        error = SYSCTL_OUT(req, &xsg, sizeof(xsg));
        if (error) {
                goto done;
	}
        /*
         * We are done if there is no pcb
         */
        if (n == 0) {
                goto done;
	}

        i = 0;
        for (i = 0, kctl = TAILQ_FIRST(&ctl_head);
            i < n && kctl != NULL;
            i++, kctl = TAILQ_NEXT(kctl, next)) {
                struct xkctl_reg *xkr = (struct xkctl_reg *)buf;
                struct ctl_cb *kcb;
                u_int32_t pcbcount = 0;

                TAILQ_FOREACH(kcb, &kctl->kcb_head, next)
                pcbcount++;

                bzero(buf, item_size);

                xkr->xkr_len = sizeof(struct xkctl_reg);
                xkr->xkr_kind = XSO_KCREG;
                xkr->xkr_id = kctl->id;
                xkr->xkr_reg_unit = kctl->reg_unit;
                xkr->xkr_flags = kctl->flags;
                xkr->xkr_kctlref = (uint64_t)(kctl->kctlref);
                xkr->xkr_recvbufsize = kctl->recvbufsize;
                xkr->xkr_sendbufsize = kctl->sendbufsize;
                xkr->xkr_lastunit = kctl->lastunit;
                xkr->xkr_pcbcount = pcbcount;
                xkr->xkr_connect = (uint64_t)VM_KERNEL_UNSLIDE(kctl->connect);
                xkr->xkr_disconnect =
                    (uint64_t)VM_KERNEL_UNSLIDE(kctl->disconnect);
                xkr->xkr_send = (uint64_t)VM_KERNEL_UNSLIDE(kctl->send);
                xkr->xkr_send_list =
                    (uint64_t)VM_KERNEL_UNSLIDE(kctl->send_list);
                xkr->xkr_setopt = (uint64_t)VM_KERNEL_UNSLIDE(kctl->setopt);
                xkr->xkr_getopt = (uint64_t)VM_KERNEL_UNSLIDE(kctl->getopt);
                xkr->xkr_rcvd = (uint64_t)VM_KERNEL_UNSLIDE(kctl->rcvd);
                strlcpy(xkr->xkr_name, kctl->name, sizeof(xkr->xkr_name));

                error = SYSCTL_OUT(req, buf, item_size);
	}

        if (error == 0) {
                /*
                 * Give the user an updated idea of our state.
                 * If the generation differs from what we told
                 * her before, she knows that something happened
                 * while we were processing this request, and it
                 * might be necessary to retry.
                 */
                bzero(&xsg, sizeof(xsg));
                xsg.xg_len = sizeof(xsg);
                xsg.xg_count = n;
                xsg.xg_gen = kctlstat.kcs_gencnt;
                xsg.xg_sogen = so_gencnt;
                error = SYSCTL_OUT(req, &xsg, sizeof(xsg));
                if (error) {
                        goto done;
		}
	}

done:
        lck_mtx_unlock(ctl_mtx);

        if (buf != NULL) {
                FREE(buf, M_TEMP);
	}

        return error;
}

__private_extern__ int
kctl_pcblist SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
        int error = 0;
        int n, i;
        struct xsystmgen xsg;
        void *buf = NULL;
        struct kctl *kctl;
        size_t item_size = ROUNDUP64(sizeof(struct xkctlpcb)) +
            ROUNDUP64(sizeof(struct xsocket_n)) +
            2 * ROUNDUP64(sizeof(struct xsockbuf_n)) +
            ROUNDUP64(sizeof(struct xsockstat_n));

        buf = _MALLOC(item_size, M_TEMP, M_WAITOK | M_ZERO);
        if (buf == NULL) {
                return ENOMEM;
	}

        lck_mtx_lock(ctl_mtx);

        n = kctlstat.kcs_pcbcount;

        if (req->oldptr == USER_ADDR_NULL) {
                req->oldidx = (n + n / 8) * item_size;
                goto done;
	}
        if (req->newptr != USER_ADDR_NULL) {
                error = EPERM;
                goto done;
	}
        bzero(&xsg, sizeof(xsg));
        xsg.xg_len = sizeof(xsg);
        xsg.xg_count = n;
        xsg.xg_gen = kctlstat.kcs_gencnt;
        xsg.xg_sogen = so_gencnt;
        error = SYSCTL_OUT(req, &xsg, sizeof(xsg));
        if (error) {
                goto done;
	}
        /*
         * We are done if there is no pcb
         */
        if (n == 0) {
                goto done;
	}

        i = 0;
        for (i = 0, kctl = TAILQ_FIRST(&ctl_head);
            i < n && kctl != NULL;
            kctl = TAILQ_NEXT(kctl, next)) {
                struct ctl_cb *kcb;

                for (kcb = TAILQ_FIRST(&kctl->kcb_head);
                    i < n && kcb != NULL;
                    i++, kcb = TAILQ_NEXT(kcb, next)) {
                        struct xkctlpcb *xk = (struct xkctlpcb *)buf;
                        struct xsocket_n *xso = (struct xsocket_n *)
                            ADVANCE64(xk, sizeof(*xk));
                        struct xsockbuf_n *xsbrcv = (struct xsockbuf_n *)
                            ADVANCE64(xso, sizeof(*xso));
                        struct xsockbuf_n *xsbsnd = (struct xsockbuf_n *)
                            ADVANCE64(xsbrcv, sizeof(*xsbrcv));
                        struct xsockstat_n *xsostats = (struct xsockstat_n *)
                            ADVANCE64(xsbsnd, sizeof(*xsbsnd));

                        bzero(buf, item_size);

                        xk->xkp_len = sizeof(struct xkctlpcb);
                        xk->xkp_kind = XSO_KCB;
                        xk->xkp_unit = kcb->sac.sc_unit;
                        xk->xkp_kctpcb = (uint64_t)VM_KERNEL_ADDRPERM(kcb);
                        xk->xkp_kctlref = (uint64_t)VM_KERNEL_ADDRPERM(kctl);
                        xk->xkp_kctlid = kctl->id;
                        strlcpy(xk->xkp_kctlname, kctl->name,
                            sizeof(xk->xkp_kctlname));

                        sotoxsocket_n(kcb->so, xso);
                        sbtoxsockbuf_n(kcb->so ?
                            &kcb->so->so_rcv : NULL, xsbrcv);
                        sbtoxsockbuf_n(kcb->so ?
                            &kcb->so->so_snd : NULL, xsbsnd);
                        sbtoxsockstat_n(kcb->so, xsostats);

                        error = SYSCTL_OUT(req, buf, item_size);
		}
	}

        if (error == 0) {
                /*
                 * Give the user an updated idea of our state.
                 * If the generation differs from what we told
                 * her before, she knows that something happened
                 * while we were processing this request, and it
                 * might be necessary to retry.
                 */
                bzero(&xsg, sizeof(xsg));
                xsg.xg_len = sizeof(xsg);
                xsg.xg_count = n;
                xsg.xg_gen = kctlstat.kcs_gencnt;
                xsg.xg_sogen = so_gencnt;
                error = SYSCTL_OUT(req, &xsg, sizeof(xsg));
                if (error) {
                        goto done;
		}
	}

done:
        lck_mtx_unlock(ctl_mtx);

        return error;
}

int
kctl_getstat SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
        int error = 0;

        lck_mtx_lock(ctl_mtx);

        if (req->newptr != USER_ADDR_NULL) {
                error = EPERM;
                goto done;
	}
        if (req->oldptr == USER_ADDR_NULL) {
                req->oldidx = sizeof(struct kctlstat);
                goto done;
	}

        error = SYSCTL_OUT(req, &kctlstat,
            MIN(sizeof(struct kctlstat), req->oldlen));
done:
        lck_mtx_unlock(ctl_mtx);
        return error;
}

void
kctl_fill_socketinfo(struct socket *so, struct socket_info *si)
{
        struct ctl_cb *kcb = (struct ctl_cb *)so->so_pcb;
        struct kern_ctl_info *kcsi =
            &si->soi_proto.pri_kern_ctl;
        struct kctl *kctl = kcb->kctl;

        si->soi_kind = SOCKINFO_KERN_CTL;

        if (kctl == 0) {
                return;
	}

        kcsi->kcsi_id = kctl->id;
        kcsi->kcsi_reg_unit = kctl->reg_unit;
        kcsi->kcsi_flags = kctl->flags;
        kcsi->kcsi_recvbufsize = kctl->recvbufsize;
        kcsi->kcsi_sendbufsize = kctl->sendbufsize;
        kcsi->kcsi_unit = kcb->sac.sc_unit;
        strlcpy(kcsi->kcsi_name, kctl->name, MAX_KCTL_NAME);
}
