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
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/mcache.h>
#include <sys/syslog.h>
#include <sys/proc.h>
#include <sys/proc_internal.h>
#include <sys/resourcevar.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_timer.h>
#include <netinet/mptcp_var.h>
#include <netinet/mptcp_timer.h>

#include <mach/sdt.h>

static int mptcp_usr_attach(struct socket *, int, struct proc *);
static int mptcp_usr_detach(struct socket *);
static int mptcp_attach(struct socket *, struct proc *);
static int mptcp_detach(struct socket *, struct mppcb *);
static int mptcp_connectx(struct mptses *, struct sockaddr_list **,
    struct sockaddr_list **, struct proc *, uint32_t, associd_t, connid_t *,
    uint32_t, void *, uint32_t);
static int mptcp_usr_connectx(struct socket *, struct sockaddr_list **,
    struct sockaddr_list **, struct proc *, uint32_t, associd_t, connid_t *,
    uint32_t, void *, uint32_t);
static int mptcp_getassocids(struct mptses *, uint32_t *, user_addr_t);
static int mptcp_getconnids(struct mptses *, associd_t, uint32_t *,
    user_addr_t);
static int mptcp_getconninfo(struct mptses *, connid_t *, uint32_t *,
    uint32_t *, int32_t *, user_addr_t, socklen_t *, user_addr_t, socklen_t *,
    uint32_t *, user_addr_t, uint32_t *);
static int mptcp_usr_control(struct socket *, u_long, caddr_t, struct ifnet *,
    struct proc *);
static int mptcp_disconnectx(struct mptses *, associd_t, connid_t);
static int mptcp_usr_disconnectx(struct socket *, associd_t, connid_t);
static struct mptses *mptcp_usrclosed(struct mptses *);
static int mptcp_usr_peeloff(struct socket *, associd_t, struct socket **);
static int mptcp_peeloff(struct mptses *, associd_t, struct socket **);
static int mptcp_usr_rcvd(struct socket *, int);
static int mptcp_usr_send(struct socket *, int, struct mbuf *,
    struct sockaddr *, struct mbuf *, struct proc *);
static int mptcp_usr_shutdown(struct socket *);
static int mptcp_uiotombuf(struct uio *, int, int, uint32_t, struct mbuf **);
static int mptcp_usr_sosend(struct socket *, struct sockaddr *, struct uio *,
    struct mbuf *, struct mbuf *, int);
static int mptcp_usr_socheckopt(struct socket *, struct sockopt *);
static int mptcp_setopt_apply(struct mptses *, struct mptopt *);
static int mptcp_setopt(struct mptses *, struct sockopt *);
static int mptcp_getopt(struct mptses *, struct sockopt *);
static int mptcp_default_tcp_optval(struct mptses *, struct sockopt *, int *);
static void mptcp_connorder_helper(struct mptsub *mpts);

struct pr_usrreqs mptcp_usrreqs = {
	.pru_attach =		mptcp_usr_attach,
	.pru_connectx =		mptcp_usr_connectx,
	.pru_control =		mptcp_usr_control,
	.pru_detach =		mptcp_usr_detach,
	.pru_disconnectx =	mptcp_usr_disconnectx,
	.pru_peeloff =		mptcp_usr_peeloff,
	.pru_rcvd =		mptcp_usr_rcvd,
	.pru_send =		mptcp_usr_send,
	.pru_shutdown =		mptcp_usr_shutdown,
	.pru_sosend =		mptcp_usr_sosend,
	.pru_soreceive =	soreceive,
	.pru_socheckopt =	mptcp_usr_socheckopt,
};

/*
 * Attaches an MPTCP control block to a socket.
 */
static int
mptcp_usr_attach(struct socket *mp_so, int proto, struct proc *p)
{
#pragma unused(proto)
	int error;

	VERIFY(sotomppcb(mp_so) == NULL);

	error = mptcp_attach(mp_so, p);
	if (error != 0)
		goto out;
	/*
	 * XXX: adi@apple.com
	 *
	 * Might want to use a different SO_LINGER timeout than TCP's?
	 */
	if ((mp_so->so_options & SO_LINGER) && mp_so->so_linger == 0)
		mp_so->so_linger = TCP_LINGERTIME * hz;
out:
	return (error);
}

/*
 * Detaches an MPTCP control block from a socket.
 */
static int
mptcp_usr_detach(struct socket *mp_so)
{
	struct mppcb *mpp = sotomppcb(mp_so);
	int error = 0;

	VERIFY(mpp != NULL);
	VERIFY(mpp->mpp_socket != NULL);

	error = mptcp_detach(mp_so, mpp);
	return (error);
}

/*
 * Attach MPTCP protocol to socket, allocating MP control block,
 * MPTCP session, control block, buffer space, etc.
 */
static int
mptcp_attach(struct socket *mp_so, struct proc *p)
{
#pragma unused(p)
	struct mptses *mpte;
	struct mptcb *mp_tp;
	struct mppcb *mpp;
	int error = 0;

	if (mp_so->so_snd.sb_hiwat == 0 || mp_so->so_rcv.sb_hiwat == 0) {
		error = soreserve(mp_so, tcp_sendspace, MPTCP_RWIN_MAX);
		if (error != 0)
			goto out;
	}

	/*
	 * MPTCP socket buffers cannot be compressed, due to the
	 * fact that each mbuf chained via m_next is a M_PKTHDR
	 * which carries some MPTCP metadata.
	 */
	mp_so->so_snd.sb_flags |= SB_NOCOMPRESS;
	mp_so->so_rcv.sb_flags |= SB_NOCOMPRESS;

	/* Disable socket buffer auto-tuning. */
	mp_so->so_rcv.sb_flags &= ~SB_AUTOSIZE;
	mp_so->so_snd.sb_flags &= ~SB_AUTOSIZE;

	if ((error = mp_pcballoc(mp_so, &mtcbinfo)) != 0)
		goto out;

	mpp = sotomppcb(mp_so);
	VERIFY(mpp != NULL);

	mpte = mptcp_sescreate(mp_so, mpp);
	if (mpte == NULL) {
		mp_pcbdetach(mpp);
		error = ENOBUFS;
		goto out;
	}
	mp_tp = mpte->mpte_mptcb;
	VERIFY(mp_tp != NULL);

	MPT_LOCK(mp_tp);
	mp_tp->mpt_state = MPTCPS_CLOSED;
	MPT_UNLOCK(mp_tp);

out:
	return (error);
}

/*
 * Called when the socket layer loses its final reference to the socket;
 * at this point, there is only one case in which we will keep things
 * around: time wait.
 */
static int
mptcp_detach(struct socket *mp_so, struct mppcb *mpp)
{
	struct mptses *mpte;
	struct mppcbinfo *mppi;

	VERIFY(mp_so->so_pcb == mpp);
	VERIFY(mpp->mpp_socket == mp_so);

	mppi = mpp->mpp_pcbinfo;
	VERIFY(mppi != NULL);

	mpte = &((struct mpp_mtp *)mpp)->mpp_ses;
	VERIFY(mpte->mpte_mppcb == mpp);

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */

	/*
	 * We are done with this MPTCP socket (it has been closed);
	 * trigger all subflows to be disconnected, if not already,
	 * by initiating the PCB detach sequence (SOF_PCBCLEARING
	 * will be set.)
	 */
	mp_pcbdetach(mpp);

	(void) mptcp_disconnectx(mpte, ASSOCID_ALL, CONNID_ALL);

	/*
	 * XXX: adi@apple.com
	 *
	 * Here, we would want to handle time wait state.
	 */

	return (0);
}

/*
 * Common subroutine to open a MPTCP connection to one of the remote hosts
 * specified by dst_sl.  This includes allocating and establishing a
 * subflow TCP connection, either initially to establish MPTCP connection,
 * or to join an existing one.  Returns a connection handle upon success.
 */
static int
mptcp_connectx(struct mptses *mpte, struct sockaddr_list **src_sl,
    struct sockaddr_list **dst_sl, struct proc *p, uint32_t ifscope,
    associd_t aid, connid_t *pcid, uint32_t flags, void *arg,
    uint32_t arglen)
{
#pragma unused(p, aid, flags, arg, arglen)
	struct mptsub *mpts;
	struct socket *mp_so;
	int error = 0;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	mp_so = mpte->mpte_mppcb->mpp_socket;

	VERIFY(dst_sl != NULL && *dst_sl != NULL);
	VERIFY(pcid != NULL);

	mptcplog((LOG_DEBUG, "%s: mp_so 0x%llx\n", __func__,
	    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so)));
	DTRACE_MPTCP3(connectx, struct mptses *, mpte, associd_t, aid,
	    struct socket *, mp_so);

	mpts = mptcp_subflow_alloc(M_WAITOK);
	if (mpts == NULL) {
		error = ENOBUFS;
		goto out;
	}
	MPTS_ADDREF(mpts);		/* for this routine */

	if (src_sl != NULL) {
		mpts->mpts_src_sl = *src_sl;
		*src_sl = NULL;
	}
	mpts->mpts_dst_sl = *dst_sl;
	*dst_sl = NULL;

	error = mptcp_subflow_add(mpte, mpts, p, ifscope);
	if (error == 0 && pcid != NULL)
		*pcid = mpts->mpts_connid;

out:
	if (mpts != NULL) {
		if ((error != 0) && (error != EWOULDBLOCK)) {
			MPTS_LOCK(mpts);
			if (mpts->mpts_flags & MPTSF_ATTACHED) {
				MPTS_UNLOCK(mpts);
				MPTS_REMREF(mpts);
				mptcp_subflow_del(mpte, mpts, TRUE);
				return (error);
			}
			MPTS_UNLOCK(mpts);
		}
		MPTS_REMREF(mpts);
	}

	return (error);
}

/*
 * User-protocol pru_connectx callback.
 */
static int
mptcp_usr_connectx(struct socket *mp_so, struct sockaddr_list **src_sl,
    struct sockaddr_list **dst_sl, struct proc *p, uint32_t ifscope,
    associd_t aid, connid_t *pcid, uint32_t flags, void *arg,
    uint32_t arglen)
{
#pragma unused(arg, arglen)
	struct mppcb *mpp = sotomppcb(mp_so);
	struct mptses *mpte;
	int error = 0;

	if (mpp == NULL || mpp->mpp_state == MPPCB_STATE_DEAD) {
		error = EINVAL;
		goto out;
	}
	mpte = mptompte(mpp);
	VERIFY(mpte != NULL);

	error = mptcp_connectx(mpte, src_sl, dst_sl, p, ifscope,
	    aid, pcid, flags, arg, arglen);
out:
	return (error);
}

/*
 * Handle SIOCGASSOCIDS ioctl for PF_MULTIPATH domain.
 */
static int
mptcp_getassocids(struct mptses *mpte, uint32_t *cnt, user_addr_t aidp)
{
	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */

	/* MPTCP has at most 1 association */
	*cnt = (mpte->mpte_associd != ASSOCID_ANY) ? 1 : 0;

	/* just asking how many there are? */
	if (aidp == USER_ADDR_NULL)
		return (0);

	return (copyout(&mpte->mpte_associd, aidp,
	    sizeof (mpte->mpte_associd)));
}

/*
 * Handle SIOCGCONNIDS ioctl for PF_MULTIPATH domain.
 */
static int
mptcp_getconnids(struct mptses *mpte, associd_t aid, uint32_t *cnt,
    user_addr_t cidp)
{
	struct mptsub *mpts;
	int error = 0;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */

	if (aid != ASSOCID_ANY && aid != ASSOCID_ALL &&
	    aid != mpte->mpte_associd)
		return (EINVAL);

	*cnt = mpte->mpte_numflows;

	/* just asking how many there are? */
	if (cidp == USER_ADDR_NULL)
		return (0);

	TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
		if ((error = copyout(&mpts->mpts_connid, cidp,
		    sizeof (mpts->mpts_connid))) != 0)
			break;

		cidp += sizeof (mpts->mpts_connid);
	}

	return (error);
}

/*
 * Handle SIOCGCONNINFO ioctl for PF_MULTIPATH domain.
 */
static int
mptcp_getconninfo(struct mptses *mpte, connid_t *cid, uint32_t *flags,
    uint32_t *ifindex, int32_t *soerror, user_addr_t src, socklen_t *src_len,
    user_addr_t dst, socklen_t *dst_len, uint32_t *aux_type,
    user_addr_t aux_data, uint32_t *aux_len)
{
#pragma unused(aux_data)
	struct sockaddr_entry *se;
	struct ifnet *ifp = NULL;
	struct mptsub *mpts;
	int error = 0;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */

	if (*cid == CONNID_ALL)
		return (EINVAL);

	TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
		if (mpts->mpts_connid == *cid || *cid == CONNID_ANY)
			break;
	}
	if (mpts == NULL)
		return ((*cid == CONNID_ANY) ? ENXIO : EINVAL);

	MPTS_LOCK(mpts);
	ifp = mpts->mpts_outif;
	*cid = mpts->mpts_connid;
	*ifindex = ((ifp != NULL) ? ifp->if_index : 0);
	*soerror = mpts->mpts_soerror;
	*flags = 0;
	if (mpts->mpts_flags & MPTSF_CONNECTING)
		*flags |= CIF_CONNECTING;
	if (mpts->mpts_flags & MPTSF_CONNECTED)
		*flags |= CIF_CONNECTED;
	if (mpts->mpts_flags & MPTSF_DISCONNECTING)
		*flags |= CIF_DISCONNECTING;
	if (mpts->mpts_flags & MPTSF_DISCONNECTED)
		*flags |= CIF_DISCONNECTED;
	if (mpts->mpts_flags & MPTSF_BOUND_IF)
		*flags |= CIF_BOUND_IF;
	if (mpts->mpts_flags & MPTSF_BOUND_IP)
		*flags |= CIF_BOUND_IP;
	if (mpts->mpts_flags & MPTSF_BOUND_PORT)
		*flags |= CIF_BOUND_PORT;
	if (mpts->mpts_flags & MPTSF_PREFERRED)
		*flags |= CIF_PREFERRED;
	if (mpts->mpts_flags & MPTSF_MP_CAPABLE)
		*flags |= CIF_MP_CAPABLE;
	if (mpts->mpts_flags & MPTSF_MP_DEGRADED)
		*flags |= CIF_MP_DEGRADED;
	if (mpts->mpts_flags & MPTSF_MP_READY)
		*flags |= CIF_MP_READY;
	if (mpts->mpts_flags & MPTSF_ACTIVE)
		*flags |= CIF_MP_ACTIVE;

	VERIFY(mpts->mpts_src_sl != NULL);
	se = TAILQ_FIRST(&mpts->mpts_src_sl->sl_head);
	VERIFY(se != NULL && se->se_addr != NULL);
	*src_len = se->se_addr->sa_len;
	if (src != USER_ADDR_NULL) {
		error = copyout(se->se_addr, src, se->se_addr->sa_len);
		if (error != 0)
			goto out;
	}

	VERIFY(mpts->mpts_dst_sl != NULL);
	se = TAILQ_FIRST(&mpts->mpts_dst_sl->sl_head);
	VERIFY(se != NULL && se->se_addr != NULL);
	*dst_len = se->se_addr->sa_len;
	if (dst != USER_ADDR_NULL) {
		error = copyout(se->se_addr, dst, se->se_addr->sa_len);
		if (error != 0)
			goto out;
	}

	*aux_type = 0;
	*aux_len = 0;
	if (mpts->mpts_socket != NULL) {
		struct conninfo_tcp tcp_ci;
		
		*aux_type = CIAUX_TCP;
		*aux_len = sizeof (tcp_ci);
		
		if (aux_data != USER_ADDR_NULL) {
			struct socket *so = mpts->mpts_socket;

			VERIFY(SOCK_PROTO(so) == IPPROTO_TCP);
			bzero(&tcp_ci, sizeof (tcp_ci));
			socket_lock(so, 0);
			tcp_getconninfo(so, &tcp_ci);
			socket_unlock(so, 0);
			error = copyout(&tcp_ci, aux_data, sizeof (tcp_ci));
			if (error != 0)
				goto out;
		}
	}
out:
	MPTS_UNLOCK(mpts);
	return (error);
}

/*
 * Handle SIOCSCONNORDER
 */
int
mptcp_setconnorder(struct mptses *mpte, connid_t cid, uint32_t rank)
{
	struct mptsub *mpts, *mpts1;
	int error = 0;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	mptcplog((LOG_DEBUG, "%s: cid %d rank %d \n", __func__, cid, rank));

	if (cid == CONNID_ANY || cid == CONNID_ALL) {
		error = EINVAL;
		goto out;
	}

	TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
		if (mpts->mpts_connid == cid)
			break;
	}
	if (mpts == NULL) {
		error = ENXIO;
		goto out;
	}

	if (rank == 0 || rank > 1) {
		/*
		 * If rank is 0, determine whether this should be the
		 * primary or backup subflow, depending on what we have.
		 *
		 * Otherwise, if greater than 0, make it a backup flow.
		 */
		TAILQ_FOREACH(mpts1, &mpte->mpte_subflows, mpts_entry) {
			MPTS_LOCK(mpts1);
			if (mpts1->mpts_flags & MPTSF_PREFERRED) {
				MPTS_UNLOCK(mpts1);
				break;
			}
			MPTS_UNLOCK(mpts1);
		}

		MPTS_LOCK(mpts);
		mpts->mpts_flags &= ~MPTSF_PREFERRED;
		mpts->mpts_rank = rank;
		if (mpts1 != NULL && mpts != mpts1) {
			/* preferred subflow found; set rank as necessary */
			if (rank == 0)
				mpts->mpts_rank = (mpts1->mpts_rank + 1);
		} else if (rank == 0) {
			/* no preferred one found; promote this */
			rank = 1;
		}
		MPTS_UNLOCK(mpts);
	}

	if (rank == 1) {
		/*
		 * If rank is 1, promote this subflow to be preferred.
		 */
		TAILQ_FOREACH(mpts1, &mpte->mpte_subflows, mpts_entry) {
			MPTS_LOCK(mpts1);
			if (mpts1 != mpts &&
			    (mpts1->mpts_flags & MPTSF_PREFERRED)) {
				mpts1->mpts_flags &= ~MPTSF_PREFERRED;
				if (mpte->mpte_nummpcapflows > 1) 
					mptcp_connorder_helper(mpts1);
			} else if (mpts1 == mpts) {
				mpts1->mpts_rank = 1;
				if (mpts1->mpts_flags & MPTSF_MP_CAPABLE) {
					mpts1->mpts_flags |= MPTSF_PREFERRED;
					if (mpte->mpte_nummpcapflows > 1)
						mptcp_connorder_helper(mpts1);
				}
			}
			MPTS_UNLOCK(mpts1);
		}
	}

out:
	return (error);
}

static void
mptcp_connorder_helper(struct mptsub *mpts)
{
	struct socket *so = mpts->mpts_socket;
	struct tcpcb *tp = NULL;

	socket_lock(so, 0);
	
	tp = intotcpcb(sotoinpcb(so));
	tp->t_mpflags |= TMPF_SND_MPPRIO;
	if (mpts->mpts_flags & MPTSF_PREFERRED)
		tp->t_mpflags &= ~TMPF_BACKUP_PATH;
	else
		tp->t_mpflags |= TMPF_BACKUP_PATH;
	mptcplog((LOG_DEBUG, "%s cid %d flags %x", __func__,
	    mpts->mpts_connid, mpts->mpts_flags));	
	socket_unlock(so, 0);

}

/*
 * Handle SIOCSGONNORDER
 */
int
mptcp_getconnorder(struct mptses *mpte, connid_t cid, uint32_t *rank)
{
	struct mptsub *mpts;
	int error = 0;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	VERIFY(rank != NULL);
	*rank = 0;

	if (cid == CONNID_ANY || cid == CONNID_ALL) {
		error = EINVAL;
		goto out;
	}

	TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
		if (mpts->mpts_connid == cid)
			break;
	}
	if (mpts == NULL) {
		error = ENXIO;
		goto out;
	}

	MPTS_LOCK(mpts);
	*rank = mpts->mpts_rank;
	MPTS_UNLOCK(mpts);
out:
	return (error);
}

/*
 * User-protocol pru_control callback.
 */
static int
mptcp_usr_control(struct socket *mp_so, u_long cmd, caddr_t data,
    struct ifnet *ifp, struct proc *p)
{
#pragma unused(ifp, p)
	struct mppcb *mpp = sotomppcb(mp_so);
	struct mptses *mpte;
	int error = 0;

	if (mpp == NULL || mpp->mpp_state == MPPCB_STATE_DEAD) {
		error = EINVAL;
		goto out;
	}
	mpte = mptompte(mpp);
	VERIFY(mpte != NULL);

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */

	switch (cmd) {
	case SIOCGASSOCIDS32: {		/* struct so_aidreq32 */
		struct so_aidreq32 aidr;
		bcopy(data, &aidr, sizeof (aidr));
		error = mptcp_getassocids(mpte, &aidr.sar_cnt,
		    aidr.sar_aidp);
		if (error == 0)
			bcopy(&aidr, data, sizeof (aidr));
		break;
	}

	case SIOCGASSOCIDS64: {		/* struct so_aidreq64 */
		struct so_aidreq64 aidr;
		bcopy(data, &aidr, sizeof (aidr));
		error = mptcp_getassocids(mpte, &aidr.sar_cnt,
		    aidr.sar_aidp);
		if (error == 0)
			bcopy(&aidr, data, sizeof (aidr));
		break;
	}

	case SIOCGCONNIDS32: {		/* struct so_cidreq32 */
		struct so_cidreq32 cidr;
		bcopy(data, &cidr, sizeof (cidr));
		error = mptcp_getconnids(mpte, cidr.scr_aid, &cidr.scr_cnt,
		    cidr.scr_cidp);
		if (error == 0)
			bcopy(&cidr, data, sizeof (cidr));
		break;
	}

	case SIOCGCONNIDS64: {		/* struct so_cidreq64 */
		struct so_cidreq64 cidr;
		bcopy(data, &cidr, sizeof (cidr));
		error = mptcp_getconnids(mpte, cidr.scr_aid, &cidr.scr_cnt,
		    cidr.scr_cidp);
		if (error == 0)
			bcopy(&cidr, data, sizeof (cidr));
		break;
	}

	case SIOCGCONNINFO32: {		/* struct so_cinforeq32 */
		struct so_cinforeq32 cifr;
		bcopy(data, &cifr, sizeof (cifr));
		error = mptcp_getconninfo(mpte, &cifr.scir_cid,
		    &cifr.scir_flags, &cifr.scir_ifindex, &cifr.scir_error,
		    cifr.scir_src, &cifr.scir_src_len, cifr.scir_dst,
		    &cifr.scir_dst_len, &cifr.scir_aux_type, cifr.scir_aux_data,
		    &cifr.scir_aux_len);
		if (error == 0)
			bcopy(&cifr, data, sizeof (cifr));
		break;
	}

	case SIOCGCONNINFO64: {		/* struct so_cinforeq64 */
		struct so_cinforeq64 cifr;
		bcopy(data, &cifr, sizeof (cifr));
		error = mptcp_getconninfo(mpte, &cifr.scir_cid,
		    &cifr.scir_flags, &cifr.scir_ifindex, &cifr.scir_error,
		    cifr.scir_src, &cifr.scir_src_len, cifr.scir_dst,
		    &cifr.scir_dst_len, &cifr.scir_aux_type, cifr.scir_aux_data,
		    &cifr.scir_aux_len);
		if (error == 0)
			bcopy(&cifr, data, sizeof (cifr));
		break;
	}

	case SIOCSCONNORDER: {		/* struct so_cordreq */
		struct so_cordreq cor;
		bcopy(data, &cor, sizeof (cor));
		error = mptcp_setconnorder(mpte, cor.sco_cid, cor.sco_rank);
		if (error == 0)
			bcopy(&cor, data, sizeof (cor));
		break;
	}

	case SIOCGCONNORDER: {		/* struct so_cordreq */
		struct so_cordreq cor;
		bcopy(data, &cor, sizeof (cor));
		error = mptcp_getconnorder(mpte, cor.sco_cid, &cor.sco_rank);
		if (error == 0)
			bcopy(&cor, data, sizeof (cor));
		break;
	}

	default:
		error = EOPNOTSUPP;
		break;
	}
out:
	return (error);
}

/*
 * Initiate a disconnect.  MPTCP-level disconnection is specified by
 * CONNID_{ANY,ALL}.  Otherwise, selectively disconnect a subflow
 * connection while keeping the MPTCP-level connection (association).
 */
static int
mptcp_disconnectx(struct mptses *mpte, associd_t aid, connid_t cid)
{
	struct mptsub *mpts;
	struct socket *mp_so;
	struct mptcb *mp_tp;
	int error = 0;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */

	mp_so = mpte->mpte_mppcb->mpp_socket;
	mp_tp = mpte->mpte_mptcb;

	mptcplog((LOG_DEBUG, "%s: mp_so 0x%llx aid %d cid %d\n", __func__,
	    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so), aid, cid));
	DTRACE_MPTCP5(disconnectx, struct mptses *, mpte, associd_t, aid,
	    connid_t, cid, struct socket *, mp_so, struct mptcb *, mp_tp);

	VERIFY(aid == ASSOCID_ANY || aid == ASSOCID_ALL ||
	    aid == mpte->mpte_associd);

	/* terminate the association? */
	if (cid == CONNID_ANY || cid == CONNID_ALL) {
		/* if we're not detached, go thru socket state checks */
		if (!(mp_so->so_flags & SOF_PCBCLEARING)) {
			if (!(mp_so->so_state & (SS_ISCONNECTED|
			    SS_ISCONNECTING))) {
				error = ENOTCONN;
				goto out;
			}
			if (mp_so->so_state & SS_ISDISCONNECTING) {
				error = EALREADY;
				goto out;
			}
		}
		MPT_LOCK(mp_tp);
		mptcp_cancel_all_timers(mp_tp);
		if (mp_tp->mpt_state < MPTCPS_ESTABLISHED) {
			(void) mptcp_close(mpte, mp_tp);
			MPT_UNLOCK(mp_tp);
		} else if ((mp_so->so_options & SO_LINGER) &&
		    mp_so->so_linger == 0) {
			(void) mptcp_drop(mpte, mp_tp, 0);
			MPT_UNLOCK(mp_tp);
		} else {
			MPT_UNLOCK(mp_tp);
			soisdisconnecting(mp_so);
			sbflush(&mp_so->so_rcv);
			if (mptcp_usrclosed(mpte) != NULL)
				(void) mptcp_output(mpte);
		}
	} else {
		TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
			if (mpts->mpts_connid != cid)
				continue;
			MPTS_LOCK(mpts);
			mptcp_subflow_disconnect(mpte, mpts, FALSE);
			MPTS_UNLOCK(mpts);
			break;
		}

		if (mpts == NULL) {
			error = EINVAL;
			goto out;
		}
	}

	if (error == 0)
		mptcp_thread_signal(mpte);

	if ((mp_so->so_state & (SS_CANTRCVMORE | SS_CANTSENDMORE)) ==
	    (SS_CANTRCVMORE | SS_CANTSENDMORE)) {
		/* the socket has been shutdown, no more sockopt's */
		mptcp_flush_sopts(mpte);
	}

out:
	return (error);
}

/*
 * User-protocol pru_disconnectx callback.
 */
static int
mptcp_usr_disconnectx(struct socket *mp_so, associd_t aid, connid_t cid)
{
	struct mppcb *mpp = sotomppcb(mp_so);
	struct mptses *mpte;
	int error = 0;

	if (mpp == NULL || mpp->mpp_state == MPPCB_STATE_DEAD) {
		error = EINVAL;
		goto out;
	}
	mpte = mptompte(mpp);
	VERIFY(mpte != NULL);
	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */

	if (aid != ASSOCID_ANY && aid != ASSOCID_ALL &&
	    aid != mpte->mpte_associd) {
		error = EINVAL;
		goto out;
	}

	error = mptcp_disconnectx(mpte, aid, cid);
out:
	return (error);
}

/*
 * User issued close, and wish to trail thru shutdown states.
 */
static struct mptses *
mptcp_usrclosed(struct mptses *mpte)
{
	struct socket *mp_so;
	struct mptcb *mp_tp;
	struct mptsub *mpts;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	mp_so = mpte->mpte_mppcb->mpp_socket;
	mp_tp = mpte->mpte_mptcb;

	MPT_LOCK(mp_tp);
	mptcp_close_fsm(mp_tp, MPCE_CLOSE);

	if (mp_tp->mpt_state == TCPS_CLOSED) {
		mpte = mptcp_close(mpte, mp_tp);
		MPT_UNLOCK(mp_tp);
	} else if (mp_tp->mpt_state >= MPTCPS_FIN_WAIT_2) {
		MPT_UNLOCK(mp_tp);
		soisdisconnected(mp_so);
	} else {
		mp_tp->mpt_sndmax += 1; /* adjust for Data FIN */
		MPT_UNLOCK(mp_tp);

		TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
			MPTS_LOCK(mpts);
			mptcp_subflow_disconnect(mpte, mpts, FALSE);
			MPTS_UNLOCK(mpts);
		}
	}
	/*
	 * XXX: adi@apple.com
	 *
	 * Do we need to handle time wait specially here?  We need to handle
	 * the case where MPTCP has been established, but we have not usable
	 * subflow to use.  Do we want to wait a while before forcibly
	 * tearing this MPTCP down, in case we have one or more subflows
	 * that are flow controlled?
	 */

	return (mpte);
}

/*
 * User-protocol pru_peeloff callback.
 */
static int
mptcp_usr_peeloff(struct socket *mp_so, associd_t aid, struct socket **psop)
{
	struct mppcb *mpp = sotomppcb(mp_so);
	struct mptses *mpte;
	int error = 0;

	VERIFY(psop != NULL);

	if (mpp == NULL || mpp->mpp_state == MPPCB_STATE_DEAD) {
		error = EINVAL;
		goto out;
	}
	mpte = mptompte(mpp);
	VERIFY(mpte != NULL);

	error = mptcp_peeloff(mpte, aid, psop);
out:
	return (error);
}

/*
 * Transform a previously connected TCP subflow connection which has
 * failed to negotiate MPTCP to its own socket which can be externalized
 * with a file descriptor.  Valid only when the MPTCP socket is not
 * yet associated (MPTCP-level connection has not been established.)
 */
static int
mptcp_peeloff(struct mptses *mpte, associd_t aid, struct socket **psop)
{
	struct socket *so = NULL, *mp_so;
	struct mptsub *mpts;
	int error = 0;

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	mp_so = mpte->mpte_mppcb->mpp_socket;

	VERIFY(psop != NULL);
	*psop = NULL;

	DTRACE_MPTCP3(peeloff, struct mptses *, mpte, associd_t, aid,
	    struct socket *, mp_so);

	/* peeloff cannot happen after an association is established */
	if (mpte->mpte_associd != ASSOCID_ANY) {
		error = EINVAL;
		goto out;
	}

	if (aid != ASSOCID_ANY && aid != ASSOCID_ALL) {
		error = EINVAL;
		goto out;
	}

	TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
		MPTS_LOCK(mpts);
		if (mpts->mpts_flags & MPTSF_MP_CAPABLE) {
			panic("%s: so %p is MPTCP capable but mp_so %p "
			    "aid is %d\n", __func__, so, mp_so,
			    mpte->mpte_associd);
			/* NOTREACHED */
		}
		MPTS_ADDREF_LOCKED(mpts);	/* for us */
		so = mpts->mpts_socket;
		VERIFY(so != NULL);
		/*
		 * This subflow socket is about to be externalized; make it
		 * appear as if it has the same properties as the MPTCP socket,
		 * undo what's done earlier in mptcp_subflow_add().
		 */
		mptcp_subflow_sopeeloff(mpte, mpts, so);
		MPTS_UNLOCK(mpts);

		mptcp_subflow_del(mpte, mpts, FALSE);
		MPTS_REMREF(mpts);		/* ours */
		/*
		 * XXX adi@apple.com
		 *
		 * Here we need to make sure the subflow socket is not
		 * flow controlled; need to clear both INP_FLOW_CONTROLLED
		 * and INP_FLOW_SUSPENDED on the subflow socket, since
		 * we will no longer be monitoring its events.
		 */
		break;
	}

	if (so == NULL) {
		error = EINVAL;
		goto out;
	}
	*psop = so;

	mptcplog((LOG_DEBUG, "%s: mp_so 0x%llx\n", __func__,
	    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so)));
out:
	return (error);
}

/*
 * After a receive, possible send some update to peer.
 */
static int
mptcp_usr_rcvd(struct socket *mp_so, int flags)
{
#pragma unused(flags)
	struct mppcb *mpp = sotomppcb(mp_so);
	struct mptses *mpte;
	int error = 0;

	if (mpp == NULL || mpp->mpp_state == MPPCB_STATE_DEAD) {
		error = EINVAL;
		goto out;
	}
	mpte = mptompte(mpp);
	VERIFY(mpte != NULL);

	error = mptcp_output(mpte);
out:
	return (error);
}

/*
 * Do a send by putting data in the output queue.
 */
static int
mptcp_usr_send(struct socket *mp_so, int prus_flags, struct mbuf *m,
    struct sockaddr *nam, struct mbuf *control, struct proc *p)
{
#pragma unused(nam, p)
	struct mppcb *mpp = sotomppcb(mp_so);
	struct mptses *mpte;
	int error = 0;

	if (prus_flags & (PRUS_OOB|PRUS_EOF)) {
		error = EOPNOTSUPP;
		goto out;
	}

	if (nam != NULL) {
		error = EOPNOTSUPP;
		goto out;
	}

	if (control != NULL && control->m_len != 0) {
		error = EOPNOTSUPP;
		goto out;
	}

	if (mpp == NULL || mpp->mpp_state == MPPCB_STATE_DEAD) {
		error = ECONNRESET;
		goto out;
	}
	mpte = mptompte(mpp);
	VERIFY(mpte != NULL);

	if (!(mp_so->so_state & SS_ISCONNECTED)) {
		error = ENOTCONN;
		goto out;
	}

	mptcp_insert_dsn(mpp, m);
	VERIFY(mp_so->so_snd.sb_flags & SB_NOCOMPRESS);
	(void) sbappendstream(&mp_so->so_snd, m);
	m = NULL;

	if (mpte != NULL) {
		/*
		 * XXX: adi@apple.com
		 *
		 * PRUS_MORETOCOME could be set, but we don't check it now.
		 */
		error = mptcp_output(mpte);
	}

out:
	if (error) {
		if (m != NULL)
			m_freem(m);
		if (control != NULL)
			m_freem(control);
	}
	return (error);
}

/*
 * Mark the MPTCP connection as being incapable of further output.
 */
static int
mptcp_usr_shutdown(struct socket *mp_so)
{
	struct mppcb *mpp = sotomppcb(mp_so);
	struct mptses *mpte;
	int error = 0;

	if (mpp == NULL || mpp->mpp_state == MPPCB_STATE_DEAD) {
		error = EINVAL;
		goto out;
	}
	mpte = mptompte(mpp);
	VERIFY(mpte != NULL);

	socantsendmore(mp_so);

	mpte = mptcp_usrclosed(mpte);
	if (mpte != NULL)
		error = mptcp_output(mpte);
out:
	return (error);
}

/*
 * Copy the contents of uio into a properly sized mbuf chain.
 */
static int
mptcp_uiotombuf(struct uio *uio, int how, int space, uint32_t align,
    struct mbuf **top)
{
	struct mbuf *m, *mb, *nm = NULL, *mtail = NULL;
	user_ssize_t resid, tot, len, progress;	/* must be user_ssize_t */
	int error;

	VERIFY(top != NULL && *top == NULL);

	/*
	 * space can be zero or an arbitrary large value bound by
	 * the total data supplied by the uio.
	 */
	resid = uio_resid(uio);
	if (space > 0)
		tot = imin(resid, space);
	else
		tot = resid;

	/*
	 * The smallest unit is a single mbuf with pkthdr.
	 * We can't align past it.
	 */
	if (align >= MHLEN)
		return (EINVAL);

	/*
	 * Give us the full allocation or nothing.
	 * If space is zero return the smallest empty mbuf.
	 */
	if ((len = tot + align) == 0)
		len = 1;

	/* Loop and append maximum sized mbufs to the chain tail. */
	while (len > 0) {
		uint32_t m_needed = 1;

		if (njcl > 0 && len > MBIGCLBYTES)
			mb = m_getpackets_internal(&m_needed, 1,
			    how, 1, M16KCLBYTES);
		else if (len > MCLBYTES)
			mb = m_getpackets_internal(&m_needed, 1,
			    how, 1, MBIGCLBYTES);
		else if (len >= (signed)MINCLSIZE)
			mb = m_getpackets_internal(&m_needed, 1,
			    how, 1, MCLBYTES);
		else
			mb = m_gethdr(how, MT_DATA);

		/* Fail the whole operation if one mbuf can't be allocated. */
		if (mb == NULL) {
			if (nm != NULL)
				m_freem(nm);
			return (ENOBUFS);
		}

		/* Book keeping. */
		VERIFY(mb->m_flags & M_PKTHDR);
		len -= ((mb->m_flags & M_EXT) ? mb->m_ext.ext_size : MHLEN);
		if (mtail != NULL)
			mtail->m_next = mb;
		else
			nm = mb;
		mtail = mb;
	}

	m = nm;
	m->m_data += align;

	progress = 0;
	/* Fill all mbufs with uio data and update header information. */
	for (mb = m; mb != NULL; mb = mb->m_next) {
		len = imin(M_TRAILINGSPACE(mb), tot - progress);

		error = uiomove(mtod(mb, char *), len, uio);
		if (error != 0) {
			m_freem(m);
			return (error);
		}

		/* each mbuf is M_PKTHDR chained via m_next */
		mb->m_len = len;
		mb->m_pkthdr.len = len;

		progress += len;
	}
	VERIFY(progress == tot);
	*top = m;
	return (0);
}

/*
 * MPTCP socket protocol-user socket send routine, derived from sosend().
 */
static int
mptcp_usr_sosend(struct socket *mp_so, struct sockaddr *addr, struct uio *uio,
    struct mbuf *top, struct mbuf *control, int flags)
{
#pragma unused(addr)
	int32_t space;
	user_ssize_t resid;
	int error, sendflags;
	struct proc *p = current_proc();
	int sblocked = 0;

	/* UIO is required for now, due to per-mbuf M_PKTHDR constrains */
	if (uio == NULL || top != NULL) {
		error = EINVAL;
		goto out;
	}
	resid = uio_resid(uio);

	socket_lock(mp_so, 1);
	so_update_last_owner_locked(mp_so, p);
	so_update_policy(mp_so);

	VERIFY(mp_so->so_type == SOCK_STREAM);
	VERIFY(!(mp_so->so_flags & SOF_MP_SUBFLOW));

	if ((flags & (MSG_OOB|MSG_DONTROUTE|MSG_HOLD|MSG_SEND|MSG_FLUSH)) ||
	    (mp_so->so_flags & SOF_ENABLE_MSGS)) {
		error = EOPNOTSUPP;
		socket_unlock(mp_so, 1);
		goto out;
	}

	/*
	 * In theory resid should be unsigned.  However, space must be
	 * signed, as it might be less than 0 if we over-committed, and we
	 * must use a signed comparison of space and resid.  On the other
	 * hand, a negative resid causes us to loop sending 0-length
	 * segments to the protocol.
	 */
	if (resid < 0 || (flags & MSG_EOR) || control != NULL) {
		error = EINVAL;
		socket_unlock(mp_so, 1);
		goto out;
	}

	OSIncrementAtomicLong(&p->p_stats->p_ru.ru_msgsnd);

	do {
		error = sosendcheck(mp_so, NULL, resid, 0, 0, flags,
		    &sblocked, NULL);
		if (error != 0)
			goto release;

		space = sbspace(&mp_so->so_snd);
		do {
			socket_unlock(mp_so, 0);
			/*
			 * Copy the data from userland into an mbuf chain.
			 */
			error = mptcp_uiotombuf(uio, M_WAITOK, space, 0, &top);
			if (error != 0) {
				socket_lock(mp_so, 0);
				goto release;
			}
			VERIFY(top != NULL);
			space -= resid - uio_resid(uio);
			resid = uio_resid(uio);
			socket_lock(mp_so, 0);

			/*
			 * Compute flags here, for pru_send and NKEs.
			 */
			sendflags = (resid > 0 && space > 0) ?
			    PRUS_MORETOCOME : 0;

			/*
			 * Socket filter processing
			 */
			VERIFY(control == NULL);
			error = sflt_data_out(mp_so, NULL, &top, &control, 0);
			if (error != 0) {
				if (error == EJUSTRETURN) {
					error = 0;
					top = NULL;
					/* always free control if any */
				}
				goto release;
			}
			if (control != NULL) {
				m_freem(control);
				control = NULL;
			}

			/*
			 * Pass data to protocol.
			 */
			error = (*mp_so->so_proto->pr_usrreqs->pru_send)
			    (mp_so, sendflags, top, NULL, NULL, p);

			top = NULL;
			if (error != 0)
				goto release;
		} while (resid != 0 && space > 0);
	} while (resid != 0);

release:
	if (sblocked)
		sbunlock(&mp_so->so_snd, FALSE); /* will unlock socket */
	else
		socket_unlock(mp_so, 1);
out:
	if (top != NULL)
		m_freem(top);
	if (control != NULL)
		m_freem(control);

	return (error);
}

/*
 * Called to filter SOPT_{SET,GET} for SOL_SOCKET level socket options.
 * This routine simply indicates to the caller whether or not to proceed
 * further with the given socket option.  This is invoked by sosetoptlock()
 * and sogetoptlock().
 */
static int
mptcp_usr_socheckopt(struct socket *mp_so, struct sockopt *sopt)
{
#pragma unused(mp_so)
	int error = 0;

	VERIFY(sopt->sopt_level == SOL_SOCKET);

	/*
	 * We could check for sopt_dir (set/get) here, but we'll just
	 * let the caller deal with it as appropriate; therefore the
	 * following is a superset of the socket options which we
	 * allow for set/get.
	 *
	 * XXX: adi@apple.com
	 *
	 * Need to consider the following cases:
	 *
	 *   a. In the event peeloff(2) occurs on the subflow socket,
	 *	we may want to issue those options which are now
	 *	handled at the MP socket.  In that case, we will need
	 *	to record them in mptcp_setopt() so that they can
	 *	be replayed during peeloff.
	 *
	 *   b.	Certain socket options don't have a clear definition
	 *	on the expected behavior post connect(2).  At the time
	 *	those options are issued on the MP socket, there may
	 *	be existing subflow sockets that are already connected.
	 */
	switch (sopt->sopt_name) {
	case SO_LINGER:				/* MP */
	case SO_LINGER_SEC:			/* MP */
	case SO_TYPE:				/* MP */
	case SO_NREAD:				/* MP */
	case SO_NWRITE:				/* MP */
	case SO_ERROR:				/* MP */
	case SO_SNDBUF:				/* MP */
	case SO_RCVBUF:				/* MP */
	case SO_SNDLOWAT:			/* MP */
	case SO_RCVLOWAT:			/* MP */
	case SO_SNDTIMEO:			/* MP */
	case SO_RCVTIMEO:			/* MP */
	case SO_NKE:				/* MP */
	case SO_NOSIGPIPE:			/* MP */
	case SO_NOADDRERR:			/* MP */
	case SO_LABEL:				/* MP */
	case SO_PEERLABEL:			/* MP */
	case SO_DEFUNCTOK:			/* MP */
	case SO_ISDEFUNCT:			/* MP */
	case SO_TRAFFIC_CLASS_DBG:		/* MP */
		/*
		 * Tell the caller that these options are to be processed.
		 */
		break;

	case SO_DEBUG:				/* MP + subflow */
	case SO_KEEPALIVE:			/* MP + subflow */
	case SO_USELOOPBACK:			/* MP + subflow */
	case SO_RANDOMPORT:			/* MP + subflow */
	case SO_TRAFFIC_CLASS:			/* MP + subflow */
	case SO_RECV_TRAFFIC_CLASS:		/* MP + subflow */
	case SO_PRIVILEGED_TRAFFIC_CLASS:	/* MP + subflow */
	case SO_RECV_ANYIF:			/* MP + subflow */
	case SO_RESTRICTIONS:			/* MP + subflow */
	case SO_FLUSH:				/* MP + subflow */
		/*
		 * Tell the caller that these options are to be processed;
		 * these will also be recorded later by mptcp_setopt().
		 *
		 * NOTE: Only support integer option value for now.
		 */
		if (sopt->sopt_valsize != sizeof (int))
			error = EINVAL;
		break;

	default:
		/*
		 * Tell the caller to stop immediately and return an error.
		 */
		error = ENOPROTOOPT;
		break;
	}

	return (error);
}

/*
 * Issue SOPT_SET for all MPTCP subflows (for integer option values.)
 */
static int
mptcp_setopt_apply(struct mptses *mpte, struct mptopt *mpo)
{
	struct socket *mp_so;
	struct mptsub *mpts;
	struct mptopt smpo;
	int error = 0;

	/* just bail now if this isn't applicable to subflow sockets */
	if (!(mpo->mpo_flags & MPOF_SUBFLOW_OK)) {
		error = ENOPROTOOPT;
		goto out;
	}

	/*
	 * Skip those that are handled internally; these options
	 * should not have been recorded and marked with the
	 * MPOF_SUBFLOW_OK by mptcp_setopt(), but just in case.
	 */
	if (mpo->mpo_level == SOL_SOCKET &&
	    (mpo->mpo_name == SO_NOSIGPIPE || mpo->mpo_name == SO_NOADDRERR)) {
		error = ENOPROTOOPT;
		goto out;
	}

	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	mp_so = mpte->mpte_mppcb->mpp_socket;

	/*
	 * Don't bother going further if there's no subflow; mark the option
	 * with MPOF_INTERIM so that we know whether or not to remove this
	 * option upon encountering an error while issuing it during subflow
	 * socket creation.
	 */
	if (mpte->mpte_numflows == 0) {
		VERIFY(TAILQ_EMPTY(&mpte->mpte_subflows));
		mpo->mpo_flags |= MPOF_INTERIM;
		/* return success */
		goto out;
	}

	bzero(&smpo, sizeof (smpo));
	smpo.mpo_flags |= MPOF_SUBFLOW_OK;
	smpo.mpo_level = mpo->mpo_level;
	smpo.mpo_name = mpo->mpo_name;

	/* grab exisiting values in case we need to rollback */
	TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
		struct socket *so;

		MPTS_LOCK(mpts);
		mpts->mpts_flags &= ~(MPTSF_SOPT_OLDVAL|MPTSF_SOPT_INPROG);
		mpts->mpts_oldintval = 0;
		smpo.mpo_intval = 0;
		VERIFY(mpts->mpts_socket != NULL);
		so = mpts->mpts_socket;
		socket_lock(so, 0);
		if (mptcp_subflow_sogetopt(mpte, so, &smpo) == 0) {
			mpts->mpts_flags |= MPTSF_SOPT_OLDVAL;
			mpts->mpts_oldintval = smpo.mpo_intval;
		}
		socket_unlock(so, 0);
		MPTS_UNLOCK(mpts);
	}

	/* apply socket option */
	TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
		struct socket *so;

		MPTS_LOCK(mpts);
		mpts->mpts_flags |= MPTSF_SOPT_INPROG;
		VERIFY(mpts->mpts_socket != NULL);
		so = mpts->mpts_socket;
		socket_lock(so, 0);
		error = mptcp_subflow_sosetopt(mpte, so, mpo);
		socket_unlock(so, 0);
		MPTS_UNLOCK(mpts);
		if (error != 0)
			break;
	}

	/* cleanup, and rollback if needed */
	TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
		struct socket *so;

		MPTS_LOCK(mpts);
		if (!(mpts->mpts_flags & MPTSF_SOPT_INPROG)) {
			/* clear in case it's set */
			mpts->mpts_flags &= ~MPTSF_SOPT_OLDVAL;
			mpts->mpts_oldintval = 0;
			MPTS_UNLOCK(mpts);
			continue;
		}
		if (!(mpts->mpts_flags & MPTSF_SOPT_OLDVAL)) {
			mpts->mpts_flags &= ~MPTSF_SOPT_INPROG;
			VERIFY(mpts->mpts_oldintval == 0);
			MPTS_UNLOCK(mpts);
			continue;
		}
		/* error during sosetopt, so roll it back */
		if (error != 0) {
			VERIFY(mpts->mpts_socket != NULL);
			so = mpts->mpts_socket;
			socket_lock(so, 0);
			smpo.mpo_intval = mpts->mpts_oldintval;
			(void) mptcp_subflow_sosetopt(mpte, so, &smpo);
			socket_unlock(so, 0);
		}
		mpts->mpts_oldintval = 0;
		mpts->mpts_flags &= ~(MPTSF_SOPT_OLDVAL|MPTSF_SOPT_INPROG);
		MPTS_UNLOCK(mpts);
	}

out:
	return (error);
}

/*
 * Handle SOPT_SET for socket options issued on MP socket.
 */
static int
mptcp_setopt(struct mptses *mpte, struct sockopt *sopt)
{
	int error = 0, optval, level, optname, rec = 1;
	struct mptopt smpo, *mpo = NULL;
	struct socket *mp_so;
	char buf[32];

	level = sopt->sopt_level;
	optname = sopt->sopt_name;

	VERIFY(sopt->sopt_dir == SOPT_SET);
	VERIFY(level == SOL_SOCKET || level == IPPROTO_TCP);
	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */
	mp_so = mpte->mpte_mppcb->mpp_socket;

	/*
	 * Record socket options which are applicable to subflow sockets so
	 * that we can replay them for new ones; see mptcp_usr_socheckopt()
	 * for the list of eligible socket-level options.
	 */
	if (level == SOL_SOCKET) {
		switch (optname) {
		case SO_DEBUG:
		case SO_KEEPALIVE:
		case SO_USELOOPBACK:
		case SO_RANDOMPORT:
		case SO_TRAFFIC_CLASS:
		case SO_RECV_TRAFFIC_CLASS:
		case SO_PRIVILEGED_TRAFFIC_CLASS:
		case SO_RECV_ANYIF:
		case SO_RESTRICTIONS:
			/* record it */
			break;
		case SO_FLUSH:
			/* don't record it */
			rec = 0;
			break;
		default:
			/* nothing to do; just return success */
			goto out;
		}
	} else {
		switch (optname) {
		case TCP_NODELAY:
		case TCP_RXT_FINDROP:
		case TCP_KEEPALIVE:
		case TCP_KEEPINTVL:
		case TCP_KEEPCNT:
		case TCP_CONNECTIONTIMEOUT:
		case TCP_RXT_CONNDROPTIME:
		case PERSIST_TIMEOUT:
			/* eligible; record it */
			break;
		default:
			/* not eligible */
			error = ENOPROTOOPT;
			goto out;
		}
	}

	if ((error = sooptcopyin(sopt, &optval, sizeof (optval),
	    sizeof (optval))) != 0)
		goto out;

	if (rec) {
		/* search for an existing one; if not found, allocate */
		if ((mpo = mptcp_sopt_find(mpte, sopt)) == NULL)
			mpo = mptcp_sopt_alloc(M_WAITOK);

		if (mpo == NULL) {
			error = ENOBUFS;
		} else {
			mptcplog((LOG_DEBUG, "%s: mp_so 0x%llx sopt %s "
			    "val %d %s\n", __func__,
			    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
			    mptcp_sopt2str(level, optname, buf,
			    sizeof (buf)), optval,
			    (mpo->mpo_flags & MPOF_ATTACHED) ?
			    "updated" : "recorded"));

			/* initialize or update, as needed */
			mpo->mpo_intval = optval;
			if (!(mpo->mpo_flags & MPOF_ATTACHED)) {
				mpo->mpo_level = level;
				mpo->mpo_name = optname;
				mptcp_sopt_insert(mpte, mpo);
			}
			VERIFY(mpo->mpo_flags & MPOF_ATTACHED);
			/* this can be issued on the subflow socket */
			mpo->mpo_flags |= MPOF_SUBFLOW_OK;
		}
	} else {
		bzero(&smpo, sizeof (smpo));
		mpo = &smpo;
		mpo->mpo_flags |= MPOF_SUBFLOW_OK;
		mpo->mpo_level = level;
		mpo->mpo_name = optname;
		mpo->mpo_intval = optval;
	}
	VERIFY(mpo == NULL || error == 0);

	/* issue this socket option on existing subflows */
	if (error == 0) {
		error = mptcp_setopt_apply(mpte, mpo);
		if (error != 0 && (mpo->mpo_flags & MPOF_ATTACHED)) {
			VERIFY(mpo != &smpo);
			mptcp_sopt_remove(mpte, mpo);
			mptcp_sopt_free(mpo);
		}
		if (mpo == &smpo)
			mpo->mpo_flags &= ~MPOF_INTERIM;
	}
out:
	if (error == 0 && mpo != NULL) {
		mptcplog((LOG_ERR, "%s: mp_so 0x%llx sopt %s val %d set %s\n",
		    __func__, (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
		    mptcp_sopt2str(level, optname, buf,
		    sizeof (buf)), optval, (mpo->mpo_flags & MPOF_INTERIM) ?
		    "pending" : "successful"));
	} else if (error != 0) {
		mptcplog((LOG_ERR, "%s: mp_so 0x%llx sopt %s can't be issued "
		    "error %d\n", __func__,
		    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so), mptcp_sopt2str(level,
		    optname, buf, sizeof (buf)), error));
	}
	return (error);
}

/*
 * Handle SOPT_GET for socket options issued on MP socket.
 */
static int
mptcp_getopt(struct mptses *mpte, struct sockopt *sopt)
{
	int error = 0, optval;

	VERIFY(sopt->sopt_dir == SOPT_GET);
	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */

	/*
	 * We only handle SOPT_GET for TCP level socket options; we should
	 * not get here for socket level options since they are already
	 * handled at the socket layer.
	 */
	if (sopt->sopt_level != IPPROTO_TCP) {
		error = ENOPROTOOPT;
		goto out;
	}

	switch (sopt->sopt_name) {
	case TCP_NODELAY:
	case TCP_RXT_FINDROP:
	case TCP_KEEPALIVE:
	case TCP_KEEPINTVL:
	case TCP_KEEPCNT:
	case TCP_CONNECTIONTIMEOUT:
	case TCP_RXT_CONNDROPTIME:
	case PERSIST_TIMEOUT:
		/* eligible; get the default value just in case */
		error = mptcp_default_tcp_optval(mpte, sopt, &optval);
		break;
	default:
		/* not eligible */
		error = ENOPROTOOPT;
		break;
	}

	/*
	 * Search for a previously-issued TCP level socket option and
	 * return the recorded option value.  This assumes that the
	 * value did not get modified by the lower layer after it was
	 * issued at setsockopt(2) time.  If not found, we'll return
	 * the default value obtained ealier.
	 */
	if (error == 0) {
		struct mptopt *mpo;

		if ((mpo = mptcp_sopt_find(mpte, sopt)) != NULL)
			optval = mpo->mpo_intval;

		error = sooptcopyout(sopt, &optval, sizeof (int));
	}
out:
	return (error);
}

/*
 * Return default values for TCP socket options.  Ideally we would query the
 * subflow TCP socket, but that requires creating a subflow socket before
 * connectx(2) time.  To simplify things, just return the default values
 * that we know of.
 */
static int
mptcp_default_tcp_optval(struct mptses *mpte, struct sockopt *sopt, int *optval)
{
	int error = 0;

	VERIFY(sopt->sopt_level == IPPROTO_TCP);
	VERIFY(sopt->sopt_dir == SOPT_GET);
	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */

	/* try to do what tcp_newtcpcb() does */
	switch (sopt->sopt_name) {
	case TCP_NODELAY:
	case TCP_RXT_FINDROP:
	case TCP_KEEPINTVL:
	case TCP_KEEPCNT:
	case TCP_CONNECTIONTIMEOUT:
	case TCP_RXT_CONNDROPTIME:
		*optval = 0;
		break;

	case TCP_KEEPALIVE:
		*optval = mptcp_subflow_keeptime;
		break;

	case PERSIST_TIMEOUT:
		*optval = tcp_max_persist_timeout;
		break;

	default:
		error = ENOPROTOOPT;
		break;
	}
	return (error);
}

/*
 * MPTCP SOPT_{SET,GET} socket option handler, for options issued on the MP
 * socket, at SOL_SOCKET and IPPROTO_TCP levels.  The former is restricted
 * to those that are allowed by mptcp_usr_socheckopt().
 */
int
mptcp_ctloutput(struct socket *mp_so, struct sockopt *sopt)
{
	struct mppcb *mpp = sotomppcb(mp_so);
	struct mptses *mpte;
	int error = 0;

	if (mpp == NULL || mpp->mpp_state == MPPCB_STATE_DEAD) {
		error = EINVAL;
		goto out;
	}
	mpte = mptompte(mpp);
	MPTE_LOCK_ASSERT_HELD(mpte);	/* same as MP socket lock */

	/* we only handle socket and TCP-level socket options for MPTCP */
	if (sopt->sopt_level != SOL_SOCKET && sopt->sopt_level != IPPROTO_TCP) {
		char buf[32];
		mptcplog((LOG_DEBUG, "%s: mp_so 0x%llx sopt %s level not "
		    "handled\n", __func__, (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
		    mptcp_sopt2str(sopt->sopt_level,
		    sopt->sopt_name, buf, sizeof (buf))));
		error = EINVAL;
		goto out;
	}

	switch (sopt->sopt_dir) {
	case SOPT_SET:
		error = mptcp_setopt(mpte, sopt);
		break;

	case SOPT_GET:
		error = mptcp_getopt(mpte, sopt);
		break;
	}
out:
	return (error);
}

/*
 * Return a string representation of <sopt_level,sopt_name>
 */
const char *
mptcp_sopt2str(int level, int optname, char *dst, int size)
{
	char lbuf[32], obuf[32];
	const char *l = lbuf, *o = obuf;

	(void) snprintf(lbuf, sizeof (lbuf), "0x%x", level);
	(void) snprintf(obuf, sizeof (obuf), "0x%x", optname);

	switch (level) {
	case SOL_SOCKET:
		l = "SOL_SOCKET";
		switch (optname) {
		case SO_LINGER:
			o = "SO_LINGER";
			break;
		case SO_LINGER_SEC:
			o = "SO_LINGER_SEC";
			break;
		case SO_DEBUG:
			o = "SO_DEBUG";
			break;
		case SO_KEEPALIVE:
			o = "SO_KEEPALIVE";
			break;
		case SO_USELOOPBACK:
			o = "SO_USELOOPBACK";
			break;
		case SO_TYPE:
			o = "SO_TYPE";
			break;
		case SO_NREAD:
			o = "SO_NREAD";
			break;
		case SO_NWRITE:
			o = "SO_NWRITE";
			break;
		case SO_ERROR:
			o = "SO_ERROR";
			break;
		case SO_SNDBUF:
			o = "SO_SNDBUF";
			break;
		case SO_RCVBUF:
			o = "SO_RCVBUF";
			break;
		case SO_SNDLOWAT:
			o = "SO_SNDLOWAT";
			break;
		case SO_RCVLOWAT:
			o = "SO_RCVLOWAT";
			break;
		case SO_SNDTIMEO:
			o = "SO_SNDTIMEO";
			break;
		case SO_RCVTIMEO:
			o = "SO_RCVTIMEO";
			break;
		case SO_NKE:
			o = "SO_NKE";
			break;
		case SO_NOSIGPIPE:
			o = "SO_NOSIGPIPE";
			break;
		case SO_NOADDRERR:
			o = "SO_NOADDRERR";
			break;
		case SO_RESTRICTIONS:
			o = "SO_RESTRICTIONS";
			break;
		case SO_LABEL:
			o = "SO_LABEL";
			break;
		case SO_PEERLABEL:
			o = "SO_PEERLABEL";
			break;
		case SO_RANDOMPORT:
			o = "SO_RANDOMPORT";
			break;
		case SO_TRAFFIC_CLASS:
			o = "SO_TRAFFIC_CLASS";
			break;
		case SO_RECV_TRAFFIC_CLASS:
			o = "SO_RECV_TRAFFIC_CLASS";
			break;
		case SO_TRAFFIC_CLASS_DBG:
			o = "SO_TRAFFIC_CLASS_DBG";
			break;
		case SO_PRIVILEGED_TRAFFIC_CLASS:
			o = "SO_PRIVILEGED_TRAFFIC_CLASS";
			break;
		case SO_DEFUNCTOK:
			o = "SO_DEFUNCTOK";
			break;
		case SO_ISDEFUNCT:
			o = "SO_ISDEFUNCT";
			break;
		case SO_OPPORTUNISTIC:
			o = "SO_OPPORTUNISTIC";
			break;
		case SO_FLUSH:
			o = "SO_FLUSH";
			break;
		case SO_RECV_ANYIF:
			o = "SO_RECV_ANYIF";
			break;
		}
		break;
	case IPPROTO_TCP:
		l = "IPPROTO_TCP";
		switch (optname) {
		case TCP_KEEPALIVE:
			o = "TCP_KEEPALIVE";
			break;
		case TCP_KEEPINTVL:
			o = "TCP_KEEPINTVL";
			break;
		case TCP_KEEPCNT:
			o = "TCP_KEEPCNT";
			break;
		case TCP_CONNECTIONTIMEOUT:
			o = "TCP_CONNECTIONTIMEOUT";
			break;
		case TCP_RXT_CONNDROPTIME:
			o = "TCP_RXT_CONNDROPTIME";
			break;
		case PERSIST_TIMEOUT:
			o = "PERSIST_TIMEOUT";
			break;
		}
		break;
	}

	(void) snprintf(dst, size, "<%s,%s>", l, o);
	return (dst);
}
