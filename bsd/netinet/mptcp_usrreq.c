/*
 * Copyright (c) 2012-2017 Apple Inc. All rights reserved.
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
#include <sys/kauth.h>
#include <sys/priv.h>

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
static int mptcp_usr_connectx(struct socket *, struct sockaddr *,
    struct sockaddr *, struct proc *, uint32_t, sae_associd_t,
    sae_connid_t *, uint32_t, void *, uint32_t, struct uio *, user_ssize_t *);
static int mptcp_getassocids(struct mptses *, uint32_t *, user_addr_t);
static int mptcp_getconnids(struct mptses *, sae_associd_t, uint32_t *,
    user_addr_t);
static int mptcp_getconninfo(struct mptses *, sae_connid_t *, uint32_t *,
    uint32_t *, int32_t *, user_addr_t, socklen_t *, user_addr_t, socklen_t *,
    uint32_t *, user_addr_t, uint32_t *);
static int mptcp_usr_control(struct socket *, u_long, caddr_t, struct ifnet *,
    struct proc *);
static int mptcp_disconnect(struct mptses *);
static int mptcp_usr_disconnect(struct socket *);
static int mptcp_usr_disconnectx(struct socket *, sae_associd_t, sae_connid_t);
static struct mptses *mptcp_usrclosed(struct mptses *);
static int mptcp_usr_rcvd(struct socket *, int);
static int mptcp_usr_send(struct socket *, int, struct mbuf *,
    struct sockaddr *, struct mbuf *, struct proc *);
static int mptcp_usr_shutdown(struct socket *);
static int mptcp_usr_sosend(struct socket *, struct sockaddr *, struct uio *,
    struct mbuf *, struct mbuf *, int);
static int mptcp_usr_socheckopt(struct socket *, struct sockopt *);
static int mptcp_setopt(struct mptses *, struct sockopt *);
static int mptcp_getopt(struct mptses *, struct sockopt *);
static int mptcp_default_tcp_optval(struct mptses *, struct sockopt *, int *);
static int mptcp_usr_preconnect(struct socket *so);

struct pr_usrreqs mptcp_usrreqs = {
	.pru_attach =		mptcp_usr_attach,
	.pru_connectx =		mptcp_usr_connectx,
	.pru_control =		mptcp_usr_control,
	.pru_detach =		mptcp_usr_detach,
	.pru_disconnect =	mptcp_usr_disconnect,
	.pru_disconnectx =	mptcp_usr_disconnectx,
	.pru_peeraddr =		mp_getpeeraddr,
	.pru_rcvd =		mptcp_usr_rcvd,
	.pru_send =		mptcp_usr_send,
	.pru_shutdown =		mptcp_usr_shutdown,
	.pru_sockaddr =		mp_getsockaddr,
	.pru_sosend =		mptcp_usr_sosend,
	.pru_soreceive =	soreceive,
	.pru_socheckopt =	mptcp_usr_socheckopt,
	.pru_preconnect =	mptcp_usr_preconnect,
};


#if (DEVELOPMENT || DEBUG)
static int mptcp_disable_entitlements = 0;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, disable_entitlements, CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_disable_entitlements, 0, "Disable Multipath TCP Entitlement Checking");
#endif

int mptcp_developer_mode = 0;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, allow_aggregate, CTLFLAG_RW | CTLFLAG_LOCKED,
	&mptcp_developer_mode, 0, "Allow the Multipath aggregation mode");


/*
 * Attaches an MPTCP control block to a socket.
 */
static int
mptcp_usr_attach(struct socket *mp_so, int proto, struct proc *p)
{
#pragma unused(proto)
	int error;

	VERIFY(mpsotomppcb(mp_so) == NULL);

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
	struct mptses *mpte = mpsotompte(mp_so);
	struct mppcb *mpp = mpsotomppcb(mp_so);

	if (mpp == NULL || mpp->mpp_state == MPPCB_STATE_DEAD) {
		mptcplog((LOG_ERR, "%s state: %d\n", __func__,
			  mpp ? mpp->mpp_state : -1),
			  MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
		return (EINVAL);
	}

	/*
	 * We are done with this MPTCP socket (it has been closed);
	 * trigger all subflows to be disconnected, if not already,
	 * by initiating the PCB detach sequence (SOF_PCBCLEARING
	 * will be set.)
	 */
	mp_pcbdetach(mp_so);

	mptcp_disconnect(mpte);

	return (0);
}

/*
 * Attach MPTCP protocol to socket, allocating MP control block,
 * MPTCP session, control block, buffer space, etc.
 */
static int
mptcp_attach(struct socket *mp_so, struct proc *p)
{
#pragma unused(p)
	struct mptses *mpte = NULL;
	struct mptcb *mp_tp = NULL;
	struct mppcb *mpp = NULL;
	int error = 0;

	if (mp_so->so_snd.sb_hiwat == 0 || mp_so->so_rcv.sb_hiwat == 0) {
		error = soreserve(mp_so, tcp_sendspace, tcp_recvspace);
		if (error != 0)
			goto out;
	}

	if (mp_so->so_snd.sb_preconn_hiwat == 0) {
		soreserve_preconnect(mp_so, 2048);
	}

	if ((mp_so->so_rcv.sb_flags & SB_USRSIZE) == 0)
		mp_so->so_rcv.sb_flags |= SB_AUTOSIZE;
	if ((mp_so->so_snd.sb_flags & SB_USRSIZE) == 0)
		mp_so->so_snd.sb_flags |= SB_AUTOSIZE;

	/*
	 * MPTCP socket buffers cannot be compressed, due to the
	 * fact that each mbuf chained via m_next is a M_PKTHDR
	 * which carries some MPTCP metadata.
	 */
	mp_so->so_snd.sb_flags |= SB_NOCOMPRESS;
	mp_so->so_rcv.sb_flags |= SB_NOCOMPRESS;

	if ((error = mp_pcballoc(mp_so, &mtcbinfo)) != 0) {
		goto out;
	}

	mpp = mpsotomppcb(mp_so);
	VERIFY(mpp != NULL);
	mpte = (struct mptses *)mpp->mpp_pcbe;
	VERIFY(mpte != NULL);
	mp_tp = mpte->mpte_mptcb;
	VERIFY(mp_tp != NULL);
out:
	return (error);
}

static int
mptcp_entitlement_check(struct socket *mp_so)
{
	struct mptses *mpte = mpsotompte(mp_so);

	if (soopt_cred_check(mp_so, PRIV_NET_RESTRICTED_MULTIPATH_EXTENDED, TRUE) == 0) {
		/*
		 * This means the app has the extended entitlement. Thus,
		 * it's a first party app and can run without restrictions.
		 */
		mpte->mpte_flags |= MPTE_FIRSTPARTY;
		goto grant;
	}

#if (DEVELOPMENT || DEBUG)
	if (mptcp_disable_entitlements)
		goto grant;
#endif

	if (soopt_cred_check(mp_so, PRIV_NET_PRIVILEGED_MULTIPATH, TRUE)) {
		mptcplog((LOG_NOTICE, "%s Multipath Capability needed\n", __func__),
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_LOG);
		return (-1);
	}

	if (mpte->mpte_svctype > MPTCP_SVCTYPE_INTERACTIVE &&
	    mptcp_developer_mode == 0) {
		mptcplog((LOG_NOTICE, "%s need to set allow_aggregate sysctl\n",
			  __func__), MPTCP_SOCKET_DBG, MPTCP_LOGLVL_LOG);
		return (-1);
	}

grant:
	mptcplog((LOG_NOTICE, "%s entitlement granted for %u\n", __func__, mpte->mpte_svctype),
	    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_LOG);

	return (0);
}

/*
 * Common subroutine to open a MPTCP connection to one of the remote hosts
 * specified by dst_sl.  This includes allocating and establishing a
 * subflow TCP connection, either initially to establish MPTCP connection,
 * or to join an existing one.  Returns a connection handle upon success.
 */
static int
mptcp_connectx(struct mptses *mpte, struct sockaddr *src,
    struct sockaddr *dst, uint32_t ifscope, sae_connid_t *pcid)
{
	struct socket *mp_so = mptetoso(mpte);
	int error = 0;

	VERIFY(dst != NULL);
	VERIFY(pcid != NULL);

	mptcplog((LOG_DEBUG, "%s: mp_so 0x%llx\n", __func__,
	    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so)),
	    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_LOG);
	DTRACE_MPTCP2(connectx, struct mptses *, mpte, struct socket *, mp_so);

	error = mptcp_subflow_add(mpte, src, dst, ifscope, pcid);

	return (error);
}

/*
 * User-protocol pru_connectx callback.
 */
static int
mptcp_usr_connectx(struct socket *mp_so, struct sockaddr *src,
    struct sockaddr *dst, struct proc *p, uint32_t ifscope,
    sae_associd_t aid, sae_connid_t *pcid, uint32_t flags, void *arg,
    uint32_t arglen, struct uio *auio, user_ssize_t *bytes_written)
{
#pragma unused(p, aid, flags, arg, arglen)
	struct mppcb *mpp = mpsotomppcb(mp_so);
	struct mptses *mpte = NULL;
	struct mptcb *mp_tp = NULL;
	user_ssize_t	datalen;
	int error = 0;

	if (mpp == NULL || mpp->mpp_state == MPPCB_STATE_DEAD) {
		mptcplog((LOG_ERR, "%s state %d\n", __func__,
			  mpp ? mpp->mpp_state : -1),
			 MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
		error = EINVAL;
		goto out;
	}
	mpte = mptompte(mpp);
	VERIFY(mpte != NULL);
	mpte_lock_assert_held(mpte);

	mp_tp = mpte->mpte_mptcb;
	VERIFY(mp_tp != NULL);

	if (mp_tp->mpt_flags &  MPTCPF_FALLBACK_TO_TCP) {
		mptcplog((LOG_ERR, "%s fell back to TCP\n", __func__),
			 MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
		error = EINVAL;
		goto out;
	}

	if (dst->sa_family == AF_INET &&
	    dst->sa_len != sizeof(mpte->__mpte_dst_v4)) {
		mptcplog((LOG_ERR, "%s IPv4 dst len %u\n", __func__,
			  dst->sa_len),
			 MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
		error = EINVAL;
		goto out;
	}

	if (dst->sa_family == AF_INET6 &&
	    dst->sa_len != sizeof(mpte->__mpte_dst_v6)) {
		mptcplog((LOG_ERR, "%s IPv6 dst len %u\n", __func__,
			  dst->sa_len),
			 MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
		error = EINVAL;
		goto out;
	}

	if (!(mpte->mpte_flags & MPTE_SVCTYPE_CHECKED)) {
		if (mptcp_entitlement_check(mp_so) < 0) {
			error = EPERM;
			goto out;
		}

		mpte->mpte_flags |= MPTE_SVCTYPE_CHECKED;
	}

	if ((mp_so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)) == 0) {
		memcpy(&mpte->mpte_dst, dst, dst->sa_len);
	}

	if (src) {
		if (src->sa_family == AF_INET &&
		    src->sa_len != sizeof(mpte->__mpte_src_v4)) {
			mptcplog((LOG_ERR, "%s IPv4 src len %u\n", __func__,
				  src->sa_len),
				 MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
			error = EINVAL;
			goto out;
		}

		if (src->sa_family == AF_INET6 &&
		    src->sa_len != sizeof(mpte->__mpte_src_v6)) {
			mptcplog((LOG_ERR, "%s IPv6 src len %u\n", __func__,
				  src->sa_len),
				 MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
			error = EINVAL;
			goto out;
		}

		if ((mp_so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)) == 0) {
			memcpy(&mpte->mpte_src, src, src->sa_len);
		}
	}

	error = mptcp_connectx(mpte, src, dst, ifscope, pcid);

	/* If there is data, copy it */
	if (auio != NULL) {
		datalen = uio_resid(auio);
		socket_unlock(mp_so, 0);
		error = mp_so->so_proto->pr_usrreqs->pru_sosend(mp_so, NULL,
		    (uio_t) auio, NULL, NULL, 0);

		if (error == 0 || error == EWOULDBLOCK)
			*bytes_written = datalen - uio_resid(auio);

		if (error == EWOULDBLOCK)
			error = EINPROGRESS;

		socket_lock(mp_so, 0);
	}

out:
	return (error);
}

/*
 * Handle SIOCGASSOCIDS ioctl for PF_MULTIPATH domain.
 */
static int
mptcp_getassocids(struct mptses *mpte, uint32_t *cnt, user_addr_t aidp)
{
	mpte_lock_assert_held(mpte);	/* same as MP socket lock */

	/* MPTCP has at most 1 association */
	*cnt = (mpte->mpte_associd != SAE_ASSOCID_ANY) ? 1 : 0;

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
mptcp_getconnids(struct mptses *mpte, sae_associd_t aid, uint32_t *cnt,
    user_addr_t cidp)
{
	struct mptsub *mpts;
	int error = 0;

	mpte_lock_assert_held(mpte);	/* same as MP socket lock */

	if (aid != SAE_ASSOCID_ANY && aid != SAE_ASSOCID_ALL &&
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
mptcp_getconninfo(struct mptses *mpte, sae_connid_t *cid, uint32_t *flags,
    uint32_t *ifindex, int32_t *soerror, user_addr_t src, socklen_t *src_len,
    user_addr_t dst, socklen_t *dst_len, uint32_t *aux_type,
    user_addr_t aux_data, uint32_t *aux_len)
{
	struct socket *so;
	struct inpcb *inp;
	struct mptsub *mpts;
	int error = 0;

	*flags = 0;
	*aux_type = 0;
	*ifindex = 0;
	*soerror = 0;

	if (*cid == SAE_CONNID_ALL) {
		struct socket *mp_so = mptetoso(mpte);
		struct mptcb *mp_tp = mpte->mpte_mptcb;
		struct conninfo_multipathtcp mptcp_ci;

		if (*aux_len != 0 && *aux_len != sizeof(mptcp_ci))
			return (EINVAL);

		if (mp_so->so_state & SS_ISCONNECTING)
			*flags |= CIF_CONNECTING;
		if (mp_so->so_state & SS_ISCONNECTED)
			*flags |= CIF_CONNECTED;
		if (mp_so->so_state & SS_ISDISCONNECTING)
			*flags |= CIF_DISCONNECTING;
		if (mp_so->so_state & SS_ISDISCONNECTED)
			*flags |= CIF_DISCONNECTED;
		if (!(mp_tp->mpt_flags & MPTCPF_FALLBACK_TO_TCP))
			*flags |= CIF_MP_CAPABLE;
		if (mp_tp->mpt_flags & MPTCPF_FALLBACK_TO_TCP)
			*flags |= CIF_MP_DEGRADED;

		*src_len = 0;
		*dst_len = 0;

		*aux_type = CIAUX_MPTCP;
		*aux_len = sizeof(mptcp_ci);

		if (aux_data != USER_ADDR_NULL) {
			unsigned long i = 0;
			int initial_info_set = 0;

			bzero(&mptcp_ci, sizeof (mptcp_ci));
			mptcp_ci.mptcpci_subflow_count = mpte->mpte_numflows;
			mptcp_ci.mptcpci_switch_count = mpte->mpte_subflow_switches;

			VERIFY(sizeof(mptcp_ci.mptcpci_itfstats) == sizeof(mpte->mpte_itfstats));
			memcpy(mptcp_ci.mptcpci_itfstats, mpte->mpte_itfstats, sizeof(mptcp_ci.mptcpci_itfstats));

			TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
				if (i >= sizeof(mptcp_ci.mptcpci_subflow_connids) / sizeof(sae_connid_t))
					break;
				mptcp_ci.mptcpci_subflow_connids[i] = mpts->mpts_connid;

				if (mpts->mpts_flags & MPTSF_INITIAL_SUB) {
					inp = sotoinpcb(mpts->mpts_socket);

					mptcp_ci.mptcpci_init_rxbytes = inp->inp_stat->rxbytes;
					mptcp_ci.mptcpci_init_txbytes = inp->inp_stat->txbytes;
					initial_info_set = 1;
				}

				mptcpstats_update(mptcp_ci.mptcpci_itfstats, mpts);

				i++;
			}

			if (initial_info_set == 0) {
				mptcp_ci.mptcpci_init_rxbytes = mpte->mpte_init_rxbytes;
				mptcp_ci.mptcpci_init_txbytes = mpte->mpte_init_txbytes;
			}

			if (mpte->mpte_flags & MPTE_FIRSTPARTY)
				mptcp_ci.mptcpci_flags |= MPTCPCI_FIRSTPARTY;

			error = copyout(&mptcp_ci, aux_data, sizeof(mptcp_ci));
			if (error != 0) {
				mptcplog((LOG_ERR, "%s copyout failed: %d\n",
					  __func__, error),
					 MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
				return (error);
			}
		}

		return (0);
	}

	TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
		if (mpts->mpts_connid == *cid || *cid == SAE_CONNID_ANY)
			break;
	}
	if (mpts == NULL)
		return ((*cid == SAE_CONNID_ANY) ? ENXIO : EINVAL);

	so = mpts->mpts_socket;
	inp = sotoinpcb(so);

	if (inp->inp_vflag & INP_IPV4)
		error = in_getconninfo(so, SAE_CONNID_ANY, flags, ifindex,
				       soerror, src, src_len, dst, dst_len,
				       aux_type, aux_data, aux_len);
	else
		error = in6_getconninfo(so, SAE_CONNID_ANY, flags, ifindex,
					soerror, src, src_len, dst, dst_len,
					aux_type, aux_data, aux_len);

	if (error != 0) {
		mptcplog((LOG_ERR, "%s error from in_getconninfo %d\n",
			  __func__, error),
			 MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
		return (error);
	}

	if (mpts->mpts_flags & MPTSF_MP_CAPABLE)
		*flags |= CIF_MP_CAPABLE;
	if (mpts->mpts_flags & MPTSF_MP_DEGRADED)
		*flags |= CIF_MP_DEGRADED;
	if (mpts->mpts_flags & MPTSF_MP_READY)
		*flags |= CIF_MP_READY;
	if (mpts->mpts_flags & MPTSF_ACTIVE)
		*flags |= CIF_MP_ACTIVE;

	mptcplog((LOG_DEBUG, "%s: cid %d flags %x \n", __func__,
		  mpts->mpts_connid, mpts->mpts_flags),
		 MPTCP_SOCKET_DBG, MPTCP_LOGLVL_VERBOSE);

	return (0);
}

/*
 * User-protocol pru_control callback.
 */
static int
mptcp_usr_control(struct socket *mp_so, u_long cmd, caddr_t data,
    struct ifnet *ifp, struct proc *p)
{
#pragma unused(ifp, p)
	struct mppcb *mpp = mpsotomppcb(mp_so);
	struct mptses *mpte;
	int error = 0;

	if (mpp == NULL || mpp->mpp_state == MPPCB_STATE_DEAD) {
		error = EINVAL;
		goto out;
	}
	mpte = mptompte(mpp);
	VERIFY(mpte != NULL);

	mpte_lock_assert_held(mpte);	/* same as MP socket lock */

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

	default:
		error = EOPNOTSUPP;
		break;
	}
out:
	return (error);
}

static int
mptcp_disconnect(struct mptses *mpte)
{
	struct socket *mp_so;
	struct mptcb *mp_tp;
	int error = 0;

	mpte_lock_assert_held(mpte);	/* same as MP socket lock */

	mp_so = mptetoso(mpte);
	mp_tp = mpte->mpte_mptcb;

	mptcplog((LOG_DEBUG, "%s: mp_so 0x%llx %d\n", __func__,
	    (u_int64_t)VM_KERNEL_ADDRPERM(mp_so), mp_so->so_error),
	    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_LOG);

	DTRACE_MPTCP3(disconnectx, struct mptses *, mpte,
	    struct socket *, mp_so, struct mptcb *, mp_tp);

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

	mptcp_cancel_all_timers(mp_tp);
	if (mp_tp->mpt_state < MPTCPS_ESTABLISHED) {
		mptcp_close(mpte, mp_tp);
	} else if ((mp_so->so_options & SO_LINGER) &&
	    mp_so->so_linger == 0) {
		mptcp_drop(mpte, mp_tp, 0);
	} else {
		soisdisconnecting(mp_so);
		sbflush(&mp_so->so_rcv);
		if (mptcp_usrclosed(mpte) != NULL)
			mptcp_output(mpte);
	}

	if (error == 0)
		mptcp_subflow_workloop(mpte);

out:
	return (error);
}

/*
 * Wrapper function to support disconnect on socket
 */
static int
mptcp_usr_disconnect(struct socket *mp_so)
{
	return (mptcp_disconnect(mpsotompte(mp_so)));
}

/*
 * User-protocol pru_disconnectx callback.
 */
static int
mptcp_usr_disconnectx(struct socket *mp_so, sae_associd_t aid, sae_connid_t cid)
{
	if (aid != SAE_ASSOCID_ANY && aid != SAE_ASSOCID_ALL)
		return (EINVAL);

	if (cid != SAE_CONNID_ANY && cid != SAE_CONNID_ALL)
		return (EINVAL);

	return (mptcp_usr_disconnect(mp_so));
}

void
mptcp_finish_usrclosed(struct mptses *mpte)
{
	struct mptcb *mp_tp = mpte->mpte_mptcb;
	struct socket *mp_so = mptetoso(mpte);

	if (mp_tp->mpt_state == MPTCPS_CLOSED) {
		mpte = mptcp_close(mpte, mp_tp);
	} else if (mp_tp->mpt_state >= MPTCPS_FIN_WAIT_2) {
		soisdisconnected(mp_so);
	} else {
		struct mptsub *mpts;

		TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
			if ((mp_so->so_state & (SS_CANTRCVMORE|SS_CANTSENDMORE)) ==
			    (SS_CANTRCVMORE | SS_CANTSENDMORE))
				mptcp_subflow_disconnect(mpte, mpts);
			else
				mptcp_subflow_shutdown(mpte, mpts);
		}
	}
}

/*
 * User issued close, and wish to trail thru shutdown states.
 */
static struct mptses *
mptcp_usrclosed(struct mptses *mpte)
{
	struct mptcb *mp_tp = mpte->mpte_mptcb;

	mptcp_close_fsm(mp_tp, MPCE_CLOSE);

	/* Not everything has been acknowledged - don't close the subflows! */
	if (mp_tp->mpt_sndnxt + 1 != mp_tp->mpt_sndmax)
		return (mpte);

	mptcp_finish_usrclosed(mpte);

	return (mpte);
}

/*
 * After a receive, possible send some update to peer.
 */
static int
mptcp_usr_rcvd(struct socket *mp_so, int flags)
{
#pragma unused(flags)
	struct mppcb *mpp = mpsotomppcb(mp_so);
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
	struct mppcb *mpp = mpsotomppcb(mp_so);
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

	if (!(mp_so->so_state & SS_ISCONNECTED) &&
	    !(mp_so->so_flags1 & SOF1_PRECONNECT_DATA)) {
		error = ENOTCONN;
		goto out;
	}

	mptcp_insert_dsn(mpp, m);
	VERIFY(mp_so->so_snd.sb_flags & SB_NOCOMPRESS);
	sbappendstream(&mp_so->so_snd, m);
	m = NULL;

	error = mptcp_output(mpte);
	if (error != 0)
		goto out;

	if (mp_so->so_state & SS_ISCONNECTING) {
		if (mp_so->so_state & SS_NBIO)
			error = EWOULDBLOCK;
		else
			error = sbwait(&mp_so->so_snd);
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
	struct mppcb *mpp = mpsotomppcb(mp_so);
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

	soclearfastopen(mp_so);

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
	 *   a.	Certain socket options don't have a clear definition
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
	case SO_DELEGATED:			/* MP */
	case SO_DELEGATED_UUID:			/* MP */
#if NECP
	case SO_NECP_ATTRIBUTES:
	case SO_NECP_CLIENTUUID:
#endif /* NECP */
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
	case SO_NOWAKEFROMSLEEP:
	case SO_NOAPNFALLBK:
	case SO_MARK_CELLFALLBACK:
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

	mpte_lock_assert_held(mpte);	/* same as MP socket lock */
	mp_so = mptetoso(mpte);

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

		mpts->mpts_flags &= ~(MPTSF_SOPT_OLDVAL|MPTSF_SOPT_INPROG);
		mpts->mpts_oldintval = 0;
		smpo.mpo_intval = 0;
		VERIFY(mpts->mpts_socket != NULL);
		so = mpts->mpts_socket;
		if (mptcp_subflow_sogetopt(mpte, so, &smpo) == 0) {
			mpts->mpts_flags |= MPTSF_SOPT_OLDVAL;
			mpts->mpts_oldintval = smpo.mpo_intval;
		}
	}

	/* apply socket option */
	TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
		struct socket *so;

		mpts->mpts_flags |= MPTSF_SOPT_INPROG;
		VERIFY(mpts->mpts_socket != NULL);
		so = mpts->mpts_socket;
		error = mptcp_subflow_sosetopt(mpte, mpts, mpo);
		if (error != 0)
			break;
	}

	/* cleanup, and rollback if needed */
	TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
		struct socket *so;

		if (!(mpts->mpts_flags & MPTSF_SOPT_INPROG)) {
			/* clear in case it's set */
			mpts->mpts_flags &= ~MPTSF_SOPT_OLDVAL;
			mpts->mpts_oldintval = 0;
			continue;
		}
		if (!(mpts->mpts_flags & MPTSF_SOPT_OLDVAL)) {
			mpts->mpts_flags &= ~MPTSF_SOPT_INPROG;
			VERIFY(mpts->mpts_oldintval == 0);
			continue;
		}
		/* error during sosetopt, so roll it back */
		if (error != 0) {
			VERIFY(mpts->mpts_socket != NULL);
			so = mpts->mpts_socket;
			smpo.mpo_intval = mpts->mpts_oldintval;
			mptcp_subflow_sosetopt(mpte, mpts, &smpo);
		}
		mpts->mpts_oldintval = 0;
		mpts->mpts_flags &= ~(MPTSF_SOPT_OLDVAL|MPTSF_SOPT_INPROG);
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
	int error = 0, optval = 0, level, optname, rec = 1;
	struct mptopt smpo, *mpo = NULL;
	struct socket *mp_so;

	level = sopt->sopt_level;
	optname = sopt->sopt_name;

	VERIFY(sopt->sopt_dir == SOPT_SET);
	VERIFY(level == SOL_SOCKET || level == IPPROTO_TCP);
	mpte_lock_assert_held(mpte);	/* same as MP socket lock */
	mp_so = mptetoso(mpte);

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
		case SO_NOWAKEFROMSLEEP:
		case SO_NOAPNFALLBK:
		case SO_MARK_CELLFALLBACK:
			/* record it */
			break;
		case SO_FLUSH:
			/* don't record it */
			rec = 0;
			break;

			/* Next ones, record at MPTCP-level */
#if NECP
		case SO_NECP_CLIENTUUID:
			if (!uuid_is_null(mpsotomppcb(mp_so)->necp_client_uuid)) {
				error = EINVAL;
				goto out;
			}

			error = sooptcopyin(sopt, &mpsotomppcb(mp_so)->necp_client_uuid,
					    sizeof(uuid_t), sizeof(uuid_t));
			if (error != 0) {
				goto out;
			}

			mpsotomppcb(mp_so)->necp_cb = mptcp_session_necp_cb;
			error = necp_client_register_multipath_cb(mp_so->last_pid,
								  mpsotomppcb(mp_so)->necp_client_uuid,
								  mpsotomppcb(mp_so));
			if (error)
				goto out;

			if (uuid_is_null(mpsotomppcb(mp_so)->necp_client_uuid)) {
				error = EINVAL;
				goto out;
			}

			goto out;
		case SO_NECP_ATTRIBUTES:
#endif /* NECP */
		default:
			/* nothing to do; just return */
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
		case TCP_ADAPTIVE_READ_TIMEOUT:
		case TCP_ADAPTIVE_WRITE_TIMEOUT:
			/* eligible; record it */
			break;
		case TCP_NOTSENT_LOWAT:
			/* record at MPTCP level */
			error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval));
			if (error)
				goto out;
			if (optval < 0) {
				error = EINVAL;
				goto out;
			} else {
				if (optval == 0) {
					mp_so->so_flags &= ~SOF_NOTSENT_LOWAT;
					error = mptcp_set_notsent_lowat(mpte,0);
				} else {
					mp_so->so_flags |= SOF_NOTSENT_LOWAT;
					error = mptcp_set_notsent_lowat(mpte,
					    optval);
				}
			}
			goto out;
		case MPTCP_SERVICE_TYPE:
			/* record at MPTCP level */
			error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval));
			if (error)
				goto out;
			if (optval < 0 || optval >= MPTCP_SVCTYPE_MAX) {
				error = EINVAL;
				goto out;
			}

			mpte->mpte_svctype = optval;

			if (mptcp_entitlement_check(mp_so) < 0) {
				error = EACCES;
				goto out;
			}

			mpte->mpte_flags |= MPTE_SVCTYPE_CHECKED;

			goto out;
		case MPTCP_ALTERNATE_PORT:
			/* record at MPTCP level */
			error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval));
			if (error)
				goto out;

			if (optval < 0 || optval > UINT16_MAX) {
				error = EINVAL;
				goto out;
			}

			mpte->mpte_alternate_port = optval;

			goto out;
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
			mptcplog((LOG_DEBUG, "%s: mp_so 0x%llx sopt %s val %d %s\n",
			    __func__, (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
			    mptcp_sopt2str(level, optname), optval,
			    (mpo->mpo_flags & MPOF_ATTACHED) ?
			    "updated" : "recorded"),
			    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_LOG);

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
		mptcplog((LOG_INFO, "%s:  mp_so 0x%llx sopt %s val %d set %s\n",
		    __func__, (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
		    mptcp_sopt2str(level, optname), optval,
		    (mpo->mpo_flags & MPOF_INTERIM) ?
		    "pending" : "successful"),
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_LOG);
	} else if (error != 0) {
		mptcplog((LOG_ERR, "%s: mp_so 0x%llx sopt %s (%d, %d) val %d can't be issued error %d\n",
		    __func__, (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
		    mptcp_sopt2str(level, optname), level, optname, optval, error),
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
	}
	return (error);
}

/*
 * Handle SOPT_GET for socket options issued on MP socket.
 */
static int
mptcp_getopt(struct mptses *mpte, struct sockopt *sopt)
{
	int error = 0, optval = 0;

	VERIFY(sopt->sopt_dir == SOPT_GET);
	mpte_lock_assert_held(mpte);	/* same as MP socket lock */

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
	case TCP_ADAPTIVE_READ_TIMEOUT:
	case TCP_ADAPTIVE_WRITE_TIMEOUT:
	case TCP_NOTSENT_LOWAT:
	case MPTCP_SERVICE_TYPE:
	case MPTCP_ALTERNATE_PORT:
		/* eligible; get the default value just in case */
		error = mptcp_default_tcp_optval(mpte, sopt, &optval);
		break;
	default:
		/* not eligible */
		error = ENOPROTOOPT;
		break;
	}

	switch (sopt->sopt_name) {
	case TCP_NOTSENT_LOWAT:
		if (mptetoso(mpte)->so_flags & SOF_NOTSENT_LOWAT)
			optval = mptcp_get_notsent_lowat(mpte);
		else
			optval = 0;
		goto out;
	case MPTCP_SERVICE_TYPE:
		optval = mpte->mpte_svctype;
		goto out;
	case MPTCP_ALTERNATE_PORT:
		optval = mpte->mpte_alternate_port;
		goto out;
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
	mpte_lock_assert_held(mpte);	/* same as MP socket lock */

	/* try to do what tcp_newtcpcb() does */
	switch (sopt->sopt_name) {
	case TCP_NODELAY:
	case TCP_RXT_FINDROP:
	case TCP_KEEPINTVL:
	case TCP_KEEPCNT:
	case TCP_CONNECTIONTIMEOUT:
	case TCP_RXT_CONNDROPTIME:
	case TCP_NOTSENT_LOWAT:
	case TCP_ADAPTIVE_READ_TIMEOUT:
	case TCP_ADAPTIVE_WRITE_TIMEOUT:
	case MPTCP_SERVICE_TYPE:
	case MPTCP_ALTERNATE_PORT:
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
	struct mppcb *mpp = mpsotomppcb(mp_so);
	struct mptses *mpte;
	int error = 0;

	if (mpp == NULL || mpp->mpp_state == MPPCB_STATE_DEAD) {
		error = EINVAL;
		goto out;
	}
	mpte = mptompte(mpp);
	mpte_lock_assert_held(mpte);	/* same as MP socket lock */

	/* we only handle socket and TCP-level socket options for MPTCP */
	if (sopt->sopt_level != SOL_SOCKET && sopt->sopt_level != IPPROTO_TCP) {
		mptcplog((LOG_DEBUG, "MPTCP Socket: "
		    "%s: mp_so 0x%llx sopt %s level not "
		    "handled\n", __func__, (u_int64_t)VM_KERNEL_ADDRPERM(mp_so),
		    mptcp_sopt2str(sopt->sopt_level, sopt->sopt_name)),
		    MPTCP_SOCKET_DBG, MPTCP_LOGLVL_LOG);
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

const char *
mptcp_sopt2str(int level, int optname)
{
	switch (level) {
	case SOL_SOCKET:
		switch (optname) {
		case SO_LINGER:
			return ("SO_LINGER");
		case SO_LINGER_SEC:
			return ("SO_LINGER_SEC");
		case SO_DEBUG:
			return ("SO_DEBUG");
		case SO_KEEPALIVE:
			return ("SO_KEEPALIVE");
		case SO_USELOOPBACK:
			return ("SO_USELOOPBACK");
		case SO_TYPE:
			return ("SO_TYPE");
		case SO_NREAD:
			return ("SO_NREAD");
		case SO_NWRITE:
			return ("SO_NWRITE");
		case SO_ERROR:
			return ("SO_ERROR");
		case SO_SNDBUF:
			return ("SO_SNDBUF");
		case SO_RCVBUF:
			return ("SO_RCVBUF");
		case SO_SNDLOWAT:
			return ("SO_SNDLOWAT");
		case SO_RCVLOWAT:
			return ("SO_RCVLOWAT");
		case SO_SNDTIMEO:
			return ("SO_SNDTIMEO");
		case SO_RCVTIMEO:
			return ("SO_RCVTIMEO");
		case SO_NKE:
			return ("SO_NKE");
		case SO_NOSIGPIPE:
			return ("SO_NOSIGPIPE");
		case SO_NOADDRERR:
			return ("SO_NOADDRERR");
		case SO_RESTRICTIONS:
			return ("SO_RESTRICTIONS");
		case SO_LABEL:
			return ("SO_LABEL");
		case SO_PEERLABEL:
			return ("SO_PEERLABEL");
		case SO_RANDOMPORT:
			return ("SO_RANDOMPORT");
		case SO_TRAFFIC_CLASS:
			return ("SO_TRAFFIC_CLASS");
		case SO_RECV_TRAFFIC_CLASS:
			return ("SO_RECV_TRAFFIC_CLASS");
		case SO_TRAFFIC_CLASS_DBG:
			return ("SO_TRAFFIC_CLASS_DBG");
		case SO_PRIVILEGED_TRAFFIC_CLASS:
			return ("SO_PRIVILEGED_TRAFFIC_CLASS");
		case SO_DEFUNCTOK:
			return ("SO_DEFUNCTOK");
		case SO_ISDEFUNCT:
			return ("SO_ISDEFUNCT");
		case SO_OPPORTUNISTIC:
			return ("SO_OPPORTUNISTIC");
		case SO_FLUSH:
			return ("SO_FLUSH");
		case SO_RECV_ANYIF:
			return ("SO_RECV_ANYIF");
		case SO_NOWAKEFROMSLEEP:
			return ("SO_NOWAKEFROMSLEEP");
		case SO_NOAPNFALLBK:
			return ("SO_NOAPNFALLBK");
		case SO_MARK_CELLFALLBACK:
			return ("SO_CELLFALLBACK");
		case SO_DELEGATED:
			return ("SO_DELEGATED");
		case SO_DELEGATED_UUID:
			return ("SO_DELEGATED_UUID");
#if NECP
		case SO_NECP_ATTRIBUTES:
			return ("SO_NECP_ATTRIBUTES");
		case SO_NECP_CLIENTUUID:
			return ("SO_NECP_CLIENTUUID");
#endif /* NECP */
		}

		break;
	case IPPROTO_TCP:
		switch (optname) {
		case TCP_NODELAY:
			return ("TCP_NODELAY");
		case TCP_KEEPALIVE:
			return ("TCP_KEEPALIVE");
		case TCP_KEEPINTVL:
			return ("TCP_KEEPINTVL");
		case TCP_KEEPCNT:
			return ("TCP_KEEPCNT");
		case TCP_CONNECTIONTIMEOUT:
			return ("TCP_CONNECTIONTIMEOUT");
		case TCP_RXT_CONNDROPTIME:
			return ("TCP_RXT_CONNDROPTIME");
		case PERSIST_TIMEOUT:
			return ("PERSIST_TIMEOUT");
		case TCP_NOTSENT_LOWAT:
			return ("NOTSENT_LOWAT");
		case TCP_ADAPTIVE_READ_TIMEOUT:
			return ("ADAPTIVE_READ_TIMEOUT");
		case TCP_ADAPTIVE_WRITE_TIMEOUT:
			return ("ADAPTIVE_WRITE_TIMEOUT");
		case MPTCP_SERVICE_TYPE:
			return ("MPTCP_SERVICE_TYPE");
		case MPTCP_ALTERNATE_PORT:
			return ("MPTCP_ALTERNATE_PORT");
		}

		break;
	}

	return ("unknown");
}

static int
mptcp_usr_preconnect(struct socket *mp_so)
{
	struct mptsub *mpts = NULL;
	struct mppcb *mpp = mpsotomppcb(mp_so);
	struct mptses *mpte;
	struct socket *so;
	struct tcpcb *tp = NULL;
	int error;

	mpte = mptompte(mpp);
	VERIFY(mpte != NULL);
	mpte_lock_assert_held(mpte);    /* same as MP socket lock */

	mpts = mptcp_get_subflow(mpte, NULL, NULL);
	if (mpts == NULL) {
		mptcplog((LOG_ERR, "%s: mp_so 0x%llx invalid preconnect ",
			  __func__, (u_int64_t)VM_KERNEL_ADDRPERM(mp_so)),
			 MPTCP_SOCKET_DBG, MPTCP_LOGLVL_ERR);
		return (EINVAL);
	}
	mpts->mpts_flags &= ~MPTSF_TFO_REQD;
	so = mpts->mpts_socket;
	tp = intotcpcb(sotoinpcb(so));
	tp->t_mpflags &= ~TMPF_TFO_REQUEST;
	error = tcp_output(sototcpcb(so));

	soclearfastopen(mp_so);

	return (error);
}
