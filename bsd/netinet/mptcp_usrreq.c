/*
 * Copyright (c) 2012-2020 Apple Inc. All rights reserved.
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
static int mptcp_usr_preconnect(struct socket *so);

struct pr_usrreqs mptcp_usrreqs = {
	.pru_attach =           mptcp_usr_attach,
	.pru_connectx =         mptcp_usr_connectx,
	.pru_control =          mptcp_usr_control,
	.pru_detach =           mptcp_usr_detach,
	.pru_disconnect =       mptcp_usr_disconnect,
	.pru_disconnectx =      mptcp_usr_disconnectx,
	.pru_peeraddr =         mp_getpeeraddr,
	.pru_rcvd =             mptcp_usr_rcvd,
	.pru_send =             mptcp_usr_send,
	.pru_shutdown =         mptcp_usr_shutdown,
	.pru_sockaddr =         mp_getsockaddr,
	.pru_sosend =           mptcp_usr_sosend,
	.pru_soreceive =        soreceive,
	.pru_socheckopt =       mptcp_usr_socheckopt,
	.pru_preconnect =       mptcp_usr_preconnect,
};


#if (DEVELOPMENT || DEBUG)
static int mptcp_disable_entitlements = 0;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, disable_entitlements, CTLFLAG_RW | CTLFLAG_LOCKED,
    &mptcp_disable_entitlements, 0, "Disable Multipath TCP Entitlement Checking");
#endif

int mptcp_developer_mode = 0;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, allow_aggregate, CTLFLAG_RW | CTLFLAG_LOCKED,
    &mptcp_developer_mode, 0, "Allow the Multipath aggregation mode");

static unsigned long mptcp_expected_progress_headstart = 5000;
SYSCTL_ULONG(_net_inet_mptcp, OID_AUTO, expected_progress_headstart, CTLFLAG_RW | CTLFLAG_LOCKED,
    &mptcp_expected_progress_headstart, "Headstart to give MPTCP before meeting the progress deadline");


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
	if (error) {
		goto out;
	}

	if ((mp_so->so_options & SO_LINGER) && mp_so->so_linger == 0) {
		mp_so->so_linger = (short)(TCP_LINGERTIME * hz);
	}
out:
	return error;
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
		os_log_error(mptcp_log_handle, "%s - %lx: state: %d\n",
		    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte),
		    mpp ? mpp->mpp_state : -1);
		return EINVAL;
	}

	/*
	 * We are done with this MPTCP socket (it has been closed);
	 * trigger all subflows to be disconnected, if not already,
	 * by initiating the PCB detach sequence (SOF_PCBCLEARING
	 * will be set.)
	 */
	mp_pcbdetach(mp_so);

	mptcp_disconnect(mpte);

	return 0;
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
		if (error != 0) {
			goto out;
		}
	}

	if (mp_so->so_snd.sb_preconn_hiwat == 0) {
		soreserve_preconnect(mp_so, 2048);
	}

	if ((mp_so->so_rcv.sb_flags & SB_USRSIZE) == 0) {
		mp_so->so_rcv.sb_flags |= SB_AUTOSIZE;
	}
	if ((mp_so->so_snd.sb_flags & SB_USRSIZE) == 0) {
		mp_so->so_snd.sb_flags |= SB_AUTOSIZE;
	}

	/*
	 * MPTCP send-socket buffers cannot be compressed, due to the
	 * fact that each mbuf chained via m_next is a M_PKTHDR
	 * which carries some MPTCP metadata.
	 */
	mp_so->so_snd.sb_flags |= SB_NOCOMPRESS;

	if ((error = mp_pcballoc(mp_so, &mtcbinfo)) != 0) {
		goto out;
	}

	mpp = mpsotomppcb(mp_so);
	mpte = (struct mptses *)mpp->mpp_pcbe;
	mp_tp = mpte->mpte_mptcb;

	VERIFY(mp_tp != NULL);
out:
	return error;
}

static int
mptcp_entitlement_check(struct socket *mp_so, uint8_t svctype)
{
	struct mptses *mpte = mpsotompte(mp_so);

	/* First, check for mptcp_extended without delegation */
	if (soopt_cred_check(mp_so, PRIV_NET_RESTRICTED_MULTIPATH_EXTENDED, TRUE, FALSE) == 0) {
		/*
		 * This means the app has the extended entitlement. Thus,
		 * it's a first party app and can run without restrictions.
		 */
		mpte->mpte_flags |= MPTE_FIRSTPARTY;
		return 0;
	}

	/* Now with delegation */
	if (mp_so->so_flags & SOF_DELEGATED &&
	    soopt_cred_check(mp_so, PRIV_NET_RESTRICTED_MULTIPATH_EXTENDED, TRUE, TRUE) == 0) {
		/*
		 * This means the app has the extended entitlement. Thus,
		 * it's a first party app and can run without restrictions.
		 */
		mpte->mpte_flags |= MPTE_FIRSTPARTY;
		return 0;
	}

	if (svctype == MPTCP_SVCTYPE_AGGREGATE) {
		if (mptcp_developer_mode) {
			return 0;
		}

		os_log_error(mptcp_log_handle, "%s - %lx: MPTCP prohibited on svc %u\n",
		    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte), mpte->mpte_svctype);
		return -1;
	}

	return 0;
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
	int error = 0;

	VERIFY(dst != NULL);
	VERIFY(pcid != NULL);

	error = mptcp_subflow_add(mpte, src, dst, ifscope, pcid);

	return error;
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
	user_ssize_t    datalen;
	int error = 0;

	if (mpp == NULL || mpp->mpp_state == MPPCB_STATE_DEAD) {
		os_log_error(mptcp_log_handle, "%s - %lx: state %d\n",
		    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte),
		    mpp ? mpp->mpp_state : -1);
		error = EINVAL;
		goto out;
	}
	mpte = mptompte(mpp);
	mp_tp = mpte->mpte_mptcb;

	if (mp_tp->mpt_flags &  MPTCPF_FALLBACK_TO_TCP) {
		os_log_error(mptcp_log_handle, "%s - %lx: fell back to TCP\n",
		    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte));
		error = EINVAL;
		goto out;
	}

	if (dst->sa_family != AF_INET && dst->sa_family != AF_INET6) {
		error = EAFNOSUPPORT;
		goto out;
	}

	if (dst->sa_family == AF_INET &&
	    dst->sa_len != sizeof(mpte->__mpte_dst_v4)) {
		os_log_error(mptcp_log_handle, "%s - %lx: IPv4 dst len %u\n",
		    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte), dst->sa_len);
		error = EINVAL;
		goto out;
	}

	if (dst->sa_family == AF_INET6 &&
	    dst->sa_len != sizeof(mpte->__mpte_dst_v6)) {
		os_log_error(mptcp_log_handle, "%s - %lx: IPv6 dst len %u\n",
		    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte), dst->sa_len);
		error = EINVAL;
		goto out;
	}

	if (!(mpte->mpte_flags & MPTE_SVCTYPE_CHECKED)) {
		if (mptcp_entitlement_check(mp_so, mpte->mpte_svctype) < 0) {
			error = EPERM;
			goto out;
		}

		mpte->mpte_flags |= MPTE_SVCTYPE_CHECKED;
	}

	if ((mp_so->so_state & (SS_ISCONNECTED | SS_ISCONNECTING)) == 0) {
		memcpy(&mpte->mpte_u_dst, dst, dst->sa_len);
	}

	if (src) {
		if (src->sa_family != AF_INET && src->sa_family != AF_INET6) {
			error = EAFNOSUPPORT;
			goto out;
		}

		if (src->sa_family == AF_INET &&
		    src->sa_len != sizeof(mpte->__mpte_src_v4)) {
			os_log_error(mptcp_log_handle, "%s - %lx: IPv4 src len %u\n",
			    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte), src->sa_len);
			error = EINVAL;
			goto out;
		}

		if (src->sa_family == AF_INET6 &&
		    src->sa_len != sizeof(mpte->__mpte_src_v6)) {
			os_log_error(mptcp_log_handle, "%s - %lx: IPv6 src len %u\n",
			    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte), src->sa_len);
			error = EINVAL;
			goto out;
		}

		if ((mp_so->so_state & (SS_ISCONNECTED | SS_ISCONNECTING)) == 0) {
			memcpy(&mpte->mpte_u_src, src, src->sa_len);
		}
	}

	error = mptcp_connectx(mpte, src, dst, ifscope, pcid);

	/* If there is data, copy it */
	if (auio != NULL) {
		datalen = uio_resid(auio);
		socket_unlock(mp_so, 0);
		error = mp_so->so_proto->pr_usrreqs->pru_sosend(mp_so, NULL,
		    (uio_t) auio, NULL, NULL, 0);

		if (error == 0 || error == EWOULDBLOCK) {
			*bytes_written = datalen - uio_resid(auio);
		}

		if (error == EWOULDBLOCK) {
			error = EINPROGRESS;
		}

		socket_lock(mp_so, 0);
	}

out:
	return error;
}

/*
 * Handle SIOCGASSOCIDS ioctl for PF_MULTIPATH domain.
 */
static int
mptcp_getassocids(struct mptses *mpte, uint32_t *cnt, user_addr_t aidp)
{
	/* MPTCP has at most 1 association */
	*cnt = (mpte->mpte_associd != SAE_ASSOCID_ANY) ? 1 : 0;

	/* just asking how many there are? */
	if (aidp == USER_ADDR_NULL) {
		return 0;
	}

	return copyout(&mpte->mpte_associd, aidp,
	           sizeof(mpte->mpte_associd));
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

	if (aid != SAE_ASSOCID_ANY && aid != SAE_ASSOCID_ALL &&
	    aid != mpte->mpte_associd) {
		return EINVAL;
	}

	*cnt = mpte->mpte_numflows;

	/* just asking how many there are? */
	if (cidp == USER_ADDR_NULL) {
		return 0;
	}

	TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
		if ((error = copyout(&mpts->mpts_connid, cidp,
		    sizeof(mpts->mpts_connid))) != 0) {
			break;
		}

		cidp += sizeof(mpts->mpts_connid);
	}

	return error;
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
	*flags = 0;
	*aux_type = 0;
	*ifindex = 0;
	*soerror = 0;

	/* MPTCP-level global stats */
	if (*cid == SAE_CONNID_ALL) {
		struct socket *mp_so = mptetoso(mpte);
		struct mptcb *mp_tp = mpte->mpte_mptcb;
		struct conninfo_multipathtcp mptcp_ci;
		int error = 0;

		if (*aux_len != 0 && *aux_len != sizeof(mptcp_ci)) {
			return EINVAL;
		}

		if (mp_so->so_state & SS_ISCONNECTING) {
			*flags |= CIF_CONNECTING;
		}
		if (mp_so->so_state & SS_ISCONNECTED) {
			*flags |= CIF_CONNECTED;
		}
		if (mp_so->so_state & SS_ISDISCONNECTING) {
			*flags |= CIF_DISCONNECTING;
		}
		if (mp_so->so_state & SS_ISDISCONNECTED) {
			*flags |= CIF_DISCONNECTED;
		}
		if (!(mp_tp->mpt_flags & MPTCPF_FALLBACK_TO_TCP)) {
			*flags |= CIF_MP_CAPABLE;
		}
		if (mp_tp->mpt_flags & MPTCPF_FALLBACK_TO_TCP) {
			*flags |= CIF_MP_DEGRADED;
		}

		*src_len = 0;
		*dst_len = 0;

		*aux_type = CIAUX_MPTCP;
		*aux_len = sizeof(mptcp_ci);

		if (aux_data != USER_ADDR_NULL) {
			const struct mptsub *mpts;
			int initial_info_set = 0;
			unsigned long i = 0;

			bzero(&mptcp_ci, sizeof(mptcp_ci));
			mptcp_ci.mptcpci_subflow_count = mpte->mpte_numflows;
			mptcp_ci.mptcpci_switch_count = mpte->mpte_subflow_switches;

			VERIFY(sizeof(mptcp_ci.mptcpci_itfstats) == sizeof(mpte->mpte_itfstats));
			memcpy(mptcp_ci.mptcpci_itfstats, mpte->mpte_itfstats, sizeof(mptcp_ci.mptcpci_itfstats));

			TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
				if (i >= sizeof(mptcp_ci.mptcpci_subflow_connids) / sizeof(sae_connid_t)) {
					break;
				}
				mptcp_ci.mptcpci_subflow_connids[i] = mpts->mpts_connid;

				if (mpts->mpts_flags & MPTSF_INITIAL_SUB) {
					const struct inpcb *inp;

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

			if (mpte->mpte_flags & MPTE_FIRSTPARTY) {
				mptcp_ci.mptcpci_flags |= MPTCPCI_FIRSTPARTY;
			}

			error = copyout(&mptcp_ci, aux_data, sizeof(mptcp_ci));
			if (error != 0) {
				os_log_error(mptcp_log_handle, "%s - %lx: copyout failed: %d\n",
				    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte), error);
				return error;
			}
		}

		return 0;
	}

	/* Any stats of any subflow */
	if (*cid == SAE_CONNID_ANY) {
		const struct mptsub *mpts;
		struct socket *so;
		const struct inpcb *inp;
		int error = 0;

		mpts = TAILQ_FIRST(&mpte->mpte_subflows);
		if (mpts == NULL) {
			return ENXIO;
		}

		so = mpts->mpts_socket;
		inp = sotoinpcb(so);

		if (inp->inp_vflag & INP_IPV4) {
			error = in_getconninfo(so, SAE_CONNID_ANY, flags, ifindex,
			    soerror, src, src_len, dst, dst_len,
			    aux_type, aux_data, aux_len);
		} else {
			error = in6_getconninfo(so, SAE_CONNID_ANY, flags, ifindex,
			    soerror, src, src_len, dst, dst_len,
			    aux_type, aux_data, aux_len);
		}

		if (error != 0) {
			os_log_error(mptcp_log_handle, "%s - %lx:error from in_getconninfo %d\n",
			    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte), error);
			return error;
		}

		if (mpts->mpts_flags & MPTSF_MP_CAPABLE) {
			*flags |= CIF_MP_CAPABLE;
		}
		if (mpts->mpts_flags & MPTSF_MP_DEGRADED) {
			*flags |= CIF_MP_DEGRADED;
		}
		if (mpts->mpts_flags & MPTSF_MP_READY) {
			*flags |= CIF_MP_READY;
		}
		if (mpts->mpts_flags & MPTSF_ACTIVE) {
			*flags |= CIF_MP_ACTIVE;
		}

		return 0;
	} else {
		/* Per-interface stats */
		const struct mptsub *mpts, *orig_mpts = NULL;
		struct conninfo_tcp tcp_ci;
		const struct inpcb *inp;
		struct socket *so;
		int error = 0;
		int index;

		/* cid is thus an ifindex - range-check first! */
		if (*cid > USHRT_MAX) {
			return EINVAL;
		}

		bzero(&tcp_ci, sizeof(tcp_ci));

		/* First, get a subflow to fill in the "regular" info. */
		TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
			const struct ifnet *ifp = sotoinpcb(mpts->mpts_socket)->inp_last_outifp;

			if (ifp && ifp->if_index == *cid) {
				break;
			}
		}

		if (mpts == NULL) {
			/* No subflow there - well, let's just get the basic itf-info */
			goto interface_info;
		}

		so = mpts->mpts_socket;
		inp = sotoinpcb(so);

		/* Give it USER_ADDR_NULL, because we are doing this on our own */
		if (inp->inp_vflag & INP_IPV4) {
			error = in_getconninfo(so, SAE_CONNID_ANY, flags, ifindex,
			    soerror, src, src_len, dst, dst_len,
			    aux_type, USER_ADDR_NULL, aux_len);
		} else {
			error = in6_getconninfo(so, SAE_CONNID_ANY, flags, ifindex,
			    soerror, src, src_len, dst, dst_len,
			    aux_type, USER_ADDR_NULL, aux_len);
		}

		if (error != 0) {
			os_log_error(mptcp_log_handle, "%s - %lx:error from in_getconninfo %d\n",
			    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte), error);
			return error;
		}

		/* ToDo: Nobody is reading these flags on subflows. Why bother ? */
		if (mpts->mpts_flags & MPTSF_MP_CAPABLE) {
			*flags |= CIF_MP_CAPABLE;
		}
		if (mpts->mpts_flags & MPTSF_MP_DEGRADED) {
			*flags |= CIF_MP_DEGRADED;
		}
		if (mpts->mpts_flags & MPTSF_MP_READY) {
			*flags |= CIF_MP_READY;
		}
		if (mpts->mpts_flags & MPTSF_ACTIVE) {
			*flags |= CIF_MP_ACTIVE;
		}

		/*
		 * Now, we gather the metrics (aka., tcp_info) and roll them in
		 * across all subflows of this interface to build an aggregated
		 * view.
		 *
		 * We take the TCP_INFO from the first subflow as the "master",
		 * feeding into those fields that we do not roll.
		 */
		if (aux_data != USER_ADDR_NULL) {
			tcp_getconninfo(so, &tcp_ci);

			orig_mpts = mpts;
			TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
				const struct inpcb *mptsinp = sotoinpcb(mpts->mpts_socket);
				const struct ifnet *ifp;

				ifp = mptsinp->inp_last_outifp;

				if (ifp == NULL || ifp->if_index != *cid || mpts == orig_mpts) {
					continue;
				}

				/* Roll the itf-stats into the tcp_info */
				tcp_ci.tcpci_tcp_info.tcpi_txbytes +=
				    mptsinp->inp_stat->txbytes;
				tcp_ci.tcpci_tcp_info.tcpi_rxbytes +=
				    mptsinp->inp_stat->rxbytes;

				tcp_ci.tcpci_tcp_info.tcpi_wifi_txbytes +=
				    mptsinp->inp_wstat->txbytes;
				tcp_ci.tcpci_tcp_info.tcpi_wifi_rxbytes +=
				    mptsinp->inp_wstat->rxbytes;

				tcp_ci.tcpci_tcp_info.tcpi_wired_txbytes +=
				    mptsinp->inp_Wstat->txbytes;
				tcp_ci.tcpci_tcp_info.tcpi_wired_rxbytes +=
				    mptsinp->inp_Wstat->rxbytes;

				tcp_ci.tcpci_tcp_info.tcpi_cell_txbytes +=
				    mptsinp->inp_cstat->txbytes;
				tcp_ci.tcpci_tcp_info.tcpi_cell_rxbytes +=
				    mptsinp->inp_cstat->rxbytes;
			}
		}

interface_info:
		*aux_type = CIAUX_TCP;
		if (*aux_len == 0) {
			*aux_len = sizeof(tcp_ci);
		} else if (aux_data != USER_ADDR_NULL) {
			boolean_t create;

			/*
			 * Finally, old subflows might have been closed - we
			 * want this data as well, so grab it from the interface
			 * stats.
			 */
			create = orig_mpts != NULL;

			/*
			 * When we found a subflow, we are willing to create a stats-index
			 * because we have some data to return. If there isn't a subflow,
			 * nor anything in the stats, return EINVAL. Because the
			 * ifindex belongs to something that doesn't exist.
			 */
			index = mptcpstats_get_index_by_ifindex(mpte->mpte_itfstats, (u_short)(*cid), false);
			if (index == -1) {
				os_log_error(mptcp_log_handle,
				    "%s - %lx: Asking for too many ifindex: %u subcount %u, mpts? %s\n",
				    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte),
				    *cid, mpte->mpte_numflows,
				    orig_mpts ? "yes" : "no");

				if (orig_mpts == NULL) {
					return EINVAL;
				}
			} else {
				struct mptcp_itf_stats *stats;

				stats = &mpte->mpte_itfstats[index];

				/* Roll the itf-stats into the tcp_info */
				tcp_ci.tcpci_tcp_info.tcpi_last_outif = *cid;
				tcp_ci.tcpci_tcp_info.tcpi_txbytes +=
				    stats->mpis_txbytes;
				tcp_ci.tcpci_tcp_info.tcpi_rxbytes +=
				    stats->mpis_rxbytes;

				tcp_ci.tcpci_tcp_info.tcpi_wifi_txbytes +=
				    stats->mpis_wifi_txbytes;
				tcp_ci.tcpci_tcp_info.tcpi_wifi_rxbytes +=
				    stats->mpis_wifi_rxbytes;

				tcp_ci.tcpci_tcp_info.tcpi_wired_txbytes +=
				    stats->mpis_wired_txbytes;
				tcp_ci.tcpci_tcp_info.tcpi_wired_rxbytes +=
				    stats->mpis_wired_rxbytes;

				tcp_ci.tcpci_tcp_info.tcpi_cell_txbytes +=
				    stats->mpis_cell_txbytes;
				tcp_ci.tcpci_tcp_info.tcpi_cell_rxbytes +=
				    stats->mpis_cell_rxbytes;
			}

			*aux_len = min(*aux_len, sizeof(tcp_ci));
			error = copyout(&tcp_ci, aux_data, *aux_len);
			if (error != 0) {
				return error;
			}
		}
	}

	return 0;
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

	switch (cmd) {
	case SIOCGASSOCIDS32: {         /* struct so_aidreq32 */
		struct so_aidreq32 aidr;
		bcopy(data, &aidr, sizeof(aidr));
		error = mptcp_getassocids(mpte, &aidr.sar_cnt,
		    aidr.sar_aidp);
		if (error == 0) {
			bcopy(&aidr, data, sizeof(aidr));
		}
		break;
	}

	case SIOCGASSOCIDS64: {         /* struct so_aidreq64 */
		struct so_aidreq64 aidr;
		bcopy(data, &aidr, sizeof(aidr));
		error = mptcp_getassocids(mpte, &aidr.sar_cnt,
		    (user_addr_t)aidr.sar_aidp);
		if (error == 0) {
			bcopy(&aidr, data, sizeof(aidr));
		}
		break;
	}

	case SIOCGCONNIDS32: {          /* struct so_cidreq32 */
		struct so_cidreq32 cidr;
		bcopy(data, &cidr, sizeof(cidr));
		error = mptcp_getconnids(mpte, cidr.scr_aid, &cidr.scr_cnt,
		    cidr.scr_cidp);
		if (error == 0) {
			bcopy(&cidr, data, sizeof(cidr));
		}
		break;
	}

	case SIOCGCONNIDS64: {          /* struct so_cidreq64 */
		struct so_cidreq64 cidr;
		bcopy(data, &cidr, sizeof(cidr));
		error = mptcp_getconnids(mpte, cidr.scr_aid, &cidr.scr_cnt,
		    (user_addr_t)cidr.scr_cidp);
		if (error == 0) {
			bcopy(&cidr, data, sizeof(cidr));
		}
		break;
	}

	case SIOCGCONNINFO32: {         /* struct so_cinforeq32 */
		struct so_cinforeq32 cifr;
		bcopy(data, &cifr, sizeof(cifr));
		error = mptcp_getconninfo(mpte, &cifr.scir_cid,
		    &cifr.scir_flags, &cifr.scir_ifindex, &cifr.scir_error,
		    cifr.scir_src, &cifr.scir_src_len, cifr.scir_dst,
		    &cifr.scir_dst_len, &cifr.scir_aux_type, cifr.scir_aux_data,
		    &cifr.scir_aux_len);
		if (error == 0) {
			bcopy(&cifr, data, sizeof(cifr));
		}
		break;
	}

	case SIOCGCONNINFO64: {         /* struct so_cinforeq64 */
		struct so_cinforeq64 cifr;
		bcopy(data, &cifr, sizeof(cifr));
		error = mptcp_getconninfo(mpte, &cifr.scir_cid,
		    &cifr.scir_flags, &cifr.scir_ifindex, &cifr.scir_error,
		    (user_addr_t)cifr.scir_src, &cifr.scir_src_len,
		    (user_addr_t)cifr.scir_dst, &cifr.scir_dst_len,
		    &cifr.scir_aux_type, (user_addr_t)cifr.scir_aux_data,
		    &cifr.scir_aux_len);
		if (error == 0) {
			bcopy(&cifr, data, sizeof(cifr));
		}
		break;
	}

	default:
		error = EOPNOTSUPP;
		break;
	}
out:
	return error;
}

static int
mptcp_disconnect(struct mptses *mpte)
{
	struct socket *mp_so;
	struct mptcb *mp_tp;
	int error = 0;

	mp_so = mptetoso(mpte);
	mp_tp = mpte->mpte_mptcb;

	DTRACE_MPTCP3(disconnectx, struct mptses *, mpte,
	    struct socket *, mp_so, struct mptcb *, mp_tp);

	/* if we're not detached, go thru socket state checks */
	if (!(mp_so->so_flags & SOF_PCBCLEARING)) {
		if (!(mp_so->so_state & (SS_ISCONNECTED |
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
		if (mptcp_usrclosed(mpte) != NULL) {
			mptcp_output(mpte);
		}
	}

	if (error == 0) {
		mptcp_subflow_workloop(mpte);
	}

out:
	return error;
}

/*
 * Wrapper function to support disconnect on socket
 */
static int
mptcp_usr_disconnect(struct socket *mp_so)
{
	return mptcp_disconnect(mpsotompte(mp_so));
}

/*
 * User-protocol pru_disconnectx callback.
 */
static int
mptcp_usr_disconnectx(struct socket *mp_so, sae_associd_t aid, sae_connid_t cid)
{
	if (aid != SAE_ASSOCID_ANY && aid != SAE_ASSOCID_ALL) {
		return EINVAL;
	}

	if (cid != SAE_CONNID_ANY && cid != SAE_CONNID_ALL) {
		return EINVAL;
	}

	return mptcp_usr_disconnect(mp_so);
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
			if ((mp_so->so_state & (SS_CANTRCVMORE | SS_CANTSENDMORE)) ==
			    (SS_CANTRCVMORE | SS_CANTSENDMORE)) {
				mptcp_subflow_disconnect(mpte, mpts);
			} else {
				mptcp_subflow_shutdown(mpte, mpts);
			}
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
	if (mp_tp->mpt_sndnxt + 1 != mp_tp->mpt_sndmax) {
		return mpte;
	}

	mptcp_finish_usrclosed(mpte);

	return mpte;
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
	struct mptsub *mpts;
	int error = 0;

	if (mpp == NULL || mpp->mpp_state == MPPCB_STATE_DEAD) {
		error = EINVAL;
		goto out;
	}

	mpte = mptompte(mpp);

	TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
		struct socket *so = mpts->mpts_socket;

		if (so->so_proto->pr_flags & PR_WANTRCVD && so->so_pcb != NULL) {
			(*so->so_proto->pr_usrreqs->pru_rcvd)(so, 0);
		}
	}

	error = mptcp_output(mpte);
out:
	return error;
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

	if (prus_flags & (PRUS_OOB | PRUS_EOF)) {
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
	if (error != 0) {
		goto out;
	}

	if (mp_so->so_state & SS_ISCONNECTING) {
		if (mp_so->so_state & SS_NBIO) {
			error = EWOULDBLOCK;
		} else {
			error = sbwait(&mp_so->so_snd);
		}
	}

out:
	if (error) {
		if (m != NULL) {
			m_freem(m);
		}
		if (control != NULL) {
			m_freem(control);
		}
	}
	return error;
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
	if (mpte != NULL) {
		error = mptcp_output(mpte);
	}
out:
	return error;
}

/*
 * Copy the contents of uio into a properly sized mbuf chain.
 */
static int
mptcp_uiotombuf(struct uio *uio, int how, user_ssize_t space, struct mbuf **top)
{
	struct mbuf *m, *mb, *nm = NULL, *mtail = NULL;
	int progress, len, error;
	user_ssize_t resid, tot;

	VERIFY(top != NULL && *top == NULL);

	/*
	 * space can be zero or an arbitrary large value bound by
	 * the total data supplied by the uio.
	 */
	resid = uio_resid(uio);
	if (space > 0) {
		tot = MIN(resid, space);
	} else {
		tot = resid;
	}

	if (tot < 0 || tot > INT_MAX) {
		return EINVAL;
	}

	len = (int)tot;
	if (len == 0) {
		len = 1;
	}

	/* Loop and append maximum sized mbufs to the chain tail. */
	while (len > 0) {
		uint32_t m_needed = 1;

		if (njcl > 0 && len > MBIGCLBYTES) {
			mb = m_getpackets_internal(&m_needed, 1,
			    how, 1, M16KCLBYTES);
		} else if (len > MCLBYTES) {
			mb = m_getpackets_internal(&m_needed, 1,
			    how, 1, MBIGCLBYTES);
		} else if (len >= (signed)MINCLSIZE) {
			mb = m_getpackets_internal(&m_needed, 1,
			    how, 1, MCLBYTES);
		} else {
			mb = m_gethdr(how, MT_DATA);
		}

		/* Fail the whole operation if one mbuf can't be allocated. */
		if (mb == NULL) {
			if (nm != NULL) {
				m_freem(nm);
			}
			return ENOBUFS;
		}

		/* Book keeping. */
		VERIFY(mb->m_flags & M_PKTHDR);
		len -= ((mb->m_flags & M_EXT) ? mb->m_ext.ext_size : MHLEN);
		if (mtail != NULL) {
			mtail->m_next = mb;
		} else {
			nm = mb;
		}
		mtail = mb;
	}

	m = nm;

	progress = 0;
	/* Fill all mbufs with uio data and update header information. */
	for (mb = m; mb != NULL; mb = mb->m_next) {
		/* tot >= 0 && tot <= INT_MAX (see above) */
		len = MIN((int)M_TRAILINGSPACE(mb), (int)(tot - progress));

		error = uiomove(mtod(mb, char *), len, uio);
		if (error != 0) {
			m_freem(m);
			return error;
		}

		/* each mbuf is M_PKTHDR chained via m_next */
		mb->m_len = len;
		mb->m_pkthdr.len = len;

		progress += len;
	}
	VERIFY(progress == tot);
	*top = m;
	return 0;
}

/*
 * MPTCP socket protocol-user socket send routine, derived from sosend().
 */
static int
mptcp_usr_sosend(struct socket *mp_so, struct sockaddr *addr, struct uio *uio,
    struct mbuf *top, struct mbuf *control, int flags)
{
#pragma unused(addr)
	user_ssize_t resid, space;
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

	if (flags & (MSG_OOB | MSG_DONTROUTE)) {
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
	if (resid < 0 || resid > INT_MAX ||
	    (flags & MSG_EOR) || control != NULL) {
		error = EINVAL;
		socket_unlock(mp_so, 1);
		goto out;
	}

	OSIncrementAtomicLong(&p->p_stats->p_ru.ru_msgsnd);

	do {
		error = sosendcheck(mp_so, NULL, resid, 0, 0, flags,
		    &sblocked);
		if (error != 0) {
			goto release;
		}

		space = sbspace(&mp_so->so_snd);
		do {
			socket_unlock(mp_so, 0);
			/*
			 * Copy the data from userland into an mbuf chain.
			 */
			error = mptcp_uiotombuf(uio, M_WAITOK, space, &top);
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
			if (error != 0) {
				goto release;
			}
		} while (resid != 0 && space > 0);
	} while (resid != 0);

release:
	if (sblocked) {
		sbunlock(&mp_so->so_snd, FALSE); /* will unlock socket */
	} else {
		socket_unlock(mp_so, 1);
	}
out:
	if (top != NULL) {
		m_freem(top);
	}
	if (control != NULL) {
		m_freem(control);
	}

	soclearfastopen(mp_so);

	return error;
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
	case SO_LINGER:                         /* MP */
	case SO_LINGER_SEC:                     /* MP */
	case SO_TYPE:                           /* MP */
	case SO_NREAD:                          /* MP */
	case SO_NWRITE:                         /* MP */
	case SO_ERROR:                          /* MP */
	case SO_SNDBUF:                         /* MP */
	case SO_RCVBUF:                         /* MP */
	case SO_SNDLOWAT:                       /* MP */
	case SO_RCVLOWAT:                       /* MP */
	case SO_SNDTIMEO:                       /* MP */
	case SO_RCVTIMEO:                       /* MP */
	case SO_NKE:                            /* MP */
	case SO_NOSIGPIPE:                      /* MP */
	case SO_NOADDRERR:                      /* MP */
	case SO_LABEL:                          /* MP */
	case SO_PEERLABEL:                      /* MP */
	case SO_DEFUNCTIT:                      /* MP */
	case SO_DEFUNCTOK:                      /* MP */
	case SO_ISDEFUNCT:                      /* MP */
	case SO_TRAFFIC_CLASS_DBG:              /* MP */
	case SO_DELEGATED:                      /* MP */
	case SO_DELEGATED_UUID:                 /* MP */
#if NECP
	case SO_NECP_ATTRIBUTES:
	case SO_NECP_CLIENTUUID:
#endif /* NECP */
	case SO_MPKL_SEND_INFO:
		/*
		 * Tell the caller that these options are to be processed.
		 */
		break;

	case SO_DEBUG:                          /* MP + subflow */
	case SO_KEEPALIVE:                      /* MP + subflow */
	case SO_USELOOPBACK:                    /* MP + subflow */
	case SO_RANDOMPORT:                     /* MP + subflow */
	case SO_TRAFFIC_CLASS:                  /* MP + subflow */
	case SO_RECV_TRAFFIC_CLASS:             /* MP + subflow */
	case SO_PRIVILEGED_TRAFFIC_CLASS:       /* MP + subflow */
	case SO_RECV_ANYIF:                     /* MP + subflow */
	case SO_RESTRICTIONS:                   /* MP + subflow */
	case SO_FLUSH:                          /* MP + subflow */
	case SO_NOWAKEFROMSLEEP:
	case SO_NOAPNFALLBK:
	case SO_MARK_CELLFALLBACK:
		/*
		 * Tell the caller that these options are to be processed;
		 * these will also be recorded later by mptcp_setopt().
		 *
		 * NOTE: Only support integer option value for now.
		 */
		if (sopt->sopt_valsize != sizeof(int)) {
			error = EINVAL;
		}
		break;

	default:
		/*
		 * Tell the caller to stop immediately and return an error.
		 */
		error = ENOPROTOOPT;
		break;
	}

	return error;
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

	bzero(&smpo, sizeof(smpo));
	smpo.mpo_flags |= MPOF_SUBFLOW_OK;
	smpo.mpo_level = mpo->mpo_level;
	smpo.mpo_name = mpo->mpo_name;

	/* grab exisiting values in case we need to rollback */
	TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
		struct socket *so;

		mpts->mpts_flags &= ~(MPTSF_SOPT_OLDVAL | MPTSF_SOPT_INPROG);
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
		if (error != 0) {
			break;
		}
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
		mpts->mpts_flags &= ~(MPTSF_SOPT_OLDVAL | MPTSF_SOPT_INPROG);
	}

out:
	return error;
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
		case SO_DELEGATED:
			error = sooptcopyin(sopt, &mpte->mpte_epid,
			    sizeof(int), sizeof(int));
			if (error != 0) {
				goto err_out;
			}

			goto out;
		case SO_DELEGATED_UUID:
			error = sooptcopyin(sopt, &mpte->mpte_euuid,
			    sizeof(uuid_t), sizeof(uuid_t));
			if (error != 0) {
				goto err_out;
			}

			goto out;
#if NECP
		case SO_NECP_CLIENTUUID:
			if (!uuid_is_null(mpsotomppcb(mp_so)->necp_client_uuid)) {
				error = EINVAL;
				goto err_out;
			}

			error = sooptcopyin(sopt, &mpsotomppcb(mp_so)->necp_client_uuid,
			    sizeof(uuid_t), sizeof(uuid_t));
			if (error != 0) {
				goto err_out;
			}

			mpsotomppcb(mp_so)->necp_cb = mptcp_session_necp_cb;
			error = necp_client_register_multipath_cb(mp_so->last_pid,
			    mpsotomppcb(mp_so)->necp_client_uuid,
			    mpsotomppcb(mp_so));
			if (error) {
				goto err_out;
			}

			if (uuid_is_null(mpsotomppcb(mp_so)->necp_client_uuid)) {
				error = EINVAL;
				goto err_out;
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
			if (error) {
				goto err_out;
			}
			if (optval < 0) {
				error = EINVAL;
				goto err_out;
			} else {
				if (optval == 0) {
					mp_so->so_flags &= ~SOF_NOTSENT_LOWAT;
					error = mptcp_set_notsent_lowat(mpte, 0);
				} else {
					mp_so->so_flags |= SOF_NOTSENT_LOWAT;
					error = mptcp_set_notsent_lowat(mpte,
					    optval);
				}

				if (error) {
					goto err_out;
				}
			}
			goto out;
		case MPTCP_SERVICE_TYPE:
			/* record at MPTCP level */
			error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval));
			if (error) {
				goto err_out;
			}
			if (optval < 0 || optval >= MPTCP_SVCTYPE_MAX) {
				error = EINVAL;
				goto err_out;
			}

			if (mptcp_entitlement_check(mp_so, (uint8_t)optval) < 0) {
				error = EACCES;
				goto err_out;
			}

			mpte->mpte_svctype = (uint8_t)optval;
			mpte->mpte_flags |= MPTE_SVCTYPE_CHECKED;

			goto out;
		case MPTCP_ALTERNATE_PORT:
			/* record at MPTCP level */
			error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval));
			if (error) {
				goto err_out;
			}

			if (optval < 0 || optval > UINT16_MAX) {
				error = EINVAL;
				goto err_out;
			}

			mpte->mpte_alternate_port = (uint16_t)optval;

			goto out;
		case MPTCP_FORCE_ENABLE:
			/* record at MPTCP level */
			error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval));
			if (error) {
				goto err_out;
			}

			if (optval < 0 || optval > 1) {
				error = EINVAL;
				goto err_out;
			}

			if (optval) {
				mpte->mpte_flags |= MPTE_FORCE_ENABLE;
			} else {
				mpte->mpte_flags &= ~MPTE_FORCE_ENABLE;
			}

			goto out;
		case MPTCP_EXPECTED_PROGRESS_TARGET:
		{
			struct mptcb *mp_tp = mpte->mpte_mptcb;
			uint64_t mach_time_target;
			uint64_t nanoseconds;

			if (mpte->mpte_svctype != MPTCP_SVCTYPE_TARGET_BASED) {
				os_log(mptcp_log_handle, "%s - %lx: Can't set urgent activity when svctype is %u\n",
				    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte), mpte->mpte_svctype);
				error = EINVAL;
				goto err_out;
			}

			error = sooptcopyin(sopt, &mach_time_target, sizeof(mach_time_target), sizeof(mach_time_target));
			if (error) {
				goto err_out;
			}

			if (!mptcp_ok_to_create_subflows(mp_tp)) {
				os_log(mptcp_log_handle, "%s - %lx: Not ok to create subflows, state %u flags %#x\n",
				    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte), mp_tp->mpt_state, mp_tp->mpt_flags);
				error = EINVAL;
				goto err_out;
			}

			if (mach_time_target) {
				uint64_t time_now = 0;
				uint64_t time_now_nanoseconds;

				absolutetime_to_nanoseconds(mach_time_target, &nanoseconds);
				nanoseconds = nanoseconds - (mptcp_expected_progress_headstart * NSEC_PER_MSEC);

				time_now = mach_continuous_time();
				absolutetime_to_nanoseconds(time_now, &time_now_nanoseconds);

				nanoseconds_to_absolutetime(nanoseconds, &mach_time_target);
				/* If the timer is already running and it would
				 * fire in less than mptcp_expected_progress_headstart
				 * seconds, then it's not worth canceling it.
				 */
				if (mpte->mpte_time_target &&
				    mpte->mpte_time_target < time_now &&
				    time_now_nanoseconds > nanoseconds - (mptcp_expected_progress_headstart * NSEC_PER_MSEC)) {
					os_log(mptcp_log_handle, "%s - %lx: Not rescheduling timer %llu now %llu target %llu\n",
					    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte),
					    mpte->mpte_time_target,
					    time_now,
					    mach_time_target);
					goto out;
				}
			}

			mpte->mpte_time_target = mach_time_target;
			mptcp_set_urgency_timer(mpte);

			goto out;
		}
		default:
			/* not eligible */
			error = ENOPROTOOPT;
			goto err_out;
		}
	}

	if ((error = sooptcopyin(sopt, &optval, sizeof(optval),
	    sizeof(optval))) != 0) {
		goto err_out;
	}

	if (rec) {
		/* search for an existing one; if not found, allocate */
		if ((mpo = mptcp_sopt_find(mpte, sopt)) == NULL) {
			mpo = mptcp_sopt_alloc(Z_WAITOK);
		}

		if (mpo == NULL) {
			error = ENOBUFS;
			goto err_out;
		} else {
			/* initialize or update, as needed */
			mpo->mpo_intval = optval;
			if (!(mpo->mpo_flags & MPOF_ATTACHED)) {
				mpo->mpo_level = level;
				mpo->mpo_name = optname;
				mptcp_sopt_insert(mpte, mpo);
			}
			/* this can be issued on the subflow socket */
			mpo->mpo_flags |= MPOF_SUBFLOW_OK;
		}
	} else {
		bzero(&smpo, sizeof(smpo));
		mpo = &smpo;
		mpo->mpo_flags |= MPOF_SUBFLOW_OK;
		mpo->mpo_level = level;
		mpo->mpo_name = optname;
		mpo->mpo_intval = optval;
	}

	/* issue this socket option on existing subflows */
	error = mptcp_setopt_apply(mpte, mpo);
	if (error != 0 && (mpo->mpo_flags & MPOF_ATTACHED)) {
		VERIFY(mpo != &smpo);
		mptcp_sopt_remove(mpte, mpo);
		mptcp_sopt_free(mpo);
	}
	if (mpo == &smpo) {
		mpo->mpo_flags &= ~MPOF_INTERIM;
	}

	if (error) {
		goto err_out;
	}

out:

	return 0;

err_out:
	os_log_error(mptcp_log_handle, "%s - %lx: sopt %s (%d, %d) val %d can't be issued error %d\n",
	    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte),
	    mptcp_sopt2str(level, optname), level, optname, optval, error);
	return error;
}

static void
mptcp_fill_info_bytestats(struct tcp_info *ti, struct mptses *mpte)
{
	struct mptsub *mpts;
	int i;

	TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
		const struct inpcb *inp = sotoinpcb(mpts->mpts_socket);

		if (inp == NULL) {
			continue;
		}

		ti->tcpi_txbytes += inp->inp_stat->txbytes;
		ti->tcpi_rxbytes += inp->inp_stat->rxbytes;
		ti->tcpi_cell_txbytes += inp->inp_cstat->txbytes;
		ti->tcpi_cell_rxbytes += inp->inp_cstat->rxbytes;
		ti->tcpi_wifi_txbytes += inp->inp_wstat->txbytes;
		ti->tcpi_wifi_rxbytes += inp->inp_wstat->rxbytes;
		ti->tcpi_wired_txbytes += inp->inp_Wstat->txbytes;
		ti->tcpi_wired_rxbytes += inp->inp_Wstat->rxbytes;
	}

	for (i = 0; i < MPTCP_ITFSTATS_SIZE; i++) {
		struct mptcp_itf_stats *stats = &mpte->mpte_itfstats[i];

		ti->tcpi_txbytes += stats->mpis_txbytes;
		ti->tcpi_rxbytes += stats->mpis_rxbytes;

		ti->tcpi_wifi_txbytes += stats->mpis_wifi_txbytes;
		ti->tcpi_wifi_rxbytes += stats->mpis_wifi_rxbytes;

		ti->tcpi_wired_txbytes += stats->mpis_wired_txbytes;
		ti->tcpi_wired_rxbytes += stats->mpis_wired_rxbytes;

		ti->tcpi_cell_txbytes += stats->mpis_cell_txbytes;
		ti->tcpi_cell_rxbytes += stats->mpis_cell_rxbytes;
	}
}

static void
mptcp_fill_info(struct mptses *mpte, struct tcp_info *ti)
{
	struct mptsub *actsub = mpte->mpte_active_sub;
	struct mptcb *mp_tp = mpte->mpte_mptcb;
	struct tcpcb *acttp = NULL;

	if (actsub) {
		acttp = sototcpcb(actsub->mpts_socket);
	}

	bzero(ti, sizeof(*ti));

	ti->tcpi_state = (uint8_t)mp_tp->mpt_state;
	/* tcpi_options */
	/* tcpi_snd_wscale */
	/* tcpi_rcv_wscale */
	/* tcpi_flags */
	if (acttp) {
		ti->tcpi_rto = acttp->t_timer[TCPT_REXMT] ? acttp->t_rxtcur : 0;
	}

	/* tcpi_snd_mss */
	/* tcpi_rcv_mss */
	if (acttp) {
		ti->tcpi_rttcur = acttp->t_rttcur;
		ti->tcpi_srtt = acttp->t_srtt >> TCP_RTT_SHIFT;
		ti->tcpi_rttvar = acttp->t_rttvar >> TCP_RTTVAR_SHIFT;
		ti->tcpi_rttbest = acttp->t_rttbest >> TCP_RTT_SHIFT;
	}
	/* tcpi_snd_ssthresh */
	/* tcpi_snd_cwnd */
	/* tcpi_rcv_space */
	ti->tcpi_snd_wnd = mp_tp->mpt_sndwnd;
	ti->tcpi_snd_nxt = (uint32_t)mp_tp->mpt_sndnxt;
	ti->tcpi_rcv_nxt = (uint32_t)mp_tp->mpt_rcvnxt;
	if (acttp) {
		ti->tcpi_last_outif = (acttp->t_inpcb->inp_last_outifp == NULL) ? 0 :
		    acttp->t_inpcb->inp_last_outifp->if_index;
	}

	mptcp_fill_info_bytestats(ti, mpte);
	/* tcpi_txpackets */

	/* tcpi_txretransmitbytes */
	/* tcpi_txunacked */
	/* tcpi_rxpackets */

	/* tcpi_rxduplicatebytes */
	/* tcpi_rxoutoforderbytes */
	/* tcpi_snd_bw */
	/* tcpi_synrexmits */
	/* tcpi_unused1 */
	/* tcpi_unused2 */
	/* tcpi_cell_rxpackets */

	/* tcpi_cell_txpackets */

	/* tcpi_wifi_rxpackets */

	/* tcpi_wifi_txpackets */

	/* tcpi_wired_rxpackets */
	/* tcpi_wired_txpackets */
	/* tcpi_connstatus */
	/* TFO-stuff */
	/* ECN stuff */
	/* tcpi_ecn_recv_ce */
	/* tcpi_ecn_recv_cwr */
	if (acttp) {
		ti->tcpi_rcvoopack = acttp->t_rcvoopack;
	}
	/* tcpi_pawsdrop */
	/* tcpi_sack_recovery_episode */
	/* tcpi_reordered_pkts */
	/* tcpi_dsack_sent */
	/* tcpi_dsack_recvd */
	/* tcpi_flowhash */
	if (acttp) {
		ti->tcpi_txretransmitpackets = acttp->t_stat.rxmitpkts;
	}
}

/*
 * Handle SOPT_GET for socket options issued on MP socket.
 */
static int
mptcp_getopt(struct mptses *mpte, struct sockopt *sopt)
{
	int error = 0, optval = 0;

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
	case PERSIST_TIMEOUT:
		/* Only case for which we have a non-zero default */
		optval = tcp_max_persist_timeout;
		OS_FALLTHROUGH;
	case TCP_NODELAY:
	case TCP_RXT_FINDROP:
	case TCP_KEEPALIVE:
	case TCP_KEEPINTVL:
	case TCP_KEEPCNT:
	case TCP_CONNECTIONTIMEOUT:
	case TCP_RXT_CONNDROPTIME:
	case TCP_ADAPTIVE_READ_TIMEOUT:
	case TCP_ADAPTIVE_WRITE_TIMEOUT:
	{
		struct mptopt *mpo = mptcp_sopt_find(mpte, sopt);

		if (mpo != NULL) {
			optval = mpo->mpo_intval;
		}
		break;
	}

	/* The next ones are stored at the MPTCP-level */
	case TCP_NOTSENT_LOWAT:
		if (mptetoso(mpte)->so_flags & SOF_NOTSENT_LOWAT) {
			optval = mptcp_get_notsent_lowat(mpte);
		} else {
			optval = 0;
		}
		break;
	case TCP_INFO:
	{
		struct tcp_info ti;

		mptcp_fill_info(mpte, &ti);
		error = sooptcopyout(sopt, &ti, sizeof(struct tcp_info));

		goto out;
	}
	case MPTCP_SERVICE_TYPE:
		optval = mpte->mpte_svctype;
		break;
	case MPTCP_ALTERNATE_PORT:
		optval = mpte->mpte_alternate_port;
		break;
	case MPTCP_FORCE_ENABLE:
		optval = !!(mpte->mpte_flags & MPTE_FORCE_ENABLE);
		break;
	case MPTCP_EXPECTED_PROGRESS_TARGET:
		error = sooptcopyout(sopt, &mpte->mpte_time_target, sizeof(mpte->mpte_time_target));

		goto out;
	default:
		/* not eligible */
		error = ENOPROTOOPT;
		break;
	}

	if (error == 0) {
		error = sooptcopyout(sopt, &optval, sizeof(int));
	}

out:
	return error;
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
	socket_lock_assert_owned(mp_so);

	/* we only handle socket and TCP-level socket options for MPTCP */
	if (sopt->sopt_level != SOL_SOCKET && sopt->sopt_level != IPPROTO_TCP) {
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
	return error;
}

const char *
mptcp_sopt2str(int level, int optname)
{
	switch (level) {
	case SOL_SOCKET:
		switch (optname) {
		case SO_LINGER:
			return "SO_LINGER";
		case SO_LINGER_SEC:
			return "SO_LINGER_SEC";
		case SO_DEBUG:
			return "SO_DEBUG";
		case SO_KEEPALIVE:
			return "SO_KEEPALIVE";
		case SO_USELOOPBACK:
			return "SO_USELOOPBACK";
		case SO_TYPE:
			return "SO_TYPE";
		case SO_NREAD:
			return "SO_NREAD";
		case SO_NWRITE:
			return "SO_NWRITE";
		case SO_ERROR:
			return "SO_ERROR";
		case SO_SNDBUF:
			return "SO_SNDBUF";
		case SO_RCVBUF:
			return "SO_RCVBUF";
		case SO_SNDLOWAT:
			return "SO_SNDLOWAT";
		case SO_RCVLOWAT:
			return "SO_RCVLOWAT";
		case SO_SNDTIMEO:
			return "SO_SNDTIMEO";
		case SO_RCVTIMEO:
			return "SO_RCVTIMEO";
		case SO_NKE:
			return "SO_NKE";
		case SO_NOSIGPIPE:
			return "SO_NOSIGPIPE";
		case SO_NOADDRERR:
			return "SO_NOADDRERR";
		case SO_RESTRICTIONS:
			return "SO_RESTRICTIONS";
		case SO_LABEL:
			return "SO_LABEL";
		case SO_PEERLABEL:
			return "SO_PEERLABEL";
		case SO_RANDOMPORT:
			return "SO_RANDOMPORT";
		case SO_TRAFFIC_CLASS:
			return "SO_TRAFFIC_CLASS";
		case SO_RECV_TRAFFIC_CLASS:
			return "SO_RECV_TRAFFIC_CLASS";
		case SO_TRAFFIC_CLASS_DBG:
			return "SO_TRAFFIC_CLASS_DBG";
		case SO_PRIVILEGED_TRAFFIC_CLASS:
			return "SO_PRIVILEGED_TRAFFIC_CLASS";
		case SO_DEFUNCTIT:
			return "SO_DEFUNCTIT";
		case SO_DEFUNCTOK:
			return "SO_DEFUNCTOK";
		case SO_ISDEFUNCT:
			return "SO_ISDEFUNCT";
		case SO_OPPORTUNISTIC:
			return "SO_OPPORTUNISTIC";
		case SO_FLUSH:
			return "SO_FLUSH";
		case SO_RECV_ANYIF:
			return "SO_RECV_ANYIF";
		case SO_NOWAKEFROMSLEEP:
			return "SO_NOWAKEFROMSLEEP";
		case SO_NOAPNFALLBK:
			return "SO_NOAPNFALLBK";
		case SO_MARK_CELLFALLBACK:
			return "SO_CELLFALLBACK";
		case SO_DELEGATED:
			return "SO_DELEGATED";
		case SO_DELEGATED_UUID:
			return "SO_DELEGATED_UUID";
#if NECP
		case SO_NECP_ATTRIBUTES:
			return "SO_NECP_ATTRIBUTES";
		case SO_NECP_CLIENTUUID:
			return "SO_NECP_CLIENTUUID";
#endif /* NECP */
		}

		break;
	case IPPROTO_TCP:
		switch (optname) {
		case TCP_NODELAY:
			return "TCP_NODELAY";
		case TCP_KEEPALIVE:
			return "TCP_KEEPALIVE";
		case TCP_KEEPINTVL:
			return "TCP_KEEPINTVL";
		case TCP_KEEPCNT:
			return "TCP_KEEPCNT";
		case TCP_CONNECTIONTIMEOUT:
			return "TCP_CONNECTIONTIMEOUT";
		case TCP_RXT_CONNDROPTIME:
			return "TCP_RXT_CONNDROPTIME";
		case PERSIST_TIMEOUT:
			return "PERSIST_TIMEOUT";
		case TCP_NOTSENT_LOWAT:
			return "NOTSENT_LOWAT";
		case TCP_ADAPTIVE_READ_TIMEOUT:
			return "ADAPTIVE_READ_TIMEOUT";
		case TCP_ADAPTIVE_WRITE_TIMEOUT:
			return "ADAPTIVE_WRITE_TIMEOUT";
		case MPTCP_SERVICE_TYPE:
			return "MPTCP_SERVICE_TYPE";
		case MPTCP_ALTERNATE_PORT:
			return "MPTCP_ALTERNATE_PORT";
		case MPTCP_FORCE_ENABLE:
			return "MPTCP_FORCE_ENABLE";
		case MPTCP_EXPECTED_PROGRESS_TARGET:
			return "MPTCP_EXPECTED_PROGRESS_TARGET";
		}

		break;
	}

	return "unknown";
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

	mpts = mptcp_get_subflow(mpte, NULL);
	if (mpts == NULL) {
		os_log_error(mptcp_log_handle, "%s - %lx: invalid preconnect ",
		    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte));
		return EINVAL;
	}
	mpts->mpts_flags &= ~MPTSF_TFO_REQD;
	so = mpts->mpts_socket;
	tp = intotcpcb(sotoinpcb(so));
	tp->t_mpflags &= ~TMPF_TFO_REQUEST;
	error = tcp_output(sototcpcb(so));

	soclearfastopen(mp_so);

	return error;
}
