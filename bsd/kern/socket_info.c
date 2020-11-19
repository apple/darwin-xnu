/*
 * Copyright (c) 2005-2020 Apple Inc. All rights reserved.
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

#include <sys/types.h>
#include <sys/kernel_types.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/file_internal.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/pipe.h>
#include <sys/proc_info.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/socketvar.h>
#include <sys/unpcb.h>
#include <sys/sys_domain.h>
#include <sys/kern_event.h>
#include <sys/vsock_domain.h>
#include <mach/vm_param.h>
#include <net/ndrv_var.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp_var.h>
#include <string.h>

static void fill_sockbuf_info(struct sockbuf *sb, struct sockbuf_info *sbi);
static void fill_common_sockinfo(struct socket *so, struct socket_info *si);

static void
fill_sockbuf_info(struct sockbuf *sb, struct sockbuf_info *sbi)
{
	sbi->sbi_cc = sb->sb_cc;
	sbi->sbi_hiwat = sb->sb_hiwat;
	sbi->sbi_mbcnt = sb->sb_mbcnt;
	sbi->sbi_mbmax = sb->sb_mbmax;
	sbi->sbi_lowat = sb->sb_lowat;
	sbi->sbi_flags = (short)sb->sb_flags;
	sbi->sbi_timeo = (short)((sb->sb_timeo.tv_sec * hz) +
	    sb->sb_timeo.tv_usec / tick);
	if (sbi->sbi_timeo == 0 && sb->sb_timeo.tv_usec != 0) {
		sbi->sbi_timeo = 1;
	}
}

static void
fill_common_sockinfo(struct socket *so, struct socket_info *si)
{
	si->soi_so = (u_int64_t)VM_KERNEL_ADDRPERM(so);
	si->soi_type = so->so_type;
	si->soi_options = (short)(so->so_options & 0xffff);
	si->soi_linger = so->so_linger;
	si->soi_state = so->so_state;
	si->soi_pcb = (u_int64_t)VM_KERNEL_ADDRPERM(so->so_pcb);
	if (so->so_proto) {
		si->soi_protocol = SOCK_PROTO(so);
		if (so->so_proto->pr_domain) {
			si->soi_family = SOCK_DOM(so);
		} else {
			si->soi_family = 0;
		}
	} else {
		si->soi_protocol = si->soi_family = 0;
	}
	si->soi_qlen = so->so_qlen;
	si->soi_incqlen = so->so_incqlen;
	si->soi_qlimit = so->so_qlimit;
	si->soi_timeo = so->so_timeo;
	si->soi_error = so->so_error;
	si->soi_oobmark = so->so_oobmark;
	fill_sockbuf_info(&so->so_snd, &si->soi_snd);
	fill_sockbuf_info(&so->so_rcv, &si->soi_rcv);
}

errno_t
fill_socketinfo(struct socket *so, struct socket_info *si)
{
	errno_t error = 0;
	int domain;
	short type;
	short protocol;

	socket_lock(so, 0);

	si->soi_kind = SOCKINFO_GENERIC;

	fill_common_sockinfo(so, si);

	if (so->so_pcb == NULL || so->so_proto == 0 ||
	    so->so_proto->pr_domain == NULL) {
		goto out;
	}

	/*
	 * The kind of socket is determined by the triplet
	 * {domain, type, protocol}
	 */
	domain = SOCK_DOM(so);
	type = SOCK_TYPE(so);
	protocol = SOCK_PROTO(so);
	switch (domain) {
	case PF_INET:
	case PF_INET6: {
		struct in_sockinfo *insi = &si->soi_proto.pri_in;
		struct inpcb *inp = (struct inpcb *)so->so_pcb;

		si->soi_kind = SOCKINFO_IN;

		insi->insi_fport = inp->inp_fport;
		insi->insi_lport = inp->inp_lport;
		insi->insi_gencnt = inp->inp_gencnt;
		insi->insi_flags = inp->inp_flags;
		insi->insi_vflag = inp->inp_vflag;
		insi->insi_ip_ttl = inp->inp_ip_ttl;
		insi->insi_faddr.ina_6 = inp->inp_dependfaddr.inp6_foreign;
		insi->insi_laddr.ina_6 = inp->inp_dependladdr.inp6_local;
		insi->insi_v4.in4_tos = inp->inp_depend4.inp4_ip_tos;
		insi->insi_v6.in6_hlim = 0;
		insi->insi_v6.in6_cksum = inp->inp_depend6.inp6_cksum;
		insi->insi_v6.in6_ifindex = 0;
		insi->insi_v6.in6_hops = inp->inp_depend6.inp6_hops;

		if (type == SOCK_STREAM && (protocol == 0 ||
		    protocol == IPPROTO_TCP) && inp->inp_ppcb != NULL) {
			struct tcp_sockinfo *tcpsi = &si->soi_proto.pri_tcp;
			struct tcpcb *tp = (struct tcpcb *)inp->inp_ppcb;

			si->soi_kind = SOCKINFO_TCP;

			tcpsi->tcpsi_state = tp->t_state;
			tcpsi->tcpsi_timer[TSI_T_REXMT] =
			    tp->t_timer[TCPT_REXMT];
			tcpsi->tcpsi_timer[TSI_T_PERSIST] =
			    tp->t_timer[TCPT_PERSIST];
			tcpsi->tcpsi_timer[TSI_T_KEEP] =
			    tp->t_timer[TCPT_KEEP];
			tcpsi->tcpsi_timer[TSI_T_2MSL] =
			    tp->t_timer[TCPT_2MSL];
			tcpsi->tcpsi_mss = tp->t_maxseg;
			tcpsi->tcpsi_flags = tp->t_flags;
			tcpsi->tcpsi_tp =
			    (u_int64_t)VM_KERNEL_ADDRPERM(tp);
		}
		break;
	}
	case PF_UNIX: {
		struct unpcb *unp = (struct unpcb *)so->so_pcb;
		struct un_sockinfo *unsi = &si->soi_proto.pri_un;

		si->soi_kind = SOCKINFO_UN;

		unsi->unsi_conn_pcb =
		    (uint64_t)VM_KERNEL_ADDRPERM(unp->unp_conn);
		if (unp->unp_conn) {
			unsi->unsi_conn_so = (uint64_t)
			    VM_KERNEL_ADDRPERM(unp->unp_conn->unp_socket);
		}

		if (unp->unp_addr) {
			size_t  addrlen = unp->unp_addr->sun_len;

			if (addrlen > SOCK_MAXADDRLEN) {
				addrlen = SOCK_MAXADDRLEN;
			}
			bcopy(unp->unp_addr, &unsi->unsi_addr, addrlen);
		}
		if (unp->unp_conn && unp->unp_conn->unp_addr) {
			size_t  addrlen = unp->unp_conn->unp_addr->sun_len;

			if (addrlen > SOCK_MAXADDRLEN) {
				addrlen = SOCK_MAXADDRLEN;
			}
			bcopy(unp->unp_conn->unp_addr, &unsi->unsi_caddr,
			    addrlen);
		}
		break;
	}
	case PF_NDRV: {
		struct ndrv_cb *ndrv_cb = (struct ndrv_cb *)so->so_pcb;
		struct ndrv_info *ndrvsi = &si->soi_proto.pri_ndrv;

		si->soi_kind = SOCKINFO_NDRV;

		/* TDB lock ifnet ???? */
		if (ndrv_cb->nd_if != 0) {
			struct ifnet *ifp = ndrv_cb->nd_if;

			ndrvsi->ndrvsi_if_family = ifp->if_family;
			ndrvsi->ndrvsi_if_unit = ifp->if_unit;
			strlcpy(ndrvsi->ndrvsi_if_name, ifp->if_name, IFNAMSIZ);
		}
		break;
	}
	case PF_VSOCK: {
		const struct vsockpcb *pcb = (struct vsockpcb *)(so)->so_pcb;
		struct vsock_sockinfo *vsocksi = &si->soi_proto.pri_vsock;

		si->soi_kind = SOCKINFO_VSOCK;

		vsocksi->local_cid = pcb->local_address.cid;
		vsocksi->local_port = pcb->local_address.port;
		vsocksi->remote_cid = pcb->remote_address.cid;
		vsocksi->remote_port = pcb->remote_address.port;

		break;
	}
	case PF_SYSTEM:
		if (SOCK_PROTO(so) == SYSPROTO_EVENT) {
			struct kern_event_pcb *ev_pcb =
			    (struct kern_event_pcb *)so->so_pcb;
			struct kern_event_info *kesi =
			    &si->soi_proto.pri_kern_event;

			si->soi_kind = SOCKINFO_KERN_EVENT;

			kesi->kesi_vendor_code_filter =
			    ev_pcb->evp_vendor_code_filter;
			kesi->kesi_class_filter = ev_pcb->evp_class_filter;
			kesi->kesi_subclass_filter = ev_pcb->evp_subclass_filter;
		} else if (SOCK_PROTO(so) == SYSPROTO_CONTROL) {
			kctl_fill_socketinfo(so, si);
		}
		break;

	case PF_ROUTE:
	case PF_PPP:
	default:
		break;
	}
out:
	socket_unlock(so, 0);

	return error;
}
