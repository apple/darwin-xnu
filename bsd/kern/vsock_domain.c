/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#include <sys/domain.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/mcache.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/random.h>
#include <sys/mbuf.h>
#include <sys/vsock_domain.h>
#include <sys/vsock_transport.h>
#include <kern/task.h>
#include <kern/zalloc.h>
#include <kern/locks.h>
#include <machine/atomic.h>

#define sotovsockpcb(so) ((struct vsockpcb *)(so)->so_pcb)

#define VSOCK_PORT_RESERVED 1024

/* VSock Protocol Globals */

static struct vsock_transport * _Atomic the_vsock_transport = NULL;
static ZONE_DECLARE(vsockpcb_zone, "vsockpcbzone",
    sizeof(struct vsockpcb), ZC_NONE);
static struct vsockpcbinfo vsockinfo;

static uint32_t vsock_sendspace = VSOCK_MAX_PACKET_SIZE * 8;
static uint32_t vsock_recvspace = VSOCK_MAX_PACKET_SIZE * 8;

/* VSock PCB Helpers */

static uint32_t
vsock_get_peer_space(struct vsockpcb *pcb)
{
	return pcb->peer_buf_alloc - (pcb->tx_cnt - pcb->peer_fwd_cnt);
}

static struct vsockpcb *
vsock_get_matching_pcb(struct vsock_address src, struct vsock_address dst)
{
	struct vsockpcb *preferred = NULL;
	struct vsockpcb *match = NULL;
	struct vsockpcb *pcb = NULL;

	lck_rw_lock_shared(vsockinfo.bound_lock);
	LIST_FOREACH(pcb, &vsockinfo.bound, bound) {
		// Source cid and port must match. Only destination port must match. (Allows for a changing CID during migration)
		socket_lock(pcb->so, 1);
		if ((pcb->so->so_state & SS_ISCONNECTED || pcb->so->so_state & SS_ISCONNECTING) &&
		    pcb->local_address.cid == src.cid && pcb->local_address.port == src.port &&
		    pcb->remote_address.port == dst.port) {
			preferred = pcb;
			break;
		} else if ((pcb->local_address.cid == src.cid || pcb->local_address.cid == VMADDR_CID_ANY) &&
		    pcb->local_address.port == src.port) {
			match = pcb;
		}
		socket_unlock(pcb->so, 1);
	}
	if (!preferred && match) {
		socket_lock(match->so, 1);
		preferred = match;
	}
	lck_rw_done(vsockinfo.bound_lock);

	return preferred;
}

static errno_t
vsock_bind_address_if_free(struct vsockpcb *pcb, uint32_t local_cid, uint32_t local_port, uint32_t remote_cid, uint32_t remote_port)
{
	socket_lock_assert_owned(pcb->so);

	// Privileged ports.
	if (local_port != VMADDR_PORT_ANY && local_port < VSOCK_PORT_RESERVED &&
	    current_task() != kernel_task && proc_suser(current_proc()) != 0) {
		return EACCES;
	}

	bool taken = false;
	const bool check_remote = (remote_cid != VMADDR_CID_ANY && remote_port != VMADDR_PORT_ANY);

	struct vsockpcb *pcb_match = NULL;

	socket_unlock(pcb->so, 0);
	lck_rw_lock_exclusive(vsockinfo.bound_lock);
	LIST_FOREACH(pcb_match, &vsockinfo.bound, bound) {
		socket_lock(pcb_match->so, 1);
		if (pcb == pcb_match ||
		    (!check_remote && pcb_match->local_address.port == local_port) ||
		    (check_remote && pcb_match->local_address.port == local_port &&
		    pcb_match->remote_address.cid == remote_cid && pcb_match->remote_address.port == remote_port)) {
			socket_unlock(pcb_match->so, 1);
			taken = true;
			break;
		}
		socket_unlock(pcb_match->so, 1);
	}
	socket_lock(pcb->so, 0);
	if (!taken) {
		pcb->local_address = (struct vsock_address) { .cid = local_cid, .port = local_port };
		pcb->remote_address = (struct vsock_address) { .cid = remote_cid, .port = remote_port };
		LIST_INSERT_HEAD(&vsockinfo.bound, pcb, bound);
	}
	lck_rw_done(vsockinfo.bound_lock);

	return taken ? EADDRINUSE : 0;
}

static errno_t
vsock_bind_address(struct vsockpcb *pcb, struct vsock_address laddr, struct vsock_address raddr)
{
	if (!pcb) {
		return EINVAL;
	}

	socket_lock_assert_owned(pcb->so);

	// Certain CIDs are reserved.
	if (laddr.cid == VMADDR_CID_HYPERVISOR || laddr.cid == VMADDR_CID_RESERVED || laddr.cid == VMADDR_CID_HOST) {
		return EADDRNOTAVAIL;
	}

	// Remote address must be fully specified or not specified at all.
	if ((raddr.cid == VMADDR_CID_ANY) ^ (raddr.port == VMADDR_PORT_ANY)) {
		return EINVAL;
	}

	// Cannot bind if already bound.
	if (pcb->local_address.port != VMADDR_PORT_ANY) {
		return EINVAL;
	}

	uint32_t transport_cid;
	struct vsock_transport *transport = pcb->transport;
	errno_t error = transport->get_cid(transport->provider, &transport_cid);
	if (error) {
		return error;
	}

	// Local CID must be this transport's CID or any.
	if (laddr.cid != transport_cid && laddr.cid != VMADDR_CID_ANY) {
		return EINVAL;
	}

	if (laddr.port != VMADDR_PORT_ANY) {
		error = vsock_bind_address_if_free(pcb, laddr.cid, laddr.port, raddr.cid, raddr.port);
	} else {
		lck_mtx_lock(&vsockinfo.port_lock);

		const uint32_t first = VSOCK_PORT_RESERVED;
		const uint32_t last = VMADDR_PORT_ANY - 1;
		uint32_t count = last - first + 1;
		uint32_t *last_port = &vsockinfo.last_port;

		if (pcb->so->so_flags & SOF_BINDRANDOMPORT) {
			uint32_t random = 0;
			read_frandom(&random, sizeof(random));
			*last_port = first + (random % count);
		}

		do {
			if (count == 0) {
				lck_mtx_unlock(&vsockinfo.port_lock);
				return EADDRNOTAVAIL;
			}
			count--;

			++*last_port;
			if (*last_port < first || *last_port > last) {
				*last_port = first;
			}

			error = vsock_bind_address_if_free(pcb, laddr.cid, *last_port, raddr.cid, raddr.port);
		} while (error);

		lck_mtx_unlock(&vsockinfo.port_lock);
	}

	return error;
}

static void
vsock_unbind_pcb(struct vsockpcb *pcb, bool is_locked)
{
	if (!pcb) {
		return;
	}

	socket_lock_assert_owned(pcb->so);

	soisdisconnected(pcb->so);

	if (!pcb->bound.le_prev) {
		return;
	}

	if (!is_locked) {
		socket_unlock(pcb->so, 0);
		lck_rw_lock_exclusive(vsockinfo.bound_lock);
		socket_lock(pcb->so, 0);
		if (!pcb->bound.le_prev) {
			lck_rw_done(vsockinfo.bound_lock);
			return;
		}
	}

	LIST_REMOVE(pcb, bound);
	pcb->bound.le_next = NULL;
	pcb->bound.le_prev = NULL;

	if (!is_locked) {
		lck_rw_done(vsockinfo.bound_lock);
	}
}

static struct sockaddr *
vsock_new_sockaddr(struct vsock_address *address)
{
	if (!address) {
		return NULL;
	}

	struct sockaddr_vm *addr;
	MALLOC(addr, struct sockaddr_vm *, sizeof(*addr), M_SONAME, M_WAITOK);
	if (!addr) {
		return NULL;
	}

	bzero(addr, sizeof(*addr));
	addr->svm_len = sizeof(*addr);
	addr->svm_family = AF_VSOCK;
	addr->svm_port = address->port;
	addr->svm_cid = address->cid;

	return (struct sockaddr *)addr;
}

static errno_t
vsock_pcb_send_message(struct vsockpcb *pcb, enum vsock_operation operation, mbuf_t m)
{
	if (!pcb) {
		if (m != NULL) {
			mbuf_freem_list(m);
		}
		return EINVAL;
	}

	socket_lock_assert_owned(pcb->so);

	errno_t error;

	struct vsock_address dst = pcb->remote_address;
	if (dst.cid == VMADDR_CID_ANY || dst.port == VMADDR_PORT_ANY) {
		if (m != NULL) {
			mbuf_freem_list(m);
		}
		return EINVAL;
	}

	struct vsock_address src = pcb->local_address;
	if (src.cid == VMADDR_CID_ANY) {
		uint32_t transport_cid;
		struct vsock_transport *transport = pcb->transport;
		error = transport->get_cid(transport->provider, &transport_cid);
		if (error) {
			if (m != NULL) {
				mbuf_freem_list(m);
			}
			return error;
		}
		src.cid = transport_cid;
	}

	uint32_t buf_alloc = pcb->so->so_rcv.sb_hiwat;
	uint32_t fwd_cnt = pcb->fwd_cnt;

	if (src.cid == dst.cid) {
		pcb->last_buf_alloc = buf_alloc;
		pcb->last_fwd_cnt = fwd_cnt;

		socket_unlock(pcb->so, 0);
		error = vsock_put_message(src, dst, operation, buf_alloc, fwd_cnt, m);
		socket_lock(pcb->so, 0);
	} else {
		struct vsock_transport *transport = pcb->transport;
		error = transport->put_message(transport->provider, src, dst, operation, buf_alloc, fwd_cnt, m);

		if (!error) {
			pcb->last_buf_alloc = buf_alloc;
			pcb->last_fwd_cnt = fwd_cnt;
		}
	}

	return error;
}

static errno_t
vsock_pcb_reset_address(struct vsock_address src, struct vsock_address dst)
{
	if (dst.cid == VMADDR_CID_ANY || dst.port == VMADDR_PORT_ANY) {
		return EINVAL;
	}

	errno_t error;
	struct vsock_transport *transport = NULL;

	if (src.cid == VMADDR_CID_ANY) {
		transport = os_atomic_load(&the_vsock_transport, relaxed);
		if (transport == NULL) {
			return ENODEV;
		}

		uint32_t transport_cid;
		error = transport->get_cid(transport->provider, &transport_cid);
		if (error) {
			return error;
		}
		src.cid = transport_cid;
	}

	if (src.cid == dst.cid) {
		error = vsock_put_message(src, dst, VSOCK_RESET, 0, 0, NULL);
	} else {
		if (!transport) {
			transport = os_atomic_load(&the_vsock_transport, relaxed);
			if (transport == NULL) {
				return ENODEV;
			}
		}
		error = transport->put_message(transport->provider, src, dst, VSOCK_RESET, 0, 0, NULL);
	}

	return error;
}

static errno_t
vsock_pcb_safe_reset_address(struct vsockpcb *pcb, struct vsock_address src, struct vsock_address dst)
{
	if (pcb) {
		socket_lock_assert_owned(pcb->so);
		socket_unlock(pcb->so, 0);
	}
	errno_t error = vsock_pcb_reset_address(src, dst);
	if (pcb) {
		socket_lock(pcb->so, 0);
	}
	return error;
}

static errno_t
vsock_pcb_connect(struct vsockpcb *pcb)
{
	return vsock_pcb_send_message(pcb, VSOCK_REQUEST, NULL);
}

static errno_t
vsock_pcb_respond(struct vsockpcb *pcb)
{
	return vsock_pcb_send_message(pcb, VSOCK_RESPONSE, NULL);
}

static errno_t
vsock_pcb_send(struct vsockpcb *pcb, mbuf_t m)
{
	return vsock_pcb_send_message(pcb, VSOCK_PAYLOAD, m);
}

static errno_t
vsock_pcb_shutdown_send(struct vsockpcb *pcb)
{
	return vsock_pcb_send_message(pcb, VSOCK_SHUTDOWN_SEND, NULL);
}

static errno_t
vsock_pcb_reset(struct vsockpcb *pcb)
{
	return vsock_pcb_send_message(pcb, VSOCK_RESET, NULL);
}

static errno_t
vsock_pcb_credit_update(struct vsockpcb *pcb)
{
	return vsock_pcb_send_message(pcb, VSOCK_CREDIT_UPDATE, NULL);
}

static errno_t
vsock_pcb_credit_request(struct vsockpcb *pcb)
{
	return vsock_pcb_send_message(pcb, VSOCK_CREDIT_REQUEST, NULL);
}

static errno_t
vsock_disconnect_pcb_common(struct vsockpcb *pcb, bool is_locked)
{
	socket_lock_assert_owned(pcb->so);
	vsock_unbind_pcb(pcb, is_locked);
	return vsock_pcb_reset(pcb);
}

static errno_t
vsock_disconnect_pcb_locked(struct vsockpcb *pcb)
{
	return vsock_disconnect_pcb_common(pcb, true);
}

static errno_t
vsock_disconnect_pcb(struct vsockpcb *pcb)
{
	return vsock_disconnect_pcb_common(pcb, false);
}

static errno_t
vsock_sockaddr_vm_validate(struct vsockpcb *pcb, struct sockaddr_vm *addr)
{
	if (!pcb || !pcb->so || !addr) {
		return EINVAL;
	}

	// Validate address length.
	if (addr->svm_len < sizeof(struct sockaddr_vm)) {
		return EINVAL;
	}

	// Validate address family.
	if (addr->svm_family != AF_UNSPEC && addr->svm_family != AF_VSOCK) {
		return EAFNOSUPPORT;
	}

	// Only stream is supported currently.
	if (pcb->so->so_type != SOCK_STREAM) {
		return EAFNOSUPPORT;
	}

	return 0;
}
/* VSock Receive Handlers */

static errno_t
vsock_put_message_connected(struct vsockpcb *pcb, enum vsock_operation op, mbuf_t m)
{
	socket_lock_assert_owned(pcb->so);

	errno_t error = 0;

	switch (op) {
	case VSOCK_SHUTDOWN:
		error = vsock_disconnect_pcb(pcb);
		break;
	case VSOCK_SHUTDOWN_RECEIVE:
		socantsendmore(pcb->so);
		break;
	case VSOCK_SHUTDOWN_SEND:
		socantrcvmore(pcb->so);
		break;
	case VSOCK_PAYLOAD:
		// Add data to the receive queue then wakeup any reading threads.
		error = !sbappendstream(&pcb->so->so_rcv, m);
		if (!error) {
			sorwakeup(pcb->so);
		}
		break;
	case VSOCK_RESET:
		vsock_unbind_pcb(pcb, false);
		break;
	default:
		error = ENOTSUP;
		break;
	}

	return error;
}

static errno_t
vsock_put_message_connecting(struct vsockpcb *pcb, enum vsock_operation op)
{
	socket_lock_assert_owned(pcb->so);

	errno_t error = 0;

	switch (op) {
	case VSOCK_RESPONSE:
		soisconnected(pcb->so);
		break;
	case VSOCK_RESET:
		pcb->so->so_error = EAGAIN;
		error = vsock_disconnect_pcb(pcb);
		break;
	default:
		vsock_disconnect_pcb(pcb);
		error = ENOTSUP;
		break;
	}

	return error;
}

static errno_t
vsock_put_message_listening(struct vsockpcb *pcb, enum vsock_operation op, struct vsock_address src, struct vsock_address dst)
{
	socket_lock_assert_owned(pcb->so);

	struct sockaddr_vm addr;
	struct socket *so2 = NULL;
	struct vsockpcb *pcb2 = NULL;

	errno_t error = 0;

	switch (op) {
	case VSOCK_REQUEST:
		addr = (struct sockaddr_vm) {
			.svm_len = sizeof(addr),
			.svm_family = AF_VSOCK,
			.svm_reserved1 = 0,
			.svm_port = pcb->local_address.port,
			.svm_cid = pcb->local_address.cid
		};
		so2 = sonewconn(pcb->so, 0, (struct sockaddr *)&addr);
		if (!so2) {
			// It is likely that the backlog is full. Deny this request.
			vsock_pcb_safe_reset_address(pcb, dst, src);
			error = ECONNREFUSED;
			break;
		}

		pcb2 = sotovsockpcb(so2);
		if (!pcb2) {
			error = EINVAL;
			goto done;
		}

		error = vsock_bind_address(pcb2, dst, src);
		if (error) {
			goto done;
		}

		error = vsock_pcb_respond(pcb2);
		if (error) {
			goto done;
		}

		soisconnected(so2);

done:
		if (error) {
			soisdisconnected(so2);
			if (pcb2) {
				vsock_unbind_pcb(pcb2, false);
			}
			socket_unlock(so2, 1);
			vsock_pcb_reset_address(dst, src);
		} else {
			socket_unlock(so2, 0);
		}
		socket_lock(pcb->so, 0);

		break;
	case VSOCK_RESET:
		error = vsock_pcb_safe_reset_address(pcb, dst, src);
		break;
	default:
		vsock_pcb_safe_reset_address(pcb, dst, src);
		error = ENOTSUP;
		break;
	}

	return error;
}

/* VSock Transport */

errno_t
vsock_add_transport(struct vsock_transport *transport)
{
	if (transport == NULL || transport->provider == NULL) {
		return EINVAL;
	}
	if (!os_atomic_cmpxchg((void * volatile *)&the_vsock_transport, NULL, transport, acq_rel)) {
		return EEXIST;
	}
	return 0;
}

errno_t
vsock_remove_transport(struct vsock_transport *transport)
{
	if (!os_atomic_cmpxchg((void * volatile *)&the_vsock_transport, transport, NULL, acq_rel)) {
		return ENODEV;
	}
	return 0;
}

errno_t
vsock_reset_transport(struct vsock_transport *transport)
{
	if (transport == NULL) {
		return EINVAL;
	}

	errno_t error = 0;
	struct vsockpcb *pcb = NULL;
	struct vsockpcb *tmp_pcb = NULL;

	lck_rw_lock_exclusive(vsockinfo.bound_lock);
	LIST_FOREACH_SAFE(pcb, &vsockinfo.bound, bound, tmp_pcb) {
		// Disconnect this transport's sockets. Listen and bind sockets must stay alive.
		socket_lock(pcb->so, 1);
		if (pcb->transport == transport && pcb->so->so_state & (SS_ISCONNECTED | SS_ISCONNECTING | SS_ISDISCONNECTING)) {
			errno_t dc_error = vsock_disconnect_pcb_locked(pcb);
			if (dc_error && !error) {
				error = dc_error;
			}
		}
		socket_unlock(pcb->so, 1);
	}
	lck_rw_done(vsockinfo.bound_lock);

	return error;
}

errno_t
vsock_put_message(struct vsock_address src, struct vsock_address dst, enum vsock_operation op, uint32_t buf_alloc, uint32_t fwd_cnt, mbuf_t m)
{
	struct vsockpcb *pcb = vsock_get_matching_pcb(dst, src);
	if (!pcb) {
		if (op != VSOCK_RESET) {
			vsock_pcb_reset_address(dst, src);
		}
		if (m != NULL) {
			mbuf_freem_list(m);
		}
		return EINVAL;
	}

	socket_lock_assert_owned(pcb->so);

	struct socket *so = pcb->so;
	errno_t error = 0;

	// Check if the peer's buffer has changed. Update our view of the peer's forwarded bytes.
	int buffers_changed = (pcb->peer_buf_alloc != buf_alloc) || (pcb->peer_fwd_cnt) != fwd_cnt;
	pcb->peer_buf_alloc = buf_alloc;
	pcb->peer_fwd_cnt = fwd_cnt;

	// Peer's buffer has enough space for the next packet. Notify any threads waiting for space.
	if (buffers_changed && vsock_get_peer_space(pcb) >= pcb->waiting_send_size) {
		sowwakeup(so);
	}

	switch (op) {
	case VSOCK_CREDIT_REQUEST:
		error = vsock_pcb_credit_update(pcb);
		break;
	case VSOCK_CREDIT_UPDATE:
		break;
	default:
		if (so->so_state & SS_ISCONNECTED) {
			error = vsock_put_message_connected(pcb, op, m);
			m = NULL;
		} else if (so->so_state & SS_ISCONNECTING) {
			error = vsock_put_message_connecting(pcb, op);
		} else if (so->so_options & SO_ACCEPTCONN) {
			error = vsock_put_message_listening(pcb, op, src, dst);
		} else {
			// Reset the connection for other states such as 'disconnecting'.
			error = vsock_disconnect_pcb(pcb);
			if (!error) {
				error = ENODEV;
			}
		}
		break;
	}
	socket_unlock(so, 1);

	if (m != NULL) {
		mbuf_freem_list(m);
	}

	return error;
}

/* VSock Sysctl */

static int
vsock_pcblist SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp,arg2)

	int error;

	// Only stream is supported.
	if ((intptr_t)arg1 != SOCK_STREAM) {
		return EINVAL;
	}

	// Get the generation count and the count of all vsock sockets.
	lck_rw_lock_shared(vsockinfo.all_lock);
	uint64_t n = vsockinfo.all_pcb_count;
	vsock_gen_t gen_count = vsockinfo.vsock_gencnt;
	lck_rw_done(vsockinfo.all_lock);

	const size_t xpcb_len = sizeof(struct xvsockpcb);
	struct xvsockpgen xvg;

	/*
	 * The process of preparing the PCB list is too time-consuming and
	 * resource-intensive to repeat twice on every request.
	 */
	if (req->oldptr == USER_ADDR_NULL) {
		req->oldidx = (size_t)(2 * sizeof(xvg) + (n + n / 8) * xpcb_len);
		return 0;
	}

	if (req->newptr != USER_ADDR_NULL) {
		return EPERM;
	}

	bzero(&xvg, sizeof(xvg));
	xvg.xvg_len = sizeof(xvg);
	xvg.xvg_count = n;
	xvg.xvg_gen = gen_count;
	xvg.xvg_sogen = so_gencnt;
	error = SYSCTL_OUT(req, &xvg, sizeof(xvg));
	if (error) {
		return error;
	}

	// Return if no sockets exist.
	if (n == 0) {
		return 0;
	}

	lck_rw_lock_shared(vsockinfo.all_lock);

	n = 0;
	struct vsockpcb *pcb = NULL;
	TAILQ_FOREACH(pcb, &vsockinfo.all, all) {
		// Bail if there is not enough user buffer for this next socket.
		if (req->oldlen - req->oldidx - sizeof(xvg) < xpcb_len) {
			break;
		}

		// Populate the socket structure.
		socket_lock(pcb->so, 1);
		if (pcb->vsock_gencnt <= gen_count) {
			struct xvsockpcb xpcb;
			bzero(&xpcb, xpcb_len);
			xpcb.xv_len = xpcb_len;
			xpcb.xv_vsockpp = (uint64_t)VM_KERNEL_ADDRHASH(pcb);
			xpcb.xvp_local_cid = pcb->local_address.cid;
			xpcb.xvp_local_port = pcb->local_address.port;
			xpcb.xvp_remote_cid = pcb->remote_address.cid;
			xpcb.xvp_remote_port = pcb->remote_address.port;
			xpcb.xvp_rxcnt = pcb->fwd_cnt;
			xpcb.xvp_txcnt = pcb->tx_cnt;
			xpcb.xvp_peer_rxhiwat = pcb->peer_buf_alloc;
			xpcb.xvp_peer_rxcnt = pcb->peer_fwd_cnt;
			xpcb.xvp_last_pid = pcb->so->last_pid;
			xpcb.xvp_gencnt = pcb->vsock_gencnt;
			if (pcb->so) {
				sotoxsocket(pcb->so, &xpcb.xv_socket);
			}
			socket_unlock(pcb->so, 1);

			error = SYSCTL_OUT(req, &xpcb, xpcb_len);
			if (error != 0) {
				break;
			}
			n++;
		} else {
			socket_unlock(pcb->so, 1);
		}
	}

	// Update the generation count to match the sockets being returned.
	gen_count = vsockinfo.vsock_gencnt;

	lck_rw_done(vsockinfo.all_lock);

	if (!error) {
		/*
		 * Give the user an updated idea of our state.
		 * If the generation differs from what we told
		 * her before, she knows that something happened
		 * while we were processing this request, and it
		 * might be necessary to retry.
		 */
		bzero(&xvg, sizeof(xvg));
		xvg.xvg_len = sizeof(xvg);
		xvg.xvg_count = n;
		xvg.xvg_gen = gen_count;
		xvg.xvg_sogen = so_gencnt;
		error = SYSCTL_OUT(req, &xvg, sizeof(xvg));
	}

	return error;
}

#ifdef SYSCTL_DECL
SYSCTL_NODE(_net, OID_AUTO, vsock, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "vsock");
SYSCTL_UINT(_net_vsock, OID_AUTO, sendspace, CTLFLAG_RW | CTLFLAG_LOCKED,
    &vsock_sendspace, 0, "Maximum outgoing vsock datagram size");
SYSCTL_UINT(_net_vsock, OID_AUTO, recvspace, CTLFLAG_RW | CTLFLAG_LOCKED,
    &vsock_recvspace, 0, "Maximum incoming vsock datagram size");
SYSCTL_PROC(_net_vsock, OID_AUTO, pcblist,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (caddr_t)(long)SOCK_STREAM, 0, vsock_pcblist, "S,xvsockpcb",
    "List of active vsock sockets");
#endif

/* VSock Protocol */

static int
vsock_attach(struct socket *so, int proto, struct proc *p)
{
	#pragma unused(proto, p)

	// Attach should only be run once per socket.
	struct vsockpcb *pcb = sotovsockpcb(so);
	if (pcb) {
		return EINVAL;
	}

	// Get the transport for this socket.
	struct vsock_transport *transport = os_atomic_load(&the_vsock_transport, relaxed);
	if (transport == NULL) {
		return ENODEV;
	}

	// Reserve send and receive buffers.
	errno_t error = soreserve(so, vsock_sendspace, vsock_recvspace);
	if (error) {
		return error;
	}

	// Initialize the vsock protocol control block.
	pcb = zalloc(vsockpcb_zone);
	if (pcb == NULL) {
		return ENOBUFS;
	}
	bzero(pcb, sizeof(*pcb));
	pcb->so = so;
	pcb->transport = transport;
	pcb->local_address = (struct vsock_address) {
		.cid = VMADDR_CID_ANY,
		.port = VMADDR_PORT_ANY
	};
	pcb->remote_address = (struct vsock_address) {
		.cid = VMADDR_CID_ANY,
		.port = VMADDR_PORT_ANY
	};
	so->so_pcb = pcb;

	// Tell the transport that this socket has attached.
	error = transport->attach_socket(transport->provider);
	if (error) {
		return error;
	}

	// Add to the list of all vsock sockets.
	lck_rw_lock_exclusive(vsockinfo.all_lock);
	TAILQ_INSERT_TAIL(&vsockinfo.all, pcb, all);
	vsockinfo.all_pcb_count++;
	pcb->vsock_gencnt = ++vsockinfo.vsock_gencnt;
	lck_rw_done(vsockinfo.all_lock);

	return 0;
}

static int
vsock_control(struct socket *so, u_long cmd, caddr_t data, struct ifnet *ifp, struct proc *p)
{
	#pragma unused(ifp)

	VERIFY(so != NULL || p == kernproc);

	if (cmd != IOCTL_VM_SOCKETS_GET_LOCAL_CID) {
		return EINVAL;
	}

	struct vsock_transport *transport;
	if (so) {
		struct vsockpcb *pcb = sotovsockpcb(so);
		if (pcb == NULL) {
			return EINVAL;
		}
		transport = pcb->transport;
	} else {
		transport = os_atomic_load(&the_vsock_transport, relaxed);
	}

	if (transport == NULL) {
		return ENODEV;
	}

	uint32_t transport_cid;
	errno_t error = transport->get_cid(transport->provider, &transport_cid);
	if (error) {
		return error;
	}

	memcpy(data, &transport_cid, sizeof(transport_cid));

	return 0;
}

static int
vsock_detach(struct socket *so)
{
	struct vsockpcb *pcb = sotovsockpcb(so);
	if (pcb == NULL) {
		return EINVAL;
	}

	vsock_unbind_pcb(pcb, false);

	// Tell the transport that this socket has detached.
	struct vsock_transport *transport = pcb->transport;
	errno_t error = transport->detach_socket(transport->provider);
	if (error) {
		return error;
	}

	// Remove from the list of all vsock sockets.
	lck_rw_lock_exclusive(vsockinfo.all_lock);
	TAILQ_REMOVE(&vsockinfo.all, pcb, all);
	pcb->all.tqe_next = NULL;
	pcb->all.tqe_prev = NULL;
	vsockinfo.all_pcb_count--;
	vsockinfo.vsock_gencnt++;
	lck_rw_done(vsockinfo.all_lock);

	// Deallocate any resources.
	zfree(vsockpcb_zone, pcb);
	so->so_pcb = 0;
	so->so_flags |= SOF_PCBCLEARING;
	sofree(so);

	return 0;
}

static int
vsock_abort(struct socket *so)
{
	soisdisconnected(so);
	return vsock_detach(so);
}

static int
vsock_bind(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	#pragma unused(p)

	struct vsockpcb *pcb = sotovsockpcb(so);
	if (pcb == NULL) {
		return EINVAL;
	}

	struct sockaddr_vm *addr = (struct sockaddr_vm *)nam;

	errno_t error = vsock_sockaddr_vm_validate(pcb, addr);
	if (error) {
		return error;
	}

	struct vsock_address laddr = (struct vsock_address) {
		.cid = addr->svm_cid,
		.port = addr->svm_port,
	};

	struct vsock_address raddr = (struct vsock_address) {
		.cid = VMADDR_CID_ANY,
		.port = VMADDR_PORT_ANY,
	};

	error = vsock_bind_address(pcb, laddr, raddr);
	if (error) {
		return error;
	}

	return 0;
}

static int
vsock_listen(struct socket *so, struct proc *p)
{
	#pragma unused(p)

	struct vsockpcb *pcb = sotovsockpcb(so);
	if (pcb == NULL) {
		return EINVAL;
	}

	// Only stream is supported currently.
	if (so->so_type != SOCK_STREAM) {
		return EAFNOSUPPORT;
	}

	struct vsock_address *addr = &pcb->local_address;

	if (addr->port == VMADDR_CID_ANY) {
		return EFAULT;
	}

	struct vsock_transport *transport = pcb->transport;
	uint32_t transport_cid;
	errno_t error = transport->get_cid(transport->provider, &transport_cid);
	if (error) {
		return error;
	}

	// Can listen on the transport's cid or any.
	if (addr->cid != transport_cid && addr->cid != VMADDR_CID_ANY) {
		return EFAULT;
	}

	return 0;
}

static int
vsock_accept(struct socket *so, struct sockaddr **nam)
{
	struct vsockpcb *pcb = sotovsockpcb(so);
	if (pcb == NULL) {
		return EINVAL;
	}

	// Do not accept disconnected sockets.
	if (so->so_state & SS_ISDISCONNECTED) {
		return ECONNABORTED;
	}

	*nam = vsock_new_sockaddr(&pcb->remote_address);

	return 0;
}

static int
vsock_connect(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	#pragma unused(p)

	struct vsockpcb *pcb = sotovsockpcb(so);
	if (pcb == NULL) {
		return EINVAL;
	}

	struct sockaddr_vm *addr = (struct sockaddr_vm *)nam;

	errno_t error = vsock_sockaddr_vm_validate(pcb, addr);
	if (error) {
		return error;
	}

	uint32_t transport_cid;
	struct vsock_transport *transport = pcb->transport;
	error = transport->get_cid(transport->provider, &transport_cid);
	if (error) {
		return error;
	}

	// Only supporting connections to the host, hypervisor, or self for now.
	if (addr->svm_cid != VMADDR_CID_HOST &&
	    addr->svm_cid != VMADDR_CID_HYPERVISOR &&
	    addr->svm_cid != transport_cid) {
		return EFAULT;
	}

	soisconnecting(so);

	// Set the remote and local address.
	struct vsock_address remote_addr = (struct vsock_address) {
		.cid = addr->svm_cid,
		.port = addr->svm_port,
	};

	struct vsock_address local_addr = (struct vsock_address) {
		.cid = transport_cid,
		.port = VMADDR_PORT_ANY,
	};

	// Bind to the address.
	error = vsock_bind_address(pcb, local_addr, remote_addr);
	if (error) {
		goto cleanup;
	}

	// Attempt a connection using the socket's transport.
	error = vsock_pcb_connect(pcb);
	if (error) {
		goto cleanup;
	}

	if ((so->so_state & SS_ISCONNECTED) == 0) {
		// Don't wait for peer's response if non-blocking.
		if (so->so_state & SS_NBIO) {
			error = EINPROGRESS;
			goto done;
		}

		struct timespec ts = (struct timespec) {
			.tv_sec = so->so_snd.sb_timeo.tv_sec,
			.tv_nsec = so->so_snd.sb_timeo.tv_usec * 1000,
		};

		lck_mtx_t *mutex_held;
		if (so->so_proto->pr_getlock != NULL) {
			mutex_held = (*so->so_proto->pr_getlock)(so, PR_F_WILLUNLOCK);
		} else {
			mutex_held = so->so_proto->pr_domain->dom_mtx;
		}

		// Wait until we receive a response to the connect request.
		error = msleep((caddr_t)&so->so_timeo, mutex_held, PSOCK | PCATCH, "vsock_connect", &ts);
		if (error) {
			if (error == EAGAIN) {
				error = ETIMEDOUT;
			}
			goto cleanup;
		}
	}

cleanup:
	if (so->so_error && !error) {
		error = so->so_error;
		so->so_error = 0;
	}
	if (!error) {
		error = !(so->so_state & SS_ISCONNECTED);
	}
	if (error) {
		vsock_unbind_pcb(pcb, false);
	}

done:
	return error;
}

static int
vsock_disconnect(struct socket *so)
{
	struct vsockpcb *pcb = sotovsockpcb(so);
	if (pcb == NULL) {
		return EINVAL;
	}

	return vsock_disconnect_pcb(pcb);
}

static int
vsock_sockaddr(struct socket *so, struct sockaddr **nam)
{
	struct vsockpcb *pcb = sotovsockpcb(so);
	if (pcb == NULL) {
		return EINVAL;
	}

	*nam = vsock_new_sockaddr(&pcb->local_address);

	return 0;
}

static int
vsock_peeraddr(struct socket *so, struct sockaddr **nam)
{
	struct vsockpcb *pcb = sotovsockpcb(so);
	if (pcb == NULL) {
		return EINVAL;
	}

	*nam = vsock_new_sockaddr(&pcb->remote_address);

	return 0;
}

static int
vsock_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *nam, struct mbuf *control, proc_t p)
{
	#pragma unused(flags, nam, p)

	struct vsockpcb *pcb = sotovsockpcb(so);
	if (pcb == NULL || m == NULL) {
		return EINVAL;
	}

	if (control != NULL) {
		m_freem(control);
		return EOPNOTSUPP;
	}

	// Ensure this socket is connected.
	if ((so->so_state & SS_ISCONNECTED) == 0) {
		if (m != NULL) {
			mbuf_freem_list(m);
		}
		return EPERM;
	}

	errno_t error;

	const size_t len = mbuf_pkthdr_len(m);
	uint32_t free_space = vsock_get_peer_space(pcb);

	// Ensure the peer has enough space in their receive buffer.
	while (len > free_space) {
		// Record the number of free peer bytes necessary before we can send.
		if (len > pcb->waiting_send_size) {
			pcb->waiting_send_size = len;
		}

		// Send a credit request.
		error = vsock_pcb_credit_request(pcb);
		if (error) {
			if (m != NULL) {
				mbuf_freem_list(m);
			}
			return error;
		}

		// Check again in case free space was automatically updated in loopback case.
		free_space = vsock_get_peer_space(pcb);
		if (len <= free_space) {
			pcb->waiting_send_size = 0;
			break;
		}

		// Bail if this is a non-blocking socket.
		if (so->so_state & SS_NBIO) {
			if (m != NULL) {
				mbuf_freem_list(m);
			}
			return EWOULDBLOCK;
		}

		// Wait until our peer has enough free space in their receive buffer.
		error = sbwait(&so->so_snd);
		pcb->waiting_send_size = 0;
		if (error) {
			if (m != NULL) {
				mbuf_freem_list(m);
			}
			return error;
		}

		// Bail if an error occured or we can't send more.
		if (so->so_state & SS_CANTSENDMORE) {
			if (m != NULL) {
				mbuf_freem_list(m);
			}
			return EPIPE;
		} else if (so->so_error) {
			error = so->so_error;
			so->so_error = 0;
			if (m != NULL) {
				mbuf_freem_list(m);
			}
			return error;
		}

		free_space = vsock_get_peer_space(pcb);
	}

	// Send a payload over the transport.
	error = vsock_pcb_send(pcb, m);
	if (error) {
		return error;
	}

	pcb->tx_cnt += len;

	return 0;
}

static int
vsock_shutdown(struct socket *so)
{
	struct vsockpcb *pcb = sotovsockpcb(so);
	if (pcb == NULL) {
		return EINVAL;
	}

	socantsendmore(so);

	// Tell peer we will no longer send.
	errno_t error = vsock_pcb_shutdown_send(pcb);
	if (error) {
		return error;
	}

	return 0;
}

static int
vsock_soreceive(struct socket *so, struct sockaddr **psa, struct uio *uio,
    struct mbuf **mp0, struct mbuf **controlp, int *flagsp)
{
	struct vsockpcb *pcb = sotovsockpcb(so);
	if (pcb == NULL) {
		return EINVAL;
	}

	user_ssize_t length = uio_resid(uio);
	int result = soreceive(so, psa, uio, mp0, controlp, flagsp);
	length -= uio_resid(uio);

	socket_lock(so, 1);

	pcb->fwd_cnt += length;

	const uint32_t threshold = VSOCK_MAX_PACKET_SIZE;

	// Send a credit update if is possible that the peer will no longer send.
	if ((pcb->fwd_cnt - pcb->last_fwd_cnt + threshold) >= pcb->last_buf_alloc) {
		errno_t error = vsock_pcb_credit_update(pcb);
		if (!result && error) {
			result = error;
		}
	}

	socket_unlock(so, 1);

	return result;
}

static struct pr_usrreqs vsock_usrreqs = {
	.pru_abort =            vsock_abort,
	.pru_attach =           vsock_attach,
	.pru_control =          vsock_control,
	.pru_detach =           vsock_detach,
	.pru_bind =             vsock_bind,
	.pru_listen =           vsock_listen,
	.pru_accept =           vsock_accept,
	.pru_connect =          vsock_connect,
	.pru_disconnect =       vsock_disconnect,
	.pru_send =             vsock_send,
	.pru_shutdown =         vsock_shutdown,
	.pru_sockaddr =         vsock_sockaddr,
	.pru_peeraddr =         vsock_peeraddr,
	.pru_sosend =           sosend,
	.pru_soreceive =        vsock_soreceive,
};

static void
vsock_init(struct protosw *pp, struct domain *dp)
{
	#pragma unused(dp)

	static int vsock_initialized = 0;
	VERIFY((pp->pr_flags & (PR_INITIALIZED | PR_ATTACHED)) == PR_ATTACHED);
	if (!os_atomic_cmpxchg((volatile int *)&vsock_initialized, 0, 1, acq_rel)) {
		return;
	}

	// Setup VSock protocol info struct.
	vsockinfo.vsock_lock_grp_attr = lck_grp_attr_alloc_init();
	vsockinfo.vsock_lock_grp = lck_grp_alloc_init("vsock", vsockinfo.vsock_lock_grp_attr);
	vsockinfo.vsock_lock_attr = lck_attr_alloc_init();
	if ((vsockinfo.all_lock = lck_rw_alloc_init(vsockinfo.vsock_lock_grp, vsockinfo.vsock_lock_attr)) == NULL ||
	    (vsockinfo.bound_lock = lck_rw_alloc_init(vsockinfo.vsock_lock_grp, vsockinfo.vsock_lock_attr)) == NULL) {
		panic("%s: unable to allocate PCB lock\n", __func__);
		/* NOTREACHED */
	}
	lck_mtx_init(&vsockinfo.port_lock, vsockinfo.vsock_lock_grp, vsockinfo.vsock_lock_attr);
	TAILQ_INIT(&vsockinfo.all);
	LIST_INIT(&vsockinfo.bound);
	vsockinfo.last_port = VMADDR_PORT_ANY;
}

static struct protosw vsocksw[] = {
	{
		.pr_type =              SOCK_STREAM,
		.pr_protocol =          0,
		.pr_flags =             PR_CONNREQUIRED | PR_WANTRCVD,
		.pr_init =              vsock_init,
		.pr_usrreqs =           &vsock_usrreqs,
	}
};

static const int vsock_proto_count = (sizeof(vsocksw) / sizeof(struct protosw));

/* VSock Domain */

static struct domain *vsock_domain = NULL;

static void
vsock_dinit(struct domain *dp)
{
	// The VSock domain is initialized with a singleton pattern.
	VERIFY(!(dp->dom_flags & DOM_INITIALIZED));
	VERIFY(vsock_domain == NULL);
	vsock_domain = dp;

	// Add protocols and initialize.
	for (int i = 0; i < vsock_proto_count; i++) {
		net_add_proto((struct protosw *)&vsocksw[i], dp, 1);
	}
}

struct domain vsockdomain_s = {
	.dom_family =           PF_VSOCK,
	.dom_name =             "vsock",
	.dom_init =             vsock_dinit,
	.dom_maxrtkey =         sizeof(struct sockaddr_vm),
	.dom_protohdrlen =      sizeof(struct sockaddr_vm),
};
