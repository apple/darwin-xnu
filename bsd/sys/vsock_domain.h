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

 #ifndef _VSOCK_DOMAIN_H_
 #define _VSOCK_DOMAIN_H_
 #ifdef  BSD_KERNEL_PRIVATE

 #include <sys/queue.h>
 #include <sys/vsock_transport.h>

/* VSock Protocol Control Block */

struct vsockpcb {
	TAILQ_ENTRY(vsockpcb) all;
	LIST_ENTRY(vsockpcb) bound;
	struct socket *so;
	struct vsock_address local_address;
	struct vsock_address remote_address;
	struct vsock_transport *transport;
	uint32_t fwd_cnt;
	uint32_t tx_cnt;
	uint32_t peer_buf_alloc;
	uint32_t peer_fwd_cnt;
	uint32_t last_buf_alloc;
	uint32_t last_fwd_cnt;
	size_t waiting_send_size;
	vsock_gen_t vsock_gencnt;
};

/* VSock Protocol Control Block Info */

struct vsockpcbinfo {
	// PCB locking.
	lck_attr_t *vsock_lock_attr;
	lck_grp_t *vsock_lock_grp;
	lck_grp_attr_t *vsock_lock_grp_attr;
	lck_rw_t *all_lock;
	lck_rw_t *bound_lock;
	// PCB lists.
	TAILQ_HEAD(, vsockpcb) all;
	LIST_HEAD(, vsockpcb) bound;
	// Port generation.
	uint32_t last_port;
	lck_mtx_t port_lock;
	// Counts.
	uint64_t all_pcb_count;
	vsock_gen_t vsock_gencnt;
};

#endif /* BSD_KERNEL_PRIVATE */
#endif /* _VSOCK_DOMAIN_H_ */
