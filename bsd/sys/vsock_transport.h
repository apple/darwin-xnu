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

#ifndef _VSOCK_TRANSPORT_H_
#define _VSOCK_TRANSPORT_H_
#ifdef  KERNEL_PRIVATE

#include <sys/cdefs.h>

__BEGIN_DECLS

#include <sys/queue.h>
#include <sys/kernel_types.h>
#include <sys/vsock.h>

#define VSOCK_MAX_PACKET_SIZE 65536

enum vsock_operation {
	VSOCK_REQUEST = 0,
	VSOCK_RESPONSE = 1,
	VSOCK_PAYLOAD = 2,
	VSOCK_SHUTDOWN = 3,
	VSOCK_SHUTDOWN_RECEIVE = 4,
	VSOCK_SHUTDOWN_SEND = 5,
	VSOCK_RESET = 6,
	VSOCK_CREDIT_UPDATE = 7,
	VSOCK_CREDIT_REQUEST = 8,
};

struct vsock_address {
	uint32_t cid;
	uint32_t port;
};

struct vsock_transport {
	void *provider;
	int (*get_cid)(void *provider, uint32_t *cid);
	int (*attach_socket)(void *provider);
	int (*detach_socket)(void *provider);
	int (*put_message)(void *provider, struct vsock_address src, struct vsock_address dst,
	    enum vsock_operation op, uint32_t buf_alloc, uint32_t fwd_cnt, mbuf_t m);
};

extern int vsock_add_transport(struct vsock_transport *transport);
extern int vsock_remove_transport(struct vsock_transport *transport);
extern int vsock_reset_transport(struct vsock_transport *transport);
extern int vsock_put_message(struct vsock_address src, struct vsock_address dst,
    enum vsock_operation op, uint32_t buf_alloc, uint32_t fwd_cnt, mbuf_t m);

__END_DECLS

#endif /* KERNEL_PRIVATE */
#endif /* _VSOCK_TRANSPORT_H_ */
