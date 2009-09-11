/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 *	Copyright (c) 1999 Apple Computer, Inc. 
 *
 *	Data Link Inteface Layer
 *	Author: Ted Walker
 */
#ifndef DLIL_H
#define DLIL_H
#ifdef KERNEL

#include <sys/kernel_types.h>
#include <net/kpi_interface.h>

enum {
	BPF_TAP_DISABLE,
	BPF_TAP_INPUT,
	BPF_TAP_OUTPUT,
	BPF_TAP_INPUT_OUTPUT
};

/* Ethernet specific types */
#define DLIL_DESC_ETYPE2	4
#define DLIL_DESC_SAP		5
#define DLIL_DESC_SNAP		6
/*
 * DLIL_DESC_ETYPE2 - native_type must point to 2 byte ethernet raw protocol,
 *                    variants.native_type_length must be set to 2
 * DLIL_DESC_SAP - native_type must point to 3 byte SAP protocol
 *                 variants.native_type_length must be set to 3
 * DLIL_DESC_SNAP - native_type must point to 5 byte SNAP protocol
 *                  variants.native_type_length must be set to 5
 *
 * All protocols must be in Network byte order.
 *
 * Future interface families may define more protocol types they know about.
 * The type implies the offset and context of the protocol data at native_type.
 * The length of the protocol data specified at native_type must be set in
 * variants.native_type_length.
 */

#ifdef KERNEL_PRIVATE

#include <net/if.h>
#include <net/if_var.h>
#include <sys/kern_event.h>
#include <kern/thread.h>
#include <kern/locks.h>

#if __STDC__

struct ifnet;
struct mbuf;
struct ether_header;
struct sockaddr_dl;

#endif

#ifdef BSD_KERNEL_PRIVATE
struct ifnet_stat_increment_param;
struct iff_filter;

struct dlil_threading_info {
	mbuf_t 		mbuf_head;	/* start of mbuf list from if */
	mbuf_t 		mbuf_tail;
	u_int32_t 	mbuf_count;
	boolean_t	net_affinity;	/* affinity set is available */
	u_int32_t 	input_waiting;	/* DLIL condition of thread */
	struct thread	*input_thread;	/* thread data for this input */
	struct thread	*workloop_thread; /* current workloop thread */
	u_int32_t	tag;		/* current affinity tag */
	lck_mtx_t	*input_lck;	
	lck_grp_t	*lck_grp;	/* lock group (for lock stats) */
	char 		input_name[32];		 
#if IFNET_INPUT_SANITY_CHK
	u_int32_t	input_wake_cnt;	/* number of times the thread was awaken with packets to process */
	u_long		input_mbuf_cnt;	/* total number of mbuf packets processed by this thread */
#endif
};

/*
	The following are shared with kpi_protocol.c so that it may wakeup
	the input thread to run through packets queued for protocol input.
*/
#define	DLIL_INPUT_RUNNING	0x80000000
#define	DLIL_INPUT_WAITING	0x40000000
#define	DLIL_PROTO_REGISTER	0x20000000
#define	DLIL_PROTO_WAITING	0x10000000
#define	DLIL_INPUT_TERMINATE	0x08000000

void dlil_init(void);

errno_t dlil_set_bpf_tap(ifnet_t ifp, bpf_tap_mode mode,
						 bpf_packet_func callback);

/*
 * Send arp internal bypasses the check for
 * IPv4LL.
 */
errno_t
dlil_send_arp_internal(
	ifnet_t	ifp,
	u_int16_t arpop,
	const struct sockaddr_dl* sender_hw,
	const struct sockaddr* sender_proto,
	const struct sockaddr_dl* target_hw,
	const struct sockaddr* target_proto);

int
dlil_output(
	ifnet_t					ifp,
	protocol_family_t		proto_family,
	mbuf_t					packetlist,
	void					*route,
	const struct sockaddr	*dest,
	int						raw);

errno_t
dlil_resolve_multi(
	struct ifnet *ifp,
	const struct sockaddr *proto_addr,
	struct sockaddr *ll_addr,
	size_t ll_len);

errno_t
dlil_send_arp(
	ifnet_t	ifp,
	u_int16_t arpop,
	const struct sockaddr_dl* sender_hw,
	const struct sockaddr* sender_proto,
	const struct sockaddr_dl* target_hw,
	const struct sockaddr* target_proto);

int dlil_attach_filter(ifnet_t ifp, const struct iff_filter *if_filter,
					   interface_filter_t *filter_ref);
void dlil_detach_filter(interface_filter_t filter);
int dlil_detach_protocol(ifnet_t ifp, u_int32_t protocol);
extern void dlil_proto_unplumb_all(ifnet_t);

#endif /* BSD_KERNEL_PRIVATE */

void
dlil_post_msg(struct ifnet *ifp,u_int32_t event_subclass, u_int32_t event_code, 
		   struct net_event_data *event_data, u_int32_t event_data_len);

/* 
 * dlil_if_acquire is obsolete. Use ifnet_allocate.
 */

int dlil_if_acquire(u_int32_t family, const void *uniqueid, size_t uniqueid_len, 
			struct ifnet **ifp);
			

/* 
 * dlil_if_release is obsolete. The equivalent is called automatically when
 * an interface is detached.
 */

void dlil_if_release(struct ifnet *ifp);

#endif /* KERNEL_PRIVATE */
#endif /* KERNEL */
#endif /* DLIL_H */
