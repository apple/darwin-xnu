/*
 * Copyright (c) 2010-2011 Apple Inc. All rights reserved.
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
/*-
 * Copyright (c) 2008 Swinburne University of Technology, Melbourne, Australia
 * All rights reserved.
 *
 * This software was developed at the Centre for Advanced Internet
 * Architectures, Swinburne University, by Lawrence Stewart and James Healy,
 * made possible in part by a grant from the Cisco University Research Program
 * Fund at Community Foundation Silicon Valley.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _NETINET_CC_H_
#define _NETINET_CC_H_

#ifdef KERNEL

#include <netinet/tcp_var.h>

#define TCP_CC_ALGO_NEWRENO_INDEX 0	/* default congestion control algorithm */
#define TCP_CC_ALGO_BACKGROUND_INDEX 1	/* congestion control for background transport */
#define TCP_CC_ALGO_COUNT 2		/* Count of CC algorithms defined */

#define TCP_CA_NAME_MAX 16		/* Maximum characters in the name of a CC algorithm */

/*
 * Structure to hold definition various actions defined by a congestion control
 * algorithm for TCP. This can be used to change the congestion control on a 
 * connection based on the user settings of priority of a connection.
 */
struct tcp_cc_algo {
	char name[TCP_CA_NAME_MAX];
	uint32_t num_sockets;
	uint32_t flags;

	/* init the congestion algorithm for the specified control block */
	int (*init) (struct tcpcb *tp);

	/* cleanup any state that is stored in the connection related to the algorithm */
	int (*cleanup) (struct tcpcb *tp); 

	/* initialize cwnd at the start of a connection */
	void (*cwnd_init) (struct tcpcb *tp);

	/* called on the receipt of in-sequence ack during congestion avoidance phase */
	void (*inseq_ack_rcvd) (struct tcpcb *tp, struct tcphdr *th);

	/* called on the receipt of a valid ack */
	void (*ack_rcvd) (struct tcpcb *tp, struct tcphdr *th);

	/* called before entering FR */
	void (*pre_fr) (struct tcpcb *tp);

	/*  after exiting FR */
	void (*post_fr) (struct tcpcb *tp, struct tcphdr *th);

	/* perform tasks when data transfer resumes after an idle period */
	void (*after_idle) (struct tcpcb *tp);

	/* perform tasks when the connection's retransmit timer expires */
	void (*after_timeout) (struct tcpcb *tp);

	/* Whether or not to delay the ack */
	int (*delay_ack)(struct tcpcb *tp, struct tcphdr *th);

	/* Switch a connection to this CC algorithm after sending some packets */
	void (*switch_to)(struct tcpcb *tp, uint16_t old_cc_index); 

} __attribute__((aligned(4)));

extern struct tcp_cc_algo* tcp_cc_algo_list[TCP_CC_ALGO_COUNT];

#define CC_ALGO(tp) (tcp_cc_algo_list[tp->tcp_cc_index])

extern void tcp_cc_resize_sndbuf(struct tcpcb *tp);
extern void tcp_bad_rexmt_fix_sndbuf(struct tcpcb *tp);

#endif /* KERNEL */
#endif /* _NETINET_CC_H_ */
