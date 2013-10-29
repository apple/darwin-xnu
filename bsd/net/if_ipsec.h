/*
 * Copyright (c) 2012 Apple Inc. All rights reserved.
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


#ifndef	_NET_IF_IPSEC_H_
#define	_NET_IF_IPSEC_H_

#ifdef BSD_KERNEL_PRIVATE

#include <sys/kern_control.h>
#include <netinet/ip_var.h>

/* Control block allocated for each kernel control connection */
struct ipsec_pcb {
	kern_ctl_ref	ipsec_ctlref;
	ifnet_t			ipsec_ifp;
	u_int32_t		ipsec_unit;
	u_int32_t		ipsec_flags;
	int				ipsec_ext_ifdata_stats;
};

errno_t ipsec_register_control(void);

/* Helpers */
int ipsec_interface_isvalid (ifnet_t interface);

#endif

/*
 * Name registered by the ipsec kernel control
 */
#define IPSEC_CONTROL_NAME "com.apple.net.ipsec_control"

/*
 * Socket option names to manage ipsec
 */
#define IPSEC_OPT_FLAGS							1
#define IPSEC_OPT_IFNAME						2
#define IPSEC_OPT_EXT_IFDATA_STATS				3	/* get|set (type int) */
#define IPSEC_OPT_INC_IFDATA_STATS_IN			4	/* set to increment stat counters (type struct ipsec_stats_param) */
#define IPSEC_OPT_INC_IFDATA_STATS_OUT			5	/* set to increment stat counters (type struct ipsec_stats_param) */
#define IPSEC_OPT_SET_DELEGATE_INTERFACE		6	/* set the delegate interface (char[]) */
/*
 * ipsec stats parameter structure
 */
struct ipsec_stats_param {
	u_int64_t       utsp_packets;
	u_int64_t       utsp_bytes;
	u_int64_t       utsp_errors;
};

#endif
