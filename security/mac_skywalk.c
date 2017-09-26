/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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
#include <sys/proc.h>
#include <sys/kauth.h>
#include <security/mac_framework.h>
#include <security/mac_internal.h>

int
mac_skywalk_flow_check_connect(proc_t proc, void *flow, const struct sockaddr *addr, int type, int protocol)
{
	int error;

	MAC_CHECK(skywalk_flow_check_connect, proc_ucred(proc), flow, addr, type, protocol);
	return (error);
}

int
mac_skywalk_flow_check_listen(proc_t proc, void *flow, const struct sockaddr *addr, int type, int protocol)
{
	int error;

	MAC_CHECK(skywalk_flow_check_listen, proc_ucred(proc), flow, addr, type, protocol);
	return (error);
}

