/*
 * Copyright (c) 2018-2019 Apple Inc. All rights reserved.
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


#include <sys/sysctl.h>
#include <sys/proc.h>
#include <net/multi_layer_pkt_log.h>

SYSCTL_NODE(_net, OID_AUTO, mpklog,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "Multi-layer packet logging");

/*
 * Note:  net_mpklog_enabled allows to override the interface flags IFXF_MPK_LOG
 */
int net_mpklog_enabled = 1;
static int sysctl_net_mpklog_enabled SYSCTL_HANDLER_ARGS;
SYSCTL_PROC(_net_mpklog, OID_AUTO, enabled, CTLTYPE_INT | CTLFLAG_LOCKED | CTLFLAG_RW,
    0, 0, &sysctl_net_mpklog_enabled, "I", "Multi-layer packet logging enabled");

static int sysctl_net_mpklog_type SYSCTL_HANDLER_ARGS;
int net_mpklog_type =  OS_LOG_TYPE_DEFAULT;
SYSCTL_PROC(_net_mpklog, OID_AUTO, type, CTLTYPE_INT | CTLFLAG_LOCKED | CTLFLAG_RW,
    0, 0, &sysctl_net_mpklog_type, "I", "Multi-layer packet logging type");

SYSCTL_INT(_net_mpklog, OID_AUTO, version, CTLFLAG_RD | CTLFLAG_LOCKED,
    (int *)NULL, MPKL_VERSION, "Multi-layer packet logging version");

static int
sysctl_net_mpklog_enabled SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int value = net_mpklog_enabled;

	int error = sysctl_handle_int(oidp, &value, 0, req);
	if (error || !req->newptr) {
		return error;
	}

	net_mpklog_enabled = (value == 0) ? 0 : 1;

	os_log(OS_LOG_DEFAULT, "%s:%d set net_mpklog_enabled to %d",
	    proc_best_name(current_proc()), proc_selfpid(), net_mpklog_enabled);

	return 0;
}

static int
sysctl_net_mpklog_type SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int value = net_mpklog_type;

	int error = sysctl_handle_int(oidp, &value, 0, req);
	if (error || !req->newptr) {
		return error;
	}

	if (value != OS_LOG_TYPE_DEFAULT &&
	    value != OS_LOG_TYPE_INFO) {
		return EINVAL;
	}

	net_mpklog_type = value;

	os_log(OS_LOG_DEFAULT, "%s:%d set net_mpklog_type to %d (%s)",
	    proc_best_name(current_proc()), proc_selfpid(), net_mpklog_type,
	    net_mpklog_type == OS_LOG_TYPE_DEFAULT ? "default" : "info");

	return 0;
}
