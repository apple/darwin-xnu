/*
 * Copyright (c) 2018 Apple Computer, Inc. All rights reserved.
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
#include <darwintest.h>
#include <mach/port_descriptions.h>

static void
expect_special_port_description(const char *(*fn)(mach_port_t),
		mach_port_t port, const char *namestr)
{
	const char *desc = fn(port);
	T_EXPECT_NOTNULL(desc, "%s is %s", namestr, desc);
	if (desc) {
		T_QUIET; T_EXPECT_GT(strlen(desc), strlen(""),
				"%s's description string is not empty", namestr);
	}
}

T_DECL(host_special_port_descriptions,
		"verify that host special ports can be described")
{
#define TEST_HSP(portdef) \
		expect_special_port_description(mach_host_special_port_description, \
		portdef, #portdef)

	TEST_HSP(HOST_PORT);
	TEST_HSP(HOST_PRIV_PORT);
	TEST_HSP(HOST_IO_MASTER_PORT);
	TEST_HSP(HOST_DYNAMIC_PAGER_PORT);
	TEST_HSP(HOST_AUDIT_CONTROL_PORT);
	TEST_HSP(HOST_USER_NOTIFICATION_PORT);
	TEST_HSP(HOST_AUTOMOUNTD_PORT);
	TEST_HSP(HOST_LOCKD_PORT);
	TEST_HSP(HOST_KTRACE_BACKGROUND_PORT);
	TEST_HSP(HOST_SEATBELT_PORT);
	TEST_HSP(HOST_KEXTD_PORT);
	TEST_HSP(HOST_LAUNCHCTL_PORT);
	TEST_HSP(HOST_UNFREED_PORT);
	TEST_HSP(HOST_AMFID_PORT);
	TEST_HSP(HOST_GSSD_PORT);
	TEST_HSP(HOST_TELEMETRY_PORT);
	TEST_HSP(HOST_ATM_NOTIFICATION_PORT);
	TEST_HSP(HOST_COALITION_PORT);
	TEST_HSP(HOST_SYSDIAGNOSE_PORT);
	TEST_HSP(HOST_XPC_EXCEPTION_PORT);
	TEST_HSP(HOST_CONTAINERD_PORT);
	TEST_HSP(HOST_NODE_PORT);
	TEST_HSP(HOST_RESOURCE_NOTIFY_PORT);
	TEST_HSP(HOST_CLOSURED_PORT);
	TEST_HSP(HOST_SYSPOLICYD_PORT);

#undef TEST_HSP

	T_EXPECT_EQ(HOST_SYSPOLICYD_PORT, HOST_MAX_SPECIAL_PORT,
			"checked all of the ports");

	const char *invalid_hsp =
			mach_host_special_port_description(HOST_MAX_SPECIAL_PORT + 1);
	T_EXPECT_NULL(invalid_hsp,
			"invalid host special port description should be NULL");
}

T_DECL(task_special_port_descriptions,
		"verify that task special ports can be described")
{
#define TEST_TSP(portdef) \
		expect_special_port_description(mach_task_special_port_description, \
		portdef, #portdef)

	TEST_TSP(TASK_KERNEL_PORT);
	TEST_TSP(TASK_HOST_PORT);
	TEST_TSP(TASK_NAME_PORT);
	TEST_TSP(TASK_BOOTSTRAP_PORT);
	TEST_TSP(TASK_SEATBELT_PORT);
	TEST_TSP(TASK_ACCESS_PORT);
	TEST_TSP(TASK_DEBUG_CONTROL_PORT);
	TEST_TSP(TASK_RESOURCE_NOTIFY_PORT);

#undef TEST_TSP

	T_EXPECT_EQ(TASK_RESOURCE_NOTIFY_PORT, TASK_MAX_SPECIAL_PORT,
			"checked all of the ports");

	const char *invalid_tsp =
			mach_task_special_port_description(TASK_MAX_SPECIAL_PORT + 1);
	T_EXPECT_NULL(invalid_tsp,
			"invalid task special port description should be NULL");
}

static void
expect_special_port_id(int (*fn)(const char *id), int port, const char *portid)
{
	int observed_port = fn(portid);
	T_WITH_ERRNO;
	T_EXPECT_EQ(observed_port, port, "%s is %d", portid, observed_port);
}

T_DECL(host_special_port_mapping,
		"verify that task special port names can be mapped to numbers")
{
#define TEST_HSP(portdef) \
		expect_special_port_id(mach_host_special_port_for_id, \
		portdef, #portdef)

	TEST_HSP(HOST_PORT);
	TEST_HSP(HOST_PRIV_PORT);
	TEST_HSP(HOST_IO_MASTER_PORT);
	TEST_HSP(HOST_DYNAMIC_PAGER_PORT);
	TEST_HSP(HOST_AUDIT_CONTROL_PORT);
	TEST_HSP(HOST_USER_NOTIFICATION_PORT);
	TEST_HSP(HOST_AUTOMOUNTD_PORT);
	TEST_HSP(HOST_LOCKD_PORT);
	TEST_HSP(HOST_KTRACE_BACKGROUND_PORT);
	TEST_HSP(HOST_SEATBELT_PORT);
	TEST_HSP(HOST_KEXTD_PORT);
	TEST_HSP(HOST_LAUNCHCTL_PORT);
	TEST_HSP(HOST_UNFREED_PORT);
	TEST_HSP(HOST_AMFID_PORT);
	TEST_HSP(HOST_GSSD_PORT);
	TEST_HSP(HOST_TELEMETRY_PORT);
	TEST_HSP(HOST_ATM_NOTIFICATION_PORT);
	TEST_HSP(HOST_COALITION_PORT);
	TEST_HSP(HOST_SYSDIAGNOSE_PORT);
	TEST_HSP(HOST_XPC_EXCEPTION_PORT);
	TEST_HSP(HOST_CONTAINERD_PORT);
	TEST_HSP(HOST_NODE_PORT);
	TEST_HSP(HOST_RESOURCE_NOTIFY_PORT);
	TEST_HSP(HOST_CLOSURED_PORT);
	TEST_HSP(HOST_SYSPOLICYD_PORT);

#undef TEST_HSP

	int invalid_tsp = mach_host_special_port_for_id("BOGUS_SPECIAL_PORT_NAME");
	T_EXPECT_EQ(invalid_tsp, -1,
			"invalid host special port IDs should return -1");
}

T_DECL(task_special_port_mapping,
		"verify that task special port names can be mapped to numbers")
{
#define TEST_TSP(portdef) \
		expect_special_port_id(mach_task_special_port_for_id, \
		portdef, #portdef)

	TEST_TSP(TASK_KERNEL_PORT);
	TEST_TSP(TASK_HOST_PORT);
	TEST_TSP(TASK_NAME_PORT);
	TEST_TSP(TASK_BOOTSTRAP_PORT);
	TEST_TSP(TASK_SEATBELT_PORT);
	TEST_TSP(TASK_ACCESS_PORT);
	TEST_TSP(TASK_DEBUG_CONTROL_PORT);
	TEST_TSP(TASK_RESOURCE_NOTIFY_PORT);

#undef TEST_TSP

	int invalid_tsp = mach_task_special_port_for_id("BOGUS_SPECIAL_PORT_NAME");
	T_EXPECT_EQ(invalid_tsp, -1,
			"invalid task special port IDs should return -1");
}
