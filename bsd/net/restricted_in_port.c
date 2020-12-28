/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <kern/task.h>
#include <IOKit/IOBSD.h>
#include <net/restricted_in_port.h>
#include <netinet/in.h>
#include <os/log.h>

/*
 * Entitlement required for using the port of the test entry
 */
#define ENTITLEMENT_TEST_PORT "com.apple.private.network.restricted.port.test"

/*
 * Entitlement required for setting the test sysctl variables
 */
#define ENTITLEMENT_TEST_CONTROL "com.apple.private.network.restricted.port.control"

/*
 * Use a single bitmap for quickly checking if a TCP or UDP port is restricted
 */
bitmap_t *restricted_port_bitmap = NULL;

struct restricted_port_entry {
	const char      *rpe_entitlement;   // entitlement to check for this port
	in_port_t       rpe_port;           // restricted port number (host byte order)
	uint16_t        rpe_flags;          // RPE_FLAG_xxx
};

/*
 * Possible values for the field rpe_flags
 */
#define RPE_FLAG_SUPERUSER     0x01    // superuser can use the port
#define RPE_FLAG_ENTITLEMENT   0x02    // can use the port with the required entitlement
#define RPE_FLAG_TCP           0x04    // require entitlement for TCP
#define RPE_FLAG_UDP           0x08    // require entitlement for TCP
#define RPE_FLAG_TEST          0x10    // entry for testing

static struct restricted_port_entry restricted_port_list[] = {
#if CONFIG_EMBEDDED
	/*
	 * Network relay proxy
	 */
	{
		.rpe_port = 62742,
		.rpe_flags = RPE_FLAG_ENTITLEMENT | RPE_FLAG_TCP | RPE_FLAG_UDP,
		.rpe_entitlement = "com.apple.private.network.restricted.port.nr_proxy",
	},

	/*
	 * Network relay control
	 */
	{
		.rpe_port = 62743,
		.rpe_flags = RPE_FLAG_ENTITLEMENT | RPE_FLAG_UDP,
		.rpe_entitlement = "com.apple.private.network.restricted.port.nr_control",
	},

	/*
	 * Entries for identityservicesd
	 */
	{
		.rpe_port = 61314,
		.rpe_flags = RPE_FLAG_ENTITLEMENT | RPE_FLAG_TCP | RPE_FLAG_UDP,
		.rpe_entitlement = "com.apple.private.network.restricted.port.ids_service_connector",
	},
	{
		.rpe_port = 61315,
		.rpe_flags = RPE_FLAG_ENTITLEMENT | RPE_FLAG_TCP | RPE_FLAG_UDP,
		.rpe_entitlement = "com.apple.private.network.restricted.port.ids_cloud_service_connector",
	},
#endif /* CONFIG_EMBEDDED */

#if (DEBUG || DEVELOPMENT)
	/*
	 * Entries reserved for unit testing
	 */
	{
		.rpe_port = 0,
		.rpe_flags = RPE_FLAG_TCP | RPE_FLAG_TEST,
		.rpe_entitlement = ENTITLEMENT_TEST_PORT,
	},
	{
		.rpe_port = 0,
		.rpe_flags = RPE_FLAG_UDP | RPE_FLAG_TEST,
		.rpe_entitlement = ENTITLEMENT_TEST_PORT,
	},
#endif /* (DEBUG || DEVELOPMENT) */

	/*
	 * Sentinel to mark the actual end of the list (rpe_entitlement == NULL)
	 */
	{
		.rpe_port = 0,
		.rpe_flags = 0,
		.rpe_entitlement = NULL,
	}
};

#define RPE_ENTRY_COUNT (sizeof(restricted_port_list) / sizeof(restricted_port_list[0]))

SYSCTL_NODE(_net, OID_AUTO, restricted_port,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "restricted port");

static int sysctl_restricted_port_bitmap SYSCTL_HANDLER_ARGS;
static int sysctl_restricted_port_enforced SYSCTL_HANDLER_ARGS;
static int sysctl_restricted_port_verbose SYSCTL_HANDLER_ARGS;

SYSCTL_PROC(_net_restricted_port, OID_AUTO, bitmap,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, &sysctl_restricted_port_bitmap, "", "");

/*
 * In order to set the following sysctl variables the process needs to run as superuser
 * or have the entitlement ENTITLEMENT_TEST_CONTROL
 */
#if (DEBUG || DEVELOPMENT)
static int restricted_port_enforced = 1;
SYSCTL_PROC(_net_restricted_port, OID_AUTO, enforced,
    CTLTYPE_INT | CTLFLAG_LOCKED | CTLFLAG_RW | CTLFLAG_ANYBODY,
    0, 0, &sysctl_restricted_port_enforced, "I", "");
#else /* (DEBUG || DEVELOPMENT) */
const int restricted_port_enforced = 1;
SYSCTL_PROC(_net_restricted_port, OID_AUTO, enforced,
    CTLTYPE_INT | CTLFLAG_LOCKED | CTLFLAG_RD,
    0, 0, &sysctl_restricted_port_enforced, "I", "");
#endif /* (DEBUG || DEVELOPMENT) */

static int restricted_port_verbose = 0;
SYSCTL_PROC(_net_restricted_port, OID_AUTO, verbose,
    CTLTYPE_INT | CTLFLAG_LOCKED | CTLFLAG_RW | CTLFLAG_ANYBODY,
    0, 0, &sysctl_restricted_port_verbose, "I", "");

#if (DEBUG || DEVELOPMENT)

/*
 * Register dynamically a test port set by the unit test program to avoid conflict with
 * a restricted port currently used by its legetimate process.
 * The value must be passed is in host byte order.
 */
static uint16_t restricted_port_test = 0;

static int sysctl_restricted_port_test_entitlement SYSCTL_HANDLER_ARGS;
static int sysctl_restricted_port_test_superuser SYSCTL_HANDLER_ARGS;

SYSCTL_PROC(_net_restricted_port, OID_AUTO, test_entitlement,
    CTLTYPE_INT | CTLFLAG_LOCKED | CTLFLAG_RW | CTLFLAG_ANYBODY,
    0, 0, &sysctl_restricted_port_test_entitlement, "UI", "");

SYSCTL_PROC(_net_restricted_port, OID_AUTO, test_superuser,
    CTLTYPE_INT | CTLFLAG_LOCKED | CTLFLAG_RW | CTLFLAG_ANYBODY,
    0, 0, &sysctl_restricted_port_test_superuser, "UI", "");
#endif /* (DEBUG || DEVELOPMENT) */

static int
sysctl_restricted_port_bitmap SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)

	if (req->newptr) {
		return EPERM;
	}
	int error = SYSCTL_OUT(req, restricted_port_bitmap, BITMAP_SIZE(UINT16_MAX));

	return error;
}

static int
sysctl_restricted_port_enforced SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int old_value = restricted_port_enforced;
	int value = old_value;

	int error = sysctl_handle_int(oidp, &value, 0, req);
	if (error != 0 || !req->newptr) {
		return error;
	}
#if (DEBUG || DEVELOPMENT)
	if (proc_suser(current_proc()) != 0 &&
	    !IOTaskHasEntitlement(current_task(), ENTITLEMENT_TEST_CONTROL)) {
		return EPERM;
	}
	restricted_port_enforced = value;
	os_log(OS_LOG_DEFAULT,
	    "%s:%u sysctl net.restricted_port.enforced: %d -> %d",
	    proc_best_name(current_proc()), proc_selfpid(),
	    old_value, restricted_port_enforced);
	return error;
#else
	return EPERM;
#endif /* (DEBUG || DEVELOPMENT) */
}

static int
sysctl_restricted_port_verbose SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int old_value = restricted_port_verbose;
	int value = old_value;

	int error = sysctl_handle_int(oidp, &value, 0, req);
	if (error != 0 || !req->newptr) {
		return error;
	}
	if (proc_suser(current_proc()) != 0 &&
	    !IOTaskHasEntitlement(current_task(), ENTITLEMENT_TEST_CONTROL)) {
		return EPERM;
	}
	restricted_port_verbose = value;
	os_log(OS_LOG_DEFAULT,
	    "%s:%u sysctl net.restricted_port.verbose: %d -> %d)",
	    proc_best_name(current_proc()), proc_selfpid(),
	    old_value, restricted_port_verbose);

	return error;
}

#if (DEBUG || DEVELOPMENT)

static int
sysctl_restricted_port_test_common(struct sysctl_oid *oidp,
    struct sysctl_req *req, bool test_superuser)
{
	uint16_t old_value = restricted_port_test;
	int value = old_value;
	unsigned int i;

	int error = sysctl_handle_int(oidp, &value, 0, req);
	if (error != 0 || !req->newptr) {
		return error;
	}
	if (proc_suser(current_proc()) != 0 &&
	    !IOTaskHasEntitlement(current_task(), ENTITLEMENT_TEST_CONTROL)) {
		return EPERM;
	}
	if (value < 0 || value > UINT16_MAX) {
		return EINVAL;
	}
	if (value == 0) {
		/*
		 * Clear the current test port entries
		 */
		if (restricted_port_test != 0) {
			for (i = 0; i < RPE_ENTRY_COUNT; i++) {
				struct restricted_port_entry *rpe = &restricted_port_list[i];

				if (rpe->rpe_entitlement == NULL) {
					break;
				}
				if (!(rpe->rpe_flags & RPE_FLAG_TEST)) {
					continue;
				}
				rpe->rpe_port = 0;
				rpe->rpe_flags &= ~(RPE_FLAG_ENTITLEMENT | RPE_FLAG_SUPERUSER);
			}
			bitmap_clear(restricted_port_bitmap, restricted_port_test);
			restricted_port_test = 0;
		}
	} else {
		for (i = 0; i < RPE_ENTRY_COUNT; i++) {
			struct restricted_port_entry *rpe = &restricted_port_list[i];

			if (rpe->rpe_entitlement == NULL) {
				break;
			}
			if (!(rpe->rpe_flags & RPE_FLAG_TEST)) {
				continue;
			}
			rpe->rpe_port = value;
			if (test_superuser) {
				rpe->rpe_flags |= RPE_FLAG_SUPERUSER;
				rpe->rpe_flags &= ~RPE_FLAG_ENTITLEMENT;
			} else {
				rpe->rpe_flags |= RPE_FLAG_ENTITLEMENT;
				rpe->rpe_flags &= ~RPE_FLAG_SUPERUSER;
			}
		}
		restricted_port_test = (uint16_t)value;
		bitmap_set(restricted_port_bitmap, restricted_port_test);
	}

	return 0;
}

static int
sysctl_restricted_port_test_entitlement SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	uint16_t old_value = restricted_port_test;
	int error;

	error = sysctl_restricted_port_test_common(oidp, req, false);
	if (error == 0) {
		os_log(OS_LOG_DEFAULT,
		    "%s:%u sysctl net.restricted_port.test_entitlement: %u -> %u)",
		    proc_best_name(current_proc()), proc_selfpid(),
		    old_value, restricted_port_test);
	}
	return error;
}

static int
sysctl_restricted_port_test_superuser SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	uint16_t old_value = restricted_port_test;
	int error;

	error = sysctl_restricted_port_test_common(oidp, req, true);
	if (error == 0) {
		os_log(OS_LOG_DEFAULT,
		    "%s:%u sysctl net.restricted_port.test_superuser: %u -> %u)",
		    proc_best_name(current_proc()), proc_selfpid(),
		    old_value, restricted_port_test);
	}
	return error;
}

#endif /* (DEBUG || DEVELOPMENT) */

void
restricted_in_port_init(void)
{
	unsigned int i;


	restricted_port_bitmap = bitmap_alloc(UINT16_MAX);

	if (restricted_port_bitmap == NULL) {
		panic("restricted_port_init: bitmap allocation failed");
	}

	for (i = 0; i < RPE_ENTRY_COUNT; i++) {
		struct restricted_port_entry *rpe = &restricted_port_list[i];

		if (rpe->rpe_entitlement == NULL) {
			break;
		}
		if (rpe->rpe_port == 0) {
			continue;
		}
		bitmap_set(restricted_port_bitmap, rpe->rpe_port);
	}
}

static const char *
port_flag_str(uint32_t port_flags)
{
	switch (port_flags) {
	case PORT_FLAGS_LISTENER:
		return "listener";
	case PORT_FLAGS_BSD:
		return "bsd";
	case PORT_FLAGS_PF:
		return "pf";
	default:
		break;
	}
	return "?";
}

/*
 * The port is passed in network byte order
 */
bool
current_task_can_use_restricted_in_port(in_port_t port, uint8_t protocol, uint32_t port_flags)
{
	unsigned int i;
	struct proc *p = current_proc();
	pid_t pid = proc_pid(p);

	/*
	 * Quick check that does not take in account the protocol
	 */
	if (!IS_RESTRICTED_IN_PORT(port) || restricted_port_enforced == 0) {
		if (restricted_port_verbose > 1) {
			os_log(OS_LOG_DEFAULT,
			    "port %u for protocol %u via %s can be used by process %s:%u",
			    ntohs(port), protocol, port_flag_str(port_flags), proc_best_name(p), pid);
		}
		return true;
	}

	for (i = 0; i < RPE_ENTRY_COUNT; i++) {
		struct restricted_port_entry *rpe = &restricted_port_list[i];

		if (rpe->rpe_entitlement == NULL) {
			break;
		}
		if (rpe->rpe_port == 0) {
			continue;
		}
		if ((protocol == IPPROTO_TCP && !(rpe->rpe_flags & RPE_FLAG_TCP)) ||
		    (protocol == IPPROTO_UDP && !(rpe->rpe_flags & RPE_FLAG_UDP))) {
			continue;
		}
		if (rpe->rpe_port != ntohs(port)) {
			continue;
		}
		/*
		 * Found an entry in the list of restricted ports
		 *
		 * A process can use a restricted port if it meets at least one of
		 * the following conditions:
		 * - The process has the required entitlement
		 * - The port is marked as usable by root
		 */
		task_t task = current_task();
		if (rpe->rpe_flags & RPE_FLAG_SUPERUSER) {
			if (task == kernel_task || proc_suser(current_proc()) == 0) {
				os_log(OS_LOG_DEFAULT,
				    "root restricted port %u for protocol %u via %s can be used by superuser process %s:%u",
				    ntohs(port), protocol, port_flag_str(port_flags), proc_best_name(p), pid);
				return true;
			}
		}
		if (rpe->rpe_flags & RPE_FLAG_ENTITLEMENT) {
			/*
			 * Do not let the kernel use the port because there is
			 * no entitlement for kernel extensions
			 */
			if (task == kernel_task) {
				os_log(OS_LOG_DEFAULT,
				    "entitlement restricted port %u for protocol %u via %s cannot be used by kernel",
				    ntohs(port), protocol, port_flag_str(port_flags));
				return false;
			}
			if (!IOTaskHasEntitlement(current_task(), rpe->rpe_entitlement)) {
				os_log(OS_LOG_DEFAULT,
				    "entitlement restricted port %u for protocol %u via %s cannot be used by process %s:%u -- IOTaskHasEntitlement(%s) failed",
				    ntohs(port), protocol, port_flag_str(port_flags), proc_best_name(p), pid, rpe->rpe_entitlement);
				return false;
			}
			os_log(OS_LOG_DEFAULT,
			    "entitlement restricted port %u for protocol %u via %s can be used by process %s:%u",
			    ntohs(port), protocol, port_flag_str(port_flags), proc_best_name(p), pid);
			return true;
		}
		os_log(OS_LOG_DEFAULT,
		    "root restricted port %u for protocol %u via %s cannot be used by process %s:%u",
		    ntohs(port), protocol, port_flag_str(port_flags), proc_best_name(p), pid);
		return false;
	}
	if (restricted_port_verbose > 1) {
		os_log(OS_LOG_DEFAULT,
		    "port %u for protocol %u via %s can be used by process %s:%u",
		    ntohs(port), protocol, port_flag_str(port_flags), proc_best_name(p), pid);
	}
	return true;
}
