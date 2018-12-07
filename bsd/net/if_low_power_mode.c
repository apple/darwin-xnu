/*
 * Copyright (c) 2018 Apple Inc. All rights reserved.
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
#include <sys/systm.h>
#include <sys/eventhandler.h>

#include <net/dlil.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/nwk_wq.h>

#include <os/log.h>

typedef enum {
	IF_LOW_POWER_EVENT_OFF = 0,
	IF_LOW_POWER_EVENT_ON = 1
} if_low_power_ev_code_t;

struct if_low_power_ev_args {
	struct ifnet *ifp;
	if_low_power_ev_code_t event_code;
};

struct if_low_power_ev_nwk_wq_entry {
	struct nwk_wq_entry nwk_wqe;
	struct if_low_power_ev_args ev_args;
};


typedef void (*if_low_power_event_fn) (struct eventhandler_entry_arg,
    struct ifnet *, if_low_power_ev_code_t);
EVENTHANDLER_DECLARE(if_low_power_event, if_low_power_event_fn);

struct eventhandler_lists_ctxt if_low_power_evhdlr_ctx;

static void if_low_power_evhdlr_callback(__unused struct eventhandler_entry_arg arg,
    struct ifnet *ifp, if_low_power_ev_code_t event_code);

#if 0
static void if_low_power_nwk_ev_callback(void *arg);
static void if_low_power_event_enqueue_nwk_wq_entry(struct ifnet *ifp,
    if_low_power_ev_code_t event_code);
#endif

extern void shutdown_sockets_on_interface(struct ifnet *ifp);

SYSCTL_DECL(_net_link_generic_system);
SYSCTL_NODE(_net_link_generic_system, OID_AUTO, low_power,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "low power mode");

int if_low_power_verbose = 0;
int if_low_power_restricted = 1;

#if (DEVELOPMENT || DEBUG)
SYSCTL_INT(_net_link_generic_system_low_power, OID_AUTO, verbose,
    CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_low_power_verbose, 0, "");
SYSCTL_INT(_net_link_generic_system_low_power, OID_AUTO, restricted,
    CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_low_power_restricted, 0, "");
#endif /* (DEVELOPMENT || DEBUG) */


static void
if_low_power_evhdlr_callback(__unused struct eventhandler_entry_arg arg,
    struct ifnet *ifp, if_low_power_ev_code_t event_code)
{
	struct kev_dl_low_power_mode kev;

	if (!IF_FULLY_ATTACHED(ifp))
		return;

	if (if_low_power_verbose > 0) {
		os_log_info(OS_LOG_DEFAULT,
		    "%s: ifp %s event_code %d", __func__,
		    if_name(ifp), event_code);
	}

	ifnet_lock_exclusive(ifp);
	if (event_code == IF_LOW_POWER_EVENT_OFF) {
		ifp->if_xflags &= ~IFXF_LOW_POWER;
	} else {
		ifp->if_xflags |= IFXF_LOW_POWER;
	}
	ifnet_lock_done(ifp);

	if (event_code == IF_LOW_POWER_EVENT_ON) {
		atomic_add_32(&ifp->if_low_power_gencnt, 1);

		if (if_low_power_restricted != 0) {
			shutdown_sockets_on_interface(ifp);
			intf_event_enqueue_nwk_wq_entry(ifp, NULL,
			    INTF_EVENT_CODE_LOW_POWER_UPDATE);
		}
	}

	bzero(&kev, sizeof(struct kev_dl_low_power_mode));
	kev.low_power_event = event_code;
	dlil_post_msg(ifp,
	    KEV_DL_SUBCLASS,
	    KEV_DL_LOW_POWER_MODE_CHANGED,
	    (struct net_event_data *)&kev,
	    sizeof(struct kev_dl_low_power_mode));
}

void
if_low_power_evhdlr_init(void)
{
	eventhandler_lists_ctxt_init(&if_low_power_evhdlr_ctx);

	(void) EVENTHANDLER_REGISTER(&if_low_power_evhdlr_ctx,
	    if_low_power_event,
	    if_low_power_evhdlr_callback, 
	    eventhandler_entry_dummy_arg,
	    EVENTHANDLER_PRI_ANY);
}

#if 0
static void
if_low_power_nwk_ev_callback(void *arg)
{
	struct if_low_power_ev_args *if_low_power_ev_args =
	    (struct if_low_power_ev_args *)arg;
	
	EVENTHANDLER_INVOKE(&if_low_power_evhdlr_ctx,
	    if_low_power_event,
	    if_low_power_ev_args->ifp,
	    if_low_power_ev_args->event_code);
}

static void
if_low_power_event_enqueue_nwk_wq_entry(struct ifnet *ifp,
    if_low_power_ev_code_t event_code)
{
	struct if_low_power_ev_nwk_wq_entry *event_nwk_wq_entry = NULL;

	MALLOC(event_nwk_wq_entry, struct if_low_power_ev_nwk_wq_entry *,
	    sizeof(struct if_low_power_ev_nwk_wq_entry),
	    M_NWKWQ, M_WAITOK | M_ZERO);

	event_nwk_wq_entry->ev_args.ifp = ifp;
	event_nwk_wq_entry->ev_args.event_code = event_code;

	event_nwk_wq_entry->nwk_wqe.func = if_low_power_nwk_ev_callback;
	event_nwk_wq_entry->nwk_wqe.is_arg_managed = TRUE;
	event_nwk_wq_entry->nwk_wqe.arg = &event_nwk_wq_entry->ev_args;

	nwk_wq_enqueue((struct nwk_wq_entry*)event_nwk_wq_entry);
}
#endif

int
if_set_low_power(ifnet_t ifp, bool on)
{
	int error = 0;

	if (ifp == NULL)
		return (EINVAL);

	os_log(OS_LOG_DEFAULT,
	    "%s: ifp %s low_power mode %d", __func__, if_name(ifp), on);

	ifnet_lock_exclusive(ifp);
	ifp->if_xflags = on ? (ifp->if_xflags | IFXF_LOW_POWER) :
	    (ifp->if_xflags & ~IFXF_LOW_POWER);
	ifnet_lock_done(ifp);

	return (error);
}

