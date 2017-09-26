/*
 * Copyright (c) 2011 Apple Computer, Inc. All rights reserved.
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

/*  sysctl interface for paramters from user-land */

#include <kern/debug.h>
#include <libkern/libkern.h>
#include <pexpert/pexpert.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/kauth.h>

#include <kperf/action.h>
#include <kperf/context.h>
#include <kperf/kdebug_trigger.h>
#include <kperf/kperf.h>
#include <kperf/kperfbsd.h>
#include <kperf/kperf_timer.h>
#include <kperf/pet.h>

#include <sys/ktrace.h>

/* IDs for dispatch from SYSCTL macros */
#define REQ_SAMPLING                (1)
#define REQ_ACTION_COUNT            (2)
#define REQ_ACTION_SAMPLERS         (3)
#define REQ_TIMER_COUNT             (4)
#define REQ_TIMER_PERIOD            (5)
#define REQ_TIMER_PET               (6)
#define REQ_TIMER_ACTION            (7)
#define REQ_BLESS                   (8)
#define REQ_ACTION_USERDATA         (9)
#define REQ_ACTION_FILTER_BY_TASK   (10)
#define REQ_ACTION_FILTER_BY_PID    (11)
/* 12 unused */
#define REQ_PET_IDLE_RATE           (13)
#define REQ_BLESS_PREEMPT           (14)
#define REQ_KDBG_CSWITCH            (15)
#define REQ_RESET                   (16)
/* 17 unused */
#define REQ_ACTION_UCALLSTACK_DEPTH (18)
#define REQ_ACTION_KCALLSTACK_DEPTH (19)
#define REQ_LIGHTWEIGHT_PET         (20)
#define REQ_KDEBUG_ACTION           (21)
#define REQ_KDEBUG_FILTER           (22)

int kperf_debug_level = 0;

#if DEVELOPMENT || DEBUG
_Atomic long long kperf_pending_ipis = 0;
#endif /* DEVELOPMENT || DEBUG */

/*
 * kperf has a different sysctl model than others.
 *
 * For simple queries like the number of actions, the normal sysctl style
 * of get/set works well.
 *
 * However, when requesting information about something specific, like an
 * action, user space needs to provide some contextual information.  This
 * information is stored in a uint64_t array that includes the context, like
 * the action ID it is interested in.  If user space is getting the value from
 * the kernel, then the get side of the sysctl is valid.  If it is setting the
 * value, then the get pointers are left NULL.
 *
 * These functions handle marshalling and unmarshalling data from sysctls.
 */

static int
kperf_sysctl_get_set_uint32(struct sysctl_req *req,
	uint32_t (*get)(void), int (*set)(uint32_t))
{
	assert(req != NULL);
	assert(get != NULL);
	assert(set != NULL);

	uint32_t value = 0;
	if (req->oldptr) {
		value = get();
	}

	int error = sysctl_io_number(req, value, sizeof(value), &value, NULL);

	if (error || !req->newptr) {
		return error;
	}

	return set(value);
}

static int
kperf_sysctl_get_set_int(struct sysctl_req *req,
	int (*get)(void), int (*set)(int))
{
	assert(req != NULL);
	assert(get != NULL);
	assert(set != NULL);

	int value = 0;
	if (req->oldptr) {
		value = get();
	}

	int error = sysctl_io_number(req, value, sizeof(value), &value, NULL);

	if (error || !req->newptr) {
		return error;
	}

	return set(value);
}

static int
kperf_sysctl_get_set_unsigned_uint32(struct sysctl_req *req,
	int (*get)(unsigned int, uint32_t *), int (*set)(unsigned int, uint32_t))
{
	assert(req != NULL);
	assert(get != NULL);
	assert(set != NULL);

	int error = 0;
	uint64_t inputs[2] = {};

	if (req->newptr == USER_ADDR_NULL) {
		return EFAULT;
	}

	if ((error = copyin(req->newptr, inputs, sizeof(inputs)))) {
		return error;
	}

	unsigned int action_id = (unsigned int)inputs[0];
	uint32_t new_value = (uint32_t)inputs[1];

	if (req->oldptr != USER_ADDR_NULL) {
		uint32_t value_out = 0;
		if ((error = get(action_id, &value_out))) {
			return error;
		}

		inputs[1] = value_out;

		return copyout(inputs, req->oldptr, sizeof(inputs));
	} else {
		return set(action_id, new_value);
	}
}

/*
 * These functions are essentially the same as the generic
 * kperf_sysctl_get_set_unsigned_uint32, except they have unique input sizes.
 */

static int
sysctl_timer_period(struct sysctl_req *req)
{
	int error;
	uint64_t inputs[2] = {};

	assert(req != NULL);

	if (req->newptr == USER_ADDR_NULL) {
		return EFAULT;
	}

	if ((error = copyin(req->newptr, inputs, sizeof(inputs)))) {
		return error;
	}

	unsigned int timer = (unsigned int)inputs[0];
	uint64_t new_period = inputs[1];

	if (req->oldptr != USER_ADDR_NULL) {
		uint64_t period_out = 0;
		if ((error = kperf_timer_get_period(timer, &period_out))) {
			return error;
		}

		inputs[1] = period_out;

		return copyout(inputs, req->oldptr, sizeof(inputs));
	} else {
		return kperf_timer_set_period(timer, new_period);
	}
}

static int
sysctl_action_filter(struct sysctl_req *req, bool is_task_t)
{
	int error = 0;
	uint64_t inputs[2] = {};

	assert(req != NULL);

	if (req->newptr == USER_ADDR_NULL) {
		return EFAULT;
	}

	if ((error = copyin(req->newptr, inputs, sizeof(inputs)))) {
		return error;
	}

	unsigned int actionid = (unsigned int)inputs[0];
	int new_filter = (int)inputs[1];

	if (req->oldptr != USER_ADDR_NULL) {
		int filter_out;
		if ((error = kperf_action_get_filter(actionid, &filter_out))) {
			return error;
		}

		inputs[1] = filter_out;
		return copyout(inputs, req->oldptr, sizeof(inputs));
	} else {
		int pid = is_task_t ? kperf_port_to_pid((mach_port_name_t)new_filter)
				: new_filter;

		return kperf_action_set_filter(actionid, pid);
	}
}

static int
sysctl_bless(struct sysctl_req *req)
{
	int value = ktrace_get_owning_pid();
	int error = sysctl_io_number(req, value, sizeof(value), &value, NULL);

	if (error || !req->newptr) {
		return error;
	}

	return ktrace_set_owning_pid(value);
}

/* sysctl handlers that use the generic functions */

static int
sysctl_action_samplers(struct sysctl_req *req)
{
	return kperf_sysctl_get_set_unsigned_uint32(req,
		kperf_action_get_samplers, kperf_action_set_samplers);
}

static int
sysctl_action_userdata(struct sysctl_req *req)
{
	return kperf_sysctl_get_set_unsigned_uint32(req,
		kperf_action_get_userdata, kperf_action_set_userdata);
}

static int
sysctl_action_ucallstack_depth(struct sysctl_req *req)
{
	return kperf_sysctl_get_set_unsigned_uint32(req,
		kperf_action_get_ucallstack_depth, kperf_action_set_ucallstack_depth);
}

static int
sysctl_action_kcallstack_depth(struct sysctl_req *req)
{
	return kperf_sysctl_get_set_unsigned_uint32(req,
		kperf_action_get_kcallstack_depth, kperf_action_set_kcallstack_depth);
}

static int
sysctl_kdebug_action(struct sysctl_req *req)
{
	return kperf_sysctl_get_set_int(req, kperf_kdebug_get_action,
		kperf_kdebug_set_action);
}

static int
sysctl_kdebug_filter(struct sysctl_req *req)
{
	assert(req != NULL);

	if (req->oldptr != USER_ADDR_NULL) {
		struct kperf_kdebug_filter *filter = NULL;
		uint32_t n_debugids = kperf_kdebug_get_filter(&filter);
		size_t filter_size = KPERF_KDEBUG_FILTER_SIZE(n_debugids);

		if (n_debugids == 0) {
			return EINVAL;
		}

		return SYSCTL_OUT(req, filter, filter_size);
	}

	return kperf_kdebug_set_filter(req->newptr, (uint32_t)req->newlen);
}

static int
kperf_sampling_set(uint32_t sample_start)
{
	if (sample_start) {
		return kperf_sampling_enable();
	} else {
		return kperf_sampling_disable();
	}
}

static int
sysctl_sampling(struct sysctl_req *req)
{
	return kperf_sysctl_get_set_uint32(req, kperf_sampling_status,
		kperf_sampling_set);
}

static int
sysctl_action_count(struct sysctl_req *req)
{
	return kperf_sysctl_get_set_uint32(req, kperf_action_get_count,
		kperf_action_set_count);
}

static int
sysctl_timer_count(struct sysctl_req *req)
{
	return kperf_sysctl_get_set_uint32(req, kperf_timer_get_count,
		kperf_timer_set_count);
}

static int
sysctl_timer_action(struct sysctl_req *req)
{
	return kperf_sysctl_get_set_unsigned_uint32(req, kperf_timer_get_action,
		kperf_timer_set_action);
}

static int
sysctl_timer_pet(struct sysctl_req *req)
{
	return kperf_sysctl_get_set_uint32(req, kperf_timer_get_petid,
		kperf_timer_set_petid);
}

static int
sysctl_bless_preempt(struct sysctl_req *req)
{
	return sysctl_io_number(req, ktrace_root_set_owner_allowed,
		sizeof(ktrace_root_set_owner_allowed),
		&ktrace_root_set_owner_allowed, NULL);
}

static int
sysctl_kperf_reset(struct sysctl_req *req)
{
	int should_reset = 0;

	int error = sysctl_io_number(req, should_reset, sizeof(should_reset),
		&should_reset, NULL);
	if (error) {
		return error;
	}

	if (should_reset) {
		ktrace_reset(KTRACE_KPERF);
	}
	return 0;
}

static int
sysctl_pet_idle_rate(struct sysctl_req *req)
{
	return kperf_sysctl_get_set_int(req, kperf_get_pet_idle_rate,
		kperf_set_pet_idle_rate);
}

static int
sysctl_lightweight_pet(struct sysctl_req *req)
{
	return kperf_sysctl_get_set_int(req, kperf_get_lightweight_pet,
		kperf_set_lightweight_pet);
}

static int
sysctl_kdbg_cswitch(struct sysctl_req *req)
{
	return kperf_sysctl_get_set_int(req, kperf_kdbg_cswitch_get,
		kperf_kdbg_cswitch_set);
}

static int
kperf_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
	int ret;
	uintptr_t type = (uintptr_t)arg1;

	ktrace_lock();

	if (req->oldptr == USER_ADDR_NULL && req->newptr != USER_ADDR_NULL) {
		if ((ret = ktrace_configure(KTRACE_KPERF))) {
			ktrace_unlock();
			return ret;
		}
	} else {
		if ((ret = ktrace_read_check())) {
			ktrace_unlock();
			return ret;
		}
	}

	/* which request */
	switch (type) {
	case REQ_ACTION_COUNT:
		ret = sysctl_action_count(req);
		break;
	case REQ_ACTION_SAMPLERS:
		ret = sysctl_action_samplers(req);
		break;
	case REQ_ACTION_USERDATA:
		ret = sysctl_action_userdata(req);
		break;
	case REQ_TIMER_COUNT:
		ret = sysctl_timer_count(req);
		break;
	case REQ_TIMER_PERIOD:
		ret = sysctl_timer_period(req);
		break;
	case REQ_TIMER_PET:
		ret = sysctl_timer_pet(req);
		break;
	case REQ_TIMER_ACTION:
		ret = sysctl_timer_action(req);
		break;
	case REQ_SAMPLING:
		ret = sysctl_sampling(req);
		break;
	case REQ_KDBG_CSWITCH:
		ret = sysctl_kdbg_cswitch(req);
		break;
	case REQ_ACTION_FILTER_BY_TASK:
		ret = sysctl_action_filter(req, true);
		break;
	case REQ_ACTION_FILTER_BY_PID:
		ret = sysctl_action_filter(req, false);
		break;
	case REQ_KDEBUG_ACTION:
		ret = sysctl_kdebug_action(req);
		break;
	case REQ_KDEBUG_FILTER:
		ret = sysctl_kdebug_filter(req);
		break;
	case REQ_PET_IDLE_RATE:
		ret = sysctl_pet_idle_rate(req);
		break;
	case REQ_BLESS_PREEMPT:
		ret = sysctl_bless_preempt(req);
		break;
	case REQ_RESET:
		ret = sysctl_kperf_reset(req);
		break;
	case REQ_ACTION_UCALLSTACK_DEPTH:
		ret = sysctl_action_ucallstack_depth(req);
		break;
	case REQ_ACTION_KCALLSTACK_DEPTH:
		ret = sysctl_action_kcallstack_depth(req);
		break;
	case REQ_LIGHTWEIGHT_PET:
		ret = sysctl_lightweight_pet(req);
        break;
	default:
		ret = ENOENT;
		break;
	}

	ktrace_unlock();

	return ret;
}

static int
kperf_sysctl_bless_handler SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
	int ret;

	ktrace_lock();

	/* if setting a new "blessed pid" (ktrace owning pid) */
	if (req->newptr != USER_ADDR_NULL) {
		/*
		 * root can bypass the ktrace check when a flag is set (for
		 * backwards compatibility) or when ownership is maintained over
		 * subsystems resets (to allow the user space process that set
		 * ownership to unset it).
		 */
		if (!((ktrace_root_set_owner_allowed ||
		       ktrace_keep_ownership_on_reset) &&
		      kauth_cred_issuser(kauth_cred_get())))
		{
			if ((ret = ktrace_configure(KTRACE_KPERF))) {
				ktrace_unlock();
				return ret;
			}
		}
	} else {
		if ((ret = ktrace_read_check())) {
			ktrace_unlock();
			return ret;
		}
	}

	/* which request */
	if ((uintptr_t)arg1 == REQ_BLESS) {
		ret = sysctl_bless(req);
	} else {
		ret = ENOENT;
	}

	ktrace_unlock();

	return ret;
}

/* root kperf node */

SYSCTL_NODE(, OID_AUTO, kperf, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
            "kperf");

/* actions */

SYSCTL_NODE(_kperf, OID_AUTO, action, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
            "action");

SYSCTL_PROC(_kperf_action, OID_AUTO, count,
            CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_LOCKED,
            (void *)REQ_ACTION_COUNT,
            sizeof(int), kperf_sysctl, "I", "Number of actions");

SYSCTL_PROC(_kperf_action, OID_AUTO, samplers,
            CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_MASKED | CTLFLAG_LOCKED,
            (void *)REQ_ACTION_SAMPLERS,
            3 * sizeof(uint64_t), kperf_sysctl, "UQ",
            "What to sample when a trigger fires an action");

SYSCTL_PROC(_kperf_action, OID_AUTO, userdata,
            CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_MASKED | CTLFLAG_LOCKED,
            (void *)REQ_ACTION_USERDATA,
            3 * sizeof(uint64_t), kperf_sysctl, "UQ",
            "User data to attribute to action");

SYSCTL_PROC(_kperf_action, OID_AUTO, filter_by_task,
            CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_MASKED | CTLFLAG_LOCKED,
            (void *)REQ_ACTION_FILTER_BY_TASK,
            3 * sizeof(uint64_t), kperf_sysctl, "UQ",
            "Apply a task filter to the action");

SYSCTL_PROC(_kperf_action, OID_AUTO, filter_by_pid,
            CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_MASKED | CTLFLAG_LOCKED,
            (void *)REQ_ACTION_FILTER_BY_PID,
            3 * sizeof(uint64_t), kperf_sysctl, "UQ",
            "Apply a pid filter to the action");

SYSCTL_PROC(_kperf_action, OID_AUTO, ucallstack_depth,
            CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_MASKED | CTLFLAG_LOCKED,
            (void *)REQ_ACTION_UCALLSTACK_DEPTH,
            sizeof(int), kperf_sysctl, "I",
            "Maximum number of frames to include in user callstacks");

SYSCTL_PROC(_kperf_action, OID_AUTO, kcallstack_depth,
            CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_MASKED | CTLFLAG_LOCKED,
            (void *)REQ_ACTION_KCALLSTACK_DEPTH,
            sizeof(int), kperf_sysctl, "I",
            "Maximum number of frames to include in kernel callstacks");

/* timers */

SYSCTL_NODE(_kperf, OID_AUTO, timer, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
            "timer");

SYSCTL_PROC(_kperf_timer, OID_AUTO, count,
            CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_LOCKED,
            (void *)REQ_TIMER_COUNT,
            sizeof(int), kperf_sysctl, "I", "Number of time triggers");

SYSCTL_PROC(_kperf_timer, OID_AUTO, period,
            CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_MASKED | CTLFLAG_LOCKED,
            (void *)REQ_TIMER_PERIOD,
            2 * sizeof(uint64_t), kperf_sysctl, "UQ",
            "Timer number and period");

SYSCTL_PROC(_kperf_timer, OID_AUTO, action,
            CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_MASKED | CTLFLAG_LOCKED,
            (void *)REQ_TIMER_ACTION,
            2 * sizeof(uint64_t), kperf_sysctl, "UQ",
            "Timer number and actionid");

SYSCTL_PROC(_kperf_timer, OID_AUTO, pet_timer,
            CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_LOCKED,
            (void *)REQ_TIMER_PET,
            sizeof(int), kperf_sysctl, "I", "Which timer ID does PET");

/* kdebug trigger */

SYSCTL_NODE(_kperf, OID_AUTO, kdebug, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
            "kdebug");

SYSCTL_PROC(_kperf_kdebug, OID_AUTO, action,
            CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_LOCKED,
            (void*)REQ_KDEBUG_ACTION,
            sizeof(int), kperf_sysctl, "I", "ID of action to trigger on kdebug events");

SYSCTL_PROC(_kperf_kdebug, OID_AUTO, filter,
            CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_MASKED | CTLFLAG_LOCKED,
            (void*)REQ_KDEBUG_FILTER,
            sizeof(int), kperf_sysctl, "P", "The filter that determines which kdebug events trigger a sample");

/* misc */

SYSCTL_PROC(_kperf, OID_AUTO, sampling,
            CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_LOCKED,
            (void *)REQ_SAMPLING,
            sizeof(int), kperf_sysctl, "I", "Sampling running");

SYSCTL_PROC(_kperf, OID_AUTO, reset,
            CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_MASKED | CTLFLAG_LOCKED,
            (void *)REQ_RESET,
            0, kperf_sysctl, "-", "Reset kperf");

SYSCTL_PROC(_kperf, OID_AUTO, blessed_pid,
            CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, /* must be root */
            (void *)REQ_BLESS,
            sizeof(int), kperf_sysctl_bless_handler, "I", "Blessed pid");

SYSCTL_PROC(_kperf, OID_AUTO, blessed_preempt,
            CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_LOCKED,
            (void *)REQ_BLESS_PREEMPT,
            sizeof(int), kperf_sysctl, "I", "Blessed preemption");

SYSCTL_PROC(_kperf, OID_AUTO, kdbg_cswitch,
            CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_LOCKED,
            (void *)REQ_KDBG_CSWITCH,
            sizeof(int), kperf_sysctl, "I", "Generate context switch info");

SYSCTL_PROC(_kperf, OID_AUTO, pet_idle_rate,
            CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_LOCKED,
            (void *)REQ_PET_IDLE_RATE,
            sizeof(int), kperf_sysctl, "I",
            "Rate at which unscheduled threads are forced to be sampled in "
            "PET mode");

SYSCTL_PROC(_kperf, OID_AUTO, lightweight_pet,
            CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY | CTLFLAG_LOCKED,
            (void *)REQ_LIGHTWEIGHT_PET,
            sizeof(int), kperf_sysctl, "I",
            "Status of lightweight PET mode");

/* limits */

SYSCTL_NODE(_kperf, OID_AUTO, limits, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
            "limits");

#define REQ_LIM_PERIOD_NS (1)
#define REQ_LIM_BG_PERIOD_NS (2)
#define REQ_LIM_PET_PERIOD_NS (3)
#define REQ_LIM_BG_PET_PERIOD_NS (4)

static int
kperf_sysctl_limits SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
	int type = (int)arg1;
	uint64_t limit = 0;

	switch (type) {
	case REQ_LIM_PERIOD_NS:
		limit = KP_MIN_PERIOD_NS;
		break;

	case REQ_LIM_BG_PERIOD_NS:
		limit = KP_MIN_PERIOD_BG_NS;
		break;

	case REQ_LIM_PET_PERIOD_NS:
		limit = KP_MIN_PERIOD_PET_NS;
		break;

	case REQ_LIM_BG_PET_PERIOD_NS:
		limit = KP_MIN_PERIOD_PET_BG_NS;
		break;

	default:
		return ENOENT;
	}

	return sysctl_io_number(req, limit, sizeof(limit), &limit, NULL);
}

SYSCTL_PROC(_kperf_limits, OID_AUTO, timer_min_period_ns,
		 CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_ANYBODY | CTLFLAG_LOCKED,
		(void *)REQ_LIM_PERIOD_NS, sizeof(uint64_t), kperf_sysctl_limits,
		"Q", "Minimum timer period in nanoseconds");
SYSCTL_PROC(_kperf_limits, OID_AUTO, timer_min_bg_period_ns,
		 CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_ANYBODY | CTLFLAG_LOCKED,
		(void *)REQ_LIM_BG_PERIOD_NS, sizeof(uint64_t), kperf_sysctl_limits,
		"Q", "Minimum background timer period in nanoseconds");
SYSCTL_PROC(_kperf_limits, OID_AUTO, timer_min_pet_period_ns,
		 CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_ANYBODY | CTLFLAG_LOCKED,
		(void *)REQ_LIM_PET_PERIOD_NS, sizeof(uint64_t), kperf_sysctl_limits,
		"Q", "Minimum PET timer period in nanoseconds");
SYSCTL_PROC(_kperf_limits, OID_AUTO, timer_min_bg_pet_period_ns,
		 CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_ANYBODY | CTLFLAG_LOCKED,
		(void *)REQ_LIM_BG_PET_PERIOD_NS, sizeof(uint64_t), kperf_sysctl_limits,
		"Q", "Minimum background PET timer period in nanoseconds");

/* debug */
SYSCTL_INT(_kperf, OID_AUTO, debug_level, CTLFLAG_RW | CTLFLAG_LOCKED,
           &kperf_debug_level, 0, "debug level");

#if DEVELOPMENT || DEBUG
SYSCTL_QUAD(_kperf, OID_AUTO, already_pending_ipis,
            CTLFLAG_RD | CTLFLAG_LOCKED,
            &kperf_pending_ipis, "");
#endif /* DEVELOPMENT || DEBUG */
