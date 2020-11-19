/*
 * Copyright (c) 2017-2020 Apple Inc. All rights reserved.
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
#include <mach/mach_time.h>
#include <mach/clock_types.h>
#include <kern/misc_protos.h>
#include <kern/clock.h>
#include <kern/remote_time.h>
#include <kern/spl.h>
#include <kern/locks.h>
#include <sys/kdebug.h>
#include <machine/machine_routines.h>
#include <kern/assert.h>
#include <kern/kern_types.h>
#include <kern/thread.h>
#include <machine/commpage.h>
#include <machine/atomic.h>

LCK_GRP_DECLARE(bt_lck_grp, "bridge timestamp");
LCK_SPIN_DECLARE(bt_spin_lock, &bt_lck_grp);
LCK_SPIN_DECLARE(bt_ts_conversion_lock, &bt_lck_grp);
LCK_SPIN_DECLARE(bt_maintenance_lock, &bt_lck_grp);

#if CONFIG_MACH_BRIDGE_SEND_TIME

uint32_t bt_enable_flag = 0;
_Atomic uint32_t bt_init_flag = 0;

void mach_bridge_timer_maintenance(void);
uint32_t mach_bridge_timer_enable(uint32_t new_value, int change);

/*
 * When CONFIG_MACH_BRIDGE_SEND_TIME is defined, it is expected
 * that a machine-specific timestamp sending routine such as
 * void mach_bridge_send_timestamp(uint64_t); has also been defined.
 */
extern void mach_bridge_send_timestamp(uint64_t);

void
mach_bridge_timer_maintenance(void)
{
	if (!os_atomic_load(&bt_init_flag, acquire)) {
		return;
	}

	lck_spin_lock(&bt_maintenance_lock);
	if (!bt_enable_flag) {
		goto done;
	}
	mach_bridge_send_timestamp(0);

done:
	lck_spin_unlock(&bt_maintenance_lock);
}

/*
 * If change = 0, return the current value of bridge_timer_enable
 * If change = 1, update bridge_timer_enable and return the updated
 * value
 */
uint32_t
mach_bridge_timer_enable(uint32_t new_value, int change)
{
	uint32_t current_value = 0;
	assert(os_atomic_load(&bt_init_flag, relaxed));
	lck_spin_lock(&bt_maintenance_lock);
	if (change) {
		bt_enable_flag = new_value;
	}
	current_value = bt_enable_flag;
	lck_spin_unlock(&bt_maintenance_lock);
	return current_value;
}

#endif /* CONFIG_MACH_BRIDGE_SEND_TIME */

#if CONFIG_MACH_BRIDGE_RECV_TIME
#include <machine/machine_remote_time.h>

/*
 * functions used by machine-specific code
 * that implements CONFIG_MACH_BRIDGE_RECV_TIME
 */
void mach_bridge_add_timestamp(uint64_t remote_timestamp, uint64_t local_timestamp);
void bt_calibration_thread_start(void);
void bt_params_add(struct bt_params *params);

/* function called by sysctl */
struct bt_params bt_params_get_latest(void);

/*
 * Platform specific bridge time receiving interface.
 * These variables should be exported by the platform specific time receiving code.
 */
extern _Atomic uint32_t bt_init_flag;

static uint64_t received_local_timestamp = 0;
static uint64_t received_remote_timestamp = 0;
/*
 * Buffer the previous timestamp pairs and rate
 * It is protected by the bt_ts_conversion_lock
 */
#define BT_PARAMS_COUNT 10
static struct bt_params bt_params_hist[BT_PARAMS_COUNT] = {};
static int bt_params_idx = -1;

void
bt_params_add(struct bt_params *params)
{
	lck_spin_assert(&bt_ts_conversion_lock, LCK_ASSERT_OWNED);

	bt_params_idx = (bt_params_idx + 1) % BT_PARAMS_COUNT;
	bt_params_hist[bt_params_idx] = *params;
}

#if defined(XNU_TARGET_OS_BRIDGE)
static inline struct bt_params*
bt_params_find(uint64_t local_ts)
{
	lck_spin_assert(&bt_ts_conversion_lock, LCK_ASSERT_OWNED);

	int idx = bt_params_idx;
	if (idx < 0) {
		return NULL;
	}
	do {
		if (local_ts >= bt_params_hist[idx].base_local_ts) {
			return &bt_params_hist[idx];
		}
		if (--idx < 0) {
			idx = BT_PARAMS_COUNT - 1;
		}
	} while (idx != bt_params_idx);

	return NULL;
}
#endif /* defined(XNU_TARGET_OS_BRIDGE) */

static inline struct bt_params
bt_params_get_latest_locked(void)
{
	lck_spin_assert(&bt_ts_conversion_lock, LCK_ASSERT_OWNED);

	struct bt_params latest_params = {};
	if (bt_params_idx >= 0) {
		latest_params = bt_params_hist[bt_params_idx];
	}

	return latest_params;
}

struct bt_params
bt_params_get_latest(void)
{
	struct bt_params latest_params = {};

	/* Check if ts_converison_lock has been initialized */
	if (os_atomic_load(&bt_init_flag, acquire)) {
		lck_spin_lock(&bt_ts_conversion_lock);
		latest_params = bt_params_get_latest_locked();
		lck_spin_unlock(&bt_ts_conversion_lock);
	}
	return latest_params;
}

/*
 * Conditions: bt_spin_lock held and called from primary interrupt context
 */
void
mach_bridge_add_timestamp(uint64_t remote_timestamp, uint64_t local_timestamp)
{
	lck_spin_assert(&bt_spin_lock, LCK_ASSERT_OWNED);

	/* sleep/wake might return the same mach_absolute_time as the previous timestamp pair */
	if ((received_local_timestamp == local_timestamp) ||
	    (received_remote_timestamp == remote_timestamp)) {
		return;
	}

	received_local_timestamp = local_timestamp;
	received_remote_timestamp = remote_timestamp;
	thread_wakeup((event_t)bt_params_hist);
}

static double
mach_bridge_compute_rate(uint64_t new_local_ts, uint64_t new_remote_ts,
    uint64_t old_local_ts, uint64_t old_remote_ts)
{
	int64_t rdiff = (int64_t)new_remote_ts - (int64_t)old_remote_ts;
	int64_t ldiff = (int64_t)new_local_ts - (int64_t)old_local_ts;
	double calc_rate = ((double)rdiff) / (double)ldiff;
	return calc_rate;
}

#define MAX_RECALCULATE_COUNT 8
#define CUMULATIVE_RATE_DECAY_CONSTANT 0.01
#define CUMULATIVE_RATE_WEIGHT 0.99
#define INITIAL_RATE 1.0
#define MIN_INITIAL_SAMPLE_COUNT 10
#define MAX_INITIAL_SAMPLE_COUNT 50
#define MAX_SKIP_RESET_COUNT 2
#define MIN_LOCAL_TS_DISTANCE_NS 100000000 /* 100 ms */
#define MAX_LOCAL_TS_DISTANCE_NS 350000000 /* 350 ms */
#define TS_PAIR_MISMATCH_THRESHOLD_NS 50000000 /* 50 ms */
#define MAX_TS_PAIR_MISMATCHES 5
#define MAX_TS_PAIR_MISMATCH_RESET_COUNT 3
#define MIN_OBSERVED_RATE 0.8
#define MAX_OBSERVED_RATE 1.2

static void
bt_calibration_thread(void)
{
	static uint64_t prev_local_ts = 0, prev_remote_ts = 0, curr_local_ts = 0, curr_remote_ts = 0;
	static uint64_t prev_received_local_ts = 0, prev_received_remote_ts = 0;
	static double cumulative_rate = INITIAL_RATE;
	static uint32_t initial_sample_count = 1;
	static uint32_t max_initial_sample_count = MAX_INITIAL_SAMPLE_COUNT;
	static uint32_t skip_reset_count = MAX_SKIP_RESET_COUNT;
	int recalculate_count = 1;
	static bool reset = false;
	bool sleep = false;
	static bool skip_rcv_ts = false;
	static uint64_t ts_pair_mismatch = 0;
	static uint32_t ts_pair_mismatch_reset_count = 0;
	spl_t s = splsched();
	lck_spin_lock(&bt_spin_lock);
	if (!received_remote_timestamp) {
		if (PE_parse_boot_argn("rt_ini_count", &max_initial_sample_count,
		    sizeof(uint32_t)) == TRUE) {
			if (max_initial_sample_count < MIN_INITIAL_SAMPLE_COUNT) {
				max_initial_sample_count = MIN_INITIAL_SAMPLE_COUNT;
			}
		}
		/* Nothing to do the first time */
		goto block;
	}
	/*
	 * The values in bt_params are recalculated every time a new timestamp
	 * pair is received. Firstly, both timestamps are converted to nanoseconds.
	 * The current and previous timestamp pairs are used to compute the
	 * observed_rate of the two clocks w.r.t each other. For the first
	 * MIN_INITIAL_SAMPLE_COUNT number of pairs, the cumulative_rate is a simple
	 * average of the observed_rate. For the later pairs, the cumulative_rate
	 * is updated using exponential moving average of the observed_rate.
	 * The current and bt_params' base timestamp pairs are used to compute
	 * the rate_from_base. This value ensures that the bt_params base
	 * timestamp pair curve doesn't stay parallel to the observed timestamp
	 * pair curve, rather moves in the direction of the observed timestamp curve.
	 * The bt_params.rate is computed as a weighted average of the cumulative_rate
	 * and the rate_from_base. For each current local timestamp, the remote_time
	 * is predicted using the previous values of bt_params. After computing the new
	 * bt_params.rate, bt_params.base_remote_time is set to this predicted value
	 * and bt_params.base_local_time is set to the current local timestamp.
	 */
recalculate:
	assertf(recalculate_count <= MAX_RECALCULATE_COUNT, "bt_caliberation_thread: recalculate \
					invocation exceeds MAX_RECALCULATE_COUNT");

	if ((received_remote_timestamp == BT_RESET_SENTINEL_TS) || (received_remote_timestamp == BT_WAKE_SENTINEL_TS)) {
		KDBG(MACHDBG_CODE(DBG_MACH_CLOCK, MACH_BRIDGE_RESET_TS), received_local_timestamp, received_remote_timestamp, 1);
		reset = true;
		skip_reset_count = MAX_SKIP_RESET_COUNT;
		ts_pair_mismatch_reset_count = 0;
		goto block;
	} else if (received_remote_timestamp == BT_SLEEP_SENTINEL_TS) {
		sleep = true;
	} else if (!received_local_timestamp) {
		/* If the local timestamp isn't accurately captured, the received value will be ignored */
		skip_rcv_ts = true;
		goto block;
	}

	/* Keep a copy of the prev timestamps to compute distance */
	prev_received_local_ts = curr_local_ts;
	prev_received_remote_ts = curr_remote_ts;

	uint64_t curr_local_abs = received_local_timestamp;
	absolutetime_to_nanoseconds(curr_local_abs, &curr_local_ts);
	curr_remote_ts = received_remote_timestamp;

	/* Prevent unusual rate changes caused by delayed timestamps */
	uint64_t local_diff = curr_local_ts - prev_received_local_ts;
	if (!(reset || sleep) && ((local_diff < MIN_LOCAL_TS_DISTANCE_NS) ||
	    (!skip_rcv_ts && (local_diff > MAX_LOCAL_TS_DISTANCE_NS)))) {
		/* Skip the current timestamp */
		KDBG(MACHDBG_CODE(DBG_MACH_CLOCK, MACH_BRIDGE_SKIP_TS), curr_local_ts, curr_remote_ts,
		    prev_received_local_ts);
		goto block;
	} else {
		skip_rcv_ts = false;
		/* Use the prev copy of timestamps only if the distance is acceptable */
		prev_local_ts = prev_received_local_ts;
		prev_remote_ts = prev_received_remote_ts;
	}
	lck_spin_unlock(&bt_spin_lock);
	splx(s);

	struct bt_params bt_params = {};

	lck_spin_lock(&bt_ts_conversion_lock);
	if (reset) {
		if (skip_reset_count > 0) {
			KDBG(MACHDBG_CODE(DBG_MACH_CLOCK, MACH_BRIDGE_SKIP_TS), curr_local_ts, curr_remote_ts,
			    prev_local_ts, skip_reset_count);
			skip_reset_count--;
			goto skip_reset;
		}
		bt_params.base_local_ts = curr_local_ts;
		bt_params.base_remote_ts = curr_remote_ts;
		bt_params.rate = cumulative_rate;
		prev_local_ts = 0;
		prev_remote_ts = 0;
		ts_pair_mismatch = 0;
		initial_sample_count = 1;
		reset = false;
		KDBG(MACHDBG_CODE(DBG_MACH_CLOCK, MACH_BRIDGE_RESET_TS), curr_local_ts, curr_remote_ts, 2);
	} else if (sleep) {
		absolutetime_to_nanoseconds(mach_absolute_time(), &bt_params.base_local_ts);
		bt_params.base_remote_ts = 0;
		bt_params.rate = 0;
		sleep = false;
	} else {
		struct bt_params bt_params_snapshot = {};
		if (bt_params_idx >= 0) {
			bt_params_snapshot = bt_params_hist[bt_params_idx];
		}
		lck_spin_unlock(&bt_ts_conversion_lock);
		if (bt_params_snapshot.rate == 0.0) {
			/*
			 * The rate should never be 0 because we always expect a reset/wake
			 * sentinel after sleep, followed by valid timestamp pair data that
			 * will be handled by the reset clause (above). However, we should
			 * not rely on a paired version of the remote OS - we could actually
			 * be running a completely different OS! Treat a timestamp after
			 * a sleep as a reset condition.
			 */
			reset = true;
			skip_reset_count = MAX_SKIP_RESET_COUNT;
			ts_pair_mismatch_reset_count = 0;
			KDBG(MACHDBG_CODE(DBG_MACH_CLOCK, MACH_BRIDGE_RESET_TS), curr_local_ts, curr_remote_ts, 3);
			s = splsched();
			lck_spin_lock(&bt_spin_lock);
			goto block;
		}

		/* Check if the predicted remote timestamp is within the expected current remote timestamp range */
		uint64_t pred_remote_ts = mach_bridge_compute_timestamp(curr_local_ts, &bt_params_snapshot);
		uint64_t diff = 0;
		if (initial_sample_count >= max_initial_sample_count) {
			if (pred_remote_ts > curr_remote_ts) {
				diff = pred_remote_ts - curr_remote_ts;
			} else {
				diff = curr_remote_ts - pred_remote_ts;
			}
			if (diff > TS_PAIR_MISMATCH_THRESHOLD_NS) {
				ts_pair_mismatch++;
				KDBG(MACHDBG_CODE(DBG_MACH_CLOCK, MACH_BRIDGE_TS_MISMATCH), curr_local_ts,
				    curr_remote_ts, pred_remote_ts, ts_pair_mismatch);
			} else {
				ts_pair_mismatch = 0;
			}
			if (ts_pair_mismatch > MAX_TS_PAIR_MISMATCHES) {
#if (DEVELOPMENT || DEBUG)
				if (ts_pair_mismatch_reset_count == MAX_TS_PAIR_MISMATCH_RESET_COUNT) {
					panic("remote_time: timestamp pair mismatch exceeded limit");
				}
#endif /* (DEVELOPMENT || DEBUG) */
				reset = true;
				ts_pair_mismatch_reset_count++;
				KDBG(MACHDBG_CODE(DBG_MACH_CLOCK, MACH_BRIDGE_RESET_TS), curr_local_ts, curr_remote_ts, 4);
				s = splsched();
				lck_spin_lock(&bt_spin_lock);
				goto block;
			}
		}
		double observed_rate, rate_from_base, new_rate;
		observed_rate = mach_bridge_compute_rate(curr_local_ts, curr_remote_ts, prev_local_ts, prev_remote_ts);
		/* Log bad observed rates and skip the timestamp pair */
		if ((observed_rate < MIN_OBSERVED_RATE) || (observed_rate > MAX_OBSERVED_RATE)) {
			KDBG(MACHDBG_CODE(DBG_MACH_CLOCK, MACH_BRIDGE_OBSV_RATE), *(uint64_t *)((void *)&observed_rate));
			ts_pair_mismatch = ts_pair_mismatch > 0 ? (ts_pair_mismatch - 1) : 0;
			s = splsched();
			lck_spin_lock(&bt_spin_lock);
			goto block;
		}
		if (initial_sample_count <= MIN_INITIAL_SAMPLE_COUNT) {
			initial_sample_count++;
			cumulative_rate = cumulative_rate + (observed_rate - cumulative_rate) / initial_sample_count;
		} else {
			if (initial_sample_count < max_initial_sample_count) {
				initial_sample_count++;
			}
			cumulative_rate = cumulative_rate + CUMULATIVE_RATE_DECAY_CONSTANT * (observed_rate - cumulative_rate);
		}
		rate_from_base = mach_bridge_compute_rate(curr_local_ts, curr_remote_ts, bt_params_snapshot.base_local_ts,
		    bt_params_snapshot.base_remote_ts);
		new_rate = CUMULATIVE_RATE_WEIGHT * cumulative_rate + (1 - CUMULATIVE_RATE_WEIGHT) * rate_from_base;
		/*
		 * Acquire the lock first to ensure that bt_params.base_local_ts is always
		 * greater than the last value of now captured by mach_bridge_remote_time.
		 * This ensures that we always use the same parameters to compute remote
		 * timestamp for a given local timestamp.
		 */
		lck_spin_lock(&bt_ts_conversion_lock);
		absolutetime_to_nanoseconds(mach_absolute_time(), &bt_params.base_local_ts);
		bt_params.base_remote_ts = mach_bridge_compute_timestamp(bt_params.base_local_ts, &bt_params_snapshot);
		bt_params.rate = new_rate;
	}
	bt_params_add(&bt_params);
	commpage_set_remotetime_params(bt_params.rate, bt_params.base_local_ts, bt_params.base_remote_ts);
	KDBG(MACHDBG_CODE(DBG_MACH_CLOCK, MACH_BRIDGE_TS_PARAMS), bt_params.base_local_ts,
	    bt_params.base_remote_ts, *(uint64_t *)((void *)&bt_params.rate));

skip_reset:
	lck_spin_unlock(&bt_ts_conversion_lock);

	s = splsched();
	lck_spin_lock(&bt_spin_lock);
	/* Check if a new timestamp pair was received */
	if (received_local_timestamp != curr_local_abs) {
		recalculate_count++;
		goto recalculate;
	}
block:
	assert_wait((event_t)bt_params_hist, THREAD_UNINT);
	lck_spin_unlock(&bt_spin_lock);
	splx(s);
	thread_block((thread_continue_t)bt_calibration_thread);
}

void
bt_calibration_thread_start(void)
{
	thread_t thread;
	kern_return_t result = kernel_thread_start_priority((thread_continue_t)bt_calibration_thread,
	    NULL, BASEPRI_KERNEL, &thread);
	if (result != KERN_SUCCESS) {
		panic("mach_bridge_add_timestamp: thread_timestamp_calibration");
	}
	thread_deallocate(thread);
}

#endif /* CONFIG_MACH_BRIDGE_RECV_TIME */

/**
 * mach_bridge_remote_time
 *
 * This function is used to predict the remote CPU's clock time, given
 * the local time.
 *
 * If local_timestamp = 0, then the remote_timestamp is calculated
 * corresponding to the current mach_absolute_time.
 *
 * If XNU_TARGET_OS_BRIDGE is defined, then monotonicity of
 * predicted time is guaranteed only for recent local_timestamp values
 * lesser than the current mach_absolute_time upto 1 second.
 *
 * If CONFIG_MACH_BRIDGE_SEND_TIME is true, then the function is compiled
 * for the remote CPU. If CONFIG_MACH_BRIDGE_RECV_TIME is true, then the
 * the function is compiled for the local CPU. Both config options cannot
 * be true simultaneously.
 */
uint64_t
mach_bridge_remote_time(uint64_t local_timestamp)
{
#if defined(CONFIG_MACH_BRIDGE_SEND_TIME)
#if !defined(CONFIG_MACH_BRIDGE_RECV_TIME)
	/* only send side of the bridge is defined: no translation needed */
	if (!local_timestamp) {
		return mach_absolute_time();
	}
	return 0;
#else
#error "You cannot define both sides of the bridge!"
#endif /* !defined(CONFIG_MACH_BRIDGE_RECV_TIME) */
#else
#if !defined(CONFIG_MACH_BRIDGE_RECV_TIME)
	/* neither the send or receive side of the bridge is defined: echo the input */
	return local_timestamp;
#else
	if (!os_atomic_load(&bt_init_flag, acquire)) {
		return 0;
	}

	uint64_t remote_timestamp = 0;

	lck_spin_lock(&bt_ts_conversion_lock);
	uint64_t now = mach_absolute_time();
	if (!local_timestamp) {
		local_timestamp = now;
	}
#if defined(XNU_TARGET_OS_BRIDGE)
	uint64_t local_timestamp_ns = 0;
	if (local_timestamp < now) {
		absolutetime_to_nanoseconds(local_timestamp, &local_timestamp_ns);
		struct bt_params *params = bt_params_find(local_timestamp_ns);
		remote_timestamp = mach_bridge_compute_timestamp(local_timestamp_ns, params);
	}
#else
	struct bt_params params = bt_params_get_latest_locked();
	remote_timestamp = mach_bridge_compute_timestamp(local_timestamp, &params);
#endif /* defined(XNU_TARGET_OS_BRIDGE) */
	lck_spin_unlock(&bt_ts_conversion_lock);
	KDBG(MACHDBG_CODE(DBG_MACH_CLOCK, MACH_BRIDGE_REMOTE_TIME), local_timestamp, remote_timestamp, now);

	return remote_timestamp;
#endif /* !defined(CONFIG_MACH_BRIDGE_RECV_TIME) */
#endif /* defined(CONFIG_MACH_BRIDGE_SEND_TIME) */
}
