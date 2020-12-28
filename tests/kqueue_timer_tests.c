#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/task.h>

#include <TargetConditionals.h>
#include <darwintest.h>

#ifndef NOTE_MACHTIME
#define NOTE_MACHTIME   0x00000100
#endif

static mach_timebase_info_data_t timebase_info;

static uint64_t
nanos_to_abs(uint64_t nanos)
{
	return nanos * timebase_info.denom / timebase_info.numer;
}
static uint64_t
abs_to_nanos(uint64_t abs)
{
	return abs * timebase_info.numer / timebase_info.denom;
}

static int kq, passed, failed;

static struct timespec failure_timeout = { .tv_sec = 10, .tv_nsec = 0 };

/*
 * Wait for given kevent, which should return in 'expected' usecs.
 */
static int
do_simple_kevent(struct kevent64_s *kev, uint64_t expected)
{
	int ret;
	int64_t elapsed_usecs;
	uint64_t delta_usecs;
	struct timespec timeout;
	struct timeval before, after;

	/* time out after 1 sec extra delay */
	timeout.tv_sec = (expected / USEC_PER_SEC) + 1;
	timeout.tv_nsec = (expected % USEC_PER_SEC) * 1000;

	T_SETUPBEGIN;

	/* measure time for the kevent */
	gettimeofday(&before, NULL);
	ret = kevent64(kq, kev, 1, kev, 1, 0, &timeout);
	gettimeofday(&after, NULL);

	if (ret < 1 || (kev->flags & EV_ERROR)) {
		T_LOG("%s() failure: kevent returned %d, error %d\n", __func__, ret,
		    (ret == -1 ? errno : (int) kev->data));
		return 0;
	}

	T_SETUPEND;

	/* did it work? */
	elapsed_usecs = (after.tv_sec - before.tv_sec) * (int64_t)USEC_PER_SEC +
	    (after.tv_usec - before.tv_usec);
	delta_usecs = (uint64_t)llabs(elapsed_usecs - ((int64_t)expected));

	/* failure if we're 30% off, or 50 mics late */
	if (delta_usecs > (30 * expected / 100.0) && delta_usecs > 50) {
		T_LOG("\tfailure: expected %lld usec, measured %lld usec.\n",
		    expected, elapsed_usecs);
		return 0;
	} else {
		T_LOG("\tsuccess, measured %lld usec.\n", elapsed_usecs);
		return 1;
	}
}

static void
test_absolute_kevent(int time, int scale)
{
	struct timeval tv;
	struct kevent64_s kev;
	uint64_t nowus, expected, timescale = 0;
	int ret;
	int64_t deadline;

	gettimeofday(&tv, NULL);
	nowus = (uint64_t)tv.tv_sec * USEC_PER_SEC + (uint64_t)tv.tv_usec;

	T_SETUPBEGIN;

	switch (scale) {
	case NOTE_MACHTIME:
		T_LOG("Testing %d MATUs absolute timer...\n", time);
		break;
	case NOTE_SECONDS:
		T_LOG("Testing %d sec absolute timer...\n", time);
		timescale = USEC_PER_SEC;
		break;
	case NOTE_USECONDS:
		T_LOG("Testing %d usec absolute timer...\n", time);
		timescale = 1;
		break;
	case 0:
		T_LOG("Testing %d msec absolute timer...\n", time);
		timescale = 1000;
		break;
	default:
		T_FAIL("Failure: scale 0x%x not recognized.\n", scale);
		return;
	}

	T_SETUPEND;

	if (scale == NOTE_MACHTIME) {
		expected = abs_to_nanos((uint64_t)time) / NSEC_PER_USEC;
		deadline = (int64_t)mach_absolute_time() + time;
	} else {
		expected = (uint64_t)time * timescale;
		deadline = (int64_t)(nowus / timescale) + time;
	}

	/* deadlines in the past should fire immediately */
	if (time < 0) {
		expected = 0;
	}

	EV_SET64(&kev, 1, EVFILT_TIMER, EV_ADD,
	    NOTE_ABSOLUTE | scale, deadline, 0, 0, 0);
	ret = do_simple_kevent(&kev, expected);

	if (ret) {
		passed++;
		T_PASS("%s time:%d, scale:0x%x", __func__, time, scale);
	} else {
		failed++;
		T_FAIL("%s time:%d, scale:0x%x", __func__, time, scale);
	}
}

static void
test_oneshot_kevent(int time, int scale)
{
	int ret;
	uint64_t expected = 0;
	struct kevent64_s kev;

	T_SETUPBEGIN;

	switch (scale) {
	case NOTE_MACHTIME:
		T_LOG("Testing %d MATUs interval timer...\n", time);
		expected = abs_to_nanos((uint64_t)time) / NSEC_PER_USEC;
		break;
	case NOTE_SECONDS:
		T_LOG("Testing %d sec interval timer...\n", time);
		expected = (uint64_t)time * USEC_PER_SEC;
		break;
	case NOTE_USECONDS:
		T_LOG("Testing %d usec interval timer...\n", time);
		expected = (uint64_t)time;
		break;
	case NOTE_NSECONDS:
		T_LOG("Testing %d nsec interval timer...\n", time);
		expected = (uint64_t)time / 1000;
		break;
	case 0:
		T_LOG("Testing %d msec interval timer...\n", time);
		expected = (uint64_t)time * 1000;
		break;
	default:
		T_FAIL("Failure: scale 0x%x not recognized.\n", scale);
		return;
	}

	T_SETUPEND;

	/* deadlines in the past should fire immediately */
	if (time < 0) {
		expected = 0;
	}

	EV_SET64(&kev, 2, EVFILT_TIMER, EV_ADD | EV_ONESHOT, scale, time,
	    0, 0, 0);
	ret = do_simple_kevent(&kev, expected);

	if (ret) {
		passed++;
		T_PASS("%s time:%d, scale:0x%x", __func__, time, scale);
	} else {
		failed++;
		T_FAIL("%s time:%d, scale:0x%x", __func__, time, scale);
	}
}

/* Test that the timer goes ding multiple times */
static void
test_interval_kevent(int usec)
{
	struct kevent64_s kev;
	int ret;

	T_SETUPBEGIN;

	uint64_t test_duration_us = USEC_PER_SEC; /* 1 second */
	uint64_t expected_pops;

	if (usec < 0) {
		expected_pops = 1; /* TODO: test 'and only once' */
	} else {
		expected_pops = test_duration_us / (uint64_t)usec;
	}

	T_LOG("Testing interval kevent at %d usec intervals (%lld pops/second)...\n",
	    usec, expected_pops);

	EV_SET64(&kev, 3, EVFILT_TIMER, EV_ADD, NOTE_USECONDS, usec, 0, 0, 0);
	ret = kevent64(kq, &kev, 1, NULL, 0, 0, NULL);
	if (ret != 0 || (kev.flags & EV_ERROR)) {
		T_FAIL("%s() setup failure: kevent64 returned %d\n", __func__, ret);
		failed++;
		return;
	}

	T_SETUPEND;

	struct timeval before, after;
	uint64_t elapsed_usecs;

	gettimeofday(&before, NULL);

	uint64_t pops = 0;

	for (uint32_t i = 0; i < expected_pops; i++) {
		ret = kevent64(kq, NULL, 0, &kev, 1, 0, &failure_timeout);
		if (ret != 1) {
			T_FAIL("%s() failure: kevent64 returned %d\n", __func__, ret);
			failed++;
			return;
		}

		//T_LOG("\t ding: %lld\n", kev.data);

		pops += (uint64_t)kev.data;
		gettimeofday(&after, NULL);
		elapsed_usecs = (uint64_t)((after.tv_sec - before.tv_sec) * (int64_t)USEC_PER_SEC +
		    (after.tv_usec - before.tv_usec));

		if (elapsed_usecs > test_duration_us) {
			break;
		}
	}

	/* check how many times the timer fired: within 5%? */
	if (pops > expected_pops + (expected_pops / 20) ||
	    pops < expected_pops - (expected_pops / 20)) {
		T_FAIL("%s() usec:%d (saw %lld of %lld expected pops)", __func__, usec, pops, expected_pops);
		failed++;
	} else {
		T_PASS("%s() usec:%d (saw %lld pops)", __func__, usec, pops);
		passed++;
	}

	EV_SET64(&kev, 3, EVFILT_TIMER, EV_DELETE, 0, 0, 0, 0, 0);
	ret = kevent64(kq, &kev, 1, NULL, 0, 0, NULL);
	if (ret != 0) {
		T_LOG("\tfailed to stop repeating timer: %d\n", ret);
	}
}

/* Test that the repeating timer repeats even while not polling in kqueue */
static void
test_repeating_kevent(int usec)
{
	struct kevent64_s kev;
	int ret;

	T_SETUPBEGIN;

	uint64_t test_duration_us = USEC_PER_SEC; /* 1 second */

	uint64_t expected_pops = test_duration_us / (uint64_t)usec;
	T_LOG("Testing repeating kevent at %d usec intervals (%lld pops/second)...\n",
	    usec, expected_pops);

	EV_SET64(&kev, 4, EVFILT_TIMER, EV_ADD, NOTE_USECONDS, usec, 0, 0, 0);
	ret = kevent64(kq, &kev, 1, NULL, 0, 0, NULL);
	if (ret != 0) {
		T_FAIL("%s() setup failure: kevent64 returned %d\n", __func__, ret);
		failed++;
		return;
	}

	usleep((useconds_t)test_duration_us);

	ret = kevent64(kq, NULL, 0, &kev, 1, 0, &failure_timeout);
	if (ret != 1 || (kev.flags & EV_ERROR)) {
		T_FAIL("%s() setup failure: kevent64 returned %d\n", __func__, ret);
		failed++;
		return;
	}

	T_SETUPEND;

	uint64_t pops = (uint64_t) kev.data;

	/* check how many times the timer fired: within 5%? */
	if (pops > expected_pops + (expected_pops / 20) ||
	    pops < expected_pops - (expected_pops / 20)) {
		T_FAIL("%s() usec:%d (saw %lld of %lld expected pops)", __func__, usec, pops, expected_pops);
		failed++;
	} else {
		T_PASS("%s() usec:%d (saw %lld pops)", __func__, usec, pops);
		passed++;
	}

	EV_SET64(&kev, 4, EVFILT_TIMER, EV_DELETE, 0, 0, 0, 0, 0);
	ret = kevent64(kq, &kev, 1, NULL, 0, 0, NULL);
	if (ret != 0) {
		T_LOG("\tfailed to stop repeating timer: %d\n", ret);
	}
}


static void
test_updated_kevent(int first, int second)
{
	struct kevent64_s kev;
	int ret;

	T_LOG("Testing update from %d to %d msecs...\n", first, second);

	T_SETUPBEGIN;

	EV_SET64(&kev, 4, EVFILT_TIMER, EV_ADD | EV_ONESHOT, 0, first, 0, 0, 0);
	ret = kevent64(kq, &kev, 1, NULL, 0, 0, NULL);
	if (ret != 0) {
		T_FAIL("%s() failure: initial kevent returned %d\n", __func__, ret);
		failed++;
		return;
	}

	T_SETUPEND;

	EV_SET64(&kev, 4, EVFILT_TIMER, EV_ONESHOT, 0, second, 0, 0, 0);

	uint64_t expected_us = (uint64_t)second * 1000;

	if (second < 0) {
		expected_us = 0;
	}

	ret = do_simple_kevent(&kev, expected_us);

	if (ret) {
		passed++;
		T_PASS("%s() %d, %d", __func__, first, second);
	} else {
		failed++;
		T_FAIL("%s() %d, %d", __func__, first, second);
	}
}

static void
disable_timer_coalescing(void)
{
	struct task_qos_policy      qosinfo;
	kern_return_t                       kr;

	T_SETUPBEGIN;

	qosinfo.task_latency_qos_tier = LATENCY_QOS_TIER_0;
	qosinfo.task_throughput_qos_tier = THROUGHPUT_QOS_TIER_0;

	kr = task_policy_set(mach_task_self(), TASK_OVERRIDE_QOS_POLICY, (task_policy_t)&qosinfo,
	    TASK_QOS_POLICY_COUNT);
	if (kr != KERN_SUCCESS) {
		T_FAIL("task_policy_set(... TASK_OVERRIDE_QOS_POLICY ...) failed: %d (%s)", kr, mach_error_string(kr));
	}

	T_SETUPEND;
}

T_DECL(kqueue_timer_tests,
    "Tests assorted kqueue operations for timer-related events")
{
	/*
	 * Since we're trying to test timers here, disable timer coalescing
	 * to improve the accuracy of timer fires for this process.
	 */
	disable_timer_coalescing();

	mach_timebase_info(&timebase_info);

	kq = kqueue();
	assert(kq > 0);
	passed = 0;
	failed = 0;

	test_absolute_kevent(100, 0);
	test_absolute_kevent(200, 0);
	test_absolute_kevent(300, 0);
	test_absolute_kevent(1000, 0);
	T_MAYFAIL;
	test_absolute_kevent(500, NOTE_USECONDS);
	T_MAYFAIL;
	test_absolute_kevent(100, NOTE_USECONDS);
	T_MAYFAIL;
	test_absolute_kevent(2, NOTE_SECONDS);
	T_MAYFAIL;
	test_absolute_kevent(-1000, 0);

	T_MAYFAIL;
	test_absolute_kevent((int)nanos_to_abs(10 * NSEC_PER_MSEC), NOTE_MACHTIME);

	test_oneshot_kevent(1, NOTE_SECONDS);
	T_MAYFAIL;
	test_oneshot_kevent(10, 0);
	T_MAYFAIL;
	test_oneshot_kevent(200, NOTE_USECONDS);
	T_MAYFAIL;
	test_oneshot_kevent(300000, NOTE_NSECONDS);
	T_MAYFAIL;
	test_oneshot_kevent(-1, NOTE_SECONDS);

	T_MAYFAIL;
	test_oneshot_kevent((int)nanos_to_abs(10 * NSEC_PER_MSEC), NOTE_MACHTIME);

	test_interval_kevent(250 * 1000);
	T_MAYFAIL;
	test_interval_kevent(5 * 1000);
	T_MAYFAIL;
	test_interval_kevent(200);
	T_MAYFAIL;
	test_interval_kevent(50);

	test_interval_kevent(-1000);

	test_repeating_kevent(10000); /* 10ms */

	test_updated_kevent(1000, 2000);
	test_updated_kevent(2000, 1000);
	test_updated_kevent(1000, -1);
}
