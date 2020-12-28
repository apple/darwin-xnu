#include <stdio.h>
#include <unistd.h>

#include <mach/mach.h>
#include <mach/mach_time.h>
#include <sys/time.h>
#include <spawn.h>
#include <sys/wait.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <sys/event.h>

#include <darwintest.h>

extern char **environ;

static mach_timebase_info_data_t tb_info;
static const uint64_t one_mil = 1000LL * 1000LL;

#define tick_to_ns(ticks) (((ticks) * tb_info.numer) / (tb_info.denom))
#define tick_to_ms(ticks) (tick_to_ns(ticks)/one_mil)

#define ns_to_tick(ns) ((ns) * tb_info.denom / tb_info.numer)
#define ms_to_tick(ms) (ns_to_tick((ms) * one_mil))

static uint64_t
time_delta_ms(void)
{
	uint64_t abs_now = mach_absolute_time();
	uint64_t cnt_now = mach_continuous_time();;
	return tick_to_ms(cnt_now) - tick_to_ms(abs_now);
}

static int run_sleep_tests = 0;

static int
trigger_sleep(int for_secs)
{
	if (!run_sleep_tests) {
		return 0;
	}

	// sleep for 1 seconds each iteration
	char buf[10];
	snprintf(buf, 10, "%d", for_secs);

	T_LOG("Sleepeing for %s seconds...", buf);

	int spawn_ret, pid;
	char *const pmset1_args[] = {"/usr/bin/pmset", "relative", "wake", buf, NULL};
	T_ASSERT_POSIX_ZERO((spawn_ret = posix_spawn(&pid, pmset1_args[0], NULL, NULL, pmset1_args, environ)), NULL);

	T_ASSERT_EQ(waitpid(pid, &spawn_ret, 0), pid, NULL);
	T_ASSERT_EQ(spawn_ret, 0, NULL);

	char *const pmset2_args[] = {"/usr/bin/pmset", "sleepnow", NULL};
	T_ASSERT_POSIX_ZERO((spawn_ret = posix_spawn(&pid, pmset2_args[0], NULL, NULL, pmset2_args, environ)), NULL);

	T_ASSERT_EQ(waitpid(pid, &spawn_ret, 0), pid, NULL);
	T_ASSERT_EQ(spawn_ret, 0, NULL);

	return 0;
}

// waits up to 30 seconds for system to sleep
// returns number of seconds it took for sleep to be entered
// or -1 if sleep wasn't accomplished
static int
wait_for_sleep()
{
	if (!run_sleep_tests) {
		return 0;
	}

	uint64_t before_diff = time_delta_ms();

	for (int i = 0; i < 30; i++) {
		uint64_t after_diff = time_delta_ms();

		// on OSX, there's enough latency between calls to MCT and MAT
		// when the system is going down for sleep for values to diverge a few ms
		if (llabs((int64_t)before_diff - (int64_t)after_diff) > 2) {
			return i + 1;
		}

		sleep(1);
		T_LOG("waited %d seconds for sleep...", i + 1);
	}
	return -1;
}

T_DECL(kevent_continuous_time_periodic_tick, "kevent(EVFILT_TIMER with NOTE_MACH_CONTINUOUS_TIME)", T_META_LTEPHASE(LTE_POSTINIT)){
	mach_timebase_info(&tb_info);
	int kq;
	T_ASSERT_POSIX_SUCCESS((kq = kqueue()), NULL);

	struct kevent64_s kev = {
		.ident = 1,
		.filter = EVFILT_TIMER,
		.flags = EV_ADD | EV_RECEIPT,
		.fflags = NOTE_SECONDS | NOTE_MACH_CONTINUOUS_TIME,
		.data = 4,
	};
	T_LOG("EV_SET(&kev, 1, EVFILT_TIMER, EV_ADD, NOTE_SECONDS | NOTE_MACH_CONTINUOUS_TIME, 4, 0, 0, 0);");

	T_ASSERT_EQ(kevent64(kq, &kev, 1, &kev, 1, 0, NULL), 1, NULL);
	T_ASSERT_EQ(0ll, kev.data, "No error returned");

	uint64_t abs_then = mach_absolute_time();
	uint64_t cnt_then = mach_continuous_time();;

	trigger_sleep(1);
	int sleep_secs = wait_for_sleep();

	T_WITH_ERRNO; T_ASSERT_EQ(kevent64(kq, NULL, 0, &kev, 1, 0, NULL), 1, "kevent() should have returned one event");
	T_LOG("event = {.ident = %llx, .filter = %d, .flags = %d, .fflags = %d, .data = %lld, .udata = %lld}", kev.ident, kev.filter, kev.flags, kev.fflags, kev.data, kev.udata);
	T_ASSERT_EQ(kev.flags & EV_ERROR, 0, "event should not have EV_ERROR set: %s", kev.flags & EV_ERROR ? strerror((int)kev.data) : "no error");

	uint64_t abs_now = mach_absolute_time();
	uint64_t cnt_now = mach_continuous_time();;
	uint64_t ct_ms_progressed = tick_to_ms(cnt_now - cnt_then);
	uint64_t ab_ms_progressed = tick_to_ms(abs_now - abs_then);

	T_LOG("ct progressed %llu ms, abs progressed %llu ms", ct_ms_progressed, tick_to_ms(abs_now - abs_then));

	if (run_sleep_tests) {
		T_ASSERT_GT(llabs((int64_t)ct_ms_progressed - (int64_t)ab_ms_progressed), 500LL, "should have > 500ms difference between MCT and MAT");
	} else {
		T_ASSERT_LT(llabs((int64_t)ct_ms_progressed - (int64_t)ab_ms_progressed), 10LL, "should have < 10ms difference between MCT and MAT");
	}

	if (sleep_secs < 4) {
		T_ASSERT_LT(llabs((int64_t)ct_ms_progressed - 4000), 100LL, "mach_continuous_time should progress ~4 seconds (+/- 100ms) between sleeps");
	}

	sleep(1);

	kev = (struct kevent64_s){
		.ident = 1,
		.filter = EVFILT_TIMER,
		.flags = EV_DELETE | EV_RECEIPT,
	};
	T_LOG("EV_SET(&kev, 1, EVFILT_TIMER, EV_DELETE, 0, 0, 0);");
	T_ASSERT_EQ(kevent64(kq, &kev, 1, &kev, 1, 0, NULL), 1, NULL);
	T_ASSERT_EQ(0ll, kev.data, "No error returned");

	T_ASSERT_POSIX_ZERO(close(kq), NULL);
}

T_DECL(kevent_continuous_time_absolute, "kevent(EVFILT_TIMER with NOTE_MACH_CONTINUOUS_TIME and NOTE_ABSOLUTE)", T_META_LTEPHASE(LTE_POSTINIT)){
	mach_timebase_info(&tb_info);

	int kq;
	T_ASSERT_POSIX_SUCCESS((kq = kqueue()), NULL);

	struct timeval tv;
	gettimeofday(&tv, NULL);
	int64_t nowus   = (int64_t)tv.tv_sec * USEC_PER_SEC + (int64_t)tv.tv_usec;
	int64_t fire_at = (3 * USEC_PER_SEC) + nowus;

	uint64_t cnt_now = mach_continuous_time();
	uint64_t cnt_then = cnt_now + ms_to_tick(3000);

	T_LOG("currently is %llu, firing at %llu", nowus, fire_at);

	struct kevent64_s kev = {
		.ident = 2,
		.filter = EVFILT_TIMER,
		.flags = EV_ADD | EV_RECEIPT,
		.fflags = NOTE_MACH_CONTINUOUS_TIME | NOTE_ABSOLUTE | NOTE_USECONDS,
		.data = fire_at,
	};
	T_LOG("EV_SET(&kev, 2, EVFILT_TIMER, EV_ADD, NOTE_MACH_CONTINUOUS_TIME | NOTE_ABSOLUTE | NOTE_USECONDS, fire_at, 0);");

	T_ASSERT_EQ(kevent64(kq, &kev, 1, &kev, 1, 0, NULL), 1, NULL);
	T_ASSERT_EQ(0ll, kev.data, "No error returned");

	T_LOG("testing NOTE_MACH_CONTINUOUS_TIME | NOTE_ABSOLUTE between sleep");

	trigger_sleep(1);

	struct timespec timeout = {
		.tv_sec = 10,
		.tv_nsec = 0,
	};
	struct kevent64_s event = {0};
	T_ASSERT_EQ(kevent64(kq, NULL, 0, &event, 1, 0, &timeout), 1, "kevent() should have returned one event");
	T_LOG("event = {.ident = %llx, .filter = %d, .flags = %d, .fflags = %d, .data = %lld, .udata = %lld}", event.ident, event.filter, event.flags, event.fflags, event.data, event.udata);
	T_ASSERT_EQ(event.flags & EV_ERROR, 0, "event should not have EV_ERROR set: %s", event.flags & EV_ERROR ? strerror((int)event.data) : "no error");

	uint64_t elapsed_ms = tick_to_ms(mach_continuous_time() - cnt_now);
	int64_t missed_by  = tick_to_ns((int64_t)mach_continuous_time() - (int64_t)cnt_then) / 1000000;

	// ~1/2 second is about as good as we'll get
	T_ASSERT_LT(llabs(missed_by), 500LL, "timer should pop 3 sec in the future, popped after %lldms", elapsed_ms);

	T_ASSERT_EQ(event.data, 1LL, NULL);

	T_ASSERT_EQ(event.ident, 2ULL, NULL);

	// try getting a periodic tick out of kq
	T_ASSERT_EQ(kevent64(kq, NULL, 0, &event, 1, 0, &timeout), 0, NULL);
	T_ASSERT_EQ(event.flags & EV_ERROR, 0, "event should not have EV_ERROR set: %s", event.flags & EV_ERROR ? strerror((int)event.data) : "no error");

	T_ASSERT_POSIX_ZERO(close(kq), NULL);
}

T_DECL(kevent_continuous_time_pops, "kevent(EVFILT_TIMER with NOTE_MACH_CONTINUOUS_TIME with multiple pops)", T_META_LTEPHASE(LTE_POSTINIT)){
	// have to throttle rate at which pmset is called
	sleep(2);

	mach_timebase_info(&tb_info);

	int kq;
	T_ASSERT_POSIX_SUCCESS((kq = kqueue()), NULL);

	// test that periodic ticks accumulate while asleep
	struct kevent64_s kev = {
		.ident = 3,
		.filter = EVFILT_TIMER,
		.flags = EV_ADD | EV_RECEIPT,
		.fflags = NOTE_MACH_CONTINUOUS_TIME,
		.data = 100,
	};
	T_LOG("EV_SET(&kev, 3, EVFILT_TIMER, EV_ADD, NOTE_MACH_CONTINUOUS_TIME, 100, 0);");

	// wait for first pop, then sleep
	T_ASSERT_EQ(kevent64(kq, &kev, 1, &kev, 1, 0, NULL), 1, NULL);
	T_ASSERT_EQ(0ll, kev.data, "No error returned");

	struct kevent64_s event = {0};
	T_ASSERT_EQ(kevent64(kq, NULL, 0, &event, 1, 0, NULL), 1, "kevent() should have returned one event");
	T_LOG("event = {.ident = %llx, .filter = %d, .flags = %d, .fflags = %d, .data = %lld, .udata = %llu}", event.ident, event.filter, event.flags, event.fflags, event.data, event.udata);
	T_ASSERT_EQ(event.flags & EV_ERROR, 0, "should not have EV_ERROR set: %s", event.flags & EV_ERROR ? strerror((int)event.data) : "no error");
	T_ASSERT_EQ(event.ident, 3ULL, NULL);

	uint64_t cnt_then = mach_continuous_time();
	trigger_sleep(2);

	int sleep_secs = 0;
	if (run_sleep_tests) {
		sleep_secs = wait_for_sleep();
	} else {
		// simulate 2 seconds of system "sleep"
		sleep(2);
	}

	uint64_t cnt_now = mach_continuous_time();

	uint64_t ms_elapsed = tick_to_ms(cnt_now - cnt_then);
	if (run_sleep_tests) {
		T_ASSERT_LT(llabs((int64_t)ms_elapsed - 2000LL), 500LL, "slept for %llums, expected 2000ms (astris is connected?)", ms_elapsed);
	}

	T_ASSERT_EQ(kevent64(kq, NULL, 0, &event, 1, 0, NULL), 1, "kevent() should have returned one event");
	T_LOG("event = {.ident = %llx, .filter = %d, .flags = %d, .fflags = %d, .data = %lld, .udata = %llu}", event.ident, event.filter, event.flags, event.fflags, event.data, event.udata);
	T_ASSERT_EQ(event.ident, 3ULL, NULL);

	uint64_t expected_pops = ms_elapsed / 100;
	uint64_t got_pops      = (uint64_t)event.data;

	T_ASSERT_GE(got_pops, expected_pops - 1, "tracking pops while asleep");
	T_ASSERT_POSIX_ZERO(close(kq), NULL);
}
