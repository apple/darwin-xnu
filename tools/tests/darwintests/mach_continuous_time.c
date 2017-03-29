#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/clock_types.h>
#include <sys/time.h>
#include <spawn.h>
#include <sys/wait.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>

#include <darwintest.h>

extern char **environ;

static const int64_t one_mil = 1000*1000;

#define to_ns(ticks) ((ticks * tb_info.numer) / (tb_info.denom))
#define to_ms(ticks) (to_ns(ticks)/one_mil)

static mach_timebase_info_data_t tb_info;

static void
update(uint64_t *a, uint64_t *c) {
	mach_get_times(a,c,NULL);
}

T_DECL(mct_monotonic, "Testing mach_continuous_time returns sane, monotonic values",
		T_META_ALL_VALID_ARCHS(true))
{
	mach_timebase_info(&tb_info);

	volatile uint64_t multiple_test = to_ms(mach_continuous_time());
	for(int i = 0; i < 10; i++) {
		uint64_t tmp = to_ms(mach_continuous_time());
		T_ASSERT_GE(tmp, multiple_test, "mach_continuous_time must be monotonic");

		// each successive call shouldn't be more than 50ms in the future
		T_ASSERT_LE(tmp - multiple_test, 50ULL, "mach_continuous_time should not jump forward too fast");

		multiple_test = tmp;
	}
}

T_DECL(mct_pause, "Testing mach_continuous_time and mach_absolute_time don't diverge")
{
	mach_timebase_info(&tb_info);

	uint64_t abs_now;
	uint64_t cnt_now;
	int before_diff, after_diff;

	update(&abs_now, &cnt_now);
	before_diff = (int)(to_ms(cnt_now) - to_ms(abs_now));

	sleep(1);

	update(&abs_now, &cnt_now);
	after_diff = (int)(to_ms(cnt_now) - to_ms(abs_now));

	T_ASSERT_LE(abs(after_diff - before_diff), 1, "mach_continuous_time and mach_absolute_time should not diverge");
}

T_DECL(mct_sleep, "Testing mach_continuous_time behavior over system sleep"){
#ifndef MCT_SLEEP_TEST
	T_SKIP("Skipping test that sleeps the device; compile with MCT_SLEEP_TEST define to enable.");
#endif

	mach_timebase_info(&tb_info);

	uint64_t abs_now;
	uint64_t cnt_now;
	int before_diff, after_diff = 0;

	T_LOG("Testing mach_continuous_time is ~5 seconds ahead of mach_absolute_time after 5 second sleep");
	update(&abs_now, &cnt_now);
	before_diff = (int)(to_ms(cnt_now) - to_ms(abs_now));

	// performs:
	// pmset relative wake 5
	// pmset sleepnow

	pid_t pid;
	int spawn_ret = 0;
	time_t before_sleep = time(NULL);
	int ct_ms_before_sleep = (int)to_ms(cnt_now);
	int ab_ms_before_sleep = (int)to_ms(abs_now);

	char *const pmset1_args[] = {"/usr/bin/pmset", "relative", "wake", "5", NULL};
	T_ASSERT_POSIX_ZERO((spawn_ret = posix_spawn(&pid, pmset1_args[0], NULL, NULL, pmset1_args, environ)), NULL);

	T_ASSERT_EQ(waitpid(pid, &spawn_ret, 0), pid, "waitpid failed");
	T_ASSERT_EQ(spawn_ret, 0, "pmset relative wait 5 failed");

	char *const pmset2_args[] = {"/usr/bin/pmset", "sleepnow", NULL};
	T_ASSERT_POSIX_ZERO((spawn_ret = posix_spawn(&pid, pmset2_args[0], NULL, NULL, pmset2_args, environ)), NULL);

	T_ASSERT_EQ(waitpid(pid, &spawn_ret, 0), pid, "waitpid failed");
	T_ASSERT_EQ(spawn_ret, 0, "pmset relative wait 5 failed");

	// wait for device to sleep (up to 30 seconds)
	for(int i = 0; i < 30; i++) {
		update(&abs_now, &cnt_now);
		after_diff = (int)(to_ms(cnt_now) - to_ms(abs_now));

		// on OSX, there's enough latency between calls to MCT and MAT
		// when the system is going down for sleep for values to diverge a few ms
		if(abs(before_diff - after_diff) > 2) {
			break;
		}

		sleep(1);
		T_LOG("waited %d seconds for sleep...", i+1);
	}

	if((after_diff - before_diff) < 4000) {
		T_LOG("Device slept for less than 4 seconds, did it really sleep? (%d ms change between abs and cont)",
			after_diff - before_diff);
	}

	time_t after_sleep = time(NULL);

	int cal_sleep_diff  = (int)(double)difftime(after_sleep, before_sleep);
	int ct_sleep_diff = ((int)to_ms(cnt_now) - ct_ms_before_sleep)/1000;
	int ab_sleep_diff = ((int)to_ms(abs_now) - ab_ms_before_sleep)/1000;

	T_LOG("Calendar progressed: %d sec; continuous time progressed: %d sec; absolute time progressed %d sec",
		cal_sleep_diff, ct_sleep_diff, ab_sleep_diff);

	T_ASSERT_LE(abs(ct_sleep_diff - cal_sleep_diff), 2,
		"continuous time should progress at ~ same rate as calendar");
}

T_DECL(mct_settimeofday, "Testing mach_continuous_time behavior over settimeofday"){
	if (geteuid() != 0){
		T_SKIP("The settimeofday() test requires root privileges to run.");
	}
	mach_timebase_info(&tb_info);

	struct timeval saved_tv;
	struct timezone saved_tz;
	int before, after;

	T_ASSERT_POSIX_ZERO(gettimeofday(&saved_tv, &saved_tz), NULL);

	struct timeval forward_tv = saved_tv;
	// move time forward by two minutes, ensure mach_continuous_time keeps
	// chugging along with mach_absolute_time
	forward_tv.tv_sec += 2*60;

	before = (int)to_ms(mach_continuous_time());
	T_ASSERT_POSIX_ZERO(settimeofday(&forward_tv, &saved_tz), NULL);

	after = (int)to_ms(mach_continuous_time());
	T_ASSERT_POSIX_ZERO(settimeofday(&saved_tv, &saved_tz), NULL);

	T_ASSERT_LT(abs(before - after), 1000, "mach_continuous_time should not jump more than 1s");
}

T_DECL(mct_aproximate, "Testing mach_continuous_approximate_time()",
		T_META_ALL_VALID_ARCHS(true))
{
	mach_timebase_info(&tb_info);

	uint64_t absolute = to_ns(mach_continuous_time());
	uint64_t approximate = to_ns(mach_continuous_approximate_time());

	T_EXPECT_LE(llabs((long long)absolute - (long long)approximate), (long long)(25*NSEC_PER_MSEC), NULL);
}
