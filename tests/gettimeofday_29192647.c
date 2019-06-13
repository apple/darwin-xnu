#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <mach/mach_time.h>
#include <sys/time.h>

#include <darwintest.h>
#include <darwintest_perf.h>

T_GLOBAL_META(T_META_TAG_PERF);

T_DECL(gettimeofday_tl, "gettimeofday performance in tight loop") {
	{
		struct timeval time;
		dt_stat_time_t s = dt_stat_time_create("gettimeofday tight loop");
		T_STAT_MEASURE_LOOP(s){
			gettimeofday(&time, NULL);
		}
		dt_stat_finalize(s);
	}
}

extern int __gettimeofday(struct timeval *, struct timezone *);
T_DECL(__gettimeofday_tl, "__gettimeofday performance in tight loop") {
	{
		struct timeval time;

		dt_stat_time_t s = dt_stat_time_create("__gettimeofday tight loop");
		T_STAT_MEASURE_LOOP(s){
			__gettimeofday(&time, NULL);
		}
		dt_stat_finalize(s);
	}
}

T_DECL(gettimeofday_sl, "gettimeofday performance in loop with sleep") {
	{
		struct timeval time;
		dt_stat_time_t s = dt_stat_time_create("gettimeofday loop with sleep");
		while (!dt_stat_stable(s)) {
			T_STAT_MEASURE_BATCH(s){
				gettimeofday(&time, NULL);
			}
			sleep(1);
		}
		dt_stat_finalize(s);
	}
}
