#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif

#include <darwintest.h>
#include <darwintest_multiprocess.h>
#include <darwintest_utils.h>
#include <pthread.h>
#include <launch.h>
#include <servers/bootstrap.h>
#include <stdlib.h>
#include <sys/event.h>
#include <unistd.h>
#include <crt_externs.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <spawn.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.kernel_mtx_perf_test"));

#define ITER 100000
#define TEST_MTX_MAX_STATS              8
#define FULL_CONTENDED 0
#define HALF_CONTENDED 1
#define MAX_CONDENDED  2


#define TEST_MTX_LOCK_STATS             0
#define TEST_MTX_UNLOCK_MTX_STATS       6

static void
test_from_kernel_lock_unlock_contended(void)
{
	int i, ret;
	unsigned long name_size;
	uint64_t avg, run, tot;
	size_t size;
	char iter[35];
	char *buff, *buff_p, *avg_p, *name, *end_name;

	T_LOG("Testing locking/unlocking mutex from kernel with contention.\n");
	T_LOG("Requesting test with %d iterations\n", ITER);

	size = 2000;
	buff = calloc(size, sizeof(char));
	T_QUIET; T_ASSERT_NOTNULL(buff, "Allocating buffer fo sysctl");

	snprintf(iter, sizeof(iter), "%d", ITER);
	ret = sysctlbyname("kern.test_mtx_contended", buff, &size, iter, sizeof(iter));
	T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname kern.test_mtx_contended");

	T_LOG("\n%s stats :\n%s\n", __func__, buff);

	buff_p = buff;
	int t;
	for (t = 0; t < MAX_CONDENDED; t++) {
		char *type;
		if (t == FULL_CONTENDED) {
			type = "FULL_CONTENDED ";
		} else {
			type = "HALF_CONTENDED ";
		}

		/* first line is "STATS INNER LOOP" */
		while (*buff_p != '\n') {
			buff_p++;
		}
		buff_p++;

		/*
		 * Sequence of statistic lines like
		 * { samples 100000, tot 3586175 ns, avg 35 ns, max 3997 ns, min 33 ns } TEST_MTX_LOCK_STATS
		 * for all TEST_MTX_MAX_STATS statistics
		 */
		for (i = 0; i < TEST_MTX_MAX_STATS; i++) {
			avg_p = strstr(buff_p, "avg ");

			/* contended test records statistics only for lock/unlock for now */
			if (i == TEST_MTX_LOCK_STATS || i == TEST_MTX_UNLOCK_MTX_STATS) {
				T_QUIET; T_ASSERT_NOTNULL(avg_p, "contended %i average not found", i);
				sscanf(avg_p, "avg %llu", &avg);

				name = strstr(buff_p, "TEST_MTX_");
				end_name = strstr(buff_p, "_STATS");
				name_size = (unsigned long) end_name - (unsigned long) name - strlen("TEST_MTX_") + 1;

				char name_string[40];
				char avg_name_string[50];
				char *pre_string = "contended ";
				snprintf(name_string, name_size + strlen(pre_string) + strlen(type), "%s%s%s", pre_string, type, &name[strlen("TEST_MTX_")]);
				pre_string = "avg contended ";
				snprintf(avg_name_string, name_size + strlen(pre_string) + strlen(type), "%s%s%s", pre_string, type, &name[strlen("TEST_MTX_")]);
				T_PERF(name_string, avg, "ns", avg_name_string);
			}

			buff_p = avg_p;
			while (*buff_p != '\n') {
				buff_p++;
			}
			buff_p++;
		}

		while (*buff_p != '\n') {
			buff_p++;
		}
		buff_p++;

		/* next line is "STATS OUTER LOOP" */
		while (*buff_p != '\n') {
			buff_p++;
		}
		buff_p++;

		/* contended test records statistics only for lock/unlock for now */
		avg_p = strstr(buff_p, "run time ");
		T_QUIET; T_ASSERT_NOTNULL(avg_p, "contended %d loop run time not found", 0);
		sscanf(avg_p, "run time %llu", &run);

		avg_p = strstr(buff_p, "total time ");
		T_QUIET; T_ASSERT_NOTNULL(avg_p, "uncontended %d loop total time not found", 0);
		sscanf(avg_p, "total time %llu", &tot);

		if (run < tot) {
			avg = run;
		} else {
			avg = tot;
		}

		name = strstr(buff_p, "TEST_MTX_");
		end_name = strstr(buff_p, "_STATS");
		name_size = (unsigned long) end_name - (unsigned long) name - strlen("TEST_MTX_") + 1;

		char name_string[50];
		char avg_name_string[60];
		char *pre_string = "contended loop ";
		snprintf(name_string, name_size + strlen(pre_string) + strlen(type), "%s%s%s", pre_string, type, &name[strlen("TEST_MTX_")]);
		pre_string = "avg time contended loop ";
		snprintf(avg_name_string, name_size + strlen(pre_string) + strlen(type), "%s%s%s", pre_string, type, &name[strlen("TEST_MTX_")]);
		T_PERF(name_string, avg / ITER, "ns", avg_name_string);
	}

	free(buff);
}

static void
test_from_kernel_lock_unlock_uncontended(void)
{
	int i, ret;
	unsigned long name_size;
	uint64_t avg, run, tot;
	size_t size;
	char iter[35];
	char *buff, *buff_p, *avg_p, *name, *end_name;

	T_LOG("Testing locking/unlocking mutex from kernel without contention.\n");
	T_LOG("Requesting test with %d iterations\n", ITER);

	size = 2000;
	buff = calloc(size, sizeof(char));
	T_QUIET; T_ASSERT_NOTNULL(buff, "Allocating buffer fo sysctl");

	snprintf(iter, sizeof(iter), "%d", ITER);
	ret = sysctlbyname("kern.test_mtx_uncontended", buff, &size, iter, sizeof(iter));
	T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname kern.test_mtx_uncontended");

	T_LOG("%s stats:\n%s\n", __func__, buff);

	/* first line is "STATS INNER LOOP" */
	buff_p = buff;
	while (*buff_p != '\n') {
		buff_p++;
	}
	buff_p++;

	/*
	 * Sequence of statistic lines like
	 * { samples 100000, tot 3586175 ns, avg 35 ns, max 3997 ns, min 33 ns } TEST_MTX_LOCK_STATS
	 * for all TEST_MTX_MAX_STATS statistics
	 */
	for (i = 0; i < TEST_MTX_MAX_STATS; i++) {
		avg_p = strstr(buff_p, "avg ");
		T_QUIET; T_ASSERT_NOTNULL(avg_p, "uncontended %i average not found", i);
		sscanf(avg_p, "avg %llu", &avg);

		name = strstr(buff_p, "TEST_MTX_");
		end_name = strstr(buff_p, "_STATS");
		name_size = (unsigned long) end_name - (unsigned long) name - strlen("TEST_MTX_") + 1;

		char name_string[40];
		char avg_name_string[50];
		char *pre_string = "uncontended ";
		snprintf(name_string, name_size + strlen(pre_string), "%s%s", pre_string, &name[strlen("TEST_MTX_")]);
		pre_string = "avg time uncontended ";
		snprintf(avg_name_string, name_size + strlen(pre_string), "%s%s", pre_string, &name[strlen("TEST_MTX_")]);
		T_PERF(name_string, avg, "ns", avg_name_string);

		buff_p = avg_p;
		while (*buff_p != '\n') {
			buff_p++;
		}
		buff_p++;
	}

	while (*buff_p != '\n') {
		buff_p++;
	}
	buff_p++;

	/* next line is "STATS OUTER LOOP" */
	while (*buff_p != '\n') {
		buff_p++;
	}
	buff_p++;

	/*
	 * Sequence of statistic lines like
	 * total time 4040673 ns total run time 3981080 ns TEST_MTX_LOCK_STATS
	 * for all TEST_MTX_MAX_STATS statistics exept UNLOCK
	 */
	for (i = 0; i < TEST_MTX_MAX_STATS - 2; i++) {
		avg_p = strstr(buff_p, "run time ");
		T_QUIET; T_ASSERT_NOTNULL(avg_p, "uncontended %d loop run time not found", i);
		sscanf(avg_p, "run time %llu", &run);

		avg_p = strstr(buff_p, "total time ");
		T_QUIET; T_ASSERT_NOTNULL(avg_p, "uncontended %d loop total time not found", i);
		sscanf(avg_p, "total time %llu", &tot);

		if (run < tot) {
			avg = run;
		} else {
			avg = tot;
		}

		name = strstr(buff_p, "TEST_MTX_");
		end_name = strstr(buff_p, "_STATS");
		name_size = (unsigned long) end_name - (unsigned long) name - strlen("TEST_MTX_") + 1;

		char name_string[50];
		char avg_name_string[60];
		char *pre_string = "uncontended loop ";
		snprintf(name_string, name_size + strlen(pre_string), "%s%s", pre_string, &name[strlen("TEST_MTX_")]);
		pre_string = "avg time uncontended loop ";
		snprintf(avg_name_string, name_size + strlen(pre_string), "%s%s", pre_string, &name[strlen("TEST_MTX_")]);
		T_PERF(name_string, avg / ITER, "ns", avg_name_string);

		buff_p = avg_p;
		while (*buff_p != '\n') {
			buff_p++;
		}
		buff_p++;
	}
	free(buff);
}

#if !(TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR)
static bool
get_freq(float val, char scale, int *int_val)
{
	switch (scale) {
	case 'M':
	case 'm':
		*int_val = (int) val;
		break;
	case 'G':
	case 'g':
		*int_val = (int) (val * 1000);
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

static bool
parse_freq(char* buff, int buff_size, const char* string_start, int string_start_size, char* to_parse)
{
	char* start;
	float val;
	char scale;
	int int_val;

	start = strstr(to_parse, string_start);
	if (start == NULL) {
		return FALSE;
	}

	if (strstr(start, "Hz") != NULL) {
		sscanf(start + string_start_size, "%f%cHz", &val, &scale);
	} else {
		if (strstr(start, "hz") != NULL) {
			sscanf(start + string_start_size, "%f%chz", &val, &scale);
		} else {
			return FALSE;
		}
	}

	if (!get_freq(val, scale, &int_val)) {
		return FALSE;
	}

	snprintf(buff, buff_size, "%d", int_val);

	return TRUE;
}

static bool freq_fixed = FALSE;
static char str_val_min[10];
static char str_val_max[10];

static bool
get_previous_freq_values(void)
{
	FILE *fp;
	char out_xcpm[1035];
	bool min_scan = FALSE;
	bool max_scan = FALSE;

	memset(str_val_min, 0, sizeof(str_val_min));
	memset(str_val_max, 0, sizeof(str_val_max));

	fp = popen("/usr/local/bin/xcpm limits", "r");
	if (fp == NULL) {
		return FALSE;
	}

	while (fgets(out_xcpm, sizeof(out_xcpm) - 1, fp) != NULL && (!max_scan || !min_scan)) {
		if (!max_scan) {
			max_scan = parse_freq(str_val_max, sizeof(str_val_max), "Max frequency:", sizeof("Max frequency:"), out_xcpm);
		}
		if (!min_scan) {
			min_scan = parse_freq(str_val_min, sizeof(str_val_min), "Min frequency:", sizeof("Min frequency:"), out_xcpm);
		}
	}

	pclose(fp);

	if (!max_scan || !min_scan) {
		return FALSE;
	}

	return TRUE;
}
#endif

static void
fix_cpu_frequency(void)
{
#if (TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR)
	int spawn_ret, pid;
	char *const clpcctrl_args[] = {"/usr/local/bin/clpcctrl", "-f", "5000", NULL};

	T_LOG("Setting cpu frequency to %d\n", 5000);

	spawn_ret = posix_spawn(&pid, clpcctrl_args[0], NULL, NULL, clpcctrl_args, *_NSGetEnviron());
	T_QUIET; T_ASSERT_POSIX_ZERO(spawn_ret, "posix_spawn");
	T_QUIET; T_ASSERT_EQ(waitpid(pid, &spawn_ret, 0), pid, "waitpid failed");
	T_QUIET; T_ASSERT_EQ(spawn_ret, 0, " clpcctrl failed");

#else /*(TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR)*/

	int spawn_ret, pid;
	int ret;
	size_t len;
	char *buffer;
	char str_val[10];

	if (!get_previous_freq_values()) {
		T_LOG("Impossible to parse freq values from xcpm");
		freq_fixed = FALSE;
		return;
	}

	ret = sysctlbyname("machdep.cpu.brand_string", NULL, &len, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname machdep.cpu.brand_string");

	buffer = calloc(len + 2, sizeof(char));
	ret = sysctlbyname("machdep.cpu.brand_string", buffer, &len, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname machdep.cpu.brand_string");
	buffer[len + 1] = '\0';

	memset(str_val, 0, sizeof(str_val));
	if (!parse_freq(str_val, sizeof(str_val), "CPU @", sizeof("CPU @"), buffer)) {
		T_LOG("Impossible to parse freq values from machdep.cpu.brand_string (string was %s)", buffer);
		freq_fixed = FALSE;
		return;
	}

	T_LOG("Previous min and max cpu frequency (%s) (%s)\n", str_val_min, str_val_max);
	T_LOG("Setting min and max cpu frequency to (%s)\n", str_val);
	char *xcpm_args[] = {"/usr/local/bin/xcpm", "limits", str_val, str_val, NULL};
	spawn_ret = posix_spawn(&pid, xcpm_args[0], NULL, NULL, xcpm_args, *_NSGetEnviron());
	T_QUIET; T_ASSERT_POSIX_ZERO(spawn_ret, "posix_spawn");
	T_QUIET; T_ASSERT_EQ(waitpid(pid, &spawn_ret, 0), pid, "waitpid failed");
	T_QUIET; T_ASSERT_EQ(spawn_ret, 0, "xcpm limits failed");

	freq_fixed = TRUE;

	free(buffer);
	return;
#endif /*(TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR)*/
}

static void
cleanup_cpu_freq(void)
{
#if (TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR)
	int spawn_ret, pid;
	char *const clpcctrl_args[] = {"/usr/local/bin/clpcctrl", "-d", NULL};
	spawn_ret = posix_spawn(&pid, clpcctrl_args[0], NULL, NULL, clpcctrl_args, *_NSGetEnviron());
	T_QUIET; T_ASSERT_POSIX_ZERO(spawn_ret, "posix_spawn");
	T_QUIET; T_ASSERT_EQ(waitpid(pid, &spawn_ret, 0), pid, "waitpid failed");
	T_QUIET; T_ASSERT_EQ(spawn_ret, 0, "clpcctrl failed");

#else
	if (freq_fixed) {
		int spawn_ret, pid;
		char *xcpm_args[] = {"/usr/local/bin/xcpm", "limits", str_val_min, str_val_max, NULL};
		spawn_ret = posix_spawn(&pid, xcpm_args[0], NULL, NULL, xcpm_args, *_NSGetEnviron());
		T_QUIET; T_ASSERT_POSIX_ZERO(spawn_ret, "posix_spawn");
		T_QUIET; T_ASSERT_EQ(waitpid(pid, &spawn_ret, 0), pid, "waitpid failed");
		T_QUIET; T_ASSERT_EQ(spawn_ret, 0, "xcpm limits failed");
	}
#endif
}

T_DECL(kernel_mtx_perf_test,
    "Kernel mutex performance test",
    T_META_ASROOT(YES), T_META_CHECK_LEAKS(NO))
{
	fix_cpu_frequency();

	T_ATEND(cleanup_cpu_freq);

	test_from_kernel_lock_unlock_uncontended();
	test_from_kernel_lock_unlock_contended();
}
