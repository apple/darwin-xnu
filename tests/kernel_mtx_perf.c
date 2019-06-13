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
#define TEST_MTX_MAX_STATS 		8

#define TEST_MTX_LOCK_STATS 		0
#define TEST_MTX_UNLOCK_MTX_STATS 	6

static void
test_from_kernel_lock_unlock_contended(void)
{
	int i, ret, name_size;
	uint64_t avg, run, tot;
	size_t size;
	char iter[35];
	char *buff, *buff_p, *avg_p, *name, *end_name;

	T_LOG("Testing locking/unlocking mutex from kernel with contention.\n");
	T_LOG("Requesting test with %d iterations\n", ITER);

	size = 1000;
	buff = calloc(size, sizeof(char));
	T_QUIET;T_ASSERT_NOTNULL(buff, "Allocating buffer fo sysctl");

	snprintf(iter, sizeof(iter), "%d", ITER);
	ret = sysctlbyname("kern.test_mtx_contended", buff, &size, iter, sizeof(iter));
	T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname kern.test_mtx_contended");

	T_LOG("%s stats:\n%s\n", __func__, buff);

	/* first line is "STATS INNER LOOP" */
	buff_p = buff;
	while( *buff_p != '\n' ) buff_p++;
	buff_p++;

	/*
	 * Sequence of statistic lines like
	 * { samples 100000, tot 3586175 ns, avg 35 ns, max 3997 ns, min 33 ns } TEST_MTX_LOCK_STATS
	 * for all TEST_MTX_MAX_STATS statistics
	 */
	for (i = 0; i < TEST_MTX_MAX_STATS; i++) {
		avg_p = strstr(buff_p, "avg ");

		/* contended test records statistics only for lock/unlock for now */
		if (i == TEST_MTX_LOCK_STATS || i == TEST_MTX_UNLOCK_MTX_STATS ) {
			T_QUIET;T_ASSERT_NOTNULL(avg_p, "contended %i average not found", i);
			sscanf(avg_p, "avg %llu", &avg);

			name = strstr(buff_p, "TEST_MTX_");
			end_name = strstr(buff_p, "_STATS");
			name_size = end_name - name - strlen("TEST_MTX_") + 1;

			char name_string[40];
			char avg_name_string[50];
			char *pre_string = "contended ";
			snprintf(name_string, name_size + strlen(pre_string), "%s%s", pre_string, &name[strlen("TEST_MTX_")]);
			pre_string = "avg contended ";
			snprintf(avg_name_string, name_size + strlen(pre_string), "%s%s", pre_string, &name[strlen("TEST_MTX_")]);
			T_PERF(name_string, avg, "ns", avg_name_string);
		}

		buff_p = avg_p;
		while( *buff_p != '\n' ) buff_p++;
		buff_p++;

	}

	while( *buff_p != '\n' ) buff_p++;
	buff_p++;

	/* next line is "STATS OUTER LOOP" */
	while( *buff_p != '\n' ) buff_p++;
	buff_p++;

	/* contended test records statistics only for lock/unlock for now */
	avg_p = strstr(buff_p, "run time ");
	T_QUIET;T_ASSERT_NOTNULL(avg_p, "contended %d loop run time not found", 0);
	sscanf(avg_p, "run time %llu", &run);

	avg_p = strstr(buff_p, "total time ");
	T_QUIET;T_ASSERT_NOTNULL(avg_p, "uncontended %d loop total time not found", 0);
	sscanf(avg_p, "total time %llu", &tot);

	if (run < tot)
		avg = run;
	else
		avg = tot;

	name = strstr(buff_p, "TEST_MTX_");
	end_name = strstr(buff_p, "_STATS");
	name_size = end_name - name - strlen("TEST_MTX_") + 1;

	char name_string[50];
	char avg_name_string[60];
	char *pre_string = "contended loop ";
	snprintf(name_string, name_size + strlen(pre_string), "%s%s", pre_string, &name[strlen("TEST_MTX_")]);
	pre_string = "avg time contended loop ";
	snprintf(avg_name_string, name_size + strlen(pre_string), "%s%s", pre_string, &name[strlen("TEST_MTX_")]);
	T_PERF(name_string, avg/ITER, "ns", avg_name_string);

	free(buff);
}

static void
test_from_kernel_lock_unlock_uncontended(void)
{
	int i, ret, name_size;
	uint64_t avg, run, tot;
	size_t size;
	char iter[35];
	char *buff, *buff_p, *avg_p, *name, *end_name;

	T_LOG("Testing locking/unlocking mutex from kernel without contention.\n");
	T_LOG("Requesting test with %d iterations\n", ITER);

	size = 2000;
	buff = calloc(size, sizeof(char));
	T_QUIET;T_ASSERT_NOTNULL(buff, "Allocating buffer fo sysctl");

	snprintf(iter, sizeof(iter), "%d", ITER);
	ret = sysctlbyname("kern.test_mtx_uncontended", buff, &size, iter, sizeof(iter));
	T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname kern.test_mtx_uncontended");

	T_LOG("%s stats:\n%s\n", __func__, buff);

	/* first line is "STATS INNER LOOP" */
	buff_p = buff;
	while( *buff_p != '\n' ) buff_p++;
	buff_p++;

	/*
	 * Sequence of statistic lines like
	 * { samples 100000, tot 3586175 ns, avg 35 ns, max 3997 ns, min 33 ns } TEST_MTX_LOCK_STATS
	 * for all TEST_MTX_MAX_STATS statistics
	 */
	for (i = 0; i < TEST_MTX_MAX_STATS; i++) {
		avg_p = strstr(buff_p, "avg ");
		T_QUIET;T_ASSERT_NOTNULL(avg_p, "uncontended %i average not found", i);
		sscanf(avg_p, "avg %llu", &avg);

		name = strstr(buff_p, "TEST_MTX_");
		end_name = strstr(buff_p, "_STATS");
		name_size = end_name - name - strlen("TEST_MTX_") + 1;

		char name_string[40];
		char avg_name_string[50];
		char *pre_string = "uncontended ";
		snprintf(name_string, name_size + strlen(pre_string), "%s%s", pre_string, &name[strlen("TEST_MTX_")]);
		pre_string = "avg time uncontended ";
		snprintf(avg_name_string, name_size + strlen(pre_string), "%s%s", pre_string, &name[strlen("TEST_MTX_")]);
		T_PERF(name_string, avg, "ns", avg_name_string);

		buff_p = avg_p;
		while( *buff_p != '\n' ) buff_p++;
		buff_p++;
	}

	while( *buff_p != '\n' ) buff_p++;
	buff_p++;

	/* next line is "STATS OUTER LOOP" */
	while( *buff_p != '\n' ) buff_p++;
	buff_p++;

	/*
	 * Sequence of statistic lines like
	 * total time 4040673 ns total run time 3981080 ns TEST_MTX_LOCK_STATS
	 * for all TEST_MTX_MAX_STATS statistics exept UNLOCK
	 */
	for (i = 0; i < TEST_MTX_MAX_STATS - 2; i++) {
		avg_p = strstr(buff_p, "run time ");
		T_QUIET;T_ASSERT_NOTNULL(avg_p, "uncontended %d loop run time not found", i);
		sscanf(avg_p, "run time %llu", &run);

		avg_p = strstr(buff_p, "total time ");
		T_QUIET;T_ASSERT_NOTNULL(avg_p, "uncontended %d loop total time not found", i);
		sscanf(avg_p, "total time %llu", &tot);

		if (run < tot)
			avg = run;
		else
			avg = tot;

		name = strstr(buff_p, "TEST_MTX_");
		end_name = strstr(buff_p, "_STATS");
		name_size = end_name - name - strlen("TEST_MTX_") + 1;

		char name_string[50];
		char avg_name_string[60];
		char *pre_string = "uncontended loop ";
		snprintf(name_string, name_size + strlen(pre_string), "%s%s", pre_string, &name[strlen("TEST_MTX_")]);
		pre_string = "avg time uncontended loop ";
		snprintf(avg_name_string, name_size + strlen(pre_string), "%s%s", pre_string, &name[strlen("TEST_MTX_")]);
		T_PERF(name_string, avg/ITER, "ns", avg_name_string);

		buff_p = avg_p;
		while( *buff_p != '\n' ) buff_p++;
		buff_p++;

	}
	free(buff);
}

extern char **environ;
static void
fix_cpu_frequency(void)
{
#if CONFIG_EMBEDDED
	int spawn_ret, pid;
	char *const clpcctrl_args[] = {"/usr/local/bin/clpcctrl", "-f", "5000", NULL};

	T_LOG("Setting cpu frequency to %d\n", 5000);

	spawn_ret = posix_spawn(&pid, clpcctrl_args[0], NULL, NULL, clpcctrl_args, environ);
	waitpid(pid, &spawn_ret, 0);

#else /*CONFIG_EMBEDDED*/

	int spawn_ret, pid;
	int ret, nom_freq;
	size_t len;
	float val;
	char scale;
	char *buffer, *cpu_freq;
	char str_val[10];

	ret = sysctlbyname("machdep.cpu.brand_string", NULL, &len, NULL, 0);
	T_QUIET;T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname machdep.cpu.brand_string");

	buffer = malloc(len+2);
	ret = sysctlbyname("machdep.cpu.brand_string", buffer, &len, NULL, 0);
	T_QUIET;T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname machdep.cpu.brand_string");
	buffer[len+1] = '\0';

	cpu_freq = strstr(buffer, "CPU @ ");
	if (cpu_freq == NULL) {
		T_LOG("Could not fix frequency, %s field not present\n", "CPU @ ");
		goto out;
	}

	if (strstr(cpu_freq, "Hz") != NULL) {
		sscanf(cpu_freq, "CPU @ %f%cHz", &val, &scale);
	} else {
		if (strstr(cpu_freq, "hz") != NULL) {
			sscanf(cpu_freq, "CPU @ %f%chz", &val, &scale);
		} else {
			T_LOG("Could not fix frequency, %s field not present\n", "Hz");
			goto out;
		}
	}

	switch(scale){
	case 'M':
	case 'm':
		nom_freq = (int) val;
		break;
	case 'G':
	case 'g':
		nom_freq = (int) (val*1000);
		break;
	default:
		T_LOG("Could not fix frequency, scale field is %c\n", scale);
		goto out;
	}

	snprintf(str_val, 10, "%d", nom_freq);
	T_LOG("Setting min and max cpu frequency to %d (%s)\n", nom_freq, str_val);
	char *xcpm_args[] = {"/usr/local/bin/xcpm", "limits", str_val, str_val, NULL};
	spawn_ret = posix_spawn(&pid, xcpm_args[0], NULL, NULL, xcpm_args, environ);
	waitpid(pid, &spawn_ret, 0);

out:
	free(buffer);
	return;
#endif /*CONFIG_EMBEDDED*/
}

T_DECL(kernel_mtx_perf_test,
	"Kernel mutex performance test",
	T_META_ASROOT(YES), T_META_CHECK_LEAKS(NO))
{
	fix_cpu_frequency();

	test_from_kernel_lock_unlock_uncontended();
	test_from_kernel_lock_unlock_contended();
}

