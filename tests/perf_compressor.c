#include <stdio.h>
#include <signal.h>
#include <sys/sysctl.h>
#include <mach-o/dyld.h>
#include <perfcheck_keys.h>

#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif
#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm.perf"),
	T_META_CHECK_LEAKS(false),
	T_META_TAG_PERF
	);

enum {
	ALL_ZEROS,
	MOSTLY_ZEROS,
	RANDOM,
	TYPICAL
};

#define CREATE_LIST(X) \
	X(SUCCESS) \
	X(TOO_FEW_ARGUMENTS) \
	X(SYSCTL_VM_PAGESIZE_FAILED) \
	X(VM_PAGESIZE_IS_ZERO) \
	X(UNKNOWN_PAGE_TYPE) \
	X(DISPATCH_SOURCE_CREATE_FAILED) \
	X(INITIAL_SIGNAL_TO_PARENT_FAILED) \
	X(SIGNAL_TO_PARENT_FAILED) \
	X(EXIT_CODE_MAX)

#define EXIT_CODES_ENUM(VAR) VAR,
enum exit_codes_num {
	CREATE_LIST(EXIT_CODES_ENUM)
};

#define EXIT_CODES_STRING(VAR) #VAR,
static const char *exit_codes_str[] = {
	CREATE_LIST(EXIT_CODES_STRING)
};

#define SYSCTL_FREEZE_TO_MEMORY         "kern.memorystatus_freeze_to_memory=1"

static pid_t pid = -1;
static dt_stat_t r;
static dt_stat_time_t s;

void allocate_zero_pages(char **buf, int num_pages, int vmpgsize);
void allocate_mostly_zero_pages(char **buf, int num_pages, int vmpgsize);
void allocate_random_pages(char **buf, int num_pages, int vmpgsize);
void allocate_representative_pages(char **buf, int num_pages, int vmpgsize);
void run_compressor_test(int size_mb, int page_type);
void freeze_helper_process(void);
void cleanup(void);

void
allocate_zero_pages(char **buf, int num_pages, int vmpgsize)
{
	int i;

	for (i = 0; i < num_pages; i++) {
		buf[i] = (char*)malloc((size_t)vmpgsize * sizeof(char));
		memset(buf[i], 0, vmpgsize);
	}
}

void
allocate_mostly_zero_pages(char **buf, int num_pages, int vmpgsize)
{
	int i, j;

	for (i = 0; i < num_pages; i++) {
		buf[i] = (char*)malloc((size_t)vmpgsize * sizeof(char));
		memset(buf[i], 0, vmpgsize);
		for (j = 0; j < 40; j++) {
			buf[i][j] = (char)(j + 1);
		}
	}
}

void
allocate_random_pages(char **buf, int num_pages, int vmpgsize)
{
	int i;

	for (i = 0; i < num_pages; i++) {
		buf[i] = (char*)malloc((size_t)vmpgsize * sizeof(char));
		arc4random_buf((void*)buf[i], (size_t)vmpgsize);
	}
}

// Gives us the compression ratio we see in the typical case (~2.7)
void
allocate_representative_pages(char **buf, int num_pages, int vmpgsize)
{
	int i, j;
	char val;

	for (j = 0; j < num_pages; j++) {
		buf[j] = (char*)malloc((size_t)vmpgsize * sizeof(char));
		val = 0;
		for (i = 0; i < vmpgsize; i += 16) {
			memset(&buf[j][i], val, 16);
			if (i < 3400 * (vmpgsize / 4096)) {
				val++;
			}
		}
	}
}

void
freeze_helper_process(void)
{
	int ret, freeze_enabled;
	int64_t compressed_before, compressed_after, input_before, input_after;
	size_t length;
	int errno_sysctl_freeze;

	length = sizeof(compressed_before);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctlbyname("vm.compressor_compressed_bytes", &compressed_before, &length, NULL, 0),
	    "failed to query vm.compressor_compressed_bytes");
	length = sizeof(input_before);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctlbyname("vm.compressor_input_bytes", &input_before, &length, NULL, 0),
	    "failed to query vm.compressor_input_bytes");

	T_STAT_MEASURE(s) {
		ret = sysctlbyname("kern.memorystatus_freeze", NULL, NULL, &pid, sizeof(pid));
		errno_sysctl_freeze = errno;
	};

	length = sizeof(compressed_after);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctlbyname("vm.compressor_compressed_bytes", &compressed_after, &length, NULL, 0),
	    "failed to query vm.compressor_compressed_bytes");
	length = sizeof(input_after);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctlbyname("vm.compressor_input_bytes", &input_after, &length, NULL, 0),
	    "failed to query vm.compressor_input_bytes");

	length = sizeof(freeze_enabled);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctlbyname("vm.freeze_enabled", &freeze_enabled, &length, NULL, 0),
	    "failed to query vm.freeze_enabled");
	if (freeze_enabled) {
		errno = errno_sysctl_freeze;
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl kern.memorystatus_freeze failed");
	} else {
		/* If freezer is disabled, skip the test. This can happen due to disk space shortage. */
		T_LOG("Freeze has been disabled. Terminating early.");
		T_END;
	}

	dt_stat_add(r, (double)(input_after - input_before) / (double)(compressed_after - compressed_before));

	ret = sysctlbyname("kern.memorystatus_thaw", NULL, NULL, &pid, sizeof(pid));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl kern.memorystatus_thaw failed");

	T_QUIET; T_ASSERT_POSIX_SUCCESS(kill(pid, SIGUSR1), "failed to send SIGUSR1 to child process");
}

void
cleanup(void)
{
	int status = 0;

	/* No helper process. */
	if (pid == -1) {
		return;
	}
	/* Kill the helper process. */
	kill(pid, SIGKILL);
}

void
run_compressor_test(int size_mb, int page_type)
{
	int ret;
	char sz_str[50];
	char pt_str[50];
	char **launch_tool_args;
	char testpath[PATH_MAX];
	uint32_t testpath_buf_size;
	dispatch_source_t ds_freeze, ds_proc;
	int freeze_enabled;
	size_t length;

	length = sizeof(freeze_enabled);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctlbyname("vm.freeze_enabled", &freeze_enabled, &length, NULL, 0),
	    "failed to query vm.freeze_enabled");
	if (!freeze_enabled) {
		/* If freezer is disabled, skip the test. This can happen due to disk space shortage. */
		T_SKIP("Freeze has been disabled. Skipping test.");
	}

	T_ATEND(cleanup);

	r = dt_stat_create("(input bytes / compressed bytes)", "compression_ratio");
	s = dt_stat_time_create("compressor_latency");
	// This sets the A/B failure threshold at 50% of baseline for compressor_latency
	dt_stat_set_variable(s, kPCFailureThresholdPctVar, 50.0);

	signal(SIGUSR1, SIG_IGN);
	ds_freeze = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, dispatch_get_main_queue());
	T_QUIET; T_ASSERT_NOTNULL(ds_freeze, "dispatch_source_create (ds_freeze)");

	dispatch_source_set_event_handler(ds_freeze, ^{
		if (!dt_stat_stable(s)) {
		        freeze_helper_process();
		} else {
		        dt_stat_finalize(s);
		        dt_stat_finalize(r);

		        kill(pid, SIGKILL);
		        dispatch_source_cancel(ds_freeze);
		}
	});
	dispatch_activate(ds_freeze);

	testpath_buf_size = sizeof(testpath);
	ret = _NSGetExecutablePath(testpath, &testpath_buf_size);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "_NSGetExecutablePath");
	T_LOG("Executable path: %s", testpath);

	sprintf(sz_str, "%d", size_mb);
	sprintf(pt_str, "%d", page_type);
	launch_tool_args = (char *[]){
		testpath,
		"-n",
		"allocate_pages",
		"--",
		sz_str,
		pt_str,
		NULL
	};

	/* Spawn the child process. Suspend after launch until the exit proc handler has been set up. */
	ret = dt_launch_tool(&pid, launch_tool_args, true, NULL, NULL);
	if (ret != 0) {
		T_LOG("dt_launch tool returned %d with error code %d", ret, errno);
	}
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pid, "dt_launch_tool");

	ds_proc = dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC, (uintptr_t)pid, DISPATCH_PROC_EXIT, dispatch_get_main_queue());
	T_QUIET; T_ASSERT_NOTNULL(ds_proc, "dispatch_source_create (ds_proc)");

	dispatch_source_set_event_handler(ds_proc, ^{
		int status = 0, code = 0;
		pid_t rc = waitpid(pid, &status, 0);
		T_QUIET; T_ASSERT_EQ(rc, pid, "waitpid");
		code = WEXITSTATUS(status);

		if (code == 0) {
		        T_END;
		} else if (code > 0 && code < EXIT_CODE_MAX) {
		        T_ASSERT_FAIL("Child exited with %s", exit_codes_str[code]);
		} else {
		        T_ASSERT_FAIL("Child exited with unknown exit code %d", code);
		}
	});
	dispatch_activate(ds_proc);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(kill(pid, SIGCONT), "failed to send SIGCONT to child process");
	dispatch_main();
}

T_HELPER_DECL(allocate_pages, "allocates pages to compress") {
	int i, j, ret, size_mb, page_type, vmpgsize;
	size_t vmpgsize_length;
	__block int num_pages;
	__block char **buf;
	dispatch_source_t ds_signal;

	vmpgsize_length = sizeof(vmpgsize);
	ret = sysctlbyname("vm.pagesize", &vmpgsize, &vmpgsize_length, NULL, 0);
	if (ret != 0) {
		exit(SYSCTL_VM_PAGESIZE_FAILED);
	}
	if (vmpgsize == 0) {
		exit(VM_PAGESIZE_IS_ZERO);
	}

	if (argc < 2) {
		exit(TOO_FEW_ARGUMENTS);
	}

	size_mb = atoi(argv[0]);
	page_type = atoi(argv[1]);
	num_pages = size_mb * 1024 * 1024 / vmpgsize;
	buf = (char**)malloc(sizeof(char*) * (size_t)num_pages);

	// Switch on the type of page requested
	switch (page_type) {
	case ALL_ZEROS:
		allocate_zero_pages(buf, num_pages, vmpgsize);
		break;
	case MOSTLY_ZEROS:
		allocate_mostly_zero_pages(buf, num_pages, vmpgsize);
		break;
	case RANDOM:
		allocate_random_pages(buf, num_pages, vmpgsize);
		break;
	case TYPICAL:
		allocate_representative_pages(buf, num_pages, vmpgsize);
		break;
	default:
		exit(UNKNOWN_PAGE_TYPE);
	}

	for (j = 0; j < num_pages; j++) {
		i = buf[j][0];
	}

	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC), dispatch_get_main_queue(), ^{
		/* Signal to the parent that we're done allocating and it's ok to freeze us */
		printf("[%d] Sending initial signal to parent to begin freezing\n", getpid());
		if (kill(getppid(), SIGUSR1) != 0) {
		        exit(INITIAL_SIGNAL_TO_PARENT_FAILED);
		}
	});

	signal(SIGUSR1, SIG_IGN);
	ds_signal = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, dispatch_get_main_queue());
	if (ds_signal == NULL) {
		exit(DISPATCH_SOURCE_CREATE_FAILED);
	}

	dispatch_source_set_event_handler(ds_signal, ^{
		volatile int tmp;

		/* Make sure all the pages are accessed before trying to freeze again */
		for (int x = 0; x < num_pages; x++) {
		        tmp = buf[x][0];
		}
		if (kill(getppid(), SIGUSR1) != 0) {
		        exit(SIGNAL_TO_PARENT_FAILED);
		}
	});
	dispatch_activate(ds_signal);

	dispatch_main();
}

// Numbers for 10MB and above are fairly reproducible. Anything smaller shows a lot of variation.

// Keeping just the 100MB version for iOSMark
#ifndef DT_IOSMARK
T_DECL(compr_10MB_zero,
    "Compression latency for 10MB - zero pages",
    T_META_SYSCTL_INT(SYSCTL_FREEZE_TO_MEMORY)) {
	run_compressor_test(10, ALL_ZEROS);
}

T_DECL(compr_10MB_mostly_zero,
    "Compression latency for 10MB - mostly zero pages",
    T_META_SYSCTL_INT(SYSCTL_FREEZE_TO_MEMORY)) {
	run_compressor_test(10, MOSTLY_ZEROS);
}

T_DECL(compr_10MB_random,
    "Compression latency for 10MB - random pages",
    T_META_SYSCTL_INT(SYSCTL_FREEZE_TO_MEMORY)) {
	run_compressor_test(10, RANDOM);
}

T_DECL(compr_10MB_typical,
    "Compression latency for 10MB - typical pages",
    T_META_SYSCTL_INT(SYSCTL_FREEZE_TO_MEMORY)) {
	run_compressor_test(10, TYPICAL);
}

T_DECL(compr_100MB_zero,
    "Compression latency for 100MB - zero pages",
    T_META_SYSCTL_INT(SYSCTL_FREEZE_TO_MEMORY)) {
	run_compressor_test(100, ALL_ZEROS);
}

T_DECL(compr_100MB_mostly_zero,
    "Compression latency for 100MB - mostly zero pages",
    T_META_SYSCTL_INT(SYSCTL_FREEZE_TO_MEMORY)) {
	run_compressor_test(100, MOSTLY_ZEROS);
}

T_DECL(compr_100MB_random,
    "Compression latency for 100MB - random pages",
    T_META_SYSCTL_INT(SYSCTL_FREEZE_TO_MEMORY)) {
	run_compressor_test(100, RANDOM);
}
#endif

T_DECL(compr_100MB_typical,
    "Compression latency for 100MB - typical pages",
    T_META_SYSCTL_INT(SYSCTL_FREEZE_TO_MEMORY)) {
	run_compressor_test(100, TYPICAL);
}
