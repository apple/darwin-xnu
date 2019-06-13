#include <stdio.h>
#include <signal.h>
#include <sys/sysctl.h>
#include <sys/kern_memorystatus.h>
#include <mach-o/dyld.h>

#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif
#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_CHECK_LEAKS(false)
);

#define MEM_SIZE_MB			10
#define NUM_ITERATIONS		5

#define CREATE_LIST(X) \
	X(SUCCESS) \
	X(TOO_FEW_ARGUMENTS) \
	X(SYSCTL_VM_PAGESIZE_FAILED) \
	X(VM_PAGESIZE_IS_ZERO) \
	X(SYSCTL_VM_FREEZE_ENABLED_FAILED) \
	X(FREEZER_DISABLED) \
	X(DISPATCH_SOURCE_CREATE_FAILED) \
	X(INITIAL_SIGNAL_TO_PARENT_FAILED) \
	X(SIGNAL_TO_PARENT_FAILED) \
	X(MEMORYSTATUS_CONTROL_FAILED) \
	X(IS_FREEZABLE_NOT_AS_EXPECTED) \
	X(MEMSTAT_PRIORITY_CHANGE_FAILED) \
	X(EXIT_CODE_MAX)

#define EXIT_CODES_ENUM(VAR) VAR,
enum exit_codes_num {
	CREATE_LIST(EXIT_CODES_ENUM)
};

#define EXIT_CODES_STRING(VAR) #VAR,
static const char *exit_codes_str[] = {
	CREATE_LIST(EXIT_CODES_STRING)
};


static pid_t pid = -1;
static int freeze_count = 0;

void move_to_idle_band(void);
void run_freezer_test(int size_mb);
void freeze_helper_process(void);


void move_to_idle_band(void) {

	memorystatus_priority_properties_t props;
	/*
	 * Freezing a process also moves it to an elevated jetsam band in order to protect it from idle exits.
	 * So we move the child process to the idle band to mirror the typical 'idle app being frozen' scenario.
	 */
	props.priority = JETSAM_PRIORITY_IDLE;
	props.user_data = 0;

	/*
	 * This requires us to run as root (in the absence of entitlement).
	 * Hence the T_META_ASROOT(true) in the T_HELPER_DECL.
	 */
	if (memorystatus_control(MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES, getpid(), 0, &props, sizeof(props))) {
		exit(MEMSTAT_PRIORITY_CHANGE_FAILED);
	}
}

void freeze_helper_process(void) {
	int ret;

	T_LOG("Freezing child pid %d", pid);
	ret = sysctlbyname("kern.memorystatus_freeze", NULL, NULL, &pid, sizeof(pid));
	sleep(1);

	if (freeze_count % 2 == 0) {
		/*
		 * The child process toggles its freezable state on each iteration.
		 * So a failure for every alternate freeze is expected.
		 */
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl kern.memorystatus_freeze failed");
		T_LOG("Freeze succeeded. Thawing child pid %d", pid);
		ret = sysctlbyname("kern.memorystatus_thaw", NULL, NULL, &pid, sizeof(pid));
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl kern.memorystatus_thaw failed");
	} else {
		T_QUIET; T_ASSERT_TRUE(ret != KERN_SUCCESS, "Freeze should have failed");
		T_LOG("Freeze failed as expected");
	}

	freeze_count++;

	T_QUIET; T_ASSERT_POSIX_SUCCESS(kill(pid, SIGUSR1), "failed to send SIGUSR1 to child process");
}

void run_freezer_test(int size_mb) {
	int ret;
	char sz_str[50];
	char **launch_tool_args;
	char testpath[PATH_MAX];
	uint32_t testpath_buf_size;
	dispatch_source_t ds_freeze, ds_proc;

#ifndef CONFIG_FREEZE
	T_SKIP("Task freeze not supported.");
#endif

	signal(SIGUSR1, SIG_IGN);
	ds_freeze = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, dispatch_get_main_queue());
	T_QUIET; T_ASSERT_NOTNULL(ds_freeze, "dispatch_source_create (ds_freeze)");

	dispatch_source_set_event_handler(ds_freeze, ^{
		if (freeze_count < NUM_ITERATIONS) {
			freeze_helper_process();
		} else {
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
	launch_tool_args = (char *[]){
		testpath,
		"-n",
		"allocate_pages",
		"--",
		sz_str,
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

T_HELPER_DECL(allocate_pages,
		"allocates pages to freeze",
		T_META_ASROOT(true)) {
	int i, j, temp, ret, size_mb, vmpgsize;
	size_t len;
	char val;
	__block int num_pages, num_iter = 0;
	__block char **buf;
	dispatch_source_t ds_signal;

	len = sizeof(vmpgsize);
	ret = sysctlbyname("vm.pagesize", &vmpgsize, &len, NULL, 0);
	if (ret != 0) {
		exit(SYSCTL_VM_PAGESIZE_FAILED);
	}
	if (vmpgsize == 0) {
		exit(VM_PAGESIZE_IS_ZERO);
	}

	if (argc < 1) {
		exit(TOO_FEW_ARGUMENTS);
	}

	len = sizeof(temp);
	ret = sysctlbyname("vm.freeze_enabled", &temp, &len, NULL, 0);
	if (ret != 0) {
		exit(SYSCTL_VM_FREEZE_ENABLED_FAILED);
	}
	if (temp == 0) {
		exit(FREEZER_DISABLED);
	}

	size_mb = atoi(argv[0]);
	num_pages = size_mb * 1024 * 1024 / vmpgsize;
	buf = (char**)malloc(sizeof(char*) * (size_t)num_pages);

	/* Gives us the compression ratio we see in the typical case (~2.7) */
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

	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC), dispatch_get_main_queue(), ^{
		/* Signal to the parent that we're done allocating and it's ok to freeze us */
		printf("Sending initial signal to parent to begin freezing\n");
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
		int current_state, new_state;
		volatile int tmp;

		/* Make sure all the pages are accessed before trying to freeze again */
		for (int x = 0; x < num_pages; x++) {
			tmp = buf[x][0];
		}

		current_state = memorystatus_control(MEMORYSTATUS_CMD_GET_PROCESS_IS_FREEZABLE, getpid(), 0, NULL, 0);

		/* Toggle freezable state */
		new_state = (current_state) ? 0: 1;
		printf("Changing state from %s to %s\n", (current_state) ? "freezable": "unfreezable", (new_state) ? "freezable": "unfreezable");
		if (memorystatus_control(MEMORYSTATUS_CMD_SET_PROCESS_IS_FREEZABLE, getpid(), (uint32_t)new_state, NULL, 0) != KERN_SUCCESS) {
			exit(MEMORYSTATUS_CONTROL_FAILED);
		}

		/* Verify that the state has been set correctly */
		current_state = memorystatus_control(MEMORYSTATUS_CMD_GET_PROCESS_IS_FREEZABLE, getpid(), 0, NULL, 0);
		if (new_state != current_state) {
			exit(IS_FREEZABLE_NOT_AS_EXPECTED);
		}
		num_iter++;

		if (kill(getppid(), SIGUSR1) != 0) {
			exit(SIGNAL_TO_PARENT_FAILED);
		}
	});
	dispatch_activate(ds_signal);
	move_to_idle_band();

	dispatch_main();
}

T_DECL(freeze, "VM freezer test") {
	run_freezer_test(MEM_SIZE_MB);
}
