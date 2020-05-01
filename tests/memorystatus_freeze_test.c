#include <stdio.h>
#include <signal.h>
#include <sys/sysctl.h>
#include <sys/kern_memorystatus.h>
#include <time.h>
#include <mach-o/dyld.h>
#include <mach/mach_vm.h>
#include <mach/vm_page_size.h>  /* Needed for vm_region info */
#include <mach/shared_region.h>
#include <mach/mach.h>

#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif
#include <darwintest.h>
#include <darwintest_utils.h>

#include "memorystatus_assertion_helpers.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_CHECK_LEAKS(false)
	);

#define MEM_SIZE_MB                     10
#define NUM_ITERATIONS          5
#define FREEZE_PAGES_MAX 256

#define CREATE_LIST(X) \
	X(SUCCESS) \
	X(TOO_FEW_ARGUMENTS) \
	X(SYSCTL_VM_PAGESIZE_FAILED) \
	X(VM_PAGESIZE_IS_ZERO) \
	X(DISPATCH_SOURCE_CREATE_FAILED) \
	X(INITIAL_SIGNAL_TO_PARENT_FAILED) \
	X(SIGNAL_TO_PARENT_FAILED) \
	X(MEMORYSTATUS_CONTROL_FAILED) \
	X(IS_FREEZABLE_NOT_AS_EXPECTED) \
	X(MEMSTAT_PRIORITY_CHANGE_FAILED) \
	X(INVALID_ALLOCATE_PAGES_ARGUMENTS) \
	X(EXIT_CODE_MAX)

#define EXIT_CODES_ENUM(VAR) VAR,
enum exit_codes_num {
	CREATE_LIST(EXIT_CODES_ENUM)
};

#define EXIT_CODES_STRING(VAR) #VAR,
static const char *exit_codes_str[] = {
	CREATE_LIST(EXIT_CODES_STRING)
};

static int
get_vmpage_size()
{
	int vmpage_size;
	size_t size = sizeof(vmpage_size);
	int ret = sysctlbyname("vm.pagesize", &vmpage_size, &size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "failed to query vm.pagesize");
	T_QUIET; T_ASSERT_GT(vmpage_size, 0, "vm.pagesize is not > 0");
	return vmpage_size;
}

static pid_t child_pid = -1;
static int freeze_count = 0;

void move_to_idle_band(void);
void run_freezer_test(int);
void freeze_helper_process(void);
/* Gets and optionally sets the freeze pages max threshold */
int sysctl_freeze_pages_max(int* new_value);

/* NB: in_shared_region and get_rprvt are pulled from the memorystatus unit test.
 * We're moving away from those unit tests, so they're copied here.
 */

/* Cribbed from 'top'... */
static int
in_shared_region(mach_vm_address_t addr, cpu_type_t type)
{
	mach_vm_address_t base = 0, size = 0;

	switch (type) {
	case CPU_TYPE_ARM:
		base = SHARED_REGION_BASE_ARM;
		size = SHARED_REGION_SIZE_ARM;
		break;

	case CPU_TYPE_ARM64:
		base = SHARED_REGION_BASE_ARM64;
		size = SHARED_REGION_SIZE_ARM64;
		break;


	case CPU_TYPE_X86_64:
		base = SHARED_REGION_BASE_X86_64;
		size = SHARED_REGION_SIZE_X86_64;
		break;

	case CPU_TYPE_I386:
		base = SHARED_REGION_BASE_I386;
		size = SHARED_REGION_SIZE_I386;
		break;

	case CPU_TYPE_POWERPC:
		base = SHARED_REGION_BASE_PPC;
		size = SHARED_REGION_SIZE_PPC;
		break;

	case CPU_TYPE_POWERPC64:
		base = SHARED_REGION_BASE_PPC64;
		size = SHARED_REGION_SIZE_PPC64;
		break;

	default: {
		int t = type;

		fprintf(stderr, "unknown CPU type: 0x%x\n", t);
		abort();
	}
	}

	return addr >= base && addr < (base + size);
}

/* Get the resident private memory of the given pid */
static unsigned long long
get_rprvt(pid_t pid)
{
	mach_port_name_t task;
	kern_return_t kr;

	mach_vm_size_t rprvt = 0;
	mach_vm_size_t empty = 0;
	mach_vm_size_t fw_private = 0;
	mach_vm_size_t pagesize = vm_kernel_page_size;  // The vm_region page info is reported
	                                                // in terms of vm_kernel_page_size.
	mach_vm_size_t regs = 0;

	mach_vm_address_t addr;
	mach_vm_size_t size;

	int split = 0;

	kr = task_for_pid(mach_task_self(), pid, &task);
	T_QUIET; T_ASSERT_TRUE(kr == KERN_SUCCESS, "Unable to get task_for_pid of child");

	for (addr = 0;; addr += size) {
		vm_region_top_info_data_t info;
		mach_msg_type_number_t count = VM_REGION_TOP_INFO_COUNT;
		mach_port_t object_name;

		kr = mach_vm_region(task, &addr, &size, VM_REGION_TOP_INFO, (vm_region_info_t)&info, &count, &object_name);
		if (kr != KERN_SUCCESS) {
			break;
		}

#if   defined (__arm64__)
		if (in_shared_region(addr, CPU_TYPE_ARM64)) {
#else
		if (in_shared_region(addr, CPU_TYPE_ARM)) {
#endif
			// Private Shared
			fw_private += info.private_pages_resident * pagesize;

			/*
			 * Check if this process has the globally shared
			 * text and data regions mapped in.  If so, set
			 * split to TRUE and avoid checking
			 * again.
			 */
			if (split == FALSE && info.share_mode == SM_EMPTY) {
				vm_region_basic_info_data_64_t  b_info;
				mach_vm_address_t b_addr = addr;
				mach_vm_size_t b_size = size;
				count = VM_REGION_BASIC_INFO_COUNT_64;

				kr = mach_vm_region(task, &b_addr, &b_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&b_info, &count, &object_name);
				if (kr != KERN_SUCCESS) {
					break;
				}

				if (b_info.reserved) {
					split = TRUE;
				}
			}

			/*
			 * Short circuit the loop if this isn't a shared
			 * private region, since that's the only region
			 * type we care about within the current address
			 * range.
			 */
			if (info.share_mode != SM_PRIVATE) {
				continue;
			}
		}

		regs++;

		/*
		 * Update counters according to the region type.
		 */

		if (info.share_mode == SM_COW && info.ref_count == 1) {
			// Treat single reference SM_COW as SM_PRIVATE
			info.share_mode = SM_PRIVATE;
		}

		switch (info.share_mode) {
		case SM_LARGE_PAGE:
		// Treat SM_LARGE_PAGE the same as SM_PRIVATE
		// since they are not shareable and are wired.
		case SM_PRIVATE:
			rprvt += info.private_pages_resident * pagesize;
			rprvt += info.shared_pages_resident * pagesize;
			break;

		case SM_EMPTY:
			empty += size;
			break;

		case SM_COW:
		case SM_SHARED:
			if (pid == 0) {
				// Treat kernel_task specially
				if (info.share_mode == SM_COW) {
					rprvt += info.private_pages_resident * pagesize;
				}
				break;
			}

			if (info.share_mode == SM_COW) {
				rprvt += info.private_pages_resident * pagesize;
			}
			break;

		default:
			assert(0);
			break;
		}
	}

	return rprvt;
}

void
move_to_idle_band(void)
{
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

void
freeze_helper_process(void)
{
	size_t length;
	int ret, freeze_enabled, errno_freeze_sysctl;
	uint64_t resident_memory_before, resident_memory_after, vmpage_size;
	vmpage_size = (uint64_t) get_vmpage_size();
	resident_memory_before = get_rprvt(child_pid) / vmpage_size;

	T_LOG("Freezing child pid %d", child_pid);
	ret = sysctlbyname("kern.memorystatus_freeze", NULL, NULL, &child_pid, sizeof(child_pid));
	errno_freeze_sysctl = errno;
	sleep(1);

	/*
	 * The child process toggles its freezable state on each iteration.
	 * So a failure for every alternate freeze is expected.
	 */
	if (freeze_count % 2) {
		length = sizeof(freeze_enabled);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctlbyname("vm.freeze_enabled", &freeze_enabled, &length, NULL, 0),
		    "failed to query vm.freeze_enabled");
		if (freeze_enabled) {
			errno = errno_freeze_sysctl;
			T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl kern.memorystatus_freeze failed");
		} else {
			/* If freezer is disabled, skip the test. This can happen due to disk space shortage. */
			T_LOG("Freeze has been disabled. Terminating early.");
			T_END;
		}
		resident_memory_after = get_rprvt(child_pid) / vmpage_size;
		uint64_t freeze_pages_max = (uint64_t) sysctl_freeze_pages_max(NULL);
		T_QUIET; T_ASSERT_LT(resident_memory_after, resident_memory_before, "Freeze didn't reduce resident memory set");
		if (resident_memory_before > freeze_pages_max) {
			T_QUIET; T_ASSERT_LE(resident_memory_before - resident_memory_after, freeze_pages_max, "Freeze pages froze more than the threshold.");
		}
		ret = sysctlbyname("kern.memorystatus_thaw", NULL, NULL, &child_pid, sizeof(child_pid));
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl kern.memorystatus_thaw failed");
	} else {
		T_QUIET; T_ASSERT_TRUE(ret != KERN_SUCCESS, "Freeze should have failed");
		T_LOG("Freeze failed as expected");
	}

	freeze_count++;

	T_QUIET; T_ASSERT_POSIX_SUCCESS(kill(child_pid, SIGUSR1), "failed to send SIGUSR1 to child process");
}

void
run_freezer_test(int num_pages)
{
	int ret, freeze_enabled;
	char sz_str[50];
	char **launch_tool_args;
	char testpath[PATH_MAX];
	uint32_t testpath_buf_size;
	dispatch_source_t ds_freeze, ds_proc;
	size_t length;

	length = sizeof(freeze_enabled);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctlbyname("vm.freeze_enabled", &freeze_enabled, &length, NULL, 0),
	    "failed to query vm.freeze_enabled");
	if (!freeze_enabled) {
		/* If freezer is disabled, skip the test. This can happen due to disk space shortage. */
		T_SKIP("Freeze has been disabled. Skipping test.");
	}

	signal(SIGUSR1, SIG_IGN);
	ds_freeze = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, dispatch_get_main_queue());
	T_QUIET; T_ASSERT_NOTNULL(ds_freeze, "dispatch_source_create (ds_freeze)");

	dispatch_source_set_event_handler(ds_freeze, ^{
		if (freeze_count < NUM_ITERATIONS) {
		        freeze_helper_process();
		} else {
		        kill(child_pid, SIGKILL);
		        dispatch_source_cancel(ds_freeze);
		}
	});
	dispatch_activate(ds_freeze);

	testpath_buf_size = sizeof(testpath);
	ret = _NSGetExecutablePath(testpath, &testpath_buf_size);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "_NSGetExecutablePath");
	T_LOG("Executable path: %s", testpath);

	sprintf(sz_str, "%d", num_pages);
	launch_tool_args = (char *[]){
		testpath,
		"-n",
		"allocate_pages",
		"--",
		sz_str,
		NULL
	};

	/* Spawn the child process. Suspend after launch until the exit proc handler has been set up. */
	ret = dt_launch_tool(&child_pid, launch_tool_args, true, NULL, NULL);
	if (ret != 0) {
		T_LOG("dt_launch tool returned %d with error code %d", ret, errno);
	}
	T_QUIET; T_ASSERT_POSIX_SUCCESS(child_pid, "dt_launch_tool");

	ds_proc = dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC, (uintptr_t)child_pid, DISPATCH_PROC_EXIT, dispatch_get_main_queue());
	T_QUIET; T_ASSERT_NOTNULL(ds_proc, "dispatch_source_create (ds_proc)");

	dispatch_source_set_event_handler(ds_proc, ^{
		int status = 0, code = 0;
		pid_t rc = waitpid(child_pid, &status, 0);
		T_QUIET; T_ASSERT_EQ(rc, child_pid, "waitpid");
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

	T_QUIET; T_ASSERT_POSIX_SUCCESS(kill(child_pid, SIGCONT), "failed to send SIGCONT to child process");
	dispatch_main();
}

static void
allocate_pages(int num_pages)
{
	int i, j, vmpgsize;
	char val;
	__block int num_iter = 0;
	__block char **buf;
	dispatch_source_t ds_signal;
	vmpgsize = get_vmpage_size();
	if (num_pages < 1) {
		printf("Invalid number of pages to allocate: %d\n", num_pages);
		exit(INVALID_ALLOCATE_PAGES_ARGUMENTS);
	}

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
		int current_state, new_state;
		volatile int tmp;

		/* Make sure all the pages are accessed before trying to freeze again */
		for (int x = 0; x < num_pages; x++) {
		        tmp = buf[x][0];
		}

		current_state = memorystatus_control(MEMORYSTATUS_CMD_GET_PROCESS_IS_FREEZABLE, getpid(), 0, NULL, 0);
		/* Sysprocs start off as unfreezable. Verify that first. */
		if (num_iter == 0 && current_state != 0) {
		        exit(IS_FREEZABLE_NOT_AS_EXPECTED);
		}

		/* Toggle freezable state */
		new_state = (current_state) ? 0: 1;
		printf("[%d] Changing state from %s to %s\n", getpid(),
		(current_state) ? "freezable": "unfreezable", (new_state) ? "freezable": "unfreezable");
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

T_HELPER_DECL(allocate_pages,
    "allocates pages to freeze",
    T_META_ASROOT(true)) {
	if (argc < 1) {
		exit(TOO_FEW_ARGUMENTS);
	}

	int num_pages = atoi(argv[0]);
	allocate_pages(num_pages);
}

T_DECL(freeze, "VM freezer test", T_META_ASROOT(true)) {
	run_freezer_test(
		(MEM_SIZE_MB << 20) / get_vmpage_size());
}

static int old_freeze_pages_max = 0;
static void
reset_freeze_pages_max()
{
	if (old_freeze_pages_max != 0) {
		sysctl_freeze_pages_max(&old_freeze_pages_max);
	}
}

int
sysctl_freeze_pages_max(int* new_value)
{
	static int set_end_handler = false;
	int freeze_pages_max, ret;
	size_t size = sizeof(freeze_pages_max);
	ret = sysctlbyname("kern.memorystatus_freeze_pages_max", &freeze_pages_max, &size, new_value, size);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "Unable to query kern.memorystatus_freeze_pages_max");
	if (!set_end_handler) {
		// Save the original value and instruct darwintest to restore it after the test completes
		old_freeze_pages_max = freeze_pages_max;
		T_ATEND(reset_freeze_pages_max);
		set_end_handler = true;
	}
	return old_freeze_pages_max;
}

T_DECL(freeze_over_max_threshold, "Max Freeze Threshold is Enforced", T_META_ASROOT(true)) {
	int freeze_pages_max = FREEZE_PAGES_MAX;
	sysctl_freeze_pages_max(&freeze_pages_max);
	run_freezer_test(FREEZE_PAGES_MAX * 2);
}

T_HELPER_DECL(frozen_background, "Frozen background process", T_META_ASROOT(true)) {
	kern_return_t kern_ret;
	/* Set the process to freezable */
	kern_ret = memorystatus_control(MEMORYSTATUS_CMD_SET_PROCESS_IS_FREEZABLE, getpid(), 1, NULL, 0);
	T_QUIET; T_ASSERT_EQ(kern_ret, KERN_SUCCESS, "set process is freezable");
	/* Signal to our parent that we can be frozen */
	if (kill(getppid(), SIGUSR1) != 0) {
		T_LOG("Unable to signal to parent process!");
		exit(1);
	}
	while (1) {
		;
	}
}

/* Launches the frozen_background helper as a managed process. */
static pid_t
launch_frozen_background_process()
{
	pid_t pid;
	char **launch_tool_args;
	char testpath[PATH_MAX];
	uint32_t testpath_buf_size;
	int ret;

	testpath_buf_size = sizeof(testpath);
	ret = _NSGetExecutablePath(testpath, &testpath_buf_size);
	printf("Launching %s\n", testpath);
	launch_tool_args = (char *[]){
		testpath,
		"-n",
		"frozen_background",
		NULL
	};
	ret = dt_launch_tool(&pid, launch_tool_args, false, NULL, NULL);
	if (ret != 0) {
		T_LOG("dt_launch tool returned %d with error code %d", ret, errno);
	}
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "dt_launch_tool");
	/* Set the process's managed bit, so that the kernel treats this process like an app instead of a sysproc. */
	ret = memorystatus_control(MEMORYSTATUS_CMD_SET_PROCESS_IS_MANAGED, pid, 1, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memorystatus_control");
	return pid;
}

static void
freeze_process(pid_t pid)
{
	int ret, freeze_enabled, errno_freeze_sysctl;
	size_t length;
	T_LOG("Freezing pid %d", pid);

	ret = sysctlbyname("kern.memorystatus_freeze", NULL, NULL, &pid, sizeof(pid));
	errno_freeze_sysctl = errno;
	length = sizeof(freeze_enabled);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctlbyname("vm.freeze_enabled", &freeze_enabled, &length, NULL, 0),
	    "failed to query vm.freeze_enabled");
	if (freeze_enabled) {
		errno = errno_freeze_sysctl;
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl kern.memorystatus_freeze failed");
	} else {
		/* If freezer is disabled, skip the test. This can happen due to disk space shortage. */
		T_LOG("Freeze has been disabled. Terminating early.");
		T_END;
	}
}

static void
memorystatus_assertion_test_demote_frozen()
{
#if !CONFIG_EMBEDDED
	T_SKIP("Freezing processes is only supported on embedded");
#endif
	/*
	 * Test that if we assert a priority on a process, freeze it, and then demote all frozen processes, it does not get demoted below the asserted priority.
	 * Then remove thee assertion, and ensure it gets demoted properly.
	 */
	/* these values will remain fixed during testing */
	int             active_limit_mb = 15;   /* arbitrary */
	int             inactive_limit_mb = 7;  /* arbitrary */
	int             demote_value = 1;
	/* Launch the child process, and elevate its priority */
	int requestedpriority;
	dispatch_source_t ds_signal, ds_exit;
	requestedpriority = JETSAM_PRIORITY_UI_SUPPORT;

	/* Wait for the child process to tell us that it's ready, and then freeze it */
	signal(SIGUSR1, SIG_IGN);
	ds_signal = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, dispatch_get_main_queue());
	T_QUIET; T_ASSERT_NOTNULL(ds_signal, "dispatch_source_create");
	dispatch_source_set_event_handler(ds_signal, ^{
		int sysctl_ret;
		/* Freeze the process, trigger agressive demotion, and check that it hasn't been demoted. */
		freeze_process(child_pid);
		/* Agressive demotion */
		sysctl_ret = sysctlbyname("kern.memorystatus_demote_frozen_processes", NULL, NULL, &demote_value, sizeof(demote_value));
		T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctl_ret, "sysctl kern.memorystatus_demote_frozen_processes succeeded");
		/* Check */
		(void)check_properties(child_pid, requestedpriority, inactive_limit_mb, 0x0, ASSERTION_STATE_IS_SET, "Priority was set");
		T_LOG("Relinquishing our assertion.");
		/* Relinquish our assertion, and check that it gets demoted. */
		relinquish_assertion_priority(child_pid, 0x0);
		(void)check_properties(child_pid, JETSAM_PRIORITY_AGING_BAND2, inactive_limit_mb, 0x0, ASSERTION_STATE_IS_RELINQUISHED, "Assertion was reqlinquished.");
		/* Kill the child */
		T_QUIET; T_ASSERT_POSIX_SUCCESS(kill(child_pid, SIGKILL), "Killed child process");
		T_END;
	});

	/* Launch the child process and set the initial properties on it. */
	child_pid = launch_frozen_background_process();
	set_memlimits(child_pid, active_limit_mb, inactive_limit_mb, false, false);
	set_assertion_priority(child_pid, requestedpriority, 0x0);
	(void)check_properties(child_pid, requestedpriority, inactive_limit_mb, 0x0, ASSERTION_STATE_IS_SET, "Priority was set");
	/* Listen for exit. */
	ds_exit = dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC, (uintptr_t)child_pid, DISPATCH_PROC_EXIT, dispatch_get_main_queue());
	dispatch_source_set_event_handler(ds_exit, ^{
		int status = 0, code = 0;
		pid_t rc = waitpid(child_pid, &status, 0);
		T_QUIET; T_ASSERT_EQ(rc, child_pid, "waitpid");
		code = WEXITSTATUS(status);
		T_QUIET; T_ASSERT_EQ(code, 0, "Child exited cleanly");
		T_END;
	});

	dispatch_activate(ds_exit);
	dispatch_activate(ds_signal);
	dispatch_main();
}

T_DECL(assertion_test_demote_frozen, "demoted frozen process goes to asserted priority.", T_META_ASROOT(true)) {
	memorystatus_assertion_test_demote_frozen();
}

T_DECL(budget_replenishment, "budget replenishes properly") {
	size_t length;
	int ret;
	static unsigned int kTestIntervalSecs = 60 * 60 * 32; // 32 Hours
	unsigned int memorystatus_freeze_daily_mb_max, memorystatus_freeze_daily_pages_max;
	static unsigned int kFixedPointFactor = 100;
	static unsigned int kNumSecondsInDay = 60 * 60 * 24;
	unsigned int new_budget, expected_new_budget_pages;
	size_t new_budget_ln;
	unsigned int page_size = (unsigned int) get_vmpage_size();

	/*
	 * Calculate a new budget as if the previous interval expired kTestIntervalSecs
	 * ago and we used up its entire budget.
	 */
	length = sizeof(kTestIntervalSecs);
	new_budget_ln = sizeof(new_budget);
	ret = sysctlbyname("vm.memorystatus_freeze_calculate_new_budget", &new_budget, &new_budget_ln, &kTestIntervalSecs, length);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "vm.memorystatus_freeze_calculate_new_budget");

	// Grab the daily budget.
	length = sizeof(memorystatus_freeze_daily_mb_max);
	ret = sysctlbyname("kern.memorystatus_freeze_daily_mb_max", &memorystatus_freeze_daily_mb_max, &length, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kern.memorystatus_freeze_daily_mb_max");

	memorystatus_freeze_daily_pages_max = memorystatus_freeze_daily_mb_max * 1024 * 1024 / page_size;

	/*
	 * We're kTestIntervalSecs past a new interval. Which means we are owed kNumSecondsInDay
	 * seconds of budget.
	 */
	expected_new_budget_pages = memorystatus_freeze_daily_pages_max;
	expected_new_budget_pages += ((kTestIntervalSecs * kFixedPointFactor) / (kNumSecondsInDay)
	    * memorystatus_freeze_daily_pages_max) / kFixedPointFactor;

	T_QUIET; T_ASSERT_EQ(new_budget, expected_new_budget_pages, "Calculate new budget behaves correctly.");
}
