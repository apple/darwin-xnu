#include <stdio.h>
#include <mach/mach_vm.h>
#include <mach/mach_port.h>
#include <mach/mach_host.h>
#include <mach/mach_error.h>
#include <mach-o/dyld.h>
#include <sys/sysctl.h>
#include <sys/kdebug.h>
#include <sys/mman.h>
#include <sys/kern_memorystatus.h>
#include <ktrace/session.h>
#include <dispatch/private.h>

#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif
#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_CHECK_LEAKS(false)
	);

#define TIMEOUT_SECS                                    10 * 60 /* abort if test takes > 10 minutes */

#if (TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR)
#define ALLOCATION_SIZE_VM_REGION                       (16*1024)               /* 16 KB */
#define ALLOCATION_SIZE_VM_OBJECT                       ALLOCATION_SIZE_VM_REGION
#else
#define ALLOCATION_SIZE_VM_REGION                       (1024*1024*100) /* 100 MB */
#define ALLOCATION_SIZE_VM_OBJECT                       (16*1024)               /* 16 KB */
#endif
#define MAX_CHILD_PROCS                                 100

#define NUM_GIVE_BACK                                   5
#define NUM_GIVE_BACK_PORTS                             20

/* 60% is too high on bridgeOS to achieve without vm-pageshortage jetsams. Set it to 40%. */
#if TARGET_OS_BRIDGE
#define ZONEMAP_JETSAM_LIMIT_SYSCTL                     "kern.zone_map_jetsam_limit=40"
#else
#define ZONEMAP_JETSAM_LIMIT_SYSCTL                     "kern.zone_map_jetsam_limit=60"
#endif

#define VME_ZONE_TEST_OPT                               "allocate_vm_regions"
#define VM_OBJECTS_ZONE_TEST_OPT                        "allocate_vm_objects"
#define GENERIC_ZONE_TEST_OPT                           "allocate_from_generic_zone"

#define VME_ZONE                                        "VM map entries"
#define VMOBJECTS_ZONE                                  "vm objects"
#define VMENTRY_TO_VMOBJECT_COMPARISON_RATIO            98

#define VM_TAG1                                         100
#define VM_TAG2                                         101

#define LARGE_MEM_GB                                    32
#define LARGE_MEM_JETSAM_LIMIT                          40
#define JETSAM_LIMIT_LOWEST                             10

enum {
	VME_ZONE_TEST = 0,
	VM_OBJECTS_ZONE_TEST,
	GENERIC_ZONE_TEST,
};

typedef struct test_config_struct {
	int test_index;
	int num_zones;
	const char *helper_func;
	mach_zone_name_array_t zone_names;
} test_config_struct;

static test_config_struct current_test;
static dispatch_source_t ds_signal = NULL;
static dispatch_source_t ds_timer = NULL;
static dispatch_queue_t dq_spawn = NULL;
static ktrace_session_t session = NULL;

static mach_zone_info_array_t zone_info_array = NULL;
static mach_zone_name_t largest_zone_name;
static mach_zone_info_t largest_zone_info;

static pthread_mutex_t test_mtx = PTHREAD_MUTEX_INITIALIZER;   /* protects the next 3 things */
static bool test_ending = false;
static int num_children = 0;
static pid_t child_pids[MAX_CHILD_PROCS];

static char testpath[PATH_MAX];
static void allocate_vm_stuff(int);
static void allocate_from_generic_zone(void);
static void begin_test_teardown(void);
static void cleanup_and_end_test(void);
static void setup_ktrace_session(void);
static void spawn_child_process(void);
static void run_test(void);
static bool verify_generic_jetsam_criteria(void);
static bool vme_zone_compares_to_vm_objects(void);
static int query_zone_map_size(void);
static void query_zone_info(void);
static void print_zone_info(mach_zone_name_t *zn, mach_zone_info_t *zi);

extern void mach_zone_force_gc(host_t host);
extern kern_return_t mach_zone_info_for_largest_zone(
	host_priv_t host,
	mach_zone_name_t *name,
	mach_zone_info_t *info
	);

static bool
check_time(time_t start, int timeout)
{
	return start + timeout < time(NULL);
}

/*
 * flag values for allocate_vm_stuff()
 */
#define REGIONS 1
#define OBJECTS 2

static void
allocate_vm_stuff(int flags)
{
	uint64_t alloc_size, i;
	time_t start = time(NULL);
	mach_vm_address_t give_back[NUM_GIVE_BACK];
	char *msg;

	if (flags == REGIONS) {
		alloc_size = ALLOCATION_SIZE_VM_REGION;
		msg = "";
	} else {
		alloc_size = ALLOCATION_SIZE_VM_OBJECT;
		msg = " each region backed by a VM object";
	}

	printf("[%d] Allocating VM regions, each of size %lld KB%s\n", getpid(), (alloc_size >> 10), msg);

	for (i = 0;; i++) {
		mach_vm_address_t addr = (mach_vm_address_t)NULL;

		/* Alternate VM tags between consecutive regions to prevent coalescing */
		int vmflags = VM_MAKE_TAG((i % 2)? VM_TAG1: VM_TAG2) | VM_FLAGS_ANYWHERE;

		if ((mach_vm_allocate(mach_task_self(), &addr, (mach_vm_size_t)alloc_size, vmflags)) != KERN_SUCCESS) {
			break;
		}

		/*
		 * If interested in objects, touch the region so the VM object is created,
		 * then free this page. Keeps us from holding a lot of dirty pages.
		 */
		if (flags == OBJECTS) {
			*((int *)addr) = 0;
			madvise((void *)addr, (size_t)alloc_size, MADV_FREE);
		}

		if (check_time(start, TIMEOUT_SECS)) {
			printf("[%d] child timeout during allocations\n", getpid());
			exit(0);
		}

		if (i < NUM_GIVE_BACK) {
			give_back[i] = addr;
		}
	}

	/* return some of the resource to avoid O-O-M problems */
	for (uint64_t j = 0; j < NUM_GIVE_BACK && j < i; ++j) {
		mach_vm_deallocate(mach_task_self(), give_back[j], (mach_vm_size_t)alloc_size);
	}

	printf("[%d] Number of allocations: %lld\n", getpid(), i);

	/* Signal to the parent that we're done allocating */
	kill(getppid(), SIGUSR1);

	while (1) {
		sleep(2);
		/* Exit if parent has exited. Ensures child processes don't linger around after the test exits */
		if (getppid() == 1) {
			exit(0);
		}

		if (check_time(start, TIMEOUT_SECS)) {
			printf("[%d] child timeout while waiting\n", getpid());
			exit(0);
		}
	}
}


static void
allocate_from_generic_zone(void)
{
	uint64_t i = 0;
	time_t start = time(NULL);
	mach_port_t give_back[NUM_GIVE_BACK_PORTS];

	printf("[%d] Allocating mach_ports\n", getpid());
	for (i = 0;; i++) {
		mach_port_t port;

		if ((mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port)) != KERN_SUCCESS) {
			break;
		}

		if (check_time(start, TIMEOUT_SECS)) {
			printf("[%d] child timeout during allocations\n", getpid());
			exit(0);
		}

		if (i < NUM_GIVE_BACK_PORTS) {
			give_back[i] = port;
		}
	}

	/* return some of the resource to avoid O-O-M problems */
	for (uint64_t j = 0; j < NUM_GIVE_BACK_PORTS && j < i; ++j) {
		mach_port_deallocate(mach_task_self(), give_back[j]);
	}
	printf("[%d] Number of allocations: %lld\n", getpid(), i);

	/* Signal to the parent that we're done allocating */
	kill(getppid(), SIGUSR1);

	while (1) {
		sleep(2);
		/* Exit if parent has exited. Ensures child processes don't linger around after the test exits */
		if (getppid() == 1) {
			exit(0);
		}

		if (check_time(start, TIMEOUT_SECS)) {
			printf("[%d] child timeout while waiting\n", getpid());
			exit(0);
		}
	}
}

static void
print_zone_info(mach_zone_name_t *zn, mach_zone_info_t *zi)
{
	T_LOG("ZONE NAME: %-35sSIZE: %-25lluELEMENTS: %llu",
	    zn->mzn_name, zi->mzi_cur_size, zi->mzi_count);
}

static time_t main_start;

static void
query_zone_info(void)
{
	int i;
	kern_return_t kr;
	static uint64_t num_calls = 0;

	if (check_time(main_start, TIMEOUT_SECS)) {
		T_ASSERT_FAIL("Global timeout expired");
	}
	for (i = 0; i < current_test.num_zones; i++) {
		kr = mach_zone_info_for_zone(mach_host_self(), current_test.zone_names[i], &(zone_info_array[i]));
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_zone_info_for_zone(%s) returned %d [%s]", current_test.zone_names[i].mzn_name, kr, mach_error_string(kr));
	}
	kr = mach_zone_info_for_largest_zone(mach_host_self(), &largest_zone_name, &largest_zone_info);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_zone_info_for_largest_zone returned %d [%s]", kr, mach_error_string(kr));

	num_calls++;
	if (num_calls % 5 != 0) {
		return;
	}

	/* Print out size and element count for zones relevant to the test */
	for (i = 0; i < current_test.num_zones; i++) {
		print_zone_info(&(current_test.zone_names[i]), &(zone_info_array[i]));
	}
}

static bool
vme_zone_compares_to_vm_objects(void)
{
	int i;
	uint64_t vm_object_element_count = 0, vm_map_entry_element_count = 0;

	T_LOG("Comparing element counts of \"VM map entries\" and \"vm objects\" zones");
	for (i = 0; i < current_test.num_zones; i++) {
		if (!strcmp(current_test.zone_names[i].mzn_name, VME_ZONE)) {
			vm_map_entry_element_count = zone_info_array[i].mzi_count;
		} else if (!strcmp(current_test.zone_names[i].mzn_name, VMOBJECTS_ZONE)) {
			vm_object_element_count = zone_info_array[i].mzi_count;
		}
		print_zone_info(&(current_test.zone_names[i]), &(zone_info_array[i]));
	}

	T_LOG("# VM map entries as percentage of # vm objects = %llu", (vm_map_entry_element_count * 100) / vm_object_element_count);
	if (vm_map_entry_element_count >= ((vm_object_element_count * VMENTRY_TO_VMOBJECT_COMPARISON_RATIO) / 100)) {
		T_LOG("Number of VM map entries is comparable to vm objects\n\n");
		return true;
	}
	T_LOG("Number of VM map entries is NOT comparable to vm objects\n\n");
	return false;
}

static bool
verify_generic_jetsam_criteria(void)
{
	T_LOG("Largest zone info");
	print_zone_info(&largest_zone_name, &largest_zone_info);

	/* If VM map entries is not the largest zone */
	if (strcmp(largest_zone_name.mzn_name, VME_ZONE)) {
		/* If vm objects is the largest zone and the VM map entries zone had comparable # of elements, return false */
		if (!strcmp(largest_zone_name.mzn_name, VMOBJECTS_ZONE) && vme_zone_compares_to_vm_objects()) {
			return false;
		}
		return true;
	}
	return false;
}

static void
begin_test_teardown(void)
{
	int ret, old_limit = 95;

	/*
	 * Restore kern.zone_map_jetsam_limit to the default high value, to prevent further jetsams.
	 * We should change the value of old_limit if ZONE_MAP_JETSAM_LIMIT_DEFAULT changes in the kernel.
	 * We don't have a way to capture what the original value was before the test, because the
	 * T_META_SYSCTL_INT macro will have changed the value before the test starts running.
	 */
	ret = sysctlbyname("kern.zone_map_jetsam_limit", NULL, NULL, &old_limit, sizeof(old_limit));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl kern.zone_map_jetsam_limit failed");
	T_LOG("kern.zone_map_jetsam_limit set to %d%%", old_limit);


	/* End ktrace session */
	if (session != NULL) {
		T_LOG("Ending ktrace session...");
		ktrace_end(session, 1);
	}

	dispatch_sync(dq_spawn, ^{
		T_LOG("Cancelling dispatch sources...");

		/* Disable the timer that queries and prints zone info periodically */
		if (ds_timer != NULL) {
		        dispatch_source_cancel(ds_timer);
		}

		/* Disable signal handler that spawns child processes */
		if (ds_signal != NULL) {
		        /*
		         * No need for a dispatch_source_cancel_and_wait here.
		         * We're queueing this on the spawn queue, so no further
		         * processes will be spawned after the source is cancelled.
		         */
		        dispatch_source_cancel(ds_signal);
		}
	});
}

static void
cleanup_and_end_test(void)
{
	int i;

	/*
	 * The atend handler executes on a different dispatch queue.
	 * We want to do the cleanup only once.
	 */
	pthread_mutex_lock(&test_mtx);
	if (test_ending) {
		pthread_mutex_unlock(&test_mtx);
		return;
	}
	test_ending = TRUE;
	pthread_mutex_unlock(&test_mtx);

	dispatch_async(dq_spawn, ^{
		/*
		 * If the test succeeds, we will call dispatch_source_cancel twice, which is fine since
		 * the operation is idempotent. Just make sure to not drop all references to the dispatch sources
		 * (in this case we're not, we have globals holding references to them), or we can end up with
		 * use-after-frees which would be a problem.
		 */
		/* Disable the timer that queries and prints zone info periodically */
		if (ds_timer != NULL) {
		        dispatch_source_cancel(ds_timer);
		}

		/* Disable signal handler that spawns child processes */
		if (ds_signal != NULL) {
		        dispatch_source_cancel(ds_signal);
		}
	});

	pthread_mutex_lock(&test_mtx);
	T_LOG("Number of processes spawned: %d", num_children);
	T_LOG("Killing child processes...");

	/* Kill all the child processes that were spawned */
	for (i = 0; i < num_children; i++) {
		pid_t pid = child_pids[i];
		int status = 0;

		/*
		 * Kill and wait for each child to exit
		 * Without this we were seeing hw_lock_bit timeouts in BATS.
		 */
		kill(pid, SIGKILL);
		pthread_mutex_unlock(&test_mtx);
		if (waitpid(pid, &status, 0) < 0) {
			T_LOG("waitpid returned status %d", status);
		}
		pthread_mutex_lock(&test_mtx);
	}
	sleep(1);

	/* Force zone_gc before starting test for another zone or exiting */
	mach_zone_force_gc(mach_host_self());

	/* End ktrace session */
	if (session != NULL) {
		ktrace_end(session, 1);
	}

	if (current_test.num_zones > 0) {
		T_LOG("Relevant zone info at the end of the test:");
		for (i = 0; i < current_test.num_zones; i++) {
			print_zone_info(&(current_test.zone_names[i]), &(zone_info_array[i]));
		}
	}
}

static void
setup_ktrace_session(void)
{
	int ret = 0;

	T_LOG("Setting up ktrace session...");
	session = ktrace_session_create();
	T_QUIET; T_ASSERT_NOTNULL(session, "ktrace_session_create");

	ktrace_set_interactive(session);

	ktrace_set_dropped_events_handler(session, ^{
		T_FAIL("Dropped ktrace events; might have missed an expected jetsam event. Terminating early.");
	});

	ktrace_set_completion_handler(session, ^{
		ktrace_session_destroy(session);
		T_END;
	});

	/* Listen for memorystatus_do_kill trace events */
	ret = ktrace_events_single(session, (BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_DO_KILL)), ^(ktrace_event_t event) {
		int i;
		bool received_jetsam_event = false;

		/*
		 * libktrace does not support DBG_FUNC_START/END in the event filter. It simply ignores it.
		 * So we need to explicitly check for the end event (a successful jetsam kill) here,
		 * instead of passing in ((BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_DO_KILL)) | DBG_FUNC_START).
		 */
		if (!(event->debugid & DBG_FUNC_START)) {
		        return;
		}

		/* Check for zone-map-exhaustion jetsam. */
		if (event->arg2 == kMemorystatusKilledZoneMapExhaustion) {
		        begin_test_teardown();
		        T_LOG("[memorystatus_do_kill] jetsam reason: zone-map-exhaustion, pid: %d\n\n", (int)event->arg1);
		        if (current_test.test_index == VME_ZONE_TEST || current_test.test_index == VM_OBJECTS_ZONE_TEST) {
		                /*
		                 * For the VM map entries zone we try to kill the leaking process.
		                 * Verify that we jetsammed one of the processes we spawned.
		                 *
		                 * For the vm objects zone we pick the leaking process via the VM map entries
		                 * zone, if the number of vm objects and VM map entries are comparable.
		                 * The test simulates this scenario, we should see a targeted jetsam for the
		                 * vm objects zone too.
		                 */
		                pthread_mutex_lock(&test_mtx);
		                for (i = 0; i < num_children; i++) {
		                        if (child_pids[i] == (pid_t)event->arg1) {
		                                received_jetsam_event = true;
		                                T_LOG("Received jetsam event for a child");
		                                break;
					}
				}
		                pthread_mutex_unlock(&test_mtx);
		                /*
		                 * If we didn't see a targeted jetsam, verify that the largest zone actually
		                 * fulfilled the criteria for generic jetsams.
		                 */
		                if (!received_jetsam_event && verify_generic_jetsam_criteria()) {
		                        received_jetsam_event = true;
		                        T_LOG("Did not receive jetsam event for a child, but generic jetsam criteria holds");
				}
			} else {
		                received_jetsam_event = true;
		                T_LOG("Received generic jetsam event");
			}

		        T_QUIET; T_ASSERT_TRUE(received_jetsam_event, "Jetsam event not as expected");
		} else {
		        /*
		         * The test relies on the children being able to send a signal to the parent, to continue spawning new processes
		         * that leak more zone memory. If a child is jetsammed for some other reason, the parent can get stuck waiting for
		         * a signal from the child, never being able to make progress (We spawn only a single process at a time to rate-limit
		         * the zone memory bloat.). If this happens, the test eventually times out. So if a child is jetsammed for some
		         * reason other than zone-map-exhaustion, end the test early.
		         *
		         * This typically happens when we end up triggering vm-pageshortage jetsams before zone-map-exhaustion jetsams.
		         * Lowering the zone_map_jetsam_limit if the zone map size was initially low should help with this too.
		         * See sysctlbyname("kern.zone_map_jetsam_limit"...) in run_test() below.
		         */
		        pthread_mutex_lock(&test_mtx);
		        for (i = 0; i < num_children; i++) {
		                if (child_pids[i] == (pid_t)event->arg1) {
		                        begin_test_teardown();
		                        T_PASS("Child pid %d was jetsammed due to reason %d. Terminating early.",
		                        (int)event->arg1, (int)event->arg2);
				}
			}
		        pthread_mutex_unlock(&test_mtx);
		}
	});
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "ktrace_events_single");

	ret = ktrace_start(session, dispatch_get_main_queue());
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "ktrace_start");
}

static int
query_zone_map_size(void)
{
	int ret;
	uint64_t zstats[2];
	size_t zstats_size = sizeof(zstats);

	ret = sysctlbyname("kern.zone_map_size_and_capacity", &zstats, &zstats_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl kern.zone_map_size_and_capacity failed");

	T_LOG("Zone map capacity: %-30lldZone map size: %lld [%lld%% full]", zstats[1], zstats[0], (zstats[0] * 100) / zstats[1]);

#if (TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR)
	int memstat_level;
	size_t memstat_level_size = sizeof(memstat_level);
	ret = sysctlbyname("kern.memorystatus_level", &memstat_level, &memstat_level_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl kern.memorystatus_level failed");

	T_LOG("kern.memorystatus_level = %d%%", memstat_level);
#endif
	return (int)(zstats[0] * 100 / zstats[1]);
}

static void
spawn_child_process(void)
{
	pid_t pid = -1;
	char helper_func[50];
	char *launch_tool_args[4];

	pthread_mutex_lock(&test_mtx);
	if (!test_ending) {
		if (num_children == MAX_CHILD_PROCS) {
			pthread_mutex_unlock(&test_mtx);
			T_ASSERT_FAIL("Spawned too many children. Aborting test");
			/* not reached */
		}

		strlcpy(helper_func, current_test.helper_func, sizeof(helper_func));
		launch_tool_args[0] = testpath;
		launch_tool_args[1] = "-n";
		launch_tool_args[2] = helper_func;
		launch_tool_args[3] = NULL;

		/* Spawn the child process */
		int rc = dt_launch_tool(&pid, launch_tool_args, false, NULL, NULL);
		if (rc != 0) {
			T_LOG("dt_launch tool returned %d with error code %d", rc, errno);
		}
		T_QUIET; T_ASSERT_POSIX_SUCCESS(pid, "dt_launch_tool");

		child_pids[num_children++] = pid;
	}
	pthread_mutex_unlock(&test_mtx);
}

static void
run_test(void)
{
	uint64_t mem;
	uint32_t testpath_buf_size, pages;
	int ret, dev, pgsz, initial_zone_occupancy, old_limit, new_limit = 0;
	size_t sysctl_size;

	T_ATEND(cleanup_and_end_test);
	T_SETUPBEGIN;

	main_start = time(NULL);
	dev = 0;
	sysctl_size = sizeof(dev);
	ret = sysctlbyname("kern.development", &dev, &sysctl_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl kern.development failed");
	if (dev == 0) {
		T_SKIP("Skipping test on release kernel");
	}

	testpath_buf_size = sizeof(testpath);
	ret = _NSGetExecutablePath(testpath, &testpath_buf_size);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "_NSGetExecutablePath");
	T_LOG("Executable path: %s", testpath);

	sysctl_size = sizeof(mem);
	ret = sysctlbyname("hw.memsize", &mem, &sysctl_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl hw.memsize failed");
	T_LOG("hw.memsize: %llu", mem);

	sysctl_size = sizeof(pgsz);
	ret = sysctlbyname("vm.pagesize", &pgsz, &sysctl_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl vm.pagesize failed");
	T_LOG("vm.pagesize: %d", pgsz);

	sysctl_size = sizeof(pages);
	ret = sysctlbyname("vm.pages", &pages, &sysctl_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl vm.pages failed");
	T_LOG("vm.pages: %d", pages);

	sysctl_size = sizeof(old_limit);
	ret = sysctlbyname("kern.zone_map_jetsam_limit", &old_limit, &sysctl_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl kern.zone_map_jetsam_limit failed");
	T_LOG("kern.zone_map_jetsam_limit: %d", old_limit);

	initial_zone_occupancy = query_zone_map_size();

	/* On large memory systems, set the zone_map jetsam limit lower so we can hit it without timing out. */
	if (mem > (uint64_t)LARGE_MEM_GB * 1024 * 1024 * 1024) {
		new_limit = LARGE_MEM_JETSAM_LIMIT;
	}

	/*
	 * If we start out with the zone map < 5% full, aim for 10% as the limit, so we don't time out.
	 * For anything else aim for 2x the initial size, capped by whatever value was set by T_META_SYSCTL_INT,
	 * or LARGE_MEM_JETSAM_LIMIT for large memory systems.
	 */
	if (initial_zone_occupancy < 5) {
		new_limit = JETSAM_LIMIT_LOWEST;
	} else {
		new_limit = initial_zone_occupancy * 2;
	}

	if (new_limit > 0 && new_limit < old_limit) {
		/*
		 * We should be fine messing with the zone_map_jetsam_limit here, i.e. outside of T_META_SYSCTL_INT.
		 * When the test ends, T_META_SYSCTL_INT will restore the zone_map_jetsam_limit to what it was
		 * before the test anyway.
		 */
		ret = sysctlbyname("kern.zone_map_jetsam_limit", NULL, NULL, &new_limit, sizeof(new_limit));
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl kern.zone_map_jetsam_limit failed");
		T_LOG("kern.zone_map_jetsam_limit set to %d%%", new_limit);
	}

	zone_info_array = (mach_zone_info_array_t) calloc((unsigned long)current_test.num_zones, sizeof *zone_info_array);

	/*
	 * If the timeout specified by T_META_TIMEOUT is hit, the atend handler does not get called.
	 * So we're queueing a dispatch block to fire after TIMEOUT_SECS seconds, so we can exit cleanly.
	 */
	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, TIMEOUT_SECS * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
		T_ASSERT_FAIL("Timed out after %d seconds", TIMEOUT_SECS);
	});

	/*
	 * Create a dispatch source for the signal SIGUSR1. When a child is done allocating zone memory, it
	 * sends SIGUSR1 to the parent. Only then does the parent spawn another child. This prevents us from
	 * spawning many children at once and creating a lot of memory pressure.
	 */
	signal(SIGUSR1, SIG_IGN);
	dq_spawn = dispatch_queue_create("spawn_queue", DISPATCH_QUEUE_SERIAL);
	ds_signal = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, dq_spawn);
	T_QUIET; T_ASSERT_NOTNULL(ds_signal, "dispatch_source_create: signal");

	dispatch_source_set_event_handler(ds_signal, ^{
		(void)query_zone_map_size();

		/* Wait a few seconds before spawning another child. Keeps us from allocating too aggressively */
		sleep(5);
		spawn_child_process();
	});
	dispatch_activate(ds_signal);

	/* Timer to query jetsam-relevant zone info every second. Print it every 5 seconds. */
	ds_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_queue_create("timer_queue", NULL));
	T_QUIET; T_ASSERT_NOTNULL(ds_timer, "dispatch_source_create: timer");
	dispatch_source_set_timer(ds_timer, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC), NSEC_PER_SEC, 0);

	dispatch_source_set_event_handler(ds_timer, ^{
		query_zone_info();
	});
	dispatch_activate(ds_timer);

	/* Set up a ktrace session to listen for jetsam events */
	setup_ktrace_session();

	T_SETUPEND;

	/* Spawn the first child process */
	T_LOG("Spawning child processes to allocate zone memory...\n\n");
	spawn_child_process();

	dispatch_main();
}

static void
move_to_idle_band(void)
{
	memorystatus_priority_properties_t props;

	/*
	 * We want to move the processes we spawn into the idle band, so that jetsam can target them first.
	 * This prevents other important BATS tasks from getting killed, specially in LTE where we have very few
	 * processes running.
	 *
	 * This is only needed for tests which (are likely to) lead us down the generic jetsam path.
	 */
	props.priority = JETSAM_PRIORITY_IDLE;
	props.user_data = 0;

	if (memorystatus_control(MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES, getpid(), 0, &props, sizeof(props))) {
		printf("memorystatus call to change jetsam priority failed\n");
		exit(-1);
	}
}

T_HELPER_DECL(allocate_vm_regions, "allocates VM regions")
{
	move_to_idle_band();
	allocate_vm_stuff(REGIONS);
}

T_HELPER_DECL(allocate_vm_objects, "allocates VM objects and VM regions")
{
	move_to_idle_band();
	allocate_vm_stuff(OBJECTS);
}

T_HELPER_DECL(allocate_from_generic_zone, "allocates from a generic zone")
{
	move_to_idle_band();
	allocate_from_generic_zone();
}

/*
 * T_META_SYSCTL_INT(ZONEMAP_JETSAM_LIMIT_SYSCTL) changes the zone_map_jetsam_limit to a
 * lower value, so that the test can complete faster.
 * The test allocates zone memory pretty aggressively which can cause the system to panic
 * if the jetsam limit is quite high; a lower value keeps us from panicking.
 */
T_DECL( memorystatus_vme_zone_test,
    "allocates elements from the VM map entries zone, verifies zone-map-exhaustion jetsams",
    T_META_ASROOT(true),
    T_META_TIMEOUT(1800),
/*		T_META_LTEPHASE(LTE_POSTINIT),
 */
    T_META_SYSCTL_INT(ZONEMAP_JETSAM_LIMIT_SYSCTL))
{
	current_test = (test_config_struct) {
		.test_index = VME_ZONE_TEST,
		.helper_func = VME_ZONE_TEST_OPT,
		.num_zones = 1,
		.zone_names = (mach_zone_name_t[]){
			{ .mzn_name = VME_ZONE }
		}
	};
	run_test();
}

T_DECL( memorystatus_vm_objects_zone_test,
    "allocates elements from the VM objects and the VM map entries zones, verifies zone-map-exhaustion jetsams",
    T_META_ASROOT(true),
    T_META_TIMEOUT(1800),
/*		T_META_LTEPHASE(LTE_POSTINIT),
 */
    T_META_SYSCTL_INT(ZONEMAP_JETSAM_LIMIT_SYSCTL))
{
	current_test = (test_config_struct) {
		.test_index = VM_OBJECTS_ZONE_TEST,
		.helper_func = VM_OBJECTS_ZONE_TEST_OPT,
		.num_zones = 2,
		.zone_names = (mach_zone_name_t[]){
			{ .mzn_name = VME_ZONE },
			{ .mzn_name = VMOBJECTS_ZONE}
		}
	};
	run_test();
}

T_DECL( memorystatus_generic_zone_test,
    "allocates elements from a zone that doesn't have an optimized jetsam path, verifies zone-map-exhaustion jetsams",
    T_META_ASROOT(true),
    T_META_TIMEOUT(1800),
/*		T_META_LTEPHASE(LTE_POSTINIT),
 */
    T_META_SYSCTL_INT(ZONEMAP_JETSAM_LIMIT_SYSCTL))
{
	current_test = (test_config_struct) {
		.test_index = GENERIC_ZONE_TEST,
		.helper_func = GENERIC_ZONE_TEST_OPT,
		.num_zones = 0,
		.zone_names = NULL
	};
	run_test();
}
