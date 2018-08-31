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

#define TIMEOUT_SECS                			1500

#if TARGET_OS_EMBEDDED
#define ALLOCATION_SIZE_VM_REGION				(16*1024)		/* 16 KB */
#define ALLOCATION_SIZE_VM_OBJECT				ALLOCATION_SIZE_VM_REGION
#else
#define ALLOCATION_SIZE_VM_REGION				(1024*1024*100)	/* 100 MB */
#define ALLOCATION_SIZE_VM_OBJECT				(16*1024)		/* 16 KB */
#endif
#define MAX_CHILD_PROCS             			100

#define ZONEMAP_JETSAM_LIMIT_SYSCTL 			"kern.zone_map_jetsam_limit=60"

#define VME_ZONE_TEST_OPT           			"allocate_vm_regions"
#define VM_OBJECTS_ZONE_TEST_OPT    			"allocate_vm_objects"
#define GENERIC_ZONE_TEST_OPT       			"allocate_from_generic_zone"

#define VME_ZONE								"VM map entries"
#define VMOBJECTS_ZONE							"vm objects"
#define VMENTRY_TO_VMOBJECT_COMPARISON_RATIO	98

#define VM_TAG1									100
#define VM_TAG2									101

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
static int num_children = 0;
static bool test_ending = false;
static bool within_dispatch_signal_handler = false;
static bool within_dispatch_timer_handler = false;
static dispatch_source_t ds_signal = NULL;
static dispatch_source_t ds_timer = NULL;
static ktrace_session_t session = NULL;

static mach_zone_info_array_t zone_info_array = NULL;
static mach_zone_name_t largest_zone_name;
static mach_zone_info_t largest_zone_info;

static char testpath[PATH_MAX];
static pid_t child_pids[MAX_CHILD_PROCS];
static pthread_mutex_t test_ending_mtx;

static void allocate_vm_regions(void);
static void allocate_vm_objects(void);
static void allocate_from_generic_zone(void);
static void cleanup_and_end_test(void);
static void setup_ktrace_session(void);
static void spawn_child_process(void);
static void run_test(void);
static bool verify_generic_jetsam_criteria(void);
static bool vme_zone_compares_to_vm_objects(void);
static void print_zone_map_size(void);
static void query_zone_info(void);
static void print_zone_info(mach_zone_name_t *zn, mach_zone_info_t *zi);

extern void mach_zone_force_gc(host_t host);
extern kern_return_t mach_zone_info_for_largest_zone(
	host_priv_t host,
	mach_zone_name_t *name,
	mach_zone_info_t *info
);

static void allocate_vm_regions(void)
{
	uint64_t alloc_size = ALLOCATION_SIZE_VM_REGION, i = 0;

	printf("[%d] Allocating VM regions, each of size %lld KB\n", getpid(), (alloc_size>>10));
	for (i = 0; ; i++) {
		mach_vm_address_t addr = (mach_vm_address_t)NULL;

		/* Alternate VM tags between consecutive regions to prevent coalescing */
		int flags = VM_MAKE_TAG((i % 2)? VM_TAG1: VM_TAG2) | VM_FLAGS_ANYWHERE;

		if ((mach_vm_allocate(mach_task_self(), &addr, (mach_vm_size_t)alloc_size, flags)) != KERN_SUCCESS) {
			break;
		}
	}
	printf("[%d] Number of allocations: %lld\n", getpid(), i);

	/* Signal to the parent that we're done allocating */
	kill(getppid(), SIGUSR1);

	while (1) {
		pause();
	}
}

static void allocate_vm_objects(void)
{
	uint64_t alloc_size = ALLOCATION_SIZE_VM_OBJECT, i = 0;

	printf("[%d] Allocating VM regions, each of size %lld KB, each backed by a VM object\n", getpid(), (alloc_size>>10));
	for (i = 0; ; i++) {
		mach_vm_address_t addr = (mach_vm_address_t)NULL;

		/* Alternate VM tags between consecutive regions to prevent coalescing */
		int flags = VM_MAKE_TAG((i % 2)? VM_TAG1: VM_TAG2) | VM_FLAGS_ANYWHERE;

		if ((mach_vm_allocate(mach_task_self(), &addr, (mach_vm_size_t)alloc_size, flags)) != KERN_SUCCESS) {
			break;
		}
		/* Touch the region so the VM object can actually be created */
		*((int *)addr) = 0;
		/* OK to free this page. Keeps us from holding a lot of dirty pages */
		madvise((void *)addr, (size_t)alloc_size, MADV_FREE);
	}
	printf("[%d] Number of allocations: %lld\n", getpid(), i);

	/* Signal to the parent that we're done allocating */
	kill(getppid(), SIGUSR1);

	while (1) {
		pause();
	}
}

static void allocate_from_generic_zone(void)
{
	uint64_t i = 0;

	printf("[%d] Allocating mach_ports\n", getpid());
	for (i = 0; ; i++) {
		mach_port_t port;

		if ((mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port)) != KERN_SUCCESS) {
			break;
		}
	}
	printf("[%d] Number of allocations: %lld\n", getpid(), i);

	/* Signal to the parent that we're done allocating */
	kill(getppid(), SIGUSR1);

	while (1) {
		pause();
	}
}

static void print_zone_info(mach_zone_name_t *zn, mach_zone_info_t *zi)
{
	T_LOG("ZONE NAME: %-35sSIZE: %-25lluELEMENTS: %llu",
			zn->mzn_name, zi->mzi_cur_size, zi->mzi_count);
}

static void query_zone_info(void)
{
	int i;
	kern_return_t kr;
	static uint64_t num_calls = 0;

	for (i = 0; i < current_test.num_zones; i++) {
		kr = mach_zone_info_for_zone(mach_host_self(), current_test.zone_names[i], &(zone_info_array[i]));
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_zone_info_for_zone(%s) returned %d [%s]", current_test.zone_names[i].mzn_name, kr, mach_error_string(kr));
	}
	kr = mach_zone_info_for_largest_zone(mach_host_self(), &largest_zone_name, &largest_zone_info);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_zone_info_for_largest_zone returned %d [%s]", kr, mach_error_string(kr));

	num_calls++;
	if (num_calls % 10 != 0) {
		return;
	}

	/* Print out size and element count for zones relevant to the test */
	for (i = 0; i < current_test.num_zones; i++) {
		print_zone_info(&(current_test.zone_names[i]), &(zone_info_array[i]));
	}
}

static bool vme_zone_compares_to_vm_objects(void)
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

	T_LOG("# VM map entries as percentage of # vm objects = %llu", (vm_map_entry_element_count * 100)/ vm_object_element_count);
	if (vm_map_entry_element_count >= ((vm_object_element_count * VMENTRY_TO_VMOBJECT_COMPARISON_RATIO) / 100)) {
		T_LOG("Number of VM map entries is comparable to vm objects\n\n");
		return true;
	}
	T_LOG("Number of VM map entries is NOT comparable to vm objects\n\n");
	return false;
}

static bool verify_generic_jetsam_criteria(void)
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

static void cleanup_and_end_test(void)
{
	int i;

	/*
	 * The atend handler executes on a different dispatch queue.
	 * We want to do the cleanup only once.
	 */
	pthread_mutex_lock(&test_ending_mtx);
	if (test_ending) {
		pthread_mutex_unlock(&test_ending_mtx);
		return;
	}
	test_ending = true;
	pthread_mutex_unlock(&test_ending_mtx);

	T_LOG("Number of processes spawned: %d", num_children);
	T_LOG("Cleaning up...");

	/* Disable the timer that queries and prints zone info periodically */
	if (ds_timer != NULL && !within_dispatch_timer_handler) {
		dispatch_source_cancel(ds_timer);
	}

	/* Disable signal handler that spawns child processes, only if we're not in the event handler's context */
	if (ds_signal != NULL && !within_dispatch_signal_handler) {
		dispatch_source_cancel_and_wait(ds_signal);
	}

	/* Kill all the child processes that were spawned */
	for (i = 0; i < num_children; i++) {
		kill(child_pids[i], SIGKILL);
	}
	for (i = 0; i < num_children; i++) {
		int status = 0;
		if (waitpid(child_pids[i], &status, 0) < 0) {
			T_LOG("waitpid returned status %d", status);
		}
	}
	sleep(1);

	/* Force zone_gc before starting test for another zone or exiting */
	mach_zone_force_gc(mach_host_self());

	/* End ktrace session */
	if (session != NULL) {
		ktrace_end(session, 1);
	}

	for (i = 0; i < current_test.num_zones; i++) {
		print_zone_info(&(current_test.zone_names[i]), &(zone_info_array[i]));
	}
}

static void setup_ktrace_session(void)
{
	int ret = 0;

	T_LOG("Setting up ktrace session...");
	session = ktrace_session_create();
	T_QUIET; T_ASSERT_NOTNULL(session, "ktrace_session_create");

	ktrace_set_interactive(session);

	ktrace_set_completion_handler(session, ^{
		ktrace_session_destroy(session);
		T_END;
	});

	/* Listen for memorystatus_do_kill trace events */
	ret = ktrace_events_single(session, (BSDDBG_CODE(DBG_BSD_MEMSTAT, BSD_MEMSTAT_DO_KILL)) | DBG_FUNC_END, ^(ktrace_event_t event) {
		int i;
		bool received_jetsam_event = false;

		/* We don't care about jetsams for any other reason except zone-map-exhaustion */
		if (event->arg2 == kMemorystatusKilledZoneMapExhaustion) {
			cleanup_and_end_test();
			T_LOG("[memorystatus_do_kill] jetsam reason: zone-map-exhaustion, pid: %lu\n\n", event->arg1);
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
				for (i = 0; i < num_children; i++) {
					if (child_pids[i] == (pid_t)event->arg1) {
						received_jetsam_event = true;
						break;
					}
				}
				/*
				 * If we didn't see a targeted jetsam, verify that the largest zone actually
				 * fulfilled the criteria for generic jetsams.
				 */
				if (!received_jetsam_event && verify_generic_jetsam_criteria()) {
					received_jetsam_event = true;
				}
			} else {
				received_jetsam_event = true;
			}

			T_ASSERT_TRUE(received_jetsam_event, "Received zone-map-exhaustion jetsam event as expected");
		}
	});
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "ktrace_events_single");

	ret = ktrace_start(session, dispatch_get_main_queue());
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "ktrace_start");
}

static void print_zone_map_size(void)
{
	int ret;
	uint64_t zstats[2];
	size_t zstats_size = sizeof(zstats);

	ret = sysctlbyname("kern.zone_map_size_and_capacity", &zstats, &zstats_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl kern.zone_map_size_and_capacity failed");

	T_LOG("Zone map capacity: %-30lldZone map size: %lld [%lld%% full]", zstats[1], zstats[0], (zstats[0] * 100)/zstats[1]);
}

static void spawn_child_process(void)
{
	pid_t pid = -1;
	char helper_func[50];
	char *launch_tool_args[4];

	T_QUIET; T_ASSERT_LT(num_children, MAX_CHILD_PROCS, "Spawned %d children. Timing out...", MAX_CHILD_PROCS);

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

static void run_test(void)
{
	uint64_t mem;
	uint32_t testpath_buf_size, pages;
	int ret, dev, pgsz;
	size_t sysctl_size;

	T_ATEND(cleanup_and_end_test);
	T_SETUPBEGIN;

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

	zone_info_array = (mach_zone_info_array_t) calloc((unsigned long)current_test.num_zones, sizeof *zone_info_array);

	print_zone_map_size();

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
	ds_signal = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, dispatch_get_main_queue());
	T_QUIET; T_ASSERT_NOTNULL(ds_signal, "dispatch_source_create: signal");

	dispatch_source_set_event_handler(ds_signal, ^{
		within_dispatch_signal_handler = true;
		print_zone_map_size();

		/* Wait a few seconds before spawning another child. Keeps us from allocating too aggressively */
		sleep(5);
		spawn_child_process();
		within_dispatch_signal_handler = false;
	});
	dispatch_activate(ds_signal);

	/* Timer to query jetsam-relevant zone info every second. Print it every 10 seconds. */
	ds_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_queue_create("timer_queue", NULL));
	T_QUIET; T_ASSERT_NOTNULL(ds_timer, "dispatch_source_create: timer");
    dispatch_source_set_timer(ds_timer, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC), NSEC_PER_SEC, 0);

	dispatch_source_set_event_handler(ds_timer, ^{
		within_dispatch_timer_handler = true;
		query_zone_info();
		within_dispatch_timer_handler = false;
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

static void move_to_idle_band(void)
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
	allocate_vm_regions();
}

T_HELPER_DECL(allocate_vm_objects, "allocates VM objects and VM regions")
{
	move_to_idle_band();
	allocate_vm_objects();
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
T_DECL(	memorystatus_vme_zone_test,
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
		.zone_names = (mach_zone_name_t []){
			{ .mzn_name = VME_ZONE }
		}
	};
	run_test();
}

T_DECL(	memorystatus_vm_objects_zone_test,
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
		.zone_names = (mach_zone_name_t []){
			{ .mzn_name = VME_ZONE },
			{ .mzn_name = VMOBJECTS_ZONE}
		}
	};
	run_test();
}

T_DECL(	memorystatus_generic_zone_test,
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
