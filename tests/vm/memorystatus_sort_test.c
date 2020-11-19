#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <sys/sysctl.h>

#include <darwintest.h>
#include <dispatch/dispatch.h>
#include <mach-o/dyld.h>

/* internal */
#include <spawn_private.h>
#include <sys/coalition.h>
#include <sys/kern_memorystatus.h>

#define JETSAM_PRIORITY_IDLE 0
#define JETSAM_PRIORITY_FOREGROUND 10

#define kNumProcsInCoalition 4
typedef struct {
	pid_t pids[kNumProcsInCoalition]; // An array of pids in this coalition. Owned by this struct.
	pid_t expected_order[kNumProcsInCoalition]; // An array of pids in this coalition in proper sorted order.
	uint64_t ids[COALITION_NUM_TYPES];
} coalition_info_t;

/*
 * Children pids spawned by this test that need to be cleaned up.
 * Has to be a global because the T_ATEND API doesn't take any arguments.
 */
#define kMaxChildrenProcs 16
static pid_t children_pids[kMaxChildrenProcs];
static size_t num_children = 0;

/*
 * Sets up a new coalition.
 */
static void init_coalition(coalition_info_t*);

/*
 * Places all procs in the coalition in the given band.
 */
static void place_coalition_in_band(const coalition_info_t *, int band);

/*
 * Place the given proc in the given band.
 */
static void place_proc_in_band(pid_t pid, int band);

/*
 * Cleans up any children processes.
 */
static void cleanup_children(void);

/*
 * Check if we're on a kernel where we can test coalitions.
 */
static bool has_unrestrict_coalitions(void);

/*
 * Unrestrict coalition syscalls.
 */
static void unrestrict_coalitions(void);

/*
 * Restrict coalition syscalls
 */
static void restrict_coalitions(void);

/*
 * Allocate the requested number of pages and fault them in.
 * Used to achieve a desired footprint.
 */
static void *allocate_pages(int);

/*
 * Get the vm page size.
 */
static int get_vmpage_size(void);

/*
 * Launch a proc with a role in a coalition.
 * If coalition_ids is NULL, skip adding the proc to the coalition.
 */
static pid_t
launch_proc_in_coalition(uint64_t *coalition_ids, int role, int num_pages);

/*
 * Background process that will munch some memory, signal its parent, and
 * then sit in a loop.
 */
T_HELPER_DECL(coalition_member, "Mock coalition member") {
	int num_pages = 0;
	if (argc == 1) {
		num_pages = atoi(argv[0]);
	}
	allocate_pages(num_pages);
	// Signal to the parent that we've touched all of our pages.
	if (kill(getppid(), SIGUSR1) != 0) {
		T_LOG("Unable to signal to parent process!");
		exit(1);
	}
	while (true) {
		;
	}
}

/*
 * Test that sorting the fg bucket in coalition order works properly.
 * Spawns children in the same coalition in the fg band. Each child
 * has a different coalition role. Verifies that the coalition
 * is sorted properly by role.
 */
T_DECL(memorystatus_sort_coalition, "Coalition sort order",
    T_META_ASROOT(true)) {
	int ret;
	sig_t res;
	coalition_info_t coalition;
	if (!has_unrestrict_coalitions()) {
		T_SKIP("Unable to test coalitions on this kernel.");
	}
	res = signal(SIGUSR1, SIG_IGN);
	T_WITH_ERRNO; T_ASSERT_NE(res, SIG_ERR, "SIG_IGN SIGUSR1");
	unrestrict_coalitions();

	// Set up a new coalition with various members.
	init_coalition(&coalition);
	T_ATEND(cleanup_children);
	T_ATEND(restrict_coalitions);
	// Place all procs in the coalition in the foreground band
	place_coalition_in_band(&coalition, JETSAM_PRIORITY_FOREGROUND);
	// Have the kernel sort the foreground bucket and verify that it's
	// sorted correctly.
	ret = memorystatus_control(MEMORYSTATUS_CMD_TEST_JETSAM_SORT, JETSAM_PRIORITY_FOREGROUND, 0,
	    coalition.expected_order, kNumProcsInCoalition * sizeof(pid_t));
	T_QUIET; T_ASSERT_EQ(ret, 0, "Error while sorting or validating sorted order.\n"
	    "Check os log output for details.\n"
	    "Look for memorystatus_verify_sort_order.");
}

/*
 * Test that sorting the idle bucket in footprint order works properly.
 *
 * Spawns some children with very different footprints in the idle band,
 * and then ensures that they get sorted properly.
 */
T_DECL(memorystatus_sort_footprint, "Footprint sort order",
    T_META_ASROOT(true)) {
#define kNumChildren 3
	static const int kChildrenFootprints[kNumChildren] = {500, 0, 2500};
	/*
	 * The expected sort order of the children in the order that they were launched.
	 * Used to construct the expected_order pid array.
	 * Note that procs should be sorted in descending footprint order.
	 */
	static const int kExpectedOrder[kNumChildren] = {2, 0, 1};
	static const int kJetsamBand = JETSAM_PRIORITY_IDLE;
	__block pid_t pid;
	 sig_t res;
	dispatch_source_t ds_allocated;
	T_ATEND(cleanup_children);

	// After we spawn the children, they'll signal that they've touched their pages.
	res = signal(SIGUSR1, SIG_IGN);
	T_WITH_ERRNO; T_ASSERT_NE(res, SIG_ERR, "SIG_IGN SIGUSR1");
	ds_allocated = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, dispatch_get_main_queue());
	T_QUIET; T_ASSERT_NOTNULL(ds_allocated, "dispatch_source_create (ds_allocated)");

	dispatch_source_set_event_handler(ds_allocated, ^{
		if (num_children < kNumChildren) {
			pid = launch_proc_in_coalition(NULL, 0, kChildrenFootprints[num_children]);
			place_proc_in_band(pid, kJetsamBand);
		} else {
			pid_t expected_order[kNumChildren] = {0};
			int ret;
			for (int i = 0; i < kNumChildren; i++) {
				expected_order[i] = children_pids[kExpectedOrder[i]];
			}
			// Verify the sort order
			ret = memorystatus_control(MEMORYSTATUS_CMD_TEST_JETSAM_SORT, kJetsamBand, 0,
			expected_order, sizeof(expected_order));
			T_QUIET; T_ASSERT_EQ(ret, 0, "Error while sorting or validating sorted order.\n"
			    "Check os log output for details.\n"
			    "Look for memorystatus_verify_sort_order.");
			T_END;
		}
	});
	dispatch_activate(ds_allocated);

	pid = launch_proc_in_coalition(NULL, 0, kChildrenFootprints[num_children]);
	place_proc_in_band(pid, kJetsamBand);

	dispatch_main();

#undef kNumChildren
}

static pid_t
launch_proc_in_coalition(uint64_t *coalition_ids, int role, int num_pages)
{
	int ret;
	posix_spawnattr_t attr;
	pid_t pid;
	char testpath[PATH_MAX];
	uint32_t testpath_buf_size = PATH_MAX;
	char num_pages_str[32] = {0};
	char *argv[5] = {testpath, "-n", "coalition_member", num_pages_str, NULL};
	extern char **environ;
	T_QUIET; T_ASSERT_LT(num_children + 1, (size_t) kMaxChildrenProcs, "Don't create too many children.");
	ret = posix_spawnattr_init(&attr);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_init");
	if (coalition_ids != NULL) {
		for (int i = 0; i < COALITION_NUM_TYPES; i++) {
			ret = posix_spawnattr_setcoalition_np(&attr, coalition_ids[i], i, role);
			T_QUIET; T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_setcoalition_np");
		}
	}

	ret = snprintf(num_pages_str, sizeof(num_pages_str), "%d", num_pages);
	T_QUIET; T_ASSERT_LE((size_t) ret, sizeof(num_pages_str), "Don't allocate too many pages.");
	ret = _NSGetExecutablePath(testpath, &testpath_buf_size);
	T_QUIET; T_ASSERT_EQ(ret, 0, "_NSGetExecutablePath");
	ret = posix_spawn(&pid, argv[0], NULL, &attr, argv, environ);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "posix_spawn");
	ret = posix_spawnattr_destroy(&attr);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_destroy");
	children_pids[num_children++] = pid;
	return pid;
}

static void
init_coalition(coalition_info_t *coalition)
{
	int ret;
	uint32_t flags = 0;
	memset(coalition, 0, sizeof(coalition_info_t));
	for (int i = 0; i < COALITION_NUM_TYPES; i++) {
		COALITION_CREATE_FLAGS_SET_TYPE(flags, i);
		ret = coalition_create(&coalition->ids[i], flags);
		T_QUIET; T_ASSERT_POSIX_ZERO(ret, "coalition_create");
	}

	/*
	 * Spawn procs for each coalition role, and construct the expected
	 * sorted order.
	 */
	for (size_t i = 0; i < kNumProcsInCoalition; i++) {
		int role;
		if (i == 0) {
			role = COALITION_TASKROLE_LEADER;
		} else if (i == 1) {
			role = COALITION_TASKROLE_EXT;
		} else if (i == 2) {
			role = COALITION_TASKROLE_UNDEF;
		} else {
			role = COALITION_TASKROLE_XPC;
		}
		pid_t pid = launch_proc_in_coalition(coalition->ids, role, 0);
		coalition->pids[i] = pid;
		/*
		 * Determine the expected sorted order.
		 * After a bucket has been coalition sorted, coalition members should
		 * be in the following kill order:
		 * undefined coalition members, extensions, xpc services, leader
		 */
		if (role == COALITION_TASKROLE_LEADER) {
			coalition->expected_order[3] = pid;
		} else if (role == COALITION_TASKROLE_XPC) {
			coalition->expected_order[2] = pid;
		} else if (role == COALITION_TASKROLE_EXT) {
			coalition->expected_order[1] = pid;
		} else {
			coalition->expected_order[0] = pid;
		}
	}
}

static void
place_proc_in_band(pid_t pid, int band)
{
	memorystatus_priority_properties_t props = {0};
	int ret;
	props.priority = band;
	props.user_data = 0;
	ret = memorystatus_control(MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES, pid, 0, &props, sizeof(props));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "move proc to band");
}


static void
place_coalition_in_band(const coalition_info_t *coalition, int band)
{
	for (size_t i = 0; i < kNumProcsInCoalition; i++) {
		pid_t curr = coalition->pids[i];
		place_proc_in_band(curr, band);
	}
}

static void
cleanup_children(void)
{
	int ret, status;
	for (size_t i = 0; i < num_children; i++) {
		pid_t exited_pid = 0;
		pid_t curr = children_pids[i];
		ret = kill(curr, SIGKILL);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kill");
		while (exited_pid == 0) {
			exited_pid = waitpid(curr, &status, 0);
		}
		T_QUIET; T_ASSERT_POSIX_SUCCESS(exited_pid, "waitpid");
		T_QUIET; T_ASSERT_TRUE(WIFSIGNALED(status), "proc was signaled.");
		T_QUIET; T_ASSERT_EQ(WTERMSIG(status), SIGKILL, "proc was killed");
	}
}

static bool
has_unrestrict_coalitions()
{
	int ret, val;
	size_t val_sz;

	val = 0;
	val_sz = sizeof(val);
	ret = sysctlbyname("kern.unrestrict_coalitions", &val, &val_sz, NULL, 0);
	return ret >= 0;
}

static void
unrestrict_coalitions()
{
	int ret, val = 1;
	size_t val_sz;
	val_sz = sizeof(val);
	ret = sysctlbyname("kern.unrestrict_coalitions", NULL, 0, &val, val_sz);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kern.unrestrict_coalitions <- 1");
}

static void
restrict_coalitions()
{
	int ret, val = 0;
	size_t val_sz;
	val_sz = sizeof(val);
	ret = sysctlbyname("kern.unrestrict_coalitions", NULL, 0, &val, val_sz);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kern.unrestrict_coalitions <- 0");
}

static void *
allocate_pages(int num_pages)
{
	int page_size, i;
	unsigned char *buf;

	page_size = get_vmpage_size();
	buf = malloc((unsigned long)(num_pages * page_size));
	for (i = 0; i < num_pages; i++) {
		((volatile unsigned char *)buf)[i * page_size] = 1;
	}
	return buf;
}

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
