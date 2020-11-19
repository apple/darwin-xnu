/* Mach virtual memory unit tests
 *
 * The main goal of this code is to facilitate the construction,
 * running, result logging and clean up of a test suite, taking care
 * of all the scaffolding. A test suite is a sequence of very targeted
 * unit tests, each running as a separate process to isolate its
 * address space.
 * A unit test is abstracted as a unit_test_t structure, consisting of
 * a test function and a logging identifier. A test suite is a suite_t
 * structure, consisting of an unit_test_t array, fixture set up and
 * tear down functions.
 * Test suites are created dynamically. Each of its unit test runs in
 * its own fork()d process, with the fixture set up and tear down
 * running before and after each test. The parent process will log a
 * pass result if the child exits normally, and a fail result in any
 * other case (non-zero exit status, abnormal signal). The suite
 * results are then aggregated and logged after the [SUMMARY] keyword,
 * and finally the test suite is destroyed.
 * The included test suites cover the Mach memory allocators,
 * mach_vm_allocate() and mach_vm_map() with various options, and
 * mach_vm_deallocate(), mach_vm_read(), mach_vm_write(),
 * mach_vm_protect(), mach_vm_copy().
 *
 * Author: Renaud Dreyer (rdreyer@apple.com)
 *
 * Transformed to libdarwintest by Tristan Ye (tristan_ye@apple.com) */

#include <darwintest.h>

#include <stdlib.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <math.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>
#include <time.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.vm"));

/**************************/
/**************************/
/* Unit Testing Framework */
/**************************/
/**************************/

/*********************/
/* Private interface */
/*********************/

static const char frameworkname[] = "vm_unitester";

/* Type for test, fixture set up and fixture tear down functions. */
typedef void (*test_fn_t)();

/* Unit test structure. */
typedef struct {
	const char * name;
	test_fn_t test;
} unit_test_t;

/* Test suite structure. */
typedef struct {
	const char * name;
	int numoftests;
	test_fn_t set_up;
	unit_test_t * tests;
	test_fn_t tear_down;
} suite_t;

int _quietness        = 0;
int _expected_signal  = 0;

struct {
	uintmax_t numoftests;
	uintmax_t passed_tests;
} results = {0, 0};

#define logr(format, ...) \
	do { \
	        if (_quietness <= 1) { \
	                T_LOG(format, ## __VA_ARGS__); \
	        } \
	} while (0)

#define logv(format, ...) \
	do { \
	        if (_quietness == 0) { \
	                T_LOG(format, ## __VA_ARGS__); \
	        } \
	} while (0)

static suite_t *
create_suite(const char * name, int numoftests, test_fn_t set_up, unit_test_t * tests, test_fn_t tear_down)
{
	suite_t * suite = (suite_t *)malloc(sizeof(suite_t));
	T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(suite, "malloc()");

	suite->name       = name;
	suite->numoftests = numoftests;
	suite->set_up     = set_up;
	suite->tests      = tests;
	suite->tear_down  = tear_down;
	return suite;
}

static void
destroy_suite(suite_t * suite)
{
	free(suite);
}

static void
log_suite_info(suite_t * suite)
{
	logr("[TEST] %s", suite->name);
	logr("Number of tests: %d\n", suite->numoftests);
}

static void
log_suite_results(suite_t * suite, int passed_tests)
{
	results.numoftests += (uintmax_t)suite->numoftests;
	results.passed_tests += (uintmax_t)passed_tests;
}

static void
log_test_info(unit_test_t * unit_test, unsigned test_num)
{
	logr("[BEGIN] #%04d: %s", test_num, unit_test->name);
}

static void
log_test_result(unit_test_t * unit_test, boolean_t test_passed, unsigned test_num)
{
	logr("[%s] #%04d: %s\n", test_passed ? "PASS" : "FAIL", test_num, unit_test->name);
}

/* Run a test with fixture set up and teardown, while enforcing the
 * time out constraint. */
static void
run_test(suite_t * suite, unit_test_t * unit_test, unsigned test_num)
{
	log_test_info(unit_test, test_num);

	suite->set_up();
	unit_test->test();
	suite->tear_down();
}

/* Check a child return status. */
static boolean_t
child_terminated_normally(int child_status)
{
	boolean_t normal_exit = FALSE;

	if (WIFEXITED(child_status)) {
		int exit_status = WEXITSTATUS(child_status);
		if (exit_status) {
			T_LOG("Child process unexpectedly exited with code %d.",
			    exit_status);
		} else if (!_expected_signal) {
			normal_exit = TRUE;
		}
	} else if (WIFSIGNALED(child_status)) {
		int signal = WTERMSIG(child_status);
		if (signal == _expected_signal ||
		    (_expected_signal == -1 && (signal == SIGBUS || signal == SIGSEGV))) {
			if (_quietness <= 0) {
				T_LOG("Child process died with expected signal "
				    "%d.", signal);
			}
			normal_exit = TRUE;
		} else {
			T_LOG("Child process unexpectedly died with signal %d.",
			    signal);
		}
	} else {
		T_LOG("Child process unexpectedly did not exit nor die");
	}

	return normal_exit;
}

/* Run a test in its own process, and report the result. */
static boolean_t
child_test_passed(suite_t * suite, unit_test_t * unit_test)
{
	int test_status;
	static unsigned test_num = 0;

	test_num++;

	pid_t test_pid = fork();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(test_pid, "fork()");
	if (!test_pid) {
		run_test(suite, unit_test, test_num);
		exit(0);
	}
	while (waitpid(test_pid, &test_status, 0) != test_pid) {
		continue;
	}
	boolean_t test_result = child_terminated_normally(test_status);
	log_test_result(unit_test, test_result, test_num);
	return test_result;
}

/* Run each test in a suite, and report the results. */
static int
count_passed_suite_tests(suite_t * suite)
{
	int passed_tests = 0;
	int i;

	for (i = 0; i < suite->numoftests; i++) {
		passed_tests += child_test_passed(suite, &(suite->tests[i]));
	}
	return passed_tests;
}

/********************/
/* Public interface */
/********************/

#define DEFAULT_QUIETNESS    0 /* verbose */
#define RESULT_ERR_QUIETNESS 1 /* result and error */
#define ERROR_ONLY_QUIETNESS 2 /* error only */

#define run_suite(set_up, tests, tear_down, ...) \
	_run_suite((sizeof(tests) / sizeof(tests[0])), (set_up), (tests), (tear_down), __VA_ARGS__)

typedef unit_test_t UnitTests[];

void _run_suite(int numoftests, test_fn_t set_up, UnitTests tests, test_fn_t tear_down, const char * format, ...)
__printflike(5, 6);

void
_run_suite(int numoftests, test_fn_t set_up, UnitTests tests, test_fn_t tear_down, const char * format, ...)
{
	va_list ap;
	char * name;

	va_start(ap, format);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(vasprintf(&name, format, ap), "vasprintf()");
	va_end(ap);
	suite_t * suite = create_suite(name, numoftests, set_up, tests, tear_down);
	log_suite_info(suite);
	log_suite_results(suite, count_passed_suite_tests(suite));
	free(name);
	destroy_suite(suite);
}

/* Setters and getters for various test framework global
 * variables. Should only be used outside of the test, set up and tear
 * down functions. */

/* Expected signal for a test, default is 0. */
void
set_expected_signal(int signal)
{
	_expected_signal = signal;
}

int
get_expected_signal()
{
	return _expected_signal;
}

/* Logging verbosity. */
void
set_quietness(int value)
{
	_quietness = value;
}

int
get_quietness()
{
	return _quietness;
}

/* For fixture set up and tear down functions, and units tests. */
void
do_nothing()
{
}

void
log_aggregated_results()
{
	T_LOG("[SUMMARY] Aggregated Test Results\n");
	T_LOG("Total: %ju", results.numoftests);
	T_LOG("Passed: %ju", results.passed_tests);
	T_LOG("Failed: %ju\n", results.numoftests - results.passed_tests);

	T_QUIET; T_ASSERT_EQ(results.passed_tests, results.numoftests,
	    "%d passed of total %d tests",
	    results.passed_tests, results.numoftests);
}

/*******************************/
/*******************************/
/* Virtual memory unit testing */
/*******************************/
/*******************************/

/* Test exit values:
 * 0: pass
 * 1: fail, generic unexpected failure
 * 2: fail, unexpected Mach return value
 * 3: fail, time out */

#define DEFAULT_VM_SIZE ((mach_vm_size_t)(1024ULL * 4096ULL))

#define POINTER(address) ((char *)(uintptr_t)(address))
#define MACH_VM_ADDRESS_T(address) (*((mach_vm_address_t *)(uintptr_t)(address)))

static int vm_address_size = sizeof(mach_vm_address_t);

static char *progname = "";

/*************************/
/* xnu version functions */
/*************************/

/* Find the xnu version string. */
char *
xnu_version_string()
{
	size_t length;
	int mib[2];
	mib[0] = CTL_KERN;
	mib[1] = KERN_VERSION;

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(sysctl(mib, 2, NULL, &length, NULL, 0), "sysctl()");
	char * version = (char *)malloc(length);
	T_QUIET;
	T_WITH_ERRNO;
	T_ASSERT_NOTNULL(version, "malloc()");
	T_QUIET;
	T_EXPECT_POSIX_SUCCESS(sysctl(mib, 2, version, &length, NULL, 0), "sysctl()");
	if (T_RESULT == T_RESULT_FAIL) {
		free(version);
		T_END;
	}
	char * xnu_string = strstr(version, "xnu-");
	free(version);
	T_QUIET;
	T_ASSERT_NOTNULL(xnu_string, "%s: error finding xnu version string.", progname);
	return xnu_string;
}

/* Find the xnu major version number. */
unsigned int
xnu_major_version()
{
	char * endptr;
	char * xnu_substring = xnu_version_string() + 4;

	errno                    = 0;
	unsigned int xnu_version = strtoul(xnu_substring, &endptr, 0);
	T_QUIET;
	T_ASSERT_TRUE((errno != ERANGE && endptr != xnu_substring),
	    "%s: error finding xnu major version number.", progname);
	return xnu_version;
}

/*************************/
/* Mach assert functions */
/*************************/

static inline void
assert_mach_return(kern_return_t kr, kern_return_t expected_kr, const char * mach_routine)
{
	T_QUIET; T_ASSERT_EQ(kr, expected_kr,
	    "%s unexpectedly returned: %s."
	    "Should have returned: %s.",
	    mach_routine, mach_error_string(kr),
	    mach_error_string(expected_kr));
}

/*******************************/
/* Arrays for test suite loops */
/*******************************/

/* Memory allocators */
typedef kern_return_t (*allocate_fn_t)(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);


/*
 * Remember any pre-reserved fixed address, which needs to be released prior to an allocation.
 */
static mach_vm_address_t fixed_vm_address = 0x0;
static mach_vm_size_t fixed_vm_size = 0;

/* forward decl */
void assert_deallocate_success(mach_vm_address_t address, mach_vm_size_t size);

/*
 * If trying to allocate at a fixed address, we need to do the delayed deallocate first.
 */
static void
check_fixed_address(mach_vm_address_t *address, mach_vm_size_t size)
{
	if (fixed_vm_address != 0 &&
	    fixed_vm_address <= *address &&
	    *address + size <= fixed_vm_address + fixed_vm_size) {
		assert_deallocate_success(fixed_vm_address, fixed_vm_size);
		fixed_vm_address = 0;
		fixed_vm_size = 0;
	}
}

kern_return_t
wrapper_mach_vm_allocate(vm_map_t map, mach_vm_address_t * address, mach_vm_size_t size, int flags)
{
	check_fixed_address(address, size);
	return mach_vm_allocate(map, address, size, flags);
}

kern_return_t
wrapper_mach_vm_map(vm_map_t map, mach_vm_address_t * address, mach_vm_size_t size, int flags)
{
	check_fixed_address(address, size);
	return mach_vm_map(map, address, size, (mach_vm_offset_t)0, flags, MACH_PORT_NULL, (memory_object_offset_t)0, FALSE,
	           VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);
}

/* Should have the same behavior as when mask is zero. */
kern_return_t
wrapper_mach_vm_map_4kB(vm_map_t map, mach_vm_address_t * address, mach_vm_size_t size, int flags)
{
	check_fixed_address(address, size);
	return mach_vm_map(map, address, size, (mach_vm_offset_t)0xFFF, flags, MACH_PORT_NULL, (memory_object_offset_t)0, FALSE,
	           VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);
}

kern_return_t
wrapper_mach_vm_map_2MB(vm_map_t map, mach_vm_address_t * address, mach_vm_size_t size, int flags)
{
	check_fixed_address(address, size);
	return mach_vm_map(map, address, size, (mach_vm_offset_t)0x1FFFFF, flags, MACH_PORT_NULL, (memory_object_offset_t)0, FALSE,
	           VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);
}

mach_port_t
memory_entry(mach_vm_size_t * size)
{
	mach_port_t object_handle    = MACH_PORT_NULL;
	mach_vm_size_t original_size = *size;

	T_QUIET; T_ASSERT_MACH_SUCCESS(mach_make_memory_entry_64(mach_task_self(), size, (memory_object_offset_t)0,
	    (MAP_MEM_NAMED_CREATE | VM_PROT_ALL), &object_handle, 0),
	    "mach_make_memory_entry_64()");
	T_QUIET; T_ASSERT_EQ(*size, round_page_kernel(original_size),
	    "mach_make_memory_entry_64() unexpectedly returned a named "
	    "entry of size 0x%jx (%ju).\n"
	    "Should have returned a "
	    "named entry of size 0x%jx (%ju).",
	    (uintmax_t)*size, (uintmax_t)*size, (uintmax_t)original_size, (uintmax_t)original_size);
	return object_handle;
}

kern_return_t
wrapper_mach_vm_map_named_entry(vm_map_t map, mach_vm_address_t * address, mach_vm_size_t size, int flags)
{
	mach_port_t object_handle = memory_entry(&size);
	check_fixed_address(address, size);
	kern_return_t kr = mach_vm_map(map, address, size, (mach_vm_offset_t)0, flags, object_handle, (memory_object_offset_t)0, FALSE,
	    VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(mach_port_deallocate(mach_task_self(), object_handle), "mach_port_deallocate()");
	return kr;
}

static struct {
	allocate_fn_t allocate;
	const char * description;
} allocators[] = {
	{wrapper_mach_vm_allocate, "mach_vm_allocate()"},
	{wrapper_mach_vm_map, "mach_vm_map() (zero mask)"},
	{wrapper_mach_vm_map_4kB,
	 "mach_vm_map() "
	 "(4 kB address alignment)"},
	{wrapper_mach_vm_map_2MB,
	 "mach_vm_map() "
	 "(2 MB address alignment)"},
	{wrapper_mach_vm_map_named_entry,
	 "mach_vm_map() (named "
	 "entry, zero mask)"},
};
static int numofallocators = sizeof(allocators) / sizeof(allocators[0]);
static int allocators_idx;
enum { MACH_VM_ALLOCATE, MACH_VM_MAP, MACH_VM_MAP_4kB, MACH_VM_MAP_2MB, MACH_VM_MAP_NAMED_ENTRY };

/* VM size */
static struct {
	mach_vm_size_t size;
	const char * description;
} vm_sizes[] = {
	{DEFAULT_VM_SIZE, "default/input"},
	{0, "zero"},
	{4096ULL, "aligned"},
	{1ULL, "unaligned"},
	{4095ULL, "unaligned"},
	{4097ULL, "unaligned"},
};
static int numofsizes = sizeof(vm_sizes) / sizeof(vm_sizes[0]);
static int sizes_idx;
static int buffer_sizes_idx;
enum { DEFAULT_INPUT, ZERO_BYTES, ONE_PAGE, ONE_BYTE, ONE_PAGE_MINUS_ONE_BYTE, ONE_PAGE_AND_ONE_BYTE };

/* Unspecified/fixed address */
static struct {
	int flag;
	const char * description;
} address_flags[] = {
	{VM_FLAGS_ANYWHERE, "unspecified"}, {VM_FLAGS_FIXED, "fixed"},
};
static int numofflags = sizeof(address_flags) / sizeof(address_flags[0]);
static int flags_idx;
enum { ANYWHERE, FIXED };

/* Address alignment */
static struct {
	boolean_t alignment;
	const char * description;
} address_alignments[] = {
	{TRUE, " aligned"}, {FALSE, " unaligned"},
};
static int numofalignments = sizeof(address_alignments) / sizeof(*address_alignments);
static int alignments_idx;
enum { ALIGNED, UNALIGNED };

/* Buffer offset */
static struct {
	int offset;
	const char * description;
} buffer_offsets[] = {
	{0, ""}, {1, ""}, {2, ""},
};
static int numofoffsets = sizeof(buffer_offsets) / sizeof(buffer_offsets[0]);
static int offsets_idx;
enum { ZERO, ONE, TWO };

/* mach_vm_copy() post actions */
enum { VMCOPY_MODIFY_SRC, VMCOPY_MODIFY_DST, VMCOPY_MODIFY_SHARED_COPIED };

static struct {
	int action;
	const char * description;
} vmcopy_actions[] = {
	{VMCOPY_MODIFY_SRC, "modify vm_copy() source"},
	{VMCOPY_MODIFY_DST, "modify vm_copy() destination"},
	{VMCOPY_MODIFY_SHARED_COPIED,
	 "modify vm_copy source's shared "
	 "or copied from/to region"},
};
static int numofvmcopyactions = sizeof(vmcopy_actions) / sizeof(vmcopy_actions[0]);
static int vmcopy_action_idx;

/************************************/
/* Setters and getters for fixtures */
/************************************/

/* Allocation memory range. */
static allocate_fn_t _allocator      = wrapper_mach_vm_allocate;
static mach_vm_size_t _vm_size       = DEFAULT_VM_SIZE;
static int _address_flag             = VM_FLAGS_ANYWHERE;
static boolean_t _address_alignment  = TRUE;
static mach_vm_address_t _vm_address = 0x0;

/* Buffer for mach_vm_write(). */
static mach_vm_size_t _buffer_size       = DEFAULT_VM_SIZE;
static mach_vm_address_t _buffer_address = 0x0;
static int _buffer_offset                = 0;

/* Post action for mach_vm_copy(). */
static int _vmcopy_post_action = VMCOPY_MODIFY_SRC;

static void
set_allocator(allocate_fn_t allocate)
{
	_allocator = allocate;
}

static allocate_fn_t
get_allocator()
{
	return _allocator;
}

static void
set_vm_size(mach_vm_size_t size)
{
	_vm_size = size;
}

static mach_vm_size_t
get_vm_size()
{
	return _vm_size;
}

static void
set_address_flag(int flag)
{
	_address_flag = flag;
}

static int
get_address_flag()
{
	return _address_flag;
}

static void
set_address_alignment(boolean_t alignment)
{
	_address_alignment = alignment;
}

static boolean_t
get_address_alignment()
{
	return _address_alignment;
}

static void
set_vm_address(mach_vm_address_t address)
{
	_vm_address = address;
}

static mach_vm_address_t
get_vm_address()
{
	return _vm_address;
}

static void
set_buffer_size(mach_vm_size_t size)
{
	_buffer_size = size;
}

static mach_vm_size_t
get_buffer_size()
{
	return _buffer_size;
}

static void
set_buffer_address(mach_vm_address_t address)
{
	_buffer_address = address;
}

static mach_vm_address_t
get_buffer_address()
{
	return _buffer_address;
}

static void
set_buffer_offset(int offset)
{
	_buffer_offset = offset;
}

static int
get_buffer_offset()
{
	return _buffer_offset;
}

static void
set_vmcopy_post_action(int action)
{
	_vmcopy_post_action = action;
}

static int
get_vmcopy_post_action()
{
	return _vmcopy_post_action;
}

/*******************************/
/* Usage and option processing */
/*******************************/
static boolean_t flag_run_allocate_test = FALSE;
static boolean_t flag_run_deallocate_test = FALSE;
static boolean_t flag_run_read_test = FALSE;
static boolean_t flag_run_write_test = FALSE;
static boolean_t flag_run_protect_test = FALSE;
static boolean_t flag_run_copy_test = FALSE;

#define VM_TEST_ALLOCATE   0x00000001
#define VM_TEST_DEALLOCATE 0x00000002
#define VM_TEST_READ       0x00000004
#define VM_TEST_WRITE      0x00000008
#define VM_TEST_PROTECT    0x00000010
#define VM_TEST_COPY       0x00000020

typedef struct test_option {
	uint32_t        to_flags;
	int             to_quietness;
	mach_vm_size_t  to_vmsize;
} test_option_t;

typedef struct test_info {
	char            *ti_name;
	boolean_t       *ti_flag;
} test_info_t;

static test_option_t test_options;

enum {ALLOCATE = 0, DEALLOCATE, READ, WRITE, PROTECT, COPY};

static test_info_t test_info[] = {
	{"allocate", &flag_run_allocate_test},
	{"deallocate", &flag_run_deallocate_test},
	{"read", &flag_run_read_test},
	{"write", &flag_run_write_test},
	{"protect", &flag_run_protect_test},
	{"copy", &flag_run_copy_test},
	{NULL, NULL}
};

static void
die_on_invalid_value(int condition, const char * value_string)
{
	T_QUIET;
	T_ASSERT_EQ(condition, 0, "%s: invalid value: %s.",
	    progname, value_string);
}

static void
process_options(test_option_t options)
{
	test_info_t *tp;

	setvbuf(stdout, NULL, _IONBF, 0);

	set_vm_size(DEFAULT_VM_SIZE);
	set_quietness(DEFAULT_QUIETNESS);

	if (NULL != getenv("LTERDOS")) {
		logr("LTERDOS=YES this is LeanTestEnvironment\nIncreasing quietness by 1.");
		set_quietness(get_quietness() + 1);
	} else {
		if (options.to_quietness > 0) {
			set_quietness(options.to_quietness);
		}
	}

	if (options.to_vmsize != 0) {
		vm_sizes[0].size = options.to_vmsize;
	}

	if (options.to_flags == 0) {
		for (tp = test_info; tp->ti_name != NULL; ++tp) {
			*tp->ti_flag = TRUE;
		}
	} else {
		if (options.to_flags & VM_TEST_ALLOCATE) {
			*(test_info[ALLOCATE].ti_flag) = TRUE;
		}

		if (options.to_flags & VM_TEST_DEALLOCATE) {
			*(test_info[DEALLOCATE].ti_flag) = TRUE;
		}

		if (options.to_flags & VM_TEST_READ) {
			*(test_info[READ].ti_flag) = TRUE;
		}

		if (options.to_flags & VM_TEST_WRITE) {
			*(test_info[WRITE].ti_flag) = TRUE;
		}

		if (options.to_flags & VM_TEST_PROTECT) {
			*(test_info[PROTECT].ti_flag) = TRUE;
		}

		if (options.to_flags & VM_TEST_COPY) {
			*(test_info[COPY].ti_flag) = TRUE;
		}
	}
}

/*****************/
/* Various tools */
/*****************/

/* Find the allocator address alignment mask. */
mach_vm_address_t
get_mask()
{
	mach_vm_address_t mask;

	if (get_allocator() == wrapper_mach_vm_map_2MB) {
		mask = (mach_vm_address_t)0x1FFFFF;
	} else {
		mask = vm_page_size - 1;
	}
	return mask;
}

/* Find the size of the smallest aligned region containing a given
 * memory range. */
mach_vm_size_t
aligned_size(mach_vm_address_t address, mach_vm_size_t size)
{
	return round_page_kernel(address - mach_vm_trunc_page(address) + size);
}

/********************/
/* Assert functions */
/********************/

/* Address is aligned on allocator boundary. */
static inline void
assert_aligned_address(mach_vm_address_t address)
{
	T_QUIET; T_ASSERT_EQ((address & get_mask()), 0,
	    "Address 0x%jx is unexpectedly "
	    "unaligned.",
	    (uintmax_t)address);
}

/* Address is truncated to allocator boundary. */
static inline void
assert_trunc_address(mach_vm_address_t address, mach_vm_address_t trunc_address)
{
	T_QUIET; T_ASSERT_EQ(trunc_address, (address & ~get_mask()),
	    "Address "
	    "0x%jx is unexpectedly not truncated to address 0x%jx.",
	    (uintmax_t)address, (uintmax_t)trunc_address);
}

static inline void
assert_address_value(mach_vm_address_t address, mach_vm_address_t marker)
{
	/* this assert is used so frequently so that we simply judge on
	 * its own instead of leaving this to LD macro for efficiency
	 */
	if (MACH_VM_ADDRESS_T(address) != marker) {
		T_ASSERT_FAIL("Address 0x%jx unexpectedly has value 0x%jx, "
		    "instead of 0x%jx.", (uintmax_t)address,
		    (uintmax_t)MACH_VM_ADDRESS_T(address), (uintmax_t)marker);
	}
}

void
assert_allocate_return(mach_vm_address_t * address, mach_vm_size_t size, int address_flag, kern_return_t expected_kr)
{
	assert_mach_return(get_allocator()(mach_task_self(), address, size, address_flag), expected_kr, "Allocator");
}

void
assert_allocate_success(mach_vm_address_t * address, mach_vm_size_t size, int address_flag)
{
	assert_allocate_return(address, size, address_flag, KERN_SUCCESS);
}

void
assert_deallocate_return(mach_vm_address_t address, mach_vm_size_t size, kern_return_t expected_kr)
{
	assert_mach_return(mach_vm_deallocate(mach_task_self(), address, size), expected_kr, "mach_vm_deallocate()");
}

void
assert_deallocate_success(mach_vm_address_t address, mach_vm_size_t size)
{
	assert_deallocate_return(address, size, KERN_SUCCESS);
}

void
assert_read_return(mach_vm_address_t address,
    mach_vm_size_t size,
    vm_offset_t * data,
    mach_msg_type_number_t * data_size,
    kern_return_t expected_kr)
{
	assert_mach_return(mach_vm_read(mach_task_self(), address, size, data, data_size), expected_kr, "mach_vm_read()");
}

void
assert_read_success(mach_vm_address_t address, mach_vm_size_t size, vm_offset_t * data, mach_msg_type_number_t * data_size)
{
	assert_read_return(address, size, data, data_size, KERN_SUCCESS);
	T_QUIET; T_ASSERT_EQ(*data_size, size,
	    "Returned buffer size 0x%jx "
	    "(%ju) is unexpectedly different from source size 0x%jx "
	    "(%ju).",
	    (uintmax_t)*data_size, (uintmax_t)*data_size, (uintmax_t)size, (uintmax_t)size);
}

void
assert_write_return(mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t data_size, kern_return_t expected_kr)
{
	assert_mach_return(mach_vm_write(mach_task_self(), address, data, data_size), expected_kr, "mach_vm_write()");
}

void
assert_write_success(mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t data_size)
{
	assert_write_return(address, data, data_size, KERN_SUCCESS);
}

void
assert_allocate_copy_return(mach_vm_address_t source, mach_vm_size_t size, mach_vm_address_t * dest, kern_return_t expected_kr)
{
	assert_allocate_success(dest, size, VM_FLAGS_ANYWHERE);
	assert_mach_return(mach_vm_copy(mach_task_self(), source, size, *dest), expected_kr, "mach_vm_copy()");
}
void
assert_allocate_copy_success(mach_vm_address_t source, mach_vm_size_t size, mach_vm_address_t * dest)
{
	assert_allocate_copy_return(source, size, dest, KERN_SUCCESS);
}

void
assert_copy_return(mach_vm_address_t source, mach_vm_size_t size, mach_vm_address_t dest, kern_return_t expected_kr)
{
	assert_mach_return(mach_vm_copy(mach_task_self(), source, size, dest), expected_kr, "mach_vm_copy()");
}

void
assert_copy_success(mach_vm_address_t source, mach_vm_size_t size, mach_vm_address_t dest)
{
	assert_copy_return(source, size, dest, KERN_SUCCESS);
}

/*******************/
/* Memory patterns */
/*******************/

typedef boolean_t (*address_filter_t)(mach_vm_address_t);
typedef void (*address_action_t)(mach_vm_address_t, mach_vm_address_t);

/* Map over a memory region pattern and its complement, through a
 * (possibly reversed) boolean filter and a starting value. */
void
filter_addresses_do_else(address_filter_t filter,
    boolean_t reversed,
    mach_vm_address_t address,
    mach_vm_size_t size,
    address_action_t if_action,
    address_action_t else_action,
    mach_vm_address_t start_value)
{
	mach_vm_address_t i;
	for (i = 0; i + vm_address_size < size; i += vm_address_size) {
		if (filter(address + i) != reversed) {
			if_action(address + i, start_value + i);
		} else {
			else_action(address + i, start_value + i);
		}
	}
}

/* Various pattern actions. */
void
no_action(mach_vm_address_t i, mach_vm_address_t value)
{
}

void
read_zero(mach_vm_address_t i, mach_vm_address_t value)
{
	assert_address_value(i, 0);
}

void
verify_address(mach_vm_address_t i, mach_vm_address_t value)
{
	assert_address_value(i, value);
}

void
write_address(mach_vm_address_t i, mach_vm_address_t value)
{
	MACH_VM_ADDRESS_T(i) = value;
}

/* Various patterns. */
boolean_t
empty(mach_vm_address_t i)
{
	return FALSE;
}

boolean_t
checkerboard(mach_vm_address_t i)
{
	return !((i / vm_address_size) & 0x1);
}

boolean_t
page_ends(mach_vm_address_t i)
{
	mach_vm_address_t residue = i % vm_page_size;

	return residue == 0 || residue == vm_page_size - vm_address_size;
}

/*************************************/
/* Global variables set up functions */
/*************************************/

void
set_up_allocator()
{
	T_QUIET; T_ASSERT_TRUE(allocators_idx >= 0 && allocators_idx < numofallocators, "Invalid allocators[] index: %d.", allocators_idx);
	set_allocator(allocators[allocators_idx].allocate);
}

/* Find a fixed allocatable address by retrieving the address
 * populated by mach_vm_allocate() with VM_FLAGS_ANYWHERE. */
mach_vm_address_t
get_fixed_address(mach_vm_size_t size)
{
	/* mach_vm_map() starts looking for an address at 0x0. */
	mach_vm_address_t address = 0x0;

	/*
	 * The tests seem to have some funky off by one allocations. To avoid problems, we'll bump anything
	 * non-zero to have at least an extra couple pages.
	 */
	if (size != 0) {
		size = round_page_kernel(size + 2 * vm_page_size);
	}

	assert_allocate_success(&address, size, VM_FLAGS_ANYWHERE);

	/*
	 * Keep the memory allocated, otherwise the logv()/printf() activity sprinkled in these tests can
	 * cause malloc() to use the desired range and tests will randomly fail. The allocate routines will
	 * do the delayed vm_deallocate() to free the fixed memory just before allocation testing in the wrapper.
	 */
	T_QUIET; T_ASSERT_EQ(fixed_vm_address, 0, "previous fixed address not used");
	T_QUIET; T_ASSERT_EQ(fixed_vm_size, 0, "previous fixed size not used");
	fixed_vm_address = address;
	fixed_vm_size = size;

	assert_aligned_address(address);
	return address;
}

/* If needed, find an address at which a region of the specified size
 * can be allocated. Otherwise, set the address to 0x0. */
void
set_up_vm_address(mach_vm_size_t size)
{
	T_QUIET; T_ASSERT_TRUE(flags_idx >= 0 && flags_idx < numofflags, "Invalid address_flags[] index: %d.", flags_idx);
	T_QUIET; T_ASSERT_TRUE(alignments_idx >= 0 && alignments_idx < numofalignments, "Invalid address_alignments[] index: %d.", alignments_idx);
	set_address_flag(address_flags[flags_idx].flag);
	set_address_alignment(address_alignments[alignments_idx].alignment);

	if (!(get_address_flag() & VM_FLAGS_ANYWHERE)) {
		boolean_t aligned = get_address_alignment();
		logv(
			"Looking for fixed %saligned address for allocation "
			"of 0x%jx (%ju) byte%s...",
			aligned ? "" : "un", (uintmax_t)size, (uintmax_t)size, (size == 1) ? "" : "s");
		mach_vm_address_t address = get_fixed_address(size);
		if (!aligned) {
			address++;
		}
		set_vm_address(address);
		logv("Found %saligned fixed address 0x%jx.", aligned ? "" : "un", (uintmax_t)address);
	} else {
		/* mach_vm_map() with VM_FLAGS_ANYWHERE starts looking for
		 *  an address at the one supplied and goes up, without
		 *  wrapping around. */
		set_vm_address(0x0);
	}
}

void
set_up_vm_size()
{
	T_QUIET; T_ASSERT_TRUE(sizes_idx >= 0 && sizes_idx < numofsizes, "Invalid vm_sizes[] index: %d.", sizes_idx);
	set_vm_size(vm_sizes[sizes_idx].size);
}

void
set_up_buffer_size()
{
	T_QUIET; T_ASSERT_TRUE(buffer_sizes_idx >= 0 && buffer_sizes_idx < numofsizes, "Invalid vm_sizes[] index: %d.", buffer_sizes_idx);
	set_buffer_size(vm_sizes[buffer_sizes_idx].size);
}

void
set_up_buffer_offset()
{
	T_QUIET; T_ASSERT_TRUE(offsets_idx >= 0 && offsets_idx < numofoffsets, "Invalid buffer_offsets[] index: %d.", offsets_idx);
	set_buffer_offset(buffer_offsets[offsets_idx].offset);
}

void
set_up_vmcopy_action()
{
	T_QUIET; T_ASSERT_TRUE(vmcopy_action_idx >= 0 && vmcopy_action_idx < numofvmcopyactions, "Invalid vmcopy_actions[] index: %d.",
	    vmcopy_action_idx);
	set_vmcopy_post_action(vmcopy_actions[vmcopy_action_idx].action);
}

void
set_up_allocator_and_vm_size()
{
	set_up_allocator();
	set_up_vm_size();
}

void
set_up_vm_variables()
{
	set_up_vm_size();
	set_up_vm_address(get_vm_size());
}

void
set_up_allocator_and_vm_variables()
{
	set_up_allocator();
	set_up_vm_variables();
}

void
set_up_buffer_variables()
{
	set_up_buffer_size();
	set_up_buffer_offset();
}

void
set_up_copy_shared_mode_variables()
{
	set_up_vmcopy_action();
}

/*******************************/
/* Allocation set up functions */
/*******************************/

/* Allocate VM region of given size. */
void
allocate(mach_vm_size_t size)
{
	mach_vm_address_t address = get_vm_address();
	int flag                  = get_address_flag();

	logv("Allocating 0x%jx (%ju) byte%s", (uintmax_t)size, (uintmax_t)size, (size == 1) ? "" : "s");
	if (!(flag & VM_FLAGS_ANYWHERE)) {
		logv(" at address 0x%jx", (uintmax_t)address);
	}
	logv("...");
	assert_allocate_success(&address, size, flag);
	logv(
		"Memory of rounded size 0x%jx (%ju) allocated at "
		"address 0x%jx.",
		(uintmax_t)round_page_kernel(size), (uintmax_t)round_page_kernel(size), (uintmax_t)address);
	/* Fixed allocation address is truncated to the allocator
	 *  boundary. */
	if (!(flag & VM_FLAGS_ANYWHERE)) {
		mach_vm_address_t old_address = get_vm_address();
		assert_trunc_address(old_address, address);
		logv(
			"Address 0x%jx is correctly truncated to allocated "
			"address 0x%jx.",
			(uintmax_t)old_address, (uintmax_t)address);
	}
	set_vm_address(address);
}

void
allocate_buffer(mach_vm_size_t buffer_size)
{
	mach_vm_address_t data = 0x0;

	logv("Allocating 0x%jx (%ju) byte%s...", (uintmax_t)buffer_size, (uintmax_t)buffer_size, (buffer_size == 1) ? "" : "s");
	assert_allocate_success(&data, buffer_size, VM_FLAGS_ANYWHERE);
	logv(
		"Memory of rounded size 0x%jx (%ju) allocated at "
		"address 0x%jx.",
		(uintmax_t)round_page_kernel(buffer_size), (uintmax_t)round_page_kernel(buffer_size), (uintmax_t)data);
	data += get_buffer_offset();
	T_QUIET; T_ASSERT_EQ((vm_offset_t)data, data,
	    "Address 0x%jx "
	    "unexpectedly overflows to 0x%jx when cast as "
	    "vm_offset_t type.",
	    (uintmax_t)data, (uintmax_t)(vm_offset_t)data);
	set_buffer_address(data);
}

/****************************************************/
/* Global variables and allocation set up functions */
/****************************************************/

void
set_up_vm_variables_and_allocate()
{
	set_up_vm_variables();
	allocate(get_vm_size());
}

void
set_up_allocator_and_vm_variables_and_allocate()
{
	set_up_allocator();
	set_up_vm_variables_and_allocate();
}

void
set_up_vm_variables_and_allocate_extra_page()
{
	set_up_vm_size();
	/* Increment the size to insure we get an extra allocated page
	 *  for unaligned start addresses. */
	mach_vm_size_t allocation_size = get_vm_size() + 1;
	set_up_vm_address(allocation_size);

	allocate(allocation_size);
	/* In the fixed unaligned address case, restore the returned
	*  (truncated) allocation address to its unaligned value. */
	if (!get_address_alignment()) {
		set_vm_address(get_vm_address() + 1);
	}
}

void
set_up_buffer_variables_and_allocate_extra_page()
{
	set_up_buffer_variables();
	/* Increment the size to insure we get an extra allocated page
	 *  for unaligned start addresses. */
	allocate_buffer(get_buffer_size() + get_buffer_offset());
}

/* Allocate some destination and buffer memory for subsequent
 * writing, including extra pages for non-aligned start addresses. */
void
set_up_vm_and_buffer_variables_allocate_for_writing()
{
	set_up_vm_variables_and_allocate_extra_page();
	set_up_buffer_variables_and_allocate_extra_page();
}

/* Allocate some destination and source regions for subsequent
 * copying, including extra pages for non-aligned start addresses. */
void
set_up_vm_and_buffer_variables_allocate_for_copying()
{
	set_up_vm_and_buffer_variables_allocate_for_writing();
}

/************************************/
/* Deallocation tear down functions */
/************************************/

void
deallocate_range(mach_vm_address_t address, mach_vm_size_t size)
{
	logv("Deallocating 0x%jx (%ju) byte%s at address 0x%jx...", (uintmax_t)size, (uintmax_t)size, (size == 1) ? "" : "s",
	    (uintmax_t)address);
	assert_deallocate_success(address, size);
}

void
deallocate()
{
	deallocate_range(get_vm_address(), get_vm_size());
}

/* Deallocate source memory, including the extra page for unaligned
 * start addresses. */
void
deallocate_extra_page()
{
	/* Set the address and size to their original allocation
	 *  values. */
	deallocate_range(mach_vm_trunc_page(get_vm_address()), get_vm_size() + 1);
}

/* Deallocate buffer and destination memory for mach_vm_write(),
 * including the extra page for unaligned start addresses. */
void
deallocate_vm_and_buffer()
{
	deallocate_range(mach_vm_trunc_page(get_vm_address()), get_vm_size() + 1);
	deallocate_range(mach_vm_trunc_page(get_buffer_address()), get_buffer_size() + get_buffer_offset());
}

/***********************************/
/* mach_vm_read() set up functions */
/***********************************/

/* Read the source memory into a buffer, deallocate the source, set
 * the global address and size from the buffer's. */
void
read_deallocate()
{
	mach_vm_size_t size       = get_vm_size();
	mach_vm_address_t address = get_vm_address();
	vm_offset_t read_address;
	mach_msg_type_number_t read_size;

	logv("Reading 0x%jx (%ju) byte%s at address 0x%jx...", (uintmax_t)size, (uintmax_t)size, (size == 1) ? "" : "s",
	    (uintmax_t)address);
	assert_read_success(address, size, &read_address, &read_size);
	logv(
		"Memory of size 0x%jx (%ju) read into buffer of "
		"address 0x%jx.",
		(uintmax_t)read_size, (uintmax_t)read_size, (uintmax_t)read_address);
	/* Deallocate the originally allocated memory, including the
	 *  extra allocated page in
	 *  set_up_vm_variables_and_allocate_extra_page(). */
	deallocate_range(mach_vm_trunc_page(address), size + 1);

	/* Promoting to mach_vm types after checking for overflow, and
	 *  setting the global address from the buffer's. */
	T_QUIET; T_ASSERT_EQ((mach_vm_address_t)read_address, read_address,
	    "Address 0x%jx unexpectedly overflows to 0x%jx when cast "
	    "as mach_vm_address_t type.",
	    (uintmax_t)read_address, (uintmax_t)(mach_vm_address_t)read_address);
	T_QUIET; T_ASSERT_EQ((mach_vm_size_t)read_size, read_size,
	    "Size 0x%jx (%ju) unexpectedly overflows to 0x%jx (%ju) "
	    "when cast as mach_vm_size_t type.",
	    (uintmax_t)read_size, (uintmax_t)read_size, (uintmax_t)(mach_vm_size_t)read_size, (uintmax_t)(mach_vm_size_t)read_size);
	set_vm_address((mach_vm_address_t)read_address);
	set_vm_size((mach_vm_size_t)read_size);
}

/* Allocate some source memory, read it into a buffer, deallocate the
 * source, set the global address and size from the buffer's. */
void
set_up_vm_variables_allocate_read_deallocate()
{
	set_up_vm_variables_and_allocate_extra_page();
	read_deallocate();
}

/************************************/
/* mach_vm_write() set up functions */
/************************************/

/* Write the buffer into the destination memory. */
void
write_buffer()
{
	mach_vm_address_t address          = get_vm_address();
	vm_offset_t data                   = (vm_offset_t)get_buffer_address();
	mach_msg_type_number_t buffer_size = (mach_msg_type_number_t)get_buffer_size();

	logv(
		"Writing buffer of address 0x%jx and size 0x%jx (%ju), on "
		"memory at address 0x%jx...",
		(uintmax_t)data, (uintmax_t)buffer_size, (uintmax_t)buffer_size, (uintmax_t)address);
	assert_write_success(address, data, buffer_size);
	logv("Buffer written.");
}

/* Allocate some destination and buffer memory, and write the buffer
 * into the destination memory. */
void
set_up_vm_and_buffer_variables_allocate_write()
{
	set_up_vm_and_buffer_variables_allocate_for_writing();
	write_buffer();
}

/***********************************/
/* mach_vm_copy() set up functions */
/***********************************/

void
copy_deallocate(void)
{
	mach_vm_size_t size      = get_vm_size();
	mach_vm_address_t source = get_vm_address();
	mach_vm_address_t dest   = 0;

	logv("Copying 0x%jx (%ju) byte%s at address 0x%jx...", (uintmax_t)size, (uintmax_t)size, (size == 1) ? "" : "s",
	    (uintmax_t)source);
	assert_allocate_copy_success(source, size, &dest);
	logv(
		"Memory of size 0x%jx (%ju) copy into region of "
		"address 0x%jx.",
		(uintmax_t)size, (uintmax_t)size, (uintmax_t)dest);
	/* Deallocate the originally allocated memory, including the
	 *  extra allocated page in
	 *  set_up_vm_variables_and_allocate_extra_page(). */
	deallocate_range(mach_vm_trunc_page(source), size + 1);
	/* Promoting to mach_vm types after checking for overflow, and
	 *  setting the global address from the buffer's. */
	T_QUIET; T_ASSERT_EQ((vm_offset_t)dest, dest,
	    "Address 0x%jx unexpectedly overflows to 0x%jx when cast "
	    "as mach_vm_address_t type.",
	    (uintmax_t)dest, (uintmax_t)(vm_offset_t)dest);
	set_vm_address(dest);
	set_vm_size(size);
}

/* Copy the source region into the destination region. */
void
copy_region()
{
	mach_vm_address_t source    = get_vm_address();
	mach_vm_address_t dest      = get_buffer_address();
	mach_msg_type_number_t size = (mach_msg_type_number_t)get_buffer_size();

	logv(
		"Copying memory region of address 0x%jx and size 0x%jx (%ju), on "
		"memory at address 0x%jx...",
		(uintmax_t)source, (uintmax_t)size, (uintmax_t)size, (uintmax_t)dest);
	assert_copy_success(source, size, dest);
	logv("Buffer written.");
}

/* Allocate some source memory, copy it to another region, deallocate the
* source, set the global address and size from the designation region. */
void
set_up_vm_variables_allocate_copy_deallocate()
{
	set_up_vm_variables_and_allocate_extra_page();
	copy_deallocate();
}

/* Allocate some destination and source memory, and copy the source
 * into the destination memory. */
void
set_up_source_and_dest_variables_allocate_copy()
{
	set_up_vm_and_buffer_variables_allocate_for_copying();
	copy_region();
}

/**************************************/
/* mach_vm_protect() set up functions */
/**************************************/

void
set_up_vm_variables_allocate_protect(vm_prot_t protection, const char * protection_name)
{
	set_up_vm_variables_and_allocate_extra_page();
	mach_vm_size_t size       = get_vm_size();
	mach_vm_address_t address = get_vm_address();

	logv(
		"Setting %s-protection on 0x%jx (%ju) byte%s at address "
		"0x%jx...",
		protection_name, (uintmax_t)size, (uintmax_t)size, (size == 1) ? "" : "s", (uintmax_t)address);
	T_QUIET; T_ASSERT_MACH_SUCCESS(mach_vm_protect(mach_task_self(), address, size, FALSE, protection), "mach_vm_protect()");
	logv("Region %s-protected.", protection_name);
}

void
set_up_vm_variables_allocate_readprotect()
{
	set_up_vm_variables_allocate_protect(VM_PROT_WRITE, "read");
}

void
set_up_vm_variables_allocate_writeprotect()
{
	set_up_vm_variables_allocate_protect(VM_PROT_READ, "write");
}

/*****************/
/* Address tests */
/*****************/

/* Allocated address is nonzero iff size is nonzero. */
void
test_nonzero_address_iff_nonzero_size()
{
	mach_vm_address_t address = get_vm_address();
	mach_vm_size_t size       = get_vm_size();

	T_QUIET; T_ASSERT_TRUE((address && size) || (!address && !size), "Address 0x%jx is unexpectedly %szero.", (uintmax_t)address,
	    address ? "non" : "");
	logv("Address 0x%jx is %szero as expected.", (uintmax_t)address, size ? "non" : "");
}

/* Allocated address is aligned. */
void
test_aligned_address()
{
	mach_vm_address_t address = get_vm_address();

	assert_aligned_address(address);
	logv("Address 0x%jx is aligned.", (uintmax_t)address);
}

/************************/
/* Read and write tests */
/************************/

void
verify_pattern(
	address_filter_t filter, boolean_t reversed, mach_vm_address_t address, mach_vm_size_t size, const char * pattern_name)
{
	logv(
		"Verifying %s pattern on region of address 0x%jx "
		"and size 0x%jx (%ju)...",
		pattern_name, (uintmax_t)address, (uintmax_t)size, (uintmax_t)size);
	filter_addresses_do_else(filter, reversed, address, size, verify_address, read_zero, address);
	logv("Pattern verified.");
}

void
write_pattern(
	address_filter_t filter, boolean_t reversed, mach_vm_address_t address, mach_vm_size_t size, const char * pattern_name)
{
	logv(
		"Writing %s pattern on region of address 0x%jx "
		"and size 0x%jx (%ju)...",
		pattern_name, (uintmax_t)address, (uintmax_t)size, (uintmax_t)size);
	filter_addresses_do_else(filter, reversed, address, size, write_address, no_action, address);
	logv("Pattern writen.");
}

void
write_and_verify_pattern(
	address_filter_t filter, boolean_t reversed, mach_vm_address_t address, mach_vm_size_t size, const char * pattern_name)
{
	logv(
		"Writing and verifying %s pattern on region of "
		"address 0x%jx and size 0x%jx (%ju)...",
		pattern_name, (uintmax_t)address, (uintmax_t)size, (uintmax_t)size);
	filter_addresses_do_else(filter, reversed, address, size, write_address, no_action, address);
	filter_addresses_do_else(filter, reversed, address, size, verify_address, read_zero, address);
	logv("Pattern written and verified.");
}

/* Verify that the smallest aligned region containing the
 * given range is zero-filled. */
void
test_zero_filled()
{
	verify_pattern(empty, FALSE, mach_vm_trunc_page(get_vm_address()), aligned_size(get_vm_address(), get_vm_size()),
	    "zero-filled");
}

void
test_write_address_filled()
{
	write_and_verify_pattern(empty, TRUE, get_vm_address(), round_page_kernel(get_vm_size()), "address-filled");
}

void
test_write_checkerboard()
{
	write_and_verify_pattern(checkerboard, FALSE, get_vm_address(), round_page_kernel(get_vm_size()), "checkerboard");
}

void
test_write_reverse_checkerboard()
{
	write_and_verify_pattern(checkerboard, TRUE, get_vm_address(), round_page_kernel(get_vm_size()), "reverse checkerboard");
}

void
test_write_page_ends()
{
	write_and_verify_pattern(page_ends, FALSE, get_vm_address(), round_page_kernel(get_vm_size()), "page ends");
}

void
test_write_page_interiors()
{
	write_and_verify_pattern(page_ends, TRUE, get_vm_address(), round_page_kernel(get_vm_size()), "page interiors");
}

/*********************************/
/* Allocation error return tests */
/*********************************/

/* Reallocating a page in the smallest aligned region containing the
 * given allocated range fails. */
void
test_reallocate_pages()
{
	allocate_fn_t allocator   = get_allocator();
	vm_map_t this_task        = mach_task_self();
	mach_vm_address_t address = mach_vm_trunc_page(get_vm_address());
	mach_vm_size_t size       = aligned_size(get_vm_address(), get_vm_size());
	mach_vm_address_t i;
	kern_return_t kr;

	logv(
		"Reallocating pages in allocated region of address 0x%jx "
		"and size 0x%jx (%ju)...",
		(uintmax_t)address, (uintmax_t)size, (uintmax_t)size);
	for (i = address; i < address + size; i += vm_page_size) {
		kr = allocator(this_task, &i, vm_page_size, VM_FLAGS_FIXED);
		T_QUIET; T_ASSERT_EQ(kr, KERN_NO_SPACE,
		    "Allocator "
		    "at address 0x%jx unexpectedly returned: %s.\n"
		    "Should have returned: %s.",
		    (uintmax_t)address, mach_error_string(kr), mach_error_string(KERN_NO_SPACE));
	}
	logv("Returned expected error at each page: %s.", mach_error_string(KERN_NO_SPACE));
}

/* Allocating in VM_MAP_NULL fails. */
void
test_allocate_in_null_map()
{
	mach_vm_address_t address = get_vm_address();
	mach_vm_size_t size       = get_vm_size();
	int flag                  = get_address_flag();

	logv("Allocating 0x%jx (%ju) byte%s", (uintmax_t)size, (uintmax_t)size, (size == 1) ? "" : "s");
	if (!(flag & VM_FLAGS_ANYWHERE)) {
		logv(" at address 0x%jx", (uintmax_t)address);
	}
	logv(" in NULL VM map...");
	assert_mach_return(get_allocator()(VM_MAP_NULL, &address, size, flag), MACH_SEND_INVALID_DEST, "Allocator");
	logv("Returned expected error: %s.", mach_error_string(MACH_SEND_INVALID_DEST));
}

/* Allocating with non-user flags fails. */
void
test_allocate_with_kernel_flags()
{
	allocate_fn_t allocator   = get_allocator();
	vm_map_t this_task        = mach_task_self();
	mach_vm_address_t address = get_vm_address();
	mach_vm_size_t size       = get_vm_size();
	int flag                  = get_address_flag();
	int bad_flag, i;
	kern_return_t kr;
	int kernel_flags[] = {0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x8000, INT_MAX};
	int numofflags     = sizeof(kernel_flags) / sizeof(kernel_flags[0]);

	logv("Allocating 0x%jx (%ju) byte%s", (uintmax_t)size, (uintmax_t)size, (size == 1) ? "" : "s");
	if (!(flag & VM_FLAGS_ANYWHERE)) {
		logv(" at address 0x%jx", (uintmax_t)address);
	}
	logv(" with various kernel flags...");
	for (i = 0; i < numofflags; i++) {
		bad_flag = kernel_flags[i] | flag;
		kr = allocator(this_task, &address, size, bad_flag);
		T_QUIET; T_ASSERT_EQ(kr, KERN_INVALID_ARGUMENT,
		    "Allocator "
		    "with kernel flag 0x%x unexpectedly returned: %s.\n"
		    "Should have returned: %s.",
		    bad_flag, mach_error_string(kr), mach_error_string(KERN_INVALID_ARGUMENT));
	}
	logv("Returned expected error with each kernel flag: %s.", mach_error_string(KERN_INVALID_ARGUMENT));
}

/*****************************/
/* mach_vm_map() error tests */
/*****************************/

/* mach_vm_map() fails with invalid protection or inheritance
 *  arguments. */
void
test_mach_vm_map_protection_inheritance_error()
{
	kern_return_t kr;
	vm_map_t my_task          = mach_task_self();
	mach_vm_address_t address = get_vm_address();
	mach_vm_size_t size       = get_vm_size();
	vm_map_offset_t mask = (get_allocator() == wrapper_mach_vm_map || get_allocator() == wrapper_mach_vm_map_named_entry)
	    ? (mach_vm_offset_t)0
	    : (mach_vm_offset_t)get_mask();
	int flag                    = get_address_flag();
	mach_port_t object_handle   = (get_allocator() == wrapper_mach_vm_map_named_entry) ? memory_entry(&size) : MACH_PORT_NULL;
	vm_prot_t cur_protections[] = {VM_PROT_DEFAULT, VM_PROT_ALL + 1, ~VM_PROT_IS_MASK, INT_MAX};
	vm_prot_t max_protections[] = {VM_PROT_ALL, VM_PROT_ALL + 1, ~VM_PROT_IS_MASK, INT_MAX};
	vm_inherit_t inheritances[] = {VM_INHERIT_DEFAULT, VM_INHERIT_LAST_VALID + 1, UINT_MAX};
	int i, j, k;

	logv("Allocating 0x%jx (%ju) byte%s", (uintmax_t)size, (uintmax_t)size, (size == 1) ? "" : "s");
	if (!(flag & VM_FLAGS_ANYWHERE)) {
		logv(" at address 0x%jx", (uintmax_t)address);
	}
	logv(
		" with various invalid protection/inheritance "
		"arguments...");

	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			for (k = 0; k < 3; k++) {
				/* Skip the case with all valid arguments. */
				if (i == (j == (k == 0))) {
					continue;
				}
				kr = mach_vm_map(my_task, &address, size, mask, flag, object_handle, (memory_object_offset_t)0, FALSE,
				    cur_protections[i], max_protections[j], inheritances[k]);
				T_QUIET; T_ASSERT_EQ(kr, KERN_INVALID_ARGUMENT,
				    "mach_vm_map() "
				    "with cur_protection 0x%x, max_protection 0x%x, "
				    "inheritance 0x%x unexpectedly returned: %s.\n"
				    "Should have returned: %s.",
				    cur_protections[i], max_protections[j], inheritances[k], mach_error_string(kr),
				    mach_error_string(KERN_INVALID_ARGUMENT));
			}
		}
	}
	logv("Returned expected error in each case: %s.", mach_error_string(KERN_INVALID_ARGUMENT));
}

/* mach_vm_map() with unspecified address fails if the starting
 *  address overflows when rounded up to a boundary value. */
void
test_mach_vm_map_large_mask_overflow_error()
{
	mach_vm_address_t address = 0x1;
	mach_vm_size_t size       = get_vm_size();
	mach_vm_offset_t mask     = (mach_vm_offset_t)UINTMAX_MAX;
	/* mach_vm_map() cannot allocate 0 bytes at an unspecified
	 *  address, see 8003930. */
	kern_return_t kr_expected = size ? KERN_NO_SPACE : KERN_INVALID_ARGUMENT;

	logv(
		"Allocating 0x%jx (%ju) byte%s at an unspecified address "
		"starting at 0x%jx with mask 0x%jx...",
		(uintmax_t)size, (uintmax_t)size, (size == 1) ? "" : "s", (uintmax_t)address, (uintmax_t)mask);
	assert_mach_return(mach_vm_map(mach_task_self(), &address, size, mask, VM_FLAGS_ANYWHERE, MACH_PORT_NULL,
	    (memory_object_offset_t)0, FALSE, VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_DEFAULT),
	    kr_expected, "mach_vm_map()");
	logv("Returned expected error: %s.", mach_error_string(kr_expected));
}

/************************/
/* Size edge case tests */
/************************/

void
allocate_edge_size(mach_vm_address_t * address, mach_vm_size_t size, kern_return_t expected_kr)
{
	logv("Allocating 0x%jx (%ju) bytes...", (uintmax_t)size, (uintmax_t)size);
	assert_allocate_return(address, size, VM_FLAGS_ANYWHERE, expected_kr);
	logv("Returned expected value: %s.", mach_error_string(expected_kr));
}

void
test_allocate_zero_size()
{
	mach_vm_address_t address = 0x0;
	/* mach_vm_map() cannot allocate 0 bytes at an unspecified
	 *  address, see 8003930. Other allocators succeed. */
	kern_return_t kr_expected = (get_allocator() != wrapper_mach_vm_allocate) ? KERN_INVALID_ARGUMENT : KERN_SUCCESS;

	allocate_edge_size(&address, 0, kr_expected);
	if (kr_expected == KERN_SUCCESS) {
		deallocate_range(address, 0);
	}
}

/* Testing the allocation of the largest size that does not overflow
 * when rounded up to a page-aligned value. */
void
test_allocate_invalid_large_size()
{
	mach_vm_size_t size = (mach_vm_size_t)UINTMAX_MAX - vm_page_size + 1;
	if (get_allocator() != wrapper_mach_vm_map_named_entry) {
		mach_vm_address_t address = 0x0;
		allocate_edge_size(&address, size, KERN_NO_SPACE);
	} else {
		/* Named entries cannot currently be bigger than 4 GB
		 *  - 4 kb. */
		mach_port_t object_handle = MACH_PORT_NULL;
		logv("Creating named entry of 0x%jx (%ju) bytes...", (uintmax_t)size, (uintmax_t)size);
		assert_mach_return(mach_make_memory_entry_64(mach_task_self(), &size, (memory_object_offset_t)0,
		    (MAP_MEM_NAMED_CREATE | VM_PROT_ALL), &object_handle, 0),
		    KERN_FAILURE, "mach_make_memory_entry_64()");
		logv("Returned expected error: %s.", mach_error_string(KERN_FAILURE));
	}
}

/* A UINTMAX_MAX VM size will overflow to 0 when rounded up to a
 * page-aligned value. */
void
test_allocate_overflowing_size()
{
	mach_vm_address_t address = 0x0;

	allocate_edge_size(&address, (mach_vm_size_t)UINTMAX_MAX, KERN_INVALID_ARGUMENT);
}

/****************************/
/* Address allocation tests */
/****************************/

/* Allocation at address zero fails iff size is nonzero. */
void
test_allocate_at_zero()
{
	mach_vm_address_t address = 0x0;
	mach_vm_size_t size       = get_vm_size();

	kern_return_t kr_expected =
	    size ? KERN_INVALID_ADDRESS : (get_allocator() != wrapper_mach_vm_allocate) ? KERN_INVALID_ARGUMENT : KERN_SUCCESS;

	logv("Allocating 0x%jx (%ju) byte%s at address 0x0...", (uintmax_t)size, (uintmax_t)size, (size == 1) ? "" : "s");
	assert_allocate_return(&address, size, VM_FLAGS_FIXED, kr_expected);
	logv("Returned expected value: %s.", mach_error_string(kr_expected));
	if (kr_expected == KERN_SUCCESS) {
		T_QUIET; T_ASSERT_EQ(address, 0,
		    "Address 0x%jx is unexpectedly "
		    "nonzero.\n",
		    (uintmax_t)address);
		logv("Allocated address 0x%jx is zero.", (uintmax_t)address);
		deallocate_range(address, size);
	}
}

/* Allocation at page-aligned but 2 MB boundary-unaligned address
 *  fails with KERN_NO_SPACE. */
void
test_allocate_2MB_boundary_unaligned_page_aligned_address()
{
	mach_vm_size_t size = get_vm_size();

	mach_vm_address_t address = get_fixed_address(size + vm_page_size) + vm_page_size;
	logv(
		"Found 2 MB boundary-unaligned, page aligned address "
		"0x%jx.",
		(uintmax_t)address);

	/* mach_vm_allocate() cannot allocate 0 bytes, and fails with a
	 *  fixed boundary-unaligned truncated address. */
	kern_return_t kr_expected = (!size && get_allocator() != wrapper_mach_vm_allocate)
	    ? KERN_INVALID_ARGUMENT
	    : (get_allocator() == wrapper_mach_vm_map_2MB) ? KERN_NO_SPACE : KERN_SUCCESS;
	logv("Allocating 0x%jx (%ju) byte%s at address 0x%jx...", (uintmax_t)size, (uintmax_t)size, (size == 1) ? "" : "s",
	    (uintmax_t)address);
	assert_allocate_return(&address, size, VM_FLAGS_FIXED, kr_expected);
	logv("Returned expected value: %s.", mach_error_string(kr_expected));
	if (kr_expected == KERN_SUCCESS) {
		deallocate_range(address, size);
	}
}

/* With VM_FLAGS_ANYWHERE set, mach_vm_allocate() starts looking for
 *  an allocation address at 0x0, while mach_vm_map() starts at the
 *  supplied address and does not wrap around. See 8016663. */
void
test_allocate_page_with_highest_address_hint()
{
	/* Highest valid page-aligned address. */
	mach_vm_address_t address = (mach_vm_size_t)UINTMAX_MAX - vm_page_size + 1;

	logv(
		"Allocating one page with unspecified address, but hint at "
		"0x%jx...",
		(uintmax_t)address);
	if (get_allocator() == wrapper_mach_vm_allocate) {
		/* mach_vm_allocate() starts from 0x0 and succeeds. */
		assert_allocate_success(&address, vm_page_size, VM_FLAGS_ANYWHERE);
		logv("Memory allocated at address 0x%jx.", (uintmax_t)address);
		assert_aligned_address(address);
		deallocate_range(address, vm_page_size);
	} else {
		/* mach_vm_map() starts from the supplied address, and fails
		 *  with KERN_NO_SPACE, see 8016663. */
		assert_allocate_return(&address, vm_page_size, VM_FLAGS_ANYWHERE, KERN_NO_SPACE);
		logv("Returned expected error: %s.", mach_error_string(KERN_NO_SPACE));
	}
}

/* Allocators find an allocation address with a first fit strategy. */
void
test_allocate_first_fit_pages()
{
	allocate_fn_t allocator    = get_allocator();
	mach_vm_address_t address1 = 0x0;
	mach_vm_address_t i;
	kern_return_t kr;
	vm_map_t this_task = mach_task_self();

	logv(
		"Looking for first fit address for allocating one "
		"page...");
	assert_allocate_success(&address1, vm_page_size, VM_FLAGS_ANYWHERE);
	logv("Found address 0x%jx.", (uintmax_t)address1);
	assert_aligned_address(address1);
	mach_vm_address_t address2 = address1;
	logv(
		"Looking for next higher first fit address for allocating "
		"one page...");
	assert_allocate_success(&address2, vm_page_size, VM_FLAGS_ANYWHERE);
	logv("Found address 0x%jx.", (uintmax_t)address2);
	assert_aligned_address(address2);
	T_QUIET; T_ASSERT_GT(address2, address1,
	    "Second address 0x%jx is "
	    "unexpectedly not higher than first address 0x%jx.",
	    (uintmax_t)address2, (uintmax_t)address1);

	logv("Allocating pages between 0x%jx and 0x%jx...", (uintmax_t)address1, (uintmax_t)address2);
	for (i = address1; i <= address2; i += vm_page_size) {
		kr = allocator(this_task, &i, vm_page_size, VM_FLAGS_FIXED);
		T_QUIET; T_ASSERT_NE(kr, KERN_SUCCESS,
		    "Allocator at address 0x%jx "
		    "unexpectedly succeeded.",
		    (uintmax_t)i);
	}
	logv("Expectedly returned error at each page.");
	deallocate_range(address1, vm_page_size);
	deallocate_range(address2, vm_page_size);
}

/*******************************/
/* Deallocation segfault tests */
/*******************************/

/* mach_vm_deallocate() deallocates the smallest aligned region
 * (integral number of pages) containing the given range. */

/* Addresses in deallocated range are inaccessible. */
void
access_deallocated_range_address(mach_vm_address_t address, const char * position)
{
	logv("Will deallocate and read from %s 0x%jx of deallocated range...", position, (uintmax_t)address);
	deallocate();
	mach_vm_address_t bad_value = MACH_VM_ADDRESS_T(address);
	T_ASSERT_FAIL("Unexpectedly read value 0x%jx at address 0x%jx.\n"
	    "Should have died with signal SIGSEGV.",
	    (uintmax_t)bad_value, (uintmax_t)address);
}

/* Start of deallocated range is inaccessible. */
void
test_access_deallocated_range_start()
{
	access_deallocated_range_address(get_vm_address(), "start");
}

/* Middle of deallocated range is inaccessible. */
void
test_access_deallocated_range_middle()
{
	access_deallocated_range_address(get_vm_address() + (round_page_kernel(get_vm_size()) >> 1), "middle");
}

/* End of deallocated range is inaccessible. */
void
test_access_deallocated_range_end()
{
	access_deallocated_range_address(round_page_kernel(get_vm_size()) - vm_address_size + get_vm_address(), "end");
}

/* Deallocating almost the whole address space causes a SIGSEGV or SIGBUS. We
 * deallocate the largest valid aligned size to avoid overflowing when
 * rounding up. */
void
test_deallocate_suicide()
{
	mach_vm_address_t address = 0x0;
	mach_vm_size_t size       = (mach_vm_size_t)UINTMAX_MAX - vm_page_size + 1;

	logv("Deallocating 0x%jx (%ju) bytes at address 0x%jx...", (uintmax_t)size, (uintmax_t)size, (uintmax_t)address);
	kern_return_t kr = mach_vm_deallocate(mach_task_self(), address, size);
	T_ASSERT_FAIL("mach_vm_deallocate() with address 0x%jx and "
	    "size 0x%jx (%ju) unexpectedly returned: %s.\n"
	    "Should have died with signal SIGSEGV or SIGBUS.",
	    (uintmax_t)address, (uintmax_t)size, (uintmax_t)size, mach_error_string(kr));
}

/***************************************/
/* Deallocation and reallocation tests */
/***************************************/

/* Deallocating memory twice succeeds. */
void
test_deallocate_twice()
{
	deallocate();
	deallocate();
}

/* Deallocated and reallocated memory is zero-filled. Deallocated
 * memory is inaccessible since it can be reallocated. */
void
test_write_pattern_deallocate_reallocate_zero_filled()
{
	mach_vm_address_t address = get_vm_address();
	mach_vm_size_t size       = get_vm_size();

	write_pattern(page_ends, FALSE, address, size, "page ends");
	logv("Deallocating, then Allocating 0x%jx (%ju) byte%s at address 0x%jx...", (uintmax_t)size, (uintmax_t)size, (size == 1) ? "" : "s",
	    (uintmax_t)address);
	deallocate();
	assert_allocate_success(&address, size, VM_FLAGS_FIXED);
	logv("Memory allocated.");
	verify_pattern(empty, FALSE, address, size, "zero-filled");
	deallocate();
}

/********************************/
/* Deallocation edge case tests */
/********************************/

/* Zero size deallocation always succeeds. */
void
test_deallocate_zero_size_ranges()
{
	int i;
	kern_return_t kr;
	vm_map_t this_task            = mach_task_self();
	mach_vm_address_t addresses[] = {0x0,
		                         0x1,
		                         vm_page_size - 1,
		                         vm_page_size,
		                         vm_page_size + 1,
		                         (mach_vm_address_t)UINT_MAX - vm_page_size + 1,
		                         (mach_vm_address_t)UINT_MAX,
		                         (mach_vm_address_t)UINTMAX_MAX - vm_page_size + 1,
		                         (mach_vm_address_t)UINTMAX_MAX};
	int numofaddresses = sizeof(addresses) / sizeof(addresses[0]);

	logv("Deallocating 0x0 (0) bytes at various addresses...");
	for (i = 0; i < numofaddresses; i++) {
		kr = mach_vm_deallocate(this_task, addresses[i], 0);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_deallocate() at "
		    "address 0x%jx unexpectedly failed: %s.",
		    (uintmax_t)addresses[i], mach_error_string(kr));
	}
	logv("Deallocations successful.");
}

/* Deallocation succeeds if the end of the range rounds to 0x0. */
void
test_deallocate_rounded_zero_end_ranges()
{
	int i;
	kern_return_t kr;
	vm_map_t this_task = mach_task_self();
	struct {
		mach_vm_address_t address;
		mach_vm_size_t size;
	} ranges[] = {
		{0x0, (mach_vm_size_t)UINTMAX_MAX},
		{0x0, (mach_vm_size_t)UINTMAX_MAX - vm_page_size + 2},
		{0x1, (mach_vm_size_t)UINTMAX_MAX - 1},
		{0x1, (mach_vm_size_t)UINTMAX_MAX - vm_page_size + 1},
		{0x2, (mach_vm_size_t)UINTMAX_MAX - 2},
		{0x2, (mach_vm_size_t)UINTMAX_MAX - vm_page_size},
		{(mach_vm_address_t)UINTMAX_MAX - vm_page_size + 1, vm_page_size - 1},
		{(mach_vm_address_t)UINTMAX_MAX - vm_page_size + 1, 1},
		{(mach_vm_address_t)UINTMAX_MAX - 1, 1},
	};
	int numofranges = sizeof(ranges) / sizeof(ranges[0]);

	logv(
		"Deallocating various memory ranges whose end rounds to "
		"0x0...");
	for (i = 0; i < numofranges; i++) {
		kr = mach_vm_deallocate(this_task, ranges[i].address, ranges[i].size);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr,
		    "mach_vm_deallocate() with address 0x%jx and size "
		    "0x%jx (%ju) unexpectedly returned: %s.\n"
		    "Should have succeeded.",
		    (uintmax_t)ranges[i].address, (uintmax_t)ranges[i].size, (uintmax_t)ranges[i].size, mach_error_string(kr));
	}
	logv("Deallocations successful.");
}

/* Deallocating a range wrapped around the address space fails. */
void
test_deallocate_wrapped_around_ranges()
{
	int i;
	kern_return_t kr;
	vm_map_t this_task = mach_task_self();
	struct {
		mach_vm_address_t address;
		mach_vm_size_t size;
	} ranges[] = {
		{0x1, (mach_vm_size_t)UINTMAX_MAX},
		{vm_page_size, (mach_vm_size_t)UINTMAX_MAX - vm_page_size + 1},
		{(mach_vm_address_t)UINTMAX_MAX - vm_page_size + 1, vm_page_size},
		{(mach_vm_address_t)UINTMAX_MAX, 1},
	};
	int numofranges = sizeof(ranges) / sizeof(ranges[0]);

	logv(
		"Deallocating various memory ranges wrapping around the "
		"address space...");
	for (i = 0; i < numofranges; i++) {
		kr = mach_vm_deallocate(this_task, ranges[i].address, ranges[i].size);
		T_QUIET; T_ASSERT_EQ(kr, KERN_INVALID_ARGUMENT,
		    "mach_vm_deallocate() with address 0x%jx and size "
		    "0x%jx (%ju) unexpectedly returned: %s.\n"
		    "Should have returned: %s.",
		    (uintmax_t)ranges[i].address, (uintmax_t)ranges[i].size, (uintmax_t)ranges[i].size, mach_error_string(kr),
		    mach_error_string(KERN_INVALID_ARGUMENT));
	}
	logv("Returned expected error on each range: %s.", mach_error_string(KERN_INVALID_ARGUMENT));
}

/* Deallocating in VM_MAP_NULL fails. */
void
test_deallocate_in_null_map()
{
	mach_vm_address_t address = get_vm_address();
	mach_vm_size_t size       = get_vm_size();
	int flag                  = get_address_flag();

	logv("Deallocating 0x%jx (%ju) byte%s", (uintmax_t)size, (uintmax_t)size, (size == 1) ? "" : "s");
	if (!(flag & VM_FLAGS_ANYWHERE)) {
		logv(" at address 0x%jx", (uintmax_t)address);
	}
	logv(" in NULL VM map...");
	assert_mach_return(mach_vm_deallocate(VM_MAP_NULL, address, size), MACH_SEND_INVALID_DEST, "mach_vm_deallocate()");
	logv("Returned expected error: %s.", mach_error_string(MACH_SEND_INVALID_DEST));
}

/*****************************/
/* mach_vm_read() main tests */
/*****************************/

/* Read memory of size less than a page has aligned starting
 * address. Otherwise, the destination buffer's starting address has
 * the same boundary offset as the source region's. */
void
test_read_address_offset()
{
	mach_vm_address_t address = get_vm_address();
	mach_vm_size_t size       = get_vm_size();

	if (size < vm_page_size * 2 || get_address_alignment()) {
		assert_aligned_address(address);
		logv("Buffer address 0x%jx is aligned as expected.", (uintmax_t)address);
	} else {
		T_QUIET; T_ASSERT_EQ(((address - 1) & (vm_page_size - 1)), 0,
		    "Buffer "
		    "address 0x%jx does not have the expected boundary "
		    "offset of 1.",
		    (uintmax_t)address);
		logv(
			"Buffer address 0x%jx has the expected boundary "
			"offset of 1.",
			(uintmax_t)address);
	}
}

/* Reading from VM_MAP_NULL fails. */
void
test_read_null_map()
{
	mach_vm_address_t address = get_vm_address();
	mach_vm_size_t size       = get_vm_size();
	vm_offset_t read_address;
	mach_msg_type_number_t read_size;

	logv(
		"Reading 0x%jx (%ju) byte%s at address 0x%jx in NULL VM "
		"map...",
		(uintmax_t)size, (uintmax_t)size, (size == 1) ? "" : "s", (uintmax_t)address);
	assert_mach_return(mach_vm_read(VM_MAP_NULL, address, size, &read_address, &read_size), MACH_SEND_INVALID_DEST,
	    "mach_vm_read()");
	logv("Returned expected error: %s.", mach_error_string(MACH_SEND_INVALID_DEST));
}

/* Reading partially deallocated memory fails. */
void
test_read_partially_deallocated_range()
{
	mach_vm_address_t address   = get_vm_address();
	mach_vm_size_t size         = get_vm_size();
	mach_vm_address_t mid_point = mach_vm_trunc_page(address + size / 2);
	vm_offset_t read_address;
	mach_msg_type_number_t read_size;

	logv("Deallocating a mid-range page at address 0x%jx...", (uintmax_t)mid_point);
	assert_deallocate_success(mid_point, vm_page_size);
	logv("Page deallocated.");

	logv("Reading 0x%jx (%ju) byte%s at address 0x%jx...", (uintmax_t)size, (uintmax_t)size, (size == 1) ? "" : "s",
	    (uintmax_t)address);
	assert_read_return(address, size, &read_address, &read_size, KERN_INVALID_ADDRESS);
	logv("Returned expected error: %s.", mach_error_string(KERN_INVALID_ADDRESS));
}

/* Reading partially read-protected memory fails. */
void
test_read_partially_unreadable_range()
{
	mach_vm_address_t address   = get_vm_address();
	mach_vm_size_t size         = get_vm_size();
	mach_vm_address_t mid_point = mach_vm_trunc_page(address + size / 2);
	vm_offset_t read_address;
	mach_msg_type_number_t read_size;

	/*  For sizes < msg_ool_size_small, vm_map_copyin_common() uses
	 *  vm_map_copyin_kernel_buffer() to read in the memory,
	 *  returning different errors, see 8182239. */
	kern_return_t kr_expected = (size < vm_page_size * 2) ? KERN_INVALID_ADDRESS : KERN_PROTECTION_FAILURE;

	logv("Read-protecting a mid-range page at address 0x%jx...", (uintmax_t)mid_point);
	T_QUIET; T_ASSERT_MACH_SUCCESS(mach_vm_protect(mach_task_self(), mid_point, vm_page_size, FALSE, VM_PROT_WRITE), "mach_vm_protect()");
	logv("Page read-protected.");

	logv("Reading 0x%jx (%ju) byte%s at address 0x%jx...", (uintmax_t)size, (uintmax_t)size, (size == 1) ? "" : "s",
	    (uintmax_t)address);
	assert_read_return(address, size, &read_address, &read_size, kr_expected);
	logv("Returned expected error: %s.", mach_error_string(kr_expected));
}

/**********************************/
/* mach_vm_read() edge case tests */
/**********************************/

void
read_edge_size(mach_vm_size_t size, kern_return_t expected_kr)
{
	int i;
	kern_return_t kr;
	vm_map_t this_task            = mach_task_self();
	mach_vm_address_t addresses[] = {vm_page_size - 1,
		                         vm_page_size,
		                         vm_page_size + 1,
		                         (mach_vm_address_t)UINT_MAX - vm_page_size + 1,
		                         (mach_vm_address_t)UINT_MAX,
		                         (mach_vm_address_t)UINTMAX_MAX - vm_page_size + 1,
		                         (mach_vm_address_t)UINTMAX_MAX};
	int numofaddresses = sizeof(addresses) / sizeof(addresses[0]);
	vm_offset_t read_address;
	mach_msg_type_number_t read_size;

	logv("Reading 0x%jx (%ju) bytes at various addresses...", (uintmax_t)size, (uintmax_t)size);
	for (i = 0; i < numofaddresses; i++) {
		kr = mach_vm_read(this_task, addresses[i], size, &read_address, &read_size);
		T_QUIET; T_ASSERT_EQ(kr, expected_kr,
		    "mach_vm_read() at "
		    "address 0x%jx unexpectedly returned: %s.\n"
		    "Should have returned: %s.",
		    (uintmax_t)addresses[i], mach_error_string(kr), mach_error_string(expected_kr));
	}
	logv(
		"mach_vm_read() returned expected value in each case: "
		"%s.",
		mach_error_string(expected_kr));
}

/* Reading 0 bytes always succeeds. */
void
test_read_zero_size()
{
	read_edge_size(0, KERN_SUCCESS);
}

/* Reading 4GB or higher always fails. */
void
test_read_invalid_large_size()
{
	read_edge_size((mach_vm_size_t)UINT_MAX + 1, KERN_INVALID_ARGUMENT);
}

/* Reading a range wrapped around the address space fails. */
void
test_read_wrapped_around_ranges()
{
	int i;
	kern_return_t kr;
	vm_map_t this_task = mach_task_self();
	struct {
		mach_vm_address_t address;
		mach_vm_size_t size;
	} ranges[] = {
		{(mach_vm_address_t)(UINTMAX_MAX - UINT_MAX + 1), (mach_vm_size_t)UINT_MAX},
		{(mach_vm_address_t)(UINTMAX_MAX - UINT_MAX + vm_page_size), (mach_vm_size_t)(UINT_MAX - vm_page_size + 1)},
		{(mach_vm_address_t)UINTMAX_MAX - vm_page_size + 1, vm_page_size},
		{(mach_vm_address_t)UINTMAX_MAX, 1},
	};
	int numofranges = sizeof(ranges) / sizeof(ranges[0]);
	vm_offset_t read_address;
	mach_msg_type_number_t read_size;

	logv(
		"Reading various memory ranges wrapping around the "
		"address space...");
	for (i = 0; i < numofranges; i++) {
		kr = mach_vm_read(this_task, ranges[i].address, ranges[i].size, &read_address, &read_size);
		T_QUIET; T_ASSERT_EQ(kr, KERN_INVALID_ADDRESS,
		    "mach_vm_read() at address 0x%jx with size "
		    "0x%jx (%ju) unexpectedly returned: %s.\n"
		    "Should have returned: %s.",
		    (uintmax_t)ranges[i].address, (uintmax_t)ranges[i].size, (uintmax_t)ranges[i].size, mach_error_string(kr),
		    mach_error_string(KERN_INVALID_ADDRESS));
	}
	logv("Returned expected error on each range: %s.", mach_error_string(KERN_INVALID_ADDRESS));
}

/********************************/
/* mach_vm_read() pattern tests */
/********************************/

/* Write a pattern on pre-allocated memory, read into a buffer and
 * verify the pattern on the buffer. */
void
write_read_verify_pattern(address_filter_t filter, boolean_t reversed, const char * pattern_name)
{
	mach_vm_address_t address = get_vm_address();

	write_pattern(filter, reversed, address, get_vm_size(), pattern_name);
	read_deallocate();
	/* Getting the address and size of the read buffer. */
	mach_vm_address_t read_address = get_vm_address();
	mach_vm_size_t read_size = get_vm_size();
	logv(
		"Verifying %s pattern on buffer of "
		"address 0x%jx and size 0x%jx (%ju)...",
		pattern_name, (uintmax_t)read_address, (uintmax_t)read_size, (uintmax_t)read_size);
	filter_addresses_do_else(filter, reversed, read_address, read_size, verify_address, read_zero, address);
	logv("Pattern verified on destination buffer.");
}

void
test_read_address_filled()
{
	write_read_verify_pattern(empty, TRUE, "address-filled");
}

void
test_read_checkerboard()
{
	write_read_verify_pattern(checkerboard, FALSE, "checkerboard");
}

void
test_read_reverse_checkerboard()
{
	write_read_verify_pattern(checkerboard, TRUE, "reverse checkerboard");
}

/***********************************/
/* mach_vm_write() edge case tests */
/***********************************/

/* Writing in VM_MAP_NULL fails. */
void
test_write_null_map()
{
	mach_vm_address_t address          = get_vm_address();
	vm_offset_t data                   = (vm_offset_t)get_buffer_address();
	mach_msg_type_number_t buffer_size = (mach_msg_type_number_t)get_buffer_size();

	logv(
		"Writing buffer of address 0x%jx and size 0x%jx (%ju), on "
		"memory at address 0x%jx in NULL VM MAP...",
		(uintmax_t)data, (uintmax_t)buffer_size, (uintmax_t)buffer_size, (uintmax_t)address);
	assert_mach_return(mach_vm_write(VM_MAP_NULL, address, data, buffer_size), MACH_SEND_INVALID_DEST, "mach_vm_write()");
	logv("Returned expected error: %s.", mach_error_string(MACH_SEND_INVALID_DEST));
}

/* Writing 0 bytes always succeeds. */
void
test_write_zero_size()
{
	set_buffer_size(0);
	write_buffer();
}

/*****************************************/
/* mach_vm_write() inaccessibility tests */
/*****************************************/

/* Writing a partially deallocated buffer fails. */
void
test_write_partially_deallocated_buffer()
{
	mach_vm_address_t address          = get_vm_address();
	vm_offset_t data                   = (vm_offset_t)get_buffer_address();
	mach_msg_type_number_t buffer_size = (mach_msg_type_number_t)get_buffer_size();
	mach_vm_address_t buffer_mid_point = (mach_vm_address_t)mach_vm_trunc_page(data + buffer_size / 2);

	logv(
		"Deallocating a mid-range buffer page at address "
		"0x%jx...",
		(uintmax_t)buffer_mid_point);
	assert_deallocate_success(buffer_mid_point, vm_page_size);
	logv("Page deallocated.");

	logv(
		"Writing buffer of address 0x%jx and size 0x%jx (%ju), on "
		"memory at address 0x%jx...",
		(uintmax_t)data, (uintmax_t)buffer_size, (uintmax_t)buffer_size, (uintmax_t)address);
	assert_write_return(address, data, buffer_size, MACH_SEND_INVALID_MEMORY);
	logv("Returned expected error: %s.", mach_error_string(MACH_SEND_INVALID_MEMORY));
}

/* Writing a partially read-protected buffer fails. */
void
test_write_partially_unreadable_buffer()
{
	mach_vm_address_t address          = get_vm_address();
	vm_offset_t data                   = (vm_offset_t)get_buffer_address();
	mach_msg_type_number_t buffer_size = (mach_msg_type_number_t)get_buffer_size();
	mach_vm_address_t buffer_mid_point = (mach_vm_address_t)mach_vm_trunc_page(data + buffer_size / 2);

	logv(
		"Read-protecting a mid-range buffer page at address "
		"0x%jx...",
		(uintmax_t)buffer_mid_point);
	T_QUIET; T_ASSERT_MACH_SUCCESS(mach_vm_protect(mach_task_self(), buffer_mid_point, vm_page_size, FALSE, VM_PROT_WRITE),
	    "mach_vm_protect()");
	logv("Page read-protected.");

	logv(
		"Writing buffer of address 0x%jx and size 0x%jx (%ju), on "
		"memory at address 0x%jx...",
		(uintmax_t)data, (uintmax_t)buffer_size, (uintmax_t)buffer_size, (uintmax_t)address);
	assert_write_return(address, data, buffer_size, MACH_SEND_INVALID_MEMORY);
	logv("Returned expected error: %s.", mach_error_string(MACH_SEND_INVALID_MEMORY));
}

/* Writing on partially deallocated memory fails. */
void
test_write_on_partially_deallocated_range()
{
	mach_vm_address_t address          = get_vm_address();
	mach_vm_address_t start            = mach_vm_trunc_page(address);
	vm_offset_t data                   = (vm_offset_t)get_buffer_address();
	mach_msg_type_number_t buffer_size = (mach_msg_type_number_t)get_buffer_size();

	logv(
		"Deallocating the first destination page at address "
		"0x%jx...",
		(uintmax_t)start);
	assert_deallocate_success(start, vm_page_size);
	logv("Page deallocated.");

	logv(
		"Writing buffer of address 0x%jx and size 0x%jx (%ju), on "
		"memory at address 0x%jx...",
		(uintmax_t)data, (uintmax_t)buffer_size, (uintmax_t)buffer_size, (uintmax_t)address);
	assert_write_return(address, data, buffer_size, KERN_INVALID_ADDRESS);
	logv("Returned expected error: %s.", mach_error_string(KERN_INVALID_ADDRESS));
}

/* Writing on partially unwritable memory fails. */
void
test_write_on_partially_unwritable_range()
{
	mach_vm_address_t address          = get_vm_address();
	mach_vm_address_t start            = mach_vm_trunc_page(address);
	vm_offset_t data                   = (vm_offset_t)get_buffer_address();
	mach_msg_type_number_t buffer_size = (mach_msg_type_number_t)get_buffer_size();

	/*  For sizes < msg_ool_size_small,
	 *  vm_map_copy_overwrite_nested() uses
	 *  vm_map_copyout_kernel_buffer() to read in the memory,
	 *  returning different errors, see 8217123. */
	kern_return_t kr_expected = (buffer_size < vm_page_size * 2) ? KERN_INVALID_ADDRESS : KERN_PROTECTION_FAILURE;

	logv(
		"Write-protecting the first destination page at address "
		"0x%jx...",
		(uintmax_t)start);
	T_QUIET; T_ASSERT_MACH_SUCCESS(mach_vm_protect(mach_task_self(), start, vm_page_size, FALSE, VM_PROT_READ), "mach_vm_protect()");
	logv("Page write-protected.");

	logv(
		"Writing buffer of address 0x%jx and size 0x%jx (%ju), on "
		"memory at address 0x%jx...",
		(uintmax_t)data, (uintmax_t)buffer_size, (uintmax_t)buffer_size, (uintmax_t)address);
	assert_write_return(address, data, buffer_size, kr_expected);
	logv("Returned expected error: %s.", mach_error_string(kr_expected));
}

/*********************************/
/* mach_vm_write() pattern tests */
/*********************************/

/* Verify that a zero-filled buffer and destination memory are still
 * zero-filled after writing. */
void
test_zero_filled_write()
{
	verify_pattern(empty, FALSE, mach_vm_trunc_page(get_vm_address()), round_page_kernel(get_vm_size() + 1), "zero-filled");
	verify_pattern(empty, FALSE, mach_vm_trunc_page(get_buffer_address()),
	    round_page_kernel(get_buffer_size() + get_buffer_offset()), "zero-filled");
}

/* Write a pattern on a buffer, write the buffer into some destination
 * memory, and verify the pattern on both buffer and destination. */
void
pattern_write(address_filter_t filter, boolean_t reversed, const char * pattern_name)
{
	mach_vm_address_t address        = get_vm_address();
	mach_vm_size_t size              = get_vm_size();
	mach_vm_address_t buffer_address = get_buffer_address();
	mach_vm_size_t buffer_size       = get_buffer_size();

	write_pattern(filter, reversed, buffer_address, buffer_size, pattern_name);
	write_buffer();
	verify_pattern(filter, reversed, buffer_address, buffer_size, pattern_name);
	logv(
		"Verifying %s pattern on destination of "
		"address 0x%jx and size 0x%jx (%ju)...",
		pattern_name, (uintmax_t)address, (uintmax_t)buffer_size, (uintmax_t)size);
	filter_addresses_do_else(filter, reversed, address, buffer_size, verify_address, read_zero, buffer_address);
	logv("Pattern verified on destination.");
}

void
test_address_filled_write()
{
	pattern_write(empty, TRUE, "address-filled");
}

void
test_checkerboard_write()
{
	pattern_write(checkerboard, FALSE, "checkerboard");
}

void
test_reverse_checkerboard_write()
{
	pattern_write(checkerboard, TRUE, "reverse checkerboard");
}

/**********************************/
/* mach_vm_copy() edge case tests */
/**********************************/

/* Copying in VM_MAP_NULL fails. */
void
test_copy_null_map()
{
	mach_vm_address_t source    = get_vm_address();
	mach_vm_address_t dest      = get_buffer_address();
	mach_msg_type_number_t size = (mach_msg_type_number_t)get_buffer_size();

	logv(
		"Copying buffer of address 0x%jx and size 0x%jx (%ju), on "
		"memory at address 0x%jx in NULL VM MAP...",
		(uintmax_t)dest, (uintmax_t)size, (uintmax_t)size, (uintmax_t)source);
	assert_mach_return(mach_vm_copy(VM_MAP_NULL, source, size, dest), MACH_SEND_INVALID_DEST, "mach_vm_copy()");
	logv("Returned expected error: %s.", mach_error_string(MACH_SEND_INVALID_DEST));
}

void
copy_edge_size(mach_vm_size_t size, kern_return_t expected_kr)
{
	int i;
	kern_return_t kr;
	vm_map_t this_task            = mach_task_self();
	mach_vm_address_t addresses[] = {0x0,
		                         0x1,
		                         vm_page_size - 1,
		                         vm_page_size,
		                         vm_page_size + 1,
		                         (mach_vm_address_t)UINT_MAX - vm_page_size + 1,
		                         (mach_vm_address_t)UINT_MAX,
		                         (mach_vm_address_t)UINTMAX_MAX - vm_page_size + 1,
		                         (mach_vm_address_t)UINTMAX_MAX};
	int numofaddresses     = sizeof(addresses) / sizeof(addresses[0]);
	mach_vm_address_t dest = 0;

	logv("Allocating 0x%jx (%ju) byte%s...", (uintmax_t)size, (uintmax_t)size, (size == 1) ? "" : "s");
	assert_allocate_success(&dest, 4096, VM_FLAGS_ANYWHERE);
	logv("Copying 0x%jx (%ju) bytes at various addresses...", (uintmax_t)size, (uintmax_t)size);
	for (i = 0; i < numofaddresses; i++) {
		kr = mach_vm_copy(this_task, addresses[i], size, dest);
		T_QUIET; T_ASSERT_EQ(kr, expected_kr,
		    "mach_vm_copy() at "
		    "address 0x%jx unexpectedly returned: %s.\n"
		    "Should have returned: %s.",
		    (uintmax_t)addresses[i], mach_error_string(kr), mach_error_string(expected_kr));
	}
	logv(
		"mach_vm_copy() returned expected value in each case: "
		"%s.",
		mach_error_string(expected_kr));

	deallocate_range(dest, 4096);
}

/* Copying 0 bytes always succeeds. */
void
test_copy_zero_size()
{
	copy_edge_size(0, KERN_SUCCESS);
}

/* Copying 4GB or higher always fails. */
void
test_copy_invalid_large_size()
{
	copy_edge_size((mach_vm_size_t)UINT_MAX - 1, KERN_INVALID_ADDRESS);
}

/* Reading a range wrapped around the address space fails. */
void
test_copy_wrapped_around_ranges()
{
	int i;
	kern_return_t kr;
	vm_map_t this_task = mach_task_self();
	struct {
		mach_vm_address_t address;
		mach_vm_size_t size;
	} ranges[] = {
		{(mach_vm_address_t)(UINTMAX_MAX - UINT_MAX + 1), (mach_vm_size_t)UINT_MAX},
		{(mach_vm_address_t)(UINTMAX_MAX - UINT_MAX + vm_page_size), (mach_vm_size_t)(UINT_MAX - vm_page_size + 1)},
		{(mach_vm_address_t)UINTMAX_MAX - vm_page_size + 1, vm_page_size},
		{(mach_vm_address_t)UINTMAX_MAX, 1},
	};
	int numofranges        = sizeof(ranges) / sizeof(ranges[0]);
	mach_vm_address_t dest = 0;

	logv("Allocating 0x1000 (4096) bytes...");
	assert_allocate_success(&dest, 4096, VM_FLAGS_ANYWHERE);

	logv(
		"Copying various memory ranges wrapping around the "
		"address space...");
	for (i = 0; i < numofranges; i++) {
		kr = mach_vm_copy(this_task, ranges[i].address, ranges[i].size, dest);
		T_QUIET; T_ASSERT_EQ(kr, KERN_INVALID_ADDRESS,
		    "mach_vm_copy() at address 0x%jx with size "
		    "0x%jx (%ju) unexpectedly returned: %s.\n"
		    "Should have returned: %s.",
		    (uintmax_t)ranges[i].address, (uintmax_t)ranges[i].size, (uintmax_t)ranges[i].size, mach_error_string(kr),
		    mach_error_string(KERN_INVALID_ADDRESS));
	}
	logv("Returned expected error on each range: %s.", mach_error_string(KERN_INVALID_ADDRESS));

	deallocate_range(dest, 4096);
}

/********************************/
/* mach_vm_copy() pattern tests */
/********************************/

/* Write a pattern on pre-allocated region, copy into another region
 * and verify the pattern in the region. */
void
write_copy_verify_pattern(address_filter_t filter, boolean_t reversed, const char * pattern_name)
{
	mach_vm_address_t source = get_vm_address();
	mach_vm_size_t src_size = get_vm_size();
	write_pattern(filter, reversed, source, src_size, pattern_name);
	/* Getting the address and size of the dest region */
	mach_vm_address_t dest  = get_buffer_address();
	mach_vm_size_t dst_size = get_buffer_size();

	logv(
		"Copying memory region of address 0x%jx and size 0x%jx (%ju), on "
		"memory at address 0x%jx...",
		(uintmax_t)source, (uintmax_t)dst_size, (uintmax_t)dst_size, (uintmax_t)dest);
	assert_copy_success(source, dst_size, dest);
	logv(
		"Verifying %s pattern in region of "
		"address 0x%jx and size 0x%jx (%ju)...",
		pattern_name, (uintmax_t)dest, (uintmax_t)dst_size, (uintmax_t)dst_size);
	filter_addresses_do_else(filter, reversed, dest, dst_size, verify_address, read_zero, source);
	logv("Pattern verified on destination region.");
}

void
test_copy_address_filled()
{
	write_copy_verify_pattern(empty, TRUE, "address-filled");
}

void
test_copy_checkerboard()
{
	write_copy_verify_pattern(checkerboard, FALSE, "checkerboard");
}

void
test_copy_reverse_checkerboard()
{
	write_copy_verify_pattern(checkerboard, TRUE, "reverse checkerboard");
}

/* Verify that a zero-filled source and destination memory are still
 * zero-filled after writing. */
void
test_zero_filled_copy_dest()
{
	verify_pattern(empty, FALSE, mach_vm_trunc_page(get_vm_address()), round_page_kernel(get_vm_size() + 1), "zero-filled");
	verify_pattern(empty, FALSE, mach_vm_trunc_page(get_buffer_address()),
	    round_page_kernel(get_buffer_size() + get_buffer_offset()), "zero-filled");
}

/****************************************/
/* mach_vm_copy() inaccessibility tests */
/****************************************/

/* Copying partially deallocated memory fails. */
void
test_copy_partially_deallocated_range()
{
	mach_vm_address_t source    = get_vm_address();
	mach_vm_size_t size         = get_vm_size();
	mach_vm_address_t mid_point = mach_vm_trunc_page(source + size / 2);
	mach_vm_address_t dest      = 0;

	logv("Deallocating a mid-range page at address 0x%jx...", (uintmax_t)mid_point);
	assert_deallocate_success(mid_point, vm_page_size);
	logv("Page deallocated.");

	logv("Copying 0x%jx (%ju) byte%s at address 0x%jx...", (uintmax_t)size, (uintmax_t)size, (size == 1) ? "" : "s",
	    (uintmax_t)source);

	assert_allocate_copy_return(source, size, &dest, KERN_INVALID_ADDRESS);

	logv("Returned expected error: %s.", mach_error_string(KERN_INVALID_ADDRESS));

	deallocate_range(dest, size);
}

/* Copy partially read-protected memory fails. */
void
test_copy_partially_unreadable_range()
{
	mach_vm_address_t source    = get_vm_address();
	mach_vm_size_t size         = get_vm_size();
	mach_vm_address_t mid_point = mach_vm_trunc_page(source + size / 2);
	mach_vm_address_t dest      = 0;

	/*  For sizes < 1 page, vm_map_copyin_common() uses
	 *  vm_map_copyin_kernel_buffer() to read in the memory,
	 *  returning different errors, see 8182239. */
	kern_return_t kr_expected = (size < vm_page_size) ? KERN_INVALID_ADDRESS : KERN_PROTECTION_FAILURE;

	logv("Read-protecting a mid-range page at address 0x%jx...", (uintmax_t)mid_point);
	T_QUIET; T_ASSERT_MACH_SUCCESS(mach_vm_protect(mach_task_self(), mid_point, vm_page_size, FALSE, VM_PROT_WRITE), "mach_vm_protect()");
	logv("Page read-protected.");

	logv("Copying 0x%jx (%ju) byte%s at address 0x%jx...", (uintmax_t)size, (uintmax_t)size, (size == 1) ? "" : "s",
	    (uintmax_t)source);
	assert_allocate_copy_return(source, size, &dest, kr_expected);
	logv("Returned expected error: %s.", mach_error_string(kr_expected));

	deallocate_range(dest, size);
}

/* Copying to a partially deallocated region fails. */
void
test_copy_dest_partially_deallocated_region()
{
	mach_vm_address_t dest             = get_vm_address();
	mach_vm_address_t source           = get_buffer_address();
	mach_msg_type_number_t size        = (mach_msg_type_number_t)get_buffer_size();
	mach_vm_address_t source_mid_point = (mach_vm_address_t)mach_vm_trunc_page(dest + size / 2);
#if __MAC_OX_X_VERSION_MIN_REQUIRED > 1080
	logv(
		"Deallocating a mid-range source page at address "
		"0x%jx...",
		(uintmax_t)source_mid_point);
	assert_deallocate_success(source_mid_point, vm_page_size);
	logv("Page deallocated.");

	logv(
		"Copying region of address 0x%jx and size 0x%jx (%ju), on "
		"memory at address 0x%jx...",
		(uintmax_t)source, (uintmax_t)size, (uintmax_t)size, (uintmax_t)dest);
	assert_copy_return(source, size, dest, KERN_INVALID_ADDRESS);
	logv("Returned expected error: %s.", mach_error_string(KERN_INVALID_ADDRESS));
#else
	logv(
		"Bypassing partially deallocated region test "
		"(See <rdar://problem/12190999>)");
#endif /* __MAC_OX_X_VERSION_MIN_REQUIRED > 1080 */
}

/* Copying from a partially deallocated region fails. */
void
test_copy_source_partially_deallocated_region()
{
	mach_vm_address_t source           = get_vm_address();
	mach_vm_address_t dest             = get_buffer_address();
	mach_msg_type_number_t size        = (mach_msg_type_number_t)get_buffer_size();
	mach_vm_address_t source_mid_point = (mach_vm_address_t)mach_vm_trunc_page(source + size / 2);

	logv(
		"Deallocating a mid-range source page at address "
		"0x%jx...",
		(uintmax_t)source_mid_point);
	assert_deallocate_success(source_mid_point, vm_page_size);
	logv("Page deallocated.");

	logv(
		"Copying region of address 0x%jx and size 0x%jx (%ju), on "
		"memory at address 0x%jx...",
		(uintmax_t)source, (uintmax_t)size, (uintmax_t)size, (uintmax_t)dest);
	assert_copy_return(source, size, dest, KERN_INVALID_ADDRESS);
	logv("Returned expected error: %s.", mach_error_string(KERN_INVALID_ADDRESS));
}

/* Copying from a partially read-protected region fails. */
void
test_copy_source_partially_unreadable_region()
{
	mach_vm_address_t source    = get_vm_address();
	mach_vm_address_t dest      = get_buffer_address();
	mach_msg_type_number_t size = (mach_msg_type_number_t)get_buffer_size();
	mach_vm_address_t mid_point = (mach_vm_address_t)mach_vm_trunc_page(source + size / 2);
	kern_return_t kr            = (size < vm_page_size * 2) ? KERN_INVALID_ADDRESS : KERN_PROTECTION_FAILURE;

	logv(
		"Read-protecting a mid-range buffer page at address "
		"0x%jx...",
		(uintmax_t)mid_point);
	T_QUIET; T_ASSERT_MACH_SUCCESS(mach_vm_protect(mach_task_self(), mid_point, vm_page_size, FALSE, VM_PROT_WRITE), "mach_vm_protect()");
	logv("Page read-protected.");

	logv(
		"Copying region at address 0x%jx and size 0x%jx (%ju), on "
		"memory at address 0x%jx...",
		(uintmax_t)source, (uintmax_t)size, (uintmax_t)size, (uintmax_t)dest);

	assert_copy_return(source, size, dest, kr);
	logv("Returned expected error: %s.", mach_error_string(kr));
}

/* Copying to a partially write-protected region fails. */
void
test_copy_dest_partially_unwriteable_region()
{
	kern_return_t kr;
	mach_vm_address_t dest      = get_vm_address();
	mach_vm_address_t source    = get_buffer_address();
	mach_msg_type_number_t size = (mach_msg_type_number_t)get_buffer_size();
	mach_vm_address_t mid_point = (mach_vm_address_t)mach_vm_trunc_page(dest + size / 2);

#if __MAC_OX_X_VERSION_MIN_REQUIRED > 1080
	logv(
		"Read-protecting a mid-range buffer page at address "
		"0x%jx...",
		(uintmax_t)mid_point);
	T_QUIET; T_ASSERT_MACH_SUCCESS(mach_vm_protect(mach_task_self(), mid_point, vm_page_size, FALSE, VM_PROT_READ), "mach_vm_protect()");
	logv("Page read-protected.");
	logv(
		"Copying region at address 0x%jx and size 0x%jx (%ju), on "
		"memory at address 0x%jx...",
		(uintmax_t)source, (uintmax_t)size, (uintmax_t)size, (uintmax_t)dest);
	if (size >= vm_page_size) {
		kr = KERN_PROTECTION_FAILURE;
	} else {
		kr = KERN_INVALID_ADDRESS;
	}
	assert_copy_return(source, size, dest, kr);
	logv("Returned expected error: %s.", mach_error_string(kr));
#else
	logv(
		"Bypassing partially unwriteable region test "
		"(See <rdar://problem/12190999>)");
#endif /* __MAC_OX_X_VERSION_MIN_REQUIRED > 1080 */
}

/* Copying on partially deallocated memory fails. */
void
test_copy_source_on_partially_deallocated_range()
{
	mach_vm_address_t source    = get_vm_address();
	mach_vm_address_t dest      = get_buffer_address();
	mach_vm_address_t start     = mach_vm_trunc_page(source);
	mach_msg_type_number_t size = (mach_msg_type_number_t)get_buffer_size();

	logv(
		"Deallocating the first source page at address "
		"0x%jx...",
		(uintmax_t)start);
	assert_deallocate_success(start, vm_page_size);
	logv("Page deallocated.");

	logv(
		"Writing buffer of address 0x%jx and size 0x%jx (%ju), on "
		"memory at address 0x%jx...",
		(uintmax_t)dest, (uintmax_t)size, (uintmax_t)size, (uintmax_t)source);
	assert_copy_return(source, size, dest, KERN_INVALID_ADDRESS);
	logv("Returned expected error: %s.", mach_error_string(KERN_INVALID_ADDRESS));
}

/* Copying on partially deallocated memory fails. */
void
test_copy_dest_on_partially_deallocated_range()
{
	mach_vm_address_t source    = get_vm_address();
	mach_vm_address_t dest      = get_buffer_address();
	mach_vm_address_t start     = mach_vm_trunc_page(dest);
	mach_msg_type_number_t size = (mach_msg_type_number_t)get_buffer_size();

	logv(
		"Deallocating the first destination page at address "
		"0x%jx...",
		(uintmax_t)start);
	assert_deallocate_success(start, vm_page_size);
	logv("Page deallocated.");

	logv(
		"Writing buffer of address 0x%jx and size 0x%jx (%ju), on "
		"memory at address 0x%jx...",
		(uintmax_t)dest, (uintmax_t)size, (uintmax_t)size, (uintmax_t)source);
	assert_copy_return(source, size, dest, KERN_INVALID_ADDRESS);
	logv("Returned expected error: %s.", mach_error_string(KERN_INVALID_ADDRESS));
}

/* Copying on partially unwritable memory fails. */
void
test_copy_dest_on_partially_unwritable_range()
{
	mach_vm_address_t source    = get_vm_address();
	mach_vm_address_t dest      = get_buffer_address();
	mach_vm_address_t start     = mach_vm_trunc_page(dest);
	mach_msg_type_number_t size = (mach_msg_type_number_t)get_buffer_size();

	/*  For sizes < msg_ool_size_small,
	 *  vm_map_copy_overwrite_nested() uses
	 *  vm_map_copyout_kernel_buffer() to read in the memory,
	 *  returning different errors, see 8217123. */
	kern_return_t kr_expected = (size < vm_page_size * 2) ? KERN_INVALID_ADDRESS : KERN_PROTECTION_FAILURE;

	logv(
		"Write-protecting the first destination page at address "
		"0x%jx...",
		(uintmax_t)start);
	T_QUIET; T_ASSERT_MACH_SUCCESS(mach_vm_protect(mach_task_self(), start, vm_page_size, FALSE, VM_PROT_READ), "mach_vm_protect()");
	logv("Page write-protected.");

	logv(
		"Writing buffer of address 0x%jx and size 0x%jx (%ju), on "
		"memory at address 0x%jx...",
		(uintmax_t)dest, (uintmax_t)size, (uintmax_t)size, (uintmax_t)source);
	assert_copy_return(source, size, dest, kr_expected);
	logv("Returned expected error: %s.", mach_error_string(kr_expected));
}

/* Copying on partially unreadable memory fails. */
void
test_copy_source_on_partially_unreadable_range()
{
	mach_vm_address_t source    = get_vm_address();
	mach_vm_address_t dest      = get_buffer_address();
	mach_vm_address_t start     = mach_vm_trunc_page(source);
	mach_msg_type_number_t size = (mach_msg_type_number_t)get_buffer_size();

	/*  For sizes < msg_ool_size_small,
	 *  vm_map_copy_overwrite_nested() uses
	 *  vm_map_copyout_kernel_buffer() to read in the memory,
	 *  returning different errors, see 8217123. */
	kern_return_t kr_expected = (size < vm_page_size * 2) ? KERN_INVALID_ADDRESS : KERN_PROTECTION_FAILURE;

	logv(
		"Read-protecting the first destination page at address "
		"0x%jx...",
		(uintmax_t)start);
	T_QUIET; T_ASSERT_MACH_SUCCESS(mach_vm_protect(mach_task_self(), start, vm_page_size, FALSE, VM_PROT_WRITE), "mach_vm_protect()");
	logv("Page read-protected.");

	logv(
		"Writing buffer of address 0x%jx and size 0x%jx (%ju), on "
		"memory at address 0x%jx...",
		(uintmax_t)dest, (uintmax_t)size, (uintmax_t)size, (uintmax_t)source);
	assert_copy_return(source, size, dest, kr_expected);
	logv("Returned expected error: %s.", mach_error_string(kr_expected));
}

/********************************/
/* mach_vm_protect() main tests */
/********************************/

void
test_zero_filled_extended()
{
	verify_pattern(empty, FALSE, mach_vm_trunc_page(get_vm_address()), round_page_kernel(get_vm_size() + 1), "zero-filled");
}

/* Allocated region is still zero-filled after read-protecting it and
 * then restoring read-access. */
void
test_zero_filled_readprotect()
{
	mach_vm_address_t address = get_vm_address();
	mach_vm_size_t size       = get_vm_size();

	logv("Setting read access on 0x%jx (%ju) byte%s at address 0x%jx...", (uintmax_t)size, (uintmax_t)size,
	    (size == 1) ? "" : "s", (uintmax_t)address);
	T_QUIET; T_ASSERT_MACH_SUCCESS(mach_vm_protect(mach_task_self(), address, size, FALSE, VM_PROT_DEFAULT), "mach_vm_protect()");
	logv("Region has read access.");
	test_zero_filled_extended();
}

void
verify_protection(vm_prot_t protection, const char * protection_name)
{
	mach_vm_address_t address    = get_vm_address();
	mach_vm_size_t size          = get_vm_size();
	mach_vm_size_t original_size = size;
	vm_region_basic_info_data_64_t info;
	mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
	mach_port_t unused;

	logv(
		"Verifying %s-protection on region of address 0x%jx and "
		"size 0x%jx (%ju) with mach_vm_region()...",
		protection_name, (uintmax_t)address, (uintmax_t)size, (uintmax_t)size);
	T_QUIET; T_ASSERT_MACH_SUCCESS(
		mach_vm_region(mach_task_self(), &address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &unused),
		"mach_vm_region()");
	if (original_size) {
		T_QUIET; T_ASSERT_EQ((info.protection & protection), 0,
		    "Region "
		    "is unexpectedly %s-unprotected.",
		    protection_name);
		logv("Region is %s-protected as expected.", protection_name);
	} else {
		T_QUIET; T_ASSERT_NE(info.protection & protection, 0,
		    "Region is "
		    "unexpectedly %s-protected.",
		    protection_name);
		logv("Region is %s-unprotected as expected.", protection_name);
	}
}

void
test_verify_readprotection()
{
	verify_protection(VM_PROT_READ, "read");
}

void
test_verify_writeprotection()
{
	verify_protection(VM_PROT_WRITE, "write");
}

/******************************/
/* Protection bus error tests */
/******************************/

/* mach_vm_protect() affects the smallest aligned region (integral
 * number of pages) containing the given range. */

/* Addresses in read-protected range are inaccessible. */
void
access_readprotected_range_address(mach_vm_address_t address, const char * position)
{
	logv("Reading from %s 0x%jx of read-protected range...", position, (uintmax_t)address);
	mach_vm_address_t bad_value = MACH_VM_ADDRESS_T(address);
	T_ASSERT_FAIL("Unexpectedly read value 0x%jx at address 0x%jx."
	    "Should have died with signal SIGBUS.",
	    (uintmax_t)bad_value, (uintmax_t)address);
}

/* Start of read-protected range is inaccessible. */
void
test_access_readprotected_range_start()
{
	access_readprotected_range_address(mach_vm_trunc_page(get_vm_address()), "start");
}

/* Middle of read-protected range is inaccessible. */
void
test_access_readprotected_range_middle()
{
	mach_vm_address_t address = get_vm_address();
	access_readprotected_range_address(mach_vm_trunc_page(address) + (aligned_size(address, get_vm_size()) >> 1), "middle");
}

/* End of read-protected range is inaccessible. */
void
test_access_readprotected_range_end()
{
	access_readprotected_range_address(round_page_kernel(get_vm_address() + get_vm_size()) - vm_address_size, "end");
}

/* Addresses in write-protected range are unwritable. */
void
write_writeprotected_range_address(mach_vm_address_t address, const char * position)
{
	logv("Writing on %s 0x%jx of write-protected range...", position, (uintmax_t)address);
	MACH_VM_ADDRESS_T(address) = 0x0;
	T_ASSERT_FAIL("Unexpectedly wrote value 0x0 value at address 0x%jx."
	    "Should have died with signal SIGBUS.",
	    (uintmax_t)address);
}

/* Start of write-protected range is unwritable. */
void
test_write_writeprotected_range_start()
{
	write_writeprotected_range_address(mach_vm_trunc_page(get_vm_address()), "start");
}

/* Middle of write-protected range is unwritable. */
void
test_write_writeprotected_range_middle()
{
	mach_vm_address_t address = get_vm_address();
	write_writeprotected_range_address(mach_vm_trunc_page(address) + (aligned_size(address, get_vm_size()) >> 1), "middle");
}

/* End of write-protected range is unwritable. */
void
test_write_writeprotected_range_end()
{
	write_writeprotected_range_address(round_page_kernel(get_vm_address() + get_vm_size()) - vm_address_size, "end");
}

/*************************************/
/* mach_vm_protect() edge case tests */
/*************************************/

void
protect_zero_size(vm_prot_t protection, const char * protection_name)
{
	int i;
	kern_return_t kr;
	vm_map_t this_task            = mach_task_self();
	mach_vm_address_t addresses[] = {0x0,
		                         0x1,
		                         vm_page_size - 1,
		                         vm_page_size,
		                         vm_page_size + 1,
		                         (mach_vm_address_t)UINT_MAX - vm_page_size + 1,
		                         (mach_vm_address_t)UINT_MAX,
		                         (mach_vm_address_t)UINTMAX_MAX - vm_page_size + 1,
		                         (mach_vm_address_t)UINTMAX_MAX};
	int numofaddresses = sizeof(addresses) / sizeof(addresses[0]);

	logv("%s-protecting 0x0 (0) bytes at various addresses...", protection_name);
	for (i = 0; i < numofaddresses; i++) {
		kr = mach_vm_protect(this_task, addresses[i], 0, FALSE, protection);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr,
		    "mach_vm_protect() at "
		    "address 0x%jx unexpectedly failed: %s.",
		    (uintmax_t)addresses[i], mach_error_string(kr));
	}
	logv("Protection successful.");
}

void
test_readprotect_zero_size()
{
	protect_zero_size(VM_PROT_READ, "Read");
}

void
test_writeprotect_zero_size()
{
	protect_zero_size(VM_PROT_WRITE, "Write");
}

/* Protecting a range wrapped around the address space fails. */
void
protect_wrapped_around_ranges(vm_prot_t protection, const char * protection_name)
{
	int i;
	kern_return_t kr;
	vm_map_t this_task = mach_task_self();
	struct {
		mach_vm_address_t address;
		mach_vm_size_t size;
	} ranges[] = {
		{0x1, (mach_vm_size_t)UINTMAX_MAX},
		{vm_page_size, (mach_vm_size_t)UINTMAX_MAX - vm_page_size + 1},
		{(mach_vm_address_t)UINTMAX_MAX - vm_page_size + 1, vm_page_size},
		{(mach_vm_address_t)UINTMAX_MAX, 1},
	};
	int numofranges = sizeof(ranges) / sizeof(ranges[0]);

	logv(
		"%s-protecting various memory ranges wrapping around the "
		"address space...",
		protection_name);
	for (i = 0; i < numofranges; i++) {
		kr = mach_vm_protect(this_task, ranges[i].address, ranges[i].size, FALSE, protection);
		T_QUIET; T_ASSERT_EQ(kr, KERN_INVALID_ARGUMENT,
		    "mach_vm_protect() with address 0x%jx and size "
		    "0x%jx (%ju) unexpectedly returned: %s.\n"
		    "Should have returned: %s.",
		    (uintmax_t)ranges[i].address, (uintmax_t)ranges[i].size, (uintmax_t)ranges[i].size, mach_error_string(kr),
		    mach_error_string(KERN_INVALID_ARGUMENT));
	}
	logv("Returned expected error on each range: %s.", mach_error_string(KERN_INVALID_ARGUMENT));
}

void
test_readprotect_wrapped_around_ranges()
{
	protect_wrapped_around_ranges(VM_PROT_READ, "Read");
}

void
test_writeprotect_wrapped_around_ranges()
{
	protect_wrapped_around_ranges(VM_PROT_WRITE, "Write");
}

/*******************/
/* vm_copy() tests */
/*******************/

/* Verify the address space is being shared. */
void
assert_share_mode(mach_vm_address_t address, unsigned share_mode, const char * share_mode_name)
{
	mach_vm_size_t size = get_vm_size();
	vm_region_extended_info_data_t info;
	mach_msg_type_number_t count = VM_REGION_EXTENDED_INFO_COUNT;
	mach_port_t unused;

/*
 * XXX Fails on UVM kernel.  See <rdar://problem/12164664>
 */
#if notyet /* __MAC_OS_X_VERSION_MIN_REQUIRED < 1090 */
	logv(
		"Verifying %s share mode on region of address 0x%jx and "
		"size 0x%jx (%ju)...",
		share_mode_name, (uintmax_t)address, (uintmax_t)size, (uintmax_t)size);
	T_QUIET; T_ASSERT_MACH_SUCCESS(
		mach_vm_region(mach_task_self(), &address, &size, VM_REGION_EXTENDED_INFO, (vm_region_info_t)&info, &count, &unused),
		"mach_vm_region()");
	T_QUIET; T_ASSERT_EQ(info.share_mode, share_mode,
	    "Region's share mode "
	    " unexpectedly is not %s but %d.",
	    share_mode_name, info.share_mode);
	logv("Region has a share mode of %s as expected.", share_mode_name);
#else
	logv("Bypassing share_mode verification (See <rdar://problem/12164664>)");
#endif /* __MAC_OS_X_VERSION_MIN_REQUIRED < 1090 */
}

/* Do the vm_copy() and verify its success. */
void
assert_vmcopy_success(vm_address_t src, vm_address_t dst, const char * source_name)
{
	kern_return_t kr;
	mach_vm_size_t size = get_vm_size();

	logv("Copying (using mach_vm_copy()) from a %s source...", source_name);
	kr = mach_vm_copy(mach_task_self(), src, size, dst);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr,
	    "mach_vm_copy() with the source address "
	    "0x%jx, designation address 0x%jx, and size 0x%jx (%ju) unexpectly "
	    "returned %s.\n  Should have returned: %s.",
	    (uintmax_t)src, (uintmax_t)dst, (uintmax_t)size, (uintmax_t)size, mach_error_string(kr),
	    mach_error_string(KERN_SUCCESS));
	logv("Copy (mach_vm_copy()) was successful as expected.");
}

void
write_region(mach_vm_address_t address, mach_vm_size_t start)
{
	mach_vm_size_t size = get_vm_size();

	filter_addresses_do_else(empty, FALSE, address, size, write_address, write_address, start);
}

void
verify_region(mach_vm_address_t address, mach_vm_address_t start)
{
	mach_vm_size_t size = get_vm_size();

	filter_addresses_do_else(empty, FALSE, address, size, verify_address, verify_address, start);
}

/* Perform the post vm_copy() action and verify its results. */
void
modify_one_and_verify_all_regions(vm_address_t src, vm_address_t dst, vm_address_t shared_copied, boolean_t shared)
{
	mach_vm_size_t size = get_vm_size();
	int action          = get_vmcopy_post_action();

	/* Do the post vm_copy() action. */
	switch (action) {
	case VMCOPY_MODIFY_SRC:
		logv("Modifying: source%s...", shared ? " (shared with other region)" : "");
		write_region(src, 1);
		break;

	case VMCOPY_MODIFY_DST:
		logv("Modifying: destination...");
		write_region(dst, 1);
		break;

	case VMCOPY_MODIFY_SHARED_COPIED:
		/* If no shared_copied then no need to verify (nothing changed). */
		if (!shared_copied) {
			return;
		}
		logv("Modifying: shared/copied%s...", shared ? " (shared with source region)" : "");
		write_region(shared_copied, 1);
		break;

	default:
		T_ASSERT_FAIL("Unknown post vm_copy() action (%d)", action);
	}
	logv("Modification was successful as expected.");

	/* Verify all the regions with what is expected. */
	logv("Verifying: source... ");
	verify_region(src, (VMCOPY_MODIFY_SRC == action || (shared && VMCOPY_MODIFY_SHARED_COPIED == action)) ? 1 : 0);
	logv("destination... ");
	verify_region(dst, (VMCOPY_MODIFY_DST == action) ? 1 : 0);
	if (shared_copied) {
		logv("shared/copied... ");
		verify_region(shared_copied, (VMCOPY_MODIFY_SHARED_COPIED == action || (shared && VMCOPY_MODIFY_SRC == action)) ? 1 : 0);
	}
	logv("Verification was successful as expected.");
}

/* Test source being a simple fresh region. */
void
test_vmcopy_fresh_source()
{
	mach_vm_size_t size = get_vm_size();
	mach_vm_address_t src, dst;

	if (get_vmcopy_post_action() == VMCOPY_MODIFY_SHARED_COPIED) {
		/* No shared/copied region to modify so just return. */
		logv("No shared/copied region as expected.");
		return;
	}

	assert_allocate_success(&src, size, TRUE);

	assert_share_mode(src, SM_EMPTY, "SM_EMPTY");

	write_region(src, 0);

	assert_allocate_success(&dst, size, TRUE);

	assert_vmcopy_success(src, dst, "freshly allocated");

	modify_one_and_verify_all_regions(src, dst, 0, FALSE);

	assert_deallocate_success(src, size);
	assert_deallocate_success(dst, size);
}

/* Test source copied from a shared region. */
void
test_vmcopy_shared_source()
{
	mach_vm_size_t size = get_vm_size();
	mach_vm_address_t src, dst, shared;
	int action = get_vmcopy_post_action();
	int pid, status;

	assert_allocate_success(&src, size, TRUE);

	T_QUIET; T_ASSERT_MACH_SUCCESS(mach_vm_inherit(mach_task_self(), src, size, VM_INHERIT_SHARE), "mach_vm_inherit()");

	write_region(src, 0);

	pid = fork();
	if (pid == 0) {
		/* Verify that the child's 'src' is shared with the
		 *  parent's src */
		assert_share_mode(src, SM_SHARED, "SM_SHARED");
		assert_allocate_success(&dst, size, TRUE);
		assert_vmcopy_success(src, dst, "shared");
		if (VMCOPY_MODIFY_SHARED_COPIED == action) {
			logv("Modifying: shared...");
			write_region(src, 1);
			logv("Modification was successsful as expected.");
			logv("Verifying: source... ");
			verify_region(src, 1);
			logv("destination...");
			verify_region(dst, (VMCOPY_MODIFY_DST == action) ? 1 : 0);
			logv("Verification was successful as expected.");
		} else {
			modify_one_and_verify_all_regions(src, dst, 0, TRUE);
		}
		assert_deallocate_success(dst, size);
		exit(0);
	} else if (pid > 0) {
		/* In the parent the src becomes the shared */
		shared = src;
		wait(&status);
		if (WEXITSTATUS(status) != 0) {
			exit(status);
		}
		/* verify shared (shared with child's src) */
		logv("Verifying: shared...");
		verify_region(shared, (VMCOPY_MODIFY_SHARED_COPIED == action || VMCOPY_MODIFY_SRC == action) ? 1 : 0);
		logv("Verification was successful as expected.");
	} else {
		T_WITH_ERRNO; T_ASSERT_FAIL("fork failed");
	}

	assert_deallocate_success(src, size);
}

/* Test source copied from another mapping. */
void
test_vmcopy_copied_from_source()
{
	mach_vm_size_t size = get_vm_size();
	mach_vm_address_t src, dst, copied;

	assert_allocate_success(&copied, size, TRUE);
	write_region(copied, 0);

	assert_allocate_success(&src, size, TRUE);

	T_QUIET; T_ASSERT_MACH_SUCCESS(mach_vm_copy(mach_task_self(), copied, size, src), "mach_vm_copy()");

	assert_share_mode(src, SM_COW, "SM_COW");

	assert_allocate_success(&dst, size, TRUE);

	assert_vmcopy_success(src, dst, "copied from");

	modify_one_and_verify_all_regions(src, dst, copied, FALSE);

	assert_deallocate_success(src, size);
	assert_deallocate_success(dst, size);
	assert_deallocate_success(copied, size);
}

/* Test source copied to another mapping. */
void
test_vmcopy_copied_to_source()
{
	mach_vm_size_t size = get_vm_size();
	mach_vm_address_t src, dst, copied;

	assert_allocate_success(&src, size, TRUE);
	write_region(src, 0);

	assert_allocate_success(&copied, size, TRUE);

	T_QUIET; T_ASSERT_MACH_SUCCESS(mach_vm_copy(mach_task_self(), src, size, copied), "mach_vm_copy()");

	assert_share_mode(src, SM_COW, "SM_COW");

	assert_allocate_success(&dst, size, TRUE);

	assert_vmcopy_success(src, dst, "copied to");

	modify_one_and_verify_all_regions(src, dst, copied, FALSE);

	assert_deallocate_success(src, size);
	assert_deallocate_success(dst, size);
	assert_deallocate_success(copied, size);
}

/* Test a truedshared source copied. */
void
test_vmcopy_trueshared_source()
{
	mach_vm_size_t size   = get_vm_size();
	mach_vm_address_t src = 0x0, dst, shared;
	vm_prot_t cur_protect = (VM_PROT_READ | VM_PROT_WRITE);
	vm_prot_t max_protect = (VM_PROT_READ | VM_PROT_WRITE);
	mem_entry_name_port_t mem_obj;

	assert_allocate_success(&shared, size, TRUE);
	write_region(shared, 0);

	T_QUIET; T_ASSERT_MACH_SUCCESS(mach_make_memory_entry_64(mach_task_self(), &size, (memory_object_offset_t)shared, cur_protect, &mem_obj,
	    (mem_entry_name_port_t)NULL),
	    "mach_make_memory_entry_64()");
	T_QUIET; T_ASSERT_MACH_SUCCESS(
		mach_vm_map(mach_task_self(), &src, size, 0, TRUE, mem_obj, 0, FALSE, cur_protect, max_protect, VM_INHERIT_NONE),
		"mach_vm_map()");

	assert_share_mode(src, SM_TRUESHARED, "SM_TRUESHARED");

	assert_allocate_success(&dst, size, TRUE);

	assert_vmcopy_success(src, dst, "true shared");

	modify_one_and_verify_all_regions(src, dst, shared, TRUE);

	assert_deallocate_success(src, size);
	assert_deallocate_success(dst, size);
	assert_deallocate_success(shared, size);
}

/* Test a private aliazed source copied. */
void
test_vmcopy_private_aliased_source()
{
	mach_vm_size_t size   = get_vm_size();
	mach_vm_address_t src = 0x0, dst, shared;
	vm_prot_t cur_protect = (VM_PROT_READ | VM_PROT_WRITE);
	vm_prot_t max_protect = (VM_PROT_READ | VM_PROT_WRITE);

	assert_allocate_success(&shared, size, TRUE);
	write_region(shared, 0);

	T_QUIET; T_ASSERT_MACH_SUCCESS(mach_vm_remap(mach_task_self(), &src, size, 0, TRUE, mach_task_self(), shared, FALSE, &cur_protect,
	    &max_protect, VM_INHERIT_NONE),
	    "mach_vm_remap()");

	assert_share_mode(src, SM_PRIVATE_ALIASED, "SM_PRIVATE_ALIASED");

	assert_allocate_success(&dst, size, TRUE);

	assert_vmcopy_success(src, dst, "true shared");

	modify_one_and_verify_all_regions(src, dst, shared, TRUE);

	assert_deallocate_success(src, size);
	assert_deallocate_success(dst, size);
	assert_deallocate_success(shared, size);
}

/*************/
/* VM Suites */
/*************/

void
run_allocate_test_suites()
{
	/* <rdar://problem/10304215> CoreOSZin 12Z30: VMUnitTest fails:
	 * error finding xnu major version number. */
	/* unsigned int xnu_version = xnu_major_version(); */

	UnitTests allocate_main_tests = {
		{"Allocated address is nonzero iff size is nonzero", test_nonzero_address_iff_nonzero_size},
		{"Allocated address is page-aligned", test_aligned_address},
		{"Allocated memory is zero-filled", test_zero_filled},
		{"Write and verify address-filled pattern", test_write_address_filled},
		{"Write and verify checkerboard pattern", test_write_checkerboard},
		{"Write and verify reverse checkerboard pattern", test_write_reverse_checkerboard},
		{"Write and verify page ends pattern", test_write_page_ends},
		{"Write and verify page interiors pattern", test_write_page_interiors},
		{"Reallocate allocated pages", test_reallocate_pages},
	};
	UnitTests allocate_address_error_tests = {
		{"Allocate at address zero", test_allocate_at_zero},
		{"Allocate at a 2 MB boundary-unaligned, page-aligned "
		 "address",
		 test_allocate_2MB_boundary_unaligned_page_aligned_address},
	};
	UnitTests allocate_argument_error_tests = {
		{"Allocate in NULL VM map", test_allocate_in_null_map}, {"Allocate with kernel flags", test_allocate_with_kernel_flags},
	};
	UnitTests allocate_fixed_size_tests = {
		{"Allocate zero size", test_allocate_zero_size},
		{"Allocate overflowing size", test_allocate_overflowing_size},
		{"Allocate a page with highest address hint", test_allocate_page_with_highest_address_hint},
		{"Allocate two pages and verify first fit strategy", test_allocate_first_fit_pages},
	};
	UnitTests allocate_invalid_large_size_test = {
		{"Allocate invalid large size", test_allocate_invalid_large_size},
	};
	UnitTests mach_vm_map_protection_inheritance_error_test = {
		{"mach_vm_map() with invalid protection/inheritance "
		 "arguments",
		 test_mach_vm_map_protection_inheritance_error},
	};
	UnitTests mach_vm_map_large_mask_overflow_error_test = {
		{"mach_vm_map() with large address mask", test_mach_vm_map_large_mask_overflow_error},
	};

	/* Run the test suites with various allocators and VM sizes, and
	 *  unspecified or fixed (page-aligned or page-unaligned),
	 *  addresses. */
	for (allocators_idx = 0; allocators_idx < numofallocators; allocators_idx++) {
		for (sizes_idx = 0; sizes_idx < numofsizes; sizes_idx++) {
			for (flags_idx = 0; flags_idx < numofflags; flags_idx++) {
				for (alignments_idx = 0; alignments_idx < numofalignments; alignments_idx++) {
					/* An allocated address will be page-aligned. */
					/* Only run the zero size mach_vm_map() error tests in the
					 *  unspecified address case, since we won't be able to retrieve a
					 *  fixed address for allocation. See 8003930. */
					if ((flags_idx == ANYWHERE && alignments_idx == UNALIGNED) ||
					    (allocators_idx != MACH_VM_ALLOCATE && sizes_idx == ZERO_BYTES && flags_idx == FIXED)) {
						continue;
					}
					run_suite(set_up_allocator_and_vm_variables, allocate_argument_error_tests, do_nothing,
					    "%s argument error tests, %s%s address, "
					    "%s size: 0x%jx (%ju)",
					    allocators[allocators_idx].description, address_flags[flags_idx].description,
					    (flags_idx == ANYWHERE) ? "" : address_alignments[alignments_idx].description,
					    vm_sizes[sizes_idx].description, (uintmax_t)vm_sizes[sizes_idx].size,
					    (uintmax_t)vm_sizes[sizes_idx].size);
					/* mach_vm_map() only protection and inheritance error
					 *  tests. */
					if (allocators_idx != MACH_VM_ALLOCATE) {
						run_suite(set_up_allocator_and_vm_variables, mach_vm_map_protection_inheritance_error_test, do_nothing,
						    "%s protection and inheritance "
						    "error test, %s%s address, %s size: 0x%jx "
						    "(%ju)",
						    allocators[allocators_idx].description, address_flags[flags_idx].description,
						    (flags_idx == ANYWHERE) ? "" : address_alignments[alignments_idx].description,
						    vm_sizes[sizes_idx].description, (uintmax_t)vm_sizes[sizes_idx].size,
						    (uintmax_t)vm_sizes[sizes_idx].size);
					}
					/* mach_vm_map() cannot allocate 0 bytes, see 8003930. */
					if (allocators_idx == MACH_VM_ALLOCATE || sizes_idx != ZERO_BYTES) {
						run_suite(set_up_allocator_and_vm_variables_and_allocate, allocate_main_tests, deallocate,
						    "%s main "
						    "allocation tests, %s%s address, %s size: 0x%jx "
						    "(%ju)",
						    allocators[allocators_idx].description, address_flags[flags_idx].description,
						    (flags_idx == ANYWHERE) ? "" : address_alignments[alignments_idx].description,
						    vm_sizes[sizes_idx].description, (uintmax_t)vm_sizes[sizes_idx].size,
						    (uintmax_t)vm_sizes[sizes_idx].size);
					}
				}
			}
			run_suite(set_up_allocator_and_vm_size, allocate_address_error_tests, do_nothing,
			    "%s address "
			    "error allocation tests, %s size: 0x%jx (%ju)",
			    allocators[allocators_idx].description, vm_sizes[sizes_idx].description, (uintmax_t)vm_sizes[sizes_idx].size,
			    (uintmax_t)vm_sizes[sizes_idx].size);
		}
		run_suite(set_up_allocator, allocate_fixed_size_tests, do_nothing, "%s fixed size allocation tests",
		    allocators[allocators_idx].description);
		/* <rdar://problem/10304215> CoreOSZin 12Z30: VMUnitTest fails:
		 * error finding xnu major version number. */
		/* mach_vm_map() with a named entry triggers a panic with this test
		 *  unless under xnu-1598 or later, see 8048580. */
		/* if (allocators_idx != MACH_VM_MAP_NAMED_ENTRY
		|| xnu_version >= 1598) { */
		if (allocators_idx != MACH_VM_MAP_NAMED_ENTRY) {
			run_suite(set_up_allocator, allocate_invalid_large_size_test, do_nothing, "%s invalid large size allocation test",
			    allocators[allocators_idx].description);
		}
	}
	/* mach_vm_map() only large mask overflow tests. */
	for (sizes_idx = 0; sizes_idx < numofsizes; sizes_idx++) {
		run_suite(set_up_vm_size, mach_vm_map_large_mask_overflow_error_test, do_nothing,
		    "mach_vm_map() large mask overflow "
		    "error test, size: 0x%jx (%ju)",
		    (uintmax_t)vm_sizes[sizes_idx].size, (uintmax_t)vm_sizes[sizes_idx].size);
	}
}

void
run_deallocate_test_suites()
{
	UnitTests access_deallocated_memory_tests = {
		{"Read start of deallocated range", test_access_deallocated_range_start},
		{"Read middle of deallocated range", test_access_deallocated_range_middle},
		{"Read end of deallocated range", test_access_deallocated_range_end},
	};
	UnitTests deallocate_reallocate_tests = {
		{"Deallocate twice", test_deallocate_twice},
		{"Write pattern, deallocate, reallocate (deallocated "
		 "memory is inaccessible), and verify memory is "
		 "zero-filled",
		 test_write_pattern_deallocate_reallocate_zero_filled},
	};
	UnitTests deallocate_null_map_test = {
		{"Deallocate in NULL VM map", test_deallocate_in_null_map},
	};
	UnitTests deallocate_edge_case_tests = {
		{"Deallocate zero size ranges", test_deallocate_zero_size_ranges},
		{"Deallocate memory ranges whose end rounds to 0x0", test_deallocate_rounded_zero_end_ranges},
		{"Deallocate wrapped around memory ranges", test_deallocate_wrapped_around_ranges},
	};
	UnitTests deallocate_suicide_test = {
		{"Deallocate whole address space", test_deallocate_suicide},
	};

	/* All allocations done with mach_vm_allocate(). */
	set_allocator(wrapper_mach_vm_allocate);

	/* Run the test suites with various VM sizes, and unspecified or
	 *  fixed (page-aligned or page-unaligned), addresses. */
	for (sizes_idx = 0; sizes_idx < numofsizes; sizes_idx++) {
		for (flags_idx = 0; flags_idx < numofflags; flags_idx++) {
			for (alignments_idx = 0; alignments_idx < numofalignments; alignments_idx++) {
				/* An allocated address will be page-aligned. */
				if (flags_idx == ANYWHERE && alignments_idx == UNALIGNED) {
					continue;
				}
				/* Accessing deallocated memory should cause a segmentation
				 *  fault. */
				/* Nothing gets deallocated if size is zero. */
				if (sizes_idx != ZERO_BYTES) {
					set_expected_signal(SIGSEGV);
					run_suite(set_up_vm_variables_and_allocate, access_deallocated_memory_tests, do_nothing,
					    "Deallocated memory access tests, "
					    "%s%s address, %s size: 0x%jx (%ju)",
					    address_flags[flags_idx].description,
					    (flags_idx == ANYWHERE) ? "" : address_alignments[alignments_idx].description,
					    vm_sizes[sizes_idx].description, (uintmax_t)vm_sizes[sizes_idx].size,
					    (uintmax_t)vm_sizes[sizes_idx].size);
					set_expected_signal(0);
				}
				run_suite(set_up_vm_variables_and_allocate, deallocate_reallocate_tests, do_nothing,
				    "Deallocation and reallocation tests, %s%s "
				    "address, %s size: 0x%jx (%ju)",
				    address_flags[flags_idx].description,
				    (flags_idx == ANYWHERE) ? "" : address_alignments[alignments_idx].description,
				    vm_sizes[sizes_idx].description, (uintmax_t)vm_sizes[sizes_idx].size,
				    (uintmax_t)vm_sizes[sizes_idx].size);
				run_suite(set_up_vm_variables, deallocate_null_map_test, do_nothing,
				    "mach_vm_deallocate() null map test, "
				    "%s%s address, %s size: 0x%jx (%ju)",
				    address_flags[flags_idx].description,
				    (flags_idx == ANYWHERE) ? "" : address_alignments[alignments_idx].description,
				    vm_sizes[sizes_idx].description, (uintmax_t)vm_sizes[sizes_idx].size,
				    (uintmax_t)vm_sizes[sizes_idx].size);
			}
		}
	}
	run_suite(do_nothing, deallocate_edge_case_tests, do_nothing, "Edge case deallocation tests");

	set_expected_signal(-1);        /* SIGSEGV or SIGBUS */
	run_suite(do_nothing, deallocate_suicide_test, do_nothing, "Whole address space deallocation test");
	set_expected_signal(0);
}

void
run_read_test_suites()
{
	UnitTests read_main_tests = {
		{"Read address is nonzero iff size is nonzero", test_nonzero_address_iff_nonzero_size},
		{"Read address has the correct boundary offset", test_read_address_offset},
		{"Reallocate read pages", test_reallocate_pages},
		{"Read and verify zero-filled memory", test_zero_filled},
	};
	UnitTests read_pattern_tests = {
		{"Read address-filled pattern", test_read_address_filled},
		{"Read checkerboard pattern", test_read_checkerboard},
		{"Read reverse checkerboard pattern", test_read_reverse_checkerboard},
	};
	UnitTests read_null_map_test = {
		{"Read from NULL VM map", test_read_null_map},
	};
	UnitTests read_edge_case_tests = {
		{"Read zero size", test_read_zero_size},
		{"Read invalid large size", test_read_invalid_large_size},
		{"Read wrapped around memory ranges", test_read_wrapped_around_ranges},
	};
	UnitTests read_inaccessible_tests = {
		{"Read partially decallocated memory", test_read_partially_deallocated_range},
		{"Read partially read-protected memory", test_read_partially_unreadable_range},
	};

	/* All allocations done with mach_vm_allocate(). */
	set_allocator(wrapper_mach_vm_allocate);

	/* Run the test suites with various VM sizes, and unspecified or
	 *  fixed (page-aligned or page-unaligned) addresses. */
	for (sizes_idx = 0; sizes_idx < numofsizes; sizes_idx++) {
		for (flags_idx = 0; flags_idx < numofflags; flags_idx++) {
			for (alignments_idx = 0; alignments_idx < numofalignments; alignments_idx++) {
				/* An allocated address will be page-aligned. */
				if (flags_idx == ANYWHERE && alignments_idx == UNALIGNED) {
					continue;
				}
				run_suite(set_up_vm_variables_allocate_read_deallocate, read_main_tests, deallocate,
				    "mach_vm_read() "
				    "main tests, %s%s address, %s size: 0x%jx (%ju)",
				    address_flags[flags_idx].description,
				    (flags_idx == ANYWHERE) ? "" : address_alignments[alignments_idx].description,
				    vm_sizes[sizes_idx].description, (uintmax_t)vm_sizes[sizes_idx].size,
				    (uintmax_t)vm_sizes[sizes_idx].size);
				run_suite(set_up_vm_variables_and_allocate_extra_page, read_pattern_tests, deallocate,
				    "mach_vm_read() pattern tests, %s%s address, %s "
				    "size: 0x%jx (%ju)",
				    address_flags[flags_idx].description,
				    (flags_idx == ANYWHERE) ? "" : address_alignments[alignments_idx].description,
				    vm_sizes[sizes_idx].description, (uintmax_t)vm_sizes[sizes_idx].size,
				    (uintmax_t)vm_sizes[sizes_idx].size);
				run_suite(set_up_vm_variables_and_allocate_extra_page, read_null_map_test, deallocate_extra_page,
				    "mach_vm_read() null map test, "
				    "%s%s address, %s size: 0x%jx (%ju)",
				    address_flags[flags_idx].description,
				    (flags_idx == ANYWHERE) ? "" : address_alignments[alignments_idx].description,
				    vm_sizes[sizes_idx].description, (uintmax_t)vm_sizes[sizes_idx].size,
				    (uintmax_t)vm_sizes[sizes_idx].size);
				/* A zero size range is always accessible. */
				if (sizes_idx != ZERO_BYTES) {
					run_suite(set_up_vm_variables_and_allocate_extra_page, read_inaccessible_tests, deallocate_extra_page,
					    "mach_vm_read() inaccessibility tests, %s%s "
					    "address, %s size: 0x%jx (%ju)",
					    address_flags[flags_idx].description,
					    (flags_idx == ANYWHERE) ? "" : address_alignments[alignments_idx].description,
					    vm_sizes[sizes_idx].description, (uintmax_t)vm_sizes[sizes_idx].size,
					    (uintmax_t)vm_sizes[sizes_idx].size);
				}
			}
		}
	}
	run_suite(do_nothing, read_edge_case_tests, do_nothing, "mach_vm_read() fixed size tests");
}

void
run_write_test_suites()
{
	UnitTests write_main_tests = {
		{"Write and verify zero-filled memory", test_zero_filled_write},
	};
	UnitTests write_pattern_tests = {
		{"Write address-filled pattern", test_address_filled_write},
		{"Write checkerboard pattern", test_checkerboard_write},
		{"Write reverse checkerboard pattern", test_reverse_checkerboard_write},
	};
	UnitTests write_edge_case_tests = {
		{"Write into NULL VM map", test_write_null_map}, {"Write zero size", test_write_zero_size},
	};
	UnitTests write_inaccessible_tests = {
		{"Write partially decallocated buffer", test_write_partially_deallocated_buffer},
		{"Write partially read-protected buffer", test_write_partially_unreadable_buffer},
		{"Write on partially deallocated range", test_write_on_partially_deallocated_range},
		{"Write on partially write-protected range", test_write_on_partially_unwritable_range},
	};

	/* All allocations done with mach_vm_allocate(). */
	set_allocator(wrapper_mach_vm_allocate);

	/* Run the test suites with various destination sizes and
	 *  unspecified or fixed (page-aligned or page-unaligned)
	 *  addresses, and various buffer sizes and boundary offsets. */
	for (sizes_idx = 0; sizes_idx < numofsizes; sizes_idx++) {
		for (flags_idx = 0; flags_idx < numofflags; flags_idx++) {
			for (alignments_idx = 0; alignments_idx < numofalignments; alignments_idx++) {
				for (buffer_sizes_idx = 0; buffer_sizes_idx < numofsizes; buffer_sizes_idx++) {
					for (offsets_idx = 0; offsets_idx < numofoffsets; offsets_idx++) {
						/* An allocated address will be page-aligned. */
						if ((flags_idx == ANYWHERE && alignments_idx == UNALIGNED)) {
							continue;
						}
						run_suite(set_up_vm_and_buffer_variables_allocate_for_writing, write_edge_case_tests,
						    deallocate_vm_and_buffer,
						    "mach_vm_write() edge case tests, %s%s address, %s "
						    "size: 0x%jx (%ju), buffer %s size: 0x%jx (%ju), "
						    "buffer boundary offset: %d",
						    address_flags[flags_idx].description,
						    (flags_idx == ANYWHERE) ? "" : address_alignments[alignments_idx].description,
						    vm_sizes[sizes_idx].description, (uintmax_t)vm_sizes[sizes_idx].size,
						    (uintmax_t)vm_sizes[sizes_idx].size, vm_sizes[buffer_sizes_idx].description,
						    (uintmax_t)vm_sizes[buffer_sizes_idx].size, (uintmax_t)vm_sizes[buffer_sizes_idx].size,
						    buffer_offsets[offsets_idx].offset);
						/* A zero size buffer is always accessible. */
						if (buffer_sizes_idx != ZERO_BYTES) {
							run_suite(set_up_vm_and_buffer_variables_allocate_for_writing, write_inaccessible_tests,
							    deallocate_vm_and_buffer,
							    "mach_vm_write() inaccessibility tests, "
							    "%s%s address, %s size: 0x%jx (%ju), buffer "
							    "%s size: 0x%jx (%ju), buffer boundary "
							    "offset: %d",
							    address_flags[flags_idx].description,
							    (flags_idx == ANYWHERE) ? "" : address_alignments[alignments_idx].description,
							    vm_sizes[sizes_idx].description, (uintmax_t)vm_sizes[sizes_idx].size,
							    (uintmax_t)vm_sizes[sizes_idx].size, vm_sizes[buffer_sizes_idx].description,
							    (uintmax_t)vm_sizes[buffer_sizes_idx].size, (uintmax_t)vm_sizes[buffer_sizes_idx].size,
							    buffer_offsets[offsets_idx].offset);
						}
						/* The buffer cannot be larger than the destination. */
						if (vm_sizes[sizes_idx].size < vm_sizes[buffer_sizes_idx].size) {
							continue;
						}
						run_suite(set_up_vm_and_buffer_variables_allocate_write, write_main_tests, deallocate_vm_and_buffer,
						    "mach_vm_write() main tests, %s%s address, %s "
						    "size: 0x%jx (%ju), buffer %s size: 0x%jx (%ju), "
						    "buffer boundary offset: %d",
						    address_flags[flags_idx].description,
						    (flags_idx == ANYWHERE) ? "" : address_alignments[alignments_idx].description,
						    vm_sizes[sizes_idx].description, (uintmax_t)vm_sizes[sizes_idx].size,
						    (uintmax_t)vm_sizes[sizes_idx].size, vm_sizes[buffer_sizes_idx].description,
						    (uintmax_t)vm_sizes[buffer_sizes_idx].size, (uintmax_t)vm_sizes[buffer_sizes_idx].size,
						    buffer_offsets[offsets_idx].offset);
						run_suite(set_up_vm_and_buffer_variables_allocate_for_writing, write_pattern_tests,
						    deallocate_vm_and_buffer,
						    "mach_vm_write() pattern tests, %s%s address, %s "
						    "size: 0x%jx (%ju), buffer %s size: 0x%jx (%ju), "
						    "buffer boundary offset: %d",
						    address_flags[flags_idx].description,
						    (flags_idx == ANYWHERE) ? "" : address_alignments[alignments_idx].description,
						    vm_sizes[sizes_idx].description, (uintmax_t)vm_sizes[sizes_idx].size,
						    (uintmax_t)vm_sizes[sizes_idx].size, vm_sizes[buffer_sizes_idx].description,
						    (uintmax_t)vm_sizes[buffer_sizes_idx].size, (uintmax_t)vm_sizes[buffer_sizes_idx].size,
						    buffer_offsets[offsets_idx].offset);
					}
				}
			}
		}
	}
}

void
run_protect_test_suites()
{
	UnitTests readprotection_main_tests = {
		{"Read-protect, read-allow and verify zero-filled memory", test_zero_filled_readprotect},
		{"Verify that region is read-protected iff size is "
		 "nonzero",
		 test_verify_readprotection},
	};
	UnitTests access_readprotected_memory_tests = {
		{"Read start of read-protected range", test_access_readprotected_range_start},
		{"Read middle of read-protected range", test_access_readprotected_range_middle},
		{"Read end of read-protected range", test_access_readprotected_range_end},
	};
	UnitTests writeprotection_main_tests = {
		{"Write-protect and verify zero-filled memory", test_zero_filled_extended},
		{"Verify that region is write-protected iff size is "
		 "nonzero",
		 test_verify_writeprotection},
	};
	UnitTests write_writeprotected_memory_tests = {
		{"Write at start of write-protected range", test_write_writeprotected_range_start},
		{"Write in middle of write-protected range", test_write_writeprotected_range_middle},
		{"Write at end of write-protected range", test_write_writeprotected_range_end},
	};
	UnitTests protect_edge_case_tests = {
		{"Read-protect zero size ranges", test_readprotect_zero_size},
		{"Write-protect zero size ranges", test_writeprotect_zero_size},
		{"Read-protect wrapped around memory ranges", test_readprotect_wrapped_around_ranges},
		{"Write-protect wrapped around memory ranges", test_writeprotect_wrapped_around_ranges},
	};

	/* All allocations done with mach_vm_allocate(). */
	set_allocator(wrapper_mach_vm_allocate);

	/* Run the test suites with various VM sizes, and unspecified or
	 *  fixed (page-aligned or page-unaligned), addresses. */
	for (sizes_idx = 0; sizes_idx < numofsizes; sizes_idx++) {
		for (flags_idx = 0; flags_idx < numofflags; flags_idx++) {
			for (alignments_idx = 0; alignments_idx < numofalignments; alignments_idx++) {
				/* An allocated address will be page-aligned. */
				if (flags_idx == ANYWHERE && alignments_idx == UNALIGNED) {
					continue;
				}
				run_suite(set_up_vm_variables_allocate_readprotect, readprotection_main_tests, deallocate_extra_page,
				    "Main read-protection tests, %s%s address, %s "
				    "size: 0x%jx (%ju)",
				    address_flags[flags_idx].description,
				    (flags_idx == ANYWHERE) ? "" : address_alignments[alignments_idx].description,
				    vm_sizes[sizes_idx].description, (uintmax_t)vm_sizes[sizes_idx].size,
				    (uintmax_t)vm_sizes[sizes_idx].size);
				run_suite(set_up_vm_variables_allocate_writeprotect, writeprotection_main_tests, deallocate_extra_page,
				    "Main write-protection tests, %s%s address, %s "
				    "size: 0x%jx (%ju)",
				    address_flags[flags_idx].description,
				    (flags_idx == ANYWHERE) ? "" : address_alignments[alignments_idx].description,
				    vm_sizes[sizes_idx].description, (uintmax_t)vm_sizes[sizes_idx].size,
				    (uintmax_t)vm_sizes[sizes_idx].size);
				/* Nothing gets protected if size is zero. */
				if (sizes_idx != ZERO_BYTES) {
					set_expected_signal(SIGBUS);
					/* Accessing read-protected memory should cause a bus
					 *  error. */
					run_suite(set_up_vm_variables_allocate_readprotect, access_readprotected_memory_tests, deallocate_extra_page,
					    "Read-protected memory access tests, %s%s "
					    "address, %s size: 0x%jx (%ju)",
					    address_flags[flags_idx].description,
					    (flags_idx == ANYWHERE) ? "" : address_alignments[alignments_idx].description,
					    vm_sizes[sizes_idx].description, (uintmax_t)vm_sizes[sizes_idx].size,
					    (uintmax_t)vm_sizes[sizes_idx].size);
					/* Writing on write-protected memory should cause a bus
					 *  error. */
					run_suite(set_up_vm_variables_allocate_writeprotect, write_writeprotected_memory_tests, deallocate_extra_page,
					    "Write-protected memory writing tests, %s%s "
					    "address, %s size: 0x%jx (%ju)",
					    address_flags[flags_idx].description,
					    (flags_idx == ANYWHERE) ? "" : address_alignments[alignments_idx].description,
					    vm_sizes[sizes_idx].description, (uintmax_t)vm_sizes[sizes_idx].size,
					    (uintmax_t)vm_sizes[sizes_idx].size);
					set_expected_signal(0);
				}
			}
		}
	}
	run_suite(do_nothing, protect_edge_case_tests, do_nothing, "Edge case protection tests");
}

void
run_copy_test_suites()
{
	/* Copy tests */
	UnitTests copy_main_tests = {
		{"Copy and verify zero-filled memory", test_zero_filled_copy_dest},
	};
	UnitTests copy_pattern_tests = {
		{"Copy address-filled pattern", test_copy_address_filled},
		{"Copy checkerboard pattern", test_copy_checkerboard},
		{"Copy reverse checkerboard pattern", test_copy_reverse_checkerboard},
	};
	UnitTests copy_edge_case_tests = {
		{"Copy with NULL VM map", test_copy_null_map},
		{"Copy zero size", test_copy_zero_size},
		{"Copy invalid large size", test_copy_invalid_large_size},
		{"Read wrapped around memory ranges", test_copy_wrapped_around_ranges},
	};
	UnitTests copy_inaccessible_tests = {
		{"Copy source partially decallocated region", test_copy_source_partially_deallocated_region},
		/* XXX */
		{"Copy destination partially decallocated region", test_copy_dest_partially_deallocated_region},
		{"Copy source partially read-protected region", test_copy_source_partially_unreadable_region},
		/* XXX */
		{"Copy destination partially write-protected region", test_copy_dest_partially_unwriteable_region},
		{"Copy source on partially deallocated range", test_copy_source_on_partially_deallocated_range},
		{"Copy destination on partially deallocated range", test_copy_dest_on_partially_deallocated_range},
		{"Copy source on partially read-protected range", test_copy_source_on_partially_unreadable_range},
		{"Copy destination on partially write-protected range", test_copy_dest_on_partially_unwritable_range},
	};

	UnitTests copy_shared_mode_tests = {
		{"Copy using freshly allocated source", test_vmcopy_fresh_source},
		{"Copy using shared source", test_vmcopy_shared_source},
		{"Copy using a \'copied from\' source", test_vmcopy_copied_from_source},
		{"Copy using a \'copied to\' source", test_vmcopy_copied_to_source},
		{"Copy using a true shared source", test_vmcopy_trueshared_source},
		{"Copy using a private aliased source", test_vmcopy_private_aliased_source},
	};

	/* All allocations done with mach_vm_allocate(). */
	set_allocator(wrapper_mach_vm_allocate);

	/* All the tests are done with page size regions. */
	set_vm_size(vm_page_size);

	/* Run the test suites with various shared modes for source */
	for (vmcopy_action_idx = 0; vmcopy_action_idx < numofvmcopyactions; vmcopy_action_idx++) {
		run_suite(set_up_copy_shared_mode_variables, copy_shared_mode_tests, do_nothing, "Copy shared mode tests, %s",
		    vmcopy_actions[vmcopy_action_idx].description);
	}

	for (sizes_idx = 0; sizes_idx < numofsizes; sizes_idx++) {
		for (flags_idx = 0; flags_idx < numofflags; flags_idx++) {
			for (alignments_idx = 0; alignments_idx < numofalignments; alignments_idx++) {
				for (buffer_sizes_idx = 0; buffer_sizes_idx < numofsizes; buffer_sizes_idx++) {
					for (offsets_idx = 0; offsets_idx < numofoffsets; offsets_idx++) {
						/* An allocated address will be page-aligned. */
						if ((flags_idx == ANYWHERE && alignments_idx == UNALIGNED)) {
							continue;
						}
						run_suite(set_up_vm_and_buffer_variables_allocate_for_copying, copy_edge_case_tests,
						    deallocate_vm_and_buffer,
						    "mach_vm_copy() edge case tests, %s%s address, %s "
						    "size: 0x%jx (%ju), buffer %s size: 0x%jx (%ju), "
						    "buffer boundary offset: %d",
						    address_flags[flags_idx].description,
						    (flags_idx == ANYWHERE) ? "" : address_alignments[alignments_idx].description,
						    vm_sizes[sizes_idx].description, (uintmax_t)vm_sizes[sizes_idx].size,
						    (uintmax_t)vm_sizes[sizes_idx].size, vm_sizes[buffer_sizes_idx].description,
						    (uintmax_t)vm_sizes[buffer_sizes_idx].size, (uintmax_t)vm_sizes[buffer_sizes_idx].size,
						    buffer_offsets[offsets_idx].offset);
						/* The buffer cannot be larger than the destination. */
						if (vm_sizes[sizes_idx].size < vm_sizes[buffer_sizes_idx].size) {
							continue;
						}

						/* A zero size buffer is always accessible. */
						if (buffer_sizes_idx != ZERO_BYTES) {
							run_suite(set_up_vm_and_buffer_variables_allocate_for_copying, copy_inaccessible_tests,
							    deallocate_vm_and_buffer,
							    "mach_vm_copy() inaccessibility tests, "
							    "%s%s address, %s size: 0x%jx (%ju), buffer "
							    "%s size: 0x%jx (%ju), buffer boundary "
							    "offset: %d",
							    address_flags[flags_idx].description,
							    (flags_idx == ANYWHERE) ? "" : address_alignments[alignments_idx].description,
							    vm_sizes[sizes_idx].description, (uintmax_t)vm_sizes[sizes_idx].size,
							    (uintmax_t)vm_sizes[sizes_idx].size, vm_sizes[buffer_sizes_idx].description,
							    (uintmax_t)vm_sizes[buffer_sizes_idx].size, (uintmax_t)vm_sizes[buffer_sizes_idx].size,
							    buffer_offsets[offsets_idx].offset);
						}
						run_suite(set_up_source_and_dest_variables_allocate_copy, copy_main_tests, deallocate_vm_and_buffer,
						    "mach_vm_copy() main tests, %s%s address, %s "
						    "size: 0x%jx (%ju), destination %s size: 0x%jx (%ju), "
						    "destination boundary offset: %d",
						    address_flags[flags_idx].description,
						    (flags_idx == ANYWHERE) ? "" : address_alignments[alignments_idx].description,
						    vm_sizes[sizes_idx].description, (uintmax_t)vm_sizes[sizes_idx].size,
						    (uintmax_t)vm_sizes[sizes_idx].size, vm_sizes[buffer_sizes_idx].description,
						    (uintmax_t)vm_sizes[buffer_sizes_idx].size, (uintmax_t)vm_sizes[buffer_sizes_idx].size,
						    buffer_offsets[offsets_idx].offset);
						run_suite(set_up_source_and_dest_variables_allocate_copy, copy_pattern_tests, deallocate_vm_and_buffer,
						    "mach_vm_copy() pattern tests, %s%s address, %s "
						    "size: 0x%jx (%ju) destination %s size: 0x%jx (%ju), "
						    "destination boundary offset: %d",
						    address_flags[flags_idx].description,
						    (flags_idx == ANYWHERE) ? "" : address_alignments[alignments_idx].description,
						    vm_sizes[sizes_idx].description, (uintmax_t)vm_sizes[sizes_idx].size,
						    (uintmax_t)vm_sizes[sizes_idx].size, vm_sizes[buffer_sizes_idx].description,
						    (uintmax_t)vm_sizes[buffer_sizes_idx].size, (uintmax_t)vm_sizes[buffer_sizes_idx].size,
						    buffer_offsets[offsets_idx].offset);
					}
				}
			}
		}
	}
}

void
perform_test_with_options(test_option_t options)
{
	process_options(options);

	/* <rdar://problem/10304215> CoreOSZin 12Z30: VMUnitTest fails:
	 * error finding xnu major version number. */
	/* printf("xnu version is %s.\n\n", xnu_version_string()); */

	if (flag_run_allocate_test) {
		run_allocate_test_suites();
	}

	if (flag_run_deallocate_test) {
		run_deallocate_test_suites();
	}

	if (flag_run_read_test) {
		run_read_test_suites();
	}

	if (flag_run_write_test) {
		run_write_test_suites();
	}

	if (flag_run_protect_test) {
		run_protect_test_suites();
	}

	if (flag_run_copy_test) {
		run_copy_test_suites();
	}

	log_aggregated_results();
}

T_DECL(vm_test_allocate, "Allocate VM unit test")
{
	test_options.to_flags = VM_TEST_ALLOCATE;
	test_options.to_vmsize = 0;
	test_options.to_quietness = ERROR_ONLY_QUIETNESS;

	perform_test_with_options(test_options);
}

T_DECL(vm_test_deallocate, "Deallocate VM unit test",
    T_META_IGNORECRASHES(".*vm_allocation.*"))
{
	test_options.to_flags = VM_TEST_DEALLOCATE;
	test_options.to_vmsize = 0;
	test_options.to_quietness = ERROR_ONLY_QUIETNESS;

	perform_test_with_options(test_options);
}

T_DECL(vm_test_read, "Read VM unit test")
{
	test_options.to_flags = VM_TEST_READ;
	test_options.to_vmsize = 0;
	test_options.to_quietness = ERROR_ONLY_QUIETNESS;

	perform_test_with_options(test_options);
}

T_DECL(vm_test_write, "Write VM unit test")
{
	test_options.to_flags = VM_TEST_WRITE;
	test_options.to_vmsize = 0;
	test_options.to_quietness = ERROR_ONLY_QUIETNESS;

	perform_test_with_options(test_options);
}

T_DECL(vm_test_protect, "Protect VM unit test",
    T_META_IGNORECRASHES(".*vm_allocation.*"))
{
	test_options.to_flags = VM_TEST_PROTECT;
	test_options.to_vmsize = 0;
	test_options.to_quietness = ERROR_ONLY_QUIETNESS;

	perform_test_with_options(test_options);
}

T_DECL(vm_test_copy, "Copy VM unit test")
{
	test_options.to_flags = VM_TEST_COPY;
	test_options.to_vmsize = 0;
	test_options.to_quietness = ERROR_ONLY_QUIETNESS;

	perform_test_with_options(test_options);
}
