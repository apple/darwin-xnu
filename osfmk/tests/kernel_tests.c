/*
 * Copyright (c) 2015 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <kern/kern_types.h>
#include <kern/assert.h>
#include <kern/host.h>
#include <kern/macro_help.h>
#include <kern/sched.h>
#include <kern/locks.h>
#include <kern/sched_prim.h>
#include <kern/misc_protos.h>
#include <kern/thread_call.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <tests/ktest.h>
#include <sys/errno.h>
#include <sys/random.h>
#include <kern/kern_cdata.h>
#include <machine/lowglobals.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <kern/priority_queue.h>

#if !(DEVELOPMENT || DEBUG)
#error "Testing is not enabled on RELEASE configurations"
#endif

#include <tests/xnupost.h>

extern boolean_t get_range_bounds(char * c, int64_t * lower, int64_t * upper);
__private_extern__ void qsort(void * a, size_t n, size_t es, int (*cmp)(const void *, const void *));

uint32_t total_post_tests_count = 0;
void xnupost_reset_panic_widgets(void);

/* test declarations */
kern_return_t zalloc_test(void);
kern_return_t RandomULong_test(void);
kern_return_t kcdata_api_test(void);
kern_return_t priority_queue_test(void);

#if defined(__arm__) || defined(__arm64__)
kern_return_t pmap_coredump_test(void);
#endif

extern kern_return_t console_serial_test(void);
extern kern_return_t console_serial_alloc_rel_tests(void);
extern kern_return_t console_serial_parallel_log_tests(void);
extern kern_return_t test_os_log(void);
extern kern_return_t test_os_log_parallel(void);
extern kern_return_t bitmap_post_test(void);

#ifdef __arm64__
extern kern_return_t arm64_munger_test(void);
extern kern_return_t ex_cb_test(void);
#if __ARM_PAN_AVAILABLE__
extern kern_return_t arm64_pan_test(void);
#endif
#endif /* __arm64__ */

extern kern_return_t test_thread_call(void);


struct xnupost_panic_widget xt_panic_widgets = {NULL, NULL, NULL, NULL};

struct xnupost_test kernel_post_tests[] = {XNUPOST_TEST_CONFIG_BASIC(zalloc_test),
                                           XNUPOST_TEST_CONFIG_BASIC(RandomULong_test),
                                           XNUPOST_TEST_CONFIG_BASIC(test_os_log),
                                           XNUPOST_TEST_CONFIG_BASIC(test_os_log_parallel),
#ifdef __arm64__
                                           XNUPOST_TEST_CONFIG_BASIC(arm64_munger_test),
                                           XNUPOST_TEST_CONFIG_BASIC(ex_cb_test),
#if __ARM_PAN_AVAILABLE__
                                           XNUPOST_TEST_CONFIG_BASIC(arm64_pan_test),
#endif
#endif /* __arm64__ */
                                           XNUPOST_TEST_CONFIG_BASIC(kcdata_api_test),
                                           XNUPOST_TEST_CONFIG_BASIC(console_serial_test),
                                           XNUPOST_TEST_CONFIG_BASIC(console_serial_alloc_rel_tests),
                                           XNUPOST_TEST_CONFIG_BASIC(console_serial_parallel_log_tests),
#if defined(__arm__) || defined(__arm64__)
                                           XNUPOST_TEST_CONFIG_BASIC(pmap_coredump_test),
#endif
                                           XNUPOST_TEST_CONFIG_BASIC(bitmap_post_test),
                                         //XNUPOST_TEST_CONFIG_TEST_PANIC(kcdata_api_assert_tests)
                                           XNUPOST_TEST_CONFIG_BASIC(test_thread_call),
                                           XNUPOST_TEST_CONFIG_BASIC(priority_queue_test),
};

uint32_t kernel_post_tests_count = sizeof(kernel_post_tests) / sizeof(xnupost_test_data_t);

#define POSTARGS_RUN_TESTS 0x1
#define POSTARGS_CONTROLLER_AVAILABLE 0x2
#define POSTARGS_CUSTOM_TEST_RUNLIST 0x4
uint64_t kernel_post_args = 0x0;

/* static variables to hold state */
static kern_return_t parse_config_retval = KERN_INVALID_CAPABILITY;
static char kernel_post_test_configs[256];
boolean_t xnupost_should_run_test(uint32_t test_num);

kern_return_t
xnupost_parse_config()
{
	if (parse_config_retval != KERN_INVALID_CAPABILITY)
		return parse_config_retval;
	PE_parse_boot_argn("kernPOST", &kernel_post_args, sizeof(kernel_post_args));

	if (PE_parse_boot_argn("kernPOST_config", &kernel_post_test_configs[0], sizeof(kernel_post_test_configs)) == TRUE) {
		kernel_post_args |= POSTARGS_CUSTOM_TEST_RUNLIST;
	}

	if (kernel_post_args != 0) {
		parse_config_retval = KERN_SUCCESS;
		goto out;
	}
	parse_config_retval = KERN_NOT_SUPPORTED;
out:
	return parse_config_retval;
}

boolean_t
xnupost_should_run_test(uint32_t test_num)
{
	if (kernel_post_args & POSTARGS_CUSTOM_TEST_RUNLIST) {
		int64_t begin = 0, end = 999999;
		char * b = kernel_post_test_configs;
		while (*b) {
			get_range_bounds(b, &begin, &end);
			if (test_num >= begin && test_num <= end) {
				return TRUE;
			}

			/* skip to the next "," */
			while (*b != ',') {
				if (*b == '\0')
					return FALSE;
				b++;
			}
			/* skip past the ',' */
			b++;
		}
		return FALSE;
	}
	return TRUE;
}

kern_return_t
xnupost_list_tests(xnupost_test_t test_list, uint32_t test_count)
{
	if (KERN_SUCCESS != xnupost_parse_config())
		return KERN_FAILURE;

	xnupost_test_t testp;
	for (uint32_t i = 0; i < test_count; i++) {
		testp = &test_list[i];
		if (testp->xt_test_num == 0) {
			testp->xt_test_num = ++total_post_tests_count;
		}
		/* make sure the boot-arg based test run list is honored */
		if (kernel_post_args & POSTARGS_CUSTOM_TEST_RUNLIST) {
			testp->xt_config |= XT_CONFIG_IGNORE;
			if (xnupost_should_run_test(testp->xt_test_num)) {
				testp->xt_config &= ~(XT_CONFIG_IGNORE);
				testp->xt_config |= XT_CONFIG_RUN;
				printf("\n[TEST] #%u is marked as ignored", testp->xt_test_num);
			}
		}
		printf("\n[TEST] TOC#%u name: %s expected: %d config: %x\n", testp->xt_test_num, testp->xt_name, testp->xt_expected_retval,
		       testp->xt_config);
	}

	return KERN_SUCCESS;
}

kern_return_t
xnupost_run_tests(xnupost_test_t test_list, uint32_t test_count)
{
	uint32_t i = 0;
	int retval = KERN_SUCCESS;

	if ((kernel_post_args & POSTARGS_RUN_TESTS) == 0) {
		printf("No POST boot-arg set.\n");
		return retval;
	}

	T_START;
	xnupost_test_t testp;
	for (; i < test_count; i++) {
		xnupost_reset_panic_widgets();
		testp = &test_list[i];
		T_BEGIN(testp->xt_name);
		testp->xt_begin_time = mach_absolute_time();
		testp->xt_end_time   = testp->xt_begin_time;

		/*
		 * If test is designed to panic and controller
		 * is not available then mark as SKIPPED
		 */
		if ((testp->xt_config & XT_CONFIG_EXPECT_PANIC) && !(kernel_post_args & POSTARGS_CONTROLLER_AVAILABLE)) {
			T_SKIP(
			    "Test expects panic but "
			    "no controller is present");
			testp->xt_test_actions = XT_ACTION_SKIPPED;
			continue;
		}

		if ((testp->xt_config & XT_CONFIG_IGNORE)) {
			T_SKIP("Test is marked as XT_CONFIG_IGNORE");
			testp->xt_test_actions = XT_ACTION_SKIPPED;
			continue;
		}

		testp->xt_func();
		T_END;
		testp->xt_retval = T_TESTRESULT;
		testp->xt_end_time = mach_absolute_time();
		if (testp->xt_retval == testp->xt_expected_retval) {
			testp->xt_test_actions = XT_ACTION_PASSED;
		} else {
			testp->xt_test_actions = XT_ACTION_FAILED;
		}
	}
	T_FINISH;
	return retval;
}

kern_return_t
kernel_list_tests()
{
	return xnupost_list_tests(kernel_post_tests, kernel_post_tests_count);
}

kern_return_t
kernel_do_post()
{
	return xnupost_run_tests(kernel_post_tests, kernel_post_tests_count);
}

kern_return_t
xnupost_register_panic_widget(xt_panic_widget_func funcp, const char * funcname, void * context, void ** outval)
{
	if (xt_panic_widgets.xtp_context_p != NULL || xt_panic_widgets.xtp_func != NULL)
		return KERN_RESOURCE_SHORTAGE;

	xt_panic_widgets.xtp_context_p = context;
	xt_panic_widgets.xtp_func      = funcp;
	xt_panic_widgets.xtp_func_name = funcname;
	xt_panic_widgets.xtp_outval_p  = outval;

	return KERN_SUCCESS;
}

void
xnupost_reset_panic_widgets()
{
	bzero(&xt_panic_widgets, sizeof(xt_panic_widgets));
}

kern_return_t
xnupost_process_kdb_stop(const char * panic_s)
{
	xt_panic_return_t retval         = 0;
	struct xnupost_panic_widget * pw = &xt_panic_widgets;
	const char * name = "unknown";
	if (xt_panic_widgets.xtp_func_name) {
		name = xt_panic_widgets.xtp_func_name;
	}

	/* bail early on if kernPOST is not set */
	if (kernel_post_args == 0) {
		return KERN_INVALID_CAPABILITY;
	}

	if (xt_panic_widgets.xtp_func) {
		T_LOG("%s: Calling out to widget: %s", __func__, xt_panic_widgets.xtp_func_name);
		retval = pw->xtp_func(panic_s, pw->xtp_context_p, pw->xtp_outval_p);
	} else {
		return KERN_INVALID_CAPABILITY;
	}

	switch (retval) {
	case XT_RET_W_SUCCESS:
		T_EXPECT_EQ_INT(retval, XT_RET_W_SUCCESS, "%s reported successful handling. Returning from kdb_stop.", name);
		/* KERN_SUCCESS means return from panic/assertion */
		return KERN_SUCCESS;

	case XT_RET_W_FAIL:
		T_FAIL("%s reported XT_RET_W_FAIL: Returning from kdb_stop", name);
		return KERN_SUCCESS;

	case XT_PANIC_W_FAIL:
		T_FAIL("%s reported XT_PANIC_W_FAIL: Continuing to kdb_stop", name);
		return KERN_FAILURE;

	case XT_PANIC_W_SUCCESS:
		T_EXPECT_EQ_INT(retval, XT_PANIC_W_SUCCESS, "%s reported successful testcase. But continuing to kdb_stop.", name);
		return KERN_FAILURE;

	case XT_PANIC_UNRELATED:
	default:
		T_LOG("UNRELATED: Continuing to kdb_stop.");
		return KERN_FAILURE;
	}
}

xt_panic_return_t
_xt_generic_assert_check(const char * s, void * str_to_match, void ** outval)
{
	xt_panic_return_t ret = XT_PANIC_UNRELATED;

	if (NULL != strnstr(__DECONST(char *, s), (char *)str_to_match, strlen(s))) {
		T_LOG("%s: kdb_stop string: '%s' MATCHED string: '%s'", __func__, s, (char *)str_to_match);
		ret = XT_RET_W_SUCCESS;
	}

	if (outval)
		*outval = (void *)(uintptr_t)ret;
	return ret;
}

kern_return_t
xnupost_reset_tests(xnupost_test_t test_list, uint32_t test_count)
{
	uint32_t i = 0;
	xnupost_test_t testp;
	for (; i < test_count; i++) {
		testp                  = &test_list[i];
		testp->xt_begin_time   = 0;
		testp->xt_end_time     = 0;
		testp->xt_test_actions = XT_ACTION_NONE;
		testp->xt_retval       = -1;
	}
	return KERN_SUCCESS;
}


kern_return_t
zalloc_test()
{
	zone_t test_zone;
	void * test_ptr;

	T_SETUPBEGIN;
	test_zone = zinit(sizeof(uint64_t), 100 * sizeof(uint64_t), sizeof(uint64_t), "test_uint64_zone");
	T_ASSERT_NOTNULL(test_zone, NULL);

	T_ASSERT_EQ_INT(zone_free_count(test_zone), 0, NULL);
	T_SETUPEND;

	T_ASSERT_NOTNULL(test_ptr = zalloc(test_zone), NULL);

	zfree(test_zone, test_ptr);

	/* A sample report for perfdata */
	T_PERF("num_threads_at_ktest", threads_count, "count", "# of threads in system at zalloc_test");

	return KERN_SUCCESS;
}

/*
 * Function used for comparison by qsort()
 */
static int
compare_numbers_ascending(const void * a, const void * b)
{
	const uint64_t x = *(const uint64_t *)a;
	const uint64_t y = *(const uint64_t *)b;
	if (x < y) {
		return -1;
	} else if (x > y) {
		return 1;
	} else {
		return 0;
	}
}

/*
 * Function used for comparison by qsort()
 */
static int
compare_numbers_descending(const void * a, const void * b)
{
	const uint32_t x = *(const uint32_t *)a;
	const uint32_t y = *(const uint32_t *)b;
	if (x > y) {
		return -1;
	} else if (x < y) {
		return 1;
	} else {
		return 0;
	}
}

/* Node structure for the priority queue tests */
struct priority_queue_test_node {
	struct priority_queue_entry	link;
	priority_queue_key_t		node_key;
};

static void
priority_queue_test_queue(struct priority_queue *pq, int type,
		priority_queue_compare_fn_t cmp_fn)
{
	/* Configuration for the test */
#define PRIORITY_QUEUE_NODES	7
	static uint32_t priority_list[] = { 20, 3, 7, 6, 50, 2, 8};
	uint32_t increase_pri = 100;
	uint32_t decrease_pri = 90;
	struct priority_queue_test_node *result;
	uint32_t key = 0;
	boolean_t update_result = false;

	struct priority_queue_test_node *node = NULL;
	/* Add all priorities to the first priority queue */
	for (int i = 0; i < PRIORITY_QUEUE_NODES; i++) {
		node = kalloc(sizeof(struct priority_queue_test_node));
		T_ASSERT_NOTNULL(node, NULL);

		priority_queue_entry_init(&(node->link));
		node->node_key = priority_list[i];
		key = (type == PRIORITY_QUEUE_GENERIC_KEY) ? PRIORITY_QUEUE_KEY_NONE : priority_list[i];
		priority_queue_insert(pq, &(node->link), key, cmp_fn);
	}

	T_ASSERT_NOTNULL(node, NULL);
	key = (type == PRIORITY_QUEUE_GENERIC_KEY) ? node->node_key : priority_queue_entry_key(pq, &(node->link));
	T_ASSERT((key == node->node_key), "verify node stored key correctly");

	/* Test the priority increase operation by updating the last node added (8) */
	T_ASSERT_NOTNULL(node, NULL);
	node->node_key = increase_pri;
	key = (type == PRIORITY_QUEUE_GENERIC_KEY) ? PRIORITY_QUEUE_KEY_NONE : node->node_key;
	update_result = priority_queue_entry_increase(pq, &node->link, key, cmp_fn);
	T_ASSERT((update_result == true), "increase key updated root");
	result = priority_queue_max(pq, struct priority_queue_test_node, link);
	T_ASSERT((result->node_key == increase_pri), "verify priority_queue_entry_increase() operation");


	/* Test the priority decrease operation by updating the last node added */
	T_ASSERT((result == node), NULL);
	node->node_key = decrease_pri;
	key = (type == PRIORITY_QUEUE_GENERIC_KEY) ? PRIORITY_QUEUE_KEY_NONE : node->node_key;
	update_result = priority_queue_entry_decrease(pq, &node->link, key, cmp_fn);
	T_ASSERT((update_result == true), "decrease key updated root");
	result = priority_queue_max(pq, struct priority_queue_test_node, link);
	T_ASSERT((result->node_key == decrease_pri), "verify priority_queue_entry_decrease() operation");

	/* Update our local priority list as well */
	priority_list[PRIORITY_QUEUE_NODES - 1] = decrease_pri;

	/* Sort the local list in descending order */
	qsort(priority_list, PRIORITY_QUEUE_NODES, sizeof(priority_list[0]), compare_numbers_descending);

	/* Test the maximum operation by comparing max node with local list */
	result = priority_queue_max(pq, struct priority_queue_test_node, link);
	T_ASSERT((result->node_key == priority_list[0]), "(heap (%u) == qsort (%u)) priority queue max node lookup", 
		(uint32_t)result->node_key, priority_list[0]);

	/* Remove all remaining elements and verify they match local list */
	for (int i = 0; i < PRIORITY_QUEUE_NODES; i++) {
		result = priority_queue_remove_max(pq, struct priority_queue_test_node, link, cmp_fn);
		T_ASSERT((result->node_key == priority_list[i]), "(heap (%u) == qsort (%u)) priority queue max node removal", 
			(uint32_t)result->node_key, priority_list[i]);
	}

	priority_queue_destroy(pq, struct priority_queue_test_node, link, ^(void *n) {
		kfree(n, sizeof(struct priority_queue_test_node));
	});
}

kern_return_t
priority_queue_test(void)
{
	/*
	 * Initialize two priority queues
	 * - One which uses the key comparator
	 * - Other which uses the node comparator
	 */
	static struct priority_queue pq;
	static struct priority_queue pq_nodes;

	T_SETUPBEGIN;

	priority_queue_init(&pq, PRIORITY_QUEUE_BUILTIN_KEY | PRIORITY_QUEUE_MAX_HEAP);
	priority_queue_init(&pq_nodes, PRIORITY_QUEUE_GENERIC_KEY | PRIORITY_QUEUE_MAX_HEAP);

	T_SETUPEND;

	priority_queue_test_queue(&pq, PRIORITY_QUEUE_BUILTIN_KEY,
			PRIORITY_QUEUE_SCHED_PRI_MAX_HEAP_COMPARE);

	priority_queue_test_queue(&pq_nodes, PRIORITY_QUEUE_GENERIC_KEY,
			priority_heap_make_comparator(a, b, struct priority_queue_test_node, link, {
				return (a->node_key > b->node_key) ? 1 : ((a->node_key == b->node_key) ? 0 : -1);
			}));

	return KERN_SUCCESS;
}

/*
 * Function to count number of bits that are set in a number.
 * It uses Side Addition using Magic Binary Numbers
 */
static int
count_bits(uint64_t number)
{
	return __builtin_popcountll(number);
}

kern_return_t
RandomULong_test()
{
/*
 * Randomness test for RandomULong()
 *
 * This test verifies that:
 *  a. RandomULong works
 *  b. The generated numbers match the following entropy criteria:
 *     For a thousand iterations, verify:
 *          1. mean entropy > 12 bits
 *          2. min entropy > 4 bits
 *          3. No Duplicate
 *          4. No incremental/decremental pattern in a window of 3
 *          5. No Zero
 *          6. No -1
 *
 * <rdar://problem/22526137> Add test to increase code coverage for /dev/random
 */

#define CONF_MIN_ENTROPY 4
#define CONF_MEAN_ENTROPY 12
#define CONF_ITERATIONS 1000
#define CONF_WINDOW_SIZE 3
#define CONF_WINDOW_TREND_LIMIT ((CONF_WINDOW_SIZE / 2) + (CONF_WINDOW_SIZE & 1)) >> 0

	int i;
	uint32_t min_bit_entropy, max_bit_entropy, bit_entropy;
	uint32_t aggregate_bit_entropy = 0;
	uint32_t mean_bit_entropy      = 0;
	uint64_t numbers[CONF_ITERATIONS];
	min_bit_entropy = UINT32_MAX;
	max_bit_entropy = 0;

	/*
	 * TEST 1: Number generation and basic and basic validation
	 * Check for non-zero (no bits set), -1 (all bits set) and error
	 */
	for (i = 0; i < CONF_ITERATIONS; i++) {
		read_random(&numbers[i], sizeof(numbers[i]));
		if (numbers[i] == 0) {
			T_ASSERT_NE_ULLONG(numbers[i], 0, "read_random returned zero value.");
		}
		if (numbers[i] == UINT64_MAX) {
			T_ASSERT_NE_ULLONG(numbers[i], UINT64_MAX, "read_random returned -1.");
		}
	}
	T_PASS("Generated %d non-zero random numbers with atleast one bit reset.", CONF_ITERATIONS);

	/*
	 * TEST 2: Mean and Min Bit Entropy
	 * Check the bit entropy and its mean over the generated numbers.
	 */
	for (i = 1; i < CONF_ITERATIONS; i++) {
		bit_entropy = count_bits(numbers[i - 1] ^ numbers[i]);
		if (bit_entropy < min_bit_entropy)
			min_bit_entropy = bit_entropy;
		if (bit_entropy > max_bit_entropy)
			max_bit_entropy = bit_entropy;

		if (bit_entropy < CONF_MIN_ENTROPY) {
			T_EXPECT_GE_UINT(bit_entropy, CONF_MIN_ENTROPY,
			                 "Number of differing bits in consecutive numbers does not satisfy the min criteria.");
		}

		aggregate_bit_entropy += bit_entropy;
	}
	T_PASS("Passed the min bit entropy expectation of %d bits", CONF_MIN_ENTROPY);

	mean_bit_entropy = aggregate_bit_entropy / CONF_ITERATIONS;
	T_EXPECT_GE_UINT(mean_bit_entropy, CONF_MEAN_ENTROPY, "Test criteria for mean number of differing bits.");
	T_PASS("Mean bit entropy criteria satisfied (Required %d, Actual: %d).", CONF_MEAN_ENTROPY, mean_bit_entropy);
	T_LOG("{PERFORMANCE} iterations: %d, min_bit_entropy: %d, mean_bit_entropy: %d, max_bit_entropy: %d", CONF_ITERATIONS,
	      min_bit_entropy, mean_bit_entropy, max_bit_entropy);
	T_PERF("min_bit_entropy_" T_TOSTRING(CONF_ITERATIONS), min_bit_entropy, "bits", "minimum bit entropy in RNG. High is better");
	T_PERF("mean_bit_entropy_" T_TOSTRING(CONF_ITERATIONS), mean_bit_entropy, "bits", "mean bit entropy in RNG. High is better");
	T_PERF("max_bit_entropy_" T_TOSTRING(CONF_ITERATIONS), max_bit_entropy, "bits", "max bit entropy in RNG. High is better");

	/*
	 * TEST 3: Incremental Pattern Search
	 * Check that incremental/decremental pattern does not exist in the given window
	 */
	int window_start, window_end, trend;
	window_start = window_end = trend = 0;

	do {
		/*
		 * Set the window
		 */
		window_end = window_start + CONF_WINDOW_SIZE - 1;
		if (window_end >= CONF_ITERATIONS)
			window_end = CONF_ITERATIONS - 1;

		trend = 0;
		for (i = window_start; i < window_end; i++) {
			if (numbers[i] < numbers[i + 1])
				trend++;
			else if (numbers[i] > numbers[i + 1])
				trend--;
		}
		/*
		 * Check that there is no increasing or decreasing trend
		 * i.e. trend <= ceil(window_size/2)
		 */
		if (trend < 0) {
			trend = -trend;
		}
		if (trend > CONF_WINDOW_TREND_LIMIT) {
			T_ASSERT_LE_INT(trend, CONF_WINDOW_TREND_LIMIT, "Found increasing/decreasing trend in random numbers.");
		}

		/*
		 * Move to the next window
		 */
		window_start++;

	} while (window_start < (CONF_ITERATIONS - 1));
	T_PASS("Did not find increasing/decreasing trends in a window of %d numbers.", CONF_WINDOW_SIZE);

	/*
	 * TEST 4: Find Duplicates
	 * Check no duplicate values are generated
	 */
	qsort(numbers, CONF_ITERATIONS, sizeof(numbers[0]), compare_numbers_ascending);
	for (i = 1; i < CONF_ITERATIONS; i++) {
		if (numbers[i] == numbers[i - 1]) {
			T_ASSERT_NE_ULLONG(numbers[i], numbers[i - 1], "read_random generated duplicate values.");
		}
	}
	T_PASS("Test did not find any duplicates as expected.");

	return KERN_SUCCESS;
}


/* KCDATA kernel api tests */
static struct kcdata_descriptor test_kc_data;//, test_kc_data2;
struct sample_disk_io_stats {
	uint64_t disk_reads_count;
	uint64_t disk_reads_size;
	uint64_t io_priority_count[4];
	uint64_t io_priority_size;
} __attribute__((packed));

struct kcdata_subtype_descriptor test_disk_io_stats_def[] = {
    {KCS_SUBTYPE_FLAGS_NONE, KC_ST_UINT64, 0 * sizeof(uint64_t), sizeof(uint64_t), "disk_reads_count"},
    {KCS_SUBTYPE_FLAGS_NONE, KC_ST_UINT64, 1 * sizeof(uint64_t), sizeof(uint64_t), "disk_reads_size"},
    {KCS_SUBTYPE_FLAGS_ARRAY, KC_ST_UINT64, 2 * sizeof(uint64_t), KCS_SUBTYPE_PACK_SIZE(4, sizeof(uint64_t)), "io_priority_count"},
    {KCS_SUBTYPE_FLAGS_ARRAY, KC_ST_UINT64, (2 + 4) * sizeof(uint64_t), sizeof(uint64_t), "io_priority_size"},
};

kern_return_t
kcdata_api_test()
{
	kern_return_t retval = KERN_SUCCESS;

	/* test for NULL input */
	retval = kcdata_memory_static_init(NULL, (mach_vm_address_t)0, KCDATA_BUFFER_BEGIN_STACKSHOT, 100, KCFLAG_USE_MEMCOPY);
	T_ASSERT(retval == KERN_INVALID_ARGUMENT, "kcdata_memory_static_init with NULL struct");

	/* another negative test with buffer size < 32 bytes */
	char data[30] = "sample_disk_io_stats";
	retval = kcdata_memory_static_init(&test_kc_data, (mach_vm_address_t)&data, KCDATA_BUFFER_BEGIN_CRASHINFO, sizeof(data),
	                                   KCFLAG_USE_MEMCOPY);
	T_ASSERT(retval == KERN_RESOURCE_SHORTAGE, "init with 30 bytes failed as expected with KERN_RESOURCE_SHORTAGE");

	/* test with COPYOUT for 0x0 address. Should return KERN_NO_ACCESS */
	retval = kcdata_memory_static_init(&test_kc_data, (mach_vm_address_t)0, KCDATA_BUFFER_BEGIN_CRASHINFO, PAGE_SIZE,
	                                   KCFLAG_USE_COPYOUT);
	T_ASSERT(retval == KERN_NO_ACCESS, "writing to 0x0 returned KERN_NO_ACCESS");

	/* test with successful kcdata_memory_static_init */
	test_kc_data.kcd_length   = 0xdeadbeef;
	mach_vm_address_t address = (mach_vm_address_t)kalloc(PAGE_SIZE);
	T_EXPECT_NOTNULL(address, "kalloc of PAGE_SIZE data.");

	retval = kcdata_memory_static_init(&test_kc_data, (mach_vm_address_t)address, KCDATA_BUFFER_BEGIN_STACKSHOT, PAGE_SIZE,
	                                   KCFLAG_USE_MEMCOPY);

	T_ASSERT(retval == KERN_SUCCESS, "successful kcdata_memory_static_init call");

	T_ASSERT(test_kc_data.kcd_length == PAGE_SIZE, "kcdata length is set correctly to PAGE_SIZE.");
	T_LOG("addr_begin 0x%llx and end 0x%llx and address 0x%llx", test_kc_data.kcd_addr_begin, test_kc_data.kcd_addr_end, address);
	T_ASSERT(test_kc_data.kcd_addr_begin == address, "kcdata begin address is correct 0x%llx", (uint64_t)address);

	/* verify we have BEGIN and END HEADERS set */
	uint32_t * mem = (uint32_t *)address;
	T_ASSERT(mem[0] == KCDATA_BUFFER_BEGIN_STACKSHOT, "buffer does contain KCDATA_BUFFER_BEGIN_STACKSHOT");
	T_ASSERT(mem[4] == KCDATA_TYPE_BUFFER_END, "KCDATA_TYPE_BUFFER_END is appended as expected");
	T_ASSERT(mem[5] == 0, "size of BUFFER_END tag is zero");

	/* verify kcdata_memory_get_used_bytes() */
	uint64_t bytes_used = 0;
	bytes_used = kcdata_memory_get_used_bytes(&test_kc_data);
	T_ASSERT(bytes_used == (2 * sizeof(struct kcdata_item)), "bytes_used api returned expected %llu", bytes_used);

	/* test for kcdata_get_memory_addr() */

	mach_vm_address_t user_addr = 0;
	/* negative test for NULL user_addr AND/OR kcdata_descriptor */
	retval = kcdata_get_memory_addr(NULL, KCDATA_TYPE_MACH_ABSOLUTE_TIME, sizeof(uint64_t), &user_addr);
	T_ASSERT(retval == KERN_INVALID_ARGUMENT, "kcdata_get_memory_addr with NULL struct -> KERN_INVALID_ARGUMENT");

	retval = kcdata_get_memory_addr(&test_kc_data, KCDATA_TYPE_MACH_ABSOLUTE_TIME, sizeof(uint64_t), NULL);
	T_ASSERT(retval == KERN_INVALID_ARGUMENT, "kcdata_get_memory_addr with NULL user_addr -> KERN_INVALID_ARGUMENT");

	/* successful case with size 0. Yes this is expected to succeed as just a item type could be used as boolean */
	retval = kcdata_get_memory_addr(&test_kc_data, KCDATA_TYPE_USECS_SINCE_EPOCH, 0, &user_addr);
	T_ASSERT(retval == KERN_SUCCESS, "Successfully got kcdata entry for 0 size data");
	T_ASSERT(user_addr == test_kc_data.kcd_addr_end, "0 sized data did not add any extra buffer space");

	/* successful case with valid size. */
	user_addr = 0xdeadbeef;
	retval = kcdata_get_memory_addr(&test_kc_data, KCDATA_TYPE_MACH_ABSOLUTE_TIME, sizeof(uint64_t), &user_addr);
	T_ASSERT(retval == KERN_SUCCESS, "kcdata_get_memory_addr with valid values succeeded.");
	T_ASSERT(user_addr > test_kc_data.kcd_addr_begin, "user_addr is in range of buffer");
	T_ASSERT(user_addr < test_kc_data.kcd_addr_end, "user_addr is in range of buffer");

	/* Try creating an item with really large size */
	user_addr  = 0xdeadbeef;
	bytes_used = kcdata_memory_get_used_bytes(&test_kc_data);
	retval = kcdata_get_memory_addr(&test_kc_data, KCDATA_TYPE_MACH_ABSOLUTE_TIME, PAGE_SIZE * 4, &user_addr);
	T_ASSERT(retval == KERN_RESOURCE_SHORTAGE, "Allocating entry with size > buffer -> KERN_RESOURCE_SHORTAGE");
	T_ASSERT(user_addr == 0xdeadbeef, "user_addr remained unaffected with failed kcdata_get_memory_addr");
	T_ASSERT(bytes_used == kcdata_memory_get_used_bytes(&test_kc_data), "The data structure should be unaffected");

	/* verify convenience functions for uint32_with_description */
	retval = kcdata_add_uint32_with_description(&test_kc_data, 0xbdc0ffee, "This is bad coffee");
	T_ASSERT(retval == KERN_SUCCESS, "add uint32 with description succeeded.");

	retval = kcdata_add_uint64_with_description(&test_kc_data, 0xf001badc0ffee, "another 8 byte no.");
	T_ASSERT(retval == KERN_SUCCESS, "add uint64 with desc succeeded.");

	/* verify creating an KCDATA_TYPE_ARRAY here */
	user_addr  = 0xdeadbeef;
	bytes_used = kcdata_memory_get_used_bytes(&test_kc_data);
	/* save memory address where the array will come up */
	struct kcdata_item * item_p = (struct kcdata_item *)test_kc_data.kcd_addr_end;

	retval = kcdata_get_memory_addr_for_array(&test_kc_data, KCDATA_TYPE_MACH_ABSOLUTE_TIME, sizeof(uint64_t), 20, &user_addr);
	T_ASSERT(retval == KERN_SUCCESS, "Array of 20 integers should be possible");
	T_ASSERT(user_addr != 0xdeadbeef, "user_addr is updated as expected");
	T_ASSERT((kcdata_memory_get_used_bytes(&test_kc_data) - bytes_used) >= 20 * sizeof(uint64_t), "memory allocation is in range");
	kcdata_iter_t iter = kcdata_iter(item_p, PAGE_SIZE - kcdata_memory_get_used_bytes(&test_kc_data));
	T_ASSERT(kcdata_iter_array_elem_count(iter) == 20, "array count is 20");

	/* FIXME add tests here for ranges of sizes and counts */

	T_ASSERT(item_p->flags == (((uint64_t)KCDATA_TYPE_MACH_ABSOLUTE_TIME << 32) | 20), "flags are set correctly");

	/* test adding of custom type */

	retval = kcdata_add_type_definition(&test_kc_data, 0x999, data, &test_disk_io_stats_def[0],
	                                    sizeof(test_disk_io_stats_def) / sizeof(struct kcdata_subtype_descriptor));
	T_ASSERT(retval == KERN_SUCCESS, "adding custom type succeeded.");

	return KERN_SUCCESS;
}

/*
kern_return_t
kcdata_api_assert_tests()
{
	kern_return_t retval       = 0;
	void * assert_check_retval = NULL;
	test_kc_data2.kcd_length   = 0xdeadbeef;
	mach_vm_address_t address = (mach_vm_address_t)kalloc(PAGE_SIZE);
	T_EXPECT_NOTNULL(address, "kalloc of PAGE_SIZE data.");

	retval = kcdata_memory_static_init(&test_kc_data2, (mach_vm_address_t)address, KCDATA_BUFFER_BEGIN_STACKSHOT, PAGE_SIZE,
	                                   KCFLAG_USE_MEMCOPY);

	T_ASSERT(retval == KERN_SUCCESS, "successful kcdata_memory_static_init call");

	retval = T_REGISTER_ASSERT_CHECK("KCDATA_DESC_MAXLEN", &assert_check_retval);
	T_ASSERT(retval == KERN_SUCCESS, "registered assert widget");

	// this will assert
	retval = kcdata_add_uint32_with_description(&test_kc_data2, 0xc0ffee, "really long description string for kcdata");
	T_ASSERT(retval == KERN_INVALID_ARGUMENT, "API param check returned KERN_INVALID_ARGUMENT correctly");
	T_ASSERT(assert_check_retval == (void *)XT_RET_W_SUCCESS, "assertion handler verified that it was hit");

	return KERN_SUCCESS;
}
*/

#if defined(__arm__) || defined(__arm64__)

#include <arm/pmap.h>

#define MAX_PMAP_OBJECT_ELEMENT 100000

extern struct vm_object pmap_object_store; /* store pt pages */
extern unsigned long gPhysBase, gPhysSize, first_avail;

/*
 * Define macros to transverse the pmap object structures and extract
 * physical page number with information from low global only
 * This emulate how Astris extracts information from coredump
 */
#if defined(__arm64__)

static inline uintptr_t
astris_vm_page_unpack_ptr(uintptr_t p)
{
	if (!p)
		return ((uintptr_t)0);

	return (p & lowGlo.lgPmapMemFromArrayMask)
	           ? lowGlo.lgPmapMemStartAddr + (p & ~(lowGlo.lgPmapMemFromArrayMask)) * lowGlo.lgPmapMemPagesize
	           : lowGlo.lgPmapMemPackedBaseAddr + (p << lowGlo.lgPmapMemPackedShift);
}

// assume next pointer is the first element
#define astris_vm_page_queue_next(qc) (astris_vm_page_unpack_ptr(*((uint32_t *)(qc))))

#endif

#if defined(__arm__)

// assume next pointer is the first element
#define astris_vm_page_queue_next(qc) *((uintptr_t *)(qc))

#endif

#define astris_vm_page_queue_first(q) astris_vm_page_queue_next(q)

#define astris_vm_page_queue_end(q, qe) ((q) == (qe))

#define astris_vm_page_queue_iterate(head, elt)                                                           \
	for ((elt) = (uintptr_t)astris_vm_page_queue_first((head)); !astris_vm_page_queue_end((head), (elt)); \
	     (elt) = (uintptr_t)astris_vm_page_queue_next(((elt) + (uintptr_t)lowGlo.lgPmapMemChainOffset)))

#define astris_ptoa(x) ((vm_address_t)(x) << lowGlo.lgPageShift)

static inline ppnum_t
astris_vm_page_get_phys_page(uintptr_t m)
{
	return (m >= lowGlo.lgPmapMemStartAddr && m < lowGlo.lgPmapMemEndAddr)
	           ? (ppnum_t)((m - lowGlo.lgPmapMemStartAddr) / lowGlo.lgPmapMemPagesize + lowGlo.lgPmapMemFirstppnum)
	           : *((ppnum_t *)(m + lowGlo.lgPmapMemPageOffset));
}

kern_return_t
pmap_coredump_test(void)
{
	int iter = 0;
	uintptr_t p;

	T_LOG("Testing coredump info for PMAP.");

	T_ASSERT_GE_ULONG(lowGlo.lgStaticAddr, gPhysBase, NULL);
	T_ASSERT_LE_ULONG(lowGlo.lgStaticAddr + lowGlo.lgStaticSize, first_avail, NULL);
	T_ASSERT_EQ_ULONG(lowGlo.lgLayoutMajorVersion, 3, NULL);
	T_ASSERT_EQ_ULONG(lowGlo.lgLayoutMinorVersion, 0, NULL);
	T_ASSERT_EQ_ULONG(lowGlo.lgLayoutMagic, LOWGLO_LAYOUT_MAGIC, NULL);

	// check the constant values in lowGlo
	T_ASSERT_EQ_ULONG(lowGlo.lgPmapMemQ, ((uint64_t) & (pmap_object_store.memq)), NULL);
	T_ASSERT_EQ_ULONG(lowGlo.lgPmapMemPageOffset, offsetof(struct vm_page_with_ppnum, vmp_phys_page), NULL);
	T_ASSERT_EQ_ULONG(lowGlo.lgPmapMemChainOffset, offsetof(struct vm_page, vmp_listq), NULL);
	T_ASSERT_EQ_ULONG(lowGlo.lgPmapMemPagesize, sizeof(struct vm_page), NULL);

#if defined(__arm64__)
	T_ASSERT_EQ_ULONG(lowGlo.lgPmapMemFromArrayMask, VM_PACKED_FROM_VM_PAGES_ARRAY, NULL);
	T_ASSERT_EQ_ULONG(lowGlo.lgPmapMemPackedShift, VM_PACKED_POINTER_SHIFT, NULL);
	T_ASSERT_EQ_ULONG(lowGlo.lgPmapMemPackedBaseAddr, VM_MIN_KERNEL_AND_KEXT_ADDRESS, NULL);
#endif

	vm_object_lock_shared(&pmap_object_store);
	astris_vm_page_queue_iterate(lowGlo.lgPmapMemQ, p)
	{
		ppnum_t ppnum   = astris_vm_page_get_phys_page(p);
		pmap_paddr_t pa = (pmap_paddr_t)astris_ptoa(ppnum);
		T_ASSERT_GE_ULONG(pa, gPhysBase, NULL);
		T_ASSERT_LT_ULONG(pa, gPhysBase + gPhysSize, NULL);
		iter++;
		T_ASSERT_LT_INT(iter, MAX_PMAP_OBJECT_ELEMENT, NULL);
	}
	vm_object_unlock(&pmap_object_store);

	T_ASSERT_GT_INT(iter, 0, NULL);
	return KERN_SUCCESS;
}
#endif
