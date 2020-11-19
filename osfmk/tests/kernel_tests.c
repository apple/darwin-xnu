/*
 * Copyright (c) 2019-2020 Apple Inc. All rights reserved.
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
#include <kern/zalloc_internal.h>
#include <kern/kalloc.h>
#include <tests/ktest.h>
#include <sys/errno.h>
#include <sys/random.h>
#include <kern/kern_cdata.h>
#include <machine/lowglobals.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <vm/vm_protos.h>
#include <string.h>

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
kern_return_t ts_kernel_primitive_test(void);
kern_return_t ts_kernel_sleep_inheritor_test(void);
kern_return_t ts_kernel_gate_test(void);
kern_return_t ts_kernel_turnstile_chain_test(void);
kern_return_t ts_kernel_timingsafe_bcmp_test(void);

#if __ARM_VFP__
extern kern_return_t vfp_state_test(void);
#endif

extern kern_return_t kprintf_hhx_test(void);

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
#if defined(HAS_APPLE_PAC)
extern kern_return_t arm64_ropjop_test(void);
#endif /* defined(HAS_APPLE_PAC) */
#endif /* __arm64__ */

extern kern_return_t test_thread_call(void);


struct xnupost_panic_widget xt_panic_widgets = {.xtp_context_p = NULL,
	                                        .xtp_outval_p = NULL,
	                                        .xtp_func_name = NULL,
	                                        .xtp_func = NULL};

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
#if defined(HAS_APPLE_PAC)
	                                   XNUPOST_TEST_CONFIG_BASIC(arm64_ropjop_test),
#endif /* defined(HAS_APPLE_PAC) */
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
	                                   XNUPOST_TEST_CONFIG_BASIC(ts_kernel_primitive_test),
	                                   XNUPOST_TEST_CONFIG_BASIC(ts_kernel_sleep_inheritor_test),
	                                   XNUPOST_TEST_CONFIG_BASIC(ts_kernel_gate_test),
	                                   XNUPOST_TEST_CONFIG_BASIC(ts_kernel_turnstile_chain_test),
	                                   XNUPOST_TEST_CONFIG_BASIC(ts_kernel_timingsafe_bcmp_test),
	                                   XNUPOST_TEST_CONFIG_BASIC(kprintf_hhx_test),
#if __ARM_VFP__
	                                   XNUPOST_TEST_CONFIG_BASIC(vfp_state_test),
#endif
	                                   XNUPOST_TEST_CONFIG_BASIC(vm_tests), };

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
	if (parse_config_retval != KERN_INVALID_CAPABILITY) {
		return parse_config_retval;
	}
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
				if (*b == '\0') {
					return FALSE;
				}
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
	if (KERN_SUCCESS != xnupost_parse_config()) {
		return KERN_FAILURE;
	}

	xnupost_test_t testp;
	for (uint32_t i = 0; i < test_count; i++) {
		testp = &test_list[i];
		if (testp->xt_test_num == 0) {
			assert(total_post_tests_count < UINT16_MAX);
			testp->xt_test_num = (uint16_t)++total_post_tests_count;
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
	if (xt_panic_widgets.xtp_context_p != NULL || xt_panic_widgets.xtp_func != NULL) {
		return KERN_RESOURCE_SHORTAGE;
	}

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

	if (outval) {
		*outval = (void *)(uintptr_t)ret;
	}
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
zalloc_test(void)
{
	zone_t test_zone;
	void * test_ptr;

	T_SETUPBEGIN;
	test_zone = zone_create("test_uint64_zone", sizeof(uint64_t),
	    ZC_DESTRUCTIBLE);
	T_ASSERT_NOTNULL(test_zone, NULL);

	T_ASSERT_EQ_INT(test_zone->countfree, 0, NULL);
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
		if (bit_entropy < min_bit_entropy) {
			min_bit_entropy = bit_entropy;
		}
		if (bit_entropy > max_bit_entropy) {
			max_bit_entropy = bit_entropy;
		}

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
		if (window_end >= CONF_ITERATIONS) {
			window_end = CONF_ITERATIONS - 1;
		}

		trend = 0;
		for (i = window_start; i < window_end; i++) {
			if (numbers[i] < numbers[i + 1]) {
				trend++;
			} else if (numbers[i] > numbers[i + 1]) {
				trend--;
			}
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
	{
		.kcs_flags = KCS_SUBTYPE_FLAGS_NONE,
		.kcs_elem_type = KC_ST_UINT64,
		.kcs_elem_offset = 0 * sizeof(uint64_t),
		.kcs_elem_size = sizeof(uint64_t),
		.kcs_name = "disk_reads_count"
	},
	{
		.kcs_flags = KCS_SUBTYPE_FLAGS_NONE,
		.kcs_elem_type = KC_ST_UINT64,
		.kcs_elem_offset = 1 * sizeof(uint64_t),
		.kcs_elem_size = sizeof(uint64_t),
		.kcs_name = "disk_reads_size"
	},
	{
		.kcs_flags = KCS_SUBTYPE_FLAGS_ARRAY,
		.kcs_elem_type = KC_ST_UINT64,
		.kcs_elem_offset = 2 * sizeof(uint64_t),
		.kcs_elem_size = KCS_SUBTYPE_PACK_SIZE(4, sizeof(uint64_t)),
		.kcs_name = "io_priority_count"
	},
	{
		.kcs_flags = KCS_SUBTYPE_FLAGS_ARRAY,
		.kcs_elem_type = KC_ST_UINT64,
		.kcs_elem_offset = (2 + 4) * sizeof(uint64_t),
		.kcs_elem_size = sizeof(uint64_t),
		.kcs_name = "io_priority_size"
	},
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
	T_ASSERT(retval == KERN_INSUFFICIENT_BUFFER_SIZE, "init with 30 bytes failed as expected with KERN_INSUFFICIENT_BUFFER_SIZE");

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
	T_ASSERT(retval == KERN_INSUFFICIENT_BUFFER_SIZE, "Allocating entry with size > buffer -> KERN_INSUFFICIENT_BUFFER_SIZE");
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
	kcdata_iter_t iter = kcdata_iter(item_p, (unsigned long)(PAGE_SIZE - kcdata_memory_get_used_bytes(&test_kc_data)));
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
 *  kern_return_t
 *  kcdata_api_assert_tests()
 *  {
 *       kern_return_t retval       = 0;
 *       void * assert_check_retval = NULL;
 *       test_kc_data2.kcd_length   = 0xdeadbeef;
 *       mach_vm_address_t address = (mach_vm_address_t)kalloc(PAGE_SIZE);
 *       T_EXPECT_NOTNULL(address, "kalloc of PAGE_SIZE data.");
 *
 *       retval = kcdata_memory_static_init(&test_kc_data2, (mach_vm_address_t)address, KCDATA_BUFFER_BEGIN_STACKSHOT, PAGE_SIZE,
 *                                          KCFLAG_USE_MEMCOPY);
 *
 *       T_ASSERT(retval == KERN_SUCCESS, "successful kcdata_memory_static_init call");
 *
 *       retval = T_REGISTER_ASSERT_CHECK("KCDATA_DESC_MAXLEN", &assert_check_retval);
 *       T_ASSERT(retval == KERN_SUCCESS, "registered assert widget");
 *
 *       // this will assert
 *       retval = kcdata_add_uint32_with_description(&test_kc_data2, 0xc0ffee, "really long description string for kcdata");
 *       T_ASSERT(retval == KERN_INVALID_ARGUMENT, "API param check returned KERN_INVALID_ARGUMENT correctly");
 *       T_ASSERT(assert_check_retval == (void *)XT_RET_W_SUCCESS, "assertion handler verified that it was hit");
 *
 *       return KERN_SUCCESS;
 *  }
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
	if (!p) {
		return (uintptr_t)0;
	}

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
	T_ASSERT_EQ_ULONG(lowGlo.lgLayoutMinorVersion, 2, NULL);
	T_ASSERT_EQ_ULONG(lowGlo.lgLayoutMagic, LOWGLO_LAYOUT_MAGIC, NULL);

	// check the constant values in lowGlo
	T_ASSERT_EQ_ULONG(lowGlo.lgPmapMemQ, ((typeof(lowGlo.lgPmapMemQ)) & (pmap_object_store.memq)), NULL);
	T_ASSERT_EQ_ULONG(lowGlo.lgPmapMemPageOffset, offsetof(struct vm_page_with_ppnum, vmp_phys_page), NULL);
	T_ASSERT_EQ_ULONG(lowGlo.lgPmapMemChainOffset, offsetof(struct vm_page, vmp_listq), NULL);
	T_ASSERT_EQ_ULONG(lowGlo.lgPmapMemPagesize, sizeof(struct vm_page), NULL);

#if defined(__arm64__)
	T_ASSERT_EQ_ULONG(lowGlo.lgPmapMemFromArrayMask, VM_PAGE_PACKED_FROM_ARRAY, NULL);
	T_ASSERT_EQ_ULONG(lowGlo.lgPmapMemPackedShift, VM_PAGE_PACKED_PTR_SHIFT, NULL);
	T_ASSERT_EQ_ULONG(lowGlo.lgPmapMemPackedBaseAddr, VM_PAGE_PACKED_PTR_BASE, NULL);
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

struct ts_kern_prim_test_args {
	int *end_barrier;
	int *notify_b;
	int *wait_event_b;
	int before_num;
	int *notify_a;
	int *wait_event_a;
	int after_num;
	int priority_to_check;
};

static void
wait_threads(
	int* var,
	int num)
{
	if (var != NULL) {
		while (os_atomic_load(var, acquire) != num) {
			assert_wait((event_t) var, THREAD_UNINT);
			if (os_atomic_load(var, acquire) != num) {
				(void) thread_block(THREAD_CONTINUE_NULL);
			} else {
				clear_wait(current_thread(), THREAD_AWAKENED);
			}
		}
	}
}

static void
wake_threads(
	int* var)
{
	if (var) {
		os_atomic_inc(var, relaxed);
		thread_wakeup((event_t) var);
	}
}

extern void IOSleep(int);

static void
thread_lock_unlock_kernel_primitive(
	void *args,
	__unused wait_result_t wr)
{
	thread_t thread = current_thread();
	struct ts_kern_prim_test_args *info = (struct ts_kern_prim_test_args*) args;
	int pri;

	thread_lock(thread);
	pri = thread->sched_pri;
	thread_unlock(thread);

	wait_threads(info->wait_event_b, info->before_num);
	wake_threads(info->notify_b);

	tstile_test_prim_lock(SYSCTL_TURNSTILE_TEST_KERNEL_DEFAULT);

	wake_threads(info->notify_a);
	wait_threads(info->wait_event_a, info->after_num);

	IOSleep(100);

	if (info->priority_to_check) {
		thread_lock(thread);
		pri = thread->sched_pri;
		thread_unlock(thread);
		T_ASSERT(pri == info->priority_to_check, "Priority thread: current sched %d sched wanted %d", pri, info->priority_to_check);
	}

	tstile_test_prim_unlock(SYSCTL_TURNSTILE_TEST_KERNEL_DEFAULT);

	wake_threads(info->end_barrier);
	thread_terminate_self();
}

kern_return_t
ts_kernel_primitive_test(void)
{
	thread_t owner, thread1, thread2;
	struct ts_kern_prim_test_args targs[2] = {};
	kern_return_t result;
	int end_barrier = 0;
	int owner_locked = 0;
	int waiters_ready = 0;

	T_LOG("Testing turnstile kernel primitive");

	targs[0].notify_b = NULL;
	targs[0].wait_event_b = NULL;
	targs[0].before_num = 0;
	targs[0].notify_a = &owner_locked;
	targs[0].wait_event_a = &waiters_ready;
	targs[0].after_num = 2;
	targs[0].priority_to_check = 90;
	targs[0].end_barrier = &end_barrier;

	// Start owner with priority 80
	result = kernel_thread_start_priority((thread_continue_t)thread_lock_unlock_kernel_primitive, &targs[0], 80, &owner);
	T_ASSERT(result == KERN_SUCCESS, "Starting owner");

	targs[1].notify_b = &waiters_ready;
	targs[1].wait_event_b = &owner_locked;
	targs[1].before_num = 1;
	targs[1].notify_a = NULL;
	targs[1].wait_event_a = NULL;
	targs[1].after_num = 0;
	targs[1].priority_to_check = 0;
	targs[1].end_barrier = &end_barrier;

	// Start waiters with priority 85 and 90
	result = kernel_thread_start_priority((thread_continue_t)thread_lock_unlock_kernel_primitive, &targs[1], 85, &thread1);
	T_ASSERT(result == KERN_SUCCESS, "Starting thread1");

	result = kernel_thread_start_priority((thread_continue_t)thread_lock_unlock_kernel_primitive, &targs[1], 90, &thread2);
	T_ASSERT(result == KERN_SUCCESS, "Starting thread2");

	wait_threads(&end_barrier, 3);

	return KERN_SUCCESS;
}

#define MTX_LOCK 0
#define RW_LOCK 1

#define NUM_THREADS 4

struct synch_test_common {
	unsigned int nthreads;
	thread_t *threads;
	int max_pri;
	int test_done;
};

static kern_return_t
init_synch_test_common(struct synch_test_common *info, unsigned int nthreads)
{
	info->nthreads = nthreads;
	info->threads = kalloc(sizeof(thread_t) * nthreads);
	if (!info->threads) {
		return ENOMEM;
	}

	return KERN_SUCCESS;
}

static void
destroy_synch_test_common(struct synch_test_common *info)
{
	kfree(info->threads, sizeof(thread_t) * info->nthreads);
}

static void
start_threads(thread_continue_t func, struct synch_test_common *info, bool sleep_after_first)
{
	thread_t thread;
	kern_return_t result;
	uint i;
	int priority = 75;

	info->test_done = 0;

	for (i = 0; i < info->nthreads; i++) {
		info->threads[i] = NULL;
	}

	info->max_pri = priority + (info->nthreads - 1) * 5;
	if (info->max_pri > 95) {
		info->max_pri = 95;
	}

	for (i = 0; i < info->nthreads; i++) {
		result = kernel_thread_start_priority((thread_continue_t)func, info, priority, &thread);
		os_atomic_store(&info->threads[i], thread, release);
		T_ASSERT(result == KERN_SUCCESS, "Starting thread %d, priority %d, %p", i, priority, thread);

		priority += 5;

		if (i == 0 && sleep_after_first) {
			IOSleep(100);
		}
	}
}

static unsigned int
get_max_pri(struct synch_test_common * info)
{
	return info->max_pri;
}

static void
wait_all_thread(struct synch_test_common * info)
{
	wait_threads(&info->test_done, info->nthreads);
}

static void
notify_waiter(struct synch_test_common * info)
{
	wake_threads(&info->test_done);
}

static void
wait_for_waiters(struct synch_test_common *info)
{
	uint i, j;
	thread_t thread;

	for (i = 0; i < info->nthreads; i++) {
		j = 0;
		while (os_atomic_load(&info->threads[i], acquire) == NULL) {
			if (j % 100 == 0) {
				IOSleep(10);
			}
			j++;
		}

		if (info->threads[i] != current_thread()) {
			j = 0;
			do {
				thread = os_atomic_load(&info->threads[i], relaxed);
				if (thread == (thread_t) 1) {
					break;
				}

				if (!(thread->state & TH_RUN)) {
					break;
				}

				if (j % 100 == 0) {
					IOSleep(100);
				}
				j++;

				if (thread->started == FALSE) {
					continue;
				}
			} while (thread->state & TH_RUN);
		}
	}
}

static void
exclude_current_waiter(struct synch_test_common *info)
{
	uint i, j;

	for (i = 0; i < info->nthreads; i++) {
		j = 0;
		while (os_atomic_load(&info->threads[i], acquire) == NULL) {
			if (j % 100 == 0) {
				IOSleep(10);
			}
			j++;
		}

		if (os_atomic_load(&info->threads[i], acquire) == current_thread()) {
			os_atomic_store(&info->threads[i], (thread_t)1, release);
			return;
		}
	}
}

struct info_sleep_inheritor_test {
	struct synch_test_common head;
	lck_mtx_t mtx_lock;
	lck_rw_t rw_lock;
	decl_lck_mtx_gate_data(, gate);
	boolean_t gate_closed;
	int prim_type;
	boolean_t work_to_do;
	unsigned int max_pri;
	unsigned int steal_pri;
	int synch_value;
	int synch;
	int value;
	int handoff_failure;
	thread_t thread_inheritor;
};

static void
primitive_lock(struct info_sleep_inheritor_test *info)
{
	switch (info->prim_type) {
	case MTX_LOCK:
		lck_mtx_lock(&info->mtx_lock);
		break;
	case RW_LOCK:
		lck_rw_lock(&info->rw_lock, LCK_RW_TYPE_EXCLUSIVE);
		break;
	default:
		panic("invalid type %d", info->prim_type);
	}
}

static void
primitive_unlock(struct info_sleep_inheritor_test *info)
{
	switch (info->prim_type) {
	case MTX_LOCK:
		lck_mtx_unlock(&info->mtx_lock);
		break;
	case RW_LOCK:
		lck_rw_unlock(&info->rw_lock, LCK_RW_TYPE_EXCLUSIVE);
		break;
	default:
		panic("invalid type %d", info->prim_type);
	}
}

static wait_result_t
primitive_sleep_with_inheritor(struct info_sleep_inheritor_test *info)
{
	wait_result_t ret = KERN_SUCCESS;
	switch (info->prim_type) {
	case MTX_LOCK:
		ret = lck_mtx_sleep_with_inheritor(&info->mtx_lock, LCK_SLEEP_DEFAULT, (event_t) &info->thread_inheritor, info->thread_inheritor, THREAD_UNINT | THREAD_WAIT_NOREPORT_USER, TIMEOUT_WAIT_FOREVER);
		break;
	case RW_LOCK:
		ret = lck_rw_sleep_with_inheritor(&info->rw_lock, LCK_SLEEP_DEFAULT, (event_t) &info->thread_inheritor, info->thread_inheritor, THREAD_UNINT | THREAD_WAIT_NOREPORT_USER, TIMEOUT_WAIT_FOREVER);
		break;
	default:
		panic("invalid type %d", info->prim_type);
	}

	return ret;
}

static void
primitive_wakeup_one_with_inheritor(struct info_sleep_inheritor_test *info)
{
	switch (info->prim_type) {
	case MTX_LOCK:
	case RW_LOCK:
		wakeup_one_with_inheritor((event_t) &info->thread_inheritor, THREAD_AWAKENED, LCK_WAKE_DEFAULT, &info->thread_inheritor);
		break;
	default:
		panic("invalid type %d", info->prim_type);
	}
}

static void
primitive_wakeup_all_with_inheritor(struct info_sleep_inheritor_test *info)
{
	switch (info->prim_type) {
	case MTX_LOCK:
	case RW_LOCK:
		wakeup_all_with_inheritor((event_t) &info->thread_inheritor, THREAD_AWAKENED);
		break;
	default:
		panic("invalid type %d", info->prim_type);
	}
	return;
}

static void
primitive_change_sleep_inheritor(struct info_sleep_inheritor_test *info)
{
	switch (info->prim_type) {
	case MTX_LOCK:
	case RW_LOCK:
		change_sleep_inheritor((event_t) &info->thread_inheritor, info->thread_inheritor);
		break;
	default:
		panic("invalid type %d", info->prim_type);
	}
	return;
}

static kern_return_t
primitive_gate_try_close(struct info_sleep_inheritor_test *info)
{
	kern_return_t ret = KERN_SUCCESS;
	switch (info->prim_type) {
	case MTX_LOCK:
		ret = lck_mtx_gate_try_close(&info->mtx_lock, &info->gate);
		break;
	case RW_LOCK:
		ret = lck_rw_gate_try_close(&info->rw_lock, &info->gate);
		break;
	default:
		panic("invalid type %d", info->prim_type);
	}
	return ret;
}

static gate_wait_result_t
primitive_gate_wait(struct info_sleep_inheritor_test *info)
{
	gate_wait_result_t ret = GATE_OPENED;
	switch (info->prim_type) {
	case MTX_LOCK:
		ret = lck_mtx_gate_wait(&info->mtx_lock, &info->gate, LCK_SLEEP_DEFAULT, THREAD_UNINT | THREAD_WAIT_NOREPORT_USER, TIMEOUT_WAIT_FOREVER);
		break;
	case RW_LOCK:
		ret = lck_rw_gate_wait(&info->rw_lock, &info->gate, LCK_SLEEP_DEFAULT, THREAD_UNINT | THREAD_WAIT_NOREPORT_USER, TIMEOUT_WAIT_FOREVER);
		break;
	default:
		panic("invalid type %d", info->prim_type);
	}
	return ret;
}

static void
primitive_gate_open(struct info_sleep_inheritor_test *info)
{
	switch (info->prim_type) {
	case MTX_LOCK:
		lck_mtx_gate_open(&info->mtx_lock, &info->gate);
		break;
	case RW_LOCK:
		lck_rw_gate_open(&info->rw_lock, &info->gate);
		break;
	default:
		panic("invalid type %d", info->prim_type);
	}
}

static void
primitive_gate_close(struct info_sleep_inheritor_test *info)
{
	switch (info->prim_type) {
	case MTX_LOCK:
		lck_mtx_gate_close(&info->mtx_lock, &info->gate);
		break;
	case RW_LOCK:
		lck_rw_gate_close(&info->rw_lock, &info->gate);
		break;
	default:
		panic("invalid type %d", info->prim_type);
	}
}

static void
primitive_gate_steal(struct info_sleep_inheritor_test *info)
{
	switch (info->prim_type) {
	case MTX_LOCK:
		lck_mtx_gate_steal(&info->mtx_lock, &info->gate);
		break;
	case RW_LOCK:
		lck_rw_gate_steal(&info->rw_lock, &info->gate);
		break;
	default:
		panic("invalid type %d", info->prim_type);
	}
}

static kern_return_t
primitive_gate_handoff(struct info_sleep_inheritor_test *info, int flags)
{
	kern_return_t ret = KERN_SUCCESS;
	switch (info->prim_type) {
	case MTX_LOCK:
		ret = lck_mtx_gate_handoff(&info->mtx_lock, &info->gate, flags);
		break;
	case RW_LOCK:
		ret = lck_rw_gate_handoff(&info->rw_lock, &info->gate, flags);
		break;
	default:
		panic("invalid type %d", info->prim_type);
	}
	return ret;
}

static void
primitive_gate_assert(struct info_sleep_inheritor_test *info, int type)
{
	switch (info->prim_type) {
	case MTX_LOCK:
		lck_mtx_gate_assert(&info->mtx_lock, &info->gate, type);
		break;
	case RW_LOCK:
		lck_rw_gate_assert(&info->rw_lock, &info->gate, type);
		break;
	default:
		panic("invalid type %d", info->prim_type);
	}
}

static void
primitive_gate_init(struct info_sleep_inheritor_test *info)
{
	switch (info->prim_type) {
	case MTX_LOCK:
		lck_mtx_gate_init(&info->mtx_lock, &info->gate);
		break;
	case RW_LOCK:
		lck_rw_gate_init(&info->rw_lock, &info->gate);
		break;
	default:
		panic("invalid type %d", info->prim_type);
	}
}

static void
primitive_gate_destroy(struct info_sleep_inheritor_test *info)
{
	switch (info->prim_type) {
	case MTX_LOCK:
		lck_mtx_gate_destroy(&info->mtx_lock, &info->gate);
		break;
	case RW_LOCK:
		lck_rw_gate_destroy(&info->rw_lock, &info->gate);
		break;
	default:
		panic("invalid type %d", info->prim_type);
	}
}

static void
thread_inheritor_like_mutex(
	void *args,
	__unused wait_result_t wr)
{
	wait_result_t wait;

	struct info_sleep_inheritor_test *info = (struct info_sleep_inheritor_test*) args;
	uint my_pri = current_thread()->sched_pri;

	T_LOG("Started thread pri %d %p", my_pri, current_thread());

	/*
	 * spin here to start concurrently
	 */
	wake_threads(&info->synch);
	wait_threads(&info->synch, info->synch_value);

	primitive_lock(info);

	if (info->thread_inheritor == NULL) {
		info->thread_inheritor = current_thread();
	} else {
		wait = primitive_sleep_with_inheritor(info);
		T_ASSERT(wait == THREAD_AWAKENED || wait == THREAD_NOT_WAITING, "sleep_with_inheritor return");
	}
	primitive_unlock(info);

	IOSleep(100);
	info->value++;

	primitive_lock(info);

	T_ASSERT(info->thread_inheritor == current_thread(), "thread_inheritor is %p", info->thread_inheritor);
	primitive_wakeup_one_with_inheritor(info);
	T_LOG("woken up %p", info->thread_inheritor);

	if (info->thread_inheritor == NULL) {
		T_ASSERT(info->handoff_failure == 0, "handoff failures");
		info->handoff_failure++;
	} else {
		T_ASSERT(info->thread_inheritor != current_thread(), "thread_inheritor is %p", info->thread_inheritor);
		thread_deallocate(info->thread_inheritor);
	}

	primitive_unlock(info);

	assert(current_thread()->kern_promotion_schedpri == 0);
	notify_waiter((struct synch_test_common *)info);

	thread_terminate_self();
}

static void
thread_just_inheritor_do_work(
	void *args,
	__unused wait_result_t wr)
{
	struct info_sleep_inheritor_test *info = (struct info_sleep_inheritor_test*) args;
	uint my_pri = current_thread()->sched_pri;
	uint max_pri;

	T_LOG("Started thread pri %d %p", my_pri, current_thread());
	primitive_lock(info);

	if (info->thread_inheritor == NULL) {
		info->thread_inheritor = current_thread();
		primitive_unlock(info);
		T_LOG("Thread pri %d first to run %p", my_pri, current_thread());

		wait_threads(&info->synch, info->synch_value - 1);

		wait_for_waiters((struct synch_test_common *)info);

		max_pri = get_max_pri((struct synch_test_common *) info);
		T_ASSERT((uint) current_thread()->sched_pri == max_pri, "sleep_inheritor inheritor priority current is %d, should be %d", current_thread()->sched_pri, max_pri);

		os_atomic_store(&info->synch, 0, relaxed);
		primitive_lock(info);
		primitive_wakeup_all_with_inheritor(info);
	} else {
		wake_threads(&info->synch);
		primitive_sleep_with_inheritor(info);
	}

	primitive_unlock(info);

	assert(current_thread()->kern_promotion_schedpri == 0);
	notify_waiter((struct synch_test_common *)info);

	thread_terminate_self();
}

static void
thread_steal_work(
	void *args,
	__unused wait_result_t wr)
{
	struct info_sleep_inheritor_test *info = (struct info_sleep_inheritor_test*) args;
	uint my_pri = current_thread()->sched_pri;

	T_LOG("Started thread pri %d %p", my_pri, current_thread());
	primitive_lock(info);

	if (info->thread_inheritor == NULL) {
		info->thread_inheritor = current_thread();
		exclude_current_waiter((struct synch_test_common *)info);

		T_LOG("Thread pri %d first to run %p", my_pri, current_thread());
		primitive_unlock(info);

		wait_threads(&info->synch, info->synch_value - 2);

		wait_for_waiters((struct synch_test_common *)info);
		T_LOG("Thread pri %d first to run %p", my_pri, current_thread());
		primitive_lock(info);
		if (info->thread_inheritor == current_thread()) {
			primitive_wakeup_all_with_inheritor(info);
		}
	} else {
		if (info->steal_pri == 0) {
			info->steal_pri = my_pri;
			info->thread_inheritor = current_thread();
			primitive_change_sleep_inheritor(info);
			exclude_current_waiter((struct synch_test_common *)info);

			primitive_unlock(info);

			wait_threads(&info->synch, info->synch_value - 2);

			T_LOG("Thread pri %d stole push %p", my_pri, current_thread());
			wait_for_waiters((struct synch_test_common *)info);

			T_ASSERT((uint) current_thread()->sched_pri == info->steal_pri, "sleep_inheritor inheritor priority current is %d, should be %d", current_thread()->sched_pri, info->steal_pri);

			primitive_lock(info);
			primitive_wakeup_all_with_inheritor(info);
		} else {
			if (my_pri > info->steal_pri) {
				info->steal_pri = my_pri;
			}
			wake_threads(&info->synch);
			primitive_sleep_with_inheritor(info);
			exclude_current_waiter((struct synch_test_common *)info);
		}
	}
	primitive_unlock(info);

	assert(current_thread()->kern_promotion_schedpri == 0);
	notify_waiter((struct synch_test_common *)info);

	thread_terminate_self();
}

static void
thread_no_inheritor_work(
	void *args,
	__unused wait_result_t wr)
{
	struct info_sleep_inheritor_test *info = (struct info_sleep_inheritor_test*) args;
	uint my_pri = current_thread()->sched_pri;

	T_LOG("Started thread pri %d %p", my_pri, current_thread());
	primitive_lock(info);

	info->value--;
	if (info->value == 0) {
		primitive_wakeup_all_with_inheritor(info);
	} else {
		info->thread_inheritor = NULL;
		primitive_sleep_with_inheritor(info);
	}

	primitive_unlock(info);

	assert(current_thread()->kern_promotion_schedpri == 0);
	notify_waiter((struct synch_test_common *)info);

	thread_terminate_self();
}

static void
thread_mtx_work(
	void *args,
	__unused wait_result_t wr)
{
	struct info_sleep_inheritor_test *info = (struct info_sleep_inheritor_test*) args;
	uint my_pri = current_thread()->sched_pri;
	int i;
	u_int8_t rand;
	unsigned int mod_rand;
	uint max_pri;

	T_LOG("Started thread pri %d %p", my_pri, current_thread());

	for (i = 0; i < 10; i++) {
		lck_mtx_lock(&info->mtx_lock);
		if (info->thread_inheritor == NULL) {
			info->thread_inheritor = current_thread();
			lck_mtx_unlock(&info->mtx_lock);

			T_LOG("Thread pri %d first to run %p", my_pri, current_thread());

			wait_threads(&info->synch, info->synch_value - 1);
			wait_for_waiters((struct synch_test_common *)info);
			max_pri = get_max_pri((struct synch_test_common *) info);
			T_ASSERT((uint) current_thread()->sched_pri == max_pri, "sleep_inheritor inheritor priority current is %d, should be %d", current_thread()->sched_pri, max_pri);

			os_atomic_store(&info->synch, 0, relaxed);

			lck_mtx_lock(&info->mtx_lock);
			info->thread_inheritor = NULL;
			wakeup_all_with_inheritor((event_t) &info->thread_inheritor, THREAD_AWAKENED);
			lck_mtx_unlock(&info->mtx_lock);
			continue;
		}

		read_random(&rand, sizeof(rand));
		mod_rand = rand % 2;

		wake_threads(&info->synch);
		switch (mod_rand) {
		case 0:
			lck_mtx_sleep_with_inheritor(&info->mtx_lock, LCK_SLEEP_DEFAULT, (event_t) &info->thread_inheritor, info->thread_inheritor, THREAD_UNINT | THREAD_WAIT_NOREPORT_USER, TIMEOUT_WAIT_FOREVER);
			lck_mtx_unlock(&info->mtx_lock);
			break;
		case 1:
			lck_mtx_sleep_with_inheritor(&info->mtx_lock, LCK_SLEEP_UNLOCK, (event_t) &info->thread_inheritor, info->thread_inheritor, THREAD_UNINT | THREAD_WAIT_NOREPORT_USER, TIMEOUT_WAIT_FOREVER);
			break;
		default:
			panic("rand()mod4 returned %u (random %u)", mod_rand, rand);
		}
	}

	/*
	 * spin here to stop using the lock as mutex
	 */
	wake_threads(&info->synch);
	wait_threads(&info->synch, info->synch_value);

	for (i = 0; i < 10; i++) {
		/* read_random might sleep so read it before acquiring the mtx as spin */
		read_random(&rand, sizeof(rand));

		lck_mtx_lock_spin(&info->mtx_lock);
		if (info->thread_inheritor == NULL) {
			info->thread_inheritor = current_thread();
			lck_mtx_unlock(&info->mtx_lock);

			T_LOG("Thread pri %d first to run %p", my_pri, current_thread());
			wait_for_waiters((struct synch_test_common *)info);
			max_pri = get_max_pri((struct synch_test_common *) info);
			T_ASSERT((uint) current_thread()->sched_pri == max_pri, "sleep_inheritor inheritor priority current is %d, should be %d", current_thread()->sched_pri, max_pri);

			lck_mtx_lock_spin(&info->mtx_lock);
			info->thread_inheritor = NULL;
			wakeup_all_with_inheritor((event_t) &info->thread_inheritor, THREAD_AWAKENED);
			lck_mtx_unlock(&info->mtx_lock);
			continue;
		}

		mod_rand = rand % 2;
		switch (mod_rand) {
		case 0:
			lck_mtx_sleep_with_inheritor(&info->mtx_lock, LCK_SLEEP_SPIN, (event_t) &info->thread_inheritor, info->thread_inheritor, THREAD_UNINT | THREAD_WAIT_NOREPORT_USER, TIMEOUT_WAIT_FOREVER);
			lck_mtx_unlock(&info->mtx_lock);
			break;
		case 1:
			lck_mtx_sleep_with_inheritor(&info->mtx_lock, LCK_SLEEP_SPIN_ALWAYS, (event_t) &info->thread_inheritor, info->thread_inheritor, THREAD_UNINT | THREAD_WAIT_NOREPORT_USER, TIMEOUT_WAIT_FOREVER);
			lck_mtx_unlock(&info->mtx_lock);
			break;
		default:
			panic("rand()mod4 returned %u (random %u)", mod_rand, rand);
		}
	}
	assert(current_thread()->kern_promotion_schedpri == 0);
	notify_waiter((struct synch_test_common *)info);

	thread_terminate_self();
}

static void
thread_rw_work(
	void *args,
	__unused wait_result_t wr)
{
	struct info_sleep_inheritor_test *info = (struct info_sleep_inheritor_test*) args;
	uint my_pri = current_thread()->sched_pri;
	int i;
	lck_rw_type_t type;
	u_int8_t rand;
	unsigned int mod_rand;
	uint max_pri;

	T_LOG("Started thread pri %d %p", my_pri, current_thread());

	for (i = 0; i < 10; i++) {
try_again:
		type = LCK_RW_TYPE_SHARED;
		lck_rw_lock(&info->rw_lock, type);
		if (info->thread_inheritor == NULL) {
			type = LCK_RW_TYPE_EXCLUSIVE;

			if (lck_rw_lock_shared_to_exclusive(&info->rw_lock)) {
				if (info->thread_inheritor == NULL) {
					info->thread_inheritor = current_thread();
					lck_rw_unlock(&info->rw_lock, type);
					wait_threads(&info->synch, info->synch_value - 1);

					T_LOG("Thread pri %d first to run %p", my_pri, current_thread());
					wait_for_waiters((struct synch_test_common *)info);
					max_pri = get_max_pri((struct synch_test_common *) info);
					T_ASSERT((uint) current_thread()->sched_pri == max_pri, "sleep_inheritor inheritor priority current is %d, should be %d", current_thread()->sched_pri, max_pri);

					os_atomic_store(&info->synch, 0, relaxed);

					lck_rw_lock(&info->rw_lock, type);
					info->thread_inheritor = NULL;
					wakeup_all_with_inheritor((event_t) &info->thread_inheritor, THREAD_AWAKENED);
					lck_rw_unlock(&info->rw_lock, type);
					continue;
				}
			} else {
				goto try_again;
			}
		}

		read_random(&rand, sizeof(rand));
		mod_rand = rand % 4;

		wake_threads(&info->synch);
		switch (mod_rand) {
		case 0:
			lck_rw_sleep_with_inheritor(&info->rw_lock, LCK_SLEEP_DEFAULT, (event_t) &info->thread_inheritor, info->thread_inheritor, THREAD_UNINT | THREAD_WAIT_NOREPORT_USER, TIMEOUT_WAIT_FOREVER);
			lck_rw_unlock(&info->rw_lock, type);
			break;
		case 1:
			lck_rw_sleep_with_inheritor(&info->rw_lock, LCK_SLEEP_UNLOCK, (event_t) &info->thread_inheritor, info->thread_inheritor, THREAD_UNINT | THREAD_WAIT_NOREPORT_USER, TIMEOUT_WAIT_FOREVER);
			break;
		case 2:
			lck_rw_sleep_with_inheritor(&info->rw_lock, LCK_SLEEP_SHARED, (event_t) &info->thread_inheritor, info->thread_inheritor, THREAD_UNINT | THREAD_WAIT_NOREPORT_USER, TIMEOUT_WAIT_FOREVER);
			lck_rw_unlock(&info->rw_lock, LCK_RW_TYPE_SHARED);
			break;
		case 3:
			lck_rw_sleep_with_inheritor(&info->rw_lock, LCK_SLEEP_EXCLUSIVE, (event_t) &info->thread_inheritor, info->thread_inheritor, THREAD_UNINT | THREAD_WAIT_NOREPORT_USER, TIMEOUT_WAIT_FOREVER);
			lck_rw_unlock(&info->rw_lock, LCK_RW_TYPE_EXCLUSIVE);
			break;
		default:
			panic("rand()mod4 returned %u (random %u)", mod_rand, rand);
		}
	}

	assert(current_thread()->kern_promotion_schedpri == 0);
	notify_waiter((struct synch_test_common *)info);

	thread_terminate_self();
}

static void
test_sleep_with_wake_all(struct info_sleep_inheritor_test *info, int prim_type)
{
	info->prim_type = prim_type;
	info->synch = 0;
	info->synch_value = info->head.nthreads;

	info->thread_inheritor = NULL;

	start_threads((thread_continue_t)thread_just_inheritor_do_work, (struct synch_test_common *)info, TRUE);
	wait_all_thread((struct synch_test_common *)info);
}

static void
test_sleep_with_wake_one(struct info_sleep_inheritor_test *info, int prim_type)
{
	info->prim_type = prim_type;

	info->synch = 0;
	info->synch_value = info->head.nthreads;
	info->value = 0;
	info->handoff_failure = 0;
	info->thread_inheritor = NULL;

	start_threads((thread_continue_t)thread_inheritor_like_mutex, (struct synch_test_common *)info, FALSE);
	wait_all_thread((struct synch_test_common *)info);

	T_ASSERT(info->value == (int)info->head.nthreads, "value protected by sleep");
	T_ASSERT(info->handoff_failure == 1, "handoff failures");
}

static void
test_change_sleep_inheritor(struct info_sleep_inheritor_test *info, int prim_type)
{
	info->prim_type = prim_type;

	info->thread_inheritor = NULL;
	info->steal_pri = 0;
	info->synch = 0;
	info->synch_value = info->head.nthreads;

	start_threads((thread_continue_t)thread_steal_work, (struct synch_test_common *)info, FALSE);
	wait_all_thread((struct synch_test_common *)info);
}

static void
test_no_inheritor(struct info_sleep_inheritor_test *info, int prim_type)
{
	info->prim_type = prim_type;
	info->synch = 0;
	info->synch_value = info->head.nthreads;

	info->thread_inheritor = NULL;
	info->value = info->head.nthreads;

	start_threads((thread_continue_t)thread_no_inheritor_work, (struct synch_test_common *)info, FALSE);
	wait_all_thread((struct synch_test_common *)info);
}

static void
test_rw_lock(struct info_sleep_inheritor_test *info)
{
	info->thread_inheritor = NULL;
	info->value = info->head.nthreads;
	info->synch = 0;
	info->synch_value = info->head.nthreads;

	start_threads((thread_continue_t)thread_rw_work, (struct synch_test_common *)info, FALSE);
	wait_all_thread((struct synch_test_common *)info);
}

static void
test_mtx_lock(struct info_sleep_inheritor_test *info)
{
	info->thread_inheritor = NULL;
	info->value = info->head.nthreads;
	info->synch = 0;
	info->synch_value = info->head.nthreads;

	start_threads((thread_continue_t)thread_mtx_work, (struct synch_test_common *)info, FALSE);
	wait_all_thread((struct synch_test_common *)info);
}

kern_return_t
ts_kernel_sleep_inheritor_test(void)
{
	struct info_sleep_inheritor_test info = {};

	init_synch_test_common((struct synch_test_common *)&info, NUM_THREADS);

	lck_attr_t* lck_attr = lck_attr_alloc_init();
	lck_grp_attr_t* lck_grp_attr = lck_grp_attr_alloc_init();
	lck_grp_t* lck_grp = lck_grp_alloc_init("test sleep_inheritor", lck_grp_attr);

	lck_mtx_init(&info.mtx_lock, lck_grp, lck_attr);
	lck_rw_init(&info.rw_lock, lck_grp, lck_attr);

	/*
	 * Testing lck_mtx_sleep_with_inheritor and wakeup_all_with_inheritor
	 */
	T_LOG("Testing mtx sleep with inheritor and wake_all_with_inheritor");
	test_sleep_with_wake_all(&info, MTX_LOCK);

	/*
	 * Testing rw_mtx_sleep_with_inheritor and wakeup_all_with_inheritor
	 */
	T_LOG("Testing rw sleep with inheritor and wake_all_with_inheritor");
	test_sleep_with_wake_all(&info, RW_LOCK);

	/*
	 * Testing lck_mtx_sleep_with_inheritor and wakeup_one_with_inheritor
	 */
	T_LOG("Testing mtx sleep with inheritor and wake_one_with_inheritor");
	test_sleep_with_wake_one(&info, MTX_LOCK);

	/*
	 * Testing lck_rw_sleep_with_inheritor and wakeup_one_with_inheritor
	 */
	T_LOG("Testing rw sleep with inheritor and wake_one_with_inheritor");
	test_sleep_with_wake_one(&info, RW_LOCK);

	/*
	 * Testing lck_mtx_sleep_with_inheritor and wakeup_all_with_inheritor
	 * and change_sleep_inheritor
	 */
	T_LOG("Testing change_sleep_inheritor with mxt sleep");
	test_change_sleep_inheritor(&info, MTX_LOCK);

	/*
	 * Testing lck_mtx_sleep_with_inheritor and wakeup_all_with_inheritor
	 * and change_sleep_inheritor
	 */
	T_LOG("Testing change_sleep_inheritor with rw sleep");
	test_change_sleep_inheritor(&info, RW_LOCK);

	/*
	 * Testing lck_mtx_sleep_with_inheritor and wakeup_all_with_inheritor
	 * with inheritor NULL
	 */
	T_LOG("Testing inheritor NULL");
	test_no_inheritor(&info, MTX_LOCK);

	/*
	 * Testing lck_mtx_sleep_with_inheritor and wakeup_all_with_inheritor
	 * with inheritor NULL
	 */
	T_LOG("Testing inheritor NULL");
	test_no_inheritor(&info, RW_LOCK);

	/*
	 * Testing mtx locking combinations
	 */
	T_LOG("Testing mtx locking combinations");
	test_mtx_lock(&info);

	/*
	 * Testing rw locking combinations
	 */
	T_LOG("Testing rw locking combinations");
	test_rw_lock(&info);

	destroy_synch_test_common((struct synch_test_common *)&info);

	lck_attr_free(lck_attr);
	lck_grp_attr_free(lck_grp_attr);
	lck_rw_destroy(&info.rw_lock, lck_grp);
	lck_mtx_destroy(&info.mtx_lock, lck_grp);
	lck_grp_free(lck_grp);

	return KERN_SUCCESS;
}

static void
thread_gate_aggressive(
	void *args,
	__unused wait_result_t wr)
{
	struct info_sleep_inheritor_test *info = (struct info_sleep_inheritor_test*) args;
	uint my_pri = current_thread()->sched_pri;

	T_LOG("Started thread pri %d %p", my_pri, current_thread());

	primitive_lock(info);
	if (info->thread_inheritor == NULL) {
		info->thread_inheritor = current_thread();
		primitive_gate_assert(info, GATE_ASSERT_OPEN);
		primitive_gate_close(info);
		exclude_current_waiter((struct synch_test_common *)info);

		primitive_unlock(info);

		wait_threads(&info->synch, info->synch_value - 2);
		wait_for_waiters((struct synch_test_common *)info);
		T_LOG("Thread pri %d first to run %p", my_pri, current_thread());

		primitive_lock(info);
		if (info->thread_inheritor == current_thread()) {
			primitive_gate_open(info);
		}
	} else {
		if (info->steal_pri == 0) {
			info->steal_pri = my_pri;
			info->thread_inheritor = current_thread();
			primitive_gate_steal(info);
			exclude_current_waiter((struct synch_test_common *)info);

			primitive_unlock(info);
			wait_threads(&info->synch, info->synch_value - 2);

			T_LOG("Thread pri %d stole push %p", my_pri, current_thread());
			wait_for_waiters((struct synch_test_common *)info);
			T_ASSERT((uint) current_thread()->sched_pri == info->steal_pri, "gate keeper priority current is %d, should be %d", current_thread()->sched_pri, info->steal_pri);

			primitive_lock(info);
			primitive_gate_open(info);
		} else {
			if (my_pri > info->steal_pri) {
				info->steal_pri = my_pri;
			}
			wake_threads(&info->synch);
			primitive_gate_wait(info);
			exclude_current_waiter((struct synch_test_common *)info);
		}
	}
	primitive_unlock(info);

	assert(current_thread()->kern_promotion_schedpri == 0);
	notify_waiter((struct synch_test_common *)info);

	thread_terminate_self();
}

static void
thread_gate_like_mutex(
	void *args,
	__unused wait_result_t wr)
{
	gate_wait_result_t wait;
	kern_return_t ret;
	uint my_pri = current_thread()->sched_pri;

	struct info_sleep_inheritor_test *info = (struct info_sleep_inheritor_test*) args;

	T_LOG("Started thread pri %d %p", my_pri, current_thread());

	/*
	 * spin here to start concurrently
	 */
	wake_threads(&info->synch);
	wait_threads(&info->synch, info->synch_value);

	primitive_lock(info);

	if (primitive_gate_try_close(info) != KERN_SUCCESS) {
		wait = primitive_gate_wait(info);
		T_ASSERT(wait == GATE_HANDOFF, "gate_wait return");
	}

	primitive_gate_assert(info, GATE_ASSERT_HELD);

	primitive_unlock(info);

	IOSleep(100);
	info->value++;

	primitive_lock(info);

	ret = primitive_gate_handoff(info, GATE_HANDOFF_DEFAULT);
	if (ret == KERN_NOT_WAITING) {
		T_ASSERT(info->handoff_failure == 0, "handoff failures");
		primitive_gate_handoff(info, GATE_HANDOFF_OPEN_IF_NO_WAITERS);
		info->handoff_failure++;
	}

	primitive_unlock(info);
	notify_waiter((struct synch_test_common *)info);

	thread_terminate_self();
}

static void
thread_just_one_do_work(
	void *args,
	__unused wait_result_t wr)
{
	struct info_sleep_inheritor_test *info = (struct info_sleep_inheritor_test*) args;
	uint my_pri = current_thread()->sched_pri;
	uint max_pri;

	T_LOG("Started thread pri %d %p", my_pri, current_thread());

	primitive_lock(info);
check_again:
	if (info->work_to_do) {
		if (primitive_gate_try_close(info) == KERN_SUCCESS) {
			primitive_gate_assert(info, GATE_ASSERT_HELD);
			primitive_unlock(info);

			T_LOG("Thread pri %d acquired the gate %p", my_pri, current_thread());
			wait_threads(&info->synch, info->synch_value - 1);
			wait_for_waiters((struct synch_test_common *)info);
			max_pri = get_max_pri((struct synch_test_common *) info);
			T_ASSERT((uint) current_thread()->sched_pri == max_pri, "gate owner priority current is %d, should be %d", current_thread()->sched_pri, max_pri);
			os_atomic_store(&info->synch, 0, relaxed);

			primitive_lock(info);
			info->work_to_do = FALSE;
			primitive_gate_open(info);
		} else {
			primitive_gate_assert(info, GATE_ASSERT_CLOSED);
			wake_threads(&info->synch);
			primitive_gate_wait(info);
			goto check_again;
		}
	}
	primitive_unlock(info);

	assert(current_thread()->kern_promotion_schedpri == 0);
	notify_waiter((struct synch_test_common *)info);
	thread_terminate_self();
}

static void
test_gate_push(struct info_sleep_inheritor_test *info, int prim_type)
{
	info->prim_type = prim_type;

	primitive_gate_init(info);
	info->work_to_do = TRUE;
	info->synch = 0;
	info->synch_value = NUM_THREADS;

	start_threads((thread_continue_t)thread_just_one_do_work, (struct synch_test_common *) info, TRUE);
	wait_all_thread((struct synch_test_common *)info);

	primitive_gate_destroy(info);
}

static void
test_gate_handoff(struct info_sleep_inheritor_test *info, int prim_type)
{
	info->prim_type = prim_type;

	primitive_gate_init(info);

	info->synch = 0;
	info->synch_value = NUM_THREADS;
	info->value = 0;
	info->handoff_failure = 0;

	start_threads((thread_continue_t)thread_gate_like_mutex, (struct synch_test_common *)info, false);
	wait_all_thread((struct synch_test_common *)info);

	T_ASSERT(info->value == NUM_THREADS, "value protected by gate");
	T_ASSERT(info->handoff_failure == 1, "handoff failures");

	primitive_gate_destroy(info);
}

static void
test_gate_steal(struct info_sleep_inheritor_test *info, int prim_type)
{
	info->prim_type = prim_type;

	primitive_gate_init(info);

	info->synch = 0;
	info->synch_value = NUM_THREADS;
	info->thread_inheritor = NULL;
	info->steal_pri = 0;

	start_threads((thread_continue_t)thread_gate_aggressive, (struct synch_test_common *)info, FALSE);
	wait_all_thread((struct synch_test_common *)info);

	primitive_gate_destroy(info);
}

kern_return_t
ts_kernel_gate_test(void)
{
	struct info_sleep_inheritor_test info = {};

	T_LOG("Testing gate primitive");

	init_synch_test_common((struct synch_test_common *)&info, NUM_THREADS);

	lck_attr_t* lck_attr = lck_attr_alloc_init();
	lck_grp_attr_t* lck_grp_attr = lck_grp_attr_alloc_init();
	lck_grp_t* lck_grp = lck_grp_alloc_init("test gate", lck_grp_attr);

	lck_mtx_init(&info.mtx_lock, lck_grp, lck_attr);
	lck_rw_init(&info.rw_lock, lck_grp, lck_attr);

	/*
	 * Testing the priority inherited by the keeper
	 * lck_mtx_gate_try_close, lck_mtx_gate_open, lck_mtx_gate_wait
	 */
	T_LOG("Testing gate push, lck");
	test_gate_push(&info, MTX_LOCK);

	T_LOG("Testing gate push, rw");
	test_gate_push(&info, RW_LOCK);

	/*
	 * Testing the handoff
	 * lck_mtx_gate_wait, lck_mtx_gate_handoff
	 */
	T_LOG("Testing gate handoff, lck");
	test_gate_handoff(&info, MTX_LOCK);

	T_LOG("Testing gate handoff, rw");
	test_gate_handoff(&info, RW_LOCK);

	/*
	 * Testing the steal
	 * lck_mtx_gate_close, lck_mtx_gate_wait, lck_mtx_gate_steal, lck_mtx_gate_handoff
	 */
	T_LOG("Testing gate steal, lck");
	test_gate_steal(&info, MTX_LOCK);

	T_LOG("Testing gate steal, rw");
	test_gate_steal(&info, RW_LOCK);

	destroy_synch_test_common((struct synch_test_common *)&info);

	lck_attr_free(lck_attr);
	lck_grp_attr_free(lck_grp_attr);
	lck_mtx_destroy(&info.mtx_lock, lck_grp);
	lck_grp_free(lck_grp);

	return KERN_SUCCESS;
}

#define NUM_THREAD_CHAIN 6

struct turnstile_chain_test {
	struct synch_test_common head;
	lck_mtx_t mtx_lock;
	int synch_value;
	int synch;
	int synch2;
	gate_t gates[NUM_THREAD_CHAIN];
};

static void
thread_sleep_gate_chain_work(
	void *args,
	__unused wait_result_t wr)
{
	struct turnstile_chain_test *info = (struct turnstile_chain_test*) args;
	thread_t self = current_thread();
	uint my_pri = self->sched_pri;
	uint max_pri;
	uint i;
	thread_t inheritor = NULL, woken_up;
	event_t wait_event, wake_event;
	kern_return_t ret;

	T_LOG("Started thread pri %d %p", my_pri, self);

	/*
	 * Need to use the threads ids, wait for all of them to be populated
	 */

	while (os_atomic_load(&info->head.threads[info->head.nthreads - 1], acquire) == NULL) {
		IOSleep(10);
	}

	max_pri = get_max_pri((struct synch_test_common *) info);

	for (i = 0; i < info->head.nthreads; i = i + 2) {
		// even threads will close a gate
		if (info->head.threads[i] == self) {
			lck_mtx_lock(&info->mtx_lock);
			lck_mtx_gate_close(&info->mtx_lock, &info->gates[i]);
			lck_mtx_unlock(&info->mtx_lock);
			break;
		}
	}

	wake_threads(&info->synch2);
	wait_threads(&info->synch2, info->synch_value);

	if (self == os_atomic_load(&info->head.threads[0], acquire)) {
		wait_threads(&info->synch, info->synch_value - 1);
		wait_for_waiters((struct synch_test_common *)info);

		T_ASSERT((uint) self->sched_pri == max_pri, "sleep_inheritor inheritor priority current is %d, should be %d", self->sched_pri, max_pri);

		lck_mtx_lock(&info->mtx_lock);
		lck_mtx_gate_open(&info->mtx_lock, &info->gates[0]);
		lck_mtx_unlock(&info->mtx_lock);
	} else {
		wait_event = NULL;
		wake_event = NULL;
		for (i = 0; i < info->head.nthreads; i++) {
			if (info->head.threads[i] == self) {
				inheritor = info->head.threads[i - 1];
				wait_event = (event_t) &info->head.threads[i - 1];
				wake_event = (event_t) &info->head.threads[i];
				break;
			}
		}
		assert(wait_event != NULL);

		lck_mtx_lock(&info->mtx_lock);
		wake_threads(&info->synch);

		if (i % 2 != 0) {
			lck_mtx_gate_wait(&info->mtx_lock, &info->gates[i - 1], LCK_SLEEP_UNLOCK, THREAD_UNINT | THREAD_WAIT_NOREPORT_USER, TIMEOUT_WAIT_FOREVER);
			T_ASSERT((uint) self->sched_pri == max_pri, "sleep_inheritor inheritor priority current is %d, should be %d", self->sched_pri, max_pri);

			ret = wakeup_one_with_inheritor(wake_event, THREAD_AWAKENED, LCK_WAKE_DO_NOT_TRANSFER_PUSH, &woken_up);
			if (ret == KERN_SUCCESS) {
				T_ASSERT(i != (info->head.nthreads - 1), "thread id");
				T_ASSERT(woken_up == info->head.threads[i + 1], "wakeup_one_with_inheritor woke next");
			} else {
				T_ASSERT(i == (info->head.nthreads - 1), "thread id");
			}

			// i am still the inheritor, wake all to drop inheritership
			ret = wakeup_all_with_inheritor(wake_event, LCK_WAKE_DEFAULT);
			T_ASSERT(ret == KERN_NOT_WAITING, "waiters on event");
		} else {
			// I previously closed a gate
			lck_mtx_sleep_with_inheritor(&info->mtx_lock, LCK_SLEEP_UNLOCK, wait_event, inheritor, THREAD_UNINT | THREAD_WAIT_NOREPORT_USER, TIMEOUT_WAIT_FOREVER);
			T_ASSERT((uint) self->sched_pri == max_pri, "sleep_inheritor inheritor priority current is %d, should be %d", self->sched_pri, max_pri);

			lck_mtx_lock(&info->mtx_lock);
			lck_mtx_gate_open(&info->mtx_lock, &info->gates[i]);
			lck_mtx_unlock(&info->mtx_lock);
		}
	}

	assert(current_thread()->kern_promotion_schedpri == 0);
	notify_waiter((struct synch_test_common *)info);

	thread_terminate_self();
}

static void
thread_gate_chain_work(
	void *args,
	__unused wait_result_t wr)
{
	struct turnstile_chain_test *info = (struct turnstile_chain_test*) args;
	thread_t self = current_thread();
	uint my_pri = self->sched_pri;
	uint max_pri;
	uint i;
	T_LOG("Started thread pri %d %p", my_pri, self);


	/*
	 * Need to use the threads ids, wait for all of them to be populated
	 */
	while (os_atomic_load(&info->head.threads[info->head.nthreads - 1], acquire) == NULL) {
		IOSleep(10);
	}

	max_pri = get_max_pri((struct synch_test_common *) info);

	for (i = 0; i < info->head.nthreads; i++) {
		if (info->head.threads[i] == self) {
			lck_mtx_lock(&info->mtx_lock);
			lck_mtx_gate_close(&info->mtx_lock, &info->gates[i]);
			lck_mtx_unlock(&info->mtx_lock);
			break;
		}
	}
	assert(i != info->head.nthreads);

	wake_threads(&info->synch2);
	wait_threads(&info->synch2, info->synch_value);

	if (self == os_atomic_load(&info->head.threads[0], acquire)) {
		wait_threads(&info->synch, info->synch_value - 1);

		wait_for_waiters((struct synch_test_common *)info);

		T_ASSERT((uint) self->sched_pri == max_pri, "sleep_inheritor inheritor priority current is %d, should be %d", self->sched_pri, max_pri);

		lck_mtx_lock(&info->mtx_lock);
		lck_mtx_gate_open(&info->mtx_lock, &info->gates[0]);
		lck_mtx_unlock(&info->mtx_lock);
	} else {
		lck_mtx_lock(&info->mtx_lock);
		wake_threads(&info->synch);
		lck_mtx_gate_wait(&info->mtx_lock, &info->gates[i - 1], LCK_SLEEP_UNLOCK, THREAD_UNINT | THREAD_WAIT_NOREPORT_USER, TIMEOUT_WAIT_FOREVER);

		T_ASSERT((uint) self->sched_pri == max_pri, "sleep_inheritor inheritor priority current is %d, should be %d", self->sched_pri, max_pri);

		lck_mtx_lock(&info->mtx_lock);
		lck_mtx_gate_open(&info->mtx_lock, &info->gates[i]);
		lck_mtx_unlock(&info->mtx_lock);
	}

	assert(current_thread()->kern_promotion_schedpri == 0);
	notify_waiter((struct synch_test_common *)info);

	thread_terminate_self();
}

static void
thread_sleep_chain_work(
	void *args,
	__unused wait_result_t wr)
{
	struct turnstile_chain_test *info = (struct turnstile_chain_test*) args;
	thread_t self = current_thread();
	uint my_pri = self->sched_pri;
	uint max_pri;
	event_t wait_event, wake_event;
	uint i;
	thread_t inheritor = NULL, woken_up = NULL;
	kern_return_t ret;

	T_LOG("Started thread pri %d %p", my_pri, self);

	/*
	 * Need to use the threads ids, wait for all of them to be populated
	 */
	while (os_atomic_load(&info->head.threads[info->head.nthreads - 1], acquire) == NULL) {
		IOSleep(10);
	}

	max_pri = get_max_pri((struct synch_test_common *) info);

	if (self == os_atomic_load(&info->head.threads[0], acquire)) {
		wait_threads(&info->synch, info->synch_value - 1);

		wait_for_waiters((struct synch_test_common *)info);

		T_ASSERT((uint) self->sched_pri == max_pri, "sleep_inheritor inheritor priority current is %d, should be %d", self->sched_pri, max_pri);

		ret = wakeup_one_with_inheritor((event_t) &info->head.threads[0], THREAD_AWAKENED, LCK_WAKE_DO_NOT_TRANSFER_PUSH, &woken_up);
		T_ASSERT(ret == KERN_SUCCESS, "wakeup_one_with_inheritor woke next");
		T_ASSERT(woken_up == info->head.threads[1], "thread woken up");

		// i am still the inheritor, wake all to drop inheritership
		ret = wakeup_all_with_inheritor((event_t) &info->head.threads[0], LCK_WAKE_DEFAULT);
		T_ASSERT(ret == KERN_NOT_WAITING, "waiters on event");
	} else {
		wait_event = NULL;
		wake_event = NULL;
		for (i = 0; i < info->head.nthreads; i++) {
			if (info->head.threads[i] == self) {
				inheritor = info->head.threads[i - 1];
				wait_event = (event_t) &info->head.threads[i - 1];
				wake_event = (event_t) &info->head.threads[i];
				break;
			}
		}

		assert(wait_event != NULL);
		lck_mtx_lock(&info->mtx_lock);
		wake_threads(&info->synch);

		lck_mtx_sleep_with_inheritor(&info->mtx_lock, LCK_SLEEP_UNLOCK, wait_event, inheritor, THREAD_UNINT | THREAD_WAIT_NOREPORT_USER, TIMEOUT_WAIT_FOREVER);

		T_ASSERT((uint) self->sched_pri == max_pri, "sleep_inheritor inheritor priority current is %d, should be %d", self->sched_pri, max_pri);

		ret = wakeup_one_with_inheritor(wake_event, THREAD_AWAKENED, LCK_WAKE_DO_NOT_TRANSFER_PUSH, &woken_up);
		if (ret == KERN_SUCCESS) {
			T_ASSERT(i != (info->head.nthreads - 1), "thread id");
			T_ASSERT(woken_up == info->head.threads[i + 1], "wakeup_one_with_inheritor woke next");
		} else {
			T_ASSERT(i == (info->head.nthreads - 1), "thread id");
		}

		// i am still the inheritor, wake all to drop inheritership
		ret = wakeup_all_with_inheritor(wake_event, LCK_WAKE_DEFAULT);
		T_ASSERT(ret == KERN_NOT_WAITING, "waiters on event");
	}

	assert(current_thread()->kern_promotion_schedpri == 0);
	notify_waiter((struct synch_test_common *)info);

	thread_terminate_self();
}

static void
test_sleep_chain(struct turnstile_chain_test *info)
{
	info->synch = 0;
	info->synch_value = info->head.nthreads;

	start_threads((thread_continue_t)thread_sleep_chain_work, (struct synch_test_common *)info, FALSE);
	wait_all_thread((struct synch_test_common *)info);
}

static void
test_gate_chain(struct turnstile_chain_test *info)
{
	info->synch = 0;
	info->synch2 = 0;
	info->synch_value = info->head.nthreads;

	start_threads((thread_continue_t)thread_gate_chain_work, (struct synch_test_common *)info, FALSE);
	wait_all_thread((struct synch_test_common *)info);
}

static void
test_sleep_gate_chain(struct turnstile_chain_test *info)
{
	info->synch = 0;
	info->synch2 = 0;
	info->synch_value = info->head.nthreads;

	start_threads((thread_continue_t)thread_sleep_gate_chain_work, (struct synch_test_common *)info, FALSE);
	wait_all_thread((struct synch_test_common *)info);
}

kern_return_t
ts_kernel_turnstile_chain_test(void)
{
	struct turnstile_chain_test info = {};
	int i;

	init_synch_test_common((struct synch_test_common *)&info, NUM_THREAD_CHAIN);
	lck_attr_t* lck_attr = lck_attr_alloc_init();
	lck_grp_attr_t* lck_grp_attr = lck_grp_attr_alloc_init();
	lck_grp_t* lck_grp = lck_grp_alloc_init("test gate", lck_grp_attr);

	lck_mtx_init(&info.mtx_lock, lck_grp, lck_attr);
	for (i = 0; i < NUM_THREAD_CHAIN; i++) {
		lck_mtx_gate_init(&info.mtx_lock, &info.gates[i]);
	}

	T_LOG("Testing sleep chain, lck");
	test_sleep_chain(&info);

	T_LOG("Testing gate chain, lck");
	test_gate_chain(&info);

	T_LOG("Testing sleep and gate chain, lck");
	test_sleep_gate_chain(&info);

	destroy_synch_test_common((struct synch_test_common *)&info);
	for (i = 0; i < NUM_THREAD_CHAIN; i++) {
		lck_mtx_gate_destroy(&info.mtx_lock, &info.gates[i]);
	}
	lck_attr_free(lck_attr);
	lck_grp_attr_free(lck_grp_attr);
	lck_mtx_destroy(&info.mtx_lock, lck_grp);
	lck_grp_free(lck_grp);

	return KERN_SUCCESS;
}

kern_return_t
ts_kernel_timingsafe_bcmp_test(void)
{
	int i, buf_size;
	char *buf = NULL;

	// empty
	T_ASSERT(timingsafe_bcmp(NULL, NULL, 0) == 0, NULL);
	T_ASSERT(timingsafe_bcmp("foo", "foo", 0) == 0, NULL);
	T_ASSERT(timingsafe_bcmp("foo", "bar", 0) == 0, NULL);

	// equal
	T_ASSERT(timingsafe_bcmp("foo", "foo", strlen("foo")) == 0, NULL);

	// unequal
	T_ASSERT(timingsafe_bcmp("foo", "bar", strlen("foo")) == 1, NULL);
	T_ASSERT(timingsafe_bcmp("foo", "goo", strlen("foo")) == 1, NULL);
	T_ASSERT(timingsafe_bcmp("foo", "fpo", strlen("foo")) == 1, NULL);
	T_ASSERT(timingsafe_bcmp("foo", "fop", strlen("foo")) == 1, NULL);

	// all possible bitwise differences
	for (i = 1; i < 256; i += 1) {
		unsigned char a = 0;
		unsigned char b = (unsigned char)i;

		T_ASSERT(timingsafe_bcmp(&a, &b, sizeof(a)) == 1, NULL);
	}

	// large
	buf_size = 1024 * 16;
	buf = kalloc(buf_size);
	T_EXPECT_NOTNULL(buf, "kalloc of buf");

	read_random(buf, buf_size);
	T_ASSERT(timingsafe_bcmp(buf, buf, buf_size) == 0, NULL);
	T_ASSERT(timingsafe_bcmp(buf, buf + 1, buf_size - 1) == 1, NULL);
	T_ASSERT(timingsafe_bcmp(buf, buf + 128, 128) == 1, NULL);

	memcpy(buf + 128, buf, 128);
	T_ASSERT(timingsafe_bcmp(buf, buf + 128, 128) == 0, NULL);

	kfree(buf, buf_size);

	return KERN_SUCCESS;
}

kern_return_t
kprintf_hhx_test(void)
{
	printf("POST hhx test %hx%hx%hx%hx %hhx%hhx%hhx%hhx - %llx",
	    (unsigned short)0xfeed, (unsigned short)0xface,
	    (unsigned short)0xabad, (unsigned short)0xcafe,
	    (unsigned char)'h', (unsigned char)'h', (unsigned char)'x',
	    (unsigned char)'!',
	    0xfeedfaceULL);
	return KERN_SUCCESS;
}
