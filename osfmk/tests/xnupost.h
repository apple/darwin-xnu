/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

#ifndef _TESTS_XNUPOST_H
#define _TESTS_XNUPOST_H

#ifndef CONFIG_XNUPOST
#error "Testing is not enabled if CONFIG_XNUPOST is not enabled"
#endif

#include <kern/kern_types.h>
#include <kern/assert.h>
#include <tests/ktest.h>

#define XT_CONFIG_RUN 0x0
#define XT_CONFIG_IGNORE 0x1
#define XT_CONFIG_EXPECT_PANIC 0x2

#define XTCTL_RUN_TESTS  1
#define XTCTL_RESET_TESTDATA 2

typedef enum { XT_ACTION_NONE = 0, XT_ACTION_SKIPPED, XT_ACTION_PASSED, XT_ACTION_FAILED } xnupost_test_action_t;

typedef kern_return_t (*test_function)(void);
struct xnupost_test {
	uint16_t xt_config;
	uint16_t xt_test_num;
	kern_return_t xt_retval;
	kern_return_t xt_expected_retval;
	uint64_t xt_begin_time;
	uint64_t xt_end_time;
	xnupost_test_action_t xt_test_actions;
	test_function xt_func;
	const char * xt_name;
};

typedef kern_return_t xt_panic_return_t;
#define XT_PANIC_UNRELATED  0x8  /* not related. continue panic */
#define XT_RET_W_FAIL       0x9  /* report FAILURE and return from panic */
#define XT_RET_W_SUCCESS    0xA  /* report SUCCESS and return from panic */
#define XT_PANIC_W_FAIL     0xB  /* report FAILURE and continue to panic */
#define XT_PANIC_W_SUCCESS  0xC  /* report SUCCESS and continue to panic */

typedef xt_panic_return_t (*xt_panic_widget_func)(const char * panicstr, void * context, void ** outval);
struct xnupost_panic_widget {
	void * xtp_context_p;
	void ** xtp_outval_p;
	const char * xtp_func_name;
	xt_panic_widget_func xtp_func;
};

/* for internal use only. Use T_REGISTER_* macros */
extern xt_panic_return_t _xt_generic_assert_check(const char * s, void * str_to_match, void ** outval);
kern_return_t xnupost_register_panic_widget(xt_panic_widget_func funcp, const char * funcname, void * context, void ** outval);

#define T_REGISTER_PANIC_WIDGET(func, ctx, outval) xnupost_register_panic_widget((func), #func, (ctx), (outval))
#define T_REGISTER_ASSERT_CHECK(assert_str, retval) \
	T_REGISTER_PANIC_WIDGET(_xt_generic_assert_check, (void *)__DECONST(char *, assert_str), retval)

typedef struct xnupost_test xnupost_test_data_t;
typedef struct xnupost_test * xnupost_test_t;

extern struct xnupost_test kernel_post_tests[];
extern uint32_t kernel_post_tests_count;
extern uint32_t total_post_tests_count;

#define XNUPOST_TEST_CONFIG_BASIC(func)                   \
	{                                                 \
	        .xt_config = XT_CONFIG_RUN,               \
	        .xt_test_num = 0,                         \
	        .xt_retval = -1,                          \
	        .xt_expected_retval = T_STATE_PASS,       \
	        .xt_begin_time = 0,                       \
	        .xt_end_time = 0,                         \
	        .xt_test_actions = 0,                     \
	        .xt_func = (func),                        \
	        .xt_name = "xnu."#func                    \
	}

#define XNUPOST_TEST_CONFIG_TEST_PANIC(func)                       \
	{                                                          \
	        .xt_config = XT_CONFIG_EXPECT_PANIC,               \
	        .xt_test_num = 0,                                  \
	        .xt_retval = -1,                                   \
	        .xt_expected_retval = T_STATE_PASS,                \
	        .xt_begin_time = 0,                                \
	        .xt_end_time = 0,                                  \
	        .xt_test_actions = 0,                              \
	        .xt_func = (func),                                 \
	        .xt_name = "xnu."#func                             \
	}

void xnupost_init(void);
/*
 * Parse boot-args specific to POST testing and setup enabled/disabled settings
 * returns: KERN_SUCCESS - if testing is enabled.
 */
kern_return_t xnupost_parse_config(void);
kern_return_t xnupost_run_tests(xnupost_test_t test_list, uint32_t test_count);
kern_return_t xnupost_list_tests(xnupost_test_t test_list, uint32_t test_count);
kern_return_t xnupost_reset_tests(xnupost_test_t test_list, uint32_t test_count);

int xnupost_export_testdata(void * outp, uint32_t size, uint32_t * lenp);
uint32_t xnupost_get_estimated_testdata_size(void);

kern_return_t kernel_do_post(void);
kern_return_t xnupost_process_kdb_stop(const char * panic_s);
int xnupost_reset_all_tests(void);

kern_return_t kernel_list_tests(void);
int bsd_do_post(void);
int bsd_list_tests(void);

#endif /* _TESTS_XNUPOST_H */
