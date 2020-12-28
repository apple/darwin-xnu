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

#include <tests/ktest.h>
#include <tests/ktest_internal.h>
#include <mach/mach_time.h>
#include <kern/misc_protos.h>

void
ktest_start(void)
{
	ktest_emit_start();
}

void
ktest_finish(void)
{
	ktest_emit_finish();
}

void
ktest_testbegin(const char * test_name)
{
	ktest_current_time = mach_absolute_time();
	ktest_test_name = test_name;
	ktest_emit_testbegin(test_name);
}

void
ktest_testend()
{
	ktest_current_time = mach_absolute_time();
	ktest_emit_testend();
	ktest_test_index++;
}

void
ktest_testskip(const char * msg, ...)
{
	va_list args;

	ktest_current_time = mach_absolute_time();

	va_start(args, msg);
	ktest_emit_testskip(msg, args);
	va_end(args);
}

void
ktest_log(const char * msg, ...)
{
	va_list args;

	ktest_current_time = mach_absolute_time();

	va_start(args, msg);
	ktest_emit_log(msg, args);
	va_end(args);
}

void
ktest_perf(const char * metric, const char * unit, double value, const char * desc)
{
	ktest_current_time = mach_absolute_time();
	ktest_emit_perfdata(metric, unit, value, desc);
}

void
ktest_testcase(int success)
{
	ktest_current_time = mach_absolute_time();

	if (success && !ktest_expectfail) {
		/* PASS */
		ktest_passcount++;
		ktest_testcase_result = T_RESULT_PASS;
	} else if (!success && !ktest_expectfail) {
		/* FAIL */
		ktest_failcount++;
		ktest_testcase_result = T_RESULT_FAIL;
	} else if (success && ktest_expectfail) {
		/* UXPASS */
		ktest_xpasscount++;
		ktest_testcase_result = T_RESULT_UXPASS;
	} else if (!success && ktest_expectfail) {
		/* XFAIL */
		ktest_xfailcount++;
		ktest_testcase_result = T_RESULT_XFAIL;
	}

	ktest_update_test_result_state();
	if (ktest_quiet == 0 ||
	    ktest_testcase_result == T_RESULT_FAIL ||
	    ktest_testcase_result == T_RESULT_UXPASS) {
		ktest_emit_testcase();
	}
	ktest_expression_index++;

	ktest_quiet = 0;
	ktest_expectfail = 0;
	ktest_output_buf[0] = '\0';
	ktest_current_msg[0] = '\0';
	ktest_current_expr[0] = '\0';
	for (int i = 0; i < KTEST_MAXVARS; i++) {
		ktest_current_var_names[i][0] = '\0';
		ktest_current_var_values[i][0] = '\0';
	}
	ktest_current_var_index = 0;
}

void
ktest_update_test_result_state(void)
{
	ktest_test_result = ktest_test_result_statetab[ktest_test_result]
	    [ktest_testcase_result]
	    [ktest_testcase_mode];
}

void
ktest_assertion_check(void)
{
	if (ktest_testcase_result == T_RESULT_FAIL || ktest_testcase_result == T_RESULT_UXPASS) {
		ktest_testend();
		panic("XNUPOST: Assertion failed : %s : at %s:%d", ktest_test_name, ktest_current_file, ktest_current_line);
	}
}
