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

#ifndef _TESTS_KTEST_INTERNAL_H
#define _TESTS_KTEST_INTERNAL_H

#include <tests/ktest.h>
#include <stdint.h>

#define KTEST_VERSION 1
#define KTEST_VERSION_STR T_TOSTRING(KTEST_VERSION)

#define KTEST_MAXLEN 1024
#define KTEST_MAXOUTLEN 4096
#define KTEST_MAXVARS 3

#define KTEST_NUM_TESTCASE_MODES 2
#define KTEST_NUM_TESTCASE_STATES 4
#define KTEST_NUM_TEST_STATES 4

extern unsigned int ktest_current_line;
extern const char * ktest_current_file;
extern const char * ktest_current_func;
extern uint64_t ktest_current_time;

extern const char * ktest_test_name;

extern char ktest_current_msg[KTEST_MAXLEN];
extern char ktest_current_expr[KTEST_MAXOUTLEN];
extern char ktest_current_var_names[KTEST_MAXVARS][KTEST_MAXLEN];
extern char ktest_current_var_values[KTEST_MAXVARS][KTEST_MAXLEN];
extern unsigned int ktest_expression_index;
extern unsigned int ktest_current_var_index;
extern unsigned int ktest_test_index;
extern unsigned int ktest_passcount;
extern unsigned int ktest_failcount;
extern unsigned int ktest_xpasscount;
extern unsigned int ktest_xfailcount;
extern int ktest_expectfail;

extern int ktest_testcase_result;
extern int ktest_test_result;
extern int ktest_testcase_mode;

extern ktest_temp ktest_temp1, ktest_temp2, ktest_temp3;

extern char ktest_output_buf[KTEST_MAXLEN];

extern int ktest_test_result_statetab[KTEST_NUM_TEST_STATES]
				     [KTEST_NUM_TESTCASE_STATES]
				     [KTEST_NUM_TESTCASE_MODES];

extern const char * ktest_testcase_result_tokens[KTEST_NUM_TESTCASE_MODES]
						[KTEST_NUM_TESTCASE_STATES];


void ktest_emit_start(void);
void ktest_emit_finish(void);
void ktest_emit_testbegin(const char * test_name);
void ktest_emit_testskip(const char * skip_msg, va_list args);
void ktest_emit_testend(void);
void ktest_emit_log(const char * log_msg, va_list args);
void ktest_emit_perfdata(const char * metric, const char * unit, double value, const char * desc);
void ktest_emit_testcase(void);

#endif /* _TESTS_KTEST_INTERNAL_H */

