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

#ifndef _TESTS_KTEST_H
#define _TESTS_KTEST_H

/* Symbol name prefix */
#define T_SYM(sym) ktest_ ## sym

#include <stdarg.h>

extern unsigned int T_SYM(current_line);
extern const char * T_SYM(current_file);
extern const char * T_SYM(current_func);
extern int T_SYM(testcase_mode);
extern int T_SYM(testcase_result);
extern int T_SYM(test_result);
extern int T_SYM(quiet);

void T_SYM(start)(void);
void T_SYM(finish)(void);
void T_SYM(testbegin)(const char * test_name);
void T_SYM(testend)(void);
void T_SYM(testskip)(const char * msg, ...);
void T_SYM(testcase)(int expr);
void T_SYM(log)(const char * msg, ...);
void T_SYM(perf)(const char * metric, const char * unit, double value, const char * desc);
void T_SYM(update_test_result_state)(void);
void T_SYM(assertion_check)(void);

void T_SYM(set_current_msg)(const char * msg, ...);
void T_SYM(set_current_expr)(const char * expr_fmt, ...);
void T_SYM(set_current_var)(const char * name, const char * value_fmt, ...);

typedef union {
    char _char;
    unsigned char _uchar;

    short _short;
    unsigned short _ushort;

    int _int;
    unsigned int _uint;

    long _long;
    unsigned long _ulong;

    long long _llong;
    unsigned long long _ullong;

    float _float;

    double _double;

    long double _ldouble;

    void* _ptr;
} T_SYM(temp);

extern T_SYM(temp) T_SYM(temp1), T_SYM(temp2), T_SYM(temp3);

#define T_SUCCESS 1
#define T_FAILURE 0

/* Testcase modes */
#define T_MAIN 0
#define T_SETUP 1

/* Testcase result states */
#define T_RESULT_PASS 0
#define T_RESULT_FAIL 1
#define T_RESULT_UXPASS 2
#define T_RESULT_XFAIL 3

/* Test result states */
#define T_STATE_UNRESOLVED 0
#define T_STATE_PASS 1
#define T_STATE_FAIL 2
#define T_STATE_SETUPFAIL 3

/*
 * Helpers
 */

#define T_TOSTRING_HELPER(x) #x
#define T_TOSTRING(x) T_TOSTRING_HELPER(x)

#define T_SAVEINFO do {\
	T_SYM(current_line) = __LINE__;\
	T_SYM(current_func) = (const char *)__func__;\
	T_SYM(current_file) = (const char *)__FILE__;\
} while(0)

#define T_SET_AUX_VARS do {\
	/* Only used in userspace lib for now */\
} while(0)

#define T_ASSERTION_CHECK do {\
	T_SYM(assertion_check)();\
} while(0)

#define T_EXPECT_BLOCK2(type, fmt, cmp, lhs, rhs, msg, ...) do {\
	T_SAVEINFO;\
	T_SYM(temp1).type = (lhs);\
	T_SYM(temp2).type = (rhs);\
	T_SYM(set_current_expr)(T_TOSTRING(lhs) " "\
				T_TOSTRING(cmp) " "\
				T_TOSTRING(rhs));\
	T_SYM(set_current_var)(T_TOSTRING(lhs), fmt, T_SYM(temp1).type);\
	T_SYM(set_current_var)(T_TOSTRING(rhs), fmt, T_SYM(temp2).type);\
	T_SET_AUX_VARS;\
	T_SYM(set_current_msg)(msg, ## __VA_ARGS__);\
	T_SYM(testcase)(T_SYM(temp1).type cmp T_SYM(temp2).type);\
} while(0)

#define T_ASSERT_BLOCK2(type, fmt, cmp, lhs, rhs, msg, ...) do {\
	T_EXPECT_BLOCK2(type, fmt, cmp, lhs, rhs, msg, ## __VA_ARGS__);\
	T_ASSERTION_CHECK;\
} while(0)

/*
 * Core functions
 */

/* Denotes start of testing. All prior output is ignored. */
#define T_START do {\
	T_SAVEINFO;\
	T_SYM(start)();\
} while(0)

/* Denotes end of testing. All subsequent output is ignored. */
#define T_FINISH do {\
	T_SAVEINFO;\
	T_SYM(finish)();\
} while(0)

/* Denotes beginning of a test. */
#define T_BEGIN(name) do {\
	T_SAVEINFO;\
	T_SYM(testbegin)(name);\
} while(0)

/* Denotes end of current test. */
#define T_END do {\
	T_SAVEINFO;\
	T_SYM(testend)();\
} while(0)

/* Denotes beginning of a setup section of the current test. */
#define T_SETUPBEGIN do {\
	T_SYM(testcase_mode) = T_SETUP;\
} while(0)

/* Denotes end of the current setup section of the current test. */
#define T_SETUPEND do {\
	T_SYM(testcase_mode) = T_MAIN;\
} while(0)

/* Denotes end of current test because test was skipped. */
#define T_SKIP(msg, ...) do {\
	T_SAVEINFO;\
	T_SYM(testskip)(msg, ## __VA_ARGS__);\
} while(0)

/* Returns result of latest testrun. */
#define T_TESTRESULT (T_SYM(test_result))

/* Return result of latest testcase. */
#define T_TESTCASERESULT (T_SYM(testcase_result))

/* Flags the next testcase as expected failure. */
#define T_EXPECTFAIL do {\
	T_SYM(expectfail) = 1;\
} while(0)

/* Only emit output for next testcase if it is a FAIL or UXPASS. */
#define T_QUIET do {\
	T_SYM(quiet) = 1;\
} while(0)

/* Logs a message. */
#define T_LOG(msg, ...) do {\
	T_SAVEINFO;\
	T_SYM(log)(msg, ## __VA_ARGS__);\
} while(0)

/* Explicit pass. */
#define T_PASS(msg, ...) do {\
	T_SAVEINFO;\
	T_SYM(set_current_msg)(msg, ## __VA_ARGS__);\
	T_SYM(testcase)(T_SUCCESS);\
} while(0)

/* Explicit fail. */
#define T_FAIL(msg, ...) do {\
	T_SAVEINFO;\
	T_SYM(set_current_msg)(msg, ## __VA_ARGS__);\
	T_SYM(testcase)(T_FAILURE);\
} while(0)

/* Explicit assert fail. */
#define T_ASSERT_FAIL(msg, ...) do {\
	T_SAVEINFO;\
	T_SET_AUX_VARS;\
	T_SYM(set_current_msg)(msg, ## __VA_ARGS__);\
	T_SYM(testcase)(T_FAILURE);\
	T_SYM(assertion_fail)();\
} while(0)

/* Generic expect. */
#define T_EXPECT(expr, msg, ...) do {\
	T_SAVEINFO;\
	T_SYM(temp1)._int = (int)(!!(expr));\
	T_SYM(set_current_expr)(T_TOSTRING(expr));\
	T_SET_AUX_VARS;\
	T_SYM(set_current_msg)(msg, ## __VA_ARGS__);\
	T_SYM(testcase)(T_SYM(temp1)._int);\
} while(0)

/* Generic assert. */
#define T_ASSERT(expr, msg, ...) do {\
	T_EXPECT(expr, msg, ## __VA_ARGS__);\
	T_ASSERTION_CHECK;\
} while(0)

/*
 * Convenience functions
 */

/* null */

#define T_EXPECT_NOTNULL(expr, msg, ...) do {\
	T_SAVEINFO;\
	T_SYM(temp1)._int = (int)(!!(expr));\
	T_SYM(set_current_expr)(T_TOSTRING(expr) " != NULL");\
	T_SYM(set_current_var)(T_TOSTRING(expr),\
			       "%s",\
			       T_SYM(temp1)._int ? "<NOTNULL>" : "NULL");\
	T_SET_AUX_VARS;\
	T_SYM(set_current_msg)(msg, ## __VA_ARGS__);\
	T_SYM(testcase)(T_SYM(temp1)._int);\
} while(0)

#define T_EXPECT_NULL(expr, msg, ...) do {\
	T_SAVEINFO;\
	T_SYM(temp1)._int = (int)(!(expr));\
	T_SYM(set_current_expr)(T_TOSTRING(expr) " == NULL");\
	T_SYM(set_current_var)(T_TOSTRING(expr),\
			       "%s",\
			       T_SYM(temp1)._int ? "NULL" : "<NOTNULL>");\
	T_SET_AUX_VARS;\
	T_SYM(set_current_msg)(msg, ## __VA_ARGS__);\
	T_SYM(testcase)(T_SYM(temp1)._int);\
} while(0)

#define T_ASSERT_NOTNULL(expr, msg, ...) do {\
	T_EXPECT_NOTNULL(expr, msg, ## __VA_ARGS__);\
	T_ASSERTION_CHECK;\
} while(0)

#define T_ASSERT_NULL(expr, msg, ...) do {\
	T_EXPECT_NULL(expr, msg, ## __VA_ARGS__);\
	T_ASSERTION_CHECK;\
} while(0)

/* string */

// TODO: check/truncate inputs
#define T_EXPECT_EQ_STR(lhs, rhs, msg, ...) do {\
	T_SAVEINFO;\
	T_SYM(temp1)._ptr = (lhs);\
	T_SYM(temp2)._ptr = (rhs);\
	T_SYM(set_current_expr)(T_TOSTRING(lhs) " == " T_TOSTRING(rhs));\
	T_SYM(set_current_var)(T_TOSTRING(lhs), "%s", T_SYM(temp1)._ptr);\
	T_SYM(set_current_var)(T_TOSTRING(rhs), "%s", T_SYM(temp2)._ptr);\
	T_SET_AUX_VARS;\
	T_SYM(set_current_msg)(msg, ## __VA_ARGS__);\
	T_SYM(testcase)(strcmp(T_SYM(temp1)._ptr, T_SYM(temp2)._ptr) == 0);\
} while(0)

#define T_EXPECT_NE_STR(lhs, rhs, msg, ...) do {\
	T_SAVEINFO;\
	T_SYM(temp1)._ptr = (lhs);\
	T_SYM(temp2)._ptr = (rhs);\
	T_SYM(set_current_expr)(T_TOSTRING(lhs) " == " T_TOSTRING(rhs));\
	T_SYM(set_current_var)(T_TOSTRING(lhs), "%s", T_SYM(temp1)._ptr);\
	T_SYM(set_current_var)(T_TOSTRING(rhs), "%s", T_SYM(temp2)._ptr);\
	T_SET_AUX_VARS;\
	T_SYM(set_current_msg)(msg, ## __VA_ARGS__);\
	T_SYM(testcase)(strcmp(T_SYM(temp1)._ptr, T_SYM(temp2)._ptr) != 0);\
} while(0)

#define T_ASSERT_EQ_STR(lhs, rhs, msg, ...) do {\
	T_EXPECT_EQ_STR(lhs, rhs, msg, # __VA_ARGS__);\
	T_ASSERTION_CHECK;\
} while(0)

#define T_ASSERT_NE_STR(lhs, rhs, msg, ...) do {\
	T_EXPECT_NE_STR(lhs, rhs, msg, # __VA_ARGS__);\
	T_ASSERTION_CHECK;\
} while(0)

/* char */

#define T_EXPECT_EQ_CHAR(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_char, "%c", ==, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_NE_CHAR(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_char, "%c", !=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_LT_CHAR(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_char, "%c", <, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_GT_CHAR(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_char, "%c", >, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_LE_CHAR(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_char, "%c", <=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_GE_CHAR(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_char, "%c", >=, lhs, rhs, msg, ## __VA_ARGS__)

#define T_ASSERT_EQ_CHAR(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_char, "%c", ==, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_NE_CHAR(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_char, "%c", !=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_LT_CHAR(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_char, "%c", <, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_GT_CHAR(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_char, "%c", >, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_LE_CHAR(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_char, "%c", <=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_GE_CHAR(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_char, "%c", >=, lhs, rhs, msg, ## __VA_ARGS__)

/* unsigned char */

#define T_EXPECT_EQ_UCHAR(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_uchar, "%c", ==, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_NE_UCHAR(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_uchar, "%c", !=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_LT_UCHAR(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_uchar, "%c", <, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_GT_UCHAR(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_uchar, "%c", >, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_LE_UCHAR(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_uchar, "%c", <=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_GE_UCHAR(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_uchar, "%c", >=, lhs, rhs, msg, ## __VA_ARGS__)

#define T_ASSERT_EQ_UCHAR(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_uchar, "%c", ==, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_NE_UCHAR(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_uchar, "%c", !=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_LT_UCHAR(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_uchar, "%c", <, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_GT_UCHAR(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_uchar, "%c", >, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_LE_UCHAR(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_uchar, "%c", <=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_GE_UCHAR(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_uchar, "%c", >=, lhs, rhs, msg, ## __VA_ARGS__)

/* short */

#define T_EXPECT_EQ_SHORT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_short, "%hi", ==, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_NE_SHORT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_short, "%hi", !=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_LT_SHORT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_short, "%hi", <, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_GT_SHORT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_short, "%hi", >, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_LE_SHORT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_short, "%hi", <=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_GE_SHORT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_short, "%hi", >=, lhs, rhs, msg, ## __VA_ARGS__)

#define T_ASSERT_EQ_SHORT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_short, "%hi", ==, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_NE_SHORT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_short, "%hi", !=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_LT_SHORT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_short, "%hi", <, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_GT_SHORT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_short, "%hi", >, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_LE_SHORT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_short, "%hi", <=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_GE_SHORT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_short, "%hi", >=, lhs, rhs, msg, ## __VA_ARGS__)

/* unsigned short */

#define T_EXPECT_EQ_USHORT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ushort, "%hu", ==, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_NE_USHORT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ushort, "%hu", !=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_LT_USHORT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ushort, "%hu", <, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_GT_USHORT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ushort, "%hu", >, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_LE_USHORT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ushort, "%hu", <=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_GE_USHORT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ushort, "%hu", >=, lhs, rhs, msg, ## __VA_ARGS__)

#define T_ASSERT_EQ_USHORT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ushort, "%hu", ==, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_NE_USHORT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ushort, "%hu", !=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_LT_USHORT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ushort, "%hu", <, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_GT_USHORT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ushort, "%hu", >, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_LE_USHORT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ushort, "%hu", <=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_GE_USHORT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ushort, "%hu", >=, lhs, rhs, msg, ## __VA_ARGS__)

/* int */

#define T_EXPECT_EQ_INT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_int, "%d", ==, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_NE_INT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_int, "%d", !=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_LT_INT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_int, "%d", <, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_GT_INT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_int, "%d", >, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_LE_INT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_int, "%d", <=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_GE_INT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_int, "%d", >=, lhs, rhs, msg, ## __VA_ARGS__)

#define T_ASSERT_EQ_INT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_int, "%d", ==, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_NE_INT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_int, "%d", !=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_LT_INT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_int, "%d", <, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_GT_INT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_int, "%d", >, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_LE_INT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_int, "%d", <=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_GE_INT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_int, "%d", >=, lhs, rhs, msg, ## __VA_ARGS__)

/* unsigned int */

#define T_EXPECT_EQ_UINT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_uint, "%u", ==, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_NE_UINT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_uint, "%u", !=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_LT_UINT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_uint, "%u", <, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_GT_UINT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_uint, "%u", >, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_LE_UINT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_uint, "%u", <=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_GE_UINT(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_uint, "%u", >=, lhs, rhs, msg, ## __VA_ARGS__)

#define T_ASSERT_EQ_UINT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_uint, "%u", ==, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_NE_UINT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_uint, "%u", !=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_LT_UINT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_uint, "%u", <, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_GT_UINT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_uint, "%u", >, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_LE_UINT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_uint, "%u", <=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_GE_UINT(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_uint, "%u", >=, lhs, rhs, msg, ## __VA_ARGS__)

/* long */

#define T_EXPECT_EQ_LONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_long, "%li", ==, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_NE_LONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_long, "%li", !=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_LT_LONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_long, "%li", <, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_GT_LONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_long, "%li", >, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_LE_LONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_long, "%li", <=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_GE_LONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_long, "%li", >=, lhs, rhs, msg, ## __VA_ARGS__)

#define T_ASSERT_EQ_LONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_long, "%li", ==, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_NE_LONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_long, "%li", !=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_LT_LONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_long, "%li", <, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_GT_LONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_long, "%li", >, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_LE_LONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_long, "%li", <=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_GE_LONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_long, "%li", >=, lhs, rhs, msg, ## __VA_ARGS__)

/* unsigned long */

#define T_EXPECT_EQ_ULONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ulong, "%lu", ==, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_NE_ULONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ulong, "%lu", !=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_LT_ULONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ulong, "%lu", <, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_GT_ULONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ulong, "%lu", >, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_LE_ULONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ulong, "%lu", <=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_GE_ULONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ulong, "%lu", >=, lhs, rhs, msg, ## __VA_ARGS__)

#define T_ASSERT_EQ_ULONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ulong, "%lu", ==, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_NE_ULONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ulong, "%lu", !=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_LT_ULONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ulong, "%lu", <, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_GT_ULONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ulong, "%lu", >, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_LE_ULONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ulong, "%lu", <=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_GE_ULONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ulong, "%lu", >=, lhs, rhs, msg, ## __VA_ARGS__)

/* long long */

#define T_EXPECT_EQ_LLONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_llong, "%lli", ==, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_NE_LLONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_llong, "%lli", !=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_LT_LLONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_llong, "%lli", <, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_GT_LLONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_llong, "%lli", >, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_LE_LLONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_llong, "%lli", <=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_GE_LLONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_llong, "%lli", >=, lhs, rhs, msg, ## __VA_ARGS__)

#define T_ASSERT_EQ_LLONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_llong, "%lli", ==, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_NE_LLONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_llong, "%lli", !=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_LT_LLONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_llong, "%lli", <, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_GT_LLONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_llong, "%lli", >, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_LE_LLONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_llong, "%lli", <=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_GE_LLONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_llong, "%lli", >=, lhs, rhs, msg, ## __VA_ARGS__)

/* unsigned long long */

#define T_EXPECT_EQ_ULLONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ullong, "%llu", ==, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_NE_ULLONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ullong, "%llu", !=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_LT_ULLONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ullong, "%llu", <, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_GT_ULLONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ullong, "%llu", >, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_LE_ULLONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ullong, "%llu", <=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_GE_ULLONG(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ullong, "%llu", >=, lhs, rhs, msg, ## __VA_ARGS__)

#define T_ASSERT_EQ_ULLONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ullong, "%llu", ==, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_NE_ULLONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ullong, "%llu", !=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_LT_ULLONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ullong, "%llu", <, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_GT_ULLONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ullong, "%llu", >, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_LE_ULLONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ullong, "%llu", <=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_GE_ULLONG(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ullong, "%llu", >=, lhs, rhs, msg, ## __VA_ARGS__)

/* pointer */

#define T_EXPECT_EQ_PTR(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ptr, "%p", ==, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_NE_PTR(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ptr, "%p", !=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_LT_PTR(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ptr, "%p", <, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_GT_PTR(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ptr, "%p", >, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_LE_PTR(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ptr, "%p", <=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_EXPECT_GE_PTR(lhs, rhs, msg, ...)\
	T_EXPECT_BLOCK2(_ptr, "%p", >=, lhs, rhs, msg, ## __VA_ARGS__)

#define T_ASSERT_EQ_PTR(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ptr, "%p", ==, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_NE_PTR(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ptr, "%p", !=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_LT_PTR(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ptr, "%p", <, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_GT_PTR(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ptr, "%p", >, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_LE_PTR(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ptr, "%p", <=, lhs, rhs, msg, ## __VA_ARGS__)
#define T_ASSERT_GE_PTR(lhs, rhs, msg, ...)\
	T_ASSERT_BLOCK2(_ptr, "%p", >=, lhs, rhs, msg, ## __VA_ARGS__)

/*
 * Log a perfdata measurement. For example:
 * T_PERF("name_of_metric", 3234, "nsec", "time since first test run")
 */
#define T_PERF(metric, value, unit, desc) \
	do {                                              \
		T_SAVEINFO;                               \
		T_SYM(perf)(metric, unit, value, desc);   \
	} while (0)

#endif /* _TESTS_KTEST_H */
