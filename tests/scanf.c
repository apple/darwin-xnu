/*
 * Copyright (c) 2020 Apple Computer, Inc. All rights reserved.
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

#include <darwintest.h>
#include <darwintest_utils.h>

// This can either test libkern's sscanf, or stdio.h's.
#define TEST_LIBKERN

#if defined(TEST_LIBKERN)
static int libkern_isspace(char c);
int libkern_sscanf(const char *ibuf, const char *fmt, ...);
int libkern_vsscanf(const char *inp, char const *fmt0, va_list ap);
# define isspace(C) libkern_isspace(C)
# define sscanf(...) libkern_sscanf(__VA_ARGS__)
# define vsscanf(...) libkern_vsscanf(__VA_ARGS__)
# include "../libkern/stdio/scanf.c"
#else
# include <stdio.h>
#endif

T_DECL(scanf_empty, "empty")
{
	T_ASSERT_EQ_INT(sscanf("", ""), 0, "empty input and format");
	T_ASSERT_EQ_INT(sscanf("", "match me"), EOF, "empty input");
	T_ASSERT_EQ_INT(sscanf("lonely", ""), 0, "empty format");
}

T_DECL(scanf_percent, "percent")
{
	T_ASSERT_EQ_INT(sscanf("%", "%%"), 0, "two percent");
}

T_DECL(scanf_character, "character")
{
	char c;
	for (char i = ' '; i <= '~'; ++i) {
		char buf[] = { i, '\0' };
		T_ASSERT_EQ_INT(sscanf(buf, "%c", &c), 1, "character matched");
		T_ASSERT_EQ_INT(c, i, "character value");
	}
}

T_DECL(scanf_characters, "characters")
{
	char c[] = { 'a', 'b', 'c', 'd', 'e' };
	T_ASSERT_EQ_INT(sscanf("01234", "%4c", c), 1, "characters matched");
	T_ASSERT_EQ_INT(c[0], '0', "characters value");
	T_ASSERT_EQ_INT(c[1], '1', "characters value");
	T_ASSERT_EQ_INT(c[2], '2', "characters value");
	T_ASSERT_EQ_INT(c[3], '3', "characters value");
	T_ASSERT_EQ_INT(c[4], 'e', "characters value wasn't overwritten");
}

T_DECL(scanf_string, "string")
{
	char s[] = { 'a', 'b', 'c', 'd', 'e' };
	T_ASSERT_EQ_INT(sscanf("012", "%s", s), 1, "string matched");
	T_ASSERT_EQ_STR(s, "012", "string value");
	T_ASSERT_EQ_INT(s[4], 'e', "string value wasn't overwritten");
	T_ASSERT_EQ_INT(sscanf("ABCDE", "%3s", s), 1, "string matched");
	T_ASSERT_EQ_STR(s, "ABC", "string value");
	T_ASSERT_EQ_INT(s[4], 'e', "string value wasn't overwritten");
}

T_DECL(scanf_decimal, "decimal")
{
	int num;
	for (char i = 0; i <= 9; ++i) {
		char buf[] = { i + '0', '\0' };
		T_ASSERT_EQ_INT(sscanf(buf, "%d", &num), 1, "decimal matched");
		T_ASSERT_EQ_INT(num, i, "decimal value");
	}
	for (char i = 10; i <= 99; ++i) {
		char buf[] = { i / 10 + '0', i % 10 + '0', '\0' };
		T_ASSERT_EQ_INT(sscanf(buf, "%d", &num), 1, "decimal matched");
		T_ASSERT_EQ_INT(num, i, "decimal value");
	}
	for (char i = 0; i <= 9; ++i) {
		char buf[] = { '-', i + '0', '\0' };
		T_ASSERT_EQ_INT(sscanf(buf, "%d", &num), 1, "negative decimal matched");
		T_ASSERT_EQ_INT(num, -i, "negative decimal value");
	}
	T_ASSERT_EQ_INT(sscanf("-2147483648", "%d", &num), 1, "INT32_MIN matched");
	T_ASSERT_EQ_INT(num, INT32_MIN, "INT32_MIN value");
	T_ASSERT_EQ_INT(sscanf("2147483647", "%d", &num), 1, "INT32_MAX matched");
	T_ASSERT_EQ_INT(num, INT32_MAX, "INT32_MAX value");
}

T_DECL(scanf_integer, "integer")
{
	int num;
	T_ASSERT_EQ_INT(sscanf("0", "%i", &num), 1, "octal integer matched");
	T_ASSERT_EQ_INT(num, 0, "octal integer value");
	for (char i = 0; i <= 7; ++i) {
		char buf[] = { '0', i + '0', '\0' };
		T_ASSERT_EQ_INT(sscanf(buf, "%i", &num), 1, "octal integer matched");
		T_ASSERT_EQ_INT(num, i, "octal integer value");
	}
	for (char i = 0; i <= 9; ++i) {
		char buf[] = { '0', 'x', i + '0', '\0' };
		T_ASSERT_EQ_INT(sscanf(buf, "%i", &num), 1, "hex integer matched");
		T_ASSERT_EQ_INT(num, i, "hex integer value");
	}
	for (char i = 10; i <= 15; ++i) {
		char buf[] = { '0', 'x', i - 10 + 'a', '\0' };
		T_ASSERT_EQ_INT(sscanf(buf, "%i", &num), 1, "hex integer matched");
		T_ASSERT_EQ_INT(num, i, "hex integer value");
	}
}

T_DECL(scanf_unsigned, "unsigned")
{
	unsigned num;
	T_ASSERT_EQ_INT(sscanf("4294967295", "%u", &num), 1, "UINT32_MAX matched");
	T_ASSERT_EQ_UINT(num, UINT32_MAX, "UINT32_MAX value");
}

T_DECL(scanf_octal, "octal")
{
	int num;
	T_ASSERT_EQ_INT(sscanf("0", "%o", &num), 1, "octal matched");
	T_ASSERT_EQ_INT(num, 0, "octal value");
	for (char i = 0; i <= 7; ++i) {
		char buf[] = { '0', i + '0', '\0' };
		T_ASSERT_EQ_INT(sscanf(buf, "%o", &num), 1, "octal matched");
		T_ASSERT_EQ_INT(num, i, "octal value");
	}
}

T_DECL(scanf_hex, "hex")
{
	int num;
	for (char i = 0; i <= 9; ++i) {
		char buf[] = { '0', 'x', i + '0', '\0' };
		T_ASSERT_EQ_INT(sscanf(buf, "%x", &num), 1, "hex matched");
		T_ASSERT_EQ_INT(num, i, "hex value");
	}
	for (char i = 10; i <= 15; ++i) {
		char buf[] = { '0', 'x', i - 10 + 'a', '\0' };
		T_ASSERT_EQ_INT(sscanf(buf, "%x", &num), 1, "hex matched");
		T_ASSERT_EQ_INT(num, i, "hex value");
	}
}

T_DECL(scanf_read, "read")
{
	int val, num;
	T_ASSERT_EQ_INT(sscanf("", "%n", &num), 0, "read matched");
	T_ASSERT_EQ_INT(num, 0, "read count");
	T_ASSERT_EQ_INT(sscanf("a", "a%n", &num), 0, "read matched");
	T_ASSERT_EQ_INT(num, 1, "read count");
	T_ASSERT_EQ_INT(sscanf("ab", "a%nb", &num), 0, "read matched");
	T_ASSERT_EQ_INT(num, 1, "read count");
	T_ASSERT_EQ_INT(sscanf("1234567", "%i%n", &val, &num), 1, "read matched");
	T_ASSERT_EQ_INT(val, 1234567, "read value");
	T_ASSERT_EQ_INT(num, 7, "read count");
}

T_DECL(scanf_pointer, "pointer")
{
	void *ptr;
	if (sizeof(void*) == 4) {
		T_ASSERT_EQ_INT(sscanf("0xdeadbeef", "%p", &ptr), 1, "pointer matched");
		T_ASSERT_EQ_PTR(ptr, (void*)0xdeadbeef, "pointer value");
	} else {
		T_ASSERT_EQ_INT(sscanf("0xdeadbeefc0defefe", "%p", &ptr), 1, "pointer matched");
		T_ASSERT_EQ_PTR(ptr, (void*)0xdeadbeefc0defefe, "pointer value");
	}
}
