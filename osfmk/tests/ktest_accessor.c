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

#include <tests/ktest_internal.h>
#include <kern/misc_protos.h>
#include <kern/debug.h>

int vsnprintf(char *, size_t, const char *, va_list);

void
ktest_set_current_expr(const char * expr_fmt, ...) {
	int ret;
	va_list args;

	va_start(args, expr_fmt);
	ret = vsnprintf(ktest_current_expr, KTEST_MAXLEN, expr_fmt, args);
	va_end(args);
}

void
ktest_set_current_var(const char * name, const char * value_fmt, ...) {
	int ret;
	va_list args;

	if(ktest_current_var_index >= KTEST_MAXVARS) {
		panic("Internal ktest error in " __func__);
	}

	strlcpy(ktest_current_var_names[ktest_current_var_index],
			name,
			KTEST_MAXLEN);

	va_start(args, value_fmt);
	ret = vsnprintf(ktest_current_var_values[ktest_current_var_index],
			KTEST_MAXLEN,
			value_fmt,
			args);
	va_end(args);

	ktest_current_var_index++;
}

void
ktest_set_current_msg(const char * msg, ...) {
	int ret;
	va_list args;

	if(msg == NULL) return;

	va_start(args, msg);
	ret = vsnprintf(ktest_current_msg, KTEST_MAXLEN, msg, args);
	va_end(args);
}

