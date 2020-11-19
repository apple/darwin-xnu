/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/buf.h>
#include <sys/time.h>
#include <sys/kauth.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/syslog.h>
#include <sys/vnode_internal.h>
#include <sys/fslog.h>
#include <sys/mount_internal.h>
#include <sys/kasl.h>

#include <dev/random/randomdev.h>

#include <uuid/uuid.h>

#include <stdarg.h>

/* String to append as format modifier for each key-value pair */
#define KASL_KEYVAL_FMT "[%s %s] "
#define KASL_KEYVAL_FMT_LEN     (sizeof(KASL_KEYVAL_FMT) - 1)

#define KASL_NEWLINE_CHAR       "\n"
#define KASL_NEWLINE_CHAR_LEN   (sizeof(KASL_NEWLINE_CHAR) - 1)

/* Length of entire ASL message in 10 characters.  Kernel defaults to zero */
#define KASL_ASL_MSG_LEN        "         0"

/* Length of default format string to be used by printf */
#define MAX_FMT_LEN             256


/* Function to print input values as key-value pairs in format
 * identifiable by Apple system log (ASL) facility. All key-value pairs
 * are assumed to be pointer to strings and are provided using va_list
 * argument which is a list of varying number of arguments created by the
 * caller of this function.
 *
 * Parameters -
 *      level     - Priority level for this ASL message
 *	facility  - Facility for this ASL message.
 *	num_pairs - Number of key-value pairs provided by vargs argument.
 *	vargs     - List of key-value pairs.
 *
 * Returns -
 *	zero	- On success, when it prints all key-values pairs provided.
 *	E2BIG	- When it cannot print all key-value pairs provided and had
 *		  to truncate the output.
 */
static int
kern_asl_msg_va(int level, const char *facility, size_t num_pairs, va_list vargs)
{
	int err = 0;
	char fmt[MAX_FMT_LEN];  /* Format string to use with vaddlog */
	size_t calc_pairs = 0;
	size_t len;

	/* Mask extra bits, if any, from priority level */
	level = LOG_PRI(level);

	/* Create the first part of format string consisting of ASL
	 * message length, level, and facility.
	 */
	if (facility) {
		snprintf(fmt, MAX_FMT_LEN, "%s [%s %d] [%s %s] ",
		    KASL_ASL_MSG_LEN,
		    KASL_KEY_LEVEL, level,
		    KASL_KEY_FACILITY, facility);
	} else {
		snprintf(fmt, MAX_FMT_LEN, "%s [%s %d] ",
		    KASL_ASL_MSG_LEN,
		    KASL_KEY_LEVEL, level);
	}

	/* Determine the number of key-value format string [%s %s] that
	 * should be added in format string for every key-value pair provided
	 * in va_list.  Calculate maximum number of format string that can be
	 * accommodated in the remaining format buffer (after saving space
	 * for newline character).  If the caller provided pairs in va_list
	 * is more than calculated pairs, truncate extra pairs.
	 */
	len = MAX_FMT_LEN - strlen(fmt) - KASL_NEWLINE_CHAR_LEN - 1;
	calc_pairs = len / KASL_KEYVAL_FMT_LEN;
	if (num_pairs <= calc_pairs) {
		calc_pairs = num_pairs;
	} else {
		err = E2BIG;
	}

	/* Append format strings [%s %s] for the key-value pairs in vargs */
	len = MAX_FMT_LEN - KASL_NEWLINE_CHAR_LEN;
	for (size_t i = 0; i < calc_pairs; i++) {
		(void) strlcat(fmt, KASL_KEYVAL_FMT, len);
	}

	/* Append newline */
	(void) strlcat(fmt, KASL_NEWLINE_CHAR, MAX_FMT_LEN);

	/* Print the key-value pairs in ASL format */
	vaddlog(fmt, vargs);

	/*
	 * Note: can't use os_log_with_args() here because 'fmt' is
	 * constructed on the stack i.e. doesn't come from a text
	 * section. More importantly, the newer logging system
	 * doesn't grok ASL either.
	 */

	return err;
}

int
kern_asl_msg(int level, const char *facility, size_t num_pairs, ...)
{
	int err;
	va_list ap;

	va_start(ap, num_pairs);
	err = kern_asl_msg_va(level, facility,
	    num_pairs, ap);
	va_end(ap);

	return err;
}

/* Search if given string contains '[' and ']'.  If any, escape it by
 * prefixing with a '\'.  If the length of the string is not big enough,
 * no changes are done and error is returned.
 *
 * Parameters -
 *      str - string that can contain '[' or ']', should be NULL terminated
 *	len - length, in bytes, of valid data, including NULL character.
 *	buflen - size of buffer that contains the string
 */
int
escape_str(char *str, size_t len, size_t buflen)
{
	size_t count;
	char *src, *dst;

	/* Count number of characters to escape */
	src = str;
	count = 0;
	do {
		if ((*src == '[') || (*src == ']')) {
			count++;
		}
	} while (*src++);

	if (count) {
		/*
		 * Check if the buffer has enough space to escape all
		 * characters
		 */
		if ((buflen - len) < count) {
			return ENOSPC;
		}

		src = str + len;
		dst = src + count;
		while (count) {
			*dst-- = *src;
			if ((*src == '[') || (*src == ']')) {
				/* Last char copied needs to be escaped */
				*dst-- = '\\';
				count--;
			}
			src--;
		}
	}

	return 0;
}
