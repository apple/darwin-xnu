/*
 * Copyright (c) 2009 Apple Inc. All rights reserved.
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

#include <string.h>
#include <sys/types.h>
#include <AssertMacros.h>

#if !KERNEL
    #include <stdio.h>
    #include <stdlib.h>
    #include "kxld.h"
    #include "kxld_types.h"
#else
    #include <libkern/libkern.h>
    #include <libkern/kxld.h>
    #include <libkern/kxld_types.h>
#endif /* KERNEL */

#include "kxld_util.h"

/******************************************************************************
* Macros
******************************************************************************/

#define kCopyrightToken "Copyright © "
#define kRightsToken " Apple Inc. All rights reserved."

/******************************************************************************
* Globals
******************************************************************************/

#if TEST

#include <CoreFoundation/CoreFoundation.h>

CFStringRef passes[] = {
	CFSTR("Copyright © 2008 Apple Inc. All rights reserved."),
	CFSTR("Copyright © 2004-2008 Apple Inc. All rights reserved."),
	CFSTR("Copyright © 2004,2006 Apple Inc. All rights reserved."),
	CFSTR("Copyright © 2004,2006-2008 Apple Inc. All rights reserved."),
	CFSTR("Copyright © 2004 , 2006-2008 Apple Inc. All rights reserved."),
	CFSTR("Copyright © 1998,2000-2002,2004,2006-2008 Apple Inc. All rights reserved."),
	CFSTR("IOPCIFamily 2.1; Copyright © 2004,2006-2008 Apple Inc. All rights reserved."),
	CFSTR("Copyright © 2004,2006-2008 Apple Inc. All rights reserved.  The quick brown fox jumped over the lazy dog."),
	CFSTR("IOPCIFamily 2.1; Copyright © 2004,2006-2008 Apple Inc. All rights reserved.  The quick brown fox jumped over the lazy dog.")
};

CFStringRef fails[] = {
	CFSTR("Copyright © 2007-08 Apple Inc. All rights reserved."),
	CFSTR("Copyright (c) 2007 Apple Inc. All rights reserved."),
	CFSTR("Copyright © 2007- Apple Inc. All rights reserved."),
	CFSTR("Copyright © 2007 - 2008 Apple Inc. All rights reserved.")
};

extern char *createUTF8CStringForCFString(CFStringRef aString);

#endif /* TEST */

/******************************************************************************
* Prototypes
******************************************************************************/

static boolean_t is_space(const char c)
__attribute__((const));
static boolean_t is_token_delimiter(const char c)
__attribute__((const));
static boolean_t is_token_break(const char *str)
__attribute__((pure, nonnull));
static boolean_t token_is_year(const char *str)
__attribute__((pure, nonnull));
static boolean_t token_is_yearRange(const char *str)
__attribute__((pure, nonnull));
static boolean_t dates_are_valid(const char *str, const u_long len)
__attribute__((pure, nonnull));

/******************************************************************************
******************************************************************************/
static boolean_t
is_space(const char c)
{
	switch (c) {
	case ' ':
	case '\t':
	case '\n':
	case '\v':
	case '\f':
	case '\r':
		return TRUE;
	}

	return FALSE;
}

/******************************************************************************
******************************************************************************/
static boolean_t
is_token_delimiter(const char c)
{
	return is_space(c) || (',' == c) || ('\0' == c);
}

/******************************************************************************
* A token break is defined to be the boundary where the current character is
* not a token delimiter and the next character is a token delimiter.
******************************************************************************/
static boolean_t
is_token_break(const char *str)
{
	/* This is safe because '\0' is a token delimiter, so the second check
	 * will not execute if we reach the end of the string.
	 */
	return !is_token_delimiter(str[0]) && is_token_delimiter(str[1]);
}

/******************************************************************************
* A year is defined by the following regular expression:
*   /[0-9]{4}$/
******************************************************************************/
#define kYearLen 5
static boolean_t
token_is_year(const char *str)
{
	boolean_t result = FALSE;
	u_int i = 0;

	for (i = 0; i < kYearLen - 1; ++i) {
		if (str[i] < '0' || str[i] > '9') {
			goto finish;
		}
	}

	if (str[i] != '\0') {
		goto finish;
	}

	result = TRUE;
finish:
	return result;
}

/******************************************************************************
* A year range is defined by the following regular expression:
*   /[0-9]{4}[-][0-9]{4}$/
******************************************************************************/
#define kYearRangeLen 10
static boolean_t
token_is_yearRange(const char *str)
{
	boolean_t result = FALSE;
	u_int i = 0;

	for (i = 0; i < kYearLen - 1; ++i) {
		if (str[i] < '0' || str[i] > '9') {
			goto finish;
		}
	}

	if (str[i] != '-') {
		goto finish;
	}

	for (i = kYearLen; i < kYearRangeLen - 1; ++i) {
		if (str[i] < '0' || str[i] > '9') {
			goto finish;
		}
	}

	if (str[i] != '\0') {
		goto finish;
	}

	result = TRUE;
finish:
	return result;
}

/******************************************************************************
* The dates_are_valid function takes as input a comma-delimited list of years
* and year ranges, and returns TRUE if all years and year ranges are valid
* and well-formed.
******************************************************************************/
static boolean_t
dates_are_valid(const char *str, const u_long len)
{
	boolean_t result = FALSE;
	const char *token_ptr = NULL;
	char token_buffer[kYearRangeLen];
	u_int token_index = 0;

	token_index = 0;
	for (token_ptr = str; token_ptr < str + len; ++token_ptr) {
		if (is_token_delimiter(*token_ptr) && !token_index) {
			continue;
		}

		/* If we exceed the length of a year range, the test will not succeed,
		 * so just fail now.  This limits the length of the token buffer that
		 * we have to keep around.
		 */
		if (token_index == kYearRangeLen) {
			goto finish;
		}

		token_buffer[token_index++] = *token_ptr;
		if (is_token_break(token_ptr)) {
			if (!token_index) {
				continue;
			}

			token_buffer[token_index] = '\0';

			if (!token_is_year(token_buffer) &&
			    !token_is_yearRange(token_buffer)) {
				goto finish;
			}

			token_index = 0;
		}
	}

	result = TRUE;
finish:
	return result;
}

/******************************************************************************
* The copyright string is composed of three parts:
*   1) A copyright notice, "Copyright ©"
*   2) One or more years or year ranges, e.g., "2004,2006-2008"
*   3) A rights reserved notice, "Apple Inc. All Rights Reserved."
* We check the validity of the string by searching for both the copyright
*
* notice and the rights reserved notice.  If both are found, we then check that
* the text between the two notices contains only valid years and year ranges.
******************************************************************************/
boolean_t
kxld_validate_copyright_string(const char *str)
{
	boolean_t result = FALSE;
	const char *copyright = NULL;
	const char *rights = NULL;
	char *date_str = NULL;
	size_t len = 0;

	len = strlen(str);
	copyright = strnstr(str, kCopyrightToken, len);
	rights = strnstr(str, kRightsToken, len);

	if (!copyright || !rights || copyright > rights) {
		goto finish;
	}

	str = copyright + const_strlen(kCopyrightToken);

	len = rights - str;
	date_str = kxld_alloc(len + 1);
	if (!date_str) {
		goto finish;
	}

	strncpy(date_str, str, len);
	date_str[len] = '\0';

	if (!dates_are_valid(date_str, len)) {
		goto finish;
	}

	result = TRUE;
finish:
	if (date_str) {
		kxld_free(date_str, len + 1);
	}
	return result;
}

#if TEST

/******************************************************************************
******************************************************************************/
int
main(int argc __unused, char *argv[] __unused)
{
	int result = 1;
	CFStringRef the_string = NULL;
	const char *str = NULL;
	u_int i = 0;

	printf("The following %lu strings should pass\n",
	    const_array_len(passes));

	for (i = 0; i < const_array_len(passes); ++i) {
		the_string = passes[i];
		str = createUTF8CStringForCFString(the_string);
		if (!str) {
			goto finish;
		}

		printf("%s: %s\n",
		    (kxld_validate_copyright_string(str)) ? "pass" : "fail", str);
	}

	printf("\nThe following %lu strings should fail\n",
	    const_array_len(fails));

	for (i = 0; i < const_array_len(fails); ++i) {
		the_string = fails[i];
		str = createUTF8CStringForCFString(the_string);
		if (!str) {
			goto finish;
		}

		printf("%s: %s\n",
		    (kxld_validate_copyright_string(str)) ? "pass" : "fail", str);
	}

	result = 0;

finish:
	return result;
}
#endif /* TEST */
