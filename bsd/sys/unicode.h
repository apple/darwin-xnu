/*
 * Copyright (c) 2016-2020 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#ifndef unicode_h
#define unicode_h

#ifdef KERNEL_PRIVATE

#include <sys/cdefs.h>
#include <stdbool.h>

/*
 * WARNING - callers that use the following Unicode normalization interface for on-disk
 * structures should be aware that the implementation will be periodically updated for
 * the latest Unicode standard version.
 */

enum {
	/* Maximum size of UTF32 reordering buffer for stream-safe format */
	kNCFStreamSafeBufMax = 32
};

/*
 * utf8_normalizeOptCaseFoldAndHash
 *
 * Convert a given UTF-8 string to UTF-32 in one of the following normalized forms,
 * as specified by the case_sens parameter, and feed the result incrementally to
 * the provided hash function callback:
 * - "canonical caseless form" (case-folded NFD, as described by definition D145
 *    in chapter 3 of The Unicode Standard); for case-insensitive behavior.
 * - standard NFD; for case-sensitive behavior (if case_sens = true).
 *
 * The input string should be valid UTF-8 that meets the criteria for stream safe
 * text as described in http://unicode.org/reports/tr15/#Stream_Safe_Text_Format.
 * It should not contain ASCII 0x00 or '/'.
 *
 * str:       The input UTF-8 string (need not be 0 terminated)
 * str_len:   The byte length of the input string (excluding any 0 terminator)
 * case_sens: False for case-insensitive behavior; generates canonical caseless form.
 *            True for case-sensitive behavior; generates standard NFD.
 * hash_func: A pointer to a hashing function to compute the hash of the
 *            normalized/case-folded result. buf contains buf_len bytes
 *            of data to be added to the hash using the caller-supplied
 *            context (ctx).
 * hash_ctx:  The context for the hash function.
 *
 * Returns: 0 on success, or
 *          EILSEQ: The input string contains illegal ASCII-range characters
 *                  (0x00 or '/'), or is not well-formed stream-safe UTF-8, or
 *                  contains codepoints that are non-characters or unassigned in
 *                  the version of Unicode currently supported.
 */
int utf8_normalizeOptCaseFoldAndHash(const char *str,
    size_t      str_len,
    bool        case_sens,
    void      (*hash_func)(void *buf, size_t buf_len, void *ctx),
    void       *hash_ctx);

/*
 * utf8_normalizeOptCaseFoldAndCompare
 *
 * Determine whether two UTF-8 strings are equal after converting each to one of the
 * following normalized forms, as specified by the case_sens parameter:
 * - "canonical caseless form" (case-folded NFD); for case-insensitive comparison.
 * - standard NFD; for case-sensitive comparison (if case_sens = true).
 * On success, sets are_equal to true if the strings are equal, or false if they are not.
 *
 * The input strings should be valid UTF-8 that meet the criteria for stream safe
 * text as described in http://unicode.org/reports/tr15/#Stream_Safe_Text_Format.
 * They should not contain ASCII 0x00 or '/'.
 *
 * strA:      A UTF-8 string to be compared (need not be 0 terminated)
 * strA_len:  The byte length of strA (excluding any 0 terminator)
 * strB:      The second UTF-8 string to be compared (need not be 0 terminated)
 * strB_len:  The byte length of strB (excluding any 0 terminator)
 * case_sens: False for case-insensitive behavior; compares canonical caseless forms.
 *            True for case-sensitive behavior; compares standard NFD forms.
 * are_equal: On success, set to true if the strings are equal, or set to false
 *            if they are not.
 *
 * Returns: 0 on success, or
 *          EILSEQ: One or both of the input strings contains illegal ASCII-range
 *                  characters (0x00 or '/'), or is not well-formed stream-safe UTF-8,
 *                  or contains codepoints that are non-characters or unassigned in
 *                  the version of Unicode currently supported.
 *                  Note: The comparison may terminate early when a difference is
 *                        detected, and may return 0 and set *are_equal=false even
 *                        if one or both strings are invalid.
 */
int utf8_normalizeOptCaseFoldAndCompare(const char *strA,
    size_t      strA_len,
    const char *strB,
    size_t      strB_len,
    bool        case_sens,
    bool       *are_equal);

/*
 * utf8_normalizeOptCaseFold
 *
 * Convert a given UTF-8 string to UTF-32 in one of the following normalized forms,
 * as specified by the case_sens parameter, and copy the result to the ustr
 * buffer:
 * - "canonical caseless form" (case-folded NFD, as described by definition D145
 *    in chapter 3 of The Unicode Standard); for case-insensitive behavior.
 * - standard NFD; for case-sensitive behavior (if case_sens = true).
 *
 * The input string should be valid UTF-8 that meets the criteria for stream safe
 * text as described in http://unicode.org/reports/tr15/#Stream_Safe_Text_Format.
 * It should not contain ASCII 0x00 or '/'.
 *
 * str:       The input UTF-8 string (need not be 0 terminated)
 * str_len:   The byte length of the input string (excluding any 0 terminator)
 * case_sens: False for case-insensitive behavior; generates canonical caseless form.
 *            True for case-sensitive behavior; generates standard NFD.
 * ustr:      A pointer to a buffer for the resulting UTF-32 string.
 * ustr_size: The capacity of ustr, in UTF-32 units.
 * ustr_len:  Pointer to a value that will be filled in with the actual length
 *            in UTF-32 units of the string copied to ustr.
 *
 * Returns: 0 on success, or
 *          EILSEQ: The input string contains illegal ASCII-range characters
 *                  (0x00 or '/'), or is not well-formed stream-safe UTF-8, or
 *                  contains codepoints that are non-characters or unassigned in
 *                  the version of Unicode currently supported.
 *          ENOMEM: ustr_size is insufficient for the resulting string. In this
 *                  case the value returned in *ustr_len is invalid.
 */
int utf8_normalizeOptCaseFold(const char *str,
    size_t      str_len,
    bool        case_sens,
    int32_t    *ustr,
    int32_t     ustr_size,
    int32_t    *ustr_len);

/*
 * utf8_normalizeOptCaseFoldToUTF8
 *
 * Convert a given UTF-8 string to UTF-8 in one of the following normalized forms,
 * as specified by the case_sens parameter, and copy the result to the ustr
 * buffer:
 * - "canonical caseless form" (case-folded NFD, as described by definition D145
 *    in chapter 3 of The Unicode Standard); for case-insensitive behavior.
 * - standard NFD; for case-sensitive behavior (if case_sens = true).
 *
 * The input string should be valid UTF-8 that meets the criteria for stream safe
 * text as described in http://unicode.org/reports/tr15/#Stream_Safe_Text_Format.
 * It should not contain ASCII 0x00 or '/'.
 *
 * str:       The input UTF-8 string (need not be 0 terminated)
 * str_len:   The byte length of the input string (excluding any 0 terminator)
 * case_sens: False for case-insensitive behavior; generates canonical caseless form.
 *            True for case-sensitive behavior; generates standard NFD.
 * ustr:      A pointer to a buffer for the resulting UTF-8 string.
 * ustr_size: The capacity of ustr, in bytes.
 * ustr_len:  Pointer to a value that will be filled in with the actual length
 *            in bytes of the string copied to ustr.
 *
 * Returns: 0 on success, or
 *          EILSEQ: The input string contains illegal ASCII-range characters
 *                  (0x00 or '/'), or is not well-formed stream-safe UTF-8, or
 *                  contains codepoints that are non-characters or unassigned in
 *                  the version of Unicode currently supported.
 *          ENOMEM: ustr_size is insufficient for the resulting string. In this
 *                  case the value returned in *ustr_len is invalid.
 */
int utf8_normalizeOptCaseFoldToUTF8(const char *str,
    size_t      str_len,
    bool        case_sens,
    char       *ustr,
    size_t      ustr_size,
    size_t     *ustr_len);

/*
 * utf8_normalizeOptCaseFoldAndMatchSubstring
 *
 * Determine whether the normalized UTF32 string derived from a specified UTF-8 string
 * strA contains another UTF32 string ustrB which has already been normalized, typically
 * with normalizeOptCaseFold. The normalization for both strings is one of the following,
 * as specified by the case_sens parameter:
 * - "canonical caseless form" (case-folded NFD); for case-insensitive comparison.
 * - standard NFD; for case-sensitive comparison (if case_sens = true).
 * On success, sets are_equal to true if strA contains ustrB, or false otherwise.
 *
 * The input string strA should be valid UTF-8 that meets the criteria for stream safe
 * text as described in http://unicode.org/reports/tr15/#Stream_Safe_Text_Format.
 * It should not contain ASCII 0x00 or '/'.
 *
 * strA:      A UTF-8 string (need not be 0 terminated) in which to search for the
 *            substring specified by ustrB.
 * strA_len:  The byte length of strA (excluding any 0 terminator)
 * ustrB:     A normalized UTF-32 substring (need not be 0 terminated) to be searched
 *            for in the UTF-32 string resulting from converting strA to the normalized
 *            UTF-32 form specified by the case_sens parameter; ustrB must already be
 *            in that form. Normally this will be produced using normalizeOptCaseFold.
 * ustrB_len: The length of ustrB in UTF-32 units (excluding any 0 terminator).
 * case_sens: False for case-insensitive matching; compares canonical caseless forms.
 *            True for case-sensitive matching; compares standard NFD forms.
 * buf:       Pointer to caller-supplied working memory for storing the portion of
 *            strA which has been converted to normalized UTF-32.
 * buf_size:  The size of buf.
 * has_match: On success, set to true if strA (when converter to UTF-32 and normalized
 *            per case_sens) contains ustrB, set to false otherwise.
 *
 * Returns: 0 on success, or
 *          EILSEQ: strA contains illegal ASCII-range characters (0x00 or '/'), or is
 *                  not well-formed stream-safe UTF-8, or contains codepoints that are
 *                  non-characters or unassigned in the version of Unicode currently
 *                  supported.
 *                  Note: The search may terminate early when a match is detected, and
 *                        may return 0 and set *has_match=true even if strA is invalid.
 *          ENOMEM: buf_size is insufficient.
 */
int utf8_normalizeOptCaseFoldAndMatchSubstring(const char    *strA,
    size_t         strA_len,
    const int32_t *ustrB,
    int32_t        ustrB_len,
    bool           case_sens,
    void          *buf,
    size_t         buf_size,
    bool          *has_match);

/*
 * utf8_normalizeOptCaseFoldGetUVersion
 *
 * Get the Unicode and code version currently associated with the normalizeOptCaseFold
 * functions. The caller allocates the version array and passes it to the function,
 * which will fill out the array as follows:
 * version[0] = Unicode major version; for Unicode 6.3.0 this would be 6
 * version[1] = Unicode minor version; for Unicode 6.3.0 this would be 3
 * version[2] = Unicode patch version; for Unicode 6.3.0 this would be 0
 * version[3] = Code revision level; for any given Unicode version, this value starts
 *              at 0 and is incremented for each significant revision to the
 *              normalizeOptCaseFold functions.
 */
void utf8_normalizeOptCaseFoldGetUVersion(unsigned char version[4]);

#endif /* KERNEL_PRIVATE */

#endif  /* unicode_h */
