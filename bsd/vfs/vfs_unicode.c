/*
 * Copyright (C) 2016-2020 Apple, Inc. All rights reserved.
 * Some portions covered by other copyrights, listed below.
 *---
 * Copyright (C) 2016 and later: Unicode, Inc. and others.
 * License & terms of use: http://www.unicode.org/copyright.html
 *---
 * Copyright (C) 1999-2015, International Business Machines
 * Corporation and others.  All Rights Reserved.
 *
 * add APPLE_OSREFERENCE_LICENSE_HEADER stuff...
 */

#include <libkern/libkern.h>
#include <sys/errno.h>
#include <sys/unicode.h>
#include "vfs_unicode_data.h"
#define STATIC_UNLESS_TEST static

enum {
	/* Maximum number of UTF8 bytes from one Unicode code point (one UTF32 code unit) */
	kMaxUTF8BytesPerChar = 4
};

/* local prototypes used by exported functions (and themselves exported for testing) */
STATIC_UNLESS_TEST
int32_t utf8ToU32Code(int32_t u32char, const char** srcPtr, const char* srcLimit);
STATIC_UNLESS_TEST
int32_t normalizeOptCaseFoldU32Char(int32_t u32char, bool case_sens,
    int32_t u32NormFoldBuf[kNFCSingleCharDecompMax],
    uint8_t combClass[kNFCSingleCharDecompMax]);
/* local prototypes used by exported functions (not exported for separate testing) */
static int nextBaseAndAnyMarks(const char** strP, const char *strLimit, bool case_sens,
    int32_t* unorm, uint8_t* unormcc, int32_t* unormlenP, int32_t* unormstartP,
    int32_t* buf, uint8_t* bufcc, int32_t* buflenP,
    bool* needReorderP, bool* startP);
void doReorder(int32_t* buf, uint8_t* bufcc, int32_t buflen);
int32_t u32CharToUTF8Bytes(uint32_t u32char, uint8_t utf8Bytes[kMaxUTF8BytesPerChar]);

/*
 * utf8_normalizeOptCaseFoldGetUVersion
 *
 * version[0] = Unicode major version; for Unicode 6.3.0 this would be 6
 * version[1] = Unicode minor version; for Unicode 6.3.0 this would be 3
 * version[2] = Unicode patch version; for Unicode 6.3.0 this would be 0
 * version[3] = Code revision level; for any given Unicode version, this value starts
 *              at 0 and is incremented for each significant revision to the
 *              normalizeOptCaseFold functions.
 */
void
utf8_normalizeOptCaseFoldGetUVersion(unsigned char version[4])
{
	version[0] = 13;
	version[1] = 0;
	version[2] = 0;
	version[3] = 0;
	return;
}

/*
 * utf8_normalizeOptCaseFoldAndHash
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
 *                  the version of Unicode currently supported (Unicode 9.0).
 */

int
utf8_normalizeOptCaseFoldAndHash(const char *str,
    size_t      str_len,
    bool        case_sens,
    void      (*hash_func)(void *buf, size_t buf_len, void *ctx),
    void       *hash_ctx)
{
	const char *strLimit = str + str_len;

	/* Data for the next pending single-char norm from input;
	 *  This will always begin with a base char (combining class 0)
	 *  or the first character in the string, which may no be a base */
	int32_t unorm[kNFCSingleCharDecompMax];
	uint8_t unormcc[kNFCSingleCharDecompMax];
	int32_t unormlen = 0;
	int32_t unormstart = 0;

	bool start = true;

	/* main loop:
	 * Each input character may be normalized to a sequence of one or more characters,
	 * some of which may have non-zero combining class. Any sequence of characters
	 * with non-zero combining class resulting from one or more input characters needs
	 * to be accumulated in the main buffer so we can reorder as necessary before
	 * calling the hash function.
	 *
	 * At the beginning of the main loop: The normalization buffer and main buffer are
	 * both empty.
	 *
	 * Each time through the main loop we do the following:
	 * 1. If there are characters available in the normalization result buffer (from the
	 *    result of normalizing a previous input character), copy the first character and
	 *    any following characters that have non-zero combining class to the main buffer.
	 * 2. If there is nothing left in the normalization buffer, then loop processing
	 *    input characters as follows:
	 *   a) Get the next input character from UTF8, get its normalized and case-folded
	 *      result in the normalization buffer.
	 *   b) If the first character in the normalization buffer has combining class 0,
	 *      break; we will handle this normalization buffer next time through the main
	 *      loop.
	 *   c) Else copy the current normalization buffer (which has only combining marks)
	 *      to the main buffer, and continue with the loop processing input characters.
	 * 3. At this point the first character in the main buffer may or may not have
	 *    combining class 0, but any subsequent characters (up to the the limit for
	 *    stream safe text) will be combining characters with nonzero combining class.
	 *    Reorder the combining marks if necessary into canonical order.
	 * 4. Call the hash function for each character in the main buffer.
	 *
	 */
	do {
		/* Data for the buffers being built up from input */
		int32_t buf[kNCFStreamSafeBufMax];
		uint8_t bufcc[kNCFStreamSafeBufMax];
		int32_t buflen = 0;
		bool needReorder = false;
		int err;

		err = nextBaseAndAnyMarks(&str, strLimit, case_sens, unorm, unormcc, &unormlen, &unormstart,
		    buf, bufcc, &buflen, &needReorder, &start);
		if (err != 0) {
			return err;
		}

		if (buflen > 0) {
			/* Now buffer should have all of the combining marks up to the next base char.
			 * Normally it will also start with the last base char encountered (unless the
			 * UTF8 string began with a combining mark). */
			/* Now reorder combining marks if necessary. */
			if (needReorder) {
				doReorder(buf, bufcc, buflen);
			}
			/* Now write to hash func */
			hash_func(buf, buflen * sizeof(buf[0]), hash_ctx);
		}
		/* OK so far, top of loop clears buffers to start refilling again */
	} while (str < strLimit || unormlen > 0);
	return 0;
}

/*
 * utf8_normalizeOptCaseFoldAndCompare
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
 *                  the version of Unicode currently supported (Unicode 9.0).
 *                  Note: The comparison may terminate early when a difference is
 *                        detected, and may return 0 and set *are_equal=false even
 *                        if one or both strings are invalid.
 */
enum { kNFCSingleCharDecompMaxPlusPushback = kNFCSingleCharDecompMax + 4 }; /* room for 03B9 pushback(s) */

int
utf8_normalizeOptCaseFoldAndCompare(const char *strA,
    size_t      strA_len,
    const char *strB,
    size_t      strB_len,
    bool        case_sens,
    bool       *are_equal)
{
	const char *strALimit = strA + strA_len;
	const char *strBLimit = strB + strB_len;

	/* Data for the next pending single-char norms from each input;
	 *  These will always begin with a base char (combining class 0)
	 *  or the first character in the string, which may not be a base */
	int32_t unormA[kNFCSingleCharDecompMaxPlusPushback], unormB[kNFCSingleCharDecompMaxPlusPushback];
	uint8_t unormAcc[kNFCSingleCharDecompMaxPlusPushback], unormBcc[kNFCSingleCharDecompMaxPlusPushback];
	int32_t unormAlen = 0, unormBlen = 0;
	int32_t unormAstart = 0, unormBstart = 0;

	bool startA = true, startB = true;

	/* main loop:
	 * The main loop here is similar to the main loop in utf8_normalizeOptCaseFoldAndHash,
	 * described above. The differences are:
	 * - We keep a normalization buffer and main buffer for each string.
	 * - In the main loop, we do steps 1-3 for each string.
	 * - In step 4, instead of calling the hash function, we compare the two main
	 *   buffers; if they are unequal, we return a non-equal result.
	 * - After the end of the main loop, if we still have data for one string but
	 *   not the other, return a non-equal result, else return an equal result.
	 */
	do {
		/* Data for the buffers being built up from each input */
		int32_t bufA[kNCFStreamSafeBufMax], bufB[kNCFStreamSafeBufMax];
		uint8_t bufAcc[kNCFStreamSafeBufMax], bufBcc[kNCFStreamSafeBufMax];
		int32_t bufAlen = 0, bufBlen = 0;
		bool needReorderA = false, needReorderB = false;
		int err;

		err = nextBaseAndAnyMarks(&strA, strALimit, case_sens, unormA, unormAcc, &unormAlen, &unormAstart,
		    bufA, bufAcc, &bufAlen, &needReorderA, &startA);
		if (err != 0) {
			return err;
		}
		err = nextBaseAndAnyMarks(&strB, strBLimit, case_sens, unormB, unormBcc, &unormBlen, &unormBstart,
		    bufB, bufBcc, &bufBlen, &needReorderB, &startB);
		if (err != 0) {
			return err;
		}

		if (bufAlen > 0 || bufBlen > 0) {
			/* Now each buffer should have all of the combining marks up to the next base char.
			 * Normally it will also start with the last base char encountered (unless the
			 * UTF8 string began with a combining mark). */
			/* Now reorder combining marks if necessary. */
			if (needReorderA) {
				doReorder(bufA, bufAcc, bufAlen);
			}
			if (needReorderB) {
				doReorder(bufB, bufBcc, bufBlen);
			}
			/* handle 03B9 pushback */
			int32_t idx;
			if (!case_sens) {
				if (bufAlen > 1 && bufA[bufAlen - 1] == 0x03B9 && unormAstart == 0) {
					int32_t tailCount = 0;
					while (tailCount < kNFCSingleCharDecompMaxPlusPushback - unormAlen && bufAlen > 1 && bufA[bufAlen - 1] == 0x03B9) {
						tailCount++;
						bufAlen--;
					}
					for (idx = unormAlen; idx > 0; idx--) {
						unormA[idx - 1 + tailCount] = unormA[idx - 1];
						unormAcc[idx - 1 + tailCount] = unormAcc[idx - 1];
					}
					for (idx = 0; idx < tailCount; idx++) {
						unormA[idx] = 0x03B9;
						unormAcc[idx] = 0;
					}
					unormAlen += tailCount;
				}
				if (bufBlen > 1 && bufB[bufBlen - 1] == 0x03B9 && unormBstart == 0) {
					int32_t tailCount = 0;
					while (tailCount < kNFCSingleCharDecompMaxPlusPushback - unormBlen && bufBlen > 1 && bufB[bufBlen - 1] == 0x03B9) {
						tailCount++;
						bufBlen--;
					}
					for (idx = unormBlen; idx > 0; idx--) {
						unormB[idx - 1 + tailCount] = unormB[idx - 1];
						unormBcc[idx - 1 + tailCount] = unormBcc[idx - 1];
					}
					for (idx = 0; idx < tailCount; idx++) {
						unormB[idx] = 0x03B9;
						unormBcc[idx] = 0;
					}
					unormBlen += tailCount;
				}
			}
			/* Now compare the buffers. */
			if (bufAlen != bufBlen || memcmp(bufA, bufB, bufAlen * sizeof(bufA[0])) != 0) {
				*are_equal = false;
				return 0;
			}
		}
		/* OK so far, top of loop clears buffers to start refilling again */
	} while ((strA < strALimit || unormAlen > 0) && (strB < strBLimit || unormBlen > 0));

	*are_equal = (strA == strALimit && unormAlen == 0 && strB == strBLimit && unormBlen == 0);
	return 0;
}

/*
 * utf8_normalizeOptCaseFold
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
int
utf8_normalizeOptCaseFold(const char *str,
    size_t      str_len,
    bool        case_sens,
    int32_t    *ustr,
    int32_t     ustr_size,
    int32_t    *ustr_len)
{
	const char *strLimit = str + str_len;
	int32_t *ustrCur = ustr;
	const int32_t *ustrLimit = ustr + ustr_size;

	/* Data for the next pending single-char norm from input;
	 *  This will always begin with a base char (combining class 0) */
	int32_t unorm[kNFCSingleCharDecompMax];
	uint8_t unormcc[kNFCSingleCharDecompMax];
	int32_t unormlen = 0;
	int32_t unormstart = 0;

	bool start = true;

	*ustr_len = 0;
	do {
		/* Data for the buffers being built up from input */
		int32_t buf[kNCFStreamSafeBufMax];
		uint8_t bufcc[kNCFStreamSafeBufMax];
		int32_t buflen = 0;
		bool needReorder = false;
		int err;

		err = nextBaseAndAnyMarks(&str, strLimit, case_sens, unorm, unormcc, &unormlen, &unormstart,
		    buf, bufcc, &buflen, &needReorder, &start);
		if (err != 0) {
			return err;
		}

		if (buflen > 0) {
			if (needReorder) {
				doReorder(buf, bufcc, buflen);
			}
			/* Now copy to output buffer */
			int32_t idx;
			if (ustrCur + buflen > ustrLimit) {
				return ENOMEM;
			}
			for (idx = 0; idx < buflen; idx++) {
				*ustrCur++ = buf[idx];
			}
		}
		/* OK so far, top of loop clears buffers to start refilling again */
	} while (str < strLimit || unormlen > 0);
	*ustr_len = (uint32_t)(ustrCur - ustr); // XXXpjr: the explicit (uint32_t) cast wasn't present in the original code drop
	return 0;
}

/*
 * utf8_normalizeOptCaseFoldToUTF8
 * (This is similar to normalizeOptCaseFold except that this has a different output
 * buffer type, and adds conversion to UTF8 while copying to output buffer)
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
int
utf8_normalizeOptCaseFoldToUTF8(const char *str,
    size_t      str_len,
    bool        case_sens,
    char       *ustr,
    size_t      ustr_size,
    size_t     *ustr_len)
{
	const char *strLimit = str + str_len;
	char *ustrCur = ustr;
	const char *ustrLimit = ustr + ustr_size;

	/* Data for the next pending single-char norm from input;
	 *  This will always begin with a base char (combining class 0) */
	int32_t unorm[kNFCSingleCharDecompMax];
	uint8_t unormcc[kNFCSingleCharDecompMax];
	int32_t unormlen = 0;
	int32_t unormstart = 0;

	bool start = true;

	*ustr_len = 0;
	do {
		/* Data for the buffers being built up from input */
		int32_t buf[kNCFStreamSafeBufMax];
		uint8_t bufcc[kNCFStreamSafeBufMax];
		int32_t buflen = 0;
		bool needReorder = false;
		int err;

		err = nextBaseAndAnyMarks(&str, strLimit, case_sens, unorm, unormcc, &unormlen, &unormstart,
		    buf, bufcc, &buflen, &needReorder, &start);
		if (err != 0) {
			return err;
		}

		if (buflen > 0) {
			uint8_t utf8Bytes[kMaxUTF8BytesPerChar];
			int32_t *bufPtr = buf;
			if (needReorder) {
				doReorder(buf, bufcc, buflen);
			}
			/* Now copy to output buffer */
			while (buflen-- > 0) {
				int32_t idx, utf8Len = u32CharToUTF8Bytes((uint32_t)*bufPtr++, utf8Bytes);
				if (ustrCur + utf8Len > ustrLimit) {
					return ENOMEM;
				}
				for (idx = 0; idx < utf8Len; idx++) {
					*ustrCur++ = (char)utf8Bytes[idx];
				}
			}
		}
		/* OK so far, top of loop clears buffers to start refilling again */
	} while (str < strLimit || unormlen > 0);
	*ustr_len = ustrCur - ustr;
	return 0;
}

/*
 * utf8_normalizeOptCaseFoldAndMatchSubstring
 *
 * strA:      A UTF-8 string (need not be 0 terminated) in which to search for the
 *            substring specified by ustrB.
 * strA_len:  The byte length of strA (excluding any 0 terminator)
 * ustrB:     A normalized UTF-32 substring (need not be 0 terminated) to be searched
 *            for in the UTF-32 string resulting from converting strA to the normalized
 *            UTF-32 form specified by the case_sens parameter; ustrB must already be
 *            in that form.
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
int
utf8_normalizeOptCaseFoldAndMatchSubstring(const char    *strA,
    size_t         strA_len,
    const int32_t *ustrB,
    int32_t        ustrB_len,
    bool           case_sens,
    void          *buf,
    size_t         buf_size,
    bool          *has_match)
{
	/*
	 * ustrA represents the current position in the UTF-32 normalized version of strA
	 * at which we want to test for a match; ustrANormEnd is the position beyond that
	 * which is just after the end of what has already been converted from strA to
	 * UTF-32 normalized form.
	 * Each time through the main loop:
	 * - The first task is to make sure we have enough of strA converted to UTF32
	 *   normalized form to test for match with ustrB at the current match position.
	 *   If we don't, then convert more of strA to UTF-32 normalized form until we
	 *   have enough to compare with ustrB. To do this, run a loop which is like the
	 *   main loop in utf8_normalizeOptCaseFoldAndHash except that in step 4, instead of
	 *   calling the hash function, we copy the normalized buffer to ustrANormEnd,
	 *   advancing the latter. We keep doing this until we have enough additional
	 *   converted to match with ustrB.
	 * - Then we test for match of ustrB at the current ustrA position. If there is
	 *   a match we return; otherwise, if there is more strA to convert we advance
	 *   ustrA  and repeat the main loop, otherwise we return without a match.
	 */
	if (ustrB_len == 0) { /* always matches */
		*has_match = true;
		return 0;
	}
	*has_match = false; /* initialize return value */
	if (ustrB_len > 2 * strA_len) {
		/* If ustrB is clearly too long to find in strA, don't bother normalizing strA.
		 * A UTF-8 character of 1 byte (ASCII) will normalize to 1 UTF-32 unit.
		 * A UTF-8 character of 2-4 bytes will normalize to a maximum of 4 UTF-32 units.
		 * The maximum expansion from unnormalized UTF-8 byte length to normalized
		 *  UTF-32 unit length is thus 2. */
		return 0;
	}

	const char *strALimit = strA + strA_len;
	int32_t *ustrA = (int32_t *)buf;
	const int32_t *ustrALimit = ustrA + (buf_size / sizeof(int32_t));
	int32_t *ustrANormEnd = ustrA; /* how far we have already normalized in ustrA */

	/* Data for the next pending single-char norms from each input;
	 *  These will always begin with a base char (combining class 0)
	 *  or the first character in the string, which may not be a base */
	int32_t unormA[kNFCSingleCharDecompMax];
	uint8_t unormAcc[kNFCSingleCharDecompMax];
	int32_t unormAlen = 0;
	int32_t unormAstart = 0;

	bool startA = true;

	while (true) {
		/* convert enough more of strA to normalized UTF-32 in ustrA to check for match */
		if (ustrANormEnd - ustrA < ustrB_len) {
			do {
				/* Data for the buffers being built up from each input */
				int32_t bufA[kNCFStreamSafeBufMax];
				uint8_t bufAcc[kNCFStreamSafeBufMax];
				int32_t bufAlen = 0;
				bool needReorderA = false;
				int err;

				err = nextBaseAndAnyMarks(&strA, strALimit, case_sens, unormA, unormAcc, &unormAlen, &unormAstart,
				    bufA, bufAcc, &bufAlen, &needReorderA, &startA);
				if (err != 0) {
					return err;
				}

				if (bufAlen > 0) {
					/* Now each buffer should have all of the combining marks up to the next base char.
					 * Normally it will also start with the last base char encountered (unless the
					 * UTF8 string began with a combining mark). */
					/* Now reorder combining marks if necessary. Should be rare, and sequences should
					 * usually be short when does occur => simple bubblesort should be sufficient. */
					if (needReorderA) {
						doReorder(bufA, bufAcc, bufAlen);
					}
					/* Now copy to working buffer */
					int32_t idx;
					if (ustrANormEnd + bufAlen > ustrALimit) {
						return ENOMEM;
					}
					for (idx = 0; idx < bufAlen; idx++) {
						*ustrANormEnd++ = bufA[idx];
					}
				}
				/* OK so far, top of loop clears buffers to start refilling again */
			} while ((ustrANormEnd - ustrA < ustrB_len) && (strA < strALimit || unormAlen > 0));
		}

		if (ustrANormEnd - ustrA < ustrB_len) {
			return 0; /* not enough of strA left for match */
		}
		/* check for match, return if so */
		if (memcmp(ustrA, ustrB, ustrB_len * sizeof(ustrB[0])) == 0) {
			*has_match = true;
			return 0;
		}
		ustrA++; /* advance match position */
	}
}

/* nextBaseAndAnyMarks:
 * Guts of code to get next bufferful of base character (or first char in string)
 * and all trailing combining marks.
 * This is called each time through the main loop of functions above, and does the
 * following:
 * 1. If there are characters available in the normalization result buffer (from the
 *    result of normalizing a previous input character), copy the first character and
 *    any following characters that have non-zero combining class to the main buffer.
 * 2. If there is nothing left in the normalization buffer, then loop processing
 *    input characters as follows:
 *   a) Get the next input character from UTF8, get its normalized and case-folded
 *      result in the normalization buffer.
 *   b) If the first character in the normalization buffer has combining class 0,
 *      break; we will handle this normalization buffer next time through the main
 *      loop.
 *   c) Else copy the current normalization buffer (which has only combining marks)
 *      to the main buffer, and continue with the loop processing input characters.
 */

static int
nextBaseAndAnyMarks(const char** strP, const char *strLimit, bool case_sens,
    int32_t* unorm, uint8_t* unormcc, int32_t* unormlenP, int32_t* unormstartP,
    int32_t* buf, uint8_t* bufcc, int32_t* buflenP,
    bool* needReorderP, bool* startP)
{
	/* update buffers for str */
	if (*unormlenP > 0 && *unormstartP < *unormlenP) {
		/* unorm begins with a base char; buflen should be 0 */
		*needReorderP = false;
		for (*buflenP = 0; true;) {
			if (*buflenP > 0 && unormcc[*unormstartP] > 0 && unormcc[*unormstartP] < bufcc[(*buflenP) - 1]) {
				*needReorderP = true;
			}
			buf[*buflenP] = unorm[*unormstartP];
			bufcc[(*buflenP)++] = unormcc[(*unormstartP)++];
			if (*unormstartP >= *unormlenP || unormcc[*unormstartP] == 0) {
				break;
			}
		}
	}
	if (*unormstartP >= *unormlenP) {
		*unormstartP = *unormlenP = 0;
		while (*strP < strLimit) {
			int32_t idx;
			uint32_t bytevalue = (uint8_t)*(*strP)++;
			/* '/' is not produced by NFD decomposition from another character so we can
			 * check for it before normalization */
			if (bytevalue == 0 || bytevalue == 0x2F /*'/'*/) {
				return EILSEQ;
			}
			if (bytevalue < 0x80) {
				unorm[0] = (!case_sens && bytevalue >= 'A' && bytevalue <= 'Z')? bytevalue += 0x20: bytevalue;
				*unormlenP = 1;
				unormcc[0] = 0;
				*startP = false;
				break;
			} else {
				int32_t u32char = utf8ToU32Code(bytevalue, strP, strLimit);
				if (u32char <= 0) {
					return EILSEQ;
				}
				*unormlenP = normalizeOptCaseFoldU32Char(u32char, case_sens, unorm, unormcc);
				if (*unormlenP <= 0) {
					return EILSEQ;
				}
				if (unormcc[0] == 0 || *startP) {
					*startP = false;
					break;
				}
			}
			/* the latest char decomposes to just combining sequence, add to buffer being built */
			if (*buflenP + *unormlenP > kNCFStreamSafeBufMax) {
				return EILSEQ;
			}
			for (idx = 0; idx < *unormlenP; idx++, (*buflenP)++) {
				if (*buflenP > 0 && unormcc[idx] > 0 && unormcc[idx] < bufcc[(*buflenP) - 1]) {
					*needReorderP = true;
				}
				buf[*buflenP] = unorm[idx];
				bufcc[*buflenP] = unormcc[idx];
			}
			*unormlenP = 0;
		}
	}
	return 0;
}

/*  local prototypes used only by internal functions */
static void swapBufCharCCWithPrevious(int32_t jdx, int32_t buf[], uint8_t bufcc[]);
static int32_t adjustCase(bool case_sens, int32_t uSeqLen,
    int32_t u32NormFoldBuf[kNFCSingleCharDecompMax]);
static uint8_t getCombClassU32Char(int32_t u32char);
static int32_t decomposeHangul(int32_t u32char, int32_t u32NormFoldBuf[kNFCSingleCharDecompMax]);

/* Reorder combining marks if necessary. Should be rare, and sequences should
 * usually be short when does occur => simple bubblesort should be sufficient. */
void
doReorder(int32_t* buf, uint8_t* bufcc, int32_t buflen)
{
	int32_t idx, jdx;
	for (idx = 0; idx < buflen - 1; idx++) {
		for (jdx = buflen - 1; jdx > idx; jdx--) {
			if (bufcc[jdx] < bufcc[jdx - 1]) {
				swapBufCharCCWithPrevious(jdx, buf, bufcc);
			}
		}
	}
}
/*  swap function for bubblesort */
static void
swapBufCharCCWithPrevious(int32_t jdx, int32_t buf[], uint8_t bufcc[])
{
	int32_t bufchar = buf[jdx];
	uint8_t bufccval = bufcc[jdx];
	buf[jdx] = buf[jdx - 1];
	bufcc[jdx] = bufcc[jdx - 1];
	buf[jdx - 1] = bufchar;
	bufcc[jdx - 1] = bufccval;
}

/*
 * u32CharToUTF8Bytes, map a valid Unicode character (UTF32 code point) to 1..4 UTF8 bytes,
 * and returns the number of UTF8 bytes.
 *
 * adapted from ICU macro U8_APPEND_UNSAFE (utf8.h).
 */
int32_t
u32CharToUTF8Bytes(uint32_t u32char, uint8_t utf8Bytes[kMaxUTF8BytesPerChar])
{
	int32_t idx = 0;
	if (u32char <= 0x7F) {
		utf8Bytes[idx++] = (uint8_t)u32char;
	} else {
		if (u32char <= 0x7FF) {
			utf8Bytes[idx++] = (uint8_t)((u32char >> 6) | 0xC0);
		} else {
			if (u32char <= 0xFFFF) {
				utf8Bytes[idx++] = (uint8_t)((u32char >> 12) | 0xE0);
			} else {
				utf8Bytes[idx++] = (uint8_t)((u32char >> 18) | 0xF0);
				utf8Bytes[idx++] = (uint8_t)(((u32char >> 12) & 0x3F) | 0x80);
			}
			utf8Bytes[idx++] = (uint8_t)(((u32char >> 6) & 0x3F) | 0x80);
		}
		utf8Bytes[idx++] = (uint8_t)((u32char & 0x3F) | 0x80);
	}
	return idx;
}

/* two macros adapted from ICU's utf8.h */
#define U8_COUNT_TRAIL_BYTES_LOC(leadByte) \
((uint8_t)(leadByte)<0XF0 ? \
((uint8_t)(leadByte)>=0XC0)+((uint8_t)(leadByte)>=0XE0) : \
(uint8_t)(leadByte)<0XFE ? 3+((uint8_t)(leadByte)>=0XF8)+((uint8_t)(leadByte)>=0XFC) : 0)

#define U8_MASK_LEAD_BYTE_LOC(leadByte, countTrailBytes) ((leadByte)&=(1<<(6-(countTrailBytes)))-1)

/* array adapted from ICU's utf_impl.c */
static const int32_t utf8_minLegal[4] = { 0, 0X80, 0x800, 0x10000 };

/*
 * utf8ToU32Code, map a non-ASCII byte value plus a buffer of trail bytes to a UTF32 code point
 *
 * adapted from ICU macro U8_NEXT (utf8.h) and function utf8_nextCharSafeBody (utf_impl.c);
 * verified to produce the same results (adusted for the difference in API signature).
 *
 * assumes at entry that:
 * 1. a non-ASCII byte value (>= 0x80) that purports to be the beginning of a UTF8 character
 *    has been read, and its value is in u32char
 * 2. *srcPtr points to the input buffer just after that non-ASCII byte, i.e. it purportedly
 *    points to the trail bytes for that UTF8 char.
 * 3. srcLimit points to end of the input buffer (just after the last byte in the buffer)
 *
 * For a valid and complete UTF8 character, the function returns its value and advances
 * *srcPtr to the first byte after the UTF8 char. Otherwise, the function returns -1
 * (and the value in *srcPtr is undefined).
 * Note that while it does not map to surrogate values (generates an error for malformed
 * UTF-8 that would map to values in 0xD800..0xD8FF), it does output noncharacter values
 * whose low 16 bits are 0xFFFE or 0xFFFF without generating an error.
 *
 * equivalences used in adapted ICU code:
 * UChar = uint16_t
 * UChar32 = int32_t
 *
 * This has been validated against ICU behavior.
 */
STATIC_UNLESS_TEST
int32_t
utf8ToU32Code(int32_t u32char, const char** srcPtr, const char* srcLimit)
{
	const char* src = *srcPtr;
	uint8_t pt1, pt2;
	if (0xE0 < u32char && u32char <= 0xEC && src + 1 < srcLimit && (pt1 = (uint8_t)(src[0] - 0x80)) <= 0x3F && (pt2 = (uint8_t)(src[1] - 0x80)) <= 0x3F) {
		/* handle U+1000..U+CFFF */
		/* no need for (u32char&0xF) because the upper bits are truncated after <<12 in the cast to (uint16_t) */
		u32char = (uint16_t)((u32char << 12) | (pt1 << 6) | pt2);
		src += 2;
	} else if (u32char < 0xE0 && u32char >= 0xC2 && src < srcLimit && (pt1 = (uint8_t)(src[0] - 0x80)) <= 0x3F) {
		/* handle U+0080..U+07FF */
		u32char = ((u32char & 0x1F) << 6) | pt1;
		src++;
	} else {
		/* "complicated" and error cases, adapted from ICU's utf8_nextCharSafeBody() */
		uint8_t count = U8_COUNT_TRAIL_BYTES_LOC(u32char);
		if (src + count <= srcLimit) {
			uint8_t trail;

			U8_MASK_LEAD_BYTE_LOC(u32char, count);
			switch (count) {
			/* branches 3, 2 fall through to the next one */
			case 0:         /* count==0 for illegally leading trail bytes and the illegal bytes 0XFE and 0XFF */
			case 5:
			case 4:          /* count>=4 is always illegal: no more than 3 trail bytes in Unicode's UTF-8 */
				break;
			case 3:
				trail = *src++ - 0X80;
				u32char = (u32char << 6) | trail;
				/* u32char>=0x110 would result in code point>0x10FFFF, outside Unicode */
				if (u32char >= 0x110 || trail > 0X3F) {
					break;
				}
			case 2:
				trail = *src++ - 0X80;
				u32char = (u32char << 6) | trail;
				/*
				 * test for a surrogate D800..DFFF:
				 * before the last (u32char<<6), a surrogate is u32char=360..37F
				 */
				if (((u32char & 0xFFE0) == 0x360) || trail > 0X3F) {
					break;
				}
			case 1:
				trail = *src++ - 0X80;
				u32char = (u32char << 6) | trail;
				if (trail > 0X3F) {
					break;
				}
				/* correct sequence - all trail bytes have (b7..b6)==(10) */
				if (u32char >= utf8_minLegal[count]) {
					*srcPtr = src;
					return u32char;
				}
				/* no default branch to optimize switch()  - all values are covered */
			}
		}
		u32char = -1;
	}
	*srcPtr = src;
	return u32char;
}

/*
 * normalizeCaseFoldU32Code, map a single UTF32 code point to its normalized result
 * and the combining classes for each resulting char, or indicate it is invalid.
 *
 * The normalized and case-folded result might be up to 4 UTF32 characters (current
 * max, could change in the future).
 *
 * u32char - input UTF32 code point
 * case_sens - false for case insensiive => casefold, true for case sensitive => NFD only
 * u32NormFoldBuf - output buffer of length kNFCSingleCharDecompMax (assume to be at least 3)
 *          to receive the normalize result.
 * combClass - output buffer of length kNFCSingleCharDecompMax (assume to be at least 3)
 *          to receive the combining classes for the characters in u32NormFoldBuf. If
 *          the first entry has non-zero combining class, the remaining entries do too.
 *
 * returns -1 if input code point is invalid, 0 if the buffer length kNFCSingleCharDecompMax
 * is insufficient (though it is assumed to be at least 3), else the length of the
 * normalized and case-folded result (currently in the range 1..4).
 *
 * This has been validated against ICU behavior.
 *
 * This function is highly dependent on the structure of the data trie; for details on
 * that structure, see comments in normalizeCaseFoldData.h
 */
STATIC_UNLESS_TEST
int32_t
normalizeOptCaseFoldU32Char(int32_t u32char, bool case_sens,
    int32_t u32NormFoldBuf[kNFCSingleCharDecompMax],
    uint8_t combClass[kNFCSingleCharDecompMax])
{
	combClass[0] = 0;
	/*  return hi-range PUA as self, except non-characters */
	if (u32char >= kU32HiPUAStart) {
		if ((u32char & 0xFFFE) == 0xFFFE) {
			return -1;
		}
		u32NormFoldBuf[0] = u32char;
		return 1;
	}
	/*  for trie lookup, shift the range 0xE0000-0xE01FF down to be just after the range */
	/*  0 - 0x313FF; everything in between in currently invalid. */
	int32_t u32charLookup = u32char;
	if (u32charLookup >= kU32LowRangeLimit) {
		u32charLookup -= (kU32HiRangeStart - kU32LowRangeLimit);
		if (u32charLookup < kU32LowRangeLimit || u32charLookup >= (kU32LowRangeLimit + kU32HiRangeLen)) {
			return -1; /* in the large range of currently-unassigned code points */
		}
	}
	/* Now we have u32charLookup either in 0..0x313FF representing u32char itself,
	 *  or in 0x31400..0x315FF representing u32char 0xE0000..0xE01FF; look it up in
	 *  the trie that identifies unassigneds in this range, or maps others to
	 *  decomps or combining class or just self. */
	uint16_t trieValue;
	/*  TrieHi */
	trieValue = nfTrieHi[u32charLookup >> kNFTrieHiShift];
	if (trieValue == kInvalidCodeFlag) {
		return -1;
	}
	if (trieValue == 0 || (trieValue & kFlagTestMask) == kCombClassFlag) { /*  return self; */
		u32NormFoldBuf[0] = u32char;
		combClass[0] = trieValue & kFlagValueMask;
		return 1;
	}
	if (trieValue == kHangulMask) {
		combClass[1] = combClass[2] = 0;
		return decomposeHangul(u32char, u32NormFoldBuf);
	}
	/*  TrieMid */
	trieValue = nfTrieMid[trieValue & kNextIndexValueMask][(u32charLookup >> kNFTrieMidShift) & kNFTrieMidMask];
	if (trieValue == kInvalidCodeFlag) {
		return -1;
	}
	if (trieValue == 0 || (trieValue & kFlagTestMask) == kCombClassFlag) {
		u32NormFoldBuf[0] = u32char;
		combClass[0] = trieValue & kFlagValueMask;
		return adjustCase(case_sens, 1, u32NormFoldBuf);
	}
	if ((trieValue & kFlagTestMask) == kInvMaskFlag) {
		uint16_t invalidMask = nfU16InvMasks[trieValue & kFlagValueMask];
		uint16_t testBit = (uint16_t)(1 << (u32charLookup & kNFTrieLoMask));
		if (testBit & invalidMask) {
			/* invalid */
			return -1;
		} else {
			/* treat like trieValue == 0 above */
			u32NormFoldBuf[0] = u32char;
			return adjustCase(case_sens, 1, u32NormFoldBuf);;
		}
	}
	if (trieValue == kHangulMask) {
		combClass[1] = combClass[2] = 0;
		return decomposeHangul(u32char, u32NormFoldBuf);
	}
	/*  TrieLo */
	trieValue = nfTrieLo[trieValue & kNextIndexValueMask][u32charLookup & kNFTrieLoMask];
	if (trieValue == kInvalidCodeFlag) {
		return -1;
	}
	if (trieValue == kHangulMask) {
		combClass[1] = combClass[2] = 0;
		return decomposeHangul(u32char, u32NormFoldBuf);
	}
	if (trieValue < kToU16Seq2Mask || trieValue > kSpecialsEnd) {
		if (trieValue == 0 || (trieValue & kFlagTestMask) == kCombClassFlag) {
			u32NormFoldBuf[0] = u32char;
			combClass[0] = trieValue & kFlagValueMask;
		} else {
			u32NormFoldBuf[0] = trieValue;
		}
		return adjustCase(case_sens, 1, u32NormFoldBuf);;
	}
	const uint16_t* u16SeqPtr = NULL;
	const int32_t*  u32SeqPtr = NULL;
	int32_t         uSeqLen = 0;
	switch (trieValue & kSpecialsMask) {
	case kToU16Seq2Mask:
		if (case_sens && (trieValue & kToSeqCaseFoldMask)) {
			/* don't use the mapping, it is only for case folding */
			u32NormFoldBuf[0] = u32char;
			/* already have combClass[0] = 0 */
			return 1;
		}
		u16SeqPtr = nfU16Seq2[trieValue & kToSeqIndexMask];
		uSeqLen = 2;
		break;
	case kToU16Seq3Mask:
		if (case_sens && (trieValue & kToSeqCaseFoldMask)) {
			/* don't use the mapping, it is only for case folding */
			u32NormFoldBuf[0] = u32char;
			/* already have combClass[0] = 0 */
			return 1;
		}
		u16SeqPtr = nfU16Seq3[trieValue & kToSeqIndexMask];
		uSeqLen = 3;
		break;
	case kToU16SeqMiscMask:
		u16SeqPtr = &nfU16SeqMisc[trieValue & kToSeqMiscIndexMask];
		uSeqLen = *u16SeqPtr & kToSeqMiscLenMask;
		combClass[0] = (uint8_t)(*u16SeqPtr++ >> kToSeqMiscCCShift);
		break;
	case kToU32CharMask:
		if (case_sens && (trieValue & kToSeqCaseFoldMask)) {
			/* don't use the mapping, it is only for case folding */
			u32NormFoldBuf[0] = u32char;
			/* already have combClass[0] = 0 */
			return 1;
		}
		u32SeqPtr = &nfU32Char[trieValue & kToSeqIndexMask];
		uSeqLen = 1;
		break;
	case kToU32SeqMiscMask:
		u32SeqPtr = &nfU32SeqMisc[trieValue & kToSeqMiscIndexMask];
		uSeqLen = *u32SeqPtr & kToSeqMiscLenMask;
		combClass[0] = (uint8_t)(*u32SeqPtr++ >> kToSeqMiscCCShift);
		break;
	default:
		return -1;
	}
	if (kNFCSingleCharDecompMax < uSeqLen) {
		return 0;
	}
	int32_t idx;
	for (idx = 0; idx < uSeqLen; idx++) {
		u32NormFoldBuf[idx] = (u16SeqPtr)? *u16SeqPtr++: *u32SeqPtr++;
		if (idx > 0) {
			combClass[idx] = getCombClassU32Char(u32NormFoldBuf[idx]);
		}
	}
	return adjustCase(case_sens, uSeqLen, u32NormFoldBuf);
}

/*
 * adjustCase, final adjustments to normalizeOptCaseFoldU32Char for case folding
 *
 * case_sens - false for case insensiive => casefold, true for case sensitive => NFD only
 * uSeqLen - length of the sequence specified in the u32NormFoldBuf
 * u32NormFoldBuf - buffer of length kNFCSingleCharDecompMax (assume to be at least 3)
 *          with normalized result.
 *
 * returns uSeqLen if input code point is invalid, 0 if the buffer length kNFCSingleCharDecompMax
 * is insufficient (though it is assumed to be at least 3), else the length of the
 * normalized and case-folded result (currently in the range 1..4).
 *
 * This function is a reduced version of normalizeOptCaseFoldU32Char above.
 */

static int32_t
adjustCase(bool case_sens, int32_t uSeqLen,
    int32_t u32NormFoldBuf[kNFCSingleCharDecompMax])
{
	if (!case_sens && uSeqLen > 0) {
		if (u32NormFoldBuf[0] < kSimpleCaseFoldLimit) {
			u32NormFoldBuf[0] = nfBasicCF[u32NormFoldBuf[0]];
			/* There is one case in which this maps to a character with different combining
			 * class: U+0345 (cc 240) casefolds to U+03B9 (cc 0). However when this is the
			 * first or only character in the sequence, we want to keep the original
			 * combining class, so nothing special to do here.
			 */
		}
		/* The following is the only case where we have a casefolding after the first
		 * character in the sequence. Don't worry about combining class here. that gets
		 * set later for characters after the first.
		 */
		if (uSeqLen > 1 && u32NormFoldBuf[uSeqLen - 1] == 0x0345) {
			u32NormFoldBuf[uSeqLen - 1] = 0x03B9;
		}
	}
	return uSeqLen;
}

/*
 * getCombClassU32Char, map a single character (in UTF32 form) to its combining class.
 *
 * u32char - input UTF32 code point. This is assumed to be a valid character that does
 * not have a decomposition.
 *
 * returns combining class of the character.
 *
 * This is only called for characters after the first is a decomposition expansion. In
 * this situation, if we encounter U+03B9 (combining class 0), it is only there as the
 * case-folding of U+0345 (combining class 240). In this case it is the combining class
 * for U+0345 that we want. In the non-casefold case we won't see U+03B9 here at all.
 *
 * This function is a reduced version of normalizeOptCaseFoldU32Char above.
 */
static uint8_t
getCombClassU32Char(int32_t u32char)
{
	if (u32char >= kU32HiPUAStart) {
		return 0;
	}
	if (u32char == 0x03B9) {
		return 240;
	}
	/*  for trie lookup, shift the range 0xE0000-0xE01FF down to be just after the range */
	/*  0 - 0x313FF; everything in between in currently invalid. */
	int32_t u32charLookup = u32char;
	if (u32charLookup >= kU32LowRangeLimit) {
		u32charLookup -= (kU32HiRangeStart - kU32LowRangeLimit);
	}
	/* Now we have u32charLookup either in 0..0x313FF representing u32char itself,
	 *  or in 0x31400..0x315FF representing u32char 0xE0000..0xE01FF; look it up in
	 *  the trie that identifies unassigneds in this range, or maps others to
	 *  decomps or combining class or just self. */
	uint16_t trieValue;
	/*  TrieHi */
	trieValue = nfTrieHi[u32charLookup >> kNFTrieHiShift];
	if (trieValue == 0 || (trieValue & kFlagTestMask) == kCombClassFlag) {
		return trieValue & kFlagValueMask;
	}
	/*  TrieMid */
	trieValue = nfTrieMid[trieValue & kNextIndexValueMask][(u32charLookup >> kNFTrieMidShift) & kNFTrieMidMask];
	if (trieValue == 0 || (trieValue & kFlagTestMask) == kCombClassFlag) { /*  return self; */
		return trieValue & kFlagValueMask;
	}
	if ((trieValue & kFlagTestMask) == kInvMaskFlag) {
		return 0;
	}
	/*  TrieLo */
	trieValue = nfTrieLo[trieValue & kNextIndexValueMask][u32charLookup & kNFTrieMidMask];
	return ((trieValue & kFlagTestMask) == kCombClassFlag)? (trieValue & kFlagValueMask): 0;
}

/*
 * decomposeHangul, map a single UTF32 code point for a composed Hangul
 * in the range AC00-D7A3, using algorithmic decomp
 *
 * The normalized result will be 2 or 3 UTF32 characters.
 *
 * u32char - input UTF32 code point
 * u32NormFoldBuf - output buffer of length kNFCSingleCharDecompMax (assume to be at least 3)
 *          to receive the normalize result.
 *
 * returns the length of the normalized result (2..3).
 *
 * Adapted from ICU Hangul:decompose in normalizer2impl.h
 *
 */

enum {
	HANGUL_BASE=0xAC00,
	JAMO_L_BASE=0x1100,     /* "lead" jamo */
	JAMO_V_BASE=0x1161,     /* "vowel" jamo */
	JAMO_T_BASE=0x11A7,     /* "trail" jamo */
	JAMO_L_COUNT=19,
	JAMO_V_COUNT=21,
	JAMO_T_COUNT=28,
};

static int32_t
decomposeHangul(int32_t u32char, int32_t u32NormFoldBuf[kNFCSingleCharDecompMax])
{
	u32char -= HANGUL_BASE;
	int32_t tIndex = u32char % JAMO_T_COUNT;
	u32char /= JAMO_T_COUNT;
	u32NormFoldBuf[0] = (uint16_t)(JAMO_L_BASE + u32char / JAMO_V_COUNT);
	u32NormFoldBuf[1] = (uint16_t)(JAMO_V_BASE + u32char % JAMO_V_COUNT);
	if (tIndex == 0) {
		return 2;
	}
	u32NormFoldBuf[2] = (uint16_t)(JAMO_T_BASE + tIndex);
	return 3;
}
