/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
 
 /*
 	Includes Unicode 3.2 decomposition code derived from Core Foundation
 */

#include <sys/param.h>
#include <sys/utfconv.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <libkern/OSByteOrder.h>

/*
 * UTF-8 (Unicode Transformation Format)
 *
 * UTF-8 is the Unicode Transformation Format that serializes a Unicode
 * character as a sequence of one to four bytes. Only the shortest form
 * required to represent the significant Unicode bits is legal.
 * 
 * UTF-8 Multibyte Codes
 *
 * Bytes   Bits   Unicode Min  Unicode Max   UTF-8 Byte Sequence (binary)
 * -----------------------------------------------------------------------------
 *   1       7       0x0000        0x007F    0xxxxxxx
 *   2      11       0x0080        0x07FF    110xxxxx 10xxxxxx
 *   3      16       0x0800        0xFFFF    1110xxxx 10xxxxxx 10xxxxxx
 *   4      21      0x10000      0x10FFFF    11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
 * -----------------------------------------------------------------------------
 */


#define UNICODE_TO_UTF8_LEN(c)  \
	((c) < 0x0080 ? 1 : ((c) < 0x0800 ? 2 : (((c) & 0xf800) == 0xd800 ? 2 : 3)))

#define UCS_ALT_NULL	0x2400

/* Surrogate Pair Constants */
#define SP_HALF_SHIFT	10
#define SP_HALF_BASE	0x0010000u
#define SP_HALF_MASK	0x3FFu

#define SP_HIGH_FIRST	0xD800u
#define SP_HIGH_LAST	0xDBFFu
#define SP_LOW_FIRST	0xDC00u
#define SP_LOW_LAST		0xDFFFu


#include "vfs_utfconvdata.h"


/*
 * Test for a combining character.
 *
 * Similar to __CFUniCharIsNonBaseCharacter except that
 * unicode_combinable also includes Hangul Jamo characters.
 */
int
unicode_combinable(u_int16_t character)
{
	const u_int8_t *bitmap = __CFUniCharCombiningBitmap;
	u_int8_t value;

	if (character < 0x0300)
		return (0);

	value = bitmap[(character >> 8) & 0xFF];

	if (value == 0xFF) {
		return (1);
	} else if (value) {
		bitmap = bitmap + ((value - 1) * 32) + 256;
		return (bitmap[(character & 0xFF) / 8] & (1 << (character % 8)) ? 1 : 0);
	}
	return (0);
}

/*
 * Test for a precomposed character.
 *
 * Similar to __CFUniCharIsDecomposableCharacter.
 */
int
unicode_decomposeable(u_int16_t character) {
	const u_int8_t *bitmap = __CFUniCharDecomposableBitmap;
	u_int8_t value;
	
	if (character < 0x00C0)
		return (0);

	value = bitmap[(character >> 8) & 0xFF];

	if (value == 0xFF) {
		return (1);
	} else if (value) {
		bitmap = bitmap + ((value - 1) * 32) + 256;
		return (bitmap[(character & 0xFF) / 8] & (1 << (character % 8)) ? 1 : 0);
	}
    	return (0);
}


/*
 * Get the combing class.
 *
 * Similar to CFUniCharGetCombiningPropertyForCharacter.
 */
static inline u_int8_t
get_combining_class(u_int16_t character) {
	const u_int8_t *bitmap = __CFUniCharCombiningPropertyBitmap;

	u_int8_t value = bitmap[(character >> 8)];

	if (value) {
		bitmap = bitmap + (value * 256);
		return bitmap[character % 256];
	}
	return (0);
}


static int unicode_decompose(u_int16_t character, u_int16_t *convertedChars);

static u_int16_t unicode_combine(u_int16_t base, u_int16_t combining);

static void prioritysort(u_int16_t* characters, int count);

static u_int16_t  ucs_to_sfm(u_int16_t ucs_ch, int lastchar);

static u_int16_t  sfm_to_ucs(u_int16_t ucs_ch);


char utf_extrabytes[32] = {
	 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	-1, -1, -1, -1, -1, -1, -1, -1,  1,  1,  1,  1,  2,  2,  3, -1
};

const char hexdigits[16] = {
	 '0',  '1',  '2',  '3',  '4',  '5',  '6', '7',
	 '8',  '9',  'A',  'B',  'C',  'D',  'E', 'F'
};

/*
 * utf8_encodelen - Calculate the UTF-8 encoding length
 *
 * This function takes a Unicode input string, ucsp, of ucslen bytes
 * and calculates the size of the UTF-8 output in bytes (not including
 * a NULL termination byte). The string must reside in kernel memory.
 *
 * If '/' chars are possible in the Unicode input then an alternate
 * (replacement) char should be provided in altslash.
 *
 * FLAGS
 *    UTF_REVERSE_ENDIAN:  Unicode byte order is opposite current runtime
 *
 *    UTF_BIG_ENDIAN:  Unicode byte order is always big endian
 *
 *    UTF_LITTLE_ENDIAN:  Unicode byte order is always little endian
 *
 *    UTF_DECOMPOSED:  generate fully decomposed output
 *
 *    UTF_PRECOMPOSED is ignored since utf8_encodestr doesn't support it
 *
 * ERRORS
 *    None
 */
size_t
utf8_encodelen(const u_int16_t * ucsp, size_t ucslen, u_int16_t altslash, int flags)
{
	u_int16_t ucs_ch;
	u_int16_t * chp = NULL;
	u_int16_t sequence[8];
	int extra = 0;
	size_t charcnt;
	int swapbytes = (flags & UTF_REVERSE_ENDIAN);
	int decompose = (flags & UTF_DECOMPOSED);
	size_t len;

	charcnt = ucslen / 2;
	len = 0;

	while (charcnt-- > 0) {
		if (extra > 0) {
			--extra;
			ucs_ch = *chp++;
		} else {
			ucs_ch = *ucsp++;
			if (swapbytes) {
				ucs_ch = OSSwapInt16(ucs_ch);
			}
			if (ucs_ch == '/') {
				ucs_ch = altslash ? altslash : '_';
			} else if (ucs_ch == '\0') {
				ucs_ch = UCS_ALT_NULL;
			} else if (decompose && unicode_decomposeable(ucs_ch)) {
				extra = unicode_decompose(ucs_ch, sequence) - 1;
				charcnt += extra;
				ucs_ch = sequence[0];
				chp = &sequence[1];
			}
		}
		len += UNICODE_TO_UTF8_LEN(ucs_ch);
	}

	return (len);
}


/*
 * utf8_encodestr - Encodes a Unicode string to UTF-8
 *
 * NOTES:
 *    The resulting UTF-8 string is NULL terminated.
 *
 *    If '/' chars are allowed on disk then an alternate
 *    (replacement) char must be provided in altslash.
 *
 * input flags:
 *    UTF_REVERSE_ENDIAN: Unicode byteorder is opposite current runtime
 *
 *    UTF_BIG_ENDIAN:  Unicode byte order is always big endian
 *
 *    UTF_LITTLE_ENDIAN:  Unicode byte order is always little endian
 *
 *    UTF_DECOMPOSED:  generate fully decomposed output
 *
 *    UTF_NO_NULL_TERM:  don't add NULL termination to UTF-8 output
 *
 * result:
 *    ENAMETOOLONG: Name didn't fit; only buflen bytes were encoded
 *
 *    EINVAL: Illegal char found; char was replaced by an '_'.
 */
int
utf8_encodestr(const u_int16_t * ucsp, size_t ucslen, u_int8_t * utf8p,
               size_t * utf8len, size_t buflen, u_int16_t altslash, int flags)
{
	u_int8_t * bufstart;
	u_int8_t * bufend;
	u_int16_t ucs_ch;
	u_int16_t * chp = NULL;
	u_int16_t sequence[8];
	int extra = 0;
	size_t charcnt;
	int swapbytes = (flags & UTF_REVERSE_ENDIAN);
	int nullterm  = ((flags & UTF_NO_NULL_TERM) == 0);
	int decompose = (flags & UTF_DECOMPOSED);
	int sfmconv = (flags & UTF_SFM_CONVERSIONS);
	int result = 0;

	bufstart = utf8p;
	bufend = bufstart + buflen;
	if (nullterm)
		--bufend;
	charcnt = ucslen / 2;

	while (charcnt-- > 0) {
		if (extra > 0) {
			--extra;
			ucs_ch = *chp++;
		} else {
			ucs_ch = swapbytes ? OSSwapInt16(*ucsp++) : *ucsp++;

			if (decompose && unicode_decomposeable(ucs_ch)) {
				extra = unicode_decompose(ucs_ch, sequence) - 1;
				charcnt += extra;
				ucs_ch = sequence[0];
				chp = &sequence[1];
			}
		}

		/* Slash and NULL are not permitted */
		if (ucs_ch == '/') {
			if (altslash)
				ucs_ch = altslash;
			else {
				ucs_ch = '_';
				result = EINVAL;
			}
		} else if (ucs_ch == '\0') {
			ucs_ch = UCS_ALT_NULL;
		}

		if (ucs_ch < 0x0080) {
			if (utf8p >= bufend) {
				result = ENAMETOOLONG;
				break;
			}			
			*utf8p++ = ucs_ch;

		} else if (ucs_ch < 0x800) {
			if ((utf8p + 1) >= bufend) {
				result = ENAMETOOLONG;
				break;
			}
			*utf8p++ = 0xc0 | (ucs_ch >> 6);
			*utf8p++ = 0x80 | (0x3f & ucs_ch);

		} else {
			/* These chars never valid Unicode. */
			if (ucs_ch == 0xFFFE || ucs_ch == 0xFFFF) {
				result = EINVAL;
				break;
			}

			/* Combine valid surrogate pairs */
			if (ucs_ch >= SP_HIGH_FIRST && ucs_ch <= SP_HIGH_LAST
				&& charcnt > 0) {
				u_int16_t ch2;
				u_int32_t pair;

				ch2 = swapbytes ? OSSwapInt16(*ucsp) : *ucsp;
				if (ch2 >= SP_LOW_FIRST && ch2 <= SP_LOW_LAST) {
					pair = ((ucs_ch - SP_HIGH_FIRST) << SP_HALF_SHIFT)
						+ (ch2 - SP_LOW_FIRST) + SP_HALF_BASE;
					if ((utf8p + 3) >= bufend) {
						result = ENAMETOOLONG;
						break;
					}
					--charcnt;
					++ucsp;				
					*utf8p++ = 0xf0 | (pair >> 18);
					*utf8p++ = 0x80 | (0x3f & (pair >> 12));
					*utf8p++ = 0x80 | (0x3f & (pair >> 6));
					*utf8p++ = 0x80 | (0x3f & pair);
					continue;
				}
			} else if (sfmconv) {
				ucs_ch = sfm_to_ucs(ucs_ch);
				if (ucs_ch < 0x0080) {
					if (utf8p >= bufend) {
						result = ENAMETOOLONG;
						break;
					}			
					*utf8p++ = ucs_ch;
					continue;
				}
			}
			if ((utf8p + 2) >= bufend) {
				result = ENAMETOOLONG;
				break;
			}
			*utf8p++ = 0xe0 | (ucs_ch >> 12);
			*utf8p++ = 0x80 | (0x3f & (ucs_ch >> 6));
			*utf8p++ = 0x80 | (0x3f & ucs_ch);
		}	
	}
	
	*utf8len = utf8p - bufstart;
	if (nullterm)
		*utf8p++ = '\0';

	return (result);
}

// Pushes a character taking account of combining character sequences
static void push(uint16_t ucs_ch, int *combcharcnt, uint16_t **ucsp)
{
	/*
	 * Make multiple combining character sequences canonical
	 */
	if (unicode_combinable(ucs_ch)) {
		++*combcharcnt;		/* start tracking a run */
	} else if (*combcharcnt) {
		if (*combcharcnt > 1) {
			prioritysort(*ucsp - *combcharcnt, *combcharcnt);
		}
		*combcharcnt = 0;	/* start over */
	}

	*(*ucsp)++ = ucs_ch;
}

/*
 * utf8_decodestr - Decodes a UTF-8 string back to Unicode
 *
 * NOTES:
 *    The input UTF-8 string does not need to be null terminated
 *    if utf8len is set.
 *
 *    If '/' chars are allowed on disk then an alternate
 *    (replacement) char must be provided in altslash.
 *
 * input flags:
 *    UTF_REV_ENDIAN:  Unicode byte order is opposite current runtime
 *
 *    UTF_BIG_ENDIAN:  Unicode byte order is always big endian
 *
 *    UTF_LITTLE_ENDIAN:  Unicode byte order is always little endian
 *
 *    UTF_DECOMPOSED:  generate fully decomposed output (NFD)
 *
 *    UTF_PRECOMPOSED:  generate precomposed output (NFC)
 *
 *    UTF_ESCAPE_ILLEGAL:  percent escape any illegal UTF-8 input
 *
 * result:
 *    ENAMETOOLONG: Name didn't fit; only ucslen chars were decoded.
 *
 *    EINVAL: Illegal UTF-8 sequence found.
 */
int
utf8_decodestr(const u_int8_t* utf8p, size_t utf8len, u_int16_t* ucsp,
               size_t *ucslen, size_t buflen, u_int16_t altslash, int flags)
{
	u_int16_t* bufstart;
	u_int16_t* bufend;
	unsigned int ucs_ch;
	unsigned int byte;
	int combcharcnt = 0;
	int result = 0;
	int decompose, precompose, escaping;
	int sfmconv;
	int extrabytes;

	decompose  = (flags & UTF_DECOMPOSED);
	precompose = (flags & UTF_PRECOMPOSED);
	escaping   = (flags & UTF_ESCAPE_ILLEGAL);
	sfmconv    = (flags & UTF_SFM_CONVERSIONS);

	bufstart = ucsp;
	bufend = (u_int16_t *)((u_int8_t *)ucsp + buflen);

	while (utf8len-- > 0 && (byte = *utf8p++) != '\0') {
		if (ucsp >= bufend)
			goto toolong;

		/* check for ascii */
		if (byte < 0x80) {
			ucs_ch = sfmconv ? ucs_to_sfm(byte, utf8len == 0) : byte;
		} else {
			u_int32_t ch;

			extrabytes = utf_extrabytes[byte >> 3];
			if ((extrabytes < 0) || ((int)utf8len < extrabytes)) {
				goto escape;
			}
			utf8len -= extrabytes;

			switch (extrabytes) {
			case 1:
				ch = byte; ch <<= 6;   /* 1st byte */
				byte = *utf8p++;       /* 2nd byte */
				if ((byte >> 6) != 2)
					goto escape2;
				ch += byte;
				ch -= 0x00003080UL;
				if (ch < 0x0080)
					goto escape2;
				ucs_ch = ch;
			        break;
			case 2:
				ch = byte; ch <<= 6;   /* 1st byte */
				byte = *utf8p++;       /* 2nd byte */
				if ((byte >> 6) != 2)
					goto escape2;
				ch += byte; ch <<= 6;
				byte = *utf8p++;       /* 3rd byte */
				if ((byte >> 6) != 2)
					goto escape3;
				ch += byte;
				ch -= 0x000E2080UL;
				if (ch < 0x0800)
					goto escape3;
				if (ch >= 0xD800) {
					if (ch <= 0xDFFF)
						goto escape3;
					if (ch == 0xFFFE || ch == 0xFFFF)
						goto escape3;
				}
				ucs_ch = ch;
				break;
			case 3:
				ch = byte; ch <<= 6;   /* 1st byte */
				byte = *utf8p++;       /* 2nd byte */
				if ((byte >> 6) != 2)
					goto escape2;
				ch += byte; ch <<= 6;
				byte = *utf8p++;       /* 3rd byte */
				if ((byte >> 6) != 2)
					goto escape3;
				ch += byte; ch <<= 6;
				byte = *utf8p++;       /* 4th byte */
				if ((byte >> 6) != 2)
					goto escape4;
			        ch += byte;
				ch -= 0x03C82080UL + SP_HALF_BASE;
				ucs_ch = (ch >> SP_HALF_SHIFT) + SP_HIGH_FIRST;
				if (ucs_ch < SP_HIGH_FIRST || ucs_ch > SP_HIGH_LAST)
					goto escape4;
				push(ucs_ch, &combcharcnt, &ucsp);
				if (ucsp >= bufend)
					goto toolong;
				ucs_ch = (ch & SP_HALF_MASK) + SP_LOW_FIRST;
				if (ucs_ch < SP_LOW_FIRST || ucs_ch > SP_LOW_LAST) {
					--ucsp;
					goto escape4;
				}
				*ucsp++ = ucs_ch;
			        continue;
			default:
				result = EINVAL;
				goto exit;
			}
			if (decompose) {
				if (unicode_decomposeable(ucs_ch)) {
					u_int16_t sequence[8];
					int count, i;

					count = unicode_decompose(ucs_ch, sequence);

					for (i = 0; i < count; ++i) {
						if (ucsp >= bufend)
							goto toolong;

						push(sequence[i], &combcharcnt, &ucsp);
					}

					continue;
				}
			} else if (precompose && (ucsp != bufstart)) {
				u_int16_t composite, base;

				if (unicode_combinable(ucs_ch)) {
					base = ucsp[-1];
					composite = unicode_combine(base, ucs_ch);
					if (composite) {
						--ucsp;
						ucs_ch = composite;
					}
				}
			}
			if (ucs_ch == UCS_ALT_NULL)
				ucs_ch = '\0';
		}
		if (ucs_ch == altslash)
			ucs_ch = '/';

		push(ucs_ch, &combcharcnt, &ucsp);
		continue;

		/* 
		 * Escape illegal UTF-8 into something legal.
		 */
escape4:
		utf8p -= 3;
		goto escape;
escape3:
		utf8p -= 2;
		goto escape;
escape2:
		utf8p -= 1;
escape:
		if (!escaping) {
			result = EINVAL;
			goto exit;
		}
		if (extrabytes > 0)
			utf8len += extrabytes;
		byte = *(utf8p - 1);

		if ((ucsp + 2) >= bufend)
			goto toolong;

		/* Make a previous combining sequence canonical. */
		if (combcharcnt > 1) {
			prioritysort(ucsp - combcharcnt, combcharcnt);
		}
		combcharcnt = 0;
		
		ucs_ch = '%';
		*ucsp++ = ucs_ch;
		ucs_ch =  hexdigits[byte >> 4];
		*ucsp++ = ucs_ch;
		ucs_ch =  hexdigits[byte & 0x0F];
		*ucsp++ = ucs_ch;
	}
	/*
	 * Make a previous combining sequence canonical
	 */
	if (combcharcnt > 1) {
		prioritysort(ucsp - combcharcnt, combcharcnt);
	}

	if (flags & UTF_REVERSE_ENDIAN) {
		uint16_t *p = bufstart;
		while (p < ucsp) {
			*p = OSSwapInt16(*p);
			++p;
		}
	}

exit:
	*ucslen = (u_int8_t*)ucsp - (u_int8_t*)bufstart;

	return (result);

toolong:
	result = ENAMETOOLONG;
	goto exit;
}


/*
 * utf8_validatestr - Check for a valid UTF-8 string.
 */
int
utf8_validatestr(const u_int8_t* utf8p, size_t utf8len)
{
	unsigned int byte;
	u_int32_t ch;
	unsigned int ucs_ch;
	size_t extrabytes;

	while (utf8len-- > 0 && (byte = *utf8p++) != '\0') {
		if (byte < 0x80)
			continue;  /* plain ascii */

		extrabytes = utf_extrabytes[byte >> 3];

		if (utf8len < extrabytes)
			goto invalid;
		utf8len -= extrabytes;

		switch (extrabytes) {
		case 1:
			ch = byte; ch <<= 6;   /* 1st byte */
			byte = *utf8p++;       /* 2nd byte */
			if ((byte >> 6) != 2)
				goto invalid;
			ch += byte;
			ch -= 0x00003080UL;
			if (ch < 0x0080)
				goto invalid;
			break;
		case 2:
			ch = byte; ch <<= 6;   /* 1st byte */
			byte = *utf8p++;       /* 2nd byte */
			if ((byte >> 6) != 2)
				goto invalid;
			ch += byte; ch <<= 6;
			byte = *utf8p++;       /* 3rd byte */
			if ((byte >> 6) != 2)
				goto invalid;
			ch += byte;
			ch -= 0x000E2080UL;
			if (ch < 0x0800)
				goto invalid;
			if (ch >= 0xD800) {
				if (ch <= 0xDFFF)
					goto invalid;
				if (ch == 0xFFFE || ch == 0xFFFF)
					goto invalid;
			}
			break;
		case 3:
			ch = byte; ch <<= 6;   /* 1st byte */
			byte = *utf8p++;       /* 2nd byte */
			if ((byte >> 6) != 2)
				goto invalid;
			ch += byte; ch <<= 6;
			byte = *utf8p++;       /* 3rd byte */
			if ((byte >> 6) != 2)
				goto invalid;
			ch += byte; ch <<= 6;
			byte = *utf8p++;       /* 4th byte */
			if ((byte >> 6) != 2)
				goto invalid;
			ch += byte;
			ch -= 0x03C82080UL + SP_HALF_BASE;
			ucs_ch = (ch >> SP_HALF_SHIFT) + SP_HIGH_FIRST;
			if (ucs_ch < SP_HIGH_FIRST || ucs_ch > SP_HIGH_LAST)
				goto invalid;
			ucs_ch = (ch & SP_HALF_MASK) + SP_LOW_FIRST;
			if (ucs_ch < SP_LOW_FIRST || ucs_ch > SP_LOW_LAST)
				goto invalid;
			break;
		default:
			goto invalid;
		}
		
	}
	return (0);
invalid:
	return (EINVAL);
}

/*
 * utf8_normalizestr - Normalize a UTF-8 string (NFC or NFD)
 *
 * This function takes an UTF-8 input string, instr, of inlen bytes
 * and produces normalized UTF-8 output into a buffer of buflen bytes
 * pointed to by outstr. The size of the output in bytes (not including
 * a NULL termination byte) is returned in outlen. In-place conversions
 * are not supported (i.e. instr != outstr).]
 
 * FLAGS
 *    UTF_DECOMPOSED:  output string will be fully decomposed (NFD)
 *
 *    UTF_PRECOMPOSED:  output string will be precomposed (NFC)
 *
 *    UTF_NO_NULL_TERM:  do not add null termination to output string
 *
 *    UTF_ESCAPE_ILLEGAL:  percent escape any illegal UTF-8 input
 *
 * ERRORS
 *    ENAMETOOLONG:  output did not fit or input exceeded MAXPATHLEN bytes
 *
 *    EINVAL:  illegal UTF-8 sequence encountered or invalid flags
 */
int
utf8_normalizestr(const u_int8_t* instr, size_t inlen, u_int8_t* outstr,
                  size_t *outlen, size_t buflen, int flags)
{
	u_int16_t unicodebuf[32];
	u_int16_t* unistr = NULL;
	size_t unicode_bytes;
	size_t uft8_bytes;
	size_t inbuflen;
	u_int8_t *outbufstart, *outbufend;
	const u_int8_t *inbufstart;
	unsigned int byte;
	int decompose, precompose;
	int result = 0;

	if (flags & ~(UTF_DECOMPOSED | UTF_PRECOMPOSED | UTF_NO_NULL_TERM | UTF_ESCAPE_ILLEGAL)) {
		return (EINVAL);
	}
	decompose = (flags & UTF_DECOMPOSED);
	precompose = (flags & UTF_PRECOMPOSED);
	if ((decompose && precompose) || (!decompose && !precompose)) {
		return (EINVAL);
	}
	outbufstart = outstr;
	outbufend = outbufstart + buflen;
	inbufstart = instr;
	inbuflen = inlen;

	while (inlen-- > 0 && (byte = *instr++) != '\0') {
		if (outstr >= outbufend) {
			result = ENAMETOOLONG;
			goto exit;
		}
		if (byte >= 0x80) {
			goto nonASCII;
		}
		/* ASCII is already normalized. */
		*outstr++ = byte;
	}
exit:
	*outlen = outstr - outbufstart;
	if (((flags & UTF_NO_NULL_TERM) == 0)) {
		if (outstr < outbufend)
			*outstr++ = '\0';
		else
			result = ENAMETOOLONG;
	}
	return (result);


	/* 
	 * Non-ASCII uses the existing utf8_encodestr/utf8_decodestr
	 * functions to perform the normalization.  Since this will
	 * presumably be used to normalize filenames in the back-end
	 * (on disk or over-the-wire), it should be fast enough.
	 */
nonASCII:

	/* Make sure the input size is reasonable. */
	if (inbuflen > MAXPATHLEN) {
		result = ENAMETOOLONG;
		goto exit;
	}
	/*
	 * Compute worst case Unicode buffer size.
	 *
	 * For pre-composed output, every UTF-8 input byte will be at
	 * most 2 Unicode bytes.  For decomposed output, 2 UTF-8 bytes
	 * (smallest composite char sequence) may yield 6 Unicode bytes
	 * (1 base char + 2 combining chars).
	 */
	unicode_bytes = precompose ? (inbuflen * 2) : (inbuflen * 3);

	if (unicode_bytes <= sizeof(unicodebuf))
		unistr = &unicodebuf[0];
	else
		MALLOC(unistr, uint16_t *, unicode_bytes, M_TEMP, M_WAITOK);

	/* Normalize the string. */
	result = utf8_decodestr(inbufstart, inbuflen, unistr, &unicode_bytes,
	                        unicode_bytes, 0, flags & ~UTF_NO_NULL_TERM);
	if (result == 0) {
		/* Put results back into UTF-8. */
		result = utf8_encodestr(unistr, unicode_bytes, outbufstart,
		                        &uft8_bytes, buflen, 0, UTF_NO_NULL_TERM);
		outstr = outbufstart + uft8_bytes;
	}
	if (unistr && unistr != &unicodebuf[0]) {
		FREE(unistr, M_TEMP);
	}
	goto exit;
}


 /*
  * Unicode 3.2 decomposition code (derived from Core Foundation)
  */

typedef struct {
	u_int32_t _key;
	u_int32_t _value;
} unicode_mappings32;

static inline u_int32_t
getmappedvalue32(const unicode_mappings32 *theTable, u_int32_t numElem,
		u_int16_t character)
{
	const unicode_mappings32 *p, *q, *divider;

	if ((character < theTable[0]._key) || (character > theTable[numElem-1]._key))
		return (0);

	p = theTable;
	q = p + (numElem-1);
	while (p <= q) {
		divider = p + ((q - p) >> 1);	/* divide by 2 */
		if (character < divider->_key) { q = divider - 1; }
		else if (character > divider->_key) { p = divider + 1; }
		else { return (divider->_value); }
	}
	return (0);
}

#define RECURSIVE_DECOMPOSITION	(1 << 15)
#define EXTRACT_COUNT(value)	(((value) >> 12) & 0x0007)

typedef struct {
	u_int16_t _key;
	u_int16_t _value;
} unicode_mappings16;

static inline u_int16_t
getmappedvalue16(const unicode_mappings16 *theTable, u_int32_t numElem,
		u_int16_t character)
{
	const unicode_mappings16 *p, *q, *divider;

	if ((character < theTable[0]._key) || (character > theTable[numElem-1]._key))
		return (0);

	p = theTable;
	q = p + (numElem-1);
	while (p <= q) {
		divider = p + ((q - p) >> 1);	/* divide by 2 */
		if (character < divider->_key)
			q = divider - 1;
		else if (character > divider->_key)
			p = divider + 1;
		else
			return (divider->_value);
	}
	return (0);
}


static u_int32_t
unicode_recursive_decompose(u_int16_t character, u_int16_t *convertedChars)
{
	u_int16_t value;
	u_int32_t length;
	u_int16_t firstChar;
	u_int16_t theChar;
	const u_int16_t *bmpMappings;
	u_int32_t usedLength;

	value = getmappedvalue16(
		(const unicode_mappings16 *)__CFUniCharDecompositionTable,
		__UniCharDecompositionTableLength, character);
	length = EXTRACT_COUNT(value);
	firstChar = value & 0x0FFF;
	theChar = firstChar;
	bmpMappings = (length == 1 ? &theChar : __CFUniCharMultipleDecompositionTable + firstChar);
	usedLength = 0;

	if (value & RECURSIVE_DECOMPOSITION) {
	    usedLength = unicode_recursive_decompose((u_int16_t)*bmpMappings, convertedChars);
	
	    --length;	/* Decrement for the first char */
	    if (!usedLength)
	    	return 0;
	    ++bmpMappings;
	    convertedChars += usedLength;
	}
	
	usedLength += length;
	
	while (length--)
		*(convertedChars++) = *(bmpMappings++);
	
	return (usedLength);
}
    
#define HANGUL_SBASE 0xAC00
#define HANGUL_LBASE 0x1100
#define HANGUL_VBASE 0x1161
#define HANGUL_TBASE 0x11A7

#define HANGUL_SCOUNT 11172
#define HANGUL_LCOUNT 19
#define HANGUL_VCOUNT 21
#define HANGUL_TCOUNT 28
#define HANGUL_NCOUNT (HANGUL_VCOUNT * HANGUL_TCOUNT)

/*
 * unicode_decompose - decompose a composed Unicode char
 *
 * Composed Unicode characters are forbidden on
 * HFS Plus volumes. ucs_decompose will convert a
 * composed character into its correct decomposed
 * sequence.
 *
 * Similar to CFUniCharDecomposeCharacter
 */
static int
unicode_decompose(u_int16_t character, u_int16_t *convertedChars)
{
	if ((character >= HANGUL_SBASE) &&
	    (character <= (HANGUL_SBASE + HANGUL_SCOUNT))) {
		u_int32_t length;

		character -= HANGUL_SBASE;
		length = (character % HANGUL_TCOUNT ? 3 : 2);

		*(convertedChars++) =
			character / HANGUL_NCOUNT + HANGUL_LBASE;
		*(convertedChars++) =
			(character % HANGUL_NCOUNT) / HANGUL_TCOUNT + HANGUL_VBASE;
		if (length > 2)
			*convertedChars = (character % HANGUL_TCOUNT) + HANGUL_TBASE;
		return (length);
	} else {
		return (unicode_recursive_decompose(character, convertedChars));
	}
}

/*
 * unicode_combine - generate a precomposed Unicode char
 *
 * Precomposed Unicode characters are required for some volume
 * formats and network protocols.  unicode_combine will combine
 * a decomposed character sequence into a single precomposed
 * (composite) character.
 *
 * Similar toCFUniCharPrecomposeCharacter but unicode_combine
 * also handles Hangul Jamo characters.
 */
static u_int16_t
unicode_combine(u_int16_t base, u_int16_t combining)
{
	u_int32_t value;

	/* Check HANGUL */
	if ((combining >= HANGUL_VBASE) && (combining < (HANGUL_TBASE + HANGUL_TCOUNT))) {
		/* 2 char Hangul sequences */
		if ((combining < (HANGUL_VBASE + HANGUL_VCOUNT)) &&
		    (base >= HANGUL_LBASE && base < (HANGUL_LBASE + HANGUL_LCOUNT))) {
		    return (HANGUL_SBASE +
		            ((base - HANGUL_LBASE)*(HANGUL_VCOUNT*HANGUL_TCOUNT)) +
		            ((combining  - HANGUL_VBASE)*HANGUL_TCOUNT));
		}
	
		/* 3 char Hangul sequences */
		if ((combining > HANGUL_TBASE) &&
		    (base >= HANGUL_SBASE && base < (HANGUL_SBASE + HANGUL_SCOUNT))) {
			if ((base - HANGUL_SBASE) % HANGUL_TCOUNT)
				return (0);
			else
				return (base + (combining - HANGUL_TBASE));
		}
	}

	value = getmappedvalue32(
		(const unicode_mappings32 *)__CFUniCharPrecompSourceTable,
		__CFUniCharPrecompositionTableLength, combining);

	if (value) {
		value = getmappedvalue16(
			(const unicode_mappings16 *)
			((const u_int32_t *)__CFUniCharBMPPrecompDestinationTable + (value & 0xFFFF)),
			(value >> 16), base);
	}
	return (value);
}


/*
 * prioritysort - order combining chars into canonical order
 *
 * Similar to CFUniCharPrioritySort
 */
static void
prioritysort(u_int16_t* characters, int count)
{
	u_int32_t p1, p2;
	u_int16_t *ch1, *ch2;
	u_int16_t *end;
	int changes = 0;

	end = characters + count;
	do {
		changes = 0;
		ch1 = characters;
		ch2 = characters + 1;
		p2 = get_combining_class(*ch1);
		while (ch2 < end) {
			p1 = p2;
			p2 = get_combining_class(*ch2);
			if (p1 > p2 && p2 != 0) {
				u_int32_t tmp;

				tmp = *ch1;
				*ch1 = *ch2;
				*ch2 = tmp;
				changes = 1;
				
				/*
				 * Make sure that p2 contains the combining class for the
				 * character now stored at *ch2.  This isn't required for
				 * correctness, but it will be more efficient if a character
				 * with a large combining class has to "bubble past" several
				 * characters with lower combining classes.
				 */
				p2 = p1;
			}
			++ch1;
			++ch2;
		}
	} while (changes);
}


/*
 * Invalid NTFS filename characters are encodeded using the
 * SFM (Services for Macintosh) private use Unicode characters.
 *
 * These should only be used for SMB, MSDOS or NTFS.
 *
 *    Illegal NTFS Char   SFM Unicode Char
 *  ----------------------------------------
 *    0x01-0x1f           0xf001-0xf01f
 *    '"'                 0xf020
 *    '*'                 0xf021
 *    '/'                 0xf022
 *    '<'                 0xf023
 *    '>'                 0xf024
 *    '?'                 0xf025
 *    '\'                 0xf026
 *    '|'                 0xf027
 *    ' '                 0xf028  (Only if last char of the name)
 *    '.'                 0xf029  (Only if last char of the name)
 *  ----------------------------------------
 *
 *  Reference: http://support.microsoft.com/kb/q117258/
 */

#define MAX_SFM2MAC           0x29
#define SFMCODE_PREFIX_MASK   0xf000 

/*
 * In the Mac OS 9 days the colon was illegal in a file name. For that reason
 * SFM had no conversion for the colon. There is a conversion for the
 * slash. In Mac OS X the slash is illegal in a file name. So for us the colon
 * is a slash and a slash is a colon. So we can just replace the slash with the
 * colon in our tables and everything will just work. 
 */
static u_int8_t
sfm2mac[42] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,   /* 00 - 07 */
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,   /* 08 - 0F */
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,   /* 10 - 17 */
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,   /* 18 - 1F */
	0x22, 0x2a, 0x3a, 0x3c, 0x3e, 0x3f, 0x5c, 0x7c,   /* 20 - 27 */
	0x20, 0x2e                                        /* 28 - 29 */
};

static u_int8_t
mac2sfm[112] = {
	0x20, 0x21, 0x20, 0x23, 0x24, 0x25, 0x26, 0x27,	  /* 20 - 27 */
	0x28, 0x29, 0x21, 0x2b, 0x2c, 0x2d, 0x2e, 0x22,   /* 28 - 2f */
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,   /* 30 - 37 */
	0x38, 0x39, 0x22, 0x3b, 0x23, 0x3d, 0x24, 0x25,   /* 38 - 3f */
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,   /* 40 - 47 */
	0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,   /* 48 - 4f */
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,   /* 50 - 57 */
	0x58, 0x59, 0x5a, 0x5b, 0x26, 0x5d, 0x5e, 0x5f,   /* 58 - 5f */
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,   /* 60 - 67 */
	0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,   /* 68 - 6f */
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,   /* 70 - 77 */
	0x78, 0x79, 0x7a, 0x7b, 0x27, 0x7d, 0x7e, 0x7f    /* 78 - 7f */
};


/*
 * Encode illegal NTFS filename characters into SFM Private Unicode characters
 *
 * Assumes non-zero ASCII input.
 */
static u_int16_t
ucs_to_sfm(u_int16_t ucs_ch, int lastchar)
{
	/* The last character of filename cannot be a space or period. */
	if (lastchar) {
		if (ucs_ch == 0x20)
			return (0xf028);
		else if (ucs_ch == 0x2e)
			return (0xf029);
	}
	/* 0x01 - 0x1f is simple transformation. */
	if (ucs_ch <= 0x1f) {
		return (ucs_ch | 0xf000);
	} else /* 0x20 - 0x7f */ {
		u_int16_t lsb;

		lsb = mac2sfm[ucs_ch - 0x0020];
		if (lsb != ucs_ch)
			return(0xf000 | lsb); 
	}
	return (ucs_ch);
}

/*
 * Decode any SFM Private Unicode characters
 */
static u_int16_t
sfm_to_ucs(u_int16_t ucs_ch)
{
	if (((ucs_ch & 0xffC0) == SFMCODE_PREFIX_MASK) && 
	    ((ucs_ch & 0x003f) <= MAX_SFM2MAC)) {
		ucs_ch = sfm2mac[ucs_ch & 0x003f];
	}
	return (ucs_ch);
}


