/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
 
 /*
 	Includes Unicode 3.2 decomposition code derived from Core Foundation
 */

#include <sys/param.h>
#include <sys/utfconv.h>
#include <sys/errno.h>
#include <architecture/byte_order.h>

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
#define SP_HALF_BASE	0x0010000UL
#define SP_HALF_MASK	0x3FFUL

#define SP_HIGH_FIRST	0xD800UL
#define SP_HIGH_LAST	0xDBFFUL
#define SP_LOW_FIRST	0xDC00UL
#define SP_LOW_LAST	0xDFFFUL


#include "vfs_utfconvdata.h"


/*
 * Test for a combining character.
 *
 * Similar to __CFUniCharIsNonBaseCharacter except that
 * unicode_combinable also includes Hangul Jamo characters.
 */
static inline int
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
static inline int
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

static int unicode_decompose(u_int16_t character, u_int16_t *convertedChars);

static u_int16_t unicode_combine(u_int16_t base, u_int16_t combining);


char utf_extrabytes[32] = {
	 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	-1, -1, -1, -1, -1, -1, -1, -1,  1,  1,  1,  1,  2,  2,  3, -1
};


/*
 * utf8_encodelen - Calculates the UTF-8 encoding length for a Unicode filename
 *
 * NOTES:
 *    If '/' chars are allowed on disk then an alternate
 *    (replacement) char must be provided in altslash.
 *
 * input flags:
 *    UTF_REVERSE_ENDIAN: Unicode byteorder is opposite current runtime
 */
size_t
utf8_encodelen(const u_int16_t * ucsp, size_t ucslen, u_int16_t altslash,
               int flags)
{
	u_int16_t ucs_ch;
	int charcnt;
	int swapbytes = (flags & UTF_REVERSE_ENDIAN);
	size_t len;
	
	charcnt = ucslen / 2;
	len = 0;

	while (charcnt-- > 0) {
		ucs_ch = *ucsp++;

		if (swapbytes)
			ucs_ch = NXSwapShort(ucs_ch);
		if (ucs_ch == '/')
			ucs_ch = altslash ? altslash : '_';
		else if (ucs_ch == '\0')
			ucs_ch = UCS_ALT_NULL;
		
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
 *    UTF_NO_NULL_TERM:  don't add NULL termination to UTF-8 output
 *
 * result:
 *    ENAMETOOLONG: Name didn't fit; only buflen bytes were encoded
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
	int charcnt;
	int swapbytes = (flags & UTF_REVERSE_ENDIAN);
	int nullterm  = ((flags & UTF_NO_NULL_TERM) == 0);
	int decompose = (flags & UTF_DECOMPOSED);
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
			ucs_ch = swapbytes ? NXSwapShort(*ucsp++) : *ucsp++;

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
			/* Combine valid surrogate pairs */
			if (ucs_ch >= SP_HIGH_FIRST && ucs_ch <= SP_HIGH_LAST
				&& charcnt > 0) {
				u_int16_t ch2;
				u_int32_t pair;

				ch2 = swapbytes ? NXSwapShort(*ucsp) : *ucsp;
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
 *    UTF_REV_ENDIAN:   Unicode byteorder is oposite current runtime
 *    UTF_DECOMPOSED:   Unicode output string must be fully decompsed
 *
 * result:
 *    ENAMETOOLONG: Name didn't fit; only ucslen chars were decoded.
 *    EINVAL: Illegal UTF-8 sequence found.
 */
int
utf8_decodestr(const u_int8_t* utf8p, size_t utf8len, u_int16_t* ucsp,
               size_t *ucslen, size_t buflen, u_int16_t altslash, int flags)
{
	u_int16_t* bufstart;
	u_int16_t* bufend;
	u_int16_t ucs_ch;
	u_int8_t byte;
	int result = 0;
	int decompose, precompose, swapbytes;

	decompose =  (flags & UTF_DECOMPOSED);
	precompose = (flags & UTF_PRECOMPOSED);
	swapbytes =  (flags & UTF_REVERSE_ENDIAN);

	bufstart = ucsp;
	bufend = (u_int16_t *)((u_int8_t *)ucsp + buflen);

	while (utf8len-- > 0 && (byte = *utf8p++) != '\0') {
		if (ucsp >= bufend)
			goto toolong;

		/* check for ascii */
		if (byte < 0x80) {
			ucs_ch = byte;				/* 1st byte */
		} else {
			u_int32_t ch;
			int extrabytes = utf_extrabytes[byte >> 3];

			if (utf8len < extrabytes)
				goto invalid;
			utf8len -= extrabytes;

			switch (extrabytes) {
			case 1: ch = byte;			/* 1st byte */
					ch <<= 6;
			        ch += *utf8p++;		/* 2nd byte */
					ch -= 0x00003080UL;
					if (ch < 0x0080)
						goto invalid;
					ucs_ch = ch;
			        break;

			case 2:	ch = byte;			/* 1st byte */
					ch <<= 6;
					ch += *utf8p++;		/* 2nd byte */
					ch <<= 6;
					ch += *utf8p++;		/* 3rd byte */
					ch -= 0x000E2080UL;
					if (ch < 0x0800)
						goto invalid;
					ucs_ch = ch;
					break;

			case 3:	ch = byte;			/* 1st byte */
					ch <<= 6;
					ch += *utf8p++;		/* 2nd byte */
					ch <<= 6;
					ch += *utf8p++;		/* 3rd byte */
					ch <<= 6;
			        ch += *utf8p++;		/* 4th byte */
					ch -= 0x03C82080UL + SP_HALF_BASE;
					ucs_ch = (ch >> SP_HALF_SHIFT) + SP_HIGH_FIRST;
					*ucsp++ = swapbytes ? NXSwapShort(ucs_ch) : ucs_ch;
					if (ucsp >= bufend)
						goto toolong;
					ucs_ch = (ch & SP_HALF_MASK) + SP_LOW_FIRST;
					*ucsp++ = swapbytes ? NXSwapShort(ucs_ch) : ucs_ch;
			        continue;

			default:
					goto invalid;
			}
			if (decompose) {
				if (unicode_decomposeable(ucs_ch)) {
					u_int16_t sequence[8];
					int count, i;

					count = unicode_decompose(ucs_ch, sequence);

					for (i = 0; i < count; ++i) {
						ucs_ch = sequence[i];
						*ucsp++ = swapbytes ? NXSwapShort(ucs_ch) : ucs_ch;
						if (ucsp >= bufend)
							goto toolong;
					}
					continue;			
				}
			} else if (precompose && (ucsp != bufstart)) {
				u_int16_t composite, base;

				if (unicode_combinable(ucs_ch)) {
					base = swapbytes ? NXSwapShort(*(ucsp - 1)) : *(ucsp - 1);
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

		*ucsp++ = swapbytes ? NXSwapShort(ucs_ch) : ucs_ch;
	}

exit:
	*ucslen = (u_int8_t*)ucsp - (u_int8_t*)bufstart;

	return (result);

invalid:
	result = EINVAL;
	goto exit;

toolong:
	result = ENAMETOOLONG;
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
			((u_int32_t *)__CFUniCharBMPPrecompDestinationTable + (value & 0xFFFF)),
			(value >> 16), base);
	}
	return (value);
}

