/*
 * Copyright (c) 2000-2001 Apple Computer, Inc. All rights reserved.
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
#define SP_LOW_LAST		0xDFFFUL


static u_int16_t ucs_decompose(u_int16_t, u_int16_t *);

static u_int16_t ucs_combine(u_int16_t base, u_int16_t comb);


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
	u_int16_t extra[2] = {0};
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
		if (!decompose)
			ucs_ch = swapbytes ? NXSwapShort(*ucsp++) : *ucsp++;
		else if (extra[0]) {
			ucs_ch = extra[0]; extra[0] = 0;
		} else if (extra[1]) {
			ucs_ch = extra[1]; extra[1] = 0;
		} else {
			ucs_ch = swapbytes ? NXSwapShort(*ucsp++) : *ucsp++;
			ucs_ch = ucs_decompose(ucs_ch, &extra[0]);
			if (extra[0])
				charcnt++;
			if (extra[1])
				charcnt++;
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
				u_int16_t comb_ch[2];

				ucs_ch = ucs_decompose(ucs_ch, &comb_ch[0]);

				if (comb_ch[0]) {
					*ucsp++ = swapbytes ? NXSwapShort(ucs_ch) : ucs_ch;
					if (ucsp >= bufend)
						goto toolong;
					ucs_ch = comb_ch[0];
					if (comb_ch[1]) {
						*ucsp++ = swapbytes ? NXSwapShort(ucs_ch) : ucs_ch;
						if (ucsp >= bufend)
							goto toolong;
						ucs_ch = comb_ch[1];
					}
				}
			} else if (precompose && (ucsp != bufstart)) {
				u_int16_t composite, base;

				base = swapbytes ? NXSwapShort(*(ucsp - 1)) : *(ucsp - 1);
				composite = ucs_combine(base, ucs_ch);
				if (composite) {
					--ucsp;
					ucs_ch = composite;
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
 * Lookup tables for Unicode chars 0x00C0 thru 0x00FF
 * primary_char yields first decomposed char. If this
 * char is an alpha char then get the combining char
 * from the combining_char table and add 0x0300 to it.
 */

static unsigned char primary_char[8*36] = {
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x43,

	0x45, 0x45, 0x45, 0x45, 0x49, 0x49, 0x49, 0x49, 		/* CF */

	0x00, 0x4E, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0x00,

	0x00, 0x55, 0x55, 0x55, 0x55, 0x59, 0x00, 0x00, 		/* DF */

	0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x00, 0x63,

	0x65, 0x65, 0x65, 0x65, 0x69, 0x69, 0x69, 0x69, 		/* EF */

	0x00, 0x6E, 0x6F, 0x6F, 0x6F, 0x6F, 0x6F, 0x00,

	0x00, 0x75, 0x75, 0x75, 0x75, 0x79, 0x00, 0x79,			/* FF */

	0x41, 0x61, 0x41, 0x61, 0x41, 0x61, 0x43, 0x63,
	
	0x43, 0x63, 0x43, 0x63, 0x43, 0x63, 0x44, 0x64,			/* 10F */
	
	0x00, 0x00, 0x45, 0x65, 0x45, 0x65, 0x45, 0x65,
	
	0x45, 0x65, 0x45, 0x65, 0x47, 0x67, 0x47, 0x67,			/* 11F */
	
	0x47, 0x67, 0x47, 0x67, 0x48, 0x68, 0x00, 0x00, 
	
	0x49, 0x69, 0x49, 0x69, 0x49, 0x69, 0x49, 0x69, 
	
	0x49, 0x00, 0x00, 0x00, 0x4A, 0x6A, 0x4B, 0x6B, 
	
	0x00, 0x4C, 0x6C, 0x4C, 0x6C, 0x4C, 0x6C, 0x00, 		/* 13F */
	
	0x00, 0x00, 0x00, 0x4E, 0x6E, 0x4E, 0x6E, 0x4E, 
	
	0x6E, 0x00, 0x00, 0x00, 0x4F, 0x6F, 0x4F, 0x6F, 
	
	0x4F, 0x6F, 0x00, 0x00, 0x52, 0x72, 0x52, 0x72, 
	
	0x52, 0x72, 0x53, 0x73, 0x53, 0x73, 0x53, 0x73, 		/* 15F */
	
	0x53, 0x73, 0x54, 0x74, 0x54, 0x74, 0x00, 0x00, 
	
	0x55, 0x75, 0x55, 0x75, 0x55, 0x75, 0x55, 0x75, 
	
	0x55, 0x75, 0x55, 0x75, 0x57, 0x77, 0x59, 0x79, 
	
	0x59, 0x5A, 0x7A, 0x5A, 0x7A, 0x5A, 0x7A, 0x00, 		/* 17F */
	
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 		/* 19F */
	
	0x4F, 0x6F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 
	
	0x75, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 		/* 1BF */
	
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	
	0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x61, 0x49, 		
	
	0x69, 0x4F, 0x6F, 0x55, 0x75, 0xDC, 0xFC, 0xDC, 
	
	0xFC, 0xDC, 0xFC, 0xDC, 0xFC, 0x00, 0xC4, 0xE4			/* 1DF */
	
};

static unsigned char combining_char[8*36] = {
	0x00, 0x01, 0x02, 0x03, 0x08, 0x0A, 0xFF, 0x27,

	0x00, 0x01, 0x02, 0x08, 0x00, 0x01, 0x02, 0x08, 		/* CF */

	0xFF, 0x03, 0x00, 0x01, 0x02, 0x03, 0x08, 0xFF,

	0xFF, 0x00, 0x01, 0x02, 0x08, 0x01, 0xFF, 0xFF,			/* DF */

	0x00, 0x01, 0x02, 0x03, 0x08, 0x0A, 0xFF, 0x27,

	0x00, 0x01, 0x02, 0x08, 0x00, 0x01, 0x02, 0x08,			/* EF */

	0xFF, 0x03, 0x00, 0x01, 0x02, 0x03, 0x08, 0xFF,

	0xFF, 0x00, 0x01, 0x02, 0x08, 0x01, 0xFF, 0x08,			/* FF */

	0x04, 0x04, 0x06, 0x06, 0x28, 0x28, 0x01, 0x01, 

	0x02, 0x02, 0x07, 0x07, 0x0C, 0x0C, 0x0C, 0x0C, 

	0x00, 0x00, 0x04, 0x04, 0x06, 0x06, 0x07, 0x07, 

	0x28, 0x28, 0x0C, 0x0C, 0x02, 0x02, 0x06, 0x06, 

	0x07, 0x07, 0x27, 0x27, 0x02, 0x02, 0x00, 0x00, 

	0x03, 0x03, 0x04, 0x04, 0x06, 0x06, 0x28, 0x28, 

	0x07, 0x00, 0x00, 0x00, 0x02, 0x02, 0x27, 0x27, 

	0x00, 0x01, 0x01, 0x27, 0x27, 0x0C, 0x0C, 0x00, 		/* 13F */

	0x00, 0x00, 0x00, 0x01, 0x01, 0x27, 0x27, 0x0C, 

	0x0C, 0x00, 0x00, 0x00, 0x04, 0x04, 0x06, 0x06, 

	0x0B, 0x0B, 0x00, 0x00, 0x01, 0x01, 0x27, 0x27, 

	0x0C, 0x0C, 0x01, 0x01, 0x02, 0x02, 0x27, 0x27, 

	0x0C, 0x0C, 0x27, 0x27, 0x0C, 0x0C, 0x00, 0x00, 

	0x03, 0x03, 0x04, 0x04, 0x06, 0x06, 0x0A, 0x0A, 		/* 16F */

	0x0B, 0x0B, 0x28, 0x28, 0x02, 0x02, 0x02, 0x02, 

	0x08, 0x01, 0x01, 0x07, 0x07, 0x0C, 0x0C, 0x00, 

	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 		/* 17F */ 

	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 

	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 

	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 		/* 19F */

	0x1B, 0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 

	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1B, 

	0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 

	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 

	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 

	0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C, 0x0C, 		/* 1CF */

	0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x04, 0x04, 0x01, 

	0x01, 0x0C, 0x0C, 0x00, 0x00, 0x00, 0x04, 0x04  		/* 1DF */
};


/* CYRILLIC codepoints 0x0400 ~ 0x04FF */
static const unsigned long __CyrillicDecompBitmap[] = {
    0x510A0040, 0x00000040, 0x0000510A, 0x00000000,	/* 0x0400 */
    0x00000000, 0x00000000, 0x00000000, 0x00000000,	/* 0x0480 */
};

/* CJK codepoints 0x3000 ~ 0x30FF */
static const unsigned long __CJKDecompBitmap[] = {
    0x00000000, 0x00000000, 0x000AAAAA, 0xA540DB6C,	/* 0x3000 */
    0x00000802, 0x000AAAAA, 0xA540DB6C, 0x000009E2,	/* 0x3080 */
};
#define IS_DECOMPOSABLE(table,unicodeVal) \
	(table[(unicodeVal) / 32] & (1 << (31 - ((unicodeVal) % 32))))

/*
 * ucs_decompose - decompose a composed Unicode char
 *
 * Composed Unicode characters are forbidden on
 * HFS Plus volumes. ucs_decompose will convert a
 * composed character into its correct decomposed
 * sequence.
 *
 * Currently only Tier-1 and Tier-2 languages
 * are handled.  Other composed characters are
 * passed unchanged.
 */
static u_int16_t
ucs_decompose(register u_int16_t ch, u_int16_t *cmb)
{
	u_int16_t base;
	
	cmb[0] = 0;
	cmb[1] = 0;

	if (ch < 0x00C0) {
		base = ch;
	} else if (ch <= 0x01DF) {
		
		base = (u_int16_t) primary_char[ch - 0x00C0];

		if (base == 0)
			base = ch;
		else  {
		    if ((base < 0x00C0) || (primary_char[base - 0x00C0] == 0))
			    cmb[0] = (u_int16_t)0x0300 + (u_int16_t)combining_char[ch - 0x00C0];
			else {
		        u_int16_t   tch = base;
		        
		        base    = (u_int16_t)primary_char[tch - 0x00C0];
			    cmb[0]  = (u_int16_t)0x0300 + (u_int16_t)combining_char[tch - 0x00C0];
			    cmb[1]  = (u_int16_t)0x0300 + (u_int16_t)combining_char[ch - 0x00C0];
			}
		}
	} else if ((ch >= 0x0400) && (ch <= 0x04FF) &&
		   IS_DECOMPOSABLE(__CyrillicDecompBitmap, ch - 0x0400)) {
	
		/* Handle CYRILLIC LETTERs */
		switch(ch) {
		case 0x0401: base = 0x0415; cmb[0] = 0x0308; break; /*  */
		case 0x0403: base = 0x0413; cmb[0] = 0x0301; break; /*  */
		case 0x0407: base = 0x0406; cmb[0] = 0x0308; break; /*  */
		case 0x040C: base = 0x041A; cmb[0] = 0x0301; break; /*  */
		case 0x040E: base = 0x0423; cmb[0] = 0x0306; break; /*  */
		case 0x0419: base = 0x0418; cmb[0] = 0x0306; break; /*  */
		case 0x0439: base = 0x0438; cmb[0] = 0x0306; break; /*  */
		case 0x0451: base = 0x0435; cmb[0] = 0x0308; break; /*  */
		case 0x0453: base = 0x0433; cmb[0] = 0x0301; break; /*  */
		case 0x0457: base = 0x0456; cmb[0] = 0x0308; break; /*  */
		case 0x045C: base = 0x043A; cmb[0] = 0x0301; break; /*  */
		case 0x045E: base = 0x0443; cmb[0] = 0x0306; break; /*  */
		
		default:
			/* Should not be hit from bit map table */
			base = ch;
		}
	} else if (ch == 0x1E3F) {
		base = 0x006D; cmb[0] = 0x0301; /* LATIN SMALL LETTER M WITH ACUTE */
	} else if ((ch > 0x3000) && (ch < 0x3100) &&
		   IS_DECOMPOSABLE(__CJKDecompBitmap, ch - 0x3000)) {
	
		/* Handle HIRAGANA LETTERs */
		switch(ch) {
		case 0x3071: base = 0x306F; cmb[0] = 0x309A; break; /* PA */
		case 0x3074: base = 0x3072; cmb[0] = 0x309A; break; /* PI */
		case 0x3077: base = 0x3075; cmb[0] = 0x309A; break; /* PU */
		case 0x307A: base = 0x3078; cmb[0] = 0x309A; break; /* PE */

		case 0x307D: base = 0x307B; cmb[0] = 0x309A; break; /* PO */
		case 0x3094: base = 0x3046; cmb[0] = 0x3099; break; /* VU */
		case 0x30D1: base = 0x30CF; cmb[0] = 0x309A; break; /* PA */
		case 0x30D4: base = 0x30D2; cmb[0] = 0x309A; break; /* PI */

		case 0x30D7: base = 0x30D5; cmb[0] = 0x309A; break; /* PU */
		case 0x30DA: base = 0x30D8; cmb[0] = 0x309A; break; /* PE */
		case 0x30DD: base = 0x30DB; cmb[0] = 0x309A; break; /* PO */
		case 0x30F4: base = 0x30A6; cmb[0] = 0x3099; break; /* VU */

		case 0x30F7: base = 0x30EF; cmb[0] = 0x3099; break; /* VA */
		case 0x30F8: base = 0x30F0; cmb[0] = 0x3099; break; /* VI */
		case 0x30F9: base = 0x30F1; cmb[0] = 0x3099; break; /* VE */
		case 0x30FA: base = 0x30F2; cmb[0] = 0x3099; break; /* VO */
		
		default:
			/* the rest (41 of them) have a simple conversion */
			base = ch - 1;
			cmb[0] = 0x3099;
		}
	} else if ((ch >= 0xAC00) && (ch < 0xD7A4)) {
		/* Hangul */
		ch -= 0xAC00;
		base 	= 0x1100 + (ch / (21*28));
		cmb[0] 	= 0x1161 + (ch % (21*28)) / 28;

		if (ch % 28)
			cmb[1] = 0x11A7 + (ch % 28);
	} else {
		base = ch;
	}
	
	return (base);
}


static const short diacrit_tbl[8*6] = {
 /* 300 - 307 */     0,  58, 116, 174, 232,  -1, 290, 348,
 /* 308 - 30F */   406,  -1, 464, 522, 580,  -1,  -1,  -1,
 /* 310 - 317 */    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
 /* 318 - 31F */    -1,  -1,  -1, 638,  -1,  -1,  -1,  -1,
 /* 320 - 327 */    -1,  -1,  -1,  -1,  -1,  -1,  -1, 696,
 /* 328 - 32F */   754,  -1,  -1,  -1,  -1,  -1,  -1,  -1
};

static const u_int16_t composite_tbl[58*14] = {
 /*
  *    A     B     C     D     E     F     G     H     I     J     K     L     M
  *    N     O     P     Q     R     S     T     U     V     W     X     Y     Z
  *    [     \     ]     ^     _     `
  *    a     b     c     d     e     f     g     h     i     j     k     l     m
  *    n     o     p     q     r     s     t     u     v     w     x     y     z
  */

 /*
  * 0x300 - grave accent
  */
  0x0C0,    0,    0,    0,0x0C8,    0,    0,    0,0x0CC,    0,    0,    0,    0,
      0,0x0D2,    0,    0,    0,    0,    0,0x0D9,    0,    0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,
  0x0E0,    0,    0,    0,0x0E8,    0,    0,    0,0x0EC,    0,    0,    0,    0,
      0,0x0F2,    0,    0,    0,    0,    0,0x0F9,    0,    0,    0,    0,    0,
 /*
  * 0x301 - acute accent
  */
  0x0C1,    0,0x106,    0,0x0C9,    0,    0,    0,0x0CD,    0,    0,0x139,    0,
  0x143,0x0D3,    0,    0,0x154,0x15A,    0,0x0DA,    0,    0,    0,0x0DD,0x179,
      0,    0,    0,    0,    0,    0,
  0x0E1,    0,0x107,    0,0x0E9,    0,    0,    0,0x0ED,    0,    0,0x13A,0x1E3F,
  0x144,0x0F3,    0,    0,0x155,0x15B,    0,0x0FA,    0,    0,    0,0x0FD,0x17A,
 /*
  * 0x302 - circumflex accent
  */
  0x0C2,    0,0x108,    0,0x0CA,    0,0x11C,0x124,0x0CE,0x134,    0,    0,    0,
      0,0x0D4,    0,    0,    0,0x15C,    0,0x0DB,    0,0x174,    0,0x176,    0,
      0,    0,    0,    0,    0,    0,
  0x0E2,    0,0x109,    0,0x0EA,    0,0x11D,0x125,0x0EE,0x135,    0,    0,    0,
      0,0x0F4,    0,    0,    0,0x15D,    0,0x0FB,    0,0x175,    0,0x177,    0,
 /*
  * 0x303 - tilde
  */
  0x0C3,    0,    0,    0,    0,    0,    0,    0,0x128,    0,    0,    0,    0,
  0x0D1,0x0D5,    0,    0,    0,    0,    0,0x168,    0,    0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,
  0x0E3,    0,    0,    0,    0,    0,    0,    0,0x129,    0,    0,    0,    0,
  0x0F1,0x0F5,    0,    0,    0,    0,    0,0x169,    0,    0,    0,    0,    0,
 /*
  * 0x304 - macron
  */
  0x100,    0,    0,    0,0x112,    0,    0,    0,0x12A,    0,    0,    0,    0,
      0,0x14C,    0,    0,    0,    0,    0,0x16A,    0,    0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,
  0x101,    0,    0,    0,0x113,    0,    0,    0,0x12B,    0,    0,    0,    0,
      0,0x14D,    0,    0,    0,    0,    0,0x16B,    0,    0,    0,    0,    0,
 /*
  * 0x306 - breve
  */
  0x102,    0,    0,    0,0x114,    0,0x11E,    0,0x12C,    0,    0,    0,    0,
      0,0x14E,    0,    0,    0,    0,    0,0x16C,    0,    0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,
  0x103,    0,    0,    0,0x115,    0,0x11F,    0,0x12D,    0,    0,    0,    0,
      0,0x14F,    0,    0,    0,    0,    0,0x16D,    0,    0,    0,    0,    0,
 /*
  * 0x307 - dot above
  */
      0,    0,0x10A,    0,0x116,    0,0x120,    0,0x130,    0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,0x17B,
      0,    0,    0,    0,    0,    0,
      0,    0,0x10B,    0,0x117,    0,0x121,    0,    0,    0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,0x17C,
 /*
  * 0x308 - diaeresis
  */
  0x0C4,    0,    0,    0,0x0CB,    0,    0,    0,0x0CF,    0,    0,    0,    0,
      0,0x0D6,    0,    0,    0,    0,    0,0x0DC,    0,    0,    0,0x178,    0,
      0,    0,    0,    0,    0,    0,
  0x0E4,    0,    0,    0,0x0EB,    0,    0,    0,0x0EF,    0,    0,    0,    0,
      0,0x0F6,    0,    0,    0,    0,    0,0x0FC,    0,    0,    0,0x0FF,    0,
 /*
  * 0x30A - ring above
  */
  0x0C5,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,    0,0x16E,    0,    0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,
  0x0E5,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,    0,0x16F,    0,    0,    0,    0,    0,
 /*
  * 0x30B - double aute accent
  */
      0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
      0,0x150,    0,    0,    0,    0,    0,0x170,    0,    0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
      0,0x151,    0,    0,    0,    0,    0,0x171,    0,    0,    0,    0,    0,
 /*
  * 0x30C - caron
  */
  0x1CD,    0,0x10C,0x10E,0x11A,    0,    0,    0,0x1CF,    0,    0,0x13D,    0,
  0x147,0x1D1,    0,    0,0x158,0x160,0x164,0x1D3,    0,    0,    0,    0,0x17D,
      0,    0,    0,    0,    0,    0,
  0x1CE,    0,0x10D,0x10F,0x11B,    0,    0,    0,0x1D0,    0,    0,0x13E,    0,
  0x148,0x1D2,    0,    0,0x159,0x161,0x165,0x1D4,    0,    0,    0,    0,0x17E,
 /*
  * 0x31B - horn
  */
      0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
      0,0x1A0,    0,    0,    0,    0,    0,0x1AF,    0,    0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
      0,0x1A1,    0,    0,    0,    0,    0,0x1B0,    0,    0,    0,    0,    0,
 /*
  * 0x327 - cedilla
  */
      0,    0,0x0C7,    0,    0,    0,0x122,    0,    0,    0,0x136,0x13B,    0,
  0x145,    0,    0,    0,0x156,0x15E,0x162,    0,    0,    0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,
      0,    0,0x0E7,    0,    0,    0,0x123,    0,    0,    0,0x137,0x13C,    0,
  0x146,    0,    0,    0,0x157,0x15F,0x163,    0,    0,    0,    0,    0,    0,
 /*
  * 0x328 - ogonek
  */
  0x104,    0,    0,    0,0x118,    0,    0,    0,0x12E,    0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,    0,0x172,    0,    0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,
  0x105,    0,    0,    0,0x119,    0,    0,    0,0x12F,    0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,    0,0x173,    0,    0,    0,    0,    0,
};


/* CJK codepoints 0x3000 ~ 0x30FF */
static const unsigned long __CJKCombBitmap[] = {
	0x00000000, 0x00000000, 0x02155555, 0x4A812490,	/* 0x3000 */
	0x00000004, 0x02155555, 0x4A812490, 0x0001E004,	/* 0x3080 */
};
#define CAN_COMBINE(table,unicodeVal) \
	(table[(unicodeVal) / 32] & (1 << (31 - ((unicodeVal) % 32))))


/*
 * ucs_combine - generate a precomposed Unicode char
 *
 * Precomposed Unicode characters are required for some volume
 * formats and network protocols.  ucs_combine will combine a
 * decomposed character sequence into a single precomposed
 * (composite) character.
 *
 * Currently only decomcomposed sequences from Apple's Tier 1
 * and Tier 2 languages are handled.
 *
 * INPUT:
 *		base - base character
 *		comb - combining character
 * OUTPUT:
 *		result - precomposed char or zero if not combinable
 */
static u_int16_t
ucs_combine(u_int16_t base, u_int16_t comb)
{
	/* Get out early if we can */
	if (comb < 0x0300)
		return (0);

	/* Try ordinary diacritics (0x300 - 0x32F) */
	if (comb <= 0x032F) {
		int index;
		
		if (base >= 'A' && base <= 'z') {
			index = diacrit_tbl[comb - 0x0300];
			if (index < 0 ) return (0);
	
			return (composite_tbl[index + (base - 'A')]);
		}

		/* Handle Cyrillic and some 3 char latin sequences */
		switch (comb) {
		case 0x0300:
			switch (base) {
			case 0x00DC:  return (0x01DB);
			case 0x00FC:  return (0x01DC);
			} break;
		case 0x0301:
			switch (base) {
			case 0x00DC:  return (0x01D7);
			case 0x00FC:  return (0x01D8);
			case 0x0413:  return (0x0403);
			case 0x041A:  return (0x040C);
			case 0x0433:  return (0x0453);
			case 0x043A:  return (0x045C);
			} break;
		case 0x0304:
			switch (base) {
			case 0x00DC:  return (0x01D5);
			case 0x00FC:  return (0x01D6);
			case 0x00C4:  return (0x01DE);
			case 0x00E4:  return (0x01DF);
			} break;
		case 0x0306:
			switch (base) {
			case 0x0418:  return (0x0419);
			case 0x0423:  return (0x040E);
			case 0x0438:  return (0x0439);
			case 0x0443:  return (0x045E);
			} break;
		case 0x0308:
			switch (base) {
			case 0x0406:  return (0x0407);
			case 0x0415:  return (0x0401);
			case 0x0435:  return (0x0451);
			case 0x0456:  return (0x0457);
			} break;
		case 0x030C:
			switch (base) {
			case 0x00DC:  return (0x01D9);
			case 0x00FC:  return (0x01DA);
			} break;
		}
		return (0);
	}

	/* Now try HANGUL */
	if (comb < 0x1161)
		return (0);

	/* 2 char Hangul sequences */
	if ((comb <= 0x1175)  && (base >= 0x1100 && base <= 0x1112))
	    return (0xAC00 + ((base - 0x1100)*(21*28)) + ((comb  - 0x1161)*28));

	/* 3 char Hangul sequences */
	if ((comb >= 0x11A8 && comb <= 0x11C2) &&
		(base >= 0xAC00 && base <= 0xD788)) {
		if ((base - 0xAC00) % 28)
			return (0);
		else
			return (base + (comb - 0x11A7));
	}

	/* Now try HIRAGANA and KATAKANA */
	if ((comb == 0x3099 || comb == 0x309A) &&
		(base > 0x3000 && base < 0x3100)   &&
		CAN_COMBINE(__CJKCombBitmap, base - 0x3000)) {
		if (comb == 0x309A) {
			switch(base) {
			case 0x306F:  return (0x3071);	/* PA */
			case 0x3072:  return (0x3074);	/* PI */
			case 0x3075:  return (0x3077);	/* PU */
			case 0x3078:  return (0x307A);	/* PE */
			case 0x307B:  return (0x307D);	/* PO */
			case 0x30CF:  return (0x30D1);	/* PA */
			case 0x30D2:  return (0x30D4);	/* PI */
			case 0x30D5:  return (0x30D7);	/* PU */
			case 0x30D8:  return (0x30DA);	/* PE */
			case 0x30DB:  return (0x30DD);	/* PO */
			default:      return (0);
			}
		} else /* 0x3099 */ {
			switch (base) {
			case 0x3046:  return (0x3094);	/* VU */
			case 0x30A6:  return (0x30F4);	/* VU */
			case 0x30EF:  return (0x30F7);	/* VA */
			case 0x30F0:  return (0x30F8);	/* VI */
			case 0x30F1:  return (0x30F9);	/* VE */
			case 0x30F2:  return (0x30FA);	/* VO */
			default:      return (base + 1); /* 41 code points here */
			}
		}
	}

	return (0);
}

