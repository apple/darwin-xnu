/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * UTF-8 (UCS Transformation Format)
 *
 * The following subset of UTF-8 is used to encode UCS-2 filenames. It
 * requires a maximum of three 3 bytes per UCS-2 character.  Only the
 * shortest encoding required to represent the significant UCS-2 bits
 * is legal.
 * 
 * UTF-8 Multibyte Codes
 *
 * Bytes   Bits   UCS-2 Min   UCS-2 Max   UTF-8 Byte Sequence (binary)
 * -------------------------------------------------------------------
 *   1       7     0x0000      0x007F      0xxxxxxx
 *   2      11     0x0080      0x07FF      110xxxxx 10xxxxxx
 *   3      16     0x0800      0xFFFF      1110xxxx 10xxxxxx 10xxxxxx
 * -------------------------------------------------------------------
 */


#define UCS_TO_UTF_LEN(c)	((c) < 0x0080 ? 1 : ((c) < 0x0800 ? 2 : 3))


static u_int16_t ucs_decompose __P((u_int16_t, u_int16_t *));


/*
 * utf8_encodelen - Calculates the UTF-8 encoding length for a UCS-2 filename
 *
 * NOTES:
 *    If '/' chars are allowed on disk then an alternate
 *    (replacement) char must be provided in altslash.
 *
 * input flags:
 *    UTF_REVERSE_ENDIAN: UCS-2 byteorder is opposite current runtime
 */
size_t
utf8_encodelen(ucsp, ucslen, altslash, flags)
	const u_int16_t * ucsp;
	size_t ucslen;
	u_int16_t altslash;
	int flags;
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
		if (altslash && ucs_ch == '/')
			ucs_ch = altslash;
		if (ucs_ch == '\0')
			ucs_ch = 0xc080;
		
		len += UCS_TO_UTF_LEN(ucs_ch);
	}

	return (len);
}


/*
 * utf8_encodestr - Encodes a UCS-2 (Unicode) string to UTF-8
 *
 * NOTES:
 *    The resulting UTF-8 string is not null terminated.
 *
 *    If '/' chars are allowed on disk then an alternate
 *    (replacement) char must be provided in altslash.
 *
 * input flags:
 *    UTF_REVERSE_ENDIAN: UCS-2 byteorder is opposite current runtime
 *    UTF_NO_NULL_TERM:  don't add NULL termination to UTF-8 output
 */
int utf8_encodestr(ucsp, ucslen, utf8p, utf8len, buflen, altslash, flags)
	const u_int16_t * ucsp;
	size_t ucslen;
	u_int8_t * utf8p;
	size_t * utf8len;
	size_t buflen;
	u_int16_t altslash;
	int flags;
{
	u_int8_t * bufstart;
	u_int8_t * bufend;
	u_int16_t ucs_ch;
	int charcnt;
	int swapbytes = (flags & UTF_REVERSE_ENDIAN);
	int nullterm = ((flags & UTF_NO_NULL_TERM) == 0);
	int result = 0;
	
	bufstart = utf8p;
	bufend = bufstart + buflen;
	if (nullterm)
		--bufend;
	charcnt = ucslen / 2;

	while (charcnt-- > 0) {
		ucs_ch = *ucsp++;

		if (swapbytes)
			ucs_ch = NXSwapShort(ucs_ch);
		if (altslash && ucs_ch == '/')
			ucs_ch = altslash;

		if ((ucs_ch < 0x0080) && (ucs_ch != '\0')) {
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
			/* NOTE: NULL maps to 0xC080 */
			*utf8p++ = (ucs_ch >> 6) | 0xc0;
			*utf8p++ = (ucs_ch & 0x3f) | 0x80;

		} else {
			if ((utf8p + 2) >= bufend) {
				result = ENAMETOOLONG;
				break;
			}
			*utf8p++ = (ucs_ch >> 12) | 0xe0;
			*utf8p++ = ((ucs_ch >> 6) & 0x3f) | 0x80;
			*utf8p++ = ((ucs_ch) & 0x3f) | 0x80;
		}	
	}
	
	*utf8len = utf8p - bufstart;
	if (nullterm)
		*utf8p++ = '\0';

	return (result);
}


/*
 * utf8_decodestr - Decodes a UTF-8 string back to UCS-2 (Unicode)
 *
 * NOTES:
 *    The input UTF-8 string does not need to be null terminated
 *    if utf8len is set.
 *
 *    If '/' chars are allowed on disk then an alternate
 *    (replacement) char must be provided in altslash.
 *
 * input flags:
 *    UTF_REV_ENDIAN:   UCS-2 byteorder is oposite current runtime
 *    UTF_DECOMPOSED:   UCS-2 output string must be fully decompsed
 */
int
utf8_decodestr(utf8p, utf8len, ucsp, ucslen, buflen, altslash, flags)
	const u_int8_t* utf8p;
	size_t utf8len;
	u_int16_t* ucsp;
	size_t *ucslen;
	size_t buflen;
	u_int16_t altslash;
	int flags;
{
	u_int16_t* bufstart;
	u_int16_t* bufend;
	u_int16_t ucs_ch;
	u_int8_t byte;
	int result = 0;
	int decompose, swapbytes;

	decompose = (flags & UTF_DECOMPOSED);
	swapbytes = (flags & UTF_REVERSE_ENDIAN);

	bufstart = ucsp;
	bufend = (u_int16_t *)((u_int8_t *)ucsp + buflen);

	while (utf8len-- > 0 && (byte = *utf8p++) != '\0') {
		if (ucsp >= bufend) {
			result = ENAMETOOLONG;
			goto stop;
		}

		/* check for ascii */
		if (byte < 0x80) {
			ucs_ch = byte;
		} else {
			switch (byte & 0xf0) {
			/*  2 byte sequence*/
			case 0xc0:
			case 0xd0:
				/* extract bits 6 - 10 from first byte */
				ucs_ch = (byte & 0x1F) << 6;  
				if ((ucs_ch < 0x0080) && (*utf8p != 0x80)) {
					result = EINVAL;  /* seq not minimal */
					goto stop;
				}
				break;
			/* 3 byte sequence*/
			case 0xe0:
				/* extract bits 12 - 15 from first byte */
				ucs_ch = (byte & 0x0F) << 6;

				/* extract bits 6 - 11 from second byte */
				if (((byte = *utf8p++) & 0xc0) != 0x80) {
					result = EINVAL;
					goto stop;
				}
				utf8len--;

				ucs_ch += (byte & 0x3F);
				ucs_ch <<= 6;

				if (ucs_ch < 0x0800) {
					result = EINVAL; /* seq not minimal */
					goto stop;
				}
				break;
			default:
				result = EINVAL;
				goto stop;
			}

			/* extract bits 0 - 5 from final byte */
			if (((byte = *utf8p++) & 0xc0) != 0x80) {
				result = EINVAL;
				goto stop;
			}
			utf8len--;
			ucs_ch += (byte & 0x3F);  

			if (decompose) {
				u_int16_t comb_ch;

				ucs_ch = ucs_decompose(ucs_ch, &comb_ch);

				if (comb_ch) {
					if (swapbytes)
						*ucsp++ = NXSwapShort(ucs_ch);
					else
						*ucsp++ = ucs_ch;

					if (ucsp >= bufend) {
						result = ENAMETOOLONG;
						goto stop;
					}

					ucs_ch = comb_ch;
				}
			}
		}

		if (ucs_ch == altslash)
			ucs_ch = '/';
		if (swapbytes)
			ucs_ch = NXSwapShort(ucs_ch);

		*ucsp++ = ucs_ch;
	}
stop:
	*ucslen = (u_int8_t*)ucsp - (u_int8_t*)bufstart;

	return (result);
}


/*
 * Lookup tables for Unicode chars 0x00C0 thru 0x00FF
 * primary_char yields first decomposed char. If this
 * char is an alpha char then get the combining char
 * from the combining_char table and add 0x0300 to it.
 */

static unsigned char primary_char[64] = {
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0xC6, 0x43,

	0x45, 0x45, 0x45, 0x45, 0x49, 0x49, 0x49, 0x49,

	0xD0, 0x4E, 0x4F, 0x4F, 0x4F, 0x4F, 0x4F, 0xD7,

	0xD8, 0x55, 0x55, 0x55, 0x55, 0x59, 0xDE, 0xDF,

	0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0xE6, 0x63,

	0x65, 0x65, 0x65, 0x65, 0x69, 0x69, 0x69, 0x69,

	0xF0, 0x6E, 0x6F, 0x6F, 0x6F, 0x6F, 0x6F, 0xF7,

	0xF8, 0x75, 0x75, 0x75, 0x75, 0x79, 0xFE, 0x79,
};

static unsigned char combining_char[64] = {
	0x00, 0x01, 0x02, 0x03, 0x08, 0x0A, 0xFF, 0x27,

	0x00, 0x01, 0x02, 0x08, 0x00, 0x01, 0x02, 0x08,

	0xFF, 0x03, 0x00, 0x01, 0x02, 0x03, 0x08, 0xFF,

	0xFF, 0x00, 0x01, 0x02, 0x08, 0x01, 0xFF, 0xFF,

	0x00, 0x01, 0x02, 0x03, 0x08, 0x0A, 0xFF, 0x27,

	0x00, 0x01, 0x02, 0x08, 0x00, 0x01, 0x02, 0x08,

	0xFF, 0x03, 0x00, 0x01, 0x02, 0x03, 0x08, 0xFF,

	0xFF, 0x00, 0x01, 0x02, 0x08, 0x01, 0xFF, 0x08
};


/* CJK codepoints 0x3000 ~ 0x30FF */
static const unsigned long __CJKDecompBitmap[] = {
    0x00000000, 0x00000000, 0x000AAAAA, 0xA540DB6C,	/* 0x3000 */
    0x00000802, 0x000AAAAA, 0xA540DB6C, 0x000009E2,	/* 0x3080 */
};
#define IS_DECOMPOSABLE(table,unicodeVal) \
	(table[(unicodeVal) / 32] & (1 << (31 - ((unicodeVal) % 32))))

/*
 * ucs_decompose - decompose a composed UCS-2 char
 *
 * Composed Unicode characters are forbidden on
 * HFS Plus volumes. ucs_decompose will convert a
 * composed character into its correct decomposed
 * sequence.
 *
 * Currently only MacRoman and MacJapanese chars
 * are handled.  Other composed characters are
 * passed unchanged.
 */
static u_int16_t
ucs_decompose(register u_int16_t ch, u_int16_t *cmb)
{
	u_int16_t base;
	
	*cmb = 0;

	if ((ch <= 0x00FF) && (ch >= 0x00C0)) {
		ch -= 0x00C0;
		
		base = (u_int16_t) primary_char[ch];

		if (base <= 'z') {
			*cmb = (u_int16_t)0x0300 + (u_int16_t)combining_char[ch];
		}
	} else if ((ch > 0x3000) && (ch < 0x3100) &&
		   IS_DECOMPOSABLE(__CJKDecompBitmap, ch - 0x3000)) {

		/* Handle HIRAGANA LETTERs */
		switch(ch) {
		case 0x3071: base = 0x306F; *cmb = 0x309A; break; /* PA */
		case 0x3074: base = 0x3072; *cmb = 0x309A; break; /* PI */
		case 0x3077: base = 0x3075; *cmb = 0x309A; break; /* PU */
		case 0x307A: base = 0x3078; *cmb = 0x309A; break; /* PE */

		case 0x307D: base = 0x307B; *cmb = 0x309A; break; /* PO */
		case 0x3094: base = 0x3046; *cmb = 0x3099; break; /* VU */
		case 0x30D1: base = 0x30CF; *cmb = 0x309A; break; /* PA */
		case 0x30D4: base = 0x30D2; *cmb = 0x309A; break; /* PI */

		case 0x30D7: base = 0x30D5; *cmb = 0x309A; break; /* PU */
		case 0x30DA: base = 0x30D8; *cmb = 0x309A; break; /* PE */
		case 0x30DD: base = 0x30DB; *cmb = 0x309A; break; /* PO */
		case 0x30F4: base = 0x30A6; *cmb = 0x3099; break; /* VU */

		case 0x30F7: base = 0x30EF; *cmb = 0x3099; break; /* VA */
		case 0x30F8: base = 0x30F0; *cmb = 0x3099; break; /* VI */
		case 0x30F9: base = 0x30F1; *cmb = 0x3099; break; /* VE */
		case 0x30FA: base = 0x30F2; *cmb = 0x3099; break; /* VO */
		
		default:
			/* the rest (41 of them) have a simple conversion */
			base = ch - 1;
			*cmb = 0x3099;
		}
	} else {
		base = ch;
	}
	
	return (base);
}

