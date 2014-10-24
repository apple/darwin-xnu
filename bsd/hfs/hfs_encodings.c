/*
 * Copyright (c) 2000-2013 Apple Computer, Inc. All rights reserved.
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

#include <sys/types.h>
#include <sys/errno.h>

#if HFS

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/utfconv.h>
#include <kern/host.h>
#include <mach/host_priv.h>
#include <libkern/OSKextLib.h>
#include <libkern/OSKextLibPrivate.h>

#include "hfs.h"


lck_grp_t * encodinglst_lck_grp;
lck_grp_attr_t * encodinglst_lck_grp_attr;
lck_attr_t * encodinglst_lck_attr;


/* hfs encoding converter list */
SLIST_HEAD(encodinglst, hfs_encoding) hfs_encoding_list = {0};

lck_mtx_t  encodinglst_mutex;

/* hfs encoding converter entry */
struct	hfs_encoding {
	SLIST_ENTRY(hfs_encoding)  link;
	int			refcount;
	int			kmod_id;
	u_int32_t	encoding;
	hfs_to_unicode_func_t	get_unicode_func;
	unicode_to_hfs_func_t	get_hfsname_func;
};

#define MAX_HFS_UNICODE_CHARS	(15*5)

#if CONFIG_HFS_STD
static int unicode_to_mac_roman(UniChar *uni_str, u_int32_t unicodeChars, Str31 hfs_str);
#endif

void
hfs_converterinit(void)
{
	SLIST_INIT(&hfs_encoding_list);

	encodinglst_lck_grp_attr= lck_grp_attr_alloc_init();
	encodinglst_lck_grp  = lck_grp_alloc_init("cnode_hash", encodinglst_lck_grp_attr);
	encodinglst_lck_attr = lck_attr_alloc_init();

	lck_mtx_init(&encodinglst_mutex, encodinglst_lck_grp, encodinglst_lck_attr);

#if CONFIG_HFS_STD
	/*
	 * add resident MacRoman converter and take a reference
	 * since its always "loaded". MacRoman is the default converter
	 * for HFS standard volumes.
	 *
	 * Only do this if we are actually supporting HFS standard 
	 * volumes. The converter is not used on configurations 
	 * that do not support HFS standard. 
	 */
	hfs_addconverter(0, kTextEncodingMacRoman, mac_roman_to_unicode, unicode_to_mac_roman);
	SLIST_FIRST(&hfs_encoding_list)->refcount++;
#endif

}

#if !CONFIG_HFS_STD

/* 
 * Function stubs are needed for KPI export.  
 * It is a little swizzly to have two separate copies of the stub functions in this file
 * but the prototypes of these functions are different if we're using the real headers
 * vs. the dummy prototypes at the end of the file.  (hfs_to_unicode_func_t vs. void*) 
 * 
 * As a result, we need our own copies in the no-HFS-Standard configuration
 */
int hfs_addconverter( __unused int id, 
					  __unused u_int32_t encoding, 
					  __unused hfs_to_unicode_func_t get_unicode, 
					  __unused unicode_to_hfs_func_t get_hfsname )
{
	return(0);
}

int hfs_getconverter(	__unused u_int32_t encoding, 
						__unused hfs_to_unicode_func_t *get_unicode, 
						__unused unicode_to_hfs_func_t *get_hfsname)
{
	return(EINVAL);
}

int hfs_relconverter(__unused u_int32_t encoding)
{
	return(EINVAL);
}

int hfs_remconverter(__unused int id, __unused u_int32_t encoding)
{
	return(0);
}

#else 

/* 
 * For configurations that do support HFS standard, we need all of these..
 */

/*
 * hfs_addconverter - add an HFS encoding converter
 *
 * This is called exclusivly by kernel loadable modules
 * (like HFS_Japanese.kmod) to register hfs encoding
 * conversion routines.
 *
 */
int
hfs_addconverter(int id, u_int32_t encoding, hfs_to_unicode_func_t get_unicode, unicode_to_hfs_func_t get_hfsname)
{
	struct hfs_encoding *encp;
	
	MALLOC(encp, struct hfs_encoding *, sizeof(struct hfs_encoding), M_TEMP, M_WAITOK);

	lck_mtx_lock(&encodinglst_mutex);

	encp->link.sle_next = NULL;
	encp->refcount = 0;
	encp->encoding = encoding;
	encp->get_unicode_func = get_unicode;
	encp->get_hfsname_func = get_hfsname;
	encp->kmod_id = id;
	SLIST_INSERT_HEAD(&hfs_encoding_list, encp, link);

	lck_mtx_unlock(&encodinglst_mutex);
	return (0);
}


/*
 * hfs_remconverter - remove an HFS encoding converter
 *
 * Can be called by a kernel loadable module's finalize
 * routine to remove an encoding converter so that the
 * module (i.e. the code) can be unloaded.
 *
 * However, in the normal case, the removing and unloading
 * of these converters is done in hfs_relconverter.
 * The call is initiated from within the kernel during the unmounting of an hfs voulume.
 */
int
hfs_remconverter(int id, u_int32_t encoding)
{
	struct hfs_encoding *encp;

	lck_mtx_lock(&encodinglst_mutex);
	SLIST_FOREACH(encp, &hfs_encoding_list, link) {
		if (encp->encoding == encoding && encp->kmod_id == id) {
			encp->refcount--;
			
			/* if converter is no longer in use, release it */
			if (encp->refcount <= 0 && encp->kmod_id != 0) {
				SLIST_REMOVE(&hfs_encoding_list, encp, hfs_encoding, link);
				lck_mtx_unlock(&encodinglst_mutex);
    				FREE(encp, M_TEMP);
    				return (0);
 			} else {
 				lck_mtx_unlock(&encodinglst_mutex);
				return (1);   /* busy */
			}
			break;
		}
	}
	lck_mtx_unlock(&encodinglst_mutex);

	return (0);
}


/*
 * hfs_getconverter - get HFS encoding converters
 *
 * Normally called during the mounting of an hfs voulume.
 */
int
hfs_getconverter(u_int32_t encoding, hfs_to_unicode_func_t *get_unicode, unicode_to_hfs_func_t *get_hfsname)
{
	struct hfs_encoding *encp;
	int found = 0;

	lck_mtx_lock(&encodinglst_mutex);
	SLIST_FOREACH(encp, &hfs_encoding_list, link) {
		if (encp->encoding == encoding) {
			found = 1;
			*get_unicode = encp->get_unicode_func;
			*get_hfsname = encp->get_hfsname_func;
			++encp->refcount;
			break;
		}
	}
	lck_mtx_unlock(&encodinglst_mutex);

	if (!found) {
		*get_unicode = NULL;
		*get_hfsname = NULL;
		return (EINVAL);
	}
	
	return (0);
}


/*
 * hfs_relconverter - release interest in an HFS encoding converter
 *
 * Normally called during the unmounting of an hfs voulume.
 */
int
hfs_relconverter(u_int32_t encoding)
{
	struct hfs_encoding *encp;

	lck_mtx_lock(&encodinglst_mutex);
	SLIST_FOREACH(encp, &hfs_encoding_list, link) {
		if (encp->encoding == encoding) {
			encp->refcount--;
			
			/* if converter is no longer in use, release it */
			if (encp->refcount <= 0 && encp->kmod_id != 0) {
				uint32_t loadTag = (uint32_t)encp->kmod_id;

				SLIST_REMOVE(&hfs_encoding_list, encp, hfs_encoding, link);
				lck_mtx_unlock(&encodinglst_mutex);
 
 				FREE(encp, M_TEMP);
   				(void)OSKextUnloadKextWithLoadTag(loadTag);
				return (0);
			}
			lck_mtx_unlock(&encodinglst_mutex);
			return (0);
		}
	}
	lck_mtx_unlock(&encodinglst_mutex);

	return (EINVAL);
}

/*
 * Convert HFS encoded string into UTF-8
 *
 * Unicode output is fully decomposed
 * '/' chars are converted to ':'
 */
int
hfs_to_utf8(ExtendedVCB *vcb, const Str31 hfs_str, ByteCount maxDstLen, ByteCount *actualDstLen, unsigned char* dstStr)
{
	int error;
	UniChar uniStr[MAX_HFS_UNICODE_CHARS];
	ItemCount uniCount;
	size_t utf8len;
	hfs_to_unicode_func_t hfs_get_unicode = VCBTOHFS(vcb)->hfs_get_unicode;
	u_int8_t pascal_length = 0;

	/* 
	 * Validate the length of the Pascal-style string before passing it
	 * down to the decoding engine.
	 */
	pascal_length = *((const u_int8_t*)(hfs_str));
	if (pascal_length > 31) {
		/* invalid string; longer than 31 bytes */
		error = EINVAL;
		return error;
	}	
	
	error = hfs_get_unicode(hfs_str, uniStr, MAX_HFS_UNICODE_CHARS, &uniCount);
	
	if (uniCount == 0)
		error = EINVAL;

	if (error == 0) {
		error = utf8_encodestr(uniStr, uniCount * sizeof(UniChar), dstStr, &utf8len, maxDstLen , ':', 0);
		if (error == ENAMETOOLONG)
			*actualDstLen = utf8_encodelen(uniStr, uniCount * sizeof(UniChar), ':', 0);
		else
			*actualDstLen = utf8len;
	}

	return error;
}

/*
 * When an HFS name cannot be encoded with the current
 * volume encoding then MacRoman is used as a fallback.
 */
int
mac_roman_to_utf8(const Str31 hfs_str, ByteCount maxDstLen, ByteCount *actualDstLen, unsigned char* dstStr)
{
	int error;
	UniChar uniStr[MAX_HFS_UNICODE_CHARS];
	ItemCount uniCount;
	size_t utf8len;
	u_int8_t pascal_length = 0;

	/* 
	 * Validate the length of the Pascal-style string before passing it
	 * down to the decoding engine.
	 */
	pascal_length = *((const u_int8_t*)(hfs_str));
	if (pascal_length > 31) {
		/* invalid string; longer than 31 bytes */
		error = EINVAL;
		return error;
	}

	error = mac_roman_to_unicode(hfs_str, uniStr, MAX_HFS_UNICODE_CHARS, &uniCount);
	
	if (uniCount == 0)
		error = EINVAL;

	if (error == 0) {
		error = utf8_encodestr(uniStr, uniCount * sizeof(UniChar), dstStr, &utf8len, maxDstLen , ':', 0);
		if (error == ENAMETOOLONG)
			*actualDstLen = utf8_encodelen(uniStr, uniCount * sizeof(UniChar), ':', 0);
		else
			*actualDstLen = utf8len;
	}

	return error;
}

/*
 * Convert Unicode string into HFS encoding
 *
 * ':' chars are converted to '/'
 * Assumes input represents fully decomposed Unicode
 */
int
unicode_to_hfs(ExtendedVCB *vcb, ByteCount srcLen, u_int16_t* srcStr, Str31 dstStr, int retry)
{
	int error;
	unicode_to_hfs_func_t hfs_get_hfsname = VCBTOHFS(vcb)->hfs_get_hfsname;

	error = hfs_get_hfsname(srcStr, srcLen/sizeof(UniChar), dstStr);
	if (error && retry) {
		error = unicode_to_mac_roman(srcStr, srcLen/sizeof(UniChar), dstStr);
	}
	return error;
}

/*
 * Convert UTF-8 string into HFS encoding
 *
 * ':' chars are converted to '/'
 * Assumes input represents fully decomposed Unicode
 */
int
utf8_to_hfs(ExtendedVCB *vcb, ByteCount srcLen, const unsigned char* srcStr, Str31 dstStr/*, int retry*/)
{
	int error;
	UniChar uniStr[MAX_HFS_UNICODE_CHARS];
	size_t ucslen;

	error = utf8_decodestr(srcStr, srcLen, uniStr, &ucslen, sizeof(uniStr), ':', 0);
	if (error == 0)
		error = unicode_to_hfs(vcb, ucslen, uniStr, dstStr, 1);

	return error;
}


int
utf8_to_mac_roman(ByteCount srcLen, const unsigned char* srcStr, Str31 dstStr)
{
	int error;
	UniChar uniStr[MAX_HFS_UNICODE_CHARS];
	size_t ucslen;

	error = utf8_decodestr(srcStr, srcLen, uniStr, &ucslen, sizeof(uniStr), ':', 0);
	if (error == 0)
		error = unicode_to_mac_roman(uniStr, ucslen/sizeof(UniChar), dstStr);

	return error;
}

/*
 * HFS MacRoman to/from Unicode conversions are built into the kernel
 * All others hfs encodings are loadable.
 */

/* 0x00A0 - 0x00FF = Latin 1 Supplement (30 total) */
static u_int8_t gLatin1Table[] = {
  /*		  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F  */
  /* 0x00A0 */	0xCA, 0xC1, 0xA2, 0xA3, 0xDB, 0xB4,  '?', 0xA4, 0xAC, 0xA9, 0xBB, 0xC7, 0xC2,  '?', 0xA8, 0xF8,
  /* 0x00B0 */	0xA1, 0XB1,  '?',  '?', 0xAB, 0xB5, 0xA6, 0xe1, 0xFC,  '?', 0xBC, 0xC8,  '?',  '?',  '?', 0xC0,
  /* 0x00C0 */	 '?',  '?',  '?',  '?',  '?',  '?', 0xAE,  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',
  /* 0x00D0 */	 '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?', 0xAF,  '?',  '?',  '?',  '?',  '?',  '?', 0xA7,
  /* 0x00E0 */	 '?',  '?',  '?',  '?',  '?',  '?', 0xBE,  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',
  /* 0x00F0 */	 '?',  '?',  '?',  '?',  '?',  '?',  '?', 0xD6, 0xBF,  '?',  '?',  '?',  '?',  '?',  '?',  '?'
};

/* 0x02C0 - 0x02DF = Spacing Modifiers (8 total) */
static u_int8_t gSpaceModsTable[] = {
  /*		  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F  */
  /* 0x02C0 */	 '?',  '?',  '?',  '?',  '?',  '?', 0xF6, 0xFF,  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',
  /* 0x02D0 */	 '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?', 0xF9, 0xFA, 0xFB, 0xFE, 0xF7, 0xFD,  '?',  '?'
};

/* 0x2010 - 0x20AF = General Punctuation (17 total) */
static u_int8_t gPunctTable[] = {
  /*		  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F  */
  /* 0x2010 */	 '?',  '?',  '?', 0xd0, 0xd1,  '?',  '?',  '?', 0xd4, 0xd5, 0xe2,  '?', 0xd2, 0xd3, 0xe3,  '?',
  /* 0x2020 */	0xa0, 0xe0, 0xa5,  '?',  '?',  '?', 0xc9,  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',
  /* 0x2030 */	0xe4,  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?', 0xdc, 0xdd,  '?',  '?',  '?',  '?',  '?',
  /* 0x2040 */	 '?',  '?',  '?',  '?', 0xda,  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',
  /* 0x2050 */	 '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',
  /* 0x2060 */	 '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',
  /* 0x2070 */	 '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',
  /* 0x2080 */	 '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',
  /* 0x2090 */	 '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',
  /* 0x20A0 */	 '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?', 0xdb,  '?',  '?',  '?'
};

/* 0x22xx = Mathematical Operators (11 total) */
static u_int8_t gMathTable[] = {
  /*		  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F  */
  /* 0x2200 */	 '?',  '?', 0xb6,  '?',  '?',  '?', 0xc6,  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?', 0xb8,
  /* 0x2210 */	 '?', 0xb7,  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?', 0xc3,  '?',  '?',  '?', 0xb0,  '?',
  /* 0x2220 */	 '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?', 0xba,  '?',  '?',  '?',  '?',
  /* 0x2230 */	 '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',
  /* 0x2240 */	 '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?', 0xc5,  '?',  '?',  '?',  '?',  '?',  '?',  '?',
  /* 0x2250 */	 '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',
  /* 0x2260 */	0xad,  '?',  '?',  '?', 0xb2, 0xb3,  '?',  '?'
};

/* */
static u_int8_t gReverseCombTable[] = {
  /*		  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F  */
  /* 0x40 */	0xDA, 0x40, 0xDA, 0xDA, 0xDA, 0x56, 0xDA, 0xDA, 0xDA, 0x6C, 0xDA, 0xDA, 0xDA, 0xDA, 0x82, 0x98,
  /* 0x50 */	0xDA, 0xDA, 0xDA, 0xDA, 0xDA, 0xAE, 0xDA, 0xDA, 0xDA, 0xC4, 0xDA, 0xDA, 0xDA, 0xDA, 0xDA, 0xDA,
  /* 0x60 */	0xDA, 0x4B, 0xDA, 0xDA, 0xDA, 0x61, 0xDA, 0xDA, 0xDA, 0x77, 0xDA, 0xDA, 0xDA, 0xDA, 0x8D, 0xA3,
  /* 0x70 */	0xDA, 0xDA, 0xDA, 0xDA, 0xDA, 0xB9, 0xDA, 0xDA, 0xDA, 0xCF, 0xDA, 0xDA, 0xDA, 0xDA, 0xDA, 0xDA,

  /* Combining Diacritical Marks (0x0300 - 0x030A) */
  /*              0     1     2     3     4     5     6     7     8     9     A  */
  /*  'A'   */
  /* 0x0300 */	0xCB, 0xE7, 0xE5, 0xCC,  '?',  '?',  '?',  '?', 0x80,  '?', 0x81,

  /*  'a'   */
  /* 0x0300 */	0x88, 0x87, 0x89, 0x8B,  '?',  '?',  '?',  '?', 0x8A,  '?', 0x8C,

  /*  'E'   */
  /* 0x0300 */	0xE9, 0x83, 0xE6,  '?',  '?',  '?',  '?',  '?', 0xE8,  '?',  '?',

  /*  'e'   */
  /* 0x0300 */	0x8F, 0x8E, 0x90,  '?',  '?',  '?',  '?',  '?', 0x91,  '?',  '?',

  /*  'I'   */
  /* 0x0300 */	0xED, 0xEA, 0xEB,  '?',  '?',  '?',  '?',  '?', 0xEC,  '?',  '?',

  /*  'i'   */
  /* 0x0300 */	0x93, 0x92, 0x94,  '?',  '?',  '?',  '?',  '?', 0x95,  '?',  '?',

  /*  'N'   */
  /* 0x0300 */	 '?',  '?',  '?', 0x84,  '?',  '?',  '?',  '?',  '?',  '?',  '?',

  /*  'n'   */
  /* 0x0300 */	 '?',  '?',  '?', 0x96,  '?',  '?',  '?',  '?',  '?',  '?',  '?',

  /*  'O'   */
  /* 0x0300 */	0xF1, 0xEE, 0xEF, 0xCD,  '?',  '?',  '?',  '?', 0x85,  '?',  '?',

  /*  'o'   */
  /* 0x0300 */	0x98, 0x97, 0x99, 0x9B,  '?',  '?',  '?',  '?', 0x9A,  '?',  '?',

  /*  'U'   */
  /* 0x0300 */	0xF4, 0xF2, 0xF3,  '?',  '?',  '?',  '?',  '?', 0x86,  '?',  '?',

  /*  'u'   */
  /* 0x0300 */	0x9D, 0x9C, 0x9E,  '?',  '?',  '?',  '?',  '?', 0x9F,  '?',  '?',

  /*  'Y'   */
  /* 0x0300 */	 '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?', 0xD9,  '?',  '?',

  /*  'y'   */
  /* 0x0300 */	 '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?', 0xD8,  '?',  '?',

  /*  else  */
  /* 0x0300 */	 '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?',  '?'
};


/*
 * Convert Unicode string into HFS MacRoman encoding
 *
 * Assumes Unicode input is fully decomposed
 */
static int unicode_to_mac_roman(UniChar *uni_str, u_int32_t unicodeChars, Str31 hfs_str)
{
	u_int8_t	*p;
	const UniChar	*u;
	UniChar		c;
	UniChar		mask;
	u_int16_t	inputChars;
	u_int16_t	pascalChars;
	OSErr		result = noErr;
	u_int8_t	lsb;
	u_int8_t	prevChar;
	u_int8_t	mc;

	mask = (UniChar) 0xFF80;
	p = &hfs_str[1];
	u = uni_str;
	inputChars = unicodeChars;
	pascalChars = prevChar = 0;
	
	while (inputChars) {
		c = *(u++);
		lsb = (u_int8_t) c;

		/*
		 * If its not 7-bit ascii, then we need to map it
		 */
		if ( c & mask ) {
			mc = '?';
			switch (c & 0xFF00) {
			case 0x0000:
				if (lsb >= 0xA0)
					mc = gLatin1Table[lsb - 0xA0];
				break;

			case 0x0200:
				if (lsb >= 0xC0 && lsb <= 0xDF)
					mc = gSpaceModsTable[lsb - 0xC0];
				break;

			case 0x2000:
				if (lsb >= 0x10 && lsb <= 0xAF)
					mc = gPunctTable[lsb- 0x10];
				break;

			case 0x2200:
				if (lsb < 0x68)
					mc = gMathTable[lsb];
				break;

			case 0x0300:
				if (c <= 0x030A) {
					if (prevChar >= 'A' && prevChar < 'z') {
						mc = gReverseCombTable[gReverseCombTable[prevChar - 0x40] + lsb];
						--p;	/* backup over base char */
						--pascalChars;
					}
				} else {
					switch (c) {
					case 0x0327:	/* combining cedilla */
						if (prevChar == 'C')
							mc = 0x82;
						else if (prevChar == 'c')
							mc = 0x8D;
						else
							break;
						--p;	/* backup over base char */
						--pascalChars;
						break;

					case 0x03A9: mc = 0xBD; break;	/* omega */

					case 0x03C0: mc = 0xB9; break;	/* pi */
					}
				}
				break;
				
			default:
				switch (c) {
				case 0x0131: mc = 0xf5; break;	/* dotless i */

				case 0x0152: mc = 0xce; break;	/* OE */

				case 0x0153: mc = 0xcf; break;	/* oe */

				case 0x0192: mc = 0xc4; break;	/* Ä */

				case 0x2122: mc = 0xaa; break;	/* TM */

				case 0x25ca: mc = 0xd7; break;	/* diamond */

				case 0xf8ff: mc = 0xf0; break;	/* apple logo */

				case 0xfb01: mc = 0xde; break;	/* fi */

				case 0xfb02: mc = 0xdf; break;	/* fl */
				}
			} /* end switch (c & 0xFF00) */
			
			/*
			 * If we have an unmapped character then we need to mangle the name...
			 */
			if (mc == '?')
				result = kTECUsedFallbacksStatus;
			
			prevChar = 0;
			lsb = mc;

		} else {
			prevChar = lsb;
		}

		if (pascalChars >= 31)
			break;

		*(p++) = lsb;
		++pascalChars;
		--inputChars;

	} /* end while */
	
	hfs_str[0] = pascalChars;
	
	if (inputChars > 0)
		result = ENAMETOOLONG;	/* ran out of room! */

	return result;
}


static UniChar gHiBitBaseUnicode[128] = {
  /* 0x80 */	0x0041, 0x0041, 0x0043, 0x0045, 0x004e, 0x004f, 0x0055, 0x0061, 
  /* 0x88 */	0x0061, 0x0061, 0x0061, 0x0061, 0x0061, 0x0063, 0x0065, 0x0065, 
  /* 0x90 */	0x0065, 0x0065, 0x0069, 0x0069, 0x0069, 0x0069, 0x006e, 0x006f, 
  /* 0x98 */	0x006f, 0x006f, 0x006f, 0x006f, 0x0075, 0x0075, 0x0075, 0x0075, 
  /* 0xa0 */	0x2020, 0x00b0, 0x00a2, 0x00a3, 0x00a7, 0x2022, 0x00b6, 0x00df, 
  /* 0xa8 */	0x00ae, 0x00a9, 0x2122, 0x00b4, 0x00a8, 0x2260, 0x00c6, 0x00d8, 
  /* 0xb0 */	0x221e, 0x00b1, 0x2264, 0x2265, 0x00a5, 0x00b5, 0x2202, 0x2211, 
  /* 0xb8 */	0x220f, 0x03c0, 0x222b, 0x00aa, 0x00ba, 0x03a9, 0x00e6, 0x00f8, 
  /* 0xc0 */	0x00bf, 0x00a1, 0x00ac, 0x221a, 0x0192, 0x2248, 0x2206, 0x00ab, 
  /* 0xc8 */	0x00bb, 0x2026, 0x00a0, 0x0041, 0x0041, 0x004f, 0x0152, 0x0153, 
  /* 0xd0 */	0x2013, 0x2014, 0x201c, 0x201d, 0x2018, 0x2019, 0x00f7, 0x25ca, 
  /* 0xd8 */	0x0079, 0x0059, 0x2044, 0x20ac, 0x2039, 0x203a, 0xfb01, 0xfb02, 
  /* 0xe0 */	0x2021, 0x00b7, 0x201a, 0x201e, 0x2030, 0x0041, 0x0045, 0x0041, 
  /* 0xe8 */	0x0045, 0x0045, 0x0049, 0x0049, 0x0049, 0x0049, 0x004f, 0x004f, 
  /* 0xf0 */	0xf8ff, 0x004f, 0x0055, 0x0055, 0x0055, 0x0131, 0x02c6, 0x02dc, 
  /* 0xf8 */	0x00af, 0x02d8, 0x02d9, 0x02da, 0x00b8, 0x02dd, 0x02db, 0x02c7
};

static UniChar gHiBitCombUnicode[128] = {
  /* 0x80 */	0x0308, 0x030a, 0x0327, 0x0301, 0x0303, 0x0308, 0x0308, 0x0301, 
  /* 0x88 */	0x0300, 0x0302, 0x0308, 0x0303, 0x030a, 0x0327, 0x0301, 0x0300, 
  /* 0x90 */	0x0302, 0x0308, 0x0301, 0x0300, 0x0302, 0x0308, 0x0303, 0x0301, 
  /* 0x98 */	0x0300, 0x0302, 0x0308, 0x0303, 0x0301, 0x0300, 0x0302, 0x0308, 
  /* 0xa0 */	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
  /* 0xa8 */	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 
  /* 0xb0 */	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 
  /* 0xb8 */	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 
  /* 0xc0 */	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 
  /* 0xc8 */	0x0000, 0x0000, 0x0000, 0x0300, 0x0303, 0x0303, 0x0000, 0x0000, 
  /* 0xd0 */	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 
  /* 0xd8 */	0x0308, 0x0308, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 
  /* 0xe0 */	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0302, 0x0302, 0x0301, 
  /* 0xe8 */	0x0308, 0x0300, 0x0301, 0x0302, 0x0308, 0x0300, 0x0301, 0x0302, 
  /* 0xf0 */	0x0000, 0x0300, 0x0301, 0x0302, 0x0300, 0x0000, 0x0000, 0x0000, 
  /* 0xf8 */	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
};


/*
 * Convert HFS MacRoman encoded string into Unicode
 *
 * Unicode output is fully decomposed
 */
int
mac_roman_to_unicode(const Str31 hfs_str, UniChar *uni_str,
				__unused u_int32_t maxCharLen, u_int32_t *unicodeChars)
{
	const u_int8_t  *p;
	UniChar  *u;
	u_int16_t  pascalChars;
	u_int8_t  c;

	p = hfs_str;
	u = uni_str;

	*unicodeChars = pascalChars = *(p++);	/* pick up length byte */

	while (pascalChars--) {
		c = *(p++);

		if ( (int8_t) c >= 0 ) {		/* check if seven bit ascii */
			*(u++) = (UniChar) c;	/* just pad high byte with zero */
		} else { /* its a hi bit character */
			UniChar uc;

			c &= 0x7F;
			*(u++) = uc = gHiBitBaseUnicode[c];
			
			/*
			 * if the unicode character we get back is an alpha char
			 * then we must have an additional combining character
			 */
			if ((uc <= (UniChar) 'z') && (uc >= (UniChar) 'A')) {
				*(u++) = gHiBitCombUnicode[c];
				++(*unicodeChars);
			}
		}
	}
	
	return noErr;
}

#endif /* CONFIG_STD_HFS */

#else /* not HFS */

/*
 * These function prototypes are here because hfs.h is not #included
 * so its prototypes are not provided. These are needed because they are exported
 * as KPI for the conversion subroutines during mounting of HFS standard.
 */
int hfs_addconverter(int id, u_int32_t encoding, void * get_unicode, void * get_hfsname);
int hfs_getconverter(u_int32_t encoding, void *get_unicode, void *get_hfsname);
int hfs_relconverter(u_int32_t encoding);
int hfs_remconverter(int id, u_int32_t encoding);

/* Function stubs are needed for KPI export */

int hfs_addconverter( __unused int id, 
					  __unused u_int32_t encoding, 
					  __unused void * get_unicode, 
					  __unused void * get_hfsname )
{
	return(0);
}

int hfs_getconverter(__unused u_int32_t encoding, __unused void *get_unicode, __unused void *get_hfsname)
{
	return(EINVAL);
}

int hfs_relconverter(__unused u_int32_t encoding)
{
	return(EINVAL);
}

int hfs_remconverter(__unused int id, __unused u_int32_t encoding)
{
	return(0);
}
#endif


