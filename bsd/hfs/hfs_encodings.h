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
 * Copyright (c) 1997-2000 Apple Computer, Inc. All Rights Reserved
 */

#ifndef _HFS_ENCODINGS_H_
#define _HFS_ENCODINGS_H_

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_UNSTABLE

#define CTL_HFS_NAMES { \
	{ 0, 0 }, \
	{ "encodingbias", CTLTYPE_INT }, \
}

/*
 * HFS Filename Encoding Converters Interface
 *
 * Private Interface for adding hfs filename
 * encoding converters. These are not needed
 * for HFS Plus volumes (since they already
 * have Unicode filenames).
 *
 * Used by HFS Encoding Converter Kernel Modules
 * (like HFS_Japanese.kmod) to register their
 * encoding conversion routines.
 */

typedef int (* hfs_to_unicode_func_t)(const Str31 hfs_str, UniChar *uni_str,
		UInt32 maxCharLen, UInt32 *usedCharLen);

typedef int (* unicode_to_hfs_func_t)(UniChar *uni_str, UInt32 unicodeChars,
		Str31 hfs_str);


int hfs_addconverter(int kmod_id, UInt32 encoding,
		hfs_to_unicode_func_t get_unicode,
		unicode_to_hfs_func_t get_hfsname);

int hfs_remconverter(int kmod_id, UInt32 encoding);

#endif /* __APPLE_API_UNSTABLE */

#endif /* ! _HFS_ENCODINGS_H_ */
