/*
 * Copyright (c) 1999, 2000-2001 Apple Computer, Inc. All rights reserved.
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
	File:		WindowsTypesForMac.h

	Contains:	Define common Windows data types in mac terms.

	Written by:	Doug Mitchell

	Copyright: (c) 2000 by Apple Computer, Inc., all rights reserved.

	Change History (most recent first):

		02/10/99	dpm		Created.
 
*/

#ifndef	_WINDOWS_TYPES_FOR_MAC_H_
#define _WINDOWS_TYPES_FOR_MAC_H_

#include <dev/random/YarrowCoreLib/include/macos_defs.h>

typedef UInt8 	UCHAR;
typedef SInt8 	CHAR;
typedef UInt8 	BYTE;
typedef char	TCHAR;
typedef SInt16	WORD;
typedef SInt32	DWORD;
typedef UInt16	USHORT;
typedef UInt32	ULONG;
typedef SInt32	LONG;
typedef UInt32	UINT;
typedef SInt64	LONGLONG;
typedef UInt8	*LPBYTE;
typedef SInt8 	*LPSTR;
typedef SInt16	*LPWORD;
typedef	SInt8	*LPCTSTR;		/* ??? */
typedef	SInt8	*LPCSTR;		/* ??? */
typedef void	*LPVOID;
typedef void	*HINSTANCE;
typedef	void	*HANDLE;

#define WINAPI

#endif	/* _WINDOWS_TYPES_FOR_MAC_H_*/

