/*
 * Copyright (c) 1999, 2000-2002 Apple Computer, Inc. All rights reserved.
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

#include <sys/types.h>

typedef u_int8_t 	UCHAR;
typedef int8_t 	CHAR;
typedef u_int8_t 	BYTE;
typedef char	TCHAR;
typedef int16_t	WORD;
typedef int32_t	DWORD;
typedef u_int16_t	USHORT;
typedef u_int32_t	ULONG;
typedef int32_t	LONG;
typedef u_int32_t	UINT;
typedef int64_t	LONGLONG;
typedef u_int8_t	*LPBYTE;
typedef int8_t 	*LPSTR;
typedef int16_t	*LPWORD;
typedef	int8_t	*LPCTSTR;		/* ??? */
typedef	int8_t	*LPCSTR;		/* ??? */
typedef void	*LPVOID;
typedef void	*HINSTANCE;
typedef	void	*HANDLE;

#define WINAPI

#endif	/* _WINDOWS_TYPES_FOR_MAC_H_*/

