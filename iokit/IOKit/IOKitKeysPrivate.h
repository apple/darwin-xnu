/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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

#ifndef _IOKIT_IOKITKEYSPRIVATE_H
#define _IOKIT_IOKITKEYSPRIVATE_H

#include <IOKit/IOKitKeys.h>

// properties found in the registry root
#define kIOConsoleUsersKey		"IOConsoleUsers"		/* value is OSArray */
#define kIOMaximumMappedIOByteCountKey  "IOMaximumMappedIOByteCount"    /* value is OSNumber */

// properties found in the console user dict

#define kIOConsoleSessionIDKey		"kCGSSessionIDKey"		/* value is OSNumber */

#define kIOConsoleSessionUserNameKey	"kCGSSessionUserNameKey"	/* value is OSString */
#define kIOConsoleSessionUIDKey		"kCGSSessionUserIDKey"		/* value is OSNumber */
#define kIOConsoleSessionConsoleSetKey	"kCGSSessionConsoleSetKey"	/* value is OSNumber */
#define kIOConsoleSessionOnConsoleKey	"kCGSSessionOnConsoleKey"	/* value is OSBoolean */
#define kIOConsoleSessionSecureInputPIDKey	"kCGSSessionSecureInputPID"	/* value is OSNumber */

// IOResources property
#define kIOConsoleUsersSeedKey		"IOConsoleUsersSeed"		/* value is OSNumber */

// private keys for clientHasPrivilege
#define kIOClientPrivilegeConsoleUser "console"
#define kIOClientPrivilegeSecureConsoleProcess "secureprocess"

// clientHasPrivilege security token for kIOClientPrivilegeSecureConsoleProcess
typedef struct _IOUCProcessToken {
    void *  token;
    UInt32  pid;
} IOUCProcessToken;

#define kIOKernelHasSafeSleep		1

#endif /* ! _IOKIT_IOKITKEYSPRIVATE_H */
