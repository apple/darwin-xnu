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
/*
 * Copyright (c) 1998 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 *
 */


#ifndef _IOKIT_IOKITDEBUG_H
#define _IOKIT_IOKITDEBUG_H

#include <IOKit/IOTypes.h>


#ifdef __cplusplus

#include <libkern/c++/OSObject.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSSerialize.h>

class IOKitDiagnostics : public OSObject
{
    OSDeclareDefaultStructors(IOKitDiagnostics)

public:
    static OSObject * diagnostics( void );
    virtual bool serialize(OSSerialize *s) const;
private:
    static void updateOffset( OSDictionary * dict,
			UInt32 value, const char * name );
};

#endif

#ifdef __cplusplus
extern "C" {
#endif

enum {
// loggage
    kIOLogAttach	= 0x00000001ULL,
    kIOLogProbe 	= 0x00000002ULL,
    kIOLogStart 	= 0x00000004ULL,
    kIOLogRegister 	= 0x00000008ULL,
    kIOLogMatch 	= 0x00000010ULL,
    kIOLogConfig 	= 0x00000020ULL,
    kIOLogYield 	= 0x00000040ULL,
    kIOLogPower 	= 0x00000080ULL,
    kIOLogMapping 	= 0x00000100ULL,
    kIOLogCatalogue 	= 0x00000200ULL,
    kIOLogTracePower 	= 0x00000400ULL,

    kIOLogServiceTree 	= 0x00001000ULL,
    kIOLogDTree 	= 0x00002000ULL,
    kIOLogMemory 	= 0x00004000ULL,

// debug aids - change behaviour
    kIONoFreeObjects 	= 0x00100000ULL
};

extern SInt64	gIOKitDebug;
extern char 	iokit_version[];

struct IORegistryPlane;
extern void	IOPrintPlane( const struct IORegistryPlane * plane );
extern void	OSPrintMemory( void );
#define IOPrintMemory OSPrintMemory

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* ! _IOKIT_IOKITDEBUG_H */
