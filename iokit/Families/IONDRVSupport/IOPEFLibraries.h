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
 * Copyright (c) 1997 Apple Computer, Inc.
 *
 *
 * HISTORY
 *
 * Simon Douglas  22 Oct 97
 * - first checked in.
 */


#include <IOKit/ndrvsupport/IOMacOSTypes.h>

#ifdef __cplusplus
extern "C" {
#endif


struct FunctionEntry
{
    char        *   name;
    LogicalAddress  address;
    LogicalAddress  toc;
};
typedef struct FunctionEntry FunctionEntry;

struct LibraryEntry
{
    char        *   name;
    ItemCount       numSyms;
    FunctionEntry * functions;
};
typedef struct LibraryEntry LibraryEntry;

extern LibraryEntry IONDRVLibraries[];
extern const ItemCount  IONumNDRVLibraries;

#ifdef __cplusplus
}
#endif

