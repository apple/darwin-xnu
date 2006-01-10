/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#include <libkern/c++/OSCPPDebug.cpp>

__BEGIN_DECLS

void OSPrintMemory( void )
{

    OSMetaClass::printInstanceCounts();

    IOLog("\n"
            "ivar kalloc()       0x%08x\n"
            "malloc()            0x%08x\n"
            "containers kalloc() 0x%08x\n"
            "IOMalloc()          0x%08x\n"
            "----------------------------------------\n",
            debug_ivars_size,
            debug_malloc_size,
            debug_container_malloc_size,
            debug_iomalloc_size
            );
}

__END_DECLS

