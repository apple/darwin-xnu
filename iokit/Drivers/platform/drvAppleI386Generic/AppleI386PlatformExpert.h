/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
/*
 * Copyright (c) 1998 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 *
 */

#ifndef _IOKIT_APPLEI386PLATFORM_H
#define _IOKIT_APPLEI386PLATFORM_H

#include <IOKit/IOPlatformExpert.h>

class AppleI386PlatformExpert : public IOPlatformExpert
{
    OSDeclareDefaultStructors(AppleI386PlatformExpert)

private:
    void    setupPIC(IOService * nub);

    static  int handlePEHaltRestart(unsigned int type);

public:
    virtual IOService * probe(IOService * provider,
                              SInt32 *    score);

    virtual bool start(IOService * provider);

    virtual bool matchNubWithPropertyTable(IOService *    nub,
                                           OSDictionary * table);

    virtual IOService * createNub(OSDictionary * from);

    virtual bool getModelName(char * name, int maxLength);
    virtual bool getMachineName(char * name, int maxLength);
};

#endif /* ! _IOKIT_APPLEI386PLATFORM_H */

