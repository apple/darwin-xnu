/*
 * Copyright (c) 2001-2002 Apple Computer, Inc. All rights reserved.
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
 
 #ifndef _IOPMEVENTSOURCE_H_
 #define _IOPMEVENTSOURCE_H_
 
 #include <IOKit/IOWorkLoop.h>
 #include <IOKit/IOEventSource.h>
    
    // Queue of requested states
     typedef struct {
        unsigned long           state;
        void                    *next;
    } ActivityTickleStateList;

 class IOPMEventSource : public IOEventSource
 {
    OSDeclareDefaultStructors(IOPMEventSource);

protected:
    virtual bool checkForWork(void);

    ActivityTickleStateList             *states;

public:
    typedef void (*Action)(OSObject *owner, unsigned long state);

    // static initialiser
    static IOPMEventSource *PMEventSource(OSObject *owner, Action action);
    
    virtual bool init(OSObject *owner, Action action);
     
    // Enqueues an activityTickle request to be executed on the workloop
    virtual IOReturn activityTickleOccurred(unsigned long);
 };
 
 #endif /* _IOPMEVENTSOURCE_H_ */
 
