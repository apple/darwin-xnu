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
#include <IOKit/IOLib.h>

#ifdef __cplusplus

#define logPrintf(x)						\
    do { 							\
        kprintf x;						\
    } while (0)

#define verPrintf(x) logPrintf(x)

// Assumes 'bool res = true' in current scope
#define TEST_ASSERT(t, l, c)						\
    do {								\
        if ( !(c) ) {							\
            verPrintf(("TEST (%c) test %s failed\n", t, l));	\
            res = false;						\
        }								\
    } while(0)

#define logSpace()		do { } while(0)
#define checkPointSpace()	((void *) 0)
#define checkSpace(l, ckp, d)	((int) 1)

// In TestContainers.cc
extern const int numStrCache;
extern const char *strCache[];

extern void testString();
extern void testSymbol();
extern void testData();

// In TestCollections.cc
extern void testArray();
extern void testSet();
extern void testDictionary();
extern void testIterator();

// In TestDevice.cc
extern void testWorkLoop();

#include <libkern/c++/OSObject.h>

class IOWorkLoop;
class IOCommandQueue;
class IOInterruptEventSource;

class TestDevice;
typedef void (*TestDeviceAction)(TestDevice *, int, void *);

class TestDevice : public OSObject
{
    OSDeclareDefaultStructors(TestDevice)

    IOWorkLoop *workLoop;
    int intCount;
    IOCommandQueue *commQ;

public:
    IOInterruptEventSource *intES;

    virtual bool init();
    virtual void free();

    void rawCommandOccurred
            (void *field0, void *field1, void *field2, void *field3);
    kern_return_t enqueueCommand(bool sleep,
                                 TestDeviceAction act, int tag, void *dataP);

    void interruptAction(IOInterruptEventSource *event, int count);

    void producer1Action(int tag);
    void producer2Action(int tag, void *inCount);

    void alarm();
};

#endif /* __cplusplus */
