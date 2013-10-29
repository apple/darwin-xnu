/*
 *  testthreadcall.cpp
 *  testkext
 *
 */

#include "testthreadcall.h"

#include <kern/thread_call.h>

#define super IOService
OSDefineMetaClassAndStructors(testthreadcall, super);

extern "C" {

static void thread_call_test_func(thread_call_param_t param0,
								  thread_call_param_t param1);

}

bool
testthreadcall::start( IOService * provider )
{
	boolean_t ret;
	uint64_t deadline;
    
    IOLog("%s\n", __PRETTY_FUNCTION__);
    
    if (!super::start(provider)) {
        return false;
    }
    
    IOLog("Attempting thread_call_allocate\n");
	tcall = thread_call_allocate(thread_call_test_func, this);
    IOLog("thread_call_t %p\n", tcall);
    
	tlock = IOSimpleLockAlloc();
	IOLog("tlock %p\n", tlock);
	
	clock_interval_to_deadline(5, NSEC_PER_SEC, &deadline);
	IOLog("%d sec deadline is %llu\n", 5, deadline);
	
	ret = thread_call_enter_delayed(tcall, deadline);
	
    return true;
}

static void thread_call_test_func(thread_call_param_t param0,
								  thread_call_param_t param1)
{
	testthreadcall *self = (testthreadcall *)param0;
	
	IOLog("thread_call_test_func %p %p\n", param0, param1);
	
	IOSimpleLockLock(self->tlock);
	IOSimpleLockUnlock(self->tlock);

#if 1
	IOSimpleLockLock(self->tlock);
#else
	IOSimpleLockUnlock(self->tlock);	
#endif
}
