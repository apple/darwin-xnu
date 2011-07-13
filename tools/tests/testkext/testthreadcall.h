/*
 *  testthreadcall.h
 *  testkext
 *
 */

#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>

class testthreadcall : public IOService {
    OSDeclareDefaultStructors(testthreadcall);
    
    virtual bool start( IOService * provider );
    
public:
	thread_call_t tcall;
	IOSimpleLock *tlock;
};