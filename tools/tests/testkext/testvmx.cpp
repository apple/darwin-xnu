/*
 *  testvmx.cpp
 *  testkext
 *
 */

#include "testvmx.h"

#if !(defined(__i386__) || defined(__x86_64__))
#error VMX only supported on i386/x86_64
#endif

#include <mach/boolean.h>
#include <i386/vmx.h>


#define super IOService
OSDefineMetaClassAndStructors(testvmx, super);

bool
testvmx::start( IOService * provider )
{
    int ret;
    
    IOLog("%s\n", __PRETTY_FUNCTION__);
    
    if (!super::start(provider)) {
        return false;
    }
    
    IOLog("Attempting host_vmxon\n");
    ret = host_vmxon(FALSE);
    IOLog("host_vmxon: %d\n", ret);
    
    return true;
}

void
testvmx::stop( IOService * provider )
{
    IOLog("%s\n", __PRETTY_FUNCTION__); 
    
    super::stop(provider);
    
    IOLog("Attempting host_vmxoff\n");
    host_vmxoff();
    IOLog("host_vmxoff called\n");
}
