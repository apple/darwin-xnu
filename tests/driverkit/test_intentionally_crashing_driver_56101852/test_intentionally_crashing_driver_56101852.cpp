//
//  test_intentionally_crashing_driver_56101852.cpp
//  test_intentionally_crashing_driver_56101852
//
//  Copyright © 2019 Apple Inc. All rights reserved.
//

#include <os/log.h>

#include <DriverKit/IOUserServer.h>
#include <DriverKit/IOLib.h>

#include "test_intentionally_crashing_driver_56101852.h"

kern_return_t
IMPL(test_intentionally_crashing_driver_56101852, Start)
{
	kern_return_t ret;
	ret = Start(provider, SUPERDISPATCH);
	os_log(OS_LOG_DEFAULT, "Hello World");
	return ret;
}

/* Intentionally crash */
__attribute__((constructor)) void
crash()
{
	/* cause SIGILL */
	__builtin_trap();
}
