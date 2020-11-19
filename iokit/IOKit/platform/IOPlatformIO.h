/*
 * Copyright (c) 2019 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#ifndef _IOKIT_PLATFORM_IOPLATFORMIO_H
#define _IOKIT_PLATFORM_IOPLATFORMIO_H

extern "C" {
#include <kern/kern_types.h>
}

#include <IOKit/IOService.h>

/*!
 * @class      IOPlatformIO
 * @abstract   The base class for platform I/O drivers, such as AppleARMIO.
 */
class IOPlatformIO : public IOService
{
	OSDeclareAbstractStructors(IOPlatformIO);

public:
	virtual bool start(IOService * provider) APPLE_KEXT_OVERRIDE;

	/*!
	 * @function   handlePlatformError
	 * @abstract   Handler for platform-defined errors.
	 * @discussion If the CPU reports an error that XNU does not know how
	 *             to handle, such as a parity error or SError, XNU will
	 *             invoke this method if there is an IOPlatformIO
	 *             driver loaded.
	 * @param far  Fault address provided by the CPU, if any.
	 * @result     true if the exception was handled, false if not.
	 */
	virtual bool handlePlatformError(vm_offset_t far) = 0;
};

#endif /* ! _IOKIT_PLATFORM_IOPLATFORMIO_H */
