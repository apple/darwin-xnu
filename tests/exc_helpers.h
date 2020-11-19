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

#ifndef EXC_HELPERS_H
#define EXC_HELPERS_H

#include <mach/mach.h>
#include <mach/exception.h>
#include <mach/thread_status.h>

/**
 * Callback invoked by run_exception_handler() when a Mach exception is
 * received.
 *
 * @param type  exception type received from the kernel
 * @param codes exception codes received from the kernel
 *
 * @return      how much the exception handler should advance the program
 *              counter, in bytes (in order to move past the code causing the
 *              exception)
 */
typedef size_t (*exc_handler_callback_t)(exception_type_t type, mach_exception_data_t codes);

mach_port_t
create_exception_port(exception_mask_t exception_mask);

void
run_exception_handler(mach_port_t exc_port, exc_handler_callback_t callback);

#endif /* EXC_HELPERS_H */
