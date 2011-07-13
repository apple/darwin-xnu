/*
 * Copyright (c) 2010 Apple Inc. All rights reserved.
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

#include <mach/mach.h>
#include <mach/mach_init.h>

extern void (*_libc_set_errno)(int);

static mach_port_t (*_libc_get_reply_port)(void);
static void (*_libc_set_reply_port)(mach_port_t);

/* 
 * Called at Libsystem initialise time, sets up callbacks we
 * need to get at thread variables inside of Libc
 */
void
_mig_reply_port_callbacks(mach_port_t (*get)(void), void (*set)(mach_port_t))
{
	_libc_get_reply_port = get;
	_libc_set_reply_port = set;
}

mach_port_t _mig_get_reply_port(void) __attribute__((visibility("hidden")));
mach_port_t
_mig_get_reply_port()
{
	return _libc_get_reply_port();
}

void _mig_set_reply_port(mach_port_t port) __attribute__((visibility("hidden")));
void
_mig_set_reply_port(mach_port_t port)
{
	_libc_set_reply_port(port);
}

void cthread_set_errno_self(int errno) __attribute__((visibility("hidden")));
void
cthread_set_errno_self(int errno)
{
	_libc_set_errno(errno);
}


void _pthread_set_self(void* ptr) __attribute__((visibility("hidden")));
void
_pthread_set_self(void* ptr) {}
