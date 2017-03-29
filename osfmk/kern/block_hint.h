/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
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

#ifndef	_KERN_BLOCK_HINT_H_
#define _KERN_BLOCK_HINT_H_

/* This must fit inside a short  */
typedef enum thread_snapshot_wait_flags {
	kThreadWaitNone			= 0x00,
	kThreadWaitKernelMutex          = 0x01,
	kThreadWaitPortReceive          = 0x02,
	kThreadWaitPortSetReceive       = 0x03,
	kThreadWaitPortSend             = 0x04,
	kThreadWaitPortSendInTransit    = 0x05,
	kThreadWaitSemaphore            = 0x06,
	kThreadWaitKernelRWLockRead     = 0x07,
	kThreadWaitKernelRWLockWrite    = 0x08,
	kThreadWaitKernelRWLockUpgrade  = 0x09,
	kThreadWaitUserLock             = 0x0a,
	kThreadWaitPThreadMutex         = 0x0b,
	kThreadWaitPThreadRWLockRead    = 0x0c,
	kThreadWaitPThreadRWLockWrite   = 0x0d,
	kThreadWaitPThreadCondVar       = 0x0e,
	kThreadWaitParkedWorkQueue      = 0x0f,
} __attribute__((packed)) block_hint_t;

#endif /* !_KERN_BLOCK_HINT_H_ */
