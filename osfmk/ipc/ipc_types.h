/*
 * Copyright (c) 2002,2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */
/*
 * Define Basic IPC types available to callers.
 * These are not intended to be used directly, but
 * are used to define other types available through
 * port.h and mach_types.h for in-kernel entities.
 */
#ifndef	_IPC_TYPES_H_
#define	_IPC_TYPES_H_

#include <mach/port.h>
#include <mach/message.h>
#include <mach/mach_types.h>

#if !defined(MACH_KERNEL_PRIVATE)

/*
 * For kernel code that resides outside of mach
 * we define empty structs so that everything will
 * remain strongly typed, without giving out
 * implementation details.
 */
struct ipc_object ;

#endif /* !MACH_KERNEL_PRIVATE */

typedef struct ipc_object	*ipc_object_t;

#define IPC_OBJECT_NULL		((ipc_object_t) 0)
#define IPC_OBJECT_DEAD		((ipc_object_t)~0)
#define IPC_OBJECT_VALID(io)	(((io) != IPC_OBJECT_NULL) && \
				 ((io) != IPC_OBJECT_DEAD))

typedef	void (*mach_msg_continue_t)(mach_msg_return_t);	/* after wakeup */

#endif	/* _IPC_TYPES_H_ */
