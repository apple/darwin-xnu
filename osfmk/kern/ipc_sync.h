/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 * 
 */
#ifndef _KERN_IPC_SYNC_H_
#define _KERN_IPC_SYNC_H_

#include <mach/mach_types.h>
#include <ipc/ipc_types.h>
#include <kern/spl.h>

semaphore_t convert_port_to_semaphore (ipc_port_t port);
ipc_port_t  convert_semaphore_to_port (semaphore_t semaphore);

lock_set_t  convert_port_to_lock_set  (ipc_port_t port);
ipc_port_t  convert_lock_set_to_port  (lock_set_t lock_set);

kern_return_t	port_name_to_semaphore(
				      mach_port_name_t	name,
				      semaphore_t	*semaphore);
#endif /* _KERN_IPC_SYNC_H_ */
