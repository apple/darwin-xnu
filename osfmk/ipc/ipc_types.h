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
 */
/*
 * Define Basic IPC types available to callers.
 * These are not intended to be used directly, but
 * are used to define other types available through
 * port.h and mach_types.h for in-kernel entities.
 */
#ifndef	_IPC_TYPES_H_
#define	_IPC_TYPES_H_

#ifdef KERNEL_PRIVATE

#if !defined(MACH_KERNEL_PRIVATE)

/*
 * For kernel code that resides outside of mach
 * we define empty structs so that everything will
 * remain strongly typed, without giving out
 * implementation details.
 */
struct ipc_object ;
struct ipc_space ;
struct ipc_port ;

#endif /* !MACH_KERNEL_PRIVATE */

typedef struct ipc_object	*ipc_object_t;
typedef struct ipc_space	*ipc_space_t;
typedef struct ipc_port	        *ipc_port_t;

#define IPC_OBJECT_NULL		((ipc_object_t) 0)
#define IPC_OBJECT_DEAD		((ipc_object_t)~0)
#define IPC_OBJECT_VALID(io)	(((io) != IPC_OBJECT_NULL) && \
				 ((io) != IPC_OBJECT_DEAD))

#define	IPC_PORT_NULL		((ipc_port_t) 0)
#define	IPC_PORT_DEAD		((ipc_port_t)~0)
#define IPC_PORT_VALID(port)	(((port) != IPC_PORT_NULL) && \
				 ((port) != IPC_PORT_DEAD))

#define IPC_SPACE_NULL		((ipc_space_t) 0)

#endif /* KERNEL_PRIVATE */

#endif	/* _IPC_TYPES_H_ */
