/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 2003 Apple Computer, Inc.  All rights reserved.
 *
 * HISTORY
 *
 * 14 January 2003 (debo)
 *  Created.
 */

#ifndef	_KERN_HOST_NOTIFY_H_
#define	_KERN_HOST_NOTIFY_H_

#ifdef MACH_KERNEL_PRIVATE
#include <mach/mach_types.h>

void	host_notify_port_destroy(
			ipc_port_t			port);

void	host_notify_calendar_change(void);

void	host_notify_init(void);

#endif /* MACH_KERNEL_PRIVATE */

#endif /* _KERN_HOST_NOTIFY_H_ */
