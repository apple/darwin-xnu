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
 * Copyright (C) Apple Computer 1998
 * ALL Rights Reserved
 */
/*
 * This file represents the interfaces that used to come
 * from creating the user headers from the mach.defs file.
 * Because mach.defs was decomposed, this file now just
 * wraps up all the new interface headers generated from
 * each of the new .defs resulting from that decomposition.
 */
#ifndef	_MACH_INTERFACE_H_
#define _MACH_INTERFACE_H_

#include <mach/clock.h>
#include <mach/clock_priv.h>
#include <mach/clock_reply_server.h>
#include <mach/exc_server.h>
#include <mach/host_priv.h>
#include <mach/host_security.h>
#include <mach/ledger.h>
#include <mach/lock_set.h>
#include <mach/mach_host.h>
#include <mach/mach_port.h>
#include <mach/memory_object_server.h>
#include <mach/memory_object_default_server.h>
#include <mach/memory_object_control.h>
#include <mach/memory_object_name.h>
#include <mach/notify_server.h>
#include <mach/processor.h>
#include <mach/processor_set.h>
#include <mach/semaphore.h>
#include <mach/task.h>
#include <mach/thread_act.h>
#include <mach/vm_map.h>

#endif /* _MACH_INTERFACE_H_ */


