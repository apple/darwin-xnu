/*
 * Copyright (c) 1993-1995, 1999-2000 Apple Computer, Inc.
 * All rights reserved.
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
 * Private declarations for thread-based callouts.
 *
 * HISTORY
 *
 * 10 July 1999 (debo)
 *  Pulled into Mac OS X (microkernel).
 *
 * 3 July 1993 (debo)
 *	Created.
 */

#ifndef _KERN_CALL_ENTRY_H_
#define _KERN_CALL_ENTRY_H_

#ifdef MACH_KERNEL_PRIVATE
#include <kern/queue.h>

typedef void			*call_entry_param_t;
typedef void			(*call_entry_func_t)(
								call_entry_param_t		param0,
								call_entry_param_t		param1);

typedef struct call_entry {
    queue_chain_t		q_link;
    call_entry_func_t	func;
    call_entry_param_t	param0;
    call_entry_param_t	param1;
    uint64_t			deadline;
    enum {
	  IDLE,
	  PENDING,
	  DELAYED }			state;
} call_entry_data_t;

#define	call_entry_setup(entry, pfun, p0)				\
MACRO_BEGIN												\
	(entry)->func		= (call_entry_func_t)(pfun);	\
	(entry)->param0		= (call_entry_param_t)(p0);		\
	(entry)->state		= IDLE;							\
MACRO_END

#endif /* MACH_KERNEL_PRIVATE */

#endif /* _KERN_CALL_ENTRY_H_ */
