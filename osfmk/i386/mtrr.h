/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
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

#ifndef _I386_MTRR_H_
#define _I386_MTRR_H_

/*
 * Memory type range register (MTRR) support.
 */

#include <mach/std_types.h>
#include <sys/appleapiopts.h>
#include <sys/cdefs.h>

#ifdef __APPLE_API_PRIVATE

enum {
	MTRR_TYPE_UNCACHEABLE  = 0,
	MTRR_TYPE_WRITECOMBINE = 1,
	MTRR_TYPE_WRITETHROUGH = 4,
	MTRR_TYPE_WRITEPROTECT = 5,
	MTRR_TYPE_WRITEBACK    = 6
};

__BEGIN_DECLS

extern void          mtrr_init(void);
extern kern_return_t mtrr_update_cpu(void);
extern kern_return_t mtrr_update_all_cpus(void);

extern kern_return_t mtrr_range_add(	addr64_t phys_addr,
					uint64_t length,
					uint32_t mem_type);

extern kern_return_t mtrr_range_remove(	addr64_t phys_addr,
					uint64_t length,
					uint32_t mem_type);

extern void          pat_init(void);

__END_DECLS

#endif /* __APPLE_API_PRIVATE */

#endif /* !_I386_MTRR_H_ */
