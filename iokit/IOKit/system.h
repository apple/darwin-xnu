/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
#ifndef __IOKIT_SYSTEM_H
#define __IOKIT_SYSTEM_H

#include <sys/cdefs.h>

__BEGIN_DECLS

#include <mach/mach_types.h>
#include <mach/mach_interface.h>
#include <mach/etap.h>
#include <mach/etap_events.h>

#include <stdarg.h>

#if KERNEL_PRIVATE
#include <IOKit/assert.h>  /* Must be before other includes of kern/assert.h */
#include <kern/cpu_data.h>
#include <kern/thread.h>
#include <kern/thread_act.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <kern/kalloc.h>
#include <kern/task.h>
#include <kern/time_out.h>
#include <kern/sched_prim.h>
#include <machine/spl.h>
#include <kern/lock.h>
#include <kern/queue.h>
#include <kern/ipc_mig.h>
#endif /* KERNEL_PRIVATE */

extern int	bcmp(const void *, const void *, size_t);
extern void	bcopy(const void *, void *, size_t);
extern void	bzero(void *, size_t);

extern int	memcmp(const void *, const void *, size_t);

extern void	_doprnt( const char *format, va_list *arg,
			void (*putc)(char), int radix );

extern int 	sscanf(const char *input, const char *fmt, ...);
extern int 	sprintf(char *s, const char *format, ...);
extern long 	strtol(const char *, char **, int);
extern unsigned long strtoul(const char *, char **, int);
extern long long strtoq(const char *, char **, int);
extern unsigned long long strtouq(const char *, char **, int);

extern
#ifdef __GNUC__
volatile
#endif
void panic(const char * msg, ...);

/*
 */

/*
 * Really need a set of interfaces from osfmk/pexpert components to do
 * all that is required to prepare an I/O from a cache management point
 * of view.
 * osfmk/ppc/cache.s
 */
extern void invalidate_icache(vm_offset_t addr, unsigned cnt, int phys);
extern void flush_dcache(vm_offset_t addr, unsigned count, int phys);
extern void invalidate_icache64(addr64_t addr, unsigned cnt, int phys);
extern void flush_dcache64(addr64_t addr, unsigned count, int phys);

__END_DECLS

#endif /* !__IOKIT_SYSTEM_H */
