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

#ifndef _PPC_MISC_PROTOS_H_
#define _PPC_MISC_PROTOS_H_

#include <cpus.h>
#include <debug.h>
#include <mach_kdb.h>
#include <mach_kgdb.h>
#include <mach_kdp.h>
#include <mach_debug.h>

#include <ppc/thread.h>
#include <ppc/boot.h>
#include <kern/thread_act.h>
#include <mach/vm_types.h>
#include <kern/cpu_data.h>
#include <mach/ppc/thread_status.h>
#include <stdarg.h>

extern int strcmp(const char *s1, const char *s2);
extern int strncmp(const char *s1, const char *s2, unsigned long n);
extern char *strcat(char *dest, const char *src);
extern char *strcpy(char *dest, const char *src);

extern void vprintf(const char *fmt, va_list args);
extern void printf(const char *fmt, ...);

extern void bcopy_nc(char *from, char *to, int size); /* uncached-safe */
extern void bcopy_phys(char *from, char *to, int size); /* Physical to physical copy (ints must be disabled) */

extern void ppc_init(boot_args *args);
extern struct ppc_saved_state *enterDebugger(unsigned int trap,
				      struct ppc_saved_state *state,
				      unsigned int dsisr);

extern void ppc_vm_init(unsigned int mem_size, boot_args *args);
extern void regDump(struct ppc_saved_state *state);

extern void autoconf(void);
extern void machine_init(void);
extern void machine_conf(void);
extern void probeio(void);
extern int  cons_find(boolean_t);
extern void machine_startup(boot_args *args);

extern void interrupt_init(void);
extern void interrupt_enable(void);
extern void interrupt_disable(void);
extern void disable_bluebox_internal(thread_act_t act);
#if	MACH_KDB
extern void db_interrupt_enable(void);
extern void db_interrupt_disable(void);
#endif	/* MACH_KDB */
extern void amic_init(void);

extern void phys_zero(vm_offset_t, vm_size_t);
extern void phys_copy(vm_offset_t, vm_offset_t, vm_size_t);

extern void Load_context(thread_t th);

extern struct thread_shuttle *Switch_context(struct thread_shuttle   *old,
				      void                    (*cont)(void),
				      struct thread_shuttle   *new);

extern int nsec_to_processor_clock_ticks(int nsec);

extern void tick_delay(int ticks);

#ifdef	DEBUG
#define DPRINTF(x) { printf("%s : ",__FUNCTION__);printf x; }
#endif	/* DEBUG */

#if MACH_ASSERT
extern void dump_pcb(pcb_t pcb);
extern void dump_thread(thread_t th);
#endif 

#if	NCPUS > 1
extern void mp_probe_cpus(void);
#if	MACH_KDB
extern void remote_kdb(void);
extern void clear_kdb_intr(void);
extern void kdb_console(void);
#endif	/* MACH_KDB */
#endif	/* NCPUS > 1 */

#endif /* _PPC_MISC_PROTOS_H_ */
