/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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

extern void	bzero_nc(char* buf, int size); /* uncached-safe */
extern void bcopy_nc(char *from, char *to, int size); /* uncached-safe */
extern void bcopy_phys(addr64_t from, addr64_t to, int size); /* Physical to physical copy (ints must be disabled) */
extern void bcopy_physvir(addr64_t from, addr64_t to, int size); /* Physical to physical copy virtually (ints must be disabled) */

extern void ppc_init(boot_args *args);
extern struct savearea *enterDebugger(unsigned int trap,
				      struct savearea *state,
				      unsigned int dsisr);

extern void draw_panic_dialog(void);
extern void ppc_vm_init(uint64_t mem_size, boot_args *args);

extern int ppcNull(struct savearea *);
extern int ppcNullinst(struct savearea *);

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
extern uint64_t hid0get64(void);
#if	MACH_KDB
extern void db_interrupt_enable(void);
extern void db_interrupt_disable(void);
#endif	/* MACH_KDB */

extern void phys_zero(vm_offset_t, vm_size_t);
extern void phys_copy(addr64_t, addr64_t, vm_size_t);

extern void Load_context(thread_t th);

extern thread_t Switch_context(
					thread_t	old,
					void		(*cont)(void),
					thread_t	new);

extern void fpu_save(struct facility_context *);
extern void vec_save(struct facility_context *);
extern void toss_live_fpu(struct facility_context *);
extern void toss_live_vec(struct facility_context *);

extern void condStop(unsigned int, unsigned int);

extern int nsec_to_processor_clock_ticks(int nsec);

extern void tick_delay(int ticks);

#ifdef	DEBUG
#define DPRINTF(x) { printf("%s : ",__FUNCTION__);printf x; }
#endif	/* DEBUG */

#if MACH_ASSERT
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
