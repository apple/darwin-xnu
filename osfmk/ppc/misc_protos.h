/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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

#include <debug.h>
#include <mach_kdb.h>
#include <mach_kgdb.h>
#include <mach_kdp.h>
#include <mach_debug.h>

#include <ppc/boot.h>
#include <kern/thread.h>
#include <mach/vm_types.h>
#include <kern/cpu_data.h>
#include <ppc/savearea.h>
#include <mach/ppc/thread_status.h>
#include <stdarg.h>
#include <string.h>

/* uncached-safe */
extern void		bzero_nc(
					char				*buf, 
					int					size);

/* uncached-safe */
extern void		bcopy_nc(
					char				*from,
					char				*to,
					int					size);

/* Physical to physical copy (ints must be disabled) */
extern void		bcopy_phys(
					addr64_t			from,
					addr64_t			to,
					int					size);

/* Physical to physical copy virtually (ints must be disabled) */
extern void		bcopy_physvir_32(
					addr64_t			from,
					addr64_t			to,
					int					size);

extern void		phys_copy(
					addr64_t			from,
					addr64_t			to,
					vm_size_t			size); 

extern void		machine_conf(
					void);

extern void		machine_startup(
					boot_args			*args);

extern void		ppc_vm_init(
					uint64_t			ppc_mem_size,
					boot_args			*args);

extern int		ppcNull(
					struct savearea		*asavearea);

extern int		ppcNullinst(
					struct savearea		*asavearea);

extern void		disable_bluebox_internal(
					thread_t		act);

extern uint64_t	hid0get64(
					void);

extern void		hid5set64(
					uint64_t);

extern void		Load_context(
					thread_t			th);

extern thread_t	Switch_context(
					thread_t			old,
					void				(*cont)(void),
					thread_t			new);

extern void		fpu_save(
					struct facility_context *fpu_fc);

extern void		vec_save(
					struct facility_context *vec_fc);

extern void		toss_live_fpu(
					struct facility_context *fpu_fc);

extern void		toss_live_vec(
					struct facility_context *vec_fc);

extern struct	savearea *enterDebugger(
					unsigned int		trap,
					struct savearea		*state,
					unsigned int		dsisr);

extern void		draw_panic_dialog(
					void);

#ifdef	DEBUG
#define DPRINTF(x) { printf("%s : ",__FUNCTION__);printf x; }
#endif	/* DEBUG */

#if MACH_ASSERT
extern void		dump_thread(
					thread_t			th);
#endif 

#endif /* _PPC_MISC_PROTOS_H_ */
