/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */

#ifndef	_I386_MISC_PROTOS_H_
#define	_I386_MISC_PROTOS_H_

#include <i386/thread.h>

struct boot_args;
struct cpu_data;

extern void		i386_init(vm_offset_t);
extern void		i386_macho_zerofill(void);
extern void		i386_vm_init(
				uint64_t		maxmem,
				boolean_t 		IA32e,
				struct boot_args	*args);
extern void		cpu_IA32e_enable(struct cpu_data *);
extern void		cpu_IA32e_disable(struct cpu_data *);
extern void		ml_load_desc64(void);
extern void		ml_64bit_wrmsr64(uint32_t msr, uint64_t value);
extern void             cpu_window_init(int);
extern void		ml_64bit_lldt(int);

extern void		machine_startup(void);

extern void		get_root_device(void);
extern void		picinit(void);
extern void		interrupt_processor(
				int		cpu);
extern void		mp_probe_cpus(void);
extern void		panic_io_port_read(void);
extern void		remote_kdb(void);
extern void		clear_kdb_intr(void);
extern void             draw_panic_dialog(void);
extern void		cpu_init(void);
extern void		cpu_shutdown(void);
extern void		fix_desc(
				void		* desc,
				int		num_desc);
extern void		fix_desc64(
				void		* desc,
				int		num_desc);
extern void		cnpollc(
				boolean_t	on);
extern void		form_pic_mask(void);
extern void		intnull(
				int		unit);
extern char *		i386_boot_info(
				char		*buf,
				vm_size_t	buf_len);

extern void		blkclr(
			       const char	*from,
			       int		nbytes);

extern unsigned int	div_scale(
				unsigned int	dividend,
				unsigned int	divisor,
				unsigned int	*scale);

extern unsigned int	mul_scale(
				unsigned int	multiplicand,
				unsigned int	multiplier,
				unsigned int	*scale);

/* Move arbitrarily-aligned data from one physical address to another */
extern void bcopy_phys(addr64_t from, addr64_t to, vm_size_t nbytes);

/* Flush all cachelines for a page. */
extern void cache_flush_page_phys(ppnum_t pa);

/* Flushing for incoherent I/O */
extern void dcache_incoherent_io_flush64(addr64_t pa, unsigned int count);
extern void dcache_incoherent_io_store64(addr64_t pa, unsigned int count);


extern processor_t	cpu_processor_alloc(boolean_t is_boot_cpu);
extern void		cpu_processor_free(processor_t proc);

extern void		*chudxnu_cpu_alloc(boolean_t is_boot_cpu);
extern void		chudxnu_cpu_free(void *);

extern void		sysclk_gettime_interrupts_disabled(
				mach_timespec_t *cur_time);

extern void rtc_nanotime_init_commpage(void);

extern void	rtc_sleep_wakeup(void);

extern void	rtc_clock_stepping(
			uint32_t new_frequency,
			uint32_t old_frequency);
extern void	rtc_clock_stepped(
			uint32_t new_frequency,
			uint32_t old_frequency);
extern void	rtc_clock_napped(
			uint64_t);

extern void     x86_lowmem_free(void);


#endif	/* _I386_MISC_PROTOS_H_ */
