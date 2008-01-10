/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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

#ifndef	_PPC_MACHINE_ROUTINES_H_
#define	_PPC_MACHINE_ROUTINES_H_

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <kern/kern_types.h>
#include <pexpert/pexpert.h>

/* Get Interrupts Enabled */
extern boolean_t	ml_get_interrupts_enabled(
						void);

/* Set Interrupts Enabled */
extern boolean_t	ml_set_interrupts_enabled(
						boolean_t				enable);

/* Check if running at interrupt context */
extern boolean_t	ml_at_interrupt_context(
						void);

#ifdef KERNEL_PRIVATE

/* Generate a fake interrupt */
extern void			ml_cause_interrupt(
						void);

/* Type for the IPI Hander */
typedef void (*ipi_handler_t)(void);

/* Type for the Time Base Enable function */
typedef void (*time_base_enable_t)(cpu_id_t cpu_id, boolean_t enable);

/* enables (or disables) the processor nap mode the function returns the previous value*/
extern boolean_t	ml_enable_nap(
						int						target_cpu,
						boolean_t				nap_enabled);

/* Put the processor to sleep */
extern void			ml_ppc_sleep(
						void);

extern void			ml_get_timebase(
						unsigned long long		*timstamp);

extern int			ml_enable_cache_level(
						int						cache_level,
						int						enable);

extern void			ml_static_mfree(
						vm_offset_t				vaddr,
						vm_size_t				size);
        
/* Init Interrupts */
extern void			ml_install_interrupt_handler(
						void					*nub,
						int						source,
						void					*target,
						IOInterruptHandler		handler,
						void					*refCon);
               
extern vm_offset_t		ml_static_ptovirt(
							vm_offset_t			paddr);

/* virtual to physical on wired pages */
extern vm_offset_t		ml_vtophys(
							vm_offset_t			vaddr);

/* PCI config cycle probing */
extern boolean_t		ml_probe_read(
							vm_offset_t			paddr,
							unsigned int		*val);

extern boolean_t		ml_probe_read_64(
							addr64_t			paddr,
							unsigned int		*val);

/* Read physical address byte */
extern unsigned int		ml_phys_read_byte(
							vm_offset_t			paddr);

extern unsigned int		ml_phys_read_byte_64(
							addr64_t			paddr);

/* Read physical address half word */
extern unsigned int		ml_phys_read_half(
							vm_offset_t			paddr);

extern unsigned int		ml_phys_read_half_64(
							addr64_t			paddr);

/* Read physical address word*/
extern unsigned int		ml_phys_read(
							vm_offset_t			paddr);

extern unsigned int		ml_phys_read_64(
							addr64_t			paddr);

extern unsigned int		ml_phys_read_word(
							vm_offset_t			paddr);

extern unsigned int		ml_phys_read_word_64(
							addr64_t			paddr);

/* Read physical address double word */
extern unsigned long long ml_phys_read_double(
							vm_offset_t			paddr);

extern unsigned long long ml_phys_read_double_64(
							addr64_t			paddr);

/* Write physical address byte */
extern void				ml_phys_write_byte(
							vm_offset_t			paddr,
							unsigned	int		data);

extern void				ml_phys_write_byte_64(
								addr64_t		paddr,
								unsigned int	data);

/* Write physical address half word */
extern void				ml_phys_write_half(
							vm_offset_t			paddr,
							unsigned int		data);

extern void				ml_phys_write_half_64(
							addr64_t			paddr,
							unsigned int		data);

/* Write physical address word */
extern void				ml_phys_write(
							vm_offset_t			paddr,
							unsigned int		data);

extern void				ml_phys_write_64(
							addr64_t			paddr,
							unsigned int		data);

extern void				ml_phys_write_word(
							vm_offset_t			paddr,
							unsigned int		data);

extern void				ml_phys_write_word_64(
							addr64_t			paddr,
							unsigned int		data);

/* Write physical address double word */
extern void				 ml_phys_write_double(
							vm_offset_t			paddr,
							unsigned long long	data);

extern void				ml_phys_write_double_64(
							addr64_t paddr,
							unsigned long long	 data);

/* Struct for ml_processor_register */
struct ml_processor_info {
	cpu_id_t			cpu_id;
	boolean_t			boot_cpu;
	vm_offset_t			start_paddr;
	boolean_t			supports_nap;
	unsigned long			l2cr_value;
	time_base_enable_t		time_base_enable;
	uint32_t			power_mode_0;
	uint32_t			power_mode_1;
};

typedef struct ml_processor_info ml_processor_info_t;

/* Register a processor */
extern kern_return_t	ml_processor_register(
							ml_processor_info_t *ml_processor_info,
							processor_t			*processor,
							ipi_handler_t		*ipi_handler);

/* Zero bytes starting at a physical address */
extern void				bzero_phys(
							addr64_t			phys_address,
							uint32_t			length);

#endif /* KERNEL_PRIVATE */

#ifdef	XNU_KERNEL_PRIVATE
#if	defined(PEXPERT_KERNEL_PRIVATE) || defined(MACH_KERNEL_PRIVATE)

/* Map memory map IO space */
extern vm_offset_t		ml_io_map(
							vm_offset_t			phys_addr, 
							vm_size_t			size);

void	ml_get_bouncepool_info(
        vm_offset_t *phys_addr,
	vm_size_t   *size);


/* boot memory allocation */
extern vm_offset_t		ml_static_malloc(
							vm_size_t			size);

#endif /* PEXPERT_KERNEL_PRIVATE || MACH_KERNEL_PRIVATE */

#if	defined(BSD_KERNEL_PRIVATE) || defined(MACH_KERNEL_PRIVATE)

extern int				set_be_bit(
							void);

extern int				clr_be_bit(
							void);

extern int				be_tracing(
							void);

#endif /* BSD_KERNEL_PRIVATE || MACH_KERNEL_PRIVATE */

#ifdef	MACH_KERNEL_PRIVATE
extern void				ml_init_interrupt(
							void);

extern void				cacheInit(
							void);

extern void				cacheDisable(
							void);

extern void				ml_init_lock_timeout(
							void);

void ml_ppc_do_sleep(void);

#endif /* MACH_KERNEL_PRIVATE */
#endif /* XNU_KERNEL_PRIVATE */

#ifdef  KERNEL_PRIVATE
extern void		ml_thread_policy(
				thread_t	thread,
				unsigned	policy_id,
				unsigned	policy_info);

#define MACHINE_GROUP				0x00000001
#define MACHINE_NETWORK_GROUP		0x10000000 
#define MACHINE_NETWORK_WORKLOOP	0x00000001
#define MACHINE_NETWORK_NETISR		0x00000002

/* Initialize the maximum number of CPUs */
extern void				ml_init_max_cpus(
							unsigned int		max_cpus);

/* Return the maximum number of CPUs set by ml_init_max_cpus() */
extern unsigned int		ml_get_max_cpus(
							void);

extern void			ml_cpu_up(void);
extern void			ml_cpu_down(void);

/* Struct for ml_cpu_get_info */
struct ml_cpu_info {
	unsigned long		vector_unit;
	unsigned long		cache_line_size;
	unsigned long		l1_icache_size;
	unsigned long		l1_dcache_size;
	unsigned long		l2_settings;
	unsigned long		l2_cache_size;
	unsigned long		l3_settings;
	unsigned long		l3_cache_size;
};

typedef struct ml_cpu_info ml_cpu_info_t;

/* Get processor info */
extern void				ml_cpu_get_info(
							ml_cpu_info_t		*ml_cpu_info);

extern void				ml_set_processor_speed(
							unsigned long		speed);
extern void				ml_set_processor_speed_slave(
							unsigned long		speed);
extern void				ml_set_processor_speed_dpll(
							unsigned long		speed);
extern void				ml_set_processor_speed_dfs(
							unsigned long		speed);
extern void				ml_set_processor_speed_powertune(
							unsigned long		speed);

extern void				ml_set_processor_voltage(
							unsigned long		voltage);

extern unsigned int		ml_scom_write(
							uint32_t			reg,
							uint64_t			data);

extern unsigned int		ml_scom_read(
							uint32_t			reg,
							uint64_t			*data);

extern uint32_t 		ml_hdec_ratio(void);

#endif /* KERNEL_PRIVATE */

#endif /* _PPC_MACHINE_ROUTINES_H_ */
