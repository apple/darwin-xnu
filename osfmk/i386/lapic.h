/*
 * Copyright (c) 2008 Apple Inc. All rights reserved.
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
 * 
 */
#ifndef _I386_LAPIC_H_
#define _I386_LAPIC_H_

#define LAPIC_START			0xFEE00000
#define LAPIC_SIZE			0x00000400

#define LAPIC_ID			0x00000020
#define		LAPIC_ID_SHIFT		24
#define		LAPIC_ID_MASK		0xFF
#define LAPIC_VERSION			0x00000030
#define		LAPIC_VERSION_MASK	0xFF
#define LAPIC_TPR			0x00000080
#define		LAPIC_TPR_MASK		0xFF
#define LAPIC_APR			0x00000090
#define		LAPIC_APR_MASK		0xFF
#define LAPIC_PPR			0x000000A0
#define		LAPIC_PPR_MASK		0xFF
#define LAPIC_EOI			0x000000B0
#define LAPIC_REMOTE_READ		0x000000C0
#define LAPIC_LDR			0x000000D0
#define		LAPIC_LDR_SHIFT		24
#define LAPIC_DFR			0x000000E0
#define		LAPIC_DFR_FLAT		0xFFFFFFFF
#define		LAPIC_DFR_CLUSTER	0x0FFFFFFF
#define		LAPIC_DFR_SHIFT         28
#define LAPIC_SVR			0x000000F0
#define		LAPIC_SVR_MASK		0x0FF
#define		LAPIC_SVR_ENABLE	0x100
#define		LAPIC_SVR_FOCUS_OFF	0x200
#define LAPIC_ISR_BASE			0x00000100
#define LAPIC_TMR_BASE			0x00000180
#define LAPIC_IRR_BASE			0x00000200
#define LAPIC_ERROR_STATUS		0x00000280
#define LAPIC_ICR			0x00000300
#define		LAPIC_ICR_VECTOR_MASK	0x000FF
#define		LAPIC_ICR_DM_MASK	0x00700
#define		LAPIC_ICR_DM_FIXED	0x00000
#define		LAPIC_ICR_DM_LOWEST	0x00100
#define		LAPIC_ICR_DM_SMI	0x00200
#define		LAPIC_ICR_DM_REMOTE	0x00300
#define		LAPIC_ICR_DM_NMI	0x00400
#define		LAPIC_ICR_DM_INIT	0x00500
#define		LAPIC_ICR_DM_STARTUP	0x00600
#define		LAPIC_ICR_DM_LOGICAL	0x00800
#define		LAPIC_ICR_DS_PENDING	0x01000
#define		LAPIC_ICR_LEVEL_ASSERT	0x04000
#define		LAPIC_ICR_TRIGGER_LEVEL	0x08000
#define		LAPIC_ICR_RR_MASK	0x30000
#define		LAPIC_ICR_RR_INVALID	0x00000
#define		LAPIC_ICR_RR_INPROGRESS	0x10000
#define		LAPIC_ICR_RR_VALID	0x20000
#define		LAPIC_ICR_DSS_MASK	0xC0000
#define		LAPIC_ICR_DSS_DEST	0x00000
#define		LAPIC_ICR_DSS_SELF	0x40000
#define		LAPIC_ICR_DSS_ALL	0x80000
#define		LAPIC_ICR_DSS_OTHERS	0xC0000
#define LAPIC_ICRD			0x00000310
#define		LAPIC_ICRD_DEST_SHIFT	24
#define LAPIC_LVT_TIMER			0x00000320
#define LAPIC_LVT_THERMAL		0x00000330
#define LAPIC_LVT_PERFCNT		0x00000340
#define LAPIC_LVT_LINT0			0x00000350
#define LAPIC_LVT_LINT1			0x00000360
#define LAPIC_LVT_ERROR			0x00000370
#define		LAPIC_LVT_VECTOR_MASK	0x000FF
#define		LAPIC_LVT_DM_SHIFT	8
#define		LAPIC_LVT_DM_MASK	0x00007
#define		LAPIC_LVT_DM_FIXED	0x00000
#define		LAPIC_LVT_DM_NMI	0x00400
#define		LAPIC_LVT_DM_EXTINT	0x00700
#define		LAPIC_LVT_DS_PENDING	0x01000
#define		LAPIC_LVT_IP_PLRITY_LOW	0x02000
#define		LAPIC_LVT_REMOTE_IRR	0x04000
#define		LAPIC_LVT_TM_LEVEL	0x08000
#define		LAPIC_LVT_MASKED	0x10000
#define		LAPIC_LVT_PERIODIC	0x20000
#define LAPIC_TIMER_INITIAL_COUNT	0x00000380
#define LAPIC_TIMER_CURRENT_COUNT	0x00000390
#define LAPIC_TIMER_DIVIDE_CONFIG	0x000003E0
/* divisor encoded by bits 0,1,3 with bit 2 always 0: */
#define 	LAPIC_TIMER_DIVIDE_MASK	0x0000000F
#define 	LAPIC_TIMER_DIVIDE_2	0x00000000
#define 	LAPIC_TIMER_DIVIDE_4	0x00000001
#define 	LAPIC_TIMER_DIVIDE_8	0x00000002
#define 	LAPIC_TIMER_DIVIDE_16	0x00000003
#define 	LAPIC_TIMER_DIVIDE_32	0x00000008
#define 	LAPIC_TIMER_DIVIDE_64	0x00000009
#define 	LAPIC_TIMER_DIVIDE_128	0x0000000A
#define 	LAPIC_TIMER_DIVIDE_1	0x0000000B

#define LAPIC_ID_MAX			(LAPIC_ID_MASK)

#define CPU_NUMBER(r)				\
	movl	%gs:CPU_NUMBER_GS,r

#define CPU_NUMBER_FROM_LAPIC(r)		\
    	movl	EXT(lapic_id),r;		\
    	movl	0(r),r;				\
    	shrl	$(LAPIC_ID_SHIFT),r;		\
    	andl	$(LAPIC_ID_MASK),r;		\
	movl	EXT(lapic_to_cpu)(,r,4),r

#ifndef	ASSEMBLER
#include <stdint.h>
#include <sys/cdefs.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
typedef enum {
	periodic,
	one_shot
} lapic_timer_mode_t;
typedef enum {	
	divide_by_1   = LAPIC_TIMER_DIVIDE_1,
	divide_by_2   = LAPIC_TIMER_DIVIDE_2,
	divide_by_4   = LAPIC_TIMER_DIVIDE_4,
	divide_by_8   = LAPIC_TIMER_DIVIDE_8,
	divide_by_16  = LAPIC_TIMER_DIVIDE_16,
	divide_by_32  = LAPIC_TIMER_DIVIDE_32,
	divide_by_64  = LAPIC_TIMER_DIVIDE_64,
	divide_by_128 = LAPIC_TIMER_DIVIDE_128
} lapic_timer_divide_t;
typedef uint32_t lapic_timer_count_t;

/*
 * By default, use high vectors to leave vector space for systems
 * with multiple I/O APIC's. However some systems that boot with
 * local APIC disabled will hang in SMM when vectors greater than
 * 0x5F are used. Those systems are not expected to have I/O APIC
 * so 16 (0x50 - 0x40) vectors for legacy PIC support is perfect.
 */
#define LAPIC_DEFAULT_INTERRUPT_BASE	0xD0
#define LAPIC_REDUCED_INTERRUPT_BASE	0x50
/*
 * Specific lapic interrupts are relative to this base
 * in priority order from high to low:
 */

#define LAPIC_PERFCNT_INTERRUPT		0xF
#define LAPIC_TIMER_INTERRUPT		0xE
#define LAPIC_INTERPROCESSOR_INTERRUPT	0xD
#define LAPIC_THERMAL_INTERRUPT		0xC
#define LAPIC_ERROR_INTERRUPT		0xB
#define LAPIC_SPURIOUS_INTERRUPT	0xA
#define LAPIC_CMCI_INTERRUPT		0x9
/* The vector field is ignored for NMI interrupts via the LAPIC
 * or otherwise, so this is not an offset from the interrupt
 * base.
 */
#define LAPIC_NMI_INTERRUPT		0x2
#define LAPIC_FUNC_TABLE_SIZE		LAPIC_PERFCNT_INTERRUPT

#define LAPIC_WRITE(reg,val) \
	*((volatile uint32_t *)(lapic_start + LAPIC_##reg)) = (val)
#define LAPIC_READ(reg) \
	(*((volatile uint32_t *)(lapic_start + LAPIC_##reg)))
#define LAPIC_READ_OFFSET(reg,off) \
	(*((volatile uint32_t *)(lapic_start + LAPIC_##reg + (off))))

#define LAPIC_VECTOR(src) \
	(lapic_interrupt_base + LAPIC_##src##_INTERRUPT)

#define LAPIC_ISR_IS_SET(base,src) \
	(LAPIC_READ_OFFSET(ISR_BASE,((base+LAPIC_##src##_INTERRUPT)/32)*0x10) \
		& (1 <<((base + LAPIC_##src##_INTERRUPT)%32)))

extern vm_offset_t	lapic_start;

extern void		lapic_init(void);
extern void		lapic_configure(void);
extern void		lapic_shutdown(void);
extern void		lapic_smm_restore(void);
extern boolean_t	lapic_probe(void);
extern void		lapic_dump(void);
extern int		lapic_interrupt(
				int interrupt, x86_saved_state_t *state);
extern void		lapic_end_of_interrupt(void);
extern int		lapic_to_cpu[];
extern int		cpu_to_lapic[];
extern int		lapic_interrupt_base;
extern void		lapic_cpu_map(int lapic, int cpu_num);
extern uint32_t		ml_get_apicid(uint32_t cpu);

extern void		lapic_set_timer(
				boolean_t		interrupt,
				lapic_timer_mode_t	mode,
				lapic_timer_divide_t 	divisor,
				lapic_timer_count_t	initial_count);

extern void		lapic_get_timer(
				lapic_timer_mode_t	*mode,
				lapic_timer_divide_t	*divisor,
				lapic_timer_count_t	*initial_count,
				lapic_timer_count_t	*current_count);

typedef	int (*i386_intr_func_t)(x86_saved_state_t *state);
extern void		lapic_set_intr_func(int intr, i386_intr_func_t func);

static inline void	lapic_set_timer_func(i386_intr_func_t func)
{
	lapic_set_intr_func(LAPIC_VECTOR(TIMER), func);
}
static inline void	lapic_set_pmi_func(i386_intr_func_t func)
{
	lapic_set_intr_func(LAPIC_VECTOR(PERFCNT), func);
}
static inline void	lapic_set_thermal_func(i386_intr_func_t func)
{
	lapic_set_intr_func(LAPIC_VECTOR(THERMAL), func);
}

#ifdef MP_DEBUG
#define LAPIC_CPU_MAP_DUMP()	lapic_cpu_map_dump()
#define LAPIC_DUMP()		lapic_dump()
#else
#define LAPIC_CPU_MAP_DUMP()
#define LAPIC_DUMP()
#endif /* MP_DEBUG */

#endif /* ASSEMBLER */

#endif /* _I386_LAPIC_H_ */

