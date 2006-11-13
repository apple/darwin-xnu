/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 * 
 */
#ifndef _I386_APIC_H_
#define _I386_APIC_H_

#define LAPIC_START			0xFEE00000
#define LAPIC_SIZE			0x00000400

#define LAPIC_ID			0x00000020
#define		LAPIC_ID_SHIFT		24
#define		LAPIC_ID_MASK		0x0F
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

#ifndef	ASSEMBLER
#include <stdint.h>
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
#endif /* ASSEMBLER */

#define IOAPIC_START			0xFEC00000
#define	IOAPIC_SIZE			0x00000020

#define IOAPIC_RSELECT			0x00000000
#define IOAPIC_RWINDOW			0x00000010
#define IOA_R_ID			0x00
#define		IOA_R_ID_SHIFT		24
#define IOA_R_VERSION			0x01
#define		IOA_R_VERSION_MASK	0xFF
#define		IOA_R_VERSION_ME_SHIFT	16
#define		IOA_R_VERSION_ME_MASK	0xFF
#define IOA_R_REDIRECTION		0x10
#define 	IOA_R_R_VECTOR_MASK	0x000FF
#define		IOA_R_R_DM_MASK		0x00700
#define		IOA_R_R_DM_FIXED	0x00000
#define		IOA_R_R_DM_LOWEST	0x00100
#define		IOA_R_R_DM_NMI		0x00400
#define		IOA_R_R_DM_RESET	0x00500
#define		IOA_R_R_DM_EXTINT	0x00700
#define		IOA_R_R_DEST_LOGICAL	0x00800
#define		IOA_R_R_DS_PENDING	0x01000
#define		IOA_R_R_IP_PLRITY_LOW	0x02000
#define		IOA_R_R_TM_LEVEL	0x08000
#define		IOA_R_R_MASKED		0x10000

#endif /* _I386_APIC_H_ */

