/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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
#ifndef _I386_PERFMON_H_
#define _I386_PERFMON_H_

#include <i386/proc_reg.h>

/*
 * Handy macros for bit/bitfield definition and manipulations:
 */
#define bit(n)			(1ULL << (n))
#define field(n,m)		((bit((m)+1)-1) & ~(bit(n)-1))
#define field_nbit(fld)		(ffs(fld)-1)
#define field_select(fld,x)	((x) & (fld))
#define field_clear(fld,x)	((x) & ~(fld))
#define field_unshift(fld,x)	((x) >> field_nbit(fld))
#define field_shift(fld,x)	((x) << field_nbit(fld))
#define field_get(fld,x)	(field_unshift(fld,field_select(fld,x)))
#define field_set(fld,x,val)	(field_clear(fld,x) | field_shift(fld,val))

#define PERFMON_AVAILABLE	bit(7)
#define BTS_UNAVAILABLE		bit(11)

static inline boolean_t
pmc_is_available(void)
{
	uint32_t	lo;
	uint32_t	hi;
	int		ret;

	ret = rdmsr_carefully(MSR_IA32_MISC_ENABLE, &lo, &hi);

	return (ret == 0) && ((lo & PERFMON_AVAILABLE) != 0);
}

/*
 * Counter layout:
 */
#define	PMC_COUNTER_COUNTER		field(0,39)
#define	PMC_COUNTER_RESERVED		field(40,64)
#define PMC_COUNTER_MAX			((uint64_t) PMC_COUNTER_COUNTER)
typedef struct {
	uint64_t	counter		: 40;
	uint64_t	reserved	: 24;
} pmc_counter_t;
#define	PMC_COUNTER_ZERO { 0, 0 }


/*
 * There are 2 basic flavors of PMCsL: P6 and P4/Xeon:
 */
typedef enum {
	pmc_none,
	pmc_P6,
	pmc_P4_Xeon,
	pmc_unknown
} pmc_machine_t;

/*
 * P6 MSRs...
 */
#define	MSR_P6_COUNTER_ADDR(n)	(0x0c1 + (n))
#define	MSR_P6_PES_ADDR(n)	(0x186 + (n))

typedef struct {
	uint64_t	event_select	: 8;
	uint64_t	umask		: 8;
	uint64_t	usr		: 1;
	uint64_t	os		: 1;
	uint64_t	e		: 1;
	uint64_t	pc		: 1;
	uint64_t	apic_int	: 1;
	uint64_t	reserved1	: 1;
	uint64_t	en		: 1;
	uint64_t	inv		: 1;
	uint64_t	cmask		: 8;
} pmc_evtsel_t;
#define PMC_EVTSEL_ZERO	((pmc_evtsel_t){ 0,0,0,0,0,0,0,0,0,0,0 }) 

#define	MSR_P6_PERFCTR0	0
#define	MSR_P6_PERFCTR1	1

/*
 * P4/Xeon MSRs...
 */
#define	MSR_COUNTER_ADDR(n)	(0x300 + (n))
#define	MSR_CCCR_ADDR(n)	(0x360 + (n))

typedef enum {
	MSR_BPU_COUNTER0	= 0,
	MSR_BPU_COUNTER1	= 1,
		#define MSR_BSU_ESCR0	7
		#define MSR_FSB_ESCR0	6
		#define MSR_MOB_ESCR0	2
		#define MSR_PMH_ESCR0	4
		#define MSR_BPU_ESCR0	0
		#define MSR_IS_ESCR0	1
		#define MSR_ITLB_ESCR0	3
		#define MSR_IX_ESCR0	5
	MSR_BPU_COUNTER2	= 2,
	MSR_BPU_COUNTER3	= 3,
		#define MSR_BSU_ESCR1	7
		#define MSR_FSB_ESCR1	6
		#define MSR_MOB_ESCR1	2
		#define MSR_PMH_ESCR1	4
		#define MSR_BPU_ESCR1	0
		#define MSR_IS_ESCR1	1
		#define MSR_ITLB_ESCR1	3
		#define MSR_IX_ESCR1	5
	MSR_MS_COUNTER0		= 4,
	MSR_MS_COUNTER1		= 5,
		#define MSR_MS_ESCR0	0
		#define MSR_TBPU_ESCR0	2
		#define MSR_TC_ESCR0	1
	MSR_MS_COUNTER2		= 6,
	MSR_MS_COUNTER3		= 7,
		#define MSR_MS_ESCR1	0
		#define MSR_TBPU_ESCR1	2
		#define MSR_TC_ESCR1	1
	MSR_FLAME_COUNTER0	= 8,
	MSR_FLAME_COUNTER1	= 9,
		#define MSR_FIRM_ESCR0	1
		#define MSR_FLAME_ESCR0	0
		#define MSR_DAC_ESCR0	5
		#define MSR_SAT_ESCR0	2
		#define MSR_U2L_ESCR0	3
	MSR_FLAME_COUNTER2	= 10,
	MSR_FLAME_COUNTER3	= 11,
		#define MSR_FIRM_ESCR1	1
		#define MSR_FLAME_ESCR1	0
		#define MSR_DAC_ESCR1	5
		#define MSR_SAT_ESCR1	2
		#define MSR_U2L_ESCR1	3
	MSR_IQ_COUNTER0		= 12,
	MSR_IQ_COUNTER1		= 13,
	MSR_IQ_COUNTER4		= 16,
		#define MSR_CRU_ESCR0	4
		#define MSR_CRU_ESCR2	5
		#define MSR_CRU_ESCR4	6
		#define MSR_IQ_ESCR0	0
		#define MSR_RAT_ESCR0	2
		#define MSR_SSU_ESCR0	3
		#define MSR_AFL_ESCR0	1
	MSR_IQ_COUNTER2		= 14,
	MSR_IQ_COUNTER3		= 15,
	MSR_IQ_COUNTER5		= 17,
		#define MSR_CRU_ESCR1	4
		#define MSR_CRU_ESCR3	5
		#define MSR_CRU_ESCR5	6
		#define MSR_IQ_ESCR1	0
		#define MSR_RAT_ESCR1	2
		#define MSR_AFL_ESCR1	1
} pmc_id_t;

typedef int pmc_escr_id_t;
#define PMC_ESID_MAX			7

/*
 * ESCR MSR layout:
 */
#define	PMC_ECSR_NOHTT_RESERVED		field(0,1)
#define	PMC_ECSR_T0_USR			bit(0)
#define	PMC_ECSR_T0_OS			bit(1)
#define	PMC_ECSR_T1_USR			bit(2)
#define	PMC_ECSR_T1_OS			bit(3)
#define	PMC_ECSR_USR			bit(2)
#define	PMC_ECSR_OS			bit(3)
#define	PMC_ECSR_TAG_ENABLE		bit(4)
#define	PMC_ECSR_TAG_VALUE		field(5,8)
#define	PMC_ECSR_EVENT_MASK		field(9,24)
#define	PMC_ECSR_EVENT_SELECT		field(25,30)
#define	PMC_ECSR_RESERVED2		field(30,64)
typedef struct {
	uint64_t	reserved1	: 2;
	uint64_t	usr		: 1;
	uint64_t	os		: 1;
	uint64_t	tag_enable	: 1;
	uint64_t	tag_value 	: 4;
	uint64_t	event_mask	: 16;
	uint64_t	event_select	: 6;
	uint64_t	reserved2	: 33;
} pmc_escr_nohtt_t;
typedef struct {
	uint64_t	t0_usr		: 1;
	uint64_t	t0_os		: 1;
	uint64_t	t1_usr		: 1;
	uint64_t	t1_os		: 1;
	uint64_t	tag_enable	: 1;
	uint64_t	tag_value 	: 4;
	uint64_t	event_mask	: 16;
	uint64_t	event_select	: 6;
	uint64_t	reserved2	: 33;
} pmc_escr_htt_t;
typedef union {
	pmc_escr_nohtt_t	u_nohtt;
	pmc_escr_htt_t		u_htt;
	uint64_t		u_u64;
} pmc_escr_t;
#define PMC_ESCR_ZERO	{ .u_u64 = 0ULL }

/*
 * CCCR MSR layout:
 */
#define	PMC_CCCR_RESERVED1		field(1,11)
#define	PMC_CCCR_ENABLE			bit(12)
#define	PMC_CCCR_ECSR_SELECT		field(13,15)
#define PMC_CCCR_RESERVED2		field(16,17)
#define PMC_CCCR_HTT_ACTIVE		field(16,17)
#define	PMC_CCCR_COMPARE		bit(18)
#define	PMC_CCCR_COMPLEMENT		bit(19)
#define	PMC_CCCR_THRESHOLD		field(20,23)
#define	PMC_CCCR_EDGE			bit(24)
#define	PMC_CCCR_FORCE_OVF		bit(25)
#define	PMC_CCCR_OVF_PMI		bit(26)
#define PMC_CCCR_NOHTT_RESERVED2	field(27,29)
#define	PMC_CCCR_OVF_PMI_T0		bit(26)
#define	PMC_CCCR_OVF_PMI_T1		bit(27)
#define PMC_CCCR_HTT_RESERVED2		field(28,29)
#define	PMC_CCCR_CASCADE		bit(30)
#define	PMC_CCCR_OVF			bit(31)
typedef struct {
	uint64_t	reserved1	: 12;
	uint64_t	enable		: 1;
	uint64_t	escr_select	: 3;
	uint64_t	reserved2	: 2;
	uint64_t	compare		: 1;
	uint64_t	complement	: 1;
	uint64_t	threshold	: 4;
	uint64_t	edge		: 1;
	uint64_t	force_ovf	: 1;
	uint64_t	ovf_pmi		: 1;
	uint64_t	reserved3	: 3;
	uint64_t	cascade		: 1;
	uint64_t	ovf		: 1;
	uint64_t	reserved4	: 32;
} pmc_cccr_nohtt_t;
typedef struct {
	uint64_t	reserved1	: 12;
	uint64_t	enable		: 1;
	uint64_t	escr_select	: 3;
	uint64_t	active_thread	: 2;
	uint64_t	compare		: 1;
	uint64_t	complement	: 1;
	uint64_t	threshold	: 4;
	uint64_t	edge		: 1;
	uint64_t	force_OVF	: 1;
	uint64_t	ovf_pmi_t0	: 1;
	uint64_t	ovf_pmi_t1	: 1;
	uint64_t	reserved3	: 2;
	uint64_t	cascade		: 1;
	uint64_t	ovf		: 1;
	uint64_t	reserved4	: 32;
} pmc_cccr_htt_t;
typedef union {
	pmc_cccr_nohtt_t	u_nohtt;
	pmc_cccr_htt_t		u_htt;
	uint64_t		u_u64;
} pmc_cccr_t;
#define PMC_CCCR_ZERO	{ .u_u64 = 0ULL }

typedef void (pmc_ovf_func_t)(pmc_id_t id, void *state);

/*
 * In-kernel PMC access primitives:
 */
/* Generic: */
extern int pmc_init(void);
extern int pmc_machine_type(pmc_machine_t *type);
extern boolean_t pmc_is_reserved(pmc_id_t id);
extern int pmc_reserve(pmc_id_t id);
extern int pmc_free(pmc_id_t id);
extern int pmc_counter_read(pmc_id_t id, pmc_counter_t *val);
extern int pmc_counter_write(pmc_id_t id, pmc_counter_t *val);

/* P6-specific: */
extern int pmc_evtsel_read(pmc_id_t id, pmc_evtsel_t *evtsel);
extern int pmc_evtsel_write(pmc_id_t id, pmc_evtsel_t *evtsel);

/* P4/Xeon-specific: */
extern int pmc_cccr_read(pmc_id_t id, pmc_cccr_t *cccr);
extern int pmc_cccr_write(pmc_id_t id, pmc_cccr_t *cccr);
extern int pmc_escr_read(pmc_id_t id, pmc_escr_id_t esid, pmc_escr_t *escr);
extern int pmc_escr_write(pmc_id_t id, pmc_escr_id_t esid, pmc_escr_t *escr);
extern int pmc_set_ovf_func(pmc_id_t id, pmc_ovf_func_t *func);

#endif /* _I386_PERFMON_H_ */
