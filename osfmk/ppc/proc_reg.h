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

#ifndef _PPC_PROC_REG_H_
#define _PPC_PROC_REG_H_

#include <mach/boolean.h>

/* Define some useful masks that convert from bit numbers */

#if __PPC__
#if _BIG_ENDIAN
#ifndef ENDIAN_MASK
#define ENDIAN_MASK(val,size) (1 << ((size-1) - val))
#endif
#else
#error code not ported to little endian targets yet
#endif /* _BIG_ENDIAN */
#endif /* __PPC__ */

#define MASK32(PART)	ENDIAN_MASK(PART ## _BIT, 32)
#define MASK16(PART)	ENDIAN_MASK(PART ## _BIT, 16)
#define MASK8(PART)	ENDIAN_MASK(PART ## _BIT, 8)

#undef MASK
#define MASK(PART)	MASK32(PART)

#define BITS_PER_WORD	32
#define BITS_PER_WORD_POW2 5

/* Defines for decoding the MSR bits */

#define MSR_SF_BIT	0
#define MSR_RES1_BIT	1
#define MSR_RES2_BIT	2
#define MSR_RES3_BIT	3
#define MSR_RES4_BIT	4
#define MSR_RES5_BIT	5
#define MSR_VEC_BIT		6
#define MSR_RES7_BIT	7
#define MSR_RES8_BIT	8
#define MSR_RES9_BIT	9
#define MSR_RES10_BIT	10
#define MSR_RES11_BIT	11
#define MSR_KEY_BIT	12	/* Key bit on 603e (not on 603) */
#define	MSR_POW_BIT	13
#define MSR_TGPR_BIT	14	/* Temporary GPR mappings on 603/603e */
#define MSR_ILE_BIT	15
#define	MSR_EE_BIT	16
#define	MSR_PR_BIT	17
#define MSR_FP_BIT	18
#define MSR_ME_BIT	19
#define MSR_FE0_BIT	20
#define MSR_SE_BIT	21
#define	MSR_BE_BIT	22
#define MSR_FE1_BIT	23
#define MSR_RES24_BIT	24	/* AL bit in power architectures */
#define MSR_IP_BIT      25
#define MSR_IR_BIT      26
#define MSR_DR_BIT      27
#define MSR_RES28_BIT	28
#define MSR_PM_BIT	29
#define	MSR_RI_BIT	30
#define MSR_LE_BIT	31

/* MSR for kernel mode, interrupts disabled, running in virtual mode */
#define MSR_SUPERVISOR_INT_OFF (MASK(MSR_ME) | MASK(MSR_IR) | MASK(MSR_DR))  

/* MSR for above but with interrupts enabled */
#define MSR_SUPERVISOR_INT_ON (MSR_SUPERVISOR_INT_OFF | MASK(MSR_EE))

/* MSR for physical mode code */
#define MSR_VM_OFF     (MASK(MSR_ME))

/* MSR for physical instruction, virtual data */
#define MSR_PHYS_INST_VIRT_DATA     (MASK(MSR_ME) | MASK(MSR_IR))

/* MSR mask for user-exported bits - identify bits that must be set/reset */

/* SET - external exceptions, machine check, vm on, user-level privs */
#define MSR_EXPORT_MASK_SET	(MASK(MSR_EE)| MASK(MSR_ME)| \
				 MASK(MSR_IR)|MASK(MSR_DR)|MASK(MSR_PR))

/* only the following bits may be changed by a task */
#define MSR_IMPORT_BITS (MASK(MSR_FE0)|MASK(MSR_SE)|MASK(MSR_BE)| \
			 MASK(MSR_FE1)| MASK(MSR_PM) | MASK(MSR_LE))

#define MSR_PREPARE_FOR_IMPORT(origmsr, newmsr) \
	((origmsr & ~MSR_IMPORT_BITS) | (newmsr & MSR_IMPORT_BITS))

#define MSR_VEC_ON	(MASK(MSR_VEC))

#define USER_MODE(msr) (msr & MASK(MSR_PR) ? TRUE : FALSE)

/* seg reg values must be simple expressions so that assembler can cope */
#define SEG_REG_INVALID 0x0000
#define KERNEL_SEG_REG0_VALUE 0x20000000 /* T=0,Ks=0,Ku=1 PPC_SID_KERNEL=0*/

/* the following segment register values are only used prior to the probe,
 * they map the various device areas 1-1 on 601 machines
 */
#define KERNEL_SEG_REG5_VALUE 0xa7F00005 /* T=1,Ks=0,Ku=1,BUID=0x7F,SR=5 */
#define KERNEL_SEG_REG8_VALUE 0xa7F00008 /* T=1,Ks=0,Ku=1,BUID=0x7F,SR=8 */
#define KERNEL_SEG_REG9_VALUE 0xa7F00009 /* T=1,Ks=0,Ku=1,BUID=0x7F,SR=9 */
#define KERNEL_SEG_REG10_VALUE 0xa7F0000a /* T=1,Ks=0,Ku=1,BUID=0x7F,SR=a */
#define KERNEL_SEG_REG11_VALUE 0xa7F0000b /* T=1,Ks=0,Ku=1,BUID=0x7F,SR=b */
#define KERNEL_SEG_REG12_VALUE 0xa7F0000c /* T=1,Ks=0,Ku=1,BUID=0x7F,SR=c */
#define KERNEL_SEG_REG13_VALUE 0xa7F0000d /* T=1,Ks=0,Ku=1,BUID=0x7F,SR=d */
#define KERNEL_SEG_REG14_VALUE 0xa7F0000e /* T=1,Ks=0,Ku=1,BUID=0x7F,SR=e */
#define KERNEL_SEG_REG15_VALUE 0xa7F0000f /* T=1,Ks=0,Ku=1,BUID=0x7F,SR=f */

/* For SEG_REG_PROT we have T=0, Ks=0, Ku=1 */
#define SEG_REG_PROT	0x20000000   /* seg regs should have these bits set */

/* SR_COPYIN is used for copyin/copyout+remapping and must be
 * saved and restored in the thread context.
 */
/* SR_UNUSED_BY_KERN is unused by the kernel, and thus contains
 * the space ID of the currently interrupted user task immediately
 * after an exception and before interrupts are reenabled. It's used
 * purely for an assert.
 */

/* SR_KERNEL used for asserts... */

#define SR_COPYIN	sr14
#define SR_UNUSED_BY_KERN sr13
#define SR_KERNEL 	sr0

#define SR_UNUSED_BY_KERN_NUM 13
#define SR_COPYIN_NAME	sr14
#define SR_COPYIN_NUM	14


/* DSISR bits on data access exceptions */

#define DSISR_IO_BIT		0	/* NOT USED on 601 */
#define DSISR_HASH_BIT		1
#define DSISR_PROT_BIT		4
#define DSISR_IO_SPC_BIT	5
#define DSISR_WRITE_BIT		6
#define DSISR_WATCH_BIT		9
#define DSISR_EIO_BIT		11

/* SRR1 bits on data/instruction translation exceptions */

#define SRR1_TRANS_HASH_BIT	1
#define SRR1_TRANS_IO_BIT	3
#define SRR1_TRANS_PROT_BIT	4
#define SRR1_TRANS_NO_PTE_BIT	10

/* SRR1 bits on program exceptions */

#define SRR1_PRG_FE_BIT		11
#define SRR1_PRG_ILL_INS_BIT	12
#define SRR1_PRG_PRV_INS_BIT	13
#define SRR1_PRG_TRAP_BIT	14

/* BAT information */

/* Constants used when setting mask values */

#define BAT_INVALID 0

/*
 * Virtual to physical mapping macros/structures.
 * IMPORTANT NOTE: there is one mapping per HW page, not per MACH page.
 */

#define CACHE_LINE_SIZE	32
#define CACHE_LINE_POW2 5
#define cache_align(x)	(((x) + CACHE_LINE_SIZE-1) & ~(CACHE_LINE_SIZE - 1))

#define PTE1_WIMG_GUARD_BIT	28	/* Needed for assembler */
#define PTE1_REFERENCED_BIT	23	/* ditto */
#define PTE1_CHANGED_BIT	24
#define PTE0_HASH_ID_BIT	25

#define PPC_HASHSIZE		2048	/* size of hash table */
#define PPC_HASHSIZE_LOG2	11
#define PPC_MIN_MPP		2	/* min # of mappings per phys page */

/* macros to help decide processor type */
#define PROCESSOR_VERSION_601		1
#define PROCESSOR_VERSION_603		3
#define PROCESSOR_VERSION_604		4
#define PROCESSOR_VERSION_603e		6
#define PROCESSOR_VERSION_750		8
#define PROCESSOR_VERSION_604e		9
#define PROCESSOR_VERSION_604ev		10	/* ? */
#define PROCESSOR_VERSION_7400		12	/* ? */
#define PROCESSOR_VERSION_7410		0x800C	/* ? */
#define PROCESSOR_VERSION_7450		0x8000	/* ? */

#ifndef ASSEMBLER
#ifdef __GNUC__

#if _BIG_ENDIAN == 0
#error - bitfield structures are not checked for bit ordering in words
#endif /* _BIG_ENDIAN */

/* Structures and types for machine registers */

typedef union {
	unsigned int word;
	struct {
		unsigned int htaborg    : 16;
		unsigned int reserved   : 7;
		unsigned int htabmask   : 9;
	} bits;
} sdr1_t;

/* Block mapping registers.  These values are model dependent. 
 * Eventually, we will need to up these to 64 bit values.
 */

#define blokValid 0x1FFE0000
#define batMin 0x00020000
#define batMax 0x10000000
#define batICnt 4
#define batDCnt 4

/* BAT register structures.
 * Not used for standard mappings, but may be used
 * for mapping devices. Note that the 601 has a
 * different BAT layout than the other PowerPC processors
 */

typedef union {
	unsigned int word;
	struct {
		unsigned int blpi	: 15;
		unsigned int reserved	: 10;
		unsigned int wim	: 3;
		unsigned int ks		: 1;
		unsigned int ku		: 1;
		unsigned int pp		: 2;
	} bits;
} bat601u_t;

typedef union {
	unsigned int word;
	struct {
		unsigned int pbn	: 15;
		unsigned int reserved	: 10;
		unsigned int valid	: 1;
		unsigned int bsm	: 6;
	} bits;
} bat601l_t;

typedef struct bat601_t {
	bat601u_t	upper;
	bat601l_t	lower;
} bat601_t;

typedef union {
	unsigned int word;
	struct {
		unsigned int bepi	: 15;
		unsigned int reserved	: 4;
		unsigned int bl		: 11;
		unsigned int vs		: 1;
		unsigned int vp		: 1;
	} bits;
} batu_t;

typedef union {
	unsigned int word;
	struct {
		unsigned int brpn	: 15;
		unsigned int reserved	: 10;
		unsigned int wimg	: 4;
		unsigned int reserved2	: 1;
		unsigned int pp		: 2;
	} bits;
} batl_t;

typedef struct bat_t {
	batu_t	upper;
	batl_t	lower;
} bat_t;

/* PTE entries
 * Used extensively for standard mappings
 */

typedef	union {
	unsigned int word;
	struct {
		unsigned int valid      : 1;
		unsigned int segment_id : 24;
		unsigned int hash_id    : 1;
		unsigned int page_index : 6; /* Abbreviated */
	} bits;
	struct {
		unsigned int valid      : 1;
		unsigned int not_used   : 5;
		unsigned int segment_id : 19; /* Least Sig 19 bits */
		unsigned int hash_id    : 1;
		unsigned int page_index : 6;
	} hash_bits;
} pte0_t;

typedef	union {
	unsigned int word;
	struct {
		unsigned int phys_page  : 20;
		unsigned int reserved3  : 3;
		unsigned int referenced : 1;
		unsigned int changed    : 1;
		unsigned int wimg       : 4;
		unsigned int reserved1  : 1;
		unsigned int protection : 2;
	} bits;
} pte1_t;

typedef struct pte_t {
	pte0_t pte0;
	pte1_t pte1;
} pte_t;

#define PTE_NULL ((pte_t*) NULL) /* No pte found/associated with this */
#define PTE_EMPTY 0x7fffffbf 	 /* Value in the pte0.word of a free pte */

#define PTE_WIMG_CB_CACHED			0 	/* cached, writeback */
#define PTE_WIMG_CB_CACHED_GUARDED		1 	/* cached, writeback, guarded */
#define PTE_WIMG_CB_CACHED_COHERENT		2 	/* cached, writeback, coherent (default) */
#define PTE_WIMG_CB_CACHED_COHERENT_GUARDED	3 	/* cached, writeback, coherent, guarded */
#define PTE_WIMG_UNCACHED			4 	/* uncached */
#define PTE_WIMG_UNCACHED_GUARDED		5	/* uncached, guarded */
#define PTE_WIMG_UNCACHED_COHERENT		6	/* uncached, coherentt */
#define PTE_WIMG_UNCACHED_COHERENT_GUARDED	7	/* uncached, coherent, guarded */
#define PTE_WIMG_WT_CACHED			8 	/* cached, writethru */
#define PTE_WIMG_WT_CACHED_GUARDED		9 	/* cached, writethru, guarded */
#define PTE_WIMG_WT_CACHED_COHERENT		10 	/* cached, writethru, coherent */
#define PTE_WIMG_WT_CACHED_COHERENT_GUARDED	11 	/* cached, writethru, coherent, guarded */

#define PTE_WIMG_DEFAULT 	PTE_WIMG_CB_CACHED_COHERENT
#define PTE_WIMG_IO		PTE_WIMG_UNCACHED_COHERENT_GUARDED

/*
 * A virtual address is decoded into various parts when looking for its PTE
 */

typedef struct va_full_t {
	unsigned int seg_num    : 4;
	unsigned int page_index : 16;
	unsigned int byte_ofs   : 12;
} va_full_t;

typedef struct va_abbrev_t { /* use bits.abbrev for abbreviated page index */
	unsigned int seg_num    : 4;
	unsigned int page_index : 6;
	unsigned int junk       : 10;
	unsigned int byte_ofs   : 12;
} va_abbrev_t;

typedef union {
	unsigned int word;
	va_full_t    full;
	va_abbrev_t  abbrev;
} virtual_addr_t;

/* A physical address can be split up into page and offset */

typedef struct pa_t {
	unsigned int page_no : 20;
	unsigned int offset  : 12;
} pa_t;

typedef union {
	unsigned int word;
	pa_t         bits;
} physical_addr_t;

/*
 * C-helper inline functions for accessing machine registers follow.
 */


#ifdef	__ELF__
#define	__CASMNL__	";"
#else
#define	__CASMNL__ "@"
#endif

/* Return the current GOT pointer */

extern unsigned int get_got(void);

extern __inline__ unsigned int get_got(void)
{
        unsigned int result;
#ifndef __ELF__
        __asm__ volatile("mr %0,	r2" : "=r" (result));
#else
        __asm__ volatile("mr %0,	2" : "=r" (result));
#endif
        return result;
}

/*
 * Various memory/IO synchronisation instructions
 */

        /*	Use eieio as a memory barrier to order stores.
         *	Useful for device control and PTE maintenance.
         */

#define eieio() \
        __asm__ volatile("eieio")

        /* 	Use sync to ensure previous stores have completed.
        	This is  required when manipulating locks and/or
        	maintaining PTEs or other shared structures on SMP 
        	machines.
        */

#define sync() \
        __asm__ volatile("sync")

        /*	Use isync to sychronize context; that is, the ensure
        	no prefetching of instructions happen before the
        	instruction.
        */

#define isync() \
        __asm__ volatile("isync")


/*
 *		This guy will make sure all tlbs on all processors finish their tlbies
 */
#define tlbsync() \
        __asm__ volatile("tlbsync")


		/*	Invalidate TLB entry. Caution, requires context synchronization.
		*/
extern void tlbie(unsigned int val);

extern __inline__ void tlbie(unsigned int val)
{
        __asm__ volatile("tlbie %0" : : "r" (val));
        return;
}



/*
 * Access to various system registers
 */

extern unsigned int mflr(void);

extern __inline__ unsigned int mflr(void)
{
        unsigned int result;
        __asm__ volatile("mflr %0" : "=r" (result));
        return result;
}

extern unsigned int mfpvr(void);

extern __inline__ unsigned int mfpvr(void)
{
        unsigned int result;
        __asm__ ("mfpvr %0" : "=r" (result));
        return result;
}

/* mtmsr might need syncs etc around it, don't provide simple
 * inline macro
 */

extern unsigned int mfmsr(void);

extern __inline__ unsigned int mfmsr(void)
{
        unsigned int result;
        __asm__ volatile("mfmsr %0" : "=r" (result));
        return result;
}

/* mtsr and mfsr must be macros since SR must be hardcoded */

#if __ELF__
#define mtsr(SR, REG)							     \
	__asm__ volatile("sync" __CASMNL__ "mtsr %0, %1 " __CASMNL__ "isync" : : "i" (SR), "r" (REG));
#define mfsr(REG, SR) \
	__asm__ volatile("mfsr %0, %1" : "=r" (REG) : "i" (SR));
#else
#define mtsr(SR, REG)							     \
	__asm__ volatile("sync" __CASMNL__ "mtsr sr%0, %1 " __CASMNL__ "isync" : : "i" (SR), "r" (REG)); 

#define mfsr(REG, SR) \
	__asm__ volatile("mfsr %0, sr%1" : "=r" (REG) : "i" (SR));
#endif


extern void mtsrin(unsigned int val, unsigned int reg);

extern __inline__ void mtsrin(unsigned int val, unsigned int reg)
{
        __asm__ volatile("sync" __CASMNL__ "mtsrin %0, %1" __CASMNL__ " isync" : : "r" (val), "r" (reg));
        return;
}

extern unsigned int mfsrin(unsigned int reg);

extern __inline__ unsigned int mfsrin(unsigned int reg)
{
	unsigned int result;
        __asm__ volatile("mfsrin %0, %1" : "=r" (result) : "r" (reg));
        return result;
}

extern void mtsdr1(unsigned int val);

extern __inline__ void mtsdr1(unsigned int val)
{
        __asm__ volatile("mtsdr1 %0" : : "r" (val));
        return;
}

extern void mtdar(unsigned int val);

extern __inline__ void mtdar(unsigned int val)
{
        __asm__ volatile("mtdar %0" : : "r" (val));
        return;
}

extern unsigned int mfdar(void);

extern __inline__ unsigned int mfdar(void)
{
        unsigned int result;
        __asm__ volatile("mfdar %0" : "=r" (result));
        return result;
}

extern void mtdec(unsigned int val);

extern __inline__ void mtdec(unsigned int val)
{
        __asm__ volatile("mtdec %0" : : "r" (val));
        return;
}

extern int isync_mfdec(void);

extern __inline__ int isync_mfdec(void)
{
        int result;
        __asm__ volatile("isync" __CASMNL__ "mfdec %0" : "=r" (result));
        return result;
}

/* Read and write the value from the real-time clock
 * or time base registers. Note that you have to
 * use the right ones depending upon being on
 * 601 or 603/604. Care about carries between
 * the words and using the right registers must be
 * done by the calling function.
 */

extern void mttb(unsigned int val);

extern __inline__ void mttb(unsigned int val)
{
        __asm__ volatile("mtspr tbl, %0" : : "r" (val));
        return;
}

extern unsigned int mftb(void);

extern __inline__ unsigned int mftb(void)
{
        unsigned int result;
        __asm__ volatile("mftb %0" : "=r" (result));
        return result;
}

extern void mttbu(unsigned int val);

extern __inline__ void mttbu(unsigned int val)
{
        __asm__ volatile("mtspr tbu, %0" : : "r" (val));
        return;
}

extern unsigned int mftbu(void);

extern __inline__ unsigned int mftbu(void)
{
        unsigned int result;
        __asm__ volatile("mftbu %0" : "=r" (result));
        return result;
}

extern void mtrtcl(unsigned int val);

extern __inline__ void mtrtcl(unsigned int val)
{
        __asm__ volatile("mtspr  21,%0" : : "r" (val));
        return;
}

extern unsigned int mfrtcl(void);

extern __inline__ unsigned int mfrtcl(void)
{
        unsigned int result;
        __asm__ volatile("mfspr %0,5" : "=r" (result));
        return result;
}

extern void mtrtcu(unsigned int val);

extern __inline__ void mtrtcu(unsigned int val)
{
        __asm__ volatile("mtspr 20,%0" : : "r" (val));
        return;
}

extern unsigned int mfrtcu(void);

extern __inline__ unsigned int mfrtcu(void)
{
        unsigned int result;
        __asm__ volatile("mfspr %0,4" : "=r" (result));
        return result;
}

extern void mtl2cr(unsigned int val);

extern __inline__ void mtl2cr(unsigned int val)
{
  __asm__ volatile("mtspr l2cr, %0" : : "r" (val));
  return;
}

extern unsigned int mfl2cr(void);

extern __inline__ unsigned int mfl2cr(void)
{
  unsigned int result;
  __asm__ volatile("mfspr %0, l2cr" : "=r" (result));
  return result;
}

extern unsigned int cntlzw(unsigned int num);

extern __inline__ unsigned int cntlzw(unsigned int num)
{
  unsigned int result;
  __asm__ volatile("cntlzw %0, %1" : "=r" (result) : "r" (num));
  return result;
}


/* functions for doing byte reversed loads and stores */

extern unsigned int lwbrx(unsigned int addr);

extern __inline__ unsigned int lwbrx(unsigned int addr)
{
  unsigned int result;
  __asm__ volatile("lwbrx %0, 0, %1" : "=r" (result) : "r" (addr));
  return result;
}

extern void stwbrx(unsigned int data, unsigned int addr);

extern __inline__ void stwbrx(unsigned int data, unsigned int addr)
{
  __asm__ volatile("stwbrx %0, 0, %1" : : "r" (data), "r" (addr));
}

/* Performance Monitor Register access routines */
extern unsigned long   mfmmcr0(void);
extern void                    mtmmcr0(unsigned long);
extern unsigned long   mfmmcr1(void);
extern void                    mtmmcr1(unsigned long);
extern unsigned long   mfmmcr2(void);
extern void                    mtmmcr2(unsigned long);
extern unsigned long   mfpmc1(void);
extern void                    mtpmc1(unsigned long);
extern unsigned long   mfpmc2(void);
extern void                    mtpmc2(unsigned long);
extern unsigned long   mfpmc3(void);
extern void                    mtpmc3(unsigned long);
extern unsigned long   mfpmc4(void);
extern void                    mtpmc4(unsigned long);
extern unsigned long   mfsia(void);
extern unsigned long   mfsda(void);

/* macros since the argument n is a hard-coded constant */

#define mtibatu(n, reg) __asm__ volatile("mtibatu " # n ", %0" : : "r" (reg))
#define mtibatl(n, reg) __asm__ volatile("mtibatl " # n ", %0" : : "r" (reg))

#define mtdbatu(n, reg) __asm__ volatile("mtdbatu " # n ", %0" : : "r" (reg))
#define mtdbatl(n, reg) __asm__ volatile("mtdbatl " # n ", %0" : : "r" (reg))

#define mfibatu(reg, n) __asm__ volatile("mfibatu %0, " # n : "=r" (reg))
#define mfibatl(reg, n) __asm__ volatile("mfibatl %0, " # n : "=r" (reg))

#define mfdbatu(reg, n) __asm__ volatile("mfdbatu %0, " # n : "=r" (reg))
#define mfdbatl(reg, n) __asm__ volatile("mfdbatl %0, " # n : "=r" (reg))

#define mtsprg(n, reg)  __asm__ volatile("mtsprg  " # n ", %0" : : "r" (reg))
#define mfsprg(reg, n)  __asm__ volatile("mfsprg  %0, " # n : "=r" (reg))

#define mtspr(spr, val)  __asm__ volatile("mtspr  " # spr ", %0" : : "r" (val))
#define mfspr(reg, spr)  __asm__ volatile("mfspr  %0, " # spr : "=r" (reg))

#endif /* __GNUC__ */
#endif /* !ASSEMBLER */

#endif /* _PPC_PROC_REG_H_ */
