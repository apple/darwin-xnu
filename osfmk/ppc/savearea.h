/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
#ifdef	XNU_KERNEL_PRIVATE

#ifndef _PPC_SAVEAREA_H_
#define _PPC_SAVEAREA_H_

#ifndef ASSEMBLER

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE

#ifdef	MACH_KERNEL_PRIVATE
#include <stdint.h>
#include <mach/vm_types.h>

#pragma pack(4)							/* Make sure the structure stays as we defined it */
typedef struct savearea_comm {

/*
 *	The following fields are common to all saveareas and are used to manage individual
 *	contexts.
 *	
 *	Fields that start with "save" are part of the individual saveareas.  Those that
 *	start with "sac" pertain to the free pool stuff and are valid only on the first slot
 *	in the page.
 */


/*	Keep the save_prev, sac_next, and sac_prev in these positions, some assembler code depends upon it to
 *	match up with fields in saveanchor.
 */
                                                /* offset 0x000 */
	addr64_t		save_prev;					/* The address of the previous (or next) savearea */
	addr64_t		sac_next;					/* Points to next savearea page that has a free slot  - real */
	addr64_t		sac_prev;					/* Points to previous savearea page that has a free slot  - real */
	unsigned int	save_level;					/* Context ID */
	unsigned int	save_01C;

												/*	 0x20 */
	unsigned int	save_time[2];				/* Context save time - for debugging or performance */
	struct thread	*save_act;					/* Associated thread */
    unsigned int	save_02c;
	uint64_t		sac_vrswap;					/* XOR mask to swap V to R or vice versa */
	unsigned int	save_flags;					/* Various flags */
	unsigned int	sac_flags;					/* Various flags */
    
                                                /* offset 0x040 */
	uint64_t		save_misc0;					/* Various stuff */
	uint64_t		save_misc1;					/* Various stuff - snapshot chain during hibernation */
	unsigned int	sac_alloc;					/* Bitmap of allocated slots */
    unsigned int	save_054;
    unsigned int	save_misc2;
    unsigned int	save_misc3;

												/* offset 0x0060 */
} savearea_comm;
#pragma pack()
#endif

#ifdef BSD_KERNEL_PRIVATE
typedef struct savearea_comm {
	unsigned int	save_000[24];
} savearea_comm;
#endif

#if	defined(MACH_KERNEL_PRIVATE) || defined(BSD_KERNEL_PRIVATE)
/*
 *	This type of savearea contains all of the general context.
 */
 
#pragma pack(4)							/* Make sure the structure stays as we defined it */
typedef struct savearea {

	savearea_comm	save_hdr;					/* Stuff common to all saveareas */

	uint64_t		save_xdat0;					/* Exception data 0 */
	uint64_t		save_xdat1;					/* Exception data 1 */
	uint64_t		save_xdat2;					/* Exception data 2 */
	uint64_t		save_xdat3;					/* Exception data 3 */
                                                /* offset 0x0080 */
	uint64_t	 	save_r0;
	uint64_t	 	save_r1;
	uint64_t	 	save_r2;
	uint64_t	 	save_r3;
                                                /* offset 0x0A0 */
	uint64_t	 	save_r4;
	uint64_t	 	save_r5;
	uint64_t	 	save_r6;
	uint64_t	 	save_r7;
                                                /* offset 0x0C0 */
	uint64_t	 	save_r8;
	uint64_t	 	save_r9;
	uint64_t	 	save_r10;
	uint64_t	 	save_r11;
                                                /* offset 0x0E0 */
	uint64_t	 	save_r12;
	uint64_t	 	save_r13;
	uint64_t	 	save_r14;
	uint64_t	 	save_r15;
                                                /* offset 0x100 */
	uint64_t	 	save_r16;
	uint64_t	 	save_r17;
	uint64_t	 	save_r18;
	uint64_t	 	save_r19;
                                                /* offset 0x120 */
	uint64_t	 	save_r20;
	uint64_t	 	save_r21;
	uint64_t	 	save_r22;
	uint64_t	 	save_r23;
                                                /* offset 0x140 */
	uint64_t	 	save_r24;
	uint64_t	 	save_r25;
	uint64_t	 	save_r26;	
	uint64_t	 	save_r27;
                                                /* offset 0x160 */
	uint64_t	 	save_r28;
	uint64_t		save_r29;
	uint64_t	 	save_r30;
	uint64_t	 	save_r31;
                                                /* offset 0x180 */
	uint64_t	 	save_srr0;
 	uint64_t	 	save_srr1;
	uint64_t	 	save_xer;
	uint64_t	 	save_lr;
                                                /* offset 0x1A0 */
	uint64_t	 	save_ctr;
	uint64_t	 	save_dar;
	unsigned int	save_cr;
	unsigned int 	save_dsisr;
	unsigned int	save_exception; 
	unsigned int	save_vrsave;
                                                /* offset 0x1C0 */
	unsigned int	save_vscr[4];
	unsigned int	save_fpscrpad;
	unsigned int	save_fpscr;
    unsigned int	save_1d8[2];
                                                /* offset 0x1E0 */
	unsigned int	save_1E0[8];
                                                /* offset 0x200 - keep on 128 byte bndry */
    uint32_t        save_pmc[8]; 
    uint64_t        save_mmcr0;					/* offset 0x220 */
    uint64_t        save_mmcr1;
    uint64_t        save_mmcr2;

	unsigned int	save_238[2];
												/* offset 0x240 */
	unsigned int	save_instr[16];				/* Instrumentation */
												/* offset 0x280 */
} savearea;
#pragma pack()


/*
 *	This type of savearea contains all of the floating point context.
 */
 
#pragma pack(4)							/* Make sure the structure stays as we defined it */
typedef struct savearea_fpu {

	savearea_comm	save_hdr;					/* Stuff common to all saveareas */

	unsigned int	save_060[8];				/* Fill 32 bytes */
												/* offset 0x0080 */
	double			save_fp0;
	double			save_fp1;
	double			save_fp2;
	double			save_fp3;

	double			save_fp4;
	double			save_fp5;
	double			save_fp6;
	double			save_fp7;

	double			save_fp8;
	double			save_fp9;
	double			save_fp10;
	double			save_fp11;
	
	double			save_fp12;
	double			save_fp13;
	double			save_fp14;
	double			save_fp15;
	
	double			save_fp16;
	double			save_fp17;
	double			save_fp18;
	double			save_fp19;

	double			save_fp20;
	double			save_fp21;
	double			save_fp22;
	double			save_fp23;
	
	double			save_fp24;
	double			save_fp25;
	double			save_fp26;
	double			save_fp27;
	
	double			save_fp28;
	double			save_fp29;
	double			save_fp30;
	double			save_fp31;
												/* offset 0x180 */
	unsigned int	save_180[8];
	unsigned int	save_1A0[8];
	unsigned int	save_1C0[8];
	unsigned int	save_1E0[8];
	unsigned int	save_200[8];
	unsigned int	save_220[8];
	unsigned int	save_240[8];
	unsigned int	save_260[8];

												/* offset 0x280 */
} savearea_fpu;
#pragma pack()

	

/*
 *	This type of savearea contains all of the vector context.
 */
 
#pragma pack(4)							/* Make sure the structure stays as we defined it */
typedef struct savearea_vec {

	savearea_comm	save_hdr;					/* Stuff common to all saveareas */

	unsigned int	save_060[7];				/* Fill 32 bytes */
	unsigned int	save_vrvalid;				/* Valid registers in saved context */

												/* offset 0x0080 */
	unsigned int	save_vr0[4];
	unsigned int	save_vr1[4];
	unsigned int	save_vr2[4];
	unsigned int	save_vr3[4];
	unsigned int	save_vr4[4];
	unsigned int	save_vr5[4];
	unsigned int	save_vr6[4];
	unsigned int	save_vr7[4];
	unsigned int	save_vr8[4];
	unsigned int	save_vr9[4];
	unsigned int	save_vr10[4];
	unsigned int	save_vr11[4];
	unsigned int	save_vr12[4];
	unsigned int	save_vr13[4];
	unsigned int	save_vr14[4];
	unsigned int	save_vr15[4];
	unsigned int	save_vr16[4];
	unsigned int	save_vr17[4];
	unsigned int	save_vr18[4];
	unsigned int	save_vr19[4];
	unsigned int	save_vr20[4];
	unsigned int	save_vr21[4];
	unsigned int	save_vr22[4];
	unsigned int	save_vr23[4];
	unsigned int	save_vr24[4];
	unsigned int	save_vr25[4];
	unsigned int	save_vr26[4];
	unsigned int	save_vr27[4];
	unsigned int	save_vr28[4];
	unsigned int	save_vr29[4];
	unsigned int	save_vr30[4];
	unsigned int	save_vr31[4];

												/* offset 0x280 */
} savearea_vec;
#pragma pack()
#endif /* MACH_KERNEL_PRIVATE || BSD_KERNEL_PRIVATE */

#ifdef	MACH_KERNEL_PRIVATE

#pragma pack(4)							/* Make sure the structure stays as we defined it */
struct Saveanchor {

/*	
 *	Note that this force aligned in aligned_data.s and must be in V=R storage.
 *	Also, all addresses in chains are physical.  This structure can only be 
 *	updated with translation and interrupts disabled. This is because it is 
 *	locked during exception processing and if we were to take a PTE miss while the
 *	lock were held, well, that would be very bad now wouldn't it? 
 *  Note that the first 24 bytes must be the same format as a savearea header.
 */

	unsigned int			savelock;		/* 000 Lock word for savearea free list manipulation */
    int						saveRSVD4;		/* 004 reserved */
	addr64_t				savepoolfwd;	/* 008 Forward anchor for the free pool */
	addr64_t				savepoolbwd;	/* 010 Backward anchor for the free pool */
	volatile addr64_t		savefree;		/* 018 Anchor for the global free list */
	volatile unsigned int	savefreecnt;	/* 020 Number of saveareas on global free list */
	volatile int			saveadjust;		/* 024 If 0 number of saveareas is ok, otherwise # to change (pos means grow, neg means shrink */
	volatile int			saveinuse;		/* 028 Number of areas in use counting those on the local free list */
	unsigned int			savetarget;		/* 02C Number of saveareas needed */
	int						savemaxcount;	/* 030 Maximum saveareas ever allocated */
	unsigned int			saveinusesnapshot;		/* 034 snapshot inuse count */
	volatile addr64_t		savefreesnapshot;		/* 038 snapshot global free list header */
/*											   040 */
};
#pragma pack()

extern struct Saveanchor	saveanchor;			/* Aliged savearea anchor */

#define sac_cnt		(4096 / sizeof(savearea))	/* Number of saveareas per page */
#define sac_empty	(0xFFFFFFFF << (32 - sac_cnt))	/* Mask with all entries empty */
#define sac_perm	0x40000000				/* Page permanently assigned */
#define sac_permb	1						/* Page permanently assigned - bit position */

#define LocalSaveTarget	(((8 + sac_cnt - 1) / sac_cnt) * sac_cnt)	/* Target for size of local savearea free list */
#define LocalSaveMin	(LocalSaveTarget / 2)	/* Min size of local savearea free list before we grow */
#define LocalSaveMax	(LocalSaveTarget * 2)	/* Max size of local savearea free list before we trim */

#define FreeListMin		(2 * LocalSaveTarget)	/* Always make sure there are enough to fill local list twice per processor */
#define SaveLowHysteresis	LocalSaveTarget		/* The number off from target before we adjust upwards */
#define SaveHighHysteresis	(2 * FreeListMin)	/* The number off from target before we adjust downwards */
#define InitialSaveAreas 	(2 * FreeListMin)	/* The number of saveareas to make at boot time */
#define InitialSaveTarget	FreeListMin			/* The number of saveareas for an initial target. This should be the minimum ever needed. */
#define	InitialSaveBloks	(InitialSaveAreas + sac_cnt - 1) / sac_cnt	/* The number of savearea blocks to allocate at boot */
#define BackPocketSaveBloks	8				/* Number of pages of back pocket saveareas */

void			save_queue(ppnum_t);		/* Add a new savearea block to the free list */
addr64_t		save_get_init(void);		/* special savearea-get for cpu initialization (returns physical address) */
struct savearea	*save_get(void);			/* Obtains a savearea from the free list (returns virtual address) */
reg64_t			save_get_phys_32(void);		/* Obtains a savearea from the free list (returns phys addr in r3) */
reg64_t			save_get_phys_64(void);		/* Obtains a savearea from the free list (returns phys addr in r3) */
struct savearea	*save_alloc(void);			/* Obtains a savearea and allocates blocks if needed */
struct savearea	*save_cpv(addr64_t);		/* Converts a physical savearea address to virtual */
void			save_ret(struct savearea *);	/* Returns a savearea to the free list by virtual address */
void			save_ret_wMSR(struct savearea *, reg64_t);	/* returns a savearea and restores an MSR */
void			save_ret_phys(reg64_t);		/* Returns a savearea to the free list by physical address */
void			save_adjust(void);			/* Adjust size of the global free list */
struct savearea_comm	*save_trim_free(void);	/* Remove free pages from savearea pool */
int				save_recover(void);			/* returns nonzero if we can recover enough from the free pool */
void 			savearea_init(vm_offset_t addr);	/* Boot-time savearea initialization */

void 			save_fake_zone_info(		/* report savearea usage statistics as fake zone info */
					int *count,
					vm_size_t *cur_size,
					vm_size_t *max_size,
					vm_size_t *elem_size,
					vm_size_t *alloc_size, 
					int *collectable, 
					int *exhaustable);

void			save_snapshot(void);
void			save_snapshot_restore(void);

#endif /* MACH_KERNEL_PRIVATE */
#endif /* __APPLE_API_PRIVATE */

#endif /* ndef ASSEMBLER */

#define SAVattach	0x80000000				/* Savearea has valid context */
#define SAVrststk	0x00010000				/* Indicates that the current stack should be reset to empty */
#define SAVsyscall	0x00020000				/* Indicates that the savearea is associated with a syscall */
#define SAVredrive	0x00040000				/* Indicates that the low-level fault handler associated */
#define SAVredriveb	13						/* Indicates that the low-level fault handler associated */
#define	SAVinstrument 0x00080000			/* Indicates that we should return instrumentation data */
#define	SAVinstrumentb 12					/* Indicates that we should return instrumentation data */
#define	SAVeat 		0x00100000				/* Indicates that interruption should be ignored */
#define	SAVeatb 	11						/* Indicates that interruption should be ignored */
#define SAVtype		0x0000FF00				/* Shows type of savearea */
#define SAVtypeshft	8						/* Shift to position type */
#define SAVempty	0x86					/* Savearea is on free list */
#define SAVgeneral	0x01					/* Savearea contains general context */
#define SAVfloat	0x02					/* Savearea contains floating point context */
#define SAVvector	0x03					/* Savearea contains vector context */



#endif /* _PPC_SAVEAREA_H_ */

#endif	/* XNU_KERNEL_PRIVATE */
