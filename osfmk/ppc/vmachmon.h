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
/*-----------------------------------------------------------------------
** vmachmon.h
**
** C routines that we are adding to the MacOS X kernel.
**
** Wierd Apple PSL stuff goes here...
**
** Until then, Copyright 2000, Connectix
**
-----------------------------------------------------------------------*/

#include <ppc/exception.h>

#ifndef	_VEMULATION_H_
#define	_VEMULATION_H_

/*************************************************************************************
	External Emulation Types
**************************************************************************************/

typedef union vmm_vector_register_t {
	unsigned long			i[4];
	unsigned short			s[8];
	unsigned char			b[16];
} vmm_vector_register_t;

typedef union vmm_fp_register_t {
	double					d;
	unsigned long			i[2];
	unsigned short			s[4];
	unsigned char			b[8];
} vmm_fp_register_t;

typedef struct vmm_processor_state_t {
/*
 *	NOTE: The general context needs to correspond to the order of the savearea for quick swaps
 */
	unsigned long			ppcPC;
	unsigned long			ppcMSR;

	unsigned long			ppcGPRs[32];

	unsigned long			ppcCR;
	unsigned long			ppcXER;
	unsigned long			ppcLR;
	unsigned long			ppcCTR;
	unsigned long			ppcMQ;						/* Obsolete */
	unsigned long			ppcVRSave;
	unsigned long			ppcReserved1[40];			/* Future processor state can go here */
	
/*	We must be 16-byte aligned here */

	vmm_vector_register_t	ppcVRs[32];
	vmm_vector_register_t	ppcVSCR;
	
/*	We must be 8-byte aligned here */

	vmm_fp_register_t		ppcFPRs[32];
	vmm_fp_register_t		ppcFPSCR;
	unsigned long			ppcReserved2[2];			/* Pad out to multiple of 16 bytes */
} vmm_processor_state_t;

typedef unsigned long vmm_return_code_t;

typedef unsigned long vmm_thread_index_t;
enum {
	kVmmCurrentVersion				= 0x00010000
};

typedef unsigned long vmm_features_t;
enum {
	kVmmFeature_LittleEndian			= 0x00000001
};

typedef unsigned long vmm_version_t;

typedef struct vmm_state_page_t {
	/* This structure must remain below 4Kb (one page) in size */
	vmm_version_t			interface_version;
	vmm_thread_index_t		thread_index;
	unsigned int			vmmStat;	/* Note: this field is identical to vmmFlags in vmmCntrlEntry */
	unsigned int			vmmCntrl;
#define vmmFloatLoad	0x80000000
#define vmmFloatLoadb	0
#define vmmVectLoad		0x40000000
#define vmmVectLoadb	1
#define vmmVectVRall	0x20000000
#define vmmVectVRallb	2
#define vmmVectVAss		0x10000000
#define vmmVectVAssb	3
	vmm_return_code_t		return_code;
	unsigned long			return_params[4];
	unsigned long			gas[7];		/* For alignment */

	/* The next portion of the structure must remain 32-byte aligned */
	vmm_processor_state_t	vmm_proc_state;

} vmm_state_page_t;

enum {
	/* Function Indices (passed in r3) */
	kVmmGetVersion				= 0,
	kVmmvGetFeatures,
	kVmmInitContext,
	kVmmTearDownContext,
	kVmmTearDownAll,
	kVmmMapPage,
	kVmmGetPageMapping,
	kVmmUnmapPage,
	kVmmUnmapAllPages,
	kVmmGetPageDirtyFlag,
	kVmmGetFloatState,
	kVmmGetVectorState,
	kVmmSetTimer,
	kVmmGetTimer,
	kVmmExecuteVM
};

#define kVmmReturnNull					0
#define kVmmBogusContext				1
#define kVmmReturnDataPageFault			3
#define kVmmReturnInstrPageFault		4
#define kVmmReturnAlignmentFault		6
#define kVmmReturnProgramException		7
#define kVmmReturnSystemCall			12
#define kVmmReturnTraceException		13
#define kVmmAltivecAssist				22


/*************************************************************************************
	Internal Emulation Types
**************************************************************************************/

#define kVmmMaxContextsPerThread		32

enum {
	kVmmCurrentFeatures				= kVmmFeature_LittleEndian
};

typedef struct vmmCntrlEntry {						/* Virtual Machine Monitor control table entry */
	unsigned int	vmmFlags;						/* Assorted control flags */
#define vmmInUse 		0x80000000
#define vmmInUseb 		0
#define vmmFloatCngd	0x40000000
#define vmmFloatCngdb	1
#define vmmVectCngd		0x20000000
#define vmmVectCngdb	2
#define vmmTimerPop		0x10000000
#define vmmTimerPopb	3
#define vmmMapDone		0x08000000
#define vmmMapDoneb		4
#define vmmSpfSave		0x000000FF
#define vmmSpfSaveb		24
	pmap_t			vmmPmap;						/* pmap for alternate context's view of task memory */
	vmm_state_page_t *vmmContextKern;				/* Kernel address of context communications area */
	vmm_state_page_t *vmmContextUser;				/* User address of context communications area */
	pcb_t			vmmFPU_pcb;						/* Saved floating point context */
	unsigned int	vmmFPU_cpu;						/* CPU saved fp context is valid on */
	pcb_t 			vmmVMX_pcb;						/* Saved vector context */
	unsigned int	vmmVMX_cpu;						/* CPU saved vector context is valid on */
	AbsoluteTime	vmmTimer;						/* Last set timer value. Zero means unset */
	vm_offset_t		vmmLastMap;						/* Last vaddr mapping into virtual machine */
} vmmCntrlEntry;

typedef struct vmmCntrlTable {						/* Virtual Machine Monitor Control table */
	vmmCntrlEntry	vmmc[kVmmMaxContextsPerThread];	/* One entry for each possible Virtual Machine Monitor context */
} vmmCntrlTable;

/* function decls for kernel level routines... */
extern vmmCntrlEntry *vmm_get_entry(thread_act_t act, vmm_thread_index_t index);
extern kern_return_t vmm_tear_down_context(thread_act_t act, vmm_thread_index_t index);
extern kern_return_t vmm_get_float_state(thread_act_t act, vmm_thread_index_t index);
extern kern_return_t vmm_get_vector_state(thread_act_t act, vmm_thread_index_t index);
extern kern_return_t vmm_set_timer(thread_act_t act, vmm_thread_index_t index, unsigned int timerhi, unsigned int timerlo);
extern kern_return_t vmm_get_timer(thread_act_t act, vmm_thread_index_t index);
extern void vmm_tear_down_all(thread_act_t act);
extern kern_return_t vmm_map_page(thread_act_t act, vmm_thread_index_t hindex, vm_offset_t cva,
	vm_offset_t ava, vm_prot_t prot);
extern vm_offset_t vmm_get_page_mapping(thread_act_t act, vmm_thread_index_t index,
	vm_offset_t va);
extern kern_return_t vmm_unmap_page(thread_act_t act, vmm_thread_index_t index, vm_offset_t va);
extern void vmm_unmap_all_pages(thread_act_t act, vmm_thread_index_t index);
extern boolean_t vmm_get_page_dirty_flag(thread_act_t act, vmm_thread_index_t index,
	vm_offset_t va, unsigned int reset);
extern int vmm_get_features(struct savearea *);
extern int vmm_get_version(struct savearea *);
extern int vmm_init_context(struct savearea *);
extern int vmm_dispatch(struct savearea *);
extern int vmm_exit(thread_act_t act, struct savearea *);
extern void vmm_force_exit(thread_act_t act, struct savearea *);
void vmm_timer_pop(thread_act_t act);

#endif

