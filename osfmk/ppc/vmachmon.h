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

	unsigned long			ppcPC;
	unsigned long			ppcMSR;

	unsigned long			ppcGPRs[32];

	unsigned long			ppcCR;
	unsigned long			ppcXER;
	unsigned long			ppcLR;
	unsigned long			ppcCTR;
	unsigned long			ppcMQ;						/* Obsolete */
	unsigned long			ppcVRSave;
														/* 32-byte bndry */
	vmm_vector_register_t	ppcVSCR;
	vmm_fp_register_t		ppcFPSCR;
	
	unsigned long			ppcReserved1[34];			/* Future processor state can go here */
	
/*	We must be 16-byte aligned here */

	vmm_vector_register_t	ppcVRs[32];
	vmm_vector_register_t	ppcVSCRshadow;
	
/*	We must be 8-byte aligned here */

	vmm_fp_register_t		ppcFPRs[32];
	vmm_fp_register_t		ppcFPSCRshadow;
	unsigned long			ppcReserved2[2];			/* Pad out to multiple of 16 bytes */
} vmm_processor_state_t;

typedef unsigned long vmm_return_code_t;

typedef unsigned long vmm_thread_index_t;

enum {
	kVmmCurMajorVersion					= 0x0001,
	kVmmCurMinorVersion					= 0x0005,
	kVmmMinMajorVersion					= 0x0001,
};
#define kVmmCurrentVersion ((kVmmCurMajorVersion << 16) | kVmmCurMinorVersion)

typedef unsigned long vmm_features_t;
enum {
	kVmmFeature_LittleEndian			= 0x00000001,
	kVmmFeature_Stop					= 0x00000002,
	kVmmFeature_ExtendedMapping			= 0x00000004,
	kVmmFeature_ListMapping				= 0x00000008,
	kVmmFeature_FastAssist				= 0x00000010,
};
#define kVmmCurrentFeatures (kVmmFeature_LittleEndian |		 \
							kVmmFeature_Stop |				 \
							kVmmFeature_ExtendedMapping |	 \
							kVmmFeature_ListMapping |		 \
							kVmmFeature_FastAssist)


typedef unsigned long vmm_version_t;

typedef struct vmm_fastassist_state_t {
	unsigned long fastassist_dispatch;
	unsigned long fastassist_refcon;

	unsigned long fastassist_dispatch_code;
	unsigned long fastassist_parameter[5];

	unsigned long guest_register[8];

	unsigned long guest_pc;
	unsigned long guest_msr;

	unsigned long fastassist_intercepts;
	unsigned long fastassist_reserved1;
} vmm_fastassist_state_t;

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
#define vmmXStart		0x08000000
#define vmmXStartb		4
#define vmmKey			0x04000000
#define vmmKeyb			5
#define vmmFamEna		0x02000000
#define vmmFamEnab		6
#define vmmFamSet		0x01000000
#define vmmFamSetb		7

	vmm_return_code_t		return_code;
	unsigned long			return_params[4];
	unsigned long			gas[7];		/* For alignment */

	/* The next portion of the structure must remain 32-byte aligned */
	vmm_processor_state_t	vmm_proc_state;

	/* The next portion of the structure must remain 16-byte aligned */
	vmm_fastassist_state_t	vmm_fastassist_state;

} vmm_state_page_t;

typedef struct vmm_comm_page_t {
	union {
		vmm_state_page_t	vmcpState;					/* Reserve area for state */
		unsigned int		vmcpPad[768];				/* Reserve space for 3/4 page state area */
	} vmcpfirst;
	unsigned int			vmcpComm[256];				/* Define last 1024 bytes as a communications area - function specific */
} vmm_comm_page_t;

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
	kVmmExecuteVM,
	kVmmProtectPage,
	kVmmMapExecute,
	kVmmProtectExecute,
	kVmmMapList,
	kVmmUnmapList,
	kvmmExitToHost,
	kvmmResumeGuest,
	kvmmGetGuestRegister,
	kvmmSetGuestRegister,
};

#define kVmmReturnNull					0
#define kVmmBogusContext				1
#define kVmmStopped						2
#define kVmmReturnDataPageFault			3
#define kVmmReturnInstrPageFault		4
#define kVmmReturnAlignmentFault		6
#define kVmmReturnProgramException		7
#define kVmmReturnSystemCall			12
#define kVmmReturnTraceException		13
#define kVmmAltivecAssist				22
#define kVmmInvalidAddress				4096

/*
 *	Storage Extended Protection modes
 *	Notes:
 *		To keep compatibility, vmmKey and the PPC key have reversed meanings,
 *		i.e., vmmKey 0 is PPC key 1 and vice versa.
 *
 *	    vmmKey										Notes
 *	Mode			0				1
 *
 *	kVmmProtNARW	not accessible	read/write		VM_PROT_NONE (not settable via VM calls)
 *	kVmmProtRORW	read only		read/write		
 *	kVmmProtRWRW	read/write		read/write		VM_PROT_WRITE or (VM_PROT_WRITE | VM_PROT_READ)
 *	kVmmProtRORO	read only		read only		VM_PROT_READ
 
 */
 
#define kVmmProtXtnd 0x00000008
#define kVmmProtNARW (kVmmProtXtnd | 0x00000000)
#define kVmmProtRORW (kVmmProtXtnd | 0x00000001)
#define kVmmProtRWRW (kVmmProtXtnd | 0x00000002)
#define kVmmProtRORO (kVmmProtXtnd | 0x00000003)

/*
 *	Map list format
 */

typedef struct vmmMapList {
	unsigned int	vmlva;			/* Virtual address in emulator address space */
	unsigned int	vmlava;			/* Virtual address in alternate address space */
#define vmlFlgs 0x00000FFF			/* Flags passed in in vmlava low order 12 bits */
#define vmlProt 0x00000003			/* Protection flags for the page */
} vmmMapList;


/*************************************************************************************
	Internal Emulation Types
**************************************************************************************/

#define kVmmMaxContextsPerThread		32
#define kVmmMaxUnmapPages				64
#define kVmmMaxMapPages					64

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
#define vmmFAMmode		0x04000000
#define vmmFAMmodeb		5
#define vmmXStop		0x00800000
#define vmmXStopb		8
#define vmmSpfSave		0x000000FF
#define vmmSpfSaveb		24
	pmap_t			vmmPmap;						/* pmap for alternate context's view of task memory */
	vmm_state_page_t *vmmContextKern;				/* Kernel address of context communications area */
	vmm_state_page_t *vmmContextPhys;				/* Physical address of context communications area */
	vmm_state_page_t *vmmContextUser;				/* User address of context communications area */
	facility_context vmmFacCtx;						/* Header for vector and floating point contexts */
	uint64_t		vmmTimer;						/* Last set timer value. Zero means unset */
	vm_offset_t		vmmLastMap;						/* Last vaddr mapping into virtual machine */
	unsigned int	vmmFAMintercept;				/* FAM intercepted exceptions */
} vmmCntrlEntry;

typedef struct vmmCntrlTable {						/* Virtual Machine Monitor Control table */
	vmmCntrlEntry	vmmc[kVmmMaxContextsPerThread];	/* One entry for each possible Virtual Machine Monitor context */
} vmmCntrlTable;

/* function decls for kernel level routines... */
extern void vmm_execute_vm(thread_act_t act, vmm_thread_index_t index);
extern vmmCntrlEntry *vmm_get_entry(thread_act_t act, vmm_thread_index_t index);
extern kern_return_t vmm_tear_down_context(thread_act_t act, vmm_thread_index_t index);
extern kern_return_t vmm_get_float_state(thread_act_t act, vmm_thread_index_t index);
extern kern_return_t vmm_get_vector_state(thread_act_t act, vmm_thread_index_t index);
extern kern_return_t vmm_set_timer(thread_act_t act, vmm_thread_index_t index, unsigned int timerhi, unsigned int timerlo);
extern kern_return_t vmm_get_timer(thread_act_t act, vmm_thread_index_t index);
extern void vmm_tear_down_all(thread_act_t act);
extern kern_return_t vmm_map_page(thread_act_t act, vmm_thread_index_t hindex, vm_offset_t cva,
	vm_offset_t ava, vm_prot_t prot);
extern vmm_return_code_t vmm_map_execute(thread_act_t act, vmm_thread_index_t hindex, vm_offset_t cva,
	vm_offset_t ava, vm_prot_t prot);
extern kern_return_t vmm_protect_page(thread_act_t act, vmm_thread_index_t hindex, vm_offset_t va,
	vm_prot_t prot);
extern vmm_return_code_t vmm_protect_execute(thread_act_t act, vmm_thread_index_t hindex, vm_offset_t va,
	vm_prot_t prot);
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
extern int vmm_stop_vm(struct savearea *save);
extern void vmm_timer_pop(thread_act_t act);
extern void vmm_interrupt(ReturnHandler *rh, thread_act_t act);
extern kern_return_t vmm_map_list(thread_act_t act, vmm_thread_index_t index, unsigned int cnt);
extern kern_return_t vmm_unmap_list(thread_act_t act, vmm_thread_index_t index, unsigned int cnt);
extern vmm_return_code_t vmm_resume_guest(vmm_thread_index_t index, unsigned long pc, 
	unsigned long vmmCntrl, unsigned long vmmCntrMaskl);
extern vmm_return_code_t vmm_exit_to_host(vmm_thread_index_t index);
extern unsigned long vmm_get_guest_register(vmm_thread_index_t index, unsigned long reg_index);
extern vmm_return_code_t vmm_set_guest_register(vmm_thread_index_t index, unsigned long reg_index, unsigned long reg_value);

#endif

