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


typedef struct vmm_regs32_t {

	unsigned long			ppcPC;						/* 000 */
	unsigned long			ppcMSR;						/* 004 */

	unsigned long			ppcGPRs[32];				/* 008 */

	unsigned long			ppcCR;						/* 088 */
	unsigned long			ppcXER;						/* 08C */
	unsigned long			ppcLR;						/* 090 */
	unsigned long			ppcCTR;						/* 094 */
	unsigned long			ppcMQ;						/* 098 - Obsolete */
	unsigned long			ppcVRSave;					/* 09C */
	unsigned long			ppcRsrvd0A0[40];			/* 0A0 */
														/* 140 */
} vmm_regs32_t;

#pragma pack(4)							/* Make sure the structure stays as we defined it */
typedef struct vmm_regs64_t {

	unsigned long long		ppcPC;						/* 000 */
	unsigned long long		ppcMSR;						/* 008 */

	unsigned long long		ppcGPRs[32];				/* 010 */

	unsigned long long		ppcXER;						/* 110 */
	unsigned long long		ppcLR;						/* 118 */
	unsigned long long		ppcCTR;						/* 120 */
	unsigned long			ppcCR;						/* 128 */
	unsigned long			ppcVRSave;					/* 12C */
	unsigned long			ppcRsvd130[4];				/* 130 */
														/* 140 */
} vmm_regs64_t;
#pragma pack()
	
	
#pragma pack(4)							/* Make sure the structure stays as we defined it */
typedef union vmm_regs_t {
	vmm_regs32_t			ppcRegs32;
	vmm_regs64_t			ppcRegs64;
} vmm_regs_t;
#pragma pack()

#pragma pack(4)							/* Make sure the structure stays as we defined it */
typedef struct vmm_processor_state_t {
														/* 32-byte bndry */
	vmm_regs_t				ppcRegs;					/* Define registers areas */
	
/*	We must be 16-byte aligned here */

	vmm_vector_register_t	ppcVRs[32];					/* These are only valid after a kVmmGetVectorState */
	vmm_vector_register_t	ppcVSCR;					/* This is always loaded/saved at host/guest transition */
	
/*	We must be 8-byte aligned here */

	vmm_fp_register_t		ppcFPRs[32];				/* These are only valid after a kVmmGetFloatState */
	vmm_fp_register_t		ppcFPSCR;					/* This is always loaded/saved at host/guest transition */
	unsigned long			ppcReserved2[2];			/* Pad out to multiple of 16 bytes */
} vmm_processor_state_t;
#pragma pack()

typedef unsigned long vmm_return_code_t;

typedef unsigned long vmm_thread_index_t;
#define vmmTInum 0x000000FF
#define vmmTIadsp 0x0000FF00
typedef unsigned long vmm_adsp_id_t;

enum {
	kVmmCurMajorVersion					= 0x0001,
	kVmmCurMinorVersion					= 0x0006,
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
	kVmmFeature_XA						= 0x00000020,
	kVmmFeature_SixtyFourBit			= 0x00000040,
	kVmmFeature_MultAddrSpace			= 0x00000080,
};
#define kVmmCurrentFeatures (kVmmFeature_LittleEndian | kVmmFeature_Stop | kVmmFeature_ExtendedMapping \
	| kVmmFeature_ListMapping | kVmmFeature_FastAssist | kVmmFeature_XA | kVmmFeature_MultAddrSpace)

enum {
	vmm64Bit							= 0x80000000,
};


typedef unsigned long vmm_version_t;

typedef struct vmm_ret_parms32_t {
	unsigned long 			return_params[4];
} vmm_ret_parms32_t;

typedef struct vmm_ret_parms64_t {
	unsigned long long		return_params[4];
} vmm_ret_parms64_t;

#pragma pack(4)							/* Make sure the structure stays as we defined it */
typedef union vmm_ret_parms_t {
	vmm_ret_parms64_t		vmmrp64;		/* 64-bit flavor */
	vmm_ret_parms32_t		vmmrp32;		/* 32-bit flavor */
	unsigned int			retgas[11];		/* Force this to be 11 words long */
} vmm_ret_parms_t;
#pragma pack()

#pragma pack(4)							/* Make sure the structure stays as we defined it */
typedef struct vmm_fastassist_state32_t {
	unsigned long fastassist_dispatch;
	unsigned long fastassist_refcon;

	unsigned long fastassist_dispatch_code;
	unsigned long fastassist_parameter[5];

	unsigned long guest_register[8];

	unsigned long guest_pc;
	unsigned long guest_msr;

	unsigned long fastassist_intercepts;
	unsigned long fastassist_reserved1;
} vmm_fastassist_state32_t;

typedef struct vmm_fastassist_state64_t {
	unsigned long long fastassist_dispatch;
	unsigned long long fastassist_refcon;

	unsigned long long fastassist_dispatch_code;
	unsigned long long fastassist_parameter[5];

	unsigned long long guest_register[8];

	unsigned long long guest_pc;
	unsigned long long guest_msr;

	unsigned long fastassist_intercepts;
	unsigned long fastassist_reserved1;
} vmm_fastassist_state64_t;

typedef union vmm_fastassist_state_t {
	vmm_fastassist_state64_t		vmmfs64;		/* 64-bit flavor */
	vmm_fastassist_state32_t		vmmfs32;		/* 32-bit flavor */
} vmm_fastassist_state_t;
#pragma pack()

#pragma pack(4)							/* Make sure the structure stays as we defined it */
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
	vmm_ret_parms_t			vmmRet;

	/* The next portion of the structure must remain 32-byte aligned */
	vmm_processor_state_t	vmm_proc_state;

	/* The next portion of the structure must remain 16-byte aligned */
	vmm_fastassist_state_t	vmm_fastassist_state;

} vmm_state_page_t;
#pragma pack()

#pragma pack(4)							/* Make sure the structure stays as we defined it */
typedef struct vmm_comm_page_t {
	union {
		vmm_state_page_t	vmcpState;					/* Reserve area for state */
		unsigned int		vmcpPad[768];				/* Reserve space for 3/4 page state area */
	} vmcpfirst;
	unsigned int			vmcpComm[256];				/* Define last 1024 bytes as a communications area - function specific */
} vmm_comm_page_t;
#pragma pack()

enum {
	/* Function Indices (passed in r3) */
	kVmmGetVersion				= 0,					/* Get VMM system version */
	kVmmvGetFeatures,									/* Get VMM supported features */
	kVmmInitContext,									/* Initialize a context */
	kVmmTearDownContext,								/* Destroy a context */
	kVmmTearDownAll,									/* Destory all contexts */
	kVmmMapPage,										/* Map a host to guest address space */
	kVmmGetPageMapping,									/* Get host address of a guest page */
	kVmmUnmapPage,										/* Unmap a guest page */
	kVmmUnmapAllPages,									/* Unmap all pages in a guest address space */
	kVmmGetPageDirtyFlag,								/* Check if guest page modified */
	kVmmGetFloatState,									/* Retrieve guest floating point context */
	kVmmGetVectorState,									/* Retrieve guest vector context */
	kVmmSetTimer,										/* Set a guest timer */
	kVmmGetTimer,										/* Get a guest timer */
	kVmmExecuteVM,										/* Launch a guest */
	kVmmProtectPage,									/* Set protection attributes for a guest page */
	kVmmMapExecute,										/* Map guest page and launch */
	kVmmProtectExecute,									/* Set prot attributes and launch */
	kVmmMapList,										/* Map a list of pages into guest address spaces */
	kVmmUnmapList,										/* Unmap a list of pages from guest address spaces */
	kvmmExitToHost,
	kvmmResumeGuest,
	kvmmGetGuestRegister,
	kvmmSetGuestRegister,
	
	kVmmSetXA,											/* Set extended architecture features for a VM */
	kVmmGetXA,											/* Get extended architecture features from a VM */

	kVmmMapPage64,										/* Map a host to guest address space - supports 64-bit */
	kVmmGetPageMapping64,								/* Get host address of a guest page - supports 64-bit  */
	kVmmUnmapPage64,									/* Unmap a guest page - supports 64-bit  */
	kVmmGetPageDirtyFlag64,								/* Check if guest page modified - supports 64-bit  */
	kVmmProtectPage64,									/* Set protection attributes for a guest page - supports 64-bit */
	kVmmMapExecute64,									/* Map guest page and launch - supports 64-bit  */
	kVmmProtectExecute64,								/* Set prot attributes and launch - supports 64-bit  */
	kVmmMapList64,										/* Map a list of pages into guest address spaces - supports 64-bit  */
	kVmmUnmapList64,									/* Unmap a list of pages from guest address spaces - supports 64-bit  */
	kVmmMaxAddr,										/* Returns the maximum virtual address that is mappable  */
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
#define kVmmInvalidAddress				0x1000
#define kVmmInvalidAdSpace				0x1001

/*
 *	Notes on guest address spaces.
 *
 *	Address spaces are loosely coupled to virtual machines.  The default is for
 *	a guest with an index of 1 to use address space 1, 2 to use 2, etc.  However,
 *	any guest may be launched using any address space and any address space may be the
 *	target for a map or unmap function.  Note that the (un)map list functions may pass in
 *	an address space ID on a page-by-page basis.
 *	
 *	An address space is instantiated either explicitly by mapping something into it, or 
 *	implicitly by launching a guest with it.
 *
 *	An address space is destroyed explicitly by kVmmTearDownAll or kVmmUnmapAllPages.  It is
 *	destroyed implicitly by kVmmTearDownContext.  The latter is done in order to remain
 *	backwards compatible with the previous implementation, which does not have decoupled
 *	guests and address spaces.
 *
 *	An address space supports the maximum virtual address supported by the processor.  
 *	The 64-bit variant of the mapping functions can be used on non-64-bit machines.  If an
 *	unmappable address (e.g., an address larger than 4GB-1 on a 32-bit machine) is requested, 
 *	the operation fails with a kVmmInvalidAddress return code.
 *
 *	Note that for 64-bit calls, both host and guest are specified at 64-bit values.
 *
 */




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
 *	Map list formats
 *	The last 12 bits in the guest virtual address is used as flags as follows:
 *		0x007 - for the map calls, this is the key to set
 *		0x3F0 - for both map and unmap, this is the address space ID upon which to operate.
 *				Note that if 0, the address space ID from the function call is used instead.
 */

typedef struct vmmMList {
	unsigned int	vmlva;			/* Virtual address in host address space */
	unsigned int	vmlava;			/* Virtual address in guest address space */
} vmmMList;

typedef struct vmmMList64 {
	unsigned long long	vmlva;		/* Virtual address in host address space */
	unsigned long long	vmlava;		/* Virtual address in guest address space */
} vmmMList64;

typedef struct vmmUMList {
	unsigned int	vmlava;			/* Virtual address in guest address space */
} vmmUMList;

typedef struct vmmUMList64 {
	unsigned long long	vmlava;		/* Virtual address in guest address space */
} vmmUMList64;

#define vmmlFlgs 0x00000FFF			/* Flags passed in in vmlava low order 12 bits */
#define vmmlProt 0x00000007			/* Protection flags for the page */
#define vmmlAdID 0x000003F0			/* Guest address space ID - used only if non-zero */
#define vmmlRsvd 0x00000C08			/* Reserved for future */

/*************************************************************************************
	Internal Emulation Types
**************************************************************************************/

#define kVmmMaxContexts					32
#define kVmmMaxUnmapPages				64
#define kVmmMaxMapPages					64

#pragma pack(4)							/* Make sure the structure stays as we defined it */
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
#define vmmFAMmode		0x04000000
#define vmmFAMmodeb		5
#define vmmXStop		0x00800000
#define vmmXStopb		8
#define vmmSpfSave		0x000000FF
#define vmmSpfSaveb		24
	unsigned int	vmmXAFlgs;						/* Extended Architecture flags */
	vmm_state_page_t *vmmContextKern;				/* Kernel address of context communications area */
	ppnum_t			vmmContextPhys;				/* Physical address of context communications area */
	vmm_state_page_t *vmmContextUser;				/* User address of context communications area */
	facility_context vmmFacCtx;						/* Header for vector and floating point contexts */
	pmap_t			vmmPmap;						/* Last dispatched pmap */
	uint64_t		vmmTimer;						/* Last set timer value. Zero means unset */
	unsigned int	vmmFAMintercept;				/* FAM intercepted exceptions */
} vmmCntrlEntry;
#pragma pack()

#pragma pack(4)							/* Make sure the structure stays as we defined it */
typedef struct vmmCntrlTable {						/* Virtual Machine Monitor Control table */
	unsigned int	vmmGFlags;						/* Global flags */
#define vmmLastAdSp 0xFF							/* Remember the address space that was mapped last */
	addr64_t		vmmLastMap;						/* Last vaddr mapping made */
	vmmCntrlEntry	vmmc[kVmmMaxContexts];			/* One entry for each possible Virtual Machine Monitor context */
	pmap_t			vmmAdsp[kVmmMaxContexts];		/* Guest address space pmaps */
} vmmCntrlTable;
#pragma pack()

/* function decls for kernel level routines... */
extern void vmm_execute_vm(thread_act_t act, vmm_thread_index_t index);
extern vmmCntrlEntry *vmm_get_entry(thread_act_t act, vmm_thread_index_t index);
extern kern_return_t vmm_tear_down_context(thread_act_t act, vmm_thread_index_t index);
extern kern_return_t vmm_get_float_state(thread_act_t act, vmm_thread_index_t index);
extern kern_return_t vmm_get_vector_state(thread_act_t act, vmm_thread_index_t index);
extern kern_return_t vmm_set_timer(thread_act_t act, vmm_thread_index_t index, unsigned int timerhi, unsigned int timerlo);
extern kern_return_t vmm_get_timer(thread_act_t act, vmm_thread_index_t index);
extern void vmm_tear_down_all(thread_act_t act);
extern kern_return_t vmm_map_page(thread_act_t act, vmm_thread_index_t hindex, addr64_t cva,
	addr64_t ava, vm_prot_t prot);
extern vmm_return_code_t vmm_map_execute(thread_act_t act, vmm_thread_index_t hindex, addr64_t cva,
	addr64_t ava, vm_prot_t prot);
extern kern_return_t vmm_protect_page(thread_act_t act, vmm_thread_index_t hindex, addr64_t va,
	vm_prot_t prot);
extern vmm_return_code_t vmm_protect_execute(thread_act_t act, vmm_thread_index_t hindex, addr64_t va,
	vm_prot_t prot);
extern addr64_t vmm_get_page_mapping(thread_act_t act, vmm_thread_index_t index,
	addr64_t va);
extern kern_return_t vmm_unmap_page(thread_act_t act, vmm_thread_index_t index, addr64_t va);
extern void vmm_unmap_all_pages(thread_act_t act, vmm_thread_index_t index);
extern boolean_t vmm_get_page_dirty_flag(thread_act_t act, vmm_thread_index_t index,
	addr64_t va, unsigned int reset);
extern kern_return_t vmm_set_XA(thread_act_t act, vmm_thread_index_t index, unsigned int xaflags);
extern unsigned int vmm_get_XA(thread_act_t act, vmm_thread_index_t index);
extern int vmm_get_features(struct savearea *);
extern int vmm_get_version(struct savearea *);
extern int vmm_init_context(struct savearea *);
extern int vmm_dispatch(struct savearea *);
extern int vmm_exit(thread_act_t act, struct savearea *);
extern void vmm_force_exit(thread_act_t act, struct savearea *);
extern int vmm_stop_vm(struct savearea *save);
extern void vmm_timer_pop(thread_act_t act);
extern void vmm_interrupt(ReturnHandler *rh, thread_act_t act);
extern kern_return_t vmm_map_list(thread_act_t act, vmm_thread_index_t index, unsigned int cnt, unsigned int flavor);
extern kern_return_t vmm_unmap_list(thread_act_t act, vmm_thread_index_t index, unsigned int cnt, unsigned int flavor);
extern vmm_return_code_t vmm_resume_guest(vmm_thread_index_t index, unsigned long pc, 
	unsigned long vmmCntrl, unsigned long vmmCntrMaskl);
extern vmm_return_code_t vmm_exit_to_host(vmm_thread_index_t index);
extern unsigned long vmm_get_guest_register(vmm_thread_index_t index, unsigned long reg_index);
extern vmm_return_code_t vmm_set_guest_register(vmm_thread_index_t index, unsigned long reg_index, unsigned long reg_value);
extern addr64_t vmm_max_addr(thread_act_t act);

#endif

