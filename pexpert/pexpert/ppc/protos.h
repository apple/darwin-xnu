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
#ifndef _PEXPERT_PPC_PROTOS_H_
#define _PEXPERT_PPC_PROTOS_H_
 
#define mtsprg(n, reg)  __asm__ volatile("mtsprg  " # n ", %0" : : "r" (reg))
#define mfsprg(reg, n)  __asm__ volatile("mfsprg  %0, " # n : "=r" (reg))
 
#define mtspr(spr, val)  __asm__ volatile("mtspr  " # spr ", %0" : : "r" (val))
#define mfspr(reg, spr)  __asm__ volatile("mfspr  %0, " # spr : "=r" (reg))

/*
 * Various memory/IO synchronisation instructions
 */     
 
        /*      Use eieio as a memory barrier to order stores.
         *      Useful for device control and PTE maintenance.
         */ 
 
#define eieio() \
        __asm__ volatile("eieio")
 
        /*      Use sync to ensure previous stores have completed.
                This is  required when manipulating locks and/or
                maintaining PTEs or other shared structures on SMP
                machines.
        */

#define sync() \
        __asm__ volatile("sync") 
 
        /*      Use isync to sychronize context; that is, the ensure
                no prefetching of instructions happen before the
                instruction.
        */

#define isync() \
        __asm__ volatile("isync")


//------------------------------------------------------------------------
// from ppc/endian.h
static __inline__ unsigned int byte_reverse_word(unsigned int word);
static __inline__ unsigned int byte_reverse_word(unsigned int word) {
        unsigned int result;
        __asm__ volatile("lwbrx %0, 0, %1" : "=r" (result) : "r" (&word));
        return result;
}

//------------------------------------------------------------------------
// from ppc/serial_io.h
extern void initialize_serial(void * scc_phys_base, uint32_t serial_baud);


//------------------------------------------------------------------------
// from osfmk/ppc/POWERMAC/video_console.c

extern void initialize_screen(void *, unsigned int);

extern void vc_progress_initialize( void * desc,
				    const unsigned char * data,
				    const unsigned char * clut );

extern void vc_display_icon( void * desc,
			     const unsigned char * data );

//-------------------------------------------------------------------------
// from osfmk/console/panic_dialog.c
extern void panic_ui_initialize(const unsigned char * clut);

// from osfmk/ppc/serial_console.c
extern int  switch_to_serial_console(void);
extern void switch_to_old_console(int old_console);

typedef unsigned spl_t;

//------------------------------------------------------------------------
// from bsd/dev/ppc/busses.h which clashes with mach/device/device_types.h
typedef int		io_req_t;


//typedef struct ipc_port         *ipc_port_t;

extern void            cninit(void);

/*
 *	Temporarily stolen from Firmware.h
 */

extern void dbgTrace(unsigned int item1, unsigned int item2, unsigned int item3);
#if 1		/* (TEST/DEBUG) - eliminate inline */
extern __inline__ void dbgTrace(unsigned int item1, unsigned int item2, unsigned int item3) {
 
	__asm__ volatile("mr   r3,%0" : : "r" (item1) : "r3");
	__asm__ volatile("mr   r4,%0" : : "r" (item2) : "r4");
	__asm__ volatile("mr   r5,%0" : : "r" (item3) : "r5");
	__asm__ volatile("lis  r0,hi16(CutTrace)" : : : "r0");
	__asm__ volatile("ori  r0,r0,lo16(CutTrace)" : : : "r0");
	__asm__ volatile("sc");
	return;
}
#endif

extern void DoPreempt(void);
extern __inline__ void DoPreempt(void) {
	__asm__ volatile("lis  r0,hi16(DoPreemptCall)" : : : "r0");
	__asm__ volatile("ori  r0,r0,lo16(DoPreemptCall)" : : : "r0");
	__asm__ volatile("sc");
	return;
}

extern void CreateFakeIO(void);
extern __inline__ void CreateFakeIO(void) {
	__asm__ volatile("lis  r0,hi16(CreateFakeIOCall)" : : : "r0");
	__asm__ volatile("ori  r0,r0,lo16(CreateFakeIOCall)" : : : "r0");
	__asm__ volatile("sc");
		return;
}

extern void StoreReal(unsigned int val, unsigned int addr);
extern void ReadReal(unsigned int raddr, unsigned int *vaddr);
extern unsigned int LLTraceSet(unsigned int tflags);
extern void GratefulDebInit(void);
extern void GratefulDebDisp(unsigned int coord, unsigned int data);
extern void checkNMI(void);

#endif /* _PEXPERT_PPC_PROTOS_H_ */
