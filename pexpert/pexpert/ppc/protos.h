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
#ifndef _PEXPERT_PPC_PROTOS_H_
#define _PEXPERT_PPC_PROTOS_H_

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
extern void initialize_serial(void * scc_phys_base);


//------------------------------------------------------------------------
// from ppc/POWERMAC/device_tree.h
extern void ofw_init(void *);

//------------------------------------------------------------------------
// from osfmk/ppc/POWERMAC/video_console.c

extern void initialize_screen(void *, unsigned int);

extern boolean_t vc_progress_initialize( void * desc,
					 unsigned char * data,
					 unsigned char * clut );

extern void vc_display_icon( void * desc,
			     unsigned char * data );

// from osfmk/ppc/serial_console.c
extern int  switch_to_serial_console(void);
extern void switch_to_old_console(int old_console);

//------------------------------------------------------------------------
// from ppc/spl.h
 /* Note also : if any new SPL's are introduced, please add to debugging list*/
#define SPLOFF          0       /* all interrupts disabled TODO NMGS  */
#define SPLPOWER        1       /* power failure (unused) */
#define SPLHIGH         2       /* TODO NMGS any non-zero, non-INTPRI value */
#define SPLSCHED        SPLHIGH
#define SPLCLOCK        SPLSCHED /* hard clock */
#define SPLVM           4       /* pmap manipulations */
#define SPLBIO          8       /* block I/O */
#define SPLIMP          8       /* network & malloc */
#define SPLTTY          16      /* TTY */
#define SPLNET          24      /* soft net */
#define SPLSCLK         27      /* soft clock */
#define SPLLO           32      /* no interrupts masked */

/* internal - masked in to spl level if ok to lower priority (splx, splon)
 * the mask bit is never seen externally
 */
#define SPL_LOWER_MASK  0x8000

#define SPL_CMP_GT(a, b)        ((unsigned)(a) >  (unsigned)(b))
#define SPL_CMP_LT(a, b)        ((unsigned)(a) <  (unsigned)(b))
#define SPL_CMP_GE(a, b)        ((unsigned)(a) >= (unsigned)(b))
#define SPL_CMP_LE(a, b)        ((unsigned)(a) <= (unsigned)(b))

typedef unsigned spl_t;

//------------------------------------------------------------------------
// from bsd/dev/ppc/busses.h which clashes with mach/device/device_types.h
typedef int		io_req_t;


//typedef struct ipc_port         *ipc_port_t;

extern void            cninit(void);

/*
 *	Temporarily stolen from Firmware.h
 */

void dbgDisp(unsigned int port, unsigned int id, unsigned int data);
void dbgDispLL(unsigned int port, unsigned int id, unsigned int data);
void fwSCCinit(unsigned int port);

extern void dbgTrace(unsigned int item1, unsigned int item2, unsigned int item3);
#if 1		/* (TEST/DEBUG) - eliminate inline */
extern __inline__ void dbgTrace(unsigned int item1, unsigned int item2, unsigned int item3) {
 
 		__asm__ volatile("mr   r3,%0" : : "r" (item1) : "r3");
 		__asm__ volatile("mr   r4,%0" : : "r" (item2) : "r4");
 		__asm__ volatile("mr   r5,%0" : : "r" (item3) : "r5");
#ifdef __ELF__
        __asm__ volatile("lis  r0,CutTrace@h" : : : "r0");
        __asm__ volatile("ori  r0,r0,CutTrace@l" : : : "r0");
#else
        __asm__ volatile("lis  r0,hi16(CutTrace)" : : : "r0");
        __asm__ volatile("ori  r0,r0,lo16(CutTrace)" : : : "r0");
#endif
        __asm__ volatile("sc");
		return;
}
#endif

extern void DoPreempt(void);
extern __inline__ void DoPreempt(void) {
#ifdef __ELF__
        __asm__ volatile("lis  r0,DoPreemptCall@h" : : : "r0");
        __asm__ volatile("ori  r0,r0,DoPreemptCall@l" : : : "r0");
#else
        __asm__ volatile("lis  r0,hi16(DoPreemptCall)" : : : "r0");
        __asm__ volatile("ori  r0,r0,lo16(DoPreemptCall)" : : : "r0");
#endif
        __asm__ volatile("sc");
		return;
}

extern void CreateFakeIO(void);
extern __inline__ void CreateFakeIO(void) {
#ifdef __ELF__
        __asm__ volatile("lis  r0,CreateFakeIOCall@h" : : : "r0");
        __asm__ volatile("ori  r0,r0,CreateFakeIOCall@l" : : : "r0");
#else
        __asm__ volatile("lis  r0,hi16(CreateFakeIOCall)" : : : "r0");
        __asm__ volatile("ori  r0,r0,lo16(CreateFakeIOCall)" : : : "r0");
#endif
         __asm__ volatile("sc");
		return;
}

extern void StoreReal(unsigned int val, unsigned int addr);
extern void ReadReal(unsigned int raddr, unsigned int *vaddr);
extern void ClearReal(unsigned int addr, unsigned int lgn);
extern void LoadDBATs(unsigned int *bat);
extern void LoadIBATs(unsigned int *bat);
extern unsigned int LLTraceSet(unsigned int tflags);
extern void GratefulDebInit(void);
extern void GratefulDebDisp(unsigned int coord, unsigned int data);
extern void checkNMI(void);

/*
 *	Temporarily stolen from ppc/cpu_number.h
 */
int cpu_number(void);

#endif /* _PEXPERT_PPC_PROTOS_H_ */
